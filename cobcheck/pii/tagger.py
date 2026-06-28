"""
cobcheck/pii/tagger.py
───────────────────────
Tags DATA_ITEM nodes in the CPG as PII sources.

Three-stage pipeline (run in order, short-circuit on first match):

  Stage 1 — Name heuristics
      Field name contains a known PII keyword: SSN, NAME, DOB, BIRTH,
      ADDR, ACCT, CARD, PAN, EMAIL, PHONE, POLICY, CLAIM, etc.

  Stage 2 — PIC heuristics
      PIC pattern matches a known PII shape even when the name is cryptic:
      e.g.  9(09) on a field named CUST-ID  →  SSN-shaped
            X(16) on a field named TOKEN    →  card-number-shaped

  Stage 3 — Groq LLM fallback
      Only for fields that pass stages 1 & 2 without a decision AND whose
      name gives no clue.  We pass the field name + surrounding context
      and ask for a yes/no.  Rate-limited to avoid burning quota on obvious
      non-PII fields.

The tagger writes back into the CPG:
    cpg.G.nodes[nid]["pii_fields"].add(field_name)
    cpg.G.nodes[nid]["pii_category"] = PiiCategory.<X>

Usage
─────
    tagger = PiiTagger(groq_api_key="gsk_...", model="llama3-8b-8192")
    tagger.tag(cpg)
"""

from __future__ import annotations

import re
import os
import logging
from enum import Enum, auto
from typing import Optional

from ..cpg.graph_model import CPG, NodeKind

logger = logging.getLogger(__name__)


# ─── PII categories (used in violation reports) ───────────────────────────────

class PiiCategory(Enum):
    NATIONAL_ID    = auto()   # SSN, TIN, NI number
    FINANCIAL      = auto()   # card number, account, IBAN
    NAME           = auto()   # first/last/full name
    CONTACT        = auto()   # email, phone, address
    HEALTH         = auto()   # diagnosis, DOB, medical record
    DATE_OF_BIRTH  = auto()
    LOCATION       = auto()
    IDENTIFIER     = auto()   # generic customer/policy/claim ID
    UNKNOWN_PII    = auto()   # LLM fallback said yes but we don't know the subtype


# ─── Stage 1: name heuristics ────────────────────────────────────────────────

# (pattern, category) — checked left-to-right, first match wins
_NAME_RULES: list[tuple[re.Pattern, PiiCategory]] = [
    (re.compile(r"\bSSN\b|\bSIN\b|\bNIN\b|\bTIN\b|\bTFN\b"), PiiCategory.NATIONAL_ID),
    (re.compile(r"\bCARD\b|\bCCN\b|\bPAN\b|\bIBAN\b|\bBIC\b"), PiiCategory.FINANCIAL),
    (re.compile(r"\bACCT\b|\bACCOUNT\b"), PiiCategory.FINANCIAL),
    (re.compile(r"\bDOB\b|\bBIRTH\b|\bBDAY\b"), PiiCategory.DATE_OF_BIRTH),
    (re.compile(r"\bNAME\b|\bFNAME\b|\bLNAME\b|\bMNAME\b|\bSURNAME\b"), PiiCategory.NAME),
    (re.compile(r"\bEMAIL\b|\bMAIL\b"), PiiCategory.CONTACT),
    (re.compile(r"\bPHONE\b|\bMOBILE\b|\bFAX\b|\bTEL\b"), PiiCategory.CONTACT),
    (re.compile(r"\bADDR\b|\bSTREET\b|\bZIP\b|\bPOSTAL\b|\bCITY\b"), PiiCategory.CONTACT),
    (re.compile(r"\bDIAG\b|\bMED\b|\bPATIENT\b|\bCLINIC\b|\bRX\b"), PiiCategory.HEALTH),
    (re.compile(r"\bPOLICY\b|\bCLAIM\b|\bMEMBER\b|\bSUBSCR\b"), PiiCategory.IDENTIFIER),
    (re.compile(r"\bCUST\b|\bCLIENT\b|\bPERSON\b|\bINDIV\b"), PiiCategory.IDENTIFIER),
    (re.compile(r"\bGPS\b|\bLAT\b|\bLONG\b|\bLOCATION\b|\bGEO\b"), PiiCategory.LOCATION),
]


def _check_name_heuristic(field_name: str) -> Optional[PiiCategory]:
    upper = field_name.upper()
    for pattern, category in _NAME_RULES:
        if pattern.search(upper):
            return category
    return None


# ─── Stage 2: PIC heuristics ─────────────────────────────────────────────────

# PIC strings that are characteristic of specific PII shapes.
# (pic_pattern, field_name_hint, category)
_PIC_RULES: list[tuple[re.Pattern, Optional[re.Pattern], PiiCategory]] = [
    # 9(09) or 9(9) → SSN shape (exactly 9 digits)
    (re.compile(r"^9\(09\)$|^9{9}$"), None, PiiCategory.NATIONAL_ID),
    # X(16) or 9(16) → payment card number shape
    (re.compile(r"^[X9]\(16\)$|^[X9]{16}$"), None, PiiCategory.FINANCIAL),
    # X(34) → IBAN shape
    (re.compile(r"^X\(34\)$"), None, PiiCategory.FINANCIAL),
    # X(10) field named DOB/DATE → date of birth
    (re.compile(r"^X\(10\)$|^9\(8\)$"),
     re.compile(r"DOB|DATE|BIRTH|BDAY"),
     PiiCategory.DATE_OF_BIRTH),
    # X(25..50) field named NAME/ADDR → name or address string
    (re.compile(r"^X\((?:2[0-9]|[3-9][0-9]|[1-9][0-9]{2})\)$"),
     re.compile(r"NAME|ADDR|STREET|EMAIL"),
     PiiCategory.NAME),
    # X(10..15) field named PHONE → phone number
    (re.compile(r"^X\((?:1[0-5]|[7-9])\)$"),
     re.compile(r"PHONE|TEL|MOBILE|FAX"),
     PiiCategory.CONTACT),
]


def _check_pic_heuristic(field_name: str, picture: str) -> Optional[PiiCategory]:
    if not picture:
        return None
    pic = picture.upper().replace(" ", "")
    upper_name = field_name.upper()
    for pic_pattern, name_hint, category in _PIC_RULES:
        if pic_pattern.match(pic):
            if name_hint is None or name_hint.search(upper_name):
                return category
    return None


# ─── Stage 3: Groq LLM fallback ──────────────────────────────────────────────

_LLM_SYSTEM_PROMPT = """You are a GDPR compliance expert analysing legacy COBOL data fields.

Your task: given a COBOL field name and its PIC clause, decide if it is likely to
hold Personal Identifiable Information (PII) as defined by GDPR Article 4(1).

Reply with exactly one of:
  YES <CATEGORY>
  NO

Where CATEGORY (only when YES) is one of:
  national_id | financial | name | contact | health | date_of_birth | location | identifier

Be conservative — if you are not sure, reply NO.
Do NOT explain your reasoning. Do NOT add any other text."""


def _call_groq_llm(
    field_name: str,
    picture:    str,
    context_lines: list[str],
    api_key:    str,
    model:      str,
) -> Optional[PiiCategory]:
    """
    Call the Groq API to classify a single ambiguous field.

    Returns a PiiCategory if the LLM says YES, else None.
    Logs a warning and returns None on API errors.
    """
    try:
        from groq import Groq  # type: ignore
    except ImportError:
        logger.warning("groq package not installed — skipping LLM fallback")
        return None

    context = "\n".join(context_lines[:5]) if context_lines else "(no context)"
    user_msg = (
        f"Field name: {field_name}\n"
        f"PIC clause: {picture or '(none)'}\n"
        f"Surrounding COBOL lines:\n{context}\n\n"
        "Is this field PII?"
    )

    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model    = model,
            messages = [
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            max_tokens  = 16,
            temperature = 0.0,
        )
        reply = response.choices[0].message.content.strip().upper()
        logger.debug("Groq reply for %s: %r", field_name, reply)

        if reply.startswith("YES"):
            parts = reply.split()
            if len(parts) >= 2:
                cat_name = parts[1].strip()
                _MAP = {
                    "NATIONAL_ID":    PiiCategory.NATIONAL_ID,
                    "FINANCIAL":      PiiCategory.FINANCIAL,
                    "NAME":           PiiCategory.NAME,
                    "CONTACT":        PiiCategory.CONTACT,
                    "HEALTH":         PiiCategory.HEALTH,
                    "DATE_OF_BIRTH":  PiiCategory.DATE_OF_BIRTH,
                    "LOCATION":       PiiCategory.LOCATION,
                    "IDENTIFIER":     PiiCategory.IDENTIFIER,
                }
                return _MAP.get(cat_name, PiiCategory.UNKNOWN_PII)
            return PiiCategory.UNKNOWN_PII
        return None

    except Exception as exc:
        logger.warning("Groq API error for field %s: %s", field_name, exc)
        return None


# ─── Main tagger class ────────────────────────────────────────────────────────

class PiiTagger:
    """
    Tags DATA_ITEM nodes in a CPG as PII sources.

    Parameters
    ----------
    groq_api_key : str | None
        Groq API key.  If None, stage 3 is disabled.
    model : str
        Groq model ID (default: llama3-8b-8192 — fast and cheap).
    llm_threshold : int
        Maximum number of LLM calls per analysis run (guard against quota burn).
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        model:        str           = "llama3-8b-8192",
        llm_threshold: int          = 50,
    ):
        self._api_key      = groq_api_key or os.getenv("GROQ_API_KEY", "")
        self._model        = model
        self._llm_limit    = llm_threshold
        self._llm_calls    = 0
        self._stats        = {"name": 0, "pic": 0, "llm": 0, "none": 0}

    # ─── Public API ───────────────────────────────────────────────────────────

    def tag(self, cpg: CPG) -> dict[int, PiiCategory]:
        """
        Iterate over all DATA_ITEM nodes in *cpg*, classify each, and
        write results back into the graph.

        Returns
        -------
        dict[node_id, PiiCategory]
            All nodes classified as PII, for downstream inspection.
        """
        results: dict[int, PiiCategory] = {}

        for nid, data in cpg.G.nodes(data=True):
            if data.get("kind") != NodeKind.DATA_ITEM:
                continue

            stmt = data.get("stmt")
            if stmt is None:
                continue

            field_name = getattr(stmt, "name", "")
            picture    = getattr(stmt, "picture", "") or ""

            category = self._classify(field_name, picture)
            if category is not None:
                cpg.tag_pii(nid, field_name)
                cpg.G.nodes[nid]["pii_category"] = category
                results[nid] = category

        logger.info(
            "PII tagging complete — name:%d  pic:%d  llm:%d  none:%d",
            self._stats["name"], self._stats["pic"],
            self._stats["llm"], self._stats["none"],
        )
        return results

    # ─── Classification pipeline ──────────────────────────────────────────────

    def _classify(
        self,
        field_name: str,
        picture:    str,
        context:    Optional[list[str]] = None,
    ) -> Optional[PiiCategory]:

        # Stage 1: name heuristics
        cat = _check_name_heuristic(field_name)
        if cat is not None:
            self._stats["name"] += 1
            logger.debug("PII[name] %s → %s", field_name, cat.name)
            return cat

        # Stage 2: PIC heuristics
        cat = _check_pic_heuristic(field_name, picture)
        if cat is not None:
            self._stats["pic"] += 1
            logger.debug("PII[pic] %s %s → %s", field_name, picture, cat.name)
            return cat

        # Stage 3: LLM fallback (only for truly ambiguous fields)
        if self._api_key and self._llm_calls < self._llm_limit:
            self._llm_calls += 1
            cat = _call_groq_llm(
                field_name    = field_name,
                picture       = picture,
                context_lines = context or [],
                api_key       = self._api_key,
                model         = self._model,
            )
            if cat is not None:
                self._stats["llm"] += 1
                logger.debug("PII[llm] %s → %s", field_name, cat.name)
                return cat

        self._stats["none"] += 1
        return None

    # ─── Diagnostics ──────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        return dict(self._stats)