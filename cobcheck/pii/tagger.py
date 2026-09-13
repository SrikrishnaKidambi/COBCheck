"""
cobcheck/pii/tagger.py
──────────────────────

Tags DATA_ITEM nodes in the CPG as potential personal-data sources.

Pipeline:

    Stage 1 — Deterministic detection
        1. Privado YAML rules, when available.
        2. COBOL-adapted Privado semantic categories.
        3. COBOL-specific name heuristics.
        4. PIC-based evidence.

    Stage 2 — Context analysis
        Uses nearby declarations and connected CPG nodes to identify
        ambiguous fields through deterministic contextual evidence.

    Stage 3 — Groq LLM fallback
        Used only when stages 1 and 2 cannot make a decision.

The tagger records the detection method and metadata in the CPG so that
results can later be evaluated and explained in research experiments.
"""

from __future__ import annotations

from collections import Counter
from enum import Enum, auto
from typing import Optional
import logging
import os
import re

from ..cpg.graph_model import CPG, NodeKind
from .privado_rules import (
    PrivadoMatch,
    match_privado_source,
    normalize_identifier,
)

logger = logging.getLogger(__name__)


# ─── PII categories ──────────────────────────────────────────────────────────

class PiiCategory(Enum):
    ACCOUNT = auto()
    AUDIO_VISUAL_SENSORY = auto()
    BACKGROUND_CHECK = auto()
    BIOMETRIC = auto()
    CONTACT = auto()
    EDUCATION = auto()
    FINANCIAL = auto()
    HEALTH = auto()
    LOCATION = auto()
    NATIONAL_ID = auto()
    ONLINE_IDENTIFIER = auto()
    PERSONAL_CHARACTERISTICS = auto()
    IDENTIFIER = auto()
    EMPLOYMENT = auto()
    PURCHASE = auto()
    SOCIAL_MEDIA = auto()
    FAMILY = auto()
    TECHNICAL = auto()
    USAGE = auto()
    USER_CONTENT = auto()
    VEHICLE = auto()
    WORKPLACE_MONITORING = auto()
    DATE_OF_BIRTH = auto()

    # Art. 9(1) GDPR special categories (closed list — gdpr-info.eu/art-9-gdpr).
    # HEALTH and BIOMETRIC already existed above for other reasons (general
    # health-adjacent and biometric-adjacent fields); they are ALSO special
    # category under Art. 9 and are included in PII_ART9_SPECIAL_CATEGORIES
    # below. These five are categories Art. 9 names that had no equivalent
    # in the taxonomy before:
    RACIAL_ETHNIC_ORIGIN = auto()
    POLITICAL_OPINION = auto()
    RELIGIOUS_OR_PHILOSOPHICAL_BELIEF = auto()
    TRADE_UNION_MEMBERSHIP = auto()
    GENETIC = auto()
    SEXUAL_ORIENTATION_OR_SEX_LIFE = auto()

    # Art. 10 GDPR — criminal convictions/offences. Textually adjacent to
    # Art. 9 (both get processing restrictions beyond ordinary personal
    # data) but is a SEPARATE article with a separate condition (official
    # authority / specific legal basis, not the Art. 9(2) exception list) —
    # kept as its own category rather than folded into special-category.
    CRIMINAL_OFFENCE_DATA = auto()

    UNKNOWN_PII = auto()


# Art. 9(1): "special categories of personal data" — processing is
# prohibited by default unless an Art. 9(2) exception applies. This is a
# CLOSED list per the article text; nothing outside it belongs here.
PII_ART9_SPECIAL_CATEGORIES = frozenset({
    PiiCategory.RACIAL_ETHNIC_ORIGIN,
    PiiCategory.POLITICAL_OPINION,
    PiiCategory.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
    PiiCategory.TRADE_UNION_MEMBERSHIP,
    PiiCategory.GENETIC,
    PiiCategory.BIOMETRIC,       # "for the purpose of uniquely identifying"
    PiiCategory.HEALTH,
    PiiCategory.SEXUAL_ORIENTATION_OR_SEX_LIFE,
})

# Art. 10: personal data relating to criminal convictions and offences —
# a distinct article from Art. 9, not part of the closed list above.
PII_ART10_CRIMINAL_DATA = frozenset({
    PiiCategory.CRIMINAL_OFFENCE_DATA,
})


# ─── Privado category mapping ────────────────────────────────────────────────

_PRIVADO_CATEGORY_MAP = {
    "ACCOUNT DATA": PiiCategory.ACCOUNT,
    "AUDIO VISUAL SENSORY DATA": PiiCategory.AUDIO_VISUAL_SENSORY,
    "BACKGROUND CHECK DATA": PiiCategory.BACKGROUND_CHECK,
    "BIOMETRIC DATA": PiiCategory.BIOMETRIC,
    "CONTACT DATA": PiiCategory.CONTACT,
    "EDUCATION BACKGROUND DATA": PiiCategory.EDUCATION,
    "FINANCIAL DATA": PiiCategory.FINANCIAL,
    "HEALTH DATA": PiiCategory.HEALTH,
    "LOCATION DATA": PiiCategory.LOCATION,
    "NATIONAL IDENTIFICATION NUMBERS": PiiCategory.NATIONAL_ID,
    "ONLINE IDENTIFIERS": PiiCategory.ONLINE_IDENTIFIER,
    "PERSONAL CHARACTERISTICS": PiiCategory.PERSONAL_CHARACTERISTICS,
    "PERSONAL IDENTIFICATION": PiiCategory.IDENTIFIER,
    "PROFESSIONAL EMPLOYMENT BACKGROUND DATA": PiiCategory.EMPLOYMENT,
    "PURCHASE DATA": PiiCategory.PURCHASE,
    "SOCIAL MEDIA DATA": PiiCategory.SOCIAL_MEDIA,
    "SPOUSE FAMILY DEPENDEND DATA": PiiCategory.FAMILY,
    "TECHNICAL DATA": PiiCategory.TECHNICAL,
    "USAGE DATA": PiiCategory.USAGE,
    "USER CONTENT DATA": PiiCategory.USER_CONTENT,
    "VEHICLE DATA": PiiCategory.VEHICLE,
    "WORKPLACE MONITORING DATA": PiiCategory.WORKPLACE_MONITORING,
}


# ─── Stage 1: supplementary COBOL heuristics ─────────────────────────────────

_NAME_RULES: tuple[
    tuple[re.Pattern[str], PiiCategory],
    ...
] = (
    (
        re.compile(
            r"\b(?:DOB|BIRTH DATE|BIRTHDAY)\b",
            re.IGNORECASE,
        ),
        PiiCategory.DATE_OF_BIRTH,
    ),
    (
        re.compile(
            r"\b(?:SSN|SIN|NIN|TIN|TFN|AADHAAR)\b",
            re.IGNORECASE,
        ),
        PiiCategory.NATIONAL_ID,
    ),
    (
        re.compile(
            r"\b(?:IBAN|SWIFT|BIC|CVV|CVC|CCN|PAN)\b",
            re.IGNORECASE,
        ),
        PiiCategory.FINANCIAL,
    ),

    # Art. 9(1) special categories — name-heuristic only; Privado's own
    # taxonomy strings for these are not known to us, so there is no
    # corresponding _PRIVADO_CATEGORY_MAP entry (see note there).
    (
        re.compile(
            r"\b(?:RACE|RACIAL|ETHNIC|ETHNICITY)\b",
            re.IGNORECASE,
        ),
        PiiCategory.RACIAL_ETHNIC_ORIGIN,
    ),
    (
        re.compile(
            r"\b(?:POLITICAL|PARTY[-_]?AFFIL)\b",
            re.IGNORECASE,
        ),
        PiiCategory.POLITICAL_OPINION,
    ),
    (
        re.compile(
            r"\b(?:RELIGION|RELIGIOUS|CREED|FAITH)\b",
            re.IGNORECASE,
        ),
        PiiCategory.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
    ),
    (
        re.compile(
            r"\b(?:UNION|TRADE[-_]?UNION)\b",
            re.IGNORECASE,
        ),
        PiiCategory.TRADE_UNION_MEMBERSHIP,
    ),
    (
        re.compile(
            r"\b(?:GENETIC|DNA|GENOME)\b",
            re.IGNORECASE,
        ),
        PiiCategory.GENETIC,
    ),
    (
        re.compile(
            r"\b(?:SEXUAL[-_]?ORIENT|SEX[-_]?LIFE)\b",
            re.IGNORECASE,
        ),
        PiiCategory.SEXUAL_ORIENTATION_OR_SEX_LIFE,
    ),

    # Art. 10 — a separate article from Art. 9, kept as its own category.
    (
        re.compile(
            r"\b(?:CRIMINAL|CONVICTION|OFFENSE|OFFENCE)\b",
            re.IGNORECASE,
        ),
        PiiCategory.CRIMINAL_OFFENCE_DATA,
    ),
)


def _check_name_heuristic(
    field_name: str,
) -> Optional[PiiCategory]:

    normalized = normalize_identifier(
        field_name
    )

    for pattern, category in _NAME_RULES:

        if pattern.search(normalized):
            return category

    return None


# ─── Stage 1: PIC heuristics ─────────────────────────────────────────────────

_PIC_RULES: tuple[
    tuple[
        re.Pattern[str],
        Optional[re.Pattern[str]],
        PiiCategory,
    ],
    ...
] = (

    (
        re.compile(
            r"^(?:9\(09\)|9{9})$"
        ),
        re.compile(
            r"\b(?:SSN|SIN|NIN|TIN|ID)\b",
            re.IGNORECASE,
        ),
        PiiCategory.NATIONAL_ID,
    ),

    (
        re.compile(
            r"^(?:X|9)\(16\)$|^[X9]{16}$"
        ),
        re.compile(
            r"\b(?:CARD|PAN|PAYMENT)\b",
            re.IGNORECASE,
        ),
        PiiCategory.FINANCIAL,
    ),

    (
        re.compile(
            r"^X\(34\)$"
        ),
        re.compile(
            r"\b(?:IBAN|BANK|ACCOUNT)\b",
            re.IGNORECASE,
        ),
        PiiCategory.FINANCIAL,
    ),

    (
        re.compile(
            r"^(?:X\(10\)|9\(8\))$"
        ),
        re.compile(
            r"\b(?:DOB|DATE|BIRTH)\b",
            re.IGNORECASE,
        ),
        PiiCategory.DATE_OF_BIRTH,
    ),

    (
        re.compile(
            r"^X\((?:[2-9][0-9]|[1-9][0-9]{2,})\)$"
        ),
        re.compile(
            r"\b(?:NAME|ADDRESS|EMAIL)\b",
            re.IGNORECASE,
        ),
        PiiCategory.CONTACT,
    ),

    (
        re.compile(
            r"^X\((?:1[0-5]|[7-9])\)$"
        ),
        re.compile(
            r"\b(?:PHONE|TEL|MOBILE|FAX)\b",
            re.IGNORECASE,
        ),
        PiiCategory.CONTACT,
    ),
)


def _check_pic_heuristic(
    field_name: str,
    picture: str,
) -> Optional[PiiCategory]:

    if not picture:
        return None

    pic = (
        picture.upper()
        .replace(" ", "")
    )

    normalized_name = normalize_identifier(
        field_name
    )

    for pic_pattern, name_hint, category in _PIC_RULES:

        if not pic_pattern.fullmatch(pic):
            continue

        if (
            name_hint is None
            or name_hint.search(normalized_name)
        ):
            return category

    return None


# ─── Stage 2: deterministic context analysis ─────────────────────────────────

def _extract_context(
    cpg: CPG,
    nid: int,
    limit: int = 12,
) -> list[str]:
    """
    Extract useful local context from:

    - neighbouring CPG nodes,
    - nearby DATA_ITEM declarations in the same program,
    - the current field's program metadata.

    This deliberately does not depend on a particular AST shape.
    """

    node = cpg.G.nodes[nid]

    context: list[str] = []

    program = str(
        node.get("program", "")
    )

    line = node.get("line", 0)

    if program:
        context.append(
            f"PROGRAM {program}"
        )

    # ── Graph neighbours ──────────────────────────────────────────────────

    neighbours = list(
        cpg.G.predecessors(nid)
    ) + list(
        cpg.G.successors(nid)
    )

    seen: set[int] = set()

    for other_nid in neighbours:

        if other_nid in seen:
            continue

        seen.add(other_nid)

        other = cpg.G.nodes.get(
            other_nid,
            {},
        )

        stmt = other.get("stmt")

        if stmt is not None:

            name = getattr(
                stmt,
                "name",
                "",
            )

            if name:
                context.append(str(name))

        if len(context) >= limit:
            return context[:limit]

    return context[:limit]


def _check_context(
    field_name: str,
    context_lines: list[str],
) -> Optional[PiiCategory]:
    """
    Classify an ambiguous field using deterministic context.

    The field itself is combined with nearby identifiers and each
    contextual identifier is checked against the Privado-derived matcher.
    """

    if not context_lines:
        return None

    category_votes: Counter[
        PiiCategory
    ] = Counter()

    for context in context_lines:

        match = match_privado_source(
            context
        )

        if match is None:
            continue

        category = _category_from_privado(
            match
        )

        if category is not None:
            category_votes[category] += 1

    if not category_votes:
        return None

    category, votes = (
        category_votes.most_common(1)[0]
    )

    # One random nearby declaration is not enough evidence.
    if votes < 2:
        return None

    logger.debug(
        "PII[context] %s -> %s "
        "(votes=%d)",
        field_name,
        category.name,
        votes,
    )

    return category


# ─── Category conversion ─────────────────────────────────────────────────────

def _category_from_privado(
    match: PrivadoMatch,
) -> Optional[PiiCategory]:

    category_name = (
        match.category
        .strip()
        .upper()
    )

    return _PRIVADO_CATEGORY_MAP.get(
        category_name
    )


# ─── Stage 3: Groq LLM fallback ──────────────────────────────────────────────

_LLM_SYSTEM_PROMPT = """
You are analysing a legacy COBOL application for GDPR compliance.

Determine whether the COBOL field likely stores personal data under
GDPR Article 4(1).

Reply with exactly one of:

YES <CATEGORY>
NO

CATEGORY must be one of:

account
audio_visual_sensory
background_check
biometric
contact
education
financial
health
location
national_id
online_identifier
personal_characteristics
identifier
employment
purchase
social_media
family
technical
usage
user_content
vehicle
workplace_monitoring
date_of_birth

Use surrounding COBOL context as evidence.

Be conservative.
If evidence is insufficient, reply NO.
Do not explain your answer.
""".strip()


_LLM_CATEGORY_MAP = {
    "ACCOUNT": PiiCategory.ACCOUNT,
    "AUDIO_VISUAL_SENSORY": (
        PiiCategory.AUDIO_VISUAL_SENSORY
    ),
    "BACKGROUND_CHECK": (
        PiiCategory.BACKGROUND_CHECK
    ),
    "BIOMETRIC": PiiCategory.BIOMETRIC,
    "CONTACT": PiiCategory.CONTACT,
    "EDUCATION": PiiCategory.EDUCATION,
    "FINANCIAL": PiiCategory.FINANCIAL,
    "HEALTH": PiiCategory.HEALTH,
    "LOCATION": PiiCategory.LOCATION,
    "NATIONAL_ID": PiiCategory.NATIONAL_ID,
    "ONLINE_IDENTIFIER": (
        PiiCategory.ONLINE_IDENTIFIER
    ),
    "PERSONAL_CHARACTERISTICS": (
        PiiCategory.PERSONAL_CHARACTERISTICS
    ),
    "IDENTIFIER": PiiCategory.IDENTIFIER,
    "EMPLOYMENT": PiiCategory.EMPLOYMENT,
    "PURCHASE": PiiCategory.PURCHASE,
    "SOCIAL_MEDIA": PiiCategory.SOCIAL_MEDIA,
    "FAMILY": PiiCategory.FAMILY,
    "TECHNICAL": PiiCategory.TECHNICAL,
    "USAGE": PiiCategory.USAGE,
    "USER_CONTENT": PiiCategory.USER_CONTENT,
    "VEHICLE": PiiCategory.VEHICLE,
    "WORKPLACE_MONITORING": (
        PiiCategory.WORKPLACE_MONITORING
    ),
    "DATE_OF_BIRTH": PiiCategory.DATE_OF_BIRTH,
}


def _call_groq_llm(
    field_name: str,
    picture: str,
    context_lines: list[str],
    api_key: str,
    model: str,
) -> Optional[PiiCategory]:

    try:
        from groq import Groq  # type: ignore

    except ImportError:

        logger.warning(
            "groq package not installed; "
            "skipping LLM fallback"
        )

        return None

    context = (
        "\n".join(context_lines[:12])
        if context_lines
        else "(no context)"
    )

    user_msg = (
        f"Field name: {field_name}\n"
        f"PIC clause: "
        f"{picture or '(none)'}\n"
        f"Relevant COBOL context:\n"
        f"{context}\n\n"
        "Is this field personal data?"
    )

    try:

        client = Groq(
            api_key=api_key
        )

        response = (
            client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            _LLM_SYSTEM_PROMPT
                        ),
                    },
                    {
                        "role": "user",
                        "content": user_msg,
                    },
                ],
                max_tokens=16,
                temperature=0.0,
            )
        )

        reply = (
            response
            .choices[0]
            .message.content
            .strip()
            .upper()
        )

        if not reply.startswith("YES"):
            return None

        parts = reply.split()

        if len(parts) < 2:
            return PiiCategory.UNKNOWN_PII

        return _LLM_CATEGORY_MAP.get(
            parts[1],
            PiiCategory.UNKNOWN_PII,
        )

    except Exception as exc:

        logger.warning(
            "Groq API error for %s: %s",
            field_name,
            exc,
        )

        return None


# ─── Main tagger ─────────────────────────────────────────────────────────────

class PiiTagger:
    """
    Classify COBOL DATA_ITEM declarations as personal-data sources.

    Pipeline:

        Stage 1:
            Privado + COBOL deterministic detection.

        Stage 2:
            Deterministic contextual evidence.

        Stage 3:
            LLM fallback.
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        model: str = "llama3-8b-8192",
        llm_threshold: int = 50,
    ):

        self._api_key = (
            groq_api_key
            or os.getenv(
                "GROQ_API_KEY",
                "",
            )
        )

        self._model = model
        self._llm_limit = llm_threshold
        self._llm_calls = 0

        self._stats = {
            "privado": 0,
            "name": 0,
            "pic": 0,
            "context": 0,
            "llm": 0,
            "none": 0,
        }

    def tag(
        self,
        cpg: CPG,
    ) -> dict[int, PiiCategory]:

        results: dict[
            int,
            PiiCategory,
        ] = {}

        for nid, data in cpg.G.nodes(
            data=True
        ):

            if (
                data.get("kind")
                != NodeKind.DATA_ITEM
            ):
                continue

            if data.get("is_group"):
                # Group items (01-level records etc.) are never an
                # independent PII source. They correctly carry taint
                # via CONTAINS propagation from whichever elementary
                # children are real PII (see cpg/builder.py) — tagging
                # them here as well would double-count the same
                # underlying field and also falsely tag groups whose
                # children happen to be declared nearby but are
                # unrelated.
                continue

            stmt = data.get("stmt")

            if stmt is None:
                continue

            field_name = (
                getattr(
                    stmt,
                    "name",
                    "",
                )
                or ""
            )

            picture = (
                getattr(
                    stmt,
                    "picture",
                    "",
                )
                or ""
            )

            context = _extract_context(
                cpg,
                nid,
            )

            category, detection = (
                self._classify(
                    field_name,
                    picture,
                    context,
                )
            )

            if category is None:
                continue

            cpg.tag_pii(
                nid,
                field_name,
            )

            node = cpg.G.nodes[nid]

            node["pii_category"] = category
            node["pii_detection"] = detection

            results[nid] = category

        logger.info(
            "PII tagging complete — "
            "privado:%d name:%d pic:%d "
            "context:%d llm:%d none:%d",
            self._stats["privado"],
            self._stats["name"],
            self._stats["pic"],
            self._stats["context"],
            self._stats["llm"],
            self._stats["none"],
        )

        return results

    def _classify(
        self,
        field_name: str,
        picture: str,
        context: list[str],
    ) -> tuple[
        Optional[PiiCategory],
        Optional[str],
    ]:

        # ── Stage 1A: Privado-derived rules ──────────────────────────────

        privado_match = (
            match_privado_source(
                field_name
            )
        )

        if privado_match is not None:

            category = _category_from_privado(
                privado_match
            )

            if category is not None:

                self._stats["privado"] += 1

                return (
                    category,
                    privado_match.source,
                )

        # ── Stage 1B: COBOL name heuristics ──────────────────────────────

        category = _check_name_heuristic(
            field_name
        )

        if category is not None:

            self._stats["name"] += 1

            return (
                category,
                "cobol_name",
            )

        # ── Stage 1C: PIC heuristics ─────────────────────────────────────

        category = _check_pic_heuristic(
            field_name,
            picture,
        )

        if category is not None:

            self._stats["pic"] += 1

            return (
                category,
                "pic",
            )

        # ── Stage 2: deterministic context ───────────────────────────────

        category = _check_context(
            field_name,
            context,
        )

        if category is not None:

            self._stats["context"] += 1

            return (
                category,
                "context",
            )

        # ── Stage 3: LLM fallback ────────────────────────────────────────

        if (
            self._api_key
            and self._llm_calls
            < self._llm_limit
        ):

            self._llm_calls += 1

            category = _call_groq_llm(
                field_name=field_name,
                picture=picture,
                context_lines=context,
                api_key=self._api_key,
                model=self._model,
            )

            if category is not None:

                self._stats["llm"] += 1

                return (
                    category,
                    "llm",
                )

        self._stats["none"] += 1

        return (
            None,
            None,
        )

    @property
    def stats(self) -> dict:
        return dict(self._stats)