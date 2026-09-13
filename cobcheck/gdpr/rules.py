"""
cobcheck/gdpr/rules.py
───────────────────────
GDPR rule definitions R1–R6, grounded in the article text at
https://gdpr-info.eu/ (Art. 4, 5, 6, 9, 10, 32, 44).

Rule → Article → Fires When → Neutralised By
─────────────────────────────────────────────────────────────────────────────
R1   Art. 5(1)(f) + 32   any PII -> log/display, unmasked         sanitiser on path
R2   Art. 6(1)           any PII -> any sink, no basis indicator  guard on path
R3   Art. 44             any PII -> external/cross-border sink    (structural)
R4   Art. 5(1)(f) + 32   any PII -> file/DB at-rest, unencrypted  sanitiser on path
R5   Art. 9              special-category PII -> any sink,        explicit-consent
                          no explicit-consent indicator             guard on path
R6   Art. 10             criminal-offence PII -> any sink          (structural — flag
                                                                     for review)

Article grounding (gdpr-info.eu, checked against the live text):
  - Art. 4(1): personal data = any information relating to an identified or
    identifiable natural person, e.g. by name, ID number, or other
    identifying factor. This is the baseline that makes ANY tagged PII
    field relevant to R1/R2/R3/R4, regardless of category.
  - Art. 5(1)(f): the "integrity and confidentiality" principle — personal
    data must be processed with appropriate security against unauthorised
    or unlawful processing and against accidental loss/damage. Art. 32 is
    the concrete obligation that implements this principle, so the two are
    cited together for R1/R4, matching how they are cited in practice.
  - Art. 6(1): processing is lawful ONLY if at least one of six bases
    applies — (a) consent, (b) contract, (c) legal obligation, (d) vital
    interests, (e) public task, (f) legitimate interests. A missing
    consent-flag in code is evidence of a missing basis-check, NOT proof
    that no lawful basis exists — (b)-(f) are not things a consent flag
    would represent, and a static tool cannot verify them. R2's wording
    reflects this rather than treating "no consent flag" as "unlawful".
  - Art. 9(1): a CLOSED list of special categories (racial/ethnic origin,
    political opinions, religious/philosophical beliefs, trade union
    membership, genetic data, biometric data for unique identification,
    health data, sex life/sexual orientation) is prohibited by default.
    Art. 9(2) lists ten exceptions; only (a) explicit consent is something
    a static analysis can plausibly look for as a code-level guard, so R5
    only recognises that one. Masking/encryption does NOT cure an Art. 9
    problem (the prohibition is on the processing itself), so — unlike
    R1/R4 — R5 is not neutralised by `sanitised`.
  - Art. 10: personal data relating to criminal convictions/offences is a
    SEPARATE article from Art. 9 with its own condition (official
    authority or specific legal basis). A static tool cannot verify
    "official authority", so R6 flags any such field reaching any sink
    for manual review rather than asserting a definite violation.
  - Art. 44: the general principle anchoring Chapter V — any transfer to a
    third country/international organisation must comply with the
    conditions in Art. 45-49 (adequacy / safeguards / BCRs / derogations).
    A static COBOL analysis can observe that data reaches an
    external-looking sink; it cannot determine which Art. 45-49 mechanism
    (if any) governs that transfer, so R3 cites Art. 44 as the engaged
    principle rather than asserting which specific downstream article is
    satisfied or violated.

Each rule is a function:

    rule_fn(flow: TaintFlow) -> Violation | None

The RuleEngine calls all rules over every TaintFlow and collects violations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable

from ..cpg.graph_model import SinkKind
from ..taint.engine import TaintFlow
from ..pii.tagger import (
    PII_ART9_SPECIAL_CATEGORIES,
    PII_ART10_CRIMINAL_DATA,
)


# ─── Category name-sets (pii_category on a flow is a .name string) ────────────

_ART9_CATEGORY_NAMES  = {c.name for c in PII_ART9_SPECIAL_CATEGORIES}
_ART10_CATEGORY_NAMES = {c.name for c in PII_ART10_CRIMINAL_DATA}


# ─── Violation record (frozen schema — matches JSON report exactly) ────────────

@dataclass
class Violation:
    """
    Matches the JSON schema in the brief exactly.
    The report emitter serialises this to JSON.
    """
    violation_id:     str = ""
    rule_id:          str = ""
    gdpr_article:     str = ""
    severity:         str = "high"
    pii_field:        str = ""
    pii_category:     str = ""
    source_program:   str = ""
    source_copybook:  str = ""
    source_line:      int = 0
    sink_kind:        str = ""
    sink_program:     str = ""
    sink_line:        int = 0
    flow_path:        list[dict] = field(default_factory=list)
    sanitised:        bool = False
    consent_checked:  bool = False
    remediation:      str = ""


# ─── Rule implementations ─────────────────────────────────────────────────────

RuleFunction = Callable[[TaintFlow], Optional[Violation]]

_LOG_DISPLAY_SINKS = {SinkKind.LOGGING}
_AT_REST_SINKS     = {SinkKind.FILE_STORAGE, SinkKind.DATABASE}
_EXTERNAL_SINKS    = {SinkKind.NETWORK_TRANSFER, SinkKind.CONTENT_OR_SERVICE, SinkKind.MESSAGING}


def _base_violation(flow: TaintFlow, rule_id: str, article: str, severity: str) -> Violation:
    return Violation(
        rule_id         = rule_id,
        gdpr_article    = article,
        severity        = severity,
        pii_field       = flow.pii_field,
        pii_category    = flow.pii_category,
        sink_kind       = flow.sink_kind.name.lower(),
        sink_program    = flow.sink_program,
        sink_line       = flow.sink_line,
        sanitised       = flow.sanitised,
        consent_checked = flow.consent_checked,
    )


def rule_R1(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 5(1)(f) + Art. 32 — Integrity/confidentiality principle and its
    concrete security-of-processing obligation.
    Any personal data (Art. 4(1)) reaches a log/display output without
    masking. Applies regardless of category — the security obligation in
    Art. 32(1) is not limited to special-category data.
    """
    if flow.sink_kind not in _LOG_DISPLAY_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R1", "Art. 5(1)(f) / Art. 32", "high")
    v.remediation = (
        f"Mask or encrypt {flow.pii_field} before writing to "
        f"the {flow.sink_kind.name.lower()} sink in {flow.sink_program} "
        "(Art. 32(1)(a) names pseudonymisation/encryption as an example measure)."
    )
    return v


def rule_R2(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 6(1) — Lawfulness of processing.
    No basis-check indicator (the only proxy a static tool can look for is
    a consent-flag guard) was found on the path. This flags an ABSENCE OF
    DETECTABLE EVIDENCE of a lawful basis — consent is only one of six
    Art. 6(1) bases, so this is not proof processing is actually unlawful;
    it is a prompt to confirm which basis (a)-(f) applies and, if it is
    consent, that Art. 7's conditions are met.
    """
    if flow.consent_checked:
        return None

    v = _base_violation(flow, "R2", "Art. 6(1)", "medium")
    v.remediation = (
        f"No lawful-basis indicator found on the path to {flow.pii_field}'s "
        f"sink in {flow.sink_program}. Confirm which Art. 6(1) basis applies "
        "(consent, contract, legal obligation, vital interests, public task, "
        "or legitimate interests) and, if consent, that a check such as "
        "IF CONSENT-FLAG = 'Y' actually gates this path."
    )
    return v


def rule_R3(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 44 — General principle for transfers (Chapter V).
    Personal data reaches an external/cross-border-looking sink. Art. 44
    requires the Art. 45-49 conditions (adequacy decision / appropriate
    safeguards / BCRs / derogations) to be met for ANY such transfer; a
    static COBOL analysis can observe the transfer but not which mechanism
    (if any) is in place, so this is structural — it always fires when the
    sink looks external, and does not assert which Art. 45-49 article
    resolves it.
    """
    if flow.sink_kind not in _EXTERNAL_SINKS:
        return None

    v = _base_violation(flow, "R3", "Art. 44", "critical")
    v.remediation = (
        f"{flow.pii_field} appears to be transferred outside the "
        f"processing system from {flow.sink_program}. Confirm an Art. 45 "
        "adequacy decision, Art. 46 appropriate safeguards (e.g. SCCs), "
        "Art. 47 BCRs, or an Art. 49 derogation applies to this transfer."
    )
    return v


def rule_R4(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 5(1)(f) + Art. 32 — Security of processing (at-rest).
    Personal data persisted to a file/database with no encryption marker
    on the path. Same principle/obligation pairing as R1, for storage
    rather than disclosure.
    """
    if flow.sink_kind not in _AT_REST_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R4", "Art. 5(1)(f) / Art. 32", "high")
    v.remediation = (
        f"{flow.pii_field} is written to persistent storage in {flow.sink_program} "
        "without an encryption marker on the path. Apply AES-256 or equivalent "
        "before the WRITE, or store only a pseudonymous key (Art. 32(1)(a))."
    )
    return v


def rule_R5(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 9 — Processing of special categories of personal data.
    Fields tagged with a category on Art. 9(1)'s closed list (racial/ethnic
    origin, political opinions, religious/philosophical beliefs, trade
    union membership, genetic data, biometric data for unique
    identification, health data, sex life/sexual orientation) are
    PROHIBITED by default. Of the ten Art. 9(2) exceptions, only (a)
    explicit consent is something a static analysis can plausibly detect
    as a code-level guard, so this rule fires unless that guard is present.
    NOT neutralised by `sanitised`: masking/encryption addresses Art. 32
    security, not the Art. 9 prohibition on the processing itself.
    """
    if flow.pii_category not in _ART9_CATEGORY_NAMES:
        return None
    if flow.consent_checked:
        return None

    v = _base_violation(flow, "R5", "Art. 9", "critical")
    v.remediation = (
        f"{flow.pii_field} is special-category data under Art. 9(1) "
        f"({flow.pii_category.lower().replace('_', ' ')}) reaching a sink in "
        f"{flow.sink_program} with no explicit-consent indicator on the path. "
        "Processing is prohibited unless one of the Art. 9(2) exceptions "
        "applies — confirm which one, and if it is explicit consent (9(2)(a)), "
        "that a corresponding guard actually gates this path."
    )
    return v


def rule_R6(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 10 — Processing of personal data relating to criminal convictions
    and offences. A separate article from Art. 9 with its own condition:
    processing must be under the control of official authority or
    specifically authorised by law. A static tool cannot verify "official
    authority", so this always fires when such a field reaches any sink —
    it flags the field for manual legal review rather than asserting a
    definite violation.
    """
    if flow.pii_category not in _ART10_CATEGORY_NAMES:
        return None

    v = _base_violation(flow, "R6", "Art. 10", "high")
    v.remediation = (
        f"{flow.pii_field} appears to be criminal-conviction/offence data "
        f"(Art. 10) reaching a sink in {flow.sink_program}. Confirm this "
        "processing is under the control of official authority or "
        "specifically authorised by Union/Member State law."
    )
    return v


# ─── Rule engine ──────────────────────────────────────────────────────────────

ALL_RULES: list[RuleFunction] = [rule_R1, rule_R2, rule_R3, rule_R4, rule_R5, rule_R6]


class RuleEngine:
    """
    Applies all GDPR rules to a list of TaintFlow objects and returns
    a de-duplicated, numbered list of Violation records.

    Parameters
    ----------
    rules : list[RuleFunction]
        Rules to apply (default: ALL_RULES = R1–R6).
    """

    def __init__(self, rules: Optional[list[RuleFunction]] = None):
        self._rules = rules if rules is not None else ALL_RULES
        self._counter = 0

    def run(self, flows: list[TaintFlow], cpg) -> list[Violation]:
        """
        Apply rules to *flows* and return de-duplicated Violation list.

        Parameters
        ----------
        flows : list[TaintFlow]
        cpg   : CPG  (passed through to build flow_path details)
        """
        violations: list[Violation] = []
        seen: set[tuple] = set()  # dedup key

        for flow in flows:
            for rule_fn in self._rules:
                v = rule_fn(flow)
                if v is None:
                    continue

                # De-duplicate: same rule + field + sink line
                key = (v.rule_id, v.pii_field, v.sink_program, v.sink_line)
                if key in seen:
                    continue
                seen.add(key)

                # Assign ID
                self._counter += 1
                v.violation_id = f"V-{self._counter:04d}"

                # Fill source location from CPG
                src_data = cpg.get(flow.source_nid)
                v.source_program  = src_data.get("program", "")
                v.source_copybook = src_data.get("copybook", "")
                v.source_line     = src_data.get("line", 0)

                # Build flow_path list for the report
                v.flow_path = _build_flow_path(flow.path, cpg)

                violations.append(v)

        return violations


def _build_flow_path(path: list[int], cpg) -> list[dict]:
    """
    Convert a list of CPG node IDs into the flow_path format used in the
    JSON report schema.
    """
    result = []
    for nid in path:
        data = cpg.get(nid)
        stmt = data.get("stmt")
        stmt_text = getattr(stmt, "__class__", type(stmt)).__name__
        if hasattr(stmt, "text"):
            stmt_text = stmt.text
        elif hasattr(stmt, "source"):
            stmt_text = (
                f"MOVE {stmt.source} TO "
                f"{', '.join(getattr(stmt, 'destinations', []))}"
            )
        elif hasattr(stmt, "target"):
            stmt_text = f"CALL {stmt.target}"
        result.append({
            "program": data.get("program", ""),
            "line":    data.get("line", 0),
            "stmt":    stmt_text,
        })
    return result