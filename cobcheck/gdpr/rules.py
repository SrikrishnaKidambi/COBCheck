"""
cobcheck/gdpr/rules.py
───────────────────────
GDPR rule definitions R1–R4.

All four rules share the same structure — they differ only in which
sink kinds they fire on and which guards neutralise them.

Rule → Article → Fires When → Neutralised By
──────────────────────────────────────────────
R1   Art. 32 / 5(1)(f)  PII → log/display/print, no masking    sanitiser on path
R2   Art. 6              PII → any sink, no consent-flag check   guard on path
R3   Art. 44–49          PII → external/cross-border sink        (structural — no neutraliser)
R4   Art. 32             PII → file/VSAM at-rest, no encryption  sanitiser on path

Each rule is a function:

    rule_fn(flow: TaintFlow) -> Violation | None

The RuleEngine calls all rules over every TaintFlow and collects violations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable

from ..cpg.graph_model import SinkKind
from ..taint.engine import TaintFlow


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

_LOG_DISPLAY_SINKS = {SinkKind.LOG, SinkKind.DISPLAY, SinkKind.PRINT}
_AT_REST_SINKS     = {SinkKind.FILE}
_EXTERNAL_SINKS    = {SinkKind.EXTERNAL}


def rule_R1(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 32 / 5(1)(f) — Security of processing.
    PII reaches a log, display, or print output without masking/encryption.
    """
    if flow.sink_kind not in _LOG_DISPLAY_SINKS:
        return None
    if flow.sanitised:
        return None

    return Violation(
        rule_id       = "R1",
        gdpr_article  = "Art. 32 / 5(1)(f)",
        severity      = "high",
        pii_field     = flow.pii_field,
        pii_category  = flow.pii_category,
        sink_kind     = flow.sink_kind.name.lower(),
        sink_program  = flow.sink_program,
        sink_line     = flow.sink_line,
        sanitised     = flow.sanitised,
        consent_checked = flow.consent_checked,
        remediation   = (
            f"Mask or encrypt {flow.pii_field} before writing to "
            f"the {flow.sink_kind.name.lower()} sink in {flow.sink_program}."
        ),
    )


def rule_R2(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 6 — Lawfulness of processing.
    PII reaches any sink without a consent-flag check on the path.
    """
    if flow.consent_checked:
        return None

    return Violation(
        rule_id       = "R2",
        gdpr_article  = "Art. 6",
        severity      = "high",
        pii_field     = flow.pii_field,
        pii_category  = flow.pii_category,
        sink_kind     = flow.sink_kind.name.lower(),
        sink_program  = flow.sink_program,
        sink_line     = flow.sink_line,
        sanitised     = flow.sanitised,
        consent_checked = flow.consent_checked,
        remediation   = (
            f"Add a consent-flag check (e.g. IF CONSENT-FLAG = 'Y') before "
            f"{flow.pii_field} reaches the sink in {flow.sink_program}."
        ),
    )


def rule_R3(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 44–49 — Transfers to third countries.
    PII reaches an external or cross-border sink.
    No structural neutraliser — any external transfer is a potential violation.
    """
    if flow.sink_kind not in _EXTERNAL_SINKS:
        return None

    return Violation(
        rule_id       = "R3",
        gdpr_article  = "Art. 44–49",
        severity      = "critical",
        pii_field     = flow.pii_field,
        pii_category  = flow.pii_category,
        sink_kind     = flow.sink_kind.name.lower(),
        sink_program  = flow.sink_program,
        sink_line     = flow.sink_line,
        sanitised     = flow.sanitised,
        consent_checked = flow.consent_checked,
        remediation   = (
            f"{flow.pii_field} is transferred externally from {flow.sink_program}. "
            "Ensure an adequacy decision, SCCs, or BCRs are in place. "
            "Consider pseudonymisation before the transfer."
        ),
    )


def rule_R4(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 32 — Security of processing (at-rest).
    PII persisted to a file or VSAM with no encryption marker on the path.
    """
    if flow.sink_kind not in _AT_REST_SINKS:
        return None
    if flow.sanitised:
        return None

    return Violation(
        rule_id       = "R4",
        gdpr_article  = "Art. 32",
        severity      = "high",
        pii_field     = flow.pii_field,
        pii_category  = flow.pii_category,
        sink_kind     = flow.sink_kind.name.lower(),
        sink_program  = flow.sink_program,
        sink_line     = flow.sink_line,
        sanitised     = flow.sanitised,
        consent_checked = flow.consent_checked,
        remediation   = (
            f"{flow.pii_field} is written to persistent storage in {flow.sink_program} "
            "without encryption. Apply AES-256 or equivalent before the WRITE, "
            "or store only a pseudonymous key."
        ),
    )


# ─── Rule engine ──────────────────────────────────────────────────────────────

ALL_RULES: list[RuleFunction] = [rule_R1, rule_R2, rule_R3, rule_R4]


class RuleEngine:
    """
    Applies all GDPR rules to a list of TaintFlow objects and returns
    a de-duplicated, numbered list of Violation records.

    Parameters
    ----------
    rules : list[RuleFunction]
        Rules to apply (default: ALL_RULES = R1–R4).
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