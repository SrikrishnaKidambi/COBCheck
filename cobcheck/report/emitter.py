"""
cobcheck/report/emitter.py
───────────────────────────
Serialises Violation records to the frozen JSON schema defined in the brief.

Schema (one element of the output array):

{
  "violation_id":    "V-0007",
  "rule_id":         "R1",
  "gdpr_article":    "Art. 32",
  "severity":        "high",
  "pii_field":       "CUST-SSN",
  "pii_category":    "national_id",
  "source": {
    "program":   "COACTVWC",
    "copybook":  "CVCUS01Y",
    "line":      142
  },
  "sink": {
    "kind":    "log",
    "program": "COACTVWC",
    "line":    311
  },
  "flow_path": [
    {"program": "COACTVWC", "line": 142, "stmt": "READ CUSTFILE INTO CUSTOMER-RECORD"},
    {"program": "COACTVWC", "line": 268, "stmt": "MOVE CUST-SSN TO WS-AUDIT-SSN"},
    {"program": "COACTVWC", "line": 311, "stmt": "WRITE AUDIT-LOG-REC FROM WS-AUDIT-REC"}
  ],
  "sanitised":       false,
  "consent_checked": false,
  "remediation":     "Mask or encrypt CUST-SSN before writing to AUDIT-LOG-REC."
}
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..gdpr.rules import Violation


def _violation_to_dict(v: Violation) -> dict:
    return {
        "violation_id":    v.violation_id,
        "rule_id":         v.rule_id,
        "gdpr_article":    v.gdpr_article,
        "severity":        v.severity,
        "pii_field":       v.pii_field,
        "pii_category":    v.pii_category.lower(),
        "source": {
            "program":  v.source_program,
            "copybook": v.source_copybook,
            "line":     v.source_line,
        },
        "sink": {
            "kind":    v.sink_kind,
            "program": v.sink_program,
            "line":    v.sink_line,
        },
        "flow_path":       v.flow_path,
        "sanitised":       v.sanitised,
        "consent_checked": v.consent_checked,
        "remediation":     v.remediation,
    }


def emit_json(
    violations: list[Violation],
    output_path: Optional[str] = None,
    metadata:   Optional[dict] = None,
) -> str:
    """
    Serialise *violations* to JSON and write to *output_path* (or stdout).

    Returns the JSON string.

    Parameters
    ----------
    violations  : list of Violation records (from RuleEngine.run())
    output_path : file path to write (None → stdout)
    metadata    : optional dict merged into the report header
    """
    report = {
        "cobcheck_version": "0.1.0",
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_violations": len(violations),
        "violations":       [_violation_to_dict(v) for v in violations],
    }
    if metadata:
        report.update(metadata)

    json_str = json.dumps(report, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str)
        sys.stdout.write("\n")

    return json_str


def emit_summary(violations: list[Violation]) -> str:
    """
    Return a human-readable summary table (for CLI output).
    """
    if not violations:
        return "✓  No violations found."

    lines = [
        f"{'ID':<10} {'Rule':<6} {'Severity':<10} {'Field':<25} {'Sink Program':<20} {'Article'}",
        "-" * 90,
    ]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for v in sorted(violations, key=lambda x: sev_order.get(x.severity, 9)):
        lines.append(
            f"{v.violation_id:<10} {v.rule_id:<6} {v.severity:<10} "
            f"{v.pii_field:<25} {v.sink_program:<20} {v.gdpr_article}"
        )
    lines.append("")
    lines.append(f"Total: {len(violations)} violation(s)")
    return "\n".join(lines)