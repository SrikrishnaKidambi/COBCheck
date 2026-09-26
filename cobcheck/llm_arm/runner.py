"""
cobcheck/llm_arm/runner.py
─────────────────────────────
Orchestrates the LLM-only arm end to end and returns list[Violation],
the SAME schema the full pipeline's RuleEngine produces, so
report/emitter.py's emit_json / emit_summary work unmodified and a
scoring script can diff Arm 1 output against Arm 3 output directly.

No CPG, no taint engine, no PII tagger — this arm reasons over raw
concatenated COBOL source only, per obligation, via Groq.
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional

from ..parser.copybook_resolver import CopybookResolver
from ..gdpr.rules import Violation
from .codebook import CODEBOOK, DEFAULT_RULES, CodebookEntry
from .source_bundle import build_source_bundle
from .client import call_groq_for_rule

logger = logging.getLogger("cobcheck.llm_arm")

_VALID_VERDICTS = {"VIOLATION", "INSUFFICIENT_EVIDENCE"}  # NOT_A_VIOLATION omitted by design


def _classify_locality(source_program: str, sink_program: str) -> tuple[str, list[str]]:
    if source_program and source_program != sink_program:
        return "cross_program", [f"{source_program} -> {sink_program}"]
    return "intra_program", []


def _finding_to_violation(finding: dict, entry: CodebookEntry, counter: int) -> Optional[Violation]:
    verdict = str(finding.get("verdict", "")).upper()
    if verdict not in _VALID_VERDICTS:
        return None  # NOT_A_VIOLATION, or malformed — drop it

    source_program = str(finding.get("source_program", "") or "")
    sink_program = str(finding.get("sink_program", "") or "")
    locality, boundary_crossings = _classify_locality(source_program, sink_program)

    rationale = str(finding.get("rationale", ""))
    if verdict == "INSUFFICIENT_EVIDENCE":
        rationale = f"[INSUFFICIENT EVIDENCE] {rationale}"

    return Violation(
        violation_id       = f"LLM-{counter:04d}",
        rule_id            = entry.rule_id,
        gdpr_article       = entry.article,
        severity           = entry.severity,
        pii_field          = str(finding.get("pii_field", "")),
        pii_category       = str(finding.get("pii_category", "")).lower(),
        source_program     = source_program,
        source_copybook    = "",
        source_line        = int(finding.get("source_line") or 0),
        sink_kind          = str(finding.get("sink_kind", "")).lower(),
        sink_program       = sink_program,
        sink_line          = int(finding.get("sink_line") or 0),
        flow_path=[
            {"program": source_program, "line": int(finding.get("source_line") or 0),
             "stmt": "(LLM-identified source — no recovered flow path)"},
            {"program": sink_program, "line": int(finding.get("sink_line") or 0),
             "stmt": "(LLM-identified sink — no recovered flow path)"},
        ],
        sanitised          = False,
        consent_checked    = False,
        retention_checked  = False,
        rationale          = rationale,
        remediation         = str(finding.get("remediation", "")),
        locality            = locality,
        boundary_crossings  = boundary_crossings,
    )


def run_llm_only_arm(
    src_dirs: list[str],
    copybook_dirs: list[str],
    rules: Optional[list[str]] = None,
    api_key: Optional[str] = None,
    model: str = "openai/gpt-oss-120b",
) -> list[Violation]:
    """
    Run the LLM-only arm over every .cbl file found under src_dirs.
    Returns list[Violation] matching the full pipeline's output schema.
    """
    rules = rules or DEFAULT_RULES
    if not api_key:
        raise ValueError("run_llm_only_arm requires a Groq API key")

    cbl_files: list[Path] = []
    for src_dir in src_dirs:
        for ext in ("*.cbl", "*.CBL", "*.cob", "*.COB"):
            cbl_files.extend(Path(src_dir).rglob(ext))

    if not cbl_files:
        logger.error("No .cbl files found in: %s", src_dirs)
        return []

    resolver = CopybookResolver(search_paths=copybook_dirs + src_dirs)
    source_bundle = build_source_bundle(cbl_files, resolver)
    logger.info("Built source bundle: %d programs, %d chars",
               len(cbl_files), len(source_bundle))

    violations: list[Violation] = []
    counter = 0

    for rule_id in rules:
        if rule_id not in CODEBOOK:
            logger.warning("No codebook entry for rule %s — skipping", rule_id)
            continue
        entry = CODEBOOK[rule_id]
        logger.info("LLM-only arm: deciding %s (%s)...", rule_id, entry.article)

        findings = call_groq_for_rule(entry, source_bundle, api_key, model)
        logger.info("%s: %d raw findings from LLM", rule_id, len(findings))

        for finding in findings:
            counter += 1
            v = _finding_to_violation(finding, entry, counter)
            if v is not None:
                violations.append(v)

    logger.info("LLM-only arm: %d violations total", len(violations))
    return violations