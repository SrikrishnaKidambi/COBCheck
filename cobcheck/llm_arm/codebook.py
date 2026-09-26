"""
cobcheck/llm_arm/codebook.py
──────────────────────────────
Per-rule codebook text fed to the LLM-only arm (Arm 1). Sourced from
cobcheck/gdpr/rules.py's docstrings — rules.py is the project's ground
truth (obligation_registry.py is unused by the running pipeline).

Each entry gives the LLM exactly what a human rater in the V2 oracle
procedure would see: article, code-level condition, and what clears it —
NOT recovered flow facts. This is deliberate: Arm 1 measures whether an
LLM given only source + the obligation definition can decide the same
question the full pipeline decides from CPG/taint facts.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class CodebookEntry:
    rule_id: str
    article: str
    fires_when: str
    neutralised_by: str
    locality: str          # "intra_program" | "cross_program" | "either"
    severity: str          # matches rules.py's per-rule severity


CODEBOOK: dict[str, CodebookEntry] = {

    "R1": CodebookEntry(
        rule_id="R1",
        article="Art. 5(1)(f)",
        fires_when=(
            "Any personal data (Art. 4(1) — any information relating to an "
            "identified or identifiable natural person) reaches a log or "
            "display output (a DISPLAY statement, or a WRITE to a file whose "
            "name suggests a log/audit/report)."
        ),
        neutralised_by=(
            "A masking or encryption operation applied to the field on the "
            "path before it reaches the sink."
        ),
        locality="either",
        severity="high",
    ),

    "R4": CodebookEntry(
        rule_id="R4",
        article="Art. 5(1)(f)",
        fires_when=(
            "Any personal data is written to persistent storage (a file "
            "WRITE, or a database INSERT/UPDATE) with no encryption on the "
            "path — i.e. it is persisted in the clear."
        ),
        neutralised_by=(
            "A masking or encryption operation applied to the field before "
            "the WRITE/INSERT/UPDATE."
        ),
        locality="either",
        severity="high",
    ),

    "R8": CodebookEntry(
        rule_id="R8",
        article="Art. 6(4)",
        fires_when=(
            "A personal-data field originates in one program and crosses a "
            "PROGRAM boundary (via CALL) to a sink in a DIFFERENT program, "
            "where that sink's function looks materially different from "
            "ordinary same-program record-keeping — specifically an external "
            "transfer, a messaging operation, or a database write. This is "
            "the closest observable proxy for 'further processing for a "
            "different purpose than the data was originally collected for.'"
        ),
        neutralised_by=(
            "Nothing clears this structurally — it is always reported when "
            "the trigger condition holds, flagged for a human purpose-"
            "compatibility assessment rather than asserted as a definite "
            "violation."
        ),
        locality="cross_program",
        severity="medium",
    ),

    "R9": CodebookEntry(
        rule_id="R9",
        article="Art. 5(1)(c)",
        fires_when=(
            "A field is passed from a caller program to a callee program via "
            "CALL ... USING, the field carries personal data, AND that field "
            "is never referenced anywhere in the callee's own PROCEDURE "
            "DIVISION body (i.e. it was shared but never used). Deciding "
            "this REQUIRES seeing both the caller's CALL statement (what was "
            "shared) and the callee's full body (what was ever used) at the "
            "same time — it cannot be decided from either program's source "
            "alone."
        ),
        neutralised_by=(
            "The callee referencing the field anywhere in its PROCEDURE "
            "DIVISION (a MOVE, COMPUTE, WRITE FROM, or EXEC statement using "
            "it as a source)."
        ),
        locality="cross_program",
        severity="medium",
    ),
}

DEFAULT_RULES = ["R1", "R4", "R8", "R9"]  # the four obligations V2 evaluates


def build_system_prompt(entry: CodebookEntry) -> str:
    return (
        "You are a GDPR compliance analyst reviewing raw COBOL source code. "
        "You are given the full text of one or more COBOL programs and their "
        "copybooks, already expanded (COPY statements inlined). You have NOT "
        "been given any pre-computed data-flow graph, taint analysis, or call "
        "graph — you must read the source yourself to trace how fields move.\n\n"
        f"You are deciding ONLY obligation {entry.rule_id} ({entry.article}).\n\n"
        f"Fires when: {entry.fires_when}\n\n"
        f"Cleared by: {entry.neutralised_by}\n\n"
        "For each candidate finding, output one JSON object with these exact "
        "keys: verdict (one of \"VIOLATION\", \"NOT_A_VIOLATION\", "
        "\"INSUFFICIENT_EVIDENCE\"), pii_field, pii_category, source_program, "
        "source_line (integer or null), sink_program, sink_line (integer or "
        "null), sink_kind, rationale, remediation.\n\n"
        "Only report VIOLATION or INSUFFICIENT_EVIDENCE findings — omit fields "
        "you traced and found NOT_A_VIOLATION for; do not include them in the "
        "output at all. Respond with a JSON array only, no prose, no markdown "
        "fences."
    )