"""
cobcheck/llm_arm/source_bundle.py
────────────────────────────────────
Builds the concatenated raw-source text the LLM-only arm sees. Reuses
CopybookResolver's own COPY-inlining logic so the LLM reads exactly the
same expanded text the parser would — just skips build_ast, since Arm 1
must not have access to any parsed/graph structure.
"""

from __future__ import annotations
from pathlib import Path

from ..parser.copybook_resolver import CopybookResolver, _inline_copy_statements


def build_source_bundle(cbl_files: list[Path], resolver: CopybookResolver) -> str:
    """
    Concatenate every program's copybook-expanded source into one text
    block, each program clearly delimited so the LLM can attribute
    source_program / sink_program correctly across the boundary.
    """
    parts: list[str] = []
    for cbl_path in cbl_files:
        program_id = cbl_path.stem.upper()
        raw_text = cbl_path.read_text(encoding="latin-1")
        expanded_text, _splices, _members = _inline_copy_statements(
            raw_text, resolver, program_id,
        )
        parts.append(
            f"===== PROGRAM: {program_id} (file: {cbl_path.name}) =====\n"
            f"{expanded_text}\n"
            f"===== END PROGRAM: {program_id} =====\n"
        )
    return "\n".join(parts)