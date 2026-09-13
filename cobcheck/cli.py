"""
cobcheck/cli.py
────────────────
End-to-end pipeline runner + CLI entry point.

Pipeline:
  1. Load + parse all .cbl files  →  list[CobolProgram]
  2. Resolve copybooks inline
  3. Build CPG                    →  CPG
  4. Tag PII                      →  PII-annotated CPG
  5. Propagate taint              →  list[TaintFlow]
  6. Apply GDPR rules             →  list[Violation]
  7. Emit JSON report + summary

Usage:
  python -m cobcheck.cli \
      --src testbeds/sample/src \
      --copybooks testbeds/sample/copybooks \
      --output violations.json
"""

from __future__ import annotations

import os
import sys
import logging
import argparse
from pathlib import Path
from dotenv import load_dotenv

from .parser.ast_nodes     import CobolProgram
from .parser.copybook_resolver import CopybookResolver, load_program_resolved
from .cpg.builder           import CPGBuilder
from .pii.tagger            import PiiTagger
from .taint.engine          import TaintEngine
from .gdpr.rules            import RuleEngine
from .report.emitter        import emit_json, emit_summary

logging.basicConfig(
    level  = logging.INFO,
    format = "%(levelname)s  %(name)s  %(message)s",
)
logger = logging.getLogger("cobcheck")


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(
    src_dirs:       list[str],
    copybook_dirs:  list[str],
    output_path:    str | None  = None,
    groq_api_key:   str | None  = None,
    verbose:        bool        = False,
) -> list:
    """
    Full COBCheck pipeline. Returns the list of Violation objects.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Step 1: discover .cbl files ──────────────────────────────────────────
    cbl_files: list[Path] = []
    for src_dir in src_dirs:
        for ext in ("*.cbl", "*.CBL", "*.cob", "*.COB"):
            cbl_files.extend(Path(src_dir).rglob(ext))

    if not cbl_files:
        logger.error("No .cbl files found in: %s", src_dirs)
        sys.exit(1)

    logger.info("Found %d COBOL source files", len(cbl_files))

    # ── Step 2: parse all programs ───────────────────────────────────────────
    resolver = CopybookResolver(search_paths=copybook_dirs + src_dirs)
    programs: list[CobolProgram] = []

    for cbl_path in cbl_files:
        logger.info("Parsing %s", cbl_path.name)
        try:
            prog = load_program_resolved(str(cbl_path), resolver)
            programs.append(prog)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", cbl_path.name, exc)

    if not programs:
        logger.error("No programs parsed successfully — check ANTLR generated files.")
        sys.exit(1)

    logger.info("Parsed %d programs successfully", len(programs))

    # ── Step 3: build CPG ────────────────────────────────────────────────────
    logger.info("Building CPG...")
    builder = CPGBuilder(resolver=resolver)
    cpg     = builder.build(programs)
    logger.info("CPG: %s", cpg)

    # ── Step 4: tag PII ──────────────────────────────────────────────────────
    logger.info("Tagging PII fields...")
    tagger    = PiiTagger(groq_api_key=groq_api_key)
    pii_nodes = tagger.tag(cpg)
    logger.info("Tagged %d PII nodes  (stats: %s)", len(pii_nodes), tagger.stats)

    # ── Step 5: taint propagation ────────────────────────────────────────────
    logger.info("Running taint propagation...")
    engine = TaintEngine()
    flows  = engine.run(cpg)
    logger.info("Found %d taint flows", len(flows))

    # ── Step 6: GDPR rules ───────────────────────────────────────────────────
    logger.info("Applying GDPR rules R1–R6...")
    rule_engine = RuleEngine()
    violations  = rule_engine.run(flows, cpg)
    logger.info("Found %d violations", len(violations))

    # ── Step 7: report ───────────────────────────────────────────────────────
    print("\n" + emit_summary(violations))

    meta = {
        "programs_analysed": [p.program_id for p in programs],
        "pii_fields_found":  len(pii_nodes),
        "taint_flows":       len(flows),
    }
    emit_json(violations, output_path=output_path, metadata=meta)

    if output_path:
        logger.info("JSON report written to %s", output_path)

    return violations


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="COBCheck — GDPR compliance analyser for COBOL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cobcheck.cli --src testbeds/sample/src --copybooks testbeds/sample/copybooks
  python -m cobcheck.cli --src testbeds/carddemo/app/cbl --copybooks testbeds/carddemo/app/copybooks --output out.json
        """,
    )
    parser.add_argument("--src",        nargs="+", required=True,
                        help="Directory/directories containing .cbl source files")
    parser.add_argument("--copybooks",  nargs="+", default=[],
                        help="Copybook search path directories")
    parser.add_argument("--output",     default=None,
                        help="Output JSON file path (default: stdout)")
    parser.add_argument("--groq-key",   default=os.getenv("GROQ_API_KEY", ""),
                        help="Groq API key for LLM fallback PII detection")
    parser.add_argument("--verbose",    action="store_true",
                        help="Enable DEBUG logging")

    args = parser.parse_args()

    run_pipeline(
        src_dirs      = args.src,
        copybook_dirs = args.copybooks,
        output_path   = args.output,
        groq_api_key  = args.groq_key or None,
        verbose       = args.verbose,
    )


if __name__ == "__main__":
    main()