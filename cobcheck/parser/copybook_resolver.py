"""
cobcheck/parser/copybook_resolver.py
──────────────────────────────────────
Resolves COPY member names to absolute file paths using an ordered search-path list.

This mirrors how IBM COBOL compilers (and OpenCOBOL/GnuCOBOL) resolve COPY
statements: you give the compiler a list of directories to search, and the
first match wins.  This is the research-standard approach — reviewers familiar
with COBOL tooling will immediately recognise it.

Typical usage
─────────────
    resolver = CopybookResolver(search_paths=[
        "/project/copybooks",
        "/project/src",
        "/shared/copybooks",
    ])

    path = resolver.resolve("CVCUS01Y", from_program="COACTVWC")
    # → "/project/copybooks/CVCUS01Y.cpy"  (or .CPY / .cbl etc.)

    program_ast = resolver.load("CVCUS01Y", from_program="COACTVWC")
    # → CobolProgram  (parsed + cached)
"""

from __future__ import annotations

import os
import re
import logging
from dataclasses import replace as _replace
from pathlib import Path
from typing import Optional

from .ast_nodes  import CobolProgram, CopyStmt, SourceLocation
from .ast_builder import build_ast, normalize_fixed_format

logger = logging.getLogger(__name__)


# ─── COPY statement text-level preprocessing ──────────────────────────────────
#
# The Cobol85 grammar used here has no rule for a COPY statement — COPY is
# treated (correctly, per how real compilers work) as a library/preprocessor
# directive that must be resolved *before* syntax analysis, not during it.
# Leaving `COPY member.` in the token stream is therefore a hard parse error.
#
# So: scan for COPY statements as plain text, splice in the resolved
# copybook's raw source in place of the COPY line, and only THEN call
# build_ast on the expanded text. Field nodes from the copybook end up as
# ordinary DataItems in the consuming program (correctly sectioned, since
# the splice happens inside whatever SECTION context surrounded the COPY),
# so nothing downstream needs to treat them specially. We keep a record of
# where each splice landed so source locations can be corrected back to the
# real copybook file/line afterwards — reports should cite the copybook,
# not a synthetic expanded blob.
#
# Known limitation: REPLACING clauses are not handled — a COPY ... REPLACING
# will not match _COPY_STMT_RE and is left as an unresolved marker instead.

_COPY_STMT_RE = re.compile(
    r'^\s*COPY\s+([A-Za-z0-9\-]+)\s*\.\s*$',
    re.IGNORECASE,
)


def _inline_copy_statements(
    source_text:  str,
    resolver:     "CopybookResolver",
    from_program: str,
) -> tuple[str, list[dict], list[str]]:
    """
    Replace every (non-REPLACING) COPY statement in *source_text* with the
    resolved copybook's raw text.

    Returns (expanded_text, splices, unresolved_members) where each splice
    is {"member", "path", "start_line", "num_lines"} — start_line/num_lines
    are 1-indexed line ranges *in the returned expanded_text*.
    """
    out_lines: list[str] = []
    splices:   list[dict] = []
    resolved_members: list[str] = []
    unresolved_members: list[str] = []

    source_text = normalize_fixed_format(source_text)

    for line in source_text.splitlines():
        m = _COPY_STMT_RE.match(line)
        if not m:
            out_lines.append(line)
            continue

        member = m.group(1).upper()
        path = resolver.resolve(member, from_program)
        if path is None:
            unresolved_members.append(member)
            out_lines.append(f"      *> COBCHECK: UNRESOLVED COPY {member}")
            continue

        try:
            cb_text = normalize_fixed_format(
                Path(path).read_text(encoding="latin-1")
            )
        except Exception as exc:
            logger.error("Failed to read copybook %s: %s", path, exc)
            unresolved_members.append(member)
            out_lines.append(f"      *> COBCHECK: UNREADABLE COPY {member}")
            continue

        # normalize_fixed_format already blanks comment lines (indicator
        # column '*'/'/'), preserving one line per original line — so no
        # separate comment filter is needed here, and every line's
        # original line number maps 1:1 to its position in cb_text.
        kept = list(enumerate(cb_text.splitlines(), start=1))
        start_line = len(out_lines) + 1  # 1-indexed line in expanded text
        out_lines.extend(ln for _, ln in kept)
        splices.append({
            "member":       member,
            "path":         path,
            "start_line":   start_line,
            "num_lines":    len(kept),
            "orig_lines":   [orig_no for orig_no, _ in kept],  # index-aligned
        })
        resolved_members.append(member)

    return "\n".join(out_lines), splices, resolved_members + unresolved_members


def load_program_resolved(file_path: str, resolver: "CopybookResolver") -> CobolProgram:
    """
    Parse *file_path*, inlining COPY statements first (see module docstring
    above) so the grammar only ever sees plain data-item declarations.

    Fields pulled in from a copybook are tagged `.copybook = <member>` and
    have their `.loc` corrected to point at the real copybook file and the
    original line within it, so violation reports still cite true source
    locations instead of the synthetic expanded text.
    """
    from_program = Path(file_path).stem.upper()
    raw_text = Path(file_path).read_text(encoding="latin-1")

    expanded_text, splices, members = _inline_copy_statements(
        raw_text, resolver, from_program,
    )

    program = build_ast(expanded_text, file_path)

    def _patch_location(item) -> None:
        if item.loc is None:
            return
        for sp in splices:
            lo, hi = sp["start_line"], sp["start_line"] + sp["num_lines"]
            if lo <= item.loc.line < hi:
                original_line = sp["orig_lines"][item.loc.line - lo]
                item.loc = _replace(item.loc, file=sp["path"], line=original_line)
                item.copybook = sp["member"]
                return

    for item in program.data_items:
        _patch_location(item)

    if members:
        program.copy_stmts = [
            CopyStmt(
                member=m,
                loc=SourceLocation(program=program.program_id, file=file_path, line=0),
            )
            for m in members
        ]

    return program


# ─── Known file extensions (tried in order) ───────────────────────────────────

_EXTENSIONS = [".cpy", ".CPY", ".cbl", ".CBL", ".cob", ".COB", ".copy", ".COPY"]


class CopybookResolver:
    """
    Resolve COPY member names to filesystem paths and parse them into ASTs.

    Parameters
    ----------
    search_paths : list[str | Path]
        Directories searched in order, left to right (like a compiler's COPYPATH).
        Relative paths are resolved relative to the current working directory
        at construction time.

    Attributes
    ----------
    _cache : dict[str, CobolProgram | None]
        Memoises parse results keyed by absolute file path.
        ``None`` means we tried and failed (avoids repeated I/O).
    """

    def __init__(self, search_paths: list[str | Path]):
        self._search_paths: list[Path] = [
            Path(p).resolve() for p in search_paths
        ]
        self._cache: dict[str, CobolProgram | None] = {}
        # member name → resolved path (for diagnostics / reporting)
        self._resolution_map: dict[str, str] = {}

    # ─── Public interface ─────────────────────────────────────────────────────

    def resolve(self, member: str, from_program: str = "") -> Optional[str]:
        """
        Return the absolute path for *member*, or None if not found.

        The member name is normalised (stripped, upper-cased) before
        directory scanning so case differences between COPY statements
        and filesystem filenames are handled gracefully.
        """
        member_upper = member.strip().upper()

        # Fast path: already resolved
        if member_upper in self._resolution_map:
            return self._resolution_map[member_upper]

        for directory in self._search_paths:
            for ext in _EXTENSIONS:
                candidate = directory / (member_upper + ext)
                if candidate.is_file():
                    resolved = str(candidate)
                    self._resolution_map[member_upper] = resolved
                    logger.debug(
                        "Resolved COPY %s → %s (for program %s)",
                        member_upper, resolved, from_program,
                    )
                    return resolved
                # Also try lower-case member name (Linux FS)
                candidate_lower = directory / (member.lower() + ext)
                if candidate_lower.is_file():
                    resolved = str(candidate_lower)
                    self._resolution_map[member_upper] = resolved
                    return resolved

        logger.warning(
            "Could not resolve COPY %s (referenced in %s). "
            "Searched: %s",
            member_upper,
            from_program,
            [str(p) for p in self._search_paths],
        )
        self._resolution_map[member_upper] = None  # type: ignore[assignment]
        return None

    def load(self, member: str, from_program: str = "") -> Optional[CobolProgram]:
        """
        Resolve *member* and return its parsed CobolProgram, or None.

        Results are memoised — each copybook is parsed at most once regardless
        of how many programs COPY it.
        """
        path = self.resolve(member, from_program)
        if path is None:
            return None

        if path in self._cache:
            return self._cache[path]

        try:
            source = normalize_fixed_format(Path(path).read_text(encoding="latin-1"))
            program = build_ast(source, path)
            self._cache[path] = program
            logger.debug("Parsed copybook %s (%d data items)",
                         path, len(program.data_items))
            return program
        except Exception as exc:
            logger.error("Failed to parse copybook %s: %s", path, exc)
            self._cache[path] = None
            return None

    def all_resolved(self) -> dict[str, Optional[str]]:
        """Return the full member → path mapping (useful for diagnostics)."""
        return dict(self._resolution_map)

    def add_search_path(self, path: str | Path) -> None:
        """Append a search path at runtime (useful in tests)."""
        self._search_paths.append(Path(path).resolve())


# ─── Convenience loader ───────────────────────────────────────────────────────

def load_program(file_path: str) -> CobolProgram:
    """Parse a single .cbl file and return its AST (no copybook resolution)."""
    source = normalize_fixed_format(Path(file_path).read_text(encoding="latin-1"))
    return build_ast(source, file_path)