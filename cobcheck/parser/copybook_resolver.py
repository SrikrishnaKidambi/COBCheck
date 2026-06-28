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
import logging
from pathlib import Path
from typing import Optional

from .ast_nodes  import CobolProgram
from .ast_builder import build_ast

logger = logging.getLogger(__name__)


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
            source = Path(path).read_text(encoding="latin-1")
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
    source = Path(file_path).read_text(encoding="latin-1")
    return build_ast(source, file_path)