"""
cobcheck/parser/ast_nodes.py
────────────────────────────
Language-agnostic AST node dataclasses.

These sit *above* the ANTLR parse tree and give the rest of COBCheck a
clean, typed view of COBOL programs.  The ANTLR visitor (ast_builder.py)
walks the raw parse tree and produces these nodes; every later layer —
CPG builder, PII tagger, taint engine — works exclusively with these.

Design decisions
----------------
* Dataclasses with __slots__ for low memory overhead on large codebases.
* Every node carries (program, file, line) so violations can be mapped
  back to source.
* Copybook COPY statements are preserved so the CPG builder can resolve
  and inline them.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ─── Source location ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SourceLocation:
    """Immutable source position attached to every AST node."""
    program: str          # e.g. "COACTVWC"
    file:    str          # absolute path to .cbl / .cpy
    line:    int
    column:  int = 0

    def __str__(self) -> str:
        return f"{self.program}:{self.file}:{self.line}"


# ─── Data Division nodes ──────────────────────────────────────────────────────

class DataSection(Enum):
    FILE            = auto()
    WORKING_STORAGE = auto()
    LINKAGE         = auto()
    LOCAL_STORAGE   = auto()
    UNKNOWN         = auto()


@dataclass
class DataItem:
    """
    One COBOL data item (01–49, 77, 88, 66).

    level       : integer level number (1, 5, 10 … 49, 66, 77, 88)
    name        : data-name or FILLER
    picture     : raw PIC string, e.g. "9(09)" or "X(25)"
    redefines   : name of the item being redefined (or None)
    section     : which Data Division section this item lives in
    copybook    : copybook filename if the item was pulled from a COPY
    children    : subordinate DataItems (group item)
    loc         : source location
    """
    level:      int
    name:       str
    picture:    Optional[str]       = None
    redefines:  Optional[str]       = None
    section:    DataSection         = DataSection.UNKNOWN
    copybook:   Optional[str]       = None
    children:   list["DataItem"]    = field(default_factory=list)
    loc:        Optional[SourceLocation] = None

    @property
    def is_group(self) -> bool:
        return bool(self.children)

    @property
    def is_elementary(self) -> bool:
        return self.picture is not None and not self.children

    def __repr__(self) -> str:
        pic = f" PIC {self.picture}" if self.picture else ""
        return f"<DataItem {self.level:02d} {self.name}{pic}>"


# ─── Procedure Division statement nodes ───────────────────────────────────────

@dataclass
class MoveStmt:
    """MOVE src TO dest1 dest2 …"""
    source:       str               # sending field name (or literal)
    destinations: list[str]         = field(default_factory=list)
    is_group_move: bool             = False   # MOVE CORRESPONDING
    loc:          Optional[SourceLocation] = None


@dataclass
class ComputeStmt:
    """COMPUTE dest = expr"""
    destination:  str
    operands:     list[str]         = field(default_factory=list)  # RHS data refs
    loc:          Optional[SourceLocation] = None


@dataclass
class CallStmt:
    """CALL 'program' USING param1 param2 …"""
    target:       str               # program name (literal or var)
    target_is_literal: bool         = True
    using_params: list[str]         = field(default_factory=list)  # field names
    giving_param: Optional[str]     = None
    loc:          Optional[SourceLocation] = None


@dataclass
class WriteStmt:
    """WRITE record-name FROM field"""
    record_name:  str
    from_field:   Optional[str]     = None
    file_name:    Optional[str]     = None   # resolved by CPG builder
    loc:          Optional[SourceLocation] = None


@dataclass
class ReadStmt:
    """READ file-name INTO field"""
    file_name:    str
    into_field:   Optional[str]     = None
    loc:          Optional[SourceLocation] = None


@dataclass
class DisplayStmt:
    """DISPLAY field1 field2 …"""
    operands:     list[str]         = field(default_factory=list)
    upon:         Optional[str]     = None   # UPON SYSOUT etc.
    loc:          Optional[SourceLocation] = None


@dataclass
class CopyStmt:
    """COPY copybook-name"""
    member:       str               # e.g. "CVCUS01Y"
    replacing:    list[tuple[str, str]] = field(default_factory=list)
    loc:          Optional[SourceLocation] = None


@dataclass
class IfStmt:
    """IF condition THEN … ELSE …"""
    condition_text: str             # raw text of the condition (for guard detection)
    then_stmts:   list              = field(default_factory=list)
    else_stmts:   list              = field(default_factory=list)
    loc:          Optional[SourceLocation] = None


@dataclass
class PerformStmt:
    """PERFORM paragraph / PERFORM … UNTIL"""
    target:       Optional[str]     = None   # paragraph/section name
    is_inline:    bool              = False
    body_stmts:   list              = field(default_factory=list)
    loc:          Optional[SourceLocation] = None


@dataclass
class GenericStmt:
    """
    Catch-all for statements COBCheck doesn't analyse in detail.
    Kept so the CFG has complete node coverage.
    """
    text:         str
    loc:          Optional[SourceLocation] = None


# ─── Paragraph / Section ──────────────────────────────────────────────────────

@dataclass
class Paragraph:
    name:       str
    statements: list                = field(default_factory=list)
    loc:        Optional[SourceLocation] = None


@dataclass
class Section:
    name:       str
    paragraphs: list[Paragraph]     = field(default_factory=list)
    loc:        Optional[SourceLocation] = None


# ─── Program (top-level compilation unit) ────────────────────────────────────

@dataclass
class CobolProgram:
    """
    Complete AST for one COBOL program unit (.cbl file).

    file_path    : absolute path to the source file
    program_id   : value of the PROGRAM-ID paragraph
    data_items   : all DataItems from all Data Division sections, in declaration order
    sections     : all Procedure Division sections
    paragraphs   : top-level paragraphs (not inside a section)
    copy_stmts   : all COPY statements encountered (both divs)
    fd_map       : file-name → record-name from the File Section FD entries
    """
    file_path:   str
    program_id:  str
    data_items:  list[DataItem]     = field(default_factory=list)
    sections:    list[Section]      = field(default_factory=list)
    paragraphs:  list[Paragraph]    = field(default_factory=list)
    copy_stmts:  list[CopyStmt]     = field(default_factory=list)
    fd_map:      dict[str, str]     = field(default_factory=dict)  # file→record

    # Populated after copybook resolution
    resolved_copybooks: dict[str, "CobolProgram"] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.program_id

    @property
    def all_statements(self):
        """Flat iterator over every statement in the program."""
        for p in self.paragraphs:
            yield from p.statements
        for s in self.sections:
            for p in s.paragraphs:
                yield from p.statements

    def __repr__(self) -> str:
        return f"<CobolProgram {self.program_id} ({self.file_path})>"