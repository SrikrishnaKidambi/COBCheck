"""
cobcheck/parser/ast_nodes.py
────────────────────────────
Language-agnostic AST node dataclasses.

These sit above the ANTLR parse tree and give the rest of COBCheck a
clean, typed view of COBOL programs.

The AST deliberately preserves the semantic distinction between:

* ordinary COBOL data movement (MOVE, COMPUTE, READ, WRITE)
* inter-program calls (CALL)
* output operations (DISPLAY, WRITE)
* external data-service operations (EXEC SQL, EXEC CICS, EXEC SQL IMS)

This distinction is important for COBCheck's source-to-sink analysis.
A later CPG layer decides whether a particular external operation is a
data source, sink, or merely an intermediate operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ─── Source location ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SourceLocation:
    """Immutable source position attached to every AST node."""

    program: str
    file: str
    line: int
    column: int = 0

    def __str__(self) -> str:
        return f"{self.program}:{self.file}:{self.line}"


# ─── Data Division nodes ──────────────────────────────────────────────────────

class DataSection(Enum):
    FILE = auto()
    WORKING_STORAGE = auto()
    LINKAGE = auto()
    LOCAL_STORAGE = auto()
    UNKNOWN = auto()


@dataclass
class DataItem:
    """
    One COBOL data item.

    The name and picture are preserved because they are later used by the
    PII-identification layer.
    """

    level: int
    name: str
    picture: Optional[str] = None
    redefines: Optional[str] = None
    section: DataSection = DataSection.UNKNOWN
    copybook: Optional[str] = None
    children: list["DataItem"] = field(default_factory=list)
    loc: Optional[SourceLocation] = None

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

    source: str
    destinations: list[str] = field(default_factory=list)
    is_group_move: bool = False
    loc: Optional[SourceLocation] = None


@dataclass
class ComputeStmt:
    """COMPUTE dest = expression"""

    destination: str
    operands: list[str] = field(default_factory=list)
    loc: Optional[SourceLocation] = None


@dataclass
class CallStmt:
    """
    CALL target USING param1 param2 …

    CALL itself is not automatically a sink. The CPG layer can distinguish
    between an internal COBOL call and a recognised external interface.
    """

    target: str
    target_is_literal: bool = True
    using_params: list[str] = field(default_factory=list)
    giving_param: Optional[str] = None
    loc: Optional[SourceLocation] = None


@dataclass
class WriteStmt:
    """
    WRITE record-name [FROM field]

    Represents a COBOL output operation. The CPG builder later resolves
    whether the destination corresponds to a file or another output target.
    """

    record_name: str
    from_field: Optional[str] = None
    file_name: Optional[str] = None
    loc: Optional[SourceLocation] = None


@dataclass
class ReadStmt:
    """READ file-name [INTO field]"""

    file_name: str
    into_field: Optional[str] = None
    loc: Optional[SourceLocation] = None


@dataclass
class DisplayStmt:
    """DISPLAY operand1 operand2 … [UPON destination]"""

    operands: list[str] = field(default_factory=list)
    upon: Optional[str] = None
    loc: Optional[SourceLocation] = None


# ─── External / subsystem statements ─────────────────────────────────────────

@dataclass
class ExecSqlStmt:
    """
    EXEC SQL ... END-EXEC.

    ``operation`` stores the primary SQL operation where it can be extracted,
    for example SELECT, INSERT, UPDATE, DELETE or CALL.

    ``operands`` contains COBOL identifiers referenced by the SQL block.
    This allows the CPG to connect host variables to the operation node.

    ``raw_text`` preserves the original statement for traceability and for
    cases where precise SQL parsing is unavailable.
    """

    operation: str
    operands: list[str] = field(default_factory=list)
    raw_text: str = ""
    loc: Optional[SourceLocation] = None


@dataclass
class ExecCicsStmt:
    """
    EXEC CICS ... END-EXEC.

    ``operation`` stores the primary CICS command, such as SEND, RECEIVE,
    LINK, XCTL, WRITEQ or READQ when extractable.

    ``operands`` contains COBOL identifiers referenced by the command.
    """

    operation: str
    operands: list[str] = field(default_factory=list)
    raw_text: str = ""
    loc: Optional[SourceLocation] = None


@dataclass
class ExecSqlImsStmt:
    """
    EXEC SQL IMS ... END-EXEC.

    IMS operations are represented explicitly because they can involve
    persistent database access and cross-program data movement.
    """

    operation: str
    operands: list[str] = field(default_factory=list)
    raw_text: str = ""
    loc: Optional[SourceLocation] = None


@dataclass
class CopyStmt:
    """COPY copybook-name."""

    member: str
    replacing: list[tuple[str, str]] = field(default_factory=list)
    loc: Optional[SourceLocation] = None


@dataclass
class IfStmt:
    """IF condition THEN … ELSE …"""

    condition_text: str
    then_stmts: list = field(default_factory=list)
    else_stmts: list = field(default_factory=list)
    loc: Optional[SourceLocation] = None


@dataclass
class PerformStmt:
    """PERFORM paragraph / PERFORM … UNTIL"""

    target: Optional[str] = None
    is_inline: bool = False
    body_stmts: list = field(default_factory=list)
    loc: Optional[SourceLocation] = None


@dataclass
class GenericStmt:
    """
    Catch-all for statements COBCheck does not yet analyse semantically.

    The original text is retained so unsupported constructs remain visible
    in the CFG and can be supported by future analysis extensions.
    """

    text: str
    loc: Optional[SourceLocation] = None


# ─── Paragraph / Section ──────────────────────────────────────────────────────

@dataclass
class Paragraph:
    name: str
    statements: list = field(default_factory=list)
    loc: Optional[SourceLocation] = None


@dataclass
class Section:
    name: str
    paragraphs: list[Paragraph] = field(default_factory=list)
    loc: Optional[SourceLocation] = None


# ─── Program ──────────────────────────────────────────────────────────────────

@dataclass
class CobolProgram:
    """
    Complete AST for one COBOL program unit.
    """

    file_path: str
    program_id: str
    data_items: list[DataItem] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    paragraphs: list[Paragraph] = field(default_factory=list)
    copy_stmts: list[CopyStmt] = field(default_factory=list)

    # File-name → record-name from File Section FD entries.
    fd_map: dict[str, str] = field(default_factory=dict)

    # Populated after copybook resolution.
    resolved_copybooks: dict[str, "CobolProgram"] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.program_id

    @property
    def all_statements(self):
        """Flat iterator over every statement in the program."""

        for paragraph in self.paragraphs:
            yield from paragraph.statements

        for section in self.sections:
            for paragraph in section.paragraphs:
                yield from paragraph.statements

    def __repr__(self) -> str:
        return f"<CobolProgram {self.program_id} ({self.file_path})>"