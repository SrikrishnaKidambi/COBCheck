"""
cobcheck/cpg/builder.py
────────────────────────
Builds a cross-program Code Property Graph from COBOL ASTs.

The builder performs:

1. Node creation
2. CFG construction
3. PDG construction
4. Sink classification
5. Cross-program CALL relationships
6. Shared copybook relationships
7. Shared-file relationships

Sink categories:

    LOGGING
    FILE_STORAGE
    NETWORK_TRANSFER
    MESSAGING
    DATABASE
    CONTENT_OR_SERVICE
"""

from __future__ import annotations

import logging
import re

from collections import defaultdict
from typing import Optional

from ..parser.ast_nodes import (
    CobolProgram,
    DataItem,
    DataSection,
    MoveStmt,
    ComputeStmt,
    CallStmt,
    WriteStmt,
    ReadStmt,
    DisplayStmt,
    ExecSqlStmt,
    ExecCicsStmt,
    ExecSqlImsStmt,
    IfStmt,
    PerformStmt,
    GenericStmt,
)

from ..parser.copybook_resolver import CopybookResolver

from .graph_model import (
    CPG,
    NodeKind,
    EdgeKind,
    SinkKind,
)


logger = logging.getLogger(__name__)


# ─── Classification constants ─────────────────────────────────────────────────

_LOG_TOKENS = {
    "LOG",
    "AUDIT",
    "TRACE",
    "JOURNAL",
    "JRNL",
    "REPORT",
    "RPT",
}

_PRINT_TOKENS = {
    "PRINT",
    "SYSPRINT",
    "SYSOUT",
    "LIST",
    "LISTING",
}

_EXTERNAL_CALL_TOKENS = {
    "API",
    "SOCKET",
    "HTTP",
    "HTTPS",
    "REST",
    "SERVICE",
    "WEBSERVICE",
    "WEBSVC",
    "TRANSFER",
    "XFER",
    "EXPORT",
}

_MESSAGING_CALL_TOKENS = {
    "MQ",
    "QUEUE",
    "MESSAGE",
    "KAFKA",
}

_SANITISER_TOKENS = {
    "ENCRYPT",
    "ENCR",
    "MASK",
    "HASH",
    "REDACT",
    "SCRAMBLE",
    "CIPHER",
    "AES",
    "SHA",
    "HMAC",
}

_CONSENT_TOKENS = {
    "CONSENT",
    "PERMISSION",
    "PERMIT",
    "AUTHORI",
    "AUTHORIZ",
    "GDPR",
}


# SQL operations that persist or modify data.

_SQL_DATABASE_SINKS = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "MERGE",
}

# SQL operations that introduce data into COBOL.

_SQL_DATABASE_SOURCES = {
    "SELECT",
    "FETCH",
}


# IMS persistent operations.

_IMS_DATABASE_SINKS = {
    "ISRT",
    "REPL",
    "DLET",
}

_IMS_DATABASE_SOURCES = {
    "GU",
    "GN",
    "GHU",
    "GHN",
    "GNP",
}


# CICS operations.

_CICS_NETWORK_SINKS = {
    "SEND",
}

_CICS_MESSAGE_SINKS = {
    "WRITEQ",
    "PUT",
}

_CICS_MESSAGE_SOURCES = {
    "READQ",
    "RECEIVE",
    "GET",
}

_CICS_CALL_OPERATIONS = {
    "LINK",
    "XCTL",
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _normalise_identifier(
    value: Optional[str],
) -> str:
    if not value:
        return ""

    return re.sub(
        r"[^A-Z0-9]",
        "",
        value.upper(),
    )


def _looks_like_literal(
    value: Optional[str],
) -> bool:
    if not value:
        return True

    value = value.strip()

    if not value:
        return True

    if (
        value.startswith("'")
        and value.endswith("'")
    ):
        return True

    if (
        value.startswith('"')
        and value.endswith('"')
    ):
        return True

    return bool(
        re.fullmatch(
            r"[+-]?\d+(\.\d+)?",
            value,
        )
    )


def _classify_write_sink(
    record_name: str,
    file_name: Optional[str],
) -> SinkKind:
    """
    COBOL WRITE deterministically represents output to persistent storage.

    Naming is used to refine the output into LOGGING when the destination
    clearly represents a log, audit or report target, or into
    NETWORK_TRANSFER when the name suggests the data leaves the
    organisation (export/transfer feeds) rather than staying in ordinary
    at-rest storage — this distinction matters because GDPR Art. 44-49
    (cross-border transfer) only engages for the latter.
    """

    candidate = " ".join(
        value
        for value in (
            record_name,
            file_name,
        )
        if value
    ).upper()

    if any(
        token in candidate
        for token in _LOG_TOKENS
    ):
        return SinkKind.LOGGING

    if any(
        token in candidate
        for token in _EXTERNAL_CALL_TOKENS
    ):
        return SinkKind.NETWORK_TRANSFER

    return SinkKind.FILE_STORAGE


def _classify_display_sink(
    upon: Optional[str],
) -> SinkKind:
    """
    DISPLAY is an observable disclosure point.

    DISPLAY is therefore treated as LOGGING/output disclosure.
    """

    return SinkKind.LOGGING


def _classify_call_target_as_sink(
    target: str,
) -> Optional[SinkKind]:
    """
    Conservative classification for unresolved CALL targets.

    Internal CALL targets are not sinks.

    Only strongly suggestive unresolved targets are treated as external
    interfaces.
    """

    upper = target.upper()

    if any(
        token in upper
        for token in _MESSAGING_CALL_TOKENS
    ):
        return SinkKind.MESSAGING

    if any(
        token in upper
        for token in _EXTERNAL_CALL_TOKENS
    ):
        return SinkKind.CONTENT_OR_SERVICE

    return None


def _is_sanitiser_text(
    value: str,
) -> bool:
    upper = value.upper()

    return any(
        token in upper
        for token in _SANITISER_TOKENS
    )


def _is_guard_text(
    value: str,
) -> bool:
    upper = value.upper()

    return any(
        token in upper
        for token in _CONSENT_TOKENS
    )


# ─── CPG Builder ──────────────────────────────────────────────────────────────

class CPGBuilder:

    def __init__(
        self,
        resolver: Optional[CopybookResolver] = None,
    ):
        self._resolver = resolver

        self._cpg = CPG()

        self._entry_nodes: dict[str, int] = {}
        self._exit_nodes: dict[str, int] = {}

        self._field_nodes: dict[
            tuple[str, str],
            int,
        ] = {}

        self._normalised_field_nodes: dict[
            tuple[str, str],
            int,
        ] = {}

        self._stmt_nodes: dict[
            tuple[str, int],
            int,
        ] = {}

        self._write_nodes: list[int] = []
        self._read_nodes: list[int] = []

    # ─── Public API ───────────────────────────────────────────────────────────

    def build(
        self,
        programs: list[CobolProgram],
    ) -> CPG:

        logger.info(
            "CPG builder: creating nodes"
        )

        for program in programs:
            self._pass1_nodes(program)

        logger.info(
            "CPG builder: creating intra-program edges"
        )

        for program in programs:
            self._pass2_edges(program)

        logger.info(
            "CPG builder: creating cross-program edges"
        )

        self._pass3_cross_program(programs)

        logger.info(
            "CPG construction complete: %s",
            self._cpg,
        )

        return self._cpg

    # ─── Pass 1: nodes ────────────────────────────────────────────────────────

    def _pass1_nodes(
        self,
        program: CobolProgram,
    ) -> None:

        entry_nid = self._cpg.add_node(
            kind=NodeKind.ENTRY,
            program=program.program_id,
            file=program.file_path,
            line=1,
            label=program.program_id,
        )

        exit_nid = self._cpg.add_node(
            kind=NodeKind.EXIT,
            program=program.program_id,
            file=program.file_path,
            line=0,
            label=f"{program.program_id}:EXIT",
        )

        self._entry_nodes[
            program.program_id
        ] = entry_nid

        self._exit_nodes[
            program.program_id
        ] = exit_nid

        for item in program.data_items:
            self._make_data_item_node(
                item,
                program.program_id,
            )

        for stmt in self._iter_top_level_statements(
            program
        ):
            self._make_stmt_node(
                stmt,
                program.program_id,
                program.file_path,
            )

    def _make_data_item_node(
        self,
        item: DataItem,
        program_id: str,
    ) -> int:

        nid = self._cpg.add_node(
            kind=NodeKind.DATA_ITEM,
            stmt=item,
            program=program_id,
            file=(
                item.loc.file
                if item.loc
                else ""
            ),
            line=(
                item.loc.line
                if item.loc
                else 0
            ),
            field_name=item.name,
            section=item.section.name,
            picture=item.picture or "",
            copybook=item.copybook or "",
            redefines=item.redefines or "",
            is_sanitiser=_is_sanitiser_text(
                item.name
            ),
        )

        self._field_nodes[
            (program_id, item.name)
        ] = nid

        normalised = _normalise_identifier(
            item.name
        )

        if normalised:
            self._normalised_field_nodes[
                (program_id, normalised)
            ] = nid

        return nid

    # ─── Statement nodes ──────────────────────────────────────────────────────

    def _make_stmt_node(
        self,
        stmt,
        program_id: str,
        file_path: str,
    ) -> Optional[int]:

        key = (
            program_id,
            id(stmt),
        )

        if key in self._stmt_nodes:
            return self._stmt_nodes[key]

        loc = getattr(stmt, "loc", None)

        line = (
            loc.line
            if loc
            else 0
        )

        nid: Optional[int] = None

        # MOVE

        if isinstance(stmt, MoveStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.MOVE,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
            )

        # COMPUTE

        elif isinstance(stmt, ComputeStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.COMPUTE,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
            )

        # CALL

        elif isinstance(stmt, CallStmt):

            sink_kind = None

            if stmt.target_is_literal:
                sink_kind = (
                    _classify_call_target_as_sink(
                        stmt.target
                    )
                )

            nid = self._cpg.add_node(
                kind=NodeKind.CALL,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=sink_kind is not None,
                sink_kind=sink_kind,
                call_target=stmt.target,
            )

        # WRITE -> FILE_STORAGE or LOGGING

        elif isinstance(stmt, WriteStmt):

            sink_kind = _classify_write_sink(
                stmt.record_name,
                stmt.file_name,
            )

            nid = self._cpg.add_node(
                kind=NodeKind.WRITE,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=True,
                sink_kind=sink_kind,
                record_name=stmt.record_name,
                file_name=stmt.file_name or "",
            )

            self._write_nodes.append(nid)

        # READ

        elif isinstance(stmt, ReadStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.READ,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_source=True,
                source_kind="FILE",
                file_name=stmt.file_name,
                into_field=stmt.into_field or "",
            )

            self._read_nodes.append(nid)

        # DISPLAY -> LOGGING

        elif isinstance(stmt, DisplayStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.DISPLAY,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=True,
                sink_kind=_classify_display_sink(
                    stmt.upon
                ),
                upon=stmt.upon or "",
            )

        # EXEC SQL -> DATABASE

        elif isinstance(stmt, ExecSqlStmt):

            operation = (
                stmt.operation.upper()
                .strip()
            )

            is_sink = (
                operation
                in _SQL_DATABASE_SINKS
            )

            is_source = (
                operation
                in _SQL_DATABASE_SOURCES
            )

            nid = self._cpg.add_node(
                kind=NodeKind.EXEC_SQL,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=is_sink,
                sink_kind=(
                    SinkKind.DATABASE
                    if is_sink
                    else None
                ),
                is_source=is_source,
                source_kind=(
                    "DATABASE"
                    if is_source
                    else None
                ),
                external_kind="SQL",
                operation=operation,
                raw_text=stmt.raw_text,
            )

        # EXEC SQL IMS -> DATABASE

        elif isinstance(stmt, ExecSqlImsStmt):

            operation = (
                stmt.operation.upper()
                .strip()
            )

            is_sink = (
                operation
                in _IMS_DATABASE_SINKS
            )

            is_source = (
                operation
                in _IMS_DATABASE_SOURCES
            )

            nid = self._cpg.add_node(
                kind=NodeKind.EXEC_SQL_IMS,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=is_sink,
                sink_kind=(
                    SinkKind.DATABASE
                    if is_sink
                    else None
                ),
                is_source=is_source,
                source_kind=(
                    "IMS_DATABASE"
                    if is_source
                    else None
                ),
                external_kind="IMS",
                operation=operation,
                raw_text=stmt.raw_text,
            )

        # EXEC CICS

        elif isinstance(stmt, ExecCicsStmt):

            operation = (
                stmt.operation.upper()
                .strip()
            )

            is_sink = False
            is_source = False

            sink_kind = None
            source_kind = None

            if operation in _CICS_NETWORK_SINKS:

                is_sink = True
                sink_kind = (
                    SinkKind.NETWORK_TRANSFER
                )

            elif operation in _CICS_MESSAGE_SINKS:

                is_sink = True
                sink_kind = (
                    SinkKind.MESSAGING
                )

            elif operation in _CICS_MESSAGE_SOURCES:

                is_source = True
                source_kind = "MESSAGING"

            elif operation in _CICS_CALL_OPERATIONS:

                # CICS LINK/XCTL can transfer data to another
                # program/service. They are retained as explicit
                # service-interface operations rather than blindly
                # declaring every one a sink.

                sink_kind = None

            nid = self._cpg.add_node(
                kind=NodeKind.EXEC_CICS,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sink=is_sink,
                sink_kind=sink_kind,
                is_source=is_source,
                source_kind=source_kind,
                external_kind="CICS",
                operation=operation,
                raw_text=stmt.raw_text,
            )

        # IF

        elif isinstance(stmt, IfStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.IF,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_guard=_is_guard_text(
                    stmt.condition_text
                ),
                condition=stmt.condition_text,
            )

            self._stmt_nodes[key] = nid

            for child in stmt.then_stmts:

                child_nid = self._make_stmt_node(
                    child,
                    program_id,
                    file_path,
                )

                if child_nid is not None:
                    self._cpg.add_edge(
                        nid,
                        child_nid,
                        kind=EdgeKind.AST,
                        branch="THEN",
                    )

            for child in stmt.else_stmts:

                child_nid = self._make_stmt_node(
                    child,
                    program_id,
                    file_path,
                )

                if child_nid is not None:
                    self._cpg.add_edge(
                        nid,
                        child_nid,
                        kind=EdgeKind.AST,
                        branch="ELSE",
                    )

            return nid

        # PERFORM

        elif isinstance(stmt, PerformStmt):

            nid = self._cpg.add_node(
                kind=NodeKind.PERFORM,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                target=stmt.target or "",
                is_inline=stmt.is_inline,
            )

            self._stmt_nodes[key] = nid

            for child in stmt.body_stmts:

                child_nid = self._make_stmt_node(
                    child,
                    program_id,
                    file_path,
                )

                if child_nid is not None:
                    self._cpg.add_edge(
                        nid,
                        child_nid,
                        kind=EdgeKind.AST,
                    )

            return nid

        # GENERIC

        else:

            text = (
                stmt.text
                if isinstance(stmt, GenericStmt)
                else str(stmt)
            )

            nid = self._cpg.add_node(
                kind=NodeKind.GENERIC,
                stmt=stmt,
                program=program_id,
                file=file_path,
                line=line,
                is_sanitiser=_is_sanitiser_text(
                    text
                ),
            )

        if nid is not None:

            self._stmt_nodes[key] = nid

        return nid

    # ─── Pass 2: CFG and PDG ──────────────────────────────────────────────────

    def _pass2_edges(
        self,
        program: CobolProgram,
    ) -> None:

        entry_nid = self._entry_nodes[
            program.program_id
        ]

        exit_nid = self._exit_nodes[
            program.program_id
        ]

        statements = list(
            self._iter_top_level_statements(
                program
            )
        )

        nodes = [
            self._find_stmt_node(
                stmt,
                program.program_id,
            )
            for stmt in statements
        ]

        nodes = [
            nid
            for nid in nodes
            if nid is not None
        ]

        # CFG

        if not nodes:

            self._cpg.add_edge(
                entry_nid,
                exit_nid,
                kind=EdgeKind.CFG,
            )

        else:

            self._cpg.add_edge(
                entry_nid,
                nodes[0],
                kind=EdgeKind.CFG,
            )

            for current, successor in zip(
                nodes,
                nodes[1:],
            ):
                self._cpg.add_edge(
                    current,
                    successor,
                    kind=EdgeKind.CFG,
                )

            self._cpg.add_edge(
                nodes[-1],
                exit_nid,
                kind=EdgeKind.CFG,
            )

        # Nested CFG

        for stmt in statements:
            self._add_nested_cfg(
                stmt,
                program.program_id,
            )

        # PDG

        for stmt in self._iter_all_statements_recursive(
            statements
        ):
            self._add_pdg_edges(
                stmt,
                program,
            )

    # ─── Nested CFG ───────────────────────────────────────────────────────────

    def _add_nested_cfg(
        self,
        stmt,
        program_id: str,
    ) -> None:

        parent_nid = self._find_stmt_node(
            stmt,
            program_id,
        )

        if parent_nid is None:
            return

        if isinstance(stmt, IfStmt):

            self._connect_nested_sequence(
                parent_nid,
                stmt.then_stmts,
                program_id,
                "THEN",
            )

            self._connect_nested_sequence(
                parent_nid,
                stmt.else_stmts,
                program_id,
                "ELSE",
            )

            for child in stmt.then_stmts:
                self._add_nested_cfg(
                    child,
                    program_id,
                )

            for child in stmt.else_stmts:
                self._add_nested_cfg(
                    child,
                    program_id,
                )

        elif isinstance(stmt, PerformStmt):

            self._connect_nested_sequence(
                parent_nid,
                stmt.body_stmts,
                program_id,
                "PERFORM",
            )

            for child in stmt.body_stmts:
                self._add_nested_cfg(
                    child,
                    program_id,
                )

    def _connect_nested_sequence(
        self,
        parent_nid: int,
        statements: list,
        program_id: str,
        branch: str,
    ) -> None:

        nodes = [
            self._find_stmt_node(
                stmt,
                program_id,
            )
            for stmt in statements
        ]

        nodes = [
            nid
            for nid in nodes
            if nid is not None
        ]

        if not nodes:
            return

        self._cpg.add_edge(
            parent_nid,
            nodes[0],
            kind=EdgeKind.CFG,
            branch=branch,
        )

        for current, successor in zip(
            nodes,
            nodes[1:],
        ):
            self._cpg.add_edge(
                current,
                successor,
                kind=EdgeKind.CFG,
                branch=branch,
            )

    # ─── PDG ──────────────────────────────────────────────────────────────────

    def _add_pdg_edges(
        self,
        stmt,
        program: CobolProgram,
    ) -> None:

        program_id = program.program_id

        stmt_nid = self._find_stmt_node(
            stmt,
            program_id,
        )

        # MOVE

        if isinstance(stmt, MoveStmt):

            source_nid = self._lookup_field_node(
                program_id,
                stmt.source,
            )

            if source_nid is None:
                return

            if stmt_nid is not None:

                self._cpg.add_edge(
                    source_nid,
                    stmt_nid,
                    kind=EdgeKind.PDG,
                    operation="MOVE",
                )

            for destination in stmt.destinations:

                destination_nid = (
                    self._lookup_field_node(
                        program_id,
                        destination,
                    )
                )

                if destination_nid is None:
                    continue

                self._cpg.add_edge(
                    source_nid,
                    destination_nid,
                    kind=EdgeKind.PDG,
                    operation="MOVE",
                    via=(
                        f"MOVE {stmt.source} "
                        f"TO {destination}"
                    ),
                )

        # COMPUTE

        elif isinstance(stmt, ComputeStmt):

            destination_nid = (
                self._lookup_field_node(
                    program_id,
                    stmt.destination,
                )
            )

            if destination_nid is None:
                return

            for operand in stmt.operands:

                source_nid = (
                    self._lookup_field_node(
                        program_id,
                        operand,
                    )
                )

                if source_nid is None:
                    continue

                if stmt_nid is not None:

                    self._cpg.add_edge(
                        source_nid,
                        stmt_nid,
                        kind=EdgeKind.PDG,
                        operation="COMPUTE",
                    )

                self._cpg.add_edge(
                    source_nid,
                    destination_nid,
                    kind=EdgeKind.PDG,
                    operation="COMPUTE",
                    via=(
                        f"COMPUTE "
                        f"{stmt.destination}"
                    ),
                )

        # READ -> field

        elif isinstance(stmt, ReadStmt):

            if (
                stmt_nid is None
                or not stmt.into_field
            ):
                return

            destination_nid = (
                self._lookup_field_node(
                    program_id,
                    stmt.into_field,
                )
            )

            if destination_nid is not None:

                self._cpg.add_edge(
                    stmt_nid,
                    destination_nid,
                    kind=EdgeKind.PDG,
                    operation="READ",
                    via=f"READ {stmt.file_name}",
                )

        # WRITE -> sink

        elif isinstance(stmt, WriteStmt):

            if stmt_nid is None:
                return

            source_field = (
                stmt.from_field
                or stmt.record_name
            )

            source_nid = (
                self._lookup_field_node(
                    program_id,
                    source_field,
                )
            )

            if source_nid is not None:

                self._cpg.add_edge(
                    source_nid,
                    stmt_nid,
                    kind=EdgeKind.PDG,
                    operation="WRITE",
                )

        # DISPLAY -> sink

        elif isinstance(stmt, DisplayStmt):

            if stmt_nid is None:
                return

            for operand in stmt.operands:

                source_nid = (
                    self._lookup_field_node(
                        program_id,
                        operand,
                    )
                )

                if source_nid is not None:

                    self._cpg.add_edge(
                        source_nid,
                        stmt_nid,
                        kind=EdgeKind.PDG,
                        operation="DISPLAY",
                    )

        # CALL

        elif isinstance(stmt, CallStmt):

            if stmt_nid is None:
                return

            for parameter in stmt.using_params:

                source_nid = (
                    self._lookup_field_node(
                        program_id,
                        parameter,
                    )
                )

                if source_nid is not None:

                    self._cpg.add_edge(
                        source_nid,
                        stmt_nid,
                        kind=EdgeKind.PDG,
                        operation="CALL",
                    )

        # EXEC SQL

        elif isinstance(stmt, ExecSqlStmt):

            if stmt_nid is None:
                return

            operation = (
                stmt.operation.upper()
                .strip()
            )

            if operation in _SQL_DATABASE_SINKS:

                for operand in stmt.operands:

                    source_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if source_nid is not None:

                        self._cpg.add_edge(
                            source_nid,
                            stmt_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"SQL {operation}"
                            ),
                        )

            elif operation in _SQL_DATABASE_SOURCES:

                for operand in stmt.operands:

                    destination_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if destination_nid is not None:

                        self._cpg.add_edge(
                            stmt_nid,
                            destination_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"SQL {operation}"
                            ),
                        )

        # EXEC SQL IMS

        elif isinstance(stmt, ExecSqlImsStmt):

            if stmt_nid is None:
                return

            operation = (
                stmt.operation.upper()
                .strip()
            )

            if operation in _IMS_DATABASE_SINKS:

                for operand in stmt.operands:

                    source_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if source_nid is not None:

                        self._cpg.add_edge(
                            source_nid,
                            stmt_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"IMS {operation}"
                            ),
                        )

            elif operation in _IMS_DATABASE_SOURCES:

                for operand in stmt.operands:

                    destination_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if destination_nid is not None:

                        self._cpg.add_edge(
                            stmt_nid,
                            destination_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"IMS {operation}"
                            ),
                        )

        # EXEC CICS

        elif isinstance(stmt, ExecCicsStmt):

            if stmt_nid is None:
                return

            operation = (
                stmt.operation.upper()
                .strip()
            )

            if (
                operation
                in _CICS_NETWORK_SINKS
                or operation
                in _CICS_MESSAGE_SINKS
            ):

                for operand in stmt.operands:

                    source_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if source_nid is not None:

                        self._cpg.add_edge(
                            source_nid,
                            stmt_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"CICS {operation}"
                            ),
                        )

            elif operation in _CICS_MESSAGE_SOURCES:

                for operand in stmt.operands:

                    destination_nid = (
                        self._lookup_field_node(
                            program_id,
                            operand,
                        )
                    )

                    if destination_nid is not None:

                        self._cpg.add_edge(
                            stmt_nid,
                            destination_nid,
                            kind=EdgeKind.PDG,
                            operation=(
                                f"CICS {operation}"
                            ),
                        )

    # ─── Pass 3: cross-program relationships ──────────────────────────────────

    def _pass3_cross_program(
        self,
        programs: list[CobolProgram],
    ) -> None:

        self._add_copybook_edges(programs)
        self._add_call_edges(programs)
        self._add_file_io_edges(programs)

    # ─── Copybooks ────────────────────────────────────────────────────────────

    def _add_copybook_edges(
        self,
        programs: list[CobolProgram],
    ) -> None:

        by_copybook_field: dict[
            tuple[str, str],
            list[int],
        ] = defaultdict(list)

        for program in programs:

            for item in program.data_items:

                if not item.copybook:
                    continue

                nid = self._lookup_field_node(
                    program.program_id,
                    item.name,
                )

                if nid is None:
                    continue

                key = (
                    item.copybook.upper(),
                    _normalise_identifier(
                        item.name
                    ),
                )

                by_copybook_field[key].append(
                    nid
                )

        for (
            member,
            field_name,
        ), nodes in by_copybook_field.items():

            unique_nodes = list(
                dict.fromkeys(nodes)
            )

            if len(unique_nodes) < 2:
                continue

            for source in unique_nodes:

                for destination in unique_nodes:

                    if source == destination:
                        continue

                    self._cpg.add_edge(
                        source,
                        destination,
                        kind=EdgeKind.COPYBOOK,
                        member=member,
                        field_name=field_name,
                    )

    # ─── CALL relationships ───────────────────────────────────────────────────

    def _add_call_edges(
        self,
        programs: list[CobolProgram],
    ) -> None:

        program_map = {
            program.program_id.upper(): program
            for program in programs
        }

        for caller in programs:

            statements = (
                self._iter_all_statements_recursive(
                    list(
                        self._iter_top_level_statements(
                            caller
                        )
                    )
                )
            )

            for stmt in statements:

                if not isinstance(
                    stmt,
                    CallStmt,
                ):
                    continue

                if not stmt.target_is_literal:
                    continue

                target_name = (
                    stmt.target.upper()
                    .strip()
                    .strip("'\"")
                )

                callee = program_map.get(
                    target_name
                )

                if callee is None:
                    continue

                call_nid = self._find_stmt_node(
                    stmt,
                    caller.program_id,
                )

                entry_nid = self._entry_nodes.get(
                    callee.program_id
                )

                exit_nid = self._exit_nodes.get(
                    callee.program_id
                )

                if (
                    call_nid is None
                    or entry_nid is None
                ):
                    continue

                self._cpg.add_edge(
                    call_nid,
                    entry_nid,
                    kind=EdgeKind.CALL,
                )

                if exit_nid is not None:

                    self._cpg.add_edge(
                        exit_nid,
                        call_nid,
                        kind=EdgeKind.RETURN,
                    )

                linkage_fields = [
                    item
                    for item in callee.data_items
                    if (
                        item.section
                        == DataSection.LINKAGE
                        and item.level == 1
                    )
                ]

                for index, parameter_name in enumerate(
                    stmt.using_params
                ):

                    if index >= len(linkage_fields):
                        break

                    caller_field_nid = (
                        self._lookup_field_node(
                            caller.program_id,
                            parameter_name,
                        )
                    )

                    linkage_field = (
                        linkage_fields[index]
                    )

                    callee_field_nid = (
                        self._lookup_field_node(
                            callee.program_id,
                            linkage_field.name,
                        )
                    )

                    if (
                        caller_field_nid is None
                        or callee_field_nid is None
                    ):
                        continue

                    self._cpg.add_edge(
                        caller_field_nid,
                        callee_field_nid,
                        kind=EdgeKind.PDG,
                        operation="CALL USING",
                        via=(
                            f"CALL "
                            f"{callee.program_id}"
                        ),
                        position=index,
                    )

                    self._cpg.add_edge(
                        callee_field_nid,
                        caller_field_nid,
                        kind=EdgeKind.RETURN,
                        operation="CALL RETURN",
                        via=(
                            f"CALL "
                            f"{callee.program_id}"
                        ),
                        position=index,
                    )

                if stmt.giving_param:

                    giving_nid = (
                        self._lookup_field_node(
                            caller.program_id,
                            stmt.giving_param,
                        )
                    )

                    if giving_nid is not None:

                        self._cpg.add_edge(
                            call_nid,
                            giving_nid,
                            kind=EdgeKind.RETURN,
                            operation="CALL GIVING",
                        )

    # ─── Shared-file flow ─────────────────────────────────────────────────────

    def _add_file_io_edges(
        self,
        programs: list[CobolProgram],
    ) -> None:

        write_aliases: dict[
            int,
            set[str],
        ] = {}

        read_aliases: dict[
            int,
            set[str],
        ] = {}

        program_map = {
            program.program_id: program
            for program in programs
        }

        # WRITE aliases

        for write_nid in self._write_nodes:

            data = self._cpg.get(
                write_nid
            )

            stmt = data.get("stmt")

            if not isinstance(
                stmt,
                WriteStmt,
            ):
                continue

            program = program_map.get(
                data.get("program", "")
            )

            aliases: set[str] = set()

            if stmt.file_name:
                aliases.add(
                    _normalise_identifier(
                        stmt.file_name
                    )
                )

            if stmt.record_name:
                aliases.add(
                    _normalise_identifier(
                        stmt.record_name
                    )
                )

            if program is not None:

                for (
                    file_name,
                    record_name,
                ) in program.fd_map.items():

                    if (
                        _normalise_identifier(
                            record_name
                        )
                        == _normalise_identifier(
                            stmt.record_name
                        )
                    ):

                        aliases.add(
                            _normalise_identifier(
                                file_name
                            )
                        )

            aliases.discard("")

            write_aliases[
                write_nid
            ] = aliases

        # READ aliases

        for read_nid in self._read_nodes:

            data = self._cpg.get(
                read_nid
            )

            stmt = data.get("stmt")

            if not isinstance(
                stmt,
                ReadStmt,
            ):
                continue

            program = program_map.get(
                data.get("program", "")
            )

            aliases = {
                _normalise_identifier(
                    stmt.file_name
                )
            }

            if program is not None:

                record_name = (
                    program.fd_map.get(
                        stmt.file_name
                    )
                )

                if record_name:

                    aliases.add(
                        _normalise_identifier(
                            record_name
                        )
                    )

            aliases.discard("")

            read_aliases[
                read_nid
            ] = aliases

        # Connect matching WRITE -> READ.

        for (
            write_nid,
            write_names,
        ) in write_aliases.items():

            for (
                read_nid,
                read_names,
            ) in read_aliases.items():

                shared = (
                    write_names
                    & read_names
                )

                if not shared:
                    continue

                self._cpg.add_edge(
                    write_nid,
                    read_nid,
                    kind=EdgeKind.FILE_IO,
                    shared_identifiers=sorted(
                        shared
                    ),
                )

    # ─── Lookup helpers ───────────────────────────────────────────────────────

    def _lookup_field_node(
        self,
        program_id: str,
        field_name: Optional[str],
    ) -> Optional[int]:

        if not field_name:
            return None

        if _looks_like_literal(
            field_name
        ):
            return None

        exact = self._field_nodes.get(
            (
                program_id,
                field_name,
            )
        )

        if exact is not None:
            return exact

        normalised = _normalise_identifier(
            field_name
        )

        return self._normalised_field_nodes.get(
            (
                program_id,
                normalised,
            )
        )

    def _find_stmt_node(
        self,
        stmt,
        program_id: str,
    ) -> Optional[int]:

        return self._stmt_nodes.get(
            (
                program_id,
                id(stmt),
            )
        )

    # ─── AST traversal ────────────────────────────────────────────────────────

    @staticmethod
    def _iter_top_level_statements(
        program: CobolProgram,
    ):

        for paragraph in program.paragraphs:
            yield from paragraph.statements

        for section in program.sections:

            for paragraph in section.paragraphs:
                yield from paragraph.statements

    def _iter_all_statements_recursive(
        self,
        statements: list,
    ):

        for stmt in statements:

            yield stmt

            if isinstance(
                stmt,
                IfStmt,
            ):

                yield from (
                    self._iter_all_statements_recursive(
                        stmt.then_stmts
                    )
                )

                yield from (
                    self._iter_all_statements_recursive(
                        stmt.else_stmts
                    )
                )

            elif isinstance(
                stmt,
                PerformStmt,
            ):

                yield from (
                    self._iter_all_statements_recursive(
                        stmt.body_stmts
                    )
                )