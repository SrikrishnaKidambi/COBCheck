"""
cobcheck/cpg/builder.py
────────────────────────
Builds a CPG from one or more CobolProgram ASTs.

The builder runs in three passes:

Pass 1 — Intra-program nodes
    For every program: create DATA_ITEM nodes for all data fields,
    then walk each statement and create a corresponding statement node.
    All nodes are added to the shared CPG.

Pass 2 — Intra-program edges
    AST edges (containment), CFG edges (sequential flow through statements
    within a paragraph), PDG edges (MOVE/COMPUTE def→use chains).

Pass 3 — Inter-program edges
    COPYBOOK edges: a field defined in a copybook is connected to every
    program that COPYs it.
    CALL edges: CALL statement node → ENTRY node of the called program.
    FILE_IO edges: FILE_WRITE node in program A → FILE_READ node in
    program B that reads the same file.

After construction the CPG is ready for the PII tagger (which sets pii_fields
on DATA_ITEM nodes) and the taint engine (which propagates pii_fields along
PDG/CALL/FILE_IO edges and checks sink reachability).
"""

from __future__ import annotations

import logging
from typing import Optional

from ..parser.ast_nodes import (
    CobolProgram, DataItem, DataSection,
    MoveStmt, ComputeStmt, CallStmt, WriteStmt, ReadStmt,
    DisplayStmt, IfStmt, PerformStmt, GenericStmt, CopyStmt,
    Paragraph, Section,
)
from ..parser.copybook_resolver import CopybookResolver
from .graph_model import CPG, NodeKind, EdgeKind, SinkKind

logger = logging.getLogger(__name__)


# ─── Sink detection heuristics ────────────────────────────────────────────────
# These match file/record names against known patterns to classify sink kinds.

_LOG_PATTERNS    = {"LOG", "AUDIT", "TRACE", "JOURNAL", "JRNL", "RPT", "REPORT",
                    "SYSOUT", "SYSPRINT", "PRINT", "LIST"}
_DISPLAY_TOKENS  = {"DISPLAY"}
_EXTERNAL_TOKENS = {"SEND", "API", "EXPORT", "XFER", "TRANSFER", "SOCKET", "MQ",
                    "QUEUE", "CICS", "WEBSVC"}
_ENCRYPT_TOKENS  = {"ENCR", "MASK", "HASH", "REDACT", "SCRAMBLE", "CIPHER",
                    "ENCRYPT", "AES", "SHA", "HMAC"}
_CONSENT_TOKENS  = {"CONSENT", "GDPR", "PERMIT", "AUTHORIZ", "AUTHORI"}


def _classify_sink(name: str) -> Optional[SinkKind]:
    """
    Heuristically classify a record/file name as a sink kind.
    Returns None if the name looks benign.
    """
    upper = name.upper()
    for tok in _EXTERNAL_TOKENS:
        if tok in upper:
            return SinkKind.EXTERNAL
    for tok in _LOG_PATTERNS:
        if tok in upper:
            return SinkKind.LOG
    return None


def _is_sanitiser(name: str) -> bool:
    upper = name.upper()
    return any(tok in upper for tok in _ENCRYPT_TOKENS)


def _is_guard(condition_text: str) -> bool:
    upper = condition_text.upper()
    return any(tok in upper for tok in _CONSENT_TOKENS)


# ─── Builder ──────────────────────────────────────────────────────────────────

class CPGBuilder:
    """
    Builds the cross-program CPG from a collection of CobolProgram ASTs.

    Parameters
    ----------
    resolver : CopybookResolver
        Used to inline copybook fields and draw COPYBOOK edges.
    """

    def __init__(self, resolver: Optional[CopybookResolver] = None):
        self._resolver = resolver
        self._cpg      = CPG()

        # Internal index structures
        # program_id → entry node ID
        self._entry_nodes:  dict[str, int]          = {}
        # (program_id, field_name) → DATA_ITEM node ID
        self._field_nodes:  dict[tuple[str,str], int] = {}
        # record_name → WRITE node IDs  (for file-I/O edges)
        self._write_nodes:  dict[str, list[int]]    = {}
        # record_name → READ node IDs
        self._read_nodes:   dict[str, list[int]]    = {}
        # copybook member → list[DATA_ITEM node IDs] in the copybook
        self._copybook_fields: dict[str, list[int]] = {}

    # ─── Public API ───────────────────────────────────────────────────────────

    def build(self, programs: list[CobolProgram]) -> CPG:
        """
        Run all three passes over *programs* and return the finished CPG.
        """
        logger.info("CPG builder: pass 1 — nodes (%d programs)", len(programs))
        for prog in programs:
            self._pass1_nodes(prog)

        logger.info("CPG builder: pass 2 — intra-program edges")
        for prog in programs:
            self._pass2_edges(prog)

        logger.info("CPG builder: pass 3 — inter-program edges")
        self._pass3_cross_program(programs)

        logger.info("CPG built: %s", self._cpg)
        return self._cpg

    # ─── Pass 1: nodes ────────────────────────────────────────────────────────

    def _pass1_nodes(self, prog: CobolProgram) -> None:
        # Program ENTRY node
        entry_nid = self._cpg.add_node(
            kind    = NodeKind.ENTRY,
            program = prog.program_id,
            file    = prog.file_path,
            line    = 1,
            label   = prog.program_id,
        )
        self._entry_nodes[prog.program_id] = entry_nid

        # DATA_ITEM nodes for every field in the Data Division
        for item in prog.data_items:
            self._make_data_item_node(item, prog.program_id)

        # Statement nodes for every statement in the Procedure Division
        for para in prog.paragraphs:
            for stmt in para.statements:
                self._make_stmt_node(stmt, prog.program_id, prog.file_path)
        for sec in prog.sections:
            for para in sec.paragraphs:
                for stmt in para.statements:
                    self._make_stmt_node(stmt, prog.program_id, prog.file_path)

    def _make_data_item_node(self, item: DataItem, program_id: str) -> int:
        is_san = _is_sanitiser(item.name)
        nid = self._cpg.add_node(
            kind         = NodeKind.DATA_ITEM,
            stmt         = item,
            program      = program_id,
            file         = item.loc.file  if item.loc else "",
            line         = item.loc.line  if item.loc else 0,
            field_name   = item.name,
            section      = item.section.name,
            picture      = item.picture or "",
            copybook     = item.copybook or "",
            redefines    = item.redefines or "",
            is_sanitiser = is_san,
        )
        self._field_nodes[(program_id, item.name)] = nid
        return nid

    def _make_stmt_node(self, stmt, program_id: str, file_path: str) -> Optional[int]:
        loc  = getattr(stmt, "loc", None)
        line = loc.line if loc else 0

        if isinstance(stmt, MoveStmt):
            nid = self._cpg.add_node(
                kind    = NodeKind.MOVE,
                stmt    = stmt,
                program = program_id,
                file    = file_path,
                line    = line,
            )
            return nid

        if isinstance(stmt, ComputeStmt):
            nid = self._cpg.add_node(
                kind    = NodeKind.COMPUTE,
                stmt    = stmt,
                program = program_id,
                file    = file_path,
                line    = line,
            )
            return nid

        if isinstance(stmt, CallStmt):
            nid = self._cpg.add_node(
                kind      = NodeKind.CALL,
                stmt      = stmt,
                program   = program_id,
                file      = file_path,
                line      = line,
                call_target = stmt.target,
            )
            return nid

        if isinstance(stmt, WriteStmt):
            sink_kind = _classify_sink(stmt.record_name)
            is_sink   = True   # WRITE is always potentially a sink
            if sink_kind is None:
                sink_kind = SinkKind.FILE   # default: at-rest persistence
            nid = self._cpg.add_node(
                kind        = NodeKind.WRITE,
                stmt        = stmt,
                program     = program_id,
                file        = file_path,
                line        = line,
                is_sink     = is_sink,
                sink_kind   = sink_kind,
                record_name = stmt.record_name,
            )
            rec = stmt.record_name.upper()
            self._write_nodes.setdefault(rec, []).append(nid)
            return nid

        if isinstance(stmt, ReadStmt):
            nid = self._cpg.add_node(
                kind      = NodeKind.READ,
                stmt      = stmt,
                program   = program_id,
                file      = file_path,
                line      = line,
                file_name = stmt.file_name,
            )
            file_upper = stmt.file_name.upper()
            self._read_nodes.setdefault(file_upper, []).append(nid)
            return nid

        if isinstance(stmt, DisplayStmt):
            nid = self._cpg.add_node(
                kind      = NodeKind.DISPLAY,
                stmt      = stmt,
                program   = program_id,
                file      = file_path,
                line      = line,
                is_sink   = True,
                sink_kind = SinkKind.DISPLAY,
            )
            return nid

        if isinstance(stmt, IfStmt):
            is_guard = _is_guard(stmt.condition_text)
            nid = self._cpg.add_node(
                kind      = NodeKind.IF,
                stmt      = stmt,
                program   = program_id,
                file      = file_path,
                line      = line,
                is_guard  = is_guard,
            )
            # Recurse into branches
            for child in stmt.then_stmts + stmt.else_stmts:
                self._make_stmt_node(child, program_id, file_path)
            return nid

        if isinstance(stmt, PerformStmt):
            nid = self._cpg.add_node(
                kind    = NodeKind.PERFORM,
                stmt    = stmt,
                program = program_id,
                file    = file_path,
                line    = line,
            )
            for child in stmt.body_stmts:
                self._make_stmt_node(child, program_id, file_path)
            return nid

        # Catch-all
        is_san  = isinstance(stmt, GenericStmt) and _is_sanitiser(stmt.text)
        nid = self._cpg.add_node(
            kind         = NodeKind.GENERIC,
            stmt         = stmt,
            program      = program_id,
            file         = file_path,
            line         = line,
            is_sanitiser = is_san,
        )
        return nid

    # ─── Pass 2: intra-program edges ──────────────────────────────────────────

    def _pass2_edges(self, prog: CobolProgram) -> None:
        entry_nid = self._entry_nodes[prog.program_id]

        # CFG: entry → first paragraph
        all_paras = list(prog.paragraphs)
        for sec in prog.sections:
            all_paras.extend(sec.paragraphs)

        if all_paras:
            # We don't have paragraph entry nodes; connect entry → first stmt
            first_stmts = _first_stmts(all_paras[0])
            for fs in first_stmts:
                self._add_cfg_for_stmt(fs, entry_nid, prog)

        # PDG: def → use edges from MOVE / COMPUTE
        for stmt in prog.all_statements:
            self._add_pdg_edges(stmt, prog)

    def _add_cfg_for_stmt(self, stmt, prev_nid: int, prog: CobolProgram) -> None:
        """Add a CFG edge from prev_nid to the node for stmt (best-effort)."""
        nid = self._find_stmt_node(stmt, prog.program_id)
        if nid is not None:
            self._cpg.add_edge(prev_nid, nid, kind=EdgeKind.CFG)

    def _add_pdg_edges(self, stmt, prog: CobolProgram) -> None:
        """Add PDG (def→use) edges for data-flow statements."""
        if isinstance(stmt, MoveStmt):
            src_nid = self._field_nodes.get((prog.program_id, stmt.source))
            if src_nid is None:
                return
            for dest in stmt.destinations:
                dst_nid = self._field_nodes.get((prog.program_id, dest))
                if dst_nid is not None:
                    self._cpg.add_edge(src_nid, dst_nid, kind=EdgeKind.PDG,
                                       via=f"MOVE {stmt.source} TO {dest}")

            # Also PDG: source field → MOVE statement node (for sink reachability)
            stmt_nid = self._find_stmt_node(stmt, prog.program_id)
            if stmt_nid is not None:
                self._cpg.add_edge(src_nid, stmt_nid, kind=EdgeKind.PDG)

        if isinstance(stmt, ComputeStmt):
            dst_nid = self._field_nodes.get((prog.program_id, stmt.destination))
            if dst_nid is None:
                return
            for op in stmt.operands:
                src_nid = self._field_nodes.get((prog.program_id, op))
                if src_nid is not None:
                    self._cpg.add_edge(src_nid, dst_nid, kind=EdgeKind.PDG,
                                       via=f"COMPUTE {stmt.destination}")

        if isinstance(stmt, WriteStmt):
            # from_field → WRITE node
            if stmt.from_field:
                src_nid  = self._field_nodes.get((prog.program_id, stmt.from_field))
                stmt_nid = self._find_stmt_node(stmt, prog.program_id)
                if src_nid is not None and stmt_nid is not None:
                    self._cpg.add_edge(src_nid, stmt_nid, kind=EdgeKind.PDG)

        if isinstance(stmt, DisplayStmt):
            stmt_nid = self._find_stmt_node(stmt, prog.program_id)
            if stmt_nid is None:
                return
            for op in stmt.operands:
                src_nid = self._field_nodes.get((prog.program_id, op))
                if src_nid is not None:
                    self._cpg.add_edge(src_nid, stmt_nid, kind=EdgeKind.PDG)

    # ─── Pass 3: inter-program edges ──────────────────────────────────────────

    def _pass3_cross_program(self, programs: list[CobolProgram]) -> None:
        self._add_copybook_edges(programs)
        self._add_call_edges(programs)
        self._add_file_io_edges(programs)

    def _add_copybook_edges(self, programs: list[CobolProgram]) -> None:
        """
        COPYBOOK edges: for each COPY statement, connect DATA_ITEM nodes in
        the copybook to the corresponding DATA_ITEM in the program that COPYs it.
        (A PII field defined in a shared copybook is automatically tainted in
        every program that includes it — the edge makes this explicit.)
        """
        if self._resolver is None:
            return

        for prog in programs:
            for copy_stmt in prog.copy_stmts:
                cb_prog = self._resolver.load(copy_stmt.member, prog.program_id)
                if cb_prog is None:
                    continue
                for item in cb_prog.data_items:
                    # The item should also have been added to prog.data_items
                    # by the resolver (field inlining). Draw a COPYBOOK edge
                    # from the copybook's DATA_ITEM node to the program's node.
                    cb_nid   = self._field_nodes.get((cb_prog.program_id, item.name))
                    prog_nid = self._field_nodes.get((prog.program_id, item.name))
                    if cb_nid is not None and prog_nid is not None:
                        self._cpg.add_edge(cb_nid, prog_nid,
                                           kind   = EdgeKind.COPYBOOK,
                                           member = copy_stmt.member)

    def _add_call_edges(self, programs: list[CobolProgram]) -> None:
        """
        CALL edges: CALL statement node → ENTRY node of the called program.
        Also draw PDG edges for USING parameters:
            caller field → callee linkage field (by position).
        """
        prog_map = {p.program_id: p for p in programs}

        for prog in programs:
            for stmt in prog.all_statements:
                if not isinstance(stmt, CallStmt):
                    continue
                if not stmt.target_is_literal:
                    # Dynamic call — can't resolve statically; skip for now
                    logger.debug("Dynamic CALL in %s — skipped", prog.program_id)
                    continue

                callee = prog_map.get(stmt.target)
                if callee is None:
                    logger.debug("Unresolved CALL %s from %s",
                                 stmt.target, prog.program_id)
                    continue

                call_nid  = self._find_stmt_node(stmt, prog.program_id)
                entry_nid = self._entry_nodes.get(callee.program_id)
                if call_nid is None or entry_nid is None:
                    continue

                self._cpg.add_edge(call_nid, entry_nid, kind=EdgeKind.CALL)

                # PDG: USING params → LINKAGE SECTION fields (positional)
                linkage_fields = [
                    item for item in callee.data_items
                    if item.section == DataSection.LINKAGE and item.level == 1
                ]
                for i, param_name in enumerate(stmt.using_params):
                    if i >= len(linkage_fields):
                        break
                    src_nid = self._field_nodes.get((prog.program_id, param_name))
                    dst_nid = self._field_nodes.get(
                        (callee.program_id, linkage_fields[i].name))
                    if src_nid is not None and dst_nid is not None:
                        self._cpg.add_edge(src_nid, dst_nid,
                                           kind    = EdgeKind.PDG,
                                           via     = f"CALL {callee.program_id}",
                                           via_pos = i)

    def _add_file_io_edges(self, programs: list[CobolProgram]) -> None:
        """
        FILE_IO edges: if program A WRITEs to file F and program B READs
        from file F, draw FILE_IO edge from A's WRITE node to B's READ node.

        Matching is done by record name (from FD maps), falling back to
        file name matching.
        """
        for write_rec, write_nids in self._write_nodes.items():
            # Try to find READs for the same record
            for read_file, read_nids in self._read_nodes.items():
                # Heuristic match: record name appears in file name or vice versa
                if write_rec in read_file or read_file in write_rec:
                    for w_nid in write_nids:
                        for r_nid in read_nids:
                            self._cpg.add_edge(w_nid, r_nid,
                                               kind = EdgeKind.FILE_IO,
                                               via  = f"shared file {write_rec}")
                            logger.debug("FILE_IO edge: write(%s) → read(%s)",
                                         write_rec, read_file)

    # ─── Lookup helpers ───────────────────────────────────────────────────────

    def _find_stmt_node(self, stmt, program_id: str) -> Optional[int]:
        """Find the node ID whose stmt attribute is *exactly* the given stmt object."""
        for nid, data in self._cpg.G.nodes(data=True):
            if data.get("stmt") is stmt and data.get("program") == program_id:
                return nid
        return None


# ─── Private helpers ──────────────────────────────────────────────────────────

def _first_stmts(para: Paragraph) -> list:
    """Return the first statement(s) of a paragraph."""
    return para.statements[:1] if para.statements else []