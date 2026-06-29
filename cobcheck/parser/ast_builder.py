"""
cobcheck/parser/ast_builder.py
Walks the real Cobol85.g4 parse tree and produces CobolProgram AST nodes.
Method names match the real grammars-v4 Cobol85.g4 exactly.
"""

from __future__ import annotations
import re
import os
from typing import Optional

from .ast_nodes import (
    SourceLocation, DataItem, DataSection,
    MoveStmt, ComputeStmt, CallStmt, WriteStmt, ReadStmt,
    DisplayStmt, CopyStmt, IfStmt, PerformStmt, GenericStmt,
    Paragraph, Section, CobolProgram,
)

try:
    from antlr4 import CommonTokenStream, InputStream
    from antlr4.tree.Tree import TerminalNode
    from .generated.Cobol85Lexer  import Cobol85Lexer
    from .generated.Cobol85Parser import Cobol85Parser
    _ANTLR_AVAILABLE = True
except ImportError:
    _ANTLR_AVAILABLE = False


# ── helpers ───────────────────────────────────────────────────────────────────

def _loc(ctx, program_id: str, file_path: str) -> SourceLocation:
    token = ctx.start if hasattr(ctx, "start") and ctx.start else ctx
    line   = token.line   if hasattr(token, "line")   else 0
    column = token.column if hasattr(token, "column") else 0
    return SourceLocation(program=program_id, file=file_path,
                          line=line, column=column)

def _text(ctx) -> str:
    if ctx is None:
        return ""
    if isinstance(ctx, list):
        return ctx[0].getText().upper() if ctx else ""
    return ctx.getText()

def _name(ctx) -> str:
    return _text(ctx).upper()

def _safe(ctx, attr, *args):
    """Safely call ctx.attr() returning None on any error."""
    try:
        fn = getattr(ctx, attr, None)
        if fn is None or not callable(fn):
            return None
        result = fn(*args)
        if isinstance(result, list):
            return result[0] if result else None
        return result
    except Exception:
        return None

def _collect_identifiers(ctx) -> list[str]:
    """Recursively collect all identifier names from a subtree."""
    names = []
    if ctx is None:
        return names
    try:
        count = ctx.getChildCount()
    except Exception:
        return names
    for i in range(count):
        child = ctx.getChild(i)
        if child is None:
            continue
        try:
            text = child.getText().upper()
            if re.match(r'^[A-Z][A-Z0-9\-]+$', text):
                names.append(text)
        except Exception:
            pass
        names.extend(_collect_identifiers(child))
    return names


# ── visitor ───────────────────────────────────────────────────────────────────

class _CobolASTVisitor:

    def __init__(self, file_path: str):
        self._file_path   = file_path
        self._program_id  = os.path.splitext(
            os.path.basename(file_path))[0].upper()
        self._data_items: list[DataItem]  = []
        self._sections:   list[Section]   = []
        self._paragraphs: list[Paragraph] = []
        self._copy_stmts: list[CopyStmt]  = []
        self._fd_map:     dict[str,str]   = {}
        self._current_section = DataSection.UNKNOWN

    def build(self, tree) -> CobolProgram:
        self._walk(tree)
        return CobolProgram(
            file_path  = self._file_path,
            program_id = self._program_id,
            data_items = self._data_items,
            sections   = self._sections,
            paragraphs = self._paragraphs,
            copy_stmts = self._copy_stmts,
            fd_map     = self._fd_map,
        )

    # ── tree walker ───────────────────────────────────────────────────────────

    def _walk(self, ctx):
        if ctx is None:
            return
        name = type(ctx).__name__

        if name == "ProgramIdParagraphContext":
            self._on_program_id(ctx)
        elif name == "WorkingStorageSectionContext":
            self._current_section = DataSection.WORKING_STORAGE
            self._walk_children(ctx)
        elif name == "LinkageSectionContext":
            self._current_section = DataSection.LINKAGE
            self._walk_children(ctx)
        elif name == "FileSectionContext":
            self._current_section = DataSection.FILE
            self._walk_children(ctx)
        elif name == "LocalStorageSectionContext":
            self._current_section = DataSection.LOCAL_STORAGE
            self._walk_children(ctx)
        elif name == "DataDescriptionEntryFormat1Context":
            self._on_data_item(ctx)
        elif name == "FileDescriptionEntryContext":
            self._on_fd(ctx)
        elif name == "ParagraphContext":
            self._on_paragraph(ctx)
        elif name == "ProcedureSectionContext":
            self._on_section(ctx)
        else:
            self._walk_children(ctx)

    def _walk_children(self, ctx):
        if ctx is None:
            return
        try:
            count = ctx.getChildCount()
        except Exception:
            return
        for i in range(count):
            self._walk(ctx.getChild(i))

    # ── identification ────────────────────────────────────────────────────────

    def _on_program_id(self, ctx):
        pn = _safe(ctx, "programName")
        if pn:
            self._program_id = _name(pn)

    # ── data division ─────────────────────────────────────────────────────────

    def _on_fd(self, ctx):
        fn = _safe(ctx, "fileName")
        if fn:
            self._fd_map[_name(fn)] = _name(fn)
        self._walk_children(ctx)

    def _on_data_item(self, ctx):
        # Level number — first INTEGERLITERAL or LEVEL_NUMBER_77
        level = 1
        try:
            il = _safe(ctx, "INTEGERLITERAL")
            if il:
                level = int(il.getText())
            else:
                lv = _safe(ctx, "LEVEL_NUMBER_77")
                if lv:
                    level = 77
        except Exception:
            pass

        # Name — dataName() or FILLER
        name = "FILLER"
        try:
            dn = _safe(ctx, "dataName")
            if dn:
                name = _name(dn)
        except Exception:
            pass

        # PIC — dataPictureClause (real grammar name)
        picture = None
        try:
            clauses = ctx.dataPictureClause() if hasattr(ctx, "dataPictureClause") else []
            if clauses:
                pc = clauses[0] if isinstance(clauses, list) else clauses
                ps = _safe(pc, "pictureString")
                if ps:
                    picture = ps.getText().upper()
        except Exception:
            pass

        # REDEFINES — dataRedefinesClause (real grammar name)
        redefines = None
        try:
            rc_list = ctx.dataRedefinesClause() if hasattr(ctx, "dataRedefinesClause") else []
            if rc_list:
                rc = rc_list[0] if isinstance(rc_list, list) else rc_list
                dn2 = _safe(rc, "dataName")
                if dn2:
                    redefines = _name(dn2)
        except Exception:
            pass

        item = DataItem(
            level     = level,
            name      = name,
            picture   = picture,
            redefines = redefines,
            section   = self._current_section,
            loc       = _loc(ctx, self._program_id, self._file_path),
        )
        self._data_items.append(item)
        # Walk children for nested items
        self._walk_children(ctx)

    # ── procedure division ────────────────────────────────────────────────────

    def _on_section(self, ctx):
        hdr  = _safe(ctx, "procedureSectionHeader")
        name = _name(_safe(hdr, "sectionName")) if hdr else "UNKNOWN"
        sec  = Section(name=name,
                       loc=_loc(ctx, self._program_id, self._file_path))
        paras_ctx = _safe(ctx, "paragraphs")
        if paras_ctx:
            for pc in (paras_ctx.paragraph() if hasattr(paras_ctx, "paragraph") else []):
                sec.paragraphs.append(self._build_paragraph(pc))
        self._sections.append(sec)

    def _on_paragraph(self, ctx):
        self._paragraphs.append(self._build_paragraph(ctx))

    def _build_paragraph(self, ctx) -> Paragraph:
        pn   = _safe(ctx, "paragraphName")
        name = _name(pn) if pn else "UNKNOWN"
        para = Paragraph(name=name,
                         loc=_loc(ctx, self._program_id, self._file_path))
        # sentences → statements
        sentences = ctx.sentence() if hasattr(ctx, "sentence") else []
        for sent in sentences:
            stmts = sent.statement() if hasattr(sent, "statement") else []
            for stmt_ctx in stmts:
                s = self._build_stmt(stmt_ctx)
                if s is not None:
                    para.statements.append(s)
        return para

    # ── statement dispatch ────────────────────────────────────────────────────

    def _build_stmt(self, ctx):
        if ctx is None:
            return None
        name = type(ctx).__name__

        # The real grammar wraps in StatementContext — unwrap one level
        if name == "StatementContext":
            for i in range(ctx.getChildCount()):
                child = ctx.getChild(i)
                if child and not isinstance(child,
                        __import__('antlr4').tree.Tree.TerminalNode
                        if _ANTLR_AVAILABLE else type(None)):
                    return self._build_stmt(child)
            return None

        if name == "MoveStatementContext":
            return self._build_move(ctx)
        if name == "ComputeStatementContext":
            return self._build_compute(ctx)
        if name == "CallStatementContext":
            return self._build_call(ctx)
        if name == "WriteStatementContext":
            return self._build_write(ctx)
        if name == "ReadStatementContext":
            return self._build_read(ctx)
        if name == "DisplayStatementContext":
            return self._build_display(ctx)
        if name == "IfStatementContext":
            return self._build_if(ctx)
        if name == "PerformStatementContext":
            return self._build_perform(ctx)

        return GenericStmt(text=ctx.getText(),
                           loc=_loc(ctx, self._program_id, self._file_path))

    def _build_move(self, ctx) -> MoveStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            # Real grammar: moveStatement → MOVE ALL? (moveToStatement | moveCorrespondingToStatement)
            mts = _safe(ctx, "moveToStatement")
            if mts:
                src_ctx = _safe(mts, "moveToSendingArea")
                source  = _name(src_ctx) if src_ctx else ""
                dests   = [_name(d) for d in (mts.identifier() if hasattr(mts, "identifier") else [])]
                return MoveStmt(source=source, destinations=dests, loc=loc)
            mcs = _safe(ctx, "moveCorrespondingToStatement")
            if mcs:
                src_ctx = _safe(mcs, "moveCorrespondingToSendingArea")
                source  = _name(src_ctx) if src_ctx else ""
                dests   = [_name(d) for d in (mcs.identifier() if hasattr(mcs, "identifier") else [])]
                return MoveStmt(source=source, destinations=dests,
                                is_group_move=True, loc=loc)
        except Exception:
            pass
        return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_compute(self, ctx) -> ComputeStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            stores = ctx.computeStore() if hasattr(ctx, "computeStore") else []
            dest   = _name(stores[0]) if stores else ""
            ae     = _safe(ctx, "arithmeticExpression")
            ops    = _collect_identifiers(ae) if ae else []
            return ComputeStmt(destination=dest, operands=ops, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_call(self, ctx) -> CallStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            lit = _safe(ctx, "literal")
            idn = _safe(ctx, "identifier")
            target_is_literal = lit is not None
            target = _name(lit or idn).strip("'\"") if (lit or idn) else "UNKNOWN"

            using_params = []
            cup = _safe(ctx, "callUsingPhrase")
            if cup:
                for param in (cup.callUsingParameter() if hasattr(cup, "callUsingParameter") else []):
                    names = _collect_identifiers(param)
                    for n in names:
                        if n not in {"BY","REFERENCE","VALUE","CONTENT",
                                     "ADDRESS","OF","LENGTH","USING"}:
                            using_params.append(n)
            return CallStmt(target=target, target_is_literal=target_is_literal,
                            using_params=using_params, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_write(self, ctx) -> WriteStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            rn = _safe(ctx, "recordName")
            record_name = _name(rn) if rn else ""
            from_field  = None
            wfp = _safe(ctx, "writeFromPhrase")
            if wfp:
                idn = _safe(wfp, "identifier")
                lit = _safe(wfp, "literal")
                from_field = _name(idn or lit) if (idn or lit) else None
            return WriteStmt(record_name=record_name,
                             from_field=from_field, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_read(self, ctx) -> ReadStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            fn        = _safe(ctx, "fileName")
            file_name = _name(fn) if fn else ""
            into_field = None
            # real grammar uses readInto not readIntoPhrase
            for attr in ("readInto", "readIntoPhrase"):
                ri = _safe(ctx, attr)
                if ri:
                    idn = _safe(ri, "identifier")
                    into_field = _name(idn) if idn else None
                    break
            return ReadStmt(file_name=file_name, into_field=into_field, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_display(self, ctx) -> DisplayStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            operands = []
            ops = ctx.displayOperand() if hasattr(ctx, "displayOperand") else []
            for op in ops:
                # real grammar: displayOperand → identifier | literal
                idn = _safe(op, "identifier")
                lit = _safe(op, "literal")
                val = _name(idn or lit) if (idn or lit) else op.getText().upper()
                if val:
                    operands.append(val)
            return DisplayStmt(operands=operands, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)

    def _build_if(self, ctx) -> IfStmt:
        loc  = _loc(ctx, self._program_id, self._file_path)
        cond = ""
        try:
            cond_ctx = _safe(ctx, "condition")
            if cond_ctx:
                cond = cond_ctx.getText()
        except Exception:
            pass
        then_stmts, else_stmts = [], []
        try:
            it = _safe(ctx, "ifThen")
            if it:
                for sc in (it.statement() if hasattr(it, "statement") else []):
                    s = self._build_stmt(sc)
                    if s:
                        then_stmts.append(s)
            ie = _safe(ctx, "ifElse")
            if ie:
                for sc in (ie.statement() if hasattr(ie, "statement") else []):
                    s = self._build_stmt(sc)
                    if s:
                        else_stmts.append(s)
        except Exception:
            pass
        return IfStmt(condition_text=cond, then_stmts=then_stmts,
                      else_stmts=else_stmts, loc=loc)

    def _build_perform(self, ctx) -> PerformStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            pps = _safe(ctx, "performProcedureStatement")
            if pps:
                pn = pps.procedureName(0) if hasattr(pps, "procedureName") else None
                return PerformStmt(target=_name(pn) if pn else None,
                                   is_inline=False, loc=loc)
            pis = _safe(ctx, "performInlineStatement")
            if pis:
                body = [self._build_stmt(sc)
                        for sc in (pis.statement() if hasattr(pis, "statement") else [])]
                return PerformStmt(target=None, is_inline=True,
                                   body_stmts=[s for s in body if s], loc=loc)
        except Exception:
            pass
        return GenericStmt(text=ctx.getText(), loc=loc)


# ── public API ────────────────────────────────────────────────────────────────

def build_ast(source_text: str, file_path: str) -> CobolProgram:
    if not _ANTLR_AVAILABLE:
        raise ImportError(
            "ANTLR4 generated parser files not found.\n"
            "Run: ./scripts/generate_parser.sh"
        )
    input_stream = InputStream(source_text)
    lexer        = Cobol85Lexer(input_stream)
    token_stream = CommonTokenStream(lexer)
    parser       = Cobol85Parser(token_stream)
    tree         = parser.startRule()
    visitor      = _CobolASTVisitor(file_path)
    return visitor.build(tree)