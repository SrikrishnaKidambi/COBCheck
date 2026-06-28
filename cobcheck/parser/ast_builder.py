"""
cobcheck/parser/ast_builder.py
───────────────────────────────
ANTLR4 visitor that walks a Cobol85 parse tree and produces CobolProgram AST nodes.

Usage
-----
    from cobcheck.parser.ast_builder import build_ast

    program: CobolProgram = build_ast(source_text, file_path)

The function handles the ANTLR boilerplate internally.  If the generated
parser files aren't present (i.e., generate_parser.sh hasn't been run),
a clear ImportError is raised with instructions.

Note on the grammar stub
------------------------
The full grammars-v4 Cobol85.g4 has ~1 000 rules.  Our stub covers the
rules COBCheck needs.  When you replace the stub with the full grammar,
*this visitor doesn't change* — it only references the rule names listed
here, which are identical in the real grammar.
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

# ─── ANTLR4 import guard ──────────────────────────────────────────────────────

try:
    from antlr4 import CommonTokenStream, InputStream, ParseTreeVisitor
    from .generated.Cobol85Lexer  import Cobol85Lexer    # noqa: E402
    from .generated.Cobol85Parser import Cobol85Parser   # noqa: E402
    _ANTLR_AVAILABLE = True
except ImportError:
    _ANTLR_AVAILABLE = False

    class ParseTreeVisitor:          # type: ignore[no-redef]
        """Minimal shim so the class definition below doesn't crash."""
        def visit(self, tree): ...
        def visitChildren(self, node): ...


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _loc(ctx, program_id: str, file_path: str) -> SourceLocation:
    """Extract SourceLocation from an ANTLR4 context object."""
    token = ctx.start if hasattr(ctx, "start") else ctx
    return SourceLocation(
        program=program_id,
        file=file_path,
        line=token.line,
        column=token.column,
    )


def _text(ctx) -> str:
    """Safe getText() that handles None."""
    return ctx.getText() if ctx is not None else ""


def _name(ctx) -> str:
    """Upper-cased getText() — COBOL is case-insensitive."""
    return _text(ctx).upper()


# ─── Visitor ──────────────────────────────────────────────────────────────────

class _CobolASTVisitor(ParseTreeVisitor):
    """
    Walks the ANTLR4 parse tree for one COBOL program and builds a
    CobolProgram AST node.

    The visitor is intentionally *selective*: it only processes the rule
    contexts COBCheck needs.  Unknown contexts fall through to
    visitChildren() so the tree walk completes without errors.
    """

    def __init__(self, file_path: str):
        self._file_path = file_path
        self._program_id: str = os.path.splitext(os.path.basename(file_path))[0].upper()

        # Accumulators filled during the walk
        self._data_items: list[DataItem]   = []
        self._sections:   list[Section]    = []
        self._paragraphs: list[Paragraph]  = []
        self._copy_stmts: list[CopyStmt]   = []
        self._fd_map:     dict[str, str]   = {}
        self._current_section: DataSection = DataSection.UNKNOWN

    # ── public entry ─────────────────────────────────────────────────────────

    def build(self, tree) -> CobolProgram:
        self.visit(tree)
        return CobolProgram(
            file_path   = self._file_path,
            program_id  = self._program_id,
            data_items  = self._data_items,
            sections    = self._sections,
            paragraphs  = self._paragraphs,
            copy_stmts  = self._copy_stmts,
            fd_map      = self._fd_map,
        )

    # ── ANTLR4 visitor protocol ───────────────────────────────────────────────

    def visit(self, tree):
        if tree is None:
            return
        if hasattr(tree, "accept"):
            return tree.accept(self)
        return self.visitChildren(tree)

    def visitChildren(self, node):
        if node is None:
            return
        for i in range(node.getChildCount()):
            self.visit(node.getChild(i))

    # ── Identification Division ───────────────────────────────────────────────

    def visitProgramIdParagraph(self, ctx):
        self._program_id = _name(ctx.programName()).upper()

    # ── Data Division sections ────────────────────────────────────────────────

    def visitWorkingStorageSection(self, ctx):
        self._current_section = DataSection.WORKING_STORAGE
        self.visitChildren(ctx)

    def visitLinkageSection(self, ctx):
        self._current_section = DataSection.LINKAGE
        self.visitChildren(ctx)

    def visitFileSection(self, ctx):
        self._current_section = DataSection.FILE
        self.visitChildren(ctx)

    def visitLocalStorageSection(self, ctx):
        self._current_section = DataSection.LOCAL_STORAGE
        self.visitChildren(ctx)

    def visitFileDescriptionEntry(self, ctx):
        """Record FD file-name → record-name mapping."""
        file_name = _name(ctx.fileName())
        # First dataDescriptionEntry directly under this FD is the record layout
        dde_list = ctx.dataDescriptionEntry()
        if dde_list:
            record_name = _extract_data_name(dde_list[0])
            if record_name:
                self._fd_map[file_name] = record_name
        self.visitChildren(ctx)

    def visitDataDescriptionEntryFormat1(self, ctx):
        # Level number
        level_ctx = getattr(ctx, 'INTEGERLITERAL', None)
        level = int(level_ctx().getText()) if callable(level_ctx) else 1

        # Data name
        name = _extract_data_name(ctx) or "FILLER"

        # PIC clause — defensive
        pic = _extract_picture(ctx)

        # REDEFINES — defensive
        redefines = None
        redefines_ctx = getattr(ctx, 'redefinesClause', None)
        if callable(redefines_ctx):
            rc = redefines_ctx()
            if rc:
                redefines = _name(rc) if not isinstance(rc, list) else (
                    _name(rc[0]) if rc else None)

        item = DataItem(
            level     = level,
            name      = name,
            picture   = pic,
            redefines = redefines,
            section   = self._current_section,
            loc       = _loc(ctx, self._program_id, self._file_path),
        )
        self._data_items.append(item)
        self.visitChildren(ctx)

    # ── COPY statements ───────────────────────────────────────────────────────

    def visitCopyStatement(self, ctx):
        source = ctx.copySource()
        member = _name(source.literal() or source.cobolWord())
        # Strip quotes if literal
        member = member.strip("'\"")

        replacing = []
        rp = ctx.copyReplacingPhrase()
        if rp:
            for op in rp.copyReplacingOperand():
                operands = op.copyOperand()
                if len(operands) == 2:
                    replacing.append((_text(operands[0]), _text(operands[1])))

        stmt = CopyStmt(
            member    = member,
            replacing = replacing,
            loc       = _loc(ctx, self._program_id, self._file_path),
        )
        self._copy_stmts.append(stmt)

    # ── Procedure Division structure ──────────────────────────────────────────

    def visitProcedureSection(self, ctx):
        sec_name = _name(ctx.procedureSectionHeader().sectionName())
        sec = Section(
            name = sec_name,
            loc  = _loc(ctx, self._program_id, self._file_path),
        )
        # Visit paragraphs inside
        for para_ctx in ctx.paragraphs().paragraph():
            para = self._visit_paragraph(para_ctx)
            sec.paragraphs.append(para)
        self._sections.append(sec)

    def visitParagraphs(self, ctx):
        """Top-level paragraphs (outside a SECTION)."""
        for para_ctx in ctx.paragraph():
            self._paragraphs.append(self._visit_paragraph(para_ctx))
        for sent_ctx in ctx.sentence():
            # Sentences before any named paragraph
            stmts = self._visit_sentence(sent_ctx)
            if stmts:
                if not self._paragraphs:
                    self._paragraphs.append(
                        Paragraph(name="__IMPLICIT__",
                                  loc=_loc(sent_ctx, self._program_id, self._file_path))
                    )
                self._paragraphs[-1].statements.extend(stmts)

    def _visit_paragraph(self, ctx) -> Paragraph:
        name = _name(ctx.paragraphName())
        para = Paragraph(
            name = name,
            loc  = _loc(ctx, self._program_id, self._file_path),
        )
        for sent_ctx in ctx.sentence():
            para.statements.extend(self._visit_sentence(sent_ctx))
        return para

    def _visit_sentence(self, ctx) -> list:
        stmts = []
        for stmt_ctx in ctx.statement():
            s = self._visit_statement(stmt_ctx)
            if s is not None:
                stmts.append(s)
        return stmts

    # ── Statement dispatch ────────────────────────────────────────────────────

    def _visit_statement(self, ctx):
        # Safe attribute checker
        def has(attr):
            return hasattr(ctx, attr) and callable(getattr(ctx, attr)) and getattr(ctx, attr)() is not None

        if has('moveStatement'):
            return self._visit_move(ctx.moveStatement())
        if has('computeStatement'):
            return self._visit_compute(ctx.computeStatement())
        if has('callStatement'):
            return self._visit_call(ctx.callStatement())
        if has('writeStatement'):
            return self._visit_write(ctx.writeStatement())
        if has('readStatement'):
            return self._visit_read(ctx.readStatement())
        if has('displayStatement'):
            return self._visit_display(ctx.displayStatement())
        if has('ifStatement'):
            return self._visit_if(ctx.ifStatement())
        if has('performStatement'):
            return self._visit_perform(ctx.performStatement())
        # copyStatement lives outside statementContext in the real grammar
        # Everything else is generic
        return GenericStmt(
            text=ctx.getText(),
            loc=_loc(ctx, self._program_id, self._file_path),
        )

    def _visit_move(self, ctx) -> MoveStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            if hasattr(ctx, 'moveToStatement') and ctx.moveToStatement():
                mv = ctx.moveToStatement()
                source = _name(mv.moveToSendingArea()) if hasattr(mv, 'moveToSendingArea') else ''
                dests = [_name(d) for d in mv.identifier()] if hasattr(mv, 'identifier') else []
                return MoveStmt(source=source, destinations=dests, loc=loc)
            if hasattr(ctx, 'moveCorrespondingToStatement') and ctx.moveCorrespondingToStatement():
                mv = ctx.moveCorrespondingToStatement()
                source = _name(mv.qualifiedDataName()) if hasattr(mv, 'qualifiedDataName') else ''
                dests = [_name(d) for d in mv.identifier()] if hasattr(mv, 'identifier') else []
                return MoveStmt(source=source, destinations=dests, is_group_move=True, loc=loc)
        except Exception:
            pass
        return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_compute(self, ctx) -> ComputeStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            dest = _name(ctx.computeStore(0)) if hasattr(ctx, 'computeStore') else ''
            rhs = _collect_data_refs(ctx.arithmeticExpression()) if hasattr(ctx, 'arithmeticExpression') else []
            return ComputeStmt(destination=dest, operands=rhs, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_call(self, ctx) -> CallStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            target_is_literal = hasattr(ctx, 'literal') and ctx.literal() is not None
            target_ctx = ctx.literal() if target_is_literal else (ctx.identifier() if hasattr(ctx, 'identifier') else None)
            target = _name(target_ctx).strip("'\"") if target_ctx else 'UNKNOWN'
            using_params = []
            if hasattr(ctx, 'callUsingPhrase') and ctx.callUsingPhrase():
                cup = ctx.callUsingPhrase()
                if hasattr(cup, 'callUsingParameter'):
                    for param in cup.callUsingParameter():
                        for ref_attr in ('callByReferencePhrase', 'callByValuePhrase', 'callByContentPhrase'):
                            ref = getattr(param, ref_attr, lambda: None)()
                            if ref:
                                for child in _flatten(ref):
                                    n = _name(child)
                                    if n and n not in {'BY','REFERENCE','VALUE','CONTENT','ADDRESS','OF','LENGTH'}:
                                        using_params.append(n)
            return CallStmt(target=target, target_is_literal=target_is_literal,
                            using_params=using_params, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_write(self, ctx) -> WriteStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            record_name = _name(ctx.recordName()) if hasattr(ctx, 'recordName') else ''
            from_field = None
            if hasattr(ctx, 'writeFromPhrase') and ctx.writeFromPhrase():
                wfp = ctx.writeFromPhrase()
                from_field = _name(wfp.identifier() or wfp.literal()) if hasattr(wfp, 'identifier') else None
            return WriteStmt(record_name=record_name, from_field=from_field, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_read(self, ctx) -> ReadStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            file_name = _name(ctx.fileName()) if hasattr(ctx, 'fileName') else ''
            into_field = None
            if hasattr(ctx, 'readIntoPhrase') and ctx.readIntoPhrase():
                into_field = _name(ctx.readIntoPhrase().identifier())
            return ReadStmt(file_name=file_name, into_field=into_field, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_display(self, ctx) -> DisplayStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        try:
            operands = []
            if hasattr(ctx, 'displayOperand'):
                for o in ctx.displayOperand():
                    qdn = o.qualifiedDataName() if hasattr(o, 'qualifiedDataName') else None
                    lit = o.literal() if hasattr(o, 'literal') else None
                    operands.append(_name(qdn or lit))
            return DisplayStmt(operands=operands, loc=loc)
        except Exception:
            return GenericStmt(text=ctx.getText(), loc=loc)
    
    def _visit_if(self, ctx) -> IfStmt:
        loc  = _loc(ctx, self._program_id, self._file_path)
        cond = _text(ctx.condition())
        then_stmts = []
        else_stmts = []
        if ctx.ifThen():
            for sc in ctx.ifThen().statement():
                s = self._visit_statement(sc)
                if s:
                    then_stmts.append(s)
        if ctx.ifElse():
            for sc in ctx.ifElse().statement():
                s = self._visit_statement(sc)
                if s:
                    else_stmts.append(s)
        return IfStmt(condition_text=cond, then_stmts=then_stmts,
                      else_stmts=else_stmts, loc=loc)

    def _visit_perform(self, ctx) -> PerformStmt:
        loc = _loc(ctx, self._program_id, self._file_path)
        if ctx.performProcedureStatement():
            pps = ctx.performProcedureStatement()
            target = _name(pps.procedureName(0))
            return PerformStmt(target=target, is_inline=False, loc=loc)
        if ctx.performInlineStatement():
            pis = ctx.performInlineStatement()
            body = [self._visit_statement(sc) for sc in pis.statement()]
            return PerformStmt(target=None, is_inline=True,
                               body_stmts=[s for s in body if s], loc=loc)
        return GenericStmt(text=ctx.getText(), loc=loc)


# ─── Private helpers ──────────────────────────────────────────────────────────

def _extract_data_name(ctx) -> Optional[str]:
    if ctx is None:
        return None
    # Try dataName() method
    for attr in ('dataName', 'entryName'):
        dn = getattr(ctx, attr, None)
        if callable(dn):
            result = dn()
            if result is not None:
                if isinstance(result, list):
                    return _name(result[0]) if result else None
                return _name(result)
    # Try getText on first child that looks like an identifier
    try:
        for i in range(ctx.getChildCount()):
            child = ctx.getChild(i)
            text = child.getText().upper() if hasattr(child, 'getText') else ''
            if re.match(r'^[A-Z][A-Z0-9\-]*$', text):
                return text
    except Exception:
        pass
    return None


def _extract_picture(ctx) -> Optional[str]:
    if not hasattr(ctx, "dataDescriptionEntryClause"):
        return None
    clauses = ctx.dataDescriptionEntryClause()
    if clauses is None:
        return None
    for clause_ctx in clauses:
        if not hasattr(clause_ctx, "pictureClause"):
            continue
        pc = clause_ctx.pictureClause()
        if pc is not None:
            return _text(pc.pictureString()).upper()
    return None


def _collect_data_refs(ctx) -> list[str]:
    """
    Walk an arithmetic-expression subtree and collect all data-name references.
    Returns upper-cased names, excluding numeric literals.
    """
    refs: list[str] = []
    if ctx is None:
        return refs
    for i in range(ctx.getChildCount()):
        child = ctx.getChild(i)
        child_text = child.getText().upper() if hasattr(child, "getText") else ""
        if re.match(r"^[A-Z][A-Z0-9\-]*$", child_text):
            refs.append(child_text)
        refs.extend(_collect_data_refs(child))
    return refs


def _flatten(ctx) -> list:
    """Yield all terminal/leaf contexts under ctx."""
    results = []
    if ctx is None:
        return results
    if ctx.getChildCount() == 0:
        results.append(ctx)
    else:
        for i in range(ctx.getChildCount()):
            results.extend(_flatten(ctx.getChild(i)))
    return results


# ─── Public API ───────────────────────────────────────────────────────────────

def build_ast(source_text: str, file_path: str) -> CobolProgram:
    """
    Parse *source_text* (a COBOL source file) and return a CobolProgram AST.

    Requires the ANTLR4 generated files to be present.
    Run ``scripts/generate_parser.sh`` if you get an ImportError.
    """
    if not _ANTLR_AVAILABLE:
        raise ImportError(
            "ANTLR4 generated parser files not found.\n"
            "Run:  ./scripts/generate_parser.sh\n"
            "Then: pip install antlr4-python3-runtime==4.13.2"
        )

    input_stream  = InputStream(source_text)
    lexer         = Cobol85Lexer(input_stream)
    token_stream  = CommonTokenStream(lexer)
    parser        = Cobol85Parser(token_stream)
    tree          = parser.startRule()

    visitor = _CobolASTVisitor(file_path)
    return visitor.build(tree)