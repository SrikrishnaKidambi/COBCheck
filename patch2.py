#!/usr/bin/env python
"""
apply_grammar_prep.py
=====================
One-shot patcher: makes COBCheck use the grammar-prep stage (EXEC tagging,
CBL/PROCESS card removal, syntax-error counting, duplicate-file fix).

What it does
  1. writes  cobcheck/parser/grammar_prep.py            (embedded below)
  2. patches cobcheck/parser/ast_builder.py             (8 small edits)
  3. patches cobcheck/cli.py                            (3 small edits)

Safety
  * every edit is anchored on exact text and must match exactly ONCE;
    if any anchor is missing or ambiguous NOTHING is written
  * patched code is syntax-checked (ast.parse) before anything is written
  * originals are saved as <file>.pre_grammarprep  (never overwritten)
  * safe to re-run: edits that are already applied are skipped
  * Windows (CRLF) line endings are preserved

Usage (from the project root, e.g. D:\\RISHA\\COBCheck)
  python apply_grammar_prep.py --check     # dry run, changes nothing
  python apply_grammar_prep.py             # apply
  python apply_grammar_prep.py --revert    # undo, restoring the backups
  python apply_grammar_prep.py --root PATH # project root if not the cwd
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from pathlib import Path

BACKUP_SUFFIX = ".pre_grammarprep"


class PatchError(Exception):
    pass


# ══════════════════════════════════════════════════════════════════════════════
#  Embedded new module
# ══════════════════════════════════════════════════════════════════════════════

GRAMMAR_PREP_SRC = r'''"""
cobcheck/parser/grammar_prep.py
───────────────────────────────
Text-level rewrites that make IBM COBOL acceptable to the ProLeap-style
Cobol85.g4 grammar.  Runs on *normalized* (already column-stripped) text,
after COPY inlining, immediately before the ANTLR lexer.

Contract for every rule in RULES:
    * takes text, returns text
    * NEVER adds or removes a line  (source locations stay valid)

To handle a new construct later: write one function with that contract and
append it to RULES.

EXEC tagging convention (taken from Cobol85.g4):

    EXECCICSLINE   : '*>EXECCICS'   WS ~('\\n'|'\\r'|'}')* ('\\n'|'\\r'|'}')
    EXECSQLLINE    : '*>EXECSQL'    WS ...
    EXECSQLIMSLINE : '*>EXECSQLIMS' WS ...

so every physical line of an EXEC block gets its own tag prefix, and the
block is closed with '}' right after END-EXEC (so a following '.' is not
swallowed into the token).
"""

from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# EXEC <family> -> grammar tag.  DLI is IMS DL/I, so it shares the IMS rule.
_FAMILY_TAG: dict[str, str] = {
    "CICS":   "*>EXECCICS",
    "SQL":    "*>EXECSQL",
    "SQLIMS": "*>EXECSQLIMS",
    "DLI":    "*>EXECSQLIMS",
}

# Families the grammar has no rule for (ADATA, ...).  They are tagged with this
# opaque rule so the rest of the file still parses; a warning is logged for each.
# Set to None to leave them untouched (they will then show up as parse errors).
UNKNOWN_FAMILY_TAG: str | None = "*>EXECSQLIMS"

_EXEC_RE     = re.compile(r"(?<![A-Za-z0-9\-])EXEC(?![A-Za-z0-9\-])", re.IGNORECASE)
_END_EXEC_RE = re.compile(r"(?<![A-Za-z0-9\-])END-EXEC(?![A-Za-z0-9\-])", re.IGNORECASE)
_WORD_RE     = re.compile(r"\s*([A-Za-z][A-Za-z0-9\-]*)")
_IMS_RE      = re.compile(r"\s+IMS(?![A-Za-z0-9\-])", re.IGNORECASE)


def _mask_literals(line: str) -> str:
    """
    Same-length copy of *line* with string literals and a '*>' floating
    comment blanked out, so regexes only ever see code.  Literals never span
    physical lines here, so state resets per line.
    """
    out = list(line)
    n, i, quote = len(line), 0, None
    while i < n:
        c = line[i]
        if quote:
            out[i] = " "
            if c == quote:
                if i + 1 < n and line[i + 1] == quote:   # doubled quote = escape
                    out[i + 1] = " "
                    i += 1
                else:
                    quote = None
        elif c in ("'", '"'):
            quote = c
            out[i] = " "
        elif c == "*" and line.startswith("*>", i):
            for j in range(i, n):
                out[j] = " "
            break
        i += 1
    return "".join(out)


def _family_after(code: str, end: int, masked: list[str], idx: int) -> str:
    """Family word following EXEC (looks on the next lines if EXEC ends the line)."""
    m = _WORD_RE.match(code, end)
    if m:
        family = m.group(1).upper()
        if family == "SQL" and _IMS_RE.match(code, m.end()):
            return "SQLIMS"
        return family
    if code[end:].strip() == "":
        for nxt in masked[idx + 1: idx + 4]:
            m = _WORD_RE.match(nxt)
            if m:
                return m.group(1).upper()
            if nxt.strip():
                break
    return ""


def tag_exec_blocks(text: str) -> str:
    lines  = text.split("\n")
    masked = [_mask_literals(ln) for ln in lines]
    out: list[str] = []
    open_tag: str | None = None          # tag of the EXEC block we are inside

    for idx, line in enumerate(lines):
        code   = masked[idx]
        pieces: list[str] = []
        pos    = 0
        if open_tag is not None:         # continuation line of a multi-line block
            pieces.append(open_tag + " ")

        while True:
            if open_tag is None:
                m = _EXEC_RE.search(code, pos)
                if not m:
                    pieces.append(line[pos:])
                    break
                family = _family_after(code, m.end(), masked, idx)
                tag = _FAMILY_TAG.get(family)
                if tag is None:
                    logger.warning("line %d: EXEC %s has no grammar tag%s",
                                   idx + 1, family or "<?>",
                                   "" if UNKNOWN_FAMILY_TAG else " (left untouched)")
                    tag = UNKNOWN_FAMILY_TAG
                if tag is None:
                    pieces.append(line[pos:m.end()])
                    pos = m.end()
                    continue
                pieces.append(line[pos:m.start()])
                pieces.append(tag + " ")
                open_tag = tag
                pos = m.start()

            e = _END_EXEC_RE.search(code, pos)
            if e is None:                # block continues on the next line
                pieces.append(line[pos:].replace("}", " "))
                break
            pieces.append(line[pos:e.end()].replace("}", " ") + "}")
            pos = e.end()
            open_tag = None

        out.append("".join(pieces))

    if open_tag is not None:
        logger.warning("file ends inside an unterminated EXEC block")
    return "\n".join(out)


# Ordered list of rewrites.  Add new ones here.
RULES = [tag_exec_blocks]


def prepare_for_grammar(text: str) -> str:
    n_lines = text.count("\n")
    for rule in RULES:
        text = rule(text)
    assert text.count("\n") == n_lines, "grammar_prep rule changed the line count"
    return text
'''


# ══════════════════════════════════════════════════════════════════════════════
#  Code blobs inserted into ast_builder.py
# ══════════════════════════════════════════════════════════════════════════════

COLLECTOR_BLOCK = r'''
    from antlr4.error.ErrorListener import ErrorListener

    class _ErrorCollector(ErrorListener):
        """Collects syntax errors instead of printing them to stderr."""

        def __init__(self):
            super().__init__()
            self.errors = []

        def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
            self.errors.append((line, column, msg))
'''

NEW_NORMALIZE = r'''_CBL_CARD_RE = re.compile(
    r"^\s*(?:CBL|PROCESS)(?![A-Za-z0-9\-])\s+\S",
    re.IGNORECASE,
)
_LISTING_DIRECTIVE_RE = re.compile(
    r"^\s*(?:EJECT|SKIP[123]|TITLE\s+['\"].*)\s*$",
    re.IGNORECASE,
)


def normalize_fixed_format(source_text: str) -> str:
    """
    Convert IBM fixed-format COBOL source into free-format text the
    grammar can parse.

    Column layout (1-indexed, per the IBM COBOL fixed-format spec):
        1-6    sequence number   (discarded)
        7      indicator area    ('*' or '/' = comment; '-' = continuation)
        8-11   Area A
        12-72  Area B
        73-80  identification field (discarded)

    One output line is produced per input line (comment lines and compiler
    directives -- CBL/PROCESS cards before the first real line, EJECT, SKIP1-3,
    TITLE -- become an empty line rather than being deleted), so line numbers
    in the normalized text stay identical to line numbers in the original
    file; no downstream location remapping is required.

    Known limitation: continuation lines (indicator '-') are passed
    through as ordinary code rather than joined onto the previous line's
    literal.
    """
    out_lines: list[str] = []
    in_header = True   # CBL/PROCESS cards can only precede the first real line
    for raw_line in source_text.splitlines():
        indicator = raw_line[6:7] if len(raw_line) > 6 else " "
        if indicator in ("*", "/"):
            out_lines.append("")
            continue
        content = raw_line[7:72] if len(raw_line) > 7 else ""
        if in_header:
            if _CBL_CARD_RE.match(raw_line) or _CBL_CARD_RE.match(content):
                out_lines.append("")
                continue
            if content.strip():
                in_header = False
        if _LISTING_DIRECTIVE_RE.match(content):
            out_lines.append("")
            continue
        out_lines.append(content.rstrip())
    return "\n".join(_blank_comment_entries(out_lines))


'''

EXEC_HELPER = r'''_EXEC_TAG_RE = re.compile(r"\*>EXEC(?:CICS|SQLIMS|SQL)[ \t]?")


def _exec_raw_text(ctx) -> str:
    """Original EXEC ... END-EXEC text, with grammar tags and '}' removed."""
    return _EXEC_TAG_RE.sub("", _text(ctx)).replace("}", " ")


'''

NEW_BUILD_AST = r'''PARSE_DIAGNOSTICS: dict[str, dict] = {}   # file_path -> {"syntax_errors", "first_errors"}


def build_ast(
    source_text: str,
    file_path: str,
) -> CobolProgram:

    if not _ANTLR_AVAILABLE:

        raise ImportError(
            "ANTLR4 generated parser files not found.\n"
            "Run: ./scripts/generate_parser.sh"
        )

    source_text = prepare_for_grammar(source_text)

    collector = _ErrorCollector()

    lexer = Cobol85Lexer(InputStream(source_text))
    lexer.removeErrorListeners()
    lexer.addErrorListener(collector)

    parser = Cobol85Parser(CommonTokenStream(lexer))
    parser.removeErrorListeners()
    parser.addErrorListener(collector)

    tree = parser.startRule()

    program = _CobolASTVisitor(file_path).build(tree)

    PARSE_DIAGNOSTICS[file_path] = {
        "syntax_errors": len(collector.errors),
        "first_errors":  collector.errors[:5],
    }

    return program
'''

# ══════════════════════════════════════════════════════════════════════════════
#  Edit helpers.  Each edit: text -> (new_text, "applied" | "already")
# ══════════════════════════════════════════════════════════════════════════════


def _one(regex: str, text: str, what: str, flags: int = re.M) -> re.Match:
    found = list(re.finditer(regex, text, flags))
    if len(found) != 1:
        raise PatchError(f"{what}: expected exactly 1 match, found {len(found)}")
    return found[0]


# ── ast_builder.py ────────────────────────────────────────────────────────────

def ab_import(t: str):
    if "from .grammar_prep import prepare_for_grammar" in t:
        return t, "already"
    m = _one(r"^import re[ \t]*$", t, "ast_builder: 'import re' line")
    return t[:m.end()] + "\nfrom .grammar_prep import prepare_for_grammar" + t[m.end():], "applied"


def ab_collector(t: str):
    if "_ErrorCollector" in t:
        return t, "already"
    m = _one(r"^    from antlr4\.tree\.Tree import TerminalNode[ \t]*$", t,
             "ast_builder: 'from antlr4.tree.Tree import TerminalNode' line")
    return t[:m.end()] + "\n" + COLLECTOR_BLOCK.rstrip("\n") + t[m.end():], "applied"


def ab_normalize(t: str):
    if "_CBL_CARD_RE" in t:
        return t, "already"
    s = _one(r"^def normalize_fixed_format\(", t, "ast_builder: def normalize_fixed_format")
    e = _one(r"^def _loc\(", t, "ast_builder: def _loc")
    if e.start() <= s.start():
        raise PatchError("ast_builder: _loc appears before normalize_fixed_format")
    return t[:s.start()] + NEW_NORMALIZE + t[e.start():], "applied"


def ab_helper(t: str):
    if "def _exec_raw_text" in t:
        return t, "already"
    m = _one(r"^def _extract_exec_operation\(", t, "ast_builder: def _extract_exec_operation")
    return t[:m.start()] + EXEC_HELPER + t[m.start():], "applied"


def ab_builders(t: str):
    status = "already"
    for fn in ("_build_exec_sql", "_build_exec_cics", "_build_exec_sql_ims"):
        m = _one(r"^    def %s\(" % fn, t, f"ast_builder: def {fn}")
        nxt = re.search(r"\n    def |\n# ", t[m.end():])
        end = m.end() + nxt.start() if nxt else len(t)
        seg = t[m.start():end]
        if "_exec_raw_text(ctx)" in seg:
            continue
        if seg.count("raw_text = _text(ctx)") != 1:
            raise PatchError(f"ast_builder: {fn}: expected exactly one 'raw_text = _text(ctx)'")
        seg = seg.replace("raw_text = _text(ctx)", "raw_text = _exec_raw_text(ctx)")
        t = t[:m.start()] + seg + t[end:]
        status = "applied"
    return t, status


def ab_sqlims_regex(t: str):
    old = r'r"EXEC\s+SQL\s+IMS\s+([A-Z0-9\-]+)",'
    new = r'r"EXEC\s+(?:SQLIMS|SQL\s+IMS|DLI)\s+([A-Z0-9\-]+)",'
    if new in t:
        return t, "already"
    if t.count(old) != 1:
        raise PatchError(f"ast_builder: SQL_IMS regex: expected exactly 1 match, found {t.count(old)}")
    return t.replace(old, new), "applied"


def ab_excluded(t: str):
    if re.search(r'^[ \t]*"SQLIMS",[ \t]*$', t, re.M):
        return t, "already"
    m = _one(r'^([ \t]*)"IMS",[ \t]*$', t, 'ast_builder: excluded-word entry "IMS",')
    ind = m.group(1)
    return t[:m.end()] + f'\n{ind}"SQLIMS",\n{ind}"DLI",' + t[m.end():], "applied"


def ab_build_ast(t: str):
    if "PARSE_DIAGNOSTICS" in t:
        return t, "already"
    m = _one(r"^def build_ast\(", t, "ast_builder: def build_ast")
    if re.search(r"^(?:def|class) ", t[m.end():], re.M):
        raise PatchError("ast_builder: build_ast is not the last top-level definition; "
                         "refusing to replace to end of file")
    return t[:m.start()] + NEW_BUILD_AST, "applied"


AST_BUILDER_EDITS = [
    ("import grammar_prep",                     ab_import),
    ("syntax-error collector class",            ab_collector),
    ("normalize_fixed_format (CBL/PROCESS etc.)", ab_normalize),
    ("_exec_raw_text helper",                   ab_helper),
    ("EXEC builders use tag-free text",         ab_builders),
    ("SQL_IMS operation regex",                 ab_sqlims_regex),
    ("excluded identifiers (SQLIMS, DLI)",      ab_excluded),
    ("build_ast: prep + diagnostics",           ab_build_ast),
]


# ── cli.py ────────────────────────────────────────────────────────────────────

def cli_import(t: str):
    if "from .parser.ast_builder import PARSE_DIAGNOSTICS" in t:
        return t, "already"
    m = _one(r"^from \.parser\.copybook_resolver import .*$", t,
             "cli: 'from .parser.copybook_resolver import ...' line")
    return t[:m.end()] + "\nfrom .parser.ast_builder import PARSE_DIAGNOSTICS" + t[m.end():], "applied"


def cli_dedupe(t: str):
    if "os.path.normcase" in t:
        return t, "already"
    m = _one(r"^([ \t]*)if not cbl_files:[ \t]*$", t, "cli: 'if not cbl_files:'")
    ind = m.group(1)
    block = (
        f"{ind}# rglob is case-insensitive on Windows, so '*.cbl' and '*.CBL' hit the\n"
        f"{ind}# same files: de-duplicate so each program is parsed once.\n"
        f"{ind}cbl_files = sorted(\n"
        f"{ind}    {{os.path.normcase(str(p.resolve())): p for p in cbl_files}}.values()\n"
        f"{ind})\n\n"
    )
    return t[:m.start()] + block + t[m.start():], "applied"


def cli_diag(t: str):
    if "PARSE_DIAGNOSTICS.get(" in t:
        return t, "already"
    m = _one(r"^([ \t]*)programs\.append\(prog\)[ \t]*$", t, "cli: 'programs.append(prog)'")
    ind = m.group(1)
    lines = [
        'diag = PARSE_DIAGNOSTICS.get(str(cbl_path), {})',
        'n_err = diag.get("syntax_errors", 0)',
        'if not (prog.paragraphs or prog.sections):',
        '    logger.warning("%s: EMPTY program after parse (%d syntax errors)",',
        '                   cbl_path.name, n_err)',
        'elif n_err:',
        '    logger.warning("%s: %d syntax errors, first: %s",',
        '                   cbl_path.name, n_err, diag["first_errors"][:2])',
    ]
    block = "".join(f"{ind}{ln}\n" for ln in lines)
    return t[:m.start()] + block + t[m.start():], "applied"


CLI_EDITS = [
    ("import PARSE_DIAGNOSTICS",          cli_import),
    ("de-duplicate discovered files",     cli_dedupe),
    ("per-file syntax-error report",      cli_diag),
]


# ══════════════════════════════════════════════════════════════════════════════
#  File I/O (preserves encoding and CRLF/LF)
# ══════════════════════════════════════════════════════════════════════════════

def read_text(path: Path):
    raw = path.read_bytes()
    try:
        text, enc = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("latin-1"), "latin-1"
    crlf = "\r\n" in text
    return text.replace("\r\n", "\n"), enc, crlf


def write_text(path: Path, text: str, enc: str, crlf: bool):
    if crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode(enc))


def backup(path: Path):
    bak = path.with_name(path.name + BACKUP_SUFFIX)
    if not bak.exists():
        shutil.copy2(path, bak)
    return bak


def plan_file(path: Path, edits, label: str):
    text, enc, crlf = read_text(path)
    results = []
    for name, fn in edits:
        try:
            text, status = fn(text)
        except PatchError as exc:
            raise PatchError(f"{label}: edit '{name}' failed -> {exc}")
        results.append((name, status))
    try:
        ast.parse(text)
    except SyntaxError as exc:
        raise PatchError(f"{label}: patched code would not compile ({exc}); nothing written")
    return text, enc, crlf, results


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(description="Adopt grammar_prep in COBCheck.")
    ap.add_argument("--root", default=".", help="project root containing the cobcheck/ package")
    ap.add_argument("--check", action="store_true", help="dry run: report, change nothing")
    ap.add_argument("--revert", action="store_true", help="restore the .pre_grammarprep backups")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    ast_builder = root / "cobcheck" / "parser" / "ast_builder.py"
    cli = root / "cobcheck" / "cli.py"
    prep = root / "cobcheck" / "parser" / "grammar_prep.py"

    for p in (ast_builder, cli):
        if not p.is_file():
            print(f"ERROR: {p} not found. Run from the project root or pass --root.")
            return 1

    # ── revert ───────────────────────────────────────────────────────────────
    if args.revert:
        done = False
        for p in (ast_builder, cli):
            bak = p.with_name(p.name + BACKUP_SUFFIX)
            if bak.is_file():
                shutil.copy2(bak, p)
                print(f"restored {p.name} from {bak.name}")
                done = True
            else:
                print(f"no backup for {p.name}; left untouched")
        if prep.is_file() and prep.read_text(encoding="utf-8").replace("\r\n", "\n") == GRAMMAR_PREP_SRC:
            prep.unlink()
            print("removed grammar_prep.py")
        return 0 if done else 1

    # ── plan everything in memory first ─────────────────────────────────────
    try:
        ab_text, ab_enc, ab_crlf, ab_res = plan_file(ast_builder, AST_BUILDER_EDITS, "ast_builder.py")
        cl_text, cl_enc, cl_crlf, cl_res = plan_file(cli, CLI_EDITS, "cli.py")
    except PatchError as exc:
        print(f"ABORTED, nothing was changed.\n  {exc}")
        print("Send me that file (or the anchor lines around the failing edit) and I will adjust the patch.")
        return 1

    prep_state = "missing"
    if prep.is_file():
        cur = prep.read_text(encoding="utf-8").replace("\r\n", "\n")
        prep_state = "identical" if cur == GRAMMAR_PREP_SRC else "different"

    print("Plan:")
    print(f"  grammar_prep.py : {'create' if prep_state == 'missing' else 'already identical' if prep_state == 'identical' else 'EXISTS, differs -> back up and overwrite'}")
    for label, res in (("ast_builder.py", ab_res), ("cli.py", cl_res)):
        for name, status in res:
            print(f"  {label:<15} {status:<8} {name}")

    if args.check:
        print("\n--check: nothing written.")
        return 0

    # ── write ────────────────────────────────────────────────────────────────
    if prep_state == "different":
        backup(prep)
    if prep_state != "identical":
        prep.write_text(GRAMMAR_PREP_SRC, encoding="utf-8", newline="\n")
    if any(s == "applied" for _, s in ab_res):
        backup(ast_builder)
        write_text(ast_builder, ab_text, ab_enc, ab_crlf)
    if any(s == "applied" for _, s in cl_res):
        backup(cli)
        write_text(cli, cl_text, cl_enc, cl_crlf)

    print("\nDone. Originals kept as *" + BACKUP_SUFFIX + "  (undo with --revert).")
    print("Next: rerun the GenApp baseline and paste:")
    print('  Select-String genapp_run2.log -Pattern "Found \\d+ COBOL|syntax errors|EMPTY program|Parsed \\d+"')
    return 0


if __name__ == "__main__":
    sys.exit(main())    

    """
    #!/usr/bin/env python
"""
apply_grammar_prep.py
=====================
One-shot patcher: makes COBCheck use the grammar-prep stage (EXEC tagging,
CBL/PROCESS card removal, syntax-error counting, duplicate-file fix).

What it does
  1. writes  cobcheck/parser/grammar_prep.py            (embedded below)
  2. patches cobcheck/parser/ast_builder.py             (8 small edits)
  3. patches cobcheck/cli.py                            (3 small edits)

Safety
  * every edit is anchored on exact text and must match exactly ONCE;
    if any anchor is missing or ambiguous NOTHING is written
  * patched code is syntax-checked (ast.parse) before anything is written
  * originals are saved as <file>.pre_grammarprep  (never overwritten)
  * safe to re-run: edits that are already applied are skipped
  * Windows (CRLF) line endings are preserved

Usage (from the project root, e.g. D:\\RISHA\\COBCheck)
  python apply_grammar_prep.py --check     # dry run, changes nothing
  python apply_grammar_prep.py             # apply
  python apply_grammar_prep.py --revert    # undo, restoring the backups
  python apply_grammar_prep.py --root PATH # project root if not the cwd
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from pathlib import Path

BACKUP_SUFFIX = ".pre_grammarprep"


class PatchError(Exception):
    pass


# ══════════════════════════════════════════════════════════════════════════════
#  Embedded new module
# ══════════════════════════════════════════════════════════════════════════════

GRAMMAR_PREP_SRC = r'''"""
cobcheck/parser/grammar_prep.py
───────────────────────────────
Text-level rewrites that make IBM COBOL acceptable to the ProLeap-style
Cobol85.g4 grammar.  Runs on *normalized* (already column-stripped) text,
after COPY inlining, immediately before the ANTLR lexer.

Contract for every rule in RULES:
    * takes text, returns text
    * NEVER adds or removes a line  (source locations stay valid)

To handle a new construct later: write one function with that contract and
append it to RULES.

EXEC tagging convention (taken from Cobol85.g4):

    EXECCICSLINE   : '*>EXECCICS'   WS ~('\\n'|'\\r'|'}')* ('\\n'|'\\r'|'}')
    EXECSQLLINE    : '*>EXECSQL'    WS ...
    EXECSQLIMSLINE : '*>EXECSQLIMS' WS ...

so every physical line of an EXEC block gets its own tag prefix, and the
block is closed with '}' right after END-EXEC (so a following '.' is not
swallowed into the token).
"""

from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# EXEC <family> -> grammar tag.  DLI is IMS DL/I, so it shares the IMS rule.
_FAMILY_TAG: dict[str, str] = {
    "CICS":   "*>EXECCICS",
    "SQL":    "*>EXECSQL",
    "SQLIMS": "*>EXECSQLIMS",
    "DLI":    "*>EXECSQLIMS",
}

# Families the grammar has no rule for (ADATA, ...).  They are tagged with this
# opaque rule so the rest of the file still parses; a warning is logged for each.
# Set to None to leave them untouched (they will then show up as parse errors).
UNKNOWN_FAMILY_TAG: str | None = "*>EXECSQLIMS"

_EXEC_RE     = re.compile(r"(?<![A-Za-z0-9\-])EXEC(?![A-Za-z0-9\-])", re.IGNORECASE)
_END_EXEC_RE = re.compile(r"(?<![A-Za-z0-9\-])END-EXEC(?![A-Za-z0-9\-])", re.IGNORECASE)
_WORD_RE     = re.compile(r"\s*([A-Za-z][A-Za-z0-9\-]*)")
_IMS_RE      = re.compile(r"\s+IMS(?![A-Za-z0-9\-])", re.IGNORECASE)


def _mask_literals(line: str) -> str:
    """
    Same-length copy of *line* with string literals and a '*>' floating
    comment blanked out, so regexes only ever see code.  Literals never span
    physical lines here, so state resets per line.
    """
    out = list(line)
    n, i, quote = len(line), 0, None
    while i < n:
        c = line[i]
        if quote:
            out[i] = " "
            if c == quote:
                if i + 1 < n and line[i + 1] == quote:   # doubled quote = escape
                    out[i + 1] = " "
                    i += 1
                else:
                    quote = None
        elif c in ("'", '"'):
            quote = c
            out[i] = " "
        elif c == "*" and line.startswith("*>", i):
            for j in range(i, n):
                out[j] = " "
            break
        i += 1
    return "".join(out)


def _family_after(code: str, end: int, masked: list[str], idx: int) -> str:
    """Family word following EXEC (looks on the next lines if EXEC ends the line)."""
    m = _WORD_RE.match(code, end)
    if m:
        family = m.group(1).upper()
        if family == "SQL" and _IMS_RE.match(code, m.end()):
            return "SQLIMS"
        return family
    if code[end:].strip() == "":
        for nxt in masked[idx + 1: idx + 4]:
            m = _WORD_RE.match(nxt)
            if m:
                return m.group(1).upper()
            if nxt.strip():
                break
    return ""


def tag_exec_blocks(text: str) -> str:
    lines  = text.split("\n")
    masked = [_mask_literals(ln) for ln in lines]
    out: list[str] = []
    open_tag: str | None = None          # tag of the EXEC block we are inside

    for idx, line in enumerate(lines):
        code   = masked[idx]
        pieces: list[str] = []
        pos    = 0
        if open_tag is not None:         # continuation line of a multi-line block
            pieces.append(open_tag + " ")

        while True:
            if open_tag is None:
                m = _EXEC_RE.search(code, pos)
                if not m:
                    pieces.append(line[pos:])
                    break
                family = _family_after(code, m.end(), masked, idx)
                tag = _FAMILY_TAG.get(family)
                if tag is None:
                    logger.warning("line %d: EXEC %s has no grammar tag%s",
                                   idx + 1, family or "<?>",
                                   "" if UNKNOWN_FAMILY_TAG else " (left untouched)")
                    tag = UNKNOWN_FAMILY_TAG
                if tag is None:
                    pieces.append(line[pos:m.end()])
                    pos = m.end()
                    continue
                pieces.append(line[pos:m.start()])
                pieces.append(tag + " ")
                open_tag = tag
                pos = m.start()

            e = _END_EXEC_RE.search(code, pos)
            if e is None:                # block continues on the next line
                pieces.append(line[pos:].replace("}", " "))
                break
            pieces.append(line[pos:e.end()].replace("}", " ") + "}")
            pos = e.end()
            open_tag = None

        out.append("".join(pieces))

    if open_tag is not None:
        logger.warning("file ends inside an unterminated EXEC block")
    return "\n".join(out)


_SEP_COMMA_RE = re.compile(r",(?=\s|$)")


def blank_separator_commas(text: str) -> str:
    """
    In COBOL a comma followed by a space (or end of line) is a separator that
    means the same as a space, e.g.  STRING TSQPRE,  'X05V' DELIMITED BY ...
    The grammar has no rule for it, so blank those commas.  Commas inside
    string literals, '*>' comments and tagged EXEC lines are left alone, and
    so are commas with no space after them (numeric literals like 1,5 or
    PICTURE strings like 9,999).
    """
    out: list[str] = []
    for line in text.split("\n"):
        if "," not in line:
            out.append(line)
            continue
        code  = _mask_literals(line)
        chars = list(line)
        for m in _SEP_COMMA_RE.finditer(code):
            chars[m.start()] = " "
        out.append("".join(chars))
    return "\n".join(out)


# Ordered list of rewrites.  Add new ones here.
# (blank_separator_commas must run after tag_exec_blocks: tagged EXEC lines start
#  with '*>' and are therefore masked and left alone.)
RULES = [tag_exec_blocks, blank_separator_commas]


def prepare_for_grammar(text: str) -> str:
    n_lines = text.count("\n")
    for rule in RULES:
        text = rule(text)
    assert text.count("\n") == n_lines, "grammar_prep rule changed the line count"
    return text
'''


# ══════════════════════════════════════════════════════════════════════════════
#  Code blobs inserted into ast_builder.py
# ══════════════════════════════════════════════════════════════════════════════

COLLECTOR_BLOCK = r'''
    from antlr4.error.ErrorListener import ErrorListener

    class _ErrorCollector(ErrorListener):
        """Collects syntax errors instead of printing them to stderr."""

        def __init__(self):
            super().__init__()
            self.errors = []

        def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
            self.errors.append((line, column, msg))
'''

NEW_NORMALIZE = r'''_CBL_CARD_RE = re.compile(
    r"^\s*(?:CBL|PROCESS)(?![A-Za-z0-9\-])\s+\S",
    re.IGNORECASE,
)
_LISTING_DIRECTIVE_RE = re.compile(
    r"^\s*(?:EJECT|SKIP[123]|TITLE\s+['\"].*)\s*$",
    re.IGNORECASE,
)


def normalize_fixed_format(source_text: str) -> str:
    """
    Convert IBM fixed-format COBOL source into free-format text the
    grammar can parse.

    Column layout (1-indexed, per the IBM COBOL fixed-format spec):
        1-6    sequence number   (discarded)
        7      indicator area    ('*' or '/' = comment; '-' = continuation)
        8-11   Area A
        12-72  Area B
        73-80  identification field (discarded)

    One output line is produced per input line (comment lines and compiler
    directives -- CBL/PROCESS cards before the first real line, EJECT, SKIP1-3,
    TITLE -- become an empty line rather than being deleted), so line numbers
    in the normalized text stay identical to line numbers in the original
    file; no downstream location remapping is required.

    Known limitation: continuation lines (indicator '-') are passed
    through as ordinary code rather than joined onto the previous line's
    literal.
    """
    out_lines: list[str] = []
    in_header = True   # CBL/PROCESS cards can only precede the first real line
    for raw_line in source_text.splitlines():
        indicator = raw_line[6:7] if len(raw_line) > 6 else " "
        if indicator in ("*", "/"):
            out_lines.append("")
            continue
        content = raw_line[7:72] if len(raw_line) > 7 else ""
        if in_header:
            if _CBL_CARD_RE.match(raw_line) or _CBL_CARD_RE.match(content):
                out_lines.append("")
                continue
            if content.strip():
                in_header = False
        if _LISTING_DIRECTIVE_RE.match(content):
            out_lines.append("")
            continue
        out_lines.append(content.rstrip())
    return "\n".join(_blank_comment_entries(out_lines))


'''

EXEC_HELPER = r'''_EXEC_TAG_RE = re.compile(r"\*>EXEC(?:CICS|SQLIMS|SQL)[ \t]?")


def _exec_raw_text(ctx) -> str:
    """Original EXEC ... END-EXEC text, with grammar tags and '}' removed."""
    return _EXEC_TAG_RE.sub("", _text(ctx)).replace("}", " ")


'''

NEW_BUILD_AST = r'''PARSE_DIAGNOSTICS: dict[str, dict] = {}   # file_path -> {"syntax_errors", "first_errors"}


def build_ast(
    source_text: str,
    file_path: str,
) -> CobolProgram:

    if not _ANTLR_AVAILABLE:

        raise ImportError(
            "ANTLR4 generated parser files not found.\n"
            "Run: ./scripts/generate_parser.sh"
        )

    source_text = prepare_for_grammar(source_text)

    collector = _ErrorCollector()

    lexer = Cobol85Lexer(InputStream(source_text))
    lexer.removeErrorListeners()
    lexer.addErrorListener(collector)

    parser = Cobol85Parser(CommonTokenStream(lexer))
    parser.removeErrorListeners()
    parser.addErrorListener(collector)

    tree = parser.startRule()

    program = _CobolASTVisitor(file_path).build(tree)

    PARSE_DIAGNOSTICS[file_path] = {
        "syntax_errors": len(collector.errors),
        "first_errors":  collector.errors[:5],
    }

    return program
'''

# ══════════════════════════════════════════════════════════════════════════════
#  Edit helpers.  Each edit: text -> (new_text, "applied" | "already")
# ══════════════════════════════════════════════════════════════════════════════


def _one(regex: str, text: str, what: str, flags: int = re.M) -> re.Match:
    found = list(re.finditer(regex, text, flags))
    if len(found) != 1:
        raise PatchError(f"{what}: expected exactly 1 match, found {len(found)}")
    return found[0]


# ── ast_builder.py ────────────────────────────────────────────────────────────

def ab_import(t: str):
    if "from .grammar_prep import prepare_for_grammar" in t:
        return t, "already"
    m = _one(r"^import re[ \t]*$", t, "ast_builder: 'import re' line")
    return t[:m.end()] + "\nfrom .grammar_prep import prepare_for_grammar" + t[m.end():], "applied"


def ab_collector(t: str):
    if "_ErrorCollector" in t:
        return t, "already"
    m = _one(r"^    from antlr4\.tree\.Tree import TerminalNode[ \t]*$", t,
             "ast_builder: 'from antlr4.tree.Tree import TerminalNode' line")
    return t[:m.end()] + "\n" + COLLECTOR_BLOCK.rstrip("\n") + t[m.end():], "applied"


def ab_normalize(t: str):
    if "_CBL_CARD_RE" in t:
        return t, "already"
    s = _one(r"^def normalize_fixed_format\(", t, "ast_builder: def normalize_fixed_format")
    e = _one(r"^def _loc\(", t, "ast_builder: def _loc")
    if e.start() <= s.start():
        raise PatchError("ast_builder: _loc appears before normalize_fixed_format")
    return t[:s.start()] + NEW_NORMALIZE + t[e.start():], "applied"


def ab_helper(t: str):
    if "def _exec_raw_text" in t:
        return t, "already"
    m = _one(r"^def _extract_exec_operation\(", t, "ast_builder: def _extract_exec_operation")
    return t[:m.start()] + EXEC_HELPER + t[m.start():], "applied"


def ab_builders(t: str):
    status = "already"
    for fn in ("_build_exec_sql", "_build_exec_cics", "_build_exec_sql_ims"):
        m = _one(r"^    def %s\(" % fn, t, f"ast_builder: def {fn}")
        nxt = re.search(r"\n    def |\n# ", t[m.end():])
        end = m.end() + nxt.start() if nxt else len(t)
        seg = t[m.start():end]
        if "_exec_raw_text(ctx)" in seg:
            continue
        if seg.count("raw_text = _text(ctx)") != 1:
            raise PatchError(f"ast_builder: {fn}: expected exactly one 'raw_text = _text(ctx)'")
        seg = seg.replace("raw_text = _text(ctx)", "raw_text = _exec_raw_text(ctx)")
        t = t[:m.start()] + seg + t[end:]
        status = "applied"
    return t, status


def ab_sqlims_regex(t: str):
    old = r'r"EXEC\s+SQL\s+IMS\s+([A-Z0-9\-]+)",'
    new = r'r"EXEC\s+(?:SQLIMS|SQL\s+IMS|DLI)\s+([A-Z0-9\-]+)",'
    if new in t:
        return t, "already"
    if t.count(old) != 1:
        raise PatchError(f"ast_builder: SQL_IMS regex: expected exactly 1 match, found {t.count(old)}")
    return t.replace(old, new), "applied"


def ab_excluded(t: str):
    if re.search(r'^[ \t]*"SQLIMS",[ \t]*$', t, re.M):
        return t, "already"
    m = _one(r'^([ \t]*)"IMS",[ \t]*$', t, 'ast_builder: excluded-word entry "IMS",')
    ind = m.group(1)
    return t[:m.end()] + f'\n{ind}"SQLIMS",\n{ind}"DLI",' + t[m.end():], "applied"


def ab_build_ast(t: str):
    if "PARSE_DIAGNOSTICS" in t:
        return t, "already"
    m = _one(r"^def build_ast\(", t, "ast_builder: def build_ast")
    if re.search(r"^(?:def|class) ", t[m.end():], re.M):
        raise PatchError("ast_builder: build_ast is not the last top-level definition; "
                         "refusing to replace to end of file")
    return t[:m.start()] + NEW_BUILD_AST, "applied"


AST_BUILDER_EDITS = [
    ("import grammar_prep",                     ab_import),
    ("syntax-error collector class",            ab_collector),
    ("normalize_fixed_format (CBL/PROCESS etc.)", ab_normalize),
    ("_exec_raw_text helper",                   ab_helper),
    ("EXEC builders use tag-free text",         ab_builders),
    ("SQL_IMS operation regex",                 ab_sqlims_regex),
    ("excluded identifiers (SQLIMS, DLI)",      ab_excluded),
    ("build_ast: prep + diagnostics",           ab_build_ast),
]


# ── cli.py ────────────────────────────────────────────────────────────────────

def cli_import(t: str):
    if "from .parser.ast_builder import PARSE_DIAGNOSTICS" in t:
        return t, "already"
    m = _one(r"^from \.parser\.copybook_resolver import .*$", t,
             "cli: 'from .parser.copybook_resolver import ...' line")
    return t[:m.end()] + "\nfrom .parser.ast_builder import PARSE_DIAGNOSTICS" + t[m.end():], "applied"


def cli_dedupe(t: str):
    if "os.path.normcase" in t:
        return t, "already"
    m = _one(r"^([ \t]*)if not cbl_files:[ \t]*$", t, "cli: 'if not cbl_files:'")
    ind = m.group(1)
    block = (
        f"{ind}# rglob is case-insensitive on Windows, so '*.cbl' and '*.CBL' hit the\n"
        f"{ind}# same files: de-duplicate so each program is parsed once.\n"
        f"{ind}cbl_files = sorted(\n"
        f"{ind}    {{os.path.normcase(str(p.resolve())): p for p in cbl_files}}.values()\n"
        f"{ind})\n\n"
    )
    return t[:m.start()] + block + t[m.start():], "applied"


def cli_diag(t: str):
    if "PARSE_DIAGNOSTICS.get(" in t:
        return t, "already"
    m = _one(r"^([ \t]*)programs\.append\(prog\)[ \t]*$", t, "cli: 'programs.append(prog)'")
    ind = m.group(1)
    lines = [
        'diag = PARSE_DIAGNOSTICS.get(str(cbl_path), {})',
        'n_err = diag.get("syntax_errors", 0)',
        'if not (prog.paragraphs or prog.sections):',
        '    logger.warning("%s: EMPTY program after parse (%d syntax errors)",',
        '                   cbl_path.name, n_err)',
        'elif n_err:',
        '    logger.warning("%s: %d syntax errors, first: %s",',
        '                   cbl_path.name, n_err, diag["first_errors"][:2])',
    ]
    block = "".join(f"{ind}{ln}\n" for ln in lines)
    return t[:m.start()] + block + t[m.start():], "applied"


CLI_EDITS = [
    ("import PARSE_DIAGNOSTICS",          cli_import),
    ("de-duplicate discovered files",     cli_dedupe),
    ("per-file syntax-error report",      cli_diag),
]


# ══════════════════════════════════════════════════════════════════════════════
#  File I/O (preserves encoding and CRLF/LF)
# ══════════════════════════════════════════════════════════════════════════════

def read_text(path: Path):
    raw = path.read_bytes()
    try:
        text, enc = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("latin-1"), "latin-1"
    crlf = "\r\n" in text
    return text.replace("\r\n", "\n"), enc, crlf


def write_text(path: Path, text: str, enc: str, crlf: bool):
    if crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode(enc))


def backup(path: Path):
    bak = path.with_name(path.name + BACKUP_SUFFIX)
    if not bak.exists():
        shutil.copy2(path, bak)
    return bak


def plan_file(path: Path, edits, label: str):
    text, enc, crlf = read_text(path)
    results = []
    for name, fn in edits:
        try:
            text, status = fn(text)
        except PatchError as exc:
            raise PatchError(f"{label}: edit '{name}' failed -> {exc}")
        results.append((name, status))
    try:
        ast.parse(text)
    except SyntaxError as exc:
        raise PatchError(f"{label}: patched code would not compile ({exc}); nothing written")
    return text, enc, crlf, results


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(description="Adopt grammar_prep in COBCheck.")
    ap.add_argument("--root", default=".", help="project root containing the cobcheck/ package")
    ap.add_argument("--check", action="store_true", help="dry run: report, change nothing")
    ap.add_argument("--revert", action="store_true", help="restore the .pre_grammarprep backups")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    ast_builder = root / "cobcheck" / "parser" / "ast_builder.py"
    cli = root / "cobcheck" / "cli.py"
    prep = root / "cobcheck" / "parser" / "grammar_prep.py"

    for p in (ast_builder, cli):
        if not p.is_file():
            print(f"ERROR: {p} not found. Run from the project root or pass --root.")
            return 1

    # ── revert ───────────────────────────────────────────────────────────────
    if args.revert:
        done = False
        for p in (ast_builder, cli):
            bak = p.with_name(p.name + BACKUP_SUFFIX)
            if bak.is_file():
                shutil.copy2(bak, p)
                print(f"restored {p.name} from {bak.name}")
                done = True
            else:
                print(f"no backup for {p.name}; left untouched")
        if prep.is_file() and prep.read_text(encoding="utf-8").replace("\r\n", "\n") == GRAMMAR_PREP_SRC:
            prep.unlink()
            print("removed grammar_prep.py")
        return 0 if done else 1

    # ── plan everything in memory first ─────────────────────────────────────
    try:
        ab_text, ab_enc, ab_crlf, ab_res = plan_file(ast_builder, AST_BUILDER_EDITS, "ast_builder.py")
        cl_text, cl_enc, cl_crlf, cl_res = plan_file(cli, CLI_EDITS, "cli.py")
    except PatchError as exc:
        print(f"ABORTED, nothing was changed.\n  {exc}")
        print("Send me that file (or the anchor lines around the failing edit) and I will adjust the patch.")
        return 1

    prep_state = "missing"
    if prep.is_file():
        cur = prep.read_text(encoding="utf-8").replace("\r\n", "\n")
        prep_state = "identical" if cur == GRAMMAR_PREP_SRC else "different"

    print("Plan:")
    print(f"  grammar_prep.py : {'create' if prep_state == 'missing' else 'already identical' if prep_state == 'identical' else 'EXISTS, differs -> back up and overwrite'}")
    for label, res in (("ast_builder.py", ab_res), ("cli.py", cl_res)):
        for name, status in res:
            print(f"  {label:<15} {status:<8} {name}")

    if args.check:
        print("\n--check: nothing written.")
        return 0

    # ── write ────────────────────────────────────────────────────────────────
    if prep_state == "different":
        backup(prep)
    if prep_state != "identical":
        prep.write_text(GRAMMAR_PREP_SRC, encoding="utf-8", newline="\n")
    if any(s == "applied" for _, s in ab_res):
        backup(ast_builder)
        write_text(ast_builder, ab_text, ab_enc, ab_crlf)
    if any(s == "applied" for _, s in cl_res):
        backup(cli)
        write_text(cli, cl_text, cl_enc, cl_crlf)

    print("\nDone. Originals kept as *" + BACKUP_SUFFIX + "  (undo with --revert).")
    print("Next: rerun the GenApp baseline and paste:")
    print('  Select-String genapp_run2.log -Pattern "Found \\d+ COBOL|syntax errors|EMPTY program|Parsed \\d+"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
    """