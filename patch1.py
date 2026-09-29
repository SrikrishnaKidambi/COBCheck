"""
apply_fix_idcomments.py

Run from the PROJECT ROOT:   python apply_fix_idcomments.py

Patches cobcheck/parser/ast_builder.py so the free-text comment entries after
AUTHOR. / DATE-WRITTEN. / INSTALLATION. / DATE-COMPILED. / SECURITY. / REMARKS.
(IDENTIFICATION DIVISION only) are removed before parsing. The grammar only
accepts that text when it is tagged '*>CE' by the upstream preprocessor, which
this pipeline does not run.

Safe to run twice (skips if already applied). Writes ast_builder.py.bak first.
If anything about the file looks unexpected it aborts WITHOUT changing it.
To undo: copy ast_builder.py.bak back over ast_builder.py.
"""
import ast
import re
import shutil
import sys
from pathlib import Path

TARGET = Path("cobcheck/parser/ast_builder.py")

MARKER = "def _blank_comment_entries("
FUNC_ANCHOR = "def normalize_fixed_format("
RETURN_OLD = 'return "\\n".join(out_lines)'
RETURN_NEW = 'return "\\n".join(_blank_comment_entries(out_lines))'

NEW_BLOCK = r'''_ID_DIV_RE = re.compile(r"^\s*(?:IDENTIFICATION|ID)\s+DIVISION\s*\.", re.IGNORECASE)
_OTHER_DIV_RE = re.compile(r"^\s*(?:ENVIRONMENT|DATA|PROCEDURE)\s+DIVISION\b", re.IGNORECASE)
_PROGRAM_ID_RE = re.compile(r"^\s*PROGRAM-ID\b", re.IGNORECASE)
_COMMENT_PARA_RE = re.compile(
    r"^(\s*(?:AUTHOR|INSTALLATION|DATE-WRITTEN|DATE-COMPILED|SECURITY|REMARKS))\s*\.",
    re.IGNORECASE,
)


def _blank_comment_entries(lines: list[str]) -> list[str]:
    """
    Inside IDENTIFICATION DIVISION only: keep 'AUTHOR.' style headers but drop
    their free-text comment entries (including continuation lines).
    Line count is preserved (dropped text becomes an empty line), so line
    numbers stay identical to the original file.
    """
    out: list[str] = []
    in_id = False
    in_comment = False
    for ln in lines:
        if _ID_DIV_RE.match(ln):
            in_id, in_comment = True, False
            out.append(ln)
            continue
        if in_id and _OTHER_DIV_RE.match(ln):
            in_id, in_comment = False, False
            out.append(ln)
            continue
        if not in_id:
            out.append(ln)
            continue
        m = _COMMENT_PARA_RE.match(ln)
        if m:
            out.append(m.group(1) + ".")
            in_comment = True
            continue
        if _PROGRAM_ID_RE.match(ln):
            in_comment = False
            out.append(ln)
            continue
        out.append("" if in_comment else ln)
    return out
'''


def die(msg: str) -> None:
    sys.exit(f"ABORTED - no changes made.\n{msg}")


def main() -> None:
    if not TARGET.exists():
        die(f"{TARGET} not found. Run this from the project root (D:\\RISHA\\COBCheck).")

    raw = TARGET.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    if MARKER in text:
        print("Already applied - nothing to do.")
        return

    if not re.search(r"^import re\b", text, re.MULTILINE):
        die("ast_builder.py has no top-level 'import re'. Send me the top of the file.")

    n = text.count(FUNC_ANCHOR)
    if n != 1:
        die(f"Expected exactly 1 'normalize_fixed_format' definition, found {n}. "
            "Has the earlier column-normalisation edit been applied?")

    start = text.index(FUNC_ANCHOR)
    ret_pos = text.find(RETURN_OLD, start)
    if ret_pos == -1:
        die("Could not find the final 'return \"\\n\".join(out_lines)' inside "
            "normalize_fixed_format. Send me that function as it currently is.")

    between = text[start + 1:ret_pos]
    if "\ndef " in between or "\nclass " in between:
        die("The return line found belongs to a different function. "
            "Send me normalize_fixed_format as it currently is.")

    # 1) change the return line (comes after 'start', so do it first)
    text = text[:ret_pos] + RETURN_NEW + text[ret_pos + len(RETURN_OLD):]
    # 2) insert the helper block just above normalize_fixed_format
    text = text[:start] + NEW_BLOCK + "\n\n" + text[start:]

    try:
        ast.parse(text)
    except SyntaxError as exc:
        die(f"Patched file would not be valid Python ({exc}). Original left untouched.")

    shutil.copy2(TARGET, TARGET.with_name(TARGET.name + ".bak"))
    out = text.replace("\n", "\r\n") if crlf else text
    TARGET.write_bytes(out.encode("utf-8"))
    print(f"Patched {TARGET}  (backup: {TARGET.name}.bak)")

    # ---- self-test -------------------------------------------------------
    sys.path.insert(0, str(Path.cwd()))
    try:
        from cobcheck.parser.ast_builder import normalize_fixed_format
    except Exception as exc:  # noqa: BLE001
        print(f"Patched OK, but self-test could not import the module: {exc}")
        return

    sample = (
        "000100* comment line\n"
        "       IDENTIFICATION DIVISION.\n"
        "       PROGRAM-ID.    TEST1.\n"
        "       AUTHOR.        AWS.\n"
        "       DATE-WRITTEN.  April 2022.\n"
        "                      continued text.\n"
        "       ENVIRONMENT DIVISION.\n"
    )
    result = normalize_fixed_format(sample)
    ok = (
        "AWS" not in result
        and "April" not in result
        and "continued" not in result
        and "AUTHOR." in result
        and "PROGRAM-ID" in result
        and "ENVIRONMENT DIVISION." in result
        and len(result.splitlines()) == len(sample.splitlines())
    )
    print("Self-test:", "PASS" if ok else "FAIL")
    if not ok:
        print(result)


if __name__ == "__main__":
    main()