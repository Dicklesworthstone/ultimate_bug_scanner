"""ubs_core.analyzers.spec_typeof — typeof checks with wrong string literals
(bead A4-js final wave).

Verbatim port of the legacy ubs-js.sh "typeof checks with wrong string
literals" heredoc (ubs-js.sh 4211-4303): every ``typeof X <op> Y`` /
``Y <op> typeof X`` comparison (``<op>`` one of ``=== == !== !=``) whose Y
operand is a quoted string literal outside the eight valid typeof results
(``undefined string number boolean function object symbol bigint``) is
reported as critical ("Invalid typeof comparison"). The legacy flow matched
the comparisons with eight ast-grep patterns and consumed the concatenated
JSON stream in python (dedup key ``(file, line, Y literal)``); here the same
detection runs over ``RunContext.files`` with an equivalent code-aware scan:
``ubs_core.lexer.strip_comments_and_strings`` blanks comments (ast-grep only
matches code nodes), then a JS-specific pass blanks template-literal text
and regex literals while blanking string-literal *contents* — string
delimiters stay visible so a comparison operand can be recognized, and the
literal's text is taken from the original source at the same offsets.
``${...}`` interpolation code stays visible. ``unquote`` and the
valid-literal set are the heredoc code byte-for-byte.

The heredoc's project-level counter becomes one finding record per unique
(line, literal) triple, severity ``critical`` per the legacy
``print_finding``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.type-coercion.invalid-typeof"
CATEGORY_ID = "js.type-coercion"
TITLE = "Invalid typeof comparison"
REMEDIATION = "Valid: undefined|string|number|boolean|function|object|symbol|bigint"
MESSAGE = f"{TITLE} — {REMEDIATION}"
SEVERITY = "critical"

# A `/` is a regex-literal start when, skipping whitespace backwards, the
# previous token is a keyword or the previous char is not an identifier /
# number / closing bracket.
_REGEX_KEYWORDS = frozenset((
    'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
    'throw', 'case', 'do', 'else', 'yield', 'await',
))


def _regex_start_context(text: str, idx: int) -> bool:
    j = idx - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j < 0:
        return True
    ch = text[j]
    if ch.isalnum() or ch in '_$':
        k = j
        while k >= 0 and (text[k].isalnum() or text[k] in '_$'):
            k -= 1
        return text[k + 1:j + 1] in _REGEX_KEYWORDS
    return not (ch in ')]')


def _mask_strings_templates_regex(masked: str) -> str:
    """JS-specific pass over the comment-stripped text: blank template-literal
    *text* (keeping ``${...}`` interpolation code), blank string-literal
    *contents* while keeping their delimiters (they are the comparison
    operands this detector classifies), and blank regex literals. Newlines
    preserved; offsets identical."""
    out = list(masked)
    n = len(masked)

    def blank(a: int, b: int) -> None:
        for j in range(a, min(b, n)):
            if out[j] != '\n':
                out[j] = ' '

    i = 0
    while i < n:
        c = masked[i]
        if c == '`':
            j = i + 1
            while j < n:
                ch = masked[j]
                if ch == '\\':
                    j += 2
                    continue
                if ch == '`':
                    j += 1
                    break
                if ch == '$' and j + 1 < n and masked[j + 1] == '{':
                    depth = 1
                    k = j + 2
                    while k < n and depth:
                        if masked[k] == '{':
                            depth += 1
                        elif masked[k] == '}':
                            depth -= 1
                        k += 1
                    blank(j, j + 2)
                    j = k
                    continue
                blank(j, j + 1)
                j += 1
            i = j
            continue
        if c in '\'"':
            j = i + 1
            while j < n:
                ch = masked[j]
                if ch == '\\':
                    j += 2
                    continue
                if ch == c or ch == '\n':
                    break
                blank(j, j + 1)
                j += 1
            i = j + 1
            continue
        if c == '/' and i + 1 < n and masked[i + 1] not in '/*' \
                and _regex_start_context(masked, i):
            j = i + 1
            in_class = False
            while j < n:
                ch = masked[j]
                if ch == '\\':
                    j += 2
                    continue
                if ch == '\n':
                    break
                if in_class:
                    if ch == ']':
                        in_class = False
                elif ch == '[':
                    in_class = True
                elif ch == '/':
                    break
                j += 1
            if j < n and masked[j] == '/':
                end = j + 1
                while end < n and (masked[end].isalnum()):
                    end += 1
                blank(i, end)
                i = end
                continue
        i += 1
    return ''.join(out)


def _mask_non_code(text: str) -> str:
    """Blank comments, template/regex text and string contents (newlines
    preserved) so only real code — with string delimiters — survives.
    Offsets are identical to the input."""
    return _mask_strings_templates_regex(strip_comments_and_strings(text, strip_strings=False))


# ── Verbatim from the legacy typeof heredoc ─────────────────────────────────
def unquote(text: str) -> str:
    text = (text or "").strip()
    if len(text) >= 2 and text[0] in ("'", '"') and text[-1] == text[0]:
        return text[1:-1]
    return ""


VALID_TYPEOF = {"undefined", "string", "number", "boolean", "function", "object", "symbol", "bigint"}
# ── End verbatim heredoc section ────────────────────────────────────────────

_X = r"(?:\([^()\n]*\)|[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z0-9_$]+|\[[^\]\n]*\])*)"
_Y = r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\""
_OP = r"===|==|!==|!="
_TYPEOF_FIRST_RE = re.compile(rf"\btypeof\s*(?P<x>{_X})\s*(?P<op>{_OP})\s*(?P<y>{_Y})")
_TYPEOF_SECOND_RE = re.compile(rf"(?P<y>{_Y})\s*(?P<op>{_OP})\s*typeof\s*(?P<x>{_X})")


def scan_file_findings(path: Path) -> Iterator[tuple[int, int, str]]:
    """Yield (line, col, literal) per invalid typeof comparison; dedup key
    (line, literal) identical to the heredoc's ``(file, line, y_val)``."""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return
    masked = _mask_non_code(text)
    seen: set[tuple[int, str]] = set()
    for regex in (_TYPEOF_FIRST_RE, _TYPEOF_SECOND_RE):
        for m in regex.finditer(masked):
            y_span = m.span("y")
            y_val = unquote(text[y_span[0]:y_span[1]])
            if not y_val or y_val in VALID_TYPEOF:
                continue
            start = m.start()
            line = text.count('\n', 0, start) + 1
            key = (line, y_val)
            if key in seen:
                continue
            seen.add(key)
            col = start - (text.rfind('\n', 0, start) + 1) + 1
            yield line, col, y_val


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for line, col, _literal in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": col,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_invalid_literals_flagged(
    tmp_prefix: str = "ubs_core_spec_typeof_flagged_",
) -> None:
    import tempfile

    src = "\n".join([
        "function checkType(value) {",
        "  if (typeof value === 'array') { return 1; }",
        "  if (typeof value === 'null') { return 2; }",
        "  if (typeof value === 'numeric') { return 3; }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "check.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [(f[0], f[2]) for f in findings] == [
            (2, 'array'), (3, 'null'), (4, 'numeric'),
        ], findings


def _selftest_valid_literals_clean(
    tmp_prefix: str = "ubs_core_spec_typeof_valid_",
) -> None:
    import tempfile

    valids = ('undefined', 'string', 'number', 'boolean', 'function', 'object', 'symbol', 'bigint')
    src = "\n".join(
        f"if (typeof v{k} === '{name}') {{ k{k}(); }}" for k, name in enumerate(valids, 1)
    ) + "\nif ('string' == typeof v9) { v9(); }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "valid.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_reversed_form_flagged(
    tmp_prefix: str = "ubs_core_spec_typeof_reversed_",
) -> None:
    import tempfile

    src = "\n".join([
        "if ('array' === typeof value) { a(); }",
        "if ('str' !== typeof value) { b(); }",
        "if (flag == typeof value) { c(); }  // non-literal Y: ignored",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "reversed.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [(f[0], f[2]) for f in findings] == [(1, 'array'), (2, 'str')], findings


def _selftest_non_string_operands_ignored(
    tmp_prefix: str = "ubs_core_spec_typeof_nonstring_",
) -> None:
    import tempfile

    src = "\n".join([
        "if (typeof value === CONST) { a(); }",
        "if (typeof value === 42) { b(); }",
        "if (typeof value === `array`) { c(); }  // template literal is not a Y string",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "nonstring.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_same_line_dedup(
    tmp_prefix: str = "ubs_core_spec_typeof_dedup_",
) -> None:
    import tempfile

    src = ("if (typeof a === 'array' || typeof b === 'array') { x(); }  "
           "// one (line, literal) pair\n"
           "if (typeof a === 'array' && typeof b === 'null') { y(); }\n")
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "dedup.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [(f[0], f[2]) for f in findings] == [(1, 'array'), (2, 'array'), (2, 'null')], findings


def _selftest_non_code_never_matches(
    tmp_prefix: str = "ubs_core_spec_typeof_noise_",
) -> None:
    import tempfile

    src = "\n".join([
        "// comment: typeof x === 'array'",
        "const s = \"if (typeof q === 'array') {}\";  // string content",
        "const re = /typeof x === 'array'/;",
        "const t = `typeof x === 'array'`;",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "noise.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_template_interpolation_is_code(
    tmp_prefix: str = "ubs_core_spec_typeof_template_",
) -> None:
    import tempfile

    src = "const s = `${typeof v === 'array'}` + `${typeof v === 'string'}`;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tpl.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [(f[0], f[2]) for f in findings] == [(1, 'array')], findings


def _selftest_run_record_shape(
    tmp_prefix: str = "ubs_core_spec_typeof_run_",
) -> None:
    import tempfile

    src = "if (typeof value === 'array') { a(); }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "shape.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "critical", rec
        assert rec["line"] == 1 and rec["col"] == 5, rec
        assert rec["message"].startswith("Invalid typeof comparison"), rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("invalid-literals-flagged", _selftest_invalid_literals_flagged),
    ("valid-literals-clean", _selftest_valid_literals_clean),
    ("reversed-form-flagged", _selftest_reversed_form_flagged),
    ("non-string-operands-ignored", _selftest_non_string_operands_ignored),
    ("same-line-dedup", _selftest_same_line_dedup),
    ("non-code-never-matches", _selftest_non_code_never_matches),
    ("template-interpolation-is-code", _selftest_template_interpolation_is_code),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="spec_typeof", run=run, selftests=SELF_TESTS))
