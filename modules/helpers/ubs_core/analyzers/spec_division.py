"""ubs_core.analyzers.spec_division — division denominators (bead A4-js final wave).

Verbatim port of the legacy ubs-js.sh ``analyze_division_denominators``
heredoc (ubs-js.sh 2857-2980, GH #73): classify the denominator of every
``$L / $R`` division so constant non-zero divisors (``x / 2``, ``x / 100``,
``x / Math.PI``, ``x / Number.EPSILON``, BigInt/hex/exponent literals) and
``x / (y || <non-zero literal>)`` guards never count toward ÷0 risk, while
every other denominator is reported. The legacy flow matched the divisions
with ast-grep and consumed its JSON stream in python; here the same
per-operator scan runs over ``RunContext.files`` with an equivalent
code-aware single-pass tokenizer that blanks comments, string/template
literals and regex literals with spaces (ast-grep matches code nodes only,
never trivia or literal text — ``"a/b"``, ``// a / b`` and ``/re/`` never
match), keeps ``${...}`` template interpolation code visible (real code
ast-grep matches), and skips ``/=`` (division-assignment is a different
node than ``$L / $R``). A dedicated lexer is required because
``ubs_core.lexer`` has no template/regex awareness and operator-level
detection cannot tolerate literal-text noise. Denominator classification is
the heredoc logic byte-for-byte, so masking can neither invent a safe
denominator (it only deletes characters) nor destroy one (safe candidates
are numeric/``Math.*``/``Number.*``/``||``-literal forms that contain no
strings).

The heredoc's project-level risky counter becomes one finding record per
risky division, severity ``warning`` per the legacy ``print_finding``
("Division by variable - verify non-zero").
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.equality.division-denominator"
CATEGORY_ID = "js.equality"
TITLE = "Division by variable - verify non-zero"
REMEDIATION = "Add guards: if (divisor === 0) throw; or use fallback"
MESSAGE = f"{TITLE} — {REMEDIATION}"
INFO_TITLE = "Division operations found"
INFO_MESSAGE = INFO_TITLE
SEVERITY = "warning"
INFO_SEVERITY = "info"

def _jsx_punct(text: str, idx: int) -> bool:
    """True for the slash of JSX ``</tag>`` / ``<tag/>`` / ``<tag />``
    punctuation: immediately preceded by ``<`` or followed (skipping
    whitespace) by ``>``. No JS division or regex can sit in those spots, so
    such slashes are neither ``$L / $R`` nodes nor regex starts."""
    if idx > 0 and text[idx - 1] == '<':
        return True
    j = idx + 1
    n = len(text)
    while j < n and text[j].isspace():
        j += 1
    return j < n and text[j] == '>'

# A `/` is a regex-literal start when, skipping whitespace backwards, the
# previous token is a keyword or the previous char is not an identifier /
# number / closing bracket (`(a + b) / 2`, `arr[0] / 2` stay divisions).
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


def _mask_non_code(text: str) -> str:
    """Blank comments, string/template-literal text and regex literals with
    spaces (newlines preserved) so only real code operators survive; ``${...}``
    interpolation code stays visible. Offsets are identical to the input."""
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for j in range(a, min(b, n)):
            if out[j] != '\n':
                out[j] = ' '

    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            end = text.find('\n', i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue
        if c == '/' and nxt == '*':
            end = text.find('*/', i + 2)
            end = n if end == -1 else end + 2
            blank(i, end)
            i = end
            continue
        if c in '\'"':
            j = i + 1
            while j < n:
                ch = text[j]
                if ch == '\\':
                    j += 2
                    continue
                if ch == c or ch == '\n':
                    break
                j += 1
            blank(i, min(j + 1, n))
            i = j + 1
            continue
        if c == '`':
            j = i + 1
            while j < n:
                ch = text[j]
                if ch == '\\':
                    j += 2
                    continue
                if ch == '`':
                    j += 1
                    break
                if ch == '$' and j + 1 < n and text[j + 1] == '{':
                    depth = 1
                    k = j + 2
                    while k < n and depth:
                        if text[k] == '{':
                            depth += 1
                        elif text[k] == '}':
                            depth -= 1
                        k += 1
                    blank(j, j + 2)
                    j = k
                    continue
                blank(j, j + 1)
                j += 1
            i = j
            continue
        if c == '/' and nxt == '=':
            i += 2  # /= division-assignment: code, but not a $L / $R node
            continue
        if c == '/' and nxt not in ('/', '*') and not _jsx_punct(text, i) \
                and _regex_start_context(text, i):
            j = i + 1
            in_class = False
            while j < n:
                ch = text[j]
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
            if j < n and text[j] == '/':
                end = j + 1
                while end < n and (text[end].isalnum()):
                    end += 1
                blank(i, end)
                i = end
                continue
        i += 1
    return ''.join(out)


# ── Verbatim from the legacy analyze_division_denominators heredoc ──────────
NUMERIC_LITERAL_RE = re.compile(
    r'^[+-]?(?:'
    r'0[xX][0-9a-fA-F][0-9a-fA-F_]*'
    r'|0[oO][0-7][0-7_]*'
    r'|0[bB][01][01_]*'
    r'|(?:\d[\d_]*)?\.\d[\d_]*(?:[eE][+-]?\d+)?'
    r'|\d[\d_]*\.?(?:[eE][+-]?\d+)?'
    r')n?$'
)
SAFE_CONSTANT_RE = re.compile(
    r'^(?:Math\s*\.\s*(?:PI|E|LN2|LN10|LOG2E|LOG10E|SQRT2|SQRT1_2)'
    r'|Number\s*\.\s*(?:MAX_SAFE_INTEGER|MIN_SAFE_INTEGER|MAX_VALUE|MIN_VALUE|EPSILON))$'
)


def literal_value(text):
    t = text.replace('_', '')
    if t.endswith(('n', 'N')):
        t = t[:-1]
    sign = 1
    if t[:1] in '+-':
        if t[0] == '-':
            sign = -1
        t = t[1:]
    try:
        if t[:2].lower() in ('0x', '0o', '0b'):
            return sign * int(t, 0)
        return sign * float(t)
    except ValueError:
        return None


def strip_outer_parens(text):
    t = text.strip()
    while t.startswith('(') and t.endswith(')'):
        inner = t[1:-1].strip()
        depth = 0
        balanced = True
        for ch in inner:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        t = inner
    return t


def is_safe_denominator(text):
    t = strip_outer_parens(text)
    if NUMERIC_LITERAL_RE.match(t):
        value = literal_value(t)
        return value is not None and value != 0
    if SAFE_CONSTANT_RE.match(t):
        return True
    # `divisor || <non-zero literal>` guards against 0 (0 is falsy). `??` does not.
    fallback = re.match(r'^.+\|\|\s*([^|&]+)$', t)
    if fallback:
        candidate = strip_outer_parens(fallback.group(1))
        if NUMERIC_LITERAL_RE.match(candidate):
            value = literal_value(candidate)
            return value is not None and value != 0
        if SAFE_CONSTANT_RE.match(candidate):
            return True
    return False
# ── End verbatim heredoc section ────────────────────────────────────────────


def _rhs_operand(masked: str, i: int) -> str:
    """Text of the ``$R`` operand starting one past the ``/`` operator index
    ``i - 1``. Mirrors ast-grep's single-expression binding: parens/groups,
    optional unary prefix, then a primary with call and member suffixes."""
    n = len(masked)
    j = i
    while j < n and masked[j].isspace():
        j += 1
    start = j
    if j < n and masked[j] == '(':
        depth = 1
        j += 1
        while j < n and depth:
            if masked[j] == '(':
                depth += 1
            elif masked[j] == ')':
                depth -= 1
            j += 1
        return masked[start:j]
    while j < n and masked[j] in '+-~!':
        j += 1
        while j < n and masked[j].isspace():
            j += 1
    while j < n:
        c = masked[j]
        if c.isalnum() or c in '_$.':
            j += 1
        elif c == '(':
            depth = 1
            j += 1
            while j < n and depth:
                if masked[j] == '(':
                    depth += 1
                elif masked[j] == ')':
                    depth -= 1
                j += 1
        elif c == '[':
            depth = 1
            j += 1
            while j < n and depth:
                if masked[j] == '[':
                    depth += 1
                elif masked[j] == ']':
                    depth -= 1
                j += 1
        else:
            break
    return masked[start:j]


def _lhs_start(masked: str, op_idx: int) -> int:
    """Index where the division expression starts (ast-grep reports the match
    range at the beginning of ``$L``; only its line/col reach the record)."""

    def skip_ws_back(j: int) -> int:
        while j >= 0 and masked[j].isspace():
            j -= 1
        return j

    j = skip_ws_back(op_idx - 1)
    while j >= 0:
        c = masked[j]
        if c in ')]':
            open_ch = '(' if c == ')' else '['
            depth = 0
            while j >= 0:
                if masked[j] == c:
                    depth += 1
                elif masked[j] == open_ch:
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            j = skip_ws_back(j - 1)
            if j >= 0 and masked[j] == '.':
                j -= 1
                j = skip_ws_back(j)
            continue
        if c.isalnum() or c in '_$':
            while j >= 0 and (masked[j].isalnum() or masked[j] in '_$'):
                j -= 1
            if j >= 0 and masked[j] == '.':
                j -= 1
                j = skip_ws_back(j)
                continue
            break
        break
    return j + 1


def scan_file_divisions(path: Path) -> Iterator[tuple[int, int, str]]:
    """Yield (line, col, denominator) per risky division; classification is
    the heredoc's is_safe_denominator, denominator text the ``$R`` binding."""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return
    masked = _mask_non_code(text)
    for m in re.finditer('/', masked):
        i = m.start()
        if i + 1 < len(masked) and masked[i + 1] == '=':
            continue  # /= is a different node
        if _jsx_punct(masked, i):
            continue  # JSX </tag>/<tag/> punctuation, never a $L / $R node
        denominator = _rhs_operand(masked, i + 1)
        if is_safe_denominator(denominator):
            continue
        start = _lhs_start(masked, i)
        line = text.count('\n', 0, start) + 1
        col = start - (text.rfind('\n', 0, start) + 1) + 1
        yield line, col, denominator


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    hits: list[tuple[str, int, int]] = []
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
        for line, col, _denominator in scan_file_divisions(path):
            hits.append((str(rel), line, col))
    if not hits:
        return
    # Legacy severity ladder (ubs-js.sh 4052-4063): severity is resolved ONCE
    # from the project-wide risky count — warning above 25, info otherwise.
    if len(hits) > 25:
        severity, message = SEVERITY, MESSAGE
    else:
        severity, message = INFO_SEVERITY, INFO_MESSAGE
    for rel, line, col in hits:
        yield {
            "rule": RULE,
            "category_id": CATEGORY_ID,
            "path": rel,
            "line": line,
            "col": col,
            "severity": severity,
            "message": message,
        }


def _selftest_variable_denominators_flagged(
    tmp_prefix: str = "ubs_core_spec_division_risky_",
) -> None:
    import tempfile

    src = "\n".join([
        "export function ratios(a, b, c) {",
        "  const r1 = a / b;",
        "  const r2 = a / c;",
        "  const m1 = b / c;",
        "  const m2 = (a + b) / c;",
        "  const m3 = a.a1 / b.b1;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ratios.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_divisions(target))
        assert len(findings) == 5, findings
        assert [f[0] for f in findings] == [2, 3, 4, 5, 6], findings


def _selftest_gh73_safe_denominators_clean(
    tmp_prefix: str = "ubs_core_spec_division_safe_",
) -> None:
    import tempfile

    # GH #73: constant non-zero denominators and ||-guarded divisors are safe
    # no matter how numerous.
    src = "\n".join([
        "export function summarize(samples, total) {",
        "  const h1 = samples[0] / 2;",
        "  const h2 = samples[1] / 100;",
        "  const h3 = samples[2] / Math.PI;",
        "  const h4 = samples[3] / Number.EPSILON;",
        "  const h5 = samples[4] / 0.5;",
        "  const h6 = samples[5] / 0x10;",
        "  const h7 = samples[6] / 1e3;",
        "  const h8 = samples[7] / 10n;",
        "  const h9 = samples[8] / (total || 1);",
        "  const h10 = samples[9] / (total || Math.PI);",
        "  const h11 = samples[10] / -2;",
        "  return [h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11];",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_divisions(target))
        assert findings == [], findings


def _selftest_zero_and_unguarded_risky(
    tmp_prefix: str = "ubs_core_spec_division_zero_",
) -> None:
    import tempfile

    src = "\n".join([
        "const a = x / 0;        // literal zero: still risky",
        "const b = x / (y || 0); // ||-zero guard guards nothing",
        "const c = x / (y ?? 1); // ?? does not guard 0 vs falsy blanks",
        "const d = x / y;",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "zero.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_divisions(target))
        assert [f[0] for f in findings] == [1, 2, 3, 4], findings


def _selftest_non_code_never_matches(
    tmp_prefix: str = "ubs_core_spec_division_noise_",
) -> None:
    import tempfile

    src = "\n".join([
        "const url = 'https://example.com/a/b';   // string text",
        "// comment: total / count should not match",
        "/* block: a / b */",
        "const re = /a\\/b/; return re.test('x / y');",
        "const d = a /= b; // division-assignment is not $L / $R",
        "const t = `text ${p} more`; // template text without division",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "noise.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_divisions(target))
        assert findings == [], findings

def _selftest_severity_ladder(
    tmp_prefix: str = "ubs_core_spec_division_ladder_",
) -> None:
    import tempfile

    # Legacy ladder (ubs-js.sh 4052-4063): 1..25 risky -> info, >25 -> warning.
    for count, expected_severity, expected_prefix in (
        (3, "info", "Division operations found"),
        (25, "info", "Division operations found"),
        (26, "warning", "Division by variable - verify non-zero"),
    ):
        src = "\n".join(
            ["function f(a, b) {"] + [f"  const r{k} = a / b;" for k in range(count)] + ["}"]
        )
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "ladder.js"
            target.write_text(src, encoding="utf-8")
            ctx = RunContext(lang="javascript", files=[target])
            records = list(run(ctx))
            assert len(records) == count, (count, records)
            assert records[0]["severity"] == expected_severity, (count, records[0])
            assert records[0]["message"].startswith(expected_prefix), (count, records[0])


def _selftest_template_interpolation_is_code(
    tmp_prefix: str = "ubs_core_spec_division_template_",
) -> None:
    import tempfile

    src = "const s = `ratio ${total / count} of ${n / 2}`;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tpl.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_divisions(target))
        assert len(findings) == 1, findings  # ${total / count}; ${n / 2} safe
        assert findings[0][0] == 1, findings


def _selftest_run_record_shape(
    tmp_prefix: str = "ubs_core_spec_division_run_",
) -> None:
    import tempfile

    src = "const q = total / count;\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "shape.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "info", rec  # single risky division: info tier
        assert rec["line"] == 1 and rec["col"] == 11, rec
        assert rec["message"].startswith("Division operations found"), rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("variable-denominators-flagged", _selftest_variable_denominators_flagged),
    ("gh73-safe-denominators-clean", _selftest_gh73_safe_denominators_clean),
    ("zero-and-unguarded-risky", _selftest_zero_and_unguarded_risky),
    ("non-code-never-matches", _selftest_non_code_never_matches),
    ("template-interpolation-is-code", _selftest_template_interpolation_is_code),
    ("severity-ladder", _selftest_severity_ladder),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="spec_division", run=run, selftests=SELF_TESTS))
