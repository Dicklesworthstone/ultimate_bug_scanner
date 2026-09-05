"""ubs_core.analyzers.spec_block_function — function declarations inside
conditional/loop blocks (bead A4-js final wave).

Verbatim port of the legacy ubs-js.sh heredoc "Function declarations inside
blocks" (GH #72): per-file brace tracking that classifies every opened block
(function / conditional / other) and reports only function *declarations*
whose immediately enclosing block is an if/for/while/switch block or an
else/do block — so module-scope helpers whose names merely contain
"for"/"if"/"while" substrings are no longer flagged. Same DECL_RE /
COND_HEAD_RE regexes, same comment/string-blanking strip_code
(offset-preserving), same paren-depth-aware statement reset, same
``ubs:ignore`` placement rule (on the declaration's raw line).
The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.function-scope.block-function"
CATEGORY_ID = "js.function-scope"
MESSAGE = ("Function declarations in blocks - use function expressions: "
           "Hoisting is inconsistent")

DECL_RE = re.compile(
    r'^(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s*\*)?\s+[A-Za-z_$][\w$]*\s*\('
)
COND_HEAD_RE = re.compile(r'(?:^|[^\w$])(?:if|for|while|switch)\s*\(')
REGEX_PREFIX_CHARS = set('(,=:[!&|?{};+-*%~^<>')


def strip_code(text):
    """Blank out comments and string/template literal contents, preserving
    line structure so line numbers stay aligned with the source."""
    out = []
    i = 0
    n = len(text)
    state = 'code'
    prev_code = ''
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if state == 'code':
            if ch == '/' and nxt == '/':
                state = 'line_comment'
                out.append('  ')
                i += 2
                continue
            if ch == '/' and nxt == '*':
                state = 'block_comment'
                out.append('  ')
                i += 2
                continue
            if ch == '/' and (prev_code == '' or prev_code in REGEX_PREFIX_CHARS):
                state = 'regex'
                out.append(' ')
                i += 1
                continue
            if ch == "'":
                state = 'single'
                out.append(' ')
                i += 1
                continue
            if ch == '"':
                state = 'double'
                out.append(' ')
                i += 1
                continue
            if ch == '`':
                state = 'template'
                out.append(' ')
                i += 1
                continue
            out.append(ch)
            if not ch.isspace():
                prev_code = ch
            i += 1
            continue
        if state == 'line_comment':
            if ch == '\n':
                state = 'code'
                out.append('\n')
            else:
                out.append(' ')
            i += 1
            continue
        if state == 'block_comment':
            if ch == '*' and nxt == '/':
                state = 'code'
                out.append('  ')
                i += 2
            else:
                out.append('\n' if ch == '\n' else ' ')
                i += 1
            continue
        closer = {'single': "'", 'double': '"', 'template': '`', 'regex': '/'}[state]
        if ch == '\\':
            out.append(' ')
            if nxt:
                out.append('\n' if nxt == '\n' else ' ')
            i += 2
            continue
        if ch == closer:
            state = 'code'
            out.append(' ')
            i += 1
            continue
        if ch == '\n':
            if state in ('single', 'double', 'regex'):
                state = 'code'
            out.append('\n')
            i += 1
            continue
        out.append(' ')
        i += 1
    return ''.join(out)


def classify(head):
    """Classify the block opened after `head`. Returns (kind, is_declaration)."""
    h = head.strip()
    if DECL_RE.match(h):
        return 'func', True
    if re.search(r'\bfunction\b', h) or re.search(r'=>\s*$', h):
        return 'func', False
    if re.search(r'\bclass\b', h):
        return 'func', False
    if COND_HEAD_RE.search(h) and h.endswith(')'):
        return 'cond', False
    if re.search(r'(?:^|[^\w$])(?:else|do)\s*$', h):
        return 'cond', False
    return 'other', False


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) of each function declaration inside a conditional or
    loop block; match logic identical to the heredoc."""
    try:
        raw_text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return
    text = strip_code(raw_text)
    raw_lines = raw_text.splitlines()

    stack = []
    head = []
    head_start_line = None
    head_start_col = None
    paren_depth = 0
    line_no = 1
    for pos, ch in enumerate(text):
        if ch == '\n':
            line_no += 1
            head.append(' ')
            continue
        if ch == '(':
            paren_depth += 1
            head.append(ch)
            continue
        if ch == ')':
            paren_depth = max(0, paren_depth - 1)
            head.append(ch)
            continue
        if ch == ';' and paren_depth == 0:
            head = []
            head_start_line = None
            head_start_col = None
            continue
        if ch == '{':
            kind, is_declaration = classify(''.join(head))
            if is_declaration and stack and stack[-1] == 'cond':
                decl_line = head_start_line or line_no
                raw_line = raw_lines[decl_line - 1].strip() if decl_line <= len(raw_lines) else ''
                if 'ubs:ignore' not in raw_line:
                    decl_col = head_start_col or (pos - text.rfind('\n', 0, pos))
                    yield decl_line, decl_col
            stack.append(kind)
            head = []
            head_start_line = None
            head_start_col = None
            continue
        if ch == '}':
            if stack:
                stack.pop()
            head = []
            head_start_line = None
            head_start_col = None
            continue
        if head_start_line is None and not ch.isspace():
            head_start_line = line_no
            head_start_col = pos - text.rfind('\n', 0, pos)
        head.append(ch)


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
        for line, col in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": col,
                "severity": "warning",
                "message": MESSAGE,
            }


def _selftest_block_function_flagged(tmp_prefix: str = "ubs_core_block_function_") -> None:
    import tempfile

    src = "\n".join([
        "export function setup(flag, items) {",
        "  if (flag) {",
        "    function helper() {",
        "      return 1;",
        "    }",
        "    return helper();",
        "  }",
        "  for (const item of items) {",
        "    function perItem() {",
        "      return item;",
        "    }",
        "    perItem();",
        "  }",
        "  return 0;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "functions.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [(3, 5), (9, 5)], findings


def _selftest_module_scope_helpers_clean(tmp_prefix: str = "ubs_core_block_function_clean_") -> None:
    import tempfile

    # Module-scope declarations whose names merely contain for/if/while
    # substrings, plus expression/arrow forms inside a conditional block,
    # must not be reported.
    src = "\n".join([
        "export function formatCurrencyShort(amount) {",
        "  return `$${(amount / 100).toFixed(2)}`;",
        "}",
        "",
        "export function classifyRecord(record) {",
        '  return record.total > 0 ? "credit" : "debit";',
        "}",
        "",
        "export function verifyRun(run) {",
        "  return Boolean(run && run.completedAt);",
        "}",
        "",
        "export function formatValue(value) {",
        "  return String(value);",
        "}",
        "",
        "export function classifyValue(value) {",
        "  return typeof value;",
        "}",
        "",
        "export function whileLabel(count) {",
        "  return `${count} remaining`;",
        "}",
        "",
        "export function ifCaption(enabled) {",
        "  const render = function caption() {",
        '    return enabled ? "on" : "off";',
        "  };",
        "  return render();",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_expression_forms_not_declarations(tmp_prefix: str = "ubs_core_block_function_expr_") -> None:
    import tempfile

    # Function expressions, arrows, and classes opened in a conditional block
    # are hoisting-safe (is_declaration False); so are declarations nested in
    # plain function blocks.
    src = "\n".join([
        "function outer() {",
        "  if (true) {",
        "    const f = function () {",
        "      return 1;",
        "    };",
        "    const g = () => {",
        "      return 2;",
        "    };",
        "    class C {",
        "      m() {}",
        "    }",
        "  }",
        "  function innerMethod() {",
        "    return 3;",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "expr.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_line_ignore_suppressed(tmp_prefix: str = "ubs_core_block_function_ign_") -> None:
    import tempfile

    # ubs:ignore on the declaration's raw line suppresses that declaration
    # only; the un-ignored sibling is still reported.
    src = "\n".join([
        "export function setup(flag) {",
        "  if (flag) {",
        "    function ignored() { // ubs:ignore",
        "      return 1;",
        "    }",
        "    ignored();",
        "  }",
        "  while (flag) {",
        "    function tick() {",
        "      return 2;",
        "    }",
        "    tick();",
        "    break;",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.js"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [(9, 5)], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_block_function_run_") -> None:
    import tempfile

    src = "\n".join([
        "function drive(ready) {",
        "  while (ready) {",
        "    function tick() {",
        "      return 1;",
        "    }",
        "    tick();",
        "    break;",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "shape.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 3 and rec["col"] == 5, rec
        assert "function expressions" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("block-function-flagged", _selftest_block_function_flagged),
    ("module-scope-helpers-clean", _selftest_module_scope_helpers_clean),
    ("expression-forms-not-declarations", _selftest_expression_forms_not_declarations),
    ("line-ignore-suppressed", _selftest_line_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="spec_block_function", run=run, selftests=SELF_TESTS))
