"""ubs_core.analyzers.sec_request_regex — request-controlled regex patterns
reaching the regex engine (bead A4-js security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh ``js_request_regex_matches`` function
including its suppression helpers: same source/sink regexes, same 14-line
statement window, same taint propagation (destructuring + assignments with
escape-helper kill rules), same RegExp argument extraction, same ``ubs:ignore``
placement rules (line above, same line, and anywhere inside the collected
statement). The heredoc's os.walk over the project is replaced by iteration
over ``RunContext.files``; per-file match logic is unchanged.

Legacy emission: print_finding "warning" / "Request-controlled regex pattern
reaches regex engine". The legacy title rides in the message so the
contract-v2 text renderer surfaces it verbatim (rule ids are not in
js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.request-regex"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
TITLE = "Request-controlled regex pattern reaches regex engine"
REMEDIATION = ("Escape user-controlled pattern fragments with RegExp.escape/escapeRegExp "
               "or validate against an allow-list before compiling")

source_re = re.compile(
    r'\b(?:req|request|ctx|context|event)\.(?:body|query|params|headers|cookies|nextUrl|url)\b'
    r'|\b(?:req|request|ctx|context)\.(?:get|header|param|query)\s*\('
    r'|\b(?:searchParams|queryParams|URLSearchParams)\.(?:get|getAll)\s*\('
    r'|\bnew\s+URL\s*\([^)]*(?:req|request|event)\b',
    re.IGNORECASE,
)
sink_re = re.compile(r'(?<![A-Za-z0-9_$.])(?:new\s+)?RegExp\s*\(')
assign_re = re.compile(r'^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(.+)$')
simple_assign_re = re.compile(r'^\s*([A-Za-z_$][\w$]*)\s*=\s*(?![=>=])(.+)$')
destructure_re = re.compile(r'^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$')
safe_re = re.compile(
    r'\b(?:RegExp\.escape|escapeRegExp|escapeRegex|regexpEscape|regexEscape|'
    r'sanitizeRegex|sanitizeRegExp|safeRegex|safeRegExp|validateRegex|validateRegExp|'
    r'allowedRegex|allowedRegExp|isAllowedRegex|isSafeRegex|assertSafeRegex)[A-Za-z0-9_$]*\s*\('
    r'|\b(?:ALLOWED|Allowed|allowed)[A-Za-z0-9_$]*\.(?:has|includes)\s*\(',
    re.IGNORECASE,
)


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ''
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            i += 2
            while i + 1 < len(line) and not (line[i] == '*' and line[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def statement_from(lines: list[str], index: int, max_lines: int = 14) -> str:
    parts = []
    paren = brace = bracket = 0
    for offset in range(index, min(len(lines), index + max_lines)):
        current = strip_line_comments(lines[offset]).strip()
        if not current:
            continue
        parts.append(current)
        paren += current.count('(') - current.count(')')
        brace += current.count('{') - current.count('}')
        bracket += current.count('[') - current.count(']')
        if offset > index and paren <= 0 and brace <= 0 and bracket <= 0:
            break
        if ';' in current and paren <= 0 and brace <= 0 and bracket <= 0:
            break
    return ' '.join(parts)


def split_top_level(text: str) -> list[str]:
    parts = []
    current = []
    depth = 0
    quote = ''
    escape = False
    for ch in text:
        if quote:
            current.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            current.append(ch)
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def names_from_destructure(blob: str) -> list[str]:
    names = []
    for part in split_top_level(blob):
        token = part.strip().split('=')[0].strip()
        if ':' in token:
            token = token.split(':', 1)[1].strip()
        if token.startswith('...'):
            token = token[3:].strip()
        if re.match(r'^[A-Za-z_$][\w$]*$', token):
            names.append(token)
    return names


def mask_literals(expr: str) -> str:
    out = []
    quote = ''
    escape = False
    template_expr_depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        nxt = expr[i + 1] if i + 1 < len(expr) else ''
        if quote:
            if quote == '`' and ch == '$' and nxt == '{':
                out.append(' ')
                out.append(' ')
                i += 2
                quote = ''
                template_expr_depth = 1
                continue
            out.append(' ')
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if template_expr_depth:
            out.append(ch)
            if ch in ('"', "'", '`'):
                quote = ch
            elif ch == '{':
                template_expr_depth += 1
            elif ch == '}':
                template_expr_depth -= 1
                if template_expr_depth == 0:
                    quote = '`'
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(' ')
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def refs(expr: str, tainted: set[str]) -> list[str]:
    haystack = mask_literals(expr)
    return [name for name in tainted if re.search(rf'(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])', haystack)]


def is_safe(expr: str) -> bool:
    return bool(safe_re.search(expr))


def has_ignore(lines: list[str], index: int) -> bool:
    return (
        0 <= index < len(lines) and 'ubs:ignore' in lines[index]
    ) or (
        0 <= index - 1 < len(lines) and 'ubs:ignore' in lines[index - 1]
    )


def sink_arg(statement: str) -> str:
    match = sink_re.search(statement)
    if not match:
        return ''
    start = match.end()
    depth = 1
    quote = ''
    escape = False
    for pos in range(start, len(statement)):
        ch = statement[pos]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                args = split_top_level(statement[start:pos])
                return args[0] if args else ''
    return ''


def source_line(lines: list[str], index: int) -> str:
    return lines[index].strip().replace('\t', ' ')


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line_number, sample_text) per detection; heredoc-identical."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    text = '\n'.join(lines)
    if not (source_re.search(text) and sink_re.search(text)):
        return
    tainted: set[str] = set()
    seen: set[tuple[str, int]] = set()
    for idx, raw in enumerate(lines):
        stripped = strip_line_comments(raw).strip()
        if not stripped or has_ignore(lines, idx):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        destruct = destructure_re.match(statement)
        if destruct:
            rhs = destruct.group(2)
            names = names_from_destructure(destruct.group(1))
            if source_re.search(rhs) or refs(rhs, tainted):
                tainted.update(names)
            elif is_safe(rhs):
                tainted.difference_update(names)
        assign = assign_re.match(statement) or simple_assign_re.match(statement)
        if assign:
            name, rhs = assign.groups()
            if is_safe(rhs):
                tainted.discard(name)
            elif source_re.search(rhs) or refs(rhs, tainted):
                tainted.add(name)
        if not sink_re.search(statement):
            continue
        arg = sink_arg(statement)
        if not arg or is_safe(arg):
            continue
        if not (source_re.search(arg) or refs(arg, tainted)):
            continue
        key = (str(path), idx + 1)
        if key in seen:
            continue
        seen.add(key)
        yield idx + 1, source_line(lines, idx)


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
        for line, sample in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": f"{TITLE}: {sample}",
                "remediation": REMEDIATION,
            }


def _selftest_request_pattern_compiled(tmp_prefix: str = "ubs_core_sec_regex_") -> None:
    import tempfile

    src = "\n".join([
        "export function filter(request: Request) {",
        "  const term = new URL(request.url).searchParams.get('q');",
        "  return new RegExp(term).test('x');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "filter.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample = findings[0]
    assert line == 3, findings
    assert "new RegExp(term)" in sample, findings


def _selftest_propagated_pattern(tmp_prefix: str = "ubs_core_sec_regex_prop_") -> None:
    import tempfile

    src = "\n".join([
        "export function match(req: Request) {",
        "  const pattern = req.query.get('pattern');",
        "  const re = new RegExp(pattern, 'i');",
        "  return re.exec('payload');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "match.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, _sample = findings[0]
    assert line == 3, findings


def _selftest_escaped_and_allowlisted_clean(tmp_prefix: str = "ubs_core_sec_regex_clean_") -> None:
    import tempfile

    # escaped fragment and allow-list validated pattern both stay clean
    src = "\n".join([
        "export function search(request: Request) {",
        "  const q = new URL(request.url).searchParams.get('q');",
        "  const escaped = new RegExp(escapeRegExp(q));",
        "  const allowed = allowedPatterns.has(q) ? new RegExp(q) : null;",
        "  return { escaped, allowed };",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "search.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_regex_ign_") -> None:
    import tempfile

    # line-above placement suppresses; same-line placement suppresses
    src = "\n".join([
        "export function f(req: Request) {",
        "  // ubs:ignore",
        "  const a = new RegExp(req.query.get('q'));",
        "  const b = new RegExp(req.query.get('q')); // ubs:ignore",
        "  return [a, b];",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ign.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_regex_run_") -> None:
    import tempfile

    src = "export function f(req: Request) {\n  return new RegExp(req.query.get('q'));\n}\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "run.ts"
        target.write_text(src, encoding="utf-8")
        records = list(run(RunContext(lang="javascript", files=[target])))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 2, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("request-pattern-compiled", _selftest_request_pattern_compiled),
    ("propagated-pattern", _selftest_propagated_pattern),
    ("escaped-and-allowlisted-clean", _selftest_escaped_and_allowlisted_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_request_regex", run=run, selftests=SELF_TESTS))
