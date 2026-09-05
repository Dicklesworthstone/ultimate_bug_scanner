"""ubs_core.analyzers.sec_header_injection — request-controlled value reaches an
HTTP response header (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "HTTP response header injection":
same regexes, same header-method/response-object sink classification, same
6-round taint fixpoint with the DB-result exclusion, same 18-line statement
window, same ubs:ignore placement rules (the marker on the finding line, on
the line before it, or anywhere inside the collected statement text).
The heredoc's os.walk over the project is replaced by iteration over
RunContext.files; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.header-injection"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Request-controlled value reaches HTTP response header"

assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
destruct_assignment_re = re.compile(r'\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.*)')
header_method_re = re.compile(
    r'\b(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)'
    r'\s*\.\s*(?P<method>setHeader|header|set|append)\s*\('
)
candidate_re = re.compile(
    r'(?:setHeader|\.header\s*\(|\.set\s*\(|\.append\s*\(|\bnew\s+Response\s*\(|\bResponse\s*\.|\bNextResponse\s*\.|\bheaders\s*:)',
    re.IGNORECASE,
)
response_headers_object_re = re.compile(
    r'(?:'
    r'\bnew\s+Response\s*\(|'
    r'\bResponse\s*\.\s*(?:json|redirect|error)\s*\(|'
    r'\bNextResponse\s*\.\s*(?:json|redirect|rewrite|next)\s*\('
    r')',
    re.IGNORECASE,
)
source_re = re.compile(
    r'(?:'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:query|body|params|headers|cookies|nextUrl|url)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\[\s*[\'"`](?:query|body|params|headers|cookies|url)[\'"`]\s*\]|'
    r'\b(?:query|body|params|headers|cookies|searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\b(?:searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\bheaders\s*\(\s*\)\s*\.\s*get\s*\(|'
    r'\b(?:req|request)\s*\.\s*headers\s*\.\s*get\s*\(|'
    r'\bnew\s+URL\s*\([^)]*\)\s*\.\s*searchParams\s*\.\s*get\s*\('
    r')',
    re.IGNORECASE,
)
db_result_assignment_re = re.compile(
    r'\b(?:await\s+)?[A-Za-z_$][A-Za-z0-9_$.]*\s*\.\s*(?:query|execute|find|findOne|select)\s*\(',
    re.IGNORECASE,
)
safe_re = re.compile(
    r'(?:'
    r'\b(?:sanitize|clean|escape|encode|validate|assert|ensure|strip|remove)[A-Za-z0-9_$]*(?:Header|CRLF|Crlf|CrlF|CrLf|Newline|Control|Value|Filename)[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:sanitizeHeaderValue|safeHeaderValue|stripCrlf|stripCRLF|removeCRLF|rejectCRLF|contentDisposition|formatContentDisposition)\s*\(|'
    r'\bencodeURIComponent\s*\(|\bencodeURI\s*\(|'
    r'\.replace(?:All)?\s*\([^)]*(?:\\\\r|\\\\n|\[\\\\r\\\\n\]|\\r|\\n|CRLF)[^)]*\)'
    r')',
    re.IGNORECASE,
)
header_literal_re = re.compile(r'^[\'"`]([^\'"`]+)[\'"`]$')
known_response_headers = {
    'location', 'refresh', 'set-cookie', 'content-disposition', 'content-type',
    'cache-control', 'link', 'etag', 'vary', 'x-frame-options',
    'x-content-type-options', 'strict-transport-security',
}


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def statement_from(lines, idx, max_lines=18):
    parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            continue
        parts.append(current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if ';' in current and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts) if saw_code else ""


def split_top_level_args(args_text):
    args = []
    current = []
    depth = 0
    quote = ""
    escaped = False
    for ch in args_text:
        current.append(ch)
        if quote:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            current.pop()
            args.append(''.join(current).strip())
            current = []
    tail = ''.join(current).strip()
    if tail:
        args.append(tail)
    return args


def extract_call_args(text, open_pos):
    depth = 1
    quote = ""
    escaped = False
    start = open_pos
    for pos in range(start, len(text)):
        ch = text[pos]
        if quote:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue
            if ch == quote:
                quote = ""
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[start:pos]
    return text[start:]


def header_name_from_arg(arg):
    match = header_literal_re.match(arg.strip())
    return match.group(1).strip() if match else ""


def looks_like_response_header(name):
    lower = name.lower()
    return '-' in name or lower in known_response_headers


def receiver_parts(receiver):
    compact = re.sub(r'\s+', '', receiver).lower()
    leaf = compact.split('.')[-1]
    return compact, leaf


def is_response_header_method(match, statement):
    args = split_top_level_args(extract_call_args(statement, match.end()))
    first_header = header_name_from_arg(args[0]) if args else ""
    compact_receiver, leaf_receiver = receiver_parts(match.group('receiver'))
    method = match.group('method')
    if 'request' in compact_receiver or leaf_receiver in {'req', 'request', 'clientrequest'}:
        return False
    if method in {'setHeader', 'header'}:
        return True
    if method in {'set', 'append'}:
        receiver_is_headers = leaf_receiver == 'headers' or compact_receiver.endswith('headers')
        return receiver_is_headers and first_header and looks_like_response_header(first_header)
    return False


def destructured_targets(body):
    targets = []
    for part in split_top_level_args(body):
        part = part.strip()
        if not part or part.startswith('...'):
            continue
        if ':' in part:
            local = part.rsplit(':', 1)[-1].strip()
        else:
            local = part
        local = local.split('=')[0].strip()
        if re.match(r'^[A-Za-z_$][A-Za-z0-9_$]*$', local):
            targets.append(local)
    return targets


def has_taint(text, tainted_vars):
    if safe_re.search(text):
        return False
    if source_re.search(text):
        return True
    for name in tainted_vars:
        if re.search(rf'\b{re.escape(name)}\b', text):
            return True
    return False


def collect_tainted_vars(lines):
    assignments = []
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        statement = statement_from(lines, idx)
        if not statement:
            continue
        match = destruct_assignment_re.search(stripped)
        if match:
            targets = destructured_targets(match.group(1))
            expr = match.group(2)
        else:
            match = assignment_re.search(stripped)
            if not match:
                continue
            targets = [match.group(1)]
            expr = match.group(2)
        if not targets:
            continue
        if db_result_assignment_re.search(statement):
            continue
        assignments.append((idx, targets, statement or expr))

    tainted = {}
    for _ in range(6):
        changed = False
        for idx, targets, expr in assignments:
            if safe_re.search(expr):
                continue
            expr_is_tainted = source_re.search(expr) or any(
                re.search(rf'\b{re.escape(name)}\b', expr) for name in tainted
            )
            if not expr_is_tainted:
                continue
            for target in targets:
                if target not in tainted:
                    tainted[target] = idx
                    changed = True
        if not changed:
            break
    return tainted


def response_object_header_sink(statement):
    return bool(
        response_headers_object_re.search(statement)
        and re.search(r'\bheaders\s*:', statement)
    )


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line, sample_text) per detection; logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    tainted_vars = collect_tainted_vars(lines)
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]) or not candidate_re.search(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        has_header_sink = any(is_response_header_method(match, statement) for match in header_method_re.finditer(statement))
        if not has_header_sink:
            has_header_sink = response_object_header_sink(statement)
        if not has_header_sink or not has_taint(statement, tainted_vars):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        yield idx + 1, stripped.replace('\t', ' ')


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
        for line, _sample in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_header_sink_flagged(tmp_prefix: str = "ubs_core_sec_header_injection_") -> None:
    import tempfile

    src = "\n".join([
        "export function expressHeader(req, res) {",
        "  res.setHeader('X-Display-Name', req.query.name);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "server.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 2, findings


def _selftest_sanitized_headers_clean(tmp_prefix: str = "ubs_core_sec_header_injection_san_") -> None:
    import tempfile

    # CR/LF-stripping helper and encodeURIComponent both sanitize the value.
    src = "\n".join([
        "function sanitizeHeaderValue(value: string | null | undefined): string {",
        "  return String(value ?? '').replace(/[\\r\\n]/g, '');",
        "}",
        "export function expressHeader(req, res) {",
        "  res.setHeader('X-Display-Name', sanitizeHeaderValue(req.query.name));",
        "}",
        "export function download(req, res) {",
        "  const filename = encodeURIComponent(req.query.filename);",
        "  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${filename}`);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "server.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_marker_suppression(tmp_prefix: str = "ubs_core_sec_header_injection_ign_") -> None:
    import tempfile

    # Legacy placement rules: marker on the finding line or the line before it.
    for marker in ("res.setHeader('X-A', req.query.name); // ubs:ignore",
                   "// ubs:ignore",
                   "res.setHeader('X-A', req.query.name);"):
        src = "\n".join([
            "export function expressHeader(req, res) {",
            marker,
            "}",
            "",
        ])
        with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
            target = Path(tmp) / "server.ts"
            target.write_text(src, encoding="utf-8")
            findings = list(scan_file_findings(target))
        expected = [] if 'ubs:ignore' in marker else [2]
        assert [line for line, _ in findings] == expected, (marker, findings)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_header_injection_run_") -> None:
    import tempfile

    src = "res.setHeader('X-A', req.query.name);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "server.js"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["message"] == MESSAGE, rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("header-sink-flagged", _selftest_header_sink_flagged),
    ("sanitized-headers-clean", _selftest_sanitized_headers_clean),
    ("ignore-marker-suppression", _selftest_ignore_marker_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_header_injection", run=run, selftests=SELF_TESTS))
