"""ubs_core.analyzers.sec_reverse_proxy — SSRF-prone proxy/rewrite targets (bead A4-js).

Port of the "SSRF-prone proxy/rewrite targets" python heredoc from
modules/ubs-js.sh (warning severity, rule js.security.reverse-proxy). Flags
server-side proxy/rewrite sinks (createProxyMiddleware, http-proxy
createProxyServer/.web()/.ws(), NextResponse.rewrite) whose target comes from
request data (query/headers/host) directly or via an unvalidated URL-ish local
variable, unless a proxy-target validator (validateProxyTarget, allowedProxy*,
ALLOWED_PROXY_* ...) guards the statement or surrounding function context.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.reverse-proxy"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Request-derived proxy target reaches server-side proxy/rewrite"

assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
urlish_name_re = re.compile(
    r'(?:url|uri|target|callback|webhook|endpoint|proxy|upstream|backend|remote|origin|host|hostname|rewrite|router)',
    re.IGNORECASE,
)
source_re = re.compile(
    r'(?:'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:query|body|params|headers|cookies|nextUrl|url)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:host|hostname|protocol|originalUrl|baseUrl)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:get|header)\s*\(\s*[\'"`](?:host|x-forwarded-host|x-forwarded-proto|origin|x-upstream|x-target|x-proxy-target)[\'"`]\s*\)|'
    r'\b(?:req|request|ctx|context|event)\s*\[\s*[\'"`](?:query|body|params|headers|url)[\'"`]\s*\]|'
    r'\b(?:query|body|params|headers|searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\b(?:searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\bheaders\s*\(\s*\)\s*\.\s*get\s*\('
    r')',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'(?:'
    r'\bcreateProxyMiddleware\s*\(|'
    r'\bhttpProxy\s*\.\s*createProxyServer\s*\(|'
    r'\bcreateProxyServer\s*\(|'
    r'\b[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*(?:web|ws)\s*\(|'
    r'\bNextResponse\s*\.\s*rewrite\s*\('
    r')'
)
safe_re = re.compile(
    r'(?:'
    r'\b(?:validate|assert|ensure|require|check)[A-Za-z0-9_$]*(?:Proxy|ProxyTarget|ProxyUrl|ProxyURL|Url|URL|Host|Origin|Outbound|Allowed|Trusted)[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:is|has)[A-Za-z0-9_$]*(?:Allowed|Trusted|Safe)[A-Za-z0-9_$]*(?:Proxy|ProxyTarget|ProxyUrl|ProxyURL|Url|URL|Host|Origin)?[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:safe|trusted|allowed)[A-Za-z0-9_$]*(?:Proxy|ProxyTarget|ProxyUrl|ProxyURL|Url|URL|Host|Origin|Target)[A-Za-z0-9_$]*\s*\(|'
    r'\bALLOWED_(?:PROXY_)?(?:HOSTS|ORIGINS|URLS|TARGETS)\b|'
    r'\ballowed(?:Proxy)?(?:Hosts|Origins|Urls|URLs|Targets)\b'
    r')',
    re.IGNORECASE,
)
function_boundary_re = re.compile(
    r'^\s*(?:export\s+)?(?:async\s+)?function\b|'
    r'^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>'
)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    out = []
    quote = ""
    escaped = False
    i = 0
    while i < len(source_line):
        ch = source_line[i]
        nxt = source_line[i + 1] if i + 1 < len(source_line) else ""
        if quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        if ch == "/" and nxt == "*":
            end = source_line.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def statement_from(lines, idx, max_lines=16):
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


def context_from(lines, idx, max_lines=10):
    start = max(0, idx - max_lines)
    blank_gap = 0
    for line_idx in range(idx - 1, start - 1, -1):
        clean = code_line(lines[line_idx])
        if not clean.strip():
            blank_gap += 1
            if blank_gap > 2:
                start = line_idx + 1
                break
            continue
        blank_gap = 0
        if function_boundary_re.search(clean):
            start = line_idx
            break
    return '\n'.join(
        clean
        for source_line in lines[start:idx + 1]
        for clean in [code_line(source_line)]
        if clean.strip()
    )


def has_safe_validation(text, var_name=""):
    if not safe_re.search(text):
        return False
    return not var_name or re.search(rf'\b{re.escape(var_name)}\b', text)


def tainted_ref(text, tainted_vars):
    for name in tainted_vars:
        if re.search(rf'\b{re.escape(name)}\b', text):
            return name
    return ""


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) per detection; per-file logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    text = '\n'.join(lines)
    if not (source_re.search(text) and sink_re.search(text)):
        return
    tainted_vars = {}
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        statement = statement_from(lines, idx)
        assignment = assignment_re.search(stripped)
        if assignment:
            name = assignment.group(1)
            if (
                urlish_name_re.search(name)
                and not has_safe_validation(statement)
                and (source_re.search(statement) or tainted_ref(statement, tainted_vars))
            ):
                tainted_vars[name] = idx
        if not sink_re.search(stripped):
            continue
        if not statement or 'ubs:ignore' in statement or has_safe_validation(statement):
            continue
        unsafe = bool(source_re.search(statement))
        if not unsafe:
            context = context_from(lines, idx)
            for name, source_idx in tainted_vars.items():
                if source_idx <= idx and re.search(rf'\b{re.escape(name)}\b', statement):
                    if not has_safe_validation(context, name):
                        unsafe = True
                    break
        if not unsafe or idx in seen_lines:
            continue
        seen_lines.add(idx)
        match = sink_re.search(line)
        yield idx + 1, (match.start() + 1) if match else 1


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs pruning relative to the scan root (cwd)
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
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_middleware_query_flagged(tmp_prefix: str = "ubs_core_sec_reverse_proxy_") -> None:
    import tempfile

    src = "\n".join([
        "import { createProxyMiddleware } from \"http-proxy-middleware\";",
        "",
        "export function proxyMiddlewareFromQuery(req: any) {",
        "  const target = req.query.upstream;",
        "  return createProxyMiddleware({",
        "    target,",
        "    changeOrigin: true,",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "proxy.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [5], findings


def _selftest_proxy_web_and_rewrite_flagged(tmp_prefix: str = "ubs_core_sec_reverse_proxy_web_") -> None:
    import tempfile

    src = "\n".join([
        "import httpProxy from \"http-proxy\";",
        "import { NextResponse } from \"next/server\";",
        "",
        "const proxy = httpProxy.createProxyServer({});",
        "",
        "export function proxyWebFromHeader(req: any, res: any) {",
        "  const upstreamUrl = req.headers[\"x-upstream\"];",
        "  proxy.web(req, res, {",
        "    target: upstreamUrl,",
        "  });",
        "}",
        "",
        "export function nextRewriteProxy(request: Request) {",
        "  const rewriteUrl = new URL(request.url).searchParams.get(\"proxy\");",
        "  return NextResponse.rewrite(rewriteUrl!);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "web.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [8, 15], findings


def _selftest_validator_suppressed(tmp_prefix: str = "ubs_core_sec_reverse_proxy_safe_") -> None:
    import tempfile

    src = "\n".join([
        "import { createProxyMiddleware } from \"http-proxy-middleware\";",
        "",
        "const allowedProxyHosts = new Set([\"api.example.com\"]);",
        "",
        "function validateProxyTarget(raw: string | null | undefined): string {",
        "  const parsed = new URL(raw ?? \"https://api.example.com/health\");",
        "  if (parsed.protocol !== \"https:\" || !allowedProxyHosts.has(parsed.hostname)) {",
        "    throw new Error(\"blocked proxy target\");",
        "  }",
        "  return parsed.toString();",
        "}",
        "",
        "export function proxyMiddlewareFromQuery(req: any) {",
        "  const target = validateProxyTarget(req.query.upstream);",
        "  return createProxyMiddleware({",
        "    target,",
        "    changeOrigin: true,",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_literal_target_clean(tmp_prefix: str = "ubs_core_sec_reverse_proxy_lit_") -> None:
    import tempfile

    src = "\n".join([
        "import { createProxyMiddleware } from \"http-proxy-middleware\";",
        "",
        "export function proxyLiteral() {",
        "  return createProxyMiddleware({",
        "    target: \"https://api.example.com\",",
        "    changeOrigin: true,",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "literal.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_ignore_placement_suppressed(tmp_prefix: str = "ubs_core_sec_reverse_proxy_ign_") -> None:
    import tempfile

    trailing = "\n".join([
        "export function proxyFromQuery(req: any) {",
        "  const target = req.query.upstream;",
        "  return createProxyMiddleware({ target }); // ubs:ignore",
        "}",
        "",
    ])
    previous = "\n".join([
        "export function proxyFromQuery(req: any) {",
        "  const target = req.query.upstream;",
        "  // ubs:ignore",
        "  return createProxyMiddleware({ target });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        first = Path(tmp) / "a.ts"
        first.write_text(trailing, encoding="utf-8")
        second = Path(tmp) / "b.ts"
        second.write_text(previous, encoding="utf-8")
        assert list(scan_file_findings(first)) == []
        assert list(scan_file_findings(second)) == []


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_reverse_proxy_run_") -> None:
    import tempfile

    src = ("export function proxyFromQuery(req: any) {\n"
           "  const target = req.query.upstream;\n"
           "  return createProxyMiddleware({ target });\n"
           "}\n")
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "proxy.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == SEVERITY, rec
        assert rec["line"] == 3 and rec["col"] == 10, rec
        assert "proxy" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("middleware-query-flagged", _selftest_middleware_query_flagged),
    ("proxy-web-and-rewrite-flagged", _selftest_proxy_web_and_rewrite_flagged),
    ("validator-suppressed", _selftest_validator_suppressed),
    ("literal-target-clean", _selftest_literal_target_clean),
    ("ignore-placement-suppressed", _selftest_ignore_placement_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_reverse_proxy", run=run, selftests=SELF_TESTS))
