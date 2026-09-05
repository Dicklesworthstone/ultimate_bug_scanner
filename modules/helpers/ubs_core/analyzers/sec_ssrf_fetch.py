"""ubs_core.analyzers.sec_ssrf_fetch — SSRF-prone outbound request targets (bead A4-js).

Port of the "SSRF-prone outbound request targets" python heredoc from
modules/ubs-js.sh (warning severity, rule js.security.ssrf-fetch). Flags
outbound HTTP client calls (fetch, axios, got, request, http/https, typed
clients) whose target URL is derived from request data (query/body/params/
headers/host) directly or via an unvalidated URL-ish local variable, unless an
allow-list validator (validateOutboundUrl, isAllowedUrl, ALLOWED_HOSTS ...)
guards the statement or surrounding context.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.ssrf-fetch"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Request-derived URL reaches outbound HTTP client"

assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
urlish_name_re = re.compile(
    r'(?:url|uri|target|callback|webhook|endpoint|image|feed|proxy|remote|avatar|next[_-]?hop|host|hostname|origin)',
    re.IGNORECASE,
)
source_re = re.compile(
    r'(?:'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:query|body|params|headers|cookies|nextUrl|url)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:host|hostname|protocol|originalUrl|baseUrl)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:get|header)\s*\(\s*[\'"`](?:host|x-forwarded-host|x-forwarded-proto|origin)[\'"`]\s*\)|'
    r'\b(?:req|request|ctx|context|event)\s*\[\s*[\'"`](?:query|body|params|headers|url)[\'"`]\s*\]|'
    r'\b(?:query|body|params|headers|searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\b(?:searchParams|queryParams)\s*\.\s*get\s*\(|'
    r'\bheaders\s*\(\s*\)\s*\.\s*get\s*\('
    r')',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'(?:'
    r'(?<![\w$.])(?:window\s*\.\s*|globalThis\s*\.\s*)?fetch\s*\(|'
    r'\baxios\s*(?:\.\s*(?:get|post|put|patch|delete|head|request))?\s*\(|'
    r'\bgot\s*(?:\.\s*(?:get|post|put|patch|delete|head))?\s*\(|'
    r'\brequest\s*(?:\.\s*(?:get|post|put|patch|delete|head))?\s*\(|'
    r'\b(?:http|https)\s*\.\s*(?:get|request)\s*\(|'
    r'\b(?:client|httpClient|requestClient|apiClient|transport)\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\('
    r')'
)
safe_re = re.compile(
    r'(?:'
    r'\b(?:validate|assert|ensure|require|check)[A-Za-z0-9_$]*(?:Url|URL|Host|Origin|Outbound|Allowed|Trusted)[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:is|has)[A-Za-z0-9_$]*(?:Allowed|Trusted|Safe)[A-Za-z0-9_$]*(?:Url|URL|Host|Origin)?[A-Za-z0-9_$]*\s*\(|'
    r'\ballow(?:ed|list)[A-Za-z0-9_$]*(?:Url|URL|Host|Origin|Target)?[A-Za-z0-9_$]*\s*\(|'
    r'\bALLOWED_(?:HOSTS|ORIGINS|URLS)\b|\ballowed(?:Hosts|Origins|Urls)\b'
    r')',
    re.IGNORECASE,
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


def statement_from(lines, idx, max_lines=14):
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


def context_from(lines, idx, max_lines=8):
    start = max(0, idx - max_lines)
    for line_idx in range(idx - 1, start - 1, -1):
        if not lines[line_idx].strip():
            start = line_idx + 1
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
        if not unsafe:
            continue
        if idx in seen_lines:
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


def _selftest_query_fetch_flagged(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_") -> None:
    import tempfile

    src = "\n".join([
        "type ExpressRequest = {",
        "  query: Record<string, string | undefined>;",
        "};",
        "",
        "export async function proxyQueryUrl(req: ExpressRequest): Promise<Response> {",
        "  const targetUrl = req.query.url;",
        "  return fetch(targetUrl!, { signal: AbortSignal.timeout(5000) });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "proxy.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [7], findings


def _selftest_multi_client_flagged(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_clients_") -> None:
    import tempfile

    src = "\n".join([
        "import axios from \"axios\";",
        "import got from \"got\";",
        "import http from \"http\";",
        "",
        "export function fetchPreview(request: Request): Promise<unknown> {",
        "  const imageUrl = new URL(request.url).searchParams.get(\"image\");",
        "  return axios.get(imageUrl!);",
        "}",
        "",
        "export function postWebhook(req: any): Promise<unknown> {",
        "  const callbackUrl = req.body.callbackUrl;",
        "  return got(callbackUrl!);",
        "}",
        "",
        "export function streamTarget(req: any): http.ClientRequest {",
        "  const remoteEndpoint = req.headers[\"x-forward-to\"];",
        "  return http.get(remoteEndpoint!);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clients.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [7, 12, 17], findings


def _selftest_validator_suppressed(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_safe_") -> None:
    import tempfile

    src = "\n".join([
        "const ALLOWED_HOSTS = new Set([\"api.example.com\"]);",
        "",
        "function validateOutboundUrl(raw: string | null | undefined): string {",
        "  const parsed = new URL(raw ?? \"https://api.example.com/status\");",
        "  if (parsed.protocol !== \"https:\" || !ALLOWED_HOSTS.has(parsed.hostname)) {",
        "    throw new Error(\"blocked outbound URL\");",
        "  }",
        "  return parsed.toString();",
        "}",
        "",
        "export async function proxyQueryUrl(req: any): Promise<Response> {",
        "  const targetUrl = validateOutboundUrl(req.query.url);",
        "  return fetch(targetUrl, { signal: AbortSignal.timeout(5000) });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_constant_url_clean(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_const_") -> None:
    import tempfile

    src = "\n".join([
        "import axios from \"axios\";",
        "",
        "export function constantServiceCall(): Promise<unknown> {",
        "  return axios.get(\"https://api.example.com/status\");",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "const.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_ignore_placement_suppressed(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_ign_") -> None:
    import tempfile

    trailing = "\n".join([
        "export async function h(req: any) {",
        "  const targetUrl = req.query.url;",
        "  return fetch(targetUrl!); // ubs:ignore",
        "}",
        "",
    ])
    previous = "\n".join([
        "export async function h(req: any) {",
        "  const targetUrl = req.query.url;",
        "  // ubs:ignore",
        "  return fetch(targetUrl!);",
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


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_ssrf_fetch_run_") -> None:
    import tempfile

    src = ("export async function h(req: any) {\n"
           "  const targetUrl = req.query.url;\n"
           "  return fetch(targetUrl!);\n"
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
        assert "outbound HTTP client" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("query-fetch-flagged", _selftest_query_fetch_flagged),
    ("multi-client-flagged", _selftest_multi_client_flagged),
    ("validator-suppressed", _selftest_validator_suppressed),
    ("constant-url-clean", _selftest_constant_url_clean),
    ("ignore-placement-suppressed", _selftest_ignore_placement_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_ssrf_fetch", run=run, selftests=SELF_TESTS))
