"""ubs_core.java_detectors.ssrf_outbound_url — category 4 (bead 0xjg.8).

Verbatim port of run_outbound_url_checks (modules/ubs-java.sh 1720-1993):
request-derived values reaching outbound HTTP client sinks (HttpRequest
builders, RestTemplate/WebClient/OkHttp calls, Jsoup/Unirest, openConnection)
unless an allow-list context (safe/validate/allow helpers, URI host checks
with a rejecting branch) guards them. Current+previous-line ubs:ignore
suppresses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.java_detectors._common import (
    annotated_sources,
    has_ignore,
    is_safe_expr,
    iter_java_files,
    logical_statement,
    refs_in_expr,
    source_line,
    taint_from_expr,
    taint_path_desc,
)

RULE_ID = "java.security.ssrf-outbound-url"
CATEGORY = 4
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = (
    "Validate outbound URLs with explicit scheme and host allow-lists before "
    "building or sending client requests"
)

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getServerName|getServerPort|getRemoteHost|getRemoteAddr|'
    r'getLocalName|getLocalAddr|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:path|uri|local|host|port|origin|queryParameters|headers|header)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam)\b'
    r'(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|URI|URL|Object|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:URL|Uri|URI|OutboundURL|OutboundUri|OutboundURI|WebhookURL|CallbackURL|HttpURL)|'
    r'secure(?:URL|Uri|URI|OutboundURL|WebhookURL|CallbackURL)|'
    r'allow(?:URL|Uri|URI|Host|OutboundURL)|allowed(?:URL|Uri|URI|Host|OutboundURL)|'
    r'validate(?:URL|Uri|URI|Host|OutboundURL|WebhookURL|CallbackURL)|'
    r'sanitize(?:URL|Uri|URI|OutboundURL)|resolveAllowed(?:URL|Uri|URI)|'
    r'isAllowedHost|isSafeURL|isSafeUri|isSafeURI)\b',
    re.IGNORECASE,
)
URL_PARSE_RE = re.compile(r'\b(?:URI\.create|URI\.Builder|new\s+URI|new\s+URL)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.\s*(?:getHost|getScheme|getAuthority)\s*\('
    r'|\b(?:allowedHosts|allowlist|hostAllowlist|trustedHosts|isAllowedHost)\b'
    r'|\bSet\.of\s*\('
)
REJECT_RE = re.compile(
    r'\b(?:throw|return\s+false|sendError|abort|forbidden|badRequest|ResponseStatusException|'
    r'IllegalArgumentException|SecurityException)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bHttpRequest\.newBuilder\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:send|newCall|getForObject|getForEntity|postForObject|'
    r'postForEntity|exchange|execute)\s*\('
    r'|\b(?:client|httpClient|ktorClient|webClient|restClient|okHttpClient|'
    r'[A-Za-z_][A-Za-z0-9_]*(?:Client|Http|Rest|Web|Ktor)[A-Za-z0-9_]*)\.'
    r'(?:get|post|put|patch|delete|head|request|prepareGet|preparePost)\s*\('
    r'|\b(?:Jsoup\.connect|Unirest\.(?:get|post|put|delete|patch|head)|Request\.(?:Get|Post|Put|Delete))\s*\('
    r'|\.\s*(?:openConnection|openStream|uri|url)\s*\(',
)
ASSIGN_RE = re.compile(
    r'^\s*(?:final\s+)?(?:val|var|String|URI|URL|HttpRequest|Request|java\.net\.URI|java\.net\.URL|'
    r'okhttp3\.Request|org\.apache\.http\.client\.methods\.[A-Za-z]+)?(?:\s*<[^>]+>)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PATH_LIMIT = 4


def has_allowlist_context(lines, line_no, refs, strip_line_comments):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URL_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))


def analyze(path: Path, issues):
    from ubs_core.java_detectors._common import strip_line_comments

    text = path.read_text(encoding='utf-8', errors='ignore')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    non_http = frozenset()
    if path.suffix.lower() == ".java":
        from ubs_core.analyzers.taint_java_sql import non_http_execute_sites
        non_http = non_http_execute_sites(text)
    line_offsets, offset = [], 0
    for line in text.splitlines(keepends=True):
        line_offsets.append(offset)
        offset += len(line)
    analysis_lines = lines
    if non_http:
        from ubs_core.analyzers.taint_java_sql import comment_masked_source
        analysis_lines = comment_masked_source(text).splitlines()
    tainted = annotated_sources(text, ANNOTATED_PARAM_RE)
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(analysis_lines, idx).strip()
        if not statement:
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted, SOURCE_RE, SAFE_EXPR_RE, PATH_LIMIT)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs, SAFE_EXPR_RE):
                tainted.pop(name, None)
        candidates = list(SINK_RE.finditer(statement))
        if not candidates:
            continue
        # The legacy generic `.execute` spelling also covers JDBC Statements
        # and JDK executors. Exclude only an exactly qualified API call; a
        # neighboring/unknown HTTP call in the same statement still applies.
        physical = strip_line_comments(analysis_lines[idx - 1])
        leading = len(physical) - len(physical.lstrip())
        remaining = []
        for candidate in candidates:
            execute = re.search(r"\.\s*execute\s*\(", candidate.group())
            dot = candidate.start() + execute.start() if execute else -1
            if 0 <= dot < len(physical.strip()) and line_offsets[idx - 1] + leading + dot in non_http:
                continue
            remaining.append(candidate)
        if not remaining:
            continue
        if is_safe_expr(statement, SAFE_EXPR_RE):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, idx, refs, strip_line_comments):
            continue
        key = (str(path), idx)
        if key in seen:
            continue
        seen.add(key)
        path_desc = taint_path_desc(direct, refs, tainted, 'outbound HTTP', PATH_LIMIT)
        issues.append((path, idx, f"{source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        try:
            analyze(path, issues)
        except OSError:
            continue
    for path, line_no, detail in issues:
        yield path, line_no, 1, detail
