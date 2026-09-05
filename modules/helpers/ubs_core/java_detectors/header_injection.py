"""ubs_core.java_detectors.header_injection — category 4 (bead 0xjg.8).

Verbatim port of run_response_header_injection_checks (modules/ubs-java.sh
1419-1718): request-derived values reaching header sinks (setHeader/addHeader/
header/add/set/append with a literal header name, headers[...] =, headersOf)
unless a safe encoder (URLEncoder, ContentDisposition, strip-CRLF, ...) or a
CRLF-rejecting context guards them. Current+previous-line ubs:ignore
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
    read_lines,
    refs_in_expr,
    source_line,
    strip_line_comments,
    taint_from_expr,
    taint_path_desc,
)

RULE_ID = "java.security.header-injection"
CATEGORY = 4
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = (
    "Reject or strip CR/LF, URL-encode filename fragments, or route values "
    "through a header-safe helper before setHeader/addHeader/header/headers.append"
)

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getCookies|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:headers|header|queryParameters|parameters)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|Object|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:Header|HeaderValue|ResponseHeader|Disposition|Filename|FileName)|'
    r'secure(?:Header|HeaderValue|ResponseHeader|Disposition|Filename|FileName)|'
    r'sanitize(?:Header|HeaderValue|ResponseHeader|Disposition|Filename|FileName|CRLF)|'
    r'validate(?:Header|HeaderValue|ResponseHeader|Filename|FileName)|'
    r'clean(?:Header|HeaderValue|Filename|FileName)|strip(?:CRLF|Newlines)|'
    r'headerSafe|crlfSafe|validHeaderValue|isSafeHeaderValue)\b'
    r'|\b(?:URLEncoder\.encode|UriUtils\.encode|UriUtils\.encodePathSegment|'
    r'PercentEscaper|MimeUtility\.encodeText|ContentDisposition\.)\b'
    r'|\.replace(?:All|First)?\s*\([^;\n]*(?:\\r|\\n|\\\\r|\\\\n)',
    re.IGNORECASE,
)
CRLF_LITERAL_RE = re.compile(r'\\r|\\n|\\\\r|\\\\n|\[\\r\\n\]')
BLOCK_RE = re.compile(
    r'\b(?:throw|return|sendError|abort|badRequest|ResponseStatusException|'
    r'IllegalArgumentException|SecurityException|require)\b',
    re.IGNORECASE,
)
HEADER_CALL_RE = re.compile(
    r'\.\s*(?:setHeader|addHeader|header|add|set|append)\s*\(\s*'
    r'(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*,',
    re.IGNORECASE,
)
HEADER_START_RE = re.compile(
    r'\.\s*(?:setHeader|addHeader|header|add|set|append)\s*\('
    r'|\bheadersOf\s*\(',
    re.IGNORECASE,
)
HEADER_CONST_CALL_RE = re.compile(
    r'\.\s*(?:setHeader|addHeader|header|add|set|append)\s*\(\s*'
    r'(?:HttpHeaders\.)?(?P<name>CONTENT_DISPOSITION|CONTENT_TYPE|CACHE_CONTROL|ETAG|SET_COOKIE)\s*,',
    re.IGNORECASE,
)
HEADER_INDEX_ASSIGN_RE = re.compile(
    r'\.\s*headers\s*\[\s*(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*\]\s*=',
    re.IGNORECASE,
)
HEADERS_OF_RE = re.compile(
    r'\bheadersOf\s*\(\s*(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*,',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:final\s+)?(?:val|var|String|Object|HttpHeaders|HeadersBuilder|MutableHeaders|'
    r'ResponseEntity|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]+)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PATH_LIMIT = 4


def header_sink(statement):
    for regex in (HEADER_CALL_RE, HEADER_CONST_CALL_RE, HEADER_INDEX_ASSIGN_RE, HEADERS_OF_RE):
        match = regex.search(statement)
        if match:
            name = match.group('name').lower().replace('_', '-')
            if name == 'location':
                return None
            return match
    return None


def starts_header_sink(line):
    return bool(HEADER_START_RE.search(line) or HEADER_INDEX_ASSIGN_RE.search(line))


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    return bool(CRLF_LITERAL_RE.search(context) and BLOCK_RE.search(context))


def analyze(path: Path, issues):
    text = path.read_text(encoding='utf-8', errors='ignore')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and (
        HEADER_START_RE.search(text) or HEADER_CALL_RE.search(text) or HEADER_CONST_CALL_RE.search(text) or
        HEADER_INDEX_ASSIGN_RE.search(text) or HEADERS_OF_RE.search(text)
    )):
        return
    lines = text.splitlines()
    tainted = annotated_sources(text, ANNOTATED_PARAM_RE)
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        current_line = strip_line_comments(lines[idx - 1]).strip()
        statement = logical_statement(lines, idx).strip()
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
        if not starts_header_sink(current_line):
            continue
        if not header_sink(statement):
            continue
        if is_safe_expr(statement, SAFE_EXPR_RE):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        key = (str(path), idx)
        if key in seen:
            continue
        seen.add(key)
        path_desc = taint_path_desc(direct, refs, tainted, 'response header', PATH_LIMIT)
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
