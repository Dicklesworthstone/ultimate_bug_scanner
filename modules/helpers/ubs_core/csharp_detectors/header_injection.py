"""ubs_core.csharp_detectors.header_injection — cat 8 security (bead 0xjg.12).

Verbatim port of the ubs-csharp.sh ``run_response_header_injection_checks``
heredoc (2089-2372): same request-source / annotated-param / safe-helper /
CRLF-block / header-sink regexes, bracket-balanced statement joiner, sink-start
gate on the raw line plus sink-name match on the joined statement, and the
18-line CR/LF reject context. The NUL-filelist loader is replaced by iteration
over ``files``; per-file match logic is unchanged.

Legacy emission: critical "Request-controlled value reaches HTTP response
header".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.csharp_detectors._common import (
    has_ignore,
    logical_statement_brackets,
    relpath,
    source_line,
    strip_line_comments,
)

RULE_ID = "csharp.security.header-injection"
CATEGORY = 8
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = "Reject or strip CR/LF, URL-encode filename fragments, or route through a header-safe helper"

SOURCE_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\s*\[[^\]]+\]'
    r'|\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.(?:TryGetValue|ContainsKey)\s*\('
    r'|\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Request\.(?:Host|Path|PathBase|RawTarget|QueryString)\b(?:\.Value\b)?'
    r'|\b(?:ControllerContext|ActionContext)\.HttpContext\.Request\.(?:Host|Path|RawTarget|QueryString)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'\[(?:FromQuery|FromHeader|FromRoute|FromForm|FromBody|FromCookie)'
    r'(?:\s*\([^]]*\))?\]\s*'
    # No space in the class: it overlapped `\s+` under the enclosing `+`
    # and made this an exponential-backtracking match on a long line.
    r'(?:[A-Za-z_][A-Za-z0-9_.<>,?\[\]]+\s+)+'  # ubs:ignore[py.regex.nested-quantifiers] — disjoint separator, verified linear
    r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE | re.MULTILINE,
)
OUT_PARAM_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.TryGetValue\s*\('
    r'[^)]*,\s*out\s+(?:var\s+|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:Safe(?:Header|HeaderValue|ResponseHeader|Disposition|FileName|Filename)|'
    r'Secure(?:Header|HeaderValue|ResponseHeader|Disposition|FileName|Filename)|'
    r'Sanitize(?:Header|HeaderValue|ResponseHeader|Disposition|CRLF|CrLf|FileName|Filename)|'
    r'Validate(?:Header|HeaderValue|ResponseHeader|FileName|Filename)|'
    r'Clean(?:Header|HeaderValue|ResponseHeader|FileName|Filename)|'
    r'Strip(?:CRLF|CrLf|Newlines)|Remove(?:CRLF|CrLf|Newlines)|'
    r'HeaderSafe|CrlfSafe|CrLfSafe|ValidHeaderValue|IsSafeHeaderValue)\b'
    r'|\b(?:Uri\.EscapeDataString|Uri\.EscapeUriString|WebUtility\.UrlEncode|HttpUtility\.UrlEncode|'
    r'UrlEncoder\.Default\.Encode|HeaderUtilities\.SetHttpFileName|HeaderUtilities\.SetHttpFileNameStar)\s*\('
    r'|\.Replace\s*\([^;\n]*(?:\\r|\\n|\\\\r|\\\\n|Environment\.NewLine)',
    re.IGNORECASE,
)
CRLF_LITERAL_RE = re.compile(r'\\r|\\n|\\\\r|\\\\n|Environment\.NewLine|\[\\r\\n\]', re.IGNORECASE)
BLOCK_RE = re.compile(
    r'\b(?:throw|return|BadRequest|Status400BadRequest|Forbid|Unauthorized|'
    r'ArgumentException|InvalidOperationException|SecurityException)\b',
    re.IGNORECASE,
)
HEADER_CALL_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.Headers\.(?:Append|Add|Set)\s*\(\s*'
    r'(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*,',
    re.IGNORECASE,
)
HEADER_INDEX_ASSIGN_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.Headers\s*\[\s*'
    r'(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*\]\s*=',
    re.IGNORECASE,
)
HEADER_PROP_ASSIGN_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.Headers\.'
    r'(?P<name>ContentDisposition|ContentType|CacheControl|ETag|SetCookie|WWWAuthenticate)\s*=',
    re.IGNORECASE,
)
TYPED_HEADER_PROP_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.GetTypedHeaders\s*\(\s*\)\.'
    r'(?P<name>ContentDisposition|CacheControl|ETag)\s*=',
    re.IGNORECASE,
)
HEADER_START_RE = re.compile(
    r'\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.Headers(?:\s*\[|\.(?:Append|Add|Set|'
    r'ContentDisposition|ContentType|CacheControl|ETag|SetCookie|WWWAuthenticate)\b)'
    r'|\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?Response\.GetTypedHeaders\s*\(\s*\)\.',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:var|string|String|object|StringValues|IHeaderDictionary|ResponseHeaders|ContentDispositionHeaderValue)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PROP_HEADER_NAMES = {
    'contentdisposition': 'content-disposition',
    'contenttype': 'content-type',
    'cachecontrol': 'cache-control',
    'etag': 'etag',
    'setcookie': 'set-cookie',
    'wwwauthenticate': 'www-authenticate',
}
PATH_LIMIT = 4


def annotated_sources(text):
    sources = {}
    for match in ANNOTATED_PARAM_RE.finditer(text):
        name = match.group('name')
        sources[name] = {'path': [f'@request {name}']}
    return sources


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def taint_from_expr(expr, tainted):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
        return {'path': [direct.group(0).strip('(')]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def header_sink(statement):
    for regex in (HEADER_CALL_RE, HEADER_INDEX_ASSIGN_RE, HEADER_PROP_ASSIGN_RE, TYPED_HEADER_PROP_RE):
        match = regex.search(statement)
        if not match:
            continue
        raw_name = match.group('name').lower().replace('_', '-').replace('-', '')
        name = PROP_HEADER_NAMES.get(raw_name, raw_name)
        if name == 'location':
            return None
        return match
    return None


def starts_header_sink(line):
    return bool(HEADER_START_RE.search(line))


def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    return bool(CRLF_LITERAL_RE.search(context) and BLOCK_RE.search(context))


def analyze(path: Path, base_dir: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and HEADER_START_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = annotated_sources(text)
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        current_line = strip_line_comments(lines[idx - 1]).strip()
        statement = logical_statement_brackets(lines, idx).strip()
        if not statement:
            continue
        out_param = OUT_PARAM_RE.search(statement)
        if out_param:
            out_source = out_param.group(0).strip()
            if not out_source.endswith(')'):
                out_source += ')'
            tainted[out_param.group('lhs')] = {'path': [out_source]}
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not starts_header_sink(current_line):
            continue
        if not header_sink(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        key = (relpath(path, base_dir), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('response header')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path, base_dir), idx, f"{source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path], base_dir: Path | None = None) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[str, int, str]] = []
    base = base_dir if base_dir is not None else Path.cwd()
    for path in files:
        if path.suffix.lower() not in {'.cs', '.csx'}:
            continue
        analyze(path, base, issues)
    for name, line_no, code in issues:
        yield (name, line_no, 1, code)
