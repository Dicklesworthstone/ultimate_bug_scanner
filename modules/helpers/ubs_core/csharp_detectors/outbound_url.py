"""ubs_core.csharp_detectors.outbound_url — cat 8 security (bead 0xjg.12).

Verbatim port of the ubs-csharp.sh ``run_request_outbound_url_checks`` heredoc
(2389-2622): same URL-keyed request-source / safe-helper / Uri-parse +
host-check + reject context regexes, statement joiner, and PATH_LIMIT-bounded
taint propagation (assignment kill on safe reassignment, TryGetValue out-param
sources, url-ish LHS names). The NUL-filelist loader is replaced by iteration
over ``files``; per-file match logic is unchanged.

Legacy emission: critical "Request-derived URL reaches outbound HTTP client".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.csharp_detectors._common import (
    has_ignore,
    logical_statement,
    relpath,
    source_line,
    strip_line_comments,
)

RULE_ID = "csharp.security.outbound-url"
CATEGORY = 8
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = "Validate with Uri parsing plus explicit https scheme and host allow-list checks"

URL_KEY = r'(?:url|uri|host|origin|callback|webhook|redirect|endpoint|target|remote|link|location|referer|referrer)'

SOURCE_RE = re.compile(
    rf'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers)\s*\[[^\]]*{URL_KEY}[^\]]*\]'
    rf'|\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers)\.(?:TryGetValue|ContainsKey)\s*\([^)]*{URL_KEY}[^)]*\)'
    r'|\b(?:HttpContext\.)?Request\.(?:Host|Path|PathBase|RawTarget|QueryString)\b(?:\.Value\b)?'
    r'|\b(?:ControllerContext|ActionContext)\.HttpContext\.Request\.(?:Host|Path|RawTarget|QueryString)\b',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers)\s*\[[^\]]+\]'
    r'|\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers)\.(?:TryGetValue|ContainsKey)\s*\(',
    re.IGNORECASE,
)
URLISH_NAME_RE = re.compile(URL_KEY, re.IGNORECASE)
SAFE_EXPR_RE = re.compile(
    r'\b(?:Safe(?:Outbound)?Url|Safe(?:Outbound)?Uri|Validated(?:Outbound)?Url|Validate(?:Outbound)?Url|'
    r'Allowed(?:Outbound)?Url|AllowlistedUrl|TrustedUrl|SanitizeUrl|SanitizeUri|'
    r'ResolveAllowedUrl|RequireAllowedHost|IsAllowedHost|AllowedHost)\b',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:Uri\.TryCreate|new\s+Uri)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:Scheme|Host)\b'
    r'|\b(?:AllowedHosts|AllowedHost|HostAllowlist|TrustedHosts|ALLOWED_HOSTS)\b'
    r'|\.Contains\s*\('
    r'|\bUri\.UriSchemeHttps\b',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'\b(?:throw|return\s+(?:null|false)|BadRequest|Forbid|Unauthorized)\b', re.IGNORECASE)
SINK_RE = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.(?:GetAsync|GetStringAsync|GetByteArrayAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync)\s*\('
    r'|\bnew\s+HttpRequestMessage\s*\('
    r'|\b(?:WebRequest|HttpWebRequest)\.Create(?:Http)?\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:DownloadString|DownloadData|OpenRead|UploadString|UploadData)\s*\('
    r'|\bRestClient\.(?:Get|Post|Put|Patch|Delete|Execute)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:Get|Post|Put|Patch|Delete|Execute)\s*\([^;]*(?:url|uri|endpoint|request)',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:var|string|String|Uri|UriBuilder|HttpRequestMessage|HttpRequest|HttpResponseMessage)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
OUT_PARAM_RE = re.compile(
    rf'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers)\.TryGetValue\s*\([^)]*{URL_KEY}[^)]*,\s*out\s+'
    r'(?:var\s+|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
PATH_LIMIT = 4


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def has_source(expr, target_name=''):
    if SOURCE_RE.search(expr):
        return True
    return bool(target_name and URLISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(expr))


def taint_from_expr(expr, tainted, target_name=''):
    if is_safe_expr(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = SOURCE_RE.search(expr)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))


def analyze(path: Path, base_dir: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:Request|HttpContext)\b', text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
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
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = has_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, idx, refs):
            continue
        key = (relpath(path, base_dir), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('outbound HTTP')
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
