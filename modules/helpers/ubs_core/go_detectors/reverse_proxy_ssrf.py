"""ubs_core.go_detectors.reverse_proxy_ssrf — category 9 security (bead 0xjg.6).

Port of run_reverse_proxy_ssrf_checks (modules/ubs-golang.sh 2504-2793):
a line-oriented taint tracker that propagates request-derived values
(r.URL.Query().Get, r.FormValue/PostFormValue/PathValue, r.Form/PostForm
.Get, r.Header.Get/Values/[...], r.Host/RequestURI, r.URL.Path/RawPath/
RawQuery/Host, chi.URLParam/mux.Vars, gin/echo-style c.Param/Query/
QueryParam/FormValue/PostForm/GetHeader and c.Request() variants)
through ``var``-aware :=/= assignments (chained up to PATH_LIMIT hops)
and flags reverse-proxy sinks reached by a tainted name or a direct
source: httputil.NewSingleHostReverseProxy(...), <proxy>.SetURL(...) and
URL-mutation assignments (<p>.URL.Scheme|Host|Opaque|Path|RawPath|
RawQuery = ..., <p>.Host = ...).

URL-mutation sinks only report when the preceding 18 / following 8 lines
show reverse-proxy context (httputil.ReverseProxy/ProxyRequest,
ReverseProxy{, Director:/Rewrite:). A statement is suppressed when it
names a proxy-target sanitizer (safe/secure/validate/sanitize/allow/
allowed/allowlisted/isSafe|Allowed|Trusted/trusted/resolveAllowed*Proxy
URL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host*, canonicalProxyTarget,
proxyTargetAllowlist, proxyHostAllowlist), or when the preceding 28 /
following 1 lines mention the tainted name through such a helper, an
allow-list name plus a blocking action (http.Error/panic/return nil|
false|""|0|err/errors.New/fmt.Errorf). Unlike the host-header tracker,
re-assignment clears a taint only when the RHS itself is a safe helper.

Legacy: ``print_finding critical $N "Request-derived reverse proxy
target reaches httputil.ReverseProxy" "Validate reverse proxy targets
with an HTTPS scheme and explicit host allow-list before
NewSingleHostReverseProxy, ProxyRequest.SetURL, or Director URL
mutation"``. Same-file and previous-line ``ubs:ignore`` markers suppress
a hit; the legacy heredoc keeps no line dedupe here (preserved). The
rglob/SKIP_DIRS traversal is replaced by the contract file list; the v2
record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

RULE_ID = "go.security.reverse-proxy-ssrf"
CATEGORY = 9
TITLE = "Request-derived reverse proxy target reaches httputil.ReverseProxy"
SEVERITY = "critical"
DESCRIPTION = ("Require HTTPS scheme and host allow-list validation for "
               "reverse proxy targets")

SOURCE_RE = re.compile(
    r'\b(?:r|req|request)\.URL\.Query\(\)\.Get\s*\('
    r'|\b(?:r|req|request)\.(?:FormValue|PostFormValue|PathValue)\s*\('
    r'|\b(?:r|req|request)\.(?:Form|PostForm)\.Get\s*\('
    r'|\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:r|req|request)\.Header\s*\['
    r'|\b(?:r|req|request)\.(?:Host|RequestURI)\b'
    r'|\b(?:r|req|request)\.URL\.(?:Path|RawPath|RawQuery|Host)\b'
    r'|\b(?:chi\.URLParam|mux\.Vars)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Param|Query|QueryParam|FormValue|PostForm|GetHeader)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.(?:Host|RequestURI)\b'
    r'|\b(?:c|ctx|context)\.Request\(\)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.URL\.(?:Path|RawPath|RawQuery|Host)\b'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL)|'
    r'secure(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost)|'
    r'validate(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'sanitize(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'allow(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'allowed(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'allowlisted(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'is(?:Safe|Allowed|Trusted)(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'trusted(?:ProxyURL|ProxyTarget|UpstreamURL|UpstreamHost|URL|Host)|'
    r'resolveAllowed(?:ProxyURL|ProxyTarget|UpstreamURL|URL)|'
    r'canonicalProxyTarget|proxyTargetAllowlist|proxyHostAllowlist)\b',
    re.IGNORECASE,
)
ALLOWLIST_CONTEXT_RE = re.compile(
    r'\b(?:allowedHosts|allowedProxyHosts|proxyHostAllowlist|upstreamAllowlist|allowlist|hostAllowlist)\b'
    r'|\bslices\.Contains\s*\('
)
REVERSE_PROXY_RE = re.compile(
    r'\bhttputil\.(?:NewSingleHostReverseProxy|ReverseProxy|ProxyRequest)\b'
    r'|\bReverseProxy\s*\{'
    r'|\bProxyRequest\b'
)
NEW_PROXY_RE = re.compile(r'\bhttputil\.NewSingleHostReverseProxy\s*\(')
SETURL_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\.SetURL\s*\(')
URL_MUTATION_RE = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.URL\.(?:Scheme|Host|Opaque|Path|RawPath|RawQuery)\s*='
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.Host\s*='
)
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
PATH_LIMIT = 5


def _strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
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
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _logical_statement(lines, line_no):
    idx = line_no - 1
    statement = _strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 10:
        next_line = _strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _lhs_names(lhs):
    names = []
    for part in lhs.split(','):
        name = part.strip()
        if name and name != '_' and IDENT_RE.fullmatch(name):
            names.append(name)
    return names


def _is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def _refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def _taint_from_expr(expr, tainted):
    if _is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
        return {'path': [direct.group(0).strip('(')]}
    refs = _refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def _has_proxy_context(lines, line_no):
    start = max(0, line_no - 18)
    end = min(len(lines), line_no + 8)
    context = '\n'.join(_strip_line_comments(line) for line in lines[start:end])
    return bool(REVERSE_PROXY_RE.search(context) or re.search(r'\b(?:Director|Rewrite)\s*:', context))


def _has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 28)
    context_lines = [_strip_line_comments(line) for line in lines[start:line_no + 1]]
    ref_lines = [
        line for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if not ref_lines:
        return False
    ref_context = '\n'.join(ref_lines)
    full_context = '\n'.join(context_lines)
    if SAFE_EXPR_RE.search(ref_context):
        return True
    has_blocking_action = re.search(
        r'\b(?:http\.Error|panic)\b|\breturn\s+(?:nil|false|""|0|[^,\n]*(?:err|errors\.New|fmt\.Errorf))\b',
        full_context,
    )
    return bool(ALLOWLIST_CONTEXT_RE.search(ref_context) and has_blocking_action)


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and REVERSE_PROXY_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    for idx, _ in enumerate(lines, start=1):
        if _has_ignore(lines, idx):
            continue
        line = _logical_statement(lines, idx).strip()
        if not line:
            continue

        assign = ASSIGN_RE.match(line)
        if assign:
            names = _lhs_names(assign.group('lhs'))
            rhs = assign.group('rhs')
            taint = _taint_from_expr(rhs, tainted)
            if taint:
                for name in names:
                    tainted[name] = taint
            else:
                for name in names:
                    if name in tainted and _is_safe_expr(rhs):
                        tainted.pop(name, None)

        is_proxy_sink = bool(NEW_PROXY_RE.search(line) or SETURL_RE.search(line) or URL_MUTATION_RE.search(line))
        if not is_proxy_sink:
            continue
        if URL_MUTATION_RE.search(line) and not _has_proxy_context(lines, idx):
            continue
        if _is_safe_expr(line):
            continue
        direct = SOURCE_RE.search(line)
        refs = _refs_in_expr(line, tainted)
        if not direct and not refs:
            continue
        if _has_allowlist_context(lines, idx, refs):
            continue
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> reverse proxy target"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('reverse proxy target')
            path_desc = ' -> '.join(seq)
        issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
