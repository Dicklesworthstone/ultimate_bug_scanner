"""ubs_core.go_detectors.outbound_url — category 9 security (bead 0xjg.6).

Port of run_outbound_url_checks (modules/ubs-golang.sh 1996-2240):
a line-oriented taint tracker that propagates request-derived values
(r.URL.Query().Get, r.FormValue/PostFormValue/PathValue, r.Header.Get,
r.Host/RequestURI, r.URL.Path/RawPath/RawQuery, chi.URLParam/mux.Vars,
gin/echo-style c.Param/Query/FormValue/GetHeader and c.Request()
variants) through :=/= assignments (chained up to PATH_LIMIT hops; for
``req, err := http.NewRequest(...)`` only the first LHS name is tainted)
and flags outbound sends — http.Get/Head/Post/PostForm, non-Header/
Query/Values/Form/PostForm/URL receivers' Get/Head/Post/PostForm, and
<client>.Do — reached by a tainted name or a direct source.

A tainted send is suppressed when the surrounding window (preceding 22
lines through the current line) carries a safe-URL helper, or the
tainted name appears together with an allow-list construction
(url.Parse, .Hostname(), allowedHosts/allowlist/hostAllowlist/
isAllowedHost, slices.Contains) plus a blocking action
(return/http.Error/errors.New/fmt.Errorf).

Legacy: ``print_finding critical $N "Request-derived URL reaches
outbound HTTP client" "Validate outbound URLs with an explicit
scheme/host allow-list before calling http.Get/Post/NewRequest or
client.Do"``. Same-file and previous-line ``ubs:ignore`` markers
suppress a hit; the v2 record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.outbound-url"
CATEGORY = 9
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = "Validate scheme and host against an allow-list before outbound HTTP requests"
MARKER = "ubs:ignore"

SOURCE_RE = re.compile(
    r'\br\.URL\.Query\(\)\.Get\s*\('
    r'|\br\.(?:FormValue|PostFormValue|PathValue)\s*\('
    r'|\br\.Header\.Get\s*\('
    r'|\br\.(?:Host|RequestURI)\b'
    r'|\br\.URL\.(?:Path|RawPath|RawQuery)\b'
    r'|\b(?:chi\.URLParam|mux\.Vars)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Param|Query|QueryParam|FormValue|PostForm|GetHeader)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.(?:Host|RequestURI)\b'
    r'|\b(?:c|ctx|context)\.Request\(\)\.URL\.(?:Path|RawPath|RawQuery)\b'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:URL|OutboundURL|WebhookURL|CallbackURL|FetchURL)|'
    r'secure(?:URL|OutboundURL|WebhookURL|CallbackURL)|'
    r'allow(?:URL|Host|OutboundURL)|allowed(?:URL|Host|OutboundURL)|'
    r'validate(?:URL|Host|OutboundURL|WebhookURL|CallbackURL)|'
    r'sanitize(?:URL|OutboundURL)|resolveAllowedURL|isAllowedHost|isSafeURL)\b',
    re.IGNORECASE,
)
ALLOWLIST_CONTEXT_RE = re.compile(
    r'\burl\.Parse\s*\('
    r'|\.\s*Hostname\s*\('
    r'|\b(?:allowedHosts|allowlist|hostAllowlist|isAllowedHost)\b'
    r'|\bslices\.Contains\s*\('
)
HTTP_CALL_RE = re.compile(
    r'\bhttp\.(?:Get|Head|Post|PostForm)\s*\('
    r'|\b(?!Header\b|Query\b|Values\b|Form\b|PostForm\b|URL\b)[A-Za-z_][A-Za-z0-9_]*\.(?:Get|Head|Post|PostForm)\s*\('
)
REQUEST_BUILD_RE = re.compile(r'\bhttp\.NewRequest(?:WithContext)?\s*\(')
DO_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\.Do\s*\(')
ASSIGN_RE = re.compile(r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
PATH_LIMIT = 4


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
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
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


def _has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 22)
    context = '\n'.join(_strip_line_comments(line) for line in lines[start:line_no + 1])
    if SAFE_EXPR_RE.search(context):
        return True
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    return bool(ALLOWLIST_CONTEXT_RE.search(context) and re.search(r'\b(?:return|http\.Error|errors\.New|fmt\.Errorf)\b', context))


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and (HTTP_CALL_RE.search(text) or REQUEST_BUILD_RE.search(text) or DO_RE.search(text))):
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
            target_names = names[:1] if REQUEST_BUILD_RE.search(rhs) else names
            if taint:
                for name in target_names:
                    tainted[name] = taint
            else:
                for name in names:
                    if name in tainted and _is_safe_expr(rhs):
                        tainted.pop(name, None)

        is_send = bool(HTTP_CALL_RE.search(line) or DO_RE.search(line))
        if not is_send:
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
            path_desc = f"{direct.group(0).strip('(')} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('outbound HTTP')
            path_desc = ' -> '.join(seq)
        issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
