"""ubs_core.go_detectors.header_injection — category 9 security (bead 0xjg.6).

Port of run_response_header_injection_checks (modules/ubs-golang.sh
1737-1994): a line-oriented taint tracker that propagates request-derived
values (r.URL.Query().Get, r.FormValue/PostFormValue/PathValue/Cookie,
r.Form/PostForm.Get, r.Header.Get/Values/[...], r.Host/Referer/
RequestURI, r.URL.Path/RawPath/RawQuery, chi.URLParam/mux.Vars,
gin/echo-style c.Param/Query/Cookie/GetHeader and c.Request() variants)
through ``var``-aware :=/= assignments (chained up to PATH_LIMIT hops)
and flags response-header sinks (w.Header().Set/Add,
w.Header()[...] =, header/headers/respHeaders/responseHeaders/h
.Set/Add, c.Header/c.Set) reached by a tainted name or a direct source.
Location-header writes are excluded here (the open-redirect rule owns
them).

A tainted line is suppressed when the statement itself carries a header
sanitizer (safe/sanitize/clean/strip-*, url/path.QueryEscape,
mime.FormatMediaType, strconv.Quote, strings.NewReplacer/ReplaceAll of
\r\n), or when the preceding 20 lines show the tainted name through a
safe helper, or a CR/LF containment check followed by a blocking action
(return/http.Error/panic/StatusBadRequest/errors.New/fmt.Errorf). Unlike
the sibling trackers, re-assignment of a tainted name to a clean value
drops the taint unconditionally.

Legacy: ``print_finding critical $N "Request-controlled value reaches
HTTP response header" "Reject or strip CR/LF, use mime.FormatMediaType
for Content-Disposition, or route through a header-safe helper before
Header().Set/Add"``. Same-file and previous-line ``ubs:ignore`` markers
suppress a hit; the v2 record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.header-injection"
CATEGORY = 9
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = "Strip CR/LF or reject newline-bearing header values before w.Header().Set/Add"
MARKER = "ubs:ignore"

SOURCE_RE = re.compile(
    r'\br\.URL\.Query\(\)\.Get\s*\('
    r'|\br\.(?:FormValue|PostFormValue|PathValue|Cookie)\s*\('
    r'|\br\.(?:Form|PostForm)\.Get\s*\('
    r'|\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:r|req|request)\.Header\s*\['
    r'|\b(?:r|req|request)\.(?:Host|Referer|RequestURI)\b'
    r'|\br\.URL\.(?:Path|RawPath|RawQuery)\b'
    r'|\b(?:chi\.URLParam|mux\.Vars)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Param|Query|QueryParam|FormValue|PostForm|GetHeader|Cookie)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.(?:Host|Referer|RequestURI)\b'
    r'|\b(?:c|ctx|context)\.Request\(\)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.URL\.(?:Path|RawPath|RawQuery)\b'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:Header|HeaderValue|ResponseHeader|Filename|FileName)|'
    r'secure(?:Header|HeaderValue|ResponseHeader|Filename|FileName)|'
    r'sanitize(?:Header|HeaderValue|ResponseHeader|Filename|FileName|CRLF)|'
    r'clean(?:Header|HeaderValue|ResponseHeader|Filename|FileName)|'
    r'strip(?:CRLF|Newlines)|headerSafe|crlfSafe|validHeaderValue|validateHeaderValue)\b'
    r'|\b(?:url|path)\.(?:QueryEscape|PathEscape)\s*\('
    r'|\bmime\.FormatMediaType\s*\('
    r'|\bstrconv\.Quote\s*\('
    r'|\bstrings\.NewReplacer\s*\('
    r'|\bstrings\.(?:ReplaceAll|Replace)\s*\([^)]*(?:\\r|\\n)',
    re.IGNORECASE,
)
HEADER_SINK_RE = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.Header\(\)\.(?:Set|Add)\s*\('
    r'|\bHeader\(\)\.(?:Set|Add)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.Header\(\)\s*\[[^\]]+\]\s*='
    r'|\b(?:header|headers|respHeaders|responseHeaders|h)\.(?:Set|Add)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Header|Set)\s*\('
)
LOCATION_HEADER_RE = re.compile(r'\(\s*"Location"\s*,', re.IGNORECASE)
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
CRLF_CHECK_RE = re.compile(
    r'\bstrings\.ContainsAny\s*\([^)]*(?:\\r|\\n)'
    r'|\bstrings\.Contains\s*\([^)]*(?:\\r|\\n)'
    r'|(?:==|!=)\s*(?:"\\r"|"\\n"|`\\r`|`\\n`)',
    re.IGNORECASE,
)
BLOCK_RE = re.compile(r'\b(?:return|http\.Error|panic|StatusBadRequest|errors\.New|fmt\.Errorf)\b')
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


def _has_header_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 20)
    context_lines = [_strip_line_comments(line) for line in lines[start:line_no]]
    context = '\n'.join(context_lines)
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    ref_lines = [
        line for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if any(SAFE_EXPR_RE.search(line) for line in ref_lines):
        return True
    return bool(CRLF_CHECK_RE.search(context) and BLOCK_RE.search(context))


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and HEADER_SINK_RE.search(text)):
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
                    tainted.pop(name, None)
        if not HEADER_SINK_RE.search(line):
            continue
        if LOCATION_HEADER_RE.search(line):
            continue
        if _is_safe_expr(line):
            continue
        direct = SOURCE_RE.search(line)
        refs = _refs_in_expr(line, tainted)
        if not direct and not refs:
            continue
        if _has_header_validation_context(lines, idx, refs):
            continue
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('response header')
            path_desc = ' -> '.join(seq)
        issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
