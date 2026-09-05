"""ubs_core.go_detectors.open_redirect — category 9 security (bead 0xjg.6).

Port of run_open_redirect_checks (modules/ubs-golang.sh 1485-1735):
a line-oriented taint tracker that propagates request-derived values
(r.URL.Query().Get, r.FormValue/PostFormValue/PathValue, r.Form/PostForm
.Get, r.Header.Get/Values/[...], r.Referer(), r.Host/Referer/RequestURI,
r.URL.Path/RawPath/RawQuery, chi.URLParam/mux.Vars, gin/echo-style
c.Param/Query/FormValue/GetHeader and c.Request() variants) through
``var``-aware :=/= assignments (chained up to PATH_LIMIT hops) and flags
http.Redirect / <w>.Redirect calls plus Location-header
Header().Set/Add writes reached by a tainted name or a direct source.

A tainted line is suppressed when the statement itself carries a
safe-redirect helper, or when the preceding 24 lines show the tainted
name guarded by a safe-redirect helper together with a blocking action
(return/http.Error/errors.New/fmt.Errorf/panic).

Legacy: ``print_finding critical $N "Unvalidated redirect from request
data" "Validate redirect targets with same-origin relative paths or an
explicit host allow-list before redirecting or setting Location"``.
Same-file and previous-line ``ubs:ignore`` markers suppress a hit; the
v2 record count equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.open-redirect"
CATEGORY = 9
TITLE = "Unvalidated redirect from request data"
SEVERITY = "critical"
DESCRIPTION = "Validate redirect targets against same-origin relative paths or an explicit host allow-list"
MARKER = "ubs:ignore"

SOURCE_RE = re.compile(
    r'\br\.URL\.Query\(\)\.Get\s*\('
    r'|\br\.(?:FormValue|PostFormValue|PathValue)\s*\('
    r'|\br\.(?:Form|PostForm)\.Get\s*\('
    r'|\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:r|req|request)\.Header\s*\['
    r'|\b(?:r|req|request)\.Referer\s*\('
    r'|\br\.(?:Host|Referer|RequestURI)\b'
    r'|\br\.URL\.(?:Path|RawPath|RawQuery)\b'
    r'|\b(?:chi\.URLParam|mux\.Vars)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Param|Query|QueryParam|FormValue|PostForm|GetHeader)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.(?:Host|Referer|RequestURI)\b'
    r'|\b(?:c|ctx|context)\.Request\(\)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.URL\.(?:Path|RawPath|RawQuery)\b'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'secure(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'validate(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'sanitize(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'allow(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'allowed(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'is(?:Safe|Allowed)(?:Redirect|RedirectURL|RedirectTarget|Location|ReturnTo)|'
    r'sameOrigin(?:Redirect|RedirectURL|URL)?|localRedirect|relativeRedirect|urlFor)\b',
    re.IGNORECASE,
)
REDIRECT_SINK_RE = re.compile(
    r'\bhttp\.Redirect\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.Redirect\s*\('
)
LOCATION_SINK_RE = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\.Header\(\)\.(?:Set|Add)\s*\(\s*"Location"\s*,'
    r'|\bHeader\(\)\.(?:Set|Add)\s*\(\s*"Location"\s*,'
)
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
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


def _has_safe_redirect_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context_lines = [_strip_line_comments(line) for line in lines[start:line_no]]
    ref_lines = [
        line for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if not ref_lines:
        return False
    ref_context = '\n'.join(ref_lines)
    full_context = '\n'.join(context_lines)
    has_blocking_action = re.search(r'\b(?:return|http\.Error|errors\.New|fmt\.Errorf|panic)\b', full_context)
    return bool(SAFE_EXPR_RE.search(ref_context) and has_blocking_action)


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and (REDIRECT_SINK_RE.search(text) or LOCATION_SINK_RE.search(text))):
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

        if not (REDIRECT_SINK_RE.search(line) or LOCATION_SINK_RE.search(line)):
            continue
        if _is_safe_expr(line):
            continue
        direct = SOURCE_RE.search(line)
        refs = _refs_in_expr(line, tainted)
        if not direct and not refs:
            continue
        if _has_safe_redirect_context(lines, idx, refs):
            continue
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> redirect sink"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect sink')
            path_desc = ' -> '.join(seq)
        issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
