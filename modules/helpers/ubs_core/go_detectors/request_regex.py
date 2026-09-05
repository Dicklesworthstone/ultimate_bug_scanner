"""ubs_core.go_detectors.request_regex — cat 9 request-controlled regex (bead 0xjg.6).

Port of run_request_regex_checks (modules/ubs-golang.sh 7175-7425):
the python3 heredoc tracks request-derived values (URL query/form values,
headers, chi.URLParam/mux.Vars, gin/echo-style c.Param/c.Query accessors)
through local assignments with a bounded taint path (PATH_LIMIT=4) and
flags regexp.Compile/MustCompile/MatchString/Match sinks whose first
argument is tainted, unless the expression goes through
regexp.QuoteMeta or an allow-list/escape helper. The detail column
carries the legacy taint path suffix, e.g.
`return regexp.Compile(pattern)  [r.URL.Query().Get -> regex engine]`.
Legacy outcome:

    print_finding warning <count> "Request-controlled regex pattern reaches regex engine" ...

Marker suppression is ported verbatim: `ubs:ignore` on the finding line
or on the previous line suppresses it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.request-regex"
CATEGORY = 9
TITLE = "Request-controlled regex pattern reaches regex engine"
SEVERITY = "warning"
DESCRIPTION = "Escape with regexp.QuoteMeta or match against an allow-list before compiling/matching request-derived patterns"
MARKER = "ubs:ignore"

SOURCE_RE = re.compile(
    r'\br\.URL\.Query\(\)\.Get\s*\('
    r'|\br\.(?:FormValue|PostFormValue|PathValue)\s*\('
    r'|\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\('
    r'|\b(?:r|req|request)\.Header\s*\['
    r'|\b(?:chi\.URLParam|mux\.Vars)\s*\('
    r'|\b(?:c|ctx|context)\.(?:Param|Query|QueryParam|FormValue|PostForm|GetHeader)\s*\('
    r'|\b(?:c|ctx|context)\.Request\(\)\.Header\.(?:Get|Values)\s*\(',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bregexp\.(?:Compile|CompilePOSIX|MustCompile|MustCompilePOSIX|MatchString|Match)\s*\('
)
SAFE_RE = re.compile(
    r'\bregexp\.QuoteMeta\s*\('
    r'|\b(?:escapeRegex|escapeRegexp|sanitizeRegex|sanitizeRegexp|safeRegex|safeRegexp|'
    r'validateRegex|validateRegexp|allowedRegex|allowedRegexp|isSafeRegex|isAllowedRegex)[A-Za-z0-9_]*\s*\('
    r'|\b(?:allowed|Allowed|ALLOWED)[A-Za-z0-9_]*\s*\['
    r'|\b(?:allowed|Allowed|ALLOWED)[A-Za-z0-9_]*\.(?:Contains|Has|Lookup)\s*\(',
    re.IGNORECASE,
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


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def _lhs_names(lhs):
    names = []
    for part in lhs.split(','):
        name = part.strip()
        if name and name != '_' and IDENT_RE.fullmatch(name):
            names.append(name)
    return names


def _refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def _taint_from_expr(expr, tainted):
    if SAFE_RE.search(expr):
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


def _first_arg(statement):
    match = SINK_RE.search(statement)
    if not match:
        return ''
    start = match.end()
    depth = 1
    quote = ''
    escape = False
    for pos in range(start, len(statement)):
        ch = statement[pos]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return statement[start:pos].split(',', 1)[0].strip()
        elif ch == ',' and depth == 1:
            return statement[start:pos].strip()
    return ''


def _analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, raw in enumerate(lines, start=1):
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
            elif SAFE_RE.search(rhs):
                for name in names:
                    tainted.pop(name, None)
        if not SINK_RE.search(line):
            continue
        arg = _first_arg(line)
        if not arg or SAFE_RE.search(arg):
            continue
        direct = SOURCE_RE.search(arg)
        refs = _refs_in_expr(arg, tainted)
        if not direct and not refs:
            continue
        if idx in seen:
            continue
        seen.add(idx)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> regex engine"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('regex engine')
            path_desc = ' -> '.join(seq)
        issues.append((idx, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix != ".go":
            continue
        issues = []
        _analyze_file(path, issues)
        for line_no, detail in issues:
            yield (path, line_no, 1, detail)
