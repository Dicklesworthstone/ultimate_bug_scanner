"""ubs_core.go_detectors.host_header — category 9 security (bead 0xjg.6).

Port of run_host_header_url_checks (modules/ubs-golang.sh 2242-2502): a
line-oriented taint tracker that propagates request-derived host values
(r.Host, r.Header.Get/Values/[...] of Host/X-Forwarded-Host/Forwarded/
X-Original-Host, gin/echo-style c.GetHeader and c.Request() variants)
through ``var``-aware :=/= assignments (chained up to PATH_LIMIT hops)
and flags absolute-URL construction sinks (string-literal or fmt.Sprintf
"https?:// prefixes, and url.URL{...} composites with a Scheme literal
plus a Host: field) reached by a tainted name or a direct source.

A statement is suppressed when it names a host sanitizer/allow-list
(safe/secure/trusted/canonical/validated/allowed*Host|Origin|URL*,
validate/assert/ensure/check*Host…, is/has*Allowed|Trusted|Safe*,
allowedHosts/trustedHosts/hostAllowlist/… slices, slices.Contains), or
when the preceding 18 lines mention the tainted name through such a safe
helper together with a blocking action (return/http.Error/errors.New/
fmt.Errorf). Encountering a ``func`` line resets the taint map (but a
func signature line that is itself a direct hit still reports).

Legacy: ``print_finding critical $N "Request Host header used to build
absolute URL" "Use a configured canonical origin or validate Host/
X-Forwarded-Host against an explicit allow-list before generating
links"``. Same-file and previous-line ``ubs:ignore`` markers suppress a
hit; per-(file, line) dedupe is preserved. The legacy rglob/SKIP_DIRS
traversal is replaced by the contract file list; the v2 record count
equals the heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

RULE_ID = "go.security.host-header"
CATEGORY = 9
TITLE = "Request Host header used to build absolute URL"
SEVERITY = "critical"
DESCRIPTION = ("Build absolute URLs from a configured canonical origin or "
               "validate Host/X-Forwarded-Host against an allow-list")

HOST_SOURCE_RE = re.compile(
    r'\b(?:r|req|request)\.Host\b'
    r'|\b(?:r|req|request)\.Header\.(?:Get|Values)\s*\(\s*["`](?:Host|X-Forwarded-Host|Forwarded|X-Original-Host)["`]\s*\)'
    r'|\b(?:r|req|request)\.Header\s*\[\s*["`](?:Host|X-Forwarded-Host|Forwarded|X-Original-Host)["`]\s*\]'
    r'|\b(?:c|ctx|context)\.GetHeader\s*\(\s*["`](?:Host|X-Forwarded-Host|Forwarded|X-Original-Host)["`]\s*\)'
    r'|\b(?:c|ctx|context)\.Request\(\)\.Host\b'
    r'|\b(?:c|ctx|context)\.Request\(\)\.Header\.(?:Get|Values)\s*\(\s*["`](?:Host|X-Forwarded-Host|Forwarded|X-Original-Host)["`]\s*\)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe|secure|trusted|canonical|validated|allowed)[A-Za-z0-9_]*(?:Host|Origin|URL|URLString|BaseURL|LinkOrigin)[A-Za-z0-9_]*\s*\('
    r'|\b(?:validate|assert|ensure|require|check)[A-Za-z0-9_]*(?:Host|Origin|URL|BaseURL|Canonical|Allowed|Trusted)[A-Za-z0-9_]*\s*\('
    r'|\b(?:is|has)[A-Za-z0-9_]*(?:Allowed|Trusted|Safe)[A-Za-z0-9_]*(?:Host|Origin|URL)?[A-Za-z0-9_]*\s*\('
    r'|\b(?:allowedHosts|trustedHosts|hostAllowlist|originAllowlist|allowedOrigins|trustedOrigins)\b'
    r'|\bslices\.Contains\s*\(',
    re.IGNORECASE,
)
ABSOLUTE_URL_RE = re.compile(r'["`]https?://|\bfmt\.Sprintf\s*\(\s*["`]https?://', re.IGNORECASE)
URL_STRUCT_RE = re.compile(r'\b(?:url\.)?URL\s*\{')
ASSIGN_RE = re.compile(r'^\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>.+)$')
FUNC_RE = re.compile(r'^\s*func\b')
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
    balance = (
        statement.count('(') - statement.count(')')
        + statement.count('{') - statement.count('}')
    )
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 12:
        next_line = _strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += (
            next_line.count('(') - next_line.count(')')
            + next_line.count('{') - next_line.count('}')
        )
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


def _is_absolute_url_construction(expr):
    if ABSOLUTE_URL_RE.search(expr):
        return True
    return bool(
        URL_STRUCT_RE.search(expr)
        and re.search(r'\bScheme\s*:\s*["`](?:http|https)["`]', expr, re.IGNORECASE)
        and re.search(r'\bHost\s*:', expr)
    )


def _taint_from_expr(expr, tainted):
    if _is_safe_expr(expr):
        return None
    direct = HOST_SOURCE_RE.search(expr)
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
    start = max(0, line_no - 18)
    context_lines = [_strip_line_comments(line) for line in lines[start:line_no]]
    context = '\n'.join(context_lines)
    ref_context_lines = [
        line
        for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if not ref_context_lines:
        return False
    return bool(
        any(SAFE_EXPR_RE.search(line) for line in ref_context_lines)
        and re.search(r'\b(?:return|http\.Error|errors\.New|fmt\.Errorf)\b', context)
    )


def _analyze(path: Path, issues: list) -> None:
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not HOST_SOURCE_RE.search(text):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if _has_ignore(lines, idx):
            continue
        raw_line = _strip_line_comments(lines[idx - 1]).strip()
        if FUNC_RE.search(raw_line):
            tainted = {}
            if not (HOST_SOURCE_RE.search(raw_line) and _is_absolute_url_construction(raw_line)):
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

        direct = HOST_SOURCE_RE.search(line)
        refs = _refs_in_expr(line, tainted)
        if not direct and not refs:
            continue
        if not _is_absolute_url_construction(line):
            continue
        if _is_safe_expr(line) or _has_allowlist_context(lines, idx, refs):
            continue
        key = (path, idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> absolute URL"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('absolute URL')
            path_desc = ' -> '.join(seq)
        issues.append((path, idx, 1, f"{_source_line(lines, idx)}  [{path_desc}]"))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    yield from issues
