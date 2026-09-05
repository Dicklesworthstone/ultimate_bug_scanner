"""ubs_core.go_detectors.cors_credentials — cat 9 CORS credential policy (bead 0xjg.6).

Port of run_cors_credentials_checks (modules/ubs-golang.sh 6936-7173):
the python3 heredoc flags CORS contexts that combine
Access-Control-Allow-Credentials/AllowCredentials with a wildcard origin
(`*` in Allow-Origin headers or AllowedOrigins/AllowOrigins lists) or a
reflected request Origin (directly or via a local assigned from
Header.Get("Origin")/GetHeader("Origin"), including AllowOriginFunc
returning true). Findings closer than 4 lines apart are collapsed.
Legacy outcome:

    print_finding critical <count> "Credentialed wildcard/reflected CORS" ...

Marker suppression is ported verbatim: `ubs:ignore` on the finding line
or on the previous line suppresses it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.cors-credentials"
CATEGORY = 9
TITLE = "Credentialed wildcard/reflected CORS"
SEVERITY = "critical"
DESCRIPTION = "Echo origins only against an allow-list and never combine AllowCredentials with wildcard origins"
MARKER = "ubs:ignore"

ORIGIN_WILDCARD_RE = re.compile(
    r'\bAccess-Control-Allow-Origin\b["`]\s*,\s*["`]\*["`]'
    r'|\b(?:AllowedOrigins|AllowOrigins)\s*:\s*\[\]string\s*\{[^}]*["`]\*["`]'
    r'|\b(?:handlers\.)?AllowedOrigins\s*\(\s*\[\]string\s*\{[^}]*["`]\*["`]',
    re.IGNORECASE,
)
ORIGIN_REFLECTION_RE = re.compile(
    r'\bAccess-Control-Allow-Origin\b["`]\s*,\s*(?:'
    r'(?:r|req|request)\.Header\.Get\s*\(\s*["`]Origin["`]\s*\)|'
    r'(?:c|ctx|context)\.(?:GetHeader|Request\(\)\.Header\.Get)\s*\(\s*["`]Origin["`]\s*\))'
    r'|\bAllowOriginFunc\s*:\s*func\s*\([^)]*\)\s*bool\s*\{[^}]*return\s+true\b',
    re.IGNORECASE,
)
ORIGIN_SOURCE_RE = re.compile(
    r'\b(?:r|req|request)\.Header\.Get\s*\(\s*["`]Origin["`]\s*\)'
    r'|\b(?:c|ctx|context)\.(?:GetHeader|Request\(\)\.Header\.Get)\s*\(\s*["`]Origin["`]\s*\)',
    re.IGNORECASE,
)
CREDENTIALS_TRUE_RE = re.compile(
    r'\bAccess-Control-Allow-Credentials\b["`]\s*,\s*(?:true|["`]true["`])'
    r'|\bAllowCredentials\s*:\s*true\b'
    r'|\b(?:handlers\.)?AllowCredentials\s*\(',
    re.IGNORECASE,
)
CANDIDATE_RE = re.compile(
    r'Access-Control-Allow-(?:Origin|Credentials)|AllowedOrigins|AllowOrigins|AllowOriginFunc|AllowCredentials|AllowedOrigins\s*\(',
    re.IGNORECASE,
)
IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')


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


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def _context_around(lines, line_no, before=8, after=18):
    idx = line_no - 1
    start = idx
    blank_gap = 0
    while start > 0 and idx - start < before:
        previous = _strip_line_comments(lines[start - 1]).strip()
        if not previous:
            blank_gap += 1
            if blank_gap > 2:
                break
            start -= 1
            continue
        if previous.startswith(('const ', 'func ', 'type ', 'var ')) and start - 1 != idx:
            break
        blank_gap = 0
        start -= 1
    end = idx
    blank_gap = 0
    while end + 1 < len(lines) and end - idx < after:
        following = _strip_line_comments(lines[end + 1]).strip()
        if not following:
            blank_gap += 1
            if blank_gap > 2:
                break
            end += 1
            continue
        if following.startswith(('const ', 'func ', 'type ', 'var ')):
            break
        blank_gap = 0
        end += 1
    parts = []
    for current in range(start, end + 1):
        stripped = _strip_line_comments(lines[current]).strip()
        if stripped:
            parts.append(stripped)
    return ' '.join(parts)


def _lhs_names(lhs):
    names = []
    for part in lhs.split(','):
        name = part.strip()
        if name and name != '_' and IDENT_RE.fullmatch(name):
            names.append(name)
    return names


def _context_origin_ref_vars(context):
    refs = set()
    for assign in re.finditer(r'(?:^|[;{}])\s*(?:var\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*)\s*(?::=|=)\s*(?P<rhs>[^;{}]+)', context):
        if not assign or not ORIGIN_SOURCE_RE.search(assign.group('rhs')):
            continue
        for name in _lhs_names(assign.group('lhs')):
            refs.add(name)
    return refs


def _has_reflected_origin(context, refs):
    if ORIGIN_REFLECTION_RE.search(context):
        return True
    for name in refs:
        if re.search(rf'\bAccess-Control-Allow-Origin\b["`]\s*,\s*{re.escape(name)}\b', context, re.IGNORECASE):
            return True
    return False


def _analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not CANDIDATE_RE.search(text):
        return
    lines = text.splitlines()
    seen = set()
    last_issue = -100
    for idx, raw in enumerate(lines, start=1):
        if _has_ignore(lines, idx):
            continue
        stripped = _strip_line_comments(raw).strip()
        if not stripped or not CANDIDATE_RE.search(stripped):
            continue
        context = _context_around(lines, idx)
        refs = _context_origin_ref_vars(context)
        if not CREDENTIALS_TRUE_RE.search(context):
            continue
        if not (ORIGIN_WILDCARD_RE.search(context) or _has_reflected_origin(context, refs)):
            continue
        if idx - last_issue <= 3:
            continue
        if idx in seen:
            continue
        seen.add(idx)
        last_issue = idx
        issues.append((idx, _source_line(lines, idx)))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix != ".go":
            continue
        issues = []
        _analyze_file(path, issues)
        for line_no, detail in issues:
            yield (path, line_no, 1, detail)
