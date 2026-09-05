"""ubs_core.go_detectors.cookie_security — cat 9 auth/session cookie settings (bead 0xjg.6).

Port of run_cookie_security_checks (modules/ubs-golang.sh 6673-6934):
the python3 heredoc inspects http.Cookie struct literals, raw
`Header().Set/Add("Set-Cookie", ...)` writes, and framework
`.SetCookie(...)` calls touching session/auth/token-named cookies, and
flags missing HttpOnly/Secure/SameSite flags plus SameSite=None without
Secure. Legacy outcome:

    print_finding warning <count> "Insecure auth/session cookie settings" ...

Marker suppression is ported verbatim: `ubs:ignore` on the finding line,
on the previous line, or anywhere in the joined statement suppresses it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.cookie-security"
CATEGORY = 9
TITLE = "Insecure auth/session cookie settings"
SEVERITY = "warning"
DESCRIPTION = "Set auth cookies with HttpOnly, Secure, and SameSite protections; SameSite=None must also use Secure"
MARKER = "ubs:ignore"

SENSITIVE_COOKIE_RE = re.compile(r'["`][^"`]*(?:session|sess|sid|auth|token|jwt|refresh|access|remember|login)[^"`]*["`]', re.IGNORECASE)
COOKIE_CANDIDATE_RE = re.compile(r'\bhttp\.SetCookie\s*\(|\bhttp\.Cookie\s*\{|\bSet-Cookie\b|\.\s*SetCookie\s*\(', re.IGNORECASE)
RAW_SET_COOKIE_RE = re.compile(r'\b(?:Header\(\)\.)?(?:Set|Add)\s*\(\s*["`]Set-Cookie["`]\s*,', re.IGNORECASE)
HTTP_SET_COOKIE_RE = re.compile(r'\bhttp\.SetCookie\s*\(', re.IGNORECASE)
HTTP_COOKIE_STRUCT_RE = re.compile(r'\bhttp\.Cookie\s*\{', re.IGNORECASE)
FRAMEWORK_SET_COOKIE_RE = re.compile(r'\.\s*SetCookie\s*\(', re.IGNORECASE)
HTTP_ONLY_TRUE_RE = re.compile(r'\bHttpOnly\s*:\s*true\b')
HTTP_ONLY_FALSE_RE = re.compile(r'\bHttpOnly\s*:\s*false\b')
SECURE_TRUE_RE = re.compile(r'\bSecure\s*:\s*true\b')
SECURE_FALSE_RE = re.compile(r'\bSecure\s*:\s*false\b')
SAMESITE_RE = re.compile(r'\bSameSite\s*:\s*(?:http\.)?SameSite(?:Default|Lax|Strict|None)Mode\b')
SAMESITE_NONE_RE = re.compile(r'\bSameSite\s*:\s*(?:http\.)?SameSiteNoneMode\b')
RAW_HTTP_ONLY_RE = re.compile(r'\bHttpOnly\b', re.IGNORECASE)
RAW_SECURE_RE = re.compile(r'(?:^|[;,\s])Secure(?:[;,\s]|$)', re.IGNORECASE)
RAW_SAMESITE_RE = re.compile(r'\bSameSite\s*=', re.IGNORECASE)
RAW_SAMESITE_NONE_RE = re.compile(r'\bSameSite\s*=\s*None\b', re.IGNORECASE)


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


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def _statement_from(lines, line_no, max_lines=18):
    idx = line_no - 1
    parts = []
    balance = 0
    for current_idx in range(idx, min(len(lines), idx + max_lines)):
        current = _strip_line_comments(lines[current_idx]).strip()
        if not current:
            if parts and balance <= 0:
                break
            continue
        parts.append(current)
        balance += current.count('(') + current.count('{') - current.count(')') - current.count('}')
        if current_idx > idx and balance <= 0:
            break
        if current_idx == idx and balance <= 0 and not current.endswith(('{', '(', ',')):
            break
    return ' '.join(parts)


def _split_args(arg_text: str):
    args = []
    current = []
    quote = ''
    escape = False
    depth = 0
    for ch in arg_text:
        if quote:
            current.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            current.append(ch)
            continue
        if ch in '({[':
            depth += 1
            current.append(ch)
            continue
        if ch in ')}]':
            depth = max(0, depth - 1)
            current.append(ch)
            continue
        if ch == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        args.append(''.join(current).strip())
    return args


def _call_args(statement: str, marker_re):
    match = marker_re.search(statement)
    if not match:
        return []
    start = statement.find('(', match.start())
    if start == -1:
        return []
    depth = 0
    quote = ''
    escape = False
    for idx in range(start, len(statement)):
        ch = statement[idx]
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
                return _split_args(statement[start + 1:idx])
    return []


def _sensitive_cookie(statement: str) -> bool:
    return bool(SENSITIVE_COOKIE_RE.search(statement))


def _insecure_http_cookie_struct(statement: str) -> bool:
    if not HTTP_COOKIE_STRUCT_RE.search(statement) or not _sensitive_cookie(statement):
        return False
    explicit_insecure = HTTP_ONLY_FALSE_RE.search(statement) or SECURE_FALSE_RE.search(statement)
    missing_required_flags = not HTTP_ONLY_TRUE_RE.search(statement) or not SECURE_TRUE_RE.search(statement) or not SAMESITE_RE.search(statement)
    none_without_secure = SAMESITE_NONE_RE.search(statement) and not SECURE_TRUE_RE.search(statement)
    return bool(explicit_insecure or missing_required_flags or none_without_secure)


def _insecure_raw_set_cookie(statement: str) -> bool:
    if not RAW_SET_COOKIE_RE.search(statement) or not _sensitive_cookie(statement):
        return False
    missing_flags = not RAW_HTTP_ONLY_RE.search(statement) or not RAW_SECURE_RE.search(statement) or not RAW_SAMESITE_RE.search(statement)
    none_without_secure = RAW_SAMESITE_NONE_RE.search(statement) and not RAW_SECURE_RE.search(statement)
    return bool(missing_flags or none_without_secure)


def _insecure_framework_set_cookie(statement: str) -> bool:
    if not FRAMEWORK_SET_COOKIE_RE.search(statement) or HTTP_SET_COOKIE_RE.search(statement) or not _sensitive_cookie(statement):
        return False
    args = _call_args(statement, FRAMEWORK_SET_COOKIE_RE)
    if len(args) >= 7:
        secure_arg = args[-2].strip().lower()
        http_only_arg = args[-1].strip().lower()
        return secure_arg != 'true' or http_only_arg != 'true'
    return False


def _insecure_cookie_statement(statement: str) -> bool:
    return (
        _insecure_http_cookie_struct(statement)
        or _insecure_raw_set_cookie(statement)
        or _insecure_framework_set_cookie(statement)
    )


def _analyze_file(path):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if not COOKIE_CANDIDATE_RE.search(text):
        return []
    lines = text.splitlines()
    issues = []
    seen = set()
    for idx, raw in enumerate(lines, start=1):
        if _has_ignore(lines, idx):
            continue
        stripped = _strip_line_comments(raw).strip()
        if not stripped or not COOKIE_CANDIDATE_RE.search(stripped):
            continue
        statement = _statement_from(lines, idx)
        if not statement or MARKER in statement:
            continue
        if not _insecure_cookie_statement(statement):
            continue
        if idx in seen:
            continue
        seen.add(idx)
        issues.append((idx, _source_line(lines, idx)))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix != ".go":
            continue
        for line_no, detail in _analyze_file(path):
            yield (path, line_no, 1, detail)
