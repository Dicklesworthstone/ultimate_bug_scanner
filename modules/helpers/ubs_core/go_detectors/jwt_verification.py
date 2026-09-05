"""ubs_core.go_detectors.jwt_verification — cat 9 JWT verification bypass (bead 0xjg.6).

Port of run_jwt_verification_checks (modules/ubs-golang.sh 6416-6671):
the python3 heredoc flags Parse/ParseWithClaims/ParseUnverified calls,
SigningMethodNone, and WithoutClaimsValidation on the jwt import aliases
and NewParser-derived receivers, unless the surrounding function validates
the signing method (jwt.WithValidMethods / token.Method vs SigningMethod*)
and binds both issuer and audience. Legacy outcome:

    print_finding critical <count> "JWT parse/decode verification bypass risk" ...

Marker suppression is ported verbatim: `ubs:ignore` on the finding line,
on the previous line, or anywhere in the joined statement suppresses it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "go.security.jwt-verification"
CATEGORY = 9
TITLE = "JWT parse/decode verification bypass risk"
SEVERITY = "critical"
DESCRIPTION = "Validate signing methods against an allow-list and bind issuer/audience before trusting JWT claims"
MARKER = "ubs:ignore"

JWT_IMPORT_RE = re.compile(
    r'^\s*(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s+|[._]\s+)?'
    r'"github\.com/(?:golang-jwt/jwt(?:/v\d+)?|dgrijalva/jwt-go)"'
)
PARSER_ASSIGN_TEMPLATE = r'\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(?:{prefix})\.NewParser\s*\('
SAFE_METHOD_RE = re.compile(
    r'\bWithValidMethods\s*\(|\bValidMethods\b|'
    r'(?:\b[A-Za-z_][A-Za-z0-9_]*\.Method\b|\.Method\b).*?'
    r'(?:\bSigningMethod[A-Za-z0-9_]*\b|\bAlg\s*\()|'
    r'(?:\bSigningMethod[A-Za-z0-9_]*\b|\bAlg\s*\().*?'
    r'(?:\b[A-Za-z_][A-Za-z0-9_]*\.Method\b|\.Method\b)',
    re.DOTALL,
)
ISSUER_BINDING_RE = re.compile(
    r'\bWithIssuer\s*\(|\bVerifyIssuer\s*\(|'
    r'\b(?:Issuer|issuer|iss)\b\s*(?:==|!=)|'
    r'\[\s*["\']iss["\']\s*\]',
    re.DOTALL,
)
AUDIENCE_BINDING_RE = re.compile(
    r'\bWithAudience\s*\(|\bVerifyAudience\s*\(|'
    r'\b(?:Audience|audience|aud)\b\s*(?:==|!=)|'
    r'\[\s*["\']aud["\']\s*\]',
    re.DOTALL,
)
QUICK_REJECT_RE = re.compile(r'jwt|ParseUnverified|SigningMethodNone|WithoutClaimsValidation')
LINE_TRIGGER_RE = re.compile(
    r'Parse(?:WithClaims|Unverified)?\s*\(|SigningMethodNone\b|\bWithoutClaimsValidation\s*\('
)


def _strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    idx = 0
    while idx < len(line):
        ch = line[idx]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            idx += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            idx += 1
            continue
        if ch == '/' and idx + 1 < len(line):
            nxt = line[idx + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', idx + 2)
                if end == -1:
                    break
                idx = end + 2
                continue
        out.append(ch)
        idx += 1
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


def _statement_from(lines, line_no, max_lines=12):
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


def _function_context(lines, line_no, max_lines=180):
    start = line_no - 1
    while start > 0 and not re.match(r'^\s*func\b', _strip_line_comments(lines[start])):
        start -= 1
    if not re.match(r'^\s*func\b', _strip_line_comments(lines[start])):
        return _statement_from(lines, line_no, max_lines=24)
    parts = []
    balance = 0
    saw_open = False
    for idx in range(start, min(len(lines), start + max_lines)):
        current = _strip_line_comments(lines[idx])
        parts.append(current.strip())
        balance += current.count('{') - current.count('}')
        if '{' in current:
            saw_open = True
        if saw_open and idx > start and balance <= 0:
            break
    return ' '.join(part for part in parts if part)


def _collect_jwt_names(lines):
    names = {'jwt'}
    for raw in lines:
        match = JWT_IMPORT_RE.match(_strip_line_comments(raw).strip())
        if not match:
            continue
        alias = match.group('alias')
        if alias:
            names.add(alias)
        else:
            names.add('jwt')
    return names


def _collect_parser_names(lines, jwt_names):
    names = set()
    prefix = '|'.join(re.escape(name) for name in sorted(jwt_names))
    if not prefix:
        return names
    parser_assign_re = re.compile(PARSER_ASSIGN_TEMPLATE.format(prefix=prefix))
    for raw in lines:
        match = parser_assign_re.search(_strip_line_comments(raw))
        if match:
            names.add(match.group('name'))
    return names


def _prefixed_call_re(names, methods):
    prefix = '|'.join(re.escape(name) for name in sorted(names))
    method = '|'.join(re.escape(name) for name in methods)
    if not prefix:
        return re.compile(r'$.')
    return re.compile(rf'\b(?:{prefix})\.(?:{method})\s*\(')


def _analyze_file(path):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    if not QUICK_REJECT_RE.search(text):
        return []
    lines = text.splitlines()
    jwt_names = _collect_jwt_names(lines)
    parser_names = _collect_parser_names(lines, jwt_names)
    all_receivers = jwt_names | parser_names
    parse_re = _prefixed_call_re(all_receivers, ('Parse', 'ParseWithClaims'))
    unverified_re = _prefixed_call_re(all_receivers, ('ParseUnverified',))
    issues = []
    seen = set()
    for line_no, raw in enumerate(lines, start=1):
        if _has_ignore(lines, line_no):
            continue
        stripped = _strip_line_comments(raw).strip()
        if not stripped:
            continue
        if not LINE_TRIGGER_RE.search(stripped):
            continue
        statement = _statement_from(lines, line_no)
        if not statement or MARKER in statement:
            continue
        reason = ''
        if unverified_re.search(statement) or re.search(r'\bParseUnverified\s*\(', statement):
            reason = 'decode-only'
        elif re.search(r'\bSigningMethodNone\b', statement):
            reason = 'none-alg'
        elif re.search(r'\bWithoutClaimsValidation\s*\(', statement):
            reason = 'claims-disabled'
        elif parse_re.search(statement):
            context = _function_context(lines, line_no)
            if not SAFE_METHOD_RE.search(context):
                reason = 'method-unvalidated'
            elif not (ISSUER_BINDING_RE.search(context) and AUDIENCE_BINDING_RE.search(context)):
                reason = 'claims-unbound'
        if not reason:
            continue
        if line_no in seen:
            continue
        seen.add(line_no)
        issues.append((line_no, _source_line(lines, line_no)))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix != ".go":
            continue
        for line_no, detail in _analyze_file(path):
            yield (path, line_no, 1, detail)
