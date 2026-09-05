"""ubs_core.go_detectors.hardcoded_secrets — category 9 security (bead 0xjg.6).

Port of run_hardcoded_secret_checks (modules/ubs-golang.sh 5823-6062):
line-oriented literal scanner flagging secret-named targets assigned
plausible credentials. Trigger lines are those whose (comment-stripped)
text is secret-flavored (secret/password/passwd/pwd/token/api[_-]key/
private[_-]key/client[_-]secret/webhook[_-]secret/jwt[_-]secret/
access[_-]token/refresh[_-]token/session[_-]secret/cookie[_-]secret/
signing[_-]secret/encryption[_-]key/credential(s), camel/dash/underscore-
normalized) or that call os.Getenv; the multi-line statement (up to 10
lines, bracket-balanced, comment-stripped) is then matched against
const/var/:= assignments, struct fields, map literals and map key
assignments where the target name is sensitive and the literal is
risky (>=8 chars, alphanumeric, not a known placeholder, no example./
example_|sample_|dummy_ prefix), or against env-default fallbacks
(getenv/getEnv/envOrDefault/envDefault/envFallback/defaultEnv/
mustGetenvDefault with a risky literal, and os.Getenv("SECRET") paired
with cmp.Or/Coalesce/Default and a risky fallback).

Suppression is two-layered (both ported verbatim): a line is skipped
when its own line or the previous line carries ``ubs:ignore``, and a
candidate is dropped when the assembled multi-line statement contains
``ubs:ignore`` (covers markers riding the opening line of a multi-line
statement). A final pass dedupes per (file, line).

Legacy: ``print_finding critical $N "Possible hardcoded secrets" "Use
secret managers or required environment variables; do not keep literal
defaults for secret env vars"``. The rglob/SKIP_DIRS traversal is
replaced by the contract file list; the v2 record count equals the
heredoc's __COUNT__.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MARKER = "ubs:ignore"

RULE_ID = "go.security.hardcoded-secrets"
CATEGORY = 9
TITLE = "Possible hardcoded secrets"
SEVERITY = "critical"
DESCRIPTION = ("Use secret managers or required environment variables; do not "
               "keep literal defaults for secret env vars")

STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|`[^`]*`')
SECRET_WORD_RE = re.compile(
    r'(?:'
    r'\bsecret\b|\bpassword\b|\bpasswd\b|\bpwd\b|\btoken\b|\bapi[_-]?key\b|'
    r'\bprivate[_-]?key\b|\bclient[_-]?secret\b|\bwebhook[_-]?secret\b|'
    r'\bjwt[_-]?secret\b|\baccess[_-]?token\b|\brefresh[_-]?token\b|'
    r'\bsession[_-]?secret\b|\bcookie[_-]?secret\b|\bsigning[_-]?secret\b|'
    r'\bencryption[_-]?key\b|\bcredential(?:s)?\b'
    r')'
)
SECRET_PHRASE_RE = re.compile(
    r'\b(?:'
    r'api\s+key|private\s+key|client\s+secret|webhook\s+secret|jwt\s+secret|'
    r'access\s+token|refresh\s+token|session\s+secret|cookie\s+secret|'
    r'signing\s+secret|encryption\s+key'
    r')\b'
)
PLACEHOLDERS = {
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change_me',
    'not_a_secret', 'your_secret_here', 'your-api-key', 'localhost',
    '127.0.0.1', 'http://localhost', 'https://localhost', 'https://example.com',
}
ASSIGN_RE = re.compile(r'\b(?:const|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+)')
FIELD_RE = re.compile(r'(?:^|[{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)')
MAP_KEY_RE = re.compile(r'(?:^|[{,]\s*)(' + STRING_RE.pattern + r')\s*:\s*(.+)')
MAP_ASSIGN_RE = re.compile(r'\[[^\]]*(' + STRING_RE.pattern + r')[^\]]*\]\s*=\s*(.+)')
ENV_DEFAULT_RE = re.compile(
    r'\b(?:getenv|getEnv|envOrDefault|envDefault|envFallback|defaultEnv|mustGetenvDefault)\s*\(\s*('
    + STRING_RE.pattern + r')\s*,\s*(.+)\)',
)
OS_GETENV_RE = re.compile(r'\bos\.Getenv\s*\(\s*(' + STRING_RE.pattern + r')\s*\)')


def _strip_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ''
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
        if ch in ('"', '`'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            end = line.find('*/', i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _statement_from(lines, start_idx, max_lines=10):
    parts = []
    balance = 0
    for idx in range(start_idx, min(len(lines), start_idx + max_lines)):
        current = _strip_comments(lines[idx]).strip()
        if not current:
            continue
        parts.append(current)
        balance += current.count('(') + current.count('{') - current.count(')') - current.count('}')
        if balance <= 0 and (
            current.endswith(',') or current.endswith('}') or current == ')' or current == '}'
        ):
            break
        if idx == start_idx and balance <= 0 and not current.endswith(('{', '(', ',')):
            break
    return ' '.join(parts)


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def _has_ignore(lines, idx):
    return MARKER in lines[idx] or (idx > 0 and MARKER in lines[idx - 1])


def _normalize_name(name: str) -> str:
    text = str(name or '').strip().strip('"`')
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', text)
    text = re.sub(r'[^A-Za-z0-9]+', '_', text)
    return text.lower().strip('_')


def _is_sensitive_name(name: str) -> bool:
    normalized = _normalize_name(name)
    spaced = normalized.replace('_', ' ')
    return bool(SECRET_WORD_RE.search(normalized) or SECRET_WORD_RE.search(spaced) or SECRET_PHRASE_RE.search(spaced))


def _unquote_literal(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] in ('"', '`') and token[-1] == token[0]:
        return token[1:-1]
    return ''


def _risky_literal(token: str) -> bool:
    value = _unquote_literal(token).strip()
    lowered = value.lower()
    if len(value) < 8:
        return False
    if lowered in PLACEHOLDERS:
        return False
    if 'example.' in lowered or lowered.startswith(('example_', 'sample_', 'dummy_')):
        return False
    return bool(re.search(r'[A-Za-z0-9]', value))


def _first_risky_literal(expr: str) -> str:
    for match in STRING_RE.finditer(expr):
        token = match.group(0)
        if _risky_literal(token):
            return token
    return ''


def _direct_risky_literal(expr: str) -> str:
    match = re.match(r'\s*(' + STRING_RE.pattern + r')', expr)
    if not match:
        return ''
    token = match.group(1)
    return token if _risky_literal(token) else ''


def _assignment_literal(statement: str) -> bool:
    for regex in (ASSIGN_RE, FIELD_RE):
        for match in regex.finditer(statement):
            if _is_sensitive_name(match.group(1)) and _direct_risky_literal(match.group(2)):
                return True
    for match in MAP_KEY_RE.finditer(statement):
        if _is_sensitive_name(_unquote_literal(match.group(1))) and _direct_risky_literal(match.group(2)):
            return True
    for match in MAP_ASSIGN_RE.finditer(statement):
        if _is_sensitive_name(_unquote_literal(match.group(1))) and _direct_risky_literal(match.group(2)):
            return True
    return False


def _env_default_literal(statement: str) -> bool:
    for match in ENV_DEFAULT_RE.finditer(statement):
        if _is_sensitive_name(_unquote_literal(match.group(1))) and _first_risky_literal(match.group(2)):
            return True
    env_match = OS_GETENV_RE.search(statement)
    if not env_match or not _is_sensitive_name(_unquote_literal(env_match.group(1))):
        return False
    suffix = statement[env_match.end():]
    return bool(('cmp.Or' in statement or 'Coalesce' in statement or 'Default' in statement) and _first_risky_literal(suffix))


def _analyze(path: Path, issues: list) -> None:
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    for idx, line in enumerate(lines):
        stripped = _strip_comments(line).strip()
        if not stripped or _has_ignore(lines, idx):
            continue
        if not (_is_sensitive_name(stripped) or OS_GETENV_RE.search(stripped)):
            continue
        statement = _statement_from(lines, idx)
        if not statement or MARKER in statement:
            continue
        if _assignment_literal(statement) or _env_default_literal(statement):
            issues.append((path, idx + 1, 1, _source_line(lines, idx + 1)))


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    issues: list[tuple[Path, int, int, str]] = []
    for path in files:
        if path.suffix != ".go":
            continue
        _analyze(path, issues)
    deduped: list[tuple[Path, int, int, str]] = []
    seen = set()
    for item in issues:
        key = item[:2]
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    yield from deduped
