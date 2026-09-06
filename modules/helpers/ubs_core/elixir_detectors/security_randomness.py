"""ubs_core.elixir_detectors.security_randomness — category 4 security (bead 0xjg.13).

Verbatim port of run_security_randomness_checks (modules/ubs-elixir.sh
1771-1989): non-cryptographic randomness (:rand/:random, Enum.random/take_
random/shuffle, System.unique_integer, :erlang.unique_integer/monotonic_time/
system_time/phash2) assigned to security-named variables or sunk into
session/cookie/encoding calls, skipping continuation lines and requiring a
security name in the variable, statement, or enclosing function context.
Same-file and previous-line `ubs:ignore` markers suppress a hit.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.elixir_detectors._common import (
    EXTS,
    elixir_files,
    has_ignore,
    read_lines,
    source_line,
    strip_line_comments,
)

RULE_ID = "ex.randomness.security-token"
CATEGORY = 4
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = (
    "Use :crypto.strong_rand_bytes/1 plus Base.url_encode64/2, or a "
    "framework helper built on cryptographic randomness, for tokens, "
    "sessions, CSRF values, OTPs, salts, and API keys."
)

VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
SECURITY_NAME_RE = re.compile(
    r'(?:token|secret|password|passwd|pwd|session|cookie|csrf|xsrf|otp|totp|mfa|'
    r'nonce|salt|api[_-]?key|access[_-]?key|private[_-]?key|public[_-]?key|'
    r'\bkey\b|auth|bearer|credential|reset|invite|verification|confirm|'
    r'magic[_-]?link|recovery|signature|\bsig\b)',
    re.IGNORECASE,
)
UNSAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:rand|random)\.(?:uniform(?:_s)?|bytes|seed|seed_s)\b|'
    r'\bEnum\.(?:random|take_random|shuffle)\s*\(|'
    r'\bSystem\.unique_integer\s*\(|'
    r'\b:erlang\.(?:unique_integer|monotonic_time|system_time|phash2)\s*\(',
    re.IGNORECASE,
)
SAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_]):crypto\.strong_rand_bytes\s*\(|'
    r'\b(?:safe_token|secure_token|secure_random|crypto_random|'
    r'generate_secure_token|Phoenix\.Token\.sign|Plug\.Crypto)\b',
    re.IGNORECASE,
)
SECURITY_SINK_RE = re.compile(
    r'\b(?:put_session|configure_session|put_resp_cookie|put_private|assign)\s*\([^#\n]*(?:token|session|csrf|xsrf|otp|nonce|salt|api[_-]?key|secret|auth|credential)|'
    r'\b(?:Base\.encode(?:16|32|64)!?|Integer\.to_string|to_string)\s*\(',
    re.IGNORECASE,
)


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 8:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 8:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement


def is_continuation_line(lines, line_no):
    idx = line_no - 2
    while idx >= 0:
        previous = strip_line_comments(lines[idx]).strip()
        if not previous:
            idx -= 1
            continue
        return previous.endswith(('=', '|>', ',', '->'))
    return False


def function_context(lines, line_no):
    start = max(0, line_no - 14)
    for line in reversed(lines[start:line_no]):
        clean = strip_line_comments(line)
        if re.search(r'\bdefp?\s+[A-Za-z_][A-Za-z0-9_?!]*', clean):
            return clean
    return ''


def is_security_context(statement: str, variable: str, lines, line_no) -> bool:
    if variable and SECURITY_NAME_RE.search(variable):
        return True
    if SECURITY_NAME_RE.search(statement):
        return True
    return bool(SECURITY_NAME_RE.search(function_context(lines, line_no)))


def scan_file_findings(path: Path) -> Iterable[tuple[int, int, str]]:
    lines = read_lines(path)
    if lines is None:
        return
    text = "\n".join(lines)
    if not UNSAFE_RANDOM_RE.search(text):
        return
    seen: set[int] = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        if is_continuation_line(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement or not UNSAFE_RANDOM_RE.search(statement):
            continue
        if SAFE_RANDOM_RE.search(statement):
            continue
        assignment = ASSIGN_RE.search(statement)
        variable = assignment.group(1) if assignment else ''
        security_context = is_security_context(statement, variable, lines, idx)
        if not security_context:
            continue
        if not (assignment or SECURITY_SINK_RE.search(statement) or SECURITY_NAME_RE.search(statement) or security_context):
            continue
        if idx in seen:
            continue
        seen.add(idx)
        yield idx, 1, source_line(lines, idx)


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in elixir_files(files, EXTS):
        for line_no, col, code in scan_file_findings(path):
            yield str(path), line_no, col, code
