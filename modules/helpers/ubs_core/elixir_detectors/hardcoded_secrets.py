"""ubs_core.elixir_detectors.hardcoded_secrets — category 4 security (bead 0xjg.13).

Verbatim port of run_hardcoded_secret_checks (modules/ubs-elixir.sh
1991-2180): secret-keyed assignments, module attributes and config stanzas
with literal values (>= 8 chars, not low-value placeholders), plus
System.get_env literal fallbacks whose env name looks secret-keyed. Test
trees (a /test/ path segment, *_test.exs, config/test.exs) are skipped like
the heredoc's should_skip. Same-file and previous-line `ubs:ignore` markers
suppress a hit.
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
)

RULE_ID = "ex.secrets.hardcoded"
CATEGORY = 4
TITLE = "Hardcoded secrets/tokens in source"
SEVERITY = "critical"
DESCRIPTION = (
    "Use runtime environment variables, secret stores, or release-time "
    "config for Phoenix secret_key_base, signing salts, JWT/API secrets, "
    "and token keys."
)

SECRET_KEY_RE = re.compile(
    r'(?:secret[_-]?key[_-]?base|signing[_-]?salt|encryption[_-]?salt|guardian[_-]?secret|'
    r'joken[_-]?secret|jwt[_-]?secret|client[_-]?secret|webhook[_-]?secret|api[_-]?key|'
    r'private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?secret|cookie[_-]?secret|'
    r'(?:^|[_-])secret(?:$|[_-])|password|passwd|pwd|token|credential)',
    re.IGNORECASE,
)
ASSIGNMENT_SECRET_RE = re.compile(
    r'(?P<key>@?[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s*'
    r'(?::|=>|=)\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
MODULE_ATTR_SECRET_RE = re.compile(
    r'(?P<key>@[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s+'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
CONFIG_SECRET_RE = re.compile(
    r'\bconfig\s+:[A-Za-z_][A-Za-z0-9_?!]*(?:\s*,\s*[A-Za-z0-9_.:]+)*\s*,\s*'
    r'(?P<key>:[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s*,\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
ENV_FALLBACK_RE = re.compile(
    r'\bSystem\.get_env\s*\(\s*(?P<env_quote>["\'])(?P<env>[A-Za-z0-9_]+)(?P=env_quote)\s*,\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)\s*\)'
)
LOW_VALUE_LITERAL_RE = re.compile(
    r'^(?:example|sample|dummy|placeholder|change[_-]?me|please[_-]?change|'
    r'localhost|127\.0\.0\.1|https?://example\.com)$',
    re.IGNORECASE,
)


def strip_line_comment(line: str) -> str:
    out = []
    quote = ''
    escape = False
    for ch in line:
        if quote:
            out.append(ch)
            escape = False
            if ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            continue
        if ch == '#':
            break
        out.append(ch)
    return ''.join(out)

def looks_like_secret_literal(value: str) -> bool:
    raw = value.strip()
    if len(raw) < 8:
        return False
    if LOW_VALUE_LITERAL_RE.search(raw):
        return False
    if re.fullmatch(r'[\w.-]+', raw) and raw.upper() == raw and '_' in raw:
        return False
    return True

def should_skip(path: Path) -> bool:
    """The heredoc's test-tree pruning, evaluated on the cwd-relative path
    (absolute path as fallback) instead of BASE_DIR-relative: the v2 file
    list is pre-pruned for SKIP_DIRS, but the test-tree rules are
    detection-relevant and must survive the port."""
    try:
        rel = path.resolve().relative_to(Path.cwd())
        normalized = rel.as_posix()
    except ValueError:
        normalized = Path(path).as_posix()
    if '/test/' in f'/{normalized}/':
        return True
    return (
        normalized.endswith('_test.exs')
        or normalized == 'config/test.exs'
        or normalized.endswith('/config/test.exs')
    )


def scan_file_findings(path: Path) -> Iterable[tuple[int, int, str]]:
    if should_skip(path):
        return
    lines = read_lines(path)
    if lines is None:
        return
    text = "\n".join(lines)
    if not (SECRET_KEY_RE.search(text) or 'System.get_env' in text):
        return
    seen: set[tuple[int, str]] = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = strip_line_comment(lines[idx - 1]).strip()
        for regex in (ASSIGNMENT_SECRET_RE, MODULE_ATTR_SECRET_RE, CONFIG_SECRET_RE):
            for match in regex.finditer(statement):
                key = match.group('key').lstrip('@:')
                value = match.group('value')
                if not SECRET_KEY_RE.search(key):
                    continue
                if not looks_like_secret_literal(value):
                    continue
                if (idx, key) in seen:
                    continue
                seen.add((idx, key))
                yield idx, 1, f"{source_line(lines, idx)}  [hardcoded {key}]"
        for match in ENV_FALLBACK_RE.finditer(statement):
            env_name = match.group('env')
            value = match.group('value')
            if not (SECRET_KEY_RE.search(env_name) and looks_like_secret_literal(value)):
                continue
            if (idx, env_name) in seen:
                continue
            seen.add((idx, env_name))
            yield idx, 1, f"{source_line(lines, idx)}  [literal fallback for {env_name}]"


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in elixir_files(files, EXTS):
        for line_no, col, code in scan_file_findings(path):
            yield str(path), line_no, col, code
