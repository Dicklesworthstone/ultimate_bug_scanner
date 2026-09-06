"""ubs_core.rust_detectors.hardcoded_secrets — hardcoded secrets/credentials (bead 0xjg.7).

Port of the inline hardcoded-secrets python heredoc inside the CATEGORY 8
block of modules/ubs-rust.sh (8963-9179): a line-oriented literal scanner
flagging secret-named targets assigned plausible credentials. Trigger
lines are those whose (comment-stripped) text is secret-flavored
(secret/password/passwd/pwd/token/api[_-]key/private[_-]key/
client[_-]secret/webhook[_-]secret/jwt[_-]secret/access[_-]token/
refresh[_-]token/session[_-]secret/cookie[_-]secret/signing[_-]secret/
encryption[_-]key/secret[_-]key[_-]base/credential(s), camel/dash/
underscore-normalized) or that calls std::env::var/env::var/option_env!;
the multi-line statement (up to 10 lines, comment-stripped) is then
matched against pub/const/static/let [mut] declarations and struct fields
where the target name is sensitive and the literal is risky (>=8 chars,
alphanumeric, not a known placeholder, no example./example_|sample_|
dummy_ prefix), or against ``.insert("SECRET_NAME", ...)`` map keys, or
against env fallbacks (``env::var("SECRET").unwrap_or[_else](...)`` with a
risky fallback literal). Suppression is two-layered (both ported
verbatim): a line is skipped when its own line or the previous line
carries ``ubs:ignore``, and a candidate is dropped when the assembled
statement contains ``ubs:ignore``. A final pass dedupes per (file, line).

Legacy printed ``__COUNT__`` plus up to 25 ``__SAMPLE__`` lines; the 25 cap
was a display cap (the count used all deduped issues), so find() yields
the FULL deduped issue list in legacy dedup order.

Path spelling (ported verbatim): the legacy heredoc resolved list entries
via ``Path(entry).resolve()`` and relpathed against the resolved root
argument (the directory itself, or its parent when the root is a file).
``find(files, root=None)`` keeps that: pass the project root as ``root``
(or the ``--root`` CLI flag / PROJECT_ROOT module constant); when omitted
it defaults to the common parent of the resolved files. The legacy
rglob/SKIP_DIRS fallback is documentation-only: the orchestrator passes
the already-filtered file list.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, Iterator, Sequence

MARKER = "ubs:ignore"

RULE_ID = "rust.security.hardcoded-secrets"
CATEGORY = 8
TITLE = "Possible hardcoded secrets"
SEVERITY = "critical"
DESCRIPTION = (
    "Use secret managers or required environment variables; do not keep "
    "literal fallbacks for secret env vars"
)

PROJECT_ROOT: Path | None = None

# Documentation only: legacy rglob fallback's skip list. The orchestrator
# passes the already-filtered file list, so this is never applied.
SKIP_DIRS = {'.git', 'target', '.cache', 'dist', 'build'}
EXTS = {'.rs'}
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|r#+?"[^"]*"#+|r"[^"]*"')
SECRET_WORD_RE = re.compile(
    r'(?:'
    r'\bsecret\b|\bpassword\b|\bpasswd\b|\bpwd\b|\btoken\b|\bapi[_-]?key\b|'
    r'\bprivate[_-]?key\b|\bclient[_-]?secret\b|\bwebhook[_-]?secret\b|'
    r'\bjwt[_-]?secret\b|\baccess[_-]?token\b|\brefresh[_-]?token\b|'
    r'\bsession[_-]?secret\b|\bcookie[_-]?secret\b|\bsigning[_-]?secret\b|'
    r'\bencryption[_-]?key\b|\bsecret[_-]?key[_-]?base\b|\bcredential(?:s)?\b'
    r')'
)
SECRET_PHRASE_RE = re.compile(
    r'\b(?:'
    r'api\s+key|private\s+key|client\s+secret|webhook\s+secret|jwt\s+secret|'
    r'access\s+token|refresh\s+token|session\s+secret|cookie\s+secret|'
    r'signing\s+secret|encryption\s+key|secret\s+key\s+base'
    r')\b'
)
PLACEHOLDERS = {
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change_me',
    'not_a_secret', 'your_secret_here', 'your-api-key', 'localhost',
    '127.0.0.1', 'http://localhost', 'https://localhost', 'https://example.com',
}
DECL_RE = re.compile(r'\b(?:pub\s+)?(?:const|static|let)(?:\s+mut)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(.+)')
FIELD_RE = re.compile(r'(?:^|[{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)')
INSERT_RE = re.compile(r'\.insert\s*\(\s*(' + STRING_RE.pattern + r')\s*,\s*(.+)\)')
ENV_CALL_RE = re.compile(r'(?:std::env::var|env::var|option_env!)\s*!?\s*\(\s*(' + STRING_RE.pattern + r')\s*\)')


def relpath(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except ValueError:
        return str(path)


def _base_dir(root, files):
    if root is not None:
        resolved_root = Path(root).resolve()
        return resolved_root if resolved_root.is_dir() else resolved_root.parent
    resolved = [Path(entry).resolve() for entry in files]
    if resolved:
        common = Path(os.path.commonpath([str(p) for p in resolved]))
        return common if common.is_dir() else common.parent
    return Path.cwd()


def strip_comments(line: str) -> str:
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
        if ch == '"':
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


def statement_from(lines, start_idx, max_lines=10):
    parts = []
    balance = 0
    for idx in range(start_idx, min(len(lines), start_idx + max_lines)):
        current = strip_comments(lines[idx]).strip()
        if not current:
            continue
        parts.append(current)
        balance += current.count('(') + current.count('{') - current.count(')') - current.count('}')
        if balance <= 0 and (
            current.endswith(';') or current.endswith(',') or current.endswith('}') or current == '}'
        ):
            break
    return ' '.join(parts)


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def has_ignore(lines, idx):
    return MARKER in lines[idx] or (idx > 0 and MARKER in lines[idx - 1])


def normalize_name(name: str) -> str:
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', str(name or ''))
    text = re.sub(r'[^A-Za-z0-9]+', '_', text)
    return text.lower().strip('_')


def is_sensitive_name(name: str) -> bool:
    normalized = normalize_name(name.strip('"#r '))
    spaced = normalized.replace('_', ' ')
    return bool(SECRET_WORD_RE.search(normalized) or SECRET_WORD_RE.search(spaced) or SECRET_PHRASE_RE.search(spaced))


def unquote_literal(token: str) -> str:
    token = token.strip()
    if token.startswith('r'):
        first = token.find('"')
        last = token.rfind('"')
        return token[first + 1:last] if first >= 0 and last > first else ''
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return ''


def risky_literal(token: str) -> bool:
    value = unquote_literal(token).strip()
    lowered = value.lower()
    if len(value) < 8:
        return False
    if lowered in PLACEHOLDERS:
        return False
    if 'example.' in lowered or lowered.startswith(('example_', 'sample_', 'dummy_')):
        return False
    return bool(re.search(r'[A-Za-z0-9]', value))


def first_risky_literal(expr: str) -> str:
    for match in STRING_RE.finditer(expr):
        token = match.group(0)
        if risky_literal(token):
            return token
    return ''


def direct_risky_literal(expr: str) -> str:
    match = re.match(r'\s*(?:&\s*)?(' + STRING_RE.pattern + r')', expr)
    if not match:
        return ''
    token = match.group(1)
    return token if risky_literal(token) else ''


def assignment_literal(statement: str) -> bool:
    for regex in (DECL_RE, FIELD_RE):
        for match in regex.finditer(statement):
            if is_sensitive_name(match.group(1)) and direct_risky_literal(match.group(2)):
                return True
    for match in INSERT_RE.finditer(statement):
        if is_sensitive_name(unquote_literal(match.group(1))) and direct_risky_literal(match.group(2)):
            return True
    return False


def env_fallback_literal(statement: str) -> bool:
    match = ENV_CALL_RE.search(statement)
    if not match or not is_sensitive_name(unquote_literal(match.group(1))):
        return False
    suffix = statement[match.end():]
    return bool(re.search(r'\.unwrap_or(?:_else)?\s*\(', suffix) and first_risky_literal(suffix))


def analyze(path: Path, base_dir: Path, issues):
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    for idx, line in enumerate(lines):
        stripped = strip_comments(line).strip()
        if not stripped or has_ignore(lines, idx):
            continue
        if not (is_sensitive_name(stripped) or ENV_CALL_RE.search(stripped)):
            continue
        statement = statement_from(lines, idx)
        if not statement or MARKER in statement:
            continue
        if assignment_literal(statement) or env_fallback_literal(statement):
            issues.append((relpath(path, base_dir), idx + 1, 1, source_line(lines, idx + 1)))


def find(files: Sequence[Path], root: Path | None = None) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (relpath, line, col, code) per legacy deduped finding, in legacy order."""
    if root is None:
        root = PROJECT_ROOT
    base_dir = _base_dir(root, files)
    issues: list[tuple[str, int, int, str]] = []
    for entry in files:
        path = Path(entry)
        if path.suffix.lower() not in EXTS:
            continue
        analyze(path.resolve(), base_dir, issues)  # legacy resolved list entries
    deduped: list[tuple[str, int, int, str]] = []
    seen = set()
    for item in issues:
        key = item[:2]
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    yield from deduped


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    cli_root = None
    if "--root" in args:
        i = args.index("--root")
        cli_root = Path(args[i + 1])
        del args[i:i + 2]
    root_files = [Path(p) for p in args]
    for found_path, line, col, code in find(root_files, cli_root):
        print(f"{found_path}:{line}:{code}")
