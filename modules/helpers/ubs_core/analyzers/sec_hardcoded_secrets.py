"""ubs_core.analyzers.sec_hardcoded_secrets — hardcoded secrets/credentials
(bead A4-js security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh heredoc "Hardcoded secrets/credentials":
same literal/env-fallback/declaration/property/assignment regexes, same
sensitive-name normalization and placeholder filtering, same 14-line statement
window, same ``ubs:ignore`` placement rules (same line or the line immediately
above, and anywhere inside the collected statement). The heredoc's os.walk over
the project is replaced by iteration over ``RunContext.files``; per-file match
logic is unchanged.

Legacy emission: print_finding "critical" / "Possible hardcoded secrets". The
legacy title rides in the message so the contract-v2 text renderer surfaces it
verbatim (rule ids are not in js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.hardcoded-secrets"
CATEGORY_ID = "js.security"
SEVERITY = "critical"
TITLE = "Possible hardcoded secrets"
REMEDIATION = "Use environment variables or secret managers; do not keep literal fallbacks for secret env vars"

literal_pattern = r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)"""
env_fallback_re = re.compile(
    r'\bprocess\.env(?:\.([A-Za-z_$][\w$]*)|\[\s*[\'"]([^\'"]+)[\'"]\s*\])'
    r'\s*(?:\|\||\?\?)\s*(' + literal_pattern + r')'
)
declaration_re = re.compile(
    r'\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)'
)
property_re = re.compile(
    r'(?:^|[{,]\s*)([A-Za-z_$][\w$]*|[\'"][^\'"]+[\'"])\s*:\s*(.+)'
)
assignment_re = re.compile(
    r'(?:^|[;\s])(?:this\.)?([A-Za-z_$][\w$]*)\s*=\s*(.+)'
)
direct_literal_re = re.compile(r'^\s*(' + literal_pattern + r')')
secret_word_re = re.compile(
    r'(?:'
    r'\bsecret\b|\bpassword\b|\bpasswd\b|\bpwd\b|\btoken\b|\bapi[_-]?key\b|'
    r'\bprivate[_-]?key\b|\bclient[_-]?secret\b|\bwebhook[_-]?secret\b|'
    r'\bjwt[_-]?secret\b|\bnext[_-]?auth[_-]?secret\b|\bnextauth[_-]?secret\b|'
    r'\baccess[_-]?token\b|\brefresh[_-]?token\b|\bsession[_-]?secret\b|'
    r'\bcookie[_-]?secret\b|\bsigning[_-]?secret\b|\bencryption[_-]?key\b|'
    r'\bcredential(?:s)?\b'
    r')'
)
sensitive_phrase_re = re.compile(
    r'\b(?:'
    r'api\s+key|private\s+key|client\s+secret|webhook\s+secret|'
    r'jwt\s+secret|next\s+auth\s+secret|nextauth\s+secret|'
    r'access\s+token|refresh\s+token|session\s+secret|cookie\s+secret|'
    r'signing\s+secret|encryption\s+key|secret\s+key\s+base'
    r')\b'
)

placeholder_values = {
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change_me',
    'not_a_secret', 'your_secret_here', 'your-api-key', 'localhost',
    '127.0.0.1', 'http://localhost', 'https://localhost', 'https://example.com',
}


def strip_line_comments(source_line: str) -> str:
    out = []
    quote = ''
    escape = False
    idx = 0
    while idx < len(source_line):
        ch = source_line[idx]
        nxt = source_line[idx + 1] if idx + 1 < len(source_line) else ''
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
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            end = source_line.find('*/', idx + 2)
            if end == -1:
                break
            idx = end + 2
            continue
        out.append(ch)
        idx += 1
    return ''.join(out)


def code_line(source_line: str) -> str:
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    return strip_line_comments(source_line)


def statement_from(lines: list[str], idx: int, max_lines: int = 14) -> str:
    parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = code_line(lines[line_idx]).strip()
        if not current:
            continue
        parts.append(current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if ';' in current and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts) if saw_code else ""


def normalize_name(name: str) -> str:
    cleaned = name.strip().strip('"\'`')
    cleaned = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', cleaned)
    cleaned = re.sub(r'[^A-Za-z0-9]+', '_', cleaned)
    return cleaned.lower().strip('_')


def is_sensitive_name(name: str) -> bool:
    normalized = normalize_name(name)
    spaced = normalized.replace('_', ' ')
    return bool(secret_word_re.search(spaced) or secret_word_re.search(normalized) or sensitive_phrase_re.search(spaced))


def unquote_literal(token: str) -> str:
    token = token.strip()
    if len(token) < 2 or token[0] not in ('"', "'", '`') or token[-1] != token[0]:
        return ""
    return token[1:-1]


def is_risky_literal(token: str) -> bool:
    value = unquote_literal(token)
    if token.startswith('`') and '${' in value:
        return False
    compact = value.strip()
    if len(compact) < 8:
        return False
    lowered = compact.lower()
    if lowered in placeholder_values:
        return False
    if 'example.' in lowered or lowered.startswith(('example_', 'sample_', 'dummy_')):
        return False
    if not re.search(r'[A-Za-z0-9]', compact):
        return False
    return True


def first_direct_literal(expr: str) -> str:
    match = direct_literal_re.search(expr)
    if not match:
        return ""
    token = match.group(1)
    return token if is_risky_literal(token) else ""


def env_fallback_literal(statement: str) -> str:
    for match in env_fallback_re.finditer(statement):
        env_name = match.group(1) or match.group(2) or ""
        token = match.group(3)
        if is_sensitive_name(env_name) and is_risky_literal(token):
            return token
    return ""


def assignment_literal(statement: str) -> str:
    for regex in (declaration_re, property_re, assignment_re):
        for match in regex.finditer(statement):
            name, expr = match.group(1), match.group(2)
            if is_sensitive_name(name) and first_direct_literal(expr):
                return match.group(0)
    return ""


def has_ignore(lines: list[str], idx: int) -> bool:
    if 'ubs:ignore' in lines[idx]:
        return True
    return idx > 0 and 'ubs:ignore' in lines[idx - 1]


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line_number, sample_text) per detection; heredoc-identical."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or has_ignore(lines, idx):
            continue
        if not is_sensitive_name(stripped):
            continue
        if re.match(r'(?:export\s+)?(?:async\s+)?function\b', stripped) and not env_fallback_literal(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        if not (env_fallback_literal(statement) or assignment_literal(statement)):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        yield idx + 1, stripped.replace('\t', ' ')


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for line, sample in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": f"{TITLE}: {sample}",
                "remediation": REMEDIATION,
            }


def _selftest_env_fallback_secret(tmp_prefix: str = "ubs_core_sec_secrets_") -> None:
    import tempfile

    src = "\n".join([
        "export const jwtSecret = process.env.JWT_SECRET || 'live-jwt-signing-key-9f3a';",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "config.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample = findings[0]
    assert line == 1, findings
    assert "jwtSecret" in sample, findings


def _selftest_hardcoded_assignment(tmp_prefix: str = "ubs_core_sec_secrets_decl_") -> None:
    import tempfile

    src = "\n".join([
        "const config = {",
        "  apiKey: 'sk-live-4f8a2b91cd77e530',",
        "};",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "config.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, _sample = findings[0]
    assert line == 2, findings


def _selftest_clean_env_required(tmp_prefix: str = "ubs_core_sec_secrets_clean_") -> None:
    import tempfile

    # required env (no fallback), short/placeholder literals, non-secret names
    src = "\n".join([
        "function loadConfig() {",
        "  return {",
        "    jwtSecret: requireEnv('JWT_SECRET'),",
        "    apiKey: process.env.API_KEY,",
        "    name: 'example',",
        "    host: 'http://localhost',",
        "    port: 3000,",
        "  };",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "config.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_secrets_ign_") -> None:
    import tempfile

    # both placement rules suppress: line above and same line
    src = "\n".join([
        "// ubs:ignore",
        "const clientSecret = 'prod-client-secret-a1b2c3d4e5';",
        "const webhookSecret = 'prod-webhook-secret-a1b2c3';  // ubs:ignore",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "config.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_secrets_run_") -> None:
    import tempfile

    src = "const apiToken = process.env.API_TOKEN || 'raw-token-value-7712abcd';\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "token.js"
        target.write_text(src, encoding="utf-8")
        records = list(run(RunContext(lang="javascript", files=[target])))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "critical", rec
        assert rec["line"] == 1, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("env-fallback-secret", _selftest_env_fallback_secret),
    ("hardcoded-assignment", _selftest_hardcoded_assignment),
    ("clean-env-required", _selftest_clean_env_required),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_hardcoded_secrets", run=run, selftests=SELF_TESTS))
