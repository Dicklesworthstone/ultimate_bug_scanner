"""ubs_core.analyzers.sec_cookies — insecure auth/session cookie settings (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "Insecure auth/session cookie
settings" (``cookie_security_report``): same cookie-call / Set-Cookie-header
candidate regexes, same 18-line statement window, same explicit-insecure /
SameSite-None-without-secure / missing-required-flags rules for cookie calls,
same raw HttpOnly+Secure requirement for Set-Cookie headers, same ``ubs:ignore``
placement rules (trigger line, line above, or anywhere inside the collected
statement).
The heredoc's os.walk over the project is replaced by iteration over
``RunContext.files``; per-file match logic is unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.cookies"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = ("Insecure auth/session cookie settings: Set auth cookies with httpOnly, secure, and "
           "SameSite protections; SameSite=None must also use Secure")

cookie_call_re = re.compile(
    r'(?:'
    r'\.(?:cookie)\s*\(|'
    r'\bcookie\s*\.\s*serialize\s*\(|'
    r'\bcookies\s*\(\s*\)\s*\.\s*set\s*\(|'
    r'\.cookies\s*\.\s*set\s*\('
    r')',
    re.IGNORECASE,
)
set_cookie_header_re = re.compile(
    r'(?:'
    r'\b(?:setHeader|append|set)\s*\(\s*[\'"]Set-Cookie[\'"]|'
    r'\bheaders\s*\.\s*(?:append|set)\s*\(\s*[\'"]Set-Cookie[\'"]'
    r')',
    re.IGNORECASE,
)
sensitive_name_re = re.compile(
    r'[\'"`][^\'"`]*(?:session|sess|sid|auth|token|jwt|refresh|access|remember|login)[^\'"`]*[\'"`]',
    re.IGNORECASE,
)
http_only_true_re = re.compile(r'\bhttpOnly\s*:\s*true\b', re.IGNORECASE)
http_only_false_re = re.compile(r'\bhttpOnly\s*:\s*false\b', re.IGNORECASE)
secure_true_re = re.compile(r'\bsecure\s*:\s*true\b', re.IGNORECASE)
secure_false_re = re.compile(r'\bsecure\s*:\s*false\b', re.IGNORECASE)
same_site_none_re = re.compile(r'\bsameSite\s*:\s*[\'"`]none[\'"`]', re.IGNORECASE)
raw_http_only_re = re.compile(r'\bHttpOnly\b', re.IGNORECASE)
raw_secure_re = re.compile(r'(?:^|[;,\s])Secure(?:[;,\s]|$)', re.IGNORECASE)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def statement_from(lines, idx, max_lines=18):
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
        ends_statement = current.endswith(';') or current.endswith('});') or current.endswith('}));')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0 and ends_statement:
            break
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0 and ');' in current:
            break
    return ' '.join(parts) if saw_code else ""


def is_insecure_cookie_call(statement):
    if not cookie_call_re.search(statement):
        return False
    explicit_insecure = http_only_false_re.search(statement) or secure_false_re.search(statement)
    same_site_none_without_secure = same_site_none_re.search(statement) and not secure_true_re.search(statement)
    sensitive_cookie = sensitive_name_re.search(statement)
    has_options = '{' in statement and '}' in statement
    missing_required_flags = sensitive_cookie and (
        not has_options or not http_only_true_re.search(statement) or not secure_true_re.search(statement)
    )
    return bool(explicit_insecure or same_site_none_without_secure or missing_required_flags)


def is_insecure_set_cookie_header(statement):
    if not set_cookie_header_re.search(statement):
        return False
    return not (raw_http_only_re.search(statement) and raw_secure_re.search(statement))


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield 1-based line numbers per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        if not (cookie_call_re.search(stripped) or set_cookie_header_re.search(stripped)):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        if not (is_insecure_cookie_call(statement) or is_insecure_set_cookie_header(statement)):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        yield idx + 1


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
        for line in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": 1,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_missing_flags_flagged(tmp_prefix: str = "ubs_core_sec_cookies_") -> None:
    import tempfile

    src = "\n".join([
        "export function expressMissingFlags(res, sessionId) {",
        "  res.cookie('session_id', sessionId);",
        "}",
        "",
        "export function expressExplicitlyUnsafe(res, token) {",
        "  res.cookie('auth_token', token, {",
        "    httpOnly: false,",
        "    secure: false,",
        "    sameSite: 'none',",
        "  });",
        "}",
        "",
        "export function serializedCookie(token) {",
        "  return cookie.serialize('access_token', token, {",
        "    httpOnly: true,",
        "    sameSite: 'lax',",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "cookies.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [2, 6, 14], findings


def _selftest_raw_set_cookie_flagged(tmp_prefix: str = "ubs_core_sec_cookies_raw_") -> None:
    import tempfile

    insecure = "res.setHeader('Set-Cookie', `jwt=${jwt}; Path=/; SameSite=Lax`);\n"
    secure = "res.setHeader('Set-Cookie', `jwt=${jwt}; Path=/; HttpOnly; Secure; SameSite=Lax`);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        bad = Path(tmp) / "bad.ts"
        bad.write_text(insecure, encoding="utf-8")
        good = Path(tmp) / "good.ts"
        good.write_text(secure, encoding="utf-8")
        assert list(scan_file_findings(bad)) == [1], "raw Set-Cookie without HttpOnly+Secure must be flagged"
        assert list(scan_file_findings(good)) == [], "raw Set-Cookie with HttpOnly and Secure stays clean"


def _selftest_fully_protected_clean(tmp_prefix: str = "ubs_core_sec_cookies_clean_") -> None:
    import tempfile

    src = "\n".join([
        "export function expressSafeSession(res, sessionId) {",
        "  res.cookie('session_id', sessionId, {",
        "    httpOnly: true,",
        "    secure: true,",
        "    sameSite: 'lax',",
        "  });",
        "}",
        "",
        "export function nextResponseSafe(token) {",
        "  response.cookies.set('refresh_token', token, {",
        "    httpOnly: true,",
        "    secure: true,",
        "    sameSite: 'strict',",
        "  });",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_cookies_ign_") -> None:
    import tempfile

    # ubs:ignore on the line above, on the line itself, and inside the statement window.
    above = "// ubs:ignore\nres.cookie('session_id', sessionId);\n"
    same = "res.cookie('session_id', sessionId); // ubs:ignore\n"
    in_stmt = "\n".join([
        "res.cookie('auth_token', token, {",
        "  httpOnly: false, // ubs:ignore",
        "  secure: false,",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        for name, body in (("above.ts", above), ("same.ts", same), ("stmt.ts", in_stmt)):
            target = Path(tmp) / name
            target.write_text(body, encoding="utf-8")
            findings = list(scan_file_findings(target))
            assert findings == [], (name, findings)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_cookies_run_") -> None:
    import tempfile

    src = "res.cookie('session_id', sessionId);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "app.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 1, rec
        assert "Insecure auth/session cookie settings" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("missing-flags-flagged", _selftest_missing_flags_flagged),
    ("raw-set-cookie-flagged", _selftest_raw_set_cookie_flagged),
    ("fully-protected-clean", _selftest_fully_protected_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_cookies", run=run, selftests=SELF_TESTS))
