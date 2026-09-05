"""ubs_core.analyzers.sec_tls — disabled TLS certificate verification (bead A4-js
security wave, bead 0xjg.4).

Verbatim port of the legacy ubs-js.sh heredoc "Disabled TLS certificate
verification": same regexes, same 14-line statement window (paren/brace
balance, no bracket tracking), same false-like-constant resolution
(``const rejectUnauthorized = false`` / ``= "0"``), same ``ubs:ignore``
placement rules (same line or the line immediately above, anywhere in the
collected statement). The heredoc's os.walk over the project is replaced by
iteration over ``RunContext.files``; per-file match logic is unchanged.

Legacy emission: print_finding "warning" / "TLS certificate verification
disabled". The legacy title rides in the message so the contract-v2 text
renderer surfaces it verbatim (rule ids are not in js_rules.SUMMARY_MAP).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.tls"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
TITLE = "TLS certificate verification disabled"
REMEDIATION = "Keep certificate verification enabled; use explicit CA bundles for private trust roots"

candidate_re = re.compile(r'\b(?:rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED)\b')
reject_unauthorized_false_re = re.compile(r'\brejectUnauthorized\s*:\s*false\b')
env_tls_zero_re = re.compile(
    r'(?:'
    r'\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[:=]\s*(?:[\'"`]0[\'"`]|0\b)|'
    r'[\'"`]NODE_TLS_REJECT_UNAUTHORIZED[\'"`]\s*:\s*(?:[\'"`]0[\'"`]|0\b)'
    r')'
)
false_like_assignment_re = re.compile(
    r'\b(?:export\s+)?(?:const|let|var)\s+'
    r'(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?=\s*'
    r'(?:false\b|0\b|[\'"`]0[\'"`])'
)


def code_line(source_line: str) -> str:
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


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


def collect_false_like_vars(lines: list[str]) -> set[str]:
    names = set()
    for raw in lines:
        line = code_line(raw)
        if not line or 'ubs:ignore' in line:
            continue
        match = false_like_assignment_re.search(line)
        if match:
            names.add(match.group('name'))
    return names


def uses_false_like_tls_var(statement: str, false_like_vars: set[str]) -> bool:
    for name in false_like_vars:
        escaped = re.escape(name)
        if re.search(rf'\brejectUnauthorized\s*:\s*{escaped}\b', statement):
            return True
        if name == 'rejectUnauthorized' and re.search(r'(?:^|[{,])\s*rejectUnauthorized\s*(?:[,}])', statement):
            return True
        if re.search(rf'\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[:=]\s*{escaped}\b', statement):
            return True
        if re.search(rf'[\'"`]NODE_TLS_REJECT_UNAUTHORIZED[\'"`]\s*:\s*{escaped}\b', statement):
            return True
    return False


def scan_file_findings(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (line_number, sample_text) per detection; heredoc-identical."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    false_like_vars = collect_false_like_vars(lines)
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]) or not candidate_re.search(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        if not (
            reject_unauthorized_false_re.search(statement)
            or env_tls_zero_re.search(statement)
            or uses_false_like_tls_var(statement, false_like_vars)
        ):
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


def _selftest_reject_unauthorized_false(tmp_prefix: str = "ubs_core_sec_tls_") -> None:
    import tempfile

    src = "\n".join([
        "import https from 'https';",
        "export const agent = new https.Agent({",
        "  rejectUnauthorized: false,",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tls.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert len(findings) == 1, findings
    line, sample = findings[0]
    assert line == 3, findings
    assert "rejectUnauthorized: false" in sample, findings


def _selftest_env_zero_and_false_like_var(tmp_prefix: str = "ubs_core_sec_tls_env_") -> None:
    import tempfile

    # direct env zero (line 2) + false-like local resolved through shorthand
    # `rejectUnauthorized,` (line 7); NODE_TLS form inside object (line 9).
    src = "\n".join([
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
        "const rejectUnauthorized = false;",
        "export const agent = new https.Agent({",
        "  rejectUnauthorized,",
        "});",
        "export const env = {",
        "  NODE_TLS_REJECT_UNAUTHORIZED: 0,",
        "};",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tls.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert [line for line, _ in findings] == [1, 4, 7], findings


def _selftest_clean_verification(tmp_prefix: str = "ubs_core_sec_tls_clean_") -> None:
    import tempfile

    src = "\n".join([
        "export const agent = new https.Agent({",
        "  ca: privateCa,",
        "  rejectUnauthorized: true,",
        "});",
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tls.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_tls_ign_") -> None:
    import tempfile

    # ubs:ignore on the line above suppresses (heredoc placement rule).
    src = "\n".join([
        "const agent = new https.Agent({",
        "  // ubs:ignore",
        "  rejectUnauthorized: false,",
        "});",
        "const agent2 = new https.Agent({",
        "  rejectUnauthorized: false, // ubs:ignore",
        "});",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tls.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
    assert findings == [], findings


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_tls_run_") -> None:
    import tempfile

    src = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tls.js"
        target.write_text(src, encoding="utf-8")
        records = list(run(RunContext(lang="javascript", files=[target])))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1, rec
        assert TITLE in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("reject-unauthorized-false", _selftest_reject_unauthorized_false),
    ("env-zero-and-false-like-var", _selftest_env_zero_and_false_like_var),
    ("clean-verification", _selftest_clean_verification),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_tls", run=run, selftests=SELF_TESTS))
