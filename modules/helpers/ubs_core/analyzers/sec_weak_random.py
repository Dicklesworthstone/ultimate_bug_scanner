"""ubs_core.analyzers.sec_weak_random — security tokens generated with Math.random (bead A4-js security wave).

Verbatim port of the legacy ubs-js.sh heredoc "Security token generated with
Math.random" (``random_security_report``): same Math.random candidate gate,
same 10-line statement window, same ±context collection (6 lines back / 4
forward, blank-gap > 2 and function-boundary stops), same sensitivity +
token-shape conjunction, same ``ubs:ignore`` placement rules (trigger line,
line above, or anywhere inside the collected statement — the heredoc does not
honor ubs:ignore inside the surrounding context).
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

RULE = "js.security.weak-random"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = ("Security token generated with Math.random: Use crypto.randomUUID(), crypto.randomBytes(), "
           "crypto.getRandomValues(), or crypto.randomInt() for security-sensitive tokens")

math_random_re = re.compile(r'\bMath\s*\.\s*random\s*\(')
sensitive_re = re.compile(
    r'(?:'
    r'\b(?:token|session|sess|sid|jwt|secret|nonce|csrf|xsrf|otp|mfa|2fa|'
    r'reset|password|auth|invite|verification|verify|login|credential|'
    r'bearer|salt|key|recovery|activation)\b|'
    r'\bapi\s+key\b|\bmagic\s+link\b'
    r')',
    re.IGNORECASE,
)
token_shape_re = re.compile(r'\.toString\s*\(\s*(?:36|16)\s*\)|\bpadStart\s*\(\s*[46]\b')
function_boundary_re = re.compile(
    r'^\s*(?:export\s+)?(?:async\s+)?function\b|'
    r'^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>'
)


def identifier_terms(text):
    spaced = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    return re.sub(r'[_-]+', ' ', spaced)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    without_block_comments = re.sub(r'/\*.*?\*/', '', source_line)
    return re.sub(r'//.*', '', without_block_comments)


def statement_from(lines, idx, max_lines=10):
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


def context_from(lines, idx):
    start = max(0, idx - 6)
    end = min(len(lines), idx + 4)
    blank_gap = 0
    for line_idx in range(idx - 1, start - 1, -1):
        clean = code_line(lines[line_idx])
        if not clean.strip():
            blank_gap += 1
            if blank_gap > 2:
                start = line_idx + 1
                break
            continue
        blank_gap = 0
        if function_boundary_re.search(clean):
            start = line_idx
            break
    blank_gap = 0
    for line_idx in range(idx + 1, end):
        clean = code_line(lines[line_idx])
        if not clean.strip():
            blank_gap += 1
            if blank_gap > 2:
                end = line_idx
                break
            continue
        if function_boundary_re.search(clean):
            end = line_idx
            break
        blank_gap = 0
    return '\n'.join(
        clean
        for source_line in lines[start:end]
        for clean in [code_line(source_line)]
        if clean.strip()
    )


def scan_file_findings(path: Path) -> Iterator[int]:
    """Yield 1-based line numbers per detection; match logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]) or not math_random_re.search(stripped):
            continue
        statement = statement_from(lines, idx)
        if not statement or 'ubs:ignore' in statement:
            continue
        context = context_from(lines, idx)
        if not (sensitive_re.search(identifier_terms(context)) or token_shape_re.search(statement)):
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


def _selftest_token_generation_flagged(tmp_prefix: str = "ubs_core_sec_weak_random_") -> None:
    import tempfile

    src = "\n".join([
        "export function generatePasswordResetToken() {",
        "  return Math.random().toString(36).slice(2);",
        "}",
        "",
        "export function createOtpCode() {",
        "  return Math.floor(100000 + Math.random() * 900000).toString();",
        "}",
        "",
        "export function csrfNonce() {",
        "  const nonce = Buffer.from(String(Math.random())).toString('base64url');",
        "  return nonce;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tokens.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [2, 6, 9], findings


def _selftest_sensitive_context_and_shape(tmp_prefix: str = "ubs_core_sec_weak_random_ctx_") -> None:
    import tempfile

    # No token-shape, but sensitive identifier in the surrounding context.
    sensitive_ctx = "\n".join([
        "export function csrfNonce() {",
        "  const nonce = Buffer.from(String(Math.random())).toString('base64url');",
        "  return nonce;",
        "}",
        "",
    ])
    # Token shape (toString(36)) carries the finding without sensitive words.
    shape_only = "const id = Math.random().toString(36).slice(2);\n"
    # Neither sensitive context nor token shape stays clean.
    plain = "\n".join([
        "export function animationJitter() {",
        "  return Math.random() * 12;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        sens = Path(tmp) / "sens.ts"
        sens.write_text(sensitive_ctx, encoding="utf-8")
        shape = Path(tmp) / "shape.ts"
        shape.write_text(shape_only, encoding="utf-8")
        ui = Path(tmp) / "ui.ts"
        ui.write_text(plain, encoding="utf-8")
        assert list(scan_file_findings(sens)) == [2], "sensitive nonce context must be flagged"
        assert list(scan_file_findings(shape)) == [1], "toString(36) token shape must be flagged"
        assert list(scan_file_findings(ui)) == [], "UI jitter randomness stays clean"


def _selftest_crypto_backed_clean(tmp_prefix: str = "ubs_core_sec_weak_random_crypto_") -> None:
    import tempfile

    src = "\n".join([
        "import { randomBytes, randomInt, randomUUID } from 'crypto';",
        "",
        "export function generatePasswordResetToken() {",
        "  return randomBytes(32).toString('base64url');",
        "}",
        "",
        "export function createOtpCode() {",
        "  return randomInt(0, 1000000).toString().padStart(6, '0');",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "crypto.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert findings == [], findings


def _selftest_ignore_suppression(tmp_prefix: str = "ubs_core_sec_weak_random_ign_") -> None:
    import tempfile

    # ubs:ignore on the line above, on the line itself, and inside the statement
    # window all suppress; heredoc does NOT honor ubs:ignore in the wider context.
    above = "// ubs:ignore\nconst sid = `${userId}-${Math.random().toString(16).slice(2)}`;\n"
    same = "const resetCode = Math.random().toString(36).slice(2); // ubs:ignore\n"
    in_stmt = "\n".join([
        "export function makeInviteCode() {",
        "  const inviteCode = Math.random() // ubs:ignore",
        "    .toString(36).slice(2, 10);",
        "  return inviteCode;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        for name, body in (("above.ts", above), ("same.ts", same), ("stmt.ts", in_stmt)):
            target = Path(tmp) / name
            target.write_text(body, encoding="utf-8")
            findings = list(scan_file_findings(target))
            assert findings == [], (name, findings)


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_weak_random_run_") -> None:
    import tempfile

    src = "const resetToken = Math.random().toString(36).slice(2);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "tokens.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == "warning", rec
        assert rec["line"] == 1 and rec["col"] == 1, rec
        assert "Security token generated with Math.random" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("token-generation-flagged", _selftest_token_generation_flagged),
    ("sensitive-context-and-shape", _selftest_sensitive_context_and_shape),
    ("crypto-backed-clean", _selftest_crypto_backed_clean),
    ("ignore-suppression", _selftest_ignore_suppression),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_weak_random", run=run, selftests=SELF_TESTS))
