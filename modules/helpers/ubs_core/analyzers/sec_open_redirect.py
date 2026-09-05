"""ubs_core.analyzers.sec_open_redirect — unvalidated client redirects (bead A4-js).

Port of the "unvalidated client redirects" python heredoc from modules/ubs-js.sh
(warning severity, rule js.security.open-redirect). Detects redirect/navigation
sinks (router.push/replace, redirect(), location.assign/replace/href) whose
target comes straight from URL/query/header request data without a
same-origin/allowlist guard (isSafeRedirect*, validateRedirect*, ALLOWED_* ...)
in the preceding eight code lines.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.open-redirect"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "unvalidated redirect from URL/query/header data"

assignment_re = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.*(?:'
    r'(?:URLSearchParams|searchParams|params)\s*\.\s*get\s*\('
    r'|(?:window\.)?location\.(?:search|hash|href)\b'
    r'|(?:req|request)\.(?:headers)\s*(?:\.\s*(?:referer|referrer|origin|host)|\[\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\])'
    r'|(?:req|request)\.(?:get|header)\s*\(\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\)'
    r'|headers\s*\(\s*\)\s*\.\s*get\s*\(\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\)'
    r'|(?:req|request)\.query\b'
    r'|router\.query\b'
    r'|query\.(?:next|redirect|returnTo|return_to|callbackUrl|callback_url)\b'
    r').*)',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\b(?:router|navigation|history)\s*\.\s*(?:push|replace)\s*\('
    r'|\b(?:redirect|permanentRedirect|navigate)\s*\('
    r'|\b(?:window\.)?location\s*\.\s*(?:assign|replace)\s*\('
    r'|\b(?:window\.)?location\s*\.\s*href\s*=',
    re.IGNORECASE,
)
direct_source_re = re.compile(
    r'(?:URLSearchParams|searchParams|params)\s*\.\s*get\s*\('
    r'|(?:window\.)?location\.(?:search|hash|href)\b'
    r'|(?:req|request)\.(?:headers)\s*(?:\.\s*(?:referer|referrer|origin|host)|\[\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\])'
    r'|(?:req|request)\.(?:get|header)\s*\(\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\)'
    r'|headers\s*\(\s*\)\s*\.\s*get\s*\(\s*[\'"`](?:referer|referrer|origin|host|x-forwarded-host|x-forwarded-proto|x-next-url|x-redirect-url|x-return-to|location)[\'"`]\s*\)'
    r'|(?:req|request)\.query\b'
    r'|router\.query\b'
    r'|query\.(?:next|redirect|returnTo|return_to|callbackUrl|callback_url)\b',
    re.IGNORECASE,
)
safe_re = re.compile(
    r'\b(?:isSafeRedirect[A-Za-z0-9_]*|safeRedirect[A-Za-z0-9_]*|validateRedirect[A-Za-z0-9_]*|sanitizeRedirect[A-Za-z0-9_]*|allowedRedirects?|trustedRedirects?|sameOrigin|same-origin)\b',
    re.IGNORECASE,
)


def statement_from(lines, idx):
    parts = []
    paren_balance = 0
    for line_idx in range(idx, min(len(lines), idx + 10)):
        current = lines[line_idx].strip()
        parts.append(current)
        paren_balance += current.count('(') - current.count(')')
        if line_idx > idx and paren_balance <= 0:
            break
        if ';' in current and paren_balance <= 0:
            break
    return ' '.join(parts)


def validation_code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    out = []
    quote = ""
    escaped = False
    i = 0
    while i < len(source_line):
        ch = source_line[i]
        nxt = source_line[i + 1] if i + 1 < len(source_line) else ""
        if quote:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        if ch == "/" and nxt == "*":
            end = source_line.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) per detection; per-file logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    tainted_vars = {}
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        assignment = assignment_re.search(line)
        if assignment and 'ubs:ignore' not in line:
            tainted_vars[assignment.group(1)] = idx
        if not sink_re.search(line):
            continue
        statement = statement_from(lines, idx)
        if 'ubs:ignore' in statement or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        context_start = max(0, idx - 8)
        context_lines = [
            code_line
            for source_line in lines[context_start:idx + 1]
            for code_line in [validation_code_line(source_line)]
            if code_line.strip()
        ]
        validation_context = '\n'.join(context_lines)
        if safe_re.search(validation_context):
            continue
        tainted = direct_source_re.search(statement)
        if not tainted:
            for name, source_idx in tainted_vars.items():
                if source_idx <= idx and re.search(rf'\b{re.escape(name)}\b', statement):
                    tainted = True
                    break
        if not tainted:
            continue
        yield idx + 1, sink_re.search(line).start() + 1


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs pruning relative to the scan root (cwd)
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
        for line, col in scan_file_findings(path):
            yield {
                "rule": RULE,
                "category_id": CATEGORY_ID,
                "path": str(rel),
                "line": line,
                "col": col,
                "severity": SEVERITY,
                "message": MESSAGE,
            }


def _selftest_query_taint_flagged(tmp_prefix: str = "ubs_core_sec_open_redirect_") -> None:
    import tempfile

    src = "\n".join([
        "import { useRouter, useSearchParams } from \"next/navigation\";",
        "",
        "export function LoginRedirectButton() {",
        "  const router = useRouter();",
        "  const searchParams = useSearchParams();",
        "",
        "  function handleLoginSuccess(): void {",
        "    const returnTo = searchParams.get(\"returnTo\") || \"/\";",
        "    router.push(returnTo);",
        "  }",
        "",
        "  return <button onClick={handleLoginSuccess}>Continue</button>;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "login.tsx"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 9, findings


def _selftest_header_sources_flagged(tmp_prefix: str = "ubs_core_sec_open_redirect_hdr_") -> None:
    import tempfile

    src = "\n".join([
        "export function redirectReferer(req: any): never {",
        "  const returnTo = req.headers.referer || \"/\";",
        "  redirect(returnTo);",
        "}",
        "",
        "export function redirectHeaderMethod(req: any): never {",
        "  const nextUrl = req.get(\"x-next-url\") || \"/\";",
        "  redirect(nextUrl);",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "redirect.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [3, 8], findings


def _selftest_safe_validator_suppressed(tmp_prefix: str = "ubs_core_sec_open_redirect_safe_") -> None:
    import tempfile

    # startsWith("/") alone does NOT suppress (see open-redirect-startswith-buggy),
    # but a recognized validator within the 8-line context does.
    src = "\n".join([
        "export function LoginRedirectButton() {",
        "  const searchParams = useSearchParams();",
        "  function handleLoginSuccess(): void {",
        "    const returnTo = searchParams.get(\"returnTo\") || \"/\";",
        "    if (!isSafeRedirect(returnTo)) {",
        "      return;",
        "    }",
        "    router.push(returnTo);",
        "  }",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.tsx"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_assignment_ignore_suppressed(tmp_prefix: str = "ubs_core_sec_open_redirect_ign_") -> None:
    import tempfile

    # ubs:ignore on the assignment line keeps the var out of the taint map;
    # ubs:ignore above the sink line suppresses directly. Both must stay clean.
    tainted_free = "\n".join([
        "const target = searchParams.get(\"to\"); // ubs:ignore",
        "router.push(target);",
        "",
    ])
    sink_ignore = "\n".join([
        "const target = searchParams.get(\"to\");",
        "// ubs:ignore",
        "router.push(target);",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        first = Path(tmp) / "a.ts"
        first.write_text(tainted_free, encoding="utf-8")
        second = Path(tmp) / "b.ts"
        second.write_text(sink_ignore, encoding="utf-8")
        assert list(scan_file_findings(first)) == []
        assert list(scan_file_findings(second)) == []


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_open_redirect_run_") -> None:
    import tempfile

    src = "const returnTo = searchParams.get(\"returnTo\") || \"/\";\nrouter.push(returnTo);\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "login.tsx"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == SEVERITY, rec
        assert rec["line"] == 2 and rec["col"] == 1, rec
        assert "redirect" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("query-taint-flagged", _selftest_query_taint_flagged),
    ("header-sources-flagged", _selftest_header_sources_flagged),
    ("safe-validator-suppressed", _selftest_safe_validator_suppressed),
    ("ignore-placement-suppressed", _selftest_assignment_ignore_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_open_redirect", run=run, selftests=SELF_TESTS))
