"""ubs_core.analyzers.sec_host_header — Host header used for absolute URLs (bead A4-js).

Port of the "Host header used for absolute URL construction" python heredoc from
modules/ubs-js.sh (warning severity, rule js.security.host-header). Flags lines
whose statement builds an absolute URL (``https://`` template, ``new URL``,
``url.format``, ``Response.redirect`` ...) from a request Host/X-Forwarded-Host
value — directly or through an unvalidated local alias — unless a canonical
origin / host allow-list (ALLOWED_HOSTS, validateXxxHost, process.env.APP_URL ...)
validates it in the statement or the enclosing function context.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE = "js.security.host-header"
CATEGORY_ID = "js.security"
SEVERITY = "warning"
MESSAGE = "Host header used to build absolute URL"

assignment_re = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b[^=]*=\s*(.*)')
source_re = re.compile(
    r'(?:'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*headers\s*\.\s*(?:host|hostname)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:host|hostname)\b|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*headers\s*\[\s*[\'"`](?:host|x-forwarded-host|forwarded|x-original-host)[\'"`]\s*\]|'
    r'\b(?:req|request|ctx|context|event)\s*\.\s*(?:get|header)\s*\(\s*[\'"`](?:host|x-forwarded-host|forwarded|x-original-host)[\'"`]\s*\)|'
    r'\b(?:headers|request\.headers|event\.headers)\s*\.\s*get\s*\(\s*[\'"`](?:host|x-forwarded-host|forwarded|x-original-host)[\'"`]\s*\)|'
    r'\bheaders\s*\(\s*\)\s*\.\s*get\s*\(\s*[\'"`](?:host|x-forwarded-host|forwarded|x-original-host)[\'"`]\s*\)'
    r')',
    re.IGNORECASE,
)
absolute_url_re = re.compile(
    r'(?:'
    r'[\'"`]https?://|'
    r'\bnew\s+URL\s*\(|'
    r'\bURL\s*\.\s*canParse\s*\(|'
    r'\burl\s*\.\s*format\s*\(|'
    r'\b(?:Response|NextResponse)\s*\.\s*redirect\s*\('
    r')',
    re.IGNORECASE,
)
safe_re = re.compile(
    r'(?:'
    r'\b(?:validate|assert|ensure|require|check)[A-Za-z0-9_$]*(?:Host|Origin|Url|URL|BaseUrl|BaseURL|Canonical|Allowed|Trusted)[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:is|has)[A-Za-z0-9_$]*(?:Allowed|Trusted|Safe)[A-Za-z0-9_$]*(?:Host|Origin|BaseUrl|BaseURL)?[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:safe|trusted|allowed|canonical)[A-Za-z0-9_$]*(?:Host|Origin|BaseUrl|BaseURL|Url|URL)[A-Za-z0-9_$]*\s*\(|'
    r'\b(?:ALLOWED|TRUSTED)_(?:HOSTS|ORIGINS|BASE_URLS|BASE_URL|DOMAINS)\b|'
    r'\b(?:allowed|trusted)(?:Hosts|Origins|BaseUrls|BaseURLs|Domains)\b|'
    r'\b(?:PUBLIC|CANONICAL|APP|SITE)_(?:ORIGIN|BASE_URL|URL)\b|'
    r'\bprocess\s*\.\s*env\s*\.\s*(?:NEXT_PUBLIC_|PUBLIC_|APP_|SITE_|CANONICAL_)?(?:APP_URL|BASE_URL|ORIGIN|SITE_URL)\b'
    r')',
    re.IGNORECASE,
)
function_boundary_re = re.compile(
    r'^\s*(?:export\s+)?(?:async\s+)?function\b|'
    r'^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>'
)


def code_line(source_line):
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


def statement_from(lines, idx, max_lines=14):
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


def context_from(lines, idx, max_lines=10):
    start = max(0, idx - max_lines)
    for line_idx in range(idx - 1, start - 1, -1):
        clean = code_line(lines[line_idx])
        if function_boundary_re.search(clean):
            start = line_idx
            break
        if not clean.strip() and idx - line_idx > 2:
            start = line_idx + 1
            break
    return '\n'.join(
        clean
        for source_line in lines[start:idx + 1]
        for clean in [code_line(source_line)]
        if clean.strip()
    )


def has_safe_validation(text, var_name=""):
    if not safe_re.search(text):
        return False
    return not var_name or re.search(rf'\b{re.escape(var_name)}\b', text)


def tainted_ref(text, tainted_vars):
    for name in tainted_vars:
        if re.search(rf'\b{re.escape(name)}\b', text):
            return name
    return ""


def scan_file_findings(path: Path) -> Iterator[tuple[int, int]]:
    """Yield (line, col) per detection; per-file logic identical to the heredoc."""
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return
    text = '\n'.join(lines)
    if not source_re.search(text):
        return
    tainted_vars = {}
    seen_lines = set()
    for idx, line in enumerate(lines):
        stripped = code_line(line).strip()
        if not stripped or 'ubs:ignore' in line or (idx > 0 and 'ubs:ignore' in lines[idx - 1]):
            continue
        if function_boundary_re.search(stripped):
            tainted_vars = {}
            continue
        statement = statement_from(lines, idx)
        assignment = assignment_re.search(stripped)
        if assignment:
            name = assignment.group(1)
            if has_safe_validation(statement):
                tainted_vars.pop(name, None)
            elif source_re.search(statement) or tainted_ref(statement, tainted_vars):
                tainted_vars[name] = idx
            else:
                tainted_vars.pop(name, None)
        direct = bool(source_re.search(statement))
        ref = tainted_ref(statement, tainted_vars)
        if not direct and not ref:
            continue
        if not absolute_url_re.search(statement):
            continue
        if has_safe_validation(statement) or has_safe_validation(context_from(lines, idx), ref):
            continue
        if idx in seen_lines:
            continue
        seen_lines.add(idx)
        match = source_re.search(line) or absolute_url_re.search(line)
        yield idx + 1, (match.start() + 1) if match else 1


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


def _selftest_host_template_flagged(tmp_prefix: str = "ubs_core_sec_host_header_") -> None:
    import tempfile

    src = "\n".join([
        "export function passwordResetUrl(req: any, token: string): string {",
        "  const host = req.headers.host ?? \"app.example.com\";",
        "  return `https://${host}/reset?token=${token}`;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "reset.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert len(findings) == 1, findings
        assert findings[0][0] == 3, findings


def _selftest_new_url_and_headers_call_flagged(tmp_prefix: str = "ubs_core_sec_host_header_url_") -> None:
    import tempfile

    src = "\n".join([
        "declare function headers(): { get(name: string): string | null };",
        "",
        "export function nextHeadersCanonicalUrl(pathname: string): string {",
        "  const origin = `https://${headers().get(\"host\")}`;",
        "  return new URL(pathname, origin).toString();",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "url.ts"
        target.write_text(src, encoding="utf-8")
        findings = list(scan_file_findings(target))
        assert [line for line, _col in findings] == [4, 5], findings


def _selftest_allowlist_context_suppressed(tmp_prefix: str = "ubs_core_sec_host_header_safe_") -> None:
    import tempfile

    src = "\n".join([
        "const ALLOWED_HOSTS = new Set([\"app.example.com\"]);",
        "",
        "export function resetUrl(req: any): string {",
        "  const host = req.headers.host ?? \"\";",
        "  if (!ALLOWED_HOSTS.has(host)) {",
        "    throw new Error(\"untrusted host\");",
        "  }",
        "  return `https://${host}/reset`;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_canonical_env_suppressed(tmp_prefix: str = "ubs_core_sec_host_header_env_") -> None:
    import tempfile

    src = "\n".join([
        "export function canonicalUrl(pathname: string): string {",
        "  return new URL(pathname, process.env.NEXT_PUBLIC_APP_URL).toString();",
        "}",
        "",
        "export function auditedHost(req: any): boolean {",
        "  const host = req.headers.host || \"\";",
        "  return host.length > 0;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "env.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_ignore_placement_suppressed(tmp_prefix: str = "ubs_core_sec_host_header_ign_") -> None:
    import tempfile

    src = "\n".join([
        "export function resetUrl(req: any): string {",
        "  const host = req.headers.host ?? \"\";",
        "  // ubs:ignore",
        "  return `https://${host}/reset`;",
        "}",
        "",
    ])
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ign.ts"
        target.write_text(src, encoding="utf-8")
        assert list(scan_file_findings(target)) == []


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_sec_host_header_run_") -> None:
    import tempfile

    src = ("export function resetUrl(req: any): string {\n"
           "  const host = req.headers.host ?? \"\";\n"
           "  return `https://${host}/reset`;\n"
           "}\n")
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "reset.ts"
        target.write_text(src, encoding="utf-8")
        ctx = RunContext(lang="javascript", files=[target])
        records = list(run(ctx))
        assert len(records) == 1, records
        rec = records[0]
        assert rec["rule"] == RULE, rec
        assert rec["category_id"] == CATEGORY_ID, rec
        assert rec["severity"] == SEVERITY, rec
        assert rec["line"] == 3, rec
        assert "Host header" in rec["message"], rec


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("host-template-flagged", _selftest_host_template_flagged),
    ("new-url-and-headers-call-flagged", _selftest_new_url_and_headers_call_flagged),
    ("allowlist-context-suppressed", _selftest_allowlist_context_suppressed),
    ("canonical-env-suppressed", _selftest_canonical_env_suppressed),
    ("ignore-placement-suppressed", _selftest_ignore_placement_suppressed),
    ("run-record-shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="sec_host_header", run=run, selftests=SELF_TESTS))
