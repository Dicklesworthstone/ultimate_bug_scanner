"""ubs_core.analyzers.taint_swift_redirect — request-derived open redirect taint analysis (bead A2).

Logic moved verbatim from the run_request_open_redirect_checks heredoc in
modules/ubs-swift.sh, which keeps its own copy until that module's port bead.
Also exposes a structured `run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'DerivedData', 'build', 'dist', 'vendor', '.build', '.swiftpm'}
name_re = r'[A-Za-z_][A-Za-z0-9_]*'
assign_re = re.compile(rf'\b(?:let|var)\s+({name_re})\s*(?::[^=]+)?=\s*(.+)')
redirect_key = r'(?:return[_-]?to|return[_-]?url|redirect(?:[_-]?url)?|next|continue|callback|target|destination|location|url|uri)'
request_source = re.compile(
    rf'\b(?:req|request)\s*\.\s*(?:query|parameters|params)\s*(?:\[[^\]]*{redirect_key}[^\]]*\]|\.\s*get\s*\([^)]*{redirect_key}[^)]*\))|'
    rf'\b(?:req|request)\s*\.\s*headers\s*(?:\[[^\]]*{redirect_key}[^\]]*\]|\.\s*first\s*\([^)]*{redirect_key}[^)]*\)|\.\s*get\s*\([^)]*{redirect_key}[^)]*\))|'
    r'\b(?:req|request)\s*\.\s*(?:url|uri)\s*(?:\.\s*(?:string|absoluteString|description|host|path|query))?\b|'
    rf'\b(?:req|request)\s*\.\s*content\s*\.\s*get\s*\([^)]*\bat\s*:\s*["\'][^"\']*{redirect_key}[^"\']*["\']',
    re.IGNORECASE,
)
request_collection_source = re.compile(
    r'\b(?:req|request)\s*\.\s*(?:query|parameters|params|headers)\b(?:\s*\[[^\]]+\]|\s*\.\s*(?:get|first)\s*\([^)]*\))?',
    re.IGNORECASE,
)
content_source = re.compile(r'\b(?:req|request)\s*\.\s*content\b')
redirectish_name = re.compile(r'(redirect|return|callback|next|continue|target|destination|location|url|uri)', re.IGNORECASE)
safe_named = re.compile(
    r'\b(?:safeRedirect(?:URL|URI|Target)?|validatedRedirect(?:URL|URI|Target)?|'
    r'validateRedirect(?:URL|URI|Target)?|sanitizeRedirect(?:URL|URI|Target)?|'
    r'allowedRedirect(?:URL|URI|Host|Target)?|sameOriginRedirect(?:URL|URI|Target)?|'
    r'localRedirect(?:URL|URI|Target)?|isLocalRedirect|isAllowedRedirectHost|'
    r'url_from|urlFrom)\b',
    re.IGNORECASE,
)
url_parse_re = re.compile(r'\b(?:URL|URLComponents)\s*\(\s*(?:string\s*:)?')
host_check_re = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowedRedirectHosts|allowedHosts|allowedHost|redirectHostAllowlist|trustedRedirectHosts)\b|'
    r'\.contains\s*\('
)
local_path_check_re = re.compile(
    r'\.hasPrefix\s*\(\s*["\']/["\']\s*\).*!\s*[A-Za-z_][A-Za-z0-9_]*\.hasPrefix\s*\(\s*["\']//["\']\s*\)|'
    r'!\s*[A-Za-z_][A-Za-z0-9_]*\.hasPrefix\s*\(\s*["\']//["\']\s*\).*\.hasPrefix\s*\(\s*["\']/["\']\s*\)',
    re.DOTALL,
)
reject_re = re.compile(r'\b(?:throw|return(?:\s+(?:nil|false))?|abort|preconditionFailure)\b')
sink_re = re.compile(
    r'\b(?:req|request)\s*\.\s*redirect\s*\(\s*to\s*:|'
    r'\b(?:Response|HTTPResponse)\s*\.\s*redirect\s*\(\s*to\s*:|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*redirect\s*\(\s*to\s*:|'
    r'\bredirect\s*\(\s*(?:to\s*:)?|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\.headers\s*\[\s*["\']Location["\']\s*\]\s*=|'
    r'\bheaders\s*\[\s*["\']Location["\']\s*\]\s*=|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\.headers\s*\.\s*(?:add|replaceOrAdd)\s*\([^)]*name\s*:\s*\.?\s*location[^)]*value\s*:|'
    r'\bheaders\s*\.\s*(?:add|replaceOrAdd)\s*\([^)]*name\s*:\s*\.?\s*location[^)]*value\s*:|'
    r'\bHTTPHeaders\s*\(\s*\[\s*\(\s*["\']Location["\']',
    re.IGNORECASE,
)
PATH_LIMIT = 4


def should_skip(path: Path, base: Path) -> bool:
    try:
        parts = path.relative_to(base).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)


def iter_swift_files(path: Path, base: Path):
    if path.is_file():
        if path.suffix == '.swift':
            yield path
        return
    for candidate in path.rglob('*.swift'):
        if candidate.is_file() and not should_skip(candidate, base):
            yield candidate


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
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
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        out.append(ch)
        i += 1
    return ''.join(out)


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        lookahead += 1
    return statement


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def source_line(lines, line_no):
    idx = line_no - 1
    return lines[idx].strip() if 0 <= idx < len(lines) else ''


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def is_safe_expression(statement: str) -> bool:
    return bool(safe_named.search(statement))


def has_source(statement: str, target_name: str = '') -> bool:
    if request_source.search(statement):
        return True
    if target_name and redirectish_name.search(target_name) and request_collection_source.search(statement):
        return True
    return bool(target_name and redirectish_name.search(target_name) and content_source.search(statement))


def refs_in_expr(expr: str, tainted: dict[str, dict]) -> list[str]:
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def taint_from_expr(expr: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = request_source.search(expr)
        return {'path': [(source.group(0) if source else target_name or 'request content').strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_redirect_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if safe_named.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(
        (url_parse_re.search(context) and host_check_re.search(context) and reject_re.search(context))
        or (local_path_check_re.search(context) and reject_re.search(context))
    )


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, int, str]]:
    """Return (rel_path, line_no, annotated source) findings for one file's text (heredoc loop verbatim)."""
    if not (re.search(r'\b(?:req|request)\b', text) and sink_re.search(text)):
        return []

    lines = text.splitlines()
    tainted: dict[str, dict] = {}
    seen: set[tuple[str, int]] = set()
    findings: list[tuple[str, int, str]] = []
    for line_no, _ in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        statement = logical_statement(lines, line_no).strip()
        if not statement:
            continue

        assignment = assign_re.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_expr(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif variable in tainted and is_safe_expression(rhs):
                tainted.pop(variable, None)

        if not sink_re.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_redirect_validation_context(lines, line_no, refs):
            continue
        key = (rel(path, base), line_no)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = request_source.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> redirect"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect')
            path_desc = ' -> '.join(seq)
        findings.append((rel(path, base), line_no, f"{source_line(lines, line_no)} [{path_desc}]"))
    return findings


def collect_findings(root: Path) -> list[tuple[str, int, str]]:
    root = Path(root).resolve()
    base = root if root.is_dir() else root.parent
    findings: list[tuple[str, int, str]] = []
    for path in iter_swift_files(root, base):
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        findings.extend(scan_text(path, text, base))
    return findings


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: taint_swift_redirect.py <project_dir>", file=sys.stderr)
        return 2
    findings = collect_findings(Path(sys.argv[1]).resolve())
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    print(f"{len(findings)}\t{samples}")
    return 0


_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix != '.swift':
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for rel_path, line_no, _code in scan_text(path, text, cwd):
            yield {
                "rule": "swift.taint.request_open_redirect",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "swift",
                "severity": "critical",
                "message": _MESSAGE,
            }


def _selftest_detects_query_redirect() -> None:
    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    findings = scan_text(Path("F.swift"), code, Path("."))
    assert len(findings) == 1, findings
    assert findings[0][1] == 3, findings
    assert findings[0][2].endswith("[req.query[\"returnUrl\"] -> redirect]"), findings


def _selftest_validation_context_suppression() -> None:
    code = (
        "func localOnly(req: Request) throws -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    guard let url = URL(string: target), let host = url.host, allowedHosts.contains(host) else {\n"
        "        throw Abort(.badRequest)\n"
        "    }\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target) // ubs:ignore\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_taint_swift_redirect_") -> None:
    import tempfile

    code = (
        "func queryRedirect(req: Request) -> Response {\n"
        "    let target = req.query[\"returnUrl\"] ?? \"/\"\n"
        "    return req.redirect(to: target)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "F.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.taint.request_open_redirect", findings
    assert findings[0]["line"] == 3, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_query_redirect", _selftest_detects_query_redirect),
    ("validation_context_suppression", _selftest_validation_context_suppression),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("run_finds_redirect", _selftest_run),
)

register(Analyzer(layer="taint", lang="swift", name="taint_swift_redirect", run=run, selftests=SELF_TESTS))
