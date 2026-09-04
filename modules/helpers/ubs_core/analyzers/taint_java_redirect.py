"""ubs_core.analyzers.taint_java_redirect — request → open-redirect taint (bead A2).

Verbatim port of the `run_open_redirect_checks` python heredoc in
modules/ubs-java.sh: request-derived values reaching redirect sinks
(sendRedirect, redirect views, Location headers) in Java/Kotlin sources.
`main` reproduces the heredoc's `__COUNT__`/`__SAMPLE__` emit dialect;
`run` yields the same detections as structured NDJSON findings.
"""
from __future__ import annotations

from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
import re
import sys
from pathlib import Path

SKIP_DIRS = {'.git', '.gradle', '.mvn', 'build', 'target', 'out', 'node_modules', '.cache'}

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getServerName|getServerPort|getRemoteHost|getRemoteAddr|'
    r'getLocalName|getLocalAddr|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:path|uri|local|host|port|origin|queryParameters|headers|header)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|URI|URL|Object|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'secure(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'validate(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'sanitize(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'allow(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'allowed(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'is(?:Safe|Allowed)(?:Redirect|RedirectURL|RedirectUri|RedirectURI|RedirectTarget|Location|ReturnTo)|'
    r'sameOrigin(?:Redirect|RedirectURL|RedirectUri|URL|URI)?|localRedirect|relativeRedirect|urlFor)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\.\s*sendRedirect\s*\('
    r'|\.\s*respondRedirect\s*\('
    r'|\.\s*redirect\s*\('
    r'|\bnew\s+(?:RedirectView|ModelAndView)\s*\('
    r'|\b(?:RedirectView|ModelAndView)\s*\('
    r'|\breturn\s+["\']redirect:'
    r'|\.\s*(?:setHeader|addHeader|header|add)\s*\(\s*["\']Location["\']\s*,',
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:final\s+)?(?:val|var|String|URI|URL|Object|RedirectView|ModelAndView|ResponseEntity'
    r'|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]+)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.java', '.kt', '.kts'}:
            yield root
        return
    for suffix in ('*.java', '*.kt', '*.kts'):
        for path in root.rglob(suffix):
            if path.is_file() and not should_skip(path):
                yield path

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

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') - statement.count(')')
    stripped = statement.strip()
    has_kotlin_line_end = balance <= 0 and bool(
        re.match(r'(?:val|var|return|throw)\b', stripped) or
        (re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', stripped) is not None)
    )
    has_end = ';' in statement or '{' in statement or '}' in statement or has_kotlin_line_end
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_kotlin_line_end = balance <= 0 and bool(
            re.match(r'(?:val|var|return|throw)\b', next_line) or
            (re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', next_line) is not None)
        )
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line or has_kotlin_line_end
        lookahead += 1
    return statement

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def annotated_sources(text):
    sources = {}
    for match in ANNOTATED_PARAM_RE.finditer(text):
        name = match.group(1)
        sources[name] = {'path': [f'@request {name}']}
    return sources

def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))

def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs

def taint_from_expr(expr, tainted):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct:
        return {'path': [direct.group(0).strip('(')]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}

def has_safe_redirect_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no + 1]]
    ref_lines = [
        line for line in context_lines
        if any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs)
    ]
    if not ref_lines:
        return False
    ref_context = '\n'.join(ref_lines)
    full_context = '\n'.join(context_lines)
    has_blocking_action = re.search(
        r'\b(?:throw|return\s+false|sendError|abort|forbidden|badRequest|ResponseStatusException|'
        r'IllegalArgumentException|SecurityException|require)\b',
        full_context,
        re.IGNORECASE,
    )
    return bool(SAFE_EXPR_RE.search(ref_context) and has_blocking_action)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = annotated_sources(text)
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_safe_redirect_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> redirect sink"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect sink')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))

def main(argv: list[str] | None = None) -> int:
    """Reproduce the module heredoc: `python3 - <project_dir> <<PY` emit dialect."""
    global ROOT, BASE_DIR

    argv = sys.argv if argv is None else list(argv)
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_RUN_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR

    BASE_DIR = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".java", ".kt", ".kts"}:
            continue
        issues: list[tuple[str, str, int]] = []
        analyze(path, issues)
        for rel_path, line_no, _sample in issues:
            yield {
                "rule": "java.taint.open_redirect",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "severity": "critical",
                "message": _RUN_MESSAGE,
            }


def _selftest_direct_source_to_redirect() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        "response.sendRedirect(target);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "java.taint.open_redirect"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        "response.sendRedirect(target);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert findings == [], findings


def _selftest_allowlist_guard_suppression() -> None:
    import tempfile

    code = (
        "String target = request.getParameter(\"url\");\n"
        "if (!isAllowedRedirect(target)) { throw new SecurityException(\"bad\"); }\n"
        "response.sendRedirect(target);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_redirect_") as tmp:
        target_file = Path(tmp) / "A.java"
        target_file.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target_file])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_redirect", _selftest_direct_source_to_redirect),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("allowlist_guard_suppression", _selftest_allowlist_guard_suppression),
)

register(Analyzer(layer="taint", lang="java", name="taint_java_redirect", run=run, selftests=SELF_TESTS))
