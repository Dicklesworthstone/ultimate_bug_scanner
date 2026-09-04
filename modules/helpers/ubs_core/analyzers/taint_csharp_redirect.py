"""ubs_core.analyzers.taint_csharp_redirect — request → open-redirect taint (bead A2).

Verbatim port of the `run_request_open_redirect_checks` python heredoc in
modules/ubs-csharp.sh: request-derived redirect targets (returnUrl/url/next/
callback-style keys plus Request.Host/Path*) reaching Redirect/Results.Redirect/
Location-header sinks in C# sources. `main` reproduces the heredoc's
`path:line:code` emit dialect over a NUL-delimited file list; `run` yields the
same detections as structured NDJSON findings over ctx.files.
"""
from __future__ import annotations

from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
import re
import sys
from pathlib import Path

PROJECT_DIR = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
BASE_DIR = PROJECT_DIR if PROJECT_DIR.is_dir() else PROJECT_DIR.parent
FILELIST = Path(sys.argv[2]) if len(sys.argv) > 2 else Path()

REDIRECT_KEY = r'(?:return(?:url|uri|to)?|return_to|redirect(?:url|uri|to)?|next|continue|callback|target|destination|location|url|uri)'

SOURCE_RE = re.compile(
    rf'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\s*\[[^\]]*{REDIRECT_KEY}[^\]]*\]'
    rf'|\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.(?:TryGetValue|ContainsKey)\s*\([^)]*{REDIRECT_KEY}[^)]*\)'
    r'|\b(?:HttpContext\.)?Request\.(?:Host|Path|PathBase|RawTarget|QueryString)\b(?:\.Value\b)?'
    r'|\b(?:ControllerContext|ActionContext)\.HttpContext\.Request\.(?:Host|Path|RawTarget|QueryString)\b',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\s*\[[^\]]+\]'
    r'|\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.(?:TryGetValue|ContainsKey)\s*\(',
    re.IGNORECASE,
)
URLISH_NAME_RE = re.compile(
    r'(?:return(?:url|uri|to)?|return_to|redirect(?:url|uri|to)?|next|continue|callback|target|destination|location|url|uri)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:LocalRedirect|SafeRedirect(?:Url|Uri|Target)?|ValidatedRedirect(?:Url|Uri|Target)?|'
    r'Validate(?:Redirect|Return)(?:Url|Uri|Target)?|SanitizeRedirect(?:Url|Uri|Target)?|'
    r'IsLocalUrl|IsAllowedRedirect(?:Url|Uri|Target)?|AllowedRedirect(?:Url|Uri|Target)?|'
    r'TrustedRedirect(?:Url|Uri|Target)?|SameOriginRedirect(?:Url|Uri|Target)?|'
    r'RequireLocalRedirect|RequireAllowedRedirectHost)\b',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:Uri\.TryCreate|new\s+Uri)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:Scheme|Host|IsLoopback)\b'
    r'|\b(?:AllowedHosts|AllowedRedirectHosts|RedirectAllowlist|TrustedHosts|KnownRedirectOrigins|ALLOWED_HOSTS)\b'
    r'|\.Contains\s*\('
    r'|\bUri\.UriSchemeHttps\b'
    r'|\bStringComparison\.OrdinalIgnoreCase\b',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'\b(?:throw|return\s+(?:null|false)|BadRequest|Forbid|Unauthorized|NotFound)\b', re.IGNORECASE)
SINK_RE = re.compile(
    r'\b(?:Response\.)?Redirect(?:Permanent|PreserveMethod|PermanentPreserveMethod)?\s*\('
    r'|\bResults\.Redirect\s*\('
    r'|\bnew\s+RedirectResult\s*\('
    r"""|\b(?:HttpContext\.)?Response\.Headers\s*\[\s*["']Location["']\s*\]\s*="""
    r"""|\b(?:HttpContext\.)?Response\.Headers\.(?:Append|Add)\s*\(\s*["']Location["']\s*,""",
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(
    r'^\s*(?:var|string|String|Uri|UriBuilder|IActionResult|IResult|RedirectResult|StringValues)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
OUT_PARAM_RE = re.compile(
    rf'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.TryGetValue\s*\([^)]*{REDIRECT_KEY}[^)]*,\s*out\s+'
    r'(?:var\s+|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
PATH_LIMIT = 4


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
    paren_balance = statement.count('(') - statement.count(')')
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (paren_balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        paren_balance += next_line.count('(') - next_line.count(')')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
        lookahead += 1
    return statement


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def load_paths():
    try:
        data = FILELIST.read_bytes().split(b'\0')
    except OSError:
        return []
    return [Path(raw.decode('utf-8', 'ignore')) for raw in data if raw]


def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))


def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs


def has_source(expr, target_name=''):
    if SOURCE_RE.search(expr):
        return True
    return bool(target_name and URLISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(expr))


def taint_from_expr(expr, tainted, target_name=''):
    if is_safe_expr(expr):
        return None
    direct = has_source(expr, target_name)
    if direct:
        source = SOURCE_RE.search(expr)
        return {'path': [(source.group(0) if source else target_name or 'request redirect target').strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}


def has_safe_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:Request|HttpContext)\b', text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        out_param = OUT_PARAM_RE.search(statement)
        if out_param:
            out_source = out_param.group(0).strip()
            if not out_source.endswith(')'):
                out_source += ')'
            tainted[out_param.group('lhs')] = {'path': [out_source]}
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            elif name in tainted and is_safe_expr(rhs):
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = has_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_safe_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request redirect target').strip()} -> redirect sink"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect sink')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))


def main(argv: list[str] | None = None) -> int:
    """Reproduce the module heredoc: `python3 - <project_dir> <nul-filelist> <<PY` emit dialect."""
    global PROJECT_DIR, BASE_DIR, FILELIST

    argv = sys.argv if argv is None else list(argv)
    PROJECT_DIR = Path(argv[1]).resolve()
    BASE_DIR = PROJECT_DIR if PROJECT_DIR.is_dir() else PROJECT_DIR.parent
    FILELIST = Path(argv[2])
    issues = []
    for file_path in load_paths():
        analyze(file_path, issues)
    for file_name, line_no, code in issues:
        print(f"{file_name}:{line_no}:{code}")
    return 0


_RUN_MESSAGE = "Unvalidated redirect from request data"


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR

    BASE_DIR = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        issues: list[tuple[str, str, int]] = []
        analyze(path, issues)
        for rel_path, line_no, _sample in issues:
            yield {
                "rule": "csharp.taint.open_redirect",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "severity": "critical",
                "message": _RUN_MESSAGE,
            }


def _selftest_direct_source_to_sink() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "Response.Redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.taint.open_redirect"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "Response.Redirect(url);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


def _selftest_local_url_guard_suppression() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "if (!Url.IsLocalUrl(url)) { return BadRequest(); }\n"
        "Response.Redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_sink", _selftest_direct_source_to_sink),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("local_url_guard_suppression", _selftest_local_url_guard_suppression),
)

register(Analyzer(layer="taint", lang="csharp", name="taint_csharp_redirect", run=run, selftests=SELF_TESTS))
