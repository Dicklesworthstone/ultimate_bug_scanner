"""ubs_core.analyzers.taint_cpp_redirect — C++ open-redirect taint (bead A2).

Logic moved verbatim from the open-redirect heredoc in modules/ubs-cpp.sh
(run_open_redirect_checks); the shell keeps its copy until that module's port
bead. `main()` reproduces the heredoc's __COUNT__/__SAMPLE__ output exactly for
the same argv; run(ctx) exposes the same detections as structured findings.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

REDIRECT_KEY = r'(?:return[_-]?to|return[_-]?url|redirect(?:[_-]?url)?|next|continue|callback|target|destination|location|uri|url)'
SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:host|target|raw_url|url)\b'
    r'|\b(?:FCGX_GetParam)\s*\('
    r'|\bgetenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_REFERER|HTTP_REFERRER|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:cgiFormString|FCGX_GetParam|getenv)\s*\('
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
CGI_FORM_OUT_RE = re.compile(
    rf'\bcgiFormString\s*\(\s*["\'][^"\']*{REDIRECT_KEY}[^"\']*["\']\s*,\s*(?:&\s*)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*,',
    re.IGNORECASE,
)
REDIRECTISH_NAME_RE = re.compile(
    r'(redirect|return|callback|next|continue|target|destination|location|uri|url)',
    re.IGNORECASE,
)
HOST_SOURCE_RE = re.compile(
    r'\b(?:req|request)(?:\.|->)host\b|\bgetenv\s*\(\s*"HTTP_HOST"\s*\)|\b(?:getHost|get_host|host)\s*\(',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'safe_(?:redirect_url|redirect_uri|redirect_target)|'
    r'validate(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'validate_(?:redirect_url|redirect_uri|redirect_target)|'
    r'validated(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'validated_(?:redirect_url|redirect_uri|redirect_target)|'
    r'sanitize(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'sanitize_(?:redirect_url|redirect_uri|redirect_target)|'
    r'allowed(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectHost|RedirectTarget)|'
    r'allowed_(?:redirect_url|redirect_uri|redirect_host|redirect_target)|'
    r'local(?:RedirectURL|RedirectUrl|RedirectURI|RedirectUri|RedirectTarget)|'
    r'local_(?:redirect_url|redirect_uri|redirect_target)|'
    r'sameOriginRedirect|same_origin_redirect|isLocalRedirect|is_local_redirect|'
    r'isAllowedRedirectHost|is_allowed_redirect_host)\b',
    re.IGNORECASE,
)
URL_PARSE_RE = re.compile(r'\b(?:Poco::URI|QUrl|ada::parse|boost::urls::parse_uri|boost::urls::url_view|curl_url)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\b(?:allowedRedirectHosts|allowed_redirect_hosts|allowedHosts|allowed_hosts|redirectHostAllowlist|'
    r'redirect_host_allowlist|trustedRedirectHosts|trusted_redirect_hosts|isAllowedRedirectHost|is_allowed_redirect_host)\b'
    r'|\.\s*(?:host|scheme|getHost|getScheme|isValid)\s*\('
    r'|\b(?:starts_with|rfind|compare)\s*\([^;\n]*https://',
    re.IGNORECASE,
)
LOCAL_PATH_RE = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:starts_with|rfind)\s*\(\s*["\']/["\'](?:\s*,\s*0)?\s*\)\s*(?:==\s*0)?'
    r'(?:(?!;).)*(?:&&|\band\b)(?:(?!;).)*(?:!\s*)?\1\s*\.\s*(?:starts_with|rfind)\s*\(\s*["\']//["\'](?:\s*,\s*0)?\s*\)\s*(?:!=\s*0|==\s*(?:false|std::string::npos))?'
    r'|(?:!\s*)?\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:starts_with|rfind)\s*\(\s*["\']//["\'](?:\s*,\s*0)?\s*\)\s*(?:!=\s*0|==\s*(?:false|std::string::npos))?'
    r'(?:(?!;).)*(?:&&|\band\b)(?:(?!;).)*\2\s*\.\s*(?:starts_with|rfind)\s*\(\s*["\']/["\'](?:\s*,\s*0)?\s*\)\s*(?:==\s*0)?',
    re.IGNORECASE | re.DOTALL,
)
REJECT_RE = re.compile(
    r'\b(?:throw|return\s+false|return\s+\{\}|abort|forbid|deny|invalid_argument|runtime_error|domain_error)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:res|resp|response|reply|http_response|httpResponse|ctx|context)(?:\.|->)\s*'
    r'(?:redirect|Redirect|sendRedirect|setRedirect)\s*\('
    r'|\b(?:redirect|send_redirect|sendRedirect|http_redirect|httpRedirect)\s*\('
    r'|\b(?:set_header|setHeader|add_header|addHeader|header|set)\s*\([^;\n]*(?:"Location"|\'Location\')\s*,'
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_header|setHeader|add_header|addHeader|header|set)\s*\([^;\n]*(?:"Location"|\'Location\')\s*,'
    r'|\b(?:headers|response_headers|resp_headers)\s*\[\s*(?:"Location"|\'Location\')\s*\]\s*='
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:headers|response_headers|resp_headers)\s*\[\s*(?:"Location"|\'Location\')\s*\]\s*=',
)
ASSIGN_RE = re.compile(
    r'^\s*(?:const\s+)?(?:auto|std::string(?:_view)?|string(?:_view)?|'
    r'QUrl|Poco::URI|boost::urls::url(?:_view)?|char\s*(?:const\s*)?\*|const\s+char\s*\*)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
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
    has_end = ';' in statement or '{' in statement or '}' in statement
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') - next_line.count(')')
        has_end = has_end or ';' in next_line or '{' in next_line or '}' in next_line
        lookahead += 1
    return statement

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def is_safe_expr(expr):
    return bool(SAFE_EXPR_RE.search(expr))

def has_request_source(expr, target_name=''):
    if SOURCE_RE.search(expr):
        return bool(REDIRECTISH_NAME_RE.search(expr) or HOST_SOURCE_RE.search(expr))
    return bool(target_name and REDIRECTISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(expr))

def refs_in_expr(expr, tainted):
    refs = []
    for name in tainted:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            refs.append(name)
    return refs

def taint_from_expr(expr, tainted, target_name=''):
    if is_safe_expr(expr):
        return None
    direct = SOURCE_RE.search(expr)
    if direct and has_request_source(expr, target_name):
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

def has_redirect_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_EXPR_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(
        (URL_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))
        or (LOCAL_PATH_RE.search(context) and REJECT_RE.search(context))
    )

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (REQUEST_COLLECTION_RE.search(text) and SINK_RE.search(text)):
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
        cgi_out = CGI_FORM_OUT_RE.search(statement)
        if cgi_out:
            name = cgi_out.group('lhs')
            tainted[name] = {'path': [f"cgiFormString(..., {name}, ...)"]}
        assign = ASSIGN_RE.match(statement)
        if assign:
            name = assign.group('lhs')
            rhs = assign.group('rhs')
            taint = taint_from_expr(rhs, tainted, name)
            if taint:
                tainted[name] = taint
            else:
                tainted.pop(name, None)
        if not SINK_RE.search(statement):
            continue
        if is_safe_expr(statement):
            continue
        direct = SOURCE_RE.search(statement) and has_request_source(statement)
        refs = refs_in_expr(statement, tainted)
        if not direct and not refs:
            continue
        if has_redirect_validation_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip('(')} -> redirect"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:5]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_KIND = "open_redirect"
_SEVERITY = "critical"
_MESSAGE = "Unvalidated redirect from request data"


def _path_desc(code: str) -> str:
    """Recover the taint-flow description from an analyze() sample row."""
    if "  [" in code and code.endswith("]"):
        return code.rsplit("  [", 1)[1][:-1]
    return code


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR
    cwd = Path.cwd()
    BASE_DIR = cwd
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        if should_skip(path):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        issues = []
        analyze(path, issues)
        for _rel, line_no, code in issues:
            yield {
                "rule": f"cpp.taint.{_KIND}",
                "path": str(rel),
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "cpp",
                "severity": _SEVERITY,
                "message": f"{_MESSAGE} ({_path_desc(code)})",
            }


def _selftest_direct_redirect(tmp_prefix: str = "ubs_core_taint_cpp_redir_") -> None:
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "cpp.taint.open_redirect", findings
    assert findings[0]["line"] == 2, findings
    assert "req.getParam -> redirect" in findings[0]["message"], findings


def _selftest_validation_context_suppression(tmp_prefix: str = "ubs_core_taint_cpp_redir_val_") -> None:
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "if (url.starts_with(\"/\") && !url.starts_with(\"//\")) return false;\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert findings == [], findings


def _selftest_sanitizer_suppression(tmp_prefix: str = "ubs_core_taint_cpp_redir_san_") -> None:
    import tempfile

    code = (
        "std::string url = validate_redirect_target(req.getParam(\"next\"));\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_cpp_redir_main_") -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "std::string url = req.getParam(\"next\");\n"
        "res.redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["taint_cpp_redirect.py", tmp])
    out = buf.getvalue()
    assert rc == 0, rc
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tmain.cpp\t2\tres.redirect(url);  [req.getParam -> redirect]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_redirect", _selftest_direct_redirect),
    ("validation_context_suppression", _selftest_validation_context_suppression),
    ("sanitizer_suppression", _selftest_sanitizer_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="cpp", name="taint_cpp_redirect", run=run, selftests=SELF_TESTS))
