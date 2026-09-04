"""ubs_core.analyzers.taint_cpp_traversal — C++ request-path traversal taint (bead A2).

Logic moved verbatim from the path-traversal heredoc in modules/ubs-cpp.sh
(run_path_traversal_checks); the shell keeps its copy until that module's port
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

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getPath|getPathInfo|path|target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:path|target|raw_url|url)\b'
    r'|\b(?:cgiFormString|FCGX_GetParam)\s*\('
    r'|\bgetenv\s*\(\s*"(?:QUERY_STRING|PATH_INFO|REQUEST_URI|SCRIPT_NAME|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:filename|file_name|original_filename|client_filename|getOriginalFilename)\s*(?:\(\s*\))?\b'
)
SAFE_EXPR_RE = re.compile(
    r'\b(?:safe(?:Path|Join|File|Filename|UploadPath|DownloadPath)|safe_(?:path|join|file|filename|upload_path|download_path)|'
    r'secure(?:Path|Join|File|Filename|UploadPath|DownloadPath)|secure_(?:path|join|file|filename|upload_path|download_path)|'
    r'sanitize(?:Path|Filename|FileName)|sanitize_(?:path|filename|file_name)|cleanFilename|clean_filename|'
    r'validate(?:Path|Filename|FileName)|validate_(?:path|filename|file_name)|resolveUnderRoot|resolve_under_root|'
    r'withinRoot|within_root|insideRoot|inside_root|isSafePath|is_safe_path|allowedFile|allowed_file)\b'
    r'|(?:std::filesystem::|filesystem::|fs::)?path\s*\([^;\n]*\)\s*\.\s*filename\s*\('
    r'|\.\s*filename\s*\(',
    re.IGNORECASE,
)
CONTAINMENT_CANON_RE = re.compile(r'\b(?:weakly_canonical|canonical|realpath|lexically_normal)\s*\(')
CONTAINMENT_REL_RE = re.compile(r'\b(?:std::filesystem::|filesystem::|fs::)?(?:relative|proximate)\s*\(|\.\s*lexically_relative\s*\(')
CONTAINMENT_GUARD_RE = re.compile(
    r'\b(?:starts_with|compare|rfind|find)\s*\('
    r'|(?:==|!=)\s*"\.\."'
    r'|(?:==|!=)\s*"\.\./"'
    r'|(?:throw|return\s+false|return\s+\{\}|continue)\b'
    r'|\b(?:insideRoot|inside_root|withinRoot|within_root|isSubpath|is_subpath|isDescendant|is_descendant)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:std::)?(?:ifstream|ofstream|fstream)\s+[A-Za-z_][A-Za-z0-9_]*\s*\('
    r'|\b(?:fopen|freopen|open|openat|creat|remove|unlink|rename|mkdir|mkdirat)\s*\('
    r'|\b(?:std::filesystem::|filesystem::|fs::)(?:remove|remove_all|copy_file|rename|create_directories|permissions|exists|file_size)\s*\('
    r'|\b(?:send_file|sendfile|serve_file|serveFile|set_file_content|set_static_file_info|write_file_response)\s*\('
)
ASSIGN_RE = re.compile(
    r'^\s*(?:const\s+)?(?:auto|std::string(?:_view)?|string(?:_view)?|'
    r'(?:std::)?filesystem::path|fs::path|char\s*(?:const\s*)?\*|const\s+char\s*\*)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
)
IDENT_RE = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
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

def has_containment_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    if SAFE_EXPR_RE.search(context):
        return True
    return bool(
        CONTAINMENT_CANON_RE.search(context)
        and CONTAINMENT_REL_RE.search(context)
        and CONTAINMENT_GUARD_RE.search(context)
    )

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
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
        if has_containment_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            path_desc = f"{direct.group(0).strip('(')} -> file sink"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('file sink')
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


_KIND = "path_traversal"
_SEVERITY = "critical"
_MESSAGE = "Request-derived path reaches file read/write/serve sink"


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


def _selftest_direct_source_sink(tmp_prefix: str = "ubs_core_taint_cpp_trav_") -> None:
    import tempfile

    code = (
        "std::string p = req.getParam(\"file\");\n"
        "std::ifstream in(p);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "cpp.taint.path_traversal", findings
    assert findings[0]["line"] == 2, findings
    assert "req.getParam -> file sink" in findings[0]["message"], findings


def _selftest_sanitizer_and_ignore_suppression(tmp_prefix: str = "ubs_core_taint_cpp_trav_sup_") -> None:
    import tempfile

    code = (
        "std::string a = sanitize_filename(req.getParam(\"f\"));\n"
        "std::ifstream in1(a);\n"
        "std::string b = req.getParam(\"g\");\n"
        "std::ifstream in2(b);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_cpp_trav_main_") -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "std::string p = req.getParam(\"file\");\n"
        "std::ifstream in(p);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["taint_cpp_traversal.py", tmp])
    out = buf.getvalue()
    assert rc == 0, rc
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tmain.cpp\t2\tstd::ifstream in(p);  [req.getParam -> file sink]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_sink", _selftest_direct_source_sink),
    ("sanitizer_and_ignore_suppression", _selftest_sanitizer_and_ignore_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="cpp", name="taint_cpp_traversal", run=run, selftests=SELF_TESTS))
