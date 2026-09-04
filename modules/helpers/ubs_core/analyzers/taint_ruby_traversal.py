"""ubs_core.analyzers.taint_ruby_traversal — request-derived filesystem path taint (bead A2).

Logic moved verbatim from the run_path_traversal_checks heredoc in
modules/ubs-ruby.sh; the shell keeps its copy until that module's port bead
lands (transitional duplication is sanctioned). main(argv) reproduces the
heredoc's __COUNT__/__SAMPLE__ stdout byte-for-byte for the same argv;
run(ctx) mirrors the same detection over RunContext.files as NDJSON findings.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT = Path.cwd()
BASE_DIR = ROOT

SKIP_DIRS = {'.git', '.bundle', 'vendor', 'node_modules', 'tmp', 'log', 'coverage', '.cache', 'dist', 'build'}
EXTS = {'.rb', '.rake', '.ru', '.gemspec', '.erb', '.haml', '.slim', '.rbi', '.rbs', '.jbuilder'}

SOURCE_RE = re.compile(
    r'\b(?:params|request\.params)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:path|path_info|fullpath|original_fullpath|query_string|url)\b'
    r'|\b(?:request|req|rack_request)\.(?:get|post|params|query|POST|GET)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.(?:headers|env)\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b(?:request|req|rack_request)\.get_header\s*\('
    r'|\b(?:env|request\.env)\s*\[\s*[\'"](?:PATH_INFO|REQUEST_URI|QUERY_STRING|SCRIPT_NAME|HTTP_[A-Z0-9_]+)[\'"]\s*\]'
    r'|\bRack::Request\.new\s*\([^)]*\)\.params\s*(?:\[[^\]]+\]|\.fetch\s*\(|\.dig\s*\()'
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|\[)[A-Za-z_"\':][A-Za-z0-9_"\'\]:]*\]?\.(?:original_filename|filename)\b'
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:original_filename|filename)\b',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\bFile\.basename\s*\('
    r'|\bPathname\.new\s*\([^;\n]*\)\.basename\b'
    r'|\.basename\b'
    r'|\b(?:safe(?:_path|_join|_file|_filename|_upload_path|_download_path|Path|Join|File|Filename|UploadPath|DownloadPath)|'
    r'secure(?:_path|_join|_file|_filename|_upload_path|_download_path|Path|Join|File|Filename|UploadPath|DownloadPath)|'
    r'sanitize(?:_path|_filename|_file_name|Path|Filename|FileName)|clean(?:_filename|Filename)|'
    r'validate(?:_path|_filename|_file_name|Path|Filename|FileName)|resolve_under_root|resolveUnderRoot|'
    r'safe_under_root|inside_root|insideRoot|within_root|withinRoot|is_safe_path|isSafePath|allowed_file|allowedFile)\b',
    re.IGNORECASE,
)
CONTAINMENT_CANON_RE = re.compile(r'\b(?:File\.expand_path|Pathname\.new|\.realpath\b|\.cleanpath\b)')
CONTAINMENT_GUARD_RE = re.compile(
    r'\.start_with\?\s*\('
    r'|\.relative_path_from\s*\('
    r'|\b(?:raise|return\s+false|next|break)\b'
    r'|\b(?:inside_root\?|within_root\?|safe_path\?|assert_inside_root)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bFile\.(?:read|binread|write|binwrite|open|delete|unlink|rename|chmod|chown|truncate|size|exist\?|directory\?|file\?)\s*\('
    r'|\bIO\.(?:read|binread|write|binwrite|open)\s*\('
    r'|\bFileUtils\.(?:cp|copy|mv|move|rm|remove|rm_f|rm_rf|remove_entry|mkdir|mkdir_p|touch|chmod|chown)\s*\('
    r'|\bDir\.(?:open|foreach|mkdir|entries|children|delete|rmdir)\s*\('
    r'|\b(?:send_file|serve_file|download_file|write_file_response)\s*\(?'
    r'|\brender\s+(?:file|template):',
)
ASSIGN_RE = re.compile(
    r'^\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
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
        if ch == '#':
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
    lookahead = idx + 1
    while balance > 0 and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead])
        statement += ' ' + next_line.strip()
        balance += next_line.count('(') - next_line.count(')')
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
    return bool(CONTAINMENT_CANON_RE.search(context) and CONTAINMENT_GUARD_RE.search(context))

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


def _configure(root: Path) -> None:
    """Bind ROOT/BASE_DIR the way the heredoc derived them from sys.argv[1]."""
    global ROOT, BASE_DIR
    ROOT = root
    BASE_DIR = root if root.is_dir() else root.parent


MESSAGE = "Request-derived path reaches file read/write/serve sink"
REMEDY = (
    "Validate paths with File.expand_path containment checks or reduce upload "
    "names to File.basename before opening, serving, or deleting files"
)


def main(argv: list[str] | None = None) -> int:
    """Print the heredoc's __COUNT__/__SAMPLE__ report for one project dir."""
    if argv is None:
        argv = sys.argv[1:]
    _configure(Path(argv[0]).resolve())
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    """Mirror the heredoc detection over ctx.files as NDJSON findings."""
    _configure(Path.cwd())
    for path in ctx.files:
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            path.relative_to(BASE_DIR)
        except ValueError:
            pass  # outside the scan root: the heredoc's glob never applied SKIP_DIRS there
        else:
            if should_skip(path):
                continue
        issues: list[tuple[str, int, str]] = []
        analyze(path, issues)
        for rel, line_no, code in issues:
            yield {
                "rule": "ruby.taint.path_traversal",
                "path": rel,
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "ruby",
                "severity": "critical",
                "message": f"{MESSAGE}: {code}",
            }


def _selftest_positive_run() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file]\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "ruby.taint.path_traversal", findings
    assert findings[0]["line"] == 4, findings


def _selftest_basename_suppression() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = File.basename(params[:file])\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert findings == [], findings


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file] # ubs:ignore\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        target = Path(tmp) / "app.rb"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="ruby", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect() -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "class Downloads\n"
        "  def show\n"
        "    name = params[:file]\n"
        "    send_file File.join(ROOT, name)\n"
        "  end\n"
        "end\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_taint_ruby_traversal_") as tmp:
        (Path(tmp) / "app.rb").write_text(code, encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main([tmp])
    lines = buffer.getvalue().splitlines()
    assert rc == 0
    assert lines[0] == "__COUNT__\t1", lines
    assert lines[1].startswith("__SAMPLE__\tapp.rb\t4\t"), lines


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("positive_run", _selftest_positive_run),
    ("basename_suppression", _selftest_basename_suppression),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="ruby", name="taint_ruby_traversal", run=run, selftests=SELF_TESTS))
