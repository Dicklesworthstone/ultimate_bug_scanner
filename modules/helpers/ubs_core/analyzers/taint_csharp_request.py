"""ubs_core.analyzers.taint_csharp_request — request path → file-sink taint (bead A2).

Verbatim port of the `run_request_path_traversal_checks` python heredoc in
modules/ubs-csharp.sh: request-derived paths (Query/Form/RouteValues/Headers/
Cookies, Request.Path*, IFormFile.FileName) reaching file read/write/serve
sinks in C# sources. `main` reproduces the heredoc's `path:line:code` emit
dialect over a NUL-delimited file list; `run` yields the same detections as
structured NDJSON findings over ctx.files.
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

SOURCE_RE = re.compile(
    r'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\s*\[[^\]]+\]'
    r'|\b(?:HttpContext\.)?Request\.(?:Path|PathBase|RawTarget|QueryString)\b(?:\.Value\b)?'
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.FileName\b',
    re.IGNORECASE,
)
TRYGET_SOURCE_RE = re.compile(
    r'\b(?:HttpContext\.)?Request\.(?:Query|Form|RouteValues|Headers|Cookies)\.TryGetValue\s*\('
    r'[^)]*,\s*out\s+(?:var\s+|[A-Za-z_][A-Za-z0-9_<>, ?]*\s+)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFE_EXPR_RE = re.compile(
    r'\bPath\.GetFileName(?:WithoutExtension)?\s*\('
    r'|\b(?:Safe(?:Path|File|Filename|UploadPath|DownloadPath|UnderRoot)|'
    r'Secure(?:Path|File|Filename|UploadPath|DownloadPath|UnderRoot)|'
    r'Sanitize(?:Path|Filename|FileName)|Clean(?:Filename|FileName)|'
    r'Validate(?:Path|Filename|FileName)|ResolveUnderRoot|EnsureInsideRoot|'
    r'AssertInsideRoot|IsSafePath|AllowedFile|SafeUploadPath|SafeDownloadPath)\b',
    re.IGNORECASE,
)
CONTAINMENT_CANON_RE = re.compile(r'\bPath\.(?:GetFullPath|GetRelativePath)\s*\(')
CONTAINMENT_GUARD_RE = re.compile(
    r'\.StartsWith\s*\('
    r'|\bPath\.GetRelativePath\s*\('
    r'|\bStringComparison\.[A-Za-z]+\b'
    r'|\b(?:throw|return\s+false|continue)\b'
    r'|\b(?:IsSubPathOf|IsPathInside|InsideRoot|WithinRoot|EnsureInsideRoot)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bFile\.(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenWrite|Open|Create|CreateText|'
    r'WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|AppendText|Delete|Move|Copy|Replace|Exists)\s*\('
    r'|\bDirectory\.(?:CreateDirectory|Delete|Move|EnumerateFiles|GetFiles|EnumerateFileSystemEntries|GetFileSystemEntries)\s*\('
    r'|\bnew\s+(?:FileStream|StreamReader|StreamWriter)\s*\('
    r'|\b(?:PhysicalFile|VirtualFile|Results\.File|FileStreamResult)\s*\('
    r'|\.SendFileAsync\s*\(',
)
ASSIGN_RE = re.compile(
    r'^\s*(?:var|string|String|PathString|IFormFile|FileInfo|FileStream|Stream)?\s*'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+)$'
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


def taint_from_tryget(statement):
    match = TRYGET_SOURCE_RE.search(statement)
    if not match:
        return None
    lhs = match.group('lhs')
    return lhs, {'path': [match.group(0).split(',')[0].strip() + ')']}


def has_containment_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 20)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    if SAFE_EXPR_RE.search(context):
        return True
    return bool(CONTAINMENT_CANON_RE.search(context) and CONTAINMENT_GUARD_RE.search(context))


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ((SOURCE_RE.search(text) or TRYGET_SOURCE_RE.search(text)) and SINK_RE.search(text)):
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
        tryget = taint_from_tryget(statement)
        if tryget:
            tainted[tryget[0]] = tryget[1]
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


_RUN_MESSAGE = "Request-derived path reaches file read/write/serve sink"


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
                "rule": "csharp.taint.request_traversal",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "severity": "critical",
                "message": _RUN_MESSAGE,
            }


def _selftest_direct_source_to_sink() -> None:
    import tempfile

    code = (
        "var p = Request.Query[\"path\"];\n"
        "System.IO.File.ReadAllText(p);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_request_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.taint.request_traversal"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "var p = Request.Query[\"path\"];\n"
        "System.IO.File.ReadAllText(p);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_request_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


def _selftest_containment_guard_suppression() -> None:
    import tempfile

    code = (
        "var p = Request.Query[\"path\"];\n"
        "var root = \"/srv/uploads\";\n"
        "var full = Path.GetFullPath(root + p);\n"
        "if (!full.StartsWith(root, StringComparison.Ordinal)) { return; }\n"
        "System.IO.File.ReadAllText(full);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_request_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_sink", _selftest_direct_source_to_sink),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("containment_guard_suppression", _selftest_containment_guard_suppression),
)

register(Analyzer(layer="taint", lang="csharp", name="taint_csharp_request", run=run, selftests=SELF_TESTS))
