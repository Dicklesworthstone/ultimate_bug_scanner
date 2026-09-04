"""ubs_core.analyzers.taint_swift_traversal — request-derived path traversal taint analysis (bead A2).

Logic moved verbatim from the run_request_path_traversal_checks heredoc in
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
request_source = re.compile(
    r'\b(?:req|request)\s*\.\s*(?:query|parameters|params)\b|'
    r'\b(?:req|request)\s*\.\s*headers\s*(?:\[[^\]]+\]|\.\s*(?:get|first)\s*\([^)]*\))|'
    r'\b(?:req|request)\s*\.\s*url\s*\.\s*(?:path|string)\b|'
    r'\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:filename|fileName|originalFilename|originalFileName)\b'
)
content_path_source = re.compile(
    r'\b(?:req|request)\s*\.\s*content\s*\.\s*get\s*\([^)]*\bat\s*:\s*'
    r'["\'][^"\']*(?:path|file|filename|name|dir|folder|target|destination|download|upload)[^"\']*["\']',
    re.IGNORECASE,
)
content_source = re.compile(r'\b(?:req|request)\s*\.\s*content\b')
sink_re = re.compile(
    r'\b(?:String|Data)\s*\(\s*contentsOf(?:File)?\s*:|'
    r'\bFileManager\.default\.(?:removeItem|copyItem|moveItem|createDirectory|createFile|'
    r'contentsOfDirectory|attributesOfItem|fileExists)\s*\(|'
    r'\bFileHandle\s*\(\s*for(?:Reading|Writing|Updating)(?:From|To|AtPath)\s*:|'
    r'\.write\s*\(\s*to\s*:|'
    r'\b(?:sendFile|streamFile|readFile|serveFile)\s*\(|'
    r'\b(?:req|request)\s*\.\s*fileio\s*\.\s*(?:streamFile|readFile|writeFile)\s*\(|'
    r'\bResponse\s*\.\s*(?:file|sendFile)\s*\('
)
safe_named = re.compile(
    r'\b(?:safePath|safeURL|safeFileName|safeFilename|sanitizeFilename|sanitizeFileName|'
    r'sanitizePath|sanitizedFilename|sanitizedFileName|validatedPath|validatePath|'
    r'safeUnderRoot|resolveUnderRoot|ensureInsideRoot|containedPath|allowedFile|'
    r'canonicalPathInside)\b',
    re.IGNORECASE,
)
pathish_name = re.compile(r'(path|file|name|dir|folder|target|destination|download|upload|export|key)', re.IGNORECASE)


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


def context_around(lines, line_no):
    start = max(0, line_no - 12)
    end = min(len(lines), line_no + 12)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def is_pathish(variable: str) -> bool:
    return bool(pathish_name.search(variable))


def has_source(statement: str, target_name: str = '') -> bool:
    if request_source.search(statement) or content_path_source.search(statement):
        return True
    return bool(target_name and is_pathish(target_name) and content_source.search(statement))


def is_safe_expression(statement: str) -> bool:
    return bool(
        safe_named.search(statement)
        or '.lastPathComponent' in statement
        or re.search(r'\bURL\s*\([^)]*\)\s*\.\s*lastPathComponent\b', statement)
    )


def has_containment_context(context: str) -> bool:
    lower = context.lower()
    has_canonical = (
        'standardizedfileurl' in lower or
        'resolvingsymlinksinpath' in lower or
        'standardizedpath' in lower
    )
    has_anchor = 'hasprefix' in lower or 'relativepath' in lower
    rejects_escape = 'throw ' in lower or 'return false' in lower or 'guard ' in lower
    return has_canonical and has_anchor and rejects_escape


def contains_tainted_path(statement: str, tainted: set[str]) -> bool:
    if has_source(statement):
        return True
    return any(re.search(rf'\b{re.escape(var)}\b', statement) for var in tainted)


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def source_line(lines, line_no):
    idx = line_no - 1
    return lines[idx].strip() if 0 <= idx < len(lines) else ''


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, int, str]]:
    """Return (rel_path, line_no, source_line) findings for one file's text (heredoc loop verbatim)."""
    if not (
        re.search(r'\b(?:req|request)\b', text)
        or re.search(r'\b(?:filename|fileName|originalFilename|originalFileName)\b', text)
    ):
        return []

    lines = text.splitlines()
    tainted = set()
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
            if is_safe_expression(rhs):
                tainted.discard(variable)
            elif has_source(rhs, variable) or contains_tainted_path(rhs, tainted):
                tainted.add(variable)
            else:
                tainted.discard(variable)

        if not sink_re.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        if not contains_tainted_path(statement, tainted):
            continue
        if has_containment_context(context_around(lines, line_no)):
            continue
        findings.append((rel(path, base), line_no, source_line(lines, line_no)))
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
        print("usage: taint_swift_traversal.py <project_dir>", file=sys.stderr)
        return 2
    findings = collect_findings(Path(sys.argv[1]).resolve())
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    print(f"{len(findings)}\t{samples}")
    return 0


_MESSAGE = "Request-derived path reaches file read/write/serve sink"


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
                "rule": "swift.taint.request_path_traversal",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "swift",
                "severity": "critical",
                "message": _MESSAGE,
            }


def _selftest_detects_tainted_file_sink() -> None:
    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path)\n"
        "}\n"
    )
    findings = scan_text(Path("F.swift"), code, Path("."))
    assert len(findings) == 1, findings
    assert findings[0][1] == 4, findings
    assert findings[0][2] == "return try String(contentsOfFile: path)", findings


def _selftest_basename_suppression() -> None:
    code = (
        "func safeRead(req: Request) throws -> String {\n"
        "    let requested = req.query[\"file\"] ?? \"index.html\"\n"
        "    let name = URL(fileURLWithPath: requested).lastPathComponent\n"
        "    return try String(contentsOfFile: name)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path) // ubs:ignore\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_taint_swift_traversal_") -> None:
    import tempfile

    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "F.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.taint.request_path_traversal", findings
    assert findings[0]["line"] == 4, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_tainted_file_sink", _selftest_detects_tainted_file_sink),
    ("basename_suppression", _selftest_basename_suppression),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("run_finds_traversal", _selftest_run),
)

register(Analyzer(layer="taint", lang="swift", name="taint_swift_traversal", run=run, selftests=SELF_TESTS))
