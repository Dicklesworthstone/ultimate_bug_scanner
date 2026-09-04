"""ubs_core.analyzers.taint_elixir_traversal — Elixir request path-traversal taint (bead A2).

Logic moved verbatim from the request path-traversal heredoc in
modules/ubs-elixir.sh (run_request_path_traversal_checks), which keeps its own
copy until that module's port bead. Also exposes a structured `run(ctx)` for
the `python3 -m ubs_core` CLI.

Emit dialects:
- main(argv) reproduces the heredoc byte-for-byte: a `__COUNT__<TAB>count`
  header row followed by at most five `__SAMPLE__<TAB>file<TAB>line<TAB>code`
  rows.
- run(ctx) yields one NDJSON finding per detection with rule id
  `elixir.taint.request_path_traversal` (registry lang prefix).

Adaptations vs the heredoc (detection logic untouched):
- ROOT/BASE_DIR become module globals set by main(argv) instead of being
  derived from sys.argv at import time.
- analyze() delegates the per-file loop to scan_file_findings() so main() and
  run() share one copy of the detection logic.
- run(ctx) skips a file only when its cwd-relative parts hit SKIP_DIRS; the
  heredoc computes the same check against its own ROOT, while ctx.files are
  handed in by the caller (self-test tempdirs live outside the project).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path()
BASE_DIR: Path = Path()



SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|path_info|request_path|query_string)\b|'
    r'\bparams\s*(?:\[|\|>)|'
    r'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.params)\b|'
    r'\bget_in\s*\(\s*(?:params|conn\.params)\b|'
    r'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,|'
    r'\b(?:conn|socket)\s*\|>\s*(?:Plug\.Conn\.)?get_req_header\s*\(|'
    r'\b[A-Za-z_][A-Za-z0-9_?!]*\.filename\b|'
    r'%Plug\.Upload\{[^}]*filename\s*:',
    re.IGNORECASE,
)
PATHISH_NAME_RE = re.compile(r'(path|file|name|dir|folder|target|destination|download|upload|export|key)', re.IGNORECASE)
SINK_RE = re.compile(
    r'\bFile\.(?:read!?|write!?|open!?|rm!?|cp!?|rename!?|mkdir!?|mkdir_p!?|stat!?|'
    r'ls!?|stream!?|exists\?)\s*\(|'
    r'\b(?:Plug\.Conn\.)?send_file\s*\(|'
    r'\b(?:Phoenix\.Controller\.)?send_download\s*\('
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_path|safePath|safe_file_name|safeFileName|safe_filename|safeFilename|'
    r'sanitize_filename|sanitizeFilename|sanitize_path|sanitizePath|validated_path|validatedPath|'
    r'validate_path|validatePath|safe_under_root|safeUnderRoot|resolve_under_root|resolveUnderRoot|'
    r'ensure_inside_root|ensureInsideRoot|inside_root\?|insideRoot\?|allowed_file|allowedFile|'
    r'canonical_path_inside|canonicalPathInside)\b',
    re.IGNORECASE,
)

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

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def context_around(lines, line_no):
    start = max(0, line_no - 10)
    end = min(len(lines), line_no + 12)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])

def is_pathish(variable: str) -> bool:
    return bool(PATHISH_NAME_RE.search(variable))

def has_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        return True
    return bool(target_name and is_pathish(target_name) and re.search(r'\bparams\b', statement))

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement) or re.search(r'\bPath\.basename\s*\(', statement))

def has_containment_context(context: str) -> bool:
    lower = context.lower()
    has_canonical = 'path.expand' in lower or 'path.relative_to' in lower
    has_anchor = 'string.starts_with?' in lower or 'path.relative_to' in lower
    rejects_escape = 'raise ' in lower or '{:error' in lower or 'halt(' in lower or 'send_resp(' in lower
    return has_canonical and has_anchor and rejects_escape

def contains_tainted_path(statement: str, tainted: set[str]) -> bool:
    if has_source(statement):
        return True
    return any(re.search(rf'\b{re.escape(var)}\b', statement) for var in tainted)

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def scan_file_findings(path: Path):
    """Verbatim per-file detection loop from the heredoc's analyze().

    Yields (line_no, col, sample_code) per finding; relpath aggregation
    and the five-sample __SAMPLE__ cap stay in analyze()/main().
    """
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not re.search(r'\b(?:conn|params|Plug\.Upload|filename|send_file|send_download)\b', text):
        return
    lines = text.splitlines()
    tainted = set()
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            if is_safe_expression(rhs):
                tainted.discard(variable)
            elif has_source(rhs, variable) or contains_tainted_path(rhs, tainted):
                tainted.add(variable)
            else:
                tainted.discard(variable)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        if not contains_tainted_path(statement, tainted):
            continue
        if has_containment_context(context_around(lines, idx)):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        yield idx, SINK_RE.search(current_line).start() + 1, source_line(lines, idx)


def analyze(path, issues):
    """Heredoc aggregation: collect one (relpath, line, code) tuple per finding."""
    for idx, _col, code in scan_file_findings(path):
        issues.append((relpath(path), idx, code))


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


_MESSAGE = "Request-derived path reaches file read/write/serve sink"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd().resolve()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        resolved = path.resolve()
        try:
            rel = resolved.relative_to(cwd)
            parts = rel.parts
        except ValueError:
            rel = path.name
            parts = ()
        if any(part in SKIP_DIRS for part in parts):
            continue
        for line_no, col, code in scan_file_findings(path):
            yield {
                "rule": "elixir.taint.request_path_traversal",
                "path": str(rel),
                "line": line_no,
                "col": col,
                "layer": "taint",
                "lang": "elixir",
                "severity": "critical",
                "message": f"{_MESSAGE} ({code})",
            }


def _selftest_direct_traversal(tmp_prefix: str = "ubs_core_taint_elixir_trav_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "show.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = conn.params[\"file\"]\n"
            "  File.read(path)\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "elixir.taint.request_path_traversal", findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["col"] == 3, findings
    assert findings[0]["severity"] == "critical", findings
    assert "File.read(path)" in findings[0]["message"], findings


def _selftest_propagated_traversal(tmp_prefix: str = "ubs_core_taint_elixir_trav_prop_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "flow.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  raw = conn.params[\"file\"]\n"
            "  path = raw\n"
            "  File.write(path, \"data\")\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 4, findings


def _selftest_basename_suppression(tmp_prefix: str = "ubs_core_taint_elixir_trav_base_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = Path.basename(conn.params[\"file\"])\n"
            "  File.read(Path.join(\"uploads\", path))\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_elixir_trav_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ex"
        target.write_text(
            "# ubs:ignore\n"
            "path = conn.params[\"file\"]\n"
            "File.read(path)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_elixir_trav_main_") -> None:
    import tempfile
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "show.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = conn.params[\"file\"]\n"
            "  File.read(path)\n"
            "end\n",
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", tmp])
        assert rc == 0
        out = buffer.getvalue()
    assert out == "__COUNT__\t1\n__SAMPLE__\tshow.ex\t3\tFile.read(path)\n", repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_traversal", _selftest_direct_traversal),
    ("propagated_traversal", _selftest_propagated_traversal),
    ("basename_suppression", _selftest_basename_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="elixir", name="taint_elixir_traversal", run=run, selftests=SELF_TESTS))
