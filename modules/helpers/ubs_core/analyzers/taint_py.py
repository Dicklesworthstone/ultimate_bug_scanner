"""ubs_core.analyzers.taint_py — Python lightweight taint analysis (bead A2).

Logic moved verbatim from the taint heredoc in modules/ubs-python.sh
(run_taint_analysis_checks), which keeps its own copy until that module's
port bead. Also exposes a structured `run(ctx)` for the `python3 -m ubs_core`
CLI.

Emit dialects:
- main(argv) reproduces the heredoc byte-for-byte: one
  `rule_id<TAB>count<TAB>sample,sample,...` row per rule with hits
  (rule ids `py.taint.*`, at most 3 comma-joined samples per rule).
- run(ctx) yields one NDJSON finding per detection with rule ids
  `python.taint.{kind}` (registry lang prefix).
"""
from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
EXTS = {'.py', '.pyi'}
PATH_LIMIT = 5

SOURCE_PATTERNS = [
    re.compile(r"request\.(?:args|get_json|json|form|values|data|body|GET|POST)", re.IGNORECASE),
    re.compile(r"flask\.request", re.IGNORECASE),
    re.compile(r"django\.http\.request", re.IGNORECASE),
    re.compile(r"input\s*\(", re.IGNORECASE),
    re.compile(r"raw_input\s*\(", re.IGNORECASE),
    re.compile(r"sys\.argv", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"event\['body'\]", re.IGNORECASE),
    re.compile(r"params\[[^\]]+\]", re.IGNORECASE),
]

SANITIZER_REGEXES = [
    re.compile(r"html\.escape"),
    re.compile(r"django\.utils\.html\.escape"),
    re.compile(r"flask\.escape"),
    re.compile(r"mark_safe"),
    re.compile(r"bleach\.clean"),
    re.compile(r"shlex\.quote"),
    re.compile(r"urllib\.parse\.quote"),
]

SINKS = [
    (re.compile(r"render_template(?:_string)?\s*\((.+)\)"), 'py.taint.xss', 'render_template'),
    (re.compile(r"HttpResponse\((.+)\)"), 'py.taint.xss', 'HttpResponse'),
    (re.compile(r"Response\((.+)\)"), 'py.taint.xss', 'Flask Response'),
    (re.compile(r"(?:cursor|session|conn)\.(?:execute|executemany)\s*\((.+)\)"), 'py.taint.sql', 'SQL execute'),
    (re.compile(r"(?:engine|db)\.(?:execute|text)\s*\((.+)\)"), 'py.taint.sql', 'SQL engine execute'),
    (re.compile(r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\((.+)\)"), 'py.taint.command', 'subprocess execution'),
    (re.compile(r"os\.(?:system|popen|execv)\s*\((.+)\)"), 'py.taint.command', 'os command execution'),
    (re.compile(r"eval\s*\((.+)\)"), 'py.taint.eval', 'eval'),
    (re.compile(r"exec\s*\((.+)\)"), 'py.taint.eval', 'exec'),
]

ASSIGN_SIMPLE = re.compile(r"^(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*=\s*(?P<expr>.+)")

KIND_BY_RULE = {rule: rule.rsplit('.', 1)[-1] for _regex, rule, _label in SINKS}


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file(): continue
        if should_skip(path): continue
        if path.suffix.lower() in EXTS: yield path


def strip_comments(line: str) -> str:
    if '#' in line:
        idx = line.find('#')
        if idx >= 0: line = line[:idx]
    return line


def parse_assignments(lines):
    assignments = []
    for idx, raw in enumerate(lines, start=1):
        line = strip_comments(raw).strip()
        if not line or '=' not in line: continue
        if '==' in line or '>=' in line or '<=' in line or '!=' in line: continue
        match = ASSIGN_SIMPLE.match(line)
        if not match: continue
        lhs = match.group('targets'); expr = match.group('expr')
        for target in [t.strip() for t in lhs.split(',') if t.strip()]:
            assignments.append((idx, target, expr))
    return assignments


def find_sources(expr: str):
    matches = []
    for regex in SOURCE_PATTERNS:
        for m in regex.finditer(expr):
            matches.append(m.group(0))
    return matches


def expr_has_sanitizer(expr: str, sink_rule: str | None = None) -> bool:
    expr_lower = expr.lower()
    for regex in SANITIZER_REGEXES:
        if regex.search(expr_lower): return True
    if sink_rule == 'py.taint.sql':
        if re.search(r'%(?!\()|\.format\(|f["\']', expr): return False
        if re.search(r",\s*(?:\(|\[|params|data|values|bindings)", expr_lower): return True
    return False


def expr_has_tainted(expr: str, tainted):
    for name, meta in tainted.items():
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
        if re.search(pattern, expr): return name, meta
    return None, None


def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        if expr_has_sanitizer(expr, None): continue
        sources = find_sources(expr)
        if sources:
            tainted[target] = {'source': sources[0], 'line': line_no, 'path': [sources[0], target]}
    for _ in range(5):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr, None): continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                new_path = list(meta.get('path', [ref]))
                if len(new_path) >= 5: new_path = new_path[-4:]
                new_path.append(target)
                tainted[target] = {'source': meta.get('source', ref), 'line': line_no, 'path': new_path}
                changed = True
        if not changed: break
    return tainted


def analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8')
    except Exception:
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    for idx, raw in enumerate(lines, start=1):
        if 'ubs:ignore' in raw: continue
        if idx > 1 and 'ubs:ignore' in lines[idx-2]: continue
        stripped = strip_comments(raw)
        if not stripped: continue
        for regex, rule, label in SINKS:
            match = regex.search(stripped)
            if not match: continue
            expr = match.group(1)
            if not expr or expr_has_sanitizer(expr, rule): continue
            direct = find_sources(expr)
            if direct:
                path_desc = f"{direct[0]} -> {label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref: continue
                seq = list(meta.get('path', [ref]))
                if len(seq) >= 5: seq = seq[-4:]
                seq.append(label)
                path_desc = ' -> '.join(seq)
            try: rel = path.relative_to(ROOT)
            except ValueError: rel = path.name
            sample = f"{rel}:{idx} {path_desc}"
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(sample)


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = defaultdict(lambda: {'count': 0, 'samples': []})
    for file_path in iter_files(ROOT):
        analyze_file(file_path, issues)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    return 0


_SEVERITY = {
    "xss": "critical",
    "sql": "critical",
    "command": "critical",
    "eval": "critical",
}

_MESSAGE = {
    "xss": "Unsanitized request data reaches HTML/response sinks",
    "sql": "User input flows into SQL execute() without parameters",
    "command": "User input reaches subprocess/os.system",
    "eval": "User input flows into eval/exec",
}


def scan_file_findings(path: Path):
    """Yield (rule_id, line, col, path_desc) per detection, without the
    heredoc's 3-sample cap — used by the structured run(ctx) path."""
    try:
        text = path.read_text(encoding='utf-8')
    except Exception:
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    for idx, raw in enumerate(lines, start=1):
        if 'ubs:ignore' in raw: continue
        if idx > 1 and 'ubs:ignore' in lines[idx-2]: continue
        stripped = strip_comments(raw)
        if not stripped: continue
        for regex, rule, label in SINKS:
            match = regex.search(stripped)
            if not match: continue
            expr = match.group(1)
            if not expr or expr_has_sanitizer(expr, rule): continue
            direct = find_sources(expr)
            if direct:
                path_desc = f"{direct[0]} -> {label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref: continue
                seq = list(meta.get('path', [ref]))
                if len(seq) >= 5: seq = seq[-4:]
                seq.append(label)
                path_desc = ' -> '.join(seq)
            yield rule, idx, match.start() + 1, path_desc


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        if should_skip(path):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for rule, line, col, path_desc in scan_file_findings(path):
            kind = KIND_BY_RULE[rule]
            yield {
                "rule": f"python.taint.{kind}",
                "path": str(rel),
                "line": line,
                "col": col,
                "layer": "taint",
                "lang": "python",
                "severity": _SEVERITY.get(kind, "warning"),
                "message": f"{_MESSAGE.get(kind, kind)} ({path_desc})",
            }


def _selftest_direct_source_sink(tmp_prefix: str = "ubs_core_taint_py_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "view.py"
        target.write_text(
            "render_template('hi.html', q=request.args.get('q'))\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.taint.xss", findings
    assert findings[0]["line"] == 1
    assert findings[0]["severity"] == "critical"
    assert "request.args -> render_template" in findings[0]["message"]


def _selftest_propagated_taint(tmp_prefix: str = "ubs_core_taint_py_prop_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "flow.py"
        target.write_text(
            "q = request.args.get('q')\n"
            "cursor.execute('SELECT * FROM t WHERE x=' + q)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.taint.sql", findings
    assert findings[0]["line"] == 2
    assert "request.args -> q -> SQL execute" in findings[0]["message"]


def _selftest_sanitizer_suppression(tmp_prefix: str = "ubs_core_taint_py_san_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.py"
        target.write_text(
            "q = html.escape(request.args.get('q'))\n"
            "render_template('hi.html', q=q)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_py_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.py"
        target.write_text(
            "# ubs:ignore\n"
            "render_template('hi.html', q=request.args.get('q'))\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_py_main_") -> None:
    import contextlib
    import io
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "view.py"
        target.write_text(
            "q = request.args.get('q')\n"
            "eval(q)\n",
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", str(tmp)])
        assert rc == 0
        out = buffer.getvalue()
    assert out == f"py.taint.eval\t1\tview.py:2 request.args -> q -> eval\n", repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_sink", _selftest_direct_source_sink),
    ("propagated_taint", _selftest_propagated_taint),
    ("sanitizer_suppression", _selftest_sanitizer_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="python", name="taint_py", run=run, selftests=SELF_TESTS))
