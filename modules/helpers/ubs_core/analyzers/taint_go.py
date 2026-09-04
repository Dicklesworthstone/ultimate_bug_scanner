"""ubs_core.analyzers.taint_go — lightweight Go taint analysis (bead A2).

Ported verbatim from the `run_taint_analysis_checks` python3 heredoc in
modules/ubs-golang.sh (sources -> sanitizers -> sinks across function scopes).
`main()` reproduces the heredoc's CLI behavior exactly (argv[1] = project dir;
emits ``rule_id\\tcount\\tsamples`` rows, samples comma-joined, at most 3 per
rule); `run()` yields the same hits as structured findings.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {'.git', 'vendor', '.cache', 'bin', 'dist', '.idea'}
EXTS = {'.go'}
PATH_LIMIT = 6

SOURCE_PATTERNS = [
    re.compile(r"\.FormValue\(", re.IGNORECASE),
    re.compile(r"\.PostFormValue\(", re.IGNORECASE),
    re.compile(r"\.(?:Form|PostForm)\.Get\(", re.IGNORECASE),
    re.compile(r"\.Header\.Get\(", re.IGNORECASE),
    re.compile(r"URL\.Query\(\)\.Get", re.IGNORECASE),
    re.compile(r"\.PathValue\(", re.IGNORECASE),
    re.compile(r"mux\.Vars\(", re.IGNORECASE),
    re.compile(r"chi\.URLParam\(", re.IGNORECASE),
    re.compile(r"\.(?:QueryParam|FormParam|Param)\(", re.IGNORECASE),
    re.compile(r"os\.Getenv", re.IGNORECASE),
    re.compile(r"bufio\.NewReader\(os\.Stdin\)", re.IGNORECASE),
    re.compile(r"io\.ReadAll\([^)]*(?:r|req|request)\.Body", re.IGNORECASE),
    re.compile(r"json\.NewDecoder\([^)]*(?:r|req|request)\.Body", re.IGNORECASE),
]

SANITIZER_REGEXES = [
    re.compile(r"html\.EscapeString"),
    re.compile(r"template\.HTMLEscapeString"),
    re.compile(r"url\.QueryEscape"),
    re.compile(r"path\.Clean"),
    re.compile(r"filepath\.Clean"),
]

SINKS = [
    (re.compile(r"fmt\.Fprint[fLn]?\s*\((.+)\)"), 'go.taint.xss', 'fmt.Fprintf'),
    (re.compile(r"[A-Za-z0-9_]+\.Write\s*\((.+)\)"), 'go.taint.xss', 'ResponseWriter.Write'),
    (re.compile(r"template\.(?:Must\()?[A-Za-z0-9_]+\.Execute\s*\((.+)\)"), 'go.taint.xss', 'template.Execute'),
    (re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?\.(?:Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|Raw|NamedQuery|NamedExec|Select|Where|Or|Not|Having|Order)\s*\((?!\))(.+)\)"), 'go.taint.sql', 'SQL query'),
    (re.compile(r"\b(?:db|tx|conn|pool|repo|store|database|queries|sqlxDB)\.Get\s*\((?!\))(.+)\)"), 'go.taint.sql', 'SQL query'),
    (re.compile(r"exec\.Command(?:Context)?\s*\((.+)\)"), 'go.taint.command', 'exec.Command'),
]

ASSIGN_PATTERNS = [
    re.compile(r"^\s*(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*:=\s*(?P<expr>.+)"),
    re.compile(r"^\s*(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*=\s*(?P<expr>.+)"),
    re.compile(r"^\s*var\s+(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)(?:\s+[A-Za-z0-9_\*\[\]]+)?\s*=\s*(?P<expr>.+)")
]


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if should_skip(path):
            continue
        if path.suffix.lower() in EXTS:
            yield path


def strip_comments(line: str) -> str:
    out, quote, escape = [], '', False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            i += 1
            continue
        if ch == '/' and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return ''.join(out).strip()


def parse_assignments(lines, start_line=1):
    assignments = []
    for idx, raw in enumerate(lines, start=start_line):
        line = strip_comments(raw)
        if not line or '=' not in line:
            continue
        for pattern in ASSIGN_PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            targets = match.group('targets')
            expr = match.group('expr')
            for target in [t.strip() for t in targets.split(',') if t.strip()]:
                assignments.append((idx, target, expr))
            break
    return assignments


def find_sources(expr: str):
    matches = []
    for regex in SOURCE_PATTERNS:
        for m in regex.finditer(expr):
            matches.append(m.group(0))
    return matches


def expr_has_sanitizer(expr: str, sink_rule=None) -> bool:
    if sink_rule == 'go.taint.sql':
        return False
    for regex in SANITIZER_REGEXES:
        if regex.search(expr):
            return True
    return False


def expr_has_tainted(expr: str, tainted):
    haystack = strip_comments(expr)
    for name, meta in tainted.items():
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
        if re.search(pattern, haystack):
            return name, meta
    return None, None


def split_go_args(expr: str):
    args = []
    start = 0
    depth = 0
    quote = ''
    escape = False
    for idx, ch in enumerate(expr):
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            continue
        if ch in '([{':
            depth += 1
            continue
        if ch in ')]}' and depth > 0:
            depth -= 1
            continue
        if ch == ',' and depth == 0:
            args.append(expr[start:idx].strip())
            start = idx + 1
    tail = expr[start:].strip()
    if tail:
        args.append(tail)
    return args


def looks_context_arg(arg: str) -> bool:
    return bool(re.match(
        r"^(?:ctx|context\.(?:Background|TODO)\(\)|[A-Za-z_][\w]*\.Context\(\))$",
        arg.strip(),
    ))


def sql_arg_from_call(expr: str):
    args = split_go_args(expr)
    if not args:
        return ''
    if len(args) > 1 and looks_context_arg(args[0]):
        return args[1]
    return args[0]


def sql_arg_is_parameterized(sql_arg: str) -> bool:
    return bool(re.search(r"(?:\?|\$\d+|@[A-Za-z_][\w]*|:[A-Za-z_][\w]*)", sql_arg))


def brace_delta(raw: str) -> int:
    stripped = strip_comments(raw)
    return stripped.count('{') - stripped.count('}')


def function_ranges(lines):
    ranges = []
    start = None
    depth = 0
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if start is None:
            if not re.match(r"^\s*func\b", stripped):
                continue
            start = idx
            depth = brace_delta(raw)
            if depth <= 0:
                ranges.append((start, idx))
                start = None
                depth = 0
            continue
        depth += brace_delta(raw)
        if depth <= 0:
            ranges.append((start, idx))
            start = None
            depth = 0
    if start is not None:
        ranges.append((start, len(lines)))
    return ranges


def analysis_ranges(lines):
    ranges = function_ranges(lines)
    if not ranges:
        return [(1, len(lines))]
    scoped = []
    cursor = 1
    for start, end in ranges:
        if cursor < start:
            scoped.append((cursor, start - 1))
        scoped.append((start, end))
        cursor = end + 1
    if cursor <= len(lines):
        scoped.append((cursor, len(lines)))
    return [
        (start, end)
        for start, end in scoped
        if any(strip_comments(raw) for raw in lines[start - 1:end])
    ]


def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        if expr_has_sanitizer(expr, None):
            continue
        sources = find_sources(expr)
        if sources:
            tainted[target] = {'source': sources[0], 'line': line_no, 'path': [sources[0], target]}
    for _ in range(7):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr, None):
                continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                seq = list(meta.get('path', [ref]))
                if len(seq) >= PATH_LIMIT:
                    seq = seq[-(PATH_LIMIT-1):]
                seq.append(target)
                tainted[target] = {'source': meta.get('source', ref), 'line': line_no, 'path': seq}
                changed = True
        if not changed:
            break
    return tainted


def iter_file_hits(path: Path, base_dir: Path):
    """Yield (rule, rel, line, col, path_desc) for every sink hit in one file."""
    try:
        text = path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    for start, end in analysis_ranges(lines):
        scoped_lines = lines[start - 1:end]
        assignments = parse_assignments(scoped_lines, start)
        tainted = record_taint(assignments)
        for idx, raw in enumerate(scoped_lines, start=start):
            stripped = strip_comments(raw)
            if not stripped:
                continue
            for regex, rule, label in SINKS:
                match = regex.search(stripped)
                if not match:
                    continue
                expr = match.group(1)
                raw_match = regex.search(raw)
                expr_raw = raw_match.group(1) if raw_match else expr
                if not expr or expr_has_sanitizer(expr_raw or expr, rule):
                    continue
                taint_expr = expr
                if rule == 'go.taint.sql':
                    taint_expr = sql_arg_from_call(expr_raw or expr)
                    if not taint_expr:
                        continue
                direct = find_sources(taint_expr)
                ref = meta = None
                if not direct:
                    ref, meta = expr_has_tainted(taint_expr, tainted)
                if rule == 'go.taint.sql' and sql_arg_is_parameterized(taint_expr) and not direct and not ref:
                    continue
                if direct:
                    path_desc = f"{direct[0]} -> {label}"
                else:
                    if not ref:
                        continue
                    seq = list(meta.get('path', [ref]))
                    if len(seq) >= PATH_LIMIT:
                        seq = seq[-(PATH_LIMIT-1):]
                    seq.append(label)
                    path_desc = ' -> '.join(seq)
                try:
                    rel = path.relative_to(base_dir)
                except ValueError:
                    rel = path.name
                col = (raw_match.start(1) + 1) if raw_match else 1
                yield rule, str(rel), idx, col, path_desc


def main() -> int:
    import sys

    root = Path(sys.argv[1]).resolve()
    base_dir = root if root.is_dir() else root.parent
    issues: dict[str, dict] = defaultdict(lambda: {'count': 0, 'samples': []})
    for file_path in iter_files(root):
        for rule, rel, line, _col, path_desc in iter_file_hits(file_path, base_dir):
            sample = f"{rel}:{line} {path_desc}"
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(sample)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    return 0


_SEVERITY = {
    'go.taint.xss': 'critical',
    'go.taint.sql': 'critical',
    'go.taint.command': 'critical',
}

_MESSAGE = {
    'go.taint.xss': 'User input flows into fmt.Fprintf/template Execute/ResponseWriter.Write',
    'go.taint.sql': 'User input concatenated into SQL execution/query-builder strings',
    'go.taint.command': 'User input reaches exec.Command/CommandContext',
}


def run(ctx: RunContext) -> Iterable[dict]:
    base_dir = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        for rule, rel, line, col, path_desc in iter_file_hits(path, base_dir):
            yield {
                "rule": rule,
                "path": rel,
                "line": line,
                "col": col,
                "severity": _SEVERITY[rule],
                "message": f"{_MESSAGE[rule]} ({path_desc})",
            }


def _write_go(tmp_dir: Path, body: str) -> Path:
    path = tmp_dir / "main.go"
    path.write_text("package main\n\n" + body, encoding="utf-8")
    return path


def _selftest_xss_positive() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"fmt\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "\tname := r.FormValue(\"name\")\n"
        "\tfmt.Fprintf(w, \"hello \"+name)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        ctx = RunContext(lang="go", files=[path])
        findings = [f for f in run(ctx) if f["rule"] == "go.taint.xss"]
        assert len(findings) == 1, findings
        assert findings[0]["line"] == 10, findings[0]
        assert findings[0]["severity"] == "critical"
        assert findings[0]["path"] == "main.go"
        assert "name" in findings[0]["message"]


def _selftest_sanitizer_suppresses() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"fmt\"\n"
        "\t\"html\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "\tname := r.FormValue(\"name\")\n"
        "\tfmt.Fprintf(w, \"hello \"+html.EscapeString(name))\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = list(run(RunContext(lang="go", files=[path])))
        assert findings == [], findings


def _selftest_parameterized_sql_suppressed() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"database/sql\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {\n"
        "\tq := r.URL.Query().Get(\"q\")\n"
        "\trows, err := db.Query(\"SELECT * FROM users WHERE name = ?\", q)\n"
        "\t_ = rows\n"
        "\t_ = err\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = [f for f in run(RunContext(lang="go", files=[path])) if f["rule"] == "go.taint.sql"]
        assert findings == [], findings


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("xss_positive", _selftest_xss_positive),
    ("sanitizer_suppresses", _selftest_sanitizer_suppresses),
    ("parameterized_sql_suppressed", _selftest_parameterized_sql_suppressed),
)

register(Analyzer(layer="taint", lang="go", name="taint_go", run=run, selftests=SELF_TESTS))
