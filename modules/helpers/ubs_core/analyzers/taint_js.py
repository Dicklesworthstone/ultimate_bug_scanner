"""ubs_core.analyzers.taint_js — JavaScript/TypeScript lightweight taint analysis (bead A2).

Logic moved verbatim from the taint heredoc in modules/ubs-js.sh
(run_taint_analysis_checks), which keeps its own copy until that module's
port bead. Also exposes a structured `run(ctx)` for the `python3 -m ubs_core`
CLI.

Emit dialects:
- main(argv) reproduces the heredoc byte-for-byte: one
  `rule_id<TAB>count<TAB>sample,sample,...` row per rule with hits
  (rule ids `js.taint.*`, at most 3 comma-joined samples per rule).
- run(ctx) yields one NDJSON finding per detection with rule ids
  `javascript.taint.{kind}` (registry lang prefix).
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'node_modules', '.next', '.nuxt', '.cache', 'dist', 'build', 'coverage', 'tmp', '.turbo'}
EXTS = {'.js', '.jsx', '.ts', '.tsx'}
PATH_LIMIT = 5
ROUTE_PARAM_FIELDS = r"(?:id|slug|user|username|email|name|status|tenant|account|role|filter|search|sort|limit|offset|where|order|table|column)"
ROUTE_PARAM_OBJECT = re.compile(r"^\s*\(?\s*(?:await\s+)?((?:context\.)?params)\s*\)?\s*$", re.IGNORECASE)

SOURCE_PATTERNS = [
    (re.compile(r"\b(?:req|request|ctx\.request|context\.req)\.(?:body|query|params)[\w\.\[\]'\"]*", re.IGNORECASE), 'HTTP request payload'),
    (re.compile(rf"\b(?:context\.)?params\s*(?:\.\s*{ROUTE_PARAM_FIELDS}\b|\[\s*['\"]{ROUTE_PARAM_FIELDS}['\"]\s*\])", re.IGNORECASE), 'Route params'),
    (re.compile(r"\b(?:req|request)\.files?\b", re.IGNORECASE), 'Uploaded file'),
    (re.compile(r"\b(?:event|e)\.target\.value\b", re.IGNORECASE), 'DOM event value'),
    (re.compile(r"\blocation\.(?:search|hash|href)\b", re.IGNORECASE), 'window.location data'),
    (re.compile(r"\bwindow\.location\b", re.IGNORECASE), 'window.location data'),
    (re.compile(r"\bdocument\.cookie\b", re.IGNORECASE), 'document.cookie'),
    (re.compile(r"\b(?:localStorage|sessionStorage)\.getItem\s*\([^)]*\)", re.IGNORECASE), 'Web storage read'),
    (re.compile(r"\b(?:new\s+)?FormData\s*\([^)]*\)", re.IGNORECASE), 'FormData payload'),
    (re.compile(r"\bURLSearchParams\s*\([^)]*\)", re.IGNORECASE), 'URLSearchParams payload'),
]

SANITIZER_REGEXES = [
    re.compile(r"DOMPurify\.sanitize"),
    re.compile(r"sanitizeHtml"),
    re.compile(r"escapeHtml"),
    re.compile(r"xssFilters"),
    re.compile(r"encodeURIComponent"),
    re.compile(r"he\.escape"),
    re.compile(r"(?:lodash|_)\.escape"),
    re.compile(r"validator\.escape"),
    re.compile(r"stripTags"),
    re.compile(r"sanitizeInput"),
    re.compile(r"sanitizeUrl"),
    re.compile(r"shellescape"),
    re.compile(r"db\.escape|pool\.escape|connection\.escape|mysql\.escape|sqlstring\.escape"),
]

CHILD_PROCESS_APIS = ('execFileSync', 'execFile', 'execSync', 'spawnSync', 'spawn', 'exec')
CHILD_PROCESS_API_RE = r"(?:execFileSync|execFile|execSync|spawnSync|spawn|exec)"
CHILD_PROCESS_MODULE_RE = r"['\"](?:node:)?child_process['\"]"

SINKS = [
    (re.compile(r"\.innerHTML\s*=\s*(.+)"), 'js.taint.xss', 'innerHTML write'),
    (re.compile(r"\.outerHTML\s*=\s*(.+)"), 'js.taint.xss', 'outerHTML write'),
    (re.compile(r"dangerouslySetInnerHTML\s*=\s*(.+)"), 'js.taint.xss', 'dangerouslySetInnerHTML'),
    (re.compile(r"insertAdjacentHTML\s*\((.+)\)"), 'js.taint.xss', 'insertAdjacentHTML'),
    (re.compile(r"document\.write\s*\((.+)\)"), 'js.taint.xss', 'document.write'),
    (re.compile(r"res(?:ponse)?\.send\s*\((.+)\)"), 'js.taint.xss', 'HTTP send'),
    (re.compile(r"res(?:ponse)?\.json\s*\((.+)\)"), 'js.taint.xss', 'HTTP json send'),
    (re.compile(r"eval\s*\((.+)\)"), 'js.taint.eval', 'eval'),
    (re.compile(r"new\s+Function\s*\((.+)\)"), 'js.taint.eval', 'Function constructor'),
    (re.compile(r"shell\.exec\s*\((.+)\)"), 'js.taint.command', 'shell.exec'),
    (re.compile(r"(?:db|pool|connection|client|knex|sequelize|prisma)\.(?:query|execute|raw)\s*\((.+)\)"), 'js.taint.sql', 'SQL execution'),
]

ASSIGN_DECL = re.compile(r"^(?:const|let|var)\s+(.+?)\s*=\s*(.+)")
ASSIGN_SIMPLE = re.compile(r"^([A-Za-z_$][\w$]*)\s*=\s*(?![=])(.+)")
DESTRUCT_OBJECT = re.compile(r"^(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)")
DESTRUCT_ARRAY = re.compile(r"^(?:const|let|var)\s*\[([^]]*)\]\s*=\s*(.+)")

KIND_BY_RULE = {rule: rule.rsplit('.', 1)[-1] for _regex, rule, _label in SINKS}


def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)


def iter_js_files(root: Path):
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


def split_statements(line: str):
    if ';' not in line:
        return [line]
    parts, buf, depth = [], [], 0
    for ch in line:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(depth - 1, 0)
        if ch == ';' and depth == 0:
            token = ''.join(buf).strip()
            if token:
                parts.append(token)
            buf = []
            continue
        buf.append(ch)
    token = ''.join(buf).strip()
    if token:
        parts.append(token)
    return parts


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ''
    raw = raw.split('=')[0].strip()
    raw = raw.split(':')[-1].strip()
    if raw.startswith('...'):
        raw = raw[3:]
    return raw


def parse_targets(blob: str):
    targets = []
    for chunk in blob.split(','):
        name = normalize_target(chunk)
        if name and re.match(r"[A-Za-z_$][\w$]*", name):
            targets.append(name)
    return targets


def parse_child_process_members(blob: str):
    members = set()
    for chunk in blob.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        chunk = chunk.split('=')[0].strip()
        if ':' in chunk:
            exported, local = chunk.split(':', 1)
        elif re.search(r"\s+as\s+", chunk):
            exported, local = re.split(r"\s+as\s+", chunk, maxsplit=1)
        else:
            exported, local = chunk, chunk
        exported = exported.strip()
        local = normalize_target(local)
        if exported in CHILD_PROCESS_APIS and re.match(r"^[A-Za-z_$][\w$]*$", local):
            members.add(local)
    return members


def source_line(raw: str) -> str:
    line = raw.strip()
    if line.startswith('//') or line.startswith('*'):
        return ''
    return line


def child_process_bindings(lines):
    module_aliases = {'child_process', 'cp'}
    function_aliases = set()
    api_group = CHILD_PROCESS_API_RE

    for raw in lines:
        line = source_line(raw)
        if not line:
            continue
        m = re.search(rf"\b(?:const|let|var)\s*\{{([^}}]+)\}}\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)", line)
        if m:
            function_aliases.update(parse_child_process_members(m.group(1)))
        m = re.search(rf"\bimport\s*\{{([^}}]+)\}}\s*from\s*{CHILD_PROCESS_MODULE_RE}", line)
        if m:
            function_aliases.update(parse_child_process_members(m.group(1)))
        m = re.search(rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)", line)
        if m:
            module_aliases.add(m.group(1))
        m = re.search(rf"\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+{CHILD_PROCESS_MODULE_RE}", line)
        if m:
            module_aliases.add(m.group(1))
        m = re.search(rf"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+{CHILD_PROCESS_MODULE_RE}", line)
        if m:
            module_aliases.add(m.group(1))
        m = re.search(rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)\.{api_group}\b", line)
        if m:
            function_aliases.add(m.group(1))

    alias_group = '|'.join(re.escape(alias) for alias in sorted(module_aliases, key=len, reverse=True))
    if alias_group:
        for raw in lines:
            line = source_line(raw)
            if not line:
                continue
            m = re.search(rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:{alias_group})\.{api_group}\b", line)
            if m:
                function_aliases.add(m.group(1))

    return module_aliases, function_aliases


def parse_assignments(lines):
    assignments = []
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped:
            continue
        for stmt in split_statements(stripped):
            stmt = stmt.strip()
            if not stmt:
                continue
            m = DESTRUCT_OBJECT.match(stmt)
            if m:
                targets = parse_targets(m.group(1))
                expr = m.group(2)
            else:
                m = DESTRUCT_ARRAY.match(stmt)
                if m:
                    targets = parse_targets(m.group(1))
                    expr = m.group(2)
                else:
                    m = ASSIGN_DECL.match(stmt)
                    if m:
                        targets = parse_targets(m.group(1))
                        expr = m.group(2)
                    else:
                        m = ASSIGN_SIMPLE.match(stmt)
                        if m:
                            targets = [m.group(1)]
                            expr = m.group(2)
                        else:
                            continue
            expr = expr.strip()
            for target in targets:
                assignments.append((idx, target, expr))
    return assignments


def find_sources(expr: str):
    matches = []
    for regex, label in SOURCE_PATTERNS:
        for match in regex.finditer(expr):
            snippet = match.group(0).strip()
            if snippet:
                matches.append((snippet, label))
    return matches


def assignment_sources(expr: str):
    sources = find_sources(expr)
    if sources:
        return sources
    route_params = ROUTE_PARAM_OBJECT.match(expr)
    if route_params:
        return [(route_params.group(1), 'Route params')]
    return []


def expr_has_sanitizer(expr: str, sink_rule: str | None = None) -> bool:
    for regex in SANITIZER_REGEXES:
        if regex.search(expr):
            return True
    if sink_rule == 'js.taint.sql' and re.search(r",\s*(?:\[[^\]]+\]|params|values|bindings)", expr, re.IGNORECASE):
        return True
    return False


def expr_has_tainted(expr: str, tainted):
    for name, meta in tainted.items():
        if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expr):
            return name, meta
    return None, None


def find_child_process_sink(line: str, module_aliases, function_aliases):
    direct = re.search(rf"require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)\.{CHILD_PROCESS_API_RE}\s*\((.*)", line)
    if direct:
        return direct.group(1), 'child_process exec'

    alias_group = '|'.join(re.escape(alias) for alias in sorted(module_aliases, key=len, reverse=True))
    if alias_group:
        member = re.search(rf"(?<![A-Za-z0-9_$])(?:{alias_group})\.{CHILD_PROCESS_API_RE}\s*\((.*)", line)
        if member:
            return member.group(1), 'child_process exec'

    function_group = '|'.join(re.escape(name) for name in sorted(function_aliases, key=len, reverse=True))
    if function_group:
        bare = re.search(rf"(?<![A-Za-z0-9_$])(?:{function_group})\s*\((.*)", line)
        if bare:
            return bare.group(1), 'child_process exec'

    return None


def extend_path(meta, new_node):
    clone = deepcopy(meta)
    path = list(clone.get('path') or [clone.get('source', new_node)])
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT-1):]
    path.append(new_node)
    clone['path'] = path
    return clone


def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        sources = assignment_sources(expr)
        if sources:
            snippet, label = sources[0]
            tainted[target] = {
                'source': snippet,
                'source_label': label,
                'line': line_no,
                'path': [snippet.strip(), target]
            }
    for _ in range(6):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr):
                continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                clone = extend_path(meta, target)
                clone['line'] = line_no
                tainted[target] = clone
                changed = True
                continue
            sources = assignment_sources(expr)
            if sources:
                snippet, label = sources[0]
                tainted[target] = {
                    'source': snippet,
                    'source_label': label,
                    'line': line_no,
                    'path': [snippet.strip(), target]
                }
                changed = True
        if not changed:
            break
    return tainted


def format_path(path, sink_label):
    seq = list(path)
    if len(seq) >= PATH_LIMIT:
        seq = seq[-(PATH_LIMIT-1):]
    seq.append(sink_label)
    return ' -> '.join(seq)


def analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    child_process_modules, child_process_functions = child_process_bindings(lines)
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped:
            continue
        command_sink = find_child_process_sink(source_line(raw), child_process_modules, child_process_functions)
        if command_sink:
            expr, sink_label = command_sink
            if expr and not expr_has_sanitizer(expr, 'js.taint.command'):
                literal = find_sources(expr)
                if literal:
                    snippet, _ = literal[0]
                    path_desc = f"{snippet.strip()} -> {sink_label}"
                else:
                    ref, meta = expr_has_tainted(expr, tainted)
                    if ref:
                        path_desc = format_path(meta.get('path', [ref]), sink_label)
                    else:
                        path_desc = ''
                if path_desc:
                    try:
                        rel = path.relative_to(BASE_DIR)
                    except ValueError:
                        rel = path.name
                    sample = f"{rel}:{idx} {path_desc}"
                    bucket = issues['js.taint.command']
                    bucket['count'] += 1
                    if len(bucket['samples']) < 3:
                        bucket['samples'].append(sample)
        for regex, rule, sink_label in SINKS:
            match = regex.search(stripped)
            if not match:
                continue
            expr = match.group(1).strip()
            if not expr or expr_has_sanitizer(expr, rule):
                continue
            literal = find_sources(expr)
            if literal:
                snippet, _ = literal[0]
                path_desc = f"{snippet.strip()} -> {sink_label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref:
                    continue
                path_desc = format_path(meta.get('path', [ref]), sink_label)
            try:
                rel = path.relative_to(BASE_DIR)
            except ValueError:
                rel = path.name
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
    for file_path in iter_js_files(ROOT):
        analyze_file(file_path, issues)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    return 0


_SEVERITY = {
    "xss": "critical",
    "eval": "critical",
    "command": "critical",
    "sql": "critical",
}

_MESSAGE = {
    "xss": "Unsanitized data flows to HTML response sinks",
    "eval": "User input reaches eval/Function without sanitization",
    "command": "User input reaches command execution APIs",
    "sql": "User input reaches SQL query builders without sanitization",
}


def scan_file_findings(path: Path):
    """Yield (rule_id, line, col, path_desc) per detection, without the
    heredoc's 3-sample cap — used by the structured run(ctx) path."""
    try:
        text = path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    child_process_modules, child_process_functions = child_process_bindings(lines)
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped:
            continue
        line = source_line(raw)
        command_sink = find_child_process_sink(line, child_process_modules, child_process_functions)
        if command_sink:
            expr, sink_label = command_sink
            if expr and not expr_has_sanitizer(expr, 'js.taint.command'):
                literal = find_sources(expr)
                if literal:
                    snippet, _ = literal[0]
                    path_desc = f"{snippet.strip()} -> {sink_label}"
                else:
                    ref, meta = expr_has_tainted(expr, tainted)
                    if ref:
                        path_desc = format_path(meta.get('path', [ref]), sink_label)
                    else:
                        path_desc = ''
                if path_desc:
                    # every child-process sink regex ends in `\((.*)`, so the
                    # captured expr is a suffix of the searched line
                    yield 'js.taint.command', idx, len(line) - len(expr) + 1, path_desc
        for regex, rule, sink_label in SINKS:
            match = regex.search(stripped)
            if not match:
                continue
            expr = match.group(1).strip()
            if not expr or expr_has_sanitizer(expr, rule):
                continue
            literal = find_sources(expr)
            if literal:
                snippet, _ = literal[0]
                path_desc = f"{snippet.strip()} -> {sink_label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref:
                    continue
                path_desc = format_path(meta.get('path', [ref]), sink_label)
            yield rule, idx, match.start() + 1, path_desc


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's should_skip() relative to the scan root (cwd):
        # the module-global BASE_DIR only exists on the main() parity path.
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for rule, line, col, path_desc in scan_file_findings(path):
            kind = KIND_BY_RULE[rule]
            yield {
                "rule": f"javascript.taint.{kind}",
                "path": str(rel),
                "line": line,
                "col": col,
                "layer": "taint",
                "lang": "javascript",
                "severity": _SEVERITY.get(kind, "warning"),
                "message": f"{_MESSAGE.get(kind, kind)} ({path_desc})",
            }


def _selftest_direct_source_sink(tmp_prefix: str = "ubs_core_taint_js_") -> None:
    import tempfile

    code = (
        "function render(req) {\n"
        "  const snippet = req.query.html;\n"
        "  document.getElementById('out').innerHTML = snippet;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "render.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "javascript.taint.xss", findings
    assert findings[0]["line"] == 3, findings
    assert "req.query.html -> snippet -> innerHTML write" in findings[0]["message"], findings


def _selftest_propagated_sql_taint(tmp_prefix: str = "ubs_core_taint_js_prop_") -> None:
    import tempfile

    code = (
        "async function listAccounts(params) {\n"
        "  const tenant = params.tenant;\n"
        "  const rows = await db.query('SELECT * FROM accounts WHERE t = ' + tenant);\n"
        "  return rows;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "accounts.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "javascript.taint.sql", findings
    assert findings[0]["line"] == 3, findings
    assert "params.tenant -> tenant -> SQL execution" in findings[0]["message"], findings


def _selftest_command_sink(tmp_prefix: str = "ubs_core_taint_js_cmd_") -> None:
    import tempfile

    code = (
        "const { exec } = require('child_process');\n"
        "app.get('/run', (req, res) => {\n"
        "  const cmd = req.query.cmd;\n"
        "  exec(cmd);\n"
        "});\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "run.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "javascript.taint.command", findings
    assert findings[0]["line"] == 4, findings
    assert "req.query.cmd -> cmd -> child_process exec" in findings[0]["message"], findings


def _selftest_sanitizer_suppression(tmp_prefix: str = "ubs_core_taint_js_san_") -> None:
    import tempfile

    code = (
        "app.get('/', (req, res) => {\n"
        "  const html = req.query.html;\n"
        "  res.send(DOMPurify.sanitize(html));\n"
        "});\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "clean.js"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_js_main_") -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "function render(req) {\n"
        "  const snippet = req.query.html;\n"
        "  document.getElementById('out').innerHTML = snippet;\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "render.js"
        target.write_text(code, encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["x", str(tmp)])
    out = buf.getvalue()
    assert out == "js.taint.xss\t1\trender.js:3 req.query.html -> snippet -> innerHTML write\n", repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_sink", _selftest_direct_source_sink),
    ("propagated_sql_taint", _selftest_propagated_sql_taint),
    ("command_sink", _selftest_command_sink),
    ("sanitizer_suppression", _selftest_sanitizer_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="javascript", name="taint_js", run=run, selftests=SELF_TESTS))
