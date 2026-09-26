"""JavaScript/TypeScript taint analysis with sink-specific sanitizer effects.

Executable-expression masks retain template interpolation and source offsets.
Propagation is still flow-insensitive within a file; this is not a complete
interprocedural or control-flow analysis (the remaining D6 work).

Emit dialects:
- main(argv) preserves the legacy output dialect: one
  `rule_id<TAB>count<TAB>sample,sample,...` row per rule with hits
  (rule ids `js.taint.*`, at most 3 comma-joined samples per rule).
- run(ctx) yields one NDJSON finding per detection with rule ids
  `javascript.taint.{kind}` (registry lang prefix).
"""
from __future__ import annotations

import re
import sys
from bisect import bisect_right
from collections import defaultdict, deque
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

# Escaping for one interpreter is not escaping for another. Unknown helpers,
# URL encoders and tag strippers are deliberately not universal sanitizers.
SANITIZERS_BY_RULE = {
    'js.taint.xss': re.compile(
        r'(?<![\w$.])(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|'
        r'he\.escape|(?:lodash|_)\.escape|validator\.escape)\s*\('
    ),
    'js.taint.command': re.compile(r'(?<![\w$.])shellescape\s*\('),
    'js.taint.sql': re.compile(
        r'(?<![\w$.])(?:db|pool|connection|mysql|sqlstring)\.escape\s*\('
    ),
}

CHILD_PROCESS_APIS = ('execFileSync', 'execFile', 'execSync', 'spawnSync', 'spawn', 'exec')
CHILD_PROCESS_API_RE = r"(?:execFileSync|execFile|execSync|spawnSync|spawn|exec)"
CHILD_PROCESS_MODULE_RE = r"['\"](?:node:)?child_process['\"]"

SINKS = [
    (re.compile(r"\.innerHTML\s*=(?!=)"), 'js.taint.xss', 'innerHTML write', False),
    (re.compile(r"\.outerHTML\s*=(?!=)"), 'js.taint.xss', 'outerHTML write', False),
    (re.compile(r"\bdangerouslySetInnerHTML\s*=(?!=)"), 'js.taint.xss', 'dangerouslySetInnerHTML', False),
    (re.compile(r"\binsertAdjacentHTML\s*\("), 'js.taint.xss', 'insertAdjacentHTML', True),
    (re.compile(r"\bdocument\.write\s*\("), 'js.taint.xss', 'document.write', True),
    (re.compile(r"\bres(?:ponse)?\.send\s*\("), 'js.taint.xss', 'HTTP send', True),
    (re.compile(r"\bres(?:ponse)?\.json\s*\("), 'js.taint.xss', 'HTTP json send', True),
    (re.compile(r"\beval\s*\("), 'js.taint.eval', 'eval', True),
    (re.compile(r"\bnew\s+Function\s*\("), 'js.taint.eval', 'Function constructor', True),
    (re.compile(r"\bshell\.exec\s*\("), 'js.taint.command', 'shell.exec', True),
    (re.compile(r"\b(?:db|pool|connection|client|knex|sequelize|prisma)\.(?:query|execute|raw)\s*\("), 'js.taint.sql', 'SQL execution', True),
]

ASSIGN_DECL = re.compile(r"^(?:const|let|var)\s+(.+?)\s*=\s*(.+)")
ASSIGN_SIMPLE = re.compile(r"^([A-Za-z_$][\w$]*)\s*=\s*(?![=])(.+)")
DESTRUCT_OBJECT = re.compile(r"^(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)")
DESTRUCT_ARRAY = re.compile(r"^(?:const|let|var)\s*\[([^]]*)\]\s*=\s*(.+)")

KIND_BY_RULE = {rule: rule.rsplit('.', 1)[-1] for _regex, rule, _label, _call in SINKS}


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


def lexical_views(text: str) -> tuple[str, str]:
    """Return comment-free source and executable code at original offsets.

    Template text is inert, but ${expressions} (including nested templates)
    are executable. Synthetic parentheses keep their boundaries balanced for
    argument scanning. No source text is evaluated. Regex recognition is
    intentionally lexical, not a claim to implement the JavaScript grammar.
    """
    source, code = list(text), list(text)
    frames = [['code', 0]]

    def mask(output, start, end):
        for pos in range(start, end):
            output[pos] = '\n' if text[pos] == '\n' else ' '

    def regex_allowed(pos):
        previous = pos - 1
        while previous >= 0 and code[previous].isspace():
            previous -= 1
        if previous < 0 or code[previous] in '=(:,[!&|?;{}':
            return True
        if previous > 0 and text[previous - 1:previous + 1] == '=>':
            return True
        end = previous + 1
        while previous >= 0 and (code[previous].isalnum() or code[previous] in '_$'):
            previous -= 1
        return ''.join(code[previous + 1:end]) in {'return', 'throw', 'yield', 'case', 'void', 'typeof', 'delete'}

    i = 0
    while i < len(text):
        ch = text[i]
        if frames[-1][0] == 'template':
            code[i] = '\n' if ch == '\n' else ' '
            if ch == '\\':
                mask(code, i, min(i + 2, len(text)))
                i += 2
                continue
            if ch == '`':
                code[i] = ')'
                frames.pop()
            elif text.startswith('${', i):
                code[i + 1] = '('
                frames.append(['expression', 0])
                i += 2
                continue
            i += 1
            continue

        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            end = len(text) if end < 0 else end
            mask(source, i, end)
            mask(code, i, end)
            i = end
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = len(text) if end < 0 else end + 2
            mask(source, i, end)
            mask(code, i, end)
            i = end
            continue
        if ch in ('"', "'"):
            end = i + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                elif text[end] == ch:
                    end += 1
                    break
                elif text[end] == '\n':
                    break
                else:
                    end += 1
            end = min(end, len(text))
            mask(code, i, end)
            code[i] = '0'  # an inert value, not missing syntax
            i = end
            continue
        if ch == '`':
            code[i] = '('
            frames.append(['template', 0])
            i += 1
            continue
        if ch == '/' and regex_allowed(i):
            end, character_class = i + 1, False
            while end < len(text) and text[end] != '\n':
                if text[end] == '\\':
                    end += 2
                    continue
                if text[end] == '[':
                    character_class = True
                elif text[end] == ']':
                    character_class = False
                elif text[end] == '/' and not character_class:
                    end += 1
                    while end < len(text) and text[end].isalpha():
                        end += 1
                    mask(code, i, end)
                    code[i] = '0'
                    i = end
                    break
                end += 1
            else:
                end = -1
            if end >= 0:
                continue
        if frames[-1][0] == 'expression':
            if ch == '{':
                frames[-1][1] += 1
            elif ch == '}':
                if frames[-1][1] == 0:
                    code[i] = ')'
                    frames.pop()
                else:
                    frames[-1][1] -= 1
        i += 1
    return ''.join(source), ''.join(code)


def strip_comments(text: str) -> str:
    return lexical_views(text)[0]


def expression_end(code: str, start: int, *, call: bool = False) -> int:
    """Find a balanced call argument list or assignment expression boundary."""
    stack = []
    closing = {')': '(', ']': '[', '}': '{'}
    previous = ''
    for index in range(start, len(code)):
        char = code[index]
        if char in '([{':
            stack.append(char)
        elif char in closing:
            if not stack:
                return index
            if stack[-1] == closing[char]:
                stack.pop()
        elif char == ';' and not stack:
            return index
        elif char == '\n' and not call and not stack and previous not in '=+-,.?:*/&|':
            return index
        if not char.isspace():
            previous = char
    return len(code)


def split_statements(line: str):
    if ';' not in line:
        return [line]
    parts, buf, depth = [], [], 0
    code = lexical_views(line)[1]
    for index, ch in enumerate(code):
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
        buf.append(line[index])
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
    text, code = lexical_views('\n'.join(lines))
    module_aliases = {'child_process', 'cp'}
    function_aliases = set()
    api_group = CHILD_PROCESS_API_RE

    def bindings(pattern):
        for match in re.finditer(pattern, text):
            if code[match.start()] == text[match.start()]:
                yield match.group(1)

    for pattern in (
        rf"\b(?:const|let|var)\s*\{{([^}}]+)\}}\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)",
        rf"\bimport\s*\{{([^}}]+)\}}\s*from\s+{CHILD_PROCESS_MODULE_RE}",
    ):
        for members in bindings(pattern):
            function_aliases.update(parse_child_process_members(members))
    for pattern in (
        rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)",
        rf"\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+{CHILD_PROCESS_MODULE_RE}",
        rf"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+{CHILD_PROCESS_MODULE_RE}",
    ):
        module_aliases.update(bindings(pattern))
    function_aliases.update(bindings(
        rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)\.{api_group}\b"
    ))

    alias_group = '|'.join(re.escape(alias) for alias in sorted(module_aliases, key=len, reverse=True))
    if alias_group:
        function_aliases.update(bindings(
            rf"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:{alias_group})\.{api_group}\b"
        ))

    return module_aliases, function_aliases


def parse_assignments(lines):
    text, code = lexical_views('\n'.join(lines))
    assignments = []
    seen = set()
    line_starts = [0] + [m.end() for m in re.finditer('\n', text)]
    for boundary in re.finditer(r'(?:^|[;\n{}])\s*', code):
        start = boundary.end()
        statement = text[start:]
        match = None
        for pattern in (DESTRUCT_OBJECT, DESTRUCT_ARRAY, ASSIGN_DECL, ASSIGN_SIMPLE):
            match = pattern.match(statement)
            if match:
                break
        if match is None:
            continue
        expr_start = start + match.start(2)
        if expr_start in seen:
            continue
        seen.add(expr_start)
        raw_target = match.group(1)
        # A declaration's colon is a TypeScript annotation, whereas an object
        # destructuring colon introduces the local binding name.
        if pattern is ASSIGN_DECL:
            raw_target = raw_target.split(':', 1)[0]
        targets = parse_targets(raw_target)
        end = expression_end(code, expr_start)
        expr = text[expr_start:end].strip()
        for target in targets:
            assignments.append((bisect_right(line_starts, start), target, expr))
    return assignments


def find_sources(expr: str):
    matches = []
    code = lexical_views(expr)[1]
    for regex, label in SOURCE_PATTERNS:
        for match in regex.finditer(expr):
            if code[match.start():match.start() + 1] != expr[match.start():match.start() + 1]:
                continue
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


def unsanitized_expression(expr: str, sink_rule: str | None) -> str:
    """Mask only complete sanitizer call results, not their unsafe siblings.

    Replacing complete calls with spaces preserves offsets and cannot join
    identifiers. Delimiters in strings and comments do not close calls.
    An incomplete call is not evidence of sanitization.
    """
    regex = SANITIZERS_BY_RULE.get(sink_rule)
    if regex is None:
        return expr
    code = lexical_views(expr)[1]
    out = list(expr)
    stack, closes = [], {}
    for index, char in enumerate(code):
        if char == '(':
            stack.append(index)
        elif char == ')' and stack:
            closes[stack.pop()] = index
    covered_until = 0
    for match in regex.finditer(code):
        if match.start() < covered_until:
            continue
        previous = match.start() - 1
        while previous >= 0 and code[previous].isspace():
            previous -= 1
        if previous >= 0 and code[previous] == '.':
            continue
        end = closes.get(match.end() - 1)
        if end is None:
            continue
        following = end + 1
        while following < len(code) and code[following].isspace():
            following += 1
        if following < len(code) and code[following] in '.[':
            # Slicing SQL quotes or reversing HTML escaping invalidates the
            # sanitizer guarantee. Unknown chained transformations stay tainted.
            continue
        covered_until = end + 1
        out[match.start():covered_until] = [
            '\n' if char == '\n' else ' ' for char in expr[match.start():covered_until]
        ]
    return ''.join(out)


def query_argument(expr: str) -> str:
    """Isolate SQL text: bound data never makes a dynamic query safe."""
    stack = []
    closing = {')': '(', ']': '[', '}': '{'}
    for index, char in enumerate(lexical_views(expr)[1]):
        if char in '([{':
            stack.append(char)
        elif char in closing:
            if not stack or stack[-1] != closing[char]:
                # Malformed syntax is not evidence for excluding the rest.
                return expr
            stack.pop()
        elif char == ',' and not stack:
            return expr[:index]
    return expr


def expr_has_tainted(expr: str, tainted):
    expr = lexical_views(expr)[1]
    for name, meta in tainted.items():
        if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expr):
            return name, meta
    return None, None


def child_process_sinks(text: str, code: str, module_aliases, function_aliases):
    patterns = [rf"\brequire\s*\(\s*{CHILD_PROCESS_MODULE_RE}\s*\)\.{CHILD_PROCESS_API_RE}\s*\("]
    alias_group = '|'.join(re.escape(alias) for alias in sorted(module_aliases, key=len, reverse=True))
    if alias_group:
        patterns.append(rf"(?<![A-Za-z0-9_$])(?:{alias_group})\.{CHILD_PROCESS_API_RE}\s*\(")
    function_group = '|'.join(re.escape(name) for name in sorted(function_aliases, key=len, reverse=True))
    if function_group:
        patterns.append(rf"(?<![A-Za-z0-9_$])(?:{function_group})\s*\(")
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            if code[match.start()] != text[match.start()] or match.end() in seen:
                continue
            seen.add(match.end())
            yield match.start(), match.end(), 'js.taint.command', 'child_process exec', True


def extend_path(meta, new_node):
    clone = deepcopy(meta)
    path = list(clone.get('path') or [clone.get('source', new_node)])
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT-1):]
    path.append(new_node)
    clone['path'] = path
    return clone


def record_taint(assignments, sink_rule: str | None = None):
    assignments = [(line, target, unsanitized_expression(expr, sink_rule))
                   for line, target, expr in assignments]
    tainted = {}
    dependents = defaultdict(list)
    for line_no, target, expr in assignments:
        code = lexical_views(expr)[1]
        for name in set(re.findall(r'[A-Za-z_$][\w$]*', code)):
            dependents[name].append((line_no, target))
        sources = assignment_sources(expr)
        if sources:
            snippet, label = sources[0]
            tainted[target] = {
                'source': snippet,
                'source_label': label,
                'line': line_no,
                'path': [snippet.strip(), target]
            }
    # A monotone worklist visits each newly tainted binding once. Unlike a
    # whole-file rescan loop this handles long reverse-ordered chains without
    # either a hop cutoff or quadratic numbers of assignment visits.
    pending = deque(tainted)
    while pending:
        ref = pending.popleft()
        for line_no, target in dependents[ref]:
            if target not in tainted:
                clone = extend_path(tainted[ref], target)
                clone['line'] = line_no
                tainted[target] = clone
                pending.append(target)
    return tainted


def format_path(path, sink_label):
    seq = list(path)
    if len(seq) >= PATH_LIMIT:
        seq = seq[-(PATH_LIMIT-1):]
    seq.append(sink_label)
    return ' -> '.join(seq)


def analyze_file(path, issues):
    # Both public entrypoints consume the same uncapped finding stream.
    for rule, line, _col, path_desc in scan_file_findings(path):
        try:
            rel = path.relative_to(BASE_DIR)
        except ValueError:
            rel = path.name
        bucket = issues[rule]
        bucket['count'] += 1
        if len(bucket['samples']) < 3:
            bucket['samples'].append(f"{rel}:{line} {path_desc}")


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
    text, code = lexical_views(text)
    lines = text.splitlines()
    line_starts = [0] + [match.end() for match in re.finditer('\n', text)]
    assignments = parse_assignments(lines)
    tainted_by_rule = {rule: record_taint(assignments, rule) for rule in KIND_BY_RULE}
    child_process_modules, child_process_functions = child_process_bindings(lines)
    sinks = list(child_process_sinks(text, code, child_process_modules, child_process_functions))
    for regex, rule, label, call in SINKS:
        sinks.extend((match.start(), match.end(), rule, label, call) for match in regex.finditer(code))
    for start, expr_start, rule, sink_label, call in sorted(sinks):
        expr = text[expr_start:expression_end(code, expr_start, call=call)]
        if rule == 'js.taint.sql':
            expr = query_argument(expr)
        expr = unsanitized_expression(expr, rule)
        literal = find_sources(expr)
        if literal:
            snippet, _ = literal[0]
            path_desc = f"{snippet.strip()} -> {sink_label}"
        else:
            ref, meta = expr_has_tainted(expr, tainted_by_rule[rule])
            if not ref:
                continue
            path_desc = format_path(meta.get('path', [ref]), sink_label)
        line = bisect_right(line_starts, start)
        yield rule, line, start - line_starts[line - 1] + 1, path_desc


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
        rel = path.resolve()
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
