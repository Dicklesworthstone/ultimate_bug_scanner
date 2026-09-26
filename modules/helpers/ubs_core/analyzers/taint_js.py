"""JavaScript/TypeScript taint analysis with sink-specific sanitizer effects.

Executable-expression masks retain template interpolation and source offsets.
Local functions use finite return/sink summaries and ordered assignment state.
Known local allocations retain heap aliases, property state and ordinary array
mutator effects. General heap mutation through helper calls is not summarized.
The lexical front end handles ordinary functions, arrows and structured blocks;
cross-file calls, dynamic dispatch and the full JavaScript grammar are not modeled.

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
from dataclasses import dataclass, field
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
        seq = [seq[0], *seq[-(PATH_LIMIT-2):]]
    seq.append(sink_label)
    return ' -> '.join(seq)


@dataclass(frozen=True)
class _Trace:
    origin: tuple
    # Evidence is deliberately outside equality: recursive calls cannot grow
    # the finite fact lattice by repeatedly appending their names to a path.
    path: tuple[str, ...] = field(default=(), compare=False)


class _Fact(frozenset):
    """Immutable taint origins plus references to finite allocation sites.

    References are not taint: a clean object is still a value, and two names
    can refer to it before a later property write introduces any source.
    """

    def __new__(cls, traces=(), refs=()):
        value = super().__new__(cls, traces)
        object.__setattr__(value, 'refs', frozenset(refs))
        return value

    def __setattr__(self, name, value):
        raise AttributeError('taint facts are immutable')

    def __bool__(self):
        return bool(len(self) or self.refs)

    def __eq__(self, other):
        return (isinstance(other, frozenset) and frozenset.__eq__(self, other)
                and self.refs == getattr(other, 'refs', frozenset()))

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        # Retain the frozenset hash for ordinary scalar facts.
        return hash((frozenset(self), self.refs)) if self.refs else frozenset.__hash__(self)


def _refs(fact):
    return getattr(fact, 'refs', frozenset())


def _materialize(fact, heap, seen=frozenset()):
    """Snapshot reachable taint at a consumption point; cycles are finite."""
    result = frozenset()
    pending, visited = [fact], set(seen)
    while pending:
        current = pending.pop()
        result = _join(result, frozenset(current))
        for ref in _refs(current) - visited:
            visited.add(ref)
            pending.extend(heap.get(ref, {}).values())
    return result


def _join(*facts):
    traces = {}
    for fact in facts:
        for trace in fact:
            previous = traces.get(trace)
            if previous is None or (len(trace.path), trace.path) < (len(previous.path), previous.path):
                traces[trace] = trace
    return _Fact(traces.values(), frozenset().union(*(_refs(fact) for fact in facts)))


def _step(fact, name):
    traces = []
    for trace in fact:
        path = (*trace.path, name)
        if len(path) > PATH_LIMIT:
            path = (path[0], *path[-(PATH_LIMIT - 1):])
        traces.append(_Trace(trace.origin, path))
    return _Fact(traces, _refs(fact))


class _State(dict):
    def __init__(self, values=(), bindings=None):
        super().__init__(values)
        self.bindings = dict(bindings if bindings is not None else getattr(values, 'bindings', {}))
        # Visible names and captured cells are separate: a caller's shadowing
        # local must never redirect a callee's write into its lexical parent.
        self.owners = dict(getattr(values, 'owners', {}))
        self.cells = dict(getattr(values, 'cells', {}))
        self.heap = {ref: dict(slots) for ref, slots in getattr(values, 'heap', {}).items()}
        self.weak_refs = set(getattr(values, 'weak_refs', ()))
        self.array_lengths = dict(getattr(values, 'array_lengths', {}))
        self.written_cells = set(getattr(values, 'written_cells', ()))

    def copy(self):
        return _State(self)

    def __eq__(self, other):
        return (isinstance(other, _State) and dict.__eq__(self, other)
                and self.bindings == other.bindings and self.owners == other.owners
                and self.cells == other.cells and self.heap == other.heap
                and self.weak_refs == other.weak_refs and self.array_lengths == other.array_lengths
                and self.written_cells == other.written_cells)


def _cell_input(key):
    return frozenset({_Trace(('capture', key), (key[2],))})


def _cell_value(key, state):
    if state.owners.get(key[2]) == key and key[2] in state:
        return state[key[2]]
    return state.cells.get(key, _cell_input(key))


def _join_states(*states):
    states = [state for state in states if state is not None]
    if not states:
        return None
    names = set().union(*(state.keys() for state in states))
    bindings = {}
    for name in set().union(*(state.bindings.keys() for state in states)):
        candidates = [state.bindings.get(name) for state in states]
        bindings[name] = candidates[0] if all(value is candidates[0] for value in candidates) else None
    result = _State({name: _join(*(state.get(name, frozenset()) for state in states)) for name in names}, bindings)
    for state in states:
        result.owners.update(state.owners)
    for name, key in result.owners.items():
        if name in names:
            result[name] = _join(*(state[name] if name in state else _cell_value(key, state) for state in states))
    for key in set().union(*(state.cells.keys() for state in states)):
        # A branch without a write preserves the incoming cell, not bottom.
        # This also permits a definitely executed clean setter to kill taint.
        result.cells[key] = _join(*(_cell_value(key, state) for state in states))
    for ref in set().union(*(state.heap.keys() for state in states)):
        # Allocation sites can be absent on one branch; only paths on which
        # the object exists contribute its property values.
        objects = [state.heap[ref] for state in states if ref in state.heap]
        keys = set().union(*(slots.keys() for slots in objects))
        result.heap[ref] = {key: _join(*(slots.get(key, frozenset()) for slots in objects)) for key in keys}
    result.weak_refs = set().union(*(state.weak_refs for state in states))
    result.written_cells = set().union(*(state.written_cells for state in states))
    for ref in set().union(*(state.array_lengths.keys() for state in states)):
        lengths = [state.array_lengths[ref] for state in states if ref in state.array_lengths]
        result.array_lengths[ref] = lengths[0] if all(length == lengths[0] for length in lengths) else None
    return result


@dataclass(eq=False)
class _Scope:
    start: int
    end: int
    body_start: int
    body_end: int
    name: str = ''
    params: tuple = ()
    declaration: bool = False
    concise: bool = False
    parent: object = None
    children: list = field(default_factory=list)
    code: str = ''
    statements: list = field(default_factory=list)
    parameter_sources: dict = field(default_factory=dict)


@dataclass
class _Statement:
    kind: str
    start: int
    end: int
    body: list = field(default_factory=list)
    alternate: list = field(default_factory=list)
    extra: object = None


@dataclass(eq=False)
class _HeapCall:
    """A reusable transfer summary for one abstract heap input, not an inline AST.

    The worklist evaluates callees separately. Inputs retain alias equivalence
    and exact property facts; different actual inputs never share mutable state.
    """

    scope: _Scope
    rule: str
    location: int
    bound: dict
    incoming: _State
    ancestors: frozenset
    result: object = None
    readers: set = field(default_factory=set)


def _pairs(code, start=0, end=None):
    stack, pairs = [], {}
    close_to_open = {')': '(', ']': '[', '}': '{'}
    for index in range(start, len(code) if end is None else end):
        char = code[index]
        if char in '([{':
            stack.append((char, index))
        elif char in close_to_open and stack and stack[-1][0] == close_to_open[char]:
            _, start = stack.pop()
            pairs[start] = index
            pairs[index] = start
    return pairs


def _chunks(code, start, end, separator=','):
    """Split balanced lists without splitting strings or template expressions."""
    pairs = _pairs(code, start, end)
    cursor = part = start
    while cursor < end:
        if code[cursor] in '([{' and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if code[cursor] == separator:
            if separator == '=' and (code[cursor:cursor + 2] in {'=>', '=='}
                                     or code[cursor - 1:cursor] in {'=', '!', '<', '>'}):
                cursor += 1
                continue
            yield part, cursor
            part = cursor + 1
        cursor += 1
    yield part, end


def _parameters(text, code, start, end):
    result = []
    for left, right in _chunks(code, start, end):
        parameter = text[left:right].strip()
        if not parameter:
            continue
        rest = parameter.startswith('...')
        _, equals = next(_chunks(code, left, right, '='))
        declaration = text[left:equals].strip().removeprefix('...')
        targets = _binding_names(declaration)
        default = (equals + 1, right) if equals < right else None
        result.append((tuple(targets), rest, default))
    return tuple(result)


def _binding_paths(target, prefix=()):
    """Keep destructured property names separate from their local aliases."""
    target = target.strip()
    if target.startswith(('{', '[')):
        bindings = []
        code = lexical_views(target)[1]
        end = target.rfind('}' if target[0] == '{' else ']')
        for index, (left, right) in enumerate(_chunks(code, 1, end)):
            _, equals = next(_chunks(code, left, right, '='))
            component = str(index)
            if target[0] == '{':
                _, colon = next(_chunks(code, left, equals, ':'))
                component = target[left:colon].strip().strip('\'"')
                if colon < equals:
                    left = colon + 1
            bindings.extend(_binding_paths(target[left:equals], (*prefix, component)))
        return bindings
    name = target.removeprefix('...').split(':', 1)[0].rstrip('?').strip()
    return [(name, prefix)] if re.fullmatch(r'[A-Za-z_$][\w$]*', name) else []


def _binding_names(target):
    return [name for name, _ in _binding_paths(target)]


def _parameter_sources(text, code, start, end):
    sources = {}
    for left, right in _chunks(code, start, end):
        _, equals = next(_chunks(code, left, right, '='))
        for name, path in _binding_paths(text[left:equals]):
            if not path or not all(re.fullmatch(r'[A-Za-z_$][\w$]*', part) for part in path):
                continue
            matches = assignment_sources('.'.join(path))
            if matches:
                sources[name] = matches[0][0]
    return sources


def _declaration_entries(text, code, start, end):
    head = re.match(r'\s*(const|let|var)\b\s*', text[start:end])
    if head is None:
        return []
    entries = []
    for left, right in _chunks(code, start + head.end(), end):
        _, equals = next(_chunks(code, left, right, '='))
        entries.append((head.group(1), _binding_names(text[left:equals]),
                        equals + 1 if equals < right else None, right))
    return entries


def _signature_body(code, pairs, closing):
    """Find the implementation body, not a brace inside a TS return type."""
    cursor = closing + 1
    while cursor < len(code) and code[cursor].isspace():
        cursor += 1
    if code[cursor:cursor + 1] == '{':
        return cursor
    if code[cursor:cursor + 1] != ':':
        return None
    start, angle = cursor + 1, 0
    cursor = start
    while cursor < len(code):
        char = code[cursor]
        if char == ';' and not angle:
            return None
        if char in '([' and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if char == '<':
            angle += 1
        elif char == '>' and code[cursor - 1:cursor] != '=':
            angle = max(0, angle - 1)
        elif char == '{':
            before = code[start:cursor].rstrip()
            if angle or not before or before[-1:] in {'|', '&', '?', ':'} or before.endswith('=>'):
                if cursor not in pairs:
                    return None
                cursor = pairs[cursor] + 1
                continue
            return cursor
        cursor += 1
    return None


def _type_parameters_end(code, pairs, opening):
    """Return the end of a balanced generic parameter list, if complete."""
    depth, cursor = 1, opening + 1
    while cursor < len(code):
        char = code[cursor]
        if char in '([{' and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if char == '<':
            depth += 1
        elif char == '>' and code[cursor - 1:cursor] != '=':
            depth -= 1
            if depth == 0:
                return cursor + 1
        elif char == ';' and depth == 1:
            return None
        cursor += 1
    return None


def _signature_arrow(code, pairs, closing):
    cursor = closing + 1
    while cursor < len(code) and code[cursor].isspace():
        cursor += 1
    if code[cursor:cursor + 2] == '=>':
        return cursor
    if code[cursor:cursor + 1] != ':':
        return None
    cursor += 1
    while cursor < len(code):
        char = code[cursor]
        if char in '([{' and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if char == '<':
            after = _type_parameters_end(code, pairs, cursor)
            if after is None:
                return None
            cursor = after
            continue
        if code[cursor:cursor + 2] == '=>':
            return cursor
        if char in ';=' or (char == '}' and cursor not in pairs):
            return None
        cursor += 1
    return None


def _function_scopes(text, code):
    """Recognize bounded lexical function forms; never import scanned code."""
    pairs = _pairs(code)
    scopes, body_starts = [], set()
    type_ranges = []
    arrow_parameters = {}

    def parameter_types(start, end):
        for left, right in _chunks(code, start, end):
            _, equals = next(_chunks(code, left, right, '='))
            _, colon = next(_chunks(code, left, equals, ':'))
            if colon < equals:
                type_ranges.append((colon + 1, equals))

    for match in re.finditer(r'\b(?:const|let|var)\s+[A-Za-z_$][\w$]*', code):
        end = expression_end(code, match.start())
        _, equals = next(_chunks(code, match.end(), end, '='))
        if code[match.end():equals].lstrip().startswith(':'):
            type_ranges.append((match.end(), equals))
    # Callback parameter types must be known before visiting any arrow in
    # their enclosing signature; they are not executable nested functions.
    for opening, closing in pairs.items():
        if opening < closing and code[opening] == '(':
            if any(left <= opening < right for left, right in type_ranges):
                continue
            body = _signature_body(code, pairs, closing)
            arrow = _signature_arrow(code, pairs, closing)
            if body is not None or arrow is not None:
                parameter_types(opening + 1, closing)
            if body is not None:
                type_ranges.append((closing + 1, body))
            elif arrow is not None:
                type_ranges.append((closing + 1, arrow))
                arrow_parameters[arrow] = (opening, closing)

    def add(start, params_start, params_end, body, name='', declaration=False, concise=False):
        if body in body_starts:
            return
        if concise:
            end = expression_end(code, body)
            for left, right in _chunks(code, body, end):
                end = right
                break
            body_end = end
        elif code[body:body + 1] == '{' and body in pairs:
            body_end, end = pairs[body], pairs[body] + 1
            body += 1
        else:
            return
        body_starts.add(body if concise else body - 1)
        scope = _Scope(start, end, body, body_end, name,
                       _parameters(text, code, params_start, params_end), declaration, concise)
        scope.parameter_sources = _parameter_sources(text, code, params_start, params_end)
        scopes.append(scope)

    for match in re.finditer(r'\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)?', code):
        opening = match.end()
        while opening < len(code) and code[opening].isspace():
            opening += 1
        if code[opening:opening + 1] == '<':
            after = _type_parameters_end(code, pairs, opening)
            if after is None:
                continue
            type_ranges.append((opening, after))
            opening = after
            while opening < len(code) and code[opening].isspace():
                opening += 1
        if code[opening:opening + 1] != '(':
            continue
        closing = pairs.get(opening)
        if closing is None:
            continue
        body = _signature_body(code, pairs, closing)
        if body is None:
            continue
        type_ranges.append((closing + 1, body))
        prefix = code[:match.start()].rstrip()
        declaration = not prefix or prefix[-1] in ';{}' or bool(re.search(r'\b(?:export|default|async)\s*$', prefix))
        if '\n' in code[max(prefix.rfind(';'), prefix.rfind('}')) + 1:match.start()] and not re.search(r'=\s*$', prefix):
            declaration = True
        add(match.start(), opening + 1, closing, body, match.group(1) or '', declaration)

    for match in re.finditer(r'=>', code):
        if any(left <= match.start() < right for left, right in type_ranges):
            continue
        before = code[:match.start()].rstrip()
        end = len(before)
        if match.start() in arrow_parameters:
            opening, closing = arrow_parameters[match.start()]
            start, params_start, params_end = opening, opening + 1, closing
        elif before.endswith(')') and end - 1 in pairs:
            opening = pairs[end - 1]
            start, params_start, params_end = opening, opening + 1, end - 1
        else:
            typed = re.search(r'\)\s*:\s*[A-Za-z_$][\w$<>\[\]| &.?]*$', before)
            if typed and typed.start() in pairs:
                opening = pairs[typed.start()]
                start, params_start, params_end = opening, opening + 1, typed.start()
            else:
                parameter = re.search(r'[A-Za-z_$][\w$]*$', before)
                if not parameter:
                    continue
                start = params_start = parameter.start()
                params_end = parameter.end()
        # A generic arrow's type-parameter prefix belongs to the function
        # value, not to its enclosing declaration or a comma-separated RHS.
        generic = re.search(r'<[^;={}]*>\s*$', code[:start])
        if generic:
            start = generic.start()
        body = match.end()
        while body < len(code) and code[body].isspace():
            body += 1
        name_match = re.search(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:[^=;\n]+)?\s*=\s*(?:async\s+)?$', code[:start])
        add(start, params_start, params_end, body, name_match.group(1) if name_match else '',
            concise=code[body:body + 1] != '{')

    # Methods are analyzed as isolated scopes even when dynamic receiver
    # dispatch cannot be resolved to a local summary.
    for match in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\(', code):
        if match.group(1) in {'if', 'for', 'while', 'switch', 'catch', 'with', 'function'}:
            continue
        closing = pairs.get(match.end() - 1)
        if closing is None:
            continue
        body = _signature_body(code, pairs, closing)
        if body is not None and body not in body_starts:
            add(match.start(), match.end(), closing, body)

    root = _Scope(0, len(text), 0, len(text), '<module>')
    for scope in sorted(scopes, key=lambda item: (item.start, -item.end)):
        containers = [parent for parent in scopes if parent is not scope
                      and parent.body_start <= scope.start < scope.end <= parent.body_end]
        scope.parent = min(containers, key=lambda item: item.end - item.start) if containers else root
        scope.parent.children.append(scope)
    for scope in [root, *scopes]:
        if not scope.children:
            scope.code = code
            continue
        masked = list(code)
        for child in scope.children:
            masked[child.start:child.end] = ['\n' if char == '\n' else ' ' for char in code[child.start:child.end]]
        scope.code = ''.join(masked)
    return root, scopes


class _Parser:
    def __init__(self, scope):
        self.code = scope.code
        self.pairs = _pairs(self.code, scope.body_start, scope.body_end)

    def skip(self, start, end):
        while start < end and (self.code[start].isspace() or self.code[start] == ';'):
            start += 1
        return start

    def sequence(self, start, end):
        statements = []
        while (start := self.skip(start, end)) < end:
            statement, after = self.statement(start, end)
            statements.append(statement)
            start = max(start + 1, after)
        return statements

    def statement(self, start, end):
        code = self.code
        if code[start] == '{' and start in self.pairs:
            closing = self.pairs[start]
            return _Statement('block', start, closing + 1, self.sequence(start + 1, closing)), closing + 1
        keyword = re.match(r'(if|while|for|do|try|switch|return|throw|break|continue)\b', code[start:])
        if keyword and keyword.group(1) == 'try':
            body_start = self.skip(start + keyword.end(), end)
            if code[body_start:body_start + 1] == '{':
                body, after = self.statement(body_start, end)
                handlers, final = [], []
                lookahead = self.skip(after, end)
                if re.match(r'catch\b', code[lookahead:]):
                    handler_start = self.skip(lookahead + 5, end)
                    if code[handler_start:handler_start + 1] == '(' and handler_start in self.pairs:
                        handler_start = self.skip(self.pairs[handler_start] + 1, end)
                    if code[handler_start:handler_start + 1] == '{':
                        handler, after = self.statement(handler_start, end)
                        handlers = [handler]
                    lookahead = self.skip(after, end)
                if re.match(r'finally\b', code[lookahead:]):
                    final_start = self.skip(lookahead + 7, end)
                    if code[final_start:final_start + 1] == '{':
                        tail, after = self.statement(final_start, end)
                        final = [tail]
                return _Statement('try', start, after, [body], handlers, final), after
        if keyword and keyword.group(1) == 'do':
            body_start = self.skip(start + keyword.end(), end)
            if body_start < end:
                body, after = self.statement(body_start, end)
                lookahead = self.skip(after, end)
                if re.match(r'while\b', code[lookahead:]):
                    opening = self.skip(lookahead + 5, end)
                    if code[opening:opening + 1] == '(' and opening in self.pairs:
                        closing = self.pairs[opening]
                        return _Statement('do', opening + 1, closing, [body]), closing + 1
        if keyword and keyword.group(1) == 'switch':
            opening = self.skip(start + keyword.end(), end)
            if code[opening:opening + 1] == '(' and opening in self.pairs:
                closing = self.pairs[opening]
                body_start = self.skip(closing + 1, end)
                if code[body_start:body_start + 1] == '{' and body_start in self.pairs:
                    body_end = self.pairs[body_start]
                    arms, cursor, default = [], body_start + 1, False
                    while cursor < body_end:
                        label = re.search(r'\b(case|default)\b', code[cursor:body_end])
                        if label is None:
                            break
                        left = cursor + label.start()
                        colon = code.find(':', cursor + label.end(), body_end)
                        if colon < 0:
                            break
                        default |= label.group(1) == 'default'
                        if arms:
                            arms[-1].end = left
                            arms[-1].body = self.sequence(arms[-1].start, left)
                        arms.append(_Statement('case', colon + 1, body_end))
                        cursor = colon + 1
                        while cursor < body_end:
                            if code[cursor] in '([{' and cursor in self.pairs:
                                cursor = self.pairs[cursor] + 1
                            elif re.match(r'(case|default)\b', code[cursor:]):
                                break
                            else:
                                cursor += 1
                    if arms:
                        arms[-1].body = self.sequence(arms[-1].start, body_end)
                    return _Statement('switch', opening + 1, closing, arms, extra=default), body_end + 1
        if keyword and keyword.group(1) in {'if', 'while', 'for'}:
            opening = self.skip(start + keyword.end(), end)
            if code[opening:opening + 1] == '(' and opening in self.pairs:
                closing = self.pairs[opening]
                body_start = self.skip(closing + 1, end)
                if body_start < end:
                    body, after = self.statement(body_start, end)
                    alternate = []
                    lookahead = self.skip(after, end)
                    if keyword.group(1) == 'if' and re.match(r'else\b', code[lookahead:]):
                        other_start = self.skip(lookahead + 4, end)
                        if other_start < end:
                            other, after = self.statement(other_start, end)
                            alternate = [other]
                    return _Statement(keyword.group(1), opening + 1, closing, [body], alternate), after
        finish = min(expression_end(code, start), end)
        if finish <= start:
            finish = start + 1
        kind = keyword.group(1) if keyword else 'expression'
        expression_start = start + keyword.end() if keyword else start
        return _Statement(kind, expression_start, finish), finish + (code[finish:finish + 1] == ';')


class _Flow:
    def __init__(self, engine, scope, rule):
        self.engine, self.scope, self.rule = engine, scope, rule
        self.returned = frozenset()
        self.effects = {}
        self.exit_states = []
        self.parameter_context = False
        self.breaks, self.continues = [], []
        self.pairs = _pairs(scope.code, scope.body_start, scope.body_end)

    def effect(self, start, label, fact, state=None):
        if state is not None:
            fact = _materialize(fact, state.heap)
        if fact:
            key = (start, label)
            self.effects[key] = _join(self.effects.get(key, frozenset()), fact)

    def reference(self, name, state):
        if name in state:
            return state[name]
        if self.scope.parent is not None:
            scope = self.scope.parent if self.parameter_context else self.scope
            position = self.scope.start if self.parameter_context else None
            return _cell_value(self.engine.binding(scope, name, position), state)
        return frozenset()

    def assign(self, name, fact, state, position, binding=None):
        state[name] = _step(fact, name)
        state.bindings[name] = binding
        if re.fullmatch(r'[A-Za-z_$][\w$]*', name):
            key = state.owners.get(name, self.engine.binding(self.scope, name, position))
            state.owners[name] = key
            state.cells[key] = state[name]
            state.written_cells.add(key)

    @staticmethod
    def property_key(raw):
        raw = raw.strip()
        if re.fullmatch(r'[A-Za-z_$][\w$]*|(?:0|[1-9][0-9]*)', raw):
            return raw
        if len(raw) >= 2 and raw[0] in '\'"' and raw[-1] == raw[0] and '\\' not in raw[1:-1]:
            return raw[1:-1]
        return None

    @staticmethod
    def array_index(key):
        if key is not None and re.fullmatch(r'0|[1-9][0-9]*', key):
            # Other numeric-looking names are ordinary properties, not indices.
            return int(key) if len(key) <= 10 and int(key) < 4294967295 else None
        return None

    def access(self, start, end):
        """A variable and balanced dot/bracket selectors, at real offsets."""
        code, text = self.scope.code, self.engine.text
        root = re.match(r'[A-Za-z_$][\w$]*', code[start:end])
        if root is None:
            return None
        selectors, cursor = self.selectors(start + root.end(), end)
        return root.group(), selectors, cursor

    def selectors(self, cursor, end, stop_at_call=False):
        code, text = self.scope.code, self.engine.text
        selectors = []
        while cursor < end:
            before = cursor
            while cursor < end and code[cursor].isspace():
                cursor += 1
            member = re.match(r'\?*\.\s*([A-Za-z_$][\w$]*)', code[cursor:end])
            if member:
                if stop_at_call and code[cursor + member.end():end].lstrip().startswith('('):
                    cursor = before
                    break
                selectors.append((member.group(1), None))
                cursor += member.end()
            elif code[cursor:cursor + 1] == '[' and self.pairs.get(cursor, end) < end:
                closing = self.pairs[cursor]
                raw = text[cursor + 1:closing].strip()
                key = self.property_key(raw) if raw.startswith(('"', "'")) or raw.isdecimal() else None
                selectors.append((key, (cursor + 1, closing) if key is None else None))
                cursor = closing + 1
            else:
                cursor = before
                break
        return selectors, cursor

    def property(self, fact, key, state):
        # Unknown objects retain the original conservative parameter/source
        # fact. Known allocations allow unrelated clean fields to stay clean.
        result = frozenset(fact)
        for ref in _refs(fact):
            slots = state.heap.get(ref, {})
            if key == 'length' and ref in state.array_lengths:
                continue  # array length is a count, not attacker-provided text
            if key is None:
                result = _join(result, *slots.values())
            else:
                result = _join(result, slots.get(key, frozenset()), slots.get(None, frozenset()))
        return result

    def read_access(self, parsed, state, evaluate_keys=True):
        root, selectors, _end = parsed
        fact = self.reference(root, state)
        for key, expression in selectors:
            selected = frozenset()
            if expression is not None:
                # Computed keys have effects. Unknown/external maps also keep
                # conservative selector flow; their unseen stored values are
                # not evidence of safety. Known allocations use their slots.
                selected = (self.value(*expression, state) if evaluate_keys
                            else self.operand_snapshot(*expression, state))
            unknown = not _refs(fact) or bool(frozenset(fact))
            fact = self.property(fact, key, state)
            if unknown:
                fact = _join(fact, selected)
        return fact

    def write_property(self, fact, key, value, state):
        refs = _refs(fact)
        strong = (len(refs) == 1 and key is not None and not frozenset(fact)
                  and not refs & state.weak_refs)
        for ref in refs:
            slots = state.heap.setdefault(ref, {})
            slots[key] = value if strong else _join(slots.get(key, frozenset()), value)
            if ref in state.array_lengths:
                length = state.array_lengths[ref]
                if key is None or key == 'length':
                    state.array_lengths[ref] = None
                elif self.array_index(key) is not None and length is not None:
                    state.array_lengths[ref] = max(length, int(key) + 1)

    def allocate(self, start, end, state):
        text, code = self.engine.text, self.scope.code
        ref = (self.scope, start)
        slots = {}
        array = code[start] == '['
        unknown_offset = False
        length = 0
        for index, (left, right) in enumerate(_chunks(code, start + 1, end - 1)):
            raw = text[left:right].strip()
            if not raw:
                if array and right < end - 1:
                    length += 1  # an interior hole contributes to array length
                continue
            length += 1
            if raw.startswith('...'):
                begin = left + text[left:right].index('...') + 3
                spread = self.value(begin, right, state)
                if array:
                    unknown_offset = True
                    slots[None] = _join(slots.get(None, frozenset()), _materialize(spread, state.heap))
                else:
                    refs = _refs(spread)
                    if len(refs) == 1 and not frozenset(spread):
                        slots.update(state.heap.get(next(iter(refs)), {}))
                    else:
                        slots[None] = _join(slots.get(None, frozenset()), _materialize(spread, state.heap))
                continue
            if array:
                key, begin = (None if unknown_offset else str(index)), left
            else:
                _, colon = next(_chunks(code, left, right, ':'))
                key = self.property_key(text[left:colon])
                if text[left:colon].strip().startswith('['):
                    opening = left + text[left:colon].index('[')
                    closing = self.pairs.get(opening)
                    if closing is not None:
                        raw_key = text[opening + 1:closing].strip()
                        key = self.property_key(raw_key) if raw_key.startswith(('"', "'")) or raw_key.isdecimal() else None
                        if key is None:
                            self.value(opening + 1, closing, state)
                begin = colon + 1 if colon < right else left
            value = self.value(begin, right, state)
            slots[key] = _join(slots.get(key, frozenset()), value) if key is None else value
        # Repeated visits to a loop allocation site summarize all its objects;
        # do not discard earlier aliases when the site is evaluated again.
        previous = state.heap.get(ref)
        if previous is not None:
            state.weak_refs.add(ref)
            slots = {key: _join(previous.get(key, frozenset()), slots.get(key, frozenset()))
                     for key in previous.keys() | slots.keys()}
        state.heap[ref] = slots
        if array:
            state.array_lengths[ref] = None if unknown_offset or previous is not None else length
        return _Fact(refs=(ref,))

    def mutation_call(self, name, arguments, facts, state):
        """Model ordinary built-in mutators without treating counts as data.

        Exact lengths widen to unknown at branch/loop disagreement. No length
        counter can grow forever in the worklist, and uncertain aliases never
        receive a destructive strong update.
        """
        if name == 'Object.assign' and state.bindings.get('Object', 'imported') == 'imported' and facts:
            target = facts[0]
            if not _refs(target):
                return None
            for source in facts[1:]:
                refs = _refs(source)
                keys = set().union(*(state.heap.get(ref, {}).keys() for ref in refs))
                for key in keys:
                    incoming = self.property(source, key, state)
                    # Missing keys on an alternative source must retain the
                    # target's old value; Object.assign does not delete them.
                    if len(refs) != 1 or frozenset(source):
                        incoming = _join(incoming, self.property(target, key, state))
                    self.write_property(target, key, incoming, state)
                if frozenset(source):
                    self.write_property(target, None, frozenset(source), state)
            return target
        receiver_name, dot, method = name.rpartition('.')
        if not dot or method not in {'push', 'unshift', 'pop', 'shift', 'reverse'}:
            return None
        parts = receiver_name.split('.')
        receiver = self.reference(parts[0], state)
        for key in parts[1:]:
            receiver = self.property(receiver, key, state)
        refs = _refs(receiver)
        if not refs or any(ref not in state.array_lengths or method in state.heap[ref] for ref in refs):
            return None
        returned = frozenset()
        spread = any(self.engine.text[left:right].lstrip().startswith('...') for left, right in arguments)
        for ref in refs:
            slots = state.heap[ref]
            length = state.array_lengths[ref]
            precise = len(refs) == 1 and ref not in state.weak_refs and length is not None
            numeric = {key: value for key, value in slots.items() if self.array_index(key) is not None}
            if method in {'push', 'unshift'}:
                if not facts:
                    continue
                if not precise or spread:
                    slots[None] = _join(slots.get(None, frozenset()), *facts,
                                        *numeric.values() if method == 'unshift' else ())
                    state.array_lengths[ref] = None
                else:
                    if method == 'unshift':
                        for key in numeric:
                            slots.pop(key)
                        slots.update({str(int(key) + len(facts)): value for key, value in numeric.items()})
                    for offset, value in enumerate(facts):
                        slots[str((length if method == 'push' else 0) + offset)] = value
                    state.array_lengths[ref] = length + len(facts)
            elif method in {'pop', 'shift'}:
                if not precise:
                    returned = _join(returned, *slots.values())
                elif length:
                    index = str(length - 1) if method == 'pop' else '0'
                    returned = _join(returned, slots.pop(index, frozenset()), slots.get(None, frozenset()))
                    if method == 'shift':
                        for key in numeric:
                            slots.pop(key, None)
                        slots.update({str(int(key) - 1): value for key, value in numeric.items() if int(key) > 0})
                    state.array_lengths[ref] = length - 1
            else:  # reverse returns the same array, not a copy
                if precise:
                    for key in numeric:
                        slots.pop(key)
                    slots.update({str(length - int(key) - 1): value for key, value in numeric.items() if int(key) < length})
                else:
                    slots[None] = _join(slots.get(None, frozenset()), *numeric.values())
        return receiver if method == 'reverse' else returned

    def operand_snapshot(self, start, end, state):
        """Consume non-call operands before a later call mutates the heap."""
        text, code = self.engine.text[start:end], self.scope.code[start:end]
        facts = [frozenset({_Trace(('source', source), (source,))})
                 for source, _ in assignment_sources(text)]
        consumed = 0
        for match in re.finditer(r'(?<![\w$.])[A-Za-z_$][\w$]*', code):
            if match.start() < consumed or code[match.end():].lstrip().startswith(':'):
                continue
            if match.group() in {'true', 'false', 'null', 'undefined', 'new', 'await', 'typeof', 'void', 'this'}:
                continue
            parsed = self.access(start + match.start(), end)
            if parsed:
                facts.append(self.read_access(parsed, state, evaluate_keys=False))
                consumed = parsed[2] - start
        return _materialize(_join(*facts), state.heap)

    def apply_writes(self, writes, callee, bound, state, incoming):
        # Substitute against one pre-call snapshot. Reading a preceding update
        # here would incorrectly turn a swap into two copies of the same cell.
        for key, fact in writes.items():
            value = self.substitute(fact, callee, bound, incoming)
            state.cells[key] = value
            state.written_cells.add(key)
            name = key[2]
            if name not in state or state.owners.get(name) == key:
                state[name], state.owners[name] = value, key
                state.bindings[name] = None

    def callable(self, start, end, state):
        # Parentheses around an arrow do not turn it into an unknown callee.
        # Trim original whitespace: the scope mask also blanks real functions.
        text = self.engine.text
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        while self.scope.code[start:start + 1] == '(' and self.pairs.get(start) == end - 1:
            start, end = start + 1, end - 1
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
        for child in self.scope.children:
            if start <= child.start and child.end <= end and self.scope.code[start:child.start].strip() in {'', 'async'}:
                return child
        name = self.engine.text[start:end].strip()
        if re.fullmatch(r'[A-Za-z_$][\w$]*', name):
            if name in state.bindings:
                return state.bindings[name]
            return self.engine.lookup(self.scope, name)
        return None

    def bind(self, callee, arguments, ranges, state):
        actual, uncertain = [], None

        def expand(fact, left, right):
            nonlocal uncertain
            raw = self.scope.code[left:right].strip()
            if raw.startswith('...'):
                opening = left + self.scope.code[left:right].index('...') + 3
                while opening < right and self.scope.code[opening].isspace():
                    opening += 1
                if self.scope.code[opening:opening + 1] == '[' and self.pairs.get(opening) is not None:
                    closing = self.pairs[opening]
                    if self.scope.code[opening + 1:closing].strip():
                        for begin, finish in _chunks(self.scope.code, opening + 1, closing):
                            if begin == finish == closing:
                                continue  # a trailing comma creates no argument
                            if self.scope.code[begin:finish].strip():
                                expand(self.value(begin, finish, state), begin, finish)
                            else:
                                actual.append((frozenset(), True))  # an array hole is undefined
                    return
                if uncertain is None:
                    uncertain = len(actual)
                fact = self.value(opening, right, state)
            actual.append((fact, raw in {'undefined', 'void 0'}))

        for fact, (left, right) in zip(arguments, ranges):
            expand(fact, left, right)
        bound = {}
        default_flow = None
        default_state = None
        for index, (names, rest, default) in enumerate(callee.params):
            incoming = _join(*(fact for fact, _ in actual[index:])) if rest else (actual[index][0] if index < len(actual) else frozenset())
            missing = index >= len(actual) or actual[index][1]
            if uncertain is not None and index >= uncertain:
                incoming = _join(incoming, *(fact for fact, _ in actual[uncertain:]))
                missing = True
            if default is not None and missing and not rest:
                if default_flow is None:
                    default_flow = _Flow(self.engine, callee, self.rule)
                    default_flow.parameter_context = True
                    default_state = _State()
                    default_state.cells = dict(state.cells)
                    default_state.heap = {ref: dict(slots) for ref, slots in state.heap.items()}
                    default_state.weak_refs = set(state.weak_refs)
                    default_state.array_lengths = dict(state.array_lengths)
                default_state.update(bound)
                for name in bound:
                    default_state.owners[name] = self.engine.binding(callee, name)
                default_flow.pairs.update(_pairs(callee.code, *default))
                bypass = default_state.copy() if uncertain is not None and index >= uncertain else None
                default_fact = default_flow.value(*default, default_state)
                if bypass is not None:
                    # An unknown spread may supply this formal. The default's
                    # effects are possible, not proof that cleanup occurred.
                    default_state = _join_states(bypass, default_state)
                incoming = _join(incoming, default_fact)
            for name in names:
                bound[name] = incoming
        if default_flow is not None:
            incoming = state.copy()
            for (location, label), fact in default_flow.effects.items():
                self.effect(location, label, self.substitute(fact, callee, bound, incoming), incoming)
            state.heap = default_state.heap
            state.weak_refs = default_state.weak_refs
            state.array_lengths = default_state.array_lengths
            writes = {key: value for key, value in default_state.cells.items()
                      if key[0] is not callee and key in default_state.written_cells}
            self.apply_writes(writes, callee, bound, state, incoming)
            for dependency, callers in self.engine.dependents.items():
                if dependency[1] == self.rule and callee in callers:
                    callers.add(self.scope)
        return bound

    def substitute(self, fact, callee, bound, state):
        result = frozenset()
        for trace in fact:
            if trace.origin[0] == 'capture':
                incoming = _cell_value(trace.origin[1], state)
                result = _join(result, _step(incoming, (callee.name or '<callback>') + '()'))
                continue
            kind, owner, name = trace.origin if trace.origin[0] != 'source' else ('source', None, None)
            if kind == 'parameter' and owner is callee:
                incoming = bound.get(name, frozenset())
            elif kind == 'free' and owner is callee and callee.parent is self.scope:
                incoming = self.reference(name, state)
            else:
                incoming = frozenset({trace})
            if incoming:
                incoming = _step(incoming, (callee.name or '<callback>') + '()')
                if kind in {'parameter', 'free'}:
                    for name in trace.path[1:]:
                        incoming = _step(incoming, name)
            result = _join(result, incoming)
        return result

    def value(self, start, end, state):
        text, code = self.engine.text, self.scope.code
        while start < end and code[start].isspace():
            start += 1
        while end > start and code[end - 1].isspace():
            end -= 1
        if start >= end:
            return frozenset()
        if code[start] == '(' and self.pairs.get(start) == end - 1:
            return self.value(start + 1, end - 1, state)
        if code[start] in '[{' and self.pairs.get(start) == end - 1:
            return self.allocate(start, end, state)
        access = self.access(start, end)
        assignment = (re.match(r'\s*(=(?!=|>)|\+=|\|\|=|&&=|\?\?=)\s*', code[access[2]:end])
                      if access else None)
        if assignment:
            target = re.sub(r'\s+', '', text[start:access[2]])
            rhs = access[2] + assignment.end()
            receiver = None
            if access[1]:
                receiver = self.read_access((access[0], access[1][:-1], access[2]), state)
                key, computed = access[1][-1]
                if computed is not None:
                    self.value(*computed, state)
            fact = self.value(rhs, end, state)
            if assignment.group(1) != '=':
                old = self.property(receiver, key, state) if receiver is not None else self.reference(target, state)
                fact = _join(old, fact)
            if receiver is not None and _refs(receiver):
                self.write_property(receiver, key, _step(fact, target), state)
            else:
                self.assign(target, fact, state, start, self.callable(rhs, end, state))
            for location, expr_start, rule, label in self.engine.write_sinks:
                if rule == self.rule and start <= location < rhs <= expr_start:
                    self.effect(location, label, fact, state)
            return fact
        if access and access[2] == end:
            fact = self.read_access(access, state)
            root_fact = self.reference(access[0], state)
            sources = () if _refs(root_fact) and not frozenset(root_fact) else assignment_sources(text[start:end])
            sources = frozenset(_Trace(('source', source), (source,))
                                for source, _ in sources)
            return _join(fact, sources)
        operators, question, colon, depth = [], None, None, 0
        cursor = start
        while cursor < end:
            if code[cursor] in '([{' and cursor in self.pairs:
                cursor = self.pairs[cursor] + 1
                continue
            operator = code[cursor:cursor + 2]
            if operator in {'&&', '||', '??'}:
                operators.append((1 if operator in {'||', '??'} else 2, cursor))
                cursor += 2
                continue
            if code[cursor] == '?' and operator != '?.':
                if question is None:
                    question = cursor
                depth += 1
            elif code[cursor] == ':' and depth:
                depth -= 1
                if depth == 0:
                    colon = cursor
                    break
            cursor += 1
        if question is not None and colon is not None:
            self.value(start, question, state)
            left, right = state.copy(), state.copy()
            facts = (self.value(question + 1, colon, left), self.value(colon + 1, end, right))
            merged = _join_states(left, right)
            state.clear()
            state.update(merged)
            state.bindings = dict(merged.bindings)
            state.owners, state.cells = dict(merged.owners), dict(merged.cells)
            state.heap = merged.heap
            state.weak_refs = merged.weak_refs
            state.array_lengths = merged.array_lengths
            state.written_cells = merged.written_cells
            return _join(*facts)
        if operators:
            _, operator = min(operators, key=lambda item: (item[0], -item[1]))
            left = self.value(start, operator, state)
            branch = state.copy()
            right = self.value(operator + 2, end, branch)
            merged = _join_states(state, branch)
            state.clear()
            state.update(merged)
            state.bindings = dict(merged.bindings)
            state.owners, state.cells = dict(merged.owners), dict(merged.cells)
            state.heap = merged.heap
            state.weak_refs = merged.weak_refs
            state.array_lengths = merged.array_lengths
            state.written_cells = merged.written_cells
            return _join(left, right)
        remainder = list(code[start:end])
        source_remainder = list(text[start:end])
        for child in self.scope.children:
            left, right = max(start, child.start), min(end, child.end)
            if left < right:
                source_remainder[left - start:right - start] = [' '] * (right - left)
        facts = []
        sole_local_call = False
        call_pattern = re.compile(r'(?<![\w$])(?:new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(')
        cursor = start
        while cursor < end:
            match = call_pattern.search(code, cursor, end)
            if match is None:
                break
            opening = match.end() - 1
            closing = self.pairs.get(opening)
            if closing is None or closing >= end:
                cursor = match.end()
                continue
            if cursor < match.start():
                facts.append(self.operand_snapshot(cursor, match.start(), state))
                remainder[cursor - start:match.start() - start] = [' '] * (match.start() - cursor)
                source_remainder[cursor - start:match.start() - start] = [' '] * (match.start() - cursor)
            arguments = [(left, right) for left, right in _chunks(code, opening + 1, closing)
                         if code[left:right].strip()]
            argument_facts = [self.value(left, right, state) for left, right in arguments]
            callee_name = re.sub(r'\s+', '', match.group(1))
            callee = None
            if '.' not in callee_name:
                callee = state.bindings.get(callee_name) if callee_name in state.bindings else self.engine.lookup(self.scope, callee_name)
            if isinstance(callee, _Scope):
                sole_local_call = (code[start:match.start()].strip() in {'', 'await'} and closing + 1 == end)
                self.engine.dependents[(callee, self.rule)].add(self.scope)
                bound = self.bind(callee, argument_facts, arguments, state)
                incoming = state.copy()
                if self.engine.heap_required(callee, bound, incoming):
                    call_fact, effects = self.engine.heap_call(callee, self.rule, match.start(), bound, state)
                    for (location, label), fact in effects.items():
                        self.effect(location, label, fact)
                else:
                    returned, effects, writes = self.engine.summaries.get((callee, self.rule), (frozenset(), {}, {}))
                    call_fact = self.substitute(returned, callee, bound, incoming)
                    for (location, label), fact in effects.items():
                        self.effect(location, label, self.substitute(fact, callee, bound, incoming), incoming)
                    self.apply_writes(writes, callee, bound, state, incoming)
            else:
                mutation = self.mutation_call(callee_name, arguments, argument_facts, state)
                call_fact = _join(*argument_facts)
                receiver = callee_name.split('.')[0]
                if '.' in callee_name:
                    call_fact = _join(call_fact, self.reference(receiver, state))
                # Argument facts already retain precise local-call returns.
                # Only a source in the callee itself introduces new input.
                candidate = text[match.start():closing + 1]
                for pattern, _ in SOURCE_PATTERNS:
                    source_match = pattern.search(candidate)
                    if source_match and source_match.start() <= opening - match.start():
                        source = source_match.group(0)
                        call_fact = _join(call_fact, frozenset({_Trace(('source', source), (source,))}))
                sink = self.engine.call_sinks.get(match.start())
                binding = state.bindings.get(receiver, 'imported')
                if sink and sink[0] == self.rule and state.bindings.get(callee_name, 'imported') == 'imported':
                    selected = argument_facts[:1] if self.rule == 'js.taint.sql' else argument_facts
                    self.effect(match.start(), sink[1], _join(*selected), state)
                regex = SANITIZERS_BY_RULE.get(self.rule)
                following = code[closing + 1:end].lstrip()
                if regex and regex.match(candidate) and not following.startswith(('.', '[')):
                    previous = code[:match.start()].rstrip()
                    if not previous.endswith('.') and binding == 'imported':
                        call_fact = frozenset()
                # Unknown calls may transform or serialize their arguments;
                # their return is not proof of object identity.
                call_fact = _materialize(call_fact, state.heap)
                if mutation is not None:
                    call_fact = mutation
                    sole_local_call = (code[start:match.start()].strip() in {'', 'await'} and closing + 1 == end)
            selectors, call_end = self.selectors(closing + 1, end, stop_at_call=True)
            for key, computed in selectors:
                selected = self.value(*computed, state) if computed is not None else frozenset()
                unknown = not _refs(call_fact) or bool(frozenset(call_fact))
                call_fact = self.property(call_fact, key, state)
                if unknown:
                    call_fact = _join(call_fact, selected)
            sole_local_call = code[start:match.start()].strip() in {'', 'await'} and call_end == end
            facts.append(call_fact)
            remainder[match.start() - start:call_end - start] = [' '] * (call_end - match.start())
            source_remainder[match.start() - start:call_end - start] = [' '] * (call_end - match.start())
            cursor = call_end
        remaining = ''.join(remainder)
        for source, _ in assignment_sources(''.join(source_remainder)):
            facts.append(frozenset({_Trace(('source', source), (source,))}))
        consumed = 0
        for match in re.finditer(r'(?<![\w$.])[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*', remaining):
            if match.start() < consumed:
                continue
            name = match.group(0)
            name = re.sub(r'\s+', '', name)
            if name in {'true', 'false', 'null', 'undefined', 'new', 'await', 'typeof', 'void', 'this'}:
                continue
            after = remaining[match.end():].lstrip()
            if after.startswith(':'):
                continue  # object literal keys are not variable references
            member = self.access(start + match.start(), end)
            if member:
                facts.append(self.read_access(member, state))
                consumed = member[2] - start
            if '.' in name and name in state and not _refs(self.reference(name.split('.')[0], state)):
                facts.append(state[name])
        result = _join(*facts)
        for location, expr_start, rule, label in self.engine.write_sinks:
            if rule == self.rule and start <= location < end:
                self.effect(location, label, self.value(expr_start, end, state), state)
        return result if sole_local_call else _materialize(result, state.heap)

    def expression(self, start, end, state):
        text = self.engine.text
        raw = text[start:end].strip()
        offset = start + len(text[start:end]) - len(text[start:end].lstrip())
        entries = _declaration_entries(text, self.scope.code, start, end)
        if entries:
            for _, names, rhs, finish in entries:
                fact = self.value(rhs, finish, state) if rhs is not None else frozenset()
                binding = self.callable(rhs, finish, state) if rhs is not None else None
                if rhs is not None and binding is None and re.match(r"\s*require\s*\(\s*['\"][^'\"]+['\"]\s*\)", text[rhs:finish]):
                    binding = 'imported'
                for name in names:
                    self.assign(name, fact, state, start, binding)
            return state
        compound = re.match(r'([A-Za-z_$][\w$]*)\s*(\+=|\|\|=|&&=|\?\?=)\s*(.+)', raw, re.S)
        if compound:
            name = compound.group(1)
            fact = self.value(offset + compound.start(3), end, state)
            self.assign(name, _join(self.reference(name, state), fact), state, start)
            return state
        declaration = None
        for pattern in (DESTRUCT_OBJECT, DESTRUCT_ARRAY, ASSIGN_DECL, ASSIGN_SIMPLE):
            match = pattern.match(raw)
            if match:
                declaration = (pattern, match)
                break
        if declaration:
            pattern, match = declaration
            rhs = offset + match.start(2)
            fact = self.value(rhs, end, state)
            target = match.group(1).split(':', 1)[0] if pattern is ASSIGN_DECL else match.group(1)
            binding = self.callable(rhs, end, state)
            if binding is None and re.match(r"\s*require\s*\(\s*['\"][^'\"]+['\"]\s*\)", text[rhs:end]):
                binding = 'imported'
            for name in parse_targets(target):
                self.assign(name, fact, state, start, binding)
        else:
            self.value(start, end, state)
        return state

    def block(self, statements, state):
        for statement in statements:
            if state is None:
                break
            state = self.statement(statement, state)
        return state

    @staticmethod
    def restore(state, outer, names):
        if state is None:
            return None
        for name in names:
            if name in outer:
                key = outer.owners.get(name)
                state[name] = state.cells.get(key, outer[name])
            else:
                state.pop(name, None)
            if name in outer.bindings:
                state.bindings[name] = outer.bindings[name]
            else:
                state.bindings.pop(name, None)
            if name in outer.owners:
                state.owners[name] = outer.owners[name]
            else:
                state.owners.pop(name, None)
        return state

    def statement(self, node, state):
        if node.kind == 'block':
            local = self.engine.declarations(node.body, block=True)
            outer = state.copy()
            break_count, continue_count = len(self.breaks), len(self.continues)
            for name in local:
                state[name], state.bindings[name] = frozenset(), None
                state.owners[name] = self.engine.binding(self.scope, name, node.start + 1)
            result = self.block(node.body, state)
            for child in self.scope.children:
                if node.start <= child.start < child.end <= node.end:
                    captured = result if result is not None else state
                    key = (child, self.rule)
                    self.engine.captures[key] = _join_states(self.engine.captures.get(key), captured)
            for exit_state in (*self.breaks[break_count:], *self.continues[continue_count:]):
                self.restore(exit_state, outer, local)
            return self.restore(result, outer, local)
        if node.kind == 'if':
            self.value(node.start, node.end, state)
            condition = self.scope.code[node.start:node.end].strip()
            left = self.block(node.body, state.copy()) if condition != 'false' else None
            right = self.block(node.alternate, state.copy()) if condition != 'true' else None
            return _join_states(left, right)
        if node.kind == 'try':
            # An exception may interrupt any statement before the handler.
            # Join prefix states so a later overwrite cannot erase that path.
            entry = state.copy()
            exit_count, break_count, continue_count = len(self.exit_states), len(self.breaks), len(self.continues)
            body = node.body[0].body if node.body and node.body[0].kind == 'block' else node.body
            prefix, current = entry.copy(), entry.copy()
            for statement in body:
                if current is None:
                    break
                current = self.statement(statement, current)
                prefix = _join_states(prefix, current)
            handler = self.block(node.alternate, prefix) if node.alternate else None
            merged = _join_states(current, handler)
            if node.extra:
                # Finally transforms every completion, including pending
                # return/throw/break/continue. Do not keep pre-finally cells in
                # the write summary: a definite cleanup can replace them.
                exits, breaks, continues = (self.exit_states[exit_count:], self.breaks[break_count:],
                                             self.continues[continue_count:])
                self.exit_states[exit_count:] = []
                self.breaks[break_count:] = []
                self.continues[continue_count:] = []
                for destination, pending in ((self.exit_states, exits), (self.breaks, breaks),
                                             (self.continues, continues)):
                    for exit_state in pending:
                        tail = self.block(node.extra, exit_state.copy())
                        if tail is not None:
                            destination.append(tail)
                return self.block(node.extra, merged.copy()) if merged is not None else None
            return merged
        if node.kind == 'switch':
            self.value(node.start, node.end, state)
            previous_breaks = self.breaks
            self.breaks = []
            fallthrough, exits = None, [] if node.extra else [state.copy()]
            for arm in node.body:
                fallthrough = self.block(arm.body, _join_states(state.copy(), fallthrough))
            exits.extend(self.breaks)
            self.breaks = previous_breaks
            return _join_states(fallthrough, *exits)
        if node.kind in {'while', 'for', 'do'}:
            header = list(_chunks(self.scope.code, node.start, node.end, ';'))
            outer = state.copy()
            loop_names = set()
            iteration = None
            if node.kind == 'for' and len(header) == 1:
                iterator = re.match(r'\s*(?:(const|let|var)\s+)?(.+?)\s+(?:of|in)\s+(.+)',
                                    self.engine.text[node.start:node.end], re.S)
                if iterator:
                    iteration = (_binding_names(iterator.group(2)), node.start + iterator.start(3), node.end)
                    if iterator.group(1) in {'const', 'let'}:
                        loop_names.update(iteration[0])
            if node.kind == 'for' and len(header) == 3:
                loop_names.update(name for kind, names, _, _ in _declaration_entries(
                    self.engine.text, self.scope.code, *header[0]) if kind != 'var' for name in names)
                for name in loop_names:
                    state.owners[name] = self.engine.binding(self.scope, name, node.start)
                state = self.expression(*header[0], state)
                condition, update = header[1], header[2]
            else:
                condition, update = (node.start, node.end), None
            outer_breaks, outer_continues = self.breaks, self.continues
            exits = []
            entry, current = state.copy(), state.copy()
            if node.kind == 'do':
                self.breaks, self.continues = [], []
                current = self.block(node.body, current)
                exits.extend(self.breaks)
                current = _join_states(current, *self.continues)
                if current is None:
                    self.breaks, self.continues = outer_breaks, outer_continues
                    return self.restore(_join_states(*exits), outer, loop_names)
                entry = current.copy()
            if self.scope.code[condition[0]:condition[1]].strip() == 'false':
                self.breaks, self.continues = outer_breaks, outer_continues
                return self.restore(_join_states(current, *exits), outer, loop_names)
            while True:
                self.breaks, self.continues = [], []
                self.value(*condition, current)
                body_state = current.copy()
                if iteration:
                    names, left, right = iteration
                    fact = self.value(left, right, body_state)
                    for name in names:
                        if name in loop_names:
                            body_state.owners[name] = self.engine.binding(self.scope, name, node.start)
                        self.assign(name, fact, body_state, node.start)
                after = self.block(node.body, body_state)
                after = _join_states(after, *self.continues)
                if after is not None and update is not None:
                    after = self.expression(*update, after)
                exits.extend(self.breaks)
                merged = _join_states(entry, after)
                if merged == current:
                    break
                current = merged
            self.breaks, self.continues = outer_breaks, outer_continues
            return self.restore(_join_states(current, *exits), outer, loop_names)
        if node.kind == 'return':
            self.returned = _join(self.returned, self.value(node.start, node.end, state))
            self.exit_states.append(state.copy())
            return None
        if node.kind == 'throw':
            self.value(node.start, node.end, state)
            self.exit_states.append(state.copy())
            return None
        if node.kind in {'break', 'continue'}:
            (self.breaks if node.kind == 'break' else self.continues).append(state.copy())
            return None
        return self.expression(node.start, node.end, state)


class _Engine:
    def __init__(self, text, code):
        self.text, self.code = text, code
        self.root, self.functions = _function_scopes(text, code)
        self.scopes = [self.root, *self.functions]
        self.summaries, self.final_states = {}, {}
        self.captures = {}
        self.dependents = defaultdict(set)
        self.heap_calls = {}
        self.current_task = None
        self.pending, self.queued = deque(), set()
        modules, functions = child_process_bindings(text.splitlines())
        sinks = list(child_process_sinks(text, code, modules, functions))
        for regex, rule, label, call in SINKS:
            sinks.extend((match.start(), match.end(), rule, label, call) for match in regex.finditer(code))
        self.call_sinks = {start: (rule, label) for start, _, rule, label, call in sinks if call}
        self.write_sinks = [(start, expr_start, rule, label) for start, expr_start, rule, label, call in sinks if not call]
        for scope in self.scopes:
            scope.statements = _Parser(scope).sequence(scope.body_start, scope.body_end) if not scope.concise else []
        self.binding_regions = {scope: self.regions(scope) for scope in self.scopes}
        self.capture_keys = {}
        self.local_targets = {}
        for scope in self.functions:
            keys, targets = set(), set()
            ranges = [(scope.body_start, scope.body_end)]
            ranges.extend(default for _names, _rest, default in scope.params if default is not None)
            for left, right in ranges:
                for match in re.finditer(r'(?<![\w$.])[A-Za-z_$][\w$]*', scope.code[left:right]):
                    start, end = left + match.start(), left + match.end()
                    if scope.code[end:right].lstrip().startswith(':'):
                        continue
                    name = match.group()
                    key = self.binding(scope, name, start)
                    if key[0] is not scope:
                        keys.add(key)
                    if scope.code[end:right].lstrip().startswith('('):
                        target = self.lookup(scope, name)
                        if target is not None:
                            targets.add(target)
                        # A constant arrow binding is also a lexical target.
                        targets.update(fn for fn in self.functions if fn.name == name)
            self.capture_keys[scope], self.local_targets[scope] = keys, targets
        while True:
            changed = False
            for scope, targets in self.local_targets.items():
                extra = set().union(*(self.capture_keys[target] for target in targets)) - self.capture_keys[scope]
                if extra:
                    self.capture_keys[scope].update(extra)
                    changed = True
            if not changed:
                break
        self.heap_scopes = {scope for scope in self.functions
                            if re.search(r'[\[{]', scope.code[scope.body_start:scope.body_end])}
        # Factories hidden behind ordinary local wrappers still need an object
        # result. This set only grows over the finite set of lexical functions.
        while True:
            added = {scope for scope in self.functions if scope not in self.heap_scopes
                     and any(self.lookup(scope, match.group(1)) in self.heap_scopes
                             for match in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*\(',
                                                      scope.code[scope.body_start:scope.body_end]))}
            if not added:
                break
            self.heap_scopes.update(added)

    def enqueue(self, task):
        if task not in self.queued:
            self.queued.add(task)
            self.pending.append(task)

    def heap_required(self, callee, bound, state):
        return (callee in self.heap_scopes or isinstance(self.current_task, _HeapCall)
                or any(_refs(fact) for fact in bound.values())
                or any(_refs(fact) for fact in state.cells.values()))

    def heap_input(self, callee, bound, incoming, recursive):
        state = _State()
        ancestors, parent = set(), callee.parent
        while parent is not None:
            ancestors.add(parent)
            parent = parent.parent
        state.cells = {key: value for key, value in incoming.cells.items()
                       if key[0] in ancestors and key in self.capture_keys[callee]}
        for name, key in incoming.owners.items():
            if key in state.cells and self.binding(callee, name) == key:
                state[name], state.owners[name] = state.cells[key], key
                state.bindings[name] = incoming.bindings.get(name)
        # Copy only reachable objects, preserving borrowed identities and cycles.
        pending = list(frozenset().union(*(_refs(fact) for fact in (*bound.values(), *state.cells.values()))))
        while pending:
            ref = pending.pop()
            if ref in state.heap:
                continue
            state.heap[ref] = dict(incoming.heap.get(ref, {}))
            for fact in state.heap[ref].values():
                pending.extend(_refs(fact) - state.heap.keys())
            if ref in incoming.array_lengths:
                state.array_lengths[ref] = None if recursive else incoming.array_lengths[ref]
        state.weak_refs = incoming.weak_refs & state.heap.keys()
        return state

    def heap_call(self, callee, rule, location, bound, state):
        """Apply a separately solved summary, preserving borrowed references.

        Fresh allocations retain their finite set of traversed call sites.
        Distinct inner allocations must not merge at an outer return, while
        recursion must not create an unbounded call-history tuple. A collapsed
        allocation is weak; recursive array lengths widen rather than growing.
        """
        task = self.current_task
        ancestors = task.ancestors if isinstance(task, _HeapCall) else frozenset((task,))
        incoming = self.heap_input(callee, bound, state, callee in ancestors)
        signature = (callee, rule, location, frozenset(bound.items()),
                     frozenset(incoming.cells.items()), frozenset(incoming.bindings.items()),
                     frozenset((ref, frozenset(slots.items())) for ref, slots in incoming.heap.items()),
                     frozenset(incoming.weak_refs), frozenset(incoming.array_lengths.items()))
        context = self.heap_calls.get(signature)
        if context is None:
            context = _HeapCall(callee, rule, location, dict(bound), incoming,
                                ancestors | {callee})
            self.heap_calls[signature] = context
            self.enqueue(context)
        context.readers.add(task)
        if context.result is None:
            return frozenset(), {}
        returned, effects, writes, output = context.result
        renamed = {ref: ref if ref in incoming.heap else
                   (*ref[:2], (ref[2] if len(ref) > 2 else frozenset()) | {location})
                   for ref in output.heap}

        def translate(fact):
            return _Fact(fact, (renamed.get(ref, ref) for ref in _refs(fact)))

        # All translations use the same pre-call input. A swap must not read
        # an already-updated slot; borrowed objects keep their caller identity.
        groups = defaultdict(list)
        for old, new in renamed.items():
            groups[new].append(old)
        for new, originals in groups.items():
            keys = set().union(*(output.heap[old].keys() for old in originals))
            slots = {key: _join(*(translate(output.heap[old].get(key, frozenset()))
                                  for old in originals)) for key in keys}
            collision = any(old not in incoming.heap for old in originals) and new in state.heap
            if collision:
                previous = state.heap[new]
                slots = {key: _join(previous.get(key, frozenset()), slots.get(key, frozenset()))
                         for key in previous.keys() | slots.keys()}
            collapsed = len(originals) > 1 or collision
            if collapsed or any(old in output.weak_refs for old in originals):
                state.weak_refs.add(new)
            state.heap[new] = slots
            lengths = [output.array_lengths[old] for old in originals if old in output.array_lengths]
            if lengths:
                state.array_lengths[new] = (lengths[0] if not collapsed
                    and all(length == lengths[0] for length in lengths) else None)
        for key, fact in writes.items():
            value = translate(fact)
            state.cells[key] = value
            state.written_cells.add(key)
            name = key[2]
            if name not in state or state.owners.get(name) == key:
                state[name], state.owners[name], state.bindings[name] = value, key, None
        label = (callee.name or '<callback>') + '()'
        return _step(translate(returned), label), {key: _step(fact, label) for key, fact in effects.items()}

    def analyze_heap(self, context):
        scope, rule = context.scope, context.rule
        state = context.incoming.copy()
        for name in self.declarations(scope.statements):
            state[name], state.bindings[name] = frozenset(), None
            state.owners[name] = self.binding(scope, name)
        for names, _, _ in scope.params:
            for name in names:
                state[name] = context.bound.get(name, frozenset())
                state.bindings[name], state.owners[name] = None, self.binding(scope, name)
        for child in scope.children:
            if child.name and child.declaration:
                state.bindings[child.name] = child
                state.owners[child.name] = self.binding(scope, child.name, child.start)
        flow = _Flow(self, scope, rule)
        if scope.concise:
            flow.returned = flow.value(scope.body_start, scope.body_end, state)
            final = state
        else:
            final = flow.block(scope.statements, state)
        exits = [*flow.exit_states, *([final] if final is not None else [])]
        output = _join_states(*exits)
        if output is None:
            output = context.incoming.copy()
        writes = {key: value for key, value in output.cells.items()
                  if key[0] is not scope and key in output.written_cells}
        return flow.returned, flow.effects, writes, output

    def regions(self, scope):
        """Static lexical identities; dataflow state still supplies values."""
        regions = [(scope.body_start, scope.body_end, name)
                   for names, _, _ in scope.params for name in names]
        blocks = [(scope.body_start, scope.body_end)]
        pending = [(scope.statements, scope.body_start, scope.body_end)]
        while pending:
            statements, left, right = pending.pop()
            for node in statements:
                if node.kind == 'expression':
                    for kind, names, _, _ in _declaration_entries(self.text, scope.code, node.start, node.end):
                        begin, finish = (scope.body_start, scope.body_end) if kind == 'var' else (left, right)
                        regions.extend((begin, finish, name) for name in names)
                if node.kind == 'block':
                    blocks.append((node.start + 1, node.end - 1))
                    pending.append((node.body, node.start + 1, node.end - 1))
                else:
                    if node.kind == 'for':
                        finish = max((child.end for child in node.body), default=node.end)
                        header = next(_chunks(scope.code, node.start, node.end, ';'))
                        for kind, names, _, _ in _declaration_entries(self.text, scope.code, *header):
                            begin, stop = (scope.body_start, scope.body_end) if kind == 'var' else (node.start, finish)
                            regions.extend((begin, stop, name) for name in names)
                        iterator = re.match(r'\s*(let|const|var)\s+(.+?)\s+(?:of|in)\b', self.text[node.start:node.end])
                        if iterator:
                            begin, stop = (scope.body_start, scope.body_end) if iterator.group(1) == 'var' else (node.start, finish)
                            regions.extend((begin, stop, name) for name in _binding_names(iterator.group(2)))
                    pending.append((node.body, left, right))
                pending.append((node.alternate, left, right))
                if node.kind == 'try' and node.extra:
                    pending.append((node.extra, left, right))
        for child in scope.children:
            if child.name and child.declaration:
                left, right = min((span for span in blocks if span[0] <= child.start <= span[1]),
                                  key=lambda span: span[1] - span[0])
                regions.append((left, right, child.name))
        return regions

    def binding(self, scope, name, position=None):
        position = scope.body_start if position is None else position
        while scope is not None:
            matches = [(left, right) for left, right, candidate in self.binding_regions[scope]
                       if candidate == name and left <= position <= right]
            if matches:
                left, _ = min(matches, key=lambda span: span[1] - span[0])
                return scope, left, name
            position, scope = scope.start, scope.parent
        return self.root, self.root.body_start, name

    def lookup(self, scope, name):
        while scope is not None:
            for child in reversed(scope.children):
                if child.name == name and child.declaration:
                    return child
            scope = scope.parent
        return None

    def declarations(self, statements, block=False):
        names = set()
        pending = [(node, True) for node in statements]
        while pending:
            node, direct = pending.pop()
            if node.kind == 'expression':
                for kind, targets, _, _ in _declaration_entries(self.text, self.code, node.start, node.end):
                    if (direct and (not block or kind != 'var')) or (not block and kind == 'var'):
                        names.update(targets)
            if not block:
                pending.extend((child, False) for child in (*node.body, *node.alternate))
        return names

    def analyze(self, scope, rule):
        state = _State()
        for name in self.declarations(scope.statements):
            state[name], state.bindings[name] = frozenset(), None
            state.owners[name] = self.binding(scope, name)
        for names, _, _ in scope.params:
            for name in names:
                state[name] = frozenset({_Trace(('parameter', scope, name), (name,))})
                state.bindings[name] = None
                state.owners[name] = self.binding(scope, name)
        for child in scope.children:
            if child.name and child.declaration:
                state.bindings[child.name] = child
                state.owners[child.name] = self.binding(scope, child.name, child.start)
        flow = _Flow(self, scope, rule)
        if scope.concise:
            flow.returned = flow.value(scope.body_start, scope.body_end, state)
            final = state
        else:
            final = flow.block(scope.statements, state)
        self.final_states[(scope, rule)] = final or state
        exits = [*flow.exit_states, *([final] if final is not None else [])]
        joined = _join_states(*exits)
        writes = {} if joined is None else {key: value for key, value in joined.cells.items() if key[0] is not scope}
        heap = (joined if joined is not None else state).heap
        return (_materialize(flow.returned, heap), flow.effects,
                {key: _materialize(value, heap) for key, value in writes.items()})

    def concrete(self, fact, rule, visited=frozenset()):
        result = frozenset()
        for trace in fact:
            if trace.origin[0] == 'source':
                result = _join(result, frozenset({trace}))
            elif trace.origin[0] == 'capture' and trace.origin not in visited:
                key = trace.origin[1]
                owner = key[0]
                state = self.final_states.get((owner, rule))
                if state is not None:
                    captured = _materialize(_cell_value(key, state), state.heap)
                    result = _join(result, self.concrete(captured, rule, visited | {trace.origin}))
            elif trace.origin[0] == 'parameter':
                _, scope, name = trace.origin
                source = scope.parameter_sources.get(name)
                if source:
                    # Framework entrypoint parameters supply external input.
                    # Known local calls substitute their actual arguments
                    # before this point, so a safe call remains safe.
                    resolved = frozenset({_Trace(('source', source), (source,))})
                    for step in trace.path:
                        resolved = _step(resolved, step)
                    result = _join(result, resolved)
            elif trace.origin[0] == 'free' and trace.origin not in visited:
                _, scope, name = trace.origin
                parent = scope.parent
                while parent is not None:
                    state = self.captures.get((scope, rule), self.final_states.get((parent, rule), {}))
                    if name in state:
                        captured = _materialize(state[name], getattr(state, 'heap', {}))
                        result = _join(result, self.concrete(captured, rule, visited | {trace.origin}))
                        break
                    parent = parent.parent
        return result

    def findings(self):
        found = {}
        for rule in KIND_BY_RULE:
            self.pending, self.queued = deque(reversed(self.scopes)), set(self.scopes)
            while self.pending:
                task = self.pending.popleft()
                self.queued.discard(task)
                self.current_task = task
                if isinstance(task, _HeapCall):
                    result = self.analyze_heap(task)
                    if task.result != result:
                        task.result = result
                        for reader in task.readers:
                            self.enqueue(reader)
                    continue
                scope = task
                summary = self.analyze(scope, rule)
                if self.summaries.get((scope, rule)) != summary:
                    self.summaries[(scope, rule)] = summary
                    for caller in self.dependents[(scope, rule)]:
                        self.enqueue(caller)
            self.current_task = None
            for scope in self.scopes:
                for (location, label), fact in self.summaries[(scope, rule)][1].items():
                    if self.dependents[(scope, rule)]:
                        # Known call sites already instantiated captures at
                        # their program points. Rebinding them to end-of-scope
                        # values here would taint calls that happened earlier.
                        fact = frozenset(trace for trace in fact if trace.origin[0] == 'source')
                    concrete = self.concrete(fact, rule)
                    if concrete:
                        key = (location, rule, label)
                        found[key] = _join(found.get(key, frozenset()), concrete)
        for (location, rule, label), fact in sorted(found.items()):
            trace = min(fact, key=lambda item: (len(item.path), item.path))
            yield location, rule, format_path(trace.path, label)


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
    line_starts = [0] + [match.end() for match in re.finditer('\n', text)]
    for start, rule, path_desc in _Engine(text, code).findings():
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
