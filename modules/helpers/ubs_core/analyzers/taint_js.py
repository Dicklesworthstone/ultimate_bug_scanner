"""JavaScript/TypeScript taint analysis with sink-specific sanitizer effects.

Executable-expression masks retain template interpolation and source offsets.
Local functions use finite return/sink summaries and ordered assignment state.
Selected relative ES modules and static CommonJS interfaces share call summaries
without sharing lexical locals. Heap identities and mutations propagate through
local/imported helpers; require snapshots retain shared export object identity.
Package resolution, dynamic loaders/dispatch and the full grammar are not modeled.

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
from os.path import commonpath
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.taint_flow import AnalysisLimit, Budget

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'node_modules', '.next', '.nuxt', '.cache', 'dist', 'build', 'coverage', 'tmp', '.turbo'}
EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts'}
PATH_LIMIT = 5
# Marks the call-site set of an allocation that came back through a widened
# summary (_Engine.heap_call): one weak object per allocation site and context
# into a recursion, instead of one per subset of call sites.
WIDENED = '<widened>'


def _collapsed(ref):
    return (len(ref) > 2 and isinstance(ref[-1], frozenset)
            and any(isinstance(site, tuple) and site[:1] == (WIDENED,) for site in ref[-1]))
ROUTE_PARAM_FIELDS = r"(?:id|slug|user|username|email|name|status|tenant|account|role|filter|search|sort|limit|offset|where|order|table|column)"
# Each whitespace run has exactly one owner: `\s*\(?\s*` split a run of N
# blanks N ways on every failed match, and callers pass expressions whose
# calls are blanked, so a large describe() body cost seconds per call (GH #156).
ROUTE_PARAM_OBJECT = re.compile(r"^\s*(?:\(\s*)?(?:await\s+)?((?:context\.)?params)\s*(?:\)\s*)?$", re.IGNORECASE)

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

# A number carries no markup, SQL or shell syntax. Calls to these globals
# (not a local or relatively imported function of the same name) return
# untainted values.
NUMERIC_CONVERSIONS = re.compile(
    r'(?:parseInt|parseFloat|Number(?:\.(?:parseInt|parseFloat))?|Math\.[A-Za-z_$][\w$]*)'
)

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
    (re.compile(r"\beval\s*\("), 'js.taint.eval', 'eval', True),
    (re.compile(r"\bnew\s+Function\s*\("), 'js.taint.eval', 'Function constructor', True),
    (re.compile(r"\bshell\.exec\s*\("), 'js.taint.command', 'shell.exec', True),
    (re.compile(r"\b(?:db|pool|connection|client|knex|sequelize|prisma)\.(?:query|execute|raw)\s*\("), 'js.taint.sql', 'SQL execution', True),
]

PROPERTY_WRITE_SINKS = {
    'innerHTML': ('js.taint.xss', 'innerHTML write'),
    'outerHTML': ('js.taint.xss', 'outerHTML write'),
    'dangerouslySetInnerHTML': ('js.taint.xss', 'dangerouslySetInnerHTML'),
}
BINDING_WRITE_TARGET = re.compile(
    r'\.\s*(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b'
    r'|\[\s*([\'"])(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\1\s*\]'
)

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


def _materialize(fact, heap, seen=frozenset(), *, budget=None):
    """Snapshot reachable taint at a consumption point; cycles are finite."""
    result = frozenset()
    pending, visited = [fact], set(seen)
    while pending:
        current = pending.pop()
        if budget is not None:
            budget.spend(1 + len(current) + len(_refs(current)))
        result = _join(result, frozenset(current))
        for ref in _refs(current) - visited:
            visited.add(ref)
            slots = heap.get(ref, {})
            if budget is not None:
                budget.spend(1 + len(slots))
            pending.extend(slots.values())
    return result


def _heap_work(heap):
    """Charge reachable fields and facts, not just the number of call sites."""
    return sum(1 + sum(1 + len(value) + len(_refs(value)) for value in slots.values())
               for slots in heap.values())


def _join(*facts):
    nonempty = [fact for fact in facts if fact]
    if not nonempty:
        return _Fact()
    first = nonempty[0]
    if all(fact is first for fact in nonempty):
        # Facts and traces are immutable. Identity also preserves the exact
        # evidence path; equality alone would miss shorter paths to one origin.
        return first
    traces = {}
    for fact in nonempty:
        for trace in fact:
            previous = traces.get(trace)
            if previous is None or (len(trace.path), trace.path) < (len(previous.path), previous.path):
                traces[trace] = trace
    return _Fact(traces.values(), frozenset().union(*(_refs(fact) for fact in nonempty)))


def _step(fact, name):
    traces = []
    for trace in fact:
        path = (*trace.path, name)
        if len(path) > PATH_LIMIT:
            path = (path[0], *path[-(PATH_LIMIT - 1):])
        traces.append(_Trace(trace.origin, path))
    return _Fact(traces, _refs(fact))


class _State(dict):
    def __init__(self, values=(), bindings=None, *, budget=None):
        self.budget = budget if budget is not None else getattr(values, 'budget', None)
        if self.budget is not None:
            self.budget.spend(1 + len(values) + len(getattr(values, 'cells', {}))
                              + len(getattr(values, 'binding_kinds', {}))
                              + _heap_work(getattr(values, 'heap', {})))
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
        self.binding_kinds = dict(getattr(values, 'binding_kinds', {}))

    def copy(self):
        return _State(self)

    def __eq__(self, other):
        return (isinstance(other, _State) and dict.__eq__(self, other)
                and self.bindings == other.bindings and self.owners == other.owners
                and self.cells == other.cells and self.heap == other.heap
                and self.weak_refs == other.weak_refs and self.array_lengths == other.array_lengths
                and self.written_cells == other.written_cells
                and self.binding_kinds == other.binding_kinds)

    def __ne__(self, other):
        return not self == other


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
    budget = states[0].budget
    if budget is not None:
        budget.spend(sum(1 + len(state) + len(state.cells) + len(state.binding_kinds) + _heap_work(state.heap)
                         for state in states))
    names = set().union(*(state.keys() for state in states))
    bindings = {}
    for name in set().union(*(state.bindings.keys() for state in states)):
        candidates = [state.bindings.get(name) for state in states]
        bindings[name] = candidates[0] if all(value is candidates[0] for value in candidates) else None
    result = _State({name: _join(*(state.get(name, frozenset()) for state in states)) for name in names},
                    bindings, budget=budget)
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
    for key in set().union(*(state.binding_kinds.keys() for state in states)):
        kinds = [state.binding_kinds.get(key) for state in states]
        result.binding_kinds[key] = kinds[0] if all(kind == kinds[0] for kind in kinds) else None
    for ref in set().union(*(state.array_lengths.keys() for state in states)):
        lengths = [state.array_lengths[ref] for state in states if ref in state.array_lengths]
        result.array_lengths[ref] = lengths[0] if all(length == lengths[0] for length in lengths) else None
    return result


class _ComponentCode:
    """A masked module over shared component code, using component offsets.

    Function masks only change their own module. Concatenating the unchanged
    component prefix/suffix into every scope retained one component-sized
    string per module with children; slices can assemble just the requested
    range instead.
    """

    def __init__(self, component, masked, offset):
        self.component = component
        self.masked = masked
        self.offset = offset

    def __len__(self):
        return len(self.component)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, end, step = key.indices(len(self))
            if step != 1:
                return ''.join(self[index] for index in range(start, end, step))
            if start >= end:
                return ''
            left = max(start, self.offset)
            right = min(end, self.offset + len(self.masked))
            if left >= right:
                return self.component[start:end]
            return (self.component[start:left]
                    + self.masked[left - self.offset:right - self.offset]
                    + self.component[right:end])
        index = key + len(self) if key < 0 else key
        if not 0 <= index < len(self):
            raise IndexError('component code index out of range')
        if self.offset <= index < self.offset + len(self.masked):
            return self.masked[index - self.offset]
        return self.component[index]

    def find(self, value, start=0, end=None):
        if start is not None and start > len(self):
            return -1
        start, stop, _ = slice(start, end).indices(len(self))
        if start > stop:
            return -1
        found = self[start:stop].find(value)
        return start + found if found >= 0 else -1


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
    code: str | _ComponentCode = ''
    statements: list | None = None
    parameter_sources: dict = field(default_factory=dict)
    asynchronous: bool = False
    generator: bool = False


# Slots reduce the retained statement graph on runtimes whose dataclasses
# support them; Python 3.9 uses the same generated behavior without slots.
@dataclass(**({'slots': True} if sys.version_info >= (3, 10) else {}))
class _Statement:
    kind: str
    start: int
    end: int
    body: list | tuple = ()
    alternate: list | tuple = ()
    extra: object = None
    catch_names: tuple = ()
    catch_range: tuple | None = None


class _NoNormalCompletion(Exception):
    """Internal analysis control: this expression has no returning path.

    Exceptional facts are recorded separately by the flow. This is never an
    exception raised by executing the scanned program (which is not run).
    """


class _BoundValues(dict):
    """Actual binding kinds travel to an existing bounded call context."""

    def __init__(self):
        super().__init__()
        self.kinds = {}


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
    widened: bool = False
    superseded: bool = False
    root: object = None
    widened_parent: object = None
    readers: set = field(default_factory=set)


@dataclass(**({'slots': True} if sys.version_info >= (3, 10) else {}))
class _HeapOutput:
    heap: dict
    weak_refs: set
    array_lengths: dict
    binding_kinds: dict = field(default_factory=dict)


def _pairs(code, start=0, end=None):
    stack, pairs = [], {}
    if end is not None and start >= end:
        return pairs
    close_to_open = {')': '(', ']': '[', '}': '{'}
    # Materialize this span once; masked component views otherwise dispatch
    # every character through Python while retaining shared component storage.
    for index, char in enumerate(code[start:end], start):
        if char in '([{':
            stack.append((char, index))
        elif char in close_to_open and stack and stack[-1][0] == close_to_open[char]:
            _, start = stack.pop()
            pairs[start] = index
            pairs[index] = start
    return pairs


def _chunks(code, start, end, separator=','):
    """Split balanced lists without splitting strings or template expressions."""
    if start >= end:
        yield start, end
        return
    fragment = code[start:end]
    pairs = _pairs(fragment)
    cursor = part = 0
    while cursor < len(fragment):
        if fragment[cursor] in '([{' and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if fragment[cursor] == separator:
            # Operators can cross the requested span's boundary. Check the
            # original code, then keep yielded coordinates component-relative.
            absolute = start + cursor
            if separator == '=' and (code[absolute:absolute + 2] in {'=>', '=='}
                                     or code[absolute - 1:absolute] in {'=', '!', '<', '>'}):
                cursor += 1
                continue
            yield start + part, absolute
            part = cursor + 1
        cursor += 1
    yield start + part, end


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
        pattern_start = left + len(text[left:equals]) - len(text[left:equals].lstrip())
        if rest:
            pattern_start += 3
        result.append((tuple(targets), rest, default, (pattern_start, equals)))
    return tuple(result)


def _binding_paths(target, prefix=()):
    """Keep destructured property names separate from their local aliases."""
    target = target.strip()
    if target.startswith(('{', '[')):
        bindings = []
        code = lexical_views(target)[1]
        end = _pairs(code).get(0)
        if end is None:
            return []
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
        entries.append((head.group(1), _binding_names(text[left:equals]), left,
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

    def add(start, parameter_span, body, name='', declaration=False, concise=False):
        params_start, params_end = parameter_span
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
        async_prefix = re.search(r'\basync[ \t]*$', code[:start])
        generator = bool(re.match(r'function\s*\*', code[start:]))
        if async_prefix is not None:
            start = async_prefix.start()
        scope = _Scope(start, end, body, body_end, name,
                       _parameters(text, code, params_start, params_end), declaration, concise)
        scope.parameter_sources = _parameter_sources(text, code, params_start, params_end)
        scope.asynchronous = async_prefix is not None
        scope.generator = generator
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
        add(match.start(), (opening + 1, closing), body, match.group(1) or '', declaration)

    for match in re.finditer(r'=>', code):
        if any(left <= match.start() < right for left, right in type_ranges):
            continue
        before = code[:match.start()].rstrip()
        end = len(before)
        if match.start() in arrow_parameters:
            opening, closing = arrow_parameters[match.start()]
            start, params_start, params_end = opening, opening + 1, closing
        elif before.endswith(')') and end - 1 in pairs:
            # pairs is a dict and the key was just tested — ubs:ignore[py.collections.index-arithmetic]
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
        add(start, (params_start, params_end), body, name_match.group(1) if name_match else '',
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
            add(match.start(), (match.end(), closing), body)

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
        keyword = re.match(r'(if|while|for|do|try|switch|return|throw|break|continue)\b', code[start:end])
        if keyword and keyword.group(1) == 'try':
            body_start = self.skip(start + keyword.end(), end)
            if code[body_start:body_start + 1] == '{':
                body, after = self.statement(body_start, end)
                handlers, final, catch_names, catch_range = [], [], (), None
                lookahead = self.skip(after, end)
                if re.match(r'catch\b', code[lookahead:end]):
                    handler_start = self.skip(lookahead + 5, end)
                    if code[handler_start:handler_start + 1] == '(' and handler_start in self.pairs:
                        catch_range = (handler_start + 1, self.pairs[handler_start])
                        catch_names = tuple(_binding_names(code[handler_start + 1:self.pairs[handler_start]]))
                        handler_start = self.skip(self.pairs[handler_start] + 1, end)
                    if code[handler_start:handler_start + 1] == '{':
                        handler, after = self.statement(handler_start, end)
                        handlers = [handler]
                    lookahead = self.skip(after, end)
                if re.match(r'finally\b', code[lookahead:end]):
                    final_start = self.skip(lookahead + 7, end)
                    if code[final_start:final_start + 1] == '{':
                        tail, after = self.statement(final_start, end)
                        final = [tail]
                return _Statement('try', start, after, [body], handlers, final, catch_names, catch_range), after
        if keyword and keyword.group(1) == 'do':
            body_start = self.skip(start + keyword.end(), end)
            if body_start < end:
                body, after = self.statement(body_start, end)
                lookahead = self.skip(after, end)
                if re.match(r'while\b', code[lookahead:end]):
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
                            elif re.match(r'(case|default)\b', code[cursor:body_end]):
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
                    if keyword.group(1) == 'if' and re.match(r'else\b', code[lookahead:end]):
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
        self.effects = {}
        # Completion value and store travel together. A finalizer can replace
        # one without retroactively reevaluating the other.
        self.returns, self.throws = [], []
        self.parameter_context = False
        self.breaks, self.continues = [], []
        self.pairs = _pairs(scope.code, scope.body_start, scope.body_end)

    def branch_value(self, start, end, state):
        try:
            return self.value(start, end, state), state
        except _NoNormalCompletion:
            return frozenset(), None

    @staticmethod
    def replace_state(state, incoming):
        state.clear()
        state.update(incoming)
        state.bindings = dict(incoming.bindings)
        state.owners, state.cells = dict(incoming.owners), dict(incoming.cells)
        state.heap = incoming.heap
        state.weak_refs = incoming.weak_refs
        state.array_lengths = incoming.array_lengths
        state.written_cells = incoming.written_cells
        state.binding_kinds = dict(incoming.binding_kinds)

    def effect(self, start, label, fact, state=None):
        if state is not None:
            fact = _materialize(fact, state.heap, budget=self.engine.budget)
        if fact:
            key = (start, label)
            self.effects[key] = _join(self.effects.get(key, frozenset()), fact)

    def reference(self, name, state):
        if name in state:
            return state[name]
        key = self.engine.binding(self.scope, name)
        captured_require = ((key[0], name) in self.engine.commonjs_locals
                            and self.scope is not key[0])
        imported = self.engine.import_value(key, state, self.rule,
                                           captured_require=captured_require)
        if imported is not None:
            return imported
        if self.scope.parent is not None:
            scope = self.scope.parent if self.parameter_context else self.scope
            position = self.scope.start if self.parameter_context else None
            return _cell_value(self.engine.binding(scope, name, position), state)
        return frozenset()

    def assign(self, name, fact, state, position, binding=None, input_kind=None):
        if input_kind == 'undefined':
            fact = frozenset()
        state[name] = _step(fact, name)
        state.bindings[name] = binding
        if re.fullmatch(r'[A-Za-z_$][\w$]*', name):
            key = state.owners.get(name, self.engine.binding(self.scope, name, position))
            state.owners[name] = key
            state.cells[key] = state[name]
            state.written_cells.add(key)
            state.binding_kinds[key] = (input_kind or
                ('present' if isinstance(binding, _Scope) or (_refs(fact) and not frozenset(fact)) else None))

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
        exported, consumed = None, 0
        local = self.engine.lexical_binding(self.scope, root)
        if root not in state.bindings and (local[0], root) not in self.engine.commonjs_locals:
            names = [root]
            for key, _expression in selectors:
                if key is None:
                    break
                names.append(key)
                candidate = self.engine.import_path(self.scope, names)
                if candidate is None:
                    break
                consumed += 1
                if candidate[2] != '@namespace':
                    exported = candidate
                    break
        if exported is not None:
            fact = self.engine.import_value(exported, state, self.rule)
            fact = frozenset() if fact is None else fact
            selectors = selectors[consumed:]
        else:
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

    def write_property(self, fact, key, value, state, *, initialize_export=False):
        refs = _refs(fact)
        strong = (len(refs) == 1 and key is not None and not frozenset(fact)
                  and not refs & state.weak_refs)
        for ref in refs:
            slots = state.heap.setdefault(ref, {})
            slots[key] = value if strong else _join(slots.get(key, frozenset()), value)
            owner = self.engine.commonjs_namespace_refs.get(ref)
            if owner is not None and not initialize_export:
                # A namespace export is a property of a shared ordinary
                # object, not an immutable ESM binding. Every spelling and
                # borrowed helper must observe writes through that identity.
                module = self.engine.module_roots[owner]
                names = [name for name in module.exports if key is None or name == key]
                for name in names:
                    exported = self.engine.export_key(module, name)
                    if exported is not None:
                        state.cells[exported] = self.property(_Fact(refs=(ref,)), name, state)
                        state.binding_kinds[exported] = None
                        state.written_cells.add(exported)
                        state.bindings[exported[2]] = None
            if ref in state.array_lengths:
                length = state.array_lengths[ref]
                if key is None or key == 'length':
                    state.array_lengths[ref] = None
                elif self.array_index(key) is not None and length is not None:
                    state.array_lengths[ref] = max(length, int(key) + 1)

    def binding_reference(self, start, end, state):
        """Evaluate an assignment target before reading its selected value."""
        text, code = self.engine.text, self.scope.code
        _, end = next(_chunks(code, start, end, '='))
        _, end = next(_chunks(code, start, end, ':'))
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        while code[start:start + 1] == '(' and self.pairs.get(start) == end - 1:
            start, end = start + 1, end - 1
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
        target = self.access(start, end)
        if target is not None and target[2] == end and not target[1]:
            return None
        if target is not None and target[2] == end and target[1]:
            receiver = self.read_access((target[0], target[1][:-1], target[2]), state)
            key, computed = target[1][-1]
        else:
            # The receiver can itself be a call or a parenthesized expression.
            # Retain its evaluated identity before a computed key/default can
            # mutate or rebind it; GetValue of the selected source follows.
            member = re.search(r'\.\s*([A-Za-z_$][\w$]*)\s*$', code[start:end])
            opening = self.pairs.get(end - 1) if code[end - 1:end] == ']' else None
            if opening is not None and opening <= start:
                opening = None
            if member is not None:
                receiver = self.value(start, start + member.start(), state)
                key, computed = member.group(1), None
            elif opening is not None:
                receiver = self.value(start, opening, state)
                raw = text[opening + 1:end - 1].strip()
                key = self.property_key(raw) if raw.startswith(('"', "'")) or raw.isdecimal() else None
                computed = (opening + 1, end - 1) if key is None else None
            else:
                return None
        if computed is not None:
            self.value(*computed, state)
        return start, end, receiver, key

    def binding_input(self, start, end, state):
        """Recognize definite entry values without guessing scalar types.

        `void` consumes one unary expression. A following binary/comma
        operator belongs to a larger value and must not activate a default.
        """
        code = self.engine.code

        def skip(position):
            while position < end and code[position].isspace():
                position += 1
            return position

        start = skip(start)
        while end > start and code[end - 1].isspace():
            end -= 1
        while code[start:start + 1] == '(' and self.pairs.get(start) == end - 1:
            if self.engine.text[start:start + 1] == '`':
                # Template delimiters also become parentheses in the lexical
                # code view. Keep their string identity after outer parens;
                # their interpolation's null/void value is not the input.
                return 'present'
            start, end = skip(start + 1), end - 1
            while end > start and code[end - 1].isspace():
                end -= 1
        raw = code[start:end]
        if raw == 'null':
            return 'null'
        if re.fullmatch(r'[A-Za-z_$][\w$]*', raw) and raw not in {'true', 'false', 'null'}:
            scope, position = self.scope, start
            if self.parameter_context:
                # The parameter environment includes all formals, but body
                # var/let/function declarations cannot shadow an initializer.
                formal = any(raw in names for names, _, _, _ in scope.params)
                if formal:
                    position = scope.body_start
                elif scope.parent is not None:
                    position, scope = scope.start, scope.parent
            lexical = self.engine.lexical_binding(scope, raw, position)
            shadowed = (raw in state or any(name == raw and left == lexical[1]
                        for left, _right, name in self.engine.binding_regions[lexical[0]]))
            if raw == 'undefined' and not shadowed:
                return 'undefined'
            return state.binding_kinds.get(self.engine.binding(scope, raw, position))
        if re.fullmatch(r'(?:true|false|(?:0[xX][\da-fA-F]+|0[bB][01]+|0[oO][0-7]+'
                        r'|[0-9][\d_]*(?:\.[\d_]*)?(?:[eE][+-]?[\d_]+)?)n?)', raw):
            return 'present' if self.engine.text[start:start + 1] in {'"', "'"} else 'noniterable'
        head = re.match(r'void\b', raw)
        if head is None:
            return None
        cursor = skip(start + head.end())
        while cursor < end:
            self.engine.budget.spend()
            prefix = re.match(r'(?:void|typeof|delete|await|new)\b|\+\+|--|[!~+-]', code[cursor:end])
            if prefix is None:
                break
            cursor = skip(cursor + prefix.end())
        function = next((child for child in self.scope.children if child.start == cursor and child.end <= end), None)
        if function is not None:
            cursor = function.end
        elif code[cursor:cursor + 1] in {'(', '[', '{'} and cursor in self.pairs:
            cursor = self.pairs[cursor] + 1
        else:
            primary = re.match(r'[A-Za-z_$][\w$]*|(?:0[xX][\da-fA-F]+|0[bB][01]+|0[oO][0-7]+'
                               r'|[0-9][\d_]*(?:\.[\d_]*)?(?:[eE][+-]?[\d_]+)?)n?', code[cursor:end])
            if primary is None:
                return None
            cursor += primary.end()
        while (cursor := skip(cursor)) < end:
            self.engine.budget.spend()
            member = re.match(r'(?:\?\.)?\.\s*[A-Za-z_$][\w$]*|\?\.\s*[A-Za-z_$][\w$]*', code[cursor:end])
            if member:
                cursor += member.end()
            elif code[cursor:cursor + 2] == '?.' and code[skip(cursor + 2):skip(cursor + 2) + 1] in {'(', '['}:
                opening = skip(cursor + 2)
                cursor = self.pairs.get(opening, end) + 1
            elif code[cursor:cursor + 1] in {'(', '['} and cursor in self.pairs:
                cursor = self.pairs[cursor] + 1
            elif code[cursor:cursor + 2] in {'++', '--'}:
                cursor += 2
            else:
                break
        return 'undefined' if skip(cursor) == end else None

    def binding_entry_failure(self, fact, state, array, missing=False, input_kind=None):
        """Snapshot possible pattern-entry failures before binding effects."""
        unusable = (missing or input_kind in {'null', 'undefined'}
                    or (array and input_kind == 'noniterable'))
        unknown_scalar = (input_kind not in {'present', 'noniterable'}
                          and (not _refs(fact) or frozenset(fact)))
        unknown_iterator = array and any(ref not in state.array_lengths for ref in _refs(fact))
        if unusable or unknown_scalar or unknown_iterator:
            self.throws.append((frozenset(), state.copy()))
        return unusable

    def bind_pattern(self, start, end, fact, state, position, missing=False, binding=None,
                     reference=None, input_kind=None, entry_checked=False):
        """Bind a pattern, preserving field identity and initializer order.

        Scalar facts do not distinguish undefined from another clean scalar,
        so an uncertain default joins both stores; it cannot prove cleanup.
        A definitely absent own slot executes its initializer, while a known
        object value cannot be undefined. Getters and custom iterators remain
        outside this lexical heap model.
        """
        text, code = self.engine.text, self.scope.code
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        if start == end:
            return
        if reference is None:
            reference = self.binding_reference(start, end, state)
        _, equals = next(_chunks(code, start, end, '='))
        if equals < end:
            if missing:
                fact = self.value(equals + 1, end, state)
                input_kind = self.binding_input(equals + 1, end, state)
                missing = input_kind == 'undefined'
                if missing:
                    fact = frozenset()
            elif input_kind is None and (not _refs(fact) or frozenset(fact)):
                # The bypass can be null, while the default has its own
                # result and effects. Check each entry store before joining:
                # the null branch never executes the default initializer.
                nested = code[start:start + 1] in {'{', '['}
                if nested:
                    self.binding_entry_failure(fact, state, code[start] == '[')
                fallback, branch = self.branch_value(equals + 1, end, state.copy())
                fallback_kind = (self.binding_input(equals + 1, end, branch)
                                 if branch is not None else None)
                if fallback_kind == 'undefined':
                    fallback = frozenset()
                if nested and branch is not None:
                    self.binding_entry_failure(fallback, branch, code[start] == '[',
                                               input_kind=fallback_kind)
                entry_checked |= nested
                self.replace_state(state, _join_states(state, branch))
                fact = _join(fact, fallback)
                input_kind = None
            end = equals
            while end > start and text[end - 1].isspace():
                end -= 1
        # A TypeScript annotation describes the value, not another pattern.
        # Inspect only the binding, after separating its initializer; a
        # ternary default's colon is part of its executable expression.
        _, annotation = next(_chunks(code, start, end, ':'))
        if annotation < end:
            end = annotation
            while end > start and text[end - 1].isspace():
                end -= 1
        if code[start:start + 1] in {'{', '['} and self.pairs.get(start) == end - 1:
            # RequireObjectCoercible/GetIterator happens before any selected
            # property's target, default or body. Unknown scalar facts retain
            # that exceptional path; a proven nullish input cannot continue.
            array, excluded = code[start] == '[', set()
            if (not entry_checked and
                    self.binding_entry_failure(fact, state, array, missing, input_kind)):
                raise _NoNormalCompletion
            for index, (left, right) in enumerate(_chunks(code, start + 1, end - 1)):
                while left < right and text[left].isspace():
                    left += 1
                if left == right:
                    continue
                if code[left:left + 3] == '...':
                    target_reference = self.binding_reference(left + 3, right, state)
                    ref, slots = (self.scope, left, 'binding-rest'), {}
                    for parent in _refs(fact):
                        for key, value in state.heap.get(parent, {}).items():
                            if array:
                                numeric = self.array_index(key)
                                if key is not None and (numeric is None or numeric < index):
                                    continue
                                key = str(numeric - index) if numeric is not None else None
                            elif key in excluded:
                                continue
                            slots[key] = _join(slots.get(key, frozenset()), value)
                    if ref in state.heap:
                        previous = state.heap[ref]
                        slots = {key: _join(previous.get(key, frozenset()), slots.get(key, frozenset()))
                                 for key in previous.keys() | slots.keys()}
                        state.weak_refs.add(ref)
                    state.heap[ref] = slots
                    if array:
                        lengths = [state.array_lengths.get(parent) for parent in _refs(fact)]
                        state.array_lengths[ref] = (max(0, lengths[0] - index) if lengths and
                            lengths[0] is not None and all(length == lengths[0] for length in lengths) else None)
                    rest = _Fact(frozenset(fact), refs=(ref,))
                    self.bind_pattern(left + 3, right, rest, state, position,
                                      binding=binding, reference=target_reference)
                    continue
                selected = frozenset()
                if array:
                    key, begin = str(index), left
                else:
                    _, default = next(_chunks(code, left, right, '='))
                    _, colon = next(_chunks(code, left, default, ':'))
                    raw_key = text[left:colon].strip()
                    key = self.property_key(raw_key)
                    if code[left:left + 1] == '[' and left in self.pairs:
                        close = self.pairs[left]
                        literal = text[left + 1:close].strip()
                        key = self.property_key(literal) if literal.startswith(('"', "'")) or literal.isdecimal() else None
                        if key is None:
                            selected = self.value(left + 1, close, state)
                    begin = colon + 1 if colon < default else left
                    if key is not None:
                        excluded.add(key)
                # Get the target reference before GetV/IteratorStep and its
                # default. A computed target can mutate the source or throw;
                # retain its receiver so later effects cannot rebind it.
                target_reference = self.binding_reference(begin, right, state)
                value = self.property(fact, key, state)
                if not _refs(fact) or frozenset(fact):
                    value = _join(value, selected)
                absent = (bool(_refs(fact)) and not frozenset(fact) and key is not None
                          and all(key not in state.heap.get(parent, {}) and None not in state.heap.get(parent, {})
                                  for parent in _refs(fact)))
                self.bind_pattern(begin, right, value, state, position, absent, binding, target_reference)
            return
        if reference is not None:
            start, end, receiver, key = reference
            name = re.sub(r'\s+', '', text[start:end])
            sink = PROPERTY_WRITE_SINKS.get(key)
            if sink is not None and sink[0] == self.rule:
                candidates = list(BINDING_WRITE_TARGET.finditer(text, start, end))
                location = candidates[-1].start() if candidates else start
                self.effect(location, sink[1], fact, state)
            if _refs(receiver):
                self.write_property(receiver, key, _step(fact, name), state)
            else:
                self.assign(name, fact, state, position)
            return
        for name in _binding_names(text[start:end]):
            state.owners[name] = self.engine.binding(self.scope, name, position)
            self.assign(name, fact, state, position, binding,
                        'undefined' if missing else input_kind)

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
                    slots[None] = _join(slots.get(None, frozenset()),
                                        _materialize(spread, state.heap, budget=self.engine.budget))
                else:
                    refs = _refs(spread)
                    if len(refs) == 1 and not frozenset(spread):
                        slots.update(state.heap.get(next(iter(refs)), {}))
                    else:
                        slots[None] = _join(slots.get(None, frozenset()),
                                            _materialize(spread, state.heap, budget=self.engine.budget))
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
        return _materialize(_join(*facts), state.heap, budget=self.engine.budget)

    def apply_writes(self, writes, callee, bound, state, incoming):
        # Substitute against one pre-call snapshot. Reading a preceding update
        # here would incorrectly turn a swap into two copies of the same cell.
        for key, fact in writes.items():
            value = self.substitute(fact, callee, bound, incoming)
            state.cells[key] = value
            state.binding_kinds[key] = None
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
        if re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*', name):
            return self.engine.call_target(self.scope, name, state, self.rule)
        return None

    def evaluate_arguments(self, ranges, state):
        """Evaluate and snapshot each spread before the following argument.

        A later argument may mutate the iterable or replace one of its slots.
        The already yielded values retain their own scalar/object identities.
        """
        actual, uncertain = [], None
        maybe_missing = set()
        input_kinds = {}

        def expand(left, right):
            nonlocal uncertain
            while left < right and self.engine.text[left].isspace():
                left += 1
            while right > left and self.engine.text[right - 1].isspace():
                right -= 1
            raw = self.scope.code[left:right].strip()
            if raw.startswith('...'):
                opening = left + self.scope.code[left:right].index('...') + 3
                while opening < right and self.scope.code[opening].isspace():
                    opening += 1
                if self.scope.code[opening:opening + 1] == '[' and self.pairs.get(opening) == right - 1:
                    closing = self.pairs[opening]
                    elements = []
                    if self.scope.code[opening + 1:closing].strip():
                        for begin, finish in _chunks(self.scope.code, opening + 1, closing):
                            if begin == finish == closing:
                                continue  # a trailing comma creates no argument
                            if self.scope.code[begin:finish].strip():
                                elements.append(expand(begin, finish))
                            else:
                                actual.append((frozenset(), True))  # an array hole is undefined
                    return _join(*elements)
                fact = self.value(opening, right, state)
                refs = _refs(fact)
                lengths = [state.array_lengths.get(ref) for ref in refs]
                if (refs and not frozenset(fact) and lengths[0] is not None
                        and all(length == lengths[0] for length in lengths)):
                    self.engine.budget.spend(lengths[0])
                    for position in range(lengths[0]):
                        key = str(position)
                        missing = all(key not in state.heap.get(ref, {})
                                      and None not in state.heap.get(ref, {}) for ref in refs)
                        value = self.property(fact, key, state)
                        if not missing and (not _refs(value) or frozenset(value)):
                            # Heap scalar facts do not distinguish undefined
                            # from another clean scalar. A default can run,
                            # but its writes are not a definite cleanup.
                            missing = True
                            maybe_missing.add(len(actual))
                        actual.append((value, missing))
                    return _join(*(value for value, _missing in actual[-lengths[0]:])) if lengths[0] else frozenset()
                if uncertain is None:
                    uncertain = len(actual)
                if refs and all(ref in state.array_lengths for ref in refs):
                    # An unknown-length spread supplies array elements, not
                    # the array object itself. Retain borrowed element refs.
                    fact = self.property(fact, None, state)
            else:
                fact = self.value(left, right, state)
            kind = self.binding_input(left, right, state)
            if kind is None and _refs(fact) and not frozenset(fact):
                kind = 'present'
            if kind is not None:
                input_kinds[len(actual)] = kind
            if kind == 'undefined':
                fact = frozenset()  # operand effects ran; the void value is clean
            unknown_undefined = kind is None and raw.strip('() \t\r\n') == 'undefined'
            if unknown_undefined:
                maybe_missing.add(len(actual))
            actual.append((fact, kind == 'undefined' or unknown_undefined))
            return fact

        try:
            facts = [expand(left, right) for left, right in ranges]
        finally:
            # Recursive closures otherwise retain the completed flow and its
            # incoming heap until cyclic GC, including when expansion throws.
            expand = None
        return facts, (actual, uncertain, maybe_missing, input_kinds)

    def bind(self, callee, prepared, state, call_location):
        actual, uncertain, maybe_missing, input_kinds = prepared
        bound = _BoundValues()
        default_flow = None
        default_state = None

        def complete_defaults(normal=True):
            if default_flow is None:
                return
            incoming = state.copy()
            for (location, label), fact in default_flow.effects.items():
                self.effect(location, label, self.substitute(fact, callee, bound, incoming), incoming)
            for fact, store in default_flow.throws:
                exceptional = incoming.copy()
                writes = {key: self.substitute(value, callee, bound, incoming)
                          for key, value in store.cells.items()
                          if key[0] is not callee and key in store.written_cells}
                output = _HeapOutput(store.heap, store.weak_refs, store.array_lengths, store.binding_kinds)
                thrown = self.engine.apply_heap_output(
                    incoming, exceptional, output, writes,
                    self.substitute(fact, callee, bound, incoming), call_location)
                self.throws.append((thrown, exceptional))
            if normal:
                writes = {key: self.substitute(value, callee, bound, incoming)
                          for key, value in default_state.cells.items()
                          if key[0] is not callee and key in default_state.written_cells}
                output = _HeapOutput(default_state.heap, default_state.weak_refs, default_state.array_lengths,
                                     default_state.binding_kinds)
                # Initializers and rest bindings execute before the callee's
                # summary. Give their fresh objects this invocation's history
                # too, while borrowed aliases keep their incoming identities.
                self.engine.apply_heap_output(incoming, state, output, writes,
                                              frozenset(), call_location, bound=bound)
            for dependency, callers in self.engine.dependents.items():
                if dependency[1] == self.rule and callee in callers:
                    callers.add(self.scope)

        for index, (names, rest, default, pattern) in enumerate(callee.params):
            incoming = _join(*(fact for fact, _ in actual[index:])) if rest else (actual[index][0] if index < len(actual) else frozenset())
            missing = index >= len(actual) or actual[index][1]
            input_kind = input_kinds.get(index)
            if missing and index not in maybe_missing:
                input_kind = 'undefined'
            entry_checked = False
            if uncertain is not None and index >= uncertain:
                incoming = _join(incoming, *(fact for fact, _ in actual[uncertain:]))
                missing = True
                input_kind = None
            destructured = self.engine.text[slice(*pattern)].lstrip().startswith(('{', '['))
            if rest or destructured or (default is not None and missing):
                if default_flow is None:
                    default_flow = _Flow(self.engine, callee, self.rule)
                    default_flow.parameter_context = True
                    default_state = _State(budget=self.engine.budget)
                    # Unassigned caller formals live only in the visible-name
                    # map. Snapshot their current lexical values for nested
                    # defaults, including clean values and borrowed objects.
                    # Earlier callee formals below still shadow these cells.
                    available = state.cells.keys() | state.owners.values()
                    default_state.cells = {key: _cell_value(key, state) for key in available}
                    default_state.heap = {ref: dict(slots) for ref, slots in state.heap.items()}
                    default_state.weak_refs = set(state.weak_refs)
                    default_state.array_lengths = dict(state.array_lengths)
                    default_state.binding_kinds = dict(state.binding_kinds)
                default_state.update(bound)
                for name in bound:
                    default_state.owners[name] = self.engine.binding(callee, name)
                    default_state.binding_kinds[default_state.owners[name]] = bound.kinds.get(name)
            if rest:
                # A rest formal receives a fresh array, including when its
                # binding is itself an array/object pattern. Joining actuals
                # loses positional fields and mistakes element objects for
                # this wrapper; writes must still reach borrowed elements.
                ref = (callee, pattern[0], 'arguments-rest')
                precise_end = len(actual) if uncertain is None else uncertain
                slots = {str(position - index): actual[position][0]
                         for position in range(index, precise_end)}
                if uncertain is not None:
                    slots[None] = _join(*(fact for fact, _ in actual[uncertain:]))
                previous = default_state.heap.get(ref)
                if previous is not None:
                    slots = {key: _join(previous.get(key, frozenset()), slots.get(key, frozenset()))
                             for key in previous.keys() | slots.keys()}
                    default_state.weak_refs.add(ref)
                default_state.heap[ref] = slots
                default_state.array_lengths[ref] = (max(0, len(actual) - index)
                    if uncertain is None and previous is None else None)
                incoming = _Fact(refs=(ref,))
                missing, input_kind = False, 'present'
            if default is not None and missing and not rest:
                default_flow.pairs.update(_pairs(callee.code, *default))
                bypass = (default_state.copy() if index in maybe_missing or
                          (uncertain is not None and index >= uncertain) else None)
                if bypass is not None and destructured:
                    default_flow.binding_entry_failure(
                        incoming, bypass, self.engine.text[slice(*pattern)].lstrip().startswith('['),
                        input_kind=input_kind)
                    entry_checked = True
                default_fact, evaluated = default_flow.branch_value(*default, default_state)
                if evaluated is None and bypass is None:
                    complete_defaults(normal=False)
                    raise _NoNormalCompletion
                default_kind = (default_flow.binding_input(*default, evaluated)
                                if evaluated is not None else None)
                if default_kind == 'undefined':
                    default_fact = frozenset()
                if entry_checked and evaluated is not None:
                    default_flow.binding_entry_failure(
                        default_fact, evaluated, self.engine.text[slice(*pattern)].lstrip().startswith('['),
                        input_kind=default_kind)
                if bypass is not None:
                    # An unknown spread or scalar slot may supply this formal.
                    # Its default cannot prove that cleanup occurred.
                    default_state = _join_states(bypass, evaluated)
                    input_kind = None
                else:
                    input_kind = default_kind
                missing = input_kind == 'undefined'
                incoming = _join(incoming, default_fact)
            if destructured:
                default_flow.pairs.update(_pairs(callee.code, *pattern))
                try:
                    default_flow.bind_pattern(*pattern, incoming, default_state, callee.body_start,
                                              missing and index not in maybe_missing and uncertain is None,
                                              input_kind=input_kind, entry_checked=entry_checked)
                except _NoNormalCompletion:
                    complete_defaults(normal=False)
                    raise
                for name in names:
                    bound[name] = default_state.get(name, frozenset())
                    bound.kinds[name] = default_state.binding_kinds.get(self.engine.binding(callee, name))
            else:
                for name in names:
                    bound[name] = incoming
                    bound.kinds[name] = (input_kind or
                        ('present' if _refs(incoming) and not frozenset(incoming) else None))
            if default_state is not None:
                # A later initializer can assign an earlier formal. Keep the
                # updated parameter environment for both subsequent defaults
                # and the callee body instead of restoring the old bound map.
                for name in bound:
                    if name in default_state:
                        bound[name] = default_state[name]
                        bound.kinds[name] = default_state.binding_kinds.get(self.engine.binding(callee, name))
        complete_defaults()
        return bound

    def substitute(self, fact, callee, bound, state):
        # Default initializers run against the caller's heap. Their returned,
        # thrown and captured-write values can carry real object identities,
        # unlike the already-materialized ordinary scalar summaries.
        result = _Fact(refs=_refs(fact))
        for trace in fact:
            if trace.origin[0] == 'capture':
                incoming = _cell_value(trace.origin[1], state)
                result = _join(result, _step(incoming, self.engine.call_label(callee)))
                continue
            kind, owner, name = trace.origin if trace.origin[0] != 'source' else ('source', None, None)
            if kind == 'parameter' and owner is callee:
                incoming = bound.get(name, frozenset())
            else:
                incoming = frozenset({trace})
            if incoming:
                incoming = _step(incoming, self.engine.call_label(callee))
                if kind == 'parameter':
                    for name in trace.path[1:]:
                        incoming = _step(incoming, name)
            result = _join(result, incoming)
        return result

    def value(self, start, end, state):
        self.engine.budget.spend()
        text, code = self.engine.text, self.scope.code
        while start < end and code[start].isspace():
            start += 1
        while end > start and code[end - 1].isspace():
            end -= 1
        if start >= end:
            return frozenset()
        if code[start] == '(' and self.pairs.get(start) == end - 1:
            return self.value(start + 1, end - 1, state)
        if code[start] in '[{' and start in self.pairs:
            closing = self.pairs[start]
            assignment = re.match(r'\s*=(?!=|>)\s*', code[closing + 1:end])
            if assignment is not None:
                rhs = closing + 1 + assignment.end()
                fact = self.value(rhs, end, state)
                self.bind_pattern(start, closing + 1, fact, state, start,
                                  input_kind=self.binding_input(rhs, end, state))
                return fact
            if closing == end - 1:
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
            old = (self.property(receiver, key, state) if receiver is not None
                   else self.reference(target, state)) if assignment.group(1) != '=' else frozenset()
            logical = assignment.group(1) in {'||=', '&&=', '??='}
            if logical:
                # The receiver and computed key are evaluated once, before
                # the split. A RHS write, call or throw belongs only to the
                # taken branch; the bypass store must remain reachable.
                fact, evaluated = self.branch_value(rhs, end, state.copy())
                if evaluated is None:
                    return old
            else:
                old = _materialize(old, state.heap, budget=self.engine.budget)
                evaluated = state
                fact = self.value(rhs, end, evaluated)
            if assignment.group(1) == '+=':
                fact = _join(old, fact)
            if receiver is not None and _refs(receiver):
                self.write_property(receiver, key, _step(fact, target), evaluated)
            else:
                self.assign(target, fact, evaluated, start, self.callable(rhs, end, evaluated),
                            self.binding_input(rhs, end, evaluated) if assignment.group(1) == '=' else None)
            for location, expr_start, rule, label in self.engine.write_sinks:
                if (rule == self.rule and start <= location < expr_start <= rhs
                        and not code[expr_start:rhs].strip()):
                    self.effect(location, label, fact, evaluated)
            if logical:
                self.replace_state(state, _join_states(state, evaluated))
                return _join(old, fact)
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
            left_fact, left = self.branch_value(question + 1, colon, left)
            right_fact, right = self.branch_value(colon + 1, end, right)
            merged = _join_states(left, right)
            if merged is None:
                raise _NoNormalCompletion
            self.replace_state(state, merged)
            return _join(left_fact, right_fact)
        if operators:
            _, operator = min(operators, key=lambda item: (item[0], -item[1]))
            left = self.value(start, operator, state)
            branch = state.copy()
            right, branch = self.branch_value(operator + 2, end, branch)
            merged = _join_states(state, branch)
            self.replace_state(state, merged)
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
        call_code, call_offset = ((code.masked, code.offset) if isinstance(code, _ComponentCode)
                                  else (code, 0))
        cursor = start
        while cursor < end:
            match = call_pattern.search(call_code, cursor - call_offset, end - call_offset)
            if match is None:
                break
            match_start, match_end = match.start() + call_offset, match.end() + call_offset
            opening = match_end - 1
            closing = self.pairs.get(opening)
            if closing is None or closing >= end:
                cursor = match_end
                continue
            if cursor < match_start:
                facts.append(self.operand_snapshot(cursor, match_start, state))
                remainder[cursor - start:match_start - start] = [' '] * (match_start - cursor)
                source_remainder[cursor - start:match_start - start] = [' '] * (match_start - cursor)
            arguments = [(left, right) for left, right in _chunks(code, opening + 1, closing)
                         if code[left:right].strip()]
            # GetValue(callee) precedes ArgumentListEvaluation. An argument can
            # rebind a function or sanitizer for *later* calls, not this one.
            callee_name = re.sub(r'\s+', '', match.group(1))
            callee = self.engine.call_target(self.scope, callee_name, state, self.rule)
            receiver = callee_name.split('.')[0]
            binding = state.bindings.get(receiver, 'imported')
            sink_binding = state.bindings.get(callee_name, 'imported')
            if self.engine.relative_import(self.scope, receiver):
                binding = None
            if isinstance(callee, _Scope) and not callee.generator:
                argument_facts, prepared = self.evaluate_arguments(arguments, state)
            else:
                argument_facts = [self.value(left, right, state) for left, right in arguments]
            if isinstance(callee, _Scope) and callee.generator:
                # A generator call creates an iterator; it does not execute
                # the body. Iterator advancement is outside this call model.
                callee = None
            if isinstance(callee, _Scope):
                self.engine.import_captures(callee, state, self.rule)
                if (callee in self.engine.input_kind_scopes and self.scope.parent is not None
                        and self.scope not in self.engine.input_kind_scopes):
                    # Namespace imports and runtime aliases can resolve only
                    # after module/call summaries are available. Propagate
                    # this finite requirement to their scalar wrappers too.
                    self.engine.input_kind_scopes.add(self.scope)
                    self.engine.heap_scopes.add(self.scope)
                    for caller in self.engine.dependents[(self.scope, self.rule)]:
                        self.engine.enqueue(caller)
                deferred = callee.asynchronous and not re.search(r'\bawait\s*$', code[start:match_start])
                sole_local_call = (code[start:match_start].strip() in {'', 'await'} and closing + 1 == end)
                self.engine.dependents[(callee, self.rule)].add(self.scope)
                throw_count = len(self.throws)
                try:
                    bound = self.bind(callee, prepared, state, match_start)
                except _NoNormalCompletion:
                    if not deferred:
                        raise
                    # An async parameter initializer rejects the promise; it
                    # does not synchronously throw at the call expression.
                    rejected = self.throws[throw_count:]
                    self.throws[throw_count:] = []
                    merged = _join_states(*(store for _, store in rejected))
                    if merged is not None:
                        self.replace_state(state, merged)
                    call_fact = _join(*(fact for fact, _ in rejected))
                    facts.append(call_fact)
                    remainder[match_start - start:closing + 1 - start] = [' '] * (closing + 1 - match_start)
                    source_remainder[match_start - start:closing + 1 - start] = [' '] * (closing + 1 - match_start)
                    cursor = closing + 1
                    continue
                if deferred:
                    self.throws[throw_count:] = []
                incoming = state.copy()
                if self.engine.heap_required(callee, bound, incoming):
                    call_fact, effects, normal, thrown, exceptional = self.engine.heap_call(
                        callee, self.rule, match_start, bound, state)
                    for (location, label), fact in effects.items():
                        self.effect(location, label, fact)
                    if exceptional is not None:
                        if deferred:
                            self.replace_state(state, _join_states(state if normal else None, exceptional))
                            call_fact = _join(call_fact, thrown)
                        else:
                            self.throws.append((thrown, exceptional))
                    if not normal and not deferred:
                        raise _NoNormalCompletion
                else:
                    # A scalar summary can be consumed inside a heap context.
                    # Revisit that context if the summary changes later, not
                    # just the independently analyzed lexical caller.
                    if self.engine.current_task is not None:
                        self.engine.dependents[(callee, self.rule)].add(self.engine.current_task)
                    returned, effects, writes, normal, thrown, throw_writes = self.engine.summaries.get(
                        (callee, self.rule), (frozenset(), {}, {}, False, None, {}))
                    call_fact = self.substitute(returned, callee, bound, incoming)
                    for (location, label), fact in effects.items():
                        self.effect(location, label, self.substitute(fact, callee, bound, incoming), incoming)
                    if thrown is not None:
                        exceptional = incoming.copy()
                        self.apply_writes(throw_writes, callee, bound, exceptional, incoming)
                        if deferred:
                            self.apply_writes(writes, callee, bound, state, incoming)
                            self.replace_state(state, _join_states(state if normal else None, exceptional))
                            call_fact = _join(call_fact, self.substitute(thrown, callee, bound, incoming))
                        else:
                            self.throws.append((self.substitute(thrown, callee, bound, incoming), exceptional))
                    if not normal and not deferred:
                        raise _NoNormalCompletion
                    if not (deferred and thrown is not None):
                        self.apply_writes(writes, callee, bound, state, incoming)
            else:
                mutation = self.mutation_call(callee_name, arguments, argument_facts, state)
                call_fact = _join(*argument_facts)
                if '.' in callee_name:
                    call_fact = _join(call_fact, self.reference(receiver, state))
                # Argument facts already retain precise local-call returns.
                # Only a source in the callee itself introduces new input.
                candidate = text[match_start:closing + 1]
                for pattern, _ in SOURCE_PATTERNS:
                    source_match = pattern.search(candidate)
                    if source_match and source_match.start() <= opening - match_start:
                        source = source_match.group(0)
                        call_fact = _join(call_fact, frozenset({_Trace(('source', source), (source,))}))
                sink = self.engine.call_sinks.get(match_start)
                if sink and sink[0] == self.rule and sink_binding == 'imported':
                    selected = argument_facts[:1] if self.rule == 'js.taint.sql' else argument_facts
                    self.effect(match_start, sink[1], _join(*selected), state)
                regex = SANITIZERS_BY_RULE.get(self.rule)
                following = code[closing + 1:end].lstrip()
                if regex and regex.match(candidate) and not following.startswith(('.', '[')):
                    previous = code[:match_start].rstrip()
                    if not previous.endswith('.') and binding == 'imported':
                        call_fact = frozenset()
                if binding == 'imported' and NUMERIC_CONVERSIONS.fullmatch(callee_name):
                    before = match_start - 1
                    while before >= 0 and code[before].isspace():
                        before -= 1
                    if before < 0 or code[before] != '.':
                        call_fact = frozenset()
                if sink and sink[0] == 'js.taint.sql' and sink_binding == 'imported':
                    # Rows returned by a query come from the database. The
                    # arguments are checked at the SQL sink itself; they do
                    # not make the result request input (bound parameters
                    # are data, not the rows the query returns).
                    call_fact = frozenset()
                # Unknown calls may transform or serialize their arguments;
                # their return is not proof of object identity.
                call_fact = _materialize(call_fact, state.heap, budget=self.engine.budget)
                if mutation is not None:
                    call_fact = mutation
                    sole_local_call = (code[start:match_start].strip() in {'', 'await'} and closing + 1 == end)
                # Unknown code may throw. Record the invocation-time store,
                # not every unrelated statement prefix in a try block.
                self.throws.append((_materialize(_join(*argument_facts), state.heap,
                                                 budget=self.engine.budget), state.copy()))
            selectors, call_end = self.selectors(closing + 1, end, stop_at_call=True)
            for key, computed in selectors:
                selected = self.value(*computed, state) if computed is not None else frozenset()
                unknown = not _refs(call_fact) or bool(frozenset(call_fact))
                call_fact = self.property(call_fact, key, state)
                if unknown:
                    call_fact = _join(call_fact, selected)
            sole_local_call = code[start:match_start].strip() in {'', 'await'} and call_end == end
            facts.append(call_fact)
            remainder[match_start - start:call_end - start] = [' '] * (call_end - match_start)
            source_remainder[match_start - start:call_end - start] = [' '] * (call_end - match_start)
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
        return result if sole_local_call else _materialize(result, state.heap, budget=self.engine.budget)

    def expression(self, start, end, state):
        text = self.engine.text
        raw = text[start:end].strip()
        offset = start + len(text[start:end]) - len(text[start:end].lstrip())
        entries = _declaration_entries(text, self.scope.code, start, end)
        if entries:
            for kind, names, left, rhs, finish in entries:
                fact = self.value(rhs, finish, state) if rhs is not None else frozenset()
                binding = self.callable(rhs, finish, state) if rhs is not None else None
                if rhs is not None and binding is None:
                    required = re.match(r"\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", text[rhs:finish])
                    if required and not required.group(1).startswith(('./', '../', '/')):
                        binding = 'imported'
                pattern_end = rhs - 1 if rhs is not None else finish
                if text[left:pattern_end].lstrip().startswith(('{', '[')):
                    self.bind_pattern(left, pattern_end, fact, state, start, binding=binding,
                                      input_kind=self.binding_input(rhs, finish, state) if rhs is not None else 'undefined')
                else:
                    for name in names:
                        if (kind == 'var' and rhs is None and
                                self.engine.binding(self.scope, name, start) in state.binding_kinds):
                            # Hoisting already initialized this cell. A later
                            # bare var declaration does not replace a formal
                            # or an earlier assignment with undefined.
                            continue
                        self.assign(name, fact, state, start, binding,
                                    self.binding_input(rhs, finish, state) if rhs is not None else 'undefined')
            return state
        compound = re.match(r'([A-Za-z_$][\w$]*)\s*(\+=|\|\|=|&&=|\?\?=)\s*(.+)', raw, re.S)
        if compound:
            if compound.group(2) in {'||=', '&&=', '??='}:
                self.value(offset, end, state)
                return state
            name = compound.group(1)
            old = _materialize(self.reference(name, state), state.heap, budget=self.engine.budget)
            fact = self.value(offset + compound.start(3), end, state)
            self.assign(name, _join(old, fact), state, start)
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
            if binding is None:
                required = re.match(r"\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", text[rhs:end])
                if required and not required.group(1).startswith(('./', '../', '/')):
                    binding = 'imported'
            for name in parse_targets(target):
                self.assign(name, fact, state, start, binding, self.binding_input(rhs, end, state))
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
        self.engine.budget.spend()
        try:
            return self.transfer(node, state)
        except _NoNormalCompletion:
            return None

    def transfer(self, node, state):
        if node.kind == 'commonjs_import':
            for name in node.extra:
                key = self.engine.import_path(self.scope, [name])
                fact, binding = frozenset(), None
                if key is not None:
                    fact = self.engine.import_value(key, state, self.rule) or frozenset()
                    source = self.engine.final_states.get((key[0], self.rule))
                    if source is not None and key not in state.written_cells:
                        binding = source.bindings.get(key[2])
                # require/destructuring takes a value snapshot at this point.
                # Its local cell is not the exporting module's mutable slot.
                state.owners[name] = self.engine.lexical_binding(self.scope, name, node.start)
                self.assign(name, fact, state, node.start, binding)
            return state
        if node.kind == 'commonjs_export':
            kind, members = node.extra
            value = self.value(node.start, node.end, state)
            if kind == 'object':
                namespace = value
            elif kind == 'namespace':
                namespace = state.get('@namespace')
                if namespace is None:
                    ref = (self.scope, self.scope.body_start, 'commonjs')
                    state.heap[ref] = {}
                    namespace = _Fact(refs=(ref,))
            else:
                namespace = None
            for name, key, begin, end in members:
                fact = self.property(value, name, state) if kind == 'object' else value
                # Field extraction must not retain the container reference:
                # its unrelated fields must not taint a clean named export.
                if kind == 'object':
                    fact = _join(*(state.heap[ref].get(name, frozenset()) for ref in _refs(value)))
                self.assign(key, fact, state, begin, self.callable(begin, end, state))
                if kind == 'namespace':
                    self.write_property(namespace, name, fact, state, initialize_export=True)
            if namespace is not None:
                for ref in _refs(namespace):
                    self.engine.commonjs_namespace_refs[ref] = self.scope
                self.assign('@namespace', namespace, state, node.start)
            return state
        if node.kind == 'module_default':
            value = self.value(node.start, node.end, state)
            self.assign('@default', value, state, node.start,
                        self.callable(node.start, node.end, state))
            return state
        if node.kind == 'block':
            local = self.engine.declarations(node.body, block=True)
            outer = state.copy()
            break_count, continue_count = len(self.breaks), len(self.continues)
            return_count, throw_count = len(self.returns), len(self.throws)
            for name in local:
                state[name], state.bindings[name] = frozenset(), None
                state.owners[name] = self.engine.binding(self.scope, name, node.start + 1)
                state.binding_kinds[state.owners[name]] = 'undefined'
            result = self.block(node.body, state)
            for exit_state in (*self.breaks[break_count:], *self.continues[continue_count:]):
                self.restore(exit_state, outer, local)
            for _, exit_state in (*self.returns[return_count:], *self.throws[throw_count:]):
                self.restore(exit_state, outer, local)
            return self.restore(result, outer, local)
        if node.kind == 'if':
            self.value(node.start, node.end, state)
            condition = self.scope.code[node.start:node.end].strip()
            left = self.block(node.body, state.copy()) if condition != 'false' else None
            right = self.block(node.alternate, state.copy()) if condition != 'true' else None
            return _join_states(left, right)
        if node.kind == 'try':
            return_count, throw_count = len(self.returns), len(self.throws)
            break_count, continue_count = len(self.breaks), len(self.continues)
            current = self.block(node.body, state.copy())
            handler = None
            if node.alternate and self.throws[throw_count:]:
                thrown = self.throws[throw_count:]
                self.throws[throw_count:] = []
                caught = _join_states(*(exit_state for _, exit_state in thrown))
                outer = caught.copy()
                value = _join(*(fact for fact, _ in thrown))
                handler_return, handler_throw = len(self.returns), len(self.throws)
                handler_break, handler_continue = len(self.breaks), len(self.continues)
                try:
                    if node.catch_range is not None:
                        self.bind_pattern(*node.catch_range, value, caught, node.alternate[0].start + 1)
                    handler = self.block(node.alternate, caught)
                except _NoNormalCompletion:
                    # Binding initializers are part of handler completion;
                    # their throws still run this try statement's finalizer.
                    handler = None
                self.restore(handler, outer, node.catch_names)
                for _, exit_state in (*self.returns[handler_return:], *self.throws[handler_throw:]):
                    self.restore(exit_state, outer, node.catch_names)
                for exit_state in (*self.breaks[handler_break:], *self.continues[handler_continue:]):
                    self.restore(exit_state, outer, node.catch_names)
            merged = _join_states(current, handler)
            if node.extra:
                # A normal finalizer preserves the pending completion/value;
                # an abrupt finalizer replaces it. Never union a cancelled
                # return into the function result or a throw into normal writes.
                returns, throws = self.returns[return_count:], self.throws[throw_count:]
                breaks, continues = self.breaks[break_count:], self.continues[continue_count:]
                self.returns[return_count:] = []
                self.throws[throw_count:] = []
                self.breaks[break_count:] = []
                self.continues[continue_count:] = []
                for destination, pending in ((self.returns, returns), (self.throws, throws)):
                    for value, exit_state in pending:
                        tail = self.block(node.extra, exit_state.copy())
                        if tail is not None:
                            destination.append((value, tail))
                for destination, pending in ((self.breaks, breaks), (self.continues, continues)):
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
            mandatory_iteration = False
            if node.kind == 'for' and len(header) == 1:
                iterator = re.match(r'\s*(?:(const|let|var)\s+)?(.+?)\s+(of|in)\s+(.+)',
                                    self.engine.text[node.start:node.end], re.S)
                if iterator:
                    iteration = (_binding_names(iterator.group(2)), node.start + iterator.start(4), node.end)
                    # A plain non-empty array literal makes for...of execute at
                    # least once on every normal path. Do not retain a
                    # zero-iteration state that can erase a closure assigned
                    # in that guaranteed first iteration. Spread-only arrays
                    # remain unknown because the spread can be empty.
                    iterable = self.scope.code[iteration[1]:iteration[2]].strip()
                    mandatory_iteration = (
                        iterator.group(3) == 'of'
                        and iterable.startswith('[') and iterable.endswith(']')
                        and bool(iterable[1:-1].strip())
                        and not iterable[1:-1].lstrip().startswith('...')
                    )
                    if iterator.group(1) in {'const', 'let'}:
                        loop_names.update(iteration[0])
            if node.kind == 'for' and len(header) == 3:
                loop_names.update(name for kind, names, _, _, _ in _declaration_entries(
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
            if node.kind == 'do' or mandatory_iteration:
                self.breaks, self.continues = [], []
                if mandatory_iteration:
                    names, left, right = iteration
                    fact = self.value(left, right, current)
                    for name in names:
                        if name in loop_names:
                            current.owners[name] = self.engine.binding(self.scope, name, node.start)
                        self.assign(name, fact, current, node.start)
                current = self.block(node.body, current)
                exits.extend(self.breaks)
                current = _join_states(current, *self.continues)
                if current is None:
                    self.breaks, self.continues = outer_breaks, outer_continues
                    return self.restore(_join_states(*exits), outer, loop_names)
                # Both do...while and a definitely non-empty for...of have
                # already executed their mandatory first body. Subsequent
                # fixed-point iterations start from that post-body state.
                entry = current.copy()
            if self.scope.code[condition[0]:condition[1]].strip() == 'false':
                self.breaks, self.continues = outer_breaks, outer_continues
                return self.restore(_join_states(current, *exits), outer, loop_names)
            condition_exit = current
            while True:
                self.breaks, self.continues = [], []
                # The loop-head approximant and the post-condition store are
                # different program points. Evaluating a condition directly
                # into `current` lets a strong update (for example a helper
                # that cleans a captured value) fight the entry join forever:
                # the condition clears it, then the join restores it before
                # comparing against the cleared state. Keep the head monotone
                # and carry the condition's side effects only along paths that
                # actually evaluate it.
                condition_state = current.copy()
                try:
                    self.value(*condition, condition_state)
                except _NoNormalCompletion:
                    self.breaks, self.continues = outer_breaks, outer_continues
                    return self.restore(_join_states(*exits), outer, loop_names)
                body_state = condition_state.copy()
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
                    try:
                        after = self.expression(*update, after)
                    except _NoNormalCompletion:
                        after = None
                exits.extend(self.breaks)
                # A pending heap-call summary has no normal output yet.
                # Keep earlier iterations rather than resetting to entry and
                # alternating forever between populated and empty heaps.
                merged = _join_states(entry, current, after)
                if merged == current:
                    condition_exit = condition_state
                    break
                current = merged
            self.breaks, self.continues = outer_breaks, outer_continues
            return self.restore(_join_states(condition_exit, *exits), outer, loop_names)
        if node.kind == 'return':
            value = self.value(node.start, node.end, state)
            self.returns.append((value, state.copy()))
            return None
        if node.kind == 'throw':
            value = self.value(node.start, node.end, state)
            self.throws.append((value, state.copy()))
            return None
        if node.kind in {'break', 'continue'}:
            (self.breaks if node.kind == 'break' else self.continues).append(state.copy())
            return None
        return self.expression(node.start, node.end, state)


class _Engine:
    def __init__(self, text, code, graph=None, modules=()):
        self.graph = graph
        self.source_free = False
        self.module_roots = {}
        self.default_targets = {}
        self.commonjs_targets = {}
        self.commonjs_namespace_refs = {}
        self.commonjs_locals = set()
        self.source_root = Path(commonpath([str(module.path.parent) for module in modules])) if modules else None
        if modules:
            chunks, masks, offset = [], [], 0
            for module in modules:
                module.start, module.end = offset, offset + len(module.text)
                chunks.extend((module.text, '\n;\n'))
                masks.extend((module.code, '\n;\n'))
                offset = module.end + 3
            text, code = ''.join(chunks), ''.join(masks)
        self.text, self.code = text, code
        # Allocation-site contexts are finite but their heap shapes can grow
        # exponentially through a small chain of binary factories. Count the
        # actual copied/traversed facts as well as transfers. Larger selected
        # components receive proportional work; exhaustion is an explicit
        # incomplete analysis, never an empty successful finding stream.
        self.work_limit = max(500_000, 128 * len(code))
        sinks = []
        for left, right in ([(m.start, m.end) for m in modules] if modules else [(0, len(text))]):
            aliases, functions = child_process_bindings(text[left:right].splitlines())
            sinks.extend((a + left, b + left, rule, label, call)
                         for a, b, rule, label, call in
                         child_process_sinks(text[left:right], code[left:right], aliases, functions))
        for regex, rule, label, call in SINKS:
            sinks.extend((match.start(), match.end(), rule, label, call) for match in regex.finditer(code))
        self.call_sinks = {start: (rule, label) for start, _, rule, label, call in sinks if call}
        self.write_sinks = [(start, expr_start, rule, label) for start, expr_start, rule, label, call in sinks if not call]
        targets = [match.start() for match in BINDING_WRITE_TARGET.finditer(text)
                   if code[match.start()] == text[match.start()]]
        self.binding_write_sinks = False
        if targets:
            assignment_after = re.compile(r'\s*=(?!=|>)')
            for opening, closing in _pairs(code).items():
                if code[opening] not in '[{' or not assignment_after.match(code, closing + 1):
                    continue
                candidate = bisect_right(targets, opening)
                if candidate < len(targets) and targets[candidate] < closing:
                    self.binding_write_sinks = True
                    break
        if not sinks and not self.binding_write_sinks:
            # No rule can emit a finding without one of these exact sinks.
            # Avoid parsing scopes and constructing their capture graph for
            # sink-free components; every selected module was still inspected.
            self.scopes = []
            return
        if modules:
            self.functions, roots = [], []
            for module in modules:
                root, functions = _function_scopes(module.text, module.code)
                for scope in [root, *functions]:
                    scope.start += module.start
                    scope.end += module.start
                    scope.body_start += module.start
                    scope.body_end += module.start
                    scope.params = tuple((names, rest, None if default is None else
                                          (default[0] + module.start, default[1] + module.start),
                                          (pattern[0] + module.start, pattern[1] + module.start))
                                         for names, rest, default, pattern in scope.params)
                    scope.code = code if scope.code == module.code else _ComponentCode(
                        code, scope.code, module.start)
                module.root = root
                self.module_roots[root] = module
                roots.append(root)
                self.functions.extend(functions)
                if module.anonymous_default is not None:
                    begin = module.start + module.anonymous_default
                    candidates = [fn for fn in root.children if begin <= fn.start
                                  and re.fullmatch(r'\s*(?:async\s*)?\(*\s*', code[begin:fn.start])]
                    if candidates:
                        self.default_targets[root] = min(candidates, key=lambda fn: fn.start)
            self.root = roots[0]
            self.scopes = [*roots, *self.functions]
        else:
            self.root, self.functions = _function_scopes(text, code)
            self.scopes = [self.root, *self.functions]
        # Every concrete origin comes from a source pattern, bare route
        # params, or a destructured framework parameter. Check the entire
        # selected component, including source-only dependencies. Parameters
        # and captures alone cannot manufacture a concrete source origin.
        # Keep text matches conservative (even inert strings may retain work).
        self.source_free = (not any(pattern.search(text) for pattern, _ in SOURCE_PATTERNS)
                            and re.search(r'\bparams\b', code, re.IGNORECASE) is None
                            and not any(scope.parameter_sources for scope in self.functions))
        if self.source_free:
            return
        self.summaries, self.final_states = {}, {}
        self.dependents = defaultdict(set)
        self.heap_calls = {}
        self.widened_calls, self.exact_calls, self.recursive = {}, defaultdict(list), set()
        self.current_task = None
        self.pending, self.queued = deque(), set()
        self.binding_regions = {}
        for scope in self.scopes:
            scope.statements = _Parser(scope).sequence(scope.body_start, scope.body_end) if not scope.concise else []
            if scope.parent is not None:
                # Keep lexical identities, not every function's parsed body.
                # Evaluation reparses this immutable source span for its task.
                self.binding_regions[scope] = self.regions(scope)
                scope.statements = None
        for root, module in self.module_roots.items():
            for begin, end, names in module.commonjs_imports:
                root.statements.append(_Statement('commonjs_import', module.start + begin,
                                                 module.start + end, extra=names))
                self.commonjs_locals.update((root, name) for name in names)
            root.statements.sort(key=lambda node: node.start)
            if module.anonymous_default is not None:
                begin, end = module.start + module.anonymous_default, module.start + module.default_end
                root.statements = [node for node in root.statements if not begin <= node.start < end]
                root.statements.append(_Statement('module_default', begin, end))
                root.statements.sort(key=lambda node: node.start)
            for start, begin, end, members in module.commonjs_exports:
                start, begin, end = (position + module.start for position in (start, begin, end))
                root.statements = [node for node in root.statements if not start <= node.start < end]
                members = [(name, key, left + module.start, right + module.start)
                           for name, key, left, right in members]
                root.statements.append(_Statement('commonjs_export', begin, end,
                                                 extra=(module.commonjs, members)))
                root.statements.sort(key=lambda node: node.start)
                for _name, key, left, right in members:
                    literal = self.text[left:right].strip()
                    candidates = [fn for fn in root.children
                                  if (left <= fn.start and fn.end <= right)
                                  or (fn.name == literal and fn.declaration)]
                    if len(candidates) == 1:
                        self.commonjs_targets[root, key] = candidates[0]
        for scope in self.scopes:
            if scope.parent is None:
                self.binding_regions[scope] = self.regions(scope)
        for root, module in self.module_roots.items():
            self.binding_regions[root].extend((root.body_start, root.body_end, name) for name in module.imports)
        self.capture_keys = {}
        self.local_targets = {}
        for scope in self.functions:
            keys, targets = set(), set()
            ranges = [(scope.body_start, scope.body_end)]
            ranges.extend(default for _names, _rest, default, _pattern in scope.params if default is not None)
            ranges.extend(pattern for _names, _rest, _default, pattern in scope.params
                          if text[slice(*pattern)].lstrip().startswith(('{', '[')))
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
        self.heap_scopes = {
            scope for scope in self.functions
            if any(re.search(r'[\[{]', scope.code[left:right])
                   for left, right in [(scope.body_start, scope.body_end),
                                       *(default for _, _, default, _ in scope.params
                                         if default is not None),
                                       *(pattern for _, _, _, pattern in scope.params)])
        }
        # Shadowing identifies a lexical cell; it does not prove that the
        # cell contains a defined value. These functions need the same finite
        # caller contexts used for borrowed objects so a missing actual and a
        # clean string actual do not share one default-initializer decision.
        self.input_kind_scopes = {
            scope for scope in self.functions
            if any(name == 'undefined' for _left, _right, name in self.binding_regions[scope])
            or any(key[2] == 'undefined' and any(left == key[1] and name == key[2]
                   for left, _right, name in self.binding_regions[key[0]])
                   for key in self.capture_keys[scope])
        }
        self.heap_scopes.update(self.input_kind_scopes)
        # Factories hidden behind ordinary local wrappers still need an object
        # result, including allocations/throws in parameter initializers. The
        # capture graph already includes those calls and named arrow helpers.
        # This set only grows over the finite set of lexical functions.
        while True:
            added = {scope for scope in self.functions if scope not in self.heap_scopes
                     and self.local_targets[scope] & self.heap_scopes}
            kind_added = {scope for scope in self.functions if scope not in self.input_kind_scopes
                          and self.local_targets[scope] & self.input_kind_scopes}
            if not added and not kind_added:
                break
            self.heap_scopes.update(added)
            self.input_kind_scopes.update(kind_added)

    def selected_import(self, scope, name):
        key = self.lexical_binding(scope, name)
        module = self.module_roots.get(key[0])
        imported = module.imports.get(name) if module is not None else None
        return bool(imported and name not in module.uncertain_requires
                    and self.graph.resolve(module, imported[0]) is not None)

    def relative_import(self, scope, name):
        # A helper excluded from the selected scan is unknown, not a proof of
        # sanitization. This also covers missing and ambiguous dependencies.
        key = self.lexical_binding(scope, name)
        module = self.module_roots.get(key[0])
        entry = module.imports.get(name) if module is not None else None
        return bool(entry and entry[0].startswith(('./', '../')))

    def export_key(self, module, name):
        found = self.graph.exported(module, name)
        if found is None:
            return None
        target, local = found
        if target.root not in self.module_roots:
            return None
        return target.root, target.root.body_start, local

    def import_path(self, scope, names):
        owner = self.lexical_binding(scope, names[0])[0]
        module = self.module_roots.get(owner)
        entry = module.imports.get(names[0]) if module is not None else None
        if entry is None or names[0] in module.uncertain_requires:
            return None
        target = self.graph.resolve(module, entry[0])
        if target is None:
            return None
        found = ((target, '@namespace') if entry[1] == '*'
                 else self.graph.exported(target, entry[1]))
        for name in names[1:]:
            if found is None or found[1] != '@namespace':
                return None
            found = self.graph.exported(found[0], name)
        if found is None or found[0].root not in self.module_roots:
            return None
        return found[0].root, found[0].root.body_start, found[1]

    def call_label(self, callee):
        label = (callee.name or '<callback>') + '()'
        if len(self.module_roots) > 1:
            root = callee
            while root.parent is not None:
                root = root.parent
            module = self.module_roots[root]
            label = f'{module.path.relative_to(self.source_root).as_posix()}:{label}'
        return label

    def import_value(self, key, state, rule, *, captured_require=False):
        owner = key[0]
        task = self.current_task
        current_scope = task.scope if isinstance(task, _HeapCall) else task
        root = current_scope
        while root is not None and root.parent is not None:
            root = root.parent
        if owner not in self.module_roots or (owner is root and not captured_require):
            return None
        if task is not None:
            self.dependents[(owner, rule)].add(task)
        if key in state.cells:
            return state.cells[key]
        source = self.final_states.get((owner, rule))
        if source is None:
            return frozenset()
        fact = source.cells.get(key, source.get(key[2], frozenset()))
        state.cells[key] = fact
        state.binding_kinds[key] = source.binding_kinds.get(key)
        pending = list(_refs(fact))
        while pending:
            ref = pending.pop()
            if ref in state.heap:
                continue
            state.heap[ref] = dict(source.heap.get(ref, {}))
            namespace_owner = self.commonjs_namespace_refs.get(ref)
            if namespace_owner is not None:
                module = self.module_roots[namespace_owner]
                for name in module.exports:
                    exported = self.export_key(module, name)
                    if exported in source.written_cells:
                        state.written_cells.add(exported)
                        if exported in source.cells:
                            state.cells[exported] = source.cells[exported]
                            state.binding_kinds[exported] = source.binding_kinds.get(exported)
            for value in state.heap[ref].values():
                pending.extend(_refs(value) - state.heap.keys())
            if ref in source.array_lengths:
                state.array_lengths[ref] = source.array_lengths[ref]
        state.weak_refs.update(source.weak_refs & state.heap.keys())
        return fact

    def import_captures(self, callee, state, rule):
        for key in self.capture_keys[callee]:
            self.import_value(key, state, rule)

    def call_target(self, scope, name, state, rule):
        parts = name.split('.')
        local = self.lexical_binding(scope, parts[0])
        if (local[0], parts[0]) in self.commonjs_locals and parts[0] not in state.bindings:
            # An independently analyzed closure may read its defining module's
            # require snapshot. Concrete calls already provide current cells.
            self.import_value(local, state, rule, captured_require=scope is not local[0])
            if len(parts) == 1:
                if local in state.written_cells:
                    return None
                source = self.final_states.get((local[0], rule))
                return source.bindings.get(parts[0]) if source is not None else None
        if len(parts) == 2:
            receiver = state.get(parts[0], state.cells.get(local, frozenset()))
            refs = _refs(receiver)
            if refs and not frozenset(receiver):
                targets = []
                for ref in refs:
                    owner = self.commonjs_namespace_refs.get(ref)
                    if owner is None:
                        return None
                    key = self.export_key(self.module_roots[owner], parts[1])
                    if key is None or key in state.written_cells:
                        return None
                    source = self.final_states.get((owner, rule))
                    if self.current_task is not None:
                        self.dependents[(owner, rule)].add(self.current_task)
                    targets.append(source.bindings.get(key[2]) if source is not None else None)
                return targets[0] if all(target is targets[0] for target in targets) else None
        if parts[0] in state.bindings:
            return state.bindings[name] if len(parts) == 1 else None
        key = self.import_path(scope, parts)
        if key is not None:
            # A setter may have replaced the exported binding through another
            # import name or namespace. The exporter's initialization summary
            # is stale at this call site even if this spelling was never read.
            if key in state.written_cells:
                return None
            owner, _, local = key
            task = self.current_task
            if task is not None:
                self.dependents[(owner, rule)].add(task)
            source = self.final_states.get((owner, rule))
            return source.bindings.get(local) if source is not None else None
        if len(parts) == 1:
            return state.bindings.get(name) if name in state.bindings else self.lookup(scope, name)
        return None

    def enqueue(self, task):
        if task not in self.queued:
            self.queued.add(task)
            self.pending.append(task)

    def heap_required(self, callee, bound, state):
        # Scalar helpers use substitutable summaries even when their caller
        # allocates objects. Only objects the callee receives or captures need
        # a separate heap context; unrelated caller cells cannot affect it.
        return (callee in self.heap_scopes
                or any(_refs(fact) for fact in bound.values())
                # Unassigned formals live in the visible-name map. Use the
                # same lexical lookup as heap_input so a nested setter or
                # property reader cannot lose its captured object's identity
                # by taking a scalar summary before the first assignment.
                or any(_refs(_cell_value(key, state)) for key in self.capture_keys[callee]))

    def heap_input(self, callee, bound, incoming, recursive):
        state = _State(budget=self.budget)
        ancestors, parent = set(), callee.parent
        while parent is not None:
            ancestors.add(parent)
            parent = parent.parent
        # Formal parameters initially live in the visible-name map, before
        # any assignment creates a cell. Nested heap calls must capture their
        # current values too, including clean values that kill symbolic taint.
        available = incoming.cells.keys() | incoming.owners.values()
        state.cells = {key: _cell_value(key, incoming) for key in available
                       if key[0] in ancestors and key in self.capture_keys[callee]}
        state.binding_kinds = {key: incoming.binding_kinds.get(key) for key in state.cells}
        state.binding_kinds.update({self.binding(callee, name): kind
                                    for name, kind in getattr(bound, 'kinds', {}).items()})
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
            self.budget.spend(_heap_work({ref: incoming.heap.get(ref, {})}))
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

        Once a callee calls itself, a call to it from outside its recursion gets
        a widened summary of its own, keyed by that call site and its caller;
        recursive backedges share their ancestor's summary, while acyclic
        helper calls keep their caller and call site. Inputs only grow by
        joining, and a widened parent chain never repeats a callee, so call
        depth cannot create unbounded contexts. Distinct helper calls must
        not mix clean and tainted values even inside the same recursion. Each
        fresh object a recursive interpreter appends to a captured array
        otherwise comes back under a new subset of call sites, and almost every
        recursive call met a new heap.
        """
        task = self.current_task
        ancestors = task.ancestors if isinstance(task, _HeapCall) else frozenset((task,))
        incoming = self.heap_input(callee, bound, state, callee in ancestors)
        if getattr(task, 'widened', False):
            context = self.widened_call(callee, rule, task.root, location, bound, incoming,
                                        ancestors | {callee}, caller=task)
        elif callee in ancestors or (callee, rule) in self.recursive:
            if (callee, rule) not in self.recursive:
                # Its exact summaries so far were entries into a recursion:
                # their callers re-run and enter through a widened summary.
                self.recursive.add((callee, rule))
                for old in self.exact_calls.pop((callee, rule), []):
                    old.superseded = True
                    for reader in old.readers:
                        self.enqueue(reader)
            context = self.widened_call(callee, rule, (location, task), location, bound, incoming,
                                        ancestors | {callee})
        else:
            signature = (callee, rule, location, frozenset(bound.items()),
                         frozenset(incoming.cells.items()), frozenset(incoming.bindings.items()),
                         frozenset(incoming.binding_kinds.items()),
                         frozenset((ref, frozenset(slots.items())) for ref, slots in incoming.heap.items()),
                         frozenset(incoming.weak_refs), frozenset(incoming.array_lengths.items()))
            context = self.heap_calls.get(signature)
            if context is None:
                context = _HeapCall(callee, rule, location, dict(bound), incoming,
                                    ancestors | {callee})
                self.heap_calls[signature] = context
                self.exact_calls[(callee, rule)].append(context)
                self.enqueue(context)
        # Borrowed means borrowed by this caller: a joined widened input also
        # holds the callee's own allocations from its recursive calls.
        context.readers.add(task)
        if context.result is None:
            return frozenset(), {}, False, frozenset(), None
        returned, effects, writes, output, thrown, throw_writes, exceptional = context.result
        # Allocation identities must preserve the same distinctions as inputs;
        # sharing the outer root here would merge separate helper results again.
        widened = context if context.widened else None
        label = self.call_label(callee)
        thrown_value, thrown_state = frozenset(), None
        if exceptional is not None:
            thrown_state = state.copy()
            thrown_value = self.apply_heap_output(incoming, thrown_state, exceptional, throw_writes, thrown, location,
                                                  widened=widened)
        result = frozenset()
        if output is not None:
            result = self.apply_heap_output(incoming, state, output, writes, returned, location,
                                            widened=widened)
        return (_step(result, label), {key: _step(fact, label) for key, fact in effects.items()},
                output is not None, _step(thrown_value, label), thrown_state)

    def widened_call(self, callee, rule, root, location, bound, incoming, ancestors, *, caller=None):
        """Join backedges into an ancestor; keep acyclic helper contexts separate.

        The parent chain contains each callee at most once. Recursion through
        any number of call sites therefore closes a finite cycle rather than
        extending the context. Sibling helpers, including shared inner sites
        reached through different wrappers, retain distinct inputs and objects.
        """
        context = caller
        while context is not None:
            self.budget.spend()
            if context.scope is callee and context.rule == rule:
                break
            context = context.widened_parent
        if context is None:
            key = (callee, rule, root) if caller is None else (callee, rule, root, caller, location)
            context = self.widened_calls.get(key)
            if context is None:
                incoming.array_lengths = dict.fromkeys(incoming.array_lengths)
                context = _HeapCall(callee, rule, location, dict(bound), incoming, ancestors,
                                    widened=True, root=root, widened_parent=caller)
                self.widened_calls[key] = context
                self.enqueue(context)
                return context
        joined_bound = {name: _join(context.bound.get(name, frozenset()), bound.get(name, frozenset()))
                        for name in context.bound.keys() | bound.keys()}
        joined = _join_states(context.incoming, incoming)
        # Lengths that differ become unknown anyway; unknown from the start
        # saves the re-solves of a length counting up through the fixed point.
        joined.array_lengths = dict.fromkeys(joined.array_lengths)
        # Include heap/cell-only growth, not just changes to visible names.
        if (joined_bound != context.bound or not joined == context.incoming
                or not ancestors <= context.ancestors):
            context.bound, context.incoming = joined_bound, joined
            context.ancestors = context.ancestors | ancestors
            self.enqueue(context)
        return context

    def apply_heap_output(self, incoming, state, output, writes, returned, location, *, widened=None, bound=None):
        self.budget.spend(1 + _heap_work(output.heap))

        def fresh(ref):
            if _collapsed(ref):
                return ref
            # Tagged sites (binding-rest and CommonJS namespaces) have a string
            # discriminator. Only a trailing frozenset is a call history; keep
            # the entire allocation site rather than dropping its discriminator.
            has_history = len(ref) > 2 and isinstance(ref[-1], frozenset)
            site = ref[:-1] if has_history else ref
            history = ref[-1] if has_history else frozenset()
            if widened is not None:
                # Every object a widened summary returns from this allocation
                # site is one weak object per summary: writes join, reads see
                # all iterations, and unrelated helper calls keep their own.
                return (*site, frozenset({(WIDENED, widened)}))
            return (*site, history | {location})

        renamed = {ref: ref if ref in incoming.heap else fresh(ref) for ref in output.heap}

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
            collapsed = len(originals) > 1 or collision or _collapsed(new)
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
            state.binding_kinds[key] = output.binding_kinds.get(key)
            state.written_cells.add(key)
            name = key[2]
            if name not in state or state.owners.get(name) == key:
                state[name], state.owners[name], state.bindings[name] = value, key, None
        if bound is not None:
            for name, fact in bound.items():
                bound[name] = translate(fact)
        return translate(returned)

    def analyze_heap(self, context):
        scope, rule = context.scope, context.rule
        statements = self.scope_statements(scope)
        state = context.incoming.copy()
        for name in self.declarations(statements):
            state[name], state.bindings[name] = frozenset(), None
            state.owners[name] = self.binding(scope, name)
            state.binding_kinds[state.owners[name]] = 'undefined'
        for names, _, _, _ in scope.params:
            for name in names:
                state[name] = context.bound.get(name, frozenset())
                state.bindings[name], state.owners[name] = None, self.binding(scope, name)
                state.binding_kinds[state.owners[name]] = context.incoming.binding_kinds.get(state.owners[name])
        for child in scope.children:
            if child.name and child.declaration:
                state.bindings[child.name] = child
                state.owners[child.name] = self.binding(scope, child.name, child.start)
                state.binding_kinds[state.owners[child.name]] = 'present'
        flow = _Flow(self, scope, rule)
        if scope.concise:
            value, final = flow.branch_value(scope.body_start, scope.body_end, state)
            if final is not None:
                flow.returns.append((value, final.copy()))
            final = None
        else:
            final = flow.block(statements, state)
        exits = [*(exit_state for _, exit_state in flow.returns), *([final] if final is not None else [])]
        output = _join_states(*exits)
        exceptional = _join_states(*(exit_state for _, exit_state in flow.throws))
        def writes(store):
            return {} if store is None else {key: value for key, value in store.cells.items()
                                            if key[0] is not scope and key in store.written_cells}
        returned = _join(*(value for value, _ in flow.returns))
        thrown = _join(*(value for value, _ in flow.throws))
        normal_writes, throw_writes = writes(output), writes(exceptional)

        def escaped_heap(store, value, changes):
            if store is None:
                return None
            # Borrowed objects remain observable through caller aliases even
            # after a formal is rebound. Local allocations only escape through
            # a returned value, an exception, or a write to a captured cell.
            pending = [*context.incoming.heap, *_refs(value)]
            for fact in changes.values():
                pending.extend(_refs(fact))
            heap = {}
            while pending:
                ref = pending.pop()
                if ref in heap or ref not in store.heap:
                    continue
                slots = heap[ref] = store.heap[ref]
                self.budget.spend(_heap_work({ref: slots}))
                for fact in slots.values():
                    pending.extend(_refs(fact) - heap.keys())
            return _HeapOutput(heap, store.weak_refs & heap.keys(),
                               {ref: length for ref, length in store.array_lengths.items() if ref in heap},
                               {key: store.binding_kinds.get(key) for key in changes})

        return (returned, flow.effects, normal_writes, escaped_heap(output, returned, normal_writes),
                thrown, throw_writes, escaped_heap(exceptional, thrown, throw_writes))

    def regions(self, scope):
        """Static lexical identities; dataflow state still supplies values."""
        regions = [(scope.body_start, scope.body_end, name)
                   for names, _, _, _ in scope.params for name in names]
        blocks = [(scope.body_start, scope.body_end)]
        pending = [(scope.statements, scope.body_start, scope.body_end)]
        while pending:
            statements, left, right = pending.pop()
            for node in statements:
                if node.kind == 'expression':
                    for kind, names, _, _, _ in _declaration_entries(self.text, scope.code, node.start, node.end):
                        begin, finish = (scope.body_start, scope.body_end) if kind == 'var' else (left, right)
                        regions.extend((begin, finish, name) for name in names)
                if node.kind == 'block':
                    blocks.append((node.start + 1, node.end - 1))
                    pending.append((node.body, node.start + 1, node.end - 1))
                else:
                    if node.kind == 'for':
                        finish = max((child.end for child in node.body), default=node.end)
                        header = next(_chunks(scope.code, node.start, node.end, ';'))
                        for kind, names, _, _, _ in _declaration_entries(self.text, scope.code, *header):
                            begin, stop = (scope.body_start, scope.body_end) if kind == 'var' else (node.start, finish)
                            regions.extend((begin, stop, name) for name in names)
                        iterator = re.match(r'\s*(let|const|var)\s+(.+?)\s+(?:of|in)\b', self.text[node.start:node.end])
                        if iterator:
                            begin, stop = (scope.body_start, scope.body_end) if iterator.group(1) == 'var' else (node.start, finish)
                            regions.extend((begin, stop, name) for name in _binding_names(iterator.group(2)))
                    pending.append((node.body, left, right))
                pending.append((node.alternate, left, right))
                if node.kind == 'try':
                    if node.alternate:
                        handler = node.alternate[0]
                        regions.extend((handler.start + 1, handler.end - 1, name) for name in node.catch_names)
                    if node.extra:
                        pending.append((node.extra, left, right))
        for child in scope.children:
            if child.name and child.declaration:
                left, right = min((span for span in blocks if span[0] <= child.start <= span[1]),
                                  key=lambda span: span[1] - span[0])
                regions.append((left, right, child.name))
        return regions

    def lexical_binding(self, scope, name, position=None):
        position = scope.body_start if position is None else position
        root = scope
        while scope is not None:
            root = scope
            matches = [(left, right) for left, right, candidate in self.binding_regions[scope]
                       if candidate == name and left <= position <= right]
            if matches:
                left, _ = min(matches, key=lambda span: span[1] - span[0])
                return scope, left, name
            position, scope = scope.start, scope.parent
        return root, root.body_start, name

    def binding(self, scope, name, position=None):
        key = self.lexical_binding(scope, name, position)
        if (key[0], name) in self.commonjs_locals:
            return key
        module = self.module_roots.get(key[0])
        entry = module.imports.get(name) if module is not None else None
        if entry and entry[1] != '*' and name not in module.uncertain_requires:
            target = self.graph.resolve(module, entry[0])
            resolved = self.export_key(target, entry[1]) if target is not None else None
            if resolved is not None:
                return resolved
        return key

    def lookup(self, scope, name):
        key = self.binding(scope, name)
        if self.selected_import(scope, name) and key[0] in self.module_roots:
            if (key[0], key[2]) in self.commonjs_targets:
                return self.commonjs_targets[key[0], key[2]]
            if key[2] == '@default':
                return self.default_targets.get(key[0])
            return next((fn for fn in key[0].children if fn.name == key[2]), None)
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
                for kind, targets, _, _, _ in _declaration_entries(self.text, self.code, node.start, node.end):
                    if (direct and (not block or kind != 'var')) or (not block and kind == 'var'):
                        names.update(targets)
            if not block:
                pending.extend((child, False) for child in (*node.body, *node.alternate))
        return names

    def scope_statements(self, scope):
        if scope.statements is not None:
            # Module bodies include resolved CommonJS/default-export nodes.
            return scope.statements
        return [] if scope.concise else _Parser(scope).sequence(scope.body_start, scope.body_end)

    def analyze(self, scope, rule):
        statements = self.scope_statements(scope)
        state = _State(budget=self.budget)
        for name in self.declarations(statements):
            state[name], state.bindings[name] = frozenset(), None
            state.owners[name] = self.binding(scope, name)
            state.binding_kinds[state.owners[name]] = 'undefined'
        for names, _, _, _ in scope.params:
            for name in names:
                state[name] = frozenset({_Trace(('parameter', scope, name), (name,))})
                state.bindings[name] = None
                state.owners[name] = self.binding(scope, name)
                state.binding_kinds[state.owners[name]] = None
        for child in scope.children:
            if child.name and child.declaration:
                state.bindings[child.name] = child
                state.owners[child.name] = self.binding(scope, child.name, child.start)
                state.binding_kinds[state.owners[child.name]] = 'present'
        flow = _Flow(self, scope, rule)
        if scope.concise:
            value, final = flow.branch_value(scope.body_start, scope.body_end, state)
            if final is not None:
                flow.returns.append((value, final.copy()))
            final = None
        else:
            final = flow.block(statements, state)
        self.final_states[(scope, rule)] = final or state
        exits = [*(exit_state for _, exit_state in flow.returns), *([final] if final is not None else [])]
        joined = _join_states(*exits)
        writes = {} if joined is None else {key: value for key, value in joined.cells.items() if key[0] is not scope}
        heap = (joined if joined is not None else state).heap
        thrown = _join_states(*(exit_state for _, exit_state in flow.throws))
        throw_value = (None if thrown is None else
                       _join(*(_materialize(value, store.heap, budget=self.budget)
                               for value, store in flow.throws)))
        throw_writes = ({} if thrown is None else
                        {key: _materialize(value, thrown.heap, budget=self.budget)
                         for key, value in thrown.cells.items()
                         if key[0] is not scope})
        return (_join(*(_materialize(value, store.heap, budget=self.budget)
                       for value, store in flow.returns)), flow.effects,
                {key: _materialize(value, heap, budget=self.budget) for key, value in writes.items()},
                joined is not None, throw_value, throw_writes)

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
                    captured = _materialize(_cell_value(key, state), state.heap, budget=self.budget)
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
        return result

    def rule_findings(self, rule):
        """Publish a rule's evidence only after its fixed point is resolved."""
        found = {}
        while self.pending:
            self.budget.spend()
            task = self.pending.popleft()
            self.queued.discard(task)
            self.current_task = task
            if isinstance(task, _HeapCall):
                if task.superseded:
                    continue
                result = self.analyze_heap(task)
                if task.result != result:
                    task.result = result
                    for reader in task.readers:
                        self.enqueue(reader)
                continue
            scope = task
            before = self.final_states.get((scope, rule))
            summary = self.analyze(scope, rule)
            if (self.summaries.get((scope, rule)) != summary or
                    (scope in self.module_roots and before != self.final_states.get((scope, rule)))):
                self.summaries[(scope, rule)] = summary
                for caller in self.dependents[(scope, rule)]:
                    self.enqueue(caller)
        self.current_task = None
        callers, callees = defaultdict(set), defaultdict(set)
        for (callee, domain), readers in self.dependents.items():
            if domain != rule:
                continue
            for reader in readers:
                caller = reader.scope if isinstance(reader, _HeapCall) else reader
                callers[callee].add(caller)
                callees[caller].add(callee)
        # Follow concrete entry summaries, retaining independent summaries
        # for uncalled functions and isolated recursive components. A cycle
        # with no outside entry must not lose its direct source evidence.
        pending = [scope for scope in self.scopes if scope.parent is None or not callers[scope]]
        seen, invoked = set(), set()
        while pending:
            caller = pending.pop()
            if caller in seen:
                continue
            seen.add(caller)
            self.budget.spend(1 + len(callees[caller]))
            invoked.update(callees[caller])
            pending.extend(callees[caller] - seen)
        for scope in self.scopes:
            if scope in self.input_kind_scopes and scope in invoked:
                # These defaults depend on actual definedness, which a
                # symbolic parameter trace cannot express. Concrete callers
                # already publish the effects of their separate contexts.
                continue
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
        return found

    def findings(self):
        if self.source_free:
            return
        found, failures = {}, []
        active_rules = {rule for rule, _label in self.call_sinks.values()}
        active_rules.update(rule for _location, _expr_start, rule, _label in self.write_sinks)
        if self.binding_write_sinks:
            active_rules.add('js.taint.xss')
        for rule in KIND_BY_RULE:
            if rule not in active_rules:
                continue
            self.budget = Budget(self.work_limit)
            self.pending, self.queued = deque(reversed(self.scopes)), set(self.scopes)
            try:
                found.update(self.rule_findings(rule))
            except AnalysisLimit as exc:
                # A failed rule contributes no provisional fixed-point facts.
                # Text alone cannot retain its exception traceback and heap.
                failures.append(f'{rule}: {str(exc)[:180]}')
            finally:
                # Each domain is independent. Release completed or unfinished
                # flow states before giving the next rule a fresh work budget.
                self.current_task = None
                self.pending.clear()
                self.queued.clear()
                self.summaries.clear()
                self.final_states.clear()
                self.dependents.clear()
                self.heap_calls.clear()
                self.widened_calls.clear()
                self.exact_calls.clear()
                self.recursive.clear()
        for (location, rule, label), fact in sorted(found.items()):
            trace = min(fact, key=lambda item: (len(item.path), item.path))
            yield location, rule, format_path(trace.path, label)
        if failures:
            raise AnalysisLimit('Unfinished taint rules: ' + '; '.join(failures))


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
    for file_path, rule, line, _col, path_desc in scan_project_findings(iter_js_files(ROOT)):
        bucket = issues[rule]
        bucket['count'] += 1
        if len(bucket['samples']) < 3:
            bucket['samples'].append(f'{file_path.relative_to(BASE_DIR)}:{line} {path_desc}')
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
    """Single selected file, using the same module semantics as both CLIs."""
    for _path, rule, line, col, path_desc in scan_project_findings([path]):
        yield rule, line, col, path_desc


def scan_project_findings(files):
    """Resolve only selected modules; findings retain original file offsets."""
    from ubs_core.js_modules import ModuleGraph
    graph = ModuleGraph(files)
    failures, failed_components = [], 0
    for modules in graph.components():
        engine = _Engine('', '', graph, modules)
        try:
            starts = [module.start for module in modules]
            line_starts = {module.path: [0] + [match.end() for match in re.finditer('\n', module.text)]
                           for module in modules}
            for start, rule, path_desc in engine.findings():
                module = modules[bisect_right(starts, start) - 1]
                if start >= module.end:
                    continue
                offset = start - module.start
                lines = line_starts[module.path]
                line = bisect_right(lines, offset)
                # line_starts lists begin with offset 0 <= offset, so line >= 1 — ubs:ignore[py.collections.index-arithmetic]
                yield module.path, rule, line, offset - lines[line - 1] + 1, path_desc
        except AnalysisLimit as exc:
            failed_components += 1
            if len(failures) < 3:
                selected = ', '.join(str(module.path) for module in modules[:3])
                if len(modules) > 3:
                    selected += f', and {len(modules) - 3} more files'
                failures.append(f'{selected[:240]}: {str(exc)[:300]}')
        finally:
            # No import edge crosses a component boundary. Retaining these
            # roots on the project graph kept every completed component's
            # scopes, statements and combined code alive until the scan ended.
            # Also detach them when a consumer closes the findings iterator.
            for module in modules:
                module.root = None
            del engine
    if failed_components:
        omitted = (f'; and {failed_components - len(failures)} more failed components'
                   if failed_components > len(failures) else '')
        raise AnalysisLimit(
            f'JavaScript taint analysis is incomplete in {failed_components} component(s): '
            + '; '.join(failures) + omitted)


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    selected = []
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
        selected.append(path)
    for path, rule, line, col, path_desc in scan_project_findings(selected):
        kind = KIND_BY_RULE[rule]
        yield {
            "rule": f"javascript.taint.{kind}",
            "path": str(path),
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
