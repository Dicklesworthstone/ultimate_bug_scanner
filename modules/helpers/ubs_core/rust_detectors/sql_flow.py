"""Function-scoped Rust SQL taint with finite local-call summaries.

Balanced lexical expressions retain original offsets. Parameter influence is a
set of semantic facts, never a truncated display path. Local return/sink
summaries and loop backedges reach fixed points; only SQL-text operands are
sinks. Bound values do not become SQL, and .bind() does not repair dirty SQL.

This is not a Rust type checker: imported/dynamic calls are opaque, aggregate
fields are not distinguished, and only selected-file free functions are
resolved. Work/nesting exhaustion raises an analysis error, never a clean scan.

Checkout entrypoint (independent of the legacy module's pinned detector):
  PYTHONPATH=modules/helpers python3 -m ubs_core.rust_detectors.sql_flow --format=json file.rs
Exit 0: complete and clean; 1: complete with findings; 2: incomplete or invalid.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join, substitute

RULE_ID = "rust.security.sql-injection"
CATEGORY = 8
TITLE = "Interpolated SQL reaches execution sink"
SEVERITY = "critical"
DESCRIPTION = (
    "Use sqlx query macros, .bind(), rusqlite params!, diesel DSL/bind(), or "
    "other parameterized placeholders instead of format!/concat SQL"
)

source_re = re.compile(
    r'\b(?:params|query|form|body|json|payload|data|input)\s*\.\s*get\s*\('
    r'|\b(?:params|query|form|body|json|payload|data|input)\s*\.\s*'
    r'(?:user|username|email|name|status|tenant|account|id|role|filter|search|sort|limit|offset|where|order|table|column)\b'
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|param|query|path|match_info)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\('
    r'|(?-i:\bPath)\s*\('
    r'|\b(?:std::)?env::args(?:_os)?\s*\(', re.IGNORECASE,
)
_NAME = re.compile(r'(?:r#)?[A-Za-z_]\w*(?:\s*(?:::|\.)\s*(?:r#)?[A-Za-z_]\w*)*')
_IDENT = re.compile(r'(?:r#)?[A-Za-z_]\w*')
_FN = re.compile(r'\bfn\s+((?:r#)?[A-Za-z_]\w*)')
_SQL_FUNCTIONS = re.compile(r'(?:sqlx::query(?:_as|_scalar|_unchecked|_as_unchecked)?|diesel::sql_query)')
_SQL_METHODS = re.compile(
    r'(?:conn|connection|db|database|client|pool|tx|transaction|stmt)\.'
    r'(?:execute|execute_batch|batch_execute|query|query_one|query_opt|query_row|query_map|prepare|prepare_cached|raw_query|execute_raw|query_raw)'
)


@dataclass
class State:
    values: dict[str, Fact] = field(default_factory=dict)
    reachable: bool = True

    def copy(self):
        return State(dict(self.values), self.reachable)

    def replace(self, other):
        self.values = dict(other.values)
        self.reachable = other.reachable


def merge_states(*states):
    live = [state for state in states if state.reachable]
    names = set().union(*(state.values for state in live))
    # Keep clean bindings too: a clean local still shadows a function name.
    return State({name: join(*(state.values.get(name, CLEAN) for state in live))
                  for name in names}, bool(live))


@dataclass(frozen=True)
class Function:
    start: int
    body: int
    end: int
    name: str
    scope: int
    params: tuple[tuple[str, ...], ...]
    extractors: frozenset[int]


@dataclass
class Summary:
    returned: Fact = CLEAN
    sinks: dict[int, Fact] = field(default_factory=dict)


class Source:
    def __init__(self, text: str, *, max_steps: int = 2_000_000):
        self.text = text
        self.raw = strip_comments_and_strings(text, 'rust', strip_strings=False)
        self.code = strip_comments_and_strings(text, 'rust')
        self.budget = Budget(max_steps)
        self.budget.spend(len(text) // 32 + 1)
        self.lines = [0] + [m.end() for m in re.finditer('\n', text)]
        self.pairs, self.parents = {}, {}
        stack, braces = [], []
        for pos, char in enumerate(self.code):
            if char in '([{':
                stack.append((char, pos))
                if len(stack) > 128:
                    raise AnalysisLimit('Rust SQL nesting limit exceeded; analysis is incomplete')
                if char == '{':
                    self.parents[pos] = braces[-1] if braces else -1
                    braces.append(pos)
            elif char in ')]}':
                if not stack or stack[-1][0] != {')': '(', ']': '[', '}': '{'}[char]:
                    raise AnalysisLimit('Unbalanced Rust SQL input; analysis is incomplete')
                opening = stack.pop()[1]
                self.pairs[opening] = pos
                if char == '}':
                    braces.pop()
        if stack:
            raise AnalysisLimit('Unbalanced Rust SQL input; analysis is incomplete')
        self.braces = sorted(self.parents)
        self.macros = {}
        for macro in re.finditer(r'\bmacro_rules!\s*[A-Za-z_]\w*\s*', self.code):
            opening = self.skip(macro.end())
            if opening in self.pairs:
                self.macros[macro.start()] = self.pairs[opening] + 1
        def inert(pos):
            return any(start <= pos < end for start, end in self.macros.items())
        self.boundaries = {}
        for item in re.finditer(r'\b(mod|impl|trait|struct|enum|union)\b', self.code):
            if inert(item.start()):
                continue
            opening = self.boundary(item.end(), len(text), '{;')
            if opening in self.pairs and self.code[opening] == '{':
                self.boundaries[opening] = item.group(1)
        self.functions, self.symbols = [], {}
        for match in _FN.finditer(self.code):
            if inert(match.start()):
                continue
            opening = self.skip(match.end())
            if self.code[opening:opening + 1] == '<':
                opening = self.skip(self.angle_end(opening, len(text)))
            if opening not in self.pairs or self.code[opening] != '(':
                continue
            closing = self.pairs[opening]
            body = self.boundary(closing + 1, len(text), '{;')
            if body not in self.pairs or self.code[body] != '{':
                continue
            params, extractors = [], set()
            for index, (begin, end) in enumerate(self.parts(opening + 1, closing, types=True)):
                colon = self.boundary(begin, end, ':')
                params.append(self.pattern_names(begin, colon))
                if re.match(r'\s*(?:[A-Za-z_]\w*::)*(?:Path|Query|Json|Form)\s*\(', self.code[begin:colon]):
                    extractors.add(index)
            function = Function(match.start(), body, self.pairs[body], match.group(1).removeprefix('r#'),
                                self.scope_at(match.start()), tuple(params), frozenset(extractors))
            self.functions.append(function)
            key = (function.scope, function.name)
            self.symbols[key] = None if key in self.symbols else function
        self.by_start = {f.start: f for f in self.functions}
        self.imports = defaultdict(set)
        for item in re.finditer(r'\buse\b', self.code):
            if inert(item.start()):
                continue
            end = self.boundary(item.end(), len(text), ';')
            # Imported/aliased names must not accidentally resolve to a local
            # namesake. A glob makes unresolved bare lookup opaque in its scope.
            raw = self.code[item.end():end]
            scope = self.scope_at(item.start())
            self.imports[scope].update(_IDENT.findall(raw))
            if '*' in raw:
                self.imports[scope].add('*')
        self.summaries = {function: Summary() for function in self.functions}
        self.callers = defaultdict(set)

    def skip(self, pos, end=None):
        end = len(self.code) if end is None else end
        while pos < end and self.code[pos].isspace():
            self.budget.spend()
            pos += 1
        return pos

    def trim(self, start, end):
        while start < end and self.raw[start].isspace():
            start += 1
        while end > start and self.raw[end - 1].isspace():
            end -= 1
        return start, end

    def boundary(self, start, end, chars):
        pos = start
        while pos < end:
            self.budget.spend()
            if self.code[pos] in chars:
                return pos
            pos = self.pairs[pos] + 1 if pos in self.pairs else pos + 1
        return end

    def angle_end(self, start, end):
        depth = 0
        for pos in range(start, end):
            self.budget.spend()
            char = self.code[pos]
            if char == '<':
                depth += 1
            elif char == '>' and self.code[pos - 1:pos] != '-':
                depth -= 1
                if depth == 0:
                    return pos + 1
        raise AnalysisLimit('Unclosed Rust type arguments; SQL analysis is incomplete')

    def parts(self, start, end, *, types=False):
        parts, begin, pos = [], start, start
        while pos < end:
            self.budget.spend()
            if self.code[pos] == ',':
                parts.append((begin, pos))
                begin = pos + 1
            elif pos in self.pairs:
                pos = self.pairs[pos] + 1
                continue
            elif self.code[pos] == '<' and (types or self.code[start:pos].rstrip().endswith('::')):
                pos = self.angle_end(pos, end)
                continue
            pos += 1
        if self.raw[begin:end].strip():
            parts.append((begin, end))
        return parts

    def pattern_names(self, start, end):
        names = []
        for token in _IDENT.finditer(self.code, start, end):
            name = token.group().removeprefix('r#')
            before, after = self.code[start:token.start()].rstrip(), self.code[token.end():end].lstrip()
            if (name in {'mut', 'ref', '_', 'self', 'Self', 'None', 'true', 'false'}
                    or before.endswith(("'", '::')) or after.startswith(('::', ':', '(', '{'))):
                continue
            names.append(name)
        return tuple(dict.fromkeys(names))

    def scope_at(self, pos):
        index = bisect_right(self.braces, pos) - 1
        scope = self.braces[index] if index >= 0 else -1
        while scope >= 0 and self.pairs[scope] < pos:
            scope = self.parents[scope]
        return scope

    def resolve(self, name, pos, state):
        if '.' in name or '::' in name or name in state.values:
            return None
        scope = self.scope_at(pos)
        while True:
            if name in self.imports[scope] or '*' in self.imports[scope]:
                return None
            if self.boundaries.get(scope) not in {None, 'mod'}:
                return None  # associated functions are not free functions
            if (scope, name) in self.symbols:
                return self.symbols[scope, name]
            if scope < 0 or self.boundaries.get(scope) == 'mod':
                return None
            scope = self.parents[scope]

    def step(self, pos, kind, label):
        line = bisect_right(self.lines, pos)
        return Step('', line, pos - self.lines[line - 1] + 1, kind, label)

    def origin(self, pos, label):
        return frozenset({Trace('source', (pos,), evidence=(self.step(pos, 'source', label),))})

    def solve(self):
        pending = deque(self.functions)
        queued = set(pending)
        while pending:
            self.budget.spend()
            function = pending.popleft()
            queued.remove(function)
            state = State()
            for index, names in enumerate(function.params):
                fact = frozenset({Trace('parameter', (index,))})
                if index in function.extractors:
                    fact = join(fact, self.origin(function.start, f"request extractor ({', '.join(names)})"))
                for name in names:
                    state.values[name] = fact
            flow = Flow(self, function)
            tail = flow.block(function.body + 1, function.end, state)
            previous = self.summaries[function]
            summary = Summary(join(previous.returned, flow.returned, tail if state.reachable else CLEAN), dict(previous.sinks))
            for site, fact in flow.sinks.items():
                summary.sinks[site] = join(summary.sinks.get(site, CLEAN), fact)
            if summary != previous:
                self.summaries[function] = summary
                for caller in sorted(self.callers[function], key=lambda f: f.start):
                    if caller not in queued:
                        queued.add(caller)
                        pending.append(caller)
        top = Flow(self, None)
        top.block(0, len(self.code), State())
        findings = dict(top.sinks)
        for summary in self.summaries.values():
            for site, fact in summary.sinks.items():
                findings[site] = join(findings.get(site, CLEAN), fact)
        return {site: frozenset(t for t in fact if t.kind == 'source')
                for site, fact in findings.items() if any(t.kind == 'source' for t in fact)}


class Flow:
    def __init__(self, source, function):
        self.source = source
        self.function = function
        self.returned = CLEAN
        self.sinks = {}
        self.loops = []

    @staticmethod
    def restore(state, shadows):
        for name, (present, fact) in shadows.items():
            if present:
                state.values[name] = fact
            else:
                state.values.pop(name, None)

    def exit_marks(self):
        return [(frame, len(frame['break']), len(frame['continue'])) for frame in self.loops]

    def restore_exits(self, marks, shadows):
        for frame, breaks, continues in marks:
            for state in frame['break'][breaks:] + frame['continue'][continues:]:
                self.restore(state, shadows)

    def emit(self, site, fact):
        if fact:
            self.sinks[site] = join(self.sinks.get(site, CLEAN), fact)

    def block(self, start, end, state):
        src, pos, tail, shadows = self.source, start, CLEAN, {}
        marks = self.exit_marks()
        while state.reachable and (pos := src.skip(pos, end)) < end:
            src.budget.spend()
            if pos in src.macros:
                pos = src.macros[pos]
                continue
            if src.code[pos] == ';':
                tail = CLEAN
                pos += 1
                continue
            # Item bodies are analyzed under their own parameters, never with
            # the enclosing function's local variable state.
            item = re.match(r'(?:(?:pub(?:\([^)]*\))?|async|unsafe|const)\s+)*fn\b', src.code[pos:end])
            if item:
                fn_start = pos + item.end() - 2
                function = src.by_start.get(fn_start)
                if function is not None:
                    pos = function.end + 1
                    continue
            item = re.match(r'(?:pub\s+)?(?:mod|impl|trait|struct|enum|union)\b', src.code[pos:end])
            if item:
                opening = src.boundary(pos + item.end(), end, '{;')
                pos = src.pairs.get(opening, opening) + 1
                continue
            if re.match(r'if\b', src.code[pos:end]):
                tail, pos = self.branch(pos, end, state)
                continue
            if re.match(r'match\b', src.code[pos:end]):
                opening = src.boundary(pos + 5, end, '{')
                if opening not in src.pairs:
                    raise AnalysisLimit('Malformed Rust match; SQL analysis is incomplete')
                tail = self.match_expression(pos, src.pairs[opening] + 1, state)
                pos = src.pairs[opening] + 1
                continue
            if re.match(r'(?:while|for|loop)\b', src.code[pos:end]):
                tail, pos = self.loop(pos, end, state)
                continue
            if src.code[pos] == '{':
                tail = self.block(pos + 1, src.pairs[pos], state)
                pos = src.pairs[pos] + 1
                continue
            finish = src.boundary(pos, end, ';')
            stop = re.match(r'(return|break|continue)\b', src.code[pos:finish])
            if stop:
                value = self.expr(pos + stop.end(), finish, state)
                if stop.group(1) == 'return':
                    self.returned = join(self.returned, value)
                elif self.loops:
                    self.loops[-1][stop.group(1)].append(state.copy())
                    if stop.group(1) == 'break':
                        self.loops[-1]['values'].append(value)
                state.reachable = False
            else:
                declaration = re.match(r'let\s+(?:mut\s+)?', src.code[pos:finish])
                equal = src.boundary(pos, finish, '=')
                assignment = (equal < finish and src.code[equal:equal + 2] not in {'==', '=>'}
                              and src.code[equal - 1:equal] not in '=!<>')
                if declaration and assignment:
                    colon = src.boundary(pos + declaration.end(), equal, ':')
                    names = src.pattern_names(pos + declaration.end(), colon)
                    value = self.expr(equal + 1, finish, state)
                    for name in names:
                        if name not in shadows:
                            shadows[name] = (name in state.values, state.values.get(name, CLEAN))
                        state.values[name] = advance(value, src.step(pos, 'assign', name))
                    tail = CLEAN
                elif assignment and re.fullmatch(r'\s*(?:r#)?[A-Za-z_]\w*\s*\+?\s*', src.code[pos:equal]):
                    lhs = src.code[pos:equal].strip()
                    name = lhs.rstrip('+').strip().removeprefix('r#')
                    value = self.expr(equal + 1, finish, state)
                    if lhs.endswith('+'):
                        value = join(state.values.get(name, CLEAN), value)
                    state.values[name] = advance(value, src.step(pos, 'assign', name))
                    tail = CLEAN
                elif assignment and re.match(r'\s*[A-Za-z_]\w*\s*[.\[]', src.code[pos:equal]):
                    # Aggregate updates are weak: replacing one field cannot
                    # erase the facts in a different field of the same object.
                    name = re.match(r'\s*([A-Za-z_]\w*)', src.code[pos:equal]).group(1)
                    state.values[name] = join(state.values.get(name, CLEAN), self.expr(equal + 1, finish, state))
                    tail = CLEAN
                else:
                    tail = self.expr(pos, finish, state)
                    if finish < end:
                        tail = CLEAN  # a semicolon discards the expression result
            pos = finish + 1
        self.restore(state, shadows)
        self.restore_exits(marks, shadows)
        return tail

    def branch(self, start, end, state):
        src = self.source
        opening = src.boundary(start + 2, end, '{')
        if opening not in src.pairs:
            raise AnalysisLimit('Malformed Rust if expression; SQL analysis is incomplete')
        condition = self.expr(start + 2, opening, state)
        yes, no = state.copy(), state.copy()
        pattern = re.match(r'\s*let\s+', src.code[start + 2:opening])
        shadows = {}
        if pattern:
            equal = src.boundary(start + 2 + pattern.end(), opening, '=')
            for name in src.pattern_names(start + 2 + pattern.end(), equal):
                shadows[name] = (name in yes.values, yes.values.get(name, CLEAN))
                yes.values[name] = condition
        marks = self.exit_marks()
        left = self.block(opening + 1, src.pairs[opening], yes)
        self.restore(yes, shadows)
        self.restore_exits(marks, shadows)
        pos = src.skip(src.pairs[opening] + 1, end)
        right = CLEAN
        if re.match(r'else\b', src.code[pos:end]):
            pos = src.skip(pos + 4, end)
            if re.match(r'if\b', src.code[pos:end]):
                right, pos = self.branch(pos, end, no)
            elif pos in src.pairs and src.code[pos] == '{':
                right = self.block(pos + 1, src.pairs[pos], no)
                pos = src.pairs[pos] + 1
            else:
                raise AnalysisLimit('Malformed Rust else expression; SQL analysis is incomplete')
        state.replace(merge_states(yes, no))
        return join(left if yes.reachable else CLEAN, right if no.reachable else CLEAN), pos

    def loop(self, start, end, state):
        src = self.source
        keyword = re.match(r'while|for|loop', src.code[start:end]).group()
        opening = src.boundary(start + len(keyword), end, '{')
        if opening not in src.pairs:
            raise AnalysisLimit('Malformed Rust loop; SQL analysis is incomplete')
        entry, head = state.copy(), state.copy()
        exits, values = [], []
        names = ()
        value_start = start + len(keyword)
        if keyword == 'for':
            header = re.search(r'\bin\b', src.code[value_start:opening])
            if header is None:
                raise AnalysisLimit('Malformed Rust for-loop; SQL analysis is incomplete')
            names = src.pattern_names(value_start, value_start + header.start())
            value_start += header.end()
        shadows = {name: (name in entry.values, entry.values.get(name, CLEAN)) for name in names}
        while True:
            src.budget.spend()
            body = head.copy()
            iterator = self.expr(value_start, opening, body)
            for name in names:
                body.values[name] = iterator
            frame = {'break': [], 'continue': [], 'values': []}
            self.loops.append(frame)
            self.block(opening + 1, src.pairs[opening], body)
            self.loops.pop()
            for output in [body, *frame['break'], *frame['continue']]:
                self.restore(output, shadows)
            exits.extend(frame['break'])
            values.extend(frame['values'])
            merged = merge_states(entry, body, *frame['continue'])
            if merged == head:
                break
            head = merged
        state.replace(merge_states(*(exits + ([head] if keyword != 'loop' else []))))
        return join(*values), src.pairs[opening] + 1

    def match_expression(self, start, end, state):
        src = self.source
        opening = src.boundary(start + 5, end, '{')
        if opening not in src.pairs:
            raise AnalysisLimit('Malformed Rust match; SQL analysis is incomplete')
        subject = self.expr(start + 5, opening, state)
        outputs, values = [], []
        begin, closing = opening + 1, src.pairs[opening]
        while (begin := src.skip(begin, closing)) < closing:
            if src.code[begin] == ',':
                begin += 1
                continue
            finish = src.boundary(begin, closing, ',')
            arrow = src.boundary(begin, finish, '=')
            if src.code[arrow:arrow + 2] != '=>':
                raise AnalysisLimit('Unsupported Rust match arm; SQL analysis is incomplete')
            value_start = src.skip(arrow + 2, closing)
            # Block arms may omit commas. Their closing brace, not the next
            # arm's comma, determines the expression's extent.
            if src.code[value_start:value_start + 1] == '{':
                finish = src.pairs[value_start] + 1
            guard = re.search(r'\bif\b', src.code[begin:arrow])
            pattern_end = begin + guard.start() if guard else arrow
            names = src.pattern_names(begin, pattern_end)
            branch = state.copy()
            shadows = {name: (name in branch.values, branch.values.get(name, CLEAN)) for name in names}
            for name in names:
                branch.values[name] = subject
            marks = self.exit_marks()
            if guard:
                self.expr(begin + guard.end(), arrow, branch)
            value = self.expr(arrow + 2, finish, branch)
            self.restore(branch, shadows)
            self.restore_exits(marks, shadows)
            outputs.append(branch)
            if branch.reachable:
                values.append(value)
            begin = finish
        state.replace(merge_states(*outputs))
        return join(*values)

    def expr(self, start, end, state):
        src = self.source
        start, end = src.trim(start, end)
        if re.match(r'if\b', src.code[start:end]):
            return self.branch(start, end, state)[0]
        if re.match(r'(?:while|for|loop)\b', src.code[start:end]):
            return self.loop(start, end, state)[0]
        if re.match(r'match\b', src.code[start:end]):
            return self.match_expression(start, end, state)
        result, receiver, pos = CLEAN, CLEAN, start
        while state.reachable and pos < end:
            src.budget.spend()
            if pos in src.pairs:
                close = src.pairs[pos]
                value = (self.block(pos + 1, close, state) if src.code[pos] == '{'
                         else self.expr(pos + 1, close, state))
                result, receiver, pos = join(result, value), value, close + 1
                continue
            token = _NAME.match(src.code, pos, end)
            if token is None:
                pos += 1
                continue
            name = re.sub(r'\s+', '', token.group()).replace('r#', '')
            after = src.skip(token.end(), end)
            if src.code.startswith('::<', after):
                after = src.skip(src.angle_end(after + 2, end), end)
            macro = src.code[after:after + 1] == '!'
            if macro:
                after = src.skip(after + 1, end)
            chained = src.code[start:pos].rstrip().endswith('.')
            root = re.split(r'\.|::', name)[0]
            value = receiver if chained else state.values.get(root, CLEAN)
            if after in src.pairs and src.code[after] in ('([{' if macro else '('):
                close = src.pairs[after]
                spans = src.parts(after + 1, close)
                arguments = [self.expr(a, b, state) for a, b in spans]
                local = None if macro or chained else src.resolve(name, pos, state)
                if local is not None:
                    if self.function is not None:
                        src.callers[local].add(self.function)
                    summary = src.summaries[local]
                    actuals = {(i,): value for i, value in enumerate(arguments)}
                    step = src.step(pos, 'call', f'{name}()')
                    value = substitute(summary.returned, actuals, step)
                    for site, fact in summary.sinks.items():
                        self.emit(site, substitute(fact, actuals, src.step(pos, 'call', f'{name}() SQL execution')))
                else:
                    value = join(value, *arguments)
                    direct = source_re.match(src.raw[pos:close + 1])
                    if direct:
                        value = join(value, src.origin(pos, ' '.join(direct.group().split())))
                    index = self.sink_operand(name, macro)
                    if index is not None and index < len(arguments):
                        self.emit(pos, arguments[index])
                    if macro and name in {'format', 'format_args', 'write', 'writeln'}:
                        template_index = 1 if name in {'write', 'writeln'} else 0
                        if template_index < len(spans):
                            a, b = spans[template_index]
                            for capture in re.finditer(r'(?<!\{)\{((?:r#)?[A-Za-z_]\w*)(?::[^{}]*)?\}(?!\})', src.raw[a:b]):
                                value = join(value, state.values.get(capture.group(1).removeprefix('r#'), CLEAN))
                        if template_index and spans:
                            targets = src.pattern_names(*spans[0])
                            for target in targets:
                                if target in state.values:
                                    state.values[target] = join(state.values[target], value)
                            value = CLEAN
                    if name.rsplit('.', 1)[-1] in {'push', 'push_str', 'write_str'} and '.' in name:
                        if root in state.values:
                            state.values[root] = join(state.values[root], *arguments)
                        value = CLEAN
                    if macro and name in {'panic', 'unreachable', 'todo'}:
                        state.reachable = False
                result, receiver, pos = join(result, value), value, close + 1
            else:
                direct = source_re.fullmatch(src.raw[pos:token.end()])
                if direct:
                    value = join(value, src.origin(pos, ' '.join(direct.group().split())))
                result, receiver, pos = join(result, value), value, token.end()
        return result

    @staticmethod
    def sink_operand(name, macro):
        # Compile-time checked macros are not runtime query-string sinks.
        # This decision belongs to this exact call, not its whole source line.
        if macro:
            return None
        if (_SQL_FUNCTIONS.fullmatch(name) or _SQL_METHODS.fullmatch(name)
                or name in {'execute_sql', 'raw_query', 'query_raw', 'execute_raw'}):
            return 0
        if name in {'sea_orm::Statement::from_sql_and_values',
                    'tokio_postgres::Client::query', 'postgres::Client::query'}:
            return 1
        return None


def scan_text(text: str, *, max_steps: int = 2_000_000):
    """Analyze source without I/O or suppression; return sink sites and facts."""
    try:
        return Source(text, max_steps=max_steps).solve()
    except RecursionError as exc:
        raise AnalysisLimit('Rust SQL recursion limit exceeded; analysis is incomplete') from exc


def scan_file(path: Path, *, max_steps: int = 2_000_000):
    """Structured findings after shared, sink-only suppression processing."""
    from ubs_core.suppression import build_index

    text = path.read_text(encoding='utf-8')
    findings = scan_text(text, max_steps=max_steps)
    suppressions = build_index(text, lang='rust')
    lines = text.splitlines()
    starts = [0] + [m.end() for m in re.finditer('\n', text)]
    records = []
    for site, facts in sorted(findings.items()):
        line = bisect_right(starts, site)
        if suppressions.is_suppressed(line, RULE_ID):
            continue
        trace = min(facts, key=lambda t: (len(t.evidence), t.evidence, t.key))
        labels = [step.label for step in trace.evidence]
        labels.append('SQL execution')
        sample = lines[line - 1].strip().replace('\t', ' ')
        records.append({
            'rule': RULE_ID, 'path': str(path), 'line': line,
            'col': site - starts[line - 1] + 1, 'severity': SEVERITY,
            'message': TITLE, 'sample': f"{sample}  [{' -> '.join(labels)}]",
            'source_count': len(facts),
            'evidence': [dict(step.record(), path=str(path)) for step in trace.evidence],
        })
    return records


def analyze(path: Path, issues):
    """Legacy detector result shape, deduplicated by physical sink line."""
    seen = set()
    for record in scan_file(path):
        if record['line'] not in seen:
            seen.add(record['line'])
            issues.append((path, record['line'], record['sample']))


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Keep selected-file ordering and completed results before a later error."""
    for path in files:
        if path.suffix != '.rs':
            continue
        issues = []
        analyze(path, issues)
        for file, line, sample in issues:
            yield file, line, 1, sample


def main(argv=None):
    """Explicit selected-file scans with JSON purity and honest partial status."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('--files-from', type=Path, help='NUL-separated selected Rust paths')
    parser.add_argument('--max-steps', type=int, default=2_000_000, help='Per-file analysis work limit')
    parser.add_argument('files', nargs='*', type=Path)
    args = parser.parse_args(argv)
    if args.max_steps <= 0:
        parser.error('--max-steps must be positive')
    if not args.files and args.files_from is None:
        parser.error('provide Rust files or --files-from')
    files, findings, errors, completed = list(args.files), [], [], 0
    if args.files_from is not None:
        try:
            data = args.files_from.read_bytes()
            if data and not data.endswith(b'\0'):
                raise ValueError('file list must be NUL-terminated')
            files.extend(Path(p.decode('utf-8', 'surrogateescape')) for p in data.split(b'\0') if p)
        except (OSError, ValueError) as exc:
            errors.append({'path': str(args.files_from), 'reason': str(exc)})
    selected = list(dict.fromkeys(files))
    for path in selected:
        try:
            if path.suffix != '.rs':
                raise ValueError('selected input must be a Rust .rs file')
            findings.extend(scan_file(path, max_steps=args.max_steps))
            completed += 1
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append({'path': str(path), 'reason': str(exc)})
    status = ('partial' if completed else 'error') if errors else 'ok'
    code = 2 if errors else (1 if findings else 0)
    report = {
        'schema': 'ubs.rust-sql/1', 'status': status, 'exit_code': code,
        'summary': {'files': len(selected), 'completed_files': completed, 'critical': len(findings)},
        'findings': findings, 'errors': errors,
    }
    if args.format == 'json':
        print(json.dumps(report, sort_keys=True))
    else:
        for record in findings:
            print(f"{record['path']}:{record['line']}:{record['col']}: {record['sample']}")
        for error in errors:
            print(f"ERROR: {error['path']}: {error['reason']}", file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
