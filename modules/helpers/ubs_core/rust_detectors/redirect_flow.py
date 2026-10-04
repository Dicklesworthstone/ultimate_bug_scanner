"""Finite, function-scoped Rust redirect dataflow over selected source text.

This is a conservative lexical front end, not a Rust type checker. Balanced
expressions, lexical blocks, branches, loops and named local functions are
modeled; macro expansion, dynamic dispatch and imported functions are opaque.
A fact is a finite set of source sites or symbolic parameter positions. Local
return/sink summaries and loop backedges reach a least fixed point without
inlining, path enumeration or an iteration cutoff. Reporting never changes
transfer functions: suppressing a source line cannot erase its downstream use.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field
import re

from ubs_core.lexer import strip_comments_and_strings
from . import open_redirect as rules


@dataclass(frozen=True, order=True)
class Origin:
    kind: str
    site: int
    label: str = ''


Fact = frozenset[Origin]
CLEAN: Fact = frozenset()


def join(*facts: Fact) -> Fact:
    return frozenset().union(*facts)


@dataclass
class State:
    values: dict[str, Fact] = field(default_factory=dict)
    checks: dict[str, frozenset[str]] = field(default_factory=dict)
    reachable: bool = True
    parsed: dict[str, str] = field(default_factory=dict)
    literals: dict[str, str] = field(default_factory=dict)

    def copy(self):
        return State(dict(self.values), dict(self.checks), self.reachable, dict(self.parsed), dict(self.literals))

    def assign(self, name, fact):
        self.values[name] = fact
        self.checks.pop(name, None)
        self.literals.pop(name, None)
        self.parsed = {key: value for key, value in self.parsed.items() if key != name and value != name}

    def replace(self, other):
        if other is None:
            self.reachable = False
        else:
            self.values = dict(other.values)
            self.checks = dict(other.checks)
            self.reachable = other.reachable
            self.parsed = dict(other.parsed)
            self.literals = dict(other.literals)

    def checked(self, name, check):
        self.checks[name] = self.checks.get(name, frozenset()) | {check}
        if ({'local-slash', 'not-network-path'} <= self.checks[name]
                or {'https-scheme', 'allowed-host'} <= self.checks[name]
                or 'validated' in self.checks[name]):
            self.values[name] = CLEAN


def join_states(*states):
    live = [s for s in states if s is not None and s.reachable]
    if not live:
        return None
    names = set().union(*(s.values for s in live))
    values = {n: join(*(s.values.get(n, CLEAN) for s in live)) for n in names}
    checks = {n: frozenset.intersection(*(s.checks.get(n, frozenset()) for s in live)) for n in names}
    parsed = {n: v for n, v in live[0].parsed.items() if all(s.parsed.get(n) == v for s in live)}
    literals = {n: v for n, v in live[0].literals.items() if all(s.literals.get(n) == v for s in live)}
    return State(values, {n: c for n, c in checks.items() if c}, True, parsed, literals)


@dataclass
class Exit:
    kind: str
    state: State
    value: Fact = CLEAN


@dataclass(frozen=True)
class Function:
    start: int
    body: int
    end: int
    name: str
    params: tuple[tuple[str, ...], ...]
    scope: int


@dataclass
class Summary:
    returned: Fact = CLEAN
    sinks: dict[int, Fact] = field(default_factory=dict)
    completes: bool = False


_IDENTIFIER = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*')
_PATH = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*(?:\s*(?:::|\.)\s*(?:r#)?[A-Za-z_][A-Za-z_0-9]*)*')
_PREDICATE = re.compile(r'(?:is_local_redirect|isLocalRedirect|is_allowed_redirect_host|isAllowedRedirectHost)')


class Source:
    def __init__(self, text):
        self.text = text
        self.raw = strip_comments_and_strings(text, 'rust', strip_strings=False)
        self.code = strip_comments_and_strings(text, 'rust')
        self.pairs = {}
        self.parents = {}
        stack = []
        braces = []
        for pos, char in enumerate(self.code):
            if char in '([{':
                stack.append((char, pos))
                if char == '{':
                    self.parents[pos] = braces[-1] if braces else -1
                    braces.append(pos)
            elif char in ')]}' and stack and stack[-1][0] == {')': '(', ']': '[', '}': '{'}[char]:
                opening = stack.pop()[1]
                self.pairs[opening] = pos
                if char == '}':
                    braces.pop()
        self.braces = sorted(self.parents)
        self.lines = [0] + [m.end() for m in re.finditer('\n', text)]
        self.boundaries = {}
        for opening in self.braces:
            prefix = self.code[max(0, opening - 500):opening]
            prefix = re.split(r'[;{}]', prefix)[-1]
            if re.search(r'\b(?:mod|impl|trait)\b', prefix):
                self.boundaries[opening] = 'module' if re.search(r'\bmod\b', prefix) else 'type'
        self.functions = []
        self.symbols = {}
        self.definitions = {}
        for match in re.finditer(r'\bfn\s+((?:r#)?[A-Za-z_]\w*)', self.code):
            pos = self.skip(match.end())
            if pos < len(self.code) and self.code[pos] == '<':
                pos = self.generic_end(pos, len(self.code))
                pos = self.skip(pos)
            if pos not in self.pairs or self.code[pos] != '(':
                continue
            close = self.pairs[pos]
            body = self.next_boundary(close + 1, len(self.code), '{;')
            if body >= len(self.code) or self.code[body] != '{' or body not in self.pairs:
                continue
            params = []
            for begin, end in self.parts(pos + 1, close, generics=True):
                colon = self.next_boundary(begin, end, ':')
                names = tuple(n.group().removeprefix('r#') for n in _IDENTIFIER.finditer(self.code[begin:colon])
                              if n.group() not in {'mut', 'ref', 'self', 'Self'}
                              and (n.end() == colon - begin or self.code[begin + n.end():colon].lstrip()[:1] != '('))
                params.append(names)
            function = Function(match.start(), body, self.pairs[body], match.group(1).removeprefix('r#'),
                                tuple(params), self.scope_at(match.start()))
            self.functions.append(function)
            self.definitions[match.start()] = function
            key = (function.scope, function.name)
            self.symbols[key] = None if key in self.symbols else function
        self.summaries = {f: Summary() for f in self.functions}
        self.callers = defaultdict(set)

    def skip(self, pos, end=None):
        end = len(self.code) if end is None else end
        while pos < end and self.code[pos].isspace():
            pos += 1
        return pos

    def trim(self, start, end):
        # Use comment-masked text here: string literals are expressions too.
        while start < end and self.raw[start].isspace():
            start += 1
        while end > start and self.raw[end - 1].isspace():
            end -= 1
        return start, end

    def generic_end(self, start, end):
        depth = 0
        for pos in range(start, end):
            char = self.code[pos]
            if char == '<':
                depth += 1
            elif char == '>' and (pos == 0 or self.code[pos - 1] != '-'):
                depth -= 1
                if depth == 0:
                    return pos + 1
        return end

    def next_boundary(self, start, end, chars):
        pos = start
        while pos < end:
            if self.code[pos] in chars:
                return pos
            if pos in self.pairs:
                pos = self.pairs[pos] + 1
            else:
                pos += 1
        return end

    def parts(self, start, end, separator=',', *, generics=False):
        result = []
        pos = start
        begin = start
        while pos < end:
            if self.code[pos] == separator:
                result.append((begin, pos))
                begin = pos + 1
            elif pos in self.pairs:
                pos = self.pairs[pos] + 1
                continue
            elif generics and self.code[pos] == '<':
                pos = self.generic_end(pos, end)
                continue
            pos += 1
        if self.raw[begin:end].strip():
            result.append((begin, end))
        return result

    def scope_at(self, pos):
        index = bisect_right(self.braces, pos) - 1
        scope = self.braces[index] if index >= 0 else -1
        while scope >= 0 and self.pairs.get(scope, -1) < pos:
            scope = self.parents[scope]
        return scope

    def resolve(self, name, pos, state):
        if name in state.values or '.' in name or '::' in name:
            return None
        scope = self.scope_at(pos)
        while True:
            if self.boundaries.get(scope) != 'type' and (scope, name) in self.symbols:
                return self.symbols[(scope, name)]
            if scope < 0 or scope in self.boundaries:
                return None
            scope = self.parents[scope]

    def solve(self):
        pending = deque(self.functions)
        queued = set(pending)
        while pending:
            function = pending.popleft()
            queued.discard(function)
            flow = Flow(self, function)
            state = State()
            for index, names in enumerate(function.params):
                for name in names:
                    state.assign(name, frozenset({Origin('parameter', index)}))
            normal, tail = flow.block(function.body + 1, function.end, state)
            returned = join(tail if normal is not None else CLEAN,
                            *(exit.value for exit in flow.exits if exit.kind == 'return'))
            previous = self.summaries[function]
            summary = Summary(join(previous.returned, returned), dict(previous.sinks),
                              previous.completes or normal is not None or any(e.kind == 'return' for e in flow.exits))
            for site, fact in flow.sinks.items():
                summary.sinks[site] = join(summary.sinks.get(site, CLEAN), fact)
            if summary != previous:
                self.summaries[function] = summary
                for caller in self.callers[function]:
                    if caller not in queued:
                        queued.add(caller)
                        pending.append(caller)
        # Top-level snippets and initializers are a separate lexical scope.
        flow = Flow(self, None)
        flow.block(0, len(self.code), State())
        findings = dict(flow.sinks)
        for summary in self.summaries.values():
            for site, fact in summary.sinks.items():
                findings[site] = join(findings.get(site, CLEAN), fact)
        return {site: frozenset(o for o in fact if o.kind == 'source') for site, fact in findings.items()
                if any(o.kind == 'source' for o in fact)}


class Flow:
    def __init__(self, source, function):
        self.source = source
        self.function = function
        self.exits = []
        self.sinks = {}

    def emit(self, site, fact):
        if fact:
            self.sinks[site] = join(self.sinks.get(site, CLEAN), fact)

    @staticmethod
    def restore(state, shadows):
        if state is None:
            return
        for name, (present, value, checks, parsed, literal) in shadows.items():
            if present:
                state.values[name] = value
            else:
                state.values.pop(name, None)
            if checks:
                state.checks[name] = checks
            else:
                state.checks.pop(name, None)
            for mapping, saved in ((state.parsed, parsed), (state.literals, literal)):
                if saved is not None:
                    mapping[name] = saved
                else:
                    mapping.pop(name, None)

    @staticmethod
    def snapshot(state, name):
        return (name in state.values, state.values.get(name, CLEAN), state.checks.get(name, frozenset()),
                state.parsed.get(name), state.literals.get(name))

    def declare(self, name, value, state, shadows):
        if name not in shadows:
            shadows[name] = self.snapshot(state, name)
        state.assign(name, value)

    def block(self, start, end, state):
        src = self.source
        state = state.copy()
        shadows = {}
        first_exit = len(self.exits)
        tail = CLEAN
        pos = start
        while state.reachable:
            pos = src.skip(pos, end)
            while pos < end and src.code[pos] == ';':
                pos = src.skip(pos + 1, end)
            if pos >= end:
                break
            if src.code.startswith('#[', pos) or src.code.startswith('#![', pos):
                bracket = src.code.find('[', pos, end)
                pos = src.pairs.get(bracket, end - 1) + 1
                continue
            # Items do not execute when their enclosing function executes.
            item = re.match(r'(?:(?:pub(?:\([^)]*\))?|async|unsafe|const|extern)\s+)*(fn|mod|impl|trait|struct|enum|use)\b', src.code[pos:end])
            if item:
                boundary = src.next_boundary(pos, end, '{;')
                pos = src.pairs.get(boundary, boundary) + 1
                continue
            control = re.match(r'(if|while|for|loop)\b', src.code[pos:end])
            if control:
                if control.group() == 'if':
                    pos, normal, tail = self.branch(pos, end, state)
                else:
                    pos, normal, tail = self.loop(pos, end, state, control.group())
                state.replace(normal)
                continue
            if src.code[pos] == '{' and pos in src.pairs:
                normal, tail = self.block(pos + 1, src.pairs[pos], state)
                state.replace(normal)
                pos = src.pairs[pos] + 1
                continue
            stop = src.next_boundary(pos, end, ';')
            begin, finish = src.trim(pos, stop)
            exit_match = re.match(r'(return|break|continue)\b', src.code[begin:finish])
            if exit_match:
                value = self.expr(begin + exit_match.end(), finish, state)
                if state.reachable:
                    self.exits.append(Exit(exit_match.group(), state.copy(), value))
                state.reachable = False
                break
            declaration = re.match(r'let\s+(?:mut\s+)?', src.code[begin:finish])
            equal = src.next_boundary(begin, finish, '=')
            assignment = (equal < finish and src.code[equal:equal + 2] not in {'==', '=>'}
                          and (equal == begin or src.code[equal - 1] not in '=!<>'))
            if assignment:
                lhs_begin = begin + declaration.end() if declaration else begin
                lhs = src.code[lhs_begin:equal].strip()
                compound = lhs.endswith(('+', '-', '*', '/', '|', '&', '^'))
                if compound:
                    lhs = lhs[:-1].rstrip()
                colon = src.next_boundary(lhs_begin, equal, ':')
                if declaration:
                    lhs = src.code[lhs_begin:colon].strip()
                value = self.expr(equal + 1, finish, state)
                if state.reachable:
                    names = [n.group().removeprefix('r#') for n in _IDENTIFIER.finditer(lhs)
                             if n.group() not in {'mut', 'ref'}]
                    if declaration:
                        for name in names:
                            self.declare(name, value, state, shadows)
                            self.binding_contract(name, equal + 1, finish, state)
                    elif names:
                        name = names[0]
                        if compound or not _IDENTIFIER.fullmatch(lhs):
                            value = join(state.values.get(name, CLEAN), value)
                        state.assign(name, value)
                        if not compound and _IDENTIFIER.fullmatch(lhs):
                            self.binding_contract(name, equal + 1, finish, state)
                tail = CLEAN
            elif declaration:
                name = _IDENTIFIER.match(src.code, begin + declaration.end())
                if name:
                    self.declare(name.group(), CLEAN, state, shadows)
                tail = CLEAN
            else:
                value = self.expr(begin, finish, state)
                tail = value if stop == end else CLEAN
            pos = stop + 1
        normal = state if state.reachable else None
        self.restore(normal, shadows)
        for exit in self.exits[first_exit:]:
            self.restore(exit.state, shadows)
        return normal, tail

    def branch(self, start, end, state):
        src = self.source
        opening = src.next_boundary(start + 2, end, '{')
        if opening not in src.pairs or src.pairs[opening] > end:
            return end, state, self.expr(start + 2, end, state)
        close = src.pairs[opening]
        yes, no = self.condition(start + 2, opening, state)
        left, left_value = self.block(opening + 1, close, yes) if yes is not None else (None, CLEAN)
        pos = src.skip(close + 1, end)
        right_value = CLEAN
        if re.match(r'else\b', src.code[pos:end]):
            body = src.skip(pos + 4, end)
            if src.code.startswith('if', body):
                if no is not None:
                    pos, no, right_value = self.branch(body, end, no)
                else:
                    pos = self.branch_end(body, end)
            elif body in src.pairs and src.code[body] == '{':
                if no is not None:
                    no, right_value = self.block(body + 1, src.pairs[body], no)
                pos = src.pairs[body] + 1
        return pos, join_states(left, no), join(left_value if left is not None else CLEAN,
                                              right_value if no is not None else CLEAN)

    def branch_end(self, start, end):
        src = self.source
        opening = src.next_boundary(start + 2, end, '{')
        if opening not in src.pairs:
            return end
        pos = src.skip(src.pairs[opening] + 1, end)
        if re.match(r'else\b', src.code[pos:end]):
            pos = src.skip(pos + 4, end)
            if src.code.startswith('if', pos):
                return self.branch_end(pos, end)
            return src.pairs.get(pos, end - 1) + 1
        return pos

    def loop(self, start, end, state, kind):
        src = self.source
        opening = src.next_boundary(start + len(kind), end, '{')
        if opening not in src.pairs:
            return end, state, CLEAN
        close = src.pairs[opening]
        entry = state.copy()
        head = entry.copy()
        completed = []
        values = CLEAN
        while True:
            if kind == 'while':
                body, zero = self.condition(start + len(kind), opening, head.copy())
            else:
                body, zero = head.copy(), None if kind == 'loop' else head.copy()
            if zero is not None:
                completed.append(zero)
            first_exit = len(self.exits)
            if kind == 'for':
                header = src.code[start + 3:opening]
                match = re.match(r'\s*([A-Za-z_]\w*)\s+in\b', header)
                if match:
                    value = self.expr(start + 3 + match.end(), opening, body)
                    name = match.group(1)
                    old = self.snapshot(body, name)
                    body.assign(name, value)
                else:
                    name, old = None, None
            else:
                name, old = None, None
            normal, _ = self.block(opening + 1, close, body) if body is not None else (None, CLEAN)
            exits = self.exits[first_exit:]
            del self.exits[first_exit:]
            if name is not None:
                self.restore(normal, {name: old})
                for exit in exits:
                    self.restore(exit.state, {name: old})
            back = [normal]
            for exit in exits:
                if exit.kind == 'break':
                    completed.append(exit.state)
                    values = join(values, exit.value)
                elif exit.kind == 'continue':
                    back.append(exit.state)
                else:
                    self.exits.append(exit)
            next_head = join_states(entry, *back)
            if next_head == head:
                break
            head = next_head
        return close + 1, join_states(*completed), values

    def condition(self, start, end, state):
        src = self.source
        start, end = src.trim(start, end)
        while start < end and src.code[start] == '(' and src.pairs.get(start) == end - 1:
            start, end = src.trim(start + 1, end - 1)
        if start >= end:
            return state.copy(), state.copy()
        # Respect precedence: OR splits before AND, then unary negation.
        for operator in ('||', '&&'):
            pos = start
            while pos < end:
                if pos in src.pairs:
                    pos = src.pairs[pos] + 1
                    continue
                if src.code.startswith(operator, pos):
                    yes, no = self.condition(start, pos, state)
                    if operator == '&&':
                        right_yes, right_no = self.condition(pos + 2, end, yes) if yes is not None else (None, None)
                        return right_yes, join_states(no, right_no)
                    right_yes, right_no = self.condition(pos + 2, end, no) if no is not None else (None, None)
                    return join_states(yes, right_yes), right_no
                pos += 1
        if src.code[start] == '!':
            yes, no = self.condition(start + 1, end, state)
            return no, yes
        self.expr(start, end, state)
        if not state.reachable:
            return None, None
        code = src.code[start:end].strip()
        if code in {'true', 'false'}:
            return (state.copy(), None) if code == 'true' else (None, state.copy())
        yes, no = state.copy(), state.copy()
        raw = src.raw[start:end].strip()
        predicate = re.fullmatch(r'([A-Za-z_]\w*)\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)', raw)
        if (predicate and _PREDICATE.fullmatch(predicate.group(1))
                and predicate.group(1) not in state.values
                and src.resolve(predicate.group(1), start, state) is None):
            yes.checked(predicate.group(2), 'validated')
        local = re.fullmatch(r'''([A-Za-z_]\w*)\s*\.\s*starts_with\s*\(\s*(["'])(/{1,2})\2\s*\)''', raw)
        if local:
            if local.group(3) == '/':
                yes.checked(local.group(1), 'local-slash')
            else:
                no.checked(local.group(1), 'not-network-path')
        scheme = re.fullmatch(r'([A-Za-z_]\w*)\s*\.\s*scheme\s*\(\s*\)\s*(==|!=)\s*"https"', raw)
        if scheme:
            self.parsed_check(yes if scheme.group(2) == '==' else no, scheme.group(1), 'https-scheme')
        host = re.fullmatch(r'([A-Za-z_]\w*)\s*\.\s*contains\s*\(\s*&\s*([A-Za-z_]\w*)\s*\.\s*host_str\s*\(\s*\)\s*\.\s*unwrap_or_default\s*\(\s*\)\s*\)', raw)
        if host and host.group(1) in state.literals and self.host_allowlist(state.literals[host.group(1)]):
            self.parsed_check(yes, host.group(2), 'allowed-host')
        return yes, no

    @staticmethod
    def host_allowlist(raw):
        return bool(re.fullmatch(r'\[\s*"[A-Za-z0-9.-]+"(?:\s*,\s*"[A-Za-z0-9.-]+")*\s*,?\s*\]', raw))

    def parsed_check(self, state, parsed, check):
        original = state.parsed.get(parsed)
        if original is not None:
            state.checked(original, check)
            state.checked(parsed, check)

    def binding_contract(self, name, start, end, state):
        src = self.source
        raw = src.raw[start:end].strip()
        if self.host_allowlist(raw):
            state.literals[name] = raw
        # Only successful parsing of this exact binding carries authority
        # back to it. An unwrap_or fallback, transformation, or later write
        # breaks that relationship and cannot validate the original target.
        match = re.match(r'(?:url::)?Url::parse\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)', raw)
        if match and match.group(1) != name:
            suffix = raw[match.end():].strip()
            if not suffix or suffix == '?' or re.fullmatch(r'\.(?:map_err|expect|unwrap)\s*\(.*\)\s*\??', suffix, re.DOTALL):
                state.parsed[name] = match.group(1)

    def expr(self, start, end, state):
        src = self.source
        start, end = src.trim(start, end)
        if start >= end or not state.reachable:
            return CLEAN
        if re.match(r'if\b', src.code[start:end]):
            _, normal, value = self.branch(start, end, state)
            state.replace(normal)
            return value
        if re.match(r'loop\b', src.code[start:end]):
            _, normal, value = self.loop(start, end, state, 'loop')
            state.replace(normal)
            return value
        # Closure bodies execute on invocation, not construction. Dynamic
        # closure dispatch is deliberately outside this front end's contract.
        if re.match(r'(?:move\s+)?\|', src.code[start:end]):
            return CLEAN
        result = CLEAN
        receiver = CLEAN
        pos = start
        while pos < end and state.reachable:
            char = src.code[pos]
            if char in '([' and pos in src.pairs:
                close = src.pairs[pos]
                if close >= end:
                    break
                receiver = self.expr(pos + 1, close, state)
                result = join(result, receiver)
                pos = close + 1
                continue
            if char == '{' and pos in src.pairs:
                normal, receiver = self.block(pos + 1, src.pairs[pos], state)
                state.replace(normal)
                result = join(result, receiver)
                pos = src.pairs[pos] + 1
                continue
            match = _PATH.match(src.code, pos)
            if not match:
                if char not in '.?&*' and not char.isspace():
                    receiver = CLEAN
                pos += 1
                continue
            name = re.sub(r'\s+', '', match.group()).replace('r#', '')
            chained = pos > start and src.code[start:pos].rstrip().endswith('.')
            base = name.split('.')[0]
            value = receiver if chained else state.values.get(base, CLEAN)
            call = src.skip(match.end(), end)
            macro = call < end and src.code[call] == '!'
            if macro:
                call = src.skip(call + 1, end)
            if src.code.startswith('::<', call):
                call = src.skip(src.generic_end(call + 2, end), end)
            if call in src.pairs and src.code[call] in '([' and src.pairs[call] < end:
                close = src.pairs[call]
                spans = src.parts(call + 1, close)
                arguments = [self.expr(a, b, state) for a, b in spans]
                if not state.reachable:
                    return CLEAN
                local = src.resolve(name, pos, state) if not chained and not macro else None
                if local is not None:
                    if self.function is not None:
                        src.callers[local].add(self.function)
                    summary = src.summaries[local]
                    def substitute(fact):
                        return join(*(arguments[o.site] if o.kind == 'parameter' and o.site < len(arguments)
                                      else CLEAN if o.kind == 'parameter' else frozenset({o}) for o in fact))
                    value = substitute(summary.returned)
                    for site, fact in summary.sinks.items():
                        self.emit(site, substitute(fact))
                    if not summary.completes:
                        state.reachable = False
                elif rules.safe_expr_re.fullmatch(name) and not chained and name not in state.values:
                    # Preserve explicit external safe-redirect contracts;
                    # a local definition is analyzed rather than trusted.
                    value = CLEAN
                elif _PREDICATE.fullmatch(name) or name.endswith(('.starts_with', '.contains', '.is_empty')):
                    value = CLEAN
                else:
                    value = join(value, *arguments)
                raw_call = src.raw[pos:close + 1]
                direct = rules.source_re.match(raw_call)
                if direct and rules.has_request_source(src.raw[pos:self.chain_end(close + 1, end)]):
                    value = join(value, frozenset({Origin('source', pos, ' '.join(direct.group().split()))}))
                target = self.sink_target(name, spans, chained) if local is None and name not in state.values else None
                if target is not None:
                    self.emit(pos, arguments[target] if target >= 0 else arguments[0])
                    value = CLEAN
                if macro and name == 'format' and spans:
                    template = src.raw[spans[0][0]:spans[0][1]]
                    for capture in re.finditer(r'(?<!\{)\{([A-Za-z_]\w*)(?:[!:][^{}]*)?\}(?!\})', template):
                        value = join(value, state.values.get(capture.group(1), CLEAN))
                if macro and name in {'panic', 'unreachable', 'todo'}:
                    self.exits.append(Exit('abort', state.copy()))
                    state.reachable = False
                receiver = value
                result = join(result, value)
                pos = close + 1
            else:
                raw_name = src.raw[pos:match.end()]
                direct = rules.source_re.fullmatch(raw_name)
                if direct:
                    value = join(value, frozenset({Origin('source', pos, ' '.join(direct.group().split()))}))
                receiver = value
                result = join(result, value)
                pos = match.end()
        return result

    def sink_target(self, name, spans, chained):
        leaf = name.split('.')[-1]
        if re.fullmatch(r'(?:(?:axum|rocket)::response::|poem::web::)?Redirect::(?:to|temporary|permanent|found|see_other|moved_permanently)', name):
            return 0 if spans else None
        if re.fullmatch(r'(?:(?:warp::)?redirect::(?:redirect|temporary|permanent|see_other|found)|redirect|send_redirect|http_redirect)', name) and not chained:
            return 0 if spans else None
        if leaf == 'insert' and name not in {'headers.insert', 'header_map.insert', 'response_headers.insert'}:
            return None
        if leaf in {'header', 'append_header', 'insert_header', 'insert'} and spans:
            raw = self.source.raw[spans[0][0]:spans[0][1]].strip()
            if len(spans) >= 2 and self.location_key(raw):
                return 1
            if len(spans) == 1 and raw.startswith('('):
                begin, end = self.source.trim(*spans[0])
                if self.source.pairs.get(begin) == end - 1:
                    parts = self.source.parts(begin + 1, end - 1)
                    if len(parts) == 2 and self.location_key(self.source.raw[parts[0][0]:parts[0][1]].strip()):
                        return -1
        return None

    @staticmethod
    def location_key(raw):
        return bool(re.fullmatch(r'"(?i:location)"|(?:[A-Za-z_]\w*::)*LOCATION', raw))

    def chain_end(self, start, end):
        """Keep a request headers().get(key) source within its member chain."""
        src = self.source
        pos = src.skip(start, end)
        while pos < end and src.code[pos] == '.':
            match = _PATH.match(src.code, src.skip(pos + 1, end))
            if not match:
                break
            pos = src.skip(match.end(), end)
            if pos in src.pairs and src.code[pos] == '(':
                pos = src.skip(src.pairs[pos] + 1, end)
        return pos
