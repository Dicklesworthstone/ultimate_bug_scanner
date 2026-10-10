"""Finite, function-scoped Rust redirect dataflow over selected source text.

This is a conservative lexical front end, not a Rust type checker. Balanced
expressions, lexical blocks, pattern branches, loops and named local functions
are modeled; macro expansion, dynamic dispatch and imported functions are opaque.
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
from ubs_core.taint_flow import AnalysisLimit, Budget
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
        if ({'local-slash', 'not-network-path', 'no-backslash',
             'no-tab', 'no-newline', 'no-carriage-return'} <= self.checks[name]
                or {'https-scheme', 'allowed-host'} <= self.checks[name]):
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
    receiver: str | None = None
    generic: bool = False
    public: bool = False


@dataclass
class Summary:
    returned: Fact = CLEAN
    sinks: dict[int, Fact] = field(default_factory=dict)
    completes: bool = False


@dataclass(frozen=True)
class Namespace:
    kind: str
    site: int
    generic: bool = False


_IDENTIFIER = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*')
_PATH = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z_0-9]*(?:\s*(?:::|\.)\s*(?:r#)?[A-Za-z_][A-Za-z_0-9]*)*')
_DEFAULT_STEPS = object()


class Source:
    def __init__(self, text, *, max_steps=_DEFAULT_STEPS, raw=None):
        if max_steps is _DEFAULT_STEPS:
            max_steps = min(5_000_000, max(500_000, len(text)))
        self.budget = Budget(max_steps)
        self.budget.spend(len(text) // 64 + 1)
        self.text = text
        self.raw = raw if raw is not None else strip_comments_and_strings(text, 'rust', strip_strings=False)
        self.code = strip_comments_and_strings(text, 'rust')
        self.pairs = {}
        self.parents = {}
        stack = []
        braces = []
        for pos, char in enumerate(self.code):
            if char in '([{':
                stack.append((char, pos))
                if len(stack) > 128:
                    raise AnalysisLimit('Rust redirect nesting limit exceeded; analysis is incomplete')
                if char == '{':
                    self.parents[pos] = braces[-1] if braces else -1
                    braces.append(pos)
            elif char in ')]}':
                if not stack or stack[-1][0] != {')': '(', ']': '[', '}': '{'}[char]:
                    raise ValueError('Unbalanced Rust delimiters; redirect analysis is incomplete')
                opening = stack.pop()[1]
                self.pairs[opening] = pos
                if char == '}':
                    braces.pop()
        if stack:
            raise ValueError('Unbalanced Rust delimiters; redirect analysis is incomplete')
        self.braces = sorted(self.parents)
        self.lines = [0] + [m.end() for m in re.finditer('\n', text)]
        self.boundaries = {}
        self.functions = []
        self.symbols = {}
        self.definitions = {}
        # Rust's type/module namespace is separate from local value bindings.
        # None records an imported, unsupported, or ambiguous declaration; it
        # must stop lookup rather than falling through to an outer namesake.
        self.namespaces = {}
        self.imported_names = defaultdict(set)
        self.glob_imports = set()
        self.impl_headers = {}
        self.generic_impls = set()
        self.impl_owners = {}
        self.associated = {}
        for match in re.finditer(r'\bfn\s+((?:r#)?[A-Za-z_]\w*)', self.code):
            self.budget.spend()
            pos = self.skip(match.end())
            generic_start, generic_end = pos, pos
            if pos < len(self.code) and self.code[pos] == '<':
                generic_end = self.generic_end(pos, len(self.code))
                pos = generic_end
                pos = self.skip(pos)
            if pos not in self.pairs or self.code[pos] != '(':
                continue
            close = self.pairs[pos]
            body = self.next_boundary(close + 1, len(self.code), '{;')
            if body >= len(self.code) or self.code[body] != '{' or body not in self.pairs:
                continue
            if generic_end > generic_start:
                self.type_parameters(generic_start, generic_end, body)
            params = []
            receiver = None
            for begin, end in self.parts(pos + 1, close, generics=True):
                colon = self.next_boundary(begin, end, ':')
                names = self.pattern_names(begin, colon)
                if not params:
                    raw = self.code[begin:end].strip()
                    if re.fullmatch(r'(?:mut\s+)?self', raw):
                        receiver, names = 'value', ('self',)
                    else:
                        borrowed = re.fullmatch(r'&\s*(mut\s+)?self', raw)
                        if borrowed:
                            receiver = 'mutable' if borrowed.group(1) else 'shared'
                            names = ('self',)
                params.append(names)
            function = Function(match.start(), body, self.pairs[body], match.group(1).removeprefix('r#'),
                                tuple(params), self.scope_at(match.start()), receiver, generic_end > generic_start,
                                self.public_function(match.start()))
            self.functions.append(function)
            self.definitions[match.start()] = function
            key = (function.scope, function.name)
            self.symbols[key] = None if key in self.symbols else function
        self.index_namespaces()
        for opening, (begin, end) in self.impl_headers.items():
            raw = self.code[begin:end].strip()
            # Specializations and trait impls require type/trait resolution.
            # Keep them opaque; do not associate their methods by leaf name.
            if not re.fullmatch(r'(?:r#)?[A-Za-z_]\w*(?:\s*::\s*(?:r#)?[A-Za-z_]\w*)*', raw):
                continue
            owner = self.namespace_path(re.sub(r'\s+', '', raw).split('::'), opening)
            if owner is not None and owner.kind == 'type':
                self.impl_owners[opening] = owner
        for function in self.functions:
            owner = self.impl_owners.get(function.scope)
            if owner is not None:
                key = (owner.site, function.name)
                self.associated[key] = None if key in self.associated else function
        self.summaries = {f: Summary() for f in self.functions}
        self.callers = defaultdict(set)

    def skip(self, pos, end=None):
        end = len(self.code) if end is None else end
        while pos < end and self.code[pos].isspace():
            pos += 1
        return pos

    def public_function(self, pos):
        """Read only contiguous function modifiers, with budgeted lookbehind."""
        while pos > 0:
            previous = pos - 1
            self.budget.spend()
            if self.code[previous].isspace():
                pos = previous
                continue
            end = pos
            while pos > 0:
                previous = pos - 1
                self.budget.spend()
                if not (self.code[previous].isalnum() or self.code[previous] == '_'):
                    break
                pos = previous
            word = self.code[pos:end]
            if word == 'pub':
                return self.code[pos - 1:pos] != '#'
            if word not in {'async', 'unsafe', 'const', 'extern'}:
                return False
        return False

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
            # Failed lookahead is work too: repeated ordinary comparisons
            # must not hide an unbounded character scan from the solver.
            self.budget.spend()
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
            elif self.code[pos] == '<' and not self.code.startswith('<=', pos):
                closing = self.generic_end(pos, end)
                # Expression paths introduce type arguments with `::<...>`
                # or a qualified `<Type as Trait>::...` owner. Their commas
                # are not call-argument separators. Plain comparisons still
                # split normally; only type contexts accept a bare `<...>`.
                if (generics or self.code[start:pos].rstrip().endswith('::')
                        or self.code.startswith('::', self.skip(closing, end))):
                    pos = closing
                    continue
            pos += 1
        if self.raw[begin:end].strip():
            result.append((begin, end))
        return result

    def keyword(self, start, end, word):
        """Find a header keyword without entering nested expressions/patterns."""
        pos = start
        while pos < end:
            self.budget.spend()
            if pos in self.pairs:
                pos = self.pairs[pos] + 1
                continue
            token = _IDENTIFIER.match(self.code, pos)
            if token:
                if token.group() == word:
                    return pos
                pos = token.end()
            else:
                pos += 1
        return end

    def pattern_names(self, start, end):
        """Bindings, not constructors, paths, struct field labels or literals.

        All captures conservatively receive the subject's aggregate fact; this
        front end does not infer Rust types or project individual tuple fields.
        Qualified names and the built-in Option unit variant are not locals.
        Capitalization alone is not evidence that an identifier is a constant.
        """
        names = []
        for token in _IDENTIFIER.finditer(self.code, start, end):
            self.budget.spend()
            spelling = token.group()
            name = spelling.removeprefix('r#')
            if spelling == name and name in {'_', 'ref', 'mut', 'self', 'Self', 'true', 'false', 'const', 'None'}:
                continue
            before = self.code[start:token.start()].rstrip()
            after = self.code[token.end():end].lstrip()
            if (before.endswith('::') or after.startswith(('::', ':', '(', '{'))
                    or before.endswith("'")):
                continue
            if name not in names:
                names.append(name)
        return tuple(names)

    def condition_opening(self, start, end, *, skip_control_expressions=False):
        """Find a body after let patterns and optional header expressions."""
        pos = start
        while pos < end:
            self.budget.spend()
            token = _IDENTIFIER.match(self.code, pos)
            if token and token.group() == 'let':
                equal = self.next_boundary(token.end(), end, '=')
                pos = equal + 1
            elif skip_control_expressions and token and token.group() == 'match':
                # An unparenthesized match is a legal for-loop iterator. Its
                # arms belong to the iterator expression, before the loop body.
                opening = self.condition_opening(token.end(), end, skip_control_expressions=True)
                if opening not in self.pairs or self.pairs[opening] >= end:
                    raise ValueError('Malformed Rust match iterator; redirect analysis is incomplete')
                pos = self.pairs[opening] + 1
            elif skip_control_expressions and token and token.group() == 'if':
                opening = self.condition_opening(token.end(), end, skip_control_expressions=True)
                if opening not in self.pairs or self.pairs[opening] >= end:
                    raise ValueError('Malformed Rust if header; redirect analysis is incomplete')
                pos = self.skip(self.pairs[opening] + 1, end)
                while re.match(r'else\b', self.code[pos:end]):
                    pos = self.skip(pos + 4, end)
                    if re.match(r'if\b', self.code[pos:end]):
                        opening = self.condition_opening(pos + 2, end, skip_control_expressions=True)
                    else:
                        opening = pos
                    if opening not in self.pairs or self.code[opening] != '{' or self.pairs[opening] >= end:
                        raise ValueError('Malformed Rust else header; redirect analysis is incomplete')
                    pos = self.skip(self.pairs[opening] + 1, end)
            elif self.code[pos] == '{':
                return pos
            elif pos in self.pairs:
                pos = self.pairs[pos] + 1
            else:
                pos = token.end() if token else pos + 1
        return end

    def condition_names(self, start, end):
        names = set()
        pos = start
        while pos < end:
            at = self.keyword(pos, end, 'let')
            if at == end:
                break
            equal = self.next_boundary(at + 3, end, '=')
            names.update(self.pattern_names(at + 3, equal))
            pos = equal + 1
        return sorted(names)

    def scope_at(self, pos):
        index = bisect_right(self.braces, pos) - 1
        scope = self.braces[index] if index >= 0 else -1
        while scope >= 0 and self.pairs.get(scope, -1) < pos:
            scope = self.parents[scope]
        return scope

    def declare_namespace(self, scope, name, namespace):
        key = (scope, name.removeprefix('r#'))
        self.namespaces[key] = None if key in self.namespaces else namespace

    def type_parameters(self, start, end, scope):
        for begin, finish in self.parts(start + 1, end - 1, generics=True):
            begin = self.skip(begin, finish)
            # Const parameters and lifetimes do not shadow type names.
            if self.code[begin:begin + 1] == "'" or re.match(r'const\b', self.code[begin:finish]):
                continue
            token = _IDENTIFIER.match(self.code, begin, finish)
            if token is not None:
                self.declare_namespace(scope, token.group(), None)

    def import_names(self, start, end, prefix=''):
        names, wildcard = set(), False
        for begin, finish in self.parts(start, end):
            raw = self.code[begin:finish].strip()
            alias = re.search(r'\bas\s+((?:r#)?[A-Za-z_]\w*)\s*$', raw)
            if alias is not None:
                if alias.group(1) != '_':
                    names.add(alias.group(1).removeprefix('r#'))
                continue
            opening = self.next_boundary(begin, finish, '{')
            if opening in self.pairs and self.pairs[opening] < finish:
                tokens = list(_IDENTIFIER.finditer(self.code, begin, opening))
                parent = tokens[-1].group() if tokens else prefix
                nested, star = self.import_names(opening + 1, self.pairs[opening], parent)
                names.update(nested)
                wildcard |= star
            elif '*' in raw:
                wildcard = True
            else:
                tokens = list(_IDENTIFIER.finditer(raw))
                if tokens:
                    name = tokens[-1].group().removeprefix('r#')
                    if name == 'self':
                        name = tokens[-2].group() if len(tokens) > 1 else prefix
                    if name and name not in {'self', 'super', 'crate', '_'}:
                        names.add(name)
        return names, wildcard

    def index_namespaces(self):
        for match in re.finditer(r'\b(mod|struct|enum|union|trait|type)\s+((?:r#)?[A-Za-z_]\w*)', self.code):
            self.budget.spend()
            kind, name = match.groups()
            scope = self.scope_at(match.start())
            namespace = None
            if kind == 'mod':
                opening = self.skip(match.end())
                if self.code[opening:opening + 1] == '{' and opening in self.pairs:
                    namespace = Namespace('module', opening)
                    self.boundaries[opening] = 'module'
            elif kind in {'struct', 'enum', 'union'}:
                opening = self.skip(match.end())
                namespace = Namespace('type', match.start(), self.code[opening:opening + 1] == '<')
            elif kind == 'trait':
                opening = self.next_boundary(match.end(), len(self.code), '{;')
                if opening in self.pairs and self.code[opening] == '{':
                    self.boundaries[opening] = 'type'
            self.declare_namespace(scope, name, namespace)
        for match in re.finditer(r'\buse\s+', self.code):
            self.budget.spend()
            end = self.next_boundary(match.end(), len(self.code), ';')
            scope = self.scope_at(match.start())
            names, wildcard = self.import_names(match.end(), end)
            self.imported_names[scope].update(names)
            if wildcard:
                self.glob_imports.add(scope)
            for name in names:
                self.declare_namespace(scope, name, None)
        for match in re.finditer(r'\bextern\s+crate\s+((?:r#)?[A-Za-z_]\w*)(?:\s+as\s+((?:r#)?[A-Za-z_]\w*))?', self.code):
            self.declare_namespace(self.scope_at(match.start()), match.group(2) or match.group(1), None)
        function_starts = [function.start for function in self.functions]
        for match in re.finditer(r'\bimpl\b', self.code):
            self.budget.spend()
            index = bisect_right(function_starts, match.start()) - 1
            if index >= 0 and match.start() < self.functions[index].body:
                # `impl Trait` parameters/returns are function signatures,
                # not impl items defining an associated-method namespace.
                continue
            begin = self.skip(match.end())
            generic_start, generic_end = begin, begin
            if self.code[begin:begin + 1] == '<':
                generic_end = self.generic_end(begin, len(self.code))
                begin = self.skip(generic_end)
            opening = self.next_boundary(begin, len(self.code), '{;')
            if opening not in self.pairs or self.code[opening] != '{':
                continue
            self.boundaries[opening] = 'type'
            self.impl_headers[opening] = (begin, opening)
            if generic_end > generic_start:
                self.generic_impls.add(opening)
                self.type_parameters(generic_start, generic_end, opening)

    def module_scope(self, scope):
        while scope >= 0 and self.boundaries.get(scope) != 'module':
            scope = self.parents[scope]
        return scope

    def lookup_namespace(self, name, scope):
        while True:
            key = (scope, name.removeprefix('r#'))
            if key in self.namespaces:
                return self.namespaces[key]
            if scope in self.glob_imports or scope < 0 or self.boundaries.get(scope) == 'module':
                return None
            scope = self.parents[scope]

    def namespace_path(self, parts, pos):
        if not parts or not parts[0] or parts[0] == 'crate':
            # The selected file may itself be an external module. Its text
            # does not establish crate-root or extern-prelude identities.
            return None
        scope = self.scope_at(pos)
        first, *rest = parts
        if first == 'Self':
            owner = scope
            while owner >= 0 and self.boundaries.get(owner) != 'type':
                owner = self.parents[owner]
            namespace = self.impl_owners.get(owner)
        elif first in {'self', 'super'}:
            module = self.module_scope(scope)
            if first == 'super':
                if module < 0:
                    return None
                module = self.module_scope(self.parents[module])
            while rest and rest[0] == 'super':
                if module < 0:
                    return None
                module = self.module_scope(self.parents[module])
                rest.pop(0)
            namespace = Namespace('module', module)
        else:
            namespace = self.lookup_namespace(first, scope)
        for name in rest:
            if namespace is None or namespace.kind != 'module':
                return None
            namespace = self.namespaces.get((namespace.site, name.removeprefix('r#')))
        return namespace

    def path(self, start, end):
        """Consume a complete path, including opaque UFCS/turbofish owners.

        Never reinterpret a trailing qualified method as a free function when
        its owner requires type inference that this front end does not perform.
        """
        pos = start
        opaque = False
        prefix = ''
        if self.code.startswith('::', pos):
            opaque, prefix = True, '::'
            pos = self.skip(pos + 2, end)
        elif self.code[pos:pos + 1] == '<':
            if self.code.startswith('<=', pos):
                return None
            closing = self.skip(self.generic_end(pos, end), end)
            if not self.code.startswith('::', closing):
                return None
            opaque, prefix = True, '<qualified>::'
            pos = self.skip(closing + 2, end)
        token = _PATH.match(self.code, pos, end)
        if token is None:
            return None
        name = prefix + re.sub(r'\s+', '', token.group()).replace('r#', '')
        pos = token.end()
        while self.code.startswith('::', self.skip(pos, end)):
            opening = self.skip(self.skip(pos, end) + 2, end)
            if self.code[opening:opening + 1] != '<':
                break
            pos = self.skip(self.generic_end(opening, end), end)
            if not self.code.startswith('::', pos):
                break
            opaque = True
            token = _PATH.match(self.code, self.skip(pos + 2, end), end)
            if token is None:
                return name, end, True
            name += '::' + re.sub(r'\s+', '', token.group()).replace('r#', '')
            pos = token.end()
        return name, pos, opaque

    def resolve(self, name, pos, state):
        if '.' in name:
            return None
        if '::' in name:
            *owners, leaf = name.split('::')
            namespace = self.namespace_path(owners, pos)
            if namespace is None:
                return None
            if namespace.kind == 'module':
                return self.symbols.get((namespace.site, leaf))
            target = self.associated.get((namespace.site, leaf))
            return target if target is not None and self.visible_from(target, pos) else None
        if name in state.values:
            return None
        scope = self.scope_at(pos)
        while True:
            if self.boundaries.get(scope) != 'type' and (scope, name) in self.symbols:
                return self.symbols[(scope, name)]
            if (name in self.imported_names[scope] or scope in self.glob_imports
                    or scope < 0 or self.boundaries.get(scope) == 'module'):
                return None
            scope = self.parents[scope]

    def visible_from(self, function, pos):
        if function.public:
            return True
        target = self.module_scope(function.scope)
        scope = self.module_scope(self.scope_at(pos))
        while True:
            if scope == target:
                return True
            if scope < 0:
                return False
            scope = self.module_scope(self.parents[scope])

    def resolve_receiver(self, function, name):
        """A plain `self` receiver with the same exact inherent receiver type.

        Borrowing or dereferencing to a different receiver type can select a
        trait method before an inherent namesake. Without type inference,
        only identical value/shared/mutable forms prove this dispatch target.
        Cross-module visibility and receiver adjustments remain opaque here.
        """
        if (function is None or function.receiver is None or function.generic
                or function.scope in self.generic_impls):
            return None
        match = re.fullmatch(r'self\.([A-Za-z_]\w*)', name)
        owner = self.impl_owners.get(function.scope)
        if match is None or owner is None or owner.generic:
            return None
        target = self.associated.get((owner.site, match.group(1)))
        if (target is None or target.receiver != function.receiver or target.generic
                or target.scope in self.generic_impls
                or self.module_scope(target.scope) != self.module_scope(function.scope)):
            return None
        return target

    def solve(self):
        pending = deque(self.functions)
        queued = set(pending)
        while pending:
            self.budget.spend()
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
                for caller in sorted(self.callers[function], key=lambda f: f.start):
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
            src.budget.spend()
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
            item = re.match(r'(?:(?:pub(?:\([^)]*\))?|async|unsafe|const|extern)\s+)*(fn|mod|impl|trait|struct|enum|union|type|use)\b|extern\s+crate\b', src.code[pos:end])
            if item:
                boundary = src.next_boundary(pos, end, '{;')
                pos = src.pairs.get(boundary, boundary) + 1
                continue
            control = re.match(r'(if|while|for|loop|match)\b', src.code[pos:end])
            if control:
                if control.group() == 'if':
                    pos, normal, tail = self.branch(pos, end, state)
                elif control.group() == 'match':
                    pos, normal, tail = self.match(pos, end, state)
                else:
                    pos, normal, tail = self.loop(pos, end, state, control.group())
                state.replace(normal)
                if src.skip(pos, end) < end and src.code[src.skip(pos, end)] == ';':
                    tail = CLEAN
                continue
            if src.code[pos] == '{' and pos in src.pairs:
                normal, tail = self.block(pos + 1, src.pairs[pos], state)
                state.replace(normal)
                pos = src.pairs[pos] + 1
                if src.skip(pos, end) < end and src.code[src.skip(pos, end)] == ';':
                    tail = CLEAN
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
                          and (equal == begin or (equal > 0 and src.code[equal - 1] not in '=!<>')))
            if assignment:
                lhs_begin = begin + declaration.end() if declaration else begin
                lhs = src.code[lhs_begin:equal].strip()
                compound = lhs.endswith(('+', '-', '*', '/', '|', '&', '^'))
                if compound:
                    lhs = lhs[:-1].rstrip()
                colon = src.next_boundary(lhs_begin, equal, ':')
                if declaration:
                    lhs = src.code[lhs_begin:colon].strip()
                initializer, _ = src.trim(equal + 1, finish)
                # Skip complete initializer branches, including infix if
                # expressions, before looking for a statement-level let-else.
                otherwise = finish
                cursor = initializer
                while declaration and cursor < finish:
                    src.budget.spend()
                    if cursor in src.pairs:
                        cursor = src.pairs[cursor] + 1
                        continue
                    token = _IDENTIFIER.match(src.code, cursor)
                    if token is None:
                        cursor += 1
                    elif token.group() == 'if':
                        cursor = self.branch_end(cursor, finish)
                    elif token.group() == 'else':
                        otherwise = cursor
                        break
                    else:
                        cursor = token.end()
                value = self.expr(equal + 1, otherwise, state)
                if otherwise < finish and state.reachable:
                    opening = src.skip(otherwise + 4, finish)
                    if opening not in src.pairs or src.code[opening] != '{' or src.pairs[opening] >= finish:
                        raise ValueError('Malformed Rust let-else; redirect analysis is incomplete')
                    failed, _ = self.block(opening + 1, src.pairs[opening], state)
                    if failed is not None:
                        raise ValueError('Rust let-else must diverge; redirect analysis is incomplete')
                if state.reachable:
                    names = (src.pattern_names(lhs_begin, colon) if declaration else
                             [n.group().removeprefix('r#') for n in _IDENTIFIER.finditer(lhs)])
                    if declaration:
                        for name in names:
                            self.declare(name, value, state, shadows)
                            self.binding_contract(name, equal + 1, otherwise, state)
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
        opening = src.condition_opening(start + 2, end)
        if opening not in src.pairs or src.pairs[opening] > end:
            return end, state, self.expr(start + 2, end, state)
        close = src.pairs[opening]
        shadows = {name: self.snapshot(state, name) for name in src.condition_names(start + 2, opening)}
        first_exit = len(self.exits)
        yes, no = self.condition(start + 2, opening, state)
        left, left_value = self.block(opening + 1, close, yes) if yes is not None else (None, CLEAN)
        self.restore(left, shadows)
        self.restore(no, shadows)
        for exit in self.exits[first_exit:]:
            self.restore(exit.state, shadows)
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
        opening = src.condition_opening(start + 2, end)
        if opening not in src.pairs:
            return end
        pos = src.skip(src.pairs[opening] + 1, end)
        if re.match(r'else\b', src.code[pos:end]):
            pos = src.skip(pos + 4, end)
            if src.code.startswith('if', pos):
                return self.branch_end(pos, end)
            return src.pairs.get(pos, end - 1) + 1
        return pos

    def match(self, start, end, state):
        src = self.source
        opening = src.condition_opening(start + 5, end, skip_control_expressions=True)
        if opening not in src.pairs or src.pairs[opening] > end:
            raise ValueError('Malformed Rust match; redirect analysis is incomplete')
        close = src.pairs[opening]
        subject = self.expr(start + 5, opening, state)
        remaining = state.copy() if state.reachable else None
        completed, values = [], CLEAN
        pos = opening + 1
        while pos < close and remaining is not None:
            src.budget.spend()
            pos, _ = src.trim(pos, close)
            if pos == close:
                break
            if pos + 1 < close and src.code.startswith('#[', pos):
                pos = src.pairs[pos + 1] + 1
                continue
            arrow = pos
            while arrow < close:
                arrow = src.next_boundary(arrow, close, '=')
                if src.code.startswith('=>', arrow):
                    break
                arrow += 1
            if arrow >= close:
                raise ValueError('Rust match arm lacks =>; redirect analysis is incomplete')
            guard = src.keyword(pos, arrow, 'if')
            body, _ = src.trim(arrow + 2, close)
            finish = self.arm_end(body, close)
            case = remaining.copy()
            names = (*src.pattern_names(pos, guard), *src.condition_names(guard + 2, arrow))
            shadows = {name: self.snapshot(case, name) for name in names}
            for name in src.pattern_names(pos, guard):
                case.assign(name, subject)
            first_exit = len(self.exits)
            yes, no = self.condition(guard + 2, arrow, case) if guard < arrow else (case, None)
            if yes is not None:
                value = self.expr(body, finish, yes)
                if yes.reachable:
                    self.restore(yes, shadows)
                    completed.append(yes)
                    values = join(values, value)
            for exit in self.exits[first_exit:]:
                self.restore(exit.state, shadows)
            self.restore(no, shadows)
            # Only `_` is unambiguously total without resolving const/enum
            # names. Refutable patterns may fail before their guard is run.
            remaining = no if src.raw[pos:guard].strip() == '_' else join_states(remaining, no)
            pos = src.skip(finish, close)
            if pos < close and src.code[pos] == ',':
                pos += 1
            elif pos == body:
                raise ValueError('Empty Rust match arm; redirect analysis is incomplete')
        # Rust requires match exhaustiveness. Every normal continuation comes
        # from an arm; the scrutinee itself is not the match expression result.
        return close + 1, join_states(*completed), values

    def arm_end(self, start, end):
        """Block/control arms may omit their comma; scalar arms may not."""
        src = self.source
        stop = None
        if start in src.pairs and src.code[start] == '{':
            stop = src.pairs[start] + 1
        elif re.match(r'if\b', src.code[start:end]):
            stop = self.branch_end(start, end)
        elif re.match(r'(?:match|loop|while|for|unsafe)\b', src.code[start:end]):
            opening = src.condition_opening(start, end)
            if opening in src.pairs:
                stop = src.pairs[opening] + 1
        if stop is not None:
            following = src.skip(stop, end)
            if following == end or src.code[following] not in '.?+-*/&|^<>=':
                return stop
        return src.next_boundary(start, end, ',')

    def loop(self, start, end, state, kind):
        src = self.source
        iterator = src.keyword(start + 3, end, 'in') if kind == 'for' else None
        opening = (src.condition_opening(iterator + 2, end, skip_control_expressions=True) if iterator is not None else
                   src.condition_opening(start + len(kind), end))
        if opening not in src.pairs:
            return end, state, CLEAN
        close = src.pairs[opening]
        entry = state.copy()
        # Rust evaluates the iterator once, including when it yields no items.
        # Its effects precede both the zero-iteration path and every loop head.
        iterator_value = self.expr(iterator + 2, opening, entry) if kind == 'for' and iterator < opening else CLEAN
        if not entry.reachable:
            return close + 1, None, CLEAN
        head = entry.copy()
        completed = []
        values = CLEAN
        while True:
            src.budget.spend()
            shadows = {name: self.snapshot(head, name)
                       for name in src.condition_names(start + len(kind), opening)} if kind == 'while' else {}
            if kind == 'while':
                body, zero = self.condition(start + len(kind), opening, head.copy())
            else:
                body, zero = head.copy(), None if kind == 'loop' else head.copy()
            if zero is not None:
                self.restore(zero, shadows)
                completed.append(zero)
            first_exit = len(self.exits)
            if kind == 'for' and iterator < opening:
                for name in src.pattern_names(start + 3, iterator):
                    shadows[name] = self.snapshot(body, name)
                    body.assign(name, iterator_value)
            normal, _ = self.block(opening + 1, close, body) if body is not None else (None, CLEAN)
            exits = self.exits[first_exit:]
            del self.exits[first_exit:]
            self.restore(normal, shadows)
            for exit in exits:
                self.restore(exit.state, shadows)
            back = [normal]
            for exit in exits:
                if exit.kind == 'break':
                    completed.append(exit.state)
                    values = join(values, exit.value)
                elif exit.kind == 'continue':
                    back.append(exit.state)
                else:
                    self.exits.append(exit)
            # Retain previously reached loop heads as summaries become known.
            next_head = join_states(entry, head, *back)
            if next_head == head:
                break
            head = next_head
        return close + 1, join_states(*completed), values

    def condition(self, start, end, state):
        src = self.source
        src.budget.spend()
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
        if re.match(r'let\b', src.code[start:end]):
            equal = src.next_boundary(start + 3, end, '=')
            if equal >= end:
                raise ValueError('Rust let condition lacks initializer; redirect analysis is incomplete')
            value = self.expr(equal + 1, end, state)
            if not state.reachable:
                return None, None
            yes, no = state.copy(), state.copy()
            for name in src.pattern_names(start + 3, equal):
                yes.assign(name, value)
            return yes, no
        self.expr(start, end, state)
        if not state.reachable:
            return None, None
        code = src.code[start:end].strip()
        if code in {'true', 'false'}:
            return (state.copy(), None) if code == 'true' else (None, state.copy())
        yes, no = state.copy(), state.copy()
        raw = src.raw[start:end].strip()
        local = re.fullmatch(r'''([A-Za-z_]\w*)\s*\.\s*starts_with\s*\(\s*(["'])(/{1,2})\2\s*\)''', raw)
        if local:
            if local.group(3) == '/':
                yes.checked(local.group(1), 'local-slash')
            else:
                no.checked(local.group(1), 'not-network-path')
        # Browsers treat /\\host as a network path and remove embedded ASCII
        # tabs/newlines before URL parsing. Prefix checks alone are not proof.
        excluded = re.fullmatch(r'''([A-Za-z_]\w*)\s*\.\s*contains\s*\(\s*(["'])(\\\\|\\[tnr])\2\s*\)''', raw)
        if excluded:
            check = {r'\\': 'no-backslash', r'\t': 'no-tab',
                     r'\n': 'no-newline', r'\r': 'no-carriage-return'}[excluded.group(3)]
            no.checked(excluded.group(1), check)
        controls = re.fullmatch(
            r'([A-Za-z_]\w*)\s*\.\s*chars\s*\(\s*\)\s*\.\s*any\s*\(\s*'
            r'(?:std::primitive::)?char::is_control\s*\)', raw,
        )
        if controls:
            for check in ('no-tab', 'no-newline', 'no-carriage-return'):
                no.checked(controls.group(1), check)
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
        start, end = src.trim(start, end)
        raw = src.raw[start:end]
        if self.host_allowlist(raw):
            state.literals[name] = raw
        # Only successful parsing of this exact binding carries authority
        # back to it. An unwrap_or fallback, transformation, or later write
        # breaks that relationship and cannot validate the original target.
        match = re.match(r'(?:url::)?Url::parse\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)', raw)
        if match and match.group(1) != name:
            pos = src.skip(start + match.end(), end)
            # Consume exact balanced Result operations. A greedy suffix regex
            # also accepts unwrap().join(other).unwrap(), which checks a
            # transformed URL instead of the original redirect target.
            while pos < end:
                if src.code[pos] == '?':
                    pos = src.skip(pos + 1, end)
                    break
                operation = re.match(r'\.\s*(?:map_err|expect|unwrap)\b', src.code[pos:end])
                if operation is None:
                    return
                opening = src.skip(pos + operation.end(), end)
                if src.code[opening:opening + 1] != '(' or opening not in src.pairs:
                    return
                closing = src.pairs[opening]
                if closing >= end:
                    return
                pos = src.skip(closing + 1, end)
            if pos == end:
                state.parsed[name] = match.group(1)

    def expr(self, start, end, state):
        src = self.source
        src.budget.spend()
        start, end = src.trim(start, end)
        if start >= end or not state.reachable:
            return CLEAN
        exit_match = re.match(r'(return|break|continue)\b', src.code[start:end])
        if exit_match:
            value = self.expr(start + exit_match.end(), end, state)
            if state.reachable:
                self.exits.append(Exit(exit_match.group(), state.copy(), value))
            state.reachable = False
            return CLEAN
        if re.match(r'match\b', src.code[start:end]):
            _, normal, value = self.match(start, end, state)
            state.replace(normal)
            return value
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
            src.budget.spend()
            char = src.code[pos]
            if re.compile(r'if\b').match(src.code, pos, end):
                pos, normal, receiver = self.branch(pos, end, state)
                state.replace(normal)
                result = join(result, receiver)
                continue
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
            path = src.path(pos, end)
            if path is None:
                if char not in '.?&*' and not char.isspace():
                    receiver = CLEAN
                pos += 1
                continue
            name, path_end, opaque_path = path
            chained = pos > start and src.code[start:pos].rstrip().endswith('.')
            base = name.split('.')[0]
            value = receiver if chained else state.values.get(base, CLEAN)
            call = src.skip(path_end, end)
            macro = call < end and src.code[call] == '!'
            if macro:
                call = src.skip(call + 1, end)
            if call in src.pairs and src.code[call] in '([' and src.pairs[call] < end:
                close = src.pairs[call]
                spans = src.parts(call + 1, close)
                arguments = [self.expr(a, b, state) for a, b in spans]
                if not state.reachable:
                    return CLEAN
                catalogued = self.sink_target(name, spans, chained)
                local = (src.resolve(name, pos, state)
                         if not chained and not macro and not opaque_path
                         and not ('::' in name and catalogued is not None) else None)
                implicit_receiver = False
                if local is None and not chained and not macro and not opaque_path:
                    local = src.resolve_receiver(self.function, name)
                    implicit_receiver = local is not None
                if local is not None:
                    if self.function is not None:
                        src.callers[local].add(self.function)
                    summary = src.summaries[local]
                    actuals = ([state.values.get('self', CLEAN)] if implicit_receiver else []) + arguments
                    def substitute(fact):
                        return join(*(actuals[o.site] if o.kind == 'parameter' and o.site < len(actuals)
                                      else CLEAN if o.kind == 'parameter' else frozenset({o}) for o in fact))
                    value = substitute(summary.returned)
                    for site, fact in summary.sinks.items():
                        self.emit(site, substitute(fact))
                    if not summary.completes:
                        state.reachable = False
                elif name.endswith(('.starts_with', '.contains', '.is_empty')):
                    value = CLEAN
                else:
                    # Unknown helpers retain their arguments' taint. A name
                    # such as safe_redirect_url is not a sanitizer contract.
                    value = join(value, *arguments)
                raw_call = src.raw[pos:close + 1]
                direct = rules.source_re.match(raw_call)
                if direct and rules.has_request_source(src.raw[pos:self.chain_end(close + 1, end)]):
                    value = join(value, frozenset({Origin('source', pos, ' '.join(direct.group().split()))}))
                target = catalogued if local is None and name not in state.values and not opaque_path else None
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
                raw_name = src.raw[pos:path_end]
                direct = rules.source_re.fullmatch(raw_name)
                if direct:
                    value = join(value, frozenset({Origin('source', pos, ' '.join(direct.group().split()))}))
                receiver = value
                result = join(result, value)
                pos = path_end
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
