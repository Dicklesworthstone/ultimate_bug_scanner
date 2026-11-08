"""Swift resource obligations tied to lexical bindings and structured exits.

Assigned Foundation resources use the shared Swift lexer and a bounded set of
path states. Aliases refer to the acquired object, reassignment does not close
it, and deferred cleanup executes against the bindings at scope exit. Stored
properties can be discharged by a matching method of their own type. This is
a selected source analysis, not a Swift type checker or actor lifetime model.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.taint_flow import AnalysisLimit, Budget
from ubs_core.analyzers.taint_swift_traversal import (
    SwiftFunction, SwiftLexer, SwiftParser, SwiftStatement,
    swift_close, swift_parts, swift_text, swift_ungroup,
)

SKIP_DIRS = {".git", ".hg", ".svn", "build", "DerivedData", ".swiftpm", ".idea", "node_modules"}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# A publisher alone acquires no subscription. The sink token below activates
# analysis when a subscription is actually acquired; unrelated publish methods
# must not introduce a Foundation resource obligation.
ACQUISITION_NAMES = {'scheduledTimer', 'dataTask', 'uploadTask', 'downloadTask',
                     'addObserver', 'sink', 'makeTimerSource', 'makeFileSystemObjectSource',
                     'makeReadSource', 'makeWriteSource', 'CADisplayLink'}

ASSIGNED_RULES: tuple[tuple[str, str, re.Pattern[str], tuple[re.Pattern[str], ...]], ...] = (
    (
        "timer",
        "Timer is never invalidated",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*(?:try[!?]?\s*)?Timer\.scheduledTimer"),
        (re.compile(r"\.invalidate\s*\("),),
    ),
    (
        "urlsession_task",
        "URLSession task is never resumed or cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*(?:try[!?]?\s*)?[^=\n;]*\.(?:dataTask|uploadTask|downloadTask)\s*\("),
        (re.compile(r"\.(?:resume|cancel)\s*\("),),
    ),
    (
        "notification_token",
        "NotificationCenter observer token is never removed",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*NotificationCenter\.default\.addObserver\s*\("),
        (re.compile(r"NotificationCenter\.default\.removeObserver\s*\("), re.compile(r"\.removeObserver\s*\(")),
    ),
    (
        "combine_sink",
        "Combine sink result is neither stored nor cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*.*?\.sink\s*\(", re.MULTILINE),
        (re.compile(r"\.store\s*\(\s*in:\s*&"), re.compile(r"\.cancel\s*\(")),
    ),
    (
        "dispatch_source",
        "DispatchSource is never resumed or cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*DispatchSource\.(?:makeTimerSource|makeFileSystemObjectSource|makeReadSource|makeWriteSource)\s*\("),
        (re.compile(r"\.(?:resume|cancel)\s*\("),),
    ),
    (
        "cadisplaylink",
        "CADisplayLink is never invalidated",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*CADisplayLink\s*\("),
        (re.compile(r"\.invalidate\s*\("),),
    ),
)

KVO_RULE = (
    "kvo_observer",
    "KVO observer is added without a matching removeObserver",
    re.compile(r"\baddObserver\s*\([^)]*forKeyPath:"),
    re.compile(r"\bremoveObserver\s*\([^)]*forKeyPath:"),
)

SWIFTISH_SUFFIXES = {".swift", ".m", ".mm"}

_SEVERITY = {
    "timer": "warning",
    "urlsession_task": "warning",
    "notification_token": "warning",
    "combine_sink": "warning",
    "dispatch_source": "warning",
    "cadisplaylink": "warning",
    "kvo_observer": "warning",
    "analysis-limited": "warning",
}


def iter_swiftish_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in SWIFTISH_SUFFIXES:
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SWIFTISH_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    result: list[str] = []
    i = 0
    n = len(text)
    in_line = False
    in_block = False
    in_string = False
    escaped = False
    quote = ""

    def mask_char(ch: str) -> str:
        return "\n" if ch == "\n" else " "

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line:
            result.append(mask_char(ch))
            if ch == "\n":
                in_line = False
            i += 1
            continue

        if in_block:
            result.append(mask_char(ch))
            if ch == "*" and nxt == "/":
                result.append(" ")
                in_block = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            result.append(mask_char(ch))
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            result.extend("  ")
            in_line = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            result.extend("  ")
            in_block = True
            i += 2
            continue

        if ch == '"':
            result.append(mask_char(ch))
            in_string = True
            quote = ch
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    col = pos + 1 if last_newline == -1 else pos - last_newline
    return line, col


def rel_to(base: Path, path: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


class LifecycleParser(SwiftParser):
    """Retain stored properties and cleanup scopes omitted by the taint parser."""

    def __init__(self, text):
        self.fields = {}
        self.field_scopes = {}
        self.limitations = []
        super().__init__(text)

    def switch(self, part, owner, scope, depth):
        opening = next((i for i, token in enumerate(part) if token.value == '{'), -1)
        if opening < 0 or swift_close(part, opening) != len(part) - 1:
            raise ValueError('Swift lifecycle malformed switch; analysis is incomplete')
        cursor, limit, arms, exhaustive = opening + 1, len(part) - 1, [], False
        while cursor < limit:
            while cursor < limit and part[cursor].value == '\n':
                cursor += 1
            if cursor == limit:
                break
            if tuple(t.value for t in part[cursor:cursor + 2]) == ('@', 'unknown'):
                cursor += 2
                if cursor == limit or part[cursor].value != 'default':
                    raise ValueError('Swift lifecycle switch attribute needs analysis; analysis is incomplete')
            kind = part[cursor].value
            if kind not in {'case', 'default'}:
                raise ValueError('Swift lifecycle malformed switch arm; analysis is incomplete')
            end = cursor + 1
            while end < limit and part[end].value != ':':
                if part[end].kind == 'code' and part[end].value in {'where', '[', '{', '=', 'is', 'as'}:
                    self.limitations.append((part[end].start,
                        'switch pattern matching is approximated; every case remains reachable'))
                if part[end].kind == 'code' and part[end].value in {'(', '[', '{'}:
                    end = swift_close(part, end)
                end += 1
            pattern = tuple(part[cursor + 1:end])
            if end == limit or (kind == 'default' and end != cursor + 1):
                raise ValueError('Swift lifecycle malformed switch label; analysis is incomplete')
            exhaustive |= kind == 'default'
            start = end + 1
            end = start
            while end < limit:
                token = part[end]
                if token.kind == 'code' and token.value in {'case', 'default', '@'}:
                    break
                if token.kind == 'code' and token.value in {'(', '[', '{'}:
                    end = swift_close(part, end)
                end += 1
            body_tokens = part[start:end]
            if any(t.kind == 'code' and t.value == 'fallthrough' for t in body_tokens):
                self.limitations.append((part[start].start,
                    'switch fallthrough may bypass cleanup; resource obligations are retained'))
            for index, token in enumerate(body_tokens[:-1]):
                if token.kind == 'code' and token.value == 'break' and body_tokens[index + 1].value not in {'\n', ';', '}'}:
                    self.limitations.append((token.start,
                        'labeled break may bypass cleanup; resource obligations are retained'))
            body = self.block(body_tokens, owner, scope, depth=depth + 1)
            arms.append(SwiftStatement('case', pattern, body))
            cursor = end
        if not arms:
            raise ValueError('Swift lifecycle empty switch; analysis is incomplete')
        if not exhaustive:
            # Without a type checker, enum exhaustiveness is not established.
            arms.append(SwiftStatement('case', (), ()))
        return SwiftStatement('switch', part[1:opening], extra=tuple(arms))

    def block(self, tokens, owner, scope, declarations=False, depth=0):
        if declarations and owner:
            # Local types with the same spelling belong to different lexical
            # declarations. Their cleanup methods must not discharge each
            # other's fields, including types discovered inside callbacks.
            if scope and tokens:
                owner = (*owner[:-1], f'{owner[-1]}@{tokens[0].start}')
            self.field_scopes[owner] = scope
        statements = super().block(tokens, owner, scope, declarations=False, depth=depth)
        result = []
        for statement in statements:
            part = tuple(statement.tokens)
            while part and part[0].value == '\n':
                part = part[1:]
            while part and part[-1].value == '\n':
                part = part[:-1]
            if not part:
                result.append(statement)
                continue
            if statement.kind == 'simple':
                while part and part[0].value in {'private', 'fileprivate', 'internal', 'public', 'lazy', 'static', 'final'}:
                    part = part[1:]
                statement = replace(statement, tokens=part)
            first = part[0].value
            if statement.kind == 'unsupported' and first == 'switch':
                statement = self.switch(part, owner, scope, depth)
            elif statement.kind == 'unsupported' and first in {'defer', 'do'}:
                opening = next((i for i, token in enumerate(part) if token.value == '{'), -1)
                if opening < 0:
                    raise ValueError('Swift lifecycle catch or malformed cleanup scope; analysis is incomplete')
                finish = swift_close(part, opening)
                body = self.block(part[opening + 1:finish], owner, scope, depth=depth + 1)
                cursor, catches = finish + 1, []
                while cursor < len(part):
                    if part[cursor].value == '\n':
                        cursor += 1
                        continue
                    if first != 'do' or part[cursor].value != 'catch':
                        raise ValueError('Swift lifecycle malformed cleanup scope; analysis is incomplete')
                    start = cursor + 1
                    cursor = start
                    while cursor < len(part) and part[cursor].value != '{':
                        if part[cursor].value in {'(', '['}:
                            cursor = swift_close(part, cursor)
                        cursor += 1
                    if cursor == len(part):
                        raise ValueError('Swift lifecycle catch has no body; analysis is incomplete')
                    finish = swift_close(part, cursor)
                    catches.append(SwiftStatement('catch', part[start:cursor],
                        self.block(part[cursor + 1:finish], owner, scope, depth=depth + 1)))
                    cursor = finish + 1
                statement = SwiftStatement(first, part[:opening], body, extra=tuple(catches))
            elif statement.kind == 'simple' and first in {'init', 'deinit'}:
                opening = next((i for i, token in enumerate(part) if token.value == '{'), -1)
                if opening >= 0:
                    finish, key = swift_close(part, opening), part[0].start
                    function = SwiftFunction(key, first, owner, scope, ())
                    self.functions[key] = function
                    function.body = self.block(part[opening + 1:finish], owner, (*scope, key), depth=depth + 1)
                    statement = SwiftStatement('definition', part, extra=(key,))
            result.append(statement)
        if declarations and owner:
            fields = self.fields.setdefault(owner, [])
            seen = {statement.tokens[0].start for statement in fields if statement.tokens}
            fields.extend(statement for statement in result if statement.kind != 'definition'
                          and statement.tokens and statement.tokens[0].start not in seen)
        return tuple(result)


@dataclass
class LifecycleState:
    values: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    filters: dict = field(default_factory=dict)
    active: set = field(default_factory=set)
    repeated: set = field(default_factory=set)
    returned: set = field(default_factory=set)

    def copy(self):
        return LifecycleState(values=dict(self.values), constants=dict(self.constants),
                              filters=dict(self.filters), active=set(self.active), repeated=set(self.repeated),
                              returned=set(self.returned))

    def key(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.constants.items())),
                tuple(sorted(self.filters.items())), tuple(sorted(self.active)), tuple(sorted(self.repeated)),
                tuple(sorted(self.returned)))


@dataclass(frozen=True)
class LifecycleClosure:
    """Lexical bindings plus value snapshots for explicit capture-list entries."""

    key: int
    body: tuple
    parameters: tuple
    names: tuple
    captures: tuple
    owner: tuple


class LifecycleEngine:
    RELEASES = {
        'timer': {'invalidate'}, 'cadisplaylink': {'invalidate'},
        'urlsession_task': {'resume', 'cancel'}, 'dispatch_source': {'resume', 'cancel'},
        'combine_sink': {'store', 'cancel'},
    }

    def __init__(self, text):
        self.text, self.parser = text, LifecycleParser(text)
        self.budget = Budget()
        self.resources, self.leaked, self.property_resources = {}, set(), set()
        self.optional_cleanup = set()
        self.assigned_fields = set()
        self.owner, self.function = (), -1
        self.limitations = dict(self.parser.limitations)
        self.executing_closures = set()
        self.mutable_bindings = set()
        self.asynchronous_writes = set()
        self.closure_writes = []
        self.closure_bindings = {}

    def limited(self, offset, reason):
        self.limitations.setdefault(offset, reason)

    @staticmethod
    def merge_states(target, states):
        """Keep may-live obligations and only constants shared by every exit."""
        if not states:
            return
        target.active = set().union(*(state.active for state in states))
        target.repeated = set().union(*(state.repeated for state in states))
        for key in set().union(*(state.values.keys() for state in states)):
            target.values[key] = tuple(sorted(set().union(*(state.values.get(key, ()) for state in states))))
        target.constants = {key: value for key, value in states[0].constants.items()
                            if all(state.constants.get(key) == value for state in states[1:])}
        target.filters = {}
        for resource in set().union(*(state.filters.keys() for state in states)):
            registrations = [state.filters.get(resource, (('unknown',), ('unknown',)))
                             for state in states if resource in state.filters or resource in state.active]
            target.filters[resource] = tuple(
                value if all(registration[index] == value for registration in registrations[1:]) else ('unknown',)
                for index, value in enumerate(registrations[0]))

    def closure(self, tokens, state, environment):
        """Parse a closure signature without treating its body as caller code."""
        # Expression normalization removes newlines, but those newlines still
        # separate statements in a closure's own control-flow scope.
        inner = tuple(SwiftLexer(self.text).scan(tokens[0].end, tokens[-1].start))
        cursor, in_index = 0, None
        # A signature ends at a top-level `in`. A `for ... in` statement in
        # a signature-less body is not a signature, nor is a nested closure.
        body_heads = {'let', 'var', 'guard', 'if', 'for', 'while', 'repeat', 'do',
                      'defer', 'switch', 'return', 'throw', 'try', 'await'}
        while cursor < len(inner):
            token = inner[cursor]
            if token.kind != 'code' or token.value in body_heads or token.value in {'{', ';'}:
                break
            if token.value == 'in':
                in_index = cursor
                break
            if token.value in {'(', '['}:
                cursor = swift_close(inner, cursor)
            cursor += 1
        header = tuple(t for t in inner[:in_index] if t.value != '\n') if in_index is not None else ()
        body_tokens = inner[in_index + 1:] if in_index is not None else inner
        names, captures, parameters = dict(environment), [], []
        cursor = 0
        while cursor < len(header):
            if header[cursor].value == '@':
                cursor += 2
                if cursor < len(header) and header[cursor].value == '(':
                    cursor = swift_close(header, cursor) + 1
                continue
            if header[cursor].value != '[':
                break
            end = swift_close(header, cursor)
            for part in swift_parts(header[cursor + 1:end], {','}):
                part = tuple(part)
                if part and part[0].value in {'weak', 'unowned'}:
                    part = part[1:]
                    if part and part[0].value == '(':
                        part = part[swift_close(part, 0) + 1:]
                pieces = swift_parts(part, {'='})
                if len(pieces) not in {1, 2} or len(pieces[0]) != 1 or not re.fullmatch(IDENT, pieces[0][0].value):
                    self.limited(tokens[0].start, 'closure capture pattern is unknown; captured resources remain live')
                    continue
                name = pieces[0][0].value
                expression = pieces[1] if len(pieces) == 2 else pieces[0]
                self.release_calls(expression, state, environment)
                # Capture initializers execute when the closure is created,
                # even if no caller ever invokes its body.
                acquired = self.acquire(SwiftStatement('simple', tuple(expression)),
                                        expression, name, state, environment)
                key = ('capture', tokens[0].start, name)
                captures.append((key, self.value(expression, state, environment) if acquired is None else acquired,
                                 self.constant(expression, state, environment)))
                names[name] = key
            cursor = end + 1
        signature = header[cursor:]
        if signature:
            # Return types and effects do not introduce parameter bindings.
            signature = swift_parts(signature, {'->'})[0]
            while signature and signature[-1].value in {'async', 'throws', 'rethrows'}:
                signature = signature[:-1]
            signature = swift_ungroup(signature)
            for part in swift_parts(signature, {','}):
                if not part:
                    continue
                label = swift_parts(part, {':'})[0]
                candidates = [token.value for token in label if re.fullmatch(IDENT, token.value)]
                if not candidates:
                    self.limited(tokens[0].start, 'closure parameter pattern is unknown; outer bindings are not released')
                    continue
                parameters.append(candidates[-1])
        elif in_index is None:
            parameters = ['$' + str(index) for index in range(10)]
        body = self.parser.block(body_tokens, self.owner, (self.function, tokens[0].start))
        if len(body) == 1 and body[0].kind == 'simple' and not self.parser.assignment(body[0].tokens):
            body = (replace(body[0], kind='return'),)
        return LifecycleClosure(tokens[0].start, body, tuple(parameters),
                                tuple(sorted(names.items())), tuple(captures), self.owner)

    def call_closure(self, closure, state, arguments=(), *, optional=True, exceptions=None):
        """Analyze callback-local acquisitions without assuming it will run.

        Escaping callbacks may never run, so their cleanup cannot discharge
        the caller's obligations. A direct call can do so, but only on every
        possible exit. Explicit captures retain their values at creation;
        implicit captures resolve their lexical binding at the invocation.
        """
        if closure.key in self.executing_closures:
            self.limited(closure.key, 'recursive closure effects are unknown; resources remain live')
            self.leaked.update(state.active)
            return ()
        initial, names = state.copy(), dict(closure.names)
        initial.returned.clear()
        if optional:
            # An implicit var capture is a shared binding. Its creation-time
            # constant cannot establish how a delayed callback will observe it.
            for key in names.values():
                if key in self.mutable_bindings:
                    initial.constants.pop(key, None)
        for key, value, constant in closure.captures:
            initial.values[key] = value
            if constant is not None:
                initial.constants[key] = constant
            else:
                initial.constants.pop(key, None)
        for index, name in enumerate(closure.parameters):
            key = ('closure-parameter', closure.key, name)
            names[name] = key
            initial.values[key] = arguments[index] if index < len(arguments) else ()
            initial.constants.pop(key, None)
        parent_owner = self.owner
        self.executing_closures.add(closure.key)
        writes = set()
        self.closure_writes.append(writes)
        try:
            self.owner = closure.owner
            outcomes = self.block(closure.body, initial, names, len(self.executing_closures))
        finally:
            self.owner = parent_owner
            self.executing_closures.remove(closure.key)
            self.closure_writes.pop()
        if optional:
            # Include the zero-execution path, and allow later execution after
            # a subsequent assignment in the caller. No scheduling guarantee
            # is inferred from passing or storing the callback.
            self.asynchronous_writes.update(writes)
            for key in writes:
                state.constants.pop(key, None)
            for after, _ in outcomes:
                self.optional_cleanup.update(initial.active - after.active)
                self.leaked.update((after.active | after.repeated) - initial.active)
                if after.returned:
                    self.limited(closure.key,
                        'escaping callback returns a resource to an unknown owner; its obligation remains live')
                    self.leaked.update(after.returned - initial.active)
                # A callback may overwrite an enclosing alias before caller
                # cleanup. Preserve the abandoned object's obligation.
                for key in state.values:
                    if after.values.get(key, ()) != state.values[key]:
                        self.leaked.update(set(state.values[key]) & after.active)
            return ()
        normal = [after for after, outcome in outcomes if outcome != 'throw']
        returned = set().union(*(after.returned for after in normal))
        if exceptions is not None:
            exceptions.extend(after for after, outcome in outcomes if outcome == 'throw')
        self.merge_states(state, normal or [after for after, _ in outcomes])
        state.active.update(returned)
        return tuple(sorted(returned))

    def binding(self, tokens, environment):
        tokens = swift_ungroup(tokens)
        while tokens and tokens[-1].value in {'?', '!'}:
            tokens = tokens[:-1]
        name = swift_text(tokens)
        if name.startswith('self.'):
            return ('field', self.owner, name[5:])
        return environment.get(name)

    def value(self, tokens, state, environment):
        if len(tokens) == 1 and tokens[0].kind != 'code':
            return ()
        tokens = swift_ungroup(tokens)
        while tokens and tokens[0].value in {'try', 'await', '&'}:
            tokens = tokens[1:]
            if tokens and tokens[0].value in {'?', '!'}:
                tokens = tokens[1:]
        binding = self.binding(tokens, environment)
        if binding is not None:
            return state.values.get(binding, ())
        if tokens:
            result = state.values.get(('call', tokens[0].start, tokens[-1].end))
            if result is not None:
                return result
        if tokens and tokens[0].value == '[' and swift_close(tokens, 0) == len(tokens) - 1:
            members = swift_parts(tokens[1:-1], {',', ':'})
            if any(self.value(member, state, environment) for member in members):
                self.limited(tokens[0].start, 'resource collection ownership is unknown; member obligations remain live')
            return ()
        pieces = swift_parts(tokens, {','})
        if len(pieces) > 1 and any(self.value(piece, state, environment) for piece in pieces):
            self.limited(tokens[0].start, 'resource tuple ownership is unknown; member obligations remain live')
        return ()

    def compact(self, outcomes):
        result = {}
        for state, control in outcomes:
            self.budget.spend()
            result.setdefault((state.key(), control), (state, control))
        if len(result) > 256:
            raise AnalysisLimit('Swift lifecycle path-state limit exceeded; analysis is incomplete')
        return list(result.values())

    def constant(self, tokens, state, environment):
        if len(tokens) == 1 and tokens[0].kind == 'literal':
            return ('literal', tokens[0].value)
        tokens = swift_ungroup(tokens)
        if len(tokens) == 1 and tokens[0].value in {'true', 'false', 'nil'}:
            return tokens[0].value
        binding = self.binding(tokens, environment)
        return state.constants.get(binding)

    @staticmethod
    def named_arguments(tokens):
        arguments = {}
        for part in swift_parts(tokens, {','}):
            pieces = swift_parts(part, {':'})
            if len(pieces) == 2:
                arguments[swift_text(swift_ungroup(pieces[0]))] = swift_ungroup(pieces[1])
        return arguments

    def observer_filter(self, tokens, state, environment):
        if not tokens or swift_text(tokens) == 'nil':
            return ('nil',)
        if len(tokens) == 1 and tokens[0].kind == 'literal':
            return ('literal', tokens[0].value)
        raw = swift_text(tokens)
        if (raw.startswith('Notification.Name(') or raw.startswith('NotificationName(')) and len(tokens) >= 4:
            literals = [token.value for token in tokens if token.kind == 'literal']
            if len(literals) == 1:
                return ('literal', literals[0])
        constant = self.constant(tokens, state, environment)
        return constant if isinstance(constant, tuple) and constant[0] == 'literal' else ('unknown',)

    def acquire(self, statement, rhs, name, state, environment):
        # Reuse the public acquisition inventory, but bind its result to the
        # actual assignment, including typed and post-declaration assignments.
        masked = ''
        # Preserve source positions while excluding comments and literal text.
        if rhs:
            raw = [' '] * (rhs[-1].end - rhs[0].start)
            cursor = 0
            while cursor < len(rhs):
                token = rhs[cursor]
                if token.kind == 'code' and token.value == '{':
                    cursor = swift_close(rhs, cursor) + 1
                    continue
                if token.kind == 'code':
                    raw[token.start - rhs[0].start:token.end - rhs[0].start] = self.text[token.start:token.end]
                cursor += 1
            masked = ''.join(raw).replace('\n', ' ')
        probe = 'let __resource = ' + masked
        for kind, message, pattern, _ in ASSIGNED_RULES:
            if not pattern.match(probe):
                continue
            root = next((token.value for token in rhs if token.kind == 'code' and token.value not in {'try', '?', '!'}), '')
            if root in {'Timer', 'FileHandle', 'CADisplayLink', 'DispatchSource', 'NotificationCenter'} and (
                root in self.parser.types or root in environment
            ):
                self.limited(statement.tokens[0].start,
                    'acquisition receiver is shadowed; possible resource obligation is retained')
            opening = next((i for i, token in enumerate(rhs) if token.kind == 'code' and token.value == '('), -1)
            arguments = self.named_arguments(rhs[opening + 1:swift_close(rhs, opening)]) if opening >= 0 else {}
            if kind == 'timer' and self.constant(arguments.get('repeats', ()), state, environment) == 'false':
                # A nonrepeating Foundation timer invalidates itself.
                return ()
            resource = statement.tokens[0].start
            if resource in state.active:
                state.repeated.add(resource)
            self.resources[resource] = (kind, message, name)
            if kind == 'notification_token':
                state.filters[resource] = (
                    self.observer_filter(arguments.get('forName', ()), state, environment),
                    self.observer_filter(arguments.get('object', ()), state, environment),
                )
            state.active.add(resource)
            return (resource,)
        return None

    def release_calls(self, tokens, state, environment, exceptions=None, throwing=False):
        """Read receivers/operands and analyze closures at their own boundary."""
        if len(tokens) == 1 and tokens[0].kind != 'code':
            for part in tokens[0].parts:
                self.release_calls(part, state, environment, exceptions, throwing)
            return
        tokens, cursor = swift_ungroup(tokens), 0
        if not throwing:
            for index, token in enumerate(tokens):
                if token.kind != 'code' or token.value != 'try':
                    continue
                following = None
                if index + 1 < len(tokens):
                    following = tokens[index + 1].value
                if following not in {'?', '!'}:
                    throwing = True
                    break
        # Only the selected arm of a conditional expression executes. A
        # resource remains outstanding if either possible arm leaves it live.
        top, position = [], 0
        while position < len(tokens):
            if tokens[position].kind == 'code' and tokens[position].value in {'(', '[', '{'}:
                position = swift_close(tokens, position)
            else:
                top.append(position)
            position += 1
        questions = [i for i in top if tokens[i].value == '?' and (
            i + 1 < len(tokens) and tokens[i + 1].value != '.'
        )]
        if questions:
            question, nesting, colon = questions[0], 0, None
            for position in top:
                if position <= question:
                    continue
                if tokens[position].value == '?':
                    nesting += 1
                elif tokens[position].value == ':':
                    if not nesting:
                        colon = position
                        break
                    nesting -= 1
            if colon is not None:
                self.release_calls(tokens[:question], state, environment, exceptions, throwing)
                left, right = state.copy(), state.copy()
                self.release_calls(tokens[question + 1:colon], left, environment, exceptions, throwing)
                self.release_calls(tokens[colon + 1:], right, environment, exceptions, throwing)
                state.active = left.active | right.active
                state.repeated = left.repeated | right.repeated
                return
        logical = [i for i in top if tokens[i].value in {'&&', '||'}]
        if logical:
            first = logical[0]
            self.release_calls(tokens[:first], state, environment, exceptions, throwing)
            conditional = state.copy()
            self.release_calls(tokens[first + 1:], conditional, environment, exceptions, throwing)
            state.active.update(conditional.active)
            state.repeated.update(conditional.repeated)
            return
        while cursor < len(tokens):
            self.budget.spend()
            token = tokens[cursor]
            if token.kind != 'code':
                for part in token.parts:
                    self.release_calls(part, state, environment, exceptions, throwing)
                cursor += 1
                continue
            if token.value == '{':
                finish = swift_close(tokens, cursor)
                closure = self.closure(tokens[cursor:finish + 1], state, environment)
                cursor = finish + 1
                immediate = cursor < len(tokens) and tokens[cursor].value == '('
                arguments = ()
                if immediate:
                    end = swift_close(tokens, cursor)
                    arguments = tuple(self.value(arg, state, environment)
                                      for arg in swift_parts(tokens[cursor + 1:end], {','}))
                    self.release_calls(tokens[cursor + 1:end], state, environment, exceptions, throwing)
                    cursor = end + 1
                returned = self.call_closure(closure, state, arguments, optional=not immediate, exceptions=exceptions)
                if immediate:
                    state.values[('call', token.start, tokens[cursor - 1].end)] = returned
                continue
            if token.value != '(':
                cursor += 1
                continue
            finish = swift_close(tokens, cursor)
            grouped = swift_ungroup(tokens[cursor + 1:finish])
            if (grouped and grouped[0].value == '{' and swift_close(grouped, 0) == len(grouped) - 1
                    and finish + 1 < len(tokens) and tokens[finish + 1].value == '('):
                end = swift_close(tokens, finish + 1)
                arguments = tuple(self.value(arg, state, environment)
                                  for arg in swift_parts(tokens[finish + 2:end], {','}))
                self.release_calls(tokens[finish + 2:end], state, environment, exceptions, throwing)
                closure = self.closure(grouped, state, environment)
                returned = self.call_closure(closure, state, arguments, optional=False, exceptions=exceptions)
                state.values[('call', token.start, tokens[end].end)] = returned
                cursor = end + 1
                continue
            start = cursor - 1
            while start >= 0 and tokens[start].kind == 'code' and (
                re.fullmatch(rf'(?:{IDENT}|\$\d+)', tokens[start].value) or tokens[start].value in {'.', '?', '!'}
            ):
                start -= 1
            call = tuple(tokens[start + 1:cursor])
            name = swift_text(call).replace('?.', '.').replace('!.', '.')
            arguments = tuple(swift_ungroup(part) for part in swift_parts(tokens[cursor + 1:finish], {','}))
            self.release_calls(tokens[cursor + 1:finish], state, environment, exceptions, throwing)
            method = name.rsplit('.', 1)[-1]
            argument_count = sum(bool(argument) for argument in arguments)
            known_release = False
            if len(call) >= 3 and '.' in name:
                dot = max(i for i, item in enumerate(call) if item.value == '.')
                values = self.value(call[:dot], state, environment)
                # A merged callback exit can leave several possible aliases.
                # Calling one receiver cannot prove every object was released.
                if len(values) > 1:
                    values = ()
                for resource in values:
                    kind = self.resources[resource][0]
                    if method in self.RELEASES.get(kind, ()):
                        if ((method != 'store' and argument_count == 0) or
                                (method == 'store' and argument_count == 1 and swift_text(arguments[0]).startswith('in:&'))):
                            state.active.discard(resource)
                            known_release = True
            if name == 'NotificationCenter.default.removeObserver' and argument_count in {1, 3}:
                filters = self.named_arguments(tokens[cursor + 1:finish])
                values = self.value(arguments[0], state, environment)
                for resource in values if len(values) == 1 else ():
                    if self.resources[resource][0] == 'notification_token':
                        registration = state.filters[resource]
                        selected = tuple(self.observer_filter(filters.get(key, ()), state, environment)
                                         for key in ('name', 'object'))
                        if all(value == ('nil',) or (value != ('unknown',) and value == original)
                               for value, original in zip(selected, registration)):
                            state.active.discard(resource)
                        known_release = True
            called = self.binding(call, environment)
            constant = state.constants.get(called)
            if isinstance(constant, LifecycleClosure):
                values = tuple(self.value(arg, state, environment) for arg in arguments)
                returned = self.call_closure(constant, state, values, optional=False, exceptions=exceptions)
                state.values[('call', call[0].start, tokens[finish].end)] = returned
                known_release = True
            else:
                if called in self.closure_bindings:
                    self.limited(call[0].start,
                        'mutable callback target is uncertain; possible bodies are analyzed without assuming cleanup')
                    for candidate in tuple(self.closure_bindings[called].values()):
                        self.call_closure(candidate, state, optional=True)
                # Passing a stored closure may schedule it. Analyze its body,
                # but never infer that its cleanup is guaranteed to happen.
                for argument in arguments:
                    pieces = swift_parts(argument, {':'})
                    operand = pieces[1] if len(pieces) == 2 else argument
                    candidate = self.constant(operand, state, environment)
                    if isinstance(candidate, LifecycleClosure):
                        self.call_closure(candidate, state, optional=True)
                    else:
                        key = self.binding(operand, environment)
                        if key in self.closure_bindings:
                            self.limited(operand[0].start,
                                'mutable callback target is uncertain; possible bodies are analyzed without assuming cleanup')
                            for candidate in tuple(self.closure_bindings[key].values()):
                                self.call_closure(candidate, state, optional=True)
            if throwing and exceptions is not None and not known_release:
                exceptions.append(state.copy())
            cursor = finish + 1

    def simple(self, statement, state, environment, exceptions=None):
        assignment = self.parser.assignment(statement.tokens)
        if assignment:
            name, lhs, rhs, operator, declaration = assignment
            field_key = self.binding(lhs, environment)
            if not name and field_key is not None and field_key[:1] == ('field',):
                name = swift_text(lhs)
            if not name:
                # Heap transfer needs a model of its receiving owner. Keeping
                # this explicit prevents an arbitrary field write proving clean.
                if self.value(rhs, state, environment):
                    self.limited(lhs[0].start, 'resource transfer to an unknown owner cannot prove cleanup')
                if self.acquire(statement, rhs, swift_text(lhs), state, environment):
                    self.limited(lhs[0].start, 'resource field owner is unknown; its cleanup obligation is retained')
                callback = self.constant(rhs, state, environment)
                if isinstance(callback, LifecycleClosure):
                    self.call_closure(callback, state, optional=True)
                self.release_calls(rhs, state, environment, exceptions)
                return
            key = field_key or environment.get(name)
            if declaration:
                key = ('local', statement.tokens[0].start, name)
            elif key is None:
                key = ('global', name)
            if not declaration or statement.tokens[0].value == 'var':
                self.mutable_bindings.add(key)
            if not declaration:
                for writes in self.closure_writes:
                    writes.add(key)
            expression = swift_ungroup(rhs)
            closure = bool(expression and expression[0].value == '{' and swift_close(expression, 0) == len(expression) - 1)
            if not closure:
                self.release_calls(rhs, state, environment, exceptions)
            acquired = self.acquire(statement, rhs, name, state, environment)
            if acquired and key[:1] == ('field',) and self.function != -1:
                self.assigned_fields.update(acquired)
            value = self.value(rhs, state, environment) if acquired is None else acquired
            constant = self.closure(expression, state, environment) if closure else self.constant(rhs, state, environment)
            environment[name] = key
            state.values[key] = value
            if isinstance(constant, LifecycleClosure):
                self.closure_bindings.setdefault(key, {})[constant.key] = constant
            if constant is not None and key not in self.asynchronous_writes:
                state.constants[key] = constant
            else:
                state.constants.pop(key, None)
            if isinstance(constant, LifecycleClosure) and key[:1] == ('field',):
                self.call_closure(constant, state, optional=True)
        else:
            uninitialized = self.parser.uninitialized(statement.tokens)
            if uninitialized:
                key = ('local', uninitialized.start, uninitialized.value)
                environment[uninitialized.value] = key
                state.values[key] = ()
                if statement.tokens[0].value == 'var':
                    self.mutable_bindings.add(key)
            else:
                self.release_calls(statement.tokens, state, environment, exceptions)
                self.acquire(statement, statement.tokens, '<discarded>', state, environment)

    def block(self, statements, initial, environment, depth=0):
        if depth > 64:
            raise AnalysisLimit('Swift lifecycle scope limit exceeded; analysis is incomplete')
        # Each path retains the defers it actually reached. Their environment
        # resolves lexical names now; their values are read at scope exit.
        paths = [(initial.copy(), dict(environment), (), '')]
        for statement in statements:
            next_paths = []
            for state, names, deferred, control in paths:
                self.budget.spend()
                if control:
                    next_paths.append((state, names, deferred, control))
                    continue
                kind = statement.kind
                if kind == 'definition':
                    next_paths.append((state, names, deferred, ''))
                    continue
                if kind == 'defer':
                    next_paths.append((state, names, (*deferred, (statement.body, dict(names))), ''))
                    continue
                if kind == 'switch':
                    exceptions = []
                    self.release_calls(statement.tokens, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                    for arm in statement.extra:
                        arm_state, arm_names = state.copy(), dict(names)
                        binding_pattern = False
                        for index, token in enumerate(arm.tokens):
                            if token.kind == 'code' and token.value in {'let', 'var'}:
                                binding_pattern = True
                                continue
                            if (binding_pattern and token.kind == 'code' and re.fullmatch(IDENT, token.value)
                                    and token.value not in {'where', 'is', 'as', 'true', 'false', 'nil', '_'}
                                    and (not index or arm.tokens[index - 1].value != '.')):
                                bound_name = token.value
                                key = ('case', statement.tokens[0].start, bound_name)
                                arm_names[bound_name] = key
                                arm_state.values[key] = ()
                                arm_state.constants.pop(key, None)
                        for child, outcome in self.block(arm.body, arm_state, arm_names, depth + 1):
                            next_paths.append((child, dict(names), deferred, '' if outcome == 'break' else outcome))
                    continue
                if kind in {'if', 'guard'}:
                    exceptions = []
                    self.release_calls(statement.tokens, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                    arms = (statement.body, statement.alternate)
                    literal = swift_text(swift_ungroup(statement.tokens))
                    if literal in {'true', 'false'}:
                        branch = (literal == 'true') != (kind == 'guard')
                        arms = (statement.body if branch else statement.alternate,)
                    for arm in arms:
                        for child, outcome in self.block(arm, state, names, depth + 1):
                            if kind == 'guard' and arm is statement.body and not outcome:
                                self.limited(statement.tokens[0].start,
                                    'guard exit is opaque; cleanup before an unknown terminator is not assumed')
                                self.leaked.update(child.active)
                                outcome = 'return'
                            next_paths.append((child, dict(names), deferred, outcome))
                    continue
                if kind == 'do':
                    for child, outcome in self.block(statement.body, state, names, depth + 1):
                        if outcome != 'throw':
                            next_paths.append((child, dict(names), deferred, outcome))
                            continue
                        # Inner defers have already run. Matching is conservative:
                        # a typed/filtered catch may or may not match, and only an
                        # unconditional catch consumes the unmatched throw path.
                        exhaustive = False
                        for handler in statement.extra:
                            pattern = swift_ungroup(handler.tokens)
                            parts = swift_parts(pattern, {'where'})
                            if len(parts) > 2:
                                raise ValueError('Swift lifecycle catch pattern needs binding analysis; analysis is incomplete')
                            head = tuple(parts[0])
                            caught_names = dict(names)
                            bound = ['error']
                            binding_pattern = False
                            for index, token in enumerate(head):
                                if token.value in {'let', 'var'}:
                                    if index + 1 == len(head):
                                        raise ValueError('Swift lifecycle catch pattern needs binding analysis; analysis is incomplete')
                                    binding_pattern = True
                                    continue
                                if token.value in {'as', 'is'}:
                                    binding_pattern = False
                                following = head[index + 1].value if index + 1 < len(head) else ''
                                if (binding_pattern and token.kind == 'code' and re.fullmatch(IDENT, token.value)
                                        and token.value not in {'true', 'false', 'nil', '_'}
                                        and (not index or head[index - 1].value != '.')
                                        and following not in {'.', '(', ':'}):
                                    bound.append(token.value)
                            caught = child.copy()
                            for name in bound:
                                key = ('catch', statement.tokens[0].start, name)
                                caught_names[name] = key
                                caught.values[key] = ()
                                caught.constants.pop(key, None)
                            if len(parts) == 2:
                                exceptional_filters = []
                                self.release_calls(parts[1], caught, caught_names, exceptional_filters)
                                next_paths.extend((item, dict(names), deferred, 'throw') for item in exceptional_filters)
                            for handled, exit_kind in self.block(handler.body, caught, caught_names, depth + 1):
                                next_paths.append((handled, dict(names), deferred, exit_kind))
                            exhaustive = len(parts) == 1 and (not head or (
                                len(head) == 2 and head[0].value in {'let', 'var'} and re.fullmatch(IDENT, head[1].value)))
                            if exhaustive:
                                break
                        if not exhaustive:
                            next_paths.append((child, dict(names), deferred, 'throw'))
                    continue
                if kind in {'while', 'for'}:
                    exceptions = []
                    self.release_calls(statement.tokens, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                    always = kind == 'while' and swift_text(swift_ungroup(statement.tokens)) == 'true'
                    loop_names = dict(names)
                    if kind == 'for':
                        pieces = swift_parts(statement.tokens, {'in'})
                        pattern = tuple(token for token in pieces[0] if token.value != '\n')
                        while pattern and pattern[0].value in {'try', 'await'}:
                            pattern = pattern[1:]
                        try:
                            bindings = self.parser.iteration_names(pattern)
                        except AnalysisLimit:
                            raise
                        except ValueError as error:
                            if str(error) != 'Swift iteration binding needs pattern analysis; analysis is incomplete':
                                raise
                            self.limited(statement.tokens[0].start,
                                'loop pattern bindings are approximated; resource obligations remain live')
                            bindings = tuple(token for token in pattern if re.fullmatch(IDENT, token.value))
                        for token in bindings:
                            key = ('iteration', token.start, token.value)
                            loop_names[token.value] = key
                            state.values[key] = ()
                    pending, visited = [state.copy()], set()
                    while pending:
                        entry = pending.pop()
                        self.budget.spend()
                        key = entry.key()
                        if key in visited:
                            continue
                        visited.add(key)
                        if len(visited) > 256:
                            raise AnalysisLimit('Swift lifecycle loop-state limit exceeded; analysis is incomplete')
                        if not always:
                            next_paths.append((entry.copy(), dict(names), deferred, ''))
                        for child, outcome in self.block(statement.body, entry, loop_names, depth + 1):
                            if outcome in {'return', 'throw', 'break'}:
                                next_paths.append((child, dict(names), deferred, '' if outcome == 'break' else outcome))
                            else:
                                pending.append(child)
                    continue
                if kind in {'return', 'throw', 'break', 'continue'}:
                    exceptions = []
                    self.release_calls(statement.tokens, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                    if kind == 'return':
                        callback = self.constant(statement.tokens, state, names)
                        if isinstance(callback, LifecycleClosure):
                            self.call_closure(callback, state, optional=True)
                        acquired = self.acquire(statement, statement.tokens, '<return>', state, names)
                        returned = set(self.value(statement.tokens, state, names) if acquired is None else acquired)
                        state.returned.update(returned)
                        state.active.difference_update(returned - self.property_resources)
                    if kind in {'break', 'continue'} and statement.tokens:
                        self.limited(statement.tokens[0].start,
                            'labeled control transfer may bypass cleanup; resource obligations are retained')
                        self.leaked.update(state.active)
                    next_paths.append((state, names, deferred, kind))
                    continue
                if kind in {'unsupported', 'closure'}:
                    if kind == 'closure':
                        closure = self.closure(statement.tokens, state, names)
                        self.call_closure(closure, state, optional=True)
                    else:
                        first = statement.tokens[0]
                        self.limited(first.start, f'{first.value} control flow is approximated; resource obligations are retained')
                        self.leaked.update(state.active)
                        self.release_calls(statement.tokens, state.copy(), names)
                else:
                    exceptions = []
                    if statement.tokens and statement.tokens[0].value == 'fallthrough':
                        self.leaked.update(state.active)
                    self.simple(statement, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                next_paths.append((state, names, deferred, ''))
            unique_paths = {}
            for state, names, deferred, control in next_paths:
                key = (state.key(), tuple(sorted(names.items())),
                       tuple((body, tuple(sorted(captured.items()))) for body, captured in deferred), control)
                unique_paths.setdefault(key, (state, names, deferred, control))
            if len(unique_paths) > 256:
                raise AnalysisLimit('Swift lifecycle path-state limit exceeded; analysis is incomplete')
            paths = list(unique_paths.values())
        outcomes = []
        for state, names, deferred, control in paths:
            cleanup = [(state, control)]
            for body, captured in reversed(deferred):
                after = []
                for before, outcome in cleanup:
                    for cleaned, cleanup_exit in self.block(body, before, captured, depth + 1):
                        if cleanup_exit:
                            raise ValueError('Swift lifecycle defer transfers control; analysis is incomplete')
                        after.append((cleaned, outcome))
                cleanup = after
            outcomes.extend(cleanup)
        return self.compact(outcomes)

    def analyze(self):
        property_states, property_names, discharged = {}, {}, set()
        analyzed_functions = set()
        while True:
            # Parsing a callback discovers local functions and types lazily.
            # Initialize newly discovered fields before visiting their methods;
            # a dictionary snapshot alone would silently omit their resources.
            pending_owners = [owner for owner in self.parser.fields if owner not in property_states]
            if pending_owners:
                for owner in pending_owners:
                    self.budget.spend()
                    self.owner, self.function = owner, -1
                    names = {}
                    state = LifecycleState()
                    for statement in tuple(self.parser.fields[owner]):
                        assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                        if assignment and assignment[0]:
                            self.simple(statement, state, names)
                            name = assignment[0]
                            previous = names[name]
                            value = state.values.pop(previous)
                            constant = state.constants.pop(previous, None)
                            names[name] = ('field', owner, name)
                            state.values[names[name]] = value
                            if previous in self.mutable_bindings:
                                self.mutable_bindings.add(names[name])
                            if previous in self.asynchronous_writes:
                                self.asynchronous_writes.add(names[name])
                            if previous in self.closure_bindings:
                                self.closure_bindings[names[name]] = dict(self.closure_bindings[previous])
                            if constant is not None and names[name] not in self.asynchronous_writes:
                                state.constants[names[name]] = constant
                            if isinstance(constant, LifecycleClosure):
                                self.call_closure(constant, state, optional=True)
                        elif statement.kind == 'simple':
                            token = self.parser.uninitialized(statement.tokens)
                            if token is not None:
                                names[token.value] = ('field', owner, token.value)
                                state.values[names[token.value]] = ()
                                if statement.tokens[0].value == 'var':
                                    self.mutable_bindings.add(names[token.value])
                    property_states[owner], property_names[owner] = state, names
                    self.property_resources.update(state.active)
                continue
            function = next((item for key, item in self.parser.functions.items()
                             if key not in analyzed_functions), None)
            if function is None:
                break
            self.budget.spend()
            analyzed_functions.add(function.key)
            self.owner, self.function = function.owner, function.key
            initial = property_states.get(function.owner, LifecycleState()).copy()
            for key in tuple(initial.constants):
                if key in self.mutable_bindings:
                    initial.constants.pop(key, None)
            names = dict(property_names.get(function.owner, {}))
            for name, _, _, _ in function.parameters:
                names[name] = ('parameter', function.key, name)
            outcomes = self.block(function.body, initial, names)
            outstanding = set().union(*(state.active | state.repeated for state, _ in outcomes))
            self.leaked.update(outstanding - initial.active)
            if function.scope == self.parser.field_scopes.get(function.owner, ()):
                discharged.update(initial.active - outstanding)
        for state in property_states.values():
            self.leaked.update(state.active - discharged)
        self.limitations.update(self.parser.limitations)
        result = []
        for position in sorted(self.leaked):
            kind, message, name = self.resources[position]
            if position in self.optional_cleanup:
                message = 'Resource cleanup is not guaranteed: its escaping callback may never run'
            elif position in self.assigned_fields:
                self.limited(position,
                    'stored-property acquisition is tracked locally; cleanup in another method is not correlated')
                message = 'Resource stored by this method has no proven cleanup on this path'
            result.append((position, kind, message, name))
        return result


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, str, str, int, int]]:
    """Return (kind, message, rel, line, col) findings for one file's text."""
    code = strip_comments_and_strings(text)
    rel = str(rel_to(base, path))
    found: list[tuple[str, str, str, int, int]] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(pos: int, kind: str, message: str) -> None:
        line, col = line_col(text, pos)
        issue = (f"{rel}:{line}:{col}", kind, message)
        if issue not in seen:
            seen.add(issue)
            found.append((kind, message, rel, line, col))

    tokens = SwiftLexer(text).scan()
    analysis_text = text
    directives = [(index, token) for index, token in enumerate(tokens)
                  if token.kind == 'code' and token.value == '#'
                  and index + 1 < len(tokens) and tokens[index + 1].value in {'if', 'elseif', 'else', 'endif'}]
    significant = [token for token in tokens if token.value != '\n']
    if (len(directives) == 2 and significant
            and directives[0][1] == significant[0]
            and tokens[directives[0][0] + 1].value == 'if'
            and tokens[directives[1][0] + 1] == significant[-1]
            and significant[-1].value == 'endif'):
        # A whole-file conditional has exactly two possible programs: this
        # body, or an empty file. Analyze the body regardless of host SDK so
        # platform-specific leaks stay visible. Blank only the directives to
        # preserve original finding coordinates; other conditional shapes
        # remain unsupported rather than merging mutually exclusive cleanup.
        chars = list(text)
        for _, token in directives:
            end = text.find('\n', token.start)
            if end < 0:
                end = len(text)
            chars[token.start:end] = ' ' * (end - token.start)
        analysis_text = ''.join(chars)
    # Owning FileHandle URL/path initializers close their descriptor in deinit.
    # A borrowed raw descriptor needs origin/ownership analysis, not a blanket
    # missing-explicit-close warning on the wrapper object.
    if any(token.kind == 'code' and token.value in ACQUISITION_NAMES for token in tokens):
        engine = LifecycleEngine(analysis_text)
        for position, kind, message, name in engine.analyze():
            emit(position, kind, f"{message} ({name})")
        for position, reason in sorted(engine.limitations.items()):
            emit(position, 'analysis-limited', f"Swift lifecycle analysis is conservative: {reason}")

    kvo_kind, kvo_message, kvo_acquire, kvo_release = KVO_RULE
    if not kvo_release.search(code):
        for match in kvo_acquire.finditer(code):
            emit(match.start(), kvo_kind, kvo_message)

    return found


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_swiftish_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, message, rel, line, col in scan_text(path, text, base):
            issues.append((f"{rel}:{line}:{col}", kind, message))

    return issues


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_swift.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in SWIFTISH_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, message, rel, line, col in scan_text(path, text, cwd):
            finding = {
                "rule": f"swift.lifecycle.{kind}",
                "path": str(path.resolve()),
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "swift",
                "severity": _SEVERITY[kind],
                "message": message,
            }
            if kind == 'analysis-limited':
                finding['extras'] = {'analysis': 'conservative', 'construct': 'resource ownership',
                                     'reason': message}
            yield finding


def _selftest_timer_positive() -> None:
    code = (
        "class A {\n"
        "  // timer.invalidate() mentioned in a comment must not mask the leak\n"
        "  let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n"
        "  let leaky = Timer.publish(every: 2, on: .main, in: .common).autoconnect()\n"
        "}\n"
    )
    issues = scan_text(Path("A.swift"), code, Path("."))
    kinds = [kind for kind, _, _, _, _ in issues]
    # Timer.publish(...).autoconnect() does not start publishing until a
    # subscriber attaches. It has no Timer.invalidate() obligation itself.
    assert kinds == ["timer"], kinds
    assert "(timer)" in issues[0][1]
    assert issues[0][3] == 3, issues


def _selftest_invalidated_suppression() -> None:
    code = (
        "class A {\n"
        "  let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n"
        "  func stop() { timer.invalidate() }\n"
        "  let s = \"let fake = Timer.scheduledTimer(x)\"\n"
        "}\n"
    )
    assert scan_text(Path("A.swift"), code, Path(".")) == []


def _selftest_kvo_suppression() -> None:
    leaky = 'obj.addObserver(self, forKeyPath: "state", options: [], context: nil)\n'
    issues = scan_text(Path("A.swift"), leaky, Path("."))
    assert [kind for kind, _, _, _, _ in issues] == ["kvo_observer"], issues
    cleaned = leaky + 'func deinit2() { obj.removeObserver(self, forKeyPath: "state") }\n'
    assert scan_text(Path("A.swift"), cleaned, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_swift_") -> None:
    import tempfile

    code = (
        "import Foundation\n"
        "class A {\n"
        "  let handle = try FileHandle(forReadingFrom: url)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
        assert findings == [], findings
        target.write_text("import Foundation\nclass A {\n  let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n}\n", encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.lifecycle.timer"
    assert findings[0]["line"] == 3
    assert findings[0]["col"] == 3
    assert findings[0]["severity"] == "warning"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("timer_positive", _selftest_timer_positive),
    ("invalidated_suppression", _selftest_invalidated_suppression),
    ("kvo_suppression", _selftest_kvo_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="swift", name="lifecycle_swift", run=run, selftests=SELF_TESTS))
