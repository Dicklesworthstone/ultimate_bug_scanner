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
}


def iter_swiftish_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in SWIFTISH_SUFFIXES and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SWIFTISH_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
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
        super().__init__(text)

    def block(self, tokens, owner, scope, declarations=False, depth=0):
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
            if statement.kind == 'unsupported' and first in {'defer', 'do'}:
                opening = next((i for i, token in enumerate(part) if token.value == '{'), -1)
                if opening < 0 or swift_close(part, opening) != len(part) - 1:
                    raise ValueError('Swift lifecycle catch or malformed cleanup scope; analysis is incomplete')
                body = self.block(part[opening + 1:-1], owner, scope, depth=depth + 1)
                statement = SwiftStatement(first, part[:opening], body)
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
            self.fields.setdefault(owner, []).extend(s for s in result if s.kind != 'definition')
        return tuple(result)


@dataclass
class LifecycleState:
    values: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    filters: dict = field(default_factory=dict)
    active: set = field(default_factory=set)
    repeated: set = field(default_factory=set)

    def copy(self):
        return LifecycleState(values=dict(self.values), constants=dict(self.constants),
                              filters=dict(self.filters), active=set(self.active), repeated=set(self.repeated))

    def key(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.constants.items())),
                tuple(sorted(self.filters.items())), tuple(sorted(self.active)), tuple(sorted(self.repeated)))


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
        self.owner, self.function = (), -1

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
        if tokens and tokens[0].value == '[' and swift_close(tokens, 0) == len(tokens) - 1:
            members = swift_parts(tokens[1:-1], {',', ':'})
            if any(self.value(member, state, environment) for member in members):
                raise ValueError('Swift lifecycle resource collection needs member ownership analysis; analysis is incomplete')
            return ()
        pieces = swift_parts(tokens, {','})
        if len(pieces) > 1 and any(self.value(piece, state, environment) for piece in pieces):
            raise ValueError('Swift lifecycle resource tuple needs member ownership analysis; analysis is incomplete')
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
            for token in rhs:
                if token.kind == 'code':
                    raw[token.start - rhs[0].start:token.end - rhs[0].start] = self.text[token.start:token.end]
            masked = ''.join(raw).replace('\n', ' ')
        probe = 'let __resource = ' + masked
        for kind, message, pattern, _ in ASSIGNED_RULES:
            if not pattern.match(probe):
                continue
            root = next((token.value for token in rhs if token.kind == 'code' and token.value not in {'try', '?', '!'}), '')
            if root in {'Timer', 'FileHandle', 'CADisplayLink', 'DispatchSource', 'NotificationCenter'} and (
                root in self.parser.types or root in environment
            ):
                raise ValueError('Swift lifecycle acquisition receiver is shadowed; analysis is incomplete')
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
        """Read actual receivers/operands; never execute a callback body here."""
        if len(tokens) == 1 and tokens[0].kind != 'code':
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
                if any(self.value(part, state, environment) for part in token.parts):
                    raise ValueError('Swift lifecycle interpolation effects need call analysis; analysis is incomplete')
                cursor += 1
                continue
            if token.value == '{':
                finish = swift_close(tokens, cursor)
                captured = any(self.value((item,), state, environment) for item in tokens[cursor + 1:finish]
                               if item.kind == 'code' and re.fullmatch(IDENT, item.value))
                if captured:
                    raise ValueError('Swift lifecycle escaping callback captures a resource; analysis is incomplete')
                cursor = finish + 1
                continue
            if token.value != '(':
                cursor += 1
                continue
            finish = swift_close(tokens, cursor)
            start = cursor - 1
            while start >= 0 and tokens[start].kind == 'code' and (
                re.fullmatch(IDENT, tokens[start].value) or tokens[start].value in {'.', '?', '!'}
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
                for resource in values:
                    kind = self.resources[resource][0]
                    if method in self.RELEASES.get(kind, ()):
                        if ((method != 'store' and argument_count == 0) or
                                (method == 'store' and argument_count == 1 and swift_text(arguments[0]).startswith('in:&'))):
                            state.active.discard(resource)
                            known_release = True
            if name == 'NotificationCenter.default.removeObserver' and argument_count in {1, 3}:
                filters = self.named_arguments(tokens[cursor + 1:finish])
                for resource in self.value(arguments[0], state, environment):
                    if self.resources[resource][0] == 'notification_token':
                        registration = state.filters[resource]
                        selected = tuple(self.observer_filter(filters.get(key, ()), state, environment)
                                         for key in ('name', 'object'))
                        if all(value == ('nil',) or (value != ('unknown',) and value == original)
                               for value, original in zip(selected, registration)):
                            state.active.discard(resource)
                        known_release = True
            called = environment.get(name)
            constant = state.constants.get(called)
            if isinstance(constant, tuple) and constant[0] == 'closure':
                raise ValueError('Swift lifecycle local callback execution needs capture analysis; analysis is incomplete')
            if throwing and exceptions is not None and not known_release:
                exceptions.append(state.copy())
            cursor = finish + 1

    def simple(self, statement, state, environment, exceptions=None):
        assignment = self.parser.assignment(statement.tokens)
        if assignment:
            name, lhs, rhs, operator, declaration = assignment
            if not name:
                # Heap transfer needs a model of its receiving owner. Keeping
                # this explicit prevents an arbitrary field write proving clean.
                if self.value(rhs, state, environment):
                    raise ValueError('Swift lifecycle resource field transfer needs owner analysis; analysis is incomplete')
                if self.acquire(statement, rhs, swift_text(lhs), state.copy(), environment):
                    raise ValueError('Swift lifecycle resource field initialization needs owner analysis; analysis is incomplete')
                self.release_calls(rhs, state, environment, exceptions)
                return
            key = environment.get(name)
            if declaration:
                key = ('local', statement.tokens[0].start, name)
            elif key is None:
                key = ('global', name)
            expression = swift_ungroup(rhs)
            closure = bool(expression and expression[0].value == '{' and swift_close(expression, 0) == len(expression) - 1)
            if not closure:
                self.release_calls(rhs, state, environment, exceptions)
            acquired = self.acquire(statement, rhs, name, state, environment)
            value = self.value(rhs, state, environment) if acquired is None else acquired
            constant = ('closure', expression[0].start) if closure else self.constant(rhs, state, environment)
            environment[name] = key
            state.values[key] = value
            if constant is not None:
                state.constants[key] = constant
            else:
                state.constants.pop(key, None)
        else:
            uninitialized = self.parser.uninitialized(statement.tokens)
            if uninitialized:
                key = ('local', uninitialized.start, uninitialized.value)
                environment[uninitialized.value] = key
                state.values[key] = ()
            else:
                self.release_calls(statement.tokens, state, environment, exceptions)

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
                if kind in {'if', 'guard'}:
                    self.release_calls(statement.tokens, state, names)
                    arms = (statement.body, statement.alternate)
                    literal = swift_text(swift_ungroup(statement.tokens))
                    if literal in {'true', 'false'}:
                        branch = (literal == 'true') != (kind == 'guard')
                        arms = (statement.body if branch else statement.alternate,)
                    for arm in arms:
                        for child, outcome in self.block(arm, state, names, depth + 1):
                            if kind == 'guard' and arm is statement.body and not outcome:
                                raise ValueError('Swift lifecycle guard does not exit; analysis is incomplete')
                            next_paths.append((child, dict(names), deferred, outcome))
                    continue
                if kind == 'do':
                    for child, outcome in self.block(statement.body, state, names, depth + 1):
                        next_paths.append((child, dict(names), deferred, outcome))
                    continue
                if kind in {'while', 'for'}:
                    self.release_calls(statement.tokens, state, names)
                    always = kind == 'while' and swift_text(swift_ungroup(statement.tokens)) == 'true'
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
                        for child, outcome in self.block(statement.body, entry, names, depth + 1):
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
                        state.active.difference_update(set(self.value(statement.tokens, state, names)) - self.property_resources)
                    next_paths.append((state, names, deferred, kind))
                    continue
                if kind in {'unsupported', 'closure'}:
                    if state.active or any(pattern.search(self.text) for _, _, pattern, _ in ASSIGNED_RULES):
                        raise ValueError('Unsupported Swift lifecycle control flow; analysis is incomplete')
                else:
                    exceptions = []
                    self.simple(statement, state, names, exceptions)
                    next_paths.extend((exceptional, dict(names), deferred, 'throw') for exceptional in exceptions)
                next_paths.append((state, names, deferred, ''))
            if len(next_paths) > 256:
                raise AnalysisLimit('Swift lifecycle path-state limit exceeded; analysis is incomplete')
            paths = next_paths
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
        for owner, statements in self.parser.fields.items():
            self.owner = owner
            names = {}
            state = LifecycleState()
            for statement in statements:
                assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                if assignment and assignment[0]:
                    self.simple(statement, state, names)
                    name = assignment[0]
                    value = state.values.pop(names[name])
                    names[name] = ('field', owner, name)
                    state.values[names[name]] = value
            property_states[owner], property_names[owner] = state, names
            self.property_resources.update(state.active)
        for function in self.parser.functions.values():
            self.owner, self.function = function.owner, function.key
            initial = property_states.get(function.owner, LifecycleState())
            names = dict(property_names.get(function.owner, {}))
            for name, _, _, _ in function.parameters:
                names[name] = ('parameter', function.key, name)
            outcomes = self.block(function.body, initial, names)
            outstanding = set().union(*(state.active | state.repeated for state, _ in outcomes))
            self.leaked.update(outstanding - initial.active)
            if not function.scope:
                discharged.update(initial.active - outstanding)
        for state in property_states.values():
            self.leaked.update(state.active - discharged)
        return [(position, *self.resources[position]) for position in sorted(self.leaked)]


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
    # Owning FileHandle URL/path initializers close their descriptor in deinit.
    # A borrowed raw descriptor needs origin/ownership analysis, not a blanket
    # missing-explicit-close warning on the wrapper object.
    acquisition_names = {'scheduledTimer', 'publish', 'dataTask', 'uploadTask', 'downloadTask',
                         'addObserver', 'sink', 'makeTimerSource',
                         'makeFileSystemObjectSource', 'makeReadSource', 'makeWriteSource', 'CADisplayLink'}
    if any(token.kind == 'code' and token.value in acquisition_names for token in tokens):
        for position, kind, message, name in LifecycleEngine(text).analyze():
            emit(position, kind, f"{message} ({name})")

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
            yield {
                "rule": f"swift.lifecycle.{kind}",
                "path": str(path.resolve()),
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "swift",
                "severity": _SEVERITY[kind],
                "message": message,
            }


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
