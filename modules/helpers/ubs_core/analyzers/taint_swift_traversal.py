"""Scoped Swift request dataflow for file and redirect sinks (mj1j.8).

The lexer keeps executable interpolation separate from inert literal text.
Lexical bindings, structured branches/loops and selected same-file calls use
the shared finite worklist. Proofs belong to the checked value and sink kind;
neither a helper's name nor a nearby check is evidence of validation.
This is a bounded source frontend, not a Swift compiler. Unsupported relevant
closures, dynamic dispatch, captures and exhausted work report incomplete
analysis. The tuple-returning scan_text is the count/sample output adapter.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join, join_states, retag, solve


@dataclass(frozen=True)
class SwiftToken:
    value: str
    start: int
    end: int
    kind: str = 'code'
    parts: tuple = ()


class SwiftLexer:
    def __init__(self, text):
        self.text = text
        self.budget = Budget(max(1000, len(text) * 16))

    def comment(self, start, limit):
        if self.text.startswith('//', start):
            finish = self.text.find('\n', start, limit)
            return limit if finish < 0 else finish
        cursor, nesting = start + 2, 1
        while cursor < limit:
            self.budget.spend()
            if self.text.startswith('/*', cursor):
                nesting += 1
                cursor += 2
            elif self.text.startswith('*/', cursor):
                nesting -= 1
                cursor += 2
                if not nesting:
                    return cursor
            else:
                cursor += 1
        raise ValueError('Unterminated Swift comment; analysis is incomplete')

    def literal(self, start, limit, depth):
        if depth > 64:
            raise AnalysisLimit('Swift interpolation nesting limit exceeded; analysis is incomplete')
        marker = re.match(r'(#{0,32})("""|"|/)', self.text[start:limit])
        if marker is None:
            raise ValueError('Invalid Swift literal; analysis is incomplete')
        hashes, quote = marker.groups()
        closing, escape = quote + hashes, '\\' + hashes
        cursor, content, holes = start + marker.end(), [], []
        while cursor < limit:
            self.budget.spend()
            if self.text.startswith(closing, cursor):
                kind = 'regex' if quote == '/' else 'template' if holes else 'literal'
                return SwiftToken(''.join(content), start, cursor + len(closing), kind, tuple(holes))
            if self.text.startswith(escape + '(', cursor) and quote != '/':
                opening = cursor + len(escape)
                finish = self.interpolation_end(opening + 1, limit, depth + 1)
                holes.append(tuple(self.scan(opening + 1, finish, depth + 1)))
                cursor = finish + 1
                continue
            if self.text.startswith(escape, cursor):
                after = cursor + len(escape)
                if after >= limit:
                    break
                char = self.text[after]
                unicode_escape = re.match(r'u\{([0-9a-fA-F]{1,8})\}', self.text[after:limit])
                if unicode_escape:
                    try:
                        content.append(chr(int(unicode_escape.group(1), 16)))
                    except ValueError as error:
                        raise ValueError('Invalid Swift Unicode escape; analysis is incomplete') from error
                    cursor = after + unicode_escape.end()
                else:
                    content.append({'n': '\n', 'r': '\r', 't': '\t', '0': '\0'}.get(char, char))
                    cursor = after + 1
                continue
            if quote == '"' and self.text[cursor] in '\r\n':
                raise ValueError('Unterminated Swift string; analysis is incomplete')
            content.append(self.text[cursor])
            cursor += 1
        raise ValueError('Unterminated Swift literal; analysis is incomplete')

    def interpolation_end(self, start, limit, depth):
        cursor, nesting = start, 1
        while cursor < limit:
            self.budget.spend()
            if self.text.startswith(('//', '/*'), cursor):
                cursor = self.comment(cursor, limit)
                continue
            if re.match(r'#{0,32}"', self.text[cursor:limit]):
                cursor = self.literal(cursor, limit, depth).end
                continue
            if self.text[cursor] == '(':
                nesting += 1
            elif self.text[cursor] == ')':
                nesting -= 1
                if not nesting:
                    return cursor
            cursor += 1
        raise ValueError('Unterminated Swift interpolation; analysis is incomplete')

    def scan(self, start=0, limit=None, depth=0):
        text, cursor = self.text, start
        limit = len(text) if limit is None else limit
        output = []
        while cursor < limit:
            self.budget.spend()
            char = text[cursor]
            if char in ' \t\r':
                cursor += 1
                continue
            if text.startswith(('//', '/*'), cursor):
                finish = self.comment(cursor, limit)
                output.extend(SwiftToken('\n', position, position + 1)
                              for position in range(cursor, finish) if text[position] == '\n')
                cursor = finish
                continue
            regex = char == '/' and (not output or output[-1].value in {'=', '(', ',', ':', 'return'})
            if re.match(r'#{0,32}"|#+/', text[cursor:limit]) or regex:
                token = self.literal(cursor, limit, depth)
                output.append(token)
                cursor = token.end
                continue
            if char == '`':
                finish = text.find('`', cursor + 1, limit)
                if finish < 0:
                    raise ValueError('Unterminated Swift identifier; analysis is incomplete')
                output.append(SwiftToken(text[cursor + 1:finish], cursor, finish + 1))
                cursor = finish + 1
                continue
            match = re.match(r'[A-Za-z_$][A-Za-z_0-9$]*|\d+(?:\.\d+)?|\.\.\.|\.\.<|->|==|!=|<=|>=|&&|\|\||\?\?|\+=|-=|\*=|/=', text[cursor:limit])
            finish = cursor + (match.end() if match else 1)
            output.append(SwiftToken(text[cursor:finish], cursor, finish,
                                     'number' if char.isdigit() else 'code'))
            cursor = finish
        return tuple(output)


def swift_text(tokens):
    return ''.join(token.value if token.kind == 'code' else repr(token.value) for token in tokens)


def swift_close(tokens, start):
    stack = []
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind != 'code':
            continue
        if token.value in {'(', '[', '{'}:
            stack.append(token.value)
            if len(stack) > 128:
                raise AnalysisLimit('Swift delimiter nesting limit exceeded; analysis is incomplete')
        elif token.value in {')', ']', '}'}:
            if not stack or stack.pop() != {')': '(', ']': '[', '}': '{'}[token.value]:
                raise ValueError('Unbalanced Swift delimiters; analysis is incomplete')
            if not stack:
                return index
    raise ValueError('Unbalanced Swift delimiters; analysis is incomplete')


def swift_parts(tokens, separators, generics=False):
    result, start, cursor, angles = [], 0, 0, 0
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.kind == 'code':
            if token.value in {'(', '[', '{'}:
                cursor = swift_close(tokens, cursor)
            elif generics and token.value == '<':
                angles += 1
            elif generics and token.value == '>':
                angles = max(0, angles - 1)
            elif not angles and token.value in separators:
                result.append(tuple(tokens[start:cursor]))
                start = cursor + 1
        cursor += 1
    return (*result, tuple(tokens[start:]))


def swift_ungroup(tokens):
    tokens = tuple(token for token in tokens if token.kind != 'code' or token.value != '\n')
    while tokens and tokens[0].value == '(' and swift_close(tokens, 0) == len(tokens) - 1:
        tokens = tokens[1:-1]
    return tokens


@dataclass(frozen=True)
class SwiftStatement:
    kind: str
    tokens: tuple
    body: tuple = ()
    alternate: tuple = ()
    extra: tuple = ()


@dataclass
class SwiftFunction:
    key: int
    name: str
    owner: tuple
    scope: tuple
    parameters: tuple
    body: tuple = ()
    static: bool = False
    return_type: str = ''


class SwiftParser:
    def __init__(self, text):
        self.tokens = SwiftLexer(text).scan()
        cursor = 0
        while cursor < len(self.tokens):
            token = self.tokens[cursor]
            if token.kind == 'code' and token.value in {'(', '[', '{'}:
                cursor = swift_close(self.tokens, cursor)
            elif token.kind == 'code' and token.value in {')', ']', '}'}:
                raise ValueError('Unbalanced Swift delimiters; analysis is incomplete')
            cursor += 1
        self.functions, self.types, self.extensions, self.final_types = {}, set(), set(), set()
        body = self.block(self.tokens, (), (), declarations=True)
        self.functions[-1] = SwiftFunction(-1, '<script>', (), (), (), body)

    def statement_end(self, tokens, start):
        cursor = start
        continuation = {'=', '+', '-', '*', '/', '??', '&&', '||', ',', '.', '->', ':', 'try', 'await'}
        while cursor < len(tokens):
            token = tokens[cursor]
            if token.kind == 'code':
                if token.value in {'(', '[', '{'}:
                    cursor = swift_close(tokens, cursor)
                elif token.value == ';':
                    return cursor
                elif token.value == '\n':
                    previous = tokens[cursor - 1].value if cursor > start and tokens[cursor - 1].kind == 'code' else ''
                    following = cursor + 1
                    while following < len(tokens) and tokens[following].value == '\n':
                        following += 1
                    next_value = tokens[following].value if following < len(tokens) and tokens[following].kind == 'code' else ''
                    if previous not in continuation and next_value not in {'.', '&&', '||', '??', '+', ','}:
                        return cursor
            cursor += 1
        return cursor

    def block(self, tokens, owner, scope, declarations=False, depth=0):
        if depth > 64:
            raise AnalysisLimit('Swift block nesting limit exceeded; analysis is incomplete')
        statements, cursor = [], 0
        while cursor < len(tokens):
            if tokens[cursor].value in {'\n', ';'}:
                cursor += 1
                continue
            start = cursor
            modifiers = {'public', 'private', 'fileprivate', 'internal', 'open', 'final', 'static', 'class', 'mutating', 'nonmutating', 'override', 'nonisolated', 'indirect', 'required', 'convenience'}
            head = cursor
            while head < len(tokens) and tokens[head].value == '@':
                head += 2
                if head < len(tokens) and tokens[head].value == '(':
                    head = swift_close(tokens, head) + 1
                while head < len(tokens) and tokens[head].value == '\n':
                    head += 1
            while head < len(tokens) and tokens[head].value in modifiers:
                if tokens[head].value == 'class' and head + 1 < len(tokens) and tokens[head + 1].value != 'func':
                    break
                head += 1
            if head < len(tokens) and tokens[head].value == 'func':
                name_index = head + 1
                if name_index >= len(tokens):
                    raise ValueError('Missing Swift function name; analysis is incomplete')
                name, opening = tokens[name_index].value, name_index + 1
                if opening < len(tokens) and tokens[opening].value == '<':
                    while opening < len(tokens) and tokens[opening].value != '>':
                        opening += 1
                    opening += 1
                if opening >= len(tokens) or tokens[opening].value != '(':
                    raise ValueError('Unsupported Swift function declaration; analysis is incomplete')
                close = swift_close(tokens, opening)
                parameters = []
                for part in swift_parts(tokens[opening + 1:close], {','}, generics=True):
                    part = swift_ungroup(part)
                    if not part:
                        continue
                    pieces = swift_parts(part, {':'})
                    if len(pieces) != 2:
                        raise ValueError('Unsupported Swift parameter binding; analysis is incomplete')
                    names = [item.value for item in pieces[0] if item.kind == 'code']
                    if not 1 <= len(names) <= 2:
                        raise ValueError('Unsupported Swift parameter labels; analysis is incomplete')
                    default = swift_parts(pieces[1], {'='})
                    declaration = swift_text(default[0])
                    parameters.append((names[-1], '' if names[0] == '_' else names[0], declaration,
                                       default[1] if len(default) == 2 else ()))
                body_start = close + 1
                while body_start < len(tokens) and tokens[body_start].value not in {'{', ';'}:
                    body_start += 1
                if body_start == len(tokens) or tokens[body_start].value != '{':
                    cursor = self.statement_end(tokens, close + 1) + 1
                    continue
                finish = swift_close(tokens, body_start)
                key = tokens[head].start
                function = SwiftFunction(key, name, owner, scope, tuple(parameters),
                                         static=any(token.value in {'static', 'class'} for token in tokens[start:head]))
                result_type = swift_parts(tokens[close + 1:body_start], {'->'})
                if len(result_type) == 2:
                    function.return_type = swift_text(swift_ungroup(result_type[1]))
                self.functions[key] = function
                body = self.block(tokens[body_start + 1:finish], owner, (*scope, key), depth=depth + 1)
                if len(body) == 1 and body[0].kind == 'simple' and not self.assignment(body[0].tokens):
                    body = (replace(body[0], kind='return'),)
                function.body = body
                statements.append(SwiftStatement('definition', tuple(tokens[start:finish + 1]), extra=(key,)))
                cursor = finish + 1
                continue
            if head < len(tokens) and tokens[head].value in {'struct', 'class', 'enum', 'protocol', 'actor', 'extension'}:
                kind, position = tokens[head].value, head + 1
                names = []
                while position < len(tokens) and tokens[position].value not in {'{', ':', 'where', '\n'}:
                    names.append(tokens[position].value)
                    position += 1
                while position < len(tokens) and tokens[position].value != '{':
                    position += 1
                if position >= len(tokens):
                    raise ValueError('Unterminated Swift type declaration; analysis is incomplete')
                finish, name = swift_close(tokens, position), ''.join(names)
                (self.extensions if kind == 'extension' else self.types).add(name)
                if kind in {'struct', 'enum'} or any(token.value == 'final' for token in tokens[start:head]):
                    self.final_types.add(name)
                self.block(tokens[position + 1:finish], (*owner, name), scope, declarations=True, depth=depth + 1)
                statements.append(SwiftStatement('definition', tuple(tokens[start:finish + 1])))
                cursor = finish + 1
                continue
            first = tokens[start].value
            if first in {'if', 'guard', 'while', 'for'}:
                opening = start + 1
                while opening < len(tokens) and tokens[opening].value != '{':
                    if tokens[opening].value in {'(', '['}:
                        opening = swift_close(tokens, opening)
                    opening += 1
                if opening >= len(tokens):
                    raise ValueError('Missing Swift control-flow body; analysis is incomplete')
                finish = swift_close(tokens, opening)
                condition = tuple(tokens[start + 1:opening])
                if first == 'guard':
                    condition = tuple(token for token in condition if token.kind != 'code' or token.value != '\n')
                    if not condition or condition[-1].value != 'else':
                        raise ValueError('Swift guard has no else; analysis is incomplete')
                    condition = condition[:-1]
                body = self.block(tokens[opening + 1:finish], owner, scope, depth=depth + 1)
                alternate, cursor = (), finish + 1
                following = cursor
                while following < len(tokens) and tokens[following].value == '\n':
                    following += 1
                if first == 'if' and following < len(tokens) and tokens[following].value == 'else':
                    following += 1
                    while following < len(tokens) and tokens[following].value == '\n':
                        following += 1
                    if following < len(tokens) and tokens[following].value == '{':
                        finish = swift_close(tokens, following)
                        alternate = self.block(tokens[following + 1:finish], owner, scope, depth=depth + 1)
                        cursor = finish + 1
                    elif following < len(tokens) and tokens[following].value == 'if':
                        # The nested if owns its complete else chain.
                        tail = self.block(tokens[following:], owner, scope, depth=depth + 1)
                        alternate, cursor = tail[:1], len(tokens)
                        statements.append(SwiftStatement(first, condition, body, alternate))
                        statements.extend(tail[1:])
                        continue
                    else:
                        raise ValueError('Invalid Swift else body; analysis is incomplete')
                statements.append(SwiftStatement(first, condition, body, alternate))
                continue
            if first == '{':
                finish = swift_close(tokens, start)
                statements.append(SwiftStatement('closure', tuple(tokens[start:finish + 1])))
                cursor = finish + 1
                continue
            finish = self.statement_end(tokens, start)
            part = tuple(tokens[start:finish])
            cursor = finish + 1
            if not part:
                continue
            if declarations and owner:
                # Stored fields/accessors require an object state model. Never
                # silently discard an executable request source in this region.
                if any(token.kind == 'code' and token.value in {'req', 'request'} for token in part):
                    raise ValueError('Swift request-derived type initialization needs field analysis; analysis is incomplete')
                continue
            if first in {'import', 'typealias', 'case', '@'}:
                if first == 'typealias' and len(part) >= 2:
                    self.types.add(part[1].value)
                if first == '@' and swift_source_tokens(part):
                    raise ValueError('Swift attributed executable declaration needs binding analysis; analysis is incomplete')
                statements.append(SwiftStatement('definition', part))
            elif first in {'switch', 'do', 'catch', 'defer', 'repeat', '#'}:
                statements.append(SwiftStatement('unsupported', part))
            elif first in {'return', 'throw', 'break', 'continue'}:
                statements.append(SwiftStatement(first, part[1:]))
            else:
                statements.append(SwiftStatement('simple', part))
        return tuple(statements)

    @staticmethod
    def assignment(tokens):
        parts = swift_parts(tokens, {'=', '+=', '-=', '*=', '/='})
        if len(parts) != 2:
            return None
        lhs = swift_ungroup(parts[0])
        declaration = bool(lhs and lhs[0].value in {'let', 'var'})
        if declaration:
            lhs = lhs[1:]
        if not lhs:
            raise ValueError('Missing Swift assignment binding; analysis is incomplete')
        colon = swift_parts(lhs, {':'})
        binding = colon[0]
        if len(binding) != 1 or binding[0].kind != 'code' or not re.fullmatch(r'[A-Za-z_]\w*', binding[0].value):
            return ('', tuple(lhs), parts[1], '=', declaration)
        operator = tokens[len(parts[0])].value
        return binding[0].value, (binding[0],), parts[1], operator, declaration

    @staticmethod
    def uninitialized(tokens):
        tokens = swift_ungroup(tokens)
        if (len(tokens) >= 3 and tokens[0].value in {'let', 'var'}
                and tokens[1].kind == 'code' and tokens[2].value == ':'
                and len(swift_parts(tokens, {'='})) == 1):
            return tokens[1]
        return None


SWIFT_VALUE_TAGS = frozenset({'local-slash', 'not-network-path', 'no-backslash', 'no-tab',
    'no-newline', 'no-carriage-return', 'url-scheme', 'url-host', 'url-object',
    'serialized-url', 'file-url', 'path-string', 'canonical-path', 'contained-path', 'file-leaf'})
SWIFT_LOCAL_TAGS = frozenset({'local-slash', 'not-network-path', 'no-backslash',
                            'no-tab', 'no-newline', 'no-carriage-return'})


def swift_tainted(fact):
    return frozenset(trace for trace in fact if trace.kind == 'source')


def swift_constant(value, kind='literal'):
    return frozenset({Trace('constant', (kind, value), tags=frozenset({'swift-string'}) if kind == 'literal' else frozenset())})


def swift_shape(name, offset=-1):
    return frozenset({Trace('shape', (name, offset))})


def swift_has_shape(fact, name):
    return any(trace.kind == 'shape' and trace.key[0] == name for trace in fact)


def swift_source_tokens(tokens):
    for token in tokens:
        if token.kind == 'code' and token.value in {'Request', 'req', 'request', 'filename', 'fileName', 'originalFilename', 'originalFileName'}:
            return True
        if any(swift_source_tokens(part) for part in token.parts):
            return True
    return False


def swift_statement_tokens(statements):
    for statement in statements:
        if statement.kind == 'definition':
            continue
        yield from statement.tokens
        yield from swift_statement_tokens(statement.body)
        yield from swift_statement_tokens(statement.alternate)


@dataclass
class SwiftSummary:
    returned: Fact = CLEAN
    effects: dict = field(default_factory=dict)
    mutations: dict = field(default_factory=dict)

    def merged(self, other):
        effects, mutations = dict(self.effects), dict(self.mutations)
        for key, value in other.effects.items():
            effects[key] = join(effects.get(key, CLEAN), value)
        for key, value in other.mutations.items():
            mutations[key] = join(mutations.get(key, CLEAN), value)
        return SwiftSummary(join(self.returned, other.returned), effects, mutations)


class SwiftEngine:
    def __init__(self, path, text, policy='path', parser=None):
        self.path, self.text, self.policy = path, text, policy
        self.parser = SwiftParser(text) if parser is None else parser
        self.lines = [0, *(index + 1 for index, char in enumerate(text) if char == '\n')]
        self.budget, self.graphs = Budget(), {}
        self.contexts, self.summaries, self.globals = {}, {}, {}
        self.url_reads = {}
        self.function = self.parser.functions[-1]
        self.effects, self.mutations = {}, {}
        self.local_globals = set()
        for statement in self.function.body:
            assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
            if assignment and assignment[0]:
                name, _, rhs, _, declaration = assignment
                if declaration:
                    self.local_globals.add(name)
                    self.globals[name] = self.expression(rhs, dict(self.globals), {})
                    if swift_tainted(self.globals[name]):
                        raise ValueError('Swift request-derived global state needs capture analysis; analysis is incomplete')
        for function in self.parser.functions.values():
            request_parameter = any(re.fullmatch(r'(?:Vapor\.)?Request\??', item[2]) for item in function.parameters)
            if function.key == -1 or request_parameter or swift_source_tokens(swift_statement_tokens(function.body)):
                self.context(function, tuple(CLEAN for _ in function.parameters), entry=True)

    def step(self, offset, kind, label):
        offset = max(0, offset)
        index = bisect_right(self.lines, offset) - 1
        return Step(str(self.path), index + 1, offset - self.lines[index] + 1, kind, label[:160])

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path), offset, label),
            tags=frozenset({'swift-string'}), evidence=(self.step(offset, 'source', label),))})

    def context(self, function, arguments, entry=False):
        key = function.key, arguments, entry
        if key not in self.contexts:
            self.budget.spend()
            if len(self.contexts) >= 2048:
                raise AnalysisLimit('Swift call-context limit exceeded; analysis is incomplete')
            self.contexts[key], self.summaries[key] = function, SwiftSummary()
        return key

    def builtin(self, name, state=None, bindings=None):
        parts = name.split('.')
        if parts[0] in self.parser.types or parts[0] in (bindings or {}):
            return False
        if parts[0] in (state or {}) and (state or {})[parts[0]]:
            return False
        if len(parts) == 2 and parts[0] in {'Foundation', 'Swift'}:
            return True
        return len(parts) == 1 and name not in self.parser.types

    def forget(self, value, keep=frozenset()):
        tags = SWIFT_VALUE_TAGS - keep
        links = frozenset(tag for trace in value for tag in trace.tags if tag.startswith(('property-of:', 'url-id:')))
        plain = frozenset(trace for trace in value if trace.kind not in {'shape', 'constant'})
        return retag(plain, remove=tags | links)

    def record(self, offset, value, file_leaf=False):
        if self.policy == 'redirect':
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if not SWIFT_LOCAL_TAGS <= trace.tags and not (
                    {'url-scheme', 'url-host', 'serialized-url'} <= trace.tags))
        else:
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if 'contained-path' not in trace.tags and not (file_leaf and 'file-leaf' in trace.tags))
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN),
                advance(unsafe, self.step(offset, 'sink', 'redirect' if self.policy == 'redirect' else 'file sink')))

    def candidates(self, name, receiver, state, bindings):
        leaf, owner = name.rsplit('.', 1)[-1], self.function.owner
        function_values = {trace.key[0] for trace in receiver if trace.kind == 'function'}
        if function_values:
            return [self.parser.functions[key] for key in function_values]
        if any(trace.kind == 'shape' and trace.key[0].startswith('dynamic-instance:') for trace in receiver):
            return []
        if '.' in name:
            prefix = name.rsplit('.', 1)[0]
            if prefix == 'self':
                owner = self.function.owner
            elif prefix in self.parser.types:
                owner = tuple(prefix.split('.'))
            else:
                instances = {trace.key[0][9:] for trace in receiver if trace.kind == 'shape' and trace.key[0].startswith('instance:')}
                if len(instances) != 1:
                    return []
                owner = tuple(next(iter(instances)).split('.'))
        elif name in bindings:
            return []
        visible = [function for function in self.parser.functions.values()
            if function.name == leaf and function.owner == owner
            and (not function.scope or tuple((*self.function.scope, self.function.key)[:len(function.scope)]) == function.scope)]
        if not visible and '.' not in name and owner:
            visible = [function for function in self.parser.functions.values()
                if function.name == leaf and not function.owner and not function.scope]
        if visible:
            innermost = max(len(function.scope) for function in visible)
            visible = [function for function in visible if len(function.scope) == innermost]
        return visible

    def bind(self, function, arguments, state, bindings):
        position, values = 0, []
        for name, label, declaration, default in function.parameters:
            if '...' in declaration or '@escaping' in declaration or '@autoclosure' in declaration:
                raise ValueError('Swift variadic/escaping parameters need call binding analysis; analysis is incomplete')
            if position < len(arguments) and arguments[position][0] == label:
                value = arguments[position][1]
                position += 1
            elif default:
                value = self.expression(default, self.globals, {})
            else:
                return None
            values.append(value)
        return tuple(values) if position == len(arguments) else None

    def mutate(self, name, value, state, bindings):
        binding = bindings.get(name, name)
        previous = state.get(binding, CLEAN)
        state[binding] = self.forget(join(previous, value))
        if name in self.local_globals and binding == name and swift_tainted(state[binding]):
            raise ValueError('Swift request-derived global mutation needs shared-state analysis; analysis is incomplete')
        self.invalidate_properties(binding, state)
        return state[binding]

    def invalidate_properties(self, binding, state):
        link = 'property-of:' + binding
        for key, value in tuple(state.items()):
            if any(link in trace.tags for trace in value):
                state[key] = retag(value, remove=frozenset({link, 'url-host', 'url-scheme'}))

    def call(self, name, receiver, arguments, token, state, bindings, callee_token=None):
        leaf = name.rsplit('.', 1)[-1]
        values = [value for _, value, _ in arguments]
        labeled = {label: value for label, value, _ in arguments if label}
        value = join(receiver, *values)
        candidates = self.candidates(name, receiver, state, bindings)
        native_redirect = ('.' in name and not any(swift_has_shape(fact, 'request') for fact in values)
                           and (not candidates or all(function.return_type in {'Response', 'HTTPResponse'} for function in candidates)))
        if leaf == 'redirect' and values and (native_redirect or not candidates):
            if self.policy == 'redirect':
                self.record(token.start, labeled.get('to', values[0]))
            return CLEAN
        if leaf in {'Response', 'HTTPResponse', 'HTTPHeaders'}:
            header_value = labeled.get('headers', join(*values) if leaf == 'HTTPHeaders' else CLEAN)
            if self.policy == 'redirect':
                self.record(token.start, frozenset(trace for trace in header_value if 'header-key:location' in trace.tags))
            return swift_shape('instance:' + leaf, token.start)
        if leaf in {'add', 'replaceOrAdd'} and ('headers' in name.lower() or swift_has_shape(receiver, 'instance:Headers')):
            names = {trace.key[1].lower() for trace in labeled.get('name', CLEAN) if trace.kind == 'constant'}
            name_tokens = next((part for label, _, part in arguments if label == 'name'), ())
            if names & {'location'} or swift_text(name_tokens).lower() == '.location':
                if self.policy == 'redirect':
                    self.record(token.start, labeled.get('value', CLEAN))
            return CLEAN
        native_file = (not candidates or name.startswith(('req.fileio.', 'request.fileio.')))
        if leaf in {'String', 'Data', 'FileHandle'}:
            native_file = native_file and self.builtin(name, state, bindings)
        if native_file and (leaf in {'String', 'Data', 'FileHandle', 'sendFile', 'streamFile', 'readFile', 'serveFile', 'writeFile', 'file', 'write'} or name.startswith('FileManager.default.')):
            selected, leaf_safe = [], False
            if leaf in {'String', 'Data'}:
                selected = [labeled[key] for key in ('contentsOf', 'contentsOfFile') if key in labeled]
                leaf_safe = True
            elif leaf == 'FileHandle':
                selected = [fact for label, fact, _ in arguments if label.startswith(('forReading', 'forWriting', 'forUpdating'))]
                leaf_safe = True
            elif name.startswith('FileManager.default.'):
                selected = [fact for label, fact, _ in arguments if label in {'at', 'atPath', 'to', 'toPath', 'from', 'fromPath'}]
            elif leaf in {'sendFile', 'streamFile', 'readFile', 'serveFile', 'writeFile', 'file'}:
                selected = [labeled.get('at', labeled.get('path', values[0] if values else CLEAN))]
                leaf_safe = True
            elif leaf == 'write' and 'to' in labeled:
                selected, leaf_safe = [labeled['to']], True
            if selected:
                if leaf in {'String', 'Data'} and 'contentsOf' in labeled:
                    read_offset = (callee_token or token).start
                    read_value = labeled['contentsOf'] or swift_shape('unknown-url', read_offset)
                    self.url_reads[read_offset] = join(self.url_reads.get(read_offset, CLEAN), read_value)
                if self.policy == 'path':
                    sink_value = join(*selected)
                    if leaf in {'String', 'Data'} and 'contentsOf' in labeled:
                        # Foundation URL readers also accept remote URLs. A
                        # checked HTTPS URL is not a request-controlled file path.
                        sink_value = frozenset(trace for trace in sink_value if not {'url-object', 'url-scheme'} <= trace.tags)
                    self.record(token.start, sink_value, leaf_safe)
                return CLEAN
        returned, matched = CLEAN, False
        for function in candidates:
            bound = self.bind(function, arguments, state, bindings)
            if bound is None:
                continue
            if function.scope:
                def identifiers(statements):
                    for statement in statements:
                        yield from (item.value for item in statement.tokens if item.kind == 'code')
                        yield from identifiers(statement.body)
                        yield from identifiers(statement.alternate)
                names = set(identifiers(function.body)) - {item[0] for item in function.parameters}
                for captured in names.intersection(bindings):
                    fact = state.get(bindings[captured], CLEAN)
                    if swift_tainted(fact) or swift_has_shape(fact, 'request'):
                        raise ValueError('Swift request-derived nested capture needs capture analysis; analysis is incomplete')
            if any(item[2].startswith('inout') for item in function.parameters) and any(item[3] for item in function.parameters):
                raise ValueError('Swift defaulted inout arguments need mutation binding analysis; analysis is incomplete')
            matched = True
            call = self.step(token.start, 'call', name + '()')
            facts = tuple(advance(fact, call) for fact in bound)
            summary = self.summaries[self.context(function, facts)]
            returned = join(returned, advance(summary.returned, call))
            for offset, fact in summary.effects.items():
                self.effects[offset] = join(self.effects.get(offset, CLEAN), fact)
            for index, parameter in enumerate(function.parameters):
                if parameter[2].startswith('inout') and index < len(arguments):
                    # The callee's exit summary includes unchanged inout
                    # parameters too. Use lattice bottom until that summary
                    # is available; an identity guess would permanently add
                    # a false finding before a known literal overwrite.
                    fact = summary.mutations.get(index, CLEAN)
                    tokens = swift_ungroup(arguments[index][2])
                    if len(tokens) == 2 and tokens[0].value == '&':
                        state[bindings.get(tokens[1].value, tokens[1].value)] = fact
                        self.invalidate_properties(bindings.get(tokens[1].value, tokens[1].value), state)
        if matched:
            return returned
        if candidates and any(swift_tainted(fact) for fact in values):
            raise ValueError('Swift selected helper arguments could not bind; analysis is incomplete')
        if leaf in {'URL', 'URLComponents'} and self.builtin(name, state, bindings):
            if 'fileURLWithPath' in labeled:
                return join(retag(self.forget(labeled['fileURLWithPath']), add=frozenset({'file-url'})),
                            retag(swift_shape('file-url', token.start), add=frozenset({'file-url'})))
            if 'string' in labeled:
                tags = frozenset({'url-object', 'url-id:' + str(token.start)})
                return join(retag(self.forget(labeled['string']), add=tags), retag(swift_shape('url', token.start), add=tags))
        if leaf == 'Set' and len(values) == 1 and swift_has_shape(values[0], 'literal-list'):
            return values[0]
        if name in self.parser.types:
            if any(swift_tainted(fact) for fact in values):
                raise ValueError('Swift request-derived object initialization needs field analysis; analysis is incomplete')
            return swift_shape('instance:' + name, token.start)
        if leaf in {'get', 'first'} and any(swift_has_shape(receiver, kind) for kind in {'request-collection', 'request-content'}):
            return self.source(token.start, name + '()')
        if leaf in {'append', 'appendContentsOf', 'insert', 'remove', 'removeAll', 'removeFirst', 'removeLast', 'removeSubrange', 'replaceSubrange', 'replace', 'appendPathComponent', 'deleteLastPathComponent', 'deletePathExtension'}:
            return self.mutate(name.split('.', 1)[0], join(*values), state, bindings)
        if any(part and part[0].value == '&' for _, _, part in arguments) and swift_tainted(value):
            raise ValueError('Swift unresolved inout call needs mutation analysis; analysis is incomplete')
        if any(trace.kind == 'function' for fact in values for trace in fact) and (
                swift_tainted(value) or swift_has_shape(value, 'request')):
            raise ValueError('Swift selected callback needs higher-order call analysis; analysis is incomplete')
        if any(function.name == leaf for function in self.parser.functions.values()) and swift_tainted(value):
            raise ValueError('Swift unresolved receiver dispatch needs binding analysis; analysis is incomplete')
        if '.' in name and swift_tainted(receiver) and leaf not in {'hasPrefix', 'contains', 'hasSuffix', 'lowercased', 'uppercased', 'replacingOccurrences', 'addingPercentEncoding', 'dropFirst', 'dropLast'}:
            self.mutate(name.split('.', 1)[0], CLEAN, state, bindings)
        return self.forget(value)

    def member(self, name, receiver, token, owner_binding=None):
        if swift_has_shape(receiver, 'request'):
            if name in {'query', 'parameters', 'params', 'headers'}:
                return swift_shape('request-collection', token.start)
            if name == 'content':
                return swift_shape('request-content', token.start)
            if name in {'url', 'uri'}:
                return self.source(token.start, 'request.' + name)
        if name in {'filename', 'fileName', 'originalFilename', 'originalFileName'}:
            return self.source(token.start, name)
        if name == 'lastPathComponent' and all('file-url' in trace.tags for trace in receiver):
            return retag(self.forget(receiver), add=frozenset({'file-leaf', 'swift-string'}))
        if name in {'standardizedFileURL', 'resolvingSymlinksInPath', 'standardized'} and any('file-url' in trace.tags for trace in receiver):
            return retag(receiver, add=frozenset({'canonical-path'}))
        if name == 'path' and any('file-url' in trace.tags for trace in receiver):
            return retag(receiver, add=frozenset({'path-string', 'swift-string'}))
        if name in {'absoluteString', 'string', 'description'} and any('url-object' in trace.tags for trace in receiver):
            return retag(receiver, add=frozenset({'serialized-url', 'swift-string'}), remove=frozenset({'url-object'}))
        if name in {'host', 'scheme'} and any('url-object' in trace.tags for trace in receiver):
            links = frozenset({'property-of:' + owner_binding, 'url-property:' + name}) if owner_binding else frozenset()
            return retag(receiver, add=links | frozenset({'swift-string'}), remove=frozenset({'url-object', 'serialized-url'}))
        if name in {'query', 'parameters', 'params', 'headers', 'content'} and swift_tainted(receiver):
            return receiver
        return self.forget(receiver)

    def expression(self, tokens, state, bindings, depth=0):
        if depth > 64:
            raise AnalysisLimit('Swift expression nesting limit exceeded; analysis is incomplete')
        tokens = swift_ungroup(tokens)
        while tokens and tokens[0].value in {'try', 'await', '?', '!'}:
            tokens = tokens[1:]
        if not tokens:
            return CLEAN
        ternary = swift_parts(tokens, {'?'})
        if len(ternary) == 2:
            branches = swift_parts(ternary[1], {':'})
            if len(branches) == 2:
                self.expression(ternary[0], state, bindings, depth + 1)
                selector = swift_text(ternary[0])
                selected = (branches[0],) if selector == 'true' else (branches[1],) if selector == 'false' else branches
                branch_states, values = [], []
                for part in selected:
                    branch = dict(state)
                    values.append(self.expression(part, branch, bindings, depth + 1))
                    branch_states.append(branch)
                state.update(join_states(*branch_states))
                return join(*values)
        groups = swift_parts(tokens, {'??', '+', '-', '*', '/', '&&', '||'})
        if len(groups) > 1:
            operators = [tokens[sum(len(part) for part in groups[:index + 1]) + index].value
                         for index in range(len(groups) - 1)]
            values = [self.expression(groups[0], state, bindings, depth + 1)]
            for operator, part in zip(operators, groups[1:]):
                before = dict(state)
                values.append(self.expression(part, state, bindings, depth + 1))
                if operator in {'??', '&&', '||'}:
                    # These operands may never execute. Their selected
                    # helper mutations cannot strongly kill the skipped arm.
                    state.update(join_states(before, state))
            value = join(*values)
            return value if set(operators) <= {'??'} else self.forget(value)
        if tokens[0].kind in {'literal', 'number', 'regex', 'template'}:
            token = tokens[0]
            if token.kind == 'template':
                value = retag(self.forget(join(*(self.expression(part, state, bindings, depth + 1) for part in token.parts))),
                              add=frozenset({'swift-string'}))
            else:
                value = swift_constant(token.value, token.kind)
            cursor, name, owner_binding = 1, '', None
        elif tokens[0].value == '[':
            close = swift_close(tokens, 0)
            parts = []
            for part in swift_parts(tokens[1:close], {','}):
                if not part:
                    continue
                keyed = swift_parts(part, {':'})
                paired = swift_parts(swift_ungroup(part), {','})
                pair = keyed if len(keyed) == 2 else paired
                key = swift_ungroup(pair[0]) if len(pair) == 2 else ()
                if len(key) == 1 and key[0].kind == 'literal':
                    fact = self.expression(pair[1], state, bindings, depth + 1)
                    parts.append(retag(fact, add=frozenset({'header-key:' + key[0].value.lower()})))
                else:
                    parts.append(self.expression(part, state, bindings, depth + 1))
            if all(all(trace.kind == 'constant' for trace in fact) for fact in parts):
                value = join(*parts, swift_shape('literal-list', tokens[0].start))
            else:
                value = join(*parts)
            cursor, name, owner_binding = close + 1, '', None
        elif tokens[0].value == '(':
            close = swift_close(tokens, 0)
            value = self.expression(tokens[1:close], state, bindings, depth + 1)
            cursor, name, owner_binding = close + 1, '', None
        elif tokens[0].value == '{':
            raise ValueError('Swift closure execution/capture needs closure analysis; analysis is incomplete')
        elif tokens[0].value in {'nil', 'true', 'false'}:
            return swift_constant(tokens[0].value, 'code')
        elif tokens[0].value == '&':
            return self.expression(tokens[1:], state, bindings, depth + 1)
        else:
            name = tokens[0].value
            owner_binding = bindings.get(name, name)
            value = state.get(owner_binding, self.globals.get(name, CLEAN))
            if not value and name in {'req', 'request'} and name not in bindings and name not in state:
                value = swift_shape('request', tokens[0].start)
            if not value:
                functions = self.candidates(name, CLEAN, state, bindings)
                value = frozenset(Trace('function', (function.key,)) for function in functions)
            cursor = 1
        while cursor < len(tokens):
            self.budget.spend()
            token = tokens[cursor]
            if token.value in {'?', '!'}:
                cursor += 1
                continue
            if token.value == '.':
                if cursor + 1 >= len(tokens):
                    raise ValueError('Incomplete Swift member expression; analysis is incomplete')
                member = tokens[cursor + 1]
                name = name + '.' + member.value if name else member.value
                cursor += 2
                if cursor < len(tokens) and tokens[cursor].value == '(':
                    close = swift_close(tokens, cursor)
                    arguments = []
                    for part in swift_parts(tokens[cursor + 1:close], {','}):
                        if not part:
                            continue
                        label, argument = '', part
                        if len(part) >= 2 and part[1].value == ':' and part[0].kind == 'code':
                            label, argument = part[0].value, part[2:]
                        arguments.append((label, self.expression(argument, state, bindings, depth + 1), argument))
                    if member.value == 'appendingPathComponent' and value and all(
                            'file-url' in trace.tags and 'path-string' not in trace.tags for trace in value):
                        addition = join(*(fact for _, fact, _ in arguments))
                        value = join(retag(self.forget(value), add=frozenset({'file-url'})),
                                     retag(self.forget(addition, frozenset({'file-leaf'})), add=frozenset({'file-url'})),
                                     retag(swift_shape('file-url', member.start), add=frozenset({'file-url'})))
                    elif member.value == 'resolvingSymlinksInPath' and not arguments:
                        value = self.member(member.value, value, member, owner_binding)
                    else:
                        value = self.call(name, value, arguments, tokens[0], state, bindings, member)
                    cursor = close + 1
                else:
                    value = self.member(member.value, value, member, owner_binding)
                continue
            if token.value == '(':
                close = swift_close(tokens, cursor)
                arguments = []
                for part in swift_parts(tokens[cursor + 1:close], {','}):
                    if not part:
                        continue
                    label, argument = '', part
                    if len(part) >= 2 and part[1].value == ':' and part[0].kind == 'code':
                        label, argument = part[0].value, part[2:]
                    arguments.append((label, self.expression(argument, state, bindings, depth + 1), argument))
                value = self.call(name, value, arguments, tokens[0], state, bindings)
                cursor = close + 1
                continue
            if token.value == '[':
                close = swift_close(tokens, cursor)
                if swift_has_shape(value, 'request-collection'):
                    value = self.source(tokens[0].start, self.text[tokens[0].start:tokens[close].end])
                else:
                    value = join(value, self.expression(tokens[cursor + 1:close], state, bindings, depth + 1))
                cursor = close + 1
                continue
            if token.value == '{':
                raise ValueError('Swift escaping/trailing closure needs capture analysis; analysis is incomplete')
            # Preserve dependencies in selected casts, tuples and unfamiliar
            # operators, but do not preserve any validation across them.
            value = self.forget(join(value, self.expression(tokens[cursor + 1:], state, bindings, depth + 1)))
            break
        return value

    def check(self, name, tag, state, bindings):
        binding = bindings.get(name, name)
        value = state.get(binding, self.globals.get(name, CLEAN))
        if tag in SWIFT_LOCAL_TAGS:
            if not self.builtin('String') or any('file-url' in trace.tags or 'url-object' in trace.tags for trace in value):
                return state
            state[binding] = retag(value, add=frozenset({tag}))
            return state
        if tag in {'url-scheme', 'url-host'}:
            if value and all('url-object' in trace.tags for trace in value):
                state[binding] = retag(value, add=frozenset({tag}))
            else:
                property_name = 'scheme' if tag == 'url-scheme' else 'host'
                links = {item[len('property-of:'):] for trace in value for item in trace.tags
                         if item.startswith('property-of:') and 'url-property:' + property_name in trace.tags}
                for parent in links:
                    owner = state.get(parent, CLEAN)
                    identities = {item for trace in value for item in trace.tags if item.startswith('url-id:')}
                    if owner and all('url-object' in trace.tags and identities.intersection(trace.tags) for trace in owner):
                        state[parent] = retag(owner, add=frozenset({tag}))
            return state
        return state

    def proof(self, tokens, truth, state, bindings):
        tokens = swift_ungroup(tokens)
        if not tokens:
            return state
        if tokens[0].value == '!':
            return self.proof(tokens[1:], not truth, state, bindings)
        text = swift_text(tokens)
        prefix = re.fullmatch(r'([A-Za-z_]\w*)\.(hasPrefix|contains)\((.*)\)', text, re.DOTALL)
        if prefix:
            name, method = prefix.group(1), prefix.group(2)
            opening = next((index for index, token in enumerate(tokens) if token.value == '('), None)
            argument = swift_ungroup(tokens[opening + 1:-1]) if opening is not None else ()
            literal = argument[0].value if len(argument) == 1 and argument[0].kind == 'literal' else None
            tag = None
            if method == 'hasPrefix' and literal == '/' and truth:
                tag = 'local-slash'
            elif method == 'hasPrefix' and literal == '//' and not truth:
                tag = 'not-network-path'
            elif method == 'contains' and not truth:
                tag = {'\\': 'no-backslash', '\t': 'no-tab', '\r': 'no-carriage-return', '\n': 'no-newline'}.get(literal)
            if tag:
                return self.check(name, tag, state, bindings)
        comparison = swift_parts(tokens, {'==', '!='})
        if len(comparison) == 2:
            operator = tokens[len(comparison[0])].value
            equal = truth == (operator == '==')
            if equal:
                for lhs, rhs in (comparison, tuple(reversed(comparison))):
                    right = swift_ungroup(rhs)
                    literal = right[0].value if len(right) == 1 and right[0].kind == 'literal' else None
                    member = re.fullmatch(r'([A-Za-z_]\w*)\.(scheme|host)', swift_text(lhs))
                    name = member.group(1) if member else swift_text(lhs)
                    if literal is not None and re.fullmatch(r'[A-Za-z_]\w*', name):
                        value = state.get(bindings.get(name, name), self.globals.get(name, CLEAN))
                        is_scheme = member and member.group(2) == 'scheme' or any('url-property:scheme' in trace.tags for trace in value)
                        is_host = member and member.group(2) == 'host' or any('url-property:host' in trace.tags for trace in value)
                        if is_scheme and literal == 'https':
                            state = self.check(name, 'url-scheme', state, bindings)
                        if is_host and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', literal):
                            state = self.check(name, 'url-host', state, bindings)
        membership = re.fullmatch(r'([A-Za-z_]\w*)\.contains\(([A-Za-z_]\w*(?:\.(?:host|scheme))?)\)', text)
        if membership and truth:
            allowlist, selected = membership.groups()
            allowed = state.get(bindings.get(allowlist, allowlist), self.globals.get(allowlist, CLEAN))
            literals = {trace.key[1] for trace in allowed if trace.kind == 'constant' and trace.key[0] == 'literal'}
            if swift_has_shape(allowed, 'literal-list') and not swift_tainted(allowed) and literals:
                variable = selected.split('.')[0]
                fact = state.get(bindings.get(variable, variable), CLEAN)
                if selected.endswith('.scheme') or any('url-property:scheme' in trace.tags for trace in fact):
                    if literals == {'https'}:
                        state = self.check(variable, 'url-scheme', state, bindings)
                elif all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', literal) for literal in literals):
                    state = self.check(variable, 'url-host', state, bindings)
        containment = re.fullmatch(r'([A-Za-z_]\w*)\.path\.hasPrefix\(([A-Za-z_]\w*)\.path\+([\'\"])/\3\)', text)
        equality = re.fullmatch(r'([A-Za-z_]\w*)\.path==([A-Za-z_]\w*)\.path', text)
        match = containment or equality
        if match and truth:
            selected, root = match.group(1), match.group(2)
            root_value = state.get(bindings.get(root, root), self.globals.get(root, CLEAN))
            binding = bindings.get(selected, selected)
            value = state.get(binding, CLEAN)
            if root_value and not swift_tainted(root_value) and any('file-url' in trace.tags for trace in root_value):
                state[binding] = join(*(retag(frozenset({trace}), add=frozenset({'contained-path'}))
                    if {'file-url', 'canonical-path'} <= trace.tags else frozenset({trace}) for trace in value))
        return state

    def graph(self, function):
        actions, edges = {}, {}
        scope = {name: 'parameter:' + name for name, _, _, _ in function.parameters}

        def node(kind, tokens=(), bindings=None, targets=(), extra=None, reads=None):
            self.budget.spend()
            key = len(actions)
            local = {} if bindings is None else dict(bindings)
            actions[key], edges[key] = (kind, tokens, local, extra, local if reads is None else dict(reads)), tuple(targets)
            return key

        exit_node = node('exit', bindings=scope)

        def condition(tokens, yes, no, bindings, reads=None):
            tokens = swift_ungroup(tokens)
            commas = swift_parts(tokens, {','})
            conjunction = swift_parts(tokens, {'&&'})
            disjunction = swift_parts(tokens, {'||'})
            if len(commas) > 1:
                snapshots, local = [], dict(bindings if reads is None else reads)
                for part in commas:
                    before = dict(local)
                    assignment = self.parser.assignment(part)
                    if assignment and assignment[-1] and assignment[0]:
                        local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                    snapshots.append((dict(local), before))
                for part, (local, before) in reversed(list(zip(commas, snapshots))):
                    yes = condition(part, yes, no, local, before)
                return yes
            if len(conjunction) > 1:
                for part in reversed(conjunction):
                    yes = condition(part, yes, no, bindings)
                return yes
            if len(disjunction) > 1:
                for part in reversed(disjunction):
                    no = condition(part, yes, no, bindings)
                return no
            if tokens and tokens[0].value == '!':
                return condition(tokens[1:], no, yes, bindings, reads)
            assignment = self.parser.assignment(tokens)
            if assignment and assignment[-1]:
                return node('optional', tokens, bindings, (yes, no), reads=reads)
            if len(tokens) == 2 and tokens[0].value in {'let', 'var'}:
                return node('optional-shorthand', tokens, bindings, (yes, no), reads=reads)
            text = swift_text(tokens)
            positive = node('proof', tokens, bindings, (yes,), True)
            negative = node('proof', tokens, bindings, (no,), False)
            targets = (positive,) if text == 'true' else (negative,) if text in {'false', 'nil'} else (positive, negative)
            return node('eval', tokens, bindings, targets)

        def optional_scope(tokens, bindings):
            local = dict(bindings)
            for part in swift_parts(swift_ungroup(tokens), {','}):
                assignment = self.parser.assignment(part)
                if assignment and assignment[-1] and assignment[0]:
                    local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                elif len(part) == 2 and part[0].value in {'let', 'var'}:
                    local[part[1].value] = part[1].value + '@' + str(part[1].start)
            return local

        def terminates(statements):
            for statement in statements:
                if statement.kind in {'return', 'throw', 'break', 'continue'}:
                    return True
                if statement.kind == 'if' and terminates(statement.body) and terminates(statement.alternate):
                    return True
                if statement.kind == 'simple' and re.match(r'(?:fatalError|preconditionFailure)\(', swift_text(statement.tokens)):
                    return True
            return False

        def block(statements, following, bindings, break_to=None, continue_to=None):
            snapshots, local = [], dict(bindings)
            for statement in statements:
                before = dict(local)
                assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                if assignment and assignment[-1] and assignment[0]:
                    local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                declaration = self.parser.uninitialized(statement.tokens) if statement.kind == 'simple' else None
                if declaration:
                    local[declaration.value] = declaration.value + '@' + str(declaration.start)
                if statement.kind == 'guard':
                    local = optional_scope(statement.tokens, local)
                snapshots.append((dict(local), before))
            for statement, (local, before) in reversed(list(zip(statements, snapshots))):
                kind, tokens = statement.kind, statement.tokens
                if kind == 'definition':
                    continue
                if kind == 'if':
                    yes_scope = optional_scope(tokens, local)
                    yes = block(statement.body, following, yes_scope, break_to, continue_to)
                    no = block(statement.alternate, following, local, break_to, continue_to)
                    following = condition(tokens, yes, no, yes_scope, local)
                elif kind == 'guard':
                    if not terminates(statement.body):
                        raise ValueError('Swift guard else does not exit its enclosing scope; analysis is incomplete')
                    failure = block(statement.body, following, before, break_to, continue_to)
                    following = condition(tokens, following, failure, local, before)
                elif kind == 'while':
                    loop = node('branch')
                    inner = optional_scope(tokens, local)
                    body = block(statement.body, loop, inner, following, loop)
                    edges[loop] = (condition(tokens, body, following, inner, local),)
                    following = loop
                elif kind == 'for':
                    parts = swift_parts(tokens, {'in'})
                    names = swift_ungroup(parts[0])
                    if len(parts) != 2 or len(names) != 1 or names[0].kind != 'code':
                        raise ValueError('Swift iteration binding needs pattern analysis; analysis is incomplete')
                    inner = dict(local)
                    inner[names[0].value] = names[0].value + '@' + str(names[0].start)
                    loop = node('branch')
                    body = block(statement.body, loop, inner, following, loop)
                    bound = node('element', parts[1], inner, (body,), names[0].value, reads=local)
                    edges[loop] = (bound, following)
                    following = loop
                elif kind in {'break', 'continue'}:
                    target = break_to if kind == 'break' else continue_to
                    if target is None or tokens:
                        raise ValueError('Swift labeled/nonlocal loop exit needs control-flow analysis; analysis is incomplete')
                    following = node('branch', targets=(target,))
                elif kind in {'return', 'throw'}:
                    following = node(kind, tokens, local, (exit_node,) if kind == 'return' else ())
                else:
                    following = node(kind, tokens, local, (following,), reads=before)
            return following

        return block(function.body, exit_node, scope), actions, edges

    def transfer(self, action, state):
        if not state.get('@reachable'):
            return state
        kind, tokens, bindings, extra, reads = action
        if kind == 'branch':
            return state
        if kind == 'exit':
            self.returned = join(self.returned, state.get('@result', CLEAN))
            for index, (name, _, declaration, _) in enumerate(self.function.parameters):
                if declaration.startswith('inout'):
                    self.mutations[index] = join(self.mutations.get(index, CLEAN), state.get('parameter:' + name, CLEAN))
            return state
        if kind == 'proof':
            return self.proof(tokens, extra, state, bindings)
        if kind in {'unsupported', 'closure'}:
            raise ValueError('Unsupported Swift control flow or closure; analysis is incomplete')
        if kind == 'element':
            value = self.expression(tokens, state, reads)
            state[bindings[extra]] = advance(value, self.step(tokens[0].start, 'assign', extra))
            return state
        if kind == 'optional-shorthand':
            name = tokens[1].value
            state[bindings.get(name, name)] = state.get(reads.get(name, name), CLEAN)
            return state
        declaration = self.parser.uninitialized(tokens) if kind == 'simple' else None
        if declaration:
            state.pop(bindings.get(declaration.value, declaration.value), None)
            return state
        assignment = self.parser.assignment(tokens) if kind in {'simple', 'optional'} else None
        if kind == 'optional' and not assignment:
            raise ValueError('Unsupported Swift optional binding; analysis is incomplete')
        if assignment:
            name, lhs, rhs, operator, _ = assignment
            value = self.expression(rhs, state, reads)
            if not name:
                header = swift_text(lhs)
                header_assignment = re.fullmatch(r'(?:[A-Za-z_]\w*\.)?headers\[([\'\"])([^\'\"]+)\1\]', header, re.IGNORECASE)
                if header_assignment:
                    if self.policy == 'redirect' and header_assignment.group(2).lower() == 'location':
                        self.record(lhs[0].start, value)
                    return state
                member = re.fullmatch(r'([A-Za-z_]\w*)\.[A-Za-z_]\w*', header)
                if member:
                    self.mutate(member.group(1), value, state, bindings)
                    return state
                if swift_tainted(value):
                    raise ValueError('Swift request-derived field/element write needs heap analysis; analysis is incomplete')
                return state
            binding = bindings.get(name, name)
            if operator != '=':
                value = self.forget(join(state.get(reads.get(name, name), CLEAN), value))
            self.invalidate_properties(binding, state)
            state[binding] = advance(value, self.step(lhs[0].start, 'assign', name))
            if name in self.local_globals and binding == name and swift_tainted(value):
                raise ValueError('Swift request-derived global write needs shared-state analysis; analysis is incomplete')
            return state
        value = self.expression(tokens, state, bindings)
        if kind == 'return':
            state['@result'] = advance(value, self.step(tokens[0].start if tokens else self.function.key, 'return', self.function.name))
        return state

    def analyze(self):
        changed = True
        while changed:
            changed = False
            before = len(self.contexts)
            # Keep the last complete iteration's observations, not guesses
            # made before a selected callee's return summary was available.
            self.url_reads = {}
            for key, function in tuple(self.contexts.items()):
                self.budget.spend()
                self.function, self.effects, self.mutations, self.returned = function, {}, {}, CLEAN
                if function.key not in self.graphs:
                    self.graphs[function.key] = self.graph(function)
                entry, actions, edges = self.graphs[function.key]
                initial = dict(self.globals)
                initial['@reachable'] = swift_constant('true', 'code')
                for index, (name, _, declaration, _) in enumerate(function.parameters):
                    value = key[1][index]
                    if re.fullmatch(r'(?:Vapor\.)?Request\??', declaration):
                        value = join(value, swift_shape('request', function.key))
                    elif re.fullmatch(r'(?:inout)?(?:Swift\.)?String\??', declaration):
                        value = retag(value, add=frozenset({'swift-string'}))
                    elif declaration in self.parser.types:
                        kind = 'instance:' if declaration in self.parser.final_types else 'dynamic-instance:'
                        value = join(value, swift_shape(kind + declaration, function.key))
                    initial['parameter:' + name] = value
                if function.owner:
                    owner = '.'.join(function.owner)
                    kind = 'instance:' if owner in self.parser.final_types else 'dynamic-instance:'
                    initial['self'] = swift_shape(kind + owner, function.key)
                solve(entry, initial, edges, lambda node, state: self.transfer(actions[node], state), self.budget)
                updated = self.summaries[key].merged(SwiftSummary(self.returned, self.effects, self.mutations))
                if updated != self.summaries[key]:
                    self.summaries[key], changed = updated, True
            changed = changed or before != len(self.contexts)
        effects = {}
        for summary in self.summaries.values():
            for offset, value in summary.effects.items():
                sink = self.step(offset, 'sink', 'redirect' if self.policy == 'redirect' else 'file sink')
                effects[offset] = join(effects.get(offset, CLEAN), advance(swift_tainted(value), sink))
        return effects


def file_url_read_offsets(path, text):
    """Character offsets of proven native String/Data file-URL readers.

    The caller can exclude these from HTTP/SSRF findings even when the file
    path itself is unsafe; path traversal is a distinct sink obligation. A
    mixed/unknown URL kind never qualifies. Unsupported flow propagates its
    error rather than granting a file-only exemption. Offsets identify the
    String or Data identifier, including a qualified Foundation.String call,
    so another network read on the same physical line remains an obligation.
    Every selected call context contributes to the site's final value facts.
    """
    parser = SwiftParser(text)
    engine = SwiftEngine(path, text, 'path', parser)
    engine.analyze()
    return frozenset(offset for offset, value in engine.url_reads.items()
        if value and all('file-url' in trace.tags and 'path-string' not in trace.tags for trace in value))


def flow_findings(path, text, policy='path'):
    parser = SwiftParser(text)
    # Lexing and delimiter validation still run on every selected source.
    # With no selected request source, there is no source-to-sink obligation
    # for these two policies; unrelated Swift closure/actor syntax belongs to
    # its own analyzer rather than being misreported as a failed taint pass.
    if not swift_source_tokens(parser.tokens):
        return []
    engine = SwiftEngine(path, text, policy, parser)
    rule = 'swift.taint.request_open_redirect' if policy == 'redirect' else 'swift.taint.request_path_traversal'
    suppression = SourceSuppressions('swift')
    suppression.index(path, text)
    findings, seen = [], set()
    for offset, value in sorted(engine.analyze().items()):
        traces = sorted(value, key=lambda trace: (len(trace.evidence), trace.evidence, trace.key))
        if not traces:
            continue
        sink = engine.step(offset, 'sink', 'redirect' if policy == 'redirect' else 'file sink')
        if sink.line in seen or suppression.is_suppressed(path, sink.line, rule):
            continue
        seen.add(sink.line)
        findings.append(dict(rule=rule, path=str(path.resolve()), line=sink.line, col=sink.column,
            lang='swift', layer='taint', severity='critical',
            message='Unvalidated redirect from request data' if policy == 'redirect' else 'Request-derived path reaches file read/write/serve sink',
            extras={'taint_path': [step.record() for step in traces[0].evidence],
                    'source_count': len({trace.key for trace in traces})}))
    return findings

SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'DerivedData', 'build', 'dist', 'vendor', '.build', '.swiftpm'}


def should_skip(path: Path, base: Path) -> bool:
    try:
        parts = path.relative_to(base).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)


def iter_swift_files(path: Path, base: Path):
    if path.is_file():
        if path.suffix == '.swift':
            yield path
        return
    for candidate in path.rglob('*.swift'):
        if candidate.is_file() and not should_skip(candidate, base):
            yield candidate


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return path.name


def source_line(lines, line_no):
    idx = line_no - 1
    return lines[idx].strip() if 0 <= idx < len(lines) else ''


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, int, str]]:
    """Return count/sample records from the same structured flow analysis."""
    lines = text.splitlines()
    return [(rel(path, base), finding['line'], source_line(lines, finding['line']))
            for finding in flow_findings(path, text)]


def collect_findings(root: Path) -> list[tuple[str, int, str]]:
    root = Path(root).resolve()
    base = root if root.is_dir() else root.parent
    findings: list[tuple[str, int, str]] = []
    for path in iter_swift_files(root, base):
        text = path.read_text(encoding='utf-8', errors='replace')
        findings.extend(scan_text(path, text, base))
    return findings


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: taint_swift_traversal.py <project_dir>", file=sys.stderr)
        return 2
    findings = collect_findings(Path(sys.argv[1]).resolve())
    samples = '; '.join(f'{file}:{line}:{code}' for file, line, code in findings[:3])
    print(f"{len(findings)}\t{samples}")
    return 0


_MESSAGE = "Request-derived path reaches file read/write/serve sink"


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix != '.swift':
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        yield from flow_findings(path, text)


def _selftest_detects_tainted_file_sink() -> None:
    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path)\n"
        "}\n"
    )
    findings = scan_text(Path("F.swift"), code, Path("."))
    assert len(findings) == 1, findings
    assert findings[0][1] == 4, findings
    assert findings[0][2] == "return try String(contentsOfFile: path)", findings


def _selftest_basename_suppression() -> None:
    code = (
        "func safeRead(req: Request) throws -> String {\n"
        "    let requested = req.query[\"file\"] ?? \"index.html\"\n"
        "    let name = URL(fileURLWithPath: requested).lastPathComponent\n"
        "    return try String(contentsOfFile: name)\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path) // ubs:ignore\n"
        "}\n"
    )
    assert scan_text(Path("F.swift"), code, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_taint_swift_traversal_") -> None:
    import tempfile

    code = (
        "func readDownload(req: Request) throws -> String {\n"
        "    let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
        "    let path = documentRoot + \"/\" + requestedName\n"
        "    return try String(contentsOfFile: path)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "F.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.taint.request_path_traversal", findings
    assert findings[0]["line"] == 4, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_tainted_file_sink", _selftest_detects_tainted_file_sink),
    ("basename_suppression", _selftest_basename_suppression),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("run_finds_traversal", _selftest_run),
)

register(Analyzer(layer="taint", lang="swift", name="taint_swift_traversal", run=run, selftests=SELF_TESTS))
