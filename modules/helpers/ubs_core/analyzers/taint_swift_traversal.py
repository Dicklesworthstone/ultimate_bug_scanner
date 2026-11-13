"""Scoped Swift request dataflow for file, redirect, header and HTTP sinks.

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
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join, join_states, solve


@dataclass(frozen=True)
class SwiftToken:
    value: str
    start: int
    end: int
    kind: str = 'code'
    parts: tuple = ()


@dataclass(frozen=True)
class CallSite:
    """Keep the whole-expression origin separate from a fluent callee."""
    expression: SwiftToken
    callee: SwiftToken | None = None


class SwiftUnsupported(ValueError):
    """A well-formed construct whose effects need a conservative summary.

    Proof consumers propagate this exception. The ordinary scanner can report
    the affected scope and continue; lexical errors and work limits are never
    converted into this diagnostic.
    """
    def __init__(self, message, offset=None):
        super().__init__(message)
        self.offset = offset


class SwiftLexer:
    _literal_start = re.compile(r'#*"|#+/')
    _literal_marker = re.compile(r'(#*)("""|"|/)')
    _unicode_escape = re.compile(r'u\{([0-9a-fA-F]{1,8})\}')
    _token = re.compile(r'[A-Za-z_$][A-Za-z_0-9$]*|\d+(?:\.\d+)?|\.\.\.|\.\.<|->|==|!=|<=|>=|&&|\|\||\?\?|\+=|-=|\*=|/=')

    def __init__(self, text):
        self.text = text
        self.budget = Budget(max(1000, len(text) * 16))

    def comment(self, start, limit):
        if self.text.startswith('//', start, limit):
            finish = self.text.find('\n', start, limit)
            return limit if finish < 0 else finish
        cursor, nesting = start + 2, 1
        while cursor < limit:
            self.budget.spend()
            if self.text.startswith('/*', cursor, limit):
                nesting += 1
                cursor += 2
            elif self.text.startswith('*/', cursor, limit):
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
        marker = self._literal_marker.match(self.text, start, limit)
        if marker is None:
            raise ValueError('Invalid Swift literal; analysis is incomplete')
        hashes, quote = marker.groups()
        closing, escape = quote + hashes, '\\' + hashes
        cursor, content, holes = marker.end(), [], []
        while cursor < limit:
            self.budget.spend()
            if self.text.startswith(closing, cursor, limit):
                kind = 'regex' if quote == '/' else 'template' if holes else 'literal'
                return SwiftToken(''.join(content), start, cursor + len(closing), kind, tuple(holes))
            if self.text.startswith(escape + '(', cursor, limit) and quote != '/':
                opening = cursor + len(escape)
                part, finish = self.interpolation(opening + 1, limit, depth + 1)
                holes.append(part)
                cursor = finish + 1
                continue
            if self.text.startswith(escape, cursor, limit):
                after = cursor + len(escape)
                if after >= limit:
                    break
                char = self.text[after]
                unicode_escape = self._unicode_escape.match(self.text, after, limit)
                if unicode_escape:
                    try:
                        content.append(chr(int(unicode_escape.group(1), 16)))
                    except ValueError as error:
                        raise ValueError('Invalid Swift Unicode escape; analysis is incomplete') from error
                    cursor = unicode_escape.end()
                else:
                    content.append({'n': '\n', 'r': '\r', 't': '\t', '0': '\0'}.get(char, char))
                    cursor = after + 1
                continue
            if quote == '"' and self.text[cursor] in '\r\n':
                raise ValueError('Unterminated Swift string; analysis is incomplete')
            content.append(self.text[cursor])
            cursor += 1
        raise ValueError('Unterminated Swift literal; analysis is incomplete')

    def interpolation(self, start, limit, depth):
        # The interpolation is executable Swift. Use the same lexer for its
        # boundary and its tokens: regexes, nested strings and comments can all
        # contain parentheses which do not close the surrounding expression.
        # Retaining the tokens also avoids repeatedly lexing nested holes.
        tokens, nesting = [], 1
        for token in self.tokens(start, limit, depth):
            if token.kind == 'code' and token.value == '(':
                nesting += 1
            elif token.kind == 'code' and token.value == ')':
                nesting -= 1
                if not nesting:
                    return tuple(tokens), token.start
            tokens.append(token)
        raise ValueError('Unterminated Swift interpolation; analysis is incomplete')

    def scan(self, start=0, limit=None, depth=0):
        return tuple(self.tokens(start, limit, depth))

    def tokens(self, start=0, limit=None, depth=0):
        text, cursor = self.text, start
        limit = len(text) if limit is None else limit
        prev_significant = None
        while cursor < limit:
            self.budget.spend()
            char = text[cursor]
            if char in ' \t\r':
                cursor += 1
                continue
            if text.startswith(('//', '/*'), cursor, limit):
                finish = self.comment(cursor, limit)
                for position in range(cursor, finish):
                    if text[position] == '\n':
                        yield SwiftToken('\n', position, position + 1)
                cursor = finish
                continue
            regex = char == '/' and (
                prev_significant is None
                or (prev_significant.kind == 'code'
                    and prev_significant.value in {'=', '(', '[', ',', ':', 'return'})
            )
            # Match in the original source. Copying the entire suffix for
            # every token makes lexing quadratic on production Swift files,
            # including repeated scans of interpolations and callback bodies.
            if self._literal_start.match(text, cursor, limit) or regex:
                token = self.literal(cursor, limit, depth)
                yield token
                prev_significant = token
                cursor = token.end
                continue
            if char == '`':
                finish = text.find('`', cursor + 1, limit)
                if finish < 0:
                    raise ValueError('Unterminated Swift identifier; analysis is incomplete')
                token = SwiftToken(text[cursor + 1:finish], cursor, finish + 1)
                yield token
                prev_significant = token
                cursor = finish + 1
                continue
            match = self._token.match(text, cursor, limit)
            finish = match.end() if match else cursor + 1
            token = SwiftToken(text[cursor:finish], cursor, finish,
                               'number' if char.isdigit() else 'code')
            yield token
            if token.value.strip():
                prev_significant = token
            cursor = finish


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


def swift_validated_tokens(text):
    """Always validate lexical structure before deciding a policy is inapplicable."""
    tokens = SwiftLexer(text).scan()
    swift_validate_structure(tokens)
    return tokens


def swift_validate_structure(tokens):
    cursor = 0
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.kind == 'code' and token.value in {'(', '[', '{'}:
            cursor = swift_close(tokens, cursor)
        elif token.kind == 'code' and token.value in {')', ']', '}'}:
            raise ValueError('Unbalanced Swift delimiters; analysis is incomplete')
        cursor += 1
    # Do not miss a template nested inside an already balanced outer group.
    for token in tokens:
        for part in token.parts:
            swift_validate_structure(part)


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
    parameter_attributes: tuple = ()
    generic: bool = False


class SwiftParser:
    def __init__(self, text, tokens=None, suppressed=frozenset(), obligation=None, *, recover=False):
        self.tokens = swift_validated_tokens(text) if tokens is None else tokens
        code = tuple(token for token in self.tokens if token.kind == 'code' and token.value != '\n')
        # Aliases/associated types can shadow standard protocols even when
        # declared inside a nominal type. Alias expansion is not native proof.
        self.shadow_type_names = {right.value for left, right in zip(code, code[1:])
                                  if left.value in {'typealias', 'associatedtype'}}
        self.type_alias_names = {right.value for left, right in zip(code, code[1:])
                                if left.value == 'typealias'}
        self.suppressed = suppressed
        self.obligation = obligation
        self.recover, self.diagnostics = recover, []
        self.functions, self.types, self.extensions, self.final_types = {}, set(), set(), set()
        self.value_types, self.protocols = set(), set()
        self.fields, self.field_functions = {}, {}
        self.opaque_fields = {}
        self.stored_fields, self.type_declarations = {}, {}
        self.initialization_limits = {}
        self.generic_types = set()
        self.enum_cases = {}
        self.aliased_types, previous = set(), None
        for token in self.tokens:
            if token.kind == 'code' and token.value == '\n':
                continue
            if previous is not None and previous.kind == 'code' and previous.value in {'typealias', 'associatedtype'}:
                self.aliased_types.add(token.value)
            previous = token
        self.synthetic_initializers = set()
        body = self.block(self.tokens, (), (), declarations=True)
        self.synthesize_initializers()
        self.functions[-1] = SwiftFunction(-1, '<script>', (), (), (), body)

    def synthesize_initializers(self):
        """Materialize selected Swift memberwise/default initialization.

        A struct's stored-property order determines its memberwise labels.
        Constant let defaults are initialized once and are not parameters.
        Inheritance, wrappers, lazy storage and conditional field declarations
        are deliberately outside this bounded layout model.
        """
        for owner, (kind, token, header) in self.type_declarations.items():
            if kind not in {'struct', 'class', 'actor'} or any(
                    function.name == 'init' and function.owner == owner
                    for function in self.functions.values()):
                continue
            parameters, body = [], []
            for name, (declaration, default, mutable, field_token, reason) in self.stored_fields.get(owner, {}).items():
                if reason:
                    continue
                if kind != 'struct' or (default and not mutable):
                    continue
                if not default and mutable and declaration.endswith('?'):
                    default = (replace(field_token, value='nil'),)
                parameters.append((name, name, declaration, default))
                tokens = tuple(replace(field_token, value=value) for value in ('self', '.', name, '=', name))
                body.append(SwiftStatement('simple', tokens))
            key = token.start
            self.functions[key] = SwiftFunction(key, 'init', owner, (), tuple(parameters), tuple(body))
            self.synthetic_initializers.add(key)

    def limitation(self, reason, tokens, owner):
        offset = tokens[0].start if tokens else 0
        if not self.recover:
            raise SwiftUnsupported(reason + '; analysis is incomplete', offset)
        self.diagnostics.append((offset, reason, owner))

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
                    if previous not in continuation and next_value not in {'.', '&&', '||', '??', '+', ',', 'catch'}:
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
            modifiers = {'public', 'private', 'fileprivate', 'internal', 'open', 'final', 'static', 'class', 'mutating', 'nonmutating', 'override', 'nonisolated', 'indirect', 'required', 'convenience', 'lazy', 'weak', 'unowned'}
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
                if head < len(tokens) and tokens[head].value == '(':
                    head = swift_close(tokens, head) + 1
            constructor = (declarations and owner and head < len(tokens)
                           and tokens[head].value in {'init', 'deinit'})
            if head < len(tokens) and (tokens[head].value == 'func' or constructor):
                name_index = head if constructor else head + 1
                if name_index >= len(tokens):
                    raise ValueError('Missing Swift function name; analysis is incomplete')
                name, opening = tokens[name_index].value, name_index + 1
                # The general lexer keeps assignment punctuation separate.
                # Recognize the matching operator in declaration position so
                # pattern analysis can retain an explicit overload boundary.
                if (not constructor and name == '~' and opening < len(tokens)
                        and tokens[opening].value == '=' and tokens[name_index].end == tokens[opening].start):
                    name, opening = '~=', opening + 1
                if constructor and opening < len(tokens) and tokens[opening].value in {'?', '!'}:
                    opening += 1
                if name == 'deinit':
                    while opening < len(tokens) and tokens[opening].value != '{':
                        opening += 1
                    if opening >= len(tokens):
                        raise ValueError('Unterminated Swift deinitializer; analysis is incomplete')
                    finish, key = swift_close(tokens, opening), tokens[head].start
                    function = SwiftFunction(key, name, owner, scope, ())
                    self.functions[key] = function
                    function.body = self.block(tokens[opening + 1:finish], owner, (*scope, key), depth=depth + 1)
                    statements.append(SwiftStatement('definition', tuple(tokens[start:finish + 1]), extra=(key,)))
                    cursor = finish + 1
                    continue
                generic = opening < len(tokens) and tokens[opening].value == '<'
                if generic:
                    while opening < len(tokens) and tokens[opening].value != '>':
                        opening += 1
                    opening += 1
                if opening >= len(tokens) or tokens[opening].value != '(':
                    raise ValueError('Unsupported Swift function declaration; analysis is incomplete')
                close = swift_close(tokens, opening)
                parameters, parameter_attributes = [], []
                for part in swift_parts(tokens[opening + 1:close], {','}, generics=True):
                    part = swift_ungroup(part)
                    if not part:
                        continue
                    pieces = swift_parts(part, {':'})
                    if len(pieces) != 2:
                        raise ValueError('Unsupported Swift parameter binding; analysis is incomplete')
                    label_tokens, attribute_end = pieces[0], 0
                    while attribute_end < len(label_tokens) and label_tokens[attribute_end].value == '@':
                        attribute_end += 1
                        if attribute_end == len(label_tokens) or not re.fullmatch(r'[A-Za-z_]\w*', label_tokens[attribute_end].value):
                            raise ValueError('Unsupported Swift parameter attribute; analysis is incomplete')
                        attribute_end += 1
                        while attribute_end + 1 < len(label_tokens) and label_tokens[attribute_end].value == '.':
                            attribute_end += 2
                        if attribute_end < len(label_tokens) and label_tokens[attribute_end].value == '(':
                            attribute_end = swift_close(label_tokens, attribute_end) + 1
                    attributes = swift_text(label_tokens[:attribute_end])
                    names = [item.value for item in label_tokens[attribute_end:] if item.kind == 'code']
                    if not 1 <= len(names) <= 2:
                        raise ValueError('Unsupported Swift parameter labels; analysis is incomplete')
                    default = swift_parts(pieces[1], {'='})
                    declaration = swift_text(default[0])
                    parameters.append((names[-1], '' if names[0] == '_' else names[0], declaration,
                                       default[1] if len(default) == 2 else ()))
                    parameter_attributes.append(attributes)
                body_start = close + 1
                while body_start < len(tokens) and tokens[body_start].value not in {'{', ';'}:
                    body_start += 1
                if body_start == len(tokens) or tokens[body_start].value != '{':
                    cursor = self.statement_end(tokens, close + 1) + 1
                    continue
                finish = swift_close(tokens, body_start)
                key = tokens[head].start
                function = SwiftFunction(key, name, owner, scope, tuple(parameters),
                                         static=any(token.value in {'static', 'class'} for token in tokens[start:head]),
                                         parameter_attributes=tuple(parameter_attributes), generic=generic)
                result_type = swift_parts(tokens[close + 1:body_start], {'->'})
                if len(result_type) == 2:
                    function.return_type = swift_text(swift_ungroup(result_type[1]))
                self.functions[key] = function
                body = self.block(tokens[body_start + 1:finish], owner, (*scope, key), depth=depth + 1)
                body = self.result_body(body) or body
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
                if kind != 'extension':
                    self.type_declarations[(*owner, name)] = (kind, tokens[head], tuple(tokens[head + 2:position]))
                    self.types.add('.'.join((*owner, name)))
                    if '<' in name:
                        base = name.split('<', 1)[0]
                        self.generic_types.update((base, '.'.join((*owner, base))))
                        self.types.update((base, '.'.join((*owner, base))))
                if kind in {'struct', 'enum'} or any(token.value == 'final' for token in tokens[start:head]):
                    self.final_types.add(name)
                    self.final_types.add('.'.join((*owner, name)))
                if kind in {'struct', 'enum'}:
                    self.value_types.add(name)
                    self.value_types.add('.'.join((*owner, name)))
                if kind == 'enum':
                    self.enum_cases.setdefault((*owner, name), set())
                if kind == 'protocol':
                    self.protocols.add(name)
                self.block(tokens[position + 1:finish], (*owner, name), scope, declarations=True, depth=depth + 1)
                statements.append(SwiftStatement('definition', tuple(tokens[start:finish + 1])))
                cursor = finish + 1
                continue
            first = tokens[start].value
            if first == 'repeat':
                opening = start + 1
                while opening < len(tokens) and tokens[opening].value == '\n':
                    opening += 1
                if opening >= len(tokens) or tokens[opening].value != '{':
                    raise ValueError('Swift repeat has no body; analysis is incomplete')
                close = swift_close(tokens, opening)
                tail = close + 1
                while tail < len(tokens) and tokens[tail].value == '\n':
                    tail += 1
                if tail >= len(tokens) or tokens[tail].value != 'while':
                    raise ValueError('Swift repeat block has no while condition; analysis is incomplete')
                condition_start = tail + 1
                while condition_start < len(tokens) and tokens[condition_start].value == '\n':
                    condition_start += 1
                finish = self.statement_end(tokens, condition_start)
                condition = tuple(tokens[condition_start:finish])
                if not condition:
                    raise ValueError('Swift repeat has an empty condition; analysis is incomplete')
                body = self.block(tokens[opening + 1:close], owner, scope, depth=depth + 1)
                statements.append(SwiftStatement('repeat', tuple(tokens[start:finish]), body,
                                                 extra=(condition,)))
                cursor = finish + 1
                continue
            if first == 'switch':
                opening = start + 1
                while opening < len(tokens) and tokens[opening].value != '{':
                    if tokens[opening].kind == 'code' and tokens[opening].value in {'(', '['}:
                        opening = swift_close(tokens, opening)
                    opening += 1
                if opening >= len(tokens) or not swift_ungroup(tokens[start + 1:opening]):
                    raise ValueError('Swift switch has no subject or body; analysis is incomplete')
                close = swift_close(tokens, opening)
                # Keep unknown label syntax attached to this complete switch.
                # Recovery can then mark its effects unknown without skipping
                # independently analyzable statements after it.
                try:
                    arms = self.switch_arms(tokens[opening + 1:close], owner, scope, depth + 1)
                except SwiftUnsupported:
                    arms = None
                if arms is None:
                    statements.append(SwiftStatement('unsupported', tuple(tokens[start:close + 1])))
                else:
                    statements.append(SwiftStatement('switch', tuple(tokens[start:close + 1]), arms,
                                                     extra=(tuple(tokens[start + 1:opening]),)))
                cursor = close + 1
                continue
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
            if declarations and owner and head < finish and tokens[head].value in {'case', 'typealias', 'associatedtype'}:
                # Enum cases and type requirements declare names. In particular,
                # CodingKeys.case fileName is not a read of an uploaded filename.
                if tokens[head].value == 'case' and owner in self.enum_cases:
                    for item in swift_parts(tokens[head + 1:finish], {','}):
                        item = swift_ungroup(item)
                        if item and item[0].kind == 'code' and re.fullmatch(r'[A-Za-z_]\w*', item[0].value):
                            self.enum_cases[owner].add(item[0].value)
                statements.append(SwiftStatement('definition', part))
                continue
            if declarations and owner:
                # Stored fields/accessors require an object state model. Never
                # silently discard an executable request source in this region.
                source_region = part
                if first == '#' or (head < finish and tokens[head].value in {'let', 'var'}
                        and not (head + 2 < finish and tokens[head + 2].value in {':', '='})):
                    self.initialization_limits[owner] = (
                        'Swift conditional or compound stored properties need layout analysis', part[0].start)
                if (head + 2 < finish and tokens[head].value in {'let', 'var'}
                        and re.fullmatch(r'[A-Za-z_]\w*', tokens[head + 1].value)
                        and tokens[head + 2].value in {':', '='}):
                    # A field's declared name is not a read of upload.filename.
                    # Keep attributes, types, initializers and getter bodies as
                    # witnesses, and retain the conservative request fields.
                    source_region = (*tokens[start:head], *tokens[head + 2:finish])
                    field_name = tokens[head + 1].value
                    declaration = swift_parts(tuple(tokens[head + 2:finish]), {'='})
                    field_type = swift_text(declaration[0][1:]) if declaration[0] and declaration[0][0].value == ':' else ''
                    self.fields.setdefault(owner, {})[field_name] = field_type
                    stored = len(declaration) == 2 or not any(t.value == '{' and t.kind == 'code' for t in declaration[0])
                    if stored and not any(t.value in {'static', 'class'} for t in tokens[start:head]):
                        prefix = {t.value for t in tokens[start:head]}
                        reason = ('Swift wrapped stored property needs initialization/accessor analysis'
                                  if '@' in prefix else
                                  'Swift lazy stored property needs deferred initialization analysis'
                                  if 'lazy' in prefix else '')
                        if len(declaration) > 2:
                            reason = 'Swift stored property declaration needs initialization analysis'
                        if len(declaration) == 2 and any(
                                t.value in {'willSet', 'didSet'} for t in declaration[1] if t.kind == 'code'):
                            reason = 'Swift property observer needs assignment binding analysis'
                        if len(declaration) == 2 and any(t.value == 'self' and t.kind == 'code' for t in declaration[1]):
                            reason = 'Swift stored initializer with self needs initialization-order analysis'
                        self.stored_fields.setdefault(owner, {})[field_name] = (
                            field_type, declaration[1] if len(declaration) == 2 else (),
                            tokens[head].value == 'var', tokens[head + 1], reason)
                    if len(declaration) == 1 and not any(t.value == '{' and t.kind == 'code' for t in declaration[0]):
                        continue
                    if len(declaration) == 2:
                        field_key = tokens[head].start
                        initializer = SwiftFunction(field_key, '<field:' + field_name + '>', owner, scope, (),
                                                    (SwiftStatement('return', declaration[1]),),
                                                    static=any(token.value in {'static', 'class'} for token in tokens[start:head]))
                        self.functions[field_key] = initializer
                        self.field_functions[(owner, field_name)] = field_key
                        statements.append(SwiftStatement('definition', part, extra=(field_key,)))
                        if self.obligation is not None and _swift_observer_obligation(part, self.obligation):
                            self.limitation('Swift property observer with a sink needs assignment binding analysis', part, owner)
                        continue
                accessor_brace = next((i for i in range(head, finish)
                                       if tokens[i].kind == 'code' and tokens[i].value == '{'), -1)
                if (accessor_brace >= 0 and tokens[head].value in {'var', 'let'}
                        and not any(tokens[i].kind == 'code' and tokens[i].value == '='
                                    for i in range(head, accessor_brace))):
                    body_close = swift_close(tokens, accessor_brace)
                    body_tokens = tokens[accessor_brace + 1:body_close]
                    head_body = [t for t in body_tokens if t.kind == 'code' and t.value != '\n']
                    if ('.'.join(owner) in self.protocols and head_body
                            and all(t.value in {'get', 'set', 'async', 'throws'} for t in head_body)):
                        # A protocol requirement declares dispatch, not an
                        # executable accessor body or a source of input.
                        continue
                    if head_body and head_body[0].value == 'get':
                        opening = next((i for i, t in enumerate(body_tokens)
                                        if t.kind == 'code' and t.value == '{'), -1)
                        closing = swift_close(body_tokens, opening) if opening >= 0 else -1
                        header = {t.value for t in body_tokens[:opening] if t.value != '\n'}
                        if (opening < 0 or not header <= {'get', 'async', 'throws'}
                                or any(t.value != '\n' for t in body_tokens[closing + 1:])):
                            reason = 'Swift property accessor needs binding analysis'
                            self.opaque_fields[(owner, tokens[head + 1].value)] = reason
                            if swift_source_tokens(source_region, self.suppressed):
                                self.limitation(reason, part, owner)
                            continue
                        body_tokens = body_tokens[opening + 1:closing]
                    elif head_body and head_body[0].value in {'set', 'willSet', 'didSet',
                            '_modify', 'unsafeAddress', 'unsafeMutableAddress', '@'}:
                        reason = 'Swift property accessor needs binding analysis'
                        self.opaque_fields[(owner, tokens[head + 1].value)] = reason
                        if swift_source_tokens(source_region, self.suppressed):
                            self.limitation(reason, part, owner)
                        continue
                    accessor_key = tokens[start].start
                    accessor = SwiftFunction(accessor_key, tokens[head + 1].value, owner, scope, (),
                                             static=any(token.value in {'static', 'class'} for token in tokens[start:head]))
                    self.functions[accessor_key] = accessor
                    self.field_functions[(owner, tokens[head + 1].value)] = accessor_key
                    accessor.body = self.block(body_tokens, owner, (*scope, accessor_key), depth=depth + 1)
                    accessor.body = self.result_body(accessor.body) or accessor.body
                    statements.append(SwiftStatement('definition', part, extra=(accessor_key,)))
                    continue
                if swift_source_tokens(source_region, self.suppressed):
                    self.limitation('Swift request-derived type initialization needs field analysis', part, owner)
                if self.obligation is not None:
                    obs_brace = next((i for i in range(head, finish) if tokens[i].kind == 'code' and tokens[i].value == '{'), -1)
                    if obs_brace >= 0 and _swift_observer_obligation(tokens[obs_brace + 1:swift_close(tokens, obs_brace)], self.obligation):
                        self.limitation('Swift property observer with a sink needs assignment binding analysis', part, owner)
                continue
            if first in {'import', 'typealias', 'case', '@'}:
                if first == 'typealias' and len(part) >= 2:
                    self.types.add(part[1].value)
                if first == '@' and swift_source_tokens(part, self.suppressed):
                    raise ValueError('Swift attributed executable declaration needs binding analysis; analysis is incomplete')
                statements.append(SwiftStatement('definition', part))
            elif first in {'switch', 'do', 'catch', 'defer', 'repeat'} or (
                    first == '#' and (len(part) < 2 or part[1].value not in {'expect', 'require'})):
                statements.append(SwiftStatement('unsupported', part))
            elif first == 'fallthrough':
                statements.append(SwiftStatement('fallthrough', part))
            elif first in {'return', 'throw', 'break', 'continue'}:
                statements.append(SwiftStatement(first, part[1:]))
            else:
                statements.append(SwiftStatement('simple', part))
        return tuple(statements)

    def switch_arms(self, tokens, owner, scope, depth):
        """Separate case labels from bodies without consuming nested cases."""
        arms, cursor, has_default = [], 0, False
        while cursor < len(tokens):
            if tokens[cursor].value in {'\n', ';'}:
                cursor += 1
                continue
            start = cursor
            if tokens[cursor].value == '@':
                if tuple(t.value for t in tokens[cursor:cursor + 3]) != ('@', 'unknown', 'default'):
                    raise SwiftUnsupported('Swift switch label attribute needs analysis; analysis is incomplete', tokens[cursor].start)
                cursor += 2
            if tokens[cursor].value not in {'case', 'default'}:
                raise SwiftUnsupported('Swift switch label needs pattern analysis; analysis is incomplete', tokens[cursor].start)
            marker = tokens[cursor].value
            if has_default:
                raise ValueError('Swift switch default must be the last case; analysis is incomplete')
            colon, ternary, where = cursor + 1, 0, False
            while colon < len(tokens):
                token = tokens[colon]
                if token.kind == 'code':
                    if token.value in {'(', '[', '{'}:
                        colon = swift_close(tokens, colon)
                    elif token.value == 'where':
                        where = True
                    elif (where and token.value == '?' and colon > cursor + 1
                          and token.start > tokens[colon - 1].end):
                        ternary += 1
                    elif token.value == ':':
                        if not ternary:
                            break
                        ternary -= 1
                colon += 1
            if colon >= len(tokens):
                raise ValueError('Swift switch case has no colon; analysis is incomplete')
            pattern = tuple(tokens[cursor + 1:colon])
            if marker == 'default':
                if swift_ungroup(pattern):
                    raise ValueError('Swift default label has a pattern; analysis is incomplete')
                has_default = True
            elif not swift_ungroup(pattern):
                raise ValueError('Swift case label has no pattern; analysis is incomplete')
            finish = colon + 1
            previous = ':'
            while finish < len(tokens):
                token = tokens[finish]
                if token.kind == 'code':
                    if token.value in {'(', '[', '{'}:
                        finish = swift_close(tokens, finish)
                    elif (token.value in {'case', 'default'}
                          and previous not in {'if', 'guard', 'while', 'for'}):
                        break
                    elif token.value == '@' and tuple(t.value for t in tokens[finish:finish + 3]) == ('@', 'unknown', 'default'):
                        break
                if token.value != '\n':
                    previous = tokens[finish].value
                finish += 1
            body = self.block(tokens[colon + 1:finish], owner, scope, depth=depth)
            if not body:
                raise ValueError('Swift switch case has no statements; analysis is incomplete')
            arms.append(SwiftStatement(marker, pattern, body,
                                       extra=(tokens[start].start,)))
            cursor = finish
        return tuple(arms)

    def result_body(self, statements, prefix=()):
        """Lower a single-expression branch to its return or assignment site.

        Swift switch/if expressions have a value in every arm. A statement
        switch with imperative arms is left alone by implicit-return callers;
        an explicit value context must refuse it if this returns None.
        """
        if len(statements) != 1:
            return None
        statement = statements[0]
        if statement.kind in {'simple', 'closure'} and not self.assignment(statement.tokens):
            result = (replace(statement, kind='simple', tokens=(*prefix, *statement.tokens)) if prefix
                      else replace(statement, kind='return'))
            return (result,)
        if statement.kind == 'switch':
            arms = []
            for arm in statement.body:
                body = self.result_body(arm.body, prefix)
                if body is None:
                    return None
                arms.append(replace(arm, body=body))
            return (replace(statement, body=tuple(arms)),)
        if statement.kind == 'if' and statement.alternate:
            body = self.result_body(statement.body, prefix)
            alternate = self.result_body(statement.alternate, prefix)
            if body is not None and alternate is not None:
                return (replace(statement, body=body, alternate=alternate),)
        return None

    @staticmethod
    def literal_pattern(tokens):
        def scalar(part):
            return (len(part) == 1 and (part[0].kind in {'number', 'literal'}
                    or part[0].kind == 'code' and part[0].value in {'true', 'false', 'nil'})
                    or len(part) == 2 and part[0].value in {'+', '-'} and part[1].kind == 'number')
        parts = swift_parts(tokens, {'...', '..<'})
        return len(parts) <= 2 and all(scalar(part) for part in parts)

    @staticmethod
    def assignment(tokens):
        parts = swift_parts(tokens, {'=', '+=', '-=', '*=', '/='})
        if len(parts) != 2:
            return None
        lhs = swift_ungroup(parts[0])
        if len(lhs) > 1 and lhs[0].value == 'async' and lhs[1].value == 'let':
            lhs = lhs[1:]
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
    def closure_signature(inner):
        """Separate a closure signature from its body without mistaking for/in.

        A signature may have actor attributes, capture bindings, typed
        parameters and async/throws/result annotations. Delimited expressions
        in capture initializers are skipped when finding the signature's in.
        """
        cursor, split = 0, None
        statements = {'for', 'if', 'guard', 'while', 'switch', 'repeat', 'do',
                      'defer', 'return', 'throw', 'let', 'var'}
        while cursor < len(inner):
            token = inner[cursor]
            if token.kind == 'code':
                if token.value in {'(', '['}:
                    cursor = swift_close(inner, cursor)
                elif token.value == 'in':
                    split = cursor
                    break
                elif token.value in statements | {'{', ';', '='}:
                    break
            cursor += 1
        if split is None:
            return (), (), tuple(inner), False
        header = swift_ungroup(inner[:split])
        body, captures, cursor = tuple(inner[split + 1:]), [], 0
        while cursor < len(header) and header[cursor].value == '@':
            if cursor + 1 >= len(header):
                raise ValueError('Malformed Swift closure attribute; analysis is incomplete')
            # Actor isolation and Sendable affect scheduling, not taint identity.
            cursor += 2
            if cursor < len(header) and header[cursor].value == '(':
                cursor = swift_close(header, cursor) + 1
        if cursor < len(header) and header[cursor].value == '[':
            close = swift_close(header, cursor)
            for capture in swift_parts(header[cursor + 1:close], {','}):
                capture = swift_ungroup(capture)
                if capture and capture[0].value in {'weak', 'unowned'}:
                    capture = capture[1:]
                    if capture and capture[0].value == '(':
                        capture = capture[swift_close(capture, 0) + 1:]
                pair = swift_parts(capture, {'='})
                if (len(pair) not in {1, 2} or len(pair[0]) != 1
                        or not re.fullmatch(r'[A-Za-z_]\w*', pair[0][0].value)):
                    raise SwiftUnsupported('Swift closure capture pattern needs binding analysis; analysis is incomplete', header[cursor].start)
                captures.append((pair[0][0], pair[-1]))
            cursor = close + 1
        signature = swift_parts(header[cursor:], {'->'})[0]
        while signature and signature[-1].value in {'async', 'throws', 'rethrows'}:
            signature = signature[:-1]
        signature = swift_ungroup(signature)
        parameters = []
        for part in swift_parts(signature, {','}):
            if not part:
                continue
            pieces = swift_parts(part, {':'})
            names = swift_ungroup(pieces[0])
            if len(names) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', names[0].value):
                raise SwiftUnsupported('Swift closure parameter pattern needs binding analysis; analysis is incomplete', part[0].start)
            parameters.append((names[0], swift_text(pieces[1]) if len(pieces) == 2 else ''))
        return tuple(captures), tuple(parameters), body, True

    @staticmethod
    def iteration_names(tokens, depth=0):
        """Bind only identifier/wildcard tuple patterns, never case/cast patterns."""
        if depth > 64:
            raise AnalysisLimit('Swift iteration pattern nesting limit exceeded; analysis is incomplete')
        tokens = tuple(token for token in tokens if token.kind != 'code' or token.value != '\n')
        if (len(tokens) == 1 and tokens[0].kind == 'code'
                and re.fullmatch(r'[A-Za-z_]\w*', tokens[0].value)
                and tokens[0].value not in {'case', 'let', 'var', 'await', 'try', 'in', 'where',
                                            'self', 'super', 'true', 'false', 'nil'}):
            return () if tokens[0].value == '_' else tokens
        if tokens and tokens[0].value == '(' and swift_close(tokens, 0) == len(tokens) - 1:
            names = tuple(name for part in swift_parts(tokens[1:-1], {','})
                          for name in SwiftParser.iteration_names(part, depth + 1))
            if len({name.value for name in names}) == len(names):
                return names
        raise SwiftUnsupported('Swift iteration binding needs pattern analysis; analysis is incomplete',
                               tokens[0].start if tokens else None)

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
    'serialized-url', 'file-url', 'path-string', 'canonical-path', 'contained-path', 'file-leaf',
    'url-components', 'http-request'})
SWIFT_LOCAL_TAGS = frozenset({'local-slash', 'not-network-path', 'no-backslash',
                            'no-tab', 'no-newline', 'no-carriage-return'})
SWIFT_HEADER_TAGS = frozenset({'no-newline', 'no-carriage-return'})
SWIFT_HTTP_METHODS = frozenset({'dataTask', 'downloadTask', 'uploadTask', 'streamTask',
    'webSocketTask', 'data', 'bytes', 'download', 'upload'})
SWIFT_CLIENT_METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete', 'head', 'fetch', 'request', 'send'})


def swift_retag(fact, *, add=frozenset(), remove=frozenset()):
    """Transform concrete Swift values without retaining summary operations.

    Swift calls are analyzed with their actual argument/receiver facts. Unlike
    parameterized summaries, they never substitute an incoming value through
    Trace.removed_tags. Keeping that operation history would distinguish equal
    values by every URL/property/field proof they previously lost, multiplying
    callback contexts even after all of those proofs have been invalidated.
    Current tags, origins and field paths remain distinct. When histories
    collapse, retain the same deterministic shortest evidence used by join().
    """
    result = {}
    for trace in fact:
        tags = (trace.tags - remove) | add
        updated = (trace if tags == trace.tags and not trace.removed_tags
                   else replace(trace, tags=tags, removed_tags=frozenset()))
        previous = result.get(updated)
        if previous is None or (len(updated.evidence), updated.evidence) < (len(previous.evidence), previous.evidence):
            result[updated] = updated
    return frozenset(result.values())


def swift_tainted(fact):
    return frozenset(trace for trace in fact if trace.kind == 'source')


def swift_constant(value, kind='literal'):
    return frozenset({Trace('constant', (kind, value), tags=frozenset({'swift-string'}) if kind == 'literal' else frozenset())})


def swift_shape(name, offset=-1):
    return frozenset({Trace('shape', (name, offset))})


def swift_field_path(trace):
    """A finite projection path, separate from the value's security proofs."""
    return next((tag[len('stored-field:'):].split('.') for tag in trace.tags
                 if tag.startswith('stored-field:')), ())


def swift_top(value):
    """Nested stored values are not the aggregate's callable/type identity."""
    return frozenset(trace for trace in value if not swift_field_path(trace))


def swift_has_shape(fact, name):
    return any(trace.kind == 'shape' and trace.key[0] == name for trace in swift_top(fact))


def swift_request_dependency(fact):
    return bool(swift_tainted(fact)) or any(trace.kind == 'shape' and trace.key[0]
        in {'request', 'request-collection', 'request-content'} for trace in fact)


def swift_source_witness_offsets(tokens, text, drop_lines):
    if not drop_lines:
        return frozenset()
    line_starts = [0, *(index + 1 for index, ch in enumerate(text) if ch == '\n')]
    witnesses = {'Request', 'req', 'request', 'filename', 'fileName', 'originalFilename', 'originalFileName'}
    offsets = set()
    def walk(items):
        for token in items:
            if token.kind == 'code' and token.value in witnesses and bisect_right(line_starts, token.start) in drop_lines:
                offsets.add(token.start)
            for part in token.parts:
                walk(part)
    walk(tokens)
    return frozenset(offsets)


def swift_taint_source_drops(path, text, tokens=None):
    """One source of truth for ubs:ignore[taint-source] drops in a swift file.

    Returns (offsets, drops, warnings): the witness offsets the activation gates
    drop, the applied drops [{path,line,reason}] (a witness on the marked line),
    and the warnings [{path,line}] (bad scope, empty reason, or a marker on a line
    with no witness). The engine and the listing both call this, so an applied
    drop is always listed; nothing is swallowed, so a parse failure fails closed.
    """
    from ubs_core.suppression import build_index
    if tokens is None:
        tokens = swift_validated_tokens(text)
    dropped, warned = build_index(text, 'swift').taint_source_drops()
    offsets = swift_source_witness_offsets(tokens, text, set(dropped))
    line_starts = [0, *(index + 1 for index, ch in enumerate(text) if ch == '\n')]
    active = {bisect_right(line_starts, offset) for offset in offsets}
    drops, warnings = [], []
    for line in sorted(warned):
        warnings.append({'path': str(path), 'line': line})
    for line, reason in sorted(dropped.items()):
        if line in active:
            drops.append({'path': str(path), 'line': line, 'reason': reason})
        else:
            warnings.append({'path': str(path), 'line': line})
    return offsets, drops, warnings


def swift_source_tokens(tokens, suppressed=frozenset()):
    # A request/filename *value/member* may be incoming data; an argument label
    # in Draft(request: draft) or IntentFile(filename: name) is not a value.
    # Only exclude a proven parenthesized label position, retaining dictionary keys, ternary values,
    # member access and interpolation as conservative source witnesses.
    tokens = tuple(token for token in tokens if token.kind != 'code' or token.value != '\n')
    delimiters = []
    closing = {')': '(', ']': '[', '}': '{'}
    for index, token in enumerate(tokens):
        if token.kind == 'code':
            if token.value == 'Request' and token.start not in suppressed:
                return True
            if token.value in {'req', 'request', 'filename', 'fileName', 'originalFilename', 'originalFileName'} and token.start not in suppressed:
                previous = tokens[index - 1] if index else None
                following = tokens[index + 1] if index + 1 < len(tokens) else None
                is_label = (
                    delimiters and delimiters[-1] == '('
                    and previous is not None and previous.kind == 'code' and previous.value in {'(', ','}
                    and following is not None and following.kind == 'code' and following.value == ':'
                )
                if not is_label:
                    return True
            if token.value in {'(', '[', '{'}:
                delimiters.append(token.value)
            elif token.value in closing and delimiters and delimiters[-1] == closing[token.value]:
                delimiters.pop()
        if any(swift_source_tokens(part, suppressed) for part in token.parts):
            return True
    return False


def swift_request_source_tokens(tokens, suppressed=frozenset()):
    """Keep unknown roots, but distinguish lexically bound Vision requests.

    This is only a negative source proof, not a source/sink suppression. Every
    req/request occurrence must resolve to a known native declaration in its
    lexical scope. Unknown/shadowed declarations, capture bindings, upload
    names and actual Request types keep the ordinary fail-closed analysis.
    """
    tokens = tuple(tokens)
    if not swift_source_tokens(tokens, suppressed):
        return False
    native = {'VNCoreMLRequest', 'VNGenerateImageFeaturePrintRequest', 'VNRecognizeTextRequest'}
    code = tuple(t for t in tokens if t.kind == 'code' and t.value != '\n')
    if not any(a.value == 'import' and b.value == 'Vision' for a, b in zip(code, code[1:])):
        return True
    # A locally declared framework type/function can return a web request.
    if any(b.value in native | {'Vision'} and a.value in {
            'class', 'struct', 'enum', 'actor', 'protocol', 'typealias', 'func', 'let', 'var', 'extension'}
           for a, b in zip(code, code[1:])):
        return True
    significant = tuple(t for t in tokens if t.kind != 'code' or t.value != '\n')
    budget = Budget()
    newlines = [t.start for t in tokens if t.kind == 'code' and t.value == '\n']
    for index, token in enumerate(significant):
        if token.kind != 'code' or token.value not in native | {'Vision'}:
            continue
        previous = significant[index - 1].value if index else ''
        following = significant[index + 1].value if index + 1 < len(significant) else ''
        if token.value == 'Vision':
            if previous == 'import' or following == '.' or (index >= 2 and
                    significant[index - 2].value == 'canImport' and previous == '('):
                continue
            return True
        if previous == '.' and (index < 2 or significant[index - 2].value != 'Vision'):
            return True
        if previous not in {':', '->', '.'} and following != '(':
            # In particular, a closure/generic/capture binding with the same
            # spelling is not the imported constructor.
            return True
    for index, token in enumerate(significant):
        if token.kind == 'code' and token.value in {'req', 'request'}:
            tail = significant[index + 1:index + 5]
            member = tuple(t.value for t in tail if t.value not in {'?', '!'})
            if len(member) >= 2 and member[0] == '.' and member[1] in {
                    'query', 'parameters', 'params', 'headers', 'content', 'url', 'uri'}:
                return True
        if token.kind == 'code' and token.value == 'for':
            end = index + 1
            while end < len(significant) and significant[end].value not in {'in', '{'}:
                end += 1
            if any(t.value in {'req', 'request'} for t in significant[index + 1:end]):
                return True
    if swift_source_tokens((t for t in significant if t.value not in {'req', 'request'}), suppressed):
        return True
    # Interpolations and nested patterns need their own binding model.
    if any(swift_source_tokens(part, suppressed) for t in tokens for part in t.parts):
        return True
    ranges, type_ranges, bindings, declarations = [], [], [], set()
    parents, stack = {}, []
    for index, token in enumerate(significant):
        parents[index] = stack[-1] if stack else ''
        if token.kind == 'code' and token.value in {'(', '[', '{'}:
            stack.append(token.value)
        elif token.kind == 'code' and token.value in {')', ']', '}'}:
            stack.pop()
    for index, token in enumerate(significant):
        if token.kind == 'code' and token.value == '{':
            ranges.append((index, swift_close(significant, index)))
        if (token.kind == 'code' and token.value in {'class', 'struct', 'actor', 'enum', 'extension'}
                and index + 1 < len(significant) and significant[index + 1].value != 'func'):
            opening = index + 1
            while opening < len(significant) and significant[opening].value != '{':
                opening += 1
            if opening < len(significant):
                type_ranges.append((opening, swift_close(significant, opening)))

    def native_type(part):
        return swift_text(part).rstrip('?!') in native | {'Vision.' + name for name in native}

    # Parameters are bound only in their own body, never a sibling function.
    for index, token in enumerate(significant):
        if token.value not in {'func', 'init'} or token.kind != 'code':
            continue
        opening = index + 1
        while opening < len(significant) and significant[opening].value not in {'(', '{'}:
            opening += 1
        if opening == len(significant) or significant[opening].value != '(':
            continue
        close = swift_close(significant, opening)
        body = close + 1
        while body < len(significant) and significant[body].value not in {'{', ';'}:
            body += 1
        for part in swift_parts(significant[opening + 1:close], {','}, generics=True):
            pieces = swift_parts(part, {':'})
            if len(pieces) != 2 or not pieces[0]:
                continue
            name = pieces[0][-1]
            if name.value in native | {'Vision'}:
                return True
            if name.value not in {'req', 'request'}:
                continue
            if not native_type(swift_parts(pieces[1], {'='})[0]) or body == len(significant):
                return True
            declarations.add(name.start)
            bindings.append((name.value, body, swift_close(significant, body), False))

    for index, token in enumerate(significant):
        if token.kind != 'code' or token.value not in {'let', 'var'} or index + 1 == len(significant):
            continue
        name = significant[index + 1]
        if name.value == '(':
            if swift_source_tokens(significant[index + 2:swift_close(significant, index + 1)], suppressed):
                return True
        if name.value not in {'req', 'request'}:
            continue
        following = significant[index + 2:index + 3]
        if not following or following[0].value in {'{', ',', 'else'}:
            # Optional-binding shorthand resolves the existing binding below.
            continue
        header = index - 1
        while header >= 0 and significant[header].value not in {';', '{', '}'}:
            if (significant[header].value in {'if', 'while', 'guard', 'for'}
                    and not (significant[header].value == 'if' and header > 0
                             and significant[header - 1].value == '#')):
                # Conditional bindings have narrower visibility than the
                # enclosing brace. Do not grant a function-wide native proof.
                return True
            header -= 1
        position = index + 3
        if following[0].value == ':':
            ending = position
            while ending < len(significant) and significant[ending].value not in {'=', '{', '}', ';'}:
                if ending > position and bisect_right(newlines, significant[ending - 1].end - 1) < bisect_right(
                        newlines, significant[ending].start - 1):
                    break
                ending += 1
            known = native_type(significant[position:ending])
        elif following[0].value == '=':
            ending = position
            while ending < len(significant) and significant[ending].value not in {'(', '{', ';', '}'}:
                ending += 1
            known = ending < len(significant) and significant[ending].value == '(' and native_type(significant[position:ending])
        else:
            known = False
        if not known:
            return True
        containing = [(a, b) for a, b in ranges if a < index < b]
        scope = max(containing, default=(-1, len(significant)))
        start = scope[0] if scope in type_ranges else index
        bindings.append((name.value, start, scope[1], scope in type_ranges))
        declarations.add(name.start)

    for index, token in enumerate(significant):
        if token.kind != 'code' or token.value not in {'req', 'request'} or token.start in declarations:
            continue
        previous = significant[index - 1].value if index else ''
        following = significant[index + 1].value if index + 1 < len(significant) else ''
        if previous == ',' and following in {'=', ':'} and parents[index] != '(':
            return True  # later binding in a declaration/capture list
        # A closure/iteration binding or an arbitrary object's property is not
        # the outer local/field with the same spelling.
        if following == 'in' or previous == 'for' or (previous == '.' and (
                index < 2 or significant[index - 2].value != 'self')):
            return True
        for opening, closing in ranges:
            if opening < index < closing:
                budget.spend(closing - opening)
                header = significant[opening + 1:index + 1]
                after = significant[index + 1:closing]
                if not any(t.value in {';', '{', '}', 'let', 'var', 'return'} for t in header):
                    if any(t.value == 'in' for t in after[:next((i for i, t in enumerate(after)
                            if t.value in {';', '{', '}'}), len(after))]):
                        return True
        if following == ':' and previous in {'(', ','} and parents[index] == '(':
            continue  # actual argument label, not a value
        if not any(name == token.value and start <= index < end and (previous != '.' or field)
                   for name, start, end, field in bindings):
            return True
    return False


def swift_flow_obligation(tokens):
    """Conservative syntax witnesses for this frontend's source/sink policies.

    Bare identifiers named `req`/`request` are only *possible* source roots;
    ordinary clients also use them for UUIDs or task handles. In the absence
    of any modeled source operation OR sink anywhere in the file, these two
    request-flow policies have nothing to classify. Keep request type/direct
    member spellings and all sink families as activators, even when an
    unrelated declaration uses the same name. This deliberately prefers an
    incomplete result over guessing when relevant unsupported syntax remains.
    """
    witnesses = {
        'Request',
        'filename', 'fileName', 'originalFilename', 'originalFileName',
        'redirect', 'Response', 'HTTPResponse', 'HTTPHeaders', 'add', 'replaceOrAdd',
        'contentsOf', 'contentsOfFile', 'FileHandle', 'FileManager',
        'sendFile', 'streamFile', 'readFile', 'serveFile', 'writeFile', 'file', 'write',
    }
    significant = tuple(token for token in tokens if token.kind != 'code' or token.value != '\n')
    non_file_writes = set()
    for index, token in enumerate(significant):
        if (token.kind == 'code' and token.value == 'write' and index > 0
                and significant[index - 1].value == '.' and index + 1 < len(significant)
                and significant[index + 1].kind == 'code' and significant[index + 1].value == '('):
            close = swift_close(significant, index + 1)
            arguments = swift_parts(significant[index + 2:close], {','})
            if not any(len(part) >= 2 and part[0].kind == 'code' and part[0].value == 'to'
                       and part[1].kind == 'code' and part[1].value == ':' for part in arguments):
                # The file policy models Foundation write(to:), not an API
                # client's write(path, body:). Only this direct call is excluded:
                # a bare method reference is unresolved, and nested arguments
                # and interpolation still contribute their own obligations.
                non_file_writes.add(token.start)
    code_tokens = [token for token in tokens if token.kind == 'code' and token.value != '\n']
    code = [token.value for token in code_tokens]
    request_members = {'query', 'parameters', 'params', 'headers', 'content', 'url', 'uri'}
    if any(code[index] in {'req', 'request'} and code[index + 1] == '.' and code[index + 2] in request_members
           for index in range(len(code) - 2)):
        return True
    for index, value in enumerate(code):
        if value == 'write' and code_tokens[index].start in non_file_writes:
            continue
        if value == 'file':
            # A record receiver (file.name / configuration.file.contents)
            # and a closure's binding token are not calls to the file-serving
            # operation. Keep bare values, aliases, direct/optional calls,
            # explicit callable access and every other source/sink witness.
            # Only code tokens participate: literal text cannot prove a use.
            position = index + 1
            if position < len(code) and code[position] in {'?', '!'}:
                position += 1
            if (position + 1 < len(code) and code[position] == '.'
                    and re.fullmatch(r'[A-Za-z_]\w*', code[position + 1])
                    and code[position + 1] not in {'self', 'callAsFunction'}):
                continue
            if (index > 0 and code[index - 1] == '{'
                    and index + 1 < len(code) and code[index + 1] == 'in'):
                continue
        # A collection append's argument label is not Foundation's URL reader.
        # Actual reads elsewhere and request member/type witnesses still activate
        # analysis, including a read nested inside the appended expression.
        if (value == 'contentsOf' and index >= 3 and index + 1 < len(code)
                and code[index - 3:index] == ['.', 'append', '('] and code[index + 1] == ':'):
            continue
        if value in witnesses or value.lower() == 'headers':
            return True
    for token in tokens:
        if any(swift_flow_obligation(part) for part in token.parts):
            return True
    return False


def swift_statement_tokens(statements):
    for statement in statements:
        if statement.kind == 'definition':
            continue
        yield from statement.tokens
        yield from swift_statement_tokens(statement.body)
        yield from swift_statement_tokens(statement.alternate)


def _swift_observer_obligation(tokens, obligation):
    """True if an accessor-position set/willSet/didSet observer's body meets the
    active policy's obligation. A property observer is never wired to its
    assignment site, so a request-tainted store into the property never reaches
    the observer's newValue and a sink there would be silently missed -> refuse.
    Matches the keyword at accessor position (not preceded by '.'), with its block
    immediately or after a single named parameter '(name)'.
    """
    items = tuple(tokens)
    for index, token in enumerate(items):
        if token.kind != 'code' or token.value not in {'set', 'willSet', 'didSet'}:
            continue
        if index > 0 and items[index - 1].kind == 'code' and items[index - 1].value == '.':
            continue
        rest = [j for j in range(index + 1, len(items)) if not (items[j].kind == 'code' and items[j].value == '\n')]
        brace = -1
        if rest and items[rest[0]].kind == 'code' and items[rest[0]].value == '{':
            brace = rest[0]
        elif (len(rest) >= 4 and items[rest[0]].value == '(' and items[rest[1]].kind == 'code'
              and re.fullmatch(r'[A-Za-z_]\w*', items[rest[1]].value) and items[rest[2]].value == ')'
              and items[rest[3]].value == '{'):
            brace = rest[3]
        if brace < 0:
            continue
        if obligation(items[brace + 1:swift_close(items, brace)]):
            return True
    return False


def swift_outbound_obligation(tokens):
    """Lexical activation only; native receiver identity is checked by flow."""
    significant = tuple(token for token in tokens if token.kind != 'code' or token.value != '\n')
    for index, token in enumerate(significant):
        if token.kind == 'code':
            if token.value == 'URLRequest':
                # A native request may reach a client through a variable or
                # selected helper. Construction activates flow; it is not a
                # network operation or a reason to report a local method.
                return True
            if index > 0 and significant[index - 1].value == '.' and token.value in SWIFT_HTTP_METHODS | {'client'}:
                return True
            if (token.value == 'contentsOf' and index >= 2 and significant[index - 1].value == '('
                    and significant[index - 2].value in {'String', 'Data'}):
                return True
            if (token.value in {'AF', 'Alamofire'} and index + 1 < len(significant)
                    and significant[index + 1].value == '.'):
                return True
        if (token.kind == 'code' and token.value in SWIFT_CLIENT_METHODS
                and index > 0 and significant[index - 1].value == '.'
                and index + 1 < len(significant) and significant[index + 1].value == '('):
            end = swift_close(significant, index + 1)
            for part in swift_parts(significant[index + 2:end], {','}):
                if (part and part[0].value == 'URLRequest' or len(part) >= 2
                        and part[0].value in {'url', 'with'} and part[1].value == ':'):
                    return True
        if any(swift_outbound_obligation(part) for part in token.parts):
            return True
    return False


@dataclass
class SwiftSummary:
    returned: Fact = CLEAN
    effects: dict = field(default_factory=dict)
    mutations: dict = field(default_factory=dict)
    thrown: Fact = CLEAN
    captures: dict = field(default_factory=dict)
    # Exit mutations include unchanged inout arguments; these are real writes.
    assigned: frozenset[int] = frozenset()

    def merged(self, other):
        effects, mutations, captures = dict(self.effects), dict(self.mutations), dict(self.captures)
        for key, value in other.effects.items():
            effects[key] = join(effects.get(key, CLEAN), value)
        for key, value in other.mutations.items():
            mutations[key] = join(mutations.get(key, CLEAN), value)
        for key, value in other.captures.items():
            captures[key] = join(captures.get(key, CLEAN), value)
        return SwiftSummary(join(self.returned, other.returned), effects, mutations,
                            join(self.thrown, other.thrown), captures, self.assigned | other.assigned)


class SwiftEngine:
    def __init__(self, path, text, policy='path', parser=None, *, recover=False):
        self.path, self.text, self.policy = Path(path).resolve(), text, policy
        self.recover, self.diagnostics = recover, {}
        self.sink_label = {'path': 'file sink', 'redirect': 'redirect', 'header': 'response header',
                           'outbound': 'outbound HTTP destination'}[policy]
        self.parser = SwiftParser(text) if parser is None else parser
        self.lines = [0, *(index + 1 for index, char in enumerate(text) if char == '\n')]
        self.budget, self.graphs = Budget(), {}
        self.contexts, self.summaries, self.globals = {}, {}, {}
        self.pending, self.queued = deque(), set()
        self.summary_readers, self.capture_readers = {}, {}
        self.context_inputs, self.context_groups, self.context_revision = {}, {}, 0
        self.default_functions = {}
        self.capture_states, self.capture_revision, self.active_context = {}, 0, None
        self.capture_origins = set()
        self.closure_keys, self.stored_closures = {}, {}
        self.active_closures = set()
        self.pending_calls, self.opaque_calls = {}, set()
        self.capture_frames, self.captured_writes = [], {}
        self.summary_context, self.assigned = None, set()
        self.callback_seen = False
        self.thrown = CLEAN
        self.url_reads = {}
        self.function = self.parser.functions[-1]
        self.effects, self.mutations, self.returned = {}, {}, CLEAN
        self.opaque_owners = {}
        self.local_globals, self.global_bindings = set(), {}
        for offset, reason, owner in self.parser.diagnostics:
            self.function = SwiftFunction(offset, '<declaration>', owner, (), ())
            self.opaque_owners[owner] = join(self.opaque_owners.get(owner, CLEAN), self.limitation(reason, offset))
        self.function = self.parser.functions[-1]
        for statement in self.function.body:
            assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
            if assignment and assignment[0]:
                name, lhs, rhs, _, declaration = assignment
                if declaration:
                    self.local_globals.add(name)
                    self.global_bindings[name] = name + '@' + str(lhs[0].start)
                    self.globals[name] = self.expression(rhs, dict(self.globals), {})
                    if swift_tainted(self.globals[name]):
                        self.globals[name] = join(self.globals[name], self.limitation(
                            'Swift request-derived global state needs capture analysis', statement.tokens[0].start))
        for function in self.parser.functions.values():
            request_parameter = any(re.fullmatch(r'(?:Vapor\.)?Request\??', item[2]) for item in function.parameters)
            if function.key == -1 or request_parameter or swift_source_tokens(swift_statement_tokens(function.body), self.parser.suppressed):
                if self.parser.obligation is not None and _swift_observer_obligation(swift_statement_tokens(function.body), self.parser.obligation):
                    self.limitation('Swift property observer with a sink needs assignment binding analysis', function.key)
                self.context(function, tuple(CLEAN for _ in function.parameters), entry=True)

    def step(self, offset, kind, label):
        offset = max(0, offset)
        index = bisect_right(self.lines, offset) - 1
        return Step(str(self.path), index + 1, offset - self.lines[index] + 1, kind, label[:160])

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path), offset, label),
            tags=frozenset({'swift-string'}), evidence=(self.step(offset, 'source', label),))})

    def limitation(self, reason, offset, state=None, bindings=None):
        """Report an opaque effect at its site and retain unsafe alternatives.

        This is deliberately separate from lexical/structural failures and
        AnalysisLimit. A proof-only consumer still gets an exception. During
        an ordinary scan, unknown effects cannot certify a sanitizer, a clean
        return, or an unchanged captured alias.
        """
        offset = max(0, offset)
        if not self.recover:
            raise SwiftUnsupported(reason + '; analysis is incomplete', offset)
        location = self.step(offset, 'analysis', reason)
        scope = '.'.join((*self.function.owner, self.function.name))
        self.diagnostics[(offset, reason)] = dict(
            rule='swift.taint.analysis-limited', path=str(self.path),
            line=location.line, col=location.column, lang='swift', layer='taint',
            severity='warning', message=reason + '; effects are conservatively unknown in ' + scope,
            extras={'analysis': 'conservative', 'construct': self.text[offset:offset + 100].split('\n')[0],
                    'reason': reason, 'policy': self.policy, 'scope': scope})
        # Every refusal above retains its own location and reason. Its value,
        # however, is the same abstract unknown, not a distinct request source.
        # Giving that value a new identity at every opaque operation makes
        # joins and callback contexts grow with the number of diagnostics.
        # Keep field paths and validation tags on the individual values; only
        # their unknowable origin is shared. Real request sources keep their
        # original identities and never merge into this conservative marker.
        unknown = frozenset({Trace('source', (str(self.path), -1, 'unknown effects'),
            tags=frozenset({'swift-string', 'unknown-provenance', 'analysis-limited'}),
            evidence=(self.step(offset, 'source', 'unknown effects: ' + reason),))})
        self.apply_unknown_effects(unknown, state, bindings)
        return unknown

    def apply_unknown_effects(self, unknown, state, bindings=None):
        """Replay established uncertainty without inventing another refusal."""
        if state is not None:
            for binding in set(state) | set((bindings or {}).values()):
                if binding.startswith('@'):
                    continue
                value = state.get(binding, CLEAN)
                shapes = frozenset(trace for trace in value if trace.kind == 'shape')
                state[binding] = join(self.forget(value), shapes, unknown)

    def context(self, function, arguments, entry=False, receiver=CLEAN):
        if any(function.parameter_attributes):
            opaque = self.limitation('Swift attributed parameters need transformation analysis', function.key)
            arguments = tuple(join(value, opaque) for value in arguments)
        key = function.key, arguments, entry, receiver
        if key in self.contexts:
            if self.summary_context is not None:
                self.summary_readers.setdefault(key, {})[self.summary_context] = None
            return key
        group = self.context_groups.setdefault((function.key, entry), [])
        if len(group) >= 16:
            # Exact combinations of growing object fields/callback captures
            # otherwise create a fresh context at every iteration. Preserve
            # the first precise contexts, then join every later input into one
            # stable context. This is a monotone may-analysis: no source,
            # validation alternative, callable or receiver identity is dropped.
            # Capture origins use this stable key even as its inputs grow.
            key = function.key, (), entry, CLEAN, 'joined'
            previous = self.context_inputs.get(key)
            if previous is not None:
                arguments = tuple(join(old, new) for old, new in zip(previous[0], arguments))
                receiver = join(previous[1], receiver)
            current = arguments, receiver
            if previous != current:
                self.budget.spend()
                self.context_inputs[key] = current
                self.context_revision += 1
                self.enqueue(key)
        else:
            group.append(key)
            self.context_inputs[key] = arguments, receiver
        if key not in self.contexts:
            self.budget.spend()
            if len(self.contexts) >= 2048:
                raise AnalysisLimit('Swift call-context limit exceeded; analysis is incomplete')
            self.contexts[key], self.summaries[key] = function, SwiftSummary()
            self.enqueue(key)
        if self.summary_context is not None:
            self.summary_readers.setdefault(key, {})[self.summary_context] = None
        return key

    def enqueue(self, key):
        if key not in self.queued:
            self.pending.append(key)
            self.queued.add(key)

    def future_captures(self, context):
        # Captures can see writes after their creation/call site. Record which
        # enclosing function summary consumed that future state, including a
        # stored callback invoked from a different helper's context.
        if self.summary_context is not None:
            self.capture_readers.setdefault(context, {})[self.summary_context] = None
        return self.capture_states.get(context, {})

    def enable_callbacks(self):
        if not self.callback_seen:
            self.callback_seen = True
            self.capture_revision += 1
            # Callback-aware heap effects also apply to already visited calls.
            # The first callback therefore invalidates every earlier context;
            # subsequent capture changes invalidate only actual readers.
            for key in self.contexts:
                self.enqueue(key)

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
        links = frozenset(tag for trace in value for tag in trace.tags
                          if tag.startswith(('property-of:', 'url-id:', 'stored-field:')))
        plain = frozenset(trace for trace in value if trace.kind not in {'shape', 'constant', 'field'})
        # Opaque transformations may extract incoming data from a stored
        # Request. Discarding its nested shape must not turn that result clean.
        requests = [self.source(trace.key[1], 'stored ' + trace.key[0]) for trace in value
                    if swift_field_path(trace) and trace.kind == 'shape'
                    and trace.key[0] in {'request', 'request-collection', 'request-content'}]
        plain = join(plain, *requests)
        return swift_retag(plain, remove=tags | links)

    def record(self, offset, value, file_leaf=False):
        if self.policy == 'redirect':
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if not SWIFT_LOCAL_TAGS <= trace.tags and not (
                    {'url-scheme', 'url-host', 'serialized-url'} <= trace.tags))
        elif self.policy == 'header':
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if not SWIFT_HEADER_TAGS <= trace.tags)
        elif self.policy == 'outbound':
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if not ({'url-scheme', 'url-host'} <= trace.tags
                        and trace.tags & {'url-object', 'serialized-url'}))
        else:
            unsafe = frozenset(trace for trace in swift_tainted(value)
                if 'contained-path' not in trace.tags and not (file_leaf and 'file-leaf' in trace.tags))
        if any('unknown-provenance' in trace.tags for trace in unsafe):
            self.limitation('Swift unknown closure parameter or opaque value reaches a sink', offset)
            unsafe = frozenset(trace for trace in unsafe if 'unknown-provenance' not in trace.tags)
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN),
                advance(unsafe, self.step(offset, 'sink', self.sink_label)))

    def header_text(self, values):
        """String composition preserves only each component's CR/LF proof.

        It cannot manufacture a redirect or filesystem validation. Literal
        CR/LF in the composition invalidates the corresponding header proof.
        Unknown transformations still use forget(), including percent decoding.
        """
        value = join(*values)
        removed = set()
        for trace in value:
            if trace.kind == 'constant' and trace.key[0] == 'literal':
                if '\r' in trace.key[1]:
                    removed.add('no-carriage-return')
                if '\n' in trace.key[1]:
                    removed.add('no-newline')
        return swift_retag(self.forget(value, SWIFT_HEADER_TAGS - removed), add=frozenset({'swift-string'}))

    def native_string_method(self, leaf, receiver):
        # A selected String extension can override/overload a sanitizer. Its
        # spelling alone is never proof of Foundation/stdlib behavior.
        return (bool(receiver) and all('swift-string' in trace.tags for trace in receiver)
                and self.builtin('String')
                and not any(function.owner and function.owner[-1] in {'String', 'NSString'}
                            and function.name == leaf for function in self.parser.functions.values()))

    def header_sanitizer(self, leaf, receiver, arguments, state, bindings):
        if not self.native_string_method(leaf, receiver):
            return None
        parts = {label: swift_ungroup(tokens) for label, _, tokens in arguments}
        if leaf == 'replacingOccurrences' and len(arguments) == 2 and set(parts) == {'of', 'with'}:
            target, replacement = parts['of'], parts['with']
            if (len(target) == len(replacement) == 1
                    and target[0].kind == replacement[0].kind == 'literal'
                    and target[0].value in {'\r', '\n'}
                    and not any(char in replacement[0].value for char in '\r\n')):
                tag = 'no-carriage-return' if target[0].value == '\r' else 'no-newline'
                return swift_retag(self.forget(receiver, SWIFT_HEADER_TAGS),
                             add=frozenset({tag, 'swift-string'}))
        if leaf == 'addingPercentEncoding' and len(arguments) == 1 and set(parts) == {'withAllowedCharacters'}:
            allowed = swift_text(parts['withAllowedCharacters'])
            if (re.fullmatch(r'(?:(?:Foundation\.)?CharacterSet)?\.(?:urlPathAllowed|urlQueryAllowed|alphanumerics)', allowed)
                    and self.builtin('CharacterSet', state, bindings)
                    and not any(owner.split('.')[-1] == 'CharacterSet' for owner in self.parser.extensions)):
                return swift_retag(self.forget(receiver), add=SWIFT_HEADER_TAGS | frozenset({'swift-string'}))
        return None

    def candidates(self, name, receiver, state, bindings, *, direct=True):
        leaf, owner = name.rsplit('.', 1)[-1], self.function.owner
        receiver = swift_top(receiver)
        function_values = {trace.key[0] for trace in receiver if direct and trace.kind == 'function'}
        if function_values:
            return [self.parser.functions[key] for key in function_values]
        if any(trace.kind == 'shape' and trace.key[0].startswith('dynamic-instance:') for trace in receiver):
            return []
        if name in self.parser.types:
            return [function for function in self.parser.functions.values()
                    if function.name == 'init' and function.owner == tuple(name.split('.'))]
        if '.' in name:
            prefix = name.rsplit('.', 1)[0]
            if prefix == 'self' or (prefix == 'Self'
                    and '.'.join(self.function.owner) in self.parser.final_types):
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
            if '...' in declaration:
                raise SwiftUnsupported('Swift variadic parameters need call binding analysis; analysis is incomplete', function.key)
            if position < len(arguments) and arguments[position][0] == label:
                value = arguments[position][1]
                position += 1
            elif default:
                value = self.default_argument(function, name, default)
            else:
                return None
            values.append(value)
        return tuple(values) if position == len(arguments) else None

    def default_argument(self, function, name, tokens):
        """Default arguments execute in the declaration's lexical context."""
        identity = function.key, name
        if identity not in self.default_functions:
            existing = self.parser.field_functions.get((function.owner, name))
            if function.key in self.parser.synthetic_initializers and existing is not None:
                default = self.parser.functions[existing]
            else:
                key = -2 - tokens[0].start
                default = SwiftFunction(key, '<default:' + name + '>', function.owner,
                                        function.scope, (), (SwiftStatement('return', tuple(tokens)),), static=True)
                self.parser.functions[key] = default
            self.default_functions[identity] = default
        summary = self.summaries[self.context(self.default_functions[identity], ())]
        self.thrown = join(self.thrown, summary.thrown)
        for offset, value in summary.effects.items():
            self.effects[offset] = join(self.effects.get(offset, CLEAN), value)
        return summary.returned

    @staticmethod
    def reference_ids(value):
        """Allocation identities are distinct from reusable type witnesses.

        A source allocation site is finite, including repeated factory calls.
        Unknown incoming references of the same type deliberately share -1:
        separate formal parameters are not proof of separate objects.
        """
        return frozenset(trace.key for trace in swift_top(value) if trace.kind == 'shape'
                         and trace.key[0].startswith('reference:'))

    def reference_value(self, value, state):
        identities = self.reference_ids(value)
        if not identities:
            return value
        aliases = []
        for fact in state.values():
            paths = {tuple(swift_field_path(trace)) for trace in fact
                     if trace.kind == 'shape' and trace.key in identities}
            for path in paths:
                selected = fact
                for name in path:
                    selected = self.project_field(name, selected) or CLEAN
                aliases.append(selected)
        return join(value, *aliases)

    def allocation(self, name, offset):
        value = swift_shape('instance:' + name, offset)
        if name not in self.parser.value_types:
            value = join(value, swift_shape('reference:' + name, offset))
        # Summaries start at bottom. Mark the known layout immediately so a
        # tainted sibling cannot stand in for a not-yet-computed clean field.
        for field_name in self.parser.stored_fields.get(tuple(name.split('.')), {}):
            value = join(value, self.stored_value(field_name, CLEAN, offset))
        return value

    def object_payload(self, value):
        # A stored Request/collection is still incoming data after projection
        # through an aggregate field. Dropping its shape must not make all of
        # its later query/content reads clean.
        fields = frozenset(trace for trace in value if swift_field_path(trace))
        value = swift_top(value)
        requests = (trace for trace in value if trace.kind == 'shape' and trace.key[0]
                    in {'request', 'request-collection', 'request-content'})
        return join(fields, self.forget(value), *(self.source(trace.key[1], 'stored ' + trace.key[0])
                                                  for trace in requests))

    def stored_value(self, name, value, offset):
        """Retain the exact selected field, including callable and type facts."""
        result = {Trace('field', (name,), tags=frozenset({'stored-field:' + name}))}
        for trace in value:
            self.budget.spend()
            path = (name, *swift_field_path(trace))
            if len(path) > 16:
                raise AnalysisLimit('Swift stored-field depth limit exceeded; analysis is incomplete')
            tags = frozenset(tag for tag in trace.tags if not tag.startswith('stored-field:'))
            result.add(replace(trace, tags=tags | frozenset({'stored-field:' + '.'.join(path)})))
        return frozenset(result)

    def project_field(self, name, receiver):
        result, present = [], False
        for trace in receiver:
            path = swift_field_path(trace)
            if not path or path[0] != name:
                continue
            present = True
            if len(path) == 1 and trace.kind == 'field':
                continue
            tags = frozenset(tag for tag in trace.tags if not tag.startswith('stored-field:'))
            if len(path) > 1:
                tags |= frozenset({'stored-field:' + '.'.join(path[1:])})
            result.append(replace(trace, tags=tags))
        if not present:
            return None
        # An explicitly opaque aggregate may still mutate any stored field.
        return join(frozenset(result), self.forget(swift_top(receiver)))

    def write_field(self, receiver, name, value, state, binding, offset, operator='=', field_path=()):
        owners = {tuple(trace.key[0].split(':', 1)[1].split('.'))
                  for trace in swift_top(receiver) if trace.kind == 'shape'
                  and trace.key[0].startswith(('instance:', 'dynamic-instance:'))}
        if not owners or any(name not in self.parser.stored_fields.get(owner, {}) for owner in owners):
            return False
        for owner in owners:
            reason = self.parser.stored_fields[owner][name][4]
            if reason:
                value = join(value, self.limitation(reason, offset, state))
        if operator != '=':
            value = self.forget(join(value, self.project_field(name, receiver) or CLEAN))
        tagged = self.stored_value(name, value, offset)
        if field_path:
            self.object_effect(receiver, tagged, state, binding, field_path)
        else:
            strong = binding == 'self' and self.function.name == 'init'
            previous = state.get(binding, receiver)
            if strong:
                previous = frozenset(trace for trace in previous
                                     if not swift_field_path(trace) or swift_field_path(trace)[0] != name)
            state[binding] = join(previous, tagged)
            if not strong:
                self.object_effect(receiver, tagged, state, binding)
        self.invalidate_properties(binding, state)
        self.note_write(binding, state.get(binding, CLEAN))
        identities = self.reference_ids(receiver)
        if field_path:
            identities |= self.reference_ids(state.get(binding, CLEAN))
        # Incoming references use the type's unknown allocation (offset -1).
        # They may alias an allocated global of that type as well as another
        # incoming parameter; an exact allocation-key comparison is insufficient.
        unknown_types = {identity[0] for identity in identities if identity[1] == -1}
        affected_globals = {key for key, fact in self.globals.items()
                            if binding in {key, self.global_bindings.get(key)}
                            or any(trace.kind == 'shape' and (
                                trace.key in identities or trace.key[0] in unknown_types)
                                for trace in join(fact, state.get(key, CLEAN)))}
        if affected_globals:
            opaque = (join(self.forget(self.object_payload(value)), self.limitation(
                'Swift request-derived global field mutation needs shared-state analysis', offset))
                if swift_request_dependency(value) else CLEAN)
            for key in affected_globals:
                # A global may own the mutated reference in a nested field.
                # Publish the updated aggregate, preserving aliases and all
                # prior alternatives, so other contexts revisit their reads.
                updated = state.get(key, CLEAN)
                if binding in {key, self.global_bindings.get(key)}:
                    updated = join(updated, state.get(binding, CLEAN))
                self.globals[key] = join(self.globals[key], updated, opaque)
                state[key] = join(state.get(key, CLEAN), self.globals[key])
                self.invalidate_properties(key, state)
        return True

    def initialize_fields(self, function, receiver):
        fields = self.parser.stored_fields.get(function.owner, {})
        if function.owner in self.parser.initialization_limits:
            reason, offset = self.parser.initialization_limits[function.owner]
            receiver = join(receiver, self.limitation(reason, offset))
        declaration = self.parser.type_declarations.get(function.owner)
        if declaration:
            kind, token, header = declaration
            parents = swift_parts(header, {':'})
            if kind in {'class', 'actor'} and len(parents) == 2:
                first = swift_text(swift_parts(parents[1], {','})[0])
                known_protocols = self.parser.protocols | {
                    'Codable', 'Decodable', 'Encodable', 'Sendable', 'Identifiable',
                    'ObservableObject', 'Equatable', 'Hashable', 'Error', 'LocalizedError'}
                if first not in known_protocols and not self.passive_superclass(first):
                    receiver = join(receiver, self.limitation(
                        'Swift inherited initialization needs superclass analysis', token.start))
        synthetic = function.key in self.parser.synthetic_initializers
        parameter_names = {name for name, _, _, _ in function.parameters} if synthetic else set()
        for name, (field_type, default, mutable, token, reason) in fields.items():
            if name in parameter_names:
                value = CLEAN
            elif reason:
                value = self.limitation(reason, token.start)
            elif default:
                key = self.parser.field_functions[(function.owner, name)]
                summary = self.summaries[self.context(self.parser.functions[key], ())]
                value = summary.returned
                self.thrown = join(self.thrown, summary.thrown)
                for offset, fact in summary.effects.items():
                    self.effects[offset] = join(self.effects.get(offset, CLEAN), fact)
            elif mutable and field_type.endswith('?'):
                value = swift_constant('nil', 'code')
            elif synthetic:
                value = self.limitation('Swift default initializer has unmodeled required storage', token.start)
            else:
                # The explicit body initializes this field. A clean bottom
                # here cannot certify a missing/opaque assignment: those
                # statements carry their own incomplete-analysis outcome.
                value = CLEAN
            receiver = join(receiver, self.stored_value(name, value, token.start))
        return receiver

    def passive_superclass(self, name, seen=frozenset()):
        """A selected superclass with no storage or executable initializer."""
        if name in seen:
            return False
        owner = tuple(name.split('.'))
        declaration = self.parser.type_declarations.get(owner)
        if (not declaration or declaration[0] != 'class' or self.parser.stored_fields.get(owner)
                or owner in self.parser.initialization_limits
                or any(function.owner == owner and function.name == 'init'
                       and function.key not in self.parser.synthetic_initializers
                       or function.owner == owner and function.name == 'deinit'
                       for function in self.parser.functions.values())):
            return False
        parents = swift_parts(declaration[2], {':'})
        if len(parents) == 1:
            return True
        first = swift_text(swift_parts(parents[1], {','})[0])
        return first in self.parser.protocols or self.passive_superclass(first, seen | {name})

    def decode_object(self, name, source, site, state, bindings, depth=0):
        if depth > 16:
            raise AnalysisLimit('Swift decoded-field depth limit exceeded; analysis is incomplete')
        owner = tuple(name.split('.'))
        shadowed_types = self.parser.types | self.parser.shadow_type_names
        custom = [function for function in self.parser.functions.values()
                  if function.owner == owner and function.name == 'init'
                  and len(function.parameters) == 1 and function.parameters[0][1] == 'from'
                  and re.fullmatch(r'(?:any)?(?:Swift\.)?Decoder', function.parameters[0][2])
                  and (('Swift.Decoder' in function.parameters[0][2] and 'Swift' not in shadowed_types)
                       or ('Swift.Decoder' not in function.parameters[0][2] and 'Decoder' not in shadowed_types))]
        if custom:
            argument = join(source, swift_shape('decoder', site.expression.start))
            selected = frozenset(Trace('function', (function.key,)) for function in custom)
            return self.call(name, selected, [('from', argument, ())], site, state, bindings)
        declaration = self.parser.type_declarations.get(owner)
        synthetic = [function for function in self.parser.functions.values()
                     if function.owner == owner and function.key in self.parser.synthetic_initializers]
        inheritance = swift_parts(declaration[2], {':'}) if declaration else ()
        conformances = {swift_text(part) for part in swift_parts(inheritance[1], {','})} if len(inheritance) == 2 else set()
        native_conformances = {name for name in {'Codable', 'Decodable', 'Content'} if name not in shadowed_types}
        if 'Swift' not in shadowed_types:
            native_conformances.update({'Swift.Codable', 'Swift.Decodable'})
        if 'Vapor' not in shadowed_types:
            native_conformances.add('Vapor.Content')
        if (not declaration or declaration[0] != 'struct' or not synthetic
                or not conformances.intersection(native_conformances)):
            return join(source, self.limitation(
                'Swift decoded type needs selected Decodable initialization analysis', site.expression.start))
        function = synthetic[0]
        arguments = []
        for field_name, label, field_type, _default in function.parameters:
            selected = field_type.rstrip('?')
            if selected in self.parser.types:
                value = self.decode_object(selected, source, site, state, bindings, depth + 1)
            elif (not selected or re.fullmatch(r'(?:Swift\.|Foundation\.)?(?:String|Bool|Int\d*|UInt\d*|Float|Double|Data|URL)', selected)):
                value = source
            else:
                value = join(source, self.limitation(
                    'Swift decoded stored property type needs initialization analysis', site.expression.start))
            arguments.append((label, value, ()))
        return self.call(name, CLEAN, arguments, site, state, bindings)

    def object_effect(self, receiver, value, state, binding=None, field_path=()):
        """Weakly update every possible reference alias, or one value copy.

        Fields remain an aggregate: writing a literal to one property cannot
        certify that another property, or an alias, no longer holds input.
        """
        identities = self.reference_ids(receiver)
        if not identities and field_path:
            for name in reversed(field_path):
                value = self.stored_value(name, value, self.function.key)
        targets = {key: {tuple(swift_field_path(trace)) for trace in fact
                         if trace.kind == 'shape' and trace.key in identities}
                   for key, fact in state.items()}
        if not identities and binding in state:
            targets[binding] = {()}
        for key, paths in targets.items():
            if not paths:
                continue
            previous = state[key]
            shapes = frozenset(trace for trace in swift_top(previous) if trace.kind == 'shape'
                               and trace.key[0].startswith(('instance:', 'dynamic-instance:', 'reference:')))
            additions = []
            for path in paths:
                selected = value
                for name in reversed(path):
                    selected = self.stored_value(name, selected, self.function.key)
                additions.append(selected)
            state[key] = join(self.object_payload(join(previous, *additions)), shapes)
            self.invalidate_properties(key, state)

    def mutate(self, name, value, state, bindings):
        binding = bindings.get(name, name)
        previous = state.get(binding, CLEAN)
        if self.callback_seen and swift_request_dependency(value) and not self.reference_ids(previous):
            # Lexical capture IDs do not establish object/heap alias identity.
            # A write through another reference may change a captured object.
            value = join(value, self.limitation(
                'Swift callback with request-derived object mutation needs heap/capture analysis',
                self.function.key, state, bindings))
        instances = frozenset(trace for trace in swift_top(previous) if trace.kind == 'shape'
                              and trace.key[0].startswith(('instance:', 'dynamic-instance:', 'reference:')))
        state[binding] = join(self.object_payload(join(previous, value)), instances)
        self.object_effect(previous, state[binding], state, binding)
        if name in self.local_globals and binding == name and swift_tainted(state[binding]):
            state[binding] = join(state[binding], self.limitation(
                'Swift request-derived global mutation needs shared-state analysis', self.function.key))
        self.invalidate_properties(binding, state)
        return state[binding]

    def capture_visible(self, origin, binding, context=None):
        context = self.active_context if context is None else context
        return origin == context or any(
            origin == frame and binding in slots for frame, slots, _ in self.capture_frames)

    def note_write(self, binding, value, *, origin=None):
        origin = self.active_context if origin is None else origin
        if self.capture_frames:
            frame, slots, writes = self.capture_frames[-1]
            if binding in slots:
                writes[binding] = join(writes.get(binding, CLEAN), value)
                origin = frame
        # A stored closure can execute in its creation context while its
        # effects contribute to a different helper's function summary.
        if origin == self.summary_context and origin in self.contexts:
            for index, (name, _, declaration, _) in enumerate(self.contexts[origin].parameters):
                if declaration.startswith('inout') and binding == 'parameter:' + name:
                    self.assigned.add(index)

    def apply_captures(self, writes, state, *, context=None):
        """Carry callback writes through helpers to their lexical owner.

        Function parameters can share names across call contexts. A captured
        slot therefore belongs to its closure's creation context, not to an
        unrelated callee parameter with the same spelling. These are may-write
        summaries: an optional callback cannot certify that a tainted value was
        overwritten, and transitive helper calls must retain each possible write.
        """
        for key, value in writes.items():
            origin, binding = key
            self.captured_writes[key] = join(self.captured_writes.get(key, CLEAN), value)
            if self.capture_visible(origin, binding, context):
                # CLEAN lexical slots can be absent from the sparse state;
                # their declaration identity still belongs to this capture.
                state[binding] = join(state.get(binding, CLEAN), value)
                self.invalidate_properties(binding, state)
                # A future-capture join can already contain this fact. The
                # nested call still writes the enclosing capture.
                self.note_write(binding, value, origin=origin)

    def invalidate_properties(self, binding, state):
        link = 'property-of:' + binding
        for key, value in tuple(state.items()):
            if any(link in trace.tags for trace in value):
                state[key] = swift_retag(value, remove=frozenset({link, 'url-host', 'url-scheme'}))

    @staticmethod
    def http_receiver(value, family):
        return bool(value) and all(trace.kind == 'shape' and trace.key[0] == 'http-client:' + family
                                   for trace in value)

    @staticmethod
    def http_request(value):
        return bool(value) and all('http-request' in trace.tags for trace in value)

    @staticmethod
    def request_destination(value, offset):
        """URLRequest copies its destination independently of headers and body."""
        return swift_retag(join(value, swift_shape('http-request', offset)), add=frozenset({'http-request'}))

    def outbound_call(self, name, receiver, arguments, token, state, bindings):
        """Selected native clients; unresolved HTTP dispatch stays incomplete.

        Same-file helpers are resolved before this method. Neither a helper's
        name nor a method on an unrelated custom type grants native behavior.
        """
        leaf = name.rsplit('.', 1)[-1]
        values = [value for _, value, _ in arguments]
        labeled = {label: value for label, value, _ in arguments}
        if leaf == 'URLSession' and self.builtin(name, state, bindings):
            return swift_shape('http-client:foundation', token.start)
        if leaf == 'URLRequest' and self.builtin(name, state, bindings) and 'url' in labeled:
            return self.request_destination(labeled['url'], token.start)
        if self.http_request(receiver) and leaf in {'setValue', 'addValue'} and 'forHTTPHeaderField' in labeled:
            if any(function.owner and function.owner[-1].split('.')[-1] == 'URLRequest' and function.name == leaf
                   for function in self.parser.functions.values()):
                raise SwiftUnsupported('Swift URLRequest extension needs destination-mutation analysis; analysis is incomplete', token.start)
            return CLEAN
        method_refs = {trace.key[0] for trace in receiver if trace.kind == 'shape'
                       and trace.key[0].startswith('http-method:')}
        selected_method = (next(iter(method_refs)).split(':', 2) if len(method_refs) == 1
                           and all(trace.kind == 'shape' and trace.key[0] in method_refs
                                   for trace in receiver) else None)
        if selected_method:
            leaf = selected_method[2]
        foundation = self.http_receiver(receiver, 'foundation') or bool(selected_method and selected_method[1] == 'foundation')
        vapor = self.http_receiver(receiver, 'vapor') or bool(selected_method and selected_method[1] == 'vapor')
        overridden = any(function.owner and function.owner[-1].split('.')[-1] in {'URLSession', 'Client'}
                         and function.name == leaf for function in self.parser.functions.values())
        if foundation and leaf in SWIFT_HTTP_METHODS and not overridden:
            target = next((value for label, value, _ in arguments if label in {'with', 'from', 'for'}), None)
            if leaf == 'streamTask':
                target = labeled.get('withHostName', target)
            if target is not None:
                self.record(token.start, target)
                return CLEAN
        if vapor and leaf in SWIFT_CLIENT_METHODS and not overridden:
            target = next((value for label, value, _ in arguments if label in {'', 'url', 'to'}), None)
            if target is not None:
                self.record(token.start, target)
                return CLEAN
        request_argument = any('http-request' in trace.tags for value in values for trace in value)
        http_shape = (request_argument or bool(method_refs) or leaf in SWIFT_HTTP_METHODS
                      or leaf in SWIFT_CLIENT_METHODS and (
                          vapor or foundation or any(label in {'url', 'with'} for label in labeled)
                          or name.startswith(('AF.', 'Alamofire.', 'req.client.', 'request.client.'))))
        if http_shape and any(swift_request_dependency(value) for value in [receiver, *values]):
            raise SwiftUnsupported('Swift outbound HTTP receiver or overload needs binding analysis; analysis is incomplete', token.start)
        return None

    def pending_callable(self, name, site, state, bindings, reason, value=CLEAN):
        """Resolve selected summaries before declaring a callable opaque.

        Bottom during fixpoint iteration is not proof of an empty callback.
        A binding that remains unresolved at a stable pass produces an explicit
        limitation, followed by a pass propagating conservative unknown effects.
        """
        key = self.summary_context, self.active_context, site.expression.start, name
        if key in self.opaque_calls:
            return join(self.forget(value), self.limitation(reason, site.expression.start, state, bindings))
        self.pending_calls.setdefault(self.summary_context, {})[key] = self.function, reason
        return CLEAN

    def call(self, name, receiver, arguments, site, state, bindings, *, selected_callable=False):
        token, callee_token = site.expression, site.callee
        alias_callee = name.removesuffix('.init')
        if (alias_callee.rsplit('.', 1)[-1] in self.parser.type_alias_names
                and name.split('.', 1)[0] not in bindings
                and ('.' not in alias_callee or alias_callee.rsplit('.', 1)[0] in self.parser.types
                     or alias_callee.rsplit('.', 1)[0] == 'Self')
                and not any(trace.kind in {'function', 'closure', 'native-callable'}
                            for trace in swift_top(receiver))):
            return join(self.forget(join(receiver, *(fact for _, fact, _ in arguments))), self.limitation(
                'Swift object initialization through a type alias needs selected type binding analysis', token.start, state, bindings))
        if name in self.parser.generic_types:
            return join(self.forget(join(receiver, *(fact for _, fact, _ in arguments))), self.limitation(
                'Swift generic type initialization needs type-substitution analysis', token.start, state, bindings))
        if name in self.parser.types and tuple(name.split('.')) not in self.parser.type_declarations:
            matches = ['.'.join((*self.function.owner[:index], name))
                       for index in range(len(self.function.owner), -1, -1)
                       if (*self.function.owner[:index], name) in self.parser.type_declarations]
            if matches:
                name = matches[0]
        leaf = name.rsplit('.', 1)[-1]
        top_receiver = swift_top(receiver)
        direct = callee_token is None or (
            leaf in {'self', 'callAsFunction'}
            and any(trace.kind in {'function', 'closure', 'native-callable'} for trace in top_receiver))
        if not direct:
            owners = {tuple(trace.key[0].split(':', 1)[1].split('.')) for trace in top_receiver
                      if trace.kind == 'shape' and trace.key[0].startswith(('instance:', 'dynamic-instance:'))}
            if any(leaf in self.parser.fields.get(owner, {})
                   or (owner, leaf) in self.parser.field_functions for owner in owners):
                # Calling a stored/computed callable field first reads exactly
                # that property. An ordinary method never invokes unrelated
                # callbacks merely because the receiver contains them.
                binding = bindings.get(name.split('.', 1)[0], name.split('.', 1)[0])
                target = self.member(leaf, receiver, callee_token, binding, state)
                if not target:
                    return self.pending_callable(name, site, state, bindings,
                        'Swift callable property needs stored-value binding analysis',
                        join(receiver, *(fact for _, fact, _ in arguments)))
                return self.call(name, target, arguments, CallSite(token), state, bindings,
                                 selected_callable=True)
        instances = {tuple(trace.key[0].split(':', 1)[1].split('.')) for trace in top_receiver
                     if trace.kind == 'shape' and trace.key[0].startswith(('instance:', 'dynamic-instance:'))}
        http_method = self.policy == 'outbound' and any(
            trace.kind == 'shape' and trace.key[0].startswith('http-method:')
            for trace in top_receiver)
        callable_values = http_method or any(trace.kind in {'function', 'closure', 'native-callable'}
                                             for trace in top_receiver)
        opaque_return, opaque_state = CLEAN, None
        if direct and any(trace.kind == 'opaque-value' for trace in top_receiver):
            opaque_return = join(self.forget(join(receiver, *(fact for _, fact, _ in arguments))),
                self.limitation('Swift opaque callable needs binding analysis', token.start, state, bindings))
            opaque_state = dict(state)
            if not callable_values and not instances:
                return opaque_return
        if direct and instances and not callable_values:
            # A selected callable instance invokes a real method. Its stored
            # initializer payload does not summarize callAsFunction's effects.
            methods = [function for function in self.parser.functions.values()
                       if function.name == 'callAsFunction' and function.owner in instances]
            if len(instances) == 1 and methods and not any(
                    trace.kind == 'shape' and trace.key[0].startswith('dynamic-instance:')
                    for trace in top_receiver):
                name, leaf, callee_token, direct = name + '.callAsFunction', 'callAsFunction', token, False
            else:
                return join(opaque_return, self.pending_callable(name, site, state, bindings,
                    'Swift callable instance needs callAsFunction dispatch analysis',
                    join(receiver, *(fact for _, fact, _ in arguments))))
        if direct and instances and callable_values:
            opaque_return = join(opaque_return,
                self.forget(join(receiver, *(fact for _, fact, _ in arguments))),
                self.limitation('Swift mixed callable instance alternatives need dispatch analysis',
                                token.start, state, bindings))
            opaque_state = dict(state)
        if direct and not callable_values and not instances and not http_method and (name in bindings or selected_callable):
            diagnosed = frozenset(trace for trace in top_receiver if trace.kind == 'source'
                                 and 'analysis-limited' in trace.tags)
            if diagnosed:
                # A prior local limitation can poison a callable binding or
                # add an alternative beside a known callback. Its effects are
                # still unknown on invocation, but already explicitly reported.
                # Unknown callback parameters lack this marker and still refuse.
                self.apply_unknown_effects(diagnosed, state, bindings)
                return self.forget(join(receiver, *(fact for _, fact, _ in arguments)))
            return self.pending_callable(name, site, state, bindings,
                'Swift unresolved callable needs binding analysis',
                join(receiver, *(fact for _, fact, _ in arguments)))
        if self.policy == 'outbound' and arguments and all(
                label and (not part or re.fullmatch(r'(?:[A-Za-z_]\w*:)+', swift_text(part)))
                for label, _, part in arguments):
            # Method references carry labels, not clean destination arguments.
            return self.limitation('Swift labeled callable reference needs argument binding', token.start, state, bindings)
        native_calls = {trace.key[0] for trace in top_receiver
                        if direct and trace.kind == 'native-callable'}
        stored = [trace for trace in top_receiver if direct and trace.kind == 'closure']
        http_methods = frozenset(trace for trace in top_receiver if direct and self.policy == 'outbound'
                                 and trace.kind == 'shape' and trace.key[0].startswith('http-method:'))
        if native_calls or stored or http_methods:
            # A branch may select a stored closure, a native sink or a named
            # helper. Evaluate every possible callable against the same input
            # state; one alternative must not erase another's effects.
            ordinary = frozenset(trace for trace in receiver
                                 if trace.kind not in {'native-callable', 'closure'} and trace not in http_methods)
            base = frozenset(trace for trace in ordinary if trace.kind not in {'function', 'opaque-value'})
            results, states = [opaque_return], [opaque_state] if opaque_state is not None else []
            for target in sorted(native_calls):
                branch = dict(state)
                results.append(self.call(target, base, arguments, site, branch, bindings))
                states.append(branch)
            for closure in stored:
                branch = dict(state)
                results.append(self.invoke_stored(closure, tuple(fact for _, fact, _ in arguments), branch))
                states.append(branch)
            for method in http_methods:
                branch = dict(state)
                result = self.outbound_call(name, frozenset({method}), arguments, token, branch, bindings)
                if result is None:
                    result = self.limitation('Swift outbound HTTP receiver or overload needs binding analysis',
                                             token.start, branch, bindings)
                results.append(result)
                states.append(branch)
            if ordinary:
                branch = dict(state)
                results.append(self.call(name, ordinary, arguments, site, branch, bindings,
                                         selected_callable=selected_callable))
                states.append(branch)
            state.clear()
            state.update(join_states(*states))
            return join(*results)
        values = [value for _, value, _ in arguments]
        labeled = {label: value for label, value, _ in arguments if label}
        value = join(receiver, *values)
        candidates = self.candidates(name, receiver, state, bindings, direct=direct)
        if name == 'Self' or leaf == 'init' and name not in self.parser.types:
            return join(self.forget(value), self.limitation(
                'Swift delegating initializer needs initialization-order analysis', token.start, state, bindings))
        if leaf == 'decode' and swift_has_shape(receiver, 'request-content'):
            if ('Request' in self.parser.types or 'Vapor' in self.parser.types or any(
                    function.name == 'decode' and function.owner and function.owner[-1].split('.')[-1] in {
                        'Request', 'Content', 'ContentContainer'} for function in self.parser.functions.values())):
                return join(self.source(token.start, name + '()'), self.limitation(
                    'Swift request content decoder identity needs binding analysis', token.start, state, bindings))
            selected = swift_text(arguments[0][2]) if arguments else ''
            match = re.fullmatch(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.self', selected)
            if len(arguments) != 1 or arguments[0][0] or not match or match.group(1) not in self.parser.types:
                return join(self.source(token.start, name + '()'), self.limitation(
                    'Swift request decoding needs a selected local type', token.start))
            return self.decode_object(match.group(1), self.source(token.start, name + '()'),
                                      CallSite(token), state, bindings)
        if any(swift_has_shape(receiver, shape) for shape in {'decoder', 'decoder-container'}):
            if any(function.owner and function.owner[-1].split('.')[-1] in {
                    'Decoder', 'KeyedDecodingContainer', 'UnkeyedDecodingContainer', 'SingleValueDecodingContainer'}
                    and function.name == leaf for function in self.parser.functions.values()):
                return join(self.forget(value), self.limitation(
                    'Swift extended decoder dispatch needs binding analysis', token.start, state, bindings))
            if leaf in {'container', 'singleValueContainer', 'unkeyedContainer', 'nestedContainer', 'nestedUnkeyedContainer'}:
                return join(self.forget(receiver), swift_shape('decoder-container', token.start))
            if leaf == 'superDecoder':
                return join(self.forget(receiver), swift_shape('decoder', token.start))
            if leaf in {'decode', 'decodeIfPresent'}:
                selected = swift_text(arguments[0][2]) if arguments else ''
                match = re.fullmatch(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.self', selected)
                if match and match.group(1) in self.parser.types:
                    return self.decode_object(match.group(1), self.forget(receiver), CallSite(token), state, bindings)
                if match and re.fullmatch(r'(?:Swift\.|Foundation\.)?(?:String|Bool|Int\d*|UInt\d*|Float|Double|Data|URL)', match.group(1)):
                    return self.forget(receiver)
                return join(self.forget(receiver), self.limitation(
                    'Swift decoded stored property type needs initialization analysis', token.start))
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
            elif self.policy == 'header':
                self.record(token.start, frozenset(trace for trace in header_value
                    if {tag for tag in trace.tags if tag.startswith('header-key:')} != {'header-key:location'}))
            return swift_shape('instance:' + leaf, token.start)
        if leaf in {'add', 'replaceOrAdd', 'set'} and ('headers' in name.lower()
                or swift_has_shape(receiver, 'instance:Headers')
                or swift_has_shape(receiver, 'instance:HTTPHeaders')):
            name_value = labeled.get('name', CLEAN)
            names = {trace.key[1].lower() for trace in name_value
                     if trace.kind == 'constant' and trace.key[0] == 'literal'}
            name_tokens = next((part for label, _, part in arguments if label == 'name'), ())
            member = swift_text(name_tokens).lower()
            literal_names = bool(name_value) and all(trace.kind == 'constant' and trace.key[0] == 'literal'
                                                     for trace in name_value)
            static_member = bool(re.fullmatch(r'\.[a-z][a-z0-9]*', member))
            only_location = member == '.location' or literal_names and names == {'location'}
            possible_location = (member == '.location' or 'location' in names
                                 or not literal_names and not static_member)
            if self.policy == 'redirect' and possible_location:
                self.record(token.start, labeled.get('value', CLEAN))
            elif self.policy == 'header' and not only_location:
                self.record(token.start, labeled.get('value', CLEAN))
            return CLEAN
        native_file = (not candidates or name.startswith(('req.fileio.', 'request.fileio.')))
        if leaf in {'String', 'Data', 'FileHandle'}:
            native_file = native_file and self.builtin(name, state, bindings)
        elif leaf == 'write' and receiver and all(
                trace.kind == 'shape' and trace.key[0].startswith('instance:')
                and trace.key[0][len('instance:'):] in self.parser.value_types for trace in receiver):
            # A struct or enum declared here (including one shadowing Data)
            # has no Foundation write(to:). A receiver of unknown type may
            # still be String or Data, so it remains a file sink.
            native_file = False
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
                elif self.policy == 'outbound' and leaf in {'String', 'Data'} and 'contentsOf' in labeled:
                    self.record(token.start, frozenset(trace for trace in labeled['contentsOf']
                        if not ('file-url' in trace.tags and 'path-string' not in trace.tags)))
                return CLEAN
        returned, matched = opaque_return, False
        call_states = [opaque_state] if opaque_state is not None else []
        for function in candidates:
            # Callable alternatives are different executions from one input
            # state. An inout overwrite in a later alternative cannot erase an
            # earlier alternative's request-derived mutation.
            branch = dict(state)
            bound = self.bind(function, arguments, branch, bindings)
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
                    fact = branch.get(bindings[captured], CLEAN)
                    if swift_tainted(fact) or swift_has_shape(fact, 'request'):
                        return join(self.forget(value), self.limitation(
                            'Swift request-derived nested capture needs capture analysis', token.start, state, bindings))
            if any(item[2].startswith('inout') for item in function.parameters) and any(item[3] for item in function.parameters):
                raise SwiftUnsupported('Swift defaulted inout arguments need mutation binding analysis; analysis is incomplete', token.start)
            matched = True
            call = self.step(token.start, 'call', name + '()')
            facts = tuple(advance(fact, call) for fact in bound)
            call_receiver = receiver
            receiver_binding = bindings.get(name.split('.', 1)[0], name.split('.', 1)[0])
            if function.name == 'init' and name in self.parser.types:
                # The callable names an initializer, not a function-valued
                # object field that should become part of the new self.
                call_receiver = CLEAN
            if (function.owner == self.function.owner and function.owner and not function.static
                    and function.name != 'init' and '.' not in name and name not in bindings):
                call_receiver, receiver_binding = branch.get('self', CLEAN), 'self'
            call_receiver = self.reference_value(call_receiver, branch)
            summary = self.summaries[self.context(function, facts, receiver=call_receiver)]
            returned = join(returned, advance(summary.returned, call))
            self.thrown = join(self.thrown, advance(summary.thrown, call))
            for offset, fact in summary.effects.items():
                self.effects[offset] = join(self.effects.get(offset, CLEAN), fact)
            self.apply_captures({key: advance(fact, call) for key, fact in summary.captures.items()}, branch)
            if function.owner and not function.static and function.name != 'init':
                receiver_path = tuple(name.split('.')[1:-1]) if '.' in name else ()
                self.object_effect(call_receiver, summary.mutations.get('self', CLEAN),
                                   branch, receiver_binding, receiver_path)
            for index, parameter in enumerate(function.parameters):
                if parameter[2].startswith('inout') and index < len(arguments):
                    # The callee's exit summary includes unchanged inout
                    # parameters too. Use lattice bottom until that summary
                    # is available; an identity guess would permanently add
                    # a false finding before a known literal overwrite.
                    fact = summary.mutations.get(index, CLEAN)
                    tokens = swift_ungroup(arguments[index][2])
                    if len(tokens) == 2 and tokens[0].value == '&':
                        binding = bindings.get(tokens[1].value, tokens[1].value)
                        branch[binding] = fact
                        self.invalidate_properties(binding, branch)
                        if index in summary.assigned:
                            self.note_write(binding, fact)
                elif index < len(bound) and self.reference_ids(bound[index]):
                    self.object_effect(bound[index], summary.mutations.get(index, CLEAN), branch)
            call_states.append(branch)
        if matched:
            state.clear()
            state.update(join_states(*call_states))
            if name in self.parser.types:
                return join(returned, self.allocation(name, token.start))
            return returned
        if candidates and (name in self.parser.types or any(swift_request_dependency(fact) for fact in values)):
            return join(self.forget(value), self.limitation(
                'Swift selected helper arguments could not bind', token.start, state, bindings))
        if self.policy == 'outbound':
            result = self.outbound_call(name, receiver, arguments, token, state, bindings)
            if result is not None:
                return result
        if self.policy == 'header':
            sanitized = self.header_sanitizer(leaf, receiver, arguments, state, bindings)
            if sanitized is not None:
                return sanitized
        if leaf in {'URL', 'URLComponents'} and self.builtin(name, state, bindings):
            if 'fileURLWithPath' in labeled:
                return join(swift_retag(self.forget(labeled['fileURLWithPath']), add=frozenset({'file-url'})),
                            swift_retag(swift_shape('file-url', token.start), add=frozenset({'file-url'})))
            if 'string' in labeled:
                tags = frozenset({'url-object', 'url-id:' + str(token.start)})
                source = labeled['string']
                if self.policy == 'outbound':
                    source = join(source, labeled.get('relativeTo', CLEAN))
                    if leaf == 'URLComponents':
                        tags |= frozenset({'url-components'})
                return join(swift_retag(self.forget(source), add=tags), swift_retag(swift_shape('url', token.start), add=tags))
        if leaf == 'Set' and len(values) == 1 and swift_has_shape(values[0], 'literal-list'):
            return values[0]
        if name in self.parser.types:
            # Types discovered while parsing a callback, type aliases and
            # unmodeled constructors must not bypass initializer effects just
            # because their input is a Request shape rather than a source.
            value = join(value, self.limitation(
                'Swift object initialization needs field analysis', token.start))
            return join(self.forget(value), self.allocation(name, token.start))
        if leaf in {'get', 'first'} and any(swift_has_shape(receiver, kind) for kind in {'request-collection', 'request-content'}):
            return self.source(token.start, name + '()')
        if leaf in {'append', 'appendContentsOf', 'insert', 'remove', 'removeAll', 'removeFirst', 'removeLast', 'removeSubrange', 'replaceSubrange', 'replace', 'appendPathComponent', 'deleteLastPathComponent', 'deletePathExtension'}:
            if self.reference_ids(receiver) and swift_request_dependency(join(*values)):
                return join(self.forget(value), self.limitation(
                    'Swift unresolved reference call needs heap/alias analysis',
                    token.start, state, bindings))
            return self.mutate(name.split('.', 1)[0], join(*values), state, bindings)
        if any(part and part[0].value == '&' for _, _, part in arguments) and swift_tainted(value):
            return join(self.forget(value), self.limitation(
                'Swift unresolved inout call needs mutation analysis', token.start, state, bindings))
        if any(trace.kind == 'function' for fact in values for trace in fact) and (
                swift_tainted(value) or swift_has_shape(value, 'request')):
            return join(self.forget(value), self.limitation(
                'Swift selected callback needs higher-order call analysis', token.start, state, bindings))
        if any(function.name == leaf for function in self.parser.functions.values()) and swift_tainted(value):
            return join(self.forget(value), self.limitation(
                'Swift unresolved receiver dispatch needs binding analysis', token.start, state, bindings))
        self.escape_closures(join(*values), state)
        references = frozenset(trace for fact in [receiver, *values] if self.reference_ids(fact)
                               for trace in fact if trace.kind == 'shape' and trace.key[0].startswith(
                                   ('instance:', 'dynamic-instance:', 'reference:')))
        if references and any(swift_request_dependency(fact) for fact in values):
            return join(self.forget(value), references, self.limitation(
                'Swift unresolved reference call needs heap/alias analysis', token.start, state, bindings))
        if self.callback_seen and any(swift_request_dependency(fact) for fact in values) and (
                '.' in name or any(not fact or any(trace.kind == 'shape' for trace in fact) for fact in values)):
            # An unmodeled method (or a function given an unknown object) can
            # mutate a captured alias. Returning joined arguments alone is not
            # a summary of those heap effects. Selected same-file helpers and
            # modeled native sinks above keep their established semantics.
            return join(self.forget(value), self.limitation(
                'Swift callback with unknown request-derived call effects needs heap/capture analysis',
                token.start, state, bindings))
        if '.' in name and swift_tainted(receiver) and leaf not in {'hasPrefix', 'contains', 'hasSuffix', 'lowercased', 'uppercased', 'replacingOccurrences', 'addingPercentEncoding', 'dropFirst', 'dropLast'}:
            self.mutate(name.split('.', 1)[0], CLEAN, state, bindings)
        # An opaque helper may return one of its reference arguments. Keeping
        # those possible identities avoids silently treating it as disjoint.
        # Keep an unresolved value alternative finite and distinct from bottom.
        # Otherwise an opaque callback factory can disappear when joined with
        # a known callable before a later invocation. It is not a taint source.
        result = join(self.forget(value), references, frozenset({Trace('opaque-value', ())}))
        return join(result, swift_shape('unknown', token.start)) if self.policy == 'outbound' else result

    def member(self, name, receiver, token, owner_binding=None, state=None):
        if state is not None:
            receiver = self.reference_value(receiver, state)
        owners = {tuple(instance.key[0].split(':', 1)[1].split('.')) for instance in swift_top(receiver)
                  if instance.kind == 'shape' and instance.key[0].startswith(('instance:', 'dynamic-instance:', 'type:'))}
        if owners and all(name in self.parser.stored_fields.get(owner, {}) for owner in owners):
            projected = self.project_field(name, receiver)
            if projected is not None:
                if any(trace.kind == 'unknown-layout' for trace in swift_top(receiver)):
                    shadowed = self.parser.types | self.parser.shadow_type_names
                    plain_strings = True
                    for owner in owners:
                        declaration, default, _, _, reason = self.parser.stored_fields[owner][name]
                        selected = declaration.rstrip('?!')
                        if not selected and len(default) == 1 and default[0].kind in {'literal', 'template'}:
                            selected = 'String'
                        native = (selected == 'String' and 'String' not in shadowed
                                  or selected == 'Swift.String' and 'Swift' not in shadowed)
                        if reason or not native:
                            plain_strings = False
                            break
                    if not plain_strings:
                        # Native String writes retain their source alternatives
                        # through the ordinary weak field/alias update. Other
                        # unknown fields can hide dispatch or Request shapes.
                        projected = join(projected, frozenset({Trace('opaque-value', ())}), self.limitation(
                            'Swift mixed incoming stored property needs value binding analysis', token.start))
                if not projected:
                    for owner in owners:
                        declaration, default, _, _, _ = self.parser.stored_fields[owner][name]
                        selected_type = declaration.rstrip('?')
                        if not selected_type and default and default[0].value in self.parser.types:
                            selected_type = default[0].value
                        if selected_type in self.parser.types:
                            kind = 'instance:' if selected_type in self.parser.final_types else 'dynamic-instance:'
                            projected = join(projected, swift_shape(kind + selected_type, token.start))
                            if selected_type not in self.parser.value_types:
                                projected = join(projected, swift_shape('reference:' + selected_type))
                return projected
        if name in {'self', 'callAsFunction'} and any(trace.kind == 'native-callable' for trace in swift_top(receiver)):
            return receiver
        if name == 'write' and not owners and (not receiver or self.native_string_method(name, receiver)):
            # Preserve the existing native write(to:) destination model when
            # extracting the method. A selected local type or an opaque factory
            # does not acquire this identity. The qualified internal name also
            # keeps non-file API signatures subject to ordinary call analysis.
            return frozenset({Trace('native-callable', ('<file-value>.write', token.start))})
        if name in {'file', 'sendFile', 'streamFile', 'readFile', 'serveFile', 'writeFile'} and not any(
                name in self.parser.fields.get(owner, {}) or (owner, name) in self.parser.field_functions
                for owner in owners):
            return join(self.forget(receiver), frozenset({Trace('native-callable', (name, token.start))}))
        resolved, unresolved = [], []
        for owner in sorted(owners):
            if (owner, name) in self.parser.opaque_fields:
                resolved.append(join(self.forget(receiver), self.limitation(
                    self.parser.opaque_fields[(owner, name)], token.start, state)))
                continue
            declaration = self.parser.fields.get(owner, {}).get(name, '')
            if re.fullmatch(r'(?:Vapor\.)?Request\??', declaration):
                resolved.append(swift_shape('request', token.start))
                continue
            stored = self.parser.stored_fields.get(owner, {}).get(name)
            selected_type = declaration.rstrip('?')
            if stored and not selected_type and stored[1] and stored[1][0].value in self.parser.types:
                selected_type = stored[1][0].value
            if stored and selected_type in self.parser.types and self.project_field(name, receiver) is None:
                kind = 'instance:' if selected_type in self.parser.final_types else 'dynamic-instance:'
                fallback = join(self.forget(swift_top(receiver)), swift_shape(kind + selected_type, token.start))
                if selected_type not in self.parser.value_types:
                    fallback = join(fallback, swift_shape('reference:' + selected_type))
                resolved.append(fallback)
                continue
            if (stored and '->' in declaration and self.project_field(name, receiver) is None
                    and any(trace.kind == 'shape' and trace.key[0] in {
                        'instance:' + '.'.join(owner), 'dynamic-instance:' + '.'.join(owner)}
                        for trace in swift_top(receiver))):
                # An incoming object's callable field can differ from its
                # declaration default. Retain that unresolved alternative when
                # joined with a known callable. A constructor's present field
                # marker (even while its summary is bottom) returned above.
                resolved.append(join(self.forget(swift_top(receiver)),
                                     frozenset({Trace('opaque-value', ())})))
                continue
            key = self.parser.field_functions.get((owner, name))
            if stored and key is None:
                resolved.append(self.forget(swift_top(receiver)))
                continue
            if key is not None:
                accessor = self.parser.functions[key]
                selected = frozenset(trace for trace in receiver
                    if swift_field_path(trace) or trace.kind != 'shape' or not trace.key[0].startswith(
                        ('instance:', 'dynamic-instance:', 'reference:'))
                    or trace.key[0].split(':', 1)[1] == '.'.join(owner))
                summary = self.summaries[self.context(accessor, (), receiver=(
                    CLEAN if accessor.name.startswith('<field:') else selected))]
                # A computed getter executes its body, so a literal result
                # stays independent of other tainted receiver fields. Stored
                # field initializers also need later aggregate field writes.
                resolved.append(join(summary.returned, self.forget(swift_top(receiver)))
                                if accessor.name.startswith('<field:') else summary.returned)
                if (not accessor.name.startswith('<field:') and any(
                        trace.kind == 'shape' and trace.key[0] == 'dynamic-instance:' + '.'.join(owner)
                        for trace in swift_top(selected))):
                    resolved.append(self.limitation(
                        'Swift dynamically dispatched property needs accessor binding analysis', token.start))
                self.thrown = join(self.thrown, summary.thrown)
                for offset, fact in summary.effects.items():
                    self.effects[offset] = join(self.effects.get(offset, CLEAN), fact)
                if state is not None:
                    self.object_effect(receiver, summary.mutations.get('self', CLEAN), state, owner_binding)
            else:
                unresolved.append(owner)
        if resolved:
            value = join(*resolved)
            if unresolved:
                value = join(value, self.limitation(
                    'Swift mixed property receivers need accessor binding analysis', token.start))
            return value
        if self.policy == 'outbound':
            if receiver and all(trace.kind == 'shape' and trace.key[0] == 'namespace:Foundation' for trace in receiver) and name == 'URLSession':
                return swift_shape('native-type:URLSession', token.start)
            if receiver and all(trace.kind == 'shape' and trace.key[0] == 'native-type:URLSession' for trace in receiver) and name == 'shared':
                return swift_shape('http-client:foundation', token.start)
            if swift_has_shape(receiver, 'request') and name == 'application':
                return swift_shape('vapor-application', token.start)
            if name == 'client' and any(swift_has_shape(receiver, shape) for shape in {'request', 'vapor-application'}):
                return swift_shape('http-client:vapor', token.start)
            if name in SWIFT_HTTP_METHODS and self.http_receiver(receiver, 'foundation'):
                return swift_shape('http-method:foundation:' + name, token.start)
            if name in SWIFT_CLIENT_METHODS and self.http_receiver(receiver, 'vapor'):
                return swift_shape('http-method:vapor:' + name, token.start)
            if name == 'url' and self.http_request(receiver):
                return swift_retag(frozenset(trace for trace in receiver if trace.key[0] != 'http-request'),
                             remove=frozenset({'http-request'}))
            if name == 'url' and receiver and all('url-components' in trace.tags for trace in receiver):
                return swift_retag(receiver, remove=frozenset({'url-components'}))
        if swift_has_shape(receiver, 'request'):
            if name in {'query', 'parameters', 'params', 'headers', 'cookies'}:
                return swift_shape('request-collection', token.start)
            if name == 'content':
                return swift_shape('request-content', token.start)
            if name in {'url', 'uri'}:
                return self.source(token.start, 'request.' + name)
        if name in {'filename', 'fileName', 'originalFilename', 'originalFileName'}:
            return self.source(token.start, name)
        if name == 'lastPathComponent' and all('file-url' in trace.tags for trace in receiver):
            return swift_retag(self.forget(receiver), add=frozenset({'file-leaf', 'swift-string'}))
        if name in {'standardizedFileURL', 'resolvingSymlinksInPath', 'standardized'} and any('file-url' in trace.tags for trace in receiver):
            return swift_retag(receiver, add=frozenset({'canonical-path'}))
        if name == 'path' and any('file-url' in trace.tags for trace in receiver):
            return swift_retag(receiver, add=frozenset({'path-string', 'swift-string'}))
        if name in {'absoluteString', 'string', 'description'} and any('url-object' in trace.tags for trace in receiver):
            return swift_retag(receiver, add=frozenset({'serialized-url', 'swift-string'}), remove=frozenset({'url-object'}))
        if name in {'host', 'scheme'} and any('url-object' in trace.tags for trace in receiver):
            links = frozenset({'property-of:' + owner_binding, 'url-property:' + name}) if owner_binding else frozenset()
            return swift_retag(receiver, add=links | frozenset({'swift-string'}), remove=frozenset({'url-object', 'serialized-url'}))
        if name in {'query', 'parameters', 'params', 'headers', 'content'} and swift_tainted(receiver):
            return receiver
        value = self.forget(receiver)
        return join(value, swift_shape('unknown', token.start)) if self.policy == 'outbound' else value

    def watch_captures(self):
        """Retain future values only for a context which owns a capture.

        Discovering the first capture invalidates the outer fixpoint so that
        earlier writes, branch paths and forwarded callbacks are revisited.
        A leaf predicate's unrelated locals need no whole-state history.
        """
        if self.active_context not in self.capture_origins:
            self.capture_origins.add(self.active_context)
            self.capture_revision += 1
            # Earlier writes may precede the first closure encountered by the
            # worklist. Revisit its lexical owner and the summary invoking it.
            origin = self.active_context
            while origin not in self.contexts and isinstance(origin, tuple) and len(origin) == 2:
                origin = origin[0]
            if origin in self.contexts:
                self.enqueue(origin)
            if self.summary_context is not None:
                self.enqueue(self.summary_context)

    def store_closure(self, tokens, state, bindings, depth):
        self.watch_captures()
        inner = SwiftLexer(self.text).scan(tokens[0].end, tokens[-1].start)
        captures, _parameters, _body, _explicit = self.parser.closure_signature(inner)
        snapshots = tuple((token.value, self.expression(expression, state, bindings, depth + 1))
                          for token, expression in captures)
        key = (tokens[0].start, tokens[-1].end, self.active_context, snapshots)
        if key not in self.closure_keys:
            self.budget.spend()
            if len(self.stored_closures) >= 2048:
                raise AnalysisLimit('Swift stored closure allocation limit exceeded; analysis is incomplete')
            identifier = len(self.stored_closures)
            self.closure_keys[key] = identifier
            self.stored_closures[identifier] = (tuple(tokens), self.function, dict(bindings),
                                                dict(state), dict(snapshots), self.active_context)
        return frozenset({Trace('closure', (self.closure_keys[key],))})

    def invoke_stored(self, closure, arguments, state):
        self.enable_callbacks()
        tokens, function, bindings, captured, snapshots, context = self.stored_closures[closure.key[0]]
        if closure.key[0] in self.active_closures:
            return self.limitation('Swift recursive stored callback needs a recursive closure summary',
                                   tokens[0].start, state, bindings)
        if len(self.active_closures) >= 64:
            raise AnalysisLimit('Swift stored closure nesting limit exceeded; analysis is incomplete')
        parent, active = self.function, self.active_context
        visible = {binding: fact for binding, fact in state.items()
                   if self.capture_visible(context, binding)}
        environment = join_states(captured, self.future_captures(context), visible)
        writes = {}
        self.active_closures.add(closure.key[0])
        try:
            self.function, self.active_context = function, context
            value = self.inline_closure(tokens, join(*arguments), environment, bindings, 0,
                                        capture_values=snapshots, argument_values=arguments,
                                        capture_writes=writes)
            self.apply_captures({(context, binding): fact for binding, fact in writes.items()},
                                state, context=active)
            return value
        finally:
            self.function, self.active_context = parent, active
            self.active_closures.remove(closure.key[0])

    def escape_closures(self, value, state):
        for closure in value:
            if closure.kind != 'closure':
                continue
            self.enable_callbacks()
            tokens = self.stored_closures[closure.key[0]][0]
            unknown = swift_retag(self.source(tokens[0].start, 'unknown closure parameter'),
                            add=frozenset({'unknown-provenance'}))
            self.invoke_stored(closure, (unknown,), state)

    def inline_closure(self, tokens, argument, state, bindings, depth, *, catches_errors=False,
                       capture_values=None, argument_values=None, capture_writes=None):
        """Evaluate a collection callback with lexical captures and a loop join.

        A method name does not establish nonescaping execution. Captures also
        inherit the enclosing context's reachable future values. Zero or more
        calls are possible, so a callback cannot strongly kill a captured value
        or confer its element proof on the whole collection. Unknown callback
        APIs can supply unknown arguments. Explicit capture-list entries are
        snapshots; ordinary lexical captures also see reachable later writes.
        """
        if depth > 64:
            raise AnalysisLimit('Swift closure nesting limit exceeded; analysis is incomplete')
        self.watch_captures()
        # Expression normalization removes newlines. Recover this exact source
        # range so separate callback statements retain their control flow.
        inner = SwiftLexer(self.text).scan(tokens[0].end, tokens[-1].start)
        captures, parameters, body_tokens, explicit = self.parser.closure_signature(inner)
        if not explicit:
            names = {'$0', *(item.value for item in body_tokens
                            if item.kind == 'code' and re.fullmatch(r'\$\d+', item.value))}
            parameters = tuple((SwiftToken(name, tokens[0].start, tokens[0].end), '')
                               for name in sorted(names))
        parent = self.function
        body = self.parser.block(body_tokens, parent.owner, (*parent.scope, parent.key))
        body = self.parser.result_body(body) or body
        function = SwiftFunction(tokens[0].start, '<closure>', parent.owner,
                                 (*parent.scope, parent.key), (), body)
        scope = dict(bindings)
        initial = dict(state)
        initial.pop('@result', None)
        future = self.future_captures(self.active_context)
        for binding in bindings.values():
            initial[binding] = join(initial.get(binding, CLEAN),
                                    future.get(binding, CLEAN))
        for capture, expression in captures:
            # Evaluate in the creation environment before introducing aliases.
            value = (capture_values[capture.value] if capture_values is not None
                     else self.expression(expression, state, bindings, depth + 1))
            scope[capture.value] = 'capture:' + str(capture.start)
            initial[scope[capture.value]] = value
        for index, (parameter, declaration) in enumerate(parameters):
            if parameter.value == '_':
                continue
            scope[parameter.value] = 'closure-argument:' + str(parameter.start) + ':' + parameter.value
            value = argument if argument_values is None or index >= len(argument_values) else argument_values[index]
            if re.fullmatch(r'(?:Vapor\.)?Request\??', declaration):
                value = join(value, swift_shape('request', parameter.start))
            initial[scope[parameter.value]] = value
        initial['@reachable'] = swift_constant('true', 'code')
        entry, actions, edges = self.graph(function, scope)
        returned, mutations, context, thrown = self.returned, self.mutations, self.active_context, self.thrown
        result, raised = CLEAN, CLEAN
        # Only parent bindings escape the callback. Its locals and @result
        # must not overwrite either a sibling closure or the enclosing return.
        captured = set(state) - {'@result', '@reachable'}
        captured.update(bindings.values())
        writes = {} if capture_writes is None else capture_writes
        self.capture_frames.append((context, captured, writes))
        try:
            self.function, self.mutations = function, {}
            self.active_context = (context, tokens[0].start)
            while True:
                self.budget.spend()
                self.returned, self.thrown = CLEAN, CLEAN
                solve(entry, initial, edges, lambda node, incoming: self.observe(actions[node], incoming),
                      self.budget)
                # Testing's throws expectations can return the caught error.
                # Unknown collection implementations may also handle it, so
                # retain dependencies from exceptional callback exits.
                result = join(result, self.returned, self.thrown)
                raised = join(raised, self.thrown)
                updated = dict(initial)
                # observe() and apply_captures() record every captured write,
                # including writes through aliases and nested helper calls.
                # Only those slots can change the next callback invocation;
                # joining every unchanged local at every node is quadratic in
                # large SwiftUI closures and adds no possible flow.
                for binding, value in writes.items():
                    updated[binding] = join(initial.get(binding, CLEAN), value)
                if updated == initial:
                    break
                initial = updated
            self.apply_captures({(context, binding): fact for binding, fact in writes.items()}, state)
            return result
        finally:
            self.capture_frames.pop()
            self.function, self.returned, self.mutations, self.active_context = parent, returned, mutations, context
            # Collection operations can rethrow even when their expression
            # result is discarded by a multi-statement enclosing helper.
            # Testing assertions catch that error into their own result.
            self.thrown = thrown if catches_errors else join(thrown, raised)

    # one Swift closure argument: name, receiver, token slice, state, bindings and depth, plus member_call; a parameter record is bead ultimate_bug_scanner-8tqg — ubs:ignore[py.functions.high-param-count]
    def callback(self, name, receiver, tokens, state, bindings, depth, member_call=False):
        self.enable_callbacks()
        leaf = name.rsplit('.', 1)[-1]
        if name in {'#expect', '#require'}:
            argument = CLEAN
        elif (member_call and leaf in {'map', 'compactMap', 'flatMap', 'filter', 'forEach', 'contains', 'first'}
              and not any(function.name == leaf for function in self.parser.functions.values())
              and not any(trace.kind == 'shape' and trace.key[0].startswith(('dynamic-instance:', 'instance:')) for trace in receiver)):
            argument = receiver
            if any(swift_has_shape(receiver, kind) for kind in {'request-collection', 'request-content'}):
                argument = join(argument, self.source(tokens[0].start, 'request callback element'))
            requests = frozenset(trace for trace in argument if trace.kind == 'shape'
                and trace.key[0] in {'request', 'request-collection', 'request-content'})
            argument = join(self.forget(argument), requests)
        else:
            # Unknown call: the closure parameter has unknown provenance. It is
            # request-tainted if the receiver or any argument is (call() folds the
            # call's argument taint into the receiver value). Otherwise it carries an
            # 'unknown-provenance' source so that reaching a sink's checked position
            # refuses -- an unknown call may invoke the closure with a request.
            requests = frozenset(trace for trace in receiver if trace.kind == 'shape'
                and trace.key[0] in {'request', 'request-collection', 'request-content'})
            argument = join(self.forget(receiver), requests)
            if not swift_request_dependency(argument):
                argument = join(argument, swift_retag(self.source(tokens[0].start, 'unknown closure parameter'),
                                                add=frozenset({'unknown-provenance'})))
        value = self.inline_closure(tokens, argument, state, bindings, depth + 1,
                                    catches_errors=name in {'#expect', '#require'})
        # A method name also does not prove that its result is exactly the
        # callback return (an external map may ignore the callback). Retain
        # receiver dependencies rather than treating map as a sanitizer.
        return join(self.forget(receiver), argument, value)

    def expression(self, tokens, state, bindings, depth=0):
        if depth > 64:
            raise AnalysisLimit('Swift expression nesting limit exceeded; analysis is incomplete')
        tokens = swift_ungroup(tokens)
        while tokens and tokens[0].value in {'try', 'await', '?', '!'}:
            tokens = tokens[1:]
        if not tokens:
            return CLEAN
        for index, token in enumerate(tokens):
            if token.value == '<' and swift_text(tokens[:index]) in self.parser.generic_types:
                raise SwiftUnsupported(
                    'Swift generic type initialization needs type-substitution analysis; analysis is incomplete',
                    tokens[0].start)
        if tokens[0].value in {'switch', 'if'}:
            # Statement/return assignments are lowered by the CFG builder.
            # Other value positions need that same branch-to-result binding;
            # treating their braces as a callback would drop branch values.
            raise SwiftUnsupported('Swift embedded control-flow expression needs result binding analysis; analysis is incomplete',
                                   tokens[0].start)
        components = swift_parts(tokens, {','})
        if len(components) > 1:
            # Preserve all tuple dependencies, including request-object shapes.
            # Iteration projection below deliberately drops validation facts;
            # these joined components are not positional proof of a safe value.
            return join(*(self.expression(part, state, bindings, depth + 1) for part in components))
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
            if set(operators) <= {'??'}:
                return value
            if self.policy == 'header' and set(operators) <= {'+'}:
                return self.header_text(values)
            return self.forget(value)
        if tokens[0].value == '#':
            if len(tokens) > 1 and tokens[1].value in {'available', 'unavailable'}:
                return CLEAN
            imports_testing = any(left.value == 'import' and right.value == 'Testing'
                                  for left, right in zip(self.parser.tokens, self.parser.tokens[1:]))
            if (len(tokens) < 3 or tokens[1].value not in {'expect', 'require'} or tokens[2].value != '('
                    or not imports_testing or any(item.value == 'macro' for item in self.parser.tokens)):
                raise SwiftUnsupported('Swift macro expansion needs analysis; analysis is incomplete', tokens[0].start)
            name, cursor, value, owner_binding = '#' + tokens[1].value, 2, CLEAN, None
        elif tokens[0].kind in {'literal', 'number', 'regex', 'template'}:
            token = tokens[0]
            if token.kind == 'template':
                parts = [self.expression(part, state, bindings, depth + 1) for part in token.parts]
                if self.policy == 'header':
                    value = self.header_text([swift_constant(token.value), *parts])
                else:
                    value = swift_retag(self.forget(join(*parts)), add=frozenset({'swift-string'}))
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
                    parts.append(swift_retag(fact, add=frozenset({'header-key:' + key[0].value.lower()})))
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
            close = swift_close(tokens, 0)
            value = self.store_closure(tokens[:close + 1], state, bindings, depth)
            cursor, name, owner_binding = close + 1, '', None
        elif tokens[0].value in {'nil', 'true', 'false'}:
            return swift_constant(tokens[0].value, 'code')
        elif tokens[0].value == '&':
            return self.expression(tokens[1:], state, bindings, depth + 1)
        else:
            name = tokens[0].value
            owner_binding = bindings.get(name, name)
            value = self.reference_value(state.get(owner_binding, self.globals.get(name, CLEAN)), state)
            if not value and name not in bindings and name in self.parser.fields.get(self.function.owner, {}):
                value = self.member(name, state.get('self', CLEAN), tokens[0], 'self', state)
            if not value and name in {'req', 'request'} and name not in bindings and name not in state:
                value = swift_shape('request', tokens[0].start)
            if not value and name in self.parser.types and len(tokens) > 1 and tokens[1].value == '.':
                value = swift_shape('type:' + name, tokens[0].start)
            if not value:
                functions = self.candidates(name, CLEAN, state, bindings)
                value = frozenset(Trace('function', (function.key,)) for function in functions)
            if (not value and name not in bindings and name not in state
                    and name in {'file', 'sendFile', 'streamFile', 'readFile', 'serveFile', 'writeFile'}):
                value = frozenset({Trace('native-callable', (name, tokens[0].start))})
            if self.policy == 'outbound' and not value and name not in bindings and name not in state:
                if self.builtin(name, state, bindings) and name in {'URLSession', 'Foundation'}:
                    shape = 'native-type:URLSession' if name == 'URLSession' else 'namespace:Foundation'
                    value = swift_shape(shape, tokens[0].start)
                elif name not in self.globals:
                    # An unresolved alternative must not disappear when joined
                    # with a known session and thereby prove a native receiver.
                    value = swift_shape('unknown', tokens[0].start)
            if (len(tokens) == 1 and name not in bindings and name not in state
                    and name not in self.globals and name not in self.parser.types
                    and name not in self.parser.fields.get(self.function.owner, {})
                    and (not value or all(trace.kind == 'shape' and trace.key[0] == 'unknown'
                                          for trace in value))):
                # Imported function values are not selected same-file helpers.
                # Preserve this alternative through joins until it is invoked.
                value = join(value, frozenset({Trace('opaque-value', ())}))
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
                if cursor < len(tokens) and tokens[cursor].value == '{':
                    close = swift_close(tokens, cursor)
                    if not self.trailing_route_closure(name, tokens[cursor], tokens[close], state, bindings):
                        value = self.callback(name, value, tokens[cursor:close + 1], state, bindings, depth, member_call=True)
                    cursor = close + 1
                elif cursor < len(tokens) and tokens[cursor].value == '(':
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
                        value = join(swift_retag(self.forget(value), add=frozenset({'file-url'})),
                                     swift_retag(self.forget(addition, frozenset({'file-leaf'})), add=frozenset({'file-url'})),
                                     swift_retag(swift_shape('file-url', member.start), add=frozenset({'file-url'})))
                    elif member.value == 'resolvingSymlinksInPath' and not arguments:
                        value = self.member(member.value, value, member, owner_binding, state)
                    else:
                        value = self.call(name, value, arguments, CallSite(tokens[0], member), state, bindings)
                    cursor = close + 1
                else:
                    value = self.member(member.value, value, member, owner_binding, state)
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
                previous = cursor - 1
                while previous >= 0 and tokens[previous].value in {'?', '!'}:
                    previous -= 1
                selected = previous >= 0 and tokens[previous].value in {')', ']', '}'}
                value = self.call(name, value, arguments, CallSite(tokens[0]), state, bindings,
                                  selected_callable=selected)
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
                close = swift_close(tokens, cursor)
                if self.trailing_route_closure(name, token, tokens[close], state, bindings):
                    cursor = close + 1
                    continue
                value = self.callback(name, value, tokens[cursor:close + 1], state, bindings, depth)
                cursor = close + 1
                continue
            if token.value == 'as' and self.reference_ids(value):
                target = swift_text(tokens[cursor + 1:]).lstrip('?!')
                if target in self.parser.types or target in {'Any', 'AnyObject'}:
                    identities = frozenset(trace for trace in value if trace.kind == 'shape'
                        and trace.key[0].startswith(('instance:', 'dynamic-instance:', 'reference:')))
                    # A checked/forced reference cast changes the static view,
                    # not the object. It establishes no sanitizer proof.
                    return join(self.forget(value), identities)
            # Preserve dependencies in selected casts, tuples and unfamiliar
            # operators, but do not preserve any validation across them.
            value = self.forget(join(value, self.expression(tokens[cursor + 1:], state, bindings, depth + 1)))
            break
        if (not value and len(tokens) > 1
                and re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+', swift_text(tokens))
                and tokens[0].value not in bindings and tokens[0].value not in state
                and tokens[0].value not in self.globals and tokens[0].value not in self.parser.types):
            value = frozenset({Trace('opaque-value', ())})
        return value

    def trailing_route_closure(self, name, token, close_token, state, bindings):
        leaf = name.rsplit('.', 1)[-1]
        if '.' not in name or leaf not in {'get', 'post', 'put', 'patch', 'delete', 'on', 'webSocket'}:
            return False
        closure_tokens = tuple(
            item for item in self.parser.tokens
            if token.end <= item.start and item.end <= close_token.start
        )
        in_index = None
        probe = 0
        while probe < len(closure_tokens):
            tok = closure_tokens[probe]
            if tok.kind == 'code':
                if tok.value in {'(', '['}:
                    probe = swift_close(closure_tokens, probe)
                elif tok.value in {'{', ';'}:
                    break
                elif tok.value == 'in':
                    in_index = probe
                    break
            probe += 1
        if in_index is None:
            return False
        header = tuple(tok for tok in closure_tokens[:in_index] if tok.kind != 'code' or tok.value != '\n')
        arrow_parts = swift_parts(header, {'->'})
        if len(arrow_parts) > 2:
            return False
        return_type = swift_text(swift_ungroup(arrow_parts[1])) if len(arrow_parts) == 2 else ''
        param_section = arrow_parts[0]
        while param_section and param_section[-1].kind == 'code' and param_section[-1].value in {'async', 'throws', 'rethrows'}:
            param_section = param_section[:-1]
        param_section = swift_ungroup(param_section)
        raw_params = [swift_ungroup(p) for p in swift_parts(param_section, {','}) if swift_ungroup(p)]
        if not raw_params:
            return False
        parameters = []
        for idx, raw_param in enumerate(raw_params):
            colon_parts = swift_parts(raw_param, {':'})
            if len(colon_parts) == 1:
                if len(raw_param) != 1 or raw_param[0].kind != 'code' or not re.fullmatch(r'[A-Za-z_]\w*', raw_param[0].value):
                    return False
                param_name = raw_param[0].value
                decl_type = 'Request' if idx == 0 else ''
            elif len(colon_parts) == 2:
                lhs_names = [t.value for t in colon_parts[0] if t.kind == 'code']
                if len(lhs_names) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', lhs_names[0]):
                    return False
                param_name = lhs_names[0]
                decl_type = swift_text(swift_ungroup(colon_parts[1]))
            else:
                return False
            parameters.append((param_name, '', decl_type, ()))
        body_tokens = closure_tokens[in_index + 1:]
        body = self.parser.block(body_tokens, self.function.owner, (*self.function.scope, self.function.key))
        if len(body) == 1 and body[0].kind == 'simple' and not self.parser.assignment(body[0].tokens):
            body = (replace(body[0], kind='return'),)

        def identifiers(statements):
            for statement in statements:
                yield from (item.value for item in statement.tokens if item.kind == 'code')
                yield from identifiers(statement.body)
                yield from identifiers(statement.alternate)

        def outer_writes(statements, local_names):
            for statement in statements:
                if statement.kind == 'simple':
                    assign = self.parser.assignment(statement.tokens)
                    if assign and assign[0]:
                        if assign[4]:
                            local_names = local_names | {assign[0]}
                        elif assign[0] not in local_names and assign[0] in bindings:
                            return True
                if outer_writes(statement.body, set(local_names)) or outer_writes(statement.alternate, set(local_names)):
                    return True
            return False

        param_names = {item[0] for item in parameters}
        if outer_writes(body, set(param_names)):
            return False
        self.enable_callbacks()
        self.watch_captures()
        future = self.future_captures(self.active_context)
        names = set(identifiers(body)) - param_names
        for captured in names.intersection(bindings):
            binding = bindings[captured]
            # Route handlers escape too. A value written after registration
            # or through an object alias cannot become a clean capture.
            fact = join(state.get(binding, CLEAN),
                        future.get(binding, CLEAN))
            if swift_request_dependency(fact):
                return False
        closure_fn = self.parser.functions.get(token.start)
        if closure_fn is None:
            closure_fn = SwiftFunction(
                token.start,
                f'<closure@{token.start}>',
                self.function.owner,
                (*self.function.scope, self.function.key),
                tuple(parameters),
                body,
                return_type=return_type,
            )
            self.parser.functions[token.start] = closure_fn
        self.context(closure_fn, tuple(CLEAN for _ in parameters), entry=True)
        return True

    def check(self, name, tag, state, bindings):
        binding = bindings.get(name, name)
        value = state.get(binding, self.globals.get(name, CLEAN))
        if tag in SWIFT_LOCAL_TAGS:
            if not self.builtin('String') or any('file-url' in trace.tags or 'url-object' in trace.tags for trace in value):
                return state
            if self.policy == 'header' and not self.native_string_method('contains', value):
                return state
            state[binding] = swift_retag(value, add=frozenset({tag}))
            return state
        if tag in {'url-scheme', 'url-host'}:
            if value and all('url-object' in trace.tags for trace in value):
                state[binding] = swift_retag(value, add=frozenset({tag}))
            else:
                property_name = 'scheme' if tag == 'url-scheme' else 'host'
                links = {item[len('property-of:'):] for trace in value for item in trace.tags
                         if item.startswith('property-of:') and 'url-property:' + property_name in trace.tags}
                for parent in links:
                    owner = state.get(parent, CLEAN)
                    identities = {item for trace in value for item in trace.tags if item.startswith('url-id:')}
                    if owner and all('url-object' in trace.tags and identities.intersection(trace.tags) for trace in owner):
                        state[parent] = swift_retag(owner, add=frozenset({tag}))
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
                state[binding] = join(*(swift_retag(frozenset({trace}), add=frozenset({'contained-path'}))
                    if {'file-url', 'canonical-path'} <= trace.tags else frozenset({trace}) for trace in value))
        return state

    def graph(self, function, outer_scope=None):
        """Build a graph, isolating unsupported semantics to their statement.

        Structural failures and work limits are deliberately not caught here.
        Each retry marks a distinct statement opaque, so unaffected statements
        and other functions retain their ordinary source-to-sink analysis.
        """
        opaque = {}
        while True:
            try:
                return self._graph(function, outer_scope, opaque)
            except SwiftUnsupported as error:
                if not self.recover:
                    raise
                offset = error.offset
                if offset is None or offset in opaque:
                    # A failure without a statement location cannot be safely
                    # localized. Do not turn an internal error into a clean scan.
                    raise
                self.budget.spend()
                opaque[offset] = str(error).removesuffix('; analysis is incomplete')

    def _graph(self, function, outer_scope, opaque):
        actions, edges = {}, {}
        scope = dict(outer_scope or {})
        scope.update({name: 'parameter:' + name for name, _, _, _ in function.parameters})
        binding_types = {'parameter:' + name: declaration
                         for name, _, declaration, _ in function.parameters}
        enclosing = [self.parser.functions[key] for key in function.scope if key in self.parser.functions]
        generic_context = function.generic or any(parent.generic for parent in enclosing) or any(
            '.'.join(function.owner[:index]) in self.parser.generic_types
            for index in range(1, len(function.owner) + 1))
        static_context = function.static or any(parent.static and parent.owner == function.owner for parent in enclosing)

        def type_owner(declaration, context=function.owner):
            # swift_text removes whitespace. Do not confuse `inout Choice`
            # (or another type modifier) with an unrelated joined identifier.
            if (declaration.startswith(('inout', 'some', 'any', 'borrowing', 'consuming', 'isolated', 'sending'))
                    or any(part in self.parser.aliased_types for part in declaration.split('.')) or generic_context
                    or any('.'.join(context[:index]) in self.parser.generic_types
                           for index in range(1, len(context) + 1))
                    or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', declaration)):
                return ()
            parts = tuple(declaration.split('.'))
            return next(((*context[:index], *parts)
                         for index in range(len(context), -1, -1)
                         if (*context[:index], *parts) in self.parser.type_declarations), ())

        def enum_subject(tokens, bindings):
            """Prove a subject's declared enum type, without trusting joined facts.

            A joined fact may contain one enum shape and another unknown value.
            Only lexical type declarations authorize skipping executable ~=.
            Unannotated/compound expressions remain explicitly incomplete.
            """
            text = swift_text(swift_ungroup(tokens))
            if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', text):
                return ()
            root, *members = text.split('.')
            if root == 'self':
                owner = () if static_context or generic_context else function.owner
            elif root in bindings:
                owner = type_owner(binding_types.get(bindings[root], ''))
            else:
                owner = type_owner(self.parser.fields.get(function.owner, {}).get(root, ''))
            for member in members:
                owner = type_owner(self.parser.fields.get(owner, {}).get(member, ''), owner)
            return owner if owner in self.parser.enum_cases else ()

        def node(kind, tokens=(), bindings=None, targets=(), extra=None, reads=None):
            self.budget.spend()
            key = len(actions)
            local = {} if bindings is None else dict(bindings)
            actions[key], edges[key] = (kind, tokens, local, extra, local if reads is None else dict(reads)), tuple(targets)
            return key

        exit_node = node('exit', bindings=scope)

        def throwing(tokens):
            return any(token.kind == 'code' and token.value == 'try'
                       and (index + 1 >= len(tokens) or tokens[index + 1].value not in {'?', '!'})
                       for index, token in enumerate(tokens))

        def condition(tokens, yes, no, bindings, reads=None, throw_to=None):
            tokens = swift_ungroup(tokens)
            commas = swift_parts(tokens, {','})
            conjunction = swift_parts(tokens, {'&&'})
            disjunction = swift_parts(tokens, {'||'})
            if len(commas) > 1:
                snapshots, local = [], dict(bindings if reads is None else reads)
                for part in commas:
                    before = dict(local)
                    local = optional_scope(part, local)
                    snapshots.append((dict(local), before))
                for part, (local, before) in reversed(list(zip(commas, snapshots))):
                    yes = condition(part, yes, no, local, before, throw_to)
                return yes
            if len(conjunction) > 1:
                for part in reversed(conjunction):
                    yes = condition(part, yes, no, bindings, throw_to=throw_to)
                return yes
            if len(disjunction) > 1:
                for part in reversed(disjunction):
                    no = condition(part, yes, no, bindings, throw_to=throw_to)
                return no
            if tokens and tokens[0].value == '!':
                return condition(tokens[1:], no, yes, bindings, reads, throw_to)
            exceptional = (throw_to,) if throw_to is not None and throwing(tokens) else ()
            if tokens and tokens[0].value == 'case':
                (names, expressions, total, _structural), subject = conditional_pattern(tokens)
                slot = '@case:' + str(tokens[0].start)
                matched = node('switch-bind', subject, bindings, (yes,),
                               (slot, tuple((name.value, projected) for name, projected in names)))
                matched = node('branch', targets=(matched,) if total else (matched, no))
                for expression, projected in reversed(expressions):
                    matched = node('switch-expression', expression, bindings, (matched, no) + exceptional,
                                   (slot, () if projected else enum_subject(subject, bindings if reads is None else reads)),
                                   reads=reads)
                return node('switch-subject', subject, bindings, (matched,) + exceptional, slot, reads=reads)
            assignment = self.parser.assignment(tokens)
            if assignment and assignment[-1]:
                return node('optional', tokens, bindings, (yes, no) + exceptional, reads=reads)
            if len(tokens) == 2 and tokens[0].value in {'let', 'var'}:
                return node('optional-shorthand', tokens, bindings, (yes, no), reads=reads)
            text = swift_text(tokens)
            positive = node('proof', tokens, bindings, (yes,), True)
            negative = node('proof', tokens, bindings, (no,), False)
            targets = (positive,) if text == 'true' else (negative,) if text in {'false', 'nil'} else (positive, negative)
            return node('eval', tokens, bindings, targets + exceptional)

        def optional_scope(tokens, bindings):
            local = dict(bindings)
            for part in swift_parts(swift_ungroup(tokens), {','}):
                if part and part[0].value == 'case':
                    (names, _expressions, _total, _structural), _subject = conditional_pattern(part)
                    for name, _projected in names:
                        local[name.value] = name.value + '@' + str(name.start)
                    continue
                assignment = self.parser.assignment(part)
                if assignment and assignment[-1] and assignment[0]:
                    local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                elif len(part) == 2 and part[0].value in {'let', 'var'}:
                    local[part[1].value] = part[1].value + '@' + str(part[1].start)
            return local

        def process_exit(tokens, bindings):
            tokens = swift_ungroup(tokens)
            opening = next((i for i, token in enumerate(tokens) if token.value == '('), -1)
            if opening < 0 or swift_close(tokens, opening) != len(tokens) - 1:
                return False
            name = swift_text(tokens[:opening])
            if name not in {'exit', 'Darwin.exit', 'Glibc.exit', 'fatalError', 'Swift.fatalError',
                            'preconditionFailure', 'Swift.preconditionFailure'}:
                return False
            root, leaf = name.split('.')[0], name.split('.')[-1]
            if root in bindings or root in self.parser.types or root in self.local_globals:
                return False
            if any(left.value in {'let', 'var'} and right.value == root
                   for left, right in zip(self.parser.tokens, self.parser.tokens[1:])):
                return False
            if '.' not in name and any(fn.name == leaf for fn in self.parser.functions.values()):
                return False
            if '.' not in name and function.owner:
                # An inherited member may shadow the global primitive.
                return False
            return True

        def terminates(statements, bindings):
            local = dict(bindings)
            for statement in statements:
                assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                if assignment and assignment[-1] and assignment[0]:
                    local[assignment[0]] = assignment[0]
                if statement.kind in {'return', 'throw', 'break', 'continue'}:
                    return True
                if statement.kind == 'if' and terminates(statement.body, local) and terminates(statement.alternate, local):
                    return True
                if statement.kind == 'simple' and process_exit(statement.tokens, local):
                    return True
            return False

        def pattern_names(tokens):
            """Bind case/catch payloads without claiming their pattern matched.

            Every arm remains possible; each component inherits the subject's
            dependencies. Types, enum constructors, labels and wildcards are
            not value bindings.
            """
            names, binding = {}, False
            for index, token in enumerate(tokens):
                if token.kind != 'code':
                    continue
                if token.value in {'let', 'var'}:
                    binding = True
                    continue
                if token.value in {'where', 'is', 'as'}:
                    binding = False
                    continue
                previous = tokens[index - 1].value if index else ''
                following = tokens[index + 1].value if index + 1 < len(tokens) else ''
                if (binding and re.fullmatch(r'[A-Za-z_]\w*', token.value)
                        and token.value not in {'_', 'true', 'false', 'nil'}
                        and previous != '.' and following not in {'(', ':', '.'}):
                    names[token.value] = token
            return tuple(names.values())

        def switch_pattern(tokens, binding=False, projected=False, depth=0):
            """Return bindings, executable patterns, totality and pattern syntax.

            Binding syntax proves a structural pattern. Binding-free member
            patterns also need the subject's exact enum type: the same spelling
            can call an overloaded ~= with another subject type. Their transfer
            action checks that evidence before skipping matching effects.
            """
            if depth > 64:
                raise AnalysisLimit('Swift switch pattern nesting limit exceeded; analysis is incomplete')
            tokens = tuple(t for t in tokens if t.kind != 'code' or t.value != '\n')
            if not tokens:
                raise ValueError('Swift switch has an empty pattern; analysis is incomplete')
            if tokens[0].value in {'let', 'var'}:
                return switch_pattern(tokens[1:], True, projected, depth + 1)
            if tokens[-1].value == '?':
                names, expressions, _, _structural = switch_pattern(tokens[:-1], binding, projected, depth + 1)
                return names, tuple((expression, True) for expression, _ in expressions), False, True
            casts = swift_parts(tokens, {'as'})
            if len(casts) == 2:
                target = swift_text(casts[1])
                if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\??', target):
                    raise SwiftUnsupported('Swift switch cast needs type analysis; analysis is incomplete', tokens[0].start)
                names, expressions, _, structural = switch_pattern(casts[0], binding, projected, depth + 1)
                if structural:
                    return names, tuple((expression, True) for expression, _ in expressions), False, True
                return (), ((tokens, projected),), False, False
            if tokens[0].value == 'is':
                if re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\??', swift_text(tokens[1:])):
                    return (), (), False, True
                raise SwiftUnsupported('Swift switch type pattern needs analysis; analysis is incomplete', tokens[0].start)
            if tokens[0].value == '(' and swift_close(tokens, 0) == len(tokens) - 1:
                parts = swift_parts(tokens[1:-1], {','})
                if len(parts) == 1 and not parts[0]:
                    return (), (), True, False
                names, expressions, complete, structural = [], [], True, False
                for part in parts:
                    labels = swift_parts(part, {':'})
                    if len(labels) == 2 and len(labels[0]) == 1 and re.fullmatch(r'[A-Za-z_]\w*', labels[0][0].value):
                        part = labels[1]
                    found, effects, total, syntax = switch_pattern(part, binding, projected or len(parts) > 1, depth + 1)
                    names.extend(found); expressions.extend(effects); complete = complete and total
                    structural = structural or syntax
                if len({name.value for name, _ in names}) != len(names):
                    raise ValueError('Swift switch pattern repeats a binding; analysis is incomplete')
                return tuple(names), tuple(expressions), complete, structural
            if len(tokens) == 1:
                token = tokens[0]
                if token.kind == 'code' and token.value == '_':
                    return (), (), True, True
                if token.kind in {'literal', 'number'} or token.value in {'nil', 'true', 'false'}:
                    return (), ((tokens, projected),), False, False
                if binding and token.kind == 'code' and re.fullmatch(r'[A-Za-z_]\w*', token.value):
                    return ((token, projected),), (), True, True
            opening = next((i for i, token in enumerate(tokens) if token.kind == 'code' and token.value == '('), len(tokens))
            prefix = swift_text(tokens[:opening])
            if re.fullmatch(r'(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*|\.[A-Za-z_]\w*', prefix):
                if opening < len(tokens) and swift_close(tokens, opening) == len(tokens) - 1:
                    names, expressions, _, structural = switch_pattern(tokens[opening:], binding, True, depth + 1)
                    if structural:
                        return names, expressions, False, True
            ranges = swift_parts(tokens, {'...', '..<'})
            if len(ranges) == 2 and all(
                    (len(part) == 1 and part[0].kind in {'number', 'literal'})
                    or (len(part) == 2 and part[0].value in {'+', '-'} and part[1].kind == 'number')
                    for part in ranges):
                return (), ((tokens, projected),), False, False
            if len(tokens) == 2 and tokens[0].value in {'+', '-'} and tokens[1].kind == 'number':
                return (), ((tokens, projected),), False, False
            return (), ((tokens, projected),), False, False

        def conditional_pattern(tokens):
            parts = swift_parts(tokens[1:], {'='})
            if len(parts) != 2 or not all(swift_ungroup(part) for part in parts):
                raise SwiftUnsupported('Swift conditional case needs pattern analysis; analysis is incomplete', tokens[0].start)
            return switch_pattern(parts[0]), parts[1]

        def group_directives(statements):
            result, index, total = [], 0, len(statements)
            while index < total:
                statement = statements[index]
                if (statement.kind == 'unsupported' and statement.tokens
                        and statement.tokens[0].value == '#' and len(statement.tokens) > 1
                        and statement.tokens[1].value == 'if'):
                    start = index
                    arms, has_else, depth, index, closed = [[]], False, 1, index + 1, False
                    while index < total:
                        inner = statements[index]
                        marker = (inner.kind == 'unsupported' and inner.tokens
                                  and inner.tokens[0].value == '#' and len(inner.tokens) > 1
                                  and inner.tokens[1].value in {'if', 'elseif', 'else', 'endif'})
                        name = inner.tokens[1].value if marker else ''
                        if name == 'if':
                            depth += 1; arms[-1].append(inner)
                        elif name == 'endif':
                            depth -= 1
                            if depth == 0:
                                index += 1; closed = True; break
                            arms[-1].append(inner)
                        elif name in {'elseif', 'else'} and depth == 1:
                            arms.append([]); has_else = has_else or name == 'else'
                        else:
                            arms[-1].append(inner)
                        index += 1
                    if not closed:
                        raise ValueError('Swift unterminated #if directive; analysis is incomplete')
                    grouped = tuple(group_directives(tuple(arm)) for arm in arms)
                    original = tuple(token for item in statements[start:index] for token in item.tokens)
                    result.append(SwiftStatement('ifdirective', original, (True,) if has_else else (), (), grouped))
                    continue
                result.append(statement); index += 1
            return tuple(result)

        def register_arm_declarations(directive, local):
            for arm in directive.extra:
                for statement in arm:
                    if statement.kind == 'ifdirective':
                        register_arm_declarations(statement, local); continue
                    assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                    if assignment and assignment[-1] and assignment[0]:
                        local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                    declaration = self.parser.uninitialized(statement.tokens) if statement.kind == 'simple' else None
                    if declaration:
                        local[declaration.value] = declaration.value + '@' + str(declaration.start)

        def block(statements, following, bindings, break_to=None, continue_to=None, exit_to=None,
                  fallthrough_to=None):
            exit_target = exit_node if exit_to is None else exit_to
            statements = group_directives(statements)
            deferred_bodies, snapshots, local = [], [], dict(bindings)

            def is_defer(statement):
                return (statement.kind == 'unsupported' and statement.tokens
                        and statement.tokens[0].value == 'defer')

            def conditional_defer(directive):
                return any(is_defer(statement) or statement.kind == 'ifdirective' and conditional_defer(statement)
                           for arm in directive.extra for statement in arm)

            for statement in statements:
                before = dict(local)
                opaque_defer = any(statement.tokens and statement.tokens[0].start <= offset < statement.tokens[-1].end
                                   for offset in opaque)
                if is_defer(statement) and not opaque_defer:
                    op = next((i for i, t in enumerate(statement.tokens) if t.value == '{'), -1)
                    if op < 0:
                        raise ValueError('Swift malformed defer; analysis is incomplete')
                    body = self.parser.block(statement.tokens[op + 1:swift_close(statement.tokens, op)],
                                             function.owner, {})
                    deferred_bodies.append((body, before))
                assignment = self.parser.assignment(statement.tokens) if statement.kind == 'simple' else None
                if assignment and assignment[-1] and assignment[0]:
                    local[assignment[0]] = assignment[0] + '@' + str(assignment[1][0].start)
                    annotation = swift_parts(swift_parts(statement.tokens, {'='})[0], {':'})
                    if len(annotation) == 2:
                        binding_types[local[assignment[0]]] = swift_text(annotation[1])
                declaration = self.parser.uninitialized(statement.tokens) if statement.kind == 'simple' else None
                if declaration:
                    local[declaration.value] = declaration.value + '@' + str(declaration.start)
                    annotation = swift_parts(statement.tokens, {':'})
                    if len(annotation) == 2:
                        binding_types[local[declaration.value]] = swift_text(annotation[1])
                if statement.kind == 'guard':
                    local = optional_scope(statement.tokens, local)
                if statement.kind == 'ifdirective':
                    register_arm_declarations(statement, local)
                snapshots.append((dict(local), before, len(deferred_bodies)))
            orig_break, orig_continue, orig_exit, orig_fallthrough = break_to, continue_to, exit_target, fallthrough_to
            cleanup_chains = {}

            def defer_chain(target, count):
                if target is None or not count:
                    return target
                if (target, count - 1) in cleanup_chains:
                    return cleanup_chains[(target, count - 1)]
                entry = target
                # A newer registration runs before the older chain. Reuse
                # each prefix at a destination instead of expanding paths.
                for index in range(count):
                    key = (target, index)
                    if key not in cleanup_chains:
                        body, captured = deferred_bodies[index]
                        cleanup_chains[key] = block(body, entry, captured, orig_break, orig_continue,
                                                    orig_exit, orig_fallthrough)
                    entry = cleanup_chains[key]
                return entry

            following = defer_chain(following, len(deferred_bodies))
            for statement, (local, before, registered) in reversed(list(zip(statements, snapshots))):
                break_to = defer_chain(orig_break, registered)
                continue_to = defer_chain(orig_continue, registered)
                exit_target = defer_chain(orig_exit, registered)
                fallthrough_to = defer_chain(orig_fallthrough, registered)
                kind, tokens = statement.kind, statement.tokens
                if kind == 'definition':
                    continue
                limitation = next(((offset, reason) for offset, reason in opaque.items()
                                   if tokens and tokens[0].start <= offset < tokens[-1].end), None)
                if limitation is not None:
                    following = node('opaque', tokens, local, (following,), limitation, reads=before)
                    continue
                if is_defer(statement):
                    continue
                assignment = self.parser.assignment(tokens) if kind == 'simple' else None
                value = swift_ungroup(assignment[2] if assignment else tokens) if kind in {'simple', 'return'} else ()
                if value and value[0].value in {'switch', 'if'}:
                    prefix = ()
                    if assignment:
                        left = swift_parts(tokens, {'=', '+=', '-=', '*=', '/='})[0]
                        prefix = tuple(tokens[:len(left) + 1])
                    parsed = self.parser.block(value, function.owner, (*function.scope, function.key))
                    lowered = self.parser.result_body(parsed, prefix)
                    if lowered is None:
                        raise SwiftUnsupported('Swift branch expression needs result analysis; analysis is incomplete', tokens[0].start)
                    following = block(lowered, following, local, break_to, continue_to, exit_target,
                                      fallthrough_to)
                    continue
                if kind == 'ifdirective':
                    if conditional_defer(statement):
                        raise SwiftUnsupported('Swift conditional defer registration needs scope-exit analysis; analysis is incomplete',
                                               tokens[0].start)
                    arm_entries = [block(arm, following, before, break_to, continue_to, exit_target,
                                         fallthrough_to)
                                   for arm in statement.extra]
                    targets = tuple(arm_entries) if statement.body else (*arm_entries, following)
                    following = node('branch', targets=targets)
                    continue
                if kind == 'if':
                    yes_scope = optional_scope(tokens, local)
                    yes = block(statement.body, following, yes_scope, break_to, continue_to, exit_target,
                                fallthrough_to)
                    no = block(statement.alternate, following, local, break_to, continue_to, exit_target,
                               fallthrough_to)
                    following = condition(tokens, yes, no, yes_scope, local, exit_target)
                elif kind == 'guard':
                    if not terminates(statement.body, before):
                        raise ValueError('Swift guard else does not exit its enclosing scope; analysis is incomplete')
                    failure = block(statement.body, following, before, break_to, continue_to, exit_target,
                                    fallthrough_to)
                    following = condition(tokens, following, failure, local, before, exit_target)
                elif kind == 'while':
                    loop = node('branch')
                    inner = optional_scope(tokens, local)
                    body = block(statement.body, loop, inner, following, loop, exit_target, fallthrough_to)
                    edges[loop] = (condition(tokens, body, following, inner, local, exit_target),)
                    following = loop
                elif kind == 'for':
                    parts = swift_parts(tokens, {'in'})
                    if len(parts) != 2:
                        raise SwiftUnsupported('Swift iteration binding needs pattern analysis; analysis is incomplete', tokens[0].start)
                    # Parentheses here are tuple patterns, not expression
                    # grouping: retain them for recursive binding analysis.
                    pattern = tuple(t for t in parts[0] if t.value != '\n')
                    while pattern and pattern[0].value in {'try', 'await'}:
                        pattern = pattern[1:]
                    names = self.parser.iteration_names(pattern)
                    sequence = swift_parts(parts[1], {'where'})
                    if len(sequence) > 2 or not all(swift_ungroup(part) for part in sequence):
                        raise SwiftUnsupported('Swift iteration filter needs condition analysis; analysis is incomplete', tokens[0].start)
                    inner = dict(local)
                    for name in names:
                        inner[name.value] = name.value + '@' + str(name.start)
                    loop = node('branch')
                    body = block(statement.body, loop, inner, following, loop, exit_target, fallthrough_to)
                    if len(sequence) == 2:
                        body = condition(sequence[1], body, loop, inner, throw_to=exit_target)
                    bound = node('element', sequence[0], inner, (body,), tuple(name.value for name in names), reads=local)
                    edges[loop] = (bound, following)
                    following = loop
                elif kind in {'break', 'continue'}:
                    target = break_to if kind == 'break' else continue_to
                    if target is None or tokens:
                        raise SwiftUnsupported('Swift labeled/nonlocal loop exit needs control-flow analysis; analysis is incomplete',
                                               tokens[0].start if tokens else function.key)
                    following = node('branch', targets=(target,))
                elif kind == 'fallthrough':
                    if fallthrough_to is None or len(tokens) != 1:
                        raise ValueError('Swift fallthrough has no unbound successor case; analysis is incomplete')
                    following = node('branch', targets=(fallthrough_to,))
                elif kind == 'jump':
                    following = node('branch', targets=statement.extra)
                elif kind in {'return', 'throw'}:
                    following = node(kind, tokens, local, (exit_target,))
                elif kind == 'simple' and process_exit(tokens, before):
                    following = node('eval', tokens, local, ())
                elif kind == 'repeat':
                    loop = node('branch')
                    body = block(statement.body, loop, local, following, loop, exit_target, fallthrough_to)
                    edges[loop] = (condition(statement.extra[0], body, following, local,
                                             throw_to=exit_target),)
                    following = body
                elif kind == 'switch':
                    subject = statement.extra[0]
                    slot = '@switch:' + str(tokens[0].start)
                    next_match, next_body, next_names = following, None, ()
                    for arm in reversed(statement.body):
                        patterns, declared = [], {}
                        if arm.kind != 'default':
                            for part in swift_parts(arm.tokens, {','}):
                                where = swift_parts(part, {'where'})
                                if len(where) > 2 or not all(swift_ungroup(value) for value in where):
                                    raise SwiftUnsupported('Swift switch where clause needs condition analysis; analysis is incomplete', part[0].start)
                                names, expressions, total, _structural = switch_pattern(where[0])
                                current = {name.value: name for name, _ in names}
                                if patterns and set(current) != set(declared):
                                    raise ValueError('Swift switch alternatives bind different names; analysis is incomplete')
                                declared = declared or current
                                patterns.append((names, expressions, total, where[1] if len(where) == 2 else ()))
                        inner = {**local, **{name: name + '@' + str(token.start)
                                            for name, token in declared.items()}}
                        body_entry = block(arm.body, following, inner, following, continue_to, exit_target,
                                           next_body if not next_names else None)
                        if arm.kind == 'default':
                            next_match = body_entry
                        else:
                            for names, expressions, total, where in reversed(patterns):
                                matched = (condition(where, body_entry, next_match, inner,
                                                     throw_to=exit_target) if where else body_entry)
                                if names:
                                    matched = node('switch-bind', subject, inner, (matched,),
                                                   (slot, tuple((name.value, projected) for name, projected in names)))
                                matched = node('branch', targets=(matched,) if total else (matched, next_match))
                                for expression, projected in reversed(expressions):
                                    # Failed earlier components can skip later
                                    # expression patterns, including their
                                    # mutations. Preserve both paths.
                                    targets = (matched, next_match) + ((exit_target,) if throwing(expression) else ())
                                    matched = node('switch-expression', expression, local, targets,
                                                   (slot, () if projected else enum_subject(subject, local)))
                                next_match = matched
                        next_body, next_names = body_entry, tuple(declared)
                    targets = (next_match,) + ((exit_target,) if throwing(subject) else ())
                    following = node('switch-subject', subject, local, targets, slot)
                elif kind == 'unsupported' and tokens and tokens[0].value == 'do':
                    opening = next((i for i, t in enumerate(tokens) if t.value == '{'), -1)
                    if opening < 1:
                        raise ValueError('Swift malformed do block; analysis is incomplete')
                    do_close = swift_close(tokens, opening)
                    catch_entries = []
                    rest = do_close + 1
                    while rest < len(tokens) and tokens[rest].value == '\n':
                        rest += 1
                    while rest < len(tokens) and tokens[rest].value == 'catch':
                        brace = next((k for k in range(rest + 1, len(tokens)) if tokens[k].value == '{'), -1)
                        if brace < 0:
                            raise ValueError('Swift malformed catch; analysis is incomplete')
                        signature = swift_ungroup(tokens[rest + 1:brace])
                        names = pattern_names(signature)
                        if not names:
                            names = (SwiftToken('error', tokens[rest].start, tokens[rest].end),)
                        catch_scope = dict(local)
                        for name in names:
                            catch_scope[name.value] = name.value + '@' + str(name.start)
                        hclose = swift_close(tokens, brace)
                        handler_stmts = self.parser.block(tokens[brace + 1:hclose], function.owner, ())
                        entry = block(handler_stmts, following, catch_scope, break_to, continue_to, exit_target,
                                      fallthrough_to)
                        where = swift_parts(signature, {'where'})
                        if len(where) == 2:
                            entry = node('eval', where[1], catch_scope, (entry,))
                        catch_entries.append(node('catch', (), catch_scope, (entry,), tuple(name.value for name in names)))
                        rest = hclose + 1
                        while rest < len(tokens) and tokens[rest].value == '\n':
                            rest += 1
                    if rest != len(tokens):
                        raise ValueError('Swift do trailing tokens; analysis is incomplete')
                    do_stmts = self.parser.block(tokens[opening + 1:do_close], function.owner, ())
                    before_key = len(actions)
                    do_entry = block(do_stmts, following, local, break_to, continue_to, exit_target, fallthrough_to)
                    for created in range(before_key, len(actions)):
                        edges[created] = edges[created] + tuple(catch_entries)
                    following = do_entry
                else:
                    throw_targets = (exit_target,) if any(
                        t.kind == 'code' and t.value == 'try'
                        and (idx + 1 >= len(tokens) or tokens[idx + 1].value not in {'?', '!'})
                        for idx, t in enumerate(tokens)) else ()
                    following = node(kind, tokens, local, (following,) + throw_targets, reads=before)
            return following

        return block(function.body, exit_node, scope), actions, edges

    def transfer(self, action, state):
        if not state.get('@reachable'):
            return state
        kind, tokens, bindings, extra, reads = action
        if kind == 'branch':
            return state
        if kind == 'opaque':
            offset, reason = extra
            unknown = self.limitation(reason, offset, state, bindings)
            # The skipped statement may return, throw or mutate an inout
            # argument. Its summary cannot certify any of those effects clean.
            self.returned = join(self.returned, unknown)
            self.thrown = join(self.thrown, unknown)
            for index, (_, _, declaration, _) in enumerate(self.function.parameters):
                if declaration.startswith('inout'):
                    self.mutations[index] = join(self.mutations.get(index, CLEAN), unknown)
                    self.assigned.add(index)
            return state
        if kind == 'exit':
            self.returned = join(self.returned, state.get('@result', CLEAN))
            if self.function.name == 'init':
                self.returned = join(self.returned, state.get('self', CLEAN))
            elif self.function.owner and not self.function.static:
                self.mutations['self'] = join(self.mutations.get('self', CLEAN), state.get('self', CLEAN))
            for index, (name, _, declaration, _) in enumerate(self.function.parameters):
                if declaration.startswith('inout') or self.reference_ids(state.get('parameter:' + name, CLEAN)):
                    self.mutations[index] = join(self.mutations.get(index, CLEAN), state.get('parameter:' + name, CLEAN))
            return state
        if kind == 'proof':
            return self.proof(tokens, extra, state, bindings)
        if kind == 'switch-subject':
            # A case or where clause may mutate the original variable. Swift
            # matches the value evaluated on entry, not a second read at every
            # arm; keep the same dependency snapshot for all case bindings.
            state[extra] = self.expression(tokens, state, reads)
            return state
        if kind == 'switch-bind':
            slot, names = extra
            value = state.get(slot, CLEAN)
            for name, projected in names:
                selected = swift_retag(value, remove=SWIFT_VALUE_TAGS) if projected else value
                state[bindings[name]] = advance(selected, self.step(tokens[0].start, 'assign', name))
            return state
        if kind == 'switch-expression':
            slot, subject_type = extra
            pattern = swift_text(tokens)
            if (subject_type and re.fullmatch(r'(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*|\.[A-Za-z_]\w*', pattern)
                    and pattern.rsplit('.', 1)[-1] in self.parser.enum_cases[subject_type]):
                qualifier = pattern.rsplit('.', 1)[0]
                owner = next(((*self.function.owner[:index], *qualifier.split('.'))
                              for index in range(len(self.function.owner), -1, -1)
                              if (*self.function.owner[:index], *qualifier.split('.'))
                              in self.parser.type_declarations), ()) if qualifier else subject_type
                root = qualifier.split('.')[0]
                if (subject_type == owner and (not qualifier or
                        root not in reads and root not in self.local_globals
                        and not any(part in self.parser.aliased_types for part in qualifier.split('.')))):
                    return state
            self.expression(tokens, state, reads)
            subject = state.get(slot, CLEAN)
            custom_match = any(function.name in {'==', '~='} for function in self.parser.functions.values())
            nonprimitive = any(trace.kind in {'shape', 'field', 'closure', 'function', 'native-callable'}
                               for trace in subject)
            if self.parser.literal_pattern(tokens) and not custom_match and not nonprimitive:
                return state
            self.limitation('Swift expression pattern needs matching-operator analysis',
                            tokens[0].start, state, bindings)
            return state
        if kind == 'unsupported':
            raise SwiftUnsupported('Unsupported Swift control flow or closure; analysis is incomplete',
                                   tokens[0].start if tokens else self.function.key)
        if kind == 'catch':
            value = join(state.get('@exception', CLEAN),
                         *(self.forget(fact) for name, fact in state.items() if not name.startswith('@')))
            for name in extra:
                state[bindings[name]] = value
            return state
        if kind == 'element':
            value = self.expression(tokens, state, reads)
            if any(swift_has_shape(value, shape) for shape in {'request-collection', 'request-content'}):
                value = join(value, self.source(tokens[0].start, 'request iteration'))
            requests = frozenset(trace for trace in value if trace.kind == 'shape'
                and trace.key[0] in {'request', 'request-collection', 'request-content'})
            value = join(self.forget(value), requests)
            for name in extra:
                state[bindings[name]] = advance(value, self.step(tokens[0].start, 'assign', name))
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
            raise SwiftUnsupported('Unsupported Swift optional binding; analysis is incomplete', tokens[0].start)
        if assignment:
            name, lhs, rhs, operator, _ = assignment
            value = self.expression(rhs, state, reads)
            if not name:
                header = swift_text(lhs)
                header_assignment = re.fullmatch(r'(?:[A-Za-z_]\w*\.)?headers\[([\'\"])([^\'\"]+)\1\]', header, re.IGNORECASE)
                if header_assignment:
                    if self.policy == 'redirect' and header_assignment.group(2).lower() == 'location':
                        self.record(lhs[0].start, value)
                    elif self.policy == 'header' and header_assignment.group(2).lower() != 'location':
                        self.record(lhs[0].start, value)
                    return state
                member = re.fullmatch(r'([A-Za-z_]\w*)\.[A-Za-z_]\w*', header)
                if member:
                    binding = bindings.get(member.group(1), member.group(1))
                    if member.group(1) in self.parser.types and member.group(1) not in bindings:
                        self.limitation('Swift static stored property mutation needs shared-state analysis',
                                        lhs[0].start, state, bindings)
                        return state
                    previous = state.get(binding, CLEAN)
                    field_path = ()
                    if (member.group(1) not in bindings
                            and member.group(1) in self.parser.stored_fields.get(self.function.owner, {})):
                        binding = 'self'
                        field_path = (member.group(1),)
                        previous = self.member(member.group(1), state.get('self', CLEAN), lhs[0], 'self', state)
                    field_name = header.rsplit('.', 1)[-1]
                    owners = {tuple(trace.key[0].split(':', 1)[1].split('.')) for trace in swift_top(previous)
                              if trace.kind == 'shape' and trace.key[0].startswith(('instance:', 'dynamic-instance:'))}
                    for owner in sorted(owners):
                        if (owner, field_name) in self.parser.opaque_fields:
                            self.limitation(self.parser.opaque_fields[(owner, field_name)],
                                            lhs[0].start, state, bindings)
                    if self.write_field(previous, field_name, value, state, binding, lhs[0].start, operator, field_path):
                        return state
                    if field_path:
                        self.limitation('Swift nested stored property write needs binding analysis',
                                        lhs[0].start, state, bindings)
                        return state
                    self.escape_closures(value, state)
                    if owners and all(re.fullmatch(r'(?:Vapor\.)?Request\??',
                            self.parser.fields.get(owner, {}).get(field_name, '')) for owner in owners):
                        # The declared Request field is modeled when read;
                        # its presence does not taint every sibling property.
                        value = self.forget(value)
                    if self.policy == 'outbound' and self.http_request(previous):
                        property_name = header.rsplit('.', 1)[-1]
                        if property_name == 'url' and operator == '=':
                            state[binding] = self.request_destination(value, lhs[0].start)
                            self.invalidate_properties(binding, state)
                            return state
                        if property_name in {'httpBody', 'httpBodyStream', 'httpMethod', 'allHTTPHeaderFields',
                                             'cachePolicy', 'timeoutInterval'}:
                            return state
                    self.mutate(member.group(1), value, state, bindings)
                    return state
                self.escape_closures(value, state)
                if swift_request_dependency(value):
                    self.limitation('Swift request-derived field/element write needs heap analysis', lhs[0].start, state, bindings)
                return state
            binding = bindings.get(name, name)
            if name not in bindings and name in self.parser.fields.get(self.function.owner, {}):
                # Unqualified stored-property writes inside an initializer or
                # method have the same receiver effects as self.property = ... .
                # A local declaration/parameter of that name remains lexical.
                if (self.function.owner, name) in self.parser.opaque_fields:
                    self.limitation(self.parser.opaque_fields[(self.function.owner, name)],
                                    lhs[0].start, state, bindings)
                if self.write_field(state.get('self', CLEAN), name, value, state, 'self', lhs[0].start, operator):
                    return state
                self.escape_closures(value, state)
                if re.fullmatch(r'(?:Vapor\.)?Request\??', self.parser.fields[self.function.owner][name]):
                    value = self.forget(value)
                self.mutate('self', value, state, bindings)
                return state
            if operator != '=':
                value = self.forget(join(state.get(reads.get(name, name), CLEAN), value))
            self.invalidate_properties(binding, state)
            state[binding] = advance(value, self.step(lhs[0].start, 'assign', name))
            self.note_write(binding, state[binding])
            if name in self.local_globals and (binding == name or (
                    self.function.key == -1 and binding == self.global_bindings.get(name))):
                if swift_request_dependency(value):
                    self.globals[name] = join(self.globals.get(name, CLEAN), value,
                        self.limitation('Swift request-derived global write needs shared-state analysis', lhs[0].start))
                elif self.reference_ids(value) or any(trace.kind == 'field' for trace in value):
                    # Constructor summaries begin at bottom. Publish their
                    # settled clean layouts too, including nested identities
                    # needed to recognize a later global-reference mutation.
                    self.globals[name] = join(self.globals.get(name, CLEAN), value)
            return state
        value = self.expression(tokens, state, bindings)
        if kind == 'return':
            # A stored-property initializer is represented as a synthetic
            # return so member() can reuse its summary. Merely creating that
            # property does not invoke its callback with an unknown argument.
            # Actual calls and escapes of the selected property still analyze
            # the callback, including its captured values and sink effects.
            if not self.function.name.startswith('<field:'):
                self.escape_closures(value, state)
            state['@result'] = advance(value, self.step(tokens[0].start if tokens else self.function.key, 'return', self.function.name))
        elif kind == 'throw':
            self.thrown = join(self.thrown, value)
            state['@exception'] = join(state.get('@exception', CLEAN), value)
        return state

    def observe(self, action, state):
        """Retain future values for escaping callbacks in this lexical context."""
        previous = self.capture_states.get(self.active_context, {})
        before = {key: value for key, value in state.items() if not key.startswith('@')}
        try:
            output = self.transfer(action, state)
        except SwiftUnsupported as error:
            if not self.recover:
                raise
            kind, tokens, bindings, _extra, _reads = action
            offset = error.offset if error.offset is not None else (tokens[0].start if tokens else self.function.key)
            unknown = self.limitation(str(error).removesuffix('; analysis is incomplete'), offset, state, bindings)
            if kind == 'return':
                state['@result'] = join(state.get('@result', CLEAN), unknown)
            output = state
        after = {key: value for key, value in output.items() if not key.startswith('@')}
        if self.capture_frames and action[0] != 'proof':
            _context, slots, _writes = self.capture_frames[-1]
            changed = {binding for binding in slots if before.get(binding, CLEAN) != after.get(binding, CLEAN)}
            for binding in changed:
                self.note_write(binding, after.get(binding, CLEAN))
        if self.active_context in self.capture_origins:
            updated = join_states(previous, before, after)
            if updated != previous:
                self.capture_states[self.active_context] = updated
                self.capture_revision += 1
                for reader in self.capture_readers.get(self.active_context, {}):
                    self.enqueue(reader)
        return output

    def analyze(self):
        context_reads = {}
        # Global initializers are evaluated again in the top-level context.
        # Their constructor-time pending summaries are not settled obligations.
        self.pending_calls.pop(None, None)
        while True:
            while self.pending:
                key = self.pending.popleft()
                self.queued.remove(key)
                function = self.contexts[key]
                globals_before = dict(self.globals)
                self.budget.spend()
                self.function, self.effects, self.mutations, self.returned, self.thrown = function, {}, {}, CLEAN, CLEAN
                self.captured_writes = {}
                self.summary_context, self.assigned = key, set()
                self.active_context = key
                self.pending_calls[key] = {}
                self.url_reads = {}
                arguments, receiver = self.context_inputs[key]
                if function.key not in self.graphs:
                    self.graphs[function.key] = self.graph(function)
                entry, actions, edges = self.graphs[function.key]
                initial = dict(self.globals)
                initial['@reachable'] = swift_constant('true', 'code')
                parameter_types = tuple(declaration.rstrip('?!') if declaration.rstrip('?!') in self.parser.types
                                        else declaration.removeprefix('inout').rstrip('?!')
                                        for _, _, declaration, _ in function.parameters)
                for index, (name, _, declaration, _) in enumerate(function.parameters):
                    value = arguments[index]
                    object_type = parameter_types[index]
                    if re.fullmatch(r'(?:Vapor\.)?Request\??', declaration):
                        value = join(value, swift_shape('request', function.key))
                    elif re.fullmatch(r'(?:inout)?(?:Swift\.)?String\??', declaration):
                        value = swift_retag(value, add=frozenset({'swift-string'}))
                    elif (self.policy == 'outbound' and re.fullmatch(r'(?:Foundation\.)?URLSession\??', declaration)
                          and self.builtin(declaration.rstrip('?'))):
                        value = join(value, swift_shape('http-client:foundation', function.key))
                    elif object_type in self.parser.types:
                        kind = 'instance:' if object_type in self.parser.final_types else 'dynamic-instance:'
                        if not any(swift_has_shape(value, prefix + object_type)
                                   for prefix in ('instance:', 'dynamic-instance:')):
                            if key[2] or any(trace.kind == 'opaque-value' for trace in swift_top(value)):
                                # True entry values have unknown fields. A
                                # pending known callee's bottom must not gain
                                # this permanent alternative before it resolves.
                                value = join(value, frozenset({Trace('unknown-layout', (object_type,))}))
                            value = join(value, swift_shape(kind + object_type, function.key))
                        if object_type not in self.parser.value_types and not self.reference_ids(value):
                            value = join(value, swift_shape('reference:' + object_type))
                    initial['parameter:' + name] = value
                if function.owner:
                    owner = '.'.join(function.owner)
                    kind = 'instance:' if owner in self.parser.final_types else 'dynamic-instance:'
                    if not any(swift_has_shape(receiver, prefix + owner)
                               for prefix in ('instance:', 'dynamic-instance:')):
                        if (function.name != 'init' and not function.static and (key[2]
                                or any(trace.kind == 'opaque-value' for trace in swift_top(receiver)))):
                            receiver = join(receiver, frozenset({Trace('unknown-layout', (owner,))}))
                        receiver = join(receiver, swift_shape(kind + owner, function.key))
                    initial['self'] = join(receiver, self.opaque_owners.get(function.owner, CLEAN))
                    if function.name == 'init':
                        initial['self'] = self.initialize_fields(function, initial['self'])
                    if (function.name != 'init' and owner not in self.parser.value_types
                            and not self.reference_ids(initial['self'])):
                        initial['self'] = join(initial['self'], swift_shape('reference:' + owner))
                if key[2] and any(object_type in self.parser.types
                        and object_type not in self.parser.final_types
                        and not self.reference_ids(arguments[index])
                        for index, object_type in enumerate(parameter_types)):
                    self.limitation('Swift incoming polymorphic references need subtype alias analysis',
                                    function.key, initial)
                solve(entry, initial, edges, lambda node, state: self.observe(actions[node], state), self.budget)
                context_reads[key] = self.url_reads
                updated = self.summaries[key].merged(SwiftSummary(
                    self.returned, self.effects, self.mutations, self.thrown,
                    self.captured_writes, frozenset(self.assigned)))
                if updated != self.summaries[key]:
                    self.summaries[key] = updated
                    for reader in self.summary_readers.get(key, {}):
                        self.enqueue(reader)
                if self.globals != globals_before:
                    for reader in self.contexts:
                        self.enqueue(reader)
            unresolved = {call: details for calls in self.pending_calls.values()
                          for call, details in calls.items() if call not in self.opaque_calls}
            if not unresolved:
                break
            # Only a drained summary/capture worklist establishes that a
            # callable is unsupported rather than waiting for a selected body.
            # Its unknown effects then invalidate exactly the owning summaries.
            self.opaque_calls.update(unresolved)
            for call in sorted(unresolved, key=lambda item: (item[2], item[3])):
                self.function, reason = unresolved[call]
                self.limitation(reason, call[2])
                self.enqueue(call[0])
        # Keep the latest reads from every reached context; a callee may have
        # completed after its caller first attempted a native file-URL proof.
        self.url_reads = {}
        for reads in context_reads.values():
            for offset, value in reads.items():
                self.url_reads[offset] = join(self.url_reads.get(offset, CLEAN), value)
        effects = {}
        for summary in self.summaries.values():
            for offset, value in summary.effects.items():
                sink = self.step(offset, 'sink', self.sink_label)
                effects[offset] = join(effects.get(offset, CLEAN), advance(swift_tainted(value), sink))
        return effects


def file_url_read_offsets(path, text):
    """Offsets of proven native file-URL readers, using strict flow summaries.

    An opaque or incomplete summary cannot authorize a file-only exemption.
    """
    parser = SwiftParser(text)
    engine = SwiftEngine(path, text, 'path', parser)
    engine.analyze()
    return frozenset(offset for offset, value in engine.url_reads.items()
        if value and all('file-url' in trace.tags and 'path-string' not in trace.tags for trace in value))


def flow_findings(path, text, policy='path', *, recover=False):
    """Run scoped flow, optionally reporting local conservative limitations.

    Strict proof consumers must not authorize an exemption from an opaque
    summary. Ordinary scanner adapters opt into local warnings; lexical
    failures, malformed syntax and work limits still fail the scan.
    """
    tokens = swift_validated_tokens(text)
    suppressed, _drops, _warnings = swift_taint_source_drops(path, text, tokens)
    obligation_fn = swift_outbound_obligation if policy == 'outbound' else swift_flow_obligation
    if not swift_request_source_tokens(tokens, suppressed) or not obligation_fn(tokens):
        return []
    parser = SwiftParser(text, tokens, suppressed, obligation_fn, recover=recover)
    engine = SwiftEngine(path, text, policy, parser, recover=recover)
    rule, message = {
        'path': ('swift.taint.request_path_traversal', 'Request-derived path reaches file read/write/serve sink'),
        'redirect': ('swift.taint.request_open_redirect', 'Unvalidated redirect from request data'),
        'header': ('swift.taint.header-injection', 'Request-controlled value reaches HTTP response header'),
        'outbound': ('swift.taint.outbound-url', 'Request-derived URL reaches outbound HTTP client'),
    }[policy]
    suppression = SourceSuppressions('swift')
    suppression.index(path, text)
    findings, seen = [], set()
    for offset, value in sorted(engine.analyze().items()):
        traces = sorted(value, key=lambda trace: (len(trace.evidence), trace.evidence, trace.key))
        if not traces:
            continue
        sink = engine.step(offset, 'sink', engine.sink_label)
        if sink.line in seen or suppression.is_suppressed(path, sink.line, rule):
            continue
        seen.add(sink.line)
        findings.append(dict(rule=rule, path=str(path.resolve()), line=sink.line, col=sink.column,
            lang='swift', layer='taint', severity='critical', message=message,
            extras={'taint_path': [step.record() for step in traces[0].evidence],
                    'source_count': len({trace.key for trace in traces})}))
    findings.extend(engine.diagnostics[key] for key in sorted(engine.diagnostics))
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
        yield from flow_findings(path, text, recover=True)


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
