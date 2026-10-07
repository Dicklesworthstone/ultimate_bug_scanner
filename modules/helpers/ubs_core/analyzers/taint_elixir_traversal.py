"""Scoped Elixir request flow for file paths and redirect policies (mj1j.10).

Selected same-module clauses, immutable rebinding, tuples, pipelines and
branch expressions share finite taint facts and bounded worklists. Validation
belongs to the exact value checked, with separate URL and filesystem proofs.
Unsupported syntax, dynamic dispatch, expansion and exhausted budgets raise
an error so callers can report an incomplete scan.
"""
from __future__ import annotations

import posixpath
import sys
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Step, Trace, advance, join


class ElixirSyntaxError(ValueError):
    """Selected Elixir syntax could not be analyzed completely."""


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    col: int
    offset: int
    interpolations: tuple = ()


def tokenize(text: str, budget: Budget, line: int = 1, col: int = 1,
             offset: int = 0) -> tuple[Token, ...]:
    """Tokenize code, retaining interpolated expressions but never lexical decoys."""
    tokens = []
    index = 0
    operators = ('===', '!==', '<<<', '>>>', '<<', '>>', '|>', '->', '<-', '=>',
                 '==', '!=', '<=', '>=', '&&', '||', '<>', '++', '--', '\\\\', '..')
    while index < len(text):
        budget.spend()
        char = text[index]
        start, start_line, start_col = index, line, col
        if char in ' \t\r':
            index += 1
            col += 1
            continue
        if char == '\n':
            tokens.append(Token('nl', '\n', line, col, offset + index))
            index, line, col = index + 1, line + 1, 1
            continue
        if char == '#':
            while index < len(text) and text[index] != '\n':
                index += 1
                col += 1
            continue
        sigil = char == '~' and index + 2 < len(text) and text[index + 1].isalpha()
        if char in '\"\'' or sigil:
            name = text[index + 1] if sigil else ''
            if sigil:
                index += 2
                col += 2
            opener = text[index]
            if opener not in '\"\'/|([{<':
                raise ElixirSyntaxError(f'Unsupported Elixir sigil at line {line}; analysis is incomplete')
            closer = {'(': ')', '[': ']', '{': '}', '<': '>'}.get(opener, opener)
            triple = opener in '\"\'' and text.startswith(opener * 3, index)
            delimiter = closer * (3 if triple else 1)
            width = len(delimiter)
            index += width
            col += width
            value, embedded, nesting = [], [], 1
            interpolate = not sigil or name.islower()
            while index < len(text):
                budget.spend()
                if text.startswith(delimiter, index):
                    nesting -= 1
                    if not nesting:
                        index += width
                        col += width
                        break
                if opener != closer and text[index] == opener:
                    nesting += 1
                if interpolate and text.startswith('#{', index):
                    begin = index + 2
                    inner_line, inner_col = line, col + 2
                    cursor, depth, quote, escaped = begin, 1, '', False
                    while cursor < len(text) and depth:
                        current = text[cursor]
                        if quote:
                            if escaped:
                                escaped = False
                            elif current == '\\':
                                escaped = True
                            elif current == quote:
                                quote = ''
                        elif current in '\"\'':
                            quote = current
                        elif current == '{':
                            depth += 1
                        elif current == '}':
                            depth -= 1
                        cursor += 1
                    if depth:
                        raise ElixirSyntaxError(f'Unclosed Elixir interpolation at line {line}')
                    inner = text[begin:cursor - 1]
                    embedded.append(tokenize(inner, budget, inner_line, inner_col, offset + begin))
                    consumed = text[index:cursor]
                    breaks = consumed.count('\n')
                    line += breaks
                    col = len(consumed.rsplit('\n', 1)[-1]) + 1 if breaks else col + len(consumed)
                    index = cursor
                    value.append('{}')
                    continue
                current = text[index]
                if current == '\\' and index + 1 < len(text):
                    following = text[index + 1]
                    if sigil and name.isupper() and following != closer:
                        value.append('\\' + following)
                    else:
                        value.append({'n': '\n', 'r': '\r', 't': '\t', '0': '\0'}.get(following, following))
                    index += 2
                    col += 2
                    continue
                value.append(current)
                index += 1
                if current == '\n':
                    line, col = line + 1, 1
                else:
                    col += 1
            else:
                raise ElixirSyntaxError(f'Unclosed Elixir string or sigil at line {start_line}')
            if sigil:
                while index < len(text) and text[index].isalpha():
                    index += 1
                    col += 1
            tokens.append(Token('string', ''.join(value), start_line, start_col,
                                offset + start, tuple(embedded)))
            continue
        if char == ':' and index + 1 < len(text) and (text[index + 1].isalpha() or text[index + 1] == '_'):
            index += 2
            while index < len(text) and (text[index].isalnum() or text[index] in '_?!'):
                index += 1
            tokens.append(Token('atom', text[start + 1:index], line, col, offset + start))
            col += index - start
            continue
        if char.isalpha() or char == '_':
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in '_?!'):
                index += 1
            tokens.append(Token('id', text[start:index], line, col, offset + start))
            col += index - start
            continue
        if char.isdigit():
            index += 1
            while index < len(text) and (text[index].isdigit() or text[index] == '_'):
                index += 1
            tokens.append(Token('number', text[start:index], line, col, offset + start))
            col += index - start
            continue
        operator = next((op for op in operators if text.startswith(op, index)), char)
        tokens.append(Token('symbol', operator, line, col, offset + index))
        index += len(operator)
        col += len(operator)
    tokens.append(Token('eof', '', line, col, offset + index))
    return tuple(tokens)


@dataclass(frozen=True)
class Expr:
    kind: str
    token: Token
    value: str = ''
    args: tuple = ()


class Parser:
    """Selected Elixir expressions with real do/end and clause boundaries."""

    PRECEDENCE = {'=': 1, '<-': 1, '\\\\': 1, 'when': 2, 'or': 3, '||': 3,
                  'and': 4, '&&': 4, '==': 5, '===': 5, '!=': 5, '!==': 5,
                  'in': 5, '<': 5, '>': 5, '<=': 5, '>=': 5, '|>': 6,
                  '<>': 7, '++': 7, '--': 7, '+': 8, '-': 8, '*': 9, '/': 9}
    TERMINATORS = frozenset({'end', 'else', 'after', 'rescue', 'catch', 'do'})

    def __init__(self, tokens: tuple[Token, ...], budget: Budget):
        self.tokens, self.budget, self.index, self.depth = tokens, budget, 0, 0

    @property
    def current(self):
        return self.tokens[self.index]

    def take(self):
        token = self.current
        self.index += 1
        self.budget.spend()
        return token

    def accept(self, text):
        if self.current.text == text:
            return self.take()
        return None

    def require(self, text):
        token = self.accept(text)
        if token is None:
            raise ElixirSyntaxError(f'Expected {text!r} at Elixir line {self.current.line}; analysis is incomplete')
        return token

    def newlines(self):
        while self.current.kind == 'nl' or self.current.text == ';':
            self.take()

    def block(self, stops=frozenset()):
        self.depth += 1
        if self.depth > 80:
            raise AnalysisLimit('Elixir syntax nesting limit exceeded; analysis is incomplete')
        expressions = []
        self.newlines()
        while self.current.kind != 'eof' and self.current.text not in stops:
            expressions.append(self.expression())
            if self.current.kind not in {'nl', 'eof'} and self.current.text not in stops | {';'}:
                raise ElixirSyntaxError(f'Unexpected Elixir token {self.current.text!r} at line {self.current.line}')
            self.newlines()
        self.depth -= 1
        return Expr('block', expressions[0].token if expressions else self.current, args=tuple(expressions))

    def arguments(self, closer):
        args = []
        self.newlines()
        while self.current.text != closer:
            if self.current.kind == 'eof':
                self.require(closer)
            args.append(self.argument())
            self.newlines()
            if not self.accept(','):
                break
            self.newlines()
        self.require(closer)
        return tuple(args)

    def argument(self):
        if self.current.kind == 'id' and self.tokens[self.index + 1].text == ':':
            key = self.take()
            self.take()
            self.newlines()
            return Expr('pair', key, key.text, (self.expression(),))
        expr = self.expression()
        if self.accept('=>'):
            expr = Expr('map_pair', expr.token, args=(expr, self.expression()))
        return expr

    def function(self, token):
        name = self.take()
        if name.kind != 'id':
            raise ElixirSyntaxError(f'Unsupported dynamic Elixir function at line {name.line}')
        parameters = self.arguments(')') if self.accept('(') else ()
        if not parameters and self.current.text not in {'do', ',', 'when'}:
            params = [self.expression(3, bare=False)]
            while self.accept(',') and self.current.text != 'do':
                params.append(self.expression(3, bare=False))
            parameters = tuple(params)
        guard = Expr('literal', name, 'true')
        if self.accept('when'):
            guard = self.expression()
        self.accept(',')
        self.require('do')
        if self.accept(':'):
            body = Expr('block', name, args=(self.expression(),))
        else:
            self.newlines()
            body = self.block(frozenset({'end'}))
            self.require('end')
        return Expr('function', token, token.text, (name.text, parameters, guard, body))

    def conditional(self, token):
        condition = self.expression()
        self.accept(',')
        self.require('do')
        if self.accept(':'):
            positive = Expr('block', token, args=(self.expression(),))
            negative = Expr('block', token)
            if self.accept(','):
                self.require('else')
                self.require(':')
                negative = Expr('block', token, args=(self.expression(),))
        else:
            positive = self.block(frozenset({'else', 'end'}))
            negative = self.block(frozenset({'end'})) if self.accept('else') else Expr('block', token)
            self.require('end')
        return Expr('if', token, token.text, (condition, positive, negative))

    def clauses(self):
        clauses = []
        self.newlines()
        while self.current.text != 'end':
            if self.current.kind == 'eof':
                self.require('end')
            pattern = self.expression()
            self.require('->')
            self.newlines()
            body = []
            while self.current.text != 'end' and self.current.kind != 'eof':
                checkpoint = self.index
                expression = self.expression()
                if self.current.text == '->':
                    self.index = checkpoint
                    break
                body.append(expression)
                if self.current.text in {'end'}:
                    break
                if self.current.kind != 'nl' and self.current.text != ';':
                    raise ElixirSyntaxError(f'Invalid Elixir clause at line {self.current.line}')
                self.newlines()
            clauses.append((pattern, Expr('block', pattern.token, args=tuple(body))))
        self.require('end')
        return tuple(clauses)

    def expression(self, minimum=0, bare=True):
        self.depth += 1
        if self.depth > 120:
            raise AnalysisLimit('Elixir expression nesting limit exceeded; analysis is incomplete')
        self.newlines()
        token = self.take()
        if token.kind in {'string', 'atom', 'number'}:
            interpolations = []
            for embedded in token.interpolations:
                parser = Parser(embedded, self.budget)
                interpolations.append(parser.block())
            left = Expr(token.kind, token, token.text, tuple(interpolations))
        elif token.text in {'true', 'false', 'nil'}:
            left = Expr('literal', token, token.text)
        elif token.text in {'def', 'defp'}:
            left = self.function(token)
        elif token.text == 'defmodule':
            name = self.expression(10, bare=False)
            self.require('do')
            body = self.block(frozenset({'end'}))
            self.require('end')
            left = Expr('module', token, args=(name, body))
        elif token.text in {'if', 'unless'}:
            left = self.conditional(token)
        elif token.text == 'case':
            subject = self.expression()
            self.require('do')
            left = Expr('case', token, args=(subject, self.clauses()))
        elif token.text == 'cond':
            self.require('do')
            left = Expr('cond', token, args=self.clauses())
        elif token.text == 'with':
            generators = [self.expression()]
            while self.accept(','):
                self.newlines()
                if self.current.text == 'do':
                    break
                generators.append(self.expression())
            self.require('do')
            body = self.block(frozenset({'else', 'end'}))
            if self.accept('else'):
                clauses = self.clauses()
            else:
                self.require('end')
                clauses = ()
            left = Expr('with', token, args=(tuple(generators), body, clauses))
        elif token.text in {'defmacro', 'defmacrop', 'quote', 'unquote', 'for', 'receive', 'try', 'fn'}:
            raise ElixirSyntaxError(f'Elixir {token.text} needs additional flow semantics at line {token.line}; analysis is incomplete')
        elif token.text == '(':
            left = self.expression()
            self.newlines()
            self.require(')')
        elif token.text in {'{', '['}:
            left = Expr('tuple' if token.text == '{' else 'list', token,
                        args=self.arguments('}' if token.text == '{' else ']'))
        elif token.text == '%':
            struct = ''
            if self.current.text != '{':
                name = self.expression(10, bare=False)
                struct = self.name(name)
            self.require('{')
            left = Expr('map', token, struct, self.arguments('}'))
        elif token.text in {'not', '!', '^', '+', '-'}:
            left = Expr('unary', token, token.text, (self.expression(10),))
        elif token.text == '@':
            name = self.take()
            left = Expr('attribute', token, name.text)
            if name.text in {'doc', 'moduledoc', 'spec', 'type', 'typep', 'opaque', 'callback', 'macrocallback', 'impl', 'behaviour', 'derive', 'compile'}:
                while self.current.kind not in {'nl', 'eof'}:
                    self.take()
                left = Expr('noop', token)
            elif self.current.kind not in {'nl', 'eof'} and self.current.text not in self.PRECEDENCE and self.current.text not in {',', ')', ']', '}', 'do'}:
                left = Expr('set_attribute', token, name.text, (self.expression(),))
        elif token.kind == 'id' and token.text not in self.TERMINATORS:
            left = Expr('name', token, token.text)
        else:
            raise ElixirSyntaxError(f'Unsupported Elixir token {token.text!r} at line {token.line}; analysis is incomplete')
        while True:
            current = self.current
            if current.kind == 'nl':
                probe = self.index
                while self.tokens[probe].kind == 'nl':
                    probe += 1
                if self.tokens[probe].text == '|>':
                    self.newlines()
                    current = self.current
                else:
                    break
            if current.text == '.':
                self.take()
                member = self.take()
                if member.text == '(':
                    left = Expr('dynamic_call', left.token, args=(left, *self.arguments(')')))
                elif member.kind == 'id':
                    left = Expr('member', left.token, member.text, (left,))
                else:
                    raise ElixirSyntaxError(f'Unsupported Elixir member at line {member.line}')
                continue
            if current.text == '(':
                self.take()
                left = Expr('call', left.token, args=(left, *self.arguments(')')))
                continue
            if current.text == '[':
                self.take()
                item = self.expression()
                self.require(']')
                left = Expr('index', left.token, args=(left, item))
                continue
            precedence = self.PRECEDENCE.get(current.text, -1)
            if precedence >= minimum:
                operator = self.take()
                self.newlines()
                right = self.expression(precedence if operator.text in {'=', '<-', '\\\\'} else precedence + 1)
                left = Expr('binary', operator, operator.text, (left, right))
                continue
            if bare and minimum == 0 and left.kind in {'name', 'member'} and self.starts_argument(current):
                arguments = [self.argument()]
                while self.accept(','):
                    self.newlines()
                    if self.current.text == 'do':
                        self.index -= 1
                        break
                    arguments.append(self.argument())
                left = Expr('call', left.token, args=(left, *arguments))
                continue
            break
        self.depth -= 1
        return left

    def starts_argument(self, token):
        return token.kind in {'string', 'atom', 'number'} or (token.kind == 'id' and token.text not in self.TERMINATORS and token.text not in self.PRECEDENCE) or token.text in {'%', '{', '['}

    @staticmethod
    def name(expr):
        if expr.kind == 'name':
            return expr.value
        if expr.kind == 'member':
            return Parser.name(expr.args[0]) + '.' + expr.value
        raise ElixirSyntaxError(f'Dynamic module expression at Elixir line {expr.token.line}; analysis is incomplete')


@dataclass(frozen=True)
class Value:
    kind: str = 'unknown'
    literal: object = None
    fact: Fact = CLEAN
    identity: tuple = ()
    items: tuple = ()
    test: tuple = ()


@dataclass
class FlowState:
    bindings: dict[str, Value] = field(default_factory=dict)
    checks: dict[tuple, frozenset] = field(default_factory=dict)

    def copy(self):
        return FlowState(dict(self.bindings), dict(self.checks))


@dataclass(frozen=True)
class Function:
    owner: str
    name: str
    parameters: tuple
    guard: Expr
    body: Expr
    token: Token
    public: bool
    attributes: tuple = ()
    aliases: tuple = ()
    imports: tuple = ()


class ElixirEngine:
    """Bounded, path-sensitive worklists over immutable values and scoped bindings.

    The shared Fact lattice owns source joins and finite evidence. Calls bind
    selected same-module clauses to actual arguments. Unsupported recursion or
    syntax is an explicit analysis error, never an empty successful summary.
    """

    def __init__(self, path: Path, text: str, policy: str, budget: Budget | None = None):
        self.path, self.text, self.policy = str(path.resolve()), text, policy
        self.budget = budget or Budget()
        self.tokens = tokenize(text, self.budget)
        self.functions: dict[tuple, list[Function]] = {}
        self.attributes: dict[str, dict[str, Value]] = {}
        self.aliases: dict[str, dict[str, str]] = {}
        self.imports: dict[str, dict[str, str]] = {}
        self.effects: dict[tuple[int, int], Fact] = {}
        self.owner, self.context, self.call_stack = '', (), []
        self.function_scope: Function | None = None

    def step(self, token, kind, label):
        return Step(self.path, token.line, token.col, kind, label)

    def identity(self, expr):
        return (self.owner, *self.context, expr.token.offset)

    def source(self, expr, label, kind='unknown'):
        key = self.identity(expr)
        fact = frozenset({Trace('source', key, evidence=(self.step(expr.token, 'source', label),))})
        return Value(kind, fact=fact, identity=key)

    def derive(self, expr, values, kind='unknown', literal=None, items=()):
        fact = join(*(value.fact for value in values))
        fact = advance(fact, self.step(expr.token, 'transform', expr.value or expr.kind))
        return Value(kind, literal, fact, self.identity(expr), items)

    def outcomes(self, outcomes):
        unique = {}
        for state, value in outcomes:
            key = (tuple(sorted(state.bindings.items())), frozenset(state.checks.items()), value)
            unique.setdefault(key, (state, value))
        if len(unique) > 512:
            raise AnalysisLimit('Elixir branch-state limit exceeded; analysis is incomplete')
        return list(unique.values())

    def sequence(self, block, initial):
        pending = deque([(0, initial, Value('nil'))])
        outputs, visited = [], set()
        while pending:
            self.budget.spend()
            index, state, value = pending.popleft()
            key = (index, tuple(sorted(state.bindings.items())), frozenset(state.checks.items()), value)
            if key in visited:
                continue
            visited.add(key)
            if index == len(block.args):
                outputs.append((state, value))
                continue
            for successor, returned in self.evaluate(block.args[index], state):
                pending.append((index + 1, successor, returned))
            if len(pending) > 512:
                raise AnalysisLimit('Elixir worklist limit exceeded; analysis is incomplete')
        return self.outcomes(outputs)

    def values(self, expressions, state):
        pending = [(state, ())]
        for expr in expressions:
            pending = [(after, (*values, value)) for before, values in pending
                       for after, value in self.evaluate(expr, before)]
            if len(pending) > 512:
                raise AnalysisLimit('Elixir argument-state limit exceeded; analysis is incomplete')
        return pending

    def register_block(self, block, owner=''):
        self.attributes.setdefault(owner, {})
        self.aliases.setdefault(owner, {})
        self.imports.setdefault(owner, {})
        statements = []
        for expr in block.args:
            if expr.kind == 'module':
                name = Parser.name(expr.args[0])
                qualified = f'{owner}.{name}' if owner and '.' not in name else name
                self.aliases[owner][name.split('.')[-1]] = qualified
                self.register_block(expr.args[1], qualified)
            elif expr.kind == 'function':
                name, parameters, guard, body = expr.args
                function = Function(owner, name, parameters, guard, body, expr.token, expr.value == 'def',
                                    tuple(self.attributes[owner].items()), tuple(self.aliases[owner].items()),
                                    tuple(self.imports[owner].items()))
                self.functions.setdefault((owner, name, len(parameters)), []).append(function)
                required = len(parameters)
                for parameter in reversed(parameters):
                    if parameter.kind != 'binary' or parameter.value != '\\\\':
                        break
                    required -= 1
                    self.functions.setdefault((owner, name, required), []).append(function)
            elif expr.kind == 'set_attribute':
                previous = self.owner
                self.owner = owner
                values = self.evaluate(expr.args[0], FlowState())
                self.owner = previous
                if len(values) == 1 and not values[0][1].fact:
                    self.attributes[owner][expr.value] = values[0][1]
            elif expr.kind == 'call' and Parser.name(expr.args[0]) in {'alias', 'import', 'require', 'use'}:
                directive = Parser.name(expr.args[0])
                if directive == 'alias' and len(expr.args) >= 2:
                    name = Parser.name(expr.args[1])
                    short = name.split('.')[-1]
                    for option in expr.args[2:]:
                        if option.kind == 'pair' and option.value == 'as':
                            short = Parser.name(option.args[0])
                    self.aliases[owner][short] = name
                elif directive == 'use':
                    raise ElixirSyntaxError(f'Elixir use macro expansion at line {expr.token.line}; analysis is incomplete')
                elif directive == 'import' and len(expr.args) >= 2:
                    imported = Parser.name(expr.args[1])
                    if imported not in {'Plug.Conn', 'Phoenix.Controller', 'Kernel'}:
                        selected = [option for option in expr.args[2:] if option.kind == 'pair' and option.value == 'only']
                        if selected and selected[0].args[0].kind == 'list':
                            for item in selected[0].args[0].args:
                                if item.kind == 'pair':
                                    self.imports[owner][item.value] = imported
                        else:
                            self.imports[owner]['*'] = imported
            elif expr.kind != 'noop':
                statements.append(expr)
        if statements:
            previous = self.owner
            self.owner = owner
            seed = FlowState({'conn': Value('conn', identity=(owner, 'conn')),
                              'params': Value('request_map', identity=(owner, 'params')),
                              'socket': Value('conn', identity=(owner, 'socket'))})
            self.sequence(Expr('block', block.token, args=tuple(statements)), seed)
            self.owner = previous

    def resolve_module(self, name):
        if name == '__MODULE__':
            return self.owner
        if name.startswith('Elixir.'):
            return name[7:]
        first, *rest = name.split('.')
        aliases = dict(self.function_scope.aliases) if self.function_scope is not None else self.aliases.get(self.owner, {})
        return '.'.join((aliases.get(first, first), *rest))

    def seed(self, pattern):
        if pattern.kind == 'name':
            name = pattern.value.lstrip('_')
            kind = 'conn' if name in {'conn', 'socket'} else 'request_map' if name in {'params', 'query_params'} else 'upload' if name == 'upload' else 'parameter'
            return Value(kind, identity=(self.owner, 'parameter', pattern.token.offset))
        if pattern.kind == 'map':
            kind = {'Plug.Conn': 'conn', 'Plug.Upload': 'upload'}.get(pattern.value, 'request_map')
            return Value(kind, identity=self.identity(pattern))
        if pattern.kind == 'binary' and pattern.value == '=':
            return self.seed(pattern.args[0]) if pattern.args[0].kind == 'map' else self.seed(pattern.args[1])
        return Value(identity=self.identity(pattern))

    def entry_arguments(self, function):
        args = [self.seed(pattern) for pattern in function.parameters]
        if len(args) != 2 or function.parameters[0].kind != 'name':
            return tuple(args)
        connection = function.parameters[0].value
        pending = [function.body]
        request_action = args[0].kind == 'conn'
        while pending:
            node = pending.pop()
            if isinstance(node, Expr):
                if node.kind == 'call' and len(node.args) >= 2 and node.args[0].kind in {'name', 'member'}:
                    callee = Parser.name(node.args[0])
                    actual = node.args[1]
                    if callee in {'redirect', 'Phoenix.Controller.redirect', 'put_resp_header', 'Plug.Conn.put_resp_header', 'send_file', 'Plug.Conn.send_file'} and actual.kind == 'name' and actual.value == connection:
                        request_action = True
                pending.extend(node.args)
            elif isinstance(node, tuple):
                pending.extend(node)
        if request_action:
            args[0] = replace(args[0], kind='conn')
            if args[1].kind == 'parameter':
                args[1] = replace(args[1], kind='request_map')
        return tuple(args)

    def analyze(self):
        # Tokens establish executable vocabulary: strings/comments cannot opt a
        # file into, or out of, the semantic parser.
        pending, executable_tokens = [self.tokens], []
        while pending:
            for token in pending.pop():
                executable_tokens.append(token)
                pending.extend(token.interpolations)
        names = {token.text for token in executable_tokens if token.kind == 'id'}
        sources = {'params', 'conn', '_conn', '_params', 'socket', 'upload', 'filename', 'Conn'}
        sinks = {'redirect', 'put_resp_header', 'send_file', 'send_download', 'File', 'apply', 'Code', 'defmacro'}
        dynamic = any(token.kind == 'id' and token.text[:1].islower() and
                      dot.text == '.' and (next_token.text == '(' or following.text == '(')
                      for token, dot, next_token, following in
                      zip(executable_tokens, executable_tokens[1:], executable_tokens[2:], executable_tokens[3:]))
        request_sinks = {'redirect', 'put_resp_header', 'send_file', 'send_download'}
        if (not names & sources and not names & request_sinks) or (not names & sinks and not dynamic):
            return {}
        program = Parser(self.tokens, self.budget).block()
        self.register_block(program)
        for key, clauses in tuple(self.functions.items()):
            if not any(function.public for function in clauses):
                continue
            self.owner, self.context = key[0], ('entry', key[1], key[2])
            for function in clauses:
                if function.public:
                    if key[2] != len(function.parameters):
                        continue
                    args = self.entry_arguments(function)
                    self.invoke(key, args, FlowState(), Expr('name', function.token, function.name))
        return self.effects

    def evaluate(self, expr, state):
        self.budget.spend()
        kind = expr.kind
        if kind == 'block':
            return self.sequence(expr, state)
        if kind in {'noop', 'function', 'module'}:
            return [(state, Value('nil'))]
        if kind in {'string', 'atom', 'number', 'literal'}:
            if expr.args:
                return [(after, self.derive(expr, values, 'string')) for after, values in self.values(expr.args, state)]
            literal = int(expr.value.replace('_', '')) if kind == 'number' else expr.value
            value_kind = {'true': 'bool', 'false': 'bool', 'nil': 'nil'}.get(expr.value, kind) if kind == 'literal' else kind
            if value_kind == 'bool':
                literal = expr.value == 'true'
            return [(state, Value(value_kind, literal, identity=self.identity(expr)))]
        if kind == 'name':
            if expr.value in state.bindings:
                return [(state, state.bindings[expr.value])]
            if expr.value == '__MODULE__' or expr.value[:1].isupper():
                return [(state, Value('module', self.resolve_module(expr.value)))]
            key = (self.owner, expr.value, 0)
            if key in self.functions:
                return self.invoke(key, (), state, expr)
            return [(state, Value(identity=self.identity(expr)))]
        if kind == 'attribute':
            attributes = dict(self.function_scope.attributes) if self.function_scope is not None else self.attributes.get(self.owner, {})
            return [(state, attributes.get(expr.value, Value(identity=self.identity(expr))))]
        if kind == 'member':
            results = []
            for after, receiver in self.evaluate(expr.args[0], state):
                if receiver.kind == 'module':
                    results.append((after, Value('module', str(receiver.literal) + '.' + expr.value)))
                elif receiver.kind in {'conn', 'parameter'} and expr.value in {'params', 'query_params', 'cookies', 'req_cookies'}:
                    results.append((after, Value('request_map', identity=(*receiver.identity, expr.value))))
                elif receiver.kind in {'conn', 'parameter'} and expr.value in {'host', 'request_path', 'path_info', 'query_string'}:
                    results.append((after, self.source(expr, Parser.name(expr))))
                elif receiver.kind == 'upload' and expr.value == 'filename':
                    results.append((after, self.source(expr, Parser.name(expr))))
                elif receiver.kind == 'upload' and expr.value == 'path':
                    results.append((after, Value('string', identity=self.identity(expr))))
                elif receiver.kind == 'uri' and expr.value in {'scheme', 'host', 'path', 'authority', 'userinfo'}:
                    results.append((after, Value('uri_' + expr.value, fact=receiver.fact,
                                                 identity=(*receiver.identity, expr.value), items=receiver.items)))
                elif receiver.kind == 'map':
                    results.append((after, self.lookup(expr, receiver, Value('atom', expr.value))))
                else:
                    results.append((after, self.derive(expr, (receiver,))))
            return results
        if kind == 'index':
            return [(after, self.lookup(expr, values[0], values[1])) for after, values in self.values(expr.args, state)]
        if kind in {'tuple', 'list', 'pair', 'map_pair', 'map'}:
            results = []
            for after, values in self.values(expr.args, state):
                if kind == 'map':
                    entries = tuple((('atom', value.literal) if value.kind == 'pair' else value.literal, value.items[0])
                                    for value in values if value.kind in {'pair', 'map_pair'})
                    struct = self.resolve_module(expr.value) if expr.value else None
                    results.append((after, self.derive(expr, values, 'map', struct, entries)))
                elif kind == 'map_pair':
                    key = self.map_key(values[0])
                    results.append((after, Value('map_pair', key, values[1].fact, items=(values[1],))))
                elif kind == 'pair':
                    results.append((after, Value('pair', expr.value, values[0].fact, items=values)))
                else:
                    results.append((after, self.derive(expr, values, kind, items=values)))
            return results
        if kind == 'unary':
            results = []
            for after, value in self.evaluate(expr.args[0], state):
                if expr.value in {'not', '!'}:
                    results.append((after, Value('test', test=('not', value))))
                elif expr.value == '-' and value.kind == 'number':
                    results.append((after, replace(value, literal=-value.literal)))
                else:
                    results.append((after, value))
            return results
        if kind == 'binary':
            return self.binary(expr, state)
        if kind in {'call', 'dynamic_call'}:
            if kind == 'dynamic_call':
                raise ElixirSyntaxError(f'Dynamic Elixir function dispatch at line {expr.token.line}; analysis is incomplete')
            return self.call(expr, state)
        if kind == 'if':
            condition, positive, negative = expr.args
            results = []
            for after, value in self.evaluate(condition, state):
                for truth, body in ((expr.value != 'unless', positive), (expr.value == 'unless', negative)):
                    for branch in self.refine(value, after, truth):
                        for final, result in self.sequence(body, branch.copy()):
                            results.append((FlowState(dict(state.bindings), final.checks), result))
            return self.outcomes(results)
        if kind == 'case':
            results = []
            for after, value in self.evaluate(expr.args[0], state):
                for final, result in self.select_clauses(expr.args[1], value, after):
                    results.append((FlowState(dict(state.bindings), final.checks), result))
            return self.outcomes(results)
        if kind == 'cond':
            pending, outputs = [state], []
            for condition, body in expr.args:
                next_pending = []
                for candidate in pending:
                    for after, value in self.evaluate(condition, candidate):
                        for selected in self.refine(value, after, True):
                            for final, result in self.sequence(body, selected.copy()):
                                outputs.append((FlowState(dict(state.bindings), final.checks), result))
                        next_pending.extend(self.refine(value, after, False))
                pending = next_pending
            return self.outcomes(outputs)
        if kind == 'with':
            generators, body, clauses = expr.args
            pending, failed = [state.copy()], []
            for generator in generators:
                following = []
                for candidate in pending:
                    if generator.kind == 'binary' and generator.value == '<-':
                        for after, value in self.evaluate(generator.args[1], candidate):
                            matches, can_fail = self.match(generator.args[0], value, after)
                            following.extend(matches)
                            if can_fail:
                                failed.append((after, value))
                    else:
                        following.extend(after for after, _ in self.evaluate(generator, candidate))
                pending = following
            outputs = [outcome for candidate in pending for outcome in self.sequence(body, candidate)]
            for candidate, value in failed:
                outputs.extend(self.select_clauses(clauses, value, FlowState(dict(state.bindings), candidate.checks)) if clauses else [(candidate, value)])
            return self.outcomes((FlowState(dict(state.bindings), final.checks), value) for final, value in outputs)
        raise ElixirSyntaxError(f'Unsupported Elixir expression {kind} at line {expr.token.line}')

    def binary(self, expr, state):
        left, right = expr.args
        if expr.value == '=':
            return [(matched, value) for after, value in self.evaluate(right, state)
                    for matched in self.match(left, value, after)[0]]
        if expr.value == '|>':
            results = []
            for after, value in self.evaluate(left, state):
                call = right if right.kind == 'call' else Expr('call', right.token, args=(right,))
                results.extend(self.call(call, after, (value,)))
            return self.outcomes(results)
        if expr.value in {'and', '&&', 'or', '||'}:
            results = []
            continuation = expr.value in {'and', '&&'}
            for after, value in self.evaluate(left, state):
                for short in self.refine(value, after, not continuation):
                    results.append((short, value))
                for proceed in self.refine(value, after, continuation):
                    results.extend(self.evaluate(right, proceed))
            return self.outcomes(results)
        results = []
        for after, values in self.values((left, right), state):
            first, second = values
            if expr.value in {'==', '===', '!=', '!==', 'in', '<', '>', '<=', '>='}:
                results.append((after, Value('test', test=(expr.value, first, second))))
            elif expr.value == '<>':
                literal = first.literal + second.literal if isinstance(first.literal, str) and isinstance(second.literal, str) and not first.fact and not second.fact else None
                results.append((after, self.derive(expr, values, 'concat', literal, values)))
            elif expr.value in {'+', '-'} and first.kind == second.kind == 'number':
                results.append((after, Value('number', first.literal + second.literal if expr.value == '+' else first.literal - second.literal)))
            else:
                results.append((after, self.derive(expr, values)))
        return results

    def lookup(self, expr, collection, key):
        if collection.kind == 'request_map':
            name = Parser.name(expr.args[0]) if expr.kind == 'index' and expr.args[0].kind in {'name', 'member'} else 'request value'
            return self.source(expr, name + '[')
        if collection.kind == 'conn' and key.literal in {'params', 'query_params'}:
            return Value('request_map', identity=(*collection.identity, key.literal))
        if collection.kind == 'upload':
            return self.source(expr, 'upload filename') if key.literal == 'filename' else Value(identity=self.identity(expr))
        if collection.kind == 'map':
            selected_key = self.map_key(key)
            if selected_key[0] == 'dynamic':
                return self.derive(expr, tuple(value for _, value in collection.items))
            entries = dict(collection.items)
            possible = [value for item_key, value in collection.items if item_key[0] == 'dynamic']
            if selected_key in entries:
                possible.append(entries[selected_key])
            if len(possible) == 1:
                return possible[0]
            return self.derive(expr, possible) if possible else Value('nil')
        if collection.kind == 'list' and all(item.kind == 'pair' for item in collection.items):
            return next((item.items[0] for item in collection.items if key.kind == 'atom' and item.literal == key.literal), Value('nil'))
        if collection.kind in {'tuple', 'list'} and isinstance(key.literal, int) and 0 <= key.literal < len(collection.items):
            return collection.items[key.literal]
        return self.derive(expr, (collection,))

    @staticmethod
    def map_key(value):
        if value.kind in {'string', 'atom', 'number', 'bool', 'nil'} and not value.fact and value.literal is not None:
            return value.kind, value.literal
        return 'dynamic', value.identity

    def call(self, expr, state, prepend=()):
        callee = expr.args[0]
        name = Parser.name(callee)
        if '.' in name:
            module, function_name = name.rsplit('.', 1)
            if module.split('.')[0] in state.bindings:
                raise ElixirSyntaxError(f'Dynamic Elixir module dispatch at line {expr.token.line}; analysis is incomplete')
            module = self.resolve_module(module)
        else:
            module, function_name = self.owner, name
        results = []
        for after, values in self.values(expr.args[1:], state):
            args = (*prepend, *values)
            first_keyword = next((index for index, value in enumerate(args) if value.kind == 'pair'), len(args))
            selected_args = (*args[:first_keyword], Value('list', items=args[first_keyword:])) if first_keyword < len(args) else args
            key = (module, function_name, len(selected_args))
            if key in self.functions:
                results.extend(self.invoke(key, selected_args, after, expr))
            else:
                results.extend(self.builtin(expr, module, function_name, args, after, '.' in name))
        return self.outcomes(results)

    def invoke(self, key, args, state, expr):
        if len(self.call_stack) >= 24 or self.call_stack.count(key) >= 8:
            raise AnalysisLimit('Elixir selected-call recursion limit exceeded; analysis is incomplete')
        previous_owner, previous_context, previous_scope = self.owner, self.context, self.function_scope
        self.owner, self.context = key[0], (*self.context, expr.token.offset)
        self.call_stack.append(key)
        pending, results = [state.copy()], []
        try:
            for function in self.functions[key]:
                self.function_scope = function
                following = []
                for candidate in pending:
                    selections = [FlowState({}, dict(candidate.checks))]
                    possible_failure = False
                    pattern_bindings = {}
                    for index, pattern in enumerate(function.parameters):
                        if index < len(args):
                            value = args[index]
                        elif pattern.kind == 'binary' and pattern.value == '\\\\':
                            defaults = self.evaluate(pattern.args[1], selections[0]) if selections else []
                            if len(defaults) != 1:
                                raise ElixirSyntaxError(f'Elixir default argument requires additional flow semantics at line {pattern.token.line}')
                            value = defaults[0][1]
                        else:
                            selections = []
                            break
                        if pattern.kind == 'binary' and pattern.value == '\\\\':
                            pattern = pattern.args[0]
                        matches = []
                        for selection in selections:
                            selected, failed = self.match(pattern, value, selection, pattern_bindings)
                            matches.extend(selected)
                            possible_failure |= failed
                        selections = matches
                    if possible_failure or not selections:
                        following.append(candidate)
                    for selection in selections:
                        for guarded, condition in self.evaluate(function.guard, selection):
                            for accepted in self.refine(condition, guarded, True):
                                for final, value in self.sequence(function.body, accepted):
                                    fact = advance(value.fact, self.step(expr.token, 'call', key[1]))
                                    results.append((FlowState(dict(state.bindings), final.checks), replace(value, fact=fact)))
                            if self.refine(condition, guarded, False):
                                following.append(candidate)
                pending = following
                if not pending:
                    break
        finally:
            self.call_stack.pop()
            self.owner, self.context, self.function_scope = previous_owner, previous_context, previous_scope
        return self.outcomes(results)

    def match(self, pattern, value, state, bound=None):
        bound = {} if bound is None else bound
        if pattern.kind == 'binary' and pattern.value == 'when':
            matched, can_fail = self.match(pattern.args[0], value, state, bound)
            accepted = []
            for selected in matched:
                for guarded, condition in self.evaluate(pattern.args[1], selected):
                    accepted.extend(self.refine(condition, guarded, True))
                    can_fail |= bool(self.refine(condition, guarded, False))
            return accepted, can_fail
        if pattern.kind == 'name':
            if pattern.value != '_' and pattern.value in bound:
                equality = Value('test', test=('==', value, bound[pattern.value]))
                return self.refine(equality, state, True), bool(self.refine(equality, state, False))
            selected = state.copy()
            if pattern.value != '_':
                bound[pattern.value] = value
                selected.bindings[pattern.value] = replace(value, fact=advance(value.fact, self.step(pattern.token, 'assignment', pattern.value)))
            return [selected], False
        if pattern.kind == 'binary' and pattern.value in {'=', '\\\\'}:
            matched, failed = self.match(pattern.args[0], value, state, bound)
            results = []
            for selected in matched:
                next_matches, next_failed = self.match(pattern.args[1], value, selected, bound)
                results.extend(next_matches)
                failed |= next_failed
            return results, failed
        if pattern.kind == 'unary' and pattern.value == '^':
            pinned = state.bindings.get(pattern.args[0].value, Value())
            predicate = Value('test', test=('==', value, pinned))
            return self.refine(predicate, state, True), bool(self.refine(predicate, state, False))
        if pattern.kind in {'string', 'atom', 'number', 'literal'}:
            constant = self.evaluate(pattern, state)[0][1]
            predicate = Value('test', test=('==', value, constant))
            return self.refine(predicate, state, True), bool(self.refine(predicate, state, False))
        if pattern.kind in {'tuple', 'list'}:
            if value.kind == pattern.kind and len(value.items) != len(pattern.args):
                return [], True
            if value.kind not in {pattern.kind, 'unknown', 'parameter'}:
                return [], True
            selections = [state.copy()]
            uncertain = value.kind in {'unknown', 'parameter'}
            for index, child in enumerate(pattern.args):
                item = value.items[index] if value.kind == pattern.kind else self.derive(child, (value,))
                following = []
                for selected in selections:
                    matches, failure = self.match(child, item, selected, bound)
                    following.extend(matches)
                    uncertain |= failure
                selections = following
            return selections, uncertain
        if pattern.kind == 'map':
            if value.kind not in {'map', 'request_map', 'conn', 'upload', 'uri', 'unknown', 'parameter'}:
                return [], True
            struct = self.resolve_module(pattern.value) if pattern.value else None
            known_struct = value.literal if value.kind == 'map' else {'conn': 'Plug.Conn', 'upload': 'Plug.Upload', 'uri': 'URI'}.get(value.kind)
            if struct and value.kind not in {'request_map', 'unknown', 'parameter'} and known_struct != struct:
                return [], True
            selections, uncertain = [state.copy()], value.kind in {'request_map', 'unknown', 'parameter'}
            for pair in pattern.args:
                if pair.kind == 'pair':
                    key = Value('atom', pair.value)
                    child = pair.args[0]
                elif pair.kind == 'map_pair':
                    key = self.evaluate(pair.args[0], state)[0][1]
                    child = pair.args[1]
                else:
                    raise ElixirSyntaxError(f'Unsupported Elixir map pattern at line {pair.token.line}')
                selected_key = self.map_key(key)
                if selected_key[0] == 'dynamic':
                    raise ElixirSyntaxError(f'Unresolved Elixir map-pattern key at line {pair.token.line}; analysis is incomplete')
                if value.kind == 'map' and selected_key not in dict(value.items):
                    if not any(item_key[0] == 'dynamic' for item_key, _ in value.items):
                        return [], True
                    uncertain = True
                item = self.lookup(pair, value, key)
                following = []
                for selected in selections:
                    matches, failed = self.match(child, item, selected, bound)
                    following.extend(matches)
                    uncertain |= failed
                selections = following
            return selections, uncertain
        if pattern.kind == 'binary' and pattern.value == '<>' and pattern.args[0].kind == 'string':
            prefix = self.evaluate(pattern.args[0], state)[0][1]
            predicate = Value('test', test=('prefix', value, prefix))
            selections = self.refine(predicate, state, True)
            results = []
            for selected in selections:
                results.extend(self.match(pattern.args[1], self.derive(pattern, (value,)), selected, bound)[0])
            return results, bool(self.refine(predicate, state, False))
        raise ElixirSyntaxError(f'Unsupported Elixir match at line {pattern.token.line}; analysis is incomplete')

    def select_clauses(self, clauses, value, state):
        pending, results = [state], []
        for pattern, body in clauses:
            following = []
            for candidate in pending:
                matches, can_fail = self.match(pattern, value, candidate)
                for selected in matches:
                    results.extend(self.sequence(body, selected))
                if can_fail:
                    following.append(candidate)
            pending = following
        return self.outcomes(results)

    def mark(self, state, value, check):
        updated = state.copy()
        if value.identity:
            updated.checks[value.identity] = updated.checks.get(value.identity, frozenset()) | {check}
        return updated

    @staticmethod
    def constants(value):
        values = value.items if value.kind in {'list', 'set'} else (value,)
        if all(item.kind in {'string', 'atom', 'number', 'bool', 'concat', 'path'} and item.literal is not None and not item.fact for item in values):
            return tuple(item.literal for item in values)
        return ()

    def refine(self, predicate, state, truth):
        identity = ('predicate', predicate.test) if predicate.kind == 'test' else ('truth', predicate.identity)
        known = state.checks.get(identity, frozenset())
        if ('truth', not truth) in known:
            return []
        outcomes = self._refine(predicate, state, truth)
        if predicate.kind in {'test', 'unknown', 'parameter'}:
            for outcome in outcomes:
                outcome.checks[identity] = frozenset({('truth', truth)})
        return outcomes

    def _refine(self, predicate, state, truth):
        self.budget.spend()
        if predicate.kind == 'bool':
            return [state.copy()] if bool(predicate.literal) == truth else []
        if predicate.kind == 'nil':
            return [] if truth else [state.copy()]
        if predicate.kind in {'string', 'number', 'atom', 'tuple', 'list', 'map', 'conn', 'upload', 'uri', 'path', 'concat'}:
            return [state.copy()] if truth else []
        if predicate.kind != 'test':
            return [state.copy()]
        operation, *arguments = predicate.test
        if operation == 'not':
            return self.refine(arguments[0], state, not truth)
        first, second = arguments[:2]
        if operation in {'!=', '!=='}:
            return self.refine(Value('test', test=('==', first, second)), state, not truth)
        if operation in {'==', '==='}:
            if first.kind == 'bool':
                return self.refine(second, state, truth == bool(first.literal))
            if second.kind == 'bool':
                return self.refine(first, state, truth == bool(second.literal))
            known_first, known_second = self.constants(first), self.constants(second)
            if known_first and known_second and first.kind not in {'list', 'set'} and second.kind not in {'list', 'set'}:
                return [state.copy()] if (first.kind == second.kind and first.literal == second.literal) == truth else []
            if first.identity and first.identity == second.identity:
                return [state.copy()] if truth else []
            if first.kind in {'uri_scheme', 'uri_host'} and known_second and truth:
                return [self.mark(state, first.items[0], (first.kind, str(second.literal)))]
            if second.kind in {'uri_scheme', 'uri_host'}:
                return self.refine(Value('test', test=(operation, second, first)), state, truth)
            if truth and first.kind == second.kind == 'path' and not second.fact:
                return [self.mark(state, first, ('bounded', second.identity))]
            if truth and second.kind == 'path' and first.kind == 'path' and not first.fact:
                return [self.mark(state, second, ('bounded', first.identity))]
            if truth and known_second and not second.fact:
                return [self.mark(state, first, ('literal', str(second.literal)))]
            return [state.copy()]
        if operation == 'in':
            constants = self.constants(second)
            if constants and first.kind in {'uri_scheme', 'uri_host'} and truth:
                if first.kind == 'uri_scheme' and not set(constants) <= {'http', 'https'}:
                    return [state.copy()]
                return [self.mark(state, first.items[0], (first.kind, '|'.join(map(str, constants))))]
            if self.constants(first) and constants:
                return [state.copy()] if (first.literal in constants) == truth else []
            return [state.copy()]
        if operation in {'prefix', 'contains'}:
            constants = self.constants(second)
            if not constants:
                return [state.copy()]
            if first.literal is not None and isinstance(first.literal, str):
                result = any(first.literal.startswith(item) if operation == 'prefix' else item in first.literal for item in constants if isinstance(item, str))
                return [state.copy()] if result == truth else []
            updated = state.copy()
            if truth:
                if len(constants) != 1:
                    return [updated]
                term = constants[0]
                updated = self.mark(updated, first, (operation, term))
                if operation == 'prefix' and first.kind == 'path' and isinstance(term, str) and term.startswith('/') and term.endswith('/') and len(term) > 1:
                    updated = self.mark(updated, first, ('bounded', term))
            else:
                for term in constants:
                    updated = self.mark(updated, first, ('no_' + operation, term))
            return [updated]
        return [state.copy()]

    def safe(self, value, state, file_leaf=False):
        checks = state.checks.get(value.identity, frozenset())
        if any(check[0] == 'literal' for check in checks):
            return True
        if self.policy == 'path':
            return any(check[0] == 'bounded' for check in checks) or (file_leaf and value.kind in {'basename', 'basename_join'})
        prohibited = {'\\', '\r', '\n', '\t'}
        excludes = {check[1] for check in checks if check[0] == 'no_contains'}
        if not prohibited <= excludes:
            return False
        if ('prefix', '/') in checks and ('no_prefix', '//') in checks:
            return True
        schemes = [check[1] for check in checks if check[0] == 'uri_scheme']
        hosts = [check[1] for check in checks if check[0] == 'uri_host']
        return bool(schemes and hosts and all(set(scheme.split('|')) <= {'https', 'http'} for scheme in schemes))

    def sink(self, expr, value, state, label, file_leaf=False):
        if not value.fact or self.safe(value, state, file_leaf):
            return
        fact = advance(value.fact, self.step(expr.token, 'sink', label))
        key = (expr.token.line, expr.token.col)
        self.effects[key] = join(self.effects.get(key, CLEAN), fact)

    def builtin(self, expr, module, name, args, state, qualified):
        canonical = f'{module}.{name}' if qualified else name
        options = [value for value in args if value.kind == 'pair']
        for value in args:
            if value.kind == 'list' and value.items and all(item.kind == 'pair' for item in value.items):
                options.extend(value.items)
        keywords = {value.literal: value.items[0] for value in options}
        positional = tuple(value for value in args if value.kind != 'pair')
        imported = dict(self.function_scope.imports) if self.function_scope is not None else self.imports.get(self.owner, {})
        if not qualified and (name in imported or '*' in imported):
            raise ElixirSyntaxError(f'Unresolved imported Elixir call {name} at line {expr.token.line}; analysis is incomplete')
        if canonical in {'apply', 'Kernel.apply', 'Code.eval_string', 'Code.eval_quoted', 'Module.eval_quoted'}:
            raise ElixirSyntaxError(f'Dynamic Elixir execution at line {expr.token.line}; analysis is incomplete')
        if canonical in {'raise', 'throw', 'exit', 'Kernel.raise', 'Kernel.throw', 'Kernel.exit'}:
            return []
        if canonical in {'redirect', 'Phoenix.Controller.redirect'}:
            if self.policy == 'redirect':
                for option in ('external', 'to'):
                    if option in keywords:
                        self.sink(expr, keywords[option], state, 'redirect')
            return [(state, positional[0] if positional else Value())]
        if canonical in {'put_resp_header', 'Plug.Conn.put_resp_header'}:
            if self.policy == 'redirect' and len(positional) >= 3:
                if str(positional[1].literal).lower() == 'location':
                    self.sink(expr, positional[2], state, 'redirect')
                elif positional[1].literal is None and positional[2].fact:
                    raise ElixirSyntaxError(f'Unresolved Elixir response-header name at line {expr.token.line}; analysis is incomplete')
            return [(state, positional[0] if positional else Value())]
        if canonical in {'put_resp_headers', 'Plug.Conn.put_resp_headers'}:
            if self.policy == 'redirect' and len(positional) >= 2:
                headers = positional[1]
                if headers.kind == 'list':
                    for pair in headers.items:
                        if pair.kind == 'tuple' and len(pair.items) == 2 and str(pair.items[0].literal).lower() == 'location':
                            self.sink(expr, pair.items[1], state, 'redirect')
                        elif pair.kind == 'tuple' and len(pair.items) == 2 and pair.items[0].literal is None and pair.items[1].fact:
                            raise ElixirSyntaxError(f'Unresolved Elixir response-header name at line {expr.token.line}; analysis is incomplete')
                elif headers.fact:
                    raise ElixirSyntaxError(f'Unresolved Elixir response-header collection at line {expr.token.line}; analysis is incomplete')
            return [(state, positional[0] if positional else Value())]
        if canonical in {'send_file', 'Plug.Conn.send_file', 'send_download', 'Phoenix.Controller.send_download'}:
            if self.policy == 'path':
                if name == 'send_file' and len(positional) >= 3:
                    self.sink(expr, positional[2], state, 'send_file', True)
                elif name == 'send_download' and len(positional) >= 2:
                    value = positional[1]
                    if value.kind == 'tuple' and len(value.items) == 2 and value.items[0].literal == 'file':
                        self.sink(expr, value.items[1], state, 'send_download', True)
            return [(state, positional[0] if positional else Value())]
        if module == 'File' and qualified:
            leaf = name.rstrip('!?') in {'read', 'write', 'open', 'stream', 'cp', 'copy'}
            path_arguments = positional[:2] if name.rstrip('!?') in {'cp', 'copy', 'rename'} else positional[:1]
            if self.policy == 'path' and name.rstrip('!?') in {'read', 'write', 'open', 'rm', 'cp', 'copy', 'rename', 'mkdir', 'mkdir_p', 'stat', 'ls', 'stream', 'exists', 'touch', 'rmdir', 'rm_rf'}:
                for argument in path_arguments:
                    self.sink(expr, argument, state, canonical, leaf)
            return [(state, Value(identity=self.identity(expr)))]
        if canonical in {'Plug.Conn.get_req_header', 'get_req_header'} and positional:
            value = self.source(expr, 'request header') if positional[0].kind == 'conn' else self.derive(expr, positional)
            return [(state, replace(value, kind='list', items=(value,)))]
        if canonical in {'Map.get', 'Map.fetch', 'Map.fetch!', 'Keyword.get', 'Keyword.fetch', 'Keyword.fetch!'} and len(positional) >= 2:
            value = self.lookup(expr, positional[0], positional[1])
            if name == 'fetch':
                success = (state, Value('tuple', fact=value.fact, identity=self.identity(expr), items=(Value('atom', 'ok'), value)))
                failure = (state.copy(), Value('atom', 'error'))
                if positional[0].kind == 'map' and self.map_key(positional[1])[0] != 'dynamic':
                    if self.map_key(positional[1]) in dict(positional[0].items):
                        return [success]
                    if not any(key[0] == 'dynamic' for key, _ in positional[0].items):
                        return [failure]
                if positional[0].kind == 'list' and positional[1].literal is not None:
                    return [success] if any(item.kind == 'pair' and item.literal == positional[1].literal for item in positional[0].items) else [failure]
                return [success, failure]
            if value.kind == 'nil' and len(positional) > 2:
                value = positional[2]
            return [(state, value)]
        if canonical == 'get_in' and len(positional) >= 2:
            value = positional[0]
            if positional[1].kind != 'list':
                return [(state, self.derive(expr, positional))]
            for key in positional[1].items:
                value = self.lookup(expr, value, key)
            return [(state, value)]
        if canonical in {'List.first', 'hd', 'Kernel.hd'} and positional:
            value = positional[0].items[0] if positional[0].kind == 'list' and positional[0].items else self.derive(expr, positional)
            return [(state, value)]
        if canonical in {'elem', 'Kernel.elem'} and len(positional) == 2:
            return [(state, self.lookup(expr, positional[0], positional[1]))]
        if canonical == 'MapSet.new' and positional:
            return [(state, replace(positional[0], kind='set'))]
        if canonical in {'MapSet.member?', 'Enum.member?'} and len(positional) == 2:
            return [(state, Value('test', test=('in', positional[1], positional[0])))]
        if canonical in {'String.starts_with?', 'String.contains?'} and len(positional) == 2:
            return [(state, Value('test', test=('prefix' if name == 'starts_with?' else 'contains', *positional)))]
        if canonical == 'URI.parse' and positional:
            value = positional[0]
            return [(state, self.derive(expr, (value,), 'uri', items=(value,)))]
        if canonical == 'URI.to_string' and positional:
            original = positional[0].items[0] if positional[0].kind == 'uri' else positional[0]
            return [(state, replace(original, fact=advance(original.fact, self.step(expr.token, 'transform', canonical))))]
        if canonical == 'Path.expand' and positional:
            literal = positional[0].literal
            if isinstance(literal, str):
                base = positional[1].literal if len(positional) > 1 else '/'
                literal = posixpath.normpath(literal if literal.startswith('/') else posixpath.join(base if isinstance(base, str) else '/', literal))
            return [(state, self.derive(expr, positional, 'path', literal))]
        if canonical == 'Path.basename' and positional:
            return [(state, self.derive(expr, positional, 'basename'))]
        if canonical == 'Path.join' and positional:
            parts = positional[0].items if len(positional) == 1 and positional[0].kind == 'list' else positional
            literal = posixpath.join(*(str(part.literal) for part in parts)) if parts and all(isinstance(part.literal, str) for part in parts) else None
            leaf = bool(parts and parts[-1].kind == 'basename' and all(not part.fact for part in parts[:-1]))
            return [(state, self.derive(expr, parts, 'basename_join' if leaf else 'path_join', literal, parts))]
        if canonical in {'is_binary', 'is_map', 'is_list', 'is_atom', 'is_integer', 'is_nil', 'is_tuple'} and positional:
            if canonical == 'is_nil' and positional[0].kind != 'unknown':
                return [(state, Value('bool', positional[0].kind == 'nil'))]
            return [(state, Value('test', test=('type', positional[0], Value('atom', canonical))))]
        if canonical in {'halt', 'Plug.Conn.halt', 'send_resp', 'Plug.Conn.send_resp', 'put_status', 'Plug.Conn.put_status', 'json', 'Phoenix.Controller.json', 'assign', 'Plug.Conn.assign', 'put_resp_content_type', 'Plug.Conn.put_resp_content_type', 'put_resp_cookie', 'Plug.Conn.put_resp_cookie'}:
            return [(state, positional[0] if positional else Value())]
        if canonical in {'String.trim', 'String.trim_leading', 'String.trim_trailing', 'String.replace', 'String.downcase', 'String.upcase', 'URI.decode', 'URI.decode_www_form', 'URI.encode', 'URI.encode_www_form', 'to_string', 'Kernel.to_string', 'Path.relative_to', 'Path.relative', 'Enum.join', 'List.to_string'}:
            return [(state, self.derive(expr, positional))]
        if any(value.fact for value in positional) or any(value.kind in {'conn', 'request_map'} for value in positional):
            raise ElixirSyntaxError(f'Unresolved Elixir call {canonical} at line {expr.token.line}; analysis is incomplete')
        return [(state, Value(identity=self.identity(expr)))]

ROOT: Path = Path()
BASE_DIR: Path = Path()



SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''


def flow_findings(path: Path, policy: str, budget: Budget | None = None):
    """Report sink findings; source annotations never erase downstream flow."""
    text = path.read_text(encoding='utf-8')
    engine = ElixirEngine(path, text, policy, budget)
    lines = text.splitlines()
    suppressions = build_index(text, lang='elixir')
    rule = 'elixir.taint.request_path_traversal' if policy == 'path' else 'elixir.taint.open_redirect'
    # The shell modules shipped these scoped annotation IDs before the core
    # analyzer IDs. Preserve only the matching alias, at the actual sink.
    legacy_rule = 'ex.request-path-traversal' if policy == 'path' else 'ex.request-open-redirect'
    incomplete = None
    try:
        effects = engine.analyze()
    except ValueError as exc:
        # A later unsupported call cannot retract already established sinks.
        effects, incomplete = engine.effects, exc
    for (line, col), fact in sorted(effects.items()):
        if any(suppressions.is_suppressed(line, name) for name in (rule, legacy_rule)):
            continue
        evidence = min((trace.evidence for trace in fact), key=lambda steps: (len(steps), steps))
        code = source_line(lines, line)
        if policy == 'redirect':
            code += f"  [{evidence[0].label} -> redirect]"
        yield line, col, code, {
            'taint_path': [step.record() for step in evidence],
            'source_count': len({trace.key for trace in fact}),
        }
    if incomplete is not None:
        raise incomplete


def scan_file_findings(path: Path):
    for line, col, code, _extras in flow_findings(path, 'path'):
        yield line, col, code


def analyze(path, issues):
    """Heredoc aggregation: collect one (relpath, line, code) tuple per finding."""
    for idx, _col, code in scan_file_findings(path):
        issues.append((relpath(path), idx, code))


def main(argv=None) -> int:
    """Byte-parity entrypoint: same behavior as the heredoc given the same argv."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code in issues[:5]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_MESSAGE = "Request-derived path reaches file read/write/serve sink"


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        resolved = path.resolve()
        for line_no, col, code, extras in flow_findings(path, 'path'):
            yield {
                "rule": "elixir.taint.request_path_traversal",
                "path": str(resolved),
                "line": line_no,
                "col": col,
                "layer": "taint",
                "lang": "elixir",
                "severity": "critical",
                "message": f"{_MESSAGE} ({code})",
                "extras": extras,
            }


def _selftest_direct_traversal(tmp_prefix: str = "ubs_core_taint_elixir_trav_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "show.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = conn.params[\"file\"]\n"
            "  File.read(path)\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "elixir.taint.request_path_traversal", findings
    assert findings[0]["line"] == 3, findings
    assert findings[0]["col"] == 3, findings
    assert findings[0]["severity"] == "critical", findings
    assert "File.read(path)" in findings[0]["message"], findings


def _selftest_propagated_traversal(tmp_prefix: str = "ubs_core_taint_elixir_trav_prop_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "flow.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  raw = conn.params[\"file\"]\n"
            "  path = raw\n"
            "  File.write(path, \"data\")\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 4, findings


def _selftest_basename_suppression(tmp_prefix: str = "ubs_core_taint_elixir_trav_base_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = Path.basename(conn.params[\"file\"])\n"
            "  File.read(Path.join(\"uploads\", path))\n"
            "end\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_elixir_trav_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.ex"
        target.write_text(
            "# ubs:ignore\n"
            "path = conn.params[\"file\"]\n"
            "File.read(path)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="elixir", files=[target])))
    # Suppressing the source assignment never suppresses a later sink.
    assert len(findings) == 1 and findings[0]["line"] == 3, findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_elixir_trav_main_") -> None:
    import tempfile
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "show.ex"
        target.write_text(
            "def show(conn, _params) do\n"
            "  path = conn.params[\"file\"]\n"
            "  File.read(path)\n"
            "end\n",
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", tmp])
        assert rc == 0
        out = buffer.getvalue()
    assert out == "__COUNT__\t1\n__SAMPLE__\tshow.ex\t3\tFile.read(path)\n", repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_traversal", _selftest_direct_traversal),
    ("propagated_traversal", _selftest_propagated_traversal),
    ("basename_suppression", _selftest_basename_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="elixir", name="taint_elixir_traversal", run=run, selftests=SELF_TESTS))
