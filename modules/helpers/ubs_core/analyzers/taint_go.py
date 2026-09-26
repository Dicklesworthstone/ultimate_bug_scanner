"""Function-scoped Go taint analysis with local helper summaries (bead D6).

The lexical front end preserves source locations and Go string semantics.
Statement transfers strongly update assignments, join branches and iterate
loops and local call summaries to convergence. Sanitizers are specific to the
interpreter receiving a value. This is a conservative source analyzer, not a
Go type checker; cross-file calls and dynamically invoked closures are not
resolved. Both output entrypoints consume the same finding stream.
"""
from __future__ import annotations

import ast
import re
from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {'.git', 'vendor', '.cache', 'bin', 'dist', '.idea'}
EXTS = {'.go'}
PATH_LIMIT = 6

SOURCE_PATTERNS = [
    re.compile(r"\.FormValue\(", re.IGNORECASE),
    re.compile(r"\.PostFormValue\(", re.IGNORECASE),
    re.compile(r"\.(?:Form|PostForm)\.Get\(", re.IGNORECASE),
    re.compile(r"\.Header\.Get\(", re.IGNORECASE),
    re.compile(r"URL\.Query\(\)\.Get", re.IGNORECASE),
    re.compile(r"\.PathValue\(", re.IGNORECASE),
    re.compile(r"mux\.Vars\(", re.IGNORECASE),
    re.compile(r"chi\.URLParam\(", re.IGNORECASE),
    re.compile(r"\.(?:QueryParam|FormParam|Param)\(", re.IGNORECASE),
    re.compile(r"os\.Getenv", re.IGNORECASE),
    re.compile(r"bufio\.NewReader\(os\.Stdin\)", re.IGNORECASE),
    re.compile(r"io\.ReadAll\([^)]*(?:r|req|request)\.Body", re.IGNORECASE),
    re.compile(r"json\.NewDecoder\([^)]*(?:r|req|request)\.Body", re.IGNORECASE),
]

HTML_SANITIZERS = re.compile(
    r"(?<![\w.])(?:html\.EscapeString|template\.HTMLEscapeString)\s*\("
)

SINKS = [
    (re.compile(r"(?<![\w.])fmt\.Fprint(?:f|ln)?\s*\("), 'go.taint.xss', 'fmt.Fprintf'),
    (re.compile(r"\b[A-Za-z_][\w]*\.Write\s*\("), 'go.taint.xss', 'ResponseWriter.Write'),
    (re.compile(r"\btemplate\.[A-Za-z_][\w]*\.Execute\s*\("), 'go.taint.xss', 'template.Execute'),
    (re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?\.(?:Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|Raw|NamedQuery|NamedQueryContext|NamedExec|NamedExecContext|Select|SelectContext|Where|Or|Not|Having|Order)\s*\("), 'go.taint.sql', 'SQL query'),
    (re.compile(r"\b(?:db|tx|conn|pool|repo|store|database|queries|sqlxDB)\.Get(?:Context)?\s*\("), 'go.taint.sql', 'SQL query'),
    (re.compile(r"(?<![\w.])exec\.Command(?:Context)?\s*\("), 'go.taint.command', 'exec.Command'),
]

ASSIGN_PATTERNS = [
    re.compile(r"^\s*(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*(?P<op>:=|\+=|=(?!=))\s*(?P<expr>.+)", re.DOTALL),
    re.compile(r"^\s*(?:var|const)\s+(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)(?:\s+[^=]+)?\s*(?P<op>=)\s*(?P<expr>.+)", re.DOTALL),
]


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
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


def _masked_source(text: str, *, strings: bool = True) -> str:
    """Mask inert Go text, preserving offsets and newline positions.

    Raw strings do not interpret backslashes. An inert zero at the start of
    each string preserves Go's newline/semicolon boundary after a literal.
    """
    out = list(text)
    i = 0
    while i < len(text):
        start = i
        literal = text[i] in ('"', "'", '`')
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            i = len(text) if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            i = len(text) if end < 0 else end + 2
        elif literal:
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == '\\' and quote != '`':
                    i += 2
                else:
                    i += 1
            i = min(i, len(text))
            if not strings:
                continue
        else:
            i += 1
            continue
        for pos in range(start, i):
            out[pos] = '\n' if text[pos] == '\n' else ' '
        if literal and strings:
            out[start] = '0'
    return ''.join(out)


def _pairs(code: str) -> dict[int, int]:
    stack, pairs = [], {}
    for pos, char in enumerate(code):
        if char in '([{':
            stack.append((char, pos))
        elif char in ')]}' and stack and stack[-1][0] == {')': '(', ']': '[', '}': '{'}[char]:
            pairs[stack.pop()[1]] = pos
    return pairs


def _parts(code: str, separator: str = ',') -> list[tuple[int, int]]:
    starts, depth, start = [], 0, 0
    for pos, char in enumerate(code):
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif char == separator and depth == 0:
            starts.append((start, pos))
            start = pos + 1
    if code[start:].strip() or starts:
        starts.append((start, len(code)))
    return starts


def split_go_args(expr: str):
    return [expr[start:end].strip() for start, end in _parts(_masked_source(expr))]


def _string_literal(expr: str) -> str | None:
    expr = expr.strip()
    if expr.startswith('`') and expr.endswith('`') and '`' not in expr[1:-1]:
        return expr[1:-1]
    if not expr.startswith('"'):
        return None
    try:
        value = ast.literal_eval(expr)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _command_arguments(arguments: list[str]) -> list[int]:
    """Select executable source; fixed-program argv values are data.

    An unknown interpreter option/expanded argv can select an eval mode, so
    its remaining arguments are conservatively retained. Once a fixed script
    or eval program is selected, subsequent positional data is not code.
    """
    if not arguments:
        return []
    executable = _string_literal(arguments[0])
    if executable is None:
        return list(range(len(arguments)))
    executable = executable.replace('\\', '/').rsplit('/', 1)[-1].lower().removesuffix('.exe')
    shells = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'fish'}
    flags = {'node': {'-e', '--eval', '-p', '--print'}, 'nodejs': {'-e', '--eval', '-p', '--print'},
             'ruby': {'-e'}, 'perl': {'-e', '-E'}, 'php': {'-r'},
             'powershell': {'-command', '-c'}, 'pwsh': {'-command', '-c'},
             'cmd': {'/c', '/k'}}
    if re.fullmatch(r'python(?:\d+(?:\.\d+)*)?', executable):
        code_flags = {'-c'}
    elif executable in shells:
        code_flags = {'-c', '--command'}
    elif executable in flags:
        code_flags = flags[executable]
    else:
        return [0]
    for index in range(1, len(arguments)):
        argument = _string_literal(arguments[index])
        if argument is None:
            return [0, *range(index, len(arguments))]
        option = argument.lower() if executable in {'powershell', 'pwsh', 'cmd'} else argument
        shell_code = executable in shells and option.startswith('-') and not option.startswith('--') and 'c' in option[1:]
        if option in code_flags or shell_code:
            return [0, index + 1] if index + 1 < len(arguments) else [0]
        if option == '--':
            return [0, index + 1] if index + 1 < len(arguments) else [0]
        if not option.startswith('-'):
            return [0, index]
    return [0]


@dataclass(frozen=True)
class _Trace:
    source: str
    parameter: int | None = None
    # Evidence does not change lattice equality: recursive paths must not
    # prevent convergence once the actual source/parameter facts stabilize.
    path: tuple[str, ...] = field(default=(), compare=False)


_Fact = frozenset[_Trace]
_CLEAN: _Fact = frozenset()


def _join(*facts: _Fact) -> _Fact:
    result = {}
    for fact in facts:
        for trace in fact:
            previous = result.get(trace)
            if previous is None or (len(trace.path), trace.path) < (len(previous.path), previous.path):
                result[trace] = trace
    return frozenset(result.values())


def _advance(fact: _Fact, step: str) -> _Fact:
    result = []
    for trace in fact:
        path = trace.path
        if not path or path[-1] != step:
            path += (step,)
        if len(path) > PATH_LIMIT:
            path = (path[0], *path[-(PATH_LIMIT - 1):])
        result.append(_Trace(trace.source, trace.parameter, path))
    return frozenset(result)


def _join_states(*states):
    states = [state for state in states if state is not None]
    if not states:
        return None
    return {name: _join(*(state.get(name, _CLEAN) for state in states))
            for name in set().union(*(state.keys() for state in states))}


@dataclass
class _Scope:
    bindings: dict[str, str] = field(default_factory=dict)
    local: set[str] = field(default_factory=set)

    def child(self):
        return _Scope(dict(self.bindings))

    def declare(self, name: str, offset: int) -> str:
        if name not in self.local:
            self.bindings[name] = f'{name}@{offset}'
            self.local.add(name)
        return self.bindings[name]


@dataclass(frozen=True)
class _Statement:
    start: int
    end: int
    kind: str = 'simple'
    body: tuple = ()
    otherwise: tuple = ()


class _Parser:
    """Recognize balanced statements and structured Go control flow."""

    def __init__(self, code: str):
        self.code = code
        self.pairs = _pairs(code)

    def skip(self, start: int, end: int) -> int:
        while start < end and (self.code[start].isspace() or self.code[start] == ';'):
            start += 1
        return start

    def body_open(self, start: int, end: int) -> int | None:
        pos = start
        while pos < end:
            char = self.code[pos]
            if char == '{':
                return pos
            if char in '([' and pos in self.pairs:
                pos = self.pairs[pos]
            pos += 1
        return None

    def statement_end(self, start: int, end: int) -> int:
        pos, previous = start, ''
        while pos < end:
            char = self.code[pos]
            if char in '([{' and pos in self.pairs:
                pos = self.pairs[pos]
                previous = self.code[pos]
            elif char == ';' or (char == '\n' and previous not in '=+-,.:*/&|^<>!'):
                return pos
            elif not char.isspace():
                previous = char
            pos += 1
        return end

    def block(self, start: int, end: int) -> tuple[_Statement, ...]:
        statements = []
        while (start := self.skip(start, end)) < end:
            statement, following = self.statement(start, end)
            statements.append(statement)
            start = max(following, start + 1)
        return tuple(statements)

    def statement(self, start: int, end: int):
        if self.code[start] == '{' and start in self.pairs:
            close = self.pairs[start]
            return _Statement(start, close + 1, 'block', self.block(start + 1, close)), close + 1
        control = re.match(r'(if|for|switch|select)\b', self.code[start:end])
        if control:
            opening = self.body_open(start + control.end(), end)
            if opening is not None and opening in self.pairs:
                close = self.pairs[opening]
                kind = control.group(1)
                body = self.cases(opening + 1, close) if kind in {'switch', 'select'} else self.block(opening + 1, close)
                following, otherwise = close + 1, ()
                after = self.skip(following, end)
                if kind == 'if' and re.match(r'else\b', self.code[after:end]):
                    other_start = self.skip(after + 4, end)
                    other, following = self.statement(other_start, end)
                    otherwise = (other,)
                return _Statement(start, opening, kind, body, otherwise), following
        following = self.statement_end(start, end)
        return _Statement(start, following), following + 1

    def cases(self, start: int, end: int) -> tuple[_Statement, ...]:
        labels = []
        pos = start
        while pos < end:
            if self.code[pos] in '([{' and pos in self.pairs:
                pos = self.pairs[pos] + 1
                continue
            label = re.match(r'(case\b|default\s*:)', self.code[pos:end])
            if label:
                colon = pos + label.end() - 1
                while colon < end and self.code[colon] != ':':
                    if self.code[colon] in '([{' and colon in self.pairs:
                        colon = self.pairs[colon]
                    colon += 1
                labels.append((pos, colon))
                pos = colon
            pos += 1
        return tuple(_Statement(pos, colon, 'default' if self.code[pos:].startswith('default') else 'case',
                                self.block(colon + 1, labels[index + 1][0] if index + 1 < len(labels) else end))
                     for index, (pos, colon) in enumerate(labels))


@dataclass(frozen=True)
class _Function:
    name: str
    start: int
    end: int
    parameters: tuple[str, ...]
    results: tuple[str, ...]
    body: tuple[_Statement, ...]
    variadic: int | None = None


def _parameter_names(code: str) -> tuple[str, ...]:
    """Preserve positions for both grouped names and unnamed parameters."""
    names, grouped = [], False
    for start, end in reversed(_parts(code)):
        part = code[start:end].strip()
        match = re.match(r'^([A-Za-z_]\w*)\s+(.+)$', part, re.DOTALL)
        if match:
            names.append(match.group(1))
            grouped = True
        elif grouped and re.fullmatch(r'[A-Za-z_]\w*', part):
            names.append(part)
        else:
            names.append('')
            grouped = False
    return tuple(reversed(names))


def _functions(code: str, parser: _Parser) -> list[_Function]:
    functions, covered = [], 0
    pattern = re.compile(r'\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*(?:\[[^]]*\]\s*)?\('
                         r'|\bvar\s+(?P<closure>[A-Za-z_]\w*)\s*=\s*func\s*\(')
    for match in pattern.finditer(code):
        if match.start() < covered:
            continue
        param_end = parser.pairs.get(match.end() - 1)
        if param_end is None:
            continue
        opening = parser.body_open(param_end + 1, len(code))
        if opening is None or opening not in parser.pairs:
            continue
        end = parser.pairs[opening] + 1
        result = code[param_end + 1:opening].strip()
        results = _parameter_names(result[1:-1]) if result.startswith('(') and result.endswith(')') else ('',) if result else ()
        # Methods remain separately scoped, but cannot be resolved from an
        # unqualified helper call without receiver type information.
        name = match.group('closure')
        if name is None:
            name = match.group('name') if not code[match.start() + 4:match.start('name')].strip() else f'@method:{match.start()}'
        if name == 'init':
            name = f'@init:{match.start()}'
        parameters = _parameter_names(code[match.end():param_end])
        functions.append(_Function(name, match.start(), end, parameters, results,
                                   parser.block(opening + 1, end - 1),
                                   len(parameters) - 1 if '...' in code[match.end():param_end] else None))
        covered = end
    return functions


@dataclass
class _Summary:
    returns: tuple[_Fact, ...] = ()
    effects: dict[tuple[int, str], _Fact] = field(default_factory=dict)
    variadic: int | None = None


@dataclass
class _Flow:
    normal: dict | None
    breaks: list[dict] = field(default_factory=list)
    continues: list[dict] = field(default_factory=list)


class _Analysis:
    def __init__(self, source: str, code: str, rule: str, summaries: dict[str, _Summary]):
        self.source, self.code, self.rule, self.summaries = source, code, rule, summaries
        self.effects = {}
        self.returns: tuple[_Fact, ...] = ()
        self.named_returns = ()

    def effect(self, offset: int, label: str, fact: _Fact):
        if fact:
            key = (offset, label)
            self.effects[key] = _join(self.effects.get(key, _CLEAN), fact)

    def instantiate(self, fact: _Fact, arguments: list[_Fact], name: str) -> _Fact:
        result = []
        for trace in fact:
            if trace.parameter is None:
                result.append(_advance(frozenset({trace}), name + '()'))
            elif trace.parameter < len(arguments):
                bound = _advance(arguments[trace.parameter], name + '()')
                for step in trace.path[1:]:
                    bound = _advance(bound, step)
                result.append(bound)
        return _join(*result)

    def call(self, name: str, expr: str, offset: int, call_offset: int, state, scope) -> tuple[_Fact, ...]:
        arguments = [self.value(expr[start:end], offset + start, state, scope)
                     for start, end in _parts(_masked_source(expr))]
        summary = self.summaries[name]
        if summary.variadic is not None:
            arguments = [*arguments[:summary.variadic], _join(*arguments[summary.variadic:])]
        for (_sink_offset, label), fact in summary.effects.items():
            # Concrete sources are reported at the helper itself. Only an
            # input-dependent sink produces an additional call-site finding.
            dependent = frozenset(trace for trace in fact if trace.parameter is not None)
            self.effect(call_offset, label, self.instantiate(dependent, arguments, name))
        return tuple(self.instantiate(fact, arguments, name) for fact in summary.returns)

    def values(self, expr: str, offset: int, state, scope) -> tuple[_Fact, ...]:
        code = _masked_source(expr)
        parts = _parts(code)
        if len(parts) > 1:
            return tuple(self.value(expr[start:end], offset + start, state, scope) for start, end in parts)
        call = re.match(r'\s*([A-Za-z_]\w*)\s*\(', code)
        if call and call.group(1) in self.summaries and call.group(1) not in scope.bindings:
            end = _pairs(code).get(call.end() - 1)
            if end is not None and not code[end + 1:].strip():
                return self.call(call.group(1), expr[call.end():end], offset + call.end(),
                                 offset + call.start(1), state, scope)
        return (self.value(expr, offset, state, scope),)

    def value(self, expr: str, offset: int, state, scope) -> _Fact:
        code = _masked_source(expr)
        pairs = _pairs(code)
        masked = list(code)
        facts = []

        def cover(start, end):
            for pos in range(start, end):
                masked[pos] = '\n' if code[pos] == '\n' else ' '

        if self.rule == 'go.taint.xss':
            for match in HTML_SANITIZERS.finditer(code):
                package = match.group().split('.')[0]
                if package in scope.bindings or code[:match.start()].rstrip().endswith('.'):
                    continue
                end = pairs.get(match.end() - 1)
                if end is not None and not re.match(r'\s*[.\[]', code[end + 1:]):
                    # Escaping the return cannot undo effects performed while
                    # computing the argument (including local helper sinks).
                    self.value(expr[match.end():end], offset + match.end(), state, scope)
                    cover(match.start(), end + 1)
        for match in re.finditer(r'\bstruct\s*\{', code):
            end = pairs.get(match.end() - 1)
            if end is None:
                continue
            cover(match.start(), end + 1)
            literal = end + 1
            while literal < len(code) and code[literal].isspace():
                literal += 1
            if literal < len(code) and code[literal] == '{' and literal in pairs:
                for start, stop in _parts(code[literal + 1:pairs[literal]]):
                    key = re.match(r'\s*([A-Za-z_]\w*)\s*:', code[literal + 1 + start:literal + 1 + stop])
                    if key:
                        cover(literal + 1 + start + key.start(1), literal + 1 + start + key.end(1))
        # Scan callback bodies in their own scopes, retaining captured values.
        # Their returns only affect this expression for an immediate call.
        for match in re.finditer(r'\bfunc\s*\(', code):
            if masked[match.start()].isspace():
                continue
            param_end = pairs.get(match.end() - 1)
            if param_end is None:
                continue
            opening = _Parser(code).body_open(param_end + 1, len(code))
            if opening is not None and opening in pairs:
                close = pairs[opening]
                parameters = _parameter_names(code[match.end():param_end])
                closure_scope, closure_state = scope.child(), dict(state)
                invocation = close + 1
                while invocation < len(code) and code[invocation].isspace():
                    invocation += 1
                immediate = invocation < len(code) and code[invocation] == '(' and invocation in pairs
                arguments = []
                if immediate:
                    arguments = [self.value(expr[invocation + 1 + start:invocation + 1 + end],
                                            offset + invocation + 1 + start, state, scope)
                                 for start, end in _parts(code[invocation + 1:pairs[invocation]])]
                for index, parameter in enumerate(parameters):
                    if parameter:
                        closure_state[closure_scope.declare(parameter, offset + match.start())] = (
                            arguments[index] if index < len(arguments) else _CLEAN)
                nested = _Analysis(self.source, self.code, self.rule, self.summaries)
                nested.block(_Parser(self.code).block(offset + opening + 1, offset + close),
                             closure_state, closure_scope)
                for (sink_offset, label), fact in nested.effects.items():
                    self.effect(sink_offset, label, fact)
                if immediate:
                    facts.extend(nested.returns)
                    close = pairs[invocation]
                cover(match.start(), close + 1)
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\(', code):
            name = match.group(1)
            end = pairs.get(match.end() - 1)
            if (end is None or masked[match.start()].isspace() or name not in self.summaries
                    or name in scope.bindings):
                continue
            facts.extend(self.call(name, expr[match.end():end], offset + match.end(),
                                   offset + match.start(), state, scope))
            cover(match.start(), end + 1)
        remaining = ''.join(masked)
        for regex, rule, label in SINKS:
            if rule != self.rule:
                continue
            for match in regex.finditer(remaining):
                end = pairs.get(match.end() - 1)
                if end is None:
                    continue
                arg_start = match.end()
                arguments = _parts(code[arg_start:end])
                if rule == 'go.taint.sql':
                    method = match.group().split('.')[-1].split('(')[0].strip()
                    index = 1 if method.endswith('Context') else 0
                    base_method = method.removesuffix('Context')
                    if base_method == 'Get' or method == 'SelectContext':
                        index += 1
                    elif base_method == 'Select' and index < len(arguments):
                        first_start, first_end = arguments[index]
                        if code[arg_start + first_start:arg_start + first_end].lstrip().startswith('&'):
                            index += 1
                    arguments = arguments[index:index + 1]
                elif label == 'fmt.Fprintf' or label == 'template.Execute':
                    arguments = arguments[1:]
                elif rule == 'go.taint.command':
                    if 'CommandContext' in match.group():
                        arguments = arguments[1:]
                    raw_arguments = [expr[arg_start + start:arg_start + stop] for start, stop in arguments]
                    arguments = [arguments[index] for index in _command_arguments(raw_arguments)]
                fact = _join(*(self.value(expr[arg_start + start:arg_start + stop],
                                          offset + arg_start + start, state, scope)
                               for start, stop in arguments))
                self.effect(offset + match.start(), label, fact)
        for regex in SOURCE_PATTERNS:
            for match in regex.finditer(remaining):
                source = match.group()
                facts.append(frozenset({_Trace(source, path=(source,))}))
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)', remaining):
            name = match.group(1)
            facts.append(state.get(scope.bindings.get(name, name), _CLEAN))
        return _join(*facts)

    def simple(self, start: int, end: int, state, scope) -> _Flow:
        code = self.code[start:end]
        keyword = re.match(r'\s*(return|break|continue)\b', code)
        if keyword:
            if keyword.group(1) == 'break':
                return _Flow(None, breaks=[state])
            if keyword.group(1) == 'continue':
                return _Flow(None, continues=[state])
            expr_start = start + keyword.end()
            if self.code[expr_start:end].strip():
                values = self.values(self.source[expr_start:end], expr_start, state, scope)
            else:
                values = tuple(state.get(scope.bindings.get(name, name), _CLEAN) for name in self.named_returns)
            count = max(len(values), len(self.returns))
            self.returns = tuple(_join(self.returns[index] if index < len(self.returns) else _CLEAN,
                                       values[index] if index < len(values) else _CLEAN)
                                 for index in range(count))
            return _Flow(None)
        for pattern in ASSIGN_PATTERNS:
            match = pattern.match(code)
            if match is None:
                continue
            targets = [name.strip() for name in match.group('targets').split(',')]
            expr_start = start + match.start('expr')
            values = self.values(self.source[expr_start:end], expr_start, state, scope)
            declaration = match.group('op') == ':=' or bool(re.match(r'\s*(?:var|const)\b', code))
            updates = {}
            for index, target in enumerate(targets):
                if target == '_':
                    continue
                # Unknown multi-result APIs conservatively taint every result;
                # locally summarized functions retain their result positions.
                fact = values[index] if index < len(values) else values[0] if values else _CLEAN
                key = scope.declare(target, start) if declaration else scope.bindings.get(target, target)
                if match.group('op') == '+=':
                    fact = _join(state.get(key, _CLEAN), fact)
                updates[key] = _advance(fact, target)
            state.update(updates)
            return _Flow(state)
        declaration = re.match(r'\s*var\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+[^=]+$', code)
        if declaration:
            for name in declaration.group(1).split(','):
                state[scope.declare(name.strip(), start)] = _CLEAN
        self.value(self.source[start:end], start, state, scope)
        return _Flow(state)

    def block(self, nodes, state, scope) -> _Flow:
        breaks, continues = [], []
        for node in nodes:
            if state is None:
                break
            flow = self.statement(node, state, scope)
            state = flow.normal
            breaks.extend(flow.breaks)
            continues.extend(flow.continues)
        return _Flow(state, breaks, continues)

    def statement(self, node, state, scope) -> _Flow:
        if node.kind == 'simple':
            return self.simple(node.start, node.end, state, scope)
        if node.kind == 'block':
            return self.block(node.body, state, scope.child())
        control = scope.child()
        header_start = node.start + len(node.kind)
        header = self.code[header_start:node.end]
        parts = _parts(header, ';')
        if node.kind == 'for':
            condition = (header_start, node.end)
            post = None
            if len(parts) == 3:
                first, condition_part, post_part = parts
                self.simple(header_start + first[0], header_start + first[1], state, control)
                condition = (header_start + condition_part[0], header_start + condition_part[1])
                post = (header_start + post_part[0], header_start + post_part[1])
            entry = dict(state)
            head = dict(state)
            exits = []
            while True:
                iteration = dict(head)
                self.simple(*condition, iteration, control)
                flow = self.block(node.body, iteration, control.child())
                exits.extend(flow.breaks)
                back = _join_states(flow.normal, *flow.continues)
                if back is not None and post is not None:
                    self.simple(*post, back, control)
                joined = _join_states(entry, back)
                if joined == head:
                    break
                head = joined
            condition_text = self.code[condition[0]:condition[1]].strip()
            if condition_text not in {'', 'true'}:
                exits.append(head)
            return _Flow(_join_states(*exits))
        if len(parts) > 1:
            first = parts[0]
            self.simple(header_start + first[0], header_start + first[1], state, control)
            header_start += parts[-1][0]
        self.value(self.source[header_start:node.end], header_start, state, control)
        if node.kind == 'if':
            positive = self.block(node.body, dict(state), control.child())
            negative = self.block(node.otherwise, dict(state), control.child())
            return _Flow(_join_states(positive.normal, negative.normal),
                         positive.breaks + negative.breaks, positive.continues + negative.continues)
        branches, continues = [], []
        for case in node.body:
            branch_state = dict(state)
            self.value(self.source[case.start:case.end], case.start, branch_state, control)
            flow = self.block(case.body, branch_state, control.child())
            branches.extend([flow.normal, *flow.breaks])
            continues.extend(flow.continues)
        if not any(case.kind == 'default' for case in node.body):
            branches.append(state)
        return _Flow(_join_states(*branches), continues=continues)


def _summaries(source: str, code: str, functions: list[_Function], parser: _Parser, rule: str):
    summaries = {function.name: _Summary(tuple(_CLEAN for _ in function.results), variadic=function.variadic)
                 for function in functions}
    global_nodes, cursor = [], 0
    for function in functions:
        global_nodes.extend(parser.block(cursor, function.start))
        cursor = function.end
    global_nodes.extend(parser.block(cursor, len(code)))
    globals_scope = _Scope()
    global_analysis = _Analysis(source, code, rule, summaries)
    global_state = {}
    by_name = {function.name: function for function in functions}
    dependents = defaultdict(set)
    for function in functions:
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\(', code[function.start:function.end]):
            if match.group(1) in summaries:
                dependents[match.group(1)].add(function.name)
    for node in global_nodes:
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\(', code[node.start:node.end]):
            if match.group(1) in summaries:
                dependents[match.group(1)].add('@globals')
    pending, queued = deque(['@globals', *summaries]), {'@globals', *summaries}
    while pending:
        name = pending.popleft()
        queued.discard(name)
        if name == '@globals':
            globals_scope = _Scope()
            global_analysis = _Analysis(source, code, rule, summaries)
            updated = global_analysis.block(global_nodes, {}, globals_scope).normal or {}
            if updated != global_state:
                global_state = updated
                for caller in summaries:
                    if caller not in queued:
                        pending.append(caller)
                        queued.add(caller)
            continue
        function = by_name[name]
        analysis = _Analysis(source, code, rule, summaries)
        state, scope = dict(global_state), globals_scope.child()
        for index, parameter in enumerate(function.parameters):
            if parameter and parameter != '_':
                key = scope.declare(parameter, function.start)
                state[key] = frozenset({_Trace(parameter, index, (parameter,))})
        for result in function.results:
            if result:
                state[scope.declare(result, function.start)] = _CLEAN
        analysis.named_returns = function.results
        analysis.block(function.body, state, scope)
        summary = _Summary(analysis.returns, analysis.effects, function.variadic)
        if summary != summaries[name]:
            summaries[name] = summary
            for caller in sorted(dependents[name]):
                if caller not in queued:
                    pending.append(caller)
                    queued.add(caller)
    return summaries, global_analysis.effects


def iter_file_hits(path: Path, base_dir: Path):
    """Yield every concrete source-to-sink flow without truncating findings."""
    try:
        source = path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return
    source = _masked_source(source, strings=False)
    code = _masked_source(source)
    parser = _Parser(code)
    functions = _functions(code, parser)
    line_starts = [0] + [match.end() for match in re.finditer('\n', code)]
    hits = {}
    for rule in dict.fromkeys(rule for _regex, rule, _label in SINKS):
        summaries, globals_effects = _summaries(source, code, functions, parser, rule)
        for effects in [globals_effects, *(summary.effects for summary in summaries.values())]:
            for (offset, label), fact in effects.items():
                concrete = [trace for trace in fact if trace.parameter is None]
                if not concrete:
                    continue
                trace = min(concrete, key=lambda trace: (len(trace.path), trace.path, trace.source))
                path_desc = ' -> '.join(next(iter(_advance(frozenset({trace}), label))).path)
                hits[(offset, rule)] = path_desc
    try:
        rel = str(path.relative_to(base_dir))
    except ValueError:
        rel = path.name
    for (offset, rule), path_desc in sorted(hits.items()):
        line = bisect_right(line_starts, offset)
        yield rule, rel, line, offset - line_starts[line - 1] + 1, path_desc


def main() -> int:
    import sys

    root = Path(sys.argv[1]).resolve()
    base_dir = root if root.is_dir() else root.parent
    issues: dict[str, dict] = defaultdict(lambda: {'count': 0, 'samples': []})
    for file_path in iter_files(root):
        for rule, rel, line, _col, path_desc in iter_file_hits(file_path, base_dir):
            sample = f"{rel}:{line} {path_desc}"
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(sample)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    return 0


_SEVERITY = {
    'go.taint.xss': 'critical',
    'go.taint.sql': 'critical',
    'go.taint.command': 'critical',
}

_MESSAGE = {
    'go.taint.xss': 'User input flows into fmt.Fprintf/template Execute/ResponseWriter.Write',
    'go.taint.sql': 'User input concatenated into SQL execution/query-builder strings',
    'go.taint.command': 'User input reaches exec.Command/CommandContext',
}


def run(ctx: RunContext) -> Iterable[dict]:
    base_dir = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        for rule, _rel, line, col, path_desc in iter_file_hits(path, base_dir):
            yield {
                "rule": rule,
                "path": str(path.resolve()),
                "line": line,
                "col": col,
                "severity": _SEVERITY[rule],
                "message": f"{_MESSAGE[rule]} ({path_desc})",
            }


def _write_go(tmp_dir: Path, body: str) -> Path:
    path = tmp_dir / "main.go"
    path.write_text("package main\n\n" + body, encoding="utf-8")
    return path


def _selftest_xss_positive() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"fmt\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "\tname := r.FormValue(\"name\")\n"
        "\tfmt.Fprintf(w, \"hello \"+name)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        ctx = RunContext(lang="go", files=[path])
        findings = [f for f in run(ctx) if f["rule"] == "go.taint.xss"]
        assert len(findings) == 1, findings
        assert findings[0]["line"] == 10, findings[0]
        assert findings[0]["severity"] == "critical"
        assert findings[0]["path"] == str(path.resolve())
        assert "name" in findings[0]["message"]


def _selftest_sanitizer_suppresses() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"fmt\"\n"
        "\t\"html\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "\tname := r.FormValue(\"name\")\n"
        "\tfmt.Fprintf(w, \"hello \"+html.EscapeString(name))\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = list(run(RunContext(lang="go", files=[path])))
        assert findings == [], findings


def _selftest_parameterized_sql_suppressed() -> None:
    import tempfile

    code = (
        "import (\n"
        "\t\"database/sql\"\n"
        "\t\"net/http\"\n"
        ")\n"
        "\n"
        "func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {\n"
        "\tq := r.URL.Query().Get(\"q\")\n"
        "\trows, err := db.Query(\"SELECT * FROM users WHERE name = ?\", q)\n"
        "\t_ = rows\n"
        "\t_ = err\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = [f for f in run(RunContext(lang="go", files=[path])) if f["rule"] == "go.taint.sql"]
        assert findings == [], findings


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("xss_positive", _selftest_xss_positive),
    ("sanitizer_suppresses", _selftest_sanitizer_suppresses),
    ("parameterized_sql_suppressed", _selftest_parameterized_sql_suppressed),
)

register(Analyzer(layer="taint", lang="go", name="taint_go", run=run, selftests=SELF_TESTS))
