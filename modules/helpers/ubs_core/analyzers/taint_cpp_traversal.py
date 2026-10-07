"""Bounded, function-scoped C/C++ request-path dataflow.

The redirect frontend shares this C/C++ parser and finite dataflow engine.
Selected same-file functions, scalar assignments and structured branches carry
actual values and sink-specific proof. Unknown calls preserve dependencies but
invalidate proof; unmodeled preprocessor, heap and control-flow effects report
incomplete analysis instead of being interpreted as a clean result.
"""
from __future__ import annotations

import re
import sys
import json
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import (AnalysisLimit, Budget, CLEAN, Fact, Step, Trace,
                                 advance, join, join_states, retag, solve, substitute)

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getPath|getPathInfo|path|target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:path|target|raw_url|url)\b'
    r'|\b(?:cgiFormString|FCGX_GetParam)\s*\('
    r'|\b(?:std::)?getenv\s*\(\s*"(?:QUERY_STRING|PATH_INFO|REQUEST_URI|SCRIPT_NAME|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:filename|file_name|original_filename|client_filename|getOriginalFilename)\s*(?:\(\s*\))?\b'
)
SINK_RE = re.compile(
    r'\b(?:std::)?(?:ifstream|ofstream|fstream)\s+[A-Za-z_][A-Za-z0-9_]*\s*\('
    r'|\b(?:fopen|freopen|open|openat|creat|remove|unlink|rename|mkdir|mkdirat)\s*\('
    r'|\b(?:std::filesystem::|filesystem::|fs::)(?:remove|remove_all|copy_file|rename|create_directories|permissions|exists|file_size)\s*\('
    r'|\b(?:send_file|sendfile|serve_file|serveFile|set_file_content|set_static_file_info|write_file_response)\s*\('
)

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

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int
    literal: bool = False


@dataclass(frozen=True)
class Statement:
    start: int
    end: int
    kind: str = 'simple'
    body: tuple = ()
    otherwise: tuple = ()
    header: tuple = (0, 0)


@dataclass
class Function:
    key: int
    name: str
    owner: tuple
    parameters: tuple
    declarations: tuple
    body: tuple
    end: int


@dataclass
class Summary:
    returned: Fact = CLEAN
    effects: dict = field(default_factory=dict)
    escapes: dict = field(default_factory=dict)
    mutations: dict = field(default_factory=dict)
    globals: dict = field(default_factory=dict)


class Parser:
    """Offset-preserving C/C++ lexical subset; no implicit macro expansion."""

    def __init__(self, text):
        self.text, self.tokens, self.macros = text, [], {}
        self.conditional = False
        index = 0
        while index < len(text):
            if len(self.tokens) > 200_000:
                raise AnalysisLimit('C/C++ token limit exceeded; analysis is incomplete')
            if text[index].isspace():
                index += 1
                continue
            if text.startswith('//', index):
                finish = text.find('\n', index + 2)
                index = len(text) if finish < 0 else finish
                continue
            if text.startswith('/*', index):
                finish = text.find('*/', index + 2)
                if finish < 0:
                    raise ValueError('Unterminated C/C++ comment; analysis is incomplete')
                index = finish + 2
                continue
            if text[index] == '#' and not text[text.rfind('\n', 0, index) + 1:index].strip():
                finish = text.find('\n', index)
                finish = len(text) if finish < 0 else finish
                while finish < len(text) and text[index:finish].rstrip().endswith('\\'):
                    following = text.find('\n', finish + 1)
                    finish = len(text) if following < 0 else following
                directive = text[index:finish]
                macro = re.match(r'#\s*define\s+([A-Za-z_]\w*)(?:\(([A-Za-z_]\w*)\))?\s*(.*)', directive, re.DOTALL)
                if macro:
                    name, parameter, body = macro.groups()
                    identity = bool(parameter and re.fullmatch(r'\s*\(*\s*' + re.escape(parameter) + r'\s*\)*\s*', body)
                        and body.count('(') == body.count(')'))
                    self.macros.setdefault(name, []).append((index, parameter, identity))
                elif undefine := re.match(r'#\s*undef\s+([A-Za-z_]\w*)', directive):
                    self.macros.setdefault(undefine.group(1), []).append((index, None, None))
                elif re.match(r'#\s*(?:if|ifdef|ifndef|elif|else)\b', directive):
                    self.conditional = True
                index = finish
                continue
            raw = re.match(r'(?:u8|u|U|L)?R"([^ ()\\\t\r\n]{0,16})\(', text[index:])
            if raw:
                closing = ')' + raw.group(1) + '"'
                finish = text.find(closing, index + raw.end())
                if finish < 0:
                    raise ValueError('Unterminated C++ raw string; analysis is incomplete')
                finish += len(closing)
                self.tokens.append(Token(text[index:finish], index, finish, True))
                index = finish
                continue
            quoted = re.match(r'(?:u8|u|U|L)?(["\'])', text[index:])
            if quoted:
                quote, finish = quoted.group(1), index + quoted.end()
                while finish < len(text) and text[finish] != quote:
                    if text[finish] in '\r\n':
                        raise ValueError('Unterminated C/C++ literal; analysis is incomplete')
                    finish += 2 if text[finish] == '\\' else 1
                if finish >= len(text):
                    raise ValueError('Unterminated C/C++ literal; analysis is incomplete')
                finish += 1
                self.tokens.append(Token(text[index:finish], index, finish, True))
                index = finish
                continue
            match = re.match(r'[A-Za-z_]\w*|[0-9]+(?:[A-Za-z0-9_.]*)|::|->|\+\+|--|&&|\|\||==|!=|<=|>=|\+=|-=|\*=|/=|<<|>>|.', text[index:])
            finish = index + match.end()
            self.tokens.append(Token(match.group(), index, finish))
            index = finish
        self.pairs, self.reverse = {}, {}
        stack = []
        for index, token in enumerate(self.tokens):
            if token.literal:
                continue
            if token.value in {'(', '[', '{'}:
                stack.append(index)
            elif token.value in {')', ']', '}'}:
                if not stack or self.tokens[stack[-1]].value != {')': '(', ']': '[', '}': '{'}[token.value]:
                    raise ValueError('Unbalanced C/C++ source; analysis is incomplete')
                opening = stack.pop()
                self.pairs[opening], self.reverse[index] = index, opening
        if stack:
            raise ValueError('Unbalanced C/C++ source; analysis is incomplete')
        self.functions = {}
        script = self.definitions(0, len(self.tokens), ())
        if script:
            self.functions[-1] = Function(-1, '<global>', (), (), (), script, len(self.tokens))
        self.globals = {assignment[0] for statement in script
                        if (assignment := self.assignment(statement.start, statement.end))}

    def value(self, index):
        return self.tokens[index].value if 0 <= index < len(self.tokens) else ''

    def macro_at(self, name, token):
        offset = self.tokens[token].start
        active = [entry for entry in self.macros.get(name, ()) if entry[0] < offset]
        return active[-1][1:] if active and active[-1][2] is not None else None

    def raw(self, start, end):
        return self.text[self.tokens[start].start:self.tokens[end - 1].end] if start < end else ''

    def compact(self, start, end):
        return ''.join(token.value for token in self.tokens[start:end])

    def parts(self, start, end, separator=','):
        beginning = start
        while start < end:
            if start in self.pairs:
                start = self.pairs[start]
            elif self.value(start) == separator:
                yield beginning, start
                beginning = start + 1
            start += 1
        if beginning < end:
            yield beginning, end

    def definitions(self, start, end, owner):
        script = []
        while start < end:
            if self.value(start) == ';':
                start += 1
                continue
            cursor = start
            while cursor < end and self.value(cursor) not in {';', '{'}:
                if self.value(cursor) in {'(', '['}:
                    cursor = self.pairs[cursor]
                cursor += 1
            if cursor >= end:
                if not owner:
                    script.append(Statement(start, end))
                break
            if self.value(cursor) == ';':
                if not owner:
                    opening = next((i for i in range(start, cursor) if self.value(i) == '('), cursor)
                    prefix = self.raw(start, opening)
                    is_prototype = (self.value(cursor - 1) == ')' and bool(re.match(
                        r'(?:extern\s+)?(?:void|bool|int|long|short|double|float|char)\s+\**\s*[A-Za-z_]\w*\s*$', prefix)))
                    script.append(Statement(start, cursor, 'definition' if is_prototype else 'simple'))
                start = cursor + 1
                continue
            finish = self.pairs[cursor]
            header = [token.value for token in self.tokens[start:cursor]]
            if header and header[0] in {'namespace', 'class', 'struct', 'union', 'enum'}:
                name = header[1] if len(header) > 1 else '<anonymous>'
                self.definitions(cursor + 1, finish, (*owner, name))
            else:
                closing = next((i for i in range(cursor - 1, start - 1, -1) if self.value(i) == ')'), None)
                opening = self.reverse.get(closing, -1)
                name_index = opening - 1
                if opening >= start and re.fullmatch(r'[A-Za-z_]\w*', self.value(name_index)):
                    name = self.value(name_index)
                    if name in {'if', 'while', 'for', 'switch', 'catch'}:
                        raise ValueError('C/C++ control flow outside a selected function; analysis is incomplete')
                    declarations = tuple(self.raw(low, high) for low, high in self.parts(opening + 1, closing))
                    if declarations == ('void',):
                        declarations = ()
                    parameters = []
                    for declaration in declarations:
                        identifiers = re.findall(r'[A-Za-z_]\w*', declaration.split('=', 1)[0])
                        if not identifiers or '...' in declaration:
                            raise ValueError('Unsupported C/C++ parameter declaration; analysis is incomplete')
                        parameters.append(identifiers[-1])
                    selected_owner = list(owner)
                    qualifier = name_index - 1
                    prefix = []
                    while qualifier >= start + 1 and self.value(qualifier) == '::':
                        prefix.insert(0, self.value(qualifier - 1))
                        qualifier -= 2
                    if prefix:
                        selected_owner = prefix
                    self.functions[name_index] = Function(name_index, name, tuple(selected_owner),
                        tuple(parameters), declarations, self.block(cursor + 1, finish), finish)
                elif not owner:
                    following = finish + 1
                    if self.value(following) == ';':
                        following += 1
                    script.append(Statement(start, following))
            start = finish + 1
        return tuple(script)

    def block(self, start, end):
        statements = []
        while start < end:
            if self.value(start) == ';':
                start += 1
                continue
            statement, following = self.statement(start, end)
            if following <= start:
                raise ValueError('C/C++ parser made no progress; analysis is incomplete')
            statements.append(statement)
            start = following
        return tuple(statements)

    def statement(self, start, end):
        word = self.value(start)
        if word == '{':
            close = self.pairs[start]
            return Statement(start, close + 1, 'block', self.block(start + 1, close)), close + 1
        if word in {'if', 'while', 'for'} and self.value(start + 1) == '(':
            if start + 1 >= end:
                raise ValueError('C/C++ condition exceeds its enclosing block; analysis is incomplete')
            close = self.pairs[start + 1]
            body, following = self.statement(close + 1, end)
            otherwise = ()
            if word == 'if' and self.value(following) == 'else':
                alternate, following = self.statement(following + 1, end)
                otherwise = alternate.body if alternate.kind == 'block' else (alternate,)
            return Statement(start, following, word,
                body.body if body.kind == 'block' else (body,), otherwise, (start + 2, close)), following
        if word == 'do':
            body, following = self.statement(start + 1, end)
            if following + 1 >= end:
                raise ValueError('C/C++ do/while exceeds its enclosing block; analysis is incomplete')
            if self.value(following) != 'while' or self.value(following + 1) != '(':
                raise ValueError('Malformed C/C++ do/while; analysis is incomplete')
            close = self.pairs[following + 1]
            return Statement(start, close + 1, 'do',
                body.body if body.kind == 'block' else (body,), header=(following + 2, close)), close + 1
        if word in {'switch', 'goto', 'try', 'catch', 'co_await', 'co_yield', 'co_return'}:
            raise ValueError('Unsupported C/C++ control flow; analysis is incomplete')
        cursor = start
        while cursor < end and self.value(cursor) not in {';', '}'}:
            if cursor in self.pairs:
                if self.value(cursor) == '{' and any(self.value(i) == ']' for i in range(start, cursor)):
                    raise ValueError('C++ executable lambda needs capture analysis; analysis is incomplete')
                cursor = self.pairs[cursor]
            cursor += 1
        kind = word if word in {'return', 'throw', 'break', 'continue'} else 'simple'
        return Statement(start, cursor, kind), cursor + (self.value(cursor) == ';')

    def assignment(self, start, end):
        for low, high in self.parts(start, end, '='):
            if high == end:
                break
            lhs = self.tokens[start:high]
            if not lhs:
                return None
            name = lhs[-1].value
            if not re.fullmatch(r'[A-Za-z_]\w*', name):
                return None
            if len(lhs) > 1 and lhs[-2].value in {'.', '->', '::'}:
                return None
            declaration = len(lhs) > 1
            if declaration and (lhs[0].value in {'*', '&'} or any(t.value in {'(', '['} for t in lhs)):
                return None
            return name, high - 1, high + 1, end, '=', declaration
        if start + 1 < end and self.value(start + 1) in {'+=', '/=', '-=', '*='}:
            return self.value(start), start, start + 2, end, self.value(start + 1), False
        return None


PROOF_TAGS = frozenset({'contained', 'canonical', 'basename', 'url-slash', 'url-not-network',
    'url-no-backslash', 'url-no-cr', 'url-no-lf', 'url-no-tab', 'url-constant', 'url-https', 'url-host'})


class Engine:
    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label = 'file sink'
    rule = 'cpp.taint.path_traversal'

    def __init__(self, path, text):
        self.path, self.text = path, text
        self.parser = Parser(text)
        self.budget = Budget()
        self.lines = [0] + [m.end() for m in re.finditer('\n', text)]
        self.summaries = {key: Summary() for key in self.parser.functions}
        self.graphs = {}
        self.alias_declarations = set()
        self.unsupported_references = set()
        self.suppressions = SourceSuppressions('cpp')

    def step(self, token, kind, label):
        offset = self.parser.tokens[token].start if 0 <= token < len(self.parser.tokens) else len(self.text)
        line = bisect_right(self.lines, offset)
        if line < 1 or line > len(self.lines):
            raise ValueError('C/C++ source location is outside its line table; analysis is incomplete')
        return Step(str(self.path.resolve()), line, offset - self.lines[line - 1] + 1, kind, label)

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path.resolve()), offset),
            frozenset({'string'}), evidence=(self.step(offset, 'source', label),))})

    def without_proof(self, value):
        # Relations describe one exact representation of a value. Carrying
        # their hidden identity through a transform would let checks of the
        # transformed result discharge a different, original sink operand.
        value = frozenset(trace for trace in value if trace.kind not in
            {'relation', 'host', 'host-end', 'allowlist'})
        return retag(value, remove=PROOF_TAGS | frozenset(
            tag for trace in value for tag in trace.tags if tag.startswith('relative-')))

    def record(self, offset, value, file_leaf=False):
        if file_leaf:
            value = retag(value, add=frozenset({'file-leaf'}))
        value = frozenset(trace for trace in value if trace.kind in {'source', 'parameter'})
        if value:
            self.effects[offset] = join(self.effects.get(offset, CLEAN),
                advance(value, self.step(offset, 'sink', self.sink_label)))

    def safe(self, trace):
        return 'contained' in trace.tags or {'basename', 'file-leaf'} <= trace.tags

    @staticmethod
    def fingerprint(value):
        return tuple(sorted((trace.kind, trace.key, tuple(sorted(trace.tags))) for trace in value))

    def path_value(self, value, offset, *tags):
        value = value or frozenset({Trace('value', (offset,))})
        return retag(value, add=frozenset({'path', *tags}))

    def literal(self, start, end):
        if start + 1 != end or not self.parser.tokens[start].literal:
            return None
        raw = self.parser.value(start)
        if raw.startswith("'") and raw.endswith("'"):
            raw = '"' + raw[1:-1].replace('"', '\\"') + '"'
        if not raw.startswith('"'):
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return None
        return value if isinstance(value, str) else None

    def selected(self, name, arity):
        if '.' in name or '->' in name:
            return []
        pieces = name.split('::')
        owners = [tuple(pieces[:-1])] if len(pieces) > 1 else [
            self.function.owner[:index] for index in range(len(self.function.owner), -1, -1)]
        for owner in owners:
            candidates = [function for function in self.parser.functions.values()
                if function.name == pieces[-1] and function.owner == owner and len(function.parameters) == arity]
            if candidates:
                return candidates
        return []

    def call_sink(self, name, spans, arguments, offset, receiver=CLEAN):
        method = re.split(r'::|\.|->', name)[-1]
        targets = []
        file_leaf = False
        if method in {'fopen', 'freopen', 'open', 'creat', 'unlink', 'remove', 'mkdir',
                      'send_file', 'sendfile', 'serve_file', 'serveFile', 'set_file_content',
                      'set_static_file_info', 'write_file_response'}:
            targets = [0]
            file_leaf = method in {'fopen', 'freopen', 'creat'}
        elif method in {'openat', 'mkdirat'}:
            targets = [1]
        elif method == 'rename':
            targets = [0, 1]
        if re.match(r'(?:std::filesystem|filesystem|fs)::', name):
            if method in {'remove_all', 'create_directories', 'permissions', 'exists', 'file_size'}:
                targets = [0]
            elif method in {'copy_file', 'rename'}:
                targets = [0, 1]
                file_leaf = method == 'copy_file'
        for index in targets:
            if index < len(arguments):
                self.record(offset, arguments[index], file_leaf)

    def external_call(self, name, spans, arguments, receiver, offset, state, bindings):
        method = re.split(r'::|\.|->', name)[-1]
        macro = self.parser.macro_at(method, offset)
        if macro is not None:
            if macro[1] and len(arguments) == 1:
                return arguments[0]
            raise ValueError('C/C++ macro invocation needs preprocessing; analysis is incomplete')
        if name == 'cgiFormString' and len(spans) >= 2:
            target = self.parser.compact(*spans[1]).lstrip('&')
            value = self.source(offset, 'cgiFormString')
            if re.fullmatch(r'[A-Za-z_]\w*', target):
                binding = bindings.get(target, target)
                state[binding] = value
                self.note_mutation(binding)
            else:
                self.escapes[offset] = join(self.escapes.get(offset, CLEAN), value)
            # The request text is written through argument two; the integer
            # status result is not that text.
            return CLEAN
        raw = self.parser.raw(offset, self.parser.pairs.get(
            next((i for i in range(offset, len(self.parser.tokens)) if self.parser.value(i) == '('), offset), offset) + 1)
        source = self.source_re.search(raw)
        if source and source.start() == 0:
            return self.source(offset, source.group().strip().rstrip('('))
        value = join(receiver, *arguments)
        if re.fullmatch(r'(?:std::filesystem|filesystem|fs)::path', name):
            return self.path_value(join(*arguments), offset)
        if re.fullmatch(r'(?:std::filesystem|filesystem|fs)::(?:canonical|weakly_canonical)', name):
            return self.path_value(self.without_proof(arguments[0] if arguments else CLEAN), offset, 'canonical')
        if method in {'string', 'native', 'c_str'} and not arguments:
            return receiver
        if method == 'filename' and not arguments and any('path' in trace.tags for trace in receiver):
            return self.path_value(self.without_proof(receiver), offset, 'basename')
        if method == 'lexically_normal' and not arguments and any('path' in trace.tags for trace in receiver):
            return self.path_value(self.without_proof(receiver), offset)
        if method in {'relative', 'lexically_relative'}:
            relation = self.relative_relation(name, spans, arguments, receiver, offset, state, bindings)
            if relation:
                return join(self.without_proof(value), frozenset({relation}))
        if method in {'assign', 'append', 'clear', 'replace', 'push_back', 'operator='} and receiver:
            root = re.split(r'\.|->', name)[0]
            if root in bindings:
                value = CLEAN if method == 'clear' else join(*arguments) if method == 'assign' else value
                value = self.without_proof(value)
                state[bindings[root]] = value
                self.note_mutation(bindings[root])
        return self.without_proof(value)

    def relative_relation(self, name, spans, arguments, receiver, offset, state, bindings):
        if name.endswith('.lexically_relative') and len(spans) == 1:
            target_name = name.split('.', 1)[0]
            base_name = self.parser.compact(*spans[0])
        elif re.fullmatch(r'(?:std::filesystem|filesystem|fs)::relative', name) and len(spans) == 2:
            target_name, base_name = (self.parser.compact(*span) for span in spans)
        else:
            return None
        if target_name not in bindings or base_name not in bindings:
            return None
        target, base = bindings[target_name], bindings[base_name]
        target_value, base_value = state.get(target, CLEAN), state.get(base, CLEAN)
        if not target_value or not all('canonical' in trace.tags for trace in target_value):
            return None
        if not base_value or not all('canonical' in trace.tags for trace in base_value):
            return None
        return Trace('relation', ('relative', target, self.fingerprint(target_value), base,
            self.fingerprint(base_value)), frozenset({'relative-value', 'relative-not-absolute'}))

    def expression(self, start, end, state, bindings, depth=0):
        self.budget.spend()
        if depth > 64:
            raise AnalysisLimit('C/C++ expression depth exceeded; analysis is incomplete')
        while start < end and self.parser.value(start) == '(' and self.parser.pairs[start] == end - 1:
            start, end = start + 1, end - 1
        if start >= end:
            return CLEAN
        literal = self.literal(start, end)
        if literal is not None:
            return frozenset({Trace('constant', (literal,), frozenset({'string'}))})
        assignment = self.parser.assignment(start, end)
        if assignment and not assignment[-1]:
            name, offset, low, high, operator, _ = assignment
            value = self.expression(low, high, state, bindings, depth + 1)
            binding = bindings.get(name, name)
            if operator != '=':
                value = self.without_proof(join(state.get(binding, CLEAN), value))
            value = advance(value, self.step(offset, 'assign', name))
            value = retag(value, remove=frozenset(tag for trace in value for tag in trace.tags
                if tag.startswith('binding-version:')), add=frozenset({'binding-version:' + str(offset)}))
            state[binding] = value
            self.note_mutation(binding)
            if (binding in self.unsupported_references or
                    binding.startswith('global:') and self.function.key != -1):
                self.escapes[offset] = join(self.escapes.get(offset, CLEAN), value)
            return value
        top = list(self.top_tokens(start, end))
        question = next((i for i in top if self.parser.value(i) == '?'), None)
        if question is not None:
            colon = next((i for i in top if i > question and self.parser.value(i) == ':'), None)
            if colon is None:
                raise ValueError('Malformed C/C++ conditional expression; analysis is incomplete')
            self.expression(start, question, state, bindings, depth + 1)
            yes, no = dict(state), dict(state)
            for truth, guard in self.guard_facts(start, question):
                self.apply_guard(guard, yes if truth else no, bindings)
            left = self.expression(question + 1, colon, yes, bindings, depth + 1)
            right = self.expression(colon + 1, end, no, bindings, depth + 1)
            state.clear()
            state.update(join_states(yes, no))
            return join(left, right)
        for operator in ('||', '&&', '==', '!=', '+', '/', '-', '*'):
            positions = [i for i in top if self.parser.value(i) == operator and i > start]
            if positions:
                split = positions[-1]
                left = self.expression(start, split, state, bindings, depth + 1)
                if operator in {'&&', '||'}:
                    skipped, evaluated = dict(state), dict(state)
                    for truth, guard in self.guard_facts(start, split):
                        self.apply_guard(guard, evaluated if truth == (operator == '&&') else skipped, bindings)
                    right = self.expression(split + 1, end, evaluated, bindings, depth + 1)
                    state.clear()
                    state.update(join_states(skipped, evaluated))
                    return self.without_proof(join(left, right))
                right = self.expression(split + 1, end, state, bindings, depth + 1)
                if operator == '/' and any('path' in trace.tags for trace in join(left, right)):
                    return self.path_value(join(self.without_proof(left),
                        retag(right, remove=PROOF_TAGS - frozenset({'basename'}))), split)
                return self.without_proof(join(left, right))
        value, cursor = CLEAN, start
        while cursor < end:
            token = self.parser.tokens[cursor]
            if token.literal:
                cursor += 1
                continue
            if self.parser.value(cursor) in {'(', '{', '['}:
                close = self.parser.pairs[cursor]
                if self.parser.value(cursor) == '[':
                    following = close + 1
                    if self.parser.value(following) == '(':
                        following = self.parser.pairs[following] + 1
                    if self.parser.value(following) in {'{', 'mutable', '->'}:
                        raise ValueError('C++ lambda requires capture/callback analysis; analysis is incomplete')
                value = join(value, self.expression(cursor + 1, close, state, bindings, depth + 1))
                cursor = close + 1
                continue
            if not re.fullmatch(r'[A-Za-z_]\w*', token.value):
                cursor += 1
                continue
            offset, name = cursor, token.value
            cursor += 1
            while cursor + 1 < end and self.parser.value(cursor) in {'::', '.', '->'} and re.fullmatch(
                    r'[A-Za-z_]\w*', self.parser.value(cursor + 1)):
                name += self.parser.value(cursor) + self.parser.value(cursor + 1)
                cursor += 2
            root = re.split(r'::|\.|->', name)[0]
            atom = state.get(bindings.get(root, root), CLEAN)
            if cursor < end and self.parser.value(cursor) == '(':
                close = self.parser.pairs[cursor]
                spans = list(self.parser.parts(cursor + 1, close))
                arguments = [self.expression(low, high, state, bindings, depth + 1) for low, high in spans]
                selected = self.selected(name, len(arguments)) if (
                    name not in bindings and self.parser.macro_at(re.split(r'::|\.|->', name)[-1], offset) is None) else []
                if selected:
                    returned = CLEAN
                    for function in selected:
                        bound = {(function.key, i): argument for i, argument in enumerate(arguments)}
                        summary, call = self.summaries[function.key], self.step(offset, 'call', name + '()')
                        returned = join(returned, substitute(summary.returned, bound, call))
                        for site, fact in summary.effects.items():
                            self.effects[site] = join(self.effects.get(site, CLEAN), substitute(fact, bound, call))
                        for site, fact in summary.escapes.items():
                            self.escapes[site] = join(self.escapes.get(site, CLEAN), substitute(fact, bound, call))
                        for index, fact in summary.mutations.items():
                            actual = self.parser.compact(*spans[index])
                            if actual not in bindings:
                                self.escapes[offset] = join(self.escapes.get(offset, CLEAN), *arguments)
                                continue
                            binding = bindings[actual]
                            updated = substitute(fact, bound, call)
                            state[binding] = updated if len(selected) == 1 else join(state.get(binding, CLEAN), updated)
                            self.note_mutation(binding)
                    atom = returned
                else:
                    self.call_sink(name, spans, arguments, offset, atom)
                    atom = self.external_call(name, spans, arguments, atom, offset, state, bindings)
                cursor = close + 1
            elif self.source_re.search(name):
                source = self.source_re.search(name)
                atom = join(atom, self.source(offset, source.group().strip().rstrip('(')))
            elif (macro := self.parser.macro_at(name, offset)) is not None and macro[0] is None:
                raise ValueError('C/C++ object macro needs preprocessing; analysis is incomplete')
            while cursor + 1 < end and self.parser.value(cursor) in {'.', '->'}:
                method_offset, method = cursor, self.parser.value(cursor + 1)
                cursor += 2
                if self.parser.value(cursor) != '(':
                    atom = self.without_proof(atom)
                    continue
                close = self.parser.pairs[cursor]
                spans = list(self.parser.parts(cursor + 1, close))
                arguments = [self.expression(low, high, state, bindings, depth + 1) for low, high in spans]
                self.call_sink('.' + method, spans, arguments, method_offset, atom)
                if name == 'QUrlQuery' and method == 'queryItemValue':
                    atom = self.source(offset, 'QUrlQuery.queryItemValue')
                else:
                    atom = self.external_call('.' + method, spans, arguments, atom, method_offset, state, bindings)
                cursor = close + 1
            value = join(value, atom)
        return value

    def top_tokens(self, start, end):
        while start < end:
            yield start
            start = self.parser.pairs[start] + 1 if start in self.parser.pairs else start + 1

    def guard_facts(self, start, end):
        while self.parser.value(start) == '(' and self.parser.pairs.get(start) == end - 1:
            start, end = start + 1, end - 1
        for operator, truth in (('||', False), ('&&', True)):
            parts = list(self.parser.parts(start, end, operator))
            if len(parts) > 1:
                guards = [self.guard_facts(low, high) for low, high in parts]
                result = [(truth, guard) for item in guards for positive, guard in item if positive == truth]
                common = set(guard for positive, guard in guards[0] if positive != truth)
                for item in guards[1:]:
                    common &= {guard for positive, guard in item if positive != truth}
                result.extend((not truth, guard) for guard in sorted(common))
                return result
        if self.parser.value(start) == '!':
            return [(not truth, guard) for truth, guard in self.guard_facts(start + 1, end)]
        return self.atomic_guard(start, end)

    def atomic_guard(self, start, end):
        raw = self.parser.compact(start, end)
        check = re.fullmatch(r'([A-Za-z_]\w*)\.(empty|is_absolute)\(\)', raw)
        if check:
            return [(False, (check.group(1), 'relative-nonempty' if check.group(2) == 'empty' else 'relative-not-absolute'))]
        check = re.fullmatch(r'\*([A-Za-z_]\w*)\.begin\(\)(==|!=)"\.\."', raw)
        if check:
            return [(check.group(2) == '!=', (check.group(1), 'relative-not-parent'))]
        check = re.fullmatch(r'([A-Za-z_]\w*)\.(?:native|string)\(\)\.starts_with\("\.\."\)', raw)
        if check:
            return [(False, (check.group(1), 'relative-not-parent'))]
        return []

    def apply_guard(self, guard, state, bindings):
        name, tag = guard
        binding = bindings.get(name, name)
        original = state.get(binding, CLEAN)
        state[binding] = retag(original, add=frozenset({tag}))
        required = {'relative-nonempty', 'relative-not-absolute', 'relative-not-parent'}
        for trace in state[binding]:
            if trace.kind != 'relation' or trace.key[0] != 'relative':
                continue
            if not required <= trace.tags:
                continue
            _, target, target_identity, base, base_identity = trace.key
            target_value, base_value = state.get(target, CLEAN), state.get(base, CLEAN)
            if self.fingerprint(target_value) != target_identity or self.fingerprint(base_value) != base_identity:
                continue
            roots = {(value.kind, value.key) for value in base_value}
            state[target] = join(*(retag(frozenset({value}), add=frozenset({'contained'}))
                if (value.kind, value.key) not in roots else frozenset({value}) for value in target_value))
        return state

    def note_mutation(self, binding):
        if binding.startswith('param:'):
            index = int(binding.split(':', 1)[1])
            declaration = self.function.declarations[index]
            if '&' in declaration and not re.search(r'\bconst\b', declaration):
                self.mutated.add(index)

    def assigned_value(self, start, offset, low, high, value, state, bindings):
        return value

    def graph(self, function):
        actions, edges = {}, {}
        scope = {name: 'global:' + name for name in self.parser.globals}
        scope.update({name: 'param:' + str(i) for i, name in enumerate(function.parameters)})

        def node(kind, span, bindings, targets=(), guard=None, reads=None):
            self.budget.spend()
            key = len(actions)
            actions[key] = kind, span, dict(bindings), guard, dict(bindings if reads is None else reads)
            edges[key] = tuple(targets)
            return key

        exit_node = node('exit', (function.end, function.end), scope)

        def block(statements, following, bindings, break_to=None, continue_to=None):
            snapshots = []
            for statement in statements:
                reads = dict(bindings)
                assignment = self.parser.assignment(statement.start, statement.end) if statement.kind == 'simple' else None
                if assignment and assignment[-1]:
                    name, offset, low, high, _, _ = assignment
                    declared = self.parser.compact(statement.start, offset)
                    target = self.parser.compact(low, high)
                    if '&' in declared and '&&' not in declared and target in reads:
                        bindings[name] = reads[target]
                        self.alias_declarations.add(offset)
                    else:
                        bindings[name] = ('global:' + name if function.key == -1 else name + '@' + str(offset))
                        if '&' in declared:
                            self.unsupported_references.add(bindings[name])
                snapshots.append((dict(bindings), reads))
            entry = following
            for statement, (local, reads) in reversed(list(zip(statements, snapshots))):
                span, kind = (statement.start, statement.end), statement.kind
                if kind == 'definition':
                    continue
                if kind == 'block':
                    entry = block(statement.body, entry, dict(local), break_to, continue_to)
                elif kind == 'if':
                    yes = block(statement.body, entry, dict(local), break_to, continue_to)
                    no = block(statement.otherwise, entry, dict(local), break_to, continue_to)
                    for truth, guard in self.guard_facts(*statement.header):
                        successor = yes if truth else no
                        refined = node('guard', statement.header, local, (successor,), guard)
                        if truth:
                            yes = refined
                        else:
                            no = refined
                    condition = self.parser.compact(*statement.header)
                    entry = node('eval', statement.header, local,
                        (yes,) if condition == 'true' else (no,) if condition == 'false' else (yes, no))
                elif kind in {'while', 'for', 'do'}:
                    condition, initial, update = statement.header, None, None
                    if kind == 'for':
                        parts = list(self.parser.parts(*condition, ';'))
                        if len(parts) != 3:
                            raise ValueError('C++ range loop needs element binding analysis; analysis is incomplete')
                        initial, condition, update = parts
                        assignment = self.parser.assignment(*initial)
                        if assignment and assignment[-1]:
                            local[assignment[0]] = assignment[0] + '@' + str(assignment[1])
                    test = node('eval', condition, local)
                    step = node('simple', update, local, (test,)) if update else test
                    body = block(statement.body, step, dict(local), entry, step)
                    condition_text = self.parser.compact(*condition)
                    edges[test] = (body,) if condition_text in {'true', ''} else (
                        (entry,) if condition_text == 'false' else (body, entry))
                    entry = body if kind == 'do' else test
                    if initial:
                        entry = node('simple', initial, local, (entry,))
                else:
                    targets = (entry,)
                    if kind in {'return', 'throw'}:
                        targets = (exit_node,) if kind == 'return' else ()
                    elif kind in {'break', 'continue'}:
                        destination = break_to if kind == 'break' else continue_to
                        if destination is None:
                            raise ValueError('Invalid C/C++ loop transfer; analysis is incomplete')
                        targets = (destination,)
                    entry = node(kind, span, local, targets, reads=reads)
            return entry

        entry = block(function.body, exit_node, scope)
        if function.key == -1:
            actions[exit_node] = 'exit', (function.end, function.end), dict(scope), None, dict(scope)
        return entry, actions, edges

    def transfer(self, action, state):
        self.budget.spend()
        kind, span, bindings, guard, reads = action
        start, end = span
        if kind == 'exit':
            self.returned = join(self.returned, state.get('@return', CLEAN))
            for index in self.mutated:
                self.mutations[index] = join(self.mutations.get(index, CLEAN), state.get('param:' + str(index), CLEAN))
            if self.function.key == -1:
                for name in self.parser.globals:
                    self.global_values[name] = join(self.global_values.get(name, CLEAN), state.get('global:' + name, CLEAN))
            return state
        if kind == 'guard':
            return self.apply_guard(guard, state, bindings)
        assignment = self.parser.assignment(start, end) if kind == 'simple' else None
        if assignment:
            name, offset, low, high, operator, declaration = assignment
            if offset in self.alias_declarations:
                return state
            value = self.expression(low, high, state, reads)
            if operator != '=':
                value = self.without_proof(join(state.get(reads.get(name, name), CLEAN), value))
            value = self.assigned_value(start, offset, low, high, value, state, reads)
            if declaration and any(self.parser.value(i) in {'&', '*'} for i in range(start, offset)):
                declared = self.parser.raw(start, offset)
                if '&' in declared and value:
                    self.escapes[offset] = join(self.escapes.get(offset, CLEAN), value)
            value = advance(value, self.step(offset, 'assign', name))
            value = retag(value, remove=frozenset(tag for trace in value for tag in trace.tags
                if tag.startswith('binding-version:')), add=frozenset({'binding-version:' + str(offset)}))
            binding = bindings.get(name, name)
            state[binding] = value
            self.note_mutation(binding)
            if (binding in self.unsupported_references or
                    binding.startswith('global:') and self.function.key != -1):
                self.escapes[offset] = join(self.escapes.get(offset, CLEAN), value)
        else:
            raw = self.parser.raw(start, end)
            stream = re.match(r'(?:std\s*::\s*)?(?:ifstream|ofstream|fstream)\s+([A-Za-z_]\w*)\s*\(', raw)
            if stream:
                opening = next(i for i in range(start, end) if self.parser.value(i) == '(')
                spans = list(self.parser.parts(opening + 1, self.parser.pairs[opening]))
                if spans:
                    self.record(start, self.expression(*spans[0], state, bindings), file_leaf=True)
            if kind == 'return':
                start += 1
            value = self.expression(start, end, state, bindings)
            if kind == 'return':
                state['@return'] = advance(value, self.step(start, 'return', self.function.name))
            elif any(self.parser.value(i) == '=' for i in self.top_tokens(start, end)) and value:
                self.escapes[start] = join(self.escapes.get(start, CLEAN), value)
        return state

    def analyze(self):
        if self.parser.conditional:
            raise ValueError('Conditional C/C++ preprocessing needs an active configuration; analysis is incomplete')
        changed = True
        while changed:
            changed = False
            for key, function in self.parser.functions.items():
                self.budget.spend()
                self.function, self.returned = function, CLEAN
                self.effects, self.escapes, self.mutations, self.global_values, self.mutated = {}, {}, {}, {}, set()
                if key not in self.graphs:
                    self.graphs[key] = self.graph(function)
                entry, actions, edges = self.graphs[key]
                initial = {'global:' + name: value for name, value in self.summaries.get(-1, Summary()).globals.items()}
                for index, name in enumerate(function.parameters):
                    declaration = function.declarations[index]
                    tags = frozenset({'path'}) if re.search(r'(?:filesystem|fs)::path', declaration) else frozenset({'string'})
                    initial['param:' + str(index)] = frozenset({Trace('parameter', (key, index), tags,
                        evidence=(self.step(key, 'parameter', name),))})
                solve(entry, initial, edges, lambda node, state: self.transfer(actions[node], state), self.budget)
                updated = Summary(self.returned, self.effects, self.escapes, self.mutations, self.global_values)
                if updated != self.summaries[key]:
                    self.summaries[key], changed = updated, True
        effects = {}
        for summary in self.summaries.values():
            for offset, fact in summary.escapes.items():
                if any(trace.kind == 'source' for trace in fact):
                    site = self.step(offset, 'escape', 'unsupported heap/reference write')
                    raise ValueError(f'{site.path}:{site.line}: C/C++ heap or reference binding needs alias analysis; analysis is incomplete')
            for offset, fact in summary.effects.items():
                concrete = frozenset(trace for trace in fact if trace.kind == 'source' and not self.safe(trace))
                if concrete:
                    sink = self.step(offset, 'sink', self.sink_label)
                    if not self.suppressions.is_suppressed(self.path, sink.line, self.rule):
                        effects[sink.line] = join(effects.get(sink.line, CLEAN), advance(concrete, sink))
        return effects


def analyze(path, issues):
    text = path.read_text(encoding='utf-8')
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    for line, fact in sorted(Engine(path, text).analyze().items()):
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        source = witness.evidence[0].label if witness.evidence else 'request source'
        issues.append((relpath(path), line, f"{source_line(lines, line)}  [{source} -> file sink]"))


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


_KIND = "path_traversal"
_SEVERITY = "critical"
_MESSAGE = "Request-derived path reaches file read/write/serve sink"


def _path_desc(code: str) -> str:
    """Recover the taint-flow description from an analyze() sample row."""
    if "  [" in code and code.endswith("]"):
        return code.rsplit("  [", 1)[1][:-1]
    return code


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR
    cwd = Path.cwd()
    BASE_DIR = cwd
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        if not ctx.rule_enabled('cpp.taint.path_traversal'):
            continue
        rel = path.resolve()
        issues = []
        analyze(path, issues)
        for _rel, line_no, code in issues:
            yield {
                "rule": f"cpp.taint.{_KIND}",
                "path": str(rel),
                "line": line_no,
                "col": 1,
                "layer": "taint",
                "lang": "cpp",
                "severity": _SEVERITY,
                "message": f"{_MESSAGE} ({_path_desc(code)})",
            }


def _selftest_direct_source_sink(tmp_prefix: str = "ubs_core_taint_cpp_trav_") -> None:
    import tempfile

    code = (
        "std::string p = req.getParam(\"file\");\n"
        "std::ifstream in(p);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "cpp.taint.path_traversal", findings
    assert findings[0]["line"] == 2, findings
    assert "req.getParam -> file sink" in findings[0]["message"], findings


def _selftest_unknown_sanitizer_and_ignore(tmp_prefix: str = "ubs_core_taint_cpp_trav_sup_") -> None:
    import tempfile

    code = (
        "std::string a = sanitize_filename(req.getParam(\"f\"));\n"
        "std::ifstream in1(a);\n"
        "std::string b = req.getParam(\"g\");\n"
        "std::ifstream in2(b);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert [(finding['rule'], finding['line']) for finding in findings] == [
        ('cpp.taint.path_traversal', 2)], findings


def _selftest_selected_literal_helper(tmp_prefix: str = "ubs_core_taint_cpp_trav_fixed_") -> None:
    import tempfile

    code = (
        'std::string destination(std::string input) { return "/srv/help.txt"; }\n'
        'void handle(Request& req) {\n'
        '  auto path = destination(req.getParam("file"));\n'
        '  std::ifstream input(path);\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert findings == [], findings


def _selftest_transformed_relative_is_not_original_proof(tmp_prefix: str = "ubs_core_taint_cpp_trav_transform_") -> None:
    import tempfile

    code = (
        'std::filesystem::path opaque(std::filesystem::path input);\n'
        'void handle(const Request& req) {\n'
        '  auto root = std::filesystem::canonical("/srv/data");\n'
        '  auto file = std::filesystem::canonical(root / req.get_param_value("file"));\n'
        '  auto relative = file.lexically_relative(root);\n'
        '  auto checked = opaque(relative);\n'
        '  if (checked.empty() || checked.is_absolute() || *checked.begin() == "..")\n'
        '    throw std::runtime_error("outside root");\n'
        '  std::ifstream input(file);\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="cpp", files=[target])))
    assert [(finding['rule'], finding['line']) for finding in findings] == [
        ('cpp.taint.path_traversal', 9)], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_cpp_trav_main_") -> None:
    import contextlib
    import io
    import tempfile

    code = (
        "std::string p = req.getParam(\"file\");\n"
        "std::ifstream in(p);\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "main.cpp"
        target.write_text(code, encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["taint_cpp_traversal.py", tmp])
    out = buf.getvalue()
    assert rc == 0, rc
    assert out == (
        "__COUNT__\t1\n"
        "__SAMPLE__\tmain.cpp\t2\tstd::ifstream in(p);  [req.getParam -> file sink]\n"
    ), repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_sink", _selftest_direct_source_sink),
    ("unknown_sanitizer_and_ignore", _selftest_unknown_sanitizer_and_ignore),
    ("selected_literal_helper", _selftest_selected_literal_helper),
    ("transformed_relative_is_not_original_proof", _selftest_transformed_relative_is_not_original_proof),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="cpp", name="taint_cpp_traversal", run=run, selftests=SELF_TESTS))
