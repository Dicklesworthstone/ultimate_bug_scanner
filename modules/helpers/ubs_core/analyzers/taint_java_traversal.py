"""Function-scoped Java/Kotlin request-path dataflow (D6 increment).

Structured branches and loops use the shared finite taint lattice/worklist.
Local summaries carry parameter-to-return and file-sink flows. This lexical
frontend does not model fields, tainted global captures, or cross-file/virtual
calls. Request-derived field/global escapes and executable class initialization
report incomplete analysis. Unknown calls conservatively propagate receiver and
argument facts. Unsupported control flow and malformed lexical input are
analysis errors, never clean scans.
The legacy main() count/sample interface remains an output adapter.
"""
from __future__ import annotations

from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import (AnalysisLimit, Budget, CLEAN, Fact, Step, Trace,
                                 advance, join, retag, solve, substitute)
from bisect import bisect_right
from dataclasses import dataclass, field
import re
import sys
from pathlib import Path

SKIP_DIRS = {'.git', '.gradle', '.mvn', 'build', 'target', 'out', 'node_modules', '.cache'}

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getPathInfo|getRequestURI|getServletPath|'
    r'getRequestPath|getPath|getHeader|queryParam|queryParams|pathParam|pathParams|formParam|formParams|'
    r'uploadedFile|fileUpload)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall|context|ctx)\.request\.(?:headers|header)\s*(?:\(|\[|\.get\b|\b)'
    r'|\b(?:call|routingCall)\.request\.(?:path|uri|local|queryParameters)\s*(?:\(|\[|\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b'
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:getSubmittedFileName|getOriginalFilename|fileName|filename|originalFileName|originalFilename)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:submittedFileName|originalFilename|originalFileName|fileName|filename)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|Path|File|Object|MultipartFile|Part|UploadedFile|FileUpload|'
    r'[A-Za-z_][A-Za-z0-9_<>, ?]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
CONTAINMENT_NORMALIZE_RE = re.compile(r'\b(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile)\s*\(')
SINK_RE = re.compile(
    r'\b(?:new\s+)?(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\('
    r'|\b(?:new\s+File|File|Paths\.get|Path\.of)\s*\('
    r'|\.\s*resolve\s*\('
    r'|\bFiles\.(?:readAllBytes|readString|readAllLines|write|writeString|copy|move|delete|deleteIfExists|'
    r'newInputStream|newOutputStream|createDirectories|createFile|size|exists)\s*\('
    r'|\b(?:sendFile|send_file|serveFile|serve_file|writeFileResponse|respondFile|respondLocalFile)\s*\(',
)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.java', '.kt', '.kts'}:
            yield root
        return
    for suffix in ('*.java', '*.kt', '*.kts'):
        for path in root.rglob(suffix):
            if path.is_file() and not should_skip(path):
                yield path

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def lexical_source(text: str, kotlin: bool, depth: int = 0) -> str:
    """Mask inert text at original offsets; keep executable Kotlin holes."""
    if depth > 32:
        raise AnalysisLimit('Java/Kotlin literal nesting limit exceeded')
    output = list(text)

    def blank(start, end):
        for index in range(start, end):
            if text[index] not in '\r\n':
                output[index] = ' '

    index = 0
    while index < len(text):
        if text.startswith('//', index):
            end = text.find('\n', index + 2)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith('/*', index):
            end, nesting = index + 2, 1
            while end < len(text) and nesting:
                if kotlin and text.startswith('/*', end):
                    nesting += 1
                    end += 2
                elif text.startswith('*/', end):
                    nesting -= 1
                    end += 2
                else:
                    end += 1
            if nesting:
                raise ValueError('Unterminated Java/Kotlin comment; analysis is incomplete')
            blank(index, end)
            index = end
        elif text[index] in '\"\'':
            start = index
            delimiter = text[index] * (3 if text.startswith(text[index] * 3, index) else 1)
            index += len(delimiter)
            holes = []
            while index < len(text) and not text.startswith(delimiter, index):
                if text[index] == '\\' and len(delimiter) == 1:
                    index += 2
                    continue
                if kotlin and delimiter.startswith('\"') and text[index] == '$':
                    name = re.match(r'\$([A-Za-z_]\w*)', text[index:])
                    if name:
                        holes.append((index + 1, index + name.end()))
                        index += name.end()
                        continue
                    if text.startswith('${', index):
                        opening, cursor, nesting = index + 2, index + 2, 1
                        while cursor < len(text) and nesting:
                            if text[cursor] in '\"\'':
                                quote = text[cursor]
                                cursor += 1
                                while cursor < len(text) and text[cursor] != quote:
                                    cursor += 2 if text[cursor] == '\\' else 1
                            elif text[cursor] == '{':
                                nesting += 1
                            elif text[cursor] == '}':
                                nesting -= 1
                            cursor += 1
                        if nesting:
                            raise ValueError('Unterminated Kotlin interpolation; analysis is incomplete')
                        holes.append((opening, cursor - 1))
                        index = cursor
                        continue
                index += 1
            if index >= len(text):
                raise ValueError('Unterminated Java/Kotlin literal; analysis is incomplete')
            index += len(delimiter)
            blank(start, index)
            output[start] = '0'
            for low, high in holes:
                output[low:high] = lexical_source(text[low:high], kotlin, depth + 1)
                if (0 <= low - 1 < len(text) and 0 <= low - 1 < len(output)
                        and 0 <= high < len(output)):
                    if text[low - 1] == '{':
                        output[low - 1], output[high] = '(', ')'
                else:
                    raise ValueError('Invalid Kotlin interpolation bounds; analysis is incomplete')
        else:
            index += 1
    return ''.join(output)


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
    start: int
    end: int
    parameters: tuple
    sources: frozenset = frozenset()
    body: tuple = ()
    declaration: int = -1
    captures: tuple = ()
    parameter_declarations: tuple = ()


class Parser:
    def __init__(self, text, kotlin, source_re=SOURCE_RE, sink_re=SINK_RE):
        self.text, self.kotlin = text, kotlin
        self.code = lexical_source(text, kotlin)
        self.pairs, stack = {}, []
        for index, char in enumerate(self.code):
            if char in '([{':
                stack.append((char, index))
            elif char in ')]}':
                if not stack or stack[-1][0] != {')': '(', ']': '[', '}': '{'}[char]:
                    raise ValueError('Unbalanced Java/Kotlin source; analysis is incomplete')
                _, opening = stack.pop()
                self.pairs[opening] = index
        if stack:
            raise ValueError('Unbalanced Java/Kotlin source; analysis is incomplete')
        self.functions = {}
        owners = []
        for match in re.finditer(r'\b(?:class|interface|object|enum)\s+([A-Za-z_]\w*)[^;{}]*\{', self.code):
            owners.append((match.start(), self.pairs[match.end() - 1], match.group(1)))
        self.owners = tuple(owners)
        for match in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', self.code):
            name, opening = match.group(1), match.end() - 1
            if name in {'if', 'while', 'for', 'switch', 'catch', 'try', 'synchronized', 'when'}:
                continue
            close = self.pairs[opening]
            boundary = max(self.code.rfind(char, 0, match.start()) for char in ';{}') + 1
            prefix = self.code[boundary:match.start()]
            prefix = re.sub(r'@\w+(?:\s*\([^)]*\))?', ' ', prefix).strip()
            if kotlin:
                if not re.search(r'\bfun(?:\s+[\w.<>?]+\s*\.)?$', prefix):
                    continue
            elif not prefix or any(char in prefix for char in '=()!+') or prefix.split()[0] in {'return', 'throw', 'new', 'else'}:
                continue
            following = self.skip(close + 1, len(self.code))
            if self.code.startswith('throws ', following):
                following = self.code.find('{', following)
            elif kotlin and self.code[following:following + 1] == ':':
                tail = re.match(r':\s*[\w.<>?, \[\]]+\s*', self.code[following:])
                if tail:
                    following += tail.end()
            if following < 0 or following >= len(self.code) or self.code[following] not in '{=':
                continue
            if self.code[following] == '=' and not kotlin:
                continue
            parameters, sources, parameter_declarations = [], set(), []
            for low, high in self.parts(opening + 1, close, generics=True):
                declaration = re.sub(r'@\w+(?:\s*\([^)]*\))?', ' ', self.code[low:high])
                if '=' in declaration and (source_re.search(declaration) or sink_re.search(declaration)):
                    raise ValueError('Executable Java/Kotlin parameter default needs call binding; analysis is incomplete')
                if kotlin:
                    parameter = re.search(r'\b([A-Za-z_]\w*)\s*:', declaration)
                    parameter = parameter.group(1) if parameter else None
                else:
                    ids = re.findall(r'\b[A-Za-z_]\w*\b', declaration.split('=', 1)[0])
                    parameter = ids[-1] if len(ids) >= 2 else None
                if not parameter:
                    raise ValueError('Unsupported Java/Kotlin parameter shape; analysis is incomplete')
                parameters.append(parameter)
                parameter_declarations.append(declaration)
                if ANNOTATED_PARAM_RE.search(self.code[low:high]):
                    sources.add(parameter)
            if self.code[following] == '{':
                start, end = following + 1, self.pairs[following]
                body = self.block(start, end)
            else:
                start = following + 1
                end = self.end_statement(start, len(self.code))
                body = (Statement(start, end, 'return'),)
            owner = tuple(name for low, high, name in owners if low < match.start() < high)
            function = Function(match.start(), name, owner, start, end, tuple(parameters), frozenset(sources), body)
            function.parameter_declarations = tuple(parameter_declarations)
            function.declaration = self.code.rfind('fun', boundary, match.start()) if kotlin else function.key
            self.functions[function.key] = function
        # Do not discard executable class/instance initialization while giving
        # a clean answer about its methods. These regions need a shared field
        # model, rather than treating their locals as unrelated method locals.
        residual = list(self.code)
        for function in self.functions.values():
            for index in range(function.declaration, min(function.end + 1, len(self.code))):
                if residual[index] not in '\r\n':
                    residual[index] = ' '
        outside = ''.join(residual)
        if any(source_re.search(outside[low:high + 1]) or sink_re.search(outside[low:high + 1])
               for low, high, _ in owners):
            raise ValueError('Executable Java/Kotlin class initialization needs field-state analysis; analysis is incomplete')
        self.globals = ()
        if kotlin and self.functions:
            # Parse executable top-level statements using a declaration-only
            # mask. The actual function/expression code keeps its offsets.
            script = list(outside)
            for low, high, _ in owners:
                for index in range(low, high + 1):
                    if script[index] not in '\r\n':
                        script[index] = ' '
            original = self.code
            try:
                self.code = ''.join(script)
                body = self.block(0, len(self.code))
            finally:
                self.code = original
            globals_ = []
            for statement in body:
                if statement.kind == 'simple':
                    declaration = re.match(r'\s*(?:val|var)\s+([A-Za-z_]\w*)\b', self.code[statement.start:statement.end])
                    if declaration:
                        globals_.append(declaration.group(1))
            self.globals = tuple(dict.fromkeys(globals_))
            for function in self.functions.values():
                function.captures = self.globals
            self.functions[-1] = Function(-1, '<script>', (), 0, len(self.code), (), body=body)
        elif not self.functions:
            self.functions[-1] = Function(-1, '<script>', (), 0, len(self.code), (), body=self.block(0, len(self.code)))

    def skip(self, position, end):
        while position < end and (self.code[position].isspace() or self.code[position] == ';'):
            position += 1
        return position

    def parts(self, start, end, separator=',', generics=False):
        beginning, original, angles = start, start, 0
        while start < end:
            if self.code[start] in '([{':
                start = self.pairs[start]
            elif generics and self.code[start] == '<':
                angles += 1
            elif generics and self.code[start] == '>':
                angles = max(0, angles - 1)
            elif self.code[start] == separator and not angles:
                yield beginning, start
                beginning = start + 1
            start += 1
        if self.code[beginning:end].strip() or beginning != original:
            yield beginning, end

    def end_statement(self, start, end):
        while start < end:
            char = self.code[start]
            if char == ';' or char == '}' or (self.kotlin and char in '\r\n'):
                return start
            if char in '([':
                start = self.pairs[start]
            elif char == '{':
                raise ValueError('Unsupported Java/Kotlin expression block; analysis is incomplete')
            start += 1
        return end

    def block(self, start, end):
        statements = []
        while (start := self.skip(start, end)) < end:
            statement, following = self.statement(start, end)
            if following <= start:
                raise ValueError('Java/Kotlin parser made no progress; analysis is incomplete')
            statements.append(statement)
            start = following
        return tuple(statements)

    def statement(self, start, end):
        if self.code[start] == '{':
            finish = self.pairs[start]
            return Statement(start, finish + 1, 'block', self.block(start + 1, finish)), finish + 1
        requirement = re.match(r'require\s*\(', self.code[start:end]) if self.kotlin else None
        if requirement:
            opening = start + requirement.end() - 1
            close = self.pairs[opening]
            following = self.skip(close + 1, end)
            if self.code[following:following + 1] == '{':
                finish = self.pairs[following]
                if self.code[following + 1:finish].strip() not in {'', '0'}:
                    raise ValueError('Executable Kotlin require message needs callback analysis; analysis is incomplete')
                following = finish + 1
            return Statement(start, following, 'require', header=(opening + 1, close)), following
        control = re.match(r'(if|while|for|synchronized)\s*\(', self.code[start:end])
        if control:
            opening = start + control.end() - 1
            close = self.pairs[opening]
            body, following = self.statement(self.skip(close + 1, end), end)
            items = body.body if body.kind == 'block' else (body,)
            otherwise = ()
            tail = self.skip(following, end)
            if control.group(1) == 'if' and re.match(r'else\b', self.code[tail:end]):
                alternate, following = self.statement(self.skip(tail + 4, end), end)
                otherwise = alternate.body if alternate.kind == 'block' else (alternate,)
            return Statement(start, following, control.group(1), items, otherwise, (opening + 1, close)), following
        if re.match(r'do\b', self.code[start:end]):
            body, following = self.statement(self.skip(start + 2, end), end)
            tail = self.skip(following, end)
            match = re.match(r'while\s*\(', self.code[tail:end])
            if not match:
                raise ValueError('Invalid Java/Kotlin do/while; analysis is incomplete')
            opening, close = tail + match.end() - 1, self.pairs[tail + match.end() - 1]
            return Statement(start, close + 1, 'do', body.body if body.kind == 'block' else (body,), header=(opening + 1, close)), close + 1
        if re.match(r'try\b', self.code[start:end]):
            position, header = self.skip(start + 3, end), (start, start)
            if self.code[position:position + 1] == '(':
                close = self.pairs[position]
                header, position = (position + 1, close), self.skip(close + 1, end)
            body, following = self.statement(position, end)
            catches, final = [], ()
            while True:
                tail = self.skip(following, end)
                match = re.match(r'(catch|finally)\b', self.code[tail:end])
                if not match:
                    break
                position = self.skip(tail + match.end(), end)
                if self.code[position:position + 1] == '(':
                    position = self.skip(self.pairs[position] + 1, end)
                handler, following = self.statement(position, end)
                if match.group(1) == 'finally':
                    final = handler.body if handler.kind == 'block' else (handler,)
                else:
                    catches.append(handler)
            return Statement(start, following, 'try', (body, *catches), final, header), following
        if re.match(r'(?:switch|when|goto|yield)\b|(?:break|continue)\s+[A-Za-z_]', self.code[start:end]):
            raise ValueError('Unsupported Java/Kotlin control flow; analysis is incomplete')
        if re.match(r'(?:package|import|class|interface|enum|object|@interface)\b', self.code[start:end]):
            if self.kotlin and re.match(r'(?:package|import)\b', self.code[start:end]):
                finish = self.end_statement(start, end)
                return Statement(start, finish, 'definition'), min(finish + 1, end)
            opening = self.code.find('{', start, end)
            semi = self.code.find(';', start, end)
            finish = self.pairs[opening] + 1 if opening >= 0 and (semi < 0 or opening < semi) else self.end_statement(start, end) + 1
            return Statement(start, finish, 'definition'), finish
        finish = self.end_statement(start, end)
        abrupt = re.match(r'(return|throw|break|continue)\b', self.code[start:finish])
        return Statement(start, finish, abrupt.group(1) if abrupt else 'simple'), min(finish + 1, end)


@dataclass
class Summary:
    returned: Fact = CLEAN
    effects: dict = field(default_factory=dict)
    escapes: dict = field(default_factory=dict)
    globals: dict = field(default_factory=dict)

    def merged(self, other):
        effects = dict(self.effects)
        for key, value in other.effects.items():
            effects[key] = join(effects.get(key, CLEAN), value)
        escapes = dict(self.escapes)
        for key, value in other.escapes.items():
            escapes[key] = join(escapes.get(key, CLEAN), value)
        globals_ = dict(self.globals)
        for key, value in other.globals.items():
            globals_[key] = join(globals_.get(key, CLEAN), value)
        return Summary(join(self.returned, other.returned), effects, escapes, globals_)


class Engine:
    source_re = SOURCE_RE
    sink_re = SINK_RE
    sink_label = 'file sink'
    path_constructors = True

    def __init__(self, path, text):
        self.path, self.text = path, text
        self.parser = Parser(text, path.suffix.lower() in {'.kt', '.kts'}, self.source_re, self.sink_re)
        self.code = self.parser.code
        self.lines = [0, *(index + 1 for index, char in enumerate(text) if char == '\n')]
        self.budget = Budget()
        self.summaries = {key: Summary() for key in self.parser.functions}
        self.graphs = {}

    def step(self, offset, kind, label):
        line = bisect_right(self.lines, offset)
        if 0 <= line - 1 < len(self.lines):
            return Step(str(self.path), line, offset - self.lines[line - 1] + 1, kind, label[:160])
        raise ValueError('Invalid Java/Kotlin evidence offset; analysis is incomplete')

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path), offset, label), evidence=(self.step(offset, 'source', label),))})

    def record(self, offset, value):
        unsafe = frozenset(trace for trace in value if 'contained-path' not in trace.tags)
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN), advance(unsafe, self.step(offset, 'sink', self.sink_label)))

    def builtin_type(self, name):
        return not re.search(r'\b(?:class|interface|object|enum|typealias)\s+' + name + r'\b|\bimport\s+(?!java\.(?:lang|io|net|util|nio\.file)\.)[\w.]+\.' + name + r'\b|\bimport\s+[\w.]+\s+as\s+' + name + r'\b', self.code)

    def parameter_tags(self, declaration):
        declaration = declaration.split('=', 1)[0].strip()
        if self.parser.kotlin:
            match = re.fullmatch(r'[A-Za-z_]\w*\s*:\s*([\w.]+)\s*\??', declaration)
        else:
            match = re.fullmatch(r'(?:final\s+)?([\w.]+)\s+[A-Za-z_]\w*', declaration)
        if not match:
            return frozenset()
        actual = match.group(1)
        types = {'String': 'jvm-string', 'java.lang.String': 'jvm-string', 'kotlin.String': 'jvm-string',
                 'Path': 'jvm-path', 'java.nio.file.Path': 'jvm-path', 'File': 'jvm-path', 'java.io.File': 'jvm-path'}
        tag = types.get(actual)
        return frozenset({tag}) if tag and self.builtin_type(actual.rsplit('.', 1)[-1]) else frozenset()

    def path_receiver(self, root, bindings, state):
        binding = bindings.get(root, root)
        receiver = state.get(binding, CLEAN)
        if receiver:
            return all('jvm-path' in trace.tags for trace in receiver)
        # Clean values have no taint traces. A declaration's lexical identity
        # still supplies its static type, including Kotlin constructor inference.
        if '@' not in binding:
            return False
        offset = int(binding.rsplit('@', 1)[1])
        prefix = self.code[max(0, offset - 80):offset]
        tail = self.code[offset:]
        declared = bool(re.search(r'\b(?:Path|File)\s+$', prefix)) or bool(re.match(re.escape(root) + r'\s*:\s*(?:Path|File)\b', tail))
        inferred = bool(re.match(re.escape(root) + r'\s*=\s*(?:Paths\.get|Path\.of|File)\s*\(', tail))
        return (declared or inferred) and all(self.builtin_type(name) for name in ('Path', 'Paths', 'File'))

    def external_call(self, name, arguments, value, offset, bindings, state):
        root, _, method = name.rpartition('.')
        if name in {'File', 'Path.of', 'Paths.get'} and self.builtin_type(name.split('.')[0]) and name.split('.')[0] not in bindings:
            return retag(value, add=frozenset({'jvm-path'}))
        if method == 'resolve':
            if self.path_receiver(root, bindings, state):
                return retag(value, add=frozenset({'jvm-path'}), remove=frozenset({'contained-path', 'canonical-path'}))
        if method in {'getFileName', 'getName'} and not arguments:
            if self.path_receiver(root, bindings, state):
                return CLEAN
        if method in {'normalize', 'toRealPath', 'getCanonicalPath', 'getCanonicalFile'} and not arguments and self.path_receiver(root, bindings, state):
            return retag(value, add=frozenset({'jvm-path'}))
        if method in {'toString', 'toFile'} and not arguments:
            return value
        return retag(value, remove=frozenset({'contained-path', 'canonical-path', 'jvm-path'}))

    def member_value(self, name, value, offset, arguments=None):
        if arguments and name in {'getFileName', 'getName', 'normalize', 'toRealPath', 'getCanonicalPath', 'getCanonicalFile', 'toString', 'toFile'}:
            return retag(value, remove=frozenset({'contained-path', 'canonical-path', 'jvm-path'}))
        if name in {'getFileName', 'getName', 'fileName', 'name'}:
            return CLEAN if all('jvm-path' in trace.tags for trace in value) else value
        if name in {'toString', 'getCanonicalPath'}:
            return retag(value, remove=frozenset({'jvm-path', 'canonical-path'}))
        if name in {'normalize', 'toRealPath', 'getCanonicalPath', 'getCanonicalFile'}:
            return join(*(retag(frozenset({trace}), add=frozenset({'canonical-path'}))
                          if 'jvm-path' in trace.tags else frozenset({trace}) for trace in value))
        if name == 'resolve':
            return retag(value, remove=frozenset({'contained-path', 'canonical-path'}))
        return value

    def call_sink(self, name, spans, arguments, value, offset):
        if self.sink_re.search(name + '('):
            if name in {'File', 'Path.of', 'Paths.get'} or name.endswith('.resolve'):
                return True
            self.record(offset, value)
        return False

    def summary_effect(self, summary, fact):
        # Construction diagnostics are retained unless this selected helper
        # proves containment for every return of the same symbolic value.
        return frozenset(trace for trace in fact if 'path-construction' not in trace.tags or not (
            (matches := [item for item in summary.returned if item.kind == trace.kind and item.key == trace.key])
            and all('contained-path' in item.tags for item in matches)))

    def summary_return(self, fact, offset):
        return fact

    def guard_facts(self, span):
        condition = self.code[slice(*span)].strip()
        guard = re.fullmatch(r'(!\s*)?([A-Za-z_]\w*)(\.(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile)\s*\(\s*\))?\.startsWith\s*\(\s*([A-Za-z_]\w*)\s*\)', condition)
        if guard:
            return [(not bool(guard.group(1)), (guard.group(2), bool(guard.group(3)), guard.group(4)))]
        return []

    def apply_guard(self, guard, state, bindings):
        name, canonical, root = guard
        binding = bindings.get(name, name)
        root_fact = state.get(bindings.get(root, root), CLEAN)
        if any(trace.kind == 'source' for trace in root_fact):
            return state
        state[binding] = join(root_fact, *(retag(frozenset({trace}), add=frozenset({'contained-path'}))
                              if 'jvm-path' in trace.tags and (canonical or 'canonical-path' in trace.tags) else frozenset({trace})
                              for trace in state.get(binding, CLEAN)))
        return state

    def expression(self, start, end, state, bindings, depth=0):
        if depth > 64:
            raise AnalysisLimit('Java/Kotlin expression depth limit exceeded')
        value, cursor = CLEAN, start
        while cursor < end:
            self.budget.spend()
            match = re.match(r'[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*', self.code[cursor:end])
            if self.code[cursor] == '(':
                close = self.parser.pairs[cursor]
                atom = self.expression(cursor + 1, close, state, bindings, depth + 1)
                cursor = close + 1
                value = join(value, atom)
                continue
            if not match:
                cursor += 1
                continue
            offset = cursor
            name = re.sub(r'\s+', '', match.group())
            root = name.split('.')[0]
            atom = state.get(bindings.get(root, root), CLEAN)
            if bindings.get(root, '').startswith('capture:') and atom:
                escaped = retag(atom, add=frozenset({'unmodeled-global-capture'}))
                self.escapes[offset] = join(self.escapes.get(offset, CLEAN),
                                            advance(escaped, self.step(offset, 'capture', root)))
            cursor += match.end()
            cursor = self.parser.skip(cursor, end)
            constructor = None
            selected = False
            arguments = None
            if cursor < end and self.code[cursor] == '(':
                close = self.parser.pairs[cursor]
                spans = list(self.parser.parts(cursor + 1, close))
                arguments = [self.expression(low, high, state, bindings, depth + 1) for low, high in spans]
                atom = join(atom, *arguments)
                call_text = self.code[offset:close + 1]
                # Arguments were evaluated above. Matching their text again
                # here would resurrect a source after a known clean helper.
                direct = self.source_re.search(self.code[offset:cursor + 1])
                if direct:
                    atom = join(atom, self.source(offset + direct.start(), direct.group().strip()))
                candidates = [function for function in self.parser.functions.values()
                              if function.name == name.removeprefix('this.') and function.owner == self.function.owner
                              and len(function.parameters) == len(arguments)] if '.' not in name or name.startswith('this.') else []
                if candidates:
                    selected = True
                    returned = CLEAN
                    for function in candidates:
                        bound = {(function.key, index): fact for index, fact in enumerate(arguments)}
                        for index, capture in enumerate(function.captures):
                            binding = bindings.get(capture, capture) if self.function.key == -1 else 'capture:' + capture
                            bound[(function.key, -index - 1)] = state.get(binding, CLEAN)
                        summary, call = self.summaries[function.key], self.step(offset, 'call', function.name + '()')
                        returned = join(returned, self.summary_return(substitute(summary.returned, bound, call), offset))
                        for sink, fact in summary.effects.items():
                            self.effects[sink] = join(self.effects.get(sink, CLEAN), substitute(self.summary_effect(summary, fact), bound, call))
                        for site, fact in summary.escapes.items():
                            self.escapes[site] = join(self.escapes.get(site, CLEAN), substitute(fact, bound, call))
                    atom = returned
                else:
                    if self.call_sink(name, spans, arguments, atom, offset):
                        constructor = offset
                    atom = self.external_call(name, arguments, atom, offset, bindings, state)
                cursor = close + 1
            else:
                direct = self.source_re.search(self.code[offset:cursor + 1])
                if direct:
                    atom = join(atom, self.source(offset + direct.start(), direct.group().strip()))
            if '.' in name and not selected:
                atom = self.member_value(name.rsplit('.', 1)[-1], atom, offset, arguments)
            while cursor < end:
                tail = self.parser.skip(cursor, end)
                member = re.match(r'\.\s*([A-Za-z_]\w*)', self.code[tail:end])
                if self.code[tail:tail + 1] == '[':
                    close = self.parser.pairs[tail]
                    atom = join(atom, self.expression(tail + 1, close, state, bindings, depth + 1))
                    cursor = close + 1
                elif member:
                    method = member.group(1)
                    arguments = None
                    cursor = self.parser.skip(tail + member.end(), end)
                    if cursor < end and self.code[cursor] == '(':
                        close = self.parser.pairs[cursor]
                        spans = list(self.parser.parts(cursor + 1, close))
                        arguments = [self.expression(low, high, state, bindings, depth + 1) for low, high in spans]
                        atom = join(atom, *arguments)
                        if self.call_sink('.' + method, spans, arguments, atom, tail):
                            constructor = tail
                        cursor = close + 1
                    atom = self.member_value(method, atom, tail, arguments)
                    if method == 'resolve' and self.path_constructors:
                        constructor = tail
                else:
                    break
            if constructor is not None:
                self.record(constructor, retag(atom, add=frozenset({'path-construction'})))
            value = join(value, atom)
        if '+' in self.code[start:end]:
            value = retag(value, remove=frozenset({'contained-path', 'canonical-path'}))
        return value

    def assignment(self, span):
        start, end = span
        text = self.code[start:end]
        match = re.match(r'\s*(?:(?:final|val|var)\s+)?(?:[\w.]+(?:\s*<[^=;]+>)?(?:\[\])?\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w.<>?]+\s*)?(\+?=)(?!=)', text)
        if not match:
            return None
        declaration = bool(re.match(r'\s*(?:final\s+)?(?:val|var|[\w.]+(?:\s*<[^=;]+>)?(?:\[\])?)\s+[A-Za-z_]\w*', text))
        return match.group(1), start + match.start(1), start + match.end(), end, match.group(2), declaration

    def unmodeled_write(self, span):
        """Locate a field/element write without inventing a heap binding."""
        start, end = span
        cursor = self.parser.skip(start, end)
        root = re.match(r'[A-Za-z_]\w*', self.code[cursor:end])
        if not root:
            return None
        lhs, cursor, indirect = cursor, cursor + root.end(), False
        while cursor < end:
            cursor = self.parser.skip(cursor, end)
            member = re.match(r'\.\s*[A-Za-z_]\w*', self.code[cursor:end])
            if member:
                cursor += member.end()
                indirect = True
            elif self.code[cursor:cursor + 1] == '[':
                cursor = self.parser.pairs[cursor] + 1
                indirect = True
            else:
                break
        operator = re.match(r'(\+?=)(?!=)', self.code[cursor:end])
        if not indirect or not operator:
            return None
        return lhs, cursor, cursor + operator.end(), end, operator.group(1)

    def graph(self, function):
        actions, edges = {}, {}
        scope = {name: 'capture:' + name for name in function.captures}
        scope.update({name: 'param:' + str(index) for index, name in enumerate(function.parameters)})

        def node(kind, span, bindings, targets=(), guard=None, reads=None):
            self.budget.spend()
            key = len(actions)
            actions[key], edges[key] = (kind, span, dict(bindings), guard, dict(bindings if reads is None else reads)), tuple(targets)
            return key

        exit_node = node('exit', (function.end, function.end), scope)

        def block(statements, following, bindings, break_to=None, continue_to=None, unwind=()):
            snapshots = []
            for statement in statements:
                reads = dict(bindings)
                assignment = self.assignment((statement.start, statement.end)) if statement.kind == 'simple' else None
                if assignment and assignment[-1]:
                    bindings[assignment[0]] = f'{assignment[0]}@{assignment[1]}'
                snapshots.append((dict(bindings), reads))
            entry = following
            for statement, (local, reads) in reversed(list(zip(statements, snapshots))):
                kind, span = statement.kind, (statement.start, statement.end)
                targets = () if entry is None else (entry,)
                if kind == 'definition':
                    continue
                if kind == 'require':
                    imported = re.search(r'\bimport\s+(?!kotlin\.require\s*(?:;|\r?$))[^\r\n;]*(?:\.require\b|\bas\s+require\b|\.\*)', self.code, re.MULTILINE)
                    if not imported and 'require' not in local and not any(item.name == 'require' for item in self.parser.functions.values()):
                        for truth, guard in self.guard_facts(statement.header):
                            if truth:
                                entry = node('guard', statement.header, local, () if entry is None else (entry,), guard)
                    entry = node('eval', statement.header, local, () if entry is None else (entry,))
                    continue
                if kind == 'block':
                    entry = block(statement.body, entry, dict(local), break_to, continue_to, unwind)
                elif kind == 'if':
                    yes = block(statement.body, entry, dict(local), break_to, continue_to, unwind)
                    no = block(statement.otherwise, entry, dict(local), break_to, continue_to, unwind)
                    condition = self.code[slice(*statement.header)].strip()
                    for truth, guard in self.guard_facts(statement.header):
                        safe = yes if truth else no
                        refined = node('guard', statement.header, local, () if safe is None else (safe,), guard)
                        if truth:
                            yes = refined
                        else:
                            no = refined
                    branch_targets = (yes,) if condition == 'true' else (no,) if condition == 'false' else (yes, no)
                    entry = node('eval', statement.header, local, tuple(target for target in branch_targets if target is not None))
                elif kind in {'while', 'for', 'do'}:
                    initial, update, condition, element = None, None, statement.header, None
                    if kind == 'for':
                        segments = list(self.parser.parts(*condition, separator=';'))
                        if len(segments) == 3:
                            initial, condition, update = segments
                            assignment = self.assignment(initial)
                            if assignment:
                                local[assignment[0]] = f'{assignment[0]}@{assignment[1]}'
                        else:
                            header = self.code[slice(*condition)]
                            match = re.match(r'\s*(?:(?:val|var|[\w.<>?]+)\s+)?([A-Za-z_]\w*)\s*(?:in\b|:)\s*', header)
                            if not match:
                                raise ValueError('Invalid Java/Kotlin for header; analysis is incomplete')
                            element = match.group(1)
                            local[element] = f'{element}@{condition[0] + match.start(1)}'
                            condition = (condition[0] + match.end(), condition[1])
                    test = node('eval', condition, local)
                    step = node('simple', update, local, (test,)) if update else test
                    body = block(statement.body, step, dict(local), (entry, len(unwind)), (step, len(unwind)), unwind)
                    if element:
                        body = node('element', condition, local, (body,), element)
                    condition_text = self.code[slice(*condition)].strip()
                    edges[test] = (body,) if condition_text in {'true', ''} and not element else targets if condition_text == 'false' else tuple(target for target in (body, entry) if target is not None)
                    entry = body if kind == 'do' else test
                    if initial:
                        entry = node('simple', initial, local, (entry,))
                elif kind == 'try':
                    after = block(statement.otherwise, entry, dict(local), break_to, continue_to, unwind)
                    cleanup = (*unwind, (statement.otherwise, dict(local))) if statement.otherwise else unwind
                    before = set(actions)
                    body = block((statement.body[0],), after, dict(local), break_to, continue_to, cleanup)
                    body_nodes = set(actions) - before
                    catches = tuple(target for handler in statement.body[1:]
                                    if (target := block((handler,), after, dict(local), break_to, continue_to, cleanup)) is not None)
                    for key in body_nodes:
                        if actions[key][0] not in {'return', 'break', 'continue'}:
                            edges[key] = tuple(dict.fromkeys((*edges[key], *catches)))
                    entry = node('simple', statement.header, local, tuple(target for target in (body, *catches) if target is not None))
                elif kind == 'synchronized':
                    body = block(statement.body, entry, dict(local), break_to, continue_to, unwind)
                    entry = node('eval', statement.header, local, () if body is None else (body,))
                else:
                    target, depth = entry, len(unwind)
                    if kind in {'break', 'continue'}:
                        destination = break_to if kind == 'break' else continue_to
                        if destination is None:
                            raise ValueError('Break/continue has no control-flow target; analysis is incomplete')
                        target, depth = destination
                    elif kind in {'return', 'throw'}:
                        target, depth = exit_node if kind == 'return' else None, 0
                    if kind in {'return', 'throw', 'break', 'continue'}:
                        for index in range(depth, len(unwind)):
                            final, final_scope = unwind[index]
                            target = block(final, target, dict(final_scope), break_to, continue_to, unwind[:index])
                    entry = node(kind, span, local, () if target is None else (target,), reads=reads)
            return entry

        entry = block(function.body, exit_node, scope)
        if function.key == -1:
            kind, span, _, guard, reads = actions[exit_node]
            actions[exit_node] = kind, span, dict(scope), guard, reads
        return entry, actions, edges

    def transfer(self, action, state):
        kind, span, bindings, guard, reads = action
        start, end = span
        if kind == 'exit':
            self.returned = join(self.returned, state.get('@return', CLEAN))
            if self.function.key == -1:
                for name in self.parser.globals:
                    fact = state.get(bindings.get(name, name), CLEAN)
                    self.global_values[name] = join(self.global_values.get(name, CLEAN), fact)
            return state
        if kind == 'guard':
            return self.apply_guard(guard, state, bindings)
        if kind == 'element':
            fact = self.expression(start, end, state, bindings)
            binding = bindings[guard]
            if fact:
                state[binding] = advance(fact, self.step(start, 'assign', guard))
            else:
                state.pop(binding, None)
            return state
        assignment = self.assignment(span) if kind == 'simple' else None
        if assignment:
            name, offset, low, high, operator, _ = assignment
            fact = self.expression(low, high, state, reads)
            if operator == '+=':
                fact = join(state.get(reads.get(name, name), CLEAN), fact)
                fact = retag(fact, remove=frozenset({'contained-path', 'canonical-path'}))
            fact = advance(fact, self.step(offset, 'assign', name))
            binding = bindings.get(name, name)
            if binding.startswith('capture:') and fact:
                escaped = retag(fact, add=frozenset({'unmodeled-global-capture'}))
                self.escapes[offset] = join(self.escapes.get(offset, CLEAN),
                                            advance(escaped, self.step(offset, 'capture', 'write global ' + name)))
            if fact:
                state[binding] = fact
            else:
                state.pop(binding, None)
        else:
            write = self.unmodeled_write(span) if kind == 'simple' else None
            if write:
                low, lhs_end, rhs, finish, operator = write
                fact = self.expression(rhs, finish, state, reads)
                if operator == '+=':
                    fact = join(fact, self.expression(low, lhs_end, state, reads))
                if fact:
                    self.escapes[low] = join(self.escapes.get(low, CLEAN),
                                             advance(fact, self.step(low, 'escape', 'unmodeled field/element write')))
                return state
            if kind == 'return' and self.code[start:end].lstrip().startswith('return'):
                start += self.code[start:end].index('return') + len('return')
            fact = self.expression(start, end, state, bindings)
            if kind == 'return':
                state['@return'] = advance(fact, self.step(start, 'return', self.function.name))
        return state

    def analyze(self):
        changed = True
        while changed:
            changed = False
            for key, function in self.parser.functions.items():
                self.budget.spend()
                self.function, self.effects, self.escapes, self.global_values, self.returned = function, {}, {}, {}, CLEAN
                if key not in self.graphs:
                    self.graphs[key] = self.graph(function)
                entry, actions, edges = self.graphs[key]
                initial = {}
                for index, name in enumerate(function.captures):
                    initial['capture:' + name] = frozenset({Trace('parameter', (key, -index - 1),
                        evidence=(self.step(key, 'parameter', 'global ' + name),))})
                for index, name in enumerate(function.parameters):
                    declaration = function.parameter_declarations[index] if index < len(function.parameter_declarations) else ''
                    fact = frozenset({Trace('parameter', (key, index), tags=self.parameter_tags(declaration),
                                           evidence=(self.step(key, 'parameter', name),))})
                    initial['param:' + str(index)] = fact
                if entry is not None:
                    solve(entry, initial, edges, lambda node, state: self.transfer(actions[node], state), self.budget)
                updated = self.summaries[key].merged(Summary(self.returned, self.effects, self.escapes, self.global_values))
                if updated != self.summaries[key]:
                    self.summaries[key], changed = updated, True
        effects = {}
        for key, summary in self.summaries.items():
            function = self.parser.functions[key]
            exposed = {(key, index): self.source(key, '@request ' + name)
                       for index, name in enumerate(function.parameters) if name in function.sources}
            script_globals = self.summaries.get(-1, Summary()).globals
            exposed.update({(key, -index - 1): script_globals.get(name, CLEAN)
                            for index, name in enumerate(function.captures)})
            for offset, fact in summary.escapes.items():
                if exposed:
                    fact = substitute(fact, exposed, self.step(key, 'entry', function.name))
                if any(trace.kind == 'source' for trace in fact):
                    site = self.step(offset, 'escape', 'unmodeled field/element write')
                    if any('unmodeled-global-capture' in trace.tags for trace in fact):
                        raise ValueError(f'{site.path}:{site.line}: Request-derived Kotlin global capture needs capture-state analysis; analysis is incomplete')
                    raise ValueError(f'{site.path}:{site.line}: Request-derived field/element write needs heap-state analysis; analysis is incomplete')
            for offset, fact in summary.effects.items():
                fact = self.summary_effect(summary, fact)
                if exposed:
                    fact = substitute(fact, exposed, self.step(key, 'entry', function.name))
                concrete = frozenset(trace for trace in fact if trace.kind == 'source')
                if concrete:
                    sink = self.step(offset, 'sink', self.sink_label)
                    # Entry exposure can append a call-site witness after a
                    # callee effect. Every exported route ends at its exact sink.
                    effects[sink.line] = join(effects.get(sink.line, CLEAN), advance(concrete, sink))
        return effects


def analyze(path, issues):
    text = path.read_text(encoding='utf-8')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
        return
    engine = Engine(path, text)
    lines = text.splitlines()
    lang = 'kotlin' if path.suffix.lower() in {'.kt', '.kts'} else 'java'
    suppressions = SourceSuppressions(lang)
    for line, fact in sorted(engine.analyze().items()):
        if suppressions.is_suppressed(path, line, lang + '.taint.path_traversal'):
            continue
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        path_desc = ' -> '.join(step.label for step in witness.evidence)
        extras = {'taint_path': [step.record() for step in witness.evidence],
                  'source_count': len({trace.key for trace in fact})}
        issues.append((relpath(path), line, f'{source_line(lines, line)}  [{path_desc}]', extras))

def main(argv: list[str] | None = None) -> int:
    """Reproduce the module heredoc: `python3 - <project_dir> <<PY` emit dialect."""
    global ROOT, BASE_DIR

    argv = sys.argv if argv is None else list(argv)
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f"__COUNT__\t{len(issues)}")
    for file_name, line_no, code, _extras in issues[:25]:
        print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
    return 0


_RUN_MESSAGE = "Request-derived path reaches file read/write/serve sink"


def run(ctx: RunContext) -> Iterable[dict]:
    global BASE_DIR

    BASE_DIR = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".java", ".kt", ".kts"}:
            continue
        lang = 'kotlin' if path.suffix.lower() in {'.kt', '.kts'} else 'java'
        if not ctx.rule_enabled(lang + '.taint.path_traversal'):
            continue
        issues: list[tuple[str, int, str, dict]] = []
        analyze(path, issues)
        for rel_path, line_no, _sample, extras in issues:
            yield {
                "rule": "java.taint.path_traversal",
                "path": rel_path,
                "line": line_no,
                "col": 1,
                "severity": "critical",
                "message": _RUN_MESSAGE,
                "extras": extras,
            }


def _selftest_direct_source_to_sink() -> None:
    import tempfile

    code = (
        "String name = request.getParameter(\"file\");\n"
        "new FileInputStream(name);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_traversal_") as tmp:
        target = Path(tmp) / "A.java"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "java.taint.path_traversal"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "String name = request.getParameter(\"file\");\n"
        "new FileInputStream(name);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_traversal_") as tmp:
        target = Path(tmp) / "A.java"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target])))
    assert findings == [], findings


def _selftest_containment_guard_suppression() -> None:
    import tempfile

    code = (
        'class Guarded {\n'
        '  Path choose(Path root, String raw) {\n'
        '    Path name = root.resolve(raw).normalize();\n'
        '    if (!name.startsWith(root)) { throw new SecurityException("bad"); }\n'
        '    return name;\n'
        '  }\n'
        '  void handler(Request request, Path root) {\n'
        '    Files.readString(choose(root, request.getParameter("file")));\n'
        '  }\n'
        '}\n'
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_java_traversal_") as tmp:
        target = Path(tmp) / "A.java"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="java", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_sink", _selftest_direct_source_to_sink),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("containment_guard_suppression", _selftest_containment_guard_suppression),
)

register(Analyzer(layer="taint", lang="java", name="taint_java_traversal", run=run, selftests=SELF_TESTS))
