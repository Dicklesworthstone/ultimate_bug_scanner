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
    r'newInputStream|newOutputStream|createDirectories|createFile|size|exists|walk|walkFileTree|'
    r'list|newDirectoryStream|find)\s*\('
    r'|\b(?:sendFile|send_file|serveFile|serve_file|writeFileResponse|respondFile|respondLocalFile)\s*\(',
)

BASENAME_TAGS = frozenset({'basename-path', 'basename-not-dot', 'basename-not-dotdot'})
PATH_PROOF_TAGS = frozenset({'contained-path', 'canonical-path'}) | BASENAME_TAGS
REQUEST_TYPE_PREFIX = 'jvm-request-type:'
SERVLET_TYPES = frozenset({'jakarta.servlet.ServletRequest', 'javax.servlet.ServletRequest'})
HTTP_SERVLET_TYPES = frozenset({'jakarta.servlet.http.HttpServletRequest', 'javax.servlet.http.HttpServletRequest'})
REQUEST_TYPES = SERVLET_TYPES | HTTP_SERVLET_TYPES
REQUEST_GETTERS = {'getParameter': 1, 'getHeader': 1, 'getQueryString': 0,
                   'getRequestURI': 0, 'getPathInfo': 0, 'getServletPath': 0,
                   'getParameterValues': 1, 'getParameterMap': 0, 'getParameterNames': 0,
                   'getHeaders': 1, 'getHeaderNames': 0}
SERVLET_BASE_GETTERS = frozenset({'getParameter', 'getParameterValues', 'getParameterMap', 'getParameterNames'})
REQUEST_COLLECTIONS = {'getParameterValues': 'string-array', 'getParameterMap': 'parameter-map',
                       'getParameterNames': 'string-enumeration', 'getHeaders': 'string-enumeration',
                       'getHeaderNames': 'string-enumeration'}
COLLECTION_PREFIX = 'jvm-collection:'
COLLECTION_KINDS = frozenset({'string-array', 'parameter-map', 'string-enumeration',
                             'string-collection', 'array-collection', 'string-iterator', 'array-iterator'})
COLLECTION_TAGS = frozenset(COLLECTION_PREFIX + kind for kind in COLLECTION_KINDS)
REQUEST_GETTER_RE = re.compile(r'\.\s*(?:' + '|'.join(REQUEST_GETTERS) + r')\s*\(')
REQUEST_PROPERTIES = {'queryString': 'getQueryString', 'requestURI': 'getRequestURI',
                      'pathInfo': 'getPathInfo', 'servletPath': 'getServletPath',
                      'parameterMap': 'getParameterMap', 'parameterNames': 'getParameterNames',
                      'headerNames': 'getHeaderNames'}
REQUEST_PROPERTY_RE = re.compile(r'\.\s*(?:' + '|'.join(REQUEST_PROPERTIES) + r')\b')
REQUEST_PROPERTY_PREFIX_RE = re.compile(
    r'(?:this\s*\.\s*)?[A-Za-z_]\w*' + REQUEST_PROPERTY_RE.pattern)
KOTLIN_SERVLET_SOURCE_RE = re.compile(REQUEST_GETTER_RE.pattern + '|' + REQUEST_PROPERTY_RE.pattern)
KTOR_CALL_TYPES = frozenset({'io.ktor.server.application.ApplicationCall',
                            'io.ktor.server.application.PipelineCall', 'io.ktor.server.routing.RoutingCall'})
KTOR_REQUEST_TYPES = frozenset({'io.ktor.server.request.ApplicationRequest',
                               'io.ktor.server.request.PipelineRequest', 'io.ktor.server.routing.RoutingRequest'})
KTOR_TYPES = KTOR_CALL_TYPES | KTOR_REQUEST_TYPES
KTOR_COLLECTION_TYPES = frozenset({'io.ktor.http.Parameters', 'io.ktor.http.Headers'})
KTOR_SOURCE_MEMBERS = frozenset({'parameters', 'pathParameters', 'queryParameters', 'rawQueryParameters', 'headers'})
KTOR_MEMBER_RE = re.compile(r'\.\s*(?:request|' + '|'.join(sorted(KTOR_SOURCE_MEMBERS)) + r')\b')
REQUEST_SOURCE_RE = re.compile(KOTLIN_SERVLET_SOURCE_RE.pattern + '|' + KTOR_MEMBER_RE.pattern)
KTOR_MAP_TAG = 'ktor-request-map'
FILE_LEAF_METHODS = frozenset({'readAllBytes', 'readString', 'readAllLines', 'write', 'writeString',
                               'newInputStream', 'newOutputStream', 'createFile'})
FILE_CONSTRUCTORS = frozenset({'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'RandomAccessFile'})


@dataclass(frozen=True)
class CallArguments:
    """Argument order, Kotlin labels and source spans for one evaluation."""
    spans: list[tuple[int, int]]
    names: list[str | None]
    values: list[Fact]

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
    declaration_scope: tuple = (-1, -1)
    member: bool = False


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
                start = self.skip(following + 1, len(self.code))
                end = self.end_statement(start, len(self.code))
                body = (Statement(start, end, 'return'),)
            owner = tuple(name for low, high, name in owners if low < match.start() < high)
            function = Function(match.start(), name, owner, start, end, tuple(parameters), frozenset(sources), body)
            function.parameter_declarations = tuple(parameter_declarations)
            function.declaration = self.code.rfind('fun', boundary, match.start()) if kotlin else function.key
            function.declaration_scope = max(
                ((low, high) for low, high in self.pairs.items()
                 if self.code[low] == '{' and low < function.key < high),
                default=(-1, len(self.code)), key=lambda scope: scope[0])
            function.member = any(self.code.find('{', low, high) == function.declaration_scope[0]
                                  for low, high, _ in owners if low < function.key < high)
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

    def array_initializer(self, opening):
        """Whether the Java `{` at `opening` opens an array initializer (GH #184).

        JLS 10.6 initializers follow `=` in a declaration (`T[] a = {...}`)
        or the dimensions of an array creation (`new T[]{...}`); nested
        initializers follow `{` or `,`. Their elements are expressions, so the
        braces evaluate like parentheses. Lambda bodies and anonymous class
        bodies (anywhere inside, too) contain statements and stay unsupported.
        Kotlin has no brace initializer: `= {` there is a lambda.
        """
        if self.kotlin:
            return False

        def shape(position, nested):
            previous = position - 1
            while previous >= 0 and self.code[previous].isspace():
                previous -= 1
            if previous < 0:
                return False
            char = self.code[previous]
            if nested and char in '{,':
                return True
            if char == '=':
                return previous == 0 or self.code[previous - 1] not in '=!<>'
            if char != ']':
                return False
            window = self.code[max(0, previous - 400):previous + 1]
            return re.search(r'\bnew\s+[A-Za-z_$][\w$.]*(?:\s*<[^;{}()]*>)?(?:\s*\[\s*\])+$', window) is not None

        if not shape(opening, False):
            return False
        close = self.pairs[opening]
        return all(shape(index, True) for index in range(opening + 1, close) if self.code[index] == '{')

    def end_statement(self, start, end):
        while start < end:
            char = self.code[start]
            if char == ';' or char == '}' or (self.kotlin and char in '\r\n'):
                return start
            if char in '([':
                start = self.pairs[start]
            elif char == '{':
                if not self.array_initializer(start):
                    raise ValueError('Unsupported Java/Kotlin expression block; analysis is incomplete')
                start = self.pairs[start]
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
        # Kotlin check(...) throws on a false condition exactly like require.
        requirement = re.match(r'(require|check)\s*\(', self.code[start:end]) if self.kotlin else None
        if requirement:
            opening = start + requirement.end() - 1
            close = self.pairs[opening]
            following = self.skip(close + 1, end)
            if self.code[following:following + 1] == '{':
                finish = self.pairs[following]
                if self.code[following + 1:finish].strip() not in {'', '0'}:
                    raise ValueError(f'Executable Kotlin {requirement.group(1)} message needs callback analysis; analysis is incomplete')
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
    parser_type = Parser
    source_re = SOURCE_RE
    sink_re = SINK_RE
    # The parser's guards for class initialization and parameter defaults; None uses sink_re.
    parser_sink_re = None
    sink_label = 'file sink'
    path_constructors = True
    request_receiver_sources = True

    def __init__(self, path, text):
        # FindingSink canonicalizes source locations; evidence and source keys
        # must identify that same file when selection used a symlink alias.
        self.path, self.text = path.resolve(), text
        self.parser = self.parser_type(text, path.suffix.lower() in {'.kt', '.kts'}, self.source_re,
                                       self.parser_sink_re or self.sink_re)
        self.code = self.parser.code
        self.lines = [0, *(index + 1 for index, char in enumerate(text) if char == '\n')]
        self.budget = Budget()
        self.summaries = {key: Summary() for key in self.parser.functions}
        self.graphs = {}
        self._request_index = None
        self._local_request_constructors = {}
        self.shadowed_fields = set()
        for match in re.finditer(r'\b([A-Za-z_]\w*)\s*(?::[^=;\n]+)?=(?!=)', self.code):
            if any(function.key != -1 and function.declaration <= match.start() < function.end
                   for function in self.parser.functions.values()):
                continue
            owner = tuple(name for low, high, name in self.parser.owners if low < match.start() < high)
            self.shadowed_fields.add((owner, match.group(1)))
        # A field can be assigned by a constructor, another method or caller.
        # Its declaration shadows a factory even without an initializer here.
        if self.parser.kotlin:
            declarations = re.finditer(r'\b(?:val|var)\s+([A-Za-z_]\w*)\s*:', self.code)
        else:
            declarations = re.finditer(
                r'\b[\w$]+(?:\.[\w$]+)*(?:\s*<[^;{}()]+>)?'
                r'(?:\s*\[\s*\])*\s+([A-Za-z_]\w*)(?:\s*\[\s*\])*\s*(?=[=,;])', self.code)
        for declaration in declarations:
            position = declaration.start(1)
            if any(function.key != -1 and function.declaration <= position < function.end
                   for function in self.parser.functions.values()):
                continue
            scopes = [(low, high, name) for low, high, name in self.parser.owners if low < position < high]
            if not self.parser.kotlin:
                if not scopes or position < self.code.find('{', scopes[-1][0], scopes[-1][1]):
                    continue
            owner = tuple(name for _, _, name in scopes)
            self.shadowed_fields.add((owner, declaration.group(1)))
            if self.parser.kotlin:
                continue
            end = declaration.end(1)
            while end < len(self.code) and self.code[end] not in ';}':
                if self.code[end] in '([{':
                    end = self.parser.pairs[end]
                end += 1
            if self.code[end:end + 1] == ';':
                for low, high in self.parser.parts(position, end):
                    name = re.match(r'\s*([A-Za-z_]\w*)(?:\s*\[\s*\])*\s*(?:=|$)', self.code[low:high])
                    if name:
                        self.shadowed_fields.add((owner, name.group(1)))
        if self.request_receiver_sources:
            self.check_request_initializers()

    def check_request_initializers(self):
        """Reject unmodeled request field flow only after proving its API."""
        def in_initializer(offset):
            owner = max((low for low, high, _ in self.parser.owners if low < offset < high), default=-1)
            if owner < 0:
                return False
            # A local class can capture its enclosing handler's request. Its
            # field initialization is not part of that handler's method body;
            # only a method declared inside this class excludes the access.
            return not any(function.key >= 0 and owner < function.declaration <= offset < function.end
                           for function in self.parser.functions.values())

        servlet_access = KOTLIN_SERVLET_SOURCE_RE if self.parser.kotlin else REQUEST_GETTER_RE
        for getter in servlet_access.finditer(self.code):
            offset = getter.start()
            signature = next((function for function in self.parser.functions.values()
                              if self.parser.kotlin and function.key >= 0 and function.key < offset < function.start), None)
            if not in_initializer(offset) and signature is None:
                continue
            index = self.request_index()
            property_ = REQUEST_PROPERTY_RE.fullmatch(getter.group()) is not None
            if property_ and self.code[self.parser.skip(getter.end(), len(self.code)):].startswith('('):
                continue  # A same-named extension call is not a synthetic property.
            receiver_end = offset
            if self.parser.kotlin and self.code[offset - 1:offset] == '?':
                receiver_end -= 1
            elif self.parser.kotlin and self.code[offset - 2:offset] == '!!':
                receiver_end -= 2
            receiver_start = index.receiver_start(receiver_end)
            actual = index.receiver_type(receiver_start, receiver_end)
            receiver_name = self.code[receiver_start:receiver_end].strip()
            if actual is None and signature is not None and receiver_name in signature.parameters:
                declaration = signature.parameter_declarations[signature.parameters.index(receiver_name)].split('=', 1)[0]
                parameter_type = re.fullmatch(r'\s*[A-Za-z_]\w*\s*:\s*([\w.]+\??)\s*', declaration)
                if parameter_type:
                    actual = index.resolve_type(parameter_type.group(1), signature.key)
            member = re.sub(r'\s+', '', getter.group()).lstrip('.').rstrip('(')
            method = REQUEST_PROPERTIES[member] if property_ else member
            arity = 0 if property_ else sum(1 for _ in self.parser.parts(getter.end(), self.parser.pairs[getter.end() - 1]))
            if (actual in (REQUEST_TYPES if method in SERVLET_BASE_GETTERS else HTTP_SERVLET_TYPES)
                    and self.request_getter_signature(method, offset, arity)):
                if signature is not None:
                    raise ValueError('Executable Kotlin Servlet parameter default needs call binding; analysis is incomplete')
                raise ValueError('Executable Java/Kotlin Servlet initialization needs field-state analysis; analysis is incomplete')
        if not self.parser.kotlin:
            return
        index = self.request_index()

        def captured_request(span, owner, seen=()):
            if len(seen) > 32:
                raise AnalysisLimit('Kotlin initializer alias depth exceeded; analysis is incomplete')
            low, high = span
            for access in re.finditer(r'[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*', self.code[low:high]):
                self.budget.spend()
                name = re.sub(r'\s+', '', access.group())
                field = name.startswith('this.')
                root = name.removeprefix('this.').split('.')[0]
                binding = index.binding(root, low + access.start(), field=field)
                if binding is None:
                    continue
                if index.resolve_type(binding.type_name, binding.declaration) in REQUEST_TYPES | KTOR_TYPES:
                    return True
                # Mutable captures can change after their declaration. A
                # fixed initializer does not prove their later captured value.
                if binding.declaration < owner and re.search(r'\bvar\s+$', self.code[:binding.declaration]):
                    return True
                if binding.initializer is not None:
                    if binding.declaration in seen:
                        raise AnalysisLimit('Cyclic Kotlin initializer aliases need field-state analysis; analysis is incomplete')
                    if captured_request(binding.initializer, owner, (*seen, binding.declaration)):
                        return True
            return False

        for bindings in index.bindings.values():
            for binding in bindings:
                if not binding.field or binding.initializer is None or not in_initializer(binding.initializer[0]):
                    continue
                owner = max(low for low, high, _ in self.parser.owners if low < binding.declaration < high)
                if captured_request(binding.initializer, owner, (binding.declaration,)):
                    raise ValueError('Executable Kotlin Ktor initialization needs captured-field analysis; analysis is incomplete')
        if not KTOR_MEMBER_RE.search(self.code):
            return
        for access in re.finditer(r'\b[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+', self.code):
            self.budget.spend()
            offset = access.start()
            if not in_initializer(offset):
                continue
            following = self.parser.skip(access.end(), len(self.code))
            arguments = [] if self.code[following:following + 1] == '(' else None
            value = self.ktor_access(re.sub(r'\s+', '', access.group()), arguments, offset, {}, {})
            if value and (any(trace.kind == 'source' for trace in value) or self.request_fact_types(value) & KTOR_TYPES):
                raise ValueError('Executable Kotlin Ktor initialization needs field-state analysis; analysis is incomplete')

    def call_is_shadowed(self, name, bindings):
        return name in bindings or any(
            field == name and owner == self.function.owner[:len(owner)]
            for owner, field in self.shadowed_fields)

    def step(self, offset, kind, label):
        line = bisect_right(self.lines, offset)
        if 0 <= line - 1 < len(self.lines):
            return Step(str(self.path), line, offset - self.lines[line - 1] + 1, kind, label[:160])
        raise ValueError('Invalid Java/Kotlin evidence offset; analysis is incomplete')

    def source(self, offset, label):
        return frozenset({Trace('source', (str(self.path), offset, label), evidence=(self.step(offset, 'source', label),))})

    def safe_sink_trace(self, trace):
        tags = trace.tags
        return 'contained-path' in tags or ('basename-path' in tags and (
            {'basename-not-dot', 'basename-not-dotdot'} <= tags or
            'file-leaf-sink' in tags or 'path-construction' in tags))

    def record(self, offset, value, file_leaf=False):
        if file_leaf:
            value = retag(value, add=frozenset({'file-leaf-sink'}))
        unsafe = frozenset(trace for trace in value if not self.safe_sink_trace(trace))
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN), advance(unsafe, self.step(offset, 'sink', self.sink_label)))

    def builtin_type(self, name):
        return not re.search(r'\b(?:class|interface|object|enum|typealias)\s+' + name + r'\b|\bimport\s+(?!java\.(?:lang|io|net|util|nio\.file)\.)[\w.]+\.' + name + r'\b|\bimport\s+[\w.]+\s+as\s+' + name + r'\b', self.code)

    def request_index(self):
        """Reuse the verified JVM import/binding index without an import cycle.

        The JDBC engine owns its own receiver semantics and disables this
        adapter. Imports are deferred until analysis, after analyzer discovery.
        """
        if self._request_index is None:
            if self.parser.kotlin:
                from ubs_core.analyzers.taint_kotlin_sql import KotlinJdbcSource
                self._request_index = KotlinJdbcSource(self.text, extra_apis=KTOR_TYPES | KTOR_COLLECTION_TYPES)
            else:
                from ubs_core.analyzers.taint_java_sql import JdbcSource, LIMIT_DEFAULTS
                self._request_index = JdbcSource(self.text, tuple(LIMIT_DEFAULTS.values()))
        return self._request_index

    @staticmethod
    def request_fact_types(value):
        return frozenset(tag[len(REQUEST_TYPE_PREFIX):] for trace in value for tag in trace.tags
                         if tag.startswith(REQUEST_TYPE_PREFIX))

    def local_request_constructor(self, declaration):
        """Prove a simple inferred local class cannot be a request API.

        A same-named factory or callable binding, imported classifier, or any
        superclass/delegation clause makes this bounded negative inconclusive.
        """
        key = declaration.declaration
        if key in self._local_request_constructors:
            return self._local_request_constructors[key]
        self._local_request_constructors[key] = False
        if not self.parser.kotlin or declaration.initializer is None:
            return False
        index = self.request_index()
        low, high = index.trim(*declaration.initializer)
        constructor = re.match(r'([A-Za-z_]\w*)\s*\(', self.code[low:high])
        if not constructor or self.parser.pairs.get(low + constructor.end() - 1) != high - 1:
            return False
        name = constructor.group(1)
        binding = index.binding(name, low)
        if binding is None or (binding.low < 0 and name in index.imports):
            return False
        if any(function.name == name for function in self.parser.functions.values()):
            return False
        for start, end, owner in self.parser.owners:
            header = re.match(r'class\s+', self.code[start:end])
            if owner != name or not header or start + header.end() != binding.declaration:
                continue
            cursor = binding.declaration + len(name)
            while cursor < end and self.code[cursor] != '{':
                if self.code[cursor] == ':':
                    return False
                cursor = self.parser.pairs[cursor] + 1 if self.code[cursor] in '([' else cursor + 1
            self._local_request_constructors[key] = True
            return True
        return False

    def request_receiver(self, name, offset, bindings, state, receiver=CLEAN):
        """Return selected request types and whether a declaration is known.

        Explicit API declarations override a value's carried type. Unresolved
        legacy snippets retain their existing heuristic; a resolved local or
        standard non-Servlet type cannot become a source merely by its name.
        """
        index = self.request_index()
        root = name.removeprefix('this.')
        if not root and not receiver:
            # Parenthesized/cast receivers are separate atoms in the shared
            # expression frontend. The lexical binding index can still prove
            # their static API identity without guessing from a method name.
            dot = offset if self.code[offset:offset + 1] == '.' or self.code[offset:offset + 2] in {'?.', '!!'} else offset - 1
            while dot >= 0 and self.code[dot].isspace():
                dot -= 1
            if dot >= 0 and (self.code[dot] == '.' or self.parser.kotlin and self.code[dot:dot + 2] in {'?.', '!!'}):
                low = index.receiver_start(dot)
                actual = index.receiver_type(low, dot)
                if actual in REQUEST_TYPES | KTOR_TYPES:
                    return frozenset({actual}), True
        if re.fullmatch(r'[A-Za-z_]\w*', root):
            receiver = state.get(bindings.get(root, root), receiver)
            declaration = index.binding(root, offset, field=name.startswith('this.'))
            if declaration:
                spelling = declaration.type_name.rstrip('?')
                actual = index.resolve_type(spelling, declaration.declaration)
                if actual in REQUEST_TYPES | KTOR_TYPES:
                    return frozenset({actual}), True
                if actual in {'com.sun.net.httpserver.HttpExchange', 'com.sun.net.httpserver.HttpsExchange'}:
                    return frozenset(), False  # Preserve the separate JDK HTTP source contract.
                if spelling == 'var' and self.local_request_constructor(declaration):
                    return frozenset(), True
                if spelling != 'var':
                    head = spelling.split('.', 1)[0]
                    local_type = any(local == head and low < declaration.declaration < high
                                     for local, low, high in index.classes)
                    inherited = re.search(r'\b(?:class|interface|object)\s+' + re.escape(head) +
                                          r'\b[^{};]*(?:\bextends\b|\bimplements\b|:)', self.code)
                    # An external or inherited type can implement ServletRequest;
                    # this bounded index does not prove a negative for it.
                    known = actual is not None or local_type and not inherited
                    if known:
                        return frozenset(), True
        types = self.request_fact_types(receiver)
        return types & (REQUEST_TYPES | KTOR_TYPES), bool(types)

    def ktor_access(self, name, arguments, offset, bindings, state, receiver=CLEAN):
        """Follow actual Ktor members without treating extension calls as properties.

        Parameters/Headers objects are not input merely because of their type.
        Their provenance starts at a verified request member and survives the
        same aliases and summaries as other facts in the shared JVM engine.
        """
        if not self.request_receiver_sources or not self.parser.kotlin or '.' not in name:
            return None
        parts = name.split('.')
        if parts[0] == 'this' and len(parts) > 2:
            root, members = '.'.join(parts[:2]), parts[2:]
        else:
            root, members = parts[0], parts[1:]
        value = state.get(bindings.get(root, root), receiver)
        map_value = any(KTOR_MAP_TAG in trace.tags for trace in value)
        if not map_value and not any(member in KTOR_SOURCE_MEMBERS | {'request'} for member in members):
            return None
        types, _ = self.request_receiver(root, offset, bindings, state, value)
        types &= KTOR_TYPES
        if not types and not map_value:
            return None
        if types and not value:
            value = frozenset({Trace('request-object', (str(self.path), offset),
                tags=frozenset(REQUEST_TYPE_PREFIX + actual for actual in types))})
        selected = False
        for position, member in enumerate(members):
            self.budget.spend()
            if arguments is not None and position == len(members) - 1:
                if member == 'get' and len(arguments) == 1 and any(KTOR_MAP_TAG in trace.tags for trace in value):
                    return retag(self.without_request_identity(join(value, *arguments)), add=frozenset({'jvm-string'}))
                # Unknown extensions keep existing receiver/argument taint but
                # cannot return a proven request object by their name alone.
                return self.without_request_identity(join(value, *arguments)) if selected else None
            if member == 'request' and types & KTOR_CALL_TYPES:
                result_types = frozenset({
                    'io.ktor.server.application.ApplicationCall': 'io.ktor.server.request.ApplicationRequest',
                    'io.ktor.server.application.PipelineCall': 'io.ktor.server.request.PipelineRequest',
                    'io.ktor.server.routing.RoutingCall': 'io.ktor.server.routing.RoutingRequest',
                }[actual] for actual in types & KTOR_CALL_TYPES)
                value = retag(self.without_request_identity(value),
                              add=frozenset(REQUEST_TYPE_PREFIX + actual for actual in result_types))
                types, selected = result_types, True
            elif ((member == 'parameters' and types & KTOR_CALL_TYPES)
                  or (member in {'queryParameters', 'rawQueryParameters', 'headers'} and types & KTOR_REQUEST_TYPES)
                  or (member in {'pathParameters', 'queryParameters'} and 'io.ktor.server.routing.RoutingCall' in types)):
                label = '.'.join([root, *members[:position + 1]])
                value = retag(self.source(offset, label), add=frozenset({KTOR_MAP_TAG, 'jvm-string'}))
                types, selected = frozenset(), True
            else:
                value = self.without_request_identity(value)
                types = frozenset()
        return value if selected else None

    def request_getter_signature(self, method, offset, arity):
        if arity != REQUEST_GETTERS[method]:
            return False
        if method in REQUEST_COLLECTIONS and arity == 1:
            # Kotlin may choose a same-arity extension for a non-String key.
            # Unresolved applicability cannot establish a request source or
            # silently turn a genuine request getter into a clean call.
            opening = self.code.find('(', offset)
            if opening in self.parser.pairs:
                spans = list(self.parser.parts(opening + 1, self.parser.pairs[opening]))
                if len(spans) == 1:
                    kind = self.request_argument_kind(*spans[0])
                    if kind is None and self.parser.kotlin:
                        raise ValueError('Kotlin Servlet collection getter needs String-key type proof; analysis is incomplete')
                    if kind in {'number', 'other'}:
                        return False
        return True

    def request_call(self, name, arguments, offset, bindings, state, receiver=CLEAN):
        if not self.request_receiver_sources:
            return None
        collection = self.request_collection_access(name, arguments, offset, bindings, state, receiver)
        if collection is not None:
            return collection
        ktor = self.ktor_access(name, arguments, offset, bindings, state, receiver)
        if ktor is not None:
            return ktor
        root, _, method = name.rpartition('.')
        property_ = self.parser.kotlin and arguments is None and method in REQUEST_PROPERTIES
        if arguments is None:
            if not property_:
                return None
            method = REQUEST_PROPERTIES[method]
        if method not in REQUEST_GETTERS:
            return None
        types, _ = self.request_receiver(root, offset, bindings, state, receiver)
        types &= REQUEST_TYPES
        if not types:
            return None
        arity = 0 if property_ else len(arguments)
        if (not self.request_getter_signature(method, offset, arity)
                or method not in SERVLET_BASE_GETTERS and not types & HTTP_SERVLET_TYPES):
            # A Kotlin extension/overload can have this name and return one
            # of its arguments. An unsupported signature is not a sanitizer.
            return None
        source = self.source(offset, name if property_ else name + '(')
        if method in REQUEST_COLLECTIONS:
            return self.collection_value(source, REQUEST_COLLECTIONS[method])
        return retag(source, add=frozenset({'jvm-string'}))

    @staticmethod
    def collection_value(value, kind):
        """Carry request contents separately from the container's metadata."""
        tags = frozenset({'jvm-string' if kind == 'string' else COLLECTION_PREFIX + kind})
        return retag(value, add=tags, remove=COLLECTION_TAGS | frozenset({'jvm-string', 'jvm-path'}) | PATH_PROOF_TAGS)

    def collection_argument_kind(self, value, span):
        """Prove native Kotlin key/index applicability before retagging values."""
        kinds = set()
        for trace in value:
            shapes = trace.tags & COLLECTION_TAGS
            if len(shapes) == 1:
                kinds.add(next(iter(shapes)).removeprefix(COLLECTION_PREFIX))
            else:
                kinds.add(None)
        if len(kinds) == 1 and None not in kinds:
            return next(iter(kinds))
        if span is None:
            return None
        low, high = span
        kind = self.request_argument_kind(low, high)
        if kind == 'number':
            # Array.get takes Int, not Long/Double/Char. A same-name extension
            # for those types must not inherit String sanitizer eligibility.
            actual = self.request_index().argument_type(low, high)
            return 'int' if actual == ('api', 'java.lang.Integer') else 'other'
        return kind

    def collection_member(self, receiver, member, arguments, offset=None, spans=None):
        """Evaluate selected native collection members, never same-name guesses.

        A source-derived map/array/enumeration transports its contents through
        extraction. Native size/presence queries instead produce bounded scalar
        metadata. Every possible receiver must prove the same contract before
        discarding provenance; an unknown member keeps the ordinary conservative
        call semantics and loses container identity.
        """
        if not receiver:
            return None
        kinds = []
        for trace in receiver:
            shapes = trace.tags & COLLECTION_TAGS
            if len(shapes) != 1:
                return None
            kinds.append(next(iter(shapes)).removeprefix(COLLECTION_PREFIX))
        arity = None if arguments is None else len(arguments)
        actuals = None
        if self.parser.kotlin and arguments:
            if spans is None and offset is not None:
                opening = self.code.find('(', offset)
                if opening in self.parser.pairs:
                    spans = list(self.parser.parts(opening + 1, self.parser.pairs[opening]))
            actuals = [self.collection_argument_kind(value, spans[index] if spans and index < len(spans) else None)
                       for index, value in enumerate(arguments)]
        result = None
        for kind in kinds:
            if actuals is not None:
                signatures = {
                    'parameter-map': {'get': ['string'], '[]': ['string'],
                                      'getOrDefault': ['string', 'string-array'],
                                      'containsKey': ['string'], 'containsValue': ['string-array']},
                    'string-array': {'get': ['int'], '[]': ['int']},
                    'string-collection': {'contains': ['string'], 'containsAll': ['string-collection']},
                    'array-collection': {'contains': ['string-array'], 'containsAll': ['array-collection']},
                }
                if signatures.get(kind, {}).get(member) != actuals:
                    return None
            selected = None
            if kind == 'parameter-map':
                if ((member, arity) in {('get', 1), ('getOrDefault', 2)}
                        or self.parser.kotlin and (member, arity) == ('[]', 1)):
                    selected = 'string-array'
                elif ((member, arity) == ('keySet', 0) and not self.parser.kotlin
                      or (member, arity) == ('keys', None) and self.parser.kotlin):
                    selected = 'string-collection'
                elif ((member, arity) == ('values', 0) and not self.parser.kotlin
                      or (member, arity) == ('values', None) and self.parser.kotlin):
                    selected = 'array-collection'
                elif ((member, arity) in {('isEmpty', 0), ('containsKey', 1), ('containsValue', 1)}
                      or (member, arity) == ('size', None if self.parser.kotlin else 0)):
                    selected = 'metadata'
            elif kind == 'string-array':
                if ((member, arity) in {('[]', 1), ('<foreach>', 0)}
                        or self.parser.kotlin and (member, arity) == ('get', 1)):
                    selected = 'string'
                elif (member, arity) == ('size' if self.parser.kotlin else 'length', None):
                    selected = 'metadata'
                elif (member, arity) == ('clone', 0):
                    selected = kind
            elif kind == 'string-enumeration':
                if (member, arity) == ('nextElement', 0):
                    selected = 'string'
                elif (member, arity) == ('asIterator', 0):
                    selected = 'string-iterator'
                elif (member, arity) == ('hasMoreElements', 0):
                    selected = 'metadata'
            elif kind in {'string-collection', 'array-collection'}:
                if (member, arity) == ('iterator', 0):
                    selected = kind.replace('collection', 'iterator')
                elif (member, arity) == ('<foreach>', 0):
                    selected = 'string' if kind == 'string-collection' else 'string-array'
                elif ((member, arity) in {('isEmpty', 0), ('contains', 1), ('containsAll', 1)}
                      or (member, arity) == ('size', None if self.parser.kotlin else 0)):
                    selected = 'metadata'
            elif kind in {'string-iterator', 'array-iterator'}:
                if (member, arity) == ('next', 0):
                    selected = 'string' if kind == 'string-iterator' else 'string-array'
                elif (member, arity) == ('hasNext', 0):
                    selected = 'metadata'
            if selected is None or result is not None and result != selected:
                return None
            result = selected
        if result == 'metadata':
            return CLEAN
        # An untrusted selector does not confer String/array API identity on
        # itself. The contents carry the selected shape; a default value keeps
        # its own facts and shape until an actual extraction proves otherwise.
        value = self.collection_value(receiver, result)
        if member == 'getOrDefault' and arguments is not None:
            value = join(value, arguments[1])
        return value

    def request_collection_access(self, name, arguments, offset, bindings, state, receiver=CLEAN):
        parts = name.split('.')
        if len(parts) < 2:
            return None
        if parts[0] == 'this' and len(parts) > 2:
            root, members = '.'.join(parts[:2]), parts[2:]
        else:
            root, members = parts[0], parts[1:]
        value = state.get(bindings.get(root, root), receiver)
        for position, member in enumerate(members):
            value = self.collection_member(value, member, arguments if position == len(members) - 1 else None, offset)
            if value is None:
                return None
        return value

    def request_argument_kind(self, low, high, seen=()):
        """Bounded static argument evidence for a local String overload.

        Reuse the JVM declaration/cast index. Java ``var`` keeps its inferred
        type after assignment, and arithmetic on proven numeric operands
        cannot select a String overload. Unknown expressions stay unknown.
        """
        index = self.request_index()
        if low >= high or (low, high) in seen or len(seen) >= 32:
            return None
        seen = (*seen, (low, high))
        # The lexical mask represents quoted text with a numeric placeholder;
        # characters can be entirely blank. Preserve the original literal's
        # extent before the binding index trims masked whitespace away.
        literal_low, literal_high = low, high
        while literal_low < literal_high:
            while literal_low < literal_high and self.text[literal_low].isspace():
                literal_low += 1
            while literal_high > literal_low and self.text[literal_high - 1].isspace():
                literal_high -= 1
            if self.text[literal_low:literal_low + 1] != '(' or self.parser.pairs.get(literal_low) != literal_high - 1:
                break
            literal_low, literal_high = literal_low + 1, literal_high - 1
        raw = self.text[literal_low:literal_high]
        if re.fullmatch(r'"(?:\\.|[^"\\])*"', raw):
            return 'string'
        if re.fullmatch(r"(?:[+-]?\d[\w.]*|'(?:\\.|[^'\\])+')", raw):
            return 'number'
        if raw in {'true', 'false'}:
            return 'other'
        low, high = index.trim(low, high)
        if low >= high:
            return None
        # Split compound expressions before using cast evidence: a leading
        # numeric cast does not make `(Integer) value + "key"` numeric.
        cursor, operator = low, None
        while cursor < high:
            char = self.code[cursor]
            if char in '([{':
                cursor = self.parser.pairs[cursor] + 1
                continue
            if char in '?:=<>!&|^':
                # A leading cast only types its operand, not an enclosing
                # comparison, conditional or other compound expression.
                return None
            if char in '+-*/%' and operator is None:
                operator = cursor, char
            cursor += 1
        if operator is not None:
            cursor, char = operator
            if cursor == low and char in '+-':
                kind = self.request_argument_kind(cursor + 1, high, seen)
                return kind if kind == 'number' else None
            left = self.request_argument_kind(low, cursor, seen)
            right = self.request_argument_kind(cursor + 1, high, seen)
            if char == '+' and 'string' in {left, right}:
                return 'string'
            return 'number' if left == right == 'number' else None
        if self.code[low] == '(':
            closing = self.parser.pairs[low]
            cast = self.code[low + 1:closing].strip()
            operand = index.skip(closing + 1)
            if (not re.fullmatch(r'[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*', cast)
                    or operand >= high or self.code[operand] in '.['):
                # A grouped receiver followed by .toString()/substring() is
                # not a cast of that whole call's result. The declaration
                # index intentionally does not resolve such postfix returns.
                return None
        call = re.match(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(', self.code[low:high])
        if call and self.parser.pairs.get(low + call.end() - 1) == high - 1:
            spelling = call.group(1)
            receiver, _, method = spelling.rpartition('.')
            if receiver and method in REQUEST_GETTERS and method not in REQUEST_COLLECTIONS:
                actual = index.receiver_type(low, low + len(receiver))
                spans = list(self.parser.parts(low + call.end(), high - 1))
                if (actual in (REQUEST_TYPES if method in SERVLET_BASE_GETTERS else HTTP_SERVLET_TYPES)
                        and len(spans) == REQUEST_GETTERS[method]
                        and all(self.request_argument_kind(*span, seen) == 'string' for span in spans)):
                    return 'string'
        actual = index.argument_type(low, high)
        if self.parser.kotlin and call and actual is not None and actual[0] != 'api':
            # The shared nominal index also treats call spellings as possible
            # constructors. A qualified function can return String; its name
            # alone cannot prove an incompatible argument type.
            actual = None
        if actual is not None:
            if actual == ('api', 'java.lang.String'):
                return 'string'
            if actual in {('api', 'java.lang.Integer'), ('api', 'java.lang.Long')}:
                return 'number'
            return 'other'
        name = re.sub(r'\s+', '', self.code[low:high])
        binding = index.binding(name.removeprefix('this.'), low, field=name.startswith('this.'))
        primitive_numbers = {'byte', 'short', 'int', 'long', 'float', 'double', 'char'}
        if binding is not None:
            if binding.type_name in primitive_numbers:
                return 'number'
            if binding.type_name == 'boolean':
                return 'other'
            if binding.type_name == 'var' and binding.initializer is not None:
                return self.request_argument_kind(*binding.initializer, seen)
        if self.parser.kotlin:
            # These standard factories have a non-String result. Qualify their
            # callable identity: a local function/import named listOf may
            # instead return a String and cannot borrow this negative proof.
            if call and self.parser.pairs.get(low + call.end() - 1) == high - 1:
                spelling = call.group(1)
                root, _, tail = spelling.partition('.')
                factories = {'listOf', 'mutableListOf', 'setOf', 'mutableSetOf',
                             'arrayListOf', 'hashSetOf', 'linkedSetOf', 'mapOf', 'mutableMapOf'}
                actual = index.imports.get(root)
                if actual is not None:
                    actual += '.' + tail if tail else ''
                elif '.' in spelling:
                    actual = spelling
                elif root in factories and not index.wildcards:
                    actual = 'kotlin.collections.' + root
                if (actual in {'kotlin.collections.' + name for name in factories}
                        and index.binding(root, low) is None
                        and not any(name == root and start < low < end for name, start, end in index.classes)):
                    return 'other'
        if self.code[low] == '(' and self.parser.pairs[low] < high - 1:
            cast = self.code[low + 1:self.parser.pairs[low]].strip()
            if cast in primitive_numbers | {'boolean'}:
                return 'other' if cast == 'boolean' else 'number'
        return None

    def bodyless_request_getter(self, root, method, offset):
        """An opaque local getter cannot prove a named request source clean.

        Preserve the existing heuristic for a selected declaration without a
        body, not Servlet identity for every interface. Concrete/default method
        bodies and inherited dispatch keep their existing receiver semantics.
        """
        if self.parser.kotlin:
            return False
        index = self.request_index()
        name = root.removeprefix('this.')
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            return False
        binding = index.binding(name, offset, field=root.startswith('this.'))
        if binding is None:
            return False

        def local_type(spelling, position):
            parts, candidates = spelling.split('.'), []
            for low, high, owner in self.parser.owners:
                chain = [(start, end, parent) for start, end, parent in self.parser.owners
                         if start < low < end] + [(low, high, owner)]
                if [item[2] for item in chain[-len(parts):]] != parts:
                    continue
                scope = index.scope(chain[-len(parts)][0])
                if scope[0] < position < scope[1]:
                    candidates.append((scope[1] - scope[0], low, high))
            return min(candidates) if candidates else None

        selected = local_type(binding.type_name, binding.declaration)
        if selected is None:
            return False
        opening = self.code.find('(', offset)
        if opening not in self.parser.pairs:
            return False
        arguments = list(self.parser.parts(opening + 1, self.parser.pairs[opening]))
        if len(arguments) != REQUEST_GETTERS[method]:
            return False
        argument_kind = self.request_argument_kind(*arguments[0]) if arguments else None
        result_type = r'String\s*\[\s*\]' if method == 'getParameterValues' else r'String'
        signature = r'\b(?:java\.lang\.)?' + result_type + r'\s+' + re.escape(method) + r'\s*\('

        def getter_tails(owner):
            _, low, high = owner
            body = self.code.find('{', low, high)
            for match in re.finditer(signature, self.code[body + 1:high]):
                start = body + 1 + match.start()
                if index.scope(start) != (body, high):
                    continue
                parameter_open = body + match.end()
                parameter_close = self.parser.pairs[parameter_open]
                parameters = list(self.parser.parts(parameter_open + 1, parameter_close))
                if len(parameters) != len(arguments):
                    continue
                if parameters:
                    declaration = re.sub(r'@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\s*\([^)]*\))?',
                                         ' ', self.code[parameters[0][0]:parameters[0][1]])
                    parameter = re.fullmatch(r'\s*(?:final\s+)?((?:java\.lang\.)?String)\s+[A-Za-z_]\w*\s*',
                                             declaration)
                    if not parameter:
                        continue
                    parameter_type = index.nominal_type(parameter.group(1), parameters[0][0])
                    if parameter_type == ('api', 'java.lang.String') and argument_kind in {'number', 'other'}:
                        continue
                yield index.skip(parameter_close + 1), high

        # The declaration may be abstract while this exact local object is
        # concrete. Only an unchanged, explicit allocation and an actual
        # literal-returning implementation can suppress that opaque fallback.
        if binding.initializer is not None and not binding.field:
            low, high = index.trim(*binding.initializer)
            constructor = re.fullmatch(r'new\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(\s*\)', self.code[low:high])

            def repeated_end(statements):
                end = offset
                for statement in statements:
                    if statement.start <= offset < statement.end:
                        if statement.kind in {'for', 'while', 'do'} and (
                                high <= statement.start or statement.kind == 'for' and
                                statement.header[0] <= binding.declaration < statement.header[1]):
                            end = max(end, statement.end)
                        end = max(end, repeated_end(statement.body), repeated_end(statement.otherwise))
                return end

            # A write later in an enclosing loop can reach this earlier call
            # on its next iteration unless the loop body recreates the object
            # before each call. A for initializer runs only once, so its later
            # writes still reach the call across the backedge.
            finish = repeated_end(self.function.body)
            reassigned = any(index.binding(name, high + match.start()) == binding
                             for match in re.finditer(r'(?<![\w$.])' + re.escape(name) + r'\s*=(?!=)',
                                                      self.code[high:finish]))
            concrete = local_type(constructor.group(1), low) if constructor and not reassigned else None
            if concrete is not None and re.match(r'class\s+', self.code[concrete[1]:]):
                for tail, _ in getter_tails(concrete):
                    if self.code[tail:tail + 1] == '{' and re.fullmatch(
                            r'\s*return\s+"(?:\\.|[^"\\])*"\s*;\s*',
                            self.text[tail + 1:self.parser.pairs[tail]]):
                        return False
        for tail, high in getter_tails(selected):
            if re.match(r'(?:throws\s+[\w.,\s]+)?;', self.code[tail:high]):
                return True
        return False

    def named_request_source(self, name, offset, bindings, state):
        if not self.request_receiver_sources:
            return True
        if self.parser.kotlin:
            parts = name.split('.')
            if len(parts) == 1 and name in KTOR_SOURCE_MEMBERS | {'params'}:
                # A declared collection is ordinary data until a source
                # assignment supplies provenance; its spelling is no proof.
                return name not in bindings and self.request_index().binding(name, offset) is None
            member = parts[-2] if len(parts) > 2 and parts[-1] in {'get', 'getAll'} else parts[-1]
            if len(parts) > 1 and member in KTOR_SOURCE_MEMBERS:
                root = '.'.join(parts[:2]) if parts[0] == 'this' else parts[0]
                _, known = self.request_receiver(root, offset, bindings, state)
                if known:
                    # The member adapter supplies real sources. A known
                    # lookalike or a same-named extension supplies none.
                    return False
        root, _, method = name.rpartition('.')
        if not root:
            return True
        # Multipart accessors and unrelated framework property paths retain
        # their own existing source contracts outside this Servlet adapter.
        if method not in REQUEST_GETTERS:
            return True
        types, known = self.request_receiver(root, offset, bindings, state)
        if types:
            if not types & REQUEST_TYPES:
                return False
            opening = self.code.find('(', offset)
            if opening in self.parser.pairs:
                arity = sum(1 for _ in self.parser.parts(opening + 1, self.parser.pairs[opening]))
                if (not self.request_getter_signature(method, offset, arity)
                        or method not in SERVLET_BASE_GETTERS and not types & HTTP_SERVLET_TYPES):
                    return False
        return bool(types) or not known or self.bodyless_request_getter(root, method, offset)

    def without_request_identity(self, value):
        if not self.request_receiver_sources:
            return value
        return retag(value, remove=frozenset(tag for trace in value for tag in trace.tags
                                            if tag.startswith(REQUEST_TYPE_PREFIX) or tag == KTOR_MAP_TAG) | COLLECTION_TAGS)

    def parameter_tags(self, declaration):
        declaration = declaration.split('=', 1)[0].strip()
        if self.request_receiver_sources:
            if self.parser.kotlin:
                array = re.fullmatch(r'[A-Za-z_]\w*\s*:\s*(?:kotlin\.)?Array\s*<\s*((?:[\w.]+)\??)\s*>\s*\??', declaration)
                builtin_array = self.builtin_type('Array')
            else:
                array = re.fullmatch(r'(?:final\s+)?([\w.]+)\s*\[\s*\]\s*[A-Za-z_]\w*', declaration)
                if array is None:
                    array = re.fullmatch(r'(?:final\s+)?([\w.]+)\s+[A-Za-z_]\w*\s*\[\s*\]', declaration)
                builtin_array = True
            if array and builtin_array:
                function = getattr(self, 'function', None)
                actual = self.request_index().resolve_type(array.group(1), function.key if function else 0)
                if actual == 'java.lang.String':
                    return frozenset({COLLECTION_PREFIX + 'string-array'})
        type_name = r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*'
        if self.parser.kotlin:
            match = re.fullmatch(r'[A-Za-z_]\w*\s*:\s*(' + type_name + r')\s*\??', declaration)
        else:
            match = re.fullmatch(r'(?:final\s+)?(' + type_name + r')\s+[A-Za-z_]\w*', declaration)
        if not match:
            return frozenset()
        actual = match.group(1)
        request_tags = frozenset()
        if self.request_receiver_sources:
            function = getattr(self, 'function', None)
            resolved = self.request_index().resolve_type(actual, function.key if function else 0)
            if resolved in REQUEST_TYPES | KTOR_TYPES:
                request_tags = frozenset({REQUEST_TYPE_PREFIX + resolved})
        types = {'String': 'jvm-string', 'java.lang.String': 'jvm-string', 'kotlin.String': 'jvm-string',
                 'Path': 'jvm-path', 'java.nio.file.Path': 'jvm-path', 'File': 'jvm-path', 'java.io.File': 'jvm-path'}
        tag = types.get(actual)
        return request_tags | (frozenset({tag}) if tag and self.builtin_type(actual.rsplit('.', 1)[-1]) else frozenset())

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

    def files_call(self, name, bindings):
        owner = name.rpartition('.')[0]
        return ((owner == 'java.nio.file.Files' and 'java' not in bindings) or
                (owner == 'Files' and 'Files' not in bindings and self.builtin_type('Files')))

    def joined_path(self, receiver, arguments):
        # A basename is a leaf only in the final component. Moving it into a
        # directory position must retain the dependency without the leaf proof:
        # getFileName("..") followed by a child can escape the intended root.
        result = retag(receiver, remove=PATH_PROOF_TAGS)
        for index, argument in enumerate(arguments):
            remove = PATH_PROOF_TAGS - BASENAME_TAGS if index == len(arguments) - 1 else PATH_PROOF_TAGS
            result = join(result, retag(argument, remove=remove))
        return retag(result, add=frozenset({'jvm-path'}), remove=frozenset({'jvm-string'}))

    def external_call(self, name, arguments, value, offset, bindings, state):
        root, _, method = name.rpartition('.')
        if name in {'File', 'Path.of', 'Paths.get'} and self.builtin_type(name.split('.')[0]) and name.split('.')[0] not in bindings:
            if len(arguments) > 1:
                return self.joined_path(CLEAN, arguments)
            return retag(value, add=frozenset({'jvm-path'}), remove=frozenset({'jvm-string'}))
        if self.files_call(name, bindings) and method in {'write', 'writeString'} and arguments:
            # Both APIs return the path operand, never the bytes/characters
            # written to it. Content taint must not become a later path flow.
            return retag(arguments[0], add=frozenset({'jvm-path'}))
        if method in {'resolve', 'resolveSibling'}:
            if self.path_receiver(root, bindings, state):
                receiver = state.get(bindings.get(root, root), CLEAN)
                return self.joined_path(receiver, arguments)
        if method in {'getFileName', 'getName'} and not arguments:
            if self.path_receiver(root, bindings, state):
                return retag(value, add=frozenset({'jvm-path'}))
        if method in {'normalize', 'toRealPath', 'getCanonicalPath', 'getCanonicalFile'} and not arguments and self.path_receiver(root, bindings, state):
            return retag(value, add=frozenset({'jvm-path'}))
        if method in {'toString', 'toFile'} and not arguments:
            return value
        return retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if arguments and name in {'getFileName', 'getName', 'normalize', 'toRealPath', 'getCanonicalPath', 'getCanonicalFile', 'toString', 'toFile'}:
            return retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))
        if (name in {'getFileName', 'getName', 'fileName', 'name', 'normalize', 'toRealPath',
                     'getCanonicalPath', 'getCanonicalFile', 'toFile'}
                and any('jvm-path' not in trace.tags for trace in value)):
            # A String extension can use the same name as a filesystem API.
            # Once rendered to text, a path needs a verified conversion before
            # those member contracts can preserve basename or containment proof.
            return retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))
        if name in {'getFileName', 'getName', 'fileName', 'name'}:
            if all('jvm-path' in trace.tags for trace in value):
                rendered = name in {'getName', 'name'}
                return retag(value, add=frozenset({'basename-path', 'jvm-string' if rendered else 'jvm-path'}),
                             remove=PATH_PROOF_TAGS | frozenset({'jvm-path' if rendered else 'jvm-string'}))
            return value
        if name in {'toString', 'getCanonicalPath'}:
            remove = frozenset({'jvm-path', 'canonical-path'})
            if name == 'getCanonicalPath':
                remove |= BASENAME_TAGS
            return retag(value, add=frozenset({'jvm-string'}), remove=remove)
        if name in {'normalize', 'toRealPath', 'getCanonicalFile'}:
            if name != 'normalize':
                # These APIs return absolute paths. A formerly relative leaf
                # can then override a root passed to Path.resolve().
                value = retag(value, remove=BASENAME_TAGS)
            return join(*(retag(frozenset({trace}), add=frozenset({'canonical-path'}))
                          if 'jvm-path' in trace.tags else frozenset({trace}) for trace in value))
        if name in {'resolve', 'resolveSibling'}:
            if direct_call:
                return value
            if arguments is not None and receiver and all('jvm-path' in trace.tags for trace in receiver):
                return self.joined_path(receiver, arguments)
            return retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))
        if name == 'toFile':
            return value
        # The first qualified call was checked by external_call. A later
        # member in a fluent chain has no such receiver/API proof: an unknown
        # transformation must not carry containment or Path identity forward.
        return value if direct_call else retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))

    def call_sink(self, name, call, value, offset, bindings):
        arguments = call.values
        if self.files_call(name, bindings) and self.sink_re.search(name + '('):
            method = name.rsplit('.', 1)[-1]
            indexes = (0, 1) if method in {'copy', 'move'} else (0,)
            for index in indexes:
                if index < len(arguments):
                    # A two-argument copy cannot replace an existing directory
                    # target. Its source remains potentially directory-capable.
                    leaf = method in FILE_LEAF_METHODS or (method == 'copy' and index == 1 and len(arguments) == 2)
                    self.record(offset, arguments[index], file_leaf=leaf)
            return False
        owner, _, constructor = name.rpartition('.')
        constructor = constructor or name
        if (constructor in FILE_CONSTRUCTORS and arguments and
                ((owner == 'java.io' and 'java' not in bindings) or
                 (not owner and constructor not in bindings and self.builtin_type(constructor)))):
            self.record(offset, arguments[0], file_leaf=True)
            return False
        if self.sink_re.search(name + '('):
            if name in {'File', 'Path.of', 'Paths.get'} or name.endswith('.resolve'):
                return True
            self.record(offset, value)
        return False

    def _discharged_construction(self, summary, trace):
        ctor_tags = frozenset(tag for tag in trace.tags if tag.startswith('ctor-site:'))
        matches = [
            item for item in summary.returned
            if item.kind == trace.kind
            and item.key == trace.key
            and (
                not (ctor_tags and (item_ctors := frozenset(tag for tag in item.tags if tag.startswith('ctor-site:'))))
                or (ctor_tags <= item_ctors)
            )
        ]
        if not matches or not all('contained-path' in item.tags for item in matches):
            return False
        if ctor_tags and not any(
            ctor_tags <= frozenset(tag for tag in item.tags if tag.startswith('ctor-site:'))
            for item in matches
        ):
            return False
        return True

    def summary_effect(self, summary, fact):
        # Construction diagnostics are retained unless this selected helper
        # proves containment for every return of the same constructed Path value.
        return frozenset(
            trace for trace in fact
            if not self.safe_sink_trace(trace)
            and ('path-construction' not in trace.tags or not self._discharged_construction(summary, trace))
        )

    def summary_return(self, fact, offset):
        return fact

    def guard_facts(self, span):
        start, end = span
        while start < end and self.text[start].isspace():
            start += 1
        while end > start and self.text[end - 1].isspace():
            end -= 1
        if self.code[start:start + 1] == '(' and self.parser.pairs.get(start) == end - 1:
            return self.guard_facts((start + 1, end - 1))
        for operator, truth in (('||', False), ('&&', True)):
            cursor, beginning, parts = start, start, []
            while cursor < end:
                if cursor in self.parser.pairs:
                    cursor = self.parser.pairs[cursor] + 1
                elif self.code.startswith(operator, cursor):
                    parts.append((beginning, cursor))
                    cursor += 2
                    beginning = cursor
                else:
                    cursor += 1
            if parts:
                parts.append((beginning, end))
                return [(truth, guard) for part in parts for positive, guard in self.guard_facts(part) if positive == truth]
        if self.code[start:start + 1] == '!':
            return [(not truth, guard) for truth, guard in self.guard_facts((start + 1, end))]
        raw = self.text[start:end].strip()
        dot = re.fullmatch(r'([A-Za-z_]\w*)(\.toString\(\))?\.equals\(\s*"(\.\.?)"\s*\)', raw)
        constant_dot = re.fullmatch(r'"(\.\.?)"\.equals\(\s*([A-Za-z_]\w*)(\.toString\(\))?\s*\)', raw)
        kotlin_dot = re.fullmatch(r'([A-Za-z_]\w*)(\.toString\(\))?\s*(==|!=)\s*"(\.\.?)"', raw) if self.parser.kotlin else None
        if dot or constant_dot or kotlin_dot:
            if dot:
                name, rendered, literal = dot.groups()
                truth = False
            elif constant_dot:
                literal, name, rendered = constant_dot.groups()
                truth = False
            else:
                name, rendered, operator, literal = kotlin_dot.groups()
                truth = operator == '!='
            tag = 'basename-not-dot' if literal == '.' else 'basename-not-dotdot'
            return [(truth, ('basename', name, tag, bool(rendered)))]
        condition = self.code[slice(*span)].strip()
        # File.getCanonicalPath() returns String. Its startsWith() accepts
        # sibling names such as /srv/uploads-evil and cannot prove containment.
        # Only Path-returning normalization can qualify this component check.
        guard = re.fullmatch(r'(!\s*)?([A-Za-z_]\w*)(\.(?:normalize|toRealPath)\s*\(\s*\))?\.startsWith\s*\(\s*([A-Za-z_]\w*)\s*\)', condition)
        if guard:
            return [(not bool(guard.group(1)), (guard.group(2), bool(guard.group(3)), guard.group(4)))]
        return []

    def apply_guard(self, guard, state, bindings):
        if len(guard) == 4 and guard[0] == 'basename':
            _, name, tag, rendered = guard
            binding = bindings.get(name, name)
            state[binding] = join(*(retag(frozenset({trace}), add=frozenset({tag}))
                if 'basename-path' in trace.tags and ('jvm-string' in trace.tags or rendered and 'jvm-path' in trace.tags)
                else frozenset({trace}) for trace in state.get(binding, CLEAN)))
            return state
        name, canonical, root = guard
        binding = bindings.get(name, name)
        root_fact = state.get(bindings.get(root, root), CLEAN)
        if any(trace.kind == 'source' for trace in root_fact):
            return state
        state[binding] = join(root_fact, *(retag(frozenset({trace}), add=frozenset({'contained-path'}))
                              if 'jvm-path' in trace.tags and (canonical or 'canonical-path' in trace.tags) else frozenset({trace})
                              for trace in state.get(binding, CLEAN)))
        return state

    def call_arguments(self, start, end, state, bindings, depth):
        spans, names = [], []
        for low, high in self.parser.parts(start, end):
            keyword = re.match(r'\s*([A-Za-z_]\w*)\s*=(?!=)', self.code[low:high]) if self.parser.kotlin else None
            names.append(keyword.group(1) if keyword else None)
            spans.append((low + keyword.end() if keyword else low, high))
        arguments = [self.expression(low, high, state, bindings, depth + 1) for low, high in spans]
        return CallArguments(spans, names, arguments)

    def selected_calls(self, name, arguments, argument_names, offset, bindings):
        explicit_member = name.startswith('this.')
        if ('.' in name and not explicit_member) or (
                self.parser.kotlin and not explicit_member and name in bindings):
            return []
        basename = name.removeprefix('this.')
        candidates = [function for function in self.parser.functions.values()
                      if function.name == basename
                      and function.owner == self.function.owner
                      and function.declaration_scope[0] < offset < function.declaration_scope[1]
                      and (not explicit_member or function.member)]
        if not candidates:
            return []
        # Exclude sibling-local helpers, but preserve visible overloads until
        # their argument-type applicability can be proved.
        selected = []
        for function in candidates:
            if len(function.parameters) != len(arguments):
                continue
            bound = {}
            for position, (keyword, fact) in enumerate(zip(argument_names, arguments)):
                if keyword is not None and keyword not in function.parameters:
                    break
                index = function.parameters.index(keyword) if keyword is not None else position
                key = (function.key, index)
                if key in bound:
                    break
                bound[key] = fact
            else:
                selected.append((function, bound))
        return selected

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
            if self.parser.kotlin and self.request_receiver_sources:
                property_prefix = REQUEST_PROPERTY_PREFIX_RE.match(self.code[cursor:end])
                if property_prefix is not None and property_prefix.end() < match.end():
                    property_name = re.sub(r'\s+', '', property_prefix.group())
                    if self.request_call(property_name, None, offset, bindings, state) is not None:
                        # Read the verified Java synthetic property before its
                        # String member chain. The normal postfix evaluator then
                        # keeps each method's own argument/sanitizer semantics.
                        match = property_prefix
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
            request_result = None
            if cursor < end and self.code[cursor] == '(':
                close = self.parser.pairs[cursor]
                call_arguments = self.call_arguments(cursor + 1, close, state, bindings, depth)
                spans, argument_names, arguments = call_arguments.spans, call_arguments.names, call_arguments.values
                atom = join(atom, *arguments)
                call_text = self.code[offset:close + 1]
                # Arguments were evaluated above. Matching their text again
                # here would resurrect a source after a known clean helper.
                direct = self.source_re.search(self.code[offset:cursor + 1])
                if direct and self.named_request_source(name, offset, bindings, state):
                    atom = join(atom, self.source(offset + direct.start(), direct.group().strip()))
                candidates = self.selected_calls(name, arguments, argument_names, offset, bindings)
                if candidates:
                    selected = True
                    returned = CLEAN
                    for function, bound in candidates:
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
                    if self.call_sink(name, call_arguments, atom, offset, bindings):
                        constructor = offset
                    request_result = self.request_call(name, arguments, offset, bindings, state)
                    atom = (request_result if request_result is not None else
                            self.without_request_identity(self.external_call(name, arguments, atom, offset, bindings, state)))
                cursor = close + 1
            else:
                direct = self.source_re.search(self.code[offset:cursor + 1])
                request_result = self.request_call(name, None, offset, bindings, state)
                if request_result is not None:
                    atom = request_result
                elif direct and self.named_request_source(name, offset, bindings, state):
                    atom = join(atom, self.source(offset + direct.start(), direct.group().strip()))
            if '.' in name and not selected and request_result is None:
                atom = self.without_request_identity(
                    self.member_value(name.rsplit('.', 1)[-1], atom, offset, arguments, direct_call=arguments is not None))
            while cursor < end:
                tail = self.parser.skip(cursor, end)
                if self.parser.kotlin and self.request_receiver_sources and self.code[tail:tail + 2] == '!!':
                    # A successful assertion preserves the same array/map
                    # contents before a following index or member read.
                    tail = self.parser.skip(tail + 2, end)
                member = re.match(r'\.\s*([A-Za-z_]\w*)', self.code[tail:end])
                if member is None and self.parser.kotlin and self.request_receiver_sources:
                    # ?. evaluates the same member on its non-null branch.
                    # The null branch contributes no attacker-controlled text.
                    member = re.match(r'\?\.\s*([A-Za-z_]\w*)', self.code[tail:end])
                if self.code[tail:tail + 1] == '[':
                    close = self.parser.pairs[tail]
                    index = self.expression(tail + 1, close, state, bindings, depth + 1)
                    selected_value = self.collection_member(atom, '[]', [index], spans=[(tail + 1, close)]) if self.request_receiver_sources else None
                    atom = selected_value if selected_value is not None else join(atom, index)
                    if any(KTOR_MAP_TAG in trace.tags for trace in atom):
                        atom = retag(self.without_request_identity(atom), add=frozenset({'jvm-string'}))
                    cursor = close + 1
                elif member:
                    method = member.group(1)
                    arguments = None
                    receiver = atom
                    cursor = self.parser.skip(tail + member.end(), end)
                    if cursor < end and self.code[cursor] == '(':
                        close = self.parser.pairs[cursor]
                        call_arguments = self.call_arguments(cursor + 1, close, state, bindings, depth)
                        arguments = call_arguments.values
                        atom = join(atom, *arguments)
                        if self.call_sink('.' + method, call_arguments, atom, tail, bindings):
                            constructor = tail
                        cursor = close + 1
                    request_result = self.request_call('.' + method, arguments, tail, bindings, state, receiver)
                    atom = (request_result if request_result is not None else
                            self.without_request_identity(self.member_value(method, atom, tail, arguments, receiver=receiver)))
                    if method in {'getFileName', 'getName', 'fileName', 'name'} and all('basename-path' in trace.tags for trace in atom):
                        # This getter discharges the earlier path construction.
                        # A later String extension must not rewrite that site.
                        constructor = None
                    if method == 'resolve' and self.path_constructors:
                        constructor = tail
                else:
                    break
            if constructor is not None:
                atom = retag(atom, add=frozenset({f'ctor-site:{constructor}'}))
                self.record(constructor, retag(atom, add=frozenset({'path-construction'})))
            value = join(value, atom)
        if '+' in self.code[start:end]:
            value = retag(value, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))
        return value

    def assignment(self, span):
        start, end = span
        text = self.code[start:end]
        # Java array declarators may repeat dimensions on the type
        # (`String[][] m`) or put them after the name (`String m[]`).
        match = re.match(r'\s*(?:(?:final|val|var)\s+)?(?:[\w.]+(?:\s*<[^=;]+>)?(?:\s*\[\s*\])*\s+)?([A-Za-z_]\w*)(?:\s*\[\s*\])*\s*(?::\s*[\w.<>?]+\s*)?(\+?=)(?!=)', text)
        if not match:
            return None
        declaration = bool(re.match(r'\s*(?:final\s+)?(?:val|var|[\w.]+(?:\s*<[^=;]+>)?(?:\s*\[\s*\])*)\s+[A-Za-z_]\w*', text))
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

    # one statement's control-flow edges: statement, successor, bindings, reads, node, block, edges and three jump targets; a parameter record is bead ultimate_bug_scanner-8tqg — ubs:ignore[py.functions.high-param-count]
    def adapter_graph(self, statement, following, bindings, reads, node, block, edges,
                      break_to, continue_to, unwind):
        raise AnalysisLimit('Unsupported Java/Kotlin adapter statement; analysis is incomplete')

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
                if kind == 'adapter':
                    entry = self.adapter_graph(statement, entry, local, reads, node, block, edges,
                                               break_to, continue_to, unwind)
                    continue
                if kind == 'require':
                    name = re.match(r'\s*(require|check)\b', self.code[statement.start:statement.end]).group(1)
                    imported = re.search(r'\bimport\s+(?!kotlin\.' + name + r'\s*(?:;|\r?$))[^\r\n;]*(?:\.' + name + r'\b|\bas\s+' + name + r'\b|\.\*)', self.code, re.MULTILINE)
                    if not imported and name not in local and not any(item.name == name for item in self.parser.functions.values()):
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
            selected = self.collection_member(fact, '<foreach>', []) if self.request_receiver_sources else None
            if selected is not None:
                fact = selected
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
                fact = retag(fact, remove=PATH_PROOF_TAGS | frozenset({'jvm-path'}))
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
    if not ((SOURCE_RE.search(text) or REQUEST_SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
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
    mixed_code = (
        'class Mixed {\n'
        '  Path choose(Path root, String raw) {\n'
        '    Path leaked = root.resolve(raw);\n'
        '    Path safe = root.resolve(raw).normalize();\n'
        '    if (!safe.startsWith(root)) { throw new SecurityException("bad"); }\n'
        '    return safe;\n'
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

        mixed_target = Path(tmp) / "Mixed.java"
        mixed_target.write_text(mixed_code, encoding="utf-8")
        mixed_findings = list(run(RunContext(lang="java", files=[mixed_target])))
        assert [item["line"] for item in mixed_findings] == [3], mixed_findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_sink", _selftest_direct_source_to_sink),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("containment_guard_suppression", _selftest_containment_guard_suppression),
)

register(Analyzer(layer="taint", lang="java", name="taint_java_traversal", run=run, selftests=SELF_TESTS))
