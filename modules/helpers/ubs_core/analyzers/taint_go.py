"""Function-scoped Go taint analysis with package helper summaries (bead D6).

The lexical front end preserves source locations and Go string semantics.
Statement transfers strongly update assignments, join branches and iterate
loops and package call summaries to convergence. Sanitizers are specific to the
interpreter receiving a value. This is a conservative source analyzer, not a
Go type checker; arbitrary imported-package calls and dynamically invoked
closures are not resolved. File-local imports identify standard JSON/XML,
reader, environment, command and HTML escape operations, including captured function aliases.
Bound JSON/XML decoder methods preserve the selected receiver and result shape.
Selected package helpers transport callable and decoder identities through
parameters and result slots, with a finite context worklist independent of
payload traces. Excessive specialization is an explicit incomplete analysis.
Callable joins retain unknown alternatives instead of borrowing a native
sanitizer or clean error-result contract. Decoders and Unmarshal
propagate input through local destination pointers and package helper output
parameters. Ordinary writes retain bounded selector paths and value copies;
native decoding uses weak writes and deep or unknown targets remain conservative.
This is not a general heap model. Only explicitly
selected files in the same directory AND package share summaries. Both output
entrypoints consume the same finding stream.
"""
from __future__ import annotations

import ast
import re
from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.taint_flow import AnalysisLimit

SKIP_DIRS = {'.git', 'vendor', '.cache', 'bin', 'dist', '.idea'}
EXTS = {'.go'}
PATH_LIMIT = 6
NATIVE_CONTEXT_LIMIT = 256
FIELD_PATH_LIMIT = 8

_NATIVE_PACKAGES = {'encoding/json': 'json', 'encoding/xml': 'xml',
                    'io': 'io', 'io/ioutil': 'ioutil', 'html': 'html',
                    'html/template': 'template', 'text/template': 'template', 'os': 'os', 'os/exec': 'exec',
                    'fmt': 'fmt', 'strings': 'strings', 'bytes': 'bytes', 'bufio': 'bufio'}
_NATIVE_MEMBERS = {'json': {'NewDecoder', 'Unmarshal'}, 'xml': {'NewDecoder', 'Unmarshal'},
                   'io': {'ReadAll', 'ReadFull', 'ReadAtLeast'}, 'ioutil': {'ReadAll'},
                   'html': {'EscapeString'}, 'template': {'HTMLEscapeString', 'HTMLEscaper'},
                   'os': {'Getenv', 'LookupEnv', 'Stdin'},
                   'exec': {'Command', 'CommandContext'},
                   'fmt': {'Scan', 'Scanln', 'Scanf', 'Fscan', 'Fscanln', 'Fscanf',
                           'Sscan', 'Sscanln', 'Sscanf'},
                   'strings': {'NewReader'}, 'bytes': {'NewReader', 'NewBuffer', 'NewBufferString'},
                   'bufio': {'NewReader', 'NewReaderSize', 'NewScanner',
                             'ScanLines', 'ScanWords', 'ScanBytes', 'ScanRunes'}}
_HTML_SANITIZERS = frozenset({('html', 'EscapeString'), ('template', 'HTMLEscapeString'), ('template', 'HTMLEscaper')})
_ENVIRONMENT_OPERATIONS = frozenset({('os', 'Getenv'), ('os', 'LookupEnv')})
_COMMAND_OPERATIONS = frozenset({('exec', 'Command'), ('exec', 'CommandContext')})
_READ_INTO_OPERATIONS = frozenset({('io', 'ReadFull'), ('io', 'ReadAtLeast')})
_SCAN_OPERATIONS = frozenset(('fmt', member) for member in _NATIVE_MEMBERS['fmt'])
_READER_CONSTRUCTORS = {
    ('strings', 'NewReader'): 'strings-reader', ('bytes', 'NewReader'): 'bytes-reader',
    ('bytes', 'NewBuffer'): 'bytes-buffer', ('bytes', 'NewBufferString'): 'bytes-buffer',
    ('bufio', 'NewReader'): 'bufio-reader', ('bufio', 'NewReaderSize'): 'bufio-reader',
    ('bufio', 'NewScanner'): 'scanner',
}
_BUFFER_SPLITTERS = frozenset(('bufio', member) for member in ('ScanLines', 'ScanWords', 'ScanBytes', 'ScanRunes'))
_CALLABLE_OPERATIONS = (_ENVIRONMENT_OPERATIONS | _SCAN_OPERATIONS | _COMMAND_OPERATIONS | _READ_INTO_OPERATIONS
                        | _READER_CONSTRUCTORS.keys())
_DECODER_METHODS = frozenset({'Decode', 'DecodeElement', 'Token', 'RawToken', 'More', 'InputOffset',
                              'UseNumber', 'DisallowUnknownFields', 'Buffered'})


def _callable_boundary(operations, action):
    family = ('command' if operations & _COMMAND_OPERATIONS else
              'formatted input' if operations & _SCAN_OPERATIONS else
              'reader' if operations & (_READER_CONSTRUCTORS.keys() | _READ_INTO_OPERATIONS) else 'environment')
    return AnalysisLimit(f'Go {family} callable {action} is unsupported; analysis is incomplete')

SOURCE_PATTERNS = [
    re.compile(r"\.FormValue\s*\(", re.IGNORECASE),
    re.compile(r"\.PostFormValue\s*\(", re.IGNORECASE),
    re.compile(r"\.(?:Form|PostForm)\.Get\s*\(", re.IGNORECASE),
    re.compile(r"\.Header\.Get\s*\(", re.IGNORECASE),
    re.compile(r"URL\.Query\(\)\.Get", re.IGNORECASE),
    re.compile(r"\.PathValue\s*\(", re.IGNORECASE),
    re.compile(r"mux\.Vars\s*\(", re.IGNORECASE),
    re.compile(r"chi\.URLParam\s*\(", re.IGNORECASE),
    re.compile(r"\.(?:QueryParam|FormParam|Param)\s*\(", re.IGNORECASE),
    re.compile(r"\b(?:r|req|request)\.Body\b"),
]

SINKS = [
    (re.compile(r"(?<![\w.])fmt\.Fprint(?:f|ln)?\s*\("), 'go.taint.xss', 'fmt.Fprintf'),
    (re.compile(r"\b[A-Za-z_][\w]*\.Write\s*\("), 'go.taint.xss', 'ResponseWriter.Write'),
    (re.compile(r"\btemplate\.[A-Za-z_][\w]*\.Execute\s*\("), 'go.taint.xss', 'template.Execute'),
    (re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?\.(?:Exec|ExecContext|Query|QueryContext|QueryRow|QueryRowContext|Raw|NamedQuery|NamedQueryContext|NamedExec|NamedExecContext|Select|SelectContext|Where|Or|Not|Having|Order)\s*\("), 'go.taint.sql', 'SQL query'),
    (re.compile(r"\b(?:db|tx|conn|pool|repo|store|database|queries|sqlxDB)\.Get(?:Context)?\s*\("), 'go.taint.sql', 'SQL query'),
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


def _call_code(code: str) -> str:
    """Expose transparent named/literal callees without changing positions.

    ``((decode))(data)`` calls the same binding as ``decode(data)``. Remove
    only grouping around an identifier/selector or complete function literal,
    preserving every argument delimiter and newline. A result such as ``factory(decode)``
    is an evaluated value, not grouping around ``decode``; it must not acquire
    the argument's native authority.
    """
    transitions = list(re.finditer(r'\)\s*\(', code))
    member_chains = list(re.finditer(r'\)\s*\.\s*[A-Za-z_]\w*\s*\(', code))
    if not transitions and not member_chains:
        return code
    pairs = _pairs(code)
    opening = {end: start for start, end in pairs.items()}
    out = list(code)
    for transition in transitions:
        end = transition.start()
        start = opening.get(end)
        if start is None or code[start] != '(':
            continue
        prefix = code[:start].rstrip()
        if (prefix and (prefix[-1].isalnum() or prefix[-1] in '_.)]}')
                and not re.search(r'(?<![\w.])(?:go|defer)\s+$', code[:start])):
            continue
        left, right = start, end
        groups = []
        while left < right and code[left] == '(' and pairs.get(left) == right:
            groups.append((left, right))
            left += 1
            right -= 1
            while left < right and code[left].isspace():
                left += 1
            while left < right and code[right].isspace():
                right -= 1
        named = re.fullmatch(r'[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*', code[left:right + 1])
        literal = re.match(r'func\s*\(', code[left:right + 1])
        literal_body = None
        if literal:
            parameter_end = pairs.get(left + literal.end() - 1)
            cursor = parameter_end + 1 if parameter_end is not None else right
            while cursor < right:
                if code[cursor] == '{':
                    literal_body = cursor
                    break
                cursor = pairs.get(cursor, cursor) + 1 if code[cursor] in '([' else cursor + 1
        if not named and (literal_body is None or pairs.get(literal_body) != right):
            continue
        for left, right in groups:
            out[left] = out[right] = ' '
    if member_chains:
        updated = ''.join(out)
        pairs = _pairs(updated)
        opening = {end: start for start, end in pairs.items()}
        for transition in re.finditer(r'\)\s*\.\s*[A-Za-z_]\w*\s*\(', updated):
            end = transition.start()
            start = opening.get(end)
            if start is None or updated[start] != '(':
                continue
            prefix = updated[:start].rstrip()
            if (prefix and (prefix[-1].isalnum() or prefix[-1] in '_.)]}')
                    and not re.search(r'(?<![\w.])(?:go|defer)\s+$', updated[:start])):
                continue
            left, right = start, end
            groups = []
            while left < right and updated[left] == '(' and pairs.get(left) == right:
                groups.append((left, right))
                left += 1
                right -= 1
                while left < right and updated[left].isspace():
                    left += 1
                while left < right and updated[right].isspace():
                    right -= 1
            inner_call = re.match(r'[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?\s*\(', updated[left:right + 1])
            if not inner_call or pairs.get(left + inner_call.end() - 1) != right:
                continue
            for g_left, g_right in groups:
                out[g_left] = out[g_right] = ' '
    return ''.join(out)


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
    # Decoder handles have a clean ordinary value but retain their reader's
    # payload. Keep that projection distinct while a helper is symbolic.
    projection: str = ''


_Fact = frozenset[_Trace]
_CLEAN: _Fact = frozenset()


@dataclass(frozen=True)
class _Target:
    cell: str
    parameter: int | None = None
    whole: bool = True
    path: tuple[str, ...] = ()
    indexed: bool = False


@dataclass(frozen=True)
class _FieldKey:
    cell: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class _PointerKey:
    cell: str


@dataclass(frozen=True)
class _ScanKindKey:
    cell: str


@dataclass(frozen=True)
class _BufferKey:
    cell: str


@dataclass(frozen=True)
class _BufferInfo:
    # Slice length belongs to the header; contents belong to its backing cells.
    length: int | None = None
    definite: bool = True


def _join_buffers(*buffers):
    present = [buffer for buffer in buffers if buffer is not None]
    if not present:
        return None
    lengths = {buffer.length for buffer in present}
    return _BufferInfo(next(iter(lengths)) if len(lengths) == 1 else None,
                       len(present) == len(buffers) and all(buffer.definite for buffer in present))


@dataclass(frozen=True)
class _DecoderKey:
    cell: str


@dataclass(frozen=True)
class _DecoderInfo:
    source: _Fact = _CLEAN
    definite: bool = True
    # The empty method is a decoder handle. A method value captures the
    # receiver at selection time, independently of later variable rebinding.
    methods: frozenset[str] = frozenset({''})


def _join_decoders(*decoders):
    present = [decoder for decoder in decoders if decoder is not None]
    if not present:
        return None
    return _DecoderInfo(_join(*(decoder.source for decoder in present)),
                        len(present) == len(decoders) and all(decoder.definite for decoder in present),
                        frozenset().union(*(decoder.methods for decoder in present)))


@dataclass(frozen=True)
class _ReaderKey:
    cell: str


@dataclass(frozen=True)
class _ReaderOrigin:
    # Allocation and call sites form a finite identity, never a call stack.
    site: tuple[int, int]
    parameter: int | None = None


@dataclass(frozen=True)
class _ReaderInfo:
    source: _Fact = _CLEAN
    kinds: frozenset[str] = frozenset()
    origins: frozenset[_ReaderOrigin] = frozenset()
    scanned: bool = False
    definite: bool = True
    methods: frozenset[str] = frozenset({''})


def _join_readers(*readers):
    present = [reader for reader in readers if reader is not None]
    if not present:
        return None
    return _ReaderInfo(_join(*(reader.source for reader in present)),
                       frozenset().union(*(reader.kinds for reader in present)),
                       frozenset().union(*(reader.origins for reader in present)),
                       any(reader.scanned for reader in present),
                       len(present) == len(readers) and all(reader.definite for reader in present),
                       frozenset().union(*(reader.methods for reader in present)))


@dataclass(frozen=True)
class _NativeKey:
    cell: str


@dataclass(frozen=True)
class _NativeInfo:
    operations: frozenset[tuple[str, str]] = frozenset()
    unknown: bool = False


_UNKNOWN_NATIVE = _NativeInfo(unknown=True)


@dataclass(frozen=True)
class _ValueInfo:
    native: _NativeInfo | None = _UNKNOWN_NATIVE
    decoder: _DecoderInfo | None = None
    pointers: frozenset[_Target] = frozenset()
    reader: _ReaderInfo | None = None
    buffer: _BufferInfo | None = None


def _join_value_info(*values):
    # None is an unevaluated summary result, not an unknown runtime value.
    values = [value for value in values if value is not None]
    if not values:
        return None
    decoder = _join_decoders(*(value.decoder for value in values))
    pointers = frozenset().union(*(value.pointers for value in values))
    if not all(value.pointers for value in values):
        pointers = frozenset(replace(target, whole=False) for target in pointers)
    return _ValueInfo(_join_native(*(value.native for value in values)), decoder, pointers,
                      _join_readers(*(value.reader for value in values)),
                      _join_buffers(*(value.buffer for value in values)))


def _join_native(*values):
    # Missing metadata is fixed-point bottom, such as a forward initializer.
    # An assigned unknown callable is a real alternative and must survive.
    values = [value for value in values if value is not None]
    if not values:
        return None
    return _NativeInfo(frozenset().union(*(value.operations for value in values)),
                       any(value.unknown for value in values))


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
        result.append(_Trace(trace.source, trace.parameter, path, trace.projection))
    return frozenset(result)


def _field_base(state, cell, path=()):
    # Field facets refine tracked ordinary writes, not an unknown aggregate's
    # layout. Retain enclosing provenance: promoted fields and pointer-valued
    # members can alias paths that this bounded model does not resolve.
    return _join(state.get(cell, _CLEAN),
                 *(state.get(_FieldKey(cell, path[:length]), _CLEAN)
                   for length in range(1, len(path) + 1)))


def _field_fact(state, cell, path=()):
    return _join(_field_base(state, cell, path),
                 *(fact for key, fact in state.items() if isinstance(key, _FieldKey)
                   and key.cell == cell and len(key.path) > len(path) and key.path[:len(path)] == path))


def _field_target(target, suffix):
    path = target.path + tuple(suffix)
    # Recursive helpers may walk arbitrarily deep structures. Widen a deep
    # destination to its aggregate instead of growing an unbounded path or
    # granting a strong update to an unrepresented descendant.
    return (replace(target, path=path) if len(path) <= FIELD_PATH_LIMIT
            else replace(target, path=(), whole=False))


def _join_states(*states):
    states = [state for state in states if state is not None]
    if not states:
        return None
    result = {}
    for name in set().union(*(state.keys() for state in states)):
        if isinstance(name, _PointerKey):
            alternatives = [state.get(name, frozenset()) for state in states]
            targets = frozenset().union(*alternatives)
            result[name] = (targets if all(alternatives) else
                            frozenset(replace(target, whole=False) for target in targets))
        elif isinstance(name, _DecoderKey):
            result[name] = _join_decoders(*(state.get(name) for state in states))
        elif isinstance(name, _ReaderKey):
            result[name] = _join_readers(*(state.get(name) for state in states))
        elif isinstance(name, _BufferKey):
            result[name] = _join_buffers(*(state.get(name) for state in states))
        elif isinstance(name, _NativeKey):
            result[name] = _join_native(*(state.get(name) for state in states))
        elif isinstance(name, _ScanKindKey):
            kinds = {state.get(name, '') for state in states}
            result[name] = next(iter(kinds)) if len(kinds) == 1 else ''
        elif isinstance(name, _FieldKey):
            result[name] = _join(*(_field_fact(state, name.cell, name.path) for state in states))
        else:
            result[name] = _join(*(state.get(name, _CLEAN) for state in states))
    return result


@dataclass(frozen=True)
class _CallExpression:
    """Aligned source/masked text and token pairs at an absolute origin."""
    text: str
    code: str
    pairs: dict[int, int]
    offset: int


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
        declaration = re.match(r'(var|const|type)\s*\(', self.code[start:end])
        if declaration:
            opening = start + declaration.end() - 1
            close = self.pairs.get(opening)
            if close is not None:
                # A declaration group is not a lexical block. Its individual
                # specs retain their original offsets and share the scope.
                body = tuple(replace(node, kind=declaration.group(1))
                             for node in self.block(opening + 1, close))
                return _Statement(start, close + 1, 'declarations', body), close + 1
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
class _FileImports:
    names: dict[str, str | None]
    dots: dict[str, str | None]

    def resolve(self, root: str, member: str | None):
        package = self.names.get(root) if member else self.dots.get(root)
        operation = member or root
        if package and operation in _NATIVE_MEMBERS[package]:
            return package, operation
        return None


@dataclass(frozen=True)
class _ImportContexts:
    """Keep imports attached to their original file in the package image."""
    starts: tuple[int, ...]
    files: tuple[_FileImports, ...]

    def resolve(self, root: str, member: str | None, offset: int):
        index = bisect_right(self.starts, offset) - 1
        return self.files[index].resolve(root, member) if index >= 0 else None

    def has_name(self, root: str, offset: int) -> bool:
        index = bisect_right(self.starts, offset) - 1
        return index >= 0 and root in self.files[index].names


def _file_imports(source: str, code: str, parser: _Parser) -> _FileImports:
    """Read only actual import declarations, before the file's other code.

    Comments are already masked in source; literals are masked in code. A raw
    string or a comment containing an import can therefore never grant native
    semantics. Importless editor fragments retain the analyzer's conventional
    names; once a file declares imports, only exact standard paths qualify.
    """
    names, dots = {}, {}
    explicit, unknown_dot = False, False
    end = len(code)
    cursor = parser.skip(0, end)
    if re.match(r'\ufeff?\s*package\b', code[cursor:]):
        cursor = parser.skip(parser.statement_end(cursor, end), end)
    while re.match(r'import\b', code[cursor:]):
        explicit = True
        start = parser.skip(cursor + len('import'), end)
        if start < end and code[start] == '(':
            close = parser.pairs.get(start)
            if close is None:
                break
            specs = [(node.start, node.end) for node in parser.block(start + 1, close)]
            cursor = parser.skip(close + 1, end)
        else:
            close = parser.statement_end(start, end)
            specs = [(start, close)]
            cursor = parser.skip(close, end)
        for left, right in specs:
            spec = re.fullmatch(r'\s*(?:([A-Za-z_]\w*|\.)\s*)?("(?:[^"\\]|\\.)*"|`[^`]*`)\s*',
                                source[left:right], re.DOTALL)
            if spec is None:
                continue
            path = _string_literal(spec.group(2))
            if path is None:
                continue
            if spec.group(2).startswith('`'):
                path = path.replace('\r', '')
            package = _NATIVE_PACKAGES.get(path)
            name = spec.group(1) or package or path.rsplit('/', 1)[-1]
            if name == '_':
                continue
            if name == '.':
                if package is None:
                    unknown_dot = True
                else:
                    for member in _NATIVE_MEMBERS[package]:
                        dots[member] = package if member not in dots else None
            else:
                names[name] = package if name not in names else None
    if not explicit:
        names = {package: package for package in _NATIVE_MEMBERS}
    return _FileImports(names, {} if unknown_dot else dots)


@dataclass(frozen=True)
class _Function:
    name: str
    start: int
    end: int
    parameters: tuple[str, ...]
    results: tuple[str, ...]
    body: tuple[_Statement, ...]
    variadic: int | None = None
    reference_parameters: frozenset[int] = frozenset()
    parameter_types: tuple[str, ...] = ()
    receiver: str = ''


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


def _reference_parameters(code: str) -> frozenset[int]:
    """Pointer/interface parameters may carry destinations; scalars are copies."""
    references, reference = set(), False
    parts = _parts(code)
    for index in reversed(range(len(parts))):
        start, end = parts[index]
        part = code[start:end].strip()
        match = re.match(r'[A-Za-z_]\w*\s+(.+)$', part, re.DOTALL)
        if match:
            typename = re.sub(r'\s+', '', match.group(1))
            reference = typename.startswith('*') or typename in {'any', 'interface{}', '[]byte', '[]uint8'}
        elif not re.fullmatch(r'[A-Za-z_]\w*', part):
            reference = False
        if reference:
            references.add(index)
    return frozenset(references)


def _parameter_types(code: str) -> tuple[str, ...]:
    types, grouped = [], ''
    for start, end in reversed(_parts(code)):
        part = code[start:end].strip()
        match = re.match(r'^[A-Za-z_]\w*\s+(.+)$', part, re.DOTALL)
        if match:
            grouped = re.sub(r'\s+', '', match.group(1))
        elif not grouped or not re.fullmatch(r'[A-Za-z_]\w*', part):
            grouped = re.sub(r'\s+', '', part)
        types.append(grouped)
    return tuple(reversed(types))


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
        receiver = ''
        if name is None:
            receiver_text = code[match.start() + 4:match.start('name')].strip()
            name = match.group('name') if not receiver_text else f'@method:{match.start()}'
            if receiver_text.startswith('(') and receiver_text.endswith(')'):
                receiver_names = _parameter_names(receiver_text[1:-1])
                receiver = receiver_names[0] if receiver_names else ''
        if name == 'init':
            name = f'@init:{match.start()}'
        parameters = _parameter_names(code[match.end():param_end])
        functions.append(_Function(name, match.start(), end, parameters, results,
                                   parser.block(opening + 1, end - 1),
                                   len(parameters) - 1 if '...' in code[match.end():param_end] else None,
                                   _reference_parameters(code[match.end():param_end]),
                                   _parameter_types(code[match.end():param_end]), receiver))
        covered = end
    return functions


@dataclass
class _Summary:
    returns: tuple[_Fact, ...] = ()
    effects: dict[tuple[int, str], _Fact] = field(default_factory=dict)
    variadic: int | None = None
    writes: dict[tuple[int, tuple[str, ...]], _Fact] = field(default_factory=dict)
    value_returns: tuple[_ValueInfo | None, ...] = ()
    native_writes: dict[tuple[int, tuple[str, ...]], _NativeInfo | None] = field(default_factory=dict)
    reader_scans: frozenset[int] = frozenset()
    buffer_escapes: frozenset[int] = frozenset()
    buffer_writes: frozenset[int] = frozenset()
    buffer_borrows: frozenset[int] = frozenset()


def _join_summaries(summaries: list[_Summary]) -> _Summary:
    """Conservatively union selected build variants, never choose by filename.

    Build-tag and GOOS selection belong to the caller's file selection. When
    mutually exclusive definitions are both selected, neither is proof that a
    call is clean. Variadic differences are widened rather than dropping args.
    """
    variadics = [summary.variadic for summary in summaries if summary.variadic is not None]
    variadic = min(variadics) if variadics else None

    def widen(fact):
        if variadic is None:
            return fact
        return frozenset(_Trace(trace.source,
                                min(trace.parameter, variadic) if trace.parameter is not None else None,
                                trace.path, trace.projection) for trace in fact)

    count = max((len(summary.returns) for summary in summaries), default=0)
    returns = tuple(_join(*(widen(summary.returns[index]) for summary in summaries
                            if index < len(summary.returns))) for index in range(count))
    value_returns = []
    for index in range(count):
        values = []
        for summary in summaries:
            if index >= len(summary.value_returns) or summary.value_returns[index] is None:
                continue
            value = summary.value_returns[index]
            decoder = (replace(value.decoder, source=widen(value.decoder.source))
                       if value.decoder is not None else None)
            reader = (replace(value.reader, source=widen(value.reader.source), origins=frozenset(
                replace(origin, parameter=min(origin.parameter, variadic))
                if variadic is not None and origin.parameter is not None else origin
                for origin in value.reader.origins)) if value.reader is not None else None)
            pointers = frozenset(replace(target, parameter=min(target.parameter, variadic))
                                 if variadic is not None and target.parameter is not None else target
                                 for target in value.pointers)
            values.append(replace(value, decoder=decoder, pointers=pointers, reader=reader))
        value_returns.append(_join_value_info(*values))
    effects = {}
    writes = {}
    native_writes = {}
    for summary in summaries:
        for key, fact in summary.effects.items():
            effects[key] = _join(effects.get(key, _CLEAN), widen(fact))
        for (index, path), fact in summary.writes.items():
            index = min(index, variadic) if variadic is not None else index
            writes[index, path] = _join(writes.get((index, path), _CLEAN), widen(fact))
        for (index, path), native in summary.native_writes.items():
            index = min(index, variadic) if variadic is not None else index
            native_writes[index, path] = _join_native(native_writes.get((index, path)), native)
    reader_scans = frozenset(min(index, variadic) if variadic is not None else index
                             for summary in summaries for index in summary.reader_scans)
    buffer_escapes = frozenset(min(index, variadic) if variadic is not None else index
                               for summary in summaries for index in summary.buffer_escapes)
    buffer_writes = frozenset(min(index, variadic) if variadic is not None else index
                              for summary in summaries for index in summary.buffer_writes)
    buffer_borrows = frozenset(min(index, variadic) if variadic is not None else index
                               for summary in summaries for index in summary.buffer_borrows)
    return _Summary(returns, effects, variadic, writes, tuple(value_returns), native_writes,
                    reader_scans, buffer_escapes, buffer_writes, buffer_borrows)


@dataclass
class _Flow:
    normal: dict | None
    breaks: list[dict] = field(default_factory=list)
    continues: list[dict] = field(default_factory=list)


class _Analysis:
    def __init__(self, source: str, code: str, rule: str, summaries: dict[str, _Summary],
                 imports: _ImportContexts, uncertain_globals=None, global_cells=frozenset(),
                 resolve_summary=None):
        self.source, self.code, self.rule, self.summaries = source, code, rule, summaries
        self.imports = imports
        self.effects = {}
        self.returns: tuple[_Fact, ...] = ()
        self.value_returns: tuple[_ValueInfo | None, ...] = ()
        self.call_results: dict[int, tuple[_ValueInfo | None, ...]] = {}
        self.chained_call_results: dict[tuple[int, int], tuple[_ValueInfo | None, ...]] = {}
        self.decoder_callees: dict[int, _DecoderInfo] = {}
        self.value_results: dict[int, tuple[_ValueInfo | None, ...]] = {}
        self.closure_results: dict[int, tuple[tuple[_Fact, ...], tuple[_ValueInfo | None, ...]]] = {}
        self.chained_value_results: dict[int, tuple[tuple[_Fact, ...], tuple[_ValueInfo | None, ...]]] = {}
        self.named_returns = ()
        self.writes: dict[tuple[int, tuple[str, ...]], _Fact] = {}
        self.native_writes: dict[tuple[int, tuple[str, ...]], _NativeInfo | None] = {}
        self.native_cell_writes: dict[str, _NativeInfo | None] = {}
        self.native_mutations: set[str] = set()
        self.native_escapes: set[str] = set()
        self.scan_writes: dict[_Target, _Fact] = {}
        self.reader_scans: set[_ReaderOrigin] = set()
        self.buffer_escapes: set[_Target] = set()
        self.buffer_borrows: set[_Target] = set()
        self.buffer_invalidated = False
        self.buffer_writes: dict[_Target, _Fact] = {}
        self.buffer_cell_writes: dict[str, _BufferInfo | None] = {}
        self.reader_cell_writes: dict[str, _ReaderInfo | None] = {}
        self.decoder_cell_writes: dict[str, _DecoderInfo | None] = {}
        self.decoder_returns: dict[str, _DecoderInfo | None] | None = None
        self.uncertain_globals = uncertain_globals if uncertain_globals is not None else set()
        self.global_cells = global_cells
        self.resolve_summary = resolve_summary

    @staticmethod
    def unparenthesize(expr, offset=0):
        offset += len(expr) - len(expr.lstrip())
        expr = expr.strip()
        while expr.startswith('(') and _pairs(_masked_source(expr)).get(0) == len(expr) - 1:
            expr, offset = expr[1:-1], offset + 1
            offset += len(expr) - len(expr.lstrip())
            expr = expr.strip()
        return expr, offset

    def pointers(self, expr, state, scope):
        expr, _ = self.unparenthesize(expr)
        if re.fullmatch(r'[A-Za-z_]\w*', expr):
            cell = scope.bindings.get(expr, expr)
            targets = state.get(_PointerKey(cell), frozenset())
            return (frozenset(replace(target, whole=False) for target in targets)
                    if cell in self.native_escapes else targets)
        if expr.startswith('&'):
            target, _ = self.unparenthesize(expr[1:])
            match = re.fullmatch(r'([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*)*)',
                                 _masked_source(target))
            if match:
                cell = scope.bindings.get(match.group(1), match.group(1))
                suffix = tuple(re.findall(r'\.\s*([A-Za-z_]\w*)', match.group(2)))
                if not suffix:
                    return frozenset({_Target(cell)})
                aliases = self.pointers(match.group(1), state, scope) or frozenset({_Target(cell)})
                return frozenset(_field_target(alias, suffix) for alias in aliases)
            indexed = re.fullmatch(r'([A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])+',
                                   _masked_source(target))
            if indexed:
                cell = scope.bindings.get(indexed.group(1), indexed.group(1))
                aliases = self.pointers(indexed.group(1), state, scope) or frozenset({_Target(cell)})
                return frozenset(replace(alias, whole=False, indexed=True) for alias in aliases)
        return frozenset()

    def assignment_targets(self, expr, state, scope):
        """Resolve bounded pointer/selector lvalues without treating values as aliases."""
        expr, _ = self.unparenthesize(expr)
        if expr.startswith('*'):
            pointer, _ = self.unparenthesize(expr[1:])
            if re.fullmatch(r'[A-Za-z_]\w*', pointer):
                decoder = state.get(_DecoderKey(scope.bindings.get(pointer, pointer)))
                if decoder is not None and decoder.methods == {''}:
                    raise AnalysisLimit('Go decoder receiver mutation is unsupported; analysis is incomplete')
                return self.pointers(pointer, state, scope)
            if pointer.startswith('*'):
                outer = self.assignment_targets(pointer, state, scope)
                if outer is not None:
                    if any(state.get(_DecoderKey(target.cell)) is not None
                           and state[_DecoderKey(target.cell)].methods == {''} for target in outer):
                        raise AnalysisLimit('Go decoder receiver mutation is unsupported; analysis is incomplete')
                    complete = all(not target.path and state.get(_PointerKey(target.cell)) for target in outer)
                    return frozenset(replace(inner, whole=inner.whole and target.whole and complete,
                                             indexed=inner.indexed or target.indexed)
                                     for target in outer if not target.path
                                     for inner in state.get(_PointerKey(target.cell), ()))
        selector = re.fullmatch(r'(?:([A-Za-z_]\w*)|\(\s*\*\s*([A-Za-z_]\w*)\s*\))'
                                r'(?:\s*\.\s*[A-Za-z_]\w*)+', expr)
        if selector:
            root = selector.group(1) or selector.group(2)
            if root in scope.bindings:
                cell = scope.bindings[root]
                targets = self.pointers(root, state, scope) or frozenset({_Target(cell)})
                suffix = tuple(re.findall(r'\.\s*([A-Za-z_]\w*)', expr))
                return frozenset(_field_target(target, suffix) for target in targets)
        if '[' in expr:
            # Index identities are deliberately collapsed to their aggregate.
            # Keep that boundary distinct from an uncertain scalar pointer so
            # native callable writes cannot masquerade as scalar metadata.
            indexed = self.pointers('&' + expr, state, scope)
            if indexed:
                return indexed
        return None

    def copy_fields(self, expr, state, scope):
        expr, _ = self.unparenthesize(expr)
        if re.fullmatch(r'[A-Za-z_]\w*', expr) and expr in scope.bindings:
            cell = scope.bindings[expr]
            if state.get(_PointerKey(cell)):
                return None
            target = _Target(cell)
        else:
            targets = self.assignment_targets(expr, state, scope)
            if not targets or len(targets) != 1:
                return None
            target = next(iter(targets))
            if not target.whole:
                return None
        fields = tuple((key.path[len(target.path):], fact) for key, fact in state.items()
                       if isinstance(key, _FieldKey) and key.cell == target.cell
                       and len(key.path) > len(target.path) and key.path[:len(target.path)] == target.path)
        return _field_base(state, target.cell, target.path), fields

    def native_identity(self, root, member, offset, scope):
        if root in scope.bindings or root in self.summaries:
            return None
        return self.imports.resolve(root, member, offset)

    def native_callable(self, root, member, offset, state, scope):
        if member is None and root in scope.bindings:
            cell = scope.bindings[root]
            value = state.get(_NativeKey(cell))
            if cell in self.uncertain_globals or cell in self.native_escapes:
                return _join_native(value, _UNKNOWN_NATIVE)
            return value
        identity = self.native_identity(root, member, offset, scope)
        return _NativeInfo(frozenset({identity})) if identity is not None else _UNKNOWN_NATIVE

    @staticmethod
    def integer_literal(expr):
        expr, _ = _Analysis.unparenthesize(expr)
        if not re.fullmatch(r'[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*)', expr):
            return None
        number = expr.replace('_', '')
        unsigned = number.lstrip('+-')
        base = 8 if len(unsigned) > 1 and unsigned[0] == '0' and unsigned[1].isdigit() else 0
        try:
            return int(number, base or (10 if unsigned.isdigit() else 0))
        except ValueError:
            return None

    def buffer_source_proven(self, expression, origin, info, state, scope):
        """Prove current byte/string contents before granting a copy capability."""
        # Missing byte-buffer metadata is not proof of a scalar string:
        # ReadAll returns mutable bytes that may have untracked aliases.
        if info is not None and info.buffer is not None:
            escaped = {target.cell for target in self.buffer_escapes}
            return (info.buffer.definite and (info.buffer.length == 0 or
                    (bool(info.pointers) and all(
                        target.whole and not target.path and not target.indexed
                        and target.cell not in escaped for target in info.pointers))))
        expression, origin = self.unparenthesize(expression, origin)
        if _string_literal(expression) is not None:
            return True
        code = _call_code(_masked_source(expression))
        call = re.match(r'([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?\s*\(', code)
        if call is None or _pairs(code).get(call.end() - 1) != len(code) - 1:
            return False
        parts = [(expression[call.end() + start:call.end() + end], origin + call.end() + start)
                 for start, end in _parts(code[call.end():-1])]
        root, member = call.group(1), call.group(2)
        native = self.native_identity(root, member, origin, scope)
        if native == ('os', 'Getenv'):
            return len(parts) == 1
        conversion = (root == 'string' and member is None and root not in scope.bindings
                      and root not in self.summaries and len(parts) == 1)
        sanitizer = native in _HTML_SANITIZERS and (
            len(parts) == 1 or native == ('template', 'HTMLEscaper'))
        if not (conversion or sanitizer):
            return False
        # A string conversion freezes its input, but cannot repair source
        # contents already lost through an unmodeled mutable byte alias.
        return all(self.buffer_source_proven(
            argument, location, self.value_info(argument, location, state, scope), state, scope)
                   for argument, location in parts)

    def buffer_expression(self, expr, offset, state, scope):
        """Describe selected builtin slices without inventing an object heap.

        Allocation-site backing cells are shared by slice aliases; conversions
        to string read their current contents. Unknown lengths permit weak
        writes, while uncertain backing identity cannot authorize a write.
        """
        expr, offset = self.unparenthesize(expr, offset)
        code = _masked_source(expr)
        if expr == 'nil' and 'nil' not in scope.bindings and 'nil' not in self.summaries:
            return _ValueInfo(buffer=_BufferInfo(0)), False, False
        if re.fullmatch(r'[A-Za-z_]\w*', expr):
            info = self.value_info(expr, offset, state, scope)
            return (info if info is not None and info.buffer is not None else None), False, False
        sliced = re.fullmatch(r'([A-Za-z_]\w*)\s*\[(.*)\]', code, re.DOTALL)
        if sliced:
            parts = _parts(sliced.group(2), ':')
            info = self.value_info(sliced.group(1), offset, state, scope)
            if len(parts) in {2, 3} and info is not None and info.buffer is not None:
                # Masking preserves delimiter positions but rewrites rune
                # tokens. Only original integer text may prove a slice length.
                bounds = expr[sliced.start(2):sliced.end(2)]
                low_text = bounds[slice(*parts[0])].strip()
                high_text = bounds[slice(*parts[1])].strip()
                low = self.integer_literal(low_text) if low_text else 0
                high = self.integer_literal(high_text) if high_text else info.buffer.length
                length = high - low if high is not None and low is not None and high >= low >= 0 else None
                return replace(info, buffer=replace(info.buffer, length=length)), False, False
        constructed = re.fullmatch(r'make\s*\((.*)\)', expr, re.DOTALL)
        length, fresh, zeroed = None, False, False
        if constructed and 'make' not in scope.bindings and 'make' not in self.summaries:
            pieces = [constructed.group(1)[start:end].strip()
                      for start, end in _parts(_masked_source(constructed.group(1)))]
            if (len(pieces) in {2, 3} and re.sub(r'\s+', '', pieces[0]) in {'[]byte', '[]uint8'}
                    and self.scan_type(pieces[0], scope) == 'text'):
                length = self.integer_literal(pieces[1])
                fresh, zeroed = True, True
        converted = re.match(r'\[\]\s*(byte|uint8)\s*\(', code)
        if converted and self.scan_type('[]' + converted.group(1), scope) == 'text':
            closing = _pairs(code).get(converted.end() - 1)
            if closing == len(code) - 1:
                argument = expr[converted.end():closing]
                info = self.value_info(argument, offset + converted.end(), state, scope)
                if info is not None and info.buffer is not None:
                    return replace(info, native=_UNKNOWN_NATIVE), False, False
                literal = _string_literal(argument.strip())
                if literal is not None:
                    length, fresh = len(literal.encode('utf-8')), True
                elif (re.fullmatch(r'\s*string\s*\(.*\)\s*', argument, re.DOTALL)
                      and 'string' not in scope.bindings and 'string' not in self.summaries):
                    # A fresh backing array does not recover contents lost
                    # through an untracked alias before the string snapshot.
                    fresh = self.buffer_source_proven(
                        argument, offset + converted.end(), info, state, scope)
        literal = re.fullmatch(r'\[\]\s*(byte|uint8)\s*\{(.*)\}', code, re.DOTALL)
        if literal and self.scan_type('[]' + literal.group(1), scope) == 'text':
            # The lexer preserves a token for rune literals; an empty-looking
            # masked rune must not prove a zero-length destination.
            items = literal.group(2).strip().rstrip(',').strip()
            length = (0 if not items else len(_parts(items))) if ':' not in items else None
            fresh = True
        if fresh:
            target = _Target(f'@byte-buffer:{offset}')
            return _ValueInfo(pointers=frozenset({target}), buffer=_BufferInfo(length)), True, zeroed
        return None, False, False

    def escape_buffer(self, info, *, borrow=False, state=None):
        if info is not None and info.buffer is None and state is not None and not borrow:
            # An opaque callee receiving &slice can replace the header and
            # mutate its old array. Follow known address aliases before their
            # native identity is invalidated; unknown parameter addresses are
            # retained as summary escapes and resolved at the selected caller.
            pending, seen = list(info.pointers), set()
            while pending:
                target = pending.pop()
                if target.cell in seen:
                    continue
                seen.add(target.cell)
                if target.parameter is not None:
                    self.buffer_escapes.add(target)
                pointers = state.get(_PointerKey(target.cell), frozenset())
                buffer = state.get(_BufferKey(target.cell))
                if buffer is not None:
                    self.escape_buffer(_ValueInfo(pointers=pointers, buffer=buffer))
                    replacement = replace(buffer, definite=False)
                    state[_BufferKey(target.cell)] = replacement
                    self.buffer_cell_writes[target.cell] = replacement
                pending.extend(pointers)
        if info is not None and info.buffer is not None:
            cells = {target.cell for target in info.pointers}
            if borrow:
                if info.buffer.length != 0 and (not info.buffer.definite or not info.pointers
                        or any(not target.whole or target.path or target.indexed for target in info.pointers)):
                    raise AnalysisLimit('Go reader buffer backing identity is unsupported; analysis is incomplete')
                self.buffer_borrows.update(info.pointers)
                self.buffer_invalidated |= bool(cells & {target.cell for target in self.buffer_escapes})
            else:
                self.buffer_escapes.update(info.pointers)
                self.buffer_invalidated |= bool(cells & {
                    target.cell for target in (*self.buffer_borrows, *self.buffer_writes)})

    def invalidate_borrowed_buffer(self, target):
        # A bytes.Reader/Buffer keeps the array, not a copy of its contents.
        # Until reader payloads can follow live backing cells, any subsequent
        # content write must refuse that old constructor snapshot.
        self.buffer_invalidated |= any(borrowed.cell == target.cell for borrowed in self.buffer_borrows)

    def check_buffer_write(self, info, state):
        global_backing = {target.cell for cell in self.global_cells
                          for target in state.get(_PointerKey(cell), ())}
        escaped = {target.cell for target in self.buffer_escapes | self.buffer_borrows}
        if (info is None or info.buffer is None or not info.buffer.definite or not info.pointers
                or any(not target.whole or target.path or target.indexed
                       or target.cell in self.global_cells or target.cell in global_backing
                       or target.cell in escaped for target in info.pointers)):
            raise AnalysisLimit('Go reader destination buffer identity or escape is unsupported; analysis is incomplete')

    def check_source_storage(self, code, offset, state, scope):
        # Scalar native identities and selected helper results are modeled.
        # Composite values are not a callable heap: losing a getter inside a
        # slice/map/struct must not turn a former source into a clean result.
        # Eager calls store ordinary contents and keep the existing data flow.
        aggregate = '{' in code and not re.match(r'\s*func\s*\(', code)
        append = (re.match(r'\s*append\s*\(', code)
                  and 'append' not in scope.bindings and 'append' not in self.summaries)
        if not (aggregate or append):
            return
        # A function body nested in an argument is executable code, not
        # aggregate contents. Its own evaluator checks any stored handles.
        # A function type after []/map or a struct field name is not a body.
        if 'func' in code:
            parser = _Parser(code)
            masked, covered_until = list(code), 0
            for closure in re.finditer(r'\bfunc\s*\(', code):
                if closure.start() < covered_until:
                    continue
                previous = closure.start() - 1
                while previous >= 0 and code[previous].isspace():
                    previous -= 1
                if previous >= 0 and code[previous] not in '(:,={':
                    continue
                parameter_end = parser.pairs.get(closure.end() - 1)
                opening = parser.body_open(parameter_end + 1, len(code)) if parameter_end is not None else None
                closing = parser.pairs.get(opening) if opening is not None else None
                if closing is not None:
                    masked[closure.start():closing + 1] = ' ' * (closing + 1 - closure.start())
                    covered_until = closing + 1
            code = ''.join(masked)
        names = re.finditer(r'(?<![\w.])([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?', code)
        for match in names:
            previous = match.start() - 1
            while previous >= 0 and code[previous].isspace():
                previous -= 1
            if previous >= 0 and code[previous] == '.':
                continue
            root, member = match.group(1), match.group(2)
            following = match.end()
            while following < len(code) and code[following].isspace():
                following += 1
            if following < len(code) and code[following] == '(':
                summary = self.summaries.get(root) if member is None and root not in scope.bindings else None
                natives = (info.native for info in summary.value_returns if info is not None) if summary else ()
                closing = _pairs(code).get(following)
                tail = code[closing + 1:].lstrip() if closing is not None else ''
                stored = tail.startswith((',', '}')) or (append and tail == ')')
                native = self.native_callable(root, member, offset + match.start(), state, scope)
                if stored and ((native is not None and native.operations & _READER_CONSTRUCTORS.keys())
                               or (summary is not None and any(info is not None and info.reader is not None
                                                               for info in summary.value_returns))):
                    raise AnalysisLimit('Go reader aggregate storage is unsupported; analysis is incomplete')
                if (stored and summary is not None and any(info is not None and info.decoder is not None
                                                           for info in summary.value_returns)):
                    raise AnalysisLimit('Go decoder aggregate storage is unsupported; analysis is incomplete')
                if stored and summary is not None:
                    for info in summary.value_returns:
                        self.escape_buffer(info, state=state)
                if (native is not None and native.operations & {('json', 'NewDecoder'), ('xml', 'NewDecoder')}
                        and (stored or re.match(r'\s*\.\s*[A-Za-z_]\w*\s*[,}]', tail))):
                    raise AnalysisLimit('Go decoder aggregate storage is unsupported; analysis is incomplete')
            else:
                natives = (self.native_callable(root, member, offset + match.start(), state, scope),)
                info = self.value_info(match.group(), offset + match.start(), state, scope)
                self.escape_buffer(info, state=state)
                if info is not None and info.reader is not None:
                    raise AnalysisLimit('Go reader aggregate storage is unsupported; analysis is incomplete')
                if info is not None and info.decoder is not None:
                    raise AnalysisLimit('Go decoder aggregate storage is unsupported; analysis is incomplete')
            operations = frozenset().union(*(native.operations & _CALLABLE_OPERATIONS
                                             for native in natives if native is not None))
            if operations:
                raise _callable_boundary(operations, 'aggregate storage')

    def value_info(self, expr, offset, state, scope):
        expr, offset = self.unparenthesize(expr, offset)
        if expr == 'nil' and 'nil' not in scope.bindings and 'nil' not in self.summaries:
            return _ValueInfo(buffer=_BufferInfo(0))
        closure = self.closure_results.get(offset)
        if closure is not None:
            return closure[1][0] if closure[1] else _ValueInfo()
        chained = self.chained_value_results.get(offset)
        if chained is not None:
            return chained[1][0] if chained[1] else _ValueInfo()
        code = _call_code(_masked_source(expr))
        name = re.fullmatch(r'([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?', code)
        if name:
            cell = scope.bindings.get(name.group(1), name.group(1))
            native = self.native_callable(name.group(1), name.group(2), offset, state, scope)
            reader = state.get(_ReaderKey(cell))
            decoder = state.get(_DecoderKey(cell))
            if decoder is not None and name.group(2) is not None:
                decoder = (replace(decoder, methods=frozenset({name.group(2)}))
                           if decoder.methods == {''} and name.group(2) in _DECODER_METHODS else None)
            if reader is not None and name.group(2) is not None:
                reader = replace(reader, methods=frozenset({name.group(2)}))
            elif reader is None and native is not None and native.operations == {('os', 'Stdin')} and not native.unknown:
                reader = _ReaderInfo(frozenset({_Trace('os.Stdin', path=('os.Stdin',))}),
                                     frozenset({'stdin'}), frozenset({_ReaderOrigin((-1, -1))}))
            elif re.fullmatch(r'(?:r|req|request)\s*\.\s*Body', code):
                reader = _ReaderInfo(frozenset({_Trace(code, path=(code,))}), frozenset({'request'}))
            buffer = state.get(_BufferKey(cell)) if name.group(2) is None else None
            if buffer is not None and cell in self.global_cells:
                buffer = replace(buffer, definite=False)
            return _ValueInfo(native, decoder, self.pointers(expr, state, scope), reader, buffer)
        call = re.match(r'\s*([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?\s*\(', code)
        if call:
            call_pairs = _pairs(code)
            end = call_pairs.get(call.end() - 1)
            results = self.call_results.get(offset + call.start(1))
            if results and end == len(expr) - 1:
                return results[0]
            if end is not None:
                chain = re.match(r'\s*\.\s*([A-Za-z_]\w*)\s*\(', code[end + 1:])
                if chain and call_pairs.get(end + chain.end()) == len(expr) - 1:
                    chained_results = self.chained_call_results.get((offset + call.start(1), offset + len(expr) - 1))
                    if chained_results:
                        return chained_results[0]
            selection = re.fullmatch(r'\s*\.\s*([A-Za-z_]\w*)\s*', code[end + 1:]) if end is not None else None
            if (selection and selection.group(1) in _DECODER_METHODS and results and results[0] is not None
                    and results[0].decoder is not None and results[0].decoder.methods == {''}):
                return _ValueInfo(decoder=replace(results[0].decoder, methods=frozenset({selection.group(1)})))
        selection = re.search(r'\.\s*([A-Za-z_]\w*)\s*$', code)
        if selection and selection.group(1) in _DECODER_METHODS:
            owner = self.value_info(expr[:selection.start()], offset, state, scope)
            if owner is not None and owner.decoder is not None and owner.decoder.methods == {''}:
                return _ValueInfo(decoder=replace(owner.decoder, methods=frozenset({selection.group(1)})))
        buffer, _fresh, _zeroed = self.buffer_expression(expr, offset, state, scope)
        return buffer if buffer is not None else _ValueInfo(pointers=self.pointers(expr, state, scope))

    def reader_payload(self, expr, offset, fact, state, scope, *, require=False):
        """Reader handles carry contents separately from ordinary value facts."""
        info = self.value_info(expr, offset, state, scope)
        if info is None or info.native is None:
            # An unevaluated selected helper/global is fixed-point bottom,
            # not evidence of a custom runtime Reader. Its dependent caller
            # is revisited when result metadata arrives. Actual unknown
            # returns use _UNKNOWN_NATIVE and still fail the proof below.
            return fact
        reader = info.reader if info is not None else None
        if reader is not None:
            if not reader.definite or reader.methods != {''} or 'scanner' in reader.kinds:
                raise AnalysisLimit('Go reader protocol alternative is unsupported; analysis is incomplete')
            return reader.source
        if require:
            # A generic summary is parameterized over its caller's Reader.
            # Actual custom Readers must not silently become clean handles.
            if fact and all(trace.parameter is not None for trace in fact):
                return frozenset(replace(trace, projection='reader') for trace in fact)
            raise AnalysisLimit('Go custom reader protocol is unsupported; analysis is incomplete')
        return fact

    def mark_scanned(self, origins, state):
        if any(key.cell in self.global_cells and reader is not None and reader.origins & origins
               for key, reader in state.items() if isinstance(key, _ReaderKey)):
            raise AnalysisLimit('Go package scanner mutation is unsupported; analysis is incomplete')
        self.reader_scans.update(origins)
        for key, reader in list(state.items()):
            if isinstance(key, _ReaderKey) and reader is not None and reader.origins & origins:
                state[key] = replace(reader, scanned=True)

    def reader_method(self, reader, method, arguments, values, state, scope):
        """Native textual input and clean metadata; no custom split/heap model."""
        if not reader.definite:
            raise AnalysisLimit('Go reader method alternative is unsupported; analysis is incomplete')
        if reader.kinds == {'scanner'}:
            if method == 'Scan':
                self.mark_scanned(reader.origins, state)
                return (_CLEAN,)
            if method in {'Text', 'Bytes'}:
                return (reader.source if reader.scanned else _CLEAN,)
            if method == 'Err':
                return (_CLEAN,)
            if method == 'Buffer':
                # Buffer's contents are ignored by Scanner; only capacity is used.
                return ()
            if method == 'Split' and len(arguments) == 1:
                info = self.value_info(*arguments[0], state, scope)
                native = info.native if info is not None else None
                if (native is not None and not native.unknown and native.operations
                        and native.operations <= _BUFFER_SPLITTERS):
                    return ()
                raise AnalysisLimit('Go custom scanner split is unsupported; analysis is incomplete')
        elif 'scanner' not in reader.kinds:
            if method in {'ReadString', 'ReadBytes', 'ReadSlice', 'Peek', 'ReadByte'}:
                return (reader.source, _CLEAN)
            if method in {'ReadLine', 'ReadRune'}:
                return (reader.source, _CLEAN, _CLEAN)
            if method in {'Bytes', 'String', 'Next'} and reader.kinds <= {'bytes-buffer'}:
                return (reader.source,)
            if method in {'Buffered', 'Size', 'Len', 'Cap', 'Available', 'Name', 'Fd'}:
                return (_CLEAN,)
            if method in {'UnreadByte', 'UnreadRune', 'Close'}:
                return (_CLEAN,)
            if method in {'Discard', 'Seek', 'Stat'}:
                return (_CLEAN, _CLEAN)
        raise AnalysisLimit('Go reader ' + method + ' mutation or protocol is unsupported; analysis is incomplete')

    def scan_type(self, typename, scope):
        typename = re.sub(r'\s+', '', typename)
        if typename == 'string' and 'string' not in scope.bindings and 'string' not in self.summaries:
            return 'text'
        if typename in {'[]byte', '[]uint8'} and not any(
                name in scope.bindings or name in self.summaries for name in ('byte', 'uint8')):
            return 'text'
        return ''

    def scan_kind(self, expr, offset, state, scope):
        """Prove a builtin text destination without borrowing fmt.Scanner authority."""
        expr, offset = self.unparenthesize(expr, offset)
        if _string_literal(expr) is not None:
            return 'text'
        if re.fullmatch(r'[A-Za-z_]\w*', expr):
            return state.get(_ScanKindKey(scope.bindings.get(expr, expr)), '')
        if re.fullmatch(r'(?:r|req|request)\s*\.\s*Body', expr):
            return 'request-reader'
        construction = re.fullmatch(r'new\s*\(\s*(string|\[\]\s*(?:byte|uint8))\s*\)', expr)
        if construction and 'new' not in scope.bindings and 'new' not in self.summaries:
            return self.scan_type(construction.group(1), scope)
        conversion = re.match(r'(string|\[\]\s*(?:byte|uint8))\s*\(', expr)
        if conversion:
            return self.scan_type(conversion.group(1), scope)
        call = re.fullmatch(r'([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(.*\)', expr, re.DOTALL)
        if call:
            identity = self.native_identity(call.group(1), call.group(2), offset, scope)
            if identity in _ENVIRONMENT_OPERATIONS | _HTML_SANITIZERS:
                return 'text'
        return ''

    def read_into(self, operations, arguments, values, state, scope):
        """Native Reader payloads weakly modify a byte slice's backing array.

        ReadFull calls ReadAtLeast with len(buffer). ReadAtLeast never calls
        the Reader for a nonpositive minimum or a minimum above len(buffer).
        A positive read can stop after a prefix, even with an error; neither
        the count/error results nor later fixed input clear prior contents.
        """
        if len(operations) != 1:
            raise AnalysisLimit('Go reader destination operation alternatives are unsupported; analysis is incomplete')
        operation = next(iter(operations))[1]
        if len(arguments) != (2 if operation == 'ReadFull' else 3):
            raise AnalysisLimit('Go reader destination argument shape is unsupported; analysis is incomplete')
        minimum = self.integer_literal(arguments[2][0]) if operation == 'ReadAtLeast' else None
        if minimum is not None and minimum <= 0:
            return
        info = self.value_info(*arguments[1], state, scope)
        if info is None or info.native is None:
            return  # A selected forward result has not reached the worklist yet.
        buffer = info.buffer
        if buffer is not None and buffer.definite:
            if buffer.length == 0 or (minimum is not None and buffer.length is not None
                                      and minimum > buffer.length):
                return
        self.check_buffer_write(info, state)
        payload = self.reader_payload(*arguments[0], values[0], state, scope, require=True)
        self.write_targets(info.pointers, payload, state, 'io.' + operation, buffer=True)
        for target in info.pointers:
            self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), payload)

    def copy_buffer(self, arguments, state, scope):
        """Copy native bytes into shared backing cells, keeping the count clean.

        copy may modify only a prefix, including when source and destination
        overlap. Weak writes preserve the untouched suffix and aliases; a
        fixed replacement is not proof that every prior source was erased.
        """
        if len(arguments) != 2:
            raise AnalysisLimit('Go buffer copy argument shape is unsupported; analysis is incomplete')
        destination_text, _ = self.unparenthesize(arguments[0][0])
        passive_destination = re.fullmatch(r'[A-Za-z_]\w*', destination_text) is not None
        sliced = re.fullmatch(r'([A-Za-z_]\w*)\s*\[(.*)\]', _masked_source(destination_text), re.DOTALL)
        if sliced is not None:
            original_bounds = destination_text[sliced.start(2):sliced.end(2)]
            bounds = [original_bounds[start:end].strip()
                      for start, end in _parts(sliced.group(2), ':')]
            passive_destination = (len(bounds) in {2, 3}
                                   and all(not bound or self.integer_literal(bound) is not None for bound in bounds))
        values, infos = [], []
        for expression, origin in arguments:
            values.append(self.value(expression, origin, state, scope))
            infos.append(self.value_info(expression, origin, state, scope))
        # Effectful destination expressions can change an ordinary source
        # read, whose order relative to the call is not fixed by Go. Refuse
        # that case after retaining argument effects instead of copying only
        # the post-call source. Direct names and literal reslices are passive.
        if not passive_destination:
            raise AnalysisLimit('Go buffer copy destination evaluation is unsupported; analysis is incomplete')
        # Keep every available backing observation before granting a native
        # write. Existing captured-header and ownership boundaries still apply;
        # joining metadata here does not bypass the enclosing evaluator.
        destination = _join_value_info(infos[0], self.value_info(*arguments[0], state, scope))
        source = infos[1]
        if destination is None or destination.native is None or source is None or source.native is None:
            return  # A selected forward result has not reached the worklist yet.
        if destination.buffer is not None and destination.buffer.definite and destination.buffer.length == 0:
            return
        if source.buffer is not None and source.buffer.definite and source.buffer.length == 0:
            return
        if _string_literal(arguments[1][0]) == '':
            return
        self.check_buffer_write(destination, state)
        if not self.buffer_source_proven(*arguments[1], source, state, scope):
            raise AnalysisLimit('Go buffer copy source identity or escape is unsupported; analysis is incomplete')
        payload = values[1]
        self.write_targets(destination.pointers, payload, state, 'copy', buffer=True)
        for target in destination.pointers:
            self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), payload)

    def scan_input(self, operations, arguments, values, targets, state, scope):
        """Bounded native text scanning; unsupported protocols remain visible.

        fmt.Scan* reads stdin, Fscan* reads its first Reader, and Sscan* reads
        its first string. The format is never input contents. Partial scans
        leave later destinations unchanged, so these are weak writes. Return
        counts/errors for the supported token/text contract are not payloads.
        Custom Scanner methods, numeric-to-rune conversion and encoded text
        need more than this engine's current fact lattice and fail explicitly.
        """
        layouts = {(operation.startswith('Scan'), operation.startswith('Fscan'), operation.endswith('f'))
                   for _, operation in operations}
        if len(layouts) != 1:
            raise AnalysisLimit('Go formatted input callable alternatives are unsupported; analysis is incomplete')
        stdin, reader, formatted = next(iter(layouts))
        first = (0 if stdin else 1) + int(formatted)
        if len(arguments) < first:
            raise AnalysisLimit('Go formatted input argument shape is unsupported; analysis is incomplete')
        verbs = ['s'] * (len(arguments) - first)
        if formatted:
            format_text = _string_literal(arguments[first - 1][0])
            if format_text is None:
                raise AnalysisLimit('Go formatted input dynamic format is unsupported; analysis is incomplete')
            verbs = []
            cursor = 0
            while cursor < len(format_text):
                if format_text[cursor] != '%':
                    cursor += 1
                    continue
                directive = re.match(r'%(\d*)([%sv])', format_text[cursor:])
                if directive is None:
                    raise AnalysisLimit('Go formatted input encoded or nontext format is unsupported; analysis is incomplete')
                if directive.group(2) != '%':
                    verbs.append('' if directive.group(1) and not directive.group(1).strip('0')
                                 else directive.group(2))
                cursor += directive.end()
        if not verbs or len(arguments) == first:
            return
        if stdin:
            payload = frozenset({_Trace('os.Stdin', path=('os.Stdin',))})
        else:
            payload = values[0]
            if reader:
                try:
                    payload = self.reader_payload(*arguments[0], payload, state, scope, require=True)
                except AnalysisLimit as error:
                    raise AnalysisLimit('Go formatted input reader protocol is unsupported; analysis is incomplete') from error
        for index, verb in enumerate(verbs, first):
            if index >= len(arguments):
                break
            if not verb:
                continue
            argument, _origin = arguments[index]
            destinations = targets[index]
            if (argument.rstrip().endswith('...') or not destinations
                    or any(not target.whole or target.path or target.indexed or target.cell in self.global_cells
                           or state.get(_ScanKindKey(target.cell)) != 'text' for target in destinations)):
                raise AnalysisLimit('Go formatted input destination or Scanner protocol is unsupported; analysis is incomplete')
            self.write_targets(destinations, payload, state, 'fmt.' + sorted(operations)[0][1])
            for target in destinations:
                self.scan_writes[target] = _join(self.scan_writes.get(target, _CLEAN), payload)

    def invalidate_native_targets(self, targets, state):
        # Code receiving an address can replace the callable or retain that
        # address. Keep possible native writes, but never its sanitizer proof.
        for target in targets:
            key = _NativeKey(target.cell)
            if key in state:
                state[key] = _join_native(state[key], _UNKNOWN_NATIVE)
                self.native_mutations.add(target.cell)
                self.native_escapes.add(target.cell)

    def invalidate_address_cell(self, expr, state, scope):
        # Points-to facts may collapse an address through its aggregate. Keep
        # the exact addressed binding uncertain too: a callee receiving &ptr
        # can replace ptr without replacing an earlier copied pointer value.
        expr, _ = self.unparenthesize(expr)
        if expr.startswith('&'):
            name, _ = self.unparenthesize(expr[1:])
            if re.fullmatch(r'[A-Za-z_]\w*', name) and name in scope.bindings:
                self.invalidate_native_targets((_Target(scope.bindings[name]),), state)

    def write_targets(self, targets, fact, state, label, *, buffer=False):
        # Decode can partially modify an object even when it returns an error.
        # It can also leave omitted fields untouched. Weak aggregate writes
        # preserve both possibilities; a clean document is not a sanitizer.
        fact = _advance(fact, label)
        pending, seen = list(targets), set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            self.invalidate_borrowed_buffer(target)
            if not target.path:
                pending.extend(state.get(_PointerKey(target.cell), ()))
                previous_buffer = state.get(_BufferKey(target.cell))
                if not buffer and previous_buffer is not None:
                    # Decoder writes through &slice may replace its header as
                    # well as reuse its old backing array. Keep both content
                    # effects without preserving the old length/identity proof.
                    replacement = _BufferInfo(definite=False)
                    state[_BufferKey(target.cell)] = replacement
                    self.buffer_cell_writes[target.cell] = replacement
            self.store_target(target, _join(_field_fact(state, target.cell, target.path), fact), state)
            if target.parameter is not None:
                key = (target.parameter, target.path)
                self.writes[key] = _join(self.writes.get(key, _CLEAN), fact)

    @staticmethod
    def store_target(target, fact, state):
        for key in list(state):
            if (isinstance(key, _FieldKey) and key.cell == target.cell
                    and key.path[:len(target.path)] == target.path):
                state.pop(key)
        state[_FieldKey(target.cell, target.path) if target.path else target.cell] = fact

    def assign_targets(self, targets, fact, info, image, state, label, *, compound=False):
        # A known scalar cell can be replaced. A field, joined destination or
        # collapsed heap/pointer alias still needs a weak aggregate write;
        # clearing it could erase other fields or another possible pointee.
        strong = (not compound and len(targets) == 1 and all(
            target.whole and (target.path or not any(alias.cell == target.cell
                              for alias in state.get(_PointerKey(target.cell), ()))) for target in targets))
        fact = _advance(fact, label)
        self.invalidate_native_targets(targets, state)
        global_backing = {pointer.cell for cell in self.global_cells
                          if state.get(_BufferKey(cell)) is not None
                          for pointer in state.get(_PointerKey(cell), ())}
        for target in targets:
            if target.indexed and target.cell in global_backing:
                raise AnalysisLimit('Go package buffer mutation is unsupported; analysis is incomplete')
            target_buffer = state.get(_BufferKey(target.cell))
            if target.indexed and target_buffer is not None and not target_buffer.definite:
                # A returned or joined slice may still carry readable contents
                # without an owned backing identity. Updating a scalar snapshot
                # here would lose writes visible through its original aliases.
                raise AnalysisLimit('Go reader result buffer mutation is unsupported; analysis is incomplete')
            if (target.cell.startswith('@byte-buffer:')
                    and any(escaped.cell == target.cell for escaped in self.buffer_escapes)):
                raise AnalysisLimit('Go escaped buffer mutation is unsupported; analysis is incomplete')
            decoder = state.get(_DecoderKey(target.cell))
            if decoder is not None and decoder.methods == {''} and (target.path or target.indexed):
                raise AnalysisLimit('Go decoder receiver mutation is unsupported; analysis is incomplete')
            written = _advance(image[0], label) if strong and image is not None else fact
            if (strong and not target.path and info is not None and info.pointers
                    and all(pointer.parameter is None for pointer in info.pointers)):
                written = _CLEAN
            self.store_target(target, written if strong else
                              _join(_field_fact(state, target.cell, target.path), fact), state)
            if strong and image is not None:
                for path, field_fact in image[1]:
                    destination = _field_target(target, path)
                    if destination.path:
                        state[_FieldKey(destination.cell, destination.path)] = _advance(field_fact, label)
                    else:
                        state[destination.cell] = _join(state.get(destination.cell, _CLEAN), field_fact)
            if target.parameter is not None:
                if info is not None and info.reader is not None:
                    raise AnalysisLimit('Go reader output-parameter replacement is unsupported; analysis is incomplete')
                if info is not None and info.decoder is not None:
                    raise AnalysisLimit('Go decoder output-parameter transport is unsupported; analysis is incomplete')
                key = (target.parameter, target.path)
                self.writes[key] = _join(self.writes.get(key, _CLEAN), fact)
                native = info.native if info is not None else None
                self.native_writes[key] = _join_native(self.native_writes.get(key), native)
            if target.path or target.indexed:
                self.invalidate_borrowed_buffer(target)
                self.escape_buffer(info, state=state)
                if target.cell.startswith('@byte-buffer:') or state.get(_BufferKey(target.cell)) is not None:
                    self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), fact)
                if info is not None and info.native is not None and info.native.operations & _CALLABLE_OPERATIONS:
                    raise _callable_boundary(info.native.operations, 'field/index storage')
                if info is not None and info.reader is not None:
                    raise AnalysisLimit('Go reader field/index storage is unsupported; analysis is incomplete')
                if info is not None and info.decoder is not None:
                    raise AnalysisLimit('Go decoder field/index storage is unsupported; analysis is incomplete')
                continue
            native_key = _NativeKey(target.cell)
            native = info.native if info is not None else None
            state[native_key] = native if strong else _join_native(state.get(native_key), native)
            self.native_cell_writes[target.cell] = _join_native(
                self.native_cell_writes.get(target.cell), native)
            if strong and info is not None:
                state[_PointerKey(target.cell)] = info.pointers
            decoder_key = _DecoderKey(target.cell)
            previous = state.get(decoder_key)
            replacement = info.decoder if info is not None else None
            if replacement is None and previous is not None:
                replacement = replace(previous, source=_join(previous.source, fact), definite=False)
            if strong:
                state[decoder_key] = replacement
            elif previous is not None or replacement is not None:
                state[decoder_key] = _join_decoders(previous, replacement)
            self.decoder_cell_writes[target.cell] = (
                _join_decoders(self.decoder_cell_writes[target.cell], replacement)
                if target.cell in self.decoder_cell_writes else replacement)
            reader_key = _ReaderKey(target.cell)
            replacement = info.reader if info is not None else None
            state[reader_key] = replacement if strong else _join_readers(state.get(reader_key), replacement)
            self.reader_cell_writes[target.cell] = (
                _join_readers(self.reader_cell_writes[target.cell], replacement)
                if target.cell in self.reader_cell_writes else replacement)
            buffer_key = _BufferKey(target.cell)
            replacement = info.buffer if info is not None else None
            state[buffer_key] = replacement if strong else _join_buffers(state.get(buffer_key), replacement)
            self.buffer_cell_writes[target.cell] = (
                _join_buffers(self.buffer_cell_writes[target.cell], replacement)
                if target.cell in self.buffer_cell_writes else replacement)

    def native_call(self, expression, match, state, scope, *, whole=False):
        """Known result shapes and output-parameter effects, never name-only Decode."""
        expr, code, pairs, offset = expression.text, expression.code, expression.pairs, expression.offset
        root, member = match.group(1), match.group(2)
        result_offset = offset + match.start(1)
        self.call_results.pop(result_offset, None)
        end = pairs.get(match.end() - 1)
        if end is None or code[:match.start()].rstrip().endswith('.'):
            return None
        receiver = state.get(_DecoderKey(scope.bindings.get(root, root)))
        if result_offset in self.decoder_callees:
            receiver = _join_decoders(receiver, self.decoder_callees.pop(result_offset))
        bound_decoder = receiver is not None and member is None and receiver.methods != {''}
        input_reader = state.get(_ReaderKey(scope.bindings.get(root, root)))
        reader_method = member if input_reader is not None and member is not None else None
        if input_reader is not None and member is None and input_reader.methods != {''}:
            if len(input_reader.methods) != 1 or '' in input_reader.methods:
                raise AnalysisLimit('Go reader method alternatives are unsupported; analysis is incomplete')
            reader_method = next(iter(input_reader.methods))
        callable_source = state.get(scope.bindings.get(root, root), _CLEAN)
        native = self.native_callable(root, member, offset + match.start(1), state, scope)
        operations = native.operations if native is not None else frozenset()
        constructor = bool(operations) and operations <= {('json', 'NewDecoder'), ('xml', 'NewDecoder')}
        unmarshal = bool(operations) and operations <= {('json', 'Unmarshal'), ('xml', 'Unmarshal')}
        readall = bool(operations) and operations <= {('io', 'ReadAll'), ('ioutil', 'ReadAll')}
        sanitizer = bool(operations) and operations <= _HTML_SANITIZERS
        environment = operations & _ENVIRONMENT_OPERATIONS
        scanning = operations & _SCAN_OPERATIONS
        reading_into = operations & _READ_INTO_OPERATIONS
        copying = (root == 'copy' and member is None and root not in scope.bindings
                   and root not in self.summaries)
        commands = operations & _COMMAND_OPERATIONS
        unbound_command = (not commands and root == 'exec' and member in _NATIVE_MEMBERS['exec']
                           and root not in scope.bindings and root not in self.summaries
                           and not self.imports.has_name(root, result_offset))
        reader_constructor = operations & _READER_CONSTRUCTORS.keys()
        method = member if receiver is not None and receiver.methods == {''} and member in _DECODER_METHODS else None
        if bound_decoder:
            method = next(iter(receiver.methods)) if len(receiver.methods) == 1 else 'bound-alternative'
        chain = None
        outer_end = end
        if constructor:
            chain = re.match(r'\s*\.\s*(Decode|DecodeElement|Token|RawToken|More|InputOffset|'
                             r'UseNumber|DisallowUnknownFields|Buffered)\s*\(', code[end + 1:])
            if chain:
                opening = end + chain.end()
                outer_end = pairs.get(opening)
                if outer_end is None:
                    return None
        if reader_constructor:
            chain = re.match(r'\s*\.\s*([A-Za-z_]\w*)\s*\(', code[end + 1:])
            if chain:
                outer_end = pairs.get(end + chain.end())
                if outer_end is None:
                    return None
        if not (constructor or unmarshal or readall or sanitizer or environment or scanning or reading_into or copying or commands
                or unbound_command or method
                or reader_constructor or reader_method):
            return None
        if whole and code[outer_end + 1:].strip():
            return None
        if sanitizer and re.match(r'\s*[.\[]', code[end + 1:]):
            return None

        if chain is not None:
            self.chained_call_results.pop((result_offset, offset + outer_end), None)

        def finish(stop, facts, decoder=None, reader=None, first_info=None):
            result_infos = tuple(
                first_info if index == 0 and first_info is not None else
                _ValueInfo(decoder=decoder if index == 0 else None, reader=reader if index == 0 else None)
                for index in range(len(facts)))
            self.call_results[result_offset] = result_infos
            if chain is not None:
                self.chained_call_results[(result_offset, offset + stop)] = result_infos
            return stop, facts

        def arguments(start, stop):
            values, targets, _raw = self._eval_call_args(expr, code, offset, start, stop, state, scope)
            return values, targets

        if copying:
            raw_arguments = [(expr[match.end() + left:match.end() + right], offset + match.end() + left)
                             for left, right in _parts(code[match.end():end])]
            if re.search(r'\b(?:go|defer)\s*$', code[:match.start()]):
                for argument, origin in raw_arguments:
                    self.value(argument, origin, state, scope)
                raise AnalysisLimit('Go delayed buffer copy is unsupported; analysis is incomplete')
            self.copy_buffer(raw_arguments, state, scope)
            return finish(end, (_CLEAN,))

        values, targets = arguments(match.end(), end)
        raw_arguments = [(expr[match.end() + left:match.end() + right], offset + match.end() + left)
                         for left, right in _parts(code[match.end():end])]
        if unbound_command:
            # Importless editor fragments retain conventional native names.
            # An explicit but incomplete import list cannot prove either a
            # standard constructor or a safe custom binding. Keep that
            # coverage boundary visible after retaining argument effects.
            raise AnalysisLimit('Go command namespace has no imported or local binding; analysis is incomplete')
        if native is not None:
            # Argument effects can invalidate a captured callable. Ordinary
            # reads and calls need not have one total evaluation order in Go,
            # so retain both identities instead of gaining sanitizer proof.
            native = _join_native(native, self.native_callable(root, member,
                                                               offset + match.start(1), state, scope))
        # Unknown callbacks can retain request data in the function value even
        # when every argument is clean. Variable reads can occur on either side
        # of argument calls, so retain both observed cell facts.
        callable_source = (_join(callable_source, state.get(scope.bindings.get(root, root), _CLEAN))
                           if native is not None and native.unknown else _CLEAN)
        fallback = _join(*values, callable_source)
        if bound_decoder:
            current_receiver = state.get(_DecoderKey(scope.bindings.get(root, root)))
            receiver = _join_decoders(receiver, current_receiver)
            supported_methods = (receiver.methods in ({'Decode'}, {'DecodeElement'}, {'Buffered'},
                                 {'More'}, {'InputOffset'}, {'UseNumber'}, {'DisallowUnknownFields'})
                                 or receiver.methods <= {'Token', 'RawToken'})
            if (not receiver.definite or not supported_methods
                    or scope.bindings.get(root, root) in self.uncertain_globals):
                raise AnalysisLimit('Go decoder method alternative is unsupported; analysis is incomplete')
            method = 'Token' if receiver.methods <= {'Token', 'RawToken'} else next(iter(receiver.methods))
        # Argument evaluation may install another possible getter. Keep the
        # pre-call family flags for existing decoder contracts, but do not
        # lose a source introduced by that captured-cell write.
        operations = native.operations if native is not None else frozenset()
        environment = operations & _ENVIRONMENT_OPERATIONS
        scanning = operations & _SCAN_OPERATIONS
        reading_into = operations & _READ_INTO_OPERATIONS
        commands = operations & _COMMAND_OPERATIONS
        if commands:
            # Constructor identity belongs to its file-local import or saved
            # callable. A same-spelled custom object does not execute commands.
            # A fixed executable takes data arguments unless they select an
            # interpreter's program/script slot; context is never that slot.
            if self.rule == 'go.taint.command':
                selected = []
                for _package, operation in commands:
                    first = int(operation == 'CommandContext')
                    operands = [argument for argument, _origin in raw_arguments[first:]]
                    selected.extend(values[first + index] for index in _command_arguments(operands))
                self.effect(result_offset, 'exec.Command', _join(*selected))
            if native.unknown or operations != commands:
                # The native alternative is a real possible sink, but an
                # unresolved replacement can have different operand effects.
                # Preserve the reached finding without certifying its return
                # contract or resuming the caller with incomplete knowledge.
                raise _callable_boundary(commands, 'alternative')
            # Cmd retains its supplied operands. Do not launder those contents
            # when the constructed object later flows to another interpreter.
            return finish(end, (fallback,))
        if reader_constructor:
            if native.unknown or operations != reader_constructor:
                raise AnalysisLimit('Go reader constructor alternative is unsupported; analysis is incomplete')
            if not values:
                raise AnalysisLimit('Go reader constructor argument shape is unsupported; analysis is incomplete')
            kinds = frozenset(_READER_CONSTRUCTORS[operation] for operation in reader_constructor)
            wrapped = any(package == 'bufio' for package, _operation in reader_constructor)
            if wrapped and any(package != 'bufio' for package, _operation in reader_constructor):
                raise AnalysisLimit('Go reader constructor argument alternatives are unsupported; analysis is incomplete')
            payload = (self.reader_payload(*raw_arguments[0], values[0], state, scope, require=True)
                       if wrapped else values[0])
            if any(package == 'bytes' and operation in {'NewReader', 'NewBuffer'}
                   for package, operation in reader_constructor):
                # These objects retain the supplied backing array. A later
                # write cannot be represented by a snapshot of its old facts.
                self.escape_buffer(self.value_info(*raw_arguments[0], state, scope), borrow=True)
            input_reader = _ReaderInfo(payload, kinds, frozenset({_ReaderOrigin((result_offset, result_offset))}))
            if not chain:
                return finish(end, (_CLEAN,), reader=input_reader)
            reader_method = chain.group(1)
            start = end + chain.end() + 1
            values, targets = arguments(start, outer_end)
            raw_arguments = [(expr[start + left:start + right], offset + start + left)
                             for left, right in _parts(code[start:outer_end])]
        if reader_method:
            # An argument can itself Scan a saved receiver. Preserve that
            # mutation before reading Text/Bytes on the enclosing invocation.
            current_reader = state.get(_ReaderKey(scope.bindings.get(root, root)))
            if current_reader is not None and not reader_constructor:
                input_reader = _join_readers(input_reader, current_reader)
            facts = self.reader_method(input_reader, reader_method, raw_arguments, values, state, scope)
            return finish(outer_end, facts)
        if scanning:
            if native.unknown or operations != scanning:
                raise AnalysisLimit('Go formatted input unknown callable alternative is unsupported; analysis is incomplete')
            self.scan_input(scanning, raw_arguments, values, targets, state, scope)
            return finish(end, (_CLEAN, _CLEAN))
        if reading_into:
            if native.unknown or operations != reading_into:
                raise AnalysisLimit('Go reader destination callable alternative is unsupported; analysis is incomplete')
            self.read_into(reading_into, raw_arguments, values, state, scope)
            return finish(end, (_CLEAN, _CLEAN))
        if environment:
            if len(values) != 1:
                return finish(end, (fallback,))
            # Reading a native environment value introduces provenance even
            # when its key is literal. Merely taking the function's address
            # introduces none. A possible getter branch must also survive a
            # join with an escaper or an unknown callback of the same type.
            sources = frozenset(_Trace(package + '.' + operation,
                                       path=(package + '.' + operation,))
                                for package, operation in environment)
            payload = _join(sources, fallback if native.unknown or operations != environment else _CLEAN)
            if operations == {('os', 'LookupEnv')}:
                return finish(end, (payload, fallback if native.unknown else _CLEAN))
            return finish(end, (payload,))
        if constructor:
            if len(values) != 1:
                return finish(end, (_CLEAN,))
            payload = self.reader_payload(*raw_arguments[0], values[0], state, scope, require=True)
            receiver = _DecoderInfo(_join(payload, callable_source), not native.unknown)
            if not chain:
                return finish(end, (_join(fallback, payload) if native.unknown else _CLEAN,), receiver)
            method = chain.group(1)
            values, targets = arguments(end + chain.end() + 1, outer_end)
        if unmarshal:
            if len(values) == 2:
                self.write_targets(targets[1], _join(values[0], callable_source), state,
                                   root + '.Unmarshal' if member else root)
            return finish(end, (fallback if native.unknown else _CLEAN,))
        if readall:
            payload = (self.reader_payload(*raw_arguments[0], values[0], state, scope, require=True)
                       if len(values) == 1 else fallback)
            # Native ReadAll owns a fresh byte array, even when the Reader's
            # contents are clean or the operation returns a partial read/error.
            # Slice assignments share that storage; string conversions do not.
            # A call-site cell is finite across loops, so retain previous facts
            # when the same allocation site may still have a live older alias.
            info = _ValueInfo(buffer=_BufferInfo(definite=False))
            if (not native.unknown and operations
                    and operations <= {('io', 'ReadAll'), ('ioutil', 'ReadAll')}
                    and len(values) == 1):
                target = _Target(f'@byte-buffer:readall:{result_offset}')
                state[target.cell] = _join(state.get(target.cell, _CLEAN), payload)
                self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), payload)
                info = _ValueInfo(pointers=frozenset({target}), buffer=_BufferInfo())
            return finish(end, (_join(payload, callable_source),
                                _join(payload, fallback) if native.unknown else _CLEAN), first_info=info)
        if sanitizer:
            # Only a definite native escaper grants HTML sanitization; unknown
            # alternatives retain argument effects and captured source data.
            # EscapeString and HTMLEscapeString take one string; HTMLEscaper is
            # variadic (...any) and escapes the formatted result of all args.
            arity_ok = len(values) == 1 or operations == {('template', 'HTMLEscaper')}
            clean = self.rule == 'go.taint.xss' and not native.unknown and arity_ok
            return finish(end, (_CLEAN if clean else fallback,))
        extra_fallback = _join(callable_source, state.get(scope.bindings.get(root, root), _CLEAN))
        result, buffered_reader = self._apply_decoder_method(
            receiver, method, values, targets, result_offset, state, callable_source, extra_fallback)
        return finish(outer_end, result, reader=buffered_reader)

    def _eval_call_args(self, expr, code, offset, start, stop, state, scope):
        values, targets, raw_arguments = [], [], []
        for left, right in _parts(code[start:stop]):
            value = expr[start + left:start + right]
            origin = offset + start + left
            raw_arguments.append((value, origin))
            values.append(self.value(value, origin, state, scope))
            info = self.value_info(value, origin, state, scope)
            # A slice value is not a Go output pointer. Read-into uses
            # its separate backing capability; Decode/Unmarshal still
            # require an actual address, such as &buffer.
            targets.append(info.pointers if info is not None and info.buffer is None else frozenset())
        return values, targets, raw_arguments

    def _apply_decoder_method(self, receiver, method, values, targets, result_offset, state,
                              callable_source=_CLEAN, extra_fallback=_CLEAN):
        if method in {'Decode', 'DecodeElement'}:
            if targets:
                source = (_join(receiver.source, callable_source)
                          if not receiver.definite else receiver.source)
                if method == 'DecodeElement':
                    # The supplied StartElement owns attributes already read
                    # from another stream; a fixed remaining reader cannot
                    # turn those attribute values into trusted contents.
                    source = _join(source, *values[1:])
                self.write_targets(targets[0], source, state, method)
            result = (_CLEAN,)
        elif method in {'Token', 'RawToken'}:
            result = (receiver.source, _CLEAN)
        elif method == 'Buffered':
            if receiver.definite:
                return (_CLEAN,), _ReaderInfo(
                    receiver.source, frozenset({'decoder-buffer'}),
                    frozenset({_ReaderOrigin((result_offset, result_offset))}))
            result = (receiver.source,)
        else:
            result = (_CLEAN,)
        if not receiver.definite:
            # A join may also contain a different, unknown implementation.
            result = (_join(*result, *values, extra_fallback),)
        return result, None

    def helper_chained_call(self, expression, match, state, scope):
        """Execute a chained decoder/reader method directly on a package-helper result."""
        if match.group(2) is not None:
            return None
        expr, code, pairs, offset = expression.text, expression.code, expression.pairs, expression.offset
        name = match.group(1)
        if name not in self.summaries or name in scope.bindings:
            return None
        if code[:match.start()].rstrip().endswith('.'):
            return None
        end = pairs.get(match.end() - 1)
        if end is None:
            return None
        chain = re.match(r'\s*\.\s*([A-Za-z_]\w*)\s*\(', code[end + 1:])
        if not chain:
            return None
        outer_end = pairs.get(end + chain.end())
        if outer_end is None:
            return None
        call_offset = offset + match.start(1)
        self.chained_call_results.pop((call_offset, offset + outer_end), None)
        helper_facts = self.call(name, expr[match.end():end], offset + match.end(), call_offset, state, scope)
        result_infos = self.call_results.get(call_offset, ())
        primary = result_infos[0] if result_infos else None
        method = chain.group(1)
        arg_start = end + chain.end() + 1
        whole_expr = not code[:match.start()].strip() and not code[outer_end + 1:].strip()
        if primary is not None and primary.decoder is not None:
            if primary.decoder.methods != {''}:
                raise AnalysisLimit('Go decoder method alternative is unsupported; analysis is incomplete')
            if method not in _DECODER_METHODS:
                raise AnalysisLimit('Go decoder ' + method + ' method is unsupported; analysis is incomplete')
            chain_values, chain_targets, _raw = self._eval_call_args(
                expr, code, offset, arg_start, outer_end, state, scope)
            result_facts, buffered_reader = self._apply_decoder_method(
                primary.decoder, method, chain_values, chain_targets, call_offset, state)
            chained_infos = tuple(
                _ValueInfo(reader=buffered_reader if index == 0 else None)
                for index in range(len(result_facts)))
            self.chained_call_results[(call_offset, offset + outer_end)] = chained_infos
            if whole_expr:
                self.chained_value_results[offset] = (result_facts, chained_infos)
            return outer_end, result_facts
        if primary is not None and primary.reader is not None:
            if primary.reader.methods != {''}:
                raise AnalysisLimit('Go reader method alternatives are unsupported; analysis is incomplete')
            chain_values, _targets, raw_arguments = self._eval_call_args(
                expr, code, offset, arg_start, outer_end, state, scope)
            result_facts = self.reader_method(primary.reader, method, raw_arguments, chain_values, state, scope)
            chained_infos = tuple(_ValueInfo() for _ in result_facts)
            self.chained_call_results[(call_offset, offset + outer_end)] = chained_infos
            if whole_expr:
                self.chained_value_results[offset] = (result_facts, chained_infos)
            return outer_end, result_facts
        if primary is None or primary.native is None:
            # Fixed-point bottom: helper metadata has not converged yet.
            # Preserve bottom so enclosing reader_payload waits for the next
            # iteration instead of treating the chained call as a custom Reader.
            self.chained_call_results[(call_offset, offset + outer_end)] = (None,)
            if whole_expr:
                self.chained_value_results[offset] = (helper_facts, (None,))
            return end, helper_facts
        return end, helper_facts

    def effect(self, offset: int, label: str, fact: _Fact):
        if fact:
            key = (offset, label)
            self.effects[key] = _join(self.effects.get(key, _CLEAN), fact)

    def instantiate(self, fact: _Fact, arguments: list[_Fact], name: str, infos=()) -> _Fact:
        result = []
        for trace in fact:
            if trace.parameter is None:
                result.append(_advance(frozenset({trace}), name + '()'))
            elif trace.parameter < len(arguments):
                argument = arguments[trace.parameter]
                if trace.projection == 'decoder':
                    info = infos[trace.parameter] if trace.parameter < len(infos) else None
                    argument = info.decoder.source if info is not None and info.decoder is not None else argument
                elif trace.projection == 'reader':
                    info = infos[trace.parameter] if trace.parameter < len(infos) else None
                    if info is not None and info.reader is not None:
                        if not info.reader.definite or info.reader.methods != {''} or 'scanner' in info.reader.kinds:
                            raise AnalysisLimit('Go helper reader protocol is unsupported; analysis is incomplete')
                        argument = info.reader.source
                    elif not argument or any(item.parameter is None for item in argument):
                        raise AnalysisLimit('Go helper custom reader protocol is unsupported; analysis is incomplete')
                    else:
                        argument = frozenset(replace(item, projection='reader') for item in argument)
                elif trace.projection == 'reader-data':
                    info = infos[trace.parameter] if trace.parameter < len(infos) else None
                    argument = info.reader.source if info is not None and info.reader is not None else argument
                bound = _advance(argument, name + '()')
                for step in trace.path[1:]:
                    bound = _advance(bound, step)
                result.append(bound)
        return _join(*result)

    def call(self, name: str, expr: str, offset: int, call_offset: int, state, scope) -> tuple[_Fact, ...]:
        arguments, infos, expressions = [], [], []
        parts = _parts(_masked_source(expr))
        for start, end in parts:
            expression, origin = expr[start:end], offset + start
            if len(parts) == 1:
                values = self.values(expression, origin, state, scope)
                metadata = self.value_results[origin]
            else:
                values = (self.value(expression, origin, state, scope),)
                metadata = (self.value_info(expression, origin, state, scope),)
            arguments.extend(values)
            infos.extend(metadata)
            expressions.extend((expression, origin) for _ in values)
            for info in metadata:
                if info is not None:
                    if any(state.get(_DecoderKey(target.cell)) is not None for target in info.pointers):
                        raise AnalysisLimit('Go decoder address transport is unsupported; analysis is incomplete')
                    # A slice argument shares byte backing storage, not the
                    # caller's slice-header or native-function variable.
                    # Selected helper effects already account for content
                    # writes and escapes. Treating its backing parameter as
                    # an output pointer would revoke valid relay summaries.
                    if info.buffer is None:
                        self.invalidate_native_targets(info.pointers, state)
            self.invalidate_address_cell(expression, state, scope)
        for index, (expression, origin) in enumerate(expressions):
            # Argument calls and ordinary variable reads do not have a total
            # order in Go. A later pointer/capture write cannot grant a
            # definite sanitizer to an earlier native-valued argument.
            variable, _ = self.unparenthesize(expression, origin)
            if re.fullmatch(r'[A-Za-z_]\w*', variable):
                infos[index] = _join_value_info(infos[index], self.value_info(expression, origin, state, scope))
                arguments[index] = _join(arguments[index], state.get(scope.bindings.get(variable, variable), _CLEAN))
        summary = self.summaries[name]
        if summary.variadic is not None:
            arguments = [*arguments[:summary.variadic], _join(*arguments[summary.variadic:])]
            infos = [*infos[:summary.variadic], _join_value_info(*infos[summary.variadic:])]
        if self.resolve_summary is not None:
            summary = self.resolve_summary(name, infos)
        targets = [info.pointers if info is not None else frozenset() for info in infos]
        for index in summary.reader_scans:
            if index < len(infos) and infos[index] is not None and infos[index].reader is not None:
                self.mark_scanned(infos[index].reader.origins, state)
        for index in summary.buffer_escapes:
            if index < len(infos):
                self.escape_buffer(infos[index], state=state)
        for index in summary.buffer_borrows:
            if index < len(infos):
                self.escape_buffer(infos[index], borrow=True)
        for index in summary.buffer_writes:
            info = infos[index] if index < len(infos) else None
            self.check_buffer_write(info, state)
        for (_sink_offset, label), fact in summary.effects.items():
            # Concrete sources are reported at the helper itself. Only an
            # input-dependent sink produces an additional call-site finding.
            dependent = frozenset(trace for trace in fact if trace.parameter is not None)
            self.effect(call_offset, label, self.instantiate(dependent, arguments, name, infos))
        for (index, path), fact in summary.writes.items():
            if index < len(targets):
                destinations = frozenset(_field_target(target, path) for target in targets[index])
                payload = self.instantiate(fact, arguments, name, infos)
                if index < len(infos) and infos[index] is not None and infos[index].buffer is not None:
                    if any(target.cell in {escaped.cell for escaped in self.buffer_escapes}
                           for target in destinations):
                        raise AnalysisLimit('Go helper escaped buffer write is unsupported; analysis is incomplete')
                    for target in destinations:
                        self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), payload)
                self.write_targets(destinations, payload, state, name + '()', buffer=index in summary.buffer_writes)
        for (index, path), native in summary.native_writes.items():
            if index >= len(targets):
                continue
            for actual in targets[index]:
                target = _field_target(actual, path)
                if target.path or target.indexed:
                    if native is not None and native.operations & _CALLABLE_OPERATIONS:
                        raise _callable_boundary(native.operations, 'field/index storage')
                    continue
                # Output-parameter summaries are may-writes: another branch or
                # aliased parameter can leave the old callable in place. Keep
                # both identities without confusing a function with its data.
                key = _NativeKey(target.cell)
                state[key] = _join_native(state.get(key), native)
                self.native_mutations.add(target.cell)
                self.native_cell_writes[target.cell] = _join_native(
                    self.native_cell_writes.get(target.cell), native)
                if target.parameter is not None:
                    destination = (target.parameter, target.path)
                    self.native_writes[destination] = _join_native(
                        self.native_writes.get(destination), native)
        result_infos = []
        for info in summary.value_returns:
            if info is None:
                result_infos.append(None)
                continue
            decoder = (replace(info.decoder, source=self.instantiate(info.decoder.source, arguments, name, infos))
                       if info.decoder is not None else None)
            reader = info.reader
            if reader is not None:
                origins = set()
                for origin in reader.origins:
                    if origin.parameter is None:
                        origins.add(_ReaderOrigin((call_offset, origin.site[1])))
                    elif origin.parameter < len(infos):
                        actual = infos[origin.parameter]
                        if actual is not None and actual.reader is not None:
                            origins.update(actual.reader.origins)
                reader = replace(reader, source=self.instantiate(reader.source, arguments, name, infos),
                                 origins=frozenset(origins))
            complete = all(target.parameter is not None and target.parameter < len(targets)
                           and targets[target.parameter] for target in info.pointers)
            pointers = frozenset(replace(_field_target(actual, target.path),
                                         whole=_field_target(actual, target.path).whole and target.whole and complete,
                                         indexed=actual.indexed or target.indexed)
                                 for target in info.pointers
                                 if target.parameter is not None and target.parameter < len(targets)
                                 for actual in targets[target.parameter])
            buffer = info.buffer
            if buffer is not None and info.pointers and not complete:
                # A helper-local allocation needs an escaped heap identity;
                # retain its contents but refuse native writes through a
                # falsely empty or borrowed backing capability.
                buffer = replace(buffer, definite=False)
            result_infos.append(replace(info, decoder=decoder, pointers=pointers, reader=reader, buffer=buffer))
        self.call_results[call_offset] = tuple(result_infos)
        return tuple(self.instantiate(fact, arguments, name, infos) for fact in summary.returns)

    def values(self, expr: str, offset: int, state, scope) -> tuple[_Fact, ...]:
        # Parentheses around a result preserve all tuple slots. Keep the
        # caller's metadata key while inner calls retain their source offsets.
        inner, inner_offset = self.unparenthesize(expr, offset)
        if inner != expr:
            values = self.values(inner, inner_offset, state, scope)
            self.value_results[offset] = self.value_results[inner_offset]
            return values
        code = _call_code(_masked_source(expr))
        parts = _parts(code)
        if len(parts) > 1:
            values, infos = [], []
            for start, end in parts:
                values.append(self.value(expr[start:end], offset + start, state, scope))
                infos.append(self.value_info(expr[start:end], offset + start, state, scope))
            for index, (start, end) in enumerate(parts):
                variable, _ = self.unparenthesize(expr[start:end])
                if re.fullmatch(r'[A-Za-z_]\w*', variable):
                    # Later result expressions may write the same cell. Go
                    # leaves ordinary reads versus calls partly unordered;
                    # both assignments and returns retain either identity.
                    infos[index] = _join_value_info(
                        infos[index], self.value_info(expr[start:end], offset + start, state, scope))
                    values[index] = _join(values[index], state.get(scope.bindings.get(variable, variable), _CLEAN))
            self.value_results[offset] = tuple(infos)
            return tuple(values)
        native = re.match(r'\s*([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?\s*\(', code)
        if native:
            result = self.native_call(_CallExpression(expr, code, _pairs(code), offset), native, state, scope, whole=True)
            if result is not None:
                self.value_results[offset] = self.call_results[offset + native.start(1)]
                return result[1]
        call = re.match(r'\s*([A-Za-z_]\w*)\s*\(', code)
        if call and call.group(1) in self.summaries and call.group(1) not in scope.bindings:
            end = _pairs(code).get(call.end() - 1)
            if end is not None and not code[end + 1:].strip():
                values = self.call(call.group(1), expr[call.end():end], offset + call.end(),
                                   offset + call.start(1), state, scope)
                self.value_results[offset] = self.call_results[offset + call.start(1)]
                return values
        value = self.value(expr, offset, state, scope)
        closure = self.closure_results.get(offset)
        if closure is not None:
            self.value_results[offset] = closure[1]
            return closure[0]
        chained = self.chained_value_results.get(offset)
        if chained is not None:
            self.value_results[offset] = chained[1]
            return chained[0]
        self.value_results[offset] = (self.value_info(expr, offset, state, scope),)
        return (value,)

    def value(self, expr: str, offset: int, state, scope) -> _Fact:
        expr, offset = self.unparenthesize(expr, offset)
        self.closure_results.pop(offset, None)
        self.chained_value_results.pop(offset, None)
        code = _call_code(_masked_source(expr))
        pairs = _pairs(code)
        whole_call = pairs.get(code.find('(')) == len(code) - 1
        conversion = re.fullmatch(r'string\s*\((.*)\)', code, re.DOTALL)
        if conversion and whole_call and 'string' not in scope.bindings and 'string' not in self.summaries:
            return self.value(expr[conversion.start(1):conversion.end(1)],
                              offset + conversion.start(1), state, scope)
        size = re.fullmatch(r'(len|cap)\s*\((.*)\)', code, re.DOTALL)
        if size and whole_call and size.group(1) not in scope.bindings and size.group(1) not in self.summaries:
            self.value(expr[size.start(2):size.end(2)], offset + size.start(2), state, scope)
            return _CLEAN
        self.check_source_storage(code, offset, state, scope)
        masked = list(code)
        facts = []

        def cover(start, end):
            for pos in range(start, end):
                masked[pos] = '\n' if code[pos] == '\n' else ' '

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
            previous = match.start() - 1
            while previous >= 0 and code[previous].isspace():
                previous -= 1
            if (previous >= 0 and code[previous] not in '(:,={'
                    and re.search(r'\b(?:go|defer)\s*$', code[:match.start()]) is None):
                # Function types in slices/maps/fields do not own the next
                # composite literal's brace or invoke their contained values.
                continue
            param_end = pairs.get(match.end() - 1)
            if param_end is None:
                continue
            opening = _Parser(code).body_open(param_end + 1, len(code))
            if opening is not None and opening in pairs:
                close = pairs[opening]
                parameters = _parameter_names(code[match.end():param_end])
                parameter_types = _parameter_types(code[match.end():param_end])
                closure_scope = scope.child()
                invocation = close + 1
                while invocation < len(code) and code[invocation].isspace():
                    invocation += 1
                invoked = invocation < len(code) and code[invocation] == '(' and invocation in pairs
                delayed = re.search(r'\b(?:go|defer)\s*$', code[:match.start()]) is not None
                immediate = invoked and not delayed
                enclosing_sources = {}
                if immediate:
                    for enclosing in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\(', code):
                        if enclosing.start() >= match.start():
                            break
                        if pairs.get(enclosing.end() - 1, -1) <= close:
                            continue
                        name = enclosing.group(1)
                        native = self.native_callable(name, None, offset + enclosing.start(1), state, scope)
                        if native is not None and native.operations & _CALLABLE_OPERATIONS:
                            enclosing_sources[scope.bindings.get(name, name)] = native.operations & _CALLABLE_OPERATIONS
                        decoder = state.get(_DecoderKey(scope.bindings.get(name, name)))
                        if decoder is not None and decoder.methods != {''}:
                            # The function value may be read before its
                            # argument's closure changes the enclosing cell.
                            # Keep that receiver only for this invocation;
                            # later statements see the replacement normally.
                            site = offset + enclosing.start(1)
                            self.decoder_callees[site] = _join_decoders(
                                self.decoder_callees.get(site, decoder), decoder)
                arguments, argument_infos, argument_expressions = [], [], []
                if invoked:
                    parts = _parts(code[invocation + 1:pairs[invocation]])
                    for start, end in parts:
                        argument = expr[invocation + 1 + start:invocation + 1 + end]
                        origin = offset + invocation + 1 + start
                        if len(parts) == 1:
                            values = self.values(argument, origin, state, scope)
                            metadata = self.value_results[origin]
                        else:
                            values = (self.value(argument, origin, state, scope),)
                            metadata = (self.value_info(argument, origin, state, scope),)
                        arguments.extend(values)
                        argument_infos.extend(metadata)
                        argument_expressions.extend((argument, origin) for _ in values)
                    for index, (argument, origin) in enumerate(argument_expressions):
                        variable, _ = self.unparenthesize(argument)
                        if re.fullmatch(r'[A-Za-z_]\w*', variable):
                            argument_infos[index] = _join_value_info(
                                argument_infos[index], self.value_info(argument, origin, state, scope))
                closure_state = dict(state)
                if not immediate:
                    for key, native in closure_state.items():
                        if isinstance(key, _NativeKey) and key.cell not in self.global_cells:
                            # A delayed body reads the eventual outer local
                            # cell, not the value at the function literal.
                            # Package cells keep the package mutation proof.
                            closure_state[key] = _join_native(native, _UNKNOWN_NATIVE)
                        elif isinstance(key, _ReaderKey) and native is not None:
                            closure_state[key] = replace(native, definite=False)
                        elif isinstance(key, _DecoderKey) and native is not None:
                            closure_state[key] = replace(native, definite=False)
                        elif isinstance(key, _BufferKey) and native is not None:
                            closure_state[key] = replace(native, definite=False)
                for index, parameter in enumerate(parameters):
                    if parameter:
                        key = closure_scope.declare(parameter, offset + match.start())
                        closure_state[key] = (
                            arguments[index] if index < len(arguments) else _CLEAN)
                        info = argument_infos[index] if index < len(argument_infos) else None
                        # Invocation arguments are value snapshots, including
                        # for go/defer. Keep the same native callback, decoder
                        # and pointer contracts used by selected named helpers;
                        # none of these handles is itself request contents.
                        # Captured outer cells remain independently uncertain
                        # for delayed execution, as established above.
                        closure_state[_NativeKey(key)] = info.native if info is not None else _UNKNOWN_NATIVE
                        typename = parameter_types[index] if index < len(parameter_types) else ''
                        closure_state[_ScanKindKey(key)] = self.scan_type(typename, closure_scope)
                        if info is not None:
                            if info.decoder is not None:
                                closure_state[_DecoderKey(key)] = info.decoder
                            if info.reader is not None:
                                closure_state[_ReaderKey(key)] = info.reader
                            if info.buffer is not None:
                                closure_state[_BufferKey(key)] = info.buffer
                            closure_state[_PointerKey(key)] = info.pointers
                            if info.pointers and all(target.parameter is None for target in info.pointers):
                                closure_state[key] = _CLEAN
                nested = _Analysis(self.source, self.code, self.rule, self.summaries, self.imports,
                                   self.uncertain_globals, self.global_cells, self.resolve_summary)
                nested.native_escapes = set(self.native_escapes)
                nested.buffer_escapes = set(self.buffer_escapes)
                nested.buffer_borrows = set(self.buffer_borrows)
                result = code[param_end + 1:opening].strip()
                nested.named_returns = (_parameter_names(result[1:-1])
                                        if result.startswith('(') and result.endswith(')')
                                        else ('',) if result else ())
                for name in nested.named_returns:
                    if name:
                        key = closure_scope.declare(name, offset + match.start())
                        closure_state[key] = _CLEAN
                        closure_state[_NativeKey(key)] = _UNKNOWN_NATIVE
                try:
                    closure_flow = nested.block(_Parser(self.code).block(offset + opening + 1, offset + close),
                                                closure_state, closure_scope)
                except AnalysisLimit as error:
                    # A failed closure has no reusable return/write summary,
                    # but sinks reached before its boundary are still facts.
                    # Copy effects only; do not continue the enclosing call.
                    for effects in (nested.effects, error.effects):
                        for (sink_offset, label), fact in effects.items():
                            self.effect(sink_offset, label, fact)
                    raise
                # The body completed even if its resulting capabilities or
                # captured writes cannot be transported by the outer call.
                for (sink_offset, label), fact in nested.effects.items():
                    self.effect(sink_offset, label, fact)
                if immediate:
                    for cell in nested.native_mutations & enclosing_sources.keys():
                        replacement = (closure_flow.normal.get(_NativeKey(cell))
                                       if closure_flow.normal is not None
                                       else nested.native_cell_writes.get(cell))
                        retained = replacement.operations if replacement is not None else frozenset()
                        if enclosing_sources[cell] - retained:
                            # Closure bodies precede outer calls in this
                            # evaluator. A replacement cannot erase the old
                            # callee; assigning the same getter preserves it.
                            raise _callable_boundary(enclosing_sources[cell], 'replacement during argument evaluation')
                # Invocation timing and captured writes are not described by
                # return facts. A possible writer invalidates the old proof.
                for cell in nested.native_mutations:
                    if _NativeKey(cell) in state:
                        was_escaped = cell in self.native_escapes
                        self.invalidate_native_targets((_Target(cell),), state)
                        if immediate:
                            native = (closure_flow.normal.get(_NativeKey(cell))
                                      if closure_flow.normal is not None
                                      else nested.native_cell_writes.get(cell))
                            state[_NativeKey(cell)] = (native if closure_flow.normal is not None
                                                       else _join_native(state.get(_NativeKey(cell)), native))
                            if (closure_flow.normal is not None and not was_escaped
                                    and cell not in nested.native_escapes):
                                # A completed lexical assignment is not an
                                # address escape. Existing or newly escaped
                                # pointers still keep the cell uncertain.
                                self.native_escapes.discard(cell)
                                if _PointerKey(cell) in closure_flow.normal:
                                    state[_PointerKey(cell)] = frozenset(
                                        target for target in closure_flow.normal[_PointerKey(cell)]
                                        if target.cell in state)
                                else:
                                    state.pop(_PointerKey(cell), None)
                            self.native_cell_writes[cell] = _join_native(
                                self.native_cell_writes.get(cell), native)
                        if cell in nested.reader_cell_writes:
                            if not immediate and (state.get(_ReaderKey(cell)) is not None
                                                  or nested.reader_cell_writes[cell] is not None):
                                raise AnalysisLimit('Go delayed reader replacement is unsupported; analysis is incomplete')
                            reader = (closure_flow.normal.get(_ReaderKey(cell))
                                      if closure_flow.normal is not None else nested.reader_cell_writes[cell])
                            state[_ReaderKey(cell)] = (reader if closure_flow.normal is not None else
                                                      _join_readers(state.get(_ReaderKey(cell)), reader))
                            self.reader_cell_writes[cell] = (
                                _join_readers(self.reader_cell_writes[cell], reader)
                                if cell in self.reader_cell_writes else reader)
                        if cell in nested.decoder_cell_writes:
                            if not immediate and (state.get(_DecoderKey(cell)) is not None
                                                  or nested.decoder_cell_writes[cell] is not None):
                                raise AnalysisLimit('Go delayed decoder replacement is unsupported; analysis is incomplete')
                            exits = []
                            if closure_flow.normal is not None:
                                exits.append(closure_flow.normal.get(_DecoderKey(cell)))
                            if nested.decoder_returns is not None:
                                exits.append(nested.decoder_returns.get(cell))
                            decoder = (_join_decoders(*exits) if exits else
                                       _join_decoders(state.get(_DecoderKey(cell)), nested.decoder_cell_writes[cell]))
                            state[_DecoderKey(cell)] = decoder
                            self.decoder_cell_writes[cell] = (
                                _join_decoders(self.decoder_cell_writes[cell], decoder)
                                if cell in self.decoder_cell_writes else decoder)
                        if cell in nested.buffer_cell_writes and (
                                state.get(_BufferKey(cell)) is not None or nested.buffer_cell_writes[cell] is not None):
                            raise AnalysisLimit('Go captured buffer replacement is unsupported; analysis is incomplete')
                captured_scans = {target: fact for target, fact in nested.scan_writes.items()
                                  if target.cell in state}
                if captured_scans and not immediate:
                    raise AnalysisLimit('Go formatted input delayed closure writes are unsupported; analysis is incomplete')
                for target, fact in captured_scans.items():
                    self.write_targets((target,), fact, state, 'closure scanning')
                    self.scan_writes[target] = _join(self.scan_writes.get(target, _CLEAN), fact)
                captured_buffers = {target: fact for target, fact in nested.buffer_writes.items()
                                    if target.cell in state}
                if captured_buffers and not immediate:
                    raise AnalysisLimit('Go delayed buffer writes are unsupported; analysis is incomplete')
                self.buffer_escapes.update(nested.buffer_escapes)
                self.buffer_borrows.update(nested.buffer_borrows)
                for target, fact in captured_buffers.items():
                    self.write_targets((target,), fact, state, 'closure buffer write', buffer=True)
                    self.buffer_writes[target] = _join(self.buffer_writes.get(target, _CLEAN), fact)
                captured_readers = frozenset().union(*(reader.origins for key, reader in state.items()
                                                       if isinstance(key, _ReaderKey) and reader is not None))
                scanned_readers = nested.reader_scans & captured_readers
                if scanned_readers and not immediate:
                    raise AnalysisLimit('Go delayed scanner mutation is unsupported; analysis is incomplete')
                self.mark_scanned(scanned_readers, state)
                if immediate:
                    whole = (not code[:match.start()].strip()
                             and not code[pairs[invocation] + 1:].strip())
                    if whole:
                        # A direct invocation has the same distinct result
                        # slots as a selected named helper. Preserve callable
                        # and decoder contracts without treating handles or
                        # clean presence/error results as input contents.
                        # Local pointee cells do not outlive this evaluator;
                        # exporting them needs a separate escaped-heap model.
                        result_infos = tuple(
                            replace(info, pointers=frozenset(), buffer=replace(info.buffer, definite=False))
                            if (info is not None and info.buffer is not None and info.pointers
                                and all(target.cell.startswith('@byte-buffer:readall:')
                                        and target.cell not in state for target in info.pointers))
                            else info for info in nested.value_returns)
                        if any(info is not None and any(target.cell not in state for target in info.pointers)
                               for info in result_infos):
                            raise AnalysisLimit('Go closure-local pointer result transport is unsupported; '
                                                'analysis is incomplete')
                        for index, info in enumerate(result_infos):
                            if info is not None and info.pointers and index < len(nested.returns):
                                # A returned outer alias may already have been
                                # written inside the closure. Publishing only
                                # its identity would drop the observed content
                                # when assignment clears the handle's own fact.
                                self.write_targets(info.pointers, nested.returns[index], state, 'closure result',
                                                   buffer=info.buffer is not None)
                        self.closure_results[offset] = (nested.returns, result_infos)
                    else:
                        if any(info is not None and info.decoder is not None for info in nested.value_returns):
                            raise AnalysisLimit('Go decoder closure-result transport is unsupported; analysis is incomplete')
                        source_operations = frozenset().union(*(
                            info.native.operations & _CALLABLE_OPERATIONS for info in nested.value_returns
                            if info is not None and info.native is not None))
                        if source_operations:
                            raise _callable_boundary(source_operations, 'closure-result transport')
                    facts.extend(nested.returns)
                if invoked:
                    close = pairs[invocation]
                cover(match.start(), close + 1)
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?\s*\(', code):
            if masked[match.start()].isspace():
                continue
            if (match.group(2) is None and match.group(1) in {'string', 'len', 'cap'}
                    and match.group(1) not in scope.bindings and match.group(1) not in self.summaries):
                end = pairs.get(match.end() - 1)
                if end is not None:
                    facts.append(self.value(expr[match.start():end + 1], offset + match.start(), state, scope))
                    cover(match.start(), end + 1)
                    continue
            result = self.native_call(_CallExpression(expr, code, pairs, offset), match, state, scope)
            if result is not None:
                end, values = result
                facts.extend(values)
                cover(match.start(), end + 1)
                continue
            chained_helper = self.helper_chained_call(_CallExpression(expr, code, pairs, offset), match, state, scope)
            if chained_helper is not None:
                end, values = chained_helper
                facts.extend(values)
                cover(match.start(), end + 1)
            else:
                end = pairs.get(match.end() - 1)
                if end is not None:
                    if match.group(1) == 'append' and match.group(2) is None:
                        self.check_source_storage(code[match.start():end + 1],
                                                  offset + match.start(), state, scope)
                    for start, stop in _parts(code[match.end():end]):
                        argument = expr[match.end() + start:match.end() + stop]
                        callable_info = self.native_callable(match.group(1), match.group(2),
                                                              offset + match.start(), state, scope)
                        if callable_info is not None and not (
                                match.group(2) is None and match.group(1) in self.summaries
                                and match.group(1) not in scope.bindings):
                            info = self.value_info(argument, offset + match.end() + start, state, scope)
                            if not (match.group(2) is None and match.group(1) in {'string', 'len', 'cap'}
                                    and match.group(1) not in scope.bindings and match.group(1) not in self.summaries):
                                self.escape_buffer(info, state=state)
                            if info is not None and ((info.reader is not None and info.reader.kinds != {'request'}) or any(
                                    state.get(_ReaderKey(target.cell)) is not None for target in info.pointers)):
                                raise AnalysisLimit('Go reader opaque-call transport is unsupported; analysis is incomplete')
                            if info is not None and (info.decoder is not None or any(
                                    state.get(_DecoderKey(target.cell)) is not None for target in info.pointers)):
                                raise AnalysisLimit('Go decoder opaque-call transport is unsupported; analysis is incomplete')
                        self.invalidate_native_targets(
                            self.pointers(argument, state, scope), state)
                        self.invalidate_address_cell(argument, state, scope)
        # Direct standard input/request-body receivers have two selectors,
        # outside the bounded root.method call matcher. Do not silently lose
        # output writes such as os.Stdin.Read(buffer) or request.Body.Read.
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(Stdin|Body)\s*\.\s*'
                                 r'([A-Za-z_]\w*)\s*\(', code):
            if masked[match.start()].isspace():
                continue
            info = self.value_info(match.group(1) + '.' + match.group(2), offset + match.start(), state, scope)
            if info.reader is not None:
                if match.group(3) not in {'Close', 'Name', 'Fd', 'Stat'}:
                    raise AnalysisLimit('Go reader ' + match.group(3) + ' mutation or protocol is unsupported; analysis is incomplete')
                end = pairs.get(match.end() - 1)
                if end is not None:
                    self.value(expr[match.end():end], offset + match.end(), state, scope)
                    cover(match.start(), end + 1)
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)\s*\(', code):
            name = match.group(1)
            end = pairs.get(match.end() - 1)
            if (end is None or masked[match.start()].isspace() or name not in self.summaries
                    or name in scope.bindings):
                continue
            call_offset = offset + match.start()
            facts.extend(self.call(name, expr[match.end():end], offset + match.end(),
                                   call_offset, state, scope))
            if re.match(r'\s*\(', code[end + 1:]):
                # A computed invocation needs a separate argument/callee
                # evaluation step. Do not silently discard a known returned
                # command constructor while only evaluating its factory.
                commands = frozenset().union(*(info.native.operations & _COMMAND_OPERATIONS
                                                for info in self.call_results.get(call_offset, ())
                                                if info is not None and info.native is not None))
                if commands:
                    raise _callable_boundary(commands, 'computed invocation')
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
                fact = _join(*(self.value(expr[arg_start + start:arg_start + stop],
                                          offset + arg_start + start, state, scope)
                               for start, stop in arguments))
                self.effect(offset + match.start(), label, fact)
        for regex in SOURCE_PATTERNS:
            for match in regex.finditer(remaining):
                source = match.group()
                facts.append(frozenset({_Trace(source, path=(source,))}))
        for match in re.finditer(r'(?<![\w.])([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*)*)', remaining):
            name = match.group(1)
            cell = scope.bindings.get(name, name)
            path = tuple(re.findall(r'\.\s*([A-Za-z_]\w*)', match.group(2)))
            facts.append(_field_fact(state, cell, path))
            pending, seen = list(state.get(_PointerKey(cell), ())), set()
            while pending:
                target = pending.pop()
                if target in seen:
                    continue
                seen.add(target)
                facts.append(_field_fact(state, target.cell, target.path + path))
                if not target.path:
                    pending.extend(state.get(_PointerKey(target.cell), ()))
        fact = _join(*facts)
        info, fresh, zeroed = self.buffer_expression(expr, offset, state, scope)
        if fresh:
            for target in info.pointers:
                state[target.cell] = _join(state.get(target.cell, _CLEAN), _CLEAN if zeroed else fact)
            if zeroed:
                return _CLEAN
        if info is not None and info.buffer is not None and info.buffer.definite and info.buffer.length == 0:
            return _CLEAN
        return fact

    def simple(self, start: int, end: int, state, scope, declaration_kind: str = '') -> _Flow:
        prefix = declaration_kind + ' ' if declaration_kind else ''
        code = prefix + self.code[start:end]
        type_declaration = re.match(r'\s*type\s+([A-Za-z_]\w*)\b', code)
        if type_declaration:
            state[scope.declare(type_declaration.group(1), start)] = _CLEAN
            return _Flow(state)
        keyword = re.match(r'\s*(return|break|continue)\b', code)
        if keyword:
            if keyword.group(1) == 'break':
                return _Flow(None, breaks=[state])
            if keyword.group(1) == 'continue':
                return _Flow(None, continues=[state])
            expr_start = start + keyword.end()
            if self.code[expr_start:end].strip():
                values = self.values(self.source[expr_start:end], expr_start, state, scope)
                infos = self.value_results[expr_start]
            else:
                # A named pointer result observes its pointee at return time,
                # just like an explicit `return result` expression. Reading
                # only the handle cell loses writes reached through aliases.
                values = tuple(self.value(name, expr_start, state, scope) if name else _CLEAN
                               for name in self.named_returns)
                infos = tuple(self.value_info(name, expr_start, state, scope) for name in self.named_returns)
            count = max(len(values), len(self.returns))
            self.returns = tuple(_join(self.returns[index] if index < len(self.returns) else _CLEAN,
                                       values[index] if index < len(values) else _CLEAN)
                                 for index in range(count))
            self.value_returns = tuple(_join_value_info(
                self.value_returns[index] if index < len(self.value_returns) else None,
                infos[index] if index < len(infos) else None) for index in range(count))
            decoder_state = {key.cell: decoder for key, decoder in state.items()
                             if isinstance(key, _DecoderKey) and decoder is not None}
            self.decoder_returns = (decoder_state if self.decoder_returns is None else
                                    {cell: _join_decoders(self.decoder_returns.get(cell), decoder_state.get(cell))
                                     for cell in self.decoder_returns.keys() | decoder_state.keys()})
            return _Flow(None)
        assignment = _parts(code, '=')
        if len(assignment) > 1:
            equal = assignment[0][1]
            lhs = code[:equal].rstrip()
            compound = lhs.endswith('+')
            if compound:
                lhs = lhs[:-1].rstrip()
            targets = self.assignment_targets(lhs, state, scope)
            if targets is not None and code[equal + 1:equal + 2] != '=':
                expr_start = start + equal + 1 - len(prefix)
                expression = self.source[expr_start:end]
                fact = self.value(expression, expr_start, state, scope)
                info = self.value_info(expression, expr_start, state, scope)
                image = self.copy_fields(expression, state, scope)
                # RHS calls may change the pointer operand. Go does not give
                # ordinary variable reads a total order against those calls.
                following = self.assignment_targets(lhs, state, scope) or frozenset()
                if not targets or not following:
                    targets = frozenset(replace(target, whole=False) for target in targets | following)
                else:
                    targets |= following
                self.assign_targets(targets, fact, info, image, state, lhs.strip(), compound=compound)
                return _Flow(state)
        for pattern in ASSIGN_PATTERNS:
            match = pattern.match(code)
            if match is None:
                continue
            targets = [name.strip() for name in match.group('targets').split(',')]
            expr_start = start + match.start('expr') - len(prefix)
            values = self.values(self.source[expr_start:end], expr_start, state, scope)
            pieces = _parts(self.code[expr_start:end])
            metadata = self.value_results[expr_start]
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
                expression = (self.source[expr_start + pieces[index][0]:expr_start + pieces[index][1]]
                              if index < len(pieces) else '')
                image = (self.copy_fields(expression, state, scope)
                         if len(pieces) == 1 and match.group('op') != '+=' else None)
                info = metadata[index] if index < len(metadata) else _ValueInfo()
                pointers, decoder, native = ((info.pointers, info.decoder, info.native) if info is not None
                                             else (frozenset(), None, None))
                previous_decoder = state.get(_DecoderKey(key))
                if decoder is None and previous_decoder is not None and previous_decoder.methods != {''}:
                    # An opaque replacement of a known decoder callback can
                    # have new output writes. Keep a refusal-only capability
                    # for a later invocation, without executing the old method
                    # or invalidating copies saved before this assignment.
                    decoder = replace(previous_decoder, definite=False)
                if pointers and all(pointer.parameter is None for pointer in pointers):
                    # A pointer alias observes its pointee at use time. Copying
                    # old pointee facts here would survive a later clean reset.
                    updates[key] = _CLEAN
                elif image is not None:
                    updates[key] = _advance(image[0], target)
                    for path, field_fact in image[1]:
                        updates[_FieldKey(key, path)] = _advance(field_fact, target)
                if not pointers and (re.match(r'\s*new\s*\(', expression)
                                     or re.match(r'\s*&\s*[A-Za-z_]\w*\s*\{', expression)):
                    pointers = frozenset({_Target(key)})
                updates[_PointerKey(key)] = pointers
                updates[_DecoderKey(key)] = decoder
                updates[_ReaderKey(key)] = info.reader if info is not None else None
                updates[_BufferKey(key)] = info.buffer if info is not None else None
                updates[_NativeKey(key)] = native
                declared_type = re.match(r'\s*(?:var|const)\s+'
                                         r'[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s+(.+?)\s*=', code, re.DOTALL)
                kind_key = _ScanKindKey(key)
                if declared_type:
                    updates[kind_key] = self.scan_type(declared_type.group(1), scope)
                elif state.get(kind_key) != 'text':
                    updates[kind_key] = self.scan_kind(expression, expr_start, state, scope)
                self.native_mutations.add(key)
                self.native_cell_writes[key] = _join_native(self.native_cell_writes.get(key), native)
                reader = info.reader if info is not None else None
                self.reader_cell_writes[key] = (_join_readers(self.reader_cell_writes[key], reader)
                                                 if key in self.reader_cell_writes else reader)
                self.decoder_cell_writes[key] = (_join_decoders(self.decoder_cell_writes[key], decoder)
                                                 if key in self.decoder_cell_writes else decoder)
                buffer = info.buffer if info is not None else None
                self.buffer_cell_writes[key] = (_join_buffers(self.buffer_cell_writes[key], buffer)
                                                if key in self.buffer_cell_writes else buffer)
            assigned = {key for key in updates if isinstance(key, str)}
            for key in list(state):
                if isinstance(key, _FieldKey) and key.cell in assigned:
                    state.pop(key)
            state.update(updates)
            return _Flow(state)
        declaration = re.match(r'\s*var\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+[^=]+$', code)
        if declaration:
            for name in declaration.group(1).split(','):
                key = scope.declare(name.strip(), start)
                state[key] = _CLEAN
                state[_NativeKey(key)] = _UNKNOWN_NATIVE
                typename = code[declaration.end(1):].strip()
                state[_ScanKindKey(key)] = self.scan_type(typename, scope)
                if re.sub(r'\s+', '', typename) in {'[]byte', '[]uint8'} and self.scan_type(typename, scope) == 'text':
                    state[_BufferKey(key)] = _BufferInfo(0)
        self.value(self.source[start:end], start, state, scope)
        return _Flow(state)

    def block(self, nodes, state, scope) -> _Flow:
        breaks, continues = [], []
        for node in nodes:
            if state is None:
                break
            flow = self.statement(node, state, scope)
            if self.buffer_invalidated:
                # Retain sinks reached in the statement before reporting the
                # unsupported mutation; never publish its return capabilities.
                raise AnalysisLimit('Go native buffer backing mutation or escape is unsupported; analysis is incomplete')
            state = flow.normal
            breaks.extend(flow.breaks)
            continues.extend(flow.continues)
        return _Flow(state, breaks, continues)

    def statement(self, node, state, scope) -> _Flow:
        if node.kind in {'var', 'const', 'type'}:
            return self.simple(node.start, node.end, state, scope, node.kind)
        if node.kind == 'declarations':
            return self.block(node.body, state, scope)
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


def _summaries(source: str, code: str, functions: list[_Function], parser: _Parser, rule: str,
               imports: _ImportContexts, global_nodes=None):
    summaries = {function.name: _Summary(tuple(_CLEAN for _ in function.results), variadic=function.variadic,
                                         value_returns=tuple(None for _ in function.results))
                 for function in functions}
    if global_nodes is None:
        global_nodes, cursor = [], 0
        for function in functions:
            global_nodes.extend(parser.block(cursor, function.start))
            cursor = function.end
        global_nodes.extend(parser.block(cursor, len(code)))
    globals_scope = _Scope()
    def declare_globals(nodes):
        for node in nodes:
            if node.kind == 'declarations':
                declare_globals(node.body)
                continue
            prefix = node.kind + ' ' if node.kind in {'var', 'const', 'type'} else ''
            declaration = re.match(r'\s*(?:var|const|type)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)',
                                   prefix + code[node.start:node.end])
            if declaration:
                for target in declaration.group(1).split(','):
                    target = target.strip()
                    if target != '_':
                        globals_scope.declare(target, node.start)
    # Package declarations are in scope even before their initializer appears.
    # Pre-bind their stable cells so a forward reference cannot accidentally
    # read a different, unbound name on the first pass.
    declare_globals(global_nodes)
    global_cells = set(globals_scope.bindings.values())
    uncertain_globals = set()
    global_state = {}
    by_name = defaultdict(list)
    for function in functions:
        by_name[function.name].append(function)
    bottoms = {name: _join_summaries([
        _Summary(tuple(_CLEAN for _ in function.results), variadic=function.variadic,
                 value_returns=tuple(None for _ in function.results)) for function in variants])
        for name, variants in by_name.items()}
    parameter_counts = {name: max(len(function.parameters) for function in variants)
                        for name, variants in by_name.items()}
    contexts = {}
    context_counts = defaultdict(int)
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
    current = '@globals'
    global_analysis = None

    def incomplete(error, active, variants=()):
        """Retain effects, never incomplete returns or native capabilities."""
        effects = {}
        completed = [summary.effects for summary in (*summaries.values(), *contexts.values(), *variants)]
        if global_analysis is not None:
            completed.append(global_analysis.effects)
        for observed in (*completed, active.effects, error.effects):
            for key, fact in observed.items():
                effects[key] = _join(effects.get(key, _CLEAN), fact)
        return AnalysisLimit(str(error), effects=effects, components=error.components)

    def enqueue(key):
        if key not in queued:
            pending.append(key)
            queued.add(key)

    def resolve_summary(name, infos):
        """Specialize identity, never concrete payloads or evidence paths.

        Each parameter ranges over a finite native-operation set, an unknown
        alternative, and absent/definite/uncertain decoder provenance. Taint
        and pointees remain symbolic parameters in every cached summary.
        """
        dependents[name].add(current)
        if any(info is None or info.native is None for info in infos):
            # Forward/recursive results have not reached this call yet. Do
            # not promote fixed-point bottom to an actual unknown callback.
            return bottoms[name]
        signature = tuple((info.native, (info.decoder.definite, info.decoder.methods) if info.decoder is not None else None,
                           (info.reader.kinds, info.reader.scanned, info.reader.definite, info.reader.methods)
                           if info.reader is not None else None, info.buffer)
                          for info in infos[:parameter_counts[name]])
        signature += ((_UNKNOWN_NATIVE, None, None, None),) * (parameter_counts[name] - len(signature))
        if all(native == _UNKNOWN_NATIVE and decoder is None and reader is None and buffer is None
               for native, decoder, reader, buffer in signature):
            return summaries[name]
        key = (name, signature)
        dependents[key].add(current)
        if key not in contexts:
            if context_counts[name] >= NATIVE_CONTEXT_LIMIT:
                raise AnalysisLimit('Go native callable context limit exceeded; analysis is incomplete')
            context_counts[name] += 1
            contexts[key] = bottoms[name]
            enqueue(key)
        return contexts[key]

    while pending:
        current = pending.popleft()
        queued.discard(current)
        if current == '@globals':
            global_analysis = _Analysis(source, code, rule, summaries, imports, uncertain_globals,
                                        global_cells, resolve_summary)
            try:
                updated = global_analysis.block(global_nodes, dict(global_state), globals_scope).normal or {}
            except AnalysisLimit as error:
                raise incomplete(error, global_analysis) from error
            updated = _join_states(global_state, updated)
            newly_uncertain = (global_analysis.native_escapes & global_cells) - uncertain_globals
            uncertain_globals.update(newly_uncertain)
            if updated != global_state or newly_uncertain:
                global_state = updated
                # Initializers can depend on later variables, including through
                # local helper calls. Join finite facts and revisit both sides
                # until stable, not for an arbitrary number of file passes.
                for caller in ('@globals', *summaries, *contexts):
                    enqueue(caller)
            continue
        name, signature = current if isinstance(current, tuple) else (current, None)
        variants = []
        mutations = set()
        for function in by_name[name]:
            analysis = _Analysis(source, code, rule, summaries, imports, uncertain_globals,
                                 global_cells, resolve_summary)
            state, scope = dict(global_state), globals_scope.child()
            if function.receiver and function.receiver != '_':
                key = scope.declare(function.receiver, function.start)
                state[key] = _CLEAN
                state[_NativeKey(key)] = _UNKNOWN_NATIVE
            for index, parameter in enumerate(function.parameters):
                if parameter and parameter != '_':
                    key = scope.declare(parameter, function.start)
                    state[key] = frozenset({_Trace(parameter, index, (parameter,))})
                    native, decoder, reader, buffer = (signature[index] if signature is not None
                                                       else (_UNKNOWN_NATIVE, None, None, None))
                    state[_NativeKey(key)] = native
                    typename = function.parameter_types[index] if index < len(function.parameter_types) else ''
                    state[_ScanKindKey(key)] = analysis.scan_type(
                        typename[1:] if typename.startswith('*') else typename, scope)
                    if decoder is not None:
                        definite, methods = decoder
                        state[_DecoderKey(key)] = _DecoderInfo(
                            frozenset({_Trace(parameter, index, (parameter,), 'decoder')}), definite, methods)
                    if reader is not None:
                        kinds, scanned, definite, methods = reader
                        state[_ReaderKey(key)] = _ReaderInfo(
                            frozenset({_Trace(parameter, index, (parameter,), 'reader-data')}), kinds,
                            frozenset({_ReaderOrigin((function.start, index), index)}), scanned, definite, methods)
                    if buffer is not None:
                        state[_BufferKey(key)] = buffer
                    elif signature is None and typename in {'[]byte', '[]uint8'} and analysis.scan_type(typename, scope) == 'text':
                        state[_BufferKey(key)] = _BufferInfo()
                    if index in function.reference_parameters:
                        state[_PointerKey(key)] = frozenset({_Target(key, index)})
            for result in function.results:
                if result:
                    key = scope.declare(result, function.start)
                    state[key] = _CLEAN
                    state[_NativeKey(key)] = _UNKNOWN_NATIVE
            analysis.named_returns = function.results
            try:
                analysis.block(function.body, state, scope)
            except AnalysisLimit as error:
                raise incomplete(error, analysis, variants) from error
            mutations.update(analysis.native_mutations)
            variants.append(_Summary(analysis.returns, analysis.effects, function.variadic,
                                     analysis.writes, analysis.value_returns, analysis.native_writes,
                                     frozenset(origin.parameter for origin in analysis.reader_scans
                                               if origin.parameter is not None),
                                     frozenset(target.parameter for target in analysis.buffer_escapes
                                               if target.parameter is not None),
                                     frozenset(target.parameter for target in analysis.buffer_writes
                                               if target.parameter is not None),
                                     frozenset(target.parameter for target in analysis.buffer_borrows
                                               if target.parameter is not None)))
        newly_uncertain = (mutations & global_cells) - uncertain_globals
        if newly_uncertain:
            # Package callbacks are mutable cells. A write in any selected
            # function invalidates initializer-only authority in every caller.
            uncertain_globals.update(newly_uncertain)
            for caller in ('@globals', *summaries, *contexts):
                enqueue(caller)
        summary = _join_summaries(variants)
        table = contexts if signature is not None else summaries
        if summary != table[current]:
            table[current] = summary
            for caller in sorted(dependents[current], key=repr):
                enqueue(caller)
    effects = dict(global_analysis.effects)
    for summary in contexts.values():
        for key, fact in summary.effects.items():
            effects[key] = _join(effects.get(key, _CLEAN), fact)
    return summaries, effects


def _source_hits(source, code, functions, global_nodes, imports):
    """Analyze a package image; offsets are mapped back to files by its owner."""
    hits = {}
    errors = []
    components = []
    for rule in (*dict.fromkeys(rule for _regex, rule, _label in SINKS), 'go.taint.command'):
        try:
            summaries, globals_effects = _summaries(source, code, functions, _Parser(code), rule, imports,
                                                   global_nodes=global_nodes)
            completed = [globals_effects, *(summary.effects for summary in summaries.values())]
        except AnalysisLimit as error:
            # Each sink domain owns its own state and sanitizer semantics.
            # Continue the others, while retaining only reached concrete
            # sources from the interrupted domain's effect table.
            completed = [error.effects]
            errors.append(str(error))
            components.extend(error.components)
        for effects in completed:
            for (offset, label), fact in effects.items():
                concrete = [trace for trace in fact if trace.parameter is None]
                if not concrete:
                    continue
                trace = min(concrete, key=lambda trace: (len(trace.path), trace.path, trace.source))
                path_desc = ' -> '.join(next(iter(_advance(frozenset({trace}), label))).path)
                hits[(offset, rule)] = path_desc
    for (offset, rule), path_desc in sorted(hits.items()):
        yield rule, offset, path_desc
    if errors:
        raise AnalysisLimit('; '.join(dict.fromkeys(errors)), components=components)


def _shift_statement(node: _Statement, offset: int) -> _Statement:
    return replace(node, start=node.start + offset, end=node.end + offset,
                   body=tuple(_shift_statement(child, offset) for child in node.body),
                   otherwise=tuple(_shift_statement(child, offset) for child in node.otherwise))


def iter_project_hits(files: Iterable[Path], base_dir: Path):
    """Resolve package-local calls without discovering or reading extra files.

    Parse each file independently before assigning package-wide offsets. An
    unterminated string/comment/block in one editor buffer cannot consume the
    next file. Package clauses and directory identities both isolate bindings;
    a missing clause stays file-local rather than inventing package membership.
    """
    packages = defaultdict(list)
    seen = set()
    # Keep independent packages in the caller's selection order, like the
    # other structured analyzers. Sorting the entire selection reorders
    # unrelated source files (and the legacy entrypoint's capped samples).
    for path in files:
        identity = path.resolve()
        if path.suffix.lower() not in EXTS or identity in seen:
            continue
        seen.add(identity)
        try:
            source = _masked_source(path.read_text(encoding='utf-8'), strings=False)
        except (UnicodeError, OSError):
            continue
        code = _masked_source(source)
        clause = re.match(r'\s*\ufeff?\s*package\s+([A-Za-z_]\w*)\s*(?:;|\n|$)', code)
        package = clause.group(1) if clause and clause.group(1) != '_' else identity
        packages[(identity.parent, package)].append((path, source, code))

    errors = []
    components = []
    for units in packages.values():
        # Package initialization and synthetic offsets must still be stable
        # when the caller presents the same package files in another order.
        units.sort(key=lambda unit: str(unit[0].resolve()))
        sources, codes, starts, locations, functions, global_nodes, imports = [], [], [], [], [], [], []
        offset = 0
        for path, source, code in units:
            starts.append(offset)
            locations.append((path, [0] + [match.end() for match in re.finditer('\n', code)]))
            parser = _Parser(code)
            imports.append(_file_imports(source, code, parser))
            cursor = 0
            for function in _functions(code, parser):
                global_nodes.extend(_shift_statement(node, offset)
                                    for node in parser.block(cursor, function.start))
                cursor = function.end
                name = function.name
                if name.startswith(('@init:', '@method:')):
                    name = name.split(':', 1)[0] + ':' + str(function.start + offset)
                functions.append(replace(function, name=name,
                                         start=function.start + offset, end=function.end + offset,
                                         body=tuple(_shift_statement(node, offset) for node in function.body)))
            global_nodes.extend(_shift_statement(node, offset) for node in parser.block(cursor, len(code)))
            sources.append(source + '\n;\n')
            codes.append(code + '\n;\n')
            offset += len(source) + 3
        contexts = _ImportContexts(tuple(starts), tuple(imports))
        try:
            for rule, position, path_desc in _source_hits(''.join(sources), ''.join(codes), functions, global_nodes, contexts):
                index = bisect_right(starts, position) - 1
                path, line_starts = locations[index]
                position -= starts[index]
                line = bisect_right(line_starts, position)
                # line_starts[0] == 0 <= position, so line >= 1 — ubs:ignore[py.collections.index-arithmetic]
                yield rule, path, line, position - line_starts[line - 1] + 1, path_desc
        except AnalysisLimit as error:
            # Packages share neither summaries nor globals. Finish the other
            # selected packages, then report failure so adapters retain the
            # findings without caching or advertising a complete scan.
            errors.append(str(error))
            components.extend(error.components)
    if errors:
        raise AnalysisLimit('; '.join(dict.fromkeys(errors)), components=components)


def iter_file_hits(path: Path, base_dir: Path):
    """Single-file compatibility entrypoint; never expands to sibling files."""
    for rule, source, line, col, path_desc in iter_project_hits([path], base_dir):
        try:
            rel = str(source.relative_to(base_dir))
        except ValueError:
            rel = source.name
        yield rule, rel, line, col, path_desc


def main() -> int:
    import sys

    root = Path(sys.argv[1]).resolve()
    base_dir = root if root.is_dir() else root.parent
    issues: dict[str, dict] = defaultdict(lambda: {'count': 0, 'samples': []})
    for rule, path, line, _col, path_desc in iter_project_hits(iter_files(root), base_dir):
        rel = path.relative_to(base_dir)
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
    for rule, path, line, col, path_desc in iter_project_hits(ctx.files, Path.cwd()):
        if not ctx.rule_enabled(rule):
            continue
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
    from ubs_core.io import temporary_directory

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
    with temporary_directory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        ctx = RunContext(lang="go", files=[path])
        findings = [f for f in run(ctx) if f["rule"] == "go.taint.xss"]
        assert len(findings) == 1, findings
        assert findings[0]["line"] == 10, findings[0]
        assert findings[0]["severity"] == "critical"
        assert findings[0]["path"] == str(path.resolve())
        assert "name" in findings[0]["message"]


def _selftest_sanitizer_suppresses() -> None:
    from ubs_core.io import temporary_directory

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
    with temporary_directory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = list(run(RunContext(lang="go", files=[path])))
        assert findings == [], findings


def _selftest_parameterized_sql_suppressed() -> None:
    from ubs_core.io import temporary_directory

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
    with temporary_directory(prefix="ubs_core_taint_go_") as tmp:
        path = _write_go(Path(tmp), code)
        findings = [f for f in run(RunContext(lang="go", files=[path])) if f["rule"] == "go.taint.sql"]
        assert findings == [], findings


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("xss_positive", _selftest_xss_positive),
    ("sanitizer_suppresses", _selftest_sanitizer_suppresses),
    ("parameterized_sql_suppressed", _selftest_parameterized_sql_suppressed),
)

register(Analyzer(layer="taint", lang="go", name="taint_go", run=run, selftests=SELF_TESTS))
