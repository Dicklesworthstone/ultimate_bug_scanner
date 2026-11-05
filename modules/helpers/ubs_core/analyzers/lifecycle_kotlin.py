"""Selected Kotlin/JVM resource ownership, with binding and exit-path identity.

Known file/socket constructors and Files factories create obligations. Kotlin
use closes its selected receiver on every exit; aliases, reassignment, local
helpers, returns and finally retain the original obligation. IO operations may
throw before a later close. Java Closeable's repeated close is valid.
Selected buffering and character-conversion wrappers retain their backing
resource identity, including aliases, ownership transfer and construction failure.
Socket streams share their socket's lifetime; ServerSocket.accept creates an
independent client obligation even when the listening socket is borrowed.
GZIP streams additionally own their compressor/decompressor: closing a wrapper
closes its backing stream, while closing only the backing stream leaves the
compression resource live. Construction can fail before that transfer occurs.

The shared Kotlin lexical frontend and JVM statement parser bound the work.
Unknown selected callbacks/heap effects and unsupported control flow are explicit
incomplete results, never evidence that an obligation was discharged.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field, replace
from pathlib import Path
import re
from typing import Iterable

from ubs_core.analyzers.coroutines_kotlin import KotlinCoroutines
from ubs_core.analyzers.narrowing_kotlin import NullParser
from ubs_core.analyzers.taint_java_traversal import Statement
from ubs_core.io import line_col
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit

KINDS = ("unclosed", "use-after-close", "escape-from-use")
CONSTRUCTORS = {
    "java.io." + name for name in
    ("FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile")
} | {"java.net.Socket", "java.net.ServerSocket"}
FILES_FACTORIES = {
    "newInputStream": "java.io.InputStream", "newOutputStream": "java.io.OutputStream",
    "newBufferedReader": "java.io.BufferedReader", "newBufferedWriter": "java.io.BufferedWriter",
    "lines": "java.util.stream.Stream", "walk": "java.util.stream.Stream",
    "list": "java.util.stream.Stream", "find": "java.util.stream.Stream",
    "newDirectoryStream": "java.nio.file.DirectoryStream",
}
FILE_EXTENSIONS = {
    "inputStream": "java.io.FileInputStream", "outputStream": "java.io.FileOutputStream",
    "reader": "java.io.Reader", "bufferedReader": "java.io.BufferedReader",
    "writer": "java.io.Writer", "bufferedWriter": "java.io.BufferedWriter",
    "printWriter": "java.io.PrintWriter",
}
STREAM_TYPES = {
    "input": frozenset("java.io." + name for name in
                       ("InputStream", "FileInputStream", "BufferedInputStream")) | {"java.util.zip.GZIPInputStream"},
    "output": frozenset("java.io." + name for name in
                        ("OutputStream", "FileOutputStream", "BufferedOutputStream")) | {"java.util.zip.GZIPOutputStream"},
    "reader": frozenset("java.io." + name for name in
                        ("Reader", "FileReader", "InputStreamReader", "BufferedReader")),
    "writer": frozenset("java.io." + name for name in
                        ("Writer", "FileWriter", "OutputStreamWriter", "BufferedWriter", "PrintWriter")),
}
WRAPPERS = {
    "java.io.BufferedInputStream": ("input", "size"),
    "java.io.BufferedOutputStream": ("output", "size"),
    "java.io.BufferedReader": ("reader", "size"),
    "java.io.BufferedWriter": ("writer", "size"),
    "java.io.InputStreamReader": ("input", "charset"),
    "java.io.OutputStreamWriter": ("output", "charset"),
}
COMPRESSION_WRAPPERS = {"java.util.zip.GZIPInputStream": "input", "java.util.zip.GZIPOutputStream": "output"}
STREAM_EXTENSIONS = {
    "buffered": {"input": "java.io.BufferedInputStream", "output": "java.io.BufferedOutputStream",
                 "reader": "java.io.BufferedReader", "writer": "java.io.BufferedWriter"},
    "reader": {"input": "java.io.InputStreamReader"},
    "bufferedReader": {"input": "java.io.BufferedReader"},
    "writer": {"output": "java.io.OutputStreamWriter"},
    "bufferedWriter": {"output": "java.io.BufferedWriter"},
}
STANDARD_CHARSETS = frozenset({"US-ASCII", "ISO-8859-1", "UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE"})
SOCKET_STREAMS = {"getInputStream": "java.io.InputStream", "getOutputStream": "java.io.OutputStream"}
IO_OPERATIONS = frozenset({
    "read", "readBytes", "readText", "readLine", "readLines", "readAllBytes", "readNBytes",
    "readFully", "readByte", "readInt", "readLong", "readUTF", "skip", "skipBytes", "available",
    "write", "writeBytes", "writeText", "writeByte", "writeInt", "writeLong", "writeUTF",
    "append", "flush", "newLine", "ready", "seek", "setLength", "length", "getFD", "getChannel", "reset", "mark",
    "connect", "bind", "accept", "getInputStream", "getOutputStream", "sendUrgentData",
    "shutdownInput", "shutdownOutput", "count", "forEach", "toArray", "collect", "reduce",
    "findFirst", "findAny", "anyMatch", "allMatch", "noneMatch", "min", "max", "iterator",
    "spliterator",
})
ResourceId = tuple[int, int]
EXCEPTION_PARENTS = {
    "java.lang.IllegalStateException": "java.lang.RuntimeException",
    "java.lang.IllegalArgumentException": "java.lang.RuntimeException",
    "java.lang.NullPointerException": "java.lang.RuntimeException",
    "java.lang.UnsupportedOperationException": "java.lang.RuntimeException",
    "java.io.UncheckedIOException": "java.lang.RuntimeException",
    "java.io.FileNotFoundException": "java.io.IOException",
    "java.io.UnsupportedEncodingException": "java.io.IOException",
    "java.io.EOFException": "java.io.IOException",
    "java.io.InterruptedIOException": "java.io.IOException",
    "java.net.SocketTimeoutException": "java.io.InterruptedIOException",
    "java.net.SocketException": "java.io.IOException",
    "java.net.BindException": "java.net.SocketException",
    "java.net.ConnectException": "java.net.SocketException",
    "java.net.NoRouteToHostException": "java.net.SocketException",
    "java.net.PortUnreachableException": "java.net.SocketException",
    "java.net.ProtocolException": "java.io.IOException",
    "java.net.UnknownHostException": "java.io.IOException",
    "java.net.UnknownServiceException": "java.io.IOException",
    "java.util.zip.ZipException": "java.io.IOException",
    "java.io.IOException": "java.lang.Exception",
    "java.lang.RuntimeException": "java.lang.Exception",
    "java.lang.Exception": "java.lang.Throwable",
    "java.lang.Error": "java.lang.Throwable",
}


class ResourceParser(NullParser):
    def end_statement(self, start, end):
        finish = super().end_statement(start, end)
        index = start
        while index < finish:
            self.model.spend()
            if index in self.pairs:
                index = self.pairs[index]
            elif self.code[index] in "\r\n" and self.code[start:index].rstrip().endswith(("++", "--")):
                # A completed increment is not a trailing binary + or -.
                return index
            index += 1
        return finish


@dataclass(frozen=True)
class ExceptionPath:
    kind: str
    exact: bool = False
    excluded: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Value:
    resources: frozenset[ResourceId] = frozenset()
    kind: str = ""
    symbol: str = ""
    constant: str = ""
    callback: int = -1
    escapes: tuple[tuple[ResourceId, int], ...] = ()
    captured: tuple[tuple[int, Value], ...] = ()
    implicit: tuple[tuple[int, int, Value], ...] = ()
    literal: str | None = None
    exception: ExceptionPath | None = None


UNKNOWN, UNIT = Value(), Value(constant="Unit")


@dataclass
class State:
    values: dict[int, Value] = field(default_factory=dict)
    life: dict[ResourceId, str] = field(default_factory=dict)
    backing: dict[ResourceId, frozenset[ResourceId]] = field(default_factory=dict)
    borrowed_closed: bool = False
    result: Value = UNIT
    position: int = 0
    exit: str = ""
    exception: ExceptionPath | None = None
    receiver: Value = UNKNOWN
    implicit: tuple[tuple[int, int, Value], ...] = ()
    managed: tuple[frozenset[ResourceId], ...] = ()
    use_scopes: tuple[int, ...] = ()
    unwinding: tuple[Value, ...] = ()

    def copy(self):
        return replace(self, values=dict(self.values), life=dict(self.life), backing=dict(self.backing))

    def signature(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.life.items())),
                tuple(sorted(self.backing.items())),
                self.borrowed_closed,
                self.result, self.position, self.exit, self.exception, self.receiver,
                self.implicit, self.managed, self.use_scopes, self.unwinding)


class Ownership:
    def __init__(self, text: str):
        self.model = KotlinCoroutines(text)
        self.parser = ResourceParser(self.model)
        self.text, self.code = text, self.model.code
        self.positions = [token.start for token in self.model.tokens]
        # The coroutine frontend's simple-expression endpoint stops at else.
        # Resource helpers need the complete if/try expression, including its
        # parameter scope, without changing the other Kotlin analyzers.
        functions = []
        for function in self.model.functions:
            if function.expression and self.model.value(function.start) in {"if", "try"}:
                _, finish = self.parser.statement(self.offset(function.start), len(self.code))
                end = self.token(finish)
                if end > function.end:
                    for name, bindings in self.model.bindings.items():
                        self.model.bindings[name] = [replace(binding, high=end)
                            if binding.low == function.start and binding.high == function.end else binding
                            for binding in bindings]
                    function = replace(function, end=end)
            functions.append(function)
        self.model.functions = functions
        self.parser.definitions = {self.offset(function.declaration): function for function in functions}
        self.functions = {fn.name: fn for fn in self.model.functions}
        self.active_calls: list[int] = []
        self.initializers: list[int] = []
        self.resources: dict[ResourceId, tuple[str, int]] = {}
        self.findings: dict[tuple[str, int], str] = {}

    def token(self, position: int) -> int:
        return bisect_left(self.positions, position)

    def offset(self, token: int) -> int:
        return self.positions[token] if token < len(self.positions) else len(self.code)

    def binding(self, name: str, token: int):
        binding = self.model.binding(name, token)
        if binding is not None and binding.declaration in self.initializers:
            # A local declaration is not a callable/binding in its own
            # initializer: val buffered = raw.buffered() still calls stdlib.
            candidates = [item for item in self.model.bindings.get(name, ())
                          if item.low <= token < item.high and item.declaration not in self.initializers]
            binding = max(candidates, key=lambda item: (item.low, item.declaration), default=None)
        return binding

    def key(self, name: str, token: int) -> int | None:
        binding = self.binding(name, token)
        return binding.declaration if binding is not None else None

    def canonical(self, name: str, token: int) -> str:
        parts = name.split(".")
        if self.binding(parts[0], token) is not None:
            return ""
        if parts[0] in self.model.imports:
            return ".".join([self.model.imports[parts[0]], *parts[1:]])
        if parts[0] in {"java", "kotlin"} and len(parts) > 1:
            return name
        known = CONSTRUCTORS | WRAPPERS.keys() | EXCEPTION_PARENTS.keys() | set().union(*STREAM_TYPES.values()) | {
            "java.io.File", "java.nio.file.Files", "java.nio.file.Path", "java.nio.file.Paths",
            "java.io.IOException", "java.io.UnsupportedEncodingException", "java.io.Closeable",
            "java.nio.charset.Charset", "java.nio.charset.CharsetDecoder", "java.nio.charset.CharsetEncoder",
            "java.nio.charset.StandardCharsets", "kotlin.text.Charsets", "java.lang.String",
            "kotlin.Boolean", "kotlin.Int", "java.lang.Boolean", "java.lang.Integer",
        }
        matches = [package + "." + name for package in self.model.wildcards
                   if package + "." + parts[0] in known]
        if len(matches) == 1:
            return matches[0]
        if name in {"Boolean", "Int"}:
            return "kotlin." + name
        if name in {"Exception", "Throwable", "Error", "RuntimeException", "IllegalStateException", "String",
                    "IllegalArgumentException", "UnsupportedOperationException", "NullPointerException"}:
            return "java.lang." + name
        return ""

    def builtin(self, name: str, token: int, wanted: str, *, state: State | None = None) -> bool:
        packages = {"use": {"kotlin.io.use", "kotlin.jdk7.use", "kotlin.use"}}
        io_name = wanted in FILE_EXTENSIONS or wanted in STREAM_EXTENSIONS or wanted in {"print", "println"}
        qualified = packages.get(wanted, {("kotlin.io." if io_name else "kotlin.") + wanted})
        if self.canonical(name, token) in qualified:
            return True
        binding = self.binding(name, token)
        if binding is not None and state is not None and binding.declaration not in self.functions:
            value = state.values.get(binding.declaration, UNKNOWN)
            if value.callback < 0 and (value.resources or value.constant or value.literal is not None):
                # A known noncallable local named buffered/reader is not an
                # extension function. Unknown and callable bindings still win.
                if self.model.imports.get(name) in qualified:
                    return True
                binding = None
        return (name == wanted and name not in self.model.imports
                and binding is None
                and all(package.startswith(("java.", "kotlin.")) for package in self.model.wildcards))

    def value(self, state: State, name: str, token: int) -> Value:
        key = self.key(name, token)
        if name == "this":
            return state.receiver
        if name == "it":
            for low, high, value in reversed(state.implicit):
                if low < token < high and (key is None or key < low):
                    return value
        if key in state.values:
            return state.values[key]
        if name.isdigit() and not self.text[self.offset(token):self.offset(token) + 1].isdigit():
            # The lexer replaces literals with numeric placeholders. Retain
            # only a literal without escapes/interpolation; arbitrary source
            # text or a variable named like a charset cannot prove its value.
            literal = re.match(r'"([^"\\$\r\n]*)"', self.text[self.offset(token):])
            return Value(kind="java.lang.String", literal=literal.group(1) if literal else None)
        if name in {"true", "false", "null", "Unit"} or name.isdigit():
            return Value(constant=name)
        return Value(symbol=name)

    @staticmethod
    def result(state: State, value: Value, position: int) -> list[State]:
        state.result, state.position = value, position
        return [state]

    def unique(self, states: Iterable[State]) -> list[State]:
        result = {state.signature(): state for state in states}
        if len(result) > 128:
            raise AnalysisLimit("Kotlin resource branch-state budget exceeded; analysis is incomplete")
        return list(result.values())

    def report(self, kind: str, resource: ResourceId, position: int | None = None) -> None:
        factory, acquisition = self.resources[resource]
        messages = {
            "unclosed": f"{factory} resource is not closed or returned on every exit path",
            "use-after-close": f"Operation uses a closed {factory} resource",
            "escape-from-use": f"{factory} resource escapes use after its receiver is closed",
        }
        self.findings[(kind, acquisition if position is None else position)] = messages[kind]

    def escaped(self, value: Value) -> None:
        for resource, position in value.escapes:
            self.report("escape-from-use", resource, position)

    def report_unclosed(self, state: State, resources: Iterable[ResourceId]) -> None:
        pending = {resource for resource in resources if state.life.get(resource) == "open"}
        for resource in sorted(pending):
            # One unclosed stream chain gets its original acquisition finding.
            # A wrapper still needs its own finding when its backing obligation
            # was closed, transferred, or remains reachable elsewhere.
            if not state.backing.get(resource, frozenset()) & pending:
                self.report("unclosed", resource)

    def discard_unreachable(self, state: State) -> None:
        values = [*state.values.values(), state.result, state.receiver, *state.unwinding]
        values.extend(value for _, _, value in state.implicit)
        references = set().union(*(self.references(value, state) for value in values), *state.managed)
        unreachable = set(state.life) - references
        self.report_unclosed(state, unreachable)
        for resource in unreachable:
            del state.life[resource]
            state.backing.pop(resource, None)

    def thrown(self, state: State, exception: str | None = None) -> State:
        failed = state.copy()
        # Native I/O can throw any IOException subtype; an explicit exception
        # from a known failing check has an exact type. Unknown ordinary calls
        # retain the existing bounded Exception-family effect.
        kind = "java.io.IOException" if exception is None else exception or "java.lang.Exception"
        failed.exit, failed.exception, failed.result = "throw", ExceptionPath(kind, exact=bool(exception)), UNIT
        return failed

    def acquire(self, state: State, factory: str, kind: str, position: int) -> list[State]:
        failed = self.thrown(state)
        slot = 0
        while (position, slot) in state.life:
            slot += 1
        resource = (position, slot)
        self.resources[resource] = (factory, position)
        state.life[resource] = "open"
        return self.result(state, Value(frozenset({resource}), kind=kind), position) + [failed]

    def socket_resource(self, receiver: Value, name: str, position: int, state: State) -> list[State]:
        closed = {resource for resource in receiver.resources if state.life.get(resource) == "closed"}
        for resource in closed:
            self.report("use-after-close", resource, position)
        self.escaped(receiver)
        if closed:
            # A closed listener cannot produce another client, and a closed
            # socket cannot return a usable stream. Avoid phantom successors.
            return [self.thrown(state, "java.net.SocketException")]
        if name == "accept":
            # Closing the listener has no effect on this accepted connection.
            # The failure branch keeps the listener but creates no client.
            return self.acquire(state, "java.net.ServerSocket.accept", "java.net.Socket", position)
        failed = self.thrown(state)
        stream = replace(receiver, kind=SOCKET_STREAMS[name], symbol="", constant="", literal=None)
        # Closing either direction closes the socket and every stream alias.
        # A getter can fail before an inner use owns its stream, so retain the
        # socket obligation unless an enclosing use/finally/catch closes it.
        return self.result(state, stream, position) + [failed]

    def standard_charset(self, value: Value, token: int) -> bool:
        owner, _, field = value.symbol.rpartition(".")
        if field not in {charset.replace("-", "_") for charset in STANDARD_CHARSETS}:
            return False
        qualified = self.canonical(owner, token)
        if qualified in {"java.nio.charset.StandardCharsets", "kotlin.text.Charsets"}:
            return True
        return (owner == "Charsets" and owner not in self.model.imports
                and self.binding(owner, token) is None
                and all(package.startswith(("java.", "kotlin.")) for package in self.model.wildcards))

    def compression_size(self, kind: str, options: tuple[Value, ...]) -> tuple[Value, ...]:
        is_output = kind == "java.util.zip.GZIPOutputStream"
        if len(options) > (2 if is_output else 1):
            raise ValueError("Unsupported Kotlin compression constructor; analysis is incomplete")
        size = options
        if is_output and options:
            last = options[-1]
            boolean = last.constant in {"true", "false"} or last.kind in {"kotlin.Boolean", "java.lang.Boolean"}
            if boolean:
                size = options[:-1]
            elif len(options) == 2:
                raise ValueError("Unresolved Kotlin compression flush mode; analysis is incomplete")
        if size and (len(size) != 1 or not (re.fullmatch(r"[+-]?\d+", size[0].constant)
                                           or size[0].kind in {"kotlin.Int", "java.lang.Integer"})):
            raise ValueError("Unresolved Kotlin compression size overload; analysis is incomplete")
        return size

    def compress_stream(self, state: State, kind: str, arguments: tuple[Value, ...], token: int) -> list[State]:
        if not arguments or arguments[0].kind not in STREAM_TYPES[COMPRESSION_WRAPPERS[kind]]:
            raise ValueError("Unresolved Kotlin compression backing stream; analysis is incomplete")
        backing, options = arguments[0], arguments[1:]
        if any(self.references(value, state) or value.callback >= 0 for value in options):
            raise ValueError("Unsupported Kotlin compression constructor arguments; analysis is incomplete")
        size, position = self.compression_size(kind, options), self.offset(token)
        output = []
        for branch in self.wrap_stream(state, backing, kind, size, token, option_kind="size"):
            if branch.exit:
                output.append(branch)
                continue
            if not backing.resources and branch.borrowed_closed:
                raise ValueError("Closed borrowed Kotlin compression backing needs alias identity; analysis is incomplete")
            closed = {resource for resource in backing.resources if branch.life.get(resource) == "closed"}
            for resource in closed:
                self.report("use-after-close", resource, position)
            self.escaped(backing)
            if closed:
                output.append(self.thrown(branch))
                continue
            wrapped = branch.result
            # Header I/O can fail before the caller obtains a wrapper. Only a
            # successful construction owns a new native inflater/deflater.
            for after in self.acquire(branch, kind, kind, position):
                if not after.exit:
                    owned = after.result.resources
                    for resource in owned:
                        after.backing[resource] = backing.resources
                    after.result = replace(wrapped, resources=backing.resources | owned)
                output.append(after)
        return self.unique(output)

    def close_resource(self, receiver: Value, position: int, state: State) -> list[State]:
        if not receiver.resources:
            # Borrowed parameters do not have local acquisition identities.
            # Do not assume their close is unrelated to a live GZIP wrapper.
            if any(not backing and state.life.get(resource) == "open"
                   for resource, backing in state.backing.items()):
                raise ValueError("Borrowed Kotlin compression close needs alias identity; analysis is incomplete")
            state.borrowed_closed = True
        for resource in receiver.resources:
            state.life[resource] = "closed"
        self.result(state, UNIT, position)
        return [state, self.thrown(state)]

    def io_operation(self, receiver: Value, name: str, position: int, state: State) -> list[State]:
        for resource in receiver.resources:
            if state.life.get(resource) == "closed":
                self.report("use-after-close", resource, position)
        self.escaped(receiver)
        # Writer.append returns the writer; GZIP.finish writes a trailer but
        # releases neither its deflater nor its backing stream.
        result = receiver if name == "append" and "Writer" in receiver.kind else UNKNOWN
        self.result(state, result, position)
        return [state, self.thrown(state)]

    def wrap_stream(self, state: State, backing: Value, kind: str, options: tuple[Value, ...],
                    token: int, *, option_kind: str, reuse: bool = False,
                    charset_extension: bool = False) -> list[State]:
        if len(options) > 1 or any(self.references(value, state) or value.callback >= 0 for value in options):
            raise ValueError("Unsupported Kotlin stream wrapper arguments; analysis is incomplete")
        position = self.offset(token)
        # The Kotlin buffered extensions return an already buffered receiver.
        # A size argument is evaluated but cannot fail a skipped constructor.
        if reuse and backing.kind == kind:
            return self.result(state, backing, position)
        wrapped = replace(backing, kind=kind, symbol="", constant="", literal=None)
        if not options:
            return self.result(state, wrapped, position)
        option = options[0]
        if option_kind == "size":
            number = int(option.constant) if re.fullmatch(r"[+-]?\d+", option.constant) else None
            if number is not None and 0 < number <= 2_147_483_647:
                return self.result(state, wrapped, position)
            failed = self.thrown(state, "java.lang.IllegalArgumentException")
            if number is not None and number <= 0:
                return [failed]
        else:
            if self.standard_charset(option, token):
                return self.result(state, wrapped, position)
            if not charset_extension and option.kind in {"java.lang.String", "kotlin.String"}:
                if option.literal is not None and option.literal.upper() in STANDARD_CHARSETS:
                    return self.result(state, wrapped, position)
                failed = self.thrown(state, "java.io.UnsupportedEncodingException")
            elif option.constant == "null":
                return [self.thrown(state, "java.lang.NullPointerException")]
            elif option.kind in {"java.nio.charset.Charset", "java.nio.charset.CharsetDecoder",
                                 "java.nio.charset.CharsetEncoder"}:
                # A nullable/custom charset or codec can fail before the
                # wrapper exists; its precise exception is not locally known.
                failed = self.thrown(state, "")
            else:
                raise ValueError("Unresolved Kotlin stream charset overload; analysis is incomplete")
        # Failure precedes ownership transfer. Keep the backing obligation in
        # this branch so outer use/finally or a matching catch must discharge it.
        return self.result(state, wrapped, position) + [failed]

    def operator(self, low: int, high: int, wanted: set[str]) -> int | None:
        index = low
        while index < high:
            self.model.spend()
            if index in self.model.pairs:
                index = self.model.pairs[index] + 1
                continue
            if self.model.value(index) in wanted:
                return index
            index += 1
        return None

    def captures(self, opening: int, state: State) -> set[ResourceId]:
        captured = set()
        for index in range(opening + 1, self.model.pairs[opening]):
            if self.model.identifier(index):
                captured.update(self.value(state, self.model.value(index), index).resources)
        return captured

    def references(self, value: Value, state: State) -> set[ResourceId]:
        pending, result, seen = [value], set(), set()
        while pending:
            self.model.spend()
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            result.update(current.resources)
            pending.extend(state.values.get(key, captured) for key, captured in current.captured)
            pending.extend(captured for _, _, captured in current.implicit)
        return result

    def closure(self, opening: int, state: State) -> Value:
        keys = {self.key(self.model.value(index), index)
                for index in range(opening + 1, self.model.pairs[opening])
                if self.model.identifier(index)}
        captured = tuple(sorted((key, state.values[key]) for key in keys if key in state.values))
        implicit = tuple(scope for scope in state.implicit if any(
            self.model.value(index) == "it" and scope[0] < index < scope[1]
            and (self.key("it", index) is None or self.key("it", index) < scope[0])
            for index in range(opening + 1, self.model.pairs[opening])))
        return Value(callback=opening, captured=captured, implicit=implicit)

    def selected(self, low: int, high: int, state: State) -> bool:
        if any(status == "open" for status in state.life.values()):
            return True
        for call in self.model.calls:
            if low <= call.start < high:
                name = self.model.path(call.start, call.name + 1)
                qualified = self.canonical(name, call.start)
                if qualified in CONSTRUCTORS or qualified in COMPRESSION_WRAPPERS or (qualified.startswith("java.nio.file.Files.")
                        and qualified.rsplit(".", 1)[-1] in FILES_FACTORIES):
                    return True
                if self.model.value(call.name) in FILE_EXTENSIONS or self.model.value(call.name) == "accept":
                    # A helper can acquire a client from a borrowed listener;
                    # the receiver's exact kind is checked during evaluation.
                    return True
        return False

    def condition(self, start: int, end: int, state: State) -> tuple[list[State], list[State], list[State]]:
        low, high = self.token(start), self.token(end)
        while low < high and self.model.value(low) == "(" and self.model.pairs.get(low) == high - 1:
            low, high = low + 1, high - 1
        conjunction = self.operator(low, high, {"||"})
        if conjunction is None:
            conjunction = self.operator(low, high, {"&&"})
        if conjunction is not None:
            left, right, abrupt = self.condition(self.offset(low), self.offset(conjunction), state)
            yes, no = [], []
            is_and = self.model.value(conjunction) == "&&"
            for branch in left if is_and else right:
                a, b, c = self.condition(self.offset(conjunction + 1), self.offset(high), branch)
                yes.extend(a); no.extend(b); abrupt.extend(c)
            return (yes, right + no, abrupt) if is_and else (left + yes, no, abrupt)
        yes, no, abrupt = [], [], []
        for branch in self.evaluate(self.offset(low), self.offset(high), state):
            if branch.exit:
                abrupt.append(branch)
            elif branch.result.constant == "true":
                yes.append(branch)
            elif branch.result.constant in {"false", "null"}:
                no.append(branch)
            else:
                yes.append(branch.copy()); no.append(branch)
        return yes, no, abrupt

    def evaluate(self, start: int, end: int, state: State) -> list[State]:
        self.model.spend()
        if state.exit:
            return [state]
        low, high = self.token(start), self.token(end)
        while low < high and self.model.value(low) == "(" and self.model.pairs.get(low) == high - 1:
            low, high = low + 1, high - 1
        if low >= high:
            return self.result(state, UNIT, start)
        word = self.model.value(low)
        if word in {"return", "throw", "break", "continue"}:
            after, label = low + 1, word
            if self.model.value(after) == "@":
                label += "@" + self.model.value(after + 1)
                after += 2
            output = self.evaluate(self.offset(after), self.offset(high), state)
            for branch in output:
                if not branch.exit:
                    branch.exit = label
                    if word == "throw":
                        branch.exception = branch.result.exception or ExceptionPath(branch.result.kind or "java.lang.Exception")
            return output
        if word in {"if", "try", "when"}:
            statement, finish = self.parser.statement(self.offset(low), self.offset(high))
            if self.code[finish:self.offset(high)].strip():
                raise ValueError("Unsupported Kotlin resource expression; analysis is incomplete")
            return self.execute(statement, state)
        if high - low == 2 and word in {"+", "-"} and self.model.value(low + 1).isdigit():
            return self.result(state, Value(constant=word + self.model.value(low + 1)), start)
        if high - low == 3:
            prefix = self.model.value(low) == self.model.value(low + 1) and word in {"+", "-"}
            postfix = self.model.value(low + 1) == self.model.value(low + 2) and self.model.value(low + 1) in {"+", "-"}
            variable = high - 1 if prefix else low
            if (prefix or postfix) and self.model.identifier(variable):
                key = self.key(self.model.value(variable), variable)
                previous = state.values.get(key, UNKNOWN)
                operation = word if prefix else self.model.value(low + 1)
                value = Value(constant=str(int(previous.constant) + (1 if operation == "+" else -1))) if previous.constant.isdigit() else UNKNOWN
                if key is not None:
                    state.values[key] = value
                return self.result(state, value if prefix else previous, start)
        boolean = self.operator(low, high, {"&&", "||"})
        if boolean is not None:
            yes, no, abrupt = self.condition(self.offset(low), self.offset(high), state)
            return ([self.result(branch, Value(constant="true"), start)[0] for branch in yes]
                    + [self.result(branch, Value(constant="false"), start)[0] for branch in no] + abrupt)
        operator = self.operator(low, high, {"?:", "==", "!=", ">", "<", ">=", "<=", "+", "-"})
        if operator is not None:
            output = []
            operation = self.model.value(operator)
            for left in self.evaluate(self.offset(low), self.offset(operator), state):
                if left.exit:
                    output.append(left); continue
                value = left.result
                if operation == "?:" and (value.resources or value.constant not in {"", "null"}):
                    output.append(left); continue
                if operation == "?:" and value.constant != "null":
                    output.append(left.copy())
                for right in self.evaluate(self.offset(operator + 1), self.offset(high), left):
                    if right.exit or operation == "?:":
                        output.append(right); continue
                    a, b = value.constant, right.result.constant
                    if value.resources and b == "null":
                        a = "nonnull"
                    if right.result.resources and a == "null":
                        b = "nonnull"
                    result = UNKNOWN
                    if a and b and operation in {"==", "!="}:
                        result = Value(constant=str((a == b) == (operation == "==")).lower())
                    elif a.isdigit() and b.isdigit():
                        x, y = int(a), int(b)
                        if operation in {"+", "-"}:
                            result = Value(constant=str(x + y if operation == "+" else x - y))
                        else:
                            result = Value(constant=str({">": x > y, "<": x < y,
                                                         ">=": x >= y, "<=": x <= y}[operation]).lower())
                    output.extend(self.result(right, result, start))
            return self.unique(output)
        if word == "!":
            output = self.evaluate(self.offset(low + 1), self.offset(high), state)
            for branch in output:
                if not branch.exit:
                    value = {"true": "false", "false": "true"}.get(branch.result.constant, "")
                    branch.result = Value(constant=value)
            return output
        if word == "{" and self.model.pairs.get(low) == high - 1:
            return self.result(state, self.closure(low, state), start)
        if word == "(" and low in self.model.pairs:
            close = self.model.pairs[low]
            states = self.evaluate(self.offset(low + 1), self.offset(close), state)
            cursor = close + 1
        else:
            states = self.result(state, self.value(state, word, low), self.offset(low))
            cursor = low + 1
        name_position = low
        receiver: dict[int, Value] = {}
        while cursor < high:
            self.model.spend()
            symbol = self.model.value(cursor)
            if symbol in {".", "?."} and self.model.identifier(cursor + 1):
                member = self.model.value(cursor + 1)
                name_position = cursor + 1
                previous_receiver, receiver = receiver, {}
                for branch in states:
                    prefix = previous_receiver.get(id(branch), UNKNOWN)
                    if prefix.symbol:
                        branch.result = Value(symbol=prefix.symbol + "." + branch.result.symbol)
                    elif prefix.resources:
                        raise ValueError("Unsupported selected Kotlin resource property; analysis is incomplete")
                    receiver[id(branch)] = branch.result
                    branch.result = Value(symbol=member)
                cursor += 2
                continue
            if symbol in {"(", "{"}:
                opening = cursor
                closing = self.model.pairs[opening]
                arguments = list(self.model.parts(opening + 1, closing)) if symbol == "(" else []
                following = closing + 1
                block = opening if symbol == "{" else None
                if symbol == "(" and self.model.value(following) == "{" and following < high:
                    block, following = following, self.model.pairs[following] + 1
                output = []
                for branch in states:
                    if branch.exit:
                        output.append(branch); continue
                    callable_value = branch.result
                    target = receiver.get(id(branch), UNKNOWN)
                    pending = [(branch, ())]
                    for a, b in arguments:
                        equal = self.operator(a, b, {"="})
                        if equal is not None:
                            a = equal + 1
                        evaluated = []
                        for current, values in pending:
                            for after in self.evaluate(self.offset(a), self.offset(b), current):
                                evaluated.append((after, (*values, after.result)))
                        pending = evaluated
                    for after, values in pending:
                        if after.exit:
                            output.append(after); continue
                        if block is not None:
                            values = (*values, self.closure(block, after))
                        output.extend(self.call(callable_value, target, values, name_position, after))
                states, cursor, receiver = self.unique(output), following, {}
                continue
            if symbol == "!!":
                cursor += 1
                continue
            if symbol in {"++", "--"}:
                for branch in states:
                    key = self.key(word, low)
                    if key is not None and branch.result.constant.isdigit():
                        branch.values[key] = Value(constant=str(int(branch.result.constant) + (1 if symbol == "++" else -1)))
                cursor += 1
                continue
            if symbol == "[":
                if any(branch.result.resources for branch in states):
                    raise ValueError("Unsupported Kotlin resource indexing; analysis is incomplete")
                cursor = self.model.pairs[cursor] + 1
                continue
            # Literal interpolation can contain several executed expressions.
            if any(self.selected(cursor, high, branch) for branch in states):
                raise ValueError("Unsupported selected Kotlin resource expression; analysis is incomplete")
            return self.result(state, UNKNOWN, start)
        if receiver:
            for branch in states:
                previous = receiver.get(id(branch), UNKNOWN)
                if previous.symbol:
                    branch.result = Value(symbol=previous.symbol + "." + branch.result.symbol)
                elif previous.resources:
                    raise ValueError("Unsupported selected Kotlin resource property; analysis is incomplete")
        return states

    def call(self, callable_value: Value, receiver: Value, arguments: tuple[Value, ...],
             token: int, state: State) -> list[State]:
        name, position = callable_value.symbol, self.offset(token)
        if callable_value.callback >= 0:
            return self.callback(callable_value, arguments, state, "")
        if receiver.symbol:
            qualified = self.canonical(receiver.symbol + "." + name, token)
        else:
            qualified = self.canonical(name, token)
        if qualified in CONSTRUCTORS:
            return self.acquire(state, qualified, qualified, position)
        if qualified in COMPRESSION_WRAPPERS:
            return self.compress_stream(state, qualified, arguments, token)
        if qualified in WRAPPERS:
            family, option_kind = WRAPPERS[qualified]
            if not arguments or arguments[0].kind not in STREAM_TYPES[family]:
                if (arguments and not any(self.references(value, state) for value in arguments)
                        and not any(value.callback >= 0 for value in arguments)
                        and not any(status == "open" for status in state.life.values())):
                    # Buffering an unowned/in-memory value does not acquire an
                    # OS resource. Do not manufacture a local obligation.
                    return self.result(state, Value(kind=qualified), position)
                raise ValueError("Unresolved Kotlin stream wrapper receiver; analysis is incomplete")
            return self.wrap_stream(state, arguments[0], qualified, arguments[1:], token, option_kind=option_kind)
        if qualified.startswith("java.nio.file.Files.") and qualified.rsplit(".", 1)[-1] in FILES_FACTORIES:
            return self.acquire(state, qualified, FILES_FACTORIES[qualified.rsplit(".", 1)[-1]], position)
        if qualified == "java.io.File":
            return self.result(state, Value(kind=qualified), position)
        if not arguments and ((receiver.kind == "java.net.Socket" and name in SOCKET_STREAMS)
                              or (receiver.kind == "java.net.ServerSocket" and name == "accept")):
            # Kotlin resolves real members ahead of same-named extensions.
            # Keep this before selected helper dispatch for the native arity.
            return self.socket_resource(receiver, name, position, state)
        if name == "getChannel" and receiver.kind in {"java.net.Socket", "java.net.ServerSocket"}:
            raise ValueError("Kotlin socket/channel ownership needs analysis; analysis is incomplete")
        if not arguments and receiver.kind == "java.util.zip.GZIPOutputStream" and name == "finish":
            return self.io_operation(receiver, name, position, state)
        if not arguments and receiver.kind in COMPRESSION_WRAPPERS and name == "close":
            return self.close_resource(receiver, position, state)
        function = self.functions.get(self.key(name, token))
        if function is not None and (not receiver.kind or function.receiver):
            if (not self.selected(function.start, function.end, state)
                    and not any(self.references(value, state) for value in (receiver, *arguments))
                    and not any(value.callback >= 0 for value in arguments)):
                return self.result(state, UNKNOWN, position)
            return self.function(function, arguments, receiver, state)
        if receiver.kind == "java.io.File" and name in FILE_EXTENSIONS and self.builtin(name, token, name):
            return self.acquire(state, "kotlin.io." + name, FILE_EXTENSIONS[name], position)
        for extension, families in STREAM_EXTENSIONS.items():
            if self.builtin(name, token, extension, state=state):
                kind = next((wrapper for family, wrapper in families.items() if receiver.kind in STREAM_TYPES[family]), None)
                if kind is not None:
                    return self.wrap_stream(state, receiver, kind, arguments, token,
                                            option_kind="size" if extension == "buffered" else "charset",
                                            reuse=extension == "buffered", charset_extension=True)
        if receiver.resources and self.builtin(name, token, "use"):
            if len(arguments) != 1 or arguments[0].callback < 0:
                raise ValueError("Unsupported Kotlin use callback; analysis is incomplete")
            previous, previous_scopes = state.managed, state.use_scopes
            state.managed += (receiver.resources,)
            state.use_scopes += (arguments[0].callback,)
            output = self.callback(arguments[0], (receiver,), state, name)
            final = []
            for branch in output:
                escaping = self.references(branch.result, branch) & receiver.resources
                if escaping:
                    branch.result = replace(branch.result, escapes=tuple(sorted(set(branch.result.escapes) |
                        {(resource, branch.position) for resource in escaping})))
                for resource in receiver.resources:
                    branch.life[resource] = "closed"
                branch.managed = previous
                branch.use_scopes = previous_scopes
                final.append(branch)
                if not branch.exit:
                    final.append(self.thrown(branch))
            return self.unique(final)
        if name == "close" and (receiver.resources or receiver.kind in COMPRESSION_WRAPPERS
                                or receiver.kind.startswith(("java.io.", "java.net.", "java.util.stream."))):
            return self.close_resource(receiver, position, state)
        if receiver.resources and name in {"getInputStream", "getOutputStream", "accept", "getChannel"}:
            raise ValueError("Related Kotlin/JVM resource return needs ownership analysis; analysis is incomplete")
        if receiver.resources and name in IO_OPERATIONS:
            return self.io_operation(receiver, name, position, state)
        if receiver.resources and name in {"toString", "hashCode", "equals", "isClosed"}:
            return self.result(state, UNKNOWN, position)
        if self.builtin(name, token, "run") and len(arguments) == 1 and arguments[0].callback >= 0:
            return self.callback(arguments[0], (), state, name)
        if any(self.builtin(name, token, builtin) for builtin in ("print", "println")):
            return self.result(state, UNIT, position)
        if name in {"requireNotNull", "checkNotNull"} and self.builtin(name, token, name) and arguments:
            return self.result(state, arguments[0], position)
        if any(value.resources for value in (receiver, *arguments)):
            raise ValueError("Unknown Kotlin resource receiver/argument effect; analysis is incomplete")
        if any(value.callback >= 0 and (self.captures(value.callback, state)
               or self.selected(value.callback, self.model.pairs[value.callback], State())) for value in arguments):
            raise ValueError("Unknown Kotlin callback affects selected resources; analysis is incomplete")
        kind = qualified if qualified.startswith("java.") and qualified.endswith(("Exception", "Throwable", "Error")) else ""
        self.result(state, Value(kind=kind, exception=ExceptionPath(kind, exact=True) if kind else None), position)
        if kind:
            return [state]
        if any(status == "open" for status in state.life.values()):
            return [state, self.thrown(state, "")]
        return [state]

    def callback(self, callback: Value, arguments: tuple[Value, ...], state: State, label: str) -> list[State]:
        opening = callback.callback
        closing = self.model.pairs[opening]
        arrow = self.operator(opening + 1, closing, {"->"})
        previous, saved = state.implicit, {}
        for key, value in callback.captured:
            if key not in state.values:
                saved[key] = None
                state.values[key] = value
        state.implicit = callback.implicit + previous
        body = opening + 1
        if arrow is not None:
            parameters = list(self.model.parts(opening + 1, arrow))
            for ordinal, (low, _) in enumerate(parameters):
                saved[low] = state.values.get(low)
                state.values[low] = arguments[ordinal] if ordinal < len(arguments) else UNKNOWN
            body = arrow + 1
        elif arguments:
            state.implicit += ((opening, closing, arguments[0]),)
        states = self.flow(self.parser.block(self.offset(body), self.offset(closing)), [state])
        for branch in states:
            if label and branch.exit == "return@" + label:
                branch.exit = ""
            branch.implicit = previous
            for key, value in saved.items():
                if value is None:
                    branch.values.pop(key, None)
                else:
                    branch.values[key] = value
        return states

    def function(self, function, arguments: tuple[Value, ...], receiver: Value, state: State) -> list[State]:
        if function.name in self.active_calls or len(self.active_calls) >= 32:
            raise AnalysisLimit("Recursive/deep Kotlin resource helper call; analysis is incomplete")
        parameters = list(self.model.parts(function.parameters + 1, self.model.pairs[function.parameters]))
        if len(arguments) != len(parameters):
            raise ValueError("Unsupported Kotlin resource helper arguments; analysis is incomplete")
        local = {binding.declaration for values in self.model.bindings.values() for binding in values
                 if function.start <= binding.low and binding.high <= function.end}
        saved = {key: state.values.get(key) for key in local}
        for (low, _), value in zip(parameters, arguments):
            state.values[low] = value
        previous_receiver, previous_implicit = state.receiver, state.implicit
        state.receiver = receiver
        state.implicit = tuple(scope for scope in previous_implicit if scope[0] < function.declaration < scope[1])
        self.active_calls.append(function.name)
        try:
            low = function.start + (0 if function.expression else 1)
            high = function.end - (0 if function.expression else 1)
            if function.expression:
                output = self.evaluate(self.offset(low), self.offset(high), state)
            else:
                output = self.flow(self.parser.block(self.offset(low), self.offset(high)), [state])
                for branch in output:
                    if not branch.exit:
                        branch.result = UNIT
        finally:
            self.active_calls.pop()
        for branch in output:
            if branch.exit == "return":
                branch.exit = ""
            branch.receiver, branch.implicit = previous_receiver, previous_implicit
            for key, value in saved.items():
                if value is None:
                    branch.values.pop(key, None)
                else:
                    branch.values[key] = value
            self.discard_unreachable(branch)
        return output

    def flow(self, statements: tuple[Statement, ...], states: list[State]) -> list[State]:
        for statement in statements:
            output = []
            for state in states:
                output.extend([state] if state.exit else self.execute(statement, state))
            for state in output:
                self.discard_unreachable(state)
            states = self.unique(output)
        return states

    def execute(self, statement: Statement, state: State) -> list[State]:
        self.model.spend()
        kind = statement.kind
        if kind == "definition":
            if re.match(r"(?:class|object|interface)\b", self.code[statement.start:statement.end]):
                for call in self.model.calls:
                    if (self.token(statement.start) <= call.start < self.token(statement.end)
                            and not any(function.start <= call.start < function.end for function in self.model.functions)
                            and self.selected(call.start, call.end, State())):
                        raise ValueError("Kotlin class-initializer resource ownership is unsupported; analysis is incomplete")
            return [state]
        if kind == "block":
            # A standalone Kotlin {...} expression is a deferred lambda. The
            # parser already unwraps control-flow bodies; try is handled below.
            return self.evaluate(statement.start, statement.end, state)
        if kind == "if":
            yes, no, abrupt = self.condition(*statement.header, state)
            return self.unique(self.flow(statement.body, yes) + self.flow(statement.otherwise, no) + abrupt)
        if kind in {"while", "for", "do"}:
            return self.loop(statement, state)
        if kind == "try":
            return self.try_flow(statement, state)
        if kind == "unsupported":
            if self.selected(self.token(statement.start), self.token(statement.end), state):
                raise ValueError("Unsupported Kotlin resource control flow; analysis is incomplete")
            return [state]
        expression = self.code[statement.start:statement.end]
        assignment = re.match(r"\s*(?:(?:val|var)\s+)?([A-Za-z_]\w*)(?:\s*:\s*[^=]+)?\s*=(?!=)", expression)
        if assignment:
            key = self.key(assignment.group(1), self.token(statement.start + assignment.start(1)))
            initializing = key is not None and re.match(r"\s*(?:val|var)\b", expression)
            if initializing:
                self.initializers.append(key)
            try:
                output = self.evaluate(statement.start + assignment.end(), statement.end, state)
            finally:
                if initializing:
                    self.initializers.pop()
            for branch in output:
                if not branch.exit:
                    if key is None:
                        if branch.result.resources:
                            raise ValueError("Unknown Kotlin resource assignment binding; analysis is incomplete")
                    else:
                        if branch.use_scopes and key < branch.use_scopes[-1]:
                            escaping = self.references(branch.result, branch) & set().union(*branch.managed)
                            if escaping:
                                branch.result = replace(branch.result, escapes=tuple(sorted(set(branch.result.escapes) |
                                    {(resource, branch.position) for resource in escaping})))
                        branch.values[key] = branch.result
                    self.escaped(branch.result)
                    branch.result = UNIT
            return output
        equals = self.operator(self.token(statement.start), self.token(statement.end), {"="})
        if equals is not None:
            for branch in self.evaluate(self.offset(equals + 1), statement.end, state):
                if self.references(branch.result, branch):
                    raise ValueError("Unknown Kotlin resource heap ownership; analysis is incomplete")
            return self.result(state, UNIT, statement.start)
        return self.evaluate(statement.start, statement.end, state)

    def loop(self, statement: Statement, state: State) -> list[State]:
        pending = self.flow(statement.body, [state]) if statement.kind == "do" else [state]
        output, seen = [], set()
        while pending:
            self.model.spend()
            current = pending.pop()
            if current.exit == "break":
                current.exit = ""; output.append(current); continue
            if current.exit == "continue":
                current.exit = ""
            if current.exit:
                output.append(current); continue
            signature = current.signature()
            if signature in seen:
                continue
            seen.add(signature)
            if len(seen) > 128:
                raise AnalysisLimit("Kotlin resource loop-state budget exceeded; analysis is incomplete")
            if statement.kind == "for":
                yes, no, abrupt = [current.copy()], [current], []
            else:
                yes, no, abrupt = self.condition(*statement.header, current)
            output.extend(no + abrupt)
            pending.extend(self.flow(statement.body, yes))
        return self.unique(output)

    def try_flow(self, statement: Statement, state: State) -> list[State]:
        body = statement.body[0]
        branches = self.flow(body.body if body.kind == "block" else (body,), [state])
        output = [branch for branch in branches if branch.exit != "throw"]
        for failed in (branch for branch in branches if branch.exit == "throw"):
            remaining = failed
            for handler in statement.body[1:]:
                text = self.code[slice(*handler.header)]
                parameter = re.match(r"\s*([A-Za-z_]\w*)\s*:\s*([\w.]+)", text)
                if parameter is None:
                    raise ValueError("Unsupported Kotlin resource catch binding; analysis is incomplete")
                token = self.token(handler.header[0] + parameter.start(1))
                kind = self.canonical(parameter.group(2), token)
                caught, rest = self.catch_partition(remaining.exception, kind)
                if caught is not None:
                    branch = remaining.copy()
                    branch.exit, branch.exception = "", None
                    branch.values[token] = Value(kind=kind, exception=caught)
                    output.extend(self.flow(handler.body, [branch]))
                if rest is None:
                    remaining = None
                    break
                remaining.exception = rest
            if remaining is not None:
                output.append(remaining)
        if statement.otherwise:
            final = []
            for branch in self.unique(output):
                previous = (branch.exit, branch.exception, branch.result, branch.position)
                previous_unwinding = branch.unwinding
                branch.unwinding += (branch.result,)
                branch.exit, branch.exception = "", None
                for after in self.flow(statement.otherwise, [branch]):
                    if not after.exit:
                        after.exit, after.exception, after.result, after.position = previous
                    after.unwinding = previous_unwinding
                    final.append(after)
            output = final
        return self.unique(output)

    @staticmethod
    def catches(handler: str, thrown: str) -> bool:
        while thrown:
            if handler == thrown:
                return True
            thrown = EXCEPTION_PARENTS.get(thrown, "")
        return False

    def catch_partition(self, failure: ExceptionPath | None, handler: str) -> tuple[ExceptionPath | None, ExceptionPath | None]:
        if failure is None:
            raise ValueError("Unknown Kotlin thrown resource effect; analysis is incomplete")
        if any(self.catches(excluded, handler) for excluded in failure.excluded):
            return None, failure
        if handler == "java.lang.Throwable" or self.catches(handler, failure.kind):
            return failure, None
        if failure.exact and (failure.kind in EXCEPTION_PARENTS or failure.kind == "java.lang.Throwable"):
            return None, failure
        if handler not in EXCEPTION_PARENTS or failure.kind not in (*EXCEPTION_PARENTS, "java.lang.Throwable"):
            raise ValueError("Unknown Kotlin resource catch hierarchy; analysis is incomplete")
        if not self.catches(failure.kind, handler):
            return None, failure
        # A subtype catch handles only its part of a declared exception family.
        # Keep the rest for later handlers/outer scopes; rethrowing a catch alias
        # must retain both its narrower type and previously handled exclusions.
        caught = ExceptionPath(handler, excluded=failure.excluded)
        return caught, replace(failure, excluded=failure.excluded | {handler})

    def initialize(self, function) -> State:
        state = State()
        for bindings in self.model.bindings.values():
            for binding in bindings:
                if binding.low <= function.start < binding.high and binding.type_name:
                    state.values[binding.declaration] = Value(kind=self.canonical(binding.type_name.rstrip("?"), binding.declaration))
        if function.receiver:
            state.receiver = Value(kind=self.canonical(function.receiver, function.declaration))
        return state

    def finish(self, states: list[State], expression: bool = False) -> None:
        for state in states:
            returned = state.result if state.exit == "return" or (expression and not state.exit) else UNIT
            self.escaped(returned)
            if returned.callback >= 0 and self.references(returned, state) - {resource for resource, _ in returned.escapes}:
                raise ValueError("Returned Kotlin callback captures selected resources; analysis is incomplete")
            self.report_unclosed(state, set(state.life) - returned.resources)

    def scan(self) -> list[tuple[str, int, int, str]]:
        for function in self.model.functions:
            low = function.start + (0 if function.expression else 1)
            high = function.end - (0 if function.expression else 1)
            state = self.initialize(function)
            self.active_calls.append(function.name)
            try:
                if function.expression:
                    output = self.evaluate(self.offset(low), self.offset(high), state)
                else:
                    output = self.flow(self.parser.block(self.offset(low), self.offset(high)), [state])
                self.finish(output, function.expression)
            finally:
                self.active_calls.pop()
        self.finish(self.flow(self.parser.block(0, len(self.code)), [State()]))
        return [(kind, *line_col(self.text, position), message)
                for (kind, position), message in sorted(self.findings.items(), key=lambda item: (item[0][1], item[0][0]))]


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    return Ownership(text).scan()


def run(ctx: RunContext) -> Iterable[dict]:
    enabled = {kind for kind in KINDS if ctx.rule_enabled("kotlin.resource." + kind)}
    if not enabled:
        return
    suppressions = SourceSuppressions("kotlin")
    for path in ctx.files:
        if path.suffix.lower() not in {".kt", ".kts"}:
            continue
        text = path.read_text(encoding="utf-8")
        suppressions.index(path, text)
        for kind, line, column, message in scan_text(text):
            rule = "kotlin.resource." + kind
            if kind in enabled and not suppressions.is_suppressed(path, line, rule):
                yield {"rule": rule, "path": str(path.resolve()), "line": line, "col": column,
                       "category_id": "kotlin.resource-lifecycle", "layer": "lifecycle", "lang": "kotlin",
                       "severity": "warning", "message": message}


register(Analyzer(layer="lifecycle", lang="kotlin", name="lifecycle_kotlin", run=run))
