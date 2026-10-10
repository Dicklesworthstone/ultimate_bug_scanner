"""Request-derived SQL executed through selected, bound JDBC receivers.

Reuse the finite JVM CFG and local call summaries. JDBC objects and captured
prepared SQL are distinct facts: setters bind values, never rewrite SQL text.
Only genuine java.sql receivers and selected JDK/Servlet request APIs qualify. Static
strings have explicit identities, while unknown values remain unknown; absence
of request taint is not proof that a legacy concatenation warning is redundant.

The selected surface is Statement execution overloads and PreparedStatement /
CallableStatement zero-argument execution, with local aliases, factory calls,
try-with-resources, branches and selected local helper calls. Batch queues are
attached to the actual statement allocation or parameter, not its variable
name. addBatch captures query text; clearBatch and successful batch execution
empty only a definitely selected object's queue. Bound parameter values never
become query text. Selected StringBuilder/StringBuffer constructors, append,
toString and setLength(0) track mutable contents separately from aliases and
immutable query snapshots. Cross-call mutable object effects, repeated
allocation sites, other builder mutations, callbacks and SQL-bearing heap
state retain an explicit incomplete-analysis result.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache
import os
from pathlib import Path
import re
from typing import Iterable

from ubs_core.analyzers.taint_java_traversal import Engine, Statement, lexical_source
from ubs_core.java_detectors.tls_verification import VerifierSource
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Trace, advance, join, retag

RULE = "java.security.sql-injection"
MESSAGE = "Request-derived SQL reaches JDBC execution"
LIMIT_DEFAULTS = {
    "UBS_JAVA_SQL_MAX_TOKENS": 100_000,
    "UBS_JAVA_SQL_MAX_NESTING": 192,
    "UBS_JAVA_SQL_MAX_STEPS": 500_000,
}
_BATCH_EXECUTE = frozenset({"executeBatch", "executeLargeBatch"})
_BATCH_MUTATE = frozenset({"addBatch", "clearBatch"})
_EXECUTE = frozenset({"execute", "executeQuery", "executeUpdate", "executeLargeUpdate"}) | _BATCH_EXECUTE
_PREPARED = frozenset({"java.sql.PreparedStatement", "java.sql.CallableStatement"})
_STATEMENTS = _PREPARED | {"java.sql.Statement"}
_HTTP = frozenset({"com.sun.net.httpserver.HttpExchange", "com.sun.net.httpserver.HttpsExchange"})
_SERVLET = frozenset({"jakarta.servlet.ServletRequest", "javax.servlet.ServletRequest"})
_SERVLET_HTTP = frozenset({"jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest"})
_SERVLET_HTTP_ARITY = {
    "getHeader": 1, "getQueryString": 0, "getRequestURI": 0,
    "getPathInfo": 0, "getServletPath": 0,
}
_EXECUTORS = frozenset({"java.util.concurrent.Executor", "java.util.concurrent.ExecutorService",
                        "java.util.concurrent.ScheduledExecutorService"})
_BUILDERS = frozenset({"java.lang.StringBuilder", "java.lang.StringBuffer"})
_OBJECTS = _STATEMENTS | _HTTP | _SERVLET | _SERVLET_HTTP | _BUILDERS | {"java.sql.Connection"}
_APIS = _OBJECTS | _EXECUTORS | {"java.lang.String", "java.lang.CharSequence", "java.lang.Object",
                               "java.net.URI", "com.sun.net.httpserver.Headers",
                               "java.lang.Integer", "java.lang.Long"}
_TYPE_PREFIX = "sql:type:"
_PREPARED_SQL = "sql:prepared-query"
_ARGUMENT_OBJECT = "sql:argument-object"
_SINK_RE = re.compile(r"\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|executeBatch|executeLargeBatch|execute)\s*\(")
_BATCH_RE = re.compile(r"\.\s*(?:addBatch|clearBatch|executeBatch|executeLargeBatch)\s*\(")
_SQL_OPERATION_RE = re.compile(r"\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|executeBatch|executeLargeBatch|execute|addBatch|clearBatch)\s*\(")
_MEMBER_CALL_RE = re.compile(r"\.\s*[A-Za-z_$][\w$]*\s*\(")
_SOURCE_RE = re.compile(
    r"\b[A-Za-z_$][\w$]*\s*\.\s*(?P<method>getRequestURI|getRequestHeaders|getParameter|"
    r"getHeader|getQueryString|getPathInfo|getServletPath)\s*\(")
_LITERAL = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_NAME = re.compile(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*")


def policy_limits() -> tuple[int, int, int]:
    values = []
    for name, default in LIMIT_DEFAULTS.items():
        try:
            value = int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise AnalysisLimit(f"{name} must be a positive integer") from exc
        if value <= 0:
            raise AnalysisLimit(f"{name} must be a positive integer")
        values.append(value)
    return tuple(values)


def _request_result_type(types: frozenset[str], method: str, arity: int) -> str | None:
    """Selected request getters, qualified by actual API type and signature.

    Servlet attributes may be set by application code, so getAttribute does
    not establish request provenance. Value binding remains a JDBC operation
    and never inherits source semantics from a getter's spelling alone.
    """
    if types & _HTTP and arity == 0:
        if method == "getRequestURI":
            return "java.net.URI"
        if method == "getRequestHeaders":
            return "com.sun.net.httpserver.Headers"
    if method == "getParameter" and arity == 1 and types & (_SERVLET | _SERVLET_HTTP):
        return "java.lang.String"
    if types & _SERVLET_HTTP and _SERVLET_HTTP_ARITY.get(method) == arity:
        return "java.lang.String"
    return None


class JdbcSource(VerifierSource):
    """Use the existing bounded Java import/declaration and shadowing index."""

    def __init__(self, text: str, limits: tuple[int, int, int]):
        super().__init__(text, max_tokens=limits[0], max_nesting=limits[1], policy="SQL")
        self.reverse_pairs = {high: low for low, high in self.pairs.items()}

    def resolve_type(self, spelling: str, position: int) -> str | None:
        spelling = re.sub(r"\s+", "", spelling)
        for actual in _APIS:
            short = actual.rsplit(".", 1)[-1]
            if spelling == actual:
                root = actual.split(".", 1)[0]
                if not any(name == root and low < position < high for name, low, high in self.classes):
                    return actual
            if spelling != short or any(name == short and low < position < high
                                        for name, low, high in self.classes):
                continue
            imported = self.imports.get(short)
            if imported == actual or (imported is None and (
                    actual.rsplit(".", 1)[0] in self.wildcards or actual.startswith("java.lang."))):
                return actual
        return None

    def receiver_start(self, end: int) -> int:
        """Start of a receiver, including grouped or fluent call expressions."""
        cursor = end
        while cursor > 0:
            while cursor > 0 and self.code[cursor - 1].isspace():
                cursor -= 1
            if cursor > 0 and self.code[cursor - 1:cursor] in {")", "]"}:
                cursor = self.reverse_pairs[cursor - 1]
                preceding = cursor
                while preceding > 0 and self.code[preceding - 1].isspace():
                    preceding -= 1
                call = re.search(r"[A-Za-z_$][\w$]*$", self.code[:preceding])
                if not call or call.group() in {"return", "throw", "new"}:
                    return cursor
                cursor = preceding
                continue
            match = re.search(r"[A-Za-z_$][\w$]*$", self.code[:cursor])
            if match:
                cursor = match.start()
                preceding = cursor
                while preceding > 0 and self.code[preceding - 1].isspace():
                    preceding -= 1
                if self.code[preceding - 1:preceding] == ".":
                    cursor = preceding - 1
                    continue
            return cursor
        return cursor

    def receiver_type(self, low: int, high: int, *, depth: int = 0) -> str | None:
        if depth > 32:
            raise AnalysisLimit("Java SQL receiver depth limit exceeded")
        low, high = self.trim(low, high)
        raw = re.sub(r"\s+", "", self.code[low:high])
        field = raw.startswith("this.")
        name = raw[5:] if field else raw
        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            binding = self.binding(name, low, field=field)
            if binding is None:
                return None
            actual = self.resolve_type(binding.type_name, binding.declaration)
            if actual:
                return actual
            if binding.type_name == "var" and binding.initializer is not None:
                return self.receiver_type(*binding.initializer, depth=depth + 1)
            return None
        if self.code[low:low + 1] == "(":
            closing = self.pairs[low]
            if closing < high - 1:
                cast = self.resolve_type(self.code[low + 1:closing].strip(), low)
                if cast:
                    return cast
        if self.code[high - 1:high] == ")":
            opening = self.reverse_pairs.get(high - 1)
            if opening is not None:
                constructor = re.fullmatch(r"new\s+([\w.$]+)\s*", self.code[low:opening])
                if constructor:
                    actual = self.resolve_type(constructor.group(1), low)
                    if actual in _BUILDERS:
                        return actual
                method = re.search(r"\.\s*(createStatement|prepareStatement|prepareCall)\s*$", self.code[low:opening])
                if method and self.receiver_type(low, low + method.start(), depth=depth + 1) == "java.sql.Connection":
                    return {"createStatement": "java.sql.Statement", "prepareStatement": "java.sql.PreparedStatement",
                            "prepareCall": "java.sql.CallableStatement"}[method.group(1)]
        return None

    def nominal_type(self, spelling: str, position: int) -> tuple | None:
        """Identity for exact overload selection, including local class scope.

        Unknown hierarchies remain unresolved. A matching local class or real
        API declaration can select an exact overload without borrowing a
        source-producing summary from an unrelated same-arity helper.
        """
        actual = self.resolve_type(spelling, position)
        if actual is not None:
            return ("api", actual)
        local = [(low, high, name) for name, low, high in self.classes
                 if name == spelling and low < position < high]
        if local:
            return ("local", *min(local, key=lambda item: item[1] - item[0]))
        return None

    def argument_type(self, low: int, high: int) -> tuple | None:
        low, high = self.trim(low, high)
        name = re.sub(r"\s+", "", self.code[low:high])
        field = name.startswith("this.")
        if field:
            name = name[5:]
        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            binding = self.binding(name, low, field=field)
            if binding is not None:
                return self.nominal_type(binding.type_name, binding.declaration)
        if self.code[low:low + 1] == "(":
            closing = self.pairs[low]
            if closing < high - 1:
                return self.nominal_type(self.code[low + 1:closing].strip(), low)
        return None

    def execution_sites(self) -> dict[int, tuple[int, str, str]]:
        sites = {}
        for match in _SINK_RE.finditer(self.code):
            start = self.receiver_start(match.start())
            actual = self.receiver_type(start, match.start())
            if actual not in _STATEMENTS:
                continue
            opening = match.end() - 1
            arguments = self.code[opening + 1:self.pairs[opening]].strip()
            method = re.search(r"[A-Za-z]+", match.group()).group()
            if method in _BATCH_EXECUTE:
                if arguments:
                    continue
            elif (actual in _PREPARED and arguments) or (actual == "java.sql.Statement" and not arguments):
                continue
            sites[match.start()] = (start, actual, method)
        return sites

    def batch_sites(self) -> frozenset[int]:
        return frozenset(match.start() for match in _BATCH_RE.finditer(self.code)
                         if self.receiver_type(self.receiver_start(match.start()), match.start()) in _STATEMENTS)

    def builder_sites(self) -> frozenset[int]:
        return frozenset(match.start() for match in _MEMBER_CALL_RE.finditer(self.code)
                         if self.receiver_type(self.receiver_start(match.start()), match.start()) in _BUILDERS)


def jdbc_execution_sites(text: str) -> dict[int, tuple[int, str, str]]:
    """API classification only, independent of enabling the SQL taint rule."""
    if not _SINK_RE.search(text):
        return {}
    defaults = tuple(LIMIT_DEFAULTS.values())
    return JdbcSource(text, defaults).execution_sites()


def non_http_execute_sites(text: str) -> frozenset[int]:
    """Known JDBC/concurrency execute calls are not outbound HTTP requests."""
    if not re.search(r"\.\s*execute\s*\(", text):
        return frozenset()
    source = JdbcSource(text, tuple(LIMIT_DEFAULTS.values()))
    sites = set()
    for match in re.finditer(r"\.\s*execute\s*\(", source.code):
        start = source.receiver_start(match.start())
        if source.receiver_type(start, match.start()) in _STATEMENTS | _EXECUTORS:
            sites.add(match.start())
    return frozenset(sites)


def comment_masked_source(text: str) -> str:
    """Preserve source offsets and literal contents while masking comments."""
    code = lexical_source(text, False)
    characters = list(code)
    for literal in _LITERAL.finditer(text):
        low, high = literal.span()
        if code[low:high].strip() == "0":
            characters[low:high] = text[low:high]
    return "".join(characters)


def _type_tags(actual: str | None) -> frozenset[str]:
    return frozenset({_TYPE_PREFIX + actual}) if actual else frozenset()


def _types(value) -> frozenset[str]:
    return frozenset(tag[len(_TYPE_PREFIX):] for trace in value for tag in trace.tags
                     if tag.startswith(_TYPE_PREFIX))


def _data(value):
    """Object receiver identity is not query data; preserve unknown provenance."""
    return frozenset(trace for trace in value if trace.kind not in {"jdbc-object", "sql-builder"} and not (
        trace.kind == "parameter" and _types((trace,)) & _OBJECTS))


class SqlEngine(Engine):
    source_re = _SOURCE_RE
    sink_re = _SQL_OPERATION_RE
    sink_label = "JDBC SQL execution"
    path_constructors = False

    def __init__(self, path: Path, text: str, source: JdbcSource, limits):
        self.jdbc = source
        self.contexts = []
        self.selected_arguments = {}
        selected = source.execution_sites()
        self.batch_sites = source.batch_sites()
        self.builder_sites = source.builder_sites()
        self.repeated_allocations = []
        for arrow in re.finditer(r"->", source.code):
            low = source.skip(arrow.end())
            high = source.pairs[low] if source.code[low:low + 1] == "{" else source.expression_end(low, len(source.code))
            if any(low <= offset < high for offset in set(selected) | self.batch_sites):
                raise ValueError("JDBC execution in a callback needs callback-state analysis; analysis is incomplete")
            if any(low <= offset < high for offset in self.builder_sites):
                raise ValueError("SQL builder operation in a callback needs callback-state analysis; analysis is incomplete")
        super().__init__(path, text)
        self.budget = Budget(limits[2])
        for function in self.parser.functions.values():
            self._batch_boundaries(function.body)
            function.body = self._resources(function.body)

    def _batch_boundaries(self, statements):
        for statement in statements:
            if statement.kind in {"while", "for", "do"}:
                self.repeated_allocations.append((statement.start, statement.end))
            if statement.kind == "try" and (len(statement.body) > 1 or statement.otherwise) and any(
                    statement.start <= offset < statement.end for offset in self.batch_sites):
                # The shared graph joins normal and exceptional successors.
                # A clear/execute operation that throws cannot establish the
                # successful-return queue state on a catch continuation.
                raise ValueError("JDBC batch operations with catch/finally continuations need exceptional object-state analysis; analysis is incomplete")
            if statement.kind == "try" and (len(statement.body) > 1 or statement.otherwise) and any(
                    statement.start <= offset < statement.end for offset in self.builder_sites):
                raise ValueError("SQL builder operations with catch/finally continuations need exceptional object-state analysis; analysis is incomplete")
            self._batch_boundaries(statement.body)
            self._batch_boundaries(statement.otherwise)

    def _resources(self, statements):
        output = []
        for statement in statements:
            statement = replace(statement, body=self._resources(statement.body),
                                otherwise=self._resources(statement.otherwise))
            if statement.kind == "try" and self.code[slice(*statement.header)].strip():
                declarations = tuple(Statement(low, high, "simple")
                                     for low, high in self.parser.parts(*statement.header, separator=";"))
                body = (*declarations, replace(statement, header=(statement.start, statement.start)))
                statement = Statement(statement.start, statement.end, "block", body)
            output.append(statement)
        return tuple(output)

    def parameter_tags(self, declaration):
        match = re.fullmatch(r"\s*(?:final\s+)?([\w.$]+)\s+[A-Za-z_$][\w$]*\s*", declaration)
        actual = self.jdbc.resolve_type(match.group(1), self.function.key) if match else None
        return _type_tags(actual)

    def _receiver(self, name, offset, bindings, state):
        root = name.removeprefix("this.")
        value = state.get(bindings.get(root, root), CLEAN)
        actual = None
        if re.fullmatch(r"(?:this\.)?[A-Za-z_$][\w$]*", name):
            binding = self.jdbc.binding(root, offset, field=name.startswith("this."))
            if binding:
                actual = self.jdbc.resolve_type(binding.type_name, binding.declaration)
                inferred = _types(value) & _STATEMENTS
                if actual == "java.sql.Statement" and inferred:
                    return value, inferred
                builders = _types(value) & _BUILDERS
                if builders and actual in _BUILDERS | {"java.lang.CharSequence", "java.lang.Object"}:
                    return value, builders
                if binding.type_name != "var":
                    return value, frozenset({actual}) if actual else frozenset()
        return value, _types(value) & _APIS

    def source(self, offset, label):
        if label.startswith("@request") or not self.contexts:
            return CLEAN
        _, _, bindings, state = self.contexts[-1]
        match = _SOURCE_RE.match(self.code, offset)
        if not match or self.code[:offset].rstrip().endswith("."):
            return CLEAN
        root = match.group().split(".", 1)[0].strip()
        _, types = self._receiver(root, offset, bindings, state)
        opening = match.end() - 1
        arity = sum(1 for _ in self.parser.parts(opening + 1, self.parser.pairs[opening]))
        actual = _request_result_type(types, match.group("method"), arity)
        if actual is None:
            return CLEAN
        return retag(super().source(offset, label), add=_type_tags(actual))

    def safe_sink_trace(self, trace):
        return False

    def summary_effect(self, summary, fact):
        actuals = self.selected_arguments.get(id(summary), {}) if self.contexts else {}
        output = CLEAN
        for trace in fact:
            remove, additions, valid = set(), set(), True
            if self.contexts and trace.kind == "parameter" and _PREPARED_SQL in trace.tags:
                actual = actuals.get(trace.key, CLEAN)
                if any(self.contexts[-1][3].get(key) for key in self._batch_keys(actual)):
                    raise ValueError("Prepared JDBC execution in a helper with queued commands needs batch object-state summaries; analysis is incomplete")
            for tag in trace.tags:
                if not tag.startswith("sql:raw-receiver:"):
                    continue
                owner, index = tag.removeprefix("sql:raw-receiver:").split(":")
                actual = actuals.get((int(owner), int(index)))
                if actual is None:
                    continue
                if self.contexts and any(self.contexts[-1][3].get(key) for key in self._batch_keys(actual)):
                    raise ValueError("JDBC execution in a helper with queued commands needs batch object-state summaries; analysis is incomplete")
                types = _types(actual) & _STATEMENTS
                if types and "java.sql.Statement" not in types:
                    valid = False
                    break
                remove.add(tag)
                for parameter in actual:
                    if parameter.kind == "parameter" and "java.sql.Statement" in _types((parameter,)):
                        additions.add(f"sql:raw-receiver:{parameter.key[0]}:{parameter.key[1]}")
            if valid:
                output = join(output, retag(frozenset({trace}), remove=frozenset(remove), add=frozenset(additions)))
        return output

    def selected_calls(self, name, arguments, argument_names, offset, bindings):
        selected = super().selected_calls(name, arguments, argument_names, offset, bindings)
        if len(selected) > 1:
            opening = self.code.find("(", offset)
            actual_types = [self.jdbc.argument_type(low, high)
                            for low, high in self.parser.parts(opening + 1, self.parser.pairs[opening])]
            exact = []
            for function, actuals in selected:
                formal_types = []
                for declaration in function.parameter_declarations:
                    match = re.fullmatch(r"\s*(?:final\s+)?([\w.$]+)\s+[A-Za-z_$][\w$]*\s*", declaration)
                    formal_types.append(self.jdbc.nominal_type(match.group(1), function.key) if match else None)
                if (len(formal_types) == len(actual_types) and all(actual_types)
                        and formal_types == actual_types):
                    exact.append((function, actuals))
            if exact:
                selected = exact
        for function, actuals in selected:
            if any(_types(value) & _BUILDERS for value in actuals.values()):
                raise ValueError("SQL builder passed to a helper needs mutable object-effect summaries; analysis is incomplete")
            if any(function.start <= site < function.end for site in self.batch_sites) and any(
                    _types(value) & _STATEMENTS for value in actuals.values()):
                raise ValueError("JDBC batch state across a statement helper argument needs object-effect summaries; analysis is incomplete")
            for key, value in actuals.items():
                actuals[key] = join(*(retag(frozenset({trace}), add=frozenset({_ARGUMENT_OBJECT}))
                                     if trace.kind == "jdbc-object" else frozenset({trace}) for trace in value))
            self.selected_arguments[id(self.summaries[function.key])] = actuals
        return selected

    def summary_return(self, fact, offset):
        # Two invocations of a selected factory create distinct JDBC objects.
        # A returned argument is an alias and must retain its caller identity.
        # Keep one finite call-site component rather than growing call strings.
        output = []
        for trace in fact:
            if trace.kind == "jdbc-object" and _ARGUMENT_OBJECT not in trace.tags:
                trace = replace(trace, key=(*trace.key[:3], offset))
            output.append(retag(frozenset({trace}), remove=frozenset({_ARGUMENT_OBJECT})))
        return join(*output)

    def guard_facts(self, span):
        return ()

    def record(self, offset, value, file_leaf=False):
        if value:
            self.effects[offset] = join(self.effects.get(offset, CLEAN),
                advance(value, self.step(offset, "sink", self.sink_label)))

    def _prepared_query(self, value):
        selected = frozenset(trace for trace in value if _PREPARED_SQL in trace.tags or (
            trace.kind == "parameter" and _types((trace,)) & _PREPARED))
        remove = frozenset(tag for trace in selected for tag in trace.tags
                           if tag.startswith(_TYPE_PREFIX) and tag[len(_TYPE_PREFIX):] in _OBJECTS)
        return retag(selected, add=frozenset({_PREPARED_SQL}), remove=remove)

    def _batch_keys(self, receiver):
        identities = frozenset((trace.kind, trace.key) for trace in receiver
                               if trace.kind == "jdbc-object" or (
                                   trace.kind == "parameter" and _types((trace,)) & _STATEMENTS))
        if any(trace.kind == "jdbc-object" and any(low <= position < high
                for position in (trace.key[1], *trace.key[3:])
                for low, high in self.repeated_allocations) for trace in receiver):
            raise ValueError("JDBC batch receiver from a repeated allocation site needs allocation-state analysis; analysis is incomplete")
        return frozenset("@sql-batch:" + repr(identity) for identity in identities)

    def _batch_call(self, method, arguments, receiver, types, offset, state):
        if not types & _STATEMENTS:
            return
        if method in _BATCH_EXECUTE | {"clearBatch"} and arguments:
            return
        if method == "addBatch" and not ((types & _PREPARED and not arguments) or (
                "java.sql.Statement" in types and len(arguments) == 1)):
            return
        keys = self._batch_keys(receiver)
        if not keys:
            raise ValueError("JDBC batch receiver needs resolved object identity; analysis is incomplete")
        if method == "addBatch":
            query = self._prepared_query(receiver) if not arguments else _data(arguments[0])
            query = advance(query, self.step(offset, "batch-add", "addBatch captures SQL"))
            for key in keys:
                state[key] = join(state.get(key, CLEAN), query)
            return
        if method in _BATCH_EXECUTE:
            self.record(offset, join(*(state.get(key, CLEAN) for key in keys)))
        # A may-alias receiver cannot clear every possible object's queue.
        # JDBC 4.3 section 14.1.2 resets the batch after successful execution.
        if len(keys) == 1:
            state.pop(next(iter(keys)), None)

    def call_sink(self, name, call, value, offset, bindings):
        arguments = call.values
        method = name.rsplit(".", 1)[-1]
        if method not in _EXECUTE | _BATCH_MUTATE:
            return False
        if name.startswith("."):
            start = self.jdbc.receiver_start(offset)
            actual = self.jdbc.receiver_type(start, offset)
            inferred = _types(value) & _STATEMENTS
            types = inferred or (frozenset({actual}) if actual else frozenset())
            receiver = value
        else:
            root = name.rpartition(".")[0]
            state = self.contexts[-1][3]
            receiver, types = self._receiver(root, offset, bindings, state)
            start = offset
        if method in _BATCH_EXECUTE | _BATCH_MUTATE:
            self._batch_call(method, arguments, receiver, types, start, self.contexts[-1][3])
            return False
        if self.batch_sites and types & _STATEMENTS and any(
                self.contexts[-1][3].get(key) for key in self._batch_keys(receiver)):
            raise ValueError("Non-batch JDBC execution with queued commands is implementation-defined; analysis is incomplete")
        if types & _PREPARED and not arguments:
            self.record(start, self._prepared_query(receiver))
        elif "java.sql.Statement" in types and arguments:
            constraints = frozenset(f"sql:raw-receiver:{trace.key[0]}:{trace.key[1]}" for trace in receiver
                                    if trace.kind == "parameter" and "java.sql.Statement" in _types((trace,)))
            self.record(start, retag(_data(arguments[0]), add=constraints))
        return False

    def _object(self, actual, offset):
        kind = "sql-builder" if actual in _BUILDERS else "jdbc-object"
        return frozenset({Trace(kind, (str(self.path), offset, actual), tags=_type_tags(actual))})

    def _builder_keys(self, receiver):
        objects = [trace for trace in receiver if trace.kind == "sql-builder"]
        if any(trace.kind == "parameter" and _types((trace,)) & _BUILDERS for trace in receiver):
            raise ValueError("SQL builder parameter needs caller object-state analysis; analysis is incomplete")
        if not objects:
            raise ValueError("SQL builder receiver needs resolved object identity; analysis is incomplete")
        if any(low <= trace.key[1] < high for trace in objects for low, high in self.repeated_allocations):
            raise ValueError("SQL builder from a repeated allocation site needs allocation-state analysis; analysis is incomplete")
        return frozenset("@sql-builder:" + repr(trace.key) for trace in objects)

    def _builder_contents(self, receiver, state, offset):
        keys = self._builder_keys(receiver)
        if any(key not in state for key in keys):
            raise ValueError("SQL builder contents need resolved object-state analysis; analysis is incomplete")
        contents = join(*(state[key] for key in keys))
        return advance(contents, self.step(offset, "builder-read", "builder contents"))

    def _string_value(self, value, state, offset):
        builders = frozenset(trace for trace in value if _types((trace,)) & _BUILDERS)
        contents = self._builder_contents(builders, state, offset) if builders else CLEAN
        data = join(_data(value), contents)
        remove = frozenset(tag for trace in data for tag in trace.tags if tag.startswith(_TYPE_PREFIX))
        return retag(data, add=_type_tags("java.lang.String"), remove=remove)

    def _constant_value(self, offset, label):
        return frozenset({Trace("literal", (str(self.path), offset),
                               evidence=(self.step(offset, "value", label),))})

    def _builder_constructor(self, name, arguments, offset, state):
        actual = self.jdbc.resolve_type(name, offset)
        if actual not in _BUILDERS or not re.search(r"\bnew\s*$", self.code[:offset]):
            return None
        if len(arguments) > 1:
            raise ValueError("Unsupported SQL builder constructor; analysis is incomplete")
        contents = self._constant_value(offset, "empty SQL builder")
        if arguments:
            opening = self.code.find("(", offset)
            low, high = next(self.parser.parts(opening + 1, self.parser.pairs[opening]))
            raw = self.text[low:high].strip()
            binding = self.jdbc.binding(raw, low) if re.fullmatch(r"[A-Za-z_$][\w$]*", raw) else None
            capacity = bool(re.fullmatch(r"[+\-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)", raw))
            capacity = capacity or (binding is not None and binding.type_name in {"byte", "short", "char", "int"})
            capacity = capacity or bool(arguments[0]) and all("sql:integer" in trace.tags for trace in arguments[0])
            if not capacity:
                declared = self.jdbc.resolve_type(binding.type_name, binding.declaration) if binding else None
                string_types = _BUILDERS | {"java.lang.String", "java.lang.CharSequence"}
                if (any(trace.kind in {"source", "parameter"} for trace in arguments[0])
                        and not _types(arguments[0]) & string_types and declared not in string_types):
                    raise ValueError("SQL builder constructor overload needs a resolved string or capacity; analysis is incomplete")
                contents = self._string_value(arguments[0], state, offset) or contents
        receiver = self._object(actual, offset)
        for key in self._builder_keys(receiver):
            state[key] = advance(contents, self.step(offset, "builder-create", name))
        return receiver

    def _builder_call(self, method, arguments, receiver, offset, state):
        keys = self._builder_keys(receiver)
        if method == "append" and len(arguments) == 1:
            contents = self._string_value(arguments[0], state, offset)
            contents = advance(contents, self.step(offset, "builder-append", "append captures SQL text"))
            for key in keys:
                if key not in state:
                    raise ValueError("SQL builder append needs resolved contents; analysis is incomplete")
                state[key] = join(state[key], contents)
            return receiver
        if method == "toString" and not arguments:
            return self._string_value(receiver, state, offset)
        if method == "setLength" and len(arguments) == 1:
            opening = self.code.find("(", offset)
            low, high = next(self.parser.parts(opening + 1, self.parser.pairs[opening]))
            if self.text[low:high].strip() != "0":
                raise ValueError("SQL builder truncation needs character-range analysis; analysis is incomplete")
            # Clearing a may-alias receiver must not erase every candidate's
            # contents. Proving the selected object's later read needs a
            # correlation that the per-object finite state does not retain.
            if len(keys) != 1:
                raise ValueError("SQL builder reset through a may-alias receiver needs correlated object state; analysis is incomplete")
            state[next(iter(keys))] = self._constant_value(offset, "SQL builder reset to empty")
            return CLEAN
        if method in {"length", "capacity"} and not arguments:
            return retag(self._constant_value(offset, "SQL builder integer result"), add=frozenset({"sql:integer"}))
        if (method == "ensureCapacity" and len(arguments) == 1) or (method == "trimToSize" and not arguments):
            return CLEAN
        raise ValueError(f"SQL builder {method} needs character/object-effect analysis; analysis is incomplete")

    def _known_call(self, method, arguments, value, offset, types, receiver=CLEAN):
        if types & _BUILDERS:
            return self._builder_call(method, arguments, receiver, offset, self.contexts[-1][3])
        request_type = _request_result_type(types, method, len(arguments))
        if request_type is not None:
            actual = Engine.source(self, offset, self.text[offset:self.text.find("(", offset) + 1].strip())
            return join(_data(value), retag(actual, add=_type_tags(request_type)))
        if "java.net.URI" in types and method in {"getQuery", "getRawQuery", "toString"} and not arguments:
            return retag(_data(value), add=_type_tags("java.lang.String"), remove=_type_tags("java.net.URI"))
        if "com.sun.net.httpserver.Headers" in types and method == "getFirst" and len(arguments) == 1:
            return retag(_data(value), add=_type_tags("java.lang.String"),
                         remove=_type_tags("com.sun.net.httpserver.Headers"))
        if "java.lang.String" in types:
            integer_methods = {"length": {0}, "hashCode": {0}, "indexOf": {1, 2},
                               "lastIndexOf": {1, 2}, "compareTo": {1}, "compareToIgnoreCase": {1}}
            if len(arguments) in integer_methods.get(method, set()):
                return retag(self._constant_value(offset, "String integer result"), add=frozenset({"sql:integer"}))
            string_methods = {"toString": {0}, "concat": {1}, "substring": {1, 2}, "trim": {0},
                              "strip": {0}, "stripLeading": {0}, "stripTrailing": {0}, "replace": {2},
                              "replaceAll": {2}, "replaceFirst": {2}, "toLowerCase": {0, 1}, "toUpperCase": {0, 1}}
            if len(arguments) in string_methods.get(method, set()):
                return retag(_data(value), add=_type_tags("java.lang.String"))
        if "java.sql.Connection" in types:
            if method == "createStatement":
                return self._object("java.sql.Statement", offset)
            if method in {"prepareStatement", "prepareCall"} and arguments:
                actual = "java.sql.PreparedStatement" if method == "prepareStatement" else "java.sql.CallableStatement"
                captured = retag(_data(arguments[0]), add=frozenset({_PREPARED_SQL}))
                return join(self._object(actual, offset), advance(captured, self.step(offset, "prepare", method)))
        if types & _STATEMENTS and (method in _EXECUTE | _BATCH_MUTATE or method.startswith("set") or
                                    method in {"close", "clearParameters", "getWarnings", "clearWarnings"}):
            return CLEAN
        return None

    def external_call(self, name, arguments, value, offset, bindings, state):
        constructed = self._builder_constructor(name, arguments, offset, state)
        if constructed is not None:
            return constructed
        root, _, method = name.rpartition(".")
        receiver, types = self._receiver(root, offset, bindings, state)
        known = self._known_call(method, arguments, value, offset, types, receiver)
        if known is not None:
            return known
        if (method == "valueOf" and len(arguments) == 1 and self.jdbc.resolve_type(root, offset) == "java.lang.String"
                and self.jdbc.binding(root.split(".", 1)[0], offset) is None):
            return self._string_value(arguments[0], state, offset)
        if any(_types(argument) & _BUILDERS for argument in arguments):
            raise ValueError("SQL builder passed to an unresolved call may mutate or escape; analysis is incomplete")
        if self.batch_sites and any(_types(argument) & _STATEMENTS for argument in arguments):
            raise ValueError("JDBC statement passed to an unresolved call may mutate its batch; analysis is incomplete")
        if method in {"parseInt", "parseLong"} and arguments and self.jdbc.resolve_type(root, offset) in {
                "java.lang.Integer", "java.lang.Long"} and self.jdbc.binding(root.split(".", 1)[0], offset) is None:
            return frozenset({Trace("literal", (str(self.path), offset), evidence=(self.step(offset, "value", "validated integer"),))})
        remove = frozenset(tag for trace in value for tag in trace.tags if tag.startswith(_TYPE_PREFIX))
        return join(retag(_data(value), remove=remove), frozenset({Trace("unknown", (str(self.path), offset, name))}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if direct_call:
            return value
        if arguments is not None:
            known = self._known_call(name, arguments, value, offset, _types(receiver) & _APIS, receiver)
            if known is not None:
                return known
        if name in _EXECUTE and arguments is not None:
            return CLEAN
        if arguments is not None:
            remove = frozenset(tag for trace in value for tag in trace.tags if tag.startswith(_TYPE_PREFIX))
            return join(retag(_data(value), remove=remove),
                        frozenset({Trace("unknown", (str(self.path), offset, name))}))
        return _data(value)

    def _grouped_chains(self, start, end):
        cursor = start
        while cursor < end:
            if self.code[cursor] not in "([":
                cursor += 1
                continue
            opening, closing = cursor, self.parser.pairs[cursor]
            before = self.code[start:opening].rstrip()
            previous = re.search(r"[A-Za-z_$][\w$]*$", before)
            group = self.code[opening] == "(" and (not previous or previous.group() in {"return", "throw"})
            cursor = closing + 1
            if not group:
                continue
            members = []
            while cursor < end:
                dot = self.parser.skip(cursor, end)
                member = re.match(r"\.\s*([A-Za-z_$][\w$]*)", self.code[dot:end])
                if not member:
                    break
                following = self.parser.skip(dot + member.end(), end)
                if self.code[following:following + 1] != "(":
                    break
                finish = self.parser.pairs[following]
                members.append((dot, member.group(1), following + 1, finish))
                cursor = finish + 1
            if members:
                yield opening, closing, cursor, members

    def _expression_value(self, start, end, state, bindings, depth):
        value, beginning = CLEAN, start
        chains = list(self._grouped_chains(start, end))
        if not chains:
            return super().expression(start, end, state, bindings, depth)
        for opening, closing, finish, members in chains:
            value = join(value, super().expression(beginning, opening, state, bindings, depth))
            receiver = self.expression(opening + 1, closing, state, bindings, depth + 1)
            declared = self.jdbc.receiver_type(opening, closing + 1)
            for dot, method, low, high in members:
                call_arguments = self.call_arguments(low, high, state, bindings, depth)
                arguments = call_arguments.values
                joined = join(receiver, *arguments)
                self.call_sink("." + method, call_arguments, joined, dot, bindings)
                types = _types(receiver) & _APIS
                if declared in _HTTP | _SERVLET | _SERVLET_HTTP:
                    types = frozenset({declared})
                known = self._known_call(method, arguments, joined, dot, types, receiver)
                declared = None
                if known is not None:
                    receiver = known
                elif method in {"getQuery", "getRawQuery", "toString", "getFirst", "get"}:
                    receiver = _data(joined)
                else:
                    receiver = join(_data(joined), frozenset({Trace("unknown", (str(self.path), dot, method))}))
            value, beginning = join(value, receiver), finish
        return join(value, super().expression(beginning, end, state, bindings, depth))

    def expression(self, start, end, state, bindings, depth=0):
        self.contexts.append((start, end, bindings, state))
        try:
            value = self._expression_value(start, end, state, bindings, depth)
            if _types(value) & _BUILDERS and sum(1 for _ in self.parser.parts(start, end, separator="+")) > 1:
                value = self._string_value(value, state, start)
        finally:
            self.contexts.pop()
        # Inert literal text is distinct from missing/unknown dataflow facts.
        literal_facts = []
        for match in _LITERAL.finditer(self.text, start, end):
            if self.code[match.start():match.end()].strip() != "0":
                continue
            literal_facts.append(frozenset({Trace("literal", (str(self.path), match.start()),
                evidence=(self.step(match.start(), "literal", "SQL string literal"),))}))
        value = join(value, *literal_facts)
        for match in _NAME.finditer(self.code, start, end):
            name = re.sub(r"\s+", "", match.group())
            following = self.parser.skip(match.end(), end)
            if (self.code[following:following + 1] == "(" or name in {
                    "new", "return", "throw", "true", "false", "null", "this", "int", "long"}
                    or self.code[match.start() - 1:match.start()] == "."):
                continue
            root = name.split(".", 1)[0]
            if state.get(bindings.get(root, root), CLEAN):
                continue
            if self.jdbc.resolve_type(name, match.start()):
                continue
            value = join(value, frozenset({Trace("unknown", (str(self.path), match.start(), name))}))
        return value

    def transfer(self, action, state):
        output = super().transfer(action, state)
        if any(_types(value) & _BUILDERS for value in self.escapes.values()):
            raise ValueError("SQL builder field/element escape needs heap-state analysis; analysis is incomplete")
        if action[0] == "return" and _types(output.get("@return", CLEAN)) & _BUILDERS:
            raise ValueError("Returning a SQL builder needs mutable object-state summaries; analysis is incomplete")
        if action[0] == "return" and self.batch_sites:
            returned = output.get("@return", CLEAN)
            if any(output.get(key) for key in self._batch_keys(returned)):
                raise ValueError("Returning a queued JDBC statement needs batch object-state summaries; analysis is incomplete")
        # Discard contents only after the final local reference is replaced.
        # Otherwise a dead object from the opposite branch would contaminate
        # a still-live object that was definitely reset on this branch.
        live_builders = {"@sql-builder:" + repr(trace.key) for binding, value in output.items()
                         if not binding.startswith("@sql-builder:") for trace in value
                         if trace.kind == "sql-builder"}
        for binding in tuple(output):
            if binding.startswith("@sql-builder:") and binding not in live_builders:
                output.pop(binding)
        return output


@dataclass(frozen=True)
class SqlAnalysis:
    findings: tuple[dict, ...]
    qualified_literal_offsets: frozenset[int] = frozenset()
    qualified_execution_lines: frozenset[int] = frozenset()


@lru_cache(maxsize=16)
def _analyze(path: Path, text: str, limits: tuple[int, int, int]) -> SqlAnalysis:
    source = JdbcSource(text, limits)
    if not source.execution_sites():
        return SqlAnalysis(())
    engine = SqlEngine(path, text, source, limits)
    effects = engine.analyze()
    findings = []
    for line, fact in sorted(effects.items()):
        sites = {}
        for trace in fact:
            sink = trace.evidence[-1]
            sites[sink.column] = join(sites.get(sink.column, CLEAN), frozenset({trace}))
        for column, values in sorted(sites.items()):
            witness = min(values, key=lambda trace: (len(trace.evidence), trace.evidence))
            findings.append({"rule": RULE, "path": str(path), "line": line, "col": column,
                "severity": "critical", "category_id": "java.security", "message": MESSAGE,
                "extras": {"taint_path": [step.record() for step in witness.evidence],
                           "source_count": len({trace.key for trace in values})}})
    literals, execution_lines = set(), set()
    for summary in engine.summaries.values():
        for offset, values in summary.effects.items():
            known = any(trace.kind == "source" for trace in values) or bool(values) and all(
                trace.kind == "literal" for trace in values)
            if known:
                execution_lines.add(engine.step(offset, "sink", MESSAGE).line)
                literals.update(int(trace.key[1]) for trace in values if trace.kind == "literal")
    return SqlAnalysis(tuple(findings), frozenset(literals), frozenset(execution_lines))


def analyze_details(path: Path, text: str) -> SqlAnalysis:
    if path.suffix.lower() != ".java" or not _SINK_RE.search(text):
        return SqlAnalysis(())
    return _analyze(path, text, policy_limits())


def analyze_source(path: Path, text: str) -> list[dict]:
    return [dict(row) for row in analyze_details(path, text).findings]


def qualify_legacy_records(path: Path, text: str, records: list[dict], *, enabled: bool) -> list[dict]:
    """Drop only inert matches or a concatenation covered by a proved query."""
    legacy = {"java.sql.concat", "java.sql.exec-concat", "java.sql.concat-fallback"}
    if not any(record.get("rule") in legacy for record in records):
        return records
    code = lexical_source(text, False)
    code_lines, source_lines = code.splitlines(), text.splitlines()
    beginnings, position = [], 0
    for line in text.splitlines(keepends=True):
        beginnings.append(position)
        position += len(line)
    analysis = analyze_details(path, text) if enabled else SqlAnalysis(())
    qualified_lines = set()
    for line, content in enumerate(source_lines, 1):
        candidates = [beginnings[line - 1] + match.start() for match in
                      re.finditer(r'"(?:SELECT|INSERT|UPDATE|DELETE)[^"\r\n]*"\s*\+', content)
                      if "+" in code_lines[line - 1][match.start():match.end()]]
        if candidates and all(offset in analysis.qualified_literal_offsets for offset in candidates):
            qualified_lines.add(line)
    output = []
    for record in records:
        if record.get("rule") not in legacy:
            output.append(record)
            continue
        line = int(record.get("line", 0))
        if not 0 < line <= len(code_lines):
            output.append(record)
            continue
        if "+" not in code_lines[line - 1]:
            continue
        if line in qualified_lines or (record["rule"] == "java.sql.exec-concat"
                                       and line in analysis.qualified_execution_lines):
            continue
        output.append(record)
    return output


def run(ctx: RunContext) -> Iterable[dict]:
    if not ctx.rule_enabled(RULE):
        return
    for path in ctx.files:
        if path.suffix.lower() == ".java":
            yield from analyze_source(path, path.read_text(encoding="utf-8"))


register(Analyzer(layer="taint", lang="java", name="taint_java_sql", run=run))
