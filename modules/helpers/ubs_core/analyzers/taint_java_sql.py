"""Request-derived SQL executed through selected, bound JDBC receivers.

Reuse the finite JVM CFG and local call summaries. JDBC objects and captured
prepared SQL are distinct facts: setters bind values, never rewrite SQL text.
Only genuine java.sql receivers and JDK HTTP exchange sources qualify. Static
strings have explicit identities, while unknown values remain unknown; absence
of request taint is not proof that a legacy concatenation warning is redundant.

The selected surface is Statement execution overloads and PreparedStatement /
CallableStatement zero-argument execution, with local aliases, factory calls,
try-with-resources, branches and selected local helper calls. Mutable SQL
builders, callbacks and SQL-bearing heap state need additional policies and
retain the frontend's explicit incomplete-analysis result.
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
_EXECUTE = frozenset({"execute", "executeQuery", "executeUpdate", "executeLargeUpdate"})
_PREPARED = frozenset({"java.sql.PreparedStatement", "java.sql.CallableStatement"})
_STATEMENTS = _PREPARED | {"java.sql.Statement"}
_HTTP = frozenset({"com.sun.net.httpserver.HttpExchange", "com.sun.net.httpserver.HttpsExchange"})
_EXECUTORS = frozenset({"java.util.concurrent.Executor", "java.util.concurrent.ExecutorService",
                        "java.util.concurrent.ScheduledExecutorService"})
_OBJECTS = _STATEMENTS | _HTTP | {"java.sql.Connection"}
_APIS = _OBJECTS | _EXECUTORS | {"java.lang.String", "java.net.URI", "java.lang.Integer", "java.lang.Long"}
_TYPE_PREFIX = "sql:type:"
_PREPARED_SQL = "sql:prepared-query"
_SINK_RE = re.compile(r"\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|execute)\s*\(")
_SOURCE_RE = re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*(?:getRequestURI|getRequestHeaders)\s*\(")
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
            if self.code[cursor - 1:cursor] in {")", "]"}:
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
                method = re.search(r"\.\s*(createStatement|prepareStatement|prepareCall)\s*$", self.code[low:opening])
                if method and self.receiver_type(low, low + method.start(), depth=depth + 1) == "java.sql.Connection":
                    return {"createStatement": "java.sql.Statement", "prepareStatement": "java.sql.PreparedStatement",
                            "prepareCall": "java.sql.CallableStatement"}[method.group(1)]
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
            if (actual in _PREPARED and arguments) or (actual == "java.sql.Statement" and not arguments):
                continue
            method = re.search(r"[A-Za-z]+", match.group()).group()
            sites[match.start()] = (start, actual, method)
        return sites


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
    return frozenset(trace for trace in value if trace.kind != "jdbc-object" and not (
        trace.kind == "parameter" and _types((trace,)) & _OBJECTS))


class SqlEngine(Engine):
    source_re = _SOURCE_RE
    sink_re = _SINK_RE
    sink_label = "JDBC SQL execution"
    path_constructors = False

    def __init__(self, path: Path, text: str, source: JdbcSource, limits):
        self.jdbc = source
        self.contexts = []
        self.selected_arguments = {}
        selected = source.execution_sites()
        for arrow in re.finditer(r"->", source.code):
            low = source.skip(arrow.end())
            high = source.pairs[low] if source.code[low:low + 1] == "{" else source.expression_end(low, len(source.code))
            if any(low <= offset < high for offset in selected):
                raise ValueError("JDBC execution in a callback needs callback-state analysis; analysis is incomplete")
        super().__init__(path, text)
        self.budget = Budget(limits[2])
        for function in self.parser.functions.values():
            function.body = self._resources(function.body)

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
                if binding.type_name != "var":
                    return value, frozenset({actual}) if actual else frozenset()
        return value, _types(value) & _OBJECTS

    def source(self, offset, label):
        if label.startswith("@request") or not self.contexts:
            return CLEAN
        _, _, bindings, state = self.contexts[-1]
        match = _SOURCE_RE.match(self.code, offset)
        if not match or self.code[:offset].rstrip().endswith("."):
            return CLEAN
        root = match.group().split(".", 1)[0].strip()
        _, types = self._receiver(root, offset, bindings, state)
        if not types & _HTTP:
            return CLEAN
        return retag(super().source(offset, label), add=_type_tags("java.net.URI"))

    def safe_sink_trace(self, trace):
        return False

    def summary_effect(self, summary, fact):
        actuals = self.selected_arguments.get(id(summary), {}) if self.contexts else {}
        output = CLEAN
        for trace in fact:
            remove, additions, valid = set(), set(), True
            for tag in trace.tags:
                if not tag.startswith("sql:raw-receiver:"):
                    continue
                owner, index = tag.removeprefix("sql:raw-receiver:").split(":")
                actual = actuals.get((int(owner), int(index)))
                if actual is None:
                    continue
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
        for function, actuals in selected:
            self.selected_arguments[id(self.summaries[function.key])] = actuals
        return selected

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

    def call_sink(self, name, spans, arguments, value, offset, argument_names=(), bindings=None):
        method = name.rsplit(".", 1)[-1]
        if method not in _EXECUTE:
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
            receiver, types = self._receiver(root, offset, bindings or {}, state)
            start = offset
        if types & _PREPARED and not arguments:
            self.record(start, self._prepared_query(receiver))
        elif "java.sql.Statement" in types and arguments:
            constraints = frozenset(f"sql:raw-receiver:{trace.key[0]}:{trace.key[1]}" for trace in receiver
                                    if trace.kind == "parameter" and "java.sql.Statement" in _types((trace,)))
            self.record(start, retag(_data(arguments[0]), add=constraints))
        return False

    def _object(self, actual, offset):
        return frozenset({Trace("jdbc-object", (str(self.path), offset, actual), tags=_type_tags(actual))})

    def _known_call(self, method, arguments, value, offset, types):
        if types & _HTTP and method in {"getRequestURI", "getRequestHeaders"} and not arguments:
            actual = Engine.source(self, offset, self.text[offset:self.text.find("(", offset) + 1].strip())
            return join(_data(value), actual)
        if "java.sql.Connection" in types:
            if method == "createStatement":
                return self._object("java.sql.Statement", offset)
            if method in {"prepareStatement", "prepareCall"} and arguments:
                actual = "java.sql.PreparedStatement" if method == "prepareStatement" else "java.sql.CallableStatement"
                captured = retag(_data(arguments[0]), add=frozenset({_PREPARED_SQL}))
                return join(self._object(actual, offset), advance(captured, self.step(offset, "prepare", method)))
        if types & _STATEMENTS and (method in _EXECUTE or method.startswith("set") or
                                    method in {"close", "clearParameters", "getWarnings", "clearWarnings"}):
            return CLEAN
        return None

    def external_call(self, name, arguments, value, offset, bindings, state):
        root, _, method = name.rpartition(".")
        receiver, types = self._receiver(root, offset, bindings, state)
        known = self._known_call(method, arguments, value, offset, types)
        if known is not None:
            return known
        if method in {"parseInt", "parseLong"} and arguments and self.jdbc.resolve_type(root, offset) in {
                "java.lang.Integer", "java.lang.Long"} and self.jdbc.binding(root.split(".", 1)[0], offset) is None:
            return frozenset({Trace("literal", (str(self.path), offset), evidence=(self.step(offset, "value", "validated integer"),))})
        return join(_data(value), frozenset({Trace("unknown", (str(self.path), offset, name))}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if direct_call:
            return value
        if name in _EXECUTE and arguments is not None:
            return CLEAN
        if name in {"getQuery", "getRawQuery", "toString", "getFirst", "get"}:
            return _data(value)
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
            for dot, method, low, high in members:
                spans, names, arguments = self.call_arguments(low, high, state, bindings, depth)
                joined = join(receiver, *arguments)
                self.call_sink("." + method, spans, arguments, joined, dot, names, bindings)
                known = self._known_call(method, arguments, joined, opening, _types(receiver) & _OBJECTS)
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
