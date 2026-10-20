"""Kotlin/JVM request provenance at selected JDBC execution sites.

The Kotlin lexical index resolves parameter types, local aliases and import
aliases. The existing JVM SQL engine supplies finite function summaries,
branches, captured prepared SQL and statement-owned batch queues. Binding a
PreparedStatement parameter never sanitizes text already captured as SQL.

Selected request APIs are the JDK HTTP server and Jakarta/javax Servlet APIs;
their Java getters also have Kotlin synthetic property spellings. Arbitrary
ORMs, callbacks, nullable receiver operations, mutable heap effects and cross-file
type resolution are outside this bounded adapter. Unsupported selected flow
remains explicitly incomplete.

API contracts: kotlinlang.org/docs/java-interop.html and the JDK java.sql
Statement/PreparedStatement interfaces. No Kotlin compiler is required to scan.
"""
from __future__ import annotations

from bisect import bisect_left
import os
from pathlib import Path
import re
from typing import Iterable

from ubs_core.analyzers import taint_java_sql as jdbc
from ubs_core.analyzers.coroutines_kotlin import KotlinCoroutines
from ubs_core.java_detectors.tls_verification import Binding
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, CLEAN, join

RULE = "kotlin.security.sql-injection"
MESSAGE = "Request-derived SQL reaches JDBC execution"
RULE_METADATA = {
    RULE: {
        "language": "kotlin", "category": "kotlin.sql", "category_id": "kotlin.sql",
        "severity": "critical", "message": MESSAGE, "confidence": "unknown",
        "manifest_cases": ["kotlin-jdbc-sql-buggy", "kotlin-jdbc-sql-clean"],
        "remediation": "Keep the SQL template static and bind values through PreparedStatement parameters.",
    }
}
_PROPERTIES = {
    "queryString": "getQueryString", "requestURI": "getRequestURI",
    "pathInfo": "getPathInfo", "servletPath": "getServletPath",
    "requestHeaders": "getRequestHeaders", "query": "getQuery", "rawQuery": "getRawQuery",
}
_EXTENSION_RE = re.compile(r"\bfun\s+[\w.?]+\s*\.\s*[A-Za-z_]\w*\s*\(")


def policy_limits() -> tuple[int, int, int]:
    values = []
    for name, default in (("UBS_KOTLIN_MAX_TOKENS", 100_000),
                          ("UBS_KOTLIN_MAX_NESTING", 192),
                          ("UBS_KOTLIN_SQL_MAX_STEPS", 500_000)):
        try:
            value = int(os.environ.get(name, str(default)))
        except ValueError as exc:
            raise AnalysisLimit(f"{name} must be a positive integer; Kotlin SQL analysis is incomplete") from exc
        if value <= 0:
            raise AnalysisLimit(f"{name} must be a positive integer; Kotlin SQL analysis is incomplete")
        values.append(value)
    return tuple(values)


class KotlinJdbcSource(jdbc.JdbcSource):
    """Adapt Kotlin lexical bindings to the shared JDBC receiver interface."""

    def __init__(self, text: str):
        self.model = KotlinCoroutines(text)
        self.text, self.code = text, self.model.code
        self.positions = [token.start for token in self.model.tokens]
        self.pairs = {self.offset(low): self.offset(high) for low, high in self.model.pairs.items()}
        self.reverse_pairs = {high: low for low, high in self.pairs.items()}
        self.imports, self.wildcards = self.model.imports, self.model.wildcards
        self.brace_parents = {self.offset(low): self.offset(parent)
                              for low, parent in self.model.parents.items()}
        self.brace_starts = sorted(self.brace_parents)
        self.classes = []
        self.type_aliases = {}
        self.bindings = {}
        for index, token in enumerate(self.model.tokens):
            if token.value not in {"class", "interface", "object", "typealias"}:
                continue
            if not self.model.identifier(index + 1):
                continue
            name = self.model.value(index + 1)
            scope = self.model.scope_at[index]
            low, high = self.offset(scope), self.offset(self.model.scopes[scope])
            self.classes.append((name, low, high))
            if token.value == "typealias" and self.model.value(index + 2) == "=":
                end = self.model.simple_end(index + 3, len(self.model.tokens))
                target = self.model.path(index + 3, end)
                self.type_aliases.setdefault(name, []).append((low, high, target, token.start))
        function_names = self.model.function_names
        for name, bindings in self.model.bindings.items():
            for binding in bindings:
                declaration = self.offset(binding.declaration)
                low, high = self.offset(binding.low), self.offset(binding.high)
                cursor = binding.declaration + 1
                type_name = binding.type_name
                initializer = None
                # An inferred constructor/call spelling is not a declared
                # type. Its runtime value gets its identity from dataflow.
                if self.model.value(cursor) != ":" and binding.declaration not in function_names:
                    type_name = "var"
                if self.model.value(cursor) == ":":
                    cursor += 1
                    while cursor < len(self.model.tokens) and self.model.value(cursor) not in {"=", ",", ")", ";", "}"}:
                        if cursor > binding.declaration + 2 and "\n" in self.code[
                                self.model.tokens[cursor - 1].end:self.offset(cursor)]:
                            break
                        cursor += 1
                if self.model.value(cursor) == "=":
                    end = self.model.simple_end(cursor + 1, len(self.model.tokens))
                    initializer = (self.offset(cursor + 1), min(self.offset(end), high))
                field = binding.low in self.model.classes
                self.bindings.setdefault(name, []).append(Binding(
                    name, type_name, declaration, max(0, low), high, initializer, field))

    def offset(self, index: int) -> int:
        if index < 0:
            return -1
        return self.positions[index] if index < len(self.positions) else len(self.code)

    def expression_end(self, low: int, high: int) -> int:
        token = bisect_left(self.positions, low)
        end = self.model.simple_end(token, bisect_left(self.positions, high))
        return min(self.offset(end), high)

    def resolve_type(self, spelling: str, position: int, depth: int = 0) -> str | None:
        if depth > 24:
            raise AnalysisLimit("Kotlin SQL type alias depth exceeded; analysis is incomplete")
        spelling = re.sub(r"\s+", "", spelling).rstrip("?")
        aliases = [(low, high, target, declaration)
                   for low, high, target, declaration in self.type_aliases.get(spelling, ())
                   if low < position < high]
        local_classes = [(name, low, high) for name, low, high in self.classes
                         if name == spelling.split(".", 1)[0] and 0 <= low < position < high]
        root, _, tail = spelling.partition(".")
        if local_classes:
            nearest = max(low for _, low, _ in local_classes)
            local_aliases = [alias for alias in aliases if alias[0] == nearest]
            if local_aliases:
                _, _, target, declaration = max(local_aliases)
                return self.resolve_type(target, declaration, depth + 1)
            return None
        # Kotlin explicit imports precede declarations in the current package;
        # local and member classifier scopes above precede those imports.
        if root in self.imports:
            spelling = self.imports[root] + ("." + tail if tail else "")
            return spelling if spelling in jdbc._APIS else None
        if aliases:
            _, _, target, declaration = max(aliases)
            return self.resolve_type(target, declaration, depth + 1)
        if any(name == root and low < position < high for name, low, high in self.classes):
            return None
        if spelling in jdbc._APIS:
            return spelling
        defaults = {"String": "java.lang.String", "kotlin.String": "java.lang.String",
                    "Any": "java.lang.Object", "kotlin.Any": "java.lang.Object",
                    "StringBuilder": "java.lang.StringBuilder"}
        candidates = {package + "." + spelling for package in self.wildcards
                      if package + "." + spelling in jdbc._APIS}
        if len(candidates) == 1:
            return next(iter(candidates))
        return defaults.get(spelling) if not candidates else None

    def receiver_type(self, low: int, high: int, *, depth: int = 0) -> str | None:
        if depth > 32:
            raise AnalysisLimit("Kotlin SQL receiver depth exceeded; analysis is incomplete")
        low, high = self.trim(low, high)
        if self.code[high - 2:high] == "!!":
            return self.receiver_type(low, high - 2, depth=depth + 1)
        return super().receiver_type(low, high, depth=depth)

    def argument_type(self, low: int, high: int) -> tuple | None:
        actual = super().argument_type(low, high)
        if actual is not None:
            return actual
        limit = high
        low, high = self.trim(low, high)
        # The lexical mask replaces the literal with 0 plus whitespace, so
        # trim() may end inside its original quoted text. Read that token from
        # the source while still requiring one inert masked argument.
        literal = jdbc._LITERAL.match(self.text, low, limit)
        if (self.text[low:low + 1] == '"' and literal and self.code[low:high] == "0"
                and self.code[low:literal.end()].strip() == "0"):
            return ("api", "java.lang.String")
        return None


class KotlinSqlEngine(jdbc.SqlEngine):
    source_re = re.compile(jdbc._SOURCE_RE.pattern + r"|\b[A-Za-z_]\w*\s*\.\s*(?:"
                           + "|".join(_PROPERTIES) + r")\b")

    def __init__(self, path, text, source, limits):
        super().__init__(path, text, source, limits)
        self.parameter_defaults = {}
        for function in self.parser.functions.values():
            self.budget.spend()
            defaults = []
            if function.parameters:
                opening = self.code.find("(", function.key)
                for low, high in self.parser.parts(opening + 1, self.parser.pairs[opening], generics=True):
                    default = None
                    cursor = low
                    while cursor < high:
                        self.budget.spend()
                        if cursor in self.parser.pairs:
                            cursor = self.parser.pairs[cursor]
                        elif self.code[cursor] == "=":
                            default = (cursor + 1, high)
                            break
                        cursor += 1
                    defaults.append(default)
            self.parameter_defaults[function.key] = tuple(defaults)

    def parameter_type(self, declaration):
        match = re.fullmatch(r"\s*[A-Za-z_]\w*\s*:\s*([\w.]+\??)\s*", declaration.split("=", 1)[0])
        return match.group(1) if match else None

    def _literal_default(self, span):
        low, high = self.jdbc.trim(*span)
        masked, raw = self.code[low:high].strip(), self.text[low:high].strip()
        string = jdbc._LITERAL.fullmatch(raw) and masked == "0"
        scalar = masked in {"true", "false", "null"} or re.fullmatch(
            r"[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)[uU]?[lLfFdD]?",
            masked)
        if not string and not scalar:
            raise ValueError("Omitted Kotlin SQL helper default needs executable argument binding; analysis is incomplete")
        return self._constant_value(low, "Kotlin literal default argument")

    @staticmethod
    def _argument_compatible(actual, formal):
        if actual is None or formal is None:
            return None
        if actual == formal or formal == ("api", "java.lang.Object"):
            return True
        if actual[0] != "api" or formal[0] != "api":
            # External API types cannot acquire a source-local supertype.
            # Source-local inheritance in the opposite direction needs its
            # own proof rather than a same-name overload guess.
            return False if actual[0] == "api" else None
        supers = {
            "java.sql.PreparedStatement": {"java.sql.Statement"},
            "java.sql.CallableStatement": {"java.sql.PreparedStatement", "java.sql.Statement"},
            "jakarta.servlet.http.HttpServletRequest": {"jakarta.servlet.ServletRequest"},
            "javax.servlet.http.HttpServletRequest": {"javax.servlet.ServletRequest"},
            "com.sun.net.httpserver.HttpsExchange": {"com.sun.net.httpserver.HttpExchange"},
            "java.lang.String": {"java.lang.CharSequence"},
            "java.lang.StringBuilder": {"java.lang.CharSequence"},
            "java.lang.StringBuffer": {"java.lang.CharSequence"},
            "java.util.concurrent.ExecutorService": {"java.util.concurrent.Executor"},
            "java.util.concurrent.ScheduledExecutorService": {
                "java.util.concurrent.ExecutorService", "java.util.concurrent.Executor"},
        }
        return formal[1] in supers.get(actual[1], ())

    def selected_calls(self, name, arguments, argument_names, offset, bindings):
        explicit_member = name.startswith("this.")
        if ("." in name and not explicit_member) or (not explicit_member and name in bindings):
            return []
        candidates = []
        for function in self.parser.functions.values():
            self.budget.spend()
            if (function.name != name.removeprefix("this.") or function.owner != self.function.owner
                    or not function.declaration_scope[0] < offset < function.declaration_scope[1]
                    or (explicit_member and not function.member) or len(arguments) > len(function.parameters)):
                continue
            bound, slots = {}, []
            for position, (keyword, fact) in enumerate(zip(argument_names, arguments)):
                if keyword is not None and keyword not in function.parameters:
                    break
                slot = function.parameters.index(keyword) if keyword is not None else position
                if slot in slots:
                    break
                bound[(function.key, slot)] = fact
                slots.append(slot)
            else:
                missing = tuple(index for index in range(len(function.parameters)) if index not in slots)
                if all(self.parameter_defaults[function.key][index] is not None for index in missing):
                    candidates.append((function, bound, slots, missing))
        if not any(missing for _, _, _, missing in candidates):
            selected = super().selected_calls(name, arguments, argument_names, offset, bindings)
            if selected:
                nearest = max(function.declaration_scope[0] for function, _ in selected)
                selected = [(function, actuals) for function, actuals in selected
                            if function.declaration_scope[0] == nearest]
            return selected

        opening = self.code.find("(", offset)
        actual_types = []
        for (low, high), keyword in zip(self.parser.parts(opening + 1, self.parser.pairs[opening]), argument_names):
            if keyword is not None:
                named = re.match(r"\s*[A-Za-z_]\w*\s*=(?!=)", self.code[low:high])
                low += named.end() if named else 0
            actual_types.append(self.jdbc.argument_type(low, high))

        selected = []
        for scope in sorted({function.declaration_scope[0] for function, _, _, _ in candidates}, reverse=True):
            applicable, exact = [], []
            for function, bound, slots, missing in candidates:
                if function.declaration_scope[0] != scope:
                    continue
                self.budget.spend()
                formals = [self.parameter_type(declaration) for declaration in function.parameter_declarations]
                ordered = [self.jdbc.nominal_type(formals[slot], function.key) if formals[slot] else None for slot in slots]
                compatibility = [self._argument_compatible(actual, formal) for actual, formal in zip(actual_types, ordered)]
                if False in compatibility:
                    continue
                entry = (function, bound, missing, compatibility)
                applicable.append(entry)
                if all(actual_types) and ordered == actual_types:
                    exact.append(entry)
            if not applicable:
                continue
            # Kotlin resolves the nearest applicable lexical overload set
            # before comparing specificity or the number of omitted defaults.
            if exact:
                applicable = exact
            elif len(applicable) > 1 or (None in applicable[0][3] and any(
                    function.declaration_scope[0] < scope for function, _, _, _ in candidates)):
                raise ValueError("Kotlin SQL helper default overload needs argument-type resolution; analysis is incomplete")
            omitted = min(len(missing) for _, _, missing, _ in applicable)
            applicable = [entry for entry in applicable if len(entry[2]) == omitted]
            if len(applicable) > 1:
                raise ValueError("Ambiguous Kotlin SQL helper default overload; analysis is incomplete")
            function, bound, missing, _ = applicable[0]
            for index in missing:
                bound[(function.key, index)] = self._literal_default(self.parameter_defaults[function.key][index])
            selected.append((function, bound))
            break

        return self._prepare_selected_calls(selected)

    def _property_receiver(self, name, offset, bindings, state):
        parts = name.split(".")
        count = 2 if parts[0] == "this" else 1
        if len(parts) <= count:
            return None
        current, types = super()._receiver(".".join(parts[:count]), offset, bindings, state)
        for index, member in enumerate(parts[count:]):
            method = _PROPERTIES.get(member)
            known = self._known_call(method, [], current, offset, types, current) if method else None
            if known is None:
                if index:
                    raise ValueError("Kotlin SQL member after a synthetic getter needs property-binding analysis; analysis is incomplete")
                return None
            current, types = known, jdbc._types(known) & jdbc._APIS
        return current, types

    def _receiver(self, name, offset, bindings, state):
        selected = self._property_receiver(name, offset, bindings, state)
        return selected if selected is not None else super()._receiver(name, offset, bindings, state)

    def external_call(self, name, arguments, value, offset, bindings, state):
        # The JVM expression reader accepts a qualified name as one atom.
        # Resolve synthetic getters in its receiver before applying the call,
        # so request.queryString.orEmpty() retains the getter's provenance.
        root = name.rpartition(".")[0]
        selected = self._property_receiver(root, offset, bindings, state)
        if selected is not None:
            value = join(value, selected[0])
        return super().external_call(name, arguments, value, offset, bindings, state)

    def _grouped_chains(self, start, end):
        """Keep Kotlin synthetic getters on parenthesized JVM receivers."""
        cursor = start
        while cursor < end:
            self.budget.spend()
            if self.code[cursor] not in "([":
                cursor += 1
                continue
            opening, closing = cursor, self.parser.pairs[cursor]
            previous = re.search(r"[A-Za-z_]\w*$", self.code[start:opening].rstrip())
            group = self.code[opening] == "(" and (not previous or previous.group() in {"return", "throw"})
            cursor = closing + 1
            if not group:
                continue
            members = []
            while cursor < end:
                self.budget.spend()
                dot = self.parser.skip(cursor, end)
                member = re.match(r"\.\s*([A-Za-z_]\w*)", self.code[dot:end])
                if not member:
                    break
                following = self.parser.skip(dot + member.end(), end)
                name = member.group(1)
                if self.code[following:following + 1] == "(":
                    finish = self.parser.pairs[following]
                    members.append((dot, name, following + 1, finish))
                    cursor = finish + 1
                elif name in _PROPERTIES:
                    members.append((dot, _PROPERTIES[name], following, following))
                    cursor = following
                else:
                    break
            if members:
                yield opening, closing, cursor, members

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if arguments is None and name in _PROPERTIES and self.contexts:
            match = re.match(r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*", self.code[offset:])
            if match and "." in match.group():
                _, _, bindings, state = self.contexts[-1]
                selected = self._property_receiver(re.sub(r"\s+", "", match.group()), offset, bindings, state)
                if selected is not None:
                    return selected[0]
            known = self._known_call(_PROPERTIES[name], [], value, offset,
                                    jdbc._types(receiver) & jdbc._APIS, receiver)
            if known is not None:
                return known
        return super().member_value(name, value, offset, arguments, direct_call, receiver)


def analyze_source(path: Path, text: str) -> list[dict]:
    if path.suffix.lower() not in {".kt", ".kts"}:
        return []
    selected_sink = jdbc._SINK_RE.search(text)
    if not selected_sink and not _EXTENSION_RE.search(text):
        return []
    limits = policy_limits()
    source = KotlinJdbcSource(text)
    for function in source.model.functions:
        if function.receiver and source.resolve_type(function.receiver, source.offset(function.name)) in jdbc._OBJECTS:
            raise ValueError("Kotlin SQL extension receiver needs implicit receiver binding; analysis is incomplete")
    if not selected_sink:
        return []
    for nullable in re.finditer(r"\?\.|!!", source.code):
        start = source.receiver_start(nullable.start())
        if source.receiver_type(start, nullable.start()) in jdbc._OBJECTS:
            raise ValueError("Nullable Kotlin JDBC/request receiver needs null-completion analysis; analysis is incomplete")
    engine = KotlinSqlEngine(path, text, source, limits)
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
                "severity": "critical", "category_id": "kotlin.sql", "message": MESSAGE,
                "extras": {"taint_path": [step.record() for step in witness.evidence],
                           "source_count": len({trace.key for trace in values})}})
    return findings


def run(ctx: RunContext) -> Iterable[dict]:
    if not ctx.rule_enabled(RULE):
        return
    suppressions = SourceSuppressions("kotlin")
    for path in ctx.files:
        if path.suffix.lower() not in {".kt", ".kts"}:
            continue
        text = path.read_text(encoding="utf-8")
        suppression = suppressions.index(path, text)
        for finding in analyze_source(path, text):
            if not suppression.is_suppressed(finding["line"], RULE):
                yield finding


register(Analyzer(layer="taint", lang="kotlin", name="taint_kotlin_sql", run=run))
