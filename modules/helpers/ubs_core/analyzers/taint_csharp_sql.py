"""Bounded, in-file ASP.NET request provenance for Dapper string-SQL calls.

This policy reuses the C# lexical frontend, lexical bindings, CFG and local
helper summaries. API facts establish actual request/connection identities;
an identifier named ``request`` or an arbitrary ``Query`` method is no proof.
SQL and separately bound values occupy different argument slots. The selected
model covers synchronous buffered and ordinary asynchronous string overloads,
including Type-leading overloads; it does not simulate deferred enumeration,
CommandDefinition, multimapping, reflection or cross-file mutable effects.

Signatures were checked against Dapper SqlMapper.cs / SqlMapper.Async.cs at
eb47546a408bbf6c178bda4f04dc205bc51ffbfe. The scanner needs only Python.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable

from ubs_core.analyzers.taint_csharp_request import CSharpFlow, masked_source, parts
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, Budget, CLEAN, Fact, Trace, join

RULE = RULE_ID = "cs.security.sql-injection"
MESSAGE = "Request-derived SQL reaches a Dapper execution call"
RULE_METADATA = {
    RULE: {
        "language": "csharp", "category": "csharp.security",
        "category_id": "csharp.security", "severity": "critical",
        "message": MESSAGE, "confidence": "unknown",
        "remediation": "Keep the SQL template static and pass request values in Dapper's separate parameter object.",
        "manifest_cases": ["csharp-dapper-buggy", "csharp-dapper-clean"],
    }
}
LIMIT_DEFAULTS = {
    "UBS_CSHARP_SQL_MAX_TOKENS": 100_000,
    "UBS_CSHARP_SQL_MAX_NESTING": 96,
    "UBS_CSHARP_SQL_MAX_STEPS": 500_000,
}

CONNECTIONS = frozenset({
    "System.Data.IDbConnection", "System.Data.Common.DbConnection",
    "System.Data.SqlClient.SqlConnection", "Microsoft.Data.SqlClient.SqlConnection",
})
REQUEST = "Microsoft.AspNetCore.Http.HttpRequest"
CONTEXT = "Microsoft.AspNetCore.Http.HttpContext"
CONTROLLERS = frozenset({"Microsoft.AspNetCore.Mvc.ControllerBase", "Microsoft.AspNetCore.Mvc.Controller"})
MAPPER = "Dapper.SqlMapper"
COMMAND = "Dapper.CommandDefinition"
KNOWN_TYPES = CONNECTIONS | CONTROLLERS | frozenset({
    REQUEST, CONTEXT, MAPPER, COMMAND, "System.Type", "System.String",
    "System.Object", "System.Boolean", "System.Int32", "System.Int64", "System.Data.CommandType",
})
PRIMITIVES = {"string": "System.String", "object": "System.Object", "bool": "System.Boolean",
              "int": "System.Int32", "long": "System.Int64", "dynamic": "dynamic"}
REQUEST_MEMBERS = frozenset({"Query", "Form", "Headers", "Cookies", "RouteValues",
                             "Path", "PathBase", "QueryString"})
STRING_METHODS = frozenset({"Execute", "ExecuteScalar", "Query", "QueryFirst", "QueryFirstOrDefault",
                            "QuerySingle", "QuerySingleOrDefault"})
SQL_CALL = re.compile(
    r"\b(?:Execute(?:Scalar)?|Query(?:First(?:OrDefault)?|Single(?:OrDefault)?|Unbuffered|Multiple)?)"
    r"(?:Async)?\s*(?:<[\w@.,\s:< >\[\]?]+>)?\s*\(")


def policy_limits() -> dict[str, int]:
    """Validate positive policy bounds and never exceed the supported ceilings."""
    limits = {}
    for key, ceiling in LIMIT_DEFAULTS.items():
        raw = os.environ.get(key, str(ceiling))
        if not re.fullmatch(r"[0-9]+", raw) or len(raw) > 12 or int(raw) <= 0:
            raise ValueError(f"Invalid {key}: expected a positive integer; analysis is incomplete")
        limits[key] = min(int(raw), ceiling)
    return limits


def api_fact(identity: str) -> Fact:
    return frozenset({Trace("api", (identity,))}) if identity else CLEAN


def identities(fact: Fact) -> frozenset[str]:
    return frozenset(trace.key[0] for trace in fact if trace.kind == "api")


def provenance(fact: Fact) -> Fact:
    return frozenset(trace for trace in fact if trace.kind in {"source", "parameter"})


@dataclass(frozen=True)
class Scope:
    start: int
    end: int
    name: str
    kind: str
    bases: str = ""


@dataclass(frozen=True)
class Import:
    start: int
    end: int
    position: int
    alias: str
    target: str
    static: bool = False


class TypeIndex:
    """Resolve the selected external types with namespace and local shadowing."""

    def __init__(self, flow):
        self.flow = flow
        self.scopes = []
        declaration = re.compile(
            r"\b(namespace|class|struct|interface|record)\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
            r"(?:\s*<[^;{}]+>)?([^;{}]*)([;{])")
        for match in declaration.finditer(flow.code):
            kind, name, tail, delimiter = match.groups()
            if delimiter == ";" and kind != "namespace":
                continue
            end = flow.parser.pairs[match.end() - 1] if delimiter == "{" else len(flow.code)
            self.scopes.append(Scope(match.start(), end, name, kind, tail))
        self.local_types = {}
        for scope in self.scopes:
            if scope.kind != "namespace":
                owner = self.owner(scope.start)
                full = ".".join((*owner, scope.name))
                self.local_types[full] = scope
        self.namespaces = {""}
        for value in KNOWN_TYPES | frozenset(self.local_types):
            segments = value.split(".")
            self.namespaces.update(".".join(segments[:index]) for index in range(1, len(segments)))
        self.imports = []
        pattern = re.compile(
            r"\b(?:global\s+)?using\s+(?:(static)\s+)?(?:(@?\w+)\s*=\s*)?([\w@.:]+)\s*;")
        for match in pattern.finditer(flow.code):
            if any(function.start <= match.start() < function.end
                   for key, function in flow.parser.functions.items() if key >= 0):
                continue
            enclosing = [scope for scope in self.scopes if scope.kind == "namespace"
                         and scope.start < match.start() < scope.end]
            scope = min(enclosing, key=lambda item: item.end - item.start) if enclosing else None
            self.imports.append(Import(scope.start if scope else 0, scope.end if scope else len(flow.code),
                                       match.start(), (match.group(2) or "").lstrip("@"),
                                       match.group(3).replace("@", ""), bool(match.group(1))))

    def owner(self, position: int) -> tuple[str, ...]:
        return tuple(scope.name for scope in self.scopes if scope.start < position < scope.end)

    def namespace(self, position: int) -> str:
        return ".".join(scope.name for scope in self.scopes
                        if scope.kind == "namespace" and scope.start < position < scope.end)

    def namespace_prefixes(self, position: int):
        segments = self.namespace(position).split(".") if self.namespace(position) else []
        return [".".join(segments[:size]) for size in range(len(segments), -1, -1)]

    def visible_imports(self, position: int):
        return sorted((item for item in self.imports if item.start <= position < item.end),
                      key=lambda item: (item.end - item.start, -item.position))

    def qualify_namespace(self, spelling: str, position: int) -> str:
        if spelling.startswith("global::"):
            return spelling[len("global::"):]
        for prefix in self.namespace_prefixes(position):
            candidate = ".".join(filter(None, (prefix, spelling)))
            if candidate in self.namespaces:
                return candidate
        return spelling

    def imported(self, namespace: str, position: int) -> bool:
        return any(not item.alias and not item.static
                   and self.qualify_namespace(item.target, item.position) == namespace
                   for item in self.visible_imports(position))

    def resolve(self, spelling: str, position: int, depth: int = 0) -> str:
        if depth > 12:
            raise AnalysisLimit("C# type alias limit exceeded; analysis is incomplete")
        spelling = re.sub(r"\s|@", "", spelling).rstrip("?")
        if not spelling:
            return ""
        if spelling in PRIMITIVES:
            return PRIMITIVES[spelling]
        global_name = spelling.startswith("global::")
        name = spelling[len("global::"):] if global_name else spelling
        if not global_name:
            root, _, suffix = name.partition(".")
            alias = next((item for item in self.visible_imports(position) if item.alias == root), None)
            if alias:
                resolved = self.resolve(alias.target, alias.position, depth + 1)
                if suffix:
                    # A namespace alias is resolved before its member type.
                    target = self.qualify_namespace(alias.target, alias.position)
                    return self.resolve("global::" + target + "." + suffix, position, depth + 1)
                return resolved
        candidates = [name] if global_name else [
            ".".join(filter(None, (prefix, name))) for prefix in self.namespace_prefixes(position)]
        if not global_name and "." not in name:
            owner = self.owner(position)
            candidates = [".".join((*owner[:size], name)) for size in range(len(owner), 0, -1)] + candidates
        for candidate in candidates:
            if candidate in self.local_types:
                return "local:" + candidate
            if candidate in KNOWN_TYPES:
                return candidate
        if not global_name and "." not in name:
            matches = set()
            for item in self.visible_imports(position):
                if item.alias or item.static:
                    continue
                candidate = self.qualify_namespace(item.target, item.position) + "." + name
                if candidate in self.local_types:
                    matches.add("local:" + candidate)
                elif candidate in KNOWN_TYPES:
                    matches.add(candidate)
            if len(matches) == 1:
                return matches.pop()
            if len(matches) > 1:
                return "ambiguous:" + name
        return "unknown:" + name

    def controller(self, position: int) -> bool:
        for full, scope in self.local_types.items():
            if scope.start < position < scope.end and ":" in scope.bases:
                bases = scope.bases.split(":", 1)[1]
                if any(self.resolve(base, scope.start) in CONTROLLERS for base in bases.split(",")):
                    return True
        return False


class DapperFlow(CSharpFlow):
    rule = RULE
    message = MESSAGE

    def __init__(self, path: Path, text: str, limits=None):
        self.limits = policy_limits() if limits is None else limits
        code = masked_source(text)
        ceiling = self.limits["UBS_CSHARP_SQL_MAX_TOKENS"]
        for count, _ in enumerate(re.finditer(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|[^\s]", code), 1):
            if count > ceiling:
                raise AnalysisLimit("C# SQL token limit exceeded; analysis is incomplete")
        nesting = 0
        for char in code:
            nesting += (char in "([{") - (char in ")]}")
            if nesting > self.limits["UBS_CSHARP_SQL_MAX_NESTING"]:
                raise AnalysisLimit("C# SQL nesting limit exceeded; analysis is incomplete")
        super().__init__(path, text)
        self.budget = Budget(self.limits["UBS_CSHARP_SQL_MAX_STEPS"])
        self.types = TypeIndex(self)
        self.context_issues = {}
        self.current_issues = set()
        self.extension_actuals = {}
        self.ambiguous_extensions = set()

    def incomplete(self, position, reason):
        location = self.step(position, "boundary", reason)
        self.current_issues.add(f"line {location.line}: {reason}")

    def is_source(self, name):
        # Source names are interpreted together with lexical storage/type facts.
        return False

    def path_guard(self, span, bindings=None):
        return None

    def parameter_fact(self, function, index):
        value = super().parameter_fact(function, index)
        spelling = function.parameter_types[index] if index < len(function.parameter_types) else ""
        return join(value, api_fact(self.types.resolve(spelling, function.key)))

    def name_value(self, name, position, state, bindings):
        pieces = name.split(".")
        root = pieces[0]
        value = state.get(bindings.get(root, ""), CLEAN)
        members = pieces[1:]
        if root == "this" and members and members[0] == "Request":
            if self.types.controller(position):
                value, members = api_fact(REQUEST), members[1:]
        elif root == "Request" and root not in bindings and self.types.controller(position):
            value = api_fact(REQUEST)
        current = identities(value)
        if CONTEXT in current and members and members[0] == "Request":
            value, members = api_fact(REQUEST), members[1:]
            current = identities(value)
        if REQUEST in current and members and members[0] in REQUEST_MEMBERS:
            return self.source_fact(position, name)
        if members:
            # Members of an arbitrary local object are not ASP.NET sources.
            return provenance(value)
        return value

    def call_candidates(self, name, args, values, state, bindings, position):
        self.extension_actuals = {}
        pieces = name.split(".")
        if len(pieces) == 1 or pieces[0] == "this":
            return super().call_candidates(name, args, values, state, bindings, position)
        root = pieces[0]
        owners = identities(state.get(bindings.get(root, ""), CLEAN)) if root in bindings else frozenset({
            self.types.resolve(self.raw_name(position, name).rsplit(".", 1)[0], position)})
        local_owners = {owner[len("local:"):] for owner in owners if owner.startswith("local:")}
        candidates = [function for function in self.parser.functions.values()
                      if function.parent is None and function.name == pieces[-1]
                      and ".".join(function.owner) in local_owners
                      and len(function.parameters) - function.defaults <= len(args) <= len(function.parameters)]
        if candidates or root not in bindings or not owners & CONNECTIONS:
            return candidates
        # Applicable extensions in an enclosing application namespace take
        # precedence over imported Dapper extensions. Execute their real local
        # helper summaries, including a separately bound implicit receiver.
        for namespace in self.types.namespace_prefixes(position):
            extensions = []
            for function in self.parser.functions.values():
                if (function.name != pieces[-1] or function.parent is not None or not function.parameter_types
                        or self.types.namespace(function.key) != namespace
                        or not re.search(r"\(\s*(?:\[[^\]]*\]\s*)*this\b", self.code[function.key:function.start])
                        or not len(function.parameters) - function.defaults <= len(args) + 1 <= len(function.parameters)):
                    continue
                expected = self.types.resolve(function.parameter_types[0], function.key)
                compatible = expected in owners or (expected == "System.Data.IDbConnection" and owners & CONNECTIONS)
                if compatible:
                    extensions.append(function)
            if extensions:
                if len(extensions) != 1:
                    self.incomplete(position, "Application extension overload resolution is outside the selected model")
                    self.ambiguous_extensions.add(position)
                    return []
                function = extensions[0]
                actual = (None, position, position + len(root))
                self.extension_actuals[function.key] = (actual, state.get(bindings[root], CLEAN))
                return extensions
        return []

    def call_context(self, callee, args, values, bindings, state):
        extension = self.extension_actuals.get(callee.key)
        if extension is not None:
            argument, value = extension
            args, values = [argument, *args], [value, *values]
        return super().call_context(callee, args, values, bindings, state)

    def raw_name(self, position, name):
        # The shared evaluator normalizes global:: for its legacy policies.
        return ("global::" + name) if self.code[position:position + 8] == "global::" else name

    def intrinsic_value(self, name, args, state, bindings, position):
        return api_fact("System.Type") if name == "typeof" else CLEAN

    def selected_call(self, name, args, values, receiver, bindings, position, opening, name_end):
        """Return the SQL slot only after resolving receiver, overload and mode."""
        if position in self.ambiguous_extensions:
            return None
        method = name.split(".")[-1]
        asynchronous = method.endswith("Async")
        family = method[:-5] if asynchronous else method
        if family not in STRING_METHODS and family not in {"QueryUnbuffered", "QueryMultiple"}:
            return None
        raw = self.raw_name(position, name)
        owner = self.types.resolve(raw.rsplit(".", 1)[0], position) if "." in raw else ""
        root = name.split(".")[0]
        static = owner == MAPPER and (root not in bindings or raw.startswith("global::"))
        if "." not in raw:
            static = any(item.static and self.types.resolve(item.target, item.position) == MAPPER
                         for item in self.types.visible_imports(position))
        receiver_types = identities(receiver)
        extension = root in bindings and bool(receiver_types & CONNECTIONS)
        if not static and extension and not self.types.imported("Dapper", position):
            self.incomplete(position, "Dapper extension dispatch requires a resolved Dapper import")
            return None
        if not static and not extension:
            previous = position - 1
            while previous >= 0 and self.code[previous].isspace():
                previous -= 1
            if "." not in raw and self.code[previous:previous + 1] == ".":
                self.incomplete(position, "Postfix SQL execution receiver is outside the selected model")
                return None
            if any(item.startswith("local:") for item in receiver_types) or owner.startswith("local:"):
                return None
            if "." in raw and (provenance(join(*values)) or receiver_types & {"dynamic"}):
                self.incomplete(position, "SQL execution receiver or Dapper dispatch is unresolved")
            return None
        if family in {"QueryUnbuffered", "QueryMultiple"}:
            self.incomplete(position, "Deferred or multiple-result Dapper execution is outside the selected model")
            return None
        generic = self.code[name_end:opening].strip()
        arity = len(list(parts(generic, 1, len(generic) - 1, generics=True))) if generic.startswith("<") else 0
        if arity > 1 or any("=>" in self.code[low:high] for _, low, high in args):
            self.incomplete(position, "Dapper multimapping overload is outside the selected model")
            return None
        if any(COMMAND in identities(value) for value in values) or any(key == "command" for key, _, _ in args):
            self.incomplete(position, "Dapper CommandDefinition execution is outside the selected model")
            return None
        # Positional Type is after cnn for static calls; named arguments may be
        # in any legal order, and generic string overloads have no Type slot.
        first = 1 if static else 0
        typed = any(key == "type" for key, _, _ in args)
        if not typed and arity == 0 and len(values) > first:
            typed = "System.Type" in identities(values[first]) and args[first][0] is None
        if typed and (arity or family not in {"Query", "QueryFirst", "QueryFirstOrDefault", "QuerySingle", "QuerySingleOrDefault"}):
            self.incomplete(position, "Unresolved Type-leading Dapper overload")
            return None
        formals = (["cnn"] if static else []) + (["type"] if typed else []) + ["sql", "param", "transaction"]
        if family == "Query" and not asynchronous:
            formals.append("buffered")
        formals.extend(("commandTimeout", "commandType"))
        slots = {}
        for index, (keyword, low, high) in enumerate(args):
            slot = keyword if keyword is not None else formals[index] if index < len(formals) else ""
            if slot not in formals or slot in slots:
                self.incomplete(position, "Dapper argument binding is outside the selected string overloads")
                return None
            slots[slot] = index
        if static and ("cnn" not in slots or not identities(values[slots["cnn"]]) & CONNECTIONS):
            self.incomplete(position, "Static Dapper connection argument is unresolved")
            return None
        if "sql" not in slots:
            self.incomplete(position, "Dapper SQL argument is unresolved")
            return None
        if "buffered" in slots:
            _, low, high = args[slots["buffered"]]
            if self.code[low:high].strip() != "true":
                self.incomplete(position, "Deferred or unknown Dapper buffered policy is outside the selected model")
                return None
        if "commandType" in slots:
            _, low, high = args[slots["commandType"]]
            spelling = re.sub(r"\s|@", "", self.code[low:high])
            qualifier, _, member = spelling.rpartition(".")
            literal_text = (member == "Text" and self.types.resolve(qualifier, low) == "System.Data.CommandType"
                            and (qualifier.split(".")[0] not in bindings or qualifier.startswith("global::")))
            if spelling != "null" and not literal_text:
                self.incomplete(position, "Dapper command type is outside the selected text-SQL model")
                return None
        return slots["sql"]

    def call_value(self, name, canonical_name, args, values, receiver, state,
                   bindings, position, opening, name_end):
        raw = self.raw_name(position, name)
        constructor = bool(re.search(r"\bnew\s*$", self.code[max(0, position - 12):position]))
        if constructor:
            identity = self.types.resolve(raw, position)
            if identity == COMMAND:
                self.incomplete(position, "Dapper CommandDefinition construction is outside the selected model")
            return join(api_fact(identity), provenance(join(*values)))
        method = name.split(".")[-1]
        family = method[:-5] if method.endswith("Async") else method
        if family in STRING_METHODS | {"QueryUnbuffered", "QueryMultiple"}:
            # SQL execution return values are not new request sources.
            return CLEAN
        source = self.name_value(name.rsplit(".", 1)[0], position, state, bindings) if "." in name else CLEAN
        if method in {"ToString", "ConfigureAwait", "AsString"}:
            return provenance(join(receiver, source))
        if raw in {"string.Format", "System.String.Format", "global::System.String.Format",
                   "string.Concat", "System.String.Concat", "global::System.String.Concat"}:
            return provenance(join(*values))
        if any(re.match(r"\s*(?:ref|out)\b", self.code[low:high]) for _, low, high in args):
            self.incomplete(position, "Unresolved ref/out call effects require cross-file analysis")
        elif (identities(join(receiver, *values)) & (CONNECTIONS | {REQUEST, CONTEXT})
              or any(trace.kind == "source" for trace in join(receiver, *values))):
            self.incomplete(position, "Unresolved external call effects require cross-file analysis")
        return provenance(join(receiver, source, *values))

    def call_sink_facts(self, name, canonical_name, args, values, receiver, state,
                        bindings, position, opening, name_end):
        index = self.selected_call(name, args, values, receiver, bindings, position, opening, name_end)
        return [(index, provenance(values[index]))] if index is not None else []

    def analyze_function(self, function, context):
        self.current_issues = set()
        self.ambiguous_extensions = set()
        try:
            return super().analyze_function(function, context)
        finally:
            # A helper return may be unresolved in an early fixpoint pass. Only
            # the latest evaluated context determines its completeness status.
            self.context_issues[context] = self.current_issues

    def retained_findings(self):
        effects = dict(self.effects)
        for summary in self.summaries.values():
            for key, value in summary.effects.items():
                effects[key] = join(effects.get(key, CLEAN), value)
        for (offset, sink), value in sorted(effects.items()):
            fact = frozenset(trace for trace in value if trace.kind == "source")
            if not fact:
                continue
            location = self.step(offset, "sink", sink)
            witnesses = sorted(fact, key=lambda trace: (len(trace.evidence), trace.evidence, trace.key))
            yield {"rule": RULE, "path": str(self.path), "line": location.line, "col": location.column,
                   "severity": "critical", "message": MESSAGE,
                   "extras": {"taint_path": [step.record() for step in witnesses[0].evidence],
                              "source_count": len({trace.key for trace in fact})}}

    def analyze(self):
        emitted = set()
        try:
            for finding in super().analyze():
                emitted.add((finding["line"], finding["col"]))
                yield finding
        except (ValueError, RecursionError) as exc:
            for finding in self.retained_findings():
                if (finding["line"], finding["col"]) not in emitted:
                    emitted.add((finding["line"], finding["col"]))
                    yield finding
            if isinstance(exc, RecursionError):
                raise AnalysisLimit("C# SQL recursion limit exceeded; analysis is incomplete") from exc
            raise
        issues = sorted(set().union(*self.context_issues.values())) if self.context_issues else []
        if issues:
            raise ValueError("C# SQL analysis is incomplete: " + "; ".join(issues[:12]))


def scan_file_findings(path: Path) -> Iterable[dict]:
    text = path.read_text(encoding="utf-8-sig")
    # Unrelated ASP.NET calls cannot create SQL effects when there is no SQL
    # execution demand. The second pass excludes comment/string decoys while
    # retaining executable interpolation holes and every selected call family.
    if not SQL_CALL.search(text) or not SQL_CALL.search(masked_source(text)):
        return
    limits = policy_limits()
    suppressions = SourceSuppressions("csharp")
    try:
        flow = DapperFlow(path, text, limits)
    except RecursionError as exc:
        raise AnalysisLimit("C# SQL parser recursion limit exceeded; analysis is incomplete") from exc
    for finding in flow.analyze():
        if not suppressions.is_suppressed(path, finding["line"], RULE):
            finding.update(category=8, category_id="csharp.security", layer="taint", language="csharp")
            yield finding


def run(ctx: RunContext) -> Iterable[dict]:
    if not ctx.rule_enabled(RULE):
        return
    for path in ctx.files:
        if path.suffix.lower() in {".cs", ".csx"}:
            yield from scan_file_findings(path)


register(Analyzer(layer="taint", lang="csharp", name="taint_csharp_sql", run=run, selftests=()))
