"""Bounded native Kotlin coroutine context and job-obligation analysis.

The supported API identities are explicit kotlinx.coroutines imports/aliases,
their qualified names, and JVM Thread.sleep. Local declarations and parameters
take precedence over imports. Coroutine builders establish suspend contexts;
ordinary nested functions and deferred lambdas do not inherit them. An explicit
IO dispatcher is inherited by structured children, but not GlobalScope children.

Only selected CancellationException handlers and known GlobalScope acquisitions
carry obligations. Branches preserve separate rethrow/ownership outcomes, and
aliases refer to lexical bindings rather than variable spellings. Passing or
returning a job transfers its ownership beyond this local analysis. Arbitrary
catch(Exception), custom blocking APIs, cross-file types and virtual calls are
outside this family. Unsupported control flow inside a selected obligation,
malformed source and exhausted budgets report incomplete analysis.

API contracts: kotlinlang.org/docs/coroutines-basics.html and
kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/
(-global-scope/, -dispatchers/-i-o.html, launch.html).
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable

from ubs_core.analyzers.taint_java_traversal import lexical_source
from ubs_core.io import line_col
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit


TOKEN_RE = re.compile(r"`[^`\r\n]+`|[A-Za-z_]\w*|\d+(?:\.\d+)?|!!|\?\.|::|->|===|!==|==|!=|<=|>=|&&|\|\||\S")
LIMIT_DEFAULTS = {"UBS_KOTLIN_MAX_TOKENS": 100_000, "UBS_KOTLIN_MAX_NESTING": 192}
COROUTINES = "kotlinx.coroutines."
CANCELLATION_TYPES = frozenset({
    COROUTINES + "CancellationException", "java.util.concurrent.CancellationException",
    "kotlin.coroutines.cancellation.CancellationException",
})
BUILDERS = frozenset({"launch", "async", "withContext", "coroutineScope", "supervisorScope", "runBlocking"})
JOB_IDENTITY_CALLS = frozenset({"kotlin.checkNotNull", "kotlin.requireNotNull"})
JOB_DISCARD_CALLS = frozenset({"kotlin.io.print", "kotlin.io.println"})
RULE_MESSAGES = {
    "swallowed-cancellation": "Selected CancellationException can leave this handler without propagating cancellation; rethrow it on every path",
    "blocking-call": "Thread.sleep blocks a coroutine thread; use delay or an explicit Dispatchers.IO context for blocking work",
    "unowned-job": "GlobalScope coroutine has no structured parent and its Job is discarded or left unobserved on a local path; join, cancel, or transfer ownership",
}


def _limit(name: str) -> int:
    raw = os.environ.get(name, str(LIMIT_DEFAULTS[name]))
    try:
        value = int(raw)
    except ValueError as exc:
        raise AnalysisLimit(f"{name} must be a positive integer; Kotlin analysis is incomplete") from exc
    if value <= 0:
        raise AnalysisLimit(f"{name} must be a positive integer; Kotlin analysis is incomplete")
    return value


def mask_non_code(text: str) -> str:
    """Reuse the shared JVM lexer, including executable Kotlin string holes."""
    return lexical_source(text, True)


def delimiter_pairs(code: str) -> dict[int, int]:
    """Map opening offsets to closing offsets, rejecting malformed/big input."""
    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    token_limit, nesting_limit = _limit("UBS_KOTLIN_MAX_TOKENS"), _limit("UBS_KOTLIN_MAX_NESTING")
    for count, token in enumerate(TOKEN_RE.finditer(code), 1):
        if count > token_limit:
            raise AnalysisLimit("Kotlin token budget exceeded; analysis is incomplete")
        value = token.group()
        if value == "`":
            raise ValueError("Unterminated Kotlin escaped identifier; analysis is incomplete")
        if value in ("(", "[", "{"):
            stack.append((value, token.start()))
            if len(stack) > nesting_limit:
                raise AnalysisLimit("Kotlin nesting budget exceeded; analysis is incomplete")
        elif value in (")", "]", "}"):
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[value]:
                raise ValueError("Unbalanced Kotlin source; analysis is incomplete")
            _, opening = stack.pop()
            pairs[opening] = token.start()
    if stack:
        raise ValueError("Unbalanced Kotlin source; analysis is incomplete")
    return pairs


@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class Function:
    declaration: int
    name: int
    parameters: int
    start: int
    end: int
    suspend: bool
    expression: bool
    receiver: str


@dataclass(frozen=True)
class Binding:
    name: str
    declaration: int
    low: int
    high: int
    type_name: str = ""


@dataclass(frozen=True)
class Call:
    start: int
    name: int
    arguments: int | None
    block: int | None
    end: int


@dataclass(frozen=True)
class Context:
    suspend: bool = False
    io: bool = False
    receiver: bool = False


@dataclass(frozen=True)
class Statement:
    start: int
    end: int
    kind: str = "simple"
    body: tuple = ()
    otherwise: tuple = ()


class KotlinCoroutines:
    def __init__(self, text: str):
        self.text, self.code = text, mask_non_code(text)
        offsets = delimiter_pairs(self.code)
        self.tokens = [Token(m.group().strip("`"), m.start(), m.end()) for m in TOKEN_RE.finditer(self.code)]
        positions = {token.start: index for index, token in enumerate(self.tokens)}
        self.pairs = {positions[low]: positions[high] for low, high in offsets.items()}
        self.reverse = {high: low for low, high in self.pairs.items()}
        self.work = _limit("UBS_KOTLIN_MAX_TOKENS") * 32
        self.scopes: dict[int, int] = {-1: len(self.tokens)}
        self.parents: dict[int, int] = {}
        self.scope_at: list[int] = []
        stack = [-1]
        for index, token in enumerate(self.tokens):
            self.scope_at.append(stack[-1])
            if token.value == "{":
                self.scopes[index] = self.pairs[index]
                self.parents[index] = stack[-1]
                stack.append(index)
            elif token.value == "}":
                stack.pop()
        self.imports: dict[str, str] = {}
        self.wildcards: set[str] = set()
        for match in re.finditer(r"(?m)^\s*import\s+([A-Za-z_][\w.]*(?:\*)?)(?:\s+as\s+([A-Za-z_]\w*))?", self.code):
            qualified, alias = match.groups()
            if qualified.endswith(".*"):
                self.wildcards.add(qualified[:-2])
            else:
                self.imports[alias or qualified.rsplit(".", 1)[-1]] = qualified
        self.functions = self._functions()
        self.function_bodies = {fn.start: fn for fn in self.functions if not fn.expression}
        self.function_names = {fn.name for fn in self.functions}
        self.classes: set[int] = set()
        self.bindings: dict[str, list[Binding]] = {}
        self._collect_bindings()
        self.calls: list[Call] = []
        self.lambda_calls: dict[int, Call] = {}
        for index, token in enumerate(self.tokens):
            if not self.identifier(index) or index in self.function_names:
                continue
            following = self.value(index + 1)
            if following not in ("(", "{"):
                continue
            if token.value in {"if", "for", "while", "when", "catch", "fun", "synchronized", "try", "else", "finally", "do"}:
                continue
            start = self.path_start(index)
            arguments = index + 1 if following == "(" else None
            after = self.pairs[arguments] + 1 if arguments is not None else index + 1
            block = after if self.value(after) == "{" and after not in self.function_bodies and after not in self.classes else None
            end = self.pairs[block] + 1 if block is not None else after
            call = Call(start, index, arguments, block, end)
            self.calls.append(call)
            if block is not None:
                self.lambda_calls[block] = call

    def spend(self) -> None:
        self.work -= 1
        if self.work < 0:
            raise AnalysisLimit("Kotlin coroutine flow budget exceeded; analysis is incomplete")

    def value(self, index: int) -> str:
        return self.tokens[index].value if 0 <= index < len(self.tokens) else ""

    def identifier(self, index: int) -> bool:
        return bool(re.fullmatch(r"[A-Za-z_]\w*", self.value(index)))

    def path_start(self, index: int) -> int:
        while index >= 2 and self.value(index - 1) == "." and self.identifier(index - 2):
            index -= 2
        return index

    def path(self, start: int, end: int) -> str:
        return "".join(token.value for token in self.tokens[start:end])

    def parts(self, start: int, end: int):
        low, index = start, start
        while index < end:
            if index in self.pairs:
                index = self.pairs[index]
            elif self.value(index) == ",":
                yield low, index
                low = index + 1
            index += 1
        if low < end:
            yield low, end

    def simple_end(self, start: int, end: int) -> int:
        index = start
        continuation = {".", "?.", "=", "+", "-", "*", "/", "&&", "||", "?:", ",", ":", "->"}
        while index < end:
            self.spend()
            if self.value(index) in (";", "}") or (index > start and self.value(index) == "else"):
                return index
            if index > start:
                gap = self.code[self.tokens[index - 1].end:self.tokens[index].start]
                if "\n" in gap and self.value(index - 1) not in continuation and self.value(index) not in continuation | {"(", "{"}:
                    return index
            if index in self.pairs:
                index = self.pairs[index]
            index += 1
        return end

    def _functions(self) -> list[Function]:
        result = []
        for declaration, token in enumerate(self.tokens):
            if token.value != "fun":
                continue
            opening = declaration + 1
            while opening < len(self.tokens) and self.value(opening) not in ("(", "{", "}", "=", ";"):
                opening += 1
            if self.value(opening) != "(":
                continue
            name = opening - 1 if self.identifier(opening - 1) else declaration
            following = self.pairs[opening] + 1
            if self.value(following) == ":":
                following += 1
                while following < len(self.tokens) and self.value(following) not in ("{", "=", ";", "}", "fun", "val", "var", "class"):
                    following += 1
            if self.value(following) not in ("{", "="):
                continue
            expression = self.value(following) == "="
            start = following + 1 if expression else following
            end = self.simple_end(start, len(self.tokens)) if expression else self.pairs[start] + 1
            receiver = self.path(declaration + 1, name - 1) if self.value(name - 1) == "." else ""
            prefix = declaration - 1
            modifiers = {"suspend", "public", "private", "internal", "protected", "inline", "tailrec", "override", "open", "final", "operator", "infix"}
            while prefix >= 0 and self.value(prefix) in modifiers:
                prefix -= 1
            suspend = any(self.value(i) == "suspend" for i in range(prefix + 1, declaration))
            result.append(Function(declaration, name, opening, start, end, suspend, expression, receiver))
        return result

    def add_binding(self, name: str, declaration: int, low: int, high: int, type_name: str = "") -> None:
        self.bindings.setdefault(name, []).append(Binding(name, declaration, low, high, type_name))

    def _collect_bindings(self) -> None:
        for fn in self.functions:
            scope = self.scope_at[fn.declaration]
            if fn.name != fn.declaration:
                self.add_binding(self.value(fn.name), fn.name, scope, self.scopes[scope])
            for low, high in self.parts(fn.parameters + 1, self.pairs[fn.parameters]):
                for index in range(low, high - 1):
                    if self.identifier(index) and self.value(index + 1) == ":":
                        finish = next((i for i in range(index + 2, high) if self.value(i) == "="), high)
                        self.add_binding(self.value(index), index, fn.start, fn.end, self.path(index + 2, finish))
                        break
        constructor_parameters: set[int] = set()
        for index, token in enumerate(self.tokens):
            scope = self.scope_at[index]
            if token.value in {"class", "object", "interface", "typealias"} and self.identifier(index + 1):
                self.add_binding(self.value(index + 1), index + 1, scope, self.scopes[scope])
                cursor = index + 2
                parameters = None
                while cursor < self.scopes[scope] and self.value(cursor) not in ("{", ";", "=", "}", "fun", "val", "var"):
                    if cursor in self.pairs:
                        if self.value(cursor) == "(" and parameters is None:
                            parameters = cursor
                        cursor = self.pairs[cursor]
                    cursor += 1
                if self.value(cursor) == "{":
                    self.classes.add(cursor)
                if parameters is not None:
                    for low, high in self.parts(parameters + 1, self.pairs[parameters]):
                        parameter = next((i for i in range(low, high) if self.value(i) in {"val", "var"}), None)
                        if parameter is not None and self.identifier(parameter + 1) and self.value(parameter + 2) == ":":
                            constructor_parameters.add(parameter)
                            if self.value(cursor) == "{":
                                finish = next((i for i in range(parameter + 3, high) if self.value(i) == "="), high)
                                self.add_binding(self.value(parameter + 1), parameter + 1, cursor, self.pairs[cursor] + 1,
                                                 self.path(parameter + 3, finish))
            elif token.value in {"val", "var"} and self.identifier(index + 1) and index not in constructor_parameters:
                cursor, type_name = index + 2, ""
                if self.value(cursor) == ":":
                    finish = cursor + 1
                    while finish < len(self.tokens) and self.value(finish) not in ("=", ",", ";", "}", ")"):
                        finish += 1
                    type_name = self.path(cursor + 1, finish)
                    cursor = finish
                if not type_name and self.value(cursor) == "=":
                    finish = cursor + 1
                    while self.identifier(finish) and self.value(finish + 1) == ".":
                        finish += 2
                    if self.identifier(finish) and self.value(finish + 1) == "(":
                        type_name = self.path(cursor + 1, finish + 1)
                low = scope if scope < 0 or scope in self.classes else index + 1
                self.add_binding(self.value(index + 1), index + 1, low, self.scopes[scope], type_name)
            elif token.value == "catch" and self.value(index + 1) == "(":
                closing = self.pairs[index + 1]
                if self.identifier(index + 2) and self.value(index + 3) == ":" and self.value(closing + 1) == "{":
                    self.add_binding(self.value(index + 2), index + 2, closing + 1, self.pairs[closing + 1] + 1,
                                     self.path(index + 4, closing))
        # Explicit lambda parameters shadow imported APIs inside the lambda.
        for opening, closing in self.scopes.items():
            if opening < 0 or opening in self.function_bodies or opening in self.classes:
                continue
            index = opening + 1
            while index < closing and self.value(index) not in ("->", ";", "{", "}", "("):
                if index > opening + 1 and "\n" in self.code[self.tokens[index - 1].end:self.tokens[index].start]:
                    break
                index += 1
            if self.value(index) == "->":
                for low, high in self.parts(opening + 1, index):
                    if self.identifier(low):
                        type_name = self.path(low + 2, high) if self.value(low + 1) == ":" else ""
                        self.add_binding(self.value(low), low, opening, closing + 1, type_name)

    def binding(self, name: str, position: int) -> Binding | None:
        candidates = [binding for binding in self.bindings.get(name, ()) if binding.low <= position < binding.high]
        return max(candidates, key=lambda binding: (binding.low, binding.declaration), default=None)

    def canonical(self, name: str, position: int) -> str:
        parts = name.split(".")
        if not parts or self.binding(parts[0], position) is not None:
            return ""
        if parts[0] in self.imports:
            return ".".join([self.imports[parts[0]], *parts[1:]])
        if parts[0] in {"java", "kotlin", "kotlinx"} and len(parts) > 1:
            return name
        known = {
            "kotlinx.coroutines": BUILDERS | {"CoroutineScope", "CancellationException", "GlobalScope", "Dispatchers", "Job", "NonCancellable", "cancelAndJoin"},
            "kotlin": {"checkNotNull", "requireNotNull"},
            "kotlin.io": {"print", "println"},
            "java.util.concurrent": {"CancellationException"},
            "kotlin.coroutines.cancellation": {"CancellationException"},
            "java.lang": {"Thread"},
        }
        matches = [package + "." + name for package in self.wildcards if parts[0] in known.get(package, ())]
        unknown_wildcards = self.wildcards - set(known)
        if len(matches) == 1 and not unknown_wildcards:
            return matches[0]
        if not matches and not unknown_wildcards and parts[0] == "Thread":
            return "java.lang." + name
        defaults = {"print": "kotlin.io.print", "println": "kotlin.io.println",
                    "checkNotNull": "kotlin.checkNotNull", "requireNotNull": "kotlin.requireNotNull"}
        if not matches and not unknown_wildcards and name in defaults:
            return defaults[name]
        return ""

    def scope_receiver(self, name: str, position: int, implicit: bool) -> bool:
        if name == "this":
            return implicit
        if self.canonical(name, position) == COROUTINES + "GlobalScope":
            return True
        binding = self.binding(name, position)
        return binding is not None and self.canonical(binding.type_name.rstrip("?"), binding.declaration) == COROUTINES + "CoroutineScope"

    def builder(self, call: Call, implicit: bool) -> str:
        name = self.path(call.start, call.name + 1)
        canonical = self.canonical(name, call.start)
        if canonical in {COROUTINES + value for value in BUILDERS - {"launch", "async"}}:
            return canonical.rsplit(".", 1)[-1]
        method = self.canonical(self.value(call.name), call.name)
        if method not in {COROUTINES + "launch", COROUTINES + "async"}:
            return ""
        receiver = self.path(call.start, call.name - 1) if call.start < call.name else ""
        if (not receiver and implicit) or (receiver and self.scope_receiver(receiver, call.start, implicit)):
            return method.rsplit(".", 1)[-1]
        return ""

    def dispatch_io(self, call: Call, inherited: bool) -> bool:
        if call.arguments is None or self.pairs[call.arguments] == call.arguments + 1:
            return inherited
        low, high = next(self.parts(call.arguments + 1, self.pairs[call.arguments]))
        if self.value(low) == "context" and self.value(low + 1) == "=":
            low += 2
        canonical = self.canonical(self.path(low, high), low)
        if canonical == COROUTINES + "Dispatchers.IO":
            return True
        if canonical == COROUTINES + "NonCancellable":
            return inherited
        return False

    def context(self, position: int) -> Context:
        scopes, scope = [], self.scope_at[position]
        while scope >= 0:
            scopes.append(scope)
            scope = self.parents[scope]
        events = [(opening, "scope", opening) for opening in reversed(scopes)]
        events.extend((fn.start, "expression", fn) for fn in self.functions
                      if fn.expression and fn.start <= position < fn.end)
        context = Context()
        for _, kind, item in sorted(events, key=lambda event: event[0]):
            self.spend()
            if kind == "expression":
                fn = item
                context = Context(fn.suspend, False, context.receiver or self.canonical(fn.receiver, fn.declaration) == COROUTINES + "CoroutineScope")
                continue
            opening = item
            if opening in self.function_bodies:
                fn = self.function_bodies[opening]
                context = Context(fn.suspend, False, context.receiver or self.canonical(fn.receiver, fn.declaration) == COROUTINES + "CoroutineScope")
            elif opening in self.classes:
                context = Context()
            elif opening in self.lambda_calls:
                call = self.lambda_calls[opening]
                builder = self.builder(call, context.receiver)
                if builder:
                    receiver = self.path(call.start, call.name - 1) if call.start < call.name else ""
                    detached = self.canonical(receiver, call.start) == COROUTINES + "GlobalScope"
                    inherited = context.io if builder != "runBlocking" and not detached else False
                    context = Context(True, self.dispatch_io(call, inherited), True)
                else:
                    context = Context()
            else:
                preceding = self.value(opening - 1)
                header = self.value(self.reverse.get(opening - 1, -2) - 1) if preceding == ")" else preceding
                if header not in {"if", "else", "for", "while", "do", "try", "catch", "finally", "when", "synchronized"}:
                    context = Context()
        return context

    def statements(self, start: int, end: int) -> tuple[Statement, ...]:
        result = []
        while start < end:
            self.spend()
            if self.value(start) == ";":
                start += 1
                continue
            statement = self.statement(start, end)
            if statement.end <= start:
                raise ValueError("Kotlin coroutine parser made no progress; analysis is incomplete")
            result.append(statement)
            start = statement.end
        return tuple(result)

    def statement(self, start: int, end: int) -> Statement:
        value = self.value(start)
        if value == "{":
            closing = self.pairs[start]
            return Statement(start, closing + 1, "block", self.statements(start + 1, closing))
        if value in {"if", "while", "for"} and self.value(start + 1) == "(":
            following = self.pairs[start + 1] + 1
            body = self.statement(following, end)
            finish, alternate = body.end, ()
            if value == "if" and self.value(finish) == "else":
                other = self.statement(finish + 1, end)
                finish, alternate = other.end, (other,)
            return Statement(start, finish, "if" if value == "if" else "loop", (body,), alternate)
        if value in {"when", "try", "do"}:
            raise ValueError(f"Kotlin selected coroutine obligation uses unsupported {value} flow; analysis is incomplete")
        fn = next((fn for fn in self.functions if fn.declaration == start or
                   (value == "suspend" and fn.declaration == start + 1)), None)
        if fn is not None:
            return Statement(start, fn.end, "declaration")
        return Statement(start, self.simple_end(start, end))

    def alias_key(self, position: int) -> int | None:
        binding = self.binding(self.value(position), position)
        return binding.declaration if binding is not None else None

    def plain_alias(self, start: int, end: int, aliases: frozenset[int]) -> bool:
        while self.value(start) == "(" and self.pairs.get(start) == end - 1:
            start, end = start + 1, end - 1
        for call in self.calls:
            self.spend()
            if call.start != start or call.end != end or call.arguments is None:
                continue
            if self.canonical(self.path(call.start, call.name + 1), call.start) in JOB_IDENTITY_CALLS:
                arguments = list(self.parts(call.arguments + 1, self.pairs[call.arguments]))
                if arguments:
                    low, high = arguments[0]
                    if self.value(low) == "value" and self.value(low + 1) == "=":
                        low += 2
                    return self.plain_alias(low, high, aliases)
        return end == start + 1 and self.alias_key(start) in aliases

    def job_argument_effect(self, position: int) -> str:
        """Follow actual enclosing calls, separating inspection from handoff.

        Parentheses alone cannot transfer ownership. Null checks return the
        same handle, while printing consumes its representation. A deliberate
        call outside these known builtins retains the local handoff contract.
        """
        calls = []
        for call in self.calls:
            self.spend()
            if (call.arguments is not None and call.arguments < position < self.pairs[call.arguments]
                    and self.value(call.name) not in {"return", "throw", "break", "continue"}):
                calls.append(call)
        calls.sort(key=lambda call: call.arguments, reverse=True)
        effect = "none"
        for call in calls:
            canonical = self.canonical(self.path(call.start, call.name + 1), call.start)
            if canonical in JOB_DISCARD_CALLS:
                return "discard"
            if canonical in JOB_IDENTITY_CALLS:
                effect = "identity"
                continue
            return "transfer"
        return effect

    def flow(self, statements: tuple[Statement, ...], states: set[tuple[str, frozenset[int]]], kind: str) -> set[tuple[str, frozenset[int]]]:
        for statement in statements:
            self.spend()
            updated: set[tuple[str, frozenset[int]]] = set()
            for status, aliases in states:
                if status != "live":
                    updated.add((status, aliases))
                elif statement.kind in {"if", "loop"}:
                    branch = self.flow(statement.body, {("live", aliases)}, kind)
                    other = self.flow(statement.otherwise, {("live", aliases)}, kind) if statement.otherwise else {("live", aliases)}
                    updated.update(branch | other)
                elif statement.kind == "block":
                    updated.update(self.flow(statement.body, {("live", aliases)}, kind))
                elif statement.kind == "declaration":
                    updated.add((status, aliases))
                else:
                    updated.add(self.simple_flow(statement, aliases, kind))
            states = updated
            if len(states) > 128:
                raise AnalysisLimit("Kotlin coroutine branch-state budget exceeded; analysis is incomplete")
        return states

    def simple_flow(self, statement: Statement, aliases: frozenset[int], kind: str) -> tuple[str, frozenset[int]]:
        start, end = statement.start, statement.end
        leading = self.value(start)
        if kind == "job" and self.job_observed(start, end, aliases):
            return "done", aliases
        if leading in {"return", "throw", "break", "continue"}:
            if kind == "cancellation":
                preserved = leading == "throw" and self.plain_alias(start + 1, end, aliases)
            else:
                preserved = leading == "return" and self.plain_alias(start + 1, end, aliases)
            return ("done" if preserved else "lost", aliases)
        # Resolve declarations and assignments by binding identity. A nested
        # declaration with the same spelling cannot change an outer alias.
        assignment = start + 2 if leading in {"val", "var"} else start + 1
        if leading in {"val", "var"}:
            while assignment < end and self.value(assignment) not in {"=", ";"}:
                assignment += 1
        if self.value(assignment) == "=":
            target = start + 1 if leading in {"val", "var"} else start
            key = self.alias_key(target)
            if key is not None:
                replacement = set(aliases)
                replacement.discard(key)
                if self.plain_alias(assignment + 1, end, aliases):
                    replacement.add(key)
                return "live", frozenset(replacement)
        return "live", aliases

    def job_observed(self, start: int, end: int, aliases: frozenset[int]) -> bool:
        index = start
        while index < end:
            if self.value(index) == "{":
                index = self.pairs[index] + 1
                continue
            if (self.value(index) == "="
                    and re.fullmatch(r"(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*", self.path(start, index))
                    and self.plain_alias(index + 1, end, aliases)):
                return True
            if self.alias_key(index) in aliases:
                if self.value(index + 1) == "." and self.value(index + 3) == "(":
                    method = self.value(index + 2)
                    if method in {"join", "cancel", "await"} or (
                        self.canonical(method, index + 2) == COROUTINES + "cancelAndJoin"
                    ):
                        return True
                # Passing the handle (also inside an assigned/returned call)
                # transfers it beyond this local ownership domain. Reading a
                # property such as logger.info(job.isActive) does not.
                if self.value(index + 1) in {",", ")"} and self.value(index - 1) in {"(", ",", "="}:
                    if self.job_argument_effect(index) == "transfer":
                        return True
                if index == end - 1 and self.value(index - 1) == "=" and any(self.value(i) == "." for i in range(start, index - 1)):
                    return True
            index += 1
        return False

    def cancellation_findings(self):
        for index, token in enumerate(self.tokens):
            if token.value != "catch" or self.value(index + 1) != "(" or not self.context(index).suspend:
                continue
            closing = self.pairs[index + 1]
            if not self.identifier(index + 2) or self.value(index + 3) != ":" or self.value(closing + 1) != "{":
                raise ValueError("Unsupported Kotlin catch parameter; analysis is incomplete")
            type_name = self.path(index + 4, closing)
            if self.canonical(type_name, index) not in CANCELLATION_TYPES:
                continue
            opening = closing + 1
            states = self.flow(self.statements(opening + 1, self.pairs[opening]), {("live", frozenset({index + 2}))}, "cancellation")
            if any(status != "done" for status, _ in states):
                yield "swallowed-cancellation", token.start

    def blocking_findings(self):
        for call in self.calls:
            if call.arguments is None:
                continue
            name = self.path(call.start, call.name + 1)
            if self.canonical(name, call.start) != "java.lang.Thread.sleep":
                continue
            context = self.context(call.start)
            if context.suspend and not context.io:
                yield "blocking-call", self.tokens[call.start].start

    def statement_start(self, position: int, scope: int) -> int:
        start, index = scope + 1, scope + 1
        continuation = {".", "?.", "=", "+", "-", "*", "/", "&&", "||", "?:", ",", ":", "->"}
        while index < position:
            if self.value(index) == ";":
                start = index + 1
            elif index > start and "\n" in self.code[self.tokens[index - 1].end:self.tokens[index].start] and self.value(index - 1) not in continuation and self.value(index) not in continuation | {"(", "{"}:
                start = index
            if index in self.pairs and self.pairs[index] < position:
                index = self.pairs[index]
            index += 1
        if position > start and "\n" in self.code[self.tokens[position - 1].end:self.tokens[position].start] and self.value(position - 1) not in continuation:
            start = position
        return start

    def job_findings(self):
        for call in self.calls:
            if call.block is None or self.builder(call, self.context(call.start).receiver) not in {"launch", "async"}:
                continue
            receiver = self.path(call.start, call.name - 1) if call.start < call.name else ""
            if self.canonical(receiver, call.start) != COROUTINES + "GlobalScope":
                continue
            # A supplied context may contain a parent Job. Diagnose only an
            # absent context or a known dispatcher, whose missing parent is
            # established without guessing arbitrary context expressions.
            if call.arguments is not None and self.pairs[call.arguments] > call.arguments + 1:
                low, high = next(self.parts(call.arguments + 1, self.pairs[call.arguments]))
                if self.value(low) == "context" and self.value(low + 1) == "=":
                    low += 2
                if self.canonical(self.path(low, high), low) not in {COROUTINES + "Dispatchers." + name for name in ("IO", "Default", "Main", "Unconfined")}:
                    continue
            scope = self.scope_at[call.start]
            if any(fn.expression and fn.start <= call.start < fn.end and self.scope_at[fn.start] == scope for fn in self.functions):
                continue
            start = self.statement_start(call.start, scope)
            end = self.simple_end(start, self.scopes[scope])
            prefix = [self.value(i) for i in range(start, call.start)]
            # Argument positions and explicit return/property assignments are
            # transfers; they are not automatically leaks on function escape.
            argument_effect = self.job_argument_effect(call.start)
            if argument_effect == "discard":
                yield "unowned-job", self.tokens[call.start].start
                continue
            if argument_effect == "transfer" or "return" in prefix:
                continue
            if call.end < end:
                if self.value(call.end) in {".", "?."}:
                    method = self.value(call.end + 1)
                    observed = method in {"join", "cancel", "await"} or self.canonical(method, call.end + 1) == COROUTINES + "cancelAndJoin"
                    if observed and self.value(call.end + 2) == "(":
                        continue
                    if method in {"toString", "hashCode", "equals", "start", "isActive", "isCompleted", "isCancelled", "getCancellationException", "invokeOnCompletion", "children", "key"}:
                        yield "unowned-job", self.tokens[call.start].start
                        continue
                    raise ValueError(f"Unsupported Kotlin Job receiver operation {method!r}; analysis is incomplete")
            if prefix and "=" in prefix:
                if prefix[0] not in {"val", "var"} or len(prefix) < 3:
                    continue
                if scope < 0 or scope in self.classes:
                    continue
                key = self.alias_key(start + 1)
                if key is None:
                    raise ValueError("Unsupported Kotlin Job binding; analysis is incomplete")
                states = self.flow(self.statements(end, self.scopes[scope]), {("live", frozenset({key}))}, "job")
                unowned = any(status != "done" for status, _ in states)
            elif prefix and argument_effect == "identity":
                unowned = True
            elif prefix:
                continue
            else:
                owner = self.lambda_calls.get(scope)
                returned_by_lambda = owner is not None and self.builder(owner, self.context(owner.start).receiver) != "launch" and end == self.scopes[scope]
                unowned = not returned_by_lambda
            if unowned:
                yield "unowned-job", self.tokens[call.start].start

    def findings(self):
        yield from self.cancellation_findings()
        yield from self.blocking_findings()
        yield from self.job_findings()


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    analysis = KotlinCoroutines(text)
    findings = []
    for kind, position in analysis.findings():
        line, column = line_col(text, position)
        findings.append((kind, line, column, RULE_MESSAGES[kind]))
    return sorted(set(findings), key=lambda finding: (finding[1], finding[2], finding[0]))


def run(ctx: RunContext) -> Iterable[dict]:
    suppressions = SourceSuppressions("kotlin")
    for path in ctx.files:
        if path.suffix.lower() not in {".kt", ".kts"}:
            continue
        text = path.read_text(encoding="utf-8")
        suppressions.index(path, text)
        for kind, line, column, message in scan_text(text):
            rule = "kotlin.coroutine." + kind
            if not ctx.rule_enabled(rule) or suppressions.is_suppressed(path, line, rule):
                continue
            yield {"rule": rule, "path": str(path.resolve()), "line": line, "col": column,
                   "layer": "lifecycle", "lang": "kotlin", "category_id": "kotlin.concurrency",
                   "severity": "warning", "message": message}


register(Analyzer(layer="lifecycle", lang="kotlin", name="coroutines_kotlin", run=run))
