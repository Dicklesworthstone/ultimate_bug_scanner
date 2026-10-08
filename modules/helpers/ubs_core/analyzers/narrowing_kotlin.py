"""Binding-sensitive Kotlin null flow with bounded, explicit failure modes.

Track values, aliases, branches, short circuits, local assignments and actual
abrupt exits. A nullable annotation alone does not justify an assertion alert:
the value needs a selected guard, safe cast, nullable Elvis result, or explicit
null origin. Known non-null values, including println's Unit, stay clean.

The JVM parser supplies statement structure and executable string interpolation;
the native coroutine frontend supplies bounded tokens and lexical bindings.
Deferred functions are analyzed independently. Unknown callback/control-flow
semantics affecting selected assertions report incomplete analysis rather than
pretending that a nested return or an unsupported branch proves non-nullness.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field, replace
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.analyzers.coroutines_kotlin import KotlinCoroutines
from ubs_core.analyzers.taint_java_traversal import Parser, Statement
from ubs_core.io import line_col
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit

SKIP_DIRS = {".git", "build", "out", "dist", "target", ".gradle", ".idea", "node_modules"}
NULL, NONNULL, MAYBE = 1, 2, 3
MESSAGES = {
    "negative_guard": "{name}!! after non-exiting null guard",
    "positive_guard": "{name}!! used after '!= null' guard without exit",
    "safecall_guard": "{name}!! used after ?. guard without exit",
    "smart_cast": "{name} forced (!!) after as? smart cast",
    "elvis_force": "{name} assigned via Elvis operator but later forced with !!",
    "nullable_value": "{name}!! may dereference an explicitly nullable value",
}


@dataclass(frozen=True)
class Value:
    nulls: int = MAYBE
    origins: frozenset[str] = frozenset()
    nullable: bool = False
    type_name: str = ""


UNKNOWN = Value()
UNIT = Value(NONNULL, type_name="Unit")


@dataclass
class State:
    values: dict[int, Value] = field(default_factory=dict)
    aliases: dict[int, frozenset[int]] = field(default_factory=dict)
    exit: str = ""
    result: Value = UNIT

    def copy(self):
        return State(dict(self.values), dict(self.aliases), self.exit, self.result)

    def signature(self):
        return (tuple(sorted(self.values.items())), tuple(sorted(self.aliases.items())), self.exit, self.result)


class NullParser(Parser):
    """Reuse the JVM statement parser without its taint-specific assumptions."""

    def __init__(self, model: KotlinCoroutines):
        self.model = model
        self.text, self.code, self.kotlin = model.text, model.code, True
        self.pairs = {model.tokens[low].start: model.tokens[high].start for low, high in model.pairs.items()}
        self.definitions = {model.tokens[fn.declaration].start: fn for fn in model.functions}

    def end_statement(self, start, end):
        index = start
        while index < end:
            self.model.spend()
            char = self.code[index]
            if char in ";}":
                return index
            if re.match(r"else\b", self.code[index:end]) and (index == 0 or not self.code[index - 1].isalnum()):
                return index
            if char in "\r\n":
                before, after = self.code[start:index].rstrip(), self.code[index:end].lstrip()
                if not before.endswith(("=", ".", "?.", "?:", ",", "&&", "||", "+", "-", "->")) and not after.startswith((".", "?.", "?:", "&&", "||")):
                    return index
            if index in self.pairs:
                index = self.pairs[index]
            index += 1
        return end

    def statement(self, start, end):
        definition = re.match(r"(?:(?:suspend|inline|tailrec|public|private|internal|override|operator|infix)\s+)*fun\b", self.code[start:end])
        if definition:
            declaration = start + definition.group().rfind("fun")
            fn = self.definitions.get(declaration)
            if fn is None:
                raise ValueError("Unsupported Kotlin function declaration; null analysis is incomplete")
            finish = self.model.tokens[fn.end - 1].end if fn.end else end
            return Statement(start, finish, "definition"), finish
        if re.match(r"try\b", self.code[start:end]):
            body, following = self.statement(self.skip(start + 3, end), end)
            catches, final = [], ()
            while True:
                tail = self.skip(following, end)
                clause = re.match(r"(catch|finally)\b", self.code[tail:end])
                if not clause:
                    break
                position = self.skip(tail + clause.end(), end)
                header = (position, position)
                if clause.group(1) == "catch":
                    if self.code[position:position + 1] != "(":
                        raise ValueError("Malformed Kotlin catch; null analysis is incomplete")
                    close = self.pairs[position]
                    header, position = (position + 1, close), self.skip(close + 1, end)
                handler, following = self.statement(position, end)
                items = handler.body if handler.kind == "block" else (handler,)
                if clause.group(1) == "finally":
                    final = items
                else:
                    catches.append(Statement(tail, following, "catch", items, header=header))
            return Statement(start, following, "try", (body, *catches), final), following
        if re.match(r"(?:when|goto|yield)\b", self.code[start:end]):
            opening = self.code.find("{", start, end)
            finish = self.pairs[opening] + 1 if opening in self.pairs else self.end_statement(start, end)
            return Statement(start, finish, "unsupported"), finish
        # require/check are Kotlin functions, not control-flow keywords. The
        # evaluator checks their binding before granting an exit/refinement.
        if re.match(r"(?:require|synchronized)\s*\(", self.code[start:end]):
            finish = self.end_statement(start, end)
            return Statement(start, finish), finish
        control = re.match(r"(?:if|while|for)\s*\(|do\b|[{}]|(?:package|import|class|interface|enum|object|@interface)\b", self.code[start:end])
        if control:
            return super().statement(start, end)
        finish = self.end_statement(start, end)
        abrupt = re.match(r"(return|throw|break|continue)\b", self.code[start:finish])
        return Statement(start, finish, abrupt.group(1) if abrupt else "simple"), finish


def iter_kotlin_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {".kt", ".kts"} and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return

    # Glob both .kt and .kts files (Kotlin script files)
    for ext in ("*.kt", "*.kts"):
        for path in root.rglob(ext):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


class NullFlow:
    def __init__(self, text: str):
        self.model = KotlinCoroutines(text)
        self.parser = NullParser(self.model)
        self.text, self.code = text, self.model.code
        self.positions = [token.start for token in self.model.tokens]
        self.findings: dict[tuple[int, str], set[str]] = {}
        self.exceptions: list[list[State]] = []
        self.functions = {fn.name: fn for fn in self.model.functions}
        self.assertions: dict[int, list[int]] = {}
        for assertion in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*!!", self.code):
            key = self.key(assertion.group(1), assertion.start())
            if key is not None:
                self.assertions.setdefault(key, []).append(assertion.start())

    def token(self, position: int) -> int:
        return max(0, bisect_right(self.positions, position) - 1)

    def key(self, name: str, position: int) -> int | None:
        binding = self.model.binding(name, self.token(position))
        return binding.declaration if binding is not None else None

    def trim(self, start: int, end: int) -> tuple[int, int]:
        while start < end and self.code[start].isspace():
            start += 1
        while end > start and self.code[end - 1].isspace():
            end -= 1
        return start, end

    def unwrap(self, start: int, end: int) -> tuple[int, int]:
        start, end = self.trim(start, end)
        while start < end and self.code[start] == "(" and self.parser.pairs.get(start) == end - 1:
            start, end = self.trim(start + 1, end - 1)
        return start, end

    def plain_key(self, start: int, end: int) -> int | None:
        start, end = self.unwrap(start, end)
        return self.key(self.code[start:end], start) if re.fullmatch(r"[A-Za-z_]\w*", self.code[start:end]) else None

    def operator(self, start: int, end: int, operators: tuple[str, ...]) -> tuple[int, str] | None:
        index = start
        while index < end:
            self.model.spend()
            if index in self.parser.pairs:
                index = self.parser.pairs[index] + 1
                continue
            for operator in operators:
                if self.code.startswith(operator, index):
                    if operator.startswith("as") and ((index > start and (self.code[index - 1].isalnum() or self.code[index - 1] == "_")) or self.code[index + len(operator):index + len(operator) + 1].isalnum()):
                        continue
                    return index, operator
            index += 1
        return None

    @staticmethod
    def result(state: State, value: Value) -> list[State]:
        state.result = value
        return [state]

    def unique(self, states: Iterable[State]) -> list[State]:
        result = {state.signature(): state for state in states}
        if len(result) > 128:
            raise AnalysisLimit("Kotlin null-flow branch-state budget exceeded; analysis is incomplete")
        return list(result.values())

    @staticmethod
    def typed(type_name: str) -> Value:
        compact = re.sub(r"\s+", "", type_name)
        if not compact:
            return UNKNOWN
        nullable = compact.endswith("?")
        return Value(MAYBE if nullable else NONNULL, nullable=nullable, type_name=compact.rstrip("?"))

    def initialize(self, position: int) -> State:
        state = State()
        for bindings in self.model.bindings.values():
            for binding in bindings:
                if binding.low <= position < binding.high and binding.type_name:
                    state.values[binding.declaration] = self.typed(binding.type_name)
                    state.aliases[binding.declaration] = frozenset({binding.declaration})
        return state

    def assign(self, state: State, key: int, value: Value, source: int | None = None) -> None:
        old = state.aliases.get(key, frozenset({key}))
        for member in old - {key}:
            state.aliases[member] = old - {key}
        state.aliases[key] = frozenset({key})
        if source is not None and source != key:
            group = state.aliases.get(source, frozenset({source})) | {key}
            for member in group:
                state.aliases[member] = group
        state.values[key] = value

    def refine(self, state: State, key: int | None, nulls: int, origin: str = "") -> State | None:
        changed = state.copy()
        if key is None:
            return changed
        group = changed.aliases.get(key, frozenset({key}))
        possible = nulls
        for member in group:
            possible &= changed.values.get(member, UNKNOWN).nulls
        if not possible:
            return None
        for member in group:
            previous = changed.values.get(member, UNKNOWN)
            origins = previous.origins | ({origin} if origin else set())
            changed.values[member] = replace(previous, nulls=possible, origins=frozenset(origins), nullable=previous.nullable or bool(origin))
        return changed

    def exceptional(self, state: State) -> None:
        if self.exceptions:
            thrown = state.copy()
            thrown.exit = "throw"
            self.exceptions[-1].append(thrown)

    def builtin(self, name: str, position: int, wanted: str) -> bool:
        package = "kotlin.io." if wanted in {"print", "println"} else "kotlin."
        canonical = self.model.canonical(name, self.token(position))
        if canonical == package + wanted:
            return True
        if name != wanted or name in self.model.imports or self.key(name, position) is not None:
            return False
        return not any(not package_name.startswith(("kotlin.", "kotlinx.coroutines", "java.")) for package_name in self.model.wildcards)

    def call_value(self, name: str, position: int) -> Value:
        if any(self.builtin(name, position, candidate) for candidate in ("print", "println", "require", "check")):
            return UNIT
        if any(self.builtin(name, position, candidate) for candidate in ("listOf", "mutableListOf", "setOf", "mutableSetOf", "mapOf", "mutableMapOf", "arrayOf")):
            return Value(NONNULL)
        binding = self.key(name, position)
        fn = self.functions.get(binding)
        if fn is not None:
            close = self.model.pairs[fn.parameters]
            declaration = self.model.path(close + 1, fn.start).rstrip("=")
            if declaration.startswith(":"):
                return self.typed(declaration[1:])
            if not fn.expression:
                return UNIT
        return UNKNOWN

    def callback_effects(self, start: int, end: int, states: list[State]) -> None:
        """Do not grant a non-null proof across an unresolved captured write.

        Both sides use lexical binding identities: an unrelated assignment or
        lambda-local variable with the same spelling cannot invalidate a fact.
        Ordinary deferred literal creation is handled separately from a lambda
        passed to an unknown call.
        """
        for assignment in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*=(?!=)", self.code[start:end]):
            key = self.key(assignment.group(1), start + assignment.start())
            if key is not None and any(key in state.values for state in states) and any(
                position >= end for position in self.assertions.get(key, ())
            ):
                raise ValueError("Unknown Kotlin callback mutates a captured value used by a later null assertion; analysis is incomplete")

    def condition(self, start: int, end: int, state: State) -> tuple[list[State], list[State]]:
        start, end = self.unwrap(start, end)
        for operator in ("||", "&&"):
            split = self.operator(start, end, (operator,))
            if split:
                position, _ = split
                left_true, left_false = self.condition(start, position, state)
                follow = left_false if operator == "||" else left_true
                right_true, right_false = [], []
                for branch in follow:
                    yes, no = self.condition(position + 2, end, branch)
                    right_true.extend(yes)
                    right_false.extend(no)
                return (self.unique(left_true + right_true), self.unique(right_false)) if operator == "||" else (self.unique(right_true), self.unique(left_false + right_false))
        expression = self.code[start:end]
        if expression.startswith("!") and not expression.startswith("!!"):
            no, yes = self.condition(start + 1, end, state)
            return yes, no
        if expression in {"true", "false"}:
            return ([state.copy()], []) if expression == "true" else ([], [state.copy()])
        comparison = re.fullmatch(r"([A-Za-z_]\w*)\s*(===|!==|==|!=)\s*null", expression)
        reverse = re.fullmatch(r"null\s*(===|!==|==|!=)\s*([A-Za-z_]\w*)", expression)
        if comparison or reverse:
            name, operator = comparison.groups() if comparison else (reverse.group(2), reverse.group(1))
            position = start + expression.find(name)
            key = self.key(name, position)
            equality = operator in {"==", "==="}
            origin = "negative_guard" if equality else "positive_guard"
            yes = self.refine(state, key, NULL if equality else NONNULL, origin)
            no = self.refine(state, key, NONNULL if equality else NULL, origin)
            return ([yes] if yes is not None else [], [no] if no is not None else [])
        safe = re.fullmatch(r"([A-Za-z_]\w*)\s*\?\..+?\s*(==|!=|===|!==)\s*(true|false|null)", expression, re.S)
        if safe:
            name, operator, constant = safe.groups()
            key = self.key(name, start)
            equality = operator in {"==", "==="}
            proves_on_true = (constant != "null" and equality) or (constant == "null" and not equality)
            # Calls/arguments in a safe call execute only on the non-null path.
            for branch in self.evaluate(start, end, state.copy()):
                if branch.exit:
                    continue
            nonnull = self.refine(state, key, NONNULL, "safecall_guard")
            other = self.refine(state, key, MAYBE, "safecall_guard")
            return ([nonnull] if nonnull else [], [other] if other else []) if proves_on_true else ([other] if other else [], [nonnull] if nonnull else [])
        positive_type = re.fullmatch(r"([A-Za-z_]\w*)\s+is\s+([A-Za-z_][\w.<>]*)", expression)
        if positive_type:
            yes = self.refine(state, self.key(positive_type.group(1), start), NONNULL)
            return ([yes] if yes else [], [state.copy()])
        branches = [item for item in self.evaluate(start, end, state) if not item.exit]
        return ([item.copy() for item in branches], [item.copy() for item in branches])

    def evaluate(self, start: int, end: int, state: State) -> list[State]:
        self.model.spend()
        if state.exit:
            return [state]
        start, end = self.unwrap(start, end)
        expression = self.code[start:end]
        if not expression:
            return self.result(state, UNIT)
        abrupt = re.match(r"(return(?:@[A-Za-z_]\w*)?|throw|break|continue)\b", expression)
        if abrupt:
            states = self.evaluate(start + abrupt.end(), end, state)
            for branch in states:
                if not branch.exit:
                    branch.exit = abrupt.group(1)
                    if branch.exit == "throw":
                        self.exceptional(branch)
            return states
        elvis = self.operator(start, end, ("?:",))
        if elvis:
            position, _ = elvis
            output = []
            key = self.plain_key(start, position)
            for left in self.evaluate(start, position, state):
                if left.exit:
                    output.append(left)
                    continue
                value = left.result
                if value.nulls & NONNULL:
                    present = self.refine(left, key, NONNULL)
                    if present is not None:
                        output.extend(self.result(present, replace(value, nulls=NONNULL)))
                if value.nulls & NULL:
                    missing = self.refine(left, key, NULL)
                    if missing is not None:
                        for fallback in self.evaluate(position + 2, end, missing):
                            if not fallback.exit and fallback.result.nulls & NULL and fallback.result.nullable:
                                fallback.result = replace(fallback.result, origins=frozenset({"elvis_force"}))
                            output.append(fallback)
            return self.unique(output)
        if self.operator(start, end, ("||", "&&")):
            yes, no = self.condition(start, end, state)
            return self.unique(self.result(branch, Value(NONNULL, type_name="Boolean"))[0] for branch in yes + no)
        if re.match(r"(?:if|try|when)\b", expression):
            statement, finish = self.parser.statement(start, end)
            if self.code[finish:end].strip():
                raise ValueError("Unsupported Kotlin compound null expression; analysis is incomplete")
            return self.flow((statement,), [state])
        cast = self.operator(start, end, ("as?", "as "))
        if cast:
            position, operator = cast
            type_name = re.sub(r"\s+", "", self.code[position + len(operator):end])
            states = self.evaluate(start, position, state)
            for branch in states:
                if branch.exit:
                    continue
                value = branch.result
                if operator == "as?":
                    nulls = value.nulls if value.type_name == type_name and value.type_name else MAYBE
                    branch.result = Value(nulls, frozenset({"smart_cast"}), True, type_name.rstrip("?"))
                else:
                    self.exceptional(branch)
                    branch.result = self.typed(type_name)
            return states
        name_only = re.fullmatch(r"[A-Za-z_]\w*", expression)
        if name_only:
            if expression == "null":
                return self.result(state, Value(NULL, frozenset({"nullable_value"}), True))
            if expression in {"true", "false", "Unit"}:
                return self.result(state, Value(NONNULL))
            return self.result(state, state.values.get(self.key(expression, start), UNKNOWN))
        inline = re.match(r"([A-Za-z_][\w.]*)\s*\{", expression)
        if inline and self.builtin(inline.group(1), start, "run"):
            opening = start + inline.end() - 1
            if self.parser.pairs[opening] != end - 1:
                raise ValueError("Unsupported Kotlin run result operation; null analysis is incomplete")
            branches = self.flow(self.parser.block(opening + 1, end - 1), [state])
            label = inline.group(1).rsplit(".", 1)[-1]
            for branch in branches:
                if branch.exit == "return@" + label:
                    branch.exit = ""
            return branches
        call = re.match(r"([A-Za-z_][\w.]*)\s*\(", expression)
        if call:
            opening = start + call.end() - 1
            closing = self.parser.pairs[opening]
            tail = self.code[closing + 1:end].strip()
            if not tail or tail.startswith("{"):
                name = call.group(1)
                arguments = list(self.parser.parts(opening + 1, closing))
                if any(self.builtin(name, start, candidate) for candidate in ("require", "check")) and arguments:
                    yes, no = self.condition(*arguments[0], state)
                    for branch in no:
                        self.exceptional(branch)
                    return [self.result(branch, UNIT)[0] for branch in yes]
                if any(self.builtin(name, start, candidate) for candidate in ("requireNotNull", "checkNotNull")) and arguments:
                    output = []
                    key = self.plain_key(*arguments[0])
                    for branch in self.evaluate(*arguments[0], state):
                        value = branch.result
                        missing = self.refine(branch, key, NULL) if value.nulls & NULL else None
                        if missing is not None:
                            self.exceptional(missing)
                        present = self.refine(branch, key, NONNULL) if value.nulls & NONNULL else None
                        if present is not None:
                            output.extend(self.result(present, replace(value, nulls=NONNULL)))
                    return output
                states = [state]
                for low, high in arguments:
                    states = self.unique(next_state for branch in states for next_state in self.evaluate(low, high, branch))
                if tail.startswith("{") and "!!" in self.code[closing + 1:end]:
                    raise ValueError("Unknown Kotlin callback contains selected null assertions; analysis is incomplete")
                if tail.startswith("{"):
                    self.callback_effects(closing + 1, end, states)
                for branch in states:
                    if not branch.exit:
                        self.exceptional(branch)
                        branch.result = self.call_value(name, start)
                        if any(self.builtin(name, start, candidate) for candidate in ("error", "TODO")):
                            branch.exit = "throw"
                return states
        return self.evaluate_parts(start, end, state)

    def evaluate_parts(self, start: int, end: int, state: State) -> list[State]:
        """Visit executable subexpressions at their own precedence/scope."""
        states, index = [state], start
        result = UNKNOWN
        original = self.text[start:end].lstrip()
        literal = original.startswith(('"', "'")) or re.fullmatch(r"[+-]?\d[\w.]*", self.code[start:end]) is not None
        while index < end:
            self.model.spend()
            if self.code[index] == "{":
                finish = self.parser.pairs[index]
                if self.code[start:index].strip():
                    self.callback_effects(index + 1, finish, states)
                if "!!" in self.code[index:finish] and (any(value.origins for branch in states for value in branch.values.values()) or re.search(r"\bas\s*\?|\?:|\bnull\b", self.code[index:finish])):
                    raise ValueError("Deferred Kotlin lambda needs null-flow binding analysis; analysis is incomplete")
                result = Value(NONNULL, type_name="Function")
                index = finish + 1
                continue
            if self.code[index] in "([":
                finish = self.parser.pairs[index]
                for low, high in self.parser.parts(index + 1, finish):
                    states = self.unique(next_state for branch in states for next_state in self.evaluate(low, high, branch))
                # A nested call can throw after its arguments complete; mere
                # grouping and interpolation holes do not introduce a throw.
                prefix = self.code[start:index].rstrip()
                if prefix and (prefix[-1].isalnum() or prefix[-1] in "_]"):
                    for branch in states:
                        if not branch.exit:
                            self.exceptional(branch)
                index = finish + 1
                continue
            assertion = re.match(r"([A-Za-z_]\w*)\s*!!", self.code[index:end])
            if assertion and (index == start or self.code[index - 1] not in "." and not (self.code[index - 1].isalnum() or self.code[index - 1] == "_")):
                name = assertion.group(1)
                key = self.key(name, index)
                continued = []
                for branch in states:
                    if branch.exit:
                        continued.append(branch)
                        continue
                    value = branch.values.get(key, UNKNOWN)
                    if value.nulls & NULL:
                        if value.origins:
                            self.findings.setdefault((index, name), set()).update(value.origins)
                        missing = self.refine(branch, key, NULL)
                        if missing is not None:
                            self.exceptional(missing)
                    present = self.refine(branch, key, NONNULL) if value.nulls & NONNULL else None
                    if present is not None:
                        present.result = replace(value, nulls=NONNULL)
                        continued.append(present)
                    else:
                        branch.exit = "throw"
                        continued.append(branch)
                states = continued
                result = Value(NONNULL)
                index += assertion.end()
                continue
            index += 1
        if literal:
            result = Value(NONNULL, type_name="String" if original.startswith('"') else "")
        elif self.operator(start, end, ("==", "!=", ">", "<")):
            result = Value(NONNULL, type_name="Boolean")
        return [self.result(branch, result)[0] if not branch.exit else branch for branch in states]

    def flow(self, statements: tuple[Statement, ...], states: list[State]) -> list[State]:
        for statement in statements:
            self.model.spend()
            output = []
            for state in states:
                if state.exit:
                    output.append(state)
                else:
                    output.extend(self.execute(statement, state))
            states = self.unique(output)
        return states

    def execute(self, statement: Statement, state: State) -> list[State]:
        kind = statement.kind
        if kind == "definition":
            return [state]
        if kind == "unsupported":
            raise ValueError("Unsupported Kotlin null control flow; analysis is incomplete")
        if kind == "block":
            return self.flow(statement.body, [state])
        if kind == "if":
            yes, no = self.condition(*statement.header, state)
            branches = self.flow(statement.body, yes) + self.flow(statement.otherwise, no)
            if not statement.otherwise:
                for branch in branches:
                    if not branch.exit:
                        branch.result = UNIT
            return self.unique(branches)
        if kind in {"while", "for", "do"}:
            return self.loop(statement, state)
        if kind == "try":
            return self.try_flow(statement, state)
        if kind in {"return", "throw", "break", "continue"}:
            return self.evaluate(statement.start, statement.end, state)
        if kind not in {"simple", "require", "synchronized"}:
            raise ValueError(f"Unsupported Kotlin null statement {kind}; analysis is incomplete")
        start, end = self.trim(statement.start, statement.end)
        expression = self.code[start:end]
        declaration = re.match(r"(?:val|var)\s+([A-Za-z_]\w*)(?:\s*:\s*[^=]+)?\s*=", expression)
        assignment = re.match(r"([A-Za-z_]\w*)\s*=(?!=)", expression) if declaration is None else None
        match = declaration or assignment
        if match:
            name = match.group(1)
            name_position = start + match.start(1)
            key = self.key(name, name_position)
            if key is None:
                raise ValueError("Unsupported Kotlin null binding; analysis is incomplete")
            low = start + match.end()
            source = self.plain_key(low, end)
            branches = self.evaluate(low, end, state)
            for branch in branches:
                if not branch.exit:
                    self.assign(branch, key, branch.result, source)
            return branches
        return self.evaluate(start, end, state)

    def loop(self, statement: Statement, state: State) -> list[State]:
        kind = statement.kind
        pending, output, seen = [state], [], set()
        if kind == "do":
            pending = self.flow(statement.body, pending)
        while pending:
            self.model.spend()
            head = pending.pop()
            if head.exit in {"return", "throw"} or head.exit.startswith("return@"):
                output.append(head)
                continue
            if head.exit == "break":
                head.exit, head.result = "", UNIT
                output.append(head)
                continue
            if head.exit == "continue":
                head.exit = ""
            signature = head.signature()
            if signature in seen:
                continue
            seen.add(signature)
            if len(seen) > 128:
                raise AnalysisLimit("Kotlin null loop-state budget exceeded; analysis is incomplete")
            if kind == "for":
                yes, no = [head.copy()], [head.copy()]
            else:
                yes, no = self.condition(*statement.header, head)
            for branch in no:
                branch.result = UNIT
            output.extend(no)
            pending.extend(self.flow(statement.body, yes))
        return self.unique(output)

    def try_flow(self, statement: Statement, state: State) -> list[State]:
        thrown: list[State] = []
        self.exceptions.append(thrown)
        try:
            normal = self.flow((statement.body[0],), [state])
        finally:
            self.exceptions.pop()
        output = [branch for branch in normal if branch.exit != "throw"]
        thrown = self.unique(thrown + [branch for branch in normal if branch.exit == "throw"])
        catches = statement.body[1:]
        for handler in catches:
            parameter = re.match(r"\s*([A-Za-z_]\w*)\s*:\s*([\w.<>?]+)", self.code[slice(*handler.header)])
            if parameter is None:
                raise ValueError("Unsupported Kotlin null catch binding; analysis is incomplete")
            parameter_position = handler.header[0] + parameter.start(1)
            key = self.token(parameter_position)
            for failed in thrown:
                branch = failed.copy()
                branch.exit = ""
                self.assign(branch, key, Value(NONNULL, type_name=parameter.group(2)))
                output.extend(self.flow(handler.body, [branch]))
        # Unmatched exception paths remain abrupt and still run finally. They
        # cannot provide a normal-path proof even when catch matching is unknown.
        output.extend(thrown)
        if statement.otherwise:
            final = []
            for branch in self.unique(output):
                previous, value = branch.exit, branch.result
                branch.exit = ""
                for after in self.flow(statement.otherwise, [branch]):
                    if not after.exit:
                        after.exit, after.result = previous, value
                    final.append(after)
            output = final
        return self.unique(output)

    def scan(self) -> list[tuple[str, int, int, str]]:
        if "!!" not in self.code:
            return []
        for fn in self.model.functions:
            start = self.model.tokens[fn.start].start
            end = self.model.tokens[fn.end - 1].end
            if not fn.expression:
                start, end = start + 1, end - 1
            if "!!" in self.code[start:end]:
                state = self.initialize(fn.start)
                statements = self.parser.block(start, end) if not fn.expression else (Statement(start, end, "return"),)
                self.flow(statements, [state])
        # Script/top-level declarations are separate from function bodies.
        self.flow(self.parser.block(0, len(self.code)), [self.initialize(-1)])
        precedence = {kind: index for index, kind in enumerate(MESSAGES)}
        result = []
        for (position, name), origins in sorted(self.findings.items()):
            kind = min(origins, key=lambda item: precedence[item])
            line, column = line_col(self.text, position)
            result.append((kind, line, column, MESSAGES[kind].format(name=name)))
        return result


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return one stable diagnostic per selected assertion and lexical binding."""
    return NullFlow(text).scan()


def analyze_file(path: Path):
    text = path.read_text(encoding="utf-8")
    deduped = []
    seen = set()
    for _kind, line, col, message in scan_text(text):
        key = (line, col, message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((line, col, message))
    return deduped


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: type_narrowing_kotlin.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        print(f"Kotlin analysis input does not exist: {root}", file=sys.stderr)
        return 2
    incomplete = False
    for path in iter_kotlin_files(root):
        try:
            issues = analyze_file(path)
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            print(f"{path}: Kotlin null analysis incomplete: {exc}", file=sys.stderr)
            incomplete = True
            continue
        for line, col, message in issues:
            print(f"{path}:{line}:{col}\t{message}")
    return 2 if incomplete else 0


def run(ctx: RunContext) -> Iterable[dict]:
    suppressions = SourceSuppressions("kotlin")
    for path in ctx.files:
        if path.suffix.lower() not in {".kt", ".kts"}:
            continue
        text = path.read_text(encoding="utf-8")
        suppressions.index(path, text)
        for kind, line, col, message in scan_text(text):
            rule = f"kotlin.narrowing.{kind}"
            if not ctx.rule_enabled(rule) or suppressions.is_suppressed(path, line, rule):
                continue
            yield {
                "rule": rule,
                "path": str(path.resolve()),
                "line": line,
                "col": col,
                "layer": "narrowing",
                "lang": "kotlin",
                "severity": "warning",
                "message": message,
            }


def _selftest_negative_guard_detection() -> None:
    code = "fun f(job: Job?) {\n    if (job == null) { log() }\n    val n = job!!\n}\n"
    findings = [item for item in scan_text(code) if item[0] == "negative_guard"]
    assert len(findings) == 1, findings
    assert findings[0][1] == 3, findings
    assert findings[0][3] == "job!! after non-exiting null guard", findings


def _selftest_exit_guard_suppressed() -> None:
    code = "fun f(user: User?) {\n    if (user == null) { return }\n    val n = user!!\n}\n"
    findings = [item for item in scan_text(code) if item[0] == "negative_guard"]
    assert findings == [], findings
    assert scan_text(code) == [], findings


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_kotlin_") -> None:
    import tempfile

    code = "fun f(admin: Any?) {\n    val a = admin as? Admin\n    val n = a!!\n}\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "Unsafe.kt"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="kotlin", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "kotlin.narrowing.smart_cast", findings
    assert findings[0]["line"] == 3, findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("negative_guard_detection", _selftest_negative_guard_detection),
    ("exit_guard_suppressed", _selftest_exit_guard_suppressed),
    ("run_finds_smart_cast_force", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="kotlin", name="narrowing_kotlin", run=run, selftests=SELF_TESTS))
