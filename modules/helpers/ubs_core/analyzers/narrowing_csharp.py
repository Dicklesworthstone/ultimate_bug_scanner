"""Scoped C# null-guard flow over the shared lexical statement frontend.

Only selected null/empty/TryGetValue guards introduce obligations. Follow
branches, assignments and actual exits instead of searching for the next
matching name in the file. Comments and string text cannot create guards or
exits; executable interpolation holes retain their original coordinates.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from ubs_core.analyzers.taint_csharp_request import Function, Parser, Statement, masked_source, pairs, parts
from ubs_core.io import line_col
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.taint_flow import AnalysisLimit, Budget

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "bin",
    "obj",
    "packages",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "TestResults",
    ".idea",
    ".vscode",
}

_NEGATIVE_GUARD_MESSAGE = "{name} dereferenced after non-exiting null/empty guard"
_POSITIVE_GUARD_MESSAGE = "{name} dereferenced after positive null guard without narrowing the fallthrough path"
_TRY_GET_VALUE_MESSAGE = "{name} used after non-exiting TryGetValue guard"
MESSAGES = {"negative_guard": _NEGATIVE_GUARD_MESSAGE,
            "positive_guard": _POSITIVE_GUARD_MESSAGE, "try_get_value": _TRY_GET_VALUE_MESSAGE}
NULL, NONNULL, MAYBE = 1, 2, 3
IDENT = r"@?[A-Za-z_]\w*"
NAME = rf"(?:this\s*\.\s*)?{IDENT}"
TYPE = r"[\w.@]+(?:\s*<[^;=]+>)?(?:\[\])?\??"
DECLARATION = re.compile(rf"\s*(?:(?:using|await|const)\s+)*({TYPE})\s+({IDENT})\s*(?:=|;|$)")
VALUE_TYPES = frozenset("bool byte sbyte short ushort int uint long ulong float double decimal char nint nuint".split())
FIELD = re.compile(rf"({TYPE})\s+({IDENT})\s*(?=[;={{])")
GUARD_EVIDENCE = re.compile(r"(?:==|!=|\bis(?:\s+not)?)\s*null\b|\bnull\s*(?:==|!=)"
                            r"|\bstring\.IsNullOr(?:Empty|WhiteSpace)\s*\(|\.TryGetValue\s*\(")


def guard_positions(code, delimiters):
    return tuple(match.start() for match in re.finditer(r"\b(?:if|while|for)\s*\(", code)
                 if GUARD_EVIDENCE.search(code[match.end():delimiters[match.end() - 1]]))


@dataclass(frozen=True)
class Value:
    nulls: int = MAYBE
    origins: frozenset[str] = frozenset()


@dataclass
class State:
    values: dict[str, Value] = field(default_factory=dict)
    exit: str = ""

    def copy(self):
        return State(dict(self.values), self.exit)

    def signature(self):
        return self.exit, tuple(sorted(self.values.items()))


class GuardParser(Parser):
    """Keep label targets, so a goto only bypasses the statements it jumps over."""

    def find_functions(self):
        for match in re.finditer(r"\binterface\s+([A-Za-z_]\w*)[^;{}]*\{", self.code):
            self.types.append((match.start(), self.pairs[match.end() - 1], match.group(1)))
        self.types.sort()
        super().find_functions()
        self.deferred: set[int] = set()

        def add(key, name, declaration, opening, parameters=()):
            if key in self.functions:
                return
            function = Function(key, name, (), declaration, opening + 1, self.pairs[opening],
                                tuple(name for name, _type in parameters),
                                parameter_types=tuple(type_ for _name, type_ in parameters))
            self.functions[key] = function
            if name not in {"lambda", "delegate"}:
                self.declarations[declaration] = function

        def parameters(opening, closing):
            result = []
            for low, high in parts(self.code, opening + 1, closing, generics=True):
                spelling = re.sub(r"\[[^\]]*\]", " ", self.code[low:high].split("=", 1)[0]).strip()
                spelling = re.sub(r"\b(?:ref|out|in|params|this|scoped)\s+", "", spelling)
                names = list(re.finditer(IDENT, spelling))
                if names:
                    last = names[-1]
                    result.append((last[0].lstrip("@"), spelling[:last.start()].strip()))
            return result

        for match in re.finditer(rf"\b({IDENT})\s*\(", self.code):
            if match.start() in self.functions:
                continue
            opening = match.end() - 1
            closing = self.pairs[opening]
            beginning = self.skip(self.boundary(match.start()), match.start())
            prefix = self.code[beginning:match.start()].strip()
            if any(word not in {"public", "private", "protected", "internal", "static", "unsafe", "extern"}
                   for word in prefix.split()):
                continue
            owners = [(low, high, name) for low, high, name in self.types if low < match.start() < high]
            if not owners or match.group(1) != min(owners, key=lambda item: item[1] - item[0])[2]:
                continue
            body = self.skip(closing + 1, len(self.code))
            initializer = re.match(r":\s*(?:base|this)\s*\(", self.code[body:])
            if initializer:
                body = self.skip(self.pairs[body + initializer.end() - 1] + 1, len(self.code))
            if self.code[body:body + 1] == "{":
                add(match.start(), match.group(1), beginning, body, parameters(opening, closing))
        for match in re.finditer(r"\b(get|set|init|add|remove)\s*\{", self.code):
            accessor = match.group(1)
            containers = [low for low, high in self.pairs.items()
                          if self.code[low] == "{" and low < match.start() < high]
            opening = max(containers, default=0)
            property_type = re.search(rf"({TYPE})\s+{IDENT}\s*$",
                                      self.code[self.boundary(opening):opening])
            add(match.start(), accessor, match.start(), match.end() - 1,
                (("value", property_type.group(1) if property_type else ""),) if accessor != "get" else ())
        reverse = {high: low for low, high in self.pairs.items()}
        for match in re.finditer(r"=>\s*\{", self.code):
            previous = match.start() - 1
            while previous >= 0 and self.code[previous].isspace():
                previous -= 1
            if self.code[previous:previous + 1] == ")" and previous in reverse:
                args = parameters(reverse[previous], previous)
            else:
                parameter = re.search(rf"({IDENT})\s*$", self.code[:match.start()])
                args = ((parameter.group(1).lstrip("@"), ""),) if parameter else ()
            add(match.start(), "lambda", match.start(), match.end() - 1, args)
            self.deferred.add(match.start())
        for match in re.finditer(r"\bdelegate\s*(\([^{}]*\))?\s*\{", self.code):
            args = ()
            if match.group(1):
                opening = self.code.find("(", match.start(), match.end())
                args = parameters(opening, self.pairs[opening])
            add(match.start(), "delegate", match.start(), match.end() - 1, args)
            self.deferred.add(match.start())
        for function in self.functions.values():
            parents = [other for other in self.functions.values()
                       if other.start <= function.key < other.end and other.key != function.key]
            function.parent = min(parents, key=lambda item: item.end - item.start).key if parents else None
            function.body = ((Statement(function.start, function.end, "return"),) if function.expression
                             else self.block(function.start, function.end))

    def statement(self, start, end):
        label = re.match(rf"({IDENT})\s*:(?!:)", self.code[start:end])
        if label and label.group(1) not in {"case", "default"}:
            finish = start + label.end()
            return Statement(start, finish, "label"), finish
        if re.match(r"goto\b", self.code[start:end]):
            finish = self.end_statement(start, end)
            if not re.fullmatch(rf"goto\s+{IDENT}\s*", self.code[start:finish]):
                return Statement(start, finish, "unsupported-goto"), min(finish + 1, end)
            return Statement(start, finish, "goto"), min(finish + 1, end)
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
                if self.code[position:position + 1] == "(":
                    close = self.pairs[position]
                    header, position = (position + 1, close), self.skip(close + 1, end)
                filter_ = ()
                if self.code.startswith("when", position):
                    opening = self.code.find("(", position, end)
                    close = self.pairs[opening]
                    filter_ = (Statement(opening + 1, close, "catch-filter"),)
                    position = self.skip(close + 1, end)
                handler, following = self.statement(position, end)
                items = handler.body if handler.kind == "block" else (handler,)
                if clause.group(1) == "finally":
                    final = items
                else:
                    catches.append(Statement(tail, following, "catch", items, filter_, header))
            return Statement(start, following, "try", (body, *catches), final), following
        return super().statement(start, end)


class GuardFlow:
    def __init__(self, text: str):
        self.text, self.code = text, masked_source(text)
        self.parser = GuardParser(text, self.code)
        self.guards = guard_positions(self.code, self.parser.pairs)
        self.budget = Budget()
        self.nullable_values: set[str] = set()
        self.type_names = {name for low, _high, name in self.parser.types
                           if re.match(r"(?:class|struct|record|interface)\b", self.code[low:])}
        self.type_paths = {".".join(owner for begin, finish, owner in self.parser.types if begin <= low < finish)
                           for low, _high, _name in self.parser.types
                           if re.match(r"(?:class|struct|record|interface)\b", self.code[low:])}
        self.type_aliases = {match.group(1).lstrip("@") for match in
                             re.finditer(rf"\busing\s+({IDENT})\s*=", self.code)}
        self.fields: dict[int, dict[str, str]] = {}
        braces = [(low, high) for low, high in self.parser.pairs.items() if self.code[low] == "{"]
        for low, high, _name in self.parser.types:
            if not re.match(r"(?:class|struct|record)\b", self.code[low:]):
                continue
            opening = self.code.find("{", low, high)
            fields = {}
            for match in FIELD.finditer(self.code, opening + 1, high):
                if any(opening < child < match.start() < close <= high for child, close in braces):
                    continue
                name = match.group(2).lstrip("@")
                key = f"field:{opening}:{name}"
                fields[name] = key
                self.typed(key, match.group(1))
            self.fields[opening] = fields
        self.findings: set[tuple[str, int, int, str]] = set()
        self.exceptions: list[list[State]] = []

    @staticmethod
    def key(name, bindings):
        name = re.sub(r"\s|@", "", name)
        return bindings.get(name, "field:" + name.removeprefix("this."))

    def typed(self, key, spelling):
        spelling = re.sub(r"\s+", "", spelling)
        builtin = spelling.endswith("?") and spelling[:-1] in VALUE_TYPES
        qualified = re.fullmatch(r"(global::)?System\.Nullable<.+>", spelling)
        framework = (qualified and "System.Nullable" not in self.type_paths
                     and (qualified.group(1) or "System" not in self.type_names | self.type_aliases))
        if builtin or framework:
            self.nullable_values.add(key)

    def declare(self, statement, bindings):
        start, end = statement.header if statement.kind == "if" else (statement.start, statement.end)
        code = self.code[start:end]
        match = DECLARATION.match(code) if statement.kind in {"simple", "declarator"} else None
        if match:
            name = match.group(2).lstrip("@")
            key = f"{name}@{start + match.start(2)}"
            bindings[name] = key
            self.typed(key, match.group(1))
        for match in re.finditer(rf"\bout\s+(?:var|{TYPE})\s+({IDENT})", code):
            name = match.group(1).lstrip("@")
            bindings[name] = f"{name}@{start + match.start(1)}"

    def unique(self, states):
        result = {state.signature(): state for state in states}
        if len(result) > 128:
            raise AnalysisLimit("C# null-flow branch-state budget exceeded; analysis is incomplete")
        return list(result.values())

    @staticmethod
    def merged(values):
        values = list(values)
        return Value(nulls=(NULL if any(v.nulls & NULL for v in values) else 0)
                     | (NONNULL if any(v.nulls & NONNULL for v in values) else 0),
                     origins=frozenset(origin for value in values for origin in value.origins))

    def join_into(self, state, branches):
        if not branches:
            return
        keys = set().union(*(branch.values for branch in branches))
        state.values = {key: self.merged(branch.values.get(key, Value()) for branch in branches) for key in keys}

    def trim(self, start, end):
        while start < end and self.code[start].isspace():
            start += 1
        while end > start and self.code[end - 1].isspace():
            end -= 1
        while start < end and self.code[start] == "(" and self.parser.pairs.get(start) == end - 1:
            start, end = self.trim(start + 1, end - 1)
        return start, end

    def operator(self, start, end, wanted):
        index = start
        while index < end:
            self.budget.spend()
            if index in self.parser.pairs:
                index = self.parser.pairs[index] + 1
                continue
            for operator in wanted:
                if self.code.startswith(operator, index):
                    if operator == "=" and (self.code[index - 1:index] in {"=", "!", "<", ">", "?", "+", "-"}
                                            or self.code[index + 1:index + 2] in {"=", ">"}):
                        continue
                    if operator == "?" and (self.code[index:index + 2] in {"??", "?.", "?["}
                                            or self.code[index - 1:index] == "?"):
                        continue
                    return index, operator
            index += 1
        return None

    def refine(self, state, name, bindings, nulls, origin=""):
        changed = state.copy()
        key = self.key(name, bindings)
        previous = changed.values.get(key, Value())
        possible = previous.nulls & nulls
        if not possible:
            return []
        origins = previous.origins or (frozenset({origin}) if origin else frozenset())
        changed.values[key] = Value(possible, origins)
        return [changed]

    def condition(self, start, end, state, bindings, depth=0):
        if depth > 96:
            raise AnalysisLimit("C# guard nesting limit exceeded; analysis is incomplete")
        start, end = self.trim(start, end)
        for operator in ("||", "&&"):
            split = self.operator(start, end, (operator,))
            if split:
                position, _ = split
                yes, no = self.condition(start, position, state, bindings, depth + 1)
                right_yes, right_no = [], []
                for branch in no if operator == "||" else yes:
                    true, false = self.condition(position + 2, end, branch, bindings, depth + 1)
                    right_yes.extend(true)
                    right_no.extend(false)
                return (self.unique(yes + right_yes), self.unique(right_no)) if operator == "||" else (self.unique(right_yes), self.unique(no + right_no))
        code = self.code[start:end]
        if code.startswith("!"):
            yes, no = self.condition(start + 1, end, state, bindings, depth + 1)
            return no, yes
        if code in {"true", "false"}:
            return ([state.copy()], []) if code == "true" else ([], [state.copy()])
        comparison = re.fullmatch(rf"({NAME})\s*(==|!=|is\s+not|is)\s*null", code)
        reverse = re.fullmatch(rf"null\s*(==|!=)\s*({NAME})", code)
        if comparison or reverse:
            name, operator = comparison.groups() if comparison else (reverse.group(2), reverse.group(1))
            negative = operator in {"==", "is"}
            origin = "negative_guard" if negative else "positive_guard"
            return (self.refine(state, name, bindings, NULL if negative else NONNULL, origin),
                    self.refine(state, name, bindings, NONNULL if negative else NULL, origin))
        empty = re.fullmatch(rf"string\.IsNullOr(?:Empty|WhiteSpace)\s*\(\s*({NAME})\s*\)", code)
        if empty:
            return (self.refine(state, empty.group(1), bindings, MAYBE, "negative_guard"),
                    self.refine(state, empty.group(1), bindings, NONNULL, "negative_guard"))
        has_value = re.fullmatch(rf"({NAME})\s*\.\s*HasValue", code)
        if has_value and self.key(has_value.group(1), bindings) in self.nullable_values:
            return (self.refine(state, has_value.group(1), bindings, NONNULL),
                    self.refine(state, has_value.group(1), bindings, NULL))
        found = re.fullmatch(rf"[\w.@]+\.TryGetValue\s*\([\s\S]*\bout\s+(?:(?:var|{TYPE})\s+)?({IDENT})\s*\)", code)
        if found:
            self.expression(start, end, state, bindings, depth + 1)
            return (self.refine(state, found.group(1), bindings, NONNULL, "try_get_value"),
                    self.refine(state, found.group(1), bindings, MAYBE, "try_get_value"))
        self.expression(start, end, state, bindings, depth + 1)
        return [state.copy()], [state.copy()]

    def expression(self, start, end, state, bindings, depth=0):
        self.budget.spend()
        if depth > 96:
            raise AnalysisLimit("C# expression nesting limit exceeded; null analysis is incomplete")
        start, end = self.trim(start, end)
        code = self.code[start:end]
        assignment = self.operator(start, end, ("=",))
        if assignment:
            position, _ = assignment
            left = self.code[start:position].strip()
            declaration = DECLARATION.match(self.code[start:position + 1])
            name = left if re.fullmatch(NAME, left) else declaration.group(2) if declaration else None
            if name is None:
                self.expression(start, position, state, bindings, depth + 1)
            value = self.expression(position + 1, end, state, bindings, depth + 1)
            if name:
                key = self.key(name, bindings)
                previous = state.values.get(key, Value())
                state.values[key] = replace(value, origins=value.origins or previous.origins)
            return value
        question = self.operator(start, end, ("?",))
        if question:
            position, _ = question
            cursor, nesting = position + 1, 1
            while cursor < end:
                if cursor in self.parser.pairs:
                    cursor = self.parser.pairs[cursor] + 1
                    continue
                if self.code[cursor] == "?" and self.code[cursor:cursor + 2] not in {"??", "?.", "?["} and self.code[cursor - 1:cursor] != "?":
                    nesting += 1
                elif self.code[cursor] == ":" and self.code[cursor:cursor + 2] != "::" and self.code[cursor - 1:cursor] != ":":
                    nesting -= 1
                    if nesting == 0:
                        yes, no = self.condition(start, position, state, bindings, depth + 1)
                        values = [self.expression(position + 1, cursor, branch, bindings, depth + 1) for branch in yes]
                        values.extend(self.expression(cursor + 1, end, branch, bindings, depth + 1) for branch in no)
                        self.join_into(state, yes + no)
                        return self.merged(values)
                cursor += 1
        if self.operator(start, end, ("||", "&&")):
            yes, no = self.condition(start, end, state, bindings, depth + 1)
            self.join_into(state, yes + no)
            return Value(NONNULL)
        coalesce = self.operator(start, end, ("??",))
        if coalesce:
            position, _ = coalesce
            left = self.expression(start, position, state, bindings, depth + 1)
            name_start, name_end = self.trim(start, position)
            name = self.code[name_start:name_end]
            direct = re.fullmatch(NAME, name)
            present = self.refine(state, name, bindings, NONNULL) if direct else [state.copy()] if left.nulls & NONNULL else []
            absent = self.refine(state, name, bindings, NULL) if direct else [state.copy()] if left.nulls & NULL else []
            values = [replace(left, nulls=NONNULL)] if present else []
            values.extend(self.expression(position + 2, end, branch, bindings, depth + 1) for branch in absent)
            self.join_into(state, present + absent)
            return self.merged(values)
        byref = re.fullmatch(rf"(?:ref|out)\s+({NAME})", code)
        if byref:
            key = self.key(byref.group(1), bindings)
            value = replace(state.values.get(key, Value()), nulls=MAYBE)
            state.values[key] = value
            return value
        if code.endswith("!"):
            # Null-forgiving changes compiler annotations, not runtime values.
            return self.expression(start, end - 1, state, bindings, depth + 1)
        if code in {"true", "false"}:
            return Value(NONNULL)
        if re.fullmatch(NAME, code):
            return Value(NULL) if code == "null" else state.values.get(self.key(code, bindings), Value())
        literal = re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[mMdDfFlLuU]*", code)
        original = self.text[start:end]
        string_literal = re.match(r'(?:\$+@?|@\$?)?["\']', original) and original.endswith(('"', "'"))
        result = Value(NONNULL) if literal or string_literal else Value()
        allocation = re.match(r"new\s+(" + TYPE + r")\s*(?=[([{])", code)
        if allocation:
            cursor = start + allocation.end()
            first = cursor
            if cursor in self.parser.pairs:
                cursor = self.parser.skip(self.parser.pairs[cursor] + 1, end)
                if self.code[cursor:cursor + 1] == "{" and cursor in self.parser.pairs:
                    cursor = self.parser.skip(self.parser.pairs[cursor] + 1, end)
                nullable = allocation.group(1).endswith("?") or "Nullable<" in allocation.group(1)
                if cursor == end and not (nullable and not self.code[first + 1:self.parser.pairs[first]].strip()):
                    result = Value(NONNULL)
        # A callback body is a different execution scope. Its return and
        # assignments cannot terminate or repair the surrounding guard path.
        if self.operator(start, end, ("=>",)) or re.match(r"(?:async\s+)?delegate\b", code):
            for key in self.parser.deferred:
                function = self.parser.functions[key]
                if start <= function.key < function.end <= end:
                    local = dict(bindings)
                    local.update({name: f"{name}@param:{function.key}" for name in function.parameters})
                    for name, spelling in zip(function.parameters, function.parameter_types):
                        self.typed(local[name], spelling)
                    self.walk(function.body, [state.copy()], local, depth + 1)
            return Value(NONNULL)
        cursor = start
        while cursor < end:
            self.budget.spend()
            word = re.match(IDENT, self.code[cursor:end])
            if word:
                name = word.group(0)
                following = cursor + word.end()
                while following < end and self.code[following].isspace():
                    following += 1
                field = re.match(rf"\.\s*({IDENT})", self.code[following:end]) if name == "this" else None
                if field:
                    name = "this." + field.group(1)
                    following += field.end()
                    while following < end and self.code[following].isspace():
                        following += 1
                if name in {"nameof", "typeof", "sizeof"} and following in self.parser.pairs:
                    cursor = self.parser.pairs[following] + 1
                    continue
                suffix = self.code[following:end]
                if suffix.startswith("!") and not suffix.startswith("!="):
                    suffix = suffix[1:].lstrip()
                key = self.key(name, bindings)
                value = state.values.get(key, Value())
                member = re.match(r"\.\s*([A-Za-z_]\w*)", suffix)
                safe_nullable = (key in self.nullable_values and member
                                 and member.group(1) in {"HasValue", "GetValueOrDefault", "ToString", "GetHashCode", "Equals"})
                dereference = (member and not safe_nullable) or suffix.startswith("[")
                previous = self.code[:cursor].rstrip()[-1:]
                if dereference and previous not in {".", "@"} and value.nulls & NULL:
                    for origin in value.origins:
                        line, column = line_col(self.text, cursor)
                        self.findings.add((origin, line, column, MESSAGES[origin].format(name=name)))
                cursor = following
                continue
            if cursor in self.parser.pairs:
                close = self.parser.pairs[cursor]
                for low, high in parts(self.code, cursor + 1, close):
                    self.expression(low, high, state, bindings, depth + 1)
                low, high = self.trim(cursor + 1, close)
                inner = self.code[low:high].rstrip("!").rstrip()
                suffix = self.code[close + 1:end].lstrip()
                if self.code[cursor] == "(" and re.fullmatch(NAME, inner) and suffix.startswith((".", "[")):
                    key = self.key(inner, bindings)
                    value = state.values.get(key, Value())
                    safe = key in self.nullable_values and re.match(r"\.\s*(?:HasValue|GetValueOrDefault|ToString|GetHashCode|Equals)\b", suffix)
                    if value.nulls & NULL and not safe:
                        line, column = line_col(self.text, low)
                        for origin in value.origins:
                            self.findings.add((origin, line, column, MESSAGES[origin].format(name=inner)))
                cursor = close + 1
            else:
                cursor += 1
        return result

    def walk(self, statements, states, bindings, depth=0):
        if depth > 96:
            raise AnalysisLimit("C# statement nesting limit exceeded; null analysis is incomplete")
        snapshots, local, labels = [], dict(bindings), {}
        for index, statement in enumerate(statements):
            self.declare(statement, local)
            if statement.kind == "declarations":
                for child in statement.body:
                    self.declare(child, local)
            snapshots.append(dict(local))
            if statement.kind == "label":
                label = self.code[statement.start:statement.end].split(":", 1)[0].strip().lstrip("@")
                labels[label] = index
        pending = [(0, state) for state in states]
        seen, result = set(), []
        while pending:
            self.budget.spend()
            index, state = pending.pop()
            if state.exit.startswith("goto:") and state.exit[5:] in labels:
                index, state = labels[state.exit[5:]], state.copy()
                state.exit = ""
            if state.exit or index == len(statements):
                result.append(state)
                continue
            signature = index, state.signature()
            if signature in seen:
                continue
            seen.add(signature)
            for branch in self.statement(statements[index], state, snapshots[index], depth + 1):
                pending.append((index + 1, branch))
        return self.unique(result)

    def statement(self, statement, state, bindings, depth):
        self.budget.spend()
        kind, start, end = statement.kind, statement.start, statement.end
        if self.exceptions:
            self.exceptions[-1].append(state.copy())
        if kind in {"definition", "label"}:
            return [state]
        if kind == "unsupported-goto":
            raise ValueError("C# goto case/default needs switch-target analysis; null analysis is incomplete")
        if kind in {"block", "declarations"}:
            return self.walk(statement.body, [state], bindings, depth)
        if kind == "if":
            yes, no = self.condition(*statement.header, state, bindings)
            return self.unique(self.walk(statement.body, yes, bindings, depth)
                               + self.walk(statement.otherwise, no, bindings, depth))
        if kind in {"while", "for", "foreach", "do"}:
            bindings = dict(bindings)
            condition, update = statement.header, None
            if kind == "for":
                initial, condition, update = tuple(parts(self.code, *statement.header, separator=";"))
                self.declare(Statement(*initial), bindings)
                self.expression(*initial, state, bindings)
            if kind == "foreach":
                declaration = re.match(rf"\s*({TYPE})\s+({IDENT})\s+in\b", self.code[slice(*condition)])
                if declaration:
                    name = declaration.group(2).lstrip("@")
                    bindings[name] = f"{name}@{condition[0]}"
                    self.typed(bindings[name], declaration.group(1))
                    self.expression(condition[0] + declaration.end(), condition[1], state, bindings)
            pending, seen, result = [state], set(), []
            first = kind == "do"
            while pending:
                current = pending.pop()
                signature = current.signature(), first
                if signature in seen:
                    continue
                seen.add(signature)
                if first or kind == "foreach" or not self.code[slice(*condition)].strip():
                    yes, no = [current], [current.copy()] if kind == "foreach" else []
                else:
                    yes, no = self.condition(*condition, current, bindings)
                first = False
                result.extend(no)
                for branch in self.walk(statement.body, yes, bindings, depth):
                    if branch.exit == "break":
                        branch.exit = ""
                        result.append(branch)
                    elif branch.exit in {"", "continue"}:
                        branch.exit = ""
                        if update:
                            self.expression(*update, branch, bindings)
                        pending.append(branch)
                    else:
                        result.append(branch)
            return self.unique(result)
        if kind == "switch":
            self.expression(*statement.header, state, bindings)
            result = [] if re.search(r"\bdefault\s*:", self.code[start:end]) else [state.copy()]
            for arm in statement.body:
                for branch in self.walk(arm.body, [state.copy()], bindings, depth):
                    if branch.exit == "break":
                        branch.exit = ""
                    result.append(branch)
            return self.unique(result)
        if kind == "try":
            thrown = [state.copy()]
            self.exceptions.append(thrown)
            result = self.walk((statement.body[0],), [state.copy()], bindings, depth)
            self.exceptions.pop()
            thrown.extend(branch for branch in result if branch.exit == "throw")
            for handler in statement.body[1:]:
                entries = [branch.copy() for branch in self.unique(thrown)]
                for branch in entries:
                    branch.exit = ""
                result.extend(self.walk((handler,), entries, bindings, depth))
            if statement.otherwise:
                final = []
                for branch in self.unique(result):
                    abrupt, branch.exit = branch.exit, ""
                    for cleaned in self.walk(statement.otherwise, [branch], bindings, depth):
                        cleaned.exit = cleaned.exit or abrupt
                        final.append(cleaned)
                result = final
            return self.unique(result)
        if kind == "catch":
            if statement.otherwise:
                raise ValueError("C# catch filters need exception-search flow; null analysis is incomplete")
            bindings = dict(bindings)
            declaration = re.fullmatch(rf"\s*({TYPE})\s+({IDENT})\s*", self.code[slice(*statement.header)])
            if declaration:
                name = declaration.group(2).lstrip("@")
                key = f"{name}@{statement.header[0]}"
                bindings[name] = key
                state.values[key] = Value(NONNULL)
            return self.walk(statement.body, [state], bindings, depth)
        if kind in {"using", "lock", "fixed"}:
            self.expression(*statement.header, state, bindings)
            return self.walk(statement.body, [state], bindings, depth)
        if kind in {"break", "continue", "goto"}:
            state.exit = ("goto:" + self.code[start:end].split()[1].lstrip("@")) if kind == "goto" else kind
        else:
            expression_start = start + len(kind) if kind in {"return", "throw"} and re.match(kind + r"\b", self.code[start:end]) else start
            self.expression(expression_start, end, state, bindings)
            if kind in {"return", "throw"}:
                state.exit = kind
        return [state]

    def function_bindings(self, function):
        owner = min((opening for opening in self.fields if opening < function.start < self.parser.pairs[opening]),
                    key=lambda opening: self.parser.pairs[opening] - opening, default=None)
        bindings = dict(self.fields.get(owner, {}))
        bindings.update({"this." + name: key for name, key in self.fields.get(owner, {}).items()})
        if function.parent is not None:
            parent = self.parser.functions[function.parent]
            bindings = self.function_bindings(parent)

            def enclosing(statements):
                for statement in statements:
                    if statement.start > function.key:
                        break
                    self.declare(statement, bindings)
                    if statement.kind == "declarations":
                        for child in statement.body:
                            if child.start < function.key:
                                self.declare(child, bindings)
                    if statement.start <= function.key < statement.end:
                        if statement.kind == "foreach":
                            declaration = re.match(rf"\s*({TYPE})\s+({IDENT})\s+in\b",
                                                   self.code[slice(*statement.header)])
                        elif statement.kind == "catch":
                            declaration = re.fullmatch(rf"\s*({TYPE})\s+({IDENT})\s*",
                                                       self.code[slice(*statement.header)])
                        else:
                            declaration = None
                        if declaration:
                            name = declaration.group(2).lstrip("@")
                            bindings[name] = f"{name}@{statement.header[0]}"
                            self.typed(bindings[name], declaration.group(1))
                        if statement.kind == "for":
                            initial = next(parts(self.code, *statement.header, separator=";"))
                            self.declare(Statement(*initial), bindings)
                        enclosing(statement.body)
                        enclosing(statement.otherwise)
                        break

            enclosing(parent.body)
        bindings.update({name: f"{name}@param:{function.key}" for name in function.parameters})
        for name, spelling in zip(function.parameters, function.parameter_types):
            self.typed(bindings[name], spelling)
        return bindings

    def scan(self):
        uncovered = [position for position in self.guards if not any(
            function.start <= position < function.end for function in self.parser.functions.values())]
        if any(any(opening < position < self.parser.pairs[opening] for opening in self.fields)
               for position in uncovered):
            raise ValueError("C# selected guard in an unsupported executable scope; null analysis is incomplete")
        for function in self.parser.functions.values():
            nested = [other for other in self.parser.functions.values() if other.parent == function.key]
            if not any(function.start <= position < function.end and not any(
                other.declaration <= position < other.end for other in nested
            ) for position in self.guards):
                continue
            bindings = self.function_bindings(function)
            remaining = self.walk(function.body, [State()], bindings)
            if any(state.exit.startswith("goto:") for state in remaining):
                raise ValueError("Unresolved C# goto target; null analysis is incomplete")
        # Top-level .csx and modern C# statements have their own scope.
        if uncovered:
            remaining = self.walk(self.parser.block(0, len(self.code)), [State()], {})
            if any(state.exit.startswith("goto:") for state in remaining):
                raise ValueError("Unresolved C# goto target; null analysis is incomplete")
        return sorted(self.findings, key=lambda finding: (finding[1], finding[2], finding[0]))


def iter_csharp_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {".cs", ".csx"} and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for ext in ("*.cs", "*.csx"):
        for path in root.rglob(ext):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def scan_text(text: str) -> list[tuple[str, int, int, str]]:
    """Return (kind, line, col, message) findings for one file's text."""
    if not re.search(r"\b(?:if|while|for)\s*\(", text) or not GUARD_EVIDENCE.search(text):
        return []
    # Demand discovery does not execute compile-time alternatives. It only
    # checks whether this analyzer has an obligation at all; if it does, the
    # real lexer below still rejects an unconfigured conditional source view.
    discovery = re.sub(r"(?m)^[ \t]*#[^\r\n]*", lambda match: " " * len(match[0]), text)
    code = masked_source(discovery)
    if not guard_positions(code, pairs(code)):
        return []
    return GuardFlow(text).scan()


def analyze_file(path: Path) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [(line, col, message) for _, line, col, message in scan_text(text)]


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: type_narrowing_csharp.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    base = root if root.is_dir() else root.parent
    for path in iter_csharp_files(root):
        try:
            issues = analyze_file(path)
        except OSError:
            continue
        try:
            display = path.relative_to(base)
        except ValueError:
            display = path
        for line, col, message in issues:
            print(f"{display}:{line}:{col}\twarning\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(cwd)) if path.is_relative_to(cwd) else str(path)
        for kind, line, col, message in scan_text(text):
            yield {
                "rule": f"csharp.narrowing.{kind}",
                "path": rel,
                "line": line,
                "layer": "narrowing",
                "lang": "csharp",
                "col": col,
                "severity": "warning",
                "message": message,
            }


def _selftest_detects_non_exiting_null_guard() -> None:
    code = "class A { int F(string raw) { if (raw == null) { log(raw); } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "negative_guard"
    assert line == 1
    assert message == "raw dereferenced after non-exiting null/empty guard"


def _selftest_exiting_guard_suppresses() -> None:
    code = "class A { int F(string raw) { if (raw == null) { return 0; } return raw.Length; } }"
    assert scan_text(code) == []


def _selftest_positive_guard_fallthrough() -> None:
    code = "class A { int F(string raw) { if (raw != null) { return raw.Length; } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, _line, _col, message = findings[0]
    assert kind == "positive_guard"
    assert message == "raw dereferenced after positive null guard without narrowing the fallthrough path"


def _selftest_trygetvalue_guard() -> None:
    code = (
        "class A {\n"
        "  int F(Dictionary<string, int> map, string key) {\n"
        "    if (!map.TryGetValue(key, out var token)) { log(); }\n"
        "    return token.Length;\n"
        "  }\n"
        "}"
    )
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "try_get_value"
    assert line == 4
    assert message == "token used after non-exiting TryGetValue guard"


def _selftest_run(tmp_prefix: str = "ubs_core_narrowing_csharp_") -> None:
    import tempfile

    code = (
        "class A {\n"
        "  int F(string raw) {\n"
        "    if (raw == null) { log(raw); }\n"
        "    return raw.Length;\n"
        "  }\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.narrowing.negative_guard"
    assert findings[0]["line"] == 4
    assert findings[0]["path"] == str(target)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("detects_non_exiting_null_guard", _selftest_detects_non_exiting_null_guard),
    ("exiting_guard_suppresses", _selftest_exiting_guard_suppresses),
    ("positive_guard_fallthrough", _selftest_positive_guard_fallthrough),
    ("trygetvalue_guard", _selftest_trygetvalue_guard),
    ("run_finds_non_exiting_guard", _selftest_run),
)

register(Analyzer(layer="narrowing", lang="csharp", name="narrowing_csharp", run=run, selftests=SELF_TESTS))
