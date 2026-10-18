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

_NEGATIVE_GUARD_MESSAGE = "{name} may be null at this dereference after a null/empty guard"
_POSITIVE_GUARD_MESSAGE = "{name} may be null at this dereference; the positive guard does not prove it safe"
_TRY_GET_VALUE_MESSAGE = "{name} may be null after TryGetValue; check the value as well as lookup success"
MESSAGES = {"negative_guard": _NEGATIVE_GUARD_MESSAGE,
            "positive_guard": _POSITIVE_GUARD_MESSAGE, "try_get_value": _TRY_GET_VALUE_MESSAGE}
NULL, NONNULL, MAYBE = 1, 2, 3
IDENT = r"@?[A-Za-z_]\w*"
NAME = rf"(?:this\s*\.\s*)?{IDENT}"
QUALIFIED_NAME = rf"(?:{IDENT}\s*\.\s*)*{IDENT}"
CALL_NAME = rf"(?:global\s*::\s*)?{QUALIFIED_NAME}"
TYPE = rf"(?:{IDENT}\s*::\s*)?[\w.@]+(?:\s*<[^;=]+>)?(?:\[\])?\??"
DECLARATION = re.compile(rf"\s*(?:(?:using|await|const)\s+)*({TYPE})\s+({IDENT})\s*(?:=|,|;|$)")
VALUE_TYPES = frozenset("bool byte sbyte short ushort int uint long ulong float double decimal char nint nuint".split())
FIELD = re.compile(rf"({TYPE})\s+({IDENT})\s*(?=[,;={{])")
GUARD_EVIDENCE = re.compile(r"(?:==|!=|\bis(?:\s+not)?)\s*null\b|\bnull\s*(?:==|!=)"
                            r"|\bstring\.IsNullOr(?:Empty|WhiteSpace)\s*\(|\.TryGetValue\s*\(")


def guard_positions(code, delimiters):
    return tuple(match.start() for match in re.finditer(r"\b(?:if|while|for)\s*\(", code)
                 if GUARD_EVIDENCE.search(code[match.end():delimiters[match.end() - 1]]))


@dataclass(frozen=True)
class Value:
    nulls: int = MAYBE
    origins: frozenset[str] = frozenset()
    callables: frozenset[int] = frozenset()
    opaque_callable: bool = False


@dataclass
class State:
    values: dict[str, Value] = field(default_factory=dict)
    exit: str = ""

    def copy(self):
        return State(dict(self.values), self.exit)

    def signature(self):
        return self.exit, tuple(sorted(self.values.items()))


class NarrowingLimit(AnalysisLimit):
    """An incomplete file still owns its independently established findings."""

    def __init__(self, message, findings=()):
        super().__init__(message)
        self.findings = tuple(findings)


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
                low = self.skip(low, high)
                while self.code[low:low + 1] == "[" and low in self.pairs:
                    low = self.skip(self.pairs[low] + 1, high)
                _, stop = next(parts(self.code, low, high, separator="=", generics=True))
                spelling = self.code[low:stop].strip()
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
            signature = re.match(rf"{IDENT}(?:\s*<[^();{{}}]+>)?\s*\(",
                                 self.code[function.key:function.start])
            if signature:
                opening = function.key + signature.end() - 1
                declared = parameters(opening, self.pairs[opening])
                if tuple(name for name, _type in declared) == function.parameters:
                    function.parameter_types = tuple(type_ for _name, type_ in declared)
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
        switch = re.match(r"switch\s*\(", self.code[start:end])
        if switch:
            opening = start + switch.end() - 1
            close = self.pairs[opening]
            body_start = self.skip(close + 1, end)
            if self.code[body_start:body_start + 1] != "{":
                raise AnalysisLimit("Unsupported C# switch body; null analysis is incomplete")
            body_end = self.pairs[body_start]
            labels, cursor = [], body_start + 1
            while cursor < body_end:
                if cursor in self.pairs:
                    cursor = self.pairs[cursor] + 1
                    continue
                label = re.match(r"(?:case\s+[^:;{}]+|default)\s*:", self.code[cursor:body_end])
                if label:
                    labels.append((cursor, cursor + label.end()))
                    cursor += label.end()
                elif re.match(r"case\b", self.code[cursor:body_end]):
                    return Statement(start, body_end + 1, "unsupported-switch"), body_end + 1
                else:
                    cursor += 1
            arms = []
            for index, (low, high) in enumerate(labels):
                stop = labels[index + 1][0] if index + 1 < len(labels) else body_end
                arms.append(Statement(high, stop, "block", self.block(high, stop), header=(low, high - 1)))
            return Statement(start, body_end + 1, "switch", tuple(arms), header=(opening + 1, close)), body_end + 1
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
                    conditional = re.match(r"when\s*\(", self.code[position:end])
                    if not conditional:
                        raise AnalysisLimit("Malformed C# catch filter; null analysis is incomplete")
                    opening = position + conditional.end() - 1
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
        self.methods = {(".".join(function.owner), function.name) for function in self.parser.functions.values()
                        if function.owner and function.parent is None}
        self.guards = guard_positions(self.code, self.parser.pairs)
        self.budget = Budget()
        self.nullable_values: set[str] = set()
        self.declared_types: dict[str, str] = {}
        self.type_names = {name for low, _high, name in self.parser.types
                           if re.match(r"(?:class|struct|record|interface)\b", self.code[low:])}
        self.type_paths = {".".join(owner for begin, finish, owner in self.parser.types if begin <= low < finish)
                           for low, _high, _name in self.parser.types
                           if re.match(r"(?:class|struct|record|interface)\b", self.code[low:])}
        self.value_type_paths = {".".join(owner for begin, finish, owner in self.parser.types if begin <= low < finish)
                                 for low, _high, _name in self.parser.types if re.match(r"struct\b", self.code[low:])}
        self.type_aliases = {match.group(1).lstrip("@") for match in
                             re.finditer(rf"\busing\s+({IDENT})\s*=", self.code)}
        self.fields: dict[int, dict[str, str]] = {}
        self.owner_fields: dict[str, dict[str, str]] = {}
        self.static_fields: dict[str, dict[str, str]] = {}
        self.properties: set[str] = set()
        self.property_accessors: dict[str, dict[str, tuple[int, ...]]] = {}
        self.property_unparsed: dict[str, frozenset[str]] = {}
        static_keys = set()
        braces = [(low, high) for low, high in self.parser.pairs.items() if self.code[low] == "{"]
        for low, high, _name in self.parser.types:
            if not re.match(r"(?:class|struct|record)\b", self.code[low:]):
                continue
            opening = self.code.find("{", low, high)
            fields = {}
            static = {}
            claimed = opening
            for match in FIELD.finditer(self.code, opening + 1, high):
                if match.start() < claimed or any(opening < child < match.start() < close <= high for child, close in braces):
                    continue
                names = [match.group(2)]
                property_ = (self.code[match.end():match.end() + 1] == "{"
                             or self.code.startswith("=>", match.end()))
                if self.code[match.end():match.end() + 1] != "{":
                    claimed = self.parser.end_statement(match.start(), high)
                    for begin, finish in tuple(parts(self.code, match.start(), claimed, generics=True))[1:]:
                        declarator = re.match(rf"\s*({IDENT})\s*(?:=|$)", self.code[begin:finish])
                        if declarator:
                            names.append(declarator.group(1))
                for name in names:
                    name = name.lstrip("@")
                    key = f"field:{opening}:{name}"
                    fields[name] = key
                    self.typed(key, match.group(1))
                    if property_:
                        self.properties.add(key)
                        stop = self.parser.pairs.get(match.end(), claimed)
                        self.budget.spend(len(self.parser.functions) + 1)
                        accessors = [function for function in self.parser.functions.values()
                                     if match.end() < function.key < stop
                                     and re.match(r"(?:get|set|init)\s*\{", self.code[function.key:])]
                        self.property_accessors[key] = {
                            kind: tuple(function.key for function in accessors if function.name == kind)
                            for kind in {function.name for function in accessors}}
                        arrows = {"get"} if self.code.startswith("=>", match.end()) else set()
                        cursor = match.end() + 1
                        while cursor < stop:
                            self.budget.spend()
                            if cursor in self.parser.pairs:
                                cursor = self.parser.pairs[cursor] + 1
                                continue
                            arrow = re.match(r"(get|set|init)\s*=>", self.code[cursor:stop])
                            if arrow:
                                arrows.add(arrow.group(1))
                            cursor += 1
                        self.property_unparsed[key] = frozenset(arrows)
                    if re.search(r"\bstatic\b", self.code[self.parser.boundary(match.start()):match.start()]):
                        static[name] = key
                        static_keys.add(key)
            self.fields[opening] = fields
            owner_path = ".".join(owner for begin, finish, owner in self.parser.types if begin <= low < finish)
            self.owner_fields.setdefault(owner_path, {}).update(fields)
            if _name in self.static_fields or _name in self.type_aliases:
                self.static_fields[_name] = {}
            else:
                self.static_fields[_name] = static
        self.findings: set[tuple[str, int, int, str]] = set()
        self.exceptions: list[list[State]] = []
        self.failures: list[str] = []
        self.active_function: Function | None = None
        self.write_summaries: dict[int, dict[str, int]] = {}
        self.call_index: dict[str, list[Function]] = {}
        self.variadic_functions: set[int] = set()
        for function in self.parser.functions.values():
            self.call_index.setdefault(function.name, []).append(function)
            opening = self.code.find("(", function.key, function.start)
            if opening >= 0 and re.search(r"\bparams\b", self.code[opening + 1:self.parser.pairs[opening]]):
                self.variadic_functions.add(function.key)
        self.static_keys = frozenset(static_keys)

    @staticmethod
    def key(name, bindings):
        name = re.sub(r"\s|@", "", name)
        return bindings.get(name, "field:" + name.removeprefix("this."))

    @staticmethod
    def bound_name(name, bindings):
        normalized = re.sub(r"\s|@", "", name)
        return (re.fullmatch(NAME, name) is not None
                or (normalized in bindings and normalized.split(".", 1)[0] not in bindings))

    def type_owner(self, spelling, position):
        """Resolve a source-declared type without confusing namespace suffixes."""
        spelling = re.sub(r"\s+|<.*>|\?$", "", spelling)
        if spelling.startswith("global::"):
            name = spelling.removeprefix("global::")
            return name if name in self.type_paths else ""
        if spelling.split(".", 1)[0].lstrip("@") in self.type_aliases:
            return ""
        self.budget.spend(len(self.parser.types) + 1)
        scope = [piece for low, high, owner in self.parser.types if low <= position < high
                 for piece in owner.split(".")]
        for count in range(len(scope), -1, -1):
            name = ".".join((*scope[:count], spelling))
            if name in self.type_paths:
                return name
        return ""

    def receiver_owner(self, receiver, bindings, position=0):
        key = self.key(receiver, bindings)
        spelling = self.declared_types.get(key, "")
        location = re.search(r"(?:^field:|@(?:param:)?)(\d+)", key)
        if spelling and location:
            position = int(location.group(1))
        if (not spelling and re.fullmatch(CALL_NAME, receiver)
                and receiver.split(".", 1)[0] not in bindings):
            spelling = receiver
        return self.type_owner(spelling, position) if spelling else ""

    def method_member(self, receiver, member, bindings, position=0):
        return (self.receiver_owner(receiver, bindings, position), member.lstrip("@")) in self.methods

    def property_key(self, name, bindings, position=0):
        key = self.key(name, bindings)
        if key in self.properties:
            return key
        receiver, _, member = re.sub(r"\s|@", "", name).rpartition(".")
        if receiver:
            owner = self.receiver_owner(receiver, bindings, position)
            return self.owner_fields.get(owner, {}).get(member, "")
        return ""

    def accessor_targets(self, key, kind):
        kinds = ("set", "init") if kind == "set" else (kind,)
        if any(item in self.property_unparsed.get(key, ()) for item in kinds):
            raise AnalysisLimit("C# expression accessor effects need callable flow; null analysis is incomplete")
        return tuple(self.parser.functions[function] for item in kinds
                     for function in self.property_accessors.get(key, {}).get(item, ()))

    def property_access(self, name, state, bindings, kind="get", position=0, fresh=False, guard=False):
        key = self.property_key(name, bindings, position)
        if key not in self.properties:
            return
        accessors = self.accessor_targets(key, kind)
        for function in accessors:
            self.apply_writes(self.call_writes(function), state, fresh)
        if kind == "get" and accessors:
            masks = []
            for function in accessors:
                body = [item for item in function.body if item.kind != "definition"]
                if body and body[-1].kind == "return" and all(item.kind in {"simple", "declarations"} for item in body[:-1]):
                    last = body[-1]
                    low = last.start + (6 if re.match(r"return\b", self.code[last.start:last.end]) else 0)
                    masks.append(self.literal_nulls(low, last.end))
                else:
                    masks.append(MAYBE)
            nulls = (NULL if any(mask & NULL for mask in masks) else 0) | (NONNULL if any(mask & NONNULL for mask in masks) else 0)
            previous = state.values.get(key, Value())
            if nulls == MAYBE and (guard or previous.origins):
                raise AnalysisLimit("C# unstable property guard needs getter return flow; null analysis is incomplete")
            if not fresh:
                state.values[key] = replace(previous, nulls=nulls)
        if accessors:
            self.note_exception(state)

    def initializer_entries(self, start, end):
        entries, cursor, beginning = [], start, start
        while cursor < end:
            self.budget.spend()
            if cursor in self.parser.pairs:
                cursor = self.parser.pairs[cursor] + 1
                continue
            generic = re.match(r"<[\w@.,<>\[\]?\s:]+>\s*(?=[(.{\[])", self.code[cursor:end])
            if generic:
                cursor += generic.end()
                continue
            if self.code[cursor] == ",":
                entries.append((beginning, cursor))
                beginning = cursor + 1
            cursor += 1
        entries.append((beginning, end))
        return entries

    def object_initializer(self, start, end, state, bindings, depth, owner="", anonymous=False):
        """Visit fresh receiver member initializers without rebinding caller names."""
        if depth > 96:
            raise AnalysisLimit("C# initializer nesting limit exceeded; null analysis is incomplete")
        fields = self.owner_fields.get(owner, {})
        for low, high in self.initializer_entries(start, end):
            if state.exit:
                break
            low, high = self.trim(low, high)
            if low == high:
                continue
            assignment = self.operator(low, high, ("=",))
            if assignment is None:
                self.expression(low, high, state, bindings, depth + 1)
                if not anonymous:
                    self.note_exception(state)
                continue
            equals, _ = assignment
            target = self.code[low:equals].strip()
            key = fields.get(target.lstrip("@"))
            first, last = self.trim(equals + 1, high)
            if target.startswith("["):
                opening, closing = self.trim(low, equals)
                if self.parser.pairs.get(opening) != closing - 1:
                    raise AnalysisLimit("Unsupported C# initializer target; null analysis is incomplete")
                for left, right in parts(self.code, opening + 1, closing - 1):
                    self.expression(left, right, state, bindings, depth + 1)
            elif not re.fullmatch(IDENT, target):
                raise AnalysisLimit("Unsupported C# initializer target; null analysis is incomplete")
            if self.code[first:first + 1] == "{" and self.parser.pairs.get(first) == last - 1:
                if key is None or key in self.properties:
                    self.property_access(target, state, {**bindings, target: key or ""}, position=low, fresh=True)
                    self.note_exception(state)
                nested_owner = self.type_owner(self.declared_types.get(key, ""), first) if key else ""
                self.object_initializer(first + 1, last - 1, state, bindings, depth + 1, nested_owner)
            else:
                self.expression(first, last, state, bindings, depth + 1)
                if not anonymous and (key is None or key in self.properties) and not state.exit:
                    self.property_access(target, state, {**bindings, target: key or ""}, kind="set", position=low, fresh=True)
                    self.note_exception(state)

    def framework_identity(self, name, position, global_name=False):
        if global_name:
            return name not in self.type_paths
        self.budget.spend(len(self.parser.types) + 1)
        scope = [piece for low, high, owner in self.parser.types if low <= position < high
                 for piece in owner.split(".")]
        return not any(".".join((*scope[:count], name)) in self.type_paths
                       for count in range(len(scope) + 1))

    def typed(self, key, spelling):
        spelling = re.sub(r"\s+", "", spelling)
        if not spelling:
            return
        self.declared_types[key] = spelling
        builtin = spelling.endswith("?") and spelling[:-1] in VALUE_TYPES
        qualified = re.fullmatch(r"(global::)?System\.Nullable<.+>", spelling)
        location = re.search(r"(?:^field:|@(?:param:)?)(\d+)", key)
        position = int(location.group(1)) if location else 0
        framework = (qualified and self.framework_identity("System.Nullable", position, bool(qualified.group(1)))
                     and (qualified.group(1) or "System" not in self.type_names | self.type_aliases))
        if builtin or framework:
            self.nullable_values.add(key)

    def dictionary_value(self, receiver, bindings):
        key = self.key(receiver, bindings)
        spelling = self.declared_types.get(key, "")
        generic = re.fullmatch(r"((?:global::)?[\w.]+)<(.+)>\??", spelling)
        if not generic:
            return "", MAYBE
        name = generic.group(1)
        short = name.rsplit(".", 1)[-1]
        namespace = ("System.Collections.Concurrent" if short == "ConcurrentDictionary"
                     else "System.Collections.Generic")
        if short not in {"Dictionary", "IDictionary", "IReadOnlyDictionary", "SortedDictionary", "SortedList", "ConcurrentDictionary"}:
            return "", MAYBE
        if "." in name and name.removeprefix("global::") != namespace + "." + short:
            return "", MAYBE
        if "." not in name and short in self.type_names | self.type_aliases:
            return "", MAYBE
        location = re.search(r"(?:^field:|@(?:param:)?)(\d+)", key)
        position = int(location.group(1)) if location else 0
        if not self.framework_identity(namespace + "." + short, position, name.startswith("global::")):
            return "", MAYBE
        arguments = tuple(parts(spelling, generic.start(2), generic.end(2), generics=True))
        if len(arguments) != 2:
            return "", MAYBE
        value = spelling[slice(*arguments[1])]
        # Key presence returns the stored value. Reference annotations do not
        # prevent a dictionary from containing null at runtime.
        value_type = (value in VALUE_TYPES or (not value.endswith("?")
                      and self.type_owner(value, position) in self.value_type_paths))
        return value, NONNULL if value_type else MAYBE

    def function_owner(self, function):
        if function is None:
            return ""
        if function.owner:
            return ".".join(function.owner)
        return ".".join(owner for low, high, owner in self.parser.types if low < function.key < high)

    @staticmethod
    def borrowed_receiver(name, bindings):
        receiver = re.sub(r"\s|@", "", name).rpartition(".")[0]
        return bool(receiver and receiver not in {"this", "base"}
                    and (receiver in bindings or receiver.split(".", 1)[0] in bindings))

    def call_candidates(self, name, count, bindings, position, function, state=None, constructor=False):
        name = re.sub(r"\s|@", "", name)
        qualifier, _, short = name.rpartition(".")
        if constructor:
            owner = self.type_owner(name, position)
            short = short.removeprefix("global::")
            return [candidate for candidate in self.call_index.get(short, []) if candidate.parent is None
                    and owner and self.function_owner(candidate) == owner]
        direct_callable = name in bindings and self.bound_name(name, bindings)
        callable_name = name if direct_callable else qualifier if short == "Invoke" else ""
        value = state.values.get(self.key(callable_name, bindings), Value()) if state else Value()
        spelling = self.declared_types.get(self.key(callable_name, bindings), "")
        delegate = (re.fullmatch(r"(?:global::)?(?:System\.)?(?:Action|Func|Predicate|Comparison|Converter|EventHandler)(?:<.*>)?\??", spelling)
                    and not self.type_owner(spelling, position))
        if direct_callable or (short == "Invoke" and (value.callables or value.opaque_callable or delegate)):
            if value.opaque_callable or (not value.callables and value.nulls & NONNULL):
                raise AnalysisLimit("Unresolved C# callable effects; null analysis is incomplete")
            return [self.parser.functions[key] for key in value.callables]
        else:
            candidates = self.call_index.get(short, [])
            self.budget.spend(len(candidates) + 1)
            if not candidates:
                return []
            ancestors, current = [], function
            while current is not None:
                ancestors.append(current.key)
                current = self.parser.functions.get(current.parent)
            local = []
            if not qualifier:
                for candidate in candidates:
                    if candidate.parent not in ancestors:
                        continue
                    containers = [low for low, high in self.parser.pairs.items() if self.code[low] == "{"
                                  and low < candidate.declaration < high and low < position < high]
                    if containers:
                        declaration_scope = max(low for low, high in self.parser.pairs.items()
                                                if self.code[low] == "{" and low < candidate.declaration < high)
                        if declaration_scope == max(containers):
                            local.append((ancestors.index(candidate.parent), -declaration_scope, candidate))
            if local:
                rank = min((distance, scope) for distance, scope, _candidate in local)
                candidates = [candidate for distance, scope, candidate in local if (distance, scope) == rank]
            else:
                owner = (self.function_owner(function) if qualifier in {"", "this", "base"}
                         else self.receiver_owner(qualifier, bindings, position))
                candidates = [candidate for candidate in candidates if candidate.parent is None
                              and self.function_owner(candidate) == owner
                              and (owner or not qualifier)]
        return [candidate for candidate in candidates if count is None or (
            len(candidate.parameters) - candidate.defaults - int(candidate.key in self.variadic_functions) <= count
            and (count <= len(candidate.parameters) or candidate.key in self.variadic_functions))]

    def literal_nulls(self, start, end):
        start, end = self.trim(start, end)
        code, original = self.code[start:end], self.text[start:end]
        if code == "null":
            return NULL
        default = re.fullmatch(r"default\s*(?:\(([^)]*)\))?", code)
        if default:
            return NONNULL if (default.group(1) or "").strip() in VALUE_TYPES else MAYBE
        if (code in {"true", "false"} or re.fullmatch(r"\d+(?:\.\d+)?[mMdDfFlLuU]*", code)
                or (re.match(r'(?:\$+@?|@\$?)?["\']', original) and original.endswith(('"', "'")))):
            return NONNULL
        return MAYBE

    def deferred_functions(self, start, end):
        contained = [self.parser.functions[key] for key in self.parser.deferred
                     if start <= key < self.parser.functions[key].end <= end]
        return [function for function in contained if not any(
            other.start <= function.key < other.end for other in contained if other.key != function.key)]

    def summary_initializer(self, start, end, bindings, function, writes, calls, values, depth, owner="", anonymous=False):
        if depth > 96:
            raise AnalysisLimit("C# call-write initializer limit exceeded; null analysis is incomplete")
        fields = self.owner_fields.get(owner, {})
        for low, high in self.initializer_entries(start, end):
            low, high = self.trim(low, high)
            assignment = self.operator(low, high, ("=",))
            if assignment is None:
                self.summary_expression(low, high, bindings, function, writes, calls, values, depth + 1)
                if owner and not anonymous:
                    calls.update((callee.key, True, False) for callee in self.call_index.get("Add", ())
                                 if callee.parent is None and self.function_owner(callee) == owner)
                continue
            equals, _ = assignment
            target = self.code[low:equals].strip()
            if target.startswith("["):
                opening, closing = self.trim(low, equals)
                if self.parser.pairs.get(opening) != closing - 1:
                    raise AnalysisLimit("Unsupported C# initializer target; null analysis is incomplete")
                self.summary_expression(opening + 1, closing - 1, bindings, function, writes, calls, values, depth + 1)
            elif not re.fullmatch(IDENT, target):
                raise AnalysisLimit("Unsupported C# initializer target; null analysis is incomplete")
            key = fields.get(target.lstrip("@"))
            first, last = self.trim(equals + 1, high)
            nested = self.code[first:first + 1] == "{" and self.parser.pairs.get(first) == last - 1
            if key in self.properties:
                calls.update((callee.key, True, False) for callee in self.accessor_targets(key, "get" if nested else "set"))
            if nested:
                nested_owner = self.type_owner(self.declared_types.get(key, ""), first) if key else ""
                self.summary_initializer(first + 1, last - 1, bindings, function, writes, calls, values,
                                         depth + 1, nested_owner)
            else:
                self.summary_expression(first, last, bindings, function, writes, calls, values, depth + 1)

    def summary_expression(self, start, end, bindings, function, writes, calls, values, depth=0):
        self.budget.spend()
        if depth > 96:
            raise AnalysisLimit("C# call-write expression limit exceeded; null analysis is incomplete")
        start, end = self.trim(start, end)
        if re.match(r"ref\s+(?:readonly\s+)?" + TYPE + rf"\s+{IDENT}\b", self.code[start:end]):
            raise AnalysisLimit("C# ref-local write aliases need reference flow; null analysis is incomplete")
        items = tuple(parts(self.code, start, end, generics=bool(DECLARATION.match(self.code[start:end]))))
        if len(items) > 1:
            for low, high in items:
                self.summary_expression(low, high, bindings, function, writes, calls, values, depth + 1)
            return
        arrow = self.operator(start, end, ("=>",))
        assignment = self.operator(start, end, ("=",))
        if (arrow and (not assignment or arrow[0] < assignment[0])) or re.match(r"(?:async\s+)?delegate\b", self.code[start:end]):
            return
        cursor, initializers = start, {}
        while cursor < end:
            self.budget.spend()
            if cursor in self.parser.pairs:
                close = self.parser.pairs[cursor]
                if cursor in initializers:
                    owner, anonymous = initializers[cursor]
                    self.summary_initializer(cursor + 1, close, bindings, function, writes, calls, values,
                                             depth + 1, owner, anonymous)
                    cursor = close + 1
                    continue
                for low, high in parts(self.code, cursor + 1, close):
                    self.summary_expression(low, high, bindings, function, writes, calls, values, depth + 1)
                cursor = close + 1
                continue
            word = re.match(CALL_NAME, self.code[cursor:end])
            if not word:
                cursor += 1
                continue
            name = re.sub(r"\s|@", "", word.group())
            following = cursor + word.end()
            following = self.parser.skip(following, end)
            suffix = self.code[following:end]
            update = re.match(r"(?:\?\?=|[+*/%&|^\-]=|\+\+|--|=(?!=|>))", suffix)
            byref = re.search(r"\b(?:ref|out)\s+$", self.code[start:cursor])
            property_key = self.property_key(name, bindings, cursor)
            if property_key in self.properties:
                kinds = ("set",) if update and update.group() == "=" else ("get", "set") if update else ("get",)
                for kind in kinds:
                    calls.update((callee.key, False, self.borrowed_receiver(name, bindings))
                                 for callee in self.accessor_targets(property_key, kind))
            if (update or byref) and (self.bound_name(name, bindings) or "." in name):
                key = self.key(name, bindings) if self.bound_name(name, bindings) else "member:" + name.rsplit(".", 1)[-1]
                mask = self.literal_nulls(following + 1, end) if update and update.group() == "=" else MAYBE
                writes[key] = writes.get(key, 0) | mask
                if update and update.group() == "=":
                    low, high = self.trim(following + 1, end)
                    deferred = self.deferred_functions(low, high)
                    rhs = self.code[low:high]
                    if self.declared_types.get(key) == "var":
                        allocation = re.match(rf"new\s+({TYPE})\s*(?=[({{\[])", rhs)
                        inferred = (self.declared_types.get(self.key(rhs, bindings), "") if self.bound_name(rhs, bindings)
                                    else allocation.group(1) if allocation else "")
                        self.typed(key, inferred)
                    target = (Value(NONNULL, callables=frozenset(item.key for item in deferred)) if deferred
                              else Value(NONNULL, opaque_callable=True) if self.operator(low, high, ("=>",))
                              or re.match(r"(?:async\s+)?delegate\b", rhs)
                              else values.values.get(self.key(rhs, bindings), Value()) if self.bound_name(rhs, bindings)
                              else Value())
                    if (not target.callables and not target.opaque_callable and re.fullmatch(QUALIFIED_NAME, rhs)
                            and re.sub(r"\s|@", "", rhs) not in bindings):
                        target = replace(target, callables=frozenset(item.key for item in
                            self.call_candidates(rhs, None, bindings, low, function, values)))
                    previous = values.values.get(key, Value())
                    values.values[key] = self.merged((previous, target))
                    if deferred or target.opaque_callable:
                        return
            generic = re.match(r"<[\w@.,<>\[\]?\s:]+>\s*(?=\()", suffix)
            opening = following + generic.end() if generic else following
            construction = re.search(r"\bnew\s+$", self.code[start:cursor])
            if name == "new" and self.code[following:following + 1] == "{":
                initializers[following] = ("", True)
            elif name == "new" and self.code[following:following + 1] == "(":
                raise AnalysisLimit("C# target-typed constructor effects need expected-type flow; null analysis is incomplete")
            elif construction:
                first = self.parser.skip(self.parser.pairs[opening] + 1, end) if self.code[opening:opening + 1] == "(" else opening
                if self.code[first:first + 1] == "{" and first in self.parser.pairs:
                    initializers[first] = (self.type_owner(name + (generic.group().strip() if generic else ""), cursor), False)
                    if first == opening:
                        calls.update((callee.key, True, False) for callee in
                                     self.call_candidates(name, None, bindings, cursor, function, values, True))
            if self.code[opening:opening + 1] == "(" and opening in self.parser.pairs:
                close = self.parser.pairs[opening]
                if name in {"nameof", "typeof", "sizeof"}:
                    cursor = close + 1
                    continue
                count = len(tuple(parts(self.code, opening + 1, close)))
                constructor = bool(construction)
                calls.update((callee.key, constructor, not constructor and self.borrowed_receiver(name, bindings)) for callee in
                             self.call_candidates(name, count, bindings, cursor, function, values, constructor))
            cursor = following

    def direct_writes(self, function):
        writes, calls, values = {}, set(), State()

        def block(statements, bindings, depth=0):
            if depth > 96:
                raise AnalysisLimit("C# call-write statement limit exceeded; null analysis is incomplete")
            local = dict(bindings)
            for statement in statements:
                self.budget.spend()
                self.declare(statement, local)
                if statement.kind == "definition":
                    continue
                scope = dict(local)
                if statement.kind in {"using", "fixed", "for"}:
                    header = (next(parts(self.code, *statement.header, separator=";")) if statement.kind == "for"
                              else statement.header)
                    self.declare(Statement(*header), scope)
                elif statement.kind in {"foreach", "catch"}:
                    declaration = re.match(rf"\s*({TYPE})\s+({IDENT})\b", self.code[slice(*statement.header)])
                    if declaration:
                        name = declaration.group(2).lstrip("@")
                        scope[name] = f"{name}@{statement.header[0]}"
                        self.typed(scope[name], declaration.group(1))
                if statement.header != (0, 0):
                    for low, high in parts(self.code, *statement.header, separator=";"):
                        self.summary_expression(low, high, scope, function, writes, calls, values)
                if statement.kind in {"simple", "declarator", "return", "throw", "catch-filter"}:
                    self.summary_expression(statement.start, statement.end, scope, function, writes, calls, values)
                resources = self.using_resources(statement, scope)
                if statement.kind == "using":
                    resources = self.using_resources(Statement(*statement.header), scope, declaration_only=True)
                    if not resources:
                        low, high = self.trim(*statement.header)
                        if self.bound_name(self.code[low:high], scope):
                            resources = (self.key(self.code[low:high], scope),)
                calls.update((key, False, True) for key in self.resource_disposers(resources, statement.start,
                             bool(re.match(r"await\s+using\b", self.code[statement.start:statement.end]))))
                if statement.kind == "unsupported-switch":
                    raise AnalysisLimit("C# call writes in unsupported switch patterns; null analysis is incomplete")
                condition = self.code[slice(*statement.header)].strip()
                if statement.kind != "if" or condition != "false":
                    block(statement.body, scope, depth + 1)
                if statement.kind != "if" or condition != "true":
                    block(statement.otherwise, scope, depth + 1)

        block(function.body, self.function_bindings(function))
        return writes, calls

    def call_writes(self, function):
        """Union possible lexical writes through a bounded known-call graph.

        Applying these summaries can invalidate a proof, never establish one.
        Callee locals and by-value parameters retain their own binding keys.
        Borrowed receiver effects keep their field identity across construction;
        only writes to the newly allocated receiver may be discarded as fresh.
        """
        if function.key in self.write_summaries:
            return self.write_summaries[function.key]
        pending, graph, effects = [function], {}, {}
        while pending:
            current = pending.pop()
            if current.key in graph or current.key in self.write_summaries:
                continue
            direct, calls = self.direct_writes(current)
            graph[current.key], effects[current.key] = calls, direct
            pending.extend(self.parser.functions[key] for key, _constructor, _borrowed in calls)
        changed = True
        while changed:
            changed = False
            for key, calls in graph.items():
                for callee, constructor, borrowed in calls:
                    inherited = effects.get(callee, self.write_summaries.get(callee, {}))
                    self.budget.spend(len(inherited) + 1)
                    for binding, nulls in inherited.items():
                        if (constructor and binding not in self.static_keys
                                and not binding.startswith(("member:", "borrowed:"))):
                            continue
                        if borrowed and binding.startswith("field:") and binding not in self.static_keys:
                            binding = "borrowed:" + binding
                        joined = effects[key].get(binding, 0) | nulls
                        if joined != effects[key].get(binding, 0):
                            effects[key][binding] = joined
                            changed = True
        self.write_summaries.update(effects)
        return self.write_summaries[function.key]

    def apply_writes(self, writes, state, fresh=False):
        for key, nulls in writes.items():
            identity = key.removeprefix("borrowed:")
            affected = ([binding for binding in state.values if binding.startswith("field:")
                         and binding.endswith(":" + identity.removeprefix("member:"))]
                        if identity.startswith("member:") else [identity])
            for binding in affected:
                if binding not in state.values or (fresh and binding not in self.static_keys
                                                   and not key.startswith(("member:", "borrowed:"))):
                    continue
                value = state.values[binding]
                state.values[binding] = replace(value, nulls=value.nulls | nulls,
                                                opaque_callable=value.opaque_callable or bool(value.callables))

    def apply_call(self, name, opening, closing, state, bindings, position, constructor=False, call_state=None):
        if state.exit:
            return
        count = None if constructor else len(tuple(parts(self.code, opening + 1, closing)))
        for callee in self.call_candidates(name, count, bindings, position, self.active_function,
                                          call_state if call_state is not None else state, constructor):
            self.apply_writes(self.call_writes(callee), state, constructor)

    def call_arguments(self, opening, closing, state, bindings):
        """A ref/out address is evaluated earlier; its possible write is at invocation."""
        if state.exit:
            return
        for low, high in parts(self.code, opening + 1, closing):
            argument = re.fullmatch(rf"\s*(?:ref|out)\s+(?:(?:var|{TYPE})\s+)?({QUALIFIED_NAME})\s*", self.code[low:high])
            if argument and self.bound_name(argument.group(1), bindings):
                key = self.key(argument.group(1), bindings)
                previous = state.values.get(key, Value())
                state.values[key] = replace(previous, nulls=MAYBE,
                                            opaque_callable=previous.opaque_callable or bool(previous.callables))

    def declare(self, statement, bindings, spelling=""):
        if statement.kind == "declarations":
            first = statement.body[0]
            declaration = DECLARATION.match(self.code[first.start:first.end])
            spelling = declaration.group(1) if declaration else ""
            for child in statement.body:
                self.declare(child, bindings, spelling)
            return
        start, end = statement.header if statement.kind == "if" else (statement.start, statement.end)
        code = self.code[start:end]
        if statement.kind == "simple" and DECLARATION.match(code):
            items = tuple(parts(self.code, start, end, generics=True))
            if len(items) > 1:
                spelling = DECLARATION.match(code).group(1)
                for index, (low, high) in enumerate(items):
                    self.declare(Statement(low, high, "simple" if index == 0 else "declarator"), bindings, spelling)
                return
        match = (re.match(rf"\s*({IDENT})\s*(?:=|$)", code) if statement.kind == "declarator"
                 else DECLARATION.match(code) if statement.kind == "simple" else None)
        if match:
            group = 1 if statement.kind == "declarator" else 2
            name = match.group(group).lstrip("@")
            key = f"{name}@{start + match.start(group)}"
            bindings[name] = key
            self.typed(key, spelling if statement.kind == "declarator" else match.group(1))
        for match in re.finditer(rf"\bout\s+(var|{TYPE})\s+({IDENT})", code):
            name = match.group(2).lstrip("@")
            key = f"{name}@{start + match.start(2)}"
            bindings[name] = key
            self.typed(key, match.group(1))

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
                     origins=frozenset(origin for value in values for origin in value.origins),
                     callables=frozenset(key for value in values for key in value.callables),
                     opaque_callable=any(value.opaque_callable for value in values))

    def join_into(self, state, branches):
        if not branches:
            return
        normal = [branch for branch in branches if not branch.exit]
        state.exit = "" if normal else branches[0].exit
        branches = normal or branches
        keys = set().union(*(branch.values for branch in branches))
        state.values = {key: self.merged(branch.values.get(key, Value()) for branch in branches) for key in keys}

    def note_exception(self, state):
        if not self.exceptions:
            return
        pending = self.exceptions[-1]
        signature = state.signature()
        self.budget.spend(len(pending) + 1)
        if all(previous.signature() != signature for previous in pending):
            pending.append(state.copy())
            if len(pending) > 128:
                raise AnalysisLimit("C# exception-state budget exceeded; null analysis is incomplete")

    def access_end(self, start, end):
        """Find the end of a conditional member/index/invocation chain."""
        cursor = start
        while cursor < end:
            self.budget.spend()
            if cursor in self.parser.pairs:
                cursor = self.parser.pairs[cursor] + 1
                continue
            if self.code[cursor].isspace() or self.code[cursor] == ".":
                cursor += 1
                continue
            if self.code.startswith(("?.", "?["), cursor):
                cursor += 1
                continue
            if self.code[cursor] == "!" and not self.code.startswith("!=", cursor):
                cursor += 1
                continue
            word = re.match(IDENT, self.code[cursor:end])
            generic = re.match(r"<[\w@.,<>\[\]?\s:]+>\s*(?=\()", self.code[cursor:end])
            if word or generic:
                cursor += (word or generic).end()
                continue
            break
        return cursor

    def access_effects(self, start, end, state, bindings, depth, receiver=""):
        """A reached access chain evaluates arguments, never its member names as locals."""
        if depth > 96:
            raise AnalysisLimit("C# access nesting limit exceeded; null analysis is incomplete")
        cursor, call_receiver = start, receiver
        while cursor < end and not state.exit:
            self.budget.spend()
            if self.code.startswith(("?.", "?["), cursor):
                entered, bypass = state.copy(), state.copy()
                self.access_effects(cursor + 1, end, entered, bindings, depth + 1)
                self.join_into(state, [entered, bypass])
                return
            if cursor in self.parser.pairs:
                close = self.parser.pairs[cursor]
                call_state = state.copy()
                for low, high in parts(self.code, cursor + 1, close):
                    self.expression(low, high, state, bindings, depth + 1)
                    if state.exit:
                        break
                if self.code[cursor] == "(":
                    self.call_arguments(cursor, close, state, bindings)
                    before = self.code[start:cursor]
                    call = re.search(rf"({CALL_NAME})(?:\s*<[\w@.,<>\[\]?\s:]+>)?\s*$", before)
                    if call:
                        name = (call_receiver + "." if call_receiver and before.lstrip().startswith(".") else "") + call.group(1)
                        self.apply_call(name, cursor, close, state, bindings, start + call.start(1), call_state=call_state)
                self.note_exception(state)
                cursor = close + 1
            else:
                if self.code[cursor:cursor + 1] == ".":
                    member = re.match(rf"\.\s*({IDENT})(?:\s*<[^;=]+>)?\s*\(", self.code[cursor:end])
                    if not member or not self.method_member(receiver, member.group(1), bindings, cursor):
                        self.note_exception(state)
                    receiver = ""
                cursor += 1

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
        changed.values[key] = replace(previous, nulls=possible, origins=origins)
        return [changed]

    def condition(self, start, end, state, bindings, depth=0):
        if depth > 96:
            raise AnalysisLimit("C# guard nesting limit exceeded; analysis is incomplete")
        start, end = self.trim(start, end)
        if state.exit:
            return [], []
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
        comparison = re.fullmatch(rf"({QUALIFIED_NAME})\s*(==|!=|is\s+not|is)\s*null", code)
        reverse = re.fullmatch(rf"null\s*(==|!=)\s*({QUALIFIED_NAME})", code)
        if comparison or reverse:
            name, operator = comparison.groups() if comparison else (reverse.group(2), reverse.group(1))
            if self.bound_name(name, bindings):
                self.property_access(name, state, bindings, position=start, guard=True)
                negative = operator in {"==", "is"}
                origin = "negative_guard" if negative else "positive_guard"
                return (self.refine(state, name, bindings, NULL if negative else NONNULL, origin),
                        self.refine(state, name, bindings, NONNULL if negative else NULL, origin))
        empty = re.fullmatch(rf"string\.IsNullOr(?:Empty|WhiteSpace)\s*\(\s*({QUALIFIED_NAME})\s*\)", code)
        if empty and self.bound_name(empty.group(1), bindings):
            self.property_access(empty.group(1), state, bindings, position=start, guard=True)
            return (self.refine(state, empty.group(1), bindings, MAYBE, "negative_guard"),
                    self.refine(state, empty.group(1), bindings, NONNULL, "negative_guard"))
        has_value = re.fullmatch(rf"({QUALIFIED_NAME})\s*\.\s*HasValue", code)
        if has_value and self.bound_name(has_value.group(1), bindings) and self.key(has_value.group(1), bindings) in self.nullable_values:
            self.property_access(has_value.group(1), state, bindings, position=start, guard=True)
            return (self.refine(state, has_value.group(1), bindings, NONNULL),
                    self.refine(state, has_value.group(1), bindings, NULL))
        found = re.fullmatch(rf"([\w.@]+)\.TryGetValue\s*\([\s\S]*\bout\s+(?:(?:var|{TYPE})\s+)?({IDENT})\s*\)", code)
        if found:
            self.expression(start, end, state, bindings, depth + 1)
            spelling, success = self.dictionary_value(found.group(1), bindings)
            if spelling:
                self.typed(self.key(found.group(2), bindings), spelling)
            return (self.refine(state, found.group(2), bindings, success, "try_get_value"),
                    self.refine(state, found.group(2), bindings, NONNULL if success == NONNULL else MAYBE, "try_get_value"))
        self.expression(start, end, state, bindings, depth + 1)
        return ([], []) if state.exit else ([state.copy()], [state.copy()])

    def expression(self, start, end, state, bindings, depth=0):
        self.budget.spend()
        if depth > 96:
            raise AnalysisLimit("C# expression nesting limit exceeded; null analysis is incomplete")
        start, end = self.trim(start, end)
        code = self.code[start:end]
        if state.exit:
            return Value(0)
        items = tuple(parts(self.code, start, end, generics=bool(DECLARATION.match(code))))
        if len(items) > 1:
            for low, high in items:
                self.expression(low, high, state, bindings, depth + 1)
                if state.exit:
                    break
            return Value()
        if re.match(r"throw\b", code):
            self.expression(start + 5, end, state, bindings, depth + 1)
            self.note_exception(state)
            state.exit = "throw"
            return Value(0)
        if re.match(r"await\b", code):
            self.expression(start + 5, end, state, bindings, depth + 1)
            self.note_exception(state)
            return Value()
        assignment = self.operator(start, end, ("=",))
        arrow = self.operator(start, end, ("=>",))
        if (arrow and (not assignment or arrow[0] < assignment[0])) or re.match(r"(?:async\s+)?delegate\b", code):
            deferred = self.deferred_functions(start, end)
            for function in deferred:
                local = dict(bindings)
                local.update({name: f"{name}@param:{function.key}" for name in function.parameters})
                for name, spelling in zip(function.parameters, function.parameter_types):
                    self.typed(local[name], spelling)
                outer_exceptions, self.exceptions = self.exceptions, []
                outer_function, self.active_function = self.active_function, function
                try:
                    self.walk(function.body, [state.copy()], local, depth + 1)
                finally:
                    self.exceptions = outer_exceptions
                    self.active_function = outer_function
            return Value(NONNULL, callables=frozenset(function.key for function in deferred),
                         opaque_callable=not deferred)
        if assignment:
            position, _ = assignment
            left = self.code[start:position].strip()
            declaration = DECLARATION.match(self.code[start:position + 1])
            name = left if self.bound_name(left, bindings) else declaration.group(2) if declaration else None
            if name is None:
                self.expression(start, position, state, bindings, depth + 1)
            value = self.expression(position + 1, end, state, bindings, depth + 1)
            if name and not state.exit:
                key = self.key(name, bindings)
                self.property_access(name, state, bindings, kind="set", position=start)
                previous = state.values.get(key, Value())
                state.values[key] = replace(value, origins=value.origins or previous.origins)
                low, high = self.trim(position + 1, end)
                if self.code[high - 1:high] == "!":
                    low, high = self.trim(low, high - 1)
                source = self.code[low:high]
                if self.declared_types.get(key) == "var":
                    allocation = re.match(rf"new\s+({TYPE})\s*(?=[({{\[])", source)
                    inferred = (self.declared_types.get(self.key(source, bindings), "") if self.bound_name(source, bindings)
                                else allocation.group(1) if allocation else "")
                    self.typed(key, inferred)
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
        coalesce = self.operator(start, end, ("??=", "??"))
        if coalesce:
            position, operator = coalesce
            left = self.expression(start, position, state, bindings, depth + 1)
            name_start, name_end = self.trim(start, position)
            name = self.code[name_start:name_end]
            direct = self.bound_name(name, bindings)
            present = self.refine(state, name, bindings, NONNULL) if direct else [state.copy()] if left.nulls & NONNULL else []
            absent = self.refine(state, name, bindings, NULL) if direct else [state.copy()] if left.nulls & NULL else []
            values = [replace(left, nulls=NONNULL)] if present else []
            for branch in absent:
                value = self.expression(position + len(operator), end, branch, bindings, depth + 1)
                if operator == "??=" and direct and not branch.exit:
                    key = self.key(name, bindings)
                    self.property_access(name, branch, bindings, kind="set", position=start)
                    branch.values[key] = replace(value, origins=value.origins or left.origins)
                values.append(value)
            self.join_into(state, present + absent)
            return self.merged(values)
        conditional = self.operator(start, end, ("?.", "?["))
        if conditional:
            position, _ = conditional
            receiver = self.expression(start, position, state, bindings, depth + 1)
            low, high = self.trim(start, position)
            name = self.code[low:high]
            direct = self.bound_name(name, bindings)
            present = self.refine(state, name, bindings, NONNULL) if direct else [state.copy()] if receiver.nulls & NONNULL else []
            absent = self.refine(state, name, bindings, NULL) if direct else [state.copy()] if receiver.nulls & NULL else []
            finish = self.access_end(position + 1, end)
            for branch in present:
                self.access_effects(position + 1, finish, branch, bindings, depth + 1, name if direct else "")
            self.join_into(state, present + absent)
            if finish < end and not state.exit:
                self.expression(finish, end, state, bindings, depth + 1)
            return Value()
        byref = re.fullmatch(rf"(?:ref|out)\s+({QUALIFIED_NAME})", code)
        if byref and self.bound_name(byref.group(1), bindings):
            key = self.key(byref.group(1), bindings)
            return state.values.get(key, Value())
        if code.endswith("!"):
            # Null-forgiving changes compiler annotations, not runtime values.
            return self.expression(start, end - 1, state, bindings, depth + 1)
        if code in {"true", "false"}:
            return Value(NONNULL)
        if self.bound_name(code, bindings):
            if code == "null":
                return Value(NULL)
            self.property_access(code, state, bindings, position=start)
            if code not in bindings and re.fullmatch(QUALIFIED_NAME, code):
                candidates = self.call_candidates(code, None, bindings, start, self.active_function, state)
                if candidates:
                    return Value(NONNULL, callables=frozenset(function.key for function in candidates))
            return state.values.get(self.key(code, bindings), Value())
        if code.startswith("(") and start in self.parser.pairs:
            closing = self.parser.pairs[start]
            spelling = self.code[start + 1:closing].strip()
            operand = self.parser.skip(closing + 1, end)
            raw_type = re.sub(r"\s+", "", spelling)
            type_head = raw_type.split(".", 1)[0].lstrip("@")
            cast = (re.fullmatch(TYPE, spelling)
                    and type_head not in bindings and operand < end
                    and self.code[operand] not in ".[,?:;)=<>|&*/%")
            if cast:
                unary = operand
                while unary < end and self.code[unary] in "+-!~":
                    unary = self.parser.skip(unary + 1, end)
                finish = self.access_end(unary, end)
                if finish > unary:
                    value = self.expression(operand, finish, state, bindings, depth + 1)
                    source_start, source_end = self.trim(operand, finish)
                    source_name = self.code[source_start:source_end]
                    source_type = self.declared_types.get(self.key(source_name, bindings), "")
                    literal_text = self.text[source_start:source_end]
                    if re.match(r'(?:\$+@?|@\$?)?"', literal_text) and literal_text.endswith('"'):
                        source_type = "string"
                    if re.fullmatch(r"[0-9]+", source_name):
                        source_type = "int"
                    null_reference = raw_type in {"string", "object"}
                    owner = self.type_owner(raw_type, start)
                    if owner:
                        null_reference = any(
                            re.match(r"(?:class|interface|record\s+(?!struct\b))\b", self.code[low:])
                            and ".".join(part for begin, finish, part in self.parser.types if begin <= low < finish) == owner
                            for low, _high, _name in self.parser.types)
                    disposable = re.fullmatch(r"((?:global::)?System\.)?(IAsyncDisposable|IDisposable)", raw_type)
                    if disposable and not owner and disposable.group(2) not in self.type_aliases | self.type_names:
                        null_reference = (self.framework_identity("System." + disposable.group(2), start,
                                           raw_type.startswith("global::"))
                                          and (raw_type.startswith("global::") or "System" not in self.type_aliases | self.type_names))
                    numeric = (raw_type in VALUE_TYPES and source_type in VALUE_TYPES
                               and ((raw_type != "decimal" and source_type != "decimal")
                                    or (raw_type == "decimal" and source_type not in {"float", "double"})
                                    or (source_type == "decimal" and raw_type in {"float", "double"})))
                    nonthrowing = (raw_type == source_type or numeric
                                   or (source_type == raw_type + "?" and not value.nulls & NULL)
                                   or (source_name == "null" and (raw_type.endswith("?") or null_reference)))
                    if not nonthrowing and not state.exit:
                        self.note_exception(state)
                    if finish < end and not state.exit:
                        self.expression(finish, end, state, bindings, depth + 1)
                    return (value if raw_type == source_type else Value(NULL)
                            if source_name == "null" and nonthrowing else Value())
        literal = re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[mMdDfFlLuU]*", code)
        original = self.text[start:end]
        string_literal = re.match(r'(?:\$+@?|@\$?)?["\']', original) and original.endswith(('"', "'"))
        result = Value(NONNULL) if literal or string_literal else Value()
        allocation = re.match(r"new\s+(" + TYPE + r")\s*(?=[([{])", code)
        initializer, initializer_owner, anonymous, bare_constructor = None, "", False, False
        if allocation:
            cursor = start + allocation.end()
            first = cursor
            array = self.code[first:first + 1] == "[" or allocation.group(1).endswith("[]")
            if cursor in self.parser.pairs:
                if self.code[cursor] == "{" and not array:
                    initializer, bare_constructor = cursor, True
                cursor = self.parser.skip(self.parser.pairs[cursor] + 1, end)
                if self.code[cursor:cursor + 1] == "{" and cursor in self.parser.pairs:
                    if not array:
                        initializer = cursor
                    cursor = self.parser.skip(self.parser.pairs[cursor] + 1, end)
                if initializer is not None:
                    initializer_owner = self.type_owner(allocation.group(1), start)
                nullable = allocation.group(1).endswith("?") or "Nullable<" in allocation.group(1)
                if cursor == end and not (nullable and not self.code[first + 1:self.parser.pairs[first]].strip()):
                    result = Value(NONNULL)
        else:
            anonymous_match = re.match(r"new\s*\{", code)
            target_typed = re.match(r"new\s*\(", code)
            if anonymous_match:
                initializer, anonymous = start + anonymous_match.end() - 1, True
            elif target_typed:
                raise AnalysisLimit("C# target-typed constructor effects need expected-type flow; null analysis is incomplete")
        cursor = start
        while cursor < end and not state.exit:
            self.budget.spend()
            word = re.match(IDENT, self.code[cursor:end])
            if word:
                name = word.group(0)
                following = cursor + word.end()
                while following < end and self.code[following].isspace():
                    following += 1
                field = re.match(rf"\.\s*({IDENT})", self.code[following:end])
                if field and (name == "this" or self.bound_name(name + "." + field.group(1), bindings)):
                    name = name + "." + field.group(1)
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
                if previous not in {".", "@"}:
                    self.property_access(name, state, bindings, position=cursor)
                    if member:
                        self.property_access(name + "." + member.group(1), state, bindings, position=cursor)
                    value = state.values.get(key, Value())
                invocation = (member and re.match(r"(?:\s*<[^;=]+>)?\s*\(", suffix[member.end():])
                              and self.method_member(name, member.group(1), bindings, cursor))
                if dereference and previous not in {".", "@"} and not (invocation or suffix.startswith("[")):
                    self.note_exception(state)
                if dereference and previous not in {".", "@"} and value.nulls & NULL:
                    for origin in value.origins:
                        line, column = line_col(self.text, cursor)
                        self.findings.add((origin, line, column, MESSAGES[origin].format(name=name)))
                cursor = following
                continue
            if cursor in self.parser.pairs:
                close = self.parser.pairs[cursor]
                if cursor == initializer:
                    if bare_constructor:
                        self.apply_call(allocation.group(1), cursor, cursor, state, bindings,
                                        start + allocation.start(1), constructor=True)
                    if not anonymous:
                        self.note_exception(state)
                    self.object_initializer(cursor + 1, close, state, bindings, depth + 1,
                                            initializer_owner, anonymous)
                    if anonymous and not state.exit:
                        self.note_exception(state)
                    cursor = close + 1
                    continue
                call_state = state.copy()
                for low, high in parts(self.code, cursor + 1, close):
                    self.expression(low, high, state, bindings, depth + 1)
                    if state.exit:
                        break
                before = self.code[start:cursor].rstrip()
                if self.code[cursor] == "[" or (self.code[cursor] == "(" and re.search(r"[\w)>\]]$", before)):
                    call = re.search(rf"({CALL_NAME})(?:\s*<[\w@.,<>\[\]?\s:]+>)?\s*$", before)
                    if self.code[cursor] == "(":
                        self.call_arguments(cursor, close, state, bindings)
                    if self.code[cursor] == "(" and call:
                        self.apply_call(call.group(1), cursor, close, state, bindings, start + call.start(1),
                                        constructor=bool(re.search(r"\bnew\s*$", before[:call.start(1)])),
                                        call_state=call_state)
                    self.note_exception(state)
                low, high = self.trim(cursor + 1, close)
                inner = self.code[low:high].rstrip("!").rstrip()
                suffix = self.code[close + 1:end].lstrip()
                if self.code[cursor] == "(" and self.bound_name(inner, bindings) and suffix.startswith((".", "[")):
                    key = self.key(inner, bindings)
                    value = state.values.get(key, Value())
                    safe = key in self.nullable_values and re.match(r"\.\s*(?:HasValue|GetValueOrDefault|ToString|GetHashCode|Equals)\b", suffix)
                    if value.nulls & NULL and not safe:
                        line, column = line_col(self.text, low)
                        for origin in value.origins:
                            self.findings.add((origin, line, column, MESSAGES[origin].format(name=inner)))
                cursor = close + 1
            else:
                if self.code[cursor] in "+-*/%":
                    self.note_exception(state)
                cursor += 1
        return result

    def using_resources(self, statement, bindings, declaration_only=False):
        code = self.code[statement.start:statement.end]
        if not declaration_only and not re.match(r"(?:await\s+)?using\s+(?!\()", code):
            return ()
        declaration = DECLARATION.match(code)
        if declaration is None:
            return ()
        names = [declaration.group(2)]
        for low, high in tuple(parts(self.code, statement.start, statement.end, generics=True))[1:]:
            match = re.match(rf"\s*({IDENT})\s*=", self.code[low:high])
            if match:
                names.append(match.group(1))
        return tuple(self.key(name, bindings) for name in names)

    def resource_disposers(self, keys, position, asynchronous=False):
        functions = set()
        name = "DisposeAsync" if asynchronous else "Dispose"
        for key in keys:
            spelling = self.declared_types.get(key, "")
            location = re.search(r"(?:^field:|@(?:param:)?)(\d+)", key)
            owner = self.type_owner(spelling, int(location.group(1)) if location else position) if spelling else ""
            functions.update(function.key for function in self.call_index.get(name, ())
                             if owner and function.parent is None and self.function_owner(function) == owner
                             and not function.parameters)
        return frozenset(functions)

    def dispose(self, state, functions):
        for key in functions:
            self.apply_writes(self.call_writes(self.parser.functions[key]), state)
        self.note_exception(state)

    def walk(self, statements, states, bindings, depth=0, cleanup=True):
        if depth > 96:
            raise AnalysisLimit("C# statement nesting limit exceeded; null analysis is incomplete")
        snapshots, local, labels = [], dict(bindings), {}
        for index, statement in enumerate(statements):
            self.declare(statement, local)
            snapshots.append(dict(local))
            if statement.kind == "label":
                label = self.code[statement.start:statement.end].split(":", 1)[0].strip().lstrip("@")
                labels[label] = index
        resources = [self.using_resources(statement, snapshot) if cleanup else ()
                     for statement, snapshot in zip(statements, snapshots)]
        pending = [(0, state, False, frozenset()) for state in states]
        seen, result = set(), []
        while pending:
            self.budget.spend()
            index, state, dispose, disposers = pending.pop()
            if state.exit.startswith("goto:") and state.exit[5:] in labels:
                index, state = labels[state.exit[5:]], state.copy()
                state.exit = ""
            if state.exit or index == len(statements):
                if dispose:
                    self.dispose(state, disposers)
                result.append(state)
                continue
            signature = index, state.signature(), dispose, disposers
            if signature in seen:
                continue
            seen.add(signature)
            try:
                successors = self.statement(statements[index], state, snapshots[index], depth + 1)
            except (AnalysisLimit, RecursionError) as exc:
                if self.budget.remaining < 0:
                    raise
                # This path cannot continue through unsupported semantics.
                # Sibling paths still establish useful independent evidence.
                self.failures.append(str(exc))
                continue
            for branch in successors:
                reached = tuple(key for key in resources[index] if not branch.exit
                                and branch.values.get(key, Value()).nulls & NONNULL)
                functions = self.resource_disposers(reached, statements[index].start,
                            bool(re.match(r"await\s+using\b", self.code[statements[index].start:statements[index].end])))
                pending.append((index + 1, branch, dispose or bool(reached), disposers | functions))
        return self.unique(result)

    def statement(self, statement, state, bindings, depth):
        self.budget.spend()
        kind, start, end = statement.kind, statement.start, statement.end
        if kind in {"definition", "label"}:
            return [state]
        if kind == "unsupported-goto":
            raise AnalysisLimit("C# goto case/default needs switch-target analysis; null analysis is incomplete")
        if kind == "unsupported-switch":
            raise AnalysisLimit("C# switch pattern binding or filter needs pattern flow; null analysis is incomplete")
        if kind in {"block", "declarations"}:
            return self.walk(statement.body, [state], bindings, depth, cleanup=kind == "block")
        if kind == "if":
            yes, no = self.condition(*statement.header, state, bindings)
            return self.unique(self.walk(statement.body, yes, bindings, depth)
                               + self.walk(statement.otherwise, no, bindings, depth))
        if kind in {"while", "for", "foreach", "do"}:
            bindings = dict(bindings)
            condition, update = statement.header, None
            iterator_throws = kind == "foreach"
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
                    low, high = self.trim(condition[0] + declaration.end(), condition[1])
                    collection = self.expression(low, high, state, bindings)
                    spelling = self.declared_types.get(self.key(self.code[low:high], bindings), "")
                    literal = self.text[low:high].startswith(('"', '@"'))
                    if not collection.nulls & NULL and (spelling.endswith("[]") or spelling == "string" or literal):
                        iterator_throws = False
                    if iterator_throws:
                        self.note_exception(state)
            pending, seen, result = [state], set(), []
            first = kind == "do"
            while pending:
                current = pending.pop()
                signature = current.signature(), first
                if signature in seen:
                    continue
                seen.add(signature)
                if first or kind == "foreach" or not self.code[slice(*condition)].strip():
                    if iterator_throws:
                        self.note_exception(current)
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
            if iterator_throws:
                for branch in result:
                    self.note_exception(branch)
            return self.unique(result)
        if kind == "switch":
            self.expression(*statement.header, state, bindings)
            low, high = self.trim(*statement.header)
            name = self.code[low:high]
            direct = self.bound_name(name, bindings)
            cases = []
            for arm in statement.body:
                label = " ".join(self.code[slice(*arm.header)].split())
                original = self.text[slice(*arm.header)].strip()
                if label in {"case null", "case not null", "default"}:
                    cases.append(label)
                elif re.fullmatch(r"case\s+(?:-?\d+[\w.]*|true|false)", label) or re.match(r"case\s+(?:@?\"|')", original):
                    cases.append("constant")
                elif re.fullmatch(r"case\s+[\w@.]+", label):
                    cases.append("unknown-constant")
                else:
                    raise AnalysisLimit("C# switch pattern binding or filter needs pattern flow; null analysis is incomplete")
            unmatched = (MAYBE & ~NULL if "case null" in cases else MAYBE)
            if "case not null" in cases:
                unmatched &= ~NONNULL
            result = []
            if "default" not in cases and unmatched:
                result.extend(self.refine(state, name, bindings, unmatched) if direct else [state.copy()])
            for index, arm in enumerate(statement.body):
                label = cases[index]
                nulls = (NULL if label == "case null" else NONNULL if label in {"case not null", "constant"}
                         else MAYBE if label == "unknown-constant" else unmatched)
                entries = (self.refine(state, name, bindings, nulls) if direct else [state.copy()]) if nulls else []
                body = next((following.body for following in statement.body[index:] if following.body), ())
                for branch in self.walk(body, entries, bindings, depth):
                    if branch.exit == "break":
                        branch.exit = ""
                    result.append(branch)
            return self.unique(result)
        if kind == "try":
            thrown = []
            self.exceptions.append(thrown)
            try:
                result = self.walk((statement.body[0],), [state.copy()], bindings, depth)
            finally:
                self.exceptions.pop()
            thrown = self.unique(thrown + [branch for branch in result if branch.exit == "throw"])
            result = [branch for branch in result if branch.exit != "throw"]
            for handler in statement.body[1:]:
                entries = [branch.copy() for branch in thrown]
                for branch in entries:
                    branch.exit = ""
                handler_thrown = []
                self.exceptions.append(handler_thrown)
                try:
                    result.extend(self.walk((handler,), entries, bindings, depth))
                finally:
                    self.exceptions.pop()
                for branch in self.unique(handler_thrown):
                    branch.exit = "throw"
                    result.append(branch)
                if self.catch_all(handler):
                    thrown = []
                    break
            for branch in thrown:
                exceptional = branch.copy()
                exceptional.exit = "throw"
                result.append(exceptional)
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
                raise AnalysisLimit("C# catch filters need exception-search flow; null analysis is incomplete")
            bindings = dict(bindings)
            declaration = re.fullmatch(rf"\s*({TYPE})\s+({IDENT})\s*", self.code[slice(*statement.header)])
            if declaration:
                name = declaration.group(2).lstrip("@")
                key = f"{name}@{statement.header[0]}"
                bindings[name] = key
                state.values[key] = Value(NONNULL)
            return self.walk(statement.body, [state], bindings, depth)
        if kind in {"using", "lock", "fixed"}:
            bindings = dict(bindings)
            if kind in {"using", "fixed"}:
                self.declare(Statement(*statement.header), bindings)
            resource = self.expression(*statement.header, state, bindings)
            if kind == "lock":
                self.note_exception(state)
            resources = self.using_resources(Statement(*statement.header), bindings, declaration_only=True)
            dispose = (any(state.values.get(key, Value()).nulls & NONNULL for key in resources)
                       if resources else resource.nulls & NONNULL)
            if not resources:
                low, high = self.trim(*statement.header)
                if self.bound_name(self.code[low:high], bindings):
                    resources = (self.key(self.code[low:high], bindings),)
            disposers = self.resource_disposers(resources, start, bool(re.match(r"await\s+using\b", self.code[start:end])))
            result = self.walk(statement.body, [state], bindings, depth)
            if kind == "using" and dispose:
                for branch in result:
                    self.dispose(branch, disposers)
            return result
        if kind in {"break", "continue", "goto"}:
            state.exit = ("goto:" + self.code[start:end].split()[1].lstrip("@")) if kind == "goto" else kind
        else:
            expression_start = start + len(kind) if kind in {"return", "throw"} and re.match(kind + r"\b", self.code[start:end]) else start
            self.expression(expression_start, end, state, bindings)
            if kind in {"return", "throw"} and not state.exit:
                if kind == "throw":
                    self.note_exception(state)
                state.exit = kind
        return [state]

    def catch_all(self, handler):
        if handler.otherwise:
            return False
        declaration = self.code[slice(*handler.header)].strip()
        if not declaration:
            return True
        framework = re.fullmatch(rf"((?:global::)?System\.)?Exception(?:\s+{IDENT})?", declaration)
        if not framework:
            return False
        if not framework.group(1):
            return "Exception" not in self.type_names | self.type_aliases
        return (self.framework_identity("System.Exception", handler.header[0], framework.group(1).startswith("global::"))
                and (framework.group(1).startswith("global::") or "System" not in self.type_names | self.type_aliases))

    def function_bindings(self, function):
        owner = min((opening for opening in self.fields if opening < function.start < self.parser.pairs[opening]),
                    key=lambda opening: self.parser.pairs[opening] - opening, default=None)
        bindings = dict(self.fields.get(owner, {}))
        bindings.update({"this." + name: key for name, key in self.fields.get(owner, {}).items()})
        for type_name, fields in self.static_fields.items():
            bindings.update({type_name + "." + name: key for name, key in fields.items()})
        if function.parent is not None:
            parent = self.parser.functions[function.parent]
            bindings = self.function_bindings(parent)

            def enclosing(statements):
                for statement in statements:
                    if statement.start > function.key:
                        break
                    self.declare(statement, bindings)
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
                        elif statement.kind in {"using", "fixed"}:
                            self.declare(Statement(*statement.header), bindings)
                        enclosing(statement.body)
                        enclosing(statement.otherwise)
                        break

            enclosing(parent.body)
        bindings.update({name: f"{name}@param:{function.key}" for name in function.parameters})
        for name, spelling in zip(function.parameters, function.parameter_types):
            self.typed(bindings[name], spelling)
        return bindings

    def scan(self):
        failures = self.failures
        uncovered = [position for position in self.guards if not any(
            function.start <= position < function.end for function in self.parser.functions.values())]
        if any(any(opening < position < self.parser.pairs[opening] for opening in self.fields)
               for position in uncovered):
            failures.append("C# selected guard in an unsupported executable scope; null analysis is incomplete")
            uncovered = [position for position in uncovered if not any(
                opening < position < self.parser.pairs[opening] for opening in self.fields)]
        for function in self.parser.functions.values():
            nested = [other for other in self.parser.functions.values() if other.parent == function.key]
            if not any(function.start <= position < function.end and not any(
                other.declaration <= position < other.end for other in nested
            ) for position in self.guards):
                continue
            try:
                self.active_function = function
                bindings = self.function_bindings(function)
                remaining = self.walk(function.body, [State()], bindings)
                if any(state.exit.startswith("goto:") for state in remaining):
                    raise AnalysisLimit("Unresolved C# goto target; null analysis is incomplete")
            except (AnalysisLimit, RecursionError) as exc:
                failures.append(str(exc))
            finally:
                self.exceptions.clear()
                self.active_function = None
            if self.budget.remaining < 0:
                break
        # Top-level .csx and modern C# statements have their own scope.
        if uncovered and self.budget.remaining >= 0:
            try:
                remaining = self.walk(self.parser.block(0, len(self.code)), [State()], {})
                if any(state.exit.startswith("goto:") for state in remaining):
                    raise AnalysisLimit("Unresolved C# goto target; null analysis is incomplete")
            except (AnalysisLimit, RecursionError) as exc:
                failures.append(str(exc))
        findings = sorted(self.findings, key=lambda finding: (finding[1], finding[2], finding[0]))
        if failures:
            raise NarrowingLimit("; ".join(dict.fromkeys(failures)), findings)
        return findings


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
    try:
        code = masked_source(discovery)
        if not guard_positions(code, pairs(code)):
            return []
        return GuardFlow(text).scan()
    except NarrowingLimit:
        raise
    except (ValueError, RecursionError) as exc:
        raise NarrowingLimit(str(exc)) from exc


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
        failure = None
        try:
            findings = scan_text(text)
        except NarrowingLimit as exc:
            findings, failure = exc.findings, exc
        for kind, line, col, message in findings:
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
        if failure is not None:
            raise failure


def _selftest_detects_non_exiting_null_guard() -> None:
    code = "class A { int F(string raw) { if (raw == null) { log(raw); } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, line, _col, message = findings[0]
    assert kind == "negative_guard"
    assert line == 1
    assert message == "raw may be null at this dereference after a null/empty guard"


def _selftest_exiting_guard_suppresses() -> None:
    code = "class A { int F(string raw) { if (raw == null) { return 0; } return raw.Length; } }"
    assert scan_text(code) == []


def _selftest_positive_guard_fallthrough() -> None:
    code = "class A { int F(string raw) { if (raw != null) { return raw.Length; } return raw.Length; } }"
    findings = scan_text(code)
    assert len(findings) == 1, findings
    kind, _line, _col, message = findings[0]
    assert kind == "positive_guard"
    assert message == "raw may be null at this dereference; the positive guard does not prove it safe"


def _selftest_trygetvalue_guard() -> None:
    code = (
        "class A {\n"
        "  int F(Dictionary<string, string> map, string key) {\n"
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
    assert message == "token may be null after TryGetValue; check the value as well as lookup success"


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
