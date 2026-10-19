"""Bounded lexical receiver classification for synchronous C# .Result reads.

This is deliberately not name-based type checking. Only selected-file Task /
ValueTask identities are critical. Locally declared non-task receivers and
named tuples are excluded; unresolved receivers remain visible as warnings.
The shared C# lexer preserves executable interpolation holes and source offsets.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from ubs_core.analyzers.taint_csharp_request import masked_source

_TOKEN = re.compile(r"@?[A-Za-z_]\w*|::|=>|[^\s]")
_IDENT = re.compile(r"@?[A-Za-z_]\w*\Z")
_MODIFIERS = frozenset("public private protected internal static async virtual override sealed new unsafe extern partial readonly ref file const using await in out params this scoped".split())
_CONTROL = frozenset("if while for foreach switch catch using lock fixed return throw new else case nameof typeof sizeof default".split())
_SCALARS = frozenset("string char bool byte sbyte short ushort int uint long ulong float double decimal nint nuint".split())
_TASKS = frozenset({"System.Threading.Tasks.Task", "System.Threading.Tasks.ValueTask"})
_FACTORIES = frozenset({"FromResult", "FromException", "FromCanceled", "Run", "WhenAll", "WhenAny"})
_UNKNOWN = ""


@dataclass(frozen=True)
class Token:
    value: str
    offset: int
    line: int


@dataclass(frozen=True)
class Binding:
    name: str
    spelling: str
    start: int
    end: int
    position: int


@dataclass(frozen=True)
class Method:
    name: str
    returns: str
    parameters: tuple[tuple[str, str], ...]
    start: int
    end: int
    owner: tuple[int, int]
    visibility: tuple[int, int]


class ResultIndex:
    def __init__(self, text: str):
        # Compile-time branches are scanned as a union, not sequential type
        # declarations: a declaration in one branch must not suppress another.
        self.conditional = bool(re.search(r"(?m)^\s*#\s*(?:if|elif|else|endif)\b", text))
        source = re.sub(r"(?m)^[ \t]*#[^\r\n]*", lambda m: " " * len(m[0]), text)
        self.code = masked_source(source)
        self.tokens = []
        line, previous = 1, 0
        for match in _TOKEN.finditer(self.code):
            line += self.code.count("\n", previous, match.start())
            previous = match.start()
            self.tokens.append(Token(match[0].lstrip("@"), match.start(), line))
        self.pairs: dict[int, int] = {}
        self.reverse: dict[int, int] = {}
        stack = []
        for index, token in enumerate(self.tokens):
            value = token.value
            if value in {"(", "[", "{"}:
                stack.append(index)
            elif value in {")", "]", "}"}:
                if not stack or self.value(stack[-1]) != {")": "(", "]": "[", "}": "{"}[value]:
                    raise ValueError("Unbalanced C# .Result input")
                opening = stack.pop()
                self.pairs[opening] = index
                self.reverse[index] = opening
        if stack:
            raise ValueError("Unbalanced C# .Result input")
        self.braces = [(low, high) for low, high in self.pairs.items() if self.value(low) == "{"]
        self.types: list[Binding] = []
        self.imports: list[Binding] = []
        self.bindings: list[Binding] = []
        self.methods: list[Method] = []
        self.method_headers: list[tuple[int, int]] = []
        self.type_bodies: list[tuple[int, int]] = []
        self.type_names: dict[tuple[int, int], str] = {}
        self.members: dict[tuple[str, str], str] = {}
        self._types_and_imports()
        self._methods()
        self._variables()

    def value(self, index: int) -> str:
        return self.tokens[index].value if 0 <= index < len(self.tokens) else ""

    def spelling(self, start: int, end: int) -> str:
        return "".join(token.value for token in self.tokens[start:end])

    def scope(self, position: int) -> tuple[int, int]:
        return min(((low, high) for low, high in self.braces if low < position < high),
                   key=lambda pair: pair[1] - pair[0], default=(-1, len(self.tokens)))

    def owner(self, position: int) -> tuple[int, int]:
        return min(((low, high) for low, high in self.type_bodies if low < position < high),
                   key=lambda pair: pair[1] - pair[0], default=(-1, len(self.tokens)))

    def split(self, start: int, end: int) -> list[tuple[int, int]]:
        result, beginning, angle = [], start, 0
        index = start
        while index < end:
            value = self.value(index)
            if index in self.pairs:
                index = self.pairs[index] + 1
                continue
            if value == "<":
                angle += 1
            elif value == ">" and angle:
                angle -= 1
            elif value == "," and not angle:
                result.append((beginning, index))
                beginning = index + 1
            index += 1
        if beginning < end:
            result.append((beginning, end))
        return result

    def declaration(self, start: int, end: int) -> tuple[str, str] | None:
        while start < end and self.value(start) in _MODIFIERS:
            start += 1
        # Defaults are not part of a parameter's declared type.
        end = next((i for i in range(start, end) if self.value(i) == "="), end)
        if end - start < 2 or not _IDENT.fullmatch(self.value(end - 1)):
            return None
        if self.value(start) in _CONTROL or self.value(start) in {"=", ".", "=>"}:
            return None
        spelling = self.spelling(start, end - 1)
        if not spelling or any(self.value(i) in {"=", "=>", ";", "{", "}"} for i in range(start, end - 1)):
            return None
        return self.value(end - 1), spelling

    def _types_and_imports(self) -> None:
        for index, token in enumerate(self.tokens):
            if token.value == "using":
                end = next((i for i in range(index + 1, len(self.tokens)) if self.value(i) in {";", "{"}), index)
                low, high = self.scope(index)
                target = self.spelling(index + 1, end)
                if target and not target.startswith("static"):
                    alias, sep, namespace = target.partition("=")
                    self.imports.append(Binding(alias if sep else "", namespace if sep else alias, low, high, index))
            if token.value not in {"class", "struct", "record", "interface"}:
                continue
            name_index = index + 1
            if token.value == "record" and self.value(name_index) in {"class", "struct"}:
                name_index += 1
            name = self.value(name_index)
            if not _IDENT.fullmatch(name):
                continue
            cursor = name_index + 1
            if self.value(cursor) == "<":
                while cursor < len(self.tokens) and self.value(cursor) not in {">", ";", "{"}:
                    cursor += 1
                cursor += self.value(cursor) == ">"
            primary_parameters = []
            if self.value(cursor) == "(" and cursor in self.pairs:
                for low, high in self.split(cursor + 1, self.pairs[cursor]):
                    item = self.declaration(low, high)
                    if item:
                        member, spelling = item
                        self.member(name, member, spelling)
                        primary_parameters.append((member, spelling))
                cursor = self.pairs[cursor] + 1
            bases = self.value(cursor) == ":"
            while cursor < len(self.tokens) and self.value(cursor) not in {"{", ";"}:
                cursor += 1
            low, high = self.scope(index)
            # Records/structs cannot inherit Task. An unknown class base can.
            safe = token.value in {"struct", "record"} or (token.value == "class" and not bases)
            self.types.append(Binding(name, "local:" + name if safe else _UNKNOWN, low, high, index))
            if self.value(cursor) == "{" and cursor in self.pairs:
                body = (cursor, self.pairs[cursor])
                self.type_bodies.append(body)
                self.type_names[body] = "local:" + name if safe else _UNKNOWN
                # C# 12 primary-constructor parameters are lexical values
                # throughout the instance type body. Without these bindings a
                # parameter named Task/ValueTask is mistaken for the BCL type,
                # while a real Task-valued parameter is downgraded to unknown.
                self.bindings.extend(
                    Binding(member, spelling, body[0], body[1], name_index)
                    for member, spelling in primary_parameters
                )

    def _methods(self) -> None:
        for opening, closing in sorted(self.pairs.items()):
            if self.value(opening) != "(" or self.value(closing + 1) not in {"{", "=>"}:
                continue
            name_index = opening - 1
            if self.value(name_index) == ">":
                depth = 1
                name_index -= 1
                while name_index >= 0 and depth:
                    depth += (self.value(name_index) == ">") - (self.value(name_index) == "<")
                    name_index -= 1
            name = self.value(name_index)
            if not _IDENT.fullmatch(name) or name in _CONTROL:
                continue
            start = name_index
            while start > 0 and self.value(start - 1) not in {";", "{", "}"}:
                start -= 1
            item = self.declaration(start, name_index + 1)
            if not item:
                continue
            parameters = []
            for low, high in self.split(opening + 1, closing):
                parameter = self.declaration(low, high)
                if not parameter:
                    break
                parameters.append(parameter)
            else:
                body = closing + 1
                end = self.pairs.get(body)
                if end is None:
                    end = body + 1
                    while end < len(self.tokens) and self.value(end) != ";":
                        end = self.pairs.get(end, end) + 1
                method = Method(name, item[1], tuple(parameters), body, end, self.owner(name_index), self.scope(name_index))
                self.methods.append(method)
                self.method_headers.append((start, body))
                self.bindings.extend(Binding(param, spelling, body, end, opening) for param, spelling in parameters)

    def _variables(self) -> None:
        for index, token in enumerate(self.tokens):
            if not _IDENT.fullmatch(token.value) or self.value(index + 1) not in {"=", ";", "{", "=>"}:
                continue
            if any(low <= index < high for low, high in self.method_headers):
                continue
            start = index
            while start > 0 and self.value(start - 1) not in {";", "{", "}", "("}:
                start -= 1
            item = self.declaration(start, index + 1)
            if not item or item[0] != token.value:
                continue
            name, spelling = item
            low, high = self.scope(index)
            # Fields/properties are in scope throughout their declaring type.
            field = (low, high) in self.type_bodies
            if spelling == "var":
                end = index + 2
                while end < len(self.tokens) and self.value(end) != ";":
                    end = self.pairs.get(end, end) + 1
                spelling = self.expression(index + 2, end, index, 0)
            self.bindings.append(Binding(name, spelling, low if field else index, high, index))
            if field:
                names = [binding.name for binding in self.types if binding.position < low and binding.start <= low < binding.end]
                if names:
                    self.member(names[-1], name, spelling)
        # Do not mistake a lambda parameter for a captured variable with the
        # same spelling. Its type needs overload inference: leave it unknown.
        for index, token in enumerate(self.tokens):
            if token.value != "=>" or any(high == index for _, high in self.method_headers):
                continue
            before = index - 1
            names = []
            if _IDENT.fullmatch(self.value(before)):
                names = [self.value(before)]
            elif self.value(before) == ")" and before in self.reverse:
                for low, high in self.split(self.reverse[before] + 1, before):
                    if high > low and _IDENT.fullmatch(self.value(high - 1)):
                        names.append(self.value(high - 1))
            end = index + 1
            while end < len(self.tokens) and self.value(end) not in {";", ",", ")"}:
                end = self.pairs.get(end, end) + 1
            self.bindings.extend(Binding(name, _UNKNOWN, index, end, index) for name in names)

    def member(self, owner: str, name: str, spelling: str) -> None:
        key = (owner, name)
        self.members[key] = spelling if key not in self.members or self.members[key] == spelling else _UNKNOWN

    def resolve_type(self, spelling: str, position: int, depth: int = 0) -> str:
        if depth > 16 or not spelling:
            return _UNKNOWN
        if spelling.startswith(("local:", "tuple:")):
            return spelling
        if spelling.startswith("(") and "," in spelling:
            return "tuple:" + spelling
        if spelling.endswith("[]"):
            return "array:" + self.resolve_type(spelling[:-2], position, depth + 1)
        spelling = spelling.rstrip("?")
        base = spelling.split("<", 1)[0]
        if base in _SCALARS:
            return "scalar:" + base
        if base.startswith("global::"):
            return base[len("global::"):] if base[len("global::"):] in _TASKS else _UNKNOWN
        locals_ = [binding for binding in self.types if binding.name == base and binding.start < position < binding.end]
        if locals_:
            return min(locals_, key=lambda b: b.end - b.start).spelling
        imports = [item for item in self.imports if item.start < position < item.end]
        alias = [item for item in imports if item.name == base]
        if alias:
            return self.resolve_type(min(alias, key=lambda b: b.end - b.start).spelling, position, depth + 1)
        if base in _TASKS:
            # A selected-file root named System makes non-global qualification
            # ambiguous, not a proof that this is the BCL Task type.
            return _UNKNOWN if any(item.name == "System" for item in self.types) else base
        if base in {"Task", "ValueTask"} and any(not item.name and item.spelling in {"System.Threading.Tasks", "global::System.Threading.Tasks"} for item in imports):
            return "System.Threading.Tasks." + base
        return _UNKNOWN

    def expression(self, start: int, end: int, position: int, depth: int = 0) -> str:
        if depth > 24 or start >= end:
            return _UNKNOWN
        while self.value(end - 1) in {"!", "?"}:
            end -= 1
        if start >= end:
            return _UNKNOWN
        if self.value(start) == "new":
            stop = start + 1
            while stop < end and self.value(stop) not in {"(", "{", "["}:
                stop += 1
            return self.resolve_type(self.spelling(start + 1, stop), position)
        if self.value(start) == "(" and self.pairs.get(start) == end - 1:
            if len(self.split(start + 1, end - 1)) > 1:
                return "tuple:" + self.spelling(start, end)
            return self.expression(start + 1, end - 1, position, depth + 1)
        if self.value(start) == "(" and start in self.pairs and self.pairs[start] < end - 1:
            cast = self.resolve_type(self.spelling(start + 1, self.pairs[start]), position)
            if cast:
                return cast
        if end - start == 1 and _IDENT.fullmatch(self.value(start)):
            candidates = [item for item in self.bindings if item.name == self.value(start) and item.start < position < item.end]
            if candidates:
                item = min(candidates, key=lambda b: (b.end - b.start, -b.position))
                return self.resolve_type(item.spelling, item.position, depth + 1)
            if self.value(start) == "this":
                return self.type_names.get(self.owner(position), _UNKNOWN)
            return self.resolve_type(self.value(start), position)
        if self.value(end - 1) == "]" and end - 1 in self.reverse:
            opening = self.reverse[end - 1]
            target = self.expression(start, opening, position, depth + 1)
            return target[len("array:"):] if target.startswith("array:") else _UNKNOWN
        if self.value(end - 1) == ")" and end - 1 in self.reverse:
            opening = self.reverse[end - 1]
            method = self.value(opening - 1)
            callee_end = opening - 1
            if method == ">":
                nesting = 1
                callee_end -= 1
                while callee_end >= start and nesting:
                    nesting += (self.value(callee_end) == ">") - (self.value(callee_end) == "<")
                    callee_end -= 1
                method = self.value(callee_end)
            qualified = self.value(callee_end - 1) == "."
            receiver = self.spelling(start, callee_end - 1) if qualified else ""
            identity = self.resolve_type(receiver, position) if receiver else ""
            if qualified and identity in _TASKS and method in _FACTORIES:
                return identity
            if method == "AsTask" and qualified and self.expression(start, callee_end - 1, position, depth + 1) == "System.Threading.Tasks.ValueTask":
                return "System.Threading.Tasks.Task"
            count = len(self.split(opening + 1, end - 1))
            candidates = [item for item in self.methods if item.name == method and len(item.parameters) == count and item.owner == self.owner(position) and item.visibility[0] < position < item.visibility[1]]
            if qualified and receiver != "this":
                return _UNKNOWN
            kinds = {self.resolve_type(item.returns, item.start) for item in candidates}
            return kinds.pop() if len(kinds) == 1 else _UNKNOWN
        if end - start >= 3 and self.value(end - 2) == ".":
            receiver = self.expression(start, end - 2, position, depth + 1)
            if receiver.startswith("local:"):
                spelling = self.members.get((receiver[len("local:"):], self.value(end - 1)), "")
                return self.resolve_type(spelling, position)
            return _UNKNOWN
        return _UNKNOWN

    def receiver_start(self, end: int) -> int:
        index = end - 1
        angles = 0
        while index >= 0:
            value = self.value(index)
            if value in {")", "]"} and index in self.reverse:
                index = self.reverse[index] - 1
                continue
            if value == ">":
                angles += 1
            elif value == "<" and angles:
                angles -= 1
            elif value == "," and not angles:
                break
            if _IDENT.fullmatch(value) or value in {".", "::", "!", "?", "<", ">", ","}:
                if value in _CONTROL and value != "new":
                    break
                # Whitespace between identifiers separates e.g. `return task`
                # and `new Outcome`, but is not a member-access operator.
                if index + 1 < end and _IDENT.fullmatch(value) and _IDENT.fullmatch(self.value(index + 1)) and value != "new":
                    break
                index -= 1
                continue
            break
        return index + 1

    def classify(self) -> tuple[set[int], set[int]]:
        critical, unknown = set(), set()
        for index, token in enumerate(self.tokens):
            if token.value != "Result" or self.value(index - 1) != ".":
                continue
            if any(self.value(low - 1) == "nameof" and low < index < high for low, high in self.pairs.items()):
                continue
            end = index - 1
            start = self.receiver_start(end)
            kind = _UNKNOWN if self.conditional else self.expression(start, end, index)
            if kind in _TASKS:
                critical.add(token.line)
            elif not kind or kind.startswith("array:"):
                unknown.add(token.line)
        # Keep one finding per line, with the strongest classification.
        return critical, unknown - critical


def result_lines(text: str) -> tuple[set[int], set[int]]:
    if "Result" not in text:
        return set(), set()
    # A pathological/unsupported input must not silently erase candidates.
    # The warning rule describes this conservative, non-type-proven result.
    try:
        if len(text) > 1_000_000:
            raise ValueError("C# .Result classification size limit")
        return ResultIndex(text).classify()
    except (ValueError, RecursionError):
        return set(), {index for index, line in enumerate(text.splitlines(), 1)
                       if re.search(r"\.\s*Result\b", line)}


def ast_result_qualifier(texts: dict):
    """Receiver gate for the ast-grep pack's type-blind `$TASK.Result` rule (GH #169).

    Keep a `cs-task-result-deadlock` match only when its `.Result` token (the
    match's end) sits on a line this classifier reports as a Task/ValueTask or
    unresolved receiver. Records, tuples and other proven non-task receivers
    are dropped, exactly as for `cs.pattern.blocking-result`.
    """
    sources = {str(Path(path).resolve()): text for path, text in texts.items()}
    lines: dict[str, set[int]] = {}

    def qualify(rule_id: str, path: Path, match: dict) -> bool:
        if rule_id != "cs-task-result-deadlock":
            return True
        key = str(Path(path).resolve())
        if key not in lines:
            text = sources.get(key)
            if text is None:
                try:
                    text = Path(path).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    return True
            critical, unknown = result_lines(text)
            lines[key] = critical | unknown
        location = match["range"].get("end") or match["range"]["start"]
        return location["line"] + 1 in lines[key]

    return qualify


def task_result_lines(text: str) -> set[int]:
    return result_lines(text)[0]


def possible_result_lines(text: str) -> set[int]:
    return result_lines(text)[1]
