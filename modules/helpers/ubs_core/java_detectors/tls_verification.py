"""Prove always-accepting callbacks installed on javax.net.ssl HTTPS clients.

The selected contract is HostnameVerifier.verify returning true after the
default hostname checks fail. A setter name alone is not evidence of disabled
verification. Resolve standard API imports and scoped receiver declarations,
then inspect expression/block lambdas, anonymous verifiers and stable local
aliases. Only a literal accepting return proves this family; delegates,
conditional policies, method references and callbacks with other executable
statements remain outside that proof. No claim of general TLS safety follows
from their absence.

This native detector also qualifies the optional AST evidence, keeping ordinary
findings identical when ast-grep is unavailable. Lexical and budget failures
propagate to the driver's incomplete, uncached scan envelope.

Contract: docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/
HostnameVerifier.html and HttpsURLConnection.html.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterator, Sequence

from ubs_core.analyzers.taint_java_traversal import lexical_source
from ubs_core.io import line_col
from ubs_core.taint_flow import AnalysisLimit

RULE_ID = "java.insecure-ssl"
CATEGORY = 4
TITLE = "HTTPS hostname verifier accepts every hostname"
SEVERITY = "critical"
DESCRIPTION = "Keep the default hostname verifier or delegate to a verifier that authenticates the requested host"
FILE_SCOPED = True
LIMIT_DEFAULTS = {"UBS_JAVA_TLS_MAX_TOKENS": 100_000, "UBS_JAVA_TLS_MAX_NESTING": 192}
_IDENT = r"[A-Za-z_$][\w$]*"
_QUALIFIED = _IDENT + r"(?:\s*\.\s*" + _IDENT + r")*"
_SETTER = re.compile(
    rf"(?<![\w$.])(?:(?P<receiver>{_QUALIFIED})\s*\.\s*)?"
    r"(?P<method>setDefaultHostnameVerifier|setHostnameVerifier)\s*\(")
_DECLARATION = re.compile(
    rf"(?<![\w$.])(?P<type>{_QUALIFIED})\s+(?P<name>{_IDENT})(?=\s*[=;,)])")
_NOT_TYPES = frozenset({"return", "throw", "new", "package", "import", "extends", "implements", "case"})
_NOT_METHODS = frozenset({"if", "while", "for", "switch", "catch", "synchronized", "try"})


def _limit(name: str) -> int:
    try:
        value = int(os.environ.get(name, str(LIMIT_DEFAULTS[name])))
    except ValueError as exc:
        raise AnalysisLimit(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise AnalysisLimit(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class Binding:
    name: str
    type_name: str
    declaration: int
    low: int
    high: int
    initializer: tuple[int, int] | None = None
    field: bool = False


class VerifierSource:
    def __init__(self, text: str):
        self.text = text
        self.code = lexical_source(text, False)
        self.pairs: dict[int, int] = {}
        stack: list[tuple[str, int]] = []
        self.brace_parents: dict[int, int] = {}
        brace_stack: list[int] = []
        token_limit = _limit("UBS_JAVA_TLS_MAX_TOKENS")
        nesting_limit = _limit("UBS_JAVA_TLS_MAX_NESTING")
        for count, token in enumerate(re.finditer(r"[\w$]+|\S", self.code), 1):
            if count > token_limit:
                raise AnalysisLimit("Java TLS token budget exceeded")
            value = token.group()
            if value in {"(", "[", "{"}:
                stack.append((value, token.start()))
                if value == "{":
                    self.brace_parents[token.start()] = brace_stack[-1] if brace_stack else -1
                    brace_stack.append(token.start())
                if len(stack) > nesting_limit:
                    raise AnalysisLimit("Java TLS nesting budget exceeded")
            elif value in {")", "]", "}"}:
                if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[value]:
                    raise ValueError("Unbalanced Java TLS source")
                _, opening = stack.pop()
                self.pairs[opening] = token.start()
                if value == "}":
                    brace_stack.pop()
        if stack:
            raise ValueError("Unbalanced Java TLS source")
        self.braces = [(low, high) for low, high in self.pairs.items() if self.code[low] == "{"]
        self.brace_starts = sorted(self.brace_parents)
        self.imports: dict[str, str] = {}
        self.static_imports: dict[str, str] = {}
        self.wildcards: set[str] = set()
        for match in re.finditer(r"\bimport\s+(static\s+)?([\w.$]+(?:\*)?)\s*;", self.code):
            static, name = match.groups()
            if static:
                self.static_imports[name.rsplit(".", 1)[-1]] = name
            elif name.endswith(".*"):
                self.wildcards.add(name[:-2])
            else:
                self.imports[name.rsplit(".", 1)[-1]] = name
        self.classes: list[tuple[str, int, int]] = []
        self.class_bodies: set[int] = set()
        for match in re.finditer(rf"\b(?:class|interface|enum|record)\s+({_IDENT})[^;{{}}]*\{{", self.code):
            low, high = self.scope(match.start())
            self.classes.append((match.group(1), low, high))
            self.class_bodies.add(match.end() - 1)
        self.functions: list[tuple[int, int, int, int]] = []
        self.method_names: set[str] = set()
        for match in re.finditer(rf"(?<![\w$.])({_IDENT})\s*\(", self.code):
            if match.group(1) in _NOT_METHODS:
                continue
            opening = match.end() - 1
            closing = self.pairs[opening]
            following = self.skip(closing + 1)
            throws = re.match(r"throws\s+[\w$.,\s]+", self.code[following:])
            if throws:
                following = self.skip(following + throws.end())
            if self.code[following:following + 1] != "{":
                continue
            boundary = max(self.code.rfind(char, 0, match.start()) for char in ";{}") + 1
            prefix = self.code[boundary:match.start()].strip()
            if not prefix or re.search(r"\bnew\s*$", prefix) or any(char in prefix for char in "=()!+"):
                continue
            self.method_names.add(match.group(1))
            self.functions.append((opening + 1, closing, following + 1, self.pairs[following]))
        lambdas: list[tuple[int, int, int, int]] = []
        for opening, closing in self.pairs.items():
            if self.code[opening] != "(":
                continue
            arrow = self.skip(closing + 1)
            if self.code[arrow:arrow + 2] == "->":
                body = self.skip(arrow + 2)
                end = self.pairs[body] if self.code[body:body + 1] == "{" else self.expression_end(body, len(self.code))
                lambdas.append((opening + 1, closing, body, end))
        for match in re.finditer(rf"(?<![\w$.])({_IDENT})\s*->", self.code):
            body = self.skip(match.end())
            end = self.pairs[body] if self.code[body:body + 1] == "{" else self.expression_end(body, len(self.code))
            lambdas.append((match.start(1), match.end(1), body, end))
        self.functions.extend(lambdas)
        self.functions.sort()
        parameter_starts = [fn[0] for fn in self.functions]
        self.bindings: dict[str, list[Binding]] = {}
        for match in _DECLARATION.finditer(self.code):
            type_name = re.sub(r"\s+", "", match.group("type"))
            if type_name in _NOT_TYPES:
                continue
            declaration = match.start("name")
            index = bisect_left(parameter_starts, declaration + 1) - 1
            parameter = self.functions[index] if index >= 0 and declaration < self.functions[index][1] else None
            brace, high = self.scope(declaration)
            is_field = brace in self.class_bodies
            low = brace + 1 if is_field else declaration
            if parameter:
                low, high, is_field = parameter[2], parameter[3], False
            tail = self.skip(match.end())
            initializer = None
            if self.code[tail:tail + 1] == "=":
                initializer = (self.skip(tail + 1), self.expression_end(tail + 1, high))
            binding = Binding(match.group("name"), type_name, declaration, low, high, initializer, is_field)
            self.bindings.setdefault(binding.name, []).append(binding)
        # Untyped lambda parameters still shadow an outer HTTPS receiver.
        for low, high, start, end in lambdas:
            for parameter in re.finditer(rf"(?:^|,)\s*({_IDENT})\s*(?=,|$)", self.code[low:high]):
                name = parameter.group(1)
                binding = Binding(name, "", low + parameter.start(1), start, end)
                self.bindings.setdefault(name, []).append(binding)

    def skip(self, position: int) -> int:
        while position < len(self.code) and self.code[position].isspace():
            position += 1
        return position

    def scope(self, position: int) -> tuple[int, int]:
        index = bisect_left(self.brace_starts, position) - 1
        opening = self.brace_starts[index] if index >= 0 else -1
        while opening >= 0 and self.pairs[opening] <= position:
            opening = self.brace_parents[opening]
        return (opening, self.pairs[opening]) if opening >= 0 else (-1, len(self.code))

    def binding(self, name: str, position: int, *, field: bool = False) -> Binding | None:
        visible = [binding for binding in self.bindings.get(name, ())
                   if binding.low <= position < binding.high and (not field or binding.field)]
        return max(visible, key=lambda item: (item.low, item.declaration), default=None)

    def api_type(self, name: str, position: int, short: str) -> bool:
        qualified = "javax.net.ssl." + short
        if name == qualified:
            return self.binding("javax", position) is None and not any(
                declared == "javax" and low < position < high for declared, low, high in self.classes)
        if name != short or any(declared == short and low < position < high
                                for declared, low, high in self.classes):
            return False
        imported = self.imports.get(short)
        return imported == qualified or (imported is None and self.wildcards == {"javax.net.ssl"})

    def connection(self, receiver: str, position: int) -> bool:
        field = receiver.startswith("this.")
        name = receiver[5:] if field else receiver
        if not re.fullmatch(_IDENT, name):
            return False
        binding = self.binding(name, position, field=field)
        return bool(binding and self.api_type(binding.type_name, binding.declaration, "HttpsURLConnection"))

    def expression_end(self, low: int, high: int) -> int:
        while low < high:
            if self.code[low] in "([{":
                low = self.pairs[low] + 1
            elif self.code[low] in ";,})]":
                return low
            else:
                low += 1
        return high

    def trim(self, low: int, high: int) -> tuple[int, int]:
        low = self.skip(low)
        while high > low and self.code[high - 1].isspace():
            high -= 1
        while low < high and self.code[low] == "(" and self.pairs[low] == high - 1:
            low, high = self.trim(low + 1, high - 1)
        return low, high

    def accepting_body(self, low: int, high: int) -> bool:
        low, high = self.trim(low, high)
        if self.code[low:high] == "true":
            return True
        if self.code[low:low + 1] != "{" or self.pairs[low] != high - 1:
            return False
        start = self.skip(low + 1)
        if not re.match(r"return\b", self.code[start:high]):
            return False
        finish = self.expression_end(start + 6, high - 1)
        if self.code[finish:finish + 1] != ";" or self.code[finish + 1:high - 1].strip():
            return False
        start, finish = self.trim(start + 6, finish)
        return self.code[start:finish] == "true"

    def callback(self, low: int, high: int, position: int, seen: frozenset[int] = frozenset()) -> bool:
        low, high = self.trim(low, high)
        if len(seen) >= 64:
            raise AnalysisLimit("Java TLS callback alias budget exceeded")
        expression = self.code[low:high]
        if re.fullmatch(_IDENT, expression):
            binding = self.binding(expression, position)
            if (binding is None or binding.field or binding.initializer is None
                    or binding.initializer[1] > position or binding.declaration in seen):
                return False
            for write in re.finditer(rf"\b{re.escape(expression)}\s*=(?!=)",
                                     self.code[binding.declaration + len(expression):position]):
                offset = binding.declaration + len(expression) + write.start()
                if self.binding(expression, offset) == binding:
                    return False
            return self.callback(*binding.initializer, binding.declaration, seen | {binding.declaration})
        if self.code[low:low + 1] == "(":
            closing = self.pairs[low]
            following = self.skip(closing + 1)
            if self.code[following:following + 2] == "->":
                return self.accepting_body(following + 2, high)
            cast = re.sub(r"\s+", "", self.code[low + 1:closing])
            if self.api_type(cast, low, "HostnameVerifier"):
                return self.callback(following, high, position, seen)
        constructor = re.match(rf"new\s+({_QUALIFIED})\s*\(\s*\)\s*\{{", expression)
        if not constructor or not self.api_type(re.sub(r"\s+", "", constructor.group(1)), low, "HostnameVerifier"):
            return False
        opening = low + constructor.end() - 1
        if self.pairs[opening] != high - 1:
            return False
        method = re.match(r"\s*(?:@(?:java\.lang\.)?Override\s+)?public\s+boolean\s+verify\s*\(",
                          self.code[opening + 1:high - 1])
        if not method:
            return False
        parameters = opening + method.end()
        body = self.skip(self.pairs[parameters] + 1)
        if self.code[body:body + 1] != "{" or self.code[self.pairs[body] + 1:high - 1].strip():
            return False
        return self.accepting_body(body, self.pairs[body] + 1)

    def sites(self) -> list[tuple[int, int, str]]:
        found = []
        for match in _SETTER.finditer(self.code):
            previous = match.start() - 1
            while previous >= 0 and self.code[previous].isspace():
                previous -= 1
            if previous >= 0 and self.code[previous] == ".":
                continue  # A suffix of a computed receiver is not a local binding.
            receiver = re.sub(r"\s+", "", match.group("receiver") or "")
            method = match.group("method")
            position = match.start()
            selected = bool(receiver and self.connection(receiver, position))
            if method == "setDefaultHostnameVerifier":
                selected = selected or bool(receiver and self.api_type(receiver, position, "HttpsURLConnection")
                                            and self.binding(receiver.split(".")[0], position) is None)
                if not receiver and method not in self.method_names:
                    selected = self.static_imports.get(method) == "javax.net.ssl.HttpsURLConnection." + method
            if not selected:
                continue
            opening = match.end() - 1
            if self.callback(opening + 1, self.pairs[opening], position):
                line, col = line_col(self.text, position)
                found.append((line, col, DESCRIPTION))
        return found


def analyze_source(text: str) -> list[tuple[int, int, str]]:
    if not re.search(r"\bset(?:Default)?HostnameVerifier\b", text):
        return []
    return VerifierSource(text).sites()


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() != ".java":
            continue
        text = path.read_text(encoding="utf-8")
        for line, col, detail in analyze_source(text):
            yield path, line, col, detail
