"""Prove that SSLContext.init installs an accepting server trust manager.

The JDK selects the first X509 trust manager in the supplied array. An actual
anonymous X509TrustManager whose two-argument checkServerTrusted override does
nothing accepts untrusted server certificate chains. Neither a similarly named
method nor an empty accepted-issuer list proves that condition.

This bounded slice resolves direct anonymous managers and local initializer
aliases, retaining the objects captured by arrays when variables are rebound.
An intervening element write or unknown call receiving an array invalidates
that array's proof, including writes through aliases. Named implementations,
extended trust-manager overloads and arbitrary callback policies are unknown.
Their absence is not a certificate-policy audit. Lexical and analysis limits
use the shared TLS frontend and propagate through the file-scoped error path.

Contracts: docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/
{SSLContext,X509TrustManager}.html.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterator, Sequence

from ubs_core.java_detectors.tls_verification import Binding, VerifierSource, _limit
from ubs_core.io import line_col
from ubs_core.taint_flow import AnalysisLimit

RULE_ID = "java.security.trust-all-certificates"
CATEGORY = 4
TITLE = "SSLContext installs a trust manager that accepts every server certificate"
SEVERITY = "critical"
DESCRIPTION = "Use provider trust managers or validate the server certificate chain before accepting it"
FILE_SCOPED = True

_IDENT = r"[A-Za-z_$][\w$]*"
_QUALIFIED = _IDENT + r"(?:\s*\.\s*" + _IDENT + r")*"
_INIT = re.compile(rf"(?<![\w$.])(?P<receiver>{_QUALIFIED})\s*\.\s*init\s*\(")
_ARRAY_DECL = re.compile(
    rf"(?<![\w$.])(?P<type>{_QUALIFIED})(?=\s|\[)\s*"
    rf"(?P<before>\[\s*\])?\s*(?P<name>{_IDENT})(?P<after>\s*\[\s*\])?(?=\s*[=;,)])")
_WRITE = re.compile(rf"(?<![\w$.])(?P<name>{_IDENT})\s*=(?!=)")
# Computed receivers can still mutate arguments passed to their call suffixes.
_CALL = re.compile(rf"(?<![\w$])(?P<callee>{_QUALIFIED})\s*\(")
_SERVER = re.compile(r"\bpublic\s+(?:final\s+)?void\s+checkServerTrusted\s*\(")
_UNKNOWN = object()


@dataclass(frozen=True)
class Manager:
    x509: bool
    accepting: bool


@dataclass(frozen=True)
class ManagerArray:
    identity: int
    elements: tuple[object, ...]


class TrustSource:
    def __init__(self, text: str):
        self.source = VerifierSource(text)
        self.code = self.source.code
        self.steps = 0
        self.step_limit = _limit("UBS_JAVA_TLS_MAX_TOKENS")
        self.memo: dict[tuple[int, int], object] = {}
        self.add_array_bindings()
        self.writes: dict[str, list[int]] = {}
        for match in _WRITE.finditer(self.code):
            if self.complete_receiver(match.start()):
                self.writes.setdefault(match.group("name"), []).append(match.start("name"))
        self.elements = sorted(low for low in self.source.pairs if self.code[low] == "[")
        self.calls = list(_CALL.finditer(self.code))
        self.call_starts = [match.start() for match in self.calls]
        self.reverse_pairs = {high: low for low, high in self.source.pairs.items()}
        self.parameter_openings = {fn[0] - 1 for fn in self.source.functions}

    def step(self):
        self.steps += 1
        if self.steps > self.step_limit:
            raise AnalysisLimit("Java TLS trust-manager resolution budget exceeded")

    def complete_receiver(self, position: int) -> bool:
        previous = position - 1
        while previous >= 0 and self.code[previous].isspace():
            previous -= 1
        return previous < 0 or self.code[previous] != "."

    def add_array_bindings(self):
        functions = self.source.functions
        starts = [fn[0] for fn in functions]
        for match in _ARRAY_DECL.finditer(self.code):
            if not (match.group("before") or match.group("after")):
                continue
            self.step()
            name = match.group("name")
            declaration = match.start("name")
            brace, high = self.source.scope(declaration)
            field = brace in self.source.class_bodies
            low = brace + 1 if field else declaration
            index = bisect_right(starts, declaration) - 1
            if index >= 0 and declaration < functions[index][1]:
                low, high, field = functions[index][2], functions[index][3], False
            tail = self.source.skip(match.end())
            initializer = None
            if self.code[tail:tail + 1] == "=":
                initializer = (self.source.skip(tail + 1), self.source.expression_end(tail + 1, high))
            binding = Binding(name, re.sub(r"\s+", "", match.group("type")) + "[]",
                              declaration, low, high, initializer, field)
            self.source.bindings.setdefault(name, []).append(binding)

    def java_type(self, name: str, position: int, qualified: str) -> bool:
        name = re.sub(r"\s+", "", name)
        short = qualified.rsplit(".", 1)[1]
        shadow = name.split(".", 1)[0]
        if any(declared == shadow and low < position < high for declared, low, high in self.source.classes):
            return False
        if name == qualified:
            return self.source.binding(shadow, position) is None
        if name != short:
            return False
        imported = self.source.imports.get(short)
        if imported is not None:
            return imported == qualified
        package = qualified.rsplit(".", 1)[0]
        return package == "java.lang" or self.source.wildcards == {package}

    def context(self, receiver: str, position: int) -> bool:
        receiver = re.sub(r"\s+", "", receiver)
        field = receiver.startswith("this.")
        name = receiver[5:] if field else receiver
        if not re.fullmatch(_IDENT, name):
            return False
        binding = self.source.binding(name, position, field=field)
        return bool(binding and self.source.api_type(binding.type_name, binding.declaration, "SSLContext"))

    def parts(self, low: int, high: int) -> list[tuple[int, int]]:
        parts = []
        start = low
        while low < high:
            self.step()
            if self.code[low] in "([{":
                low = self.source.pairs[low] + 1
                continue
            if self.code[low] == ",":
                parts.append((start, low))
                start = low + 1
            low += 1
        if self.code[start:high].strip():
            parts.append((start, high))
        return parts

    def binding_value(self, name: str, position: int, seen: frozenset[int]) -> object:
        binding = self.source.binding(name, position)
        if (binding is None or binding.field or binding.initializer is None
                or binding.initializer[1] > position):
            return _UNKNOWN
        key = (binding.declaration, position)
        if key in self.memo:
            return self.memo[key]
        if binding.declaration in seen:
            return _UNKNOWN
        if len(seen) >= 64:
            raise AnalysisLimit("Java TLS trust-manager alias budget exceeded")
        for write in self.writes.get(name, ()):
            self.step()
            if binding.declaration < write < position and self.source.binding(name, write) == binding:
                return _UNKNOWN
        value = self.value(*binding.initializer, binding.declaration,
                           seen | {binding.declaration}, binding.type_name)
        self.memo[key] = value
        return value

    def value(self, low: int, high: int, position: int,
              seen: frozenset[int] = frozenset(), declared_type: str = "") -> object:
        self.step()
        low, high = self.source.trim(low, high)
        expression = self.code[low:high]
        if expression == "null":
            return Manager(False, False)  # null cannot be the first X509 instance.
        if re.fullmatch(_IDENT, expression):
            return self.binding_value(expression, position, seen)
        if self.code[low:low + 1] == "(":
            closing = self.source.pairs[low]
            cast = re.sub(r"\s+", "", self.code[low + 1:closing])
            short = cast.removesuffix("[]")
            if any(self.source.api_type(short, low, kind) for kind in ("TrustManager", "X509TrustManager")):
                return self.value(closing + 1, high, position, seen, cast)
        array = re.match(rf"new\s+({_QUALIFIED})\s*\[\s*\]\s*\{{", expression)
        opening = None
        array_type = ""
        if array:
            array_type, opening = array.group(1), low + array.end() - 1
        elif self.code[low:low + 1] == "{" and declared_type.endswith("[]"):
            array_type, opening = declared_type[:-2], low
        if opening is not None:
            if (self.source.pairs[opening] != high - 1 or not any(
                    self.source.api_type(re.sub(r"\s+", "", array_type), low, kind)
                    for kind in ("TrustManager", "X509TrustManager"))):
                return _UNKNOWN
            return ManagerArray(opening, tuple(self.value(start, end, position, seen)
                                               for start, end in self.parts(opening + 1, high - 1)))
        constructor = re.match(rf"new\s+({_QUALIFIED})\s*\(\s*\)\s*\{{", expression)
        if constructor:
            kind = re.sub(r"\s+", "", constructor.group(1))
            opening = low + constructor.end() - 1
            if self.source.pairs[opening] != high - 1:
                return _UNKNOWN
            if self.source.api_type(kind, low, "X509TrustManager"):
                return Manager(True, self.accepting_override(opening, high - 1))
            if self.source.api_type(kind, low, "TrustManager"):
                return Manager(False, False)
        return _UNKNOWN

    def accepting_override(self, opening: int, closing: int) -> bool:
        accepted = []
        for match in _SERVER.finditer(self.code, opening + 1, closing):
            self.step()
            if self.source.scope(match.start())[0] != opening:
                continue
            parameters = match.end() - 1
            end = self.source.pairs[parameters]
            parts = self.parts(parameters + 1, end)
            if len(parts) != 2:
                continue
            chain = re.fullmatch(rf"\s*(?:final\s+)?({_QUALIFIED})\s*\[\s*\]\s*{_IDENT}\s*",
                                 self.code[slice(*parts[0])])
            auth = re.fullmatch(rf"\s*(?:final\s+)?({_QUALIFIED})\s+{_IDENT}\s*", self.code[slice(*parts[1])])
            if (not chain or not auth
                    or not self.java_type(chain.group(1), parameters, "java.security.cert.X509Certificate")
                    or not self.java_type(auth.group(1), parameters, "java.lang.String")):
                continue
            body = self.source.skip(end + 1)
            throws = re.match(r"throws\s+[\w$.,\s]+", self.code[body:])
            if throws:
                body = self.source.skip(body + throws.end())
            if self.code[body:body + 1] != "{":
                continue
            content = re.sub(r"\s+", "", self.code[body + 1:self.source.pairs[body]])
            accepted.append(content in {"", "return;"})
        return accepted == [True]

    def exposes_array(self, low: int, high: int, position: int, array: ManagerArray) -> bool:
        """Track array references escaping through casts and inline containers.

        These wrappers cannot establish an installed manager's identity, but an
        unknown recipient can unwrap them and replace a captured array element.
        Keep that conservative invalidation separate from positive TLS proof.
        """
        self.step()
        low, high = self.source.trim(low, high)
        value = self.value(low, high, position)
        if isinstance(value, ManagerArray) and value.identity == array.identity:
            return True
        if self.code[low:low + 1] == "(":
            closing = self.source.pairs[low]
            cast = self.code[low + 1:closing]
            if closing < high - 1 and re.fullmatch(rf"\s*{_QUALIFIED}(?:\s*\[\s*\])*\s*", cast):
                return self.exposes_array(closing + 1, high, position, array)
        container = re.match(rf"new\s+{_QUALIFIED}(?:\s*\[\s*\])+\s*\{{", self.code[low:high])
        if container:
            opening = low + container.end() - 1
            if self.source.pairs[opening] == high - 1:
                return any(self.exposes_array(start, end, position, array)
                           for start, end in self.parts(opening + 1, high - 1))
        return False

    def changed_array(self, array: ManagerArray, position: int) -> bool:
        for index in range(bisect_right(self.elements, array.identity), bisect_left(self.elements, position)):
            opening = self.elements[index]
            self.step()
            end = self.source.pairs[opening]
            following = self.source.skip(end + 1)
            if self.code[following:following + 1] == "=" and self.code[following + 1:following + 2] != "=":
                receiver_end = opening
                while receiver_end and self.code[receiver_end - 1].isspace():
                    receiver_end -= 1
                if self.code[receiver_end - 1:receiver_end] == ")":
                    receiver_start = self.reverse_pairs[receiver_end - 1]
                else:
                    receiver_start = receiver_end
                    while receiver_start and (self.code[receiver_start - 1].isalnum()
                                              or self.code[receiver_start - 1] in "_$"):
                        receiver_start -= 1
                    if not re.fullmatch(_IDENT, self.code[receiver_start:receiver_end]):
                        continue
                if not self.complete_receiver(receiver_start):
                    continue
                value = self.value(receiver_start, receiver_end, opening)
                if isinstance(value, ManagerArray) and value.identity == array.identity:
                    return True
        for index in range(bisect_right(self.call_starts, array.identity), bisect_left(self.call_starts, position)):
            match = self.calls[index]
            self.step()
            opening = match.end() - 1
            if opening in self.parameter_openings:
                continue
            callee = re.sub(r"\s+", "", match.group("callee"))
            if (callee.endswith(".init") and self.complete_receiver(match.start())
                    and self.context(callee[:-5], match.start())):
                continue
            for low, high in self.parts(opening + 1, self.source.pairs[opening]):
                if self.exposes_array(low, high, match.start(), array):
                    return True
        return False

    def sites(self) -> list[tuple[int, int, str]]:
        findings = []
        for match in _INIT.finditer(self.code):
            self.step()
            position = match.start()
            if not self.complete_receiver(position) or not self.context(match.group("receiver"), position):
                continue
            opening = match.end() - 1
            arguments = self.parts(opening + 1, self.source.pairs[opening])
            if len(arguments) != 3:
                continue
            array = self.value(*arguments[1], position)
            if not isinstance(array, ManagerArray) or self.changed_array(array, position):
                continue
            for manager in array.elements:
                if not isinstance(manager, Manager):
                    break  # An unknown predecessor might be the selected X509 manager.
                if manager.x509:
                    if manager.accepting:
                        line, column = line_col(self.source.text, position)
                        findings.append((line, column, DESCRIPTION))
                    break
        return findings


def analyze_source(text: str) -> list[tuple[int, int, str]]:
    if not re.search(r"\bX509TrustManager\b", text) or not re.search(r"\.\s*init\s*\(", text):
        return []
    return TrustSource(text).sites()


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() == ".java":
            for line, column, detail in analyze_source(path.read_text(encoding="utf-8")):
                yield path, line, column, detail
