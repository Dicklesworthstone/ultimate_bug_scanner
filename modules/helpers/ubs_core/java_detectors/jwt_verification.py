"""Prove Auth0 JWT verification uses an algorithm without a signature.

Auth0 java-jwt's NoneAlgorithm accepts an empty signature. JWT.require captures
the Algorithm in a Verification builder, and build captures that same object
in a JWTVerifier. Claim configuration does not replace the algorithm. Report
the actual verify(String/DecodedJWT) call, or Algorithm.verify(DecodedJWT),
rather than constructing, signing with, or merely decoding such a token.

This bounded native slice resolves real imports, fluent calls, local assignments
and aliases, and initialized final fields in the enclosing class. It preserves
capture time when algorithm, builder, or verifier variables are rebound. A
selected verifier escaping through an unknown helper, a callback, or mutable
heap state makes analysis incomplete. Conditional reassignments with uncertain
None provenance likewise cannot become a speculative critical finding.
Absence of this rule is not a general JWT policy or claims audit.

Contracts: auth0/java-jwt tag 4.6.1, algorithms/NoneAlgorithm.java,
JWTVerifier.java, and interfaces/Verification.java.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterator, Sequence

from ubs_core.io import line_col
from ubs_core.java_detectors.tls_verification import Binding, VerifierSource
from ubs_core.taint_flow import AnalysisLimit

RULE_ID = "java.security.jwt-signature-bypass"
CATEGORY = 4
TITLE = "JWT verification accepts tokens without a cryptographic signature"
SEVERITY = "critical"
DESCRIPTION = "Require a signed JWT algorithm and verify the token with a trusted key"
FILE_SCOPED = True
LIMIT_DEFAULTS = {"UBS_JAVA_JWT_MAX_TOKENS": 100_000, "UBS_JAVA_JWT_MAX_NESTING": 192}

_IDENT = r"[A-Za-z_$][\w$]*"
_QUALIFIED = _IDENT + r"(?:\s*\.\s*" + _IDENT + r")*"
_CALL = re.compile(rf"(?<![\w$])(?P<name>{_IDENT})\s*\(")
_NOT_CALLS = frozenset({"return", "throw", "if", "while", "for", "switch", "catch", "synchronized", "try", "assert"})
_JWT = "com.auth0.jwt.JWT"
_ALGORITHM = "com.auth0.jwt.algorithms.Algorithm"
_VERIFICATION = "com.auth0.jwt.interfaces.Verification"
_VERIFIERS = frozenset({"com.auth0.jwt.JWTVerifier", "com.auth0.jwt.interfaces.JWTVerifier"})
_TYPES = frozenset({_JWT, _ALGORITHM, _VERIFICATION,
                    "com.auth0.jwt.interfaces.DecodedJWT", *_VERIFIERS})
_ALGORITHMS = frozenset({"HMAC256", "HMAC384", "HMAC512", "RSA256", "RSA384", "RSA512",
                         "RSA256PSS", "RSA384PSS", "RSA512PSS", "ECDSA256", "ECDSA384", "ECDSA512"})
_CLAIMS = {
    "withIssuer": (0, None), "withAudience": (0, None), "withAnyOfAudience": (0, None),
    "withSubject": (1, 1), "withJWTId": (1, 1), "withClaimPresence": (1, 1),
    "withNullClaim": (1, 1), "withClaim": (2, 2), "withArrayClaim": (1, None),
    "acceptLeeway": (1, 1), "acceptExpiresAt": (1, 1), "acceptNotBefore": (1, 1),
    "acceptIssuedAt": (1, 1), "ignoreIssuedAt": (0, 0),
}
_SIGNING = frozenset({"withHeader", "withKeyId", "withIssuer", "withSubject", "withAudience",
                      "withExpiresAt", "withNotBefore", "withIssuedAt", "withJWTId", "withClaim",
                      "withNullClaim", "withArrayClaim", "withPayload"})


def _limit(name: str) -> int:
    try:
        value = int(os.environ.get(name, str(LIMIT_DEFAULTS[name])))
    except ValueError as exc:
        raise AnalysisLimit(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise AnalysisLimit(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class Value:
    kind: str
    unsigned: bool = False
    uncertain: bool = False


@dataclass(frozen=True)
class Write:
    start: int
    low: int
    high: int
    binding: Binding | None


_UNKNOWN = Value("unknown")


class JwtSource:
    def __init__(self, text: str):
        token_limit = _limit("UBS_JAVA_JWT_MAX_TOKENS")
        self.source = VerifierSource(text, max_tokens=token_limit,
                                     max_nesting=_limit("UBS_JAVA_JWT_MAX_NESTING"), policy="JWT")
        self.text, self.code = text, self.source.code
        self.steps, self.step_limit = 0, token_limit * 16
        self.reverse = {end: start for start, end in self.source.pairs.items()}
        self.tokens = list(re.finditer(r"[\w$]+|\S", self.code))
        self.token_starts = [token.start() for token in self.tokens]
        self.token_indices = {token.start(): index for index, token in enumerate(self.tokens)}
        self.classes = [(match.group(1), match.end() - 1, self.source.pairs[match.end() - 1])
                        for match in re.finditer(rf"\b(?:class|interface|record|enum)\s+({_IDENT})[^;{{}}]*\{{", self.code)]
        self.methods = []
        for function in self.source.functions:
            match = re.search(rf"({_IDENT})\s*$", self.code[:function[0] - 1])
            if match is not None:
                scope = self.source.scope(match.start())[0]
                if scope in self.source.class_bodies:
                    self.methods.append((match.group(1), scope))
        self.generic_bindings()
        self.writes: list[Write] = []
        self.binding_writes: dict[int, list[Write]] = {}
        self.memo: dict[tuple[int, int], Value] = {}
        self.handled: set[int] = set()
        self.callbacks: list[tuple[int, int]] = []
        for arrow in re.finditer(r"->", self.code):
            low = self.source.skip(arrow.end())
            high = (self.source.pairs[low] + 1 if self.code[low:low + 1] == "{"
                    else self.source.expression_end(low, len(self.code)))
            self.callbacks.append((low, high))
        for match in re.finditer(r"(?<![=!<>+*/%&|^\-])=(?!=|>)", self.code):
            start = self.receiver_start(match.start())
            target = re.sub(r"\s+", "", self.code[start:match.start()])
            binding = self.reference(target, start)
            low = self.source.skip(match.end())
            high = self.source.expression_end(low, len(self.code))
            write = Write(start, low, high, binding)
            self.writes.append(write)
            if binding is not None:
                self.binding_writes.setdefault(binding.declaration, []).append(write)

    def step(self):
        self.steps += 1
        if self.steps > self.step_limit:
            raise AnalysisLimit("Java JWT resolution budget exceeded")

    def receiver_start(self, end: int) -> int:
        """Keep complete grouped/chained receivers; never borrow a suffix name."""
        index = bisect_left(self.token_starts, end) - 1
        while index >= 0:
            self.step()
            token = self.tokens[index]
            if token.group() in {")", "]"}:
                index = self.token_indices[self.reverse[token.start()]]
                preceding = self.tokens[index - 1].group() if index else ""
                if re.fullmatch(_IDENT, preceding) and preceding not in {"return", "throw", "new"}:
                    index -= 1
                    continue
                return self.tokens[index].start()
            if re.fullmatch(_IDENT, token.group()):
                if index > 0 and self.tokens[index - 1].group() == ".":
                    index -= 2
                    continue
                return token.start()
            return token.end()
        return 0

    def generic_bindings(self):
        """Retain local generic callback declarations and their shadowing names."""
        for match in re.finditer(rf"(?<![\w$.])({_QUALIFIED})\s*<", self.code):
            cursor, depth = match.end(), 1
            while cursor < len(self.code) and depth:
                self.step()
                depth += (self.code[cursor] == "<") - (self.code[cursor] == ">")
                if depth > 64:
                    raise AnalysisLimit("Java JWT generic type nesting budget exceeded")
                if self.code[cursor] in ";{}":
                    break
                cursor += 1
            if depth:
                continue
            name = re.match(rf"\s*({_IDENT})(?=\s*[=;,)])", self.code[cursor:])
            if name is None:
                continue
            declaration = cursor + name.start(1)
            brace, high = self.source.scope(declaration)
            field = brace in self.source.class_bodies
            low = brace + 1 if field else declaration
            for parameter_low, parameter_high, body_low, body_high in self.source.functions:
                if parameter_low <= declaration < parameter_high:
                    low, high, field = body_low, body_high, False
                    break
            tail = self.source.skip(cursor + name.end())
            initializer = None
            if self.code[tail:tail + 1] == "=":
                initializer = (self.source.skip(tail + 1), self.source.expression_end(tail + 1, high))
            binding = Binding(name.group(1), re.sub(r"\s+", "", match.group(1)),
                              declaration, low, high, initializer, field)
            self.source.bindings.setdefault(binding.name, []).append(binding)

    def actual_type(self, name: str, position: int, *, expression: bool = True) -> str | None:
        name = re.sub(r"\s+", "", name)
        root = name.split(".", 1)[0]
        if expression and self.source.binding(root, position) is not None or any(
                declared == root and low < position < high for declared, low, high in self.source.classes):
            return None
        if name in _TYPES:
            return name
        if "." in name:
            return None
        imported = self.source.imports.get(name)
        if imported is not None:
            return imported if imported in _TYPES else None
        possible = [actual for actual in _TYPES if actual.rsplit(".", 1)[1] == name
                    and actual.rsplit(".", 1)[0] in self.source.wildcards]
        return possible[0] if len(possible) == 1 else None

    def reference(self, name: str, position: int) -> Binding | None:
        if re.fullmatch(_IDENT, name):
            return self.source.binding(name, position)
        field = re.fullmatch(rf"(this|{_IDENT})(?:\.this)?\.({_IDENT})", name)
        if not field:
            return None
        owner, member = field.groups()
        enclosing = [(declared, low) for declared, low, high in self.classes if low < position < high]
        if owner == "this":
            selected = max((low for _, low in enclosing), default=None)
        else:
            if self.source.binding(owner, position) is not None:
                return None
            selected = max((low for declared, low in enclosing if declared == owner), default=None)
        return next((binding for binding in self.source.bindings.get(member, ())
                     if binding.field and self.source.scope(binding.declaration)[0] == selected), None)

    def final(self, binding: Binding) -> bool:
        boundary = max(self.code.rfind(char, 0, binding.declaration) for char in ";{}") + 1
        return bool(re.search(r"\bfinal\b", self.code[boundary:binding.declaration]))

    def parts(self, low: int, high: int) -> list[tuple[int, int]]:
        parts, start = [], low
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

    def conditional(self, write: Write, position: int) -> bool:
        scope = self.source.scope(position)[0]
        target_scope = self.source.scope(write.start)[0]
        while scope >= 0 and scope != target_scope:
            scope = self.source.brace_parents[scope]
        if scope != target_scope:
            return True
        boundary = max(self.code.rfind(char, 0, write.start) for char in ";{}") + 1
        prefix = self.code[boundary:write.start]
        return bool(re.search(r"\b(?:if|for|while|else)\b|\?", prefix))

    def binding_value(self, binding: Binding, position: int,
                      seen: frozenset[tuple[int, int]]) -> Value:
        key = (binding.declaration, position)
        if key in self.memo:
            return self.memo[key]
        if key in seen:
            return _UNKNOWN
        if len(seen) >= 64:
            raise AnalysisLimit("Java JWT alias budget exceeded")
        seen = seen | {key}
        if binding.field:
            if not self.final(binding) or binding.initializer is None:
                return _UNKNOWN
            value = self.value(*binding.initializer, binding.initializer[0], seen)
        else:
            value = _UNKNOWN
            if binding.initializer is not None and binding.initializer[1] < position:
                value = self.value(*binding.initializer, binding.declaration, seen)
            for write in self.binding_writes.get(binding.declaration, ()):
                self.step()
                if write.start == binding.declaration or not binding.declaration < write.start < position:
                    continue
                selected = self.value(write.low, write.high, write.start, seen)
                if self.conditional(write, position):
                    if value.unsigned or selected.unsigned:
                        kind = value.kind if value.unsigned else selected.kind
                        value = Value(kind, True, True)
                    elif value.kind != selected.kind:
                        value = _UNKNOWN
                else:
                    value = selected
        self.memo[key] = value
        return value

    def static_owner(self, method: str, position: int) -> str | None:
        enclosing = {low for _, low, high in self.classes if low < position < high}
        if any(declared == method and scope in enclosing for declared, scope in self.methods):
            return None
        imported = self.source.static_imports.get(method)
        if imported:
            owner = imported.rsplit(".", 1)[0]
            return owner if owner in {_JWT, _ALGORITHM} else None
        owners = {match.group(1) for match in re.finditer(r"\bimport\s+static\s+([\w.$]+)\.\*\s*;", self.code)}
        selected = _JWT if method in {"require", "create", "decode"} else _ALGORITHM
        return selected if selected in owners else None

    def value(self, low: int, high: int, position: int,
              seen: frozenset[tuple[int, int]] = frozenset(), depth: int = 0) -> Value:
        self.step()
        if depth >= 64:
            raise AnalysisLimit("Java JWT expression depth budget exceeded")
        low, high = self.source.trim(low, high)
        if low >= high:
            return _UNKNOWN
        expression = re.sub(r"\s+", "", self.code[low:high])
        binding = self.reference(expression, position)
        if binding is not None:
            return self.binding_value(binding, position, seen)
        actual = self.actual_type(expression, low)
        if actual is not None:
            return Value("class:" + actual)
        if self.code[low] == "(":
            closing = self.source.pairs[low]
            if closing < high - 1 and self.actual_type(self.code[low + 1:closing], low, expression=False) is not None:
                return self.value(closing + 1, high, position, seen, depth + 1)
        reference = re.search(r"::\s*verify\s*$", self.code[low:high])
        if reference is not None:
            receiver = self.value(low, low + reference.start(), position, seen, depth + 1)
            if receiver.kind in {"algorithm", "verifier"}:
                return Value("callback", receiver.unsigned, receiver.uncertain)
            return _UNKNOWN
        if self.code[high - 1] != ")":
            return _UNKNOWN
        opening = self.reverse[high - 1]
        if opening < low:
            return _UNKNOWN
        method_match = re.search(rf"({_IDENT})\s*$", self.code[low:opening])
        if method_match is None:
            return _UNKNOWN
        method = method_match.group(1)
        prefix_end = low + method_match.start()
        while prefix_end > low and self.code[prefix_end - 1].isspace():
            prefix_end -= 1
        if prefix_end == low:
            owner = self.static_owner(method, low)
            receiver = Value("class:" + owner) if owner else _UNKNOWN
        elif self.code[prefix_end - 1] == ".":
            receiver = self.value(low, prefix_end - 1, position, seen, depth + 1)
        else:
            return _UNKNOWN
        arguments = self.parts(opening + 1, high - 1)
        result = _UNKNOWN
        handled = False
        if receiver.kind == "class:" + _ALGORITHM:
            if method == "none" and not arguments:
                result, handled = Value("algorithm", True), True
            elif method in _ALGORITHMS and arguments:
                result, handled = Value("algorithm"), True
        elif receiver.kind == "class:" + _JWT:  # ubs:ignore[python.ctcompare.secret_eq] public Java class-name tag
            if method == "require" and len(arguments) == 1:
                algorithm = self.value(*arguments[0], position, seen, depth + 1)
                result = Value("builder", algorithm.kind == "algorithm" and algorithm.unsigned, algorithm.uncertain)
                handled = True
            elif method == "create" and not arguments:
                result, handled = Value("signer"), True
            elif method == "decode" and len(arguments) == 1:
                result, handled = Value("decoded"), True
        elif receiver.kind == "builder":
            if method == "build" and not arguments:
                result, handled = Value("verifier", receiver.unsigned, receiver.uncertain), True
            elif method in _CLAIMS:
                minimum, maximum = _CLAIMS[method]
                if len(arguments) >= minimum and (maximum is None or len(arguments) <= maximum):
                    result, handled = receiver, True
        elif receiver.kind == "signer":
            if method in _SIGNING:
                result, handled = receiver, True
            elif method == "sign" and len(arguments) == 1:
                handled = True
        elif receiver.kind in {"algorithm", "verifier"} and method == "verify" and len(arguments) == 1:
            handled = True
        if handled:
            self.handled.add(opening)
        return result

    def unsupported(self, reason: str):
        raise ValueError("Java JWT " + reason + "; analysis is incomplete")

    def sites(self) -> list[tuple[int, int, str]]:
        findings = []
        declarations = {function[0] - 1 for function in self.source.functions}
        for match in _CALL.finditer(self.code):
            self.step()
            opening = match.end() - 1
            if opening in declarations or match.group("name") in _NOT_CALLS:
                continue
            closing = self.source.pairs[opening]
            before = match.start()
            while before > 0 and self.code[before - 1].isspace():
                before -= 1
            dot = before - 1 if self.code[before - 1:before] == "." else None
            start = self.receiver_start(dot) if dot is not None else match.start()
            result = self.value(start, closing + 1, start)
            if result.unsigned and result.kind in {"builder", "verifier"} and any(
                    low <= start < high for low, high in self.callbacks):
                self.unsupported("callback transfer needs callback-state analysis")
            arguments = self.parts(opening + 1, closing)
            if dot is not None:
                receiver = self.value(start, dot, start)
                if receiver.kind == "callback" and receiver.unsigned:
                    self.unsupported("bound verification callback consumption is unresolved")
            if match.group("name") == "verify" and dot is not None and len(arguments) == 1:
                receiver = self.value(start, dot, start)
                if receiver.kind in {"algorithm", "verifier"} and receiver.unsigned:
                    if receiver.uncertain:
                        self.unsupported("conditional verifier state is unresolved")
                    if any(low <= start < high for low, high in self.callbacks):
                        self.unsupported("verification in a callback needs callback-state analysis")
                    findings.append((*line_col(self.text, start), DESCRIPTION))
            if opening not in self.handled:
                for low, high in arguments:
                    argument = self.value(low, high, start)
                    if argument.unsigned and argument.kind in {"builder", "verifier", "callback"}:
                        self.unsupported("verifier transfer to an unknown helper is unresolved")
        for write in self.writes:
            value = self.value(write.low, write.high, write.start)
            if not value.unsigned:
                continue
            if write.binding is None or write.binding.field and not self.final(write.binding):
                self.unsupported("mutable field or heap transfer is unresolved")
        for low, high in self.callbacks:
            value = self.value(low, high, low)
            if value.unsigned and value.kind in {"builder", "verifier", "callback"}:
                self.unsupported("callback transfer needs callback-state analysis")
        for match in re.finditer(r"\breturn\b", self.code):
            low = self.source.skip(match.end())
            high = self.source.expression_end(low, len(self.code))
            value = self.value(low, high, low)
            if value.unsigned and value.kind in {"builder", "verifier", "callback"}:
                self.unsupported("verifier returned through a helper is unresolved")
        return findings


def analyze_source(text: str) -> list[tuple[int, int, str]]:
    if not re.search(r"\b(?:none|verify)\s*\(", text):
        return []
    return JwtSource(text).sites()


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() != ".java":
            continue
        for line, col, detail in analyze_source(path.read_text(encoding="utf-8")):
            yield path, line, col, detail
