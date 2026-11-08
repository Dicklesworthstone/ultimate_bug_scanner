"""Bounded, value-specific ASP.NET response-header injection analysis.

The C# CFG supplies lexical bindings, strong updates and local helper/ref/out
summaries. API identities distinguish actual request/response objects from
lookalike names. Only proven CLR string replacements, URL encoding, or a
dominating check of the exact value establish CR/LF safety. Unknown transforms
discard that proof. Location writes retain the dedicated redirect policy.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_csharp_request import CSharpFlow, parts, request_source_demand
from ubs_core.analyzers.taint_csharp_sql import (
    CONTEXT, REQUEST, TypeIndex, api_fact, identities, provenance,
)
from ubs_core.csharp_detectors._common import relpath, source_line
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, CLEAN, Trace, advance, join, retag

RULE_ID = "csharp.security.header-injection"
CATEGORY = 8
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = "Reject or strip both CR and LF from the actual header value, or URL-encode filename fragments"
RESPONSE = "Microsoft.AspNetCore.Http.HttpResponse"
HEADERS = "Microsoft.AspNetCore.Http.IHeaderDictionary"
TYPED_HEADERS = "Microsoft.AspNetCore.Http.Headers.ResponseHeaders"
HEADER_EXTENSIONS = "Microsoft.AspNetCore.Http.HeaderDictionaryExtensions"
STRING = "System.String"
STRING_VALUES = "Microsoft.Extensions.Primitives.StringValues"
URL_ENCODER = "System.Text.Encodings.Web.UrlEncoder"
CONTEXT_OWNERS = frozenset({
    "Microsoft.AspNetCore.Http.IHttpContextAccessor", "Microsoft.AspNetCore.Http.HttpContextAccessor",
    "Microsoft.AspNetCore.Mvc.ControllerContext", "Microsoft.AspNetCore.Mvc.ActionContext",
})
ATTRIBUTES = frozenset("Microsoft.AspNetCore.Mvc." + name + "Attribute" for name in (
    "FromQuery", "FromHeader", "FromRoute", "FromForm", "FromBody"))
KNOWN_TYPES = ATTRIBUTES | CONTEXT_OWNERS | frozenset({
    RESPONSE, HEADERS, TYPED_HEADERS, HEADER_EXTENSIONS, STRING_VALUES, URL_ENCODER,
    "Microsoft.AspNetCore.Http.HeaderDictionary", "Microsoft.AspNetCore.Http.DefaultHttpContext",
    "System.Uri", "System.Net.WebUtility", "System.Web.HttpUtility", "System.StringComparison",
})
COLLECTIONS = {
    "Query": "request-query", "Form": "request-form", "Headers": "request-headers",
    "Cookies": "request-cookies", "RouteValues": "request-route",
}
REQUEST_SCALARS = frozenset({"Host", "Path", "PathBase", "RawTarget", "QueryString"})
HEADER_METHODS = frozenset({"Append", "Add", "Set", "TryAdd", "AppendCommaSeparatedValues", "SetCommaSeparatedValues"})
HEADER_SAFE = frozenset({"header-no-cr", "header-no-lf"})
CONTROL_TAG = {"\r": "header-no-cr", "\n": "header-no-lf"}


def string_literal(raw):
    """Decode fixed C# string/char literals, never executable interpolation."""
    raw = raw.strip()
    if raw.startswith('@"') and raw.endswith('"'):
        inner = raw[2:-1]
        if re.fullmatch(r'(?:[^"]|"")*', inner):
            return inner.replace('""', '"')
        return None
    quoted = re.fullmatch(r'("{3,})(.*?)\1', raw, re.DOTALL)
    if quoted:
        inner = quoted.group(2)
        if not any(char in inner for char in "\r\n"):
            return inner
        opening = re.match(r"[ \t]*(?:\r\n|\r|\n)", inner)
        closing = re.search(r"(?:\r\n|\r|\n)([ \t]*)$", inner)
        if opening is None or closing is None or opening.end() > closing.start():
            return None
        indent, lines = closing.group(1), inner[opening.end():closing.start()].splitlines(keepends=True)
        result = []
        for line in lines:
            if line.startswith(indent):
                result.append(line[len(indent):])
            elif not line.strip() and indent.startswith(line.rstrip("\r\n")):
                result.append(line.lstrip(" \t"))
            else:
                return None
        return "".join(result)
    if len(raw) < 2 or raw[0] not in "\"'" or raw[-1] != raw[0]:
        return None
    quote, inner = raw[0], raw[1:-1]
    output, position = [], 0
    escapes = {"0": "\0", "a": "\a", "b": "\b", "f": "\f", "n": "\n",
               "r": "\r", "t": "\t", "v": "\v", "'": "'", '"': '"', "\\": "\\"}
    while position < len(inner):
        char = inner[position]
        if char == quote or char in "\r\n":
            return None
        if char != "\\":
            output.append(char)
            position += 1
            continue
        position += 1
        if position >= len(inner):
            return None
        escape = inner[position]
        if escape in escapes:
            output.append(escapes[escape])
            position += 1
            continue
        width = {"u": 4, "U": 8}.get(escape)
        pattern = rf"[0-9a-fA-F]{{{width}}}" if width else r"[0-9a-fA-F]{1,4}" if escape == "x" else None
        match = re.match(pattern, inner[position + 1:]) if pattern else None
        if match is None:
            return None
        number = int(match.group(), 16)
        if number > 0x10ffff:
            return None
        output.append(chr(number))
        position += 1 + len(match.group())
    value = "".join(output)
    return value if quote == '"' or len(value) == 1 else None


def controls(value):
    return frozenset(trace.key[0] for trace in value if trace.kind == "header-control")


def text_fact(text):
    return join(api_fact(STRING), frozenset(Trace("header-control", (char,)) for char in "\r\n" if char in text))


def combine(*values):
    value = join(*values)
    return retag(value, remove=frozenset(CONTROL_TAG[char] for char in controls(value)))


class HeaderFlow(CSharpFlow):
    rule, message = RULE_ID, TITLE

    def __init__(self, path, text):
        super().__init__(path, text)
        self.types = TypeIndex(self, KNOWN_TYPES)
        self.openings = {closing: opening for opening, closing in self.parser.pairs.items()}
        self.annotated = set()
        self.boundaries = {}
        self.issues = set()
        self.fields = {}
        self.field_cache = {}
        for match in re.finditer(r"\b([\w.:]+)\s+(@?\w+)\s*(?=[=;{])", self.code):
            if any(key >= 0 and function.declaration <= match.start() < function.end
                   for key, function in self.parser.functions.items()):
                continue
            self.fields[(self.types.owner(match.start()), match.group(2).lstrip("@"))] = (
                self.types.resolve(match.group(1), match.start()))
        for key, function in self.parser.functions.items():
            if key < 0:
                continue
            opening = self.code.find("(", key, function.start)
            if opening not in self.parser.pairs:
                continue
            for index, (low, high) in enumerate(parts(
                    self.code, opening + 1, self.parser.pairs[opening], generics=True)):
                position = low
                while position < high:
                    if self.code[position] != "[":
                        position += 1
                        continue
                    closing = self.parser.pairs[position]
                    for first, last in parts(self.code, position + 1, closing, generics=True):
                        attribute = re.match(r"\s*(?:param\s*:\s*)?([\w@.:]+)", self.code[first:last])
                        if attribute is None:
                            continue
                        spelling = attribute.group(1)
                        identity = self.types.resolve(spelling, first)
                        if identity.startswith("unknown:"):
                            identity = self.types.resolve(spelling + "Attribute", first)
                        if identity in ATTRIBUTES:
                            self.annotated.add((key, index))
                    position = closing + 1

    def field_type(self, owner, name, visiting=()):
        """Resolve declared members without treating their spelling as a type."""
        key = (owner, name)
        if key in self.fields:
            return self.fields[key]
        if key in self.field_cache:
            return self.field_cache[key]
        if owner in visiting or len(visiting) >= 12:
            raise AnalysisLimit("C# header field inheritance is unresolved; analysis is incomplete")
        self.budget.spend()
        scope = self.types.local_types.get(".".join(owner))
        found = set()
        if scope is not None and ":" in scope.bases:
            for spelling in scope.bases.split(":", 1)[1].split(","):
                identity = self.types.resolve(spelling.strip(), scope.start)
                if identity.startswith("local:"):
                    inherited = self.field_type(tuple(identity[6:].split(".")), name, (*visiting, owner))
                    if inherited:
                        found.add(inherited)
        identity = next(iter(found)) if len(found) == 1 else "ambiguous:" + name if found else ""
        self.field_cache[key] = identity
        return identity

    def visible_field(self, name, position):
        owner = self.types.owner(position)
        for size in range(len(owner), 0, -1):
            identity = self.field_type(owner[:size], name)
            if identity:
                return identity
        return ""

    def value_root(self, spelling, position, bindings):
        if spelling.startswith("global::"):
            return False
        root = spelling.split(".")[0].lstrip("@")
        return root in bindings or bool(self.visible_field(root, position))

    def is_source(self, name):
        return False

    def parameter_fact(self, function, index):
        value = super().parameter_fact(function, index)
        if (function.key, index) in self.annotated:
            value = join(value, self.source_fact(function.key, "request-bound " + function.parameters[index]))
        spelling = function.parameter_types[index] if index < len(function.parameter_types) else ""
        return join(value, api_fact(self.types.resolve(spelling, function.key)))

    def name_value(self, name, position, state, bindings):
        global_name = self.code[position:position + 8] == "global::"
        pieces = name.split(".")
        explicit_this = pieces[0] == "this" and len(pieces) > 1
        if explicit_this:
            pieces = pieces[1:]
        root, members = pieces[0], pieces[1:]
        field = self.visible_field(root, position) if not global_name else ""
        value = state.get(bindings.get(root, ""), CLEAN) if not explicit_this and not global_name else CLEAN
        if field and (explicit_this or root not in bindings):
            value = api_fact(field)
        controller_members = {"Request": REQUEST, "Response": RESPONSE, "HttpContext": CONTEXT,
                              "ControllerContext": "Microsoft.AspNetCore.Mvc.ControllerContext"}
        if (root in controller_members and not field and (explicit_this or root not in bindings)
                and self.types.controller(position)):
            value = api_fact(controller_members[root])
        for member in members:
            current = identities(value)
            if current & CONTEXT_OWNERS and member == "HttpContext":
                value = api_fact(CONTEXT)
            elif current & {CONTEXT, "Microsoft.AspNetCore.Http.DefaultHttpContext"} and member in {"Request", "Response"}:
                value = api_fact(REQUEST if member == "Request" else RESPONSE)
            elif REQUEST in current and member in COLLECTIONS:
                value = join(self.source_fact(position, name), api_fact(COLLECTIONS[member]))
            elif REQUEST in current and member in REQUEST_SCALARS:
                value = join(self.source_fact(position, name), api_fact(STRING))
            elif RESPONSE in current and member == "Headers":
                value = api_fact(HEADERS)
            elif URL_ENCODER in current and member == "Default":
                value = api_fact(URL_ENCODER)
            elif member == "Value" and STRING in current:
                value = join(provenance(value), api_fact(STRING))
            else:
                declared = [self.field_type(tuple(identity[6:].split(".")), member)
                            for identity in current if identity.startswith("local:")]
                value = join(provenance(value), *(api_fact(identity) for identity in declared if identity))
        spelling = ("global::" if global_name else "") + name
        if not value and name.endswith(".Default") and not self.value_root(spelling, position, bindings):
            if self.types.resolve(spelling.rsplit(".", 1)[0], position) == URL_ENCODER:
                return api_fact(URL_ENCODER)
        return value

    def call_candidates(self, name, args, values, state, bindings, position):
        pieces = name.split(".")
        if len(pieces) == 1 or pieces[0] == "this":
            return super().call_candidates(name, args, values, state, bindings, position)
        owner = name.rsplit(".", 1)[0]
        raw = ("global::" if self.code[position:position + 8] == "global::" else "") + owner
        if self.value_root(raw, position, bindings):
            owners = identities(self.name_value(owner, position, state, bindings))
        else:
            owners = {self.types.resolve(raw, position)}
        local = {identity.removeprefix("local:") for identity in owners if identity.startswith("local:")}
        return [function for function in self.parser.functions.values()
                if function.parent is None and function.name == pieces[-1]
                and ".".join(function.owner) in local
                and len(function.parameters) - function.defaults <= len(args) <= len(function.parameters)]

    def call_context(self, callee, args, values, bindings, state):
        summary, actuals, cells = super().call_context(callee, args, values, bindings, state)
        # Declared parameter types own API identity inside a typed helper.
        # Substituting a StringValues argument into a string parameter must
        # not reintroduce its pre-conversion identity into a string result.
        actuals = {key: frozenset(trace for trace in value if trace.kind != "api")
                   for key, value in actuals.items()}
        return summary, actuals, cells

    def trim(self, start, end):
        while True:
            while start < end and self.text[start].isspace():
                start += 1
            while end > start and (self.text[end - 1].isspace() or self.code[end - 1] == ";"):
                end -= 1
            if end > start and self.code[end - 1] == "!" and self.code[end - 2:end] != "!=":
                end -= 1
            elif self.code[start:start + 1] == "(" and self.parser.pairs.get(start) == end - 1:
                start, end = start + 1, end - 1
            else:
                return start, end

    def constant(self, start, end, bindings=None):
        start, end = self.trim(start, end)
        raw = self.text[start:end].strip()
        value = string_literal(raw)
        if value is not None:
            return value
        match = re.fullmatch(r"([\w@.:]+)\.Empty", raw)
        if match and not self.value_root(match.group(1), start, bindings or {}):
            if self.types.resolve(match.group(1), start) == STRING:
                return ""
        return None

    def receiver(self, call):
        owner = call.name.rsplit(".", 1)[0] if "." in call.name else ""
        return self.name_value(owner, call.position, call.state, call.bindings) if owner else CLEAN

    def unsafe(self, value):
        return frozenset(trace for trace in combine(value)
                         if trace.kind in {"source", "parameter"} and not HEADER_SAFE <= trace.tags)

    def record(self, position, name, value):
        value = self.unsafe(value)
        if value:
            key = (position, name)
            self.effects[key] = join(self.effects.get(key, CLEAN),
                                     advance(value, self.step(position, "sink", name)))

    def heap_boundary(self, position, value):
        # Keep abstract helper parameters until actual request arguments have
        # been substituted. An unused or constant-only setter is not a source.
        reason = "request-derived heap write is unresolved; header analysis is incomplete"
        key = (position, "<header-boundary> " + reason)
        self.boundaries[key] = reason
        fact = advance(provenance(value), self.step(position, "boundary", reason))
        self.effects[key] = join(self.effects.get(key, CLEAN), fact)

    def concrete_effect(self, key, fact):
        if key in self.boundaries:
            if super().concrete_effect(key, fact):
                self.issues.add(f"line {self.step(key[0], 'boundary', '').line}: {self.boundaries[key]}")
            return CLEAN
        return super().concrete_effect(key, self.unsafe(fact))

    def call_value(self, call):
        owner, _, method = call.name.rpartition(".")
        receiver = self.receiver(call)
        identities_ = identities(receiver)
        if method == "GetTypedHeaders" and RESPONSE in identities_ and not call.args:
            return api_fact(TYPED_HEADERS)
        if method == "TryGetValue" and identities_ & set(COLLECTIONS.values()):
            for _, low, high in call.args:
                output = re.fullmatch(r"\s*out\s+(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*", self.code[low:high])
                cell = call.bindings.get(output.group(1).lstrip("@")) if output else None
                if cell:
                    call.state[cell] = join(provenance(receiver), api_fact(STRING_VALUES))
            return CLEAN
        if method == "ToString" and not call.args and identities_ & {STRING, STRING_VALUES}:
            return join(frozenset(trace for trace in receiver if trace.kind != "api"), api_fact(STRING))
        raw_owner = ("global::" if self.code[call.position:call.position + 8] == "global::" else "") + owner
        identity = self.types.resolve(raw_owner, call.position) if not self.value_root(raw_owner, call.position, call.bindings) else ""
        encodes = (identity == "System.Uri" and method in {"EscapeDataString", "EscapeUriString"}
                   or identity in {"System.Net.WebUtility", "System.Web.HttpUtility"} and method == "UrlEncode"
                   or identities_ == {URL_ENCODER} and method == "Encode")
        if encodes and len(call.values) == 1:
            return join(retag(provenance(call.values[0]), add=HEADER_SAFE), api_fact(STRING))
        constructor = self.code[max(0, call.position - 5):call.position]
        if re.search(r"\bnew\s+$", constructor):
            raw = ("global::" if self.code[call.position:call.position + 8] == "global::" else "") + call.name
            return join(provenance(join(*call.values)), api_fact(self.types.resolve(raw, call.position)))
        value = retag(provenance(join(receiver, *call.values)), remove=HEADER_SAFE)
        for _, low, high in call.args:
            output = re.fullmatch(r"\s*(?:ref|out)\s+(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*", self.code[low:high])
            cell = call.bindings.get(output.group(1).lstrip("@")) if output else None
            if cell:
                call.state[cell] = retag(join(call.state.get(cell, CLEAN), value), remove=HEADER_SAFE)
        return value

    @staticmethod
    def argument(args, names, ordinal):
        named = [index for index, (key, _, _) in enumerate(args) if key in names]
        if named:
            return named[0]
        return ordinal if ordinal < len(args) and args[ordinal][0] is None else None

    def call_sink_facts(self, call):
        owner, _, method = call.name.rpartition(".")
        if method not in HEADER_METHODS:
            return []
        receiver, shift = self.receiver(call), 0
        raw_owner = ("global::" if self.code[call.position:call.position + 8] == "global::" else "") + owner
        if (not self.value_root(raw_owner, call.position, call.bindings)
                and self.types.resolve(raw_owner, call.position) == HEADER_EXTENSIONS):
            index = self.argument(call.args, {"headers"}, 0)
            receiver = call.values[index] if index is not None else CLEAN
            shift = 1
        return self.header_sink_facts(receiver, call.args, call.values, call.bindings, shift)

    def header_sink_facts(self, receiver, args, values, bindings, shift=0):
        if not identities(receiver) & {HEADERS, "Microsoft.AspNetCore.Http.HeaderDictionary"}:
            return []
        key = self.argument(args, {"key", "name"}, shift)
        value = self.argument(args, {"value", "values"}, shift + 1)
        if key is None or value is None:
            return []
        header = self.constant(*args[key][1:], bindings)
        if header is not None and header.casefold() == "location":
            return []
        return [(value, self.unsafe(values[value]))]

    def replace_value(self, receiver, args, values, bindings):
        if identities(receiver) != {STRING} or len(args) != 2:
            return retag(provenance(join(receiver, *values)), remove=HEADER_SAFE)
        names = {key for key, _, _ in args if key is not None}
        old_index = self.argument(args, {"oldValue", "oldChar"}, 0)
        new_index = self.argument(args, {"newValue", "newChar"}, 1)
        if (old_index is None or new_index is None or old_index == new_index
                or not (names <= {"oldValue", "newValue"} or names <= {"oldChar", "newChar"})):
            return retag(provenance(join(receiver, *values)), remove=HEADER_SAFE)
        old = self.constant(*args[old_index][1:], bindings)
        new = self.constant(*args[new_index][1:], bindings)
        value = frozenset(trace for trace in receiver if trace.kind != "api")
        if new is None:
            return join(retag(provenance(join(value, values[new_index])), remove=HEADER_SAFE), api_fact(STRING))
        added = frozenset({CONTROL_TAG[old]}) if old in CONTROL_TAG and old not in new else frozenset()
        value = frozenset(trace for trace in value if trace.kind != "header-control" or trace.key[0] != old or old in new)
        return combine(retag(value, add=added), text_fact(new))

    def interpolated_text(self, start, end):
        """Read literal output, skipping the frontend's exact expression holes."""
        match = re.match(r'(\$+@?|@\$)("{3,}|")', self.text[start:end])
        if match is None:
            return None
        prefix, delimiter = match.groups()
        raw, verbatim = len(delimiter) >= 3, "@" in prefix
        width = prefix.count("$") if raw else 1
        position, literal = start + match.end(), []
        while position < end:
            self.budget.spend()
            if self.text.startswith(delimiter, position):
                if verbatim and not raw and self.text.startswith('""', position):
                    literal.append('""')
                    position += 2
                    continue
                if position + len(delimiter) != end:
                    return None
                spelling = ("@" if verbatim else "") + delimiter + "".join(literal) + delimiter
                value = string_literal(spelling)
                if value is None:
                    raise AnalysisLimit("C# interpolated header literal is unresolved; analysis is incomplete")
                return value
            if not raw and not verbatim and self.text[position] == "\\":
                literal.append(self.text[position:position + 2])
                position += 2
                continue
            opening = position + width - 1
            if self.text.startswith("{" * width, position) and self.code[opening:opening + 1] == "(":
                closing = self.parser.pairs.get(opening)
                if closing is None or closing + width > end:
                    raise AnalysisLimit("C# header interpolation boundary is unresolved; analysis is incomplete")
                # A nonempty placeholder preserves raw-string indentation
                # while discarding expression syntax from the literal text.
                literal.append("x")
                position = closing + width
                continue
            literal.append(self.text[position])
            position += 1
        return None

    def evaluate(self, start, end, state, bindings, depth=0):
        self.budget.spend()
        if depth > 96:
            raise AnalysisLimit("C# header expression nesting limit exceeded; analysis is incomplete")
        start, end = self.trim(start, end)
        if start >= end:
            return CLEAN
        constant = self.constant(start, end, bindings)
        if constant is not None:
            return text_fact(constant)
        segments = list(parts(self.code, start, end, separator="+"))
        if len(segments) > 1 and all(self.code[low:high].strip() for low, high in segments):
            return combine(*(self.evaluate(low, high, state, bindings, depth + 1) for low, high in segments))
        literal = self.interpolated_text(start, end)
        if literal is not None:
            return combine(super().evaluate(start, end, state, bindings, depth), text_fact(literal))
        # Complete postfix expressions preserve the receiver of chained CLR
        # string operations; the generic request frontend deliberately joins
        # arbitrary expressions and does not give a chain sanitizer semantics.
        if self.code[end - 1] == ")" and end - 1 in self.openings:
            opening = self.openings[end - 1]
            methods = "|".join(sorted(HEADER_METHODS | {"Replace", "ToString", "GetTypedHeaders"}))
            suffix = re.search(r"\.\s*(" + methods + r")\s*$", self.code[start:opening])
            if (suffix and suffix.group(1) in HEADER_METHODS
                    and re.fullmatch(r"[\w@.\s:]+", self.code[start:start + suffix.start()])):
                # Ordinary named receivers use local-method resolution in the
                # shared evaluator. Only a compound receiver needs this path.
                suffix = None
            if suffix:
                stop = start + suffix.start()
                receiver = self.evaluate(start, stop, state, bindings, depth + 1)
                args = self.arguments(opening + 1, end - 1)
                values = [self.evaluate(low, high, state, bindings, depth + 1) for _, low, high in args]
                method = suffix.group(1)
                if method == "Replace":
                    return self.replace_value(receiver, args, values, bindings)
                if method == "GetTypedHeaders" and RESPONSE in identities(receiver) and not args:
                    return api_fact(TYPED_HEADERS)
                if method == "ToString" and identities(receiver) & {STRING, STRING_VALUES} and not args:
                    return join(frozenset(trace for trace in receiver if trace.kind != "api"), api_fact(STRING))
                if method in HEADER_METHODS:
                    if identities(receiver) & {HEADERS, "Microsoft.AspNetCore.Http.HeaderDictionary"}:
                        name = re.sub(r"\s+", "", self.code[start:opening])
                        for _, value in self.header_sink_facts(receiver, args, values, bindings):
                            self.record(start, name, value)
                        return CLEAN
                    # A helper's first summary may still be empty. Retaining
                    # its ordinary dependency lets the fixpoint revisit it.
                    return combine(super().evaluate(start, end, state, bindings, depth))
                return retag(provenance(join(receiver, *values)), remove=HEADER_SAFE)
        if self.code[end - 1] == "]" and end - 1 in self.openings:
            opening = self.openings[end - 1]
            if opening > start:
                receiver = self.evaluate(start, opening, state, bindings, depth + 1)
                index = self.evaluate(opening + 1, end - 1, state, bindings, depth + 1)
                current = identities(receiver)
                if current & set(COLLECTIONS.values()):
                    identity = STRING if current & {"request-cookies", "request-route"} else STRING_VALUES
                    return join(provenance(receiver), api_fact(identity))
                if current & {HEADERS, "Microsoft.AspNetCore.Http.HeaderDictionary"}:
                    return api_fact(STRING_VALUES)
                return combine(provenance(receiver), provenance(index))
        return combine(super().evaluate(start, end, state, bindings, depth))

    def guard_parts(self, start, end, bindings):
        start, end = self.trim(start, end)
        if self.code[start:start + 1] == "!":
            guard = self.guard_parts(start + 1, end, bindings)
            return (guard[0], guard[1], not guard[2]) if guard else None
        for separator, truth in (("|", False), ("&", True)):
            spans = list(parts(self.code, start, end, separator=separator))
            if len(spans) > 1:
                if len(spans) % 2 != 1 or any(self.code[low:high].strip() for low, high in spans[1::2]):
                    return None
                guards = [self.guard_parts(low, high, bindings) for low, high in spans[::2]]
                if (any(guard is None or guard[2] != truth for guard in guards)
                        or len({guard[0] for guard in guards}) != 1):
                    return None
                return guards[0][0], frozenset().union(*(guard[1] for guard in guards)), truth
        match = re.match(r"(@?\w+)\s*\.\s*Contains\s*\(", self.code[start:end])
        if not match:
            return None
        opening = start + match.end() - 1
        if self.parser.pairs.get(opening) != end - 1:
            return None
        args = self.arguments(opening + 1, end - 1)
        if len(args) not in {1, 2}:
            return None
        if len(args) == 2:
            option = re.sub(r"\s", "", self.code[slice(*args[1][1:])])
            owner, _, member = option.rpartition(".")
            if (self.value_root(owner, opening, bindings) or self.types.resolve(owner, opening) != "System.StringComparison"
                    or member not in {"Ordinal", "OrdinalIgnoreCase"}):
                return None
        char = self.constant(*args[0][1:], bindings)
        return (match.group(1).lstrip("@"), frozenset({CONTROL_TAG[char]}), False) if char in CONTROL_TAG else None

    def path_guard(self, span, bindings=None):
        return self.guard_parts(*span, bindings or {})

    def apply_guard(self, action, state):
        name, tags = action.guard
        cell = action.bindings.get(name)
        value = state.get(cell, CLEAN)
        if cell and identities(value) == {STRING}:
            state[cell] = retag(value, add=tags)
        return state

    def transfer(self, action, state):
        start, end = action.span
        if action.kind in {"simple", "eval"}:
            # Find a top-level setter; never mistake an assignment inside
            # an initializer for a response header write. Comparisons and
            # lambda arrows are not setters, including when the RHS of an
            # actual assignment also contains a comparison.
            assignments = [position for _, position in parts(self.code, start, end, separator="=")
                           if position < end
                           and self.code[position - 1:position] not in {"!", "<", ">", "="}
                           and self.code[position + 1:position + 2] not in {"=", ">"}]
            if len(assignments) == 1:
                lhs_start, lhs_end = self.trim(start, assignments[0])
                rhs_start, rhs_end = assignments[0] + 1, end
                if self.code[lhs_end - 1:lhs_end] == "+":
                    lhs_start, lhs_end = self.trim(lhs_start, lhs_end - 1)
                header, receiver_end = None, None
                if lhs_end > lhs_start and self.code[lhs_end - 1] == "]":
                    opening = self.openings.get(lhs_end - 1)
                    if opening is not None:
                        receiver_end = opening
                        header = self.constant(opening + 1, lhs_end - 1, action.bindings)
                else:
                    prop = re.search(r"\.\s*(\w+)\s*$", self.code[lhs_start:lhs_end])
                    if prop:
                        receiver_end, header = lhs_start + prop.start(), prop.group(1)
                if receiver_end is not None:
                    receiver = self.evaluate(lhs_start, receiver_end, state, action.bindings)
                    owners = identities(receiver)
                    sink = bool(owners & {HEADERS, TYPED_HEADERS, "Microsoft.AspNetCore.Http.HeaderDictionary"})
                    sink = sink or (RESPONSE in owners and header == "ContentType")
                    if sink:
                        value = self.evaluate(rhs_start, rhs_end, state, action.bindings)
                        if header is None or header.casefold() != "location":
                            name = re.sub(r"\s+", "", self.code[lhs_start:receiver_end]) + ".header"
                            self.record(lhs_start, name, value)
                        return state
                target = self.code[lhs_start:lhs_end].strip()
                unbound = re.fullmatch(r"@?\w+", target) and target.lstrip("@") not in action.bindings
                if receiver_end is not None or unbound:
                    value = self.evaluate(rhs_start, rhs_end, state, action.bindings)
                    self.heap_boundary(lhs_start, value)
                    return state
        result = super().transfer(action, state)
        return {cell: combine(value) for cell, value in result.items()}

    def analyze(self):
        error = None
        try:
            # The shared fixpoint substitutes actual arguments into helper
            # effects. Safety must be filtered after that substitution too.
            for _ in super().analyze():
                pass
        except (AnalysisLimit, ValueError) as exc:
            error = exc
        effects = {}
        for summary in self.summaries.values():
            for key, value in summary.effects.items():
                concrete = self.concrete_effect(key, value)
                effects[key] = join(effects.get(key, CLEAN), concrete)
        for (offset, name), value in sorted(effects.items()):
            if not value:
                continue
            location = self.step(offset, "sink", name)
            witness = min(value, key=lambda trace: (len(trace.evidence), trace.evidence, trace.key))
            yield {"rule": RULE_ID, "path": str(self.path), "line": location.line, "col": location.column,
                   "extras": {"taint_path": [step.record() for step in witness.evidence]}}
        if error is not None:
            raise error
        if self.issues:
            raise AnalysisLimit("; ".join(sorted(self.issues)))


def find(files: Sequence[Path], base_dir: Path | None = None) -> Iterable[tuple[Path, int, int, str]]:
    base = base_dir if base_dir is not None else Path.cwd()
    for path in files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        # Only an optimization; arbitrary query keys and local aliases remain
        # relevant, and comment/string decoys are removed by the frontend.
        if not re.search(r"\b(?:Headers|GetTypedHeaders|IHeaderDictionary|ContentType|Append|Add|Set|TryAdd|AppendCommaSeparatedValues|SetCommaSeparatedValues)\b", text):
            continue
        if not request_source_demand(text, set(COLLECTIONS) | REQUEST_SCALARS, ATTRIBUTES):
            continue
        suppression = SourceSuppressions("csharp").index(path, text)
        lines = text.splitlines()
        for finding in HeaderFlow(path, text).analyze():
            line = finding["line"]
            if not suppression.is_suppressed(line, RULE_ID):
                trace = " -> ".join(step["label"] for step in finding["extras"]["taint_path"])
                yield relpath(path, base), line, finding["col"], f"{source_line(lines, line)}  [{trace}]"
