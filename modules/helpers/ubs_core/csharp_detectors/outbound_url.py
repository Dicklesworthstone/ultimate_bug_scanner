"""Bounded C# outbound destinations with scoped request and client identities.

The shared CFG and helper summaries preserve assignments, branches, aliases,
and the selected argument passed to a real HTTP API. A reassuring helper name
does not establish safety. URI validation must reject an invalid absolute
HTTPS URI or unlisted host for the value subsequently sent. Mutable request
objects and unresolved HTTP dispatch remain explicit incomplete boundaries.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_csharp_redirect import RedirectFlow
from ubs_core.analyzers.taint_csharp_request import CSharpFlow, masked_source, parts, request_source_demand
from ubs_core.analyzers.taint_csharp_sql import (
    CONTEXT, CONTROLLERS, REQUEST, REQUEST_MEMBERS, TypeIndex, api_fact, identities, provenance,
)
from ubs_core.csharp_detectors._common import relpath, source_line
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit, CLEAN, advance, join

RULE_ID = "csharp.security.outbound-url"
CATEGORY = 8
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = "Validate with Uri parsing plus explicit https scheme and host allow-list checks"
FILE_SCOPED = True

HTTP_CLIENT = 'System.Net.Http.HttpClient'
HTTP_MESSAGE = 'System.Net.Http.HttpRequestMessage'
WEB_CLIENT = 'System.Net.WebClient'
WEB_REQUESTS = frozenset({'System.Net.WebRequest', 'System.Net.HttpWebRequest'})
URI = 'System.Uri'
HTTP_TYPES = WEB_REQUESTS | frozenset({HTTP_CLIENT, HTTP_MESSAGE, WEB_CLIENT, URI,
    'System.UriKind', 'System.Net.Http.HttpMessageInvoker', 'System.StringComparer',
    'System.Collections.Generic.HashSet'})
CONTEXT_OWNERS = frozenset({
    'Microsoft.AspNetCore.Http.IHttpContextAccessor', 'Microsoft.AspNetCore.Http.HttpContextAccessor',
    'Microsoft.AspNetCore.Mvc.ControllerContext', 'Microsoft.AspNetCore.Mvc.ActionContext',
})
ATTRIBUTES = frozenset('Microsoft.AspNetCore.Mvc.' + name + 'Attribute' for name in (
    'FromQuery', 'FromHeader', 'FromRoute', 'FromForm', 'FromBody'))
REQUEST_TYPES = CONTEXT_OWNERS | CONTROLLERS | frozenset({
    REQUEST, CONTEXT, 'Microsoft.AspNetCore.Http.DefaultHttpContext',
})
HTTP_METHODS = frozenset({'GetAsync', 'GetStringAsync', 'GetByteArrayAsync', 'GetStreamAsync',
    'PostAsync', 'PutAsync', 'PatchAsync', 'DeleteAsync', 'Send', 'SendAsync'})
WEB_METHODS = frozenset({'DownloadString', 'DownloadStringTaskAsync', 'DownloadData',
    'DownloadDataTaskAsync', 'OpenRead', 'OpenReadTaskAsync', 'UploadString',
    'UploadStringTaskAsync', 'UploadData', 'UploadDataTaskAsync', 'UploadValues', 'UploadFile'})
SINK_RE = re.compile(r'\b(?:' + '|'.join(sorted(HTTP_METHODS | WEB_METHODS))
                     + r'|HttpRequestMessage|CreateHttp|Create|Execute|Get|Post|Put|Patch|Delete)\s*\(')


class OutboundFlow(RedirectFlow):
    rule = RULE_ID
    message = TITLE

    def __init__(self, path, text):
        super().__init__(path, text)
        self.types = TypeIndex(self, HTTP_TYPES | REQUEST_TYPES | ATTRIBUTES)
        self.ancestry = {}
        self.annotated = set()
        self.boundaries = {}
        self.context_issues = {}
        self.current_issues = set()
        for key, function in self.parser.functions.items():
            if key < 0:
                continue
            opening = self.code.find('(', key, function.start)
            if opening not in self.parser.pairs:
                continue
            for index, (low, high) in enumerate(parts(
                    self.code, opening + 1, self.parser.pairs[opening], generics=True)):
                position = low
                while position < high:
                    if self.code[position] != '[':
                        position += 1
                        continue
                    closing = self.parser.pairs[position]
                    for first, last in parts(self.code, position + 1, closing, generics=True):
                        attribute = re.match(r'\s*(?:param\s*:\s*)?([\w@.:]+)', self.code[first:last])
                        if attribute is None:
                            continue
                        spelling = attribute.group(1)
                        identity = self.types.resolve(spelling, first)
                        if identity.startswith('unknown:'):
                            identity = self.types.resolve(spelling + 'Attribute', first)
                        if identity in ATTRIBUTES:
                            self.annotated.add((key, index))
                    position = closing + 1
        self.fields = {}
        for match in re.finditer(r'\b([\w.:]+)\s+(@?\w+)\s*(?=[=;{])', self.code):
            if any(key >= 0 and function.declaration <= match.start() < function.end
                   for key, function in self.parser.functions.items()):
                continue
            identity = self.types.resolve(match.group(1), match.start())
            self.fields[(self.types.owner(match.start()), match.group(2).lstrip('@'))] = identity

    def type_identities(self, identity, visiting=()):
        """Resolve bounded local base chains without trusting a class name."""
        if identity in self.ancestry:
            return self.ancestry[identity]
        if identity in visiting or len(visiting) >= 12:
            raise AnalysisLimit('C# outbound type inheritance is incomplete')
        self.budget.spend()
        found = {identity} if identity else set()
        scope = self.types.local_types.get(identity.removeprefix('local:')) if identity.startswith('local:') else None
        if scope is not None and ':' in scope.bases:
            for base in scope.bases.split(':', 1)[1].split(','):
                spelling = base.split('(', 1)[0].strip()
                found.update(self.type_identities(self.types.resolve(spelling, scope.start), (*visiting, identity)))
        self.ancestry[identity] = frozenset(found)
        return self.ancestry[identity]

    def type_fact(self, identity):
        return join(*(api_fact(value) for value in self.type_identities(identity)))

    def incomplete(self, position, reason, value=None):
        if value is None:
            self.current_issues.add(f'line {self.step(position, "boundary", reason).line}: {reason}')
            return
        # An abstract parameter is not itself request data. Carry the boundary
        # through ordinary helper summaries and instantiate it at callers.
        key = (position, '<outbound-boundary> ' + reason)
        self.boundaries[key] = reason
        fact = advance(provenance(value), self.step(position, 'boundary', reason))
        self.effects[key] = join(self.effects.get(key, CLEAN), fact)

    def concrete_effect(self, key, fact):
        concrete = super().concrete_effect(key, fact)
        if key in self.boundaries:
            if concrete:
                self.incomplete(key[0], self.boundaries[key])
            return CLEAN
        return concrete

    def is_source(self, name):
        return False

    def parameter_fact(self, function, index):
        value = CSharpFlow.parameter_fact(self, function, index)
        if (function.key, index) in self.annotated:
            value = join(value, self.source_fact(function.key, 'request-bound ' + function.parameters[index]))
        identity = self.types.resolve(function.parameter_types[index], function.key)
        return join(value, self.type_fact(identity))

    def name_value(self, name, position, state, bindings):
        pieces = name.split('.')
        if pieces[0] == 'this' and len(pieces) > 1:
            pieces = pieces[1:]
        root, members = pieces[0], pieces[1:]
        value = state.get(bindings.get(root, ''), CLEAN)
        if root not in bindings:
            value = self.type_fact(self.fields.get((self.function.owner, root), ''))
            if self.type_identities('local:' + '.'.join(self.function.owner)) & CONTROLLERS:
                if root == 'Request':
                    value = api_fact(REQUEST)
                elif root == 'HttpContext':
                    value = api_fact(CONTEXT)
                elif root == 'ControllerContext':
                    value = api_fact('Microsoft.AspNetCore.Mvc.ControllerContext')
        for member in members:
            current = identities(value)
            if current & CONTEXT_OWNERS and member == 'HttpContext':
                value = api_fact(CONTEXT)
            elif current & {CONTEXT, 'Microsoft.AspNetCore.Http.DefaultHttpContext'} and member == 'Request':
                value = api_fact(REQUEST)
            elif REQUEST in current and member in REQUEST_MEMBERS | {'Host', 'RawTarget'}:
                value = self.source_fact(position, name)
            else:
                value = provenance(value)
        return value

    def call_candidates(self, name, args, values, state, bindings, position):
        pieces = name.split('.')
        if len(pieces) == 1 or pieces[0] == 'this':
            return CSharpFlow.call_candidates(self, name, args, values, state, bindings, position)
        owners = identities(self.name_value('.'.join(pieces[:-1]), position, state, bindings))
        if pieces[0] not in bindings:
            owners |= {self.types.resolve('.'.join(pieces[:-1]), position)}
        local = {owner[len('local:'):] for owner in owners if owner.startswith('local:')}
        return [function for function in self.parser.functions.values()
                if function.parent is None and function.name == pieces[-1]
                and '.'.join(function.owner) in local
                and len(function.parameters) - function.defaults <= len(args) <= len(function.parameters)]

    def api_reference(self, spelling, position, bindings, expected):
        """A static expression needs a type binding, not a same-named value."""
        if self.types.resolve(spelling, position) != expected:
            return False
        root = spelling.split('.')[0]
        if root in bindings:
            return False
        owners = self.type_identities('local:' + '.'.join(self.function.owner))
        return not any(name == root and 'local:' + '.'.join(owner) in owners
                       for owner, name in self.fields)

    def path_guard(self, span, bindings=None):
        bindings = bindings or {}
        start, end = self.strip_parentheses(*span)
        guard = self.uri_guard(start, end, bindings)
        if not guard:
            return None
        parse = re.search(r'((?:System\.)?Uri)\.TryCreate\s*\(\s*(@?\w+)\s*,\s*((?:System\.)?UriKind)\.Absolute',
                          self.code[start:end])
        scheme = re.search(r'\.Scheme\s*!=\s*((?:System\.)?Uri)\.UriSchemeHttps', self.code[start:end])
        if (not parse or not scheme or not self.api_reference(parse.group(1), start, bindings, URI)
                or not self.api_reference(parse.group(3), start, bindings, 'System.UriKind')
                or not self.api_reference(scheme.group(1), start, bindings, URI)):
            return None
        return guard[0], parse.group(2).lstrip('@'), guard[2]

    def constant_hosts(self, name, bindings):
        if not super().constant_hosts(name, bindings):
            return False
        declaration = re.search(
            r'\bprivate\s+static\s+readonly\s+((?:System\.Collections\.Generic\.)?HashSet)'
            + r'\s*<\s*string\s*>\s+' + re.escape(name) + r'\s*=\s*new\s*'
            + r'(?:((?:System\.Collections\.Generic\.)?HashSet)\s*<\s*string\s*>)?'
            + r'\s*\(\s*(StringComparer\.OrdinalIgnoreCase\s*)?\)', self.code)
        if declaration is None:
            return False
        for spelling in declaration.group(1, 2):
            if spelling and self.types.resolve(spelling, declaration.start()) != 'System.Collections.Generic.HashSet':
                return False
        return not declaration.group(3) or self.api_reference(
            'StringComparer', declaration.start(), {}, 'System.StringComparer')

    def apply_guard(self, action, state):
        # The raw string and parsed URI describe the same absolute destination;
        # neither proof survives a subsequent write to the respective binding.
        for variable in action.guard:
            cell = action.bindings.get(variable)
            if cell:
                state[cell] = frozenset(trace for trace in state.get(cell, CLEAN) if trace.kind == 'api')
        return state

    def selected_arguments(self, call):
        owner, _, method = call.name.rpartition('.')
        receiver = self.name_value(owner, call.position, call.state, call.bindings) if owner else CLEAN
        receiver_types = identities(receiver)
        constructor = bool(re.search(r'\bnew\s*$', self.code[max(0, call.position - 12):call.position]))
        identity = self.types.resolve(call.name if constructor else owner, call.position)
        root = (call.name if constructor else owner).split('.')[0]
        static = root not in call.bindings
        if constructor and identity == HTTP_MESSAGE:
            slot, keyword = 1, 'requestUri'
        elif receiver_types & {HTTP_CLIENT, 'System.Net.Http.HttpMessageInvoker'} and method in HTTP_METHODS:
            slot, keyword = 0, 'request' if method in {'Send', 'SendAsync'} else 'requestUri'
        elif WEB_CLIENT in receiver_types and method in WEB_METHODS:
            slot, keyword = 0, 'address'
        elif static and identity in WEB_REQUESTS and method in {'Create', 'CreateHttp'}:
            slot, keyword = 0, 'requestUri'
        else:
            if method in HTTP_METHODS | WEB_METHODS:
                self.incomplete(call.position, 'Outbound HTTP receiver is unresolved', join(*call.values))
            return []
        return [index for index, (name, _, _) in enumerate(call.args)
                if (name is None and index == slot) or name == keyword
                or (identity in WEB_REQUESTS and name == 'address')]

    def call_value(self, call):
        name, values = call.name, call.values
        owner, _, method = name.rpartition('.')
        source = self.name_value(owner, call.position, call.state, call.bindings) if owner else CLEAN
        constructor = bool(re.search(r'\bnew\s*$', self.code[max(0, call.position - 12):call.position]))
        if constructor:
            identity = self.types.resolve(name, call.position)
            if identity == HTTP_MESSAGE:
                return join(api_fact(identity), *(provenance(values[i]) for i in self.selected_arguments(call)))
            return join(self.type_fact(identity), provenance(join(*values)) if identity not in {HTTP_CLIENT, WEB_CLIENT} else CLEAN)
        if method == 'TryGetValue' and provenance(source):
            for _, low, high in call.args:
                output = re.fullmatch(r'\s*out\s+(?:(?:var|[\w.?<>\[\]]+)\s+)?(@?\w+)\s*', self.code[low:high])
                cell = call.bindings.get(output.group(1).lstrip('@')) if output else None
                if cell:
                    call.state[cell] = provenance(source)
            return CLEAN
        if (method == 'TryCreate' and self.types.resolve(owner, call.position) == URI
                and owner.split('.')[0] not in call.bindings and len(call.args) == 3):
            _, low, high = call.args[2]
            output = re.fullmatch(r'\s*out\s+(?:(?:var|[\w.?]+)\s+)?(@?\w+)\s*', self.code[low:high])
            cell = call.bindings.get(output.group(1).lstrip('@')) if output else None
            if cell:
                call.state[cell] = join(api_fact(URI), provenance(values[0]))
            return CLEAN
        if self.selected_arguments(call):
            return CLEAN
        if method in {'ContainsKey', 'Contains', 'StartsWith', 'Equals'}:
            return CLEAN
        if any(re.match(r'\s*(?:ref|out)\b', self.code[low:high]) for _, low, high in call.args):
            self.incomplete(call.position, 'Unresolved ref/out HTTP value effects', join(source, *values))
        return provenance(join(source, call.receiver, *values))

    def call_sink_facts(self, call):
        return [(index, provenance(call.values[index])) for index in self.selected_arguments(call)]

    def evaluate(self, start, end, state, bindings, depth=0):
        low, high = self.strip_parentheses(start, end)
        creation = re.match(r'new\s+([\w.:]+)\s*', self.code[low:high])
        if creation and self.types.resolve(creation.group(1), low) == HTTP_MESSAGE:
            following = low + creation.end()
            if self.code[following:following + 1] == '(':
                constructor_end = self.parser.pairs[following] + 1
                following = self.parser.skip(constructor_end, high)
            else:
                constructor_end = following
            if self.code[following:following + 1] == '{' and self.parser.pairs[following] == high - 1:
                value = CSharpFlow.evaluate(self, low, constructor_end, state, bindings, depth)
                value = join(value, api_fact(HTTP_MESSAGE))
                for first, last in parts(self.code, following + 1, high - 1):
                    setter = re.match(r'\s*(@?\w+)\s*=(?!=|>)\s*', self.code[first:last])
                    rhs = first + setter.end() if setter else first
                    assigned = self.evaluate(rhs, last, state, bindings, depth + 1)
                    member = setter.group(1).lstrip('@') if setter else ''
                    if member == 'RequestUri':
                        value = join(api_fact(HTTP_MESSAGE), provenance(assigned))
                        key = (first + setter.start(1), 'HttpRequestMessage.RequestUri')
                        self.effects[key] = join(self.effects.get(key, CLEAN),
                                                 advance(provenance(assigned), self.step(key[0], 'sink', key[1])))
                    elif member not in {'Content', 'Method', 'Version', 'VersionPolicy', 'Headers'}:
                        self.incomplete(first, 'Outbound request initializer is unresolved', assigned)
                # Content and metadata may contain request data without
                # changing this fresh message's independently chosen URI.
                return value
        return CSharpFlow.evaluate(self, start, end, state, bindings, depth)

    def transfer(self, action, state):
        start, end = action.span
        code = self.code[start:end]
        member = re.match(r'\s*((?:\w+\.)*\w+)\.(\w+)\s*=(?!=|>)', code)
        if action.kind in {'simple', 'eval'} and member:
            value = self.evaluate(start + member.end(), end, state, action.bindings)
            receiver = self.name_value(member.group(1), start + member.start(1), state, action.bindings)
            target = identities(receiver)
            if (member.group(2) == 'RequestUri' and HTTP_MESSAGE in target
                    or member.group(2) == 'BaseAddress' and HTTP_CLIENT in target):
                self.incomplete(start, 'Mutable outbound request or object-field effects require heap analysis')
            else:
                self.incomplete(start, 'Mutable outbound request or object-field effects require heap analysis', value)
            return state
        result = CSharpFlow.transfer(self, action, state)
        if action.kind in {'simple', 'eval'}:
            declaration = re.match(r'\s*(?:(?:using|await)\s+)*([\w.:]+)\s+(@?\w+)\s*(?:=|$)', code)
            if declaration:
                identity = self.types.resolve(declaration.group(1), start)
                cell = action.bindings.get(declaration.group(2).lstrip('@'))
                if cell and (identity in HTTP_TYPES | REQUEST_TYPES or identity.startswith('local:')):
                    result[cell] = join(result.get(cell, CLEAN), self.type_fact(identity))
        return result

    def analyze_function(self, function, context):
        self.current_issues = set()
        try:
            return super().analyze_function(function, context)
        finally:
            self.context_issues[context] = self.current_issues

    def analyze(self):
        yield from super().analyze()
        issues = sorted(set().union(self.current_issues, *self.context_issues.values()))
        if issues:
            raise AnalysisLimit('C# outbound URL analysis is incomplete: ' + '; '.join(issues[:12]))


def find(files: Sequence[Path], base_dir: Path | None = None) -> Iterable[tuple[Path, int, int, str]]:
    base = base_dir if base_dir is not None else Path.cwd()
    for path in files:
        if path.suffix.lower() not in {'.cs', '.csx'}:
            continue
        text = path.read_text(encoding='utf-8-sig')
        if (not SINK_RE.search(text)
                or not request_source_demand(text, REQUEST_MEMBERS | {'Host', 'RawTarget'}, ATTRIBUTES)):
            continue
        code = masked_source(text)
        if (not SINK_RE.search(code)
                or not request_source_demand(code, REQUEST_MEMBERS | {'Host', 'RawTarget'}, ATTRIBUTES)):
            continue
        suppression = SourceSuppressions('csharp').index(path, text)
        lines = text.splitlines()
        for finding in OutboundFlow(path, text).analyze():
            line = finding['line']
            if not suppression.is_suppressed(line, RULE_ID):
                trace = ' -> '.join(step['label'] for step in finding['extras']['taint_path'])
                yield (relpath(path, base), line, finding['col'], f'{source_line(lines, line)}  [{trace}]')
