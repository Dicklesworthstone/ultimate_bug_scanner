"""Bounded Java/Kotlin source-to-destination flow for outbound HTTP calls.

The JVM CFG follows helpers, branches and reassignments. Scheme and exact-host
checks must guard the same real URI/URL. JDK builders separate destinations from
headers/body. Unsupported syntax, escapes and budgets remain incomplete.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.java_detectors._common import iter_java_files, source_line
from ubs_core.analyzers.taint_java_redirect import RedirectEngine
from ubs_core.analyzers.taint_java_traversal import Engine
from ubs_core.taint_flow import CLEAN, Trace, advance, join, retag

RULE_ID = "java.security.ssrf-outbound-url"
CATEGORY = 4
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = (
    "Validate outbound URLs with explicit scheme and host allow-lists before "
    "building or sending client requests"
)

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getServerName|getServerPort|getRemoteHost|getRemoteAddr|'
    r'getLocalName|getLocalAddr|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:path|uri|local|host|port|origin|queryParameters|headers|header)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bHttpRequest\.newBuilder\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*\.(?:send|sendAsync|newCall|getForObject|getForEntity|postForObject|'
    r'postForEntity|exchange|execute)\s*\('
    r'|\b(?:client|httpClient|ktorClient|webClient|restClient|okHttpClient|'
    r'[A-Za-z_][A-Za-z0-9_]*(?:Client|Http|Rest|Web|Ktor)[A-Za-z0-9_]*)\.'
    r'(?:get|post|put|patch|delete|head|request|prepareGet|preparePost)\s*\('
    r'|\b(?:Jsoup\.connect|Unirest\.(?:get|post|put|delete|patch|head)|Request\.(?:Get|Post|Put|Delete))\s*\('
    r'|\.\s*(?:openConnection|openStream|uri|url|build)\s*\(',
)

KINDS = frozenset({'ssrf-uri', 'ssrf-url', 'ssrf-builder', 'ssrf-request', 'ssrf-text'})
PROOFS = frozenset({'ssrf-scheme', 'ssrf-host'})
BUILDER_METADATA = frozenset({'header', 'headers', 'setHeader', 'GET', 'DELETE', 'POST', 'PUT',
                              'method', 'timeout', 'expectContinue', 'version'})


class SSRFEngine(RedirectEngine):
    """URI identities and a finite, intraprocedural JDK builder store."""

    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label = 'outbound HTTP destination'

    def __init__(self, path, text):
        super().__init__(path, text)
        if self.parser.kotlin:
            # Bind Kotlin annotations to the parsed function's parameters.
            for function in self.parser.functions.values():
                if function.key < 0:
                    continue
                opening = self.code.find('(', function.key)
                spans = self.parser.parts(opening + 1, self.parser.pairs[opening], generics=True)
                function.sources |= frozenset(name for name, (low, high) in zip(function.parameters, spans)
                                               if ANNOTATED_PARAM_RE.search(self.code[low:high]))
        self.active_state = None
        self.non_http = frozenset()
        if path.suffix.lower() == '.java' and re.search(r'\.\s*execute\s*\(', self.code):
            from ubs_core.analyzers.taint_java_sql import non_http_execute_sites
            self.non_http = non_http_execute_sites(text)

    @staticmethod
    def data(value):
        return frozenset(trace for trace in value if trace.kind != 'shape')

    @staticmethod
    def is_kind(value, kind):
        return bool(value) and all('ssrf-' + kind in trace.tags for trace in value)

    def safe(self, trace):
        return trace.kind == 'shape' or bool(trace.tags & KINDS) and PROOFS <= trace.tags

    def summary_effect(self, summary, fact):
        return frozenset(trace for trace in fact if not self.safe(trace))

    def without_proof(self, value):
        # Also invalidate proofs supplied later by summary substitution.
        remove = KINDS | PROOFS | frozenset(tag for trace in value for tag in trace.tags
                                          if tag.startswith(('uri:', 'uri-call:', 'obj:', 'obj-call:')))
        return retag(value, remove=remove)

    def unknown(self, value, offset):
        return join(self.without_proof(self.data(value)),
                    frozenset({Trace('shape', ('unknown', offset))}))

    def typed(self, value, kind, offset, *, preserve=False, identity=None):
        data = self.data(value)
        remove = KINDS | frozenset({'jvm-string'})
        if not preserve:
            remove |= PROOFS | frozenset(tag for trace in data for tag in trace.tags
                                        if tag.startswith(('uri:', 'uri-call:')))
        remove |= frozenset(tag for trace in data for tag in trace.tags if tag.startswith(('obj:', 'obj-call:')))
        tags = frozenset({'ssrf-' + kind})
        if kind in {'uri', 'url'} and not preserve:
            tags |= frozenset({'uri:' + str(offset)})
        if kind in {'builder', 'request'}:
            tags |= identity or frozenset({'obj:' + kind + ':' + str(offset)})
        shape = Trace('shape', ('object', kind, offset), tags=tags)
        return join(retag(data, add=tags, remove=remove), frozenset({shape}))

    def parameter_tags(self, declaration):
        tags = Engine.parameter_tags(self, declaration)
        declaration = declaration.split('=', 1)[0].strip()
        pattern = (r'[A-Za-z_]\w*\s*:\s*([\w.]+)\s*\??' if self.parser.kotlin else
                   r'(?:final\s+)?([\w.]+)\s+[A-Za-z_]\w*')
        match = re.fullmatch(pattern, declaration)
        if not match:
            return tags
        actual = match.group(1)
        types = {'URI': 'uri', 'java.net.URI': 'uri', 'URL': 'url', 'java.net.URL': 'url',
                 'HttpRequest': 'request', 'java.net.http.HttpRequest': 'request',
                 'HttpRequest.Builder': 'builder', 'java.net.http.HttpRequest.Builder': 'builder'}
        kind = types.get(actual)
        if kind and (actual.startswith('java.') or self.builtin_type(actual.split('.')[0])):
            return frozenset({'ssrf-' + kind})
        return tags

    def summary_return(self, fact, offset):
        result = super().summary_return(fact, offset)
        return join(*(retag(frozenset({trace}), add=frozenset({'obj-call:' + str(offset)}))
                      if any(tag.startswith('obj:') for tag in trace.tags) else frozenset({trace}) for trace in result))

    def factory(self, name, short, qualified, bindings):
        return ((name == qualified and not self.call_is_shadowed('java', bindings)) or
                (name == short and self.builtin_type(short.split('.')[0]) and
                 not self.call_is_shadowed(short.split('.')[0], bindings)))

    @staticmethod
    def object_identity(trace):
        return frozenset(tag for tag in trace.tags if tag.startswith(('obj:', 'obj-call:')))

    def mutate_builder(self, receiver, destination, offset, receiver_binding=None):
        identities = {self.object_identity(trace) for trace in receiver}
        if not all(identities):
            # Parameter/field mutations need a caller-visible heap summary.
            self.escapes[offset] = join(self.escapes.get(offset, CLEAN), self.data(join(receiver, destination)))
            return self.typed(destination, 'builder', offset, preserve=True)
        changed = join(*(self.typed(destination, 'builder', offset, preserve=True, identity=identity)
                         for identity in identities))
        if self.active_state:
            state, _ = self.active_state
            for binding, fact in list(state.items()):
                touched = frozenset(trace for trace in fact if self.object_identity(trace) in identities)
                if not touched:
                    continue
                # The named receiver is definitely updated. Other joined
                # aliases may refer to a different object at runtime.
                definite = binding == receiver_binding or len(identities) == 1 and touched == fact
                state[binding] = changed if definite else join(fact, changed)
        return changed

    def operation(self, method, arguments, receiver, value, offset, receiver_binding=None):
        arguments = arguments or []
        if self.is_kind(receiver, 'builder'):
            if method in BUILDER_METADATA:
                return receiver
            if method == 'uri' and len(arguments) == 1:
                return self.mutate_builder(receiver, arguments[0], offset, receiver_binding)
            if method == 'copy' and not arguments:
                return self.typed(receiver, 'builder', offset, preserve=True)
            if method == 'build' and not arguments:
                self.record(offset, receiver)
                return self.typed(receiver, 'request', offset, preserve=True)
            self.escapes[offset] = join(self.escapes.get(offset, CLEAN), self.data(value))
        if self.is_kind(receiver, 'request') and method == 'uri' and not arguments:
            return self.typed(receiver, 'uri', offset, preserve=True)
        uri = self.is_kind(receiver, 'uri')
        url = self.is_kind(receiver, 'url')
        if uri or url:
            if method == 'toString' and not arguments:
                return retag(receiver, add=frozenset({'ssrf-text', 'jvm-string'}), remove=KINDS)
            if method == 'normalize' and uri and not arguments:
                return receiver
            if method in {'toURI', 'toURL'} and not arguments:
                return self.typed(receiver, 'uri' if method == 'toURI' else 'url', offset, preserve=True)
            if method == 'resolve' and uri and len(arguments) == 1:
                # An absolute argument can replace both scheme and authority.
                return self.typed(join(receiver, arguments[0]), 'uri', offset)
            if method in {'getHost', 'getScheme', 'getProtocol', 'host', 'scheme', 'protocol',
                          'getPath', 'getRawPath', 'getQuery', 'getRawQuery', 'getAuthority', 'getUserInfo'}:
                return retag(self.without_proof(self.data(receiver)), add=frozenset({'jvm-string'}))
        if method in {'openConnection', 'openStream'}:
            self.record(offset, receiver)
        if method in {'uri', 'url'} and arguments:
            self.record(offset, arguments[0])
        if method == 'toString' and not arguments and receiver and all('jvm-string' in t.tags for t in receiver):
            return receiver
        return self.unknown(value, offset)

    def external_call(self, name, arguments, value, offset, bindings, state):
        if self.source_re.search(name + '('):
            return retag(self.without_proof(self.data(value)), add=frozenset({'jvm-string'}))
        for short, qualified, kind in (('URI.create', 'java.net.URI.create', 'uri'),
                                        ('URI', 'java.net.URI', 'uri'), ('URL', 'java.net.URL', 'url')):
            if self.factory(name, short, qualified, bindings):
                if len(arguments) == 1:
                    preserve = self.is_kind(arguments[0], 'text')
                    return self.typed(arguments[0], kind, offset, preserve=preserve)
                if kind == 'uri':
                    # Component constructors quote query/fragment delimiters.
                    indexes = {7: (0, 2, 3), 5: (0, 1), 4: (0, 1), 3: (0, 1)}.get(len(arguments))
                    if indexes is not None:
                        if len(arguments) in {4, 5, 7}:
                            opening = self.code.find('(', offset)
                            spans = list(self.parser.parts(opening + 1, self.parser.pairs[opening]))
                            host_index, path_index = (2, 4) if len(arguments) == 7 else (1, 2)
                            authority = self.text[slice(*spans[host_index])].strip()
                            if not re.fullmatch(r'"[^"$\r\n]+"', authority):
                                # A path's // can supply missing authority.
                                indexes += (path_index,)
                        return self.typed(join(*(arguments[index] for index in indexes)), kind, offset)
                if kind == 'url' and len(arguments) in {2, 3, 4, 5}:
                    if len(arguments) == 2 or self.is_kind(arguments[0], 'url'):
                        # A context URL does not constrain an absolute spec.
                        return self.typed(join(*arguments[:2]), kind, offset)
                    return self.typed(join(*arguments[:3 if len(arguments) >= 4 else 2]), kind, offset)
                raise ValueError('Unsupported URI/URL constructor; outbound destination analysis is incomplete')
        if self.factory(name, 'HttpRequest.newBuilder', 'java.net.http.HttpRequest.newBuilder', bindings):
            destination = arguments[0] if arguments else CLEAN
            return self.typed(destination, 'builder', offset, preserve=True)
        root, _, method = name.rpartition('.')
        receiver = state.get(bindings.get(root, root), CLEAN)
        if any(self.is_kind(argument, 'builder') for argument in arguments):
            self.escapes[offset] = join(self.escapes.get(offset, CLEAN), self.data(value))
        return self.operation(method, arguments, receiver, value, offset, bindings.get(root, root))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if direct_call:
            return value
        if not receiver and any(trace.kind == 'source' and trace.key[1] == offset for trace in value):
            return value  # Ktor property/index source, already recognized.
        if not receiver and self.active_state:
            # A first property (uri.host) keeps its receiver in value.
            receiver = value
        return self.operation(name, arguments, receiver, value, offset)

    def call_sink(self, name, call, value, offset, bindings):
        method = name.rsplit('.', 1)[-1]
        if method in {'build', 'uri', 'url', 'openConnection', 'openStream', 'newBuilder'}:
            return False  # Destination-specific receiver semantics above.
        if not self.sink_re.search(name + '(') or not call.values:
            return False
        if method == 'execute':
            opening = self.code.find('(', offset)
            dot = self.code.rfind('.', offset, opening)
            if dot in self.non_http:
                return False
        target = next((call.names.index(key) for key in ('url', 'urlString', 'uri') if key in call.names), 0)
        self.record(offset, call.values[target])
        template_start = {'getForObject': 2, 'getForEntity': 2, 'postForObject': 3, 'postForEntity': 3,
                          'exchange': 4}.get(method)
        if template_start is not None and any(self.data(fact) for fact in call.values[template_start:]):
            # Template expansion can supply authority; it is not a body.
            self.escapes[offset] = join(self.escapes.get(offset, CLEAN),
                                        self.data(join(*call.values[template_start:])))
        return False

    def expression(self, start, end, state, bindings, depth=0):
        previous = self.active_state
        self.active_state = state, bindings
        try:
            value = Engine.expression(self, start, end, state, bindings, depth)
        finally:
            self.active_state = previous
        if len(list(self.parser.parts(start, end, separator='+'))) > 1 or (
                self.parser.kotlin and re.search(r'\$(?:[A-Za-z_]|\{)', self.text[start:end])):
            value = self.without_proof(value)
        return value

    def guard_facts(self, span):
        # Reuse boolean/host-set checks, excluding relative-redirect proofs.
        mapped = {'uri-https': 'ssrf-scheme', 'uri-host': 'ssrf-host'}
        checks = [(truth, (name, mapped.get(tag, tag), 'getScheme()' if tag == 'uri-https' else member, allowlist))
                  for truth, (name, tag, member, allowlist) in super().guard_facts(span)
                  if tag in mapped or tag in PROOFS]
        raw = self.text[slice(*span)].strip()
        access = r'([A-Za-z_]\w*)\.(getHost\(\)|getScheme\(\)|getProtocol\(\)|host|scheme|protocol)'
        literal = r'"([A-Za-z0-9.-]+)"'
        match = re.fullmatch(literal + r'\s*\.equals\(\s*' + access + r'\s*\)', raw)
        truth = True
        if match:
            expected, name, member = match.groups()
        else:
            match = re.fullmatch(access + r'\s*\.equals\(\s*' + literal + r'\s*\)', raw)
            if match:
                name, member, expected = match.groups()
            elif self.parser.kotlin:
                match = re.fullmatch(access + r'\s*(==|!=)\s*' + literal, raw)
                if match:
                    name, member, operator, expected = match.groups()
                    truth = operator == '=='
        if match:
            host = member in {'getHost()', 'host'}
            if host or expected in {'http', 'https'}:
                checks.append((truth, (name, 'ssrf-host' if host else 'ssrf-scheme', member, None)))
        if self.parser.kotlin:
            membership = re.fullmatch(r'([A-Za-z_]\w*)\.host\s+(!in|in)\s+([A-Za-z_]\w*)', raw)
            if membership:
                name, operator, allowlist = membership.groups()
                if (self.function.owner, allowlist) in self.host_sets:
                    checks.append((operator == 'in', (name, 'ssrf-host', 'host', allowlist)))
        return checks

    def apply_guard(self, guard, state, bindings):
        name, tag, member, allowlist = guard
        if allowlist in bindings:
            return state
        original = state.get(bindings.get(name, name), CLEAN)
        uri, url = self.is_kind(original, 'uri'), self.is_kind(original, 'url')
        if not (uri or url) or (member in {'getProtocol()', 'protocol'} and not url) or (
                member in {'getScheme()', 'scheme'} and not uri):
            return state
        identities = {self.uri_identity(trace) for trace in original}
        for binding, fact in list(state.items()):
            state[binding] = join(*(retag(frozenset({trace}), add=frozenset({tag}))
                                   if self.uri_identity(trace) in identities else frozenset({trace}) for trace in fact))
        return state

    def transfer(self, action, state):
        result = Engine.transfer(self, action, state)
        assignment = self.assignment(action[1]) if action[0] == 'simple' else None
        if assignment and assignment[4] == '+=':
            binding = action[2].get(assignment[0], assignment[0])
            result[binding] = self.without_proof(result.get(binding, CLEAN))
        return result


def analyze(path: Path, issues, *, suppressions: SourceSuppressions, rule_id: str):
    text = path.read_text(encoding='utf-8')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and SINK_RE.search(text)):
        return
    suppression = suppressions.index(path, text)
    lines = text.splitlines()
    for line, fact in sorted(SSRFEngine(path, text).analyze().items()):
        if suppression.is_suppressed(line, rule_id):
            continue
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        path_desc = ' -> '.join(step.label for step in witness.evidence)
        issues.append((path, line, f"{source_line(lines, line)}  [{path_desc}]"))


def find(files: Sequence[Path], *, language: str = 'java', rule_id: str = RULE_ID) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions(language)
    issues: list[tuple[Path, int, str]] = []
    for path in iter_java_files(files):
        analyze(path, issues, suppressions=suppressions, rule_id=rule_id)
    for path, line_no, detail in issues:
        yield path, line_no, 1, detail
