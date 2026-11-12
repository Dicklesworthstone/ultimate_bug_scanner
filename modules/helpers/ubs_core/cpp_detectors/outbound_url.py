"""C/C++ outbound URLs using selected values and sink-specific host proof.

The shared C/C++ worklist resolves local helpers, assignment kills, reference
effects and branches. A helper's spelling never proves validation. The
frontend has the same bounded lexical scope as path and redirect analysis.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_cpp_redirect import RedirectEngine
from ubs_core.analyzers.taint_cpp_traversal import Engine
from ubs_core.taint_flow import AnalysisLimit, CLEAN

RULE_ID = "cpp.detector.outbound-url"
CATEGORY = 7
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = ("Validate outbound URLs with explicit scheme and host "
               "allow-lists before configuring or sending client requests")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|getHost|get_host|host|'
    r'target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:host|target|raw_url|url)\b'
    r'|\b(?:cgiFormString|FCGX_GetParam)\s*\('
    r'|\b(?:std\s*::\s*)?getenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:curl_easy_setopt|curl_url_set)\s*\('
    r'|\b(?:cpr::(?:Get|Post|Put|Delete|Patch|Head|Options)|QNetworkRequest)\s*\('
    r'|\b(?:httplib::Client|httplib::SSLClient|Poco::Net::HTTPClientSession)\s*\('
    r'|\b(?:client|httpClient|http_client|restClient|rest_client|webClient|web_client|session|request|manager|'
    r'[A-Za-z_][A-Za-z0-9_]*(?:Client|Http|HTTP|Rest|Web|Session|Request|Curl)[A-Za-z0-9_]*)(?:\.|->)'
    r'(?:Get|Post|Put|Patch|Delete|Head|get|post|put|patch|delete|head|request|send|setUrl|openUrl)\s*\(',
)


class OutboundEngine(RedirectEngine):
    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label = 'outbound HTTP'
    rule = RULE_ID

    def __init__(self, path, text):
        super().__init__(path, text)
        self.outbound_bindings = {}
        self.namespace_options = []
        self.local_options = []
        self.collect_namespace_options(0, len(self.parser.tokens), ())
        for function in self.parser.functions.values():
            self.collect_local_options(function.body, function.end)

    def option_declaration(self, start, end):
        assignment = self.parser.assignment(start, end)
        if assignment and assignment[-1]:
            name, offset = assignment[:2]
        else:
            # Parenthesized/braced initialization and declarations without an
            # initializer do not enter the shared assignment-only scope map.
            opening = self.parser.reverse.get(end - 1)
            offset = opening - 1 if opening is not None else end - 1
            if offset <= start or self.parser.value(offset - 1) == '::':
                return None
            if any(not (re.fullmatch(r'[A-Za-z_]\w*', token.value)
                        or token.value in {'::', '*', '&', '&&', '<', '>'})
                   for token in self.parser.tokens[start:offset]):
                return None
            name = self.parser.value(offset)
        if re.fullmatch(r'CURLOPT_[A-Z0-9_]+|CURLUPART_[A-Z0-9_]+', name):
            return name, offset
        return None

    def collect_namespace_options(self, start, end, owner):
        # The shared scalar graph deliberately omits namespace/class storage.
        # Such declarations still shadow API enum spellings during lookup;
        # record their lexical owners without pretending to resolve values.
        while start < end:
            cursor = start
            while cursor < end and self.parser.value(cursor) not in {';', '{'}:
                if self.parser.value(cursor) in {'(', '['}:
                    cursor = self.parser.pairs[cursor]
                cursor += 1
            if cursor >= end:
                break
            if self.parser.value(cursor) == ';':
                declaration = self.option_declaration(start, cursor)
                if owner and declaration:
                    self.namespace_options.append((*declaration, owner))
                start = cursor + 1
                continue
            close = self.parser.pairs[cursor]
            word = self.parser.value(start)
            if word in {'namespace', 'class', 'struct', 'union'}:
                name = self.parser.value(start + 1) if start + 1 < cursor else '<anonymous>'
                self.collect_namespace_options(cursor + 1, close, (*owner, name))
            elif owner and word == 'enum' and self.parser.value(start + 1) not in {'class', 'struct'}:
                for low, _high in self.parser.parts(cursor + 1, close):
                    self.namespace_options.append((self.parser.value(low), low, owner))
            elif owner:
                declaration = self.option_declaration(start, close + 1)
                if declaration:
                    self.namespace_options.append((*declaration, owner))
            start = close + 1

    def collect_local_options(self, statements, scope_end):
        # Unscoped enumerators enter the surrounding lexical block. They do
        # not appear as scalar assignments in the shared worklist bindings.
        for statement in statements:
            if (self.parser.value(statement.start) == 'enum'
                    and self.parser.value(statement.start + 1) not in {'class', 'struct'}):
                opening = next((index for index in range(statement.start, statement.end)
                                if self.parser.value(index) == '{'), None)
                if opening is not None:
                    for low, _high in self.parser.parts(opening + 1, self.parser.pairs[opening]):
                        self.local_options.append((self.parser.value(low), low, scope_end))
            elif statement.kind == 'simple':
                declaration = self.option_declaration(statement.start, statement.end)
                if declaration:
                    self.local_options.append((*declaration, scope_end))
            for body in (statement.body, statement.otherwise):
                if body:
                    self.collect_local_options(body, max(child.end for child in body))

    def option_bound(self, name, offset):
        return (name in self.outbound_bindings
                or any(name == declared and start < offset < end
                       for declared, start, end in self.local_options)
                or any(name == declared and start < offset
                       and self.function.owner[:len(owner)] == owner
                       for declared, start, owner in self.namespace_options))

    def expression(self, start, end, state, bindings, depth=0):
        # Sink calls can occur in conditions, initializers, nested arguments,
        # and summaries. Keep the current expression's lexical environment,
        # restoring it after recursion instead of leaking a transfer's scope.
        previous = self.outbound_bindings
        self.outbound_bindings = bindings
        try:
            return super().expression(start, end, state, bindings, depth)
        finally:
            self.outbound_bindings = previous

    def safe(self, trace):
        # These tags describe the exact selected value, not a nearby check or
        # a helper name. Local redirect and filesystem proofs do not apply.
        return {'url-https', 'url-host'} <= trace.tags

    def transfer(self, action, state):
        # RedirectEngine also owns Location-header assignments. Reuse the
        # scalar transfer without importing that different sink policy.
        return Engine.transfer(self, action, state)

    def record(self, offset, value, file_leaf=False):
        # The shared scalar transfer recognizes C++ file-stream constructors.
        # Their filesystem operand is owned by the traversal analyzer.
        if not file_leaf:
            super().record(offset, value)

    def call_sink(self, name, spans, arguments, offset, receiver=CLEAN):
        targets = []
        if name in {'curl_easy_setopt', 'curl_url_set'}:
            option = 'CURLOPT_URL' if name == 'curl_easy_setopt' else 'CURLUPART_URL'
            if len(spans) >= 3:
                low, high = spans[1]
                while self.parser.value(low) == '(' and self.parser.pairs.get(low) == high - 1:
                    low, high = low + 1, high - 1
                selected = self.parser.compact(low, high)
                request_value = any(trace.kind in {'source', 'parameter'} for trace in arguments[2])
                if self.option_bound(selected, low) and request_value:
                    raise AnalysisLimit('C/C++ curl URL option identity is unresolved; analysis is incomplete')
                if selected == option:
                    targets = [2]
                elif (not re.fullmatch(r'CURLOPT_[A-Z0-9_]+|CURLUPART_[A-Z0-9_]+', selected)
                      and request_value):
                    raise AnalysisLimit('C/C++ curl URL option identity is unresolved; analysis is incomplete')
        elif re.fullmatch(r'cpr::(?:Get|Post|Put|Delete|Patch|Head|Options)', name):
            # CPR options are positional-independent. Body/Parameters carry
            # payload data, while only Url supplies the selected endpoint.
            for index, span in enumerate(spans):
                low, high = span
                while self.parser.value(low) == '(' and self.parser.pairs.get(low) == high - 1:
                    low, high = low + 1, high - 1
                constructor = self.parser.compact(low, low + 3)
                complete = (self.parser.value(low + 3) in {'(', '{'}
                            and self.parser.pairs.get(low + 3) == high - 1)
                if complete and constructor == 'cpr::Url':
                    targets.append(index)
                elif (not (complete and constructor in {'cpr::Body', 'cpr::Parameters', 'cpr::Payload', 'cpr::Header'})
                      and any(trace.kind in {'source', 'parameter'} for trace in arguments[index])):
                    raise AnalysisLimit('C++ CPR URL option identity is unresolved; analysis is incomplete')
        elif SINK_RE.fullmatch(name + '('):
            targets = [0]
        for index in targets:
            if index < len(arguments):
                self.record(offset, arguments[index])


def analyze(path: Path, cwd: Path) -> list[tuple[str, int, str]]:
    text = path.read_text(encoding='utf-8')
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return []
    lines = text.splitlines()
    rel = str(path.resolve())
    issues = []
    for line, fact in sorted(OutboundEngine(path, text).analyze().items()):
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        source = witness.evidence[0].label if witness.evidence else 'request source'
        code = lines[line - 1].strip().replace('\t', ' ')
        issues.append((rel, line, f'{code}  [{source} -> outbound HTTP]'))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        for rel, line_no, code in analyze(path, cwd):
            yield rel, line_no, 1, code
