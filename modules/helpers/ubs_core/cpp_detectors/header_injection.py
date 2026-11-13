"""C/C++ response-header flow with selected bindings and CR/LF proof.

The shared worklist supplies function summaries, branch joins, assignment
kills and reference effects. Only checks of the selected string or a bounded
character-replacement loop establish header safety. Names of helpers and
nearby validation do not. Unsupported C/C++ constructs remain incomplete.
"""
from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_cpp_traversal import Engine
from ubs_core.taint_flow import AnalysisLimit, CLEAN, Trace, join, retag

RULE_ID = "cpp.detector.header-injection"
CATEGORY = 7
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = ("Reject or strip CR/LF before writing request data to response "
               "headers; encode Content-Disposition filenames or use a "
               "header-safe helper.")

SKIP_DIRS = {'.git', '.hg', '.svn', 'vendor', 'node_modules', '.cache', 'build', 'cmake-build-debug', 'cmake-build-release', 'dist', 'out'}
EXTS = {'.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp', '.hxx', '.ipp', '.tpp', '.ixx', '.cppm', '.mpp'}

SOURCE_RE = re.compile(
    r'\b(?:req|request|http_request|httpRequest|ctx|context)(?:\.|->)'
    r'(?:get_param_value|getParam|getParameter|getQueryParam|getQueryParameter|query_param|queryParam|'
    r'form_value|formValue|param|Param|url_params\.get|getHeader|get_header|header|cookie|cookies|'
    r'getCookie|get_cookie|getHost|get_host|host|target|raw_url|url)\s*(?:\(|\b)'
    r'|\b(?:req|request)(?:\.|->)(?:headers|cookies|host|target|raw_url|url)\b'
    r'|\b(?:cgiFormString|FCGX_GetParam)\s*\('
    r'|\b(?:std\s*::\s*)?getenv\s*\(\s*"(?:QUERY_STRING|REQUEST_URI|HTTP_HOST|HTTP_COOKIE|HTTP_[A-Z0-9_]+)"\s*\)'
    r'|\bQUrlQuery\s*\([^;\n]*\)\.queryItemValue\s*\(',
    re.IGNORECASE,
)
CGI_FORM_OUT_RE = re.compile(
    r'\bcgiFormString\s*\(\s*[^,]+,\s*(?:&\s*)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*,'
)
SINK_RE = re.compile(
    r'\b(?:set_header|setHeader|add_header|addHeader|append_header|appendHeader|write_header|writeHeader|'
    r'send_header|sendHeader|header|set)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_header|setHeader|add_header|addHeader|append_header|appendHeader|'
    r'write_header|writeHeader|send_header|sendHeader|header|set|insert|emplace)\s*\('
    r'|\b(?:set_content_type|setContentType|content_type|contentType)\s*\('
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:set_content_type|setContentType|content_type|contentType)\s*\('
    r'|\b(?:headers|response_headers|resp_headers)\s*\[\s*["\'][^"\']+["\']\s*\]\s*='
    r'|\b[A-Za-z_][A-Za-z0-9_]*(?:\.|->)\s*(?:headers|response_headers|resp_headers)\s*\[\s*["\'][^"\']+["\']\s*\]\s*='
    r'|\b(?:printf|fprintf|snprintf|FCGX_FPrintF|mg_printf|mg_send|send|write)\s*\([^;\n]*(?:["\'][A-Za-z0-9_-]+:\s*%s|["\'][A-Za-z0-9_-]+:\s*)',
    re.IGNORECASE,
)
HEADER_SAFE = frozenset({'header-no-cr', 'header-no-lf'})
HEADER_TYPES = frozenset({'header-string', 'header-cstring', 'header-request', 'header-response', 'header-map'})
HEADER_METHODS = frozenset({'set_header', 'setHeader', 'add_header', 'addHeader',
    'append_header', 'appendHeader', 'write_header', 'writeHeader', 'send_header',
    'sendHeader', 'header'})
CONTENT_TYPE_METHODS = frozenset({'set_content_type', 'setContentType', 'content_type', 'contentType'})
HEADER_MAPS = frozenset({'headers', 'response_headers', 'resp_headers'})


class HeaderEngine(Engine):
    source_re, sink_re = SOURCE_RE, SINK_RE
    sink_label, rule = 'response header', RULE_ID

    def __init__(self, path, text):
        super().__init__(path, text)
        self.header_bindings = {}
        self.declared_types = {}
        self.declared_classes = {}
        self.character_loops = {}

    @staticmethod
    def declaration_type(declaration, name=''):
        compact = re.sub(r'\s+', '', declaration)
        if re.match(r'^(?:const)?std::(?:string|string_view)(?:const)?[&*]*$', compact):
            return 'header-string'
        if re.fullmatch(r'(?:const)?char(?:const)?\*(?:const)?', compact):
            return 'header-cstring'
        if re.match(r'^(?:const)?(?:(?:httplib|crow)::)?(?:Request|HttpRequest|request)(?:const)?[&*]*$', compact):
            return 'header-request'
        if re.match(r'^(?:const)?(?:(?:httplib|crow)::)?(?:Response|HttpResponse|response)(?:const)?[&*]*$', compact):
            return 'header-response'
        if name in HEADER_MAPS and re.match(r'^(?:const)?std::(?:map|multimap|unordered_map|unordered_multimap)<', compact):
            return 'header-map'
        return None

    @staticmethod
    def declaration_class(declaration):
        compact = re.sub(r'\b(?:const|volatile)\b|\s|[&*]', '', declaration)
        if compact not in {'auto', ''} and re.fullmatch(r'(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*', compact):
            return compact
        return None

    def binding_type(self, binding):
        return self.declared_types.get(self.function.key, {}).get(binding)

    def typed_value(self, value, binding):
        kind = self.binding_type(binding)
        if kind == 'other':
            return retag(value, remove=HEADER_TYPES | HEADER_SAFE)
        return retag(value, add=frozenset({kind})) if kind else value

    def source(self, offset, label):
        value = super().source(offset, label)
        # CGI functions return/write char buffers. Request string getters have
        # the string contract already used by the bounded request frontend.
        if not re.search(r'\b(?:getenv|FCGX_GetParam|cgiFormString)\b', label):
            value = retag(value, add=frozenset({'header-string'}))
        return value

    def safe(self, trace):
        return HEADER_SAFE <= trace.tags

    def literal(self, start, end):
        if start + 1 == end:
            raw = self.parser.value(start)
            raw_string = re.fullmatch(r'R"([^ ()\\\t\r\n]{0,16})\((.*)\)\1"', raw, re.DOTALL)
            if raw_string:
                return raw_string.group(2)
            return super().literal(start, end)
        values = []
        for index in range(start, end):
            if not self.parser.value(index).startswith(('"', 'R"')):
                return None
            value = self.literal(index, index + 1)
            if value is None:
                return None
            values.append(value)
        return ''.join(values) if values else None

    def without_proof(self, value):
        return retag(super().without_proof(value), remove=HEADER_SAFE | HEADER_TYPES)

    def record(self, offset, value, file_leaf=False):
        # File-stream constructors are owned by the traversal analyzer.
        if not file_leaf:
            super().record(offset, value)

    def assigned_value(self, start, offset, low, high, value):
        declaration = self.parser.raw(start, offset)
        kind = self.declaration_type(declaration, self.parser.value(offset))
        if kind:
            return retag(value, add=frozenset({kind}))
        if declaration.strip() and not re.search(r'\bauto\b', declaration):
            return retag(value, remove=HEADER_TYPES | HEADER_SAFE)
        return value

    @staticmethod
    def string_value(value):
        return bool(value) and all(trace.kind == 'constant' or 'header-string' in trace.tags for trace in value)

    @staticmethod
    def excludes(value, character, tag):
        return bool(value) and all(tag in trace.tags or
            trace.kind == 'constant' and character not in trace.key[0] for trace in value)

    def expression(self, start, end, state, bindings, depth=0):
        previous = self.header_bindings
        self.header_bindings = bindings
        try:
            low, high = start, end
            while self.parser.value(low) == '(' and self.parser.pairs.get(low) == high - 1:
                low, high = low + 1, high - 1
            top = list(self.top_tokens(low, high))
            operators = {self.parser.value(index) for index in top}
            if '+' in operators and not operators & {'?', '=', '+=', '||', '&&', '==', '!='}:
                # Concatenating two established strings cannot introduce a
                # control character absent from both operands. Arbitrary
                # transformations continue to invalidate the proof.
                self.budget.spend()
                if depth > 64:
                    raise AnalysisLimit('C/C++ expression depth exceeded; analysis is incomplete')
                split = max(index for index in top if self.parser.value(index) == '+')
                left = self.expression(low, split, state, bindings, depth + 1)
                right = self.expression(split + 1, high, state, bindings, depth + 1)
                value = self.without_proof(join(left, right))
                if self.string_value(left) and self.string_value(right):
                    tags = {'header-string'}
                    for character, tag in (('\r', 'header-no-cr'), ('\n', 'header-no-lf')):
                        if self.excludes(left, character, tag) and self.excludes(right, character, tag):
                            tags.add(tag)
                    value = retag(value, add=frozenset(tags))
                return value
            value = super().expression(start, end, state, bindings, depth)
            if self.parser.value(low) in {'static_cast', 'reinterpret_cast', 'dynamic_cast', 'const_cast'}:
                value = self.without_proof(value)
            if high == low + 1 and re.fullmatch(r'[A-Za-z_]\w*', self.parser.value(low)):
                value = self.typed_value(value, bindings.get(self.parser.value(low), self.parser.value(low)))
            return value
        finally:
            self.header_bindings = previous

    def external_call(self, name, call, receiver, offset, state, bindings):
        method = re.split(r'::|\.|->', name)[-1]
        root = re.split(r'\.|->', name)[0]
        binding = bindings.get(root, root)
        receiver = self.typed_value(receiver, binding)
        if self.parser.macro_at(method, offset) is not None:
            return super().external_call(name, call, receiver, offset, state, bindings)
        if method in {'c_str', 'data'} and not call.values and self.string_value(receiver):
            if method == 'data':
                # A mutable pointer may be saved and passed to a writer later.
                # Keep that escape distinct from a copy of the string bytes.
                return join(receiver, frozenset({Trace('header-buffer', (self.function.key, binding))}))
            return receiver
        if name in {'std::string', 'std::string_view'} and len(call.values) == 1:
            return retag(call.values[0], add=frozenset({'header-string'}))
        if ('.' in name or '->' in name) and self.binding_type(binding) == 'other' and SOURCE_RE.match(name + '('):
            # A same-spelled getter on an explicitly unrelated receiver is
            # not the native request API modeled by this frontend.
            return self.without_proof(join(receiver, *call.values))
        result = super().external_call(name, call, receiver, offset, state, bindings)
        read_only = (method in {'find', 'find_first_of', 'size', 'length', 'empty', 'substr',
                                'compare', 'starts_with', 'ends_with', 'reserve', 'shrink_to_fit'}
                     and self.string_value(receiver))
        output = (method in HEADER_METHODS | CONTENT_TYPE_METHODS or
                  method in {'set', 'insert', 'emplace'} and self.header_receiver(name, receiver) or
                  name in {'printf', 'std::printf', 'fprintf', 'std::fprintf', 'FCGX_FPrintF', 'mg_printf'})
        if not read_only and not output and name not in {'std::regex_replace', 'std::getenv', 'getenv', 'FCGX_GetParam'}:
            if any(trace.kind == 'header-buffer' for value in (receiver, *call.values) for trace in value):
                raise AnalysisLimit('C++ mutable string buffer escapes to an unresolved call; analysis is incomplete')
            # An unresolved callee may modify an argument passed by reference.
            # Revoke only the selected objects' proofs; unrelated validated
            # strings keep theirs. Known pure readers above do not mutate.
            candidates = [root] if '.' in name or '->' in name else []
            for low, high in call.spans:
                while self.parser.value(low) == '(' and self.parser.pairs.get(low) == high - 1:
                    low, high = low + 1, high - 1
                raw = self.parser.compact(low, high)
                argument = re.fullmatch(r'&?([A-Za-z_]\w*)(?:\.data\(\)|\.begin\(\)|\.end\(\))?', raw)
                if argument:
                    candidates.append(argument.group(1))
            for candidate in candidates:
                target = bindings.get(candidate, candidate)
                value = state.get(target, CLEAN)
                if any(trace.tags & HEADER_SAFE for trace in value):
                    state[target] = self.without_proof(value)
                    self.note_mutation(target)
        return result

    def selected(self, name, arity):
        member = re.fullmatch(r'([A-Za-z_]\w*)(?:\.|->)([A-Za-z_]\w*)', name)
        if not member:
            return super().selected(name, arity)
        root, method = member.groups()
        binding = self.header_bindings.get(root, root)
        owner = self.declared_classes.get(self.function.key, {}).get(binding)
        # Request adapters are the existing C++ source contract. Other local
        # member implementations bind before an API spelling is considered.
        if not owner or self.binding_type(binding) == 'header-request':
            return []
        return [function for function in self.parser.functions.values()
                if function.name == method and function.owner == tuple(owner.split('::'))
                and len(function.parameters) == arity]

    def header_receiver(self, name, receiver):
        root = re.split(r'\.|->', name)[0]
        binding = self.header_bindings.get(root, root)
        return (self.binding_type(binding) in {'header-response', 'header-map'}
                or bool(receiver) and all(trace.tags & {'header-response', 'header-map'} for trace in receiver)
                or root in HEADER_MAPS and binding == root)

    def map_receiver(self, name, state, bindings):
        if re.fullmatch(r'[A-Za-z_]\w*', name):
            binding = bindings.get(name, name)
            value = self.typed_value(state.get(binding, CLEAN), binding)
            return (self.binding_type(binding) == 'header-map'
                    or bool(value) and all('header-map' in trace.tags for trace in value)
                    or name in HEADER_MAPS and binding == name and self.binding_type(binding) is None)
        member = re.fullmatch(r'([A-Za-z_]\w*)(?:\.|->)(headers|response_headers|resp_headers)', name)
        if member:
            binding = bindings.get(member.group(1), member.group(1))
            value = self.typed_value(state.get(binding, CLEAN), binding)
            return (self.binding_type(binding) == 'header-response'
                    or bool(value) and all('header-response' in trace.tags for trace in value)
                    or member.group(1) in {'res', 'resp', 'response'} and binding == member.group(1)
                    and self.binding_type(binding) is None)
        return False

    def call_sink(self, name, spans, arguments, offset, receiver=CLEAN):
        method = re.split(r'::|\.|->', name)[-1]
        member = '.' in name or '->' in name
        targets = []
        if method in HEADER_METHODS or method in {'set', 'insert', 'emplace'} and self.header_receiver(name, receiver):
            if len(spans) >= 2:
                header = self.literal(*spans[0])
                if header is None or header.lower() != 'location':
                    targets = [0, 1]
        elif method in CONTENT_TYPE_METHODS:
            targets = [0]
        elif not member and name in {'printf', 'std::printf', 'fprintf', 'std::fprintf', 'FCGX_FPrintF', 'mg_printf'}:
            format_index = 0 if name in {'printf', 'std::printf'} else 1
            if len(spans) > format_index:
                template = self.literal(*spans[format_index])
                if template is not None:
                    targets = self.formatted_header_values(template, format_index + 1)
                elif any(trace.kind in {'source', 'parameter'} for value in arguments[format_index:] for trace in value):
                    raise AnalysisLimit('C++ response-header format is unresolved; analysis is incomplete')
        for index in targets:
            if index >= len(arguments):
                raise AnalysisLimit('C++ response-header format argument is missing; analysis is incomplete')
            self.record(offset, arguments[index])

    @staticmethod
    def formatted_header_values(template, first):
        targets, argument, cursor = [], first, 0
        # Consume every format argument in order; an unused variadic argument
        # and a %s in an ordinary body are not response-header values.
        pattern = re.compile(r'%(?P<position>\d+\$)?[-+ #0]*'
                             r'(?P<width>\d+|\*(?:\d+\$)?)?'
                             r'(?:\.(?P<precision>\d+|\*(?:\d+\$)?))?'
                             r'(?:hh|ll|[hljztL])?(?P<conversion>[diouxXfFeEgGaAcspn])')
        while (cursor := template.find('%', cursor)) >= 0:
            if template.startswith('%%', cursor):
                cursor += 2
                continue
            conversion = pattern.match(template, cursor)
            if conversion is None:
                raise AnalysisLimit('Unsupported C++ response-header format conversion; analysis is incomplete')
            for width in (conversion.group('width'), conversion.group('precision')):
                if width == '*':
                    argument += 1
            position = conversion.group('position')
            selected = first + int(position[:-1]) - 1 if position else argument
            if selected < first:
                raise AnalysisLimit('Invalid C++ response-header format argument; analysis is incomplete')
            beginning = template.rfind('\n', 0, cursor) + 1
            prefix = template[beginning:cursor]
            header = re.match(r'([A-Za-z0-9_-]+):', prefix)
            header_end = template.find('\r\n\r\n')
            if header_end < 0:
                header_end = template.find('\n\n')
            if (conversion.group('conversion') in {'s', 'c'} and header and header.group(1).lower() != 'location'
                    and (header_end < 0 or cursor < header_end)):
                targets.append(selected)
            if not position:
                argument += 1
            cursor = conversion.end()
        return targets

    def atomic_guard(self, start, end):
        top = list(self.top_tokens(start, end))
        comparison = [index for index in top if self.parser.value(index) in {'==', '!='}]
        if len(comparison) != 1:
            return []
        split = comparison[0]
        low, high = start, split
        other = self.parser.compact(split + 1, end)
        if other not in {'std::string::npos', 'std::string_view::npos'}:
            if self.parser.compact(start, split) not in {'std::string::npos', 'std::string_view::npos'}:
                return []
            low, high = split + 1, end
        call = re.fullmatch(r'([A-Za-z_]\w*)\.(find|find_first_of)\((.*)\)', self.parser.compact(low, high))
        if not call:
            return []
        opening = low + 3
        if self.parser.value(opening) != '(' or self.parser.pairs.get(opening) != high - 1:
            return []
        spans = list(self.parser.parts(opening + 1, high - 1))
        if len(spans) != 1:
            return []
        characters = self.literal(*spans[0])
        if characters is None or call.group(2) == 'find' and len(characters) != 1:
            return []
        return [(self.parser.value(split) == '==', (call.group(1), tag))
                for character, tag in (('\r', 'header-no-cr'), ('\n', 'header-no-lf')) if character in characters]

    def apply_guard(self, guard, state, bindings):
        name, tag = guard
        binding = bindings.get(name, name)
        original = self.typed_value(state.get(binding, CLEAN), binding)
        if self.string_value(original):
            state[binding] = retag(original, add=frozenset({tag}))
        return state

    def character_replacement(self, statement):
        if statement.kind != 'for':
            return None
        low, high = statement.header
        header = re.fullmatch(r'(?:char|auto)(&?)([A-Za-z_]\w*):([A-Za-z_]\w*)', self.parser.compact(low, high))
        if not header or len(statement.body) != 1:
            return None
        condition = statement.body[0]
        if condition.kind != 'if' or condition.otherwise or len(condition.body) != 1:
            return None
        reference, character, target = header.groups()
        compared = []
        for start, end in self.parser.parts(*condition.header, '||'):
            while self.parser.value(start) == '(' and self.parser.pairs.get(start) == end - 1:
                start, end = start + 1, end - 1
            if self.parser.value(start) != character or self.parser.value(start + 1) != '==':
                return None
            compared.append(self.literal(start + 2, end))
        if not compared or any(value not in {'\r', '\n'} for value in compared):
            return None
        replacement = condition.body[0]
        assignment = self.parser.assignment(replacement.start, replacement.end)
        if not assignment or assignment[0] != character or assignment[-1] or assignment[4] != '=':
            return None
        substituted = self.literal(assignment[2], assignment[3])
        if substituted is None or len(substituted) != 1:
            return None
        proved = frozenset(tag for character, tag in (('\r', 'header-no-cr'), ('\n', 'header-no-lf'))
                           if character in compared and character != substituted)
        revoked = frozenset(tag for character, tag in (('\r', 'header-no-cr'), ('\n', 'header-no-lf'))
                            if character == substituted)
        return target, bool(reference), proved, revoked

    def require_literal_declaration(self, start, end):
        for index in range(start, end):
            name = self.parser.value(index)
            if re.fullmatch(r'[A-Za-z_]\w*', name) and self.parser.macro_at(name, index) is not None:
                raise AnalysisLimit('C++ header type or binding needs macro expansion; analysis is incomplete')

    def graph(self, function):
        def rewrite(statements):
            result = []
            for statement in statements:
                target = self.character_replacement(statement)
                if target:
                    self.require_literal_declaration(*statement.header)
                    self.character_loops[statement.start] = target
                    result.append(replace(statement, kind='header-characters', body=(), otherwise=()))
                else:
                    result.append(replace(statement, body=rewrite(statement.body), otherwise=rewrite(statement.otherwise)))
            return tuple(result)

        entry, actions, edges = super().graph(replace(function, body=rewrite(function.body)))
        declared, classes = {}, {}
        if function.key >= 0:
            opening = function.key + 1
            self.require_literal_declaration(opening + 1, self.parser.pairs[opening])
        for index, (name, declaration) in enumerate(zip(function.parameters, function.declarations)):
            prefix = declaration.rsplit(name, 1)[0]
            binding = 'param:' + str(index)
            declared[binding] = self.declaration_type(prefix, name) or 'other'
            owner = self.declaration_class(prefix)
            if owner:
                classes[binding] = owner
        for kind, (start, end), bindings, _guard, _reads in actions.values():
            assignment = self.parser.assignment(start, end) if kind == 'simple' else None
            if assignment and assignment[-1]:
                name, offset = assignment[:2]
                self.require_literal_declaration(start, offset + 1)
                declared_type = self.declaration_type(self.parser.raw(start, offset), name)
                declaration = self.parser.raw(start, offset)
                if declared_type or not re.search(r'\bauto\b', declaration):
                    declared[bindings[name]] = declared_type or 'other'
                owner = self.declaration_class(declaration)
                if owner:
                    classes[bindings[name]] = owner
            elif kind == 'simple' and end > start + 1 and re.fullmatch(r'[A-Za-z_]\w*', self.parser.value(end - 1)):
                name = self.parser.value(end - 1)
                declaration = self.parser.raw(start, end - 1)
                owner = self.declaration_class(declaration)
                if owner:
                    binding = bindings.get(name, name)
                    classes[binding] = owner
                    declared[binding] = self.declaration_type(declaration, name) or 'other'
        self.declared_types[function.key] = declared
        self.declared_classes[function.key] = classes
        return entry, actions, edges

    def transfer(self, action, state):
        kind, (start, end), bindings, _guard, reads = action
        if kind == 'header-characters':
            name, reference, proved, revoked = self.character_loops[start]
            binding = bindings.get(name, name)
            value = self.typed_value(state.get(binding, CLEAN), binding)
            if not self.string_value(value):
                raise AnalysisLimit('C++ header character loop needs a selected std::string; analysis is incomplete')
            if reference:
                state[binding] = retag(value, add=proved, remove=revoked)
                self.note_mutation(binding)
            return state
        if kind == 'simple':
            top = list(self.top_tokens(start, end))
            equals = next((index for index in top if self.parser.value(index) == '='), None)
            if equals is not None:
                opening = next((index for index in top if self.parser.value(index) == '['), None)
                if opening is not None and self.parser.pairs[opening] == equals - 1:
                    root = self.parser.compact(start, opening)
                    if self.map_receiver(root, state, reads):
                        name = self.literal(opening + 1, equals - 1)
                        key = self.expression(opening + 1, equals - 1, state, reads)
                        value = self.expression(equals + 1, end, state, reads)
                        if name is None or name.lower() != 'location':
                            self.record(start, join(key, value))
                        return state
        return super().transfer(action, state)


def analyze(path: Path, cwd: Path) -> list[tuple[str, int, str]]:
    text = path.read_text(encoding='utf-8')
    if not (SOURCE_RE.search(text) and SINK_RE.search(text)):
        return []
    lines = text.splitlines()
    rel = str(path.resolve())
    issues = []
    for line, fact in sorted(HeaderEngine(path, text).analyze().items()):
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        source = witness.evidence[0].label if witness.evidence else 'request source'
        code = lines[line - 1].strip().replace('\t', ' ')
        issues.append((rel, line, f'{code}  [{source} -> response header]'))
    return issues


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    cwd = Path.cwd()
    for path in files:
        if path.suffix.lower() not in EXTS:
            continue
        for rel, line_no, code in analyze(path, cwd):
            yield rel, line_no, 1, code
