"""Value-specific Java/Kotlin response-header flow on the bounded JVM CFG.

Selected local helpers contribute their actual return/effect summaries. CR/LF
proofs apply only to the checked String on the dominated branch, or to a
verified String replacement/URLEncoder result. Reassuring names and nearby
checks confer no trust. Unsupported flow remains explicit incomplete analysis.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.analyzers.taint_java_traversal import Engine
from ubs_core.taint_flow import CLEAN, advance, join, retag
from ubs_core.java_detectors._common import (
    iter_java_files,
    source_line,
)

RULE_ID = "java.security.header-injection"
CATEGORY = 4
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = (
    "Reject or strip CR/LF, URL-encode filename fragments, or route values "
    "through a verified header-safe helper before setHeader/addHeader/header/headers.append"
)

SOURCE_RE = re.compile(
    r'\b(?:request|req|ctx|context|exchange|routingContext)(?:\.|->)'
    r'(?:getParameter|getParameterValues|getQueryString|getRequestURI|getRequestURL|getServletPath|'
    r'getPathInfo|getHeader|getCookies|queryParam|queryParams|pathParam|pathParams|formParam|formParams)\s*\('
    r'|\b(?:call|routingCall|context|ctx)\.(?:parameters|pathParameters|queryParameters|headers)\s*(?:\[|\.get\b)'
    r'|\b(?:call|routingCall)\.request\.(?:headers|header|queryParameters|parameters)\s*(?:\(|\[|\b|\.get\b)'
    r'|\b(?:parameters|params|queryParameters|pathParameters|headers)\s*\['
    r'|\b(?:request|req)\.(?:path|uri|url|target)\b',
    re.IGNORECASE,
)
ANNOTATED_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|QueryParam|PathParam|HeaderParam|'
    r'FormParam|MatrixParam)\b(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?)*\s+'
    r'(?:final\s+)?(?:String|Object|[A-Za-z_][A-Za-z0-9_.<>, ?\[\]]*)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
HEADER_START_RE = re.compile(
    r'\.\s*(?:setHeader|addHeader|header|add|set|append)\s*\('
    r'|\bheadersOf\s*\(',
    re.IGNORECASE,
)
HEADER_INDEX_ASSIGN_RE = re.compile(
    r'\.\s*headers\s*\[\s*(?P<quote>["\'])(?P<name>[^"\']+)(?P=quote)\s*\]\s*=',
    re.IGNORECASE,
)
HEADER_SAFE = frozenset({'header-no-cr', 'header-no-lf'})
_QUOTED = r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'


def literal(text):
    if not re.fullmatch(_QUOTED, text.strip()):
        return None
    try:
        value = ast.literal_eval(text.strip())
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


class HeaderEngine(Engine):
    source_re = SOURCE_RE
    sink_re = re.compile(HEADER_START_RE.pattern + '|' + HEADER_INDEX_ASSIGN_RE.pattern)
    sink_label = 'response header'
    path_constructors = False

    def source(self, offset, label):
        return retag(super().source(offset, label), add=frozenset({'jvm-string'}))

    def record(self, offset, value, file_leaf=False):
        unsafe = frozenset(trace for trace in value if not HEADER_SAFE <= trace.tags)
        if unsafe:
            self.effects[offset] = join(self.effects.get(offset, CLEAN),
                                        advance(unsafe, self.step(offset, 'sink', self.sink_label)))

    def summary_effect(self, summary, fact):
        return frozenset(trace for trace in fact if not HEADER_SAFE <= trace.tags)

    def _literal_arguments_at(self, offset):
        opening = self.code.find('(', offset)
        if opening < 0 or opening not in self.parser.pairs:
            return []
        # Executable Kotlin template holes survive lexical masking. A quoted
        # replacement such as "$other" is not a fixed literal and can introduce
        # request-controlled CR/LF even when the receiver was already checked.
        return [literal(self.text[low:high])
                if not self.parser.kotlin or self.code[low:high].strip() == '0' else None for low, high in
                self.parser.parts(opening + 1, self.parser.pairs[opening])]

    def _replace(self, method, receiver, offset):
        if not receiver or any('jvm-string' not in trace.tags for trace in receiver):
            return None
        arguments = self._literal_arguments_at(offset)
        if len(arguments) != 2:
            return None
        old, new = arguments
        if old is None or new is None:
            return None
        removed = set()
        if method == 'replace' and old in {'\r', '\n'}:
            removed.add(old)
        elif method == 'replaceAll' and not self.parser.kotlin and not any(character in new for character in '$\\'):
            # Only these exact regexes remove every CR and LF. In particular,
            # replaceFirst and a sequence "\\r\\n" do not remove lone controls.
            # Replacement backreferences such as $0 can reinsert the match.
            if old in {'[\r\n]', '[\n\r]', r'[\r\n]', r'[\n\r]'}:
                removed.update(('\r', '\n'))
        if not removed or any(character in new for character in '\r\n'):
            return None
        tags = frozenset('header-no-cr' if character == '\r' else 'header-no-lf' for character in removed)
        return retag(receiver, add=tags)

    def external_call(self, name, arguments, value, offset, bindings, state):
        root, _, method = name.rpartition('.')
        receiver = state.get(bindings.get(root, root), CLEAN)
        if method in {'replace', 'replaceAll'}:
            replaced = self._replace(method, receiver, offset)
            if replaced is not None:
                return replaced
        if name in {'URLEncoder.encode', 'java.net.URLEncoder.encode'} and arguments:
            factory = name.split('.')[0]
            if (not self.call_is_shadowed(factory, bindings) and self.builtin_type('URLEncoder')):
                return retag(arguments[0], add=HEADER_SAFE | frozenset({'jvm-string'}))
        if self.source_re.search(name + '('):
            return retag(value, add=frozenset({'jvm-string'}), remove=HEADER_SAFE)
        if method == 'toString' and not arguments and receiver and all('jvm-string' in trace.tags for trace in receiver):
            return receiver
        return retag(value, remove=HEADER_SAFE | frozenset({'jvm-string'}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if direct_call:
            return value
        if any(trace.kind == 'source' and trace.key[1] == offset for trace in value):
            # Kotlin request-map properties are sources before the index is
            # visited, just as getParameter() is a Java String source.
            return retag(value, add=frozenset({'jvm-string'}), remove=HEADER_SAFE)
        if name in {'replace', 'replaceAll'}:
            replaced = self._replace(name, receiver, offset)
            if replaced is not None:
                return replaced
        if name == 'toString' and not arguments and receiver and all('jvm-string' in trace.tags for trace in receiver):
            return receiver
        return retag(value, remove=HEADER_SAFE | frozenset({'jvm-string'}))

    def call_sink(self, name, call, value, offset, bindings):
        method = name.rsplit('.', 1)[-1]
        if method not in {'setHeader', 'addHeader', 'header', 'add', 'set', 'append', 'headersOf'}:
            return False
        if len(call.spans) < 2:
            return False
        key = call.names.index('name') if 'name' in call.names else 0
        target = call.names.index('value') if 'value' in call.names else 1
        header = self.text[slice(*call.spans[key])].strip()
        constant = re.fullmatch(r'(?:HttpHeaders\.)?(?:CONTENT_DISPOSITION|CONTENT_TYPE|CACHE_CONTROL|ETAG|SET_COOKIE)', header)
        header_name = literal(header)
        # Location retains the dedicated open-redirect policy/public rule.
        if (header_name is not None and header_name.casefold() != 'location') or constant or (
                header_name is None and method in {'setHeader', 'addHeader', 'header'}):
            self.record(offset, call.values[target])
        return False

    def guard_facts(self, span):
        start, end = span
        while start < end and self.text[start].isspace():
            start += 1
        while end > start and self.text[end - 1].isspace():
            end -= 1
        if self.code[start:start + 1] == '(' and self.parser.pairs.get(start) == end - 1:
            return self.guard_facts((start + 1, end - 1))
        for operator, truth in (('||', False), ('&&', True)):
            cursor, beginning, parts = start, start, []
            while cursor < end:
                if cursor in self.parser.pairs:
                    cursor = self.parser.pairs[cursor] + 1
                elif self.code.startswith(operator, cursor):
                    parts.append((beginning, cursor))
                    cursor += 2
                    beginning = cursor
                else:
                    cursor += 1
            if parts:
                parts.append((beginning, end))
                return [(truth, guard) for part in parts for positive, guard in self.guard_facts(part) if positive == truth]
        if self.code[start:start + 1] == '!':
            return [(not truth, guard) for truth, guard in self.guard_facts((start + 1, end))]
        raw = self.text[start:end].strip()
        match = re.fullmatch(r'([A-Za-z_]\w*)\.(contains|indexOf)\s*\(\s*' + _QUOTED +
                             r'\s*\)\s*(?:(==|!=|>=|<=|>|<)\s*(-?\d+))?', raw)
        if not match:
            return []
        name, method, quoted, operator, number = match.groups()
        character = literal(quoted)
        if character not in {'\r', '\n'}:
            return []
        if method == 'contains' and operator is None:
            truth = False
        elif method == 'indexOf' and (operator, number) in {('>=', '0'), ('>', '-1'), ('!=', '-1')}:
            truth = False
        elif method == 'indexOf' and (operator, number) in {('<', '0'), ('<=', '-1'), ('==', '-1')}:
            truth = True
        else:
            return []
        return [(truth, (name, 'header-no-cr' if character == '\r' else 'header-no-lf'))]

    def apply_guard(self, guard, state, bindings):
        name, tag = guard
        binding = bindings.get(name, name)
        state[binding] = join(*(retag(frozenset({trace}), add=frozenset({tag}))
                               if 'jvm-string' in trace.tags else frozenset({trace})
                               for trace in state.get(binding, CLEAN)))
        return state

    def _added_controls(self, start, end):
        parts = list(self.parser.parts(start, end, separator='+')) or [(start, end)]
        controls = set()
        for low, high in parts:
            raw = self.text[low:high].strip()
            value = raw[3:-3] if raw.startswith('"""') and raw.endswith('"""') else literal(raw)
            if value is not None:
                controls.update(character for character in '\r\n' if character in value)
        return frozenset('header-no-cr' if character == '\r' else 'header-no-lf' for character in controls)

    def expression(self, start, end, state, bindings, depth=0):
        value = super().expression(start, end, state, bindings, depth)
        return retag(value, remove=self._added_controls(start, end))

    def transfer(self, action, state):
        kind, span, bindings, guard, reads = action
        if kind == 'simple':
            start, end = span
            assignment = HEADER_INDEX_ASSIGN_RE.search(self.text[start:end])
            if (assignment and self.code[start + assignment.start():start + assignment.start() + 1] == '.'
                    and assignment.group('name').casefold() != 'location'):
                self.record(start, self.expression(start + assignment.end(), end, state, reads))
                return state
        result = super().transfer(action, state)
        assignment = self.assignment(span) if kind == 'simple' else None
        if assignment and assignment[4] == '+=':
            binding = bindings.get(assignment[0], assignment[0])
            result[binding] = retag(result.get(binding, CLEAN), remove=self._added_controls(assignment[2], assignment[3]))
        return result


def analyze(path: Path, issues, *, suppressions: SourceSuppressions, rule_id: str):
    text = path.read_text(encoding='utf-8', errors='ignore')
    if not ((SOURCE_RE.search(text) or ANNOTATED_PARAM_RE.search(text)) and HeaderEngine.sink_re.search(text)):
        return
    suppression = suppressions.index(path, text)
    lines = text.splitlines()
    for line, fact in sorted(HeaderEngine(path, text).analyze().items()):
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
