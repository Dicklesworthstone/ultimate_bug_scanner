"""Native weak randomness in security-named Ruby generation contexts.

The Ruby frontend separates executable interpolation from literal text and
provides method/constant scopes. Reassuring names never establish entropy.
Only an unshadowed cryptographic generator consumes a pure size argument
without making that argument part of the generated token. This is bounded
local API/receiver analysis, not a proof of arbitrary helper entropy.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_ruby_traversal import (
    RubyParser, closing_token, split_tokens, token_text, ungroup,
)
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import Budget
from ubs_core.ruby_detectors._common import (
    EXTS,
    read_lines,
    ruby_files,
    source_line,
)

RULE_ID = "ruby.security.non-crypto-random"
CATEGORY = 6
TITLE = "Security token generated with non-cryptographic randomness"
SEVERITY = "critical"
DESCRIPTION = (
    "Use SecureRandom.hex/base64/urlsafe_base64/uuid/random_bytes/"
    "alphanumeric for tokens, sessions, CSRF nonces, API keys, OTPs, salts, "
    "and secrets"
)

SECURITY_CONTEXT_RE = re.compile(
    r'(?:^|[^A-Za-z0-9])(?:api[_-]?key|access[_-]?key|private[_-]?key|public[_-]?key|secret|client[_-]?secret|'
    r'token|session|cookie|csrf|xsrf|otp|totp|mfa|nonce|salt|password|passwd|pwd|auth|bearer|credential|'
    r'reset|invite|verification|verify|confirm|confirmation|magic[_-]?link|recovery|signature|sig|key)(?:[^A-Za-z0-9]|$)',
    re.IGNORECASE,
)
UNSAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_:.])(?:::)?(?:Kernel\s*\.\s*)?(?:rand|srand)\b'
    r'|(?<![A-Za-z0-9_:.])(?:::)?Random\s*\.\s*(?:rand|new)\b',
)
PREDICTABLE_SOURCE_RE = re.compile(
    r'\bTime\.(?:now|new)\b'
    r'|\bDateTime\.now\b'
    r'|\bProcess\.pid\b'
    r'|(?<![A-Za-z0-9_:])(?:object_id|__id__)\b'
    r'|(?<![A-Za-z0-9_])hash\s*\('
    r'|\.[A-Za-z0-9_]*hash\b',
)
TOKEN_MATERIAL_RE = re.compile(
    r'#\{'
    r'|\.to_(?:s|i)\b'
    r'|\.strftime\s*\('
    r'|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\.'
    r'|\bBase64\.'
    r'|\.pack\s*\('
    r'|\.join\s*\(',
    re.IGNORECASE,
)
_STRONG_METHODS = frozenset({'hex', 'base64', 'urlsafe_base64', 'random_bytes', 'alphanumeric'})
_PUBLIC_TOKEN_METADATA = re.compile(
    r'\b(?:parser|lexer|lexical|syntax)_tokens?_(?:index|kind|type|count|position|offset|length)\b',
    re.IGNORECASE,
)


def _code_tokens(tokens):
    """Preserve source offsets, including code executed inside literals."""
    for token in tokens:
        if token.kind in {'code', 'number'}:
            yield token
        for part in token.parts:
            yield from _code_tokens(part)


def _code_view(tokens, source):
    code = tuple(_code_tokens(tokens))
    if not code:
        return '', 0
    start, end = min(token.start for token in code), max(token.end for token in code)
    view = [' '] * (end - start)
    for token in code:
        view[token.start - start:token.end - start] = source[token.start:token.end]
    return ''.join(view), start


class RandomnessAnalysis:
    def __init__(self, text, path, issues):
        self.text, self.path, self.issues = text, path, issues
        self.lines = text.splitlines()
        self.line_starts = [0] + [index + 1 for index, char in enumerate(text) if char == '\n']
        self.parser = RubyParser(text)
        self.budget = Budget()
        self.suppressions = SourceSuppressions('ruby').index(path, text)
        self.seen = set()
        self.constants = {}
        self.scope_calls = {}
        self.scope_dispatches = {}
        self.scope_local_writes = {}
        self.opaque_scope_calls = {}
        for function in self.parser.functions.values():
            if function.scope and function.owner:
                self.constants.setdefault(function.owner, []).append((function.key, False, function.conditional))
            self._constant_writes(function.body, function, not function.scope or function.conditional)

    def execution_offset(self, function, offset):
        if function.scope:
            return offset
        # A later definition is active only for a proven later invocation.
        # A saved Method/callback or dynamic dispatch may invoke the body
        # earlier; it must never borrow the final file's method table.
        key = function.owner, function.name
        calls = [position for position, explicit in self.scope_calls.get(key, ())
                 if explicit or not any(written < position for written in self.scope_local_writes.get(key, ()))]
        selected = min(calls) if calls else offset
        # An earlier helper or receiver call can enter this body indirectly.
        # A later direct call proves neither that it was the first invocation
        # nor that earlier calls used the later method definitions.
        for position, local in self.scope_dispatches.get(function.owner, ()):
            self.budget.spend()
            if (function.key < position < selected
                    and (local is None or not any(written < position for written in
                         self.scope_local_writes.get((function.owner, local), ())))):
                selected = position
        return min(selected, self.opaque_scope_calls.get(function.owner, selected))

    def _constant_writes(self, statements, function, conditional=False):
        for statement in statements:
            self.budget.spend()
            if function.scope:
                code = tuple(_code_tokens(statement.tokens))
                for index, token in enumerate(code):
                    previous = code[index - 1].value if index else ''
                    following = code[index + 1].value if index + 1 < len(code) else ''
                    if token.value in {'method', 'public_method', 'send', 'public_send',
                                       'eval', 'class_eval', 'module_eval', 'instance_eval', 'call'}:
                        self.opaque_scope_calls[function.owner] = min(
                            self.opaque_scope_calls.get(function.owner, token.start), token.start)
                    if (re.fullmatch(r'[a-z_]\w*[!?]?', token.value)
                            and previous not in {'.', '&.', '::', ':'}
                            and (following == '(' or len(code) == 1)):
                        self.scope_calls.setdefault((function.owner, token.value), []).append(
                            (token.start, following == '('))
                    if (re.fullmatch(r'[a-z_]\w*[!?]?', token.value)
                            and token.value not in {'true', 'false', 'nil', 'self'}
                            and previous != ':'
                            and following not in {'=', '||=', '&&=', '+=', '-=', '*=', '/=', ':'}):
                        local = (token.value if previous not in {'.', '&.', '::'}
                                 and following != '(' else None)
                        self.scope_dispatches.setdefault(function.owner, []).append((token.start, local))
            parts = split_tokens(statement.tokens, {'=', '||=', '&&='})
            if len(parts) > 1:
                name = token_text(parts[0])
                if function.scope and re.fullmatch(r'[a-z_]\w*', name):
                    self.scope_local_writes.setdefault((function.owner, name), []).append(parts[0][0].start)
                if re.fullmatch(r'(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*', name):
                    owner = (tuple(name[2:].split('::')) if name.startswith('::')
                             else (*function.owner, *name.split('::')))
                    self.constants.setdefault(owner, []).append((parts[0][0].start, True, conditional))
            self._constant_writes(statement.body, function, conditional or statement.kind != 'block')
            self._constant_writes(statement.alternate, function, True)
            self._constant_writes(statement.handlers, function, True)
            self._constant_writes(statement.finalizer, function, conditional)

    def native_constant(self, name, function, offset):
        parts = tuple(name.removeprefix('::').split('::'))
        scopes = ((),) if name.startswith('::') else (*function.lexical_owners, ())
        offset = self.execution_offset(function, offset)
        for scope in scopes:
            for length in range(1, len(parts) + 1):
                candidate = (*scope, *parts[:length])
                declarations = [(replaced, uncertain) for position, replaced, uncertain in self.constants.get(candidate, ())
                                if position < offset]
                if declarations and (scope or any(replaced for replaced, _ in declarations)):
                    return None if any(uncertain for _, uncertain in declarations) else False
        return True

    def native_method(self, namespace, method, function, offset):
        constant = self.native_constant(namespace, function, offset) if namespace else True
        if constant is not True:
            return constant
        root = tuple(namespace.removeprefix('::').split('::')) if namespace else ()
        offset = self.execution_offset(function, offset)
        for declared in self.parser.functions.values():
            if declared.scope or declared.name != method or declared.key >= offset:
                continue
            if namespace:
                if declared.singleton and declared.owner == root:
                    return None if declared.conditional else False
            elif (not declared.singleton and not declared.owner
                  or declared.owner == function.owner and declared.singleton == function.singleton):
                return None if declared.conditional else False
        return True

    def _pure_size(self, tokens, function):
        # A length expression does not supply the cryptographic bytes. Keep
        # assignment and opaque call effects outside this narrow exemption.
        names = {'rand', 'srand', 'Kernel', 'Random', 'new', 'to_i', 'abs', 'floor', 'ceil', 'round'}
        code = tuple(_code_tokens(tokens))
        for index, token in enumerate(code):
            self.budget.spend()
            if token.value in {'=', '+=', '-=', '||=', '&&=', ';', 'yield', 'return'}:
                return False
            if re.fullmatch(r'[A-Za-z_]\w*[!?]?', token.value) and token.value not in names:
                return False
            if token.value in {'Kernel', 'Random'} and self.native_constant(token.value, function, token.start) is not True:
                return False
            if token.value in {'rand', 'srand'}:
                namespace = ''
                if index >= 2 and code[index - 1].value == '.':
                    namespace = code[index - 2].value
                    if namespace not in {'Kernel', 'Random'}:
                        return False
                if self.native_method(namespace, token.value, function, token.start) is not True:
                    return False
        return True

    def _strong_argument_ranges(self, tokens, function):
        ranges = []
        for token in tokens:
            for part in token.parts:
                ranges.extend(self._strong_argument_ranges(part, function))
        for index, token in enumerate(tokens):
            self.budget.spend()
            if token.kind != 'code' or token.value not in {'SecureRandom', 'OpenSSL'}:
                continue
            start = index - 1 if index and tokens[index - 1].value == '::' else index
            if start and tokens[start - 1].value in {'.', '&.', '::'}:
                continue
            count = 3 if token.value == 'SecureRandom' else 5
            selected = tokens[index:index + count]
            name = token_text(selected)
            namespace, separator, method = name.rpartition('.')
            if not separator or not ((namespace == 'SecureRandom' and method in _STRONG_METHODS)
                                     or (namespace == 'OpenSSL::Random' and method == 'random_bytes')):
                continue
            if start != index:
                namespace = '::' + namespace
            if self.native_method(namespace, method, function, token.start) is not True:
                continue
            after = index + count
            if after >= len(tokens):
                continue
            if tokens[after].value == '(':
                end = closing_token(tokens, after)
                if end < 0:
                    continue
                arguments = tokens[after + 1:end]
            elif tokens[after].value in {'+', '-', '*', '/', '.', '&.', '||', '&&', ')', ']', '}'}:
                continue
            else:
                arguments = tokens[after:]
            if arguments and self._pure_size(arguments, function):
                ranges.append((arguments[0].start, arguments[-1].end))
        return ranges

    def source(self, tokens, function, generators, local_names):
        view, start = _code_view(tokens, self.text)
        if not view:
            return None
        context = view + (' ' + function.name if not function.scope else '')
        if not SECURITY_CONTEXT_RE.search(_PUBLIC_TOKEN_METADATA.sub(' ', context)):
            return None
        masked = list(view)
        for first, last in self._strong_argument_ranges(tokens, function):
            first, last = max(first, start), min(last, start + len(masked))
            if first < last:
                masked[first - start:last - start] = ' ' * (last - first)
        view = ''.join(masked)
        for match in UNSAFE_RANDOM_RE.finditer(view):
            name = re.sub(r'\s+', '', match.group())
            offset = start + match.start()
            namespace, separator, method = name.rpartition('.')
            if not separator:
                namespace, method = '', name
                following = view[match.end():].lstrip()
                if following.startswith(':') and not following.startswith('::'):
                    continue  # a hash label, not a call
                if re.match(r'(?:\|\|=|&&=|=(?!=|>|~))', following):
                    continue  # declaring a local does not call Kernel
                if name in local_names and not following.startswith('('):
                    continue  # a local/parameter read, not Kernel dispatch
            if self.native_method(namespace, method, function, offset) is False:
                continue
            if method == 'new':
                # A generator handle is inert until its output is requested.
                tail = view[match.end():]
                chained = re.match(r'(?:\s*\([^)]*\))?\s*\.\s*rand\b', tail)
                if not chained or self.native_method(namespace, 'rand', function, offset) is False:
                    continue
                name += chained.group()
            return offset, name
        for name in sorted(generators):
            match = re.search(rf'(?<![\w.:]){re.escape(name)}\s*\.\s*rand\b', view)
            if match:
                return start + match.start(), match.group().strip()
        material = TOKEN_MATERIAL_RE.search(view) or any(token.parts for token in tokens)
        if material:
            for match in PREDICTABLE_SOURCE_RE.finditer(view):
                name = match.group().strip()
                namespace, separator, method = name.partition('.')
                if separator and namespace in {'Time', 'DateTime', 'Process'}:
                    if self.native_method(namespace, method, function, start + match.start()) is False:
                        continue
                return start + match.start(), name
        return None

    def walk(self, statements, function, generators, local_names):
        generators = set(generators)
        local_names = set(local_names)
        for statement in statements:
            self.budget.spend()
            tokens = statement.tokens
            found = self.source(tokens, function, generators, local_names)
            if found:
                offset, name = found
                line = bisect_right(self.line_starts, offset)
                if line not in self.seen and not self.suppressions.is_suppressed(line, RULE_ID):
                    self.seen.add(line)
                    self.issues.append((self.path, line, 1,
                        f'{source_line(self.lines, line)}  [{name} in security-sensitive generation context]'))
            parts = split_tokens(tokens, {'='})
            if len(parts) == 2 and len(parts[0]) == 1 and re.fullmatch(r'[a-z_]\w*', parts[0][0].value):
                name, rhs = parts[0][0].value, ungroup(parts[1])
                local_names.add(name)
                spelling = token_text(rhs)
                native = re.fullmatch(r'((?:::)?Random)\.new(?:\(.*\))?', spelling)
                if spelling in generators or (native and self.native_method(native[1], 'new', function, rhs[0].start) is not False):
                    generators.add(name)
                else:
                    generators.discard(name)
            if statement.kind in {'if', 'unless'}:
                yes, yes_locals = self.walk(statement.body, function, generators, local_names)
                no, no_locals = self.walk(statement.alternate, function, generators, local_names)
                generators, local_names = yes | no, yes_locals | no_locals
            elif statement.body:
                body, body_locals = self.walk(statement.body, function, generators - set(statement.names),
                                             local_names | set(statement.names))
                if statement.kind in {'block', 'rescue'}:
                    generators, local_names = body, body_locals
                else:
                    generators |= (body & local_names) - set(statement.names)
            if statement.alternate and statement.kind not in {'if', 'unless'}:
                alternate, alternate_locals = self.walk(statement.alternate, function, generators, local_names)
                generators |= alternate
                local_names |= alternate_locals
            for handler in statement.handlers:
                recovered, recovered_locals = self.walk(handler.body, function, generators - set(handler.names),
                                                        local_names | set(handler.names))
                generators |= recovered
                local_names |= recovered_locals
            if statement.finalizer:
                generators, local_names = self.walk(statement.finalizer, function, generators, local_names)
        return generators, local_names

    def run(self):
        for function in self.parser.functions.values():
            self.walk(function.body, function, set(), set(function.parameters))


def analyze(lines, issues, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not (UNSAFE_RANDOM_RE.search(text) or PREDICTABLE_SOURCE_RE.search(text)):
        return
    if not SECURITY_CONTEXT_RE.search(text):
        return
    RandomnessAnalysis(text, path_str, issues).run()


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        issues: list[tuple] = []
        analyze(lines, issues, str(path))
        yield from issues
