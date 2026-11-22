"""Native Rust executable selection over structured local dataflow.

Environment/argument sources retain provenance through lexical bindings,
overwrites, branches, loops and selected local helper summaries. Native API
aliases are resolved separately from value names, and local namespaces stop
that resolution. The redirect engine supplies the transfer semantics; URL
guards never establish an executable allowlist.

Saved native function values carry callable identity, not input contents.
Aliasing, finite joins, explicit function-pointer casts and selected helper
returns preserve that identity; only invocation reads input or selects an
executable. Opaque callable alternatives and transports remain explicit.

The legacy entry-parameter vocabulary remains a conservative input boundary
for externally callable functions. It does not taint fixed locals or private
helpers whose selected callers supply only fixed executables. General Rust
type inference, imported helper bodies and macro expansion remain outside the
selected-file model.
"""
from __future__ import annotations

from bisect import bisect_right
import re
from pathlib import Path
from typing import Iterator, Sequence

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import AnalysisLimit
from .redirect_flow import CLEAN, Flow, Origin, Source, State, join

RULE_ID = "rust.security.command-executable"
CATEGORY = 8
TITLE = "Command executable from untrusted-looking value"
SEVERITY = "critical"
DESCRIPTION = (
    "Use a fixed executable allowlist; pass user data only as argv after validation"
)

untrusted = re.compile(
    r"(?:^|_)(?:user|input|cmd|command|program|exe|binary|tool|shell|path|request|req|param|name|key)(?:$|_)"
)
_ENV_SOURCES = {('std', 'env', name) for name in ('var', 'var_os', 'args', 'args_os')}
_COMMAND_NEW = ('std', 'process', 'Command', 'new')
_NATIVE_CALLABLE = 'native-command-callable'
_OPAQUE_VALUE = 'opaque-command-value'
_CALLABLE_PARAMETER = 'invoked-command-parameter'
_DATA_PARAMETER = 'data-command-parameter'


class CommandSource(Source):
    def __init__(self, text, **kwargs):
        super().__init__(text, **kwargs)
        self.import_targets = {}
        self.extern_targets = {}
        self.partial_error = None
        self.current_flow = None
        self.constant_initializers = []
        for match in re.finditer(r'\b(?:const|static(?:\s+mut)?)\s+[A-Za-z_]\w*\s*:', self.code):
            end = self.next_boundary(match.end(), len(self.code), ';')
            equal = self.next_boundary(match.end(), end, '=')
            if equal < end:
                self.constant_initializers.append((equal + 1, end))
        for match in re.finditer(r'\buse\s+', self.code):
            end = self.next_boundary(match.end(), len(self.code), ';')
            scope = self.scope_at(match.start())
            for name, target in self.use_bindings(match.end(), end):
                key = scope, name
                self.import_targets[key] = None if key in self.import_targets else target
        for match in re.finditer(r'\bextern\s+crate\s+((?:r#)?[A-Za-z_]\w*)(?:\s+as\s+((?:r#)?[A-Za-z_]\w*))?', self.code):
            self.budget.spend()
            key = self.scope_at(match.start()), (match.group(2) or match.group(1)).removeprefix('r#')
            self.extern_targets[key] = None if key in self.extern_targets else match.group(1).removeprefix('r#')
        for match in re.finditer(r'\btype\s+((?:r#)?[A-Za-z_]\w*)\s*=\s*', self.code):
            end = self.next_boundary(match.end(), len(self.code), ';')
            target = re.sub(r'\s+', '', self.code[match.end():end]).replace('r#', '')
            # Only an exact, nongeneric type path proves the same constructor.
            # Associated types, generic aliases and trait projections remain
            # namespace boundaries, not guessed std identities.
            if re.fullmatch(r'(?:::)?[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', target):
                key = self.scope_at(match.start()), match.group(1).removeprefix('r#')
                self.import_targets[key] = None if key in self.import_targets else tuple(target.split('::'))

    def flow(self, function):
        self.current_flow = CommandFlow(self, function)
        return self.current_flow

    def use_bindings(self, start, end, prefix=()):
        """Expand a selected use tree without treating its leaf as API proof."""
        for begin, finish in self.parts(start, end):
            self.budget.spend()
            opening = self.next_boundary(begin, finish, '{')
            if opening in self.pairs and self.pairs[opening] < finish:
                owner = re.sub(r'\s+', '', self.code[begin:opening]).removesuffix('::')
                parts = tuple(part.removeprefix('r#') for part in owner.split('::')) if owner else ()
                yield from self.use_bindings(opening + 1, self.pairs[opening], prefix + parts)
                continue
            raw = self.code[begin:finish].strip()
            alias = re.search(r'\bas\s+((?:r#)?[A-Za-z_]\w*)\s*$', raw)
            path = raw[:alias.start()] if alias is not None else raw
            path = re.sub(r'\s+', '', path).replace('r#', '')
            if not path or '*' in path:
                continue
            parts = tuple(path.split('::'))
            target = prefix if parts == ('self',) else prefix + parts
            name = alias.group(1).removeprefix('r#') if alias is not None else target[-1]
            if name != '_':
                yield name, target

    def native_path(self, name, pos, state):
        if '.' in name or (name in state.values and '::' not in name):
            return None
        return self.native_parts(tuple(name.split('::')), self.scope_at(pos), frozenset())

    def native_parts(self, parts, scope, visited, *, direct=False):
        self.budget.spend()
        if not parts:
            return None
        first, *rest = parts
        if first == '':
            # Absolute paths bypass local modules, but an explicit root extern
            # alias also changes the extern prelude. A foreign crate named
            # `std` cannot borrow the standard library's API identity.
            if not rest:
                return None
            external = self.extern_targets.get((-1, rest[0]), rest[0])
            return ('std', *rest[1:]) if external == 'std' else None
        if first == 'crate':
            # The selected file may itself be an external module; it does not
            # prove crate-root identity.
            return None
        if first in {'self', 'super'}:
            module = self.module_scope(scope)
            if first == 'super':
                if module < 0:
                    return None
                module = self.module_scope(self.parents[module])
            return self.native_parts(tuple(rest), module, visited, direct=True)
        while True:
            key = scope, first
            if key in self.namespaces:
                if key in visited:
                    return None
                if key in self.extern_targets:
                    return ('std', *rest) if self.extern_targets[key] == 'std' else None
                if key in self.import_targets:
                    target = self.import_targets[key]
                    if target is None:
                        return None
                    native = self.native_parts(target, scope, visited | {key})
                    return native + tuple(rest) if native is not None else None
                namespace = self.namespaces[key]
                if namespace is not None and namespace.kind == 'module' and rest:
                    return self.native_parts(tuple(rest), namespace.site, visited | {key}, direct=True)
                return None
            if direct or scope in self.glob_imports:
                return None
            if scope < 0 or self.boundaries.get(scope) == 'module':
                break
            scope = self.parents[scope]
        if (-1, first) in self.extern_targets:
            return ('std', *rest) if self.extern_targets[-1, first] == 'std' else None
        if first == 'std':
            return parts
        # Preserve ordinary scanner snippets that omit their imports. Any
        # observed declaration, generic parameter, or glob above prevents this
        # shorthand; an imported/local lookalike never inherits std identity.
        shorthand = {'Command': ('std', 'process', 'Command'),
                     'process': ('std', 'process'), 'env': ('std', 'env')}
        return shorthand[first] + tuple(rest) if first in shorthand else None

    def solve(self):
        try:
            findings = super().solve()
            # Item bodies are skipped by normal block execution. Inspect
            # their initializer spans after helper summaries exist so native
            # handles in nested module/impl storage cannot disappear as clean.
            for begin, end in self.constant_initializers:
                self.flow(None).expr(begin, end, State())
        except AnalysisLimit as exc:
            self.partial_error = exc
            findings = {}
            reached = [summary.sinks for summary in self.summaries.values()]
            if self.current_flow is not None:
                reached.append(self.current_flow.sinks)
            for sinks in reached:
                for site, fact in sinks.items():
                    concrete = frozenset(origin for origin in fact if origin.kind == 'source')
                    if concrete:
                        findings[site] = join(findings.get(site, CLEAN), concrete)
            # No unfinished summary or unproven entry parameter is installed.
            # The caller emits retained concrete findings before this error.
            return findings
        entries = self.entry_functions()
        for function, summary in self.summaries.items():
            if function not in entries and not function.public:
                continue
            inputs = {index: name for index, names in enumerate(function.params)
                      for name in names if untrusted.search(name.lower())}
            for site, fact in summary.sinks.items():
                sources = frozenset(Origin('source', function.start, inputs[origin.site])
                                    for origin in fact if origin.kind in {'parameter', _DATA_PARAMETER}
                                    and origin.site in inputs)
                if sources:
                    findings[site] = join(findings.get(site, CLEAN), sources)
        return findings

    def entry_functions(self):
        """Find call-graph roots, including mutually recursive components.

        Private helpers reached from selected callers use their actual input
        facts. A root recursive component still has an unknown external entry;
        an internal backedge cannot prove its arguments are fixed.
        """
        callees = {function: set() for function in self.functions}
        for target, callers in self.callers.items():
            for caller in callers:
                self.budget.spend()
                callees[caller].add(target)
        visited, order = set(), []
        for function in self.functions:
            if function in visited:
                continue
            visited.add(function)
            stack = [(function, iter(callees[function]))]
            while stack:
                self.budget.spend()
                current, children = stack[-1]
                child = next(children, None)
                if child is None:
                    order.append(current)
                    stack.pop()
                elif child not in visited:
                    visited.add(child)
                    stack.append((child, iter(callees[child])))
        components = {}
        for function in reversed(order):
            if function in components:
                continue
            stack = [function]
            while stack:
                self.budget.spend()
                current = stack.pop()
                if current in components:
                    continue
                components[current] = function
                stack.extend(self.callers[current])
        roots = set(components.values())
        for target, callers in self.callers.items():
            for caller in callers:
                self.budget.spend()
                if components[target] != components[caller]:
                    roots.discard(components[target])
        return {function for function, component in components.items() if component in roots}


class CommandFlow(Flow):
    url_validation = False

    @staticmethod
    def native_values(fact):
        return frozenset(origin for origin in fact if origin.kind == _NATIVE_CALLABLE)

    def native_callable(self, name, pos, state):
        native = self.source.native_path(name, pos, state)
        if native in _ENV_SOURCES or native == _COMMAND_NEW:
            return native
        if name not in state.values:
            return None
        fact = state.values[name]
        identities = self.native_values(fact)
        if not identities:
            return None
        targets = {origin.label for origin in identities}
        if len(targets) != 1 or any(origin.kind != _NATIVE_CALLABLE for origin in fact):
            raise AnalysisLimit('Rust native callable alternatives require invocation summaries; analysis is incomplete')
        return tuple(next(iter(targets)).split('::'))

    def expr(self, start, end, state):
        src = self.source
        start, end = src.trim(start, end)
        cast = src.keyword(start, end, 'as')
        if cast < end:
            kind = src.code[cast + 2:end].strip()
            integer = re.fullmatch(r'usize|isize|[ui](?:8|16|32|64|128)', kind)
            if integer or re.match(r'fn\s*\(', kind):
                fact = self.expr(start, cast, state)
                # The type of a cast is syntax, not another value alternative.
                return (frozenset(Origin(_DATA_PARAMETER, origin.site, origin.label)
                                  if origin.kind == 'parameter' else origin
                                  for origin in fact if origin.kind != _NATIVE_CALLABLE)
                        if integer else fact)
        if re.match(r'(?:move\s+)?\|', src.code[start:end]):
            # A closure is a different callable even when it captures a native
            # function. Retain that uncertainty until invocation or escape;
            # constructing an unused closure does not execute its body.
            fact = frozenset({Origin(_OPAQUE_VALUE, start, 'closure')})
            opening = src.code.find('|', start, end)
            closing = src.code.find('|', opening + 1, end)
            parameters = set()
            if closing >= 0:
                for begin, finish in src.parts(opening + 1, closing, generics=True):
                    colon = src.next_boundary(begin, finish, ':')
                    parameters.update(src.pattern_names(begin, colon))
            for token in re.finditer(r'(?:::)?[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', src.code[start:end]):
                name = token.group()
                if name in parameters:
                    continue
                fact = join(fact, self.native_values(state.values.get(name, CLEAN)))
                native = src.native_path(name, start + token.start(), state)
                if native in _ENV_SOURCES or native == _COMMAND_NEW:
                    fact = join(fact, frozenset({Origin(_NATIVE_CALLABLE, start, '::'.join(native))}))
            return fact
        fact = super().expr(start, end, state)
        indirect = re.search(r'[)\]]\s*\(', src.code[start:end])
        if indirect:
            for origin in fact:
                if origin.kind == 'parameter':
                    self.emit(start, frozenset({Origin(_CALLABLE_PARAMETER, origin.site, 'indirect invocation')}))
        if not self.native_values(fact):
            return fact
        if (indirect
                or any(begin <= start < finish for begin, finish in src.constant_initializers)):
            raise AnalysisLimit('Rust native callable expression/storage requires identity analysis; analysis is incomplete')
        return fact

    def substitute(self, fact, actuals):
        result = super().substitute(frozenset(origin for origin in fact
                                              if origin.kind not in {_CALLABLE_PARAMETER, _DATA_PARAMETER}), actuals)
        for origin in fact:
            if origin.kind == _DATA_PARAMETER and origin.site < len(actuals):
                result = join(result, frozenset(Origin(_DATA_PARAMETER, value.site, value.label)
                                                if value.kind == 'parameter' else value
                                                for value in actuals[origin.site] if value.kind != _NATIVE_CALLABLE))
                continue
            if origin.kind != _CALLABLE_PARAMETER or origin.site >= len(actuals):
                continue
            actual = actuals[origin.site]
            if self.native_values(actual):
                raise AnalysisLimit('Rust native callable parameter invocation requires summaries; analysis is incomplete')
            result = join(result, frozenset(Origin(_CALLABLE_PARAMETER, value.site, origin.label)
                                            for value in actual if value.kind == 'parameter'))
        return result

    def call_result(self, name, pos, close, end, state, local, chained, macro, opaque_path, value, arguments):
        if local is not None:
            return value
        native = self.native_callable(name, pos, state) if not chained and not macro else None
        if native in _ENV_SOURCES:
            # The handle is not input data. Its invocation creates the source,
            # at this call site, irrespective of the handle's original name.
            return frozenset({Origin('source', pos, ' '.join(self.source.raw[pos:close + 1].split()))})
        if native == _COMMAND_NEW:
            return CLEAN
        if self.native_values(value):
            raise AnalysisLimit('Rust native callable escaped to an unsupported call; analysis is incomplete')
        # A native callable may reach an opaque invocation through a helper
        # argument/receiver. Preserve that use as a symbolic effect even when
        # its return value is discarded, then resolve it at the actual caller.
        for origin in value:
            if origin.kind == 'parameter':
                self.emit(pos, frozenset({Origin(_CALLABLE_PARAMETER, origin.site, name)}))
        return join(value, frozenset({Origin(_OPAQUE_VALUE, pos, name)}))

    def value_source(self, name, pos, end, state):
        native = self.source.native_path(name, pos, state)
        if native in _ENV_SOURCES or native == _COMMAND_NEW:
            return frozenset({Origin(_NATIVE_CALLABLE, pos, '::'.join(native))})
        if name in state.values or '.' in name:
            return CLEAN
        # Keep an alternative local/imported function from disappearing into
        # CLEAN beside a native function pointer at a control-flow join.
        return frozenset({Origin(_OPAQUE_VALUE, pos, name)})

    def index_result(self, name, pos, state, value, arguments):
        if self.native_values(value):
            raise AnalysisLimit('Rust native callable collection indexing requires identity analysis; analysis is incomplete')
        for origin in value:
            if origin.kind == 'parameter':
                self.emit(pos, frozenset({Origin(_CALLABLE_PARAMETER, origin.site, 'collection indexing')}))
        return value

    def supported_sink_path(self, name, pos, state, opaque_path):
        # Explicit ::std paths are native despite the shared front end's
        # conservative opaque flag for general absolute/UFCS paths.
        return self.native_callable(name, pos, state) == _COMMAND_NEW

    def sink_target(self, name, spans, chained, pos=None, state=None):
        if spans and not chained and self.native_callable(name, pos, state) == _COMMAND_NEW:
            return 0
        return None


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    seen = set()
    partial_errors = []
    suppressions = SourceSuppressions("rust")
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise OSError(f'Cannot read Rust command input {path}: {exc}') from exc
        masked = strip_comments_and_strings(text, lang="rust")
        if not re.search(r'\bCommand\b', masked) or not re.search(r'\bnew\b', masked):
            continue
        source = CommandSource(text)
        suppressions.index(path, text)
        lines = text.splitlines()
        try:
            findings = source.solve()
        except RecursionError as exc:
            raise AnalysisLimit('Rust command recursion limit exceeded; analysis is incomplete') from exc
        for site, origins in sorted(findings.items()):
            line = bisect_right(source.lines, site)
            code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            if suppressions.is_suppressed(path, line, RULE_ID):
                continue
            key = (str(path), line, code)
            if key in seen:
                continue
            seen.add(key)
            yield (path, line, 1, f'{code}  [{min(origins).label} -> command executable]')
        if source.partial_error is not None:
            partial_errors.append(f'{path}: {source.partial_error}')
    if partial_errors:
        raise AnalysisLimit('; '.join(partial_errors))


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
