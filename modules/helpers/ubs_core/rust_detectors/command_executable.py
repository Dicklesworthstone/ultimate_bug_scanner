"""Native Rust executable selection over structured local dataflow.

Environment/argument sources retain provenance through lexical bindings,
overwrites, branches, loops and selected local helper summaries. Native API
aliases are resolved separately from value names, and local namespaces stop
that resolution. The redirect engine supplies the transfer semantics; URL
guards never establish an executable allowlist.

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
from .redirect_flow import CLEAN, Flow, Origin, Source, join

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


class CommandSource(Source):
    def __init__(self, text, **kwargs):
        super().__init__(text, **kwargs)
        self.import_targets = {}
        self.extern_targets = {}
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
        return CommandFlow(self, function)

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
        findings = super().solve()
        entries = self.entry_functions()
        for function, summary in self.summaries.items():
            if function not in entries and not function.public:
                continue
            inputs = {index: name for index, names in enumerate(function.params)
                      for name in names if untrusted.search(name.lower())}
            for site, fact in summary.sinks.items():
                sources = frozenset(Origin('source', function.start, inputs[origin.site])
                                    for origin in fact if origin.kind == 'parameter' and origin.site in inputs)
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

    def call_source(self, name, pos, close, end, state, local, chained, macro, opaque_path):
        if local is not None or chained or macro:
            return CLEAN
        if self.source.native_path(name, pos, state) in _ENV_SOURCES:
            return frozenset({Origin('source', pos, ' '.join(self.source.raw[pos:close + 1].split()))})
        return CLEAN

    def value_source(self, name, pos, end, state):
        native = self.source.native_path(name, pos, state)
        if native in _ENV_SOURCES:
            return frozenset({Origin('source', pos, name)})
        if native == _COMMAND_NEW:
            raise AnalysisLimit('Rust saved command constructors require callable identity analysis; analysis is incomplete')
        return CLEAN

    def supported_sink_path(self, name, pos, state, opaque_path):
        # Explicit ::std paths are native despite the shared front end's
        # conservative opaque flag for general absolute/UFCS paths.
        return self.source.native_path(name, pos, state) == _COMMAND_NEW

    def sink_target(self, name, spans, chained, pos=None, state=None):
        if spans and not chained and self.source.native_path(name, pos, state) == _COMMAND_NEW:
            return 0
        return None


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    seen = set()
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


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
