"""Selected-input JavaScript module graph; never load or execute dependencies.

Literal relative ES-module imports and static top-level CommonJS interfaces
participate. Package imports, computed specifiers and compiler aliases remain unresolved. Resolution is
confined to selected implementations, including extension/index fallbacks and
TypeScript's emitted-extension substitution. Declaration files supply no code.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable

_AMBIGUOUS = object()
_IDENTIFIER = r'[A-Za-z_$][\w$]*'
_SPECIFIER = r'''(['"])([^'"\\\r\n]+)\1'''
_EXTENSIONS = ('.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts')
_TYPESCRIPT = frozenset(('.ts', '.tsx', '.mts', '.cts'))
_DECLARATIONS = ('.d.ts', '.d.mts', '.d.cts')
_SOURCE_EXTENSIONS = {
    '.js': ('.ts', '.tsx', '.js', '.jsx'),
    '.jsx': ('.tsx', '.ts', '.jsx', '.js'),
    '.mjs': ('.mts', '.mjs'),
    '.cjs': ('.cts', '.cjs'),
    '.ts': ('.ts', '.tsx', '.js', '.jsx'),
    '.tsx': ('.tsx', '.ts', '.jsx', '.js'),
    '.mts': ('.mts', '.mjs'),
    '.cts': ('.cts', '.cjs'),
}


@dataclass(eq=False)
class Module:
    path: Path
    text: str
    code: str = ''
    imports: dict = field(default_factory=dict)
    exports: dict = field(default_factory=dict)
    stars: list = field(default_factory=list)
    dependencies: set = field(default_factory=set)
    anonymous_default: int | None = None
    default_end: int | None = None
    start: int = 0
    end: int = 0
    root: object = None
    commonjs: str | None = None
    commonjs_exports: list = field(default_factory=list)
    commonjs_imports: list = field(default_factory=list)
    uncertain_requires: set = field(default_factory=set)
    require_specifiers: set = field(default_factory=set)

    def parse(self):
        from ubs_core.analyzers.taint_js import lexical_views, _pairs, _chunks, expression_end, _declaration_entries
        self.text, code = lexical_views(self.text)
        pairs, out = _pairs(code), list(code)
        # Import/export keywords inside expressions or function bodies are not
        # module declarations. Keep top-level offsets, not line-based guesses.
        top = list(code)
        cursor = 0
        while cursor < len(code):
            if code[cursor] in '([{' and cursor in pairs:
                stop = pairs[cursor] + 1
                top[cursor:stop] = [' '] * (stop - cursor)
                cursor = stop
            else:
                cursor += 1

        def mask(begin, end):
            out[begin:end] = ['\n' if c == '\n' else ' ' for c in code[begin:end]]

        def names(value):
            for member in value.split(','):
                match = re.fullmatch(rf'\s*({_IDENTIFIER})(?:\s+as\s+({_IDENTIFIER}))?\s*', member)
                if match:
                    yield match.group(1), match.group(2) or match.group(1)

        def import_clause(begin):
            # Consume the binding grammar, not an unbounded .*? search for
            # the next "from" somewhere later in the source file.
            cursor = begin
            while cursor < len(code) and code[cursor].isspace():
                cursor += 1
            type_only = re.match(r'type\s+(?!from\b)', code[cursor:])
            if type_only:
                cursor += type_only.end()
            first = re.match(_IDENTIFIER, code[cursor:])
            if first:
                cursor += first.end()
                while cursor < len(code) and code[cursor].isspace():
                    cursor += 1
                if code[cursor:cursor + 1] == ',':
                    cursor += 1
                    while cursor < len(code) and code[cursor].isspace():
                        cursor += 1
            if code[cursor:cursor + 1] == '{' and cursor in pairs:
                cursor = pairs[cursor] + 1
            elif code[cursor:cursor + 1] == '*':
                namespace = re.match(rf'\*\s+as\s+{_IDENTIFIER}', code[cursor:])
                if namespace is None:
                    return None
                cursor += namespace.end()
            following = re.match(r'\s*from\s*' + _SPECIFIER, self.text[cursor:])
            if following is None:
                return None
            return self.text[begin:cursor].strip(), following.group(2), cursor + following.end()

        for keyword in re.finditer(r'\b(import|export)\b', ''.join(top)):
            start = keyword.start()
            value = self.text[start:]
            if keyword.group() == 'import':
                matched = import_clause(keyword.end())
                if matched:
                    clause, spec, finish = matched
                    mask(start, finish)
                    if clause.startswith('type '):
                        continue
                    self.dependencies.add(spec)
                    default = re.match(rf'({_IDENTIFIER})(?:\s*,|\s*$)', clause)
                    if default:
                        self.imports[default.group(1)] = (spec, 'default')
                        clause = clause[default.end():].strip()
                    namespace = re.fullmatch(rf'\*\s+as\s+({_IDENTIFIER})', clause)
                    if namespace:
                        self.imports[namespace.group(1)] = (spec, '*')
                    if clause.startswith('{') and clause.endswith('}'):
                        for imported, local in names(clause[1:-1]):
                            self.imports[local] = (spec, imported)
                else:
                    side_effect = re.match(r'import\s*' + _SPECIFIER, value)
                    if side_effect:
                        self.dependencies.add(side_effect.group(2))
                        mask(start, start + side_effect.end())
                continue
            prefix = re.match(r'export\s+(default\s+)?', value)
            if prefix is None:
                continue
            begin = start + prefix.end()
            body = self.text[begin:]
            if prefix.group(1):
                function = re.match(rf'(?:async\s+)?function\s*\*?\s*({_IDENTIFIER})?\s*\(', body)
                mask(start, begin)
                if function and function.group(1):
                    self.exports['default'] = (None, function.group(1))
                else:
                    # Complete anonymous functions/arrows are matched to their
                    # lexical scope later, not treated as arbitrary clean code.
                    self.anonymous_default = begin
                    self.default_end = expression_end(code, begin)
                continue
            if body.startswith('{') and begin in pairs:
                close = pairs[begin]
                following = re.match(r'\s*from\s*' + _SPECIFIER, self.text[close + 1:])
                spec = following.group(2) if following else None
                if spec:
                    self.dependencies.add(spec)
                for local, exported in names(self.text[begin + 1:close]):
                    self.exports[exported] = (spec, local)
                mask(start, close + 1 + (following.end() if following else 0))
            elif body.startswith('*'):
                namespace = re.match(rf'''\*\s+as\s+({_IDENTIFIER})\s+from\s*(['"])([^'"\\\r\n]+)\2''', body)
                if namespace:
                    self.exports[namespace.group(1)] = (namespace.group(3), '*')
                    self.dependencies.add(namespace.group(3))
                    mask(start, begin + namespace.end())
                    continue
                star = re.match(r'\*\s+from\s*' + _SPECIFIER, body)
                if star:
                    self.stars.append(star.group(2))
                    self.dependencies.add(star.group(2))
                    mask(start, begin + star.end())
            else:
                mask(start, begin)
                function = re.match(rf'(?:async\s+)?function\s*\*?\s*({_IDENTIFIER})', body)
                if function:
                    self.exports[function.group(1)] = (None, function.group(1))
                elif re.match(r'(const|let|var)\b', body):
                    end = expression_end(code, begin)
                    for _kind, bound, _a, _b in _declaration_entries(self.text, code, begin, end):
                        for name in bound:
                            self.exports[name] = (None, name)
        self.parse_commonjs(code, ''.join(top), pairs, out)
        self.code = ''.join(out)

    def parse_commonjs(self, code, top, pairs, out):
        """Recognize bounded, unconditional CommonJS interfaces, not a loader.

        Export values are evaluated at their assignment point, unlike ESM
        live local bindings. Escaping/rebinding the exports object, conditional
        export writes and dynamic properties invalidate the interface rather
        than let a partial parse establish a clean callable summary.
        """
        from ubs_core.analyzers.taint_js import _chunks, _declaration_entries, expression_end

        def mask(begin, end):
            out[begin:end] = ['\n' if c == '\n' else ' ' for c in code[begin:end]]

        # Do not give locally replaced loader names Node's semantics. The
        # conservative whole-file test also covers callbacks shadowing require.
        replaced_loader = re.search(r'\b(?:const|let|var|function)\s+require\b|'
                                    r'(?<![\w$.])require\s*=(?!=)|'
                                    r'\([^)]*\brequire\b[^)]*\)\s*(?:=>|\{)', code)
        if not replaced_loader:
            for match in re.finditer(r'\bconst\b', top):
                begin = match.start()
                end = expression_end(code, begin)
                entries = _declaration_entries(self.text, code, begin, end)
                if len(entries) != 1 or entries[0][2] is None:
                    continue
                _, bound, rhs, _ = entries[0]
                required = re.fullmatch(r'\s*require\s*\(\s*' + _SPECIFIER +
                                        r'\s*\)\s*(?:\.\s*(' + _IDENTIFIER + r'))?\s*',
                                        self.text[rhs:end])
                if required is None:
                    continue
                spec, member = required.group(2), required.group(3)
                if not spec.startswith(('./', '../')):
                    continue
                lhs = self.text[match.end():rhs - 1].strip()
                # rhs starts after '='; trim whitespace preceding that token.
                lhs = lhs.rstrip('= \t\r\n')
                imported = {}
                if re.fullmatch(_IDENTIFIER, lhs):
                    imported[lhs] = (spec, member or '@require')
                elif lhs.startswith('{') and lhs.endswith('}') and member is None:
                    for item in lhs[1:-1].split(','):
                        if not item.strip():
                            continue
                        names = re.fullmatch(r'\s*(' + _IDENTIFIER + r')\s*(?::\s*(' +
                                             _IDENTIFIER + r')\s*)?', item)
                        if names is None:
                            imported.clear()
                            break
                        imported[names.group(2) or names.group(1)] = (spec, names.group(1))
                if not imported or set(imported) != set(bound):
                    continue
                for local in imported:
                    # Replacing the binding is outside the const-loader
                    # subset. Object property writes retain ordinary shared
                    # identity and are handled by the ordered heap engine.
                    if re.search(r'(?<![\w$.])' + re.escape(local) +
                                 r'\s*=(?!=|>)',
                                 code[end:]):
                        self.uncertain_requires.add(local)
                self.imports.update(imported)
                self.dependencies.add(spec)
                self.require_specifiers.add(spec)
                self.commonjs_imports.append((begin, end, tuple(imported)))
                mask(begin, end)

            # Even an unused literal require may participate in module
            # initialization cycles. Keep that edge without pretending to
            # model the return value of arbitrary nested require expressions.
            for match in re.finditer(r'(?<![\w$.])require\s*\(\s*' + _SPECIFIER + r'\s*\)', self.text):
                if code[match.start():match.start() + 7] != 'require':
                    continue
                if match.group(2).startswith(('./', '../')):
                    self.dependencies.add(match.group(2))
                    self.require_specifiers.add(match.group(2))

        claimed, records, exports = [], [], {}
        kind, unsupported = None, False
        base = r'(?:module\s*\.\s*exports|exports)'
        assignment = re.compile(base + r'(?:\s*\.\s*(' + _IDENTIFIER +
                                r')|\s*\[\s*([\'"])(' + _IDENTIFIER +
                                r')\2\s*\])?\s*=(?!=|>)\s*')
        for match in re.finditer(r'(?<![\w$.])(?:module|exports)\b', top):
            start = match.start()
            header = assignment.match(self.text, start)
            if header is None:
                continue
            rhs, end = header.end(), expression_end(code, header.end())
            while end > rhs and self.text[end - 1].isspace():
                end -= 1
            name = header.group(1) or header.group(3)
            whole = re.match(r'module\s*\.\s*exports\s*=', header.group()) is not None
            if not name and not whole:
                unsupported = True  # `exports = ...` detaches the alias.
                continue
            claimed.append((start, rhs))
            if name:
                if name == 'default':
                    unsupported = True  # CommonJS/ESM default interop is not inferred.
                if kind == 'value' or kind == 'object':
                    unsupported = True
                kind = kind or 'namespace'
                key = '@cjs.' + name
                exports[name] = (None, key)
                records.append((start, rhs, end, [(name, key, rhs, end)]))
            elif code[rhs:rhs + 1] == '{' and pairs.get(rhs) == end - 1:
                if records:
                    unsupported = True  # old exports aliases may be detached
                kind = 'object'
                members = []
                for left, right in _chunks(code, rhs + 1, end - 1):
                    if not self.text[left:right].strip():
                        continue
                    _, colon = next(_chunks(code, left, right, ':'))
                    key_name = self.text[left:colon].strip()
                    if re.fullmatch(_IDENTIFIER, key_name) is None:
                        unsupported = True
                        break
                    if key_name == 'default':
                        unsupported = True
                    value_start = colon + 1 if colon < right else left
                    key = '@cjs.' + key_name
                    exports[key_name] = (None, key)
                    members.append((key_name, key, value_start, right))
                records.append((start, rhs, end, members))
            else:
                if records:
                    unsupported = True
                kind = 'value'
                exports['@require'] = (None, '@cjs.value')
                records.append((start, rhs, end, [(None, '@cjs.value', rhs, end)]))
        # Any other use may mutate, replace or leak the CommonJS interface.
        # Never discard only that unsupported write and keep an old clean one.
        for match in re.finditer(r'(?<![\w$.])(?:module|exports)\b', code):
            if not any(begin <= match.start() < end for begin, end in claimed):
                unsupported = True
        if records:
            self.commonjs = 'unknown' if unsupported or self.exports or self.anonymous_default is not None else kind
            if self.commonjs != 'unknown':
                self.exports.update(exports)
                self.commonjs_exports = records


class ModuleGraph:
    def __init__(self, files: Iterable[Path]):
        self.modules = {}
        for path in sorted({Path(p).resolve() for p in files}):
            if path.suffix.lower() not in _EXTENSIONS or path.name.lower().endswith(_DECLARATIONS):
                continue
            try:
                module = Module(path, path.read_text(encoding='utf-8'))
            except (OSError, UnicodeError):
                continue
            module.parse()
            self.modules[path] = module
        self._export_cache = {}
        self.edges = {path: {target.path for spec in module.dependencies
                             if (target := self.resolve(module, spec)) is not None}
                      for path, module in self.modules.items()}
        # Node returns partially initialized exports in a require cycle. This
        # static-interface subset must not substitute an eventual clean value
        # for that earlier snapshot. Find SCCs iteratively, without a stack
        # limit on large projects, and leave cyclic CommonJS interfaces unknown.
        reverse = {path: set() for path in self.modules}
        for path, edges in self.edges.items():
            for target in edges:
                reverse[target].add(path)
        visited, finished = set(), []
        for start in self.modules:
            pending = [(start, False)]
            while pending:
                path, expanded = pending.pop()
                if expanded:
                    finished.append(path)
                elif path not in visited:
                    visited.add(path)
                    pending.append((path, True))
                    pending.extend((target, False) for target in sorted(self.edges[path], reverse=True)
                                   if target not in visited)
        assigned = set()
        for start in reversed(finished):
            if start in assigned:
                continue
            group, pending = set(), [start]
            while pending:
                path = pending.pop()
                if path in assigned:
                    continue
                assigned.add(path)
                group.add(path)
                pending.extend(reverse[path] - assigned)
            if len(group) > 1 or start in self.edges[start]:
                for path in group:
                    module = self.modules[path]
                    if module.commonjs is not None:
                        module.commonjs = 'unknown'
                        module.commonjs_exports = []

    def resolve(self, module, spec):
        if not spec.startswith(('./', '../')):
            return None
        path = module.path.parent / spec
        if path.name.lower().endswith(_DECLARATIONS):
            return None
        if module.path.suffix.lower() in _TYPESCRIPT and path.suffix in _SOURCE_EXTENSIONS:
            # A TS source commonly imports "./helper.js" before that output
            # exists. Prefer the selected implementation, not a stale emitted
            # sibling, in the same order as TypeScript extension substitution.
            # No filesystem discovery, declarations, config files or packages
            # are consulted. JS importers retain their explicit runtime file.
            for extension in _SOURCE_EXTENSIONS[path.suffix]:
                candidate = self.modules.get(path.with_suffix(extension).resolve())
                if candidate is not None:
                    return candidate
            return None
        if spec in module.require_specifiers:
            # Node's extensionless CommonJS implementation fallback is .js,
            # not an arbitrary .cjs/.mjs/TypeScript sibling. JSON, native
            # addons and package metadata are outside the selected-code model.
            # Test files before index.js and never inspect unselected paths.
            for candidate in (path, Path(str(path) + '.js'), path / 'index.js'):
                if candidate.resolve() in self.modules:
                    return self.modules[candidate.resolve()]
            return None
        candidates = [path]
        if not path.suffix:
            candidates.extend(Path(str(path) + ext) for ext in _EXTENSIONS)
            candidates.extend(path / ('index' + ext) for ext in _EXTENSIONS)
        # Do not choose an arbitrary file when an extensionless request has
        # several possible selected implementations.
        if path.resolve() in self.modules:
            return self.modules[path.resolve()]
        selected = {self.modules[p.resolve()] for p in candidates if p.resolve() in self.modules}
        return next(iter(selected)) if len(selected) == 1 else None

    def exported(self, module, name, seen=frozenset()):
        """Resolve finite binding facts without recursing through barrels.

        Each query moves from missing to one origin to ambiguous at most
        twice. Preserve ambiguity through star edges instead of treating an
        ambiguous child as absent and accidentally selecting a clean sibling.
        Parsed modules are immutable for the lifetime of this graph.
        """
        initial = (module.path, name)
        if initial in seen:
            return None
        if not seen and initial in self._export_cache:
            cached = self._export_cache[initial]
            return None if cached is _AMBIGUOUS else cached
        values, readers = {}, defaultdict(set)
        pending = [initial]
        while pending:
            query = pending.pop()
            if query in values:
                continue
            values[query] = None
            if query in seen:
                continue
            if not seen and query in self._export_cache:
                values[query] = self._export_cache[query]
                continue
            path, exported_name = query
            owner = self.modules[path]
            dependencies = []
            if owner.commonjs == 'unknown':
                continue
            if exported_name == '@require' and owner.commonjs in {'namespace', 'object'}:
                values[query] = (owner, '@namespace')
            elif exported_name == '@require' and owner.commonjs is None:
                continue  # Do not infer require/ESM runtime interoperability.
            elif exported_name == 'default' and owner.anonymous_default is not None:
                values[query] = (owner, '@default')
            elif exported_name in owner.exports:
                spec, local = owner.exports[exported_name]
                if spec is None:
                    imported = owner.imports.get(local)
                    if imported is None:
                        values[query] = (owner, local)
                        continue
                    spec, local = imported
                target = self.resolve(owner, spec)
                if target is not None:
                    if local == '*':
                        values[query] = (target, '@namespace')
                    else:
                        dependencies.append((target.path, local))
            elif exported_name != 'default':
                dependencies.extend((target.path, exported_name) for spec in owner.stars
                                    if (target := self.resolve(owner, spec)) is not None)
            for dependency in dependencies:
                readers[dependency].add(query)
                pending.append(dependency)
        queue = deque(query for query, value in values.items() if value is not None)
        while queue:
            query = queue.popleft()
            incoming = values[query]
            for parent in readers[query]:
                current = values[parent]
                if current is _AMBIGUOUS or current == incoming:
                    continue
                values[parent] = incoming if current is None else _AMBIGUOUS
                queue.append(parent)
        if not seen:
            self._export_cache.update(values)
        result = values[initial]
        return None if result is _AMBIGUOUS else result

    def components(self):
        adjacent = {path: set(edges) for path, edges in self.edges.items()}
        for path, edges in self.edges.items():
            for target in edges:
                adjacent[target].add(path)
        unseen = set(adjacent)
        while unseen:
            pending, found = [min(unseen)], set()
            while pending:
                path = pending.pop()
                if path not in found:
                    found.add(path)
                    pending.extend(adjacent[path] - found)
            unseen.difference_update(found)
            yield [self.modules[path] for path in sorted(found)]

    def cache_context(self):
        # Selection and link topology are part of cache identity. Component
        # contents are invalidated by the normal per-file cache checks.
        payload = [(str(path), sorted(map(str, targets))) for path, targets in sorted(self.edges.items())]
        return hashlib.blake2b(json.dumps(payload, separators=(',', ':')).encode(), digest_size=16).hexdigest()
