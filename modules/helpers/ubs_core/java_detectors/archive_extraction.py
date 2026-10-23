"""Scoped Java/Kotlin archive names flowing to actual filesystem destinations.

The shared finite JVM CFG supplies local bindings, branches and selected-helper
summaries. This adapter supplies archive identities, destination-only effects and
lexical containment proofs. Filesystem races and symlink traversal are outside
that proof; unsupported syntax and escaped archive state remain incomplete.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SourceSuppressions
from ubs_core.java_detectors._common import iter_java_files, source_line
from ubs_core.analyzers import taint_java_traversal as flow
from ubs_core.taint_flow import AnalysisLimit, CLEAN, Trace, advance, join, retag
RULE_ID = "java.security.archive-extraction"
CATEGORY = 4
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
FILE_SCOPED = True
DESCRIPTION = (
    "Normalize and verify archive entry paths remain under the destination "
    "before writing files"
)

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:ZipInputStream|ZipFile|ZipEntry|JarInputStream|JarFile|JarEntry|'
    r'ZipArchiveInputStream|ZipArchiveEntry|TarArchiveInputStream|TarArchiveEntry|ArchiveEntry)\b'
    r'|java\.util\.(?:zip|jar)\.|org\.apache\.commons\.compress\.archivers',
)
SINK_RE = re.compile(
    r'\b(?:FileOutputStream|FileWriter|RandomAccessFile)\s*\('
    r'|\.(?:copy|move|write|writeString|writeBytes|writeText|appendBytes|appendText|'
    r'newOutputStream|newBufferedWriter|createDirectories|createDirectory|createFile|'
    r'mkdir|mkdirs|createNewFile)\s*\('
)
ENTRY_TYPES = frozenset({'ZipEntry', 'JarEntry', 'ZipArchiveEntry', 'TarArchiveEntry', 'ArchiveEntry'})
READER_TYPES = frozenset({'ZipFile', 'JarFile'})
STREAM_TYPES = frozenset({'ZipInputStream', 'JarInputStream', 'ZipArchiveInputStream',
                          'TarArchiveInputStream', 'ArchiveInputStream'})
KINDS = frozenset({'archive-entry', 'archive-local-entry', 'archive-stream', 'archive-reader',
                   'archive-entries', 'archive-input'})
PROOFS = flow.PATH_PROOF_TAGS | frozenset({'canonical-text', 'contained-parent'})


class ArchiveParser(flow.Parser):
    """Selected Kotlin resource/iteration blocks, retaining source offsets."""

    def statement(self, start, end):
        if self.kotlin:
            receiver = None
            sequence = re.match(r'generateSequence\s*\{', self.code[start:end])
            if sequence:
                opening = start + sequence.end() - 1
                close = self.pairs[opening]
                tail = self.skip(close + 1, end)
                each = re.match(r'\.\s*forEach\s*\{', self.code[tail:end])
                if each:
                    receiver = (opening + 1, close)
                    opening = tail + each.end() - 1
                    method = 'sequence'
            else:
                cursor = start
                while cursor < end and self.code[cursor] not in ';\r\n{':
                    if self.code[cursor] in '([':
                        cursor = self.pairs[cursor]
                    cursor += 1
                if self.code[cursor:cursor + 1] == '{':
                    prefix = re.search(r'\.\s*(use|forEach)\s*$', self.code[start:cursor])
                    if prefix:
                        receiver = (start, start + prefix.start())
                        opening, method = cursor, prefix.group(1)
            if receiver is not None:
                finish = self.pairs[opening]
                parameter = re.match(r'\s*([A-Za-z_]\w*)\s*->', self.code[opening + 1:finish])
                if parameter:
                    name = parameter.group(1)
                    position = opening + 1 + parameter.start(1)
                    body_start = opening + 1 + parameter.end()
                else:
                    name, position, body_start = 'it', opening, opening + 1
                if '@' in self.code[start:body_start]:
                    raise AnalysisLimit('Labeled archive callbacks need control-flow analysis; analysis is incomplete')
                body = self.block(body_start, finish)
                return flow.Statement(start, finish + 1, 'adapter', body,
                                      (method, name, position), receiver), finish + 1
        return super().statement(start, end)


class ArchiveEngine(flow.Engine):
    parser_type = ArchiveParser
    sink_re = SINK_RE
    sink_label = 'archive filesystem destination'
    path_constructors = False

    def __init__(self, path, text):
        self.problems = set()
        super().__init__(path, text)
        if self.parser.kotlin:
            for function in self.parser.functions.values():
                if function.key < 0:
                    continue
                opening = self.code.find('(', function.key)
                spans = self.parser.parts(opening + 1, self.parser.pairs[opening], generics=True)
                function.sources |= frozenset(name for name, (low, high) in zip(function.parameters, spans)
                                               if re.search(r'@(?:RequestParam|PathVariable|RequestHeader|RequestBody|'
                                                            r'QueryParam|PathParam|HeaderParam|FormParam)\b', self.code[low:high]))

    @staticmethod
    def data(value):
        return frozenset(trace for trace in value if trace.kind != 'shape')

    @staticmethod
    def kind(value, tag):
        return bool(value) and all(tag in trace.tags for trace in value)

    def typed(self, value, tag, offset, *, preserve=False):
        remove = KINDS | frozenset({'jvm-path', 'jvm-string'})
        remove |= frozenset(item for trace in value for item in trace.tags
                            if item.startswith(('archive-view:', 'archive-call:')))
        if not preserve:
            remove |= PROOFS
        tags = frozenset({tag, f'archive-view:{offset}'})
        data = retag(self.data(value), add=tags, remove=remove)
        return join(data, frozenset({Trace('shape', (tag, offset), tags=tags)}))

    def archive_type(self, name):
        short = name.rsplit('.', 1)[-1]
        if short not in ENTRY_TYPES | READER_TYPES | STREAM_TYPES:
            return None
        if re.search(r'\b(?:class|interface|object|enum|typealias)\s+' + re.escape(short) + r'\b', self.code):
            return None
        allowed = ('java.util.zip.', 'java.util.jar.', 'org.apache.commons.compress.archivers.')
        if '.' in name and not name.startswith(allowed):
            return None
        for match in re.finditer(r'\bimport\s+([\w.]+)(?:\s+as\s+(\w+))?', self.code):
            actual, alias = match.groups()
            if (alias or actual.rsplit('.', 1)[-1]) == short and not actual.startswith(allowed):
                return None
        return 'archive-entry' if short in ENTRY_TYPES else 'archive-reader' if short in READER_TYPES else 'archive-stream'

    def parameter_tags(self, declaration):
        raw = re.sub(r'<[^<>]*>', '', declaration).strip()
        match = (re.fullmatch(r'[A-Za-z_]\w*\s*:\s*([\w.]+)\s*\??', raw) if self.parser.kotlin else
                 re.fullmatch(r'(?:final\s+)?([\w.]+)\s+[A-Za-z_]\w*', raw))
        tag = self.archive_type(match.group(1)) if match else None
        return frozenset({tag}) if tag else super().parameter_tags(declaration)

    def source(self, offset, label):
        return retag(super().source(offset, label), add=frozenset({'archive-request'}))

    def entry_name(self, receiver, offset, label):
        if self.kind(receiver, 'archive-local-entry'):
            return retag(self.data(receiver), add=frozenset({'archive-name', 'jvm-string'}), remove=KINDS | PROOFS)
        return frozenset({Trace('source', (str(self.path), offset, label),
                               tags=frozenset({'archive-name', 'jvm-string'}),
                               evidence=(self.step(offset, 'source', label),))})

    def path_value(self, value, offset, *, preserve=False):
        return self.typed(value, 'jvm-path', offset, preserve=preserve)

    def joined_path(self, receiver, arguments):
        result = retag(receiver, add=frozenset({'archive-root'}), remove=PROOFS)
        for index, argument in enumerate(arguments):
            remove = PROOFS - flow.BASENAME_TAGS if index == len(arguments) - 1 else PROOFS
            tags = frozenset({'archive-root'}) if index < len(arguments) - 1 else frozenset()
            result = join(result, retag(argument, add=tags, remove=remove))
        return retag(result, add=frozenset({'jvm-path'}), remove=frozenset({'jvm-string'}))

    def operation(self, method, receiver, arguments, offset):
        arguments = arguments or []
        if self.kind(receiver, 'archive-entry') or self.kind(receiver, 'archive-local-entry'):
            if method in {'getName', 'getPath', 'name', 'path'} and not arguments:
                return self.entry_name(receiver, offset, method)
            if method in {'isDirectory', 'directory', 'getSize', 'size', 'getTime', 'getCrc'}:
                return CLEAN
        if self.kind(receiver, 'archive-stream') and method in {'getNextEntry', 'getNextJarEntry',
                'getNextZipEntry', 'getNextTarEntry', 'nextEntry', 'nextJarEntry', 'nextZipEntry', 'nextTarEntry'}:
            return self.typed(CLEAN, 'archive-entry', offset)
        if self.kind(receiver, 'archive-reader'):
            if method in {'entries', 'stream', 'getEntries', 'getEntriesInPhysicalOrder'} and not arguments:
                return self.typed(CLEAN, 'archive-entries', offset)
            if method in {'getEntry', 'getJarEntry'}:
                return self.typed(CLEAN, 'archive-entry', offset)
            if method == 'getInputStream':
                return self.typed(CLEAN, 'archive-input', offset)
        if self.kind(receiver, 'archive-entries'):
            if method in {'nextElement', 'next'}:
                return self.typed(CLEAN, 'archive-entry', offset)
            if method in {'asSequence', 'asIterator', 'iterator', 'enumeration'}:
                return receiver
            if method in {'hasMoreElements', 'hasNext'}:
                return CLEAN
        if self.kind(receiver, 'jvm-path'):
            if method in {'resolve', 'resolveSibling'} and len(arguments) == 1:
                return self.path_value(self.joined_path(receiver, arguments), offset, preserve=True)
            if method in {'normalize', 'toRealPath', 'getCanonicalFile', 'canonicalFile'} and not arguments:
                result = self.path_value(receiver, offset, preserve=True)
                return retag(result, add=frozenset({'canonical-path'}),
                             remove=flow.BASENAME_TAGS if method != 'normalize' else frozenset())
            if method in {'toPath', 'toFile'} and not arguments:
                return receiver
            if method in {'toAbsolutePath', 'getAbsoluteFile', 'absoluteFile'} and not arguments:
                return self.path_value(retag(receiver, remove=PROOFS), offset)
            if method in {'getFileName', 'fileName', 'getName', 'name'} and not arguments:
                kind = 'jvm-string' if method in {'getName', 'name'} else 'jvm-path'
                return retag(self.typed(receiver, kind, offset), add=frozenset({'basename-path'}))
            if method in {'getParent', 'getParentFile', 'parent', 'parentFile'} and not arguments:
                return join(*(retag(frozenset({trace}), add=frozenset({'contained-parent'}), remove=PROOFS)
                              if 'contained-path' in trace.tags else retag(frozenset({trace}), remove=PROOFS)
                              for trace in receiver))
            if method in {'toString', 'getCanonicalPath', 'canonicalPath', 'getPath', 'path'} and not arguments:
                canonical = method in {'getCanonicalPath', 'canonicalPath'} or self.kind(receiver, 'canonical-path')
                result = self.typed(receiver, 'jvm-string', offset, preserve=True)
                return retag(result, add=frozenset({'canonical-text'}) if canonical else frozenset(),
                             remove=frozenset({'canonical-path'}))
            if method in {'mkdirs', 'mkdir', 'createNewFile', 'writeText', 'writeBytes', 'appendText', 'appendBytes'}:
                self.record(offset, receiver, file_leaf=method not in {'mkdir', 'mkdirs'},
                            parent=method == 'mkdirs')
                return CLEAN
            if method in {'startsWith', 'endsWith', 'isAbsolute', 'exists', 'isDirectory', 'isFile'}:
                return CLEAN
        if any(trace.tags & KINDS for trace in receiver):
            if method in {'close', 'closeEntry', 'read', 'readBytes', 'readAllBytes', 'readNBytes',
                          'transferTo', 'available', 'skip'}:
                return CLEAN
            self.problems.add(f'{self.step(offset, "call", method).line}: unsupported archive operation {method}')
        return None

    def external_call(self, name, arguments, value, offset, bindings, state):
        root, _, method = name.rpartition('.')
        tag = self.archive_type(name)
        if tag and not self.call_is_shadowed(name.split('.')[0], bindings):
            return self.typed(join(*arguments) if tag == 'archive-entry' else CLEAN,
                              'archive-local-entry' if tag == 'archive-entry' else tag, offset)
        if name in {'File', 'Path.of', 'Paths.get', 'java.io.File', 'java.nio.file.Path.of', 'java.nio.file.Paths.get'}:
            short = name.removeprefix('java.io.').removeprefix('java.nio.file.').split('.')[0]
            if self.builtin_type(short) and not self.call_is_shadowed(name.split('.')[0], bindings):
                joined = self.joined_path(CLEAN, arguments) if len(arguments) > 1 else join(*arguments)
                return self.path_value(joined, offset, preserve=len(arguments) > 1)
        receiver = state.get(bindings.get(root, root), CLEAN)
        if root:
            result = self.operation(method, receiver, arguments, offset)
            if result is not None:
                return result
        if self.files_call(name, bindings) and arguments:
            if method in {'copy', 'move'}:
                return arguments[1] if len(arguments) > 1 else CLEAN
            if method in {'write', 'writeString', 'createFile', 'createDirectory', 'createDirectories'}:
                return arguments[0]
            if method in {'newOutputStream', 'newBufferedWriter'}:
                return self.typed(CLEAN, 'archive-input', offset)
        if method in {'FileOutputStream', 'FileWriter', 'RandomAccessFile'}:
            return self.typed(CLEAN, 'archive-input', offset)
        if any(trace.tags & KINDS for trace in value):
            self.problems.add(f'{self.step(offset, "call", name).line}: archive state escapes through {name}')
        return retag(self.data(value), remove=PROOFS | frozenset({'jvm-path', 'jvm-string'}))

    def member_value(self, name, value, offset, arguments=None, direct_call=False, receiver=CLEAN):
        if direct_call:
            return value
        result = self.operation(name, receiver if receiver else value, arguments, offset)
        return result if result is not None else retag(self.data(value), remove=PROOFS | frozenset({'jvm-path'}))

    def call_sink(self, name, call, value, offset, bindings):
        args = call.values
        method = name.rsplit('.', 1)[-1]
        if self.files_call(name, bindings) and args:
            index = 1 if method in {'copy', 'move'} else 0
            if method in {'copy', 'move', 'write', 'writeString', 'newOutputStream', 'newBufferedWriter',
                          'createFile', 'createDirectory', 'createDirectories'} and index < len(args):
                self.record(offset, args[index], file_leaf=method not in {'move', 'createDirectory', 'createDirectories'},
                            parent=method == 'createDirectories')
        elif method in {'FileOutputStream', 'FileWriter', 'RandomAccessFile'} and args:
            owner = name.rpartition('.')[0]
            if ((owner == 'java.io' and not self.call_is_shadowed('java', bindings)) or
                    (not owner and self.builtin_type(method) and not self.call_is_shadowed(method, bindings))):
                if method == 'RandomAccessFile' and len(call.spans) > 1:
                    mode = self.text[slice(*call.spans[1])].strip()
                    if mode == '"r"':
                        return False
                self.record(offset, args[0], file_leaf=True)
        return False

    def record(self, offset, value, file_leaf=False, parent=False):
        value = self.data(value)
        if file_leaf:
            value = retag(value, add=frozenset({'file-leaf-sink'}))
        if parent:
            value = retag(value, add=frozenset({'archive-parent-preparation'}))
        if value:
            self.effects[offset] = join(self.effects.get(offset, CLEAN), advance(value, self.step(offset, 'sink', self.sink_label)))

    def summary_effect(self, summary, fact):
        # A root parameter may become request-derived only at the caller.
        # Retain it until substitution instead of discharging a helper early.
        return fact

    def summary_return(self, fact, offset):
        return join(*(retag(frozenset({trace}), add=frozenset({f'archive-call:{offset}'}))
                      if any(tag.startswith('archive-view:') for tag in trace.tags)
                      else frozenset({trace}) for trace in fact))

    @staticmethod
    def views(value):
        return {frozenset(tag for tag in trace.tags if tag.startswith(('archive-view:', 'archive-call:')))
                for trace in value}

    def unchanged_alias(self, selected, other, bindings):
        positions = []
        names = []
        for name, binding in bindings.items():
            if binding not in {selected, other}:
                continue
            if '@' not in binding:
                return False
            names.append(name)
            positions.append(int(binding.rsplit('@', 1)[1]))
        if len(positions) != 2 or not hasattr(self, 'guard_offset'):
            return False
        beginning = self.parser.end_statement(max(positions), self.function.end)
        if beginning >= self.guard_offset:
            return False
        window = self.code[beginning:self.guard_offset]
        return not re.search(r'\b(?:' + '|'.join(map(re.escape, names)) + r')\s*(?:\+?=)(?!=)', window)

    def guard_facts(self, span):
        raw = self.text[slice(*span)].strip()
        string = re.fullmatch(r'([A-Za-z_]\w*)\.startsWith\(\s*([A-Za-z_]\w*)\s*\+\s*File\.separator(?:Char)?\s*\)', raw)
        if string and self.builtin_type('File'):
            return [(True, ('archive-string', *string.groups()))]
        literal = re.fullmatch(r'([A-Za-z_]\w*)\.startsWith\(\s*"(/[^"\\]*?/)"\s*\)', raw)
        if literal:
            return [(True, ('archive-literal', literal.group(1)))]
        return super().guard_facts(span)

    def apply_guard(self, guard, state, bindings):
        if guard[0] == 'basename':
            return super().apply_guard(guard, state, bindings)
        if guard[0] in {'archive-string', 'archive-literal'}:
            name, canonical = guard[1], False
            root = guard[2] if len(guard) == 3 else None
            expected = 'canonical-text'
        else:
            name, canonical, root = guard
            expected = 'canonical-path'
        binding = bindings.get(name, name)
        original = state.get(binding, CLEAN)
        root_fact = state.get(bindings.get(root, root), CLEAN) if root else CLEAN
        if expected == 'canonical-path' and not self.kind(original, 'jvm-path'):
            return state
        if root and expected == 'canonical-path' and not self.kind(root_fact, 'jvm-path'):
            return state
        dependencies = retag(self.data(root_fact), add=frozenset({'archive-root'}))
        identity = self.views(original)
        for target, value in list(state.items()):
            same_alias = (target != binding and len(identity) == 1 and all(identity)
                          and self.views(value) == identity
                          and self.unchanged_alias(binding, target, bindings))
            if target != binding and not same_alias:
                continue
            state[target] = join(dependencies, *(retag(frozenset({trace}),
                                  add=frozenset({'contained-path'}), remove=frozenset({'archive-root'}))
                                  if expected in trace.tags or canonical and 'jvm-path' in trace.tags else frozenset({trace})
                                  for trace in value))
        return state

    def adapter_graph(self, statement, following, bindings, reads, node, block, edges,
                      break_to, continue_to, unwind):
        method, name, position = statement.otherwise
        local = dict(bindings)
        local[name] = f'{name}@{position}'
        if method == 'use':
            body = block(statement.body, following, local, break_to, continue_to, unwind)
            return node('archive-bind', statement.header, local, (body,), (method, name), reads=reads)
        test = node('eval', (statement.start, statement.start), local)
        body = block(statement.body, test, local, break_to, (test, len(unwind)), unwind)
        bind = node('archive-bind', statement.header, local, (body,), (method, name), reads=reads)
        edges[test] = tuple(target for target in (bind, following) if target is not None)
        return test

    def transfer(self, action, state):
        kind, span, bindings, guard, reads = action
        if kind == 'guard':
            self.guard_offset = span[0]
        if kind == 'archive-bind':
            method, name = guard
            value = self.expression(*span, state, reads)
            if method == 'use':
                if not any(trace.tags & KINDS for trace in value):
                    raise AnalysisLimit('Unknown Kotlin archive resource callback; analysis is incomplete')
            elif method == 'sequence' and self.kind(value, 'archive-entry'):
                pass
            elif method == 'forEach' and self.kind(value, 'archive-entries'):
                value = self.typed(CLEAN, 'archive-entry', span[0])
            else:
                raise AnalysisLimit('Unknown Kotlin archive iteration callback; analysis is incomplete')
            state[bindings[name]] = advance(value, self.step(span[0], 'assign', name))
            return state
        if kind == 'element':
            value = self.expression(*span, state, bindings)
            if self.kind(value, 'archive-entries'):
                state[bindings[guard]] = self.typed(CLEAN, 'archive-entry', span[0])
                return state
        return super().transfer(action, state)

    def expression(self, start, end, state, bindings, depth=0):
        assignment = self.assignment((start, end))
        if assignment and not assignment[-1] and assignment[4] == '=':
            name, offset, low, high, _, _ = assignment
            fact = self.expression(low, high, state, bindings, depth + 1)
            state[bindings.get(name, name)] = advance(fact, self.step(offset, 'assign', name))
            return fact
        return super().expression(start, end, state, bindings, depth)

    def analyze(self):
        effects = super().analyze()
        for summary in self.summaries.values():
            for offset, fact in summary.escapes.items():
                if any(trace.tags & KINDS for trace in fact):
                    self.problems.add(f'{self.step(offset, "escape", "archive state").line}: archive state needs heap analysis')
        result = {}
        for line, fact in effects.items():
            untrusted_root = any('archive-root' in trace.tags for trace in fact)
            unsafe = frozenset(trace for trace in fact if 'archive-name' in trace.tags and (
                untrusted_root or not (self.safe_sink_trace(trace) or
                                      {'contained-parent', 'archive-parent-preparation'} <= trace.tags)))
            if unsafe:
                result[line] = unsafe
        return result


def analyze(path: Path, issues, *, suppressions: SourceSuppressions, rule_id: str):
    text = path.read_text(encoding='utf-8')
    if not ARCHIVE_HINT_RE.search(text) or not SINK_RE.search(text):
        return
    suppression = suppressions.index(path, text)
    lines = text.splitlines()
    engine = ArchiveEngine(path, text)
    for line, fact in sorted(engine.analyze().items()):
        if suppression.is_suppressed(line, rule_id):
            continue
        witness = min(fact, key=lambda trace: (len(trace.evidence), trace.evidence))
        route = ' -> '.join(step.label for step in witness.evidence)
        issues.append((path, line, f'{source_line(lines, line)}  [{route}]'))
    if engine.problems:
        raise AnalysisLimit('Archive analysis is incomplete: ' + '; '.join(sorted(engine.problems)))


def find(files: Sequence[Path], *, language: str = 'java', rule_id: str = RULE_ID) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions(language)
    errors = []
    for path in iter_java_files(files):
        issues: list[tuple[Path, int, str]] = []
        try:
            analyze(path, issues, suppressions=suppressions, rule_id=rule_id)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f'{path}: {error}')
        for item, line_no, detail in issues:
            yield item, line_no, 1, detail
    if errors:
        raise AnalysisLimit('Archive analysis is incomplete: ' + '; '.join(errors))
