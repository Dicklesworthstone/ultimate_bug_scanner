"""Archive entry paths reaching filesystem writes through scoped Ruby flow.

Archive receiver contracts extend the shared Ruby CFG and selected-helper
summaries. Path construction is not a sink, and helper names confer no trust.
Containment describes lexical paths, not symlink or filesystem race safety.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers.taint_ruby_traversal import (
    RubyEngine, VALUE_TAGS, constant, has_shape, shape, split_tokens, tainted,
    token_text, ungroup,
)
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import CLEAN, advance, join, retag
from ubs_core.ruby_detectors._common import (
    EXTS, read_lines, ruby_files, source_line,
)

RULE_ID = "ruby.archive-extraction.path"
CATEGORY = 6
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Expand and verify archive entry paths remain under the destination "
    "before writing files"
)

ARCHIVE_HINT_RE = re.compile(
    r'\b(?:Zip::File|Zip::InputStream|Gem::Package::TarReader|'
    r'Minitar::Reader|Archive::Tar|Archive::Reader|Zlib::GzipReader)\b'
)
ARCHIVE_READERS = frozenset({
    'Zip::File', 'Gem::Package::TarReader', 'Minitar::Reader',
    'Archive::Tar', 'Archive::Reader',
})
ARCHIVE_TAG = frozenset({'archive-entry-name'})
WRITE_OPERATIONS = frozenset({
    'File.write', 'File.binwrite', 'File.open', 'File.rename', 'File.truncate',
    'IO.write', 'IO.binwrite', 'IO.open',
    'FileUtils.cp', 'FileUtils.copy', 'FileUtils.mv', 'FileUtils.move',
    'FileUtils.mkdir', 'FileUtils.mkdir_p', 'FileUtils.touch', 'Dir.mkdir',
})


class ArchiveEngine(RubyEngine):
    """Use archive identity only after ordinary selected-method resolution."""

    def __init__(self, path, text):
        super().__init__(path, text, 'path')

    def archive_source(self, token, name):
        return retag(self.source(token.start, name), add=ARCHIVE_TAG)

    def record(self, offset, value, operation=''):
        if operation not in WRITE_OPERATIONS and operation != 'archive.extract':
            return
        unsafe = frozenset(trace for trace in tainted(value)
                           if ('contained-path' not in trace.tags
                               or ('archive-parent-preparation' in trace.tags
                                   and operation != 'FileUtils.mkdir_p'))
                           and (operation == 'archive.extract' or trace.tags & ARCHIVE_TAG))
        if unsafe:
            site = (RULE_ID, offset)
            witness = advance(unsafe, self.step(offset, 'sink', operation + ' destination'))
            self.effects[site] = join(self.effects.get(site, CLEAN), witness)

    def call(self, name, receiver, arguments, token, state):
        canonical = self.constant_call(name)
        method = name.rsplit('.', 1)[-1]
        constant_receiver = '.' in name and re.fullmatch(
            r'(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*', name.rsplit('.', 1)[0])
        instances = {trace.key[0] for trace in receiver if trace.kind == 'instance'}
        selected = canonical is not None and self.candidates(
            '::' + canonical if constant_receiver else canonical, len(arguments))
        if (canonical is None or method in self.unresolved_definition_methods or selected
                or any(not function.scope and not function.singleton
                       and function.name == method and function.owner in instances
                       for function in self.parser.functions.values())):
            return super().call(name, receiver, arguments, token, state)
        self.pending_raises = join(self.pending_raises, self.exception_value(join(receiver, *arguments), '*'))
        owner = canonical.rsplit('.', 1)[0] if '.' in canonical else ''
        builtin_owner = owner in ARCHIVE_READERS or owner == 'Zip::InputStream'
        if builtin_owner and method in {'open', 'new'}:
            identity = tuple(owner.split('::'))
            if not any(identity[:length] in self.constant_definitions
                       for length in range(1, len(identity) + 1)):
                kind = 'archive-stream' if owner == 'Zip::InputStream' else 'archive-reader'
                return self.fresh(shape(kind, token.start), kind, token.start)
        if builtin_owner and method not in {'open', 'new'}:
            self.unresolved_calls.add(
                f'{self.path}:{self.step(token.start, "call", name).line}: '
                'Ruby archive API needs a supported reader contract; analysis is incomplete')
        reader = has_shape(receiver, 'archive-reader')
        stream = has_shape(receiver, 'archive-stream')
        entry = has_shape(receiver, 'archive-entry')
        if stream and method == 'get_next_entry' and not arguments:
            return self.fresh(shape('archive-entry', token.start), 'archive-entry', token.start)
        if reader and method in {'entries', 'each', 'each_entry'} and not arguments:
            return self.collection(shape('archive-entry', token.start), token.start)
        if entry and method in {'name', 'full_name', 'path', 'to_s'} and not arguments:
            return self.archive_source(token, name)
        if (reader or entry) and method == 'extract':
            destination = [argument for argument in arguments
                           if any(trace.kind == 'keyword' and trace.key == ('destination_directory',)
                                  for trace in argument)]
            positional = [argument for argument in arguments
                          if not any(trace.kind == 'keyword' for trace in argument)]
            # Rubyzip 3's explicit destination_directory API bounds the entry
            # path internally. The caller still owns the root. Without that
            # keyword, retain the legacy explicit-destination risk contract;
            # default extract() is not a new finding or a version assertion.
            if destination:
                self.record(token.start, join(*destination), 'archive.extract')
            elif len(positional) > (1 if reader else 0):
                self.record(token.start, positional[1 if reader else 0], 'archive.extract')
            return receiver
        if (reader or stream or entry) and method in {
                'read', 'close', 'closed?', 'eof?', 'directory?', 'file?', 'symlink?',
                'size', 'length', 'comment', 'rewind'}:
            return self.fresh(CLEAN, 'archive-content', token.start)
        dirname = ((canonical == 'File.dirname' and len(arguments) == 1)
                   or (method == 'dirname' and has_shape(receiver, 'pathname') and not arguments))
        if dirname:
            value = arguments[0] if canonical == 'File.dirname' else receiver
            # This is only preparation for mkdir_p, whose trusted root already
            # permits creating ancestors. Other writes must not reuse it as
            # containment: dirname(root) lies outside root. Keep the volatile
            # contained-path tag solely so ordinary value transformations
            # invalidate this private, sink-specific permission too.
            result = join(*(retag(frozenset({trace}), remove=VALUE_TAGS,
                                  add=frozenset({'contained-path', 'archive-parent-preparation'}))
                                  if 'contained-path' in trace.tags
                                  and 'archive-parent-preparation' not in trace.tags
                                  else retag(frozenset({trace}), remove=VALUE_TAGS)
                                  for trace in value))
            return self.fresh(result, 'pathname' if canonical != 'File.dirname' else 'string', token.start)
        if canonical in {'FileUtils.cp', 'FileUtils.copy'}:
            positional = [argument for argument in arguments
                          if not any(trace.kind == 'keyword' for trace in argument)]
            if len(positional) >= 2:
                self.record(token.start, positional[1], canonical)
            return self.fresh(CLEAN, 'archive-copy-result', token.start)
        if (reader or stream or entry) and method not in {'freeze', 'itself', 'dup', 'clone'}:
            self.unresolved_calls.add(
                f'{self.path}:{self.step(token.start, "call", name).line}: '
                'Ruby archive object method needs a supported value contract; analysis is incomplete')
        return super().call(name, receiver, arguments, token, state)

    def block_call(self, tokens):
        expression = ungroup(split_tokens(tokens, {'=', '+=', '-=', '||=', '&&='})[-1])
        members = split_tokens(expression, {'.', '&.'})
        if len(members) >= 2 and members[-1]:
            member = members[-1]
            receiver = expression[:len(expression) - len(member) - 1]
            if member[0].value in {'open', 'new'} and re.fullmatch(
                    r'(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*', token_text(receiver)):
                return 'archive-open', expression, expression
            if member[0].value == 'each_entry' and token_text(member[1:]) in {'', '()'}:
                return 'each', receiver, expression
        return super().block_call(tokens)

    def transfer(self, action, state):
        kind, tokens, extra = action
        if not state.get('@reachable'):
            return state
        if kind == 'block-bind':
            slot, parameters, locals_, method = extra
            value = state.get(slot + ':receiver', CLEAN)
            if method in {'each', 'map', 'collect'} and has_shape(value, 'archive-reader'):
                state = dict(state)
                entry = self.fresh(shape('archive-entry', int(slot.rsplit(':', 1)[-1])),
                                   'archive-entry', int(slot.rsplit(':', 1)[-1]))
                for index, name in enumerate(parameters):
                    state[name] = entry if index == 0 else constant('nil', 'code')
                for name in locals_:
                    state[name] = constant('nil', 'code')
                state['@result'] = constant('nil', 'code')
                return state
        return super().transfer(action, state)

    def expression(self, tokens, state, depth=0):
        # Zip::InputStream commonly advances in a while-condition assignment.
        parts = split_tokens(ungroup(tokens), {'='})
        if len(parts) == 2 and len(parts[0]) == 1 and re.fullmatch(r'[a-z_]\w*', parts[0][0].value):
            value = self.expression(parts[1], state, depth + 1)
            state[parts[0][0].value] = value
            return value
        return super().expression(tokens, state, depth)

    def proof(self, tokens, truth, state):
        tokens = ungroup(tokens)
        text = token_text(tokens)
        if truth:
            literal_prefix = re.fullmatch(
                r'([A-Za-z_]\w*)(?:\.to_s)?\.start_with\?\(.*\)', text)
            if literal_prefix and len(tokens) >= 6 and tokens[-2].kind == 'literal':
                prefix_text = tokens[-2].value
                if (prefix_text.startswith('/') and prefix_text.endswith('/')
                        and '\\' not in prefix_text
                        and all(part not in {'.', '..'} for part in prefix_text.split('/'))
                        and token_text(tokens[-3:-2]) == '('):
                    return {literal_prefix.group(1): frozenset({'contained-path'})}
            prefix = re.fullmatch(
                r'([A-Za-z_]\w*)(?:\.to_s)?\.start_with\?\('
                r'([A-Za-z_]\w*)(?:\.to_s)?\+((?:::)?File::SEPARATOR|[\'\"]/[\'\"])\)', text)
            equality = re.fullmatch(r'([A-Za-z_]\w*)(?:\.to_s)?==([A-Za-z_]\w*)(?:\.to_s)?', text)
            match = prefix or equality
            if match:
                name, base = match.group(1, 2)
                if prefix and prefix.group(3).endswith('::SEPARATOR'):
                    owner = self.constant_owner(prefix.group(3)[:-len('::SEPARATOR')],
                                                self.function.owner, self.function.lexical_owners)
                    if owner is None or self.constant_identity((*owner, 'SEPARATOR')) != ('File', 'SEPARATOR'):
                        return {}
                base_fact = state.get(base, CLEAN)
                # A caller-selected extraction root may be a parameter, but
                # an archive/request-derived root cannot prove containment.
                if has_shape(base_fact, 'canonical-path') and not tainted(base_fact):
                    return {name: frozenset({'contained-path'})}
        return super().proof(tokens, truth, state)


def flow_findings(lines, path_str):
    if not lines:
        return
    text = "\n".join(lines)
    if not ARCHIVE_HINT_RE.search(text):
        return
    suppressions = SourceSuppressions('ruby').index(path_str, text)
    engine = ArchiveEngine(path_str, text)
    for (rule, line), fact in sorted(engine.analyze().items()):
        if rule != RULE_ID or suppressions.is_suppressed(line, rule):
            continue
        evidence = min((trace.evidence for trace in fact), key=lambda steps: (len(steps), steps))
        extras = {
            'taint_path': [step.record() for step in evidence],
            'source_count': len({trace.key for trace in fact}),
            'analysis_boundary': 'Lexical archive path containment; symlink and filesystem race safety are outside this analysis.',
        }
        yield path_str, line, 1, source_line(lines, line), extras
    failures = set().union(*engine.dispatch_failures.values())
    if failures:
        raise ValueError('; '.join(sorted(failures)))


def analyze(lines, issues, path_str):
    issues.extend(flow_findings(lines, path_str))


def find(files: Sequence[Path]) -> Iterable[tuple]:
    for path in ruby_files(files, EXTS):
        lines = read_lines(path)
        if lines is None:
            continue
        yield from flow_findings(lines, str(path))
