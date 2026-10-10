"""Dependency-tree observation and watch invalidation, using real files and sockets."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from test_daemon_selection import ROOT, SelectionFixture, daemon
from test_daemon_watch import WatchFixture

# Protocol double. The dependency affects the result but is NOT a scan target.
DEPENDENCY_SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
files = args[args.index('--') + 1:]
records = [(name, pathlib.Path(name).read_text()) for name in files]
policy = pathlib.Path('dependency/policy')
text = policy.read_text() if policy.is_file() else ''
with open(os.environ['SCAN_COUNT'], 'a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'records': records, 'policy': text}) + '\n')
if 'SLOW' in text:
    time.sleep(30)
print(json.dumps({'files': records, 'args': args, 'policy': text}))
print('dependency scanner diagnostic', file=sys.stderr)
sys.exit(1 if 'BUG' in text else 0)
'''

# Directory selection / simple ignore-policy protocol double, not UBS rules.
DIRECTORY_SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
targets = args[args.index('--') + 1:]
root = pathlib.Path.cwd()
ignore = root / '.ubsignore'
excluded = set(ignore.read_text().splitlines()) if ignore.is_file() else set()
records = []
for target in targets:
    for path in sorted(pathlib.Path(target).rglob('*.py')):
        relative = path.relative_to(root).as_posix()
        if relative not in excluded:
            records.append((relative, path.read_text()))
with open(os.environ['SCAN_COUNT'], 'a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'records': records}) + '\n')
if any('SLOW' in text for _, text in records):
    time.sleep(30)
print(json.dumps({'files': records, 'args': args}))
print('directory scanner diagnostic', file=sys.stderr)
sys.exit(3 if not records else 1 if any('BUG' in text for _, text in records) else 0)
'''


@unittest.skipUnless(os.name == 'posix', 'descriptor-relative traversal requires POSIX')
class InputObservationTests(SelectionFixture, unittest.TestCase):
    def observe(self, *dependencies):
        return daemon.watch_inputs(self.root, ['a.py'], dependencies=dependencies)

    def test_dependency_changes_fingerprint_without_source_change(self):
        dependency = self.root / 'policy'
        dependency.write_text('allow')
        first, errors = self.observe('policy')
        self.assertEqual(errors, [])
        self.assertEqual(first, self.observe('policy')[0])
        before = self.source.read_bytes()
        dependency.write_text('deny!')
        self.assertNotEqual(first, self.observe('policy')[0])
        self.assertEqual(self.source.read_bytes(), before)

    def test_absent_policy_creation_and_removal_are_valid_distinct_states(self):
        missing, errors = self.observe('.ubsignore')
        self.assertEqual(errors, [])
        policy = self.root / '.ubsignore'
        policy.write_text('*.py\n')
        present, errors = self.observe('.ubsignore')
        self.assertEqual(errors, [])
        self.assertNotEqual(missing, present)
        policy.rename(self.work / 'old-ignore')
        absent, errors = self.observe('.ubsignore')
        self.assertEqual(errors, [])
        self.assertEqual(absent, missing)

    def test_recursive_add_rename_remove_and_hidden_files(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        stamps = [self.observe('dependency')[0]]
        nested = tree / 'nested'
        nested.mkdir()
        hidden = nested / '.policy'
        hidden.write_text('one')
        stamps.append(self.observe('dependency')[0])
        hidden.write_text('two')
        stamps.append(self.observe('dependency')[0])
        hidden.rename(nested / 'new-policy')
        stamps.append(self.observe('dependency')[0])
        nested.rename(self.work / 'removed')
        stamps.append(self.observe('dependency')[0])
        self.assertEqual(len(set(stamps)), len(stamps))
        self.assertEqual(self.observe('dependency')[1], [])

    def test_same_size_and_restored_mtime_dependency_edit_is_seen(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        source = tree / 'lib.py'
        source.write_text('AAAA')
        before, errors = self.observe('dependency')
        self.assertEqual(errors, [])
        old = source.stat()
        source.write_text('BBBB')
        os.utime(source, ns=(old.st_atime_ns, old.st_mtime_ns))
        after, errors = self.observe('dependency')
        self.assertEqual(errors, [])
        self.assertNotEqual(before, after)

    def test_internal_symlink_graph_is_finite_and_retargets_invalidate(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        (tree / 'lib').write_text('one')
        (tree / 'back').symlink_to(tree, target_is_directory=True)
        alias = self.root / 'alias'
        alias.symlink_to(tree, target_is_directory=True)
        first, errors = self.observe('dependency', 'alias')
        self.assertEqual(errors, [])
        self.assertEqual(first, self.observe('dependency', 'alias')[0])
        second = self.root / 'other'
        second.mkdir()
        (second / 'lib').write_text('two')
        alias.rename(self.work / 'old-alias')
        alias.symlink_to(second, target_is_directory=True)
        after, errors = self.observe('dependency', 'alias')
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)

    def test_escaping_symlink_fifo_and_broken_link_invalidate_graph(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        outside = self.work / 'private'
        outside.write_text('do not read this')
        (tree / 'escape').symlink_to(outside)
        _, errors = self.observe('dependency')
        self.assertTrue(any('outside' in error for error in errors), errors)
        self.assertNotIn('do not read this', '\n'.join(errors))
        (tree / 'escape').rename(self.work / 'removed-link')
        os.mkfifo(tree / 'fifo')
        _, errors = self.observe('dependency')
        self.assertTrue(any('not a regular file' in error for error in errors), errors)
        (tree / 'fifo').rename(self.work / 'removed-fifo')
        (tree / 'broken').symlink_to('missing')
        self.assertTrue(self.observe('dependency')[1])

    def test_byte_budget_is_global_and_aliases_do_not_reread_contents(self):
        dependency = self.root / 'data'
        dependency.write_bytes(b'1234')
        (self.root / 'alias').symlink_to(dependency)
        with patch.object(daemon, 'MAX_SNAPSHOT', len(self.source.read_bytes()) + 4):
            self.assertEqual(self.observe('data', 'alias')[1], [])
        with patch.object(daemon, 'MAX_SNAPSHOT', len(self.source.read_bytes()) + 3):
            _, errors = self.observe('data')
        self.assertTrue(any('byte limit' in error for error in errors), errors)

    def test_directory_enumeration_has_an_entry_budget(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        for index in range(20):
            (tree / str(index)).write_text('')
        with patch.object(daemon, 'MAX_SNAPSHOT_ENTRIES', 5):
            _, errors = self.observe('dependency')
        self.assertTrue(any('entry limit' in error for error in errors), errors)
        self.assertEqual(self.observe('dependency')[1], [])

    def test_required_sources_never_become_optional_dependency_entries(self):
        self.source.rename(self.work / 'gone.py')
        _, errors = self.observe('a.py')
        self.assertTrue(errors)
        self.assertEqual(daemon.watch_inputs(self.root, [], dependencies=('a.py',))[1], [])
        self.source.mkdir()
        self.assertTrue(self.observe('a.py')[1])

    def test_final_pass_detects_an_already_read_file_changing(self):
        trigger = self.root / 'trigger'
        trigger.write_text('trigger')
        read = os.read
        changed = False
        def edit_after_read(fd, length):
            nonlocal changed
            data = read(fd, length)
            if data == b'trigger' and not changed:
                changed = True
                self.source.write_text('new source\n')
            return data
        with patch.object(daemon.os, 'read', side_effect=edit_after_read):
            _, errors = self.observe('trigger')
        self.assertTrue(changed)
        self.assertTrue(any('during observation' in error for error in errors), errors)
        self.assertEqual(self.observe('trigger')[1], [])

    def test_later_source_open_cannot_hide_an_earlier_source_edit(self):
        trigger = self.root / 'trigger'
        trigger.write_text('second source')
        open_ = os.open
        edited = False
        def edit_on_open(path, flags, *args, **kwargs):
            nonlocal edited
            if os.fspath(path).split('/')[-1] == 'trigger' and not edited:
                edited = True
                self.source.write_text('changed after its own verification')
            return open_(path, flags, *args, **kwargs)
        with patch.object(daemon.os, 'open', side_effect=edit_on_open):
            _, errors = daemon.watch_inputs(self.root, ['a.py', 'trigger'])
        self.assertTrue(edited)
        self.assertTrue(errors, 'mixed-generation input was accepted as a stable observation')

    def test_parent_swap_cannot_redirect_open_to_external_bytes(self):
        tree = self.root / 'dependency'
        tree.mkdir()
        (tree / 'lib').write_text('inside')
        outside = self.work / 'external'
        outside.mkdir()
        (outside / 'lib').write_text('PRIVATE')
        open_ = os.open
        read = os.read
        reads = []
        swapped = False
        def swap(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == 'dependency' and flags & os.O_DIRECTORY and not swapped:
                swapped = True
                tree.rename(self.root / 'previous')
                tree.symlink_to(outside, target_is_directory=True)
            return open_(path, flags, *args, **kwargs)
        def record_read(fd, length):
            data = read(fd, length)
            reads.append(data)
            return data
        with patch.object(daemon.os, 'open', side_effect=swap), patch.object(daemon.os, 'read', side_effect=record_read):
            _, errors = self.observe('dependency/lib')
        self.assertTrue(swapped)
        self.assertTrue(errors)
        self.assertNotIn(b'PRIVATE', b''.join(reads))

    def test_input_limit_and_invalid_paths_are_rejected(self):
        for dependencies in (('policy',) * 257, ('',), ('\0',)):
            with self.subTest(dependencies=dependencies[:2]), self.assertRaises(daemon.ServiceError):
                self.observe(*dependencies)
        self.assertTrue(self.observe('../outside')[1])

    def test_required_directory_cannot_disappear_or_become_a_file(self):
        tree = self.root / 'src'
        tree.mkdir()
        def observe():
            return daemon.watch_inputs(self.root, [], directories=('.', 'src'))
        self.assertEqual(observe()[1], [])
        tree.rename(self.work / 'old-src')
        self.assertTrue(observe()[1])
        tree.write_text('now a file')
        self.assertTrue(any('no longer a directory' in error for error in observe()[1]))

    def test_project_observation_includes_git_metadata(self):
        self.init_git()
        first, errors = daemon.watch_inputs(self.root, [], directories=('.',))
        self.assertEqual(errors, [])
        # Only Git metadata changes: no source edit is needed for invalidation.
        self.git('config', 'core.excludesFile', 'different-policy')
        after, errors = daemon.watch_inputs(self.root, [], directories=('.',))
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)


@unittest.skipUnless(os.name == 'posix', 'watch uses Unix service')
class DependencyWatchTests(WatchFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.scanner.write_text(DEPENDENCY_SCANNER)
        self.tree = self.root / 'dependency'
        self.tree.mkdir()
        self.policy = self.tree / 'policy'
        self.policy.write_text('allow')

    def test_dependency_rescans_without_becoming_a_scan_target(self):
        self.start()
        self.start_watch('--watch-input=dependency', '--profile=strict')
        first = self.event('result')
        self.policy.write_text('BUG denied')
        latest = self.event('result')
        self.assertEqual(first['exit_code'], 0)
        self.assertEqual(latest['exit_code'], 1)
        self.assertGreater(latest['generation'], first['generation'])
        self.assertEqual(latest['watch_inputs'], ['.ubs.json', 'dependency'])
        report = json.loads(latest['stdout'])
        self.assertEqual([item[0] for item in report['files']], [str(self.source)])
        self.assertIn('--profile=strict', report['args'])
        self.assertNotIn('--watch-input=dependency', report['args'])
        self.assertEqual(self.source.read_text(), 'clean\n')
        self.assertEqual(len(self.calls()), 2)

    def test_policy_creation_removal_and_nested_addition_trigger_rescans(self):
        self.start()
        self.start_watch('--watch-input=.ubsignore', '--watch-input=dependency')
        initial = self.event('result')
        policy = self.root / '.ubsignore'
        policy.write_text('ignored/\n')
        created = self.event('result')
        policy.rename(self.work / 'old-ignore')
        removed = self.event('result')
        nested = self.tree / 'nested'
        nested.mkdir()
        (nested / '.config').write_text('new dependency')
        latest = self.event('result')
        self.assertEqual(latest['exit_code'], 0)
        self.assertEqual(len({item['generation'] for item in (initial, created, removed, latest)}), 4)
        # Removing the optional file can restore the exact original snapshot.
        # Its cached result is valid; it must still be delivered as a NEW
        # generation. Creation and nested addition must run fresh scans.
        self.assertFalse(created['cached'])
        self.assertFalse(latest['cached'])
        self.assertEqual(len(self.calls()), 3 if removed['cached'] else 4)
        self.assertFalse(any(item['event'] == 'invalid' for item in self.events))

    def test_dependency_edit_cancels_an_obsolete_scan(self):
        self.policy.write_text('SLOW')
        self.start()
        self.start_watch('--watch-input=dependency')
        old = self.event('scanning')
        calls = self.await_calls(1)
        self.policy.write_text('BUG current')
        latest = self.event('result', timeout=8)
        self.assertEqual(latest['exit_code'], 1)
        self.assertGreater(latest['generation'], old['generation'])
        self.assertEqual([item['generation'] for item in self.events if item['event'] == 'result'], [latest['generation']])
        with self.assertRaises(ProcessLookupError):
            os.kill(calls[0]['pid'], 0)

    def test_invalid_dependency_suspends_scans_and_repair_resumes(self):
        self.start()
        self.start_watch('--watch-input=dependency')
        self.event('result')
        os.mkfifo(self.tree / 'pipe')
        invalid = self.event('invalid')
        self.assertEqual(invalid['exit_code'], 2)
        self.assertEqual(len(self.calls()), 1)
        (self.tree / 'pipe').rename(self.work / 'old-pipe')
        self.policy.write_text('BUG')
        self.assertEqual(self.event('result')['exit_code'], 1)
        self.assertEqual(len(self.calls()), 2)

    def test_cli_rejects_external_inputs_and_non_watch_use(self):
        for command in ('client', 'serve', 'status', 'stop'):
            result = self.cli(command, '--watch-input=dependency')
            self.assertEqual(result.returncode, 2, result.stderr)
        for value in ('../external', ''):
            result = self.cli('watch', 'a.py', '--watch-input=' + value)
            self.assertEqual(result.returncode, 2, result.stderr)
        (self.tree / 'loop').symlink_to('loop')
        result = self.cli('watch', 'a.py', '--watch-input=dependency/loop')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(os.name == 'posix', 'watch uses Unix service')
class DirectoryWatchTests(WatchFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.scanner.write_text(DIRECTORY_SCANNER)
        self.tree = self.root / 'src'
        self.tree.mkdir()

    def test_added_renamed_and_removed_sources_are_rediscovered(self):
        self.start()
        self.start_watch(files=['.'])
        initial = self.event('result')
        self.assertEqual(initial['exit_code'], 0)
        source = self.tree / 'new.py'
        source.write_text('BUG')
        added = self.event('result')
        self.assertEqual(added['exit_code'], 1)
        self.assertEqual(added['selection'], 'directory')
        self.assertEqual(added['watch_inputs'], ['.'])
        source.rename(self.tree / 'renamed.py')
        renamed = self.event('result')
        self.assertIn(['src/renamed.py', 'BUG'], json.loads(renamed['stdout'])['files'])
        self.tree.rename(self.work / 'removed-src')
        removed = self.event('result')
        self.assertEqual(removed['exit_code'], 0)
        self.assertEqual(json.loads(removed['stdout'])['files'], [['a.py', 'clean\n']])
        self.assertEqual(len(self.calls()), 4)
        self.assertFalse(any(item.get('cached') for item in (initial, added, renamed, removed)))

    def test_sibling_and_root_policy_edits_trigger_without_expanding_scope(self):
        (self.tree / 'target.py').write_text('BUG')
        self.source.write_text('BUG outside scan directory')
        self.start()
        self.start_watch(files=['src'])
        self.assertEqual(self.event('result')['exit_code'], 1)
        (self.root / '.ubsignore').write_text('src/target.py\n')
        ignored = self.event('result')
        self.assertEqual(ignored['exit_code'], 3)
        report = json.loads(ignored['stdout'])
        self.assertEqual(report['args'][-2:], ['--', str(self.tree)])
        self.assertEqual(report['files'], [])
        self.source.write_text('changed sibling dependency')
        sibling = self.event('result')
        self.assertEqual(sibling['exit_code'], 3)
        self.assertEqual(sibling['paths'], ['src'])
        self.assertEqual(json.loads(sibling['stdout'])['files'], [])
        self.assertEqual(len(self.calls()), 3)

    def test_empty_directory_stays_watched_until_source_is_added(self):
        self.start()
        self.start_watch(files=['src'])
        empty = self.event('result')
        self.assertEqual(empty['exit_code'], 3)
        (self.tree / 'new.py').write_text('BUG')
        added = self.event('result')
        self.assertEqual(added['exit_code'], 1)
        self.assertGreater(added['generation'], empty['generation'])

    def test_missing_directory_invalidates_then_recreation_resumes(self):
        (self.tree / 'target.py').write_text('clean')
        self.start()
        self.start_watch(files=['src'])
        self.assertEqual(self.event('result')['exit_code'], 0)
        self.tree.rename(self.work / 'old-src')
        invalid = self.event('invalid')
        self.assertEqual(invalid['exit_code'], 2)
        self.assertEqual(len(self.calls()), 1)
        self.tree.mkdir()
        (self.tree / 'new.py').write_text('BUG')
        self.assertEqual(self.event('result')['exit_code'], 1)

    def test_obsolete_directory_scan_is_cancelled_for_new_inventory(self):
        source = self.tree / 'slow.py'
        source.write_text('SLOW')
        self.start()
        self.start_watch(files=['src'])
        self.event('scanning')
        old = self.await_calls(1)[0]
        source.rename(self.work / 'removed-slow.py')
        (self.tree / 'new.py').write_text('BUG')
        latest = self.event('result', timeout=8)
        self.assertEqual(latest['exit_code'], 1)
        self.assertEqual(json.loads(latest['stdout'])['files'], [['src/new.py', 'BUG']])
        self.assertEqual(len([item for item in self.events if item['event'] == 'result']), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)

    def test_escaping_directory_replacement_does_not_scan_external_source(self):
        (self.tree / 'target.py').write_text('clean')
        self.start()
        self.start_watch(files=['src'])
        self.event('result')
        outside = self.work / 'private'
        outside.mkdir()
        (outside / 'secret.py').write_text('PRIVATE')
        self.tree.rename(self.work / 'old-src')
        self.tree.symlink_to(outside, target_is_directory=True)
        invalid = self.event('invalid')
        self.assertIn('outside', invalid['stderr'])
        self.assertNotIn('PRIVATE', invalid['stderr'])
        self.assertEqual(len(self.calls()), 1)


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for the actual scanner')
class RealDirectoryWatchTests(WatchFixture, unittest.TestCase):
    def test_real_added_file_and_ignore_policy_are_observed(self):
        self.source.write_text('value = 1\n')
        self.start(scanner=ROOT / 'ubs')
        self.start_watch(scanner=ROOT / 'ubs', files=['.'])
        self.assertEqual(self.event('result', timeout=150)['exit_code'], 0)
        target = self.root / 'added.py'
        target.write_text('eval(input())\n')
        added = self.event('result', timeout=150)
        self.assertEqual(added['exit_code'], 1, added)
        report = json.loads(added['stdout'])
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval' for item in report['findings']), report)
        (self.root / '.ubsignore').write_text('added.py\n')
        ignored = self.event('result', timeout=150)
        self.assertEqual(ignored['exit_code'], 0, ignored)
        self.assertFalse(any(item['rule_id'] == 'python.taint.eval'
                             for item in json.loads(ignored['stdout']).get('findings', [])))


if __name__ == '__main__':
    unittest.main()
