"""Reusable private input snapshots; scanner doubles are explicitly labelled."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('lsp_reusable_workspace', str(ROOT / 'ubs-lsp'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

# An invocation/transport double, NOT UBS detection. It exposes support-file
# bytes and process identity so reuse cannot be confused with report caching.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
paths = [pathlib.Path(p) for p in args[args.index('--') + 1:]]
texts = {str(p): p.read_text() for p in paths}
support = pathlib.Path('support.dat')
context = support.read_text() if support.exists() else ''
with open(os.environ['LSP_REUSE_LOG'], 'a') as stream:
    stream.write(json.dumps({'pid': os.getpid(), 'cwd': str(pathlib.Path.cwd()), 'texts': texts,
                            'context': context, 'args': args}) + '\n')
if any('SLOW' in text for text in texts.values()):
    time.sleep(20)
if any('MUTATE' in text for text in texts.values()):
    support.write_text('scanner changed support')
if any('CREATE' in text for text in texts.values()):
    pathlib.Path('unexpected.txt').write_text('scanner output')
if any('BROKEN' in text for text in texts.values()):
    print('broken report')
    sys.exit(0)
findings = [{'rule_id': 'test.buffer', 'file': name, 'line': 1, 'severity': 'critical',
             'message': 'buffer/context test finding'} for name, text in texts.items()
            if 'BUG' in text or 'DENY' in context]
print(json.dumps({'status': 'ok', 'project': str(pathlib.Path.cwd()), 'findings': findings,
                  'totals': {'files': len(paths), 'critical': len(findings), 'warning': 0, 'info': 0}}))
sys.exit(1 if findings else 0)
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        tmp = tempfile.TemporaryDirectory(prefix='ubs-lsp-reuse-test-')
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.root = self.work / 'repo'
        self.root.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('disk source\n')
        self.support = self.root / 'support.dat'
        self.support.write_text('allow')
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        self.uri = self.source.as_uri()
        self.log = self.work / 'calls'
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(LSP_REUSE_LOG=str(self.log), PYTHONDONTWRITEBYTECODE='1')
        environment = patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.root_id = (self.root.stat().st_dev, self.root.stat().st_ino)
        self.cache = lsp.BufferWorkspaceCache()
        self.addCleanup(self.cache.close)

    def tearDown(self):
        print(f'[{self.id()}] FINISHED ({time.monotonic() - self.started:.3f}s)', flush=True)

    def documents(self, text='BUG', **others):
        return {path.as_uri(): {'path': path, 'text': lsp.normalized_text(value), 'wire_text': value,
                                'version': 1, 'generation': 1, 'synchronized': True}
                for path, value in [(self.source, text), *((self.root / name, value) for name, value in others.items())]}

    def workspace(self, text='BUG', *, documents=None, cancel=None, timeout=5):
        return lsp.BufferWorkspace(self.root, self.root_id, documents or self.documents(text),
                                   cancel or threading.Event(), time.monotonic() + timeout, cache=self.cache)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


class ReuseTests(Fixture):
    def test_unchanged_support_inode_is_retained_and_only_new_buffer_is_written(self):
        self.support.write_bytes(b'x' * 65536)
        original = (self.source.read_bytes(), lsp.file_stamp(self.source.stat()))
        with self.workspace('first') as first:
            root = first.root
            support_id = (root / 'support.dat').stat().st_ino
            self.assertFalse(first.reused)
            self.assertGreater(first.copied_bytes, 65536)
        with self.workspace('BUG second') as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.root, root)
            self.assertEqual(second.copied_bytes, 0)
            self.assertEqual(second.buffer_bytes_written, len('BUG second'))
            self.assertEqual((root / 'support.dat').stat().st_ino, support_id)
            self.assertEqual((root / 'a.py').read_text(), 'BUG second')
        self.assertEqual((self.source.read_bytes(), lsp.file_stamp(self.source.stat())), original)
        self.cache.close()
        self.assertFalse(root.exists())

    def test_unchanged_buffers_are_not_rewritten(self):
        with self.workspace('same') as first:
            before = lsp.file_stamp((first.root / 'a.py').stat())
        with self.workspace('same') as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.buffer_bytes_written, 0)
            self.assertEqual(lsp.file_stamp((second.root / 'a.py').stat()), before)

    def test_old_generation_guards_do_not_borrow_new_private_stamps(self):
        with self.workspace('old') as first:
            old_stamps = dict(first.shadow_stamps)
        with self.workspace('new') as second:
            self.assertNotEqual(second.shadow_stamps, old_stamps)
        self.assertEqual(first.shadow_stamps, old_stamps)
        with self.assertRaisesRegex(lsp.ProtocolError, 'Private buffer'):
            first.verify()

    def test_same_size_disk_edit_with_restored_mtime_refreshes_from_new_bytes(self):
        with self.workspace() as first:
            old_root = first.root
        stamp = self.support.stat()
        self.support.write_text('DENY!')
        os.utime(self.support, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        with self.workspace() as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.root, old_root)
            self.assertEqual((second.root / 'support.dat').read_text(), 'DENY!')
            self.assertEqual(second.copied_bytes, 5)
        self.assertTrue(old_root.exists())

    def test_added_removed_and_new_buffer_membership_rebuild_context(self):
        with self.workspace() as first:
            old_root = first.root
        extra = self.root / 'extra'
        extra.write_text('dependency')
        with self.workspace() as second:
            self.assertFalse(second.reused)
            self.assertEqual((second.root / 'extra').read_text(), 'dependency')
        extra.rename(self.work / 'removed')
        with self.workspace() as third:
            self.assertFalse(third.reused)
            self.assertFalse((third.root / 'extra').exists())
        with self.workspace(documents=self.documents(**{'new/b.py': 'new buffer'})) as fourth:
            self.assertFalse(fourth.reused)
            self.assertEqual((fourth.root / 'new/b.py').read_text(), 'new buffer')
        self.assertFalse((self.root / 'new').exists())
        self.assertFalse(old_root.exists())

    def test_closed_virtual_buffer_does_not_leak_into_next_selection(self):
        with self.workspace(documents=self.documents(**{'new/b.py': 'old buffer'})):
            pass
        with self.workspace() as second:
            self.assertFalse((second.root / 'new').exists())
        self.assertFalse((self.root / 'new').exists())

    def test_private_tampering_cannot_be_reused_even_with_restored_mtime(self):
        with self.workspace() as first:
            old_root = first.root
        target = old_root / 'support.dat'
        before = target.stat()
        target.write_text('DENY!')
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.workspace() as second:
            self.assertFalse(second.reused)
            self.assertEqual((second.root / 'support.dat').read_text(), 'allow')
        self.assertFalse(old_root.exists())

    def test_symlinked_private_buffer_never_redirects_writes_to_checkout(self):
        with self.workspace() as first:
            target = first.root / 'a.py'
        target.rename(self.work / 'old-private-source')
        target.symlink_to(self.source)
        original = self.source.read_bytes()
        with self.workspace('replacement') as second:
            self.assertFalse(second.reused)
            self.assertEqual((second.root / 'a.py').read_text(), 'replacement')
        self.assertEqual(self.source.read_bytes(), original)

    def test_hardlinked_private_input_is_not_accepted(self):
        with self.workspace() as first:
            private = first.root / 'a.py'
        private.rename(self.work / 'prior-source')
        os.link(self.source, private)
        with self.workspace('BUG edit') as second:
            self.assertFalse(second.reused)
        self.assertEqual(self.source.read_text(), 'disk source\n')

    def test_original_symlink_and_root_replacement_are_errors_not_cached_success(self):
        with self.workspace() as first:
            old = first.root
        self.support.rename(self.work / 'old-support')
        self.support.symlink_to(self.work / 'old-support')
        with self.assertRaises(OSError), self.workspace():
            pass
        self.assertFalse(old.exists())
        self.assertIsNone(self.cache.retained)
        self.root.rename(self.work / 'old-repo')
        self.root.mkdir()
        with self.assertRaisesRegex(lsp.ProtocolError, 'root was replaced'), self.workspace():
            pass

    def test_exclusive_lease_and_close_do_not_delete_a_live_workspace(self):
        with self.workspace() as first:
            with self.assertRaisesRegex(lsp.ProtocolError, 'already in use'), self.workspace():
                pass
            with self.assertRaisesRegex(lsp.ProtocolError, 'active'):
                self.cache.close()
            self.assertTrue(first.root.exists())
        self.cache.close()
        with self.assertRaisesRegex(lsp.ProtocolError, 'closed'), self.workspace():
            pass

    def test_cancelled_update_discards_partial_tree_and_allows_fresh_recovery(self):
        with self.workspace('before') as first:
            old_root = first.root
        token = threading.Event()
        original_write = os.write
        def interrupted(fd, data):
            count = original_write(fd, data[:1])
            token.set()
            return count
        with patch.object(lsp.os, 'write', side_effect=interrupted), self.assertRaisesRegex(lsp.ProtocolError, 'cancelled'):
            with self.workspace('long replacement', cancel=token):
                pass
        self.assertIsNone(self.cache.retained)
        self.assertFalse(old_root.exists())
        with self.workspace('recovered') as last:
            self.assertFalse(last.reused)
            self.assertEqual((last.root / 'a.py').read_text(), 'recovered')

    def test_byte_bounds_and_git_configuration_checks_apply_on_reuse(self):
        with self.workspace('old') as first:
            old_root = first.root
        with patch.object(lsp, 'MAX_WORKSPACE_BYTES', 32), self.assertRaisesRegex(lsp.ProtocolError, 'byte limit'):
            with self.workspace('x' * 40):
                pass
        self.assertFalse(old_root.exists())
        with self.workspace('old'):
            pass
        with patch.dict(os.environ, {'GIT_DIR': '/external'}), self.assertRaisesRegex(lsp.ProtocolError, 'redirected'):
            with self.workspace():
                pass
        self.assertIsNone(self.cache.retained)

    def test_deadline_and_post_scan_context_changes_discard_reusable_tree(self):
        with self.workspace() as first:
            old_root = first.root
        with self.assertRaisesRegex(lsp.ProtocolError, 'timed out'), self.workspace(timeout=-1):
            pass
        self.assertFalse(old_root.exists())
        with self.assertRaisesRegex(lsp.ProtocolError, 'context changed'):
            with self.workspace() as current:
                self.support.write_text('DENY changed')
        self.assertIsNone(self.cache.retained)
        self.assertFalse(current.root.exists())

    def test_extra_private_entries_and_support_mutation_fail_at_lease_completion(self):
        for mutate in ('support', 'extra'):
            with self.subTest(mutate=mutate), self.assertRaisesRegex(lsp.ProtocolError, 'Private buffer'):
                with self.workspace() as current:
                    target = current.root / ('support.dat' if mutate == 'support' else 'new-output')
                    target.write_text('changed')
            self.assertFalse(current.root.exists())
            self.assertIsNone(self.cache.retained)

    def test_initial_private_contents_are_checked_against_source_bytes(self):
        build = lsp.BufferWorkspace.build
        def tamper(workspace):
            result = build(workspace)
            (result.root / 'support.dat').write_text('other')
            return result
        with patch.object(lsp.BufferWorkspace, 'build', tamper), self.assertRaisesRegex(lsp.ProtocolError, 'differs'):
            with self.workspace():
                pass
        self.assertIsNone(self.cache.retained)

    def test_only_changed_support_file_is_copied(self):
        big = self.root / 'unchanged.bin'
        big.write_bytes(b'z' * 1024 * 1024)
        with self.workspace('buffer') as first:
            before = lsp.file_stamp((first.root / big.name).stat())
        self.support.write_text('DENY new policy')
        with self.workspace('buffer') as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.copied_bytes, len('DENY new policy'))
            self.assertEqual(second.buffer_bytes_written, 0)
            self.assertEqual(lsp.file_stamp((second.root / big.name).stat()), before)
            self.assertEqual((second.root / self.support.name).read_text(), 'DENY new policy')

    def test_atomic_autosave_refreshes_disk_guard_without_overwriting_buffer(self):
        with self.workspace('unsaved latest') as first:
            original_guard = dict(first.entries)
            private_stamp = lsp.file_stamp((first.root / 'a.py').stat())
        saved = self.work / 'atomic-save'
        saved.write_text('older autosaved contents')
        os.replace(saved, self.source)
        with self.workspace('unsaved latest') as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.root, first.root)
            self.assertEqual(second.copied_bytes, 0)
            self.assertEqual(second.buffer_bytes_written, 0)
            self.assertEqual(lsp.file_stamp((second.root / 'a.py').stat()), private_stamp)
            self.assertEqual((second.root / 'a.py').read_text(), 'unsaved latest')
        self.assertEqual(self.source.read_text(), 'older autosaved contents')
        self.assertEqual(first.entries, original_guard)
        with self.assertRaisesRegex(lsp.ProtocolError, 'context changed'):
            first.verify()

    def test_atomic_support_save_preserves_other_private_inodes(self):
        with self.workspace('buffer') as first:
            source_stamp = lsp.file_stamp((first.root / 'a.py').stat())
        saved = self.work / 'saved-support'
        saved.write_text('DENY atomic')
        os.replace(saved, self.support)
        with self.workspace('buffer') as second:
            self.assertTrue(second.reused)
            self.assertEqual(second.root, first.root)
            self.assertEqual((second.root / 'support.dat').read_text(), 'DENY atomic')
            self.assertEqual(lsp.file_stamp((second.root / 'a.py').stat()), source_stamp)

    def test_support_mode_changes_and_old_guards_are_not_lost(self):
        with self.workspace() as first:
            original_guard = dict(first.entries)
        self.support.chmod(0o755)
        with self.workspace() as second:
            self.assertTrue(second.reused)
            self.assertEqual((second.root / 'support.dat').stat().st_mode & 0o777, 0o700)
        self.assertEqual(first.entries, original_guard)
        with self.assertRaisesRegex(lsp.ProtocolError, 'context changed'):
            first.verify()
        self.support.chmod(0o644)
        with self.workspace() as third:
            self.assertTrue(third.reused)
            self.assertEqual((third.root / 'support.dat').stat().st_mode & 0o777, 0o600)

    def test_redirected_git_config_cannot_be_introduced_by_incremental_copy(self):
        git = self.root / '.git'
        git.mkdir()
        config = git / 'config'
        config.write_text('[core]\nrepositoryformatversion=0\n')
        with self.workspace() as first:
            root = first.root
        config.write_text('[include]\npath=/external\n')
        with self.assertRaisesRegex(lsp.ProtocolError, 'Path-dependent'), self.workspace():
            pass
        self.assertIsNone(self.cache.retained)
        self.assertFalse(root.exists())
        self.assertEqual(self.calls(), [])

    def test_changed_source_byte_bound_is_checked_before_private_mutation(self):
        with self.workspace() as first:
            root = first.root
        self.support.write_bytes(b'x' * 200)
        with patch.object(lsp, 'MAX_WORKSPACE_BYTES', 100), self.assertRaisesRegex(lsp.ProtocolError, 'byte limit'):
            with self.workspace():
                pass
        self.assertFalse(root.exists())
        self.assertIsNone(self.cache.retained)

    def test_context_edit_during_incremental_copy_discards_mixed_generation(self):
        later = self.root / 'z.dat'
        later.write_text('before')
        with self.workspace() as first:
            root = first.root
        self.support.write_text('changed one')
        later.write_text('trigger edit')
        original_read = os.read
        def edit_earlier(fd, size):
            result = original_read(fd, size)
            if result == b'trigger edit':
                self.support.write_text('changed twice')
            return result
        with patch.object(lsp.os, 'read', side_effect=edit_earlier), self.assertRaisesRegex(lsp.ProtocolError, 'context changed'):
            with self.workspace():
                pass
        self.assertIsNone(self.cache.retained)
        self.assertFalse(root.exists())
        self.assertEqual(self.calls(), [])

    def test_support_update_cancellation_discards_partial_writes(self):
        with self.workspace() as first:
            root = first.root
        self.support.write_text('DENY replacement')
        cancel = threading.Event()
        write = os.write
        def interrupt(fd, data):
            count = write(fd, data[:1])
            cancel.set()
            return count
        with patch.object(lsp.os, 'write', side_effect=interrupt), self.assertRaisesRegex(lsp.ProtocolError, 'cancelled'):
            with self.workspace(cancel=cancel):
                pass
        self.assertIsNone(self.cache.retained)
        self.assertFalse(root.exists())
        self.assertEqual(self.support.read_text(), 'DENY replacement')
        with self.workspace() as recovered:
            self.assertFalse(recovered.reused)
            self.assertEqual((recovered.root / 'support.dat').read_text(), 'DENY replacement')

    def test_late_private_symlink_substitution_cannot_redirect_support_write(self):
        with self.workspace() as first:
            root = first.root
        self.support.write_text('DENY replacement')
        refresh = lsp.BufferWorkspace.refresh_support_file
        def redirect(workspace, relative):
            target = workspace.root / relative
            target.rename(self.work / 'old-private-support')
            target.symlink_to(self.support)
            return refresh(workspace, relative)
        with patch.object(lsp.BufferWorkspace, 'refresh_support_file', redirect), self.assertRaises(OSError):
            with self.workspace():
                pass
        self.assertEqual(self.support.read_text(), 'DENY replacement')
        self.assertFalse(root.exists())
        self.assertIsNone(self.cache.retained)

    def test_original_growth_during_support_copy_is_bounded(self):
        with self.workspace() as first:
            root = first.root
        self.support.write_text('new!')
        read = os.read
        def grow(fd, size):
            chunk = read(fd, size)
            if chunk == b'new!':
                with self.support.open('a') as stream:
                    stream.write('growth')
            return chunk
        with patch.object(lsp.os, 'read', side_effect=grow), self.assertRaisesRegex(lsp.ProtocolError, 'grew'):
            with self.workspace():
                pass
        self.assertIsNone(self.cache.retained)
        self.assertFalse(root.exists())


class ServerFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.messages = []
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, buffer_mode=True,
                                 incremental_workspace=True, timeout=8)
        self.addCleanup(self.server.close)
        self.send('initialize', {'rootUri': self.root.as_uri()}, id=1)

    def send(self, method, params=None, **extra):
        self.server.handle(dict(jsonrpc='2.0', method=method, params=params or {}, **extra))

    def open(self, text='BUG', path=None):
        self.send('textDocument/didOpen', {'textDocument': {'uri': (path or self.source).as_uri(),
                                                          'version': 1, 'text': text}})

    def change(self, text, version=2):
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': version},
                                            'contentChanges': [{'text': text}]})

    def drain(self, timeout=10):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            self.server.tick()
            if not self.server.active and not self.server.pending and self.server.batch is None and self.server.batch_pending is None:
                return
            time.sleep(0.01)
        self.fail('Timed out: ' + repr(self.messages))

    def reports(self, uri=None):
        return [m['params'] for m in self.messages if m.get('method') == 'textDocument/publishDiagnostics'
                and m['params']['uri'] == (uri or self.uri)]


class ServerTests(ServerFixture):
    def test_every_edit_runs_scanner_with_stable_private_paths_and_latest_bytes(self):
        self.open('clean buffer')
        self.drain()
        self.assertEqual(self.reports()[-1]['diagnostics'], [])
        self.change('BUG buffer')
        self.drain()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'test.buffer')
        self.change('repaired buffer', 3)
        self.drain()
        self.assertEqual(self.reports()[-1]['diagnostics'], [])
        calls = self.calls()
        self.assertEqual(len(calls), 3)
        self.assertEqual(len({call['cwd'] for call in calls}), 1)
        self.assertEqual([next(iter(call['texts'].values())) for call in calls],
                         ['clean buffer', 'BUG buffer', 'repaired buffer'])
        self.assertEqual(self.source.read_text(), 'disk source\n')
        root = Path(calls[0]['cwd'])
        self.assertTrue(root.exists())
        self.server.close()
        self.assertFalse(root.exists())

    def test_scanner_private_mutation_is_unverified_and_next_scan_rebuilds(self):
        for index, text in enumerate(('MUTATE', 'CREATE', 'BROKEN'), 1):
            if index == 1:
                self.open(text)
            else:
                self.change(text, index)
            self.drain()
            self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')
            self.assertFalse(Path(self.calls()[-1]['cwd']).exists())
            self.assertIsNone(self.server.workspace_cache.retained)
        self.change('BUG recovered', 4)
        self.drain()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'test.buffer')
        self.assertEqual(self.support.read_text(), 'allow')

    def test_dependency_edit_refreshes_before_next_result(self):
        self.open('clean buffer')
        self.drain()
        self.support.write_text('DENY')
        self.send('workspace/didChangeWatchedFiles', {'changes': [{'uri': self.support.as_uri(), 'type': 2}]})
        self.drain()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'test.buffer')
        self.assertEqual(self.calls()[-1]['context'], 'DENY')
        self.assertEqual(self.calls()[0]['cwd'], self.calls()[1]['cwd'])

    def test_grouped_buffers_preserve_policy_and_new_file_scope(self):
        self.server.policy = ('--profile=strict', '--fail-on-warning')
        new = self.root / 'package' / 'new.py'
        self.open('BUG one')
        self.open('BUG two', new)
        self.drain()
        self.change('BUG edited')
        self.drain()
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[0]['cwd'], self.calls()[1]['cwd'])
        self.assertEqual(len(self.calls()[1]['texts']), 2)
        self.assertIn('--profile=strict', self.calls()[1]['args'])
        self.assertIn('--fail-on-warning', self.calls()[1]['args'])
        self.assertEqual(self.reports(new.as_uri())[-1]['diagnostics'][0]['code'], 'test.buffer')
        self.assertFalse(new.parent.exists())

    def test_cancelled_scanner_is_reaped_and_new_buffer_is_not_old_result(self):
        self.open('SLOW')
        until = time.monotonic() + 5
        while not self.calls() and time.monotonic() < until:
            self.server.tick()
            time.sleep(0.01)
        self.assertEqual(len(self.calls()), 1)
        old = self.calls()[0]
        self.change('BUG latest')
        self.drain()
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.assertFalse(Path(old['cwd']).exists())
        self.assertEqual(self.reports()[-1]['version'], 2)
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'test.buffer')

    def test_post_completion_dependency_change_cannot_publish_prior_clean_result(self):
        self.open('clean buffer')
        self.server.batch_due = 0
        self.server.tick()
        until = time.monotonic() + 5
        while not self.server.batch[0].done() and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue(self.server.batch[0].done())
        self.support.write_text('DENY')
        self.server.tick()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_autosave_keeps_private_scope_and_newer_unsaved_buffer(self):
        self.open('BUG latest buffer')
        self.drain()
        path = self.calls()[0]['cwd']
        saved = self.work / 'saved.py'
        saved.write_text('older saved text')
        os.replace(saved, self.source)
        self.send('workspace/didChangeWatchedFiles', {'changes': [{'uri': self.uri, 'type': 2}]})
        self.drain()
        self.assertEqual(self.calls()[-1]['cwd'], path)
        self.assertEqual(next(iter(self.calls()[-1]['texts'].values())), 'BUG latest buffer')
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'test.buffer')
        self.assertEqual(self.source.read_text(), 'older saved text')

    def test_last_document_close_drops_plaintext_and_reopen_uses_new_workspace(self):
        self.open('BUG private')
        self.drain()
        root = Path(self.calls()[0]['cwd'])
        self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
        self.drain()
        self.assertFalse(root.exists())
        self.assertIsNone(self.server.workspace_cache.retained)
        self.open('new buffer')
        self.drain()
        self.assertNotEqual(self.calls()[-1]['cwd'], str(root))
        self.assertEqual(self.reports()[-1]['diagnostics'], [])

    def test_shutdown_cancels_active_lease_and_removes_private_tree_before_exit(self):
        self.open('SLOW')
        until = time.monotonic() + 5
        while not self.calls() and time.monotonic() < until:
            self.server.tick()
            time.sleep(0.01)
        self.assertEqual(len(self.calls()), 1)
        old = self.calls()[0]
        self.send('shutdown', id=9)
        self.assertEqual(self.messages[-1], {'jsonrpc': '2.0', 'id': 9, 'result': None})
        marker = len(self.messages)
        self.drain()
        self.assertEqual(len(self.messages), marker)
        self.assertFalse(Path(old['cwd']).exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)

    def test_real_stdio_incremental_context_refresh_and_cleanup(self):
        process = subprocess.Popen([sys.executable, '-I', str(ROOT / 'ubs-lsp'), '--repo', str(self.root),
                                    '--scanner', str(self.scanner), '--buffer-mode=incremental'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messages = queue.Queue()
        def read():
            framer = lsp.Framer()
            while data := process.stdout.read1(65536):
                for message in framer.feed(data):
                    messages.put(message)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        def finish():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.addCleanup(finish)
        def send(method, params=None, **extra):
            process.stdin.write(lsp.frame(dict(jsonrpc='2.0', method=method, params=params or {}, **extra)))
            process.stdin.flush()
        observed = []
        def receive(predicate):
            until = time.monotonic() + 6
            while time.monotonic() < until:
                try:
                    message = messages.get(timeout=0.1)
                except queue.Empty:
                    continue
                observed.append(message)
                if predicate(message):
                    return message
            self.fail('No expected stdio result: ' + repr(observed))
        def diagnostics(message):
            return message.get('method') == 'textDocument/publishDiagnostics'
        send('initialize', {'rootUri': self.root.as_uri()}, id=1)
        capabilities = receive(lambda m: m.get('id') == 1)['result']['capabilities']
        self.assertEqual(capabilities['experimental']['ubs']['workspaceStrategy'], 'incremental')
        send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'version': 1, 'text': 'clean'}})
        receive(lambda m: diagnostics(m) and m['params']['diagnostics'] == [])
        initial = self.calls()[0]
        self.support.write_text('DENY')
        send('workspace/didChangeWatchedFiles', {'changes': [{'uri': self.support.as_uri(), 'type': 2}]})
        receive(lambda m: diagnostics(m) and any(d['code'] == 'test.buffer' for d in m['params']['diagnostics']))
        self.assertEqual(self.calls()[-1]['cwd'], initial['cwd'])
        self.assertEqual(self.calls()[-1]['context'], 'DENY')
        self.support.write_text('allow')
        send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2}, 'contentChanges': [{'text': 'repaired'}]})
        receive(lambda m: diagnostics(m) and m['params'].get('version') == 2 and m['params']['diagnostics'] == [])
        self.assertEqual(len(self.calls()), 3)
        self.assertEqual(len({call['cwd'] for call in self.calls()}), 1)
        self.assertEqual(self.source.read_text(), 'disk source\n')
        send('shutdown', id=2)
        receive(lambda m: m.get('id') == 2)
        send('exit')
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(process.stderr.read(), b'')
        self.assertFalse(Path(initial['cwd']).exists())

    def test_snapshot_mode_remains_one_shot_and_saved_mode_refuses_unsaved_text(self):
        for buffer_mode in (True, False):
            messages = []
            server = lsp.Server(self.root, self.scanner, messages.append, buffer_mode=buffer_mode)
            self.addCleanup(server.close)
            server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}})
            server.handle({'jsonrpc': '2.0', 'method': 'textDocument/didOpen', 'params': {
                'textDocument': {'uri': self.uri, 'version': 1, 'text': 'BUG'}}})
            until = time.monotonic() + 5
            while time.monotonic() < until:
                server.tick()
                if not server.active and not server.pending and server.batch is None and server.batch_pending is None:
                    break
                time.sleep(0.01)
            diagnostics = [m['params']['diagnostics'] for m in messages if m.get('method') == 'textDocument/publishDiagnostics'][-1]
            self.assertEqual(diagnostics[0]['code'], 'test.buffer' if buffer_mode else 'ubs.unsaved')
            if buffer_mode:
                self.assertFalse(Path(self.calls()[-1]['cwd']).exists())


@unittest.skipUnless(os.environ.get('UBS_LSP_E2E') == '1', 'requires complete actual UBS runtime')
class RealScannerTests(ServerFixture):
    def test_real_incremental_buffer_edits_match_new_snapshot_scans(self):
        self.server.scanner = ROOT / 'ubs'
        self.server.timeout = 120
        self.source.write_text('value = 1\n')
        for version, text in enumerate(('eval(input())\n', 'value = 2\n', 'eval(input())\n'), 1):
            if version == 1:
                self.open(text)
            else:
                self.change(text, version)
            self.drain(timeout=150)
            expected = lsp.scan_buffers(ROOT / 'ubs', self.root, self.documents(text), self.root_id,
                                        120, threading.Event())
            diagnostics = self.reports()[-1]['diagnostics']
            self.assertEqual(diagnostics, expected[self.uri][0])
            self.assertFalse(any(d['code'] == 'ubs.unverified' for d in diagnostics), diagnostics)
            self.assertEqual(any(d['code'] == 'python.taint.eval' for d in diagnostics), version != 2, diagnostics)
        self.assertEqual(self.source.read_text(), 'value = 1\n')


if __name__ == '__main__':
    unittest.main()
