"""Unsaved buffer snapshots, real subprocess boundaries, and unchanged checkout controls."""
from __future__ import annotations

from concurrent.futures import Future
import json
import os
import queue
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from test_lsp_incremental import Fixture, ROOT, SCANNER, edit, lsp


class BufferFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.server.close()
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5, buffer_mode=True)
        self.addCleanup(self.server.close)
        self.messages.clear()
        self.handle('initialize', {'rootUri': self.root.as_uri()}, id=1)
        self.log = self.work / 'scans.jsonl'
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env['LSP_TEST_LOG'] = str(self.log)
        environment = patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def preview(self, documents=None):
        return lsp.scan_buffers(self.scanner, self.root, documents or self.server.documents,
                                self.server.root_id, 5, threading.Event(), self.server.policy)

    def workspace(self, **changes):
        arguments = dict(root=self.root, root_id=self.server.root_id, documents=self.server.documents,
                         cancel=threading.Event(), deadline=time.monotonic() + 5)
        return lsp.BufferWorkspace(**dict(arguments, **changes))


class BufferScanTests(BufferFixture, unittest.TestCase):
    def test_unsaved_bug_is_scanned_and_original_bytes_and_inode_are_untouched(self):
        original = (self.source.read_bytes(), lsp.file_stamp(self.source.stat()))
        self.open('BUG\n')
        self.drain()
        result = self.diagnostics()[-1]
        self.assertEqual(result['version'], 1)
        self.assertEqual(result['diagnostics'][0]['code'], 'test.bug')
        self.assertEqual(result['diagnostics'][0]['data'], {'ubsSourceMode': 'buffer'})
        self.assertEqual((self.source.read_bytes(), lsp.file_stamp(self.source.stat())), original)
        call = self.calls()[0]
        self.assertNotEqual(call['cwd'], str(self.root))
        self.assertEqual(call['files'][0][1], 'BUG\n')
        self.assertFalse(Path(call['cwd']).exists())

    def test_git_pager_does_not_block_unsaved_buffer_analysis(self):
        original = self.source.read_bytes()
        with patch.dict(os.environ, {'GIT_PAGER': 'cat'}):
            self.open('BUG\n')
            self.drain()
        result = self.diagnostics()[-1]
        self.assertEqual(result['diagnostics'][0]['code'], 'test.bug')
        self.assertEqual(result['diagnostics'][0]['data'], {'ubsSourceMode': 'buffer'})
        self.assertEqual(self.source.read_bytes(), original)
        self.assertNotEqual(self.calls()[0]['cwd'], str(self.root))
        self.assertEqual(self.calls()[0]['files'][0][1], 'BUG\n')

    def test_real_stdio_buffer_mode_uses_unsaved_text_without_saving(self):
        process = subprocess.Popen([sys.executable, '-I', str(ROOT / 'ubs-lsp'), '--repo', str(self.root),
                                    '--scanner', str(self.scanner), '--buffer-mode=snapshot'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messages = queue.Queue()
        def read():
            parser = lsp.Framer()
            while data := process.stdout.read1(65536):
                for message in parser.feed(data):
                    messages.put(message)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        def finish():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.addCleanup(finish)
        def send(method, params=None, **extra):
            process.stdin.write(lsp.frame(dict(jsonrpc='2.0', method=method, params=params or {}, **extra)))
            process.stdin.flush()
        def receive(predicate):
            until = time.monotonic() + 6
            while time.monotonic() < until:
                try:
                    message = messages.get(timeout=0.1)
                except queue.Empty:
                    continue
                if predicate(message):
                    return message
            self.fail('No expected buffer-mode stdio result')
        send('initialize', {'rootUri': self.root.as_uri()}, id=1)
        caps = receive(lambda m: m.get('id') == 1)['result']['capabilities']
        self.assertEqual(caps['experimental']['ubs']['sourceMode'], 'buffer')
        send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'text': 'BUG', 'version': 1}})
        result = receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics' and
                         any(d['code'] == 'test.bug' for d in m['params']['diagnostics']))
        self.assertEqual(result['params']['version'], 1)
        self.assertEqual(self.source.read_text(), 'clean\n')
        self.assertFalse(Path(self.calls()[0]['cwd']).exists())
        send('shutdown', id=2)
        receive(lambda m: m.get('id') == 2)
        send('exit')
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(process.stderr.read(), b'')

    def test_incremental_unsaved_edit_rescans_without_did_save(self):
        self.open()
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'], [])
        self.change([edit((0, 0), (0, 5), 'BUG')], 2)
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'test.bug')
        self.change([edit((0, 0), (0, 3), 'fixed')], 3)
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'], [])
        self.assertEqual(self.source.read_text(), 'clean\n')
        self.assertEqual(len(self.calls()), 3)

    def test_new_unsaved_file_and_parent_are_not_created_in_checkout(self):
        new = self.root / 'new package' / 'new.py'
        self.open('BUG', uri=new.as_uri())
        self.drain()
        self.assertEqual(self.diagnostics(new.as_uri())[-1]['diagnostics'][0]['code'], 'test.bug')
        self.assertFalse(new.parent.exists())
        self.assertFalse(Path(self.calls()[0]['cwd']).exists())

    def test_all_open_buffers_are_grouped_and_policy_is_preserved(self):
        self.server.policy = ('--profile=strict', '--fail-on-warning')
        peer = self.root / 'helper.py'
        peer.write_text('disk helper')
        self.open('BUG caller')
        self.open('BUG helper', uri=peer.as_uri())
        self.drain()
        self.assertEqual(len(self.calls()), 1)
        call = self.calls()[0]
        self.assertEqual([Path(name).name for name, _ in call['files']], ['a.py', 'helper.py'])
        self.assertEqual([text for _, text in call['files']], ['BUG caller', 'BUG helper'])
        for uri in (self.uri, peer.as_uri()):
            self.assertEqual(self.diagnostics(uri)[-1]['diagnostics'][0]['code'], 'test.bug')
        self.assertIn('--profile=strict', call['args'])
        self.assertIn('--fail-on-warning', call['args'])
        self.assertEqual(peer.read_text(), 'disk helper')

    def test_burst_coalesces_and_latest_version_is_published(self):
        self.open()
        for version in range(2, 12):
            self.change([{'text': 'BUG ' + str(version)}], version)
        self.drain()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]['files'][0][1], 'BUG 11')
        self.assertEqual(self.diagnostics()[-1]['version'], 11)

    def test_unsynchronized_member_blocks_entire_group(self):
        self.open()
        peer = self.root / 'helper.py'
        self.open('BUG', uri=peer.as_uri())
        self.change([edit((50, 0), (50, 0), 'x')], 2)
        self.handle('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=2)
        self.drain()
        self.assertEqual(self.calls(), [])
        for uri in (self.uri, peer.as_uri()):
            self.assertEqual(self.diagnostics(uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_completed_snapshot_is_rejected_if_disk_dependency_changes_before_publication(self):
        config = self.root / 'config.json'
        config.write_text('{}')
        self.open('BUG')
        self.server.batch_pending = None
        documents = {uri: dict(doc) for uri, doc in self.server.documents.items()}
        result = self.preview(documents)
        config.write_text('{"changed":true}')
        future = Future()
        future.set_result(result)
        self.server.complete(future, documents, threading.Event())
        diag = self.diagnostics()[-1]['diagnostics']
        self.assertEqual(diag[0]['code'], 'ubs.unverified')
        self.assertIn('context changed', diag[0]['message'])
        self.assertFalse(any(d['code'] == 'test.bug' for d in diag))

    def test_scan_time_disk_change_is_unverified_not_a_clean_result(self):
        policy = self.root / 'policy'
        policy.write_text('old')
        self.scanner.write_text(SCANNER.replace("findings = []", "pathlib.Path(os.environ['LSP_TEST_POLICY']).write_text('new')\nfindings = []"))
        with patch.dict(os.environ, {'LSP_TEST_POLICY': str(policy)}):
            self.open()
            self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.assertFalse(Path(self.calls()[0]['cwd']).exists())

    def test_stale_slow_snapshot_is_cancelled_and_removed(self):
        self.open('SLOW')
        until = time.monotonic() + 4
        while not self.calls() and time.monotonic() < until:
            self.server.tick()
            time.sleep(0.02)
        self.assertEqual(len(self.calls()), 1)
        old = self.calls()[0]
        self.change([{'text': 'BUG current'}], 2)
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['version'], 2)
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'test.bug')
        self.assertFalse(Path(old['cwd']).exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.assertEqual(self.source.read_text(), 'clean\n')

    def test_invalid_report_fails_and_private_tree_is_cleaned(self):
        self.scanner.write_text(SCANNER.replace("'status': 'ok'", "'status': 'partial'"))
        self.open('BUG')
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.assertFalse(Path(self.calls()[0]['cwd']).exists())

    def test_original_uri_and_full_utf16_line_survive_snapshot_routing(self):
        source = self.root / 'line space😀.py'
        raw = '\ufeffBUG😀\r\n'
        self.open(raw, uri=source.as_uri())
        self.drain()
        result = self.diagnostics(source.as_uri())[-1]
        self.assertEqual(result['uri'], source.as_uri())
        self.assertEqual(result['diagnostics'][0]['range']['end'], {'line': 0, 'character': 6})
        self.assertNotIn('ubs-lsp-buffer-', json.dumps(result))
        self.assertFalse(source.exists())

    def test_closing_dirty_dependency_requeues_remaining_buffers(self):
        peer = self.root / 'helper.py'
        peer.write_text('disk helper')
        self.open('BUG')
        self.open('BUG helper', uri=peer.as_uri())
        self.drain()
        self.handle('textDocument/didClose', {'textDocument': {'uri': peer.as_uri()}})
        self.drain()
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(len(self.calls()[-1]['files']), 1)
        self.assertEqual(self.diagnostics(peer.as_uri())[-1]['diagnostics'], [])


class SnapshotTests(BufferFixture, unittest.TestCase):
    def test_complete_context_and_file_modes_are_private_without_hardlinks(self):
        auxiliary = self.root / 'hidden' / '.config'
        auxiliary.parent.mkdir()
        auxiliary.write_bytes(b'\x00data')
        auxiliary.chmod(0o755)
        (self.root / '.ubsignore').write_text('skip/\n')
        self.open('BUG')
        with self.workspace() as snapshot:
            copied = snapshot.root / 'hidden' / '.config'
            self.assertEqual(copied.read_bytes(), auxiliary.read_bytes())
            self.assertNotEqual(copied.stat().st_ino, auxiliary.stat().st_ino)
            self.assertEqual(stat.S_IMODE(snapshot.root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o700)
            self.assertEqual((snapshot.root / '.ubsignore').read_text(), 'skip/\n')
            self.assertEqual((snapshot.root / 'a.py').read_text(), 'BUG')
            saved_path = snapshot.root
        self.assertFalse(saved_path.exists())
        snapshot.verify()  # Original-context guard survives temp cleanup.

    def test_plain_git_repository_metadata_is_preserved(self):
        subprocess.run(['git', '-C', str(self.root), 'init', '-q'], check=True)
        self.open('BUG')
        with self.workspace() as snapshot:
            self.assertEqual((snapshot.root / '.git' / 'HEAD').read_bytes(), (self.root / '.git' / 'HEAD').read_bytes())
            self.assertTrue((snapshot.root / '.git' / 'objects').is_dir())
            result = subprocess.run(['git', '-C', str(snapshot.root), 'rev-parse', '--show-toplevel'], capture_output=True, text=True, check=True)
            self.assertEqual(Path(result.stdout.strip()), snapshot.root)

    def test_git_redirects_are_rejected_without_starting_scanner(self):
        self.open('BUG')
        redirected_environments = (
            {'GIT_DIR': '/somewhere'},
            {'GIT_WORK_TREE': '/somewhere'},
            {'GIT_INDEX_FILE': '/somewhere/index'},
            {'GIT_CONFIG_GLOBAL': '/somewhere/config'},
            {'GIT_CONFIG_SYSTEM': '/somewhere/config'},
            {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.worktree',
             'GIT_CONFIG_VALUE_0': '/somewhere'},
            {'GIT_CONFIG_PARAMETERS': "'core.worktree=/somewhere'"},
            {'GIT_PAGER_UNKNOWN': 'cat'},
        )
        for environment in redirected_environments:
            with self.subTest(environment=environment):
                with patch.dict(os.environ, {'GIT_PAGER': 'cat', **environment}), \
                        self.assertRaisesRegex(lsp.ProtocolError, 'redirected Git environments'):
                    self.preview()
        git = self.root / '.git'
        git.write_text('gitdir: /external')
        with self.assertRaises(lsp.ProtocolError):
            self.preview()
        git.rename(self.work / 'git-file')
        git.mkdir()
        (git / 'config').write_text('[core]\nworktree=/external\n')
        with self.assertRaises(lsp.ProtocolError):
            self.preview()
        self.assertEqual(self.calls(), [])

    def test_all_symlinks_and_special_context_are_rejected(self):
        self.open('BUG')
        target = self.root / 'symlink'
        target.symlink_to(self.source)
        with self.assertRaises(OSError):
            self.preview()
        target.rename(self.work / 'old-symlink')
        os.mkfifo(target)
        with self.assertRaises(lsp.ProtocolError):
            self.preview()
        self.assertEqual(self.calls(), [])

    def test_new_buffer_cannot_escape_through_symlinked_parent(self):
        outside = self.work / 'outside'
        outside.mkdir()
        (self.root / 'link').symlink_to(outside, target_is_directory=True)
        new = self.root / 'link' / 'new.py'
        self.open('BUG', uri=new.as_uri())
        self.drain()
        self.assertEqual(self.diagnostics(new.as_uri())[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.assertFalse((outside / 'new.py').exists())
        self.assertEqual(self.calls(), [])

    def test_byte_and_entry_limits_are_global_and_cleanup_on_failure(self):
        self.open('BUG')
        snapshot = self.workspace()
        with patch.object(lsp, 'MAX_WORKSPACE_BYTES', 1), self.assertRaises(lsp.ProtocolError):
            with snapshot:
                pass
        self.assertFalse(snapshot.root.exists())
        for index in range(8):
            (self.root / str(index)).write_text('x')
        snapshot = self.workspace()
        with patch.object(lsp, 'MAX_WORKSPACE_ENTRIES', 4), self.assertRaises(lsp.ProtocolError):
            with snapshot:
                pass
        self.assertFalse(snapshot.root.exists())

    def test_buffer_growth_counts_toward_workspace_byte_limit(self):
        self.open('BUG' * 5)
        with patch.object(lsp, 'MAX_WORKSPACE_BYTES', 10), self.assertRaises(lsp.ProtocolError):
            self.preview()
        self.assertEqual(self.source.read_text(), 'clean\n')

    def test_new_virtual_parents_count_toward_entry_limit(self):
        new = self.root / 'new' / 'nested' / 'new.py'
        self.open('BUG', uri=new.as_uri())
        with patch.object(lsp, 'MAX_WORKSPACE_ENTRIES', 4), self.assertRaisesRegex(lsp.ProtocolError, 'entry limit'):
            self.preview()
        self.assertFalse((self.root / 'new').exists())
        self.assertEqual(self.calls(), [])

    def test_cancellation_and_deadline_prevent_snapshot_work(self):
        self.open('BUG')
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(lsp.ProtocolError), self.workspace(cancel=cancel):
            pass
        with self.assertRaises(lsp.ProtocolError), self.workspace(deadline=time.monotonic() - 1):
            pass
        self.assertEqual(self.calls(), [])

    def test_input_change_during_copy_is_rejected_by_final_inventory_check(self):
        trigger = self.root / 'z.txt'
        trigger.write_bytes(b'trigger')
        self.open('BUG')
        read = os.read
        def mutate(fd, size):
            data = read(fd, size)
            if data == b'trigger':
                self.source.write_text('changed while copying')
            return data
        with patch.object(lsp.os, 'read', side_effect=mutate), self.assertRaisesRegex(lsp.ProtocolError, 'context changed'):
            self.preview()
        self.assertEqual(self.calls(), [])

    def test_new_file_appearance_invalidates_completed_buffer_context(self):
        new = self.root / 'new.py'
        self.open('BUG', uri=new.as_uri())
        result = self.preview()
        new.write_text('disk arrival')
        with self.assertRaises(lsp.ProtocolError):
            result[new.as_uri()][1].verify()

    def test_temporary_location_inside_repository_is_refused_before_creation(self):
        self.open('BUG')
        before = set(self.root.iterdir())
        with patch.object(lsp.tempfile, 'gettempdir', return_value=str(self.root)), self.assertRaises(lsp.ProtocolError):
            self.preview()
        self.assertEqual(set(self.root.iterdir()), before)

    def test_default_saved_mode_still_refuses_unsaved_buffers(self):
        self.server.buffer_mode = False
        self.open('BUG')
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'ubs.unsaved')
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(os.environ.get('UBS_LSP_E2E') == '1', 'set UBS_LSP_E2E=1 for the actual UBS scanner')
class RealBufferTests(BufferFixture, unittest.TestCase):
    def test_real_unsaved_taint_and_incremental_cleanup_leave_disk_clean(self):
        self.server.scanner = ROOT / 'ubs'
        self.server.timeout = 120
        self.source.write_text('value = 1\n')
        self.open('eval(input())\n')
        self.real_drain()
        self.assertTrue(any(d['code'] == 'python.taint.eval' for d in self.diagnostics()[-1]['diagnostics']))
        self.change([{'text': 'value = 2\n'}], 2)
        self.real_drain()
        self.assertFalse(any(d['code'] in ('python.taint.eval', 'ubs.unverified') for d in self.diagnostics()[-1]['diagnostics']))
        self.assertEqual(self.source.read_text(), 'value = 1\n')

    def test_real_cross_file_unsaved_helper_is_analyzed_in_one_snapshot(self):
        self.server.scanner = ROOT / 'ubs'
        self.server.timeout = 120
        self.source.write_text('value = 1\n')
        peer = self.root / 'helper.py'
        peer.write_text('value = 1\n')
        self.open('from helper import run\nrun(input())\n')
        self.open('def run(value):\n    eval(value)\n', uri=peer.as_uri())
        self.real_drain()
        diagnostics = self.diagnostics(peer.as_uri())[-1]['diagnostics']
        self.assertTrue(any(d['code'] == 'python.taint.eval' and d['range']['start']['line'] == 1 for d in diagnostics), diagnostics)
        self.assertEqual(peer.read_text(), 'value = 1\n')
        self.assertEqual(self.source.read_text(), 'value = 1\n')

    def real_drain(self):
        until = time.monotonic() + 150
        while time.monotonic() < until:
            self.server.tick()
            if self.server.batch_pending is None and self.server.batch is None:
                return
            time.sleep(0.03)
        self.fail('Actual UBS buffer scan did not finish')


if __name__ == '__main__':
    unittest.main()
