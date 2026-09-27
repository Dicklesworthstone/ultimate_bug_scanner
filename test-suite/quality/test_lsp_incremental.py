"""Exact incremental editor synchronization; no source is executed by these tests."""
from __future__ import annotations

from concurrent.futures import Future
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
LSP = ROOT / 'ubs-lsp'
loader = importlib.machinery.SourceFileLoader('lsp_incremental_subject', str(LSP))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)


def edit(start, end, text, **extra):
    return dict(range={'start': dict(zip(('line', 'character'), start)),
                       'end': dict(zip(('line', 'character'), end))}, text=text, **extra)


# An explicit scanner protocol double, not a real detector. It records exactly
# which files/bytes the adapter sends and emits line-addressed test findings.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
paths = [pathlib.Path(p) for p in args[args.index('--') + 1:]]
records = [(str(p), p.read_text()) for p in paths]
log = os.environ.get('LSP_TEST_LOG')
if log:
    with open(log, 'a') as out:
        out.write(json.dumps({'pid': os.getpid(), 'cwd': str(pathlib.Path.cwd()), 'args': args, 'files': records}) + '\n')
if any('SLOW' in text for _, text in records):
    time.sleep(20)
findings = []
for name, text in records:
    for number, line in enumerate(text.splitlines(), 1):
        if 'BUG' in line:
            findings.append({'file': name, 'line': number, 'rule_id': 'test.bug', 'severity': 'critical', 'message': 'test defect'})
print(json.dumps({'status': 'ok', 'failed_modules': [], 'project': str(pathlib.Path.cwd()),
                  'totals': {'files': len(paths), 'critical': len(findings), 'warning': 0, 'info': 0},
                  'findings': findings}))
sys.exit(1 if findings else 0)
'''


class Fixture:
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ubs-lsp-incremental-')
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.root = self.work / 'repo'
        self.root.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('clean\n')
        self.uri = self.source.as_uri()
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        self.messages = []
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5)
        self.addCleanup(self.server.close)
        self.handle('initialize', {'rootUri': self.root.as_uri()}, id=1)

    def handle(self, method, params=None, **extra):
        self.server.handle(dict(jsonrpc='2.0', method=method, params=params or {}, **extra))

    def open(self, text='clean\n', version=1, uri=None):
        self.handle('textDocument/didOpen', {'textDocument': {'uri': uri or self.uri, 'version': version, 'text': text}})

    def change(self, changes, version=2):
        self.handle('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': version}, 'contentChanges': changes})

    def diagnostics(self, uri=None):
        return [msg['params'] for msg in self.messages if msg.get('method') == 'textDocument/publishDiagnostics'
                and msg['params']['uri'] == (uri or self.uri)]

    def drain(self):
        until = time.monotonic() + 6
        while time.monotonic() < until:
            self.server.tick()
            if not self.server.pending and not self.server.active and self.server.batch_pending is None and self.server.batch is None:
                return
            time.sleep(0.01)
        self.fail('LSP scans did not drain')


class EditTests(unittest.TestCase):
    def test_sequential_ranges_use_preceding_change_result(self):
        result = lsp.apply_changes('abcd', [edit((0, 1), (0, 3), 'XYZ'), edit((0, 4), (0, 5), '!')])
        self.assertEqual(result, 'aXYZ!')

    def test_surrogate_pairs_and_combining_marks(self):
        self.assertEqual(lsp.apply_changes('a😀e\u0301z', [edit((0, 1), (0, 3), 'X', rangeLength=2)]), 'aXe\u0301z')
        self.assertEqual(lsp.apply_changes('e\u0301', [edit((0, 1), (0, 2), '')]), 'e')
        with self.assertRaisesRegex(lsp.ProtocolError, 'surrogate'):
            lsp.apply_changes('😀', [edit((0, 1), (0, 2), '')])

    def test_bom_crlf_cr_lf_are_preserved(self):
        original = '\ufeffa😀\r\nsecond\rthird\n'
        changed = lsp.apply_changes(original, [edit((0, 2), (1, 3), 'Q', rangeLength=7)])
        self.assertEqual(changed, '\ufeffaQond\rthird\n')
        self.assertEqual(lsp.apply_changes(original, [edit((3, 0), (3, 0), 'end')]), original + 'end')

    def test_non_newline_unicode_separators_are_not_new_lines(self):
        self.assertEqual(lsp.apply_changes('a\u2028b\x0bc', [edit((0, 2), (0, 3), 'X')]), 'a\u2028X\x0bc')

    def test_character_past_eol_is_clamped_not_a_crlf_position(self):
        self.assertEqual(lsp.apply_changes('a\r\nb', [edit((0, 999), (0, 1000), '!')]), 'a!\r\nb')

    def test_full_replacement_and_following_delta(self):
        self.assertEqual(lsp.apply_changes('stale', [{'text': '😀ok'}, edit((0, 2), (0, 4), '!')], synchronized=False), '😀!')
        with self.assertRaisesRegex(lsp.ProtocolError, 'full document'):
            lsp.apply_changes('stale', [edit((0, 0), (0, 1), 'x')], synchronized=False)

    def test_malformed_range_and_length_fail_closed(self):
        cases = [edit((0, 2), (0, 1), ''), edit((2, 0), (2, 0), ''), edit((-1, 0), (0, 0), ''),
                 edit((True, 0), (0, 0), ''), edit((0, False), (0, 0), ''),
                 edit((0, 0), (0, 1), '', rangeLength=True), edit((0, 0), (0, 1), '', rangeLength=2),
                 {'range': None, 'text': ''}, {'text': '', 'rangeLength': 0}, {'text': '\ud800'}, None]
        for change in cases:
            with self.subTest(change=change), self.assertRaises((lsp.ProtocolError, UnicodeError)):
                lsp.apply_changes('abc', [change])

    def test_empty_excessive_and_intermediate_oversize_changes(self):
        for changes in ([], None, [{'text': ''}] * 1025):
            with self.assertRaises(lsp.ProtocolError):
                lsp.apply_changes('', changes)
        with patch.object(lsp, 'MAX_TEXT', 4), self.assertRaises(lsp.ProtocolError):
            lsp.apply_changes('abcd', [edit((0, 0), (0, 0), 'x'), {'text': ''}])
        with patch.object(lsp, 'MAX_TEXT_TOTAL', 4), self.assertRaisesRegex(lsp.ProtocolError, 'work limit'):
            lsp.apply_changes('abc', [{'text': 'abc'}, {'text': 'abc'}])

    def test_utf16_byte_oracle_agrees_on_400_deterministic_edits(self):
        import random
        rng = random.Random(481)
        alphabet = ('a', 'é', '😀', '\u0301', '\ufeff', '中')
        for _ in range(400):
            text = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(40)))
            a, b = sorted((rng.randrange(len(text) + 1), rng.randrange(len(text) + 1)))
            start = len(text[:a].encode('utf-16-le')) // 2
            end = len(text[:b].encode('utf-16-le')) // 2
            replacement = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(10)))
            encoded = text.encode('utf-16-le')
            expected = (encoded[:start * 2] + replacement.encode('utf-16-le') + encoded[end * 2:]).decode('utf-16-le')
            self.assertEqual(lsp.apply_changes(text, [edit((0, start), (0, end), replacement)]), expected)

    def test_large_line_index_is_linear_and_keeps_last_empty_line(self):
        text = '\r\n' * 100000
        self.assertEqual(lsp.position_offset(text, {'line': 100000, 'character': 0}), len(text))


class SynchronizationTests(Fixture, unittest.TestCase):
    def test_advertises_incremental_and_retains_exact_wire_text(self):
        self.assertEqual(self.messages[0]['result']['capabilities']['textDocumentSync']['change'], 2)
        text = '\ufeffclean\r\n'
        self.open(text)
        self.change([edit((0, 1), (0, 6), 'BUG')])
        doc = self.server.documents[self.uri]
        self.assertEqual(doc['wire_text'], '\ufeffBUG\r\n')
        self.assertEqual(doc['text'], 'BUG\n')
        self.assertTrue(doc['synchronized'])
        self.assertEqual(self.source.read_text(), 'clean\n')

    def test_edit_save_scans_new_disk_bytes_not_prior_buffer(self):
        self.open()
        self.drain()
        self.assertEqual(self.diagnostics()[-1]['diagnostics'], [])
        self.change([edit((0, 0), (0, 5), 'BUG')])
        self.assertEqual(self.diagnostics()[-1]['diagnostics'][0]['code'], 'ubs.unsaved')
        self.source.write_text('BUG\n')
        self.handle('textDocument/didSave', {'textDocument': {'uri': self.uri}, 'text': 'BUG\n'})
        self.drain()
        final = self.diagnostics()[-1]
        self.assertEqual(final['version'], 2)
        self.assertEqual(final['diagnostics'][0]['code'], 'test.bug')

    def test_batch_failure_is_atomic_and_requires_full_recovery(self):
        self.open()
        self.change([edit((0, 0), (0, 5), 'BUG'), edit((20, 0), (20, 0), '!')], 5)
        doc = self.server.documents[self.uri]
        self.assertEqual(doc['text'], 'clean\n')
        self.assertFalse(doc['synchronized'])
        self.assertNotIn(self.uri, self.server.pending)
        self.change([{'text': 'old replacement'}], 4)
        self.assertFalse(self.server.documents[self.uri]['synchronized'])
        self.change([edit((0, 0), (0, 0), 'bad delta')], 6)
        self.assertFalse(self.server.documents[self.uri]['synchronized'])
        self.change([{'text': 'clean\n'}, edit((0, 0), (0, 5), 'BUG')], 7)
        self.assertTrue(self.server.documents[self.uri]['synchronized'])
        self.assertEqual(self.server.documents[self.uri]['text'], 'BUG\n')

    def test_incremental_change_cancels_active_and_invalidates_published_group(self):
        self.open()
        peer = self.root / 'b.py'
        peer.write_text('ok')
        self.open('ok', uri=peer.as_uri())
        self.server.pending.clear()
        future, cancel = Future(), threading.Event()
        self.server.active[future] = (self.uri, self.server.documents[self.uri]['generation'], cancel)
        self.server.published_group = {self.uri, peer.as_uri()}
        self.change([edit((0, 0), (0, 0), '!')])
        self.assertTrue(cancel.is_set())
        self.assertEqual(self.diagnostics(peer.as_uri())[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        future.set_result({self.uri: ([], None)})
        before = len(self.messages)
        self.server.tick()
        self.assertEqual(len(self.messages), before)

    def test_full_sync_remains_supported_and_reopen_resets_version_floor(self):
        self.open()
        self.change([{'text': 'new'}], 100)
        self.handle('textDocument/didClose', {'textDocument': {'uri': self.uri}})
        self.open('clean\n', 1)
        self.change([edit((0, 0), (0, 5), 'BUG')], 2)
        self.assertEqual(self.server.documents[self.uri]['text'], 'BUG\n')

    def test_total_raw_text_budget_is_enforced_before_accepting_change(self):
        self.open('a\r\n')
        with patch.object(lsp, 'MAX_TEXT_TOTAL', 4):
            self.change([{'text': 'a\r\nbc'}])
        self.assertFalse(self.server.documents[self.uri]['synchronized'])
        self.assertEqual(self.server.documents[self.uri]['wire_text'], 'a\r\n')

    def test_invalid_save_does_not_rescan_approximate_buffer(self):
        self.open()
        self.change([edit((0, 0), (0, 5), 'BUG')])
        self.handle('textDocument/didSave', {'textDocument': {'uri': self.uri}, 'text': 'clean\n'})
        self.assertFalse(self.server.documents[self.uri]['synchronized'])
        self.assertNotIn(self.uri, self.server.pending)


class StdioTests(Fixture, unittest.TestCase):
    def test_real_framed_incremental_save_and_shutdown(self):
        process = subprocess.Popen([sys.executable, '-I', str(LSP), '--repo', str(self.root), '--scanner', str(self.scanner)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messages = queue.Queue()
        def read():
            framer = lsp.Framer()
            while data := process.stdout.read1(65536):
                for message in framer.feed(data):
                    messages.put(message)
        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        def finish():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            thread.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        self.addCleanup(finish)
        def send(method, params, **extra):
            process.stdin.write(lsp.frame(dict(jsonrpc='2.0', method=method, params=params, **extra)))
            process.stdin.flush()
        def receive(predicate):
            until = time.monotonic() + 6
            while time.monotonic() < until:
                try:
                    msg = messages.get(timeout=0.1)
                except queue.Empty:
                    continue
                if predicate(msg):
                    return msg
            self.fail('stdio result timed out')
        send('initialize', {'rootUri': self.root.as_uri()}, id=1)
        self.assertEqual(receive(lambda m: m.get('id') == 1)['result']['capabilities']['textDocumentSync']['change'], 2)
        send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'version': 1, 'text': 'clean\n'}})
        receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics' and m['params']['diagnostics'] == [])
        send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                                       'contentChanges': [edit((0, 0), (0, 5), 'BUG')]})
        self.source.write_text('BUG\n')
        send('textDocument/didSave', {'textDocument': {'uri': self.uri}})
        result = receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics'
                         and any(d.get('code') == 'test.bug' for d in m['params']['diagnostics']))
        self.assertEqual(result['params']['version'], 2)
        send('shutdown', {}, id=2)
        receive(lambda m: m.get('id') == 2)
        send('exit', {})
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(process.stderr.read(), b'')


if __name__ == '__main__':
    unittest.main()
