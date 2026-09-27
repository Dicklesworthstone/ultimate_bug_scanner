"""LSP transport and saved-source diagnostics. Scanner doubles are explicit."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
LSP = ROOT / 'ubs-lsp'
loader = importlib.machinery.SourceFileLoader('ubs_lsp_tests', str(LSP))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

# Deliberately a scanner protocol double, never represented as UBS detection.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
source = pathlib.Path(args[args.index('--') + 1])
text = source.read_text()
with open(os.environ['SCAN_COUNT'], 'a') as stream:
    stream.write(json.dumps({'pid': os.getpid(), 'text': text, 'args': args, 'cwd': os.getcwd()}) + '\n')
if 'SLOW' in text:
    time.sleep(30)
if 'BROKEN' in text:
    print('not json')
    sys.exit(0)
if 'ERROR' in text:
    print('scanner environment failed', file=sys.stderr)
    sys.exit(2)
if 'NOSCAN' in text:
    sys.exit(3)
if 'FLOOD' in text:
    print('x' * (9 * 1024 * 1024))
    sys.exit(0)
findings = [{'rule_id': 'python.test.bug', 'message': 'unsafe example', 'file': str(source),
             'line': index + 1, 'col': 1, 'severity': 'critical', 'suppressed': False}
            for index, line in enumerate(text.splitlines()) if 'BUG' in line]
print(json.dumps({'status': 'ok', 'project': str(pathlib.Path.cwd()), 'findings': findings,
                  'totals': {'files': 1, 'critical': len(findings), 'warning': 0, 'info': 0}}))
print('scanner diagnostics stay off LSP stdout', file=sys.stderr)
sys.exit(1 if findings else 0)
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ubs-lsp-')
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        self.source = self.root / 'a.py'
        self.source.write_text('clean\n')
        self.uri = self.source.as_uri()
        self.messages = []
        env = patch.dict(os.environ, {'SCAN_COUNT': str(self.work / 'calls'), 'PYTHONDONTWRITEBYTECODE': '1'})
        env.start()
        self.addCleanup(env.stop)
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5)
        self.addCleanup(self.server.close)
        self.send('initialize', {'rootUri': self.root.as_uri()}, id=1)

    def send(self, method, params=None, **extra):
        self.server.handle({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra})

    def open(self, text=None, version=1, uri=None):
        self.send('textDocument/didOpen', {'textDocument': {'uri': uri or self.uri,
                  'version': version, 'languageId': 'python', 'text': text if text is not None else self.source.read_text()}})

    def change(self, text, version=2):
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': version},
                                           'contentChanges': [{'text': text}]})

    def save(self):
        self.send('textDocument/didSave', {'textDocument': {'uri': self.uri}})

    def wait(self, timeout=8):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            self.server.tick()
            if (not self.server.pending and not self.server.active
                    and not getattr(self.server, 'batch_pending', None) and not getattr(self.server, 'batch', None)):
                return
            time.sleep(0.015)
        self.fail('scan did not finish: ' + repr(self.messages))

    def reports(self, uri=None):
        return [item['params'] for item in self.messages
                if item.get('method') == 'textDocument/publishDiagnostics' and item['params']['uri'] == (uri or self.uri)]

    def calls(self):
        file = self.work / 'calls'
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def running(self):
        until = time.monotonic() + 3
        while time.monotonic() < until:
            self.server.tick()
            if self.calls():
                return self.calls()[-1]
            time.sleep(0.02)
        self.fail('scanner never started')


class FramingTests(unittest.TestCase):
    def test_fragmented_unicode_and_multiple_frames(self):
        documents = [{'jsonrpc': '2.0', 'method': 'hello', 'params': {'text': '🦀é\n'}}, {'id': 2, 'result': None}]
        parser = lsp.Framer()
        actual = []
        for byte in b''.join(map(lsp.frame, documents)):
            actual.extend(parser.feed(bytes([byte])))
        self.assertEqual(actual, documents)
        self.assertEqual(list(lsp.Framer().feed(b''.join(map(lsp.frame, documents)))), documents)

    def test_invalid_lengths_duplicate_headers_and_encoding(self):
        headers = [b'Content-Length: -1', b'Content-Length: 0', b'Content-Length: 999999999',
                   b'Content-Length: 2\r\ncontent-length: 2', b'Other: 2',
                   b'Content-Length: 2\r\nContent-Type: application/vscode-jsonrpc; charset=latin1']
        for header in headers:
            with self.subTest(header=header), self.assertRaises(lsp.ProtocolError):
                list(lsp.Framer().feed(header + b'\r\n\r\n{}'))

    def test_header_and_body_limits_are_checked_before_body_arrives(self):
        with self.assertRaises(lsp.ProtocolError):
            list(lsp.Framer().feed(b'x' * 8193))
        with self.assertRaises(lsp.ProtocolError):
            list(lsp.Framer().feed(b'Content-Length: 99999999\r\n\r\n'))

    def test_duplicate_json_fields_and_nonfinite_values_are_errors(self):
        for body in (b'{"id":1,"id":2}', b'{"value":NaN}', b'{broken', b'"\xff"'):
            with self.subTest(body=body), self.assertRaises(lsp.ProtocolError):
                lsp.decode_json(body)


class SourceTests(Fixture):
    def test_uri_spaces_newlines_unicode_and_dash_roundtrip(self):
        for name in ('has space.py', 'has\nnewline.py', 'é🦀.py', '--update.py'):
            path = self.root / name
            self.assertEqual(lsp.document_path(path.as_uri(), self.root), path)

    def test_nonlocal_and_escaping_uris_are_rejected(self):
        for uri in ('https://host/a.py', 'file://remote/a.py', (self.work / 'outside.py').as_uri(),
                    self.uri + '?x=1', self.uri + '#fragment', self.uri + '%00', self.uri + '%zz'):
            with self.subTest(uri=uri), self.assertRaises((lsp.ProtocolError, ValueError)):
                lsp.document_path(uri, self.root)

    def test_regular_files_only_and_no_follow_at_all_components(self):
        outside = self.work / 'outside.py'
        outside.write_text('private')
        target = self.root / 'link.py'
        target.symlink_to(outside)
        with self.assertRaises(OSError):
            lsp.read_source(self.root, target, self.server.root_id)
        directory = self.root / 'parent'
        directory.symlink_to(self.work, target_is_directory=True)
        with self.assertRaises(OSError):
            lsp.read_source(self.root, directory / 'outside.py', self.server.root_id)
        pipe = self.root / 'pipe.py'
        os.mkfifo(pipe)
        with self.assertRaises(lsp.ProtocolError):
            lsp.read_source(self.root, pipe, self.server.root_id)

    def test_content_and_identity_detect_restored_mtime_and_atomic_save(self):
        first = lsp.read_source(self.root, self.source, self.server.root_id)
        info = self.source.stat()
        self.source.write_text('BUG!!\n')
        os.utime(self.source, ns=(info.st_atime_ns, info.st_mtime_ns))
        second = lsp.read_source(self.root, self.source, self.server.root_id)
        self.assertNotEqual(first, second)
        replacement = self.work / 'replacement'
        replacement.write_text('BUG!!\n')
        os.replace(replacement, self.source)
        self.assertNotEqual(second, lsp.read_source(self.root, self.source, self.server.root_id))

    def test_bom_and_line_endings_compare_without_rewriting_source(self):
        self.source.write_bytes(b'\xef\xbb\xbfvalue = 1\r\n')
        text, _ = lsp.read_source(self.root, self.source, self.server.root_id)
        self.assertEqual(text, 'value = 1\n')
        self.assertEqual(self.source.read_bytes(), b'\xef\xbb\xbfvalue = 1\r\n')


class DiagnosticsTests(Fixture):
    def test_saved_open_publishes_rule_range_version_and_original_policy(self):
        self.source.write_text('value = "🦀"\nBUG 🦀\n')
        self.open()
        self.wait()
        report = self.reports()[-1]
        self.assertEqual(report['version'], 1)
        diagnostic = report['diagnostics'][0]
        self.assertEqual(diagnostic['code'], 'python.test.bug')
        self.assertEqual(diagnostic['severity'], 1)
        self.assertEqual(diagnostic['range'], {'start': {'line': 1, 'character': 0}, 'end': {'line': 1, 'character': 6}})
        call = self.calls()[0]
        self.assertEqual(call['args'], ['--ci', '--no-auto-update', '--no-color', '--format=json', '--', str(self.source)])
        self.assertEqual(call['cwd'], str(self.root))

    def test_unsaved_open_never_runs_scanner_or_changes_disk(self):
        self.open(text='BUG unsaved\n')
        self.wait()
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unsaved')
        self.assertEqual(self.source.read_text(), 'clean\n')

    def test_change_invalidates_old_diagnostics_and_save_runs_new_bytes(self):
        self.source.write_text('BUG\n')
        self.open()
        self.wait()
        self.change('clean\n')
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unsaved')
        self.source.write_text('clean\n')
        self.save()
        self.wait()
        self.assertEqual(self.reports()[-1], {'uri': self.uri, 'version': 2, 'diagnostics': []})
        self.assertEqual(len(self.calls()), 2)

    def test_obsolete_scan_is_cancelled_and_never_published(self):
        self.source.write_text('SLOW clean\n')
        self.open()
        old = self.running()
        self.change('BUG latest\n')
        marker = len(self.messages)
        self.source.write_text('BUG latest\n')
        self.save()
        self.wait()
        diagnostics = self.reports()[-1]['diagnostics']
        self.assertEqual(diagnostics[0]['code'], 'python.test.bug')
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.assertFalse(any(item.get('method') == 'textDocument/publishDiagnostics' and item['params'].get('version') == 1
                             for item in self.messages[marker:]))

    def test_close_cancels_work_clears_diagnostics_and_reopen_is_new_generation(self):
        self.source.write_text('SLOW\n')
        self.open()
        old = self.running()
        self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
        self.source.write_text('BUG\n')
        self.open(version=1)
        self.wait()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'python.test.bug')
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)

    def test_bad_json_environment_failure_and_no_targets_never_publish_clean(self):
        for text, expected in [('BROKEN', 'ubs.unverified'), ('ERROR', 'ubs.unverified'), ('NOSCAN', 'ubs.not-scanned')]:
            with self.subTest(text=text):
                if self.uri in self.server.documents:
                    self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
                self.source.write_text(text)
                self.open()
                self.wait()
                self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], expected)

    def test_timeout_and_flood_are_explicit_failures(self):
        for text in ('SLOW', 'FLOOD'):
            with self.subTest(text=text):
                if self.uri in self.server.documents:
                    self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
                self.server.timeout = 0.15
                self.source.write_text(text)
                self.open()
                self.wait()
                self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_source_changed_between_completion_and_publication_is_not_clean(self):
        self.open()
        self.running()
        until = time.monotonic() + 3
        while not all(future.done() for future in self.server.active) and time.monotonic() < until:
            time.sleep(0.01)
        self.source.write_text('BUG edited outside editor\n')
        self.wait()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_suppression_project_records_and_advisory_ast_channel(self):
        base = {'rule_id': 'py.example', 'file': str(self.source), 'line': 1, 'severity': 'warning', 'message': 'finding'}
        report = {'status': 'ok', 'totals': {'files': 1}, 'findings': [{**base, 'suppressed': True}],
                  'ast_findings': [{**base, 'rule_id': 'py.ast'}]}
        diagnostics = lsp.report_diagnostics(report, self.source, self.root, 'clean\n', 0)
        self.assertEqual([d['code'] for d in diagnostics], ['py.ast'])
        report['findings'].append({**base, 'scope': 'project_aggregate', 'file': '', 'line': 0, 'count': 4})
        self.assertIn('Project-level', lsp.report_diagnostics(report, self.source, self.root, 'clean\n', 1)[0]['message'])

    def test_malformed_or_foreign_findings_never_create_false_source_diagnostics(self):
        finding = {'rule_id': 'py.bug', 'message': 'BUG', 'file': str(self.source), 'line': 1, 'severity': 'critical'}
        for update in ({'line': True}, {'line': 40}, {'severity': 'unknown'}, {'suppressed': 'yes'}):
            report = {'status': 'ok', 'totals': {'files': 1}, 'findings': [{**finding, **update}]}
            with self.subTest(update=update), self.assertRaises(lsp.ProtocolError):
                lsp.report_diagnostics(report, self.source, self.root, 'clean', 1)
        report['findings'] = [{**finding, 'file': '/outside/private.py'}]
        self.assertEqual(lsp.report_diagnostics(report, self.source, self.root, 'clean', 1)[0]['code'], 'ubs.incomplete-display')

    def test_document_and_memory_limits_do_not_launch_extra_scans(self):
        with patch.object(lsp, 'MAX_DOCUMENTS', 0):
            self.open()
        self.assertEqual(self.server.documents, {})
        with patch.object(lsp, 'MAX_TEXT_TOTAL', 2):
            self.open()
        self.assertEqual(self.server.documents, {})
        self.assertEqual(self.calls(), [])

    def test_invalid_change_cannot_leave_earlier_scan_eligible(self):
        self.source.write_text('SLOW\n')
        self.open()
        self.running()
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                  'contentChanges': [{'range': {}, 'text': 'BUG'}]})
        self.wait()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_shutdown_is_responsive_during_scan_and_method_errors_are_typed(self):
        self.source.write_text('SLOW\n')
        self.open()
        old = self.running()
        self.send('textDocument/hover', {}, id=8)
        self.assertEqual(self.messages[-1]['error']['code'], -32601)
        self.send('shutdown', id=9)
        self.assertEqual(self.messages[-1], {'jsonrpc': '2.0', 'id': 9, 'result': None})
        self.wait()
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.send('exit')
        self.assertEqual(self.server.exit_code, 0)

    def test_invalid_change_then_save_cannot_verify_an_old_buffer(self):
        self.open()
        self.wait()
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                  'contentChanges': [{'range': {}, 'text': 'BUG'}]})
        self.save()
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.change('BUG\n', version=3)
        self.source.write_text('BUG\n')
        self.save()
        self.wait()
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'python.test.bug')

    def test_invalid_rpc_and_requests_before_initialize(self):
        self.server.handle([])
        self.assertEqual(self.messages[-1]['error']['code'], -32600)
        self.server.handle({'jsonrpc': '2.0', 'id': True, 'method': 'initialize'})
        self.assertIsNone(self.messages[-1]['id'])
        fresh = lsp.Server(self.root, self.scanner, self.messages.append)
        self.addCleanup(fresh.close)
        fresh.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'shutdown'})
        self.assertEqual(self.messages[-1]['error']['code'], -32002)


class StdioTests(Fixture):
    def test_real_stdio_framing_open_edit_save_and_shutdown(self):
        process = subprocess.Popen([sys.executable, '-I', str(LSP), '--repo', str(self.root), '--scanner', str(self.scanner)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messages = queue.Queue()
        def read():
            parser = lsp.Framer()
            while data := os.read(process.stdout.fileno(), 65536):
                for message in parser.feed(data):
                    messages.put(message)
        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        def cleanup():
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stdin.close()
            thread.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
        self.addCleanup(cleanup)
        def send(method, params=None, **extra):
            process.stdin.write(lsp.frame({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra}))
            process.stdin.flush()
        def receive(predicate):
            until = time.monotonic() + 8
            while time.monotonic() < until:
                try:
                    message = messages.get(timeout=0.1)
                except queue.Empty:
                    continue
                if predicate(message):
                    return message
            self.fail('No expected LSP message')
        send('initialize', {'rootUri': self.root.as_uri()}, id='init')
        capabilities = receive(lambda m: m.get('id') == 'init')['result']['capabilities']
        self.assertEqual(capabilities['positionEncoding'], 'utf-16')
        self.assertEqual(capabilities['textDocumentSync']['change'], 2)
        send('initialized')
        send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'text': 'clean\n', 'version': 1}})
        receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics' and m['params']['diagnostics'] == [])
        send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2}, 'contentChanges': [{'text': 'BUG\n'}]})
        receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics' and m['params']['diagnostics'][0]['code'] == 'ubs.unsaved')
        self.source.write_text('BUG\n')
        send('textDocument/didSave', {'textDocument': {'uri': self.uri}, 'text': 'BUG\n'})
        receive(lambda m: m.get('method') == 'textDocument/publishDiagnostics' and m['params']['diagnostics'][0]['code'] == 'python.test.bug')
        send('shutdown', id='shutdown')
        receive(lambda m: m.get('id') == 'shutdown')
        send('exit')
        process.wait(timeout=5)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr.read(), b'')
        self.assertEqual(len(self.calls()), 2)

    def test_truncated_frame_is_visible_error_and_does_not_scan(self):
        result = subprocess.run([sys.executable, '-I', str(LSP), '--repo', str(self.root), '--scanner', str(self.scanner)],
                                input=b'Content-Length: 200\r\n\r\n{}', capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'Incomplete', result.stderr)
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(os.environ.get('UBS_LSP_E2E') == '1', 'set UBS_LSP_E2E=1 for actual UBS integration')
class RealScannerTests(Fixture):
    def test_real_ubs_findings_on_open_and_after_saved_edit(self):
        self.server.scanner = ROOT / 'ubs'
        self.server.timeout = 120
        self.source.write_text('eval(input())\n')
        self.open()
        self.wait(timeout=150)
        self.assertIn('python.taint.eval', [d['code'] for d in self.reports()[-1]['diagnostics']])
        self.change('value = 1\n')
        self.source.write_text('value = 1\n')
        self.save()
        self.wait(timeout=150)
        self.assertEqual(self.reports()[-1]['diagnostics'], [])


if __name__ == '__main__':
    unittest.main()
