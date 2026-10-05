"""Native LSP diagnostic pulls; subprocess scanners below are protocol doubles.

These tests exercise the real adapter, not UBS detector accuracy. No network,
third-party packages, or changes to the scanned checkout are required.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
LSP = ROOT / 'ubs-lsp'
loader = importlib.machinery.SourceFileLoader('ubs_lsp_pull_tests', str(LSP))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

# Explicit scanner protocol double: its marker vocabulary is NOT a UBS rule.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
paths = [pathlib.Path(value) for value in args[args.index('--') + 1:]]
texts = [path.read_text() for path in paths]
with open(os.environ['UBS_PULL_TEST_CALLS'], 'a') as output:
    output.write(json.dumps({'args': args, 'cwd': os.getcwd(), 'texts': texts}) + '\n')
if any('SLOW' in text for text in texts):
    time.sleep(30)
if any('DELAY' in text for text in texts):
    time.sleep(0.15)
if any('ERROR' in text for text in texts):
    print('explicit scanner failure', file=sys.stderr)
    sys.exit(2)
if any('INVALID' in text for text in texts):
    print('not a JSON report')
    sys.exit(0)
if any('NOSCAN' in text for text in texts):
    sys.exit(3)
findings = [{'rule_id': 'python.test.marker', 'message': 'test-only unsafe marker',
             'file': str(path), 'line': number, 'severity': 'critical'}
            for path, text in zip(paths, texts)
            for number, line in enumerate(text.splitlines(), 1) if 'BUG' in line]
print(json.dumps({'status': 'ok', 'project': os.getcwd(), 'findings': findings,
                  'totals': {'files': len(paths), 'critical': len(findings), 'warning': 0, 'info': 0}}))
print('scanner stderr must never enter the LSP stream', file=sys.stderr)
sys.exit(1 if findings else 0)
'''


class PullFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ubs-pull-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('clean\n')
        self.uri = self.source.as_uri()
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        self.call_file = self.work / 'calls'
        environment = patch.dict(os.environ, {'UBS_PULL_TEST_CALLS': str(self.call_file),
                                              'PYTHONDONTWRITEBYTECODE': '1'})
        environment.start()
        self.addCleanup(environment.stop)
        self.messages = []
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=2)
        self.addCleanup(self.server.close)

    def start(self, *, pull=True, refresh=False, initialized=True):
        capabilities = {'textDocument': {'diagnostic': {}},
                        'workspace': {'diagnostics': {'refreshSupport': refresh}}} if pull else {}
        self.send('initialize', {'rootUri': self.root.as_uri(), 'capabilities': capabilities}, id=1)
        if initialized:
            self.send('initialized')

    def send(self, method, params=None, **extra):
        self.server.handle({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra})

    def open(self, *, uri=None, text=None, version=1):
        self.send('textDocument/didOpen', {'textDocument': {'uri': uri or self.uri, 'version': version,
                  'languageId': 'python', 'text': self.source.read_text() if text is None else text}})

    def pull(self, request_id=10, *, uri=None, previous=None, **extra):
        params = {'textDocument': {'uri': uri or self.uri}, **extra}
        if previous is not None:
            params['previousResultId'] = previous
        self.send('textDocument/diagnostic', params, id=request_id)

    def response(self, request_id):
        return next((message for message in reversed(self.messages)
                     if message.get('id') == request_id and 'method' not in message), None)

    def until(self, condition, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.server.tick()
            if condition():
                return
            time.sleep(0.01)
        self.fail('Timed out; full adapter messages: ' + repr(self.messages))

    def result(self, request_id=10):
        self.until(lambda: self.response(request_id) is not None)
        message = self.response(request_id)
        self.assertNotIn('error', message, message)
        return message['result']

    def idle(self):
        self.until(lambda: not (self.server.active or self.server.pending or self.server.batch or self.server.batch_pending))

    def calls(self):
        return [json.loads(line) for line in self.call_file.read_text().splitlines()] if self.call_file.exists() else []

    def refreshes(self):
        return [message for message in self.messages if message.get('method') == 'workspace/diagnostic/refresh']

    def acknowledge_refresh(self):
        self.server.handle({'jsonrpc': '2.0', 'id': 'ubs-diagnostic-refresh', 'result': None})


class DocumentPullTests(PullFixture):
    def test_negotiation_and_legacy_push_fallback(self):
        self.start(pull=False)
        self.assertNotIn('diagnosticProvider', self.response(1)['result']['capabilities'])
        self.open()
        self.idle()
        pushed = [message for message in self.messages if message.get('method') == 'textDocument/publishDiagnostics']
        self.assertEqual(pushed[-1]['params'], {'uri': self.uri, 'version': 1, 'diagnostics': []})
        self.pull()
        self.assertEqual(self.response(10)['error']['code'], -32602)

    def test_full_report_uses_actual_scan_ranges_and_policy(self):
        self.start()
        capabilities = self.response(1)['result']['capabilities']
        self.assertEqual(capabilities['diagnosticProvider'], {'identifier': 'ubs', 'interFileDependencies': True,
                                                             'workspaceDiagnostics': False})
        self.source.write_text('clean\nBUG 🦀\n')
        self.server.policy = ('--profile=strict', '--fail-on-warning')
        self.open(version=7)
        self.pull(identifier='ubs')
        report = self.result()
        self.assertEqual(report['kind'], 'full')
        self.assertEqual(len(report['resultId']), 64)
        self.assertEqual(report['items'][0]['code'], 'python.test.marker')
        self.assertEqual(report['items'][0]['range']['end'], {'line': 1, 'character': 6})
        self.assertEqual(self.calls()[0]['args'], ['--ci', '--no-auto-update', '--no-color', '--format=json',
                                                  '--profile=strict', '--fail-on-warning', '--', str(self.source)])
        self.assertFalse(any(message.get('method') == 'textDocument/publishDiagnostics' for message in self.messages))

    def test_matching_result_id_returns_unchanged_after_fresh_scan(self):
        self.start()
        self.open()
        self.pull()
        first = self.result()
        self.assertEqual(first['items'], [])
        self.pull(11, previous=first['resultId'])
        self.assertEqual(self.result(11), {'kind': 'unchanged', 'resultId': first['resultId']})
        self.assertEqual(len(self.calls()), 2, 'unchanged must not bless a stale cached clean scan')

    def test_concurrent_subscribers_share_one_scan(self):
        self.start()
        self.source.write_text('DELAY BUG\n')
        self.open()
        self.pull(10)
        self.until(lambda: bool(self.calls()))
        self.pull(11)
        self.assertEqual(self.result(10), self.result(11))
        self.assertEqual(len(self.calls()), 1)

    def test_cancellation_detaches_only_one_subscriber(self):
        self.start()
        self.source.write_text('DELAY BUG\n')
        self.open()
        self.pull(10)
        self.pull(11)
        self.send('$/cancelRequest', {'id': 10})
        self.assertEqual(self.response(10)['error']['code'], -32800)
        self.assertEqual(self.result(11)['items'][0]['code'], 'python.test.marker')
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(sum(message.get('id') == 10 for message in self.messages), 1)

    def test_content_change_cancels_old_version_before_new_pull(self):
        self.start()
        self.source.write_text('SLOW\n')
        self.open()
        self.pull()
        self.until(lambda: bool(self.calls()))
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                                           'contentChanges': [{'text': 'new unsaved\n'}]})
        self.assertEqual(self.response(10)['error'], {'code': -32802, 'message': 'Diagnostic input was invalidated',
                                                     'data': {'retriggerRequest': True}})
        self.pull(11)
        self.assertEqual(self.result(11)['items'][0]['code'], 'ubs.unsaved')
        self.assertEqual(sum(message.get('id') == 10 for message in self.messages), 1)

    def test_unobserved_disk_edit_never_reuses_clean_result(self):
        self.start()
        self.open()
        self.pull()
        first = self.result()
        info = self.source.stat()
        self.source.write_text('BUG!!\n')
        os.utime(self.source, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.pull(11, previous=first['resultId'])
        report = self.result(11)
        self.assertEqual(report['kind'], 'full')
        self.assertEqual(report['items'][0]['code'], 'ubs.unsaved')
        self.assertNotEqual(report['resultId'], first['resultId'])

    def test_source_change_during_scan_returns_unverified_not_clean(self):
        self.start()
        self.source.write_text('DELAY clean\n')
        self.open()
        self.pull()
        self.until(lambda: bool(self.calls()))
        self.source.write_text('BUG\n')
        self.assertEqual(self.result()['items'][0]['code'], 'ubs.unverified')

    def test_version_is_part_of_result_id_even_when_diagnostics_are_empty(self):
        self.start()
        self.open()
        self.pull()
        first = self.result()
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                                           'contentChanges': [{'text': 'clean\n'}]})
        self.pull(11, previous=first['resultId'])
        second = self.result(11)
        self.assertEqual(second['kind'], 'full')
        self.assertEqual(second['items'], [])
        self.assertNotEqual(first['resultId'], second['resultId'])

    def test_result_id_is_scoped_to_uri(self):
        self.start()
        self.open()
        self.pull()
        first = self.result()
        other = self.root / 'b.py'
        other.write_text('clean\n')
        self.open(uri=other.as_uri(), text='clean\n')
        self.pull(11, uri=other.as_uri(), previous=first['resultId'])
        self.assertEqual(self.result(11)['kind'], 'full')

    def test_errors_and_no_scan_remain_visible_in_full_reports(self):
        self.start()
        for index, marker in enumerate(('ERROR', 'INVALID', 'NOSCAN')):
            with self.subTest(marker=marker):
                self.source.write_text(marker + '\n')
                self.open()
                self.pull(10 + index)
                report = self.result(10 + index)
                self.assertEqual(report['kind'], 'full')
                self.assertEqual(report['items'][0]['code'], 'ubs.not-scanned' if marker == 'NOSCAN' else 'ubs.unverified')
                self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})

    def test_scanner_timeout_is_not_a_clean_report(self):
        self.start()
        self.server.timeout = 0.1
        self.source.write_text('SLOW\n')
        self.open()
        self.pull()
        report = self.result()
        self.assertEqual(report['items'][0]['code'], 'ubs.unverified')
        self.assertIn('timed out', report['items'][0]['message'])

    def test_document_close_and_shutdown_finish_outstanding_requests(self):
        self.start()
        self.open()
        self.pull(10)
        self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
        self.assertFalse(self.response(10)['error']['data']['retriggerRequest'])
        self.open()
        self.pull(11)
        self.send('shutdown', id=99)
        self.assertFalse(self.response(11)['error']['data']['retriggerRequest'])
        self.assertIsNone(self.response(99)['result'])
        self.assertEqual(self.server.pulls, {})
        self.server.tick()
        self.assertEqual(self.calls(), [])

    def test_invalid_params_do_not_scan_or_broaden_scope(self):
        self.start()
        self.open()
        self.idle()
        bad = [{'textDocument': {'uri': (self.work / 'outside.py').as_uri()}},
               {'textDocument': {'uri': (self.root / 'closed.py').as_uri()}},
               {'textDocument': {'uri': self.uri}, 'identifier': 'other'},
               {'textDocument': {'uri': self.uri}, 'previousResultId': False},
               {'textDocument': {'uri': self.uri}, 'previousResultId': 'x' * 257},
               {'textDocument': []}]
        for index, params in enumerate(bad, 20):
            with self.subTest(params=params):
                self.send('textDocument/diagnostic', params, id=index)
                self.assertEqual(self.response(index)['error']['code'], -32602)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.server.pulls, {})

    def test_duplicate_outstanding_id_cannot_replace_subscriber(self):
        self.start()
        self.open()
        self.pull(10)
        self.pull(10)
        self.assertEqual(self.response(10)['error']['code'], -32600)
        self.idle()
        self.assertEqual(sum(message.get('id') == 10 for message in self.messages), 1)
        self.assertEqual(self.server.pulls, {})

    def test_admission_and_request_deadlines_are_bounded(self):
        self.start()
        self.open()
        with patch.object(lsp, 'MAX_DIAGNOSTIC_REQUESTS', 2):
            self.pull(10)
            self.pull(11)
            self.pull(12)
        self.assertEqual(len(self.server.pulls), 2)
        self.assertFalse(self.response(12)['error']['data']['retriggerRequest'])
        self.server.pulls[10]['deadline'] = 0
        self.server.tick()
        self.assertIn('timed out', self.response(10)['error']['message'])
        self.assertEqual(self.result(11)['kind'], 'full')

    def test_invalid_change_drops_old_results_and_requires_full_sync(self):
        self.start()
        self.open()
        self.pull(10)
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2}, 'contentChanges': []})
        self.assertEqual(self.response(10)['error']['code'], -32802)
        self.pull(11)
        self.assertIn(self.result(11)['items'][0]['code'], ('ubs.unsaved', 'ubs.unverified'))
        self.assertFalse(self.server.documents[self.uri]['synchronized'])

    def test_boolean_cancellation_id_cannot_cancel_integer_zero(self):
        self.start()
        self.open()
        self.pull(0)
        self.send('$/cancelRequest', {'id': False})
        self.assertIn(0, self.server.pulls)
        self.assertEqual(self.result(0)['kind'], 'full')

    def test_incremental_buffer_pull_uses_snapshot_and_does_not_edit_checkout(self):
        self.server.close()
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=2,
                                 buffer_mode=True, incremental_workspace=True)
        self.addCleanup(self.server.close)
        self.start()
        self.open(text='BUG unsaved 🦀\n')
        self.pull()
        report = self.result()
        self.assertEqual(report['items'][0]['code'], 'python.test.marker')
        self.assertEqual(report['items'][0]['data'], {'ubsSourceMode': 'buffer'})
        self.assertEqual(self.source.read_text(), 'clean\n')
        self.assertNotEqual(self.calls()[0]['cwd'], str(self.root))
        self.pull(11, previous=report['resultId'])
        self.assertEqual(self.result(11)['kind'], 'unchanged')
        self.assertEqual(len(self.calls()), 2)


class PullRefreshTests(PullFixture):
    def test_refresh_requires_capability_and_initialized_notification(self):
        self.start(refresh=True, initialized=False)
        self.open()
        self.server.tick()
        self.assertEqual(self.refreshes(), [])
        self.send('initialized')
        self.server.tick()
        self.assertEqual(len(self.refreshes()), 1)

    def test_refresh_is_coalesced_and_pull_completion_does_not_loop(self):
        self.start(refresh=True)
        self.open()
        self.pull()
        self.result()
        self.assertEqual(len(self.refreshes()), 1)
        self.acknowledge_refresh()
        self.pull(11)
        self.result(11)
        self.server.tick()
        self.assertEqual(len(self.refreshes()), 1, 'a pull must never trigger another refresh')
        self.send('textDocument/didSave', {'textDocument': {'uri': self.uri}})
        self.send('textDocument/didSave', {'textDocument': {'uri': self.uri}})
        self.server.tick()
        self.assertEqual(len(self.refreshes()), 2)

    def test_dependency_event_cancels_inflight_pull_and_requests_refresh(self):
        self.start(refresh=True)
        self.open()
        self.pull()
        self.server.tick()
        self.acknowledge_refresh()
        self.send('workspace/didChangeWatchedFiles', {'changes': [{'uri': (self.root / '.ubsignore').as_uri(), 'type': 2}]})
        self.assertEqual(self.response(10)['error']['code'], -32802)
        self.server.tick()
        self.assertEqual(len(self.refreshes()), 2)
        self.pull(11)
        self.assertEqual(self.result(11)['kind'], 'full')

    def test_rejected_refresh_is_not_retried_in_a_loop(self):
        self.start(refresh=True)
        self.open()
        self.server.tick()
        self.server.handle({'jsonrpc': '2.0', 'id': 'ubs-diagnostic-refresh',
                            'error': {'code': -32601, 'message': 'unsupported'}})
        self.send('textDocument/didSave', {'textDocument': {'uri': self.uri}})
        self.idle()
        self.assertEqual(len(self.refreshes()), 1)
        self.pull()
        self.assertEqual(self.result()['kind'], 'full')

    def test_unacknowledged_refresh_times_out_without_breaking_pulls(self):
        self.start(refresh=True)
        self.open()
        self.server.tick()
        self.server.refresh_deadline = 0
        self.server.tick()
        self.assertFalse(self.server.refresh_supported)
        self.pull()
        self.assertEqual(self.result()['kind'], 'full')
        self.assertEqual(len(self.refreshes()), 1)

    def test_no_refresh_requests_without_capability(self):
        self.start(refresh=False)
        self.open()
        self.pull()
        self.result()
        self.assertEqual(self.refreshes(), [])


class PullWireTests(PullFixture):
    def test_real_stdio_adapter_full_unchanged_and_shutdown(self):
        process = subprocess.Popen([sys.executable, str(LSP), '--repo', str(self.root), '--scanner', str(self.scanner)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        parser = lsp.Framer()
        received = []
        stderr = bytearray()
        def send(method, params=None, **extra):
            process.stdin.write(lsp.frame({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra}))
            process.stdin.flush()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                def response(request_id):
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        for message in received:
                            if message.get('id') == request_id and 'method' not in message:
                                return message
                        for key, _ in selector.select(0.05):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                self.fail('Adapter closed before reply: ' + stderr.decode('utf-8', 'replace'))
                            if key.data == 'stdout':
                                received.extend(parser.feed(chunk))
                            else:
                                stderr.extend(chunk)
                    self.fail('No wire reply: ' + repr(received) + repr(bytes(stderr)))
                send('initialize', {'rootUri': self.root.as_uri(), 'capabilities': {'textDocument': {'diagnostic': {}}}}, id=1)
                self.assertIn('diagnosticProvider', response(1)['result']['capabilities'])
                send('initialized')
                send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'languageId': 'python', 'version': 1, 'text': 'clean\n'}})
                send('textDocument/diagnostic', {'textDocument': {'uri': self.uri}}, id=2)
                first = response(2)['result']
                self.assertEqual(first['items'], [])
                send('textDocument/diagnostic', {'textDocument': {'uri': self.uri}, 'previousResultId': first['resultId']}, id=3)
                self.assertEqual(response(3)['result']['kind'], 'unchanged')
                send('shutdown', id=4)
                self.assertIsNone(response(4)['result'])
                send('exit')
                self.assertEqual(process.wait(timeout=3), 0)
                self.assertEqual(stderr, b'')
                self.assertEqual(len(self.calls()), 2)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
