"""Partial scanner envelopes retain evidence, never certify clean coverage.

The subprocess is an explicit scanner protocol double, not a detector oracle.
Every generated source and transcript is retained under test-suite/artifacts.
The same tests can target an unmodified parent via UBS_LSP_TEST_SUBJECT.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SUBJECT = Path(os.environ.get('UBS_LSP_TEST_SUBJECT', str(ROOT / 'ubs-lsp')))
loader = importlib.machinery.SourceFileLoader('lsp_partial_subject', str(SUBJECT))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

SCANNER = '''import json, pathlib, sys
settings = pathlib.Path(__file__).with_suffix('.json')
config = json.loads(settings.read_text(encoding='utf-8'))
paths = sys.argv[sys.argv.index('--') + 1:]
with settings.with_suffix('.jsonl').open('a', encoding='utf-8') as stream:
    stream.write(json.dumps({'args': sys.argv[1:], 'cwd': str(pathlib.Path.cwd()),
                             'sources': {p: pathlib.Path(p).read_text() for p in paths}}) + '\\n')
if config.get('mutate'):
    pathlib.Path(paths[0]).write_text('changed after analysis\\n', encoding='utf-8')
report = config['report']
if config.get('relative'):
    report['project'] = str(pathlib.Path.cwd())
print(json.dumps(report) if not config.get('malformed') else '{broken')
print('explicit scanner-double stderr', file=sys.stderr)
sys.exit(config['exit'])
'''


class PartialReports(unittest.TestCase):
    def setUp(self):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix='partial-' + self._testMethodName + '-', dir=artifacts))
        self.root = self.work / 'project'
        self.root.mkdir()
        self.a = self.root / 'caller.py'
        self.b = self.root / 'peer.py'
        self.a.write_text('unsafe_call()\n', encoding='utf-8')
        self.b.write_text('value = 1\n', encoding='utf-8')
        self.scanner = self.work / 'scanner.py'
        self.scanner.write_text('#!' + sys.executable + '\n' + SCANNER, encoding='utf-8')
        self.scanner.chmod(0o700)
        self.messages = []
        self.server = None
        self.report = {'status': 'partial', 'project': str(self.root),
                       'totals': {'files': 1, 'critical': 1, 'warning': 0, 'info': 0},
                       'failed_modules': [{'language': 'python', 'status': 'error',
                                           'module_error': 'HELPER_FAILED', 'message': 'SQL analysis budget exceeded'}],
                       'findings': [self.finding(self.a)]}
        self.configure()

    def finding(self, path):
        return {'rule_id': 'python.test.known-bug', 'message': 'known unsafe call',
                'file': str(path), 'line': 1, 'col': 1, 'severity': 'critical', 'suppressed': False}

    def configure(self, report=None, code=2, **options):
        self.scanner.with_suffix('.json').write_text(json.dumps({
            'report': self.report if report is None else report, 'exit': code, **options}), encoding='utf-8')

    def tearDown(self):
        if self.server is not None:
            self.server.close()
        (self.work / 'transcript.json').write_text(json.dumps(self.messages, indent=2) + '\n', encoding='utf-8')
        (self.work / 'identity.json').write_text(json.dumps({
            'test': self.id(), 'subject_sha256': hashlib.sha256(SUBJECT.read_bytes()).hexdigest(),
            'python': sys.version, 'scanner_kind': 'explicit protocol double'}), encoding='utf-8')

    def direct(self, report=None, path=None, code=2):
        return lsp.report_diagnostics(self.report if report is None else report,
                                      path or self.a, self.root, (path or self.a).read_text(), code,
                                      selected_paths=(self.a, self.b))

    def assert_partial(self, diagnostics, expected=('python.test.known-bug',)):
        self.assertEqual(diagnostics[0]['code'], 'ubs.incomplete-analysis', diagnostics)
        self.assertEqual(diagnostics[0]['severity'], 2)
        self.assertEqual([d['code'] for d in diagnostics if d['code'] == 'python.test.known-bug'], list(expected))
        self.assertTrue(all(d.get('data', {}).get('ubsAnalysisStatus') == 'partial' for d in diagnostics), diagnostics)

    def documents(self, *paths):
        return {p.as_uri(): {'path': p, 'text': p.read_text(), 'wire_text': p.read_text(),
                            'version': 1, 'generation': 1, 'synchronized': True} for p in paths}

    def scan(self, *paths):
        info = self.root.stat()
        return lsp.scan(self.scanner, self.root, self.documents(*(paths or (self.a,))),
                        (info.st_dev, info.st_ino), 5, threading.Event())

    def start(self, *, pull=False, buffer=False, incremental=False):
        if buffer:
            # Artifacts live inside the real checkout. Give each buffer fixture
            # its own native Git root instead of borrowing the checkout's config.
            result = subprocess.run(['git', 'init', '--quiet', '--template=', str(self.root)],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5,
                                 buffer_mode=buffer, incremental_workspace=incremental,
                                 scan_scope='open-documents')
        self.send('initialize', {'rootUri': self.root.as_uri(), 'capabilities': {
            'textDocument': {'diagnostic': {}}} if pull else {}}, id=1)
        self.send('initialized')
        for p in (self.a, self.b):
            self.send('textDocument/didOpen', {'textDocument': {
                'uri': p.as_uri(), 'version': 1, 'text': p.read_text()}})

    def send(self, method, params=None, **extra):
        self.server.handle({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra})

    def wait(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.server.tick()
            if not (self.server.pending or self.server.active or self.server.batch_pending or self.server.batch):
                return
            time.sleep(0.01)
        self.fail('Scan did not settle: ' + str(self.work))

    def diagnostics(self, path):
        return [m['params']['diagnostics'] for m in self.messages
                if m.get('method') == 'textDocument/publishDiagnostics'
                and m['params']['uri'] == path.as_uri()][-1]

    def reply(self, id):
        return [m for m in self.messages if m.get('id') == id][-1]

    def test_partial_report_retains_exact_rule_and_range(self):
        diagnostics = self.direct()
        self.assert_partial(diagnostics)
        self.assertEqual(diagnostics[1]['range'], {'start': {'line': 0, 'character': 0},
                                                  'end': {'line': 0, 'character': 13}})
        self.assertIn('python', diagnostics[0]['message'])
        self.assertIn('HELPER_FAILED', diagnostics[0]['message'])

    def test_error_envelope_with_findings_is_still_useful(self):
        self.report['status'] = 'error'
        self.assert_partial(self.direct())

    def test_exit_two_cannot_certify_clean_even_with_ok_envelope(self):
        self.report['status'] = 'ok'
        self.report['failed_modules'] = []
        self.assert_partial(self.direct())

    def test_partial_flag_survives_permissive_exit_zero_or_one(self):
        for code in (0, 1):
            with self.subTest(code=code):
                self.assert_partial(self.direct(code=code))

    def test_failed_module_prevents_false_complete_top_level_ok(self):
        self.report['status'] = 'ok'
        self.assert_partial(self.direct(code=0))

    def test_nested_failed_scanner_prevents_false_complete_top_level_ok(self):
        self.report['status'] = 'ok'
        self.report['failed_modules'] = []
        self.report['scanners'] = [{'language': 'python', 'status': 'timeout', 'message': 'timed out'}]
        self.assert_partial(self.direct(code=0))

    def test_incomplete_empty_peer_gets_visible_marker(self):
        self.assert_partial(self.direct(path=self.b), expected=())

    def test_empty_partial_ledger_never_looks_clean(self):
        self.report['findings'] = []
        self.report['totals']['critical'] = 0
        self.assert_partial(self.direct(), expected=())

    def test_partial_suppression_and_advisory_ledger_remain_distinct(self):
        self.report['findings'][0]['suppressed'] = True
        self.report['totals']['critical'] = 0
        self.report['ast_findings'] = [dict(self.finding(self.a), rule_id='python.test.advisory')]
        diagnostics = self.direct()
        self.assert_partial(diagnostics, expected=())
        self.assertEqual([d['code'] for d in diagnostics], ['ubs.incomplete-analysis', 'python.test.advisory'])

    def test_malformed_partial_reports_are_not_salvaged(self):
        updates = ({'findings': None}, {'findings': [None]}, {'status': 'refused'},
                   {'failed_modules': 'python'}, {'scanners': [None]},
                   {'totals': {'files': 1, 'critical': 2, 'warning': 0, 'info': 0}},
                   {'totals': {'files': True, 'critical': 1, 'warning': 0, 'info': 0}})
        for update in updates:
            with self.subTest(update=update), self.assertRaises(lsp.ProtocolError):
                self.direct(dict(self.report, **update))
        for change in ({'line': 90}, {'severity': 'fatal'}, {'line': True}, {'suppressed': 'yes'}):
            report = copy.deepcopy(self.report)
            report['findings'][0].update(change)
            with self.subTest(change=change), self.assertRaises(lsp.ProtocolError):
                self.direct(report)

    def test_zero_count_missing_ledger_is_allowed_only_for_complete_scan(self):
        report = {'status': 'ok', 'totals': {'files': 1, 'critical': 0, 'warning': 0, 'info': 0}}
        self.assertEqual(self.direct(report, code=0), [])
        for code, status in ((2, 'ok'), (0, 'partial'), (2, 'partial')):
            with self.subTest(code=code, status=status), self.assertRaises(lsp.ProtocolError):
                self.direct(dict(report, status=status), code=code)

    def test_marker_survives_display_limits(self):
        self.report['findings'] *= 20
        self.report['totals']['critical'] = 20
        with patch.object(lsp, 'MAX_DIAGNOSTICS', 4):
            diagnostics = self.direct()
        self.assertEqual(len(diagnostics), 4)
        self.assertEqual(diagnostics[0]['code'], 'ubs.incomplete-analysis')
        self.assertEqual(diagnostics[-1]['code'], 'ubs.incomplete-display')

    def test_failure_detail_is_bounded(self):
        self.report['failed_modules'] = [{'language': 'x' * 10000, 'status': 'error',
                                         'message': 'm' * 10000}] * 100
        diagnostics = self.direct()
        self.assert_partial(diagnostics)
        self.assertLess(len(diagnostics[0]['message']), 8192)

    def test_real_subprocess_partial_exit_retains_findings_and_source_guard(self):
        result = self.scan()
        self.assert_partial(result[self.a.as_uri()][0])
        self.assertIsNotNone(result[self.a.as_uri()][1])

    def test_partial_group_missing_coverage_marks_every_peer(self):
        self.start()
        self.wait()
        self.assert_partial(self.diagnostics(self.a))
        self.assert_partial(self.diagnostics(self.b), expected=())

    def test_complete_group_missing_coverage_is_still_rejected(self):
        report = dict(self.report, status='ok', failed_modules=[])
        self.configure(report, code=1)
        with self.assertRaisesRegex(lsp.ProtocolError, 'coverage'):
            self.scan(self.a, self.b)

    def test_invalid_process_exits_and_refusals_are_not_source_evidence(self):
        for code, report in ((7, self.report), (2, dict(self.report, status='refused'))):
            with self.subTest(code=code):
                self.configure(report, code=code)
                with self.assertRaises(lsp.ProtocolError):
                    self.scan()

    def test_source_change_during_partial_scan_rejects_stale_evidence(self):
        self.configure(mutate=True)
        with self.assertRaisesRegex(lsp.ProtocolError, 'changed'):
            self.scan()

    def test_partial_publication_revalidates_saved_source(self):
        self.start()
        self.server.batch_due = 0
        self.server.tick()
        self.server.batch[0].result(timeout=5)
        self.a.write_text('different version\n', encoding='utf-8')
        self.wait()
        self.assertEqual(self.diagnostics(self.a)[0]['code'], 'ubs.unverified')
        self.assertNotIn('python.test.known-bug', [d['code'] for d in self.diagnostics(self.a)])

    def test_partial_pull_to_complete_pull_never_reuses_partial_result_id(self):
        self.start(pull=True)
        self.send('textDocument/diagnostic', {'textDocument': {'uri': self.a.as_uri()}}, id=10)
        self.wait()
        first = self.reply(10)['result']
        self.assert_partial(first['items'])
        clean = {'status': 'ok', 'totals': {'files': 2, 'critical': 0, 'warning': 0, 'info': 0}, 'findings': []}
        self.configure(clean, code=0)
        self.send('textDocument/diagnostic', {'textDocument': {'uri': self.a.as_uri()},
                                           'previousResultId': first['resultId']}, id=11)
        self.wait()
        second = self.reply(11)['result']
        self.assertEqual((second['kind'], second['items']), ('full', []))
        self.assertNotEqual(first['resultId'], second['resultId'])

    def test_delayed_partial_pull_revalidates_all_peers(self):
        self.start(pull=True)
        self.server.output_available = lambda: 0
        self.send('textDocument/diagnostic', {'textDocument': {'uri': self.a.as_uri()}}, id=10)
        self.wait()
        self.b.write_text('peer changed\n', encoding='utf-8')
        self.server.output_available = lambda: 2 * lsp.MAX_MESSAGE
        self.server.tick()
        self.assertEqual(self.reply(10)['error']['code'], -32802)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_snapshot_partial_keeps_original_uris_and_both_status_tags(self):
        self.report['findings'][0]['file'] = 'caller.py'
        self.report['failed_modules'][0]['message'] = 'analysis incomplete'
        self.configure(relative=True)
        self.start(buffer=True)
        self.wait()
        self.assert_partial(self.diagnostics(self.a))
        self.assert_partial(self.diagnostics(self.b), expected=())
        for path in (self.a, self.b):
            for diagnostic in self.diagnostics(path):
                self.assertEqual(diagnostic['data']['ubsSourceMode'], 'buffer')
                self.assertNotIn('ubs-lsp-buffer-', diagnostic['message'])
        self.assertEqual(self.a.read_text(), 'unsafe_call()\n')

    def test_partial_incremental_scan_discards_private_cache_not_source_evidence(self):
        self.report['findings'][0]['file'] = 'caller.py'
        self.configure(relative=True)
        self.start(buffer=True, incremental=True)
        self.wait()
        self.assert_partial(self.diagnostics(self.a))
        self.assertIsNone(self.server.workspace_cache.retained)
        clean = {'status': 'ok', 'totals': {'files': 2, 'critical': 0, 'warning': 0, 'info': 0}, 'findings': []}
        self.configure(clean, code=0, relative=True)
        self.send('textDocument/didSave', {'textDocument': {'uri': self.a.as_uri()}})
        self.wait()
        self.assertEqual(self.diagnostics(self.a), [])
        self.assertIsNotNone(self.server.workspace_cache.retained)

    def test_disposed_partial_buffer_pull_still_guards_unselected_context(self):
        support = self.root / 'support.py'
        support.write_text('context = 1\n', encoding='utf-8')
        self.report['findings'][0]['file'] = 'caller.py'
        self.configure(relative=True)
        self.start(pull=True, buffer=True, incremental=True)
        self.server.output_available = lambda: 0
        self.send('textDocument/diagnostic', {'textDocument': {'uri': self.a.as_uri()}}, id=10)
        self.wait()
        self.assertIsNone(self.server.workspace_cache.retained)
        pending = self.server.pulls[10]['reply']
        self.assert_partial(pending['items'])
        support.write_text('context = 2\n', encoding='utf-8')
        self.server.output_available = lambda: 2 * lsp.MAX_MESSAGE
        self.server.tick()
        self.assertEqual(self.reply(10)['error']['code'], -32802)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_disposed_partial_buffer_pull_can_deliver_when_context_is_unchanged(self):
        self.report['findings'][0]['file'] = 'caller.py'
        self.configure(relative=True)
        self.start(pull=True, buffer=True, incremental=True)
        self.server.output_available = lambda: 0
        self.send('textDocument/diagnostic', {'textDocument': {'uri': self.a.as_uri()}}, id=10)
        self.wait()
        self.server.output_available = lambda: 2 * lsp.MAX_MESSAGE
        self.server.tick()
        self.assert_partial(self.reply(10)['result']['items'])
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_native_nested_git_root_is_independent_but_empty_metadata_is_not(self):
        subprocess.run(['git', 'init', '--quiet', '--template=', str(self.work)],
                       check=True, capture_output=True, timeout=10)
        info = self.root.stat()
        workspace = lsp.BufferWorkspace(self.root, (info.st_dev, info.st_ino), {},
                                       threading.Event(), time.monotonic() + 5)
        with self.assertRaisesRegex(lsp.ProtocolError, 'inherited'):
            workspace.validate_configuration()
        (self.root / '.git').mkdir()
        with self.assertRaisesRegex(lsp.ProtocolError, 'inherited'):
            workspace.validate_configuration()
        subprocess.run(['git', 'init', '--quiet', '--template=', str(self.root)],
                       check=True, capture_output=True, timeout=10)
        workspace.validate_configuration()
        (self.root / '.git').rename(self.work / 'retained-root-metadata')
        (self.root / '.git').symlink_to(self.work / 'retained-root-metadata', target_is_directory=True)
        with self.assertRaisesRegex(lsp.ProtocolError, 'inherited'):
            workspace.validate_configuration()

    def test_real_stdio_partial_result_retains_failure_and_finding(self):
        command = [sys.executable, '-I', str(SUBJECT), '--repo', str(self.root),
                   '--scanner', str(self.scanner), '--scan-timeout=5']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        wire = bytearray()
        transcript = []

        def send(method, params=None, **extra):
            body = json.dumps({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra}).encode()
            process.stdin.write(b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            process.stdin.flush()

        def receive(predicate):
            deadline = time.monotonic() + 8
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    end = wire.find(b'\r\n\r\n')
                    if end >= 0:
                        fields = dict(row.split(b':', 1) for row in bytes(wire[:end]).split(b'\r\n'))
                        size = int(fields[b'Content-Length'])
                        if len(wire) >= end + 4 + size:
                            item = json.loads(bytes(wire[end + 4:end + 4 + size]))
                            del wire[:end + 4 + size]
                            transcript.append(item)
                            if predicate(item):
                                return item
                            continue
                    if selector.select(0.05):
                        data = os.read(process.stdout.fileno(), 65536)
                        if not data:
                            self.fail('LSP exited before the expected response')
                        wire.extend(data)
            self.fail('Timed out waiting for LSP; evidence: ' + str(self.work))

        try:
            send('initialize', {'rootUri': self.root.as_uri()}, id=1)
            receive(lambda item: item.get('id') == 1)
            send('initialized')
            send('textDocument/didOpen', {'textDocument': {
                'uri': self.a.as_uri(), 'version': 1, 'text': self.a.read_text()}})
            message = receive(lambda item: item.get('method') == 'textDocument/publishDiagnostics'
                              and any(d['code'] != 'ubs.pending' for d in item['params']['diagnostics']))
            self.assert_partial(message['params']['diagnostics'])
            self.assertEqual((message['params']['uri'], message['params']['version']), (self.a.as_uri(), 1))
            send('shutdown', id=2)
            receive(lambda item: item.get('id') == 2)
            send('exit')
            process.wait(timeout=5)
            self.assertEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            (self.work / 'stdio-stderr.log').write_bytes(process.stderr.read())
            process.stderr.close()
            (self.work / 'stdio-messages.json').write_text(json.dumps(transcript, indent=2), encoding='utf-8')


if __name__ == '__main__':
    unittest.main(verbosity=2)
