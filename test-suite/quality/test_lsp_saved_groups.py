"""Saved-editor selection and invalidation contracts, with a scanner double.

The external executable below models a finding that needs two selected inputs.
It tests LSP routing and lifecycle, NOT UBS detector accuracy. It runs through
real subprocess pipes, source guards, counters and diagnostic publication.
Every source, scanner invocation and protocol transcript is retained under
artifacts. UBS_LSP_TEST_SUBJECT permits the same tests against a frozen parent.
"""
from __future__ import annotations

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
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SUBJECT = Path(os.environ.get('UBS_LSP_TEST_SUBJECT', str(ROOT / 'ubs-lsp')))
loader = importlib.machinery.SourceFileLoader('lsp_saved_group_subject', str(SUBJECT))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

SCANNER = r'''import json, os, pathlib, sys, time
args = sys.argv[1:]
paths = [pathlib.Path(value) for value in args[args.index('--') + 1:]]
texts = {str(path): path.read_text(encoding='utf-8') for path in paths}
log = pathlib.Path(__file__).with_suffix('.jsonl')
with log.open('a', encoding='utf-8') as stream:
    stream.write(json.dumps({'phase': 'start', 'pid': os.getpid(), 'args': args,
                             'cwd': os.getcwd(), 'texts': texts}) + '\n')
if any('SLOW' in text for text in texts.values()):
    time.sleep(30)
if any('ERROR' in text for text in texts.values()):
    print('intentional scanner protocol failure', file=sys.stderr)
    sys.exit(2)
findings = []
if any(text == 'SOURCE\n' for text in texts.values()):
    for path, text in texts.items():
        if text == 'SINK\n':
            findings.append({'rule_id': 'python.test.selected-dependency', 'message': 'selected input reaches sink',
                             'file': path, 'line': 1, 'col': 1, 'severity': 'critical', 'suppressed': False})
report = {'status': 'ok', 'project': os.getcwd(), 'findings': findings,
          'totals': {'files': sum('UNSUPPORTED' not in text for text in texts.values()),
                     'critical': len(findings), 'warning': 0, 'info': 0}}
with log.open('a', encoding='utf-8') as stream:
    stream.write(json.dumps({'phase': 'result', 'report': report}) + '\n')
print(json.dumps(report))
sys.exit(1 if findings else 0)
'''


class SavedGroups(unittest.TestCase):
    def setUp(self):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=artifacts))
        self.root = self.work / 'project'
        self.root.mkdir()
        self.scanner = self.work / 'scanner.py'
        self.scanner.write_text('#!' + sys.executable + '\n' + SCANNER, encoding='utf-8')
        self.scanner.chmod(0o700)
        self.helper = self.root / 'helper.py'
        self.caller = self.root / 'caller.py'
        self.helper.write_text('SOURCE\n', encoding='utf-8')
        self.caller.write_text('SINK\n', encoding='utf-8')
        self.messages = []
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5)
        # Assign after construction so the same regression corpus can exercise
        # the frozen parent, where this launch policy was not implemented.
        self.server.scan_scope = 'open-documents'
        self.started = time.perf_counter()
        self.send('initialize', {'rootUri': self.root.as_uri()}, id=1)
        self.addCleanup(self.server.close)

    def tearDown(self):
        (self.work / 'messages.json').write_text(json.dumps(self.messages, indent=2) + '\n', encoding='utf-8')
        (self.work / 'identity.json').write_text(json.dumps({
            'subject': str(SUBJECT), 'subject_sha256': hashlib.sha256(SUBJECT.read_bytes()).hexdigest(),
            'scanner_sha256': hashlib.sha256(self.scanner.read_bytes()).hexdigest(),
            'python': sys.version, 'elapsed_seconds': time.perf_counter() - self.started,
            'test': self.id(), 'scanner_kind': 'explicit protocol double',
        }, indent=2) + '\n', encoding='utf-8')

    def send(self, method, params=None, **extra):
        self.server.handle({'jsonrpc': '2.0', 'method': method, 'params': params or {}, **extra})

    def open(self, path, text=None):
        self.send('textDocument/didOpen', {'textDocument': {
            'uri': path.as_uri(), 'version': 1, 'languageId': 'python',
            'text': path.read_text(encoding='utf-8') if text is None else text}})

    def change(self, path, text, version=2):
        self.send('textDocument/didChange', {'textDocument': {'uri': path.as_uri(), 'version': version},
                                           'contentChanges': [{'text': text}]})

    def save(self, path):
        self.send('textDocument/didSave', {'textDocument': {'uri': path.as_uri()}})

    def close_document(self, path):
        self.send('textDocument/didClose', {'textDocument': {'uri': path.as_uri()}})

    def wait(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            self.server.tick()
            if not (self.server.pending or self.server.active or self.server.batch_pending or self.server.batch):
                return
            time.sleep(0.01)
        self.fail('Editor scan did not settle; retained evidence: ' + str(self.work))

    def calls(self):
        path = self.scanner.with_suffix('.jsonl')
        records = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [record for record in records if record['phase'] == 'start']

    def selected(self, call):
        args = call['args']
        return set(args[args.index('--') + 1:])

    def diagnostics(self, path):
        matches = [message['params']['diagnostics'] for message in self.messages
                   if message.get('method') == 'textDocument/publishDiagnostics'
                   and message['params']['uri'] == path.as_uri()]
        self.assertTrue(matches, self.messages)
        return matches[-1]

    def assert_group_call(self, *paths):
        self.assertEqual(self.selected(self.calls()[-1]), set(map(str, paths)))

    def assert_bug(self):
        diagnostics = self.diagnostics(self.caller)
        self.assertEqual([(item['code'], item['severity'], item['range']) for item in diagnostics], [
            ('python.test.selected-dependency', 1,
             {'start': {'line': 0, 'character': 0}, 'end': {'line': 0, 'character': 4}})])

    def pull(self, path, request_id):
        self.send('textDocument/diagnostic', {'textDocument': {'uri': path.as_uri()}}, id=request_id)

    def replies(self):
        return {message['id']: message for message in self.messages
                if 'id' in message and ('result' in message or 'error' in message)}

    def open_pair(self):
        self.open(self.helper)
        self.open(self.caller)

    def test_single_saved_document_keeps_immediate_dispatch_and_policy(self):
        self.server.policy = ('--profile=strict', '--fail-on-warning')
        self.open(self.caller)
        self.server.tick()
        self.assertEqual(len(self.server.active), 1)
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]['args'], ['--ci', '--no-auto-update', '--no-color', '--format=json',
                         '--profile=strict', '--fail-on-warning', '--', str(self.caller)])
        self.assertEqual(self.diagnostics(self.caller), [])

    def test_individual_document_mode_is_still_available(self):
        self.server.scan_scope = 'document'
        self.open_pair()
        self.wait()
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual({frozenset(self.selected(call)) for call in self.calls()},
                         {frozenset({str(self.helper)}), frozenset({str(self.caller)})})

    def test_launch_scope_is_validated_and_advertised(self):
        fresh = lsp.Server(self.root, self.scanner, self.messages.append, scan_scope='open-documents')
        try:
            fresh.handle({'jsonrpc': '2.0', 'method': 'initialize', 'id': 'scope',
                          'params': {'rootUri': self.root.as_uri()}})
            self.assertEqual(self.messages[-1]['result']['capabilities']['experimental']['ubs']['scanScope'],
                             'open-documents')
        finally:
            fresh.close()
        with self.assertRaises(lsp.ProtocolError):
            lsp.Server(self.root, self.scanner, self.messages.append, scan_scope='workspace-wide')

    def test_document_notification_cannot_change_launch_scope(self):
        self.send('workspace/didChangeConfiguration', {'settings': {'scanScope': 'document'}})
        self.open_pair()
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assert_group_call(self.helper, self.caller)

    def test_two_saved_documents_share_one_real_scanner_invocation(self):
        self.open_pair()
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assert_group_call(self.helper, self.caller)
        self.assertEqual(self.diagnostics(self.helper), [])
        self.assert_bug()

    def test_saving_helper_rechecks_unchanged_caller(self):
        self.helper.write_text('SAFE\n', encoding='utf-8')
        self.open_pair()
        self.wait()
        self.assertEqual(self.diagnostics(self.caller), [])
        self.change(self.helper, 'SOURCE\n')
        self.helper.write_text('SOURCE\n', encoding='utf-8')
        self.save(self.helper)
        self.wait()
        self.assert_group_call(self.helper, self.caller)
        self.assert_bug()

    def test_dirty_peer_prevents_a_false_clean_caller(self):
        self.open(self.helper, text='unsaved SOURCE\n')
        self.open(self.caller)
        self.wait()
        self.assertEqual(self.calls(), [])
        self.assertEqual([item['code'] for item in self.diagnostics(self.helper)], ['ubs.unsaved'])
        self.assertEqual([item['code'] for item in self.diagnostics(self.caller)], ['ubs.unverified'])
        self.assertEqual(self.helper.read_text(), 'SOURCE\n')

    def test_partial_coverage_is_unverified_for_the_entire_group(self):
        self.helper.write_text('UNSUPPORTED\n', encoding='utf-8')
        self.open_pair()
        self.wait()
        for path in (self.helper, self.caller):
            self.assertEqual([item['code'] for item in self.diagnostics(path)], ['ubs.unverified'])

    def test_scanner_failure_cannot_certify_a_peer(self):
        self.helper.write_text('ERROR\n', encoding='utf-8')
        self.open_pair()
        self.wait()
        for path in (self.helper, self.caller):
            self.assertEqual([item['code'] for item in self.diagnostics(path)], ['ubs.unverified'])

    def test_close_rechecks_survivors_against_the_new_selection(self):
        self.open_pair()
        # The manual group command is an independent passing baseline control.
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=2)
        self.wait()
        self.assert_bug()
        before = len(self.calls())
        self.close_document(self.helper)
        self.wait()
        self.assertEqual(len(self.calls()), before + 1)
        self.assert_group_call(self.caller)
        self.assertEqual(self.diagnostics(self.caller), [])
        self.assertEqual(self.diagnostics(self.helper), [])

    def test_closing_last_document_does_not_launch_an_empty_scan(self):
        self.open(self.caller)
        self.wait()
        before = len(self.calls())
        self.close_document(self.caller)
        self.wait()
        self.assertEqual(len(self.calls()), before)
        self.assertEqual(self.diagnostics(self.caller), [])
        self.assertFalse(self.server.documents)

    def test_opening_peer_cancels_an_obsolete_solo_scan(self):
        self.helper.write_text('SLOW\n', encoding='utf-8')
        self.open(self.helper)
        deadline = time.monotonic() + 3
        while not self.calls() and time.monotonic() < deadline:
            self.server.tick()
            time.sleep(0.01)
        self.assertTrue(self.calls(), 'Initial scanner did not start')
        token = next(iter(self.server.active.values()))[2]
        self.open(self.caller)
        self.assertTrue(token.is_set(), 'The old solo scan remains eligible after selection changed')
        self.change(self.helper, 'SOURCE\n')
        self.helper.write_text('SOURCE\n', encoding='utf-8')
        self.save(self.helper)
        self.wait()
        self.assert_bug()

    def test_simultaneous_pulls_share_the_complete_selection(self):
        self.server.pull_mode = True
        self.open_pair()
        self.pull(self.helper, 10)
        self.pull(self.caller, 11)
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        replies = self.replies()
        self.assertEqual(replies[10]['result']['items'], [])
        self.assertEqual([item['code'] for item in replies[11]['result']['items']],
                         ['python.test.selected-dependency'])
        self.assertFalse(self.server.pulls)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_cancelling_one_pull_keeps_its_peers_scan(self):
        self.server.pull_mode = True
        self.open_pair()
        self.pull(self.helper, 10)
        self.pull(self.caller, 11)
        self.send('$/cancelRequest', {'id': 10})
        self.wait()
        replies = self.replies()
        self.assertEqual(replies[10]['error']['code'], -32800)
        self.assertEqual([item['code'] for item in replies[11]['result']['items']],
                         ['python.test.selected-dependency'])
        self.assertEqual(len(self.calls()), 1)

    def test_backpressured_pull_revalidates_every_peer_before_delivery(self):
        self.server.pull_mode = True
        self.server.output_available = lambda: 0
        self.open_pair()
        self.pull(self.helper, 10)
        self.pull(self.caller, 11)
        self.wait()
        self.assertTrue(all('reply' in value for value in self.server.pulls.values()))
        self.helper.write_text('changed outside the editor\n', encoding='utf-8')
        self.server.output_available = lambda: 2 * lsp.MAX_MESSAGE
        self.server.tick()
        for request_id in (10, 11):
            reply = self.replies().get(request_id, {})
            self.assertIn('error', reply, (request_id, self.messages))
            self.assertEqual(reply['error']['code'], -32802)
        self.assertFalse(self.server.pulls)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_malformed_peer_change_invalidates_all_waiting_pulls(self):
        self.server.pull_mode = True
        self.server.output_available = lambda: 0
        self.open_pair()
        self.pull(self.helper, 10)
        self.pull(self.caller, 11)
        self.wait()
        self.send('textDocument/didChange', {'textDocument': {'uri': self.helper.as_uri(), 'version': 2},
                                           'contentChanges': [{'text': None}]})
        for request_id in (10, 11):
            reply = self.replies().get(request_id, {})
            self.assertIn('error', reply, (request_id, self.messages))
            self.assertEqual(reply['error']['code'], -32802)
        self.assertFalse(self.server.documents[self.helper.as_uri()]['synchronized'])
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_manual_scan_still_groups_all_open_documents(self):
        self.open_pair()
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=2)
        self.wait()
        self.assertEqual(self.replies()[2]['result'], {'queued': 2})
        self.assertEqual(len(self.calls()), 1)
        self.assert_group_call(self.helper, self.caller)
        self.assert_bug()

    def test_watched_file_refresh_still_groups_open_documents(self):
        self.open_pair()
        self.send('workspace/didChangeWatchedFiles', {'changes': [
            {'uri': (self.root / 'config.json').as_uri(), 'type': 2}]})
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assert_group_call(self.helper, self.caller)
        self.assert_bug()

    def test_real_stdio_automatically_rechecks_peers_after_save(self):
        # Independent wire framing; the fixture scanner is not a detector oracle.
        command = [sys.executable, '-I', str(SUBJECT), '--repo', str(self.root),
                   '--scanner', str(self.scanner), '--scan-timeout', '5', '--scan-scope=open-documents']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        received = bytearray()
        transcript = []
        buffer = bytearray()
        def write(*messages):
            for message in messages:
                data = json.dumps(message).encode('utf-8')
                process.stdin.write(b'Content-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data)
            process.stdin.flush()
        def until(predicate):
            deadline = time.monotonic() + 8
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    end = buffer.find(b'\r\n\r\n')
                    if end >= 0:
                        headers = dict(line.split(b':', 1) for line in bytes(buffer[:end]).split(b'\r\n'))
                        length = int(headers[b'Content-Length'].strip())
                        if len(buffer) >= end + 4 + length:
                            message = json.loads(bytes(buffer[end + 4:end + 4 + length]))
                            del buffer[:end + 4 + length]
                            transcript.append(message)
                            if predicate(message):
                                return message
                            continue
                    if selector.select(0.05):
                        data = os.read(process.stdout.fileno(), 65536)
                        self.assertTrue(data, 'Adapter exited before the expected reply')
                        received.extend(data)
                        buffer.extend(data)
            self.fail('Expected stdio message missing; transcript=' + repr(transcript))
        def notification(method, params):
            return {'jsonrpc': '2.0', 'method': method, 'params': params}
        def is_caller_diagnostic(message, code):
            if message.get('method') != 'textDocument/publishDiagnostics':
                return False
            params = message['params']
            return (params['uri'] == self.caller.as_uri()
                    and [item['code'] for item in params['diagnostics']] == ([] if code is None else [code]))
        try:
            write({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'rootUri': self.root.as_uri()}})
            until(lambda message: message.get('id') == 1)
            write(*(notification('textDocument/didOpen', {'textDocument': {
                'uri': path.as_uri(), 'version': 1, 'languageId': 'python', 'text': path.read_text()}})
                    for path in (self.helper, self.caller)))
            until(lambda message: is_caller_diagnostic(message, 'python.test.selected-dependency'))
            write(notification('textDocument/didChange', {'textDocument': {'uri': self.helper.as_uri(), 'version': 2},
                                                         'contentChanges': [{'text': 'SAFE\n'}]}))
            until(lambda message: is_caller_diagnostic(message, 'ubs.unverified'))
            self.helper.write_text('SAFE\n', encoding='utf-8')
            write(notification('textDocument/didSave', {'textDocument': {'uri': self.helper.as_uri()}}))
            until(lambda message: is_caller_diagnostic(message, None))
            self.assertEqual(len(self.calls()), 2)
            self.assertTrue(all(self.selected(call) == {str(self.helper), str(self.caller)} for call in self.calls()))
            write({'jsonrpc': '2.0', 'id': 2, 'method': 'shutdown'})
            until(lambda message: message.get('id') == 2)
            write(notification('exit', {}))
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            (self.work / 'stdio.stdout').write_bytes(bytes(received))
            (self.work / 'stdio.stderr').write_bytes(process.stderr.read())
            (self.work / 'stdio.json').write_text(json.dumps({'command': command, 'messages': transcript,
                                                            'exit': process.returncode}, indent=2) + '\n')
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
