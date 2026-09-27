"""Grouped editor scans: real processes, explicit scanner double, stale-result fences."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from test_lsp import Fixture, ROOT, lsp

# The GROUP finding requires BOTH selected files. This only tests invocation
# and routing. The separate opt-in case exercises actual Python taint analysis.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
files = [pathlib.Path(name) for name in args[args.index('--') + 1:]]
texts = {str(path): path.read_text() for path in files}
with open(os.environ['SCAN_COUNT'], 'a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'files': list(texts), 'args': args}) + '\n')
if any('SLOW' in value for value in texts.values()):
    time.sleep(30)
findings = []
if any('SOURCE' in value for value in texts.values()):
    for name, text in texts.items():
        if 'SINK' in text:
            findings.append({'rule_id': 'python.test.group', 'file': name, 'line': 1,
                             'message': 'cross-file example', 'severity': 'critical'})
count = len(files) - (1 if any('IGNORED' in value for value in texts.values()) else 0)
print(json.dumps({'status': 'ok', 'project': str(pathlib.Path.cwd()),
                  'totals': {'files': count, 'critical': len(findings)}, 'findings': findings}))
sys.exit(1 if findings else 0)
'''


class WorkspaceTests(Fixture):
    def setUp(self):
        super().setUp()
        self.scanner.write_text(SCANNER)
        self.source.write_text('SOURCE\n')
        self.sink = self.root / 'sink.py'
        self.sink.write_text('SINK\n')
        self.sink_uri = self.sink.as_uri()

    def prepare(self):
        self.open()
        self.open(uri=self.sink_uri, text='SINK\n')

    def group(self, id=11):
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=id)

    def group_running(self):
        until = time.monotonic() + 3
        while time.monotonic() < until:
            self.server.tick()
            if self.calls():
                return self.calls()[-1]
            time.sleep(0.02)
        self.fail('group did not start')

    def test_grouped_invocation_preserves_cross_file_context_and_routes_diagnostics(self):
        self.prepare()
        self.group()
        self.assertEqual(self.messages[-1]['result'], {'queued': 2})
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]['files'], [str(self.source), str(self.sink)])
        self.assertEqual(self.reports()[-1]['diagnostics'], [])
        diagnostics = self.reports(self.sink_uri)[-1]['diagnostics']
        self.assertEqual([item['code'] for item in diagnostics], ['python.test.group'])
        self.assertEqual(self.reports(self.sink_uri)[-1]['version'], 1)

    def test_unsaved_member_prevents_partial_group_from_looking_clean(self):
        self.prepare()
        self.change('UNSAVED SOURCE\n')
        self.group()
        self.wait()
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.reports()[-1]['diagnostics'][0]['code'], 'ubs.unsaved')
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_dependency_change_in_one_editor_buffer_cancels_entire_group(self):
        self.source.write_text('SLOW SOURCE\n')
        self.prepare()
        self.group()
        old = self.group_running()
        self.change('clean\n')
        marker = len(self.messages)
        self.wait()
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.assertFalse(any(item.get('method') == 'textDocument/publishDiagnostics' and item['params']['diagnostics'] == []
                             for item in self.messages[marker:]))
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.source.write_text('clean\n')
        self.group()
        self.wait()
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'], [])

    def test_close_invalidates_group_even_when_other_document_version_did_not_change(self):
        self.source.write_text('SLOW SOURCE\n')
        self.prepare()
        self.group()
        self.group_running()
        self.send('textDocument/didClose', {'textDocument': {'uri': self.uri}})
        self.wait()
        self.assertEqual(self.reports()[-1]['diagnostics'], [])
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_disk_change_after_group_completion_invalidates_all_members(self):
        self.prepare()
        self.group()
        self.group_running()
        until = time.monotonic() + 3
        while self.server.batch and not self.server.batch[0].done() and time.monotonic() < until:
            time.sleep(0.02)
        self.source.write_text('changed after scan\n')
        self.wait()
        for uri in (self.uri, self.sink_uri):
            self.assertEqual(self.reports(uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_coalesced_dependency_notifications_keep_scope_to_open_documents(self):
        self.prepare()
        for index in range(10):
            policy = (self.root / f'policy{index}.toml').as_uri()
            self.send('workspace/didChangeWatchedFiles', {'changes': [{'uri': policy, 'type': 1}]})
        self.wait()
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(set(self.calls()[0]['files']), {str(self.source), str(self.sink)})
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'][0]['code'], 'python.test.group')

    def test_obsolete_individual_jobs_finish_before_group_starts(self):
        self.source.write_text('SLOW SOURCE\n')
        self.prepare()
        old = self.running()
        self.change('SOURCE\n')
        self.source.write_text('SOURCE\n')
        self.group()
        self.wait()
        self.assertEqual(self.calls()[-1]['files'], [str(self.source), str(self.sink)])
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)

    def test_cli_policy_is_preserved_for_a_group(self):
        self.server.policy = ('--profile=strict', '--fail-on-warning')
        self.prepare()
        self.group()
        self.wait()
        self.assertEqual(self.calls()[0]['args'][-5:],
                         ['--profile=strict', '--fail-on-warning', '--', str(self.source), str(self.sink)])

    def test_missing_or_filtered_member_does_not_receive_false_clean_status(self):
        self.source.write_text('IGNORED SOURCE\n')
        self.prepare()
        self.group()
        self.wait()
        for uri in (self.uri, self.sink_uri):
            self.assertEqual(self.reports(uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')

    def test_external_notification_and_command_arguments_cannot_broaden_scope(self):
        self.send('workspace/didChangeWatchedFiles', {'changes': [{'uri': (self.work / 'outside').as_uri(), 'type': 1}]})
        self.assertIsNone(self.server.batch_pending)
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments', 'arguments': ['/']}, id=12)
        self.assertEqual(self.messages[-1]['error']['code'], -32602)
        self.send('workspace/executeCommand', {'command': 'runShell', 'arguments': []}, id=13)
        self.assertEqual(self.messages[-1]['error']['code'], -32602)
        self.assertEqual(self.calls(), [])

    def test_empty_group_is_acknowledged_without_scanning(self):
        self.group()
        self.wait()
        self.assertEqual(self.messages[-1]['result'], {'queued': 0})
        self.assertEqual(self.calls(), [])

    def test_shutdown_cancels_running_group_and_prevents_late_diagnostics(self):
        self.source.write_text('SLOW\n')
        self.prepare()
        self.group()
        old = self.group_running()
        self.send('shutdown', id=12)
        marker = len(self.messages)
        self.wait()
        self.assertEqual(self.messages[-1]['id'], 12)
        self.assertEqual(len(self.messages), marker)
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)

    def test_root_scoped_watches_are_registered_only_with_client_support(self):
        fresh = lsp.Server(self.root, self.scanner, self.messages.append)
        self.addCleanup(fresh.close)
        fresh.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'rootUri': self.root.as_uri(), 'capabilities': {'workspace': {'didChangeWatchedFiles': {
                'dynamicRegistration': True, 'relativePatternSupport': True}}}}})
        fresh.handle({'jsonrpc': '2.0', 'method': 'initialized', 'params': {}})
        registration = self.messages[-1]
        self.assertEqual(registration['method'], 'client/registerCapability')
        watcher = registration['params']['registrations'][0]['registerOptions']['watchers'][0]
        self.assertEqual(watcher, {'globPattern': {'baseUri': self.root.as_uri(), 'pattern': '**/*'}, 'kind': 7})
        count = len(self.messages)
        fresh.handle({'jsonrpc': '2.0', 'id': 'ubs-watch-registration', 'result': None})
        self.assertEqual(len(self.messages), count)
        fresh.handle({'jsonrpc': '2.0', 'method': 'initialized'})
        self.assertEqual(len(self.messages), count)

    def test_rejected_watch_registration_does_not_change_scan_scope(self):
        self.server.registration_pending = True
        self.server.handle({'jsonrpc': '2.0', 'id': 'ubs-watch-registration', 'error': {'code': -1, 'message': 'unsupported'}})
        self.assertEqual(self.messages[-1]['method'], 'window/logMessage')
        self.assertFalse(self.server.registration_pending)
        self.assertEqual(self.calls(), [])

    def test_large_unicode_findings_stay_framable_and_omissions_are_visible(self):
        finding = {'rule_id': 'python.large', 'file': str(self.source), 'line': 1,
                   'message': '🦀' * 8000, 'severity': 'critical'}
        report = {'status': 'ok', 'totals': {'files': 1}, 'findings': [finding] * 100}
        diagnostics = lsp.report_diagnostics(report, self.source, self.root, 'SOURCE\n', 1)
        self.assertLess(len(diagnostics), 100)
        self.assertEqual(diagnostics[-1]['code'], 'ubs.incomplete-display')
        self.assertLess(len(lsp.frame({'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics',
                                     'params': {'uri': self.uri, 'diagnostics': diagnostics}})), lsp.MAX_MESSAGE)

    def test_edit_after_completed_group_invalidates_other_document_clean_report(self):
        self.source.write_text('clean\n')
        self.prepare()
        self.group()
        self.wait()
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'], [])
        self.change('SOURCE\n')
        self.assertEqual(self.reports(self.sink_uri)[-1]['diagnostics'][0]['code'], 'ubs.unverified')
        self.assertEqual(len(self.calls()), 1)

    def test_summary_without_ledger_cannot_become_a_clean_editor_result(self):
        report = {'status': 'ok', 'totals': {'files': 1, 'critical': 1}, 'findings': []}
        with self.assertRaisesRegex(lsp.ProtocolError, 'ledger'):
            lsp.report_diagnostics(report, self.source, self.root, 'SOURCE\n', 0)
        report['ast_findings'] = [{'rule_id': 'python.test', 'file': str(self.source),
                                  'line': 1, 'message': 'advisory', 'severity': 'critical'}]
        with self.assertRaisesRegex(lsp.ProtocolError, 'ledger'):
            lsp.report_diagnostics(report, self.source, self.root, 'SOURCE\n', 0)


@unittest.skipUnless(os.environ.get('UBS_LSP_E2E') == '1', 'set UBS_LSP_E2E=1 for actual UBS integration')
class RealGroupedScannerTests(Fixture):
    def test_actual_imported_sink_requires_group_and_reports_in_defining_document(self):
        self.server.scanner = ROOT / 'ubs'
        self.server.timeout = 120
        self.source.write_text('from helper import run\nrun(input())\n')
        helper = self.root / 'helper.py'
        helper.write_text('def run(value):\n    eval(value)\n')
        self.open()
        self.open(uri=helper.as_uri(), text=helper.read_text())
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=30)
        self.wait(timeout=150)
        diagnostics = self.reports(helper.as_uri())[-1]['diagnostics']
        self.assertTrue(any(d['code'] == 'python.taint.eval' and d['range']['start']['line'] == 1 for d in diagnostics), diagnostics)


if __name__ == '__main__':
    unittest.main()
