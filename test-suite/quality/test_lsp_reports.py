"""Real report-shape contracts and editor transitions; scanner double is explicit."""
from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('lsp_reports_subject', str(ROOT / 'ubs-lsp'))
spec = importlib.util.spec_from_loader(loader.name, loader)
lsp = importlib.util.module_from_spec(spec)
loader.exec_module(lsp)

# Match findings_merge's empty-sink behavior: a clean report has no findings
# field, while a positive report has a counted ledger. This is NOT a detector.
SCANNER = r'''#!/usr/bin/env python3
import json, pathlib, sys
paths = [pathlib.Path(p) for p in sys.argv[sys.argv.index('--') + 1:]]
records = [{'rule_id': 'test.unsafe', 'file': str(path), 'line': 1, 'severity': 'critical',
            'message': 'protocol double finding'} for path in paths if 'BUG' in path.read_text()]
doc = {'status': 'ok', 'totals': {'files': len(paths), 'critical': len(records), 'warning': 0, 'info': 0},
       'scanners': [{'language': 'python', 'files': len(paths), 'critical': len(records), 'warning': 0, 'info': 0}]}
if records:
    doc['findings'] = records
print(json.dumps(doc))
sys.exit(1 if records else 0)
'''


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/project')
        self.path = self.root / 'a.py'
        self.report = {'status': 'ok', 'totals': {'files': 1, 'critical': 0, 'warning': 0, 'info': 0}}

    def render(self, report=None, exit_code=0):
        return lsp.report_diagnostics(self.report if report is None else report, self.path,
                                      self.root, 'value = 1\n', exit_code)

    def test_omitted_empty_array_is_a_valid_clean_scanner_report(self):
        self.assertEqual(self.render(), [])
        self.report['scanners'] = [{'language': 'python', 'files': 1, 'critical': 0, 'warning': 0, 'info': 0}]
        self.assertEqual(self.render(), [])

    def test_explicit_empty_array_has_identical_diagnostics(self):
        self.assertEqual(self.render(), self.render(dict(self.report, findings=[])))

    def test_absent_ledger_with_positive_counts_is_never_clean(self):
        for severity in ('critical', 'warning', 'info'):
            report = copy.deepcopy(self.report)
            report['totals'][severity] = 1
            for exit_code in (0, 1):
                with self.subTest(severity=severity, exit_code=exit_code), self.assertRaises(lsp.ProtocolError):
                    self.render(report, exit_code)

    def test_missing_ambiguous_and_negative_counters_do_not_authorize_an_empty_ledger(self):
        for severity in ('critical', 'warning', 'info'):
            for value in (None, False, '0', 0.0, -1):
                report = copy.deepcopy(self.report)
                report['totals'][severity] = value
                with self.subTest(severity=severity, value=value), self.assertRaises(lsp.ProtocolError):
                    self.render(report)
            report = copy.deepcopy(self.report)
            del report['totals'][severity]
            with self.assertRaises(lsp.ProtocolError):
                self.render(report)

    def test_explicit_null_or_malformed_findings_are_not_equivalent_to_absence(self):
        for value in (None, {}, '', False):
            with self.subTest(value=value), self.assertRaises(lsp.ProtocolError):
                self.render(dict(self.report, findings=value))

    def test_partial_failed_and_no_target_reports_still_fail_closed(self):
        for report in (dict(self.report, status='partial'), dict(self.report, status='error'),
                       dict(self.report, failed_modules=['python']),
                       dict(self.report, totals={'files': 0, 'critical': 0, 'warning': 0, 'info': 0})):
            with self.subTest(report=report), self.assertRaises(lsp.ProtocolError):
                self.render(report)
        with self.assertRaises(lsp.ProtocolError):
            self.render(exit_code=1)

    def test_per_scanner_findings_cannot_hide_under_zero_combined_counts(self):
        for value in ([{'critical': 1}], [{'warning': '0'}], [None], {}, None):
            with self.subTest(scanners=value), self.assertRaises(lsp.ProtocolError):
                self.render(dict(self.report, scanners=value))

    def test_advisory_findings_survive_an_empty_counted_ledger(self):
        ast = {'rule_id': 'test.advisory', 'file': str(self.path), 'line': 1,
               'severity': 'warning', 'message': 'advisory only'}
        report = dict(self.report, ast_findings=[ast])
        self.assertEqual([d['code'] for d in self.render(report)], ['test.advisory'])
        report['totals'] = dict(self.report['totals'], warning=1)
        with self.assertRaises(lsp.ProtocolError):
            self.render(report)

    def test_suppressed_records_cannot_account_for_positive_counts(self):
        finding = {'rule_id': 'test.suppressed', 'severity': 'critical', 'suppressed': True,
                   'file': str(self.path), 'line': 1, 'message': 'suppressed'}
        report = dict(self.report, findings=[finding], totals=dict(self.report['totals'], critical=1))
        with self.assertRaises(lsp.ProtocolError):
            self.render(report)


class EditorTransitionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ubs-lsp-report-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.source = self.root / 'a.py'
        self.uri = self.source.as_uri()
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        # Keep external Git redirects out of this explicit protocol fixture.
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_bug_to_clean_transition_in_every_editor_source_mode(self):
        for mode in ('saved', 'snapshot', 'incremental'):
            with self.subTest(mode=mode):
                self.source.write_text('BUG\n' if mode == 'saved' else 'unchanged disk\n')
                messages = []
                server = lsp.Server(self.root, self.scanner, messages.append, buffer_mode=mode != 'saved',
                                    incremental_workspace=mode == 'incremental', timeout=5)
                try:
                    def send(method, params):
                        server.handle({'jsonrpc': '2.0', 'method': method, 'params': params})
                    def drain():
                        until = time.monotonic() + 8
                        while time.monotonic() < until:
                            server.tick()
                            if not server.active and not server.pending and server.batch is None and server.batch_pending is None:
                                return
                            time.sleep(0.005)
                        self.fail('scan did not drain: ' + repr(messages))
                    def reports():
                        return [m['params'] for m in messages if m.get('method') == 'textDocument/publishDiagnostics']
                    server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}})
                    send('textDocument/didOpen', {'textDocument': {'uri': self.uri, 'text': 'BUG\n', 'version': 1}})
                    drain()
                    self.assertEqual(reports()[-1]['diagnostics'][0]['code'], 'test.unsafe')
                    send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                                                   'contentChanges': [{'text': 'value = 1\n'}]})
                    if mode == 'saved':
                        self.source.write_text('value = 1\n')
                        send('textDocument/didSave', {'textDocument': {'uri': self.uri}})
                    drain()
                    self.assertEqual(reports()[-1], {'uri': self.uri, 'version': 2, 'diagnostics': []})
                    if mode != 'saved':
                        self.assertEqual(self.source.read_text(), 'unchanged disk\n')
                finally:
                    server.close()

    def test_completed_saved_group_is_checked_before_any_member_is_published(self):
        # Dispatch once, then wait on the worker WITHOUT ticking/publishing.
        # A fast scanner cannot escape the intended completion/publication gap.
        self.source.write_text('clean\n')
        other = self.root / 'b.py'
        other.write_text('clean\n')
        messages = []
        server = lsp.Server(self.root, self.scanner, messages.append, timeout=5)
        self.addCleanup(server.close)
        server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}})
        for path in (self.source, other):
            server.handle({'jsonrpc': '2.0', 'method': 'textDocument/didOpen', 'params': {
                'textDocument': {'uri': path.as_uri(), 'text': 'clean\n', 'version': 1}}})
        server.queue_documents()
        server.batch_due = 0
        server.tick()
        self.assertIsNotNone(server.batch)
        result = server.batch[0].result(timeout=5)
        self.assertTrue(all(not value[0] for value in result.values()), result)
        before = len(messages)
        self.source.write_text('BUG\n')
        server.tick()
        reports = [m['params'] for m in messages[before:] if m.get('method') == 'textDocument/publishDiagnostics']
        self.assertEqual(len(reports), 2)
        self.assertTrue(all(r['diagnostics'][0]['code'] == 'ubs.unverified' for r in reports))


if __name__ == '__main__':
    unittest.main()
