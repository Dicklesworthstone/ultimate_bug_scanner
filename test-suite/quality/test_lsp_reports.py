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


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/project')
        self.a = self.root / 'src/a.py'
        self.b = self.root / 'src/b.py'

    def finding(self, path, rule, **fields):
        return dict({'rule_id': rule, 'file': str(path), 'line': 1,
                     'severity': 'warning', 'message': rule}, **fields)

    def report(self, records, **fields):
        return dict({'status': 'ok', 'project': str(self.root),
                     'totals': {'files': 2}, 'findings': records}, **fields)

    def render(self, report, path, paths=None, **options):
        return lsp.report_diagnostics(report, path, self.root, '\ufeffvalue😀\nnext\n', 1,
                                      selected_paths=paths or (self.a, self.b), **options)

    def test_relative_sibling_findings_use_the_selected_file_project_parent(self):
        report = self.report([self.finding('b.py', 'test.sibling')], project=str(self.a))
        diagnostics = self.render(report, self.b)
        self.assertEqual([d['code'] for d in diagnostics], ['test.sibling'])
        self.assertEqual(diagnostics[0]['range']['end'], {'line': 0, 'character': 8})
        self.assertEqual(self.render(report, self.a), [])

    def test_ambiguous_basename_is_not_invented_as_two_source_locations(self):
        root_b = self.root / 'b.py'
        report = self.report([self.finding('b.py', 'test.ambiguous')], project=str(self.root / 'src'))
        for path in (root_b, self.b):
            diagnostics = self.render(report, path, paths=(root_b, self.b))
            self.assertEqual([d['code'] for d in diagnostics], ['ubs.incomplete-display'])
            self.assertIn('1 additional findings', diagnostics[0]['message'])

    def test_project_and_advisory_records_preserve_global_report_order(self):
        records = [self.finding(self.b, 'b.first'),
                   self.finding('', 'project', scope='project_aggregate', count=3),
                   self.finding(self.a, 'a.first'),
                   self.finding(self.a, 'suppressed', suppressed=True),
                   self.finding(self.b, 'b.second')]
        report = self.report(records, ast_findings=[self.finding(self.a, 'ast.a'),
                                                   self.finding('', 'ast.project', scope='project')])
        index = lsp.ReportIndex(report, self.root, (self.a, self.b), 1)
        self.assertEqual([d['code'] for d in self.render(report, self.a, _index=index)],
                         ['project', 'a.first', 'ast.a', 'ast.project'])
        self.assertEqual([d['code'] for d in self.render(report, self.b, _index=index)],
                         ['b.first', 'project', 'b.second', 'ast.project'])
        self.assertEqual(sum(map(len, index.by_path.values())), 4)
        self.assertEqual(len(index.shared), 2)
        self.assertIs(index.by_path[self.b][0][1], records[0])

    def test_absolute_paths_are_not_ambiguous_and_foreign_records_stay_visible(self):
        report = self.report([self.finding(self.b, 'b.exact'), self.finding('/outside/a.py', 'foreign')],
                             project=str(self.a))
        for path, expected in ((self.a, ['ubs.incomplete-display']),
                               (self.b, ['b.exact', 'ubs.incomplete-display'])):
            self.assertEqual([d['code'] for d in self.render(report, path)], expected)

    def test_display_limit_counts_omissions_per_document_without_losing_shared_records(self):
        records = [self.finding(self.a, f'a.{i}') for i in range(5)]
        records += [self.finding(self.b, 'b.only'), self.finding('', 'shared', scope='project', count=1)]
        report = self.report(records)
        index = lsp.ReportIndex(report, self.root, (self.a, self.b), 1)
        with patch.object(lsp, 'MAX_DIAGNOSTICS', 4):
            a = self.render(report, self.a, _index=index)
            b = self.render(report, self.b, _index=index)
        self.assertEqual([d['code'] for d in a], ['a.0', 'a.1', 'a.2', 'ubs.incomplete-display'])
        self.assertIn('3 additional findings', a[-1]['message'])
        self.assertEqual([d['code'] for d in b], ['b.only', 'shared'])

    def test_late_malformed_record_invalidates_whole_report_not_only_its_owner(self):
        for change in ({'line': True}, {'rule_id': ''}, {'message': None},
                       {'severity': []}, {'suppressed': 'false'}):
            report = self.report([self.finding(self.a, 'valid'), self.finding(self.b, 'invalid', **change)])
            with self.subTest(change=change), self.assertRaises(lsp.ProtocolError):
                self.render(report, self.a)

    def test_bad_source_line_in_another_group_member_prevents_result_publication(self):
        report = self.report([self.finding(self.b, 'outside-lines', line=99)])
        index = lsp.ReportIndex(report, self.root, (self.a, self.b), 1)
        with self.assertRaisesRegex(lsp.ProtocolError, 'outside the saved'):
            {path: self.render(report, path, _index=index) for path in (self.a, self.b)}

    def test_cancellation_interrupts_routing_and_empty_document_rendering(self):
        class CancelAfter:
            def __init__(self):
                self.calls = 0

            def is_set(self):
                self.calls += 1
                return self.calls >= 12

        cancel = CancelAfter()
        report = self.report([self.finding(self.a, 'test') for _ in range(100)])
        with self.assertRaisesRegex(lsp.ProtocolError, 'cancelled'):
            lsp.ReportIndex(report, self.root, (self.a, self.b), 1, cancel=cancel)
        self.assertEqual(cancel.calls, 12)
        token = threading.Event()
        report = self.report([self.finding(self.a, 'test')])
        index = lsp.ReportIndex(report, self.root, (self.a, self.b), 1, cancel=token)
        token.set()
        with self.assertRaisesRegex(lsp.ProtocolError, 'cancelled'):
            self.render(report, self.b, _index=index)

    def test_indexed_rendering_retains_unicode_byte_budget_and_omission_notice(self):
        report = self.report([self.finding(self.a, 'large', message='🦀' * 8000) for _ in range(100)])
        index = lsp.ReportIndex(report, self.root, (self.a, self.b), 1)
        diagnostics = self.render(report, self.a, _index=index)
        self.assertLess(len(diagnostics), 100)
        self.assertEqual(diagnostics[-1]['code'], 'ubs.incomplete-display')
        self.assertLess(len(lsp.frame({'jsonrpc': '2.0', 'method': 'textDocument/publishDiagnostics',
                                      'params': {'uri': self.a.as_uri(), 'diagnostics': diagnostics}})), lsp.MAX_MESSAGE)
        self.assertEqual(self.render(report, self.b, _index=index), [])


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

    def test_group_scan_validates_each_finding_once_not_once_per_document(self):
        # Count record access at the existing scan boundary, not calls to a new
        # implementation-specific API. The old implementation fails this bound.
        accesses = [0]

        class CountedFinding(dict):
            def get(self, key, default=None):
                accesses[0] += 1
                return super().get(key, default)

        decode = lsp.decode_json

        def instrument(raw):
            report = decode(raw)
            report['findings'] = [CountedFinding(record) for record in report['findings']]
            return report

        documents = {}
        for index in range(64):
            path = self.root / f'{index}.py'
            path.write_text('BUG\n')
            documents[path.as_uri()] = {'path': path, 'text': 'BUG\n', 'wire_text': 'BUG\n',
                                        'synchronized': True, 'generation': 1, 'version': 1}
        info = self.root.stat()
        with patch.object(lsp, 'decode_json', side_effect=instrument):
            result = lsp.scan(self.scanner, self.root, documents, (info.st_dev, info.st_ino),
                              5, threading.Event())
        self.assertEqual(len(result), 64)
        self.assertTrue(all([d['code'] for d in value[0]] == ['test.unsafe'] for value in result.values()))
        self.assertLessEqual(accesses[0], 12 * 64, f'{accesses[0]} record accesses for 64 findings')


if __name__ == '__main__':
    unittest.main()
