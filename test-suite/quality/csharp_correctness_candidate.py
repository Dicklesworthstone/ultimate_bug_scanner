"""Regressions for GH #169 / #171: findings, coverage identity and CLI gates."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from test_csharp_result_receivers import REPRO

SQL_REPRO = '''using System.Net.Mail;
using Microsoft.Data.SqlClient;

public static class Recipients
{
    // Parameterized query: no tainted SQL.
    public static int Count(SqlConnection db, string team)
    {
        using var cmd = new SqlCommand("SELECT COUNT(*) FROM recipients WHERE team = @team", db);
        cmd.Parameters.AddWithValue("@team", team);
        return (int)cmd.ExecuteScalar();
    }

    // A BCL call with an out parameter, unrelated to SQL.
    public static bool IsValid(string raw) => MailAddress.TryCreate(raw, out _);
}
'''
TAINTED = '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
using System.Net.Mail;
class C {
    static void Run(IDbConnection db, HttpRequest http, string raw) {
        db.Execute(http.Query["sql"].ToString());
        MailAddress.TryCreate(raw, out _);
    }
}
'''


def rule(row):
    return row.get("rule", row.get("rule_id"))


class PatternIntegrationTests(unittest.TestCase):
    def scan(self, source):
        from ubs_core.csharp_scan import load_patterns, scan_patterns
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Repro.cs"
            path.write_text(source, encoding="utf-8")
            sink = io.StringIO()
            scan_patterns(load_patterns(), {path: source}, sink, set(), phase=0)
            return [json.loads(line) for line in sink.getvalue().splitlines()]

    def test_reporter_rule_severity_and_location(self):
        rows = [row for row in self.scan(REPRO) if "blocking-result" in row["rule"]]
        self.assertEqual([(row["rule"], row["line"], row["severity"]) for row in rows],
                         [("cs.pattern.blocking-result", 15, "critical")])

    def test_unknown_receiver_is_warning_not_critical(self):
        rows = [row for row in self.scan('class C { object M(dynamic x) => x.Result; }')
                if "blocking-result" in row["rule"]]
        self.assertEqual([(row["rule"], row["severity"]) for row in rows],
                         [("cs.pattern.possible-blocking-result", "warning")])


class SqlCoverageTests(unittest.TestCase):
    def scan(self, source):
        from ubs_core.analyzers.taint_csharp_sql import scan_file_findings
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Repro.cs"
            path.write_text(source, encoding="utf-8")
            rows, error = [], None
            try:
                rows.extend(scan_file_findings(path))
            except ValueError as exc:
                error = exc
            return rows, error

    def test_reporter_combined_file_is_complete(self):
        self.assertEqual(self.scan(SQL_REPRO), ([], None))

    def test_each_reporter_method_remains_complete_alone(self):
        sql_only = SQL_REPRO[:SQL_REPRO.index('    // A BCL call')] + '}\n'
        mail_only = 'using System.Net.Mail; class C { bool Valid(string raw) => MailAddress.TryCreate(raw, out _); }'
        for source in (sql_only, mail_only):
            with self.subTest(source=source):
                self.assertEqual(self.scan(source), ([], None))

    def test_resolved_alias_and_global_qualification(self):
        for receiver in ('global::System.Net.Mail.MailAddress', 'AddressParser'):
            with self.subTest(receiver=receiver):
                source = 'using AddressParser = System.Net.Mail.MailAddress;\n' + SQL_REPRO.replace(
                    'MailAddress.TryCreate', receiver + '.TryCreate')
                self.assertEqual(self.scan(source), ([], None))

    def test_unknown_receiver_and_named_output_are_not_silently_safe(self):
        from ubs_core.taint_flow import AnalysisLimit
        for source in (
            SQL_REPRO.replace('MailAddress.TryCreate', 'Unknown.TryCreate'),
            SQL_REPRO.replace('out _', 'out var parsed'),
            SQL_REPRO.replace('IsValid(string raw)', 'IsValid(string raw, dynamic MailAddress)'),
            SQL_REPRO.replace('=> MailAddress.TryCreate(raw, out _);',
                              '{ MailAddress _ = null; return MailAddress.TryCreate(raw, out _); }'),
        ):
            with self.subTest(source=source):
                rows, error = self.scan(source)
                self.assertEqual(rows, [])
                self.assertIsInstance(error, AnalysisLimit)

    def test_safe_parser_does_not_sanitize_original_sql(self):
        rows, error = self.scan(TAINTED)
        self.assertIsNone(error)
        self.assertEqual([(rule(row), row['line'], row['severity']) for row in rows],
                         [('cs.security.sql-injection', 7, 'critical')])

    def test_unknown_out_preserves_discovered_sql_finding(self):
        from ubs_core.taint_flow import AnalysisLimit
        rows, error = self.scan(TAINTED.replace('MailAddress.TryCreate', 'Unknown.TryCreate'))
        self.assertIsInstance(error, AnalysisLimit)
        self.assertEqual([(rule(row), row['line'], row['severity']) for row in rows],
                         [('cs.security.sql-injection', 7, 'critical')])

    def test_named_arguments_literals_and_namespace_alias(self):
        calls = (
            'MailAddress.TryCreate(address: raw, result: out _)',
            'MailAddress.TryCreate(result: out _, address: raw)',
            'MailAddress.TryCreate("person@example.test", out _)',
            'MailAddress.TryCreate(null, out _)',
            'Mail.MailAddress.TryCreate(raw, out _)',
        )
        for call in calls:
            with self.subTest(call=call):
                source = 'using Mail = System.Net.Mail;\n' + SQL_REPRO.replace(
                    'MailAddress.TryCreate(raw, out _)', call)
                self.assertEqual(self.scan(source), ([], None))

    def test_dynamic_conversions_and_non_discard_storage_stay_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit
        sources = (
            SQL_REPRO.replace('IsValid(string raw)', 'IsValid(dynamic raw)'),
            SQL_REPRO.replace('IsValid(string raw)', 'IsValid(AddressLike raw)'),
            SQL_REPRO.replace('public static class Recipients\n{',
                              'public static class Recipients\n{\nstatic MailAddress _;'),
            SQL_REPRO.replace('public static class Recipients',
                              'public class Recipients : Base'),
            SQL_REPRO.replace('public static class Recipients',
                              'public static partial class Recipients'),
            SQL_REPRO.replace('public static class Recipients\n{',
                              'public static class Recipients\n{\nstatic dynamic MailAddress;'),
            SQL_REPRO.replace('public static class Recipients\n{',
                              'public static class Recipients\n{\nstatic dynamic first, MailAddress;'),
            SQL_REPRO.replace('TryCreate(raw, out _)', 'TryCreate<string>(raw, out _)'),
        )
        for source in sources:
            with self.subTest(source=source):
                rows, error = self.scan(source)
                self.assertEqual(rows, [])
                self.assertIsInstance(error, AnalysisLimit)

    def test_parsing_does_not_sanitize_later_sql(self):
        source = TAINTED.replace(
            'db.Execute(http.Query["sql"].ToString());\n        MailAddress.TryCreate(raw, out _);',
            'MailAddress.TryCreate(raw, out _);\n        db.Execute(http.Query["sql"].ToString());')
        rows, error = self.scan(source)
        self.assertIsNone(error)
        self.assertEqual([(rule(row), row['line'], row['severity']) for row in rows],
                         [('cs.security.sql-injection', 8, 'critical')])

    def test_local_lookalike_executes_its_real_sql_effects(self):
        source = '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
class MailAddress {
    public static bool TryCreate(IDbConnection db, HttpRequest http, out string parsed) {
        db.Execute(http.Query["sql"].ToString());
        parsed = "x";
        return true;
    }
}
class C { void M(IDbConnection db, HttpRequest http) { MailAddress.TryCreate(db, http, out _); } }
'''
        rows, error = self.scan(source)
        self.assertIsNone(error)
        self.assertEqual([(rule(row), row['line'], row['severity']) for row in rows],
                         [('cs.security.sql-injection', 6, 'critical')])


class ExecutionStatusTests(unittest.TestCase):
    def test_complete_and_severity_failures_are_not_analysis_errors(self):
        from ubs_core.csharp_scan import execution_status
        for status in (0, 1):
            self.assertEqual(execution_status(status, [], []),
                             {'status': 'ok', 'exit_code': status})

    def test_semantic_limits_and_mixed_infrastructure_failures(self):
        from ubs_core.csharp_scan import execution_status
        for errors, semantic, expected in (
            (['unsupported'], ['unsupported'], ('analysis', 'analysis-incomplete', 'ANALYSIS_INCOMPLETE')),
            (['unreadable'], [], ('environment', 'module-failed', 'ANALYZER_ERROR')),
            (['unsupported', 'unreadable'], ['unsupported'], ('environment', 'module-failed', 'ANALYZER_ERROR')),
        ):
            with self.subTest(errors=errors):
                status = execution_status(1, errors, semantic)
                self.assertEqual((status['status'], status['exit_code']), ('partial', 2))
                self.assertEqual((status['error'], status['reason'], status['module_error']), expected)
                self.assertEqual(status['errors'], errors)

    def test_status_sidecar_requires_an_internally_consistent_record(self):
        from ubs_core.csharp_scan import execution_status, read_execution_status
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            good = execution_status(2, ['unsupported'], ['unsupported'])
            invalid = [None, [], {}, {'module_error': ['ANALYSIS_INCOMPLETE']},
                       {**good, 'status': 'ok'}, {**good, 'exit_code': True},
                       {**good, 'exit_code': 1}, {**good, 'error': 'environment'},
                       {**good, 'reason': 'module-failed'}, {**good, 'errors': []},
                       {**good, 'errors': [None]}, {**good, 'message': None}]
            self.assertEqual(read_execution_status(str(path), 2)['error'], 'environment')
            for value in invalid:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    self.assertEqual(read_execution_status(str(path), 2)['error'], 'environment')
            path.write_text('{"status":')
            self.assertEqual(read_execution_status(str(path), 2)['error'], 'environment')
            path.write_text(json.dumps(good))
            self.assertEqual(read_execution_status(str(path), 2)['module_error'], 'ANALYSIS_INCOMPLETE')
            self.assertEqual(read_execution_status(str(path), 139)['error'], 'environment')
            self.assertEqual(read_execution_status(str(path), 0), {})
            self.assertEqual(read_execution_status(str(path), 1), {})

    def test_early_failure_invalidates_a_stale_semantic_sidecar(self):
        from ubs_core.csharp_scan import execution_status, main, read_execution_status
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            path.write_text(json.dumps(execution_status(2, ['old'], ['old'])))
            with self.assertRaises(FileNotFoundError):
                main(['--files-from', str(Path(directory) / 'missing'),
                      '--sink', str(Path(directory) / 'findings'), '--status-out', str(path)])
            self.assertEqual(json.loads(path.read_text()), {})
            self.assertEqual(read_execution_status(str(path), 2)['error'], 'environment')

    def test_orchestrator_retains_findings_and_records_per_file_coverage(self):
        from ubs_core.csharp_scan import execution_status, run_analyzers
        class SqlOnly:
            def filter_files_for_analyzer(self, name, files):
                return files if name == 'taint_csharp_sql' else []
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'Unsupported.cs'
            source.write_text(TAINTED.replace('MailAddress.TryCreate', 'Unknown.TryCreate'))
            neighbor = Path(directory) / 'Neighbor.cs'
            neighbor.write_text(TAINTED)
            sink, errors, semantic = io.StringIO(), [], []
            run_analyzers([source, neighbor], sink, set(), Path(directory),
                          prefilter=SqlOnly(), errors=errors, semantic_errors=semantic)
            rows = [json.loads(line) for line in sink.getvalue().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(rule(row) == 'cs.security.sql-injection' and row['severity'] == 'critical'
                                for row in rows))
            self.assertEqual({Path(row['path']).name for row in rows}, {'Unsupported.cs', 'Neighbor.cs'})
            self.assertEqual(len(errors), 1)
            self.assertEqual(semantic, errors)
            self.assertEqual(execution_status(2, errors, semantic)['error'], 'analysis')
            run_analyzers([Path(directory) / 'Missing.cs'], sink, set(), Path(directory),
                          prefilter=SqlOnly(), errors=errors, semantic_errors=semantic)
            self.assertEqual(len(errors), 2)
            self.assertEqual(execution_status(2, errors, semantic)['error'], 'environment')

    def test_configuration_and_semantic_budget_have_different_identity(self):
        from ubs_core.csharp_scan import execution_status, run_analyzers
        class SqlOnly:
            def filter_files_for_analyzer(self, name, files):
                return files if name == 'taint_csharp_sql' else []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Repro.cs'
            path.write_text(SQL_REPRO)
            for env, expected in (
                ({'UBS_CSHARP_SQL_MAX_TOKENS': 'invalid'}, 'environment'),
                ({'UBS_CSHARP_SQL_MAX_STEPS': '1'}, 'analysis'),
            ):
                with self.subTest(env=env), patch.dict(os.environ, env):
                    sink, errors, semantic = io.StringIO(), [], []
                    run_analyzers([path], sink, set(), Path(directory), prefilter=SqlOnly(),
                                  errors=errors, semantic_errors=semantic)
                    self.assertTrue(errors)
                    self.assertEqual(execution_status(2, errors, semantic)['error'], expected)


class ReportingBoundaryTests(unittest.TestCase):
    """Execute production bridge/runner functions without faking their logic."""

    def read_runner(self):
        return (ROOT / 'ubs').read_text(encoding='utf-8')

    def bridge(self, rows, exit_code, status=None, *, text=False, fail_on_warning=False):
        source = (ROOT / 'modules/ubs-csharp.sh').read_text(encoding='utf-8')
        bridge = source.split('run_v2_legacy_parity_bridges_csharp(){', 1)[1].split(
            '\n# ── Contract-v2 scan:', 1)[0]
        bridge = 'run_v2_legacy_parity_bridges_csharp(){' + bridge
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sink, listing = root / 'findings', root / 'files'
            sink.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            listing.write_bytes(b'Repro.cs\0')
            sidecar = root / 'status.json'
            if status is not None:
                sidecar.write_text(json.dumps(status))
            summary, rendered = root / 'summary.json', root / 'text.txt'
            env = dict(os.environ, SCRIPT_DIR=str(ROOT / 'modules'), CI_MODE='1',
                       FORMAT='text' if text else 'json', SUMMARY_JSON=str(summary),
                       VERSION='test', NO_DOTNET='1', NO_DOTNET_FORMAT='1',
                       FAIL_ON_WARNING='1' if fail_on_warning else '0',
                       PYTHONDONTWRITEBYTECODE='1')
            args = [str(sink), str(listing), str(exit_code), str(rendered) if text else '', '', '0', str(sidecar)]
            command = ('set -Eeuo pipefail\nubs_resolve_helpers_dir(){ return 1; }\n' + bridge +
                       '\nrun_v2_legacy_parity_bridges_csharp ' + shlex.join(args))
            process = subprocess.run(['bash', '-c', command], env=env, cwd=directory,
                                     text=True, capture_output=True, timeout=20)
            self.assertTrue(summary.exists(), (process.returncode, process.stdout, process.stderr))
            doc = json.loads(summary.read_text())
            if not text:
                self.assertEqual(json.loads(process.stdout), doc)
            return process, doc, rendered.read_text() if text else ''

    def test_bridge_keeps_findings_and_execution_exit_separate(self):
        from ubs_core.csharp_scan import execution_status
        rows = [{'rule': 'cs.security.sql-injection', 'severity': 'critical', 'line': 7,
                 'path': 'Repro.cs', 'message': 'Request-derived SQL'}]
        proc, doc, _ = self.bridge(rows, 1)
        self.assertEqual((proc.returncode, doc['status'], doc['critical']), (1, 'ok', 1))
        self.assertNotIn('error', doc)
        status = execution_status(2, ['unsupported out'], ['unsupported out'])
        proc, doc, _ = self.bridge(rows, 2, status)
        self.assertEqual((proc.returncode, doc['status'], doc['error'], doc['reason']),
                         (2, 'partial', 'analysis', 'analysis-incomplete'))
        self.assertEqual(doc['findings'], rows)
        self.assertEqual(doc['critical'], 1)

    def test_bridge_clean_warning_and_warning_gate(self):
        rows = [{'rule': 'cs.pattern.possible-blocking-result', 'severity': 'warning',
                 'line': 1, 'path': 'Repro.cs', 'message': 'Unresolved receiver'}]
        for findings, fail, expected in (([], False, 0), (rows, False, 0), (rows, True, 1)):
            with self.subTest(findings=findings, fail=fail):
                proc, doc, _ = self.bridge(findings, 0, fail_on_warning=fail)
                self.assertEqual(proc.returncode, expected, proc.stderr)
                self.assertEqual(doc['status'], 'ok')
                self.assertNotIn('error', doc)

    def test_bridge_absent_status_or_crash_is_not_semantic_coverage(self):
        from ubs_core.csharp_scan import execution_status
        semantic = execution_status(2, ['unsupported'], ['unsupported'])
        for status, code in ((None, 2), ({}, 2), (semantic, 139)):
            with self.subTest(status=status, code=code):
                proc, doc, _ = self.bridge([], code, status)
                self.assertEqual(proc.returncode, code)
                self.assertEqual((doc['error'], doc['module_error']), ('environment', 'ANALYZER_ERROR'))

    def test_bridge_text_exposes_typed_partial_marker(self):
        from ubs_core.csharp_scan import execution_status
        status = execution_status(2, ['unsupported out'], ['unsupported out'])
        proc, doc, text = self.bridge([], 2, status, text=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn('Partial: [ANALYSIS_INCOMPLETE]', text)
        self.assertIn('semantic coverage is incomplete', text)
        self.assertEqual(doc['error'], 'analysis')

    def test_runner_json_classification_with_healthy_and_failed_peers(self):
        source = self.read_runner()
        status = source.split('RUN_STATUS="ok"\nFAILED_MODULES_JSON="[]"', 1)[1].split(
            '\n# ─────────────────────────────────────────────────────────────────────────────\n# Emit unified result', 1)[0]
        status = 'RUN_STATUS="ok"\nFAILED_MODULES_JSON="[]"' + status
        qualify = source.split('qualify_combined_json(){', 1)[1].split('\ngenerate_combined_json(){', 1)[0]
        qualify = 'qualify_combined_json(){' + qualify
        semantic = {'language': 'csharp', 'status': 'partial',
                    'module_error': 'ANALYSIS_INCOMPLETE', 'message': 'unsupported out'}
        infrastructure = {'language': 'python', 'status': 'partial',
                          'module_error': 'ANALYZER_ERROR', 'message': 'broken helper'}
        healthy = {'language': 'python', 'status': 'ok'}
        cases = (
            ([semantic], ['csharp'], 'analysis', 'analysis-incomplete'),
            ([semantic, healthy], ['csharp'], 'analysis', 'analysis-incomplete'),
            ([semantic, infrastructure], ['csharp', 'python'], 'environment', 'module-failed'),
            ([infrastructure], ['python'], 'environment', 'module-failed'),
            ([semantic], ['csharp', 'missing'], 'environment', 'module-failed'),
            ([semantic], [], 'environment', 'module-failed'),
        )
        for docs, error_langs, expected, reason in cases:
            with self.subTest(docs=docs, error_langs=error_langs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for doc in docs:
                    (root / (doc['language'] + '.json')).write_text(json.dumps(doc))
                combined = root / 'combined.json'
                findings = [{'rule_id': 'cs.security.sql-injection', 'severity': 'critical'}]
                combined.write_text(json.dumps({'findings': findings, 'totals': {'critical': 1}}))
                env = dict(os.environ, TMPDIR_RUN=directory, COMBINED_JSON_FILE=str(combined))
                env.pop('UBS_ALLOW_PARTIAL', None)
                command = ('set -Eeuo pipefail\nneed_cmd(){ command -v "$1" >/dev/null; }\n'
                           'HAS_ENV_ERROR=1\nENV_ERROR_LANGS=(' + shlex.join(error_langs) + ')\n'
                           'langs=(' + shlex.join([doc['language'] for doc in docs]) + ')\n' +
                           qualify + '\n' + status + '\nqualify_combined_json\ncat "$COMBINED_JSON_FILE"\n')
                proc = subprocess.run(['bash', '-c', command], env=env, text=True,
                                      capture_output=True, timeout=20)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                result = json.loads(proc.stdout)
                self.assertEqual((result['status'], result['exit_code'], result['error'], result['reason']),
                                 ('partial', 2, expected, reason))
                self.assertEqual(result['findings'], findings)
                if expected == 'analysis':
                    self.assertNotIn('tooling/dependency', result['message'])


@unittest.skipUnless(os.environ.get('UBS_CSHARP_CORRECTNESS_PUBLIC') == '1',
                     'set UBS_CSHARP_CORRECTNESS_PUBLIC=1 for real module/meta scans')
class PublicContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.project = self.directory / 'project'
        self.project.mkdir()

    def execute(self, source, *, module=False, environment=None):
        (self.project / 'Repro.cs').write_text(source, encoding='utf-8')
        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_ENABLE_AUTO_UPDATE='0',
                   ENABLE_UV_TOOLS='0', PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1',
                   UBS_NO_CACHE='0', UBS_CACHE_DIR=str(self.directory / 'cache'))
        env.pop('UBS_ALLOW_PARTIAL', None)
        if environment:
            env.update(environment)
        command = ([str(ROOT / 'modules/ubs-csharp.sh'), '--ci', '--no-color', '--no-dotnet']
                   if module else [str(ROOT / 'ubs'), '--ci', '--no-config', '--no-dotnet', '--only=csharp'])
        process = subprocess.run([*command, '--format=json', str(self.project)],
                                 cwd=self.project, env=env, text=True, capture_output=True, timeout=120)
        try:
            report = json.loads(process.stdout)
        except ValueError:
            self.fail((command, process.returncode, process.stdout, process.stderr))
        return process, report

    def assert_complete(self, source, expected_exit, expected_results):
        for module in (True, False):
            with self.subTest(module=module):
                proc, doc = self.execute(source, module=module)
                self.assertEqual(proc.returncode, expected_exit, (doc, proc.stderr))
                self.assertEqual(doc['status'], 'ok', doc)
                self.assertNotIn('error', doc)
                rows = [(rule(row), row['severity']) for row in doc['findings']
                        if rule(row) in {'cs.pattern.blocking-result', 'cs.pattern.possible-blocking-result',
                                         'cs.security.sql-injection'}]
                self.assertEqual(rows, expected_results, doc)

    def test_result_exact_reproducer_and_clean_controls(self):
        self.assert_complete(REPRO, 1, [('cs.pattern.blocking-result', 'critical')])
        clean = REPRO.replace('    public static int Blocking(Task<int> t) => t.Result;\n', '')
        self.assert_complete(clean, 0, [])

    def test_unknown_result_retains_warning(self):
        self.assert_complete('class C { object M(dynamic x) => x.Result; }', 0,
                             [('cs.pattern.possible-blocking-result', 'warning')])

    def test_sql_reporter_is_clean_and_genuine_sql_is_not(self):
        self.assert_complete(SQL_REPRO, 0, [])
        self.assert_complete(TAINTED, 1, [('cs.security.sql-injection', 'critical')])

    def test_unsupported_out_is_partial_analysis_including_warm_cache(self):
        source = SQL_REPRO.replace('MailAddress.TryCreate', 'Unknown.TryCreate')
        for module in (True, False):
            for attempt in range(2):
                with self.subTest(module=module, attempt=attempt):
                    proc, doc = self.execute(source, module=module)
                    self.assertEqual(proc.returncode, 2, (doc, proc.stderr))
                    self.assertEqual((doc['status'], doc.get('error'), doc.get('reason')),
                                     ('partial', 'analysis', 'analysis-incomplete'), doc)
                    failed = [doc] if module else doc['failed_modules']
                    self.assertTrue(failed, doc)
                    self.assertTrue(all(row['module_error'] == 'ANALYSIS_INCOMPLETE' for row in failed), doc)
                    self.assertNotIn('tooling/dependency problem', proc.stderr)

    def test_unsupported_out_retains_sql_and_exit_two(self):
        proc, doc = self.execute(TAINTED.replace('MailAddress.TryCreate', 'Unknown.TryCreate'))
        self.assertEqual(proc.returncode, 2, (doc, proc.stderr))
        self.assertEqual((doc['status'], doc.get('error')), ('partial', 'analysis'), doc)
        rows = [row for row in doc['findings'] if rule(row) == 'cs.security.sql-injection']
        self.assertEqual([(row['line'], row['severity']) for row in rows], [(7, 'critical')])

    def test_bad_configuration_remains_environment_failure(self):
        proc, doc = self.execute(SQL_REPRO, environment={'UBS_CSHARP_SQL_MAX_TOKENS': 'invalid'})
        self.assertEqual(proc.returncode, 2, (doc, proc.stderr))
        self.assertEqual((doc.get('error'), doc.get('reason')), ('environment', 'module-failed'), doc)
        self.assertTrue(any(row['module_error'] == 'ANALYZER_ERROR' for row in doc['failed_modules']), doc)

    def test_exhausted_analysis_budget_is_not_environment_failure(self):
        proc, doc = self.execute(SQL_REPRO, environment={'UBS_CSHARP_SQL_MAX_STEPS': '1'})
        self.assertEqual(proc.returncode, 2, (doc, proc.stderr))
        self.assertEqual((doc['status'], doc.get('error'), doc.get('reason')),
                         ('partial', 'analysis', 'analysis-incomplete'), doc)


if __name__ == '__main__':
    unittest.main()
