"""Regressions for GH #169 / #171: findings, coverage identity and CLI gates."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
