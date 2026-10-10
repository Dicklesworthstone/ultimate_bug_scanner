"""Independent raw Ecto SQL oracle for mj1j.21/.22.

Source markers identify the actual execution site, never the source of input.
SQL text and bound values are separate operands in the documented API. These
cases were authored before extending the native engine. Public probes use the
real module and meta-runner; all source and command evidence is retained.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_elixir_traversal as native
from ubs_core.registry import RunContext
from ubs_core.taint_flow import AnalysisLimit, Budget

RULE = 'ex.security.sql-interpolation'
SKIP = '1,2,3,5,6,7,8,9,10,11,12,13,14,15,16'


@dataclass(frozen=True)
class Case:
    name: str
    code: str

    @property
    def source(self):
        source = textwrap.dedent(self.code).strip('\n') + '\n'
        if source.startswith('def '):
            source = 'defmodule SQLOracle do\n' + textwrap.indent(source, '  ') + 'end\n'
        return source

    @property
    def expected(self):
        rows = []
        for number, line in enumerate(self.source.splitlines(), 1):
            if '# sql' in line:
                target = line.split('# sql:', 1)[1].strip() if '# sql:' in line else line.lstrip().split('(', 1)[0]
                rows.append((number, line.index(target) + 1))
        return rows


CASES = (
    Case('raw_concatenation', '''
        def handle(conn, params) do
          value = params["name"]
          sql = "SELECT * FROM accounts WHERE name = '" <> value <> "'"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
        end'''),
    Case('interpolation_and_separate_binds', '''
        def handle(conn, params) do
          value = params["name"]
          Ecto.Adapters.SQL.query(ApplicationRepo, "SELECT $1 FROM accounts WHERE name = '#{value}'", [1]) # sql
        end'''),
    Case('alias_query_and_metadata', '''
        defmodule Handler do
          alias Ecto.Adapters.SQL, as: Database
          def handle(conn, params) do
            raw = params["name"]
            query = "SELECT * FROM accounts WHERE name = '#{raw}'"
            Database.query!(ApplicationRepo, query, [], log: false) # sql
          end
        end'''),
    Case('selected_import', '''
        defmodule Handler do
          import Ecto.Adapters.SQL, only: [query!: 3]
          def handle(conn, params) do
            query!(ApplicationRepo, "SELECT '#{params["name"]}'", []) # sql
          end
        end'''),
    Case('fully_qualified_despite_local_alias', '''
        defmodule Handler do
          alias Pretend, as: Ecto
          def handle(conn, params) do
            Elixir.Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'") # sql
          end
        end'''),
    Case('helper_returns_query', '''
        defmodule Handler do
          defp statement(name), do: "SELECT * FROM accounts WHERE name = '#{name}'"
          def handle(conn, params) do
            Ecto.Adapters.SQL.query!(ApplicationRepo, statement(params["name"])) # sql
          end
        end'''),
    Case('helper_executes_query', '''
        defmodule Handler do
          defp execute(sql) do
            Ecto.Adapters.SQL.query!(ApplicationRepo, sql, []) # sql
          end
          def handle(conn, params) do
            execute("SELECT '#{params["name"]}'")
          end
        end'''),
    Case('literal_rebound_to_request', '''
        def handle(conn, params) do
          sql = "SELECT 1"
          sql = "SELECT '#{params["name"]}'"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
        end'''),
    Case('unknown_branch_preserves_raw', '''
        def handle(conn, params) do
          sql = if params["mode"] == "all", do: "SELECT 1", else: "SELECT '#{params["name"]}'"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
        end'''),
    Case('case_tuple_and_clause_selection', '''
        defmodule Handler do
          defp choose({:fixed, _}), do: "SELECT 1"
          defp choose({:raw, name}), do: "SELECT '#{name}'"
          def handle(conn, params) do
            sql = choose({:raw, params["name"]})
            Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
          end
        end'''),
    Case('pipe_repo_operand', '''
        def handle(conn, params) do
          sql = "SELECT '#{params["name"]}'"
          ApplicationRepo |> Ecto.Adapters.SQL.query!(sql, []) # sql: Ecto.Adapters.SQL.query!
        end'''),
    Case('iodata_contains_raw_text', '''
        def handle(conn, params) do
          sql = ["SELECT * FROM accounts WHERE name = '", [params["name"]], "'"]
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql, []) # sql
        end'''),
    Case('request_map_alias', '''
        def handle(conn, params) do
          request = params
          raw = Map.get(request, "name")
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{raw}'") # sql
        end'''),
    Case('query_many_executes_raw', '''
        def handle(conn, params) do
          sql = "SELECT 1; SELECT '#{params["name"]}'"
          Ecto.Adapters.SQL.query_many!(ApplicationRepo, sql, []) # sql
        end'''),
    Case('same_file_postgres_repo', '''
        defmodule Database do
          use Ecto.Repo, otp_app: :example, adapter: Ecto.Adapters.Postgres
        end
        defmodule Handler do
          alias Database, as: Store
          def handle(conn, params) do
            Store.query!("SELECT '#{params["name"]}'", []) # sql
          end
        end'''),
    Case('same_file_mysql_repo_many', '''
        defmodule Database do
          use Ecto.Repo, otp_app: :example, adapter: Ecto.Adapters.MyXQL
        end
        defmodule Handler do
          def handle(conn, params) do
            Database.query_many("SELECT '#{params["name"]}'", [], log: false) # sql
          end
        end'''),
    Case('same_file_tds_repo', '''
        defmodule Database do
          use Ecto.Repo, otp_app: :example, adapter: Ecto.Adapters.Tds
        end
        defmodule Handler do
          def handle(conn, params) do
            Database.query("SELECT '#{params["name"]}'", []) # sql
          end
        end'''),
    Case('trim_does_not_bind', '''
        def handle(conn, params) do
          raw = String.trim(params["name"])
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{raw}'", []) # sql
        end'''),
    Case('path_transform_does_not_bind', '''
        def handle(conn, params) do
          raw = Path.basename(params["name"])
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{raw}'", []) # sql
        end'''),
    Case('static_sql', '''
        def handle(conn, params) do
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT 1")
        end'''),
    Case('actual_bound_values', '''
        def handle(conn, params) do
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT $1::text", [params["name"]])
        end'''),
    Case('static_interpolation', '''
        def handle(conn, params) do
          name = "fixed"
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{name}'", [])
        end'''),
    Case('static_concatenation', '''
        def handle(conn, params) do
          sql = "SELECT " <> "1"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql)
        end'''),
    Case('request_rebound_to_literal', '''
        def handle(conn, params) do
          sql = "SELECT '#{params["name"]}'"
          sql = "SELECT 1"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql)
        end'''),
    Case('constant_branch_ignores_unreachable_raw', '''
        def handle(conn, params) do
          sql = if true, do: "SELECT 1", else: "SELECT '#{params["name"]}'"
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql)
        end'''),
    Case('helper_chooses_static_clause', '''
        defmodule Handler do
          defp choose({:fixed, _}), do: "SELECT 1"
          defp choose({:raw, name}), do: "SELECT '#{name}'"
          def handle(conn, params) do
            Ecto.Adapters.SQL.query!(ApplicationRepo, choose({:fixed, params["name"]}))
          end
        end'''),
    Case('literal_map_named_params', '''
        def handle(conn, params) do
          params = %{"name" => "fixed"}
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'")
        end'''),
    Case('fake_alias_is_not_framework', '''
        defmodule FakeSQL do
          def query!(_repo, _sql), do: :ok
        end
        defmodule Handler do
          alias FakeSQL, as: SQL
          def handle(conn, params) do
            SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'")
          end
        end'''),
    Case('same_file_framework_module_shadow', '''
        defmodule Ecto.Adapters.SQL do
          def query!(_repo, _sql), do: :ok
        end
        defmodule Handler do
          def handle(conn, params) do
            Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'")
          end
        end'''),
    Case('named_repo_is_not_framework', '''
        defmodule Repo do
          def query!(_sql, _params), do: :ok
        end
        defmodule Handler do
          def handle(conn, params) do
            Repo.query!("SELECT '#{params["name"]}'", [])
          end
        end'''),
    Case('integer_conversion', '''
        def handle(conn, params) do
          count = String.to_integer(params["count"])
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT #{count}")
        end'''),
    Case('same_file_repo_bound_values', '''
        defmodule Database do
          use Ecto.Repo, otp_app: :example, adapter: Ecto.Adapters.Postgres
        end
        defmodule Handler do
          def handle(conn, params) do
            Database.query!("SELECT $1::text", [params["name"]])
          end
        end'''),
    Case('iodata_static_and_bound_values', '''
        def handle(conn, params) do
          sql = ["SELECT ", ["$1::text"]]
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql, [params["name"]])
        end'''),
    Case('lexical_query_decoys', '''
        def handle(conn, params) do
          # Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'")
          ~S(Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT '#{params["name"]}'"))
        end'''),
)

PARTIAL = (
    Case('dynamic_module', '''
        def handle(conn, params) do
          adapter = params["adapter"]
          adapter.query!(ApplicationRepo, params["sql"])
        end'''),
    Case('dynamic_apply', '''
        def handle(conn, params) do
          apply(Ecto.Adapters.SQL, :query!, [ApplicationRepo, params["sql"]])
        end'''),
    Case('unknown_query_transform', '''
        def handle(conn, params) do
          sql = Unknown.quote(params["sql"])
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql)
        end'''),
    Case('unexpanded_controller_macro', '''
        defmodule Handler do
          use MyWeb, :controller
          def handle(conn, params) do
            Ecto.Adapters.SQL.query!(ApplicationRepo, params["sql"])
          end
        end'''),
    Case('lazy_stream_needs_consumption_model', '''
        def handle(conn, params) do
          Ecto.Adapters.SQL.stream(ApplicationRepo, params["sql"])
        end'''),
    Case('valid_sink_before_unknown_call', '''
        def handle(conn, params) do
          Ecto.Adapters.SQL.query!(ApplicationRepo, params["sql"]) # sql
          Unknown.transform(params["sql"])
        end'''),
)

REVIEW_CASES = (
    Case('numeric_iodata_byte_can_close_quote', '''
        def handle(conn, params) do
          code = String.to_integer(params["code"])
          sql = ["SELECT * FROM accounts WHERE name = '", [code], " OR 1=1 --'"]
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
        end'''),
    Case('numeric_iodata_arithmetic_preserves_byte', '''
        def handle(conn, params) do
          code = String.to_integer(params["code"]) + 1
          sql = ["SELECT * FROM accounts WHERE name = '", [code], " OR 1=1 --'"]
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql) # sql
        end'''),
    Case('numeric_interpolation_renders_decimal_digits', '''
        def handle(conn, params) do
          code = -String.to_integer(params["code"]) + 1
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT #{code}")
        end'''),
    Case('numeric_iodata_is_only_a_bound_value', '''
        def handle(conn, params) do
          code = String.to_integer(params["code"])
          Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT $1", [code])
        end'''),
)
CASES = (*CASES, *REVIEW_CASES)


class ElixirSqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ROOT / 'test-suite/artifacts/elixir-sql' / uuid.uuid4().hex
        cls.artifact.mkdir(parents=True)
        cls.identities = {
            'oracle_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'engine_sha256': hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
            'python': sys.version,
        }

    def materialize(self, cases, label):
        directory = self.artifact / (label + '-' + uuid.uuid4().hex[:8])
        directory.mkdir()
        for case in cases:
            (directory / (case.name + '.ex')).write_text(case.source, encoding='utf-8')
        return directory

    def test_native_cases(self):
        directory = self.materialize(CASES, 'native')
        receipt = []
        for case in CASES:
            with self.subTest(case=case.name):
                path = directory / (case.name + '.ex')
                records = list(native.run_sql(RunContext(lang='elixir', files=[path])))
                actual = [(row['line'], row['col']) for row in records]
                receipt.append(dict(case=case.name, expected=case.expected, actual=actual,
                                    source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
                self.assertEqual(actual, case.expected, records)
                for row in records:
                    self.assertEqual((row['rule'], row['severity'], row['category_id']),
                                     (RULE, 'critical', 'elixir.security'))
                    self.assertEqual(row['extras']['taint_path'][-1]['kind'], 'sink')
        (directory / 'receipt.json').write_text(json.dumps(dict(self.identities, cases=receipt), indent=2))

    def test_partial_boundaries_and_budget(self):
        directory = self.materialize(PARTIAL, 'partial-native')
        for case in PARTIAL:
            with self.subTest(case=case.name):
                findings = []
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    for finding in native.run_sql(RunContext(lang='elixir', files=[directory / (case.name + '.ex')])):
                        findings.append(finding)
                self.assertEqual([(row['line'], row['col']) for row in findings], case.expected)
        with self.assertRaises(AnalysisLimit):
            native.ElixirEngine(directory / 'budget.ex', CASES[0].source, 'sql', Budget(2)).analyze()

    def execute(self, directory, mode, extra=(), cached=False):
        attempt = self.artifact / ('command-' + uuid.uuid4().hex[:8])
        attempt.mkdir()
        environment = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_ENABLE_AUTO_UPDATE='0',
                           ENABLE_UV_TOOLS='0', PYTHONDONTWRITEBYTECODE='1',
                           UBS_NO_CACHE='0' if cached else '1',
                           UBS_CACHE_DIR=str(self.artifact / 'cache'), TMPDIR=str(attempt))
        if mode.startswith('module-'):
            command = [str(ROOT / 'modules/ubs-elixir.sh'), '--ci', '--no-color', '--only=4',
                       '--format=' + mode.split('-', 1)[1], *extra, str(directory)]
        else:
            command = [str(ROOT / 'ubs'), '--ci', '--no-config', '--only=elixir',
                       '--skip-elixir=' + SKIP, '--format=' + mode, *extra, str(directory)]
        started = time.monotonic()
        result = subprocess.run(command, cwd=directory if directory.is_dir() else directory.parent,
                                env=environment, text=True, capture_output=True, timeout=90)
        (attempt / 'stdout.json').write_text(result.stdout, encoding='utf-8')
        (attempt / 'stderr.log').write_text(result.stderr, encoding='utf-8')
        (attempt / 'receipt.json').write_text(json.dumps(dict(self.identities, command=command,
             exit=result.returncode, elapsed=time.monotonic() - started), indent=2))
        return result, json.loads(result.stdout)

    def assert_report(self, result, report, mode, cases, partial=False):
        expected = sorted((case.name + '.ex', line, col) for case in cases for line, col in case.expected)
        context = (result.returncode, result.stdout, result.stderr)
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), context)
        if mode.endswith('sarif'):
            rows = [row for run in report['runs'] for row in run.get('results', [])]
            actual = []
            for row in rows:
                self.assertEqual((row['ruleId'], row['level']), (RULE, 'error'), context)
                location = row['locations'][0]['physicalLocation']
                actual.append((Path(location['artifactLocation']['uri']).name,
                               location['region']['startLine'], location['region']['startColumn']))
            if partial:
                self.assertTrue(any(not item['executionSuccessful'] for run in report['runs']
                                    for item in run.get('invocations', [])), context)
        else:
            totals = report if mode.startswith('module-') else report['totals']
            self.assertEqual((totals['critical'], totals['warning'], totals['info'], totals['files']),
                             (len(expected), 0, 0, len(cases)), context)
            self.assertEqual(report['status'], 'partial' if partial else 'ok', context)
            actual = []
            for row in report.get('findings', []):
                self.assertEqual((row.get('rule', row.get('rule_id')), row['severity'], row['category_id']),
                                 (RULE, 'critical', 'elixir.security'), context)
                actual.append((Path(row.get('path', row.get('file'))).name, row['line'], row['col']))
        self.assertEqual(sorted(actual), expected, context)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_SQL_E2E') == '1', 'set UBS_ELIXIR_SQL_E2E=1 for actual CLI probes')
    def test_public_module_and_runner(self):
        directory = self.materialize(CASES, 'public')
        for mode in ('module-json', 'module-sarif', 'json', 'sarif'):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, CASES)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_SQL_E2E') == '1', 'set UBS_ELIXIR_SQL_E2E=1 for actual CLI probes')
    def test_public_partial_and_independent_neighbor(self):
        cases = (CASES[0], CASES[19], PARTIAL[-1])
        directory = self.materialize(cases, 'public-partial')
        for mode in ('module-json', 'sarif'):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases, partial=True)

    @unittest.skipUnless(os.environ.get('UBS_ELIXIR_SQL_E2E') == '1', 'set UBS_ELIXIR_SQL_E2E=1 for actual CLI probes')
    def test_public_selection_skip_suppression_and_cache(self):
        case = CASES[0]
        directory = self.materialize((case, CASES[19]), 'public-policy')
        target = directory / (case.name + '.ex')
        self.assert_report(*self.execute(target, 'json'), 'json', (case,))
        result, report = self.execute(directory, 'json', ('--skip-elixir=4',))
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertFalse(any(row.get('rule_id') == RULE for row in report.get('findings', [])))
        self.assert_report(*self.execute(directory, 'json', cached=True), 'json', (case, CASES[19]))
        self.assert_report(*self.execute(directory, 'json', cached=True), 'json', (case, CASES[19]))
        suppressed = Case(case.name, case.source.replace('# sql', '# ubs:ignore[' + RULE + ']'))
        target.write_text(suppressed.source, encoding='utf-8')
        self.assert_report(*self.execute(directory, 'json', cached=True), 'json', (suppressed, CASES[19]))


if __name__ == '__main__':
    unittest.main()
