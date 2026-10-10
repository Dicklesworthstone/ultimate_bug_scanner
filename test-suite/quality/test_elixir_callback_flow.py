"""Independent bounded Elixir callback/request-flow oracle.

Labels precede the new callback implementation.  Anonymous functions capture
their lexical values; later rebinding does not mutate those captures.  Actual
Enum.each/map eagerly invoke callbacks on selected finite lists.  Unknown
callback dispatch, unknown enumeration and code outside the selected literal
evaluation subset remain explicit analysis boundaries.

This suite uses real source and real module/meta invocations.  A successful
ast-grep parse is syntax evidence, not Elixir compilation or execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "modules/helpers"))
ARTIFACTS = ROOT / "test-suite/artifacts/elixir-callback-independent"
RULES = {
    "redirect": "elixir.taint.open_redirect",
    "path": "elixir.taint.request_path_traversal",
    "sql": "ex.security.sql-interpolation",
}
SKIP_NON_SECURITY = "1,2,3,5,6,7,8,9,10,11,12,13,14,15,16"


def module(body: str, *, helpers: str = "", parameters: str = "conn, params") -> str:
    helpers = textwrap.indent(textwrap.dedent(helpers).strip(), "  ") if helpers else ""
    return ("defmodule CallbackOracle do\n" + (helpers + "\n" if helpers else "")
            + f"  def handle({parameters}) do\n"
            + textwrap.indent(textwrap.dedent(body).strip(), "    ") + "\n  end\nend\n")


@dataclass(frozen=True)
class Case:
    name: str
    policy: str
    source: str
    partial: bool = False

    @property
    def expected(self):
        rows = []
        for number, line in enumerate(self.source.splitlines(), 1):
            if "# @flow " not in line:
                continue
            statement, call = line.split("# @flow ", 1)
            call = call.strip()
            assert statement.count(call) == 1, (self.name, number, call)
            rows.append((RULES[self.policy], number, statement.index(call) + 1))
        return rows


CASES = (
    Case("direct_identity_callback_redirect", "redirect", module('''
        callback = fn value -> value end
        Phoenix.Controller.redirect(conn, external: callback.(params["next"])) # @flow Phoenix.Controller.redirect
    ''')),
    Case("identity_callback_literal_control", "redirect", module('''
        callback = fn value -> value end
        Phoenix.Controller.redirect(conn, external: callback.("/home"))
    ''')),
    Case("capture_precedes_later_literal_rebinding", "redirect", module('''
        target = params["next"]
        callback = fn -> target end
        target = "/home"
        Phoenix.Controller.redirect(conn, external: callback.()) # @flow Phoenix.Controller.redirect
    ''')),
    Case("captured_literal_survives_later_request_rebinding", "redirect", module('''
        target = "/home"
        callback = fn -> target end
        target = params["next"]
        Phoenix.Controller.redirect(conn, external: callback.())
    ''')),
    Case("callback_parameter_shadows_outer_request_value", "redirect", module('''
        target = params["next"]
        callback = fn target -> target end
        Phoenix.Controller.redirect(conn, external: callback.("/home"))
    ''')),
    Case("callback_alias_survives_function_rebinding", "redirect", module('''
        callback = fn value -> value end
        selected = callback
        callback = fn _value -> "/home" end
        Phoenix.Controller.redirect(conn, external: selected.(params["next"])) # @flow Phoenix.Controller.redirect
    ''')),
    Case("callback_body_reports_file_execution", "path", module('''
        callback = fn file ->
          File.read!(file) # @flow File.read!
        end
        callback.(params["file"])
    ''')),
    Case("unused_callback_does_not_execute_file_sink", "path", module('''
        callback = fn -> File.read!(params["file"]) end
        :ok
    ''')),
    Case("same_file_helper_receives_callback", "redirect", module('''
        callback = fn value -> value end
        target = transform(callback, params["next"])
        Phoenix.Controller.redirect(conn, external: target) # @flow Phoenix.Controller.redirect
    ''', helpers='''
        defp transform(callback, value), do: callback.(value)
    ''')),
    Case("same_file_helper_returns_captured_callback", "redirect", module('''
        callback = remember(params["next"])
        Phoenix.Controller.redirect(conn, external: callback.()) # @flow Phoenix.Controller.redirect
    ''', helpers='''
        defp remember(value), do: fn -> value end
    ''')),
    Case("enum_each_invokes_known_list_callback", "path", module('''
        Enum.each([params["file"]], fn file ->
          File.read!(file) # @flow File.read!
        end)
    ''')),
    Case("empty_enum_does_not_execute_captured_sink", "path", module('''
        Enum.each([], fn _item -> File.read!(params["file"]) end)
    ''')),
    Case("enum_map_output_reaches_real_sql_execution", "sql", module('''
        queries = Enum.map([params["name"]], fn name -> "SELECT '#{name}'" end)
        Enum.each(queries, fn sql ->
          Ecto.Adapters.SQL.query!(ApplicationRepo, sql, []) # @flow Ecto.Adapters.SQL.query!
        end)
    ''')),
    Case("enum_map_bound_values_do_not_become_sql", "sql", module('''
        values = Enum.map([params["name"]], fn name -> name end)
        Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT $1::text", values)
    ''')),
    Case("same_file_ecto_repo_callback_identity", "sql", '''defmodule Database do
  use Ecto.Repo, otp_app: :example, adapter: Ecto.Adapters.Postgres
end
defmodule CallbackOracle do
  alias Database, as: Store
  def handle(conn, params) do
    callback = fn name ->
      Store.query!("SELECT '#{name}'", []) # @flow Store.query!
    end
    callback.(params["name"])
  end
end
'''),
    Case("local_enum_alias_uses_its_noop_body", "path", '''defmodule LocalEnumeration do
  def each(_values, _callback), do: :ok
end
defmodule CallbackOracle do
  alias LocalEnumeration, as: Enum
  def handle(conn, params) do
    Enum.each([params["file"]], fn file -> File.read!(file) end)
  end
end
'''),
    Case("static_erlang_atom_modules_are_not_dynamic", "sql", module('''
        _value = :erlang.binary_to_term(:erlang.term_to_binary(:ok))
        _digest = :crypto.hash(:sha256, "fixed")
        Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT 1", [])
    ''')),
    Case("literal_arithmetic_eval_has_no_dynamic_call", "sql", module('''
        Code.eval_string("1 + 2 * (3 - 1)")
        Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT 1", [])
    ''')),
    Case("immediate_anonymous_invocation_executes_file_sink", "path", module('''
        (fn file ->
          File.read!(file) # @flow File.read!
        end).(params["file"])
    ''')),
    Case("callback_calls_same_file_sink_helper", "path", module('''
        callback = fn file -> read(file) end
        callback.(params["file"])
    ''', helpers='''
        defp read(file) do
          File.read!(file) # @flow File.read!
        end
    ''')),
)

BOUNDARIES = (
    Case("unknown_callback_dispatch_is_partial", "redirect", module('''
        Phoenix.Controller.redirect(conn, external: callback.(params["next"]))
    ''', parameters="conn, params, callback"), partial=True),
    Case("unknown_enum_collection_is_partial", "path", module('''
        Enum.each(params["files"], fn file -> File.read!(file) end)
    '''), partial=True),
    Case("dynamic_eval_preserves_prior_known_sql", "sql", module('''
        Ecto.Adapters.SQL.query!(ApplicationRepo, params["sql"], []) # @flow Ecto.Adapters.SQL.query!
        Code.eval_string(params["code"])
    '''), partial=True),
    Case("call_bearing_literal_eval_is_partial", "sql", module(r'''
        Code.eval_string("File.read!(\"/srv/private\")")
        Ecto.Adapters.SQL.query!(ApplicationRepo, "SELECT 1", [])
    '''), partial=True),
)

REVIEW_CASES = (
    Case("same_closure_site_keeps_distinct_captures", "sql", module('''
        callbacks = Enum.map([params["sql"], "SELECT 1"], fn sql -> fn -> sql end end)
        Enum.each(callbacks, fn callback ->
          Ecto.Adapters.SQL.query!(ApplicationRepo, callback.(), []) # @flow Ecto.Adapters.SQL.query!
        end)
    ''')),
)

# Literal eval/Erlang controls intentionally stay native controls: their old
# generic security heuristics are not callback findings.  Public callback
# checks use the other unchanged 18 sources and assert every ordinary result.
PUBLIC_CASES = tuple(case for case in CASES if case.name not in {
    "static_erlang_atom_modules_are_not_dynamic", "literal_arithmetic_eval_has_no_dynamic_call",
})


def materialize(directory: Path, cases=CASES):
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for case in cases:
        path = directory / (case.name + ".ex")
        path.write_text(case.source, encoding="utf-8")
        paths[case.name] = path
    return paths


def freeze_receipt(directory: Path):
    paths = materialize(directory / "cases", CASES + BOUNDARIES)
    receipt = {
        "labels_assigned_before_callback_implementation": True,
        "python": sys.version,
        "cases": [{"name": case.name, "policy": case.policy, "source": str(paths[case.name]),
                   "sha256": hashlib.sha256(case.source.encode()).hexdigest(),
                   "expected": case.expected, "partial": case.partial}
                  for case in CASES + BOUNDARIES],
    }
    (directory / "labels.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def analyzer_for(policy):
    if policy == "redirect":
        return importlib.import_module("ubs_core.analyzers.taint_elixir_redirect").run
    native = importlib.import_module("ubs_core.analyzers.taint_elixir_traversal")
    return native.run_sql if policy == "sql" else native.run


@unittest.skipIf(os.environ.get("UBS_ELIXIR_CALLBACK_PUBLIC_ONLY") == "1", "native group already run")
class ElixirCallbackNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("native-" + uuid.uuid4().hex[:12])
        cls.paths = materialize(cls.directory, CASES + BOUNDARIES + REVIEW_CASES)

    def check_case(self, case):
        from ubs_core.registry import RunContext
        findings, error = [], None
        path = self.paths[case.name]
        try:
            findings.extend(analyzer_for(case.policy)(RunContext(lang="elixir", files=[path])))
        except ValueError as exc:
            error = str(exc)
        self.assertEqual(error is not None, case.partial, (case.name, findings, error))
        if case.partial:
            self.assertTrue(error.strip())
        self.assertEqual(sorted((row["rule"], row["line"], row["col"]) for row in findings),
                         sorted(case.expected), (case.name, findings, error))
        for row in findings:
            self.assertEqual(row["severity"], "critical", row)
            self.assertEqual(Path(row["path"]), path, row)
            trace = row["extras"]["taint_path"]
            self.assertEqual((trace[0]["kind"], trace[-1]["kind"]), ("source", "sink"), row)
            self.assertEqual((trace[-1]["line"], trace[-1]["col"]), (row["line"], row["col"]), row)

    def test_unmodified_ast_pack_has_external_eval_boundary(self):
        from ubs_core.registry import RunContext
        path = ROOT / "test-suite/elixir/ast_grep_rule_pack_coverage.ex"
        findings = []
        with self.assertRaisesRegex(ValueError, "(?i)eval_file|external.*eval|eval.*file"):
            findings.extend(analyzer_for("sql")(RunContext(lang="elixir", files=[path])))
        self.assertEqual(findings, [])

    def test_permanent_callback_fixture_pair(self):
        from ubs_core.registry import RunContext
        for name, expected in (("sql_buggy.ex", [(4, 7), (12, 7), (19, 7)]), ("sql_clean.ex", [])):
            path = ROOT / "test-suite/elixir/callbacks" / name
            with self.subTest(fixture=name):
                findings = list(analyzer_for("sql")(RunContext(lang="elixir", files=[path])))
                self.assertEqual(sorted((row["line"], row["col"]) for row in findings), expected)
                self.assertTrue(all(row["rule"] == RULES["sql"] and row["severity"] == "critical"
                                    for row in findings), findings)

    def test_callback_analysis_budget_is_explicit(self):
        native = importlib.import_module("ubs_core.analyzers.taint_elixir_traversal")
        from ubs_core.taint_flow import Budget
        case = CASES[0]
        with self.assertRaisesRegex(ValueError, "(?i)budget|incomplete|limit"):
            native.ElixirEngine(self.paths[case.name], case.source, case.policy, Budget(5)).analyze()


for _case in CASES + BOUNDARIES + REVIEW_CASES:
    def _test(self, case=_case):
        self.check_case(case)
    setattr(ElixirCallbackNativeTests, "test_" + _case.name, _test)


@unittest.skipUnless(os.environ.get("UBS_ELIXIR_CALLBACK_PUBLIC") == "1",
                     "set UBS_ELIXIR_CALLBACK_PUBLIC=1 after verified module/helper pins")
class ElixirCallbackPublicTests(unittest.TestCase):
    """Eight real commands exercise frozen callback labels and public behavior."""

    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("public-" + uuid.uuid4().hex[:12])
        cls.directory.mkdir(parents=True)
        cls.identity = {
            "python": sys.version,
            "python_executable": sys.executable,
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                            text=True).strip(),
            "elixir": shutil.which("elixir"),
            "ast_grep": shutil.which("ast-grep"),
            "sources": {
                path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in (
                    "ubs", "modules/ubs-elixir.sh", "modules/helpers/ubs_core/elixir_scan.py",
                    "modules/helpers/ubs_core/analyzers/taint_elixir_traversal.py",
                    "modules/helpers/ubs_core/analyzers/lifecycle_elixir.py",
                    "test-suite/quality/test_elixir_callback_flow.py",
                )
            },
        }

    def project(self, label, cases):
        directory = self.directory / label
        materialize(directory, cases)
        return directory

    def execute(self, target, mode="module-json", *, extra=(), cached=False):
        attempt = self.directory / ("command-" + uuid.uuid4().hex[:10])
        attempt.mkdir()
        environment = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                           ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                           UBS_NO_CACHE="0" if cached else "1",
                           UBS_CACHE_DIR=str(self.directory / "cache"),
                           UBS_CACHE_FILE=str(attempt / "cache-stats.json"), TMPDIR=str(attempt))
        if mode.startswith("module-"):
            command = [str(ROOT / "modules/ubs-elixir.sh"), "--ci", "--no-color", "--only=4",
                       "--format=" + mode.split("-", 1)[1], *extra, str(target)]
        else:
            command = [str(ROOT / "ubs"), "--ci", "--no-config", "--only=elixir",
                       "--skip-elixir=" + SKIP_NON_SECURITY, "--format=" + mode,
                       *extra, str(target)]
        started = time.monotonic()
        # Source context includes cwd; cold/warm scans keep it unchanged.
        result = subprocess.run(command, cwd=target, env=environment, text=True,
                                capture_output=True, timeout=120)
        (attempt / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "cwd": str(target), "exit": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "environment": {key: environment.get(key) for key in (
                "PATH", "UBS_NO_AUTO_UPDATE", "UBS_NO_CACHE", "UBS_CACHE_DIR", "UBS_CACHE_FILE", "TMPDIR",
            )},
            "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(target.rglob("*.ex"))},
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[elixir-callback-cli:{attempt.name}] exit={result.returncode} "
              f"{time.monotonic() - started:.3f}s " + " ".join(command), flush=True)
        self.last_attempt = attempt
        try:
            report = json.loads(result.stdout)
        except ValueError:
            self.fail((result.returncode, result.stdout, result.stderr))
        return result, report

    def assert_report(self, result, report, mode, cases, *, partial=False, enabled=True,
                      expected_findings=None):
        context = (result.returncode, result.stdout, result.stderr)
        expected = ([(case.name + ".ex", rule, line, col, "critical")
                     for case in cases for rule, line, col in case.expected]
                    if expected_findings is None else list(expected_findings))
        if not enabled:
            expected = []
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), context)
        actual = []
        if mode.endswith("sarif"):
            from urllib.parse import unquote
            for run in report["runs"]:
                for row in run.get("results", []):
                    location = row["locations"][0]["physicalLocation"]
                    actual.append((Path(unquote(location["artifactLocation"]["uri"])).name,
                                   row["ruleId"], location["region"]["startLine"],
                                   location["region"]["startColumn"],
                                   {"error": "critical", "warning": "warning", "note": "info"}[row["level"]]))
                for invocation in run.get("invocations", []):
                    self.assertIs(invocation["executionSuccessful"], not partial, context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (len(expected), 0, 0, len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            for row in report["findings"]:
                self.assertEqual(row["category_id"], "elixir.security", context)
                actual.append((Path(row.get("path", row.get("file"))).name,
                               row.get("rule", row.get("rule_id")), row["line"], row["col"], row["severity"]))
        self.assertEqual(sorted(actual), sorted(expected), context)

    def test_complete_callback_corpus_module_json_and_meta_sarif(self):
        directory = self.project("complete", PUBLIC_CASES)
        for mode in ("module-json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, PUBLIC_CASES)

    def test_file_selection_contains_only_clean_controls(self):
        directory = self.project("selected", PUBLIC_CASES)
        cases = tuple(case for case in PUBLIC_CASES if not case.expected)
        file_list = self.directory / "selected-inputs.nul"
        file_list.write_bytes(b"".join(os.fsencode(directory / (case.name + ".ex")) + b"\0"
                                       for case in cases))
        self.assert_report(*self.execute(directory, extra=("--files-from", str(file_list))),
                           "module-json", cases)

    def test_category_skip_precedes_callback_analysis(self):
        cases = (BOUNDARIES[0], CASES[0])
        directory = self.project("category-skip", cases)
        self.assert_report(*self.execute(directory, extra=("--skip=4",)), "module-json", cases,
                           enabled=False)

    def test_partial_dispatch_preserves_known_neighbor(self):
        cases = (Case("a_partial", BOUNDARIES[0].policy, BOUNDARIES[0].source, partial=True),
                 Case("z_neighbor", CASES[0].policy, CASES[0].source))
        directory = self.project("partial", cases)
        result, report = self.execute(directory, "json")
        self.assert_report(result, report, "json", cases, partial=True)
        self.assertIn("a_partial.ex", result.stderr)

    def test_warm_cache_and_scoped_suppression(self):
        case = Case("cache_target", CASES[0].policy, CASES[0].source)
        directory = self.project("cache-project", (case,))
        for phase in ("cold", "warm"):
            with self.subTest(phase=phase):
                self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
                stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
                self.assertEqual((stats["hits"], stats["misses"]), (1, 0) if phase == "warm" else (0, 1))
        suppressed = case.source.replace("# @flow Phoenix.Controller.redirect",
                                         "# ubs:ignore[elixir.taint.open_redirect]")
        (directory / "cache_target.ex").write_text(suppressed, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "module-json", (case,),
                           expected_findings=[])
        stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
        self.assertEqual((stats["hits"], stats["misses"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
