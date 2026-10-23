"""Independent Kotlin/JVM SQL-flow cases for the native SQL category.

The unsafe fixtures execute actual JDBC calls with request-derived SQL. Bound
values occupy separate PreparedStatement operands. Markers identify execution
sites; no expectation is calculated by another implementation of the analyzer.
Optional compilation uses the real JDK and released Servlet API, without API
stubs. Public checks use both the module and meta-runner.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULE = "kotlin.security.sql-injection"
SQL_ONLY = ",".join(str(number) for number in range(1, 23) if number != 13)
OVERLOADS = '''
    fun selected(input: HttpServletRequest, label: String): String? = input.getParameter("query")
    fun selected(input: String, label: HttpServletRequest): String = "SELECT 1"
'''


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    parameters: str = "request: HttpServletRequest, statement: Statement"
    helpers: str = ""
    imports: str = ""

    @property
    def source(self):
        return ("import java.sql.Statement\nimport java.sql.Connection\n"
                "import java.sql.PreparedStatement\n"
                "import jakarta.servlet.http.HttpServletRequest\n" + self.imports + "\n"
                + textwrap.dedent(self.helpers).strip() + "\n"
                + f"fun handle({self.parameters}) {{\n"
                + textwrap.indent(textwrap.dedent(self.body).strip(), "    ") + "\n}\n")

    @property
    def expected(self):
        return [(line, len(text) - len(text.lstrip()) + 1)
                for line, text in enumerate(self.source.splitlines(), 1)
                if "// SQL_EXEC" in text]


CASES = (
    Case("direct_parameter", 'statement.executeQuery(request.getParameter("query")) // SQL_EXEC'),
    Case("template", '''
        val input = request.getParameter("name")
        val sql = "SELECT * FROM users WHERE name = '$input'"
        statement.executeQuery(sql) // SQL_EXEC
    '''),
    Case("template_expression", '''
        statement.executeQuery("SELECT '${request.getParameter("name")}'") // SQL_EXEC
    '''),
    Case("concatenation", '''
        val sql = "SELECT '" + request.getHeader("X-Name") + "'"
        statement.execute(sql, Statement.RETURN_GENERATED_KEYS) // SQL_EXEC
    '''),
    Case("request_alias", '''
        val incoming = request
        val sql = incoming.getParameter("query")
        val database = statement
        database.executeUpdate(sql) // SQL_EXEC
    '''),
    Case("synthetic_query_property", 'statement.execute(request.queryString) // SQL_EXEC'),
    Case("synthetic_uri_property", 'statement.execute(request.requestURI) // SQL_EXEC'),
    Case("synthetic_property_call", 'statement.execute(request.queryString.orEmpty()) // SQL_EXEC'),
    Case("synthetic_property_trim", 'statement.execute(request.queryString.trim()) // SQL_EXEC'),
    Case("grouped_synthetic_property", 'statement.execute((request).queryString) // SQL_EXEC'),
    Case("qualified_types", 'statement.execute(request.getParameter("query")) // SQL_EXEC',
         parameters="request: jakarta.servlet.http.HttpServletRequest, statement: java.sql.Statement"),
    Case("import_aliases", 'database.execute(input.getParameter("query")) // SQL_EXEC',
         parameters="input: Incoming, database: Database",
         imports="import jakarta.servlet.http.HttpServletRequest as Incoming\nimport java.sql.Statement as Database"),
    Case("type_aliases", 'database.execute(input.getParameter("query")) // SQL_EXEC',
         parameters="input: Incoming, database: Database",
         helpers="typealias Incoming = HttpServletRequest\ntypealias Database = java.sql.Statement"),
    Case("connection_factory", '''
        val query = request.getParameter("query")
        val statement = connection.createStatement()
        statement.execute(query) // SQL_EXEC
    ''', parameters="request: HttpServletRequest, connection: Connection"),
    Case("prepared_captures_sql", '''
        var query = "SELECT '${request.getParameter("name")}' WHERE tenant = ?"
        val prepared = connection.prepareStatement(query)
        prepared.setInt(1, 4)
        query = "SELECT 1"
        prepared.executeQuery() // SQL_EXEC
    ''', parameters="request: HttpServletRequest, connection: Connection"),
    Case("prepared_alias", '''
        val prepared = connection.prepareStatement(request.getParameter("query"))
        val selected = prepared
        selected.execute() // SQL_EXEC
    ''', parameters="request: HttpServletRequest, connection: Connection"),
    Case("helper_returns_source", '''
        val query = selected(request)
        statement.execute(query) // SQL_EXEC
    ''', helpers='fun selected(input: HttpServletRequest): String? = input.getParameter("query")'),
    Case("named_overload_source", '''
        val fixed: String = "SELECT 1"
        statement.execute(selected(label = fixed, input = request)) // SQL_EXEC
    ''', helpers=OVERLOADS),
    Case("named_overload_clean", '''
        val fixed: String = "SELECT 1"
        statement.execute(selected(label = request, input = fixed))
    ''', helpers=OVERLOADS),
    Case("named_overload_same_order_clean", '''
        val fixed: String = "SELECT 1"
        statement.execute(selected(input = fixed, label = request))
    ''', helpers=OVERLOADS),
    Case("named_literal_overload_clean", '''
        statement.execute(selected(label = request, input = "tag"))
    ''', helpers=OVERLOADS),
    Case("named_literal_overload_source", '''
        statement.execute(selected(label = "tag", input = request)) // SQL_EXEC
    ''', helpers=OVERLOADS),
    Case("positional_overload_clean", '''
        val fixed: String = "SELECT 1"
        statement.execute(selected(fixed, request))
    ''', helpers=OVERLOADS),
    Case("local_helper_shadows_outer_source", '''
        fun selected(input: HttpServletRequest): String = "SELECT 1"
        statement.execute(selected(request))
    ''', helpers='fun selected(input: HttpServletRequest): String? = input.getParameter("query")'),
    Case("helper_executes_query", '''
        selected(statement, request.getParameter("query"))
    ''', helpers='''
        fun selected(database: Statement, text: String?) {
            database.execute(text) // SQL_EXEC
        }
    '''),
    Case("unknown_branch", '''
        var query = "SELECT 1"
        if (choose) { query = request.getParameter("query") }
        statement.execute(query) // SQL_EXEC
    ''', parameters="request: HttpServletRequest, statement: Statement, choose: Boolean"),
    Case("raw_batch", '''
        statement.addBatch(request.getParameter("query"))
        statement.executeBatch() // SQL_EXEC
    '''),
    Case("static_sql", 'statement.execute("SELECT 1")'),
    Case("actual_binding", '''
        val prepared = connection.prepareStatement("SELECT * FROM users WHERE name = ?")
        prepared.setString(1, request.getParameter("name"))
        prepared.executeQuery()
    ''', parameters="request: HttpServletRequest, connection: Connection"),
    Case("safe_rebinding", '''
        var query = request.getParameter("query")
        query = "SELECT 1"
        statement.execute(query)
    '''),
    Case("safe_helper", '''
        statement.execute(selected(request.getParameter("query")))
    ''', helpers='fun selected(input: String?): String = "SELECT 1"'),
    Case("static_default", 'statement.execute(selected(request))',
         helpers='fun selected(input: HttpServletRequest, value: String? = "SELECT 1"): String? = value'),
    Case("unreachable_branch", '''
        var query = "SELECT 1"
        if (false) { query = request.getParameter("query") }
        statement.execute(query)
    '''),
    Case("separate_functions", '''
        val query = "SELECT 1"
        statement.execute(query)
    ''', helpers='fun unrelated(request: HttpServletRequest) { val query = request.getParameter("query") }'),
    Case("fake_request", 'statement.execute(request.getParameter("query"))',
         parameters="request: FixedRequest, statement: Statement",
         helpers='class FixedRequest { fun getParameter(key: String): String = "SELECT 1" }'),
    Case("fake_synthetic_property", 'statement.execute(request.queryString.orEmpty())',
         parameters="request: FixedRequest, statement: Statement",
         helpers='class FixedRequest { val queryString: String = "SELECT 1" }'),
    Case("fake_statement", 'statement.execute(request.getParameter("query"))',
         parameters="request: HttpServletRequest, statement: Recorder",
         helpers='class Recorder { fun execute(text: String?) { println(text) } }'),
    Case("explicit_import_precedes_package_type", 'statement.execute(request.getParameter("query")) // SQL_EXEC',
         helpers='class Statement { fun execute(text: String?) { println(text) } }'),
    Case("local_classifier_shadows_import", '''
        class Statement { fun execute(text: String?) { println(text) } }
        val statement = Statement()
        statement.execute(request.getParameter("query"))
    ''', parameters="request: HttpServletRequest"),
    Case("local_classifier_shadows_type_alias", '''
        class Database { fun execute(text: String?) { println(text) } }
        val statement: Database = Database()
        statement.execute(request.getParameter("query"))
    ''', parameters="request: HttpServletRequest", helpers="typealias Database = java.sql.Statement"),
    Case("literal_decoys", '''
        val text = "statement.execute(request.getParameter(\\\"query\\\"))"
        // statement.execute(request.getParameter("query"))
        statement.execute("SELECT 1")
    '''),
    Case("cleared_batch", '''
        statement.addBatch(request.getParameter("query"))
        statement.clearBatch()
        statement.executeBatch()
    '''),
)

DEFAULT_CASES = (
    Case("default_source_helper", '''
        statement.execute(selected(request)) // SQL_EXEC
        statement.execute(selected(request, "fixed")) // SQL_EXEC
    ''', helpers='fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")'),
    Case("default_sink_helper", 'selected(statement, request.getParameter("query"))', helpers='''
        fun selected(database: Statement, text: String?, mode: String = "fixed") {
            database.execute(text) // SQL_EXEC
        }
    '''),
    Case("default_factory_captures_query", '''
        var query = request.getParameter("query")
        val prepared = selected(connection, query)
        query = "SELECT 1"
        prepared.setString(1, "fixed")
        prepared.execute() // SQL_EXEC
    ''', parameters="request: HttpServletRequest, connection: Connection", helpers='''
        fun selected(database: Connection, text: String?, mode: String = "fixed"): PreparedStatement =
            database.prepareStatement(text)
    '''),
    Case("default_factory_static_template", '''
        val prepared = selected(connection)
        prepared.setString(1, request.getParameter("query"))
        prepared.execute()
    ''', parameters="request: HttpServletRequest, connection: Connection", helpers='''
        fun selected(database: Connection, text: String = "SELECT ?"): PreparedStatement =
            database.prepareStatement(text)
    '''),
    Case("default_factory_objects_stay_distinct", '''
        val unsafe = selected(connection, request.getParameter("query"))
        val fixed = selected(connection)
        fixed.execute()
        unsafe.execute() // SQL_EXEC
    ''', parameters="request: HttpServletRequest, connection: Connection", helpers='''
        fun selected(database: Connection, text: String? = "SELECT 1"): PreparedStatement =
            database.prepareStatement(text)
    '''),
    Case("default_returned_argument_retains_batch_identity", '''
        statement.addBatch(request.getParameter("query"))
        val alias = selected(statement)
        alias.clearBatch()
        statement.executeBatch()
    ''', helpers='fun selected(database: Statement, mode: String = "fixed"): Statement = database'),
    Case("default_clean_helper", 'statement.execute(selected(request))',
         helpers='fun selected(input: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"'),
    Case("default_before_named_required_parameter", 'statement.execute(selected(input = request)) // SQL_EXEC',
         helpers='fun selected(mode: String = "fixed", input: HttpServletRequest): String? = input.getParameter("query")'),
    Case("default_multiple_named_slots", '''
        selected(text = request.getParameter("query"), database = statement)
    ''', helpers='''
        fun selected(mode: String = "fixed", database: Statement, count: Int = 1, text: String?) {
            database.execute(text) // SQL_EXEC
        }
    '''),
    Case("default_overload_request", 'statement.execute(selected(request)) // SQL_EXEC', helpers='''
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_overload_string", '''
        val fixed: String = "SELECT 1"
        statement.execute(selected(fixed))
    ''', helpers='''
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_overload_local_request_type", 'statement.execute(selected(request))',
         parameters="request: FixedRequest, statement: Statement", helpers='''
        class FixedRequest { fun getParameter(key: String): String = "SELECT 1" }
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: FixedRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_named_overload_request", '''
        val fixed: String = "fixed"
        statement.execute(selected(label = fixed, input = request)) // SQL_EXEC
    ''', helpers='''
        fun selected(input: HttpServletRequest, label: String, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, label: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_named_overload_string", '''
        val fixed: String = "fixed"
        statement.execute(selected(label = request, input = fixed))
    ''', helpers='''
        fun selected(input: HttpServletRequest, label: String, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, label: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_named_literal_overload_string", '''
        statement.execute(selected(label = request, input = "tag"))
    ''', helpers='''
        fun selected(input: HttpServletRequest, label: String, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, label: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_named_literal_overload_request", '''
        statement.execute(selected(label = "tag", input = request)) // SQL_EXEC
    ''', helpers='''
        fun selected(input: HttpServletRequest, label: String, mode: String = "fixed"): String? = input.getParameter("query")
        fun selected(input: String, label: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_local_helper_shadows_outer_source", '''
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
        statement.execute(selected(request))
    ''', helpers='fun selected(input: HttpServletRequest): String? = input.getParameter("query")'),
    Case("default_local_source_shadows_outer_clean", '''
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")
        statement.execute(selected(request)) // SQL_EXEC
    ''', helpers='fun selected(input: HttpServletRequest): String = "SELECT 1"'),
    Case("default_local_any_shadows_outer_exact_source", '''
        fun selected(input: Any, mode: String = "fixed"): String = "SELECT 1"
        statement.execute(selected(request))
    ''', helpers='fun selected(input: HttpServletRequest): String? = input.getParameter("query")'),
    Case("default_fewer_omissions_select_clean_overload", 'statement.execute(selected(request))', helpers='''
        fun selected(input: HttpServletRequest): String = "SELECT 1"
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String? = input.getParameter("query")
    '''),
    Case("default_fewer_omissions_select_source_overload", 'statement.execute(selected(request)) // SQL_EXEC', helpers='''
        fun selected(input: HttpServletRequest): String? = input.getParameter("query")
        fun selected(input: HttpServletRequest, mode: String = "fixed"): String = "SELECT 1"
    '''),
    Case("default_grouped_literal", 'statement.execute(selected(request))',
         helpers='fun selected(input: HttpServletRequest, text: String = (("SELECT 1"))): String = text'),
    Case("default_scalar_literals", 'statement.execute(selected(request))', helpers='''
        fun selected(input: HttpServletRequest, enabled: Boolean = true, count: Long = -1L,
                     ratio: Double = 1.5, marker: Char = 'x', absent: String? = null): String = "SELECT 1"
    '''),
    Case("default_reference_explicit_override_clean", '''
        statement.execute(selected(request.getParameter("query"), value = "SELECT 1"))
    ''', helpers='fun selected(input: String?, value: String? = input): String? = value'),
    Case("default_reference_explicit_override_source", '''
        statement.execute(selected("SELECT 1", value = request.getParameter("query"))) // SQL_EXEC
    ''', helpers='fun selected(input: String?, value: String? = input): String? = value'),
)
CASES += DEFAULT_CASES

INCOMPLETE_CASES = (
    Case("nullable_request_assertion", 'statement.execute(request!!.getParameter("query"))',
         parameters="request: HttpServletRequest?, statement: Statement"),
    Case("nullable_request_safe_call", 'statement.execute(request?.getParameter("query"))',
         parameters="request: HttpServletRequest?, statement: Statement"),
    Case("nullable_statement_assertion", 'statement!!.execute(request.getParameter("query"))',
         parameters="request: HttpServletRequest, statement: Statement?"),
    Case("nullable_statement_safe_call", 'statement?.execute(request.getParameter("query"))',
         parameters="request: HttpServletRequest, statement: Statement?"),
    Case("resource_callback", 'connection.createStatement().use { it.execute(request.getParameter("query")) }',
         parameters="request: HttpServletRequest, connection: Connection"),
    Case("unresolved_extension_property", 'statement.execute(request.queryString.selected.orEmpty())',
         helpers='val String.selected: String get() = this'),
    Case("synthetic_property_default", 'statement.execute(selected(request))',
         helpers='fun selected(input: HttpServletRequest, value: String? = input.queryString): String? = value'),
    Case("request_getter_default", 'statement.execute(selected(request))',
         helpers='fun selected(input: HttpServletRequest, value: String? = input.getQueryString()): String? = value'),
    Case("request_value_reference_default", 'statement.execute(selected(request.getParameter("query")))',
         helpers='fun selected(input: String?, value: String? = input): String? = value'),
    Case("request_value_call_default", 'statement.execute(selected(request.getParameter("query")))', helpers='''
        fun identity(value: String?): String? = value
        fun selected(input: String?, value: String? = identity(input)): String? = value
    '''),
    Case("request_value_template_default", 'statement.execute(selected(request.getParameter("query")))',
         helpers='fun selected(input: String?, value: String = "$input"): String = value'),
    Case("default_batch_helper", '''
        statement.addBatch(request.getParameter("query"))
        selected(statement)
    ''', helpers='fun selected(database: Statement, mode: String = "fixed") { database.executeBatch() }'),
    Case("default_builder_helper", 'statement.execute(selected(builder))',
         parameters="request: HttpServletRequest, statement: Statement, builder: StringBuilder",
         helpers='fun selected(input: StringBuilder, mode: String = "fixed"): String = input.toString()'),
    Case("request_extension_receiver", 'statement.execute(request.selected())',
         helpers='fun HttpServletRequest.selected(): String? = this.getParameter("query")'),
    Case("jdbc_extension_receiver", 'statement.selected(request.getParameter("query"))',
         helpers='fun Statement.selected(value: String?) { execute(value) }'),
)


class KotlinSqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / "test-suite/artifacts/kotlin-sql" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifacts.mkdir(parents=True)

    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)

    def tearDown(self):
        print(f"[{self.id()}] DONE ({time.monotonic() - self.started:.3f}s)", flush=True)

    def public_scan(self, label, directory, runner="modules/ubs-kotlin.sh", output_format="json",
                    *, options=(), env=None, skip=SQL_ONLY):
        temporary = self.artifacts / "temporary"
        temporary.mkdir(exist_ok=True)
        command = [str(ROOT / runner), str(directory), "--ci", "--format=" + output_format,
                   "--skip=" + skip, *options]
        if runner == "ubs":
            command.append("--only=kotlin")
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120,
                                env={**os.environ, "UBS_NO_CACHE": "1", "NO_COLOR": "1",
                                     "UBS_NO_AUTO_UPDATE": "1", "TMPDIR": str(temporary),
                                     "XDG_CACHE_HOME": str(self.artifacts / "cache"), **(env or {})})
        prefix = self.artifacts / label
        prefix.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        prefix.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
        prefix.with_suffix(".receipt.json").write_text(json.dumps({
            "command": command, "returncode": result.returncode,
        }, indent=2) + "\n", encoding="utf-8")
        return result, json.loads(result.stdout)

    @staticmethod
    def sites(report, output_format="json"):
        if output_format == "json":
            rows = ([row for scanner in report["scanners"] for row in scanner["findings"]]
                    if "scanners" in report else report["findings"])
            return sorted((Path(row["path"]).name, row["line"], row["col"])
                          for row in rows if row["rule"] == RULE)
        actual = []
        for run in report["runs"]:
            for row in run.get("results", []):
                if row["ruleId"] == RULE:
                    location = row["locations"][0]["physicalLocation"]
                    actual.append((Path(location["artifactLocation"]["uri"]).name,
                                   location["region"]["startLine"], location["region"]["startColumn"]))
        return sorted(actual)

    def test_independent_source_cases(self):
        native = importlib.import_module("ubs_core.analyzers.taint_kotlin_sql")
        for case in CASES:
            with self.subTest(case=case.name):
                path = self.artifacts / (case.name + ".kt")
                path.write_text(case.source, encoding="utf-8")
                findings = native.analyze_source(path, case.source)
                (self.artifacts / (case.name + ".json")).write_text(json.dumps({
                    "source_sha256": hashlib.sha256(case.source.encode()).hexdigest(),
                    "expected": case.expected, "findings": findings,
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual([(row["line"], row["col"]) for row in findings], case.expected, case.source)
                for row in findings:
                    self.assertEqual(row["rule"], RULE)
                    self.assertEqual(row["severity"], "critical")
                    self.assertEqual(row["extras"]["taint_path"][-1]["line"], row["line"])

    def test_selected_unsupported_flow_is_explicit(self):
        native = importlib.import_module("ubs_core.analyzers.taint_kotlin_sql")
        for case in INCOMPLETE_CASES:
            with self.subTest(case=case.name):
                path = self.artifacts / (case.name + ".kt")
                path.write_text(case.source, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    native.analyze_source(path, case.source)

    def test_policy_limits_and_disabled_rule(self):
        native = importlib.import_module("ubs_core.analyzers.taint_kotlin_sql")
        from ubs_core.registry import RunContext
        case = CASES[0]
        path = self.artifacts / "limits.kt"
        path.write_text(case.source, encoding="utf-8")
        for key in ("UBS_KOTLIN_MAX_TOKENS", "UBS_KOTLIN_MAX_NESTING", "UBS_KOTLIN_SQL_MAX_STEPS"):
            for value in ("0", "-1", "invalid", "1"):
                with self.subTest(key=key, value=value), mock.patch.dict(os.environ, {key: value}):
                    with self.assertRaises(ValueError):
                        native.analyze_source(path, case.source)
                    self.assertEqual(list(native.run(RunContext(lang="kotlin", files=[path],
                                                               profile={"disabled_rules": [RULE]}))), [])

    @unittest.skipUnless(os.environ.get("UBS_KOTLIN_SQL_E2E") == "1", "set UBS_KOTLIN_SQL_E2E=1 for real CLI checks")
    def test_public_module_and_meta_runner(self):
        directory = self.artifacts / "public"
        directory.mkdir()
        expected = []
        for case in CASES:
            path = directory / (case.name + ".kt")
            path.write_text(case.source, encoding="utf-8")
            expected.extend((path.name, line, column) for line, column in case.expected)
        for runner in ("modules/ubs-kotlin.sh", "ubs"):
            for output_format in ("json", "sarif"):
                label = runner.replace("/", "-") + "-" + output_format
                result, report = self.public_scan(label, directory, runner, output_format)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                if output_format == "json":
                    self.assertEqual(report["status"], "ok", report)
                self.assertEqual(self.sites(report, output_format), sorted(expected), result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("UBS_KOTLIN_SQL_E2E") == "1", "set UBS_KOTLIN_SQL_E2E=1 for real CLI checks")
    def test_public_incomplete_retains_neighbor_and_sarif_failure(self):
        directory = self.artifacts / "partial"
        directory.mkdir()
        valid = directory / "valid.kt"
        valid.write_text(CASES[0].source, encoding="utf-8")
        (directory / "unsupported.kt").write_text(INCOMPLETE_CASES[0].source, encoding="utf-8")
        expected = [(valid.name, line, col) for line, col in CASES[0].expected]
        for runner in ("modules/ubs-kotlin.sh", "ubs"):
            for fmt in ("json", "sarif"):
                with self.subTest(runner=runner, fmt=fmt):
                    result, report = self.public_scan("partial-" + runner.replace("/", "-") + "-" + fmt,
                                                      directory, runner, fmt)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(self.sites(report, fmt), expected)
                    if fmt == "json":
                        self.assertNotEqual(report["status"], "ok")
                        self.assertIn("Nullable Kotlin JDBC/request receiver", json.dumps(report))
                    else:
                        invocations = [inv for run in report["runs"] for inv in run.get("invocations", [])]
                        self.assertTrue(any(inv.get("executionSuccessful") is False for inv in invocations), report)
                        self.assertIn("Nullable Kotlin JDBC/request receiver", json.dumps(invocations))

    @unittest.skipUnless(os.environ.get("UBS_KOTLIN_SQL_E2E") == "1", "set UBS_KOTLIN_SQL_E2E=1 for real CLI checks")
    def test_public_selection_suppression_and_policy_cache(self):
        directory = self.artifacts / "selection"
        directory.mkdir()
        selected = directory / "selected.kt"
        selected.write_text(Case("suppression", '''
            statement.execute(request.getParameter("query")) // ubs:ignore[kotlin.security.sql-injection]
            statement.execute(request.getParameter("query")) // ubs:ignore[kotlin.some-other-rule]
        ''').source, encoding="utf-8")
        ignored = directory / "ignored.kt"
        ignored.write_text(INCOMPLETE_CASES[0].source, encoding="utf-8")
        listing = self.artifacts / "selected-files"
        listing.write_bytes(os.fsencode(selected) + b"\0")
        expected_line = next(number for number, line in enumerate(selected.read_text().splitlines(), 1)
                             if "some-other-rule" in line)
        for runner in ("modules/ubs-kotlin.sh", "ubs"):
            result, report = self.public_scan("selection-" + runner.replace("/", "-"),
                                              selected if runner == "ubs" else directory, runner,
                                              options=() if runner == "ubs" else ("--files-from=" + str(listing),))
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(report["status"], "ok", report)
            self.assertEqual(self.sites(report), [(selected.name, expected_line, 5)])
        all_categories = ",".join(str(number) for number in range(1, 23))
        result, report = self.public_scan("disabled-before-parse", directory, skip=all_categories,
                                          env={"UBS_KOTLIN_SQL_MAX_STEPS": "invalid"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["status"], "ok", report)
        self.assertEqual(self.sites(report), [])

        valid = self.artifacts / "cached.kt"
        valid.write_text(CASES[0].source, encoding="utf-8")
        cache_stats = self.artifacts / "policy-cache.json"
        cache_env = {"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(self.artifacts / "policy-cache"),
                     "UBS_CACHE_FILE": str(cache_stats)}
        for label in ("cold", "warm"):
            result, report = self.public_scan("cache-" + label, valid, env=cache_env)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(self.sites(report), [(valid.name, *CASES[0].expected[0])])
        self.assertGreater(json.loads(cache_stats.read_text())["hits"], 0)
        result, report = self.public_scan("cache-changed-budget", valid,
                                          env={**cache_env, "UBS_KOTLIN_SQL_MAX_STEPS": "1"})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotEqual(report["status"], "ok", report)
        self.assertEqual(self.sites(report), [])
        result, report = self.public_scan("cache-recovered", valid, env=cache_env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(report["status"], "ok", report)

    @unittest.skipUnless(os.environ.get("UBS_KOTLINC") and os.environ.get("UBS_SERVLET_JAR"),
                         "set UBS_KOTLINC and UBS_SERVLET_JAR for real JVM source compilation")
    def test_sources_compile_against_real_jdbc_and_servlet(self):
        def compile_case(case):
            directory = self.artifacts / "compiler" / case.name
            directory.mkdir(parents=True)
            source = directory / "Input.kt"
            source.write_text(case.source, encoding="utf-8")
            command = [os.environ["UBS_KOTLINC"], str(source), "-classpath", os.environ["UBS_SERVLET_JAR"],
                       "-d", str(directory / "classes")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            (directory / "stdout").write_text(result.stdout, encoding="utf-8")
            (directory / "stderr").write_text(result.stderr, encoding="utf-8")
            (directory / "receipt.json").write_text(json.dumps({
                "command": command, "returncode": result.returncode,
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }, indent=2) + "\n", encoding="utf-8")
            return case, result
        with ThreadPoolExecutor(max_workers=2) as pool:
            for case, result in pool.map(compile_case, (*CASES, *INCOMPLETE_CASES)):
                with self.subTest(case=case.name):
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SpringKotlinSqlTests(unittest.TestCase):
    imports = ("import org.springframework.jdbc.core.JdbcTemplate\n"
               "import org.springframework.jdbc.core.JdbcOperations\n"
               "import org.springframework.jdbc.core.RowMapper\n"
               "import org.springframework.jdbc.core.PreparedStatementCreator\n"
               "import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate\n"
               "import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations\n"
               "import org.springframework.web.client.RestTemplate\n"
               "import org.springframework.web.client.ResponseExtractor\n"
               "import org.springframework.http.HttpMethod\n")

    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / "test-suite/artifacts/kotlin-sql" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifacts.mkdir(parents=True)

    def check(self, case, *, incomplete=False, following=""):
        from ubs_core.analyzers import taint_kotlin_sql
        from ubs_core.java_detectors import ssrf_outbound_url
        source = self.imports + case.source + textwrap.dedent(following)
        path = self.artifacts / (case.name + ".kt")
        path.write_text(source, encoding="utf-8")
        if incomplete:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                taint_kotlin_sql.analyze_source(path, source)
            return
        findings = taint_kotlin_sql.analyze_source(path, source)
        expected = [(line, len(text) - len(text.lstrip()) + 1)
                    for line, text in enumerate(source.splitlines(), 1) if "// SQL_EXEC" in text]
        self.assertEqual([(row["line"], row["col"]) for row in findings], expected, source)
        for row in findings:
            self.assertEqual((row["rule"], row["severity"], row["category_id"]),
                             (RULE, "critical", "kotlin.sql"))
            self.assertEqual(row["extras"]["source_count"], 1)
            witness = row["extras"]["taint_path"]
            self.assertIn("source", {step["kind"] for step in witness})
            self.assertEqual((witness[-1]["line"], witness[-1]["col"], witness[-1]["kind"]),
                             (row["line"], row["col"], "sink"))
        outbound = list(ssrf_outbound_url.find([path]))
        self.assertEqual([row[1] for row in outbound],
                         [line for line, text in enumerate(source.splitlines(), 1) if "// SSRF_EXEC" in text], source)
        (self.artifacts / (case.name + ".json")).write_text(json.dumps({
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "expected": expected, "findings": findings,
            "ssrf": [(str(found), line, col, detail) for found, line, col, detail in outbound],
        }, indent=2) + "\n", encoding="utf-8")

    def test_import_alias_named_bindings_and_bound_values(self):
        cases = (
            Case("spring_import_alias", '''
                val sql = request.getParameter("sql")
                database.queryForList(sql, request.getParameter("bound")) // SQL_EXEC
                database.execute(sql) // SQL_EXEC
            ''', "request: HttpServletRequest, database: Database",
                 imports="import org.springframework.jdbc.core.JdbcTemplate as Database"),
            Case("spring_named_template", '''
                val sql = request.getParameter("sql")
                database.queryForList(sql, mapOf("id" to 7)) // SQL_EXEC
            ''', "request: HttpServletRequest, database: NamedParameterJdbcTemplate"),
            Case("spring_named_interface", '''
                val input = request.getParameter("name")
                val sql = "SELECT name FROM users WHERE name = '$input'"
                database.update(sql, mapOf("id" to 7)) // SQL_EXEC
            ''', "request: HttpServletRequest, database: NamedParameterJdbcOperations"),
            Case("spring_fixed_bound", '''
                val input = request.getParameter("name")
                database.queryForList("SELECT name FROM users WHERE name = ?", input)
                database.update("UPDATE users SET name = ?", input)
                named.queryForList("SELECT name FROM users WHERE name = :name", mapOf("name" to input))
                var sql = request.getParameter("sql")
                sql = "SELECT 1"
                database.execute(sql)
                database.execute(fixed(input))
            ''', "request: HttpServletRequest, database: JdbcOperations, named: NamedParameterJdbcOperations",
                 helpers='fun fixed(ignored: String?): String = "SELECT 1"'),
            Case("spring_unknown_string", '''
                database.execute(sql)
                database.queryForList(sql)
            ''', "database: JdbcOperations, sql: String"),
            Case("spring_fake_receiver", '''
                database.queryForList(request.getParameter("sql"))
            ''', "request: HttpServletRequest, database: Recorder",
                 helpers="class Recorder { fun queryForList(sql: String?) {} }"),
        )
        for case in cases:
            with self.subTest(case=case.name):
                self.check(case)

    def test_constructor_alias_branch_and_helper_receiver_flow(self):
        self.check(Case("spring_factories", '''
            val database = JdbcTemplate(source)
            val alias = selected(database)
            var sql = "SELECT 1"
            if (choose) { sql = request.getParameter("sql") }
            alias.queryForList(sql) // SQL_EXEC
            alias.execute(sql) // SQL_EXEC
            selected(database).execute(sql) // SQL_EXEC
            send(database, sql)
        ''', "request: HttpServletRequest, source: javax.sql.DataSource, choose: Boolean"), following='''
            fun selected(database: JdbcTemplate): JdbcTemplate = database
            fun send(database: JdbcOperations, sql: String) {
                database.update(sql) // SQL_EXEC
            }
        ''')
        self.check(Case("spring_named_accessor", '''
            val named = NamedParameterJdbcTemplate(source)
            val database = named.getJdbcOperations()
            database.execute(request.getParameter("sql")) // SQL_EXEC
        ''', "request: HttpServletRequest, source: javax.sql.DataSource"))

    def test_nullable_callbacks_batches_and_unknown_escapes_are_incomplete(self):
        cases = (
            Case("spring_nullable", 'database?.queryForList(request.getParameter("sql"))',
                 "request: HttpServletRequest, database: JdbcTemplate?"),
            Case("spring_creator", "database.query(creator, mapper)",
                 "database: JdbcOperations, creator: PreparedStatementCreator, mapper: RowMapper<String>"),
            Case("spring_mapper_result", '''
                val sql = database.queryForObject("SELECT 1") { row, index -> request.getParameter("sql") }
                database.queryForList(sql)
            ''', "request: HttpServletRequest, database: JdbcTemplate"),
            Case("spring_extractor_result", '''
                val sql = database.query("SELECT 1", org.springframework.jdbc.core.ResultSetExtractor {
                    request.getParameter("sql")
                })
                database.queryForList(sql)
            ''', "request: HttpServletRequest, database: JdbcTemplate"),
            Case("spring_batch", 'database.batchUpdate("SELECT 1", request.getParameter("sql"))',
                 "request: HttpServletRequest, database: JdbcOperations"),
            Case("spring_unknown_escape", 'external(database).queryForList(request.getParameter("sql"))',
                 "request: HttpServletRequest, database: JdbcTemplate"),
        )
        for case in cases:
            with self.subTest(case=case.name):
                self.check(case, incomplete=True)

    def test_http_helper_overload_remains_http(self):
        self.check(Case("spring_http_helper", '''
            val http = selected(client)
            http.execute(request.getParameter("url"), HttpMethod.GET, null, extractor) // SSRF_EXEC
        ''', "request: HttpServletRequest, client: RestTemplate, extractor: ResponseExtractor<String>",
             helpers='''
                fun selected(database: JdbcTemplate): JdbcTemplate = database
                fun selected(client: RestTemplate): RestTemplate = client
             '''))


if __name__ == "__main__":
    unittest.main(verbosity=2)
