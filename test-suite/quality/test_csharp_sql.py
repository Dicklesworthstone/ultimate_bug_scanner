"""Independent Dapper SQL oracle, frozen before the new analyzer was inspected.

The labels describe the selected in-file model: real Dapper string-SQL calls,
resolved ADO.NET receivers and ASP.NET request inputs.  A clean label means no
proven request-to-SQL flow in that model, not a claim about arbitrary callers.
CommandDefinition, deferred execution and unresolved dispatch are explicit
boundaries.  Sources are parsed with the actual C# grammar when available;
this suite does not pretend that parsing compiles or executes Dapper.

Runtime sources and complete CLI captures stay in test-suite/artifacts.  Set
UBS_CSHARP_SQL_PUBLIC=1 to enable the actual module/meta acceptance group.
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
RULE = "cs.security.sql-injection"
ARTIFACTS = ROOT / "test-suite/artifacts/dapper-independent"
HEADER = """using System;
using System.Data;
using System.Data.Common;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Dapper;
"""


def source(body: str, *, parameters: str = "IDbConnection db, HttpRequest http, bool flag",
           helpers: str = "", async_: bool = False, extra: str = "") -> str:
    """Produce complete C# declarations; expected positions come from markers."""
    signature = "async Task" if async_ else "void"
    body = textwrap.indent(textwrap.dedent(body).strip(), "        ")
    helpers = textwrap.indent(textwrap.dedent(helpers).strip(), "    ") if helpers else ""
    return (HEADER + extra + "\nclass Row { public int Id { get; set; } }\nclass C {\n"
            + (helpers + "\n" if helpers else "")
            + f"    {signature} Run({parameters}) {{\n{body}\n    }}\n}}\n")


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    partial: bool = False

    @property
    def expected(self) -> list[tuple[str, int, int]]:
        result = []
        for line, text in enumerate(self.code.splitlines(), 1):
            if "// @sql " not in text:
                continue
            call = text.split("// @sql ", 1)[1].strip()
            statement = text.split("// @sql ", 1)[0]
            assert statement.count(call) == 1, (self.name, line, call)
            result.append((RULE, line, statement.index(call) + 1))
        return result


# These 40 complete cases were labeled from source/API semantics before the
# proposed Dapper analyzer was read or executed.  Keep their labels independent.
CASES = (
    Case("sync_string_sql_families", source('''
        var sql = http.Query["sql"].ToString();
        db.Execute(sql); // @sql db.Execute
        db.ExecuteScalar(sql); // @sql db.ExecuteScalar
        db.ExecuteScalar<int>(sql); // @sql db.ExecuteScalar
        db.Query(sql); // @sql db.Query
        db.Query<int>(sql); // @sql db.Query
        db.QueryFirst(sql); // @sql db.QueryFirst
        db.QueryFirst<int>(sql); // @sql db.QueryFirst
        db.QueryFirstOrDefault(sql); // @sql db.QueryFirstOrDefault
        db.QueryFirstOrDefault<int>(sql); // @sql db.QueryFirstOrDefault
        db.QuerySingle(sql); // @sql db.QuerySingle
        db.QuerySingle<int>(sql); // @sql db.QuerySingle
        db.QuerySingleOrDefault(sql); // @sql db.QuerySingleOrDefault
        db.QuerySingleOrDefault<int>(sql); // @sql db.QuerySingleOrDefault
    ''')),
    Case("async_string_sql_families", source('''
        var sql = http.Query["sql"].ToString();
        await db.ExecuteAsync(sql); // @sql db.ExecuteAsync
        await db.ExecuteScalarAsync(sql); // @sql db.ExecuteScalarAsync
        await db.ExecuteScalarAsync<int>(sql); // @sql db.ExecuteScalarAsync
        await db.QueryAsync(sql); // @sql db.QueryAsync
        await db.QueryAsync<int>(sql); // @sql db.QueryAsync
        await db.QueryFirstAsync(sql); // @sql db.QueryFirstAsync
        await db.QueryFirstAsync<int>(sql); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QueryFirstOrDefaultAsync<int>(sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(sql); // @sql db.QuerySingleAsync
        await db.QuerySingleAsync<int>(sql); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(sql); // @sql db.QuerySingleOrDefaultAsync
        await db.QuerySingleOrDefaultAsync<int>(sql); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("type_leading_sync_sql_position", source('''
        var sql = http.Query["sql"].ToString();
        db.Query(typeof(Row), sql); // @sql db.Query
        db.QueryFirst(typeof(Row), sql); // @sql db.QueryFirst
        db.QueryFirstOrDefault(typeof(Row), sql); // @sql db.QueryFirstOrDefault
        db.QuerySingle(typeof(Row), sql); // @sql db.QuerySingle
        db.QuerySingleOrDefault(typeof(Row), sql); // @sql db.QuerySingleOrDefault
    ''')),
    Case("type_leading_async_sql_position", source('''
        var sql = http.Query["sql"].ToString();
        await db.QueryAsync(typeof(Row), sql); // @sql db.QueryAsync
        await db.QueryFirstAsync(typeof(Row), sql); // @sql db.QueryFirstAsync
        await db.QueryFirstOrDefaultAsync(typeof(Row), sql); // @sql db.QueryFirstOrDefaultAsync
        await db.QuerySingleAsync(typeof(Row), sql); // @sql db.QuerySingleAsync
        await db.QuerySingleOrDefaultAsync(typeof(Row), sql); // @sql db.QuerySingleOrDefaultAsync
    ''', async_=True)),
    Case("static_type_leading_and_named_cnn", source('''
        var sql = http.Query["sql"].ToString();
        await SqlMapper.QueryAsync(db, typeof(Row), sql); // @sql SqlMapper.QueryAsync
        await SqlMapper.QueryAsync(type: typeof(Row), sql: sql, cnn: db, param: new { id = 1 }); // @sql SqlMapper.QueryAsync
        SqlMapper.Execute(cnn: db, sql: sql); // @sql SqlMapper.Execute
    ''', async_=True)),
    Case("named_sql_is_not_the_param_argument", source('''
        db.Execute(param: new { id = 1 }, sql: http.Query["sql"].ToString()); // @sql db.Execute
    ''')),
    Case("interpolation_remains_unsafe_with_parameters", source('''
        var id = http.Query["id"].ToString();
        db.Query<int>($"select Id from Users where Name = '{id}'", new { id }); // @sql db.Query
    ''')),
    Case("concatenated_sql_execution_location", source('''
        var name = http.Query["name"].ToString();
        var sql = "SELECT Id FROM Users WHERE Name = '" + name + "'";
        db.Query<int>(sql); // @sql db.Query
    ''')),
    Case("bound_values_are_not_sql_text", source('''
        var value = http.Query["id"].ToString();
        db.Execute("delete from Users where Id = @id", new { id = value });
        db.Query<int>("select Id from Users where Name = @name", new { name = value });
        db.QueryFirst<int>(sql: "select Id from Users where Id = @id", param: new { id = value });
        db.ExecuteScalar<int>("select count(*) from Users where Id = @id", new { id = value });
    ''')),
    Case("type_leading_bound_values_are_clean", source('''
        var value = http.Query["id"].ToString();
        db.Query(typeof(Row), "select Id from Users where Id = @id", new { id = value });
        await db.QueryAsync(typeof(Row), "select Id from Users where Id = @id", new { id = value });
        await SqlMapper.QueryAsync(cnn: db, type: typeof(Row), param: new { id = value }, sql: "select Id from Users where Id = @id");
    ''', async_=True)),
    Case("literal_interpolation_is_clean", source('''
        var table = "Users";
        db.Query<int>($"select Id from {table}");
    ''')),
    Case("comment_and_string_decoys_are_clean", source('''
        // db.Execute(http.Query["sql"].ToString());
        var documentation = @"db.Query(http.Query[""sql""]);";
        db.Execute("select 1");
    ''')),
    Case("request_connection_and_query_aliases", source('''
        var input = http;
        var connection = db;
        var query = input.Query["sql"].ToString();
        connection.Execute(query); // @sql connection.Execute
    ''')),
    Case("literal_rebinding_kills_query_taint", source('''
        var sql = http.Query["sql"].ToString();
        sql = "select 1";
        db.Execute(sql);
    ''')),
    Case("one_clean_branch_does_not_erase_taint", source('''
        var sql = http.Query["sql"].ToString();
        if (flag) { sql = "select 1"; }
        db.Execute(sql); // @sql db.Execute
    ''')),
    Case("both_clean_branches_kill_taint", source('''
        var sql = http.Query["sql"].ToString();
        if (flag) { sql = "select 1"; } else { sql = "select 2"; }
        db.Execute(sql);
    ''')),
    Case("source_on_one_branch_reaches_sink", source('''
        var sql = "select 1";
        if (flag) { sql = http.Query["sql"].ToString(); }
        db.Execute(sql); // @sql db.Execute
    ''')),
    Case("local_helper_return_preserves_taint", source('''
        var sql = Identity(http.Query["sql"].ToString());
        db.Execute(sql); // @sql db.Execute
    ''', helpers='''
        string Identity(string value) { return value; }
    ''')),
    Case("local_helper_constant_return_is_clean", source('''
        db.Execute(Fixed(http.Query["sql"].ToString()));
    ''', helpers='''
        string Fixed(string value) { return "select 1"; }
    ''')),
    Case("local_helper_sink_reports_execution", source('''
        ExecuteQuery(db, http.Query["sql"].ToString());
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("local_helper_named_arguments", source('''
        ExecuteQuery(text: http.Query["sql"].ToString(), connection: db);
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("local_helper_returns_connection_identity", source('''
        var connection = Identity(db);
        connection.Query<int>(http.Query["sql"].ToString()); // @sql connection.Query
    ''', helpers='''
        IDbConnection Identity(IDbConnection connection) { return connection; }
    ''')),
    Case("http_context_request_is_real_source", source('''
        db.Execute(context.Request.Query["sql"].ToString()); // @sql db.Execute
    ''', parameters="IDbConnection db, HttpContext context")),
    Case("controllerbase_implicit_request", HEADER + '''
class C : Microsoft.AspNetCore.Mvc.ControllerBase {
    void Run(IDbConnection db) {
        db.Execute(Request.Query["sql"].ToString()); // @sql db.Execute
    }
}
'''),
    Case("form_header_and_cookie_sources", source('''
        db.Execute(http.Form["sql"].ToString()); // @sql db.Execute
        db.Execute(http.Headers["X-Sql"].ToString()); // @sql db.Execute
        db.Execute(http.Cookies["sql"]); // @sql db.Execute
    ''')),
    Case("real_sqlconnection_type_identities", source('''
        oldConnection.Execute(http.Query["sql"].ToString()); // @sql oldConnection.Execute
        newConnection.Execute(http.Query["sql"].ToString()); // @sql newConnection.Execute
    ''', parameters="System.Data.SqlClient.SqlConnection oldConnection, Microsoft.Data.SqlClient.SqlConnection newConnection, HttpRequest http")),
    Case("real_dbconnection_type_identity", source('''
        db.Query<int>(http.Query["sql"].ToString()); // @sql db.Query
    ''', parameters="DbConnection db, HttpRequest http")),
    Case("using_aliases_resolve_real_types", '''using Db = System.Data.IDbConnection;
using Web = Microsoft.AspNetCore.Http.HttpRequest;
using Sql = Dapper.SqlMapper;
class C {
    void Run(Db db, Web http) {
        Sql.Execute(db, http.Query["sql"].ToString()); // @sql Sql.Execute
    }
}
'''),
    Case("request_variable_name_is_not_provenance", HEADER + '''
class RequestData { public string Query = "select 1"; }
class C {
    void Run(IDbConnection db, RequestData request) {
        db.Execute(request.Query);
    }
}
'''),
    Case("local_httprequest_class_shadows_import", HEADER + '''
class HttpRequest { public string Query = "select 1"; }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query);
    }
}
'''),
    Case("same_named_method_on_local_object_is_clean", HEADER + '''
class LocalDb { public void Query(string sql) { } }
class C {
    void Run(LocalDb db, HttpRequest http) {
        db.Query(http.Query["sql"].ToString());
    }
}
'''),
    Case("local_sqlmapper_class_shadows_import", HEADER + '''
class SqlMapper { public static void Execute(IDbConnection cnn, string sql) { } }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        SqlMapper.Execute(db, http.Query["sql"].ToString());
    }
}
'''),
    Case("relative_dapper_namespace_is_not_global_dapper", HEADER + '''
namespace App.Dapper {
    public static class SqlMapper {
        public static void Execute(IDbConnection cnn, string sql) { }
    }
}
namespace App {
    class C {
        void Run(IDbConnection db, HttpRequest http) {
            Dapper.SqlMapper.Execute(db, http.Query["sql"].ToString());
        }
    }
}
'''),
    Case("global_dapper_survives_local_sqlmapper_shadow", HEADER + '''
class SqlMapper { public static void Execute(IDbConnection cnn, string sql) { } }
class C {
    void Run(IDbConnection db, HttpRequest http) {
        global::Dapper.SqlMapper.Execute(db, http.Query["sql"].ToString()); // @sql global::Dapper.SqlMapper.Execute
    }
}
'''),
    Case("local_function_query_is_not_dapper", source('''
        void Query(string sql) { }
        Query(http.Query["sql"].ToString());
    ''')),
    Case("local_request_shadows_controller_property", HEADER + '''
class LocalInput { public string Query = "select 1"; }
class C : Microsoft.AspNetCore.Mvc.ControllerBase {
    void Run(IDbConnection db) {
        var Request = new LocalInput();
        db.Execute(Request.Query);
    }
}
'''),
    Case("arbitrary_string_parameter_is_not_request_source", source('''
        db.Execute(sql);
    ''', parameters="IDbConnection db, string sql")),
    Case("unrelated_method_names_do_not_share_taint", source('''
        ExecuteQuery(db, "select 1");
    ''', helpers='''
        void ReadInput(HttpRequest http) { var sql = http.Query["sql"].ToString(); }
        void ExecuteQuery(IDbConnection db, string sql) { db.Execute(sql); }
    ''')),
    Case("clean_and_unsafe_callers_share_one_execution_location", source('''
        ExecuteQuery(db, "select 1");
        ExecuteQuery(db, http.Query["sql"].ToString());
    ''', helpers='''
        void ExecuteQuery(IDbConnection connection, string text) {
            connection.Execute(text); // @sql connection.Execute
        }
    ''')),
    Case("string_format_does_not_parameterize_sql", source('''
        var sql = string.Format("select Id from Users where Name = '{0}'", http.Query["name"].ToString());
        db.Query<int>(sql); // @sql db.Query
    ''')),
)

BOUNDARIES = (
    Case("command_definition_is_explicitly_partial", source('''
        var command = new CommandDefinition(http.Query["sql"].ToString());
        db.Execute(command);
    '''), partial=True),
    Case("deferred_query_is_explicitly_partial", source('''
        db.Query<int>(http.Query["sql"].ToString(), buffered: false);
    '''), partial=True),
    Case("unknown_buffered_policy_is_explicitly_partial", source('''
        db.Query<int>(http.Query["sql"].ToString(), buffered: flag);
    '''), partial=True),
    Case("multimapping_is_explicitly_partial", source('''
        db.Query<int, int, int>(http.Query["sql"].ToString(), (a, b) => a + b);
    '''), partial=True),
    Case("dynamic_receiver_is_explicitly_partial", source('''
        db.Query(http.Query["sql"].ToString());
    ''', parameters="dynamic db, HttpRequest http"), partial=True),
    Case("known_finding_precedes_unsupported_command", source('''
        db.Execute(http.Query["sql"].ToString()); // @sql db.Execute
        var command = new CommandDefinition(http.Query["sql"].ToString());
        db.Execute(command);
    '''), partial=True),
)


# Two independently reviewed dispatch regressions authorized after the first
# native run.  They do not change the original 40 complete or six boundary
# source/expectation pairs retained in frozen-labels-v1.
REVIEW_CASES = (
    Case("local_extension_body_precedes_imported_dapper", '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
static class LocalExtensions {
    public static int Execute(this IDbConnection db, string sql) { return 0; }
}
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query["sql"].ToString());
    }
}
'''),
    Case("local_commandtype_text_is_not_framework_text", '''using System.Data;
using Microsoft.AspNetCore.Http;
using Dapper;
static class CommandType {
    public const System.Data.CommandType Text = System.Data.CommandType.StoredProcedure;
}
class C {
    void Run(IDbConnection db, HttpRequest http) {
        db.Execute(http.Query["sql"].ToString(), commandType: CommandType.Text);
    }
}
''', partial=True),
)


def materialize(directory: Path, cases=CASES) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for case in cases:
        path = directory / (case.name + ".cs")
        path.write_text(case.code, encoding="utf-8")
        paths[case.name] = path
    return paths


def freeze_receipt(directory: Path) -> dict:
    """Persist independently assigned labels and their exact source bytes."""
    paths = materialize(directory / "cases", CASES + BOUNDARIES)
    receipt = {
        "rule": RULE,
        "labels_assigned_before_proposed_analyzer_inspection": True,
        "runtime": sys.version,
        "python_executable": sys.executable,
        "cases": [
            {"name": case.name, "source": str(paths[case.name]),
             "sha256": hashlib.sha256(case.code.encode()).hexdigest(),
             "expected": case.expected, "partial": case.partial}
            for case in CASES + BOUNDARIES
        ],
    }
    (directory / "labels.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


@unittest.skipIf(os.environ.get("UBS_CSHARP_SQL_PUBLIC_ONLY") == "1", "native group already run")
class DapperNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("native-" + uuid.uuid4().hex[:12])
        cls.paths = materialize(cls.directory, CASES + BOUNDARIES + REVIEW_CASES)
        cls.analyzer = importlib.import_module("ubs_core.analyzers.taint_csharp_sql")

    def scan_case(self, case: Case):
        findings = []
        error = None
        try:
            findings.extend(self.analyzer.scan_file_findings(self.paths[case.name]))
        except ValueError as exc:
            error = str(exc)
        self.assertEqual(error is not None, case.partial, (case.name, findings, error))
        if case.partial:
            self.assertTrue(error.strip(), (case.name, error))
        actual = sorted((f["rule"], f["line"], f.get("col", 1)) for f in findings)
        self.assertEqual(actual, sorted(case.expected), (case.name, findings, error))
        for finding in findings:
            self.assertEqual(finding["severity"], "critical", finding)
            self.assertEqual(finding.get("category_id"), "csharp.security", finding)
            self.assertEqual(Path(finding["path"]), self.paths[case.name], finding)

    def test_token_budget_is_not_a_clean_report(self):
        case = CASES[0]
        prior = os.environ.get("UBS_CSHARP_SQL_MAX_TOKENS")
        os.environ["UBS_CSHARP_SQL_MAX_TOKENS"] = "16"
        try:
            with self.assertRaisesRegex(ValueError, "(?i)limit|budget|incomplete|tokens"):
                list(self.analyzer.scan_file_findings(self.paths[case.name]))
        finally:
            if prior is None:
                os.environ.pop("UBS_CSHARP_SQL_MAX_TOKENS", None)
            else:
                os.environ["UBS_CSHARP_SQL_MAX_TOKENS"] = prior

    def test_unrelated_existing_security_fixtures_do_not_become_partial(self):
        for family in ("HeaderInjection", "OpenRedirect", "RequestPathTraversal", "Ssrf"):
            for side in ("Buggy", "Clean"):
                path = ROOT / "test-suite/csharp/security" / (family + side + ".cs")
                with self.subTest(fixture=path.name):
                    self.assertEqual(list(self.analyzer.scan_file_findings(path)), [])

    def test_permanent_dapper_buggy_and_clean_fixtures(self):
        for name, expected in (
            ("DapperSqlBuggy.cs", [(RULE, 12, 16), (RULE, 18, 16), (RULE, 28, 16)]),
            ("DapperSqlClean.cs", []),
        ):
            path = ROOT / "test-suite/csharp/security" / name
            with self.subTest(fixture=name):
                findings = list(self.analyzer.scan_file_findings(path))
                self.assertEqual(sorted((row["rule"], row["line"], row["col"]) for row in findings), expected)
                for finding in findings:
                    self.assertEqual((finding["severity"], finding["category_id"]),
                                     ("critical", "csharp.security"), finding)


def _install_native_tests():
    for case in CASES + BOUNDARIES + REVIEW_CASES:
        def test(self, case=case):
            self.scan_case(case)
        setattr(DapperNativeTests, "test_" + case.name, test)


_install_native_tests()


@unittest.skipUnless(os.environ.get("UBS_CSHARP_SQL_PUBLIC") == "1",
                     "set UBS_CSHARP_SQL_PUBLIC=1 after verified module/helper pins")
class DapperPublicTests(unittest.TestCase):
    """Fifteen real commands exercise the same independent semantic labels."""

    @classmethod
    def setUpClass(cls):
        cls.directory = ARTIFACTS / ("public-" + uuid.uuid4().hex[:12])
        cls.directory.mkdir(parents=True)
        cls.identity = {
            "python": sys.version,
            "python_executable": sys.executable,
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                            text=True).strip(),
            "dotnet": shutil.which("dotnet"),
            "ast_grep": shutil.which("ast-grep"),
            "sources": {
                path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                for path in (
                    "ubs", "modules/ubs-csharp.sh", "modules/helpers/ubs_core/csharp_scan.py",
                    "modules/helpers/ubs_core/analyzers/taint_csharp_sql.py",
                    "modules/helpers/ubs_core/analyzers/taint_csharp_request.py",
                    "test-suite/quality/test_csharp_sql.py",
                )
            },
        }

    def project(self, label, cases):
        directory = self.directory / label
        materialize(directory, cases)
        return directory

    def execute(self, target, mode="module-json", *, extra=(), cached=False, environment=None):
        attempt = self.directory / ("command-" + uuid.uuid4().hex[:10])
        attempt.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                   UBS_NO_CACHE="0" if cached else "1", UBS_CACHE_DIR=str(self.directory / "cache"),
                   UBS_CACHE_FILE=str(attempt / "cache-stats.json"), TMPDIR=str(attempt))
        if environment:
            env.update(environment)
        if mode.startswith("module-"):
            command = [str(ROOT / "modules/ubs-csharp.sh"), "--ci", "--no-color", "--no-dotnet",
                       "--only=8", "--format=" + mode.split("-", 1)[1], *extra, str(target)]
        else:
            command = [str(ROOT / "ubs"), "--ci", "--no-config", "--no-dotnet", "--only=csharp",
                       "--format=" + mode, *extra, str(target)]
        started = time.monotonic()
        # The production cache includes cwd in its source context.  Keep that
        # context stable across cold/warm runs while retaining separate logs.
        result = subprocess.run(command, cwd=target, env=env, text=True, capture_output=True,
                                timeout=120)
        (attempt / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (attempt / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (attempt / "receipt.json").write_text(json.dumps({
            **self.identity, "command": command, "exit": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "environment": {key: env.get(key) for key in (
                "UBS_NO_AUTO_UPDATE", "UBS_NO_CACHE", "UBS_CACHE_DIR", "UBS_CACHE_FILE", "TMPDIR",
                "UBS_CSHARP_SQL_MAX_TOKENS", "UBS_CSHARP_SQL_MAX_NESTING", "UBS_CSHARP_SQL_MAX_STEPS",
            )},
            "inputs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(target.rglob("*.cs"))},
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[dapper-cli:{attempt.name}] exit={result.returncode} "
              f"{time.monotonic() - started:.3f}s " + " ".join(command), flush=True)
        self.last_attempt = attempt
        try:
            report = json.loads(result.stdout)
        except ValueError:
            self.fail((result.returncode, result.stdout, result.stderr))
        return result, report

    def assert_report(self, result, report, mode, cases, *, partial=False, sql_enabled=True,
                      expected_sql=None):
        context = (result.returncode, result.stdout, result.stderr)
        sql = ([(case.name + ".cs", rule, line, col, "critical")
                for case in cases for rule, line, col in case.expected]
               if expected_sql is None else list(expected_sql))
        if not sql_enabled:
            sql = []
        # Exact pre-existing warning observed on pristine 8d0a04a.  It remains
        # separate from the newly proven flow at the later execution call.
        warnings = [("concatenated_sql_execution_location.cs", "cs.pattern.sql-concat", 12, 1, "warning")]
        if not sql_enabled or not any(case.name == "concatenated_sql_execution_location" for case in cases):
            warnings = []
        inventory = [] if mode.startswith("module-") else [("", "cs.inventory.project", 0, 1, "info")]
        expected = sorted(sql + warnings + inventory)
        self.assertEqual(result.returncode, 2 if partial else int(bool(sql)), context)
        actual = []
        if mode.endswith("sarif"):
            for run in report["runs"]:
                for row in run.get("results", []):
                    if row.get("locations"):
                        location = row["locations"][0]["physicalLocation"]
                        file = Path(location["artifactLocation"]["uri"]).name
                        line = location["region"]["startLine"]
                        col = location["region"]["startColumn"]
                    else:
                        file, line, col = "", 0, 1
                    severity = {"error": "critical", "warning": "warning", "note": "info"}[row["level"]]
                    actual.append((file, row["ruleId"], line, col, severity))
            if partial:
                self.assertTrue(any(not item["executionSuccessful"] for run in report["runs"]
                                    for item in run.get("invocations", [])), context)
        else:
            totals = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((totals["critical"], totals["warning"], totals["info"], totals["files"]),
                             (len(sql), len(warnings), len(inventory), len(cases)), context)
            self.assertEqual(report["status"], "partial" if partial else "ok", context)
            for row in report["findings"]:
                rule = row.get("rule", row.get("rule_id"))
                path = row.get("path", row.get("file"))
                file = Path(path).name if path else ""
                self.assertEqual(row["category_id"], "csharp.inventory" if rule == "cs.inventory.project"
                                 else "csharp.security", context)
                actual.append((file, rule, row["line"], row["col"], row["severity"]))
        self.assertEqual(sorted(actual), expected, context)

    def test_public_all_independent_labels_in_four_formats(self):
        directory = self.project("complete", CASES)
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, CASES)

    def test_public_clean_controls(self):
        cases = tuple(case for case in CASES if not case.expected)
        directory = self.project("clean", cases)
        for mode in ("module-json", "json"):
            with self.subTest(mode=mode):
                self.assert_report(*self.execute(directory, mode), mode, cases)

    def test_public_partial_preserves_earlier_finding_and_later_file(self):
        cases = (Case("a_partial", BOUNDARIES[-1].code, partial=True),
                 Case("z_neighbor", CASES[5].code))
        directory = self.project("partial", cases)
        for mode in ("module-json", "sarif"):
            with self.subTest(mode=mode):
                result, report = self.execute(directory, mode)
                self.assert_report(result, report, mode, cases, partial=True)
                self.assertIn("a_partial.cs", result.stderr)

    def test_public_file_list_is_the_selected_scope(self):
        unsafe, clean = CASES[5], CASES[8]
        directory = self.project("selected", (unsafe, clean))
        file_list = self.directory / "selected-inputs.nul"
        file_list.write_bytes(os.fsencode(directory / (clean.name + ".cs")) + b"\0")
        self.assert_report(*self.execute(directory, extra=("--files-from", str(file_list))),
                           "module-json", (clean,))

    def test_public_category_skip_precedes_analysis(self):
        cases = (CASES[5],)
        directory = self.project("category", cases)
        self.assert_report(*self.execute(directory, extra=("--skip=8",),
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "1"}),
                           "module-json", cases, sql_enabled=False)

    def test_public_warm_cache_budget_and_suppression_changes(self):
        case = Case("cache_target", CASES[5].code)
        directory = self.project("cache-project", (case,))
        for phase in ("cold", "warm"):
            with self.subTest(phase=phase):
                self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
                stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
                self.assertEqual((stats["hits"], stats["misses"]), (1, 0) if phase == "warm" else (0, 1))
        self.assert_report(*self.execute(directory, cached=True,
                                          environment={"UBS_CSHARP_SQL_MAX_TOKENS": "16"}),
                           "module-json", (case,), partial=True, expected_sql=[])
        restricted_stats = json.loads((self.last_attempt / "cache-stats.json").read_text())
        self.assertEqual(restricted_stats["hits"], 0, restricted_stats)
        self.assert_report(*self.execute(directory, cached=True), "module-json", (case,))
        suppressed = Case("cache_target", source('''
            db.Execute(param: new { id = 1 }, sql: http.Query["sql"].ToString()); // ubs:ignore[cs.security.sql-injection]
        '''))
        (directory / "cache_target.cs").write_text(suppressed.code, encoding="utf-8")
        self.assert_report(*self.execute(directory, cached=True), "module-json", (suppressed,))


if __name__ == "__main__":
    unittest.main()
