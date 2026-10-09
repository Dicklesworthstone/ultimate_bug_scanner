#!/usr/bin/env python3
"""Independent JDBC request-to-query and actual parameter-binding oracle.

Statement execution overloads take SQL in argument zero; generated-key flags,
column indexes and column names are not query parameters. PreparedStatement
captures SQL when Connection.prepareStatement is called. Its setters bind data
to placeholders and cannot repair request text already interpolated into SQL.
Every valid fixture compiles against the real JDK JDBC and HttpExchange APIs.

https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/Statement.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/PreparedStatement.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/Connection.html
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
from unittest.mock import patch
import uuid

import test_java_tls_verifier as tls

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core.registry import RunContext
from ubs_core.taint_flow import AnalysisLimit

RULE = "java.security.sql-injection"
DETECTOR = ROOT / "modules/helpers/ubs_core/analyzers/taint_java_sql.py"
SOURCE = "exchange.getRequestURI().getQuery()"
QUERY = '"select * from users where name=\'" + input + "\'"'
UPDATE_QUERY = '"update users set enabled=1 where name=\'" + input + "\'"'
INSERT_QUERY = '"insert into users(name) values (\'" + input + "\')"'


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    column_anchor: str | None = None

    @property
    def source(self):
        return ("import java.sql.Statement;\nimport java.sql.Connection;\n"
                "import java.sql.PreparedStatement;\nimport java.sql.SQLException;\n"
                "import com.sun.net.httpserver.HttpExchange;\n"
                f"class Case_{self.name} {{\n" + textwrap.dedent(self.body).strip() + "\n}\n")

    @property
    def sites(self):
        return [(line, source.index(self.column_anchor) + 1 if self.column_anchor is not None
                 else len(source) - len(source.lstrip()) + 1)
                for line, source in enumerate(self.source.splitlines(), 1)
                if "// SQL_EXEC" in source]

    @property
    def ssrf_sites(self):
        return [(line, 1) for line, source in enumerate(self.source.splitlines(), 1)
                if "// SSRF_EXEC" in source]


def handle(statements, parameters="HttpExchange exchange, Statement statement"):
    return (f"void handle({parameters}) throws SQLException {{\n" +
            textwrap.indent(textwrap.dedent(statements).strip(), "    ") + "\n}")


def direct(call, *, source=SOURCE, query=QUERY):
    return handle(f"String input = {source};\nString query = {query};\n{call}; // SQL_EXEC")


def prepared(call, *, query=QUERY, extra=""):
    return handle(f"""
        String input = {SOURCE};
        String query = {query};
        try (PreparedStatement statement = connection.prepareStatement(query)) {{
            {extra}
            {call}; // SQL_EXEC
        }}
    """, "HttpExchange exchange, Connection connection")


# The overload spellings and expected sites below are independent JDBC API facts.
# They are not obtained from detector code or from another scanner's output.
CASES = (
    Case("execute_query", direct("statement.executeQuery(query)")),
    Case("execute_update", direct("statement.executeUpdate(query)", query=UPDATE_QUERY)),
    Case("execute_large_update", direct("statement.executeLargeUpdate(query)", query=UPDATE_QUERY)),
    Case("execute", direct("statement.execute(query)")),
    Case("execute_generated_keys", direct("statement.execute(query, Statement.RETURN_GENERATED_KEYS)", query=INSERT_QUERY)),
    Case("execute_column_indexes", direct("statement.execute(query, new int[] { 1 })", query=INSERT_QUERY)),
    Case("execute_column_names", direct('statement.execute(query, new String[] { "id" })', query=INSERT_QUERY)),
    Case("update_generated_keys", direct("statement.executeUpdate(query, Statement.RETURN_GENERATED_KEYS)", query=INSERT_QUERY)),
    Case("update_column_indexes", direct("statement.executeUpdate(query, new int[] { 1 })", query=INSERT_QUERY)),
    Case("update_column_names", direct('statement.executeUpdate(query, new String[] { "id" })', query=INSERT_QUERY)),
    Case("large_update_generated_keys", direct("statement.executeLargeUpdate(query, Statement.RETURN_GENERATED_KEYS)", query=INSERT_QUERY)),
    Case("large_update_column_indexes", direct("statement.executeLargeUpdate(query, new int[] { 1 })", query=INSERT_QUERY)),
    Case("large_update_column_names", direct('statement.executeLargeUpdate(query, new String[] { "id" })', query=INSERT_QUERY)),
    Case("entire_request_query", handle(f"statement.executeQuery({SOURCE}); // SQL_EXEC")),
    Case("multiline_query", handle(f"""
        String input = {SOURCE};
        statement.executeQuery( // SQL_EXEC
            "select * from users where name='" +
            input + "'");
    """)),
    Case("prepared_query", prepared("statement.executeQuery()")),
    Case("prepared_update", prepared("statement.executeUpdate()", query=UPDATE_QUERY)),
    Case("prepared_large_update", prepared("statement.executeLargeUpdate()", query=UPDATE_QUERY)),
    Case("prepared_execute", prepared("statement.execute()")),
    Case("mixed_placeholder_still_unsafe", prepared("statement.executeQuery()",
        query='"select * from users where name=\'" + input + "\' and tenant=?"',
        extra='statement.setString(1, "tenant-a");')),
    Case("quoted_placeholder_is_not_binding", direct(
        'statement.executeQuery("select \'?\', \'" + input + "\'")')),
    Case("statement_alias", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        Statement alias = statement;
        alias.executeQuery(query); // SQL_EXEC
    """)),
    Case("request_alias", handle(f"""
        HttpExchange incoming = exchange;
        String input = incoming.getRequestURI().getRawQuery();
        String query = {QUERY};
        statement.executeQuery(query); // SQL_EXEC
    """)),
    Case("query_alias", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        String alias = query;
        query = "select 1";
        statement.executeQuery(alias); // SQL_EXEC
    """)),
    Case("source_helper", """
        String extract(HttpExchange incoming) { return incoming.getRequestURI().getQuery(); }
    """ + handle(f"String input = extract(exchange);\nString query = {QUERY};\n"
                 "statement.executeQuery(query); // SQL_EXEC")),
    Case("query_helper", """
        String buildQuery(String value) { return "select * from users where name='" + value + "'"; }
    """ + handle(f"String query = buildQuery({SOURCE});\nstatement.executeQuery(query); // SQL_EXEC")),
    Case("execution_helper", """
        void executeSelected(Statement target, String value) throws SQLException {
            target.executeQuery(value); // SQL_EXEC
        }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nexecuteSelected(statement, query);")),
    Case("branch_merge", handle(f"""
        String input = {SOURCE};
        String query = "select 1";
        if (dynamic) {{ query = {QUERY}; }}
        statement.executeQuery(query); // SQL_EXEC
    """, "HttpExchange exchange, Statement statement, boolean dynamic")),
    Case("prepared_captures_before_query_rebind", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        try (PreparedStatement statement = connection.prepareStatement(query)) {{
            query = "select 1";
            statement.executeQuery(); // SQL_EXEC
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("prepared_alias", prepared("alias.executeQuery()", extra="PreparedStatement alias = statement;")),
    Case("connection_factory", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        try (Statement statement = connection.createStatement()) {{
            statement.executeQuery(query); // SQL_EXEC
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("qualified_apis", handle("""
        String input = incoming.getRequestURI().getQuery();
        String query = "select * from users where name='" + input + "'";
        target.executeQuery(query); // SQL_EXEC
    """, "com.sun.net.httpserver.HttpExchange incoming, java.sql.Statement target")),
    Case("static_sql", handle('statement.executeQuery("select * from users");', "Statement statement")),
    Case("constant_concatenation", handle('String table = "users";\n'
        'String query = "SELECT * FROM " + table;\nstatement.executeQuery(query);', "Statement statement")),
    Case("static_generated_keys", handle('statement.executeUpdate("insert into users(name) values(\'fixed\')", '
                                         "Statement.RETURN_GENERATED_KEYS);", "Statement statement")),
    Case("unknown_not_request", handle("statement.executeQuery(query);", "Statement statement, String query")),
    Case("source_replaced_before_query", handle(f"String input = {SOURCE};\ninput = \"fixed\";\n"
        f"String query = {QUERY};\nstatement.executeQuery(query);")),
    Case("query_replaced_before_execution", handle(f"String input = {SOURCE};\nString query = {QUERY};\n"
        'query = "select 1";\nstatement.executeQuery(query);')),
    Case("static_both_branches", handle('String query;\nif (choose) { query = "select 1"; } '
        'else { query = "select 2"; }\nstatement.executeQuery(query);', "Statement statement, boolean choose")),
    Case("query_replaced_before_preparation", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        query = "select 1";
        try (PreparedStatement statement = connection.prepareStatement(query)) {{
            statement.executeQuery();
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("bound_parameters", handle(f"""
        try (PreparedStatement statement = connection.prepareStatement("select * from users where name=?")) {{
            statement.setString(1, {SOURCE});
            statement.executeQuery();
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("bound_parameter_alias", handle(f"""
        try (PreparedStatement statement = connection.prepareStatement("select * from users where name=?")) {{
            PreparedStatement alias = statement;
            alias.setString(1, {SOURCE});
            alias.executeQuery();
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("prepared_handle_rebound", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        try (PreparedStatement unsafe = connection.prepareStatement(query);
             PreparedStatement safe = connection.prepareStatement("select 1")) {{
            PreparedStatement selected = unsafe;
            selected = safe;
            selected.executeQuery();
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("unexecuted_prepared_query", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        try (PreparedStatement statement = connection.prepareStatement(query)) {{
            statement.setFetchSize(5);
        }}
    """, "HttpExchange exchange, Connection connection")),
    Case("source_in_unrelated_scope", handle(f"String query = {SOURCE};", "HttpExchange exchange") + "\n" +
        handle('String query = "select 1";\nstatement.executeQuery(query);', "Statement statement")),
    Case("custom_statement", """
        static class CustomStatement { void executeQuery(String query) {} }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nstatement.executeQuery(query);",
                 "HttpExchange exchange, CustomStatement statement")),
    Case("shadowed_statement_type", """
        static class Statement { void executeQuery(String query) {} }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nstatement.executeQuery(query);")),
    Case("shadowed_request_type", """
        static class HttpExchange {
            java.net.URI getRequestURI() { return java.net.URI.create("https://example.test/?fixed"); }
        }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nstatement.executeQuery(query);")),
    Case("computed_receiver_suffix", """
        static class CustomStatement { void executeQuery(String query) {} }
        static class Holder { CustomStatement statement = new CustomStatement(); }
        Holder holder() { return new Holder(); }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nholder().statement.executeQuery(query);")),
    Case("lambda_shadows_field", """
        Statement statement;
        static class CustomStatement { void executeQuery(String query) {} }
    """ + handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        java.util.function.Consumer<CustomStatement> consumer = statement -> {{
            statement.executeQuery(query);
        }};
    """, "HttpExchange exchange")),
    Case("namespace_shadow", """
        static class java { static class sql { static class Statement {
            void executeQuery(String query) {}
        } } }
    """ + handle(f"String input = {SOURCE};\nString query = {QUERY};\nstatement.executeQuery(query);",
                 "HttpExchange exchange, java.sql.Statement statement")),
    Case("lexical_decoys", '''
        String text = "statement.executeQuery(exchange.getRequestURI().getQuery())";
        String block = """
            statement.executeQuery(exchange.getRequestURI().getQuery());
            connection.prepareStatement(query).executeQuery();
            """;
        // statement.executeQuery(exchange.getRequestURI().getQuery());
        /* String query = "SELECT * FROM " + exchange.getRequestURI().getQuery(); */
    '''),
)

# These sixteen additional sources were independently compiled and run against
# the first implementation candidate. They exposed five false-clean SQL paths
# and one false SSRF alert. Keep the original fifty-two cases above unchanged.
REVIEW_CASES = (
    Case("review_parenthesized_request", handle('''
        String input = (exchange).getRequestURI().getQuery();
        statement.executeQuery("select * from users where name='" + input + "'"); // SQL_EXEC
    ''')),
    Case("review_computed_request_suffix", '''
        static class FixedExchange { java.net.URI getRequestURI() { return java.net.URI.create("https://example.test/?fixed"); } }
        static class Holder { FixedExchange exchange = new FixedExchange(); }
        Holder holder() { return new Holder(); }
    ''' + handle('''
        String input = holder().exchange.getRequestURI().getQuery();
        statement.executeQuery("select * from users where name='" + input + "'");
    ''')),
    Case("review_shadowed_Integer", '''
        interface Parser { String parseInt(String input); }
    ''' + handle('''
        String input = exchange.getRequestURI().getQuery();
        String parsed = Integer.parseInt(input);
        statement.executeQuery("select * from users where name='" + parsed + "'"); // SQL_EXEC
    ''', "HttpExchange exchange, Statement statement, Parser Integer")),
    Case("review_shadowed_qualified_Integer", '''
        interface Parser { String parseInt(String input); }
        static class Language { Parser Integer; }
        static class Namespace { Language lang; }
    ''' + handle('''
        String input = exchange.getRequestURI().getQuery();
        String parsed = java.lang.Integer.parseInt(input);
        statement.executeQuery("select * from users where name='" + parsed + "'"); // SQL_EXEC
    ''', "HttpExchange exchange, Statement statement, Namespace java")),
    Case("review_actual_Integer", handle('''
        String input = exchange.getRequestURI().getQuery();
        int parsed = Integer.parseInt(input);
        statement.executeQuery("select * from users where id=" + parsed);
    ''')),
    Case("review_prepared_helper", '''
        void send(PreparedStatement selected) throws SQLException {
            selected.executeQuery(); // SQL_EXEC
        }
    ''' + handle('''
        String input = exchange.getRequestURI().getQuery();
        try (PreparedStatement selected = connection.prepareStatement("select * from users where name='" + input + "'")) {
            send(selected);
        }
    ''', "HttpExchange exchange, Connection connection")),
    Case("review_safe_prepared_helper", '''
        void send(PreparedStatement selected) throws SQLException { selected.executeQuery(); }
    ''' + handle('''
        String input = exchange.getRequestURI().getQuery();
        try (PreparedStatement selected = connection.prepareStatement("select * from users where name=?")) {
            selected.setString(1, input);
            send(selected);
        }
    ''', "HttpExchange exchange, Connection connection")),
    Case("review_chained_prepared", handle('''
        String input = exchange.getRequestURI().getQuery();
        connection.prepareStatement("select * from users where name='" + input + "'").executeQuery(); // SQL_EXEC
    ''', "HttpExchange exchange, Connection connection")),
    Case("review_grouped_statement", handle('''
        String input = exchange.getRequestURI().getQuery();
        (statement).executeQuery("select * from users where name='" + input + "'"); // SQL_EXEC
    ''')),
    Case("review_cast_statement", handle('''
        String input = exchange.getRequestURI().getQuery();
        ((Statement) connection.createStatement()).executeQuery("select * from users where name='" + input + "'"); // SQL_EXEC
    ''', "HttpExchange exchange, Connection connection")),
    Case("review_header_source", handle('''
        String input = exchange.getRequestHeaders().getFirst("X-Query");
        statement.executeQuery(input); // SQL_EXEC
    ''')),
    Case("review_block_prefix", handle('''
        String query = exchange.getRequestURI().getQuery();
        /* diagnostic */ statement.execute(query); // SQL_EXEC
    '''), column_anchor="statement.execute"),
    Case("review_block_inside_receiver", handle('''
        String query = exchange.getRequestURI().getQuery();
        statement /* diagnostic */ .execute(query); // SQL_EXEC
    ''')),
    Case("review_http_same_line", handle('''
        String query = exchange.getRequestURI().getQuery();
        statement.execute(query); java.net.http.HttpRequest.newBuilder(java.net.URI.create(query)).build(); // SQL_EXEC // SSRF_EXEC
    ''')),
    Case("review_unknown_execute_same_line", '''
        interface UnknownClient { Object execute(String target); }
    ''' + handle('''
        String query = exchange.getRequestURI().getQuery();
        statement.execute(query); client.execute(query); // SQL_EXEC // SSRF_EXEC
    ''', "HttpExchange exchange, Statement statement, UnknownClient client")),
    Case("review_jdk_http", handle('''
        String query = exchange.getRequestURI().getQuery();
        java.net.http.HttpRequest.newBuilder(java.net.URI.create(query)).build(); // SSRF_EXEC
    ''', "HttpExchange exchange")),
)

ALL_CASES = CASES + REVIEW_CASES
BY_NAME = {case.name: case for case in ALL_CASES}

INCOMPLETE_CASES = (
    Case("async_callback", handle(f"""
        String input = {SOURCE};
        String query = {QUERY};
        executor.execute(() -> {{
            try {{
                statement.executeQuery(query);
            }} catch (SQLException failure) {{
                throw new IllegalStateException(failure);
            }}
        }});
    """, "HttpExchange exchange, Statement statement, java.util.concurrent.Executor executor")),
    Case("sql_array_state", handle(f"""
        String input = {SOURCE};
        String[] queries = new String[] {{ {QUERY} }};
        statement.executeQuery(queries[0]);
    """)),
)


def artifact_directory(label):
    directory = ROOT / "test-suite/artifacts/java-sql-provenance" / (label + "-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True)
    return directory


def identities():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), DETECTOR, ROOT / "modules/helpers/ubs_core/java_scan.py") if path.is_file()}


class JavaSqlCompilerTests(unittest.TestCase):
    def test_actual_jdk_api_sources(self):
        java = shutil.which("java")
        if java is None:
            self.skipTest("A JDK with jdk.compiler is required to compile the actual API fixtures")
        artifact = artifact_directory("compiler")
        sources = []
        for case in ALL_CASES + INCOMPLETE_CASES:
            path = artifact / ("Case_" + case.name + ".java")
            path.write_text(case.source, encoding="utf-8")
            sources.append(path)
        classes = artifact / "classes"
        classes.mkdir()
        command = [java, "-m", "jdk.compiler/com.sun.tools.javac.Main", "--release", "17",
                   "--add-modules", "jdk.httpserver", "-d", str(classes), *(str(path) for path in sources)]
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)  # ubs:ignore[py.security.command-injection] — fixed JDK compiler module and repository-authored fixture paths, no shell
        for stream in ("stdout", "stderr"):
            (artifact / ("javac." + stream + ".log")).write_text(getattr(result, stream), encoding="utf-8")
        (artifact / "receipt.json").write_text(json.dumps({
            "command": command, "exit": result.returncode, "elapsed": time.monotonic() - started,
            "python": sys.version, "tools": identities(), "java": java,
            "sources": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[java-sql-compiler] {artifact}", flush=True)
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)


class JavaSqlDirectTests(unittest.TestCase):
    def test_independent_request_and_binding_cases(self):
        analyzer = importlib.import_module("ubs_core.analyzers.taint_java_sql")
        artifact = artifact_directory("direct")
        records = []
        for case in ALL_CASES:
            with self.subTest(case=case.name):
                path = artifact / ("Case_" + case.name + ".java")
                path.write_text(case.source, encoding="utf-8")
                started = time.monotonic()
                rows, error = [], None
                try:
                    rows = analyzer.analyze_source(path, case.source)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                expected = [(RULE, line, col, "critical", "java.security") for line, col in case.sites]
                actual = [(row["rule"], row["line"], row["col"], row["severity"], row["category_id"])
                          for row in rows]
                records.append({"case": case.name, "expected": expected, "actual": actual, "error": error,
                                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                "elapsed": time.monotonic() - started})
                (artifact / (case.name + ".stdout.log")).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
                (artifact / (case.name + ".stderr.log")).write_text(error or "", encoding="utf-8")
                self.assertIsNone(error, case.name)
                self.assertEqual(actual, expected, case.name)
                for row in rows:
                    self.assertEqual(Path(row["path"]), path)
                    trace = row.get("extras", {}).get("taint_path", [])
                    self.assertTrue(trace, row)
        (artifact / "receipt.json").write_text(json.dumps({"command": sys.argv, "python": sys.version,
            "tools": identities(), "cases": records}, indent=2) + "\n", encoding="utf-8")
        print(f"[java-sql-direct] {artifact}", flush=True)

    def test_http_sink_preservation_and_jdbc_exclusion(self):
        from ubs_core.java_detectors import ssrf_outbound_url
        artifact = artifact_directory("http-identity")
        receipts = []
        self.assertEqual(ssrf_outbound_url.RULE_ID, "java.security.ssrf-outbound-url")
        for case in REVIEW_CASES:
            with self.subTest(case=case.name):
                path = artifact / ("Case_" + case.name + ".java")
                path.write_text(case.source, encoding="utf-8")
                started = time.monotonic()
                rows = list(ssrf_outbound_url.find([path]))
                actual = [(Path(found).name, line, col) for found, line, col, _ in rows]
                expected = [(path.name, line, col) for line, col in case.ssrf_sites]
                receipts.append({"case": case.name, "expected": expected, "actual": actual,
                    "elapsed": time.monotonic() - started,
                    "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                (artifact / (case.name + ".stdout.log")).write_text(json.dumps(
                    [{"path": str(found), "line": line, "col": col, "detail": detail}
                     for found, line, col, detail in rows], indent=2) + "\n", encoding="utf-8")
                self.assertEqual(actual, expected, case.name)
        (artifact / "receipt.json").write_text(json.dumps({"command": sys.argv,
            "tools": {**identities(), str(Path(ssrf_outbound_url.__file__).relative_to(ROOT)):
                      hashlib.sha256(Path(ssrf_outbound_url.__file__).read_bytes()).hexdigest()},
            "cases": receipts}, indent=2) + "\n", encoding="utf-8")

    def test_bounds_and_disabled_rule_are_explicit(self):
        analyzer = importlib.import_module("ubs_core.analyzers.taint_java_sql")
        artifact = artifact_directory("bounds")
        source = BY_NAME["execute_query"].source
        target = artifact / "Case_bounds.java"
        target.write_text(source, encoding="utf-8")
        receipts = []
        for setting in ("UBS_JAVA_SQL_MAX_TOKENS", "UBS_JAVA_SQL_MAX_NESTING", "UBS_JAVA_SQL_MAX_STEPS"):
            for value in ("1", "invalid", "0"):
                with self.subTest(setting=setting, value=value), patch.dict(os.environ, {setting: value}):
                    started = time.monotonic()
                    with self.assertRaises((AnalysisLimit, ValueError)) as caught:
                        analyzer.analyze_source(target, source)
                    receipts.append({"setting": setting, "value": value, "error": str(caught.exception),
                                     "elapsed": time.monotonic() - started})
        malformed = source.rstrip()[:-1] + "\n"
        target.write_text(malformed, encoding="utf-8")
        with self.assertRaises((AnalysisLimit, ValueError)) as caught:
            analyzer.analyze_source(target, malformed)
        receipts.append({"malformed": str(caught.exception)})
        context = RunContext(lang="java", files=[target], profile={"disabled_rules": [RULE]})
        with patch.dict(os.environ, {"UBS_JAVA_SQL_MAX_TOKENS": "invalid"}):
            self.assertEqual(list(analyzer.run(context)), [])
        (artifact / "receipt.json").write_text(json.dumps({"command": sys.argv, "tools": identities(),
            "receipts": receipts, "disabled_before_parse": True}, indent=2) + "\n", encoding="utf-8")

    def test_selected_unsupported_flow_is_explicit(self):
        analyzer = importlib.import_module("ubs_core.analyzers.taint_java_sql")
        artifact = artifact_directory("unsupported")
        receipts = []
        for case in INCOMPLETE_CASES:
            with self.subTest(case=case.name):
                target = artifact / ("Case_" + case.name + ".java")
                target.write_text(case.source, encoding="utf-8")
                started = time.monotonic()
                with self.assertRaises((AnalysisLimit, ValueError)) as caught:
                    analyzer.analyze_source(target, case.source)
                receipts.append({"case": case.name, "error": str(caught.exception),
                    "source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "elapsed": time.monotonic() - started})
        (artifact / "receipt.json").write_text(json.dumps({"command": sys.argv, "tools": identities(),
            "cases": receipts}, indent=2) + "\n", encoding="utf-8")


class JavaSqlPublicTests(unittest.TestCase):
    scan = tls.JavaTlsVerifierTests.scan
    assert_json = tls.JavaTlsVerifierTests.assert_json
    assert_sarif = tls.JavaTlsVerifierTests.assert_sarif
    assert_cache = tls.JavaTlsVerifierTests.assert_cache

    def setUp(self):
        self.artifact = artifact_directory(self._testMethodName)
        (self.artifact / "oracle.identity.json").write_text(json.dumps(identities(), indent=2) + "\n", encoding="utf-8")

    def fixture(self, cases):
        project = self.artifact / "project"
        project.mkdir(exist_ok=True)
        expected = []
        for case in cases:
            target = project / ("Case_" + case.name + ".java")
            target.write_text(case.source, encoding="utf-8")
            expected.extend((target.name, RULE, line, col, "critical") for line, col in case.sites)
            expected.extend((target.name, "java.security.ssrf-outbound-url", line, col, "critical")
                            for line, col in case.ssrf_sites)
        return project, sorted(expected)

    def test_ordinary_module_with_and_without_ast(self):
        project, expected = self.fixture(ALL_CASES)
        # The custom getter behind a computed heap receiver is UNKNOWN to this
        # slice, so its existing concatenation warning must remain.  It must not
        # invent either a request-proven SQL critical or an HTTP sink critical.
        expected.append(("Case_review_computed_request_suffix.java", "java.sql.exec-concat", 12, 1, "warning"))
        for no_ast in (False, True):
            with self.subTest(no_ast=no_ast):
                result, payload = self.scan("ordinary-" + str(int(no_ast)), project, no_ast=no_ast)
                context = result.stdout + "\nstderr:\n" + result.stderr
                self.assertEqual(result.returncode, 1, context)
                self.assertEqual(payload["status"], "ok", context)
                actual = [(Path(row["path"]).name, row["rule"], row["line"], row["col"], row["severity"])
                          for row in payload["findings"]]
                self.assertEqual(sorted(actual), sorted(expected), context)
                self.assertEqual((payload["files"], payload["critical"], payload["warning"], payload["info"]),
                                 (len(ALL_CASES), len(expected) - 1, 1, 0), context)
                for row in payload["findings"]:
                    self.assertEqual(row["category_id"],
                                     "java.sql" if row["rule"] == "java.sql.exec-concat" else "java.security", context)

    def test_formats_cache_and_source_repair(self):
        selected = tuple(BY_NAME[name] for name in ("execute_query", "mixed_placeholder_still_unsafe", "bound_parameters"))
        project, expected = self.fixture(selected)
        result, payload = self.scan("cold", project)
        self.assert_json(result, payload, expected, files=3)
        self.assert_cache("cold", 0, 3)
        result, payload = self.scan("warm-sarif", project, fmt="sarif")
        self.assert_sarif(result, payload, expected)
        self.assert_cache("warm-sarif", 3, 0)
        result, payload = self.scan("meta-json", project, meta=True)
        self.assert_json(result, payload, expected, meta=True, files=3)
        result, stream = self.scan("meta-jsonl", project, meta=True, fmt="jsonl")
        summaries = [row for row in stream if row["type"] == "totals"]
        self.assertEqual(len(summaries), 1, stream)
        summary = summaries[0]
        self.assert_json(result, {"status": summary["status"], "failed_modules": summary["failed_modules"],
                                 "totals": summary, "findings": [row for row in stream if row["type"] == "finding"]},
                         expected, meta=True, files=3)
        repaired = project / "Case_execute_query.java"
        repaired.write_text(BY_NAME["execute_query"].source.replace(SOURCE, '"fixed"'), encoding="utf-8")
        result, payload = self.scan("repair", project)
        self.assert_json(result, payload, [row for row in expected if row[0] != repaired.name], files=3)
        self.assert_cache("repair", 2, 1)

    def test_selection_category_and_scoped_suppression(self):
        selected = tuple(BY_NAME[name] for name in ("execute_query", "mixed_placeholder_still_unsafe", "bound_parameters"))
        project, _ = self.fixture(selected)
        result, payload = self.scan("category-skip", project, meta=True, extra=("--skip-java=4",))
        self.assert_json(result, payload, [], meta=True, files=3)
        selection = self.artifact / "selected-files"
        selection.write_bytes(os.fsencode(project / "Case_bound_parameters.java") + b"\0")
        result, payload = self.scan("selected", project, extra=("--files-from", str(selection)))
        self.assert_json(result, payload, [], files=1)
        result, payload = self.scan("ignored", project, meta=True,
            extra=("--exclude=Case_execute_query.java,Case_mixed_placeholder_still_unsafe.java",))
        self.assert_json(result, payload, [], meta=True, files=1)
        suppression = Case("suppression", handle(f"""
            String query = {SOURCE};
            statement.executeQuery(query); // ubs:ignore[{RULE}]
            // ubs:ignore[{RULE}]
            statement.executeQuery(query);
            statement.executeQuery(query); // SQL_EXEC // ubs:ignore[java.insecure-ssl]
        """))
        project, expected = self.fixture((suppression,))
        result, payload = self.scan("suppressed", project / "Case_suppression.java")
        self.assert_json(result, payload, expected, files=1)
        result, payload = self.scan("suppressed-sarif", project / "Case_suppression.java", fmt="sarif")
        self.assert_sarif(result, payload, expected)

    def test_incomplete_neighbor_recovery_and_context_cache(self):
        ordinary = BY_NAME["execute_query"]
        budget = Case("budget", ordinary.body.replace("String input", ";" * 900 + "\nString input"))
        project, expected = self.fixture((ordinary, budget))
        retained = [row for row in expected if row[0] == "Case_execute_query.java"]

        def partial(label, environment=None):
            result, payload = self.scan(label, project, meta=True, no_ast=True, environment=environment)
            context = result.stdout + "\n" + result.stderr
            self.assertEqual(result.returncode, 2, context)
            self.assertEqual(payload["status"], "partial", context)
            self.assertEqual({row["language"] for row in payload["failed_modules"]}, {"java"}, context)
            actual = [(Path(row["file"]).name, row["rule_id"], row["line"], row["col"], row["severity"])
                      for row in payload["findings"]]
            self.assertEqual(sorted(actual), retained, context)
            self.assertEqual((payload["totals"]["files"], payload["totals"]["critical"], payload["totals"]["warning"],
                              payload["totals"]["info"]), (2, 1, 0, 0), context)
            return context

        self.assertIn("budget", partial("limited", {"UBS_JAVA_SQL_MAX_TOKENS": "256"}).lower())
        result, payload = self.scan("recovery", project, meta=True, no_ast=True)
        self.assert_json(result, payload, expected, meta=True, files=2)
        self.assertIn("budget", partial("limited-warm", {"UBS_JAVA_SQL_MAX_TOKENS": "256"}).lower())
        (project / "Case_budget.java").write_text(budget.source.rstrip()[:-1] + "\n", encoding="utf-8")
        self.assertIn("unbalanced", partial("malformed").lower())
        result, payload = self.scan("disabled-invalid-policy", project, meta=True, no_ast=True,
            extra=("--skip-java=4",), environment={"UBS_JAVA_SQL_MAX_TOKENS": "invalid"})
        self.assert_json(result, payload, [], meta=True, files=2)

    def test_unsupported_neighbor_retains_proven_findings(self):
        project, expected = self.fixture((BY_NAME["execute_query"],) + INCOMPLETE_CASES)
        result, payload = self.scan("unsupported", project, meta=True, no_ast=True)
        context = result.stdout + "\n" + result.stderr
        self.assertEqual(result.returncode, 2, context)
        self.assertEqual(payload["status"], "partial", context)
        self.assertEqual({row["language"] for row in payload["failed_modules"]}, {"java"}, context)
        actual = [(Path(row["file"]).name, row["rule_id"], row["line"], row["col"], row["severity"])
                  for row in payload["findings"]]
        self.assertEqual(sorted(actual), expected, context)
        self.assertEqual((payload["totals"]["files"], payload["totals"]["critical"],
                          payload["totals"]["warning"], payload["totals"]["info"]), (3, 1, 0, 0), context)


if __name__ == "__main__":
    unittest.main()
