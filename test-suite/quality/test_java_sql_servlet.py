#!/usr/bin/env python3
"""Independent JDBC request-source oracle for the two real Servlet namespaces.

Primary API contracts: Jakarta Servlet 6.1 ServletRequest/HttpServletRequest and
Java EE 8 javax.servlet ServletRequest/HttpServletRequest.  getParameter exposes
request parameters; the selected HTTP getters expose request header, query, and
path text.  getAttribute is deliberately not asserted to be a request source.

https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/servletrequest
https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/http/httpservletrequest
https://javaee.github.io/javaee-spec/javadocs/javax/servlet/ServletRequest.html
https://javaee.github.io/javaee-spec/javadocs/javax/servlet/http/HttpServletRequest.html

The optional compiler gate requires the pinned released API JARs.  JDBC comes
from the real JDK; local lookalike classes occur only as explicit negative cases.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
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

import test_java_sql_provenance as sql

ROOT = Path(__file__).resolve().parents[2]
RULE = "java.security.sql-injection"
DEPENDENCIES = {
    "jakarta.servlet-api-6.1.0.jar": "8a31f465f3593bf2351531a5c952014eb839da96a605b5825b93dd54714c48c4",
    "javax.servlet-api-4.0.1.jar": "83a03dd877d3674576f0da7b90755c8524af099ccf0607fc61aa971535ad7c60",
}


@dataclass(frozen=True)
class Case:
    name: str
    namespace: str
    body: str
    parameters: str = "HttpServletRequest incoming, Statement statement"
    members: str = ""
    wildcard: bool = False

    @property
    def source(self):
        imports = (f"import {self.namespace}.servlet.*;\n"
                   f"import {self.namespace}.servlet.http.*;\n") if self.wildcard else (
                   f"import {self.namespace}.servlet.ServletRequest;\n"
                   f"import {self.namespace}.servlet.http.HttpServletRequest;\n")
        return ("import java.sql.Statement;\nimport java.sql.Connection;\n"
                "import java.sql.PreparedStatement;\nimport java.sql.SQLException;\n" + imports
                + f"class Case_{self.name} {{\n"
                + textwrap.dedent(self.members).strip() + "\n"
                + f"static void handle({self.parameters}) throws SQLException {{\n"
                + textwrap.dedent(self.body).strip() + "\n}\n}\n")

    @property
    def sites(self):
        return [(line, len(text) - len(text.lstrip()) + 1)
                for line, text in enumerate(self.source.splitlines(), 1) if "// SQL_EXEC" in text]


def query_body(source, *, mark=True):
    return (f"String input = {source};\n"
            "String query = \"select * from users where name='\" + input + \"'\";\n"
            "statement.executeQuery(query);" + (" // SQL_EXEC" if mark else ""))


def namespace_cases(namespace):
    def case(name, body, **kwargs):
        return Case(namespace + "_" + name, namespace, body, **kwargs)

    sources = (
        ("parameter", "HttpServletRequest", 'incoming.getParameter("name")'),
        ("base_parameter", "ServletRequest", 'incoming.getParameter("name")'),
        ("header", "HttpServletRequest", 'incoming.getHeader("X-User")'),
        ("query_string", "HttpServletRequest", "incoming.getQueryString()"),
        ("request_uri", "HttpServletRequest", "incoming.getRequestURI()"),
        ("path_info", "HttpServletRequest", "incoming.getPathInfo()"),
        ("servlet_path", "HttpServletRequest", "incoming.getServletPath()"),
    )
    cases = [case(name, query_body(source), parameters=kind + " incoming, Statement statement")
             for name, kind, source in sources]
    cases += [
        case("request_alias", '''
            HttpServletRequest alias = incoming;
            ServletRequest base = alias;
            String query = base.getParameter("query");
            statement.executeQuery(query); // SQL_EXEC
        '''),
        case("source_helper", '''
            String query = read(incoming);
            statement.executeQuery(query); // SQL_EXEC
        ''', members='static String read(HttpServletRequest selected) { return selected.getParameter("query"); }'),
        case("request_helper", query_body('same(incoming).getParameter("name")'),
             members="static HttpServletRequest same(HttpServletRequest selected) { return selected; }"),
        case("grouped_base", query_body('((ServletRequest) incoming).getParameter("name")')),
        case("grouped_http", query_body('(incoming).getHeader("X-User")')),
        case("prepared_capture", '''
            String input = incoming.getParameter("name");
            String query = "select * from users where name='" + input + "' and tenant=?";
            try (PreparedStatement prepared = connection.prepareStatement(query)) {
                prepared.setInt(1, 7);
                query = "select 1";
                prepared.executeQuery(); // SQL_EXEC
            }
        ''', parameters="HttpServletRequest incoming, Connection connection"),
        case("branch_join", '''
            String query = "select 1";
            if (choose) { query = incoming.getParameter("query"); }
            statement.executeQuery(query); // SQL_EXEC
        ''', parameters="HttpServletRequest incoming, Statement statement, boolean choose"),
        case("qualified", query_body('incoming.getParameter("name")'),
             parameters=namespace + ".servlet.http.HttpServletRequest incoming, java.sql.Statement statement"),
        case("wildcard", query_body('incoming.getParameter("name")'), wildcard=True),
        case("shadowed_numeric_parser", '''
            String input = incoming.getParameter("name");
            String parsed = Integer.parseInt(input);
            String query = "select * from users where name='" + parsed + "'";
            statement.executeQuery(query); // SQL_EXEC
        ''', parameters="HttpServletRequest incoming, Statement statement, Parser Integer",
             members="interface Parser { String parseInt(String value); }"),
        case("bound_parameters", '''
            try (PreparedStatement prepared = connection.prepareStatement("select * from users where name=?")) {
                PreparedStatement alias = prepared;
                alias.setString(1, incoming.getParameter("name"));
                alias.executeQuery();
            }
        ''', parameters="HttpServletRequest incoming, Connection connection"),
        case("numeric_guard", '''
            int number = java.lang.Integer.parseInt(incoming.getParameter("id"));
            String query = "select * from users where id=" + number;
            statement.executeQuery(query);
        '''),
        case("safe_rebinding", '''
            String query = incoming.getParameter("query");
            query = "select 1";
            statement.executeQuery(query);
        '''),
        case("static_query", '''
            String unused = incoming.getParameter("name");
            statement.executeQuery("select 1");
        '''),
        case("shadowed_api_type", query_body('incoming.getParameter("name")', mark=False),
             members='static class HttpServletRequest { String getParameter(String key) { return "fixed"; } }'),
        case("fake_method_receiver", query_body('incoming.getParameter("name")', mark=False),
             parameters="FakeRequest incoming, HttpServletRequest actual, Statement statement",
             members='static class FakeRequest { String getParameter(String key) { return "fixed"; } }'),
        case("namespace_variable", query_body(
             namespace + '.servlet.http.HttpServletRequest.getParameter("name")', mark=False),
             parameters="Namespace " + namespace + ", HttpServletRequest actual, Statement statement",
             members='''
                 static class Namespace { ServletPart servlet = new ServletPart(); }
                 static class ServletPart { HttpPart http = new HttpPart(); }
                 static class HttpPart { FixedRequest HttpServletRequest = new FixedRequest(); }
                 static class FixedRequest { String getParameter(String key) { return "fixed"; } }
             '''),
        case("attribute_is_unknown", '''
            String query = (String) incoming.getAttribute("internal-query");
            statement.executeQuery(query);
        '''),
    ]
    return tuple(cases)


def review_cases(namespace):
    """Independent compiled and runtime-verified cast/overload regressions."""
    def case(name, body, **kwargs):
        return Case("review_" + namespace + "_" + name, namespace, body, **kwargs)

    overloads = '''
        static class FixedRequest {}
        static String read(HttpServletRequest selected) { return selected.getParameter("query"); }
        static String read(FixedRequest selected) { return "select 1"; }
    '''
    return (
        case("base_to_http_cast", query_body('((HttpServletRequest) incoming).getHeader("X-Query")'),
             parameters="ServletRequest incoming, Statement statement"),
        case("cast_type_variable", 'int HttpServletRequest = 0;\n' +
             query_body('((HttpServletRequest) incoming).getHeader("X-Query")'),
             parameters="ServletRequest incoming, Statement statement"),
        case("qualified_cast_variable", "int " + namespace + " = 0;\n" +
             query_body('((' + namespace + '.servlet.http.HttpServletRequest) incoming).getHeader("X-Query")'),
             parameters="ServletRequest incoming, Statement statement"),
        case("base_helper", '''
            String query = read(incoming);
            statement.executeQuery(query); // SQL_EXEC
        ''', members="static String read(final " + namespace +
             '.servlet.ServletRequest selected) { return selected.getParameter("query"); }'),
        case("overload_fixed", '''
            FixedRequest fixed = new FixedRequest();
            String query = read(fixed);
            statement.executeQuery(query);
        ''', members=overloads),
        case("overload_actual", '''
            String query = read(incoming);
            statement.executeQuery(query); // SQL_EXEC
        ''', members=overloads),
        case("qualified_helper_shadow", '''
            String query = read(incoming);
            statement.executeQuery(query); // SQL_EXEC
        ''', members=(
            'static class ServletRequest { String getParameter(String name) { return "fixed"; } }\n'
            "static String read(" + namespace + '.servlet.ServletRequest selected) { return selected.getParameter("query"); }')),
        case("cast_local_fake", query_body('((HttpServletRequest) incoming).getHeader("X-Query")', mark=False),
             parameters="Object incoming, " + namespace + ".servlet.http.HttpServletRequest actual, Statement statement",
             members='static class HttpServletRequest { String getHeader(String name) { return "fixed"; } }'),
    )


BASE_CASES = namespace_cases("jakarta") + namespace_cases("javax")
REVIEW_CASES = review_cases("jakarta") + review_cases("javax")
CASES = BASE_CASES + REVIEW_CASES
BY_NAME = {case.name: case for case in CASES}


def artifact(label):
    directory = ROOT / "test-suite/artifacts/java-sql-servlet" / (label + "-" + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True)
    return directory


def identities():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "test-suite/quality/test_java_sql_servlet.py",
        "test-suite/quality/test_java_sql_provenance.py",
        "modules/helpers/ubs_core/analyzers/taint_java_sql.py",
        "modules/helpers/ubs_core/java_scan.py",
        "modules/helpers/ubs_core/java_detectors/tls_verification.py",
    )}


@unittest.skipUnless(os.environ.get("UBS_JAVA_SQL_SERVLET_COMPILE") == "1",
                     "set UBS_JAVA_SQL_SERVLET_COMPILE=1 to require the pinned real Servlet API JARs")
class JavaSqlServletCompilerTests(unittest.TestCase):
    def test_actual_servlet_and_jdbc_apis(self):
        target = artifact("compiler")
        java = shutil.which("java")
        self.assertIsNotNone(java, "The actual JDK compiler is required")
        tools = Path(os.environ.get("UBS_JAVA_SQL_SERVLET_TOOL_DIR",
                                   str(ROOT / "test-suite/artifacts/java-sql-servlet-tools")))
        jars = []
        for name, digest in DEPENDENCIES.items():
            jar = tools / name
            self.assertTrue(jar.is_file(), "Required real dependency missing: " + str(jar))
            self.assertEqual(hashlib.sha256(jar.read_bytes()).hexdigest(), digest, str(jar))
            jars.append(jar)
        sources = []
        for case in CASES:
            path = target / ("Case_" + case.name + ".java")
            path.write_text(case.source, encoding="utf-8")
            sources.append(path)
        classes = target / "classes"
        classes.mkdir()
        command = [java, "-m", "jdk.compiler/com.sun.tools.javac.Main", "--release", "17",
                   "-classpath", os.pathsep.join(str(path) for path in jars), "-d", str(classes),
                   *(str(path) for path in sources)]
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)  # ubs:ignore[py.security.command-injection] — fixed JDK compiler module and repository-authored paths, no shell
        for stream in ("stdout", "stderr"):
            (target / ("javac." + stream + ".log")).write_text(getattr(result, stream), encoding="utf-8")
        (target / "receipt.json").write_text(json.dumps({"command": command, "exit": result.returncode,
            "elapsed": time.monotonic() - started, "python": sys.version, "dependencies": DEPENDENCIES,
            "tools": identities(), "sources": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                for path in sources}}, indent=2) + "\n", encoding="utf-8")
        print("[java-sql-servlet-compiler] " + str(target), flush=True)
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)


class JavaSqlServletDirectTests(unittest.TestCase):
    def test_real_sources_and_control_identities(self):
        analyzer = importlib.import_module("ubs_core.analyzers.taint_java_sql")
        target = artifact("direct")
        receipts = []
        for case in CASES:
            with self.subTest(case=case.name):
                path = target / ("Case_" + case.name + ".java")
                path.write_text(case.source, encoding="utf-8")
                expected = [(RULE, line, col, "critical", "java.security") for line, col in case.sites]
                started = time.monotonic()
                rows, error = [], None
                try:
                    rows = analyzer.analyze_source(path, case.source)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                actual = [(row["rule"], row["line"], row["col"], row["severity"], row["category_id"])
                          for row in rows]
                receipts.append({"case": case.name, "namespace": case.namespace, "expected": expected,
                    "actual": actual, "error": error, "elapsed": time.monotonic() - started,
                    "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                (target / (case.name + ".stdout.log")).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
                (target / (case.name + ".stderr.log")).write_text(error or "", encoding="utf-8")
                self.assertIsNone(error, case.name)
                self.assertEqual(actual, expected, case.name)
                for row in rows:
                    self.assertEqual(Path(row["path"]), path)
                    self.assertTrue(row.get("extras", {}).get("taint_path"), row)
        (target / "receipt.json").write_text(json.dumps({"command": sys.argv, "python": sys.version,
            "tools": identities(), "cases": receipts}, indent=2) + "\n", encoding="utf-8")
        print("[java-sql-servlet-direct] " + str(target), flush=True)


class JavaSqlServletPublicTests(unittest.TestCase):
    scan = sql.JavaSqlPublicTests.scan
    assert_json = sql.JavaSqlPublicTests.assert_json
    assert_sarif = sql.JavaSqlPublicTests.assert_sarif

    def setUp(self):
        self.artifact = artifact(self._testMethodName)
        (self.artifact / "oracle.identity.json").write_text(json.dumps(identities(), indent=2) + "\n", encoding="utf-8")

    def fixture(self, cases, directory="project"):
        project = self.artifact / directory
        project.mkdir(exist_ok=True)
        expected = []
        for case in cases:
            path = project / ("Case_" + case.name + ".java")
            path.write_text(case.source, encoding="utf-8")
            expected.extend((path.name, RULE, line, col, "critical") for line, col in case.sites)
        return project, sorted(expected)

    def test_complete_sources_with_and_without_ast(self):
        project, expected = self.fixture(CASES)
        for no_ast in (False, True):
            with self.subTest(no_ast=no_ast):
                result, payload = self.scan("ordinary-" + str(int(no_ast)), project, no_ast=no_ast)
                self.assert_json(result, payload, expected, files=len(CASES))

    def test_namespace_formats(self):
        for namespace, fmt in (("jakarta", "json"), ("javax", "sarif")):
            with self.subTest(namespace=namespace, fmt=fmt):
                selected = tuple(case for case in CASES if case.namespace == namespace)
                project, expected = self.fixture(selected, namespace)
                result, payload = self.scan(namespace, project, meta=True, fmt=fmt)
                if fmt == "json":
                    self.assert_json(result, payload, expected, meta=True, files=len(selected))
                else:
                    self.assert_sarif(result, payload, expected)

    def test_bound_controls_and_scoped_suppression(self):
        controls = tuple(case for case in CASES if not case.sites)
        project, expected = self.fixture(controls)
        result, payload = self.scan("controls", project)
        self.assert_json(result, payload, expected, files=len(controls))
        suppression = tuple(replace(BY_NAME[namespace + "_parameter"], name=namespace + "_suppression", body='''
            String query = incoming.getParameter("query");
            statement.executeQuery(query); // ubs:ignore[java.security.sql-injection]
            // ubs:ignore[java.security.sql-injection]
            statement.executeQuery(query);
            statement.executeQuery(query); // SQL_EXEC // ubs:ignore[java.insecure-ssl]
        ''') for namespace in ("jakarta", "javax"))
        project, expected = self.fixture(suppression, "suppression")
        for fmt in ("json", "sarif"):
            with self.subTest(fmt=fmt):
                result, payload = self.scan("suppressed-" + fmt, project, fmt=fmt)
                if fmt == "json":
                    self.assert_json(result, payload, expected, files=2)
                else:
                    self.assert_sarif(result, payload, expected)

    def test_disabled_security_sources(self):
        project, _ = self.fixture(CASES)
        result, payload = self.scan("category-skip", project, meta=True, extra=("--skip-java=4",))
        self.assert_json(result, payload, [], meta=True, files=len(CASES))


if __name__ == "__main__":
    unittest.main()
