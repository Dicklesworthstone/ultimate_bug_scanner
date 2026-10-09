#!/usr/bin/env python3
"""Independent ordinary-CLI controls for proven accepting TLS callbacks.

HostnameVerifier.verify returning true accepts a hostname after the default
verification rules fail. These cases specify API behavior before choosing a
detector: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/HostnameVerifier.html

The selected rule proves an unconditional accepting callback at a real HTTPS
setter. An unknown or conditional callback is not proof of that condition;
absence of this particular finding does not certify arbitrary TLS policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
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
RULE = "java.insecure-ssl"
LEGACY = "java.security.ssl-insecure"


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    unsafe: bool
    imports: str = ""

    @property
    def source(self):
        return ("import javax.net.ssl.HttpsURLConnection;\n"
                "import javax.net.ssl.HostnameVerifier;\n"
                "import javax.net.ssl.SSLSession;\n"
                + self.imports +
                f"class Case_{self.name} {{\n" + textwrap.dedent(self.body).strip() + "\n}\n")

    @property
    def sites(self):
        return [(number, len(line) - len(line.lstrip()) + 1)
                for number, line in enumerate(self.source.splitlines(), 1)
                if "// TLS_INSTALL" in line] if self.unsafe else []


CASES = (
    Case("expression_lambda", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> true); // TLS_INSTALL
        }
    """, True),
    Case("multiline_expression", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier( // TLS_INSTALL
                (hostname, session) ->
                    true
            );
        }
    """, True),
    Case("block_lambda", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> { // TLS_INSTALL
                return true;
            });
        }
    """, True),
    Case("qualified_parameter", """
        void configure(javax.net.ssl.HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> { return true; }); // TLS_INSTALL
        }
    """, True),
    Case("static_default", """
        void configure() {
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); // TLS_INSTALL
        }
    """, True),
    Case("static_default_block", """
        void configure() {
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> { // TLS_INSTALL
                return true;
            });
        }
    """, True),
    Case("anonymous_verifier", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier(new HostnameVerifier() { // TLS_INSTALL
                @Override public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        }
    """, True),
    Case("qualified_anonymous", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier(new javax.net.ssl.HostnameVerifier() { // TLS_INSTALL
                @Override public boolean verify(String hostname, javax.net.ssl.SSLSession session) {
                    return true;
                }
            });
        }
    """, True),
    Case("rejecting_expression", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> false);
        }
    """, False),
    Case("rejecting_block", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> { return false; });
        }
    """, False),
    Case("default_delegate", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
        }
    """, False),
    Case("delegating_expression", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) ->
                HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session));
        }
    """, False),
    Case("delegating_block", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> {
                return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session);
            });
        }
    """, False),
    Case("anonymous_delegate", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier(new HostnameVerifier() {
                @Override public boolean verify(String hostname, SSLSession session) {
                    return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session);
                }
            });
        }
    """, False),
    Case("conditional_rejection", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> {
                if (!session.isValid()) return false;
                return true;
            });
        }
    """, False),
    Case("throwing_callback", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> {
                throw new IllegalStateException();
            });
        }
    """, False),
    Case("finally_overrides_true", """
        void configure(HttpsURLConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> {
                try { return true; }
                finally { return false; }
            });
        }
    """, False),
    Case("custom_receiver", """
        static class CustomConnection {
            void setHostnameVerifier(HostnameVerifier verifier) {}
        }
        void configure(CustomConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> true);
        }
    """, False),
    Case("shadowed_type", """
        static class HttpsURLConnection {
            static void setDefaultHostnameVerifier(HostnameVerifier verifier) {}
        }
        void configure() {
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        }
    """, False),
    Case("unrelated_parameter", """
        static class CustomConnection {
            void setHostnameVerifier(HostnameVerifier verifier) {}
        }
        void unrelated(HttpsURLConnection connection) {}
        void configure(CustomConnection connection) {
            connection.setHostnameVerifier((hostname, session) -> true);
        }
    """, False),
    Case("uninstalled_verifier", """
        HostnameVerifier verifier() {
            return (hostname, session) -> true;
        }
    """, False),
    Case("lexical_decoys", '''
        String example = "connection.setHostnameVerifier((hostname, session) -> true)";
        // connection.setHostnameVerifier((hostname, session) -> true);
        /* HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); */
    ''', False),
    Case("local_callback_alias", """
        void configure(HttpsURLConnection connection) {
            HostnameVerifier verifier = (hostname, session) -> true;
            connection.setHostnameVerifier(verifier); // TLS_INSTALL
        }
    """, True),
    Case("reassigned_callback_alias", """
        void configure(HttpsURLConnection connection) {
            HostnameVerifier verifier = (hostname, session) -> true;
            verifier = (hostname, session) -> false;
            connection.setHostnameVerifier(verifier);
        }
    """, False),
    Case("callback_parameter_scope", """
        void unrelated(HttpsURLConnection connection) {
            HostnameVerifier verifier = (hostname, session) -> true;
        }
        void configure(HttpsURLConnection connection, HostnameVerifier verifier) {
            connection.setHostnameVerifier(verifier);
        }
    """, False),
    Case("static_import", """
        void configure() {
            setDefaultHostnameVerifier((hostname, session) -> true); // TLS_INSTALL
        }
    """, True, "import static javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier;\n"),
    Case("static_import_shadowed_method", """
        static void setDefaultHostnameVerifier(HostnameVerifier verifier) {}
        void configure() {
            setDefaultHostnameVerifier((hostname, session) -> true);
        }
    """, False, "import static javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier;\n"),
    Case("call_chain_borrows_local_receiver", """
        static class CustomConnection {
            void setHostnameVerifier(HostnameVerifier verifier) {}
        }
        static class Holder { CustomConnection connection = new CustomConnection(); }
        Holder factory() { return new Holder(); }
        void configure(HttpsURLConnection connection) {
            factory().connection.setHostnameVerifier((hostname, session) -> true);
        }
    """, False),
    Case("qualified_shadow_namespace", """
        static class javax { static class net { static class ssl {
            static class HttpsURLConnection {
                static void setDefaultHostnameVerifier(HostnameVerifier verifier) {}
            }
        } } }
        void configure() {
            javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        }
    """, False),
    Case("field_after_typed_lambda", """
        HttpsURLConnection connection;
        static class CustomConnection {
            void setHostnameVerifier(HostnameVerifier verifier) {}
        }
        void configure() {
            java.util.function.Consumer<CustomConnection> check = (CustomConnection connection) -> {
                connection.setHostnameVerifier((hostname, session) -> false);
            };
            connection.setHostnameVerifier((hostname, session) -> true); // TLS_INSTALL
        }
    """, True),
    Case("implicit_lambda_shadows_field", """
        HttpsURLConnection connection;
        static class CustomConnection {
            void setHostnameVerifier(HostnameVerifier verifier) {}
        }
        void configure() {
            java.util.function.Consumer<CustomConnection> check = connection -> {
                connection.setHostnameVerifier((hostname, session) -> true);
            };
        }
    """, False),
)


class JavaTlsVerifierTests(unittest.TestCase):
    def setUp(self):
        self.artifact = ROOT / "test-suite/artifacts/java-tls-verifier" / (
            self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.artifact.mkdir(parents=True)

    def fixture(self, cases):
        project = self.artifact / "project"
        project.mkdir(exist_ok=True)
        expected = []
        for case in cases:
            target = project / ("Case_" + case.name + ".java")
            target.write_text(case.source, encoding="utf-8")
            expected.extend((target.name, RULE, line, column, "critical") for line, column in case.sites)
        return project, sorted(expected)

    def scan(self, label, project, *, meta=False, fmt="json", extra=(), no_ast=False, environment=None):
        command = ([str(ROOT / "ubs"), "--only=java", "--ci"] if meta else
                   [str(ROOT / "modules/ubs-java.sh"), "--no-build", "--ci"])
        command += ["--fail-on-warning", "--format=" + fmt, *extra, str(project)]
        env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_ENABLE_AUTO_UPDATE": "0",
               "UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(self.artifact / ("cache-no-ast" if no_ast else "cache")),
               "UBS_CACHE_FILE": str(self.artifact / (label + ".cache.json")), "UBS_PROFILE": "1",
               "UBS_TEST_FORCE_NO_AST_GREP": str(int(no_ast)), "NO_COLOR": "1", "CI": "1"}
        env.update(environment or {})
        started = time.monotonic()
        result = subprocess.run(command, cwd=self.artifact, env=env,  # ubs:ignore[py.security.command-injection] — argv starts with a fixed repository scanner; no shell
                                capture_output=True, text=True, timeout=180)
        for stream in ("stdout", "stderr"):
            (self.artifact / (label + "." + stream + ".log")).write_text(getattr(result, stream), encoding="utf-8")
        identities = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                      ("ubs", "modules/helpers/ubs_core/java_scan.py", "modules/helpers/ubs_core/java_rules.py",
                       "modules/helpers/ubs_core/java_detectors/tls_verification.py") if (ROOT / name).is_file()}
        sources = [project] if project.is_file() else project.glob("*.java")
        (self.artifact / (label + ".identity.json")).write_text(json.dumps({
            "command": command, "exit": result.returncode, "elapsed": time.monotonic() - started,
            "python": sys.version, "ast_grep": shutil.which("ast-grep"), "tools": identities,
            "environment_overrides": environment or {},
            "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[java-tls-{label}] exit={result.returncode} ({time.monotonic() - started:.3f}s)", flush=True)
        try:
            payload = ([json.loads(line) for line in result.stdout.splitlines()] if fmt == "jsonl"
                       else json.loads(result.stdout))
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid {fmt}: {exc}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        return result, payload

    def assert_json(self, result, payload, expected, *, meta=False, files=None):
        context = result.stdout + "\nstderr:\n" + result.stderr
        self.assertEqual(result.returncode, int(bool(expected)), context)
        self.assertEqual(payload["status"], "ok", context)
        if meta:
            self.assertEqual(payload["failed_modules"], [], context)
        rows = payload["findings"]
        actual = [(Path(row["file" if meta else "path"]).name,
                   row["rule_id" if meta else "rule"], row["line"], row["col"], row["severity"]) for row in rows]
        self.assertEqual(sorted(actual), expected, context)
        totals = payload["totals"] if meta else payload
        self.assertEqual((totals["critical"], totals["warning"], totals["info"]), (len(expected), 0, 0), context)
        if files is not None:
            self.assertEqual(totals["files"], files, context)
        self.assertTrue(all(row["category_id"] == "java.security" for row in rows), context)
        self.assertFalse(any(row.get("rule", row.get("rule_id")) == LEGACY for row in rows), context)

    def assert_cache(self, label, hits, misses):
        target = self.artifact / (label + ".cache.json")
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.fail(f"Invalid cache receipt {target}: {exc}")
        self.assertEqual((payload["hits"], payload["misses"]), (hits, misses), payload)

    def assert_sarif(self, result, payload, expected):
        context = result.stdout + "\nstderr:\n" + result.stderr
        self.assertEqual(result.returncode, int(bool(expected)), context)
        self.assertEqual(payload["version"], "2.1.0", context)
        runs = {}
        for run in payload["runs"]:
            driver = run["tool"]["driver"]["name"]
            self.assertNotIn(driver, runs, context)
            rows = []
            for row in run.get("results", []):
                self.assertEqual(row["level"], "error", context)
                self.assertEqual(len(row["locations"]), 1, context)
                location = row["locations"][0]["physicalLocation"]
                region = location["region"]
                rows.append((Path(location["artifactLocation"]["uri"]).name, row["ruleId"],
                             region["startLine"], region["startColumn"], "critical"))
            self.assertEqual(len(rows), len(set(rows)), context)
            runs[driver] = sorted(rows)
        self.assertEqual(runs.get("ubs-java-heuristics"), expected, context)
        # AST evidence is ancillary and has historically had a narrower syntax
        # surface. It may only retain qualified sites, never safe callbacks.
        for driver, rows in runs.items():
            self.assertIn(driver, {"ubs-java-heuristics", "ubs-java-ast"}, context)
            self.assertTrue(set(rows).issubset(expected), context)

    def test_independent_cases_in_ordinary_module(self):
        project, expected = self.fixture(CASES)
        result, payload = self.scan("ordinary-module", project)
        self.assert_json(result, payload, expected, files=len(CASES))
        result, payload = self.scan("ordinary-no-ast", project, no_ast=True)
        self.assert_json(result, payload, expected, files=len(CASES))

    def test_public_formats_cache_and_source_repair(self):
        selected = tuple(case for case in CASES if case.name in {
            "block_lambda", "anonymous_verifier", "delegating_block"})
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
        rows = [row for row in stream if row["type"] == "finding"]
        summaries = [row for row in stream if row["type"] == "totals"]
        self.assertEqual(len(summaries), 1, stream)
        summary = summaries[0]
        document = {"status": summary["status"], "failed_modules": summary["failed_modules"],
                    "totals": summary, "findings": rows}
        self.assert_json(result, document, expected, meta=True, files=3)
        repaired = project / "Case_block_lambda.java"
        repaired.write_text(repaired.read_text(encoding="utf-8").replace("return true;", "return false;"),
                            encoding="utf-8")
        remaining = [row for row in expected if row[0] != repaired.name]
        result, payload = self.scan("source-repair", project)
        self.assert_json(result, payload, remaining, files=3)
        self.assert_cache("source-repair", 2, 1)

    def test_category_selection_and_ignore_preserve_clean_exit(self):
        selected = tuple(case for case in CASES if case.name in {
            "block_lambda", "anonymous_verifier", "delegating_block"})
        project, _ = self.fixture(selected)
        result, payload = self.scan("disabled-category", project, meta=True, extra=("--skip-java=4",))
        self.assert_json(result, payload, [], meta=True, files=3)
        selection = self.artifact / "selected-files"
        selection.write_bytes(os.fsencode(project / "Case_delegating_block.java") + b"\0")
        result, payload = self.scan("selected-safe", project, extra=("--files-from", str(selection)))
        self.assert_json(result, payload, [], files=1)
        result, payload = self.scan("ignored-unsafe", project, meta=True, extra=(
            "--exclude=Case_block_lambda.java,Case_anonymous_verifier.java",))
        self.assert_json(result, payload, [], meta=True, files=1)

    def test_scoped_suppression_keeps_enabled_neighbor(self):
        case = Case("suppression", """
            void configure(HttpsURLConnection connection) {
                connection.setHostnameVerifier((hostname, session) -> { // ubs:ignore[java.insecure-ssl]
                    return true;
                });
                // ubs:ignore[java.insecure-ssl]
                connection.setHostnameVerifier((hostname, session) -> true);
                connection.setHostnameVerifier((hostname, session) -> true); // ubs:ignore[java.secrets.string-decl] // TLS_INSTALL
            }
        """, True)
        project, expected = self.fixture((case,))
        result, payload = self.scan("suppressed", project)
        self.assert_json(result, payload, expected, files=1)
        result, payload = self.scan("suppressed-sarif", project, fmt="sarif")
        self.assert_sarif(result, payload, expected)
        self.assert_cache("suppressed-sarif", 1, 0)

    def test_frontend_limits_retain_neighbor_findings_and_recover(self):
        neighbor = next(case for case in CASES if case.name == "block_lambda")
        budget = Case("token_budget", """
            void configure(HttpsURLConnection connection) {
                %s
                connection.setHostnameVerifier((hostname, session) -> true); // TLS_INSTALL
            }
        """ % (";" * 500), True)
        project, expected = self.fixture((neighbor, budget))
        retained = [row for row in expected if row[0] == "Case_block_lambda.java"]

        def partial(label, *, environment=None):
            result, payload = self.scan(label, project, meta=True, no_ast=True, environment=environment)
            context = result.stdout + "\nstderr:\n" + result.stderr
            self.assertEqual(result.returncode, 2, context)
            self.assertEqual(payload["status"], "partial", context)
            self.assertTrue(payload["failed_modules"], context)
            self.assertEqual({row["language"] for row in payload["failed_modules"]}, {"java"}, context)
            actual = [(Path(row["file"]).name, row["rule_id"], row["line"], row["col"], row["severity"])
                      for row in payload["findings"]]
            self.assertEqual(sorted(actual), retained, context)
            self.assertEqual((payload["totals"]["files"], payload["totals"]["critical"],
                              payload["totals"]["warning"], payload["totals"]["info"]), (2, 1, 0, 0), context)
            return context

        receipt = partial("limited", environment={"UBS_JAVA_TLS_MAX_TOKENS": "100"})
        self.assertIn("token budget", receipt)
        result, payload = self.scan("budget-recovery", project, meta=True, no_ast=True)
        self.assert_json(result, payload, expected, meta=True, files=2)
        self.assertIn("token budget", partial("limited-after-cache", environment={"UBS_JAVA_TLS_MAX_TOKENS": "100"}))
        malformed = project / "Case_token_budget.java"
        malformed.write_text(budget.source.rstrip()[:-1] + "\n", encoding="utf-8")
        self.assertIn("Unbalanced Java TLS source", partial("malformed"))
        result, payload = self.scan("skipped-bad-policy", project, meta=True, no_ast=True,
                                    extra=("--skip-java=4",), environment={"UBS_JAVA_TLS_MAX_TOKENS": "invalid"})
        self.assert_json(result, payload, [], meta=True, files=2)


if __name__ == "__main__":
    unittest.main()
