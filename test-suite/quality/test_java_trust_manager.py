#!/usr/bin/env python3
"""Independent oracle for installing an explicitly accepting X509 manager.

The SSLContext.init contract selects the first manager of a given type, and
X509TrustManager.checkServerTrusted must reject an untrusted chain by throwing.
An empty issuer list alone is permitted. These fixtures specify those API facts,
not a general certificate-policy audit or an inference from method names.

https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/SSLContext.html
https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/net/ssl/X509TrustManager.html
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import textwrap
import time
import unittest
import uuid

import test_java_tls_verifier as tls

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core import java_scan

RULE = "java.security.trust-all-certificates"
DETECTOR = ROOT / "modules/helpers/ubs_core/java_detectors/trust_manager.py"


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    unsafe: bool

    @property
    def source(self):
        return ("import javax.net.ssl.SSLContext;\nimport javax.net.ssl.TrustManager;\n"
                "import javax.net.ssl.X509TrustManager;\nimport java.security.cert.X509Certificate;\n"
                "import java.security.cert.CertificateException;\n"
                f"class Case_{self.name} {{\n" + textwrap.dedent(self.body).strip() + "\n}\n")

    @property
    def sites(self):
        return [(line, len(source) - len(source.lstrip()) + 1)
                for line, source in enumerate(self.source.splitlines(), 1)
                if "// TRUST_INSTALL" in source] if self.unsafe else []


def manager(server="", *, client="throw new CertificateException();", qualified=False):
    """Render a complete, compilable callback with an independently chosen body."""
    kind = "javax.net.ssl.X509TrustManager" if qualified else "X509TrustManager"
    cert = "java.security.cert.X509Certificate" if qualified else "X509Certificate"
    return (f"new {kind}() {{\n"
            f"    public void checkServerTrusted({cert}[] chain, String auth) throws CertificateException {{ {server} }}\n"
            f"    public void checkClientTrusted({cert}[] chain, String auth) throws CertificateException {{ {client} }}\n"
            f"    public {cert}[] getAcceptedIssuers() {{ return new {cert}[0]; }}\n"
            "}")


ACCEPT = manager()
REJECT = manager("throw new CertificateException();")


def install(expression, *, parameters="SSLContext context", before="", marked=True):
    return (f"void configure({parameters}) throws Exception {{\n{before}\n"
            "    context.init( // " + ("TRUST_INSTALL" if marked else "ordinary call") + "\n"
            f"        null, {expression}, null);\n}}")


CASES = (
    Case("inline_empty", install("new TrustManager[] { " + ACCEPT + " }"), True),
    Case("inline_bare_return", install("new X509TrustManager[] { " + manager("return;") + " }"), True),
    Case("local_array_literal", install("managers", before="TrustManager[] managers = { " + ACCEPT + " };"), True),
    Case("local_manager_alias", install("managers", before=(
        "X509TrustManager manager = " + ACCEPT + ";\nTrustManager alias = manager;\n"
        "TrustManager[] managers = new TrustManager[] { alias };")), True),
    Case("fully_qualified", install("new javax.net.ssl.TrustManager[] { " + manager(qualified=True) + " }",
                                   parameters="javax.net.ssl.SSLContext context"), True),
    Case("local_context", install("new TrustManager[] { " + ACCEPT + " }", parameters="",
                                  before='SSLContext context = SSLContext.getInstance("TLS");'), True),
    Case("non_x509_before_accepting", install("new TrustManager[] { new TrustManager() {}, " + ACCEPT + " }"), True),
    Case("known_null_predecessor", install("new TrustManager[] { null, " + ACCEPT + " }"), True),
    Case("accepting_before_rejecting", install("new TrustManager[] { " + ACCEPT + ", " + REJECT + " }"), True),
    Case("rejecting_before_accepting", install("new TrustManager[] { " + REJECT + ", " + ACCEPT + " }", marked=False), False),
    Case("unknown_before_accepting", install("new TrustManager[] { first, " + ACCEPT + " }",
                                            parameters="SSLContext context, TrustManager first", marked=False), False),
    Case("provider_defaults", install("null", marked=False), False),
    Case("empty_managers", install("new TrustManager[0]", marked=False), False),
    Case("unused_accepting", "TrustManager unused() { return " + ACCEPT + "; }", False),
    Case("rejecting_empty_issuers", install("new TrustManager[] { " + REJECT + " }", marked=False), False),
    Case("delegating_server", install("new TrustManager[] { " + manager("delegate.checkServerTrusted(chain, auth);") + " }",
                                      parameters="SSLContext context, X509TrustManager delegate", marked=False), False),
    Case("conditional_rejection", install("new TrustManager[] { " + manager('if (chain.length == 0) throw new CertificateException();') + " }", marked=False), False),
    Case("finally_rejects", install("new TrustManager[] { " + manager("try { return; } finally { throw new CertificateException(); }") + " }", marked=False), False),
    Case("client_only_accepting", install("new TrustManager[] { " + manager("throw new CertificateException();", client="") + " }", marked=False), False),
    Case("custom_receiver", "static class CustomContext { void init(Object key, TrustManager[] managers, Object random) {} }\n" +
         install("new TrustManager[] { " + ACCEPT + " }", parameters="CustomContext context", marked=False), False),
    Case("shadowed_context_type", "static class SSLContext { void init(Object key, TrustManager[] managers, Object random) {} }\n" +
         install("new TrustManager[] { " + ACCEPT + " }", marked=False), False),
    Case("shadowed_namespace", """
        static class javax { static class net { static class ssl {
            static class SSLContext { void init(Object key, TrustManager[] managers, Object random) {} }
        } } }
    """ + install("new TrustManager[] { " + ACCEPT + " }", parameters="javax.net.ssl.SSLContext context", marked=False), False),
    Case("shadowed_manager_type", """
        interface X509TrustManager extends TrustManager {
            void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException;
            void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException;
            X509Certificate[] getAcceptedIssuers();
        }
    """ + install("new TrustManager[] { " + ACCEPT + " }", marked=False), False),
    Case("sibling_manager_scope", "void unrelated() { TrustManager[] managers = { " + ACCEPT + " }; }\n" +
         install("managers", parameters="SSLContext context, TrustManager[] managers", marked=False), False),
    Case("implicit_lambda_shadows_field", """
        SSLContext context;
        static class CustomContext { void init(Object key, TrustManager[] managers, Object random) {} }
        void configure() {
            java.util.function.Consumer<CustomContext> callback = context -> {
    """ + "context.init(null, new TrustManager[] { " + ACCEPT + " }, null);\n};\n}", False),
    Case("field_after_typed_lambda", """
        SSLContext context;
        static class CustomContext { void init(Object key, TrustManager[] managers, Object random) {} }
        void configure() throws Exception {
            java.util.function.Consumer<CustomContext> callback = (CustomContext context) -> {
                context.init(null, null, null);
            };
            context.init( // TRUST_INSTALL
    """ + "null, new TrustManager[] { " + ACCEPT + " }, null);\n}", True),
    Case("computed_receiver_suffix", """
        static class CustomContext { void init(Object key, TrustManager[] managers, Object random) {} }
        static class Holder { CustomContext context = new CustomContext(); }
        Holder factory() { return new Holder(); }
        void configure(SSLContext context) {
    """ + "factory().context.init(null, new TrustManager[] { " + ACCEPT + " }, null);\n}", False),
    Case("array_element_replaced", install("managers", before=("TrustManager[] managers = { " + ACCEPT +
         " };\nmanagers[0] = " + REJECT + ";"), marked=False), False),
    Case("parenthesized_array_replacement", install("managers", before=("TrustManager[] managers = { " + ACCEPT +
         " };\n(managers)[0] = " + REJECT + ";"), marked=False), False),
    Case("array_alias_element_replaced", install("managers", before=("TrustManager[] managers = { " + ACCEPT +
         " };\nTrustManager[] alias = managers;\nalias[0] = " + REJECT + ";"), marked=False), False),
    Case("unknown_array_call", install("managers", parameters="SSLContext context, java.util.function.Consumer<TrustManager[]> effect",
         before="TrustManager[] managers = { " + ACCEPT + " };\neffect.accept(managers);", marked=False), False),
    Case("unknown_cast_array_call", install("managers", parameters="SSLContext context, java.util.function.Consumer<Object> effect",
         before="TrustManager[] managers = { " + ACCEPT + " };\neffect.accept((Object) managers);", marked=False), False),
    Case("unknown_container_array_call", install("managers", parameters="SSLContext context, java.util.function.Consumer<Object[]> effect",
         before="TrustManager[] managers = { " + ACCEPT + " };\neffect.accept(new Object[] { managers });", marked=False), False),
    Case("computed_recipient_escape", install("managers", parameters="SSLContext context, java.util.function.Supplier<java.util.function.Consumer<TrustManager[]>> factory",
         before="TrustManager[] managers = { " + ACCEPT + " };\nfactory.get().accept(managers);", marked=False), False),
    Case("manager_rebound_after_capture", install("managers", before=("X509TrustManager selected = " + ACCEPT +
         ";\nTrustManager[] managers = { selected };\nselected = " + REJECT + ";")), True),
    Case("manager_rebound_before_capture", install("managers", before=("X509TrustManager selected = " + ACCEPT +
         ";\nselected = " + REJECT + ";\nTrustManager[] managers = { selected };"), marked=False), False),
    Case("array_alias_stable", install("alias", before=("TrustManager[] managers = { " + ACCEPT +
         " };\nTrustManager[] alias = managers;")), True),
    Case("lexical_decoys", '''
        String example = "context.init(null, new TrustManager[] { new X509TrustManager() {} }, null)";
        // context.init(null, new TrustManager[] { new X509TrustManager() {} }, null);
        /* public void checkServerTrusted(X509Certificate[] chain, String auth) {} */
    ''', False),
    Case("unrelated_overload", install("new TrustManager[] { " + manager(
         "throw new CertificateException();").replace("public void checkClientTrusted", "public void checkServerTrusted(Object[] chain, String auth) {}\n    public void checkClientTrusted") + " }", marked=False), False),
    Case("comments_only_server", install("new TrustManager[] { " + manager("/* no validation */ // comment\n") + " }"), True),
)


class JavaTrustDirectTests(unittest.TestCase):
    def test_independent_installation_cases(self):
        artifact = ROOT / "test-suite/artifacts/java-trust-manager" / ("direct-" + uuid.uuid4().hex[:12])
        artifact.mkdir(parents=True)
        cases = []
        for case in CASES:
            with self.subTest(case=case.name):
                source = artifact / ("Case_" + case.name + ".java")
                source.write_text(case.source, encoding="utf-8")
                sink, errors = io.StringIO(), []
                started = time.monotonic()
                java_scan.run_detectors([source], sink, set(range(1, 20)) - {4}, errors=errors)
                try:
                    rows = [json.loads(row) for row in sink.getvalue().splitlines()]
                except json.JSONDecodeError as exc:
                    self.fail(f"Invalid native detector JSON for {case.name}: {exc}")
                actual = [(row["rule"], row["line"], row["col"], row["severity"], row["category_id"])
                          for row in rows if row["rule"] == RULE]
                expected = [(RULE, line, col, "critical", "java.security") for line, col in case.sites]
                cases.append({"case": case.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                              "expected": expected, "actual": actual, "errors": errors,
                              "elapsed": time.monotonic() - started})
                (artifact / (case.name + ".stdout.log")).write_text(sink.getvalue(), encoding="utf-8")
                (artifact / (case.name + ".stderr.log")).write_text("\n".join(errors), encoding="utf-8")
                self.assertEqual(errors, [], case.name)
                self.assertEqual(actual, expected, case.name)
        identities = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (Path(__file__), DETECTOR, ROOT / "modules/helpers/ubs_core/java_scan.py") if path.is_file()}
        (artifact / "receipt.json").write_text(json.dumps({
            "command": sys.argv, "python": sys.version, "tools": identities,
            "detector_present": DETECTOR.is_file(), "cases": cases,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"[java-trust-direct] {artifact}", flush=True)


class JavaTrustPublicTests(unittest.TestCase):
    # Reuse ordinary CLI machinery without inheriting the hostname oracle cases.
    scan = tls.JavaTlsVerifierTests.scan
    assert_json = tls.JavaTlsVerifierTests.assert_json
    assert_sarif = tls.JavaTlsVerifierTests.assert_sarif
    assert_cache = tls.JavaTlsVerifierTests.assert_cache

    def setUp(self):
        self.artifact = ROOT / "test-suite/artifacts/java-trust-manager" / (
            self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.artifact.mkdir(parents=True)
        identities = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (Path(__file__), DETECTOR) if path.is_file()}
        (self.artifact / "oracle.identity.json").write_text(json.dumps(identities, indent=2) + "\n", encoding="utf-8")

    def fixture(self, cases):
        project = self.artifact / "project"
        project.mkdir(exist_ok=True)
        expected = []
        for case in cases:
            target = project / ("Case_" + case.name + ".java")
            target.write_text(case.source, encoding="utf-8")
            expected.extend((target.name, RULE, line, col, "critical") for line, col in case.sites)
        return project, sorted(expected)

    def test_ordinary_module_with_and_without_ast(self):
        project, expected = self.fixture(CASES)
        for no_ast in (False, True):
            result, payload = self.scan("ordinary-" + str(int(no_ast)), project, no_ast=no_ast)
            self.assert_json(result, payload, expected, files=len(CASES))

    def test_public_formats_and_cache_invalidation(self):
        selected = tuple(case for case in CASES if case.name in {"inline_empty", "inline_bare_return", "delegating_server"})
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
        repaired = project / "Case_inline_empty.java"
        repaired.write_text(next(case for case in CASES if case.name == "inline_empty").source.replace(
            "throws CertificateException {  }", "throws CertificateException { throw new CertificateException(); }"), encoding="utf-8")
        result, payload = self.scan("repair", project)
        self.assert_json(result, payload, [row for row in expected if row[0] != repaired.name], files=3)
        self.assert_cache("repair", 2, 1)

    def test_selection_category_and_scoped_suppression(self):
        selected = tuple(case for case in CASES if case.name in {"inline_empty", "inline_bare_return", "delegating_server"})
        project, _ = self.fixture(selected)
        result, payload = self.scan("category-skip", project, meta=True, extra=("--skip-java=4",))
        self.assert_json(result, payload, [], meta=True, files=3)
        selection = self.artifact / "selected-files"
        selection.write_bytes(os.fsencode(project / "Case_delegating_server.java") + b"\0")
        result, payload = self.scan("selected", project, extra=("--files-from", str(selection)))
        self.assert_json(result, payload, [], files=1)
        result, payload = self.scan("ignored", project, meta=True,
                                    extra=("--exclude=Case_inline_empty.java,Case_inline_bare_return.java",))
        self.assert_json(result, payload, [], meta=True, files=1)
        original = next(case for case in CASES if case.name == "inline_empty")
        suppressed = Case("suppressed", original.body.replace("// TRUST_INSTALL", "// ubs:ignore[" + RULE + "]"), False)
        project, expected = self.fixture((suppressed,))
        # Existing fixtures are deliberately retained: only the selected source is scanned.
        result, payload = self.scan("suppressed", project / "Case_suppressed.java")
        self.assert_json(result, payload, expected, files=1)

    def test_limits_partial_and_recovery(self):
        ordinary = next(case for case in CASES if case.name == "inline_empty")
        budget = Case("budget", ordinary.body.replace("context.init", ";" * 800 + "\ncontext.init"), True)
        project, expected = self.fixture((ordinary, budget))
        retained = [row for row in expected if row[0] == "Case_inline_empty.java"]

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

        self.assertIn("token budget", partial("limited", {"UBS_JAVA_TLS_MAX_TOKENS": "200"}))
        result, payload = self.scan("recovery", project, meta=True, no_ast=True)
        self.assert_json(result, payload, expected, meta=True, files=2)
        self.assertIn("token budget", partial("limited-warm", {"UBS_JAVA_TLS_MAX_TOKENS": "200"}))
        (project / "Case_budget.java").write_text(budget.source.rstrip()[:-1] + "\n", encoding="utf-8")
        self.assertIn("Unbalanced Java TLS source", partial("malformed"))
        result, payload = self.scan("disabled-invalid-policy", project, meta=True, no_ast=True,
                                    extra=("--skip-java=4",), environment={"UBS_JAVA_TLS_MAX_TOKENS": "invalid"})
        self.assert_json(result, payload, [], meta=True, files=2)


if __name__ == "__main__":
    unittest.main()
