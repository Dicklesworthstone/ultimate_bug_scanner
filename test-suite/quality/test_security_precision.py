#!/usr/bin/env python3
"""Precision regressions for security detectors and native rule packs.

Each false positive from the report is pinned by a clean fixture and paired
with the true positives the rule exists for:

* JS ``js.security.hardcoded-secrets`` — SCREAMING_SNAKE error/enum codes
  (``CREDENTIALS: 'E_CREDENTIALS'``) are not secrets; real literals, uppercase
  keys, ``Object.freeze`` wrappers and ``E_*`` env fallbacks still are.
* Python yaml Loader classification — SafeLoader subclasses (trivial, or with a
  strict mapping constructor) are safe; ``Loader``/``UnsafeLoader``/``FullLoader``/
  ``None``, python/ tag registrations, eval-ing constructors and reassuring
  class names stay critical; imported/dynamic loaders are reported for review.
  The no-Loader shape is covered by ``py.yaml-unsafe`` (ast-grep, when the
  binary is available) and the category-7 regex.
* Python ``python.ctcompare.secret_eq`` — an unkeyed hashlib digest of public
  bytes checked against a public manifest is an integrity check; keyed MACs,
  hashes of secrets, secret-fed hash objects and unresolved receivers stay
  reported. The clean fixture's runtime contract (accept intact, reject
  modified) is executed here so it cannot be weakened to please the scanner.
* Java hardcoded secrets require literal assignments; blocking Future calls
  require scoped receiver evidence and an applicable exception handler.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import ctcompare_py  # noqa: E402
from ubs_core.analyzers import ctcompare_rust  # noqa: E402
from ubs_core.analyzers import sec_hardcoded_secrets  # noqa: E402
from ubs_core.py_detectors import unsafe_deserialization  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS  # noqa: E402
from ubs_core.py_rules import _RULES  # noqa: E402
from ubs_core.py_scan import iter_matches  # noqa: E402
from ubs_core.rust_detectors import jwt_verification  # noqa: E402
from ubs_core.rust_detectors import security_randomness  # noqa: E402
from ubs_core.rust_detectors import (  # noqa: E402
    host_header_url, open_redirect, request_regex, request_url,
    response_header, sql_injection,
)
from ubs_core import rust_rules  # noqa: E402

JS_SECURITY = REPO_ROOT / "test-suite" / "js" / "security"
PY_SECURITY = REPO_ROOT / "test-suite" / "python" / "security"


class JavaRulePrecisionTests(unittest.TestCase):
    """Exercise generated Java rules and the public module on real sources."""

    FUTURE_RULE = "java.async.future-get-no-try"
    SECRET_RULE = "java.secrets.string-decl"  # ubs:ignore[py.security.hardcoded-secrets] — public diagnostic rule ID, not a secret
    LITERAL_RULE = "java.secrets.hardcoded"
    POSITIVE = """import java.util.concurrent.*;
import java.util.*;
class Positive {
    Future<String> fieldFuture;
    void secrets() {
        String apiToken = "literal-credential-value"; // secret:token
        String PASSWORD = "literal-password-value"; // secret:password
    }
    void local() throws Exception {
        Future<String> pending = CompletableFuture.completedFuture("ready");
        pending.get(); // future:local
        pending.get(1, TimeUnit.SECONDS); // future:timed
    }
    void parameter(Future<String> pending) throws Exception {
        pending.get(); // future:parameter
    }
    void qualified(java.util.concurrent.CompletableFuture<String> pending) {
        pending.join(); // future:qualified
    }
    void fields() throws Exception {
        fieldFuture.get(); // future:field
        this.fieldFuture.get(); // future:explicit_field
    }
    void factories() throws Exception {
        CompletableFuture.supplyAsync(() -> "ready").get(); // future:factory
        CompletableFuture.completedFuture("ready").copy().join(); // future:factory_chain
        new CompletableFuture<String>().get(); // future:constructor
        var inferred = CompletableFuture.completedFuture("ready");
        inferred.get(); // future:inferred
        CompletableFuture<String> typed = CompletableFuture.completedFuture("ready");
        typed.copy().join(); // future:typed_chain
    }
    void capturedParameter(Future<String> pending) {
        Callable<String> work = () -> pending.get(); // future:captured_parameter
    }
    void capturedLocal() {
        Future<String> pending = CompletableFuture.completedFuture("ready");
        Callable<String> work = () -> pending.get(); // future:captured_local
    }
    void delayed(CompletableFuture<String> pending) {
        try {
            Runnable work = () -> pending.join(); // future:delayed
        } catch (Exception error) {}
    }
    void wrongGetCatch(Future<String> pending) throws ExecutionException {
        try {
            pending.get(); // future:wrong_get_catch
        } catch (InterruptedException error) {}
    }
    void wrongJoinCatch(CompletableFuture<String> pending) {
        try {
            pending.join(); // future:wrong_join_catch
        } catch (IllegalArgumentException error) {}
    }
    void catchBody(Future<String> pending) throws Exception {
        try { throw new IllegalArgumentException(); }
        catch (Exception error) {
            pending.get(); // future:catch_body
        }
    }
    void loops(List<Future<String>> tasks) throws Exception {
        for (Future<String> pending : tasks) {
            pending.get(); // future:enhanced_loop
        }
        for (Future<String> pending = tasks.get(0); pending != null; pending = null) {
            pending.get(); // future:basic_loop
        }
    }
}
"""
    NEGATIVE = """import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.io.*;
class Negative {
    Future<String> fieldFuture;
    void ordinary(Optional<String> maybe, String configured) {
        String greeting = "hello";
        String url = "https://example.invalid";
        String apiToken = System.getenv("API_TOKEN");
        String PASSWORD = configured;
        if (maybe.isPresent()) {
            String present = maybe.get();
        }
    }
    void unrelated(Supplier<String> pending, Map<String, String> lookup) {
        pending.get();
        lookup.get("key");
    }
    void otherMethod(Future<String> pending) {}
    void localShadow() {
        Supplier<String> fieldFuture = () -> "ready";
        fieldFuture.get();
    }
    void parameterShadow(Supplier<String> fieldFuture) {
        fieldFuture.get();
        Runnable work = () -> { fieldFuture.get(); };
    }
    void mapCapture(Map<String, String> fieldFuture) {
        Runnable work = () -> { fieldFuture.get("key"); };
    }
    void lambdaShadow() {
        Function<Supplier<String>, String> first = fieldFuture -> fieldFuture.get();
        Function<Supplier<String>, String> second = (fieldFuture) -> fieldFuture.get();
        Function<Supplier<String>, String> third = (Supplier<String> fieldFuture) -> fieldFuture.get();
    }
    void loopShadow(List<Supplier<String>> sources) {
        for (Supplier<String> fieldFuture : sources) { fieldFuture.get(); }
        for (Supplier<String> fieldFuture = sources.get(0); fieldFuture != null; fieldFuture = null) {
            fieldFuture.get();
        }
    }
    void expiredLocal() {
        { Future<String> pending = CompletableFuture.completedFuture("ready"); }
        Supplier<String> pending = () -> "ready";
        pending.get();
    }
    void nestedClass() {
        class Inner {
            Supplier<String> fieldFuture;
            void run() { fieldFuture.get(); }
        }
    }
    void handled(Future<String> pending, CompletableFuture<String> complete) throws Exception {
        try { pending.get(); } catch (ExecutionException error) {}
        try { pending.get(); } catch (InterruptedException | ExecutionException error) {}
        try { complete.join(); } catch (CompletionException error) {}
        try { complete.join(); } catch (RuntimeException error) {}
        try { complete.join(); } catch (java.lang.Exception error) {}
        complete.handle((value, error) -> "recovered").join();
        complete.exceptionally(error -> "recovered").get();
    }
    void handledResource(Future<InputStream> pending) {
        try (InputStream stream = pending.get()) {} catch (Exception error) {}
    }
}
"""
    FUTURE_ANCHORS = {
        "local": "pending.get()", "timed": "pending.get(1, TimeUnit.SECONDS)",
        "parameter": "pending.get()", "qualified": "pending.join()",
        "field": "fieldFuture.get()", "explicit_field": "this.fieldFuture.get()",
        "factory": 'CompletableFuture.supplyAsync(() -> "ready").get()',
        "factory_chain": 'CompletableFuture.completedFuture("ready").copy().join()',
        "constructor": "new CompletableFuture<String>().get()", "inferred": "inferred.get()",
        "typed_chain": "typed.copy().join()", "captured_parameter": "pending.get()",
        "captured_local": "pending.get()", "delayed": "pending.join()",
        "wrong_get_catch": "pending.get()", "wrong_join_catch": "pending.join()",
        "catch_body": "pending.get()", "enhanced_loop": "pending.get()",
        "basic_loop": "pending.get()",
    }

    def setUp(self) -> None:
        from ubs_core import java_rules

        self.assertIsNotNone(shutil.which("ast-grep"), "Java precision regression requires real ast-grep")
        self.temp = tempfile.TemporaryDirectory(prefix="ubs_java_precision_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.positive = self.project / "Positive.java"
        self.negative = self.project / "Negative.java"
        self.positive.write_text(self.POSITIVE, encoding="utf-8")
        self.negative.write_text(self.NEGATIVE, encoding="utf-8")
        self.rules = self.root / "rules"
        self.manifest = java_rules.generate(self.rules)

    def _process(self, command: list[str], *, no_ast: bool = False) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                   UBS_CACHE_DIR=str(self.root / ("fallback-cache" if no_ast else "cache")),
                   UBS_CACHE_FILE=str(self.root / "cache-stats.json"), UBS_PROFILE="1",
                   UBS_TEST_FORCE_NO_AST_GREP=str(int(no_ast)), NO_COLOR="1")
        proc = subprocess.run(command, cwd=self.root, env=env, text=True,
                              capture_output=True, timeout=180)
        self.assertIn(proc.returncode, (0, 1), f"{command!r}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
        return proc

    def _json(self, proc: subprocess.CompletedProcess[str]) -> dict | list:
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"invalid Java scanner JSON: {exc}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")

    def _cache_counts(self, proc: subprocess.CompletedProcess[str], hits: int, misses: int) -> None:
        context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
        try:
            stats = json.loads((self.root / "cache-stats.json").read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self.fail(f"invalid Java scanner cache statistics: {exc}; {context}")
        self.assertEqual((stats["hits"], stats["misses"]), (hits, misses), context)

    def _expected(self, rule: str) -> list[tuple[str, int, int]]:
        if rule == self.FUTURE_RULE:
            anchors = {f"future:{tag}": code for tag, code in self.FUTURE_ANCHORS.items()}
        else:
            anchors = {"secret:token": "String apiToken", "secret:password": "String PASSWORD"}
        sites = []
        for tag, code in anchors.items():
            matches = [(number, line) for number, line in enumerate(self.POSITIVE.splitlines(), 1)
                       if line.endswith(f"// {tag}")]
            self.assertEqual(len(matches), 1, tag)
            number, line = matches[0]
            sites.append((str(self.positive), number, 1 if rule == self.LITERAL_RULE else line.index(code) + 1))
        return sorted(sites)

    def test_generated_rules_require_literals_and_scoped_future_evidence(self) -> None:
        for rule in (self.SECRET_RULE, "java.hardcoded-secrets", self.FUTURE_RULE):
            with self.subTest(rule=rule):
                proc = self._process(["ast-grep", "scan", "--rule",
                                      str(self.rules / self.manifest[rule]["file"]),
                                      "--json", str(self.positive), str(self.negative)])
                records = self._json(proc)
                actual = []
                for record in records:
                    self.assertEqual(record["ruleId"], rule)
                    self.assertEqual(record["severity"], "warning")
                    start = record["range"]["start"]
                    actual.append((str((self.root / record["file"]).resolve()),
                                   start["line"] + 1, start["column"] + 1))
                self.assertEqual(sorted(actual), self._expected(rule), proc.stdout + proc.stderr)

    def test_public_module_json_sarif_cache_and_literal_fallback_precision(self) -> None:
        rules = (self.SECRET_RULE, self.LITERAL_RULE, self.FUTURE_RULE)

        def scan(paths: list[Path], output_format: str, hits: int, *, positive: bool,
                 no_ast: bool = False) -> list[tuple]:
            inputs = self.root / "inputs"
            inputs.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
            proc = self._process([str(REPO_ROOT / "modules/ubs-java.sh"), "--no-build", "--ci",
                                  "--no-color", "--fail-on-warning", "--only=3,21",
                                  f"--format={output_format}", "--files-from", str(inputs),
                                  str(self.project)], no_ast=no_ast)
            context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
            self.assertEqual(proc.returncode, int(positive), context)
            payload = self._json(proc)
            self._cache_counts(proc, hits, len(paths) - hits)
            expected = sorted((rule, *site, "warning") for rule in rules
                              if positive and (not no_ast or rule == self.LITERAL_RULE)
                              for site in self._expected(rule))
            expected_ast = [site for site in expected if site[0] != self.LITERAL_RULE]
            actual = []
            if output_format == "json":
                self.assertEqual(payload["status"], "ok", context)
                self.assertEqual(payload["critical"], 0, context)
                self.assertEqual(payload["warning"], len(expected), context)
                self.assertEqual(payload["info"], 0, context)
                for record in payload["findings"]:
                    actual.append((record["rule"], str((self.root / record["path"]).resolve()),
                                   record["line"], record["col"], record["severity"]))
                self.assertEqual(sorted((record["rule"], str((self.root / record["path"]).resolve()),
                                         record["line"], record["col"], record["severity"])
                                        for record in payload["extras"]["ast_findings"]), expected_ast, context)
            else:
                self.assertEqual(payload["version"], "2.1.0", context)
                by_driver = {}
                for run in payload["runs"]:
                    driver = run["tool"]["driver"]["name"]
                    self.assertNotIn(driver, by_driver, context)
                    run_sites = []
                    for result in run.get("results", []):
                        self.assertEqual(result["level"], "warning", context)
                        self.assertEqual(len(result["locations"]), 1, context)
                        location = result["locations"][0]["physicalLocation"]
                        region = location["region"]
                        run_sites.append((result["ruleId"], str((self.root / location["artifactLocation"]["uri"]).resolve()),
                                          region["startLine"], region["startColumn"], "warning"))
                    by_driver[driver] = sorted(run_sites)
                # SARIF keeps the original AST evidence in a separate run,
                # including counted AST sites already present in heuristics.
                self.assertEqual(by_driver, {"ubs-java-heuristics": expected,
                                             "ubs-java-ast": expected_ast}, context)
                actual = by_driver["ubs-java-heuristics"]
            self.assertEqual(sorted(actual), expected, context)
            return sorted(actual)

        paths = [self.positive, self.negative]
        cold = scan(paths, "json", 0, positive=True)
        self.assertEqual(scan(paths, "sarif", 2, positive=True), cold)
        scan([self.negative], "json", 1, positive=False)
        self.positive.write_text(self.NEGATIVE.replace("class Negative", "class Positive"), encoding="utf-8")
        scan(paths, "json", 1, positive=False)
        scan(paths, "sarif", 2, positive=False)
        self.positive.write_text(self.POSITIVE, encoding="utf-8")
        scan(paths, "json", 0, positive=True, no_ast=True)
        scan([self.negative], "json", 1, positive=False, no_ast=True)

    def test_optional_category_filter_preserves_enabled_json_sarif_and_text(self) -> None:
        optional_rule = "java.optional-isPresent-then-get"
        detector_rule = "java.null-optional.optional-get"
        inputs = self.root / "inputs"
        inputs.write_bytes(os.fsencode(self.negative) + b"\0")
        for categories, enabled in (("1", True), ("3,21", False)):
            for index, output_format in enumerate(("json", "sarif", "text")):
                with self.subTest(categories=categories, output_format=output_format):
                    proc = self._process([
                        str(REPO_ROOT / "modules/ubs-java.sh"), "--no-build", "--ci", "--no-color",
                        "--fail-on-warning", f"--only={categories}", f"--format={output_format}",
                        "--files-from", str(inputs), str(self.project),
                    ])
                    context = f"stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                    self.assertEqual(proc.returncode, int(enabled), context)
                    self._cache_counts(proc, int(index > 0), int(index == 0))
                    expected_info = [(optional_rule, str(self.negative), 12, 9, "info")] if enabled else []
                    # The separate legacy Optional.get detector remains a
                    # warning even for this guarded call; retain its exact
                    # source alongside the AST style recommendation.
                    expected = sorted(expected_info + (
                        [(detector_rule, str(self.negative), 13, 1, "warning")] if enabled else []))
                    if output_format == "text":
                        self.assertIn("Critical issues: 0", proc.stdout, context)
                        self.assertIn(f"Warning issues: {int(enabled)}", proc.stdout, context)
                        self.assertIn(f"Info items: {int(enabled)}", proc.stdout, context)
                        if enabled:
                            self.assertEqual(proc.stdout.count("1. NULL & OPTIONAL PITFALLS"), 1, context)
                            self.assertIn(f"{self.negative}:12", proc.stdout, context)
                            self.assertIn(f"{self.negative}:13", proc.stdout, context)
                            self.assertIn(optional_rule, proc.stdout, context)
                            self.assertIn(detector_rule, proc.stdout, context)
                            self.assertLess(proc.stdout.index("1. NULL & OPTIONAL PITFALLS"),
                                            proc.stdout.index(optional_rule), context)
                        else:
                            self.assertNotIn("1. NULL & OPTIONAL PITFALLS", proc.stdout, context)
                            self.assertNotIn(optional_rule, proc.stdout, context)
                            self.assertNotIn(detector_rule, proc.stdout, context)
                        self.assertNotIn("15. AST-GREP RULE PACK FINDINGS", proc.stdout.upper(), context)
                        continue
                    payload = self._json(proc)
                    if output_format == "json":
                        self.assertEqual(payload["status"], "ok", context)
                        self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                         (0, int(enabled), int(enabled)), context)
                        self.assertEqual(sorted((record["rule"], record["path"], record["line"],
                                                 record["col"], record["severity"])
                                                for record in payload["findings"]), expected, context)
                        self.assertEqual([(record["rule"], record["path"], record["line"],
                                           record["col"], record["severity"])
                                          for record in payload["extras"]["ast_findings"]], expected_info, context)
                        for record in payload["extras"]["ast_findings"]:
                            self.assertEqual(record["category_id"], 1, context)
                    else:
                        self.assertEqual(payload["version"], "2.1.0", context)
                        by_driver = {}
                        for run in payload["runs"]:
                            driver = run["tool"]["driver"]["name"]
                            self.assertNotIn(driver, by_driver, context)
                            sites = []
                            for result in run.get("results", []):
                                self.assertEqual(len(result["locations"]), 1, context)
                                location = result["locations"][0]["physicalLocation"]
                                region = location["region"]
                                self.assertIn(result["level"], ("note", "warning"), context)
                                sites.append((result["ruleId"], location["artifactLocation"]["uri"],
                                              region["startLine"], region["startColumn"],
                                              "info" if result["level"] == "note" else "warning"))
                            by_driver[driver] = sorted(sites)
                        self.assertEqual(by_driver, {"ubs-java-heuristics": expected,
                                                     "ubs-java-ast": expected_info}, context)


class PublicScopedSuppressionTests(unittest.TestCase):
    """Real module reports must agree on scoped sites, counts, and exit status."""

    CASES = {
        "cpp": ("cpp", "3", [], "#include <mutex>\nvoid check(std::mutex &m) {\n", "}\n",
                "m.lock();", 'const char *note = "{marker}"; ',
                (("cpp.concurrency.manual-lock", "warning"),), "cpp.raw-new"),
        "rust": ("rs", "1,23", [], "fn check(raw: &str) {\n", "}\n",
                 "let parsed: i32 = raw.parse().unwrap();", 'let note = "{marker}"; ',
                 (("rust.ownership.unwrap-expect", "warning"),
                  ("rust.parsing.parse-unwrap", "warning")), "rust.panic.assert-macros"),
        "java": ("java", "19", ["--no-build"],
                 "import java.sql.*;\nclass Case {\n void check(Connection conn) throws SQLException {\n",
                 " }\n}\n", "Statement handle{index} = conn.createStatement();",
                 'String note = "{marker}"; ',
                 (("java.resource.statement-no-close", "warning"),), "java.optional-isPresent-then-get"),
        "swift": ("swift", "1,11", [], "func check() throws {\n", "}\n",
                  "let value{index} = try! operation()", 'let note = "{marker}"; ',
                  (("swift.force-try", "warning"), ("swift.optionals.try-bang", "warning"),
                   ("swift.optionals.force-some", "info")), "swift.force-cast"),
        "csharp": ("cs", "3,17", ["--no-dotnet"],
                   "using System.Threading;\nclass Case {\n void Check() {\n", " }\n}\n",
                   "Thread.Sleep(5);", 'string note = "{marker}"; ',
                   (("cs.pattern.thread-sleep", "warning"), ("cs-thread-sleep", "warning")),
                   "cs-md5-create"),
    }

    def _exercise(self, language: str) -> None:
        self.assertIsNotNone(shutil.which("ast-grep"), "public suppression regression requires real ast-grep")
        suffix, categories, flags, opening, closing, statement, literal, rules, wrong = self.CASES[language]
        with tempfile.TemporaryDirectory(prefix=f"ubs_{language}_public_scope_") as td:
            root = Path(td)
            project = root / "project"
            project.mkdir()
            marker = "ubs:ignore"
            all_scope = marker + "[" + ",".join(rule for rule, _ in rules) + "]"
            variants = ("wrong", "unknown", "literal", "baseline", "above", "trailing", "bare", "selective")
            expected: list[tuple[str, str, int, str]] = []
            paths = []
            sources = {}
            for index, variant in enumerate(variants):
                path = project / f"{index:02d}_{variant}.{suffix}"
                paths.append(path)
                body = []
                if variant == "above":
                    body.append("    // " + all_scope)
                code = statement.format(index=index)
                if variant == "literal":
                    # Both a bare token and a valid matching scope are ordinary
                    # string contents on the actual hazardous source line.
                    code = literal.format(marker=marker + " " + all_scope) + code
                scope = {
                    "wrong": marker + "[" + wrong + "]",
                    "unknown": marker + "[unknown.public.rule]",
                    "trailing": all_scope,
                    "bare": marker,
                    "selective": marker + "[" + rules[0][0] + "]",
                }.get(variant)
                body.append("    " + code + (" // " + scope if scope else ""))
                line = len(opening.splitlines()) + len(body)
                retained = rules if variant in ("wrong", "unknown", "literal", "baseline") else (
                    rules[1:] if variant == "selective" else ())
                expected.extend((rule, str(path), line, severity) for rule, severity in retained)
                if variant == "above":
                    # The comment belongs to the first statement. A following
                    # unmarked statement remains a real positive control.
                    body.append("    " + statement.format(index="adjacent"))
                    expected.extend((rule, str(path), line + 1, severity) for rule, severity in rules)
                header = opening.replace("class Case", f"class Case{index}")
                if language == "swift":
                    header = header.replace("func check", f"func check{index}")
                source = header + "\n".join(body) + "\n" + closing
                path.write_text(source, encoding="utf-8")
                sources[variant] = source
            if language == "swift":
                control = project / "08_print.swift"
                control.write_text('func trace() {\n    print("retained control")\n}\n', encoding="utf-8")
                paths.append(control)
                expected.extend((rule, str(control), 2, "info")
                                for rule in ("swift.print-call", "swift.debug.print-minimal"))

            scan_sequence = 0

            def scan(selected: list[Path], output_format: str,
                     sites: list[tuple[str, str, int, str]], hits: int, *, meta: bool = False) -> list[tuple]:
                nonlocal scan_sequence
                scan_sequence += 1
                inputs = root / "inputs"
                inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                stats_file = root / "cache-stats.json"
                records_file = root / f"findings-{scan_sequence}.ndjson"
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                           UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats_file),
                           UBS_PROFILE="1", UBS_SKIP_TYPE_NARROWING="1",
                           UBS_TEST_FORCE_NO_AST_GREP="0", NO_COLOR="1")
                command = [str(REPO_ROOT / "modules" / f"ubs-{language}.sh"), "--ci", "--no-color",
                           "--fail-on-warning", f"--only={categories}", f"--format={output_format}",
                           "--files-from", str(inputs), *flags, str(project)]
                if language == "rust" and output_format == "json":
                    # Rust's public JSON stdout is a summary; this public
                    # option retains the actual source findings separately.
                    command.insert(-1, f"--report-json={records_file}")
                if meta:
                    self.assertEqual(output_format, "text")
                    self.assertTrue(selected == paths or len(selected) == 1)
                    skip = ",".join(str(category) for category in range(1, 25)
                                    if str(category) not in categories.split(","))
                    command = [str(REPO_ROOT / "ubs"), "--ci", "--no-color", "--no-auto-update",
                               "--fail-on-warning", f"--only={language}", f"--skip-{language}={skip}",
                               "--format=text", *flags,
                               str(selected[0] if len(selected) == 1 else project)]
                proc = subprocess.run(command, cwd=root, env=env, text=True,
                                      capture_output=True, timeout=180)
                context = f"{command!r}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                totals = {severity: sum(site[3] == severity for site in sites)
                          for severity in ("critical", "warning", "info")}
                self.assertEqual(proc.returncode, int(totals["critical"] + totals["warning"] > 0), context)
                if not meta:
                    try:
                        stats = json.loads(stats_file.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError) as exc:
                        self.fail(f"invalid public suppression cache statistics: {exc}; {context}")
                    self.assertEqual((stats["hits"], stats["misses"]), (hits, len(selected) - hits), context)
                if output_format == "text":
                    text = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
                    for severity, label in (("critical", "Critical issues"),
                                            ("warning", "Warning issues"), ("info", "Info items")):
                        self.assertRegex(text, rf"{label}:\s+{totals[severity]}\b", context)
                    # Renderers deliberately cap previews. Every preview must
                    # still identify a retained finding using trusted metadata.
                    printed = []
                    location = (rf"(?P<path>\S+\.{suffix}):(?P<line>\d+)(?::\d+)?:?\s+"
                                r"\[rule:(?P<rule>[A-Za-z0-9_.:-]+)\]")
                    for match in re.finditer(location, text):
                        site = (match["rule"], str((root / match["path"]).resolve()), int(match["line"]))
                        self.assertIn(site, [item[:3] for item in sites], context)
                        printed.append(site)
                    if sites:
                        self.assertTrue(printed, context)
                        self.assertIn(rules[0][0], {site[0] for site in printed}, context)
                        if meta and (language != "swift" or len(selected) == 1):
                            # Swift's AST traversal order is independent of
                            # input order. Its three preview controls each get
                            # a separate real meta scan below, so a preview cap
                            # cannot hide lost wrong/unknown/literal findings.
                            controls = {str(paths[variants.index(name)])
                                        for name in ("wrong", "unknown", "literal")}
                            for site in sites:
                                if site[0] == rules[0][0] and site[1] in controls:
                                    self.assertIn(site[:3], printed, context)
                    else:
                        self.assertEqual(printed, [], context)
                        for path in selected:
                            self.assertNotRegex(text, re.escape(path.name) + r":\d+", context)
                    return printed
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"invalid public suppression report: {exc}; {context}")
                if output_format == "json":
                    self.assertEqual(payload["status"], "ok", context)
                    self.assertEqual({severity: payload[severity] for severity in totals}, totals, context)
                    if language == "rust":
                        try:
                            records = [json.loads(line) for line in
                                       records_file.read_text(encoding="utf-8").splitlines()]
                        except (json.JSONDecodeError, OSError) as exc:
                            self.fail(f"invalid Rust public source findings: {exc}; {context}")
                    else:
                        records = payload["findings"]
                    actual = []
                    for record in records:
                        self.assertIs(type(record["col"]), int, context)
                        self.assertGreaterEqual(record["col"], 1, context)
                        self.assertEqual(record.get("count", 1), 1, context)
                        actual.append((record["rule"], str((root / record["path"]).resolve()),
                                       record["line"], record["severity"], record["col"]))
                    self.assertEqual(sorted(item[:4] for item in actual), sorted(sites), context)
                    return sorted(actual)
                self.assertEqual(payload["version"], "2.1.0", context)
                by_driver = {}
                for run in payload["runs"]:
                    driver = run["tool"]["driver"]["name"]
                    self.assertNotIn(driver, by_driver, context)
                    actual = []
                    for record in run.get("results", []):
                        self.assertEqual(len(record["locations"]), 1, context)
                        loc = record["locations"][0]["physicalLocation"]
                        actual.append((record["ruleId"], str((root / loc["artifactLocation"]["uri"]).resolve()),
                                       loc["region"]["startLine"],
                                       "info" if record["level"] == "note" else record["level"],
                                       loc["region"]["startColumn"]))
                    self.assertEqual(sorted(item[:4] for item in actual), sorted(sites), context)
                    by_driver[driver] = sorted(actual)
                drivers = {f"ubs-{language}"} if language != "java" else {
                    "ubs-java-heuristics", "ubs-java-ast"}
                self.assertEqual(set(by_driver), drivers, context)
                return next(iter(by_driver.values()))

            cold = scan(paths, "json", expected, 0)
            self.assertEqual(scan(paths, "json", expected, len(paths)), cold)
            self.assertEqual(scan(paths, "sarif", expected, len(paths)), cold)
            scan(paths, "text", expected, len(paths))
            scan(paths, "text", expected, len(paths), meta=True)
            if language == "swift":
                for name in ("wrong", "unknown", "literal"):
                    selected = paths[variants.index(name)]
                    sites = [site for site in expected if site[1] == str(selected)]
                    scan([selected], "text", sites, 1, meta=True)
            suppressed = [paths[variants.index(name)] for name in ("trailing", "bare")]
            for output_format in ("json", "sarif", "text"):
                scan(suppressed, output_format, [], len(suppressed))
            wrong_path = paths[variants.index("wrong")]
            wrong_path.write_text(sources["wrong"].replace(marker + "[" + wrong + "]", all_scope),
                                  encoding="utf-8")
            partial_sites = [site for site in expected if site[1] != str(wrong_path)]
            partial = scan(paths, "json", partial_sites, len(paths) - 1)
            self.assertEqual(scan(paths, "sarif", partial_sites, len(paths)), partial)

    def test_cpp_public_rule_scopes(self) -> None:
        self._exercise("cpp")

    def test_rust_public_rule_scopes(self) -> None:
        self._exercise("rust")

    def test_java_public_rule_scopes(self) -> None:
        self._exercise("java")

    def test_swift_public_rule_scopes_and_unmarked_prints(self) -> None:
        self._exercise("swift")

    def test_csharp_public_rule_scopes_preserve_independent_ast_findings(self) -> None:
        self._exercise("csharp")


class NativeSourceIdentityTests(unittest.TestCase):
    def scan(self, root: Path, language: str, paths: list[Path], extra_args: list[str],
             expected: dict[str, list[tuple[Path, int, int, str]]], hits: int) -> list[dict]:
        sink = root / "identity.ndjson"
        stats = root / "identity-cache.json"
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats))
        proc = subprocess.run(
            [sys.executable, "-m", f"ubs_core.{language}_scan", "--files-from", "-",
             "--sink", str(sink), "--project-dir", str(root / "project"),
             "--fail-on-warning", *extra_args],
            input="\0".join(str(path) for path in paths) + "\0", cwd=root, env=env,
            text=True, capture_output=True, timeout=180,
        )
        context = f"{language} paths={paths}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
        owners = {source for sites in expected.values() for source, _, _, _ in sites}
        self.assertEqual(proc.returncode, int(bool(owners)), context)
        self.assertTrue(sink.is_file(), context)
        self.assertTrue(stats.is_file(), context)
        try:
            records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
            cache_stats = json.loads(stats.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"invalid native scanner output: {exc}; {context}")
        self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                         (hits, len(paths) - hits), context)
        actual: dict[str, list[tuple[Path, int, int, str]]] = {rule: [] for rule in expected}
        for record in records:
            source = (root / record["path"]).resolve()
            self.assertIn(source, owners, context)
            if record["rule"] in actual:
                actual[record["rule"]].append((source, record["line"], record["col"], record["severity"]))
        self.assertEqual({rule: sorted(sites) for rule, sites in actual.items()},
                         {rule: sorted(sites) for rule, sites in expected.items()}, context)
        if not owners:
            self.assertEqual(records, [], context)
        return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                   record["line"], record["col"]))

    def test_generated_ast_paths_keep_distinct_same_display_sources(self) -> None:
        from ubs_core import csharp_rules, elixir_rules

        cases = (
            ("csharp", csharp_rules, ".cs", 17, "cs-md5-create", "warning", 3, 9,
             "class Example {\n    void Run() {\n        MD5.Create();\n    }\n}\n",
             "class Example {\n    void Run() {\n        MD5.Create();\n        MD5.Create();\n    }\n}\n",
             "class Clean {}\n"),
            ("elixir", elixir_rules, ".ex", 4, "elixir.code-eval-string", "critical", 1, 1,
             "Code.eval_string(input)\n", "Code.eval_string(input)\nCode.eval_string(input)\n",
             "value = 42\n"),
        )
        for language, pack, suffix, category, rule, severity, line, col, hazard, changed, clean in cases:
            with self.subTest(language=language), tempfile.TemporaryDirectory(prefix="ubs_ast_source_identity_") as td:
                root = Path(td)
                outside = Path(f"outside/Case{suffix}")
                inside = Path(f"project/outside/Case{suffix}")
                clean_paths = [Path(f"Clean{suffix}"), Path(f"project/Clean{suffix}")]
                for path, source in ((outside, hazard), (inside, hazard),
                                     *((path, clean) for path in clean_paths)):
                    (root / path).parent.mkdir(parents=True, exist_ok=True)
                    (root / path).write_text(source, encoding="utf-8")
                rules = root / "rules"
                manifest = pack.generate(rules)
                self.assertIn(rule, manifest)
                extra = ["--ast-rule-dir", str(rules), "--skip",
                         ",".join(str(n) for n in range(1, 25) if n != category)]
                paths = [outside, inside, *clean_paths]
                # Before canonical dedup, both positives were "outside/Case"
                # despite denoting different source files at the same site.
                expected = {rule: [(root / outside, line, col, severity),
                                   (root / inside, line, col, severity)]}
                cold = self.scan(root, language, paths, extra, expected, 0)
                self.assertEqual(self.scan(root, language, paths, extra, expected, 4), cold)
                self.scan(root, language, clean_paths, extra, {rule: []}, 2)
                for source in (outside, inside):
                    subset = self.scan(root, language, [source], extra,
                                       {rule: [(root / source, line, col, severity)]}, 1)
                    self.assertEqual(subset, [record for record in cold
                                              if (root / record["path"]).resolve() == root / source])
                (root / inside).write_text(changed, encoding="utf-8")
                expected[rule].append((root / inside, line + 1, col, severity))
                partial = self.scan(root, language, paths, extra, expected, 3)
                self.assertEqual(self.scan(root, language, paths, extra, expected, 4), partial)

    def test_rust_root_relative_detectors_ignore_existing_cwd_shadows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_source_identity_") as td:
            root = Path(td)
            positives = [Path("project/Same.rs"), Path("project/nested/Same.rs")]
            shadows = [Path("Same.rs"), Path("nested/Same.rs")]
            hazard = (
                "fn settings() {\n"
                '    let api_key = "abcd1234efgh5678";\n'
                "    let disabled = true;\n"
                "    client.danger_accept_invalid_certs(disabled);\n"
                "}\n"
            )
            for path in positives + shadows:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(hazard if path in positives else "fn clean() {}\n",
                                         encoding="utf-8")
            secrets = "rust.security.hardcoded-secrets"
            tls = "rust.security.tls-verification"
            expected = {
                secrets: [(root / path, 2, 1, "critical") for path in positives],
                tls: [(root / path, 4, 1, "critical") for path in positives],
            }
            extra = ["--skip-type-narrowing", "--quiet", "--skip",
                     ",".join(str(n) for n in range(1, 25) if n != 8)]
            paths = positives + shadows
            cold = self.scan(root, "rust", paths, extra, expected, 0)
            self.assertEqual(self.scan(root, "rust", paths, extra, expected, 4), cold)
            self.scan(root, "rust", shadows, extra, {secrets: [], tls: []}, 2)
            for path in positives:
                subset_expected = {rule: [site for site in sites if site[0] == root / path]
                                   for rule, sites in expected.items()}
                subset = self.scan(root, "rust", [path], extra, subset_expected, 1)
                self.assertEqual(subset, [record for record in cold
                                          if (root / record["path"]).resolve() == root / path])
            (root / positives[0]).write_text(hazard.replace("disabled = true", "disabled = false"),
                                             encoding="utf-8")
            expected[tls] = [site for site in expected[tls] if site[0] == root / positives[1]]
            partial = self.scan(root, "rust", paths, extra, expected, 3)
            self.assertEqual(self.scan(root, "rust", paths, extra, expected, 4), partial)


class CSharpSourcePathTests(unittest.TestCase):
    def test_outside_relative_detector_paths_do_not_transfer_to_project_shadow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_csharp_source_paths_") as td:
            root = Path(td)
            project = root / "project"
            outside = Path("outside/Case.cs")
            shadow = Path("project/outside/Case.cs")
            inside = Path("project/Inside.cs")
            hazard = 'var url = Request.Query["url"];\nclient.GetAsync(url);\n'
            for path, source in ((outside, hazard), (shadow, "class Safe {}\n"), (inside, hazard)):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(source, encoding="utf-8")
            sink = root / "findings.ndjson"
            stats = root / "cache.json"
            env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                       UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(stats))
            rule_id = "csharp.security.outbound-url"

            def scan(paths: list[Path], hits: int, expected: dict[Path, list[int]]) -> list[dict]:
                self.assertTrue(all(not path.is_absolute() for path in paths))
                proc = subprocess.run(
                    [sys.executable, "-m", "ubs_core.csharp_scan", "--sink", str(sink),
                     "--project-dir", str(project),
                     "--skip", ",".join(str(n) for n in range(1, 25) if n != 8)],
                    input="\0".join(str(path) for path in paths) + "\0",
                    cwd=root, env=env, text=True, capture_output=True, timeout=180,
                )
                context = f"paths={paths}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                self.assertEqual(proc.returncode, int(bool(expected)), context)
                self.assertTrue(sink.is_file(), context)
                self.assertTrue(stats.is_file(), context)
                try:
                    records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                    cache_stats = json.loads(stats.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    self.fail(f"invalid C# scanner output: {exc}; {context}")
                self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                                 (hits, len(paths) - hits), context)
                actual: dict[Path, list[int]] = {}
                for record in records:
                    source = (root / record["path"]).resolve()
                    self.assertIn(source, expected, context)
                    if record["rule"] == rule_id:
                        self.assertEqual(record["severity"], "critical", context)
                        self.assertEqual(record["col"], 1, context)
                        actual.setdefault(source, []).append(record["line"])
                self.assertEqual({path: sorted(lines) for path, lines in actual.items()}, expected, context)
                if not expected:
                    self.assertEqual(records, [], context)
                return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                           record["line"], record["col"]))

            outside_source = root / outside
            inside_source = root / inside
            paths = [outside, shadow, inside]
            expected = {outside_source: [2], inside_source: [2]}
            cold = scan(paths, 0, expected)
            self.assertEqual(scan(paths, 3, expected), cold)
            scan([shadow], 1, {})
            outside_records = [record for record in cold
                               if (root / record["path"]).resolve() == outside_source]
            self.assertEqual(scan([outside], 1, {outside_source: [2]}), outside_records)
            inside_records = [record for record in cold
                              if (root / record["path"]).resolve() == inside_source]
            self.assertEqual(scan([inside], 1, {inside_source: [2]}), inside_records)

            outside_source.write_text(hazard + "client.GetAsync(url);\n", encoding="utf-8")
            changed = {outside_source: [2, 3], inside_source: [2]}
            partial = scan(paths, 2, changed)
            self.assertEqual(scan(paths, 3, changed), partial)
            scan([shadow], 1, {})


class RustPanicContextTests(unittest.TestCase):
    """Use the actual scanner and ast-grep, never pre-populated AST hits."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs_panic_context_")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.rules = self.root / "rules"
        rust_rules.generate(self.rules)

    def package(self, name: str, extra: str = "", source: str = "tests/receipt.rs") -> Path:
        root = self.root / name
        root.mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "panic_context"\nversion = "0.1.0"\nedition = "2024"\n' + extra,
            encoding="utf-8",
        )
        target = root / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('fn receipt() { panic!("wire input receipt required") }\n', encoding="utf-8")
        return target

    def scan(self, paths: list[Path], *, fail_on_warning: bool = False,
             cache: bool = False, without_tomllib: bool = False,
             categories: tuple[int, ...] = (1,), ast: bool = True) -> tuple[int, dict]:
        inputs = self.root / "inputs"
        inputs.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
        output = self.root / "scan.json"
        args = [
            "--files-from", str(inputs), "--sink", str(self.root / "findings.ndjson"),
            "--project-dir", str(self.root),
            "--skip", ",".join(str(n) for n in range(1, 25) if n not in categories),
            "--skip-type-narrowing",
            "--quiet", "--json-out", str(output),
        ]
        if ast:
            args.extend(["--ast-rule-dir", str(self.rules)])
        if fail_on_warning:
            args.append("--fail-on-warning")
        command = [sys.executable, "-m", "ubs_core.rust_scan"]
        if without_tomllib:
            command = [sys.executable, "-c", (
                "import runpy,sys; sys.modules['tomllib']=None; "
                "runpy.run_module('ubs_core.rust_scan',run_name='__main__')"
            )]
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0" if cache else "1", UBS_CACHE_DIR=str(self.root / "cache"))
        result = subprocess.run(command + args, cwd=self.root, env=env,
                                text=True, capture_output=True, timeout=30)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        try:
            document = json.loads(output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"scanner returned invalid JSON: {exc}")
        return result.returncode, document

    def test_assertion_inventory_counts_each_macro_once(self) -> None:
        targets = [self.package(name) for name in ("first", "second")]
        for target in targets:
            target.write_text(
                "fn receipt() { assert!(true); assert_eq!(1, 1); }\n"
                "fn other() { assert_ne!(1, 2); }\n",
                encoding="utf-8",
            )
        code, doc = self.scan(targets, categories=(21,), fail_on_warning=True)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.panic.assert-macros"]
        self.assertEqual(code, 1)
        self.assertEqual(len(hits), 6)
        self.assertEqual(doc["warning"], 6)
        for target in targets:
            sites = [hit for hit in hits if Path(hit["path"]) == target]
            self.assertEqual(sorted(hit["line"] for hit in sites), [1, 1, 2])
            first_line = [hit["col"] for hit in sites if hit["line"] == 1]
            self.assertEqual(len(set(first_line)), 2)

    def test_assertion_inventory_retains_line_fallback_without_ast(self) -> None:
        target = self.package("fallback")
        target.write_text(
            "fn receipt() {\n    assert!(true);\n    assert_eq!(1, 1);\n"
            "    assert_ne!(1, 2);\n}\n",
            encoding="utf-8",
        )
        code, doc = self.scan([target], categories=(21,), ast=False, fail_on_warning=True)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.panic.assert-macros"]
        self.assertEqual(code, 1)
        self.assertEqual(sorted(hit["line"] for hit in hits), [2, 3, 4])
        self.assertEqual(doc["warning"], 3)

    def test_resource_aggregate_weights_survive_full_and_partial_cache_replay(self) -> None:
        first = self.package("aggregate_first", source="src/lib.rs")
        second = self.package("aggregate_second", source="src/lib.rs")
        first_source = (
            "fn launch() {\n"
            "    let first = std::thread::spawn(|| {});\n"
            "    let second = std::thread::spawn(|| {});\n"
            "    assert!(true);\n"
            "    assert_eq!(1, 1);\n"
            "}\n"
        )
        first.write_text(first_source, encoding="utf-8")
        second.write_text(
            "fn independent() {\n"
            "    std::thread::spawn(|| {});\n"
            "    std::thread::spawn(|| {});\n"
            "    std::thread::spawn(|| {});\n"
            "    assert!(true);\n"
            "    assert_ne!(1, 2);\n"
            "}\n",
            encoding="utf-8",
        )
        aggregate_rule = "rust.resource-lifecycle.thread_join"
        concrete_rule = "rust.panic.assert-macros"

        def scan_counts(expected: dict[Path, int], hits: int, misses: int) -> list[dict]:
            code, document = self.scan([first, second], categories=(19, 21), ast=False,
                                       cache=True, fail_on_warning=True)
            self.assertEqual(code, 1)
            self.assertEqual(document["status"], "ok")
            self.assertEqual(document["files"], 2)
            profile = document["extras"]["profile"]
            self.assertEqual((profile["cache_hits"], profile["cache_misses"]), (hits, misses))
            records = document["findings"]
            self.assertEqual({record["rule"] for record in records},
                             {aggregate_rule, concrete_rule})
            aggregates = [record for record in records if record["rule"] == aggregate_rule]
            self.assertEqual(len(aggregates), 2)
            self.assertEqual({Path(record["path"]): record.get("count", 1)
                              for record in aggregates}, expected)
            for record in aggregates:
                self.assertEqual((record["severity"], record["line"], record["col"]),
                                 ("critical", 1, 1))
                if expected[Path(record["path"])] > 1:
                    self.assertEqual(record["count"], expected[Path(record["path"])])
            concrete = [record for record in records if record["rule"] == concrete_rule]
            self.assertEqual(len(concrete), 4)
            self.assertEqual(sorted((Path(record["path"]), record["line"]) for record in concrete),
                             [(first, 4), (first, 5), (second, 5), (second, 6)])
            self.assertTrue(all(record["severity"] == "warning" and record.get("count", 1) == 1
                                for record in concrete), concrete)
            self.assertEqual((document["critical"], document["warning"], document["info"]),
                             (sum(expected.values()), 4, 0))
            for severity in ("critical", "warning", "info"):
                self.assertEqual(sum(record.get("count", 1) for record in records
                                     if record["severity"] == severity), document[severity])
            return sorted(records, key=lambda record: (record["path"], record["rule"],
                                                       record["line"], record["col"]))

        cold = scan_counts({first: 2, second: 3}, 0, 2)
        warm = scan_counts({first: 2, second: 3}, 2, 0)
        self.assertEqual(warm, cold)

        # Repair only one acquisition. The other file must replay its weight
        # of three while the changed file contributes a freshly scanned one.
        first.write_text(first_source.replace("    assert_eq!(1, 1);\n",
                                              "    assert_eq!(1, 1);\n    let _ = first.join();\n"),
                         encoding="utf-8")
        partial = scan_counts({first: 1, second: 3}, 1, 1)
        self.assertEqual([record for record in partial if Path(record["path"]) == second],
                         [record for record in cold if Path(record["path"]) == second])
        self.assertEqual(scan_counts({first: 1, second: 3}, 2, 0), partial)

    def test_async_lock_inventory_does_not_duplicate_line_fallbacks(self) -> None:
        for name, acquisition, rule in (
            ("blocking", "mutex.lock().unwrap()", "rust.async-locking.std-lock-async"),
            ("async", "mutex.lock().await", "rust.async-locking.tokio-guard-await"),
        ):
            with self.subTest(acquisition=acquisition):
                targets = [self.package(f"{name}_{suffix}") for suffix in ("first", "second")]
                for target in targets:
                    target.write_text(
                        f"async fn receipt() {{ let guard = {acquisition}; pending().await; }}\n",
                        encoding="utf-8",
                    )
                code, doc = self.scan(targets, categories=(20,), fail_on_warning=True)
                hits = [hit for hit in doc["findings"] if hit["rule"] == rule]
                self.assertEqual(code, 1)
                self.assertEqual(len(hits), 2)
                self.assertEqual({Path(hit["path"]) for hit in hits}, set(targets))
                self.assertTrue(all(hit["severity"] == "warning" for hit in hits))

    def test_integration_panic_stays_visible_and_warning_gate_still_fails(self) -> None:
        target = self.package("native")
        code, doc = self.scan([target])
        self.assertEqual(code, 0)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0]["severity"], hits[0]["line"]), ("warning", 1))
        self.assertEqual(Path(hits[0]["path"]), target)
        self.assertEqual((doc["files"], doc["critical"], doc["warning"]), (1, 0, 1))
        self.assertEqual(self.scan([target], fail_on_warning=True)[0], 1)

    def test_production_and_ambiguous_paths_remain_critical(self) -> None:
        targets = [
            self.package("production", source="src/lib.rs"),
            self.package("misleading", source="src/tests/helper.rs"),
            self.package("tests/ancestor", source="src/lib.rs"),
            self.package("disabled", "autotests = false\n"),
            self.package("bin_overlap", '\n[[bin]]\nname="receipt"\npath="tests/receipt.rs"\n'),
            self.package("lib_overlap", '\n[lib]\npath="tests/receipt.rs"\n'),
            self.package("build_overlap", 'build="tests/receipt.rs"\n'),
            self.package("custom_harness", '\n[[test]]\nname="receipt"\nharness=false\n'),
        ]
        missing = self.root / "missing/tests/receipt.rs"
        missing.parent.mkdir(parents=True)
        missing.write_text('fn receipt() { panic!("missing metadata") }\n', encoding="utf-8")
        targets.append(missing)
        invalid = self.package("invalid")
        (invalid.parent.parent / "Cargo.toml").write_text("[package\n", encoding="utf-8")
        targets.append(invalid)
        after = self.package("after", source="src/lib.rs")
        after.write_text('#[cfg(test)]\nmod tests {}\nfn production() { panic!("still production") }\n',
                         encoding="utf-8")
        targets.append(after)
        linked = self.root / "production/tests/linked.rs"
        linked.parent.mkdir()
        linked.symlink_to(targets[0])
        targets.append(linked)
        code, doc = self.scan(targets)
        self.assertEqual(code, 1)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual({Path(hit["path"]) for hit in hits}, set(targets))
        self.assertTrue(all(hit["severity"] == "critical" for hit in hits), hits)

    def test_original_default_test_module_panics_remain_critical(self) -> None:
        fixture = REPO_ROOT / "test-suite/rust/exclude_tests_mod/src"
        code, doc = self.scan([fixture / "lib.rs", fixture / "tests_support.rs"])
        self.assertEqual(code, 1)
        hits = [hit for hit in doc["findings"] if hit["rule"] == "rust.ownership.panic-macro"]
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(hit["severity"] == "critical" for hit in hits))

    def test_missing_toml_parser_keeps_critical(self) -> None:
        target = self.package("native")
        code, doc = self.scan([target], without_tomllib=True)
        self.assertEqual((code, doc["critical"]), (1, 1))

    def test_legacy_autodiscovery_and_workspace_metadata_are_respected(self) -> None:
        target = self.package("legacy", '\n[lib]\npath="src/lib.rs"\n')
        (target.parent.parent / "src").mkdir()
        (target.parent.parent / "src/lib.rs").write_text("", encoding="utf-8")
        manifest = target.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('edition = "2024"', 'edition = "2015"'))
        self.assertEqual(self.scan([target])[0], 1)
        inherited = self.package("workspace/native", '\n[lib]\npath="src/lib.rs"\n')
        (inherited.parent.parent / "src").mkdir()
        (inherited.parent.parent / "src/lib.rs").write_text("", encoding="utf-8")
        manifest = inherited.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('edition = "2024"', 'edition.workspace = true'))
        self.assertEqual(self.scan([inherited])[0], 1)
        workspace = self.root / "workspace/Cargo.toml"
        workspace.write_text('[workspace]\nmembers=["native"]\n[workspace.package]\nedition="2024"\n')
        self.assertEqual(self.scan([inherited], cache=True)[0], 0)
        workspace.write_text(workspace.read_text().replace('"2024"', '"2015"'))
        self.assertEqual(self.scan([inherited], cache=True)[0], 1)

    def test_manifest_changes_invalidate_cached_severity(self) -> None:
        target = self.package("native")
        self.assertEqual(self.scan([target], cache=True)[0], 0)
        code, cached = self.scan([target], cache=True)
        self.assertEqual(code, 0)
        self.assertEqual(cached["extras"]["profile"]["cache_hits"], 1)
        manifest = target.parent.parent / "Cargo.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "autotests=false\n", encoding="utf-8")
        code, changed = self.scan([target], cache=True)
        self.assertEqual((code, changed["critical"]), (1, 1))
        self.assertEqual(changed["extras"]["profile"]["cache_hits"], 0)


class RustRestoredDiagnosticTests(unittest.TestCase):
    """Exercise the real generated pack and public reports at original fixture sites."""

    # Independent expectations from the legacy diagnostic contract. A generic
    # unwrap, cast, or filesystem finding at these lines cannot satisfy them.
    EXPECTED = {
        "rust.casts.ptr-cast": ("info", "Raw pointer cast; verify layouts and lifetimes", (
            (126, "ptr as *mut u8"), (139, "bytes as *const [u8]"), (140, "ptr as *mut u8"))),
        "rust.parsing.parse-float-no-finite-check": ("info", "validate with is_finite() after parsing", (
            (150, "input.parse::<f64>().unwrap_or(0.0)"),)),
        "rust.numeric.instant-now-elapsed": ("warning", "you likely want elapsed() on a previously-stored Instant", (
            (159, "Instant::now().elapsed()"),)),
        "rust.numeric.instant-subtraction": ("warning", "use checked_sub()", (
            (160, "Instant::now() - Duration::from_secs(1)"),)),
        "rust.panic.from-slice-panic": ("warning", "validate length first or use try_from", (
            (176, "Nonce::from_slice(data)"), (177, "GenericArray::from_slice(data)"),
            (178, "Key::from_slice(data)"))),
        "rust.numeric.i64-negate-overflow": ("info", "consider checked_neg() or promote to i128", (
            (154, "1_i64.wrapping_neg()"), (155, "-(values.len() as i64)"))),
        "rust.numeric.wrapping-arithmetic": ("info", "verify this is intentional and not masking a bug", (
            (156, "1_u64.wrapping_add(values.len() as u64)"),
            (157, "1_u64.wrapping_sub(values.len() as u64)"),
            (158, "1_u64.wrapping_mul(values.len() as u64)"))),
        "rust.async.tokio-spawn-no-move": ("info", "consider `async move` to avoid borrow across await", (
            (61, "tokio::spawn(async { async_work().await })"),)),
        "rust.async.tokio-block-in-place": ("info", "ensure this is truly needed and guarded", (
            (64, "tokio::task::block_in_place("),)),
        "rust.filesystem.write-not-atomic": ("info", "for durability, write to a temp file and rename", (
            (185, "std::fs::write("),)),
        "rust.collections.map-clone": ("info", "can often be replaced with .cloned()", (
            (96, "items.iter().map(|item| item.clone())"),)),
        "rust.parsing.strict-utf8": ("warning", "consider from_utf8_lossy() for untrusted input", (
            (152, "String::from_utf8("), (153, "str::from_utf8("))),
        "rust.perf.regex-new-unwrap": ("info", "consider compile-time regex! or handle error with context", (
            (108, "regex::Regex::new("), (117, "regex::Regex::new("))),
        "rust.panic.debug-assert-macros": ("info", "ensure invariants are also enforced where needed", (
            (73, "debug_assert!("), (74, "debug_assert_eq!("), (75, "debug_assert_ne!("))),
    }

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs_rust_restored_")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.fixture = self.root / "coverage.rs"
        shutil.copyfile(REPO_ROOT / "test-suite/rust/buggy/ast_grep_rule_pack_coverage.rs", self.fixture)
        self.source = self.fixture.read_text(encoding="utf-8")
        self.rules = self.root / "rules"
        rust_rules.generate(self.rules)

    def _process(self, command: list[str], cache_name: str, *, cache: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0" if cache else "1", UBS_CACHE_DIR=str(self.root / cache_name),
                   UBS_CACHE_FILE=str(self.root / f"{cache_name}.stats"),
                   UBS_ENABLE_AUTO_UPDATE="0", UBS_PROFILE="1", NO_COLOR="1")
        proc = subprocess.run(command, cwd=self.root, env=env, text=True,
                              capture_output=True, timeout=180, check=False)
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        return proc

    def _json(self, text: str, proc: subprocess.CompletedProcess[str]) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid Rust report: {exc}; report={text!r}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")

    def _native(self, target: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
        paths = self.root / "inputs"
        paths.write_bytes(os.fsencode(target) + b"\0")
        output = self.root / "native.json"
        proc = self._process([
            sys.executable, "-m", "ubs_core.rust_scan", "--files-from", str(paths),
            "--sink", str(self.root / "native.ndjson"), "--json-out", str(output),
            "--project-dir", str(self.root), "--ast-rule-dir", str(self.rules),
            "--skip-type-narrowing", "--quiet",
        ], "native-cache")
        self.assertTrue(output.is_file(), proc.stdout + proc.stderr)
        return proc, self._json(output.read_text(encoding="utf-8"), proc)

    def _cli(self, meta: bool, output_format: str, *, cache: bool = True) -> tuple[subprocess.CompletedProcess[str], dict]:
        command = ([str(REPO_ROOT / "ubs"), "--only=rust", "--no-auto-update"] if meta
                   else [str(REPO_ROOT / "modules/ubs-rust.sh")])
        proc = self._process([
            *command, "--no-cargo", f"--format={output_format}", str(self.fixture),
        ], f"cli-cache-{meta}", cache=cache)
        return proc, self._json(proc.stdout, proc)

    def _cli_cache_counts(self, meta: bool, payload: dict, proc: subprocess.CompletedProcess[str]) -> tuple[int, int]:
        if meta:
            return payload["profile"]["cache_hits"], payload["profile"]["cache_misses"]
        # The standalone Rust summary omits profile fields; its native scanner
        # still writes this real cache-statistics sidecar on every invocation.
        stats_path = self.root / f"cli-cache-{meta}.stats"
        self.assertTrue(stats_path.is_file(), proc.stdout + proc.stderr)
        stats = self._json(stats_path.read_text(encoding="utf-8"), proc)
        return stats["hits"], stats["misses"]

    def _expected_sites(self, anchors: tuple[tuple[int, str], ...]) -> list[tuple[int, int]]:
        lines = self.source.splitlines()
        return sorted((line, lines[line - 1].index(anchor) + 1) for line, anchor in anchors)

    def _assert_native(self, records: list[dict]) -> None:
        for rule, (severity, guidance, anchors) in self.EXPECTED.items():
            with self.subTest(rule=rule):
                hits = [record for record in records if record["rule"] == rule]
                self.assertEqual(sorted((hit["line"], hit["col"]) for hit in hits),
                                 self._expected_sites(anchors), hits)
                for hit in hits:
                    self.assertEqual(Path(hit["path"]).resolve(), self.fixture)
                    self.assertEqual(hit["severity"], severity)
                    self.assertIn(guidance, hit["message"])
        ordinary_asserts = [record for record in records if record["rule"] == "rust.panic.assert-macros"]
        self.assertFalse(any(record["line"] in (73, 74, 75) for record in ordinary_asserts))

    def _assert_sarif(self, payload: dict) -> list[tuple]:
        self.assertEqual(payload["version"], "2.1.0")
        results = [result for run in payload["runs"] for result in run.get("results", [])]
        normalized = []
        for rule, (severity, guidance, anchors) in self.EXPECTED.items():
            with self.subTest(rule=rule):
                hits = [result for result in results if result["ruleId"] == rule]
                sites = []
                for hit in hits:
                    location = hit["locations"][0]["physicalLocation"]
                    self.assertTrue(location["artifactLocation"]["uri"].endswith(self.fixture.name), location)
                    region = location["region"]
                    sites.append((region["startLine"], region["startColumn"]))
                    self.assertEqual(hit["level"], "note" if severity == "info" else severity)
                    self.assertIn(guidance, hit["message"]["text"])
                    normalized.append((rule, hit["level"], *sites[-1], hit["message"]["text"]))
                self.assertEqual(sorted(sites), self._expected_sites(anchors), hits)
        ordinary_asserts = [result for result in results if result["ruleId"] == "rust.panic.assert-macros"]
        self.assertFalse(any(result["locations"][0]["physicalLocation"]["region"]["startLine"] in (73, 74, 75)
                             for result in ordinary_asserts))
        return sorted(normalized)

    def test_original_sites_and_guidance_survive_native_cache_hits(self) -> None:
        cold_proc, cold = self._native(self.fixture)
        self.assertEqual(cold_proc.returncode, 1)
        self.assertEqual(cold["status"], "ok")
        self.assertEqual(cold["files"], 1)
        self.assertEqual((cold["profile"]["cache_hits"], cold["profile"]["cache_misses"]), (0, 1))
        self._assert_native(cold["findings"])
        cold_bytes = (self.root / "native.ndjson").read_bytes()
        warm_proc, warm = self._native(self.fixture)
        self.assertEqual(warm_proc.returncode, cold_proc.returncode)
        self.assertEqual((warm["profile"]["cache_hits"], warm["profile"]["cache_misses"]), (1, 0))
        self._assert_native(warm["findings"])
        self.assertEqual(warm["findings"], cold["findings"])
        self.assertEqual((self.root / "native.ndjson").read_bytes(), cold_bytes)

    def test_module_and_meta_sarif_preserve_uncached_and_cached_diagnostics(self) -> None:
        for meta in (False, True):
            with self.subTest(meta=meta):
                cold_proc, cold = self._cli(meta, "json")
                self.assertEqual(cold_proc.returncode, 1)
                self.assertEqual(self._cli_cache_counts(meta, cold, cold_proc), (0, 1))
                warm_proc, warm = self._cli(meta, "json")
                self.assertEqual(warm_proc.returncode, cold_proc.returncode)
                self.assertEqual(self._cli_cache_counts(meta, warm, warm_proc), (1, 0))
                cached_proc, cached = self._cli(meta, "sarif")
                self.assertEqual(cached_proc.returncode, cold_proc.returncode)
                cached_sites = self._assert_sarif(cached)
                uncached_proc, uncached = self._cli(meta, "sarif", cache=False)
                self.assertEqual(uncached_proc.returncode, cold_proc.returncode)
                self.assertEqual(self._assert_sarif(uncached), cached_sites)

    def test_safe_variants_comments_and_strings_do_not_trigger_restored_checks(self) -> None:
        target = self.root / "safe_variants.rs"
        target.write_text(
            "fn safe(input: &str, bytes: &[u8], value: i64, items: &[String]) {\n"
            "    let _ = value as usize;\n"
            "    let _ = input.parse::<f64>();\n"
            "    let started = Instant::now();\n"
            "    let _ = started.elapsed();\n"
            "    let _ = started.checked_sub(Duration::from_secs(1));\n"
            "    let _ = Nonce::try_from(bytes);\n"
            "    let _ = GenericArray::try_from(bytes);\n"
            "    let _ = Key::try_from(bytes);\n"
            "    let _ = value.checked_neg();\n"
            "    let _ = value.checked_add(1);\n"
            "    let _ = value.checked_sub(1);\n"
            "    let _ = value.checked_mul(1);\n"
            "    let _ = std::fs::rename(\"staged\", \"live\");\n"
            "    let _ = items.iter().cloned();\n"
            "    let _ = String::from_utf8_lossy(bytes);\n"
            "    let _ = str::from_utf8(bytes);\n"
            "    let _ = regex::Regex::new(input);\n"
            "    assert!(value != 0);\n"
            "    tokio::task::block_in_place(|| work());\n"
            "}\n"
            "async fn scheduled() { let task = tokio::spawn(async move { work() }); task.await; }\n"
            "fn work() {}\n"
            "// Instant::now().elapsed(); debug_assert!(false); Nonce::from_slice(bytes);\n"
            'const TEXT: &str = "tokio::spawn(async { work() }); value.wrapping_neg();";\n',
            encoding="utf-8",
        )
        _, doc = self._native(target)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["files"], 1)
        restored = [record for record in doc["findings"] if record["rule"] in self.EXPECTED]
        self.assertEqual(restored, [])


class RustJwtDecoderIdentityTests(unittest.TestCase):
    @staticmethod
    def hits(source: str) -> list[int]:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_jwt_") as tmp:
            target = Path(tmp) / "input.rs"
            target.write_text(source, encoding="utf-8")
            return [line for _, line, _, _ in jwt_verification.find([target])]

    def test_binary_decoder_names_are_not_jwt_evidence(self) -> None:
        source = (
            "fn decode(bytes: &[u8]) -> Option<u8> { bytes.first().copied() }\n"
            "fn exercise(bytes: &[u8]) {\n"
            "    let _ = decode(bytes);\n"
            "    let _ = base64::decode(bytes);\n"
            "    let _ = Frame::decode(bytes);\n"
            "    let _ = codec.decode(bytes);\n"
            "}\n"
            "// use jsonwebtoken::decode;\n"
            'const DOC: &str = "use jsonwebtoken::decode;";\n'
            'const RAW_DOC: &str = r#"use jsonwebtoken::*;"#;\n'
            "/* use jsonwebtoken as jwt; */\n"
        )
        self.assertEqual(self.hits(source), [])

    def test_imported_and_qualified_jwt_decoders_still_require_binding(self) -> None:
        cases = [
            ("", "jsonwebtoken::decode"),
            ("", "::jsonwebtoken::decode"),
            ("use jsonwebtoken::decode;", "decode"),
            ("use jsonwebtoken::{Algorithm, decode, Validation};", "decode"),
            ("use jsonwebtoken::decode as parse_token;", "parse_token"),
            ("use jsonwebtoken::{decode as parse_token, Validation};", "parse_token"),
            ("use {base64::decode as bytes, jsonwebtoken::{decode as parse_token}};", "parse_token"),
            ("use jsonwebtoken as jwt;", "jwt::decode"),
            ("use jsonwebtoken::{self as jwt, Validation};", "jwt::decode"),
            ("extern crate jsonwebtoken as jwt;", "jwt::decode"),
            ("use jsonwebtoken::*;", "decode"),
            ("use jsonwebtoken as jwt; use jwt::decode as parse_token;", "parse_token"),
        ]
        for imports, call in cases:
            with self.subTest(imports=imports, call=call):
                source = (
                    imports + "\n"
                    "fn verify(token: &str, key: &DecodingKey) {\n"
                    "    let validation = Validation::default();\n"
                    f"    let _ = {call}::<Claims>(token, key, &validation);\n"
                    "}\n"
                )
                self.assertEqual(self.hits(source), [4])
                bound = source.replace(
                    "    let validation = Validation::default();\n",
                    "    let mut validation = Validation::default();\n"
                    '    validation.set_issuer(&["issuer"]);\n'
                    '    validation.set_audience(&["audience"]);\n'
                    '    validation.set_required_spec_claims(&["exp", "iss", "aud"]);\n',
                )
                self.assertEqual(self.hits(bound), [])

    def test_unrelated_qualified_calls_do_not_inherit_a_jwt_import(self) -> None:
        self.assertEqual(self.hits(
            "use jsonwebtoken::decode;\n"
            "fn exercise(bytes: &[u8]) {\n"
            "    let _ = base64::decode(bytes);\n"
            "    let _ = Frame::decode(bytes);\n"
            "    let _ = codec.decode(bytes);\n"
            "}\n"
            "mod binary { fn decode(bytes: &[u8]) {} }\n"
        ), [])

    def test_original_jwt_security_fixtures_remain_classified(self) -> None:
        rust = REPO_ROOT / "test-suite" / "rust"
        self.assertEqual(list(jwt_verification.find([rust / "clean/jwt_verification.rs"])), [])
        self.assertGreaterEqual(len(list(jwt_verification.find([rust / "buggy/jwt_verification.rs"]))), 6)


def expected_lines(path: Path, marker: str) -> list[int]:
    """1-based line numbers carrying ``expect: <marker>`` in a fixture."""
    token = f"expect: {marker}"
    return [
        idx
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if token in line
    ]


class HardcodedSecretsSymbolicConstantTests(unittest.TestCase):
    def test_error_code_dictionary_is_clean(self) -> None:
        findings = list(sec_hardcoded_secrets.scan_file_findings(JS_SECURITY / "error-code-constants-clean.mjs"))
        self.assertEqual(findings, [])

    def test_issue_snippet_is_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_js_") as tmp:
            target = Path(tmp) / "error-codes.mjs"
            target.write_text(
                "const CODES = Object.freeze({ CREDENTIALS: 'E_CREDENTIALS' });\n"
                "throw new Error(CODES.CREDENTIALS);\n",
                encoding="utf-8",
            )
            self.assertEqual(list(sec_hardcoded_secrets.scan_file_findings(target)), [])

    def test_credential_material_still_reported(self) -> None:
        fixture = JS_SECURITY / "error-code-constants-buggy.mjs"
        findings = list(sec_hardcoded_secrets.scan_file_findings(fixture))
        self.assertEqual(sorted(line for line, _ in findings), expected_lines(fixture, "secret"))

    def test_symbolic_constant_shape(self) -> None:
        for literal in ("'E_CREDENTIALS'", '"ERR-TOKEN-EXPIRED-401"', "`HTTP_401`", "'API_KEY_MISSING'"):
            self.assertTrue(sec_hardcoded_secrets.is_symbolic_constant(literal), literal)
        for literal in (
            "'sk_live_4f8a2b91cd77e530'", "'AKIAIOSFODNN7EXAMPLE'", "'SESSION_SECRET_9f3a7c1e2b4d'",
            "'e_credentials'", "'CREDENTIALS'", "'E_CREDENTIALS_'", "'4F8A_2B91'", "''",
        ):
            self.assertFalse(sec_hardcoded_secrets.is_symbolic_constant(literal), literal)


class YamlLoaderClassificationTests(unittest.TestCase):
    UNSAFE = unsafe_deserialization.YAML_UNSAFE_LOADER_RULE_ID
    UNRESOLVED = unsafe_deserialization.YAML_LOADER_UNRESOLVED_RULE_ID

    @staticmethod
    def hits(path: Path) -> dict[str, list[int]]:
        grouped: dict[str, list[int]] = {}
        for rule_id, _path, line, _col, _detail in unsafe_deserialization.find([path]):
            grouped.setdefault(rule_id, []).append(line)
        return grouped

    def test_safe_loader_subclasses_are_clean(self) -> None:
        self.assertEqual(self.hits(PY_SECURITY / "yaml_loader_clean.py"), {})

    def test_issue_snippet_is_clean(self) -> None:
        source = (
            "import yaml\n"
            "\n"
            "class StrictSafeLoader(yaml.SafeLoader):\n"
            "    pass\n"
            "\n"
            'yaml.load("title: fixture", Loader=StrictSafeLoader)\n'
        )
        self.assertEqual(unsafe_deserialization.analyze_source(source), [])

    def test_unsafe_and_unresolved_loaders_are_reported(self) -> None:
        fixture = PY_SECURITY / "yaml_loader_buggy.py"
        hits = self.hits(fixture)
        self.assertEqual(sorted(hits.get(self.UNSAFE, [])), expected_lines(fixture, "unsafe"))
        self.assertEqual(sorted(hits.get(self.UNRESOLVED, [])), expected_lines(fixture, "unresolved"))
        # The no-Loader call belongs to py.yaml-unsafe / py.security.yaml-load.
        for line in expected_lines(fixture, "no-loader"):
            for lines in hits.values():
                self.assertNotIn(line, lines)

    def test_reassuring_name_and_dynamic_tag_are_not_evidence(self) -> None:
        source = (
            "import yaml\n"
            "class SafeLoader(yaml.Loader):\n"
            "    pass\n"
            "class DynamicTagLoader(yaml.SafeLoader):\n"
            "    pass\n"
            "DynamicTagLoader.add_constructor(TAG, lambda loader, node: node.value)\n"
            "yaml.load(s, Loader=SafeLoader)\n"
            "yaml.load(s, Loader=DynamicTagLoader)\n"
            "yaml.load(s, Loader=yaml.SafeLoader)  # ubs:ignore\n"
        )
        self.assertEqual(
            [(rule.rsplit(".", 1)[-1], line) for rule, line, _ in unsafe_deserialization.analyze_source(source)],
            [("yaml-unsafe-loader", 7), ("yaml-loader-unresolved", 8)],
        )

    def test_registrations_via_alias_classmethod_and_library_constructors(self) -> None:
        source = (
            "import yaml as y\n"
            "from yaml import SafeLoader\n"
            "class A(y.SafeLoader):\n"
            "    pass\n"
            "y.add_constructor('tag:yaml.org,2002:python/object/apply', lambda l, n: None, Loader=A)\n"
            "class B(y.SafeLoader):\n"
            "    @classmethod\n"
            "    def install(cls):\n"
            "        cls.add_constructor('!!python/name:os.system', cls.construct_scalar)\n"
            "class C(SafeLoader):\n"
            "    pass\n"
            "C.add_constructor('!pair', y.SafeLoader.construct_mapping)\n"
            "C.add_multi_constructor('!x', SafeLoader.construct_yaml_map)\n"
            "y.load(s, Loader=A)\n"
            "y.load(s, Loader=B)\n"
            "y.load(s, Loader=C)\n"
        )
        self.assertEqual(
            [(rule.rsplit(".", 1)[-1], line) for rule, line, _ in unsafe_deserialization.analyze_source(source)],
            [("yaml-unsafe-loader", 14), ("yaml-unsafe-loader", 15)],
        )

    def test_legacy_pickle_loader_rule_unchanged(self) -> None:
        hits = self.hits(PY_SECURITY / "unsafe_deserialization_buggy.py")
        self.assertGreaterEqual(len(hits.get(unsafe_deserialization.RULE_ID, [])), 12)
        self.assertEqual(self.hits(PY_SECURITY / "unsafe_deserialization_clean.py"), {})


YAML_VARIANTS = "\n".join([
    "import yaml",
    "yaml.load(stream)",                                  # 2  no loader
    "yaml.load_all(stream)",                              # 3  no loader
    "yaml.load(open(path))",                              # 4  no loader, nested call
    "yaml.load(stream, Loader=yaml.SafeLoader)",          # 5
    "yaml.load(stream, yaml.SafeLoader)",                 # 6  positional loader
    "yaml.load(stream, Loader=StrictSafeLoader)",         # 7
    "yaml.load_all(stream, Loader=yaml.SafeLoader)",      # 8
    "yaml.load(stream, Loader=yaml.Loader)",              # 9  classified by the AST detector
    "yaml.safe_load(stream)",                             # 10
    "",
])
NO_LOADER_LINES = [2, 3, 4]


class YamlNoLoaderLayersTests(unittest.TestCase):
    def test_category7_regex_matches_single_argument_calls_only(self) -> None:
        pattern = next(p for p in PATTERNS if p.rule_id == "py.security.yaml-load")
        self.assertEqual([line for line, _ in iter_matches(pattern, YAML_VARIANTS)], NO_LOADER_LINES)

    def test_ast_grep_rule_matches_single_argument_calls_only(self) -> None:
        binary = shutil.which("ast-grep") or shutil.which("sg")
        if not binary:
            self.skipTest("ast-grep not installed")
        rule_text = dict(_RULES)["yaml-unsafe"]
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_sg_") as tmp:
            rule = Path(tmp) / "yaml-unsafe.yml"
            rule.write_text(rule_text, encoding="utf-8")
            target = Path(tmp) / "variants.py"
            target.write_text(YAML_VARIANTS, encoding="utf-8")
            proc = subprocess.run(
                [binary, "scan", "-r", str(rule), "--report-style", "short", str(target)],
                capture_output=True, text=True, check=False, timeout=30,
            )
        lines = sorted(
            int(part.split(":")[1])
            for part in proc.stdout.splitlines()
            if part.startswith(str(target))
        )
        self.assertEqual(lines, NO_LOADER_LINES, proc.stdout + proc.stderr)


class ConstantTimeCompareDigestRoleTests(unittest.TestCase):
    @staticmethod
    def issue_lines(path: Path) -> list[int]:
        issues: list = []
        ctcompare_py.analyze(path, issues)
        return sorted(line for _path, line, _code in issues)

    def test_public_checksum_fixture_is_clean(self) -> None:
        self.assertEqual(self.issue_lines(PY_SECURITY / "public_checksum_compare_clean.py"), [])

    def test_authentication_comparisons_still_reported(self) -> None:
        fixture = PY_SECURITY / "public_checksum_compare_buggy.py"
        self.assertEqual(self.issue_lines(fixture), expected_lines(fixture, "secret_eq"))

    def test_existing_pairs_unchanged(self) -> None:
        self.assertEqual(self.issue_lines(PY_SECURITY / "constant_time_compare_clean.py"), [])
        self.assertEqual(self.issue_lines(PY_SECURITY / "parser_token_compare_clean.py"), [])
        self.assertEqual(len(self.issue_lines(PY_SECURITY / "constant_time_compare_buggy.py")), 6)
        self.assertEqual(len(self.issue_lines(PY_SECURITY / "parser_token_compare_buggy.py")), 5)

    def test_runtime_integrity_check_accepts_intact_and_rejects_modified_payload(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "public_checksum_compare_clean", PY_SECURITY / "public_checksum_compare_clean.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory(prefix="ubs_gh102_ct_") as tmp:
            root = Path(tmp)
            fixture.prepare_public_fixture(root)
            fixture.verify_public_fixture(root)  # intact payload verifies
            manifest_sha256 = __import__("json").loads((root / "manifest.json").read_text())["sha256"]
            self.assertTrue(fixture.verify_streamed(root, manifest_sha256))
            self.assertTrue(fixture.verify_named_algorithm(b"public article bytes", "sha256", manifest_sha256))
            (root / "article.html").write_bytes(b"public article bytes, edited")
            with self.assertRaises(RuntimeError):
                fixture.verify_public_fixture(root)
            self.assertFalse(fixture.verify_streamed(root, manifest_sha256))
            # Same length, different bytes: the size check alone must not pass it.
            (root / "article.html").write_bytes(b"public article BYTES")
            with self.assertRaises(RuntimeError):
                fixture.verify_public_fixture(root)


class RustComparisonBoundaryTests(unittest.TestCase):
    """Namespace arms and boolean destinations are not secret operands."""

    RULE = "rust.security.constant-time-compare"
    # Preserve the actual CASS ordering: a later diagnostic match arm used to
    # taint `doctor` in the fixpoint pass, corrupting both earlier comparisons.
    RESTORE = '''fn restore(command: doctor::DoctorBackupCommand,
           execution_mode: doctor::DoctorExecutionMode) {
    if command == doctor::DoctorBackupCommand::Restore {
        let apply_requested = execution_mode == doctor::DoctorExecutionMode::RestoreApply;
        let (restore_plan, plan_fingerprint) = doctor_restore_plan_payload(
            &data_dir,
            &db_path,
            &backup_id_text,
            &verification,
            apply_requested,
            requested_plan_fingerprint.clone(),
        );
        consume(restore_plan, plan_fingerprint);
    }
    match command {
        doctor::DoctorBackupCommand::Verify => {
            println!(
                "doctor backup {} verification: {}",
                backup_id_text,
                payload["backup_verification"]["status"]
            );
        }
        doctor::DoctorBackupCommand::Restore => {}
    }
}
'''
    COMPARISONS = '''fn verify(expected_signature: &str, provided: &str, ordinary: &str, expected: &str) {
    let alias: &str = expected_signature;
    alias != provided; // expect: typed-alias
    let mut value = ordinary;
    value = expected_signature;
    value == provided; // expect: assigned-alias
    expected_signature == (
        provided); // multiline right operand
    let password_matches = ordinary == expected;
    let _ = expected_signature == provided; // expect: discard-positive
    let _ = ordinary == expected;
    // ubs:ignore[unknown.public.rule]
    alias == provided; // expect: unrelated-scope
    // ubs:ignore[rust.security.constant-time-compare]
    alias == provided;
    alias == provided; // expect: adjacent-unmarked
}
fn comparison_is_not_assignment(candidate: &str, expected_signature: &str, ordinary: &str) {
    candidate == expected_signature; // expect: direct-positive
    candidate == ordinary;
}
fn local_namespace_shadow(provided: &str) {
    let doctor: &str = load_secret();
    doctor == provided; // expect: namespace-shadow
}
fn unrelated_function(doctor: &str, ordinary: &str) {
    doctor == ordinary;
}
fn branch_neighbors(mode: Mode, expected_signature: &str, provided: &str) {
    if mode == Mode::Restore {
        expected_signature == provided; // expect: branch-body
    }
    if expected_signature != provided { // expect: branch-condition
        consume(provided);
    }
    mode == Mode::Restore;
}
fn timing_safe(expected_signature: &[u8], provided: &[u8]) -> bool {
    expected_signature.ct_eq(provided).into()
}
'''

    def expected_sites(self, source: str) -> list[tuple[int, str]]:
        return [(number, line.strip()) for number, line in enumerate(source.splitlines(), 1)
                if "// expect:" in line or line.strip() == "expected_signature == ("]

    def test_real_restore_match_arm_does_not_taint_namespace(self) -> None:
        self.assertEqual(ctcompare_rust.scan_file(self.RESTORE), [])

    def test_real_aliases_operands_neighbors_and_function_shadowing(self) -> None:
        expected = self.expected_sites(self.COMPARISONS)
        self.assertEqual(len(expected), 10)
        self.assertEqual(ctcompare_rust.scan_file(self.COMPARISONS), expected)
        # Existing positive/clean source pairs also protect the original
        # detector's secret vocabulary, constant-time APIs, and function scopes.
        fixtures = REPO_ROOT / "test-suite/rust"
        for name, count in (("constant_time_compare.rs", 8),
                            ("secret_compare_function_scope.rs", 4)):
            with self.subTest(fixture=name):
                self.assertEqual(len(ctcompare_rust.scan_file(
                    (fixtures / "buggy" / name).read_text(encoding="utf-8"))), count)
                self.assertEqual(ctcompare_rust.scan_file(
                    (fixtures / "clean" / name).read_text(encoding="utf-8")), [])

    def test_public_generated_and_fallback_reports_preserve_exact_cached_sites(self) -> None:
        self.assertIsNotNone(shutil.which("ast-grep"), "generated public scan requires real ast-grep")
        for ast in (True, False):
            with self.subTest(ast=ast), tempfile.TemporaryDirectory(prefix="ubs_rust_comparison_") as td:
                root = Path(td)
                project = root / "project"
                project.mkdir()
                clean = project / "restore.rs"
                positive = project / "compare.rs"
                clean.write_text(self.RESTORE, encoding="utf-8")
                positive.write_text(self.COMPARISONS, encoding="utf-8")
                inputs = root / "inputs"
                report = root / "findings.ndjson"
                statistics = root / "cache-stats.json"
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                           UBS_CACHE_DIR=str(root / "cache"), UBS_CACHE_FILE=str(statistics),
                           UBS_PROFILE="1", UBS_SKIP_TYPE_NARROWING="1", NO_COLOR="1",
                           UBS_TEST_FORCE_NO_AST_GREP="0" if ast else "1")

                def scan(selected: list[Path], source: str, output_format: str, hits: int) -> list[tuple]:
                    inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                    command = [str(REPO_ROOT / "modules/ubs-rust.sh"), "--no-cargo", "--ci",
                               "--no-color", "--only=8", f"--format={output_format}",
                               f"--report-json={report}", "--files-from", str(inputs), str(project)]
                    proc = subprocess.run(command, cwd=root, env=env, text=True,
                                          capture_output=True, timeout=180)
                    context = f"{command!r}; exit={proc.returncode}; stdout={proc.stdout!r}; stderr={proc.stderr!r}"
                    expected = [(self.RULE, str(positive), line, 1, "critical")
                                for line, _ in self.expected_sites(source)] if positive in selected else []
                    self.assertEqual(proc.returncode, int(bool(expected)), context)
                    try:
                        payload = json.loads(proc.stdout)
                        stats = json.loads(statistics.read_text(encoding="utf-8"))
                        records = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
                    except (json.JSONDecodeError, OSError) as exc:
                        self.fail(f"invalid Rust comparison report/statistics: {exc}; {context}")
                    self.assertEqual((stats["hits"], stats["misses"]),
                                     (hits, len(selected) - hits), context)
                    actual = []
                    for record in records:
                        self.assertEqual(record.get("count", 1), 1, context)
                        actual.append((record["rule"], str((root / record["path"]).resolve()),
                                       record["line"], record["col"], record["severity"]))
                    self.assertEqual(sorted(actual), sorted(expected), context)
                    if output_format == "json":
                        self.assertEqual(payload["status"], "ok", context)
                        self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                         (len(expected), 0, 0), context)
                    else:
                        self.assertEqual(payload["version"], "2.1.0", context)
                        self.assertEqual(len(payload["runs"]), 1, context)
                        run = payload["runs"][0]
                        self.assertEqual(run["tool"]["driver"]["name"], "ubs-rust", context)
                        sarif = []
                        for record in run["results"]:
                            self.assertEqual(record["level"], "error", context)
                            self.assertEqual(len(record["locations"]), 1, context)
                            location = record["locations"][0]["physicalLocation"]
                            sarif.append((record["ruleId"], str((root / location["artifactLocation"]["uri"]).resolve()),
                                          location["region"]["startLine"], location["region"]["startColumn"], "critical"))
                        self.assertEqual(sorted(sarif), sorted(expected), context)
                    return sorted(records, key=lambda record: (record["path"], record["line"], record["col"]))

                cold = scan([clean, positive], self.COMPARISONS, "json", 0)
                self.assertEqual(scan([clean, positive], self.COMPARISONS, "json", 2), cold)
                self.assertEqual(scan([clean, positive], self.COMPARISONS, "sarif", 2), cold)
                self.assertEqual(scan([clean], self.RESTORE, "json", 1), [])
                repaired = self.COMPARISONS.replace(
                    "alias != provided; // expect: typed-alias", "consume(alias); // repaired typed-alias")
                positive.write_text(repaired, encoding="utf-8")
                partial = scan([clean, positive], repaired, "json", 1)
                self.assertEqual(len(partial), len(cold) - 1)
                self.assertEqual(scan([clean, positive], repaired, "sarif", 2), partial)


class RustPreparedSourceTests(unittest.TestCase):
    COMPARE = '''const API_SECRET: &str = "secret";
fn verify(provided: &str) {
    let alias = next_alias;
    let next_alias = API_SECRET;
    let local = alias;
    local == provided;
    API_SECRET == (
        provided);
    API_SECRET == provided; // ubs:ignore
    // ubs:ignore
    API_SECRET != provided;
}
fn unrelated(token: &str) {
    token == "BR2";
}
fn other(provided: &str) {
    local == provided;
    API_SECRET != provided;
}
'''
    RANDOM = '''fn create_session_token() {
    let token = rand::random::<u64>();
    let token = rand::random::<u64>(); // ubs:ignore
    // ubs:ignore
    let token = rand::random::<u64>();
}
fn doc() {
    let text = "token rand::random::<u64>() // literal";
}
fn csrf_nonce() {
    let nonce = rand::random::<
        u64>();
}
fn unrelated() {
    let number = rand::random::<u64>();
}
'''

    def test_rust_compare_multiline_alias_scopes_and_markers(self):
        findings = ctcompare_rust.scan_file(self.COMPARE)
        self.assertEqual([line for line, _ in findings], [6, 7, 18])
        self.assertEqual(
            findings,
            [(line, self.COMPARE.splitlines()[line - 1].strip()) for line in [6, 7, 18]],
        )

    def test_rust_random_multiline_and_markers(self):
        with tempfile.TemporaryDirectory(prefix="ubs-rust-reuse-") as tmp:
            path = Path(tmp) / "source.rs"
            path.write_text(self.RANDOM, encoding="utf-8")
            findings = list(security_randomness.find([path]))
            self.assertEqual([hit[1] for hit in findings], [2, 11])
            # The same pathname must observe replacement contents on a later
            # invocation; reuse is confined to one immutable file read.
            path.write_text("fn ordinary() {}\n", encoding="utf-8")
            self.assertEqual(list(security_randomness.find([path])), [])
            path.write_text(self.RANDOM, encoding="utf-8")
            self.assertEqual(list(security_randomness.find([path])), findings)

    def test_rust_compare_source_reuse_does_not_cross_scans(self):
        first = ctcompare_rust.scan_file(self.COMPARE)
        self.assertTrue(first)
        self.assertEqual(ctcompare_rust.scan_file("fn ordinary(x: u32) { x == 1; }"), [])
        self.assertEqual(ctcompare_rust.scan_file(self.COMPARE), first)

    def test_rust_comment_stripping_once_per_source_line(self):
        # Count actual calls while running the detector, without substituting
        # its parser or outputs. Lookahead and taint fixpoint passes must reuse
        # the prepared lines rather than rescan them.
        counts = {}
        codes = {ctcompare_rust.strip_line_comments.__code__,
                 security_randomness.strip_line_comments.__code__}

        def record(frame, event, arg):
            if event == "call" and frame.f_code in codes:
                counts[frame.f_code] = counts.get(frame.f_code, 0) + 1

        previous = sys.getprofile()
        with tempfile.TemporaryDirectory(prefix="ubs-rust-reuse-") as tmp:
            path = Path(tmp) / "source.rs"
            path.write_text(self.RANDOM, encoding="utf-8")
            try:
                sys.setprofile(record)
                compared = ctcompare_rust.scan_file(self.COMPARE)
                random = list(security_randomness.find([path]))
            finally:
                sys.setprofile(previous)
        self.assertEqual([line for line, _ in compared], [6, 7, 18])
        self.assertEqual([hit[1] for hit in random], [2, 11])
        self.assertEqual(counts[ctcompare_rust.strip_line_comments.__code__], len(self.COMPARE.splitlines()))
        self.assertEqual(counts[security_randomness.strip_line_comments.__code__], len(self.RANDOM.splitlines()))


class RustTaintReferenceTests(unittest.TestCase):
    DETECTORS = (
        request_url, open_redirect, request_regex,
        response_header, host_header_url, sql_injection,
    )
    FORMATTED = (response_header, host_header_url, sql_injection)

    @classmethod
    def original_refs(cls, detector, expression, tainted):
        # Retain the original algorithm as the independent behavior oracle:
        # optimize its cost, not its matching, masking or tie-breaking.
        if detector in cls.FORMATTED:
            searchable = detector.without_string_literals(expression)
        elif detector is request_regex:
            searchable = detector.mask_literals(expression)
        else:
            searchable = expression
        return [
            name for name in tainted
            if re.search(rf'\b{re.escape(name)}\b', searchable)
            or (detector in cls.FORMATTED and re.search(
                rf'\{{\s*{re.escape(name)}\s*(?::|[}}])', expression
            ))
        ]

    def test_reference_boundaries_literals_captures_and_order_match_original(self):
        # Deliberately different from expression order: the first recorded
        # taint owns the displayed evidence path when several names match.
        tainted = dict.fromkeys(["beta", "alpha", "_x", "Alpha", "a1", "x"])
        expressions = [
            "alpha + beta + alpha", "alpha_beta alphabeta 1alpha alpha1",
            "obj.alpha + &beta + r#_x + Alpha + a1", "éalpha alphaé αalpha alpha中",
            "alpha\u0301 + \u0301beta", '"alpha" + beta', 'r#"alpha // beta"# + _x',
            'format!("{alpha} { beta :>10} {_x:?}")',
            'format!("{alpha:{beta}} {{alpha}} {alpha_} {alphaé}")',
            '"{ alpha\n:10} {beta!} {1alpha}"', "", "αβ_中文",
        ]
        for detector in self.DETECTORS:
            for expression in expressions:
                with self.subTest(detector=detector.__name__, expression=expression):
                    self.assertEqual(
                        detector.refs_in_expr(expression, tainted),
                        self.original_refs(detector, expression, tainted),
                    )
            self.assertEqual(detector.refs_in_expr("alpha + beta", tainted), ["beta", "alpha"])
            self.assertEqual(detector.refs_in_expr("anything", {}), [])

    def test_large_taint_table_does_not_compile_one_regex_per_name(self):
        # More identifiers than Python's regex cache can hold reproduces the
        # CASS timeout's cache thrashing. Observe real compiler calls; no mock
        # replaces either the regular-expression engine or a detector.
        tainted = dict.fromkeys(f"value_{i}" for i in range(2048))
        expression = 'value_2047 + value_0 + format!("{value_1024:?}")'
        calls = []

        def record(frame, event, arg):
            if event == "call" and frame.f_code.co_name == "compile" and frame.f_globals.get("__name__") == "re._compiler":
                calls.append(1)

        previous = sys.getprofile()
        re.purge()
        try:
            sys.setprofile(record)
            results = [detector.refs_in_expr(expression, tainted) for detector in self.DETECTORS]
        finally:
            sys.setprofile(previous)
        for detector, result in zip(self.DETECTORS, results):
            self.assertEqual(result, self.original_refs(detector, expression, tainted))
        self.assertLessEqual(len(calls), 4, f"regex compilations scaled with taint table: {len(calls)}")


if __name__ == "__main__":
    unittest.main()
