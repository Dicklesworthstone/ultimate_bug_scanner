#!/usr/bin/env python3
"""Unit & E2E tests for `ubs explain <rule-id>` (bead K3).

Validates:
1. `ubs explain <rule-id>` prints rule message, remediation, buggy/clean fixture
   excerpts (looked up via detectors.yml), category id, and calibrated confidence.
2. `ubs explain <rule-id> --format=json` emits valid JSON with all required fields.
3. Unknown rule IDs exit 2 with nearest fuzzy/token match suggestions.
4. Empty/missing rule ID exits 2 with usage instructions.
5. Help flags (-h, --help) exit 0 with usage instructions.
6. Coverage for multiple languages (Python, JS, Rust, Go).
7. Ast-grep rules not in detectors.yml are explained gracefully.
8. Direct python3 -m ubs_core.explain invocation parity.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

UBS_BIN = REPO_ROOT / "ubs"
ARTIFACTS_DIR = REPO_ROOT / "test-suite" / "artifacts"


def run_ubs(args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({
        "NO_COLOR": "1",
        "UBS_NO_AUTO_UPDATE": "1",
        "UBS_SKIP_SIZE_CHECK": "1",
        "PYTHONPATH": str(HELPERS_DIR) + (f":{env['PYTHONPATH']}" if "PYTHONPATH" in env else ""),
    })
    return subprocess.run(
        [str(UBS_BIN), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def record_artifact(case_id: str, proc: subprocess.CompletedProcess, extra: dict[str, Any] | None = None) -> None:
    dest = ARTIFACTS_DIR / case_id
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "stdout.log").write_text(proc.stdout, encoding="utf-8")
    (dest / "stderr.log").write_text(proc.stderr, encoding="utf-8")
    result = {
        "exit_code": proc.returncode,
        "args": proc.args,
        **(extra or {}),
    }
    (dest / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


class ExplainRuleTests(unittest.TestCase):
    def _run_with_logging(self, case_id: str, fn) -> None:
        print(f"[{case_id}] RUN", flush=True)
        t0 = time.perf_counter()
        try:
            fn()
            elapsed = time.perf_counter() - t0
            print(f"[{case_id}] PASS ({elapsed:.3f}s)", flush=True)
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            print(f"[{case_id}] FAIL ({elapsed:.3f}s): {exc}", flush=True)
            raise

    def test_known_rule_text_format(self) -> None:
        case_id = "explain-known-rule-text"

        def _test() -> None:
            proc = run_ubs(["explain", "py.security.open-redirect"])
            record_artifact(case_id, proc)
            self.assertEqual(proc.returncode, 0, f"Expected 0, got {proc.returncode}: {proc.stderr}")
            out = proc.stdout
            self.assertIn("Rule:        py.security.open-redirect", out)
            self.assertIn("Category:", out)
            self.assertIn("Language:    Python", out)
            self.assertIn("Severity:", out)
            self.assertIn("Confidence:  high (calibrated)", out)
            self.assertIn("Message:", out)
            self.assertIn("Remediation:", out)
            self.assertIn("Buggy Fixture Example", out)
            self.assertIn("open_redirect_buggy.py", out)
            self.assertIn("Clean Fixture Example", out)
            self.assertIn("open_redirect_clean.py", out)

        self._run_with_logging(case_id, _test)

    def test_known_rule_json_format(self) -> None:
        case_id = "explain-known-rule-json"

        def _test() -> None:
            proc = run_ubs(["explain", "py.security.open-redirect", "--format=json"])
            record_artifact(case_id, proc)
            self.assertEqual(proc.returncode, 0, f"Expected 0, got {proc.returncode}: {proc.stderr}")
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["rule_id"], "py.security.open-redirect")
            self.assertEqual(doc["name"], "Open Redirect")
            self.assertEqual(doc["language"], "python")
            self.assertEqual(doc["confidence"], "high")
            self.assertEqual(doc["severity"], "critical")
            self.assertTrue(doc["category_id"], "category_id should be present")
            self.assertTrue(doc["message"], "message should be present")
            self.assertTrue(doc["remediation"], "remediation should be present")

            # Check fixtures
            self.assertIn("buggy_fixture", doc)
            self.assertIn("clean_fixture", doc)
            self.assertIn("fixtures", doc)
            bf = doc["buggy_fixture"]
            cf = doc["clean_fixture"]
            self.assertIsNotNone(bf)
            self.assertIsNotNone(cf)
            self.assertTrue((REPO_ROOT / bf["path"]).exists(), f"Buggy path does not exist: {bf['path']}")
            self.assertTrue((REPO_ROOT / cf["path"]).exists(), f"Clean path does not exist: {cf['path']}")
            self.assertTrue(len(bf["excerpt"]) > 20, "Buggy excerpt should not be empty")
            self.assertTrue(len(cf["excerpt"]) > 20, "Clean excerpt should not be empty")

        self._run_with_logging(case_id, _test)

    def test_cross_language_rules(self) -> None:
        case_id = "explain-cross-language"

        def _test() -> None:
            rules_to_test = [
                ("js.security.archive-extraction", "js"),
                ("rust.security.archive_extraction", "rust"),
                ("golang.security.open_redirect", "golang"),
            ]
            for rule_id, expected_lang in rules_to_test:
                proc = run_ubs(["explain", rule_id, "--format=json"])
                self.assertEqual(proc.returncode, 0, f"Failed explaining {rule_id}: {proc.stderr}")
                doc = json.loads(proc.stdout)
                self.assertEqual(doc["rule_id"], rule_id)
                self.assertEqual(doc["language"], expected_lang)
                self.assertEqual(doc["confidence"], "high")
                self.assertTrue(doc["buggy_fixture"], f"Expected buggy fixture for {rule_id}")
                self.assertTrue(doc["clean_fixture"], f"Expected clean fixture for {rule_id}")

        self._run_with_logging(case_id, _test)

    def test_native_php_rules_keep_uncalibrated_confidence_and_fixtures(self) -> None:
        categories = {
            "sql-injection": "php.sql",
            "command-injection": "php.execution",
            "dynamic-code": "php.execution",
            "dynamic-include": "php.includes",
            "unsafe-deserialization": "php.deserialization",
            "xss": "php.output",
        }
        for suffix, category in categories.items():
            rule_id = f"php.security.{suffix}"
            with self.subTest(rule=rule_id):
                proc = run_ubs(["explain", rule_id, "--format=json"])
                record_artifact(f"explain-{rule_id}", proc)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                document = json.loads(proc.stdout)
                self.assertEqual(document["rule_id"], rule_id)
                self.assertEqual(document["language"], "php")
                self.assertEqual(document["category_id"], category)
                self.assertEqual(document["severity"], "critical")
                self.assertEqual(document["confidence"], "unknown")
                self.assertTrue(document["message"])
                self.assertTrue(document["remediation"])
                for kind in ("buggy_fixture", "clean_fixture"):
                    fixture = document[kind]
                    self.assertTrue(fixture)
                    self.assertTrue((REPO_ROOT / fixture["path"]).is_file())
                    self.assertTrue(fixture["excerpt"])
        proc = run_ubs(["explain", "php.security.sql-injection"])
        record_artifact("explain-php-native-text", proc)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("unknown (uncalibrated)", proc.stdout)

    def test_native_dapper_rule_explains_its_own_fixtures(self) -> None:
        rule_id = "cs.security.sql-injection"
        proc = run_ubs(["explain", rule_id, "--format=json"])
        record_artifact("explain-csharp-dapper-json", proc)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        document = json.loads(proc.stdout)
        self.assertEqual(document["rule_id"], rule_id)
        self.assertEqual(document["language"], "csharp")
        self.assertEqual(document["category_id"], "csharp.security")
        self.assertEqual(document["severity"], "critical")
        self.assertEqual(document["confidence"], "unknown")
        self.assertTrue(document["message"])
        self.assertTrue(document["remediation"])
        for kind, filename in (("buggy_fixture", "DapperSqlBuggy.cs"),
                               ("clean_fixture", "DapperSqlClean.cs")):
            fixture = document[kind]
            self.assertEqual(Path(fixture["path"]).name, filename)
            self.assertTrue((REPO_ROOT / fixture["path"]).is_file())
            self.assertTrue(fixture["excerpt"])

    def test_unknown_rule_text_suggests_nearest_matches(self) -> None:
        case_id = "explain-unknown-rule-text"

        def _test() -> None:
            # Query with underscore instead of hyphen
            proc = run_ubs(["explain", "py.security.open_redirect"])
            record_artifact(case_id, proc)
            self.assertEqual(proc.returncode, 2, f"Expected exit code 2, got {proc.returncode}")
            combined = proc.stdout + proc.stderr
            self.assertIn("Unknown rule 'py.security.open_redirect'", combined)
            self.assertIn("Did you mean one of these?", combined)
            self.assertIn("py.security.open-redirect", combined)

        self._run_with_logging(case_id, _test)

    def test_unknown_rule_json_suggests_nearest_matches(self) -> None:
        case_id = "explain-unknown-rule-json"

        def _test() -> None:
            proc = run_ubs(["explain", "py.security.open_redirect", "--format=json"])
            record_artifact(case_id, proc)
            self.assertEqual(proc.returncode, 2, f"Expected exit code 2, got {proc.returncode}")
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["exit_code"], 2)
            self.assertIn("error", doc)
            self.assertEqual(doc["rule_id"], "py.security.open_redirect")
            self.assertIsInstance(doc["suggestions"], list)
            self.assertIn("py.security.open-redirect", doc["suggestions"])

        self._run_with_logging(case_id, _test)

    def test_completely_unknown_rule_exits_2(self) -> None:
        case_id = "explain-completely-unknown-rule"

        def _test() -> None:
            proc = run_ubs(["explain", "completely_nonexistent_rule_xyz_999", "--format=json"])
            record_artifact(case_id, proc)
            self.assertEqual(proc.returncode, 2)
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["exit_code"], 2)
            self.assertIn("error", doc)

        self._run_with_logging(case_id, _test)

    def test_missing_rule_id_exits_2(self) -> None:
        case_id = "explain-missing-rule-id"

        def _test() -> None:
            proc_text = run_ubs(["explain"])
            self.assertEqual(proc_text.returncode, 2)
            self.assertIn("rule-id argument is required", proc_text.stderr + proc_text.stdout)

            proc_json = run_ubs(["explain", "--format=json"])
            self.assertEqual(proc_json.returncode, 2)
            doc = json.loads(proc_json.stdout)
            self.assertEqual(doc["exit_code"], 2)
            self.assertIn("error", doc)

        self._run_with_logging(case_id, _test)

    def test_help_flag_exits_0(self) -> None:
        case_id = "explain-help-flag"

        def _test() -> None:
            for flag in ["-h", "--help"]:
                proc = run_ubs(["explain", flag])
                self.assertEqual(proc.returncode, 0, f"Failed for {flag}")
                self.assertIn("usage: ubs explain", proc.stdout.lower())

        self._run_with_logging(case_id, _test)

    def test_ast_grep_pack_rule(self) -> None:
        case_id = "explain-ast-grep-rule"

        def _test() -> None:
            proc = run_ubs(["explain", "py.none-eq", "--format=json"])
            self.assertEqual(proc.returncode, 0, f"Expected 0, got {proc.returncode}: {proc.stderr}")
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["rule_id"], "py.none-eq")
            self.assertEqual(doc["language"], "py")
            self.assertTrue(doc["message"])
            self.assertTrue(doc["severity"])
            self.assertEqual(doc["confidence"], "high")

        self._run_with_logging(case_id, _test)

    def test_python_module_direct_dispatch(self) -> None:
        case_id = "explain-python-direct-dispatch"

        def _test() -> None:
            from ubs_core.explain import explain_rule

            # Test Python direct invocation
            rc, stdout, stderr = explain_rule("py.security.open-redirect", repo_root=REPO_ROOT, output_format="json")
            self.assertEqual(rc, 0)
            doc = json.loads(stdout)
            self.assertEqual(doc["rule_id"], "py.security.open-redirect")

            # Unknown rule
            rc2, stdout2, stderr2 = explain_rule("unknown.rule.id", repo_root=REPO_ROOT, output_format="json")
            self.assertEqual(rc2, 2)
            err_doc = json.loads(stdout2)
            self.assertEqual(err_doc["exit_code"], 2)

        self._run_with_logging(case_id, _test)

    def test_registry_covers_all_13_languages_and_explains_new_modules(self) -> None:
        case_id = "explain-13-language-registry"

        def _test() -> None:
            import re
            from ubs_core.explain import explain_rule

            ubs_text = (REPO_ROOT / "ubs").read_text(encoding="utf-8")
            match = re.search(r"^ALL_LANGS=\(([^)]*)\)", ubs_text, re.M)
            all_langs = set(match.group(1).split()) if match else set()
            registry = json.loads((REPO_ROOT / "detectors.yml").read_text(encoding="utf-8"))
            reg_langs = {entry["id"] for entry in registry.get("languages", [])}
            self.assertEqual(reg_langs, all_langs)

            for rule_id, expected_lang in (
                ("kotlin.security.archive_extraction", "kotlin"),
                ("bash.security.eval_variable", "bash"),
                ("ex.security.sql-interpolation", "elixir"),
            ):
                rc, stdout, stderr = explain_rule(rule_id, repo_root=REPO_ROOT, output_format="json")
                self.assertEqual(rc, 0, stderr)
                doc = json.loads(stdout)
                self.assertEqual(doc["rule_id"], rule_id)
                self.assertEqual(doc["language"], expected_lang)
                self.assertIsNotNone(doc["buggy_fixture"], rule_id)
                self.assertIsNotNone(doc["clean_fixture"], rule_id)

        self._run_with_logging(case_id, _test)


class InstalledLayoutExplainTests(unittest.TestCase):
    """`ubs explain` from an installed runner (issue #187).

    install.sh puts the runner in a bin directory and the helpers in the module
    cache under $XDG_DATA_HOME; neither detectors.yml nor test-suite/ is
    installed. The catalog used to be read from "<runner dir>/modules/helpers",
    so every documented rule ID came back unknown with no suggestions. Each
    test builds that layout in a temporary directory, with every location the
    runner reads pinned there and PYTHONPATH cleared, so nothing can fall back
    to this checkout.
    """

    DOCUMENTED_IDS = (
        "py.security.open-redirect",
        "cs.security.sql-injection",
        "php.security.sql-injection",
        "py.io.open-no-encoding",
    )

    def setUp(self) -> None:
        import shutil
        import tempfile

        self.root = Path(tempfile.mkdtemp(prefix="ubs-explain-installed-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        shutil.copy2(UBS_BIN, self.bin_dir / "ubs")
        self.module_dir = self.root / "data" / "ubs" / "modules"
        self.module_dir.mkdir(parents=True)
        self.copy_helpers = lambda: shutil.copytree(
            HELPERS_DIR, self.module_dir / "helpers",
            ignore=shutil.ignore_patterns("__pycache__"))

    def run_installed(self, args: list[str]) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        env.update({
            "HOME": str(self.root / "home"),
            "XDG_DATA_HOME": str(self.root / "data"),
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_CACHE_HOME": str(self.root / "cache"),
            "NO_COLOR": "1",
            "UBS_NO_AUTO_UPDATE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            [str(self.bin_dir / "ubs"), "explain", *args],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=60,
        )

    def test_documented_rules_explain_from_the_module_cache(self) -> None:
        self.copy_helpers()
        for rule_id in self.DOCUMENTED_IDS:
            with self.subTest(rule=rule_id):
                proc = self.run_installed([rule_id, "--format=json"])
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                doc = json.loads(proc.stdout)
                self.assertEqual(doc["rule_id"], rule_id)
                self.assertTrue(doc["message"])
                self.assertTrue(doc["remediation"])
                self.assertIn(doc["severity"], ("critical", "warning", "info"))
                # Fixtures live in test-suite/, which an installation lacks.
                self.assertIsNone(doc["buggy_fixture"])
                self.assertIsNone(doc["clean_fixture"])

        text = self.run_installed(["py.security.open-redirect"])
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("Rule:        py.security.open-redirect", text.stdout)
        self.assertIn("source checkout", text.stdout)

        near = self.run_installed(["py.security.open_redirect", "--format=json"])
        self.assertEqual(near.returncode, 2)
        self.assertIn("py.security.open-redirect", json.loads(near.stdout)["suggestions"])

    def test_missing_helpers_report_a_repair_not_an_unknown_rule(self) -> None:
        proc = self.run_installed(["py.security.open-redirect", "--format=json"])
        self.assertEqual(proc.returncode, 2)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["exit_code"], 2)
        self.assertIn("ubs doctor --fix", doc["error"])
        self.assertNotIn("Unknown rule", proc.stdout + proc.stderr)

        text = self.run_installed(["py.security.open-redirect"])
        self.assertEqual(text.returncode, 2)
        self.assertIn("ubs doctor --fix", text.stderr)
        self.assertNotIn("Unknown rule", text.stdout + text.stderr)

    def test_helpers_left_by_an_older_release_report_a_repair(self) -> None:
        # `ubs --update` replaces only the runner. Until the next scan refreshes
        # the module cache, its explain.py is the previous release's, which read
        # the catalog from the runner's directory and answered "Unknown rule"
        # for every ID. The runner must not run a cached explain.py whose digest
        # it does not pin.
        self.copy_helpers()
        stale = self.module_dir / "helpers" / "ubs_core" / "explain.py"
        stale.write_text('import sys\nprint("Unknown rule")\nsys.exit(2)\n', encoding="utf-8")
        proc = self.run_installed(["py.security.open-redirect", "--format=json"])
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["exit_code"], 2)
        self.assertIn("ubs doctor --fix", doc["error"])
        self.assertNotIn("Unknown rule", proc.stdout + proc.stderr)

        text = self.run_installed(["py.security.open-redirect"])
        self.assertEqual(text.returncode, 2)
        self.assertIn("do not match this ubs version", text.stderr)
        self.assertNotIn("Unknown rule", text.stdout + text.stderr)

    def test_empty_catalog_is_reported_as_broken_installation(self) -> None:
        from ubs_core import explain

        original = explain.build_catalog
        explain.build_catalog = lambda _root: {}
        try:
            rc, out, err = explain.explain_rule("py.security.open-redirect", repo_root=REPO_ROOT,
                                                output_format="json")
        finally:
            explain.build_catalog = original
        self.assertEqual(rc, 2)
        self.assertIn("ubs doctor --fix", json.loads(out)["error"])
        self.assertNotIn("Unknown rule", out + err)


if __name__ == "__main__":
    unittest.main()
