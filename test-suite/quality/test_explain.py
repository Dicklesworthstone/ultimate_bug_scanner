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


if __name__ == "__main__":
    unittest.main()
