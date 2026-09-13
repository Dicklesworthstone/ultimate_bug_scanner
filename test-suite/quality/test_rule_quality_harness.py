#!/usr/bin/env python3
"""Unit checks for the rule-quality harness invariants."""

import contextlib
import io
import json
import os
import subprocess  # nosec B404 - unit tests intentionally exercise subprocess paths.
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

import rule_quality_harness


def load_artifact_result(artifact_dir: Path) -> Any:
    with (artifact_dir / "result.json").open(encoding="utf-8") as result_file:
        try:
            return json.loads(result_file.read())
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"artifact result is not valid JSON: {artifact_dir / 'result.json'}"
            ) from exc


class ProgressOutputTest(unittest.TestCase):
    def test_log_progress_writes_one_line(self) -> None:
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            rule_quality_harness.log_progress("[phase] running case")

        self.assertEqual(buffer.getvalue(), "[phase] running case\n")


class QualityHarnessConfigTest(unittest.TestCase):
    def test_default_case_timeout_has_load_margin(self) -> None:
        old_value = os.environ.pop("UBS_RULE_QUALITY_CASE_TIMEOUT", None)
        try:
            self.assertEqual(rule_quality_harness.default_case_timeout(), 120)
        finally:
            if old_value is not None:
                os.environ["UBS_RULE_QUALITY_CASE_TIMEOUT"] = old_value

    def test_default_case_timeout_is_env_overridable(self) -> None:
        old_value = os.environ.get("UBS_RULE_QUALITY_CASE_TIMEOUT")
        os.environ["UBS_RULE_QUALITY_CASE_TIMEOUT"] = "180"
        try:
            self.assertEqual(rule_quality_harness.default_case_timeout(), 180)
        finally:
            if old_value is None:
                os.environ.pop("UBS_RULE_QUALITY_CASE_TIMEOUT", None)
            else:
                os.environ["UBS_RULE_QUALITY_CASE_TIMEOUT"] = old_value

    def test_default_case_timeout_rejects_invalid_values(self) -> None:
        old_value = os.environ.get("UBS_RULE_QUALITY_CASE_TIMEOUT")
        os.environ["UBS_RULE_QUALITY_CASE_TIMEOUT"] = "0"
        try:
            with self.assertRaisesRegex(AssertionError, "must be positive"):
                rule_quality_harness.default_case_timeout()
        finally:
            if old_value is None:
                os.environ.pop("UBS_RULE_QUALITY_CASE_TIMEOUT", None)
            else:
                os.environ["UBS_RULE_QUALITY_CASE_TIMEOUT"] = old_value


class RuntimeArtifactTest(unittest.TestCase):
    def test_completed_process_from_timeout_preserves_partial_output(self) -> None:
        exc = subprocess.TimeoutExpired(
            ["ubs", "fixture.rs"],
            7,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

        proc = rule_quality_harness.completed_process_from_timeout(
            ["ubs", "fixture.rs"],
            exc,
            duration=1.2345,
            timeout=7,
        )

        self.assertEqual(proc.returncode, -1)
        self.assertEqual(proc.stdout, "partial stdout")
        self.assertEqual(proc.stderr, "partial stderr\nTimed out after 7s\n")
        self.assertEqual(proc.duration_seconds, 1.234)

    def test_run_real_case_timeout_writes_fresh_artifact(self) -> None:
        label = "unit-timeout-run-real-case"
        artifact_dir = (
            rule_quality_harness.TEST_ROOT / "artifacts" / "rule_quality" / label
        )
        timeout = subprocess.TimeoutExpired(
            ["ubs"],
            1,
            output=b"started scan",
            stderr=b"still running",
        )
        manifest = {"defaults": {"args": [], "ubs_bin": "../ubs"}}
        case = {
            "args": ["--only=rust"],
            "env": {},
            "expect": {},
            "path": "test-suite/rust/buggy/sql_injection.rs",
        }

        with mock.patch.object(
            rule_quality_harness.subprocess,
            "run",
            side_effect=timeout,
        ):
            with self.assertRaisesRegex(AssertionError, "timed out after 1s"):
                rule_quality_harness.run_real_case(
                    manifest,
                    case,
                    label,
                    timeout=1,
                )

        result = load_artifact_result(artifact_dir)
        self.assertEqual(
            (artifact_dir / "stdout.log").read_text(encoding="utf-8"),
            "started scan",
        )
        self.assertEqual(
            (artifact_dir / "stderr.log").read_text(encoding="utf-8"),
            "still running\nTimed out after 1s\n",
        )
        self.assertEqual(result["exit_code"], -1)
        self.assertEqual(result["summary"], {"timed_out": True, "timeout_seconds": 1})

    def test_run_real_case_rejects_unparseable_output_without_opt_in(self) -> None:
        label = "unit-unparseable-run-real-case"
        artifact_dir = (
            rule_quality_harness.TEST_ROOT / "artifacts" / "rule_quality" / label
        )
        proc = subprocess.CompletedProcess(
            ["ubs"],
            0,
            stdout="not a UBS summary",
            stderr="",
        )
        manifest = {"defaults": {"args": [], "ubs_bin": "../ubs"}}
        case = {
            "args": ["--only=rust"],
            "env": {},
            "expect": {"exit_code": "zero"},
            "path": "test-suite/rust/buggy/sql_injection.rs",
        }

        with mock.patch.object(
            rule_quality_harness.subprocess,
            "run",
            return_value=proc,
        ):
            with self.assertRaisesRegex(AssertionError, "unparseable UBS output"):
                rule_quality_harness.run_real_case(
                    manifest,
                    case,
                    label,
                    timeout=1,
                )

        self.assertEqual(
            (artifact_dir / "stdout.log").read_text(encoding="utf-8"),
            "not a UBS summary",
        )
        result = load_artifact_result(artifact_dir)
        self.assertIsNone(result["summary"])

    def test_run_real_case_allows_unparseable_output_with_explicit_opt_in(self) -> None:
        label = "unit-unparseable-run-real-case-allowed"
        proc = subprocess.CompletedProcess(
            ["ubs"],
            0,
            stdout="expected environment failure text",
            stderr="",
        )
        manifest = {"defaults": {"args": [], "ubs_bin": "../ubs"}}
        case = {
            "args": ["--only=rust"],
            "env": {},
            "expect": {
                "allow_unparseable_output": True,
                "exit_code": "zero",
                "require_substrings": ["environment failure"],
            },
            "path": "test-suite/rust/buggy/sql_injection.rs",
        }

        with mock.patch.object(
            rule_quality_harness.subprocess,
            "run",
            return_value=proc,
        ):
            _, totals = rule_quality_harness.run_real_case(
                manifest,
                case,
                label,
                timeout=1,
            )

        self.assertEqual(totals, {"critical": 0, "warning": 0, "info": 0})


class RuleInventoryCoverageInvariantTest(unittest.TestCase):
    def test_mixed_reports_require_both_raw_and_public_rule_coverage(self) -> None:
        for label in ("js-rule-pack", "swift-rule-pack", "elixir-rule-pack"):
            with self.subTest(label=label):
                corpus = [{"label": label, "result_rule_ids": ["pack.rule", "heuristic.rule"]}]
                inventory = {"label": label, "rules": [{"id": "pack.rule"}]}
                with self.assertRaisesRegex(AssertionError, "actual generated-config corpus evidence"):
                    rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])
                inventory["generated_corpus_check"] = {"result_rule_ids": ["pack.rule"]}
                coverage = rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])
                rule_quality_harness.assert_rule_inventory_fully_covered(coverage)
                self.assertEqual(coverage[0]["covered_generated_rule_ids"], ["pack.rule"])
                for raw_ids in ([], ["pack.rule", "orphan.rule"]):
                    inventory["generated_corpus_check"] = {"result_rule_ids": raw_ids}
                    coverage = rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])
                    with self.assertRaisesRegex(AssertionError, "generated ast-grep rules"):
                        rule_quality_harness.assert_rule_inventory_fully_covered(coverage)
                inventory["generated_corpus_check"] = {"result_rule_ids": ["pack.rule"]}
                corpus[0]["result_rule_ids"] = ["heuristic.rule"]
                with self.assertRaisesRegex(AssertionError, "public report omits generated rules"):
                    rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])

    def test_rust_coverage_requires_raw_generated_evidence(self) -> None:
        corpus = [{"label": "rust-rule-pack", "result_rule_ids": ["rust.ownership.unwrap-expect"]}]
        inventory = {"label": "rust-rule-pack", "rules": [{"id": "rust.ast.expect"}]}
        with self.assertRaisesRegex(AssertionError, "actual generated-config corpus evidence"):
            rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])

        inventory["generated_corpus_check"] = {"result_rule_ids": ["rust.ast.expect"]}
        coverage = rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])
        rule_quality_harness.assert_rule_inventory_fully_covered(coverage)
        self.assertEqual(coverage[0]["covered_generated_rule_ids"], ["rust.ast.expect"])

        for raw_ids in ([], ["rust.ast.expect", "rust.ast.orphan"]):
            with self.subTest(raw_ids=raw_ids):
                inventory["generated_corpus_check"] = {"result_rule_ids": raw_ids}
                coverage = rule_quality_harness.build_rule_inventory_coverage(corpus, [inventory])
                with self.assertRaisesRegex(AssertionError, "generated ast-grep rules"):
                    rule_quality_harness.assert_rule_inventory_fully_covered(coverage)

    def test_builds_inventory_coverage_from_corpus_and_dumped_rules(self) -> None:
        coverage = rule_quality_harness.build_rule_inventory_coverage(
            [
                {
                    "label": "test-rule-pack",
                    "result_rule_ids": [
                        "js.corpus-only",
                        "js.eval-call",
                        "js.innerHTML-assign",
                    ],
                }
            ],
            [
                {
                    "label": "test-rule-pack",
                    "rules": [
                        {"id": "js.dump-only"},
                        {"id": "js.eval-call"},
                        {"id": "js.innerHTML-assign"},
                    ],
                }
            ],
        )

        self.assertEqual(
            coverage,
            [
                {
                    "label": "test-rule-pack",
                    "corpus_result_rule_ids_without_generated_rule": ["js.corpus-only"],
                    "covered_generated_rule_count": 2,
                    "covered_generated_rule_ids": ["js.eval-call", "js.innerHTML-assign"],
                    "generated_rule_count": 3,
                    "uncovered_generated_rule_count": 1,
                    "uncovered_generated_rule_ids": ["js.dump-only"],
                }
            ],
        )

    def test_accepts_fully_covered_rule_inventory(self) -> None:
        rule_quality_harness.assert_rule_inventory_fully_covered(
            [
                {
                    "label": "rust-rule-pack",
                    "corpus_result_rule_ids_without_generated_rule": [],
                    "uncovered_generated_rule_ids": [],
                }
            ]
        )

    def test_rejects_generated_rule_without_corpus_hit(self) -> None:
        with self.assertRaisesRegex(AssertionError, "rust.new-rule"):
            rule_quality_harness.assert_rule_inventory_fully_covered(
                [
                    {
                        "label": "rust-rule-pack",
                        "corpus_result_rule_ids_without_generated_rule": [],
                        "uncovered_generated_rule_ids": ["rust.new-rule"],
                    }
                ]
            )

    def test_rejects_corpus_rule_without_dumped_rule(self) -> None:
        with self.assertRaisesRegex(AssertionError, "js.ghost-rule"):
            rule_quality_harness.assert_rule_inventory_fully_covered(
                [
                    {
                        "label": "js-rule-pack",
                        "corpus_result_rule_ids_without_generated_rule": ["js.ghost-rule"],
                        "uncovered_generated_rule_ids": [],
                    }
                ]
            )


class AstGrepRulePackHelperTest(unittest.TestCase):
    def test_elixir_dump_keeps_a_runnable_config_and_reports_copy_errors(self) -> None:
        spec = next(spec for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
                    if spec["label"] == "elixir-rule-pack")
        fixture = rule_quality_harness.REPO_ROOT / spec["fixture"]
        module = rule_quality_harness.REPO_ROOT / "modules/ubs-elixir.sh"
        with tempfile.TemporaryDirectory(prefix="ubs-elixir-export-") as temp_dir:
            root = Path(temp_dir)
            custom = root / "operator's custom rules"
            custom.mkdir()
            for metadata_only in (True, False):
                with self.subTest(metadata_only=metadata_only):
                    exported = root / ("listed rules" if metadata_only else "scanned rules")
                    args = ["bash", str(module), f"--rules={custom}",
                            f"--dump-rules={exported}", "--no-mix"]
                    args += ["--list-rules"] if metadata_only else ["--format=json", str(fixture)]
                    result = subprocess.run(args, cwd=root, text=True, capture_output=True,
                                            timeout=60, check=False)
                    context = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0 if metadata_only else 1, context)
                    config = exported / "sgconfig-elixir.yml"
                    self.assertTrue(config.is_file(), context)
                    self.assertEqual(len(list((exported / "rules").glob("*.yml"))), 26, context)
                    scan = subprocess.run(
                        [*rule_quality_harness.ast_grep_command(), "scan", "--config",
                         str(config), str(fixture), "--json=stream"],
                        cwd=root, text=True, capture_output=True, timeout=30, check=False,
                    )
                    self.assertIn(scan.returncode, (0, 1), scan.stdout + scan.stderr)
                    self.assertTrue(rule_quality_harness.is_ast_grep_diagnostic_stderr(scan.stderr),
                                    scan.stderr)
                    ids = rule_quality_harness.ast_grep_json_stream_rule_ids(scan.stdout, "elixir-export")
                    self.assertEqual(set(ids), set(spec["expected_rule_ids"]))
                    if metadata_only:
                        self.assertEqual(result.stdout.splitlines(), sorted(set(ids)))

                    blocked = root / ("blocked-list" if metadata_only else "blocked-scan")
                    blocked.write_text("existing destination", encoding="utf-8")
                    args[3] = f"--dump-rules={blocked}"
                    refused = subprocess.run(args, cwd=root, text=True, capture_output=True,
                                             timeout=60, check=False)
                    self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
                    self.assertIn("Could not export Elixir rule pack", refused.stderr)
                    self.assertEqual(blocked.read_text(encoding="utf-8"), "existing destination")

    def test_go_goroutine_error_rule_uses_the_invoked_function_scope(self) -> None:
        from ubs_core.go_ast import scan_config
        from ubs_core.go_rules import generate

        rule_id = "go.async.goroutine-err-no-check"
        cases = {
            "discarded": ('go func(u string) { resp, _ := http.Get(u); use(resp) }(url)', True),
            "unchecked": ('go func() { err := work(); use(err) }()', True),
            "two_values": ('go func(a, b string) { value, err := work(a, b); use(value, err) }(x, y)', True),
            "handled": ('go func() { value, err := work(); if err != nil { return }; use(value) }()', False),
            "nested_worker": ('go func() { callback := func() { err := work(); use(err) }; use(callback) }()', False),
            "nested_handler": ('go func() { err := work(); callback := func() { if err != nil { return } }; use(callback) }()', True),
            "outside_handler": ('if err != nil { return }; go func() { err := work(); use(err) }()', True),
            "synchronous": ('func() { err := work(); use(err) }()', False),
            "map_lookup": ('go func() { value, _ := values[key]; use(value) }()', False),
            "lookalikes": ('text := `go func() { err := work() }()`; use(text) // go func() { err := work() }()', False),
        }
        with tempfile.TemporaryDirectory(prefix="ubs-go-async-rule-") as temp_dir:
            root = Path(temp_dir)
            generate(root / "rules")
            for name, (body, expected) in cases.items():
                with self.subTest(name=name):
                    source = root / f"{name}.go"
                    source.write_text(f"package main\nfunc example() {{ {body}\n}}\n", encoding="utf-8")
                    sink = io.StringIO()
                    counts, matches = scan_config(
                        root / "rules/sgconfig-go-async.yml", [source], {}, sink,
                    )
                    self.assertEqual(counts.get(rule_id, 0), int(expected), matches)
                    try:
                        records = [json.loads(line) for line in sink.getvalue().splitlines()]
                    except json.JSONDecodeError as exc:
                        self.fail(f"Invalid Go async rule NDJSON: {exc}; output={sink.getvalue()!r}")
                    self.assertEqual(len(records), int(expected), records)
                    if expected:
                        self.assertEqual(records[0]["rule"], rule_id)
                        self.assertEqual(records[0]["severity"], "warning")
                        self.assertEqual(records[0]["line"], 2)

    def test_go_ast_reports_survive_cache_hits_without_changing_counters(self) -> None:
        expected = {
            "go.os-remove-no-error-check", "go.content-type-prefix-match",
            "go.sort-slice-mutates", "go.fmt-errorf-no-wrap",
            "go.json-decode-no-limit", "go.exec-pgrep-unanchored", "go.tls-insecure-skip",
        }
        with tempfile.TemporaryDirectory(prefix="ubs-go-reports-") as temp_dir:
            root = Path(temp_dir)
            fixture = root / "report.go"
            fixture.write_text(
                'package main\nfunc hazards() {\n'
                ' os.Remove("temporary")\n'
                ' strings.HasPrefix(contentType, "application/json")\n'
                ' sort.Slice(items, less)\n'
                ' fmt.Errorf("context: %v", err)\n'
                ' json.NewDecoder(body).Decode(&value)\n'
                ' exec.Command("pgrep", pattern)\n'
                ' transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n}\n',
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update({"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(root / "cache"),
                        "UBS_ENABLE_AUTO_UPDATE": "0", "UBS_PROFILE": "1", "NO_COLOR": "1"})

            def scan(*args: str, target: Path = fixture, meta: bool = False) -> tuple[subprocess.CompletedProcess[str], dict]:
                command = [str(rule_quality_harness.REPO_ROOT / "ubs"), "--only=golang", "--no-auto-update"] if meta else [str(rule_quality_harness.REPO_ROOT / "modules/ubs-golang.sh")]
                proc = subprocess.run(
                    [*command, *args, str(target)], cwd=rule_quality_harness.REPO_ROOT,
                    env=env, capture_output=True, text=True, timeout=180, check=False,
                )
                self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"Go report is not JSON: {exc}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
                return proc, payload

            cold_proc, cold = scan("--format=json")
            self.assertEqual(cold["profile"]["cache_misses"], 1)
            self.assertEqual(cold["profile"]["cache_hits"], 0)
            cold_ast = cold["extras"]["ast_findings"]
            ast_ids = {record["rule"] for record in cold_ast}
            self.assertTrue(expected.issubset(ast_ids), sorted(ast_ids))
            self.assertFalse(any(record.get("_report_only") for record in cold["findings"]))
            self.assertFalse(any(record["rule"] in expected - {"go.tls-insecure-skip"} for record in cold["findings"]))
            warm_proc, warm = scan("--format=json")
            self.assertEqual(warm_proc.returncode, cold_proc.returncode)
            self.assertEqual(warm["profile"]["cache_hits"], 1)
            self.assertEqual(warm["profile"]["cache_misses"], 0)
            self.assertEqual(warm["extras"]["ast_findings"], cold_ast)
            self.assertEqual(warm["findings"], cold["findings"])
            counters = {key: cold[key] for key in ("critical", "warning", "info")}
            self.assertEqual({key: warm[key] for key in counters}, counters)
            for meta in (False, True):
                with self.subTest(meta=meta):
                    sarif_proc, sarif = scan("--format=sarif", meta=meta)
                    self.assertEqual(sarif_proc.returncode, cold_proc.returncode)
                    rule_quality_harness.validate_sarif_payload_shape(sarif, "Go cached AST report")
                    pack_runs = [run for run in sarif["runs"] if run["tool"]["driver"]["name"] == "ubs-golang-ast"]
                    self.assertEqual(len(pack_runs), 1)
                    self.assertEqual({result["ruleId"] for result in pack_runs[0]["results"]}, ast_ids)
            _, skipped = scan("--format=json", "--skip=16")
            self.assertEqual(skipped["extras"]["ast_findings"], [])
            clean = root / "lookalikes.go"
            clean.write_text('package main\n// os.Remove("temporary")\nvar text = `strings.HasPrefix(contentType, "application/json")`\n', encoding="utf-8")
            _, negative = scan("--format=json", target=clean)
            self.assertEqual(negative["extras"]["ast_findings"], [])

    def test_ruby_ast_reports_survive_cache_hits_without_changing_counters(self) -> None:
        spec = next(s for s in rule_quality_harness.AST_GREP_SARIF_CHECKS if s["label"] == "ruby-rule-pack")
        module = rule_quality_harness.REPO_ROOT / "modules" / spec["module"]
        fixture = rule_quality_harness.REPO_ROOT / spec["fixture"]
        with tempfile.TemporaryDirectory(prefix="ubs-ruby-reports-") as temp_dir:
            root = Path(temp_dir)
            env = os.environ.copy()
            env.update({"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(root / "cache"),
                        "UBS_ENABLE_AUTO_UPDATE": "0", "UBS_PROFILE": "1", "NO_COLOR": "1"})

            def scan(*args: str, target: Path = fixture, meta: bool = False) -> tuple[subprocess.CompletedProcess[str], dict]:
                command = [str(rule_quality_harness.REPO_ROOT / "ubs"), "--only=ruby", "--no-auto-update"] if meta else [str(module)]
                proc = subprocess.run(
                    [*command, *args, str(target)], cwd=rule_quality_harness.REPO_ROOT,
                    env=env, capture_output=True, text=True, timeout=180, check=False,
                )
                self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"Ruby report is not JSON: {exc}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
                return proc, payload

            cold_proc, cold = scan("--format=json")
            self.assertEqual(cold["profile"]["cache_misses"], 1)
            self.assertEqual(cold["profile"]["cache_hits"], 0)
            cold_ast = cold["extras"]["ast_findings"]
            ast_ids = {record["rule"] for record in cold_ast}
            self.assertTrue(set(spec["expected_rule_ids"]).issubset(ast_ids), sorted(ast_ids))
            warm_proc, warm = scan("--format=json")
            self.assertEqual(warm_proc.returncode, cold_proc.returncode)
            self.assertEqual(warm["profile"]["cache_hits"], 1)
            self.assertEqual(warm["profile"]["cache_misses"], 0)
            self.assertEqual(warm["extras"]["ast_findings"], cold_ast)
            self.assertEqual(warm["findings"], cold["findings"])
            counters = {key: cold[key] for key in ("critical", "warning", "info")}
            self.assertEqual({key: warm[key] for key in counters}, counters)

            for meta in (False, True):
                with self.subTest(meta=meta):
                    sarif_proc, sarif = scan("--format=sarif", meta=meta)
                    self.assertEqual(sarif_proc.returncode, cold_proc.returncode)
                    rule_quality_harness.validate_sarif_payload_shape(sarif, "Ruby cached AST report")
                    pack_runs = [run for run in sarif["runs"] if run["tool"]["driver"]["name"] == "ubs-ruby-ast"]
                    self.assertEqual(len(pack_runs), 1)
                    self.assertEqual({result["ruleId"] for result in pack_runs[0]["results"]}, ast_ids)

            skipped_proc, skipped = scan("--format=json", "--skip=18")
            self.assertEqual(skipped_proc.returncode, cold_proc.returncode)
            self.assertEqual({key: skipped[key] for key in counters}, counters)
            self.assertTrue(all(r["rule"] == "ruby.async.thread-no-rescue" for r in skipped["extras"]["ast_findings"]))
            clean = root / "lookalikes.rb"
            clean.write_text('# value.equal?(true)\ntext = "value == nil"\n', encoding="utf-8")
            _, negative = scan("--format=json", target=clean)
            self.assertEqual(negative["extras"]["ast_findings"], [])

    def test_java_ast_reports_survive_cache_hits_without_changing_counters(self) -> None:
        from ubs_core.java_rules import SEVERITY_MAP

        spec = next(s for s in rule_quality_harness.AST_GREP_SARIF_CHECKS if s["label"] == "java-rule-pack")
        fixture = rule_quality_harness.REPO_ROOT / spec["fixture"]
        with tempfile.TemporaryDirectory(prefix="ubs-java-reports-") as temp_dir:
            root = Path(temp_dir)
            env = os.environ.copy()
            env.update({"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(root / "cache"),
                        "UBS_ENABLE_AUTO_UPDATE": "0", "UBS_PROFILE": "1", "NO_COLOR": "1"})

            def scan(*args: str, target: Path = fixture, meta: bool = False) -> tuple[subprocess.CompletedProcess[str], dict]:
                command = [str(rule_quality_harness.REPO_ROOT / "ubs"), "--only=java", "--no-auto-update"] if meta else [str(rule_quality_harness.REPO_ROOT / "modules" / spec["module"]), "--no-build"]
                proc = subprocess.run(
                    [*command, *args, str(target)], cwd=rule_quality_harness.REPO_ROOT,
                    env=env, capture_output=True, text=True, timeout=180, check=False,
                )
                self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"Java report is not JSON: {exc}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")
                return proc, payload

            cold_proc, cold = scan("--format=json")
            self.assertEqual(cold["profile"]["cache_misses"], 1)
            self.assertEqual(cold["profile"]["cache_hits"], 0)
            cold_ast = cold["extras"]["ast_findings"]
            ast_ids = {record["rule"] for record in cold_ast}
            self.assertTrue(set(spec["expected_rule_ids"]).issubset(ast_ids), sorted(ast_ids))
            warm_proc, warm = scan("--format=json")
            self.assertEqual(warm_proc.returncode, cold_proc.returncode)
            self.assertEqual(warm["profile"]["cache_hits"], 1)
            self.assertEqual(warm["profile"]["cache_misses"], 0)
            self.assertEqual(warm["extras"]["ast_findings"], cold_ast)
            self.assertEqual(warm["findings"], cold["findings"])
            counters = {key: cold[key] for key in ("critical", "warning", "info")}
            self.assertEqual({key: warm[key] for key in counters}, counters)
            for meta in (False, True):
                with self.subTest(meta=meta):
                    sarif_proc, sarif = scan("--format=sarif", meta=meta)
                    self.assertEqual(sarif_proc.returncode, cold_proc.returncode)
                    rule_quality_harness.validate_sarif_payload_shape(sarif, "Java cached AST report")
                    pack_runs = [run for run in sarif["runs"] if run["tool"]["driver"]["name"] == "ubs-java-ast"]
                    self.assertEqual(len(pack_runs), 1)
                    self.assertEqual({result["ruleId"] for result in pack_runs[0]["results"]}, ast_ids)

            skipped_proc, skipped = scan("--format=json", "--skip=15")
            self.assertEqual(skipped_proc.returncode, cold_proc.returncode)
            self.assertEqual({key: skipped[key] for key in counters}, counters)
            self.assertTrue(all(r["rule"] in SEVERITY_MAP for r in skipped["extras"]["ast_findings"]))
            clean = root / "Lookalikes.java"
            clean.write_text('class Lookalikes { String text = "System.out.println(value)"; }\n', encoding="utf-8")
            _, negative = scan("--format=json", target=clean)
            self.assertEqual(negative["extras"]["ast_findings"], [])

    def test_ruby_thread_rule_and_invalid_configuration_are_observable(self) -> None:
        from ubs_core.ruby_ast import scan_config
        from ubs_core.ruby_rules import generate

        with tempfile.TemporaryDirectory(prefix="ubs-ruby-thread-") as temp_dir:
            root = Path(temp_dir)
            rules = root / "rules"
            generate(rules)
            fixture = root / "threads.rb"
            fixture.write_text(
                "Thread.new { work }\n"
                "Thread.new(1, 2) do |a, b|\n  work(a, b)\nend\n"
                "Thread.new do\n  begin\n    work\n  rescue StandardError\n    warn 'failed'\n  end\nend\n"
                "Pool.new { work }\n"
                "# Thread.new { work }\n"
                "text = 'Thread.new { work }'\n",
                encoding="utf-8",
            )
            sink = io.StringIO()
            counts = scan_config(
                rules / "sgconfig-ruby.yml", [fixture], sink,
                counted_rules={"ruby.async.thread-no-rescue"},
            )
            try:
                records = [json.loads(line) for line in sink.getvalue().splitlines()]
            except json.JSONDecodeError as exc:
                self.fail(f"Ruby scanner emitted invalid findings: {exc}")
            thread_records = [r for r in records if r["rule"] == "ruby.async.thread-no-rescue"]
            self.assertEqual([r["line"] for r in thread_records], [1, 2])
            self.assertEqual(counts, {"critical": 0, "warning": 2, "info": 0})

            observed_cases = (
                ("direct-join", "Thread.new { work }.join\n", 0),
                ("named-value", "worker = Thread.new { work }\nworker.value\n", 0),
                ("named-unjoined", "worker = Thread.new { work }\nother.join\n", 1),
                ("reassigned", "worker = Thread.new { work }\nworker = other\nworker.join\n", 1),
                ("array-join", "workers << Thread.new { work }\nworkers.each(&:join)\n", 0),
                ("loop-join", "10.times do\n  workers << Thread.new { work }\nend\nworkers.each(&:join)\n", 0),
                ("loop-unjoined", "10.times do\n  workers << Thread.new { work }\nend\nother.each(&:join)\n", 1),
            )
            for name, source, warnings in observed_cases:
                with self.subTest(name=name):
                    case_path = root / f"{name}.rb"
                    case_path.write_text(source, encoding="utf-8")
                    actual = scan_config(
                        rules / "sgconfig-ruby.yml", [case_path], io.StringIO(),
                        counted_rules={"ruby.async.thread-no-rescue"},
                    )
                    self.assertEqual(actual, {"critical": 0, "warning": warnings, "info": 0})

            invalid = root / "invalid.yml"
            invalid.write_text(
                "id: invalid-thread-rule\nlanguage: ruby\nrule:\n  contains:\n    kind: rescue\n",
                encoding="utf-8",
            )
            config = root / "sgconfig.yml"
            config.write_text("ruleDirs:\n  - invalid.yml\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Ruby AST scan failed.*exit 8"):
                scan_config(config, [fixture], io.StringIO())
            with self.assertRaisesRegex(RuntimeError, "configuration is missing"):
                scan_config(root / "absent.yml", [fixture], io.StringIO())

    def test_repaired_rust_rules_match_syntax_without_comment_or_string_lookalikes(self) -> None:
        repaired = {
            "assert", "assert_eq", "assert_ne", "await_in_for", "http_url", "md5", "sha1",
            "std_guard_await_expect", "std_guard_await_unwrap", "std_lock_async_lock",
            "std_lock_async_read", "std_lock_async_write", "tokio_guard_lock",
            "tokio_guard_read", "tokio_guard_write",
        }
        expected = {f"rust.ast.{slug}" for slug in repaired}
        fixture = rule_quality_harness.REPO_ROOT / "test-suite/rust/buggy/ast_grep_rule_pack_coverage.rs"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            subprocess.run(
                [sys.executable, str(rule_quality_harness.REPO_ROOT / "modules/helpers/ubs_core/rust_rules.py"),
                 str(root / "rules")],
                capture_output=True, text=True, timeout=30, check=True,
            )
            clean = root / "lookalikes.rs"
            clean.write_text(
                'fn ordinary(lock: Mutex<i32>) {\n'
                '    lock.lock();\n'
                '    let _ = "assert!(false); md5::compute(bytes); sha1::digest(bytes)";\n'
                '    let _ = "https://example.invalid";\n'
                '    let _ = "prefix http://example.invalid";\n'
                '    // "http://example.invalid"\n'
                '    // async fn f() { let g = lock.lock().unwrap(); work().await; }\n'
                '}\n'
                'async fn await_before_guard(lock: Mutex<i32>) {\n'
                '    work().await;\n'
                '    let guard = lock.lock().unwrap();\n'
                '}\n'
                'async fn nested_sync() {\n'
                '    fn ordinary(lock: Mutex<i32>) { lock.lock(); }\n'
                '}\n',
                encoding="utf-8",
            )
            for path, required in ((fixture, expected), (clean, set())):
                proc = subprocess.run(
                    [*rule_quality_harness.ast_grep_command(), "scan", "--config",
                     str(root / "rules/sgconfig-rust.yml"), str(path), "--json=stream"],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                self.assertIn(proc.returncode, (0, 1), proc.stderr)
                self.assertTrue(rule_quality_harness.is_ast_grep_diagnostic_stderr(proc.stderr), proc.stderr)
                hits = set(rule_quality_harness.ast_grep_json_stream_rule_ids(proc.stdout, str(path)))
                self.assertEqual(hits & expected, required)

    def test_ast_grep_rule_pack_specs_include_swift_dumpable_rules(self) -> None:
        specs = {
            spec["label"]: spec
            for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
        }

        self.assertIn("swift-rule-pack", specs)
        self.assertEqual(specs["swift-rule-pack"]["module"], "ubs-swift.sh")
        self.assertIn(
            "swift.urlsession.task-no-resume",
            specs["swift-rule-pack"]["expected_rule_ids"],
        )

    def test_ast_grep_rule_pack_specs_include_ruby_dumpable_rules(self) -> None:
        specs = {
            spec["label"]: spec
            for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
        }

        self.assertIn("ruby-rule-pack", specs)
        self.assertEqual(specs["ruby-rule-pack"]["module"], "ubs-ruby.sh")
        self.assertIn(
            "ruby.resource.thread-no-join",
            specs["ruby-rule-pack"]["expected_rule_ids"],
        )
        self.assertIn(
            "rb.rescue-exception",
            specs["ruby-rule-pack"]["expected_rule_ids"],
        )

    def test_ast_grep_rule_pack_specs_include_java_dumpable_rules(self) -> None:
        specs = {
            spec["label"]: spec
            for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
        }

        self.assertIn("java-rule-pack", specs)
        self.assertEqual(specs["java-rule-pack"]["module"], "ubs-java.sh")
        self.assertIn("--no-build", specs["java-rule-pack"]["args"])
        self.assertIn(
            "java.resource.executor-no-shutdown",
            specs["java-rule-pack"]["expected_rule_ids"],
        )
        self.assertIn(
            "java.insecure-deserialization",
            specs["java-rule-pack"]["expected_rule_ids"],
        )

    def test_ast_grep_rule_pack_specs_include_csharp_dumpable_rules(self) -> None:
        specs = {
            spec["label"]: spec
            for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
        }

        self.assertIn("csharp-rule-pack", specs)
        self.assertEqual(specs["csharp-rule-pack"]["module"], "ubs-csharp.sh")
        self.assertIn("--no-dotnet", specs["csharp-rule-pack"]["args"])
        for rule_id in (
            "cs-async-discarded-startnew",
            "cs-async-discarded-task-run",
            "cs-await-in-lock",
            "cs-parallel-foreach-async-lambda",
        ):
            self.assertIn(rule_id, specs["csharp-rule-pack"]["expected_rule_ids"])

    def test_parses_machine_readable_list_rule_ids(self) -> None:
        rule_ids = rule_quality_harness.parse_list_rule_ids(
            "go.exec-sh-c\nrust.unwrap-call\n",
            "fixture",
        )

        self.assertEqual(rule_ids, ["go.exec-sh-c", "rust.unwrap-call"])

    def test_rejects_banner_text_in_list_rule_ids(self) -> None:
        with self.assertRaisesRegex(AssertionError, "non-rule text"):
            rule_quality_harness.parse_list_rule_ids(
                "banner text\nswift.urlsession.task-no-resume\n",
                "fixture",
            )

    def test_rejects_unsorted_or_duplicate_list_rule_ids(self) -> None:
        with self.assertRaisesRegex(AssertionError, "sorted and unique"):
            rule_quality_harness.parse_list_rule_ids(
                "rust.unwrap-call\nrust.arc-mutex\nrust.unwrap-call\n",
                "fixture",
            )

    def test_accepts_list_rule_ids_that_match_dumped_rules(self) -> None:
        rule_quality_harness.assert_list_rule_ids_match_dumped_rules(
            [{"label": "swift-rule-pack", "rule_ids": ["swift.urlsession.task-no-resume"]}],
            [
                {
                    "label": "swift-rule-pack",
                    "rules": [{"id": "swift.urlsession.task-no-resume"}],
                }
            ],
        )

    def test_rejects_list_rule_ids_that_drift_from_dumped_rules(self) -> None:
        with self.assertRaisesRegex(AssertionError, "listed_not_dumped"):
            rule_quality_harness.assert_list_rule_ids_match_dumped_rules(
                [{"label": "js-rule-pack", "rule_ids": ["js.ghost-rule"]}],
                [{"label": "js-rule-pack", "rules": [{"id": "js.eval-call"}]}],
            )

    def test_counts_ast_grep_json_stream_objects(self) -> None:
        rule_ids = rule_quality_harness.ast_grep_json_stream_rule_ids(
            '{"ruleId":"go.exec-sh-c"}\n\n{"ruleId":"rust.unwrap-call"}\n',
            "fixture",
        )

        self.assertEqual(rule_ids, ["go.exec-sh-c", "rust.unwrap-call"])

    def test_rejects_invalid_ast_grep_json_stream_output(self) -> None:
        with self.assertRaisesRegex(AssertionError, "emitted invalid JSON stream output"):
            rule_quality_harness.ast_grep_json_stream_rule_ids(
                '{"ruleId":"ts.non-null-assertion-chain"}\nnot json\n',
                "fixture",
            )

    def test_rejects_non_object_or_missing_id_ast_stream_records(self) -> None:
        for record in (None, [], "rust.ast.expect", {}, {"ruleId": " "}, {"ruleId": 2}):
            with self.subTest(record=record):
                with self.assertRaisesRegex(AssertionError, "non-empty ruleId"):
                    rule_quality_harness.ast_grep_json_stream_rule_ids(json.dumps(record), "fixture")

    def test_generated_config_is_distinct_from_rules_but_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rule_path = root / "expect.yml"
            rule_path.write_text("id: rust.ast.expect\nlanguage: rust\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "missing generated ast-grep config"):
                rule_quality_harness.generated_rule_paths(root, "sgconfig-rust.yml")
            (root / "sgconfig-rust.yml").write_text("ruleDirs:\n  - ./expect.yml\n", encoding="utf-8")
            self.assertEqual(
                rule_quality_harness.generated_rule_paths(root, "sgconfig-rust.yml"), [rule_path]
            )
            malformed = root / "malformed.yaml"
            malformed.write_text("language: rust\n", encoding="utf-8")
            paths = rule_quality_harness.generated_rule_paths(root, "sgconfig-rust.yml")
            self.assertIn(malformed, paths, "only the explicitly declared config is excluded")
            with self.assertRaisesRegex(AssertionError, "missing 'id'"):
                for path in paths:
                    rule_quality_harness.read_yaml_scalar(path.read_text(encoding="utf-8"), "id")

    def test_nested_rule_inventory_requires_declared_configs_and_keeps_invalid_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "rules"
            nested.mkdir()
            rule = nested / "thread.yml"
            rule.write_text("id: ruby.async.thread-no-rescue\nlanguage: ruby\n", encoding="utf-8")
            configs = ("sgconfig-ruby.yml", "sgbase-ruby.yml")
            (root / configs[0]).write_text("ruleDirs:\n  - rules\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "sgbase-ruby.yml"):
                rule_quality_harness.generated_rule_paths(root, None, configs)
            (root / configs[1]).write_text("ruleDirs:\n  - rules\n", encoding="utf-8")
            self.assertEqual(rule_quality_harness.generated_rule_paths(root, None, configs), [rule])
            invalid = nested / "sgconfig-unexpected.yml"
            invalid.write_text("language: ruby\n", encoding="utf-8")
            paths = rule_quality_harness.generated_rule_paths(root, None, configs)
            self.assertIn(invalid, paths)
            with self.assertRaisesRegex(AssertionError, "missing 'id'"):
                rule_quality_harness.read_yaml_scalar(invalid.read_text(encoding="utf-8"), "id")

    def test_accepts_only_expected_ast_grep_diagnostic_stderr(self) -> None:
        self.assertTrue(rule_quality_harness.is_ast_grep_diagnostic_stderr(""))
        self.assertTrue(
            rule_quality_harness.is_ast_grep_diagnostic_stderr(
                "error(s) found in code\nScan succeeded"
            )
        )
        self.assertFalse(
            rule_quality_harness.is_ast_grep_diagnostic_stderr("Cannot parse rule")
        )


class SarifShapeTest(unittest.TestCase):
    def test_grouped_sarif_requires_the_exact_source_site_and_level(self) -> None:
        spec = next(
            spec for spec in rule_quality_harness.AST_GREP_SARIF_CHECKS
            if spec["label"] == "rust-rule-pack"
        )
        fixture = rule_quality_harness.REPO_ROOT / spec["fixture"]
        lines = fixture.read_text(encoding="utf-8").splitlines()
        payload = {"runs": [{"results": []}]}
        for rule_id, anchor, offset, level in spec["expected_sites"]:
            line = next(i + 1 for i, text in enumerate(lines) if anchor in text) + offset
            payload["runs"][0]["results"].append({
                "ruleId": rule_id, "level": level,
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": fixture.as_uri()},
                    "region": {"startLine": line},
                }}],
            })
        sites = rule_quality_harness.validate_sarif_expected_sites(payload, spec, "fixture")
        self.assertEqual(len(sites), 4)
        # Corpus mode must still check the original file, not try reading a directory.
        self.assertEqual(
            rule_quality_harness.validate_sarif_expected_sites(
                payload, rule_quality_harness.corpus_sarif_spec(spec), "corpus"
            ), sites,
        )
        unchecked = payload["runs"][0]["results"][1]
        location = unchecked["locations"][0]["physicalLocation"]
        actual_line = location["region"]["startLine"]
        other_site = next(i + 1 for i, text in enumerate(lines) if "std::hint::unreachable_unchecked()" in text)
        location["region"]["startLine"] = other_site
        with self.assertRaisesRegex(AssertionError, "missing error rust.panic.unchecked-ub"):
            rule_quality_harness.validate_sarif_expected_sites(payload, spec, "fixture")
        location["region"]["startLine"] = actual_line
        location["artifactLocation"]["uri"] = "different.rs"
        with self.assertRaisesRegex(AssertionError, "missing error rust.panic.unchecked-ub"):
            rule_quality_harness.validate_sarif_expected_sites(payload, spec, "fixture")
        location["artifactLocation"]["uri"] = spec["fixture"]
        unchecked["level"] = "note"
        with self.assertRaisesRegex(AssertionError, "missing error rust.panic.unchecked-ub"):
            rule_quality_harness.validate_sarif_expected_sites(payload, spec, "fixture")
        unchecked["level"] = "error"
        self.assertEqual(rule_quality_harness.validate_sarif_expected_sites(payload, spec, "fixture"), sites)

    @staticmethod
    def valid_payload() -> dict[str, Any]:
        return {
            "runs": [
                {
                    "results": [
                        {
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "fixture.go"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                            "message": {"text": "command uses shell interpolation"},
                            "ruleId": "go.exec-sh-c",
                        }
                    ],
                    "tool": {"driver": {"name": "UBS"}},
                }
            ]
        }

    def test_accepts_usable_sarif_result_shape(self) -> None:
        rule_quality_harness.validate_sarif_payload_shape(
            self.valid_payload(),
            "fixture",
        )

    def test_rejects_result_without_rule_id(self) -> None:
        payload = self.valid_payload()
        payload["runs"][0]["results"][0]["ruleId"] = ""

        with self.assertRaisesRegex(AssertionError, "non-empty ruleId"):
            rule_quality_harness.validate_sarif_payload_shape(payload, "fixture")

    def test_rejects_result_without_message_text(self) -> None:
        payload = self.valid_payload()
        payload["runs"][0]["results"][0]["message"] = {"text": "   "}

        with self.assertRaisesRegex(AssertionError, "message text"):
            rule_quality_harness.validate_sarif_payload_shape(payload, "fixture")

    def test_rejects_result_without_usable_location(self) -> None:
        payload = self.valid_payload()
        payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ] = {"startLine": 0}

        with self.assertRaisesRegex(AssertionError, "positive startLine"):
            rule_quality_harness.validate_sarif_payload_shape(payload, "fixture")

    def test_rejects_boolean_start_line(self) -> None:
        payload = self.valid_payload()
        payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ] = {"startLine": True}

        with self.assertRaisesRegex(AssertionError, "positive startLine"):
            rule_quality_harness.validate_sarif_payload_shape(payload, "fixture")


class RunManifestExpectationTest(unittest.TestCase):
    @staticmethod
    def minimal_manifest_case() -> dict[str, Any]:
        return {
            "args": ["--only=js"],
            "description": "schema-valid fixture",
            "expect": {
                "exit_code": "nonzero",
                "require_substrings": ["eval"],
                "totals": {"critical": {"min": 1}},
            },
            "id": "js-schema-valid",
            "language": "js",
            "path": "test-suite/js/buggy/security.js",
            "tags": ["js", "buggy", "security"],
        }

    def test_manifest_schema_accepts_current_manifest(self) -> None:
        self.assertEqual(
            rule_quality_harness.manifest_schema_errors(
                rule_quality_harness.load_manifest()
            ),
            [],
        )

    def test_manifest_schema_rejects_false_green_expectation_shapes(self) -> None:
        case = self.minimal_manifest_case()
        case["expect"] = {
            "allow_zero_files": "false",
            "allow_unparseable_output": "false",
            "exit_code": True,
            "require_substrings": "eval",
            "totals": {"critical": {"min": "1"}},
        }

        errors = rule_quality_harness.manifest_schema_errors({"cases": [case]})

        self.assertIn(
            "case js-schema-valid.expect.exit_code must be an integer or string",
            errors,
        )
        self.assertIn(
            "case js-schema-valid.expect.require_substrings must be a list of strings",
            errors,
        )
        self.assertIn(
            "case js-schema-valid.expect.totals.critical.min must be a non-negative integer",
            errors,
        )
        self.assertIn(
            "case js-schema-valid.expect.allow_unparseable_output must be a boolean",
            errors,
        )
        self.assertIn(
            "case js-schema-valid.expect.allow_zero_files must be a boolean",
            errors,
        )

    def test_manifest_schema_rejects_scalar_command_fields(self) -> None:
        case = self.minimal_manifest_case()
        case.update(
            {
                "args": "--only=js",
                "bin_shims": {"ast-grep": ["not script text"]},
                "enabled": "false",
                "env": {"UBS_TEST_FORCE_NO_AST_GREP": 1},
            }
        )

        errors = rule_quality_harness.manifest_schema_errors(
            {
                "defaults": {"args": "--ci", "env": {"NO_COLOR": 1}},
                "cases": [case],
            }
        )

        self.assertIn("defaults.args must be a list of strings", errors)
        self.assertIn("defaults.env.NO_COLOR must be a string", errors)
        self.assertIn("case js-schema-valid.args must be a list of strings", errors)
        self.assertIn("case js-schema-valid.enabled must be a boolean", errors)
        self.assertIn(
            "case js-schema-valid.env.UBS_TEST_FORCE_NO_AST_GREP must be a string",
            errors,
        )
        self.assertIn("case js-schema-valid.bin_shims.ast-grep must be script text", errors)

    def test_manifest_schema_accepts_rule_ids_expectations(self) -> None:
        case = self.minimal_manifest_case()
        case["expect"] = {
            "exit_code": "nonzero",
            "rule_ids": {
                "min": {"py.security.sql-injection": 1, "py.security.command-injection": 2},
                "forbid": ["py.security.hardcoded-secrets"],
            },
        }
        errors = rule_quality_harness.manifest_schema_errors({"cases": [case]})
        self.assertEqual(errors, [])

    def test_manifest_schema_rejects_invalid_rule_ids_expectations(self) -> None:
        case = self.minimal_manifest_case()
        case["expect"] = {
            "rule_ids": {
                "min": "not-a-dict",
                "forbid": "not-a-list",
                "unsupported_key": 123,
            }
        }
        errors = rule_quality_harness.manifest_schema_errors({"cases": [case]})
        self.assertIn("case js-schema-valid.expect.rule_ids.min must be a non-empty object", errors)
        self.assertIn("case js-schema-valid.expect.rule_ids.forbid must be a list of strings", errors)
        self.assertIn("case js-schema-valid.expect.rule_ids.unsupported_key is not supported", errors)

        case["expect"] = {
            "rule_ids": {
                "min": {"valid.rule": -1, "": 1},
            }
        }
        errors = rule_quality_harness.manifest_schema_errors({"cases": [case]})
        self.assertIn("case js-schema-valid.expect.rule_ids.min keys must be non-empty strings", errors)
        self.assertIn("case js-schema-valid.expect.rule_ids.min.valid.rule must be a non-negative integer", errors)

        case["expect"] = {"rule_ids": {}}
        errors = rule_quality_harness.manifest_schema_errors({"cases": [case]})
        self.assertIn("case js-schema-valid.expect.rule_ids must be a non-empty object", errors)

    def test_extract_json_summary_skips_jsonl_findings(self) -> None:
        stdout = "\n".join(
            [
                '{"ruleId":"js.eval-call","severity":"critical","message":"eval"}',
                '{"project":"fixture","totals":{"files":1,"critical":2,"warning":3,"info":4}}',
                "trailing text",
            ]
        )

        summary = rule_quality_harness.extract_json_from_stdout(stdout)

        self.assertIsNotNone(summary)
        self.assertEqual(summary["totals"]["critical"], 2)
        self.assertEqual(summary["totals"]["warning"], 3)

    def test_extract_json_summary_accepts_direct_module_counts(self) -> None:
        summary = rule_quality_harness.extract_json_from_stdout(
            '{"project":"fixture","files":1,"critical":0,"warning":6,"info":2}'
        )

        self.assertIsNotNone(summary)
        self.assertEqual(summary["files"], 1)
        self.assertEqual(summary["warning"], 6)

    def test_extract_json_summary_rejects_unknown_json_noise(self) -> None:
        summary = rule_quality_harness.extract_json_from_stdout(
            "\n".join(
                [
                    '{"event":"progress","ok":true}',
                    '{"ruleId":"go.exec-sh-c","severity":"critical","message":"shell"}',
                ]
            )
        )

        self.assertIsNone(summary)

    def test_extract_json_summary_rejects_non_integer_counts(self) -> None:
        summary = rule_quality_harness.extract_json_from_stdout(
            '{"project":"fixture","totals":{"files":1,"critical":false,"warning":0,"info":0}}'
        )

        self.assertIsNone(summary)

    def test_parse_toon_summary_sums_scanner_totals(self) -> None:
        stdout = "\n".join(
            [
                "scanners[",
                "  scanner: js",
                "  critical: 1",
                "  warning: 2",
                "  info: 3",
                "  files: 4",
                "  scanner: rust",
                "  critical: 5",
                "  warning: 6",
                "  info: 7",
                "  files: 8",
                "]",
                "findings[",
                "]",
            ]
        )

        summary = rule_quality_harness.parse_toon_summary(stdout, "fixture")

        self.assertIsNotNone(summary)
        self.assertEqual(
            summary["totals"],
            {"critical": 6, "warning": 8, "info": 10, "files": 12},
        )

    def test_parse_meta_runner_text_summary(self) -> None:
        summary = rule_quality_harness.parse_text_summary(
            "\n".join(
                [
                    "scanner output",
                    "──────── Combined Summary ────────",
                    "Files: 12",
                    "Critical: 3",
                    "Warning: 4",
                    "Info: 5",
                ]
            ),
            "fixture",
        )

        self.assertIsNotNone(summary)
        self.assertEqual(
            summary["totals"],
            {"files": 12, "critical": 3, "warning": 4, "info": 5},
        )

    def test_parse_direct_module_text_summary(self) -> None:
        summary = rule_quality_harness.parse_module_text_summary(
            "\n".join(
                [
                    "module output",
                    "Summary Statistics:",
                    "Files scanned:    6",
                    "Critical issues:  1",
                    "Warning issues:   2",
                    "Info items:       3",
                ]
            ),
            "fixture",
        )

        self.assertIsNotNone(summary)
        self.assertEqual(
            summary["totals"],
            {"files": 6, "critical": 1, "warning": 2, "info": 3},
        )

    def test_check_expectations_derives_fail_on_warning_exit(self) -> None:
        errors = rule_quality_harness.check_expectations(
            {"exit_code": "zero"},
            exit_code=0,
            summary={"totals": {"critical": 0, "warning": 1, "info": 0, "files": 1}},
            stdout="",
            stderr="",
            fail_on_warning=True,
        )

        self.assertIn("expected exit 0 but derived 1", errors)

    def test_check_expectations_rejects_zero_file_summaries(self) -> None:
        errors = rule_quality_harness.check_expectations(
            {"exit_code": "zero"},
            exit_code=0,
            summary={"totals": {"critical": 0, "warning": 0, "info": 0, "files": 0}},
            stdout="",
            stderr="",
            fail_on_warning=False,
        )

        self.assertIn("summary reported zero scanned files", errors)

    def test_check_expectations_allows_explicit_zero_file_opt_in(self) -> None:
        errors = rule_quality_harness.check_expectations(
            {"allow_zero_files": True, "exit_code": "zero"},
            exit_code=0,
            summary={"totals": {"critical": 0, "warning": 0, "info": 0, "files": 0}},
            stdout="",
            stderr="",
            fail_on_warning=False,
        )

        self.assertEqual(errors, [])

    def test_check_expectations_enforces_substrings_and_totals(self) -> None:
        errors = rule_quality_harness.check_expectations(
            {
                "totals": {
                    "critical": {"min": 1},
                    "warning": {"max": 0},
                },
                "require_substrings": ["must appear"],
                "forbid_substrings": ["must not appear"],
            },
            exit_code=0,
            summary={"totals": {"critical": 0, "warning": 2, "info": 0, "files": 1}},
            stdout="must not appear",
            stderr="",
            fail_on_warning=False,
        )

        self.assertIn("critical count 0 < min 1", errors)
        self.assertIn("warning count 2 > max 0", errors)
        self.assertIn("missing substring 'must appear' in stdout", errors)
        self.assertIn("forbidden substring 'must not appear' present in stdout", errors)

    def test_missing_selected_case_ids_rejects_typos(self) -> None:
        missing = rule_quality_harness.missing_selected_case_ids(
            [
                {"id": "rust-request-body-limit-buggy"},
                {"id": "golang-request-body-limit-clean"},
            ],
            {
                "golang-request-body-limit-clean",
                "not-a-case",
                "rust-request-body-limit-buggy",
            },
        )

        self.assertEqual(missing, ["not-a-case"])

    def test_missing_selected_case_ids_ignores_cases_without_ids(self) -> None:
        missing = rule_quality_harness.missing_selected_case_ids(
            [
                {"id": "js-typescript-request-body-limit-buggy"},
                {"description": "malformed manifest entry"},
            ],
            {"js-typescript-request-body-limit-buggy"},
        )

        self.assertEqual(missing, [])

    def test_invalid_case_id_labels_rejects_missing_or_blank_ids(self) -> None:
        invalid = rule_quality_harness.invalid_case_id_labels(
            [
                {"id": "rust-sql-injection-buggy"},
                {"id": ""},
                {"description": "missing id"},
                {"id": "   "},
            ]
        )

        self.assertEqual(
            invalid,
            ["manifest case #2", "manifest case #3", "manifest case #4"],
        )

    def test_empty_manifest_error_rejects_zero_case_manifest(self) -> None:
        self.assertEqual(
            rule_quality_harness.empty_manifest_error([]),
            "manifest must contain at least one case",
        )
        self.assertIsNone(
            rule_quality_harness.empty_manifest_error(
                [{"id": "js-typescript-sql-injection-buggy"}]
            )
        )

    def test_duplicate_case_ids_rejects_ambiguous_focused_runs(self) -> None:
        duplicates = rule_quality_harness.duplicate_case_ids(
            [
                {"id": "rust-sql-injection-buggy"},
                {"id": "golang-ssrf-clean"},
                {"id": "rust-sql-injection-buggy"},
                {"id": "golang-ssrf-clean"},
                {"id": "js-typescript-request-body-limit-clean"},
                {"description": "missing id is handled by a separate preflight"},
            ]
        )

        self.assertEqual(duplicates, ["golang-ssrf-clean", "rust-sql-injection-buggy"])

    def test_disabled_case_ids_fail_only_selected_scope(self) -> None:
        cases = [
            {"id": "js-typescript-sql-injection-buggy", "enabled": False},
            {"id": "golang-ssrf-clean", "enabled": False},
            {"id": "rust-request-body-limit-clean"},
        ]

        self.assertEqual(
            rule_quality_harness.disabled_case_ids(
                cases,
                {"rust-request-body-limit-clean"},
            ),
            [],
        )
        self.assertEqual(
            rule_quality_harness.disabled_case_ids(cases, set()),
            ["golang-ssrf-clean", "js-typescript-sql-injection-buggy"],
        )


class CommandConstructionTest(unittest.TestCase):
    @staticmethod
    def manifest() -> dict[str, object]:
        return {
            "defaults": {
                "args": ["--ci"],
                "ubs_bin": "../ubs",
            }
        }

    def test_meta_runner_uses_relative_repo_path_for_repo_local_override(self) -> None:
        command = rule_quality_harness.command_for_case(
            self.manifest(),
            {
                "args": ["--only=rust"],
                "path": "test-suite/rust/buggy/request_body_limit.rs",
            },
            rule_quality_harness.REPO_ROOT / "test-suite/rust/buggy/request_body_limit.rs",
        )

        self.assertEqual(command[-1], "test-suite/rust/buggy/request_body_limit.rs")

    def test_meta_runner_uses_parent_directory_for_external_file_variant(self) -> None:
        external_file = Path("/etc/hosts")
        self.assertTrue(external_file.is_file())

        command = rule_quality_harness.command_for_case(
            self.manifest(),
            {
                "args": ["--only=golang"],
                "path": "test-suite/golang/security/request_body_limit_buggy.go",
            },
            external_file,
        )

        self.assertEqual(command[-1], "/etc")

    def test_direct_module_keeps_external_file_variant_path(self) -> None:
        external_file = Path("/etc/hosts")
        self.assertTrue(external_file.is_file())

        command = rule_quality_harness.command_for_case(
            self.manifest(),
            {
                "args": ["--format=json"],
                "path": "test-suite/js/security/request-body-limit-buggy.ts",
                "ubs_bin": "../modules/ubs-js.sh",
            },
            external_file,
        )

        self.assertEqual(command[-1], "/etc/hosts")


class ScopeConstructionTest(unittest.TestCase):
    @staticmethod
    def case(case_id: str, language: str, tags: list[str]) -> dict[str, object]:
        return {
            "expect": {},
            "id": case_id,
            "language": language,
            "path": f"test-suite/{language}/{case_id}",
            "tags": tags,
        }

    def test_runtime_campaign_scope_uses_target_pairs_and_behavior_cases(self) -> None:
        pairs = [
            {"buggy_case": "js-buggy", "clean_case": "js-clean", "language": "js"},
            {
                "buggy_case": "python-buggy",
                "clean_case": "python-clean",
                "language": "python",
            },
        ]
        cases = [
            self.case("js-behavior-buggy", "js", ["async", "buggy"]),
            self.case("golang-behavior-clean", "golang", ["resource", "clean"]),
            self.case("rust-security-excluded", "rust", ["async", "security", "buggy"]),
            self.case("python-behavior-buggy", "python", ["async", "buggy"]),
        ]

        scopes = rule_quality_harness.runtime_scopes_from_pairs(pairs, cases)

        self.assertEqual(
            scopes["campaign"],
            [
                "js-buggy",
                "js-clean",
                "js-behavior-buggy",
                "golang-behavior-clean",
            ],
        )
        self.assertEqual(
            scopes["all"],
            ["js-buggy", "js-clean", "python-buggy", "python-clean"],
        )

    def test_robustness_campaign_clean_fuzz_scope_uses_clean_target_cases(self) -> None:
        pairs = [
            {"buggy_case": "rust-buggy", "clean_case": "rust-clean", "language": "rust"},
            {
                "buggy_case": "python-buggy",
                "clean_case": "python-clean",
                "language": "python",
            },
        ]
        cases = [
            self.case("js-behavior-buggy", "js", ["type-narrowing", "buggy"]),
            self.case("js-behavior-clean", "js", ["type-narrowing", "clean"]),
            self.case("python-behavior-clean", "python", ["type-narrowing", "clean"]),
        ]

        scopes = rule_quality_harness.robustness_scopes_from_pairs(pairs, cases)

        self.assertEqual(
            scopes["campaign"]["metamorphic"],
            ["rust-buggy", "rust-clean", "js-behavior-buggy", "js-behavior-clean"],
        )
        self.assertEqual(
            scopes["campaign"]["clean_fuzz"],
            ["rust-clean", "js-behavior-clean"],
        )
        self.assertEqual(
            scopes["all"]["metamorphic"],
            [
                "rust-buggy",
                "rust-clean",
                "python-buggy",
                "python-clean",
                "js-behavior-buggy",
                "js-behavior-clean",
            ],
        )
        self.assertEqual(
            scopes["all"]["clean_fuzz"],
            ["rust-clean", "python-clean", "js-behavior-clean"],
        )


class MetamorphicTransformTest(unittest.TestCase):
    def test_target_languages_get_comment_and_whitespace_transforms(self) -> None:
        for language in ("js", "golang", "rust"):
            with self.subTest(language=language):
                self.assertEqual(
                    rule_quality_harness.metamorphic_transforms_for_case(
                        {"language": language}
                    ),
                    ("comments", "whitespace"),
                )

        self.assertEqual(
            rule_quality_harness.metamorphic_transforms_for_case({"language": "python"}),
            ("comments",),
        )

    def test_comment_transform_uses_language_comment_prefix(self) -> None:
        js_source = rule_quality_harness.transform_source(
            "const answer = 42;\n",
            Path("fixture.ts"),
            "comments",
        )
        ruby_source = rule_quality_harness.transform_source(
            "answer = 42\n",
            Path("fixture.rb"),
            "comments",
        )

        self.assertTrue(js_source.startswith("// UBS rule-quality benign metamorphic marker"))
        self.assertTrue(ruby_source.startswith("# UBS rule-quality benign metamorphic marker"))

    def test_whitespace_transform_adds_crlf_padding(self) -> None:
        transformed = rule_quality_harness.transform_source(
            "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n",
            Path("fixture.rs"),
            "whitespace",
        )

        self.assertTrue(transformed.startswith("\r\nline1"))
        self.assertIn("line4\r\n\r\nline5", transformed)
        self.assertTrue(transformed.endswith("\r\n"))

    def test_unknown_transform_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "unknown source transform"):
            rule_quality_harness.transform_source(
                "let x = 1;",
                Path("fixture.ts"),
                "delete-code",
            )


class TargetCleanBaselineBudgetTest(unittest.TestCase):
    @staticmethod
    def baseline_case(
        case_id: str,
        warning_max: int = 0,
        forbid_substrings: list[str] | None = None,
    ) -> dict[str, object]:
        expect: dict[str, object] = {
            "exit_code": "zero",
            "totals": {
                "critical": {"max": 0},
                "warning": {"max": warning_max},
            },
        }
        if forbid_substrings is not None:
            expect["forbid_substrings"] = forbid_substrings
        return {
            "expect": expect,
            "id": case_id,
            "language": case_id.split("-", 1)[0],
            "path": f"test-suite/{case_id}",
            "tags": ["clean"],
        }

    def test_rejects_missing_target_clean_baseline_case(self) -> None:
        cases = [
            self.baseline_case(case_id)
            for case_id in rule_quality_harness.TARGET_CLEAN_BASELINE_CASE_IDS[:-1]
        ]

        with self.assertRaisesRegex(AssertionError, "rust-clean"):
            rule_quality_harness.target_clean_baseline_budgets(cases)

    def test_records_target_clean_warning_budget_and_forbid_counts(self) -> None:
        cases = [
            self.baseline_case(
                case_id,
                warning_max=2 if case_id == "js-module-clean" else 0,
                forbid_substrings=["danger", "panic"] if case_id == "rust-clean" else [],
            )
            for case_id in rule_quality_harness.TARGET_CLEAN_BASELINE_CASE_IDS
        ]

        budget = rule_quality_harness.target_clean_baseline_budgets(cases)

        self.assertEqual(
            budget["case_count"],
            len(rule_quality_harness.TARGET_CLEAN_BASELINE_CASE_IDS),
        )
        self.assertEqual(
            budget["strict_zero_case_count"],
            len(rule_quality_harness.TARGET_CLEAN_BASELINE_CASE_IDS) - 1,
        )
        self.assertEqual(budget["warning_budget_total"], 2)
        rust_case = next(case for case in budget["cases"] if case["id"] == "rust-clean")
        self.assertEqual(rust_case["forbid_substring_count"], 2)


class ExpectationStrengthScopeTest(unittest.TestCase):
    def test_language_filter_separates_target_and_all_supported_debt(self) -> None:
        runtime_scopes = {"all": ["js-clean", "python-clean"]}
        cases = [
            {
                "expect": {
                    "exit_code": "zero",
                    "forbid_substrings": ["JS warning text"],
                    "totals": {"critical": {"max": 0}, "warning": {"max": 0}},
                },
                "id": "js-clean",
                "language": "js",
                "path": "test-suite/js/clean/example.js",
                "tags": ["js", "clean"],
            },
            {
                "expect": {
                    "exit_code": "zero",
                    "totals": {"critical": {"max": 0}, "warning": {"max": 2}},
                },
                "id": "python-clean",
                "language": "python",
                "path": "test-suite/python/clean/example.py",
                "tags": ["python", "clean"],
            },
        ]

        target = rule_quality_harness.expectation_strength_scopes_from_runtime(
            runtime_scopes,
            cases,
            {"js"},
        )
        all_supported = rule_quality_harness.expectation_strength_scopes_from_runtime(
            runtime_scopes,
            cases,
            {"js", "python"},
        )

        self.assertEqual(target["all"]["weak_case_count"], 0)
        self.assertEqual(all_supported["all"]["weak_case_count"], 1)
        self.assertEqual(
            all_supported["all"]["weak_cases"][0]["reasons"],
            [
                "clean_missing_forbid_substrings",
                "clean_not_strict_zero_critical_warning",
            ],
        )


class DetectorsRegistryAuditTest(unittest.TestCase):
    def test_audit_detectors_registry_on_real_files(self) -> None:
        manifest = rule_quality_harness.load_manifest()
        # Must not raise
        rule_quality_harness.audit_detectors_registry(manifest)

    def test_audit_detectors_registry_detects_na_violation(self) -> None:
        manifest = rule_quality_harness.load_manifest()
        manifest_copy = {"cases": list(manifest["cases"])}
        manifest_copy["cases"].append(
            {
                "id": "cpp-cors-buggy",
                "language": "cpp",
                "path": "test-suite/cpp/clean",
                "tags": ["cpp", "cors", "buggy"],
            }
        )
        with self.assertRaises(AssertionError) as ctx:
            rule_quality_harness.audit_detectors_registry(manifest_copy)
        self.assertIn("marks cors/cpp as n-a", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
