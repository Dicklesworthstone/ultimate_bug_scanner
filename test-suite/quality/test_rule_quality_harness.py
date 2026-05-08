#!/usr/bin/env python3
"""Unit checks for the rule-quality harness invariants."""

import contextlib
import io
import unittest
from pathlib import Path
from typing import Any

import rule_quality_harness


class ProgressOutputTest(unittest.TestCase):
    def test_log_progress_writes_one_line(self) -> None:
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            rule_quality_harness.log_progress("[phase] running case")

        self.assertEqual(buffer.getvalue(), "[phase] running case\n")


class RuleInventoryCoverageInvariantTest(unittest.TestCase):
    def test_builds_inventory_coverage_from_corpus_and_dumped_rules(self) -> None:
        coverage = rule_quality_harness.build_rule_inventory_coverage(
            [
                {
                    "label": "js-rule-pack",
                    "result_rule_ids": [
                        "js.corpus-only",
                        "js.eval-call",
                        "js.innerHTML-assign",
                    ],
                }
            ],
            [
                {
                    "label": "js-rule-pack",
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
                    "label": "js-rule-pack",
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
    def test_counts_ast_grep_json_stream_objects(self) -> None:
        count = rule_quality_harness.count_json_stream_objects(
            '{"ruleId":"go.exec-sh-c"}\n\n{"ruleId":"rust.unwrap-call"}\n',
            "fixture",
        )

        self.assertEqual(count, 2)

    def test_rejects_invalid_ast_grep_json_stream_output(self) -> None:
        with self.assertRaisesRegex(AssertionError, "emitted invalid JSON stream output"):
            rule_quality_harness.count_json_stream_objects(
                '{"ruleId":"ts.non-null-assertion-chain"}\nnot json\n',
                "fixture",
            )

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


if __name__ == "__main__":
    unittest.main()
