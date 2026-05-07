#!/usr/bin/env python3
"""Unit checks for the rule-quality harness invariants."""

import unittest

import rule_quality_harness


class RuleInventoryCoverageInvariantTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
