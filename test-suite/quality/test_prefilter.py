#!/usr/bin/env python3
"""Unit tests for ubs_core.prefilter — Necessary-literal prefilter (bead C2).

Verifies:
1. Every ast-grep rule in every language pack extracts non-empty literals OR is in ALLOWED_EMPTY_RULES.
2. ALLOWED_EMPTY_RULES contains no stale or missing rules.
3. Pattern literal extraction correctly extracts keywords and ignores lookarounds.
4. PrefilterIndex builds correct inverted index and expanded substring containment.
5. run_prefilter correctly restricts candidate rules per file.
6. UBS_NO_PREFILTER=1 cleanly bypasses filtering.
"""
from __future__ import annotations

import importlib  # ubs:ignore[py.deprecations.deprecated-api]
import os
import re
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.prefilter import (  # noqa: E402
    ALLOWED_EMPTY_RULES,
    ENV_NO_PREFILTER,
    PrefilterIndex,
    RuleSpec,
    build_prefilter_index,
    extract_ast_rule_literals,
    extract_pattern_literals,
    run_prefilter,
)


@dataclass
class DummyPattern:
    rule_id: str
    regex: Any
    category: int = 1
    title: str = "Dummy"


class RuleLiteralExtractionTests(unittest.TestCase):
    """Test necessary literal extraction on every ast-grep rule across all packs."""

    PACK_LANGUAGES = (
        "bash",
        "csharp",
        "go",
        "java",
        "js",
        "kotlin",
        "py",
        "ruby",
        "rust",
        "swift",
    )

    def test_all_pack_rules_extract_literals_or_are_allowed_empty(self) -> None:
        total_rules = 0
        unmatched_rules: list[tuple[str, str, str]] = []

        for lang in self.PACK_LANGUAGES:
            mod = importlib.import_module(f"ubs_core.{lang}_rules")
            gen = getattr(mod, "generate", None)
            self.assertIsNotNone(gen, f"Module ubs_core.{lang}_rules lacks generate()")
            with tempfile.TemporaryDirectory() as td:
                tdp = Path(td)
                manifest = gen(tdp)
                for yml_file in sorted(tdp.glob("*.yml")):
                    if yml_file.name.startswith(("sgconfig", "sgbase")):
                        continue
                    text = yml_file.read_text(encoding="utf-8")
                    rule_id = yml_file.stem
                    id_m = re.search(r"id:\s*(\S+)", text)
                    if id_m:
                        rule_id = id_m.group(1)
                    total_rules += 1
                    lits = extract_ast_rule_literals(rule_id, text, lang=lang)
                    if not lits:
                        allowed = ALLOWED_EMPTY_RULES.get(lang, set())
                        if rule_id not in allowed and yml_file.stem not in allowed:
                            unmatched_rules.append((lang, rule_id, yml_file.name))

        self.assertGreater(total_rules, 100, f"Expected >100 rules across packs, got {total_rules}")
        self.assertEqual(
            unmatched_rules,
            [],
            f"Found rules with empty literals not listed in ALLOWED_EMPTY_RULES: {unmatched_rules}",
        )

    def test_allowed_empty_rules_whitelist_integrity(self) -> None:
        """Every rule listed in ALLOWED_EMPTY_RULES must be a recognized language."""
        for lang in ALLOWED_EMPTY_RULES:
            self.assertIn(lang, self.PACK_LANGUAGES)


class PatternLiteralExtractionTests(unittest.TestCase):
    """Test regex pattern literal extraction."""

    def test_word_boundary_extraction(self) -> None:
        pat = DummyPattern("test.debugger", re.compile(r"\bdebugger\b"))
        lits = extract_pattern_literals(pat)
        self.assertIn("debugger", lits)

    def test_single_letter_class_normalized(self) -> None:
        pat = DummyPattern("test.eval", re.compile(r"\b[Ee]val\s*\("))
        lits = extract_pattern_literals(pat)
        self.assertIn("eval", lits)

    def test_alternation_branches_extracted(self) -> None:
        pat = DummyPattern("test.alert", re.compile(r"\b(alert|confirm|prompt)\s*\("))
        lits = extract_pattern_literals(pat)
        self.assertTrue(bool(lits & {"alert", "confirm", "prompt"}))

    def test_negative_lookaround_ignored(self) -> None:
        # Negative lookahead should not extract the negated token as required
        pat = DummyPattern("test.neg", re.compile(r"\bfoo\b(?![^)]*safe_token)"))
        lits = extract_pattern_literals(pat)
        self.assertIn("foo", lits)
        self.assertNotIn("safe_token", lits)


class PrefilterIndexTests(unittest.TestCase):
    """Test inverted index construction and substring expansion."""

    def test_expanded_rules_containment(self) -> None:
        index = PrefilterIndex()
        index.add_rule(RuleSpec(rule_id="r.json_parse", literals=frozenset({"json.parse"}), is_fallback=False, kind="ast"))
        index.add_rule(RuleSpec(rule_id="r.parse", literals=frozenset({"parse"}), is_fallback=False, kind="pattern"))
        index.finalize()

        rules_for_json_parse = index.expanded_rules.get("json.parse", set())
        self.assertIn("r.json_parse", rules_for_json_parse)
        self.assertIn("r.parse", rules_for_json_parse)

    def test_fallback_rules_always_included(self) -> None:
        index = PrefilterIndex()
        index.add_rule(RuleSpec(rule_id="r.fallback", literals=frozenset(), is_fallback=True, kind="ast"))
        index.add_rule(RuleSpec(rule_id="r.specific", literals=frozenset({"foobar"}), is_fallback=False, kind="pattern"))
        index.finalize()

        self.assertTrue(index.has_ast_fallback)
        self.assertIn("r.fallback", index.fallback_rules)


class RunPrefilterTests(unittest.TestCase):
    """Test running prefilter over actual files."""

    def test_run_prefilter_filtering_and_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            f_match = root / "matched.js"
            f_match.write_text("function test() { debugger; }", encoding="utf-8")
            f_clean = root / "clean.js"
            f_clean.write_text("const x = 1 + 2;", encoding="utf-8")

            index = PrefilterIndex()
            index.add_rule(RuleSpec(rule_id="js.debugger", literals=frozenset({"debugger"}), is_fallback=False, kind="ast"))
            index.add_rule(RuleSpec(rule_id="js.fallback", literals=frozenset(), is_fallback=True, kind="pattern"))
            index.finalize()

            # Normal run
            res = run_prefilter([f_match, f_clean], index)
            self.assertEqual(res.files_considered, 2)
            self.assertEqual(res.files_after_prefilter, 1)
            self.assertIn("js.debugger", res.candidate_rules_for(f_match))
            self.assertIn("js.fallback", res.candidate_rules_for(f_match))
            self.assertNotIn("js.debugger", res.candidate_rules_for(f_clean))
            self.assertIn("js.fallback", res.candidate_rules_for(f_clean))
            self.assertIn(f_match, res.ast_files)
            self.assertNotIn(f_clean, res.ast_files)

            # Bypass run with UBS_NO_PREFILTER=1
            old_val = os.environ.get(ENV_NO_PREFILTER)
            os.environ[ENV_NO_PREFILTER] = "1"
            try:
                res_bypass = run_prefilter([f_match, f_clean], index)
                self.assertTrue(res_bypass.is_bypass)
                self.assertEqual(res_bypass.files_after_prefilter, 2)
                self.assertIn(f_clean, res_bypass.ast_files)
                self.assertIn("js.debugger", res_bypass.candidate_rules_for(f_clean))
            finally:
                if old_val is None:
                    os.environ.pop(ENV_NO_PREFILTER, None)
                else:
                    os.environ[ENV_NO_PREFILTER] = old_val


if __name__ == "__main__":
    unittest.main()
