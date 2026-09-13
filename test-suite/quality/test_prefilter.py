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
import json
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


    def test_generated_rust_async_rules_require_async(self) -> None:
        from ubs_core.rust_rules import generate

        slugs = (
            "std_lock_async_lock", "std_lock_async_read", "std_lock_async_write",
            "std_guard_await_unwrap", "std_guard_await_expect",
            "tokio_guard_lock", "tokio_guard_read", "tokio_guard_write",
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = generate(root)
            for slug in slugs:
                with self.subTest(slug=slug):
                    rule_id = f"rust.ast.{slug}"
                    text = (root / f"{slug}.yml").read_text(encoding="utf-8")
                    self.assertEqual(
                        extract_ast_rule_literals(rule_id, text, lang="rust"),
                        {"async"},
                    )
                    self.assertEqual(
                        extract_ast_rule_literals(rule_id, manifest[rule_id], lang="rust"),
                        {"async"},
                    )

    def test_structured_positive_relations_extract_required_literals(self) -> None:
        for relation in ("has", "inside", "precedes", "follows"):
            rule = {relation: {"regex": r"\basync\b", "stopBy": {"regex": "unrequired_stop"}}}
            for text in (
                rule,
                json.dumps({"rule": rule}),
                f"id: test.rule\nrule: {json.dumps(rule)}\n",
            ):
                with self.subTest(relation=relation, text=text):
                    self.assertEqual(extract_ast_rule_literals("test.rule", text), {"async"})

    def test_structured_scalar_patterns_require_fixed_identifiers(self) -> None:
        cases = (
            ("$X.parse::<f64>().unwrap_or($DEFAULT)", {"parse", "f64", "unwrap_or"}),
            ("Instant::now().elapsed()", {"Instant", "now", "elapsed"}),
            ("$X as *const $TYPE", {"as", "const"}),
            ("$ITER.map(|$ITEM| $ITEM.clone())", {"map", "clone"}),
            ("console.log($$$ARGS)", {"console", "log"}),
            ("$RECEIVER?.method($$$ARGS)", {"method"}),
            ("async fn $NAME($$$ARGS) { $$$BODY }", {"async", "fn"}),
        )
        for pattern, expected in cases:
            rule = {"pattern": pattern}
            for text in (rule, json.dumps({"rule": rule}), f"rule: {json.dumps(rule)}\n"):
                with self.subTest(pattern=pattern, text=text):
                    self.assertEqual(extract_ast_rule_literals("test.rule", text), expected)

    def test_scalar_unknowns_do_not_require_incidental_text(self) -> None:
        for pattern in (
            "$ONLY", "$$OPERATOR", "$$$ARGS", "$X[$INDEX]", "$X ?? $Y",
            "$RECEIVER?.$METHOD($$$ARGS)", "$X!", "true", "0",
            '$CALL("incidental string")', "$X // incidental_comment",
            "$X /* incidental_comment */", "$X # incidental_comment",
            r"\u0061", "`incidental_template`",
        ):
            with self.subTest(pattern=pattern):
                self.assertEqual(extract_ast_rule_literals("test.rule", {"pattern": pattern}), set())
        for ignored in ("not", "stopBy"):
            with self.subTest(ignored=ignored):
                self.assertEqual(extract_ast_rule_literals(
                    "test.rule", {ignored: {"pattern": "incidental_name($X)"}},
                ), set())

    def test_scalar_alternatives_and_relations_keep_conservative_requirements(self) -> None:
        for unknown in ({"pattern": "$VALUE"}, {"pattern": "$X ?? $Y"}):
            rule = {"any": [{"pattern": "required_call($X)"}, unknown]}
            with self.subTest(unknown=unknown):
                self.assertEqual(extract_ast_rule_literals("test.rule", rule), set())
        rule = {"any": [{"pattern": "$X.first($$$)"}, {"pattern": "$X.second($$$)"}]}
        self.assertEqual(extract_ast_rule_literals("test.rule", rule), {"first", "second"})
        for relation in ("has", "inside", "precedes", "follows"):
            rule = {relation: {"pattern": "required_call($X)",
                               "stopBy": {"pattern": "incidental_boundary($Y)"}}}
            with self.subTest(relation=relation):
                self.assertEqual(extract_ast_rule_literals("test.rule", rule), {"required_call"})
        rule = {"all": [{"pattern": "$X.required_call($$$)"},
                        {"any": [{"pattern": "optional_call($X)"}, {"kind": "identifier"}]}]}
        self.assertEqual(extract_ast_rule_literals("test.rule", rule), {"required_call"})

    def test_unquoted_yaml_flow_mapping_keeps_existing_extraction(self) -> None:
        for text in (
            "rule: { pattern: 'console.log($X)' }\n",
            "{ pattern: 'console.log($X)' }\n",
        ):
            with self.subTest(text=text):
                self.assertIn("console.log", extract_ast_rule_literals("test.rule", text))

    def test_structured_negative_context_and_unknown_regexes_fall_back(self) -> None:
        rules = (
            {"not": {"regex": "negative_only"}},
            {"stopBy": {"regex": "stop_only"}},
            {"has": {"kind": "identifier", "stopBy": {"regex": "stop_only"}}},
            {"pattern": {"context": "fn synthetic_context() { $X }", "selector": "identifier"}},
            {"regex": "async|sync"},
            {"regex": "async?"},
            {"regex": "(?:async)?"},
            {"regex": "(?i)async"},
            {"regex": "[async]"},
        )
        for rule in rules:
            for text in (rule, f"rule: {json.dumps(rule)}\n"):
                with self.subTest(text=text):
                    self.assertEqual(extract_ast_rule_literals("test.rule", text), set())
        self.assertEqual(extract_ast_rule_literals("test.rule", 'rule: {"regex":'), set())

    def test_structured_any_needs_literals_in_every_branch(self) -> None:
        for unknown in (
            {"kind": "identifier"},
            {"not": {"regex": "negative_only"}},
            {"pattern": {"context": "fn scaffold() { $X }", "selector": "identifier"}},
        ):
            rule = {"any": [{"regex": r"\basync\b"}, unknown]}
            with self.subTest(unknown=unknown):
                self.assertEqual(extract_ast_rule_literals("test.rule", rule), set())
        rule = {"any": [{"regex": r"\basync\b"}, {"has": {"regex": "spawn"}}]}
        self.assertEqual(extract_ast_rule_literals("test.rule", rule), {"async", "spawn"})

    def test_structured_all_retains_a_required_literal(self) -> None:
        rule = {"all": [
            {"inside": {"has": {"regex": r"\basync\b"}}},
            {"any": [{"regex": "optional_word"}, {"kind": "identifier"}]},
            {"not": {"regex": "negative_only"}},
            {"pattern": {"context": "fn scaffold() { $X }", "selector": "identifier"}},
        ]}
        self.assertEqual(extract_ast_rule_literals("test.rule", rule), {"async"})


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

    def test_scalar_candidates_ignore_metavariable_names_and_spacing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "matched.js"
            target.write_text("console\n  . log();\n", encoding="utf-8")
            clean = root / "clean.js"
            clean.write_text("const value = 1;\n", encoding="utf-8")
            rule = {"pattern": "console.log($$$ARBITRARY_ARGUMENTS)"}
            text = f"id: test.scalar\nrule: {json.dumps(rule)}\n"
            index = build_prefilter_index(ast_rules=[("test.scalar", text)])
            self.assertFalse(index.fallback_rules)
            result = run_prefilter([target, clean], index)
            self.assertFalse(result.is_bypass)
            self.assertEqual(result.ast_files, [target])
            self.assertIn("test.scalar", result.candidate_rules_for(target))
            self.assertNotIn("test.scalar", result.candidate_rules_for(clean))

    def test_generated_restored_rust_checks_admit_each_source_variant(self) -> None:
        from ubs_core.rust_rules import AST_CHECKS, generate

        examples = {
            "ptr_cast": ("value as *const u8", "value as *mut u8"),
            "parse_float_no_finite_check": (
                "input.parse::<f64>().unwrap_or(0.0)", "input.parse::<f32>().unwrap_or(0.0)",
            ),
            "instant_now_elapsed": ("Instant::now().elapsed()",),
            "instant_subtraction": ("Instant::now() - duration",),
            "from_slice_panic": (
                "Nonce::from_slice(bytes)", "GenericArray::from_slice(bytes)", "Key::from_slice(bytes)",
            ),
            "i64_negate_overflow": ("value.wrapping_neg()", "-(value as i64)"),
            "wrapping_arithmetic": (
                "value.wrapping_add(1)", "value.wrapping_sub(1)", "value.wrapping_mul(2)",
            ),
            "tokio_spawn_no_move": ("tokio::spawn(async {})",),
            "tokio_block_in_place": ("tokio::task::block_in_place(|| {})",),
            "write_not_atomic": ("std::fs::write(path, bytes)", "fs::write(path, bytes)"),
            "map_clone": ("items.map(|item| item.clone())",),
            "strict_utf8": (
                "String::from_utf8(bytes).unwrap()", "str::from_utf8(bytes).unwrap()",
                'String::from_utf8(bytes).expect("valid")', 'str::from_utf8(bytes).expect("valid")',
            ),
            "regex_new_unwrap": ("regex::Regex::new(input).unwrap()",),
            "debug_assert_macros": ("debug_assert!(true)", "debug_assert_eq!(1, 1)",
                                    "debug_assert_ne!(1, 2)"),
        }
        self.assertEqual(set(examples), {slug for _, slug, _, _, _ in AST_CHECKS})
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rules_dir = root / "rules"
            manifest = generate(rules_dir)
            clean = root / "clean.rs"
            clean.write_text("// untouched\n", encoding="utf-8")
            for slug, sources in examples.items():
                with self.subTest(slug=slug):
                    rule_id = f"rust.ast.{slug}"
                    text = (rules_dir / f"{slug}.yml").read_text(encoding="utf-8")
                    literals = extract_ast_rule_literals(rule_id, text, lang="rust")
                    self.assertTrue(literals, rule_id)
                    self.assertEqual(extract_ast_rule_literals(rule_id, manifest[rule_id], lang="rust"),
                                     literals)
                    index = build_prefilter_index(ast_rules=[(rule_id, text)], lang="rust")
                    self.assertFalse(index.fallback_rules)
                    positive = []
                    for branch, source in enumerate(sources):
                        target = root / f"{slug}_{branch}.rs"
                        target.write_text(f"async fn example() {{ let _ = {source}; }}\n",
                                          encoding="utf-8")
                        positive.append(target)
                    result = run_prefilter([*positive, clean], index)
                    self.assertFalse(result.is_bypass)
                    self.assertEqual(result.files_after_prefilter, len(positive))
                    self.assertEqual(set(result.ast_files), set(positive))
                    for target in positive:
                        self.assertIn(rule_id, result.candidate_rules_for(target))
                    self.assertNotIn(rule_id, result.candidate_rules_for(clean))

    def test_unknown_scalar_alternative_keeps_files_without_known_literal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "numeric.rs"
            target.write_text("0\n", encoding="utf-8")
            for unknown in ("$VALUE", "0", "$X ?? $Y"):
                with self.subTest(unknown=unknown):
                    rule = {"any": [{"pattern": "known_call($X)"}, {"pattern": unknown}]}
                    text = f"id: test.scalar\nrule: {json.dumps(rule)}\n"
                    index = build_prefilter_index(ast_rules=[("test.scalar", text)])
                    self.assertEqual(index.fallback_rules, {"test.scalar"})
                    result = run_prefilter([target], index)
                    self.assertEqual(result.ast_files, [target])
                    self.assertIn("test.scalar", result.candidate_rules_for(target))

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
