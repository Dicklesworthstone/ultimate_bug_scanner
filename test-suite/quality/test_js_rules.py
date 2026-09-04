#!/usr/bin/env python3
"""Unit tests for ubs_core.js_rules — ast-grep rule-pack generation (bead 0xjg.4).

Covers generate() idempotence, manifest completeness, per-grammar sgconfig
uniqueness (GH #93 same-id variants), user-rule handling, the exported
metadata maps, and (when ast-grep is installed) an end-to-end scan smoke test.
"""
from __future__ import annotations

import hashlib
import json
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

from ubs_core.js_rules import (  # noqa: E402
    CATEGORY_MAP,
    REMEDIATION_MAP,
    SEVERITY_MAP,
    SUMMARY_MAP,
    generate,
)

GRAMMARS = ("javascript", "typescript", "tsx")


def _tree_hash(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _config_entries(rule_dir: Path, grammar: str) -> list[str]:
    text = (rule_dir / f"sgconfig-{grammar}.yml").read_text(encoding="utf-8")
    return [ln.strip()[2:] for ln in text.splitlines() if ln.strip().startswith("- ")]


def _config_ids(rule_dir: Path, grammar: str) -> set[str]:
    return {
        re.search(r"(?m)^id:\s*(\S+)", (rule_dir / entry).read_text(encoding="utf-8")).group(1)
        for entry in _config_entries(rule_dir, grammar)
    }


class GenerateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ubs-js-rules-"))
        self.rule_dir = self.tmp / "pack"
        self.manifest = generate(self.rule_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_exactly_three_sgconfigs_and_manifest(self) -> None:
        configs = sorted(p.name for p in self.rule_dir.glob("sgconfig-*.yml"))
        self.assertEqual(
            configs,
            ["sgconfig-javascript.yml", "sgconfig-tsx.yml", "sgconfig-typescript.yml"],
        )
        self.assertTrue((self.rule_dir / "manifest.json").is_file())

    def test_rule_file_count_base_plus_variants(self) -> None:
        # 37 base rules + 70 variants (18 js x2, 15 ts x2, ts-non-null-chain x1,
        # 3 tsx x1) = 107; nothing else lands in rules/.
        rules = sorted(p.name for p in (self.rule_dir / "rules").glob("*.yml"))
        self.assertEqual(len(rules), 107)
        self.assertTrue(all(p.is_file() for p in (self.rule_dir / "rules").iterdir()))

    def test_manifest_completeness(self) -> None:
        on_disk = json.loads((self.rule_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, self.manifest)
        self.assertEqual(len(self.manifest), 37)
        for rule_id, entry in self.manifest.items():
            self.assertEqual(set(entry), {"severity", "language", "file"}, rule_id)
            self.assertIn(entry["language"], GRAMMARS, rule_id)
            self.assertTrue((self.rule_dir / entry["file"]).is_file(), rule_id)
            self.assertIn(entry["severity"], {"critical", "warning", "info", "error"}, rule_id)

    def test_manifest_severity_calibration(self) -> None:
        # GH #93: the map tier wins over the YAML severity for mapped ids;
        # unmapped ids fall back to the YAML severity.
        self.assertEqual(self.manifest["js.async.await-no-try"]["severity"], "info")
        self.assertEqual(
            self.manifest["js.parseInt-no-radix"],
            {"severity": "warning", "language": "javascript", "file": "rules/parseInt-no-radix.yml"},
        )
        self.assertEqual(self.manifest["js.taint.header-injection"]["severity"], "warning")

    def test_manifest_ids_match_rule_files(self) -> None:
        ids_on_disk = set()
        for rule_file in (self.rule_dir / "rules").glob("*.yml"):
            match = re.search(r"(?m)^id:[ \t]*(\S+)", rule_file.read_text(encoding="utf-8"))
            self.assertIsNotNone(match, rule_file.name)
            ids_on_disk.add(match.group(1))
        self.assertEqual(ids_on_disk, set(self.manifest))

    def test_variant_dissolution_gh93(self) -> None:
        # ts-non-null-chain keeps its tsx-only special case; the three
        # __variants aggregates are gone, replaced by per-language files.
        rules = self.rule_dir / "rules"
        self.assertEqual(sorted(p.name for p in rules.glob("ts-non-null-chain.*.yml")),
                         ["ts-non-null-chain.tsx.yml"])
        self.assertFalse(any(p.name.startswith("__variants-") for p in rules.iterdir()))
        # variant files only: 15 ts + 3 tsx -> js, 18 js -> ts, 18 js + 16 ts -> tsx
        counts = {g: len(list(rules.glob(f"*.{g}.yml"))) for g in GRAMMARS}
        self.assertEqual(counts, {"javascript": 18, "typescript": 18, "tsx": 34})
        # per-grammar totals incl. base files: 36 / 34 / 37 sgconfig entries
        totals = {"javascript": 36, "typescript": 34, "tsx": 37}
        for grammar, total in totals.items():
            self.assertEqual(len(_config_entries(self.rule_dir, grammar)), total, grammar)

    def test_variant_only_rewrites_language_line(self) -> None:
        base = (self.rule_dir / "rules" / "parseInt-no-radix.yml").read_text(encoding="utf-8")
        variant = (self.rule_dir / "rules" / "parseInt-no-radix.typescript.yml").read_text(encoding="utf-8")
        self.assertEqual(
            base.replace("language: javascript", "language: typescript"), variant
        )

    def test_sgconfig_lists_its_grammar_only(self) -> None:
        for grammar in GRAMMARS:
            text = (self.rule_dir / f"sgconfig-{grammar}.yml").read_text(encoding="utf-8")
            self.assertTrue(text.startswith("ruleDirs:\n"))
            entries = _config_entries(self.rule_dir, grammar)
            self.assertTrue(entries, grammar)
            for entry in entries:
                self.assertRegex(entry, r"^rules/[A-Za-z0-9_-]+(\.[a-z]+)?\.yml$")
                rule_text = (self.rule_dir / entry).read_text(encoding="utf-8")
                self.assertRegex(rule_text, rf"(?m)^language:[ \t]*{grammar}[ \t]*$")
            ids = _config_ids(self.rule_dir, grammar)
            self.assertEqual(len(ids), len(entries), f"duplicate id inside {grammar} config")

    def test_every_rule_id_in_each_matching_config(self) -> None:
        # Each id appears exactly once per grammar EXCEPT where GH #93 forbids
        # a variant: ts.non-null-assertion-chain has no javascript form, and
        # the tsx-only JSX rules have no typescript form.
        missing = {
            "javascript": {"ts.non-null-assertion-chain"},
            "typescript": {"react.list-missing-key", "react.dangerously-set-html",
                           "react.setstate-in-render"},
            "tsx": set(),
        }
        for grammar in GRAMMARS:
            self.assertEqual(
                _config_ids(self.rule_dir, grammar),
                set(self.manifest) - missing[grammar],
                grammar,
            )


class IdempotenceTests(unittest.TestCase):
    def test_rerun_on_same_dir_matches_fresh_generation(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ubs-js-rules-idem-"))
        try:
            first, second = tmp / "a", tmp / "b"
            generate(first)
            generate(first)  # rerun over the SAME tree
            generate(second)
            self.assertEqual(_tree_hash(first), _tree_hash(second))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class UserRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ubs-js-rules-user-"))
        self.user_dir = self.tmp / "my-rules"
        (self.user_dir / "sub").mkdir(parents=True)
        (self.user_dir / "my-rule.yml").write_text(
            'id: myorg.my-rule\nlanguage: javascript\nrule:\n  pattern: foo()\n'
            'severity: warning\nmessage: "custom"\n',
            encoding="utf-8",
        )
        (self.user_dir / "ts-rule.yml").write_text(
            'id: myorg.ts-rule\nlanguage: typescript\nrule:\n  pattern: bar()\n'
            'severity: info\nmessage: "custom ts"\n',
            encoding="utf-8",
        )
        (self.user_dir / "sub" / "deep.yml").write_text(
            'id: myorg.deep\nlanguage: javascript\nrule:\n  pattern: deep()\n',
            encoding="utf-8",
        )
        (self.user_dir / "README.txt").write_text("not a rule", encoding="utf-8")
        self.rule_dir = self.tmp / "pack"
        self.manifest = generate(self.rule_dir, self.user_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_user_rules_copied_verbatim(self) -> None:
        rules = self.rule_dir / "rules"
        self.assertEqual(
            (rules / "my-rule.yml").read_text(encoding="utf-8"),
            (self.user_dir / "my-rule.yml").read_text(encoding="utf-8"),
        )
        self.assertTrue((rules / "sub" / "deep.yml").is_file())
        self.assertTrue((rules / "README.txt").is_file())

    def test_user_rules_excluded_from_variants(self) -> None:
        rules = self.rule_dir / "rules"
        self.assertFalse(list(rules.glob("my-rule.*.yml")))
        self.assertFalse(list(rules.glob("ts-rule.*.yml")))

    def test_user_rules_listed_in_declared_grammar_config(self) -> None:
        js_cfg = (self.rule_dir / "sgconfig-javascript.yml").read_text(encoding="utf-8")
        ts_cfg = (self.rule_dir / "sgconfig-typescript.yml").read_text(encoding="utf-8")
        tx_cfg = (self.rule_dir / "sgconfig-tsx.yml").read_text(encoding="utf-8")
        self.assertIn("rules/my-rule.yml", js_cfg)
        self.assertNotIn("my-rule", ts_cfg)
        self.assertNotIn("my-rule", tx_cfg)
        self.assertIn("rules/ts-rule.yml", ts_cfg)
        self.assertNotIn("ts-rule.yml", js_cfg)

    def test_generated_manifest_unaffected_by_user_rules(self) -> None:
        self.assertEqual(len(self.manifest), 37)
        self.assertNotIn("myorg.my-rule", self.manifest)

    def test_missing_user_dir_is_ignored(self) -> None:
        rule_dir = self.tmp / "pack-nousers"
        manifest = generate(rule_dir, self.tmp / "does-not-exist")
        self.assertEqual(len(manifest), 37)


class MapTests(unittest.TestCase):
    def test_maps_cover_the_19_documented_ids(self) -> None:
        for mapping in (SEVERITY_MAP, CATEGORY_MAP, SUMMARY_MAP, REMEDIATION_MAP):
            self.assertEqual(len(mapping), 19)

    def test_severity_values(self) -> None:
        self.assertEqual(SEVERITY_MAP["js.async.await-no-try"], "info")  # GH #93
        self.assertEqual(SEVERITY_MAP["js.async.then-no-catch"], "warning")
        self.assertEqual(SEVERITY_MAP["js.hooks.missing-critical"], "critical")
        self.assertEqual(SEVERITY_MAP["js.hooks.unused"], "info")
        for rule_id in ("js.taint.xss", "js.taint.eval", "js.taint.command", "js.taint.sql"):
            self.assertEqual(SEVERITY_MAP[rule_id], "critical")

    def test_categories_follow_group_grammar(self) -> None:
        self.assertEqual(CATEGORY_MAP["js.async.dangling-promise"], "js.async")
        self.assertEqual(CATEGORY_MAP["js.error.empty-catch"], "js.error")
        self.assertEqual(CATEGORY_MAP["js.resource.interval-no-clear"], "js.resource")
        self.assertEqual(CATEGORY_MAP["js.hooks.unstable"], "js.hooks")
        self.assertEqual(CATEGORY_MAP["js.taint.sql"], "js.taint")

    def test_summary_and_remediation_spot_checks(self) -> None:
        self.assertEqual(SUMMARY_MAP["js.json-parse-without-try"], "JSON.parse without try/catch")
        self.assertEqual(
            REMEDIATION_MAP["js.async.dangling-promise"],
            "Await the promise, return it, or add .catch()/.finally()",
        )


@unittest.skipIf(shutil.which("ast-grep") is None, "ast-grep not installed")
class ScanSmokeTests(unittest.TestCase):
    def test_sgconfigs_load_and_match(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ubs-js-rules-scan-"))
        try:
            rule_dir = tmp / "pack"
            generate(rule_dir)
            fixture = tmp / "sample.js"
            fixture.write_text("const n = parseInt(raw);\nif (x == NaN) {}\n", encoding="utf-8")
            hits: set[str] = set()
            for grammar in GRAMMARS:
                proc = subprocess.run(
                    ["ast-grep", "scan", "-c", str(rule_dir / f"sgconfig-{grammar}.yml"),
                     "--json=stream", str(fixture)],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertLessEqual(proc.returncode, 1, proc.stderr)
                for line in proc.stdout.splitlines():
                    if line.strip():
                        hits.add(json.loads(line).get("ruleId", ""))
            self.assertIn("js.parseInt-no-radix", hits)
            self.assertIn("js.nan-direct-compare", hits)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
