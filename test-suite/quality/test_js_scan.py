#!/usr/bin/env python3
"""Unit tests for ubs_core.js_scan — contract-v2 pattern layer (bead 0xjg.4)."""
from __future__ import annotations

import json
import io
import os
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

import re  # noqa: E402

from ubs_core.js_scan import (  # noqa: E402
    Pattern,
    iter_matches,
    load_patterns,
    resolve_severity,
    scan_patterns,
)


def _pat(**overrides) -> Pattern:
    fields = dict(
        category=11,
        rule_id="js.debug.debugger",
        title="debugger statements",
        regex=re.compile(r"\bdebugger\b"),
        thresholds=((0, "critical"),),
    )
    fields.update(overrides)
    return Pattern(**fields)


class ThresholdTests(unittest.TestCase):
    def test_ladder_first_match_wins(self) -> None:
        p = _pat(thresholds=((50, "warning"), (20, "info")))
        self.assertEqual(resolve_severity(p, 51), "warning")
        self.assertEqual(resolve_severity(p, 21), "info")
        self.assertIsNone(resolve_severity(p, 20))  # exclusive: 20 is not > 20

    def test_exact_counts_are_exclusive(self) -> None:
        p = _pat(thresholds=((15, "warning"), (0, "info")))
        self.assertEqual(resolve_severity(p, 16), "warning")
        self.assertEqual(resolve_severity(p, 15), "info")


class MatchTests(unittest.TestCase):
    def test_marker_lines_excluded(self) -> None:
        p = _pat()
        text = "debugger;\ndebugger;  # ubs:ignore\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)

    def test_exclude_regex_drops_lines(self) -> None:
        p = _pat(
            regex=re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*!"),
            exclude_regex=re.compile(r"!=|!=="),
        )
        text = "a!.b;\nif (x !== y) { z!; }\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)


class ScanTests(unittest.TestCase):
    def test_counters_and_sink_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n// TODO: x\n// FIXME: y\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            patterns = [
                _pat(),
                _pat(
                    category=14,
                    rule_id="js.markers.todo-family",
                    title="Technical debt markers",
                    regex=re.compile(r"TODO|FIXME"),
                    thresholds=((0, "info"),),
                ),
            ]
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns(patterns, [src], sink, skip=set())
            self.assertEqual(counters, {"critical": 1, "warning": 0, "info": 2})
            records = [json.loads(line) for line in sink_path.read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["rule"], "js.debug.debugger")
            self.assertEqual(records[0]["severity"], "critical")
            self.assertTrue(all(r["category_id"] for r in records))

    def test_skip_category_silences_patterns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns([_pat()], [src], sink, skip={11})
            self.assertEqual(counters["critical"], 0)
            self.assertEqual(sink_path.read_text(), "")


class ExemplarPatternsTests(unittest.TestCase):
    def test_exemplar_module_loads(self) -> None:
        patterns = load_patterns()
        rules = {p.rule_id for p in patterns}
        self.assertIn("js.debug.debugger", rules)
        self.assertIn("js.markers.todo-family", rules)
        self.assertIn("js.typescript.non-null-assertion", rules)


@unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep required")
class CustomPolicyIntegrationTests(unittest.TestCase):
    """Requested policies must reach the real analyzer, report and exit gate."""

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="js-policy-", dir=artifacts)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.rules = self.root / "team's policies"
        self.rules.mkdir()
        self.source = self.project / "sample.js"
        self.source.write_text("policyProbe();\n")

    def policy(self, name="policy.yml", rule_id="org.must-not-call", language="javascript"):
        path = self.rules / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'id: "{rule_id}"\nlanguage: {language}\nseverity: error\n'
            'message: Project policy violation\nrule:\n  pattern: policyProbe()\n'
        )
        return path

    def scan(self, *args, meta=False, env=None):
        command = REPO_ROOT / ("ubs" if meta else "modules/ubs-js.sh")
        return subprocess.run(
            [str(command), "--format=json", "--no-color", f"--rules={self.rules}",
             *args, str(self.project)], cwd=self.root,
            env={**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1",
                 "UBS_SKIP_TYPE_NARROWING": "1", **(env or {})},
            capture_output=True, text=True, timeout=45,
        )

    def assert_policy(self, result, rule_id="org.must-not-call"):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIn(rule_id, result.stdout)
        return report

    def test_error_policy_is_critical_without_fail_on_warning(self):
        self.policy()
        report = self.assert_policy(self.scan())
        self.assertGreater(report["critical"], 0)

    def test_nested_yaml_policy_reaches_meta_runner(self):
        self.policy("nested/custom.yaml")
        self.assert_policy(self.scan(meta=True))

    def test_custom_policy_is_not_downgraded_by_builtin_async_calibration(self):
        self.policy(rule_id="js.async.await-no-try")
        self.assert_policy(self.scan(), "js.async.await-no-try")

    def test_custom_filename_cannot_be_overwritten_by_builtin(self):
        self.policy("parseInt-no-radix.yml")
        self.assert_policy(self.scan())

    def test_multiple_documents_and_quoted_ids_are_all_counted(self):
        path = self.policy()
        path.write_text(path.read_text() + '\n---\n' +
                        path.read_text().replace('org.must-not-call', 'org.second-policy'))
        report = self.assert_policy(self.scan())
        self.assertIn("org.second-policy", json.dumps(report))

    def test_typescript_and_tsx_keep_the_authored_grammar(self):
        self.source.write_text("const value = 1;\n")
        for suffix, language in (("ts", "typescript"), ("tsx", "tsx")):
            with self.subTest(language=language):
                self.policy(f"{suffix}.yaml", f"org.{suffix}", language)
                (self.project / f"sample.{suffix}").write_text("policyProbe();\n")
                self.assert_policy(self.scan(), f"org.{suffix}")

    def test_invalid_policy_never_becomes_success(self):
        self.policy().write_text("id: broken\nlanguage: javascript\nrule: [\n")
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_empty_policy_never_becomes_success(self):
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("rules", result.stderr.lower())

    def test_missing_policy_never_becomes_success(self):
        self.rules = self.root / "missing-policy"
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_policy_not_filtered_by_native_token_prefilter(self):
        self.policy().write_text('id: org.loop\nlanguage: javascript\nseverity: error\n'
                                 'rule:\n  kind: while_statement\n')
        self.source.write_text("while (ready) { tick(); }\n")
        self.assert_policy(self.scan(), "org.loop")

    def test_list_and_dump_include_nested_yaml_without_flattening(self):
        self.policy("nested/custom.yaml")
        dump = self.root / "team's dump"
        result = self.scan("--list-rules", f"--dump-rules={dump}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("org.must-not-call", result.stdout)
        self.assertTrue((dump / "rules/custom/nested/custom.yaml").is_file())
        self.assertTrue((dump / "sgconfig-custom.yml").is_file())

    def test_custom_cache_is_invalidated_when_policy_changes(self):
        path = self.policy("nested/custom.yaml")
        path.write_text(path.read_text().replace("policyProbe()", "notCalled()"))
        env = {"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(self.root / "cache")}
        first = self.scan(env=env)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.policy("nested/custom.yaml")
        self.assert_policy(self.scan(env=env))


if __name__ == "__main__":
    unittest.main()
