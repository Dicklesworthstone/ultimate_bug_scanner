#!/usr/bin/env python3
"""Regression gates for complete, fail-closed baseline finding accounting."""
from __future__ import annotations

import hashlib
import json
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import chdir
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "modules" / "helpers"))
from ubs_core.findings_merge import load_baseline_fingerprints, load_sink, merge, to_sarif
from ubs_core import findings_merge
from ubs_core import occurrences

ARTIFACTS = REPO_ROOT / "test-suite" / "artifacts"


class FindingsIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="findings-integrity-", dir=ARTIFACTS)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.combined = self.root / "combined.json"
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text("[]", encoding="utf-8")

    def tearDown(self) -> None:
        print(f"[{self.id()}] END ({time.monotonic() - self.started:.3f}s)", flush=True)

    def summary(self, *, critical: int = 0, warning: int = 0, info: int = 0,
                lang: str = "python", scanners: bool = True) -> dict:
        counts = {"critical": critical, "warning": warning, "info": info}
        doc = {"status": "ok", "scanners": [{"language": lang, "files": 1, **counts}]
               if scanners else [], "totals": {"files": 1, **counts}}
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        return doc

    def finding(self, **changes) -> dict:
        return {"rule": "py.security.eval", "path": "app.py", "line": 1,
                "severity": "critical", "message": "unsafe evaluation", **changes}

    def sink(self, records: list[dict], lang: str = "python") -> Path:
        path = self.root / f"{lang}.findings.json"
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return path

    def filtered(self) -> dict:
        merge(self.root, self.combined, baseline_path=self.baseline, new_only=True)
        return json.loads(self.combined.read_text(encoding="utf-8"))

    def assert_refused(self, pattern: str) -> None:
        before = self.combined.read_bytes()
        with self.assertRaisesRegex(ValueError, pattern):
            self.filtered()
        self.assertEqual(self.combined.read_bytes(), before, "failed merge replaced the original report")

    def capture_baseline(self, records: list[dict], **counts) -> list[dict]:
        self.summary(**counts)
        self.sink(records)
        merge(self.root, self.combined)
        self.baseline.write_bytes(self.combined.read_bytes())
        return json.loads(self.baseline.read_text(encoding="utf-8"))["findings"]

    def merge_project(self, project: Path, *, new_only: bool = False) -> dict:
        merge(self.root, self.combined, project_dir=project,
              baseline_path=self.baseline if new_only else "", new_only=new_only)
        return json.loads(self.combined.read_text(encoding="utf-8"))

    def test_missing_sink_cannot_erase_critical_summary(self) -> None:
        self.summary(critical=1)
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_empty_sink_cannot_erase_critical_summary(self) -> None:
        self.summary(critical=1)
        self.sink([])
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_summary_only_sink_cannot_erase_critical_summary(self) -> None:
        self.summary(critical=1)
        self.sink([{"language": "python", "files": 1, "critical": 1, "extras": {}}])
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_sampled_sink_cannot_erase_unrepresented_occurrences(self) -> None:
        self.summary(critical=2)
        self.sink([self.finding()])
        self.assert_refused("python reports 2 critical.*accounts for 1")

    def test_wrong_severity_cannot_account_for_critical_occurrences(self) -> None:
        self.summary(critical=1)
        self.sink([self.finding(severity="warning")])
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_another_language_cannot_account_for_missing_producer(self) -> None:
        self.summary(critical=1)
        self.sink([self.finding(rule="js.security.eval")], lang="js")
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_combined_totals_also_require_complete_ledger(self) -> None:
        self.summary(critical=2, scanners=False)
        self.sink([self.finding()])
        self.assert_refused("combined summary reports 2 critical.*accounts for 1")

    def test_ast_report_evidence_cannot_replace_counted_findings(self) -> None:
        doc = self.summary(critical=1)
        doc["scanners"][0]["extras"] = {"ast_findings": [self.finding()]}
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_clean_scan_without_sinks_remains_clean(self) -> None:
        self.summary()
        doc = self.filtered()
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["totals"], {"files": 1, "critical": 0, "warning": 0, "info": 0})
        self.assertEqual(doc["status"], "ok")

    def test_accounting_happens_before_baseline_removal(self) -> None:
        self.summary(critical=1)
        self.sink([self.finding()])
        merge(self.root, self.combined)
        self.baseline.write_bytes(self.combined.read_bytes())
        self.summary(critical=1)
        doc = self.filtered()
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["totals"]["critical"], 0)
        self.assertEqual(doc["scanners"][0]["critical"], 0)

    def test_weighted_aggregate_accounts_for_all_occurrences(self) -> None:
        self.summary(critical=7)
        self.sink([self.finding(path="", line=0, scope="project_aggregate", count=7)])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 7)
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["count"], 7)

    def test_suppressed_records_account_without_contributing_to_new_totals(self) -> None:
        self.summary()
        self.sink([self.finding(path="", line=0, scope="project_aggregate", count=7, suppressed=True)])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 0)
        self.assertTrue(doc["findings"][0]["suppressed"])

    def test_suppressed_evidence_cannot_account_for_missing_active_findings(self) -> None:
        self.summary(critical=1)
        self.sink([self.finding(suppressed=True)])
        self.assert_refused("python reports 1 critical.*accounts for 0")

    def test_unlisted_producer_is_not_dropped_from_totals(self) -> None:
        self.summary(warning=1)
        self.sink([self.finding(severity="warning")])
        self.sink([self.finding(rule="js.security.eval")], lang="js")
        doc = self.filtered()
        self.assertEqual(doc["totals"], {"files": 1, "critical": 1, "warning": 1, "info": 0})
        self.assertEqual({finding["lang"] for finding in doc["findings"]}, {"js", "python"})

    def test_truncated_record_is_not_treated_as_an_empty_scan(self) -> None:
        self.summary(critical=1)
        path = self.sink([self.finding()])
        with path.open("a", encoding="utf-8") as stream:
            stream.write('{"rule":"py.security.eval",')
        self.assert_refused(r"python\.findings\.json:2")

    def test_malformed_sink_fails_without_baseline_too(self) -> None:
        self.summary(critical=1)
        path = self.sink([])
        path.write_text("not json at all\n", encoding="utf-8")
        before = self.combined.read_bytes()
        with self.assertRaisesRegex(ValueError, r"python\.findings\.json:1"):
            merge(self.root, self.combined)
        self.assertEqual(self.combined.read_bytes(), before)

    def test_invalid_utf8_sink_fails_closed(self) -> None:
        self.summary(critical=1)
        path = self.sink([])
        path.write_bytes(b'{"rule":"bad\xff","path":"app.py"}\n')
        self.assert_refused("cannot read findings sink")

    def test_non_finding_payloads_are_not_silently_skipped(self) -> None:
        self.summary()
        for record in (None, [], 4, "data", {}, {"rule": "py.security.eval"},
                       {"language": "python", "files": 0, "rule": "missing-path"}):
            with self.subTest(record=record):
                self.sink([record])
                self.assert_refused("expected a finding with rule/path or a module summary")

    def test_blank_lines_and_real_summary_records_remain_supported(self) -> None:
        path = self.sink([self.finding(), {"language": "python", "files": 1, "critical": 1}])
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\n  \n")
        self.assertEqual(list(load_sink(path)), [self.finding()])

    def test_invalid_suppression_cannot_hide_a_critical_finding(self) -> None:
        self.summary(critical=1)
        for suppressed in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(suppressed=suppressed):
                self.sink([self.finding(suppressed=suppressed)])
                self.assert_refused("suppressed must be a boolean")

    def test_invalid_severity_is_not_dropped_from_counters(self) -> None:
        self.summary()
        for severity in ("CRITICAL", "error", "", None, [], {}):
            with self.subTest(severity=severity):
                self.sink([self.finding(severity=severity)])
                self.assert_refused("severity must be critical, warning or info")

    def test_invalid_summary_counts_are_not_coerced(self) -> None:
        for count in (-1, True, "1", 0.5, None):
            with self.subTest(count=count):
                self.summary(critical=count)
                self.assert_refused("count must be a nonnegative integer")

    def test_missing_baseline_is_an_error_not_an_empty_baseline(self) -> None:
        self.summary()
        self.baseline = self.root / "nonexistent.json"
        self.assert_refused("cannot read baseline")

    def test_invalid_baseline_json_is_an_error(self) -> None:
        self.summary()
        self.baseline.write_text('{"findings":', encoding="utf-8")
        self.assert_refused("cannot read baseline")

    def test_invalid_baseline_schema_is_an_error(self) -> None:
        self.summary()
        for document in (None, 2, "abc", {"findings": None}, {"findings": {}},
                         [None], [{}], [{"fingerprint": 2}], [{"fingerprint": ""}]):
            with self.subTest(document=document):
                self.baseline.write_text(json.dumps(document), encoding="utf-8")
                self.assert_refused("baseline")

    def test_supported_baseline_representations(self) -> None:
        for document in (["a", "b"], [{"fingerprint": "a"}, {"fingerprint": "b"}],
                         {"findings": [{"fingerprint": "a"}, {"fingerprint": "b"}]}):
            with self.subTest(document=document):
                self.baseline.write_text(json.dumps(document), encoding="utf-8")
                self.assertEqual(load_baseline_fingerprints(self.baseline), {"a", "b"})

    def test_new_only_requires_baseline(self) -> None:
        self.summary()
        before = self.combined.read_bytes()
        with self.assertRaisesRegex(ValueError, "requires a baseline path"):
            merge(self.root, self.combined, new_only=True)
        self.assertEqual(self.combined.read_bytes(), before)

    def test_baseline_filter_does_not_clear_existing_execution_failure(self) -> None:
        doc = self.summary(critical=1)
        doc.update(status="partial", exit_code=2,
                   failed_modules=[{"language": "js", "status": "timeout"}])
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        self.sink([self.finding()])
        merge(self.root, self.combined)
        self.baseline.write_bytes(self.combined.read_bytes())
        filtered = self.filtered()
        self.assertEqual(filtered["totals"]["critical"], 0)
        self.assertEqual(filtered["status"], "partial")
        invocation = to_sarif(filtered)["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["exitCode"], 2)

    def test_removing_a_suppression_exposes_the_existing_finding(self) -> None:
        known = self.capture_baseline([self.finding(suppressed=True)])
        self.summary(critical=1)
        self.sink([self.finding(suppressed=False)])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 1)
        self.assertEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])
        self.assertFalse(doc["findings"][0]["suppressed"])

    def test_severity_increases_are_new_but_decreases_remain_known(self) -> None:
        severities = ("info", "warning", "critical")
        for old_level, old in enumerate(severities):
            for new_level, new in enumerate(severities):
                with self.subTest(old=old, new=new):
                    known = self.capture_baseline([self.finding(severity=old)], **{old: 1})
                    self.summary(**{new: 1})
                    self.sink([self.finding(severity=new)])
                    doc = self.filtered()
                    increased = new_level > old_level
                    self.assertEqual(len(doc["findings"]), int(increased))
                    self.assertEqual(doc["totals"][new], int(increased))
                    if increased:
                        self.assertEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])

    def test_aggregate_growth_retains_only_new_occurrences(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        known = self.capture_baseline([aggregate], critical=3)
        original_baseline = self.baseline.read_bytes()
        self.summary(critical=8)
        self.sink([{**aggregate, "count": 8}])
        doc = self.filtered()
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["count"], 5)
        self.assertEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])
        self.assertEqual(doc["totals"]["critical"], 5)
        self.assertEqual(doc["scanners"][0]["critical"], 5)
        result = to_sarif(doc)["runs"][0]["results"][0]
        self.assertEqual((result["level"], result["properties"]["count"]), ("error", 5))
        self.assertEqual(self.baseline.read_bytes(), original_baseline)

    def test_unchanged_and_smaller_aggregates_remain_known(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        self.capture_baseline([aggregate], critical=3)
        for count in (1, 2, 3):
            with self.subTest(count=count):
                self.summary(critical=count)
                self.sink([{**aggregate, "count": count}])
                doc = self.filtered()
                self.assertEqual(doc["findings"], [])
                self.assertEqual(doc["totals"]["critical"], 0)

    def test_aggregate_severity_increase_exposes_the_entire_weight(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3, severity="warning")
        self.capture_baseline([aggregate], warning=3)
        self.summary(critical=5)
        self.sink([{**aggregate, "severity": "critical", "count": 5}])
        doc = self.filtered()
        self.assertEqual(doc["findings"][0]["count"], 5)
        self.assertEqual(doc["totals"]["critical"], 5)

    def test_suppressed_baseline_aggregate_does_not_grant_occurrence_credit(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        self.capture_baseline([{**aggregate, "suppressed": True}])
        self.summary(critical=5)
        self.sink([aggregate | {"count": 5}])
        doc = self.filtered()
        self.assertEqual(doc["findings"][0]["count"], 5)
        self.assertEqual(doc["totals"]["critical"], 5)

    def test_duplicate_baseline_records_cannot_inflate_aggregate_credit(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        known = self.capture_baseline([aggregate], critical=3)
        self.baseline.write_text(json.dumps({"findings": known * 4}), encoding="utf-8")
        self.summary(critical=8)
        self.sink([aggregate | {"count": 8}])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 5)
        self.assertEqual(doc["findings"][0]["count"], 5)

    def test_conflicting_baseline_accounting_is_rejected_atomically(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        known = self.capture_baseline([aggregate], critical=3)
        self.baseline.write_text(json.dumps({"findings": [known[0], known[0] | {"count": 7}]}),
                                 encoding="utf-8")
        self.summary(critical=3)
        self.assert_refused("baseline has conflicting records")

    def test_project_note_cannot_hide_a_new_positive_aggregate(self) -> None:
        note = self.finding(path="", line=0, scope="project", count=0, severity="info")
        known = self.capture_baseline([note])
        self.summary(info=2)
        self.sink([note | {"scope": "project_aggregate", "count": 2}])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["info"], 2)
        self.assertEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])

    def test_legacy_fingerprints_filter_sources_but_do_not_prove_aggregate_weights(self) -> None:
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                record = (self.finding(path="", line=0, scope="project_aggregate", count=3)
                          if aggregate else self.finding())
                count = 3 if aggregate else 1
                known = self.capture_baseline([record], critical=count)
                for representation in ([known[0]["fingerprint"]],
                                       [{"fingerprint": known[0]["fingerprint"]}]):
                    with self.subTest(representation=representation):
                        self.baseline.write_text(json.dumps(representation), encoding="utf-8")
                        self.summary(critical=count)
                        doc = self.filtered()
                        self.assertEqual(doc["totals"]["critical"], count if aggregate else 0)
                        self.assertEqual(len(doc["findings"]), int(aggregate))

    def test_baseline_matching_does_not_cross_language_boundaries(self) -> None:
        known = self.capture_baseline([self.finding()], critical=1)
        self.baseline.write_text(json.dumps({"findings": [known[0] | {"lang": "js"}]}), encoding="utf-8")
        self.summary(critical=1)
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 1)

    def test_report_only_baseline_does_not_hide_a_new_counted_finding(self) -> None:
        doc = self.summary()
        doc["scanners"][0]["extras"] = {"ast_findings": [self.finding()]}
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        merge(self.root, self.combined)
        self.baseline.write_bytes(self.combined.read_bytes())
        self.summary(critical=1)
        self.sink([self.finding()])
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 1)
        self.assertEqual(len(doc["findings"]), 1)

    def test_counted_baseline_does_not_hide_a_new_report_only_finding(self) -> None:
        self.capture_baseline([self.finding()], critical=1)
        self.sink([])
        doc = self.summary()
        doc["scanners"][0]["extras"] = {"ast_findings": [self.finding()]}
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        doc = self.filtered()
        self.assertEqual(doc["totals"]["critical"], 0)
        self.assertEqual(len(doc["scanners"][0]["extras"]["ast_findings"]), 1)

    def test_known_ast_report_evidence_still_filters_in_its_own_channel(self) -> None:
        original = self.summary()
        original["scanners"][0]["extras"] = {"ast_findings": [self.finding()]}
        self.combined.write_text(json.dumps(original), encoding="utf-8")
        merge(self.root, self.combined)
        self.baseline.write_bytes(self.combined.read_bytes())
        self.combined.write_text(json.dumps(original), encoding="utf-8")
        doc = self.filtered()
        self.assertEqual(doc["scanners"][0]["extras"]["ast_findings"], [])

    def test_occurrence_allowances_do_not_leak_between_merges(self) -> None:
        aggregate = self.finding(path="", line=0, scope="project_aggregate", count=3)
        self.capture_baseline([aggregate], critical=3)
        for _ in range(3):
            self.summary(critical=8)
            self.sink([aggregate | {"count": 8}])
            self.assertEqual(self.filtered()["totals"]["critical"], 5)

    def test_invalid_baseline_policy_metadata_is_rejected(self) -> None:
        known = self.capture_baseline([self.finding()], critical=1)
        for changes in ({"severity": "error"}, {"suppressed": "false"}, {"scope": "other"},
                        {"scope": "project_aggregate", "count": True},
                        {"scope": "project_aggregate", "count": 0},
                        {"scope": "project_aggregate", "count": "3"},
                        {"scope": "project", "count": 1}):
            with self.subTest(changes=changes):
                self.baseline.write_text(json.dumps({"findings": [known[0] | changes]}), encoding="utf-8")
                self.summary(critical=1)
                self.assert_refused("baseline")

    def test_changing_cwd_does_not_change_a_project_fingerprint(self) -> None:
        project, unrelated = self.root / "project", self.root / "unrelated"
        project.mkdir()
        unrelated.mkdir()
        (project / "app.py").write_text("value = 1\n", encoding="utf-8")
        (unrelated / "app.py").write_text("value = 999\n", encoding="utf-8")
        self.summary(critical=1)
        self.sink([self.finding()])
        with chdir(project):
            self.merge_project(project)
        self.baseline.write_bytes(self.combined.read_bytes())
        self.summary(critical=1)
        with chdir(unrelated):
            doc = self.merge_project(project, new_only=True)
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["totals"]["critical"], 0)

    def test_unrelated_cwd_file_cannot_hide_a_changed_project_statement(self) -> None:
        project, unrelated = self.root / "project", self.root / "unrelated"
        project.mkdir()
        unrelated.mkdir()
        source = project / "app.py"
        source.write_text("value = 1\n", encoding="utf-8")
        (unrelated / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.summary(critical=1)
        self.sink([self.finding()])
        with chdir(project):
            known = self.merge_project(project)["findings"]
        self.baseline.write_bytes(self.combined.read_bytes())
        source.write_text("value = 2\n", encoding="utf-8")
        self.summary(critical=1)
        with chdir(unrelated):
            doc = self.merge_project(project, new_only=True)
        self.assertEqual(doc["totals"]["critical"], 1)
        self.assertNotEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])

    def test_missing_project_source_does_not_fall_back_to_a_cwd_namesake(self) -> None:
        project, unrelated = self.root / "project", self.root / "unrelated"
        project.mkdir()
        unrelated.mkdir()
        (unrelated / "app.py").write_text("value = 999\n", encoding="utf-8")
        self.summary(critical=1)
        self.sink([self.finding()])
        with chdir(unrelated):
            doc = self.merge_project(project)
        expected = hashlib.sha256(b"py.security.eval\x1fapp.py\x1f_ID_ _ID_\x1f0").hexdigest()[:16]
        self.assertEqual(doc["findings"][0]["fingerprint"], expected)

    def test_whitespace_in_source_names_does_not_alias_a_known_file(self) -> None:
        for name in (" app.py", "app.py ", " app.py "):
            with self.subTest(name=name):
                (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
                (self.root / name).write_text("value = 1\n", encoding="utf-8")
                self.summary(critical=1)
                self.sink([self.finding()])
                known = self.merge_project(self.root)["findings"]
                self.baseline.write_bytes(self.combined.read_bytes())
                self.summary(critical=1)
                self.sink([self.finding(path=name)])
                doc = self.merge_project(self.root, new_only=True)
                self.assertEqual(doc["totals"]["critical"], 1)
                self.assertEqual(doc["findings"][0]["file"], name)
                self.assertNotEqual(doc["findings"][0]["fingerprint"], known[0]["fingerprint"])

    def test_snapshot_fingerprints_preserve_whitespace_in_logical_paths(self) -> None:
        project, snapshot = self.root / "project", self.root / "snapshot"
        project.mkdir()
        snapshot.mkdir()
        name = " app.py "
        (snapshot / name).write_text("value = 1\n", encoding="utf-8")
        self.summary(critical=1)
        self.sink([self.finding(path=str(project / name))])
        merge(self.root, self.combined, project_dir=project, source_root=snapshot)
        doc = json.loads(self.combined.read_text(encoding="utf-8"))
        expected = hashlib.sha256(f"py.security.eval\x1f{name}\x1f_ID_ = 1\x1f0".encode()).hexdigest()[:16]
        self.assertEqual(doc["findings"][0]["fingerprint"], expected)

    def test_unfingerprinted_ast_reports_remain_visible_without_known_baseline_identities(self) -> None:
        # Already-normalized report-only evidence historically need not have
        # a fingerprint when no baseline comparison can remove it.
        record = {"rule_id": "py.report", "file": "app.py", "line": 1,
                  "severity": "warning", "message": "advisory evidence"}
        for new_only in (False, True):
            with self.subTest(new_only=new_only):
                doc = self.summary()
                doc["scanners"][0]["extras"] = {"ast_findings": [record]}
                self.combined.write_text(json.dumps(doc), encoding="utf-8")
                self.assertEqual(merge(self.root, self.combined, baseline_path=self.baseline,
                                       new_only=new_only), 0)
                merged = json.loads(self.combined.read_text(encoding="utf-8"))
                self.assertEqual(merged["scanners"][0]["extras"]["ast_findings"], [record])
                self.assertEqual(merged["totals"]["warning"], 0)


class StreamingBaselineTests(unittest.TestCase):
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="baseline-stream-", dir=ARTIFACTS)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.baseline = self.root / "baseline.json"

    def store(self, value):
        self.baseline.write_text(json.dumps(value), encoding="utf-8")
        return self.baseline

    def filter(self, value, limit):
        with mock.patch.object(findings_merge._BaselineFilter, "MEMORY_LIMIT", limit):
            result = findings_merge._BaselineFilter(self.store(value))
        self.addCleanup(result.close)
        return result

    def test_chunk_boundaries_preserve_json_scalars_and_escaped_names(self):
        doc = {"metadata": [1.2e-50, -1e+20, -0.02, None, True, False,
                            "line\nquote\"slash\\\u0000", {"ignored": [1, 2, 3]}],
               "findings": [{"fingerprint": "nul\0name\n雪😀", "severity": "warning"}],
               "scanners": [{"extras": {"ast_findings": [{"fingerprint": "scanner"}]}}],
               "extras": {"ast_findings": [{"fingerprint": "root"}]}}
        expected = [("counted", doc["findings"][0]), ("report", {"fingerprint": "scanner"}),
                    ("report", {"fingerprint": "root"})]
        for size in (1, 2, 3, 7, 64, 65536):
            for ascii_only in (True, False):
                with self.subTest(size=size, ascii_only=ascii_only):
                    self.baseline.write_text(json.dumps(doc, ensure_ascii=ascii_only), encoding="utf-8")
                    with mock.patch.object(findings_merge._BaselineJSON, "CHUNK_SIZE", size):
                        self.assertEqual(list(findings_merge._baseline_records(self.baseline)), expected)

    def test_only_documented_report_containers_supply_baseline_credit(self):
        self.store({"findings": [{"fingerprint": "counted"}],
                    "nested": {"findings": [{"fingerprint": "not-a-finding"}]},
                    "scanners": [None, 3, {"findings": [{"fingerprint": "not-counted"}],
                                          "extras": {"ast_findings": [{"fingerprint": "advice"}]}}]})
        self.assertEqual(list(findings_merge._baseline_records(self.baseline)),
                         [("counted", {"fingerprint": "counted"}), ("report", {"fingerprint": "advice"})])

    def test_fingerprint_lists_keep_wildcard_and_counted_channels_separate(self):
        self.store(["legacy", {"fingerprint": "counted"}])
        self.assertEqual(list(findings_merge._baseline_records(self.baseline)),
                         [("*", {"fingerprint": "legacy"}), ("counted", {"fingerprint": "counted"})])

    def test_invalid_json_after_valid_records_never_publishes_a_filtered_report(self):
        for suffix in (",]", "] trailing", ",", ",true]", ',{"fingerprint":}', ',{"fingerprint":""}]'):
            for chunk_size in (1, 65536):
                with self.subTest(suffix=suffix, chunk_size=chunk_size):
                    self.baseline.write_text('["known"' + suffix, encoding="utf-8")
                    combined = self.root / "combined.json"
                    original = '{"scanners":[],"totals":{}}'
                    combined.write_text(original, encoding="utf-8")
                    with mock.patch.object(findings_merge._BaselineJSON, "CHUNK_SIZE", chunk_size):
                        with self.assertRaises(ValueError):
                            merge(self.root, combined, baseline_path=self.baseline, new_only=True)
                    self.assertEqual(combined.read_text(encoding="utf-8"), original)

    def test_duplicate_relevant_containers_are_rejected(self):
        for source in ('{"findings":[],"findings":[]}',
                       '{"extras":{"ast_findings":[],"ast_findings":[]}}',
                       '{"scanners":[],"scanners":[]}',
                       '{"scanners":[{"extras":{},"extras":{}}]}'):
            with self.subTest(source=source):
                self.baseline.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "duplicate baseline report field"):
                    load_baseline_fingerprints(self.baseline)

    def test_malformed_numbers_are_not_accepted_at_a_chunk_boundary(self):
        for number in ("01", "1e", "1e+", "--2", "1.", "-", "1x"):
            with self.subTest(number=number):
                self.baseline.write_text('{"metadata":' + number + ',"findings":[]}', encoding="utf-8")
                with mock.patch.object(findings_merge._BaselineJSON, "CHUNK_SIZE", 1):
                    with self.assertRaises(ValueError):
                        load_baseline_fingerprints(self.baseline)

    def test_individual_values_and_metadata_nesting_are_bounded(self):
        for source in ('["' + 'a' * 300 + '"]', '{"metadata":"' + 'a' * 300 + '"}',
                       '{"metadata":' + '[' * 10 + '0' + ']' * 10 + '}'):
            with self.subTest(source=source):
                self.baseline.write_text(source, encoding="utf-8")
                with mock.patch.multiple(findings_merge._BaselineJSON, MAX_VALUE=128,
                                         MAX_DEPTH=5, CHUNK_SIZE=7):
                    with self.assertRaises(ValueError):
                        load_baseline_fingerprints(self.baseline)
        # A large read buffer cannot bypass the individual-value limit.
        with mock.patch.multiple(findings_merge._BaselineJSON, MAX_VALUE=128, CHUNK_SIZE=4096):
            self.store(["a" * 300])
            with self.assertRaises(ValueError):
                load_baseline_fingerprints(self.baseline)

    def test_unknown_large_arrays_are_walked_in_bounded_reads(self):
        class BoundedReader(io.StringIO):
            def read(self, size=-1):
                if not 0 <= size <= 19:
                    raise AssertionError("unbounded baseline read")
                return super().read(size)
        source = BoundedReader('{"metadata":[' + ','.join(['{"text":"metadata"}'] * 5000)
                               + '],"findings":[{"fingerprint":"known"}]}')
        with mock.patch.object(findings_merge._BaselineJSON, "CHUNK_SIZE", 19):
            parser = findings_merge._BaselineJSON(source)
            self.assertEqual(list(parser.report()), [("counted", {"fingerprint": "known"})])
            self.assertEqual(parser.peek(), "")

    def test_spilled_matching_preserves_scope_severity_language_and_occurrence_budget(self):
        huge_count = 2 ** 80
        entries = [
            {"fingerprint": "ordinary", "lang": "python", "severity": "warning"},
            {"fingerprint": "aggregate", "scope": "project_aggregate", "count": huge_count,
             "severity": "warning"},
            {"fingerprint": "note", "scope": "project", "count": 0, "severity": "info"},
            {"fingerprint": "suppressed", "suppressed": True},
            {"fingerprint": "unicode\0\ud800雪", "lang": "py\udfff"},
        ]
        for limit in (100, 1):
            with self.subTest(limit=limit):
                baseline = self.filter({"findings": entries + [entries[1]],
                                        "extras": {"ast_findings": [{"fingerprint": "advisory"}]}}, limit)
                ordinary = {"fingerprint": "ordinary", "lang": "python", "severity": "warning"}
                for changed in ({**ordinary, "severity": "critical"}, {**ordinary, "lang": "go"},
                                {"fingerprint": "advisory"}, {"fingerprint": "suppressed"}):
                    self.assertEqual(baseline.retain(changed), changed)
                self.assertIsNone(baseline.retain(ordinary))
                self.assertEqual(baseline.retain(ordinary), ordinary)
                aggregate = {"fingerprint": "aggregate", "scope": "project_aggregate",
                             "count": huge_count - 3, "severity": "warning"}
                self.assertIsNone(baseline.retain(aggregate))
                self.assertEqual(baseline.retain({**aggregate, "count": 8}), {**aggregate, "count": 5})
                self.assertEqual(baseline.retain({**aggregate, "count": 1}), {**aggregate, "count": 1})
                self.assertIsNone(baseline.retain({"fingerprint": "note", "scope": "project", "severity": "info"}))
                self.assertIsNone(baseline.retain({"fingerprint": "note", "scope": "project", "severity": "info"}))
                self.assertIsNone(baseline.retain({"fingerprint": "unicode\0\ud800雪", "lang": "py\udfff"}))
                self.assertIsNone(baseline.retain({"fingerprint": "advisory"}, "report"))

    def test_specific_language_allowance_still_takes_precedence_after_spill(self):
        entries = [{"fingerprint": "same", "lang": "python", "severity": "info"},
                   {"fingerprint": "same", "severity": "critical"}]
        for limit in (100, 0):
            with self.subTest(limit=limit):
                baseline = self.filter(entries, limit)
                finding = {"fingerprint": "same", "lang": "python", "severity": "warning"}
                self.assertEqual(baseline.retain(finding), finding)
                self.assertIsNone(baseline.retain({**finding, "lang": "go"}))

    def test_conflicting_records_after_spill_are_still_rejected(self):
        for limit in (100, 1):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "conflicting records"):
                self.filter([{"fingerprint": "same", "severity": "info"}, {"fingerprint": "other"},
                             {"fingerprint": "same", "severity": "critical"}], limit)

    def test_closed_filter_never_becomes_an_empty_successful_baseline(self):
        for limit in (100, 0):
            with self.subTest(limit=limit):
                baseline = self.filter(["known"], limit)
                baseline.close()
                baseline.close()
                with self.assertRaisesRegex(ValueError, "closed"):
                    baseline.retain({"fingerprint": "known"})

    def test_successful_merge_closes_the_spilled_baseline(self):
        real_connect = findings_merge.sqlite3.connect
        connections = []
        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection
        combined = self.root / "combined.json"
        combined.write_text('{"scanners":[],"totals":{}}', encoding="utf-8")
        self.store(["known"])
        with mock.patch.object(findings_merge._BaselineFilter, "MEMORY_LIMIT", 0), \
                mock.patch.object(findings_merge.sqlite3, "connect", side_effect=connect):
            self.assertEqual(merge(self.root, combined, baseline_path=self.baseline, new_only=True), 0)
        self.assertEqual(len(connections), 1)
        with self.assertRaises(findings_merge.sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")

    def test_disk_error_and_late_parse_error_close_database_without_publishing(self):
        real_connect = findings_merge.sqlite3.connect
        connections = []
        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection
        combined = self.root / "combined.json"
        original = '{"scanners":[],"totals":{}}'
        combined.write_text(original, encoding="utf-8")
        self.baseline.write_text('["one", "two", ', encoding="utf-8")
        with mock.patch.object(findings_merge._BaselineFilter, "MEMORY_LIMIT", 0), \
                mock.patch.object(findings_merge.sqlite3, "connect", side_effect=connect):
            with self.assertRaises(ValueError):
                merge(self.root, combined, baseline_path=self.baseline, new_only=True)
        self.assertEqual(len(connections), 1)
        with self.assertRaises(findings_merge.sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")
        self.assertEqual(combined.read_text(encoding="utf-8"), original)
        with mock.patch.object(findings_merge._BaselineFilter, "MEMORY_LIMIT", 0), \
                mock.patch.object(findings_merge.sqlite3, "connect",
                                  side_effect=findings_merge.sqlite3.OperationalError("disk full")):
            with self.assertRaisesRegex(ValueError, "disk full"):
                merge(self.root, combined, baseline_path=self.baseline, new_only=True)
        self.assertEqual(combined.read_text(encoding="utf-8"), original)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux VmHWM peak RSS")
    def test_large_baseline_and_new_findings_merge_stays_below_64_mib(self):
        started = time.monotonic()
        print("[baseline-stream-memory] RUN 120000 distinct baseline findings", flush=True)
        known = {"rule": "py.memory", "path": "missing.py", "line": 0,
                 "severity": "warning", "message": "diagnostic 1"}
        sink = self.root / "python.findings.json"
        combined = self.root / "combined.json"
        sink.write_text(json.dumps(known) + "\n", encoding="utf-8")
        combined.write_text('{"scanners":[],"totals":{}}', encoding="utf-8")
        merge(self.root, combined)
        captured = json.loads(combined.read_text())["findings"][0]
        with self.baseline.open("w", encoding="utf-8") as output:
            output.write('{"findings":[' + json.dumps(captured))
            for index in range(119999):
                output.write(',' + json.dumps({"fingerprint": f"filler-{index}", "lang": "python",
                                              "severity": "warning", "message": "detail " * 40}))
            output.write('],"metadata":[')
            for index in range(20000):
                output.write((',' if index else '') + json.dumps({"annotation": "text " * 30}))
            output.write(']}')
        sink.write_text(json.dumps(known) + "\n" + json.dumps({**known, "message": "diagnostic 2"}) + "\n",
                        encoding="utf-8")
        combined.write_text('{"scanners":[{"language":"python","warning":2}],"totals":{"warning":2}}',
                            encoding="utf-8")
        program = (
            "import json, pathlib, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from ubs_core.findings_merge import merge\n"
            "root = pathlib.Path(sys.argv[2])\n"
            "count = merge(root, root/'combined.json', baseline_path=root/'baseline.json', new_only=True)\n"
            "rss = next(int(s.split()[1]) for s in pathlib.Path('/proc/self/status').read_text().splitlines() if s.startswith('VmHWM:'))\n"
            "print(json.dumps({'count':count,'rss':rss}))\n"
        )
        proc = subprocess.run([sys.executable, "-c", program, str(REPO_ROOT / "modules/helpers"), str(self.root)],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        measured = json.loads(proc.stdout)
        self.assertEqual(measured["count"], 1)
        self.assertLess(measured["rss"], 64 * 1024, measured)
        result = json.loads(combined.read_text(encoding="utf-8"))
        self.assertEqual(result["totals"]["warning"], 1)
        self.assertEqual(result["findings"][0]["message"], "diagnostic 2")
        self.assertNotEqual(result["findings"][0]["fingerprint"], captured["fingerprint"])
        print(f"[baseline-stream-memory] PASS {measured['rss']} KiB ({time.monotonic() - started:.2f}s)", flush=True)


class OccurrenceExportIntegrityTests(unittest.TestCase):
    """Delivery and accounting boundaries independent of language heuristics."""

    def setUp(self):
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="occurrence-integrity-", dir=ARTIFACTS)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.combined = self.root / "combined.json"
        self.output = self.root / "out.jsonl"
        (self.root / "app.py").write_text("one\n\ttwo\nthree\n", encoding="utf-8")

    def tearDown(self):
        print(f"[{self.id()}] END ({time.monotonic() - self.started:.3f}s)", flush=True)

    def finding(self, line=1, **extra):
        return {"lang": "python", "rule_id": "py.test.rule", "severity": "warning",
                "file": "app.py", "line": line, "col": 1,
                "fingerprint": f"existing-fingerprint-{line}", "suppressed": False,
                "message": "test diagnostic", **extra}

    def document(self, findings, *, warning=0, critical=0, info=0, status="ok"):
        counts = {"warning": warning, "critical": critical, "info": info}
        doc = {"project": str(self.root), "timestamp": "2026-10-28T00:00:00Z",
               "status": status, "failed_modules": [], "findings": findings,
               "scanners": [{"language": "python", "status": status, "files": 1,
                             "timestamp": "2026-10-27T23:59:59Z", **counts}],
               "totals": {"files": 1, **counts}}
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        return doc

    def export(self, **options):
        before = self.combined.read_bytes()
        occurrences.export(self.combined, self.output, project_dir=self.root, **options)
        self.assertEqual(self.combined.read_bytes(), before)
        with self.output.open(encoding="utf-8") as source:
            rows = [json.loads(line) for line in source]
        self.assertEqual(rows[-1]["type"], "totals")
        return rows

    def test_limit_reconciles_counts_and_does_not_change_identities(self):
        doc = self.document([self.finding(n) for n in (1, 2, 3)], warning=3)
        short = self.export(max_occurrences=2)
        short_findings = [r for r in short if r["type"] == "finding"]
        self.assertEqual([r["code"] for r in short_findings], ["one", "\ttwo"])
        metadata = short[-1]["occurrence_export"]
        self.assertEqual((metadata["reported"], metadata["accounted"], metadata["emitted"], metadata["omitted"]),
                         (3, 3, 2, 1))
        self.assertTrue(metadata["analysis_complete"])
        self.assertFalse(metadata["locations_complete"])
        self.assertFalse(metadata["complete"])
        self.assertIn("occurrence_limit", metadata["reasons"])
        self.assertEqual(short[-2]["scanner_timestamp"], "2026-10-27T23:59:59Z")
        doc["timestamp"] = "2026-10-29T00:00:00Z"
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        full = self.export(max_occurrences=3)
        full_findings = [r for r in full if r["type"] == "finding"]
        self.assertEqual([r["occurrence_id"] for r in short_findings],
                         [r["occurrence_id"] for r in full_findings[:2]])
        self.assertEqual(len({r["occurrence_id"] for r in full_findings}), 3)
        self.assertTrue(all(r["occurrence_id"].startswith("sha256:") for r in full_findings))
        self.assertEqual(full_findings[0]["title"], "test diagnostic")
        self.assertTrue(full[-1]["occurrence_export"]["complete"])
        self.assertEqual(full[-1]["status"], "ok")

    def test_aggregate_counts_do_not_invent_source_occurrences(self):
        self.document([
            self.finding(extras={"taint_path": [{"kind": "source", "line": 1}]}),
            self.finding(rule_id="py.project.weighted", scope="project_aggregate", file="", line=0, count=6),
            self.finding(rule_id="py.project.note", scope="project", file="", line=0, count=0, severity="info"),
            self.finding(suppressed=True),
        ], warning=7)
        rows = self.export()
        found = [r for r in rows if r["type"] == "finding"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["count"], 1)
        self.assertEqual(found[0]["extras"]["taint_path"], [{"kind": "source", "line": 1}])
        rules = {r["rule_id"]: r for r in rows if r["type"] == "rule_summary"}
        self.assertEqual(set(rules), {"py.test.rule", "py.project.weighted"})
        self.assertEqual((rules["py.project.weighted"]["reported"], rules["py.project.weighted"]["emitted"],
                          rules["py.project.weighted"]["omitted"], rules["py.project.weighted"]["unlocated"]),
                         (6, 0, 6, 6))
        metadata = rows[-1]["occurrence_export"]
        self.assertEqual((metadata["reported"], metadata["accounted"], metadata["emitted"], metadata["unlocated"]),
                         (7, 7, 1, 6))
        self.assertFalse(metadata["complete"])
        self.assertIn("unlocated_occurrences", metadata["reasons"])

    def test_missing_ledger_cannot_fall_back_to_sampled_locations(self):
        doc = self.document([], critical=50)
        del doc["findings"]
        doc["scanners"][0]["findings"] = [{"rule_id": "py.sampled", "count": 50,
                                          "samples": [{"file": "app.py", "line": 1}]}]
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        rows = self.export()
        self.assertFalse(any(r["type"] == "finding" for r in rows))
        metadata = rows[-1]["occurrence_export"]
        self.assertEqual((metadata["reported"], metadata["accounted"], metadata["omitted"]), (50, 0, 50))
        self.assertFalse(metadata["complete"])
        self.assertIn("missing_findings_ledger", metadata["reasons"])

    def test_severity_mismatch_cannot_be_hidden_by_equal_total_counts(self):
        self.document([self.finding()], critical=1)
        metadata = self.export()[-1]["occurrence_export"]
        self.assertEqual(metadata["reported"], metadata["accounted"])
        self.assertEqual(metadata["counts"]["critical"], {"reported": 1, "accounted": 0, "emitted": 0, "omitted": 1})
        self.assertEqual(metadata["counts"]["warning"], {"reported": 0, "accounted": 1, "emitted": 1, "omitted": 0})
        self.assertFalse(metadata["complete"])
        self.assertIn("count_mismatch", metadata["reasons"])

    def test_scanner_mismatches_cannot_cancel_out_in_global_totals(self):
        (self.root / "app.rb").write_text("puts 'hello'\n", encoding="utf-8")
        doc = self.document([self.finding(), self.finding(lang="ruby", rule_id="rb.test.rule",
                                                        file="app.rb", severity="critical")], critical=1, warning=1)
        doc["scanners"][0]["warning"] = 0
        doc["scanners"].append({"language": "ruby", "status": "ok", "files": 1,
                                 "critical": 0, "warning": 1, "info": 0})
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        metadata = self.export()[-1]["occurrence_export"]
        self.assertEqual(metadata["reported"], metadata["accounted"])
        self.assertEqual(metadata["emitted"], 2)
        self.assertFalse(metadata["locations_complete"])
        self.assertFalse(metadata["complete"])
        self.assertIn("scanner_count_mismatch", metadata["reasons"])

    def test_empty_scan_requires_canonical_or_private_ledger_evidence(self):
        doc = self.document([])
        del doc["findings"]
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        metadata = self.export()[-1]["occurrence_export"]
        self.assertFalse(metadata["complete"])
        self.assertIn("missing_findings_ledger", metadata["reasons"])
        (self.root / "python.findings.json").write_text("", encoding="utf-8")
        metadata = self.export(tmp_dir=self.root)[-1]["occurrence_export"]
        self.assertTrue(metadata["complete"])
        self.assertEqual(metadata["reported"], 0)

    def test_rule_group_limit_preserves_existing_destination(self):
        self.output.write_text("previous report\n", encoding="utf-8")
        previous = self.output.read_bytes()
        self.document([self.finding(rule_id="py.first"), self.finding(rule_id="py.second")], warning=2)
        with mock.patch.object(occurrences, "MAX_RULE_SUMMARIES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds 1 distinct rule summaries"):
                self.export()
        self.assertEqual(self.output.read_bytes(), previous)

    def test_partial_analysis_and_unavailable_code_are_independent(self):
        doc = self.document([self.finding()], warning=1, status="partial")
        doc["failed_modules"] = [{"language": "python", "status": "partial",
                                  "module_error": "ANALYZER_ERROR", "message": "invalid peer.py"}]
        doc["scanners"][0].update(module_error="ANALYZER_ERROR", message="invalid peer.py")
        self.combined.write_text(json.dumps(doc), encoding="utf-8")
        rows = self.export()
        metadata = rows[-1]["occurrence_export"]
        self.assertFalse(metadata["analysis_complete"])
        self.assertTrue(metadata["locations_complete"])
        self.assertFalse(metadata["complete"])
        self.assertEqual(rows[-2]["module_error"], "ANALYZER_ERROR")
        self.assertEqual(rows[-1]["failed_modules"], doc["failed_modules"])
        self.document([self.finding(file="missing.py")], warning=1)
        rows = self.export()
        metadata = rows[-1]["occurrence_export"]
        self.assertTrue(metadata["analysis_complete"])
        self.assertTrue(metadata["locations_complete"])
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["code_unavailable"], 1)
        self.assertFalse(rows[0]["code_available"])
        self.assertEqual(rows[0]["code"], "")

    def test_snapshot_code_honors_python_encoding_and_physical_lines(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        (snapshot / "app.py").write_bytes(b"# coding: latin-1\r\n  value = 'caf\xe9'\r\n")
        (snapshot / "unicode.py").write_text("# header\r\nvalue = '\u2028'\f# same physical line\r\n", encoding="utf-8")
        self.document([self.finding(2, file=str(self.root / "app.py")),
                       self.finding(2, file=str(self.root / "unicode.py"), fingerprint="unicode")], warning=2)
        rows = self.export(source_root=snapshot)
        found = [r for r in rows if r["type"] == "finding"]
        self.assertEqual([r["code"] for r in found], ["  value = 'café'", "value = '\u2028'\f# same physical line"])
        self.assertTrue(rows[-1]["occurrence_export"]["complete"])
        self.assertEqual(found[0]["file"], str(self.root / "app.py"))

    def test_code_and_source_work_limits_are_explicit(self):
        (self.root / "app.py").write_text("#" + "x" * 5000 + "\n", encoding="utf-8")
        self.document([self.finding()], warning=1)
        rows = self.export()
        self.assertEqual(len(rows[0]["code"]), 4096)
        self.assertTrue(rows[0]["code_truncated"])
        metadata = rows[-1]["occurrence_export"]
        self.assertTrue(metadata["locations_complete"])
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["omitted"], 0)
        self.assertEqual(metadata["code_truncated"], 1)
        with mock.patch.object(occurrences, "SOURCE_WORK_LIMIT", 8):
            rows = self.export()
        self.assertFalse(rows[0]["code_available"])
        self.assertEqual(rows[0]["code_reason"], "code_work_limit")
        self.assertIn("code_work_limit", rows[-1]["occurrence_export"]["reasons"])
        (self.root / "app.py").write_text("#" + "x" * 65536 + "\n", encoding="utf-8")
        rows = self.export()
        self.assertFalse(rows[0]["code_available"])
        self.assertEqual(rows[0]["code_reason"], "encoding_header_limit")

    def test_late_failure_preserves_prior_output(self):
        self.output.write_text("prior complete report\n", encoding="utf-8")
        previous = self.output.read_bytes()
        self.document([self.finding(), self.finding(2, fingerprint="")], warning=2)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.export()
        self.assertEqual(self.output.read_bytes(), previous)
        self.document([self.finding()], warning=1)
        with mock.patch.object(occurrences.os, "replace", side_effect=OSError("delivery failure")):
            with self.assertRaisesRegex(OSError, "delivery failure"):
                self.export()
        self.assertEqual(self.output.read_bytes(), previous)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO")
    def test_fifo_source_returns_incomplete_code_without_blocking(self):
        source = self.root / "source.py"
        os.mkfifo(source)
        self.document([self.finding(file=str(source))], warning=1)
        # Start the hang deadline after imports: a cold supported interpreter
        # can take more than two seconds to import on a busy test worker.
        program = (
            "import signal\n"
            "from ubs_core import occurrences\n"
            "from ubs_core.cli import main\n"
            "signal.alarm(2)\n"
            "raise SystemExit(main())\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", program, "occurrences", "--combined", str(self.combined),
             "--output", str(self.output), "--project-dir", str(self.root)],
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "modules" / "helpers"),
                 "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with self.output.open(encoding="utf-8") as exported:
            rows = [json.loads(line) for line in exported]
        self.assertEqual(rows[0]["code_reason"], "source_not_regular")
        self.assertFalse(rows[0]["code_available"])
        self.assertEqual(rows[-1]["occurrence_export"]["emitted"], 1)
        self.assertFalse(rows[-1]["occurrence_export"]["complete"])

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO")
    def test_fifo_replacement_after_stat_is_checked_on_open_descriptor(self):
        source = self.root / "source.py"
        os.mkfifo(source)
        # Preserve a regular pre-stat path while supplying a real FIFO at
        # open time, modeling a pathname replacement without a timing race.
        program = (
            "import os, pathlib, signal, sys\n"
            "from unittest import mock\n"
            "from ubs_core import occurrences\n"
            "original_open = os.open\n"
            "opened = []\n"
            "def replaced(path, flags):\n"
            "    if len(sys.argv) > 3:\n"
            "        flags &= ~os.O_NONBLOCK\n"
            "    descriptor = original_open(sys.argv[2], flags)\n"
            "    opened.append(descriptor)\n"
            "    return descriptor\n"
            "signal.alarm(2)\n"
            "with mock.patch.object(occurrences.os, 'open', side_effect=replaced):\n"
            "    try:\n"
            "        occurrences._SourceReader(pathlib.Path(sys.argv[1]), 'python')\n"
            "    except occurrences._CodeUnavailable as exc:\n"
            "        assert str(exc) == 'source_not_regular', str(exc)\n"
            "    else:\n"
            "        raise AssertionError('a FIFO descriptor was accepted')\n"
            "assert len(opened) == 1\n"
            "try:\n"
            "    os.fstat(opened[0])\n"
            "except OSError:\n"
            "    pass\n"
            "else:\n"
            "    raise AssertionError('rejected descriptor leaked')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", program, str(self.root / "app.py"), str(source)],
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "modules" / "helpers"),
                 "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The same deadline must reject an actual blocking FIFO open. This
        # negative control keeps the hang regression independent of startup.
        blocked = subprocess.run(
            [sys.executable, "-c", program, str(self.root / "app.py"), str(source), "blocking"],
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "modules" / "helpers"),
                 "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30, check=False,
        )
        import signal
        self.assertEqual(blocked.returncode, -signal.SIGALRM, blocked.stdout + blocked.stderr)

    def test_encoding_failure_closes_descriptor_and_regular_symlinks_still_work(self):
        source = self.root / "encoded.py"
        source.write_bytes(b"# coding: unknown-no-such-encoding\nvalue = 1\n")
        descriptors = []
        original_open = occurrences.os.open

        def opened(path, flags):
            descriptor = original_open(path, flags)
            descriptors.append(descriptor)
            return descriptor

        with mock.patch.object(occurrences.os, "open", side_effect=opened):
            with self.assertRaises(SyntaxError):
                occurrences._SourceReader(source, "python")
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])
        if hasattr(os, "symlink"):
            link = self.root / "linked.py"
            link.symlink_to(self.root / "app.py")
            self.document([self.finding(file=str(link))], warning=1)
            rows = self.export()
            self.assertEqual(rows[0]["code"], "one")
            self.assertTrue(rows[-1]["occurrence_export"]["complete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
