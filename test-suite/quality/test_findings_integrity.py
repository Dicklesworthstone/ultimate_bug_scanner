#!/usr/bin/env python3
"""Regression gates for complete, fail-closed baseline finding accounting."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
import unittest
from contextlib import chdir
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "modules" / "helpers"))
from ubs_core.findings_merge import load_baseline_fingerprints, load_sink, merge, to_sarif

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
