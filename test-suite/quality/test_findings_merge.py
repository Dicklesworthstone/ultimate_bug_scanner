#!/usr/bin/env python3
"""Unit tests for ubs_core.findings_merge — K2 combined findings[] assembly."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.findings_merge import load_sink, merge, to_sarif  # noqa: E402

SUMMARY_DOC = {
    "scanners": [
        {"language": "python", "files": 1, "critical": 0, "warning": 0, "info": 0, "status": "ok"},
        {"language": "js", "files": 2, "critical": 1, "warning": 0, "info": 0, "status": "ok"},
    ],
    "totals": {"files": 3, "critical": 1, "warning": 0, "info": 0},
}

SINK_PY = "\n".join([
    json.dumps({
        "rule": "python.narrowing.partial_none_guard",
        "category_id": "python.narrowing",
        "path": "src/a.py",
        "line": 17,
        "col": 9,
        "severity": "warning",
        "message": "use after partial guard",
        "suppressed": False,
    }),
    "",  # blank lines are skipped
    "not json at all",  # malformed lines are skipped
    json.dumps({"language": "python", "files": 1, "critical": 0}),  # summary object: skipped
]) + "\n"

SINK_JS = json.dumps({
    "rule": "js.taint.xss",
    "path": "src/b.js",
    "line": 3,
    "severity": "critical",
    "message": "tainted sink",
}) + "\n"


class FindingsMergeTests(unittest.TestCase):
    def test_load_sink_skips_non_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-") as tmp:
            sink = Path(tmp) / "s.json"
            sink.write_text(SINK_PY, encoding="utf-8")
            records = load_sink(sink)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["rule"], "python.narrowing.partial_none_guard")

    def test_merge_builds_normalized_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-") as tmp:
            tmp_dir = Path(tmp)
            (tmp_dir / "python.findings.json").write_text(SINK_PY, encoding="utf-8")
            (tmp_dir / "js.findings.json").write_text(SINK_JS, encoding="utf-8")
            combined = tmp_dir / "combined.json"
            combined.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")

            count = merge(tmp_dir, combined)
            self.assertEqual(count, 2)

            doc = json.loads(combined.read_text(encoding="utf-8"))
            findings = doc["findings"]
            self.assertEqual(len(findings), 2)
            py = next(f for f in findings if f["lang"] == "python")
            self.assertEqual(py["rule_id"], "python.narrowing.partial_none_guard")
            self.assertEqual(py["file"], "src/a.py")
            self.assertEqual(py["line"], 17)
            self.assertEqual(py["col"], 9)
            self.assertEqual(py["severity"], "warning")
            self.assertFalse(py["suppressed"])
            self.assertEqual(len(py["fingerprint"]), 16)
            js = next(f for f in findings if f["lang"] == "js")
            self.assertEqual(js["rule_id"], "js.taint.xss")
            self.assertEqual(js["severity"], "critical")
            # scanners get the sink marker
            py_scanner = next(s for s in doc["scanners"] if s["language"] == "python")
            self.assertTrue(py_scanner.get("findings_sink"))

    def test_merge_no_sinks_is_noop(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-") as tmp:
            tmp_dir = Path(tmp)
            combined = tmp_dir / "combined.json"
            combined.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            self.assertEqual(merge(tmp_dir, combined), 0)
            self.assertNotIn("findings", json.loads(combined.read_text(encoding="utf-8")))

    def test_merge_missing_combined_raises(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-") as tmp:
            with self.assertRaises(ValueError):
                merge(Path(tmp), Path(tmp) / "missing.json")

    def test_to_sarif_builds_valid_runs_and_results(self) -> None:
        doc = {
            "version": "5.3.13",
            "scanners": [{"language": "python"}, {"language": "js"}],
            "findings": [
                {
                    "lang": "python",
                    "rule_id": "py.eval-exec",
                    "category_id": "py",
                    "severity": "critical",
                    "file": "src/a.py",
                    "line": 10,
                    "col": 5,
                    "message": "eval used",
                    "fingerprint": "abc123",
                    "suppressed": False,
                },
                {
                    "lang": "js",
                    "rule_id": "js.taint.xss",
                    "category_id": "js.taint",
                    "severity": "warning",
                    "file": "src/b.js",
                    "line": 20,
                    "col": 1,
                    "message": "xss risk",
                    "fingerprint": "def456",
                    "suppressed": False,
                },
            ],
        }
        sarif = to_sarif(doc, git_blob_base="https://github.com/repo/blob/sha", git_top="src")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 2)
        total_results = sum(len(r["results"]) for r in sarif["runs"])
        self.assertEqual(total_results, 2)

        py_run = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "ubs-python")
        self.assertEqual(len(py_run["results"]), 1)
        res = py_run["results"][0]
        self.assertEqual(res["ruleId"], "py.eval-exec")
        self.assertEqual(res["level"], "error")
        self.assertEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 10)
        self.assertTrue(res["locations"][0]["properties"]["permalink"].startswith("https://github.com/repo/blob/sha/"))

    def test_to_sarif_partial_status_invocations(self) -> None:
        doc = {
            "version": "5.3.13",
            "status": "partial",
            "failed_modules": [{"language": "golang", "status": "timeout", "message": "timed out"}],
            "scanners": [{"language": "golang"}],
            "findings": [],
        }
        sarif = to_sarif(doc)
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 0)
        self.assertIn("invocations", run)
        inv = run["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        self.assertEqual(inv["toolExecutionNotifications"][0]["descriptor"]["id"], "ubs/module-timeout")

    def test_sarif_emits_partial_fingerprints(self) -> None:
        doc = {
            "version": "5.3.13",
            "findings": [
                {
                    "lang": "python",
                    "rule_id": "py.eval-exec",
                    "severity": "critical",
                    "file": "src/a.py",
                    "line": 10,
                    "fingerprint": "abc1234567890123",
                }
            ],
        }
        sarif = to_sarif(doc)
        res = sarif["runs"][0]["results"][0]
        self.assertIn("partialFingerprints", res)
        self.assertEqual(res["partialFingerprints"]["ubs/v1"], "abc1234567890123")

    def test_normalize_statement_invariance(self) -> None:
        from ubs_core.findings_merge import normalize_statement
        stmt1 = "    result = 1 / 0  # division by zero"
        stmt2 = "answer = 1 / 0 // zero div"
        self.assertEqual(normalize_statement(stmt1), "_ID_ = 1 / 0")
        self.assertEqual(normalize_statement(stmt2), "_ID_ = 1 / 0")

    def test_baseline_filtering_new_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-base-") as tmp:
            tmp_dir = Path(tmp)
            sink = tmp_dir / "python.findings.json"
            sink.write_text(SINK_PY, encoding="utf-8")
            combined = tmp_dir / "combined.json"
            combined.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")

            # First merge: save as baseline
            merge(tmp_dir, combined)
            base_doc = json.loads(combined.read_text(encoding="utf-8"))
            base_file = tmp_dir / "baseline.json"
            base_file.write_text(json.dumps(base_doc), encoding="utf-8")

            # Second merge with new_only=True and same finding: should filter out
            combined2 = tmp_dir / "combined2.json"
            combined2.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            count = merge(tmp_dir, combined2, baseline_path=base_file, new_only=True)
            self.assertEqual(count, 0)
            doc2 = json.loads(combined2.read_text(encoding="utf-8"))
            self.assertEqual(doc2["findings"], [])
            self.assertEqual(doc2["totals"]["critical"], 0)
            self.assertEqual(doc2["totals"]["warning"], 0)

            # Add a second genuinely new finding
            sink2_content = SINK_PY + json.dumps({
                "rule": "python.security.eval",
                "path": "src/new_eval.py",
                "line": 5,
                "severity": "critical",
                "message": "eval execution",
            }) + "\n"
            sink.write_text(sink2_content, encoding="utf-8")
            combined3 = tmp_dir / "combined3.json"
            combined3.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            count = merge(tmp_dir, combined3, baseline_path=base_file, new_only=True)
            self.assertEqual(count, 1)
            doc3 = json.loads(combined3.read_text(encoding="utf-8"))
            self.assertEqual(len(doc3["findings"]), 1)
            self.assertEqual(doc3["findings"][0]["rule_id"], "python.security.eval")
            self.assertEqual(doc3["totals"]["critical"], 1)


if __name__ == "__main__":
    unittest.main()

