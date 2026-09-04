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

from ubs_core.findings_merge import load_sink, merge  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
