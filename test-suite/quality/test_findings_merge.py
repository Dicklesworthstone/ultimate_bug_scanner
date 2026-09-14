#!/usr/bin/env python3
"""Unit tests for ubs_core.findings_merge — K2 combined findings[] assembly."""
from __future__ import annotations

import json
import hashlib
import io
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
    def read_report(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.fail(f"merged report is not valid JSON: {exc}")

    def test_repeated_findings_read_source_once_and_preserve_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-source-") as tmp:
            root = Path(tmp)
            source = root / "source.rs"
            source.write_bytes(b'let value = 1;\r\n// invalid utf8: \xff\n' + b'// padding\n' * 100_000)
            records = [{"rule": "rust.test", "path": str(source), "line": 1} for _ in range(128)]
            (root / "rust.findings.json").write_text(
                "".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8",
            )
            combined = root / "combined.json"
            combined.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            source_reads = 0

            def count_reads(frame, event, arg):
                nonlocal source_reads
                if (event == "call" and frame.f_code is Path.read_text.__code__
                        and frame.f_locals.get("self") == source):
                    source_reads += 1

            previous_profile = sys.getprofile()
            sys.setprofile(count_reads)
            try:
                self.assertEqual(merge(root, combined, project_dir=root), len(records))
            finally:
                sys.setprofile(previous_profile)
            self.assertEqual(source_reads, 1)
            findings = self.read_report(combined)["findings"]
            expected = [hashlib.sha256(
                f"rust.test\x1fsource.rs\x1flet _ID_ = 1;\x1f{ordinal}".encode()
            ).hexdigest()[:16] for ordinal in range(len(records))]
            self.assertEqual([f["fingerprint"] for f in findings], expected)

            # A second merge in the same Python process must observe new bytes.
            source.write_text("let value = 2;\n", encoding="utf-8")
            merge(root, combined, project_dir=root)
            changed = self.read_report(combined)["findings"]
            self.assertTrue(all(a["fingerprint"] != b["fingerprint"]
                                for a, b in zip(findings, changed)))

    def test_source_cache_eviction_and_unreadable_line_fallbacks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-fm-source-") as tmp:
            root = Path(tmp)
            for index in range(10):
                (root / f"source{index}.rs").write_text(f"let value = {index};\n", encoding="utf-8")
            records = [{"rule": "rust.test", "path": f"source{i}.rs", "line": 1}
                       for i in [*range(10), 0]]
            records += [
                {"rule": "rust.test", "path": "source0.rs", "line": 100, "message": "missing line"},
                {"rule": "rust.test", "path": "absent.rs", "line": 1, "message": "missing file"},
                {"rule": "rust.test", "path": "source0.rs", "line": "invalid"},
                {"rule": "rust.test", "path": "source0.rs", "line": -1},
            ]
            (root / "rust.findings.json").write_text(
                "".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8",
            )
            combined = root / "combined.json"
            combined.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            reads = []

            def count_reads(frame, event, arg):
                if event == "call" and frame.f_code is Path.read_text.__code__:
                    path = frame.f_locals.get("self")
                    if isinstance(path, Path) and path.suffix == ".rs":
                        reads.append(path.name)

            previous_profile = sys.getprofile()
            sys.setprofile(count_reads)
            try:
                self.assertEqual(merge(root, combined, project_dir=root), len(records))
            finally:
                sys.setprofile(previous_profile)
            self.assertEqual(reads, [f"source{i}.rs" for i in [*range(10), 0]])
            findings = self.read_report(combined)["findings"]
            self.assertEqual([f["line"] for f in findings[-4:]], [100, 1, 0, -1])
            expected_statements = ["_ID_ _ID_", "_ID_ _ID_", "_ID_._ID_", "_ID_._ID_"]
            for finding, statement, ordinal in zip(findings[-4:], expected_statements, [0, 0, 0, 1]):
                normalized_path = Path(finding["file"]).name
                expected = hashlib.sha256(
                    f"rust.test\x1f{normalized_path}\x1f{statement}\x1f{ordinal}".encode()
                ).hexdigest()[:16]
                self.assertEqual(finding["fingerprint"], expected)

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

            doc = self.read_report(combined)
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
            self.assertNotIn("findings", self.read_report(combined))

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

    def test_swift_project_notes_survive_direct_and_merged_sarif(self) -> None:
        from ubs_core.swift_patterns.foundations import PATTERNS
        from ubs_core.swift_patterns.misc_cats import _packaging
        from ubs_core.swift_scan import ScanContext, _write_record, scan_patterns

        task_pattern = next(pattern for pattern in PATTERNS
                            if pattern.rule_id == "swift.concurrency.task-usages")
        with tempfile.TemporaryDirectory(prefix="ubs-project-notes-") as tmp:
            root = Path(tmp)
            source = root / "sample.swift"
            source.write_text("let value = 1\n", encoding="utf-8")
            ctx = ScanContext(files=[source], project_dir=root)
            sink = root / "swift.findings.json"
            with sink.open("w", encoding="utf-8") as stream:
                scan_patterns([task_pattern], ctx, stream, set())
                for record in _packaging(ctx):
                    _write_record(stream, record, set())
            records = load_sink(sink)
            expected = {
                "swift.concurrency.task-usages": "Task usages",
                "swift.packaging.no-manifest": "Package.swift not found in selected files",
            }
            self.assertEqual({record["rule"]: record["message"] for record in records}, expected)
            self.assertEqual(len(records), 2)
            for record in records:
                self.assertEqual((record["scope"], record["path"], record["line"],
                                  record["severity"], record["count"]),
                                 ("project", "", 0, "info", 0))
                self.assertIs(type(record["count"]), int)

            direct = to_sarif({"language": "swift", "findings": records})
            combined = root / "combined.json"
            totals = {"files": 1, "critical": 0, "warning": 0, "info": 0}
            combined.write_text(json.dumps({
                "scanners": [{"language": "swift", **totals, "status": "ok"}],
                "totals": totals,
            }), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root), 2)
            merged = self.read_report(combined)
            self.assertEqual(merged["totals"], totals)
            for finding in merged["findings"]:
                self.assertEqual((finding["scope"], finding["file"], finding["line"], finding["count"]),
                                 ("project", "", 0, 0))
                self.assertIs(type(finding["count"]), int)
            for sarif in (direct, to_sarif(merged)):
                results = [result for run in sarif["runs"] for result in run["results"]]
                self.assertEqual({result["ruleId"]: result["message"]["text"] for result in results},
                                 expected)
                self.assertEqual(len(results), 2)
                for result in results:
                    self.assertEqual((result["kind"], result["level"]), ("informational", "none"))
                    self.assertEqual(result["properties"]["scope"], "project")
                    self.assertIs(type(result["properties"]["count"]), int)
                    self.assertEqual(result["properties"]["count"], 0)
                    self.assertNotIn("locations", result)

            baseline = root / "baseline.json"

            def check_new_only(label, baseline_records, expected_findings, expected_info):
                baseline.write_text(json.dumps({"findings": baseline_records}), encoding="utf-8")
                expected_totals = {**totals, "info": expected_info}
                for has_scanner in (True, False):
                    with self.subTest(baseline=label, has_scanner=has_scanner):
                        combined.write_text(json.dumps({
                            "scanners": [{"language": "swift", **totals, "status": "ok"}]
                            if has_scanner else [],
                            "totals": totals,
                            "status": "ok",
                        }), encoding="utf-8")
                        self.assertEqual(merge(root, combined, project_dir=root,
                                               baseline_path=baseline, new_only=True),
                                         len(expected_findings))
                        filtered = self.read_report(combined)
                        self.assertEqual(filtered["findings"], expected_findings)
                        self.assertEqual(filtered["totals"], expected_totals)
                        self.assertEqual(filtered["status"], "ok")
                        if has_scanner:
                            scanner = filtered["scanners"][0]
                            self.assertEqual({key: scanner[key] for key in expected_totals},
                                             expected_totals)
                        results = [result for run in to_sarif(filtered)["runs"]
                                   for result in run["results"]]
                        self.assertEqual([result["ruleId"] for result in results],
                                         [finding["rule_id"] for finding in expected_findings])
                        for finding, result in zip(expected_findings, results):
                            if finding.get("scope") == "project":
                                self.assertEqual((result["kind"], result["level"]),
                                                 ("informational", "none"))
                                self.assertEqual((result["properties"]["scope"],
                                                  result["properties"]["count"]), ("project", 0))
                                self.assertNotIn("locations", result)
                            else:
                                self.assertEqual(result["level"], "note")
                                self.assertNotIn("scope", result["properties"])
                                physical = result["locations"][0]["physicalLocation"]
                                self.assertEqual(physical["artifactLocation"]["uri"], str(source))
                                self.assertEqual(physical["region"],
                                                 {"startLine": 1, "startColumn": 1})

            note_findings = merged["findings"]
            nonmatching = [{"fingerprint": "0000000000000000"}]
            self.assertNotIn(nonmatching[0]["fingerprint"],
                             {finding["fingerprint"] for finding in note_findings})
            check_new_only("empty", [], note_findings, 0)
            check_new_only("nonmatching", nonmatching, note_findings, 0)
            check_new_only("one note", note_findings[:1], note_findings[1:], 0)
            check_new_only("both notes", note_findings, [], 0)

            # The same rule with a real Task occurrence remains a located
            # source finding; it must not inherit the zero-count note marker.
            source.write_text("Task { operation() }\n", encoding="utf-8")
            ctx = ScanContext(files=[source], project_dir=root)
            with sink.open("w", encoding="utf-8") as stream:
                scan_patterns([task_pattern], ctx, stream, set())
            located = load_sink(sink)
            self.assertEqual(len(located), 1)
            self.assertEqual((located[0]["path"], located[0]["line"], located[0]["count"]),
                             (str(source), 1, 1))
            self.assertNotIn("scope", located[0])
            result = to_sarif({"language": "swift", "findings": located})["runs"][0]["results"][0]
            self.assertEqual(result["level"], "note")
            self.assertNotIn("kind", result)
            self.assertNotIn("scope", result["properties"])
            physical = result["locations"][0]["physicalLocation"]
            self.assertEqual(physical["artifactLocation"]["uri"], str(source))
            self.assertEqual(physical["region"], {"startLine": 1, "startColumn": 1})

            # A retained source info occurrence still counts when a zero-count
            # project note survives beside it, or the baseline removes that note.
            with sink.open("a", encoding="utf-8") as stream:
                for record in _packaging(ctx):
                    _write_record(stream, record, set())
            totals = {**totals, "info": 1}
            combined.write_text(json.dumps({"scanners": [], "totals": totals}), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root), 2)
            source_findings = self.read_report(combined)["findings"]
            self.assertEqual([finding["rule_id"] for finding in source_findings],
                             ["swift.concurrency.task-usages", "swift.packaging.no-manifest"])
            self.assertNotIn(nonmatching[0]["fingerprint"],
                             {finding["fingerprint"] for finding in source_findings})
            check_new_only("source plus note, empty", [], source_findings, 1)
            check_new_only("source plus note, nonmatching", nonmatching, source_findings, 1)
            check_new_only("old notes, new Task", note_findings, source_findings[:1], 1)
            check_new_only("known Task, new note", source_findings[:1], source_findings[1:], 0)

    def test_real_swift_project_aggregates_preserve_severity_and_new_only_counts(self) -> None:
        from ubs_core.swift_patterns.foundations import PATTERNS, _unawaited_async
        from ubs_core.swift_patterns.misc_cats import _packaging, _storyboards
        from ubs_core.swift_patterns.threading_perf import _filehandle_imbalance, _main_actor_presence
        from ubs_core.swift_scan import ScanContext, _write_record, scan_patterns

        task_pattern = next(pattern for pattern in PATTERNS
                            if pattern.rule_id == "swift.concurrency.task-usages")
        with tempfile.TemporaryDirectory(prefix="ubs-project-aggregates-") as tmp:
            root = Path(tmp)
            first = root / "first.swift"
            first.write_text(
                "import SwiftUI\nfunc first() async {}\nfunc second() async {}\n"
                "let firstHandle = try FileHandle(forReadingFrom: url)\n"
                "let secondHandle = try FileHandle(forReadingFrom: url)\n"
                "Task { operation() }\n", encoding="utf-8",
            )
            second = root / "second.swift"
            second.write_text(
                "import UIKit\nfunc third() async {}\n"
                "let thirdHandle = try FileHandle(forReadingFrom: url)\n"
                "firstHandle.close()\n", encoding="utf-8",
            )
            storyboards = [root / f"screen-{index}.storyboard" for index in range(6)]
            for storyboard in storyboards:
                storyboard.write_text("<document/>\n", encoding="utf-8")
            ctx = ScanContext(files=[first, second, *storyboards], project_dir=root)
            sink = root / "swift.findings.json"
            with sink.open("w", encoding="utf-8") as stream:
                scan_patterns([task_pattern], ctx, stream, set())
                for producer in (_unawaited_async, _filehandle_imbalance,
                                 _main_actor_presence, _storyboards, _packaging):
                    for record in producer(ctx):
                        _write_record(stream, record, set())
            records = load_sink(sink)
            expected = {
                "swift.concurrency.unawaited-async": ("info", 3, "Possible un-awaited async paths"),
                "swift.files.filehandle": ("warning", 2, "FileHandle open without matching close"),
                "swift.threading.main-actor": ("info", 2, "UI frameworks used but no @MainActor annotations found"),
                "swift.uisafety.storyboards": ("info", 6, "Many storyboards - consider modularization"),
            }
            aggregates = [record for record in records if record.get("scope") == "project_aggregate"]
            self.assertEqual(len(records), 6)
            self.assertEqual({record["rule"]: (record["severity"], record["count"], record["message"])
                              for record in aggregates}, expected)
            for record in aggregates:
                self.assertEqual((record["path"], record["line"]), ("", 0))
                self.assertIs(type(record["count"]), int)

            def check_sarif(document, expected_rules):
                results = [result for run in to_sarif(document)["runs"] for result in run["results"]]
                self.assertEqual([result["ruleId"] for result in results], expected_rules)
                for result in results:
                    rule = result["ruleId"]
                    if rule in expected:
                        severity, count, message = expected[rule]
                        self.assertEqual((result["kind"], result["level"]),
                                         ("fail", "warning" if severity == "warning" else "note"))
                        self.assertEqual(result["message"]["text"], message)
                        self.assertEqual((result["properties"]["scope"], result["properties"]["count"]),
                                         ("project_aggregate", count))
                        self.assertIs(type(result["properties"]["count"]), int)
                        self.assertNotIn("locations", result)
                    elif rule == "swift.packaging.no-manifest":
                        self.assertEqual((result["kind"], result["level"]), ("informational", "none"))
                        self.assertEqual((result["properties"]["scope"], result["properties"]["count"]),
                                         ("project", 0))
                        self.assertNotIn("locations", result)
                    else:
                        self.assertEqual(rule, "swift.concurrency.task-usages")
                        self.assertEqual(result["level"], "note")
                        self.assertNotIn("scope", result["properties"])
                        physical = result["locations"][0]["physicalLocation"]
                        self.assertEqual(physical["artifactLocation"]["uri"], str(first))
                        self.assertEqual(physical["region"], {"startLine": 6, "startColumn": 1})

            check_sarif({"language": "swift", "findings": records}, [record["rule"] for record in records])
            totals = {"files": 8, "critical": 0, "warning": 2, "info": 12}
            combined = root / "combined.json"
            combined.write_text(json.dumps({"scanners": [], "totals": totals}), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root), 6)
            merged = self.read_report(combined)
            self.assertEqual(merged["totals"], totals)
            all_findings = merged["findings"]
            baseline = root / "baseline.json"
            cases = [
                ("empty", [], all_findings, 2, 12),
                ("nonmatching", [{"fingerprint": "0000000000000000"}], all_findings, 2, 12),
            ]
            self.assertNotIn("0000000000000000", {finding["fingerprint"] for finding in all_findings})
            for rule, warning, info in (("swift.concurrency.unawaited-async", 2, 9),
                                        ("swift.files.filehandle", 0, 12)):
                known = [finding for finding in all_findings if finding["rule_id"] == rule]
                remaining = [finding for finding in all_findings if finding["rule_id"] != rule]
                cases.append((rule, known, remaining, warning, info))
            cases.append(("all aggregates", [finding for finding in all_findings
                                              if finding.get("scope") == "project_aggregate"],
                          [finding for finding in all_findings
                           if finding.get("scope") != "project_aggregate"], 0, 1))
            cases.append(("all findings", all_findings, [], 0, 0))
            for label, known, remaining, warning, info in cases:
                baseline.write_text(json.dumps({"findings": known}), encoding="utf-8")
                expected_totals = {**totals, "warning": warning, "info": info}
                for has_scanner in (True, False):
                    with self.subTest(baseline=label, has_scanner=has_scanner):
                        combined.write_text(json.dumps({
                            "scanners": [{"language": "swift", **totals}] if has_scanner else [],
                            "totals": totals,
                        }), encoding="utf-8")
                        self.assertEqual(merge(root, combined, project_dir=root,
                                               baseline_path=baseline, new_only=True), len(remaining))
                        filtered = self.read_report(combined)
                        self.assertEqual(filtered["findings"], remaining)
                        self.assertEqual(filtered["totals"], expected_totals)
                        if has_scanner:
                            scanner = filtered["scanners"][0]
                            self.assertEqual({key: scanner[key] for key in expected_totals}, expected_totals)
                        check_sarif(filtered, [finding["rule_id"] for finding in remaining])

    def test_project_note_validation_rejects_lossy_or_source_metadata(self) -> None:
        from ubs_core.swift_scan import _write_record

        valid = {
            "rule": "swift.packaging.no-manifest", "category": 20,
            "path": "", "line": 0, "severity": "info", "count": 0,
            "scope": "project", "message": "Package.swift not found in selected files",
        }
        invalid = [
            (key, value) for key, values in (
                ("path", ("source.swift", ".", " ", None)),
                ("file", ("source.swift",)),
                ("line", (1, -1, "0", "bad", False, 0.0, None)),
                ("severity", ("warning", "critical", "INFO", None)),
                ("count", (1, -1, "0", "bad", False, True, 0.0, None)),
            ) for value in values
        ]
        with tempfile.TemporaryDirectory(prefix="ubs-invalid-project-note-") as tmp:
            root = Path(tmp)
            combined = root / "combined.json"
            original = json.dumps({"scanners": [{"language": "swift"}], "totals": {"info": 0}})
            combined.write_text(original, encoding="utf-8")
            sink = root / "swift.findings.json"
            for key, value in [*invalid, ("count", "missing"), ("line", "missing")]:
                with self.subTest(key=key, value=value):
                    record = dict(valid)
                    if value == "missing":
                        record.pop(key)
                    else:
                        record[key] = value
                    with self.assertRaisesRegex(ValueError, "invalid project note"):
                        to_sarif({"language": "swift", "findings": [record]})
                    sink.write_text(json.dumps(record) + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "invalid project note"):
                        merge(root, combined, project_dir=root)
                    self.assertEqual(combined.read_text(encoding="utf-8"), original)

                    if key in ("line", "count"):
                        # Swift's shared writer must preserve malformed numeric
                        # types until validation, rather than coercing them to 0.
                        stream = io.StringIO()
                        _write_record(stream, record, set())
                        sink.write_text(stream.getvalue(), encoding="utf-8")
                        forwarded = load_sink(sink)
                        self.assertEqual(len(forwarded), 1)
                        with self.assertRaisesRegex(ValueError, "invalid project note"):
                            to_sarif({"language": "swift", "findings": forwarded})

    def test_project_aggregate_contract_rejects_invalid_metadata_and_preserves_levels(self) -> None:
        from ubs_core.swift_scan import _write_record

        # Exercise the converter's three allowed severities, including critical
        # even though the current Swift aggregate producers emit info/warning.
        valid = {
            "rule": "swift.files.filehandle", "category": 8,
            "scope": "project_aggregate", "path": "", "line": 0,
            "severity": "warning", "count": 3, "message": "FileHandle open without matching close",
        }
        with tempfile.TemporaryDirectory(prefix="ubs-aggregate-contract-") as tmp:
            root = Path(tmp)
            sink = root / "swift.findings.json"
            combined = root / "combined.json"
            baseline = root / "baseline.json"
            baseline.write_text("[]", encoding="utf-8")
            for severity, level in (("info", "note"), ("warning", "warning"), ("critical", "error")):
                for suppressed in (False, True):
                    record = {**valid, "severity": severity, "suppressed": suppressed}
                    sink.write_text(json.dumps(record) + "\n", encoding="utf-8")
                    for has_scanner in (True, False):
                        with self.subTest(severity=severity, suppressed=suppressed, has_scanner=has_scanner):
                            original_totals = {"files": 1, "critical": 0, "warning": 0, "info": 0}
                            original_totals[severity] = 3
                            combined.write_text(json.dumps({
                                "scanners": [{"language": "swift", **original_totals}] if has_scanner else [],
                                "totals": original_totals,
                            }), encoding="utf-8")
                            self.assertEqual(merge(root, combined, baseline_path=baseline, new_only=True), 1)
                            merged = self.read_report(combined)
                            expected_totals = {**original_totals, severity: 0 if suppressed else 3}
                            self.assertEqual(merged["totals"], expected_totals)
                            if has_scanner:
                                scanner = merged["scanners"][0]
                                self.assertEqual({key: scanner[key] for key in expected_totals}, expected_totals)
                            for document in ({"language": "swift", "findings": [record]}, merged):
                                result = to_sarif(document)["runs"][0]["results"][0]
                                self.assertEqual((result["kind"], result["level"]), ("fail", level))
                                self.assertEqual((result["properties"]["scope"], result["properties"]["count"]),
                                                 ("project_aggregate", 3))
                                self.assertIs(type(result["properties"]["count"]), int)
                                self.assertEqual(result["properties"]["suppressed"], suppressed)
                                self.assertNotIn("locations", result)

            invalid = [
                (key, value) for key, values in (
                    ("path", ("source.swift", ".", " ", None)),
                    ("file", ("source.swift", ".", " ", None)),
                    ("line", (1, -1, "0", False, 0.0, None)),
                    ("severity", ("none", "INFO", "error", None)),
                    ("count", (0, -1, "3", "bad", False, True, 3.0, None)),
                ) for value in values
            ]
            original = json.dumps({"scanners": [{"language": "swift"}], "totals": {"warning": 3}})
            for key, value in [*invalid, ("count", "missing"), ("line", "missing")]:
                with self.subTest(key=key, value=value):
                    record = dict(valid)
                    if value == "missing":
                        record.pop(key)
                    else:
                        record[key] = value
                    with self.assertRaisesRegex(ValueError, "invalid project aggregate"):
                        to_sarif({"language": "swift", "findings": [record]})
                    sink.write_text(json.dumps(record) + "\n", encoding="utf-8")
                    for new_only in (False, True):
                        combined.write_text(original, encoding="utf-8")
                        with self.assertRaisesRegex(ValueError, "invalid project aggregate"):
                            merge(root, combined, baseline_path=baseline, new_only=new_only)
                        self.assertEqual(combined.read_text(encoding="utf-8"), original)
                    if key in ("line", "count"):
                        stream = io.StringIO()
                        _write_record(stream, record, set())
                        sink.write_text(stream.getvalue(), encoding="utf-8")
                        forwarded = load_sink(sink)
                        self.assertEqual(len(forwarded), 1)
                        with self.assertRaisesRegex(ValueError, "invalid project aggregate"):
                            to_sarif({"language": "swift", "findings": forwarded})

    def test_ast_reports_preserve_counter_totals_locations_and_baseline_filtering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-ast-report-") as tmp:
            root = Path(tmp)
            source = root / "sample.rb"
            source.write_text("value == nil\n", encoding="utf-8")
            ast_finding = {
                "rule": "rb.nil-eq.eq", "path": str(source), "line": 1, "col": 1,
                "severity": "warning", "message": "Prefer nil?", "suppressed": False,
            }
            summary = {
                "language": "ruby", "files": 1, "critical": 0, "warning": 0, "info": 0,
                "extras": {"ast_findings": [ast_finding]},
            }
            combined = root / "combined.json"
            original = {"scanners": [summary], "totals": {"files": 1, "critical": 0, "warning": 0, "info": 0}}
            combined.write_text(json.dumps(original), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root), 0)
            doc = self.read_report(combined)
            self.assertEqual(doc["findings"], [])
            self.assertEqual(doc["totals"], original["totals"])
            self.assertEqual(doc["scanners"][0]["warning"], 0)
            ast_records = doc["scanners"][0]["extras"]["ast_findings"]
            self.assertEqual(len(ast_records), 1)
            self.assertTrue(ast_records[0]["fingerprint"])
            sarif = to_sarif(doc, git_remote="https://example.invalid/repo", git_commit="revision")
            runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
            self.assertEqual(runs["ubs-ruby-heuristics"]["results"], [])
            result = runs["ubs-ruby-ast"]["results"][0]
            self.assertEqual(result["ruleId"], "rb.nil-eq.eq")
            self.assertEqual(result["level"], "warning")
            location = result["locations"][0]["physicalLocation"]
            self.assertEqual(location["artifactLocation"]["uri"], str(source))
            self.assertEqual(location["region"], {"startLine": 1, "startColumn": 1})
            self.assertEqual(runs["ubs-ruby-ast"]["versionControlProvenance"][0]["revisionId"], "revision")

            baseline = root / "baseline.json"
            baseline.write_text(json.dumps(doc), encoding="utf-8")
            combined.write_text(json.dumps(original), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root, baseline_path=baseline, new_only=True), 0)
            filtered = self.read_report(combined)
            self.assertEqual(filtered["scanners"][0]["extras"]["ast_findings"], [])
            self.assertEqual(sum(len(run["results"]) for run in to_sarif(filtered)["runs"]), 0)
            original["scanners"][0]["extras"]["ast_findings"].append({**ast_finding, "rule": "rb.new-rule"})
            combined.write_text(json.dumps(original), encoding="utf-8")
            self.assertEqual(merge(root, combined, project_dir=root, baseline_path=baseline, new_only=True), 0)
            added = self.read_report(combined)
            self.assertEqual([r["rule_id"] for r in added["scanners"][0]["extras"]["ast_findings"]], ["rb.new-rule"])
            self.assertEqual(added["totals"]["warning"], 0)

    def test_direct_ast_report_and_malformed_evidence(self) -> None:
        record = {"rule": "rb.rule", "path": "sample.rb", "line": 2, "severity": "critical", "message": "hazard"}
        direct = {"language": "ruby", "extras": {"ast_findings": [record]}}
        runs = to_sarif(direct)["runs"]
        self.assertEqual([run["tool"]["driver"]["name"] for run in runs], ["ubs-ruby-heuristics", "ubs-ruby-ast"])
        self.assertEqual(runs[1]["results"][0]["level"], "error")
        for invalid in ({}, [None], "findings"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "ast_findings"):
                to_sarif({"language": "ruby", "extras": {"ast_findings": invalid}})

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
            base_doc = self.read_report(combined)
            base_file = tmp_dir / "baseline.json"
            base_file.write_text(json.dumps(base_doc), encoding="utf-8")

            # Second merge with new_only=True and same finding: should filter out
            combined2 = tmp_dir / "combined2.json"
            combined2.write_text(json.dumps(SUMMARY_DOC), encoding="utf-8")
            count = merge(tmp_dir, combined2, baseline_path=base_file, new_only=True)
            self.assertEqual(count, 0)
            doc2 = self.read_report(combined2)
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
            doc3 = self.read_report(combined3)
            self.assertEqual(len(doc3["findings"]), 1)
            self.assertEqual(doc3["findings"][0]["rule_id"], "python.security.eval")
            self.assertEqual(doc3["totals"]["critical"], 1)


if __name__ == "__main__":
    unittest.main()
