#!/usr/bin/env python3
"""Python pipeline suppression, cache and public CLI regressions for GH #159."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core import py_scan  # noqa: E402
from ubs_core.cache import ScanCache  # noqa: E402
from ubs_core.registry import Analyzer  # noqa: E402
from ubs_core.suppression import SourceSuppressions  # noqa: E402

LIFECYCLE = "python.lifecycle.file_handle"
GUARDS = "python.guards.deep_attr_chain"
NARROWING = "python.narrowing.partial_none_guard"
REPRO = (
    'def marked(path):\n'
    '    handle = open(path, encoding="utf-8")  # ubs:ignore -- caller closes it\n'
    '    return handle\n'
    '\n'
    '\n'
    'def unmarked(path):\n'
    '    handle = open(path, encoding="utf-8")\n'
    '    return handle.read()\n'
)


class PythonSourceSuppressionTests(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="python-suppression-", dir=artifacts)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "handles.py"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("UBS_")}
        self.env.update({
            "PYTHONPATH": str(HELPERS_DIR),
            "PYTHONDONTWRITEBYTECODE": "1",
            "UBS_NO_AUTO_UPDATE": "1",
            "UBS_CACHE_DIR": str(self.root / "cache"),
            "UBS_CACHE_FILE": str(self.root / "cache-stats.json"),
            "UBS_PREFILTER_FILE": str(self.root / "prefilter.json"),
            "ENABLE_UV_TOOLS": "0",
        })

    def decode_json(self, payload: str, context: str):
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            self.fail(f"{context}: invalid scanner JSON: {exc}\n{payload[:1000]}")

    def scan(self, *, no_cache: bool = False, enable_new: bool = False):
        paths = self.root / "files.txt"
        paths.write_bytes(os.fsencode(self.source) + b"\0")
        sink = self.root / "findings.ndjson"
        summary = self.root / "summary.json"
        report = self.root / "report.txt"
        args = ["--files-from", str(paths), "--sink", str(sink),
                "--json-out", str(summary), "--text-out", str(report),
                "--project-dir", str(self.root), "--fail-on-warning"]
        if enable_new:
            args.append("--enable-new-analyzers")
        env = dict(self.env)
        if no_cache:
            env["UBS_NO_CACHE"] = "1"
        with patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(io.StringIO()):
            code = py_scan.main(args)
        records = [self.decode_json(line, str(sink)) for line in sink.read_text().splitlines() if line.strip()]
        doc = self.decode_json(summary.read_text(), str(summary))
        self.assertEqual(doc["status"], "ok", doc)
        counts = Counter(record["severity"] for record in records)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], counts[severity], (doc, records))
        self.assertTrue(all(not record.get("suppressed") for record in records), records)
        self.assertTrue(all("_ubs_python_pattern" not in record for record in records), records)
        return code, records, doc, report.read_text()

    @staticmethod
    def sites(records, rule):
        return sorted(record["line"] for record in records if record["rule"] == rule)

    def assert_cache_contents(self, rule, expected):
        entries = list((self.root / "cache").glob("*/files/**/*.json"))
        self.assertTrue(entries, "the test must inspect a populated real cache")
        records = [record for entry in entries
                   for record in self.decode_json(entry.read_text(), str(entry)).get("findings", [])]
        self.assertEqual(self.sites(records, rule), expected, records)

    def test_all_registry_families_share_marker_semantics_and_cache_boundaries(self) -> None:
        bodies = {
            LIFECYCLE: ([], '    handle = open(value, encoding="utf-8")', ['    return handle']),
            GUARDS: ([], '    return value.a.b.c', []),
            NARROWING: (['    if value is None:', '        log.warning("missing")'],
                        '    return value.name', []),
        }
        for rule, (prefix, finding, suffix) in bodies.items():
            # One file per rule: bare and matching scopes suppress both inline
            # and preceding markers; unrelated scopes and literal text do not.
            lines = []
            expected = []
            cases = (
                ("inline_bare", "# ubs:ignore -- reviewed", False, True),
                ("inline_scoped", f"# ubs:ignore[{rule}] -- reviewed", False, True),
                ("preceding_bare", "# ubs:ignore", True, True),
                ("preceding_scoped", f"# ubs:ignore[{rule}]", True, True),
                ("unrelated_inline", "# ubs:ignore[python.unrelated.rule]", False, False),
                ("unrelated_preceding", "# ubs:ignore[python.unrelated.rule]", True, False),
                ("literal_inline", '; note = "# ubs:ignore"', False, False),
                ("literal_preceding", 'note = "# ubs:ignore"', True, False),
                ("unmarked", "", False, False),
            )
            for name, marker, preceding, suppressed in cases:
                lines.extend([f"def {name}(value):", *prefix])
                if preceding:
                    lines.append("    " + marker)
                lines.append(finding + ("  " + marker if marker and not preceding else ""))
                if not suppressed:
                    expected.append(len(lines))
                lines.extend([*suffix, "", ""])
            self.source = self.root / (rule.split(".")[1] + ".py")
            self.source.write_text("\n".join(lines), encoding="utf-8")
            for mode in ("cold", "warm", "disabled"):
                with self.subTest(rule=rule, cache=mode):
                    result = self.scan(no_cache=mode == "disabled", enable_new=True)
                    self.assertEqual(self.sites(result[1], rule), expected, result[1])
                    profile = result[2]["extras"]["profile"]
                    self.assertEqual(profile["cache_hits"], int(mode == "warm"), profile)
                    self.assertEqual(profile["cache_misses"], int(mode != "warm"), profile)
                    stable = (result[0], result[1], result[2]["findings"])
                    if mode == "cold":
                        cold = stable
                        self.assert_cache_contents(rule, expected)
                    else:
                        self.assertEqual(stable, cold)

    def test_reported_lifecycle_counts_text_and_exit_code(self) -> None:
        self.source.write_text(REPRO, encoding="utf-8")
        for mode in ("cold", "warm", "disabled"):
            with self.subTest(cache=mode):
                code, records, doc, text = self.scan(no_cache=mode == "disabled")
                self.assertEqual(code, 1)
                self.assertEqual(self.sites(records, LIFECYCLE), [7])
                self.assertEqual(doc["critical"], 1)
                bucket = [entry for entry in doc["findings"] if entry["rule"] == LIFECYCLE]
                self.assertEqual(len(bucket), 1)
                self.assertEqual(bucket[0]["count"], 1)
                self.assertEqual([sample["line"] for sample in bucket[0]["samples"]], [7])
                self.assertIn("(1 found) — " + LIFECYCLE, text)
                self.assertIn("Critical issues: 1", text)
                self.assertNotIn(f"{self.source}:2  ", text)

    def test_marker_edits_invalidate_cache_and_all_marked_scan_exits_zero(self) -> None:
        for source, expected in ((REPRO, [7]),
                                 (REPRO.replace('    handle = open(path, encoding="utf-8")\n',
                                                '    handle = open(path, encoding="utf-8")  # ubs:ignore\n'), []),
                                 (REPRO.replace('  # ubs:ignore -- caller closes it', ''), [2, 7])):
            self.source.write_text(source, encoding="utf-8")
            cold = self.scan()
            self.assertEqual(cold[2]["extras"]["profile"]["cache_misses"], 1)
            warm = self.scan()
            self.assertEqual(warm[2]["extras"]["profile"]["cache_hits"], 1)
            for result in (cold, warm, self.scan(no_cache=True)):
                self.assertEqual(self.sites(result[1], LIFECYCLE), expected)
                self.assertEqual(result[2]["critical"], len(expected))
                self.assertEqual(result[0], int(bool(expected)))

    def test_narrowing_remains_opt_in(self) -> None:
        self.source.write_text('def f(value):\n    if value is None:\n        log.warning("missing")\n'
                               '    return value.name\n', encoding="utf-8")
        self.assertEqual(self.sites(self.scan()[1], NARROWING), [])
        self.assertEqual(self.sites(self.scan(enable_new=True)[1], NARROWING), [4])

    def test_multiline_lifecycle_markers_follow_the_logical_statement(self) -> None:
        for marker in ("# ubs:ignore", f"# ubs:ignore[{LIFECYCLE}]"):
            for position in ("preceding", "argument", "closing"):
                with self.subTest(marker=marker, position=position):
                    lines = ["def marked(path):"]
                    if position == "preceding":
                        lines.append("    " + marker)
                    lines.extend(["    handle = open(", '        path, encoding="utf-8"' +
                                  ("  " + marker if position == "argument" else ""),
                                  "    )" + ("  " + marker if position == "closing" else ""),
                                  "    return handle", "", "def unmarked(path):",
                                  '    handle = open(path, encoding="utf-8")',
                                  "    return handle.read()"])
                    self.source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
                        self.assertEqual(self.sites(result[1], LIFECYCLE), [len(lines) - 1])
                        self.assertEqual(result[2]["critical"], 1)

    def test_future_analyzers_and_project_records_use_same_pipeline(self) -> None:
        self.source.write_text("x = 1  # ubs:ignore\ny = 2\n", encoding="utf-8")
        calls = Counter()

        def analyzer(name):
            def run(ctx):
                calls[name] += 1
                for line in (0, 1, 2):
                    yield {"rule": f"python.future.{name}", "path": str(ctx.files[0]),
                           "line": line, "severity": "info", "message": "future finding"}
            return Analyzer("taint" if name == "taint_py" else "guards", "python", name, run)

        with patch("ubs_core.registry.analyzers_for_lang",
                   return_value=[analyzer("future_py"), analyzer("taint_py")]):
            cold = self.scan()
            self.assert_cache_contents("python.future.future_py", [0, 2])
            self.assert_cache_contents("python.future.taint_py", [])
            warm = self.scan()
            self.assertEqual(calls, {"future_py": 1, "taint_py": 2})
            for result in (cold, warm, self.scan(no_cache=True)):
                self.assertEqual(self.sites(result[1], "python.future.future_py"), [0, 2])
                self.assertEqual(self.sites(result[1], "python.future.taint_py"), [0, 2])

    def test_cached_records_are_rechecked_before_sink_output(self) -> None:
        self.source.write_text(REPRO, encoding="utf-8")
        # Simulate a reusable entry from a producer that did not filter. This
        # isolates the output boundary from the independently tested writer.
        records = [{"rule": LIFECYCLE, "path": str(self.source), "line": line,
                    "col": 1, "category_id": "python.resource-lifecycle", "severity": "critical",
                    "message": "unreleased file", "suppressed": False} for line in (2, 7)]
        with patch.object(ScanCache, "partition_files", return_value=({self.source: records}, [])):
            result = self.scan()
        self.assertEqual(self.sites(result[1], LIFECYCLE), [7])
        self.assertEqual(result[2]["critical"], 1)

    def test_locationless_and_unreadable_source_findings_are_preserved(self) -> None:
        self.source.write_text("# ubs:ignore\nx = 1\n", encoding="utf-8")
        records = [{"rule": LIFECYCLE},
                   {"rule": LIFECYCLE, "path": str(self.source), "line": 0},
                   {"rule": LIFECYCLE, "path": "", "line": 2},
                   {"rule": LIFECYCLE, "path": str(self.root / "missing.py"), "line": 2}]
        self.assertEqual(SourceSuppressions("python").filter(records), records)

    def test_suppression_precedes_project_pattern_thresholds(self) -> None:
        rule = "py.numeric.marker-threshold"
        self.source.write_text(f"# ubs:ignore[{rule}]\ntouch()\ntouch()\n", encoding="utf-8")
        pattern = py_scan.Pattern(2, rule, "threshold probe", re.compile(r"touch\("),
                                  ((1, "warning"), (0, "info")), gate_regex=re.compile(r"touch\("))
        with patch.object(py_scan, "load_patterns", return_value=[pattern]):
            for mode in ("cold", "warm", "disabled"):
                with self.subTest(cache=mode):
                    code, records, doc, _ = self.scan(no_cache=mode == "disabled")
                    self.assertEqual(self.sites(records, rule), [3])
                    self.assertEqual([record["severity"] for record in records], ["info"])
                    self.assertEqual(doc["warning"], 0)
                    self.assertEqual(code, 0)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "public UBS requires jq and ripgrep")
    def test_public_ci_json_text_and_sarif_agree_with_lifecycle_sink(self) -> None:
        for only_marked in (False, True):
            self.source.write_text(REPRO.split('\n\n')[0] + '\n' if only_marked else REPRO,
                                   encoding="utf-8")
            for output_format in ("json", "text", "sarif"):
                with self.subTest(only_marked=only_marked, format=output_format):
                    command = [str(REPO_ROOT / "ubs"), "--ci", "--no-cache", "--only=python",
                               f"--format={output_format}", str(self.source)]
                    proc = subprocess.run(command, cwd=self.root, env=self.env, text=True,
                                          capture_output=True, timeout=180)
                    self.assertEqual(proc.returncode, int(not only_marked), proc.stdout + proc.stderr)
                    expected = int(not only_marked)
                    if output_format == "json":
                        doc = self.decode_json(proc.stdout, "public JSON CLI")
                        self.assertEqual(doc["status"], "ok", doc)
                        self.assertEqual(doc["failed_modules"], [], doc)
                        self.assertEqual(doc["totals"]["critical"], expected, doc)
                        findings = [record for record in doc.get("findings", [])
                                    if record["rule_id"] == LIFECYCLE]
                        self.assertEqual([record["line"] for record in findings], [] if only_marked else [7])
                        self.assertTrue(all(record["suppressed"] is False for record in findings))
                    elif output_format == "sarif":
                        doc = self.decode_json(proc.stdout, "public SARIF CLI")
                        findings = [record for run in doc["runs"] for record in run["results"]
                                    if record["ruleId"] == LIFECYCLE]
                        self.assertEqual([record["locations"][0]["physicalLocation"]["region"]["startLine"]
                                          for record in findings], [] if only_marked else [7])
                        self.assertTrue(all(record["level"] == "error" for record in findings))
                    else:
                        self.assertRegex(proc.stdout, rf"Critical issues:\s+{expected}\b")
                        if not only_marked:
                            self.assertIn("(1 found) — " + LIFECYCLE, proc.stdout)


if __name__ == "__main__":
    unittest.main()
