"""Swift/Elixir driver completion, failure isolation, and evidence contracts.

Faults are injected at the analyzer/process boundary. Source scanning, report
rendering, caches, and the public module entrypoints execute their real code.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "modules/helpers"
if str(HELPERS) not in sys.path:
    sys.path.insert(0, str(HELPERS))

from ubs_core import analyzers  # noqa: F401
from ubs_core.registry import Analyzer


class NativeDriverIntegrityTests(unittest.TestCase):
    LANGUAGES = (("swift", ".swift", 6), ("elixir", ".ex", 4))

    def setUp(self):
        artifacts = ROOT / "test-suite/artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="native-driver-integrity-", dir=artifacts))
        self.env = {**os.environ, "PYTHONPATH": str(HELPERS), "PYTHONDONTWRITEBYTECODE": "1",
                    "UBS_NO_PREFILTER": "1", "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1",
                    "UBS_TEST_FORCE_NO_AST_GREP": "1", "NO_COLOR": "1"}

    def parse_json(self, text):
        try:
            return json.loads(text)
        except ValueError as exc:
            self.fail(f"Invalid JSON: {exc}\n{text}")

    def sources(self, language, suffix):
        root = self.root / language
        root.mkdir(exist_ok=True)
        paths = [root / (name + suffix) for name in ("first", "broken", "later")]
        for path in paths:
            path.write_text("let value = 42\n" if language == "swift" else "value = 42\n", encoding="utf-8")
        return paths

    def finding(self, language, path):
        rule = ("swift.taint.request_open_redirect" if language == "swift"
                else "elixir.taint.open_redirect")
        trace = [{"path": str(path), "line": 1, "col": 1, "kind": "source", "label": "request"},
                 {"path": str(path), "line": 2, "col": 3, "kind": "sink", "label": "redirect"}]
        return {"rule": rule, "path": str(path), "line": 2, "col": 3,
                "severity": "critical", "message": "Retained request finding",
                "extras": {"taint_path": trace, "source_count": 1}}

    def driver_run(self, language, files, sink, skip, **kwargs):
        module = importlib.import_module("ubs_core." + language + "_scan")
        inputs = (module.ScanContext(files=list(files), project_dir=self.root)
                  if language == "swift" else files)
        return module.run_analyzers(inputs, sink, skip, **kwargs)

    def test_each_file_failure_preserves_completed_and_later_findings(self):
        for language, suffix, _category in self.LANGUAGES:
            with self.subTest(language=language):
                paths = self.sources(language, suffix)
                def scan(ctx):
                    for path in ctx.files:
                        yield self.finding(language, path)
                        if path.stem == "broken":
                            raise ValueError("selected syntax is incomplete")
                analyzer = Analyzer("taint", language, "injected_request_flow", scan)
                sink, errors = io.StringIO(), []
                with patch("ubs_core.registry.analyzers_for_lang", return_value=[analyzer]):
                    self.driver_run(language, paths, sink, set(), errors=errors)
                records = [self.parse_json(line) for line in sink.getvalue().splitlines()]
                self.assertEqual([r["path"] for r in records], [str(path) for path in paths])
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(str(paths[1]), errors[0])
                self.assertIn("selected syntax is incomplete", errors[0])
                self.assertEqual([r["extras"] for r in records],
                                 [self.finding(language, p)["extras"] for p in paths])

    def test_disabled_security_category_never_invokes_taint(self):
        for language, suffix, category in self.LANGUAGES:
            with self.subTest(language=language):
                paths = self.sources(language, suffix)
                def must_not_run(ctx):
                    self.fail("disabled security analyzer was invoked")
                    yield {}
                analyzer = Analyzer("taint", language, "injected_request_flow", must_not_run)
                sink = io.StringIO()
                with patch("ubs_core.registry.analyzers_for_lang", return_value=[analyzer]):
                    self.driver_run(language, paths, sink, {category})
                self.assertEqual(sink.getvalue(), "")

    def test_without_error_accumulator_failures_propagate(self):
        for language, suffix, _category in self.LANGUAGES:
            with self.subTest(language=language):
                paths = self.sources(language, suffix)
                def scan(ctx):
                    raise ValueError("incomplete flow")
                    yield {}
                analyzer = Analyzer("taint", language, "injected_request_flow", scan)
                with patch("ubs_core.registry.analyzers_for_lang", return_value=[analyzer]):
                    with self.assertRaisesRegex(ValueError, "incomplete flow"):
                        self.driver_run(language, paths, io.StringIO(), set())

    def test_partial_scan_is_not_cached_and_can_recover(self):
        for language, suffix, category in self.LANGUAGES:
            with self.subTest(language=language):
                paths = self.sources(language, suffix)
                root = paths[0].parent
                files = root / "files"
                files.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
                sink, report, text = root / "sink", root / "report.json", root / "report.txt"
                calls = []
                broken = True
                def scan(ctx):
                    for path in ctx.files:
                        calls.append(path)
                        yield self.finding(language, path)
                        if broken and path.stem == "broken":
                            raise ValueError("incomplete selected syntax")
                analyzer = Analyzer("taint", language, "injected_request_flow", scan)
                module = importlib.import_module("ubs_core." + language + "_scan")
                args = ["--files-from", str(files), "--sink", str(sink), "--json-out", str(report),
                        "--text-out", str(text), "--project-dir", str(root), "--skip",
                        ",".join(str(n) for n in range(1, 24) if n != category)]
                env = {**self.env, "UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(root / "cache")}
                with patch.dict(os.environ, env), patch("ubs_core.registry.analyzers_for_lang", return_value=[analyzer]):
                    for broken in (True, True, False, False):
                        with contextlib.redirect_stderr(io.StringIO()):
                            code = module.main(args)
                        doc = self.parse_json(report.read_text())
                        self.assertEqual(code, 2 if broken else 1, doc)
                        self.assertEqual(doc["status"], "partial" if broken else "ok", doc)
                        self.assertEqual(doc["critical"], 3, doc)
                        self.assertEqual(len(doc["findings"]), 3, doc)
                        if broken:
                            self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
                            self.assertIn("Partial:", text.read_text())
                            self.assertNotIn("✓ OK", text.read_text())
                            self.assertEqual(doc["extras"]["profile"]["cache_hits"], 0)
                self.assertEqual(doc["extras"]["profile"]["cache_hits"], 3)
                self.assertEqual(len(calls), 9, calls)

    def test_receipt_written_after_successful_reports(self):
        for language, suffix, category in self.LANGUAGES:
            with self.subTest(language=language):
                source = self.sources(language, suffix)[0]
                root = source.parent
                files, sink, report, receipt = (root / name for name in ("files", "sink", "report", "receipt"))
                files.write_bytes(os.fsencode(source) + b"\0")
                module = importlib.import_module("ubs_core." + language + "_scan")
                args = ["--files-from", str(files), "--sink", str(sink), "--json-out", str(report),
                        "--completion-out", str(receipt), "--project-dir", str(root)]
                with patch.dict(os.environ, self.env), contextlib.redirect_stderr(io.StringIO()):
                    result = module.main(args)
                self.assertEqual(result, 0)
                doc, finished = self.parse_json(report.read_text()), self.parse_json(receipt.read_text())
                self.assertEqual(finished["language"], language)
                self.assertEqual(finished["status"], "ok")
                for key in ("files", "critical", "warning", "info"):
                    self.assertEqual(finished[key], doc[key])

    def test_failed_report_write_does_not_publish_completion(self):
        for language, suffix, _category in self.LANGUAGES:
            with self.subTest(language=language):
                source = self.sources(language, suffix)[0]
                root = source.parent
                files, sink, receipt = (root / name for name in ("files", "sink", "receipt"))
                files.write_bytes(os.fsencode(source) + b"\0")
                module = importlib.import_module("ubs_core." + language + "_scan")
                args = ["--files-from", str(files), "--sink", str(sink), "--json-out", str(root),
                        "--completion-out", str(receipt), "--project-dir", str(root)]
                with patch.dict(os.environ, self.env), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(IsADirectoryError):
                        module.main(args)
                self.assertFalse(receipt.exists())

    def process_boundary(self):
        binary = self.root / "python3"
        binary.write_text(
            f"#!{sys.executable}\n"
            "import importlib, json, os, sys\nfrom pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "if len(args) > 1 and args[0] == '-m' and args[1] in ('ubs_core.swift_scan', 'ubs_core.elixir_scan'):\n"
            "    mode = os.environ.get('UBS_DRIVER_FAULT', '')\n"
            "    if mode.startswith('exit:'):\n        sys.exit(int(mode.split(':')[1]))\n"
            "    result = importlib.import_module(args[1]).main(args[2:])\n"
            "    if mode and '--completion-out' in args:\n"
            "        receipt = Path(args[args.index('--completion-out') + 1])\n"
            "        if mode == 'malformed':\n            receipt.write_text('{')\n"
            "        elif mode == 'missing':\n            receipt.write_text('')\n"
            "        else:\n"
            "            try:\n                doc = json.loads(receipt.read_text())\n"
            "            except ValueError as exc:\n                raise RuntimeError('Driver wrote invalid receipt JSON') from exc\n"
            "            if mode == 'wrong-language':\n                doc['language'] = 'ruby'\n"
            "            elif mode == 'wrong-files':\n                doc['files'] += 1\n"
            "            elif mode == 'wrong-counts':\n                doc['critical'] += 1\n"
            "            elif mode == 'boolean-count':\n                doc['critical'] = False\n"
            "            receipt.write_text(json.dumps(doc))\n"
            "    sys.exit(result)\n"
            + "os.execv(" + repr(sys.executable) + ", [" + repr(sys.executable) + "] + args)\n",
            encoding="utf-8")
        binary.chmod(0o755)
        return binary

    def module(self, language, target, fmt, fault="", *, meta=False):
        command = ([str(ROOT / "ubs"), str(target), "--only=" + language, "--ci", "--format=" + fmt]
                   if meta else [str(ROOT / "modules" / ("ubs-" + language + ".sh")),
                                 str(target), "--ci", "--format=" + fmt])
        env = {**self.env, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
               "UBS_DRIVER_FAULT": fault, "UBS_CACHE_DIR": str(self.root / "cache")}
        started = time.monotonic()
        result = subprocess.run(command, cwd=self.root, env=env, text=True, capture_output=True, timeout=90)
        name = ("meta-" if meta else "") + language + "-" + fmt + "-" + fault.replace(":", "-")
        (self.root / (name + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
        (self.root / (name + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
        (self.root / (name + ".identity.json")).write_text(json.dumps({
            "command": command, "python": sys.version, "elapsed": time.monotonic() - started,
            "exit": result.returncode, "source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "module_sha256": hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        return result

    def assert_partial(self, result, fmt):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        if fmt == "json":
            doc = self.parse_json(result.stdout)
            self.assertEqual(doc["status"], "partial", doc)
            self.assertEqual(doc["module_error"], "ANALYZER_ERROR", doc)
        elif fmt == "sarif":
            doc = self.parse_json(result.stdout)
            self.assertTrue(any(inv.get("executionSuccessful") is False
                                for run in doc["runs"] for inv in run.get("invocations", [])), doc)
        else:
            self.assertIn("Partial: [ANALYZER_ERROR]", result.stdout)
            self.assertRegex(result.stdout, r"(?m)^\s*UBS module:.*\(contract v2\)")
            self.assertNotIn("SCAN COMPLETE", result.stdout)
            self.assertNotIn("✓ OK", result.stdout)

    def test_missing_process_completion_never_means_success(self):
        self.process_boundary()
        for language, suffix, _category in self.LANGUAGES:
            source = self.sources(language, suffix)[0]
            for code in (0, 1, 70):
                for fmt in ("json", "sarif", "text"):
                    with self.subTest(language=language, code=code, format=fmt):
                        self.assert_partial(self.module(language, source, fmt, "exit:" + str(code)), fmt)

    def test_invalid_receipts_cannot_certify_completed_scans(self):
        self.process_boundary()
        for language, suffix, _category in self.LANGUAGES:
            source = self.sources(language, suffix)[0]
            for fault in ("missing", "malformed", "wrong-language", "wrong-files", "wrong-counts", "boolean-count"):
                with self.subTest(language=language, fault=fault):
                    self.assert_partial(self.module(language, source, "json", fault), "json")

    def request_source(self, language, source, unsafe):
        if language == "swift":
            value = 'req.query["returnUrl"] ?? "/"' if unsafe else '"/safe"'
            text = ("func handler(req: Request) -> Response {\n"
                    f"  let target = {value}\n"
                    "  return req.redirect(to: target)\n}\n")
            rule = "swift.taint.request_open_redirect"
        else:
            value = 'params["url"]' if unsafe else '"/safe"'
            text = ("def handler(conn, params) do\n"
                    f"  target = {value}\n"
                    "  redirect(conn, external: target)\nend\n")
            rule = "elixir.taint.open_redirect"
        source.write_text(text, encoding="utf-8")
        return rule

    def test_complete_clean_and_buggy_modules_keep_normal_status(self):
        self.process_boundary()
        for language, suffix, _category in self.LANGUAGES:
            source = self.sources(language, suffix)[0]
            for unsafe in (False, True):
                rule = self.request_source(language, source, unsafe)
                for fmt in ("json", "sarif", "text"):
                    with self.subTest(language=language, unsafe=unsafe, format=fmt):
                        result = self.module(language, source, fmt)
                        self.assertEqual(result.returncode, int(unsafe), result.stdout + result.stderr)
                        if fmt == "json":
                            report = self.parse_json(result.stdout)
                            self.assertEqual(report["status"], "ok", report)
                            self.assertEqual(report["critical"], int(unsafe), report)
                            hits = [r for r in report["findings"] if r["rule"] == rule]
                            self.assertEqual([r["line"] for r in hits], [3] if unsafe else [])
                        elif fmt == "sarif":
                            runs = self.parse_json(result.stdout)["runs"]
                            hits = [r for run in runs for r in run.get("results", []) if r["ruleId"] == rule]
                            self.assertEqual([r["locations"][0]["physicalLocation"]["region"]["startLine"]
                                              for r in hits], [3] if unsafe else [])
                            self.assertFalse(any(inv.get("executionSuccessful") is False
                                                 for run in runs for inv in run.get("invocations", [])))
                        else:
                            self.assertNotIn("Partial:", result.stdout)
                            self.assertIn("Critical issues:", result.stdout)

    def test_invalid_receipt_keeps_real_findings_in_every_format(self):
        self.process_boundary()
        for language, suffix, _category in self.LANGUAGES:
            source = self.sources(language, suffix)[0]
            rule = self.request_source(language, source, True)
            for fmt in ("json", "sarif", "text"):
                with self.subTest(language=language, format=fmt):
                    result = self.module(language, source, fmt, "missing")
                    self.assert_partial(result, fmt)
                    if fmt == "json":
                        report = self.parse_json(result.stdout)
                        self.assertEqual(report["critical"], 1, report)
                        self.assertEqual([r["line"] for r in report["findings"] if r["rule"] == rule], [3])
                    elif fmt == "sarif":
                        hits = [r for run in self.parse_json(result.stdout)["runs"] for r in run.get("results", [])
                                if r["ruleId"] == rule]
                        self.assertEqual([r["locations"][0]["physicalLocation"]["region"]["startLine"]
                                          for r in hits], [3])
                    else:
                        self.assertIn("Unvalidated redirect", result.stdout)

    def test_missing_completion_reaches_every_meta_renderer(self):
        self.process_boundary()
        for language, suffix, _category in self.LANGUAGES:
            source = self.sources(language, suffix)[0]
            for fmt in ("json", "sarif", "text"):
                with self.subTest(language=language, format=fmt):
                    result = self.module(language, source, fmt, "exit:1", meta=True)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertNotIn("MODULE_INVALID_TEXT", result.stdout + result.stderr)
                    if fmt == "json":
                        report = self.parse_json(result.stdout)
                        self.assertEqual(report["status"], "partial", report)
                        self.assertTrue(any(row.get("language") == language
                                            and row.get("module_error") == "ANALYZER_ERROR"
                                            for row in report["failed_modules"]), report)
                    elif fmt == "sarif":
                        runs = self.parse_json(result.stdout)["runs"]
                        self.assertTrue(any(inv.get("executionSuccessful") is False
                                            for run in runs for inv in run.get("invocations", [])))
                    else:
                        self.assertIn("Partial: [ANALYZER_ERROR]", result.stdout)
                        self.assertNotIn("SCAN COMPLETE", result.stdout)


if __name__ == "__main__":
    unittest.main()
