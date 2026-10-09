"""Python stage failures must never become successful, reusable scan results."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "modules/helpers"
sys.path.insert(0, str(HELPERS))

from ubs_core import analyzers, py_detectors, py_patterns, py_scan
from ubs_core.cache import CapturingSink, ScanCache
from ubs_core.registry import Analyzer, analyzers_for_lang


class PythonCompletionTests(unittest.TestCase):
    def setUp(self):
        artifacts = REPO_ROOT / "test-suite/artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="python-completion-", dir=artifacts))
        self.source = self.root / "sample.py"
        self.source.write_text('handle = open("data", encoding="utf-8")\n', encoding="utf-8")
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("UBS_", "XDG_"))}
        self.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(HELPERS),
                        UBS_NO_AUTO_UPDATE="1", ENABLE_UV_TOOLS="0",
                        UBS_CACHE_DIR=str(self.root / "cache"), UBS_NO_PREFILTER="1")

    def run(self, result=None):
        print(f"[{self.id()}] RUN", flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} "
              f"({time.monotonic() - started:.3f}s)", flush=True)
        return result

    def decode_json(self, payload, description):
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            self.fail(f"{description}: invalid JSON: {exc}\n{payload[:2000]}")

    def scan(self, *, files=None, no_cache=False, skip="", jobs=1):
        selected = self.root / "files"
        selected.write_bytes(b"".join(os.fsencode(path) + b"\0"
                                     for path in (files if files is not None else [self.source])))
        sink, report, text = (self.root / name for name in ("sink.jsonl", "report.json", "report.txt"))
        env = {**self.env, "UBS_NO_CACHE": str(int(no_cache))}
        stderr = io.StringIO()
        with patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(stderr):
            code = py_scan.main(["--files-from", str(selected), "--sink", str(sink),
                                 "--json-out", str(report), "--text-out", str(text),
                                 "--project-dir", str(self.root), "--skip", skip,
                                 "--jobs", str(jobs)])
        doc = self.decode_json(report.read_text(), str(report))
        records = [self.decode_json(line, str(sink)) for line in sink.read_text().splitlines()]
        return code, doc, records, text.read_text(), stderr.getvalue()

    def assert_partial(self, result, message):
        code, doc, records, text, stderr = result
        self.assertEqual(code, 2, result)
        self.assertEqual(doc["status"], "partial", result)
        self.assertEqual(doc["module_error"], "ANALYZER_ERROR", result)
        self.assertIn(message, stderr, result)
        self.assertNotIn("good:", text, result)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], sum(row.get("severity") == severity for row in records))
        self.assertFalse(list((self.root / "cache").glob("*/files/**/*.json")),
                         "an incomplete run must not admit fresh per-file cache entries")

    @staticmethod
    def finding(ctx, rule="python.lifecycle.probe"):
        return {"rule": rule, "path": str(ctx.files[0]), "line": 1,
                "col": 1, "severity": "warning", "message": "observed before failure"}

    def test_analyzer_failure_preserves_records_and_runs_sibling_analyzers(self):
        for exception in (RuntimeError("producer crashed"), SystemExit(0)):
            def broken(ctx):
                yield self.finding(ctx)
                raise exception

            def healthy(ctx):
                yield self.finding(ctx, "python.guards.sibling")

            registered = [Analyzer("lifecycle", "python", "lifecycle_py", broken),
                          Analyzer("guards", "python", "guards_py", healthy)]
            with self.subTest(exception=type(exception).__name__), \
                 patch("ubs_core.registry.analyzers_for_lang", return_value=registered):
                for _ in range(2):
                    result = self.scan()
                    self.assert_partial(result, type(exception).__name__)
                    self.assertTrue({"python.lifecycle.probe", "python.guards.sibling"}
                                    <= {row["rule"] for row in result[2]})

    def test_file_local_analyzer_failure_does_not_drop_later_source(self):
        second = self.root / "later.py"
        second.write_text("value = 1\n")

        def run(ctx):
            for path in ctx.files:
                if path == self.source:
                    raise RuntimeError("first source failed")
                yield {"rule": "python.guards.later", "path": str(path), "line": 1}

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("guards", "python", "guards_py", run)]):
            result = self.scan(files=[self.source, second])
        self.assert_partial(result, "first source failed")
        self.assertEqual([row["path"] for row in result[2] if row["rule"] == "python.guards.later"],
                         [str(second)])

    def test_project_analyzer_keeps_its_full_selected_file_context(self):
        second = self.root / "helper.py"
        second.write_text("value = 1\n")
        observed = []

        def run(ctx):
            observed.append(ctx.files)
            yield self.finding(ctx, "python.taint.probe")
            raise RuntimeError("project pass failed")

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("taint", "python", "taint_py", run)]):
            result = self.scan(files=[self.source, second])
        self.assert_partial(result, "project pass failed")
        self.assertEqual(observed, [[self.source, second]])

    def test_recovery_after_project_failure_is_cold_then_reusable(self):
        fail = True
        calls = []

        def run(ctx):
            calls.append("taint")
            if fail:
                raise RuntimeError("project pass failed")
            return []

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("taint", "python", "taint_py", run)]):
            self.assert_partial(self.scan(), "project pass failed")
            fail = False
            cold, warm = self.scan(), self.scan()
        self.assertEqual(cold[1]["extras"]["profile"]["cache_hits"], 0)
        self.assertEqual(warm[1]["extras"]["profile"]["cache_hits"], 1)
        self.assertEqual(cold[1]["status"], "ok")
        self.assertEqual(cold[2], warm[2])
        self.assertEqual(calls, ["taint"] * 3)

    def test_disabled_builtin_analyzers_are_not_executed(self):
        def broken(ctx):
            raise RuntimeError("disabled analyzer ran")

        for name, layer, category in (("taint_py", "taint", 7),
                                      ("ctcompare_py", "ctcompare", 7),
                                      ("lifecycle_py", "lifecycle", 19),
                                      ("guards_py", "guards", 1)):
            with self.subTest(analyzer=name), patch("ubs_core.registry.analyzers_for_lang", return_value=[
                    Analyzer(layer, "python", name, broken)]):
                result = self.scan(skip=str(category), no_cache=True)
                self.assertEqual(result[1]["status"], "ok", result)
                self.assertNotEqual(result[0], 2, result)

    def test_pattern_import_failure_cannot_report_or_cache_a_clean_scan(self):
        original = importlib.import_module

        def broken(name, *args, **kwargs):
            if name == "ubs_core.py_patterns.foundations":
                raise ImportError("pattern pack missing")
            return original(name, *args, **kwargs)

        with patch("importlib.import_module", side_effect=broken):
            for _ in range(2):
                self.assert_partial(self.scan(), "pattern pack missing")

    def test_detector_import_failure_preserves_other_layer_findings(self):
        original = importlib.import_module

        def broken(name, *args, **kwargs):
            if name == "ubs_core.py_detectors.sql_injection":
                raise ImportError("SQL detector missing")
            return original(name, *args, **kwargs)

        with patch("importlib.import_module", side_effect=broken):
            for _ in range(2):
                result = self.scan()
                self.assert_partial(result, "SQL detector missing")
                self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_detector_iteration_failure_keeps_earlier_hits(self):
        module = importlib.import_module("ubs_core.py_detectors.sql_injection")

        def broken(files):
            yield "py.security.sql-injection", files[0], 1, 1, "before crash"
            raise RuntimeError("SQL detector crashed")

        with patch.object(module, "find", side_effect=broken):
            for _ in range(2):
                result = self.scan()
                self.assert_partial(result, "SQL detector crashed")
                self.assertIn("py.security.sql-injection", {row["rule"] for row in result[2]})
                self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_parallel_detectors_preserve_full_project_thresholds_and_capture(self):
        files = []
        for index in range(8):
            path = self.root / f"divisions{index}.py"
            path.write_text('import os\nos.system(input())\n' +
                            ''.join(f'value{line} = numerator / divisor\n' for line in range(4)))
            files.append(path)
        outputs = []
        for jobs in (1, 3):
            target = io.StringIO()
            sink = CapturingSink(target)
            errors = []
            py_scan.run_detectors(files, sink, errors=errors, jobs=jobs)
            self.assertEqual(errors, [])
            records = [self.decode_json(line, 'detector JSON record')
                       for line in target.getvalue().splitlines()]
            self.assertTrue(any(row['severity'] == 'critical' for row in records), records)
            divisions = [row for row in records if row['rule'].startswith('py.numeric.division')]
            self.assertEqual(len(divisions), 32)
            self.assertEqual({(row['rule'], row['severity']) for row in divisions},
                             {('py.numeric.division-heavy', 'warning')})
            for path in files:
                self.assertEqual(sink.get_for_file(path),
                                 [row for row in records if row['path'] == str(path)])
            outputs.append(records)
        self.assertEqual(*outputs)
        sink = io.StringIO()
        errors = []
        py_scan.run_detectors(files, sink, skip={2}, errors=errors, jobs=3)
        self.assertEqual(errors, [])
        records = [self.decode_json(line, 'detector JSON record')
                   for line in sink.getvalue().splitlines()]
        self.assertFalse(any(row['rule'].startswith('py.numeric.division') for row in records))
        self.assertTrue(any(row['severity'] == 'critical' for row in records), records)

    def test_detector_worker_protocol_retains_hits_before_failure(self):
        module = importlib.import_module("ubs_core.py_detectors.sql_injection")

        def broken(files):
            yield "py.security.sql-injection", files[0], 1, 1, "before worker failure"
            raise RuntimeError("worker detector failed")

        with patch.object(module, "find", side_effect=broken):
            payload, errors = py_scan._detector_job("sql_injection", [self.source], None)
        self.assertEqual(self.decode_json(payload, 'worker payload')['rule'], 'py.security.sql-injection')
        self.assertEqual(errors, ['detector sql_injection: RuntimeError: worker detector failed'])

    def test_detector_worker_deadline_terminates_a_stalled_child(self):
        stalled = self.root / 'stalled-python'
        stalled.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(30)\n')
        stalled.chmod(0o755)
        with patch.object(sys, 'executable', str(stalled)), \
                patch.dict(os.environ, {'UBS_MODULE_TIMEOUT': '1'}):
            with self.assertRaises(subprocess.TimeoutExpired):
                py_scan._detector_process('division', [self.source], None)

    def test_malformed_detector_protocol_fails_loudly(self):
        for request in ('not JSON', 'null', '[]'):
            with self.subTest(request=request), patch.object(sys, 'stdin', io.StringIO(request)):
                with self.assertRaisesRegex(ValueError, 'Invalid detector worker request'):
                    py_scan._detector_worker()
        for index, reply in enumerate(('not JSON', '[null, []]', '["", [null]]')):
            invalid = self.root / f'invalid-worker{index}'
            invalid.write_text(f'#!{sys.executable}\nprint({reply!r})\n')
            invalid.chmod(0o755)
            with self.subTest(reply=reply), patch.object(sys, 'executable', str(invalid)):
                with self.assertRaisesRegex(ValueError, 'Invalid detector worker response'):
                    py_scan._detector_process('division', [self.source], None)

    def test_parallel_detector_failure_is_partial_and_keeps_sibling_records(self):
        from types import SimpleNamespace

        files = []
        for index in range(8):
            path = self.root / f"sibling{index}.py"
            path.write_text('handle = open("data", encoding="utf-8")\n' +
                            ''.join(f'value{line} = numerator / divisor\n' for line in range(4)))
            files.append(path)
        original = py_scan.run_detectors

        def selected_detectors(*args, **kwargs):
            with patch('pkgutil.iter_modules', return_value=[
                    SimpleNamespace(name='division'), SimpleNamespace(name='missing_detector_probe')]):
                return original(*args, **kwargs)

        with patch.object(py_scan, 'run_detectors', side_effect=selected_detectors):
            result = self.scan(files=files, jobs=3)
        self.assert_partial(result, 'missing_detector_probe')
        self.assertEqual(sum(row['rule'] == 'py.numeric.division-heavy' for row in result[2]), 32)
        self.assertIn('python.lifecycle.file_handle', {row['rule'] for row in result[2]})

    def test_unreadable_input_is_not_an_empty_successful_source(self):
        missing = self.root / "missing.py"
        for jobs in (1, 2):
            with self.subTest(jobs=jobs):
                result = self.scan(files=[missing, self.source], jobs=jobs)
                self.assert_partial(result, "missing.py")
                self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_direct_analyzer_api_does_not_hide_failure_without_error_collector(self):
        def broken(ctx):
            raise RuntimeError("direct API failure")

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("guards", "python", "guards_py", broken)]):
            with self.assertRaisesRegex(RuntimeError, "direct API failure"):
                py_scan.run_analyzers([self.source], io.StringIO())

    def test_failed_analyzer_keeps_suppression_as_a_reporting_operation(self):
        self.source.write_text("value = 1  # ubs:ignore\nvalue = 2\n")

        def broken(ctx):
            for line in (1, 2):
                yield {**self.finding(ctx), "line": line}
            raise RuntimeError("suppressed producer failed")

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("lifecycle", "python", "lifecycle_py", broken)]):
            result = self.scan()
        self.assert_partial(result, "suppressed producer failed")
        self.assertEqual([row["line"] for row in result[2] if row["rule"] == "python.lifecycle.probe"], [2])

    def test_suppressing_every_finding_does_not_suppress_analyzer_failure(self):
        self.source.write_text("value = 1  # ubs:ignore\n")

        def broken(ctx):
            yield self.finding(ctx)
            raise RuntimeError("no findings does not mean complete")

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("guards", "python", "guards_py", broken)]):
            result = self.scan()
        self.assert_partial(result, "no findings does not mean complete")
        self.assertEqual(result[2], [])
        self.assertEqual(result[1]["critical"], 0)
        self.assertEqual(result[1]["warning"], 0)

    def test_failed_report_write_does_not_admit_fresh_cache_entries(self):
        (self.root / "report.json").mkdir()
        with self.assertRaises(IsADirectoryError):
            self.scan()
        self.assertFalse(list((self.root / "cache").glob("*/files/**/*.json")))

    def test_unexpected_pattern_failure_still_runs_other_layers(self):
        with patch.object(py_scan, "scan_patterns", side_effect=RuntimeError("pattern failed")):
            result = self.scan()
        self.assert_partial(result, "pattern failed")
        self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_malformed_detector_metadata_does_not_discard_other_layers(self):
        module = importlib.import_module("ubs_core.py_detectors.sql_injection")
        with patch.object(module, "RULES", [("incomplete",)]):
            result = self.scan()
        self.assert_partial(result, "IndexError")
        self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_registry_load_failure_is_partial_and_preserves_pattern_findings(self):
        original = __import__

        def broken(name, *args, **kwargs):
            fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist", ())
            if name == "ubs_core" and "analyzers" in fromlist:
                raise ImportError("registry import failed")
            return original(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=broken):
            result = self.scan()
        self.assert_partial(result, "registry import failed")
        self.assertIn("py.io.open-missing-with", {row["rule"] for row in result[2]})

    def test_warm_directory_cache_cannot_treat_a_missing_source_as_a_hit(self):
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([self.source])
            cache.store_scanned_files([self.source], {})
            missing = self.root / "missing.py"
            cached, uncached = cache.partition_files([self.source, missing])
            self.assertNotIn(missing, cached)
            self.assertEqual(uncached, [missing])
            self.assertIn(self.source, cached)

    def test_cache_admission_rejects_edited_sources_but_keeps_stable_siblings(self):
        stable = self.root / "stable.py"
        stable.write_text("VALUE = 1\n")
        record = {"rule": "probe.stable", "path": str(stable), "line": 1}
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([self.source, stable])
            self.source.write_text("CHANGED = True\n")
            cache.store_scanned_files([self.source, stable], {str(stable): [record]})
            cached, misses = ScanCache("python", self.root).partition_files([self.source, stable])
        self.assertEqual(cached, {stable: [record]})
        self.assertEqual(misses, [self.source])

    def test_cache_admission_rechecks_same_size_timestamp_preserving_edits(self):
        self.source.write_text("VALUE = 1\n")
        before = self.source.stat()
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([self.source])
            self.source.write_text("VALUE = 2\n")
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
            cache.store_scanned_files([self.source], {})
            # Both a retained object and a fresh process must reject stale
            # scan results; a stat memo is not proof of the analyzed bytes.
            for instance in (cache, ScanCache("python", self.root)):
                self.assertEqual(instance.partition_files([self.source]), ({}, [self.source]))

    def test_retained_cache_rechecks_timestamp_preserving_edits_between_scans(self):
        self.source.write_text("VALUE = 1\n")
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([self.source])
            cache.store_scanned_files([self.source], {})
            self.assertEqual(cache.partition_files([self.source]), ({self.source: []}, []))
            before = self.source.stat()
            self.source.write_text("VALUE = 2\n")
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(cache.partition_files([self.source]), ({}, [self.source]))

    def test_cache_admission_rejects_a_source_that_only_appeared_after_partition(self):
        missing = self.root / "new.py"
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([missing])
            missing.write_text("VALUE = 1\n")
            cache.store_scanned_files([missing], {})
            self.assertEqual(ScanCache("python", self.root).partition_files([missing]), ({}, [missing]))

    def test_cache_admission_accepts_identical_contents_after_metadata_changes(self):
        original = self.source.read_text()
        record = {"rule": "probe.stable", "path": str(self.source), "line": 1}
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.root)
            cache.partition_files([self.source])
            self.source.write_text(original)
            cache.store_scanned_files([self.source], {str(self.source): [record]})
            self.assertEqual(ScanCache("python", self.root).partition_files([self.source]),
                             ({self.source: [record]}, []))

    def test_project_pass_edit_cannot_cache_earlier_clean_python_results(self):
        self.source.write_text("VALUE = 1\n")
        edited = False

        def edit_after_file_pass(ctx):
            nonlocal edited
            if not edited:
                self.source.write_text('handle = open("data", encoding="utf-8")\n')
                edited = True
            return []

        registered = [item for item in analyzers_for_lang("python") if item.name != "taint_py"]
        registered.append(Analyzer("taint", "python", "taint_py", edit_after_file_pass))
        with patch("ubs_core.registry.analyzers_for_lang", return_value=registered):
            first = self.scan()
            self.assertEqual(first[0], 2, first)
            self.assertEqual(first[1]["status"], "partial", first)
            self.assertIn("source changed during analysis", first[4], first)
            self.assertFalse(list((self.root / "cache").glob("*/files/**/*.json")))
            fresh, warm = self.scan(), self.scan()
        self.assertEqual(fresh[1]["extras"]["profile"]["cache_misses"], 1)
        self.assertEqual(warm[1]["extras"]["profile"]["cache_hits"], 1)
        for result in (fresh, warm):
            self.assertEqual(result[0], 1, result)
            self.assertEqual(result[1]["critical"], 1)
            self.assertIn("python.lifecycle.file_handle", {row["rule"] for row in result[2]})

    def test_structured_analyzer_evidence_survives_the_pipeline(self):
        extras = {"source_count": 1, "taint_path": [
            {"path": str(self.source), "line": 1, "col": 1,
             "kind": "source", "label": "input"}]}

        def run(ctx):
            yield {**self.finding(ctx), "extras": extras}

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("lifecycle", "python", "lifecycle_py", run)]):
            for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
                found = [row for row in result[2] if row["rule"] == "python.lifecycle.probe"]
                self.assertEqual(found[0]["extras"], extras)

    def test_python_syntax_failures_are_partial_and_never_cached(self):
        healthy = self.root / "healthy.py"
        healthy.write_text('handle = open("data", encoding="utf-8")\n')
        for source in ("def unfinished(:\n    pass\n", "if True:\n", "value = \x00\n"):
            self.source.write_text(source)
            for no_cache in (False, False, True):
                with self.subTest(source=source, no_cache=no_cache):
                    result = self.scan(files=[self.source, healthy], no_cache=no_cache)
                    self.assert_partial(result, "Python syntax")
                    self.assertTrue(any(row["rule"] == "python.lifecycle.file_handle"
                                        and Path(row["path"]).resolve() == healthy.resolve()
                                        for row in result[2]), result)

    def test_syntax_failure_cannot_be_suppressed_into_a_successful_scan(self):
        self.source.write_text("def unfinished(:  # ubs:ignore\n    pass\n")
        for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
            self.assert_partial(result, "Python syntax")

    def test_repaired_syntax_recovers_without_replaying_partial_cache(self):
        self.source.write_text("if True:\n")
        self.assert_partial(self.scan(), "Python syntax")
        self.source.write_text("VALUE = 1\n")
        cold, warm, disabled = self.scan(), self.scan(), self.scan(no_cache=True)
        self.assertEqual(cold[1]["extras"]["profile"]["cache_misses"], 1)
        self.assertEqual(warm[1]["extras"]["profile"]["cache_hits"], 1)
        for result in (cold, warm, disabled):
            self.assertEqual(result[0], 0, result)
            self.assertEqual(result[1]["status"], "ok", result)

    def test_syntax_validation_covers_stubs_but_not_other_grammars(self):
        self.source = self.root / "types.pyi"
        self.source.write_text("def unfinished(: ...\n")
        self.assert_partial(self.scan(), "Python syntax")
        for filename, contents in (("extension.pyx", "cdef int count = 1\n"),
                                   ("settings.toml", "[project]\nname = 'example'\n")):
            self.source = self.root / filename
            self.source.write_text(contents)
            result = self.scan(no_cache=True)
            self.assertEqual(result[1]["status"], "ok", result)

    def test_syntax_validation_respects_the_declared_source_encoding(self):
        self.source.write_bytes(b'# coding: latin-1\nname = "caf\xe9"\n')
        for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
            self.assertEqual(result[1]["status"], "ok", result)
            self.assertEqual(result[0], 0, result)

    def test_encoded_python_keeps_real_resource_findings(self):
        sources = (b'# coding: latin-1\nr\xe9source = open("caf\xe9", encoding="utf-8")\n',
                   b'\xef\xbb\xbf# UTF-8 BOM\nhandle = open("data", encoding="utf-8")\n')
        for source in sources:
            self.source.write_bytes(source)
            for no_cache in (False, False, True):
                with self.subTest(source=source, no_cache=no_cache):
                    result = self.scan(no_cache=no_cache)
                    self.assertEqual(result[1]["status"], "ok", result)
                    self.assertEqual(result[0], 1, result)
                    self.assertEqual([row["line"] for row in result[2]
                                      if row["rule"] == "python.lifecycle.file_handle"], [2])

    def test_source_edit_during_cold_warm_and_uncached_scans_is_partial(self):
        original_run = py_scan.run_analyzers
        for mode in ("cold", "warm", "disabled"):
            self.source = self.root / (mode + ".py")
            self.source.write_text("VALUE = 1\n")
            if mode == "warm":
                self.assertEqual(self.scan()[0], 0)
            cache_before = {path: path.read_bytes()
                            for path in (self.root / "cache").glob("*/files/**/*.json")}
            before = self.source.stat()

            def mutate(*args, **kwargs):
                result = original_run(*args, **kwargs)
                if kwargs.get("taint") is True:
                    self.source.write_text("VALUE = 2\n")
                    os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
                return result

            with self.subTest(cache=mode), patch.object(py_scan, "run_analyzers", side_effect=mutate):
                result = self.scan(no_cache=mode == "disabled")
                self.assertEqual(result[0], 2, result)
                self.assertEqual(result[1]["status"], "partial", result)
                self.assertEqual(result[1]["module_error"], "ANALYZER_ERROR", result)
                self.assertIn("source changed during analysis", result[4], result)
                self.assertEqual(result[1]["extras"]["profile"]["cache_hits"], int(mode == "warm"))
                self.assertEqual({path: path.read_bytes()
                                  for path in (self.root / "cache").glob("*/files/**/*.json")}, cache_before)

    def test_completion_barrier_includes_source_suppression_reads(self):
        self.source.write_text("VALUE = 1  # ubs:ignore\n")
        original_filter = py_scan.SourceSuppressions.filter

        def mutate(index, records):
            result = original_filter(index, records)
            self.source.write_text("VALUE = 2  # ubs:ignore\n")
            return result

        with patch.object(py_scan.SourceSuppressions, "filter", new=mutate):
            self.assert_partial(self.scan(no_cache=True), "source changed during analysis")

    def test_completion_barrier_preserves_metadata_only_rewrites(self):
        self.source.write_text("VALUE = 1\n")
        original_run = py_scan.run_analyzers

        def touch(*args, **kwargs):
            result = original_run(*args, **kwargs)
            if kwargs.get("taint") is True:
                self.source.write_text("VALUE = 1\n")
            return result

        with patch.object(py_scan, "run_analyzers", side_effect=touch):
            for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
                self.assertEqual(result[0], 0, result)
                self.assertEqual(result[1]["status"], "ok", result)

    def test_unselected_file_edits_do_not_invalidate_selected_source(self):
        self.source.write_text("VALUE = 1\n")
        other = self.root / "unselected.py"
        other.write_text("VALUE = 1\n")
        original_run = py_scan.run_analyzers

        def mutate(*args, **kwargs):
            result = original_run(*args, **kwargs)
            other.write_text("VALUE = 2\n")
            return result

        with patch.object(py_scan, "run_analyzers", side_effect=mutate):
            result = self.scan(no_cache=True)
        self.assertEqual(result[0], 0, result)
        self.assertEqual(result[1]["status"], "ok", result)

    def test_capturing_sink_preserves_locationless_records_without_file_identity(self):
        sink = CapturingSink()
        records = [{"rule": "project.probe", "line": 0},
                   {"rule": "project.probe", "path": "", "line": 0},
                   {"rule": "project.probe", "path": None, "line": 0}]
        for row in records:
            sink.write(json.dumps(row) + "\n")
        self.assertEqual(sink.unscoped, records)
        self.assertEqual(sink.by_file, {})

    def test_project_findings_are_reported_not_suppressed_or_cached_as_source_facts(self):
        self.source.write_text("value = 1  # ubs:ignore\n")

        def run(ctx):
            yield {"rule": "python.project.probe", "path": "", "line": 0,
                   "severity": "critical", "message": "project configuration is unsafe"}
            yield self.finding(ctx)

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("guards", "python", "project_extension", run)]):
            for result in (self.scan(), self.scan(), self.scan(no_cache=True)):
                self.assertEqual(result[0], 1, result)
                self.assertEqual(result[1]["status"], "ok", result)
                self.assertEqual([row["rule"] for row in result[2]], ["python.project.probe"])
                self.assertEqual(result[1]["critical"], 1)
                self.assertEqual(result[1]["extras"]["profile"]["cache_hits"], 0)
        self.assertFalse(list((self.root / "cache").glob("*/files/**/*.json")))

    def test_always_run_project_findings_survive_warm_source_caches(self):
        self.source.write_text("value = 1  # ubs:ignore\n")

        def run(ctx):
            yield {"rule": "python.project.probe", "line": 0, "severity": "critical"}

        with patch("ubs_core.registry.analyzers_for_lang", return_value=[
                Analyzer("taint", "python", "taint_py", run)]):
            cold, warm, disabled = self.scan(), self.scan(), self.scan(no_cache=True)
        self.assertEqual(warm[1]["extras"]["profile"]["cache_hits"], 1)
        for result in (cold, warm, disabled):
            self.assertEqual(result[0], 1, result)
            self.assertEqual([row["rule"] for row in result[2]], ["python.project.probe"])

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "public UBS requires jq and ripgrep")
    def test_public_cli_syntax_failures_are_partial_even_without_findings(self):
        for invalid in (True, False):
            self.source.write_text("def unfinished(:  # ubs:ignore\n    pass\n" if invalid else "VALUE = 1\n")
            for output_format in ("json", "sarif"):
                for attempt in (1, 2):
                    with self.subTest(invalid=invalid, format=output_format, attempt=attempt):
                        command = [str(REPO_ROOT / "ubs"), "--ci", "--only=python",
                                   "--format=" + output_format, str(self.source)]
                        proc = subprocess.run(command, cwd=self.root, env=self.env, text=True,
                                              capture_output=True, timeout=120)
                        prefix = self.root / f"syntax-{invalid}-{output_format}-{attempt}"
                        prefix.with_suffix(".stdout").write_text(proc.stdout)
                        prefix.with_suffix(".stderr").write_text(proc.stderr)
                        self.assertEqual(proc.returncode, 2 if invalid else 0, proc.stdout + proc.stderr)
                        doc = self.decode_json(proc.stdout, str(prefix))
                        if output_format == "json":
                            self.assertEqual(doc["status"], "partial" if invalid else "ok", doc)
                            self.assertEqual(bool(doc["failed_modules"]), invalid, doc)
                            self.assertEqual(doc["totals"]["critical"], 0, doc)
                        else:
                            self.assertTrue(doc["runs"], doc)
                            for run in doc["runs"]:
                                if invalid:
                                    invocation = run["invocations"][0]
                                    self.assertIs(invocation["executionSuccessful"], False, doc)
                                    self.assertEqual(invocation["exitCode"], 2, doc)
                                else:
                                    self.assertTrue(all(inv["executionSuccessful"] is True
                                                        for inv in run.get("invocations", [])), doc)
                        self.assertEqual(bool(list((self.root / "cache").glob("*/files/**/*.json"))), not invalid)

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg"), "public UBS requires jq and ripgrep")
    def test_public_cli_retains_findings_and_failed_completion_through_recovery(self):
        # Exercise the actual verified scanner with a real faulting detector,
        # not a simulated report or altered expected severity. Keep all fixture
        # code and subprocess artifacts under the supported artifacts directory.
        checkout = self.root / "scanner"
        shutil.copytree(REPO_ROOT, checkout,
                        ignore=shutil.ignore_patterns(".git", "artifacts", "__pycache__"))
        detector = checkout / "modules/helpers/ubs_core/py_detectors/zzz_completion_probe.py"
        detector.write_text(
            'import os\n'
            'RULE_ID = "py.security.completion-probe"\n'
            'CATEGORY = 7\n'
            'TITLE = "Completion probe"\n'
            'SEVERITY = "critical"\n'
            'def find(files):\n'
            '    for path in files:\n'
            '        yield path, 1, 1, "record emitted before failure"\n'
            '    if os.environ.get("UBS_TEST_PRODUCER_FAIL") == "1":\n'
            '        raise RuntimeError("deliberate completion regression")\n', encoding="utf-8")
        env = {**self.env, "UBS_ALLOW_PARTIAL": "0"}
        updated = subprocess.run([sys.executable, "scripts/update_checksums.py"], cwd=checkout,
                                 env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        for failure in (True, False):
            for output_format in ("json", "sarif"):
                for attempt in (1, 2):
                    with self.subTest(failure=failure, format=output_format, attempt=attempt):
                        env["UBS_TEST_PRODUCER_FAIL"] = str(int(failure))
                        command = [str(checkout / "ubs"), "--ci", "--only=python",
                                   "--format=" + output_format, str(self.source)]
                        proc = subprocess.run(command, cwd=self.root, env=env, text=True,
                                              capture_output=True, timeout=120)
                        prefix = self.root / f"public-{failure}-{output_format}-{attempt}"
                        prefix.with_suffix(".stdout").write_text(proc.stdout)
                        prefix.with_suffix(".stderr").write_text(proc.stderr)
                        self.assertEqual(proc.returncode, 2 if failure else 1, proc.stdout + proc.stderr)
                        doc = self.decode_json(proc.stdout, str(prefix))
                        if output_format == "json":
                            self.assertEqual(doc["status"], "partial" if failure else "ok", doc)
                            self.assertEqual(bool(doc["failed_modules"]), failure, doc)
                            self.assertEqual(doc["totals"]["critical"], 2, doc)
                            rows = doc["findings"]
                            rules = {row["rule_id"] for row in rows}
                        else:
                            self.assertTrue(doc["runs"], doc)
                            for run in doc["runs"]:
                                if failure:
                                    invocation = run["invocations"][0]
                                    self.assertIs(invocation["executionSuccessful"], False, doc)
                                    self.assertEqual(invocation["exitCode"], 2, doc)
                                else:
                                    # Successful UBS runs may omit the optional
                                    # invocation object; no failure may survive
                                    # recovery. The real process exit is checked
                                    # above, independently of this report field.
                                    self.assertTrue(all(inv["executionSuccessful"] is True
                                                        for inv in run.get("invocations", [])), doc)
                            rules = {row["ruleId"] for run in doc["runs"] for row in run["results"]}
                        self.assertTrue({"py.security.completion-probe", "python.lifecycle.file_handle"} <= rules)
                        entries = list((self.root / "cache").glob("*/files/**/*.json"))
                        self.assertEqual(bool(entries), not failure)


if __name__ == "__main__":
    unittest.main()
