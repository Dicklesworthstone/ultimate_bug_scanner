"""D6/C5: parallel execution must preserve whole-selection analysis semantics."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "modules" / "helpers"
sys.path.insert(0, str(HELPERS))
from ubs_core import registry


class LoggedCase(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        result = super().run(result)
        failed = any(case is self for case, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} ({time.monotonic() - started:.3f}s)", flush=True)
        return result


class SchedulingTests(LoggedCase):
    def setUp(self):
        self.context = registry.RunContext("python", files=[Path(f"{i}.py") for i in range(8)],
                                           rules={"nested": [1]}, profile={"disabled_rules": ["disabled"]})

    @staticmethod
    def record(path, rule="test.rule"):
        return {"rule": rule, "path": str(path), "line": 1}

    def test_default_analyzer_keeps_all_selected_paths_in_original_order(self):
        seen = []
        def analyze(ctx):
            seen.append(list(ctx.files))
            yield self.record(ctx.files[-1])
        analyzer = registry.Analyzer("taint", "python", "whole", analyze)
        with patch.dict(registry._REGISTRY, {("taint", "python"): [analyzer]}, clear=True):
            baseline = list(registry.run_layer("taint", self.context))
            for jobs in (2, 8, 64):
                self.assertEqual(list(registry.run_layer("taint", self.context, jobs=jobs)), baseline)
        self.assertEqual(seen, [self.context.files] * 4)

    def test_independent_analyzers_run_concurrently_without_splitting_selection(self):
        barrier = threading.Barrier(2, timeout=5)
        seen = []
        lock = threading.Lock()
        def make(name):
            def analyze(ctx):
                with lock:
                    seen.append((name, threading.get_ident(), list(ctx.files)))
                barrier.wait()
                yield self.record(ctx.files[0], name)
            return registry.Analyzer("guards", "python", name, analyze)
        analyzers = [make("first"), make("second")]
        with patch.dict(registry._REGISTRY, {("guards", "python"): analyzers}, clear=True):
            records = list(registry.run_scan(self.context, jobs=2))
        self.assertEqual([r["rule"] for r in records], ["first", "second"])
        self.assertEqual(len({thread for _, thread, _ in seen}), 2)
        self.assertTrue(all(files == self.context.files for _, _, files in seen))

    def test_only_declared_file_independent_analyzers_are_sharded(self):
        seen = []
        lock = threading.Lock()
        barrier = threading.Barrier(2, timeout=5)
        def analyze(ctx):
            with lock:
                seen.append(list(ctx.files))
            barrier.wait()
            return [self.record(path) for path in ctx.files]
        analyzer = registry.Analyzer("guards", "python", "local", analyze, file_independent=True)
        with patch.dict(registry._REGISTRY, {("guards", "python"): [analyzer]}, clear=True):
            records = list(registry.run_layer("guards", self.context, jobs=2))
        self.assertEqual([r["path"] for r in records], list(map(str, self.context.files)))
        self.assertGreater(len(seen), 1)
        self.assertTrue(all(len(paths) < len(self.context.files) for paths in seen))

    def test_pending_worker_results_are_bounded_by_requested_jobs(self):
        started = []
        class ImmediateExecutor:
            def __init__(self, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def submit(self, fn, *args):
                from concurrent.futures import Future
                started.append(args)
                future = Future()
                future.set_result(fn(*args))
                return future
        analyzer = registry.Analyzer("guards", "python", "local",
            lambda ctx: [self.record(path) for path in ctx.files], file_independent=True)
        self.context.files = [Path(f"{i}.py") for i in range(40)]
        with patch.dict(registry._REGISTRY, {("guards", "python"): [analyzer]}, clear=True), \
             patch.object(registry, "ThreadPoolExecutor", ImmediateExecutor):
            records = registry.run_layer("guards", self.context, jobs=2)
            next(records)
            self.assertEqual(len(started), 2)
            records.close()
        self.assertEqual(len(started), 2)

    def test_parallel_tasks_do_not_share_mutable_context_or_policy(self):
        def mutate(ctx):
            ctx.rules["nested"].append(2)
            ctx.profile["disabled_rules"].append("other")
            path = ctx.files.pop()
            return [self.record(path)]
        analyzers = [registry.Analyzer("guards", "python", str(i), mutate) for i in range(3)]
        with patch.dict(registry._REGISTRY, {("guards", "python"): analyzers}, clear=True):
            records = list(registry.run_scan(self.context, jobs=3))
        self.assertEqual(len(self.context.files), 8)
        self.assertEqual(self.context.rules, {"nested": [1]})
        self.assertEqual(self.context.profile, {"disabled_rules": ["disabled"]})
        self.assertEqual([r["path"] for r in records], ["7.py"] * 3)

    def test_worker_failure_is_not_silently_dropped(self):
        def fail(ctx):
            raise RuntimeError("analyzer failed")
        analyzer = registry.Analyzer("guards", "python", "broken", fail)
        with patch.dict(registry._REGISTRY, {("guards", "python"): [analyzer]}, clear=True), \
             self.assertRaisesRegex(RuntimeError, "analyzer failed"):
            list(registry.run_scan(self.context, jobs=2))

    def test_empty_selection_has_same_project_semantics_in_serial_and_parallel(self):
        analyzer = registry.Analyzer("guards", "python", "project", lambda ctx: [self.record("project")],
                                     file_independent=True)
        self.context.files = []
        with patch.dict(registry._REGISTRY, {("guards", "python"): [analyzer]}, clear=True):
            self.assertEqual(list(registry.run_scan(self.context)), list(registry.run_scan(self.context, jobs=4)))

    def test_invalid_worker_counts_and_scope_declarations_are_rejected(self):
        for jobs in (0, -1, 65, True, 1.5):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                list(registry.run_scan(self.context, jobs=jobs))
        with self.assertRaises(ValueError):
            registry.Analyzer("taint", "python", "bad", lambda ctx: [], file_independent="yes")


class CoreCLITests(LoggedCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ubs-scheduling-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.paths = []
        self.env = dict(os.environ, PYTHONPATH=str(HELPERS), PYTHONDONTWRITEBYTECODE="1")

    def source(self, name, text):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.paths.append(path)
        return path

    def run_core(self, language="python", layer="taint", jobs=1, profile=None):
        selected = self.work / "selection.nul"
        selected.write_bytes(b"".join(os.fsencode(path) + b"\0" for path in self.paths))
        command = [sys.executable, "-m", "ubs_core", layer, "--lang", language,
                   "--files-from", str(selected), "--jobs", str(jobs)]
        if profile is not None:
            config = self.work / "profile.json"
            config.write_text(json.dumps(profile))
            command += ["--profile", str(config)]
        process = subprocess.run(command, cwd=self.work, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, f"{command}\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}")
        return [json.loads(line) for line in process.stdout.splitlines()]

    def assert_parallel_parity(self, rule, language="python", layer="taint", **kwargs):
        serial = self.run_core(language, layer, 1, **kwargs)
        self.assertIn(rule, {finding["rule"] for finding in serial}, serial)
        for jobs in (2, 8):
            with self.subTest(jobs=jobs):
                self.assertEqual(self.run_core(language, layer, jobs, **kwargs), serial)
        return serial

    def test_python_imported_sink_is_not_lost_to_worker_partitioning(self):
        self.source("caller.py", "from helper import run\nrun(input())\n")
        helper = self.source("helper.py", "def run(value):\n    eval(value)\n")
        records = self.assert_parallel_parity("python.taint.eval")
        self.assertTrue(any(r["path"] == str(helper) and r["line"] == 2 for r in records))

    def test_python_returned_source_summary_survives_partitioning(self):
        self.source("caller.py", "from helper import source\nimport os\nos.system(source())\n")
        self.source("helper.py", "def source():\n    return input()\n")
        self.assert_parallel_parity("python.taint.command")

    def test_python_relative_imports_and_reexports_keep_project_root(self):
        self.source("caller.py", "from pkg.bridge import run\nrun(input())\n")
        self.source("pkg/__init__.py", "")
        self.source("pkg/bridge.py", "from .sink import execute as run\n")
        self.source("pkg/sink.py", "def execute(value):\n    eval(value)\n")
        self.assert_parallel_parity("python.taint.eval")

    def test_python_all_layers_keep_taint_scope_while_local_layers_shard(self):
        self.source("caller.py", "from helper import run\nrun(input())\na.b.c.d\n")
        self.source("helper.py", "def run(value):\n    eval(value)\n")
        records = self.assert_parallel_parity("python.taint.eval", layer="scan")
        self.assertIn("python.guards.deep_attr_chain", {r["rule"] for r in records})

    def test_go_package_sink_summary_is_not_split_from_caller(self):
        caller = self.source("caller.go", 'package main\nimport "os"\nfunc handle() {\n    sink(os.Getenv("CMD"))\n}\n')
        self.source("helper.go", 'package main\nimport "os/exec"\nfunc sink(value string) {\n    exec.Command("sh", "-c", value).Run()\n}\n')
        records = self.assert_parallel_parity("go.taint.command", language="go")
        # Go reports the summary effect at the caller, with the callee sink
        # retained in its provenance; it does not relocate it to the helper.
        self.assertTrue(any(r["path"] == str(caller) and r["line"] == 4
                            and "sink() -> exec.Command" in r["message"] for r in records))

    def test_javascript_import_graph_and_input_order_remain_intact(self):
        self.source("caller.js", 'import {send} from "./helper.js"; send(req.query.html);\n')
        self.source("helper.js", 'export function send(value) { res.send(value); }\n')
        self.source("independent.js", 'res.send(req.query.other);\n')
        self.assert_parallel_parity("javascript.taint.xss", language="javascript")

    def test_file_independent_guard_results_preserve_selection_order(self):
        for name in ("z.py", "with space.py", "line\nbreak.py", "a.py"):
            self.source(name, "a.b.c.d\n")
        serial = self.run_core(layer="guards")
        self.assertEqual([r["path"] for r in serial], list(map(str, self.paths)))
        for jobs in (2, 8):
            self.assertEqual(self.run_core(layer="guards", jobs=jobs), serial)

    def test_disabled_rule_and_unselected_helper_are_not_resurrected(self):
        self.source("caller.py", "from helper import run\nrun(input())\n")
        self.source("helper.py", "def run(value):\n    eval(value)\n")
        for jobs in (1, 2, 8):
            self.assertEqual(self.run_core(jobs=jobs, profile={"disabled_rules": ["python.taint.eval"]}), [])
        self.paths.pop()
        for jobs in (1, 2, 8):
            self.assertEqual(self.run_core(jobs=jobs), [])

    def test_invalid_jobs_fails_before_scanning(self):
        for jobs in ("0", "-1", "65", "nan"):
            command = [sys.executable, "-m", "ubs_core", "taint", "--lang", "python", "--jobs", jobs]
            result = subprocess.run(command, cwd=self.work, env=self.env, input="", capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()