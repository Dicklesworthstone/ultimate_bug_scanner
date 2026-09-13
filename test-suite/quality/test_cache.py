#!/usr/bin/env python3
"""Unit tests for ubs_core.cache — Merkle-keyed incremental scan cache (bead C4).

Verifies:
1. Replay is byte-identical to a cold scan.
2. Second run on an unchanged corpus is >= 5x faster.
3. Editing one file invalidates exactly that file's entry.
4. Rule-pack change invalidates everything.
5. Concurrent scans do not corrupt the cache.
6. User-facing controls: UBS_NO_CACHE, UBS_CACHE_DIR, --no-cache, doctor prune.
7. Cross-file input dependency invalidation.
8. Merkle directory subtree skipping.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.cache import (  # noqa: E402
    ENV_CACHE_DIR,
    ENV_NO_CACHE,
    CapturingSink,
    ScanCache,
    compute_cache_key,
    doctor_stats,
    get_cache_base_dir,
    get_clean_git_blobs,
    is_cache_disabled,
    prune_cache,
)


def record_artifact(case_id: str, data: dict[str, Any]) -> None:
    dest = REPO_ROOT / "test-suite" / "artifacts" / case_id
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "result.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


class IncrementalCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        self.cache_dir = self.test_root / "cache"
        self.project_dir = self.test_root / "project"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.project_dir.mkdir(parents=True, exist_ok=True)

        # Set env override
        os.environ[ENV_CACHE_DIR] = str(self.cache_dir)
        os.environ.pop(ENV_NO_CACHE, None)

    def tearDown(self) -> None:
        os.environ.pop(ENV_CACHE_DIR, None)
        os.environ.pop(ENV_NO_CACHE, None)
        self.temp_dir.cleanup()

    def _run_with_logging(self, case_id: str, fn) -> None:
        print(f"[{case_id}] RUN", flush=True)
        t0 = time.perf_counter()
        try:
            fn()
            elapsed = time.perf_counter() - t0
            print(f"[{case_id}] PASS ({elapsed:.3f}s)", flush=True)
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            print(f"[{case_id}] FAIL ({elapsed:.3f}s): {exc}", flush=True)
            raise

    def _git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.project_dir), *args],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"{args}: {proc.stderr}")
        return proc.stdout

    def test_git_blob_reuse_is_scoped_to_the_requested_subtree(self) -> None:
        self._git("init", "-q")
        nested = self.project_dir / "nested"
        nested.mkdir()
        # NUL-delimited Git output must retain quoted, tab/newline and trailing
        # whitespace filenames exactly; none are shell-interpolated.
        names = ["plain.py", 'quoted".py', "tab\tname.py", "line\nname.py",
                 "carriage\rname.py", "trailing.py "]
        if os.name == "posix":
            names.append(os.fsdecode(b"raw-\xff.py"))
        for name in names:
            (nested / name).write_text("VALUE = 1\n", encoding="utf-8")
        outside = self.project_dir / "outside.py"
        outside.write_text("VALUE = 1\n", encoding="utf-8")
        self._git("add", "--", "nested", "outside.py")
        self._git("-c", "user.name=UBS Test", "-c", "user.email=test@example.invalid",
                  "commit", "-q", "-m", "source fixture")
        expected = {
            name: self._git("hash-object", "--", str(nested / name)).strip()
            for name in names
        }
        outside.write_text("VALUE = 200\n", encoding="utf-8")
        self.assertTrue(self._git("status", "--porcelain"))
        self.assertEqual(get_clean_git_blobs(nested), expected)

        ignored = self.project_dir / "scratch"
        ignored.mkdir()
        (self.project_dir / ".gitignore").write_text("scratch/\n", encoding="utf-8")
        (ignored / "fresh.py").write_text("VALUE = 2\n", encoding="utf-8")
        self.assertIsNone(get_clean_git_blobs(ignored))
        if os.name == "posix":
            self._git("config", "core.quotePath", "false")
            (nested / os.fsdecode(b"raw-\xff.py")).write_text("VALUE = 4\n", encoding="utf-8")
            self.assertIsNone(get_clean_git_blobs(nested))
        (nested / "plain.py").write_text("VALUE = 3\n", encoding="utf-8")
        self.assertIsNone(get_clean_git_blobs(nested))

    def test_git_hidden_worktree_changes_invalidate_cached_findings(self) -> None:
        self._git("init", "-q")
        source = self.project_dir / "source.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        self._git("add", "--", "source.py")
        self._git("-c", "user.name=UBS Test", "-c", "user.email=test@example.invalid",
                  "commit", "-q", "-m", "source fixture")
        for flag, clear in (("--assume-unchanged", "--no-assume-unchanged"),
                            ("--skip-worktree", "--no-skip-worktree")):
            with self.subTest(flag=flag):
                source.write_text("VALUE = 1\n", encoding="utf-8")
                self._git("update-index", flag, "--", "source.py")
                self.assertFalse(self._git("status", "--porcelain"))
                self.assertIsNone(get_clean_git_blobs(self.project_dir))
                cache = ScanCache("python", self.project_dir, rulepack_hash=flag)
                cache.store_scanned_files([source], {str(source): []})
                cached, misses = cache.partition_files([source])
                self.assertEqual(set(cached), {source})
                self.assertEqual(misses, [])
                before = source.stat()
                source.write_text("VALUE = 2\n", encoding="utf-8")
                os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                self.assertFalse(self._git("status", "--porcelain"))
                refreshed = ScanCache("python", self.project_dir, rulepack_hash=flag)
                cached, misses = refreshed.partition_files([source])
                self.assertEqual(cached, {})
                self.assertEqual(misses, [source])
                self._git("update-index", clear, "--", "source.py")

    def _copy_helpers(self) -> tuple[Path, dict[str, str]]:
        helpers = self.test_root / "helpers"
        shutil.copytree(
            HELPERS_DIR,
            helpers,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        run_env = dict(os.environ)
        run_env["PYTHONPATH"] = str(helpers)
        run_env[ENV_CACHE_DIR] = str(self.cache_dir)
        run_env.pop(ENV_NO_CACHE, None)
        run_env["UBS_PROFILE"] = "1"
        run_env["UBS_CACHE_FILE"] = str(self.test_root / "scan-stats.json")
        run_env["UBS_PREFILTER_FILE"] = str(self.test_root / "prefilter-stats.json")
        return helpers, run_env

    def _decode_json(self, payload: str, context: str) -> Any:
        try:
            return json.loads(payload)
        except ValueError as exc:
            self.fail(f"Invalid JSON: {exc}\n{context}\nJSON payload:\n{payload}")

    def _python_pattern_selection(
        self, files: list[Path], cache_dir: Path, hits: int, label: str, skip: str = "",
    ) -> tuple[bytes, dict, list[dict]]:
        sink = self.test_root / "pattern-selection.ndjson"
        summary = self.test_root / "pattern-selection.json"
        text_report = self.test_root / "pattern-selection.txt"
        run_env = dict(os.environ)
        run_env["PYTHONPATH"] = str(HELPERS_DIR)
        run_env[ENV_CACHE_DIR] = str(cache_dir)
        run_env.pop(ENV_NO_CACHE, None)
        run_env["UBS_PROFILE"] = "1"
        run_env["UBS_CACHE_FILE"] = str(self.test_root / "pattern-cache-stats.json")
        run_env["UBS_PREFILTER_FILE"] = str(self.test_root / "pattern-prefilter-stats.json")
        proc = subprocess.run(
            [sys.executable, "-m", "ubs_core.py_scan", "--sink", str(sink),
             "--json-out", str(summary), "--text-out", str(text_report),
             "--project-dir", str(self.project_dir), "--fail-on-warning", "--skip", skip],
            input="\0".join(str(path) for path in files),
            capture_output=True, text=True, cwd=HELPERS_DIR, env=run_env, timeout=180,
        )
        context = f"{label}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        self.assertIn(proc.returncode, (0, 1), context)
        self.assertNotIn("_ubs_python_pattern", proc.stdout + proc.stderr, context)
        for output in (sink, summary, text_report):
            self.assertTrue(output.is_file(), context)
            self.assertNotIn("_ubs_python_pattern", output.read_text(encoding="utf-8"), context)
        doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
        data = sink.read_bytes()
        records = [self._decode_json(line, context)
                   for line in data.decode("utf-8").splitlines() if line.strip()]
        self.assertEqual(doc["status"], "ok", context)
        self.assertEqual(doc["files"], len(files), context)
        self.assertEqual(proc.returncode, int(doc["critical"] + doc["warning"] > 0), context)
        for profile in (doc["profile"], doc["extras"]["profile"]):
            self.assertEqual(profile["cache_hits"], hits, context)
            self.assertEqual(profile["cache_misses"], len(files) - hits, context)
        for record in records:
            self.assertIn(record["severity"], ("critical", "warning", "info"), context)
            self.assertFalse(any(key.startswith("_ubs_") for key in record), context)
            self.assertIn(Path(record["path"]), files, context)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], sum(record["severity"] == severity
                                               for record in records), context)
        stable = {key: doc[key] for key in ("critical", "warning", "info", "findings", "report")}
        return data, stable, records

    def _python_pattern_selection_with_oracle(
        self, files: list[Path], hits: int, label: str, skip: str = "",
    ) -> list[dict]:
        actual = self._python_pattern_selection(files, self.cache_dir, hits, label, skip)
        with tempfile.TemporaryDirectory(prefix="pattern-oracle-", dir=self.test_root) as oracle:
            fresh = self._python_pattern_selection(files, Path(oracle), 0, label + " fresh", skip)
        self.assertEqual(actual[:2], fresh[:2], label)
        return actual[2]

    def test_python_pattern_thresholds_reconcile_selected_cached_matches(self) -> None:
        a = self.project_dir / "a.py"
        b = self.project_dir / "b.py"
        c = self.project_dir / "c.py"
        lengths = {a: 20, b: 1, c: 30}
        for path, count in lengths.items():
            path.write_text("print(value)\n" * count, encoding="utf-8")

        def check(files: list[Path], hits: int, severity: str | None, label: str) -> None:
            records = self._python_pattern_selection_with_oracle(files, hits, label)
            expected = [
                ("py.debug.print", str(path), line, 1, severity)
                for path in files for line in range(1, lengths[path] + 1)
            ] if severity else []
            self.assertEqual(
                [(record["rule"], record["path"], record["line"], record["col"], record["severity"])
                 for record in records], expected, label,
            )

        # Prime silent sub-threshold files independently. Their matches must
        # still contribute when an entirely cached selection crosses a tier.
        check([a], 0, None, "prime 20")
        check([b], 0, None, "prime 1")
        check([c], 0, "info", "prime 30")
        check([a, b, c], 3, "warning", "51 all cached")
        check([a], 1, None, "20 cached")
        check([a, b], 2, "info", "21 cached")
        check([a, c], 2, "info", "50 cached")
        check([a, b, c], 3, "warning", "51 cached again")
        lengths[c] = 29
        c.write_text("print(value)\n" * lengths[c], encoding="utf-8")
        check([a, b, c], 2, "info", "50 partial")
        check([a, b, c], 3, "info", "50 warm")
        lengths[c] = 31
        c.write_text("print(value)\n" * lengths[c], encoding="utf-8")
        check([a, b, c], 2, "warning", "52 partial")
        check([a, b, c], 3, "warning", "52 warm")
        skipped = self._python_pattern_selection_with_oracle([a, b, c], 0, "skip debug", "11")
        self.assertEqual(skipped, [])
        self.assertEqual(
            self._python_pattern_selection_with_oracle([a, b, c], 3, "skip debug warm", "11"), [],
        )

    def test_python_pattern_suppressors_reconcile_selected_cached_matches(self) -> None:
        idle = self.project_dir / "idle.py"
        context = self.project_dir / "context.py"
        active = self.project_dir / "active.py"
        idle.write_text("async def idle():\n    return 1\n", encoding="utf-8")
        # A raw-text suppressor with no async match and no candidate async
        # rule must survive caching too; this is the existing rule contract.
        context.write_text("# await completion\nVALUE = 1\n", encoding="utf-8")
        active.write_text("async def active():\n    await operation()\n", encoding="utf-8")

        def check(files: list[Path], hits: int, warning: bool, label: str,
                  idle_lines: tuple[int, ...] = (1,)) -> None:
            records = self._python_pattern_selection_with_oracle(files, hits, label)
            async_sites = [(str(path), line) for path in files
                           for line in (idle_lines if path == idle else (1,) if path == active else ())]
            for rule, severity, sites in (
                ("py.async.census", "info", async_sites),
                ("py.async.un-awaited-paths", "warning", async_sites if warning else []),
            ):
                found = [record for record in records if record["rule"] == rule]
                self.assertEqual(
                    [(record["path"], record["line"], record["col"], record["severity"])
                     for record in found],
                    [(path, line, 1, severity) for path, line in sites], label,
                )
            self.assertEqual(
                {record["rule"] for record in records},
                {"py.async.census", "py.async.un-awaited-paths"} if warning
                else {"py.async.census"} if async_sites else set(), label,
            )

        check([idle, context], 0, False, "cold suppressed")
        check([idle, context], 2, False, "warm suppressed")
        check([idle], 1, True, "cached suppressor removed")
        check([context], 1, False, "context only")
        check([idle, active], 1, False, "new actual await suppresses cached idle")
        check([idle, active], 2, False, "actual await warm")
        check([idle], 1, True, "actual await removed")
        context.write_text("VALUE = 2\n", encoding="utf-8")
        check([idle, context], 1, True, "partial suppressor removed")
        check([idle, context], 2, True, "warm unsuppressed")
        context.write_text("NOTE = 'await completion'\n", encoding="utf-8")
        check([idle, context], 1, False, "partial literal suppressor added")
        check([idle, context], 2, False, "literal suppressor warm")
        idle.write_text("async def idle():\n    return 1\nasync def other():\n    return 2\n",
                        encoding="utf-8")
        check([idle, context], 1, False, "cached suppressor with fresh matches", (1, 3))
        check([idle], 1, True, "recover both cached matches", (1, 3))

    def test_python_pattern_gate_direct_api_and_cached_facts_agree(self) -> None:
        from ubs_core.py_scan import Pattern, reconcile_pattern_records, scan_patterns

        # Pattern exposes configurable gates even though no built-in Python
        # rule currently sets one. Exercise that real API with actual files.
        pattern = Pattern(
            category=11, rule_id="py.debug.gated-print", title="Gated prints",
            regex=re.compile(r"print\("), thresholds=((1, "warning"),),
            gate_regex=re.compile(r"\bfeature_enabled\b"),
            suppress_when_regex=re.compile(r"\bpaused\b"),
        )
        source = self.project_dir / "source.py"
        gate = self.project_dir / "gate.py"
        suppressor = self.project_dir / "suppressor.py"
        source.write_text("print(value)\nprint(other)\n", encoding="utf-8")
        gate.write_text("FEATURE = 'feature_enabled'\n", encoding="utf-8")
        suppressor.write_text("# paused\n", encoding="utf-8")
        cache = ScanCache("python", self.project_dir, rulepack_hash="configured-gate")
        for path in (source, gate, suppressor):
            sink = CapturingSink()
            scan_patterns([pattern], [path], sink, set(), defer_global_checks=True)
            cache.store_scanned_files([path], sink.by_file)
        for selected, count in (([source], 0), ([source, gate], 2),
                                ([source, gate, suppressor], 0), ([gate], 0)):
            with self.subTest(selected=selected):
                direct = CapturingSink()
                counters = scan_patterns([pattern], selected, direct, set())
                expected = [record for path in selected for record in direct.get_for_file(path)]
                self.assertEqual(counters, {"critical": 0, "warning": count, "info": 0})
                self.assertEqual(
                    [(record["rule"], record["path"], record["line"], record["col"], record["severity"])
                     for record in expected],
                    [(pattern.rule_id, str(source), line, 1, "warning")
                     for line in range(1, count + 1)],
                )
                cached, misses = cache.partition_files(selected)
                self.assertEqual(misses, [])
                self.assertEqual(set(cached), set(selected))
                reconciled = reconcile_pattern_records(
                    [pattern], [record for path in selected for record in cached[path]],
                )
                self.assertEqual(reconciled, expected)

    def test_helper_source_upgrades_invalidate_real_scanner_cache(self) -> None:
        helpers, run_env = self._copy_helpers()
        sources = {
            "unsafe.py": "value = eval(input())\n",  # ubs:ignore[python.taint.eval] -- literal positive scanner fixture, never executed
            "handles.py": "fh = open('/tmp/cache-test.txt')\nfh.write('test')\n",
            "clean.py": "def add(x, y):\n    return x + y\n",
        }
        files = []
        for name, source in sources.items():
            path = self.project_dir / name
            path.write_text(source, encoding="utf-8")
            files.append(path)
        original_inputs = {path: path.read_bytes() for path in files}
        helper_paths = (
            "ubs_core/prefilter.py",
            "ubs_core/lexer.py",
            "ubs_core/py_detectors/_pathlike.py",
            "resource_lifecycle_go.go",
            "type_narrowing_ts.js",
        )
        for relative in helper_paths:
            path = helpers / relative
            prefix = b"#" if path.suffix == ".py" else b"//"
            path.write_bytes(path.read_bytes() + b"\n" + prefix + b" cache identity revision A\n")

        sink = self.test_root / "helper-scan.ndjson"
        summary = self.test_root / "helper-summary.json"

        def run_scan(expected_hits: int, label: str) -> tuple[bytes, dict, str, str]:
            proc = subprocess.run(
                [
                    sys.executable, "-m", "ubs_core.py_scan",
                    "--sink", str(sink), "--json-out", str(summary),
                    "--project-dir", str(self.project_dir),
                ],
                input="\0".join(str(path) for path in files),
                capture_output=True,
                text=True,
                cwd=str(helpers),
                env=run_env,
                timeout=180,
            )
            context = f"{label}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            self.assertEqual(proc.returncode, 1, context)
            self.assertTrue(sink.is_file(), context)
            self.assertTrue(summary.is_file(), context)
            doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
            self.assertEqual(doc["status"], "ok", context)
            self.assertEqual(doc["files"], len(files), context)
            for profile in (doc["profile"], doc["extras"]["profile"]):
                self.assertEqual(profile["cache_hits"], expected_hits, context)
                self.assertEqual(profile["cache_misses"], len(files) - expected_hits, context)
            data = sink.read_bytes()
            records = [
                self._decode_json(line, context)
                for line in data.decode("utf-8").splitlines() if line.strip()
            ]
            self.assertIn("py.security.eval-exec-usage", {rec["rule"] for rec in records}, context)
            for severity in ("critical", "warning", "info"):
                self.assertEqual(
                    doc[severity], sum(rec["severity"] == severity for rec in records), context,
                )
            stable_summary = {
                key: doc[key] for key in ("critical", "warning", "info", "findings")
            }
            return data, stable_summary, proc.stderr, context

        cold_bytes, cold_summary, _, _ = run_scan(0, "initial cold scan")

        def assert_replay(expected_hits: int, label: str) -> tuple[str, str]:
            data, summary_doc, stderr, context = run_scan(expected_hits, label)
            self.assertEqual(data, cold_bytes, context)
            self.assertEqual(summary_doc, cold_summary, context)
            return stderr, context

        assert_replay(len(files), "initial warm scan")
        for relative in helper_paths:
            with self.subTest(helper=relative):
                path = helpers / relative
                before_stat = path.stat()
                before = path.read_bytes()
                self.assertTrue(before.endswith(b" cache identity revision A\n"), relative)
                after = before[:-2] + b"B\n"
                self.assertEqual(len(after), len(before), relative)
                self.assertNotEqual(after, before, relative)
                path.write_bytes(after)
                os.utime(path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
                self.assertEqual(path.stat().st_mtime_ns, before_stat.st_mtime_ns, relative)
                self.assertEqual(path.stat().st_size, before_stat.st_size, relative)
                self.assertEqual(path.read_bytes(), after, relative)
                assert_replay(0, f"helper-only upgrade: {relative}")
                assert_replay(len(files), f"unchanged upgraded helper: {relative}")

        self.assertEqual({path: path.read_bytes() for path in files}, original_inputs)

        def cache_contents() -> dict[str, bytes]:
            return {
                path.relative_to(self.cache_dir).as_posix(): path.read_bytes()
                for path in self.cache_dir.rglob("*") if path.is_file()
            }

        before_cache = cache_contents()
        self.assertTrue(before_cache, "the positive scans must populate actual cache entries")
        unreadable = helpers / "ubs_core" / "_cache_identity_unreadable.py"
        missing_target = self.test_root / "missing-helper-source.py"
        self.assertFalse(missing_target.exists())
        unreadable.symlink_to(missing_target)
        self.assertTrue(unreadable.is_symlink())
        for attempt in (1, 2):
            stderr, context = assert_replay(0, f"unreadable helper attempt {attempt}")
            self.assertIn("ubs: cache disabled: cannot fingerprint helper sources:", stderr, context)
            self.assertIn(unreadable.name, stderr, context)
            self.assertEqual(cache_contents(), before_cache, context)
        run_env[ENV_NO_CACHE] = "1"
        stderr, context = assert_replay(0, "explicitly disabled cache with unreadable helper")
        self.assertNotIn("cannot fingerprint helper sources:", stderr, context)
        self.assertEqual(cache_contents(), before_cache, context)

    def test_report_cache_is_bound_to_file_and_reporting_context(self) -> None:
        helpers, run_env = self._copy_helpers()
        first = self.project_dir / "first.py"
        second = self.project_dir / "second.py"
        sibling = self.project_dir / "nested" / "first.py"
        sibling.parent.mkdir()
        body = "value = eval(input())\n"  # ubs:ignore[python.taint.eval] -- literal positive scanner fixture
        for source in (first, second, sibling):
            source.write_text(body, encoding="utf-8")
        other_project = self.test_root / "other-project"
        other_project.mkdir()
        other = other_project / "first.py"
        other.write_text(body, encoding="utf-8")
        sink = self.test_root / "context.ndjson"
        summary = self.test_root / "context.json"

        def scan(source: Path, project: Path, cwd: Path, expected_hits: int) -> bytes:
            proc = subprocess.run(
                [sys.executable, "-m", "ubs_core.py_scan", "--sink", str(sink),
                 "--json-out", str(summary), "--project-dir", str(project)],
                input=str(source), capture_output=True, text=True, cwd=cwd,
                env=run_env, timeout=180,
            )
            context = f"{source} cwd={cwd}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            self.assertEqual(proc.returncode, 1, context)
            doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
            self.assertEqual(doc["status"], "ok", context)
            self.assertEqual(doc["files"], 1, context)
            self.assertEqual(doc["profile"]["cache_hits"], expected_hits, context)
            self.assertEqual(doc["profile"]["cache_misses"], 1 - expected_hits, context)
            data = sink.read_bytes()
            records = [self._decode_json(line, context) for line in data.decode().splitlines()]
            self.assertIn("py.security.eval-exec-usage", {record["rule"] for record in records}, context)
            self.assertTrue(records, context)
            for record in records:
                path = Path(record["path"])
                self.assertEqual(path.name, source.name, context)
                if path.is_absolute():
                    self.assertEqual(path, source, context)
            return data

        for source, project, cwd in (
            (first, self.project_dir, helpers),
            (second, self.project_dir, helpers),
            (sibling, self.project_dir, helpers),
            (other, other_project, helpers),
            (first, self.project_dir, self.project_dir),
        ):
            with self.subTest(source=source, cwd=cwd):
                cold = scan(source, project, cwd, 0)
                self.assertEqual(scan(source, project, cwd, 1), cold)

    def test_same_basename_findings_stay_with_their_source(self) -> None:
        helpers, run_env = self._copy_helpers()
        first = self.project_dir / "same.py"
        nested = self.project_dir / self.project_dir.name / "same.py"
        nested.parent.mkdir()
        # The lifecycle analyzer keeps a cwd-relative path; the taint analyzer
        # supplies its complete source path. Both must identify the same file.
        hazard = "stream = open('local.txt')\nvalue = eval(input())\n"  # ubs:ignore[python.taint.eval] -- literal positive scanner fixture
        clean = "answer = 42\n"
        sink = self.test_root / "basename.ndjson"
        summary = self.test_root / "basename.json"

        def scan(paths: list[Path], cwd: Path, hits: int, owner: Path | None,
                 eval_count: int = 1) -> list[dict]:
            proc = subprocess.run(
                [sys.executable, "-m", "ubs_core.py_scan", "--sink", str(sink),
                 "--json-out", str(summary), "--project-dir", str(self.project_dir)],
                input="\0".join(str(path) for path in paths),
                capture_output=True, text=True, cwd=cwd, env=run_env, timeout=180,
            )
            context = f"{paths} cwd={cwd}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            self.assertEqual(proc.returncode, int(owner is not None), context)
            doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
            records = [self._decode_json(line, context)
                       for line in sink.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(doc["status"], "ok", context)
            self.assertEqual(doc["files"], len(paths), context)
            self.assertEqual(doc["profile"]["cache_hits"], hits, context)
            self.assertEqual(doc["profile"]["cache_misses"], len(paths) - hits, context)
            if owner is None:
                self.assertEqual(records, [], context)
                self.assertEqual(doc["critical"], 0, context)
            else:
                self.assertTrue(records, context)
                for record in records:
                    self.assertEqual((cwd / record["path"]).resolve(), owner, context)
                self.assertEqual(sum(record["rule"] == "python.taint.eval"
                                     for record in records), eval_count, context)
                self.assertEqual(sum(record["rule"] == "python.lifecycle.file_handle"
                                     for record in records), 1, context)
            for severity in ("critical", "warning", "info"):
                self.assertEqual(doc[severity], sum(record["severity"] == severity
                                                   for record in records), context)
            return records

        for cwd, relative_inputs in (
            (self.project_dir, False), (self.project_dir.parent, True), (helpers, True),
        ):
            with self.subTest(cwd=cwd):
                first_input = Path(os.path.relpath(first, cwd)) if relative_inputs else first
                nested_input = Path(os.path.relpath(nested, cwd)) if relative_inputs else nested
                inputs = [first_input, nested_input]
                first.write_text(hazard, encoding="utf-8")
                nested.write_text(clean, encoding="utf-8")
                cold = scan(inputs, cwd, 0, first)
                self.assertEqual(scan(inputs, cwd, 2, first), cold)
                scan([nested_input], cwd, 1, None)
                self.assertEqual(scan([first_input], cwd, 1, first), cold)
                first.write_text(hazard + "again = eval(input())\n", encoding="utf-8")  # ubs:ignore[python.taint.eval] -- literal positive scanner fixture
                scan(inputs, cwd, 1, first, eval_count=2)
                first.write_text(clean, encoding="utf-8")
                nested.write_text(hazard, encoding="utf-8")
                switched = scan(inputs, cwd, 0, nested)
                self.assertEqual(scan(inputs, cwd, 2, nested), switched)
                scan([first_input], cwd, 1, None)

    def test_helper_identity_applies_to_explicit_keys_for_all_languages(self) -> None:
        helpers, run_env = self._copy_helpers()
        languages = (
            "python", "js", "golang", "rust", "java", "kotlin",
            "ruby", "swift", "csharp", "cpp", "elixir", "bash",
        )
        code = (
            "import json, sys\n"
            "from ubs_core.cache import ScanCache\n"
            "keys = {lang: ScanCache(lang, sys.argv[1], "
            "module_checksum='fixed-module', rulepack_hash='fixed-rulepack').cache_key "
            "for lang in sys.argv[2:]}\n"
            "print(json.dumps(keys, sort_keys=True))\n"
        )

        def keys() -> dict[str, str]:
            proc = subprocess.run(
                [sys.executable, "-c", code, str(self.project_dir), *languages],
                capture_output=True, text=True, cwd=str(helpers), env=run_env, timeout=60,
            )
            context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            self.assertEqual(proc.returncode, 0, context)
            result = self._decode_json(proc.stdout, context)
            self.assertEqual(set(result), set(languages), context)
            return result

        path = helpers / "ubs_core" / "prefilter.py"
        path.write_bytes(path.read_bytes() + b"\n# explicit-key helper revision A\n")
        before = keys()
        self.assertEqual(keys(), before, "unchanged explicit keys must be stable")
        source_stat = path.stat()
        original = path.read_bytes()
        changed = original[:-2] + b"B\n"
        path.write_bytes(changed)
        os.utime(path, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
        self.assertEqual(path.stat().st_size, source_stat.st_size)
        self.assertEqual(path.stat().st_mtime_ns, source_stat.st_mtime_ns)
        self.assertNotEqual(path.read_bytes(), original)
        after = keys()
        for language in languages:
            self.assertNotEqual(before[language], after[language], language)
        self.assertEqual(keys(), after, "upgraded explicit keys must be stable")

    def test_directory_hit_revalidates_external_input_dependencies(self) -> None:
        dependent = self.project_dir / "dependent.py"
        independent = self.project_dir / "independent.py"
        dependency = self.test_root / "settings.json"
        dependent.write_text("VALUE = 1\n", encoding="utf-8")
        independent.write_text("VALUE = 2\n", encoding="utf-8")
        dependency.write_text('{"mode":"before"}\n', encoding="utf-8")
        files = [dependent, independent]
        input_bytes = {path: path.read_bytes() for path in files}
        dependency_hash = hashlib.blake2b(dependency.read_bytes(), digest_size=16).hexdigest()
        cache = ScanCache("python", self.project_dir, rulepack_hash="dependency-regression")
        cache.store_scanned_files(
            files,
            {str(path): [] for path in files},
            inputs_by_file={str(dependent): {str(dependency): dependency_hash}},
        )
        cached, misses = cache.partition_files(files)
        self.assertEqual(set(cached), set(files))
        self.assertEqual(misses, [])
        self.assertEqual(cache.stats["merkle_dir_hits"], 1, "the directory path must be exercised")
        directory_entries = {path: path.read_bytes() for path in cache.dirs_dir.rglob("*.json")}
        self.assertTrue(directory_entries)

        dependency.write_text('{"mode":"after-upgrade"}\n', encoding="utf-8")
        self.assertNotEqual(
            hashlib.blake2b(dependency.read_bytes(), digest_size=16).hexdigest(), dependency_hash,
        )
        self.assertEqual({path: path.read_bytes() for path in files}, input_bytes)
        refreshed = ScanCache("python", self.project_dir, rulepack_hash="dependency-regression")
        cached, misses = refreshed.partition_files(files)
        self.assertEqual(misses, [dependent], "changed external input must invalidate its consumer")
        self.assertEqual(set(cached), {independent}, "independent source must remain cached")
        self.assertEqual(refreshed.stats["hits"], 1)
        self.assertEqual(refreshed.stats["misses"], 1)
        self.assertEqual(
            {path: path.read_bytes() for path in cache.dirs_dir.rglob("*.json")}, directory_entries,
            "dependency validation must not rely on deleting the directory cache",
        )

    def test_replay_is_byte_identical_to_cold_scan(self) -> None:
        case_id = "cache-byte-identical-replay"

        def _test() -> None:
            # Create a 3-file python fixture project
            sub = self.project_dir / "pkg"
            sub.mkdir(parents=True, exist_ok=True)
            f1 = self.project_dir / "a.py"
            f2 = sub / "b.py"
            f3 = sub / "clean.py"

            f1.write_text("fh = open('/tmp/test.txt')\nfh.write('test')\n", encoding="utf-8")
            f2.write_text("import subprocess\nproc = subprocess.Popen(['ls'])\n", encoding="utf-8")
            f3.write_text("def add(x, y):\n    return x + y\n", encoding="utf-8")

            files = [f1, f2, f3]

            sink1 = self.test_root / "sink1.json"
            sink2 = self.test_root / "sink2.json"
            summary1 = self.test_root / "summary1.json"
            summary2 = self.test_root / "summary2.json"

            run_env = dict(os.environ)
            run_env["UBS_PROFILE"] = "1"

            # Pass 1: Cold scan using ubs_core.py_scan
            proc1 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ubs_core.py_scan",
                    "--sink",
                    str(sink1),
                    "--json-out",
                    str(summary1),
                    "--project-dir",
                    str(self.project_dir),
                ],
                input=b"\0".join(str(f).encode() for f in files),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(HELPERS_DIR),
                env=run_env,
                timeout=180,
            )
            self.assertEqual(proc1.returncode, 1, f"Cold scan failed: {proc1.stderr.decode()}")
            sink1_content = sink1.read_bytes()
            summary1_content = summary1.read_bytes()

            # Pass 2: Cached replay
            proc2 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ubs_core.py_scan",
                    "--sink",
                    str(sink2),
                    "--json-out",
                    str(summary2),
                    "--project-dir",
                    str(self.project_dir),
                ],
                input=b"\0".join(str(f).encode() for f in files),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(HELPERS_DIR),
                env=run_env,
                timeout=180,
            )
            self.assertEqual(proc2.returncode, 1, f"Cached scan failed: {proc2.stderr.decode()}")
            sink2_content = sink2.read_bytes()
            summary2_content = summary2.read_bytes()

            # Assert byte identity
            self.assertEqual(
                sink1_content,
                sink2_content,
                "Replayed NDJSON sink is NOT byte-identical to cold scan!",
            )

            # Assert summary JSON findings and counts match
            doc1 = self._decode_json(summary1_content, f"cold stdout={proc1.stdout!r}; stderr={proc1.stderr!r}")
            doc2 = self._decode_json(summary2_content, f"warm stdout={proc2.stdout!r}; stderr={proc2.stderr!r}")
            self.assertEqual(doc1["critical"], doc2["critical"])
            self.assertEqual(doc1["warning"], doc2["warning"])
            self.assertEqual(doc1["info"], doc2["info"])
            self.assertEqual(doc1["findings"], doc2["findings"])

            # Verify pass 2 had 100% cache hit rate in both .profile and .extras.profile
            prof2 = doc2.get("profile") or {}
            extras_prof2 = doc2.get("extras", {}).get("profile", {})
            self.assertEqual(prof2.get("cache_hit_rate"), 1.0)
            self.assertEqual(prof2.get("cache_hits"), 3)
            self.assertEqual(prof2.get("cache_misses"), 0)
            self.assertEqual(extras_prof2.get("cache_hit_rate"), 1.0)

            record_artifact(case_id, {
                "cold_exit": proc1.returncode,
                "cached_exit": proc2.returncode,
                "hit_rate": prof2.get("cache_hit_rate"),
            })

        self._run_with_logging(case_id, _test)

    def test_second_run_is_at_least_5x_faster(self) -> None:
        case_id = "cache-second-run-5x-speedup"

        def _test() -> None:
            # Create a 40-file corpus to give measurable cold scan work
            files = []
            for i in range(40):
                d = self.project_dir / f"pkg_{i % 4}"
                d.mkdir(parents=True, exist_ok=True)
                fp = d / f"module_{i}.py"
                body = "\n".join([
                    f"import os, subprocess, sys",
                    f"def run_{i}(cmd):",
                    f"    fh = open('/tmp/log_{i}.txt', 'w')",
                    f"    fh.write('log')",
                    f"    eval('1 + ' + str({i}))",
                    f"    return subprocess.Popen(['echo', str({i})])",
                    f"class Handler_{i}:",
                    f"    def __init__(self):",
                    f"        self.f = open('/tmp/f_{i}', 'r')",
                    f"    def process(self, data):",
                    f"        return os.system('echo ' + data)",
                ])
                fp.write_text(body, encoding="utf-8")
                files.append(fp)

            file_list_bytes = b"\0".join(str(f).encode() for f in files)
            sink = self.test_root / "sink.json"

            # Measure cold scan time
            t0 = time.perf_counter()
            proc1 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ubs_core.py_scan",
                    "--sink",
                    str(sink),
                    "--project-dir",
                    str(self.project_dir),
                ],
                input=file_list_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(HELPERS_DIR),
                env=dict(os.environ),
                timeout=180,
            )
            cold_elapsed = time.perf_counter() - t0
            self.assertEqual(proc1.returncode, 1)

            # Measure cached scan time
            t1 = time.perf_counter()
            proc2 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ubs_core.py_scan",
                    "--sink",
                    str(sink),
                    "--project-dir",
                    str(self.project_dir),
                ],
                input=file_list_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(HELPERS_DIR),
                env=dict(os.environ),
                timeout=180,
            )
            cached_elapsed = time.perf_counter() - t1
            self.assertEqual(proc2.returncode, 1)

            speedup = cold_elapsed / max(cached_elapsed, 0.001)
            # Retain the actual failed sample too; an older passing artifact
            # must not survive and appear to describe this invocation.
            record_artifact(case_id, {
                "cold_elapsed_s": cold_elapsed,
                "cached_elapsed_s": cached_elapsed,
                "speedup_x": speedup,
                "passed": speedup >= 5.0,
            })
            self.assertGreaterEqual(
                speedup,
                5.0,
                f"Second run was not >= 5x faster (cold: {cold_elapsed:.4f}s, cached: {cached_elapsed:.4f}s, speedup: {speedup:.2f}x)",
            )

        self._run_with_logging(case_id, _test)

    def test_editing_one_file_invalidates_only_that_entry(self) -> None:
        case_id = "cache-single-file-invalidation"

        def _test() -> None:
            f1 = self.project_dir / "f1.py"
            f2 = self.project_dir / "f2.py"
            f3 = self.project_dir / "f3.py"

            f1.write_text("x = 1\n", encoding="utf-8")
            f2.write_text("y = 2\n", encoding="utf-8")
            f3.write_text("z = 3\n", encoding="utf-8")
            files = [f1, f2, f3]

            cache = ScanCache("python", self.project_dir, rulepack_hash="test_rulepack")

            # Run 1: All 3 are misses
            cached1, misses1 = cache.partition_files(files)
            self.assertEqual(len(cached1), 0)
            self.assertEqual(len(misses1), 3)

            # Store findings for all 3
            cache.store_scanned_files(files, {
                str(f1): [{"rule": "test.rule", "path": str(f1), "line": 1, "severity": "info"}],
                str(f2): [],
                str(f3): [],
            })

            # Run 2: All 3 are hits
            cached2, misses2 = cache.partition_files(files)
            self.assertEqual(len(cached2), 3)
            self.assertEqual(len(misses2), 0)

            # Now edit f2 only! Ensure mtime changes
            time.sleep(0.01)
            f2.write_text("y = 200  # modified\n", encoding="utf-8")

            # Run 3: Exactly f2 is a miss; f1 and f3 are hits!
            cached3, misses3 = cache.partition_files(files)
            self.assertEqual(len(cached3), 2)
            self.assertIn(f1, cached3)
            self.assertIn(f3, cached3)
            self.assertEqual(misses3, [f2])
            self.assertEqual(cache.stats["hits"], 2)
            self.assertEqual(cache.stats["misses"], 1)

            record_artifact(case_id, {
                "hits_after_edit": cache.stats["hits"],
                "misses_after_edit": cache.stats["misses"],
                "invalidated_file": str(f2),
            })

        self._run_with_logging(case_id, _test)

    def test_rulepack_change_invalidates_everything(self) -> None:
        case_id = "cache-rulepack-invalidation"

        def _test() -> None:
            f1 = self.project_dir / "app.py"
            f1.write_text("print('hello')\n", encoding="utf-8")
            files = [f1]

            # Cache with rulepack version 1
            cache_v1 = ScanCache("python", self.project_dir, rulepack_hash="rulepack_v1")
            cached1, misses1 = cache_v1.partition_files(files)
            self.assertEqual(len(misses1), 1)
            cache_v1.store_scanned_files(files, {str(f1): []})

            # Replay on rulepack v1: hit!
            cached_v1_again, misses_v1_again = cache_v1.partition_files(files)
            self.assertEqual(len(cached_v1_again), 1)
            self.assertEqual(len(misses_v1_again), 0)

            # Change rulepack to version 2
            cache_v2 = ScanCache("python", self.project_dir, rulepack_hash="rulepack_v2")
            self.assertNotEqual(cache_v1.cache_key, cache_v2.cache_key)

            # Rulepack change invalidates everything -> miss!
            cached2, misses2 = cache_v2.partition_files(files)
            self.assertEqual(len(cached2), 0)
            self.assertEqual(len(misses2), 1)

            record_artifact(case_id, {
                "v1_key": cache_v1.cache_key,
                "v2_key": cache_v2.cache_key,
                "v2_misses": len(misses2),
            })

        self._run_with_logging(case_id, _test)

    def test_concurrent_scans_do_not_corrupt_cache(self) -> None:
        case_id = "cache-concurrency-safety"

        def _test() -> None:
            # 5 files scanned concurrently by 8 worker threads
            files = []
            for i in range(5):
                fp = self.project_dir / f"worker_{i}.py"
                fp.write_text(f"def task_{i}(): pass\n", encoding="utf-8")
                files.append(fp)

            def worker_scan(worker_id: int) -> int:
                cache = ScanCache("python", self.project_dir, rulepack_hash="concurrent_pack")
                cached, misses = cache.partition_files(files)
                if misses:
                    findings = {str(f): [{"rule": "test.rule", "path": str(f), "worker": worker_id}] for f in misses}
                    cache.store_scanned_files(misses, findings)
                return len(cached) + len(misses)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(worker_scan, i) for i in range(16)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            self.assertEqual(len(results), 16)
            for r in results:
                self.assertEqual(r, 5)

            # Verify that all cached files are valid JSON and not corrupt
            stats = doctor_stats(self.cache_dir)
            self.assertGreater(stats["entries_count"], 0)
            for p in self.cache_dir.rglob("*.json"):
                if p.name.startswith(".tmp"):
                    continue
                data = self._decode_json(p.read_text(encoding="utf-8"), f"concurrent cache entry {p}")
                self.assertIsInstance(data, dict)

            record_artifact(case_id, {
                "workers_completed": len(results),
                "cache_entries": stats["entries_count"],
            })

        self._run_with_logging(case_id, _test)

    def test_no_cache_controls(self) -> None:
        case_id = "cache-controls-no-cache"

        def _test() -> None:
            f1 = self.project_dir / "sample.py"
            f1.write_text("x = 10\n", encoding="utf-8")
            files = [f1]

            # 1. Normal cache
            cache_normal = ScanCache("python", self.project_dir)
            self.assertTrue(cache_normal.enabled)

            # 2. UBS_NO_CACHE=1
            os.environ[ENV_NO_CACHE] = "1"
            self.assertTrue(is_cache_disabled())
            cache_disabled = ScanCache("python", self.project_dir)
            self.assertFalse(cache_disabled.enabled)

            cached, misses = cache_disabled.partition_files(files)
            self.assertEqual(len(cached), 0)
            self.assertEqual(len(misses), 1)

            # Storing when disabled is a no-op
            cache_disabled.store_scanned_files(files, {str(f1): []})
            self.assertFalse(cache_disabled.cache_root.exists())

            record_artifact(case_id, {"disabled_respected": True})

        self._run_with_logging(case_id, _test)

    def test_doctor_stats_and_prune_cache(self) -> None:
        case_id = "cache-doctor-and-prune"

        def _test() -> None:
            # Populate cache with dummy entries
            cache = ScanCache("python", self.project_dir, rulepack_hash="doc_pack")
            f1 = self.project_dir / "sample1.py"
            f1.write_text("a = 1\n", encoding="utf-8")
            cache.store_scanned_files([f1], {str(f1): []})

            stats_before = doctor_stats(self.cache_dir)
            self.assertGreater(stats_before["entries_count"], 0)
            self.assertGreater(stats_before["size_bytes"], 0)
            self.assertEqual(stats_before["status"], "ok")

            # Prune all entries
            freed, count = prune_cache(self.cache_dir, prune_all=True)
            self.assertGreater(freed, 0)
            self.assertGreater(count, 0)

            stats_after = doctor_stats(self.cache_dir)
            self.assertEqual(stats_after["entries_count"], 0)
            self.assertEqual(stats_after["size_bytes"], 0)
            self.assertEqual(stats_after["status"], "empty")

            record_artifact(case_id, {
                "pruned_bytes": freed,
                "pruned_entries": count,
            })

        self._run_with_logging(case_id, _test)

    def test_meta_runner_cache_integration(self) -> None:
        case_id = "cache-meta-runner-integration"

        def _test() -> None:
            # Create a clean python project fixture
            f1 = self.project_dir / "app.py"
            f2 = self.project_dir / "utils.py"
            f1.write_text("def run():\n    return 42\n", encoding="utf-8")
            f2.write_text("def helper():\n    return 100\n", encoding="utf-8")

            ubs_bin = str(REPO_ROOT / "ubs")
            env = dict(os.environ)
            env["UBS_CACHE_DIR"] = str(self.cache_dir)
            env["UBS_PROFILE"] = "1"
            env["NO_COLOR"] = "1"

            # Pass 1: Cold run via ubs CLI
            proc1 = subprocess.run(
                [ubs_bin, str(self.project_dir), "--format=json", "--only=python"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            self.assertEqual(proc1.returncode, 0, f"Cold scan failed: {proc1.stderr}")
            data1 = self._decode_json(proc1.stdout, f"cold stderr={proc1.stderr}")
            prof1 = data1.get("profile") or {}
            self.assertEqual(prof1.get("cache_hits"), 0)
            self.assertEqual(prof1.get("cache_misses"), 2)
            self.assertEqual(prof1.get("cache_hit_rate"), 0.0)

            # Pass 2: Warm replay via ubs CLI
            proc2 = subprocess.run(
                [ubs_bin, str(self.project_dir), "--format=json", "--only=python"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            self.assertEqual(proc2.returncode, 0, f"Cached scan failed: {proc2.stderr}")
            data2 = self._decode_json(proc2.stdout, f"warm stderr={proc2.stderr}")
            prof2 = data2.get("profile") or {}
            extras_prof2 = data2.get("extras", {}).get("profile", {})
            self.assertEqual(prof2.get("cache_hits"), 2)
            self.assertEqual(prof2.get("cache_misses"), 0)
            self.assertEqual(prof2.get("cache_hit_rate"), 1.0)
            self.assertEqual(extras_prof2.get("cache_hit_rate"), 1.0)

            # Pass 3: Text summary includes cache hit rate
            proc3 = subprocess.run(
                [ubs_bin, str(self.project_dir), "--only=python"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            self.assertEqual(proc3.returncode, 0)
            self.assertIn("; cache 100% hits (2/2)", proc3.stdout)

            # Pass 4: --no-cache CLI flag disables cache
            proc4 = subprocess.run(
                [ubs_bin, str(self.project_dir), "--format=json", "--only=python", "--no-cache"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            self.assertEqual(proc4.returncode, 0)
            data4 = self._decode_json(proc4.stdout, f"cache disabled stderr={proc4.stderr}")
            prof4 = data4.get("profile") or {}
            self.assertEqual(prof4.get("cache_hits", 0), 0)

            # Pass 5: Doctor cache check and prune
            proc5 = subprocess.run(
                [ubs_bin, "doctor", "--prune-cache"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
            )
            self.assertEqual(proc5.returncode, 0)
            self.assertIn("Pruned", proc5.stdout)

            record_artifact(case_id, {
                "cold_misses": prof1.get("cache_misses"),
                "cached_hits": prof2.get("cache_hits"),
                "cached_hit_rate": prof2.get("cache_hit_rate"),
            })

        self._run_with_logging(case_id, _test)


if __name__ == "__main__":
    unittest.main()
