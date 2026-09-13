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

    def test_helper_source_upgrades_invalidate_real_scanner_cache(self) -> None:
        helpers, run_env = self._copy_helpers()
        sources = {
            "unsafe.py": "value = eval(input())\n",
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
            doc1 = json.loads(summary1_content)
            doc2 = json.loads(summary2_content)
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
            )
            cached_elapsed = time.perf_counter() - t1
            self.assertEqual(proc2.returncode, 1)

            speedup = cold_elapsed / max(cached_elapsed, 0.001)
            self.assertGreaterEqual(
                speedup,
                5.0,
                f"Second run was not >= 5x faster (cold: {cold_elapsed:.4f}s, cached: {cached_elapsed:.4f}s, speedup: {speedup:.2f}x)",
            )

            record_artifact(case_id, {
                "cold_elapsed_s": cold_elapsed,
                "cached_elapsed_s": cached_elapsed,
                "speedup_x": speedup,
            })

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
                data = json.loads(p.read_text(encoding="utf-8"))
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
            )
            self.assertEqual(proc1.returncode, 0, f"Cold scan failed: {proc1.stderr}")
            data1 = json.loads(proc1.stdout)
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
            )
            self.assertEqual(proc2.returncode, 0, f"Cached scan failed: {proc2.stderr}")
            data2 = json.loads(proc2.stdout)
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
            )
            self.assertEqual(proc4.returncode, 0)
            data4 = json.loads(proc4.stdout)
            prof4 = data4.get("profile") or {}
            self.assertEqual(prof4.get("cache_hits", 0), 0)

            # Pass 5: Doctor cache check and prune
            proc5 = subprocess.run(
                [ubs_bin, "doctor", "--prune-cache"],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
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
