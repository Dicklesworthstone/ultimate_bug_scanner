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
import errno
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
from unittest.mock import patch

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
        raw_name = os.fsdecode(b"raw-\xff.py")
        if os.name == "posix":
            names.append(raw_name)
        for name in list(names):
            try:
                (nested / name).write_text("VALUE = 1\n", encoding="utf-8")
            except OSError as exc:
                # APFS and other Unicode-only filesystems refuse non-UTF-8
                # names (EILSEQ); the byte name is only checked where it exists.
                if exc.errno != errno.EILSEQ or name != raw_name:
                    raise
                names.remove(name)
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
        if raw_name in names:
            self._git("config", "core.quotePath", "false")
            (nested / raw_name).write_text("VALUE = 4\n", encoding="utf-8")
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

    def test_yaml_policy_content_change_invalidates_a_cached_clean_scan(self) -> None:
        source = self.project_dir / "entry.sh"
        source.write_text("#!/bin/sh\ncurl https://example.invalid/script\n", encoding="utf-8")
        rules = self.test_root / "policies"
        rules.mkdir()
        policy = rules / "policy.yaml"
        policy.write_text("id: project-policy\nrule:\n  pattern: wget $$$A\n", encoding="utf-8")
        first = ScanCache("bash", self.project_dir, custom_rules=str(rules))
        first.store_scanned_files([source], {str(source): []})
        warm = ScanCache("bash", self.project_dir, custom_rules=str(rules))
        cached, misses = warm.partition_files([source])
        self.assertEqual(cached, {source: []})
        self.assertEqual(misses, [])
        # Keep the filename, ID and source unchanged. Only the requested
        # policy changed: replaying the old clean result would lose coverage.
        policy.write_text("id: project-policy\nrule:\n  pattern: curl $$$A\n", encoding="utf-8")
        changed = ScanCache("bash", self.project_dir, custom_rules=str(rules))
        cached, misses = changed.partition_files([source])
        self.assertEqual(cached, {})
        self.assertEqual(misses, [source])

    def _decode_json(self, payload: str, context: str) -> Any:
        try:
            return json.loads(payload)
        except ValueError as exc:
            self.fail(f"Invalid JSON: {exc}\n{context}\nJSON payload:\n{payload}")

    def _assert_js_warning_mode_cache_order(self, first_strict: bool, case_id: str) -> None:
        from ubs_core.js_rules import generate

        # Freeze helper sources so simultaneous development cannot invalidate
        # the cache between the cold scan and the replay being checked.
        helpers, run_env = self._copy_helpers()
        rules = self.test_root / "js-rules"
        generate(rules)
        source = self.project_dir / "async.js"
        source.write_text(
            "async function run(tasks) { await Promise.all(tasks); }\n",
            encoding="utf-8",
        )
        before = source.read_bytes()
        evidence: list[dict[str, Any]] = []

        def scan(label: str, strict: bool, *, uncached: bool = False):
            sink = self.test_root / f"{label}.ndjson"
            summary = self.test_root / f"{label}.json"
            env = dict(run_env)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            if uncached:
                env[ENV_NO_CACHE] = "1"
            command = [
                sys.executable, "-m", "ubs_core.js_scan", "--sink", str(sink),
                "--json-out", str(summary), "--project-dir", str(self.project_dir),
                "--ast-rule-dir", str(rules),
            ]
            if strict:
                command.append("--fail-on-warning")
            proc = subprocess.run(
                command, input=str(source) + "\0", capture_output=True, text=True,
                cwd=helpers, env=env, timeout=120,
            )
            context = f"{label}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            entry = {"label": label, "strict": strict, "uncached": uncached,
                     "exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
            evidence.append(entry)
            self.assertIn(proc.returncode, (0, 1), context)
            self.assertTrue(summary.is_file(), context)
            doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
            entry["summary"] = doc
            context += "\nsummary:\n" + json.dumps(doc, indent=2)
            self.assertEqual(doc["status"], "ok", context)
            self.assertEqual(doc["files"], 1, context)
            self.assertEqual(proc.returncode, int(strict), context)
            self.assertEqual((doc["critical"], doc["warning"], doc["info"]),
                             (0, int(strict), 2 - int(strict)), context)
            self.assertEqual(
                {(rec["rule"], rec["severity"]) for rec in doc["findings"]},
                {("js.async.promiseall-no-try", "warning" if strict else "info"),
                 ("js.async.await-no-try", "info")}, context,
            )
            records = [self._decode_json(line, context)
                       for line in sink.read_text(encoding="utf-8").splitlines() if line.strip()]
            # ast-grep can report different rules in either order. Compare
            # complete records without making its scheduling part of parity.
            canonical = lambda recs: sorted(json.dumps(rec, sort_keys=True) for rec in recs)
            self.assertEqual(canonical(records), canonical(doc["findings"]), context)
            self.assertEqual(source.read_bytes(), before, "only scan mode may change")
            return proc.returncode, canonical(records), doc["profile"], context

        def compare(actual, expected, hits: int) -> None:
            context = actual[3]
            self.assertEqual(actual[:2], expected[:2], context)
            self.assertEqual(actual[2]["cache_hits"], hits, context)
            self.assertEqual(actual[2]["cache_misses"], 1 - hits, context)

        try:
            oracles = {strict: scan(f"oracle-{strict}", strict, uncached=True)
                       for strict in (False, True)}
            second_strict = not first_strict
            compare(scan("first-cold", first_strict), oracles[first_strict], 0)
            compare(scan("first-warm", first_strict), oracles[first_strict], 1)
            compare(scan("changed-mode", second_strict), oracles[second_strict], 0)
            compare(scan("changed-mode-warm", second_strict), oracles[second_strict], 1)
            compare(scan("original-mode-warm", first_strict), oracles[first_strict], 1)
        finally:
            record_artifact(case_id, {"scans": evidence})

    @unittest.skipUnless(shutil.which("ast-grep"), "requires real ast-grep")
    def test_js_strict_scan_cannot_replay_non_strict_async_severities(self) -> None:
        case_id = "cache-js-loose-to-strict"
        self._run_with_logging(
            case_id, lambda: self._assert_js_warning_mode_cache_order(False, case_id),
        )

    @unittest.skipUnless(shutil.which("ast-grep"), "requires real ast-grep")
    def test_js_non_strict_scan_cannot_replay_strict_async_severities(self) -> None:
        case_id = "cache-js-strict-to-loose"
        self._run_with_logging(
            case_id, lambda: self._assert_js_warning_mode_cache_order(True, case_id),
        )

    def _js_pattern_selection(
        self, helpers: Path, run_env: dict[str, str], files: list[Path],
        hits: int, label: str, skip: str = "",
    ) -> list[dict]:
        def scan(uncached: bool):
            sink = self.test_root / "js-patterns.ndjson"
            summary = self.test_root / "js-patterns.json"
            report = self.test_root / "js-patterns.txt"
            env = dict(run_env)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            if uncached:
                env[ENV_NO_CACHE] = "1"
            proc = subprocess.run(
                [sys.executable, "-m", "ubs_core.js_scan", "--sink", str(sink),
                 "--json-out", str(summary), "--text-out", str(report),
                 "--project-dir", str(self.project_dir), "--fail-on-warning", "--skip", skip],
                input="\0".join(map(str, files)), capture_output=True, text=True,
                cwd=helpers, env=env, timeout=120,
            )
            context = f"{label} uncached={uncached}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            self.assertIn(proc.returncode, (0, 1), context)
            self.assertTrue(summary.is_file(), context)
            doc = self._decode_json(summary.read_text(encoding="utf-8"), context)
            context += "\nsummary:\n" + json.dumps(doc, indent=2)
            self.assertEqual(doc["status"], "ok", context)
            self.assertEqual(doc["files"], len(files), context)
            self.assertEqual(proc.returncode, int(doc["critical"] + doc["warning"] > 0), context)
            for path in (sink, summary, report):
                self.assertNotIn("_ubs_js_pattern", path.read_text(encoding="utf-8"), context)
            records = doc["findings"]
            for severity in ("critical", "warning", "info"):
                self.assertEqual(doc[severity], sum(rec["severity"] == severity for rec in records), context)
            self.assertEqual(
                [self._decode_json(line, context) for line in sink.read_text(encoding="utf-8").splitlines()],
                records, context,
            )
            return proc.returncode, records, doc["profile"], context

        actual = scan(False)
        expected = scan(True)
        self.assertEqual(actual[:2], expected[:2], actual[3] + "\nUncached oracle:\n" + expected[3])
        self.assertEqual(actual[2]["cache_hits"], hits, actual[3])
        self.assertEqual(actual[2]["cache_misses"], len(files) - hits, actual[3])
        return actual[1]

    def test_js_pattern_thresholds_reconcile_selected_cached_matches(self) -> None:
        def check_scenario() -> None:
            helpers, env = self._copy_helpers()
            a, b, c = [self.project_dir / name for name in ("a.js", "b.js", "c.js")]
            lengths = {a: 20, b: 1, c: 30}
            for path, count in lengths.items():
                path.write_text("console.log(value);\n" * count, encoding="utf-8")

            def check(files: list[Path], hits: int, severity: str | None, label: str) -> None:
                records = self._js_pattern_selection(helpers, env, files, hits, label)
                expected = [("js.debug.console", str(path), line, severity)
                            for path in files for line in range(1, lengths[path] + 1)] if severity else []
                self.assertEqual([(r["rule"], r["path"], r["line"], r["severity"]) for r in records],
                                 expected, label)

            check([a], 0, None, "prime silent 20")
            check([b], 0, None, "prime silent 1")
            check([c], 0, "info", "prime info 30")
            check([a, b, c], 3, "warning", "51 cached")
            check([a], 1, None, "20 cached")
            check([a, b], 2, "info", "21 cached")
            check([a, c], 2, "info", "50 cached")
            lengths[c] = 29
            c.write_text("console.log(value);\n" * lengths[c], encoding="utf-8")
            check([a, b, c], 2, "info", "50 partial")
            lengths[c] = 31
            c.write_text("console.log(value);\n" * lengths[c], encoding="utf-8")
            check([a, b, c], 2, "warning", "52 partial")
            check([a, b, c], 3, "warning", "52 warm")
            for hits in (0, 3):
                self.assertEqual(self._js_pattern_selection(helpers, env, [a, b, c], hits,
                                                            "skip debug", "11"), [])

        self._run_with_logging("cache-js-pattern-thresholds", check_scenario)

    def test_js_pattern_gates_and_suppressors_follow_selected_cached_files(self) -> None:
        def check_scenario() -> None:
            helpers, env = self._copy_helpers()
            body, gate, parser = [self.project_dir / name for name in ("body.js", "gate.js", "parser.js")]
            body.write_text("const value = req.body;\n", encoding="utf-8")
            gate.write_text('import express from "express";\n', encoding="utf-8")
            parser.write_text("app.use(express.json());\n", encoding="utf-8")

            def check(files: list[Path], hits: int, warning: bool, label: str) -> None:
                records = self._js_pattern_selection(helpers, env, files, hits, label)
                expected = {(rule, str(body), 1, "warning") for rule in (
                    "js.node.express-body-no-parser", "js.node.express-body-no-validation",
                )} if warning else set()
                self.assertEqual({(r["rule"], r["path"], r["line"], r["severity"]) for r in records},
                                 expected, label)

            check([body], 0, False, "body without framework")
            check([gate], 0, False, "framework without body")
            check([parser], 0, False, "parser without body")
            check([body, gate], 2, True, "cached framework enables warning")
            check([body, gate, parser], 3, False, "cached parser suppresses warning")
            check([body, gate], 2, True, "removing parser restores warning")
            check([body], 1, False, "removing framework removes warning")
            parser.write_text("const ready = true;\n", encoding="utf-8")
            check([body, gate, parser], 2, True, "edited parser restores warning")
            parser.write_text("app.use(express.urlencoded({ extended: true }));\n", encoding="utf-8")
            check([body, gate, parser], 2, False, "edited parser suppresses warning")
            check([body, gate, parser], 3, False, "edited parser warm")

        self._run_with_logging("cache-js-pattern-context", check_scenario)

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

    def test_second_run_skips_the_analysis_work(self) -> None:
        # Issue #125. This used to compare raw wall clock and require >= 5x,
        # which is not reachable: every run pays a fixed ~0.07s of interpreter
        # start-up and module import that caching cannot remove, and the cached
        # run still Merkle-hashes each file. With this corpus the ceiling
        # including start-up is about 3.8x, and even an arbitrarily large
        # corpus only approaches the underlying work ratio (~5.4x here), so the
        # assertion sat within a few percent of a physical limit and failed
        # whenever the host was busy.
        #
        # Measure the thing caching actually changes: scan work, with the
        # start-up floor timed on this host and subtracted. A working cache
        # leaves a large ratio, a broken one leaves ~1.0x, so the threshold has
        # real headroom in between instead of hugging the ceiling.
        case_id = "cache-second-run-skips-analysis"

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

            def run_scan(stdin_bytes: bytes) -> "tuple[float, subprocess.CompletedProcess[bytes]]":
                started = time.perf_counter()
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "ubs_core.py_scan",
                        "--sink",
                        str(sink),
                        "--project-dir",
                        str(self.project_dir),
                    ],
                    input=stdin_bytes,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(HELPERS_DIR),
                    env=dict(os.environ),
                    timeout=180,
                )
                return time.perf_counter() - started, proc

            # Start-up floor: the same process with nothing to scan. Whatever
            # this costs is paid by both runs below and is not work the cache
            # can avoid, so it is excluded from the comparison. Take the best
            # of three so an unlucky sample cannot inflate the floor (which
            # would flatter the result) — the minimum is the honest estimate
            # of unavoidable cost.
            startup_floor = min(run_scan(b"")[0] for _ in range(3))

            cold_elapsed, proc1 = run_scan(file_list_bytes)
            self.assertEqual(proc1.returncode, 1)

            cached_elapsed, proc2 = run_scan(file_list_bytes)
            self.assertEqual(proc2.returncode, 1)

            # Work actually done, with the unavoidable floor removed from both
            # sides. Clamp at a small positive value: a cached run can land at
            # or below the measured floor, which means it did no measurable
            # work — the best possible outcome, not a division error.
            cold_work = max(cold_elapsed - startup_floor, 1e-4)
            cached_work = max(cached_elapsed - startup_floor, 1e-4)
            speedup = cold_work / cached_work

            # A working cache leaves a large ratio; a broken one leaves ~1.0x.
            # 3.0 sits with headroom on both sides rather than against the
            # ceiling, so a genuine regression still fails loudly while a busy
            # host does not.
            threshold = 3.0
            # Retain the actual failed sample too; an older passing artifact
            # must not survive and appear to describe this invocation.
            record_artifact(case_id, {
                "startup_floor_s": startup_floor,
                "cold_elapsed_s": cold_elapsed,
                "cached_elapsed_s": cached_elapsed,
                "cold_work_s": cold_work,
                "cached_work_s": cached_work,
                "speedup_x": speedup,
                "threshold_x": threshold,
                "passed": speedup >= threshold,
            })
            # The cached run must also not be slower overall, which no amount
            # of floor arithmetic can excuse.
            self.assertLess(
                cached_elapsed,
                cold_elapsed,
                f"cached run was not faster at all (cold: {cold_elapsed:.4f}s, cached: {cached_elapsed:.4f}s)",
            )
            self.assertGreaterEqual(
                speedup,
                threshold,
                f"cache did not skip the analysis work: {speedup:.2f}x < {threshold}x "
                f"(cold {cold_elapsed:.4f}s, cached {cached_elapsed:.4f}s, "
                f"start-up floor {startup_floor:.4f}s -> work {cold_work:.4f}s vs {cached_work:.4f}s)",
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

    def _rust_meta_scan(self, *extra: str) -> tuple[list[tuple[str, str, int]], dict]:
        proc = subprocess.run(
            [str(REPO_ROOT / "ubs"), "--ci", "--no-auto-update", "--only=rust",
             "--format=json", *extra, str(self.project_dir)],
            capture_output=True, text=True, cwd=self.test_root, timeout=300,
            env={**os.environ, "UBS_NO_AUTO_UPDATE": "1"},
        )
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        doc = json.loads(proc.stdout)
        findings = sorted((f["rule_id"], Path(f["file"]).name, f["line"]) for f in doc["findings"])
        return findings, doc["totals"]

    @unittest.skipUnless(shutil.which("ast-grep"), "the duplicated guard pass needs real ast-grep")
    def test_rust_partial_cache_matches_uncached_scan(self) -> None:
        """GH #150: a scan with some cache hits must equal a cold scan."""
        case_id = "cache-rust-partial-selection"

        def _test() -> None:
            (self.project_dir / "a.rs").write_text(
                "fn go(v: Option<u32>) -> u32 {\n    if let Some(x) = v {\n        return x;\n    }\n"
                "    v.unwrap()\n}\n", encoding="utf-8")
            (self.project_dir / "b.rs").write_text("fn other() {}\n", encoding="utf-8")
            for i in range(1, 21):
                (self.project_dir / f"m{i}.rs").write_text(f"// TODO: item {i}\nfn f{i}() {{}}\n",
                                                           encoding="utf-8")
            self._rust_meta_scan()  # prime the cache
            # One changed file and one new marker: 21 markers cross the > 20
            # tech-debt threshold only when cached files are counted too.
            (self.project_dir / "b.rs").write_text("fn other() { let n = 2; }\n", encoding="utf-8")
            (self.project_dir / "m21.rs").write_text("// TODO: one more\nfn g() {}\n", encoding="utf-8")
            partial = self._rust_meta_scan()
            warm = self._rust_meta_scan()
            cold = self._rust_meta_scan("--no-cache")
            guarded = [f for f in cold[0] if f[0] == "rust.ownership.guarded-later-unwrap"]
            self.assertEqual(guarded, [("rust.ownership.guarded-later-unwrap", "a.rs", 5)], cold)
            debt = [f for f in cold[0] if f[0] == "rust.code-quality.tech-debt"]
            self.assertEqual(len(debt), 1, cold)
            self.assertGreaterEqual(cold[1]["warning"], 2, cold)
            self.assertEqual(partial, cold)
            self.assertEqual(warm, cold)

        self._run_with_logging(case_id, _test)


class PythonPatternCountExportTests(unittest.TestCase):
    """GH #191: unthresholded pattern facts are independent of report samples."""

    PARAM_RULE = "py.functions.high-param-count"
    REGEX_RULE = "py.regex.nested-quantifiers"

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="python-pattern-counts-", dir=artifacts))
        self.project = self.root / "project"
        self.project.mkdir()
        self.run_number = 0
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("UBS_", "XDG_"))}
        self.env.update({
            "PYTHONPATH": str(HELPERS_DIR),
            "PYTHONDONTWRITEBYTECODE": "1",
            "UBS_NO_AUTO_UPDATE": "1",
            "UBS_KEEP_TEMP": "1",
            "UBS_CACHE_DIR": str(self.root / "cache"),
            "ENABLE_UV_TOOLS": "0",
            "TMPDIR": str(self.root),
        })

    def run(self, result=None):
        print(f"[{self.id()}] RUN", flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} "
              f"({time.monotonic() - started:.3f}s)", flush=True)
        return result

    def decode_json(self, text: str, context: str):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self.fail(f"{context}: invalid JSON: {exc}\n{text[:2000]}")

    @staticmethod
    def function(name: str) -> str:
        return (f"def {name}(one, two, three, four, five, six, seven):\n"
                "    return one\n")

    def source(self, name: str, text: str) -> Path:
        path = self.project / name
        path.write_text(text, encoding="utf-8")
        return path

    def scan(self, files: list[Path], *, export: bool = True,
             no_cache: bool = False, fail_on_warning: bool = False,
             skip: str = "", expected_hits: int | None = None,
             complete: bool = True):
        self.run_number += 1
        output = self.root / f"run-{self.run_number:02d}"
        output.mkdir()
        sink = output / "findings.ndjson"
        summary = output / "summary.json"
        report = output / "report.txt"
        counts = output / "pattern-counts.json"
        args = [sys.executable, "-B", "-m", "ubs_core.py_scan",
                "--sink", str(sink), "--json-out", str(summary),
                "--text-out", str(report), "--project-dir", str(self.project),
                "--skip", skip, "--jobs", "1"]
        if export:
            args.extend(["--pattern-counts-out", str(counts)])
        if fail_on_warning:
            args.append("--fail-on-warning")
        env = {**self.env, "UBS_NO_CACHE": str(int(no_cache)),
               "UBS_CACHE_FILE": str(output / "cache.json"),
               "UBS_PREFILTER_FILE": str(output / "prefilter.json")}
        proc = subprocess.run(
            args, input=b"".join(os.fsencode(path) + b"\0" for path in files),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root,
            env=env, timeout=180,
        )
        (output / "stdout.log").write_bytes(proc.stdout)
        (output / "stderr.log").write_bytes(proc.stderr)
        context = (f"run {self.run_number}: exit={proc.returncode}\n"
                   f"stdout:\n{proc.stdout.decode(errors='replace')}\n"
                   f"stderr:\n{proc.stderr.decode(errors='replace')}")
        self.assertIn(proc.returncode, (0, 1) if complete else (2,), context)
        self.assertEqual(proc.stdout, b"", context)
        doc = self.decode_json(summary.read_text(), context)
        records = [self.decode_json(line, context) for line in sink.read_text().splitlines()]
        self.assertEqual(doc["status"], "ok" if complete else "partial", context)
        self.assertEqual(doc["files"], len(files), context)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], sum(row["severity"] == severity for row in records), context)
        expected_exit = int(doc["critical"] > 0 or (fail_on_warning and doc["warning"] > 0))
        self.assertEqual(proc.returncode, expected_exit if complete else 2, context)
        if expected_hits is not None:
            profile = doc["extras"]["profile"]
            self.assertEqual(profile["cache_hits"], expected_hits, context)
            self.assertEqual(profile["cache_misses"], len(files) - expected_hits, context)
        for row in records:
            self.assertFalse(any(key.startswith("_ubs_") for key in row), context)
        if export:
            self.assertTrue(counts.is_file(), context)
            raw = self.decode_json(counts.read_text(), context)
            self.assertEqual(raw["schema"], "ubs.python-pattern-counts/1", context)
            self.assertEqual(raw["language"], "python", context)
            self.assertEqual(raw["complete"], complete, context)
            self.assertEqual(raw["status"], doc["status"], context)
            self.assertEqual(raw["count_unit"], "distinct-match-start-lines", context)
            self.assertEqual(raw["count_stage"],
                             "after-source-suppression-before-context-and-thresholds", context)
            self.assertEqual(raw["zero_counts"],
                             "implicit-for-listed-files-and-rules-when-complete", context)
            self.assertEqual(raw["files"], [{"file": str(path)} for path in sorted(set(files))], context)
            self.assertTrue(all(row["count"] > 0 for row in raw["counts"]), context)
            self.assertEqual(raw["counts"], sorted(raw["counts"], key=lambda row: (row["file"], row["rule_id"])))
            if complete:
                self.assertEqual(raw["errors"], [], context)
            else:
                self.assertTrue(raw["errors"], context)
        else:
            self.assertFalse(counts.exists(), context)
            raw = None
        return {"exit": proc.returncode, "summary": doc, "records": records,
                "text": report.read_text(), "raw": raw, "context": context}

    @staticmethod
    def public_result(result):
        summary = result["summary"]
        return (result["exit"], result["records"],
                {key: summary[key] for key in ("critical", "warning", "info", "findings", "report")})

    def rule(self, result, rule_id: str):
        found = [row for row in result["raw"]["rules"] if row["rule_id"] == rule_id]
        self.assertEqual(len(found), 1, result["context"])
        return found[0]

    def counts_for(self, result, rule_id: str):
        return {row["file"]: row["count"] for row in result["raw"]["counts"]
                if row["rule_id"] == rule_id}

    def assert_rule(self, result, rule_id: str, counts: dict[Path, int], severity: str | None):
        row = self.rule(result, rule_id)
        self.assertEqual(row["count"], sum(counts.values()), result["context"])
        self.assertEqual(self.counts_for(result, rule_id),
                         {str(path): count for path, count in counts.items() if count}, result["context"])
        self.assertEqual(row["threshold_severity"], severity, result["context"])
        self.assertEqual(row["reported_severity"], severity, result["context"])
        self.assertEqual(row["thresholds"], [{"min_count_exclusive": 3, "severity": "warning"}],
                         result["context"])
        self.assertEqual(row["context"], {"scope": "selected-input-raw-text", "gate": None,
                                          "suppress_when": None, "eligible": True}, result["context"])

    def test_one_three_four_matches_keep_findings_samples_and_exit_policy(self) -> None:
        for count in (1, 3, 4):
            with self.subTest(matches=count):
                source = self.source(f"matches-{count}.py", "import re\n" + "".join(
                    f'REGEX{index} = re.compile(r"(a+)+$")\n' + self.function(f"f{index}")
                    for index in range(count)))
                # A normal scan primes the cache without the export option.
                default = self.scan([source], export=False, fail_on_warning=True, expected_hits=0)
                warm = self.scan([source], fail_on_warning=True, expected_hits=1)
                cold = self.scan([source], no_cache=True, fail_on_warning=True, expected_hits=0)
                self.assertEqual(self.public_result(default), self.public_result(warm))
                self.assertEqual(self.public_result(default), self.public_result(cold))
                self.assertEqual(warm["raw"], cold["raw"])
                for result in (warm, cold):
                    for rule in (self.PARAM_RULE, self.REGEX_RULE):
                        self.assert_rule(result, rule, {source: count}, "warning" if count > 3 else None)
                        findings = [row for row in result["summary"]["findings"] if row["rule"] == rule]
                        if count > 3:
                            self.assertEqual(len(findings), 1)
                            self.assertEqual(findings[0]["count"], count)
                            self.assertEqual(len(findings[0]["samples"]), 3)
                        else:
                            self.assertEqual(findings, [])
                    self.assertEqual(result["summary"]["warning"], 2 * count if count > 3 else 0)
                    self.assertEqual(result["exit"], int(count > 3))
                # Warning policy stays opt-in, independently of raw counts.
                permissive = self.scan([source], expected_hits=1)
                self.assertEqual(permissive["exit"], 0)
                self.assertEqual(permissive["raw"], warm["raw"])

    def test_separate_concatenated_selected_and_empty_padded_sources(self) -> None:
        files, sources = [], []
        summed = {self.PARAM_RULE: 0, self.REGEX_RULE: 0}
        for index, letter in enumerate("abcdefghijklmn"):
            source = (f'import re\nREGEX = re.compile(r"({letter}+)+$")\n' if index < 4 else "")
            source += self.function(letter)
            path = self.source(f"part {letter}.py", source)
            files.append(path)
            sources.append(source)
            result = self.scan([path], expected_hits=0)
            self.assert_rule(result, self.PARAM_RULE, {path: 1}, None)
            self.assert_rule(result, self.REGEX_RULE, {path: int(index < 4)}, None)
            self.assertEqual(result["summary"]["warning"], 0)
            for rule in summed:
                summed[rule] += self.rule(result, rule)["count"]

        batch = self.scan(files, expected_hits=14)
        self.assert_rule(batch, self.PARAM_RULE, dict.fromkeys(files, 1), "warning")
        self.assert_rule(batch, self.REGEX_RULE, dict.fromkeys(files[:4], 1), "warning")
        self.assertEqual(batch["summary"]["warning"], 18)
        combined_path = self.source("combined.py", "\n".join(sources))
        combined = self.scan([combined_path], expected_hits=0)
        self.assert_rule(combined, self.PARAM_RULE, {combined_path: 14}, "warning")
        self.assert_rule(combined, self.REGEX_RULE, {combined_path: 4}, "warning")
        self.assertEqual(combined["summary"]["warning"], 18)
        for rule, count in summed.items():
            self.assertEqual(self.rule(batch, rule)["count"], count)
            self.assertEqual(self.rule(combined, rule)["count"], count)
            for result in (batch, combined):
                finding = next(row for row in result["summary"]["findings"] if row["rule"] == rule)
                self.assertEqual(len(finding["samples"]), 3)

        for selected in (files[:3], list(reversed(files[:4])), [files[-1]]):
            with self.subTest(selected=[path.name for path in selected]):
                result = self.scan(selected, expected_hits=len(selected))
                severity = "warning" if len(selected) > 3 else None
                self.assert_rule(result, self.PARAM_RULE, dict.fromkeys(selected, 1), severity)
                regex_files = [path for path in selected if path in files[:4]]
                self.assert_rule(result, self.REGEX_RULE, dict.fromkeys(regex_files, 1),
                                 "warning" if len(regex_files) > 3 else None)
                self.assertTrue(all(Path(row["file"]) in selected for row in result["raw"]["counts"]))

        empty = [self.source(f"empty-{index}.py", "") for index in range(13)]
        padded = self.scan([files[0], *empty], expected_hits=1)
        warm = self.scan([files[0], *empty], expected_hits=14)
        self.assertEqual(padded["raw"], warm["raw"])
        for rule in summed:
            self.assert_rule(padded, rule, {files[0]: 1}, None)
        self.assertEqual(padded["summary"]["warning"], 0)
        zero = self.scan(empty, expected_hits=13)
        self.assertEqual(zero["raw"]["counts"], [])
        self.assertTrue(zero["raw"]["rules"])
        self.assertTrue(all(row["count"] == 0 for row in zero["raw"]["rules"]))

    def test_distinct_matching_lines_are_not_regex_occurrences(self) -> None:
        for count in (1, 3, 4):
            source = self.source(f"double-{count}.py", "import re\n" + "".join(
                f'REGEX{index} = (re.compile(r"(a+)+$"), re.compile(r"(b+)+$"))\n'
                for index in range(count)))
            result = self.scan([source], expected_hits=0)
            self.assert_rule(result, self.REGEX_RULE, {source: count}, "warning" if count > 3 else None)
            self.assertEqual(result["summary"]["warning"], count if count > 3 else 0)
            warm = self.scan([source], expected_hits=1)
            self.assertEqual(result["raw"], warm["raw"])

    def test_source_suppressions_apply_before_raw_counts_and_survive_cache_edits(self) -> None:
        source = self.source("suppressed.py", "import re\n" +
            "def bare(one, two, three, four, five, six, seven):  # ubs:ignore\n    return one\n" +
            f"# ubs:ignore[{self.PARAM_RULE}]\n" + self.function("scoped") +
            f"# ubs:ignore[{self.REGEX_RULE}]\n" + self.function("unrelated") +
            'def literal(one, two, three, four, five, six, seven):\n    return "# ubs:ignore"\n' +
            'REGEX1 = re.compile(r"(a+)+$")  # ubs:ignore\n' +
            f"# ubs:ignore[{self.REGEX_RULE}]\n" + 'REGEX2 = re.compile(r"(b+)+$")\n' +
            f'REGEX3 = re.compile(r"(c+)+$")  # ubs:ignore[{self.PARAM_RULE}]\n' +
            'REGEX4 = re.compile(r"(d+)+$"); note = "# ubs:ignore"\n' +
            'MULTILINE = re.compile(\n    r"(e+)+$"\n' +
            f")  # ubs:ignore[{self.REGEX_RULE}]\n" +
            'def multiline(one, two, three, four, five, six,\n' +
            f"              seven):  # ubs:ignore[{self.PARAM_RULE}]\n    return one\n")
        cold = self.scan([source], expected_hits=0)
        warm = self.scan([source], expected_hits=1)
        disabled = self.scan([source], no_cache=True, expected_hits=0)
        for result in (cold, warm, disabled):
            for rule in (self.PARAM_RULE, self.REGEX_RULE):
                self.assert_rule(result, rule, {source: 2}, None)
            self.assertEqual(result["summary"]["warning"], 0)
        self.assertEqual(cold["raw"], warm["raw"])
        self.assertEqual(cold["raw"], disabled["raw"])
        self.source("suppressed.py", "import re\n" + "".join(
            f'REGEX{index} = re.compile(r"(a+)+$")\n' + self.function(f"f{index}")
            for index in range(4)))
        changed = self.scan([source], expected_hits=0)
        replay = self.scan([source], expected_hits=1)
        for result in (changed, replay):
            for rule in (self.PARAM_RULE, self.REGEX_RULE):
                self.assert_rule(result, rule, {source: 4}, "warning")
            self.assertEqual(result["summary"]["warning"], 8)
        self.assertEqual(changed["raw"], replay["raw"])

    def test_selected_raw_context_does_not_erase_source_local_counts(self) -> None:
        rule = "py.async.un-awaited-paths"
        idle = self.source("idle.py", "async def idle():\n    return 1\n")
        # Current pattern semantics use raw context, even a marked comment in
        # a sibling with no candidate match. Counts describe that distinction.
        context = self.source("context.py", "# await completion  # ubs:ignore\nVALUE = 1\n")
        self.scan([idle], expected_hits=0)
        self.scan([context], expected_hits=0)
        for selected, eligible in (([idle, context], False), ([idle], True),
                                   ([context, idle], False), ([context], False)):
            with self.subTest(selected=[path.name for path in selected]):
                result = self.scan(selected, expected_hits=len(selected))
                row = self.rule(result, rule)
                self.assertEqual(self.counts_for(result, rule), {str(idle): 1} if idle in selected else {})
                self.assertEqual(row["count"], int(idle in selected))
                self.assertEqual(row["threshold_severity"], "warning" if idle in selected else None)
                self.assertEqual(row["reported_severity"], "warning" if eligible else None)
                self.assertEqual(row["context"]["eligible"], eligible)
                self.assertIsNone(row["context"]["gate"])
                self.assertEqual(row["context"]["suppress_when"]["matched"], context in selected)
                self.assertEqual(row["context"]["suppress_when"]["regex"], r"\bawait\b")
        self.source("context.py", "VALUE = 2\n")
        changed = self.scan([idle, context], expected_hits=1)
        warm = self.scan([idle, context], expected_hits=2)
        self.assertEqual(changed["raw"], warm["raw"])
        self.assertEqual(self.rule(changed, rule)["reported_severity"], "warning")
        self.assertEqual(self.counts_for(changed, rule), {str(idle): 1})

    def test_gates_metadata_and_nonpattern_records_use_retained_facts(self) -> None:
        from ubs_core.py_scan import Pattern, pattern_count_report, reconcile_pattern_records, scan_patterns

        source = self.source("source.py", "print(value)\nprint(other)\n")
        gate = self.source("gate.py", "FEATURE = 'feature_enabled'\n")
        silencer = self.source("silencer.py", "# paused  # ubs:ignore\n")
        pattern = Pattern(11, "py.debug.gated-print", "Gated prints", re.compile(r"print\("),
                          ((1, "warning"),), gate_regex=re.compile(r"\bfeature_enabled\b"),
                          suppress_when_regex=re.compile(r"\bpaused\b"))
        with patch.dict(os.environ, self.env, clear=True):
            cache = ScanCache("python", self.project, rulepack_hash="raw-count-gate")
            for path in (source, gate, silencer):
                sink = CapturingSink()
                scan_patterns([pattern], [path], sink, set(), defer_global_checks=True)
                cache.store_scanned_files([path], sink.by_file)
            for selected, eligible in (([source], False), ([source, gate], True),
                                       ([source, gate, silencer], False)):
                with self.subTest(selected=[path.name for path in selected]):
                    cached, missing = cache.partition_files(selected)
                    self.assertEqual(missing, [])
                    facts = [record for path in selected for record in cached[path]]
                    facts.append({"rule": "python.future.project", "path": str(source),
                                  "line": 1, "severity": "critical", "message": "not a pattern"})
                    report = pattern_count_report([pattern], facts, selected)
                    duplicate = pattern_count_report([pattern], [*facts, *facts], selected)
                    self.assertEqual(report, duplicate, "one source line must count only once")
                    self.assertEqual(report["counts"], [{"file": str(source), "rule_id": pattern.rule_id,
                                                         "count": 2}])
                    self.assertEqual(len(report["rules"]), 1)
                    row = report["rules"][0]
                    self.assertEqual(row["count"], 2)
                    self.assertEqual(row["threshold_severity"], "warning")
                    self.assertEqual(row["reported_severity"], "warning" if eligible else None)
                    self.assertEqual(row["context"]["eligible"], eligible)
                    self.assertEqual(row["context"]["gate"]["matched"], gate in selected)
                    self.assertEqual(row["context"]["suppress_when"]["matched"], silencer in selected)
                    ordinary = reconcile_pattern_records([pattern], facts)
                    self.assertEqual(sum(r["rule"] == pattern.rule_id for r in ordinary), 2 if eligible else 0)
                    self.assertTrue(any(r["rule"] == "python.future.project" for r in ordinary))

    def test_relative_selected_paths_have_their_own_stable_cache_context(self) -> None:
        source = self.source("space in name.py", self.function("wide"))
        absolute = self.scan([source], expected_hits=0)
        self.assert_rule(absolute, self.PARAM_RULE, {source: 1}, None)
        relative = Path("project") / source.name
        # Cache identity includes the producer's path spelling, so a different
        # spelling is cold. Its subsequent replay must export identical rows.
        relative_cold = self.scan([relative], expected_hits=0)
        warm = self.scan([relative], expected_hits=1)
        cold = self.scan([relative], no_cache=True, expected_hits=0)
        self.assert_rule(warm, self.PARAM_RULE, {relative: 1}, None)
        self.assertEqual(relative_cold["raw"], warm["raw"])
        self.assertEqual(warm["raw"], cold["raw"])

    def test_skipped_categories_are_not_exported_as_zero_counts(self) -> None:
        source = self.source("skipped.py", "import re\n" + "".join(
            f'REGEX{index} = re.compile(r"(a+)+$")\n' + self.function(f"f{index}")
            for index in range(4)))
        for skip, absent, present in (("8", self.PARAM_RULE, self.REGEX_RULE),
                                      ("15", self.REGEX_RULE, self.PARAM_RULE)):
            with self.subTest(skip=skip):
                cold = self.scan([source], skip=skip, expected_hits=0)
                warm = self.scan([source], skip=skip, expected_hits=1)
                self.assertEqual(cold["raw"], warm["raw"])
                self.assertEqual(cold["raw"]["skipped_categories"], [int(skip)])
                self.assertNotIn(absent, {row["rule_id"] for row in cold["raw"]["rules"]})
                self.assertNotIn(absent, {row["rule_id"] for row in cold["raw"]["counts"]})
                self.assert_rule(cold, present, {source: 4}, "warning")
                self.assertEqual(cold["summary"]["warning"], 4)

    def test_incomplete_counts_are_labeled_partial_and_do_not_admit_cache_entries(self) -> None:
        good = self.source("good.py", self.function("wide"))
        bad = self.source("bad.py", "def broken(:\n")
        default = self.scan([good, bad], export=False, complete=False, expected_hits=0)
        partial = self.scan([good, bad], complete=False, expected_hits=0)
        self.assertEqual(self.public_result(default), self.public_result(partial))
        self.assertEqual(self.counts_for(partial, self.PARAM_RULE), {str(good): 1})
        self.assertTrue(any("syntax" in error.lower() for error in partial["raw"]["errors"]))
        missing = self.project / "missing.py"
        unreadable = self.scan([good, missing], complete=False, expected_hits=0)
        self.assertEqual(self.counts_for(unreadable, self.PARAM_RULE), {str(good): 1})
        self.assertTrue(any(str(missing) in error for error in unreadable["raw"]["errors"]))
        self.assertFalse(list((self.root / "cache").glob("*/files/**/*.json")))
        self.source("bad.py", "VALUE = 1\n")
        recovered = self.scan([good, bad], expected_hits=0)
        warm = self.scan([good, bad], expected_hits=2)
        self.assertEqual(recovered["raw"], warm["raw"])


if __name__ == "__main__":
    unittest.main()
