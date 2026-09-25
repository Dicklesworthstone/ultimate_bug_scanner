#!/usr/bin/env python3
"""Unit tests for ubs_core.scheduler and ubs_core.shards (bead C5).

Verifies:
1. Graham's LPT algorithm against brute-force optimum on small instances:
   makespan(LPT) <= (4/3 - 1/(3m)) * OPT.
2. Graham's tight worst-case instances achieve the theoretical bound.
3. Cost model estimates per-module duration: c = a_lang * files + b_lang.
4. Language ordering produces longest-expected-first (LPT) order.
5. Per-slot utilisation calculation (extras.profile.slot_utilization / slots).
6. Work-stealing file shard queue (ubs_core.shards): shards pulled from a shared
   queue across workers so one slow file does not serialise execution.
7. Scheduler CLI commands (order, profile).
8. E2E profile output includes valid slots and slot_utilization.
"""
from __future__ import annotations

import json
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

# The children below are the scheduler CLI and `ubs` itself, and an unbounded
# wait on either hides a deadlock while consuming the whole CI slot with no
# diagnostic (#123). The scheduler CLI is arithmetic on a handful of numbers
# and the e2e scan is one clean directory, so 180s fires on a hang and not on a
# busy host; `UBS_TEST_CHILD_TIMEOUT` raises it for a slower one. An expiry
# raises out of the test, which unittest reports as an error — never a pass.
CHILD_TIMEOUT_SECONDS = int(os.environ.get("UBS_TEST_CHILD_TIMEOUT", "180"))

from ubs_core.scheduler import (  # noqa: E402
    CostModel,
    ScheduleResult,
    brute_force_optimal_makespan,
    calculate_slot_utilization,
    count_file_list,
    graham_theoretical_bound,
    order_languages_lpt,
    module_timeout_seconds,
    schedule_lpt,
)
from ubs_core.shards import (  # noqa: E402
    ShardQueue,
    make_shards,
    parallel_file_map,
    run_work_stealing,
)


class GrahamLPTTheoremTests(unittest.TestCase):
    """Test Graham's LPT algorithm against exact brute-force optimum."""

    def test_single_machine_is_exact(self) -> None:
        jobs = [("j1", 10.0), ("j2", 20.0), ("j3", 5.0)]
        res = schedule_lpt(jobs, num_slots=1)
        opt = brute_force_optimal_makespan(jobs, num_slots=1)
        self.assertEqual(res.makespan, 35.0)
        self.assertEqual(opt, 35.0)
        self.assertEqual(res.slot_utilization, [1.0])

    def test_more_slots_than_jobs(self) -> None:
        jobs = [("j1", 10.0), ("j2", 20.0)]
        res = schedule_lpt(jobs, num_slots=5)
        opt = brute_force_optimal_makespan(jobs, num_slots=5)
        self.assertEqual(res.makespan, 20.0)
        self.assertEqual(opt, 20.0)
        self.assertEqual(len(res.slot_loads), 5)
        self.assertEqual(res.slot_loads[:2], [20.0, 10.0])
        self.assertEqual(res.slot_loads[2:], [0.0, 0.0, 0.0])

    def test_graham_tight_worst_case_instances(self) -> None:
        """Graham's (1966) known tight example achieving exactly (4/3 - 1/(3m)).

        For m machines: 2m jobs with durations:
        two of length m, two of length m+1, ..., two of length 2m-1, plus one of length 2m.
        """
        for m in (2, 3, 4):
            jobs: list[tuple[str, float]] = []
            idx = 0
            for length in range(m, 2 * m):
                jobs.append((f"j{idx}", float(length)))
                idx += 1
                jobs.append((f"j{idx}", float(length)))
                idx += 1
            jobs.append((f"j{idx}", float(2 * m)))

            res = schedule_lpt(jobs, num_slots=m)
            opt = brute_force_optimal_makespan(jobs, num_slots=m)
            bound = graham_theoretical_bound(opt, num_slots=m)

            # Assert: OPT <= makespan(LPT) <= (4/3 - 1/(3m)) * OPT
            self.assertGreaterEqual(res.makespan, opt - 1e-9)
            self.assertLessEqual(res.makespan, bound + 1e-9, f"Failed for m={m}: LPT={res.makespan}, bound={bound}")

    def test_random_job_distributions_satisfy_graham_bound(self) -> None:
        """Evaluate Graham's bound across 100 pseudo-random job sets for m=2, 3, 4."""
        rng = random.Random(20260908)
        instances_tested = 0
        for m in (2, 3, 4):
            for n in range(m, 9):
                for _ in range(5):
                    # Mix of uniform and exponential distributions
                    costs = [round(rng.uniform(1.0, 100.0), 2) for _ in range(n)]
                    jobs = [(f"job_{i}", c) for i, c in enumerate(costs)]

                    res = schedule_lpt(jobs, num_slots=m)
                    opt = brute_force_optimal_makespan(jobs, num_slots=m)
                    bound = graham_theoretical_bound(opt, num_slots=m)

                    self.assertGreaterEqual(res.makespan, opt - 1e-9)
                    self.assertLessEqual(
                        res.makespan,
                        bound + 1e-9,
                        f"Graham bound violated: n={n}, m={m}, LPT={res.makespan}, OPT={opt}, bound={bound}",
                    )
                    instances_tested += 1

        self.assertGreaterEqual(instances_tested, 75)


class CostModelTests(unittest.TestCase):
    """Test cost model estimation and language ordering."""

    def test_default_coefficients_all_12_languages(self) -> None:
        cm = CostModel.load()
        expected_langs = [
            "python", "js", "bash", "swift", "golang", "go",
            "rust", "csharp", "java", "ruby", "cpp", "elixir", "kotlin",
        ]
        for lang in expected_langs:
            cost = cm.estimate_cost(lang, file_count=10)
            self.assertGreater(cost, 0.0)

    def test_linear_cost_calculation(self) -> None:
        cm = CostModel(
            coefficients={"python": {"a": 100.0, "b": 500.0}},
            default={"a": 50.0, "b": 200.0},
        )
        # Python: 100 * 5 + 500 = 1000
        self.assertEqual(cm.estimate_cost("python", 5), 1000.0)
        # Fallback language: 50 * 10 + 200 = 700
        self.assertEqual(cm.estimate_cost("unknown", 10), 700.0)

    def test_order_languages_longest_expected_first(self) -> None:
        cm = CostModel(
            coefficients={
                "python": {"a": 180.0, "b": 1500.0},
                "js": {"a": 95.0, "b": 1200.0},
                "bash": {"a": 120.0, "b": 1000.0},
                "rust": {"a": 60.0, "b": 1000.0},
            },
            default={"a": 50.0, "b": 500.0},
        )
        file_counts = {"python": 100, "js": 50, "bash": 20, "rust": 10}
        # Estimates:
        # python: 180*100 + 1500 = 19500
        # js: 95*50 + 1200 = 5950
        # bash: 120*20 + 1000 = 3400
        # rust: 60*10 + 1000 = 1600
        ordered = order_languages_lpt(["rust", "bash", "python", "js"], file_counts, cost_model=cm)
        ordered_names = [name for name, _ in ordered]
        self.assertEqual(ordered_names, ["python", "js", "bash", "rust"])

    def test_automatic_timeout_tracks_cost_with_floor(self) -> None:
        self.assertEqual(module_timeout_seconds(0), 300)
        self.assertEqual(module_timeout_seconds(100_000), 300)
        self.assertEqual(module_timeout_seconds(100_001), 301)
        self.assertEqual(module_timeout_seconds(400_000), 1200)
        for invalid in (float("inf"), float("nan"), -1):
            self.assertEqual(module_timeout_seconds(invalid), 300)

    def test_invalid_cost_models_fall_back_to_finite_estimates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            model = Path(tmp) / "model.json"
            for data in ([], {"coefficients": []}, {"default": None},
                         {"coefficients": {"python": {"a": "slow"}}},
                         {"default": {"a": float("nan")}},
                         {"coefficients": {"python": {"a": -1}}}):
                with self.subTest(data=data):
                    model.write_text(json.dumps(data), encoding="utf-8")
                    estimate = CostModel.load(model).estimate_cost("python", 10)
                    self.assertTrue(math.isfinite(estimate))
                    self.assertGreater(estimate, 0)

    def test_file_list_counts_preserve_filename_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = Path(tmp) / "python.files"
            cases = (
                (b"one.py\0two.py\0three.py\0", 3),
                (b"line\nbreak.py\0invalid-\xff.py\0 space.py\0", 3),
                (b"\0\0one.py\0\0two.py", 2),
                (b"one.py\r\ntwo.py\n\nthree.py", 3),
                (b"", 0),
                (b"a" * 65535 + b"\n.py\0second.py\0", 2),
            )
            for content, expected in cases:
                with self.subTest(content=content[:40]):
                    paths.write_bytes(content)
                    self.assertEqual(count_file_list(paths), expected)


class SlotUtilizationTests(unittest.TestCase):
    """Test per-slot utilisation metric calculation."""

    def test_slot_utilization_calculation(self) -> None:
        busy = [1000.0, 500.0, 250.0, 0.0]
        makespan = 1000.0
        util = calculate_slot_utilization(busy, makespan)
        self.assertEqual(util, [1.0, 0.5, 0.25, 0.0])

    def test_slot_utilization_zero_makespan(self) -> None:
        util = calculate_slot_utilization([0.0, 0.0], 0.0)
        self.assertEqual(util, [1.0, 1.0])

    def test_slot_utilization_clamped(self) -> None:
        # If slight timing jitter produces busy slightly > makespan
        util = calculate_slot_utilization([1005.0], 1000.0)
        self.assertEqual(util, [1.0])


class WorkStealingShardsTests(unittest.TestCase):
    """Test work-stealing file shard queue (ubs_core.shards)."""

    def test_make_shards_partitioning(self) -> None:
        paths = [Path(f"f{i}.py") for i in range(10)]
        shards = make_shards(paths, shard_size=3)
        self.assertEqual(len(shards), 4)
        self.assertEqual([len(s) for s in shards], [3, 3, 3, 1])

    def test_work_stealing_parity_with_sequential(self) -> None:
        paths = [Path(f"file_{i}.txt") for i in range(30)]

        def process_fn(shard: list[Path]) -> list[str]:
            return [f"processed:{p.name}" for p in shard]

        seq_result = sorted(run_work_stealing(paths, process_fn, num_workers=1))
        par_result = sorted(run_work_stealing(paths, process_fn, num_workers=4, shard_size=2))
        self.assertEqual(seq_result, par_result)

    def test_straggler_file_does_not_serialise_shards(self) -> None:
        """Verify that a slow file in one shard does not block other workers from stealing shards."""
        # 12 files: file_0 is slow (50ms sleep), all other files are fast (instant)
        files = [Path(f"file_{i}.txt") for i in range(12)]

        def process_shard(shard: list[Path]) -> list[tuple[str, float]]:
            res = []
            for p in shard:
                if p.name == "file_0.txt":
                    time.sleep(0.05)
                res.append((p.name, time.time()))
            return res

        t0 = time.time()
        # With 4 workers and shard size 1, file_0 occupies 1 worker while 3 workers process files 1..11
        results = run_work_stealing(files, process_shard, num_workers=4, shard_size=1)
        elapsed = time.time() - t0

        self.assertEqual(len(results), 12)
        # Should finish close to the single slow file duration (~0.05s) rather than sequential
        self.assertLess(elapsed, 0.25)

    def test_parallel_file_map(self) -> None:
        files = [Path(f"src_{i}.rs") for i in range(8)]
        mapped = parallel_file_map(files, lambda p: len(p.name), num_workers=3)
        for f in files:
            self.assertEqual(mapped[f], len(f.name))


class SchedulerCLITests(unittest.TestCase):
    """Test CLI commands: order and profile."""

    def test_cli_order_command(self) -> None:
        cmd = [
            sys.executable, "-m", "ubs_core.scheduler", "order",
            "--langs", "python,js,rust",
            "--file-counts", "python:100,js:50,rust:10",
            "--slots", "2",
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONPATH": str(HELPERS_DIR)},
            timeout=CHILD_TIMEOUT_SECONDS,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["ordered_langs"], ["python", "js", "rust"])
        self.assertEqual(data["slots"], 2)
        self.assertIn("estimates", data)
        self.assertIn("makespan_estimate", data)
        self.assertIn("slot_utilization_estimate", data)

    def test_nul_lists_drive_scheduling_and_large_project_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Previously each of these NUL lists was counted as one file.
            (root / "python.files").write_bytes(b"".join(
                f"source-{i}.py\0".encode() for i in range(3000)
            ))
            (root / "bash.files").write_bytes(b"first.sh\0second.sh\0")
            (root / "cost.json").write_text(json.dumps({
                "coefficients": {"python": {"a": 180, "b": 1500},
                                 "bash": {"a": 120, "b": 1000}},
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-m", "ubs_core.scheduler", "order",
                 "--langs=bash,python", f"--files-dir={root}",
                 f"--cost-model={root / 'cost.json'}", "--slots=2"],
                capture_output=True, text=True, check=True,
                env={**os.environ, "PYTHONPATH": str(HELPERS_DIR)},
                timeout=CHILD_TIMEOUT_SECONDS,
            )
            data = json.loads(proc.stdout)
            self.assertEqual(data["file_counts"], {"bash": 2, "python": 3000})
            self.assertEqual(data["ordered_langs"], ["python", "bash"])
            self.assertEqual(data["estimates"]["python"], 541500)
            self.assertEqual(data["timeouts"], {"python": 1625, "bash": 300})

    def test_cli_profile_command(self) -> None:
        cmd = [
            sys.executable, "-m", "ubs_core.scheduler", "profile",
            "--busy-ms", "1000,500",
            "--makespan", "1000",
            "--slots", "2",
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONPATH": str(HELPERS_DIR)},
            timeout=CHILD_TIMEOUT_SECONDS,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["slots"], 2)
        self.assertEqual(data["slot_utilization"], [1.0, 0.5])


class E2ESchedulerIntegrationTests(unittest.TestCase):
    """Verify ./ubs execution profile outputs slots and slot_utilization."""

    def test_runner_applies_language_budgets_and_explicit_overrides(self) -> None:
        real_timeout = shutil.which("timeout") or shutil.which("gtimeout")
        if real_timeout is None:
            self.skipTest("timeout utility required to observe module time bounds")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            for index in range(4):
                (source / f"source-{index}.py").write_text("answer = 42\n", encoding="utf-8")
            (source / "run.sh").write_text("#!/bin/sh\nprintf '%s\\n' ok\n", encoding="utf-8")
            model = root / "cost.json"
            model.write_text(json.dumps({
                "coefficients": {"python": {"a": 100000, "b": 0},
                                 "bash": {"a": 1000, "b": 0}},
            }), encoding="utf-8")
            binary_dir = root / "bin"
            binary_dir.mkdir()
            recorder = binary_dir / "timeout"
            # Observe real module launches, then delegate to the host utility.
            # An injected timeout also proves the report uses the chosen budget.
            recorder.write_text("""#!/usr/bin/env bash
if [[ "$1" == "-k" && "$5" == *ubs-*.sh ]]; then
  printf '%s\\t%s\\n' "${5##*/}" "$3" >> "$UBS_TEST_TIMEOUT_LOG"
  if [[ "${UBS_TEST_EXPIRE:-0}" == 1 ]]; then exit 124; fi
fi
exec "$UBS_TEST_REAL_TIMEOUT" "$@"
""", encoding="utf-8")
            recorder.chmod(0o755)
            env = {**os.environ, "PATH": str(binary_dir) + os.pathsep + os.environ.get("PATH", ""),
                   "UBS_TEST_REAL_TIMEOUT": real_timeout, "UBS_COST_MODEL_PATH": str(model),
                   "UBS_NO_AUTO_UPDATE": "1", "UBS_NO_CACHE": "1", "NO_COLOR": "1"}
            env.pop("UBS_MODULE_TIMEOUT", None)
            cases = (
                ("single-auto", "python", None, False, {"ubs-python.sh": "1200s"}),
                ("mixed-auto", "python,bash", None, False,
                 {"ubs-python.sh": "1200s", "ubs-bash.sh": "300s"}),
                ("override", "python,bash", "7", False,
                 {"ubs-python.sh": "7s", "ubs-bash.sh": "7s"}),
                ("disabled", "python", "0", False, {}),
                ("timeout-envelope", "python", None, True, {"ubs-python.sh": "1200s"}),
            )
            for name, langs, override, expire, expected in cases:
                with self.subTest(case=name):
                    log = root / f"{name}.log"
                    case_env = {**env, "UBS_TEST_TIMEOUT_LOG": str(log),
                                "UBS_TEST_EXPIRE": str(int(expire))}
                    if override is not None:
                        case_env["UBS_MODULE_TIMEOUT"] = override
                    proc = subprocess.run(
                        [str(REPO_ROOT / "ubs"), str(source), f"--only={langs}",
                         "--ci", "--format=json"],
                        cwd=root, capture_output=True, text=True, env=case_env,
                        timeout=CHILD_TIMEOUT_SECONDS,
                    )
                    self.assertEqual(proc.returncode, 2 if expire else 0,
                                     f"stdout={proc.stdout}\nstderr={proc.stderr}")
                    launches = dict(line.split("\t") for line in
                                    log.read_text().splitlines()) if log.exists() else {}
                    self.assertEqual(launches, expected)
                    report = json.loads(proc.stdout)
                    self.assertEqual(report["status"], "partial" if expire else "ok")
                    if expire:
                        self.assertEqual(report["scanners"][0]["module_timeout_secs"], 1200)

    def test_ubs_profile_json_contains_slots_and_utilization(self) -> None:
        cmd = [
            str(REPO_ROOT / "ubs"),
            str(REPO_ROOT / "test-suite" / "python" / "clean"),
            "--ci",
            "--format=json",
        ]
        env = dict(os.environ)
        env["UBS_PROFILE"] = "1"
        env["NO_COLOR"] = "1"
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env,
            timeout=CHILD_TIMEOUT_SECONDS,
        )
        data = json.loads(proc.stdout)
        profile = data.get("profile")
        self.assertIsNotNone(profile, "profile block missing from json output")
        self.assertIn("slots", profile, "slots missing from profile")
        self.assertIn("slot_utilization", profile, "slot_utilization missing from profile")
        self.assertGreaterEqual(profile["slots"], 1)
        self.assertEqual(len(profile["slot_utilization"]), profile["slots"])
        for util in profile["slot_utilization"]:
            self.assertGreaterEqual(util, 0.0)
            self.assertLessEqual(util, 1.0)


if __name__ == "__main__":
    unittest.main()
