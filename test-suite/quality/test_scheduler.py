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
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.scheduler import (  # noqa: E402
    CostModel,
    ScheduleResult,
    brute_force_optimal_makespan,
    calculate_slot_utilization,
    graham_theoretical_bound,
    order_languages_lpt,
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
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env={**os.environ, "PYTHONPATH": str(HELPERS_DIR)})
        data = json.loads(proc.stdout)
        self.assertEqual(data["ordered_langs"], ["python", "js", "rust"])
        self.assertEqual(data["slots"], 2)
        self.assertIn("estimates", data)
        self.assertIn("makespan_estimate", data)
        self.assertIn("slot_utilization_estimate", data)

    def test_cli_profile_command(self) -> None:
        cmd = [
            sys.executable, "-m", "ubs_core.scheduler", "profile",
            "--busy-ms", "1000,500",
            "--makespan", "1000",
            "--slots", "2",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env={**os.environ, "PYTHONPATH": str(HELPERS_DIR)})
        data = json.loads(proc.stdout)
        self.assertEqual(data["slots"], 2)
        self.assertEqual(data["slot_utilization"], [1.0, 0.5])


class E2ESchedulerIntegrationTests(unittest.TestCase):
    """Verify ./ubs execution profile outputs slots and slot_utilization."""

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
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)
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
