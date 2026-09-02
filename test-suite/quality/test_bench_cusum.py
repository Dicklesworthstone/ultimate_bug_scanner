"""CUSUM regression alarm (scripts/bench_cusum.py): quiet on white noise,
trips on a persistent 10% slowdown within a handful of samples, and the CLI
handles a missing baseline gracefully."""
from __future__ import annotations

import json
import math
import random
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import bench_cusum  # noqa: E402


class CusumTests(unittest.TestCase):
    def test_white_noise_rarely_alarms(self) -> None:
        # Over the 30-sample window the CLI evaluates, the default k=0.5, h=6
        # must keep two-sided false alarms rare (measured: h=4 13.7%, h=5 5.7%).
        # (Deterministic seeds: this is a rate check, not a flaky one.)
        base = 10.0
        sigma = 0.05
        windows = 300
        false_alarms = 0
        for seed in range(windows):
            rng = random.Random(seed)
            walls = [base * math.exp(rng.gauss(0.0, sigma)) for _ in range(30)]
            z = bench_cusum.standardise(walls, base, sigma)
            _, _, hi, lo = bench_cusum.cusum(z)
            if hi is not None or lo is not None:
                false_alarms += 1
        self.assertLessEqual(false_alarms, windows * 0.04, f"{false_alarms}/{windows} white-noise windows alarmed")

    def test_ten_percent_step_trips_within_eight_samples(self) -> None:
        # A persistent 10% slowdown is a 2-sigma shift at the default noise:
        # the CUSUM gains ~1.5 sigma per sample, so h=6 trips around sample 4;
        # noise can delay it, never past 8 samples over these seeds.
        base = 10.0
        sigma = 0.05
        slowest = 0
        for seed in range(20):
            rng = random.Random(100 + seed)
            walls = [base * 1.10 * math.exp(rng.gauss(0.0, sigma)) for _ in range(12)]
            z = bench_cusum.standardise(walls, base, sigma)
            _, _, hi, _ = bench_cusum.cusum(z)
            self.assertIsNotNone(hi, f"no alarm on a 10% step with seed {seed}")
            slowest = max(slowest, hi + 1)
        self.assertLessEqual(slowest, 8, f"slowest detection took {slowest} samples")

    def test_baseline_sigma_uses_recorded_spread(self) -> None:
        self.assertAlmostEqual(bench_cusum.baseline_sigma({"runs": 3, "wall_s_min": 9.0, "wall_s_max": 11.0}, 0.05), (math.log(11.0) - math.log(9.0)) / 2)
        self.assertEqual(bench_cusum.baseline_sigma({"runs": 1}, 0.05), 0.05)

    def test_cli_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            baseline = {"generated_at": "b", "corpus": [{"name": "fixtures", "wall_s": 10.0, "runs": 1}]}
            (d / "baseline.json").write_text(json.dumps(baseline))
            self.assertEqual(bench_cusum.main(["--baseline", str(d / "missing.json"), "--history", str(d / "history.ndjson")]), 0)
            steady = [{"generated_at": f"t{i}", "corpus": [{"name": "fixtures", "wall_s": 10.0 * (1 + 0.01 * ((-1) ** i))}]} for i in range(10)]
            (d / "history.ndjson").write_text("\n".join(json.dumps(x) for x in steady) + "\n")
            self.assertEqual(bench_cusum.main(["--baseline", str(d / "baseline.json"), "--history", str(d / "history.ndjson")]), 0)
            slow = steady + [{"generated_at": f"s{i}", "corpus": [{"name": "fixtures", "wall_s": 11.5}]} for i in range(8)]
            (d / "history.ndjson").write_text("\n".join(json.dumps(x) for x in slow) + "\n")
            self.assertEqual(bench_cusum.main(["--baseline", str(d / "baseline.json"), "--history", str(d / "history.ndjson")]), 1)


if __name__ == "__main__":
    unittest.main()
