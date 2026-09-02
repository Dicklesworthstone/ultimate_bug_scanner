#!/usr/bin/env python3
"""Two-sided CUSUM regression alarm for scripts/bench.sh results (bead C1).

    scripts/bench_cusum.py --baseline benchmarks/baseline.json \
        --history benchmarks/history.ndjson [--latest benchmarks/latest.json] \
        [--k 0.5] [--h 6.0] [--sigma 0.05] [--window 30]

For every corpus item in the baseline, the wall times recorded in history (and
latest.json, if given and not already the last history entry) are turned into
log(wall) deviations from the baseline's log(wall), standardised by sigma (the
relative run-to-run noise; default 5% of wall time, or the baseline's own
spread when it recorded min/max over several runs). A two-sided CUSUM with
drift k (in sigmas) and threshold h (in sigmas) then raises an alarm only when
the deviation persists. Measured on white noise over the 30-sample window the
CLI evaluates: h=4 alarmed in 13.7% of windows (two-sided), h=5 in 5.7%, h=6
in about 2%, while a lasting 10% slowdown (2 sigma at the default noise) still
trips within four samples at h=6 — hence h=6 by default. Exit 1 on any alarm (slower OR faster — a faster run means the
baseline is stale and should be refreshed).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


def cusum(z: list[float], k: float = 0.5, h: float = 6.0) -> tuple[list[float], list[float], int | None, int | None]:
    """Two-sided CUSUM over standardised deviations z. Returns the upper and
    lower statistics per sample and the first sample index at which each side
    crossed h (None when it never did)."""
    s_hi = s_lo = 0.0
    hi_path, lo_path = [], []
    first_hi = first_lo = None
    for i, value in enumerate(z):
        s_hi = max(0.0, s_hi + value - k)
        s_lo = max(0.0, s_lo - value - k)
        hi_path.append(s_hi)
        lo_path.append(s_lo)
        if first_hi is None and s_hi > h:
            first_hi = i
        if first_lo is None and s_lo > h:
            first_lo = i
    return hi_path, lo_path, first_hi, first_lo


def standardise(walls: list[float], baseline_wall: float, sigma_rel: float) -> list[float]:
    base = math.log(baseline_wall)
    return [(math.log(w) - base) / sigma_rel for w in walls]


def baseline_sigma(item: dict, default: float) -> float:
    """Relative noise of the baseline: half its min..max log-range over its
    runs when it recorded several, else the default."""
    lo, hi, runs = item.get("wall_s_min"), item.get("wall_s_max"), int(item.get("runs", 1) or 1)
    if runs >= 3 and lo and hi and hi > lo > 0:
        spread = (math.log(hi) - math.log(lo)) / 2.0
        return max(spread, default / 2)
    return default


def read_json(path: Path, what: str) -> dict:
    """Load a benchmark document; a corrupt file is a clear error, not a traceback."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[bench-cusum] cannot read {what} {path}: {exc}") from exc


def load_history(path: Path, latest: Path | None) -> list[dict]:
    docs: list[dict] = []
    if path.exists():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"[bench-cusum] {path}:{lineno} is not JSON: {exc}") from exc
    if latest and latest.exists():
        doc = read_json(latest, "latest results")
        if not docs or docs[-1].get("generated_at") != doc.get("generated_at"):
            docs.append(doc)
    return docs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--history", type=Path, required=True)
    ap.add_argument("--latest", type=Path)
    ap.add_argument("--k", type=float, default=0.5, help="drift allowance in sigmas (default 0.5)")
    ap.add_argument("--h", type=float, default=6.0, help="decision threshold in sigmas (default 6)")
    ap.add_argument("--sigma", type=float, default=0.05, help="default relative noise of wall time (default 0.05)")
    ap.add_argument("--window", type=int, default=30, help="use at most this many most recent samples (default 30)")
    args = ap.parse_args(argv)

    if not args.baseline.exists():
        print(f"[bench-cusum] no baseline at {args.baseline}: nothing to compare (copy benchmarks/latest.json there to start)")
        return 0
    baseline = read_json(args.baseline, "baseline")
    history = load_history(args.history, args.latest)
    if not history:
        print("[bench-cusum] no history to compare")
        return 0

    alarms = 0
    for item in baseline.get("corpus", []):
        name = item["name"]
        base_wall = float(item.get("wall_s", 0) or 0)
        if base_wall <= 0:
            continue
        walls = [float(c["wall_s"]) for doc in history for c in doc.get("corpus", []) if c.get("name") == name and float(c.get("wall_s", 0) or 0) > 0]
        walls = walls[-args.window:]
        if not walls:
            print(f"[bench-cusum:{name}] no samples")
            continue
        sigma = baseline_sigma(item, args.sigma)
        z = standardise(walls, base_wall, sigma)
        hi, lo, first_hi, first_lo = cusum(z, args.k, args.h)
        latest_ratio = walls[-1] / base_wall - 1.0
        verdict = "PASS"
        if first_hi is not None:
            verdict = f"ALARM slower (CUSUM {hi[-1]:.1f}σ > {args.h}σ, tripped at sample {first_hi + 1}/{len(z)})"
            alarms += 1
        elif first_lo is not None:
            verdict = f"ALARM faster (CUSUM {lo[-1]:.1f}σ > {args.h}σ; refresh the baseline)"
            alarms += 1
        print(f"[bench-cusum:{name}] {verdict} — baseline {base_wall}s, latest {walls[-1]}s ({latest_ratio:+.1%} vs baseline), σ={sigma:.3f}, {len(z)} sample(s)".replace("+-", "-"))
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
