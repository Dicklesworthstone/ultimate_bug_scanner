"""ubs_core.scheduler — LPT scheduler with fitted cost model and per-slot metrics (bead C5).

Estimates per-module cost ĉ = a_lang · files_after_prefilter + b_lang with
coefficients fitted from profiles (benchmarks/cost-model.json, refreshed by the
nightly bench). Dispatches modules longest-expected-first onto min(nproc, --jobs)
slots (Graham's LPT bound: makespan ≤ (4/3 − 1/(3m))·OPT).
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

# Default coefficients: estimated_cost_ms = a * files + b
DEFAULT_COEFFICIENTS: dict[str, dict[str, float]] = {
    "python": {"a": 180.0, "b": 1500.0},
    "js": {"a": 95.0, "b": 1200.0},
    "bash": {"a": 120.0, "b": 1000.0},
    "swift": {"a": 70.0, "b": 1000.0},
    "golang": {"a": 65.0, "b": 1000.0},
    "go": {"a": 65.0, "b": 1000.0},
    "rust": {"a": 60.0, "b": 1000.0},
    "csharp": {"a": 70.0, "b": 1000.0},
    "java": {"a": 70.0, "b": 1000.0},
    "ruby": {"a": 60.0, "b": 1000.0},
    "cpp": {"a": 60.0, "b": 1000.0},
    "elixir": {"a": 55.0, "b": 1000.0},
    "kotlin": {"a": 55.0, "b": 1000.0},
}
FALLBACK_COEFFICIENT: dict[str, float] = {"a": 60.0, "b": 1000.0}


@dataclass
class CostModel:
    """Linear cost model estimating module scan duration in milliseconds."""

    coefficients: dict[str, dict[str, float]]
    default: dict[str, float]

    @classmethod
    def load(cls, path: Path | str | None = None) -> "CostModel":
        """Load cost model from explicit path, env var, or repo benchmarks dir."""
        candidate_paths: list[Path] = []
        if path:
            candidate_paths.append(Path(path))
        env_path = os.environ.get("UBS_COST_MODEL_PATH")
        if env_path:
            candidate_paths.append(Path(env_path))

        # Check repository benchmarks/cost-model.json
        repo_root = Path(__file__).resolve().parents[3]
        candidate_paths.append(repo_root / "benchmarks" / "cost-model.json")

        for cp in candidate_paths:
            if cp.is_file():
                try:
                    data = json.loads(cp.read_text(encoding="utf-8"))
                    coeffs = data.get("coefficients", {})
                    default = data.get("default", FALLBACK_COEFFICIENT)
                    return cls(coefficients=coeffs, default=default)
                except (OSError, ValueError):
                    pass

        return cls(coefficients=dict(DEFAULT_COEFFICIENTS), default=dict(FALLBACK_COEFFICIENT))

    def estimate_cost(self, lang: str, file_count: int) -> float:
        """Estimate module scan cost in milliseconds: ĉ = a_lang · files + b_lang."""
        key = lang.lower()
        coeffs = self.coefficients.get(key)
        if coeffs is None:
            if key == "golang":
                coeffs = self.coefficients.get("go")
            elif key == "go":
                coeffs = self.coefficients.get("golang")
        if coeffs is None:
            coeffs = self.default
        a = float(coeffs.get("a", self.default.get("a", 60.0)))
        b = float(coeffs.get("b", self.default.get("b", 1000.0)))
        return max(0.0, a * max(0, file_count) + b)


@dataclass
class ScheduleResult:
    """Result of Graham's Longest Processing Time (LPT) scheduling."""

    ordered_jobs: list[tuple[str, float]]
    slot_assignments: list[list[tuple[str, float]]]
    slot_loads: list[float]
    makespan: float
    slot_utilization: list[float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ordered_jobs": [{"id": jid, "cost": cost} for jid, cost in self.ordered_jobs],
            "ordered_langs": [jid for jid, _ in self.ordered_jobs],
            "slots": len(self.slot_loads),
            "slot_loads": [round(l, 2) for l in self.slot_loads],
            "makespan": round(self.makespan, 2),
            "slot_utilization": self.slot_utilization,
        }


def calculate_slot_utilization(slot_busy_times: Sequence[float], makespan: float) -> list[float]:
    """Calculate per-slot utilisation: busy_ms / makespan, clamped to [0.0, 1.0]."""
    if makespan <= 0.0 or not slot_busy_times:
        return [1.0 for _ in slot_busy_times]
    return [
        round(max(0.0, min(1.0, float(busy) / float(makespan))), 4)
        for busy in slot_busy_times
    ]


def schedule_lpt(jobs: Sequence[tuple[str, float]], num_slots: int) -> ScheduleResult:
    """Dispatch jobs longest-expected-first onto num_slots machines.

    Graham's LPT theorem guarantees: makespan(LPT) ≤ (4/3 - 1/(3m)) · OPT.
    """
    m = max(1, int(num_slots))
    # Sort descending by processing time; tie-break deterministically by id
    ordered = sorted(jobs, key=lambda item: (-item[1], item[0]))

    slot_assignments: list[list[tuple[str, float]]] = [[] for _ in range(m)]
    slot_loads: list[float] = [0.0 for _ in range(m)]

    for job_id, cost in ordered:
        # Greedily assign to machine with minimum current accumulated load
        min_slot = 0
        min_load = slot_loads[0]
        for s in range(1, m):
            if slot_loads[s] < min_load:
                min_load = slot_loads[s]
                min_slot = s
        slot_assignments[min_slot].append((job_id, cost))
        slot_loads[min_slot] += cost

    makespan = max(slot_loads) if slot_loads else 0.0
    utilization = calculate_slot_utilization(slot_loads, makespan)

    return ScheduleResult(
        ordered_jobs=ordered,
        slot_assignments=slot_assignments,
        slot_loads=slot_loads,
        makespan=makespan,
        slot_utilization=utilization,
    )


def brute_force_optimal_makespan(jobs: Sequence[tuple[str, float]], num_slots: int) -> float:
    """Compute exact optimal makespan OPT by brute-force search over all m^n partitions.

    Guards against exponential explosion by limiting to small instances (n <= 12).
    """
    n = len(jobs)
    m = max(1, int(num_slots))
    if n == 0:
        return 0.0
    if m == 1:
        return sum(cost for _, cost in jobs)
    if m >= n:
        return max(cost for _, cost in jobs)
    if n > 12:
        raise ValueError(f"brute_force_optimal_makespan instance too large: n={n}, m={m}")

    costs = [float(cost) for _, cost in jobs]
    best_makespan = float("inf")

    # Evaluate all m^n assignments of n jobs to m slots
    for assignment in itertools.product(range(m), repeat=n):
        loads = [0.0] * m
        for job_idx, slot in enumerate(assignment):
            loads[slot] += costs[job_idx]
        current_makespan = max(loads)
        if current_makespan < best_makespan:
            best_makespan = current_makespan

    return best_makespan


def graham_theoretical_bound(opt: float, num_slots: int) -> float:
    """Return Graham's upper bound: (4/3 - 1/(3m)) · OPT."""
    m = max(1, int(num_slots))
    factor = 4.0 / 3.0 - 1.0 / (3.0 * m)
    return factor * opt


def order_languages_lpt(
    langs: Sequence[str],
    file_counts: dict[str, int],
    cost_model: CostModel | None = None,
) -> list[tuple[str, float]]:
    """Estimate costs and return languages ordered longest-expected-first."""
    if cost_model is None:
        cost_model = CostModel.load()
    jobs = [(lang, cost_model.estimate_cost(lang, file_counts.get(lang, 0))) for lang in langs]
    # LPT order: descending by cost, tie-break by name
    return sorted(jobs, key=lambda item: (-item[1], item[0]))


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m ubs_core.scheduler", description="UBS LPT scheduler")
    sub = parser.add_subparsers(dest="action")

    order_p = sub.add_parser("order", help="order languages descending by estimated cost (LPT)")
    order_p.add_argument("--langs", required=True, help="comma-separated language list")
    order_p.add_argument("--files-dir", default="", help="directory containing <lang>.files lists")
    order_p.add_argument("--file-counts", default="", help="comma-separated lang:count pairs")
    order_p.add_argument("--slots", type=int, default=4, help="number of parallel slots available")
    order_p.add_argument("--cost-model", default="", help="path to custom cost-model.json")

    prof_p = sub.add_parser("profile", help="calculate slot utilization from busy times and makespan")
    prof_p.add_argument("--busy-ms", required=True, help="comma-separated slot busy times in ms")
    prof_p.add_argument("--makespan", type=float, required=True, help="total makespan in ms")
    prof_p.add_argument("--slots", type=int, default=0, help="total slots (defaults to len(busy_ms))")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    if args.action == "order":
        langs = [l.strip() for l in args.langs.split(",") if l.strip()]
        counts: dict[str, int] = {}
        if args.file_counts:
            for pair in args.file_counts.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    counts[k.strip()] = int(v.strip()) if v.strip().isdigit() else 0
        if args.files_dir:
            fdir = Path(args.files_dir)
            for lang in langs:
                fpath = fdir / f"{lang}.files"
                if fpath.is_file():
                    try:
                        # Count lines in <lang>.files
                        lines = [line for line in fpath.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
                        counts[lang] = len(lines)
                    except OSError:
                        pass

        cost_model = CostModel.load(args.cost_model if args.cost_model else None)
        jobs = [(lang, cost_model.estimate_cost(lang, counts.get(lang, 0))) for lang in langs]
        result = schedule_lpt(jobs, num_slots=args.slots)

        out = {
            "ordered_langs": [lang for lang, _ in result.ordered_jobs],
            "slots": args.slots,
            "estimates": {lang: round(cost, 1) for lang, cost in result.ordered_jobs},
            "makespan_estimate": round(result.makespan, 1),
            "slot_utilization_estimate": result.slot_utilization,
        }
        sys.stdout.write(json.dumps(out) + "\n")
        return 0

    if args.action == "profile":
        busy_list = [float(x.strip()) for x in args.busy_ms.split(",") if x.strip()]
        slots = args.slots or len(busy_list)
        while len(busy_list) < slots:
            busy_list.append(0.0)
        util = calculate_slot_utilization(busy_list, args.makespan)
        out = {
            "slots": slots,
            "makespan_ms": args.makespan,
            "slot_busy_ms": [round(b, 1) for b in busy_list],
            "slot_utilization": util,
        }
        sys.stdout.write(json.dumps(out) + "\n")
        return 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
