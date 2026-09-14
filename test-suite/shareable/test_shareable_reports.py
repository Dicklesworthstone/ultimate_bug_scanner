#!/usr/bin/env python3
"""Smoke-test the shareable report pipeline (README "shareable output", bead B5).

Runs the real ubs against the Python buggy fixtures inside this git checkout
and checks:
  - stdout --format=json carries git.{repository,commit,blob_base} and every
    finding sample with a file/line carries a permalink under blob_base
  - --format=sarif result locations carry properties.permalink
  - --report-json without a comparison has no comparison block; with
    --comparison (and the --baseline alias) the delta equals current - baseline
  - the HTML report shows a Baseline column only when a comparison was given
  - text mode prints a one-line "Δ vs baseline" when a comparison was given
Each check prints a `[shareable:<name>] PASS/FAIL` line; failures show the
captured output.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
TARGET = REPO_ROOT / "test-suite" / "python" / "buggy"
GITHUB_ORIGIN = "https://github.com/ubs-test/shareable-reports.git"
FAILURES: list[str] = []


def run(args: list[str], *, origin: str = GITHUB_ORIGIN) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({
        "NO_COLOR": "1",
        "UBS_NO_AUTO_UPDATE": "1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "remote.origin.url",
        "GIT_CONFIG_VALUE_0": origin,
    })
    return subprocess.run([str(UBS_BIN), *args], capture_output=True, text=True, env=env, cwd=REPO_ROOT, timeout=600)


def report(name: str, ok: bool, detail: str = "", proc: subprocess.CompletedProcess | None = None) -> None:
    print(f"[shareable:{name}] {'PASS' if ok else 'FAIL'}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        FAILURES.append(name)
        if proc is not None:
            print(f"  exit={proc.returncode}\n  stdout:\n{textwrap.indent(proc.stdout[-1500:], '    ')}\n  stderr:\n{textwrap.indent(proc.stderr[-1500:], '    ')}")


def totals_of(doc: dict) -> dict:
    t = doc.get("totals", {})
    return {k: int(t.get(k, 0) or 0) for k in ("critical", "warning", "info", "files")}


def record_counts(records: list[dict]) -> Counter:
    # Parallel detectors may emit records in a different order. Retain every
    # field and duplicate when comparing the same scan across Git origins.
    return Counter(json.dumps(record, sort_keys=True) for record in records)


def main() -> int:
    tmpdir = Path(tempfile.mkdtemp(prefix="ubs-shareable-"))
    try:
        common = ["--ci", "--only=python", "--category=resource-lifecycle"]

        # 1. stdout JSON: git block + sample permalinks.
        proc = run([*common, "--format=json", str(TARGET)])
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            report("stdout_json_git_block", False, f"stdout is not JSON: {exc}", proc)
            return 1
        git = doc.get("git") or {}
        blob = git.get("blob_base", "")
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            cwd=REPO_ROOT, check=True, timeout=10,
        ).stdout.strip()
        expected_blob = f"https://github.com/ubs-test/shareable-reports/blob/{commit}"
        ok = bool(git.get("repository")) and git.get("commit") == commit and blob == expected_blob
        report("stdout_json_git_block", ok, f"git={git}", proc if not ok else None)
        samples = [s for sc in doc.get("scanners", []) for f in sc.get("findings", []) for s in f.get("samples", []) if isinstance(s.get("line"), int) and s.get("file")]
        linked = [s for s in samples if s.get("permalink", "").startswith(blob + "/") and s["permalink"].endswith(f"#L{s['line']}")]
        ok = bool(samples) and len(linked) == len(samples)
        report("stdout_json_sample_permalinks", ok, f"{len(linked)}/{len(samples)} samples carry a permalink", proc if not ok else None)

        # 2. SARIF locations carry properties.permalink.
        proc = run([*common, "--format=sarif", str(TARGET)])
        locs = []
        try:
            sarif = json.loads(proc.stdout)
            locs = [loc for r in sarif["runs"] for res in r.get("results", []) for loc in res.get("locations", []) if loc.get("physicalLocation", {}).get("region", {}).get("startLine")]
            good = [loc for loc in locs if loc.get("properties", {}).get("permalink", "").startswith(blob + "/")]
            ok = bool(locs) and len(good) == len(locs)
            report("sarif_location_permalinks", ok, f"{len(good)}/{len(locs)} locations linked", proc if not ok else None)
        except Exception as exc:  # noqa: BLE001
            report("sarif_location_permalinks", False, f"{exc}", proc)

        # A local clone has no GitHub provenance. Preserve findings and counts
        # without inventing links, and never change the checkout's Git config.
        proc = run([*common, "--format=json", str(TARGET)], origin=str(REPO_ROOT))
        try:
            local_doc = json.loads(proc.stdout)
            local_samples = [s for sc in local_doc.get("scanners", []) for f in sc.get("findings", []) for s in f.get("samples", []) if isinstance(s.get("line"), int) and s.get("file")]
            without_links = lambda records: [
                {key: value for key, value in sample.items() if key != "permalink"}
                for sample in records
            ]
            expected_samples = record_counts(without_links(samples))
            actual_samples = record_counts(without_links(local_samples))
            ok = (
                not local_doc.get("git")
                and totals_of(local_doc) == totals_of(doc)
                and actual_samples == expected_samples
                and all("permalink" not in sample for sample in local_samples)
            )
            missing_samples = expected_samples - actual_samples
            extra_samples = actual_samples - expected_samples
            report("local_origin_preserves_findings_without_links", ok, f"samples={len(local_samples)} missing={dict(missing_samples)} extra={dict(extra_samples)}", proc if not ok else None)
        except json.JSONDecodeError as exc:
            report("local_origin_preserves_findings_without_links", False, f"stdout is not JSON: {exc}", proc)

        proc = run([*common, "--format=sarif", str(TARGET)], origin=str(REPO_ROOT))
        try:
            local_sarif = json.loads(proc.stdout)
            local_locs = [loc for r in local_sarif["runs"] for res in r.get("results", []) for loc in res.get("locations", []) if loc.get("physicalLocation", {}).get("region", {}).get("startLine")]
            expected_locations = record_counts([loc["physicalLocation"] for loc in locs])
            actual_locations = record_counts([loc["physicalLocation"] for loc in local_locs])
            ok = (
                actual_locations == expected_locations
                and all("permalink" not in loc.get("properties", {}) for loc in local_locs)
            )
            missing_locations = expected_locations - actual_locations
            extra_locations = actual_locations - expected_locations
            report("local_origin_sarif_preserves_locations_without_links", ok, f"locations={len(local_locs)} missing={dict(missing_locations)} extra={dict(extra_locations)}", proc if not ok else None)
        except (json.JSONDecodeError, KeyError) as exc:
            report("local_origin_sarif_preserves_locations_without_links", False, f"{exc}", proc)

        # 3. Baseline report, then comparison via --comparison and the --baseline alias.
        baseline = tmpdir / "baseline.json"
        proc = run([*common, f"--report-json={baseline}", str(TARGET)])
        base_doc = json.loads(baseline.read_text()) if baseline.exists() else {}
        ok = baseline.exists() and "comparison" not in base_doc and bool(base_doc.get("git", {}).get("repository"))
        report("report_json_baseline", ok, f"exists={baseline.exists()} keys={sorted(base_doc)[:8]}", proc if not ok else None)

        html_no_cmp = tmpdir / "plain.html"
        proc = run([*common, f"--html-report={html_no_cmp}", str(TARGET)])
        text = html_no_cmp.read_text() if html_no_cmp.exists() else ""
        ok = html_no_cmp.exists() and "Baseline" not in text and "<th>Current</th>" in text and "Per-language totals" in text
        report("html_without_comparison_has_no_baseline_column", ok, f"exists={html_no_cmp.exists()}", proc if not ok else None)

        for flag in ("--comparison", "--baseline"):
            current = tmpdir / f"current-{flag.strip('-')}.json"
            html_cmp = tmpdir / f"report-{flag.strip('-')}.html"
            proc = run([*common, f"{flag}={baseline}", f"--report-json={current}", f"--html-report={html_cmp}", str(TARGET)])
            try:
                cur_doc = json.loads(current.read_text())
                comp = cur_doc["comparison"]
                expected = {k: totals_of(cur_doc)[k] - totals_of(base_doc)[k] for k in ("critical", "warning", "info")}
                ok = comp["delta"] == expected and comp["baseline_totals"] == {k: totals_of(base_doc)[k] for k in ("files", "critical", "warning", "info")}
                report(f"comparison_delta_correct{flag.replace('-', '_')}", ok, f"delta={comp.get('delta')} expected={expected}", proc if not ok else None)
                html_text = html_cmp.read_text()
                ok = "<th>Baseline</th>" in html_text and f"<td>{totals_of(base_doc)['critical']}</td>" in html_text
                report(f"html_with_comparison_has_baseline{flag.replace('-', '_')}", ok, "", proc if not ok else None)
                ok = "Δ vs baseline" in proc.stdout and f"critical {expected['critical']:+d}" in proc.stdout
                report(f"console_delta_line{flag.replace('-', '_')}", ok, "", proc if not ok else None)
            except Exception as exc:  # noqa: BLE001
                report(f"comparison_delta_correct{flag.replace('-', '_')}", False, f"{exc}", proc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if FAILURES:
        print(f"\n[shareable] {len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("\n[shareable] all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
