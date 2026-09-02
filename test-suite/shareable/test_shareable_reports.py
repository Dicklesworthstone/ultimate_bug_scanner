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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"
TARGET = REPO_ROOT / "test-suite" / "python" / "buggy"
FAILURES: list[str] = []


def run(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_NO_AUTO_UPDATE": "1"})
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
        ok = bool(git.get("repository")) and bool(git.get("commit")) and blob.startswith("https://github.com/") and git["commit"] in blob
        report("stdout_json_git_block", ok, f"git={git}", proc if not ok else None)
        samples = [s for sc in doc.get("scanners", []) for f in sc.get("findings", []) for s in f.get("samples", []) if isinstance(s.get("line"), int) and s.get("file")]
        linked = [s for s in samples if s.get("permalink", "").startswith(blob + "/") and s["permalink"].endswith(f"#L{s['line']}")]
        ok = bool(samples) and len(linked) == len(samples)
        report("stdout_json_sample_permalinks", ok, f"{len(linked)}/{len(samples)} samples carry a permalink", proc if not ok else None)

        # 2. SARIF locations carry properties.permalink.
        proc = run([*common, "--format=sarif", str(TARGET)])
        try:
            sarif = json.loads(proc.stdout)
            locs = [loc for r in sarif["runs"] for res in r.get("results", []) for loc in res.get("locations", []) if loc.get("physicalLocation", {}).get("region", {}).get("startLine")]
            good = [loc for loc in locs if loc.get("properties", {}).get("permalink", "").startswith(blob + "/")]
            ok = bool(locs) and len(good) == len(locs)
            report("sarif_location_permalinks", ok, f"{len(good)}/{len(locs)} locations linked", proc if not ok else None)
        except Exception as exc:  # noqa: BLE001
            report("sarif_location_permalinks", False, f"{exc}", proc)

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
