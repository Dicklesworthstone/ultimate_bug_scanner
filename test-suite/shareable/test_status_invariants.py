#!/usr/bin/env python3
"""Run-status invariants across the matrix of module outcomes (issues #103-#106).

One rule, checked for every outcome a scanner module can have:

    the human status line, the machine `status` field, and the process exit
    code must all say the same thing about whether the scan completed.

Before this guard each of those three was computed on its own path, and they
disagreed in every direction: a module that exited 2 produced a minimal error
envelope with no status line and no results at all; a module that exited 7
produced `status: partial` with the results intact; `--new-only` rewrote
`status` to "ok" while `failed_modules` still named the module that crashed;
and an analyzer that failed inside the module was folded in as a clean pass.

The matrix is driven by a stub `ubs-python` on PATH (the meta-runner resolves
modules from PATH first), so the outcome is chosen exactly and the REAL bash
scanner runs alongside it — every "partial" case therefore also proves that the
healthy scanner's findings survived.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS_BIN = REPO_ROOT / "ubs"

FAILURES: list[str] = []
CHECKS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if ok:
        print(f"[status-invariants] PASS {name}")
    else:
        print(f"[status-invariants] FAIL {name}: {detail}")
        FAILURES.append(f"{name}: {detail}")


STUB = r"""#!/usr/bin/env bash
if [ "$1" = "--help" ]; then
  echo "contract: v2"
  exit 0
fi
mode="${STUB_MODE:-clean}"
rc="${STUB_EXIT:-0}"
fmt=text
report=""
for arg in "$@"; do
  case "$arg" in
    --format=*) fmt="${arg#*=}" ;;
    --report-json=*) report="${arg#*=}" ;;
  esac
done
if [ "$mode" = "sleep" ]; then sleep 30; fi
if [ "$mode" = "garbage" ]; then
  echo "Garbage text with Critical issues: 42 and Warning issues: 99"
  exit "$rc"
fi
[ -n "$report" ] && : > "$report"
if [ "$fmt" = "json" ] || [ "$fmt" = "sarif" ]; then
  printf '{"language":"python","project":"%s","files":1,"critical":0,"warning":0,"info":0,"timestamp":"2026-01-01T00:00:00Z","status":"ok","findings":[]}\n' "${STUB_PROJECT:-.}"
else
  echo "UBS module: python (contract v2)"
  echo ""
  echo "Summary Statistics:"
  echo "Files scanned: 1"
  echo "Critical issues: 0"
  echo "Warning issues: 0"
  echo "Info items: 0"
fi
exit "$rc"
"""


def make_workspace(tmpdir: Path) -> tuple[Path, Path]:
    """A scan target with one real bash critical, plus the stub module dir."""
    target = tmpdir / "project"
    target.mkdir(parents=True, exist_ok=True)
    (target / "clean.py").write_text("value = 1\n", encoding="utf-8")
    (target / "bad.sh").write_text('#!/bin/bash\neval "$1"\n', encoding="utf-8")

    bin_dir = tmpdir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "ubs-python"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    return target, bin_dir


def run_scan(target: Path, bin_dir: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update({
        "NO_COLOR": "1",
        "CI": "1",
        "UBS_NO_AUTO_UPDATE": "1",
        "UBS_ENABLE_AUTO_UPDATE": "0",
        "UBS_NO_CACHE": "1",
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    })
    merged.update(env)
    return subprocess.run(
        [str(UBS_BIN), "--only=python,bash", *args, str(target)],
        cwd=REPO_ROOT, capture_output=True, text=True, env=merged, check=False,
    )


# (case id, stub env, expected status, expected exit, whether text mode is
#  asserted). The real bash scanner runs in every case and always finds its one
#  critical, so every row also proves the healthy scanner's evidence survived.
#
# `garbage-output` is the one case where text mode is NOT asserted. The
# module exits 0 there, so it is outside "a module that exits non-zero must
# never be folded in as success": the JSON path validates the contract
# document and rejects it (bead B10), but the text path still scrapes counts
# out of whatever the module printed. That scrape is the legacy text contract
# and changing it needs a decision across all twelve modules, so the gap is
# tracked separately rather than papered over here.
MATRIX = [
    ("clean-module", {"STUB_MODE": "clean", "STUB_EXIT": "0"}, "ok", 1, True),
    ("findings-exit-1", {"STUB_MODE": "clean", "STUB_EXIT": "1"}, "ok", 1, True),
    ("module-exit-2", {"STUB_MODE": "clean", "STUB_EXIT": "2"}, "partial", 2, True),
    ("module-exit-7", {"STUB_MODE": "clean", "STUB_EXIT": "7"}, "partial", 2, True),
    ("garbage-output", {"STUB_MODE": "garbage", "STUB_EXIT": "0"}, "partial", 2, False),
    # The stub sleeps far longer than the budget, so only it can time out; the
    # budget is still generous enough that the real bash scanner never does.
    ("module-timeout", {"STUB_MODE": "sleep", "STUB_EXIT": "0",
                        "UBS_MODULE_TIMEOUT": "5", "UBS_MODULE_TIMEOUT_GRACE": "1"},
     "partial", 2, True),
]


def check_matrix(tmpdir: Path) -> None:
    target, bin_dir = make_workspace(tmpdir)
    out_dir = tmpdir / "artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)

    for case_id, stub_env, expected_status, expected_exit, assert_text in MATRIX:
        report = out_dir / f"{case_id}.report.json"
        proc = run_scan(target, bin_dir, ["--format=json", f"--report-json={report}"], stub_env)
        blob = proc.stdout + proc.stderr

        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            check(f"{case_id}/json-parses", False, f"stdout is not JSON: {proc.stdout[:200]}")
            continue

        status = str(doc.get("status", "<missing>"))
        check(f"{case_id}/exit-code", proc.returncode == expected_exit,
              f"expected {expected_exit}, got {proc.returncode}\n{blob[-600:]}")
        check(f"{case_id}/report-status", status == expected_status,
              f"expected {expected_status!r}, got {status!r}")

        # The invariant itself: a non-"ok" status and a non-2 exit cannot coexist,
        # and neither can an "ok" status with exit 2.
        incomplete_status = status != "ok"
        incomplete_exit = proc.returncode == 2
        check(f"{case_id}/status-agrees-with-exit", incomplete_status == incomplete_exit,
              f"status={status!r} exit={proc.returncode}")

        failed = doc.get("failed_modules") or []
        check(f"{case_id}/failed-modules-agree", bool(failed) == incomplete_status,
              f"status={status!r} failed_modules={failed}")

        # The bash scanner completed in every case: its critical finding is what
        # "healthy evidence survives" means.
        check(f"{case_id}/healthy-findings-kept",
              int(doc.get("totals", {}).get("critical", 0)) >= 1,
              f"totals={doc.get('totals')}")
        check(f"{case_id}/requested-report-written", report.is_file(),
              f"{report} was requested but not written")

        # Fabricated counts scraped from module text must never reach the report.
        if case_id == "garbage-output":
            check("garbage-output/no-fabricated-counts",
                  "42" not in json.dumps(doc.get("totals", {})) and "99" not in json.dumps(doc.get("totals", {})),
                  f"totals={doc.get('totals')}")

        # Text mode must tell a human the same thing.
        if not assert_text:
            print(f"[status-invariants] SKIP {case_id}/text-mode "
                  "(module exits 0; text-scrape contract tracked separately)")
            continue
        text_proc = run_scan(target, bin_dir, [], stub_env)
        text_blob = text_proc.stdout + text_proc.stderr
        check(f"{case_id}/text-exit-code", text_proc.returncode == expected_exit,
              f"expected {expected_exit}, got {text_proc.returncode}")
        if incomplete_status:
            check(f"{case_id}/text-status-line", f"Status: {expected_status}" in text_blob,
                  f"no 'Status: {expected_status}' line in text output")
        else:
            check(f"{case_id}/text-no-status-line", "Status: partial" not in text_blob
                  and "Status: error" not in text_blob,
                  "a complete run must not print an incomplete status line")


def check_new_only_preserves_execution_state(tmpdir: Path) -> None:
    """--new-only filters findings; it must not filter the failure."""
    target, bin_dir = make_workspace(tmpdir / "new-only")
    baseline = tmpdir / "new-only" / "baseline.json"
    baseline.parent.mkdir(parents=True, exist_ok=True)

    good = run_scan(target, bin_dir, ["--format=json"], {"STUB_MODE": "clean", "STUB_EXIT": "0"})
    baseline.write_text(good.stdout, encoding="utf-8")

    proc = run_scan(target, bin_dir, ["--format=json", f"--baseline={baseline}", "--new-only"],
                    {"STUB_MODE": "clean", "STUB_EXIT": "7"})
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        check("new-only/json-parses", False, proc.stdout[:200])
        return
    check("new-only/status-not-relabelled-ok", str(doc.get("status")) != "ok",
          f"status={doc.get('status')!r} with failed_modules={doc.get('failed_modules')}")
    check("new-only/exit-code", proc.returncode == 2, f"got {proc.returncode}")


def check_incomplete_scan_refuses_baseline(tmpdir: Path) -> None:
    """A partial scan must not overwrite a saved baseline, and a comparison
    against an incomplete observation must be reported unavailable rather than
    as an improvement (issue #104)."""
    target, bin_dir = make_workspace(tmpdir / "baseline")
    work = tmpdir / "baseline"
    good_baseline = work / "complete-baseline.json"

    ok_proc = run_scan(target, bin_dir, ["--format=json", f"--save-baseline={good_baseline}"],
                       {"STUB_MODE": "clean", "STUB_EXIT": "0"})
    check("baseline/complete-scan-saves-baseline", good_baseline.is_file(),
          f"exit={ok_proc.returncode} stderr={ok_proc.stderr[-300:]}")
    before = good_baseline.read_bytes() if good_baseline.is_file() else b""

    report = work / "partial-report.json"
    html = work / "partial.html"
    partial = run_scan(
        target, bin_dir,
        ["--format=json", f"--comparison={good_baseline}", f"--report-json={report}",
         f"--html-report={html}", f"--save-baseline={good_baseline}"],
        {"STUB_MODE": "clean", "STUB_EXIT": "7"},
    )
    check("baseline/partial-scan-exits-2", partial.returncode == 2, f"got {partial.returncode}")
    check("baseline/complete-baseline-not-overwritten",
          good_baseline.read_bytes() == before,
          "an incomplete scan overwrote a complete saved baseline")

    if report.is_file():
        doc = json.loads(report.read_text(encoding="utf-8"))
        comparison = doc.get("comparison") or {}
        check("baseline/comparison-unavailable",
              comparison.get("status") == "unavailable",
              f"comparison={comparison}")
        check("baseline/no-unqualified-delta", "delta" not in comparison,
              f"comparison={comparison}")
    else:
        check("baseline/partial-report-written", False, f"{report} missing")

    if html.is_file():
        markup = html.read_text(encoding="utf-8")
        check("baseline/html-marks-incompleteness",
              "Incomplete scan" in markup, "HTML report has no incompleteness marker")
    else:
        check("baseline/partial-html-written", False, f"{html} missing")

    # A baseline recorded from an incomplete scan must not be usable either.
    hand_made = work / "partial-baseline.json"
    hand_made.write_text(json.dumps({
        "project": str(target), "status": "partial",
        "failed_modules": [{"language": "python", "status": "timeout"}],
        "totals": {"critical": 0, "warning": 0, "info": 0, "files": 1},
        "scanners": [], "findings": [],
    }), encoding="utf-8")
    report2 = work / "compare-partial.json"
    run_scan(target, bin_dir, ["--format=json", f"--comparison={hand_made}",
                               f"--report-json={report2}"],
             {"STUB_MODE": "clean", "STUB_EXIT": "0"})
    if report2.is_file():
        comparison = (json.loads(report2.read_text(encoding="utf-8")).get("comparison") or {})
        check("baseline/incomplete-baseline-rejected",
              comparison.get("status") == "unavailable"
              and comparison.get("reason") == "baseline_incomplete",
              f"comparison={comparison}")
    else:
        check("baseline/compare-partial-written", False, f"{report2} missing")


def check_undeliverable_artifact_fails(tmpdir: Path) -> None:
    """A requested artifact that could not be written must fail the run (#106)."""
    target, bin_dir = make_workspace(tmpdir / "delivery")
    work = tmpdir / "delivery"
    blocker = work / "blocker"
    blocker.write_text("not a directory\n", encoding="utf-8")

    for label, flag in (("report-json", "--report-json"),
                        ("html-report", "--html-report"),
                        ("save-baseline", "--save-baseline")):
        dest = blocker / f"{label}.out"
        proc = run_scan(target, bin_dir, ["--format=json", f"{flag}={dest}"],
                        {"STUB_MODE": "clean", "STUB_EXIT": "0"})
        check(f"delivery/{label}-exit-2", proc.returncode == 2,
              f"expected 2, got {proc.returncode}\n{proc.stderr[-400:]}")
        check(f"delivery/{label}-not-written", not dest.exists(), f"{dest} should not exist")

    # A stale artifact must survive a failed rewrite rather than be truncated:
    # the write is staged beside the destination and renamed into place, so a
    # destination directory that cannot be written to leaves the old file whole.
    readonly = work / "readonly"
    readonly.mkdir(parents=True, exist_ok=True)
    stale = readonly / "report.json"
    original = '{"kept":true,"note":"previous run"}\n'
    stale.write_text(original, encoding="utf-8")
    readonly.chmod(0o555)
    try:
        proc = run_scan(target, bin_dir, ["--format=json", f"--report-json={stale}"],
                        {"STUB_MODE": "clean", "STUB_EXIT": "0"})
        check("delivery/readonly-dir-exit-2", proc.returncode == 2,
              f"expected 2, got {proc.returncode}\n{proc.stderr[-400:]}")
        check("delivery/stale-artifact-preserved",
              stale.read_text(encoding="utf-8") == original,
              "a failed rewrite truncated or replaced the previous artifact")
    finally:
        readonly.chmod(0o755)


def main() -> int:
    tmpdir = Path(tempfile.mkdtemp(prefix="ubs-status-invariants-"))
    try:
        check_matrix(tmpdir)
        check_new_only_preserves_execution_state(tmpdir)
        check_incomplete_scan_refuses_baseline(tmpdir)
        check_undeliverable_artifact_fails(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n[status-invariants] {CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        for item in FAILURES:
            print(f"  ✗ {item}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
