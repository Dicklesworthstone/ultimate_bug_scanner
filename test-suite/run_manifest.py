#!/usr/bin/env python3
"""Manifest-driven UBS test runner.

Reads test-suite/manifest.json, executes UBS per case, and enforces
expectations (exit codes, severity counts, substring hints). Artifacts
(stdout/stderr/result.json) are captured under test-suite/artifacts/<case>.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")


def load_manifest(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        sys.exit(f"Manifest not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"Invalid JSON in manifest {path}: {exc}")
    if "cases" not in data or not isinstance(data["cases"], list):
        sys.exit("Manifest must contain a 'cases' array")
    return data


def resolve_path(base: Path, value: str) -> Path:
    p = Path(value)
    if p.is_absolute():
        return p
    return (base / p).resolve()


def extract_json_from_stdout(stdout: str) -> Optional[Dict[str, Any]]:
    lines = stdout.splitlines()
    for idx, line in enumerate(lines):
        if line.strip().startswith("{"):
            candidate = "\n".join(lines[idx:])
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    return None


def parse_text_summary(stdout: str, project_label: str) -> Optional[Dict[str, Any]]:
    marker = "──────── Combined Summary"
    if marker not in stdout:
        return None
    block = stdout.split(marker, 1)[-1]
    files = re.search(r"Files:\s+(\d+)", block)
    critical = re.search(r"Critical:\s+(\d+)", block)
    warning = re.search(r"Warning:\s+(\d+)", block)
    info = re.search(r"Info:\s+(\d+)", block)
    if not (files and critical and warning and info):
        return None
    return {
        "project": project_label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": {
            "files": int(files.group(1)),
            "critical": int(critical.group(1)),
            "warning": int(warning.group(1)),
            "info": int(info.group(1)),
        },
    }


def parse_module_text_summary(stdout: str, project_label: str) -> Optional[Dict[str, Any]]:
    marker = "Summary Statistics:"
    if marker not in stdout:
        return None
    block = stdout.split(marker, 1)[-1]
    files = re.search(r"Files scanned:\s+(\d+)", block)
    critical = re.search(r"Critical issues:\s+(\d+)", block)
    warning = re.search(r"Warning issues:\s+(\d+)", block)
    info = re.search(r"Info items:\s+(\d+)", block)
    if not (files and critical and warning and info):
        return None
    return {
        "project": project_label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": {
            "files": int(files.group(1)),
            "critical": int(critical.group(1)),
            "warning": int(warning.group(1)),
            "info": int(info.group(1)),
        },
    }


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def check_expectations(
    expect: Dict[str, Any],
    exit_code: int,
    summary: Optional[Dict[str, Any]],
    stdout: str,
    stderr: str,
    fail_on_warning: bool,
) -> List[str]:
    errors: List[str] = []
    derived_exit = exit_code
    if summary and isinstance(summary, dict):
        totals = summary.get("totals", {}) or {}
        critical = int(totals.get("critical", 0) or 0)
        warning = int(totals.get("warning", 0) or 0)
        if critical > 0:
            derived_exit = 1
        else:
            derived_exit = 0
        if fail_on_warning and (critical + warning) > 0:
            derived_exit = 1
    if expect:
        need = expect.get("exit_code")
        if isinstance(need, int):
            if exit_code != need:
                errors.append(f"expected exit {need} but got {exit_code}")
        elif isinstance(need, str) and need.isdigit():
            expected_code = int(need)
            if exit_code != expected_code:
                errors.append(f"expected exit {expected_code} but got {exit_code}")
        elif need == "zero" and derived_exit != 0:
            errors.append(f"expected exit 0 but derived {derived_exit}")
        elif need == "nonzero" and derived_exit == 0:
            errors.append("expected non-zero exit but derived 0")
    totals_expect = (expect or {}).get("totals", {})
    totals = (summary or {}).get("totals", {}) if summary else {}
    for severity, limits in totals_expect.items():
        observed = int(totals.get(severity, 0) or 0)
        lower = limits.get("min")
        upper = limits.get("max")
        if lower is not None and observed < lower:
            errors.append(f"{severity} count {observed} < min {lower}")
        if upper is not None and observed > upper:
            errors.append(f"{severity} count {observed} > max {upper}")
    for substring in (expect or {}).get("require_substrings", []) or []:
        if substring not in stdout:
            errors.append(f"missing substring '{substring}' in stdout")
    for substring in (expect or {}).get("forbid_substrings", []) or []:
        if substring in stdout:
            errors.append(f"forbidden substring '{substring}' present in stdout")
    for substring in (expect or {}).get("require_substrings_stderr", []) or []:
        if substring not in stderr:
            errors.append(f"missing substring '{substring}' in stderr")
    for substring in (expect or {}).get("forbid_substrings_stderr", []) or []:
        if substring in stderr:
            errors.append(f"forbidden substring '{substring}' present in stderr")
    return errors


def format_case_result(case_id: str, status: str, duration: float, details: Sequence[str]) -> str:
    header = f"[{case_id}] {status.upper()} ({duration:.2f}s)"
    if not details:
        return header
    body = "\n  - ".join(["" ] + list(details))
    return f"{header}{body}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run UBS manifest cases")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--case", dest="cases", action="append", help="Run only matching case id (can repeat)")
    parser.add_argument("--list", action="store_true", help="List available case ids and exit")
    parser.add_argument("--fail-fast", action="store_true", help="Stop after first failure")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    defaults = manifest.get("defaults", {})
    cases: List[Dict[str, Any]] = manifest["cases"]

    if args.list:
        for entry in cases:
            status = "enabled" if entry.get("enabled", True) else "disabled"
            print(f"{entry.get('id')}: {status} :: {entry.get('description','').strip()}")
        return

    selected_ids = set(args.cases or [])

    manifest_dir = args.manifest.parent
    artifacts_root = resolve_path(manifest_dir, defaults.get("artifacts_dir", "artifacts"))
    ensure_dir(artifacts_root)

    ubs_bin = defaults.get("ubs_bin", "../ubs")
    ubs_path = resolve_path(manifest_dir, ubs_bin)
    default_args = defaults.get("args", [])
    default_env = {k: str(v) for k, v in (defaults.get("env", {}) or {}).items()}

    failures = 0
    skipped = 0
    total = 0

    for case in cases:
        case_id = case.get("id")
        if not case_id:
            print("Encountered case without id, skipping", file=sys.stderr)
            continue
        if selected_ids and case_id not in selected_ids:
            continue
        total += 1
        if not case.get("enabled", True):
            skipped += 1
            print(format_case_result(case_id, "skipped", 0.0, [case.get("skip_reason", "disabled in manifest")]))
            continue

        case_path_abs = resolve_path(REPO_ROOT, case["path"])
        case_path_arg = os.path.relpath(case_path_abs, REPO_ROOT)
        case_args = case.get("args", [])
        case_ubs_bin = case.get("ubs_bin")
        case_ubs_path = resolve_path(manifest_dir, case_ubs_bin) if case_ubs_bin else ubs_path
        cmd = [str(case_ubs_path), *default_args, *case_args, case_path_arg]
        env = os.environ.copy()
        env.update(default_env)
        env.update({k: str(v) for k, v in (case.get("env", {}) or {}).items()})
        if (case.get("language") or "").lower() == "python":
            env.setdefault("ENABLE_UV_TOOLS", "0")

        artifacts_dir = artifacts_root / case_id
        ensure_dir(artifacts_dir)
        shims = case.get("bin_shims") or {}
        stdout_path = artifacts_dir / "stdout.log"
        stderr_path = artifacts_dir / "stderr.log"
        summary_path = artifacts_dir / "result.json"

        start = time.time()
        if shims:
            shim_dir = artifacts_dir / "bin_shims"
            ensure_dir(shim_dir)
            for name, body in shims.items():
                shim_path = shim_dir / name
                shim_path.write_text(str(body))
                try:
                    shim_path.chmod(0o755)
                except OSError:
                    pass
            env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"
        proc = subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True, env=env)
        duration = time.time() - start
        stdout_path.write_text(proc.stdout)
        stderr_path.write_text(proc.stderr)
        summary = extract_json_from_stdout(proc.stdout)
        summary_error = None
        if summary is None:
            summary = parse_text_summary(proc.stdout, case_path_arg)
            if summary is None:
                summary = parse_module_text_summary(proc.stdout, case_path_arg)
            if summary is None:
                allow_unparseable = bool((case.get("expect") or {}).get("allow_unparseable_output", False))
                if not allow_unparseable:
                    summary_error = "Unable to parse UBS output"
        summary_blob = {
            "id": case_id,
            "command": cmd,
            "exit_code": proc.returncode,
            "duration_sec": duration,
            "summary": summary
        }
        summary_path.write_text(json.dumps(summary_blob, indent=2))

        fail_on_warning = any(arg == "--fail-on-warning" for arg in cmd)
        errors = check_expectations(
            case.get("expect", {}),
            proc.returncode,
            summary if isinstance(summary, dict) else None,
            proc.stdout,
            proc.stderr,
            fail_on_warning,
        )
        status = "pass"
        if summary_error:
            errors.append(summary_error)
        if errors:
            failures += 1
            status = "fail"
        print(format_case_result(case_id, status, duration, errors))
        if errors and args.fail_fast:
            break

    print(f"\nCompleted {total} case(s) with {failures} failure(s) and {skipped} skipped.")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
