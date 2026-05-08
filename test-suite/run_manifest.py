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
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")
JSON_DECODER = json.JSONDecoder()
SUMMARY_COUNT_KEYS = ("files", "critical", "warning", "info")


def load_manifest(path: Path) -> Dict[str, Any]:
    try:
        data = JSON_DECODER.decode(path.read_text(encoding="utf-8"))
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


def missing_selected_case_ids(
    cases: Sequence[Dict[str, Any]],
    selected_ids: set[str],
) -> List[str]:
    available_ids = {
        case["id"]
        for case in cases
        if isinstance(case.get("id"), str)
    }
    return sorted(selected_ids - available_ids)


def is_nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def has_summary_counts(obj: Dict[str, Any]) -> bool:
    return all(is_nonnegative_int(obj.get(key)) for key in SUMMARY_COUNT_KEYS)


def is_ubs_summary_object(obj: Dict[str, Any]) -> bool:
    totals = obj.get("totals")
    if isinstance(totals, dict) and has_summary_counts(totals):
        return True
    return has_summary_counts(obj)


def extract_json_from_stdout(stdout: str) -> Optional[Dict[str, Any]]:
    """Extract a UBS summary JSON object from stdout, ignoring findings/noise.

    UBS outputs JSONL findings (one per line) followed by text summary.
    When --format=json is used, a summary object with 'totals' key is emitted.
    Direct module JSON output uses top-level count fields instead. Unknown JSON
    objects are treated as noise so malformed summaries cannot satisfy manifest
    expectations by accident.
    """
    decoder = json.JSONDecoder()
    lines = stdout.splitlines()
    for idx, line in enumerate(lines):
        if line.strip().startswith("{"):
            candidate = "\n".join(lines[idx:])
            try:
                # raw_decode stops at end of JSON, ignoring trailing content
                obj, _ = decoder.raw_decode(candidate)
                if isinstance(obj, dict):
                    if is_ubs_summary_object(obj):
                        return obj
                    if "ruleId" in obj or ("severity" in obj and "message" in obj):
                        continue
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


def parse_toon_summary(stdout: str, project_label: str) -> Optional[Dict[str, Any]]:
    """Parse UBS --format=toon output to extract aggregate totals.

    TOON output is YAML-like with a top-level ``scanners[N]:`` array whose
    entries each expose ``critical``, ``warning``, ``info``, and ``files``
    keys. Totals are the sum across scanners so the manifest's min/max
    assertions continue to work regardless of format.
    """
    if "scanners[" not in stdout or "findings[" not in stdout:
        return None
    totals = {"critical": 0, "warning": 0, "info": 0, "files": 0}
    found_any = False
    pattern = re.compile(r"^\s+(critical|warning|info|files):\s*(\d+)\s*$")
    for line in stdout.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        key = m.group(1)
        totals[key] += int(m.group(2))
        found_any = True
    if not found_any:
        return None
    return {
        "project": project_label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": totals,
    }


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def timeout_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


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
    totals: Dict[str, Any] = {}
    if summary and isinstance(summary, dict):
        totals = summary.get("totals", {}) or {}
        if not isinstance(totals, dict) or not totals:
            totals = {
                "critical": summary.get("critical", 0),
                "warning": summary.get("warning", 0),
                "info": summary.get("info", 0),
                "files": summary.get("files", 0),
            }
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
    parser.add_argument(
        "--case-timeout",
        type=int,
        default=int(os.environ.get("UBS_MANIFEST_CASE_TIMEOUT", "120")),
        help="Per-case timeout in seconds; set to 0 to disable (default: 120 or UBS_MANIFEST_CASE_TIMEOUT)",
    )
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
    missing_case_ids = missing_selected_case_ids(cases, selected_ids)
    if missing_case_ids:
        for case_id in missing_case_ids:
            print(f"[{case_id}] FAIL\n  - no such manifest case id", file=sys.stderr)
        sys.exit(1)

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

        print(f"[{case_id}] RUN {case_path_arg}", flush=True)
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
        try:
            proc = subprocess.run(
                cmd,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                env=env,
                timeout=args.case_timeout if args.case_timeout > 0 else None,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.time() - start
            stdout_path.write_text(timeout_output(exc.stdout))
            stderr_text = timeout_output(exc.stderr)
            if stderr_text and not stderr_text.endswith("\n"):
                stderr_text += "\n"
            stderr_text += f"Timed out after {args.case_timeout}s\n"
            stderr_path.write_text(stderr_text)
            summary_path.write_text(
                json.dumps(
                    {
                        "id": case_id,
                        "command": cmd,
                        "duration_sec": duration,
                        "timeout_sec": args.case_timeout,
                        "timed_out": True,
                        "summary": None,
                    },
                    indent=2,
                )
            )
            failures += 1
            print(format_case_result(case_id, "fail", duration, [f"timed out after {args.case_timeout}s"]))
            if args.fail_fast:
                break
            continue
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
                summary = parse_toon_summary(proc.stdout, case_path_arg)
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
