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
EXPECT_SUBSTRING_KEYS = (
    "require_substrings",
    "forbid_substrings",
    "require_substrings_stderr",
    "forbid_substrings_stderr",
)


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


def empty_manifest_error(cases: Sequence[Dict[str, Any]]) -> str | None:
    if not cases:
        return "manifest must contain at least one case"
    return None


def parse_shard(spec: Optional[str]) -> Optional[tuple[int, int]]:
    """--shard I/N: run the I-th of N deterministic slices (1-based)."""
    if not spec:
        return None
    try:
        index_text, total_text = spec.split("/", 1)
        index, total = int(index_text), int(total_text)
    except ValueError as exc:
        raise SystemExit(f"--shard expects I/N (e.g. 2/4), got {spec!r}") from exc
    if total < 1 or index < 1 or index > total:
        raise SystemExit(f"--shard {spec}: need 1 <= I <= N")
    return index, total


def shard_case_ids(case_ids: List[str], index: int, total: int) -> set[str]:
    """Deterministic, order-preserving split: case k (0-based, in manifest
    order) belongs to shard (k % N) + 1. Every case lands in exactly one shard
    and the shards differ in size by at most one."""
    return {case_id for k, case_id in enumerate(case_ids) if k % total == index - 1}


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


def invalid_case_id_labels(cases: Sequence[Dict[str, Any]]) -> List[str]:
    return [
        f"manifest case #{index + 1}"
        for index, case in enumerate(cases)
        if not isinstance(case.get("id"), str) or not case["id"].strip()
    ]


def duplicate_case_ids(cases: Sequence[Dict[str, Any]]) -> List[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for case in cases:
        case_id = case.get("id")
        if not isinstance(case_id, str):
            continue
        if case_id in seen:
            duplicates.add(case_id)
        seen.add(case_id)
    return sorted(duplicates)


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def string_list_errors(value: Any, label: str) -> List[str]:
    if not isinstance(value, list):
        return [f"{label} must be a list of strings"]
    errors: List[str] = []
    for index, item in enumerate(value):
        if not nonempty_string(item):
            errors.append(f"{label}[{index}] must be a non-empty string")
    return errors


def env_mapping_errors(value: Any, label: str) -> List[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object with string keys and string values"]
    errors: List[str] = []
    for key, item in value.items():
        if not nonempty_string(key):
            errors.append(f"{label} has a non-string or empty key")
        if not isinstance(item, str):
            errors.append(f"{label}.{key} must be a string")
    return errors


def shim_mapping_errors(value: Any, label: str) -> List[str]:
    if not isinstance(value, dict):
        return [f"{label} must be an object with executable names mapped to script text"]
    errors: List[str] = []
    for key, item in value.items():
        if not nonempty_string(key):
            errors.append(f"{label} has a non-string or empty executable name")
        if not isinstance(item, str):
            errors.append(f"{label}.{key} must be script text")
    return errors


def expect_schema_errors(expect: Any, label: str) -> List[str]:
    if expect is None:
        return []
    if not isinstance(expect, dict):
        return [f"{label}.expect must be an object"]
    errors: List[str] = []
    exit_code = expect.get("exit_code")
    if exit_code is not None:
        if type(exit_code) is int:
            if exit_code < 0:
                errors.append(f"{label}.expect.exit_code must be non-negative")
        elif isinstance(exit_code, str):
            if exit_code not in {"zero", "nonzero"} and not exit_code.isdigit():
                errors.append(
                    f"{label}.expect.exit_code must be zero, nonzero, or a numeric string"
                )
        else:
            errors.append(f"{label}.expect.exit_code must be an integer or string")

    totals = expect.get("totals")
    if totals is not None:
        if not isinstance(totals, dict):
            errors.append(f"{label}.expect.totals must be an object")
        else:
            for severity, limits in totals.items():
                if severity not in SUMMARY_COUNT_KEYS:
                    errors.append(
                        f"{label}.expect.totals.{severity} is not a supported count key"
                    )
                    continue
                if not isinstance(limits, dict):
                    errors.append(f"{label}.expect.totals.{severity} must be an object")
                    continue
                for bound, value in limits.items():
                    if bound not in {"min", "max"}:
                        errors.append(
                            f"{label}.expect.totals.{severity}.{bound} is not supported"
                        )
                    elif not is_nonnegative_int(value):
                        errors.append(
                            f"{label}.expect.totals.{severity}.{bound} must be a non-negative integer"
                        )

    for key in EXPECT_SUBSTRING_KEYS:
        if key in expect:
            errors.extend(string_list_errors(expect[key], f"{label}.expect.{key}"))

    for key in ("allow_unparseable_output", "allow_zero_files", "findings_json_valid"):
        if key in expect and type(expect[key]) is not bool:
            errors.append(f"{label}.expect.{key} must be a boolean")

    if "sarif" in expect:
        sarif_expect = expect["sarif"]
        if not isinstance(sarif_expect, dict) or not sarif_expect:
            errors.append(f"{label}.expect.sarif must be a non-empty object")
        else:
            for key, value in sarif_expect.items():
                if key in ("min_runs", "min_results"):
                    if not is_nonnegative_int(value):
                        errors.append(f"{label}.expect.sarif.{key} must be a non-negative integer")
                elif key in ("require_rule_ids", "forbid_rule_ids"):
                    errors.extend(string_list_errors(value, f"{label}.expect.sarif.{key}"))
                else:
                    errors.append(f"{label}.expect.sarif.{key} is not supported")

    return errors


def manifest_schema_errors(manifest: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    defaults = manifest.get("defaults", {})
    if not isinstance(defaults, dict):
        errors.append("defaults must be an object")
        defaults = {}
    else:
        if "ubs_bin" in defaults and not nonempty_string(defaults["ubs_bin"]):
            errors.append("defaults.ubs_bin must be a non-empty string")
        if "artifacts_dir" in defaults and not nonempty_string(defaults["artifacts_dir"]):
            errors.append("defaults.artifacts_dir must be a non-empty string")
        if "args" in defaults:
            errors.extend(string_list_errors(defaults["args"], "defaults.args"))
        if "env" in defaults:
            errors.extend(env_mapping_errors(defaults["env"], "defaults.env"))

    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        return [*errors, "cases must be an array"]
    if not cases:
        return [*errors, "cases must contain at least one case"]
    for index, case in enumerate(cases):
        label = f"manifest case #{index + 1}"
        if not isinstance(case, dict):
            errors.append(f"{label} must be an object")
            continue
        case_id = case.get("id")
        if nonempty_string(case_id):
            label = f"case {case_id}"
        for key in ("id", "path", "language", "description"):
            if not nonempty_string(case.get(key)):
                errors.append(f"{label}.{key} must be a non-empty string")
        path = case.get("path")
        if isinstance(path, str) and path.strip():
            if not resolve_path(REPO_ROOT, path).exists():
                errors.append(f"{label}.path does not exist: {path}")
        tags = case.get("tags")
        if tags is not None:
            errors.extend(string_list_errors(tags, f"{label}.tags"))
        if "enabled" in case and type(case["enabled"]) is not bool:
            errors.append(f"{label}.enabled must be a boolean")
        if "ubs_bin" in case and not nonempty_string(case["ubs_bin"]):
            errors.append(f"{label}.ubs_bin must be a non-empty string")
        if "args" in case:
            errors.extend(string_list_errors(case["args"], f"{label}.args"))
        if "env" in case:
            errors.extend(env_mapping_errors(case["env"], f"{label}.env"))
        if "bin_shims" in case:
            errors.extend(shim_mapping_errors(case["bin_shims"], f"{label}.bin_shims"))
        errors.extend(expect_schema_errors(case.get("expect"), label))

    return errors


def disabled_case_ids(
    cases: Sequence[Dict[str, Any]],
    selected_ids: set[str],
) -> List[str]:
    selected_scope = selected_ids or {
        case["id"]
        for case in cases
        if isinstance(case.get("id"), str)
    }
    return sorted(
        case["id"]
        for case in cases
        if isinstance(case.get("id"), str)
        and case["id"] in selected_scope
        and not bool(case.get("enabled", True))
    )


def is_nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def has_summary_counts(obj: Dict[str, Any]) -> bool:
    return all(is_nonnegative_int(obj.get(key)) for key in SUMMARY_COUNT_KEYS)


def is_error_envelope(obj: Dict[str, Any]) -> bool:
    """The machine-format error envelope (environment error or refused scan):
    {"error": ..., "status": ..., "reason": ..., "exit_code": 2, ...}. It carries
    no totals because nothing was scanned; cases assert on exit code and
    substrings (see `ubs --schema=error`)."""
    return isinstance(obj.get("error"), str) and isinstance(obj.get("exit_code"), int) and "reason" in obj


def is_ubs_summary_object(obj: Dict[str, Any]) -> bool:
    totals = obj.get("totals")
    if isinstance(totals, dict) and has_summary_counts(totals):
        return True
    if is_error_envelope(obj):
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
                        if is_error_envelope(obj) and not isinstance(obj.get("totals"), dict):
                            obj = {**obj, "totals": {"critical": 0, "warning": 0, "info": 0, "files": 0}}
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


SARIF_LEVEL_TO_SEVERITY = {"error": "critical", "warning": "warning", "note": "info", "none": "info"}


def parse_sarif_summary(stdout: str, project_label: str) -> Optional[Dict[str, Any]]:
    """Parse a SARIF 2.1.0 document (``ubs --format=sarif``) into a summary.

    Totals are derived from result levels (error → critical, warning → warning,
    note/none → info); ``files`` counts the distinct artifact URIs the results
    point at. The extra ``sarif`` block (run count, result count, rule ids)
    feeds the manifest's ``expect.sarif`` assertions, which is how the
    meta-runner's merged SARIF output is regression-tested end to end.
    """
    stripped = stdout.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        doc, _ = JSON_DECODER.raw_decode(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict) or "runs" not in doc or "version" not in doc:
        return None
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None
    totals = {"critical": 0, "warning": 0, "info": 0, "files": 0}
    rule_ids: set = set()
    uris: set = set()
    result_count = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            result_count += 1
            severity = SARIF_LEVEL_TO_SEVERITY.get(str(result.get("level", "warning")).lower(), "warning")
            totals[severity] += 1
            rule_id = result.get("ruleId")
            if isinstance(rule_id, str) and rule_id:
                rule_ids.add(rule_id)
            for location in result.get("locations") or []:
                uri = (((location or {}).get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                if isinstance(uri, str) and uri:
                    uris.add(uri)
    totals["files"] = len(uris)
    return {
        "project": project_label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": totals,
        "sarif": {
            "runs": len(runs),
            "results": result_count,
            "rule_ids": sorted(rule_ids),
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
        if int(totals.get("files", 0) or 0) <= 0 and not bool(
            (expect or {}).get("allow_zero_files", False)
        ):
            errors.append("summary reported zero scanned files")
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
    sarif_expect = (expect or {}).get("sarif")
    if isinstance(sarif_expect, dict) and sarif_expect:
        sarif = (summary or {}).get("sarif") if isinstance(summary, dict) else None
        if not isinstance(sarif, dict):
            errors.append("expect.sarif set but stdout was not a SARIF document")
        else:
            min_runs = sarif_expect.get("min_runs")
            if min_runs is not None and int(sarif.get("runs", 0)) < int(min_runs):
                errors.append(f"sarif runs {sarif.get('runs', 0)} < min {min_runs}")
            min_results = sarif_expect.get("min_results")
            if min_results is not None and int(sarif.get("results", 0)) < int(min_results):
                errors.append(f"sarif results {sarif.get('results', 0)} < min {min_results}")
            observed_ids = set(sarif.get("rule_ids") or [])
            for rule_id in sarif_expect.get("require_rule_ids", []) or []:
                if rule_id not in observed_ids:
                    errors.append(f"missing SARIF rule id '{rule_id}'")
            for rule_id in sarif_expect.get("forbid_rule_ids", []) or []:
                if rule_id in observed_ids:
                    errors.append(f"forbidden SARIF rule id '{rule_id}' present")
    return errors


def findings_json_errors(path: Path) -> List[str]:
    """Validate a module's --emit-findings-json artifact (GH #69, #71).

    Source samples are copied verbatim into JSON strings, so an emitter that
    forgets to escape a quote, backslash, or control character produces a file
    that no JSON parser accepts. Parsing it here is the regression guard.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"findings JSON not readable at {path}: {exc}"]
    try:
        data = JSON_DECODER.decode(raw)
    except json.JSONDecodeError as exc:
        return [f"findings JSON is not valid JSON ({exc})"]
    if not isinstance(data, dict):
        return ["findings JSON must be an object"]
    findings = data.get("findings")
    if not isinstance(findings, list) or not findings:
        return ["findings JSON contains no findings array"]
    for finding in findings:
        samples = finding.get("samples") if isinstance(finding, dict) else None
        if samples is not None and not isinstance(samples, list):
            return ["findings JSON samples must be an array"]
    return []


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
    parser.add_argument("--shard", help="Run only slice I of N (I/N, 1-based) of the enabled cases, split deterministically in manifest order")
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

    empty_error = empty_manifest_error(cases)
    if empty_error:
        print(f"[manifest] FAIL\n  - {empty_error}", file=sys.stderr)
        sys.exit(1)

    schema_errors = manifest_schema_errors(manifest)
    if schema_errors:
        print(
            format_case_result("manifest", "fail", 0.0, schema_errors),
            file=sys.stderr,
        )
        sys.exit(1)

    invalid_case_ids = invalid_case_id_labels(cases)
    if invalid_case_ids:
        for case_label in invalid_case_ids:
            print(f"[{case_label}] FAIL\n  - manifest case lacks a non-empty id", file=sys.stderr)
        sys.exit(1)
    duplicate_ids = duplicate_case_ids(cases)
    if duplicate_ids:
        for case_id in duplicate_ids:
            print(f"[{case_id}] FAIL\n  - duplicate manifest case id", file=sys.stderr)
        sys.exit(1)

    selected_ids = set(args.cases or [])
    missing_case_ids = missing_selected_case_ids(cases, selected_ids)
    if missing_case_ids:
        for case_id in missing_case_ids:
            print(f"[{case_id}] FAIL\n  - no such manifest case id", file=sys.stderr)
        sys.exit(1)
    disabled_ids = disabled_case_ids(cases, selected_ids)
    if disabled_ids:
        for case_id in disabled_ids:
            print(f"[{case_id}] FAIL\n  - manifest case is disabled/skipped", file=sys.stderr)
        sys.exit(1)

    shard = parse_shard(args.shard)
    if shard is not None:
        runnable_ids = [c["id"] for c in cases if c.get("id") and c.get("enabled", True) and (not selected_ids or c["id"] in selected_ids)]
        shard_ids = shard_case_ids(runnable_ids, *shard)
        print(f"[manifest] shard {shard[0]}/{shard[1]}: {len(shard_ids)} of {len(runnable_ids)} enabled case(s)", flush=True)
        selected_ids = shard_ids or {"__no_case_in_this_shard__"}

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
        artifacts_dir = artifacts_root / case_id
        ensure_dir(artifacts_dir)
        case_expect = case.get("expect", {}) or {}
        extra_args: List[str] = []
        findings_json_path: Optional[Path] = None
        if bool(case_expect.get("findings_json_valid", False)):
            findings_json_path = artifacts_dir / "findings.json"
            # Poison the target first: a module that never writes the artifact
            # must not be able to pass on a stale file from an earlier run.
            findings_json_path.write_text("not written by this run\n")
            extra_args.append(f"--emit-findings-json={findings_json_path}")
        cmd = [str(case_ubs_path), *default_args, *case_args, *extra_args, case_path_arg]
        env = os.environ.copy()
        env.update(default_env)
        env.update({k: str(v) for k, v in (case.get("env", {}) or {}).items()})
        if (case.get("language") or "").lower() == "python":
            env.setdefault("ENABLE_UV_TOOLS", "0")

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
                summary = parse_sarif_summary(proc.stdout, case_path_arg)
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
        if findings_json_path is not None:
            errors.extend(findings_json_errors(findings_json_path))
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
