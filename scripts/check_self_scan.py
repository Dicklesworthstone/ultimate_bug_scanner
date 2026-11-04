#!/usr/bin/env python3
"""Require complete, warning-free UBS coverage before a release can mutate Git."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SELF_SCAN_TIMEOUT_SECONDS = 1800


class SelfScanError(ValueError):
    """The self-scan did not provide sufficient evidence for a release."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise SelfScanError(f"duplicate JSON field: {name}")
        result[name] = value
    return result


def reject_constant(value: str) -> object:
    raise SelfScanError(f"non-JSON numeric constant: {value}")


def validate_report(report: object) -> int:
    """Validate completion separately from finding counts; return files scanned.

    Exit status alone is insufficient: developer escape hatches can let a
    partial or empty scan exit zero. Require both the aggregate result and
    every selected language to attest completion, with consistent counters.
    """
    if not isinstance(report, dict) or report.get("status") != "ok":
        raise SelfScanError("self-scan status must be 'ok'")
    if report.get("failed_modules") != []:
        raise SelfScanError("failed_modules must be present and empty")
    totals = report.get("totals")
    scanners = report.get("scanners")
    if not isinstance(totals, dict) or not isinstance(scanners, list) or not scanners:
        raise SelfScanError("self-scan must contain totals and scanner results")
    counts = {"files": 0, "critical": 0, "warning": 0}
    seen: set[str] = set()
    for scanner in scanners:
        if not isinstance(scanner, dict):
            raise SelfScanError("invalid scanner result")
        name = scanner.get("language")
        if not isinstance(name, str) or not name or name in seen:
            raise SelfScanError("scanner languages must be nonempty and unique")
        seen.add(name)
        if scanner.get("status") != "ok":
            raise SelfScanError(f"incomplete scanner result: {name}")
        for key in counts:
            value = scanner.get(key)
            # bool is an int subclass, but is not a valid finding/file count.
            if type(value) is not int or value < 0:
                raise SelfScanError(f"invalid {key} count for {name}")
            counts[key] += value
    for key, value in counts.items():
        if type(totals.get(key)) is not int or totals[key] != value:
            raise SelfScanError(f"aggregate {key} count disagrees with scanners")
    if counts["files"] == 0:
        raise SelfScanError("self-scan did not scan any files")
    if counts["critical"] or counts["warning"]:
        raise SelfScanError(
            f"self-scan found {counts['critical']} critical and {counts['warning']} warning issues"
        )
    return counts["files"]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.update({
        "UBS_ALLOW_PARTIAL": "0",
        "UBS_ALLOW_NO_SCAN": "0",
        "UBS_NO_AUTO_UPDATE": "1",
        "UBS_ENABLE_AUTO_UPDATE": "0",
        "UBS_NO_CACHE": "1",
    })
    # Spool potentially large findings rather than buffering subprocess output
    # in memory. On failure retain the actual report in the release log, not
    # just a zero aggregate or an opaque validator error.
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
            process = subprocess.run(
                [str(root / "ubs"), ".", "--ci", "--fail-on-warning", "--format=json"],
                cwd=root, env=env, stdout=output, check=False,
                timeout=SELF_SCAN_TIMEOUT_SECONDS,
            )
            output.seek(0)
            try:
                if process.returncode != 0:
                    raise SelfScanError(f"scanner exited {process.returncode}")
                report = json.load(
                    output, object_pairs_hook=unique_object, parse_constant=reject_constant,
                )
                files = validate_report(report)
            except (ValueError, UnicodeError) as exc:
                print(f"cut-release: self-scan rejected: {exc}", file=sys.stderr)
                output.seek(0)
                # Preserve diagnostics even when the scanner returned invalid UTF-8.
                shutil.copyfileobj(output.buffer, sys.stderr.buffer)
                return 1
    except OSError as exc:
        print(f"cut-release: could not run self-scan: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("cut-release: self-scan exceeded its 30-minute release budget", file=sys.stderr)
        return 1
    print(f"Self-scan complete: {files} files, 0 critical, 0 warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
