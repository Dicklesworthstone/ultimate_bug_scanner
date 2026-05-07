#!/usr/bin/env python3
"""Quality gates for UBS rule coverage and rule robustness.

This harness intentionally invokes the real UBS binaries against real fixture
files. It does not mock scanner output; the goal is to catch detector drift,
crashes, invalid runtime assumptions, and missing regression coverage.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess  # nosec B404 - this harness intentionally runs repo-local UBS commands.
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_ROOT = REPO_ROOT / "test-suite"
GOLDEN_PATH = TEST_ROOT / "goldens" / "rule_coverage.json"
RUNTIME_ROOT = Path(
    os.environ.get(
        "UBS_RULE_QUALITY_TMP",
        str(REPO_ROOT / "rule-quality-variants"),
    )
)

SECURITY_COVERAGE_LANGUAGES = {
    "cpp",
    "csharp",
    "elixir",
    "golang",
    "java",
    "js",
    "python",
    "ruby",
    "rust",
    "swift",
}
SMOKE_CASE_IDS = (
    "cpp-open-redirect-buggy",
    "cpp-open-redirect-clean",
    "csharp-open-redirect-buggy",
    "csharp-open-redirect-clean",
    "elixir-open-redirect-buggy",
    "elixir-open-redirect-clean",
    "java-open-redirect-buggy",
    "java-open-redirect-clean",
    "js-typescript-request-body-limit-buggy",
    "js-typescript-request-body-limit-clean",
    "kotlin-open-redirect-buggy",
    "kotlin-open-redirect-clean",
    "python-redos-regex-buggy",
    "python-redos-regex-clean",
    "ruby-open-redirect-buggy",
    "ruby-open-redirect-clean",
    "golang-request-body-limit-buggy",
    "golang-request-body-limit-clean",
    "rust-request-body-limit-buggy",
    "rust-request-body-limit-clean",
    "swift-open-redirect-buggy",
    "swift-open-redirect-clean",
)
CLEAN_FUZZ_CASE_IDS = (
    "cpp-open-redirect-clean",
    "csharp-open-redirect-clean",
    "elixir-open-redirect-clean",
    "java-open-redirect-clean",
    "js-typescript-request-body-limit-clean",
    "kotlin-open-redirect-clean",
    "python-redos-regex-clean",
    "ruby-open-redirect-clean",
    "golang-open-redirect-clean",
    "golang-request-body-limit-clean",
    "golang-ssrf-clean",
    "rust-request-body-limit-clean",
    "swift-open-redirect-clean",
)
METAMORPHIC_CASE_IDS = (
    *SMOKE_CASE_IDS,
    "js-typescript-sql-injection-buggy",
    "js-typescript-sql-injection-clean",
    "golang-open-redirect-buggy",
    "golang-open-redirect-clean",
    "golang-ssrf-buggy",
    "golang-ssrf-clean",
    "rust-sql-injection-buggy",
    "rust-sql-injection-clean",
)
JSON_DECODER = json.JSONDecoder()

sys.path.insert(0, str(TEST_ROOT))
from run_manifest import (  # noqa: E402
    check_expectations,
    extract_json_from_stdout,
    parse_module_text_summary,
    parse_text_summary,
    parse_toon_summary,
)


def load_manifest() -> dict[str, Any]:
    path = TEST_ROOT / "manifest.json"
    try:
        payload = JSON_DECODER.decode(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssertionError(f"invalid JSON in {path.relative_to(REPO_ROOT)}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"{path.relative_to(REPO_ROOT)} must contain a JSON object")
    return payload


def normalize_case_path(path: str) -> str:
    return path.replace("\\", "/")


def camel_to_snake(value: str) -> str:
    value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.replace("-", "_").lower()


def case_side_and_slug(case: dict[str, Any]) -> tuple[str | None, str | None]:
    path = normalize_case_path(case["path"])
    parts = path.split("/")
    side = None
    if "buggy" in parts:
        side = "buggy"
    elif "clean" in parts:
        side = "clean"

    stem = Path(path).stem
    for suffix, suffix_side in (
        ("-buggy", "buggy"),
        ("_buggy", "buggy"),
        ("-clean", "clean"),
        ("_clean", "clean"),
    ):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            side = side or suffix_side
            break
    else:
        for suffix, suffix_side in (("Buggy", "buggy"), ("Clean", "clean")):
            if stem.endswith(suffix):
                stem = camel_to_snake(stem[: -len(suffix)])
                side = side or suffix_side
                break
        else:
            case_id = case.get("id", "")
            for suffix, suffix_side in (("-buggy", "buggy"), ("-clean", "clean")):
                if case_id.endswith(suffix):
                    stem = case_id[: -len(suffix)]
                    prefix = f"{case.get('language', '')}-"
                    if prefix != "-" and stem.startswith(prefix):
                        stem = stem[len(prefix):]
                    side = side or suffix_side
                    break
    if side is None:
        return None, None
    if path.startswith("test-suite/kotlin/"):
        stem = f"kotlin_{stem}"
    return side, stem


def build_rule_coverage(manifest: dict[str, Any]) -> dict[str, Any]:
    cases = manifest["cases"]
    ids = [case["id"] for case in cases]
    duplicate_ids = sorted(case_id for case_id in set(ids) if ids.count(case_id) > 1)
    if duplicate_ids:
        raise AssertionError(f"manifest case ids must be unique: {duplicate_ids}")

    missing_paths = [
        case["id"]
        for case in cases
        if not (REPO_ROOT / case["path"]).exists()
    ]
    if missing_paths:
        raise AssertionError(f"manifest paths do not exist: {missing_paths}")

    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for case in cases:
        language = case.get("language")
        tags = set(case.get("tags", []))
        if language not in SECURITY_COVERAGE_LANGUAGES or "security" not in tags:
            continue
        side, slug = case_side_and_slug(case)
        if side and slug:
            grouped[(language, slug)][side] = case

    pairs: list[dict[str, Any]] = []
    unpaired_buggy: list[str] = []
    unpaired_clean: list[str] = []
    for (language, slug), sides in sorted(grouped.items()):
        clean = sides.get("clean")
        buggy = sides.get("buggy")
        if buggy and not clean:
            unpaired_buggy.append(f"{language}:{slug}")
            continue
        if clean and not buggy:
            unpaired_clean.append(f"{language}:{slug}")
            continue
        if not clean or not buggy:
            continue

        clean_expect = clean.get("expect", {})
        buggy_expect = buggy.get("expect", {})
        clean_severity = clean_expect.get("totals", {})
        buggy_severity = buggy_expect.get("totals", {})
        pairs.append(
            {
                "language": language,
                "slug": slug,
                "buggy_case": buggy["id"],
                "clean_case": clean["id"],
                "buggy_path": normalize_case_path(buggy["path"]),
                "clean_path": normalize_case_path(clean["path"]),
                "buggy_require_count": len(buggy_expect.get("require_substrings", [])),
                "clean_forbid_count": len(clean_expect.get("forbid_substrings", [])),
                "buggy_min_critical": int(buggy_severity.get("critical", {}).get("min", 0)),
                "buggy_min_warning": int(buggy_severity.get("warning", {}).get("min", 0)),
                "clean_max_critical": int(clean_severity.get("critical", {}).get("max", 999)),
                "clean_max_warning": int(clean_severity.get("warning", {}).get("max", 999)),
            }
        )

    if unpaired_buggy or unpaired_clean:
        raise AssertionError(
            "security fixtures must have buggy/clean pairs; "
            f"missing clean for {unpaired_buggy}; missing buggy for {unpaired_clean}"
        )

    by_language: dict[str, dict[str, int]] = {}
    for language in sorted(SECURITY_COVERAGE_LANGUAGES):
        language_pairs = [pair for pair in pairs if pair["language"] == language]
        by_language[language] = {
            "security_pairs": len(language_pairs),
            "buggy_cases_with_required_substrings": sum(
                1 for pair in language_pairs if pair["buggy_require_count"] > 0
            ),
            "clean_cases_with_forbidden_substrings": sum(
                1 for pair in language_pairs if pair["clean_forbid_count"] > 0
            ),
            "strict_zero_clean_cases": sum(
                1
                for pair in language_pairs
                if pair["clean_max_critical"] == 0 and pair["clean_max_warning"] == 0
            ),
        }

    return {
        "version": 1,
        "scope": "security fixture pairs for every UBS-supported language module",
        "languages": by_language,
        "pairs": pairs,
        "runtime_scopes": runtime_scopes_from_pairs(pairs),
        "robustness_scopes": robustness_scopes_from_constants(),
    }


def runtime_scopes_from_pairs(pairs: list[dict[str, Any]]) -> dict[str, list[str]]:
    campaign: list[str] = []
    all_cases: list[str] = []
    for pair in pairs:
        case_ids = [pair["buggy_case"], pair["clean_case"]]
        all_cases.extend(case_ids)
        if pair["language"] in SECURITY_COVERAGE_LANGUAGES:
            campaign.extend(case_ids)
    return {
        "smoke": list(SMOKE_CASE_IDS),
        "campaign": campaign,
        "all": all_cases,
    }


def robustness_scopes_from_constants() -> dict[str, list[str]]:
    return {
        "metamorphic": list(METAMORPHIC_CASE_IDS),
        "clean_fuzz": list(CLEAN_FUZZ_CASE_IDS),
    }


def update_or_check_golden(current: dict[str, Any], update: bool) -> None:
    rendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
    if update:
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(rendered, encoding="utf-8")
        print(f"[coverage-golden] updated {GOLDEN_PATH.relative_to(REPO_ROOT)}")
        return

    try:
        expected = JSON_DECODER.decode(GOLDEN_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"invalid JSON in {GOLDEN_PATH.relative_to(REPO_ROOT)}: {exc}"
        ) from exc
    if not isinstance(expected, dict):
        raise AssertionError(f"{GOLDEN_PATH.relative_to(REPO_ROOT)} must contain a JSON object")
    if expected != current:
        raise AssertionError(
            "rule coverage golden changed; review coverage drift and rerun with "
            "UPDATE_GOLDENS=1 if the new coverage is intentional"
        )
    print("[coverage-golden] PASS")


def case_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case["id"]: case for case in manifest["cases"]}


def runtime_case_ids_for_scope(coverage: dict[str, Any], scope: str) -> tuple[str, ...]:
    runtime_scopes = coverage.get("runtime_scopes", {})
    if not isinstance(runtime_scopes, dict) or scope not in runtime_scopes:
        raise AssertionError(f"runtime scope {scope!r} is missing from coverage golden")
    case_ids = runtime_scopes[scope]
    if not isinstance(case_ids, list) or not all(isinstance(case_id, str) for case_id in case_ids):
        raise AssertionError(f"runtime scope {scope!r} must be a list of case ids")
    return tuple(case_ids)


def command_for_case(
    manifest: dict[str, Any],
    case: dict[str, Any],
    path_override: Path | None = None,
) -> list[str]:
    defaults = manifest.get("defaults", {})
    ubs_bin = case.get("ubs_bin", defaults.get("ubs_bin", "../ubs"))
    args = [*defaults.get("args", []), *case.get("args", [])]
    if path_override is not None:
        try:
            case_path = os.path.relpath(path_override, REPO_ROOT)
        except ValueError:
            case_path = str(path_override)
    else:
        case_path = case["path"]
    return [str((TEST_ROOT / ubs_bin).resolve()), *args, case_path]


def parse_summary(case: dict[str, Any], stdout: str, project_label: str) -> dict[str, Any] | None:
    output_format = case.get("format", "text")
    if output_format == "json":
        return extract_json_from_stdout(stdout)
    if output_format == "toon":
        return parse_toon_summary(stdout, project_label)
    if case.get("ubs_bin", "").startswith("../modules/"):
        return parse_module_text_summary(stdout, project_label)
    return parse_text_summary(stdout, project_label)


def summary_totals(summary: dict[str, Any] | None) -> dict[str, int]:
    if not summary:
        return {"critical": 0, "warning": 0, "info": 0}
    totals = summary.get("totals", {})
    if not isinstance(totals, dict) or not totals:
        totals = summary
    return {
        "critical": int(totals.get("critical", 0) or 0),
        "warning": int(totals.get("warning", 0) or 0),
        "info": int(totals.get("info", 0) or 0),
    }


def write_runtime_artifact(
    label: str,
    proc: subprocess.CompletedProcess[str],
    summary: dict[str, Any] | None,
) -> None:
    artifact_dir = TEST_ROOT / "artifacts" / "rule_quality" / label
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "stdout.log").write_text(proc.stdout, encoding="utf-8")
    (artifact_dir / "stderr.log").write_text(proc.stderr, encoding="utf-8")
    (artifact_dir / "result.json").write_text(
        json.dumps(
            {
                "exit_code": proc.returncode,
                "duration_seconds": getattr(proc, "duration_seconds", None),
                "summary": summary,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def run_real_case(
    manifest: dict[str, Any],
    case: dict[str, Any],
    label: str,
    timeout: int,
    path_override: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, int]]:
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"})
    env.update(case.get("env", {}))
    cmd = command_for_case(manifest, case, path_override)
    start = time.monotonic()
    try:
        proc = subprocess.run(  # nosec B603 - command is built from the checked-in manifest.
            cmd,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{label} timed out after {timeout}s: {' '.join(cmd)}") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]
    project_label = str(path_override) if path_override is not None else case["path"]
    summary = parse_summary(case, proc.stdout, project_label)
    write_runtime_artifact(label, proc, summary)
    fail_on_warning = "--fail-on-warning" in cmd
    errors = check_expectations(
        case.get("expect", {}),
        proc.returncode,
        summary,
        proc.stdout,
        proc.stderr,
        fail_on_warning,
    )
    if errors:
        raise AssertionError(f"{label} expectation failures: {errors}")
    return proc, summary_totals(summary)


AST_GREP_SARIF_CHECKS = (
    {
        "label": "js-rule-pack",
        "module": "ubs-js.sh",
        "args": ("--format=sarif",),
        "fixture": "test-suite/js/security/request-body-limit-buggy.ts",
    },
    {
        "label": "go-rule-pack",
        "module": "ubs-golang.sh",
        "args": ("--format=sarif",),
        "fixture": "test-suite/golang/security/ssrf_buggy.go",
    },
    {
        "label": "rust-rule-pack",
        "module": "ubs-rust.sh",
        "args": ("--no-cargo", "--format=sarif"),
        "fixture": "test-suite/rust/buggy/sql_injection.rs",
    },
)


def run_single_ast_grep_rule_pack_check(spec: dict[str, Any], timeout: int) -> None:
    label = f"ast-grep-{spec['label']}-sarif"
    cmd = [
        str(REPO_ROOT / "modules" / spec["module"]),
        *spec["args"],
        spec["fixture"],
    ]
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"})
    start = time.monotonic()
    try:
        proc = subprocess.run(  # nosec B603 - fixed repo-local command and fixture.
            cmd,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{label} timed out after {timeout}s") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]

    if proc.returncode not in (0, 1):
        write_runtime_artifact(label, proc, None)
        raise AssertionError(
            f"{label} failed; stderr is captured under "
            f"test-suite/artifacts/rule_quality/{label}/"
        )
    if "Environment error" in proc.stderr:
        write_runtime_artifact(label, proc, None)
        raise AssertionError(f"{label} emitted an environment error")

    try:
        payload = JSON_DECODER.decode(proc.stdout)
    except json.JSONDecodeError as exc:
        write_runtime_artifact(label, proc, None)
        raise AssertionError(f"{label} did not emit valid SARIF JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        write_runtime_artifact(label, proc, payload if isinstance(payload, dict) else None)
        raise AssertionError(f"{label} SARIF output lacks runs[]")
    write_runtime_artifact(
        label,
        proc,
        {"sarif_runs": len(payload["runs"])},
    )


def run_ast_grep_rule_pack_check(timeout: int) -> None:
    for spec in AST_GREP_SARIF_CHECKS:
        run_single_ast_grep_rule_pack_check(spec, timeout)
    print(f"[ast-grep-rule-pack] PASS ({len(AST_GREP_SARIF_CHECKS)} SARIF checks)")


def run_runtime_pair_checks(
    manifest: dict[str, Any],
    coverage: dict[str, Any],
    scope: str,
    timeout: int,
) -> None:
    if scope == "smoke":
        return
    cases = case_by_id(manifest)
    case_ids = runtime_case_ids_for_scope(coverage, scope)
    for case_id in case_ids:
        run_real_case(manifest, cases[case_id], f"runtime-{scope}-{case_id}", timeout)
    print(f"[runtime-{scope}] PASS ({len(case_ids)} real fixture scans)")


def comment_prefix_for(path: Path) -> str:
    if path.suffix in {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".cs",
        ".go",
        ".h",
        ".hh",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".rs",
        ".swift",
        ".ts",
        ".tsx",
    }:
        return "//"
    return "#"


def is_text_source(path: Path) -> bool:
    return path.suffix in {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".cs",
        ".ex",
        ".exs",
        ".go",
        ".h",
        ".hh",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".py",
        ".rb",
        ".rs",
        ".swift",
        ".ts",
        ".tsx",
    }


def source_with_benign_comments(
    source: str,
    path: Path,
    rng: random.Random | None = None,
) -> str:
    prefix = comment_prefix_for(path)
    lines = source.splitlines()
    if rng is not None and lines:
        insertion_count = min(4, max(1, len(lines) // 8))
        for index in sorted(rng.sample(range(len(lines) + 1), insertion_count), reverse=True):
            lines.insert(index, f"{prefix} UBS rule-quality benign fuzz marker")
    else:
        lines.insert(0, f"{prefix} UBS rule-quality benign metamorphic marker")
        lines.append("")
        lines.append(f"{prefix} UBS rule-quality trailing benign marker")
    return "\n".join(lines) + "\n"


def materialize_variant(
    case: dict[str, Any],
    label: str,
    rng: random.Random | None = None,
) -> Path:
    original = REPO_ROOT / case["path"]
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
    out_dir = RUNTIME_ROOT / str(os.getpid()) / safe_label
    out_dir.mkdir(parents=True, exist_ok=True)
    if original.is_file():
        out_path = out_dir / original.name
        out_path.write_text(
            source_with_benign_comments(
                original.read_text(encoding="utf-8"),
                original,
                rng,
            ),
            encoding="utf-8",
        )
        return out_path
    if not original.is_dir():
        raise AssertionError(f"cannot materialize variant for missing path: {case['path']}")

    out_path = out_dir / original.name
    for source_path in original.rglob("*"):
        relative = source_path.relative_to(original)
        target = out_path / relative
        if source_path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif is_text_source(source_path):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                source_with_benign_comments(
                    source_path.read_text(encoding="utf-8"),
                    source_path,
                    rng,
                ),
                encoding="utf-8",
            )
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target)
    return out_path


def run_metamorphic_checks(manifest: dict[str, Any], timeout: int) -> None:
    cases = case_by_id(manifest)
    for case_id in METAMORPHIC_CASE_IDS:
        case = cases[case_id]
        transformed_path = materialize_variant(case, f"metamorphic-{case_id}")
        _, original_summary = run_real_case(
            manifest, case, f"metamorphic-{case_id}-original", timeout
        )
        _, transformed_summary = run_real_case(
            manifest, case, f"metamorphic-{case_id}-transformed", timeout, transformed_path
        )
        if original_summary != transformed_summary:
            raise AssertionError(
                f"{case_id} changed under benign comment transform: "
                f"{original_summary} != {transformed_summary}"
            )
    print("[metamorphic] PASS")


def run_fuzz_smoke(manifest: dict[str, Any], timeout: int, iterations: int) -> None:
    cases = case_by_id(manifest)
    rng = random.Random(0xBEEF)  # nosec B311 - deterministic fuzzing, not cryptography.
    for case_id in CLEAN_FUZZ_CASE_IDS:
        case = cases[case_id]
        for iteration in range(iterations):
            transformed_path = materialize_variant(case, f"fuzz-{case_id}-{iteration}", rng)
            run_real_case(
                manifest,
                case,
                f"fuzz-{case_id}-{iteration}",
                timeout,
                transformed_path,
            )
    print("[fuzz-smoke] PASS")


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-timeout", type=int, default=60)
    parser.add_argument("--fuzz-iterations", type=int, default=3)
    parser.add_argument(
        "--runtime-scope",
        choices=("smoke", "campaign", "all"),
        default=os.environ.get("UBS_RULE_RUNTIME_SCOPE", "smoke"),
        help="real fixture runtime breadth: smoke=request-body MRs, campaign=recent Rust/TS/Go campaign rules, all=every paired security fixture",
    )
    parser.add_argument("--skip-runtime", action="store_true")
    parser.add_argument("--update-goldens", action="store_true")
    args = parser.parse_args(argv)

    update_golden = args.update_goldens or os.environ.get("UPDATE_GOLDENS") == "1"
    manifest = load_manifest()
    coverage = build_rule_coverage(manifest)
    update_or_check_golden(coverage, update_golden)
    print("[manifest-audit] PASS")

    if not args.skip_runtime:
        run_ast_grep_rule_pack_check(args.case_timeout)
        run_runtime_pair_checks(manifest, coverage, args.runtime_scope, args.case_timeout)
        run_metamorphic_checks(manifest, args.case_timeout)
        run_fuzz_smoke(manifest, args.case_timeout, args.fuzz_iterations)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
