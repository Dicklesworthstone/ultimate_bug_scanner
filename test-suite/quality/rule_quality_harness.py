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
AST_GREP_SARIF_GOLDEN_PATH = TEST_ROOT / "goldens" / "ast_grep_rule_pack_sarif.json"


def default_runtime_root() -> str:
    base = os.environ.get("TMPDIR")
    if not base and Path("/data/tmp").is_dir():
        base = "/data/tmp"
    if not base:
        base = "/tmp"
    return str(Path(base) / "ubs-rule-quality-variants")


RUNTIME_ROOT = Path(os.environ.get("UBS_RULE_QUALITY_TMP", default_runtime_root()))

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
CAMPAIGN_COVERAGE_LANGUAGES = {"golang", "js", "rust"}
TARGET_CLEAN_BASELINE_CASE_IDS = (
    "js-core-clean",
    "js-module-clean",
    "js-node-clean",
    "golang-clean",
    "rust-clean",
)
CAMPAIGN_BEHAVIOR_TAGS = {
    "async",
    "collections",
    "macros",
    "parsing",
    "perf",
    "react",
    "resource",
    "strings",
    "type-narrowing",
    "unsafe",
}
CAMPAIGN_BEHAVIOR_EXCLUDED_TAGS = {
    "regression",
    "security",
    "skip",
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
    "elixir-header-injection-clean",
    "elixir-open-redirect-clean",
    "java-open-redirect-clean",
    "js-typescript-request-body-limit-clean",
    "kotlin-open-redirect-clean",
    "python-redos-regex-clean",
    "ruby-open-redirect-clean",
    "golang-open-redirect-clean",
    "golang-request-body-limit-clean",
    "golang-ssrf-clean",
    "golang-tls-verification-clean",
    "rust-request-body-limit-clean",
    "rust-tls-verification-clean",
    "js-typescript-tls-verification-clean",
    "swift-open-redirect-clean",
)
METAMORPHIC_CASE_IDS = (
    *SMOKE_CASE_IDS,
    "js-typescript-tls-verification-buggy",
    "js-typescript-tls-verification-clean",
    "js-typescript-sql-injection-buggy",
    "js-typescript-sql-injection-clean",
    "golang-open-redirect-buggy",
    "golang-open-redirect-clean",
    "golang-ssrf-buggy",
    "golang-ssrf-clean",
    "golang-tls-verification-buggy",
    "golang-tls-verification-clean",
    "rust-sql-injection-buggy",
    "rust-sql-injection-clean",
    "rust-tls-verification-buggy",
    "rust-tls-verification-clean",
)
BASE_METAMORPHIC_TRANSFORMS = ("comments",)
CAMPAIGN_LANGUAGE_METAMORPHIC_TRANSFORMS = ("whitespace",)
DEFAULT_FUZZ_ITERATIONS = 3
JSON_DECODER = json.JSONDecoder()


def default_case_timeout() -> int:
    raw_timeout = os.environ.get("UBS_RULE_QUALITY_CASE_TIMEOUT", "120")
    try:
        timeout = int(raw_timeout)
    except ValueError as exc:
        raise AssertionError(
            "UBS_RULE_QUALITY_CASE_TIMEOUT must be an integer number of seconds"
        ) from exc
    if timeout <= 0:
        raise AssertionError("UBS_RULE_QUALITY_CASE_TIMEOUT must be positive")
    return timeout


sys.path.insert(0, str(TEST_ROOT))
from run_manifest import (  # noqa: E402,F401
    check_expectations,
    disabled_case_ids,
    duplicate_case_ids,
    empty_manifest_error,
    extract_json_from_stdout,
    invalid_case_id_labels,
    manifest_schema_errors,
    missing_selected_case_ids,
    parse_module_text_summary,
    parse_text_summary,
    parse_toon_summary,
    timeout_output,
)


def enable_line_buffered_stdout() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(line_buffering=True)


def log_progress(message: str) -> None:
    print(message, flush=True)


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

    runtime_scopes = runtime_scopes_from_pairs(pairs, cases)
    robustness_scopes = robustness_scopes_from_pairs(pairs, cases)
    return {
        "version": 4,
        "scope": "security fixture pairs for every UBS-supported language module plus Rust, TypeScript/JavaScript, and Go campaign behavior-rule scopes",
        "all_language_expectation_strength_scopes": expectation_strength_scopes_from_runtime(
            runtime_scopes,
            cases,
            SECURITY_COVERAGE_LANGUAGES,
        ),
        "clean_fuzz_budget_scopes": clean_fuzz_budget_scopes_from_robustness(
            robustness_scopes,
        ),
        "expectation_strength_scopes": expectation_strength_scopes_from_runtime(
            runtime_scopes,
            cases,
            CAMPAIGN_COVERAGE_LANGUAGES,
        ),
        "languages": by_language,
        "metamorphic_transform_scopes": metamorphic_transform_scopes_from_robustness(
            robustness_scopes,
            cases,
        ),
        "pairs": pairs,
        "runtime_scopes": runtime_scopes,
        "robustness_scopes": robustness_scopes,
        "target_clean_baseline_budgets": target_clean_baseline_budgets(cases),
    }


def pair_case_ids_for_languages(
    pairs: list[dict[str, Any]],
    languages: set[str],
) -> list[str]:
    case_ids: list[str] = []
    for pair in pairs:
        if pair["language"] in languages:
            case_ids.extend([pair["buggy_case"], pair["clean_case"]])
    return case_ids


def clean_case_ids_for_languages(
    pairs: list[dict[str, Any]],
    languages: set[str],
) -> list[str]:
    return [
        pair["clean_case"]
        for pair in pairs
        if pair["language"] in languages
    ]


def unique_case_ids(case_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for case_id in case_ids:
        if case_id in seen:
            continue
        seen.add(case_id)
        unique.append(case_id)
    return unique


def campaign_behavior_case_ids(
    cases: list[dict[str, Any]],
    sides: set[str] | None = None,
) -> list[str]:
    selected: list[str] = []
    for case in cases:
        tags = set(case.get("tags", []))
        if case.get("language") not in CAMPAIGN_COVERAGE_LANGUAGES:
            continue
        if not tags.intersection(CAMPAIGN_BEHAVIOR_TAGS):
            continue
        if tags.intersection(CAMPAIGN_BEHAVIOR_EXCLUDED_TAGS):
            continue
        if sides is not None and not tags.intersection(sides):
            continue
        selected.append(case["id"])
    return selected


def runtime_scopes_from_pairs(
    pairs: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, list[str]]:
    campaign: list[str] = []
    all_cases: list[str] = []
    for pair in pairs:
        case_ids = [pair["buggy_case"], pair["clean_case"]]
        all_cases.extend(case_ids)
        if pair["language"] in CAMPAIGN_COVERAGE_LANGUAGES:
            campaign.extend(case_ids)
    campaign.extend(campaign_behavior_case_ids(cases))
    return {
        "smoke": list(SMOKE_CASE_IDS),
        "campaign": unique_case_ids(campaign),
        "all": all_cases,
    }


def robustness_scopes_from_pairs(
    pairs: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, list[str]]]:
    campaign_metamorphic = pair_case_ids_for_languages(pairs, CAMPAIGN_COVERAGE_LANGUAGES)
    campaign_metamorphic.extend(campaign_behavior_case_ids(cases))
    campaign_clean_fuzz = clean_case_ids_for_languages(pairs, CAMPAIGN_COVERAGE_LANGUAGES)
    campaign_clean_fuzz.extend(campaign_behavior_case_ids(cases, {"clean"}))
    all_metamorphic = pair_case_ids_for_languages(pairs, SECURITY_COVERAGE_LANGUAGES)
    all_metamorphic.extend(campaign_behavior_case_ids(cases))
    all_clean_fuzz = clean_case_ids_for_languages(pairs, SECURITY_COVERAGE_LANGUAGES)
    all_clean_fuzz.extend(campaign_behavior_case_ids(cases, {"clean"}))
    return {
        "smoke": {
            "metamorphic": list(METAMORPHIC_CASE_IDS),
            "clean_fuzz": list(CLEAN_FUZZ_CASE_IDS),
        },
        "campaign": {
            "metamorphic": unique_case_ids(campaign_metamorphic),
            "clean_fuzz": unique_case_ids(campaign_clean_fuzz),
        },
        "all": {
            "metamorphic": unique_case_ids(all_metamorphic),
            "clean_fuzz": unique_case_ids(all_clean_fuzz),
        },
    }


def metamorphic_transform_scopes_from_robustness(
    robustness_scopes: dict[str, dict[str, list[str]]],
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    cases_by_id = {case["id"]: case for case in cases}
    transform_scopes: dict[str, dict[str, Any]] = {}
    for scope, scope_cases in sorted(robustness_scopes.items()):
        case_ids = scope_cases.get("metamorphic", [])
        by_transform: dict[str, list[str]] = defaultdict(list)
        for case_id in case_ids:
            case = cases_by_id[case_id]
            for transform in metamorphic_transforms_for_case(case):
                by_transform[transform].append(case_id)
        transform_scopes[scope] = {
            "by_transform": {
                transform: by_transform[transform]
                for transform in sorted(by_transform)
            },
            "case_count": len(case_ids),
            "transformed_scan_count": sum(len(ids) for ids in by_transform.values()),
        }
    return transform_scopes


def clean_fuzz_budget_scopes_from_robustness(
    robustness_scopes: dict[str, dict[str, list[str]]],
) -> dict[str, dict[str, int]]:
    return {
        scope: {
            "case_count": len(scope_cases.get("clean_fuzz", [])),
            "default_iterations": DEFAULT_FUZZ_ITERATIONS,
            "default_transformed_scan_count": (
                len(scope_cases.get("clean_fuzz", [])) * DEFAULT_FUZZ_ITERATIONS
            ),
        }
        for scope, scope_cases in sorted(robustness_scopes.items())
    }


def target_clean_baseline_budgets(cases: list[dict[str, Any]]) -> dict[str, Any]:
    cases_by_id = {case["id"]: case for case in cases}
    missing_ids = sorted(
        case_id
        for case_id in TARGET_CLEAN_BASELINE_CASE_IDS
        if case_id not in cases_by_id
    )
    if missing_ids:
        raise AssertionError(f"target clean baseline cases missing from manifest: {missing_ids}")

    baseline_cases: list[dict[str, Any]] = []
    for case_id in TARGET_CLEAN_BASELINE_CASE_IDS:
        case = cases_by_id[case_id]
        expect = case.get("expect", {})
        totals = expect.get("totals", {})
        critical_max = int(totals.get("critical", {}).get("max", 0))
        warning_max = int(totals.get("warning", {}).get("max", 0))
        baseline_cases.append(
            {
                "critical_max": critical_max,
                "forbid_substring_count": len(expect.get("forbid_substrings", [])),
                "id": case_id,
                "language": case.get("language", ""),
                "path": normalize_case_path(case["path"]),
                "warning_max": warning_max,
            }
        )

    return {
        "case_count": len(baseline_cases),
        "cases": baseline_cases,
        "strict_zero_case_count": sum(
            1
            for case in baseline_cases
            if case["critical_max"] == 0 and case["warning_max"] == 0
        ),
        "warning_budget_total": sum(case["warning_max"] for case in baseline_cases),
    }


def expectation_side(case: dict[str, Any]) -> str:
    side, _ = case_side_and_slug(case)
    if side:
        return side
    tags = set(case.get("tags", []))
    if "buggy" in tags:
        return "buggy"
    if "clean" in tags:
        return "clean"
    return "unknown"


def expectation_strength_scopes_from_runtime(
    runtime_scopes: dict[str, list[str]],
    cases: list[dict[str, Any]],
    languages: set[str],
) -> dict[str, dict[str, Any]]:
    cases_by_id = {case["id"]: case for case in cases}
    strength_scopes: dict[str, dict[str, Any]] = {}
    for scope, case_ids in sorted(runtime_scopes.items()):
        scoped_cases = [
            cases_by_id[case_id]
            for case_id in case_ids
            if cases_by_id[case_id].get("language") in languages
        ]
        weak_cases: list[dict[str, Any]] = []
        for case in scoped_cases:
            side = expectation_side(case)
            expect = case.get("expect", {})
            totals = expect.get("totals", {})
            reasons: list[str] = []
            if side == "buggy" and not expect.get("require_substrings"):
                reasons.append("buggy_missing_require_substrings")
            if side == "clean":
                if not expect.get("forbid_substrings"):
                    reasons.append("clean_missing_forbid_substrings")
                if (
                    totals.get("critical", {}).get("max") != 0
                    or totals.get("warning", {}).get("max") != 0
                ):
                    reasons.append("clean_not_strict_zero_critical_warning")
            if side == "unknown":
                reasons.append("unknown_expectation_side")
            if reasons:
                weak_cases.append(
                    {
                        "id": case["id"],
                        "language": case.get("language", ""),
                        "path": normalize_case_path(case["path"]),
                        "reasons": reasons,
                        "side": side,
                    }
                )
        strength_scopes[scope] = {
            "buggy_cases_with_required_substrings": sum(
                1
                for case in scoped_cases
                if expectation_side(case) == "buggy"
                and bool(case.get("expect", {}).get("require_substrings"))
            ),
            "case_count": len(scoped_cases),
            "clean_cases_with_forbidden_substrings": sum(
                1
                for case in scoped_cases
                if expectation_side(case) == "clean"
                and bool(case.get("expect", {}).get("forbid_substrings"))
            ),
            "strict_zero_clean_cases": sum(
                1
                for case in scoped_cases
                if expectation_side(case) == "clean"
                and case.get("expect", {}).get("totals", {}).get("critical", {}).get("max") == 0
                and case.get("expect", {}).get("totals", {}).get("warning", {}).get("max") == 0
            ),
            "weak_case_count": len(weak_cases),
            "weak_cases": sorted(
                weak_cases,
                key=lambda item: (item["language"], item["id"]),
            ),
        }
    return strength_scopes


def update_or_check_golden(current: dict[str, Any], update: bool) -> None:
    rendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
    if update:
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(rendered, encoding="utf-8")
        log_progress(f"[coverage-golden] updated {GOLDEN_PATH.relative_to(REPO_ROOT)}")
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
    log_progress("[coverage-golden] PASS")


def update_or_check_ast_grep_sarif_golden(current: dict[str, Any], update: bool) -> None:
    rendered = json.dumps(current, indent=2, sort_keys=True) + "\n"
    if update:
        AST_GREP_SARIF_GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        AST_GREP_SARIF_GOLDEN_PATH.write_text(rendered, encoding="utf-8")
        log_progress(
            "[ast-grep-sarif-golden] updated "
            f"{AST_GREP_SARIF_GOLDEN_PATH.relative_to(REPO_ROOT)}"
        )
        return

    try:
        expected = JSON_DECODER.decode(
            AST_GREP_SARIF_GOLDEN_PATH.read_text(encoding="utf-8")
        )
    except FileNotFoundError as exc:
        raise AssertionError(
            f"missing {AST_GREP_SARIF_GOLDEN_PATH.relative_to(REPO_ROOT)}; "
            "run with UPDATE_GOLDENS=1 after reviewing current SARIF evidence"
        ) from exc
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"invalid JSON in {AST_GREP_SARIF_GOLDEN_PATH.relative_to(REPO_ROOT)}: {exc}"
        ) from exc
    if not isinstance(expected, dict):
        raise AssertionError(
            f"{AST_GREP_SARIF_GOLDEN_PATH.relative_to(REPO_ROOT)} must contain a JSON object"
        )
    if expected != current:
        raise AssertionError(
            "ast-grep SARIF evidence golden changed; review rule-pack result drift and rerun "
            "with UPDATE_GOLDENS=1 if the new evidence is intentional"
        )
    log_progress("[ast-grep-sarif-golden] PASS")


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


def robustness_case_ids_for_scope(
    coverage: dict[str, Any],
    scope: str,
    check_kind: str,
) -> tuple[str, ...]:
    robustness_scopes = coverage.get("robustness_scopes", {})
    if not isinstance(robustness_scopes, dict) or scope not in robustness_scopes:
        raise AssertionError(f"robustness scope {scope!r} is missing from coverage golden")
    scope_cases = robustness_scopes[scope]
    if not isinstance(scope_cases, dict) or check_kind not in scope_cases:
        raise AssertionError(
            f"robustness scope {scope!r} is missing {check_kind!r} case ids"
        )
    case_ids = scope_cases[check_kind]
    if not isinstance(case_ids, list) or not all(isinstance(case_id, str) for case_id in case_ids):
        raise AssertionError(
            f"robustness scope {scope!r} {check_kind!r} must be a list of case ids"
        )
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
            path_override.relative_to(REPO_ROOT)
        except ValueError:
            if path_override.is_file() and ubs_bin == "../ubs":
                case_path = str(path_override.parent)
            else:
                case_path = str(path_override)
        else:
            case_path = os.path.relpath(path_override, REPO_ROOT)
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


def allow_unparseable_output(case: dict[str, Any]) -> bool:
    expect = case.get("expect") or {}
    return bool(expect.get("allow_unparseable_output", False))


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


def completed_process_from_timeout(
    cmd: list[str],
    exc: subprocess.TimeoutExpired,
    duration: float,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    stderr = timeout_output(exc.stderr)
    if stderr and not stderr.endswith("\n"):
        stderr += "\n"
    stderr += f"Timed out after {timeout}s\n"
    proc = subprocess.CompletedProcess(
        cmd,
        -1,
        stdout=timeout_output(exc.stdout),
        stderr=stderr,
    )
    proc.duration_seconds = round(duration, 3)  # type: ignore[attr-defined]
    return proc


def write_timeout_artifact(
    label: str,
    cmd: list[str],
    exc: subprocess.TimeoutExpired,
    duration: float,
    timeout: int,
) -> None:
    proc = completed_process_from_timeout(cmd, exc, duration, timeout)
    write_runtime_artifact(
        label,
        proc,
        {"timed_out": True, "timeout_seconds": timeout},
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
        write_timeout_artifact(label, cmd, exc, time.monotonic() - start, timeout)
        raise AssertionError(f"{label} timed out after {timeout}s: {' '.join(cmd)}") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]
    project_label = str(path_override) if path_override is not None else case["path"]
    summary = parse_summary(case, proc.stdout, project_label)
    if summary is None and not allow_unparseable_output(case):
        write_runtime_artifact(label, proc, None)
        raise AssertionError(
            f"{label} produced unparseable UBS output; stdout/stderr are captured under "
            f"test-suite/artifacts/rule_quality/{label}/"
        )
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
        "dump_args": ("--dump-rules={rules_dir}",),
        "list_args": ("--list-rules",),
        "fixture": "test-suite/js/buggy/security.js",
        "corpus_fixture": "test-suite/js",
        "expected_rule_ids": ("js.eval-call", "js.innerHTML-assign"),
    },
    {
        "label": "go-rule-pack",
        "module": "ubs-golang.sh",
        "args": ("--format=sarif",),
        "dump_args": ("--dump-rules={rules_dir}",),
        "list_args": ("--list-rules",),
        "fixture": "test-suite/golang/buggy/security_sql.go",
        "corpus_fixture": "test-suite/golang",
        "expected_rule_ids": ("go.exec-sh-c",),
    },
    {
        "label": "rust-rule-pack",
        "module": "ubs-rust.sh",
        "args": ("--no-cargo", "--format=sarif"),
        "dump_args": ("--no-cargo", "--dump-rules={rules_dir}"),
        "list_args": ("--no-cargo", "--list-rules"),
        "fixture": "test-suite/rust/buggy/ast_grep_rule_pack_coverage.rs",
        "corpus_fixture": "test-suite/rust",
        "expected_rule_ids": ("rust.unwrap-call", "rust.unwrap-unchecked"),
    },
    {
        "label": "swift-rule-pack",
        "module": "ubs-swift.sh",
        "args": ("--format=sarif",),
        "dump_args": ("--dump-rules={rules_dir}",),
        "list_args": ("--list-rules",),
        "fixture": "test-suite/swift/ssrf_buggy",
        "corpus_fixture": "test-suite/swift",
        "expected_rule_ids": ("swift.urlsession.task-no-resume",),
    },
)


def safe_artifact_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label)


def path_is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def copy_variant_metadata(out_dir: Path, original: Path) -> None:
    if original.suffix != ".go":
        return
    for name in ("go.mod", "go.sum", "go.work", "go.work.sum"):
        source = REPO_ROOT / name
        if source.is_file():
            shutil.copy2(source, out_dir / name)


def read_yaml_scalar(text: str, key: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(key)}:\s*(.+?)\s*$", text)
    if not match:
        raise AssertionError(f"generated ast-grep rule is missing {key!r}")
    value = match.group(1).strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def ast_grep_command() -> list[str]:
    for candidate in ("ast-grep", "sg"):
        path = shutil.which(candidate)
        if path:
            return [path]
    raise AssertionError("ast-grep CLI is required for per-rule validation")


def count_json_stream_objects(stdout: str, label: str) -> int:
    count = 0
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            JSON_DECODER.decode(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{label} emitted invalid JSON stream output: {exc}") from exc
        count += 1
    return count


def parse_list_rule_ids(stdout: str, label: str) -> list[str]:
    rule_ids = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not rule_ids:
        raise AssertionError(f"{label} did not emit any rule ids")
    invalid = [
        rule_id
        for rule_id in rule_ids
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", rule_id)
    ]
    if invalid:
        raise AssertionError(
            f"{label} emitted non-rule text in --list-rules output: {invalid[:5]}"
        )
    if rule_ids != sorted(set(rule_ids)):
        raise AssertionError(f"{label} --list-rules output must be sorted and unique")
    return rule_ids


def is_ast_grep_diagnostic_stderr(stderr: str) -> bool:
    stripped = stderr.strip()
    if not stripped:
        return True
    return (
        "error(s) found in code" in stripped
        and "Scan succeeded" in stripped
        and "Cannot parse rule" not in stripped
    )


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def sarif_result_has_message(result: dict[str, Any]) -> bool:
    message = result.get("message")
    if not isinstance(message, dict):
        return False
    return any(is_nonempty_string(message.get(key)) for key in ("text", "markdown"))


def sarif_result_has_usable_location(result: dict[str, Any]) -> bool:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return False
    for location in locations:
        if not isinstance(location, dict):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict) or not is_nonempty_string(artifact.get("uri")):
            continue
        region = physical.get("region")
        if not isinstance(region, dict):
            continue
        start_line = region.get("startLine")
        if (
            isinstance(start_line, int)
            and not isinstance(start_line, bool)
            and start_line > 0
        ):
            return True
    return False


def validate_sarif_payload_shape(payload: Any, label: str) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise AssertionError(f"{label} SARIF output lacks runs[]")
    for run_index, run in enumerate(payload["runs"]):
        if not isinstance(run, dict):
            raise AssertionError(f"{label} SARIF run[{run_index}] is not an object")
        results = run.get("results", [])
        if results is None:
            results = []
        if not isinstance(results, list):
            raise AssertionError(f"{label} SARIF run[{run_index}].results is not a list")
        for result_index, result in enumerate(results):
            result_label = f"{label} SARIF run[{run_index}].results[{result_index}]"
            if not isinstance(result, dict):
                raise AssertionError(f"{result_label} is not an object")
            if not is_nonempty_string(result.get("ruleId")):
                raise AssertionError(f"{result_label} lacks a non-empty ruleId")
            if not sarif_result_has_message(result):
                raise AssertionError(f"{result_label} lacks non-empty message text")
            if not sarif_result_has_usable_location(result):
                raise AssertionError(
                    f"{result_label} lacks a physical location with URI and positive startLine"
                )


def sarif_summary_from_process(
    spec: dict[str, Any],
    proc: subprocess.CompletedProcess[str],
    label: str,
) -> dict[str, Any]:
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
    try:
        validate_sarif_payload_shape(payload, label)
    except AssertionError:
        write_runtime_artifact(label, proc, payload if isinstance(payload, dict) else None)
        raise
    result_count = sum(
        1
        for run in payload["runs"]
        if isinstance(run, dict)
        for result in run.get("results", []) or []
        if isinstance(result, dict)
    )
    result_rule_ids = {
        result.get("ruleId")
        for run in payload["runs"]
        if isinstance(run, dict)
        for result in run.get("results", []) or []
        if isinstance(result, dict) and isinstance(result.get("ruleId"), str)
    }
    driver_rule_ids = {
        rule_id
        for run in payload["runs"]
        if isinstance(run, dict)
        for rule in ((run.get("tool", {}) or {}).get("driver", {}) or {}).get("rules", []) or []
        if isinstance(rule, dict)
        for rule_id in (rule.get("id"), rule.get("name"), rule.get("ruleId"))
        if isinstance(rule_id, str) and rule_id
    }
    missing_rule_ids = sorted(set(spec.get("expected_rule_ids", ())) - result_rule_ids)
    if missing_rule_ids:
        write_runtime_artifact(
            label,
            proc,
            {
                "sarif_runs": len(payload["runs"]),
                "result_rule_ids": sorted(result_rule_ids),
            },
        )
        raise AssertionError(
            f"{label} SARIF output did not include expected rule ids: {missing_rule_ids}"
        )
    summary = {
        "args": list(spec["args"]),
        "driver_rule_count": len(driver_rule_ids),
        "driver_rule_ids": sorted(driver_rule_ids),
        "expected_rule_ids": list(spec.get("expected_rule_ids", ())),
        "fixture": spec["fixture"],
        "module": spec["module"],
        "result_count": result_count,
        "result_rule_ids": sorted(result_rule_ids),
        "sarif_runs": len(payload["runs"]),
    }
    write_runtime_artifact(label, proc, summary)
    return summary


def run_sarif_rule_pack_check(
    spec: dict[str, Any],
    timeout: int,
    label_suffix: str,
) -> dict[str, Any]:
    label = f"ast-grep-{spec['label']}-{label_suffix}-sarif"
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
        write_timeout_artifact(label, cmd, exc, time.monotonic() - start, timeout)
        raise AssertionError(f"{label} timed out after {timeout}s") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]
    return sarif_summary_from_process(spec, proc, label)


def run_list_rule_inventory_check(
    spec: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    label = f"ast-grep-{spec['label']}-list-rules"
    cmd = [
        str(REPO_ROOT / "modules" / spec["module"]),
        *spec.get("list_args", ("--list-rules",)),
    ]
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"})
    start = time.monotonic()
    try:
        proc = subprocess.run(  # nosec B603 - validates checked-in module inventory output.
            cmd,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        write_timeout_artifact(label, cmd, exc, time.monotonic() - start, timeout)
        raise AssertionError(f"{label} timed out after {timeout}s") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]
    if proc.returncode != 0:
        write_runtime_artifact(label, proc, None)
        raise AssertionError(
            f"{label} failed; stdout/stderr are captured under "
            f"test-suite/artifacts/rule_quality/{label}/"
        )
    if proc.stderr.strip():
        write_runtime_artifact(label, proc, None)
        raise AssertionError(f"{label} emitted stderr")
    rule_ids = parse_list_rule_ids(proc.stdout, label)
    summary = {
        "list_args": list(spec.get("list_args", ("--list-rules",))),
        "module": spec["module"],
        "rule_count": len(rule_ids),
        "rule_ids": rule_ids,
    }
    write_runtime_artifact(label, proc, summary)
    return summary


def corpus_sarif_spec(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        **spec,
        "fixture": spec["corpus_fixture"],
    }


def run_single_ast_grep_rule_inventory_check(
    spec: dict[str, Any],
    timeout: int,
    ast_grep_cmd: list[str],
) -> dict[str, Any]:
    label = f"ast-grep-{spec['label']}-rules"
    rules_dir = RUNTIME_ROOT / str(os.getpid()) / safe_artifact_label(label)
    rules_dir.mkdir(parents=True, exist_ok=True)
    dump_args = tuple(
        arg.format(rules_dir=str(rules_dir))
        for arg in spec.get("dump_args", ())
    )
    cmd = [
        str(REPO_ROOT / "modules" / spec["module"]),
        *dump_args,
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
        write_timeout_artifact(label, cmd, exc, time.monotonic() - start, timeout)
        raise AssertionError(f"{label} timed out while dumping rules after {timeout}s") from exc
    proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]

    if proc.returncode not in (0, 1):
        write_runtime_artifact(label, proc, None)
        raise AssertionError(
            f"{label} failed while dumping rules; stderr is captured under "
            f"test-suite/artifacts/rule_quality/{label}/"
        )

    rule_paths = sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])
    if not rule_paths:
        write_runtime_artifact(label, proc, None)
        raise AssertionError(f"{label} did not dump any ast-grep YAML rules")

    fixture_path = REPO_ROOT / spec["fixture"]
    rules: list[dict[str, Any]] = []
    for rule_path in rule_paths:
        rule_text = rule_path.read_text(encoding="utf-8")
        rule_id = read_yaml_scalar(rule_text, "id")
        language = read_yaml_scalar(rule_text, "language")
        rule_label = f"{label}-{safe_artifact_label(rule_id)}"
        scan_cmd = [
            *ast_grep_cmd,
            "scan",
            "--rule",
            str(rule_path),
            str(fixture_path),
            "--json=stream",
        ]
        start = time.monotonic()
        try:
            scan_proc = subprocess.run(  # nosec B603 - validates checked-in generated rule YAML.
                scan_cmd,
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                env=env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            write_timeout_artifact(
                rule_label,
                scan_cmd,
                exc,
                time.monotonic() - start,
                timeout,
            )
            raise AssertionError(f"{rule_label} timed out after {timeout}s") from exc
        scan_proc.duration_seconds = round(time.monotonic() - start, 3)  # type: ignore[attr-defined]
        if scan_proc.returncode not in (0, 1):
            write_runtime_artifact(
                rule_label,
                scan_proc,
                {"rule_file": rule_path.name, "rule_id": rule_id},
            )
            raise AssertionError(
                f"{rule_label} failed ast-grep validation; stderr is captured under "
                f"test-suite/artifacts/rule_quality/{rule_label}/"
            )
        match_count = count_json_stream_objects(scan_proc.stdout, rule_label)
        if not is_ast_grep_diagnostic_stderr(scan_proc.stderr):
            write_runtime_artifact(
                rule_label,
                scan_proc,
                {
                    "match_count": match_count,
                    "rule_file": rule_path.name,
                    "rule_id": rule_id,
                },
            )
            raise AssertionError(f"{rule_label} emitted stderr during ast-grep validation")
        rules.append(
            {
                "file": rule_path.name,
                "id": rule_id,
                "language": language,
                "match_count": match_count,
            }
        )

    summary = {
        "dump_args": list(spec.get("dump_args", ())),
        "fixture": spec["fixture"],
        "module": spec["module"],
        "rule_count": len(rules),
        "rules": rules,
    }
    write_runtime_artifact(label, proc, summary)
    return summary


def build_rule_inventory_coverage(
    corpus_checks: list[dict[str, Any]],
    per_rule_validation: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    corpus_by_label = {item["label"]: item for item in corpus_checks}
    coverage: list[dict[str, Any]] = []
    for inventory in per_rule_validation:
        label = inventory["label"]
        generated_rule_ids = {
            rule["id"]
            for rule in inventory.get("rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("id"), str)
        }
        corpus_rule_ids = set(corpus_by_label.get(label, {}).get("result_rule_ids", []))
        covered_rule_ids = generated_rule_ids & corpus_rule_ids
        coverage.append(
            {
                "label": label,
                "corpus_result_rule_ids_without_generated_rule": sorted(
                    corpus_rule_ids - generated_rule_ids
                ),
                "covered_generated_rule_count": len(covered_rule_ids),
                "covered_generated_rule_ids": sorted(covered_rule_ids),
                "generated_rule_count": len(generated_rule_ids),
                "uncovered_generated_rule_count": len(generated_rule_ids - corpus_rule_ids),
                "uncovered_generated_rule_ids": sorted(generated_rule_ids - corpus_rule_ids),
            }
        )
    return coverage


def assert_rule_inventory_fully_covered(
    rule_inventory_coverage: list[dict[str, Any]],
) -> None:
    gaps: list[dict[str, Any]] = []
    for item in rule_inventory_coverage:
        uncovered_rule_ids = item.get("uncovered_generated_rule_ids", [])
        orphaned_corpus_rule_ids = item.get("corpus_result_rule_ids_without_generated_rule", [])
        if uncovered_rule_ids or orphaned_corpus_rule_ids:
            gaps.append(
                {
                    "corpus_result_rule_ids_without_generated_rule": orphaned_corpus_rule_ids,
                    "label": item.get("label", ""),
                    "uncovered_generated_rule_ids": uncovered_rule_ids,
                }
            )
    if gaps:
        raise AssertionError(
            "generated ast-grep rules must be exercised by the language corpus "
            "and corpus SARIF rule ids must come from dumped generated rules: "
            f"{json.dumps(gaps, sort_keys=True)}"
        )


def assert_list_rule_ids_match_dumped_rules(
    list_rule_validation: list[dict[str, Any]],
    per_rule_validation: list[dict[str, Any]],
) -> None:
    listed_by_label = {
        item["label"]: set(item.get("rule_ids", []))
        for item in list_rule_validation
    }
    dumped_by_label = {
        item["label"]: {
            rule["id"]
            for rule in item.get("rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("id"), str)
        }
        for item in per_rule_validation
    }
    mismatches: list[dict[str, Any]] = []
    for label in sorted(set(listed_by_label) | set(dumped_by_label)):
        listed = listed_by_label.get(label, set())
        dumped = dumped_by_label.get(label, set())
        if listed != dumped:
            mismatches.append(
                {
                    "dumped_not_listed": sorted(dumped - listed),
                    "label": label,
                    "listed_not_dumped": sorted(listed - dumped),
                }
            )
    if mismatches:
        raise AssertionError(
            "--list-rules output must exactly match dumped generated ast-grep rules: "
            f"{json.dumps(mismatches, sort_keys=True)}"
        )


def run_ast_grep_rule_pack_check(timeout: int, update_golden: bool) -> None:
    log_progress("[ast-grep-rule-pack] checking focused SARIF fixtures")
    checks = [
        {
            "label": spec["label"],
            **run_sarif_rule_pack_check(spec, timeout, "fixture"),
        }
        for spec in AST_GREP_SARIF_CHECKS
    ]
    log_progress("[ast-grep-rule-pack] checking language corpus SARIF evidence")
    corpus_checks = [
        {
            "label": spec["label"],
            **run_sarif_rule_pack_check(corpus_sarif_spec(spec), timeout, "corpus"),
        }
        for spec in AST_GREP_SARIF_CHECKS
    ]
    log_progress("[ast-grep-rule-pack] checking list-rules inventories")
    list_rule_validation = [
        {
            "label": spec["label"],
            **run_list_rule_inventory_check(spec, timeout),
        }
        for spec in AST_GREP_SARIF_CHECKS
    ]
    ast_grep_cmd = ast_grep_command()
    log_progress("[ast-grep-rule-pack] validating dumped ast-grep YAML rules")
    per_rule_validation = [
        {
            "label": spec["label"],
            **run_single_ast_grep_rule_inventory_check(spec, timeout, ast_grep_cmd),
        }
        for spec in AST_GREP_SARIF_CHECKS
    ]
    rule_inventory_coverage = build_rule_inventory_coverage(
        corpus_checks,
        per_rule_validation,
    )
    assert_rule_inventory_fully_covered(rule_inventory_coverage)
    assert_list_rule_ids_match_dumped_rules(
        list_rule_validation,
        per_rule_validation,
    )
    update_or_check_ast_grep_sarif_golden(
        {
            "version": 4,
            "scope": "Rust, TypeScript/JavaScript, Go, and Swift ast-grep SARIF evidence, corpus evidence, list-rules inventory, and per-rule parser validation",
            "checks": checks,
            "corpus_checks": corpus_checks,
            "list_rule_validation": list_rule_validation,
            "per_rule_validation": per_rule_validation,
            "rule_inventory_coverage": rule_inventory_coverage,
        },
        update_golden,
    )
    validated_rules = sum(item["rule_count"] for item in per_rule_validation)
    corpus_results = sum(item["result_count"] for item in corpus_checks)
    covered_generated_rules = sum(
        item["covered_generated_rule_count"] for item in rule_inventory_coverage
    )
    log_progress(
        "[ast-grep-rule-pack] PASS "
        f"({len(AST_GREP_SARIF_CHECKS)} SARIF checks, "
        f"{corpus_results} corpus SARIF results, "
        f"{covered_generated_rules}/{validated_rules} generated rules covered by corpora)"
    )


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
        log_progress(f"[runtime-{scope}] running {case_id}")
        run_real_case(manifest, cases[case_id], f"runtime-{scope}-{case_id}", timeout)
    log_progress(f"[runtime-{scope}] PASS ({len(case_ids)} real fixture scans)")


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
    if rng is not None and lines and path.suffix not in {".jsx", ".tsx"}:
        insertion_count = min(4, max(1, len(lines) // 8))
        for index in sorted(rng.sample(range(len(lines) + 1), insertion_count), reverse=True):
            lines.insert(index, f"{prefix} UBS rule-quality benign fuzz marker")
    else:
        lines.insert(0, f"{prefix} UBS rule-quality benign metamorphic marker")
        lines.append("")
        lines.append(f"{prefix} UBS rule-quality trailing benign marker")
    return "\n".join(lines) + "\n"


def source_with_benign_whitespace(source: str) -> str:
    lines = source.splitlines()
    expanded: list[str] = []
    for index, line in enumerate(lines):
        if index % 5 == 0:
            expanded.append("")
        expanded.append(line)
        if index % 7 == 3:
            expanded.append("")
    expanded.append("")
    return "\r\n".join(expanded) + "\r\n"


def transform_source(
    source: str,
    path: Path,
    transform: str,
    rng: random.Random | None = None,
) -> str:
    if transform == "comments":
        return source_with_benign_comments(source, path, rng)
    if transform == "whitespace":
        return source_with_benign_whitespace(source)
    raise AssertionError(f"unknown source transform: {transform}")


def materialize_variant(
    case: dict[str, Any],
    label: str,
    transform: str = "comments",
    rng: random.Random | None = None,
) -> Path:
    original = REPO_ROOT / case["path"]
    safe_label = safe_artifact_label(label)
    out_dir = RUNTIME_ROOT / str(os.getpid()) / safe_label
    out_dir.mkdir(parents=True, exist_ok=True)
    if original.is_file():
        if path_is_inside(RUNTIME_ROOT, REPO_ROOT):
            out_path = out_dir / original.name
            returned_path = out_path
        else:
            try:
                relative_path = original.relative_to(REPO_ROOT)
            except ValueError:
                relative_path = Path(original.name)
            out_path = out_dir / relative_path
            returned_path = out_dir
            copy_variant_metadata(out_dir, original)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            transform_source(
                original.read_text(encoding="utf-8"),
                original,
                transform,
                rng,
            ),
            encoding="utf-8",
        )
        return returned_path
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
                transform_source(
                    source_path.read_text(encoding="utf-8"),
                    source_path,
                    transform,
                    rng,
                ),
                encoding="utf-8",
            )
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target)
    return out_path


def metamorphic_transforms_for_case(case: dict[str, Any]) -> tuple[str, ...]:
    transforms = list(BASE_METAMORPHIC_TRANSFORMS)
    if case.get("language") in CAMPAIGN_COVERAGE_LANGUAGES:
        transforms.extend(CAMPAIGN_LANGUAGE_METAMORPHIC_TRANSFORMS)
    return tuple(transforms)


def run_metamorphic_checks(
    manifest: dict[str, Any],
    case_ids: tuple[str, ...],
    timeout: int,
    scope: str,
) -> None:
    cases = case_by_id(manifest)
    transform_count = 0
    for case_id in case_ids:
        case = cases[case_id]
        log_progress(f"[metamorphic-{scope}] running {case_id} original")
        _, original_summary = run_real_case(
            manifest, case, f"metamorphic-{case_id}-original", timeout
        )
        for transform in metamorphic_transforms_for_case(case):
            transform_count += 1
            log_progress(f"[metamorphic-{scope}] running {case_id} {transform}")
            transformed_path = materialize_variant(
                case,
                f"metamorphic-{case_id}-{transform}",
                transform,
            )
            _, transformed_summary = run_real_case(
                manifest,
                case,
                f"metamorphic-{case_id}-{transform}-transformed",
                timeout,
                transformed_path,
            )
            if original_summary != transformed_summary:
                raise AssertionError(
                    f"{case_id} changed under benign {transform} transform: "
                    f"{original_summary} != {transformed_summary}"
                )
    log_progress(
        f"[metamorphic-{scope}] PASS "
        f"({len(case_ids)} real fixture(s), {transform_count} transformed scan(s))"
    )


def run_fuzz_smoke(
    manifest: dict[str, Any],
    case_ids: tuple[str, ...],
    timeout: int,
    iterations: int,
    scope: str,
) -> None:
    cases = case_by_id(manifest)
    rng = random.Random(0xBEEF)  # nosec B311 - deterministic fuzzing, not cryptography.
    for case_id in case_ids:
        case = cases[case_id]
        for iteration in range(iterations):
            log_progress(f"[fuzz-{scope}] running {case_id} iteration {iteration}")
            transformed_path = materialize_variant(
                case,
                f"fuzz-{case_id}-{iteration}",
                rng=rng,
            )
            run_real_case(
                manifest,
                case,
                f"fuzz-{case_id}-{iteration}",
                timeout,
                transformed_path,
            )
    log_progress(
        f"[fuzz-{scope}] PASS "
        f"({len(case_ids)} clean fixture transforms x {iterations} iteration(s))"
    )


def main(argv: list[str]) -> int:
    import argparse

    enable_line_buffered_stdout()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-timeout", type=int, default=default_case_timeout())
    parser.add_argument("--fuzz-iterations", type=int, default=DEFAULT_FUZZ_ITERATIONS)
    parser.add_argument(
        "--runtime-scope",
        choices=("smoke", "campaign", "all"),
        default=os.environ.get("UBS_RULE_RUNTIME_SCOPE", "smoke"),
        help="real fixture runtime breadth: smoke=default fast slice, campaign=Rust/TypeScript/Go security and behavior-rule cases, all=every paired security fixture",
    )
    parser.add_argument(
        "--robustness-scope",
        choices=("smoke", "campaign", "all"),
        default=os.environ.get("UBS_RULE_ROBUSTNESS_SCOPE", "smoke"),
        help="metamorphic/fuzz breadth: smoke=default fast slice, campaign=Rust/TypeScript/Go security and behavior-rule cases, all=every paired security fixture",
    )
    parser.add_argument("--skip-runtime", action="store_true")
    parser.add_argument("--update-goldens", action="store_true")
    args = parser.parse_args(argv)

    update_golden = args.update_goldens or os.environ.get("UPDATE_GOLDENS") == "1"
    manifest = load_manifest()
    schema_errors = manifest_schema_errors(manifest)
    if schema_errors:
        raise AssertionError(f"manifest schema errors: {schema_errors}")
    coverage = build_rule_coverage(manifest)
    update_or_check_golden(coverage, update_golden)
    log_progress("[manifest-audit] PASS")

    if not args.skip_runtime:
        run_ast_grep_rule_pack_check(args.case_timeout, update_golden)
        run_runtime_pair_checks(manifest, coverage, args.runtime_scope, args.case_timeout)
        metamorphic_case_ids = robustness_case_ids_for_scope(
            coverage,
            args.robustness_scope,
            "metamorphic",
        )
        clean_fuzz_case_ids = robustness_case_ids_for_scope(
            coverage,
            args.robustness_scope,
            "clean_fuzz",
        )
        run_metamorphic_checks(
            manifest,
            metamorphic_case_ids,
            args.case_timeout,
            args.robustness_scope,
        )
        run_fuzz_smoke(
            manifest,
            clean_fuzz_case_ids,
            args.case_timeout,
            args.fuzz_iterations,
            args.robustness_scope,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
