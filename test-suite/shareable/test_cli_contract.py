#!/usr/bin/env python3
"""Meta-runner CLI contract checks (bridge-plan beads B1/B3).

Every documented flag and environment variable in README's option table must be
accepted by `ubs` and behave as described. Each check prints a
`[cli-contract:<name>] PASS/FAIL` line and, on failure, the captured output, so
the log alone is enough to diagnose a regression.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS = REPO_ROOT / "ubs"
PY_CLEAN = REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_clean.py"
JS_DEBUG = REPO_ROOT / "test-suite" / "buggy" / "09-debugging-production.js"
TS_CLEAN_DIR = REPO_ROOT / "test-suite" / "js" / "type_narrowing" / "clean"

FAILURES: list[str] = []


def run(args: list[str], *, cwd: Path = REPO_ROOT, env: dict | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    full_env.update({"NO_COLOR": "1", "UBS_NO_AUTO_UPDATE": "1", "UBS_SKIP_SIZE_CHECK": "1"})
    if env:
        full_env.update(env)
        for key, value in env.items():
            if value is None:
                full_env.pop(key, None)
    return subprocess.run([str(UBS), *args], cwd=cwd, env=full_env, capture_output=True, text=True, timeout=timeout)


def report(name: str, ok: bool, detail: str = "", proc: subprocess.CompletedProcess | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[cli-contract:{name}] {status}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        FAILURES.append(name)
        if proc is not None:
            print(f"  exit={proc.returncode}\n  stdout:\n{textwrap.indent(proc.stdout[-2000:], '    ')}\n  stderr:\n{textwrap.indent(proc.stderr[-2000:], '    ')}")


def check_unknown_flag_exit2() -> None:
    proc = run(["--bogus-flag", str(PY_CLEAN)])
    report("unknown_flag_exit2", proc.returncode == 2 and "unknown option" in proc.stderr, f"exit={proc.returncode}", proc)


def check_bad_format_exit2() -> None:
    proc = run(["--format=xml", "--only=python", str(PY_CLEAN)])
    report("bad_format_exit2", proc.returncode == 2 and "unknown --format value" in proc.stderr, f"exit={proc.returncode}", proc)


def check_documented_flags_parse() -> None:
    # Every documented flag must be accepted (never "unknown option" / "scan target not found").
    flag_sets = [
        ["--no-color"],
        ["--include-ext=py,pyi"],
        ["--jobs", "1"],
        ["--only", "python"],
        ["--skip", "14"],
        ["--format", "json"],
        ["--profile=loose"],
    ]
    bad = []
    for flags in flag_sets:
        proc = run([*flags, "--only=python", "--ci", str(PY_CLEAN)])
        if proc.returncode == 2 or "unknown option" in proc.stderr or "scan target not found" in (proc.stdout + proc.stderr):
            bad.append((flags, proc.returncode, (proc.stderr or proc.stdout)[-300:]))
    report("documented_flags_parse", not bad, "; ".join(f"{f}: exit {rc}: {err.strip()[:120]}" for f, rc, err in bad))


def check_no_color_strips_ansi() -> None:
    env = {"NO_COLOR": None}  # rely on the flag alone
    proc = run(["--no-color", "--only=python", "--ci", str(PY_CLEAN)], env=env)
    ok = proc.returncode in (0, 1) and "\x1b[" not in proc.stdout
    report("no_color_strips_ansi", ok, f"exit={proc.returncode}", proc)


def check_output_file_positional() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-cli-") as tmp:
        out = Path(tmp) / "bug-report.txt"
        proc = run(["--only=python", "--ci", str(PY_CLEAN.parent), str(out)])
        text = out.read_text(encoding="utf-8") if out.exists() else ""
        ok = (
            proc.returncode in (0, 1)
            and out.exists()
            and "UBS Meta-Runner" in text
            and text == proc.stdout
            and "\x1b[" not in text
        )
        report("output_file_positional", ok, f"exit={proc.returncode} bytes={len(text)} same_as_stdout={text == proc.stdout}", proc)


def check_output_flag_json() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-cli-") as tmp:
        out = Path(tmp) / "report.json"
        proc = run(["--only=python", "--ci", "--format=json", "--output", str(out), str(PY_CLEAN)])
        try:
            file_doc = json.loads(out.read_text(encoding="utf-8"))
            stdout_doc = json.loads(proc.stdout)
            ok = file_doc.get("totals") == stdout_doc.get("totals") and "files" in file_doc.get("totals", {})
        except Exception as exc:  # noqa: BLE001
            ok = False
            proc.stderr += f"\n[test] {exc}"
        report("output_flag_json", ok, f"exit={proc.returncode}", proc)


def check_rules_dir_custom_rule_in_sarif() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-rules-") as tmp:
        rules = Path(tmp) / "rules"
        rules.mkdir()
        (rules / "no-console.yml").write_text(
            "id: custom.no-console\nlanguage: javascript\nseverity: warning\n"
            "message: console statements should be removed before production\n"
            "rule:\n  pattern: console.log($$$)\n",
            encoding="utf-8",
        )
        proc = run(["--only=js", "--ci", "--format=sarif", f"--rules={rules}", str(JS_DEBUG)])
        rule_ids: set[str] = set()
        try:
            doc = json.loads(proc.stdout)
            for run_ in doc.get("runs", []):
                for result in run_.get("results", []):
                    rule_ids.add(result.get("ruleId", ""))
        except Exception as exc:  # noqa: BLE001
            proc.stderr += f"\n[test] {exc}"
        report("rules_dir_custom_rule_in_sarif", "custom.no-console" in rule_ids, f"exit={proc.returncode} rule_ids={sorted(rule_ids)[:6]}", proc)


def check_include_ext_forwarded() -> None:
    with tempfile.TemporaryDirectory(prefix="ubs-ext-") as tmp:
        proj = Path(tmp) / "proj"
        proj.mkdir()
        (proj / "widget.vue").write_text("<script>\nconst x = eval(userInput);\n</script>\n", encoding="utf-8")
        (proj / "package.json").write_text("{}\n", encoding="utf-8")
        proc = run(["--only=js", "--ci", "--format=json", "--include-ext=js,vue", str(proj)])
        try:
            files = int(json.loads(proc.stdout).get("totals", {}).get("files", 0))
        except Exception as exc:  # noqa: BLE001
            files = -1
            proc.stderr += f"\n[test] {exc}"
        report("include_ext_forwarded", proc.returncode != 2 and files >= 1, f"exit={proc.returncode} files={files}", proc)


def check_list_categories() -> None:
    proc = run(["--only=python", "--list-categories", str(PY_CLEAN.parent)])
    ok = proc.returncode == 0 and "python" in proc.stdout and "Security" in proc.stdout
    report("list_categories", ok, f"exit={proc.returncode}", proc)


def check_env_skip_type_narrowing() -> None:
    with_env = run(["--only=js", "--ci", str(TS_CLEAN_DIR)], env={"UBS_SKIP_TYPE_NARROWING": "1"})
    without = run(["--only=js", "--ci", str(TS_CLEAN_DIR)], env={"UBS_SKIP_TYPE_NARROWING": None})
    ok = "Type narrowing checks skipped" in with_env.stdout and "Type narrowing checks skipped" not in without.stdout
    report("env_skip_type_narrowing", ok, "", with_env if not ok else None)


def check_env_force_self_update() -> None:
    # In a development checkout the forced check reports itself instead of updating.
    proc = run(["--only=python", "--ci", str(PY_CLEAN)], env={"FORCE_SELF_UPDATE": "1", "UBS_NO_AUTO_UPDATE": None})
    report("env_force_self_update", "Development checkout detected" in proc.stderr, f"exit={proc.returncode}", proc)


def check_env_ci_disables_auto_update() -> None:
    # Run a copy of ubs outside the git checkout (so the dev-checkout guard does
    # not short-circuit) with an unreachable release base: without CI the opt-in
    # check must start ("Checking for updates"); with CI=true it must not.
    with tempfile.TemporaryDirectory(prefix="ubs-ci-") as tmp:
        bin_dir = Path(tmp) / "bin"
        bin_dir.mkdir()
        shutil.copy2(UBS, bin_dir / "ubs")
        os.symlink(REPO_ROOT / "modules", bin_dir / "modules")
        cache = Path(tmp) / "cache"
        base_env = {
            "UBS_NO_AUTO_UPDATE": None,
            "UBS_ENABLE_AUTO_UPDATE": "1",
            "UBS_RELEASE_BASE": f"file://{tmp}/no-such-release",
            "XDG_CACHE_HOME": str(cache),
            "CI": None,
        }
        cmd = [str(bin_dir / "ubs"), "--only=python", "--ci", str(PY_CLEAN)]

        def go(extra: dict) -> subprocess.CompletedProcess:
            env = os.environ.copy()
            env.update({"NO_COLOR": "1", "UBS_SKIP_SIZE_CHECK": "1"})
            for k, v in {**base_env, **extra}.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
            return subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300)

        # --ci sets CI_MODE which already disables the check; drop it to isolate the env var.
        cmd = [str(bin_dir / "ubs"), "--only=python", str(PY_CLEAN)]
        without_ci = go({})
        shutil.rmtree(cache, ignore_errors=True)
        with_ci = go({"CI": "true"})
        ok = "Checking for updates" in without_ci.stderr and "Checking for updates" not in with_ci.stderr
        report("env_ci_disables_auto_update", ok, f"without_ci_exit={without_ci.returncode} with_ci_exit={with_ci.returncode}", without_ci if not ok else None)


def main() -> int:
    for check in (
        check_unknown_flag_exit2,
        check_bad_format_exit2,
        check_documented_flags_parse,
        check_no_color_strips_ansi,
        check_output_file_positional,
        check_output_flag_json,
        check_rules_dir_custom_rule_in_sarif,
        check_include_ext_forwarded,
        check_list_categories,
        check_env_skip_type_narrowing,
        check_env_force_self_update,
        check_env_ci_disables_auto_update,
    ):
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            report(check.__name__, False, f"raised {exc!r}")
    if FAILURES:
        print(f"\n[cli-contract] {len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("\n[cli-contract] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
