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


def check_timeout_envelope() -> None:
    # A module that blows UBS_MODULE_TIMEOUT must be reported as status=timeout,
    # the run as status=partial with failed_modules, and the exit code must be 2
    # (a green exit has to mean every requested language was scanned). The
    # Python module needs several seconds on the python fixture tree, so a 1s
    # budget times out deterministically without any module stub.
    env = {"UBS_MODULE_TIMEOUT": "1", "UBS_MODULE_TIMEOUT_GRACE": "1"}
    proc = run(["--only=python", "--ci", "--format=json", str(REPO_ROOT / "test-suite" / "python")], env=env)
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        doc = json.loads(proc.stdout)
        failed = doc.get("failed_modules") or []
        scanner = next((s for s in doc.get("scanners", []) if s.get("language") == "python"), {})
        ok = (
            proc.returncode == 2
            and doc.get("status") == "partial"
            and failed and failed[0]["language"] == "python" and failed[0]["status"] == "timeout"
            and scanner.get("status") == "timeout" and scanner.get("critical") == 0
            and "Partial run" in proc.stderr
        )
        detail += f" status={doc.get('status')} failed={failed}"
    except Exception as exc:  # noqa: BLE001
        detail += f" (stdout not JSON: {exc})"
    report("timeout_envelope", ok, detail, proc if not ok else None)

    # UBS_ALLOW_PARTIAL=1 restores the findings-based exit but the envelope still says partial.
    proc2 = run(["--only=python", "--ci", "--format=json", str(REPO_ROOT / "test-suite" / "python")], env={**env, "UBS_ALLOW_PARTIAL": "1"})
    ok2 = False
    try:
        doc2 = json.loads(proc2.stdout)
        ok2 = proc2.returncode in (0, 1) and doc2.get("status") == "partial" and "UBS_ALLOW_PARTIAL=1" in proc2.stderr
    except Exception:  # noqa: BLE001
        pass
    report("timeout_allow_partial", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)

    # SARIF: every run is marked executionSuccessful=false with one notification per failed module.
    proc3 = run(["--only=python", "--ci", "--format=sarif", str(REPO_ROOT / "test-suite" / "python")], env=env)
    ok3 = False
    try:
        runs = json.loads(proc3.stdout)["runs"]
        ok3 = proc3.returncode == 2 and runs and all(
            r["invocations"][0]["executionSuccessful"] is False
            and r["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"] == "ubs/module-timeout"
            for r in runs
        )
    except Exception:  # noqa: BLE001
        pass
    report("timeout_sarif_invocations", ok3, f"exit={proc3.returncode}", proc3 if not ok3 else None)


def check_env_error_envelope() -> None:
    # Missing ast-grep is an environment error: exit 2 and an envelope on stdout
    # in every machine format (previously SARIF mode printed nothing).
    env = {"UBS_TEST_RUNNER_NO_AST_GREP": "1"}
    proc = run(["--only=js", "--ci", "--format=json", str(JS_DEBUG)], env=env)
    ok = False
    try:
        doc = json.loads(proc.stdout)
        ok = proc.returncode == 2 and doc["error"] == "environment" and doc["status"] == "error" \
            and doc["reason"] == "ast-grep-missing" and doc["failed_modules"] == ["js"] and doc["exit_code"] == 2
    except Exception:  # noqa: BLE001
        pass
    report("env_error_envelope_json", ok, f"exit={proc.returncode}", proc if not ok else None)

    proc2 = run(["--only=js", "--ci", "--format=sarif", str(JS_DEBUG)], env=env)
    ok2 = False
    try:
        inv = json.loads(proc2.stdout)["runs"][0]["invocations"][0]
        ok2 = proc2.returncode == 2 and inv["executionSuccessful"] is False and inv["exitCode"] == 2 \
            and inv["toolExecutionNotifications"][0]["descriptor"]["id"] == "ubs/ast-grep-missing"
    except Exception:  # noqa: BLE001
        pass
    report("env_error_envelope_sarif", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)


def check_size_refusal_envelope() -> None:
    # The directory-size guard refuses with exit 2; in machine formats the
    # refusal is an object on stdout and the human text moves to stderr.
    env = {"UBS_SKIP_SIZE_CHECK": None, "UBS_MAX_DIR_SIZE_MB": "1"}
    # A synthetic 3 MB tree: the fixture trees are under 1 MB after ignores.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-size-refusal-"))
    target = tmp / "big"
    target.mkdir()
    (target / "big.js").write_text("x" * 3_000_000)
    proc = run(["--ci", "--format=json", str(target)], env=env)
    ok = False
    try:
        doc = json.loads(proc.stdout)
        ok = proc.returncode == 2 and doc["error"] == "refused" and doc["status"] == "refused" \
            and doc["reason"] == "directory-too-large" and doc["limit_mb"] == 1 and doc["size_mb"] > 1 \
            and "Directory too large" in proc.stderr and proc.stdout.count("\n") == 1
    except Exception:  # noqa: BLE001
        pass
    report("size_refusal_envelope_json", ok, f"exit={proc.returncode}", proc if not ok else None)

    proc2 = run(["--ci", "--format=jsonl", str(target)], env=env)
    ok2 = False
    try:
        line = json.loads(proc2.stdout.strip().splitlines()[0])
        ok2 = proc2.returncode == 2 and line["type"] == "error" and line["reason"] == "directory-too-large"
    except Exception:  # noqa: BLE001
        pass
    report("size_refusal_envelope_jsonl", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)

    # Text mode keeps the human message on stdout and no envelope.
    proc3 = run(["--ci", str(target)], env=env)
    ok3 = proc3.returncode == 2 and "Directory too large" in proc3.stdout and '"error"' not in proc3.stdout
    report("size_refusal_text", ok3, f"exit={proc3.returncode}", proc3 if not ok3 else None)


def _exclude_project() -> Path:
    # legacy/ holds a buggy file, src/ a clean one, plus a JS file so two
    # languages are detected for the --exclude-langs check.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-exclude-"))
    (tmp / "legacy").mkdir()
    (tmp / "src").mkdir()
    shutil.copy(REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_buggy.py", tmp / "legacy" / "bad.py")
    shutil.copy(PY_CLEAN, tmp / "src" / "ok.py")
    (tmp / "src" / "app.js").write_text("export const answer = 42;\n")
    return tmp


def check_exclude_paths_skipped() -> None:
    # --exclude takes path globs (README semantics): the buggy file under
    # legacy/ must not be scanned, and the file count must drop accordingly.
    proj = _exclude_project()
    with_legacy = run(["--only=python", "--ci", "--format=json", str(proj)])
    excluded = run(["--only=python", "--exclude=legacy", "--ci", "--format=json", str(proj)])
    ok = False
    detail = f"exit(with)={with_legacy.returncode} exit(excluded)={excluded.returncode}"
    try:
        before = json.loads(with_legacy.stdout)["totals"]
        after = json.loads(excluded.stdout)["totals"]
        ok = before["critical"] > 0 and after["critical"] == 0 and after["files"] == 1 and excluded.returncode == 0
        detail += f" before={before} after={after}"
    except Exception as exc:  # noqa: BLE001
        detail += f" ({exc})"
    report("exclude_paths_skipped", ok, detail, excluded if not ok else None)
    # Space form and comma-separated globs are accepted too.
    proc = run(["--only=python", "--exclude", "legacy,*.tmp", "--ci", "--format=json", str(proj)])
    ok2 = False
    try:
        ok2 = proc.returncode == 0 and json.loads(proc.stdout)["totals"]["files"] == 1
    except Exception:  # noqa: BLE001
        pass
    report("exclude_paths_space_form", ok2, f"exit={proc.returncode}", proc if not ok2 else None)


def check_exclude_langs() -> None:
    proj = _exclude_project()
    proc = run(["--exclude-langs=python", "--ci", "--format=json", str(proj)])
    ok = False
    try:
        langs = [s["language"] for s in json.loads(proc.stdout)["scanners"]]
        ok = "python" not in langs and "js" in langs
    except Exception:  # noqa: BLE001
        pass
    report("exclude_langs", ok, f"exit={proc.returncode}", proc if not ok else None)
    # Excluding every detected language means nothing was scanned: exit 3, not a pass.
    proc2 = run(["--exclude-langs=python,js", "--ci", "--format=json", str(proj)])
    ok2 = proc2.returncode == 3
    report("exclude_langs_all_exit3", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)


def check_exclude_language_name_guard() -> None:
    # A stale `--exclude=js` (old language semantics) must be rejected with the
    # fix when no path of that name exists, and accepted when the path exists.
    proj = _exclude_project()
    proc = run(["--exclude=js", "--ci", "--format=json", str(proj)])
    ok = proc.returncode == 2 and "--exclude-langs=js" in proc.stderr
    report("exclude_language_name_guard", ok, f"exit={proc.returncode}", proc if not ok else None)
    (proj / "js").mkdir()
    (proj / "js" / "vendor.js").write_text("var x = 1;\n")
    proc2 = run(["--exclude=js", "--only=python", "--ci", "--format=json", str(proj)])
    ok2 = proc2.returncode in (0, 1) and "--exclude-langs" not in proc2.stderr
    report("exclude_language_name_allowed_when_path_exists", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)


def check_robot_docs() -> None:
    # `ubs robot-docs [topic]` is one JSON document on stdout with version metadata.
    proc = run(["robot-docs"])
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        doc = json.loads(proc.stdout)
        ok = (
            proc.returncode == 0
            and doc["schema_version"] == "1"
            and doc["ubs_version"]
            and doc["topic"] == "all"
            and {"guide", "commands", "examples", "exit_codes", "formats", "env"} <= set(doc)
            and sorted(e["code"] for e in doc["exit_codes"]) == [0, 1, 2, 3]
            and all(f in doc["formats"] for f in ("json", "jsonl", "sarif", "toon", "text"))
        )
    except Exception as exc:  # noqa: BLE001
        detail += f" ({exc})"
    report("robot_docs_all", ok, detail, proc if not ok else None)

    topic = run(["robot-docs", "exit-codes"])
    ok2 = False
    try:
        doc = json.loads(topic.stdout)
        ok2 = topic.returncode == 0 and doc["topic"] == "exit-codes" and len(doc["exit_codes"]) == 4 and "guide" not in doc
    except Exception:  # noqa: BLE001
        pass
    report("robot_docs_topic", ok2, f"exit={topic.returncode}", topic if not ok2 else None)

    bad = run(["robot-docs", "bogus"])
    report("robot_docs_unknown_topic_exit2", bad.returncode == 2 and bad.stdout.strip() == "", f"exit={bad.returncode}", bad)


def check_robot_docs_flags_parse() -> None:
    # Every flag robot-docs advertises must be accepted by the parser, using the
    # documented example form. Flags that change what runs (update, help,
    # version, list-categories, staged/diff/files, suggest-ignore) are exercised
    # for acceptance only.
    doc = json.loads(run(["robot-docs", "commands"]).stdout)
    bad = []
    for flag in doc["commands"]["flags"]:
        example = flag["example"]
        if flag["name"] in ("--update",):
            continue  # would try to self-update; covered by env_force_self_update
        args = [example, "--only=python", "--ci", str(PY_CLEAN)]
        if flag["name"] in ("--staged", "--diff", "--files"):
            args = [example, "--only=python", "--ci"]
        if flag["name"] in ("--version", "--help", "--list-categories"):
            args = [example, "--only=python", str(PY_CLEAN)]
        proc = run(args, timeout=120)
        text = proc.stdout + proc.stderr
        if "unknown option" in text or "scan target not found" in text or (proc.returncode == 2 and flag["name"] not in ("--exclude",)):
            bad.append((flag["name"], example, proc.returncode, text.strip()[-160:]))
    report("robot_docs_flags_parse", not bad, "; ".join(f"{n} ({e}): exit {rc}: {t}" for n, e, rc, t in bad))


def check_schema_validates_outputs() -> None:
    # `ubs --schema=<fmt>` must validate the real outputs of that format,
    # including the partial, no-scan and error shapes.
    try:
        import jsonschema  # type: ignore
    except ImportError:
        report("schema_validates_outputs", False, "jsonschema not installed (uv sync installs the dev group)")
        return
    schemas = {fmt: json.loads(run([f"--schema={fmt}"]).stdout) for fmt in ("json", "jsonl", "sarif", "error")}
    problems: list[str] = []

    def validate(fmt: str, label: str, instance) -> None:
        try:
            jsonschema.Draft202012Validator(schemas[fmt]).validate(instance)
        except jsonschema.ValidationError as exc:
            problems.append(f"{label} vs {fmt}: {exc.message[:160]} at {list(exc.absolute_path)}")

    py_tree = REPO_ROOT / "test-suite" / "python"
    samples = {
        "json:clean": run(["--only=python", "--ci", "--format=json", str(PY_CLEAN)]),
        "json:findings": run(["--only=python", "--ci", "--format=json", str(PY_CLEAN.parent / "parser_token_compare_buggy.py")]),
        "json:partial": run(["--only=python", "--ci", "--format=json", str(py_tree)], env={"UBS_MODULE_TIMEOUT": "1", "UBS_MODULE_TIMEOUT_GRACE": "1"}),
        "json:env-error": run(["--only=js", "--ci", "--format=json", str(JS_DEBUG)], env={"UBS_TEST_RUNNER_NO_AST_GREP": "1"}),
    }
    for label, proc in samples.items():
        try:
            validate("json", label, json.loads(proc.stdout))
        except json.JSONDecodeError as exc:
            problems.append(f"{label}: stdout is not JSON ({exc})")
    with tempfile.TemporaryDirectory(prefix="ubs-noscan-") as tmp:
        (Path(tmp) / "notes.txt").write_text("nothing scannable\n")
        noscan = run(["--ci", "--format=json", tmp])
        try:
            validate("json", "json:no-scan", json.loads(noscan.stdout))
        except json.JSONDecodeError as exc:
            problems.append(f"json:no-scan: stdout is not JSON ({exc})")
    for label, instance in (
        ("error:env", json.loads(samples["json:env-error"].stdout)),
    ):
        validate("error", label, instance)
    jsonl = run(["--only=python", "--ci", "--format=jsonl", str(PY_CLEAN.parent / "parser_token_compare_buggy.py")])
    lines = [line for line in jsonl.stdout.splitlines() if line.strip()]
    if not lines:
        problems.append("jsonl: no output lines")
    for i, line in enumerate(lines):
        try:
            validate("jsonl", f"jsonl:line{i}", json.loads(line))
        except json.JSONDecodeError as exc:
            problems.append(f"jsonl:line{i}: not JSON ({exc})")
    sarif_ok = run(["--only=js", "--ci", "--format=sarif", str(JS_DEBUG)])
    sarif_partial = run(["--only=python", "--ci", "--format=sarif", str(py_tree)], env={"UBS_MODULE_TIMEOUT": "1", "UBS_MODULE_TIMEOUT_GRACE": "1"})
    sarif_err = run(["--only=js", "--ci", "--format=sarif", str(JS_DEBUG)], env={"UBS_TEST_RUNNER_NO_AST_GREP": "1"})
    for label, proc in (("sarif:ok", sarif_ok), ("sarif:partial", sarif_partial), ("sarif:error", sarif_err)):
        try:
            validate("sarif", label, json.loads(proc.stdout))
        except json.JSONDecodeError as exc:
            problems.append(f"{label}: stdout is not JSON ({exc})")
    report("schema_validates_outputs", not problems, "; ".join(problems)[:1500])


def check_status_ok_on_clean_run() -> None:
    proc = run(["--only=python", "--ci", "--format=json", str(PY_CLEAN)])
    ok = False
    try:
        doc = json.loads(proc.stdout)
        ok = proc.returncode == 0 and doc["status"] == "ok" and doc["failed_modules"] == [] \
            and all(s.get("status") == "ok" for s in doc["scanners"])
    except Exception:  # noqa: BLE001
        pass
    report("status_ok_on_clean_run", ok, f"exit={proc.returncode}", proc if not ok else None)


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
        check_status_ok_on_clean_run,
        check_robot_docs,
        check_robot_docs_flags_parse,
        check_schema_validates_outputs,
        check_exclude_paths_skipped,
        check_exclude_langs,
        check_exclude_language_name_guard,
        check_timeout_envelope,
        check_env_error_envelope,
        check_size_refusal_envelope,
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
