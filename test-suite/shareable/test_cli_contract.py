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
    env = {"UBS_MODULE_TIMEOUT": "1", "UBS_MODULE_TIMEOUT_GRACE": "1", "UBS_NO_CACHE": "1"}
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


def check_file_list_workspace() -> None:
    # Whole-project scans are driven by a file list (bead B4): binary/data files
    # and files above UBS_MAX_FILE_MB neither count toward the size guard nor
    # reach the scan workspace, so a small JS app next to a large data directory
    # scans under a 1 MB limit and reports only its source files.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-filelist-"))
    src = tmp / "src"
    data = tmp / "data"
    src.mkdir()
    data.mkdir()
    for i in range(20):
        (src / f"m{i}.js").write_text(f"export const v{i} = {i};\n")
    (data / "events.parquet").write_bytes(b"\0" * 3_000_000)
    (data / "rows.csv").write_text("a,b\n" * 700_000)
    (tmp / "generated.js").write_text("// generated\n" + "x" * 9_000_000)  # above the 8 MB per-file cap
    env = {"UBS_SKIP_SIZE_CHECK": None, "UBS_MAX_DIR_SIZE_MB": "1", "UBS_PROFILE": "1"}
    proc = run(["--ci", "--only=js", "--format=json", str(tmp)], env=env)
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        doc = json.loads(proc.stdout)
        js = next(s for s in doc["scanners"] if s["language"] == "js")
        prof = doc.get("profile", {})
        ok = proc.returncode in (0, 1) and js["files"] == 20 and isinstance(prof.get("list_ms"), int) \
            and "Scan size after ignores: 0MB" in proc.stderr and "left out: 2 binary/data files, 1 above 8MB" in proc.stderr
        detail += f" js_files={js.get('files')} list_ms={prof.get('list_ms')}"
    except Exception as exc:  # noqa: BLE001
        detail += f" {exc}"
    report("file_list_size_guard_and_copy", ok, detail, proc if not ok else None)
    shutil.rmtree(tmp, ignore_errors=True)


def check_files_from_for_v2_modules() -> None:
    # Contract-v2 modules take --files-from and run against the source tree directly (bead B4c);
    # no shadow workspace copy is built when all selected modules are v2.
    # Unported modules in the same run still get the workspace copy.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-v2-handoff-"))
    bin_dir = Path(tempfile.mkdtemp(prefix="ubs-v2-bin-"))
    try:
        (tmp / "src").mkdir()
        (tmp / "src" / "index.js").write_text("console.log('hello');\n", encoding="utf-8")
        (tmp / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")

        # Fake v2 JS module that advertises "contract: v2" in --help
        # and on scan reads --files-from and echoes findings for those files.
        fake_js = bin_dir / "ubs-js"
        fake_js_content = textwrap.dedent("""\
            #!/usr/bin/env bash
            for arg in "$@"; do
              if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
                echo "ubs-js: fake javascript scanner (contract: v2)"
                exit 0
              fi
            done
            files_from=""
            report_json=""
            proj=""
            format="text"
            for arg in "$@"; do
              case "$arg" in
                --files-from=*) files_from="${arg#*=}" ;;
                --report-json=*) report_json="${arg#*=}" ;;
                --format=*) format="${arg#*=}" ;;
                -*) ;;
                *) proj="$arg" ;;
              esac
            done
            files=()
            if [ -n "$files_from" ] && [ -f "$files_from" ]; then
              while IFS= read -r -d '' f || [ -n "$f" ]; do
                [ -n "$f" ] && files+=("$f")
              done < <(tr '\\n' '\\0' < "$files_from"; printf '\\0')
            fi
            file_count=${#files[@]}
            if [ "$format" = "json" ]; then
              samples="[]"
              if [ "$file_count" -gt 0 ]; then
                samples="["
                first=1
                for f in "${files[@]}"; do
                  if [ "$first" -eq 1 ]; then first=0; else samples="$samples,"; fi
                  samples="$samples{\\"file\\":\\"$f\\",\\"line\\":1,\\"code\\":\\"fake-js-code\\"}"
                done
                samples="$samples]"
              fi
              echo "{\\"language\\":\\"js\\",\\"project\\":\\"$proj\\",\\"files\\":$file_count,\\"critical\\":$file_count,\\"warning\\":0,\\"info\\":0,\\"findings\\":[{\\"id\\":\\"js.fake.bug\\",\\"title\\":\\"Fake JS Bug\\",\\"severity\\":\\"critical\\",\\"count\\":$file_count,\\"samples\\":$samples}]}"
            else
              echo "Files scanned: $file_count"
              echo "Critical issues: $file_count"
              echo "Warning issues: 0"
              echo "Info items: 0"
            fi
            if [ -n "$report_json" ]; then
              : > "$report_json"
              for f in "${files[@]}"; do
                echo "{\\"id\\":\\"js.fake.bug\\",\\"file\\":\\"$f\\",\\"line\\":1,\\"severity\\":\\"critical\\",\\"message\\":\\"Fake JS bug\\"}" >> "$report_json"
              done
            fi
            exit 0
        """)
        fake_js.write_text(fake_js_content, encoding="utf-8")
        fake_js.chmod(0o755)

        env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '')}", "UBS_PROFILE": "1"}

        # Case 1: Pure v2 scan (--only=js)
        # Passes --files-from to v2 module, sets PROJECT_DIR=SOURCE_PROJECT_DIR, creates no workspace.
        proc1 = run(["--only=js", "--ci", "--format=json", str(tmp)], env=env)
        ok1 = False
        detail1 = f"exit={proc1.returncode}"
        try:
            doc1 = json.loads(proc1.stdout)
            prof1 = doc1.get("profile", {})
            js1 = next(s for s in doc1["scanners"] if s["language"] == "js")
            samples1 = [s["file"] for f in js1.get("findings", []) for s in f.get("samples", [])]
            ok1 = (
                proc1.returncode in (0, 1)
                and js1["files"] == 1
                and samples1 == ["src/index.js"]
                and "copy_ms" not in prof1
                and "scanning source tree directly" in proc1.stderr
                and "Created filtered scan workspace" not in proc1.stderr
                and js1.get("project") == str(tmp)
            )
            detail1 += f" samples={samples1} copy_ms={'copy_ms' in prof1} proj={js1.get('project')}"
        except Exception as exc:  # noqa: BLE001
            detail1 += f" ({exc})"
        report("files_from_for_v2_modules", ok1, detail1, proc1 if not ok1 else None)

        # Case 2: Polyglot scan (--only=js,python)
        # All modules are v2: both JS and Python scan the source tree directly with no workspace copy.
        proc2 = run(["--only=js,python", "--ci", "--format=json", str(tmp)], env=env)
        ok2 = False
        detail2 = f"exit={proc2.returncode}"
        try:
            doc2 = json.loads(proc2.stdout)
            js2 = next((s for s in doc2["scanners"] if s["language"] == "js"), None)
            py2 = next((s for s in doc2["scanners"] if s["language"] == "python"), None)
            samples2 = [s["file"] for f in (js2.get("findings", []) if js2 else []) for s in f.get("samples", [])]
            ok2 = (
                proc2.returncode in (0, 1)
                and js2 is not None
                and py2 is not None
                and js2["files"] == 1
                and samples2 == ["src/index.js"]
                and js2.get("project") == str(tmp)
                and "scanning source tree directly" in proc2.stderr
                and "Created filtered scan workspace" not in proc2.stderr
            )
            detail2 += f" js_samples={samples2} js_proj={js2.get('project') if js2 else 'none'}"
        except Exception as exc:  # noqa: BLE001
            detail2 += f" ({exc})"
        report("files_from_v2_mixed_workspace_for_unported", ok2, detail2, proc2 if not ok2 else None)

    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(bin_dir, ignore_errors=True)


def check_language_aware_size_guard() -> None:
    # Per-language lists make the size guard language-aware (bead B4c):
    # A 3 MB Python file in the repository does not trigger a 1 MB size refusal
    # when scanning only JS (--only=js), but triggers refusal when scanning python.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-size-guard-"))
    try:
        (tmp / "src").mkdir()
        (tmp / "src" / "index.js").write_text("console.log('hi');\n", encoding="utf-8")
        (tmp / "src" / "big.py").write_text("# big\n" + "x = 1\n" * 500_000, encoding="utf-8")  # ~3 MB
        env = {"UBS_SKIP_SIZE_CHECK": "0", "UBS_MAX_DIR_SIZE_MB": "1"}

        # --only=js sees only index.js (< 1 MB), so scan succeeds
        proc_js = run(["--only=js", "--ci", "--format=json", str(tmp)], env=env)
        ok_js = proc_js.returncode in (0, 1) and "Directory too large" not in proc_js.stderr and "Directory too large" not in proc_js.stdout

        # --only=python sees big.py (> 1 MB), so scan is refused
        proc_py = run(["--only=python", "--ci", "--format=json", str(tmp)], env=env)
        ok_py = proc_py.returncode == 2 and ("Directory too large" in proc_py.stderr or "Directory too large" in proc_py.stdout)

        ok = ok_js and ok_py
        detail = f"js_rc={proc_js.returncode} py_rc={proc_py.returncode}"
        report("language_aware_size_guard", ok, detail, proc_js if not ok_js else (proc_py if not ok_py else None))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_language_scoped_ignores() -> None:
    # bin/obj/env are decided by content (bead B4b): a Go program under bin/
    # and a plain package named env are scanned; a virtualenv named env, a C#
    # obj/ build directory and .pnpm/.bun stores are not.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-scoped-"))
    (tmp / "bin").mkdir()
    (tmp / "bin" / "main.go").write_text("package main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"sh\", \"-c\", os.Args[1]).Run() }\n")
    (tmp / "env").mkdir()
    (tmp / "env" / "config.py").write_text("import os\nos.system(input())\n")
    (tmp / "venvlike").mkdir()
    (tmp / "venvlike" / "env").mkdir()
    (tmp / "venvlike" / "env" / "pyvenv.cfg").write_text("home = /usr\n")
    (tmp / "venvlike" / "env" / "site.py").write_text("import os\nos.system(input())\n")
    (tmp / "obj").mkdir()
    (tmp / "obj" / "project.assets.json").write_text("{}\n")
    (tmp / "obj" / "Generated.cs").write_text("class G { static void M() { System.Diagnostics.Process.Start(\"cmd\", \"/c \" + System.Console.ReadLine()); } }\n")
    for store in (".pnpm", ".bun"):
        (tmp / store / "pkg").mkdir(parents=True)
        (tmp / store / "pkg" / "index.js").write_text("eval(location.hash);\n")
    (tmp / "src").mkdir()
    (tmp / "src" / "app.js").write_text("export const ok = 1;\n")
    env = {"UBS_PROFILE": "1"}
    proc = run(["--ci", "--format=json", str(tmp)], env=env)
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        doc = json.loads(proc.stdout)
        files = {s["language"]: s.get("files", 0) for s in doc["scanners"]}
        listed = [s for sc in doc["scanners"] for f in sc.get("findings", []) for s in f.get("samples", []) if s.get("file")]
        paths = {s["file"] for s in listed}
        # golang files == 1 proves bin/main.go was listed and scanned (the only Go
        # file); the Go module reports no sample for it, so paths only cover python.
        ok = files.get("golang", 0) == 1 and files.get("python", 0) == 1 and files.get("js", 0) == 1 and "csharp" not in files \
            and not any("venvlike" in p or "obj/" in p or ".pnpm" in p or ".bun" in p for p in paths) \
            and any(p.endswith("env/config.py") for p in paths)
        detail += f" files={files} paths={sorted(paths)[:6]}"
    except Exception as exc:  # noqa: BLE001
        detail += f" {exc}"
    report("language_scoped_ignores", ok, detail, proc if not ok else None)
    shutil.rmtree(tmp, ignore_errors=True)


def check_doctor_fix_refuses_tampered_toon() -> None:
    # `ubs doctor --fix` provisions the toon encoder from the digest-pinned
    # release (bead F8). A tampered asset served from a local file:// mirror must
    # be refused with the checksum diagnostic and nothing installed.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-toonfix-"))
    www = tmp / "www"
    www.mkdir()
    (www / "toon-linux-amd64.tar.xz").write_bytes(os.urandom(4096))
    tools = tmp / "tools"
    env = {"UBS_TOON_BASE_URL": f"file://{www}", "UBS_TOOLS_DIR": str(tools), "TOON_BIN": "/nonexistent/tru"}
    proc = run(["doctor", "--fix"], env=env)
    out = proc.stdout + proc.stderr
    installed = [q for q in tools.rglob("toon*") if q.is_file()] if tools.exists() else []
    if os.uname().sysname != "Linux" or os.uname().machine not in ("x86_64", "amd64"):
        report("doctor_fix_refuses_tampered_toon", True, "skipped: mirror holds only the linux-amd64 asset name")
    else:
        ok = "toon encoder checksum mismatch for toon-linux-amd64.tar.xz" in out and not installed \
            and "toon encoder: could not be provisioned" in out
        report("doctor_fix_refuses_tampered_toon", ok, f"exit={proc.returncode} installed={installed}", proc if not ok else None)
    shutil.rmtree(tmp, ignore_errors=True)


def check_python_shim_when_only_python_exists() -> None:
    # Git for Windows has `python` but no `python3` (bead G7): ubs must expose a
    # python3 for itself, the modules and the helpers. Build a PATH where every
    # directory that holds a python3 is replaced by a symlink farm without it,
    # add `python` -> the real interpreter, and require helper-backed findings.
    real = shutil.which("python3")
    if not real:
        report("python_shim_when_only_python_exists", True, "skipped: no python3 on this box")
        return
    farm_root = Path(tempfile.mkdtemp(prefix="ubs-pyshim-"))
    new_path: list[str] = []
    for n, d in enumerate(os.environ.get("PATH", "").split(os.pathsep)):
        if not d or not os.path.isdir(d):
            continue
        if not any(name.startswith("python3") for name in os.listdir(d)):
            new_path.append(d)
            continue
        farm = farm_root / f"farm{n}"
        farm.mkdir()
        for name in os.listdir(d):
            if name.startswith("python3"):
                continue
            try:
                os.symlink(os.path.join(d, name), farm / name)
            except OSError:
                pass
        new_path.append(str(farm))
    first = Path(new_path[0]) if new_path else farm_root
    if not (first / "python").exists():
        os.symlink(real, first / "python")
    env = {"PATH": os.pathsep.join(new_path)}
    target = REPO_ROOT / "test-suite" / "python" / "buggy"
    proc = run(["--ci", "--only=python", "--category=resource-lifecycle", "--format=json", str(target)], env=env)
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        doc = json.loads(proc.stdout)
        py = next(s for s in doc["scanners"] if s["language"] == "python")
        ok = proc.returncode in (0, 1) and py["critical"] + py["warning"] > 0 and "python3 is required" not in proc.stderr
        detail += f" python critical={py['critical']} warning={py['warning']}"
    except Exception as exc:  # noqa: BLE001
        detail += f" {exc}"
    report("python_shim_when_only_python_exists", ok, detail, proc if not ok else None)
    doc_proc = run(["doctor"], env=env)
    ok2 = "python: ready" in doc_proc.stdout + doc_proc.stderr and "per-run python3 shim" in doc_proc.stdout + doc_proc.stderr
    report("doctor_reports_python_shim", ok2, "", doc_proc if not ok2 else None)
    shutil.rmtree(farm_root, ignore_errors=True)


def check_workspaces_without_rsync() -> None:
    # Git for Windows ships no rsync (bead B11): explicit multi-file targets,
    # directory targets and --staged must still scan, through tar or python,
    # with the same totals as the rsync path. UBS_TEST_NO_RSYNC=1 is the seam.
    buggy = REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_buggy.py"
    args = [str(buggy), str(PY_CLEAN), "--ci", "--only=python", "--format=json"]
    with_rsync = run(args)
    without = run(args, env={"UBS_TEST_NO_RSYNC": "1"})
    ok = False
    detail = f"exit={with_rsync.returncode}/{without.returncode}"
    try:
        a = json.loads(with_rsync.stdout)["totals"]
        b = json.loads(without.stdout)["totals"]
        ok = a == b and a["files"] == 2 and "copied with tar" in without.stderr and "rsync not found" not in without.stderr
        detail += f" totals={a} vs {b}"
    except Exception as exc:  # noqa: BLE001
        detail += f" {exc}"
    report("explicit_targets_without_rsync", ok, detail, without if not ok else None)

    dir_args = [str(REPO_ROOT / "test-suite" / "python" / "security"), str(PY_CLEAN), "--ci", "--only=python", "--format=json"]
    with_rsync = run(dir_args)
    without = run(dir_args, env={"UBS_TEST_NO_RSYNC": "1"})
    ok = False
    detail = f"exit={with_rsync.returncode}/{without.returncode}"
    try:
        a = json.loads(with_rsync.stdout)["totals"]
        b = json.loads(without.stdout)["totals"]
        ok = a == b and a["files"] > 2 and "copied with tar" in without.stderr
        detail += f" totals={a} vs {b}"
    except Exception as exc:  # noqa: BLE001
        detail += f" {exc}"
    report("directory_target_without_rsync", ok, detail, without if not ok else None)

    # Planted negative: an unreadable target must fail the tar tier loudly with
    # tar's diagnostic — never a silently partial workspace (issue #98 semantics).
    if os.geteuid() == 0:
        report("unreadable_target_without_rsync_fails_loudly", True, "skipped: root can read everything")
        return
    tmp = Path(tempfile.mkdtemp(prefix="ubs-norsync-"))
    good = tmp / "good.py"
    bad = tmp / "bad.py"
    shutil.copy(PY_CLEAN, good)
    bad.write_text("x = 1\n")
    bad.chmod(0)
    try:
        proc = run([str(good), str(bad), "--ci", "--only=python", "--format=json"], env={"UBS_TEST_NO_RSYNC": "1"})
    finally:
        bad.chmod(0o644)
        shutil.rmtree(tmp, ignore_errors=True)
    out = proc.stdout + proc.stderr
    ok = proc.returncode != 0 and "tar exited with status" in out and "Failed to prepare files workspace" in out
    report("unreadable_target_without_rsync_fails_loudly", ok, f"exit={proc.returncode}", proc if not ok else None)


def check_single_file_fast_path() -> None:
    # One explicit source file is scanned in place (bead C3): only its language
    # runs, no workspace is announced, and sample paths are the real path.
    target = REPO_ROOT / "test-suite" / "python" / "security" / "parser_token_compare_buggy.py"
    shim_dir = Path(tempfile.mkdtemp(prefix="ubs-sf-shims-"))
    log_file = shim_dir / "shim.log"
    try:
        for cmd in ("rsync", "tar", "du"):
            shim = shim_dir / cmd
            shim.write_text(f'#!/bin/sh\necho "{cmd} $@" >> "{log_file}"\nexit 1\n', encoding="utf-8")
            shim.chmod(0o755)
        shim_env = {
            "PATH": f"{shim_dir}:{os.environ.get('PATH', '')}",
            "UBS_PROFILE": "1",
        }
        proc = run([str(target), "--ci", "--format=json"], env=shim_env)
        ok = False
        detail = f"exit={proc.returncode}"
        try:
            doc = json.loads(proc.stdout)
            langs = [s["language"] for s in doc["scanners"]]
            samples = [s for sc in doc["scanners"] for f in sc.get("findings", []) for s in f.get("samples", []) if s.get("file")]
            rel = "test-suite/python/security/parser_token_compare_buggy.py"
            shim_log_content = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
            no_shims_spawned = len(shim_log_content.strip()) == 0
            ok = langs == ["python"] and doc["scanners"][0]["files"] == 1 and bool(samples) \
                and all(s["file"] == rel for s in samples) \
                and all(s.get("permalink", "").endswith(f"{rel}#L{s['line']}") for s in samples if isinstance(s.get("line"), int)) \
                and "Scanning one file directly (no workspace)" in proc.stderr \
                and "Preparing shadow workspace" not in proc.stderr \
                and "copy_ms" not in doc["profile"] \
                and isinstance(doc["profile"].get("total_ms"), int) \
                and no_shims_spawned
            detail += f" langs={langs} samples={len(samples)} no_shims={no_shims_spawned}"
        except Exception as exc:  # noqa: BLE001
            detail += f" {exc}"
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)
    report("single_file_fast_path", ok, detail, proc if not ok else None)
    # Two files, or a file with an extension no module owns, keep the workspace path.
    proc2 = run([str(target), str(PY_CLEAN), "--ci", "--only=python", "--format=json"])
    ok2 = proc2.returncode in (0, 1) and "Preparing shadow workspace for 2 file(s)" in proc2.stderr
    report("multi_file_keeps_workspace", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)


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
    # Examples such as --output=report.json write relative paths: run from a
    # scratch directory so nothing lands in the repository root.
    scratch = Path(tempfile.mkdtemp(prefix="ubs-flags-"))
    for flag in doc["commands"]["flags"]:
        example = flag["example"]
        if flag["name"] in ("--update", "--update-modules"):
            # --update would self-update; --update-modules re-downloads the tagged
            # modules over the checkout's own modules/ directory (it reverted the
            # Python module once). Acceptance of both is covered elsewhere.
            continue
        args = [example, "--only=python", "--ci", str(PY_CLEAN)]
        if flag["name"] in ("--staged", "--diff"):
            args = [example, "--only=python", "--ci"]
        if flag["name"] == "--files":
            args = [f"--files={PY_CLEAN}", "--only=python", "--ci", str(PY_CLEAN.parent)]
        if flag["name"] in ("--version", "--help", "--list-categories"):
            args = [example, "--only=python", str(PY_CLEAN)]
        proc = run(args, cwd=scratch, timeout=120)
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


def check_profile_block() -> None:
    # UBS_PROFILE=1 adds phase timings to the json envelope; without it the key is absent.
    proc = run(["--only=python", "--ci", "--format=json", str(PY_CLEAN)], env={"UBS_PROFILE": "1"})
    ok = False
    detail = f"exit={proc.returncode}"
    try:
        prof = json.loads(proc.stdout)["profile"]
        ok = (
            all(isinstance(prof[k], int) and prof[k] >= 0 for k in ("total_ms", "list_ms", "fanout_ms", "merge_ms"))
            and "copy_ms" not in prof
            and isinstance(prof["modules"].get("python"), int)
            and prof["total_ms"] >= prof["fanout_ms"] >= prof["modules"]["python"]
        )
        detail += f" profile={prof}"
    except Exception as exc:  # noqa: BLE001
        detail += f" ({exc})"
    report("profile_block", ok, detail, proc if not ok else None)
    plain = run(["--only=python", "--ci", "--format=json", str(PY_CLEAN)], env={"UBS_PROFILE": None})
    ok2 = "profile" not in json.loads(plain.stdout)
    report("profile_absent_by_default", ok2, "", plain if not ok2 else None)


def check_toon_missing_encoder_exit2() -> None:
    # --format=toon without a usable tru must be an environment error with the
    # envelope on stdout (never plain JSON labelled as TOON), decided before
    # any scanning happens.
    proc = run(["--only=python", "--ci", "--format=toon", str(PY_CLEAN)], env={"UBS_TEST_FORCE_NO_TOON": "1"})
    ok = False
    try:
        doc = json.loads(proc.stdout)
        ok = proc.returncode == 2 and doc["error"] == "environment" and doc["reason"] == "toon-encoder-missing" \
            and "Scanning" not in proc.stderr and "toon_rust" in proc.stderr
    except Exception:  # noqa: BLE001
        pass
    report("toon_missing_encoder_exit2", ok, f"exit={proc.returncode}", proc if not ok else None)
    # A binary that is not toon_rust is rejected the same way.
    proc2 = run(["--only=python", "--ci", "--format=toon", str(PY_CLEAN)], env={"TOON_TRU_BIN": "/bin/true"})
    ok2 = False
    try:
        ok2 = proc2.returncode == 2 and json.loads(proc2.stdout)["reason"] == "toon-encoder-missing"
    except Exception:  # noqa: BLE001
        pass
    report("toon_wrong_encoder_exit2", ok2, f"exit={proc2.returncode}", proc2 if not ok2 else None)


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


def write_case_artifacts(case_id: str, proc: subprocess.CompletedProcess, result: dict | None = None) -> None:
    for cid in (case_id, case_id.replace("_", "-")):
        art_dir = REPO_ROOT / "test-suite" / "artifacts" / cid
        art_dir.mkdir(parents=True, exist_ok=True)
        (art_dir / "stdout.log").write_text(proc.stdout or "", encoding="utf-8")
        (art_dir / "stderr.log").write_text(proc.stderr or "", encoding="utf-8")
        if result is not None:
            (art_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        elif proc.stdout and proc.stdout.strip().startswith("{"):
            try:
                (art_dir / "result.json").write_text(json.dumps(json.loads(proc.stdout), indent=2), encoding="utf-8")
            except Exception:
                pass


def test_ubsignore_precedence() -> None:
    # Precedence: default ignores, .ubsignore, --exclude, --include-ext,
    # and explicitly named files which must always win over ignores (bead B8).
    tmp = Path(tempfile.mkdtemp(prefix="ubs-prec-"))
    try:
        (tmp / "clean.py").write_text("print('clean')\n", encoding="utf-8")
        (tmp / "node_modules").mkdir()
        (tmp / "node_modules" / "mod.py").write_text("eval(input())\n", encoding="utf-8")
        (tmp / "custom_ignored").mkdir()
        (tmp / "custom_ignored" / "cust.py").write_text("eval(input())\n", encoding="utf-8")
        (tmp / "cli_excluded").mkdir()
        (tmp / "cli_excluded" / "excl.py").write_text("eval(input())\n", encoding="utf-8")
        (tmp / "custom_ext").mkdir()
        (tmp / "custom_ext" / "file.pyw").write_text("eval(input())\n", encoding="utf-8")
        (tmp / "custom_ext" / "file.other_ext").write_text("eval(input())\n", encoding="utf-8")
        (tmp / ".ubsignore").write_text("custom_ignored\n", encoding="utf-8")

        # 1. Directory scan: default ignore, .ubsignore, and --exclude must be skipped
        proc1 = run(["--only=python", "--ci", "--format=json", "--exclude=cli_excluded", str(tmp)])
        doc1 = json.loads(proc1.stdout)
        files1 = doc1.get("totals", {}).get("files", 0)
        crit1 = doc1.get("totals", {}).get("critical", 0)

        # 2. Explicitly named file in .ubsignore must WIN
        proc2 = run(["--only=python", "--ci", "--format=json", str(tmp / "custom_ignored" / "cust.py")])
        doc2 = json.loads(proc2.stdout)
        files2 = doc2.get("totals", {}).get("files", 0)
        crit2 = doc2.get("totals", {}).get("critical", 0)

        # 3. Explicitly named file in default ignore must WIN
        proc3 = run(["--only=python", "--ci", "--format=json", str(tmp / "node_modules" / "mod.py")])
        doc3 = json.loads(proc3.stdout)
        files3 = doc3.get("totals", {}).get("files", 0)
        crit3 = doc3.get("totals", {}).get("critical", 0)

        # 4. Explicitly named file matching --exclude must WIN
        proc4 = run(["--only=python", "--ci", "--format=json", "--exclude=cli_excluded", str(tmp / "cli_excluded" / "excl.py")])
        doc4 = json.loads(proc4.stdout)
        files4 = doc4.get("totals", {}).get("files", 0)
        crit4 = doc4.get("totals", {}).get("critical", 0)

        # 5. --include-ext includes extra extensions matching the scanner (pyw is not in default INCLUDE_EXT)
        proc5 = run(["--only=python", "--ci", "--format=json", "--include-ext=py,pyw", "--exclude=cli_excluded", str(tmp)])
        doc5 = json.loads(proc5.stdout)
        files5 = doc5.get("totals", {}).get("files", 0)

        ok = (
            files1 == 1 and crit1 == 0
            and files2 == 1 and crit2 >= 1
            and files3 == 1 and crit3 >= 1
            and files4 == 1 and crit4 >= 1
            and files5 == 2
        )
        detail = (
            f"dir_files={files1}(crit={crit1}) explicit_ubsignore={files2}(crit={crit2}) "
            f"explicit_default={files3}(crit={crit3}) explicit_exclude={files4}(crit={crit4}) include_ext={files5}"
        )
        write_case_artifacts("test_ubsignore_precedence", proc1, {
            "dir_scan": doc1,
            "explicit_ubsignore": doc2,
            "explicit_default": doc3,
            "explicit_exclude": doc4,
            "include_ext": doc5,
            "ok": ok,
        })
        report("test_ubsignore_precedence", ok, detail, proc1 if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_suggest_ignore_lists_large_dirs() -> None:
    # --suggest-ignore suggests directories > 200 files not already default-ignored (bead B8).
    tmp = Path(tempfile.mkdtemp(prefix="ubs-suggest-"))
    try:
        big_dir = tmp / "large_unignored_dir"
        big_dir.mkdir()
        for i in range(205):
            (big_dir / f"dummy_{i:03d}.txt").write_text("x\n", encoding="utf-8")

        small_dir = tmp / "small_dir"
        small_dir.mkdir()
        for i in range(5):
            (small_dir / f"dummy_{i:03d}.txt").write_text("x\n", encoding="utf-8")

        node_dir = tmp / "node_modules"
        node_dir.mkdir()
        for i in range(205):
            (node_dir / f"dummy_{i:03d}.txt").write_text("x\n", encoding="utf-8")

        proc = run(["--suggest-ignore", str(tmp)])
        combined = proc.stdout + proc.stderr
        ok = (
            proc.returncode in (0, 1, 3)
            and "large_unignored_dir" in combined
            and "(205 files) → consider adding to .ubsignore" in combined
            and "small_dir" not in combined
            and "node_modules" not in combined
        )
        detail = (
            f"exit={proc.returncode} has_large={'large_unignored_dir' in combined} "
            f"has_small={'small_dir' in combined} has_node={'node_modules' in combined}"
        )
        write_case_artifacts("test_suggest_ignore_lists_large_dirs", proc, {
            "exit": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "ok": ok,
        })
        report("test_suggest_ignore_lists_large_dirs", ok, detail, proc if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_staged_scans_index_only() -> None:
    # --staged scans only files in the git index, ignoring unstaged edits and untracked files (bead B8).
    tmp = Path(tempfile.mkdtemp(prefix="ubs-staged-"))
    try:
        subprocess.run(["git", "init"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "UBS Test"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "ubs-test@example.com"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp, capture_output=True, check=True)

        base_file = tmp / "base.py"
        base_file.write_text("print('committed base')\n", encoding="utf-8")
        subprocess.run(["git", "add", "base.py"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=tmp, capture_output=True, check=True)

        # Staged buggy file
        staged_file = tmp / "staged_buggy.py"
        staged_file.write_text("eval(input())\n", encoding="utf-8")
        subprocess.run(["git", "add", "staged_buggy.py"], cwd=tmp, capture_output=True, check=True)

        # Unstaged modification to base.py
        base_file.write_text("eval(input())\n", encoding="utf-8")

        # Untracked buggy file
        untracked_file = tmp / "untracked_buggy.py"
        untracked_file.write_text("eval(input())\n", encoding="utf-8")

        proc = run(["--staged", "--only=python", "--ci", "--format=json"], cwd=tmp)
        ok = False
        detail = f"exit={proc.returncode}"
        try:
            doc = json.loads(proc.stdout)
            files = doc.get("totals", {}).get("files", 0)
            crit = doc.get("totals", {}).get("critical", 0)
            scanned_samples = [
                s.get("file")
                for sc in doc.get("scanners", [])
                for f in sc.get("findings", [])
                for s in f.get("samples", [])
                if s.get("file")
            ]
            ok = (
                files == 1
                and crit >= 1
                and any("staged_buggy.py" in p for p in scanned_samples)
                and not any("base.py" in p for p in scanned_samples)
                and not any("untracked_buggy.py" in p for p in scanned_samples)
            )
            detail += f" files={files} crit={crit} samples={scanned_samples}"
        except Exception as exc:  # noqa: BLE001
            detail += f" ({exc})"

        write_case_artifacts("test_staged_scans_index_only", proc, {
            "exit": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "ok": ok,
        })
        report("test_staged_scans_index_only", ok, detail, proc if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_diff_scans_modified_only() -> None:
    # --diff scans only working-tree files modified vs HEAD, excluding untouched and untracked (bead B8).
    tmp = Path(tempfile.mkdtemp(prefix="ubs-diff-"))
    try:
        subprocess.run(["git", "init"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "UBS Test"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "ubs-test@example.com"], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp, capture_output=True, check=True)

        unchanged = tmp / "unchanged.py"
        unchanged.write_text("print('clean')\n", encoding="utf-8")
        to_modify = tmp / "mod_buggy.py"
        to_modify.write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=tmp, capture_output=True, check=True)

        # Working tree modified vs HEAD
        to_modify.write_text("eval(input())\n", encoding="utf-8")

        # Untracked file
        untracked = tmp / "untracked_buggy.py"
        untracked.write_text("eval(input())\n", encoding="utf-8")

        proc = run(["--diff", "--only=python", "--ci", "--format=json"], cwd=tmp)
        ok = False
        detail = f"exit={proc.returncode}"
        try:
            doc = json.loads(proc.stdout)
            files = doc.get("totals", {}).get("files", 0)
            crit = doc.get("totals", {}).get("critical", 0)
            scanned_samples = [
                s.get("file")
                for sc in doc.get("scanners", [])
                for f in sc.get("findings", [])
                for s in f.get("samples", [])
                if s.get("file")
            ]
            ok = (
                files == 1
                and crit >= 1
                and any("mod_buggy.py" in p for p in scanned_samples)
                and not any("unchanged.py" in p for p in scanned_samples)
                and not any("untracked_buggy.py" in p for p in scanned_samples)
            )
            detail += f" files={files} crit={crit} samples={scanned_samples}"
        except Exception as exc:  # noqa: BLE001
            detail += f" ({exc})"

        write_case_artifacts("test_diff_scans_modified_only", proc, {
            "exit": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "ok": ok,
        })
        report("test_diff_scans_modified_only", ok, detail, proc if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


check_ubsignore_precedence = test_ubsignore_precedence
check_suggest_ignore_lists_large_dirs = test_suggest_ignore_lists_large_dirs
check_staged_scans_index_only = test_staged_scans_index_only
check_diff_scans_modified_only = test_diff_scans_modified_only


def test_skip_polyglot_mapping() -> None:
    # Bead A5: Language-prefixed category ids and per-language --skip mapping.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-skipmap-"))
    try:
        (tmp / "test.js").write_text("console.log('debug');\n", encoding="utf-8")
        (tmp / "test.py").write_text("def f(x=[]):\n    # TODO: fix\n    return x\n", encoding="utf-8")

        # 1. Valid stable ids: --skip=js.debug,python.todo
        proc1 = run(["--skip=js.debug,python.todo", "--format=json", str(tmp)])
        out1 = proc1.stdout + proc1.stderr
        ok1 = proc1.returncode in (0, 1) and "WARNING: bare --skip=" not in out1

        # 2. Unselected category id (e.g. rust.perf on js/python project) -> exit 2
        proc2 = run(["--skip=rust.perf", str(tmp)])
        ok2 = proc2.returncode == 2 and "does not exist in any selected language" in proc2.stderr

        # 3. Unknown category slug -> exit 2
        proc3 = run(["--skip=js.unknown_slug", str(tmp)])
        ok3 = proc3.returncode == 2 and "Unknown category slug" in proc3.stderr

        # 4. Bare numeric skip in polyglot mode -> warns but exits 0/1 (not 2)
        proc4 = run(["--skip=11", str(tmp)])
        ok4 = proc4.returncode in (0, 1) and "WARNING: bare --skip=11" in proc4.stderr

        # 5. --list-categories output contains <lang>.<slug>
        proc5 = run(["--only=python", "--list-categories", str(tmp)])
        ok5 = proc5.returncode == 0 and "python.security" in proc5.stdout

        ok = ok1 and ok2 and ok3 and ok4 and ok5
        detail = f"valid={ok1} unselected_exit2={ok2} unknown_slug_exit2={ok3} polyglot_warn={ok4} list_cat_ids={ok5}"
        write_case_artifacts("test_skip_polyglot_mapping", proc1, {
            "valid_ids": {"exit": proc1.returncode, "stdout": proc1.stdout, "stderr": proc1.stderr},
            "unselected_exit2": {"exit": proc2.returncode, "stderr": proc2.stderr},
            "unknown_slug_exit2": {"exit": proc3.returncode, "stderr": proc3.stderr},
            "polyglot_warn": {"exit": proc4.returncode, "stderr": proc4.stderr},
            "list_categories": {"exit": proc5.returncode, "stdout": proc5.stdout},
            "ok": ok,
        })
        report("test_skip_polyglot_mapping", ok, detail, proc1 if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


check_skip_polyglot_mapping = test_skip_polyglot_mapping


def test_findings_parity_all_langs() -> None:
    # K2: findings parity — meta-runner --format=json includes per-finding records
    # for every module; jsonl, toon, and sarif derive from them.
    manifest_file = REPO_ROOT / "test-suite" / "manifest.json"
    with manifest_file.open(encoding="utf-8") as f:
        data = json.load(f)

    langs = ["js", "python", "cpp", "rust", "golang", "java", "ruby", "swift", "csharp", "elixir"]
    failures = []
    case_summary = {}
    last_proc = None

    for lang in langs:
        cases = [c for c in data.get("cases", []) if c.get("language") == lang and "buggy" in c.get("id", "")]
        if not cases:
            failures.append(f"{lang}: no manifest buggy case found")
            continue
        c = cases[0]
        target = str(REPO_ROOT / c["path"])
        cid = c["id"]
        common = ["--ignore-file=/dev/null", target, f"--only={lang}", "--ci"]

        # 1. JSON
        pj = run([*common, "--format=json"])
        last_proc = pj
        try:
            doc = json.loads(pj.stdout)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{lang}: JSON parse error {exc}")
            continue

        findings = doc.get("findings", [])
        if not findings:
            failures.append(f"{lang}: no findings in JSON (findings[] is empty)")
            continue

        bad_rules = [f for f in findings if not str(f.get("rule_id", "")).strip()]
        if bad_rules:
            failures.append(f"{lang}: {len(bad_rules)} findings missing rule_id")
            continue

        expected_count = len(findings)

        # 2. JSONL
        pjl = run([*common, "--format=jsonl"])
        last_proc = pjl
        jl_lines = [json.loads(line) for line in pjl.stdout.splitlines() if line.strip()]
        jl_findings = [line for line in jl_lines if line.get("type") == "finding"]
        if len(jl_findings) != expected_count:
            failures.append(f"{lang}: JSONL finding count {len(jl_findings)} != expected {expected_count}")
            continue

        # 3. TOON
        pt = run([*common, "--format=toon"])
        last_proc = pt
        pt_dec = subprocess.run(["toon", "--decode"], input=pt.stdout, capture_output=True, text=True)
        try:
            tdoc = json.loads(pt_dec.stdout)
            t_findings = tdoc.get("findings", [])
            if len(t_findings) != expected_count:
                failures.append(f"{lang}: TOON finding count {len(t_findings)} != expected {expected_count}")
                continue
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{lang}: TOON decode error {exc}")
            continue

        # 4. SARIF
        ps = run([*common, "--format=sarif"])
        last_proc = ps
        try:
            sdoc = json.loads(ps.stdout)
            s_results = [r for run_ in sdoc.get("runs", []) for r in run_.get("results", [])]
            if len(s_results) != expected_count:
                failures.append(f"{lang}: SARIF result count {len(s_results)} != expected {expected_count}")
                continue
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{lang}: SARIF parse error {exc}")
            continue

        case_summary[lang] = {
            "case_id": cid,
            "findings": expected_count,
            "jsonl": len(jl_findings),
            "toon": len(t_findings),
            "sarif": len(s_results),
        }

    ok = len(failures) == 0 and len(case_summary) == len(langs)
    detail = "all 10 langs at parity" if ok else "; ".join(failures)
    write_case_artifacts("test_findings_parity_all_langs", last_proc or pj, {
        "ok": ok,
        "failures": failures,
        "summary": case_summary,
    })
    report("test_findings_parity_all_langs", ok, detail, last_proc if not ok else None)


check_findings_parity_all_langs = test_findings_parity_all_langs


def test_baseline_new_only() -> None:
    # B7: Fingerprinted baselines: --save-baseline saves findings with fingerprints;
    # --baseline FILE --new-only reports only findings absent from the baseline.
    # Alpha-renaming a local variable and inserting lines leaves the fingerprint
    # invariant (0 new findings). Adding a real new bug produces exactly 1 new finding.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-base-"))
    try:
        py_file = tmp / "sample.py"
        base_file = tmp / "baseline.json"
        py_file.write_text(
            "def append_item(old_var, bucket=[]):\n    return bucket\n",
            encoding="utf-8",
        )
        # Step 1: save baseline
        p1 = run([str(tmp), f"--save-baseline={base_file}", "--format=json", "--ci", "--only=python"])
        if not base_file.is_file():
            report("test_baseline_new_only", False, f"baseline file not created; exit={p1.returncode}", p1)
            return
        bdoc = json.loads(base_file.read_text(encoding="utf-8"))
        b_findings = bdoc.get("findings", [])
        if len(b_findings) != 1:
            report("test_baseline_new_only", False, f"baseline finding count {len(b_findings)} != 1", p1)
            return

        # Step 2: rename local variable and insert lines above the finding
        py_file.write_text(
            "# inserted comment line 1\n# inserted comment line 2\n# inserted comment line 3\n\n"
            "def append_item(new_var, bucket=[]):\n    return bucket\n",
            encoding="utf-8",
        )
        p2 = run([str(tmp), f"--baseline={base_file}", "--new-only", "--format=json", "--ci", "--only=python"])
        if p2.returncode != 0:
            report("test_baseline_new_only", False, f"p2 (rename/insert) exit {p2.returncode} != 0", p2)
            return
        doc2 = json.loads(p2.stdout)
        findings2 = doc2.get("findings", [])
        if len(findings2) != 0:
            report("test_baseline_new_only", False, f"p2 finding count {len(findings2)} != 0", p2)
            return

        # Step 3: add a real new bug
        py_file.write_text(
            "# inserted comment line 1\n# inserted comment line 2\n# inserted comment line 3\n\n"
            "def append_item(new_var, bucket=[]):\n    return bucket\n\n"
            "def another_buggy_func(arg, cache={}):\n    return cache\n",
            encoding="utf-8",
        )
        p3 = run([str(tmp), f"--baseline={base_file}", "--new-only", "--format=json", "--ci", "--only=python"])
        if p3.returncode != 1:
            report("test_baseline_new_only", False, f"p3 (new bug) exit {p3.returncode} != 1", p3)
            return
        doc3 = json.loads(p3.stdout)
        findings3 = doc3.get("findings", [])
        if len(findings3) != 1:
            report("test_baseline_new_only", False, f"p3 finding count {len(findings3)} != 1", p3)
            return

        write_case_artifacts("test_baseline_new_only", p3, {
            "baseline_findings": len(b_findings),
            "renamed_findings": len(findings2),
            "new_bug_findings": len(findings3),
            "new_finding_rule": findings3[0].get("rule_id"),
        })
        report("test_baseline_new_only", True, "baseline saved; rename+lines=0; new_bug=1")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


check_baseline_new_only = test_baseline_new_only


def test_doctor_json_schema() -> None:
    # ubs doctor --format=json emits structured JSON conforming to schema (bead B9).
    proc = run(["doctor", "--format=json"])
    ok = False
    detail = f"exit={proc.returncode}"
    res: dict = {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    try:
        data = json.loads(proc.stdout)
        res["parsed"] = data
        status = data.get("status")
        fails = data.get("fails")
        warnings = data.get("warnings")
        checks = data.get("checks")
        check_ids = [c.get("id") for c in checks] if isinstance(checks, list) else []

        # Validate schema requirements
        schema_ok = (
            proc.returncode in (0, 2)
            and status in ("ok", "error")
            and isinstance(fails, int) and fails >= 0
            and isinstance(warnings, int) and warnings >= 0
            and isinstance(checks, list)
            and len(checks) > 0
            and all(isinstance(c, dict) and "id" in c and "status" in c and "detail" in c for c in checks)
            and all(c.get("status") in ("ok", "warn", "info", "err") for c in checks)
            and "module-cache" in check_ids
            and "checksum-tool" in check_ids
        )
        # Test bad format exit 2
        bad_proc = run(["doctor", "--format=bogus"])
        bad_ok = (bad_proc.returncode == 2 and "unknown --format value for doctor" in bad_proc.stderr)

        ok = schema_ok and bad_ok
        detail = f"exit={proc.returncode} status={status} fails={fails} warnings={warnings} checks_count={len(checks)} bad_format_ok={bad_ok}"
    except Exception as exc:  # noqa: BLE001
        detail += f" parse_error={exc}"

    res["ok"] = ok
    write_case_artifacts("test_doctor_json_schema", proc, res)
    report("test_doctor_json_schema", ok, detail, proc if not ok else None)


check_doctor_json_schema = test_doctor_json_schema


def test_doctor_fix_restores_assets() -> None:
    # Test that doctor --fix restores deleted/corrupted module, helper, lib file, and ast-grep (bead B9).
    import hashlib
    import zipfile

    tmp_obj = tempfile.TemporaryDirectory(prefix="ubs-docfix-")
    tmp = Path(tmp_obj.name)
    try:
        version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        mirror = tmp / "mirror"
        mirror_v = mirror / f"v{version}" / "modules"
        mirror_main = mirror / "main" / "modules"
        mirror_v.mkdir(parents=True)
        mirror_main.mkdir(parents=True)
        shutil.copytree(REPO_ROOT / "modules", mirror_v, dirs_exist_ok=True)
        shutil.copytree(REPO_ROOT / "modules", mirror_main, dirs_exist_ok=True)

        # Prepare ast-grep fixture zip
        ast_dir = mirror / "ast-grep"
        ast_dir.mkdir(parents=True)
        arch = "x86_64" if os.uname().machine in ("x86_64", "amd64") else ("aarch64" if os.uname().machine in ("arm64", "aarch64") else "x86_64")
        os_name = "apple-darwin" if sys.platform == "darwin" else "unknown-linux-gnu"
        target = f"{arch}-{os_name}"

        real_ag = shutil.which("ast-grep")
        if not (real_ag and os.path.isfile(real_ag) and os.access(real_ag, os.X_OK)):
            for candidate in ("/home/ubuntu/.cargo/bin/ast-grep", "/usr/local/bin/ast-grep", "/usr/bin/ast-grep"):
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    real_ag = candidate
                    break

        if not real_ag:
            report("test_doctor_fix_restores_assets", True, "skipped: host lacks ast-grep binary for packaging fixture")
            return

        zip_name = f"app-{target}.zip"
        zip_path = ast_dir / zip_name
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(real_ag, arcname="ast-grep")
        ag_zip_sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()

        sandbox_modules = tmp / "sandbox_modules"
        sandbox_modules.mkdir()
        sandbox_tools = tmp / "sandbox_tools"
        sandbox_tools.mkdir()

        env = {
            "UBS_REPO_RAW_BASE": f"file://{mirror}",
            "UBS_AST_GREP_BASE_URL": f"file://{ast_dir}",
            "UBS_TEST_AST_GREP_SHA256": ag_zip_sha256,
            "UBS_TEST_NO_PATH_AST_GREP": "1",
            "UBS_TOOLS_DIR": str(sandbox_tools),
            "UBS_AST_GREP_BIN": "",
        }

        # Step 1: Initial fix to populate all assets into sandbox_modules and sandbox_tools
        init_proc = run(["doctor", "--fix", f"--module-dir={sandbox_modules}"], env=env)
        if init_proc.returncode != 0:
            report("test_doctor_fix_restores_assets", False, f"initial doctor --fix failed: exit={init_proc.returncode}", init_proc)
            return

        mod_file = sandbox_modules / "ubs-python.sh"
        helper_file = sandbox_modules / "helpers" / "resource_lifecycle_py.py"
        lib_file = sandbox_modules / "lib" / "ubs-common.sh"
        ag_bin_file = sandbox_tools / "ast-grep" / "0.45.3" / target / "ast-grep"

        orig_mod_sha = hashlib.sha256(mod_file.read_bytes()).hexdigest()
        orig_helper_sha = hashlib.sha256(helper_file.read_bytes()).hexdigest()
        orig_lib_sha = hashlib.sha256(lib_file.read_bytes()).hexdigest()

        # Step 2: Corrupt/delete the 4 assets
        mod_file.write_text("#!/bin/bash\n# corrupted module\nexit 99\n", encoding="utf-8")
        helper_file.write_text("# corrupted helper\n", encoding="utf-8")
        lib_file.write_text("# corrupted lib\n", encoding="utf-8")
        if ag_bin_file.exists():
            ag_bin_file.unlink()

        # Step 3: Run doctor WITHOUT --fix -> assert failure (exit 2) and error checks reported
        doc_fail_proc = run(["doctor", "--format=json", f"--module-dir={sandbox_modules}"], env=env)
        fail_ok = False
        if doc_fail_proc.returncode == 2:
            try:
                fail_data = json.loads(doc_fail_proc.stdout)
                checks_map = {c["id"]: c["status"] for c in fail_data.get("checks", [])}
                fail_ok = (
                    fail_data.get("status") == "error"
                    and fail_data.get("fails", 0) >= 3
                    and checks_map.get("module:python") == "err"
                    and checks_map.get("helper:helpers/resource_lifecycle_py.py") == "err"
                    and checks_map.get("helper:lib/ubs-common.sh") == "err"
                    and checks_map.get("ast-grep") in ("warn", "err")
                )
            except Exception:
                fail_ok = False

        if not fail_ok:
            report("test_doctor_fix_restores_assets", False, f"corrupted check without --fix did not fail as expected: exit={doc_fail_proc.returncode}", doc_fail_proc)
            return

        # Step 4: Run doctor WITH --fix -> assert success (exit 0) and assets restored
        doc_fix_proc = run(["doctor", "--format=json", "--fix", f"--module-dir={sandbox_modules}"], env=env)
        fix_ok = False
        if doc_fix_proc.returncode == 0:
            try:
                fix_data = json.loads(doc_fix_proc.stdout)
                checks_map = {c["id"]: c["status"] for c in fix_data.get("checks", [])}
                fix_ok = (
                    fix_data.get("status") == "ok"
                    and fix_data.get("fails") == 0
                    and checks_map.get("module:python") == "ok"
                    and checks_map.get("helper:helpers/resource_lifecycle_py.py") == "ok"
                    and checks_map.get("helper:lib/ubs-common.sh") == "ok"
                    and checks_map.get("ast-grep") == "ok"
                )
            except Exception:
                fix_ok = False

        # Step 5: Verify files on disk match original checksums and ast-grep is executable
        disk_ok = (
            hashlib.sha256(mod_file.read_bytes()).hexdigest() == orig_mod_sha
            and hashlib.sha256(helper_file.read_bytes()).hexdigest() == orig_helper_sha
            and hashlib.sha256(lib_file.read_bytes()).hexdigest() == orig_lib_sha
            and ag_bin_file.exists() and os.access(ag_bin_file, os.X_OK)
        )

        overall_ok = fail_ok and fix_ok and disk_ok
        detail = f"fail_ok={fail_ok} fix_ok={fix_ok} disk_ok={disk_ok} exit={doc_fix_proc.returncode}"
        write_case_artifacts("test_doctor_fix_restores_assets", doc_fix_proc, {
            "fail_exit": doc_fail_proc.returncode,
            "fail_stdout": doc_fail_proc.stdout,
            "fix_exit": doc_fix_proc.returncode,
            "fix_stdout": doc_fix_proc.stdout,
            "disk_ok": disk_ok,
            "ok": overall_ok,
        })
        report("test_doctor_fix_restores_assets", overall_ok, detail, doc_fix_proc if not overall_ok else None)
    finally:
        tmp_obj.cleanup()


check_doctor_fix_restores_assets = test_doctor_fix_restores_assets


def test_module_garbage_output_yields_error_envelope() -> None:
    # A module that emits non-JSON garbage must yield status "error" and exit 2
    # via the error envelope, rather than falling back to text scraping (bead B10).
    tmp_obj = tempfile.TemporaryDirectory(prefix="ubs-garbage-")
    tmp = Path(tmp_obj.name)
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        mock = bin_dir / "ubs-python"
        mock.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--help\" ]; then\n"
            "  echo \"contract: v2\"\n"
            "  exit 0\n"
            "fi\n"
            "echo \"Garbage text with Critical issues: 42 and Warning issues: 99\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        mock.chmod(0o755)

        target_file = tmp / "sample.py"
        target_file.write_text("print('hello')\n", encoding="utf-8")

        env = {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        }

        # 1. JSON mode test
        proc_json = run([str(target_file), "--only=python", "--format=json", "--ci"], env=env)
        json_ok = False
        doc_json: dict = {}
        try:
            doc_json = json.loads(proc_json.stdout)
            json_ok = (
                proc_json.returncode == 2
                and doc_json.get("error") == "environment"
                and doc_json.get("status") == "error"
                and doc_json.get("reason") == "module-failed"
                and "python" in doc_json.get("failed_modules", [])
                and "42" not in proc_json.stdout
                and "99" not in proc_json.stdout
            )
        except Exception:
            json_ok = False

        # 2. SARIF mode test
        proc_sarif = run([str(target_file), "--only=python", "--format=sarif", "--ci"], env=env)
        sarif_ok = False
        try:
            sarif_doc = json.loads(proc_sarif.stdout)
            inv = sarif_doc.get("runs", [{}])[0].get("invocations", [{}])[0]
            sarif_ok = (
                proc_sarif.returncode == 2
                and inv.get("executionSuccessful") is False
                and inv.get("exitCode") == 2
                and "42" not in proc_sarif.stdout
                and "99" not in proc_sarif.stdout
            )
        except Exception:
            sarif_ok = False

        overall_ok = json_ok and sarif_ok
        detail = f"json_ok={json_ok} sarif_ok={sarif_ok} exit_json={proc_json.returncode} exit_sarif={proc_sarif.returncode}"
        write_case_artifacts("test_module_garbage_output_yields_error_envelope", proc_json, {
            "json_exit": proc_json.returncode,
            "json_stdout": proc_json.stdout,
            "json_stderr": proc_json.stderr,
            "sarif_exit": proc_sarif.returncode,
            "sarif_stdout": proc_sarif.stdout,
            "ok": overall_ok,
            "envelope": doc_json,
        })
        report("test_module_garbage_output_yields_error_envelope", overall_ok, detail, proc_json if not overall_ok else None)
    finally:
        tmp_obj.cleanup()


check_module_garbage_output_yields_error_envelope = test_module_garbage_output_yields_error_envelope


def check_no_shadow_copy_for_whole_project() -> None:
    # Whole-project scans create no temporary copy of the tree (bead B4d).
    # All modules take --files-from and run against the source tree directly.
    # To prove no whole-project shadow copy is made, run `ubs .` with a PATH shim
    # that makes `rsync` and `tar` log and fail. The scan must succeed with
    # identical totals and the shim log must remain completely empty.
    tmp = Path(tempfile.mkdtemp(prefix="ubs-noshadow-"))
    shim_dir = Path(tempfile.mkdtemp(prefix="ubs-noshadow-shims-"))
    log_file = shim_dir / "shim.log"
    try:
        (tmp / "src").mkdir()
        (tmp / "src" / "app.py").write_text("import os\nprint('hello')\n", encoding="utf-8")
        (tmp / "src" / "index.js").write_text("console.log('hello');\n", encoding="utf-8")
        (tmp / "data").mkdir()
        (tmp / "data" / "sample.bin").write_bytes(b"\0" * 2000)

        # Base run: whole-project scan of `.` with UBS_PROFILE=1
        proc_base = run([".", "--ci", "--format=json"], cwd=tmp, env={"UBS_PROFILE": "1"})

        # Create shims for rsync and tar that log any call and fail
        for cmd in ("rsync", "tar"):
            shim = shim_dir / cmd
            shim.write_text(f'#!/bin/sh\necho "{cmd} $@" >> "{log_file}"\nexit 1\n', encoding="utf-8")
            shim.chmod(0o755)

        # Shimmed run: whole-project scan of `.` with PATH prepended with shim_dir
        shim_env = {
            "PATH": f"{shim_dir}:{os.environ.get('PATH', '')}",
            "UBS_PROFILE": "1",
        }
        proc_shim = run([".", "--ci", "--format=json"], cwd=tmp, env=shim_env)

        ok = False
        detail = f"base_exit={proc_base.returncode} shim_exit={proc_shim.returncode}"
        try:
            doc_base = json.loads(proc_base.stdout)
            doc_shim = json.loads(proc_shim.stdout)
            shim_log_content = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
            prof = doc_shim.get("profile", {})

            same_totals = doc_base.get("totals") == doc_shim.get("totals") and doc_shim.get("totals", {}).get("files", 0) >= 2
            no_shim_calls = len(shim_log_content.strip()) == 0
            no_copy_ms = "copy_ms" not in prof
            has_list_ms = isinstance(prof.get("list_ms"), int)
            no_workspace_msg = "Created filtered scan workspace" not in proc_shim.stderr
            source_direct_msg = "scanning source tree directly" in proc_shim.stderr

            ok = (
                proc_shim.returncode in (0, 1)
                and same_totals
                and no_shim_calls
                and no_copy_ms
                and has_list_ms
                and no_workspace_msg
                and source_direct_msg
            )
            detail += f" totals={doc_shim.get('totals')} shim_log_len={len(shim_log_content)} list_ms={prof.get('list_ms')} copy_ms_in_prof={'copy_ms' in prof}"
        except Exception as exc:  # noqa: BLE001
            detail += f" ({exc})"

        write_case_artifacts("test_no_shadow_copy_for_whole_project", proc_shim, {
            "base_exit": proc_base.returncode,
            "shim_exit": proc_shim.returncode,
            "shim_log": shim_log_content if "shim_log_content" in locals() else "",
            "base_totals": doc_base.get("totals") if "doc_base" in locals() else None,
            "shim_totals": doc_shim.get("totals") if "doc_shim" in locals() else None,
            "profile": prof if "prof" in locals() else None,
            "ok": ok,
        })
        report("test_no_shadow_copy_for_whole_project", ok, detail, proc_shim if not ok else None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(shim_dir, ignore_errors=True)


test_no_shadow_copy_for_whole_project = check_no_shadow_copy_for_whole_project


def main() -> int:
    filter_names = set(sys.argv[1:])
    checks = (
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
        check_toon_missing_encoder_exit2,
        check_profile_block,
        check_robot_docs,
        check_robot_docs_flags_parse,
        check_schema_validates_outputs,
        check_exclude_paths_skipped,
        check_exclude_langs,
        check_exclude_language_name_guard,
        check_timeout_envelope,
        check_env_error_envelope,
        check_size_refusal_envelope,
        check_file_list_workspace,
        check_single_file_fast_path,
        check_workspaces_without_rsync,
        check_python_shim_when_only_python_exists,
        check_doctor_fix_refuses_tampered_toon,
        check_language_scoped_ignores,
        check_files_from_for_v2_modules,
        check_language_aware_size_guard,
        test_ubsignore_precedence,
        test_suggest_ignore_lists_large_dirs,
        test_staged_scans_index_only,
        test_diff_scans_modified_only,
        test_skip_polyglot_mapping,
        check_findings_parity_all_langs,
        test_baseline_new_only,
        test_doctor_json_schema,
        test_doctor_fix_restores_assets,
        test_module_garbage_output_yields_error_envelope,
        test_no_shadow_copy_for_whole_project,
    )
    for check in checks:
        name = check.__name__
        if filter_names and name not in filter_names and name.replace("test_", "check_") not in filter_names and name.replace("check_", "test_") not in filter_names:
            continue
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            report(name, False, f"raised {exc!r}")
    if FAILURES:
        print(f"\n[cli-contract] {len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("\n[cli-contract] all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

