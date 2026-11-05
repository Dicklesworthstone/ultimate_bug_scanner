#!/usr/bin/env python3
"""Real CLI regressions for report delivery and protection of scan inputs.

Every source, command, output stream and before-image is retained under
test-suite/artifacts/report-delivery. Fault controls replace only the external
tee writer; the ordinary runner, modules and integrity checks remain active.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
UBS = ROOT / "ubs"
ARTIFACTS = ROOT / "test-suite" / "artifacts" / "report-delivery"
UNSAFE = '#!/bin/bash\nuser_command="$1"\neval "$user_command"\n'
CLEAN = '#!/bin/bash\nprintf "%s\\n" "hello"\n'
SENTINEL = b"previous complete report\n"
DESTINATIONS = (
    "--output={}", "--report-json={}", "--html-report={}",
    "--save-baseline={}", "--beads-jsonl={}", "--also=json:{}",
)


class ReportDeliveryTests(unittest.TestCase):
    def setUp(self):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=ARTIFACTS))
        self.scratch = self.work / "scratch"
        self.scratch.mkdir()
        self.calls = 0
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("UBS_", "GIT_", "XDG_", "TOON_"))
            and key not in {"PYTHONPATH", "JOBS", "ENABLE_UV_TOOLS", "UPDATE_GOLDENS"}
        }
        self.env.update(
            UBS_KEEP_TEMP="1", UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
            UBS_NO_CACHE="1", ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1",
            NO_COLOR="1", TMPDIR=str(self.scratch),
            XDG_CONFIG_HOME=str(self.work / "config"),
            XDG_CACHE_HOME=str(self.work / "cache"),
            XDG_DATA_HOME=str(self.work / "data"),
        )

    def source(self, name="unsafe.sh", text=UNSAFE):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.with_name(path.name + ".before").write_bytes(path.read_bytes())
        return path

    def invoke(self, *args, fmt="json", env=None, cwd=None, language="bash"):
        self.calls += 1
        command = [
            str(UBS), f"--only={language}", "--ci", f"--format={fmt}",
            "--no-config", "--no-cache", "--ignore-file=/dev/null",
            f"--module-dir={ROOT / 'modules'}", *map(str, args),
        ]
        directory = cwd or self.work
        prefix = self.work / f"scan-{self.calls:03d}"
        with prefix.with_suffix(".stdout").open("w", encoding="utf-8") as out:
            with prefix.with_suffix(".stderr").open("w", encoding="utf-8") as err:
                result = subprocess.run(  # ubs:ignore[python.taint.command] Fixture argv, no shell.
                    command, cwd=directory, env={**self.env, **(env or {})},
                    stdout=out, stderr=err, timeout=90, check=False,
                )
        result.stdout = prefix.with_suffix(".stdout").read_text(encoding="utf-8")
        result.stderr = prefix.with_suffix(".stderr").read_text(encoding="utf-8")
        prefix.with_suffix(".receipt.json").write_text(json.dumps({
            "command": command, "cwd": str(directory), "exit_code": result.returncode,
            "ubs_sha256": hashlib.sha256(UBS.read_bytes()).hexdigest(),
            "stdout": str(prefix.with_suffix(".stdout")),
            "stderr": str(prefix.with_suffix(".stderr")),
        }, indent=2) + "\n", encoding="utf-8")
        return result

    def assert_refused(self, result, text):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("report", result.stderr.lower())
        self.assertIn(text, result.stderr.lower())

    def alias(self, original, kind, name):
        if kind == "same":
            return original.parent / "." / original.name
        alias = original.with_name(name)
        if kind == "symlink":
            alias.symlink_to(original)
        else:
            os.link(original, alias)
        return alias

    def unchanged_project(self, name):
        source = self.source(f"{name}/clean.sh", CLEAN)
        project = source.parent
        git = [
            "git", "-c", f"core.hooksPath={project / 'empty-hooks'}",
            "-c", "user.name=UBS report tests", "-c", "user.email=ubs@example.invalid",
        ]
        for args in (["init", "-q", "-b", "main"], ["add", "clean.sh"],
                     ["commit", "-qm", "clean input"]):
            subprocess.run(git + args, cwd=project, env=self.env, capture_output=True,
                           timeout=30, check=True)  # ubs:ignore[python.taint.command] Fixture argv.
        return project

    def test_all_report_destinations_protect_explicit_source_aliases(self):
        for option in DESTINATIONS:
            for kind in ("same", "symlink", "hardlink"):
                with self.subTest(option=option, kind=kind):
                    case = f"case-{self.calls}"
                    source = self.source(f"{case}/unsafe.sh")
                    output = self.alias(source, kind, "report.json")
                    result = self.invoke(option.format(output), source)
                    self.assert_refused(result, "input")
                    self.assertEqual(source.read_text(encoding="utf-8"), UNSAFE)
                    self.assertEqual(output.read_bytes(), source.read_bytes())

    def test_pattern_count_destination_cannot_replace_python_source(self):
        source = self.source("source.py", "value = input()\neval(value)\n")  # ubs:ignore[python.taint.eval] Scanned, never executed.
        original = source.read_bytes()
        result = self.invoke(f"--python-pattern-counts={source}", source, language="python")
        self.assert_refused(result, "input")
        self.assertEqual(source.read_bytes(), original)

    def test_directory_and_external_directory_sources_are_protected(self):
        for external in (False, True):
            for option in ("--output={}", "--report-json={}"):
                with self.subTest(external=external, option=option):
                    source = self.source(f"case-{self.calls}/project/src/unsafe.sh")
                    output = self.alias(source, "hardlink", "report.json")
                    project = source.parent.parent
                    cwd = self.work / f"caller-{self.calls}"
                    cwd.mkdir()
                    targets = [project]
                    if external:
                        targets.append(self.source(f"caller-{self.calls}/other.sh", CLEAN))
                    result = self.invoke(option.format(output), *targets, cwd=cwd)
                    self.assert_refused(result, "input")
                    self.assertEqual(source.read_text(encoding="utf-8"), UNSAFE)
                    self.assertEqual(output.read_bytes(), source.read_bytes())

    def test_reports_cannot_replace_comparison_baseline(self):
        source = self.source()
        for option in (x for x in DESTINATIONS if not x.startswith("--save-baseline")):
            for kind in ("same", "symlink", "hardlink"):
                with self.subTest(option=option, kind=kind):
                    baseline = self.work / f"baseline-{self.calls}.json"
                    baseline.write_text("[]\n", encoding="utf-8")
                    output = self.alias(baseline, kind, f"baseline-alias-{self.calls}.json")
                    result = self.invoke("--new-only", f"--baseline={baseline}", option.format(output), source)
                    self.assert_refused(result, "baseline")
                    self.assertEqual(baseline.read_bytes(), b"[]\n")
                    self.assertEqual(output.read_bytes(), b"[]\n")

    def test_output_collisions_are_rejected_without_also(self):
        source = self.source()
        pairs = (
            ("--output={}", "--report-json={}"),
            ("--output={}", "--save-baseline={}"),
            ("--report-json={}", "--html-report={}"),
            ("--save-baseline={}", "--beads-jsonl={}"),
        )
        for first, second in pairs:
            for kind in ("same", "symlink", "hardlink"):
                with self.subTest(first=first, second=second, kind=kind):
                    output = self.work / f"report-{self.calls}.json"
                    output.write_bytes(SENTINEL)
                    other = self.alias(output, kind, f"alias-{self.calls}.json")
                    result = self.invoke(first.format(output), second.format(other), source)
                    self.assert_refused(result, "same file")
                    self.assertEqual(output.read_bytes(), SENTINEL)
                    self.assertEqual(other.read_bytes(), SENTINEL)

    def test_target_validation_failure_preserves_existing_output(self):
        output = self.work / "previous.json"
        output.write_bytes(SENTINEL)
        result = self.invoke(f"--output={output}", self.work / "missing.sh")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scan target not found", result.stdout + result.stderr)
        self.assertEqual(output.read_bytes(), SENTINEL)

    def test_source_aliases_are_protected_in_git_selections(self):
        for mode in ("--staged", "--diff"):
            with self.subTest(mode=mode):
                source = self.source(f"{mode[2:]}/unsafe.sh", CLEAN)
                project = source.parent
                git = [
                    "git", "-c", f"core.hooksPath={project / 'empty-hooks'}",
                    "-c", "user.name=UBS report tests", "-c", "user.email=ubs@example.invalid",
                ]
                for args in (["init", "-q", "-b", "main"], ["add", "unsafe.sh"],
                             ["commit", "-qm", "clean input"]):
                    subprocess.run(git + args, cwd=project, env=self.env, capture_output=True,
                                   timeout=30, check=True)  # ubs:ignore[python.taint.command] Fixture argv.
                source.write_text(UNSAFE, encoding="utf-8")
                if mode == "--staged":
                    subprocess.run(git + ["add", "unsafe.sh"], cwd=project, env=self.env,
                                   capture_output=True, timeout=30, check=True)  # ubs:ignore[python.taint.command]
                result = self.invoke(mode, f"--output={source}", project, cwd=project)
                self.assert_refused(result, "input")
                self.assertEqual(source.read_text(encoding="utf-8"), UNSAFE)

    def test_empty_git_selections_publish_complete_reports(self):
        for mode in ("--staged", "--diff"):
            project = self.unchanged_project(mode[2:])
            for fmt in ("json", "jsonl", "sarif", "text"):
                with self.subTest(mode=mode, fmt=fmt):
                    output = self.work / f"empty-{mode[2:]}.{fmt}"
                    output.write_bytes(SENTINEL)
                    additional = self.work / f"additional-{mode[2:]}-{fmt}.json"
                    additional.write_bytes(SENTINEL)
                    result = self.invoke(mode, f"--output={output}", f"--also=json:{additional}",
                                         project, cwd=project, fmt=fmt)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(output.read_text(encoding="utf-8"), result.stdout)
                    report = json.loads(additional.read_bytes())
                    self.assertEqual(report["exit_code"], 0)
                    self.assertEqual(report["totals"], {"critical": 0, "warning": 0, "info": 0, "files": 0})
                    self.assertEqual(report["scanners"], [])
                    if fmt == "json":
                        self.assertEqual(json.loads(result.stdout), report)
                    elif fmt == "jsonl":
                        rows = [json.loads(line) for line in result.stdout.splitlines()]
                        self.assertEqual(rows[-1]["type"], "totals")
                        for field in ("critical", "warning", "info", "files"):
                            self.assertEqual(rows[-1][field], 0)
                    elif fmt == "sarif":
                        sarif = json.loads(result.stdout)
                        self.assertEqual(sarif["version"], "2.1.0")
                        self.assertEqual(sarif["runs"][0]["results"], [])
                        self.assertEqual(sarif["runs"][0]["invocations"][0]["exitCode"], 0)
                    else:
                        self.assertIn("No changed files to scan", result.stdout)
                    self.assertEqual((project / "clean.sh").read_text(encoding="utf-8"), CLEAN)

    def test_empty_git_delivery_failure_preserves_previous_report(self):
        project = self.unchanged_project("unchanged")
        output = self.work / "previous.json"
        output.write_bytes(SENTINEL)
        env = self.tee_environment('printf "injected writer failure\\n" >&2\nstatus=74')
        result = self.invoke("--staged", f"--output={output}", project, cwd=project, env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(output.read_bytes(), SENTINEL)
        self.assertIn("injected writer failure", result.stderr)
        self.assertEqual(json.loads(result.stdout)["totals"]["files"], 0)

    def test_successful_reports_match_stdout_in_all_native_formats(self):
        source = self.source()
        for fmt in ("json", "jsonl", "sarif", "text"):
            with self.subTest(fmt=fmt):
                output = self.work / f"report.{fmt}"
                output.write_bytes(SENTINEL)
                result = self.invoke(f"--output={output}", source, fmt=fmt)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(output.read_text(encoding="utf-8"), result.stdout)
                self.assertEqual(source.read_text(encoding="utf-8"), UNSAFE)
                if fmt == "json":
                    report = json.loads(result.stdout)
                    self.assertEqual(report["status"], "ok")
                    self.assertEqual(report["totals"], {"critical": 1, "warning": 0, "info": 0, "files": 1})
                    self.assertEqual([(x["rule_id"], x["line"]) for x in report["findings"]],
                                     [("bash.security.eval_variable", 3)])
                elif fmt == "jsonl":
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(rows[-1]["critical"], 1)
                    self.assertEqual(rows[-1]["status"], "ok")
                elif fmt == "sarif":
                    findings = [item for run in json.loads(result.stdout)["runs"] for item in run["results"]]
                    self.assertEqual([x["ruleId"] for x in findings], ["bash.security.eval_variable"])
                else:
                    self.assertIn("Critical: 1", result.stdout)

    def test_successful_clean_and_no_language_reports_replace_output(self):
        for name, contents, code in (("clean.sh", CLEAN, 0), ("notes.txt", "No source code.\n", 3)):
            with self.subTest(name=name):
                source = self.source(name, contents)
                output = self.work / f"{name}.json"
                output.write_bytes(SENTINEL)
                result = self.invoke(f"--output={output}", source)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertEqual(output.read_text(encoding="utf-8"), result.stdout)
                self.assertEqual(json.loads(result.stdout)["totals"]["critical"], 0)

    def test_explicit_baseline_refresh_is_still_supported(self):
        source = self.source()
        baseline = self.work / "baseline.json"
        first = self.invoke(f"--save-baseline={baseline}", source)
        self.assertEqual(first.returncode, 1, first.stdout + first.stderr)
        before = baseline.read_bytes()
        baseline.with_suffix(".before").write_bytes(before)
        source.write_text(UNSAFE + 'eval "$user_command"\n', encoding="utf-8")
        output = self.work / "new-report.json"
        result = self.invoke(f"--baseline={baseline}", f"--save-baseline={baseline}",
                             f"--output={output}", source)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotEqual(baseline.read_bytes(), before)
        self.assertEqual(json.loads(baseline.read_bytes())["totals"]["critical"], 2)
        self.assertEqual(output.read_text(encoding="utf-8"), result.stdout)
        self.assertEqual(source.read_text(encoding="utf-8"), UNSAFE + 'eval "$user_command"\n')

    def test_complete_partial_report_is_delivered_with_failure_exit(self):
        source = self.source()
        baseline = self.work / "incomplete-baseline.json"
        baseline.write_text('{"status":"partial","findings":[]}\n', encoding="utf-8")
        before = baseline.read_bytes()
        output = self.work / "partial.json"
        output.write_bytes(SENTINEL)
        result = self.invoke("--new-only", f"--baseline={baseline}", f"--output={output}", source)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["totals"]["critical"], 1)
        self.assertEqual(baseline.read_bytes(), before)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires the POSIX full device")
    def test_unwritable_primary_destination_is_not_success(self):
        source = self.source("clean.sh", CLEAN)
        result = self.invoke("--output=/dev/full", source)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("output", result.stderr.lower())
        self.assertTrue(Path("/dev/full").is_char_device())

    def tee_environment(self, actions):
        real = shutil.which("tee")
        self.assertIsNotNone(real)
        shim = self.work / "writer-bin"
        shim.mkdir()
        script = shim / "tee"
        script.write_text(
            "#!/bin/bash\n" + shlex.quote(real) + ' "$@"\nstatus=$?\n'
            + actions + '\nexit "$status"\n', encoding="utf-8",
        )
        script.chmod(0o755)
        return {"PATH": str(shim) + os.pathsep + self.env["PATH"]}

    def test_stream_writer_failure_preserves_previous_report_and_exits_two(self):
        source = self.source("clean.sh", CLEAN)
        output = self.work / "report.json"
        output.write_bytes(SENTINEL)
        env = self.tee_environment('printf "injected writer failure\\n" >&2\nstatus=74')
        result = self.invoke(f"--output={output}", source, env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("injected writer failure", result.stderr)
        self.assertEqual(output.read_bytes(), SENTINEL)
        self.assertEqual(json.loads(result.stdout)["totals"]["critical"], 0)

    @unittest.skipUnless(os.name == "posix", "requires POSIX signal delivery")
    def test_interrupted_delivery_preserves_previous_report(self):
        source = self.source("clean.sh", CLEAN)
        output = self.work / "report.json"
        output.write_bytes(SENTINEL)
        env = self.tee_environment('kill -TERM "$PPID"')
        result = self.invoke(f"--output={output}", source, env=env)
        self.assertIn(result.returncode, (-signal.SIGTERM, 128 + signal.SIGTERM), result.stderr)
        self.assertEqual(output.read_bytes(), SENTINEL)

    def test_jsonl_renderer_failure_preserves_output_including_new_only(self):
        source = self.source()
        baseline = self.work / "baseline.json"
        first = self.invoke(f"--save-baseline={baseline}", source)
        self.assertEqual(first.returncode, 1, first.stdout + first.stderr)
        real = shutil.which("jq")
        self.assertIsNotNone(real)
        shim = self.work / "render-bin"
        shim.mkdir()
        writer = shim / "jq"
        writer.write_text('''#!/usr/bin/env python3
import os
import sys

args = sys.argv[1:]
if (any(arg.endswith("/combined.json") for arg in args)
        and any('type:"totals"' in arg for arg in args)):
    with open(os.environ["UBS_REPORT_TEST_JQ_LOG"], "a", encoding="utf-8") as log:
        log.write("injected totals failure\\n")
    sys.stdout.write('{"incomplete":')
    sys.exit(73)
real = os.environ["UBS_REPORT_TEST_REAL_JQ"]
os.execv(real, [real, *args])
''', encoding="utf-8")
        writer.chmod(0o755)
        for filtered in (False, True):
            with self.subTest(new_only=filtered):
                output = self.work / f"report-{filtered}.jsonl"
                output.write_bytes(SENTINEL)
                other = self.work / f"usable-{filtered}.json"
                log = self.work / f"render-failure-{filtered}.log"
                flags = ["--new-only", f"--baseline={baseline}"] if filtered else []
                result = self.invoke(
                    f"--output={output}", f"--also=json:{other}", *flags, source, fmt="jsonl",
                    env={"PATH": str(shim) + os.pathsep + self.env["PATH"],
                         "UBS_REPORT_TEST_REAL_JQ": real, "UBS_REPORT_TEST_JQ_LOG": str(log)},
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(log.read_text(encoding="utf-8"), "injected totals failure\n")
                self.assertEqual(output.read_bytes(), SENTINEL)
                self.assertEqual(result.stdout, "")
                report = json.loads(other.read_bytes())
                self.assertEqual(report["status"], "ok")
                self.assertEqual(report["totals"]["critical"], 0 if filtered else 1)

    def test_late_delivery_failure_preserves_report_and_exits_two(self):
        source = self.source("clean.sh", CLEAN)
        parent = self.work / "destination"
        parent.mkdir()
        output = parent / "report.json"
        output.write_bytes(SENTINEL)
        moved = self.work / "previous-destination"
        env = self.tee_environment(
            "mv -- " + shlex.quote(str(parent)) + " " + shlex.quote(str(moved)) + "\n"
            + "printf 'blocked parent\\n' > " + shlex.quote(str(parent)),
        )
        result = self.invoke(f"--output={output}", source, env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("output", result.stderr.lower())
        self.assertEqual((moved / "report.json").read_bytes(), SENTINEL)
        self.assertEqual(json.loads(result.stdout)["totals"]["critical"], 0)


if __name__ == "__main__":
    unittest.main()
