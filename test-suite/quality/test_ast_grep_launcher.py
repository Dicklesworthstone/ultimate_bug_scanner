#!/usr/bin/env python3
"""ast-grep's `sg` deprecation launcher must never be used as ast-grep.

ast-grep's release archives ship `ast-grep` (the real binary) and `sg`, which
recent releases turned into a small launcher: it prints a deprecation banner
and runs `ast-grep` from PATH. install.sh up to v5.5.0 installed whichever
member `find` listed first as `~/.local/bin/ast-grep`; when that was the
launcher, every ast-grep call ran itself recursively until the container ran
out of processes or memory (the OOM in the v5.5.0 installer e2e).

The production functions are read from `ubs` and `install.sh` and run in
bash against fakes. The fake launcher carries the real banner bytes and
records every execution, so "rejected" also means "never executed".
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BANNER = "WARNING: `sg` is deprecated. Use `ast-grep` instead."


def function(source: Path, name: str, *, optional: bool = False) -> str:
    text = source.read_text(encoding="utf-8")
    match = re.search(r"^" + re.escape(name) + r"\(\) ?\{\n.*?^\}\n", text, re.M | re.S)
    if not match:
        if optional:
            return ""
        raise AssertionError(f"{name} not found in {source.name}")
    return match.group(0)


RUNNER_FUNCTIONS = "\n".join(function(ROOT / "ubs", name) for name in (
    "ubs_remove_temp", "is_ast_grep_launcher", "verify_ast_grep_bin", "find_ast_grep_in_path",
    "shadow_ast_grep_launcher", "ensure_ast_grep",
)) + function(ROOT / "ubs", "ast_grep_version_supported", optional=True)
# Minimal stand-ins for the runner's environment around shadow_ast_grep_launcher.
RUNNER_STUBS = """
RED= X= YELLOW= WARN= RESET=
say_err(){ echo "$*" >&2; }
ensure_tmpdir_run(){ TMPDIR_RUN="${TEST_RUN_DIR}"; mkdir -p "$TMPDIR_RUN"; }
ast_grep_target_triple(){ return 1; }
"""
INSTALLER_FUNCTIONS = "\n".join(function(ROOT / "install.sh", name) for name in (
    "is_ast_grep_launcher", "check_ast_grep", "select_ast_grep_member",
))


class AstGrepLauncher(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = ROOT / "test-suite" / "artifacts" / "ast-grep-launcher"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="case-", dir=artifacts))
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.exec_log = self.root / "launcher-executions.log"
        self.launcher_dir = self.root / "launcher"
        self.real_dir = self.root / "real"
        self.launcher_dir.mkdir()
        self.real_dir.mkdir()
        self.launcher = self.write_launcher(self.launcher_dir / "ast-grep")
        self.real = self.real_dir / "ast-grep"
        self.real.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  --version) echo "ast-grep 0.45.3" ;;\n'
            "  scan|run|--pattern) exit 0 ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        self.real.chmod(0o755)

    def write_launcher(self, path: Path) -> Path:
        # Shaped like the real launcher: tiny, carries the banner, and would
        # recurse through PATH. Here it only records that it ran.
        path.write_text(
            "#!/bin/sh\n"
            f"echo '{BANNER}' >&2\n"
            f'echo run >> "{self.exec_log}"\n'
            "exit 1\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def write_versioned_engine(self, label: str, version: str, *,
                               version_exit: int = 0, no_match_exit: int = 1,
                               name: str = "ast-grep") -> Path:
        directory = self.root / label
        directory.mkdir()
        engine = directory / name
        log = self.root / f"{label}-executions.jsonl"
        # Use the test interpreter even when the isolated PATH has no Python.
        engine.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\nfrom pathlib import Path\n"
            f"version = {version!r}\nversion_exit = {version_exit!r}\n"
            f"no_match_exit = {no_match_exit!r}\nlog = Path({str(log)!r})\n"
            + r'''
args = sys.argv[1:]
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")
if args == ["--version"]:
    print(version)
    raise SystemExit(version_exit)
if args and args[0] == "scan":
    raise SystemExit(0)
if args and args[0] in ("run", "--pattern"):
    if "-p" in args or args[0] == "--pattern":
        raise SystemExit(0)
    matched = False
    if "--pattern" in args and "--" in args:
        pattern = args[args.index("--pattern") + 1]
        for filename in args[args.index("--") + 1:]:
            for line, source in enumerate(Path(filename).read_text().splitlines()):
                needle = "input.unwrap()"
                if pattern == "$X.unwrap()" and needle in source:
                    column = source.index(needle)
                    print(json.dumps({"file": filename, "text": needle,
                                      "range": {"start": {"line": line, "column": column},
                                                "end": {"line": line, "column": column + len(needle)}}}))
                    matched = True
    raise SystemExit(0 if matched else no_match_exit)
raise SystemExit(2)
''', encoding="utf-8",
        )
        engine.chmod(0o755)
        return engine

    def bash(self, functions: str, body: str, path: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{path}{os.pathsep}/usr/bin{os.pathsep}/bin",
               "HOME": str(self.root), "LC_ALL": "C", "TMPDIR": str(self.scratch),
               "UBS_KEEP_TEMP": "1"}
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.root,
                                         prefix='driver-', suffix='.sh', delete=False) as driver:
            driver.write('set -u\nAST_GREP_MIN_VERSION=0.45.3\n'
                         'warn(){ echo "WARN: $*" >&2; }\n'
                         'say_err(){ printf "%s\\n" "$*" >&2; }\n'
                         f'{functions}\n{body}')
        return subprocess.run(
            ["bash", "--", driver.name],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=60, check=False,
        )

    def assert_never_executed(self) -> None:
        self.assertFalse(self.exec_log.exists(), "the launcher was executed")

    def test_banner_marks_only_the_launcher(self) -> None:
        for functions in (RUNNER_FUNCTIONS, INSTALLER_FUNCTIONS):
            result = self.bash(functions,
                               f'is_ast_grep_launcher "{self.launcher}" && echo launcher; '
                               f'is_ast_grep_launcher "{self.real}" || echo real',
                               str(self.real_dir))
            self.assertEqual(result.stdout.split(), ["launcher", "real"], result.stderr)
        self.assert_never_executed()

    def test_runner_rejects_unsupported_or_unverifiable_versions(self) -> None:
        cases = (
            ("old", "ast-grep 0.40.1", 0),
            ("below-pin", "ast-grep 0.45.2", 0),
            ("prerelease", "ast-grep 0.45.3-rc.1", 0),
            ("unknown", "ast-grep development", 0),
            ("missing-patch", "ast-grep 0.45", 0),
            ("misidentified", "other-tool 0.51.3", 0),
            ("failed-probe", "ast-grep 0.51.3", 9),
        )
        for label, version, code in cases:
            with self.subTest(version=version, exit=code):
                engine = self.write_versioned_engine(label, version, version_exit=code)
                result = self.bash(RUNNER_FUNCTIONS,
                                   f'verify_ast_grep_bin {shlex.quote(str(engine))}',
                                   str(engine.parent))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [json.loads(line) for line in
                         (self.root / f"{label}-executions.jsonl").read_text().splitlines()]
                self.assertEqual(calls, [["--version"]],
                                 "an unsupported engine must not execute scan/run probes")

    def test_runner_accepts_pinned_and_newer_stable_versions(self) -> None:
        for label, version in (
            ("pinned", "ast-grep 0.45.3"),
            ("newer", "ast-grep 0.51.3"),
            ("major", "ast-grep 1.0.0"),
            ("metadata", "ast-grep 0.45.3+vendor.1"),
        ):
            with self.subTest(version=version):
                engine = self.write_versioned_engine(label, version)
                result = self.bash(RUNNER_FUNCTIONS,
                                   f'verify_ast_grep_bin {shlex.quote(str(engine))}',
                                   str(engine.parent))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [json.loads(line) for line in
                         (self.root / f"{label}-executions.jsonl").read_text().splitlines()]
                self.assertEqual(calls[0], ["--version"])
                self.assertIn(["scan", "-h"], calls)
                self.assertTrue(any(args[:2] == ["run", "-p"] for args in calls), calls)

    def test_configured_release_pin_cannot_lower_the_supported_floor(self) -> None:
        engine = self.write_versioned_engine("override-old", "ast-grep 0.40.1")
        result = self.bash(RUNNER_FUNCTIONS,
                           'AST_GREP_VERSION=0.40.1\n'
                           f'verify_ast_grep_bin {shlex.quote(str(engine))}',
                           str(engine.parent))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_runner_selects_supported_engine_after_stale_path_entry(self) -> None:
        old = self.write_versioned_engine("old-path", "ast-grep 0.40.1")
        result = self.bash(RUNNER_FUNCTIONS, "find_ast_grep_in_path",
                           f"{old.parent}{os.pathsep}{self.real_dir}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.real))
        calls = [json.loads(line) for line in
                 (self.root / "old-path-executions.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["--version"]])

    def test_runner_shadows_stale_engine_for_every_module(self) -> None:
        old = self.write_versioned_engine("old-shadow", "ast-grep 0.40.1")
        result = self.shadow(f"{old.parent}{os.pathsep}{self.real_dir}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["target"], str(self.real))
        self.assertEqual(out["exported"], str(self.real))
        self.assertEqual(out["version_rc"], "0")
        self.assertIn(str(old), result.stderr)
        self.assertIn("0.40.1", result.stderr)
        calls = [json.loads(line) for line in
                 (self.root / "old-shadow-executions.jsonl").read_text().splitlines()]
        self.assertTrue(calls)
        self.assertTrue(all(args == ["--version"] for args in calls), calls)

    def test_runner_replaces_stale_explicit_engine(self) -> None:
        old = self.write_versioned_engine("old-explicit", "ast-grep 0.40.1")
        result = self.shadow(str(self.real_dir), f"UBS_AST_GREP_BIN={shlex.quote(str(old))}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["exported"], str(self.real))
        self.assertEqual(out["version_rc"], "0")
        self.assertIn(str(old), result.stderr)

    def test_runner_refuses_stale_engine_without_replacement(self) -> None:
        old = self.write_versioned_engine("old-only", "ast-grep 0.40.1")
        result = self.shadow(str(old.parent), "TEST_NO_VERIFIED_AST_GREP=1")
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        calls = [json.loads(line) for line in
                 (self.root / "old-only-executions.jsonl").read_text().splitlines()]
        self.assertTrue(calls)
        self.assertTrue(all(args == ["--version"] for args in calls), calls)

    def test_runner_replaces_stale_sg_alias(self) -> None:
        old = self.write_versioned_engine("old-sg", "ast-grep 0.40.1", name="sg")
        current = self.write_versioned_engine("current-sg", "ast-grep 0.51.3", name="sg")
        result = self.shadow(f"{old.parent}{os.pathsep}{current.parent}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["target"], str(current))
        self.assertEqual(out["exported"], str(current))
        self.assertEqual(out["version_rc"], "0")

    def test_runner_resolves_relative_path_before_creating_shim(self) -> None:
        old = self.write_versioned_engine("old-relative", "ast-grep 0.40.1")
        result = self.shadow(f"{old.parent.name}{os.pathsep}{self.real_dir.name}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["target"], str(self.real))
        self.assertEqual(out["exported"], str(self.real))
        self.assertEqual(out["version_rc"], "0")

    def test_runner_honors_relative_supported_explicit_engine_outside_path(self) -> None:
        current = self.write_versioned_engine("explicit current", "ast-grep 0.51.3",
                                              name="custom-grep")
        old = self.write_versioned_engine("ambient-old", "ast-grep 0.40.1")
        relative = str(current.relative_to(self.root))
        result = self.shadow(str(old.parent), f"UBS_AST_GREP_BIN={shlex.quote(relative)}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["target"], str(current))
        self.assertEqual(out["exported"], str(current))
        self.assertEqual(out["version_rc"], "0")
        self.assertIn("ast-grep 0.51.3", result.stdout)
        self.assertFalse((self.root / "ambient-old-executions.jsonl").exists(),
                         "a valid explicit choice must not probe or execute an ambient engine")

    def test_runner_skips_a_launcher_named_ast_grep_on_path(self) -> None:
        result = self.bash(RUNNER_FUNCTIONS, "find_ast_grep_in_path",
                           f"{self.launcher_dir}{os.pathsep}{self.real_dir}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.real))
        self.assert_never_executed()

    def test_runner_finds_nothing_when_only_the_launcher_is_on_path(self) -> None:
        result = self.bash(RUNNER_FUNCTIONS, "find_ast_grep_in_path", str(self.launcher_dir))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")
        self.assert_never_executed()

    def shadow(self, path: str, extra: str = "") -> subprocess.CompletedProcess[str]:
        run_dir = self.root / "run"
        return self.bash(RUNNER_STUBS + RUNNER_FUNCTIONS,
                         f'export TEST_RUN_DIR="{run_dir}" {extra}\n'
                         'UBS_TEST_RUNNER_NO_AST_GREP="${TEST_NO_VERIFIED_AST_GREP:-0}"\n'
                         'shadow_ast_grep_launcher || exit 9\n'
                         'echo "resolved=$(command -v ast-grep)"\n'
                         'echo "target=$(readlink "$(command -v ast-grep)" || true)"\n'
                         'echo "exported=${UBS_AST_GREP_BIN:-}"\n'
                         'ast-grep --version; echo "version_rc=$?"',
                         path)

    def test_runner_shadows_a_launcher_with_the_verified_binary_for_the_whole_run(self) -> None:
        result = self.shadow(f"{self.launcher_dir}{os.pathsep}{self.real_dir}")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["target"], str(self.real))
        self.assertEqual(out["exported"], str(self.real))
        self.assertIn("ast-grep 0.45.3", result.stdout)
        self.assertEqual(out["version_rc"], "0")
        self.assertIn("launcher", result.stderr)
        self.assert_never_executed()

    def test_runner_hides_a_launcher_it_cannot_replace(self) -> None:
        result = self.shadow(str(self.launcher_dir), "TEST_NO_VERIFIED_AST_GREP=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertNotEqual(out["resolved"], str(self.launcher))
        self.assertEqual(out["version_rc"], "127")
        self.assertIn("is the sg launcher", result.stderr)
        self.assert_never_executed()

    def test_runner_fallback_does_not_execute_shell_syntax_in_launcher_path(self) -> None:
        # The diagnostic shim must not embed an untrusted PATH name as shell code.
        directory = self.root / '$(touch injected)'
        directory.mkdir()
        self.write_launcher(directory / 'ast-grep')
        result = self.shadow(str(directory), "TEST_NO_VERIFIED_AST_GREP=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("version_rc=127", result.stdout)
        self.assertNotIn("touch:", result.stderr)
        self.assertFalse((self.root / "injected").exists())
        self.assert_never_executed()

    def test_shipped_runner_refuses_scan_when_launcher_cannot_be_shadowed(self) -> None:
        # Fail one real filesystem operation in the shipped CLI. It must stop
        # before any module can invoke the unsafe launcher, even on a Python scan.
        real_mkdir = shutil.which('mkdir')
        self.assertIsNotNone(real_mkdir, 'mkdir is required to exercise the launcher failure')
        tools = self.root / 'tools'
        tools.mkdir()
        mkdir = tools / 'mkdir'
        mkdir.write_text(
            '#!/bin/sh\n'
            'case "$*" in *ast-grep-path*) exit 71;; esac\n'
            f'exec {shlex.quote(real_mkdir)} "$@"\n', encoding='utf-8',
        )
        mkdir.chmod(0o755)
        target = self.root / 'clean.py'
        target.write_text('value = 1\n', encoding='utf-8')
        env = os.environ.copy()
        env.update(PATH=f'{tools}:{self.launcher_dir}:/usr/bin:/bin', HOME=str(self.root),
                   UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', NO_COLOR='1', ENABLE_UV_TOOLS='0',
                   UBS_KEEP_TEMP='1', TMPDIR=str(self.scratch))
        result = subprocess.run(
            ['bash', str(ROOT / 'ubs'), str(target), f'--module-dir={ROOT / "modules"}',
             '--only=python', '--format=json', '--ci'],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'runner emitted invalid JSON: {exc}: {result.stdout}')
        self.assertEqual(report['error'], 'environment')
        self.assertEqual(report['reason'], 'ast-grep-launcher')
        self.assertNotIn('Finished python (', result.stderr)
        self.assert_never_executed()

    def test_runner_leaves_a_real_ast_grep_alone(self) -> None:
        result = self.shadow(str(self.real_dir))
        out = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertEqual(out["resolved"], str(self.real))
        self.assertEqual(out["exported"], "")
        self.assertNotIn("launcher", result.stderr)

    def shipped_scan(self, target: Path, languages: str, engine: Path, label: str,
                     *options: str, explicit: bool = False) -> tuple[subprocess.CompletedProcess[str], dict]:
        tool_dirs = [str(engine.parent)]
        for name in ("bash", "python3", "rg", "jq"):
            located = shutil.which(name)
            self.assertIsNotNone(located, f"{name} is required for the real runner test")
            tool_dirs.append(str(Path(located).parent))
        tool_dirs.extend(("/usr/bin", "/bin"))
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("UBS_") and key not in ("BASH_ENV", "ENV", "PYTHONPATH")}
        env.update(PATH=os.pathsep.join(dict.fromkeys(tool_dirs)), HOME=str(self.root),
                   XDG_CACHE_HOME=str(self.root / "cache"), XDG_CONFIG_HOME=str(self.root / "config"),
                   XDG_DATA_HOME=str(self.root / "data"), TMPDIR=str(self.scratch),
                   UBS_KEEP_TEMP="1", UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1",
                   UBS_SKIP_RUST_BUILD="1", NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1",
                   # Exercise unavailable provisioning without depending on
                   # the host's cache/network. Real modules still run.
                   UBS_TEST_RUNNER_NO_AST_GREP="1")
        if explicit:
            env["UBS_AST_GREP_BIN"] = str(engine)
        result = subprocess.run(
            ["bash", str(ROOT / "ubs"), str(target), f'--module-dir={ROOT / "modules"}',
             f"--only={languages}", "--format=json", "--ci", "--fail-on-warning", *options],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=60, check=False,
        )
        (self.root / f"{label}.stdout.json").write_text(result.stdout, encoding="utf-8")
        (self.root / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
        try:
            return result, json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"invalid runner JSON: {exc}\n{result.stdout}\n{result.stderr}")

    def test_native_scans_ignore_unneeded_engines_and_preserve_findings(self) -> None:
        cases = (
            ("php", "php", "<?php\n$value = 1;\n", "<?php\nsystem($_GET['cmd']);\n",
             [("php.security.command-injection", "critical")]),
            ("hcl", "tf", 'locals { name = "value" }\n', 'provider "aws" { insecure = true }\n',
             [("hcl.aws.insecure-provider-tls", "warning")]),
            ("sql", "sql", "SELECT 1;\n",
             "CREATE FUNCTION public.example() RETURNS integer LANGUAGE sql "
             "SECURITY DEFINER AS $$ SELECT 1 $$;\n",
             [("sql.security.definer-public-execute", "warning"),
              ("sql.security.definer-search-path", "warning")]),
        )
        engines = (
            ("old-native", self.write_versioned_engine("old-native", "ast-grep 0.40.1"), False),
            ("invalid-native", self.write_versioned_engine("invalid-native", "unrecognized engine"), True),
        )
        for engine_label, engine, explicit in engines:
            for language, suffix, clean, unsafe, expected in cases:
                for case, source, findings in (("clean", clean, []), ("unsafe", unsafe, expected)):
                    label = f"{engine_label}-{language}-{case}"
                    with self.subTest(case=label):
                        target = self.root / f"{label}.{suffix}"
                        target.write_text(source, encoding="utf-8")
                        result, report = self.shipped_scan(target, language, engine, label, explicit=explicit)
                        details = result.stdout + "\n" + result.stderr
                        self.assertEqual(result.returncode, int(bool(findings)), details)
                        self.assertEqual(report["status"], "ok", details)
                        self.assertEqual(report["failed_modules"], [], details)
                        self.assertEqual(report["totals"], {
                            "files": 1, "critical": sum(severity == "critical" for _, severity in findings),
                            "warning": sum(severity == "warning" for _, severity in findings), "info": 0,
                        }, details)
                        self.assertEqual(sorted((item["rule_id"], item["severity"])
                                                for item in report.get("findings", [])), sorted(findings), details)
                        self.assertEqual(target.read_text(encoding="utf-8"), source)
            self.assertFalse((self.root / f"{engine_label}-executions.jsonl").exists(),
                             "native scans must not probe or execute an unrelated AST engine")
        # A mixed selection of native modules also has no engine dependency.
        project = self.root / "native-project"
        project.mkdir()
        for language, suffix, _clean, unsafe, _findings in cases:
            (project / f"{language}.{suffix}").write_text(unsafe, encoding="utf-8")
        result, report = self.shipped_scan(project, "php,hcl,sql", engines[0][1], "mixed-native")
        details = result.stdout + "\n" + result.stderr
        self.assertEqual(result.returncode, 1, details)
        self.assertEqual(report["status"], "ok", details)
        self.assertEqual(report["failed_modules"], [], details)
        self.assertEqual(report["totals"], {"files": 3, "critical": 1, "warning": 3, "info": 0}, details)
        self.assertFalse((self.root / "old-native-executions.jsonl").exists())

    def test_ast_consumers_still_refuse_an_incompatible_engine_without_replacement(self) -> None:
        old = self.write_versioned_engine("required-old", "ast-grep 0.40.1")
        project = self.root / "mixed-project"
        project.mkdir()
        (project / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (project / "clean.php").write_text("<?php\n$value = 1;\n", encoding="utf-8")
        rules = self.root / "php-rules"
        rules.mkdir()
        (rules / "echo.yml").write_text(
            "id: local.php.echo\nlanguage: Php\nrule:\n  pattern: echo $X;\n"
            "message: Echo policy\nseverity: warning\n", encoding="utf-8",
        )
        for label, languages, options in (
            ("rust-required", "rust", ()),
            ("mixed-required", "php,rust", ()),
            ("custom-php-required", "php", (f"--rules={rules}",)),
        ):
            with self.subTest(case=label):
                result, report = self.shipped_scan(project, languages, old, label, *options)
                details = result.stdout + "\n" + result.stderr
                self.assertEqual(result.returncode, 2, details)
                self.assertEqual(report["status"], "error", details)
                self.assertEqual(report["error"], "environment", details)
                self.assertEqual(report["reason"], "ast-grep-incompatible", details)
        calls = [json.loads(line) for line in
                 (self.root / "required-old-executions.jsonl").read_text().splitlines()]
        self.assertTrue(calls)
        self.assertTrue(all(args == ["--version"] for args in calls), calls)

    def test_rust_only_runner_recovers_from_stale_engine_without_losing_findings(self) -> None:
        # Run the shipped runner and Rust module. The external AST engines are
        # protocol doubles: old no-match exits reproduce 0.40.x; current exits
        # distinguish an empty result and emit one known unwrap location.
        old = self.write_versioned_engine("rust-old", "ast-grep 0.40.1", no_match_exit=0)
        current = self.write_versioned_engine("rust-current", "ast-grep 0.45.3")
        tool_dirs = [str(old.parent), str(current.parent)]
        for name in ("bash", "python3", "rg", "jq"):
            located = shutil.which(name)
            self.assertIsNotNone(located, f"{name} is required for the real runner test")
            tool_dirs.append(str(Path(located).parent))
        tool_dirs.extend(("/usr/bin", "/bin"))
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("UBS_") and key not in ("BASH_ENV", "ENV", "PYTHONPATH")}
        env.update(PATH=os.pathsep.join(dict.fromkeys(tool_dirs)), HOME=str(self.root),
                   XDG_CACHE_HOME=str(self.root / "cache"), XDG_CONFIG_HOME=str(self.root / "config"),
                   XDG_DATA_HOME=str(self.root / "data"), TMPDIR=str(self.scratch),
                   UBS_KEEP_TEMP="1", UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1",
                   UBS_SKIP_RUST_BUILD="1", NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
        for case, source, warnings in (
            ("clean", "fn main() {}\n", 0),
            ("unwrap", "fn read(input: Option<i32>) -> i32 {\n    input.unwrap()\n}\n", 1),
        ):
            with self.subTest(case=case):
                target = self.root / f"{case}.rs"
                target.write_text(source, encoding="utf-8")
                command = ["bash", str(ROOT / "ubs"), str(target),
                           f'--module-dir={ROOT / "modules"}', "--only=rust",
                           "--format=json", "--ci", "--fail-on-warning"]
                started = time.monotonic()
                print(f"[{self.id()}/{case}] RUN {shlex.join(command)}", flush=True)
                result = subprocess.run(command, cwd=self.root, env=env, capture_output=True,
                                        text=True, timeout=60, check=False)
                (self.root / f"{case}.stdout.json").write_text(result.stdout, encoding="utf-8")
                (self.root / f"{case}.stderr.log").write_text(result.stderr, encoding="utf-8")
                details = result.stdout + "\n" + result.stderr
                self.assertEqual(result.returncode, warnings, details)
                try:
                    report = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"invalid runner JSON: {exc}\n{details}")
                self.assertEqual(report["status"], "ok", details)
                self.assertEqual(report["failed_modules"], [], details)
                self.assertEqual({key: report["totals"][key] for key in
                                  ("files", "critical", "warning")},
                                 {"files": 1, "critical": 0, "warning": warnings}, details)
                expected = [("rust.ownership.unwrap-expect", "warning", 2, 5)] if warnings else []
                findings = report["findings"] if warnings else report.get("findings", [])
                self.assertEqual([(item["rule_id"], item["severity"], item["line"], item["col"])
                                  for item in findings if item["severity"] != "info"], expected, details)
                self.assertEqual(target.read_text(encoding="utf-8"), source)
                print(f"[{self.id()}/{case}] PASS ({time.monotonic() - started:.3f}s)", flush=True)
        old_calls = [json.loads(line) for line in
                     (self.root / "rust-old-executions.jsonl").read_text().splitlines()]
        self.assertTrue(old_calls)
        self.assertTrue(all(args == ["--version"] for args in old_calls), old_calls)
        current_calls = [json.loads(line) for line in
                         (self.root / "rust-current-executions.jsonl").read_text().splitlines()]
        self.assertTrue(any(args and args[0] == "scan" and "-h" not in args
                            for args in current_calls), current_calls)
        self.assertTrue(any(args[:2] == ["run", "--pattern"] for args in current_calls), current_calls)

    def test_installer_treats_a_launcher_on_path_as_missing(self) -> None:
        result = self.bash(INSTALLER_FUNCTIONS, "check_ast_grep && echo present || echo missing",
                           str(self.launcher_dir))
        self.assertEqual(result.stdout.strip(), "missing", result.stderr)
        self.assertIn("launcher", result.stderr)
        self.assert_never_executed()
        result = self.bash(INSTALLER_FUNCTIONS, "check_ast_grep && echo present || echo missing",
                           str(self.real_dir))
        self.assertEqual(result.stdout.strip(), "present", result.stderr)

    def test_installer_takes_only_the_ast_grep_member_of_an_archive(self) -> None:
        extracted = self.root / "extracted"
        extracted.mkdir()
        self.write_launcher(extracted / "sg")
        member = extracted / "ast-grep"
        member.write_bytes(self.real.read_bytes())
        result = self.bash(INSTALLER_FUNCTIONS, f'select_ast_grep_member "{extracted}"', "")
        self.assertEqual(result.stdout.strip(), str(member), result.stderr)
        only_sg = self.root / "only-sg"
        only_sg.mkdir()
        self.write_launcher(only_sg / "sg")
        result = self.bash(INSTALLER_FUNCTIONS, f'select_ast_grep_member "{only_sg}"', "")
        self.assertNotEqual(result.returncode, 0)
        renamed = self.root / "renamed"
        renamed.mkdir()
        self.write_launcher(renamed / "ast-grep")
        result = self.bash(INSTALLER_FUNCTIONS, f'select_ast_grep_member "{renamed}"', "")
        self.assertNotEqual(result.returncode, 0)
        self.assert_never_executed()


if __name__ == "__main__":
    unittest.main()
