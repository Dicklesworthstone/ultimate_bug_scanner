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
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BANNER = "WARNING: `sg` is deprecated. Use `ast-grep` instead."


def function(source: Path, name: str) -> str:
    text = source.read_text(encoding="utf-8")
    match = re.search(r"^" + re.escape(name) + r"\(\) ?\{\n.*?^\}\n", text, re.M | re.S)
    if not match:
        raise AssertionError(f"{name} not found in {source.name}")
    return match.group(0)


RUNNER_FUNCTIONS = "\n".join(function(ROOT / "ubs", name) for name in (
    "is_ast_grep_launcher", "verify_ast_grep_bin", "find_ast_grep_in_path",
    "shadow_ast_grep_launcher",
))
# Minimal stand-ins for the runner's environment around shadow_ast_grep_launcher.
RUNNER_STUBS = """
YELLOW= WARN= RESET=
say_err(){ echo "$*" >&2; }
ensure_tmpdir_run(){ TMPDIR_RUN="${TEST_RUN_DIR}"; mkdir -p "$TMPDIR_RUN"; }
ensure_ast_grep(){
  [ "${TEST_NO_VERIFIED_AST_GREP:-0}" = 1 ] && return 1
  AST_GREP_BIN="$(find_ast_grep_in_path)" || return 1
}
"""
INSTALLER_FUNCTIONS = "\n".join(function(ROOT / "install.sh", name) for name in (
    "is_ast_grep_launcher", "check_ast_grep", "select_ast_grep_member",
))


class AstGrepLauncher(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-ast-grep-launcher-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
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

    def bash(self, functions: str, body: str, path: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": f"{path}{os.pathsep}/usr/bin{os.pathsep}/bin", "HOME": str(self.root), "LC_ALL": "C"}
        if "TMPDIR" in os.environ:
            env["TMPDIR"] = os.environ["TMPDIR"]
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.root,
                                         prefix='driver-', suffix='.sh', delete=False) as driver:
            driver.write(f'set -u\nwarn(){{ echo "WARN: $*" >&2; }}\n{functions}\n{body}')
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
        tools = self.root / 'tools'
        tools.mkdir()
        mkdir = tools / 'mkdir'
        mkdir.write_text(
            '#!/bin/sh\n'
            'case "$*" in *ast-grep-path*) exit 71;; esac\n'
            'exec /usr/bin/mkdir "$@"\n', encoding='utf-8',
        )
        mkdir.chmod(0o755)
        target = self.root / 'clean.py'
        target.write_text('value = 1\n', encoding='utf-8')
        env = os.environ.copy()
        env.update(PATH=f'{tools}:{self.launcher_dir}:/usr/bin:/bin', HOME=str(self.root),
                   UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', NO_COLOR='1', ENABLE_UV_TOOLS='0')
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
