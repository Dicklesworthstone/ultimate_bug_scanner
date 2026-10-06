#!/usr/bin/env python3
"""Issue #131: installer hook scope, DCG coexistence, and lossless registration.

Function tests execute the installer functions, stubbing only the guard payload
installation. CLI tests run the real installer with isolated HOME and no network.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"


def command_hook(command: str, matcher: str = "Bash") -> dict:
    return {"matcher": matcher, "hooks": [{"type": "command", "command": command}]}


class HookScope(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ubs-hook-scope-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "UBS_", "XDG_", "CLAUDE_"))}
        self.env.update(HOME=str(self.home), NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1",
                        GUARD_CALLS=str(self.root / "guard.calls"))
        self.git(self.project, "init", "-q")

    def git(self, cwd: Path, *args: str) -> None:
        subprocess.run(["git", "-c", "user.name=UBS Test", "-c", "user.email=test@example.invalid",
                        "-c", "commit.gpgsign=false", *args], cwd=cwd, env=self.env,
                       check=True, capture_output=True, timeout=20)

    def write_settings(self, path: Path, data: object) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True)
        contents = (json.dumps(data, indent=2) + "\n").encode()
        path.write_bytes(contents)
        return contents

    def setup_hooks(self, cwd: Path, *, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        text = INSTALLER.read_text(encoding="utf-8")
        functions = text[text.index("claude_dcg_hook_registered() {"):text.index("append_agent_rule_block() {")]
        script = """set -euo pipefail
log(){ printf '%s\\n' "$*"; }
warn(){ log "$*"; }
success(){ log "$*"; }
log_dry_run(){ log "$*"; }
dry_run_enabled(){ [[ "$DRY_RUN" == 1 ]]; }
""" + functions + """
install_claude_safety_guard(){
  local destination="${1:-.}/.claude/hooks"
  printf '%s\\n' "$destination" >> "$GUARD_CALLS"
  if [[ ! -f "$destination/git_safety_guard.py" ]]; then
    printf '#!/usr/bin/env python3\\nraise SystemExit(0)\\n' > "$destination/git_safety_guard.py"
    chmod +x "$destination/git_safety_guard.py"
  fi
}
setup_claude_code_hook
"""
        result = subprocess.run(["bash", "-c", script], cwd=cwd,
                                env={**self.env, "DRY_RUN": str(int(dry_run))},
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def settings(self, project: Path | None = None) -> dict:
        return json.loads(((project or self.project) / ".claude/settings.json").read_text())

    def test_home_and_non_repository_never_receive_project_hooks(self) -> None:
        settings = self.home / ".claude/settings.json"
        before = self.write_settings(settings, {"permissions": {"allow": ["Bash(ls:*)"]},
                                                "hooks": {"PreToolUse": [command_hook("dcg")]}})
        for cwd in (self.home, self.root):
            result = self.setup_hooks(cwd)
            self.assertIn("--setup-claude-hook", result.stdout)
            self.assertEqual(settings.read_bytes(), before)
            self.assertFalse((cwd / ".claude/hooks").exists())
        self.assertFalse((self.root / "guard.calls").exists())

    def test_home_dotfiles_repository_is_not_project_scope(self) -> None:
        self.git(self.home, "init", "-q")
        nested = self.home / "dotfiles"
        nested.mkdir()
        for cwd in (self.home, nested):
            self.setup_hooks(cwd)
            self.assertFalse((self.home / ".claude").exists())
            self.assertFalse((nested / ".claude").exists())

    def test_existing_user_scope_repair_is_preserved(self) -> None:
        settings = self.home / ".claude/settings.json"
        corrected = command_hook('"$HOME/.claude/hooks/on-file-write.sh"', "Edit|Write")
        before = self.write_settings(settings, {"permissions": {"allow": ["Bash(ls:*)"]}, "hooks": {
            "PostToolUse": [command_hook("$CLAUDE_PROJECT_DIR/.claude/hooks/on-file-write.sh", "Edit"), corrected],
            "PreToolUse": [command_hook("dcg"), command_hook("$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py")]}})
        self.setup_hooks(self.home, dry_run=True)
        self.assertEqual(settings.read_bytes(), before)
        self.setup_hooks(self.home)
        data = json.loads(settings.read_text())
        self.assertEqual(data["permissions"], {"allow": ["Bash(ls:*)"]})
        self.assertEqual(data["hooks"]["PostToolUse"], [corrected])
        self.assertEqual(data["hooks"]["PreToolUse"], [command_hook("dcg")])
        backups = list(settings.parent.glob("settings.json.bak-ubs-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        after = settings.read_bytes()
        self.setup_hooks(self.home)
        self.assertEqual(settings.read_bytes(), after)
        self.assertEqual(list(settings.parent.glob("settings.json.bak-ubs-*")), backups)

    def test_subdirectory_uses_root_and_registered_command_runs_with_spaces(self) -> None:
        nested = self.project / "src/deep"
        nested.mkdir(parents=True)
        self.setup_hooks(nested)
        self.assertFalse((nested / ".claude").exists())
        self.assertFalse((self.home / ".claude").exists())
        hooks = self.settings()["hooks"]
        command = hooks["PostToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(shlex.split(command), ["$CLAUDE_PROJECT_DIR/.claude/hooks/on-file-write.sh"])
        self.assertEqual((self.root / "guard.calls").read_text().strip(), str(self.project / ".claude/hooks"))
        # Run through the same shell-command boundary as Claude, not just JSON inspection.
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "ubs"
        # Preserve the exact single-path assertion after parsing scan options.
        stub.write_text('#!/usr/bin/env bash\n'
                        'while [[ $# -gt 0 ]]; do\n'
                        '  case "$1" in --) shift; break;; -*) shift;; *) break;; esac\n'
                        'done\n[[ $# -gt 0 ]] || exit 2\n'
                        'printf "%s\\n" "$1" > "$SCAN_LOG"\nexit 0\n')
        stub.chmod(0o755)
        target = nested / "sample with spaces.py"
        target.write_text("pass\n")
        result = subprocess.run(["sh", "-c", command], cwd=nested, env={**self.env,
            "PATH": str(bin_dir) + os.pathsep + self.env["PATH"],
            "CLAUDE_PROJECT_DIR": str(self.project), "SCAN_LOG": str(self.root / "scan.log")},
            input=json.dumps({"tool_input": {"file_path": str(target)}}),
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "scan.log").read_text().strip(), str(target))

    def test_linked_worktree_uses_its_own_root(self) -> None:
        self.git(self.project, "commit", "--allow-empty", "-qm", "fixture")
        worktree = self.root / "linked worktree"
        self.git(self.project, "worktree", "add", "--detach", str(worktree), "HEAD")
        nested = worktree / "src"
        nested.mkdir()
        self.setup_hooks(nested)
        self.assertIn("PostToolUse", self.settings(worktree)["hooks"])
        self.assertFalse((self.project / ".claude").exists())
        self.assertFalse((nested / ".claude").exists())

    def test_dry_run_writes_nothing(self) -> None:
        self.setup_hooks(self.project, dry_run=True)
        self.assertFalse((self.project / ".claude").exists())
        self.assertFalse((self.root / "guard.calls").exists())

    def test_symlinks_cannot_redirect_setup_into_user_scope(self) -> None:
        global_settings = self.home / ".claude/settings.json"
        before = self.write_settings(global_settings, {"permissions": {"allow": []}})
        (self.project / ".claude").symlink_to(global_settings.parent, target_is_directory=True)
        self.setup_hooks(self.project)
        self.assertEqual(global_settings.read_bytes(), before)
        self.assertFalse((global_settings.parent / "hooks").exists())

    def test_settings_symlink_is_not_overwritten(self) -> None:
        global_settings = self.home / ".claude/settings.json"
        before = self.write_settings(global_settings, {"permissions": {"allow": []}})
        (self.project / ".claude").mkdir()
        (self.project / ".claude/settings.json").symlink_to(global_settings)
        self.setup_hooks(self.project)
        self.assertEqual(global_settings.read_bytes(), before)
        self.assertFalse((self.project / ".claude/hooks").exists())

    def test_custom_user_config_directory_is_not_project_scope(self) -> None:
        config = self.project / ".claude"
        before = self.write_settings(config / "settings.json", {"permissions": {"allow": []}})
        self.env["CLAUDE_CONFIG_DIR"] = str(config)
        self.setup_hooks(self.project)
        self.assertEqual((config / "settings.json").read_bytes(), before)
        self.assertFalse((config / "hooks").exists())

    def test_absent_custom_user_config_directory_is_not_created(self) -> None:
        config = self.project / ".claude"
        self.env["CLAUDE_CONFIG_DIR"] = str(config)
        self.setup_hooks(self.project)
        self.assertFalse(config.exists())

    def test_dcg_in_each_effective_scope_prevents_legacy_install_and_registration(self) -> None:
        scopes = [(self.home / ".claude/settings.json", "dcg"),
                  (self.project / ".claude/settings.json", '"/opt/My Guard/dcg"'),
                  (self.project / ".claude/settings.local.json", "env DCG_CONFIG=x /opt/dcg"),
                  (self.root / "custom-config/settings.json", "exec destructive_command_guard")]
        for index, (path, command) in enumerate(scopes):
            with self.subTest(scope=str(path)):
                # Each scope is checked independently, with no previously registered DCG.
                if index:
                    scopes[index - 1][0].rename(scopes[index - 1][0].with_suffix(f".saved-{index}"))
                if index == 3:
                    self.env["CLAUDE_CONFIG_DIR"] = str(path.parent)
                before = self.write_settings(path, {"hooks": {"PreToolUse": [command_hook(command)]}})
                self.setup_hooks(self.project)
                self.assertFalse((self.root / "guard.calls").exists())
                self.assertFalse((self.project / ".claude/hooks/git_safety_guard.py").exists())
                data = self.settings()
                self.assertIn("PostToolUse", data["hooks"])
                self.assertNotIn("git_safety_guard.py", json.dumps(data))
                if path != self.project / ".claude/settings.json":
                    self.assertEqual(path.read_bytes(), before)

    def test_dcg_does_not_register_an_existing_legacy_guard(self) -> None:
        self.write_settings(self.home / ".claude/settings.json", {"hooks": {"PreToolUse": [command_hook("dcg", "*")]}})
        legacy = self.project / ".claude/hooks/git_safety_guard.py"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("# user-owned legacy script\n")
        self.setup_hooks(self.project)
        self.assertNotIn("git_safety_guard.py", json.dumps(self.settings()))
        self.assertEqual(legacy.read_text(), "# user-owned legacy script\n")
        self.assertFalse((self.root / "guard.calls").exists())

    def test_dcg_mentions_and_other_tool_matchers_are_not_bash_guards(self) -> None:
        self.write_settings(self.home / ".claude/settings.json", {"hooks": {
            "PreToolUse": [command_hook("echo dcg"), command_hook("dcg-helper"), command_hook("dcg", "Edit")],
            "PostToolUse": [command_hook("dcg")]}})
        self.setup_hooks(self.project)
        self.assertTrue((self.root / "guard.calls").exists())
        self.assertIn("git_safety_guard.py", json.dumps(self.settings()))

    def test_corrected_commands_are_preserved_without_duplicate_or_backup(self) -> None:
        settings = self.project / ".claude/settings.json"
        before = self.write_settings(settings, {"permissions": {"allow": ["Bash(ls:*)"]}, "hooks": {
            "PostToolUse": [command_hook('bash "$HOME/.claude/hooks/on-file-write.sh"', "Edit|Write")],
            "PreToolUse": [command_hook('python3 "/custom path/git_safety_guard.py"')]}})
        for _ in range(2):
            self.setup_hooks(self.project)
            self.assertEqual(settings.read_bytes(), before)
        self.assertFalse(list(settings.parent.glob("settings.json.bak-ubs-*")))

    def test_atomic_registration_preserves_settings_mode_and_backup(self) -> None:
        settings = self.project / ".claude/settings.json"
        before = self.write_settings(settings, {"permissions": {"allow": ["Bash(ls:*)"]}, "custom": {"key": 7}})
        settings.chmod(0o600)
        self.setup_hooks(self.project)
        after = settings.read_bytes()
        self.assertEqual(self.settings()["custom"], {"key": 7})
        self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
        backups = list(settings.parent.glob("settings.json.bak-ubs-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.setup_hooks(self.project)
        self.assertEqual(settings.read_bytes(), after)
        self.assertEqual(list(settings.parent.glob("settings.json.bak-ubs-*")), backups)
        self.assertFalse(list(settings.parent.glob(".ubs-settings-*")))

    def test_installer_generated_commands_are_quoted_on_upgrade(self) -> None:
        path = self.project / ".claude/settings.json"
        scan = "$CLAUDE_PROJECT_DIR/.claude/hooks/on-file-write.sh"
        guard = "$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py"
        self.write_settings(path, {"hooks": {"PostToolUse": [command_hook(scan, "Edit|Write")],
                                            "PreToolUse": [command_hook(guard)]}})
        self.setup_hooks(self.project)
        hooks = self.settings()["hooks"]
        self.assertEqual(hooks["PostToolUse"], [command_hook(f'"{scan}"', "Edit|Write")])
        self.assertEqual(hooks["PreToolUse"], [command_hook(f'"{guard}"')])
        before = path.read_bytes()
        self.setup_hooks(self.project)
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_settings_are_not_replaced(self) -> None:
        path = self.project / ".claude/settings.json"
        path.parent.mkdir()
        for data in ("{broken", '[]', '{"hooks": []}', '{"hooks":{"PostToolUse": {}}}',
                     '{"hooks":{"PostToolUse":[{"hooks":42}]}}'):
            with self.subTest(data=data):
                path.write_text(data)
                result = self.setup_hooks(self.project)
                self.assertEqual(path.read_text(), data)
                self.assertIn("Could not update", result.stdout)


class GitHookStatus(unittest.TestCase):
    """The actual generated hook must retain scanner failures and full scope.

    The scanner here is an explicit exit/argv protocol double, not a detector.
    UBS_INSTALLER_GATE_BASELINE enables replay of the actual original installer.
    """

    def setUp(self) -> None:
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        artifacts = ROOT / "test-suite/artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="git-hook-status-", dir=artifacts))
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("UBS_", "GIT_", "XDG_"))}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        SCAN_ARGUMENTS=str(self.root / "arguments.json"),
                        HOOK_INSTALL_DIR=str(self.bin))
        result = subprocess.run(["git", "init", "-q", str(self.project)], env=self.env,
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def tearDown(self) -> None:
        outcome = self._outcome.result
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in outcome.failures + outcome.errors)
        skipped = any(test is self for test, _ in outcome.skipped)
        state = 'FAIL' if failed else ('SKIP' if skipped else 'PASS')
        print(f"[{self.id()}] {state} "
              f"({time.monotonic() - self.started:.3f}s)", flush=True)

    def generate(self, source: Path) -> Path:
        text = source.read_text()
        functions = text[text.index("setup_git_hook() {"):text.index("detect_coding_agents() {")]
        script = """set -euo pipefail
log(){ :; }
warn(){ :; }
success(){ :; }
dry_run_enabled(){ return 1; }
determine_install_dir(){ printf '%s\\n' "$HOOK_INSTALL_DIR"; }
""" + functions + "\nsetup_git_hook\n"
        generator = self.root / (source.name + "-git-hook-generator.sh")
        generator.write_text(script)
        result = subprocess.run(["bash", str(generator)], cwd=self.project,
                                env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.project / ".git/hooks/pre-commit"

    def scanner(self, *, canonical: bool) -> None:
        source = "#!/usr/bin/env bash\n"
        if canonical:
            source += 'UBS_DAEMON_SHA256="' + "0" * 64 + '"\n'
        source += """python3 - "$@" <<'PY'
import json, os, pathlib, sys
pathlib.Path(os.environ['SCAN_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))
print('scanner report: configured outcome ' + os.environ['SCAN_EXIT'])
PY
exit "$SCAN_EXIT"
"""
        path = self.bin / "ubs"
        path.write_text(source)
        path.chmod(0o755)

    def run_hook(self, hook: Path, status: int, label: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(["bash", str(hook)], cwd=self.project,
                                env={**self.env, "SCAN_EXIT": str(status)},
                                capture_output=True, text=True, timeout=20)
        (self.root / (label + ".stdout.log")).write_text(result.stdout)
        (self.root / (label + ".stderr.log")).write_text(result.stderr)
        return result

    def test_one_shot_findings_and_environment_errors_block_commit(self) -> None:
        self.scanner(canonical=False)
        baseline = os.environ.get("UBS_INSTALLER_GATE_BASELINE")
        if baseline:
            original = self.generate(Path(baseline))
            for status in (1, 2):
                result = self.run_hook(original, status, f"original-{status}")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                print(f"[original-git-hook] scanner exit {status} incorrectly accepted", flush=True)
        hook = self.generate(INSTALLER)
        for status in (0, 1, 2, 3):
            result = self.run_hook(hook, status, f"current-{status}")
            self.assertEqual(result.returncode, 0 if status == 0 else 1,
                             result.stdout + result.stderr)
            self.assertEqual(self.arguments(),
                             [".", "--fail-on-warning"])

    def arguments(self) -> list[str]:
        output = Path(self.env["SCAN_ARGUMENTS"]).read_text()
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid scanner argv JSON: {exc}\nFull output:\n{output}")

    def test_canonical_client_retains_full_root_and_warning_policy(self) -> None:
        self.scanner(canonical=True)
        hook = self.generate(INSTALLER)
        for status in (0, 1, 2, 3):
            result = self.run_hook(hook, status, f"canonical-{status}")
            self.assertEqual(result.returncode, 0 if status == 0 else 1,
                             result.stdout + result.stderr)
            self.assertEqual(self.arguments(),
                             ["--client", "--repo", str(self.project), "--format=text",
                              "--fail-on-warning", "--", str(self.project)])

    def test_windows_git_hook_keeps_one_shot_scope_and_exit_policy(self) -> None:
        # A platform/argv double proves routing, not execution on Windows.
        self.scanner(canonical=True)
        uname = self.bin / "uname"
        uname.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$TEST_SYSTEM"\n')
        uname.chmod(0o755)
        hook = self.generate(INSTALLER)
        for system in ("MINGW64_NT-10.0", "MSYS_NT-10.0", "CYGWIN_NT-10.0"):
            self.env["TEST_SYSTEM"] = system
            for status in (0, 1, 2, 3):
                with self.subTest(system=system, status=status):
                    result = self.run_hook(hook, status, f"windows-git-{system}-{status}")
                    self.assertEqual(result.returncode, 0 if status == 0 else 1,
                                     result.stdout + result.stderr)
                    self.assertEqual(self.arguments(), [".", "--fail-on-warning"])

    def test_windows_save_hooks_scan_without_entering_the_posix_client(self) -> None:
        # Execute both shipped hook bodies; scanner and uname are explicit
        # protocol doubles. Native POSIX detector parity has separate tests.
        self.scanner(canonical=True)
        uname = self.bin / "uname"
        uname.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$TEST_SYSTEM"\n')
        uname.chmod(0o755)
        client = self.bin / "ubs-daemon"
        client.write_text('#!/usr/bin/env bash\nprintf called > "$CLIENT_CALLED"\nexit 99\n')
        client.chmod(0o755)
        text = INSTALLER.read_text()
        anchor = '  cat > "$hook_file" << \'HOOK_EOF\'\n'
        template = text.split(anchor, 1)[1].split('\nHOOK_EOF\n', 1)[0] + '\n'
        checkout = ROOT / ".claude/hooks/on-file-write.sh"
        self.assertEqual(template, checkout.read_text())
        generated = self.root / "installed-save-hook.sh"
        generated.write_text(template)
        target = self.project / "sample with spaces.py"
        target.write_text("pass\n")
        marker = self.root / "client-called"
        for hook in (checkout, generated):
            for system in ("MINGW64_NT-10.0", "MSYS_NT-10.0", "CYGWIN_NT-10.0"):
                for status in (0, 1, 2, 3):
                    with self.subTest(hook=hook, system=system, status=status):
                        result = subprocess.run(["bash", str(hook)], cwd=self.project,
                            env={**self.env, "TEST_SYSTEM": system, "SCAN_EXIT": str(status),
                                 "CLIENT_CALLED": str(marker)},
                            input=json.dumps({"tool_input": {"file_path": str(target)}}),
                            capture_output=True, text=True, timeout=20)
                        self.assertEqual(result.returncode, 0 if status in (0, 3) else 2,
                                         result.stdout + result.stderr)
                        self.assertEqual(self.arguments(), ["--ci", "--no-auto-update",
                            "--no-color", "--format=text", "--", str(target)])
                        self.assertFalse(marker.exists())

    def reference(self, destination: Path) -> subprocess.CompletedProcess[str]:
        text = INSTALLER.read_text()
        functions = text[text.index("\nquick_reference_block() {\n"):text.index("\nadd_to_agents_md() {\n")]
        generator = self.root / "reference-generator.sh"
        generator.write_text("set -euo pipefail\nlog(){ :; }\nwarn(){ printf '%s\\n' \"$*\" >&2; }\n"
                             "success(){ :; }\ndry_run_enabled(){ return 1; }\n" + functions +
                             '\nappend_quick_reference_block "$1" "test guardrails"\n')
        result = subprocess.run(["bash", str(generator), str(destination)],
                                cwd=self.project, env=self.env, capture_output=True,
                                text=True, timeout=20)
        (self.root / "reference.stdout.log").write_text(result.stdout)
        (self.root / "reference.stderr.log").write_text(result.stderr)
        return result

    def test_owned_guardrail_upgrade_preserves_custom_rules_mode_and_idempotence(self) -> None:
        start = '<!-- >>> Ultimate Bug Scanner quick reference (written by install.sh; removed by install.sh --uninstall) -->'
        end = '<!-- <<< End Ultimate Bug Scanner quick reference -->'
        destination = self.project / "rules"
        original = f"House rules: keep my commands.\n{start}\n## UBS Quick Reference for AI Agents\nold commands\n{end}\nAfterword: keep this too.\n"
        destination.write_text(original)
        destination.chmod(0o600)
        result = self.reference(destination)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        updated = destination.read_bytes()
        text = updated.decode()
        self.assertTrue(text.startswith("House rules: keep my commands.\n"))
        self.assertTrue(text.endswith("Afterword: keep this too.\n"))
        self.assertIn("ubs --client --repo . --format=text -- file.ts file2.py", text)
        self.assertIn("ubs --client --repo . --format=text --fail-on-warning -- .", text)
        self.assertIn("Exit 2 means an environment, authentication, or scan failure", text)
        self.assertNotIn("old commands", text)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        backups = list(destination.parent.glob("rules.bak-ubs-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), original)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        result = self.reference(destination)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(destination.read_bytes(), updated)
        self.assertEqual(list(destination.parent.glob("rules.bak-ubs-*")), backups)
        self.assertFalse(list(destination.parent.glob(".ubs-reference-*")))

    def test_custom_ambiguous_and_symlinked_guardrails_are_preserved(self) -> None:
        destination = self.project / "rules"
        for text, status in (("## UBS Quick Reference for AI Agents\nMy own scanner policy.\n", 0),
                             ("<!-- <<< End Ultimate Bug Scanner quick reference -->\n## UBS Quick Reference for AI Agents\n", 1)):
            with self.subTest(text=text):
                destination.write_text(text)
                result = self.reference(destination)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual(destination.read_text(), text)
                self.assertFalse(list(destination.parent.glob("rules.bak-ubs-*")))
        link = self.project / "linked-rules"
        link.symlink_to(destination)
        original = destination.read_bytes()
        result = self.reference(link)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertEqual(destination.read_bytes(), original)

    def test_original_unmarked_installer_block_is_refreshed_in_rule_directories(self) -> None:
        baseline = os.environ.get("UBS_INSTALLER_GATE_BASELINE")
        if not baseline:
            self.skipTest("set UBS_INSTALLER_GATE_BASELINE to replay the original installer guidance")
        text = Path(baseline).read_text()
        first = text.index("````markdown", text.index("\nquick_reference_block() {\n"))
        last = text.index("\n````", first) + len("\n````")
        original = "Before: custom rules.\n" + text[first:last] + "\nAfter: custom rules.\n"
        directory = self.project / ".codex/rules"
        directory.mkdir(parents=True)
        destination = directory / "ubs.md"
        destination.write_text(original)
        result = self.reference(directory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = destination.read_text()
        self.assertTrue(current.startswith("Before: custom rules.\n"))
        self.assertTrue(current.endswith("After: custom rules.\n"))
        self.assertIn("ubs --client --repo . --format=text -- file.ts file2.py", current)
        self.assertEqual(list(directory.glob("ubs.md.bak-ubs-*"))[0].read_text(), original)

    def test_crlf_and_symlinked_rule_directories_preserve_user_bytes(self) -> None:
        start = '<!-- >>> Ultimate Bug Scanner quick reference (written by install.sh; removed by install.sh --uninstall) -->'
        end = '<!-- <<< End Ultimate Bug Scanner quick reference -->'
        prefix = b"House rules: caf\xc3\xa9.\r\nKeep these bytes.\r\n"
        suffix = b"\r\nAfterword: keep CRLF.\r\n"
        original = prefix + f"{start}\r\n## UBS Quick Reference for AI Agents\r\nold\r\n{end}".encode() + suffix
        directory = self.project / "real-rules"
        directory.mkdir()
        destination = directory / "ubs.md"
        destination.write_bytes(original)
        link = self.project / "directory-link"
        link.symlink_to(directory, target_is_directory=True)
        result = self.reference(link)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(list(directory.iterdir()), [destination])
        result = self.reference(directory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        updated = destination.read_bytes()
        self.assertTrue(updated.startswith(prefix), updated)
        self.assertTrue(updated.endswith(suffix), updated)
        self.assertIn(b"ubs --client --repo . --format=text -- file.ts file2.py", updated)
        backups = list(directory.glob("ubs.md.bak-ubs-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        result = self.reference(directory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(destination.read_bytes(), updated)
        self.assertEqual(list(directory.glob("ubs.md.bak-ubs-*")), backups)


class InstallerCLI(unittest.TestCase):
    def test_real_setup_action_and_easy_mode_do_not_mutate_home_hooks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-hook-cli-") as tmp:
            root = Path(tmp)
            home = root / "home"
            settings = home / ".claude/settings.json"
            settings.parent.mkdir(parents=True)
            before = b'{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg"}]}]}}\n'
            settings.write_bytes(before)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for tool in ("curl", "wget"):
                path = bin_dir / tool
                path.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$0 $*" >> "$TOOL_LOG"\nexit 1\n')
                path.chmod(0o755)
            cron = bin_dir / "crontab"
            cron.write_text('#!/usr/bin/env bash\ncase "$1" in\n-l) exit 0;;\n-) cat >> "$TOOL_LOG";;\n*) exit 1;;\nesac\n')
            cron.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "UBS_", "XDG_", "CLAUDE_"))}
            env.update(HOME=str(home), NO_COLOR="1", SHELL="/bin/bash", TOOL_LOG=str(root / "tools.log"),
                       PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
            # The action path must never need the network. A full --local easy-mode
            # install exercises maybe_setup_hook under the same HOME reproduction.
            shutil.copy2(ROOT / "ubs", home / "ubs")
            shutil.copy2(ROOT / "ubs-daemon", home / "ubs-daemon")
            for index, args in enumerate((
                ["--setup-claude-hook", "--non-interactive"],
                ["--easy-mode", "--local", "--skip-ast-grep", "--skip-ripgrep", "--skip-jq", "--skip-bun",
                 "--skip-type-narrowing", "--skip-typos", "--skip-toon", "--skip-doctor", "--no-path-modify",
                 "--install-dir", str(home / ".local/bin")],
            )):
                result = subprocess.run(["bash", str(INSTALLER), "--skip-version-check", *args], cwd=home,
                    env={**env, "UBS_INSTALLER_WORKDIR": str(root / f"work-{index}")},
                    capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("skipping Claude Code hook setup", result.stdout)
                self.assertEqual(settings.read_bytes(), before)
                self.assertFalse((settings.parent / "hooks").exists())
                self.assertFalse(list(settings.parent.glob("settings.json.bak-ubs-*")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
