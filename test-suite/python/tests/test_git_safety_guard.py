#!/usr/bin/env python3
"""Regression tests for the Claude git safety guard hook."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / ".claude" / "hooks" / "git_safety_guard.py"


def run_hook(command: str) -> tuple[int, str]:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    # Hook contract: exit 0 always; stdout contains JSON only when denying.
    return proc.returncode, proc.stdout.strip()


class GitSafetyGuardTests(unittest.TestCase):
    def test_allows_safe_commands(self) -> None:
        code, out = run_hook("git clean -n")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_denies_git_reset_hard(self) -> None:
        code, out = run_hook("git reset --hard")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_allows_rm_rf_temp_dir(self) -> None:
        code, out = run_hook("rm -rf /tmp/ubs-test-dir")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_denies_rm_rf_non_temp(self) -> None:
        code, out = run_hook("rm -rf /home/user")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_denies_mixed_safe_and_unsafe_rm_rf(self) -> None:
        code, out = run_hook("rm -rf /tmp/ok && rm -rf /home/user")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_denies_bin_rm_rf_non_temp(self) -> None:
        """Regression test: /bin/rm -rf must be blocked like rm -rf."""
        code, out = run_hook("/bin/rm -rf /home/user")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_denies_usr_bin_rm_rf_non_temp(self) -> None:
        """Regression test: /usr/bin/rm -rf must be blocked like rm -rf."""
        code, out = run_hook("/usr/bin/rm -rf /home/user")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_allows_bin_rm_rf_temp_dir(self) -> None:
        """Full path rm -rf should be allowed for temp directories."""
        code, out = run_hook("/bin/rm -rf /tmp/test-dir")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

