"""The repository hygiene guard in test-suite/run_all.sh (bead H9).

The guard lives between the `# hygiene-guard-begin` / `# hygiene-guard-end`
markers so it can be exercised here without running the gates: the block is
sourced into a bash process inside a throwaway git repository, a step leaves a
stray file, and the guard must name the step and the path. Files under the
allowed prefixes (test-suite/artifacts/, test-suite/goldens/, .beads/) are not
reported. In strict mode the message is the fatal one; in warn mode it is the
warning. Nothing is ever deleted by the guard.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

RUN_ALL = Path(__file__).resolve().parents[1] / "run_all.sh"


def guard_block() -> str:
    text = RUN_ALL.read_text(encoding="utf-8")
    start = text.index("# hygiene-guard-begin")
    end = text.index("# hygiene-guard-end")
    return text[start:end]


def run_guard(repo: Path, script: str, mode: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["UBS_TEST_HYGIENE"] = mode
    env.pop("CI", None)
    prog = guard_block() + "\n" + script
    # ubs:ignore — prog is the guard block read from run_all.sh plus a fixed test script, never user input
    return subprocess.run(["bash", "-c", prog], cwd=repo, capture_output=True, text=True, env=env, timeout=60)  # ubs:ignore


class RunAllHygieneGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ubs-hygiene-"))
        subprocess.run(["git", "init", "-q", str(self.tmp)], check=True)
        (self.tmp / "tracked.txt").write_text("hello\n")
        subprocess.run(["git", "-C", str(self.tmp), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.tmp), "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init"], check=True)

    def test_stray_file_is_named_with_its_step(self) -> None:
        proc = run_guard(self.tmp, 'touch stray.txt; hygiene_check contract-tests; printf "issues=%s\\n" "${#HYGIENE_ISSUES[@]}"', "strict")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("❌ [contract-tests] left untracked files in the checkout", proc.stdout)
        self.assertIn("stray.txt", proc.stdout)
        self.assertIn("issues=1", proc.stdout)
        self.assertTrue((self.tmp / "stray.txt").exists(), "the guard must never delete anything")

    def test_warn_mode_reports_without_the_fatal_wording(self) -> None:
        proc = run_guard(self.tmp, 'mkdir -p sub; touch sub/report.json; hygiene_check manifest', "warn")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("⚠️  [manifest] new untracked files appeared during this step", proc.stdout)
        self.assertIn("sub/report.json", proc.stdout)
        self.assertNotIn("left untracked files", proc.stdout)

    def test_allowed_prefixes_and_pre_existing_files_are_ignored(self) -> None:
        (self.tmp / "already_there.txt").write_text("before the run\n")
        script = (
            "hygiene_snapshot; "
            "mkdir -p test-suite/artifacts/x .beads; touch test-suite/artifacts/x/out.log .beads/tmp.jsonl; "
            'hygiene_check quiet-step; printf "issues=%s\\n" "${#HYGIENE_ISSUES[@]}"'
        )
        proc = run_guard(self.tmp, script, "strict")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("issues=0", proc.stdout)
        self.assertNotIn("already_there.txt", proc.stdout)

    def test_each_path_is_reported_once(self) -> None:
        script = 'touch a.txt; hygiene_check first; hygiene_check second; printf "issues=%s\\n" "${#HYGIENE_ISSUES[@]}"'
        proc = run_guard(self.tmp, script, "strict")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count("a.txt"), 1, proc.stdout)
        self.assertIn("[first]", proc.stdout)
        self.assertNotIn("[second]", proc.stdout)


if __name__ == "__main__":
    unittest.main()
