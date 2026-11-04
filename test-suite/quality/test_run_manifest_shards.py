"""--shard I/N must partition the enabled manifest cases: every case in exactly
one shard, sizes differ by at most one, and the split is stable across runs."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEST_ROOT))
import run_manifest  # noqa: E402


class ShardTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_forces_shutdown_when_scanner_ignores_term(self) -> None:
        artifact_root = TEST_ROOT / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="manifest-timeout-resistant-", dir=artifact_root))
        ready = scratch / "scanner.pid"
        receiver = scratch / "receiver.py"
        receiver.write_text(
            "import os, signal, time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(ready)!r}).write_text(str(os.getpid()))\n"
            "print('scanner-started', flush=True)\n"
            "time.sleep(30)\n"
        )
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            run_manifest.run_case_command([sys.executable, str(receiver)], dict(os.environ), 2)
        self.assertLess(time.monotonic() - started, 10, "Shutdown grace must remain bounded")
        self.assertEqual(raised.exception.timeout, 2)
        self.assertIn("scanner-started", run_manifest.timeout_output(raised.exception.stdout))
        self.assertTrue(ready.exists(), "The TERM-resistant scanner must actually start")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(ready.read_text()), 0)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_allows_handler_to_drain_separate_child_group(self) -> None:
        artifact_root = TEST_ROOT / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="manifest-timeout-handler-", dir=artifact_root))
        child = scratch / "child.py"
        ready, drained = scratch / "child-started.json", scratch / "child-drained"
        child.write_text(
            "import json, os, time\nfrom pathlib import Path\n"
            f"Path({str(ready)!r}).write_text(json.dumps({{'pid': os.getpid(), 'pgid': os.getpgrp()}}))\n"
            "time.sleep(30)\n"
        )
        receiver = scratch / "receiver.py"
        receiver.write_text(
            "import os, signal, subprocess, sys, time\nfrom pathlib import Path\n"
            f"child = subprocess.Popen([sys.executable, {str(child)!r}], start_new_session=True, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "def terminate(signum, frame):\n"
            "    os.killpg(child.pid, signal.SIGTERM)\n"
            "    child.wait(timeout=2)\n"
            f"    Path({str(drained)!r}).write_text(str(child.returncode))\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, terminate)\n"
            "until = time.monotonic() + 2\n"
            f"while not Path({str(ready)!r}).exists() and time.monotonic() < until:\n"
            "    time.sleep(0.01)\n"
            "print('scanner-started', flush=True)\n"
            "time.sleep(30)\n"
        )
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                run_manifest.run_case_command([sys.executable, str(receiver)], dict(os.environ), 3)
            self.assertEqual(raised.exception.timeout, 3)
            self.assertIn("scanner-started", run_manifest.timeout_output(raised.exception.stdout))
            self.assertTrue(ready.exists(), "The separate-group child must actually start")
            child_state = json.loads(ready.read_text())
            self.assertEqual(child_state["pid"], child_state["pgid"])
            self.assertTrue(drained.exists(), "The scanner TERM handler must run and reap its child")
            self.assertEqual(drained.read_text(), str(-signal.SIGTERM))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_state["pid"], 0)
        finally:
            # The baseline intentionally fails before its handler runs; stop
            # only this fixture's recorded child rather than leaking it.
            if ready.exists():
                try:
                    os.killpg(json.loads(ready.read_text())["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX child processes")
    def test_timeout_stops_descendants_and_preserves_failure_output(self) -> None:
        """A failed case must not leave its scanner children running behind the next case."""
        artifact_root = TEST_ROOT / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="manifest-timeout-tree-", dir=artifact_root))
        receiver = scratch / "receiver"
        ready, late = scratch / "child-started", scratch / "child-survived"
        receiver.write_text(
            f"#!{sys.executable}\n"
            "import os, signal, time\n"
            "from pathlib import Path\n"
            "if os.fork() == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    os.close(1)\n"
            "    os.close(2)\n"
            f"    Path({str(ready)!r}).write_text('started')\n"
            "    time.sleep(4)\n"
            f"    Path({str(late)!r}).write_text('survived')\n"
            "    os._exit(0)\n"
            "print('scanner-started', flush=True)\n"
            "time.sleep(10)\n"
        )
        receiver.chmod(0o700)
        manifest = scratch / "manifest.json"
        manifest.write_text(json.dumps({"defaults": {
            "ubs_bin": str(receiver), "artifacts_dir": str(scratch / "reports"),
        }, "cases": [{"id": "timeout-tree", "path": str(scratch), "language": "python",
                      "description": "A timed-out scanner must stop its owned child processes.",
                      "expect": {"exit_code": "zero"}}]}))
        proc = subprocess.run(
            [sys.executable, str(TEST_ROOT / "run_manifest.py"), "--manifest", str(manifest), "--case-timeout", "1"],
            capture_output=True, text=True, cwd=scratch, timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = scratch / "reports/timeout-tree"
        self.assertTrue((report / "result.json").exists(), proc.stdout + proc.stderr)
        self.assertTrue(json.loads((report / "result.json").read_text())["timed_out"])
        self.assertIn("scanner-started", (report / "stdout.log").read_text())
        self.assertIn("Timed out after 1", (report / "stderr.log").read_text())
        self.assertTrue(ready.exists(), "The real child must have started; no zero-run green")
        time.sleep(4)
        self.assertFalse(late.exists(), "Timed-out scanner child continued writing after the case ended")

    def test_symbolic_exit_requires_both_process_status_and_counts(self) -> None:
        """A clean-looking partial run or an unsafe exit-0 must stay red."""
        for expected, actual, critical, accepted in (
            ("zero", 0, 0, True), ("zero", 2, 0, False),
            ("zero", 0, 1, False), ("nonzero", 1, 1, True),
            ("nonzero", 0, 1, False), ("nonzero", 1, 0, False),
        ):
            with self.subTest(expected=expected, actual=actual, critical=critical):
                summary = {"totals": {"files": 1, "critical": critical, "warning": 0, "info": 0}}
                errors = run_manifest.check_expectations(
                    {"exit_code": expected}, actual, summary, "", "", False,
                )
                self.assertEqual(not errors, accepted, errors)

    def test_native_cases_preserve_caller_remote_admission(self) -> None:
        """Receiver control: manifest defaults must not force Cargo local.

        This executes the real runner with a fixture receiver, not a compiler.
        Actual native RCH compilation is qualified separately.
        """
        artifact_root = TEST_ROOT / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="manifest-remote-policy-", dir=artifact_root))
        receiver = scratch / "receiver"
        receiver.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "required = os.environ.get('RCH_REQUIRE_REMOTE') == '1'\n"
            "bypassed = os.environ.get('RCH_CARGO_WRAPPER_BYPASS') == '1'\n"
            "message = 'caller-remote-policy-preserved' if required and not bypassed else 'caller-remote-policy-overridden'\n"
            "print(json.dumps({'status': 'ok', 'message': message, 'totals': {'files': 1, 'critical': 0, 'warning': 0, 'info': 0}}))\n"
            "sys.exit(0 if required and not bypassed else 73)\n"
        )
        receiver.chmod(0o700)
        canonical = run_manifest.load_manifest(TEST_ROOT / "manifest.json")
        defaults = dict(canonical["defaults"])
        defaults["ubs_bin"] = str(receiver)
        defaults["artifacts_dir"] = str(scratch / "reports")
        manifest = scratch / "manifest.json"
        manifest.write_text(json.dumps({"defaults": defaults, "cases": [{
            "id": "remote-policy", "path": str(scratch), "language": "rust",
            "description": "Native receiver preserves caller-required remote admission.",
            "expect": {"exit_code": "zero", "require_substrings": ["caller-remote-policy-preserved"]},
        }]}))
        env = dict(os.environ)
        env["RCH_REQUIRE_REMOTE"] = "1"
        env.pop("RCH_CARGO_WRAPPER_BYPASS", None)
        proc = subprocess.run(
            [sys.executable, str(TEST_ROOT / "run_manifest.py"), "--manifest", str(manifest)],
            capture_output=True, text=True, cwd=scratch, env=env, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Completed 1 case(s) with 0 failure(s) and 0 skipped", proc.stdout)

    def test_partition_is_disjoint_complete_and_balanced(self) -> None:
        manifest = run_manifest.load_manifest(TEST_ROOT / "manifest.json")
        ids = [c["id"] for c in manifest["cases"] if c.get("enabled", True)]
        total = 4
        shards = [run_manifest.shard_case_ids(ids, i, total) for i in range(1, total + 1)]
        self.assertEqual(sum(len(s) for s in shards), len(ids))
        self.assertEqual(set().union(*shards), set(ids))
        for a in range(total):
            for b in range(a + 1, total):
                self.assertFalse(shards[a] & shards[b], f"shards {a + 1} and {b + 1} overlap")
        sizes = sorted(len(s) for s in shards)
        self.assertLessEqual(sizes[-1] - sizes[0], 1)

    def test_split_is_stable(self) -> None:
        ids = [f"case-{i}" for i in range(10)]
        self.assertEqual(run_manifest.shard_case_ids(ids, 2, 3), run_manifest.shard_case_ids(ids, 2, 3))
        self.assertEqual(run_manifest.shard_case_ids(ids, 1, 3), {"case-0", "case-3", "case-6", "case-9"})

    def test_parse_shard_rejects_bad_specs(self) -> None:
        self.assertIsNone(run_manifest.parse_shard(None))
        self.assertEqual(run_manifest.parse_shard("2/4"), (2, 4))
        for bad in ("0/4", "5/4", "a/b", "3"):
            with self.assertRaises(SystemExit):
                run_manifest.parse_shard(bad)

    def test_cli_prints_shard_summary(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TEST_ROOT / "run_manifest.py"), "--shard", "1/50", "--list"],
            capture_output=True, text=True, cwd=TEST_ROOT, timeout=60,
        )
        # --list exits before running; the option must still parse.
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
