"""The parity gate must retain real child-process failures, not only exit codes."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "test-suite" / "shareable" / "test_sarif_parity.py"


class ParityFailureDiagnosticsTests(unittest.TestCase):
    def test_failed_real_scanner_launch_retains_both_stderr_streams(self):
        # Execute the actual UBS entrypoint with no bash available. This is a
        # process-launch failure, not a replacement scanner or a fake report.
        with tempfile.TemporaryDirectory(prefix="ubs-parity-launch-") as empty_path:
            env = {**os.environ, "PATH": empty_path, "PYTHONDONTWRITEBYTECODE": "1"}
            scanner = subprocess.run(
                [str(ROOT / "ubs"), "--version"], env=env,
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(scanner.returncode, 0)
            self.assertTrue(scanner.stderr.strip())
            result = subprocess.run(
                [sys.executable, str(HARNESS), "--assert=python", "python"],
                cwd=empty_path, env=env, capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[sarif-parity:python] FAIL", result.stdout)
        self.assertIn("[sarif-parity:python:json] stderr:", result.stderr)
        self.assertIn("[sarif-parity:python:sarif] stderr:", result.stderr)
        self.assertEqual(result.stderr.count(scanner.stderr.strip()), 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
