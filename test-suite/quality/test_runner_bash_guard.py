"""The runner under the stock macOS /bin/bash 3.2.

cron and launchd start jobs with PATH=/usr/bin:/bin, where `#!/usr/bin/env
bash` finds /bin/bash 3.2 even when a modern bash is installed, so the nightly
`ubs --update` cron entry failed at the bash-version guard. The runner now
re-execs under a bash >= 4 it finds; UBS_NO_BASH_REEXEC=1 keeps the documented
refusal (exit 2 with the brew hint). Skipped where /bin/bash is already 4+.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STOCK_BASH = '/bin/bash'
MODERN_BASHES = ('/opt/homebrew/bin/bash', '/usr/local/bin/bash', '/home/linuxbrew/.linuxbrew/bin/bash')


def stock_bash_major() -> int:
    try:
        out = subprocess.run([STOCK_BASH, '-c', 'echo "${BASH_VERSINFO[0]}"'],
                             capture_output=True, text=True, timeout=30).stdout
        return int(out.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 0


@unittest.skipUnless(stock_bash_major() == 3, '/bin/bash is not bash 3.x')
class RunnerBashGuardTests(unittest.TestCase):
    def run_stock(self, *extra_env: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as home:
            # The environment cron gives a job, plus the case's variables.
            cmd = ['/usr/bin/env', '-i', f'HOME={home}', 'PATH=/usr/bin:/bin',
                   'UBS_NO_AUTO_UPDATE=1', *extra_env, STOCK_BASH, str(ROOT / 'ubs'), '--version']
            return subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=ROOT)

    @unittest.skipUnless(any(os.access(b, os.X_OK) for b in MODERN_BASHES), 'no bash >= 4 installed')
    def test_cron_environment_reexecs_under_modern_bash(self):
        result = self.run_stock()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('UBS Meta-Runner', result.stdout)

    def test_opt_out_keeps_documented_refusal(self):
        result = self.run_stock('UBS_NO_BASH_REEXEC=1')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('brew install bash', result.stderr)


if __name__ == '__main__':
    unittest.main()
