"""Canonical CLI invokes pinned service bytes, never a project/PATH replacement."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import unittest

import test_daemon as base

ROOT = base.ROOT


@unittest.skipUnless(os.name == 'posix', 'The local service requires POSIX')
class EntrypointTests(unittest.TestCase):
    setUp = base.ServiceTests.setUp

    def cli(self, *args, runner=None, env=None, timeout=20):
        return subprocess.run([str(runner or ROOT / 'ubs'), *args], cwd=self.root,
                              env=env or self.env, capture_output=True, text=True, timeout=timeout)

    def installation(self):
        installed = self.work / 'installed'
        installed.mkdir()
        for name in ('ubs', 'ubs-daemon'):
            shutil.copy2(ROOT / name, installed / name)
        return installed

    def test_pinned_daemon_matches_checked_in_source(self):
        pins = re.findall(r'^UBS_DAEMON_SHA256="([0-9a-f]{64})"$', (ROOT / 'ubs').read_text(), re.M)
        self.assertEqual(pins, [hashlib.sha256((ROOT / 'ubs-daemon').read_bytes()).hexdigest()])

    def test_main_help_exposes_canonical_service_commands(self):
        result = self.cli('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        for spelling in ('ubs serve', 'ubs --client', 'ubs daemon'):
            self.assertIn(spelling, result.stdout + result.stderr)

    def test_service_help_precedes_scanner_dependency_and_update_probes(self):
        bin_ = self.work / 'help-bin'
        bin_.mkdir()
        for name in ('bash', 'python3'):
            (bin_ / name).symlink_to(shutil.which(name))
        env = dict(self.env, PATH=str(bin_), UBS_ENABLE_AUTO_UPDATE='1', FORCE_SELF_UPDATE='1')
        for args in (('serve', '--help'), ('--client', '--help'), ('daemon', '--help')):
            with self.subTest(args=args):
                result = self.cli(*args, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)
                self.assertNotIn('not found', result.stderr)

    def test_altered_daemon_fails_before_any_release_code_executes(self):
        installed = self.installation()
        marker = self.work / 'executed'
        (installed / 'ubs-daemon').write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
        result = self.cli('serve', '--help', runner=installed / 'ubs')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('checksum mismatch', result.stderr)
        self.assertFalse(marker.exists())

    def test_missing_daemon_never_uses_path_or_cwd_replacement(self):
        installed = self.installation()
        (installed / 'ubs-daemon').rename(installed / 'ubs-daemon.saved')
        marker = self.work / 'executed'
        replacement = self.root / 'ubs-daemon'
        replacement.write_text(f'#!/usr/bin/env python3\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n')
        replacement.chmod(0o755)
        env = dict(self.env, PATH=str(self.root) + os.pathsep + self.env['PATH'])
        result = self.cli('serve', '--help', runner=installed / 'ubs', env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(marker.exists())

    def test_symlinks_special_files_and_oversized_daemons_are_refused(self):
        installed = self.installation()
        frontend = installed / 'ubs-daemon'
        frontend.rename(installed / 'saved')
        frontend.symlink_to(installed / 'saved')
        result = self.cli('serve', '--help', runner=installed / 'ubs')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('symlinked', result.stderr)
        frontend.rename(installed / 'link')
        os.mkfifo(frontend)
        result = self.cli('serve', '--help', runner=installed / 'ubs', timeout=3)
        self.assertEqual(result.returncode, 2, result.stderr)
        frontend.rename(installed / 'pipe')
        frontend.write_bytes(b' ' * (512 * 1024 + 1))
        result = self.cli('serve', '--help', runner=installed / 'ubs')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_symlinked_runner_resolves_its_own_matching_daemon(self):
        alias = self.root / 'ubs-link'
        alias.symlink_to(ROOT / 'ubs')
        (self.root / 'ubs-daemon').write_text('raise RuntimeError("planted daemon")')
        result = self.cli('daemon', '--help', runner=alias)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pythonpath_and_project_imports_cannot_run_before_verification(self):
        marker = self.work / 'executed'
        for name in ('sitecustomize.py', 'json.py', 'hashlib.py'):
            (self.root / name).write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\nraise RuntimeError("injection")')
        result = self.cli('daemon', '--help', env=dict(self.env, PYTHONPATH=str(self.root)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_missing_explicit_python_is_an_environment_error(self):
        result = self.cli('daemon', '--help', env=dict(self.env, UBS_PYTHON='/missing/interpreter'))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('requires Python', result.stderr)

    def test_client_fallback_keeps_policy_and_argument_boundaries(self):
        for name in ('has space.py', 'line\nbreak.py', '--update.py'):
            (self.root / name).write_text('BUG')
        result = self.cli('--client', '--repo', str(self.root), '--scanner', str(self.scanner),
                          '--format=sarif', '--profile=strict', '--fail-on-warning',
                          '--', 'has space.py', 'line\nbreak.py', '--update.py')
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([Path(name).name for name, _ in report['files']],
                         ['has space.py', 'line\nbreak.py', '--update.py'])
        for option in ('--format=sarif', '--profile=strict', '--fail-on-warning'):
            self.assertIn(option, report['args'])

    def test_unsupported_selection_is_not_silently_changed_to_worktree(self):
        result = self.cli('--client', '--staged', '--scanner', str(self.scanner), 'a.py')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_canonical_lifecycle_and_live_client_use_same_context(self):
        process = subprocess.Popen([str(ROOT / 'ubs'), 'serve', '--repo', str(self.root),
                                    '--scanner', str(self.scanner), '--jobs=2'],
                                   cwd=self.root, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status = self.cli('daemon', 'status', '--repo', str(self.root), '--scanner', str(self.scanner))
            if status.returncode == 0:
                break
            time.sleep(0.02)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)['max_scans'], 2)
        for _ in range(2):
            result = self.cli('--client', '--repo', str(self.root), '--scanner', str(self.scanner),
                              '--require-daemon', 'a.py')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')
        stop = self.cli('daemon', 'stop', '--repo', str(self.root), '--scanner', str(self.scanner))
        self.assertEqual(stop.returncode, 0, stop.stderr)
        process.wait(timeout=5)


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for actual CLI parity')
class NativeEntrypointTests(unittest.TestCase):
    setUp = base.ServiceTests.setUp

    def test_canonical_client_matches_real_one_shot_findings(self):
        self.source.write_text('eval(input())\n')
        results = []
        for flags in (['--client', '--repo', str(self.root)],
                      ['--ci', '--no-auto-update', '--no-color', '--format=json']):
            result = subprocess.run([str(ROOT / 'ubs'), *flags, '--', str(self.source)],
                                    cwd=self.root, env=self.env, text=True, capture_output=True, timeout=130)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            results.append(json.loads(result.stdout)['findings'])
        self.assertEqual(results[0], results[1])
        self.assertTrue(any(f['rule_id'] == 'python.taint.eval' and f['line'] == 1 for f in results[0]))
        print('[canonical-client-native] one-shot finding parity PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
