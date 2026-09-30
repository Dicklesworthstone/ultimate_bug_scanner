"""A verified install checks the binary it installed, not whatever PATH finds.

install.sh's post-install verification ran `ubs --help` and a smoke scan with
the first `ubs` on PATH. With --no-path-modify (or a stale copy earlier on
PATH) that is a different, unauthenticated scanner: the checks vouched for
the wrong binary, and an older ubs fetched its modules from mutable main in
the middle of a signed install.
"""
from __future__ import annotations

import json
import unittest

import test_verified_release as verified_release

STALE_UBS = r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STALE_UBS_LOG"
exit 0
'''


class InstallerPostVerifyTests(unittest.TestCase):
    # Reuse the release fixture without collecting its tests a second time.
    _base = verified_release.VerifiedReleaseTests
    setUp = _base.setUp
    sign = _base.sign
    run_verify = _base.run_verify
    fetches = _base.fetches
    prepare_unsigned_update = _base.prepare_unsigned_update
    del _base

    def test_post_install_checks_run_the_installed_binary(self):
        self.prepare_unsigned_update()
        stale_dir = self.root / 'stale-bin'
        stale_dir.mkdir()
        stale = stale_dir / 'ubs'
        stale.write_text(STALE_UBS)
        stale.chmod(0o755)
        log = self.root / 'stale-ubs.log'
        destination = self.home / 'installed'
        self.env.update(PATH=str(stale_dir) + ':' + self.env['PATH'], STALE_UBS_LOG=str(log),
                        UBS_INSTALLER_WORKDIR=str(self.root / 'work'))
        flags = ['--easy-mode', '--skip-ast-grep', '--skip-ripgrep', '--skip-jq',
                 '--skip-bun', '--skip-type-narrowing', '--skip-typos', '--skip-toon',
                 '--skip-doctor', '--skip-hooks', '--no-path-modify',
                 '--install-dir', str(destination)]
        result = self.run_verify('--artifact-dir', str(self.bundle), '--', *flags)
        self.assertEqual((destination / 'ubs').read_bytes(), (self.bundle / 'ubs').read_bytes())
        self.assertFalse(log.exists(), 'post-install verification executed the PATH ubs: '
                         + (log.read_text() if log.exists() else ''))
        self.assertIn('ubs executes successfully', result.stdout + result.stderr)
        self.assertFalse([item for item in self.fetches()
                          if 'raw.githubusercontent.com' in item['url']], json.dumps(self.fetches()))


if __name__ == '__main__':
    unittest.main()
