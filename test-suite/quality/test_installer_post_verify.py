"""A verified install checks the binary it installed, not whatever PATH finds.

install.sh's post-install verification ran `ubs --help` and a smoke scan with
the first `ubs` on PATH. With --no-path-modify (or a stale copy earlier on
PATH) that is a different, unauthenticated scanner: the checks vouched for
the wrong binary, and an older ubs fetched its modules from mutable main in
the middle of a signed install.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
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

    def install_flags(self, destination, *, doctor=False, hooks=False):
        flags = ['--non-interactive', '--skip-ast-grep', '--skip-ripgrep', '--skip-jq',
                 '--skip-bun', '--skip-type-narrowing', '--skip-typos', '--skip-toon',
                 '--no-path-modify', '--skip-version-check', '--install-dir', str(destination)]
        if not doctor:
            flags.append('--skip-doctor')
        if not hooks:
            flags.append('--skip-hooks')
        return flags

    def prepare_installer(self, runner):
        self.prepare_unsigned_update()
        (self.bundle / 'ubs').write_text(runner)
        self.env['UBS_INSTALLER_WORKDIR'] = str(self.root / 'work')
        self.sign()

    def test_failed_smoke_scan_is_not_reported_as_detection_success(self):
        self.prepare_installer('''#!/usr/bin/env bash
UBS_VERSION="''' + self.version + '''"
case "${1:-}" in --help|-h|--version) exit 0 ;; esac
exit 2
''')
        # The scanner protocol is the double in this status-handling test;
        # keep ast-grep available so the installer must actually run the smoke.
        ast_grep = self.bin / 'ast-grep'
        ast_grep.write_text('#!/usr/bin/env bash\necho "ast-grep 0.45.3"\n')
        ast_grep.chmod(0o755)
        result = self.run_verify('--artifact-dir', str(self.bundle), '--',
                                 *self.install_flags(self.home / 'installed'), expected=1)
        self.assertIn('Smoke test could not verify the installation (exit 2)', result.stderr)
        self.assertNotIn('Smoke test PASSED', result.stdout)
        self.assertNotIn('INSTALLATION COMPLETE', result.stdout)

    def test_failed_cache_repair_cannot_print_installation_complete(self):
        self.prepare_installer('''#!/usr/bin/env bash
UBS_VERSION="''' + self.version + '''"
if [[ "${1:-}" == doctor ]]; then
  printf '%s\\n' '{"status":"error","checks":[{"id":"helper:contract.json","status":"err","detail":"checksum mismatch"}]}'
  exit 2
fi
exit 0
''')
        result = self.run_verify('--artifact-dir', str(self.bundle), '--',
                                 *self.install_flags(self.home / 'installed', doctor=True), expected=1)
        self.assertIn('Post-install health verification failed', result.stderr)
        self.assertNotIn('INSTALLATION COMPLETE', result.stdout)

    def test_explicitly_skipped_optional_dependency_remains_a_warning(self):
        self.prepare_installer('''#!/usr/bin/env bash
UBS_VERSION="''' + self.version + '''"
if [[ "${1:-}" == doctor ]]; then
  printf '%s\\n' '{"status":"error","checks":[{"id":"ast-grep","status":"err","detail":"not installed"}]}'
  exit 2
fi
exit 0
''')
        result = self.run_verify('--artifact-dir', str(self.bundle), '--',
                                 *self.install_flags(self.home / 'installed', doctor=True))
        self.assertIn('explicitly skipped ast-grep dependency', result.stdout)
        self.assertIn('INSTALLATION COMPLETE', result.stdout)

    def test_cron_executes_with_trust_and_cache_configuration_and_replaces_legacy_job(self):
        log = self.root / 'cron-executed.json'
        runner = '''#!/usr/bin/env bash
UBS_VERSION="''' + self.version + '''"
if [[ "${1:-}" == --update ]]; then
  python3 - "$BASH" "$@" <<'PY'
import json, os, pathlib, sys
pathlib.Path(''' + repr(str(log)) + ''').write_text(json.dumps({
    'args': sys.argv[2:], 'bash': sys.argv[1],
    'key': os.environ.get('UBS_MINISIGN_PUBKEY'),
    'data': os.environ.get('XDG_DATA_HOME'),
    'cache': os.environ.get('XDG_CACHE_HOME'),
    'source': os.environ.get('UBS_RELEASE_BASE')}))
PY
fi
exit 0
'''
        self.prepare_installer(runner)
        destination = self.home / "bin'quoted%dir"
        data = self.home / 'data with spaces'
        data.mkdir()
        key = "custom'key%literal;$(touch should-not-exist)"
        self.env.update(UBS_MINISIGN_PUBKEY=key, XDG_DATA_HOME=str(data),
                        XDG_CACHE_HOME=str(self.home / 'cache with spaces'),
                        UBS_RELEASE_BASE='https://updates.example.invalid/custom')
        config = self.home / '.config/ubs'
        config.mkdir(parents=True)
        (config / 'install.conf').write_text('auto_update=1\n')
        crontab = self.root / 'crontab'
        self.env['CRONTAB_SHIM_FILE'] = str(crontab)
        shim = self.bin / 'crontab'
        shim.write_text('''#!/usr/bin/env bash
case "${1:-}" in
  -l) [[ ! -f "$CRONTAB_SHIM_FILE" ]] || cat "$CRONTAB_SHIM_FILE" ;;
  -) cat > "$CRONTAB_SHIM_FILE" ;;
  *) exit 1 ;;
esac
''')
        shim.chmod(0o755)
        unrelated = '15 * * * * /usr/bin/true # another program\n'
        other_install = '0 0 * * * /other/ubs --update # Ultimate Bug Scanner Auto-Update\n'
        legacy = (f'0 0 * * * {destination}/ubs --update --quiet --non-interactive '
                  '>/dev/null 2>&1 # Ultimate Bug Scanner Auto-Update\n')
        crontab.write_text(unrelated + other_install + legacy)
        flags = self.install_flags(destination, hooks=True)
        self.run_verify('--artifact-dir', str(self.bundle), '--', *flags)
        first = crontab.read_text()
        self.assertIn(unrelated, first)
        self.assertIn(other_install, first)
        self.assertNotIn(legacy, first)
        self.run_verify('--artifact-dir', str(self.bundle), '--', *flags)
        self.assertEqual(crontab.read_text(), first)
        jobs = [line for line in first.splitlines()
                if '# Ultimate Bug Scanner Auto-Update' in line and '/other/ubs ' not in line]
        self.assertEqual(len(jobs), 1, first)
        command = jobs[0].split(None, 5)[5]
        self.assertIsNone(re.search(r'(?<!\\)%', command), command)
        # cron removes the escape before passing a literal percent to /bin/sh.
        command = command.replace(r'\%', '%')
        result = subprocess.run(['/bin/sh', '-c', command], cwd=self.project,
                                env={'HOME': str(self.home), 'PATH': '/usr/bin:/bin'},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        event = json.loads(log.read_text())
        self.assertEqual(event['args'], ['--update', '--quiet', '--non-interactive'])
        self.assertTrue(Path(event['bash']).is_absolute())
        self.assertEqual(event['key'], key)
        self.assertEqual(event['data'], str(data.resolve()))
        self.assertEqual(event['cache'], self.env['XDG_CACHE_HOME'])
        self.assertEqual(event['source'], self.env['UBS_RELEASE_BASE'])
        self.assertFalse((self.project / 'should-not-exist').exists())

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
