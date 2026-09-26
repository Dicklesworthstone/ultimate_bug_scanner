"""Exercise the real release verifier and installer at their trust boundary.

Only HTTPS transport and the external signature-verifier executables are
protocol doubles. No live Sigstore/minisign verification is claimed by these
unit tests; payload digests and the installer itself are real.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / 'scripts' / 'verify.sh'
IDENTITY = 'https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/v'
ISSUER = 'https://token.actions.githubusercontent.com'

TRANSPORT = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
url = args[-1]
name = url.rsplit('/', 1)[-1]
log = pathlib.Path(os.environ['FETCH_LOG'])
with log.open('a') as stream:
    stream.write(json.dumps({'name': name, 'args': args}) + '\n')
source = pathlib.Path(os.environ['RELEASE_FIXTURE']) / name
if not source.is_file() or os.environ.get('MISSING_ASSET') == name:
    sys.exit(22)
output = args[args.index('-o') + 1]
pathlib.Path(output).write_bytes(source.read_bytes())
'''

SIGNATURE = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, re, sys
args = sys.argv[1:]
with open(os.environ['SIGNATURE_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
if os.environ.get('BAD_SIGNATURE') == '1':
    sys.exit(1)
if pathlib.Path(sys.argv[0]).name == 'cosign':
    bundle = json.loads(pathlib.Path(args[args.index('--bundle') + 1]).read_text())
    if '--certificate-identity' in args:
        valid = bundle['identity'] == args[args.index('--certificate-identity') + 1]
    else:
        valid = re.search(args[args.index('--certificate-identity-regexp') + 1], bundle['identity']) is not None
    valid &= bundle['issuer'] == args[args.index('--certificate-oidc-issuer') + 1]
    valid &= bundle['digest'] == hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest()
else:
    bundle = json.loads(pathlib.Path(args[args.index('-x') + 1]).read_text())
    valid = bundle['digest'] == hashlib.sha256(pathlib.Path(args[args.index('-Vm') + 1]).read_bytes()).hexdigest()
    valid &= args[args.index('-P') + 1] == 'test-public-key'
if valid and os.environ.get('SWAP_AFTER_SIGNATURE') == '1':
    root = pathlib.Path(os.environ['RELEASE_FIXTURE'])
    replacement = b'#!/usr/bin/env bash\nUBS_VERSION="' + os.environ['UBS_VERSION'].encode() + b'"\nexit 99\n'
    (root / 'ubs').write_bytes(replacement)
    sums = (root / 'SHA256SUMS').read_text().splitlines()
    sums = [hashlib.sha256(replacement).hexdigest() + '  ubs' if line.endswith('  ubs') else line for line in sums]
    (root / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
sys.exit(0 if valid else 1)
'''

INSTALLER = r'''#!/usr/bin/env bash
set -euo pipefail
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 - "$source_dir" "$@" <<'CODE'
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
result = {'cwd': os.getcwd(), 'source': str(root), 'args': sys.argv[2:],
          'base': os.environ.get('UBS_ARTIFACT_BASE'), 'files': {}}
for name in ('ubs', 'VERSION', '.claude/hooks/git_safety_guard.py'):
    path = root / name
    result['files'][name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
pathlib.Path(os.environ['EXEC_LOG']).write_text(json.dumps(result))
CODE
exit "${INSTALL_EXIT:-0}"
'''


class VerifiedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ubs-verified-release-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'release'
        self.bundle.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.project = self.root / 'project with spaces'
        self.project.mkdir()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.temp_root = self.root / 'temporary'
        self.temp_root.mkdir()
        self.version = (ROOT / 'VERSION').read_text().strip()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'COSIGN_', 'SIGSTORE_'))}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        HOME=str(self.home), TMPDIR=str(self.temp_root), NO_COLOR='1',
                        PYTHONDONTWRITEBYTECODE='1', UBS_VERSION=self.version,
                        UBS_ARTIFACT_BASE='https://release.example.invalid/v' + self.version,
                        UBS_VERIFY_WITH='cosign', RELEASE_FIXTURE=str(self.bundle),
                        FETCH_LOG=str(self.root / 'fetch.log'), SIGNATURE_LOG=str(self.root / 'signature.log'),
                        EXEC_LOG=str(self.root / 'executed.json'), UBS_NO_AUTO_UPDATE='1')
        for name, content in (('curl', TRANSPORT), ('cosign', SIGNATURE), ('minisign', SIGNATURE)):
            target = self.bin / name
            target.write_text(content)
            target.chmod(0o755)
        (self.bundle / 'install.sh').write_text(INSTALLER)
        (self.bundle / 'ubs').write_text(f'#!/usr/bin/env bash\nUBS_VERSION="{self.version}"\nexit 0\n')
        (self.bundle / 'git_safety_guard.py').write_text('#!/usr/bin/env python3\nraise SystemExit(0)\n')
        self.sign()

    def sign(self, *, identity=None, issuer=ISSUER, manifest=None):
        if manifest is None:
            manifest = ''.join(f'{hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()}  {name}\n'
                               for name in ('install.sh', 'ubs', 'git_safety_guard.py'))
        (self.bundle / 'SHA256SUMS').write_text(manifest)
        claim = {'digest': hashlib.sha256(manifest.encode()).hexdigest(),
                 'identity': identity or IDENTITY + self.version, 'issuer': issuer}
        for name in ('SHA256SUMS.sigstore.json', 'SHA256SUMS.minisig'):
            (self.bundle / name).write_text(json.dumps(claim))

    def run_verify(self, *args, expected=0):
        result = subprocess.run(['bash', str(VERIFY), *args], cwd=self.project, env=self.env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def execution(self):
        return json.loads(Path(self.env['EXEC_LOG']).read_text())

    def fetches(self):
        path = Path(self.env['FETCH_LOG'])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_not_executed(self):
        self.assertFalse(Path(self.env['EXEC_LOG']).exists(), 'Unverified installer was executed')

    def test_stages_every_executable_from_one_authenticated_manifest(self):
        self.run_verify()
        result = self.execution()
        for staged, asset in (('ubs', 'ubs'), ('.claude/hooks/git_safety_guard.py', 'git_safety_guard.py')):
            self.assertEqual(result['files'][staged], hashlib.sha256((self.bundle / asset).read_bytes()).hexdigest())
        self.assertEqual(result['files']['VERSION'], hashlib.sha256((self.version + '\n').encode()).hexdigest())
        self.assertEqual(result['cwd'], str(self.project))
        self.assertEqual([record['name'] for record in self.fetches()].count('SHA256SUMS'), 1)
        self.assertFalse(Path(result['source']).exists(), 'Private staging directory leaked after success')

    def test_cosign_identity_is_the_exact_selected_release(self):
        self.run_verify()
        args = json.loads(Path(self.env['SIGNATURE_LOG']).read_text().splitlines()[0])
        self.assertIn('--certificate-identity', args)
        self.assertEqual(args[args.index('--certificate-identity') + 1], IDENTITY + self.version)
        self.assertNotIn('--certificate-identity-regexp', args)

    def test_signed_older_or_similarly_prefixed_tag_is_not_accepted(self):
        for tag in ('0.0.1', self.version + '-attacker', self.version + '.9'):
            with self.subTest(tag=tag):
                self.sign(identity=IDENTITY + tag)
                self.run_verify(expected=1)
                self.assert_not_executed()

    def test_wrong_workflow_repository_and_issuer_fail_closed(self):
        for identity, issuer in ((IDENTITY.replace('release.yml', 'test.yml') + self.version, ISSUER),
                                 (IDENTITY.replace('Dicklesworthstone/', 'other/') + self.version, ISSUER),
                                 (IDENTITY + self.version, 'https://example.invalid')):
            with self.subTest(identity=identity, issuer=issuer):
                self.sign(identity=identity, issuer=issuer)
                self.run_verify(expected=1)
                self.assert_not_executed()

    def test_signature_failure_prevents_executable_downloads(self):
        self.env['BAD_SIGNATURE'] = '1'
        self.run_verify(expected=1)
        self.assert_not_executed()
        self.assertFalse({'install.sh', 'ubs', 'git_safety_guard.py'} & {item['name'] for item in self.fetches()})

    def test_payload_tampering_is_rejected_before_installation(self):
        for name in ('install.sh', 'ubs', 'git_safety_guard.py'):
            with self.subTest(asset=name):
                self.sign()
                path = self.bundle / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n# altered after signing\n')
                self.run_verify(expected=1)
                self.assert_not_executed()
                path.write_bytes(original)

    def test_missing_duplicate_and_malformed_digest_entries_fail_closed(self):
        original = (self.bundle / 'SHA256SUMS').read_text()
        for asset in ('install.sh', 'ubs', 'git_safety_guard.py'):
            row = next(line for line in original.splitlines(True) if line.endswith('  ' + asset + '\n'))
            variants = (original.replace(row, ''), original + row,
                        original.replace(row, 'z' * 64 + '  ' + asset + '\n'),
                        original.replace(row, row.rstrip() + ' extra\n'))
            for manifest in variants:
                with self.subTest(asset=asset, manifest=manifest):
                    self.sign(manifest=manifest)
                    self.run_verify(expected=1)
                    self.assert_not_executed()

    def test_gnu_binary_checksums_and_crlf_are_supported(self):
        manifest = (self.bundle / 'SHA256SUMS').read_text().replace('  ', ' *').replace('\n', '\r\n')
        self.sign(manifest=manifest)
        self.run_verify()

    def test_minisign_also_verifies_the_complete_payload(self):
        self.env.update(UBS_VERIFY_WITH='minisign', UBS_MINISIGN_PUBKEY='test-public-key')
        self.run_verify()
        self.assertIsNotNone(self.execution()['files']['ubs'])
        self.assertNotIn('SHA256SUMS.sigstore.json', [item['name'] for item in self.fetches()])

    def test_signed_runner_version_must_match_requested_release(self):
        for verifier in ('cosign', 'minisign'):
            with self.subTest(verifier=verifier):
                self.env.update(UBS_VERIFY_WITH=verifier, UBS_MINISIGN_PUBKEY='test-public-key')
                (self.bundle / 'ubs').write_text('#!/usr/bin/env bash\nUBS_VERSION="0.0.1"\nexit 0\n')
                self.sign()
                self.run_verify(expected=1)
                self.assert_not_executed()

    def test_invalid_verifier_fails_before_network_access(self):
        self.env['UBS_VERIFY_WITH'] = 'unsupported'
        self.run_verify(expected=1)
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_missing_signature_does_not_fall_back_to_checksums(self):
        self.env['MISSING_ASSET'] = 'SHA256SUMS.sigstore.json'
        self.run_verify(expected=1)
        self.assert_not_executed()
        self.assertEqual([item['name'] for item in self.fetches()], ['SHA256SUMS', 'SHA256SUMS.sigstore.json'])

    def test_installer_failure_status_and_cleanup_are_preserved(self):
        self.env['INSTALL_EXIT'] = '37'
        self.run_verify(expected=37)
        self.assertFalse(Path(self.execution()['source']).exists())

    def test_lossless_installer_arguments_and_caller_directory(self):
        arguments = ['--install-dir', str(self.project / 'bin space'), '--label', 'a;$(not-executed)']
        self.run_verify('--', *arguments)
        self.assertEqual(self.execution()['args'], arguments)
        self.assertEqual(self.execution()['cwd'], str(self.project))

    def test_secure_entrypoint_cannot_select_unverified_local_payload(self):
        for argument in ('--local', '--insecure', '--skip-verification'):
            with self.subTest(argument=argument):
                self.run_verify('--', argument, expected=2)
                self.assert_not_executed()
                self.assertFalse(self.fetches())

    def test_invalid_versions_and_missing_option_values_are_usage_errors(self):
        for args in (('--version',), ('--install-args',), ('--version', '../../main'),
                     ('--version', '1.2.3\nother'), ('--version', 'main')):
            with self.subTest(args=args):
                self.run_verify(*args, expected=2)
                self.assert_not_executed()
                self.assertFalse(self.fetches())

    def test_cli_version_updates_identity_without_discarding_custom_mirror(self):
        self.version = '99.1.0-rc.2'
        (self.bundle / 'ubs').write_text(f'#!/usr/bin/env bash\nUBS_VERSION="{self.version}"\nexit 0\n')
        self.sign()
        self.run_verify('--version', 'v' + self.version)
        self.assertEqual(self.execution()['base'], self.env['UBS_ARTIFACT_BASE'])

    def test_explicit_insecure_mode_remains_explicit(self):
        self.env['BAD_SIGNATURE'] = '1'
        self.run_verify('--insecure')
        self.assertTrue(Path(self.env['EXEC_LOG']).exists())
        self.assertFalse(Path(self.env['SIGNATURE_LOG']).exists())

    def test_real_installer_installs_authenticated_runner_without_refetching_manifest(self):
        (self.bundle / 'install.sh').write_bytes((ROOT / 'install.sh').read_bytes())
        (self.bundle / 'ubs').write_bytes((ROOT / 'ubs').read_bytes())
        self.sign()
        # A file planted in the user's project must not override the signed
        # runner sitting next to the authenticated installer.
        (self.project / 'ubs').write_text('#!/usr/bin/env bash\nexit 99\n')
        # The existing installer rejects spaces in its destination; argument
        # fidelity is covered separately without changing that policy here.
        destination = self.home / 'bin'
        self.env['UBS_INSTALLER_WORKDIR'] = str(self.root / 'installer-work')
        flags = ['--non-interactive', '--skip-ast-grep', '--skip-ripgrep', '--skip-jq',
                 '--skip-bun', '--skip-type-narrowing', '--skip-typos', '--skip-toon',
                 '--skip-doctor', '--skip-hooks', '--skip-version-check', '--no-path-modify',
                 '--install-dir', str(destination)]
        result = self.run_verify('--', *flags)
        self.assertEqual((destination / 'ubs').read_bytes(), (self.bundle / 'ubs').read_bytes())
        self.assertEqual([item['name'] for item in self.fetches()].count('SHA256SUMS'), 1, result.stdout)
        self.assertEqual([item['name'] for item in self.fetches()].count('ubs'), 1, result.stdout)

    def test_verify_only_downloads_and_checks_but_never_executes_payloads(self):
        result = self.run_verify('--verify-only')
        self.assert_not_executed()
        self.assertIn('no installer or scanner was executed', result.stdout)
        self.assertEqual({item['name'] for item in self.fetches()},
                         {'SHA256SUMS', 'SHA256SUMS.sigstore.json', 'install.sh', 'ubs', 'git_safety_guard.py'})
        self.assertEqual(list(self.temp_root.iterdir()), [])

    def test_verify_only_cannot_be_an_insecure_success_or_discard_install_flags(self):
        for args in (('--verify-only', '--insecure'), ('--verify-only', '--', '--easy-mode'),
                     ('--verify-only', '--install-args', '--easy-mode')):
            with self.subTest(args=args):
                self.run_verify(*args, expected=2)
                self.assert_not_executed()
                self.assertFalse(self.fetches())

    def test_local_bundle_verification_does_not_download_or_execute(self):
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only')
        self.assert_not_executed()
        self.assertFalse(self.fetches())
        self.assertTrue(Path(self.env['SIGNATURE_LOG']).exists())
        self.assertEqual(list(self.temp_root.iterdir()), [])

    def test_local_bundle_can_install_from_private_verified_copies(self):
        before = {p.name: p.read_bytes() for p in self.bundle.iterdir()}
        self.run_verify('--artifact-dir', str(self.bundle))
        self.assertFalse(self.fetches())
        self.assertNotEqual(self.execution()['source'], str(self.bundle))
        self.assertEqual(self.execution()['files']['ubs'], hashlib.sha256(before['ubs']).hexdigest())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.bundle.iterdir()})

    def test_local_bundle_paths_with_spaces_and_relative_paths(self):
        destination = self.project / 'bundle with spaces'
        shutil.copytree(self.bundle, destination)
        self.run_verify('--artifact-dir=bundle with spaces', '--verify-only')
        self.assertFalse(self.fetches())
        self.assert_not_executed()

    def test_local_bundle_rejects_tampered_runner(self):
        (self.bundle / 'ubs').write_text('#!/usr/bin/env bash\nexit 99\n')
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only', expected=1)
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_local_bundle_rejects_symlinks_even_for_valid_signed_payloads(self):
        original = self.bundle / 'ubs'
        original.rename(self.bundle / 'real-ubs')
        original.symlink_to(self.bundle / 'real-ubs')
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only', expected=1)
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_local_bundle_rejects_missing_assets_without_network_fallback(self):
        (self.bundle / 'git_safety_guard.py').rename(self.bundle / 'saved-guard.py')
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only', expected=1)
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_local_manifest_cannot_be_replaced_after_signature_verification(self):
        self.env['SWAP_AFTER_SIGNATURE'] = '1'
        self.run_verify('--artifact-dir', str(self.bundle), expected=1)
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_local_bundle_minisign_path(self):
        self.env.update(UBS_VERIFY_WITH='minisign', UBS_MINISIGN_PUBKEY='test-public-key')
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only')
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_local_bundle_does_not_require_a_downloader(self):
        offline_bin = self.root / 'offline-bin'
        offline_bin.mkdir()
        digest_tool = next(name for name in ('sha256sum', 'shasum', 'openssl') if shutil.which(name))
        for name in ('bash', 'dirname', 'cat', 'mktemp', 'awk', digest_tool, 'cp', 'rm', 'mkdir', 'python3'):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, name)
            (offline_bin / name).symlink_to(executable)
        (offline_bin / 'minisign').symlink_to(self.bin / 'minisign')
        self.env.update(PATH=str(offline_bin), UBS_VERIFY_WITH='minisign', UBS_MINISIGN_PUBKEY='test-public-key')
        self.run_verify('--artifact-dir', str(self.bundle), '--verify-only')
        self.assert_not_executed()
        self.assertFalse(self.fetches())

    def test_artifact_directory_usage_errors_do_not_download(self):
        for args in (('--artifact-dir',), ('--artifact-dir=',),
                     ('--artifact-dir', str(self.root / 'missing')),
                     ('--artifact-dir', str(self.bundle / 'ubs'))):
            with self.subTest(args=args):
                self.run_verify(*args, expected=2)
                self.assert_not_executed()
                self.assertFalse(self.fetches())

    def test_real_project_hook_install_uses_authenticated_local_guard(self):
        (self.bundle / 'install.sh').write_bytes((ROOT / 'install.sh').read_bytes())
        self.sign()
        subprocess.run(['git', 'init', '-q', str(self.project)], check=True, env=self.env,
                       capture_output=True, timeout=20)
        self.env['UBS_INSTALLER_WORKDIR'] = str(self.root / 'hook-installer-work')
        self.run_verify('--artifact-dir', str(self.bundle), '--', '--setup-claude-hook',
                        '--non-interactive', '--skip-version-check', '--no-path-modify')
        guard = self.project / '.claude' / 'hooks' / 'git_safety_guard.py'
        self.assertEqual(guard.read_bytes(), (self.bundle / 'git_safety_guard.py').read_bytes())
        self.assertFalse(self.fetches())
        self.assertTrue((self.project / '.claude' / 'settings.json').is_file())


if __name__ == '__main__':
    unittest.main()
