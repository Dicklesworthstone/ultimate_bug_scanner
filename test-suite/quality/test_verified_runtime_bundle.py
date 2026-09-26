"""Real verifier/hash/copy tests; curl and signature tools are protocol doubles."""
from __future__ import annotations

import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / 'scripts' / 'verify.sh'
VERSION = '1.2.3'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def table(name, entries, declaration='declare -A'):
    return f'{declaration} {name}=(\n' + ''.join(
        f"  ['{key}']='{value}'\n" for key, value in entries.items()) + ')\n'


class RuntimeBundleTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='verified-runtime-', dir=artifacts)
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.origin = self.work / 'release'
        self.origin.mkdir()
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        self.home = self.work / 'home'
        self.home.mkdir()
        self.stage = self.work / 'tmp'
        self.stage.mkdir()
        self.log = self.work / 'events.jsonl'
        self.version = VERSION
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ['PATH'], HOME=str(self.home),
                        TMPDIR=str(self.stage), ORIGIN=str(self.origin), EVENT_LOG=str(self.log),
                        UBS_VERIFY_WITH='cosign', PYTHONDONTWRITEBYTECODE='1')
        self.tool('curl', '''
import json, os, pathlib, shutil, sys
from urllib.parse import urlsplit
args = sys.argv[1:]
url = args[-1]
path = urlsplit(url).path
name = 'modules/' + path.split('/modules/', 1)[1] if '/modules/' in path else path.rsplit('/', 1)[1]
with open(os.environ['EVENT_LOG'], 'a') as f: f.write(json.dumps(['fetch', url, args]) + '\\n')
if '/main/' in url or name == os.environ.get('FAIL_ASSET'): sys.exit(22)
try: shutil.copyfile(pathlib.Path(os.environ['ORIGIN']) / name, args[args.index('-o')+1])
except OSError: sys.exit(22)
''')
        self.tool('cosign', '''
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['EVENT_LOG'], 'a') as f: f.write(json.dumps(['signature', args]) + '\\n')
bundle = pathlib.Path(args[args.index('--bundle')+1]).read_text().strip()
actual = hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest()
expected = 'https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/v' + os.environ.get('EXPECT_VERSION', '1.2.3')
if os.environ.get('REJECT_SIGNATURE') or bundle != actual: sys.exit(1)
if args[args.index('--certificate-identity')+1] != expected: sys.exit(1)
if os.environ.get('LATE_OUTPUT'): pathlib.Path(os.environ['LATE_OUTPUT']).write_bytes(b'keep the concurrent output')
''')
        self.assets = {'contract.json': b'{"schema":"fixture"}\n', 'helpers/tool.py': b'raise SystemExit(91)\n'}
        self.rebuild()

    def tearDown(self):
        print(f'[{self.id()}] FINISHED ({time.monotonic() - self.started:.3f}s)', flush=True)

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!' + sys.executable + ' -S\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def write(self, name, data):
        path = self.origin / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def seal(self):
        manifest = ''.join(f'{digest((self.origin / name).read_bytes())}  {name}\n'
                           for name in ('install.sh', 'ubs', 'git_safety_guard.py'))
        self.write('SHA256SUMS', manifest.encode())
        self.write('SHA256SUMS.sigstore.json', digest(manifest.encode()).encode())

    def rebuild(self):
        helpers = {name: digest(data) for name, data in self.assets.items()}
        library = table('UBS_COMMON_HELPER_CHECKSUMS', helpers, 'declare -g -A').encode()
        self.write('modules/lib/ubs-common.sh', library)
        helpers['lib/ubs-common.sh'] = digest(library)
        module = ('#!/usr/bin/env bash\nUBS_LIB_CHECKSUM="' + digest(library) + '"\nexit 92\n').encode()
        self.write('modules/ubs-python.sh', module)
        for name, data in self.assets.items():
            self.write('modules/' + name, data)
        runner = '#!/usr/bin/env bash\nUBS_VERSION="1.2.3"\nexit 93\n'
        runner += table('MODULE_CHECKSUMS', {'python': digest(module)})
        runner += table('HELPER_CHECKSUMS', helpers)
        runner += 'HELPER_ASSETS=(\n' + ''.join(f'  "{name}"\n' for name in helpers) + ')\n'
        self.write('ubs', runner.encode())
        self.write('install.sh', b'#!/usr/bin/env bash\nexit 94\n')
        self.write('git_safety_guard.py', b'raise SystemExit(95)\n')
        self.seal()

    def change_runner(self, transform):
        self.write('ubs', transform((self.origin / 'ubs').read_text()).encode())
        self.seal()

    def run_verify(self, *args, local=True, expected=0):
        command = ['bash', str(VERIFY), '--version', self.version, '--verify-only', '--with-modules']
        if local:
            command += ['--artifact-dir', str(self.origin)]
        result = subprocess.run(command + list(args), cwd=self.work, env=self.env,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertFalse(list(self.stage.iterdir()), 'Private verification staging leaked')
        return result

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_local_complete_runtime_without_executing_any_payload(self):
        result = self.run_verify()
        self.assertIn('Runtime verified: 1 modules, 3 helper assets', result.stdout)
        self.assertEqual([event[0] for event in self.events()], ['signature'])

    def test_remote_modules_are_release_pinned_and_fetched_after_signature(self):
        result = self.run_verify(local=False)
        self.assertIn('Runtime verified', result.stdout)
        events = self.events()
        module_events = [e for e in events if e[0] == 'fetch' and '/modules/' in e[1]]
        self.assertEqual(len(module_events), 4, events)
        self.assertLess(next(i for i, e in enumerate(events) if e[0] == 'signature'),
                        next(i for i, e in enumerate(events) if e in module_events))
        for event in module_events:
            self.assertIn('/v1.2.3/modules/', event[1])
            self.assertIn('--proto-redir', event[2])
            self.assertIn('=https', event[2])

    def test_bad_signature_never_fetches_runtime(self):
        self.env['REJECT_SIGNATURE'] = '1'
        self.run_verify(local=False, expected=1)
        self.assertFalse(any('/modules/' in e[1] for e in self.events() if e[0] == 'fetch'))

    def test_tampered_module_helper_and_library_each_fail_closed(self):
        for asset in ('ubs-python.sh', 'helpers/tool.py', 'lib/ubs-common.sh', 'contract.json'):
            with self.subTest(asset=asset):
                self.rebuild()
                self.write('modules/' + asset, b'tampered\n')
                result = self.run_verify(expected=1)
                self.assertIn('checksum mismatch', result.stderr.lower())

    def test_missing_runtime_asset_has_no_network_fallback(self):
        original = self.origin / 'modules/helpers/tool.py'
        original.rename(original.with_suffix('.unavailable'))
        self.run_verify(expected=1)
        self.assertFalse(any(e[0] == 'fetch' for e in self.events()))

    def test_remote_missing_module_does_not_try_mutable_main(self):
        self.env['FAIL_ASSET'] = 'modules/ubs-python.sh'
        self.run_verify(local=False, expected=1)
        self.assertFalse(any('/main/' in e[1] for e in self.events() if e[0] == 'fetch'))

    def test_empty_python_package_files_are_valid(self):
        self.assets['helpers/__init__.py'] = b''
        self.rebuild()
        self.assertIn('4 helper assets', self.run_verify().stdout)

    def test_duplicate_pins_and_duplicate_asset_names_are_rejected(self):
        for transform in (
            lambda s: s.replace("  ['python']=", "  ['python']='" + '0'*64 + "'\n  ['python']=", 1),
            lambda s: s.replace('HELPER_ASSETS=(\n', 'HELPER_ASSETS=(\n  "helpers/tool.py"\n', 1),
            lambda s: s + table('MODULE_CHECKSUMS', {'python': '0'*64}),
        ):
            with self.subTest(transform=transform):
                self.rebuild()
                self.change_runner(transform)
                self.run_verify(expected=1)

    def test_nonliteral_checksum_table_never_executes_shell_expansion(self):
        marker = self.work / 'executed'
        self.change_runner(lambda s: s.replace("['python']=", "[$(touch " + str(marker) + ")]=", 1))
        self.run_verify(expected=1)
        self.assertFalse(marker.exists())

    def test_unpinned_and_unlisted_helpers_are_rejected(self):
        for transform in (
            lambda s: s.replace('HELPER_ASSETS=(\n', 'HELPER_ASSETS=(\n  "helpers/unpinned.py"\n', 1),
            lambda s: s.replace('  "helpers/tool.py"\n', '', 1),
        ):
            with self.subTest(transform=transform):
                self.rebuild()
                self.change_runner(transform)
                self.run_verify(expected=1)

    def test_unsafe_asset_paths_are_rejected_before_module_downloads(self):
        for bad in ('../escape.py', '/absolute.py', 'helpers/../escape.py', 'helpers//tool.py',
                    'helpers/./tool.py', 'helpers/tool.py?bad', 'helpers/evil\\name.py'):
            with self.subTest(path=bad):
                self.rebuild()
                self.change_runner(lambda s: s.replace('helpers/tool.py', bad))
                result = self.run_verify(local=False, expected=1)
                self.assertIn('runtime', result.stderr.lower())
                self.assertFalse(any('/modules/' in e[1] for e in self.events() if e[0] == 'fetch'))

    def test_symlinked_runtime_files_and_directories_are_rejected(self):
        for rel in ('modules/helpers/tool.py', 'modules/helpers'):
            with self.subTest(path=rel):
                target = self.origin / rel
                saved = target.with_name(target.name + '.original')
                target.rename(saved)
                target.symlink_to(saved, target_is_directory=saved.is_dir())
                self.run_verify(expected=1)
                # Preserve the symlink rather than deleting any repository file.
                target.rename(target.with_name(target.name + '.link'))
                saved.rename(target)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFO')
    def test_fifo_runtime_asset_is_rejected_without_blocking(self):
        target = self.origin / 'modules/helpers/tool.py'
        target.rename(target.with_suffix('.regular'))
        os.mkfifo(target)
        self.run_verify(expected=1)

    def test_runtime_verification_rejects_insecure_mode(self):
        self.run_verify('--insecure', expected=2)
        self.assertEqual(self.events(), [])

    def test_with_modules_requires_a_nonexecuting_mode(self):
        result = subprocess.run(['bash', str(VERIFY), '--version', VERSION, '--with-modules'],
                                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('--verify-only', result.stderr)
        self.assertEqual(self.events(), [])

    def test_conflicting_nested_library_pin_is_rejected(self):
        path = self.origin / 'modules/ubs-python.sh'
        previous = path.read_bytes()
        changed = b'#!/usr/bin/env bash\nUBS_LIB_CHECKSUM="' + b'0'*64 + b'"\n'
        path.write_bytes(changed)
        self.change_runner(lambda s: s.replace(digest(previous), digest(changed)))
        result = self.run_verify(expected=1)
        self.assertIn('library pin', result.stderr.lower())

    def test_conflicting_library_helper_pins_are_rejected(self):
        library = self.origin / 'modules/lib/ubs-common.sh'
        original = library.read_bytes()
        modified = original.replace(digest(self.assets['helpers/tool.py']).encode(), b'0' * 64)
        library.write_bytes(modified)
        module = self.origin / 'modules/ubs-python.sh'
        before = module.read_bytes()
        after = before.replace(digest(original).encode(), digest(modified).encode())
        module.write_bytes(after)
        self.change_runner(lambda s: s.replace(digest(original), digest(modified)).replace(digest(before), digest(after)))
        result = self.run_verify(expected=1)
        self.assertIn('shared-library helper pins', result.stderr)

    def test_mirror_still_requires_authenticated_checksums(self):
        self.env['UBS_MODULE_ARTIFACT_BASE'] = 'https://mirror.invalid/pinned/modules'
        self.run_verify(local=False)
        urls = [e[1] for e in self.events() if e[0] == 'fetch' and '/modules/' in e[1]]
        self.assertTrue(urls)
        self.assertTrue(all(url.startswith('https://mirror.invalid/pinned/modules/') for url in urls))
        self.write('modules/helpers/tool.py', b'tampered')
        self.run_verify(local=False, expected=1)

    def test_insecure_module_mirror_is_rejected_before_fetching(self):
        self.env['UBS_MODULE_ARTIFACT_BASE'] = 'http://mirror.invalid/modules'
        self.run_verify(local=False, expected=2)
        self.assertEqual(self.events(), [])

    def test_actual_checkout_runtime_closure(self):
        self.version = (ROOT / 'VERSION').read_text().strip().removeprefix('v')
        self.env['EXPECT_VERSION'] = self.version
        self.write('ubs', (ROOT / 'ubs').read_bytes())
        shutil.copytree(ROOT / 'modules', self.origin / 'modules', dirs_exist_ok=True)
        self.seal()
        result = self.run_verify()
        self.assertIn('Runtime verified: 12 modules,', result.stdout)

    def export(self, output, expected=0, extra=()):
        result = subprocess.run(['bash', str(VERIFY), '--version', self.version,
                                 '--artifact-dir', str(self.origin), '--bundle-output', str(output), *extra],
                                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertFalse(list(self.stage.iterdir()), 'Private verification staging leaked')
        self.assertFalse(list(self.work.glob('.ubs-bundle-*.tmp')), 'Partial output archive leaked')
        return result

    def test_plain_verification_still_accepts_a_release_without_runtime_metadata(self):
        self.write('ubs', b'#!/usr/bin/env bash\nUBS_VERSION="1.2.3"\nexit 93\n')
        self.seal()
        result = subprocess.run(['bash', str(VERIFY), '--version', VERSION, '--artifact-dir', str(self.origin),
                                 '--verify-only'], cwd=self.work, env=self.env, text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('Runtime verified', result.stdout)
        self.assertFalse(list(self.stage.iterdir()))

    def test_plain_installer_exit_status_and_cleanup_are_preserved(self):
        result = subprocess.run(['bash', str(VERIFY), '--version', VERSION, '--artifact-dir', str(self.origin)],
                                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 94, result.stdout + result.stderr)
        self.assertFalse(list(self.stage.iterdir()))

    def test_bundle_minisign_preserves_original_signature_for_reverification(self):
        self.env.update(UBS_VERIFY_WITH='minisign', UBS_MINISIGN_PUBKEY='fixture-key')
        self.write('SHA256SUMS.minisig', digest((self.origin / 'SHA256SUMS').read_bytes()).encode())
        self.tool('minisign', '''
import hashlib, pathlib, sys
args = sys.argv[1:]
expected = pathlib.Path(args[args.index('-x')+1]).read_text().strip()
actual = hashlib.sha256(pathlib.Path(args[args.index('-Vm')+1]).read_bytes()).hexdigest()
sys.exit(0 if expected == actual and args[args.index('-P')+1] == 'fixture-key' else 1)
''')
        output = self.work / 'minisign.tar.gz'
        self.export(output)
        unpacked = self.work / 'minisign-unpacked'
        unpacked.mkdir()
        with tarfile.open(output) as archive:
            self.assertIn('SHA256SUMS.minisig', archive.getnames())
            self.assertNotIn('SHA256SUMS.sigstore.json', archive.getnames())
            archive.extractall(unpacked, filter='data')
        self.origin = unpacked
        self.run_verify()

    def test_bundle_contains_only_authenticated_runtime_and_safe_metadata(self):
        output = self.work / 'portable runtime.tar.gz'
        self.write('unrelated-secret.txt', b'must not be exported')
        self.write('modules/helpers/unlisted.py', b'must not be exported')
        self.export(output)
        with tarfile.open(output) as archive:
            expected = {'SHA256SUMS', 'SHA256SUMS.sigstore.json', 'ubs', 'install.sh',
                        'git_safety_guard.py', '.claude/hooks/git_safety_guard.py', 'VERSION',
                        'modules/ubs-python.sh', 'modules/lib/ubs-common.sh',
                        'modules/contract.json', 'modules/helpers/tool.py'}
            self.assertEqual(set(archive.getnames()), expected)
            for member in archive.getmembers():
                self.assertTrue(member.isfile(), member)
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                if member.name == 'ubs' or member.name.endswith(('.sh', '.py')):
                    self.assertEqual(member.mode, 0o755)
                if member.name not in {'VERSION', '.claude/hooks/git_safety_guard.py'}:
                    self.assertEqual(archive.extractfile(member).read(), (self.origin / member.name).read_bytes())

    def test_bundle_round_trip_revalidates_entire_runtime_offline(self):
        output = self.work / 'bundle.tar.gz'
        self.export(output)
        unpacked = self.work / 'unpacked'
        unpacked.mkdir()
        with tarfile.open(output) as archive:
            archive.extractall(unpacked, filter='data')
        self.origin = unpacked
        self.run_verify()
        self.assertFalse(any(event[0] == 'fetch' for event in self.events()))

    def test_bundle_export_is_byte_reproducible(self):
        first, second = self.work / 'one.tar.gz', self.work / 'two.tar.gz'
        self.export(first)
        self.export(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def import_archive(self, archive, expected=0, extra=(), verify_only=True):
        flags = ['--verify-only', '--with-modules'] if verify_only else []
        result = subprocess.run(['bash', str(VERIFY), '--version', self.version,
                                 '--artifact-archive', str(archive), *flags, *extra],
                                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertFalse(list(self.stage.iterdir()), 'Private archive staging leaked')
        self.assertFalse(any(event[0] == 'fetch' for event in self.events()), self.events())
        return result

    def archive_with(self, name, members, include_release=True):
        output = self.work / name
        with tarfile.open(output, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            if include_release:
                for path in sorted(self.origin.rglob('*')):
                    if path.is_file():
                        archive.add(path, arcname=str(path.relative_to(self.origin)), recursive=False)
            for member, content in members:
                archive.addfile(member, io.BytesIO(content))
        return output

    def test_archive_import_round_trip_rechecks_entire_runtime_without_network(self):
        original, replay = self.work / 'portable runtime.tar.gz', self.work / 'replayed.tar.gz'
        self.export(original)
        before = {str(path.relative_to(self.origin)): path.read_bytes()
                  for path in self.origin.rglob('*') if path.is_file()}
        result = self.import_archive(original.name, extra=('--bundle-output', str(replay)))
        self.assertIn('Runtime verified: 1 modules, 3 helper assets', result.stdout)
        self.assertEqual(replay.read_bytes(), original.read_bytes())
        self.assertEqual(before, {str(path.relative_to(self.origin)): path.read_bytes()
                                 for path in self.origin.rglob('*') if path.is_file()})

    def test_archive_import_authenticates_signature_and_every_runtime_pin(self):
        output = self.work / 'signed.tar.gz'
        self.export(output)
        self.env['REJECT_SIGNATURE'] = '1'
        self.import_archive(output, expected=1)
        self.env.pop('REJECT_SIGNATURE')
        self.write('modules/helpers/tool.py', b'tampered after signing')
        altered = self.archive_with('altered.tar.gz', [])
        result = self.import_archive(altered, expected=1)
        self.assertIn('checksum mismatch', result.stderr)

    def test_archive_import_installer_status_and_arguments_are_preserved(self):
        self.write('install.sh', b'''#!/usr/bin/env bash
[[ "$UBS_INSTALLER_SELF_UPDATED" == 1 && "$UBS_NO_AUTO_UPDATE" == 1 ]] || exit 99
[[ "$1" == '--label' && "$2" == 'space ; $literal' ]] || exit 98
[[ "$PWD" == "$EXPECTED_CWD" ]] || exit 97
exit 37
''')
        self.env['EXPECTED_CWD'] = str(self.work)
        self.seal()
        output = self.work / 'installer.tar.gz'
        self.export(output)
        self.import_archive(output, expected=37, verify_only=False,
                            extra=('--', '--label', 'space ; $literal'))

    def test_archive_import_supports_minisign_and_does_not_require_curl(self):
        self.env.update(UBS_VERIFY_WITH='minisign', UBS_MINISIGN_PUBKEY='fixture-key')
        self.write('SHA256SUMS.minisig', digest((self.origin / 'SHA256SUMS').read_bytes()).encode())
        self.tool('minisign', '''
import hashlib, pathlib, sys
args = sys.argv[1:]
expected = pathlib.Path(args[args.index('-x')+1]).read_text().strip()
actual = hashlib.sha256(pathlib.Path(args[args.index('-Vm')+1]).read_bytes()).hexdigest()
sys.exit(0 if expected == actual and args[args.index('-P')+1] == 'fixture-key' else 1)
''')
        output = self.work / 'offline.tar.gz'
        self.export(output)
        isolated = self.work / 'archive-offline-tools'
        isolated.mkdir()
        for tool in ('bash', 'dirname', 'cat', 'awk', 'mktemp', 'rm', 'cp', 'mkdir', 'sha256sum', 'python3'):
            (isolated / tool).symlink_to(shutil.which(tool))
        (isolated / 'minisign').symlink_to(self.bin / 'minisign')
        self.env['PATH'] = str(isolated)
        self.import_archive(output)

    def test_archive_import_rejects_paths_outside_private_staging(self):
        for index, name in enumerate(('../outside', '/absolute', 'modules/../outside',
                                      'modules//tool.py', 'modules/./tool.py', 'C:/outside',
                                      'modules\\outside', 'modules/tool.py.', './ubs',
                                      'modules/CON', 'modules/nul.py', 'modules/Lpt1.txt')):
            with self.subTest(path=name):
                member = tarfile.TarInfo(name)
                output = self.archive_with(f'unsafe-{index}.tar.gz', [(member, b'')])
                result = self.import_archive(output, expected=1)
                self.assertIn('unsafe archive path', result.stderr)
                self.assertEqual(self.events(), [], 'Rejected archive reached authentication')
        self.assertFalse((self.work / 'outside').exists())

    def test_archive_import_rejects_links_and_special_files_before_authentication(self):
        for index, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                                      tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE)):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo('modules/linked')
                member.type, member.linkname = kind, '../../outside'
                output = self.archive_with(f'special-{index}.tar.gz', [(member, b'')])
                self.import_archive(output, expected=1)
                self.assertEqual(self.events(), [])

    def test_archive_import_rejects_duplicate_case_and_file_directory_collisions(self):
        variants = (
            [tarfile.TarInfo('ubs')],
            [tarfile.TarInfo('UBS')],
            [tarfile.TarInfo('Modules/extra.py')],
            [tarfile.TarInfo('modules')],
            [tarfile.TarInfo('ubs/extra.py')],
        )
        for index, members in enumerate(variants):
            with self.subTest(index=index):
                output = self.archive_with(f'collision-{index}.tar.gz', [(m, b'') for m in members])
                self.import_archive(output, expected=1)
                self.assertEqual(self.events(), [])

    def test_archive_import_accepts_directories_and_bounded_long_path_metadata(self):
        name = 'helpers/' + 'nested/' * 20 + 'test.py'
        self.assets[name] = b'raise SystemExit(96)\n'
        self.rebuild()
        directory = tarfile.TarInfo('modules/helpers/')
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o4777  # permissions/ownership are not trusted
        output = self.archive_with('directories.tar.gz', [(directory, b'')])
        self.import_archive(output)

    def test_archive_import_rejects_member_and_metadata_bombs_before_allocation(self):
        for index, kind in enumerate((tarfile.REGTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME)):
            member = tarfile.TarInfo('oversized')
            member.type, member.size = kind, 65 * 1024 * 1024
            output = self.work / f'oversized-{index}.tar.gz'
            # A header alone is enough to assert the size guard. Do not allocate
            # the advertised body, and do not change production limits for tests.
            output.write_bytes(gzip.compress(member.tobuf() + b'\0' * 1024))
            result = self.import_archive(output, expected=1)
            self.assertTrue('64 MiB' in result.stderr or 'oversized archive metadata' in result.stderr,
                            result.stderr)
            self.assertEqual(self.events(), [])

    def test_archive_import_rejects_truncated_and_corrupt_gzip_streams(self):
        good = self.work / 'good.tar.gz'
        self.export(good)
        original = good.read_bytes()
        for index, data in enumerate((original[:-8], original[:-1] + bytes([original[-1] ^ 1]), b'not gzip')):
            with self.subTest(index=index):
                output = self.work / f'corrupt-{index}.tar.gz'
                output.write_bytes(data)
                self.import_archive(output, expected=1)

    def test_archive_import_rejects_empty_archives_and_missing_signed_assets(self):
        empty = self.archive_with('empty.tar.gz', [], include_release=False)
        self.import_archive(empty, expected=1)
        incomplete = self.archive_with('incomplete.tar.gz', [(tarfile.TarInfo('VERSION'), b'')],
                                       include_release=False)
        self.import_archive(incomplete, expected=1)

    def test_archive_import_rejects_excessive_member_count(self):
        output = self.work / 'many.tar.gz'
        with tarfile.open(output, 'w:gz') as archive:
            for index in range(16385):
                archive.addfile(tarfile.TarInfo(f'empty-{index}'))
        result = self.import_archive(output, expected=1)
        self.assertIn('16384 entries', result.stderr)
        self.assertEqual(self.events(), [])

    def test_archive_import_rejects_compressed_size_before_decompression(self):
        output = self.work / 'large.tar.gz'
        with output.open('wb') as stream:
            stream.truncate(128 * 1024 * 1024 + 1)
        result = self.import_archive(output, expected=1)
        self.assertIn('128 MiB', result.stderr)
        self.assertEqual(self.events(), [])

    def test_archive_import_usage_errors_and_nonregular_inputs(self):
        output = self.work / 'valid.tar.gz'
        self.export(output)
        self.import_archive(output, expected=2, extra=('--artifact-dir', str(self.origin)))
        self.import_archive(output, expected=2, extra=('--insecure',))
        self.import_archive(self.origin, expected=2)
        link = self.work / 'link.tar.gz'
        link.symlink_to(output)
        self.import_archive(link, expected=2)
        if hasattr(os, 'mkfifo'):
            fifo = self.work / 'pipe.tar.gz'
            os.mkfifo(fifo)
            self.import_archive(fifo, expected=2)
        for args in (('--artifact-archive',), ('--artifact-archive=',)):
            result = subprocess.run(['bash', str(VERIFY), *args], cwd=self.work, env=self.env,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_bundle_output_never_overwrites_existing_file_or_symlink(self):
        output = self.work / 'existing.tar.gz'
        output.write_bytes(b'keep this artifact')
        self.export(output, expected=2)
        self.assertEqual(output.read_bytes(), b'keep this artifact')
        link = self.work / 'link.tar.gz'
        link.symlink_to(output)
        self.export(link, expected=2)
        self.assertTrue(link.is_symlink())
        self.assertEqual(output.read_bytes(), b'keep this artifact')
        self.assertEqual(self.events(), [])

    def test_bundle_atomic_publish_preserves_concurrent_output(self):
        output = self.work / 'raced.tar.gz'
        self.env['LATE_OUTPUT'] = str(output)
        result = self.export(output, expected=1)
        self.assertIn('File exists', result.stderr)
        self.assertEqual(output.read_bytes(), b'keep the concurrent output')

    def test_bundle_failed_authentication_or_tampering_publishes_nothing(self):
        output = self.work / 'rejected.tar.gz'
        self.env['REJECT_SIGNATURE'] = '1'
        self.export(output, expected=1)
        self.assertFalse(output.exists())
        self.env.pop('REJECT_SIGNATURE')
        self.write('modules/helpers/tool.py', b'tampered')
        self.export(output, expected=1)
        self.assertFalse(output.exists())

    def test_bundle_rejects_insecure_or_silently_discarded_install_args(self):
        for args in (('--insecure',), ('--', '--skip-hooks')):
            with self.subTest(args=args):
                output = self.work / 'invalid.tar.gz'
                self.export(output, expected=2, extra=args)
                self.assertFalse(output.exists())
        self.export(self.work / 'absent' / 'bundle.tar.gz', expected=2)
        self.assertEqual(self.events(), [])

    def test_bundle_local_export_needs_no_downloader(self):
        isolated = self.work / 'no-network-tools'
        isolated.mkdir()
        for tool in ('bash', 'dirname', 'cat', 'awk', 'mktemp', 'rm', 'cp', 'mkdir', 'sha256sum', 'python3'):
            actual = shutil.which(tool)
            self.assertIsNotNone(actual, tool)
            (isolated / tool).symlink_to(actual)
        (isolated / 'cosign').symlink_to(self.bin / 'cosign')
        self.env['PATH'] = str(isolated)
        output = self.work / 'offline.tar.gz'
        self.export(output)
        self.assertTrue(output.is_file())
        self.assertFalse(any(event[0] == 'fetch' for event in self.events()))

    def test_bundle_actual_scanner_runs_with_empty_cache_and_downloads_blocked(self):
        self.version = (ROOT / 'VERSION').read_text().strip().removeprefix('v')
        self.env['EXPECT_VERSION'] = self.version
        for name in ('ubs', 'install.sh'):
            self.write(name, (ROOT / name).read_bytes())
        self.write('git_safety_guard.py', (ROOT / '.claude/hooks/git_safety_guard.py').read_bytes())
        shutil.copytree(ROOT / 'modules', self.origin / 'modules', dirs_exist_ok=True)
        self.seal()
        output = self.work / 'real-scanner.tar.gz'
        self.export(output)
        unpacked = self.work / 'portable'
        unpacked.mkdir()
        with tarfile.open(output) as archive:
            archive.extractall(unpacked, filter='data')
        self.origin = unpacked
        self.run_verify()
        for name in ('curl', 'wget'):
            self.tool(name, '''
import json, os, sys
with open(os.environ['EVENT_LOG'], 'a') as f: f.write(json.dumps(['blocked-network', sys.argv]) + '\\n')
sys.exit(97)
''')
        source = self.work / 'view.py'
        source.write_text('eval(input())\n', encoding='utf-8')
        self.env.update(UBS_NO_AUTO_UPDATE='1', XDG_DATA_HOME=str(self.home / 'data'),
                        XDG_CACHE_HOME=str(self.home / 'cache'))
        result = subprocess.run([str(unpacked / 'ubs'), str(source), '--only=python', '--ci',
                                 '--format=json', '--module-dir=' + str(unpacked / 'modules')],
                                cwd=self.work, env=self.env, text=True, capture_output=True, timeout=120)
        artifacts = ROOT / 'test-suite/artifacts/verified-runtime-e2e'
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / 'scan.json').write_text(result.stdout)
        (artifacts / 'scan.stderr.log').write_text(result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report.get('status'), 'ok', report)
        self.assertEqual(report['totals']['files'], 1, report)
        self.assertTrue(any(f['rule_id'] == 'python.taint.eval' and f['line'] == 1
                            for f in report['findings']), report)
        clean = subprocess.run([str(unpacked / 'ubs'), str(VERIFY), '--only=bash', '--ci',
                                '--format=json', '--module-dir=' + str(unpacked / 'modules')],
                               cwd=self.work, env=self.env, text=True, capture_output=True, timeout=120)
        (artifacts / 'clean.json').write_text(clean.stdout)
        (artifacts / 'clean.stderr.log').write_text(clean.stderr)
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        clean_report = json.loads(clean.stdout)
        self.assertEqual(clean_report.get('status'), 'ok', clean_report)
        self.assertEqual(clean_report['totals']['files'], 1, clean_report)
        self.assertEqual(clean_report['totals']['critical'], 0, clean_report)
        self.assertEqual(clean_report['totals']['warning'], 0, clean_report)
        self.assertFalse(any(e[0] in {'fetch', 'blocked-network'} for e in self.events()), self.events())


if __name__ == '__main__':
    unittest.main()
