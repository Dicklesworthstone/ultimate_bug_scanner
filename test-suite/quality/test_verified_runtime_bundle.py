"""Real verifier/hash/copy tests; curl and signature tools are protocol doubles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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


if __name__ == '__main__':
    unittest.main()
