"""Cache-hit truthfulness under concurrent source, inventory and runtime edits."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('ubs_daemon_snapshot', str(ROOT / 'ubs-daemon'))
spec = importlib.util.spec_from_loader(loader.name, loader)
daemon = importlib.util.module_from_spec(spec)
loader.exec_module(daemon)

# Protocol double with a real process/stream boundary, not a UBS detector.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
text = pathlib.Path(args[args.index('--') + 1]).read_text()
with open(os.environ['SCAN_COUNT'], 'a') as out: out.write('scan\n')
print(json.dumps({'source':text}))
sys.exit(1 if 'BUG' in text else 0)
'''


@unittest.skipUnless(os.name == 'posix', 'descriptor and Unix service contracts')
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ubs-snapshot-')
        self.addCleanup(tmp.cleanup)
        # The service compares sources against the canonical repository root;
        # TMPDIR may sit behind a symlink (macOS /var/folders).
        self.work = Path(tmp.name).resolve()
        self.root = self.work / 'project'
        self.root.mkdir()
        self.home = self.work / 'home'
        self.home.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('clean\n')
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        (self.work / 'modules').mkdir()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'SCAN_'))}
        env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / '.config'),
                   SCAN_COUNT=str(self.work / 'scans'), PYTHONDONTWRITEBYTECODE='1')
        environment = patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.service = daemon.ScanService(self.root, self.scanner, 5, 1024 * 1024)

    def request(self):
        return {'protocol': 1, 'op': 'scan', 'root': str(self.root), 'paths': ['a.py'],
                'environment': daemon.environment_key(), 'scanner': str(self.scanner), 'format': 'json'}

    def snapshot(self):
        return daemon.snapshot(self.root, self.scanner)

    def during_runtime_read(self, change):
        """Same mutation boundary for the old buffered and new descriptor reader."""
        original_path_open, original_os_open = Path.open, os.open
        fired = [False]
        def maybe_change(path):
            if not fired[0] and os.fspath(path) in (str(self.scanner), self.scanner.name):
                fired[0] = True
                change()
        def path_open(path, *args, **kwargs):
            maybe_change(path)
            return original_path_open(path, *args, **kwargs)  # ubs:ignore[python.lifecycle.file_handle] - transfers the test stream to the caller's closing context.
        def os_open(path, *args, **kwargs):
            maybe_change(path)
            return original_os_open(path, *args, **kwargs)
        return patch.object(Path, 'open', path_open), patch.object(daemon.os, 'open', os_open), fired

    def test_stable_sources_reuse_exact_report_and_only_one_scanner(self):
        first = self.service.handle(self.request())
        second = self.service.handle(self.request())
        self.assertFalse(first['cached'])
        self.assertTrue(second['cached'])
        for field in ('stdout', 'stderr', 'exit_code'):
            self.assertEqual(first[field], second[field])
        self.assertEqual((self.work / 'scans').read_text(), 'scan\n')

    def test_snapshot_status_and_disabled_report_cache_do_not_initialize_runtime(self):
        cache = self.home / '.local/share/ubs/modules'
        self.assertFalse(cache.exists())
        self.assertIsNotNone(self.snapshot())
        status = self.service.handle({'protocol': 1, 'op': 'status', 'root': str(self.root)})
        self.assertEqual(status['status'], 'ready')
        self.assertFalse(cache.exists())
        self.service.cache_bytes = 0
        result = self.service.handle(self.request())
        self.assertEqual(result['exit_code'], 0, result)
        self.assertFalse(result['cached'], result)
        self.assertFalse(cache.exists())

    def test_failed_runtime_directory_preparation_delegates_without_reusing_report(self):
        first = self.service.handle(self.request())
        self.assertEqual(first['exit_code'], 0, first)
        self.assertTrue(self.service.handle(self.request())['cached'])
        cache = self.home / '.local/share/ubs/modules'
        original_mkdir = Path.mkdir
        def refuse_cache(path, *args, **kwargs):
            if path == cache:
                raise PermissionError('runtime directory unavailable')
            return original_mkdir(path, *args, **kwargs)
        with patch.object(Path, 'mkdir', refuse_cache):
            result = self.service.handle(self.request())
        self.assertFalse(result['cached'], result)
        for field in ('stdout', 'stderr', 'exit_code'):
            self.assertEqual(first[field], result[field])
        self.assertEqual((self.work / 'scans').read_text(), 'scan\nscan\n')

    def test_relative_xdg_runtime_is_prepared_in_served_root_before_first_report(self):
        with patch.dict(os.environ, {'XDG_DATA_HOME': 'runtime-data'}):
            self.service = daemon.ScanService(self.root, self.scanner, 5, 1024 * 1024)
            first = self.service.handle(self.request())
            second = self.service.handle(self.request())
        self.assertEqual(first['exit_code'], 0, first)
        self.assertFalse(first['cached'], first)
        self.assertTrue(second['cached'], second)
        cache = self.root / 'runtime-data/ubs/modules'
        self.assertTrue(cache.is_dir())
        self.assertEqual(list(cache.iterdir()), [])
        self.assertEqual((self.work / 'scans').read_text(), 'scan\n')

    def test_cached_clean_cannot_survive_edit_after_source_was_hashed(self):
        self.assertEqual(self.service.handle(self.request())['exit_code'], 0)
        before = self.source.stat()
        def edit():
            self.source.write_text('BUG!!\n')  # Same length; directory metadata does not change.
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
        a, b, fired = self.during_runtime_read(edit)
        with a, b:
            result = self.service.handle(self.request())
        self.assertTrue(fired[0])
        self.assertEqual(result['exit_code'], 1, result)
        self.assertFalse(result['cached'], result)
        self.assertEqual(json.loads(result['stdout'])['source'], 'BUG!!\n')
        self.assertEqual((self.work / 'scans').read_text(), 'scan\nscan\n')

    def test_late_directory_addition_invalidates_completed_inventory(self):
        a, b, fired = self.during_runtime_read(lambda: (self.root / 'new.py').write_text('BUG'))
        with a, b:
            result = self.snapshot()
        self.assertTrue(fired[0])
        self.assertIsNone(result)
        self.assertIsNotNone(self.snapshot())

    def test_missing_global_config_created_after_discovery_invalidates(self):
        a, b, fired = self.during_runtime_read(lambda: (self.home / '.gitconfig').write_text('[core]\nignoreCase = true\n'))
        with a, b:
            result = self.snapshot()
        self.assertTrue(fired[0])
        self.assertIsNone(result)
        self.assertIsNotNone(self.snapshot())

    def test_git_tool_replacement_after_tool_discovery_invalidates(self):
        tools = self.work / 'bin'
        tools.mkdir()
        git = tools / 'git'
        git.write_text('#!/bin/sh\nexit 0\n')
        git.chmod(0o755)
        with patch.dict(os.environ, {'PATH':str(tools) + os.pathsep + os.environ['PATH']}):
            before = self.snapshot()
            a, b, fired = self.during_runtime_read(lambda: git.write_text('#!/bin/sh\nexit 1\n'))
            with a, b:
                result = self.snapshot()
            self.assertTrue(fired[0])
            self.assertIsNone(result)
            self.assertNotEqual(before, self.snapshot())

    def test_optional_config_appearing_then_disappearing_invalidates(self):
        def edit():
            path = self.home / '.gitignore'
            path.write_text('*.py\n')
            path.rename(self.work / 'removed-ignore')
        a, b, fired = self.during_runtime_read(edit)
        with a, b:
            result = self.snapshot()
        self.assertTrue(fired[0])
        self.assertIsNone(result)
        self.assertIsNotNone(self.snapshot())

    def test_symlink_swap_is_refused_before_external_content_is_read(self):
        outside = self.work / 'outside'
        outside.write_text('PRIVATE')
        path_open, os_open = Path.open, os.open
        changed = [False]
        external_reads = []
        def swap(path):
            if os.fspath(path) in (str(self.source), self.source.name) and not changed[0]:
                changed[0] = True
                self.source.rename(self.work / 'original')
                self.source.symlink_to(outside)
        class Spy:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *exc): self.stream.close()
            def read(self, *args):
                data = self.stream.read(*args)
                external_reads.append(data)
                return data
        def old_open(path, *args, **kwargs):
            swap(path)
            stream = path_open(path, *args, **kwargs)  # ubs:ignore[python.lifecycle.file_handle] - the caller closes the returned stream or Spy via __exit__.
            return Spy(stream) if path == self.source else stream
        def new_open(path, *args, **kwargs):
            swap(path)
            return os_open(path, *args, **kwargs)
        with patch.object(Path, 'open', old_open), patch.object(daemon.os, 'open', new_open):
            self.assertIsNone(self.snapshot())
        self.assertTrue(changed[0])
        self.assertNotIn(b'PRIVATE', b''.join(external_reads))

    def test_fifo_swap_after_stat_cannot_block_snapshot(self):
        old_open, new_open = Path.open, os.open
        changed = [False]
        def swap(path):
            if os.fspath(path) in (str(self.source), self.source.name) and not changed[0]:
                changed[0] = True
                self.source.rename(self.work / 'original')
                os.mkfifo(self.source)
        def path_open(path, *args, **kwargs):
            swap(path)
            return old_open(path, *args, **kwargs)  # ubs:ignore[python.lifecycle.file_handle] - transfers the test stream to the caller's closing context.
        def os_open(path, *args, **kwargs):
            swap(path)
            return new_open(path, *args, **kwargs)
        def timeout(signum, frame):
            raise AssertionError('snapshot blocked on a file changed to a FIFO')
        previous = signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 1)
        try:
            with patch.object(Path, 'open', path_open), patch.object(daemon.os, 'open', os_open):
                self.assertIsNone(self.snapshot())
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertTrue(changed[0])

    def test_parent_symlink_swap_cannot_redirect_runtime_reads(self):
        nested = self.root / 'nested'
        nested.mkdir()
        source = nested / 'module.py'
        source.write_text('inside')
        outside = self.work / 'outside'
        outside.mkdir()
        (outside / 'module.py').write_text('PRIVATE')
        open_ = os.open
        changed = [False]
        def swap(path, flags, *args, **kwargs):
            if path == 'nested' and flags & os.O_DIRECTORY and not changed[0]:
                changed[0] = True
                nested.rename(self.work / 'old-nested')
                nested.symlink_to(outside, target_is_directory=True)
            return open_(path, flags, *args, **kwargs)
        with patch.object(daemon.os, 'open', swap):
            self.assertIsNone(self.snapshot())
        self.assertTrue(changed[0])

    def test_existing_external_configuration_and_symlinks_disable_reuse(self):
        for body in ('[include]\npath=/outside/config\n', '[core]\nexcludesFile=/outside/ignore\n'):
            (self.home / '.gitconfig').write_text(body)
            self.assertIsNone(self.snapshot())
        (self.home / '.gitconfig').rename(self.work / 'old-config')
        (self.root / 'alias').symlink_to(self.source)
        self.assertIsNone(self.snapshot())

    def test_limits_and_cancellation_still_refuse_reuse(self):
        with patch.object(daemon, 'MAX_SNAPSHOT', 1):
            self.assertIsNone(self.snapshot())
        for index in range(10):
            (self.root / str(index)).write_text('')
        with patch.object(daemon, 'MAX_SNAPSHOT_ENTRIES', 3):
            self.assertIsNone(self.snapshot())
        import threading
        stop = threading.Event()
        stop.set()
        with self.assertRaisesRegex(daemon.ServiceError, 'cancelled'):
            daemon.snapshot(self.root, self.scanner, cancel=stop)

    def test_installed_cache_appearance_changes_the_snapshot(self):
        data = self.work / 'runtime-data'
        with patch.dict(os.environ, {'XDG_DATA_HOME': str(data)}):
            before = self.snapshot()
            self.assertIsNotNone(before)
            cache = data / 'ubs/modules'
            cache.mkdir(parents=True)
            (cache / 'contract.json').write_text('{"revision": 1}\n')
            self.assertNotEqual(before, self.snapshot())

    def test_installed_cache_creation_during_snapshot_is_not_reusable(self):
        data = self.work / 'runtime-data'
        def publish():
            cache = data / 'ubs/modules'
            cache.mkdir(parents=True)
            (cache / 'contract.json').write_text('{"revision": 1}\n')
        with patch.dict(os.environ, {'XDG_DATA_HOME': str(data)}):
            a, b, fired = self.during_runtime_read(publish)
            with a, b:
                result = self.snapshot()
            self.assertTrue(fired[0])
            self.assertIsNone(result)
            self.assertIsNotNone(self.snapshot())

    def test_symlinked_installed_cache_disables_report_reuse(self):
        data = self.work / 'runtime-data'
        (data / 'ubs').mkdir(parents=True)
        outside = self.work / 'external-runtime'
        outside.mkdir()
        (outside / 'contract.json').write_text('{"revision": 1}\n')
        (data / 'ubs/modules').symlink_to(outside, target_is_directory=True)
        with patch.dict(os.environ, {'XDG_DATA_HOME': str(data)}):
            self.assertIsNone(self.snapshot())

    def test_external_helpers_override_disables_report_reuse(self):
        with patch.dict(os.environ, {'UBS_HELPERS_DIR': str(self.work / 'other-helpers')}):
            self.assertIsNone(self.snapshot())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor inventory')
    def test_repeated_snapshot_success_and_failure_do_not_leak_descriptors(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(10):
            self.assertIsNotNone(self.snapshot())
            with patch.object(daemon, 'MAX_SNAPSHOT', 1):
                self.assertIsNone(self.snapshot())
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


@unittest.skipUnless(os.name == 'posix', 'The local scan service requires POSIX')
class InstalledGenerationSnapshotTests(unittest.TestCase):
    """Real scanner processes through the service engine; no socket transport."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ubs-runtime-')
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name).resolve()
        self.root = self.work / 'project'
        self.root.mkdir()
        self.assertFalse(any((parent / '.git').exists() for parent in self.root.parents),
                         'Select a TMPDIR outside a Git worktree for report-cache tests')
        self.home = self.work / 'home'
        self.home.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('value = 1\n')
        bindir = self.work / 'bin'
        bindir.mkdir()
        self.scanner = bindir / 'ubs'
        shutil.copy2(ROOT / 'ubs', self.scanner)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'SCAN_'))}
        env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / '.config'),
                   XDG_DATA_HOME=str(self.work / 'data'), XDG_CACHE_HOME=str(self.work / 'cache'),
                   UBS_NO_AUTO_UPDATE='1', ENABLE_UV_TOOLS='0', PYTHONDONTWRITEBYTECODE='1')
        environment = patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.artifact = ROOT / 'test-suite/artifacts/daemon-installed-runtime' / self._testMethodName
        self.artifact.mkdir(parents=True, exist_ok=True)
        self.cache = self.work / 'data/ubs/modules'
        prepared = subprocess.run(
            [str(self.scanner), f'--prepare-release-cache={self.cache}',
             f'--release-source={ROOT / "modules"}'], cwd=self.root,
            capture_output=True, text=True, timeout=60)
        (self.artifact / 'prepare.stdout').write_text(prepared.stdout)
        (self.artifact / 'prepare.stderr').write_text(prepared.stderr)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        self.generation = Path(prepared.stdout.strip().splitlines()[-1])
        self.assertEqual(self.generation.parent, self.cache / '.ubs-releases')
        self.service = daemon.ScanService(self.root, self.scanner, 60, 32 * 1024 * 1024)

    def request(self, label):
        request = {'protocol': 1, 'op': 'scan', 'root': str(self.root), 'paths': ['a.py'],
                   'environment': daemon.environment_key(), 'scanner': str(self.scanner), 'format': 'json'}
        result = self.service.handle(request)
        (self.artifact / (label + '.json')).write_text(json.dumps(result, indent=2))
        return result

    def warm(self):
        cold = self.request('cold')
        self.assertEqual(cold['exit_code'], 0, cold)
        self.assertFalse(cold['cached'], cold)
        self.assertEqual(json.loads(cold['stdout'])['status'], 'ok', cold)
        warm = self.request('warm')
        self.assertTrue(warm['cached'], warm)
        for field in ('stdout', 'stderr', 'exit_code'):
            self.assertEqual(cold[field], warm[field])

    def assert_runtime_edit_invalidates(self, relative, contents):
        # An exported installation can retain adjacent source assets while
        # ordinary scans select a complete XDG generation. Both trees matter.
        shutil.copytree(ROOT / 'modules', self.scanner.parent / 'modules')
        self.warm()
        (self.generation / relative).write_bytes(contents)
        direct = subprocess.run(
            [str(self.scanner), '--ci', '--no-auto-update', '--format=json', str(self.source)],
            cwd=self.root, capture_output=True, text=True, timeout=60)
        (self.artifact / 'direct.stdout').write_text(direct.stdout)
        (self.artifact / 'direct.stderr').write_text(direct.stderr)
        self.assertEqual(direct.returncode, 2, direct.stdout + direct.stderr)
        result = self.request('after-runtime-edit')
        self.assertFalse(result['cached'], result)
        self.assertEqual(result['exit_code'], direct.returncode, result)
        self.assertIn('release assets could not be verified', result['stderr'], result)

    def test_xdg_only_installation_reuses_an_unchanged_real_report(self):
        self.assertFalse((self.scanner.parent / 'modules').exists())
        self.warm()

    def test_selected_generation_contract_edit_invalidates_a_cached_report(self):
        contract = (self.generation / 'contract.json').read_bytes()
        self.assert_runtime_edit_invalidates('contract.json', contract + b'\n')

    def test_selected_generation_ready_marker_edit_invalidates_a_cached_report(self):
        marker = (self.generation / '.ubs-ready.json').read_bytes()
        self.assert_runtime_edit_invalidates('.ubs-ready.json', marker + b'\n')

    def test_selected_generation_inventory_edit_invalidates_a_cached_report(self):
        self.assert_runtime_edit_invalidates('runtime-note.txt', b'ordinary cache metadata\n')


if __name__ == '__main__':
    unittest.main()
