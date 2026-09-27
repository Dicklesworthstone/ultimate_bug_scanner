"""Cache-hit truthfulness under concurrent source, inventory and runtime edits."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
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
        self.work = Path(tmp.name)
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
            return original_path_open(path, *args, **kwargs)
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
            stream = path_open(path, *args, **kwargs)
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
            return old_open(path, *args, **kwargs)
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

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor inventory')
    def test_repeated_snapshot_success_and_failure_do_not_leak_descriptors(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(10):
            self.assertIsNotNone(self.snapshot())
            with patch.object(daemon, 'MAX_SNAPSHOT', 1):
                self.assertIsNone(self.snapshot())
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)


if __name__ == '__main__':
    unittest.main()
