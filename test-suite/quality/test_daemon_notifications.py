"""Real Linux notification coverage, hybrid reconciliation and watch integration."""
from __future__ import annotations

import ctypes
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / 'ubs-daemon'
loader = importlib.machinery.SourceFileLoader('ubs_daemon_notifications', str(DAEMON))
spec = importlib.util.spec_from_loader(loader.name, loader)
daemon = importlib.util.module_from_spec(spec)
loader.exec_module(daemon)
LINUX = sys.platform.startswith('linux')


class ObservationFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ubs-notify-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('clean\n')

    def observer(self, names=None, *, directories=(), dependencies=(), backend='inotify', reconcile=60):
        names = ['a.py'] if names is None else names
        observer = daemon.WatchObserver(
            lambda monitor: daemon.watch_inputs(self.root, names, directories=directories,
                                                dependencies=dependencies, monitor=monitor), backend, reconcile)
        self.addCleanup(observer.close)
        return observer


@unittest.skipUnless(LINUX, 'real inotify coverage requires Linux')
class NotificationTests(ObservationFixture, unittest.TestCase):
    def test_idle_reads_retain_observation_but_forced_reads_check_bytes(self):
        observer = self.observer()
        initial = observer.read()
        self.assertEqual(initial[1], [])
        self.assertGreaterEqual(len(observer.monitor.inodes), 2)
        self.assertFalse(os.get_inheritable(observer.monitor.fd))
        for _ in range(20):
            self.assertEqual(observer.read(), initial)
        self.assertEqual(observer.byte_passes, 1)
        self.assertEqual(observer.read(force=True), initial)
        self.assertEqual(observer.byte_passes, 2)

    def test_direct_write_chmod_atomic_replace_and_restored_mtime_trigger(self):
        observer = self.observer()
        previous, errors = observer.read()
        self.assertEqual(errors, [])
        for change in ('write', 'chmod', 'replace', 'restored-mtime'):
            with self.subTest(change=change):
                before = self.source.stat()
                if change == 'write':
                    self.source.write_text('BUG!!!')
                elif change == 'chmod':
                    self.source.chmod(0o600)
                elif change == 'replace':
                    replacement = self.work / 'replacement'
                    replacement.write_text('clean\n')
                    os.replace(replacement, self.source)
                else:
                    self.source.write_text('BUG!!!')
                    os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
                current, errors = observer.read()
                self.assertEqual(errors, [])
                self.assertNotEqual(current, previous)
                previous = current
        self.assertGreaterEqual(observer.event_batches, 4)

    def test_inode_mark_catches_write_through_external_hard_link(self):
        alias = self.work / 'outside-link'
        os.link(self.source, alias)
        observer = self.observer()
        first = observer.read()[0]
        alias.write_text('BUG through another directory')
        after, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)
        self.assertEqual(observer.byte_passes, 2)
        self.assertGreater(observer.event_batches, 0)

    def test_internal_symlink_retarget_is_observed_in_lexical_parent(self):
        targets = self.root / 'targets'
        targets.mkdir()
        (targets / 'first').write_text('clean')
        (targets / 'second').write_text('BUG')
        links = self.root / 'links'
        links.mkdir()
        link = links / 'alias.py'
        link.symlink_to('../targets/first')
        observer = self.observer(['links/alias.py'])
        first = observer.read()[0]
        link.rename(self.work / 'old-link')
        link.symlink_to('../targets/second')
        after, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)
        self.assertGreater(observer.event_batches, 0)
        (targets / 'second').write_text('another version')
        self.assertNotEqual(after, observer.read()[0])

    def test_missing_nested_policy_creation_arms_parent_chain(self):
        dependency = self.root / 'config'
        dependency.mkdir()
        observer = self.observer(dependencies=('config/new/policy',))
        first, errors = observer.read()
        self.assertEqual(errors, [])
        (dependency / 'new').mkdir()
        policy = dependency / 'new' / 'policy'
        policy.write_text('one')
        after, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)
        policy.write_text('two')
        self.assertNotEqual(after, observer.read()[0])
        self.assertGreaterEqual(observer.event_batches, 2)

    def test_moved_in_nested_tree_is_enumerated_and_subscribed(self):
        observer = self.observer([], directories=('.',))
        first = observer.read()[0]
        incoming = self.work / 'incoming'
        (incoming / 'nested').mkdir(parents=True)
        child = incoming / 'nested' / 'new.py'
        child.write_text('BUG')
        incoming.rename(self.root / 'received')
        after, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(first, after)
        nested = self.root / 'received' / 'nested'
        (nested / 'new.py').write_text('clean')
        edited = observer.read()[0]
        self.assertNotEqual(after, edited)
        nested.rename(self.root / 'renamed')
        renamed, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(edited, renamed)
        (self.root / 'renamed' / 'new.py').write_text('BUG again')
        self.assertNotEqual(renamed, observer.read()[0])

    def test_periodic_reconciliation_detects_changes_without_notifications(self):
        observer = self.observer(reconcile=0.1)
        original = observer.read()[0]
        self.source.write_text('BUG')
        with patch.object(observer.monitor, 'drain', return_value=(False, False)):
            self.assertEqual(observer.read()[0], original)
            time.sleep(0.12)
            current, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(current, original)
        self.assertEqual(observer.byte_passes, 2)

    def test_force_detects_a_silent_edit_before_reconciliation_deadline(self):
        observer = self.observer()
        before = observer.read()[0]
        self.source.write_text('BUG')
        with patch.object(observer.monitor, 'drain', return_value=(False, False)):
            self.assertNotEqual(observer.read(force=True)[0], before)
        self.assertEqual(observer.byte_passes, 2)

    def test_overflow_rebuilds_even_when_bytes_have_not_changed(self):
        observer = self.observer()
        original = observer.read()[0]
        old = observer.monitor
        overflow = struct.pack('iIII', -1, 0x4000, 0, 0)
        with patch.object(daemon.os, 'read', side_effect=[overflow, BlockingIOError()]):
            self.assertEqual(old.drain(), (True, True))
        with patch.object(old, 'drain', return_value=(True, True)):
            after, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertNotEqual(original, after)
        self.assertIsNone(old.fd)
        self.assertIsNot(observer.monitor, old)
        self.assertEqual(observer.resyncs, 1)
        self.assertEqual(observer.byte_passes, 2)

    def test_continuously_full_queue_has_a_bounded_drain(self):
        events = daemon.InotifyEvents()
        self.addCleanup(events.close)
        frame = struct.pack('iIII', 1, 0x2, 0, 0)
        with patch.object(events, 'MAX_DRAIN', len(frame) * 3), \
             patch.object(daemon.os, 'read', return_value=frame) as read:
            self.assertEqual(events.drain(), (True, True))
        self.assertEqual(read.call_count, 3)

    def test_malformed_notification_is_never_a_quiet_stream(self):
        for payload in (b'bad', struct.pack('iIII', 1, 0x2, 0, 900)):
            with self.subTest(payload=payload):
                monitor = daemon.InotifyEvents()
                self.addCleanup(monitor.close)
                with patch.object(daemon.os, 'read', return_value=payload), self.assertRaises(daemon.ServiceError):
                    monitor.drain()

    def test_edit_during_subscription_prevents_stable_observation(self):
        observer = self.observer()
        add = daemon.InotifyEvents.add
        edited = False
        def edit_after_arm(monitor, descriptor):
            nonlocal edited
            add(monitor, descriptor)
            info = os.fstat(descriptor)
            if info.st_ino == self.source.stat().st_ino and not edited:
                edited = True
                self.source.write_text('BUG during registration')
        with patch.object(daemon.InotifyEvents, 'add', edit_after_arm):
            _, errors = observer.read()
        self.assertTrue(edited)
        self.assertTrue(errors)
        self.assertEqual(observer.read()[1], [])

    def test_auto_watch_limit_falls_back_without_omitting_input(self):
        observer = self.observer(backend='auto')
        with patch.object(daemon.InotifyEvents, 'add', side_effect=daemon.NotificationError('watch quota')):
            before, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertEqual(observer.backend, 'poll')
        self.assertIn('watch quota', observer.reason)
        self.assertIsNone(observer.monitor)
        self.source.write_text('BUG')
        self.assertNotEqual(before, observer.read()[0])

    def test_explicit_inotify_fails_closed_on_watch_limit(self):
        observer = self.observer()
        with patch.object(daemon.InotifyEvents, 'add', side_effect=daemon.NotificationError('watch quota')):
            with self.assertRaisesRegex(daemon.ServiceError, 'watch quota'):
                observer.read()
        self.assertIsNone(observer.monitor)

    def test_invalid_graph_is_rechecked_not_reused_as_event_free(self):
        observer = self.observer()
        observer.read()
        self.source.rename(self.work / 'old.py')
        _, errors = observer.read()
        self.assertTrue(errors)
        passes = observer.byte_passes
        observer.read()
        self.assertGreater(observer.byte_passes, passes)
        self.source.write_text('clean restored')
        self.assertEqual(observer.read()[1], [])

    def test_rebuild_and_close_release_every_notification_descriptor(self):
        before = len(list(Path('/proc/self/fd').iterdir()))
        observer = self.observer()
        for _ in range(25):
            observer.read(force=True)
        self.assertLessEqual(len(list(Path('/proc/self/fd').iterdir())), before + 1)
        observer.close()
        observer.close()
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_native_wait_wakes_on_edit_without_consuming_notification(self):
        observer = self.observer()
        first = observer.read()[0]
        timer = threading.Timer(.1, lambda: self.source.write_text('BUG wakeup'))
        timer.start()
        self.addCleanup(timer.join)
        start = time.monotonic()
        observer.wait(3)
        self.assertLess(time.monotonic() - start, 1)
        self.assertNotEqual(first, observer.read()[0])

    def test_native_wait_cannot_sleep_past_reconciliation_deadline(self):
        observer = self.observer(reconcile=.1)
        observer.read()
        start = time.monotonic()
        observer.wait(3)
        self.assertLess(time.monotonic() - start, 1)
        observer.read()
        self.assertEqual(observer.byte_passes, 2)


class PortableBackendTests(ObservationFixture, unittest.TestCase):
    def test_poll_is_default_and_every_read_is_authoritative(self):
        reader = lambda monitor: daemon.watch_inputs(self.root, ['a.py'])
        observer = daemon.WatchObserver(reader)
        self.addCleanup(observer.close)
        observer.read()
        observer.read()
        self.assertEqual(observer.backend, 'poll')
        self.assertEqual(observer.byte_passes, 2)
        self.assertIsNone(observer.monitor)

    def test_auto_falls_back_when_notification_api_is_unavailable(self):
        observer = self.observer(backend='auto')
        with patch.object(daemon.sys, 'platform', 'darwin'):
            first, errors = observer.read()
        self.assertEqual(errors, [])
        self.assertEqual(observer.backend, 'poll')
        self.assertIn('Linux', observer.reason)
        self.source.write_text('BUG')
        self.assertNotEqual(first, observer.read()[0])

    def test_unknown_backend_and_nonfinite_reconciliation_are_rejected(self):
        for backend, reconcile in (('unknown', 5), ('poll', 0), ('auto', float('nan')),
                                   ('inotify', float('inf')), ('poll', 61)):
            with self.subTest(backend=backend, reconcile=reconcile), self.assertRaises(daemon.ServiceError):
                self.observer(backend=backend, reconcile=reconcile)


# Scanner protocol double: not a UBS detector. Captures input before waiting
# so obsolete success is observable unless the native watch discards it.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
targets = args[args.index('--') + 1:]
records = []
for target in targets:
    path = pathlib.Path(target)
    for source in sorted(path.rglob('*.py')) if path.is_dir() else [path]:
        records.append((str(source), source.read_text()))
with open(os.environ['SCAN_COUNT'], 'a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'records': records}) + '\n')
if any('SLOW' in text for _, text in records):
    time.sleep(30)
print(json.dumps({'files': records, 'args': args}))
print('scanner diagnostic', file=sys.stderr)
sys.exit(1 if any('BUG' in text for _, text in records) else 0)
'''


@unittest.skipUnless(LINUX, 'native watcher integration requires Linux')
class NativeWatchTests(ObservationFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.runtime = self.work / 'run'
        self.runtime.mkdir(mode=0o700)
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        (self.work / 'modules').mkdir()
        self.home = self.work / 'home'
        self.home.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'CLAUDE_', 'SCAN_'))}
        self.env.update(HOME=str(self.home), XDG_RUNTIME_DIR=str(self.runtime),
                        XDG_CACHE_HOME=str(self.work / 'cache'), SCAN_COUNT=str(self.work / 'scans'),
                        PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1')
        env = patch.dict(os.environ, self.env, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.events = []
        self.lines = queue.Queue()

    def process(self, command, *options, scanner=None, files=()):
        proc = subprocess.Popen([sys.executable, str(DAEMON), command, '--repo', str(self.root),
                                 '--scanner', str(scanner or self.scanner), *options, '--', *files],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdout.close()
            proc.stderr.close()
        self.addCleanup(cleanup)
        return proc

    def start_service(self, scanner=None):
        proc = self.process('serve', scanner=scanner)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                self.fail(proc.stderr.read())
            try:
                response = daemon.request_service(self.root, {'protocol': 1, 'op': 'status', 'root': str(self.root)}, .3)
                if response.get('status') == 'ready':
                    return proc
            except (OSError, daemon.ServiceError):
                pass
            time.sleep(.02)
        self.fail('service did not start')

    def start_watch(self, *options, scanner=None, files=('a.py',)):
        self.watcher = self.process('watch', '--watch-backend=inotify', '--watch-reconcile=60',
                                    '--watch-interval=0.1', '--debounce=0.2', *options,
                                    scanner=scanner, files=files)
        def read():
            for line in self.watcher.stdout:
                self.lines.put(line)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        # Terminate and join the reader before process cleanup closes pipes.
        def finish_reader():
            if self.watcher.poll() is None:
                self.watcher.terminate()
            self.watcher.wait(timeout=6)
            reader.join(timeout=1)
        self.addCleanup(finish_reader)
        return self.watcher

    def event(self, name, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                item = json.loads(self.lines.get(timeout=.1))
            except queue.Empty:
                if self.watcher.poll() is not None:
                    self.fail(f'watcher exited: {self.watcher.stderr.read()} {self.events}')
                continue
            self.events.append(item)
            self.assertEqual(item['schema'], 'ubs.watch/1')
            if item['event'] == name:
                return item
        self.fail(f'missing {name}: {self.events}')

    def scans(self, minimum=0):
        deadline = time.monotonic() + 3
        path = self.work / 'scans'
        while True:
            calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            if len(calls) >= minimum:
                return calls
            if time.monotonic() >= deadline:
                self.fail(f'expected {minimum} scanner processes: {calls}')
            time.sleep(.02)

    def test_native_feedback_preserves_policy_and_does_not_poll_bytes_when_idle(self):
        self.start_service()
        self.start_watch('--profile=strict', '--fail-on-warning', '--format=sarif')
        first = self.event('result')
        self.assertEqual(first['exit_code'], 0)
        self.assertEqual(first['observer']['backend'], 'inotify')
        args = json.loads(first['stdout'])['args']
        for flag in ('--profile=strict', '--fail-on-warning', '--format=sarif'):
            self.assertIn(flag, args)
        time.sleep(.7)
        self.source.write_text('BUG new generation')
        latest = self.event('result')
        self.assertEqual(latest['exit_code'], 1)
        self.assertEqual(latest['stderr'], 'scanner diagnostic\n')
        self.assertGreater(latest['generation'], first['generation'])
        # Change, dispatch and completion each reconcile, not every idle tick.
        self.assertLessEqual(latest['observer']['byte_passes'] - first['observer']['byte_passes'], 4)
        self.assertEqual(len(self.scans()), 2)

    def test_native_recursive_inventory_and_dependency_changes(self):
        self.start_service()
        self.start_watch(files=('.',))
        self.event('result')
        nested = self.root / 'src' / 'nested'
        nested.mkdir(parents=True)
        (nested / 'new.py').write_text('BUG')
        created = self.event('result')
        self.assertEqual(created['exit_code'], 1)
        self.assertEqual(created['paths'], ['.'])
        (nested / 'new.py').write_text('clean')
        self.assertEqual(self.event('result')['exit_code'], 0)
        (self.root / '.ubsignore').write_text('src/\n')
        policy = self.event('result')
        self.assertEqual(policy['exit_code'], 0)
        self.assertEqual(len(self.scans()), 4)

    def test_native_events_cancel_obsolete_scanner_before_slow_result(self):
        self.source.write_text('SLOW clean')
        server = self.start_service()
        self.start_watch()
        self.event('scanning')
        old = self.scans(1)[0]
        self.source.write_text('BUG current')
        latest = self.event('result')
        self.assertEqual(latest['exit_code'], 1)
        self.assertEqual(len([item for item in self.events if item['event'] == 'result']), 1)
        self.assertTrue(any(item['event'] == 'superseded' for item in self.events))
        with self.assertRaises(ProcessLookupError):
            os.kill(old['pid'], 0)
        self.assertIsNone(server.poll())

    def test_invalid_source_does_not_disable_watch_and_restoration_resumes(self):
        self.start_service()
        self.start_watch()
        self.event('result')
        self.source.rename(self.work / 'old.py')
        self.assertEqual(self.event('invalid')['exit_code'], 2)
        self.assertEqual(len(self.scans()), 1)
        self.source.write_text('BUG restored')
        self.assertEqual(self.event('result')['exit_code'], 1)
        self.assertEqual(len(self.scans()), 2)

    def test_native_options_reject_lifecycle_use_and_invalid_intervals(self):
        for command in ('serve', 'client', 'status', 'stop'):
            for flag in ('--watch-backend=auto', '--watch-reconcile=5'):
                proc = self.process(command, flag)
                proc.wait(timeout=3)
                self.assertEqual(proc.returncode, 2, proc.stderr.read())
        for value in ('0', '-1', 'nan', 'inf', '61'):
            proc = self.process('watch', '--watch-reconcile=' + value, files=('a.py',))
            proc.wait(timeout=3)
            self.assertEqual(proc.returncode, 2, proc.stderr.read())
        self.assertEqual(self.scans(), [])

    @unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'requires complete UBS runtime and tools')
    def test_actual_scanner_native_watch_detects_eval_after_edit(self):
        self.source.write_text('value = 1\n')
        self.start_service(scanner=ROOT / 'ubs')
        self.start_watch(scanner=ROOT / 'ubs')
        self.assertEqual(self.event('result', timeout=150)['exit_code'], 0)
        self.source.write_text('eval(input())\n')
        result = self.event('result', timeout=150)
        self.assertEqual(result['exit_code'], 1, result)
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval'
                            for item in json.loads(result['stdout'])['findings']))


if __name__ == '__main__':
    unittest.main()
