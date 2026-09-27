"""Foreground watch generations, cancellation and bounded client transport."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from test_daemon_selection import DAEMON, ROOT, SelectionFixture, daemon

# Protocol double: snapshots source BEFORE sleeping, so stale success is a
# real threat unless the watch controller cancels/discards that generation.
WATCH_SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
files = args[args.index('--') + 1:]
records = [(p, pathlib.Path(p).read_text()) for p in files]
with open(os.environ['SCAN_COUNT'], 'a') as out:
    out.write(json.dumps({'pid': os.getpid(), 'records': records}) + '\n')
if any('SLOW' in text for _, text in records):
    time.sleep(30)
elif any('DELAY' in text for _, text in records):
    time.sleep(0.6)
code = 1 if any('BUG' in text for _, text in records) else 0
print(json.dumps({'files': records, 'args': args}))
print('scanner diagnostics', file=sys.stderr)
sys.exit(code)
'''


class WatchFixture(SelectionFixture):
    def setUp(self):
        super().setUp()
        self.scanner.write_text(WATCH_SCANNER)
        self.events = []
        self.lines = queue.Queue()

    def start_watch(self, *extra, scanner=None, files=None):
        process = subprocess.Popen(
            [sys.executable, str(DAEMON), 'watch', '--repo', str(self.root),
             '--scanner', str(scanner or self.scanner), '--watch-interval=0.1', '--debounce=0.2',
             *extra, '--', *(files or ['a.py'])], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        def read():
            for line in process.stdout:
                self.lines.put(line)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        def finish():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            reader.join(timeout=1)
            process.stdout.close()
            process.stderr.close()
        self.addCleanup(finish)
        self.watcher = process
        return process

    def event(self, wanted, predicate=lambda _: True, timeout=10):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                line = self.lines.get(timeout=0.1)
            except queue.Empty:
                if self.watcher.poll() is not None:
                    self.fail(f'watch exited {self.watcher.returncode}: {self.watcher.stderr.read()}\n{self.events}')
                continue
            value = json.loads(line)
            self.assertEqual(value['schema'], 'ubs.watch/1')
            self.events.append(value)
            if value['event'] == wanted and predicate(value):
                return value
        self.fail(f'timed out awaiting {wanted}: {self.events}')

    def calls(self):
        path = Path(self.env['SCAN_COUNT'])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def await_calls(self, count):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            calls = self.calls()
            if len(calls) >= count:
                return calls
            time.sleep(0.02)
        self.fail(f'expected {count} scanner calls, got {self.calls()}')


@unittest.skipUnless(os.name == 'posix', 'watch uses Unix service')
class WatchTests(WatchFixture, unittest.TestCase):
    def test_initial_and_edited_results_are_separate_generations(self):
        self.start()
        self.start_watch('--profile=strict', '--fail-on-warning', '--format=sarif')
        first = self.event('result')
        self.assertEqual(first['exit_code'], 0)
        self.assertEqual(first['stderr'], 'scanner diagnostics\n')
        args = json.loads(first['stdout'])['args']
        for flag in ('--profile=strict', '--fail-on-warning', '--format=sarif'):
            self.assertIn(flag, args)
        self.source.write_text('BUG\n')
        changed = self.event('changed')
        second = self.event('result')
        self.assertEqual(second['exit_code'], 1)
        self.assertEqual(second['generation'], changed['generation'])
        self.assertGreater(second['generation'], first['generation'])
        self.assertNotEqual(second['source_fingerprint'], first['source_fingerprint'])
        self.assertEqual(json.loads(second['stdout'])['files'][0][1], 'BUG\n')
        time.sleep(0.5)
        self.assertEqual(len(self.calls()), 2)  # No polling-triggered scan storm.

    def test_burst_is_debounced_to_one_scan_of_final_bytes(self):
        self.start()
        self.start_watch('--debounce=0.5')
        self.event('result')
        for text in ('first', 'second', 'BUG final'):
            self.source.write_text(text)
            time.sleep(0.14)
        last = self.event('result')
        self.assertEqual(last['exit_code'], 1)
        self.assertEqual(json.loads(last['stdout'])['files'][0][1], 'BUG final')
        self.assertEqual(len(self.calls()), 2)

    def test_superseded_slow_scan_is_cancelled_not_published(self):
        self.source.write_text('SLOW clean\n')
        self.start()
        self.start_watch()
        old = self.event('scanning')
        calls = self.await_calls(1)
        self.source.write_text('BUG newest\n')
        newest = self.event('result', timeout=6)
        self.assertGreater(newest['generation'], old['generation'])
        self.assertEqual(newest['exit_code'], 1)
        self.assertTrue(any(item['event'] == 'superseded' for item in self.events))
        self.assertEqual([item['generation'] for item in self.events if item['event'] == 'result'], [newest['generation']])
        with self.assertRaises(ProcessLookupError):
            os.kill(calls[0]['pid'], 0)
        self.assertEqual(len(self.calls()), 2)

    def test_atomic_save_and_restored_mtime_still_trigger(self):
        self.source.write_text('clean')
        self.start()
        self.start_watch()
        self.event('result')
        stamp = self.source.stat()
        self.source.write_text('BUG!!')
        os.utime(self.source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertEqual(self.event('result')['exit_code'], 1)
        replacement = self.work / 'saved.py'
        replacement.write_text('clean')
        os.replace(replacement, self.source)
        self.assertEqual(self.event('result')['exit_code'], 0)
        self.assertEqual(len(self.calls()), 3)

    def test_disappearing_source_invalidates_and_recreation_resumes(self):
        self.start()
        self.start_watch()
        self.event('result')
        self.source.rename(self.work / 'old.py')
        invalid = self.event('invalid')
        self.assertEqual(invalid['exit_code'], 2)
        self.assertEqual(invalid['stdout'], '')
        self.assertEqual(len(self.calls()), 1)
        self.source.write_text('BUG restored\n')
        self.assertEqual(self.event('result')['exit_code'], 1)

    def test_fifo_and_escaping_symlink_are_visible_invalid_states(self):
        self.start()
        self.start_watch()
        self.event('result')
        self.source.rename(self.work / 'original.py')
        os.mkfifo(self.source)
        invalid = self.event('invalid', timeout=4)
        self.assertIn('not a regular file', invalid['stderr'])
        self.source.rename(self.work / 'fifo')
        outside = self.work / 'outside.py'
        outside.write_text('BUG private\n')
        self.source.symlink_to(outside)
        invalid = self.event('invalid')
        self.assertIn('outside', invalid['stderr'])
        self.assertNotIn('private', invalid['stderr'])
        self.assertEqual(len(self.calls()), 1)
        self.source.rename(self.work / 'escape-link')
        self.source.symlink_to('a.py')
        invalid = self.event('invalid')
        self.assertEqual(invalid['exit_code'], 2)
        self.assertEqual(len(self.calls()), 1)

    def test_termination_cancels_own_scan_without_stopping_daemon(self):
        self.source.write_text('SLOW\n')
        server = self.start()
        watcher = self.start_watch()
        self.event('scanning')
        calls = self.await_calls(1)
        watcher.terminate()
        watcher.wait(timeout=6)
        self.assertEqual(watcher.returncode, 130)
        self.assertIsNone(server.poll())
        until = time.monotonic() + 3
        while time.monotonic() < until:
            try:
                os.kill(calls[0]['pid'], 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            self.fail('watch scan survived watch termination')
        self.assertEqual(self.cli('status').returncode, 0)

    def test_unsafe_or_absent_service_never_falls_back(self):
        result = self.cli('watch', 'a.py')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())
        path = daemon.socket_path(self.root, create=True)
        path.write_text('not a socket')
        result = self.cli('watch', 'a.py')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unsafe', result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_environment_mismatch_exits_as_error_not_fallback(self):
        self.start()
        self.env['UBS_PROFILE'] = 'strict'
        watcher = self.start_watch()
        error = self.event('error')
        self.assertEqual(error['exit_code'], 2)
        self.assertIn('environment', error['stderr'])
        watcher.wait(timeout=5)
        self.assertEqual(watcher.returncode, 2)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_watch_rejects_unbounded_or_ambiguous_scope_and_options(self):
        for arguments in ((), ('.',), ('--staged',), ('--diff',), ('--request-id=x', 'a.py'),
                          ('--watch-interval=0', 'a.py'), ('--debounce=nan', 'a.py'),
                          ('--watch-interval=inf', 'a.py'), ('--debounce=-1', 'a.py')):
            result = self.cli('watch', *arguments)
            self.assertEqual(result.returncode, 2, (arguments, result.stderr))
        for command in ('client', 'serve', 'status', 'stop'):
            result = self.cli(command, '--debounce=0.5')
            self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_all_explicit_paths_are_watched_without_shell_splitting(self):
        names = ['a.py', 'has space.py', 'line\nbreak.py', '--diff.py']
        for name in names:
            (self.root / name).write_text('clean\n')
        self.start()
        self.start_watch(files=names)
        first = self.event('result')
        self.assertEqual(first['paths'], names)
        self.assertEqual(len(json.loads(first['stdout'])['files']), 4)
        (self.root / names[-1]).write_text('BUG\n')
        self.assertEqual(self.event('result')['exit_code'], 1)

    def test_watch_inputs_are_byte_bounded_and_do_not_equate_error_to_clean(self):
        clean, errors = daemon.watch_inputs(self.root, ['a.py'])
        self.assertFalse(errors)
        with patch.object(daemon, 'MAX_SNAPSHOT', 1):
            invalid, errors = daemon.watch_inputs(self.root, ['a.py'])
        self.assertTrue(errors)
        self.assertNotEqual(clean, invalid)
        self.assertIn('byte limit', errors[0])

    def test_final_observation_discards_a_completion_race(self):
        # Deterministic boundary control, in addition to real-process edits.
        from concurrent.futures import Future
        completed = Future()
        completed.set_result({'protocol': 1, 'exit_code': 0, 'stdout': 'OLD', 'stderr': ''})
        statuses = {'protocol': 1, 'root': str(self.root), 'status': 'ready'}
        with patch.object(daemon, 'request_service', return_value=statuses), \
             patch.object(daemon, 'ThreadPoolExecutor') as pool, \
             patch.object(daemon, 'watch_inputs', side_effect=[('a', []), ('a', []), ('b', []), KeyboardInterrupt]), \
             patch.object(daemon.time, 'sleep'), patch('builtins.print') as output:
            pool.return_value.submit.return_value = completed
            with self.assertRaises(KeyboardInterrupt):
                daemon.watch(self.root, self.request(), 10, 0.1, 0)
        events = [json.loads(call.args[0]) for call in output.call_args_list]
        self.assertFalse(any(event['event'] == 'result' for event in events), events)
        self.assertTrue(any(event['event'] == 'superseded' for event in events), events)

    def test_transport_failure_still_cancels_remote_work(self):
        from concurrent.futures import Future
        completed = Future()
        completed.set_exception(daemon.ServiceError('Service request timed out'))
        statuses = {'protocol': 1, 'root': str(self.root), 'status': 'ready'}
        with patch.object(daemon, 'request_service', return_value=statuses), \
             patch.object(daemon, 'ThreadPoolExecutor') as pool, \
             patch.object(daemon, 'watch_inputs', return_value=('a', [])), \
             patch.object(daemon, 'cancel_watch_request', return_value=True) as cancel, \
             patch.object(daemon.time, 'sleep'), patch('builtins.print') as output:
            pool.return_value.submit.return_value = completed
            self.assertEqual(daemon.watch(self.root, self.request(), 10, 0.1, 0), 2)
        cancel.assert_called_once()
        self.assertEqual(cancel.call_args.args[0], self.root)
        self.assertTrue(cancel.call_args.args[1].startswith('watch-'))
        events = [json.loads(call.args[0]) for call in output.call_args_list]
        self.assertEqual(events[-1]['event'], 'error')
        self.assertFalse(any(event['event'] == 'result' for event in events))


@unittest.skipUnless(os.name == 'posix', 'Unix sockets')
class ClientDeadlineTests(SelectionFixture, unittest.TestCase):
    def peer(self, handler):
        path = daemon.socket_path(self.root, create=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        stop = threading.Event()
        def run():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    daemon.receive(connection, daemon.MAX_REQUEST)
                    handler(connection, stop)
            except (OSError, daemon.ServiceError):
                pass
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        def finish():
            stop.set()
            listener.close()
            thread.join(timeout=2)
        self.addCleanup(finish)
        return stop

    def test_trickling_response_cannot_extend_absolute_deadline(self):
        def trickle(connection, stop):
            frame = daemon.encode_message({'protocol': 1, 'exit_code': 0, 'stdout': 'ok', 'stderr': ''})
            for byte in frame:
                if stop.wait(0.08):
                    break
                connection.sendall(bytes([byte]))
        self.peer(trickle)
        started = time.monotonic()
        with self.assertRaisesRegex(daemon.ServiceError, 'timed out'):
            daemon.request_service(self.root, self.request(), 0.3)
        self.assertLess(time.monotonic() - started, 1)

    def test_pending_receive_can_be_interrupted(self):
        self.peer(lambda connection, stop: stop.wait(3))
        cancel = threading.Event()
        timer = threading.Timer(0.15, cancel.set)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        with self.assertRaisesRegex(daemon.ServiceError, 'cancelled'):
            daemon.request_service(self.root, self.request(), 30, cancel=cancel)
        self.assertLess(time.monotonic() - started, 1)

    def test_split_framing_and_large_streams_are_preserved(self):
        response = {'protocol': 1, 'exit_code': 1, 'stdout': 'α\n' * 70000, 'stderr': 'diagnostic'}
        def split(connection, stop):
            frame = daemon.encode_message(response)
            for begin in range(0, len(frame), 127):
                connection.sendall(frame[begin:begin + 127])
        self.peer(split)
        self.assertEqual(daemon.request_service(self.root, self.request(), 5), response)

    def test_oversized_frame_is_rejected_before_allocating_body(self):
        self.peer(lambda connection, stop: connection.sendall(struct.pack('!I', daemon.MAX_RESPONSE + 1)))
        with self.assertRaisesRegex(daemon.ServiceError, 'permitted size'):
            daemon.request_service(self.root, self.request(), 2)

    def test_boolean_protocol_is_not_a_valid_version(self):
        self.peer(lambda connection, stop: daemon.send(connection, {'protocol': True, 'exit_code': 0}))
        with self.assertRaisesRegex(daemon.ServiceError, 'protocol|response'):
            daemon.request_service(self.root, self.request(), 2)

    def test_already_completed_cancel_is_typed_and_never_clean(self):
        self.start()
        response = daemon.request_service(self.root, {'protocol': 1, 'op': 'cancel',
                                          'root': str(self.root), 'request_id': 'not-outstanding'}, 3)
        self.assertEqual(response['exit_code'], 2)
        self.assertEqual(response['error'], 'request_not_active')
        self.assertFalse(daemon.cancel_watch_request(self.root, 'not-outstanding'))


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for the actual scanner')
class RealWatchTests(WatchFixture, unittest.TestCase):
    def test_real_detector_reports_follow_edits_without_stale_success(self):
        self.source.write_text('value = 1\n')
        self.start(scanner=ROOT / 'ubs')
        self.start_watch(scanner=ROOT / 'ubs')
        first = self.event('result', timeout=150)
        self.assertEqual(first['exit_code'], 0, first)
        self.source.write_text('eval(input())\n')
        second = self.event('result', timeout=150)
        self.assertEqual(second['exit_code'], 1, second)
        report = json.loads(second['stdout'])
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval' for item in report['findings']), report)
        self.assertGreater(second['generation'], first['generation'])
        self.source.write_text('value = 2\n')
        self.assertEqual(self.event('result', timeout=150)['exit_code'], 0)


if __name__ == '__main__':
    unittest.main()
