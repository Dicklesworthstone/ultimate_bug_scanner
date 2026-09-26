"""Parallel native requests preserve isolation, bounded admission and fresh reuse."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch

import test_daemon as base

daemon = base.daemon


@unittest.skipUnless(os.name == 'posix', 'Parallel scans require Unix sockets')
class ParallelServiceTests(unittest.TestCase):
    setUp = base.ServiceTests.setUp
    start = base.ServiceTests.start
    request = base.ServiceTests.request
    cli = base.ServiceTests.cli

    def gated(self, jobs=2):
        self.gate = self.work / 'release'
        self.scanner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys, time
files = sys.argv[sys.argv.index('--') + 1:]
control = pathlib.Path(os.environ['SCAN_COUNT']).parent
name = pathlib.Path(files[0]).name
with open(os.environ['SCAN_COUNT'], 'a') as stream: stream.write(name + '\\n')
(control / (name + '.started')).write_text(str(os.getpid()))
if name == 'a.py':
    while not (control / 'release').exists(): time.sleep(0.01)
records = [(p, pathlib.Path(p).read_text()) for p in files]
print(json.dumps({'files': records, 'options': sys.argv[1:sys.argv.index('--')]}))
print(name, file=sys.stderr)
sys.exit(1 if any('BUG' in text for _, text in records) else 0)
''')
        self.process = self.start('--jobs=' + str(jobs))
        first = self.connect(self.request())
        self.wait_for(lambda: (self.work / 'a.py.started').exists(), 'first scanner')
        return first

    def connect(self, request):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.settimeout(5)
        connection.connect(str(daemon.socket_path(self.root)))
        daemon.send(connection, request)
        return connection

    def control(self, op='status'):
        return daemon.request_service(self.root, {'protocol': 1, 'root': str(self.root), 'op': op}, 1)

    def wait_for(self, predicate, label):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.01)
        self.fail('Timed out waiting for ' + label)

    def test_independent_scan_completes_while_first_is_blocked(self):
        first = self.gated()
        (self.root / 'b.py').write_text('BUG')
        second = daemon.request_service(self.root, self.request(['b.py']), 3)
        self.assertEqual(second['exit_code'], 1, second)
        self.assertEqual(json.loads(second['stdout'])['files'], [[str(self.root / 'b.py'), 'BUG']])
        self.assertEqual(second['stderr'], 'b.py\n')
        self.assertFalse(self.gate.exists())
        self.gate.touch()
        result = daemon.receive(first, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(result['stderr'], 'a.py\n')

    def test_duplicate_waiter_does_not_occupy_an_independent_worker(self):
        first = self.gated()
        duplicate = self.connect(self.request())
        self.wait_for(lambda: self.control()['queued_scans'] == 1, 'duplicate wait')
        self.assertEqual(self.control()['active_scans'], 1)
        (self.root / 'b.py').write_text('BUG')
        second = daemon.request_service(self.root, self.request(['b.py']), 3)
        self.assertEqual(second['exit_code'], 1, second)
        self.gate.touch()
        initial = daemon.receive(first, daemon.MAX_RESPONSE)
        repeated = daemon.receive(duplicate, daemon.MAX_RESPONSE)
        # Adding b.py changed the input graph during the first scan. The
        # waiter must validate the new graph, not blindly borrow that result.
        self.assertFalse(repeated['cached'])
        self.assertEqual(initial['stdout'], repeated['stdout'])
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text().splitlines(), ['a.py', 'b.py', 'a.py'])

    def test_identical_waiter_reuses_only_verified_unchanged_result(self):
        first = self.gated()
        duplicate = self.connect(self.request())
        self.wait_for(lambda: self.control()['queued_scans'] == 1, 'identical wait')
        self.gate.touch()
        initial = daemon.receive(first, daemon.MAX_RESPONSE)
        repeated = daemon.receive(duplicate, daemon.MAX_RESPONSE)
        self.assertFalse(initial['cached'])
        self.assertTrue(repeated['cached'])
        for field in ('exit_code', 'stdout', 'stderr'):
            self.assertEqual(initial[field], repeated[field])
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'a.py\n')

    def test_different_policy_is_not_coalesced_or_mixed(self):
        first = self.gated()
        other = self.connect(self.request(format='sarif', profile='strict'))
        self.wait_for(lambda: self.control()['active_scans'] == 2, 'two independent policies')
        self.gate.touch()
        initial = daemon.receive(first, daemon.MAX_RESPONSE)
        result = daemon.receive(other, daemon.MAX_RESPONSE)
        self.assertIn('--format=json', json.loads(initial['stdout'])['options'])
        self.assertIn('--format=sarif', json.loads(result['stdout'])['options'])
        self.assertIn('--profile=strict', json.loads(result['stdout'])['options'])
        self.assertFalse(result['cached'])

    def test_stop_cancels_all_workers_not_only_the_first(self):
        first = self.gated()
        second = self.connect(self.request(profile='loose'))
        self.wait_for(lambda: self.control()['active_scans'] == 2, 'two active workers')
        self.assertEqual(self.control('stop')['status'], 'stopping')
        for connection in (first, second):
            result = daemon.receive(connection, daemon.MAX_RESPONSE)
            self.assertEqual(result['exit_code'], 2, result)
            self.assertIn('cancelled', result['stderr'])
        self.process.wait(timeout=5)
        self.assertFalse(daemon.socket_path(self.root).exists())
        self.assertFalse(self.gate.exists())

    def test_parallel_half_close_still_delivers_complete_report(self):
        first = self.gated()
        first.shutdown(socket.SHUT_WR)
        (self.root / 'b.py').write_text('BUG')
        second = self.connect(self.request(['b.py']))
        second.shutdown(socket.SHUT_WR)
        result = daemon.receive(second, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 1, result)
        self.gate.touch()
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 0)

    def test_cache_accounting_after_simultaneous_completion_is_exact(self):
        barrier = threading.Barrier(4)
        request = self.request()
        native = daemon.run_scanner
        def synchronized(*args, **kwargs):
            barrier.wait(timeout=5)
            return native(*args, **kwargs)
        with patch.object(daemon, 'run_scanner', side_effect=synchronized):
            with ThreadPoolExecutor(max_workers=4) as workers:
                results = list(workers.map(lambda _: self.service.handle(request), range(4)))
        self.assertTrue(all(result['exit_code'] == 0 for result in results))
        self.assertEqual(self.service.cache_size, sum(size for _, size in self.service.cache.values()))
        self.assertLessEqual(self.service.cache_size, self.service.cache_bytes)
        self.assertEqual(len(self.service.cache), 1)

    def test_worker_count_is_bounded_and_defaults_to_one(self):
        self.start()
        self.assertEqual(self.control()['max_scans'], 1)
        for command, value in (('serve', 0), ('serve', 9), ('client', 2), ('status', 2)):
            with self.subTest(command=command, value=value):
                result = self.cli(command, '--jobs=' + str(value))
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_control_fields_are_not_silently_discarded(self):
        self.start()
        result = daemon.request_service(self.root, self.request(op='stop'), 3)
        self.assertEqual(result['exit_code'], 2, result)
        self.assertEqual(self.control()['status'], 'ready')


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for native parallel scans')
class RealParallelTests(unittest.TestCase):
    setUp = base.ServiceTests.setUp
    start = base.ServiceTests.start
    request = base.ServiceTests.request

    def test_parallel_native_findings_keep_file_and_policy_isolation(self):
        self.source.write_text('eval(input())\n')
        (self.root / 'b.py').write_text('value = 1\n')
        self.start('--jobs=2', scanner=base.ROOT / 'ubs')
        requests = [self.request([name], scanner=str(base.ROOT / 'ubs')) for name in ('a.py', 'b.py')]
        with ThreadPoolExecutor(max_workers=2) as clients:
            results = list(clients.map(lambda request: daemon.request_service(self.root, request, 130), requests))
        self.assertEqual([result['exit_code'] for result in results], [1, 0], results)
        findings = json.loads(results[0]['stdout'])['findings']
        self.assertTrue(any(f['rule_id'] == 'python.taint.eval' and f['line'] == 1
                            and Path(f['file']).name == 'a.py' for f in findings), findings)
        self.assertEqual(json.loads(results[1]['stdout']).get('findings', []), [])
        print('[daemon-parallel-native] independent unsafe/clean findings PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
