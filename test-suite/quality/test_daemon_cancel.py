"""Cancel one queued/running request without stopping other agents' scans."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

import test_daemon as base

daemon = base.daemon


@unittest.skipUnless(os.name == 'posix', 'Cancellation requires Unix sockets')
class RequestCancellationTests(unittest.TestCase):
    start = base.ServiceTests.start
    request = base.ServiceTests.request
    cli = base.ServiceTests.cli

    def setUp(self):
        base.ServiceTests.setUp(self)
        (self.root / 'b.py').write_text('BUG')
        self.scanner.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys, time
files = sys.argv[sys.argv.index('--') + 1:]
control = pathlib.Path(os.environ['SCAN_COUNT']).parent
name = pathlib.Path(files[0]).name
with open(os.environ['SCAN_COUNT'], 'a') as stream: stream.write(name + '\\n')
(control / (name + '.started')).write_text(str(os.getpid()))
while not (control / (name + '.release')).exists(): time.sleep(0.01)
records = [(p, pathlib.Path(p).read_text()) for p in files]
print(json.dumps({'files': records}))
sys.exit(1 if any('BUG' in text for _, text in records) else 0)
''')

    def connect(self, name='a.py', request_id='first'):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.settimeout(5)
        connection.connect(str(daemon.socket_path(self.root)))
        daemon.send(connection, self.request([name], request_id=request_id))
        return connection

    def control(self, **updates):
        request = {'protocol': 1, 'op': 'status', 'root': str(self.root)}
        request.update(updates)
        return daemon.request_service(self.root, request, 2)

    def cancel(self, request_id, **updates):
        return self.control(op='cancel', request_id=request_id, **updates)

    def wait_for(self, predicate, label):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.01)
        self.fail('Timed out waiting for ' + label)

    def started(self, name='a.py'):
        self.wait_for(lambda: (self.work / (name + '.started')).exists(), name + ' startup')

    def release(self, name='a.py'):
        (self.work / (name + '.release')).touch()

    def test_running_cancellation_leaves_independent_scan_active(self):
        self.start('--jobs=2')
        first, second = self.connect(), self.connect('b.py', 'second')
        self.started()
        self.started('b.py')
        pid = int((self.work / 'a.py.started').read_text())
        result = self.cancel('first')
        self.assertEqual(result['status'], 'cancelling', result)
        self.assertEqual(result['request_id'], 'first')
        result = daemon.receive(first, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 2, result)
        self.assertIn('cancelled', result['stderr'])
        self.assertEqual(result['stdout'], '')
        self.wait_for(lambda: self.control()['active_scans'] == 1, 'only surviving worker')
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.release('b.py')
        result = daemon.receive(second, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 1, result)
        self.assertEqual(self.control()['status'], 'ready')

    def test_queued_cancellation_never_starts_the_target(self):
        self.start()
        first = self.connect()
        self.started()
        queued = self.connect('b.py', 'waiting')
        self.wait_for(lambda: self.control()['queued_scans'] == 1, 'queued target')
        self.assertEqual(self.cancel('waiting')['status'], 'cancelling')
        result = daemon.receive(queued, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 2, result)
        self.release()
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 0)
        self.assertFalse((self.work / 'b.py.started').exists())
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'a.py\n')

    def test_cancelled_work_does_not_supply_a_cached_clean_result(self):
        self.start()
        first = self.connect()
        self.started()
        self.assertEqual(self.cancel('first')['status'], 'cancelling')
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 2)
        self.release()
        second = self.connect(request_id='retry')
        result = daemon.receive(second, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertFalse(result['cached'])
        third = self.connect(request_id='verified-hit')
        self.assertTrue(daemon.receive(third, daemon.MAX_RESPONSE)['cached'])
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'a.py\na.py\n')

    def test_duplicate_id_cannot_cancel_or_replace_an_existing_request(self):
        self.start('--jobs=2')
        first = self.connect()
        self.started()
        impostor = self.connect('b.py', 'first')
        result = daemon.receive(impostor, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 2, result)
        self.assertIn('already in use', result['stderr'])
        self.assertFalse((self.work / 'b.py.started').exists())
        self.release()
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 0)

    def test_cancellation_rejects_wrong_root_protocol_and_extra_policy(self):
        self.start()
        first = self.connect()
        self.started()
        for updates in ({'root': str(self.work)}, {'protocol': True}, {'protocol': 999},
                        {'paths': ['a.py']}, {'profile': 'strict'}):
            with self.subTest(updates=updates):
                self.assertEqual(self.cancel('first', **updates)['exit_code'], 2)
        self.assertEqual(self.control()['active_scans'], 1)
        self.release()
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 0)

    def test_invalid_ids_and_unknown_targets_are_errors(self):
        self.start()
        for request_id in ('', 'contains space', 'a\n', '../first', [], None, 'x' * 65):
            with self.subTest(request_id=request_id):
                self.assertEqual(self.cancel(request_id)['exit_code'], 2)
        self.assertEqual(self.cancel('unknown')['exit_code'], 2)
        self.assertEqual(self.control()['status'], 'ready')
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_cli_cancel_works_after_request_write_half_close(self):
        self.start()
        first = self.connect(request_id='edit-42')
        first.shutdown(socket.SHUT_WR)
        self.started()
        result = self.cli('cancel', '--request-id=edit-42')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'cancelling')
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 2)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_named_cli_client_reports_cancellation_as_scan_failure(self):
        self.start()
        client = subprocess.Popen([sys.executable, str(base.DAEMON), 'client', '--repo', str(self.root),
                                   '--scanner', str(self.scanner), '--require-daemon', '--request-id=cli-edit', 'a.py'],
                                  env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if client.poll() is None:
                client.terminate()
            client.communicate(timeout=5)
        self.addCleanup(cleanup)
        self.started()
        result = self.cli('cancel', '--request-id=cli-edit')
        self.assertEqual(result.returncode, 0, result.stderr)
        stdout, stderr = client.communicate(timeout=5)
        self.assertEqual(client.returncode, 2)
        self.assertEqual(stdout, '')
        self.assertIn('cancelled', stderr)

    def test_cancelled_identical_owner_does_not_cancel_its_waiter(self):
        self.start('--jobs=2')
        first = self.connect()
        self.started()
        waiter = self.connect(request_id='second')
        self.wait_for(lambda: self.control()['queued_scans'] == 1, 'identical waiter')
        self.assertEqual(self.cancel('first')['status'], 'cancelling')
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 2)
        self.wait_for(lambda: Path(self.env['SCAN_COUNT']).read_text().splitlines() == ['a.py', 'a.py'], 'waiter scan')
        self.release()
        result = daemon.receive(waiter, daemon.MAX_RESPONSE)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertFalse(result['cached'])

    def test_completed_id_does_not_cancel_a_later_unrelated_scan(self):
        self.start()
        self.release()
        first = self.connect()
        self.assertEqual(daemon.receive(first, daemon.MAX_RESPONSE)['exit_code'], 0)
        second = self.connect('b.py', 'second')
        self.started('b.py')
        self.assertEqual(self.cancel('first')['exit_code'], 2)
        self.release('b.py')
        self.assertEqual(daemon.receive(second, daemon.MAX_RESPONSE)['exit_code'], 1)

    def test_cancel_cannot_fall_back_to_one_shot_scanning(self):
        result = self.cli('cancel', '--request-id=absent')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())
        for command, args in (('cancel', []), ('status', ['--request-id=x']),
                              ('serve', ['--request-id=x']), ('cancel', ['--request-id=x', 'a.py'])):
            with self.subTest(command=command, args=args):
                self.assertEqual(self.cli(command, *args).returncode, 2)


if __name__ == '__main__':
    unittest.main()
