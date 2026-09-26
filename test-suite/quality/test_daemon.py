"""K4 Unix transport, cache correctness, and actual one-shot parity tests."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / 'ubs-daemon'
loader = importlib.machinery.SourceFileLoader('ubs_daemon', str(DAEMON))
spec = importlib.util.spec_from_loader(loader.name, loader)
daemon = importlib.util.module_from_spec(spec)
loader.exec_module(daemon)

# Deliberately a protocol double; real scanner cases are in RealScannerTests.
SCANNER = '''#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
files = args[args.index('--') + 1:]
with open(os.environ['SCAN_COUNT'], 'a') as out: out.write('scan\\n')
if os.environ.get('SCAN_SLEEP'): time.sleep(float(os.environ['SCAN_SLEEP']))
records = [(p, pathlib.Path(p).read_text()) for p in files]
code = 1 if any('BUG' in text for _, text in records) else 0
if os.environ.get('SCAN_ERROR'): code = 2
print(json.dumps({'files': records, 'args': args, 'cwd': os.getcwd()}))
print('scanner diagnostics', file=sys.stderr)
sys.exit(code)
'''


@unittest.skipUnless(os.name == 'posix', 'Unix sockets and uid authentication require POSIX')
class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ubs-d-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.runtime = self.work / 'run'
        self.runtime.mkdir(mode=0o700)
        self.home = self.work / 'home'
        self.home.mkdir()
        self.scanner = self.work / 'scanner'
        self.scanner.write_text(SCANNER)
        self.scanner.chmod(0o755)
        (self.work / 'modules').mkdir()
        self.source = self.root / 'a.py'
        self.source.write_text('clean')
        self.env = dict(os.environ, XDG_RUNTIME_DIR=str(self.runtime), HOME=str(self.home),
                        XDG_CONFIG_HOME=str(self.home / '.config'), XDG_CACHE_HOME=str(self.work / 'cache'),
                        SCAN_COUNT=str(self.work / 'count'), PYTHONDONTWRITEBYTECODE='1')
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.service = daemon.ScanService(self.root, self.scanner, 10, 1024 * 1024)

    def request(self, paths=None, **updates):
        value = {'protocol': 1, 'op': 'scan', 'root': str(self.root), 'scanner': str(self.scanner),
                 'environment': daemon.environment_key(), 'paths': ['a.py'] if paths is None else paths, 'format': 'json'}
        value.update(updates)
        return value

    def start(self, *extra, scanner=None):
        process = subprocess.Popen([sys.executable, str(DAEMON), 'serve', '--repo', str(self.root),
                                    '--scanner', str(scanner or self.scanner), *extra],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        self.addCleanup(cleanup)
        until = time.monotonic() + 10
        while time.monotonic() < until:
            if process.poll() is not None:
                self.fail('Daemon startup failed: ' + process.communicate()[1])
            try:
                result = daemon.request_service(self.root, {'protocol': 1, 'root': str(self.root), 'op': 'status'}, 1)
                if result.get('status') == 'ready':
                    return process
            except (OSError, daemon.ServiceError):
                pass
            time.sleep(0.02)
        self.fail('Daemon failed to become ready')

    def cli(self, command='client', *extra, scanner=None, env=None):
        return subprocess.run([sys.executable, str(DAEMON), command, '--repo', str(self.root),
                               '--scanner', str(scanner or self.scanner), *extra],
                              env=env or self.env, capture_output=True, text=True, timeout=60)

    def test_socket_permissions_and_peer_identity(self):
        self.start()
        path = daemon.socket_path(self.root)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(path))
            self.assertEqual(daemon.peer_uid(client), os.getuid())

    def test_rejects_outside_paths_and_symlink_escapes(self):
        outside = self.work / 'outside.py'
        outside.write_text('BUG')
        (self.root / 'escape.py').symlink_to(outside)
        for paths in ([str(outside)], ['../outside.py'], ['escape.py'], ['.']):
            with self.subTest(paths=paths), self.assertRaises(daemon.ServiceError):
                self.service.handle(self.request(paths))
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_invalid_request_does_not_crash_daemon(self):
        self.start()
        for update in ({'op': []}, {'protocol': True}, {'paths': []}, {'format': []},
                       {'paths': ['\0']}, {'fail_on_warning': 1}, {'args': ['--update']}):
            with self.subTest(update=update):
                result = daemon.request_service(self.root, self.request(**update), 3)
                self.assertEqual(result['exit_code'], 2)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_framing_is_bounded_and_rejects_partial_messages(self):
        self.start()
        for body in (struct.pack('!I', daemon.MAX_REQUEST + 1), struct.pack('!I', 3) + b'{'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(4)
                client.connect(str(daemon.socket_path(self.root)))
                client.sendall(body)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(daemon.receive(client, daemon.MAX_RESPONSE)['exit_code'], 2)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_second_daemon_cannot_steal_live_socket(self):
        process = self.start()
        second = self.cli('serve', '--idle-timeout', '0.1')
        self.assertEqual(second.returncode, 2)
        self.assertIsNone(process.poll())
        self.assertEqual(self.cli('status').returncode, 0)

    def test_non_socket_and_unsafe_directory_are_not_overwritten(self):
        path = daemon.socket_path(self.root, create=True)
        path.write_text('preserve me')
        self.assertEqual(self.cli('serve').returncode, 2)
        self.assertEqual(path.read_text(), 'preserve me')
        path.parent.chmod(0o777)
        self.assertEqual(self.cli('status').returncode, 2)

    def test_stale_socket_is_recovered_under_lock(self):
        path = daemon.socket_path(self.root, create=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            stale.bind(str(path))
        self.start()
        self.assertEqual(self.cli('status').returncode, 0)

    def test_idle_shutdown_and_stop_remove_only_owned_socket(self):
        process = self.start('--idle-timeout', '0.2')
        process.wait(timeout=5)
        self.assertFalse(daemon.socket_path(self.root).exists())
        process = self.start()
        self.assertEqual(self.cli('stop').returncode, 0)
        process.wait(timeout=5)
        self.assertFalse(daemon.socket_path(self.root).exists())

    def test_replaced_repository_is_not_served(self):
        self.root.rename(self.work / 'old-project')
        self.root.mkdir()
        (self.root / 'a.py').write_text('BUG')
        with self.assertRaisesRegex(daemon.ServiceError, 'replaced'):
            self.service.handle(self.request())
        self.assertTrue(self.service.stopping)

    def test_cache_hit_preserves_exact_streams_and_exit_status(self):
        first = self.service.handle(self.request())
        second = self.service.handle(self.request())
        self.assertFalse(first['cached'])
        self.assertTrue(second['cached'])
        for key in ('stdout', 'stderr', 'exit_code'):
            self.assertEqual(first[key], second[key])
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')

    def test_same_length_edit_with_restored_mtime_invalidates(self):
        self.service.handle(self.request())
        stamp = self.source.stat()
        self.source.write_text('BUG!!')
        os.utime(self.source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        result = self.service.handle(self.request())
        self.assertFalse(result['cached'])
        self.assertEqual(result['exit_code'], 1)

    def test_unselected_dependency_ignore_and_runtime_changes_invalidate(self):
        for path in (self.root / 'other.go', self.root / '.ubsignore', self.work / 'modules' / 'helper.py'):
            with self.subTest(path=path):
                path.write_text('before')
                self.service.handle(self.request())
                path.write_text('after')
                self.assertFalse(self.service.handle(self.request())['cached'])

    def test_policy_and_format_are_part_of_cache_key(self):
        self.service.handle(self.request())
        for update in ({'format': 'sarif'}, {'profile': 'strict'}, {'fail_on_warning': True}):
            with self.subTest(update=update):
                self.assertFalse(self.service.handle(self.request(**update))['cached'])

    def test_environment_mismatch_is_not_a_cached_clean_report(self):
        self.service.handle(self.request())
        with patch.dict(os.environ, {'UBS_PROFILE': 'strict'}):
            self.assertIn('unavailable', self.service.handle(self.request()))

    def test_errors_and_concurrent_edits_are_not_cached(self):
        with patch.dict(os.environ, {'SCAN_ERROR': '1'}):
            service = daemon.ScanService(self.root, self.scanner, 10, 1024 * 1024)
            self.assertEqual(service.handle(self.request())['exit_code'], 2)
            self.assertFalse(service.handle(self.request())['cached'])
        with patch.object(daemon, 'snapshot', side_effect=['old', 'new', 'new', 'new']):
            service = daemon.ScanService(self.root, self.scanner, 10, 1024 * 1024)
            self.assertFalse(service.handle(self.request())['cached'])
            self.assertFalse(service.handle(self.request())['cached'])

    def test_output_timeout_and_cache_memory_are_bounded(self):
        self.scanner.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n')
        result = daemon.run_scanner(self.root, self.scanner, [self.source], [], 0.05)
        self.assertEqual(result['exit_code'], 2)
        self.assertIn('timed out', result['stderr'])
        self.scanner.write_text('#!/usr/bin/env python3\nprint("x" * 10000)\n')
        with patch.object(daemon, 'MAX_OUTPUT', 100):
            result = daemon.run_scanner(self.root, self.scanner, [self.source], [], 5)
        self.assertEqual(result['exit_code'], 2)
        self.scanner.write_text(SCANNER)
        self.service.cache_bytes = 1
        self.service.handle(self.request())
        self.assertEqual(self.service.cache_size, 0)

    def test_large_or_special_input_disables_reuse_instead_of_skipping_scan(self):
        with patch.object(daemon, 'MAX_SNAPSHOT', 1):
            self.assertIsNone(daemon.snapshot(self.root, self.scanner))
            self.assertEqual(self.service.handle(self.request())['exit_code'], 0)
        os.mkfifo(self.root / 'pipe')
        self.assertIsNone(daemon.snapshot(self.root, self.scanner))

    def test_invalid_response_cannot_be_reported_as_clean(self):
        with patch.object(daemon, 'request_service', return_value={'protocol': 1}):
            self.assertEqual(daemon.main(['client', '--repo', str(self.root), '--scanner', str(self.scanner), 'a.py']), 2)

    def test_runtime_override_disables_cache_reuse(self):
        with patch.dict(os.environ, {'UBS_MODULE_DIR': str(self.work / 'custom')}):
            self.assertIsNone(daemon.snapshot(self.root, self.scanner))

    def test_directory_inventory_limit_is_bounded(self):
        for index in range(12):
            (self.root / str(index)).write_text('')
        with patch.object(daemon, 'MAX_SNAPSHOT_ENTRIES', 5):
            self.assertIsNone(daemon.snapshot(self.root, self.scanner))

    def test_client_falls_back_only_when_daemon_is_absent_or_context_differs(self):
        self.assertEqual(self.cli('client', 'a.py').returncode, 0)
        self.assertEqual(self.cli('client', '--require-daemon', 'a.py').returncode, 2)
        self.start()
        result = self.cli('client', 'a.py', env=dict(self.env, UBS_PROFILE='loose'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cli('client', '../outside.py').returncode, 2)

    def test_client_keeps_newlines_spaces_and_leading_dashes_as_paths(self):
        for name in ('has space.py', 'has\nnewline.py', '--update.py'):
            (self.root / name).write_text('BUG')
        self.start()
        result = self.cli('client', '--', 'has space.py', 'has\nnewline.py', '--update.py')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['files']), 3)


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for actual scanner integration')
class RealScannerTests(unittest.TestCase):
    setUp = ServiceTests.setUp
    request = ServiceTests.request
    start = ServiceTests.start
    cli = ServiceTests.cli
    def test_real_scanner_warm_hit_edit_and_one_shot_findings_match(self):
        self.source.write_text('eval(input())\n')
        self.start(scanner=ROOT / 'ubs')
        request = self.request(scanner=str(ROOT / 'ubs'))
        cold = daemon.request_service(self.root, request, 130)
        warm = daemon.request_service(self.root, request, 130)
        self.assertEqual(cold['exit_code'], 1, cold['stderr'])
        self.assertTrue(warm['cached'], warm['stderr'])
        cold_doc, warm_doc = json.loads(cold['stdout']), json.loads(warm['stdout'])
        self.assertEqual(cold_doc['findings'], warm_doc['findings'])
        self.assertTrue(any(f['rule_id'] == 'python.taint.eval' and f['line'] == 1 for f in warm_doc['findings']))
        direct = subprocess.run([str(ROOT / 'ubs'), '--ci', '--no-auto-update', '--no-color',
                                 '--format=json', '--', str(self.source)], cwd=self.root,
                                env=dict(self.env, UBS_NO_AUTO_UPDATE='1', NO_COLOR='1'),
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(direct.returncode, 1, direct.stderr)
        self.assertEqual(cold_doc['findings'], json.loads(direct.stdout)['findings'])
        self.source.write_text('value = 1\n')
        changed = daemon.request_service(self.root, request, 130)
        self.assertFalse(changed['cached'])
        self.assertEqual(changed['exit_code'], 0, changed['stderr'])
        self.assertEqual(json.loads(changed['stdout']).get('findings', []), [])
        print(f'[daemon-real] warm_request_ms={warm["elapsed_ms"]} cold_request_ms={cold["elapsed_ms"]}', flush=True)


if __name__ == '__main__':
    unittest.main()
