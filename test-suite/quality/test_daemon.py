"""K4 Unix transport, cache correctness, and actual one-shot parity tests."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
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
code = int(os.environ.get('SCAN_STATUS', code))
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
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'CLAUDE_', 'SCAN_'))
                    and key not in {'ENABLE_UV_TOOLS', 'UV_TOOLS'}}
        self.env.update(XDG_RUNTIME_DIR=str(self.runtime), HOME=str(self.home),
                        XDG_CONFIG_HOME=str(self.home / '.config'), XDG_CACHE_HOME=str(self.work / 'cache'),
                        SCAN_COUNT=str(self.work / 'count'), PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1')
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

    def test_external_git_metadata_and_inherited_root_disable_reuse(self):
        with patch.dict(os.environ, {'GIT_INDEX_FILE': '/outside/index'}):
            self.assertIsNone(daemon.snapshot(self.root, self.scanner))
        (self.root / '.git').write_text('gitdir: ../external-metadata\n')
        self.assertIsNone(daemon.snapshot(self.root, self.scanner))
        child = self.root / 'nested'
        child.mkdir()
        self.assertIsNone(daemon.snapshot(child, self.scanner))

    def test_git_config_external_includes_and_excludes_disable_reuse(self):
        git_config = self.home / '.gitconfig'
        for content in ('[include]\npath = /outside/config\n', '[core]\nexcludesFile = /outside/ignore\n',
                        '#' * 65530 + '\n[include]\npath = /outside/config\n'):
            with self.subTest(content=content):
                git_config.write_text(content)
                self.assertIsNone(daemon.snapshot(self.root, self.scanner))

    def test_live_dependency_audits_are_not_reused_as_source_only_reports(self):
        request = self.request(format='text')
        self.assertFalse(self.service.handle(request)['cached'])
        self.assertFalse(self.service.handle(request)['cached'])
        with patch.dict(os.environ, {'ENABLE_UV_TOOLS': '0'}):
            native = daemon.ScanService(self.root, self.scanner, 10, 1024 * 1024)
            request = self.request(format='text')
            self.assertFalse(native.handle(request)['cached'])
            self.assertTrue(native.handle(request)['cached'])

    def test_directory_inventory_limit_is_bounded(self):
        for index in range(12):
            (self.root / str(index)).write_text('')
        with patch.object(daemon, 'MAX_SNAPSHOT_ENTRIES', 5):
            self.assertIsNone(daemon.snapshot(self.root, self.scanner))

    def test_lifecycle_commands_cannot_silently_ignore_scan_policy(self):
        for option in ('--profile=strict', '--fail-on-warning', '--format=text', '--require-daemon'):
            with self.subTest(option=option), patch.object(daemon, 'serve', return_value=0):
                self.assertEqual(daemon.main(['serve', '--repo', str(self.root),
                                               '--scanner', str(self.scanner), option]), 2)

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


@unittest.skipUnless(os.name == 'posix', 'Scanner process groups require POSIX')
class ScannerProcessTests(unittest.TestCase):
    setUp = ServiceTests.setUp

    def scan(self, timeout=3, **kwargs):
        return daemon.run_scanner(self.root, self.scanner, [self.source], [], timeout, **kwargs)

    def fork_scanner(self, child_body):
        pidfile = self.work / 'child.pid'
        self.scanner.write_text(
            '#!/usr/bin/env python3\nimport os, pathlib, time\n'
            'child = os.fork()\nif child == 0:\n' +
            ''.join('    ' + line + '\n' for line in child_body.splitlines()) +
            '    os._exit(0)\n' +
            f'pathlib.Path({str(pidfile)!r}).write_text(str(child))\n'
            'print("parent", flush=True)\nos._exit(0)\n')
        def cleanup():
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.addCleanup(cleanup)

    def test_collects_helper_output_after_runner_exits(self):
        self.fork_scanner('time.sleep(0.15)\nprint("helper", flush=True)')
        result = self.scan()
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(result['stdout'], 'parent\nhelper\n')

    def test_inherited_pipes_remain_subject_to_scan_deadline(self):
        self.fork_scanner('time.sleep(30)')
        result = self.scan(timeout=3)
        self.assertTrue((self.work / 'child.pid').exists(), 'helper must start before the deadline')
        self.assertEqual(result['exit_code'], 2, result)
        self.assertIn('timed out', result['stderr'])
        self.assertEqual(result['stdout'], '')

    def test_success_does_not_leave_background_helpers_running(self):
        marker = self.work / 'helper-heartbeat'
        self.fork_scanner('os.close(1)\nos.close(2)\nwhile True:\n'
                          f'    pathlib.Path({str(marker)!r}).write_text(str(time.monotonic_ns()))\n'
                          '    time.sleep(0.02)')
        result = self.scan()
        self.assertEqual(result['exit_code'], 0, result)
        before = marker.read_bytes() if marker.exists() else None
        time.sleep(0.2)
        after = marker.read_bytes() if marker.exists() else None
        self.assertEqual(before, after, 'scanner helper survived a completed request')

    def test_cancellation_interrupts_a_running_scan(self):
        cancelled = threading.Event()
        running = threading.Event()
        def interrupt():
            until = time.monotonic() + 5
            while time.monotonic() < until:
                if Path(self.env['SCAN_COUNT']).exists():
                    running.set()
                    break
                time.sleep(0.01)
            cancelled.set()
        worker = threading.Thread(target=interrupt)
        worker.start()
        self.addCleanup(worker.join)
        with patch.dict(os.environ, {'SCAN_SLEEP': '30'}):
            result = self.scan(timeout=30, cancel=cancelled)
        self.assertTrue(running.is_set(), 'cancellation must exercise a running scanner')
        self.assertEqual(result['exit_code'], 2, result)
        self.assertEqual(result['stdout'], '')
        self.assertIn('cancelled', result['stderr'])

    def test_pre_cancelled_scan_does_not_launch_scanner(self):
        cancelled = threading.Event()
        cancelled.set()
        result = self.scan(cancel=cancelled)
        self.assertEqual(result['exit_code'], 2, result)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_both_large_streams_and_nonstandard_status_are_preserved(self):
        self.scanner.write_text(
            '#!/usr/bin/env python3\nimport os, sys\n'
            'os.write(1, ("λ\\0" * 100000).encode())\n'
            'os.write(2, b"diagnostic\\n" * 100000)\nsys.exit(7)\n')
        result = self.scan()
        self.assertEqual(result['exit_code'], 7, result['stderr'][:100])
        self.assertEqual(result['stdout'], 'λ\0' * 100000)
        self.assertEqual(result['stderr'], 'diagnostic\n' * 100000)

    def test_output_limit_is_enforced_on_each_pipe(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor):
                self.scanner.write_text('#!/usr/bin/env python3\nimport os\n'
                                        f'while True: os.write({descriptor}, b"x" * 65536)\n')
                with patch.object(daemon, 'MAX_OUTPUT', 100):
                    result = self.scan()
                self.assertEqual(result['exit_code'], 2, result)
                self.assertIn('output exceeded', result['stderr'])
                self.assertEqual(result['stdout'], '')


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

    def test_actual_save_hook_uses_a_warm_service_then_rescans_the_edit(self):
        # Exercise native source analysis, not online dependency auditing.
        # The environment is identical for the daemon, client and scanner.
        self.env['ENABLE_UV_TOOLS'] = '0'
        os.environ['ENABLE_UV_TOOLS'] = '0'
        self.env['PATH'] = str(ROOT) + os.pathsep + self.env['PATH']
        os.environ['PATH'] = self.env['PATH']
        self.env['CLAUDE_PROJECT_DIR'] = str(self.root)
        os.environ['CLAUDE_PROJECT_DIR'] = str(self.root)
        self.source.write_text('eval(input())\n')
        self.start(scanner=ROOT / 'ubs')
        payload = json.dumps({'tool_name': 'Write', 'tool_input': {'file_path': str(self.source)}})
        def invoke():
            return subprocess.run(['bash', str(ROOT / '.claude/hooks/on-file-write.sh')],
                                  input=payload, env=self.env, cwd=self.root,
                                  capture_output=True, text=True, timeout=130)
        result = invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('UBS found critical issues', result.stderr)
        self.assertNotIn('NOT been verified', result.stderr)
        self.assertEqual(result.stdout, '')
        cached = daemon.request_service(self.root, self.request(scanner=str(ROOT / 'ubs'), format='text'), 130)
        self.assertTrue(cached['cached'], cached)
        self.assertEqual(cached['exit_code'], 1, cached)
        self.source.write_text('value = 1\n')
        clean = invoke()
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(clean.stdout + clean.stderr, '')
        print('[daemon-real-hook] finding, warm service reuse, edited clean result PASS', flush=True)


@unittest.skipUnless(os.name == 'posix', 'The save-hook daemon integration requires POSIX')
class SaveHookTests(unittest.TestCase):
    start = ServiceTests.start

    def setUp(self):
        ServiceTests.setUp(self)
        self.env['ENABLE_UV_TOOLS'] = '0'
        os.environ['ENABLE_UV_TOOLS'] = '0'
        subprocess.run(['git', 'init', '-q', str(self.root)], env=self.env, check=True)
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        (self.bin / 'ubs').symlink_to(self.scanner)
        (self.bin / 'ubs-daemon').symlink_to(DAEMON)
        self.env['PATH'] = str(self.bin) + os.pathsep + self.env['PATH']
        os.environ['PATH'] = self.env['PATH']

    def hook(self, source=None, *, env=None, payload=None):
        if payload is None:
            payload = json.dumps({'tool_name': 'Write', 'tool_input': {'file_path': str(source or self.source)}})
        return subprocess.run([shutil.which('bash'), str(ROOT / '.claude/hooks/on-file-write.sh')],
                              input=payload, env=env or self.env, cwd=self.root,
                              capture_output=True, text=True, timeout=60)

    def test_hook_uses_live_service_and_repeated_edit_reuses_report(self):
        self.source.write_text('BUG')
        self.start()
        for _ in range(2):
            result = self.hook()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('UBS found critical issues', result.stderr)
            self.assertEqual(result.stdout, '')
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')
        self.source.write_text('clean')
        result = self.hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\nscan\n')

    def test_missing_daemon_falls_back_to_real_one_shot_contract(self):
        self.source.write_text('BUG')
        result = self.hook()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('UBS found critical issues', result.stderr)
        self.assertIn('--format=text', result.stderr)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')

    def test_no_frontend_on_path_still_scans_and_preserves_policy(self):
        plain = self.work / 'one-shot-bin'
        plain.mkdir()
        (plain / 'ubs').symlink_to(self.scanner)
        for name in ('cat', 'jq', 'python3', 'tail'):
            found = shutil.which(name)
            if found:
                (plain / name).symlink_to(found)
        result = self.hook(env=dict(self.env, PATH=str(plain)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')

    def test_scan_failures_are_not_reported_as_findings_or_clean(self):
        result = self.hook(env=dict(self.env, SCAN_ERROR='1'))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('NOT been verified', result.stderr)
        self.assertNotIn('found critical issues', result.stderr)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')

    def test_protocol_error_does_not_trigger_a_second_scanner(self):
        # An owned but wrong service path is a protocol/security failure, not
        # an absent daemon. The hook must surface it rather than run UBS again.
        path = daemon.socket_path(self.root, create=True)
        path.write_text('not a socket')
        result = self.hook()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('NOT been verified', result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_missing_scanner_is_a_visible_verification_failure(self):
        plain = self.work / 'missing-scanner-bin'
        plain.mkdir()
        for name in ('bash', 'cat', 'jq', 'python3', 'tail'):
            found = shutil.which(name)
            if found:
                (plain / name).symlink_to(found)
        result = self.hook(env=dict(self.env, PATH=str(plain)))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('could not scan this edit', result.stderr)

    def test_no_targets_and_non_source_writes_are_silent(self):
        result = self.hook(env=dict(self.env, SCAN_STATUS='3'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        note = self.root / 'notes.md'
        note.write_text('BUG')
        result = self.hook(note)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n')

    def test_explicit_agent_project_root_confines_the_request(self):
        outside = self.work / 'outside.py'
        outside.write_text('BUG')
        result = self.hook(outside, env=dict(self.env, CLAUDE_PROJECT_DIR=str(self.root)))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('NOT been verified', result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_paths_and_shell_sources_keep_argument_boundaries(self):
        nested = self.root / 'nested\n'
        nested.mkdir()
        self.start()
        for name in ('has space.py', 'has\nnewline.py', '--update.sh'):
            source = nested / name
            source.write_text('BUG')
            with self.subTest(name=name):
                result = self.hook(source)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('UBS found critical issues', result.stderr)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n' * 3)


if __name__ == '__main__':
    unittest.main()
