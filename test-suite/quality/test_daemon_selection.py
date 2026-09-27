"""K4 source selection: real sockets/Git with a named scanner double and UBS E2E."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / 'ubs-daemon'
loader = importlib.machinery.SourceFileLoader('ubs_daemon_selection', str(DAEMON))
spec = importlib.util.spec_from_loader(loader.name, loader)
daemon = importlib.util.module_from_spec(spec)
loader.exec_module(daemon)

# A protocol double, NOT a detector implementation. Git operations are real.
SCANNER = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
paths = args[args.index('--') + 1:]
root = pathlib.Path.cwd()
with open(os.environ['SCAN_COUNT'], 'a') as stream:
    stream.write('scan\n')
if '--staged' in args or '--diff' in args:
    staged = '--staged' in args
    command = ['git', 'diff', '--name-only', '-z', '--diff-filter=ACMR']
    command += ['--cached'] if staged else ['HEAD']
    names = subprocess.check_output(command).split(b'\0')
    records = []
    for raw in names:
        if not raw:
            continue
        name = os.fsdecode(raw)
        text = subprocess.check_output(['git', 'show', ':' + name]).decode() if staged else (root / name).read_text()
        records.append((name, text))
else:
    records = []
    for name in paths:
        path = pathlib.Path(name)
        for source in sorted(path.rglob('*.py')) if path.is_dir() else [path]:
            records.append((str(source.relative_to(root)), source.read_text()))
code = 3 if not records else 1 if any('BUG' in text for _, text in records) else 0
print(json.dumps({'files': records, 'args': args, 'cwd': str(root)}))
print('scanner diagnostics', file=sys.stderr)
sys.exit(code)
'''


class SelectionFixture:
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ubs-sel-')
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
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
        self.source.write_text('clean\n')
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('UBS_', 'GIT_', 'XDG_', 'CLAUDE_', 'SCAN_'))
                    and key not in {'ENABLE_UV_TOOLS', 'UV_TOOLS'}}
        self.env.update(HOME=str(self.home), XDG_RUNTIME_DIR=str(self.runtime),
                        XDG_CONFIG_HOME=str(self.home / '.config'), XDG_CACHE_HOME=str(self.work / 'cache'),
                        SCAN_COUNT=str(self.work / 'count'), PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1')
        environment = patch.dict(os.environ, self.env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.service = daemon.ScanService(self.root, self.scanner, 20, 1024 * 1024)

    def request(self, selection='files', paths=None, **extra):
        value = {'protocol': daemon.PROTOCOL, 'op': 'scan', 'root': str(self.root),
                 'scanner': str(self.scanner), 'environment': daemon.environment_key(),
                 'selection': selection, 'paths': ['a.py'] if paths is None else paths, 'format': 'json'}
        return dict(value, **extra)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], env=self.env,
                              capture_output=True, check=True, timeout=10).stdout

    def init_git(self):
        self.git('init', '-q')
        self.git('config', 'user.name', 'UBS test')
        self.git('config', 'user.email', 'ubs-test@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')

    def cli(self, *args, scanner=None):
        return subprocess.run([sys.executable, str(DAEMON), *args, '--repo', str(self.root),
                               '--scanner', str(scanner or self.scanner)], env=self.env,
                              capture_output=True, text=True, timeout=180)

    def start(self, scanner=None):
        process = subprocess.Popen([sys.executable, str(DAEMON), 'serve', '--repo', str(self.root),
                                    '--scanner', str(scanner or self.scanner), '--scan-timeout=120'],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def finish():
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        self.addCleanup(finish)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            if process.poll() is not None:
                self.fail('Daemon startup failed: ' + process.communicate()[1])
            try:
                response = daemon.request_service(self.root, {'protocol': daemon.PROTOCOL,
                                                  'root': str(self.root), 'op': 'status'}, 0.5)
                if response.get('status') == 'ready':
                    return process
            except (OSError, daemon.ServiceError):
                pass
            time.sleep(0.02)
        self.fail('Daemon startup timed out')


@unittest.skipUnless(os.name == 'posix', 'Unix service requires POSIX')
class SelectionTests(SelectionFixture, unittest.TestCase):
    def test_directory_delegates_selection_and_preserves_streams(self):
        request = self.request('directory', ['.'])
        result = self.service.handle(request)
        self.assertEqual(result['exit_code'], 0, result)
        report = json.loads(result['stdout'])
        self.assertEqual(report['args'][-2:], ['--', str(self.root)])
        self.assertEqual(report['cwd'], str(self.root))
        self.assertEqual(report['files'], [['a.py', 'clean\n']])
        self.assertEqual(result['stderr'], 'scanner diagnostics\n')
        again = self.service.handle(request)
        self.assertFalse(again['cached'], again)
        self.assertEqual(again['stdout'], result['stdout'])

    def test_directory_inventory_and_policy_edits_invalidate(self):
        request = self.request('directory', ['.'])
        self.service.handle(request)
        self.assertFalse(self.service.handle(request)['cached'])
        added = self.root / 'new.py'
        added.write_text('BUG\n')
        result = self.service.handle(request)
        self.assertFalse(result['cached'])
        self.assertEqual(result['exit_code'], 1)
        renamed = self.root / 'renamed.py'
        added.rename(renamed)
        result = self.service.handle(request)
        self.assertFalse(result['cached'])
        self.assertEqual(result['exit_code'], 1)
        renamed.rename(self.work / 'removed.py')
        result = self.service.handle(request)
        self.assertFalse(result['cached'])
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(json.loads(result['stdout'])['files'], [['a.py', 'clean\n']])
        (self.root / '.ubsignore').write_text('a.py\n')
        self.assertFalse(self.service.handle(request)['cached'])

    def test_directory_text_never_silently_disables_live_audits(self):
        request = self.request('directory', ['.'], format='text')
        self.assertFalse(self.service.handle(request)['cached'])
        self.assertFalse(self.service.handle(request)['cached'])
        self.assertNotIn('ENABLE_UV_TOOLS', os.environ)
        with patch.dict(os.environ, {'ENABLE_UV_TOOLS': '0'}):
            service = daemon.ScanService(self.root, self.scanner, 20, 1024 * 1024)
            request = self.request('directory', ['.'], format='text')
            self.assertFalse(service.handle(request)['cached'])
            # Disabling Python audits does not disable every project-level
            # tool/build phase, so it cannot authorize directory report reuse.
            self.assertFalse(service.handle(request)['cached'])

    def test_subdirectory_is_not_expanded_to_project(self):
        sub = self.root / 'src'
        sub.mkdir()
        (sub / 'b.py').write_text('clean\n')
        self.source.write_text('BUG\n')
        result = self.service.handle(self.request('directory', ['src']))
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(json.loads(result['stdout'])['args'][-1], str(sub))
        self.assertEqual(len(json.loads(result['stdout'])['files']), 1)

    def test_bad_selection_cannot_expand_scope_or_inject_flags(self):
        outside = self.work / 'outside'
        outside.mkdir()
        (self.root / 'escape').symlink_to(outside)
        cases = [('unknown', []), ([], []), ('directory', []), ('directory', ['.', '.']),
                 ('directory', ['a.py']), ('directory', ['escape']), ('directory', ['../outside']),
                 ('files', ['.']), ('files', []), ('files', ['\0']), ('staged', ['a.py']), ('diff', ['.'])]
        for selection, paths in cases:
            with self.subTest(selection=selection, paths=paths), self.assertRaises(daemon.ServiceError):
                self.service.handle(self.request(selection, paths))
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_cli_directory_and_missing_daemon_fallback_match(self):
        absent = self.cli('client', '.')
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.start()
        served = self.cli('client', '.', '--require-daemon')
        self.assertEqual(served.returncode, absent.returncode, served.stderr)
        self.assertEqual(served.stdout, absent.stdout)
        self.assertEqual(served.stderr, absent.stderr)

    def test_directory_names_keep_spaces_newlines_and_leading_dash(self):
        for name in ('with space', 'with\nnewline', '--staged'):
            path = self.root / name
            path.mkdir()
            (path / 'b.py').write_text('BUG\n')
            # Construct '--' last, so only the directory is positional.
            result = subprocess.run([sys.executable, str(DAEMON), 'client', '--repo', str(self.root),
                                     '--scanner', str(self.scanner), '--', name], env=self.env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)['args'][-1], str(path))

    def test_staged_uses_index_not_clean_worktree_and_never_reuses_report(self):
        self.init_git()
        self.source.write_text('BUG staged\n')
        self.git('add', 'a.py')
        self.source.write_text('clean worktree\n')
        self.start()
        request = self.request('staged', [])
        first = daemon.request_service(self.root, request, 10)
        second = daemon.request_service(self.root, request, 10)
        for result in (first, second):
            self.assertEqual(result['exit_code'], 1, result)
            self.assertFalse(result['cached'])
            report = json.loads(result['stdout'])
            self.assertEqual(report['files'], [['a.py', 'BUG staged\n']])
            self.assertEqual(report['args'][-3:], ['--staged', '--', str(self.root)])
        self.git('add', 'a.py')
        changed = daemon.request_service(self.root, request, 10)
        self.assertEqual(changed['exit_code'], 0, changed)
        self.assertEqual(Path(self.env['SCAN_COUNT']).read_text(), 'scan\n' * 3)

    def test_diff_uses_worktree_not_staged_contents(self):
        self.init_git()
        self.source.write_text('clean staged\n')
        self.git('add', 'a.py')
        self.source.write_text('BUG worktree\n')
        result = self.service.handle(self.request('diff', []))
        self.assertEqual(result['exit_code'], 1, result)
        self.assertEqual(json.loads(result['stdout'])['files'], [['a.py', 'BUG worktree\n']])
        self.assertFalse(self.service.handle(self.request('diff', []))['cached'])

    def test_no_staged_targets_retains_exit_three(self):
        self.init_git()
        result = self.cli('client', '--staged')
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)['files'], [])

    def test_staged_fallback_has_identical_policy_and_argument_boundaries(self):
        self.init_git()
        self.source.write_text('BUG\n')
        self.git('add', 'a.py')
        absent = self.cli('client', '--staged', '--profile=strict', '--fail-on-warning', '--format=sarif')
        self.assertEqual(absent.returncode, 1, absent.stderr)
        self.start()
        served = self.cli('client', '--staged', '--profile=strict', '--fail-on-warning', '--format=sarif', '--require-daemon')
        self.assertEqual((served.returncode, served.stdout, served.stderr),
                         (absent.returncode, absent.stdout, absent.stderr))
        self.assertIn('--profile=strict', json.loads(served.stdout)['args'])

    def test_git_scope_cannot_escape_a_served_subdirectory(self):
        self.init_git()
        sub = self.root / 'sub'
        sub.mkdir()
        for mode in ('staged', 'diff'):
            with self.subTest(mode=mode), self.assertRaisesRegex(daemon.ServiceError, 'worktree root'):
                daemon.validate_scan(sub, self.request(mode, []))
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_git_unavailable_or_not_repository_is_never_clean(self):
        for mode in ('--staged', '--diff'):
            result = self.cli('client', mode)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, '')
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())

    def test_git_root_with_trailing_newline_is_preserved(self):
        root = self.work / 'project\n'
        self.root.rename(root)
        self.root = root
        self.source = root / 'a.py'
        self.init_git()
        paths, options = daemon.validate_scan(root, self.request('staged', []))
        self.assertEqual(paths, [root])
        self.assertIn('--staged', options)

    def test_linked_worktree_is_scanned_without_report_reuse(self):
        self.init_git()
        linked = self.work / 'linked'
        self.git('worktree', 'add', '-q', '-b', 'test-worktree', str(linked))
        source = linked / 'a.py'
        source.write_text('BUG\n')
        subprocess.run(['git', '-C', str(linked), 'add', 'a.py'], env=self.env, check=True)
        service = daemon.ScanService(linked, self.scanner, 20, 1024 * 1024)
        request = self.request('staged', [], root=str(linked))
        result = service.handle(request)
        self.assertEqual(result['exit_code'], 1, result)
        self.assertFalse(service.handle(request)['cached'])

    def test_malformed_requests_leave_service_control_plane_alive(self):
        self.start()
        for selection, paths in (({}, []), ('staged', ['a.py']), ('directory', ['a.py'])):
            result = daemon.request_service(self.root, self.request(selection, paths), 10)
            self.assertEqual(result['exit_code'], 2, result)
        self.assertEqual(self.cli('status').returncode, 0)

    def test_lifecycle_flags_and_conflicting_selections_are_rejected(self):
        for command in ('serve', 'status', 'stop', 'cancel'):
            for mode in ('--staged', '--diff'):
                result = self.cli(command, mode)
                self.assertEqual(result.returncode, 2, (command, mode, result.stderr))
        for args in (('--staged', '--diff'), ('--staged', 'a.py'), ('--diff', '.')):
            result = self.cli('client', *args)
            self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(Path(self.env['SCAN_COUNT']).exists())


@unittest.skipUnless(os.environ.get('UBS_DAEMON_E2E') == '1', 'set UBS_DAEMON_E2E=1 for the actual scanner')
class RealSelectionTests(SelectionFixture, unittest.TestCase):
    def compare_real(self, client_args, runner_args):
        direct = subprocess.run([str(ROOT / 'ubs'), '--ci', '--no-auto-update', '--no-color', '--format=json',
                                 *runner_args, '--', str(self.root)], cwd=self.root,
                                env=dict(self.env, UBS_NO_AUTO_UPDATE='1', NO_COLOR='1'),
                                capture_output=True, text=True, timeout=180)
        served = self.cli('client', *client_args, '--require-daemon', scanner=ROOT / 'ubs')
        self.assertEqual(served.returncode, direct.returncode, (served.stderr, direct.stderr))
        a, b = json.loads(served.stdout), json.loads(direct.stdout)
        self.assertEqual(a.get('totals'), b.get('totals'))
        # Git-scoped scans may use independent private staging directories.
        def findings(doc):
            return sorted((item.get('rule_id'), item.get('line'), item.get('severity'), item.get('message'))
                          for item in doc.get('findings', []))
        self.assertEqual(findings(a), findings(b))
        return served.returncode, a

    def test_real_directory_scan_matches_one_shot_and_respects_ignore(self):
        self.source.write_text('value = 1\n')
        (self.root / 'excluded.py').write_text('eval(input())\n')
        (self.root / '.ubsignore').write_text('excluded.py\n')
        self.start(scanner=ROOT / 'ubs')
        code, report = self.compare_real(['.'], [])
        self.assertEqual(code, 0, report)
        self.source.write_text('eval(input())\n')
        code, report = self.compare_real(['.'], [])
        self.assertEqual(code, 1, report)
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval' for item in report['findings']))

    def test_real_staged_scan_uses_index_despite_clean_worktree(self):
        self.source.write_text('value = 1\n')
        self.init_git()
        self.source.write_text('eval(input())\n')
        self.git('add', 'a.py')
        self.source.write_text('value = 2\n')
        self.start(scanner=ROOT / 'ubs')
        code, report = self.compare_real(['--staged'], ['--staged'])
        self.assertEqual(code, 1, report)
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval' for item in report['findings']))
        self.git('add', 'a.py')
        code, report = self.compare_real(['--staged'], ['--staged'])
        self.assertEqual(code, 0, report)

    def test_real_diff_scan_matches_worktree_analysis(self):
        self.source.write_text('value = 1\n')
        self.init_git()
        self.source.write_text('eval(input())\n')
        self.start(scanner=ROOT / 'ubs')
        code, report = self.compare_real(['--diff'], ['--diff'])
        self.assertEqual(code, 1, report)
        self.assertTrue(any(item['rule_id'] == 'python.taint.eval' for item in report['findings']))


if __name__ == '__main__':
    unittest.main()
