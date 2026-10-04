"""C5/D6: real analyzer coverage must not depend on worker count.

These cases invoke registered Python, Go and JavaScript source analyzers, not
detector doubles. Tests need neither a compiler nor an external AST binary.
"""
from __future__ import annotations

from collections import Counter
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'modules' / 'helpers'
sys.path.insert(0, str(HELPERS))
from ubs_core import analyzers, cli, registry  # noqa: F401

PYTHON = {'caller.py': 'from helper import run\nrun(input())\n',
          'helper.py': 'def run(value):\n    eval(value)\n'}
GO = {'caller.go': 'package main\nimport "net/http"\n'
                  'func handler(w http.ResponseWriter, r *http.Request) { run(r.URL.Query().Get("cmd")) }\n',
      'helper.go': 'package main\nimport "os/exec"\n'
                  'func run(value string) { exec.Command("sh", "-c", value).Run() }\n'}


class ParallelScopeTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(case is self or getattr(case, 'test_case', None) is self
                     for case, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic()-started:.3f}s)', flush=True)
        return result

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ubs-parallel-scope-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'project'
        self.root.mkdir()
        self.env = dict(os.environ, PYTHONPATH=str(HELPERS), PYTHONDONTWRITEBYTECODE='1')

    def write(self, sources):
        paths = []
        for name, text in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
            paths.append(path)
        return paths

    def scan(self, lang, paths, jobs, *, layer='taint', profile=None, relative=False):
        selected = self.work / 'selected.nul'
        selected.write_bytes(b''.join(os.fsencode(path.relative_to(self.root) if relative else path)
                                      + b'\0' for path in paths))
        command = [sys.executable, '-m', 'ubs_core', layer, '--lang', lang,
                   '--files-from', str(selected), '--jobs', str(jobs)]
        if profile is not None:
            option = self.work / 'profile.json'
            option.write_text(json.dumps(profile), encoding='utf-8')
            command.extend(('--profile', str(option)))
        completed = subprocess.run(command, cwd=self.root, env=self.env,
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, (command, completed.stdout, completed.stderr))
        self.assertEqual(completed.stderr, '', (command, completed.stderr))
        return [json.loads(line) for line in completed.stdout.splitlines()]

    def parity(self, lang, paths, rule, **options):
        serial = self.scan(lang, paths, 1, **options)
        self.assertTrue(any(record['rule'] == rule for record in serial), serial)
        expected = Counter(json.dumps(record, sort_keys=True) for record in serial)
        for jobs in (2, 4, 8):
            with self.subTest(lang=lang, jobs=jobs, options=options):
                parallel = self.scan(lang, paths, jobs, **options)
                self.assertEqual(Counter(json.dumps(record, sort_keys=True) for record in parallel),
                                 expected, (serial, parallel))
        return serial

    def test_python_imported_sink_survives_every_worker_count(self):
        records = self.parity('python', self.write(PYTHON), 'python.taint.eval')
        self.assertEqual([(Path(r['path']).name, r['line']) for r in records], [('helper.py', 2)])

    def test_python_full_scan_keeps_taint_and_file_local_findings(self):
        paths = self.write(dict(PYTHON, **{'guard.py': 'value = request.user.profile.settings.name\n'}))
        records = self.parity('python', paths, 'python.taint.eval', layer='scan')
        self.assertTrue(any(r['layer'] != 'taint' for r in records), records)

    def test_python_transitive_packages_keep_explicit_project_root(self):
        paths = self.write({
            'pkg/__init__.py': '', 'pkg/helper.py': PYTHON['helper.py'],
            'pkg/relay.py': 'from .helper import run as target\ndef forward(value):\n    target(value)\n',
            'entry.py': 'from pkg.relay import forward as invoke\ninvoke(input())\n'})
        self.parity('python', paths, 'python.taint.eval', profile={'project_dir': str(self.root)})

    def test_python_relative_paths_and_unusual_caller_name(self):
        paths = self.write({'--caller space\né.py': 'import helper as h\nh.run(input())\n',
                            'helper.py': PYTHON['helper.py']})
        self.parity('python', list(reversed(paths)), 'python.taint.eval', relative=True)

    def test_unselected_helper_is_not_silently_added(self):
        paths = self.write(dict(PYTHON, **{'unrelated.py': 'value = 1\n'}))
        for jobs in (1, 2, 8):
            self.assertEqual(self.scan('python', [paths[0], paths[2]], jobs), [])

    def test_profile_and_inline_suppression_survive_parallel_taint(self):
        paths = self.write(PYTHON)
        self.parity('python', paths, 'python.taint.eval')
        for jobs in (1, 2, 4):
            self.assertEqual(self.scan('python', paths, jobs,
                                      profile={'disabled_rules': ['python.taint.eval']}), [])
        paths[1].write_text('def run(value):\n    eval(value)  # ubs:ignore python.taint.eval\n')
        for jobs in (1, 2, 4):
            self.assertEqual(self.scan('python', paths, jobs), [])

    def test_go_package_summary_survives_every_worker_count(self):
        paths = self.write(GO)
        self.parity('go', paths, 'go.taint.command')
        self.parity('go', paths, 'go.taint.command', layer='scan')

    def test_go_distinct_packages_do_not_share_same_named_helpers(self):
        sources = {'first/' + name: text for name, text in GO.items()}
        sources.update({'second/caller.go': GO['caller.go'],
                        'second/helper.go': 'package main\nfunc run(value string) { println(value) }\n'})
        records = self.parity('go', self.write(sources), 'go.taint.command')
        self.assertTrue(all('first' in Path(record['path']).parts for record in records), records)

    def test_javascript_component_parallelism_keeps_import_edges(self):
        paths = self.write({
            'app.js': "import { run } from './helper.js'; run(req.query.code);\n",
            'helper.js': 'export function run(value) { eval(value); }\n',
            'unrelated.js': 'const x = 1;\n'})
        self.parity('javascript', paths, 'javascript.taint.eval')

    def test_full_scan_still_shards_file_local_layers(self):
        paths = self.write(PYTHON)
        selected = self.work / 'selected.nul'
        selected.write_bytes(b''.join(os.fsencode(path) + b'\0' for path in paths))
        invocations = []
        from dataclasses import replace
        def observed(analyzer):
            def run(ctx):
                invocations.append((analyzer.layer, tuple(ctx.files)))
                return analyzer.run(ctx)
            return replace(analyzer, run=run)

        # Observe real analyzer invocations rather than requiring a particular
        # executor. Registry scheduling supersedes the old CLI shard wrapper.
        registered = {key: [observed(analyzer) for analyzer in values]
                      for key, values in registry._REGISTRY.items()}
        with patch.dict(registry._REGISTRY, registered, clear=True), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['scan', '--lang', 'python', '--files-from', str(selected), '--jobs', '4']), 0)
        self.assertTrue(any(json.loads(line)['rule'] == 'python.taint.eval' for line in output.getvalue().splitlines()))
        self.assertEqual([files for layer, files in invocations if layer == 'taint'], [tuple(paths)])
        self.assertTrue(any(layer != 'taint' and len(files) == 1 for layer, files in invocations), invocations)


if __name__ == '__main__':
    unittest.main()
