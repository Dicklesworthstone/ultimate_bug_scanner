"""Selected-module source/sink, namespace, mutation and cache regressions."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.registry import RunContext


class PythonModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ubs-python-modules-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, sources):
        files = []
        for name, source in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding='utf-8')
            files.append(path)
        return files

    def scan(self, sources, selected=None, disabled=()):
        files = self.write(sources)
        if selected is not None:
            files = [self.root / name for name in selected]
        return list(taint_py.run(RunContext(lang='python', files=files,
                    profile={'project_dir': str(self.root), 'disabled_rules': disabled})))

    def sites(self, findings):
        return [(str(Path(f['path']).relative_to(self.root)), f['line'], f['rule']) for f in findings]

    def test_imported_sink_and_constant_actual_control(self):
        helper = 'def run(value):\n    eval(value)\n'
        for value, count in [('input()', 1), ('"safe"', 0)]:
            with self.subTest(value=value):
                got = self.scan({'app.py': f'from helper import run\nrun({value})\n', 'helper.py': helper})
                self.assertEqual(len(got), count, got)
                if count:
                    self.assertEqual(self.sites(got), [('helper.py', 2, 'python.taint.eval')])
                    self.assertIn('input(', got[0]['message'])

    def test_imported_callback_helper_retains_sink_location_and_safe_context(self):
        helper = 'def apply(callback, value):\n    callback(value)\n'
        for callback, value, expected in [('eval', 'input()', [('helper.py', 2, 'python.taint.eval')]),
                                          ('eval', '"safe"', []), ('lambda value: None', 'input()', [])]:
            with self.subTest(callback=callback, value=value):
                got = self.scan({'app.py': f'from helper import apply\napply({callback}, {value})\n', 'helper.py': helper})
                self.assertEqual(self.sites(got), expected)

    def test_imported_callback_context_uses_defining_globals(self):
        for owner_value, caller_value, expected in [('input()', '"safe"', [('helper.py', 3, 'python.taint.eval')]),
                                                   ('"safe"', 'input()', [])]:
            got = self.scan({'helper.py': f'raw = {owner_value}\ndef apply(callback):\n    callback(raw)\n',
                             'app.py': f'from helper import apply\nraw = {caller_value}\napply(eval)\n'})
            self.assertEqual(self.sites(got), expected)

    def test_imported_callback_returns_sanitized_values_without_global_pollution(self):
        helper = 'def apply(callback, value):\n    return callback(value)\n'
        for sink, expected in [('HttpResponse', []), ('eval', [('app.py', 2, 'python.taint.eval')])]:
            got = self.scan({'helper.py': helper,
                             'app.py': f'from helper import apply\n{sink}(apply(html.escape, input()))\n'})
            self.assertEqual(self.sites(got), expected)

    def test_callback_defined_in_caller_module_keeps_heap_effects(self):
        got = self.scan({'helper.py': 'def apply(callback, box):\n    callback(box)\n',
                         'app.py': 'from helper import apply\ndef fill(box): box.append(input())\n'
                                   'target=[]\napply(fill, target)\neval(target[0])\n'})
        self.assertEqual(self.sites(got), [('app.py', 5, 'python.taint.eval')])

    def test_callback_roundtrip_reads_the_callers_defining_globals(self):
        for value, expected in [('input()', [('app.py', 6, 'python.taint.eval')]), ('"safe"', [])]:
            got = self.scan({'helper.py': 'raw=input()\ndef apply(callback, box): callback(box)\n',
                             'app.py': f'from helper import apply\nraw={value}\n'
                                       'def fill(box): box.append(raw)\ntarget=[]\napply(fill,target)\neval(target[0])\n'})
            self.assertEqual(self.sites(got), expected)

    def test_module_and_function_aliases(self):
        for statement, call in [('import helper', 'helper.run'), ('import helper as h', 'h.run'),
                                 ('from helper import run as invoke', 'invoke')]:
            with self.subTest(statement=statement):
                got = self.scan({'app.py': f'{statement}\n{call}(input())',
                                 'helper.py': 'def run(x):\n    eval(x)\n'})
                self.assertEqual(self.sites(got), [('helper.py', 2, 'python.taint.eval')])

    def test_returns_sources_and_sanitizer_domains(self):
        helper = 'import html\ndef clean(x):\n    return html.escape(x)\n'
        for sink, expected in [('eval', 1), ('HttpResponse', 0)]:
            with self.subTest(sink=sink):
                got = self.scan({'helper.py': helper, 'app.py': f'from helper import clean\n{sink}(clean(input()))'})
                self.assertEqual(len(got), expected, got)
        got = self.scan({'helper.py': 'def read():\n    return input()\n',
                         'app.py': 'from helper import read\neval(read())'})
        self.assertEqual(self.sites(got), [('app.py', 2, 'python.taint.eval')])

    def test_known_constant_return_does_not_echo_argument_taint(self):
        self.assertEqual(self.scan({'helper.py': 'def clean(x):\n    return "safe"\n',
                                    'app.py': 'from helper import clean\neval(clean(input()))'}), [])

    def test_defining_globals_not_same_named_caller_bindings(self):
        for safe in (False, True):
            with self.subTest(safe=safe):
                value = '"safe"' if safe else 'input()'
                other = 'input()' if safe else '"safe"'
                got = self.scan({'helper.py': f'value={value}\ndef read():\n    return value\n',
                                 'app.py': f'from helper import read\nvalue={other}\ndef handler():\n    value={other}\n    eval(read())'})
                self.assertEqual(len(got), 0 if safe else 1, got)

    def test_helper_mutates_argument_and_returned_alias(self):
        for code in ['fill(box,input())\neval(box["x"])',
                     'alias=identity(box)\nfill(alias,input())\neval(box["x"])']:
            with self.subTest(code=code):
                got = self.scan({'helper.py': 'def fill(b,x):\n    b["x"]=x\ndef identity(b):\n    return b\n',
                                 'app.py': f'from helper import fill, identity\nbox={{}}\n{code}'})
                self.assertEqual(len(got), 1, got)

    def test_mutation_clean_control(self):
        got = self.scan({'helper.py': 'def fill(b,x):\n    b["x"]="safe"\n',
                         'app.py': 'from helper import fill\nbox={}\nfill(box,input())\neval(box["x"])'})
        self.assertEqual(got, [])

    def test_imported_defaults_are_evaluated_in_defining_module(self):
        got = self.scan({'helper.py': 'def read(x=input()):\n    return x\n',
                         'app.py': 'from helper import read\neval(read())'})
        self.assertEqual(len(got), 1, got)
        got = self.scan({'helper.py': 'def read(x="safe"):\n    return x\n',
                         'app.py': 'from helper import read\neval(read())'})
        self.assertEqual(got, [])

    def test_async_helper_effects_require_await(self):
        for expr, count in [('run(input())', 0), ('await run(input())', 1)]:
            with self.subTest(expr=expr):
                got = self.scan({'helper.py': 'async def run(x):\n    eval(x)\n',
                                 'app.py': f'from helper import run\nasync def handler():\n    {expr}'})
                self.assertEqual(len(got), count, got)

    def test_exception_payload_and_finally_mutation_cross_module(self):
        got = self.scan({'helper.py': 'def fail(x):\n    raise ValueError(x)\n',
                         'app.py': 'from helper import fail\ntry:\n    fail(input())\nexcept ValueError as e:\n    eval(str(e))'})
        self.assertEqual(len(got), 1, got)
        got = self.scan({'helper.py': 'def fill(box,x):\n    try:\n        return\n    finally:\n        box["x"]=x\n',
                         'app.py': 'from helper import fill\nbox={}\nfill(box,input())\neval(box["x"])'})
        self.assertEqual(len(got), 1, got)

    def test_import_alias_reassignment_invalidates_callable(self):
        got = self.scan({'helper.py': 'def run(x):\n    eval(x)\n',
                         'app.py': 'from helper import run\nrun=lambda x: "safe"\nrun(input())'})
        self.assertEqual(got, [])

    def test_reexport_and_package_namespace(self):
        for statement in ['from pkg import run\nrun(input())',
                          'import pkg.helper\npkg.helper.run(input())',
                          'from pkg import helper\nhelper.run(input())']:
            with self.subTest(statement=statement):
                got = self.scan({'app.py': statement,
                                 'pkg/__init__.py': 'from .helper import run\n',
                                 'pkg/helper.py': 'def run(x):\n    eval(x)\n'})
                self.assertEqual(self.sites(got), [('pkg/helper.py', 2, 'python.taint.eval')])

    def test_relative_parent_and_namespace_packages(self):
        got = self.scan({'pkg/nested/app.py': 'from ..helper import run\nrun(input())',
                         'pkg/helper.py': 'def run(x):\n    eval(x)\n'})
        self.assertEqual(self.sites(got), [('pkg/helper.py', 2, 'python.taint.eval')])

    def test_same_module_names_in_other_packages_do_not_collide(self):
        got = self.scan({'app.py': 'from one.helper import clean\neval(clean(input()))',
                         'one/helper.py': 'def clean(x):\n    return "safe"',
                         'two/helper.py': 'def clean(x):\n    return x'})
        self.assertEqual(got, [])

    def test_unselected_helpers_are_never_read_or_treated_as_clean(self):
        self.write({'helper.py': 'def clean(x):\n    return "safe"'})
        original = Path.read_text
        def read(path, *args, **kwargs):
            self.assertNotEqual(path, self.root / 'helper.py', 'Read outside selection')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read):
            got = self.scan({'app.py': 'from helper import clean\neval(clean(input()))'})
        self.assertEqual(len(got), 1, got)

    def test_stub_does_not_certify_unavailable_implementation(self):
        got = self.scan({'helper.pyi': 'def clean(x: str) -> str: ...',
                         'app.py': 'from helper import clean\neval(clean(input()))'})
        self.assertEqual(len(got), 1, got)

    def test_source_execution_is_never_needed(self):
        marker = self.root / 'executed'
        got = self.scan({'helper.py': f'open({str(marker)!r},"w").write("bad")\ndef run(x):\n    eval(x)',
                         'app.py': 'from helper import run\nrun(input())'})
        self.assertEqual(len(got), 1, got)
        self.assertFalse(marker.exists())

    def test_import_cycles_terminate_without_certifying_clean_returns(self):
        got = self.scan({'a.py': 'from b import clean\ndef wrap(x):\n    return clean(x)\neval(wrap(input()))',
                         'b.py': 'from a import wrap\ndef clean(x):\n    return "safe"'})
        self.assertEqual(len(got), 1, got)

    def test_selection_order_does_not_move_imported_sink(self):
        sources = {'app.py': 'from helper import run\nrun(input())',
                   'helper.py': '\n\ndef run(x):\n    eval(x)'}
        left = self.sites(self.scan(sources))
        right = self.sites(self.scan(sources, ['helper.py', 'app.py', 'helper.py']))
        self.assertEqual(left, right)
        self.assertEqual(left, [('helper.py', 4, 'python.taint.eval')])

    def test_suppression_belongs_to_sink_file(self):
        sources = {'app.py': 'from helper import run\nrun(input()) # ubs:ignore[python.taint.eval]',
                   'helper.py': 'def run(x):\n    eval(x)'}
        self.assertEqual(len(self.scan(sources)), 1)
        sources['helper.py'] += ' # ubs:ignore[python.taint.eval]'
        self.assertEqual(self.scan(sources), [])

    def test_disabled_rules_apply_to_imported_sinks(self):
        sources = {'app.py': 'from helper import run\nrun(input())', 'helper.py': 'def run(x):\n    eval(x)'}
        for rule in ('py.taint.eval', 'python.taint.eval'):
            self.assertEqual(self.scan(sources, disabled=[rule]), [])

    def test_malformed_buffer_cannot_swallow_next_file(self):
        got = self.scan({'broken.py': '"""unterminated', 'app.py': 'eval(input())'})
        self.assertEqual(self.sites(got), [('app.py', 1, 'python.taint.eval')])

    def test_module_variables_and_saved_callable(self):
        got = self.scan({'helper.py': 'payload=input()\ndef run(x):\n    eval(x)\nsaved=run',
                         'app.py': 'import helper as h\nh.saved(h.payload)'})
        self.assertEqual(self.sites(got), [('helper.py', 3, 'python.taint.eval')])

    def test_module_object_properties_preserve_aliases(self):
        for code in ['h.box["code"]=input()', 'alias=h.box\nalias["code"]=input()',
                     'h.fill(input())']:
            with self.subTest(code=code):
                got = self.scan({'helper.py': 'box={}\ndef fill(x):\n    box["code"]=x\ndef read():\n    return box["code"]',
                                 'app.py': f'import helper as h\n{code}\neval(h.read())'})
                self.assertEqual(len(got), 1, got)

    def test_module_callable_replacement_does_not_certify_old_clean_function(self):
        for write in ['h.clean=lambda x:x', 'def replace(m):\n    m.clean=lambda x:x\nreplace(h)',
                      'def replace():\n    import helper\n    helper.clean=lambda x:x\nreplace()']:
            with self.subTest(write=write):
                got = self.scan({'helper.py': 'def clean(x):\n    return "safe"',
                                 'app.py': f'import helper as h\n{write}\neval(h.clean(input()))'})
                self.assertEqual(len(got), 1, got)

    def test_imported_framework_dependency_inputs(self):
        for body, expected in [('return code', 1), ('return "safe"', 0), ('yield code', 1)]:
            with self.subTest(body=body):
                got = self.scan({'helper.py': f'from fastapi import Query\ndef provide(code=Query()):\n    {body}',
                                 'app.py': 'from fastapi import Depends\nfrom helper import provide\ndef route(x=Depends(provide)):\n    eval(x)'})
                self.assertEqual(len(got), expected, got)

    def test_long_import_chain_has_no_recursive_loader_cutoff(self):
        sources = {f'm{i}.py': f'from m{i+1} import read\ndef forward():\n    return read()\nread=forward'
                   for i in range(110)}
        # Give each wrapper its own callee binding rather than rebinding read
        # into self-recursion in the source program itself.
        sources = {name: text.replace('import read', 'import read as next_read').replace('return read()', 'return next_read()')
                   for name, text in sources.items()}
        sources['m110.py'] = 'def read():\n    return input()'
        sources['app.py'] = 'from m0 import read\neval(read())'
        got = self.scan(sources)
        self.assertEqual(self.sites(got), [('app.py', 2, 'python.taint.eval')])

    def test_legacy_and_structured_entrypoints_agree(self):
        self.write({'app.py': 'from helper import run\nrun(input())', 'helper.py': 'def run(x):\n    eval(x)'})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            taint_py.main(['taint', str(self.root)])
        self.assertIn('py.taint.eval\t1\thelper.py:2 ', output.getvalue())

    def test_taint_project_is_not_pruned_by_per_file_literal_prefilter(self):
        from ubs_core import py_scan
        files = self.write({'helper.py': 'def read():\n    return input()',
                            'app.py': 'from helper import read\neval(read())'})
        class EmptyPrefilter:
            def filter_files_for_analyzer(self, name, files):
                return []
        sink = io.StringIO()
        py_scan.run_analyzers(files, sink, taint=True, prefilter=EmptyPrefilter(), project_dir=str(self.root))
        records = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual([(Path(r['path']).name, r['line']) for r in records], [('app.py', 2)])


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for actual scanner')
class PythonModuleRunnerTests(unittest.TestCase):
    setUp = PythonModuleTests.setUp
    write = PythonModuleTests.write

    def test_helper_edits_selection_and_warm_cache(self):
        self.write({'helper.py': 'def clean(x):\n    return "safe"',
                    'app.py': 'from helper import clean\neval(clean(input()))'})
        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', XDG_CACHE_HOME=str(self.root / 'cache'),
                   UBS_CACHE_DIR=str(self.root / 'cache'), PYTHONDONTWRITEBYTECODE='1')
        def scan(*files):
            targets = [str(self.root / name) for name in files] if files else [str(self.root)]
            result = subprocess.run([str(ROOT / 'ubs'), *targets,
                                     '--only=python', '--format=json', '--ci'],
                                    cwd=self.root, env=env, capture_output=True, text=True, timeout=120)
            self.assertIn(result.returncode, (0, 1), result.stderr + result.stdout)
            doc = json.loads(result.stdout)
            findings = [f for f in doc['findings'] if f['rule_id'] == 'python.taint.eval']
            return findings, doc['scanners'][0]['extras']['profile']['cache_hits']
        self.assertEqual(scan()[0], [])
        clean, hits = scan()
        self.assertEqual(clean, [])
        self.assertGreaterEqual(hits, 2, 'Control must actually exercise a warm per-file cache')
        self.write({'helper.py': 'def clean(x):\n    return x'})
        self.assertEqual(len(scan()[0]), 1)
        self.write({'helper.py': 'def clean(x):\n    return "safe"'})
        self.assertEqual(scan()[0], [])
        self.assertEqual(len(scan('app.py')[0]), 1)

    def test_staged_cross_module_flow_uses_index_not_worktree_bytes(self):
        self.write({'helper.py': 'def clean(x):\n    return "safe"',
                    'app.py': 'from helper import clean\neval(clean(input()))'})
        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', PYTHONDONTWRITEBYTECODE='1')
        for args in (['init', '-q', '-b', 'main'], ['add', 'app.py', 'helper.py'],
                     ['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'base']):
            subprocess.run(['git', *args], cwd=self.root, env=env, check=True, capture_output=True, timeout=20)
        self.write({'helper.py': 'def clean(x):\n    return x',
                    'app.py': 'from helper import clean\neval(clean(input()))\n# staged caller'})
        subprocess.run(['git', 'add', 'app.py', 'helper.py'], cwd=self.root, env=env, check=True, timeout=20)
        self.write({'helper.py': 'def clean(x):\n    return "safe"'})
        result = subprocess.run([str(ROOT / 'ubs'), '--staged', '--only=python', '--format=json', '--ci'],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        found = [f for f in json.loads(result.stdout)['findings'] if f['rule_id'] == 'python.taint.eval']
        self.assertEqual([(Path(f['file']).name, f['line']) for f in found], [('app.py', 2)])

    def test_sarif_imported_sink_location(self):
        self.write({'helper.py': '\n\ndef run(x):\n    eval(x)',
                    'app.py': 'from helper import run\nrun(input())'})
        result = subprocess.run([str(ROOT / 'ubs'), str(self.root), '--only=python', '--format=sarif', '--ci'],
                                cwd=self.root, env=dict(os.environ, UBS_NO_AUTO_UPDATE='1'),
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        found = [f for run in json.loads(result.stdout)['runs'] for f in run['results']
                 if f['ruleId'] == 'python.taint.eval']
        self.assertEqual(len(found), 1, result.stdout)
        location = found[0]['locations'][0]['physicalLocation']
        self.assertEqual(location['region']['startLine'], 4)
        self.assertTrue(location['artifactLocation']['uri'].endswith('helper.py'), location)


if __name__ == '__main__':
    unittest.main()
