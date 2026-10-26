"""The worklist must find exactly what a from-scratch re-solve finds.

The analyzer reuses a function's previous solve when nothing it read has
changed, skips re-joining an unchanged state into an exception collector,
and does not re-solve callback contexts inherited from earlier modules.
Each shape below makes a summary, default or namespace change only after its
reader was solved; the findings must equal those of the same scan with every
reuse disabled, and the cross-module shapes must report the known flow.
"""
from __future__ import annotations

import ast
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
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.taint_flow import AnalysisLimit, Budget

SHAPES = {
    # The module's value facts are unchanged when the factory's second
    # callable alternative becomes known. Its binding still invalidates
    # handlers solved against the earlier, harmless-only namespace.
    'late_global_callable': {'app.py': '''
import os
def harmless(value):
    return None
def build():
    callback = harmless
    if condition:
        callback = get_executor()
    return callback
def get_executor():
    return os.system
command = build()
def handler():
    command(input())
'''},
    # Caller solved before a callee chain whose summaries settle one per pass.
    'late_dependency': {'app.py': '''
import os
def a(x):
    return b(x)
def b(x):
    return c(x)
def c(x):
    return d(x)
def d(x):
    return x
def handler():
    os.system(a(input()))
'''},
    'mutual_recursion': {'app.py': '''
import os
def even(x, n):
    if n == 0:
        return x
    return odd(x, n - 1)
def odd(x, n):
    if n == 0:
        return "safe"
    return even(x, n - 1)
def handler():
    os.system(odd(input(), 5))
'''},
    # Taint reaches the sink only on the third iteration.
    'rotating_loop': {'app.py': '''
import os
def ident(v):
    return v
def f():
    a = "x"; b = "y"; c = input()
    while True:
        os.system(a)
        a = ident(b)
        b = c
        c = "z"
'''},
    # Only the exception edge carries the tainted value to the sink.
    'exception_edge': {'app.py': '''
import os
def f():
    v = "safe"
    try:
        v = relay()
        int("x")
        v = "safe"
    except ValueError:
        os.system(v)
def relay():
    return input()
'''},
    # A default is written by a job solved after its reader.
    'late_default': {'app.py': '''
import os
def use():
    f = make()
    os.system(f())
def make():
    return lambda v=relay(): v
def relay():
    return relay2()
def relay2():
    return input()
'''},
    'cross_module_callbacks': {
        'z_helpers.py': '''
def apply(cb, v):
    return cb(v)
def apply_sink(cb, v):
    cb(v)
''',
        'a_app.py': '''
import os
from z_helpers import apply, apply_sink
from m_callbacks import passthru, runner
def one():
    os.system(apply(passthru, input()))
def two():
    apply_sink(runner, input())
''',
        'm_callbacks.py': '''
import os
from z_helpers import apply
def passthru(v):
    return apply(ident, v)
def ident(v):
    return v
def runner(v):
    os.system(v)
''',
    },
    # A context solved in b.py is reused (not re-solved) by c.py.
    'inherited_context': {
        'lib.py': '''
def apply(cb, v):
    return cb(v)
def twice(cb, v):
    return apply(cb, apply(cb, v))
''',
        'b.py': '''
from lib import twice
def ident(v):
    return v
def go(v):
    return twice(ident, v)
''',
        'c.py': '''
import os
from lib import twice, apply
from b import ident, go
def main():
    os.system(go(input()))
    os.system(twice(ident, input()))
    os.system(apply(ident, input()))
''',
    },
    'call_global_refresh': {'app.py': '''
import asyncio
import os
shared = ["safe"]
def read():
    return shared[0]
async def later():
    os.system(shared[0])
def handler():
    os.system(read())
    pending = later()
    shared[0] = input()
    os.system(read())
    asyncio.run(pending)
'''},
    'exception_branch_heap': {'app.py': '''
import os
def f(flag):
    shared = ["safe"]
    target = eval
    try:
        if flag:
            shared[0] = input()
            target = os.system
        int("invalid")
    except ValueError:
        target(shared[0])
'''},
    'exception_comprehension': {'app.py': '''
import os
def f():
    shared = ["safe"]
    try:
        values = [shared.append(input()) for n in range(3)]
        int("invalid")
    except ValueError:
        os.system(shared[0])
'''},
}

EXPECTED = {
    'late_global_callable': {('app.py', 13)},
    'late_dependency': {('app.py', 11)},
    'mutual_recursion': {('app.py', 11)},
    'rotating_loop': {('app.py', 7)},
    'exception_edge': {('app.py', 9)},
    'late_default': {('app.py', 4)},
    'cross_module_callbacks': {('a_app.py', 5), ('m_callbacks.py', 8)},
    'inherited_context': {('c.py', 5), ('c.py', 6), ('c.py', 7)},
    'call_global_refresh': {('app.py', 7), ('app.py', 12)},
    'exception_branch_heap': {('app.py', 11)},
    'exception_comprehension': {('app.py', 8)},
}


def fresh_exception_join(flow, state):
    """Reference collector: join the entire state at every possible raise."""
    if state.reachable and flow.exception_states:
        flow.exception_states[-1] = taint_py._join_states(flow.exception_states[-1], state)


class WorklistReuseTests(unittest.TestCase):
    def scan(self, sources):
        with tempfile.TemporaryDirectory(prefix='ubs-python-worklist-') as tmp:
            root = Path(tmp).resolve()
            files = []
            for name, source in sources.items():
                path = root / name
                path.write_text(source.lstrip('\n'), encoding='utf-8')
                files.append(path)
            return sorted((str(path.relative_to(root)), rule, line, column, description)
                          for path, rule, line, column, description in taint_py._Project(files, root).findings())

    def test_prepared_syntax_preserves_child_scopes_and_deferred_imports(self):
        tree = ast.parse('''
import os as system
def outer(value):
    global external
    def child():
        nonlocal value
        yield value
    external = [value for value in value if (seen := value)]
    return lambda: value
class Factory:
    import builtins as builtins_alias
    def method(self):
        from mod import callback
        return callback
''')
        engine = taint_py._Analysis(tree)
        outer = tree.body[1]
        child = outer.body[1]
        callback = outer.body[-1].value
        factory = tree.body[2]
        method = factory.body[1]
        comprehension = outer.body[2].value
        self.assertEqual(engine.locals[tree], {'system', 'outer', 'Factory'})
        self.assertEqual(engine.locals[outer], {'value', 'child', 'seen'})
        self.assertEqual(engine.locals[child], set())
        self.assertEqual(engine.locals[method], {'self', 'callback'})
        self.assertEqual(engine.locals[comprehension], {'value'})
        self.assertEqual(engine.generators, {child})
        self.assertIs(engine.enclosing(callback), outer)
        self.assertIs(engine.enclosing(method), factory)
        self.assertEqual([node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
                          for node in engine.imports], ['os', 'builtins', 'mod'])
        self.assertEqual(engine.functions, [node for node in ast.walk(tree)
                         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))])

    def test_namespace_changes_recompute_handlers_without_new_value_facts(self):
        source = SHAPES['late_global_callable']['app.py']
        for callback, expected in [('os.system', {('app.py', 13)}), ('harmless', set())]:
            with self.subTest(callback=callback):
                findings = self.scan({'app.py': source.replace('return os.system', f'return {callback}')})
                self.assertEqual({(path, line) for path, _, line, _, _ in findings}, expected, findings)

    def test_state_inequality_observes_non_value_flow_facts(self):
        original = taint_py._State({'value': taint_py.CLEAN}, {'callback': 'print'})
        mutations = (
            lambda state: state.bindings.update(callback='eval'),
            lambda state: state.references.update(value=frozenset({'object'})),
            lambda state: state.heap.update(object=frozenset({taint_py.TaintTrace('input')})),
            lambda state: state.mutated.add('object'),
            lambda state: setattr(state, 'reachable', False),
        )
        self.assertEqual(original, original.copy())
        self.assertFalse(original != original.copy())
        for mutate in mutations:
            changed = original.copy()
            mutate(changed)
            self.assertFalse(original == changed)
            self.assertTrue(original != changed)

    def test_temporary_global_callable_binding_survives_nested_helpers(self):
        for initial, active, expected in (
            ('print', 'os.system', {('app.py', 4)}),
            ('os.system', 'print', set()),
        ):
            with self.subTest(initial=initial, active=active):
                findings = self.scan({'app.py': f'''import os
runner = {initial}
def invoke(value):
    return runner(value)
def forward(value):
    return invoke(value)
saved = runner
runner = {active}
forward(input())
runner = saved
'''})
                self.assertEqual({(path, line) for path, _, line, _, _ in findings}, expected, findings)

    def test_prepared_scopes_keep_closure_flow_through_shadowing_comprehension(self):
        for actual, expected in [('input()', {('app.py', 7)}), ('"safe"', set())]:
            with self.subTest(actual=actual):
                findings = self.scan({'app.py': f'''
import os
def outer(value):
    def child():
        return value
    values = [child() for value in ("safe",)]
    return values
os.system(outer({actual})[0])
'''})
                self.assertEqual({(path, line) for path, _, line, _, _ in findings}, expected, findings)

    def test_opaque_import_cycle_does_not_reassign_foreign_callback_jobs(self):
        sources = {
            'a_helpers.py': 'def apply(callback, value):\n    return callback(value)\n',
            'b_app.py': '''
import os
from a_helpers import apply
def relay(value):
    return value
os.system(apply(relay, input()))
''',
            'z_left.py': 'import z_right\nflag = unknown()\ndef left(value):\n    return value\n',
            'z_right.py': 'import z_left\nflag = unknown()\ndef right(value):\n    return value\n',
        }
        initialize = taint_py._Flow.__init__
        misplaced = []

        def check_owner(flow, engine, scope):
            if (engine is not None and engine.project is None
                    and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                    and scope not in engine.functions):
                misplaced.append(getattr(scope, 'name', '<lambda>'))
            initialize(flow, engine, scope)

        with patch.object(taint_py._Flow, '__init__', check_owner):
            findings = self.scan(sources)
        self.assertEqual({(path, line) for path, _, line, _, _ in findings}, {('b_app.py', 5)}, findings)
        self.assertEqual(misplaced, [], 'Opaque imports must not change a function\'s defining module')

    def test_opaque_cycle_cannot_erase_a_prior_callable_summary(self):
        for source, expected in [('input()', {('b_app.py', 6), ('zz_observe.py', 5)}),
                                 ('"safe"', set())]:
            with self.subTest(source=source):
                findings = self.scan({
                    'a_helpers.py': 'def apply(callback, value):\n    return callback(value)\n',
                    'b_app.py': f'''
import os
from a_helpers import apply
q = {source}
def relay(value):
    return q
os.system(apply(relay, "safe"))
''',
                    'z_left.py': 'import z_right\nflag = unknown()\n',
                    'z_right.py': 'import z_left\nflag = unknown()\n',
                    'zz_observe.py': '''
import os
from a_helpers import apply
from b_app import relay
import z_left
os.system(apply(relay, "safe"))
''',
                })
                self.assertEqual({(path, line) for path, _, line, _, _ in findings}, expected, findings)

    def test_reuse_matches_a_full_re_solve(self):
        for name, sources in SHAPES.items():
            with self.subTest(shape=name):
                reused = self.scan(sources)
                with patch.object(taint_py._Analysis, 'reads_current', lambda self, reads: False), \
                        patch.object(taint_py._Flow, 'possible_exception', fresh_exception_join):
                    fresh = self.scan(sources)
                self.assertEqual(reused, fresh)
                self.assertEqual({(path, line) for path, _, line, _, _ in reused}, EXPECTED[name], reused)

    def test_interned_formals_match_fresh_global_traces(self):
        class FreshGlobals(dict):
            def __getitem__(self, name):
                # The original solver allocated these immutable formal
                # inputs for every job/read. Concrete call/heap evidence
                # must match when the lexical templates are shared instead.
                key = f'@global:{name}'
                return (frozenset({taint_py.TaintTrace(name, parameter=key, path=(name,))}),
                        frozenset({key}), taint_py._SymbolicValue(key))

        initialize = taint_py._Analysis.__init__

        def fresh_globals(engine, *args, **kwargs):
            initialize(engine, *args, **kwargs)
            engine.global_symbols = FreshGlobals(engine.global_symbols)

        for name, sources in SHAPES.items():
            with self.subTest(shape=name):
                interned = self.scan(sources)
                with patch.object(taint_py._Analysis, '__init__', fresh_globals):
                    fresh = self.scan(sources)
                self.assertEqual(interned, fresh)
                self.assertEqual({(path, line) for path, _, line, _, _ in interned}, EXPECTED[name], interned)

    def test_exception_deltas_match_complete_joins(self):
        trace = taint_py.TaintTrace('input', path=('input', 'long', 'route'))
        shorter = taint_py.TaintTrace('input', path=('input', 'short'))
        dirty = frozenset({trace})
        clean = taint_py.CLEAN
        state = taint_py._State({'value': clean}, {'eval': None, 'target': 'eval'})
        state.references['value'] = frozenset({'object'})
        state.heap['object'] = clean
        flow = taint_py._Flow(None, None)
        flow.exception_states.append(None)
        reference = None

        def compare():
            nonlocal reference
            reference = taint_py._join_states(reference, state)
            flow.possible_exception(state)
            collected = flow.exception_states[-1]
            self.assertEqual(collected, reference)
            # TaintTrace equality intentionally ignores evidence paths. Check
            # those explicitly so retaining a longer trace cannot pass green.
            for actual, expected in ((collected, reference), (collected.heap, reference.heap)):
                self.assertEqual({name: sorted(trace.path for trace in fact) for name, fact in actual.items()},
                                 {name: sorted(trace.path for trace in fact) for name, fact in expected.items()})

        compare()
        state['value'] = dirty
        state.heap['object'] = dirty
        state.mutated.add('object')
        compare()
        state['value'] = frozenset({shorter})
        state.heap['object'] = frozenset({shorter})
        state.bindings.pop('eval')  # Missing bindings contribute implicit identities.
        state.bindings['target'] = 'os.system'
        state.references['value'] = frozenset({'other'})
        compare()
        state.pop('value')  # Missing facts/references, conversely, are neutral.
        state.references.pop('value')
        state.heap.pop('object')
        compare()
        state.bindings['eval'] = None
        state['value'] = clean
        state.references['value'] = taint_py.NO_REFERENCES
        compare()
        compare()


class WorkLimitCompletionTests(unittest.TestCase):
    """A work limit bounds analysis without manufacturing a clean result."""

    def setUp(self):
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='python-taint-limit-', dir=artifacts))

    def run(self, result=None):
        print(f'[{self.id()}] RUN', flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, 'test_case', None) is self
                     for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def source(self, name, text):
        path = self.root / name
        path.write_text(text, encoding='utf-8')
        return path

    def test_tabular_entrypoint_keeps_findings_and_returns_incomplete(self):
        from ubs_core.taint_flow import Budget

        first = self.source('a_first.py', 'eval(input())\n')
        failed = self.source('m_failed.py', 'eval(input())\n')
        last = self.source('z_last.py', 'eval(input())\n')
        budgets = iter((Budget(), Budget(0), Budget()))
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(taint_py, 'Budget', side_effect=lambda _limit: next(budgets)), \
                patch.object(taint_py, 'iter_files', return_value=iter((first, failed, last))), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = taint_py.main(['taint_py', str(self.root)])
        self.assertEqual(status, 2)
        rule, count, samples = stdout.getvalue().rstrip('\n').split('\t')
        self.assertEqual((rule, count), ('py.taint.eval', '2'))
        self.assertIn('a_first.py:1', samples)
        self.assertIn('z_last.py:1', samples)
        self.assertNotIn('m_failed.py:1', samples)
        self.assertIn('m_failed.py', stderr.getvalue())
        self.assertIn('work limit exceeded', stderr.getvalue())

    def test_recursive_and_loop_work_limits_raise_instead_of_returning_clean(self):
        sources = {
            'recursive.py': '''def relay(value):
    if condition:
        return relay(value)
    return value
eval(relay(input()))
''',
            'mutual.py': '''def left(value):
    return right(value)
def right(value):
    if condition:
        return left(value)
    return value
eval(left(input()))
''',
            'loop.py': '''def forward():
    a = "safe"
    b = "safe"
    c = input()
    while condition:
        eval(a)
        a = b
        b = c
forward()
''',
        }
        for name, source in sources.items():
            with self.subTest(shape=name):
                path = self.source(name, source)
                findings = list(taint_py.scan_file_findings(path))
                self.assertEqual([rule for rule, *_ in findings], ['py.taint.eval'], findings)
                with patch.object(taint_py, 'Budget', return_value=Budget(0)), \
                        self.assertRaises(AnalysisLimit) as raised:
                    list(taint_py.scan_file_findings(path))
                self.assertIn('work limit exceeded', str(raised.exception))
                self.assertIn('incomplete', str(raised.exception))

    def test_default_budget_preserves_recursive_cross_module_callback_domains(self):
        files = [
            self.source('left.py', '''import right
def relay(callback, value, n):
    if n:
        return right.relay(callback, value, n - 1)
    return callback(value)
'''),
            self.source('right.py', '''import left
def relay(callback, value, n):
    return left.relay(callback, value, n)
'''),
            self.source('app.py', '''import html
import left
value = left.relay(html.escape, input(), 3)
HttpResponse(value)
eval(value)
clean = left.relay(html.escape, "safe", 3)
eval(clean)
'''),
        ]
        findings = list(taint_py._Project(files, self.root).findings())
        self.assertEqual([(path.name, rule, line) for path, rule, line, _, _ in findings],
                         [('app.py', 'py.taint.eval', 5)], findings)
        self.assertIn('input', findings[0][-1])

    def test_failed_import_cycle_keeps_completed_and_later_component_findings(self):
        # Engine creation follows the selected file order. The failing engine
        # belongs to a genuine import SCC; its peer must not publish a partial
        # namespace as a successfully analyzed dependency.
        files = [
            self.source('a_first.py', 'eval(input())\n'),
            self.source('b_left.py', '''import c_right
def relay(value):
    return c_right.relay(value)
'''),
            self.source('c_right.py', '''import b_left
def relay(value):
    if condition:
        return b_left.relay(value)
    return value
'''),
            self.source('z_last.py', 'eval(input())\n'),
        ]
        for failed_index in (1, 2):
            with self.subTest(failed_module=files[failed_index].name):
                budgets = [Budget() for _ in files]
                budgets[failed_index] = Budget(0)
                findings = []
                with patch.object(taint_py, 'Budget', side_effect=budgets), \
                        self.assertRaises(AnalysisLimit) as raised:
                    project = taint_py._Project(files, self.root)
                    findings.extend(project.findings())
                self.assertEqual([(path.name, rule, line) for path, rule, line, _, _ in findings],
                                 [('a_first.py', 'py.taint.eval', 1),
                                  ('z_last.py', 'py.taint.eval', 1)], findings)
                self.assertIn(files[failed_index].name, str(raised.exception))
                self.assertIn('work limit exceeded', str(raised.exception))
                failed_engines = {engine for path, _, engine, _ in project.sources
                                  if path.name in {'b_left.py', 'c_right.py'}}
                self.assertFalse(project.ready & failed_engines,
                                 'A failed import component cannot publish completed namespaces')

    def test_python_scan_reports_native_budget_failure_and_does_not_cache_it(self):
        # Run the production Python driver, including its real registered
        # analyzers, findings sink, error envelope and cache admission barrier.
        # Only the available taint work is constrained; no producer is replaced.
        from ubs_core import py_scan

        files = [
            self.source('a_first.py', 'eval(input())\n'),
            self.source('m_recursive.py', '''def relay(value):
    if condition:
        return relay(value)
    return value
eval(relay(input()))
'''),
            self.source('z_last.py', 'eval(input())\n'),
        ]
        selected = self.root / 'files'
        selected.write_bytes(b''.join([os.fsencode(path) + b'\0' for path in files]))
        sink, report, text = (self.root / name for name in ('sink.jsonl', 'report.json', 'report.txt'))
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('UBS_', 'XDG_'))}
        environment.update(UBS_CACHE_DIR=str(self.root / 'cache'), UBS_NO_CACHE='0',
                           UBS_PROFILE='1', PYTHONDONTWRITEBYTECODE='1')
        args = ['--files-from', str(selected), '--sink', str(sink), '--json-out', str(report),
                '--text-out', str(text), '--project-dir', str(self.root), '--jobs', '1',
                '--skip', ','.join(str(number) for number in range(1, 24) if number != 7)]

        def scan():
            stderr = io.StringIO()
            with patch.dict(os.environ, environment, clear=True), contextlib.redirect_stderr(stderr):
                code = py_scan.main(args)
            try:
                document = json.loads(report.read_text(encoding='utf-8'))
                records = [json.loads(line) for line in sink.read_text(encoding='utf-8').splitlines()]
            except json.JSONDecodeError as exc:
                self.fail(f'Invalid scan output: {exc}\n{stderr.getvalue()}')
            return code, document, records, text.read_text(encoding='utf-8'), stderr.getvalue()

        for attempt in range(2):
            with self.subTest(attempt=attempt), \
                    patch.object(taint_py, 'Budget', side_effect=[Budget(), Budget(0), Budget()]):
                result = scan()
            code, document, records, rendered, stderr = result
            self.assertEqual(code, 2, result)
            self.assertEqual(document['status'], 'partial', result)
            self.assertEqual(document['module_error'], 'ANALYZER_ERROR', result)
            self.assertIn('work limit exceeded', stderr, result)
            self.assertIn('m_recursive.py', stderr, result)
            self.assertNotIn('good:', rendered, result)
            self.assertEqual(document['profile']['cache_hits'], 0, result)
            self.assertEqual([(Path(row['path']).name, row['rule'], row['line'])
                              for row in records if row['rule'].startswith('python.taint.')],
                             [('a_first.py', 'python.taint.eval', 1),
                              ('z_last.py', 'python.taint.eval', 1)], result)
            self.assertFalse(list((self.root / 'cache').glob('*/files/**/*.json')),
                             'A partial taint scan must not admit fresh cache entries')

        # Recover with the same source and the normal budget. All three
        # positives must survive both a cold file pass and a warm file cache.
        for hits in (0, 3):
            result = scan()
            code, document, records, _, _ = result
            self.assertEqual(code, 1, result)
            self.assertEqual(document['status'], 'ok', result)
            self.assertEqual(document['profile']['cache_hits'], hits, result)
            self.assertEqual([(Path(row['path']).name, row['rule'], row['line'])
                              for row in records if row['rule'].startswith('python.taint.')],
                             [('a_first.py', 'python.taint.eval', 1),
                              ('m_recursive.py', 'python.taint.eval', 5),
                              ('z_last.py', 'python.taint.eval', 1)], result)

    def test_failed_foreign_context_is_not_reused_as_a_completed_summary(self):
        files = [
            self.source('aa_lib.py', 'def apply(callback, value):\n    return callback(value)\n'),
            self.source('bb_failed.py', '''from aa_lib import apply
apply(eval, input())
'''),
            self.source('zz_later.py', '''import sys
from aa_lib import apply
apply(eval, sys.argv[1])
'''),
        ]
        project = taint_py._Project(files, self.root)
        engines = {path.name: engine for path, _, engine, _ in project.sources}
        library = engines['aa_lib.py']
        later = engines['zz_later.py']
        initialize = taint_py._Flow.__init__
        analyze = taint_py._Analysis.analyze
        interrupted = False

        def stop_first_context(flow, engine, scope):
            nonlocal interrupted
            if (engine is library and library in project.ready
                    and getattr(scope, 'name', '') == 'apply' and not interrupted):
                # The module's base summary is complete; a caller has just
                # requested a new callback-specific summary. Exhaust the real
                # owner budget at that boundary, leaving a provisional shared
                # key for failure recovery to invalidate.
                interrupted = True
                library.budget.spend(library.budget.remaining + 1)
            initialize(flow, engine, scope)

        def allow_later_component(engine):
            if engine is later:
                # Give the next caller enough work to independently finish.
                # If it mistakes the failed context for an inherited completed
                # summary, it will silently reuse bottom and miss this sink.
                library.budget = Budget()
            return analyze(engine)

        findings = []
        with patch.object(taint_py._Flow, '__init__', stop_first_context), \
                patch.object(taint_py._Analysis, 'analyze', allow_later_component), \
                self.assertRaises(AnalysisLimit) as raised:
            findings.extend(project.findings())
        self.assertTrue(interrupted, 'The test must reach a specialized foreign callback context')
        self.assertIn('bb_failed.py', str(raised.exception))
        self.assertIn(later, project.ready)
        self.assertEqual([(path.name, rule, line) for path, rule, line, _, _ in findings],
                         [('aa_lib.py', 'py.taint.eval', 2)], findings)
        self.assertIn('sys.argv', findings[0][-1])
        self.assertNotIn('input', findings[0][-1])
        self.assertIsNone(library.reads)
        self.assertIsNone(library.writes)

    def test_cli_bounds_natural_callback_context_explosion_without_losing_other_files(self):
        # A transposition and a rotation generate all permutations of eight
        # distinct callbacks. The source is small, but exact context discovery
        # has factorial growth. Exercise the default work limit through the
        # real CLI, with neither mocked budgets nor a test-only runtime knob.
        names = [f'cb{index}' for index in range(8)]
        swapped = [names[1], names[0], *names[2:]]
        rotated = [*names[1:], names[0]]
        lines = [f'def rotate({", ".join(names)}, value):',
                 '    if condition_a:',
                 f'        return rotate({", ".join(swapped)}, value)',
                 '    if condition_b:',
                 f'        return rotate({", ".join(rotated)}, value)',
                 '    return cb0(value)', '']
        for index in range(8):
            lines.extend([f'def ident{index}(value):', '    return value', ''])
        arguments = ', '.join(f'ident{index}' for index in range(8))
        lines.extend([f'eval(rotate({arguments}, input()))', ''])
        sources = self.root / 'sources'
        sources.mkdir()
        self.source('sources/a_first.py', 'eval(input())\n')
        self.source('sources/m_callbacks.py', '\n'.join(lines))
        self.source('sources/z_last.py', 'eval(input())\n')
        temporary = self.root / 'temporary'
        temporary.mkdir()
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('UBS_', 'XDG_'))}
        environment.update(UBS_CACHE_DIR=str(self.root / 'cache'), UBS_NO_CACHE='0',
                           UBS_PROFILE='1', UBS_NO_AUTO_UPDATE='1', UBS_KEEP_TEMP='1',
                           PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(temporary))
        skip = ','.join(str(number) for number in range(1, 24) if number != 7)
        try:
            result = subprocess.run([str(ROOT / 'ubs'), str(sources), '--only=python',
                                     '--ci', '--format=json', '--skip-python=' + skip],
                                    cwd=self.root, env=environment, capture_output=True,
                                    text=True, timeout=30)
        except subprocess.TimeoutExpired as exc:
            self.fail(f'Unbounded callback-context expansion: {exc}')
        (self.root / 'native-result.json').write_text(result.stdout, encoding='utf-8')
        (self.root / 'native-stderr.log').write_text(result.stderr, encoding='utf-8')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'Invalid partial scan output: {exc}\n{result.stdout}\n{result.stderr}')
        self.assertEqual(report['status'], 'partial', report)
        self.assertEqual(report['totals']['files'], 3, report)
        self.assertIn('work limit exceeded', result.stdout + result.stderr)
        self.assertIn('m_callbacks.py', result.stdout + result.stderr)
        self.assertEqual(report['profile']['cache_hits'], 0, report)
        self.assertEqual([(Path(row['file']).name, row['rule_id'], row['line'])
                          for row in report['findings'] if row['rule_id'].startswith('python.taint.')],
                         [('a_first.py', 'python.taint.eval', 1),
                          ('z_last.py', 'python.taint.eval', 1)], report)
        self.assertFalse(list((self.root / 'cache').glob('*/files/**/*.json')),
                         'A naturally exhausted scan must not admit partial cache entries')


if __name__ == '__main__':
    unittest.main()
