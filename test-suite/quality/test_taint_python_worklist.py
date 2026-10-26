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
import weakref
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.py_detectors import header_injection
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

    def test_contextual_default_read_between_writes_preserves_value(self):
        helpers = '''def factory(callback):
    def target(value=callback()):
        return value
    return target
def invoke(callback):
    return callback()
'''
        application = '''import os
def dirty():
    return input()
def clean():
    return 'safe'
def choose_clean():
    return choose2()
def choose2():
    return choose3()
def choose3():
    return clean
def main():
    a = factory(dirty)
    value = invoke(a)
    b = factory(choose_clean())
    os.system(value)
main()
'''
        for dirty in (True, False):
            selected = application if dirty else application.replace('a = factory(dirty)', 'a = factory(clean)')
            standalone = helpers + selected
            # The later factory call cannot replace a value already returned
            # by the first closure. Execute only this authored witness, with
            # input and the command sink replaced, to establish the control.
            with patch('builtins.input', return_value='external-input'), patch('os.system') as sink:
                exec(compile(standalone, 'default-order-witness.py', 'exec'), {})  # ubs:ignore[py.security.eval-exec-usage,py.eval-exec] - fixed authored witness; input and os.system are mocked
            sink.assert_called_once_with('external-input' if dirty else 'safe')
            cases = (
                {'app.py': standalone},
                {'helpers.py': helpers, 'app.py': 'from helpers import factory, invoke\n' + selected},
            )
            for sources in cases:
                with self.subTest(dirty=dirty, files=tuple(sources)):
                    findings = self.scan(sources)
                    if not dirty:
                        self.assertEqual(findings, [])
                        continue
                    line = sources['app.py'].splitlines().index('    os.system(value)') + 1
                    self.assertEqual(findings, [('app.py', 'py.taint.command', line, 5,
                                               'input( -> target() -> value -> subprocess execution')])

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


class CompletedSummaryReuseTests(unittest.TestCase):
    """Completed libraries and compact job storage keep their full semantics."""

    def setUp(self):
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='python-taint-completed-', dir=artifacts))

    def run(self, result=None):
        print(f'[{self.id()}] RUN', flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, 'test_case', None) is self
                     for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def project(self, name, sources):
        root = self.root / name
        root.mkdir()
        files = []
        for filename, source in sources.items():
            path = root / filename
            path.write_text(source, encoding='utf-8')
            files.append(path)
        return taint_py._Project(files, root)

    def test_ready_base_summaries_do_not_charge_each_importer_again(self):
        solve = taint_py._Analysis.solve_function
        for actual in ('input()', '"trusted"'):
            budgets = []
            for count in (1, 8):
                with self.subTest(actual=actual, importers=count):
                    sources = {'lib.py': 'def ident(value):\n    return value\n'}
                    sources.update({f'app{index}.py':
                                    'from lib import ident\ndef main():\n'
                                    f'    eval(ident({actual}))\n'
                                    for index in range(count)})
                    project = self.project(f'{count}-{len(budgets)}-{actual == "input()"}', sources)
                    library = next(engine for path, _, engine, _ in project.sources
                                   if path.name == 'lib.py')
                    ready_foreign, own = [], []

                    def observe(engine, function, context):
                        owner = engine.owner(function)
                        if owner is library and not context:
                            if engine is library:
                                own.append(function)
                            elif owner in project.ready and owner not in project.solving:
                                ready_foreign.append(function.name)
                        return solve(engine, function, context)

                    with patch.object(taint_py._Analysis, 'solve_function', observe):
                        findings = list(project.findings())
                    budgets.append(library.work_limit - library.budget.remaining)
                    expected = {(f'app{index}.py', 'py.taint.eval', 3, 5)
                                for index in range(count)} if actual == 'input()' else set()
                    self.assertEqual({(path.name, rule, line, column)
                                      for path, rule, line, column, _ in findings}, expected, findings)
                    self.assertTrue(own, 'The defining module must solve its base summary')
                    self.assertEqual(ready_foreign, [],
                                     'A completed base summary must not be solved once per importer')
            with self.subTest(actual=actual, library_work=budgets):
                self.assertEqual(budgets[0], budgets[1],
                                 'Additional ordinary callers must not consume the completed library budget')

    def test_imported_nonreturning_summary_keeps_reachable_sink(self):
        solve = taint_py._Analysis.solve_function
        for actual in ('input()', '"trusted"'):
            with self.subTest(actual=actual):
                project = self.project(str(actual == 'input()'), {
                    'lib.py': 'def forever(value):\n    eval(value)\n'
                              '    return forever(value)\n'
                              'def never():\n    while True:\n        pass\n',
                    'app.py': 'from lib import forever, never\ndef main():\n'
                              f'    forever({actual})\n    eval(input())\n'
                              'def quiet():\n    never()\n    eval(input())\n',
                })
                repeated = []

                def observe(engine, function, context):
                    owner = engine.owner(function)
                    if (not context and owner is not engine and owner in project.ready
                            and owner not in project.solving):
                        repeated.append(function.name)
                    return solve(engine, function, context)

                with patch.object(taint_py._Analysis, 'solve_function', observe):
                    findings = list(project.findings())
                expected = {('lib.py', 'py.taint.eval', 2)} if actual == 'input()' else set()
                self.assertEqual({(path.name, rule, line) for path, rule, line, _, _ in findings},
                                 expected, findings)
                self.assertEqual(repeated, [],
                                 'A completed bottom summary is reusable even without a stored table entry')

    def test_new_callback_contexts_are_solved_for_a_ready_library(self):
        project = self.project('callbacks', {
            'lib.py': 'def apply(callback, value):\n    return callback(value)\n',
            'a.py': 'from lib import apply\nfrom html import escape\n'
                    'from django.http import HttpResponse\ndef main():\n'
                    '    HttpResponse(apply(escape, input()))\n'
                    '    eval(apply(escape, input()))\n',
            'b.py': 'from lib import apply\ndef ident(value):\n    return value\n'
                    'def main():\n    eval(apply(ident, input()))\n',
        })
        library = next(engine for path, _, engine, _ in project.sources if path.name == 'lib.py')
        solve = taint_py._Analysis.solve_function
        contexts = set()

        def observe(engine, function, context):
            if context and engine.owner(function) is library and library in project.ready:
                contexts.add(context)
            return solve(engine, function, context)

        with patch.object(taint_py._Analysis, 'solve_function', observe):
            findings = list(project.findings())
        self.assertEqual({(path.name, rule, line) for path, rule, line, _, _ in findings},
                         {('a.py', 'py.taint.eval', 6), ('b.py', 'py.taint.eval', 5)}, findings)
        self.assertEqual(len(contexts), 2,
                         'Library readiness does not prove newly requested callback identities')

    def test_active_import_cycle_does_not_freeze_provisional_base_summaries(self):
        solve = taint_py._Analysis.solve_function
        for actual in ('input()', '"trusted"'):
            with self.subTest(actual=actual):
                project = self.project(str(actual == 'input()'), {
                    'a.py': 'import b\ndef first(value):\n    if stop:\n'
                            '        return value\n    return b.second(value)\n',
                    'b.py': 'import a\ndef second(value):\n    return a.first(value)\n',
                    'main.py': f'import a\neval(a.first({actual}))\n',
                })
                active = []

                def observe(engine, function, context):
                    owner = engine.owner(function)
                    if (not context and owner is not engine and owner in project.ready
                            and owner in project.solving):
                        active.append(function.name)
                    return solve(engine, function, context)

                with patch.object(taint_py._Analysis, 'solve_function', observe):
                    findings = list(project.findings())
                expected = {('main.py', 'py.taint.eval', 2)} if actual == 'input()' else set()
                self.assertEqual({(path.name, rule, line) for path, rule, line, _, _ in findings},
                                 expected, findings)
                self.assertTrue(active,
                                'Ready namespaces in a solving import cycle still have provisional summaries')

    def test_latest_witness_survives_semantically_equal_summary_reuse(self):
        # The factory first exposes its nested wrapper. A later pass learns
        # that get_short can return leaf directly. The handler still has the
        # same source and sink, but its fresh shortest witness improves.
        source = '''def factory():
    def wrapper(value):
        return middle(value)
    if mode:
        return wrapper
    return get_short()
def middle(value):
    return leaf(value)
def get_short():
    return leaf
def leaf(value):
    eval(value)
def handler():
    factory()(input())
'''
        engine = taint_py._Analysis(ast.parse(source))
        effects = engine.analyze()
        key = ('eval', 12, 5, 'eval')
        self.assertEqual(set(effects), {key})
        handler = next(function for function in engine.functions if function.name == 'handler')
        self.assertEqual(engine.summaries[handler].effects[0][-1], effects[key])
        # Semantic equality excludes paths; the table may keep its earlier
        # longer witness. Final diagnostics must still use the latest solve.
        self.assertEqual({trace.path for trace in effects[key]},
                         {('input(', 'leaf()', 'value')})

    def test_completed_jobs_release_full_flow_states(self):
        initialize = taint_py._Flow.__init__
        for count in (25, 50):
            for actual in ('input()', '"trusted"'):
                with self.subTest(functions=count, actual=actual):
                    live = weakref.WeakSet()
                    peak = [0]

                    def observe(flow, engine, scope):
                        initialize(flow, engine, scope)
                        live.add(flow)
                        peak[0] = max(peak[0], len(live))

                    bodies = [f'def f{index}(value):\n'
                              + (f'    return f{index + 1}(value)\n' if index + 1 < count
                                 else '    return value\n') for index in range(count)]
                    source = ''.join(bodies) + f'eval(f0({actual}))\n'
                    with patch.object(taint_py._Flow, '__init__', observe):
                        effects = taint_py._Analysis(ast.parse(source)).analyze()
                    expected = {('eval', 2 * count + 1, 1, 'eval')} if actual == 'input()' else set()
                    self.assertEqual(set(effects), expected)
                    # Summaries retain everything needed by callers. Completed
                    # jobs must release expression/heap/completion state; the
                    # module and current solve need only a few live flows.
                    self.assertLessEqual(peak[0], 4,
                                         f'{count} functions retained {peak[0]} complete Flow objects')


class ProjectSharingTests(unittest.TestCase):
    """Unrelated files cost linear work; every modeled import keeps its facts."""

    def setUp(self):
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='python-taint-sharing-', dir=artifacts))

    def run(self, result=None):
        print(f'[{self.id()}] RUN', flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, 'test_case', None) is self
                     for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def project(self, name, sources):
        root = self.root / name
        root.mkdir()
        files = []
        for filename, source in sources.items():
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding='utf-8')
            files.append(path)
        return taint_py._Project(files, root)

    @staticmethod
    def observe_work(project):
        # Count entries actually visited or copied, independently of how the
        # project groups its tables. Keep every existing sharing relationship.
        counts = {'visited': 0, 'copied': 0, 'module_passes': {}}

        class Summaries(dict):
            def __iter__(self):
                for key in super().__iter__():
                    counts['visited'] += 1
                    yield key

            def copy(self):
                counts['copied'] += len(self)
                return super().copy()

        tables = {}
        for _, _, engine, _ in project.sources:
            identity = id(engine.summaries)
            if identity not in tables:
                tables[identity] = Summaries(engine.summaries)
            engine.summaries = tables[identity]
        initialize = taint_py._Flow.__init__

        def observe(flow, engine, scope):
            if scope is engine.tree:
                passes = counts['module_passes']
                passes[engine] = passes.get(engine, 0) + 1
            initialize(flow, engine, scope)

        with patch.object(taint_py._Flow, '__init__', observe):
            findings = list(project.findings())
        return findings, counts

    def test_unrelated_writer_does_not_repeat_chain_initialization(self):
        writer = ('def outer():\n    def inner(value="safe"):\n'
                  '        return value\n    return inner\n')
        for count in (16, 64):
            bodies = [f'def f{index}(value):\n'
                      + (f'    return f{index + 1}(value)\n' if index + 1 < count
                         else '    return value\n') for index in range(count)]
            for unsafe in (True, False):
                actual = 'input()' if unsafe else '"trusted"'
                source = ''.join(bodies) + f'eval(f0({actual}))\n'
                work = []
                for extra in (False, True):
                    with self.subTest(functions=count, unsafe=unsafe, unrelated_writer=extra):
                        sources = {'a_writer.py': writer} if extra else {}
                        sources['z_chain.py'] = source
                        project = self.project(f'chain-{count}-{unsafe}-{extra}', sources)
                        chain = next(engine for path, _, engine, _ in project.sources
                                     if path.name == 'z_chain.py')
                        findings, counts = self.observe_work(project)
                        work.append(chain.work_limit - chain.budget.remaining)
                        expected = {('z_chain.py', 'py.taint.eval', 2 * count + 1, 1)} if unsafe else set()
                        self.assertEqual({(path.name, rule, line, column)
                                          for path, rule, line, column, _ in findings}, expected, findings)
                        self.assertLessEqual(counts['module_passes'][chain], 4, counts)
                        self.assertLessEqual(counts['visited'], 8 * (count + 2), counts)
                with self.subTest(functions=count, unsafe=unsafe, chain_work=work):
                    self.assertEqual(work[0], work[1],
                                     'An unreachable writer cannot consume the chain module work budget')

    def test_independent_callback_modules_visit_only_linear_summary_entries(self):
        source = ('def apply(callback, value):\n    return callback(value)\n'
                  'def identity(value):\n    return value\n'
                  'def clean(value):\n    return "trusted"\n'
                  'eval(apply(identity, input()))\n'
                  'eval(apply(clean, input()))\n')
        for count in (16, 64):
            with self.subTest(modules=count):
                project = self.project(f'callbacks-{count}',
                                       {f'm{index:03}.py': source for index in range(count)})
                findings, counts = self.observe_work(project)
                expected = {(f'm{index:03}.py', 'py.taint.eval', 7, 1) for index in range(count)}
                self.assertEqual({(path.name, rule, line, column)
                                  for path, rule, line, column, _ in findings}, expected, findings)
                self.assertLessEqual(counts['visited'], 20 * count, counts)

    def test_independent_import_cycles_copy_only_linear_summary_entries(self):
        for count in (8, 32):
            with self.subTest(cycles=count):
                sources = {}
                for index in range(count):
                    left, right = f'g{index:03}_left', f'g{index:03}_right'
                    sources[left + '.py'] = (
                        f'import {right}\ndef relay(value):\n    if again:\n'
                        f'        return {right}.relay(value)\n    return value\n')
                    sources[right + '.py'] = (
                        f'import {left}\ndef relay(value):\n    return {left}.relay(value)\n')
                    sources[f'g{index:03}_app.py'] = (
                        f'from {left} import relay\neval(relay(input()))\neval(relay("trusted"))\n')
                project = self.project(f'cycles-{count}', sources)
                findings, counts = self.observe_work(project)
                expected = {(f'g{index:03}_app.py', 'py.taint.eval', 2, 1) for index in range(count)}
                self.assertEqual({(path.name, rule, line, column)
                                  for path, rule, line, column, _ in findings}, expected, findings)
                self.assertLessEqual(counts['copied'], 8 * count, counts)

    def test_namespace_exposure_keeps_implicit_descendants_and_siblings(self):
        # The resolver can expose selected descendants without a direct
        # initialization edge. This includes namespace packages, aliases,
        # relative imports, and ambiguous file/package parent identities.
        helper = 'def helper(value):\n    eval(value)\n'
        cases = (
            ({'pkg/child.py': helper}, 'zapp.py', 'import pkg\n', 'pkg.child'),
            ({'pkg/first.py': 'value = 1\n', 'pkg/second.py': helper},
             'zapp.py', 'import pkg.first\n', 'pkg.second'),
            ({'pkg/child.py': helper}, 'zapp.py', 'import pkg as alias\n', 'alias.child'),
            ({'pkg/first.py': 'value = 1\n', 'pkg/first/child.py': helper},
             'zapp.py', 'import pkg.first as alias\n', 'alias.child'),
            ({'pkg/child/deep.py': helper}, 'zapp.py', 'from pkg import child\n', 'child.deep'),
            ({'pkg/child/deep.py': helper}, 'pkg/zapp.py', 'from . import child\n', 'child.deep'),
            ({'pkg.py': 'value = 1\n', 'pkg/__init__.py': 'value = 2\n', 'pkg/child.py': helper},
             'zapp.py', 'import pkg\n', 'pkg.child'),
        )
        for index, (modules, app, imported, target) in enumerate(cases):
            for unsafe in (True, False):
                with self.subTest(case=index, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"trusted"'
                    sources = {**modules, app: imported + f'{target}.helper({actual})\n'}
                    project = self.project(f'namespace-{index}-{unsafe}', sources)
                    findings = sorted((str(path.relative_to(project.root)), rule, line, column, description)
                                      for path, rule, line, column, description in project.findings())
                    sink = next(name for name, source in modules.items() if source == helper)
                    expected = [(sink, 'py.taint.eval', 2, 5,
                                 'input( -> helper() -> value -> eval')] if unsafe else []
                    self.assertEqual(findings, expected)

    def test_namespace_foreign_writer_preserves_captured_default_order(self):
        helpers = '''def factory(callback):
    def target(value=callback()):
        return value
    return target
def invoke(callback):
    return callback()
'''
        application = '''import pkg
factory = pkg.child.factory
invoke = pkg.child.invoke
import os
def dirty():
    return input()
def clean():
    return 'safe'
def choose_clean():
    return choose2()
def choose2():
    return choose3()
def choose3():
    return clean
def main():
    a = factory(dirty)
    value = invoke(a)
    b = factory(choose_clean())
    os.system(value)
main()
'''
        for unsafe in (True, False):
            with self.subTest(unsafe=unsafe):
                selected = application if unsafe else application.replace('a = factory(dirty)', 'a = factory(clean)')
                project = self.project(f'default-{unsafe}', {'pkg/child.py': helpers, 'zapp.py': selected})
                findings = [(path.name, rule, line, column, description)
                            for path, rule, line, column, description in project.findings()]
                # A later factory invocation cannot change a value already
                # returned by the earlier closure. Keep its captured input.
                expected = [('zapp.py', 'py.taint.command', 19, 5,
                             'input( -> target() -> value -> subprocess execution')] if unsafe else []
                self.assertEqual(findings, expected)

    def test_failed_namespace_context_rolls_back_without_poisoning_other_groups(self):
        project = self.project('rollback', {
            'a_before.py': 'eval(input())\n',
            'aa_pkg/lib.py': 'def apply(callback, value):\n    return callback(value)\n',
            'bb_failed.py': 'import aa_pkg\naa_pkg.lib.apply(eval, input())\n',
            'm_independent.py': 'eval(input())\n',
            'zz_later.py': 'import sys\nimport aa_pkg\naa_pkg.lib.apply(eval, sys.argv[1])\n',
        })
        engines = {path.name: engine for path, _, engine, _ in project.sources}
        library, later = engines['lib.py'], engines['zz_later.py']
        initialize, analyze = taint_py._Flow.__init__, taint_py._Analysis.analyze
        interrupted = False

        def stop_first_context(flow, engine, scope):
            nonlocal interrupted
            if (engine is library and library in project.ready
                    and getattr(scope, 'name', '') == 'apply' and not interrupted):
                interrupted = True
                library.budget.spend(library.budget.remaining + 1)
            initialize(flow, engine, scope)

        def allow_later_component(engine):
            if engine is later:
                library.budget = Budget()
            return analyze(engine)

        findings = []
        with patch.object(taint_py._Flow, '__init__', stop_first_context), \
                patch.object(taint_py._Analysis, 'analyze', allow_later_component), \
                self.assertRaises(AnalysisLimit) as raised:
            findings.extend(project.findings())
        self.assertTrue(interrupted, 'The failure must occur during a new foreign callback solve')
        self.assertIn('bb_failed.py', str(raised.exception))
        self.assertIn('incomplete', str(raised.exception))
        self.assertNotIn(engines['bb_failed.py'], project.ready)
        self.assertIn(engines['m_independent.py'], project.ready)
        self.assertIn(later, project.ready)
        self.assertEqual({(str(path.relative_to(project.root)), rule, line, column)
                          for path, rule, line, column, _ in findings},
                         {('a_before.py', 'py.taint.eval', 1, 1),
                          ('aa_pkg/lib.py', 'py.taint.eval', 2, 12),
                          ('m_independent.py', 'py.taint.eval', 1, 1)}, findings)
        description = next(description for path, _, _, _, description in findings if path.name == 'lib.py')
        self.assertIn('sys.argv', description)
        self.assertNotIn('input', description)
        self.assertIsNone(library.reads)
        self.assertIsNone(library.writes)


class SummarySubstitutionTests(unittest.TestCase):
    """Substitution preserves evidence and proof domains with linear join work."""

    def run(self, result=None):
        print(f'[{self.id()}] RUN', flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, 'test_case', None) is self
                     for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def assert_exact_facts(self, actual, expected):
        # Fact equality excludes paths, so compare the complete witness too.
        self.assertEqual({(trace.source, trace.parameter, trace.sanitizers, trace.path)
                          for trace in actual}, expected)

    def test_exact_witnesses_and_sanitizer_domains_survive_substitution(self):
        trace = taint_py.TaintTrace
        fact = frozenset({
            trace('formal-p', parameter='p', sanitizers=frozenset({'xss'}),
                  path=('p', 'detour')),
            trace('formal-q', parameter='q', sanitizers=frozenset({'xss'}), path=('q',)),
            trace('cmd', parameter='@global:cmd', sanitizers=frozenset({'command'}),
                  path=('cmd', 'field')),
            trace('fixed', sanitizers=frozenset({'sql'}), path=('fixed', 'stored')),
            trace('missing', parameter='missing', path=('missing',)),
        })
        bound = {
            'p': frozenset({trace('user', path=('user', 'long'))}),
            'q': frozenset({trace('user', path=('user',))}),
            '@global:cmd': frozenset({trace('cli', sanitizers=frozenset({'sql'}), path=('cli',))}),
        }
        expected = {
            ('user', None, frozenset({'xss'}), ('user', 'helper()', 'q')),
            ('cli', None, frozenset({'command', 'sql'}), ('cli', 'helper()', 'field')),
            ('fixed', None, frozenset({'sql'}), ('fixed', 'stored')),
        }
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                self.assert_exact_facts(engine.substitute(fact, bound, 'helper()'), expected)

    def test_header_reset_revokes_old_proofs_before_reestablishing_them(self):
        trace = taint_py.TaintTrace
        cr, lf, reset = 'header:cr', 'header:lf', 'header:reset'
        fact = frozenset({
            trace('p', parameter='p', path=('p',)),
            trace('q', parameter='q', sanitizers=frozenset({reset}), path=('q',)),
            trace('r', parameter='@free:r', sanitizers=frozenset({reset, cr}),
                  path=('r', 'tail')),
            trace('s', parameter='s', sanitizers=frozenset({reset, cr, lf}), path=('s',)),
        })
        encoded = frozenset({trace('request', sanitizers=frozenset({cr, lf, 'sql'}),
                                   path=('request',))})
        bound = {name: encoded for name in ('p', 'q', '@free:r', 's')}
        result = header_injection._HeaderFlow.substitute(fact, bound, 'header()')
        self.assert_exact_facts(result, {
            ('request', None, frozenset({cr, lf, 'sql'}), ('request', 'header()', 'p')),
            ('request', None, frozenset({reset, 'sql'}), ('request', 'header()', 'q')),
            ('request', None, frozenset({reset, cr, 'sql'}), ('request', 'header()', 'tail')),
            ('request', None, frozenset({reset, cr, lf, 'sql'}), ('request', 'header()', 's')),
        })
        self.assertEqual({item.path[-1] for item in result if header_injection._safe(item)},
                         {'p', 's'})

    def test_work_limit_charges_actual_expansion_before_joining(self):
        trace = taint_py.TaintTrace
        fact = frozenset({
            trace('p', parameter='p'), trace('q', parameter='q'),
            trace('missing', parameter='missing'), trace('concrete', path=('concrete',)),
        })
        bound = {
            'p': frozenset({trace('a', path=('a',)), trace('b', path=('b',))}),
            'q': frozenset({trace('c', path=('c',))}),
        }
        # Four summary traces plus three actual traces; a missing binding
        # expands to no facts, and the concrete trace has no actual argument.
        expected = {
            ('a', None, frozenset(), ('a', 'call()')),
            ('b', None, frozenset(), ('b', 'call()')),
            ('c', None, frozenset(), ('c', 'call()')),
            ('concrete', None, frozenset(), ('concrete',)),
        }
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                budget = Budget(7)
                self.assert_exact_facts(engine.substitute(fact, bound, 'call()', budget=budget),
                                        expected)
                self.assertEqual(budget.remaining, 0)
                exhausted = Budget(6)
                with patch.object(taint_py, 'join_facts', wraps=taint_py.join_facts) as join:
                    with self.assertRaisesRegex(AnalysisLimit, 'work limit exceeded.*incomplete'):
                        engine.substitute(fact, bound, 'call()', budget=exhausted)
                    join.assert_not_called()
                self.assertEqual(exhausted.remaining, -1)
                empty = Budget(0)
                self.assertIs(engine.substitute(taint_py.CLEAN, bound, 'call()', budget=empty),
                              taint_py.CLEAN)
                self.assertEqual(empty.remaining, 0)

    def test_fact_visits_scale_linearly_with_summary_size(self):
        trace = taint_py.TaintTrace
        join = taint_py.join_facts
        for count in (32, 128):
            fact = frozenset(trace(f'formal{index}', parameter=f'p{index}',
                                   sanitizers=frozenset({'xss'}) if index % 2 else frozenset(),
                                   path=(f'p{index}',)) for index in range(count))
            bound = {f'p{index}': frozenset({trace(f'source{index}', path=(f'source{index}',))})
                     for index in range(count)}
            expected = {
                (f'source{index}', None, frozenset({'xss'}) if index % 2 else frozenset(),
                 (f'source{index}', 'apply()', f'p{index}')) for index in range(count)
            }
            for engine in (taint_py._Flow, header_injection._HeaderFlow):
                with self.subTest(engine=engine.__name__, traces=count):
                    visited = [0]

                    def observe(*facts):
                        visited[0] += sum(len(part) for part in facts)
                        return join(*facts)

                    budget = Budget(2 * count)
                    with patch.object(taint_py, 'join_facts', observe):
                        actual = engine.substitute(fact, bound, 'apply()', budget=budget)
                    self.assert_exact_facts(actual, expected)
                    self.assertEqual(budget.remaining, 0)
                    self.assertLessEqual(
                        visited[0], 2 * count,
                        f'{count} summary traces caused {visited[0]} joined fact visits')

    def test_advance_cache_keeps_equal_facts_with_distinct_witnesses_separate(self):
        memo = taint_py._advance_trace
        memo.cache_clear()
        self.addCleanup(memo.cache_clear)
        left = taint_py.TaintTrace('request', sanitizers=frozenset({'xss'}),
                                   path=('request', 'left'))
        right = taint_py.TaintTrace('request', sanitizers=frozenset({'xss'}),
                                    path=('request', 'right'))
        self.assertEqual(left, right, 'Evidence must remain outside semantic lattice equality')
        expected_left = {('request', None, frozenset({'xss'}),
                          ('request', 'left', 'sink()'))}
        expected_right = {('request', None, frozenset({'xss'}),
                           ('request', 'right', 'sink()'))}
        self.assert_exact_facts(taint_py._advance(frozenset({left}), 'sink()'), expected_left)
        self.assert_exact_facts(taint_py._advance(frozenset({right}), 'sink()'), expected_right)
        self.assertEqual(memo.cache_info().misses, 2)
        self.assert_exact_facts(taint_py._advance(frozenset({left}), 'sink()'), expected_left)
        self.assertEqual(memo.cache_info().hits, 1)

    def test_advance_cache_keys_every_trace_field_steps_and_path_limit(self):
        memo = taint_py._advance_trace
        memo.cache_clear()
        self.addCleanup(memo.cache_clear)
        trace = taint_py.TaintTrace
        path = ('root', 'a', 'b', 'c')
        xss, command = frozenset({'xss'}), frozenset({'command'})
        cases = (
            (trace('source', 'p', xss, path), ('call()', 'value'), 5,
             ('source', 'p', xss, ('root', 'b', 'c', 'call()', 'value'))),
            (trace('other', 'p', xss, path), ('call()', 'value'), 5,
             ('other', 'p', xss, ('root', 'b', 'c', 'call()', 'value'))),
            (trace('source', None, xss, path), ('call()', 'value'), 5,
             ('source', None, xss, ('root', 'b', 'c', 'call()', 'value'))),
            (trace('source', 'p', command, path), ('call()', 'value'), 5,
             ('source', 'p', command, ('root', 'b', 'c', 'call()', 'value'))),
            (trace('source', 'p', xss, path), ('other()',), 5,
             ('source', 'p', xss, ('root', 'a', 'b', 'c', 'other()'))),
            (trace('source', 'p', xss, path), ('call()', 'value'), 3,
             ('source', 'p', xss, ('root', 'call()', 'value'))),
        )
        for value, steps, limit, expected in cases:
            with self.subTest(expected=expected), patch.object(taint_py, 'PATH_LIMIT', limit):
                self.assert_exact_facts(taint_py._advance(frozenset({value}), *steps),
                                        {expected})
        self.assertEqual(memo.cache_info().misses, len(cases))

    def test_advance_cache_is_bounded_and_warm_hits_do_not_refund_work(self):
        memo = taint_py._advance_trace
        memo.cache_clear()
        self.addCleanup(memo.cache_clear)
        self.assertEqual(memo.cache_info().maxsize, 1024)
        trace = taint_py.TaintTrace
        oldest = frozenset({trace('oldest', path=('oldest',))})
        taint_py._advance(oldest, 'hop()')
        for index in range(1024):
            source = f'entry{index}'
            newest = frozenset({trace(source, path=(source,))})
            taint_py._advance(newest, 'hop()')
        self.assertEqual(memo.cache_info().currsize, 1024)
        misses = memo.cache_info().misses
        self.assert_exact_facts(taint_py._advance(oldest, 'hop()'),
                                {('oldest', None, frozenset(), ('oldest', 'hop()'))})
        self.assertEqual(memo.cache_info().misses, misses + 1, 'The oldest entry must be evicted')
        hits = memo.cache_info().hits
        taint_py._advance(newest, 'hop()')
        self.assertEqual(memo.cache_info().hits, hits + 1)
        self.assertEqual(memo.cache_info().currsize, 1024)

        fact = frozenset({trace('p', parameter='p', path=('p',))})
        bound = {'p': frozenset({trace('warm_input', path=('warm_input',))})}
        expected = {('warm_input', None, frozenset(), ('warm_input', 'call()', 'p'))}
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                first = Budget(2)
                self.assert_exact_facts(engine.substitute(fact, bound, 'call()', budget=first),
                                        expected)
                self.assertEqual(first.remaining, 0)
                hits = memo.cache_info().hits
                warm = Budget(2)
                self.assert_exact_facts(engine.substitute(fact, bound, 'call()', budget=warm),
                                        expected)
                self.assertEqual(warm.remaining, 0)
                self.assertGreater(memo.cache_info().hits, hits)
                hits = memo.cache_info().hits
                exhausted = Budget(1)
                with self.assertRaisesRegex(AnalysisLimit, 'work limit exceeded.*incomplete'):
                    engine.substitute(fact, bound, 'call()', budget=exhausted)
                self.assertEqual(exhausted.remaining, -1)
                self.assertEqual(memo.cache_info().hits, hits)


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


class PythonInputAdmissionTests(unittest.TestCase):
    """Real source decoding and partial results, without filesystem fixtures."""

    def setUp(self):
        import tokenize

        self.root = Path('/__ubs_virtual_taint_inputs__')
        self.contents = {}
        original_open = io.open

        def virtual_open(file, mode='r', buffering=-1, encoding=None, errors=None,
                         newline=None, closefd=True, opener=None):
            if any(flag in mode for flag in 'wax+'):
                raise AssertionError(f'Input-admission tests must not write files: {file}')
            path = Path(os.fsdecode(file)) if not isinstance(file, int) else None
            if path is None or not path.is_relative_to(self.root):
                return original_open(file, mode, buffering, encoding, errors,
                                     newline, closefd, opener)
            if path not in self.contents:
                raise FileNotFoundError(2, 'virtual source does not exist', str(path))
            contents = self.contents[path]
            if isinstance(contents, OSError):
                raise contents
            stream = io.BytesIO(contents)
            if 'b' in mode:
                return stream
            return io.TextIOWrapper(stream, encoding=encoding, errors=errors, newline=newline)

        # Path.read_text and tokenize.open take different low-level open paths.
        # Byte streams retain TextIOWrapper's real codec/BOM/error behavior.
        for module, name in ((io, 'open'), (tokenize, '_builtin_open')):
            opened = patch.object(module, name, virtual_open)
            opened.start()
            self.addCleanup(opened.stop)

    def source(self, name, contents):
        path = self.root / name
        self.contents[path] = contents.encode('utf-8') if isinstance(contents, str) else contents
        return path

    @staticmethod
    def sites(findings):
        return [(path.name, rule, line, column) for path, rule, line, column, _ in findings]

    def incomplete_project(self, files):
        project = taint_py._Project(files, self.root)
        findings = []
        with self.assertRaises(AnalysisLimit) as raised:
            findings.extend(project.findings())
        self.assertIn('incomplete', str(raised.exception))
        return findings, str(raised.exception)

    def test_encodings_keep_real_taint_safe_values_and_suppressions(self):
        for name, prefix, line in (
                ('latin1.py', b'# coding: latin-1\nlabel = "caf\xe9"\n', 3),
                ('bom.py', b'\xef\xbb\xbf', 1)):
            path = self.source(name, prefix + b'eval(input())\neval("fixed")\n'
                               b'eval(input())  # ubs:ignore\n')
            with self.subTest(encoding=name):
                self.assertEqual([(rule, row, column) for rule, row, column, _
                                  in taint_py.scan_file_findings(path)],
                                 [('py.taint.eval', line, 1)])
                self.assertEqual(self.sites(taint_py._Project([path], self.root).findings()),
                                 [(name, 'py.taint.eval', line, 1)])

    def test_encoded_selected_modules_keep_imported_flow_and_clean_controls(self):
        helper = self.source('helper.py', b'# coding: latin-1\nlabel = "caf\xe9"\n'
                             b'def relay(value):\n    return value\n')
        app = self.source('app.py', b'\xef\xbb\xbffrom helper import relay\n'
                          b'eval(relay(input()))\n')
        for files in ([app, helper], [helper, app]):
            with self.subTest(order=[path.name for path in files]):
                self.assertEqual(self.sites(taint_py._Project(files, self.root).findings()),
                                 [('app.py', 'py.taint.eval', 2, 1)])
        self.source('helper.py', b'# coding: latin-1\nlabel = "caf\xe9"\n'
                    b'def relay(value):\n    return "fixed"\n')
        self.assertEqual(list(taint_py._Project([app, helper], self.root).findings()), [])

    def test_standalone_read_decode_codec_and_parse_failures_are_explicit(self):
        paths = [self.root / 'missing.py',
                 self.source('denied.py', PermissionError('source read denied')),
                 self.source('invalid.py', b'def invalid(:  # ubs:ignore\n    pass\n'),
                 self.source('undecodable.py', b'label = "\xff"\n'),
                 self.source('unknown-codec.py', b'# coding: unknown_codec\nvalue = 1\n'),
                 self.source('binary-codec.py', b'# coding: hex_codec\nvalue = 1\n'),
                 self.source('null.py', b'value = \x00\n')]
        for path in paths:
            with self.subTest(source=path.name):
                with self.assertRaises(AnalysisLimit) as raised:
                    list(taint_py.scan_file_findings(path))
                self.assertIn(path.name, str(raised.exception))
                self.assertIn('Cannot analyze Python source', str(raised.exception))
                self.assertIn('incomplete', str(raised.exception))

    def test_project_retains_independent_findings_around_failed_inputs(self):
        files = [self.source('a_first.py', 'eval(input())\n'),
                 self.source('b_decode.py', b'label = "\xff"\n'),
                 self.source('c_read.py', PermissionError('source read denied')),
                 self.source('d_syntax.py', 'def invalid(:\n    pass\n'),
                 self.source('z_last.py', 'eval(input())\n')]
        findings, message = self.incomplete_project(files)
        self.assertEqual(self.sites(findings),
                         [('a_first.py', 'py.taint.eval', 1, 1),
                          ('z_last.py', 'py.taint.eval', 1, 1)])
        self.assertIn('3 input(s)', message)
        for path in files[1:-1]:
            self.assertIn(path.name, message)

    def test_all_bad_inputs_deduplicate_and_bound_diagnostics(self):
        missing = self.root / 'missing.py'
        findings, message = self.incomplete_project([missing, missing])
        self.assertEqual(findings, [])
        self.assertIn('1 input(s)', message)
        self.assertNotIn('2 input(s)', message)
        files = [self.source(f'bad-{index}.py', 'def invalid(:\n    pass\n')
                 for index in range(8)]
        findings, message = self.incomplete_project([path for path in files for _ in range(2)])
        self.assertEqual(findings, [])
        self.assertIn('8 input(s)', message)
        self.assertIn('5 more failed inputs', message)
        self.assertLess(len(message), 1800)
        for path in files[:3]:
            self.assertIn(path.name, message)
        self.assertNotIn(files[-1].name, message)

    def test_parser_recursion_is_partial_and_preserves_later_sources(self):
        files = [self.source('a_first.py', 'eval(input())\n'),
                 self.source('deep.py', 'eval(input())\n'),
                 self.source('z_last.py', 'eval(input())\n')]
        original_parse = ast.parse

        def parse(source, filename='<unknown>', *args, **kwargs):
            if filename == str(files[1]):
                raise RecursionError('compiler depth probe')
            return original_parse(source, filename, *args, **kwargs)

        with patch.object(ast, 'parse', side_effect=parse):
            with self.assertRaisesRegex(AnalysisLimit, 'RecursionError.*incomplete'):
                list(taint_py.scan_file_findings(files[1]))
            findings, message = self.incomplete_project(files)
        self.assertEqual(self.sites(findings),
                         [('a_first.py', 'py.taint.eval', 1, 1),
                          ('z_last.py', 'py.taint.eval', 1, 1)])
        self.assertIn('deep.py', message)
        self.assertIn('compiler depth probe', message)

    def test_input_and_component_failures_are_both_reported(self):
        files = [self.source('a_first.py', 'eval(input())\n'),
                 self.source('b_invalid.py', 'def invalid(:\n    pass\n'),
                 self.source('m_limited.py', 'eval(input())\n'),
                 self.source('z_last.py', 'eval(input())\n')]
        with patch.object(taint_py, 'Budget', side_effect=[Budget(), Budget(0), Budget()]):
            findings, message = self.incomplete_project(files)
        self.assertEqual(self.sites(findings),
                         [('a_first.py', 'py.taint.eval', 1, 1),
                          ('z_last.py', 'py.taint.eval', 1, 1)])
        for detail in ('1 input(s)', 'b_invalid.py', '1 component(s)',
                       'm_limited.py', 'work limit exceeded'):
            self.assertIn(detail, message)

    def test_registry_retains_records_and_reports_input_failure(self):
        from ubs_core import py_scan
        from ubs_core.registry import Analyzer, RunContext

        files = [self.source('a_first.py', 'eval(input())\n'),
                 self.source('bad.py', PermissionError('source read denied')),
                 self.source('z_last.py', 'eval(input())\n')]
        registered = [Analyzer('taint', 'python', 'taint_py', taint_py.run)]
        sink, errors = io.StringIO(), []
        py_scan.run_analyzers(files, sink, taint=True, errors=errors,
                              project_dir=str(self.root), registered=registered)
        records = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual([(Path(row['path']).name, row['rule'], row['line']) for row in records],
                         [('a_first.py', 'python.taint.eval', 1),
                          ('z_last.py', 'python.taint.eval', 1)])
        self.assertEqual(len(errors), 1)
        self.assertIn('taint_py (selected project): AnalysisLimit', errors[0])
        self.assertIn('bad.py', errors[0])
        sink = io.StringIO()
        with self.assertRaises(AnalysisLimit):
            py_scan.run_analyzers(files, sink, taint=True, project_dir=str(self.root),
                                  registered=registered)
        self.assertEqual(len(sink.getvalue().splitlines()), 2)
        context = RunContext(lang='python', files=files, profile={
            'project_dir': str(self.root), 'disabled_rules': ['python.taint.eval', 'py.taint.eval']})
        suppressed = []
        with self.assertRaisesRegex(AnalysisLimit, 'bad.py'):
            suppressed.extend(taint_py.run(context))
        self.assertEqual(suppressed, [], 'Disabled findings must not disable input failure reporting')

    def test_legacy_entrypoint_keeps_rows_and_returns_incomplete(self):
        files = [self.source('a_first.py', 'eval(input())\n'),
                 self.source('bad.py', PermissionError('source read denied')),
                 self.source('z_last.py', 'eval(input())\n')]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(taint_py, 'iter_files', return_value=iter(files)), \
                patch.object(taint_py, 'ROOT', self.root), \
                patch.object(taint_py, 'BASE_DIR', self.root), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = taint_py.main(['taint_py.py', str(self.root)])
        self.assertEqual(code, 2)
        self.assertTrue(stdout.getvalue().startswith('py.taint.eval\t2\t'), stdout.getvalue())
        self.assertIn('bad.py', stderr.getvalue())
        self.assertIn('incomplete', stderr.getvalue())

    def test_header_reader_keeps_encoded_findings_and_partial_results(self):
        from ubs_core.py_detectors import header_injection

        files = []
        for name, prefix, line in (
                ('header-latin1.py', b'# coding: latin-1\nlabel = "caf\xe9"\n', 3),
                ('header-bom.py', b'\xef\xbb\xbf', 1)):
            path = self.source(name, prefix + b'response.headers["X-User"] = input()\n'
                               b'response.headers["X-Safe"] = "fixed"\n'
                               b'response.headers["X-Ignored"] = input()  # ubs:ignore\n')
            files.append(path)
            with self.subTest(encoding=name):
                self.assertEqual([(found.name, row, column) for found, row, column, _
                                  in header_injection.find([path])], [(name, line, 1)])
        broken = self.source('header-bad.py', b'# coding: unknown_codec\nvalue = 1\n')
        findings = []
        with self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*header-bad.py'):
            findings.extend(header_injection.find([files[0], broken, files[1]]))
        self.assertEqual([(found.name, row) for found, row, _, _ in findings],
                         [('header-latin1.py', 3), ('header-bom.py', 1)])


if __name__ == '__main__':
    unittest.main()
