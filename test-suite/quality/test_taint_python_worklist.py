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
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py

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


if __name__ == '__main__':
    unittest.main()
