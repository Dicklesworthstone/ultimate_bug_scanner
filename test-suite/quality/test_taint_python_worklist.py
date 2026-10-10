"""The worklist must find exactly what a from-scratch re-solve finds.

The analyzer reuses a function's previous solve when nothing it read has
changed, skips re-joining an unchanged state into an exception collector,
and does not re-solve callback contexts inherited from earlier modules.
Each shape below makes a summary, default or namespace change only after its
reader was solved; the findings must equal those of the same scan with every
reuse disabled, and the cross-module shapes must report the known flow.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py

SHAPES = {
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
