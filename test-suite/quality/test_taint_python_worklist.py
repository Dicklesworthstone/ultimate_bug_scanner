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
import builtins
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
    'transitive_global_callback_override': {'app.py': '''
import os
def safe(value):
    return None
def invoke(callback, value):
    callback(value)
def indirect(value):
    target(value)
target = safe
def handler():
    global target
    target = os.system
    invoke(indirect, input())
    target = safe
'''},
    'transitive_global_class_override': {'app.py': '''
import os
class Safe:
    @staticmethod
    def send(value):
        return None
class Unsafe:
    @staticmethod
    def send(value):
        os.system(value)
Target = Safe
def dispatch(value):
    Target.send(value)
def invoke(callback, value):
    callback(value)
def handler():
    global Target
    Target = Unsafe
    invoke(dispatch, input())
    Target = Safe
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
    'transitive_global_callback_override': {('app.py', 7)},
    'transitive_global_class_override': {('app.py', 9)},
}


def large_budget_source(line_count, *, unsafe=True):
    """Public #198 fixture: many globals/defaults, a chain and a closure.

    The unrelated nested definition used to disable dependency ordering for
    the entire module. The last handler has thirteen distinct security sinks
    and seven clean controls; the generated module is only ever analyzed.
    """
    prefix = [
        'import os', 'import subprocess', 'import requests',
        'from django.http import HttpResponse', 'from urllib.parse import quote',
        'from html import escape', 'from shlex import quote as shell_quote',
        'def unused_factory():', '    def inner(value="fixed"):',
        '        return value', '    return inner',
    ]
    actual = 'input()' if unsafe else '"fixed"'
    tail = [
        'def planted():',
        f'    value = stage0({actual})',
        '    os.system(value)',
        '    subprocess.run(value, shell=True)',
        '    subprocess.run([value])',
        '    eval(value)',
        '    exec(value)',
        '    cursor.execute(value)',
        '    cursor.executemany(value, [])',
        '    requests.get(value)',
        '    requests.post(value)',
        '    HttpResponse(value)',
        '    HttpResponse(content=value)',
        '    response.headers["X-User"] = value',
        '    response.headers["X-Other"] = value',
        '    os.system("printf %s " + shell_quote(value))',
        '    subprocess.run(["echo", value])',
        '    eval("1", {"value": value})',
        '    cursor.execute("SELECT ?", (value,))',
        '    requests.get("https://fixed.invalid/", params={"q": value})',
        '    HttpResponse(escape(value))',
        '    response.headers["X-Encoded"] = quote(value)',
    ]
    count = (line_count - len(prefix) - len(tail)) // 12
    if count < 1:
        raise ValueError('The fixture must contain at least one helper')
    lines = list(prefix)
    for index in range(count):
        successor = f'stage{index + 1}(value)' if index + 1 < count else 'value'
        lines.extend([
            f'TOKEN{index} = "fixed"',
            f'def stage{index}(value, marker=TOKEN{index}):',
            '    label = marker', '    status = 0', '    low = 1',
            '    high = 9', '    kind = "text"', '    enabled = True',
            '    offset = 0', '    scale = 1', '    token = label',
            f'    return {successor}',
        ])
    lines.extend(f'padding{index} = "fixed"'
                 for index in range(line_count - len(lines) - len(tail)))
    lines.extend(tail)
    expected = {
        ('command', line_count - len(tail) + 3, 5),
        ('command', line_count - len(tail) + 4, 5),
        ('command', line_count - len(tail) + 5, 5),
        ('eval', line_count - len(tail) + 6, 5),
        ('eval', line_count - len(tail) + 7, 5),
        ('sql', line_count - len(tail) + 8, 5),
        ('sql', line_count - len(tail) + 9, 5),
        ('ssrf', line_count - len(tail) + 10, 5),
        ('ssrf', line_count - len(tail) + 11, 5),
        ('xss', line_count - len(tail) + 12, 5),
        ('xss', line_count - len(tail) + 13, 5),
        ('header', line_count - len(tail) + 14, 5),
        ('header', line_count - len(tail) + 15, 5),
    } if unsafe else set()
    return '\n'.join(lines) + '\n', expected


def large_budget_worker():
    """Real flow evaluation in a fresh process with an external deadline."""
    source = sys.stdin.read()
    reports = {}
    for name, engine_class in (('taint', taint_py._Analysis),
                               ('header', header_injection._HeaderAnalysis)):
        engine = engine_class(ast.parse(source))
        initialize = taint_py._Flow.__init__
        counts = {'module_passes': 0, 'function_passes': 0}

        def observe(flow, owner, scope):
            counts['module_passes' if scope is owner.tree else 'function_passes'] += 1
            initialize(flow, owner, scope)

        with patch.object(taint_py._Flow, '__init__', observe):
            effects = engine.analyze()
        sites = [(kind, line, column) for (kind, line, column, _), facts in effects.items()
                 if kind != 'header' or any(not header_injection._safe(trace) for trace in facts)]
        reports[name] = {**counts, 'sites': sorted(sites),
                         'work': engine.work_limit - engine.budget.remaining,
                         'functions': len(engine.functions)}
    print(json.dumps(reports))


def fresh_exception_join(flow, state):
    """Reference collector: join the entire state at every possible raise."""
    if state.reachable and flow.exception_states:
        flow.exception_states[-1] = taint_py._join_states(flow.exception_states[-1], state)


class WorklistReuseTests(unittest.TestCase):
    def test_reflective_global_replacement_retains_callables_and_restoration(self):
        for kind in ('item', 'update', 'alias'):
            for unsafe in (False, True):
                with self.subTest(kind=kind, unsafe=unsafe):
                    prefix = '''import os
def target(value): return None
saved = target
def indirect(value): target(value)
def invoke(callback, value): callback(value)
def handler():
'''
                    if kind == 'update':
                        replace = 'globals().update(target=os.system)'
                        restore = 'globals().update(target=saved)'
                        setup = ''
                    else:
                        receiver = 'namespace' if kind == 'alias' else 'globals()'
                        setup = '    namespace = globals()\n' if kind == 'alias' else ''
                        replace = f'{receiver}["target"] = os.system'
                        restore = f'{receiver}["target"] = saved'
                    statements = [replace, 'invoke(indirect, input())', restore] if unsafe else [replace, restore, 'invoke(indirect, input())']
                    source = prefix + setup + ''.join(f'    {statement}\n' for statement in statements)
                    effects = taint_py._Analysis(ast.parse(source)).analyze()
                    self.assertEqual({key[:3] for key in effects}, {('command', 4, 22)} if unsafe else set())

    def test_namespace_mutation_keeps_same_named_local_separate(self):
        source = '''import os
def target(value): return None
def indirect(value): target(value)
def handler():
    target = print
    globals()['target'] = os.system
    target(input())
    indirect(input())
'''
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('command', 3, 22)})

    def test_namespace_reads_keep_the_replaced_callable(self):
        for expression in ("globals()['target']", "globals().get('target')"):
            source = f'''import os
target = print
globals()['target'] = os.system
{expression}(input())
'''
            with self.subTest(expression=expression):
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('command', 4, 1)})

    def test_unknown_namespace_write_is_incomplete_and_shadowed_globals_is_ordinary(self):
        source = '''import os
def handler(): globals()[input()] = os.system
'''
        with self.assertRaisesRegex(AnalysisLimit, 'dynamic globals mapping key'):
            taint_py._Analysis(ast.parse(source)).analyze()
        source = '''import os
def globals(): return {}
def target(value): return None
def handler():
    globals()['target'] = os.system
    target(input())
'''
        self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_replacement_restored_by_lexical_assignment_is_clean(self):
        source = '''import os
def target(value): return None
saved = target
def handler():
    global target
    globals()['target'] = os.system
    target = saved
    target(input())
'''
        self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_get_does_not_execute_an_unused_dangerous_default(self):
        source = '''import os
target = print
globals().get('target', os.system)(input())
'''
        self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_literal_key_alias_invalidates_prior_helper_identity(self):
        source = '''import os
def target(value): return None
def indirect(value): target(value)
def handler():
    key = 'target'
    globals()[key] = os.system
    indirect(input())
'''
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('command', 3, 22)})

    def test_namespace_finite_keys_apply_weak_writes_to_each_possible_global(self):
        for initial, replacement, unsafe in (('print', 'eval', True),
                                             ('eval', 'print', True),
                                             ('print', 'print', False)):
            source = f'''left = {initial}
right = {initial}
key = 'left' if input() else 'right'
globals()[key] = {replacement}
left(input())
right(input())
'''
            with self.subTest(initial=initial, replacement=replacement):
                # Both selections execute the real namespace update. A weak
                # clean write cannot erase the unselected unsafe binding.
                for selection in ('left', ''):
                    observed, inputs = [], iter((selection, 'MARKER', 'MARKER'))
                    namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                    with contextlib.redirect_stdout(io.StringIO()):
                        exec(compile(source, '<finite-global-write>', 'exec'), namespace)
                    self.assertEqual(observed, ['MARKER'] if unsafe else [])
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects},
                                 {('eval', 5, 1), ('eval', 6, 1)} if unsafe else set())

    def test_namespace_equal_literal_alternatives_still_make_a_strong_write(self):
        source = '''target = eval
key = 'target' if input() else 'target'
globals()[key] = print
target(input())
'''
        self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_finite_reads_retain_callable_choices_and_missing_defaults(self):
        for lookup in ("globals()[key]", "globals().get(key)"):
            for right in ('print', 'eval'):
                source = f'''left = print
right = {right}
def choose(flag): return 'left' if flag else 'right'
key = choose(input())
{lookup}(input())
'''
                with self.subTest(lookup=lookup, right=right):
                    effects = taint_py._Analysis(ast.parse(source)).analyze()
                    self.assertEqual({key[:3] for key in effects},
                                     {('eval', 5, 1)} if right == 'eval' else set())
        for alternative, unsafe in (('right', False), ('missing', True)):
            source = f'''left = print
right = print
key = 'left' if input() else '{alternative}'
globals().get(key, eval)(input())
'''
            with self.subTest(default_alternative=alternative):
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('eval', 4, 1)} if unsafe else set())

    def test_namespace_finite_key_summary_keeps_shadowed_locals_separate(self):
        source = '''left = print
right = print
def replace():
    left = print
    key = 'left' if input() else 'right'
    globals()[key] = eval
    left(input())
def indirect(value):
    left(value)
    right(value)
def handler():
    replace()
    indirect(input())
'''
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('eval', 9, 5), ('eval', 10, 5)})

    def test_namespace_finite_get_retains_defaults_after_conditional_presence(self):
        for declaration in ("if input():\n    right = print\n",
                            "right = print\nif input():\n    del right\n"):
            source = ("left = print\n" + declaration
                      + "key = 'left' if input() else 'right'\n"
                      + "globals().get(key, eval)(input())\n")
            with self.subTest(declaration=declaration):
                observed = []
                inputs = iter(('delete' if 'del right' in declaration else '', '', 'MARKER'))
                namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                exec(compile(source, '<conditional-global-presence>', 'exec'), namespace)
                self.assertEqual(observed, ['MARKER'])
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('eval', len(source.splitlines()), 1)})

    def test_namespace_finite_get_distinguishes_present_none_and_opaque_values(self):
        for value in ('None', 'object()'):
            source = f'''left = {value}
right = {value}
key = 'left' if input() else 'right'
globals().get(key, eval)(input())
'''
            with self.subTest(value=value):
                observed = []
                namespace = {'input': lambda: 'MARKER', 'eval': observed.append}
                with self.assertRaises(TypeError):
                    exec(compile(source, '<present-global-value>', 'exec'), namespace)
                self.assertEqual(observed, [])
                self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_finite_reads_ignore_active_class_shadows(self):
        for lookup in ('globals()[key]', 'globals().get(key, print)'):
            source = f'''left = eval
right = eval
key = 'left' if input() else 'right'
class Box:
    left = print
    right = print
    {lookup}(input())
'''
            with self.subTest(lookup=lookup):
                for choice in ('left', ''):
                    observed, inputs = [], iter((choice, 'MARKER'))
                    namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                    exec(compile(source, '<class-global-shadow>', 'exec'), namespace)
                    self.assertEqual(observed, ['MARKER'])
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('eval', 7, 5)})

    def test_namespace_finite_reads_require_an_ordinary_class_namespace(self):
        for lookup in ('globals()[key]', 'globals().get(key, print)'):
            source = '''class Namespace(dict):
    def __missing__(self, name):
        if name == 'globals':
            return lambda: {'left': eval, 'right': eval}
        raise KeyError(name)
class Meta(type):
    @classmethod
    def __prepare__(metacls, name, bases):
        return Namespace()
left = print
right = print
key = 'left' if input() else 'right'
class Box(metaclass=Meta):
''' + f'    {lookup}(input())\n'
            with self.subTest(lookup=lookup):
                observed = []
                exec(compile(source, '<custom-class-namespace>', 'exec'),
                     {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(AnalysisLimit, 'finite globals access in an unresolved class namespace'):
                    taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_class_reads_keep_mutations_of_module_objects(self):
        source = '''left = ['safe']
right = ['safe']
key = 'left' if input() else 'right'
class Box:
    left[0] = input()
    right[0] = input()
    left = ['safe']
    right = ['safe']
    eval(globals()[key][0])
'''
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('eval', 9, 5)})

    def test_namespace_finite_reader_captures_temporary_replacements(self):
        for lookup in ('globals()[key]', 'globals().get(key, print)'):
            source = f'''left = print
right = print
def read(value):
    key = 'left' if input() else 'right'
    {lookup}(value)
def relay(value):
    left = right = print
    read(value)
globals()['left'] = eval
relay(input())
globals()['left'] = print
'''
            with self.subTest(lookup=lookup):
                observed, inputs = [], iter(('MARKER', 'left'))
                namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                exec(compile(source, '<temporary-global-read>', 'exec'), namespace)
                self.assertEqual(observed, ['MARKER'])
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('eval', 5, 5)})

    def test_namespace_finite_reader_preserves_call_time_membership(self):
        for local in ('', '    right = None\n'):
            source = f'''left = print
def read(value):
    key = 'left' if input() else 'right'
    globals().get(key, eval)(value)
def relay(value):
{local}    read(value)
relay(input())
right = None
'''
            with self.subTest(local_shadow=bool(local)):
                observed, inputs = [], iter(('MARKER', ''))
                namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                exec(compile(source, '<call-time-global-membership>', 'exec'), namespace)
                self.assertEqual(observed, ['MARKER'])
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects}, {('eval', 4, 5)})

    def test_namespace_finite_reader_preserves_call_time_value_facts(self):
        source = '''left = 'safe'
right = 'safe'
def read():
    key = 'left' if input() else 'right'
    eval(globals()[key])
left = input()
read()
left = 'safe'
'''
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('eval', 5, 5)})

    def test_namespace_finite_get_preserves_exceptional_membership(self):
        source = '''left = print
try:
    if input():
        right = print
    raise ValueError()
except ValueError:
    key = 'left' if input() else 'right'
    globals().get(key, eval)(input())
'''
        observed, inputs = [], iter(('', '', 'MARKER'))
        namespace = {'input': lambda: next(inputs), 'eval': observed.append}
        exec(compile(source, '<exceptional-global-presence>', 'exec'), namespace)
        self.assertEqual(observed, ['MARKER'])
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('eval', 8, 5)})

    def test_namespace_finite_replacement_does_not_discard_finalizer_effects(self):
        for declaration in (
            'left = Release()\n',
            'def left(owned=Release()):\n    pass\n',
            'def make():\n    owned = Release()\n    def run():\n        return owned\n    return run\nleft = make()\n',
        ):
            source = '''code = 'safe'
tainted = input()
class Release:
    def __del__(self):
        global code
        code = tainted
''' + declaration + '''right = print
key = 'left' if input() else 'right'
globals()[key] = print
eval(code)
'''
            with self.subTest(declaration=declaration):
                observed, inputs = [], iter(('MARKER', 'left'))
                namespace = {'input': lambda: next(inputs), 'eval': observed.append}
                exec(compile(source, '<finite-global-finalizer>', 'exec'), namespace)
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(AnalysisLimit, 'finite globals replacement lifetime is unresolved'):
                    taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_native_replacement_proof_rejects_reflected_builtin_mutation(self):
        for prefix, setter in (
            ('', 'original.__self__.__setattr__'),
            ('', "getattr(getattr(original, '__' + 'self__'), '__set' + 'attr__')"),
            ('from operator import attrgetter as get\n', "get('__self__.__setattr__')(original)"),
        ):
            source = prefix + '''code = 'safe'
tainted = input()
class Release:
    def __del__(self):
        global code
        code = tainted
original = print
''' + f'''{setter}('print', Release())
left = print
{setter}('print', original)
right = original
key = 'left' if input() else 'right'
globals()[key] = original
eval(code)
'''
            with self.subTest(setter=setter):
                observed, original_print = [], builtins.print
                try:
                    exec(compile(source, '<reflected-builtin-ownership>', 'exec'),
                         {'input': lambda: 'MARKER', 'eval': observed.append})
                finally:
                    builtins.print = original_print
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(AnalysisLimit, 'finite globals replacement lifetime is unresolved'):
                    taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_weak_write_to_maybe_missing_key_remains_incomplete(self):
        source = '''left = print
if input():
    right = print
key = 'left' if input() else 'right'
globals()[key] = print
globals().get('right', eval)(input())
'''
        observed, inputs = [], iter(('', 'left', 'MARKER'))
        namespace = {'input': lambda: next(inputs), 'eval': observed.append}
        exec(compile(source, '<weak-global-creation>', 'exec'), namespace)
        self.assertEqual(observed, ['MARKER'])
        with self.assertRaisesRegex(AnalysisLimit, 'global deletion requires namespace lifetime analysis'):
            taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_finite_reads_preserve_mutable_aliases(self):
        source = '''left = ['safe']
right = ['safe']
key = 'left' if input() else 'right'
chosen = globals()[key]
chosen[0] = input()
eval(left[0])
eval(right[0])
'''
        for selection in ('left', ''):
            observed, inputs = [], iter((selection, 'MARKER'))
            namespace = {'input': lambda: next(inputs), 'eval': observed.append}
            exec(compile(source, '<finite-global-alias>', 'exec'), namespace)
            self.assertEqual(sorted(observed), ['MARKER', 'safe'])
        effects = taint_py._Analysis(ast.parse(source)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('eval', 6, 1), ('eval', 7, 1)})

    def test_namespace_mixed_unknown_key_alternatives_remain_incomplete(self):
        for key in ("'target' if input() else input()", "'target' if input() else 1"):
            for access in ("globals()[key] = eval", "globals()[key](input())",
                           "globals().get(key, eval)(input())"):
                source = f'target = print\nkey = {key}\n{access}\n'
                with self.subTest(key=key, access=access):
                    with self.assertRaisesRegex(AnalysisLimit, 'dynamic globals mapping key'):
                        taint_py._Analysis(ast.parse(source)).analyze()
        source = '''target = print
key = 'target' if input() else 'not_declared'
globals()[key] = eval
'''
        with self.assertRaisesRegex(AnalysisLimit, 'new globals mapping declaration'):
            taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_escape_to_an_unmodeled_mutator_is_incomplete(self):
        source = '''import os
def target(value): return None
def replace(namespace, value): namespace['target'] = value
def handler():
    replace(globals(), os.system)
    target(input())
'''
        with self.assertRaisesRegex(AnalysisLimit, 'globals mapping passed to a callable'):
            taint_py._Analysis(ast.parse(source)).analyze()

    def test_namespace_container_and_closure_escapes_are_incomplete(self):
        header = 'import os\ndef target(value): return None\ndef indirect(value): target(value)\n'
        bodies = (
            "namespaces = [globals()]\nnamespaces[0]['target'] = os.system",
            "namespaces = (globals(),)\nnamespaces[0]['target'] = os.system",
            "wrapper = {'namespace': globals()}\nwrapper['namespace']['target'] = os.system",
            "namespaces = [globals() for _ in (0,)]\nnamespaces[0]['target'] = os.system",
            "wrapper = {key: globals() for key in ('namespace',)}\nwrapper['namespace']['target'] = os.system",
            "namespaces = (globals() for _ in (0,))\nnext(namespaces)['target'] = os.system",
            "class Holder: pass\nbox = Holder()\nbox.namespace = globals()\nbox.namespace['target'] = os.system",
            "wrapper = {}\nwrapper['namespace'] = globals()\nwrapper['namespace']['target'] = os.system",
            "namespace = globals()\ndef replace(): namespace['target'] = os.system\nreplace()",
            "def replace(namespace=globals()): namespace['target'] = os.system\nreplace()",
        )
        for body in bodies:
            source = header + 'def handler():\n' + ''.join(
                f'    {line}\n' for line in (body + '\nindirect(input())').splitlines())
            with self.subTest(body=body):
                with self.assertRaisesRegex(AnalysisLimit, 'globals mapping.*incomplete'):
                    taint_py._Analysis(ast.parse(source)).analyze()

    def test_ordinary_containers_and_returned_namespace_keep_their_meaning(self):
        ordinary = '''def globals(): return {}
def handler():
    namespace = globals()
    wrapper = {'namespace': namespace}
    def read(): return namespace
    wrapper['namespace']['target'] = print
    read()
'''
        self.assertEqual(taint_py._Analysis(ast.parse(ordinary)).analyze(), {})
        returned = '''import os
def target(value): return None
def indirect(value): target(value)
def namespace(): return globals()
def handler():
    namespace()['target'] = os.system
    indirect(input())
'''
        effects = taint_py._Analysis(ast.parse(returned)).analyze()
        self.assertEqual({key[:3] for key in effects}, {('command', 3, 22)})

    def test_namespace_factories_cannot_escape_through_object_fields(self):
        header = 'import os\ndef target(value): return None\ndef indirect(value): target(value)\n'
        factories = (
            'box.factory = globals',
            'import builtins\nbox.factory = builtins.globals',
            'box.factory = [globals][0]',
            'def namespace(): return globals()\nbox.factory = namespace',
        )
        for factory in factories:
            body = ('class Holder: pass\nbox = Holder()\n' + factory
                    + "\nbox.factory()['target'] = os.system\nindirect(input())")
            source = header + 'def handler():\n' + ''.join(
                f'    {line}\n' for line in body.splitlines())
            with self.subTest(factory=factory):
                with self.assertRaisesRegex(AnalysisLimit, 'globals mapping factory.*incomplete'):
                    taint_py._Analysis(ast.parse(source)).analyze()

    def test_ordinary_object_factories_keep_their_meaning(self):
        factories = (
            'def globals(): return {}\nbox.factory = globals',
            "def lookup(): return globals()['target']\nbox.factory = lookup",
        )
        for factory in factories:
            source = ('def target(value): return None\nclass Holder: pass\nbox = Holder()\n'
                      + factory + '\ndef handler():\n    box.factory()\n')
            with self.subTest(factory=factory):
                self.assertEqual(taint_py._Analysis(ast.parse(source)).analyze(), {})

    def test_namespace_factory_escape_retains_observed_findings(self):
        source = '''import os
os.system(input())
class Holder: pass
box = Holder()
box.factory = globals
'''
        with self.assertRaisesRegex(AnalysisLimit, 'globals mapping factory.*incomplete') as raised:
            taint_py._Analysis(ast.parse(source)).analyze()
        self.assertIn(('command', 2, 1), {key[:3] for key in raised.exception.effects})

    def test_joined_namespace_item_access_is_incomplete(self):
        header = 'import os\ndef target(value): return None\ndef indirect(value): target(value)\n'
        cases = (
            "def handler():\n"
            "    namespace = globals() if input() else {}\n"
            "    namespace['target'] = os.system\n"
            "    indirect(input())\n",
            "def handler():\n"
            "    globals()['target'] = os.system\n"
            "    namespace = globals() if input() else {'target': print}\n"
            "    namespace['target'](input())\n",
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(AnalysisLimit, 'ambiguous globals mapping'):
                    taint_py._Analysis(ast.parse(header + source)).analyze()
        # An ordinary dictionary alternative confers no module write authority.
        ordinary = "namespace = {} if input() else {'target': print}\nnamespace['target'] = print\n"
        self.assertEqual(taint_py._Analysis(ast.parse(ordinary)).analyze(), {})

    def test_recursive_opaque_ast_fields_complete_with_unsafe_and_clean_inputs(self):
        visitor = '''import ast
def visit(node):
    if isinstance(node, ast.Constant): return node.value
    if isinstance(node, ast.BinOp): return visit(node.left) + visit(node.right)
    if isinstance(node, ast.UnaryOp): return visit(node.operand)
    if isinstance(node, ast.List): return [visit(item) for item in node.elts]
    if isinstance(node, ast.Tuple): return tuple(visit(item) for item in node.elts)
    if isinstance(node, ast.Dict): return {visit(key): visit(value) for key,value in zip(node.keys,node.values)}
    return node
'''
        for unsafe in (False, True):
            with self.subTest(unsafe=unsafe):
                value = 'input()' if unsafe else '"123"'
                source = visitor + f'eval(visit(ast.parse({value}, mode="eval").body))\n'
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                self.assertEqual({key[:3] for key in effects},
                                 {('eval', len(source.splitlines()), 1)} if unsafe else set())

    def test_unrelated_global_replacements_keep_helper_context_storage_linear(self):
        for count in (8, 64):
            for unsafe in (False, True):
                with self.subTest(count=count, unsafe=unsafe):
                    lines = ['import os', 'def safe(value): return None']
                    lines += [f'alias{index} = safe' for index in range(count)]
                    for index in range(count):
                        target = f'f{index + 1}(value)' if index + 1 < count else 'value'
                        lines += [f'def f{index}(value): return {target}']
                    lines += ['def handler():',
                              '    global ' + ', '.join(f'alias{index}' for index in range(count))]
                    lines += [f'    alias{index} = os.system' for index in range(count)]
                    actual = 'input()' if unsafe else '"fixed"'
                    lines += [f'    eval(f0({actual}))']
                    sink_line = len(lines)
                    lines += [f'    alias{index} = safe' for index in range(count)]
                    engine = taint_py._Analysis(ast.parse('\n'.join(lines) + '\n'))
                    effects = engine.analyze()
                    self.assertEqual({key[:3] for key in effects},
                                     {('eval', sink_line, 5)} if unsafe else set())
                    retained = sum(len(key[1]) for key in engine.summaries
                                   if isinstance(key, tuple) and key[0].name.startswith('f'))
                    self.assertLessEqual(retained, 32 * count)

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
                    # Per-creation defaults cross invoke's callback summary;
                    # retain that real call in the exact diagnostic witness.
                    self.assertEqual(findings, [('app.py', 'py.taint.command', line, 5,
                                               'input( -> invoke() -> target() -> value -> subprocess execution')])

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

    def test_independent_closures_retain_only_linear_scope_dependencies(self):
        for count in (64, 256):
            prefix = ''.join(
                f'def outer{index}(captured{index}):\n'
                f'    def inner{index}():\n'
                f'        return captured{index}\n'
                f'    return inner{index}\n'
                for index in range(count))
            for unsafe in (True, False):
                with self.subTest(function_pairs=count, unsafe=unsafe):
                    source = prefix + ('eval(input())\n' if unsafe else 'eval("fixed")\n')
                    engine = taint_py._Analysis(ast.parse(source))
                    # Retaining every unrelated captured name in every scope
                    # consumes quadratic memory before any budget is charged.
                    retained = sum(len(names) for names in engine.used_names.values())
                    self.assertLessEqual(retained, 4 * count)
                    effects = engine.analyze()
                    expected = {('eval', 4 * count + 1, 1)} if unsafe else set()
                    self.assertEqual({key[:3] for key in effects}, expected)

    def test_scope_dependencies_keep_transitive_closures_and_class_bodies(self):
        bodies = (
            '    alias = payload\n'
            '    def leaf():\n        return alias\n'
            '    def relay():\n        callback = leaf\n        return callback()\n'
            '    def invoke():\n        def further():\n            return relay()\n'
            '        return further()\n    return invoke()\n',
            '    def leaf():\n        return payload\n'
            '    def dispatch(callback):\n        return callback()\n'
            '    return dispatch(leaf)\n',
            '    def choose(value=payload):\n        return value\n'
            '    return choose()\n',
            '    class Local:\n        @staticmethod\n'
            '        def value():\n            return payload\n'
            '    return Local.value()\n',
        )
        for index, body in enumerate(bodies):
            for unsafe in (True, False):
                with self.subTest(shape=index, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    source = ('payload = "unrelated global"\n'
                              'def unrelated(noise):\n    def inner():\n        return noise\n'
                              '    return inner\n'
                              'def outer(payload):\n' + body + f'eval(outer({actual}))\n')
                    effects = taint_py._Analysis(ast.parse(source)).analyze()
                    expected = {('eval', len(source.splitlines()), 1)} if unsafe else set()
                    self.assertEqual({key[:3] for key in effects}, expected, effects)

    def test_lazy_scope_dependencies_keep_escaped_callable_flows(self):
        shapes = (
            'callback = maker(token)\ndef caller():\n    eval(callback())\n',
            'callback = maker(token)\ndef first():\n    return second()\n'
            'def second():\n    return callback\ndef caller():\n    eval(first()())\n',
            'callback = maker(token)\ndef invoke(target):\n    return target()\n'
            'def caller():\n    eval(invoke(callback))\n',
            'def provide():\n    return maker(token)\ndef caller():\n    eval(provide()())\n',
            'def provide():\n    yield maker(token)\ndef caller():\n'
            '    for callback in provide():\n        eval(callback())\n',
            'async def provide():\n    return maker(token)\nasync def caller():\n'
            '    callback = await provide()\n    eval(callback())\n',
            'callback = maker(token)\ndef invoke(target=callback):\n    return target()\n'
            'def caller():\n    eval(invoke())\n',
            'callback = maker(token)\ndef caller():\n'
            '    values = [callback() for token in ("fixed",)]\n    eval(values[0])\n',
        )
        definition = ('def maker(token):\n    def read():\n        return token\n'
                      '    return read\n')
        for index, shape in enumerate(shapes):
            for unsafe in (True, False):
                with self.subTest(shape=index, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    source = f'token = {actual}\n' + definition + shape
                    effects = taint_py._Analysis(ast.parse(source)).analyze()
                    expected = {('eval', len(source.splitlines()), 9 if index == 4 else 5)} if unsafe else set()
                    self.assertEqual({key[:3] for key in effects}, expected, effects)

        for unsafe in (True, False):
            with self.subTest(live_heap=True, unsafe=unsafe):
                actual = 'input()' if unsafe else '"fixed"'
                source = ('token = []\n' + definition + 'callback = maker(token)\n'
                          f'def populate():\n    token.append({actual})\n'
                          'def caller():\n    populate()\n    eval(callback()[0])\n')
                effects = taint_py._Analysis(ast.parse(source)).analyze()
                expected = {('eval', len(source.splitlines()), 5)} if unsafe else set()
                self.assertEqual({key[:3] for key in effects}, expected, effects)

    def test_function_initialization_does_not_scan_unrelated_globals(self):
        source = (''.join(f'unrelated{index} = {index}\n' for index in range(400))
                  + 'important = input()\ndef selected():\n    return important\neval(selected())\n')
        engine = taint_py._Analysis(ast.parse(source))
        self.assertEqual({key[:3] for key in engine.analyze()}, {('eval', 404, 1)})
        function = next(function for function in engine.functions if function.name == 'selected')
        visits = []

        class ObservedNames(set):
            def __iter__(self):
                visits.append(len(self))
                return super().__iter__()

        class ObservedBindings(dict):
            def items(self):
                visits.append(len(self))
                return super().items()

        engine.global_names = ObservedNames(engine.global_names)
        engine.globals.bindings = ObservedBindings(engine.globals.bindings)
        _reads, _writes, summary = engine.solve_function(function, ())
        self.assertEqual(summary, engine.summaries[function])
        self.assertLessEqual(sum(visits), 3 * len(engine.used_names[function]),
                             'A tiny function cannot visit the whole module namespace per solve')

    def test_compact_dependencies_keep_incomplete_escaped_aliases(self):
        prefix = ('box = []\ndef maker(box):\n    def read():\n        return box\n'
                  '    return read\ncallback = maker(box)\ndef expensive():\n'
                  + ''.join(f'    padding{index} = {index}\n' for index in range(100))
                  + '    return callback()\ndef caller():\n    alias = expensive()\n')
        for unsafe in (True, False):
            actual = 'input()' if unsafe else '"fixed"'
            source = prefix + f'    alias.append({actual})\n    eval(box[0])\n'
            for allowance in (5000, 20):
                with self.subTest(unsafe=unsafe, allowance=allowance):
                    engine = taint_py._Analysis(ast.parse(source))
                    expensive = next(function for function in engine.functions if function.name == 'expensive')
                    engine.scope_limits[expensive] = engine.scope_remaining[expensive] = allowance
                    if allowance == 20:
                        with self.assertRaises(AnalysisLimit) as raised:
                            engine.analyze()
                        self.assertIn('expensive', str(raised.exception))
                        effects = raised.exception.effects
                    else:
                        effects = engine.analyze()
                    expected = {('eval', len(source.splitlines()), 5)} if unsafe else set()
                    self.assertEqual({key[:3] for key in effects}, expected, effects)

    def test_function_initialization_keeps_dynamic_namespace_bindings(self):
        # Resolver-provided bindings need not appear in the module's static
        # assignment-name index, for example after a wildcard import.
        for binding, expected in (('eval', {('eval', 2, 5)}), ('print', set())):
            with self.subTest(binding=binding):
                tree = ast.parse('def handler():\n    callback(input())\n')
                engine = taint_py._Analysis(tree)
                self.assertNotIn('callback', engine.global_symbols)
                engine.refresh_globals(taint_py._State(bindings={'callback': binding}))
                _reads, _writes, summary = engine.solve_function(tree.body[0], ())
                self.assertEqual({effect[:3] for effect in summary.effects}, expected)

    def test_lazy_closure_globals_do_not_cross_module_ownership(self):
        root = Path('/__ubs_virtual_closure_names__')
        sources = {
            root / 'helpers.py': 'token = "fixed"\ndef maker(token):\n'
                                 '    def read():\n        return token\n'
                                 '    return read\ncallback = maker(token)\n',
            root / 'app.py': 'from helpers import callback\ntoken = input()\n'
                             'def caller():\n    eval(callback())\n',
        }
        with patch.object(taint_py, '_parse_source',
                          side_effect=lambda path: (sources[path], ast.parse(sources[path]))):
            project = taint_py._Project(sources, root)
            engines = {path.name: engine for path, _text, engine, _offset in project.sources}
            self.assertIn('token', engines['helpers.py'].closure_names)
            self.assertNotIn('token', engines['app.py'].closure_names)
            self.assertIs(engines['helpers.py'].closures, engines['app.py'].closures)
            self.assertEqual(list(project.findings()), [])

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

    def test_namespace_cache_accepts_fresh_literals_but_keeps_nested_witnesses(self):
        # Lattice equality omits evidence intentionally, but a cached transfer
        # must not freeze the earlier witness of a receiver, argument or heap
        # value. Fresh equal literal wrappers, conversely, are unchanged input.
        first = taint_py._State(bindings={'label': taint_py._LiteralString('fixed')})
        equal = taint_py._State(bindings={'label': taint_py._LiteralString('fixed')})
        self.assertIsNot(first.bindings['label'], equal.bindings['label'])
        self.assertTrue(taint_py._same_namespace(first, equal))

        tree = ast.parse('class Owner:\n    async def later(self, value):\n        return value\n'
                         'pending = Owner.later(input())\n')
        owner, function, call = tree.body[0], tree.body[0].body[0], tree.body[1].value
        references = frozenset({'object'})
        old = frozenset({taint_py.TaintTrace('input', path=('input', 'long', 'route'))})
        new = frozenset({taint_py.TaintTrace('input', path=('input', 'short'))})
        bindings = (
            lambda fact: taint_py._BoundCallable('append', references, fact),
            lambda fact: taint_py._BoundClassMethod(function, owner, references, fact),
            lambda fact: taint_py._DeferredCall(function, call, (('value', fact),), ()),
            lambda fact: taint_py._DeferredCall(function, call, (), (),
                                                (('callback', taint_py._BoundCallable('append', references, fact)),)),
            lambda fact: taint_py._ArgumentVector(((call, fact, taint_py._LiteralString('sh')),)),
            lambda fact: frozenset({taint_py._BoundCallable('append', references, fact), None}),
        )
        for index, binding in enumerate(bindings):
            with self.subTest(binding=index):
                before = taint_py._State(bindings={'value': binding(old)})
                after = taint_py._State(bindings={'value': binding(new)})
                self.assertEqual(before, after, 'The witnesses deliberately describe equal lattice facts')
                self.assertFalse(taint_py._same_namespace(before, after))
                self.assertTrue(taint_py._same_namespace(before, before.copy()))
        for table in ('value', 'heap'):
            with self.subTest(table=table):
                before, after = taint_py._State(), taint_py._State()
                if table == 'value':
                    before['value'], after['value'] = old, new
                else:
                    before.heap['object'], after.heap['object'] = old, new
                self.assertEqual(before, after)
                self.assertFalse(taint_py._same_namespace(before, after))

    def test_module_cache_matches_fresh_composed_value_witnesses(self):
        prefix = '''import os
import subprocess
import asyncio
label = 'fixed'
def unrelated():
    def child(value=label):
        return value
    return child
def source():
    return indirect()
def indirect():
    return input()
'''
        tails = (
            ('deferred', 'async def later(value):\n    os.system(value)\n'
                         'pending = later(source())\nasyncio.run(pending)\n',
             14, 5, 'input( -> later() -> value -> subprocess execution'),
            ('vector', 'command = ["sh", "-c", source()]\nsubprocess.run(command)\n',
             14, 1, 'input( -> subprocess execution'),
            ('receiver', 'value = source()\nstored = value.format\nos.system(stored())\n',
             15, 1, 'input( -> value -> subprocess execution'),
        )
        for name, tail, line, column, witness in tails:
            for unsafe in (True, False):
                with self.subTest(shape=name, unsafe=unsafe):
                    source = prefix + tail
                    if not unsafe:
                        source = source.replace('return input()', 'return "fixed"')
                    cached = self.scan({'app.py': source})
                    with patch.object(taint_py._Analysis, 'reads_current', lambda self, reads: False), \
                            patch.object(taint_py._Flow, 'possible_exception', fresh_exception_join):
                        fresh = self.scan({'app.py': source})
                    expected = [('app.py', 'py.taint.command', line, column, witness)] if unsafe else []
                    self.assertEqual(cached, expected)
                    self.assertEqual(cached, fresh)

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
                             'input( -> invoke() -> target() -> value -> subprocess execution')] if unsafe else []
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

    def test_call_substitution_tracks_changed_argument_environments(self):
        trace = taint_py.TaintTrace
        formal = frozenset({trace('formal', parameter='p', sanitizers=frozenset({'xss'}),
                                   path=('p', 'member'))})
        left = frozenset({trace('request', sanitizers=frozenset({'sql'}),
                                 path=('request', 'left'))})
        right = frozenset({trace('request', sanitizers=frozenset({'sql'}),
                                  path=('request', 'right'))})
        self.assertEqual(left, right, 'Actual lattice equality must not erase different witnesses')
        cases = (
            (left, {('request', None, frozenset({'sql', 'xss'}),
                     ('request', 'left', 'helper()', 'p', 'member'))}),
            (taint_py.CLEAN, set()),
            (right, {('request', None, frozenset({'sql', 'xss'}),
                      ('request', 'right', 'helper()', 'p', 'member'))}),
            (frozenset({trace('other', parameter='argument', path=('other',))}),
             {('other', 'argument', frozenset({'xss'}), ('other', 'helper()', 'p', 'member'))}),
            (left, {('request', None, frozenset({'sql', 'xss'}),
                     ('request', 'left', 'helper()', 'p', 'member'))}),
        )
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                bound = {}
                budget = Budget(20)
                memo = taint_py._CallSubstitution(engine.substitute_trace, bound, 'helper()', budget)
                self.assertIs(memo(formal), taint_py.CLEAN)
                for actual, expected in cases:
                    bound['p'] = actual
                    before = budget.remaining
                    self.assert_exact_facts(memo(formal), expected)
                    self.assertEqual(budget.remaining, before - 1 - len(actual))
                bound.clear()
                self.assertIs(memo(formal), taint_py.CLEAN)

    def test_call_substitution_keys_formal_witnesses_and_path_limits(self):
        trace = taint_py.TaintTrace
        actual = frozenset({trace('request', path=('request', 'origin'))})
        bound = {name: actual for name in ('p', '@global:p', '@free:p')}
        first = trace('p', parameter='p', path=('p', 'first'))
        second = trace('p', parameter='p', path=('p', 'second'))
        self.assertEqual(first, second, 'Formal lattice equality must not erase different witnesses')
        cases = (
            (first, 8, frozenset(), ('request', 'origin', 'helper()', 'p', 'first')),
            (second, 8, frozenset(), ('request', 'origin', 'helper()', 'p', 'second')),
            (trace('p', parameter='@global:p', path=('p', 'member')), 8,
             frozenset(), ('request', 'origin', 'helper()', 'member')),
            (trace('p', parameter='@free:p', path=('p', 'member')), 8,
             frozenset(), ('request', 'origin', 'helper()', 'member')),
            (trace('p', parameter='p', sanitizers=frozenset({'command'}), path=('p', 'first')), 8,
             frozenset({'command'}), ('request', 'origin', 'helper()', 'p', 'first')),
            (first, 3, frozenset(), ('request', 'p', 'first')),
            (first, 8, frozenset(), ('request', 'origin', 'helper()', 'p', 'first')),
        )
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                memo = taint_py._CallSubstitution(engine.substitute_trace, bound, 'helper()', Budget(40))
                for formal, limit, proofs, path in cases:
                    with self.subTest(path=path), patch.object(taint_py, 'PATH_LIMIT', limit):
                        self.assert_exact_facts(memo(frozenset({formal})),
                                                {('request', None, proofs, path)})
                other = taint_py._CallSubstitution(engine.substitute_trace, bound, 'other()', Budget(2))
                self.assert_exact_facts(other(frozenset({first})),
                                        {('request', None, frozenset(),
                                          ('request', 'origin', 'other()', 'p', 'first'))})

    def test_call_substitution_keeps_header_revocation_separate(self):
        trace = taint_py.TaintTrace
        cr, lf, reset = 'header:cr', 'header:lf', 'header:reset'
        actual = frozenset({trace('request', sanitizers=frozenset({cr, lf, 'sql'}),
                                  path=('request',))})
        formal = frozenset({trace('p', parameter='p', sanitizers=frozenset({reset, cr}),
                                   path=('p',))})
        bound = {'p': actual}
        cases = (
            (taint_py._Flow, frozenset({reset, cr, lf, 'sql'})),
            (header_injection._HeaderFlow, frozenset({reset, cr, 'sql'})),
        )
        memos = [(engine, proofs, taint_py._CallSubstitution(
            engine.substitute_trace, bound, 'same()', Budget(6))) for engine, proofs in cases]
        for _ in range(3):
            for engine, proofs, memo in memos:
                with self.subTest(engine=engine.__name__):
                    expected = {('request', None, proofs, ('request', 'same()', 'p'))}
                    self.assert_exact_facts(memo(formal), expected)
                    self.assert_exact_facts(engine.substitute(formal, bound, 'same()'), expected)

    def test_call_substitution_reuses_expansion_without_refunding_work(self):
        trace = taint_py.TaintTrace
        formal = frozenset({trace('p', parameter='p', path=('p',))})
        bound = {'p': frozenset({trace('first', path=('first',)),
                                trace('second', path=('second',))})}
        expected = {(source, None, frozenset(), (source, 'helper()', 'p'))
                    for source in ('first', 'second')}
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__), \
                    patch.object(engine, 'substitute_trace', wraps=engine.substitute_trace) as transform:
                budget = Budget(8)
                memo = taint_py._CallSubstitution(transform, bound, 'helper()', budget)
                self.assert_exact_facts(memo(formal), expected)
                self.assertEqual(budget.remaining, 5)
                self.assertEqual(transform.call_count, 1)
                self.assert_exact_facts(memo(formal), expected)
                self.assertEqual(budget.remaining, 2)
                self.assertEqual(transform.call_count, 1, 'The same expansion should be reused')
                with self.assertRaisesRegex(AnalysisLimit, 'work limit exceeded.*incomplete'):
                    memo(formal)
                self.assertEqual(budget.remaining, -1)
                self.assertEqual(transform.call_count, 1)
                empty = taint_py._CallSubstitution(transform, bound, 'helper()', Budget(0))
                self.assertIs(empty(taint_py.CLEAN), taint_py.CLEAN)
                self.assertEqual(transform.call_count, 1)

    def test_call_substitution_bounds_retention_and_keeps_overflow_correct(self):
        trace = taint_py.TaintTrace
        formal = frozenset({trace('p', parameter='p', path=('p',))})
        for engine in (taint_py._Flow, header_injection._HeaderFlow):
            with self.subTest(engine=engine.__name__):
                transformations = [0]

                def transform(formal_trace, actual, call_name):
                    transformations[0] += 1
                    return engine.substitute_trace(formal_trace, actual, call_name)

                bound = {'p': frozenset({trace('first', path=('first',))})}
                retained = weakref.ref(bound['p'])
                memo = taint_py._CallSubstitution(transform, bound, 'helper()', Budget(1000))
                self.assertEqual(memo.CACHE_LIMIT, 256)
                self.assert_exact_facts(memo(formal),
                                        {('first', None, frozenset(), ('first', 'helper()', 'p'))})
                for index in range(memo.CACHE_LIMIT + 16):
                    source = f'source-{index}'
                    bound['p'] = frozenset({trace(source, path=(source,))})
                    self.assert_exact_facts(memo(formal),
                                            {(source, None, frozenset(), (source, 'helper()', 'p'))})
                    self.assertLessEqual(len(memo.cache), memo.CACHE_LIMIT)
                self.assertEqual(len(memo.cache), memo.CACHE_LIMIT)
                # The key uses object identity: retaining the actual fact is
                # necessary to keep that identity from being recycled.
                self.assertIsNotNone(retained())
                bound['p'] = retained()
                before = transformations[0]
                self.assert_exact_facts(memo(formal),
                                        {('first', None, frozenset(), ('first', 'helper()', 'p'))})
                self.assertEqual(transformations[0], before)

    def test_call_substitution_reduces_reported_chain_expansions(self):
        from test_taint_python_summaries import subprocess_chain

        def uncached(_transform, bound, call_name, budget):
            return lambda fact: taint_py._Flow.substitute(fact, bound, call_name, budget=budget)

        def scan(source, cached):
            engine = taint_py._Analysis(ast.parse(source))
            expanded = [0]
            advance = taint_py._advance

            def observe(fact, *steps):
                expanded[0] += len(fact)
                return advance(fact, *steps)

            taint_py._advance_trace.cache_clear()
            with contextlib.ExitStack() as patches:
                patches.enter_context(patch.object(taint_py, '_advance', observe))
                if not cached:
                    patches.enter_context(patch.object(taint_py, '_CallSubstitution', uncached))
                effects = engine.analyze()
            witnesses = {key: {(item.source, item.parameter, item.sanitizers, item.path) for item in fact}
                         for key, fact in effects.items()}
            return witnesses, engine.budget.remaining, expanded[0]

        self.addCleanup(taint_py._advance_trace.cache_clear)
        for count in (12, 24):
            for safe in (False, True):
                with self.subTest(functions=count, safe=safe):
                    source = subprocess_chain(count, safe=safe)
                    reference, reference_budget, reference_expansions = scan(source, False)
                    actual, actual_budget, actual_expansions = scan(source, True)
                    expected_sinks = set() if safe else {
                        (kind, line + 12 * index, column, label)
                        for index in range(count)
                        for kind, line, column, label in (
                            ('command', 9, 9, 'subprocess executable'),
                            ('command', 11, 15, 'subprocess execution'))}
                    self.assertEqual(set(actual), expected_sinks)
                    self.assertEqual(actual, reference)
                    self.assertEqual(actual_budget, reference_budget)
                    self.assertLess(actual_expansions, reference_expansions,
                                    'Transitive summary projection must reuse repeated trace expansions')
                    print(f'[{self.id()}] functions={count} safe={safe} '
                          f'expanded={reference_expansions}->{actual_expansions}', flush=True)

    def test_call_substitution_preserves_repeated_recursive_and_cyclic_scans(self):
        bodies = (
            ('step', 'def step(value):\n    if stop:\n        return value\n'
                     '    return step(value)\n'),
            ('first', 'def first(value):\n    if stop:\n        return value\n'
                      '    return second(value)\ndef second(value):\n    return first(value)\n'),
        )

        def uncached(_transform, bound, call_name, budget):
            return lambda fact: taint_py._Flow.substitute(fact, bound, call_name, budget=budget)

        def witnesses(effects):
            return {key: {(item.source, item.parameter, item.sanitizers, item.path) for item in fact}
                    for key, fact in effects.items()}

        for entry, body in bodies:
            first_unsafe = None
            for actual in ('input()', '"trusted"', 'input()'):
                with self.subTest(entry=entry, actual=actual):
                    source = body + f'eval({entry}({actual}))\n'
                    reference = taint_py._Analysis(ast.parse(source))
                    with patch.object(taint_py, '_CallSubstitution', uncached):
                        expected_witnesses = witnesses(reference.analyze())
                    candidate = taint_py._Analysis(ast.parse(source))
                    effects = candidate.analyze()
                    expected_sinks = {('eval', len(source.splitlines()), 1, 'eval')} \
                        if actual == 'input()' else set()
                    self.assertEqual(set(effects), expected_sinks)
                    self.assertEqual(witnesses(effects), expected_witnesses)
                    self.assertEqual(candidate.budget.remaining, reference.budget.remaining)
                    if actual == 'input()':
                        self.assertEqual({item.source for fact in effects.values() for item in fact},
                                         {'input('})
                        if first_unsafe is None:
                            first_unsafe = witnesses(effects)
                        self.assertEqual(witnesses(effects), first_unsafe)


class LargeModuleBudgetTests(unittest.TestCase):
    """An unrelated definition writer cannot starve late security findings."""

    def test_nested_writer_does_not_replay_module_once_per_dependency(self):
        for count in (32, 96):
            for unsafe in (True, False):
                source, expected = large_budget_source(12 * count + 33, unsafe=unsafe)
                with self.subTest(functions=count, unsafe=unsafe):
                    engine = taint_py._Analysis(ast.parse(source))
                    initialize = taint_py._Flow.__init__
                    passes = [0]

                    def observe(flow, owner, scope):
                        if scope is owner.tree:
                            passes[0] += 1
                        initialize(flow, owner, scope)

                    with patch.object(taint_py._Flow, '__init__', observe):
                        effects = engine.analyze()
                    self.assertEqual({key[:3] for key in effects},
                                     {site for site in expected if site[0] != 'header'})
                    self.assertLessEqual(passes[0], 8,
                                         'An unrelated closure must not force one module pass per helper')

    def test_large_files_preserve_all_thirteen_sinks_and_clean_controls(self):
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith('UBS_')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        for line_count in (6568, 9696):
            for unsafe in (True, False):
                source, expected = large_budget_source(line_count, unsafe=unsafe)
                with self.subTest(lines=line_count, unsafe=unsafe):
                    self.assertEqual(len(source.splitlines()), line_count)
                    try:
                        result = subprocess.run(
                            [sys.executable, '-B', str(Path(__file__).resolve()), '--large-budget-worker'],
                            input=source, text=True, capture_output=True, env=environment, timeout=45,
                        )
                    except subprocess.TimeoutExpired as exc:
                        self.fail(f'Large-module analysis failed to make bounded progress: {exc}')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    try:
                        report = json.loads(result.stdout)
                    except json.JSONDecodeError as exc:
                        self.fail(f'Invalid large-module analysis report: {exc}\n{result.stdout}\n{result.stderr}')
                    sites = {tuple(site) for domain in report.values() for site in domain['sites']}
                    self.assertEqual(sites, expected, report)
                    for domain in report.values():
                        self.assertLessEqual(domain['module_passes'], 8, report)
                        self.assertLessEqual(domain['function_passes'], 10 * domain['functions'], report)


class CapturedCellContextTests(unittest.TestCase):
    """Distinct factory cells retain provenance without multiplying contexts."""

    def test_factory_instances_keep_provenance_outside_summary_keys(self):
        for count in (8, 32, 96):
            with self.subTest(factory_calls=count):
                lines = [
                    'def factory(value):',
                    '    def read(): return value',
                    '    return read',
                    'def invoke(callback): return callback()',
                ]
                expected = set()
                for index in range(count):
                    value = 'input()' if index % 2 else '"safe"'
                    lines.append(f'callback{index} = factory({value})')
                    lines.append(f'eval(invoke(callback{index}))')
                    if index % 2:
                        expected.add(('eval', len(lines), 1))
                engine = taint_py._Analysis(ast.parse('\n'.join(lines) + '\n'))
                effects = engine.analyze()
                self.assertEqual({key[:3] for key in effects}, expected)
                invoke = next(function for function in engine.functions if function.name == 'invoke')
                contexts = [key for key in engine.summaries if isinstance(key, tuple) and key[0] is invoke]
                self.assertLessEqual(len(contexts), 2,
                                     'Factory allocations or concrete provenance entered callback summary keys')


class CapturedDefaultValueTests(unittest.TestCase):
    """A function AST is shared; each evaluated default belongs to its creation."""

    def test_repeated_factory_initialization_uses_bounded_summaries(self):
        prefix = ('def factory(value):\n    def callback(arg=value):\n        return arg\n'
                  '    return callback\ndef identity(value):\n    return value\n')
        for count in (10, 50, 200):
            for dirty in (False, True):
                with self.subTest(count=count, dirty=dirty):
                    lines = prefix.splitlines()
                    lines += [f'saved{index} = factory("fixed")' for index in range(count)]
                    expected = set()
                    for index in range(count):
                        actual = 'input()' if dirty else '"fixed"'
                        lines += [f'def caller{index}():', f'    eval(identity({actual}))']
                        if dirty:
                            expected.add(('eval', len(lines), 5))
                    engine = self.assert_sites('\n'.join(lines) + '\n', expected)
                    self.assertLessEqual(engine.work_limit - engine.budget.remaining,
                                         40 * count + 100)
                    contexts = sum(isinstance(key, tuple) and key[0].name == 'factory'
                                   for key in engine.summaries)
                    self.assertLessEqual(contexts, 2)

    def test_repeated_factory_defaults_keep_each_creation_value(self):
        for count in (10, 50, 200):
            for mode in ('clean', 'unsafe', 'mixed'):
                with self.subTest(count=count, mode=mode):
                    lines = ['def factory(value):', '    def target(captured=value):',
                             '        return captured', '    return target']
                    dirty = [mode == 'unsafe' or (mode == 'mixed' and index % 2 == 1)
                             for index in range(count)]
                    for index, unsafe in enumerate(dirty):
                        actual = 'input()' if unsafe else '"fixed"'
                        lines.append(f'saved{index} = factory({actual})')
                    expected = set()
                    for index, unsafe in enumerate(dirty):
                        lines.append(f'eval(saved{index}())')
                        if unsafe:
                            expected.add(('eval', len(lines), 1))
                    engine = self.assert_sites('\n'.join(lines) + '\n', expected)
                    self.assertLessEqual(engine.work_limit - engine.budget.remaining,
                                         40 * count + 100)

    def test_unrelated_captured_globals_do_not_expand_forward_summaries(self):
        prefixes = (
            'def factory(value):\n    def callback(arg=value):\n        return arg\n'
            '    return callback\nsaved = factory("fixed")\n',
            'box = []\nsaved = box.append\n',
        )
        for prefix in prefixes:
            for count in (80, 200):
                helpers = ''.join(
                    f'def f{index}(value):\n    return '
                    + (f'f{index + 1}(value)' if index + 1 < count else 'value') + '\n'
                    for index in range(count)
                )
                for dirty in (False, True):
                    with self.subTest(prefix=prefix, count=count, dirty=dirty):
                        actual = 'input()' if dirty else '"fixed"'
                        source = prefix + helpers + f'eval(f0({actual}))\n'
                        sites = {('eval', len(source.splitlines()), 1)} if dirty else set()
                        engine = self.assert_sites(source, sites)
                        work = engine.work_limit - engine.budget.remaining
                        self.assertLess(work, 150 * count, (count, dirty, work))
                        contexts = sum(isinstance(key, tuple) for key in engine.summaries)
                        self.assertLessEqual(contexts, count + 10)

    def test_global_captures_follow_transitive_dependencies(self):
        factory = ('def factory(value):\n    def callback(arg=value):\n        return arg\n'
                   '    return callback\n')
        helpers = ('def leaf():\n    return saved()\n'
                   'def relay():\n    return leaf()\n')
        shapes = (
            factory + 'saved = factory(SOURCE)\n' + helpers + 'eval(relay())\n',
            factory + 'box = []\nsaved = factory(box)\n' + helpers
            + 'box.append(SOURCE)\neval(relay()[0])\n',
            factory + 'saved = factory("fixed")\n' + helpers
            + 'saved = factory(SOURCE)\nvalue = relay()\n'
            + 'saved = factory("fixed")\neval(value)\n',
        )
        for index, shape in enumerate(shapes):
            for dirty in (False, True):
                with self.subTest(shape=index, dirty=dirty):
                    source = shape.replace('SOURCE', 'input()' if dirty else '"fixed"')
                    sites = {('eval', len(source.splitlines()), 1)} if dirty else set()
                    self.assert_sites(source, sites)

    def test_unrelated_captured_globals_are_not_selected_per_call(self):
        for count in (50, 200):
            for dirty in (False, True):
                with self.subTest(count=count, dirty=dirty):
                    lines = ['def identity(value):', '    return value']
                    lines += [f'saved{index} = lambda captured="fixed": captured'
                              for index in range(count)]
                    expected = set()
                    for index in range(count):
                        lines += [f'def caller{index}():',
                                  '    eval(identity(' + ('input()' if dirty else '"fixed"') + '))']
                        if dirty:
                            expected.add(('eval', len(lines), 5))
                    selected = []
                    original = taint_py._Analysis._call_summary

                    def counted(engine, function, values, candidate_keys=None,
                                global_overrides=(), capture_globals=frozenset(),
                                value_parameters=frozenset()):
                        if function.name == 'identity':
                            keys = values if candidate_keys is None else candidate_keys
                            selected.append(sum(key.startswith('@global:saved') for key in keys))
                        return original(engine, function, values, candidate_keys,
                                        global_overrides, capture_globals, value_parameters)

                    with patch.object(taint_py._Analysis, '_call_summary', counted):
                        engine = self.assert_sites('\n'.join(lines) + '\n', expected)
                    self.assertTrue(selected)
                    self.assertEqual(sum(selected), 0,
                                     'Unused captured globals were scanned for each helper call')
                    self.assertLessEqual(engine.work_limit - engine.budget.remaining,
                                         40 * count + 200)

    def test_global_capture_dependencies_preserve_module_ownership(self):
        root = Path('/__ubs_default_capture_owners__')
        helpers = ('def factory(value):\n    def target(arg=value):\n        return arg\n'
                   '    return target\ndef leaf():\n    return saved()\n'
                   'def relay():\n    return leaf()\n')
        app = ('import left\nimport right\nsaved = "unrelated"\ndef run():\n'
               '    eval(left.relay())\n    eval(right.relay())\n')
        for left_dirty in (False, True):
            with self.subTest(left_dirty=left_dirty):
                sources = {root / 'app.py': app}
                for name, dirty in (('left', left_dirty), ('right', not left_dirty)):
                    value = 'input()' if dirty else '"fixed"'
                    sources[root / (name + '.py')] = helpers + f'saved = factory({value})\n'
                with patch.object(taint_py, '_parse_source',
                                  side_effect=lambda path: (sources[path], ast.parse(sources[path]))):
                    findings = list(taint_py._Project(list(sources), root).findings())
                self.assertEqual({(path.name, rule, line, column)
                                  for path, rule, line, column, _ in findings},
                                 {('app.py', 'py.taint.eval', 5 if left_dirty else 6, 5)})

    def test_interrupted_relay_retains_global_capture_dependencies(self):
        for dirty in (False, True):
            lines = ['saved = lambda arg=' + ('input()' if dirty else '"fixed"') + ': arg',
                     'def leaf():', '    return saved()', 'def relay():',
                     '    value = leaf()', '    if choice:', '        return value']
            lines += ['    padding = "fixed"'] * 100
            lines += ['    return "fixed"', 'eval(relay())']
            source = '\n'.join(lines) + '\n'
            expected = {('eval', len(lines), 1)} if dirty else set()
            self.assert_sites(source, expected)
            with self.subTest(dirty=dirty):
                engine = taint_py._Analysis(ast.parse(source))
                function = next(fn for fn in engine.functions if getattr(fn, 'name', None) == 'relay')
                engine.scope_limits[function] = 60
                engine.scope_remaining[function] = 60
                with self.assertRaisesRegex(AnalysisLimit, 'relay.*function work limit') as caught:
                    engine.analyze()
                self.assertEqual({effect[:3] for effect in caught.exception.effects}, expected)
                self.assertTrue(engine.failed_summaries[function].capture_globals)
                self.assertGreater(engine.budget.remaining, 0)

    def test_direct_global_filter_keeps_relevant_creation_and_deferred_reads(self):
        shapes = (
            ('def factory():\n    def target(captured=selected):\n        return captured\n'
             '    return target\nselected=SOURCE\ncallback=factory()\n'
             'selected="fixed"\neval(callback())\n', {('eval', 8, 1)}),
            ('def fixed():\n    return "fixed"\ndef factory(value):\n'
             '    def target(captured=value):\n        return selected(captured)\n'
             '    return target\nselected=eval\ncallback=factory(SOURCE)\n'
             'callback()\nselected=print\n', {('eval', 5, 16)}),
            ('def factory():\n    def target(captured=selected):\n        captured(SOURCE)\n'
             '    return target\nbox=[]\nselected=box.append\ncallback=factory()\n'
             'selected=print\ncallback()\neval(box[0])\n', {('eval', 10, 1)}),
        )
        for index, (shape, expected) in enumerate(shapes):
            for dirty in (False, True):
                with self.subTest(shape=index, dirty=dirty):
                    source = shape.replace('SOURCE', 'input()' if dirty else '"fixed"')
                    engine = self.assert_sites(source, expected if dirty else set())
                    factory = next(fn for fn in engine.functions if getattr(fn, 'name', None) == 'factory')
                    self.assertIn(factory, engine.direct_global_functions)
        source = ('import os, shlex\ndef passthrough(value): return value\n'
                  'def factory(value):\n    return selected(value)\nselected=passthrough\n'
                  'os.system(factory(input()))\nselected=shlex.quote\nos.system(factory(input()))\n')
        self.assert_sites(source, {('command', 6, 1)})

    def test_definition_header_calls_keep_indirect_global_contexts(self):
        headers = (
            'def factory():\n    def target(captured=read()):\n'
            '        return captured\n    return target\n',
            'def factory():\n    return lambda captured=read(): captured\n',
        )
        prefix = ('def fixed():\n    return "fixed"\ndef read():\n    return selected()\n')
        for index, header in enumerate(headers):
            for dirty in (False, True):
                with self.subTest(header=index, dirty=dirty):
                    source = (prefix + header + 'selected=' + ('input' if dirty else 'fixed')
                              + '\ncallback=factory()\nselected=fixed\neval(callback())\n')
                    expected = {('eval', len(source.splitlines()), 1)} if dirty else set()
                    engine = self.assert_sites(source, expected)
                    factory = next(fn for fn in engine.functions if getattr(fn, 'name', None) == 'factory')
                    self.assertNotIn(factory, engine.direct_global_functions)

    def test_factory_filter_preserves_imported_scalar_and_callback_defaults(self):
        root = Path('/__ubs_factory_import_controls__')
        helpers = (
            'from values import selected\ndef factory():\n'
            '    def target(captured=selected):\n        return captured\n    return target\n',
            'def factory():\n    from values import selected\n'
            '    def target(captured=selected):\n        return captured\n    return target\n',
            'def factory():\n    from values import source\n'
            '    def target(captured=source):\n        return captured()\n    return target\n',
        )
        app = 'from helpers import factory\ncallback=factory()\neval(callback())\n'
        for index, helper in enumerate(helpers):
            for dirty in (False, True):
                with self.subTest(helper=index, dirty=dirty):
                    values = ('selected=' + ('input()' if dirty else '"fixed"')
                              + '\nsource=' + ('input' if dirty else '(lambda: "fixed")') + '\n')
                    sources = {root / 'values.py': values, root / 'helpers.py': helper, root / 'app.py': app}
                    with patch.object(taint_py, '_parse_source',
                                      side_effect=lambda path: (sources[path], ast.parse(sources[path]))):
                        findings = list(taint_py._Project(list(sources), root).findings())
                    self.assertEqual({(path.name, rule, line, column)
                                      for path, rule, line, column, _ in findings},
                                     {('app.py', 'py.taint.eval', 3, 1)} if dirty else set())

    def assert_sites(self, source, expected, *, scope=None):
        settings = {'UBS_PYTHON_FLOW_SCOPE_STEPS': str(scope)} if scope is not None else {}
        with patch.dict(os.environ, settings):
            engine = taint_py._Analysis(ast.parse(source))
            if scope == 60:
                with self.assertRaisesRegex(AnalysisLimit, 'factory.*function work limit') as caught:
                    engine.analyze()
                effects = caught.exception.effects
                for fact in effects.values():
                    self.assertTrue(all(taint_py._INCOMPLETE_PROOF in trace.sanitizers for trace in fact))
            else:
                effects = engine.analyze()
        actual = {(kind, line, column) for kind, line, column, _label in effects}
        self.assertEqual(actual, expected, source)
        return engine

    def test_safe_and_unsafe_creations_keep_their_own_defaults(self):
        factories = (
            ('value', 'def factory(value):\n    def target(captured=value):\n        return captured\n    return target\n',
             'input()', '"fixed"'),
            ('lambda', 'def factory(value):\n    return lambda *, captured=value: captured\n',
             'input()', '"fixed"'),
            ('callback-result', 'def factory(callback):\n    def target(captured=callback()):\n        return captured\n    return target\n',
             'input', 'fixed'),
            ('callback-value', 'def factory(callback):\n    def target(captured=callback):\n        return captured()\n    return target\n',
             'input', 'fixed'),
            ('nested', 'def factory(value):\n    def inner(captured=value):\n        return captured\n'
                       '    def target(callback=inner):\n        return callback()\n    return target\n',
             'input()', '"fixed"'),
        )
        helpers = ('def fixed():\n    return "fixed"\ndef invoke(callback):\n    return callback()\n'
                   'def relay(callback):\n    return invoke(callback)\n')
        for name, factory, dirty, clean in factories:
            for first_dirty in (False, True):
                for invocation in ('{}()', 'invoke({})', 'relay({})'):
                    with self.subTest(factory=name, first_dirty=first_dirty, invocation=invocation):
                        first, second = (dirty, clean) if first_dirty else (clean, dirty)
                        lines = (helpers + factory).splitlines()
                        lines += [f'first = factory({first})', f'second = factory({second})',
                                  f'eval({invocation.format("first")})', f'eval({invocation.format("second")})']
                        expected_line = len(lines) - int(first_dirty)
                        self.assert_sites('\n'.join(lines) + '\n', {('eval', expected_line, 1)})

    def test_nested_framework_dependencies_keep_callable_identity(self):
        for returned, expected in (('q', {('eval', 6, 9)}), ('"fixed"', set())):
            with self.subTest(returned=returned):
                source = ('from fastapi import Depends, Query\ndef build():\n'
                          '    def obtain(q=Query()):\n'
                          f'        return {returned}\n'
                          '    def endpoint(code=Depends(obtain)):\n        eval(code)\n'
                          '    return endpoint\n')
                self.assert_sites(source, expected)

    def test_explicit_arguments_override_captured_defaults(self):
        factory = ('def factory(value):\n    def target(captured=value, *, named=value):\n'
                   '        return captured + named\n    return target\n')
        for invocation, dirty in (("callback('fixed', named='fixed')", False),
                                  ("callback(captured='fixed', named='fixed')", False),
                                  ("callback('fixed')", True),
                                  ("callback(named='fixed')", True)):
            with self.subTest(invocation=invocation):
                lines = factory.splitlines() + ['callback = factory(input())', f'eval({invocation})']
                self.assert_sites('\n'.join(lines) + '\n', {('eval', len(lines), 1)} if dirty else set())

    def test_default_aliases_keep_late_heap_writes_and_bound_receivers(self):
        shapes = (
            'def factory(value):\n    def target(captured=value):\n        return captured\n    return target\n'
            'box = []\ncallback = factory(box)\nother = factory([])\nbox.append(SOURCE)\neval(callback()[0])\n',
            'def factory():\n    box = []\n    def target(captured=box):\n        return captured[0]\n'
            '    box.append(SOURCE)\n    return target\neval(factory()())\n',
            'def factory():\n    box = []\n    def target(captured=box):\n        return captured[0]\n'
            '    try:\n        return target\n    finally:\n        box.append(SOURCE)\neval(factory()())\n',
            'def factory(value):\n    def target(captured=value):\n        captured.append(SOURCE)\n    return target\n'
            'def invoke(callback):\n    callback()\nbox = []\ncallback = factory(box)\n'
            'other = factory([])\ninvoke(callback)\neval(box[0])\n',
            'def factory(value):\n    def target(captured=value):\n        captured(SOURCE)\n    return target\n'
            'def invoke(callback):\n    callback()\nbox = []\ncallback = factory(box.append)\n'
            'other = factory(print)\ninvoke(callback)\neval(box[0])\n',
        )
        for index, shape in enumerate(shapes):
            for dirty in (False, True):
                with self.subTest(shape=index, dirty=dirty):
                    source = shape.replace('SOURCE', 'input()' if dirty else '"fixed"')
                    self.assert_sites(source, {('eval', len(source.splitlines()), 1)} if dirty else set())

    def test_async_and_generator_paths_preserve_captured_defaults(self):
        shapes = (
            'import asyncio\ndef factory(value):\n    async def target(captured=value):\n        return captured\n'
            '    return target\ncallback = factory(SOURCE)\nother = factory("fixed")\neval(asyncio.run(callback()))\n',
            'import asyncio\nasync def factory(value):\n    def target(captured=value):\n        return captured\n'
            '    return target\ncallback = asyncio.run(factory(SOURCE))\n'
            'other = asyncio.run(factory("fixed"))\neval(callback())\n',
            'def factory(value):\n    def target(captured=value):\n        return captured\n    yield target\n'
            'for callback in factory(SOURCE):\n    other = factory("fixed")\n    eval(callback())\n',
            'def factory(value):\n    def target(captured=value):\n        yield captured\n    return target\n'
            'callback = factory(SOURCE)\nother = factory("fixed")\nfor value in callback():\n    eval(value)\n',
            'def factory(value):\n    def target(captured=value):\n        yield "fixed"\n        return captured\n'
            '    return target\ndef caller(callback):\n    value = yield from callback()\n    eval(value)\n'
            'callback = factory(SOURCE)\nother = factory("fixed")\nfor ignored in caller(callback):\n    pass\n',
        )
        for index, shape in enumerate(shapes):
            for dirty in (False, True):
                with self.subTest(shape=index, dirty=dirty):
                    source = shape.replace('SOURCE', 'input()' if dirty else '"fixed"')
                    sink_line = next(line for line, text in enumerate(source.splitlines(), 1) if 'eval(' in text)
                    column = 5 if index >= 2 else 1
                    self.assert_sites(source, {('eval', sink_line, column)} if dirty else set())

    def test_interrupted_factory_keeps_observed_default_sources(self):
        factories = (
            'def factory():\n    def target(captured=SOURCE):\n        return captured\n',
            'def factory():\n    box = []\n    def target(captured=box):\n        return captured[0]\n'
            '    box.append(SOURCE)\n',
        )
        for index, factory in enumerate(factories):
            for dirty in (False, True):
                lines = factory.replace('SOURCE', 'input()' if dirty else '"fixed"').splitlines()
                lines += ['    if choice:', '        return target']
                lines += ['    padding = "fixed"'] * 100
                lines += ['    return target', 'eval(factory()())']
                source = '\n'.join(lines) + '\n'
                expected = {('eval', len(lines), 1)} if dirty else set()
                for scope in (250000, 60):
                    with self.subTest(factory=index, dirty=dirty, scope=scope):
                        self.assert_sites(source, expected, scope=scope)

    def test_concrete_default_facts_do_not_create_contexts(self):
        prefix = ('def factory(value):\n    def target(captured=value):\n        return captured\n    return target\n'
                  'def invoke(callback):\n    return callback()\n')
        counts = []
        for count in (8, 64):
            lines = prefix.splitlines()
            expected = set()
            for index in range(count):
                lines += [f'eval(invoke(factory({"input()" if index % 2 else repr("fixed")})))']
                if index % 2:
                    expected.add(('eval', len(lines), 1))
            engine = self.assert_sites('\n'.join(lines) + '\n', expected)
            counts.append((len(engine.summaries), engine.work_limit - engine.budget.remaining))
        self.assertEqual(counts[0][0], counts[1][0], counts)
        self.assertLessEqual(counts[1][1], 10 * counts[0][1], counts)

    def test_recursive_default_contexts_report_limits_and_retain_findings(self):
        source = ('def factory(callback):\n    def target(previous=callback):\n        return previous()\n'
                  '    return target\ncallback = input\nwhile condition:\n'
                  '    callback = factory(callback)\neval(callback())\n')
        # Use an explicit scope allowance so this exercises scope recovery
        # before the module's expanding callback environment uses its total.
        with patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '2000'}):
            engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(AnalysisLimit, 'function work limit') as caught:
            engine.analyze()
        self.assertEqual({(kind, line, column) for kind, line, column, _ in caught.exception.effects},
                         {('eval', 8, 1)})
        self.assertGreater(engine.budget.remaining, 0)

    def test_captured_value_construction_is_bounded_before_hashing(self):
        lines = ['eval(input())', 'def factory():', '    previous = input']
        for index in range(80):
            lines += [f'    def step_{index}(captured=previous):', '        return captured()',
                      f'    previous = step_{index}']
        lines += ['    return previous', 'factory()']
        engine = taint_py._Analysis(ast.parse('\n'.join(lines) + '\n'))
        with self.assertRaisesRegex(AnalysisLimit, 'captured-default nesting exceeds 64 levels') as caught:
            engine.analyze()
        self.assertEqual({(kind, line, column) for kind, line, column, _ in caught.exception.effects},
                         {('eval', 1, 1)})

    def test_header_default_instances_keep_encoder_and_body_proofs(self):
        sources = (
            ('from urllib.parse import quote\ndef factory(value):\n'
             '    def target(captured=value): return captured\n    return target\n'
             'def view(request, response):\n    raw = factory(request.args["x"])\n'
             '    safe = factory(quote(request.args["x"], safe=""))\n    fixed = factory("fixed")\n'
             '    response.headers["raw"] = raw()\n    response.headers["safe"] = safe()\n'
             '    response.headers["fixed"] = fixed()\n', {('header', 9, 5)}),
            ('def factory(value):\n    def target(captured=value):\n'
             '        return captured.replace("\\r", "").replace("\\n", "")\n    return target\n'
             'def view(request, response):\n    safe = factory(request.args["x"])\n'
             '    response.headers["safe"] = safe()\n', set()),
        )
        for source, expected in sources:
            with self.subTest(expected=expected):
                effects = header_injection._HeaderAnalysis(ast.parse(source)).analyze()
                sites = {key[:3] for key, fact in effects.items()
                         if any(not header_injection._safe(trace) for trace in fact)}
                self.assertEqual(sites, expected)

    def test_incomplete_header_factory_retains_captured_provenance(self):
        for captured in ('input()', '"fixed"', 'quote(input(), safe="")'):
            lines = ['from urllib.parse import quote', 'def factory():',
                     f'    def target(captured={captured}): return captured',
                     '    if choice: return target']
            lines += ['    padding = "fixed"'] * 100
            lines += ['    return target', 'def view(response):',
                      '    response.headers["x"] = factory()()']
            for scope in (250000, 60):
                with self.subTest(captured=captured, scope=scope):
                    with patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': str(scope)}):
                        engine = header_injection._HeaderAnalysis(ast.parse('\n'.join(lines) + '\n'))
                    if scope == 60:
                        with self.assertRaisesRegex(AnalysisLimit, 'factory.*function work limit') as caught:
                            engine.analyze()
                        effects = caught.exception.effects
                    else:
                        effects = engine.analyze()
                    sites = {key[:3] for key, fact in effects.items()
                             if any(not header_injection._safe(trace) for trace in fact)}
                    expected = ({('header', len(lines), 5)}
                                if captured == 'input()' or (scope == 60 and captured != '"fixed"') else set())
                    self.assertEqual(sites, expected)

    def test_shared_capture_graph_comparison_and_hashing_are_bounded(self):
        original_equal = taint_py._FunctionValue.__eq__
        original_hash = taint_py._FunctionValue.__hash__
        for depth in (8, 32):
            with self.subTest(depth=depth):
                visits = {'equal': 0, 'hash': 0}

                def bounded_equal(left, right):
                    visits['equal'] += 1
                    self.assertLessEqual(visits['equal'], 64 * depth,
                                         'Shared captured defaults expanded during equality')
                    return original_equal(left, right)

                def bounded_hash(value):
                    visits['hash'] += 1
                    self.assertLessEqual(visits['hash'], 64 * depth,
                                         'A captured child was recursively rehashed')
                    return original_hash(value)

                source = ('eval(input())\nprevious = input\n'
                          + 'previous = lambda left=previous, right=previous: left()\n' * depth)
                with patch.object(taint_py._FunctionValue, '__eq__', bounded_equal), \
                        patch.object(taint_py._FunctionValue, '__hash__', bounded_hash):
                    self.assert_sites(source, {('eval', 1, 1)})

    def test_mixed_coroutine_capture_depth_is_bounded(self):
        source = ('eval(input())\nasync def defer(value): return value\nprevious = input\n'
                  + ('waiting = defer(previous)\n'
                     'previous = lambda captured=waiting: captured\n') * 33)
        engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(AnalysisLimit, 'captured-default nesting exceeds 64 levels') as caught:
            engine.analyze()
        self.assertEqual({effect[:3] for effect in caught.exception.effects}, {('eval', 1, 1)})
        self.assertGreater(engine.budget.remaining, 0)

    def test_shared_capture_witness_comparison_preserves_evidence(self):
        # Use independently evaluated values from the same real syntax, so
        # identity alone cannot compare the captured graphs or their paths.
        source = ('previous = input()\n'
                  + 'previous = lambda left=previous, right=previous: left()\n' * 16)
        tree = ast.parse(source)
        first = taint_py._Analysis(tree)
        second = taint_py._Analysis(tree)
        first.analyze()
        second.analyze()
        left, right = first.globals.bindings['previous'], second.globals.bindings['previous']
        visits = 0
        original_equal = taint_py.TaintTrace.__eq__

        def bounded_equal(a, b):
            nonlocal visits
            visits += 1
            self.assertLessEqual(visits, 1024, 'Witness comparison revisited shared capture paths')
            return original_equal(a, b)

        with patch.object(taint_py.TaintTrace, '__eq__', bounded_equal):
            self.assertTrue(taint_py._same_witness(left, right))
        original_source = taint_py._Flow.source

        def changed_source(flow, node, state, candidate=None):
            facts = original_source(flow, node, state, candidate)
            return frozenset(taint_py.TaintTrace(trace.source, trace.parameter, trace.sanitizers,
                                                ('changed witness', *trace.path)) for trace in facts)

        third = taint_py._Analysis(tree)
        with patch.object(taint_py._Flow, 'source', changed_source):
            third.analyze()
        changed = third.globals.bindings['previous']
        self.assertEqual(left, changed)
        self.assertEqual(hash(left), hash(changed))
        self.assertFalse(taint_py._same_witness(left, changed))
        self.assertFalse(taint_py._same_namespace(first.globals, third.globals))

    def test_imported_factories_preserve_default_creation_instances(self):
        root = Path('/__ubs_default_capture_test__')
        helpers = ('def factory(value):\n    def target(captured=value):\n        return captured\n'
                   '    return target\ndef invoke(callback):\n    return callback()\n')
        app = ('from helpers import factory, invoke\nfirst = factory(input())\nsecond = factory("fixed")\n'
               'eval(invoke(first))\neval(invoke(second))\n')
        sources = {root / 'helpers.py': helpers, root / 'app.py': app}
        # Only parsing is virtualized; the real project resolver, summaries,
        # module ownership, line mapping and report generation are exercised.
        with patch.object(taint_py, '_parse_source', side_effect=lambda path: (sources[path], ast.parse(sources[path]))):
            findings = list(taint_py._Project(list(sources), root).findings())
        self.assertEqual({(path.name, rule, line, column) for path, rule, line, column, _ in findings},
                         {('app.py', 'py.taint.eval', 4, 1)})


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

    @staticmethod
    def environment(**settings):
        result = {name: value for name, value in os.environ.items()
                  if not name.startswith(('UBS_', 'XDG_'))}
        result.update(PYTHONDONTWRITEBYTECODE='1', UBS_KEEP_TEMP='1')
        result.update(settings)
        return result

    def driver(self, files, environment):
        from ubs_core import py_scan

        selected = self.root / 'selected-files'
        selected.write_bytes(b''.join(os.fsencode(path) + b'\0' for path in files))
        sink, report = self.root / 'budget-findings.jsonl', self.root / 'budget-report.json'
        arguments = ['--files-from', str(selected), '--sink', str(sink), '--json-out', str(report),
                     '--project-dir', str(self.root), '--jobs', '1',
                     '--skip', ','.join(str(number) for number in range(1, 24) if number != 7)]
        stderr = io.StringIO()
        with patch.dict(os.environ, environment, clear=True), contextlib.redirect_stderr(stderr):
            code = py_scan.main(arguments)
        try:
            document = json.loads(report.read_text(encoding='utf-8'))
            records = [json.loads(line) for line in sink.read_text(encoding='utf-8').splitlines()]
        except json.JSONDecodeError as exc:
            self.fail(f'Invalid budget report: {exc}\n{stderr.getvalue()}')
        return code, document, records, stderr.getvalue()

    def test_scope_limit_preserves_independent_sinks_in_the_same_file(self):
        lines = ['def before():', '    eval(input())', 'def expensive():']
        lines.extend(f'    value{index} = {index}' for index in range(300))
        lines.extend(['def after():', '    eval(input())'])
        path = self.source('same-file.py', '\n'.join(lines) + '\n')
        expected = {('py.taint.eval', 2, 5), ('py.taint.eval', len(lines), 5)}
        environment = self.environment(UBS_PYTHON_FLOW_SCOPE_STEPS='200',
                                       UBS_PYTHON_FLOW_MAX_STEPS='100000')
        findings = []
        with patch.dict(os.environ, environment, clear=True), self.assertRaises(AnalysisLimit) as raised:
            findings.extend(taint_py.scan_file_findings(path))
        self.assertEqual({row[:3] for row in findings}, expected, findings)
        for detail in ('expensive', '200', 'incomplete'):
            self.assertIn(detail, str(raised.exception))
        self.assertRegex(str(raised.exception), r'(?:lines?\s+|:)3(?:\D|$)')
        self.assertEqual({key[:3] for key in raised.exception.effects},
                         {('eval', 2, 5), ('eval', len(lines), 5)})

        # A larger explicit, still finite allowance completes the same source
        # without changing the independent sink identities or their evidence.
        environment['UBS_PYTHON_FLOW_SCOPE_STEPS'] = '5000'
        with patch.dict(os.environ, environment, clear=True):
            complete = list(taint_py.scan_file_findings(path))
        self.assertEqual(complete, findings)

    def test_scope_allowance_is_shared_by_recursive_callback_contexts(self):
        names = [f'cb{index}' for index in range(8)]
        swapped, rotated = [names[1], names[0], *names[2:]], [*names[1:], names[0]]
        lines = ['def before():', '    eval(input())',
                 f'def rotate({", ".join(names)}, value):',
                 '    if condition_a:', f'        return rotate({", ".join(swapped)}, value)',
                 '    if condition_b:', f'        return rotate({", ".join(rotated)}, value)',
                 '    return cb0(value)']
        for index in range(8):
            lines.extend([f'def ident{index}(value):', '    return value'])
        arguments = ', '.join(f'ident{index}' for index in range(8))
        lines.extend(['def expensive():', f'    return rotate({arguments}, input())',
                      'def after():', '    eval(input())'])
        path = self.source('callback-contexts.py', '\n'.join(lines) + '\n')
        initialize = taint_py._Flow.__init__
        solves = [0]

        def observe(flow, engine, scope):
            if getattr(scope, 'name', '') == 'rotate':
                solves[0] += 1
            initialize(flow, engine, scope)

        environment = self.environment(UBS_PYTHON_FLOW_SCOPE_STEPS='2500',
                                       UBS_PYTHON_FLOW_MAX_STEPS='1000000')
        findings = []
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(taint_py._Flow, '__init__', observe), self.assertRaises(AnalysisLimit) as raised:
            findings.extend(taint_py.scan_file_findings(path))
        self.assertEqual({row[:3] for row in findings},
                         {('py.taint.eval', 2, 5), ('py.taint.eval', len(lines), 5)}, findings)
        self.assertIn('rotate', str(raised.exception))
        self.assertIn('2500', str(raised.exception))
        self.assertGreater(solves[0], 1, 'The source must request specialized callback contexts')
        self.assertLessEqual(solves[0], 100,
                             'New callable permutations cannot reset the function work allowance')

    def test_failed_context_preserves_previously_completed_base_effects(self):
        source = '''def expensive(callback):
    callback()
    eval(input())
def stop():
    raise RuntimeError()
def caller():
    expensive(stop)
def tail():
    eval(input())
'''
        expected = {('eval', 3, 5), ('eval', 9, 5)}
        self.assertEqual({key[:3] for key in taint_py._Analysis(ast.parse(source)).analyze()}, expected)
        engine = taint_py._Analysis(ast.parse(source))
        expensive = next(function for function in engine.functions if function.name == 'expensive')
        # The generic solve completes in nine units; its nonreturning callback
        # context then exhausts the cumulative scope allowance. An incomplete
        # replacement summary must retain the base entry's established sink.
        engine.scope_limits[expensive] = engine.scope_remaining[expensive] = 10
        with self.assertRaises(AnalysisLimit) as raised:
            engine.analyze()
        self.assertEqual({key[:3] for key in raised.exception.effects}, expected)
        self.assertIn('expensive', str(raised.exception))

    def test_limited_import_cycle_keeps_completed_member_effects(self):
        files = [
            self.source('a.py', 'import b\ndef first():\n    eval(input())\n'),
            self.source('b.py', 'import a\ndef hard():\n    x = input()\n'
                                '    y = str(x)\n    return y\n'),
            self.source('z.py', 'def last():\n    eval(input())\n'),
        ]
        project = taint_py._Project(files, self.root)
        engines = {path.name: engine for path, _, engine, _ in project.sources}
        owner = engines['b.py']
        hard = next(function for function in owner.functions if function.name == 'hard')
        owner.scope_limits[hard] = owner.scope_remaining[hard] = 2
        findings = []
        with self.assertRaises(AnalysisLimit) as raised:
            findings.extend(project.findings())
        self.assertEqual({(path.name, rule, line, column) for path, rule, line, column, _ in findings},
                         {('a.py', 'py.taint.eval', 3, 5), ('z.py', 'py.taint.eval', 2, 5)}, findings)
        self.assertIn('hard', str(raised.exception))
        self.assertFalse(project.ready & {engines['a.py'], engines['b.py']},
                         'Retained findings do not make a partial import cycle reusable')

    def test_incomplete_helper_cannot_preserve_unproved_sanitizer_contract(self):
        for actual, unsafe in (('input()', True), ('"fixed"', False)):
            lines = ['import os', 'import shlex', 'def expensive(value):']
            lines.extend(f'    local{index} = {index}' for index in range(300))
            lines.extend(['    return decode_unknown(value)', 'def caller():',
                          f'    os.system(expensive(shlex.quote({actual})))'])
            path = self.source(f'incomplete-contract-{unsafe}.py', '\n'.join(lines) + '\n')
            environment = self.environment(UBS_PYTHON_FLOW_SCOPE_STEPS='200',
                                           UBS_PYTHON_FLOW_MAX_STEPS='100000')
            findings = []
            with self.subTest(unsafe=unsafe), patch.dict(os.environ, environment, clear=True), \
                    self.assertRaises(AnalysisLimit) as raised:
                findings.extend(taint_py.scan_file_findings(path))
            expected = {('py.taint.command', len(lines), 5)} if unsafe else set()
            self.assertEqual({row[:3] for row in findings}, expected, findings)
            self.assertIn('expensive', str(raised.exception))
            if unsafe:
                self.assertIn('input', findings[0][-1])

    def assert_budgeted_mutation_sites(self, lines, kind, unsafe, *, column=5):
        source = '\n'.join(lines) + '\n'
        expected = {(kind, len(lines), column)} if unsafe else set()
        engine_type = header_injection._HeaderAnalysis if kind == 'header' else taint_py._Analysis
        for allowance in (5000, 100):
            with self.subTest(scope_allowance=allowance):
                environment = self.environment(UBS_PYTHON_FLOW_SCOPE_STEPS=str(allowance),
                                               UBS_PYTHON_FLOW_MAX_STEPS='100000')
                with patch.dict(os.environ, environment, clear=True):
                    engine = engine_type(ast.parse(source))
                    if allowance == 100:
                        with self.assertRaises(AnalysisLimit) as raised:
                            engine.analyze()
                        self.assertIn('populate', str(raised.exception))
                        self.assertIn('100', str(raised.exception))
                        effects = raised.exception.effects
                    else:
                        effects = engine.analyze()
                sites = {key[:3] for key, facts in effects.items()
                         if key[0] != 'header' or any(not header_injection._safe(trace) for trace in facts)}
                self.assertEqual(sites, expected, effects)
                if unsafe:
                    self.assertTrue(any('input' in trace.source for facts in effects.values() for trace in facts),
                                    'The retained finding must have real external-input provenance')

    def test_incomplete_mutations_reach_callers_through_aliases_and_await(self):
        # The write precedes the cutoff. Ignoring the helper's return cannot
        # erase it, and coroutine construction must defer it until the await.
        modes = ('sync', 'await', 'run', 'return_alias', 'aliased_argument', 'symbolic_write')
        for mode in modes:
            for unsafe in (True, False):
                with self.subTest(mode=mode, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    is_async = mode in ('await', 'run')
                    arguments = 'box, value' if mode == 'symbolic_write' else 'box'
                    write = 'value' if mode == 'symbolic_write' else actual
                    lines = ['import asyncio',
                             f'{"async " if is_async else ""}def populate({arguments}):',
                             f'    box.append({write})']
                    lines.extend(f'    padding{index} = {index}' for index in range(100))
                    lines.extend(['    return box',
                                  f'{"async " if mode == "await" else ""}def caller():'])
                    if mode == 'return_alias':
                        lines.extend(['    result = populate([])', '    eval(result[0])'])
                    else:
                        lines.append('    box = []')
                        if mode == 'await':
                            lines.append('    await populate(box)')
                        elif mode == 'run':
                            lines.append('    asyncio.run(populate(box))')
                        elif mode == 'aliased_argument':
                            lines.extend(['    alias = box', '    populate(alias)'])
                        elif mode == 'symbolic_write':
                            lines.append(f'    populate(box, {actual})')
                        else:
                            lines.append('    populate(box)')
                        lines.append('    eval(box[0])')
                    self.assert_budgeted_mutation_sites(lines, 'eval', unsafe)

    def test_incomplete_mutation_revokes_argument_encoding_proofs(self):
        domains = (
            ('command', 'shlex.quote', 'os.system(box[0])'),
            ('header', 'urllib.parse.quote', 'response.headers["X-Result"] = box[0]'),
        )
        for kind, sanitizer, sink in domains:
            for unsafe in (True, False):
                with self.subTest(domain=kind, unsafe=unsafe):
                    initial = f'{sanitizer}(input())' if unsafe else '"fixed"'
                    write = 'input()' if unsafe else '"fixed"'
                    lines = ['import os', 'import shlex', 'import urllib.parse', 'def populate(box):']
                    lines.extend(f'    padding{index} = {index}' for index in range(100))
                    # The unseen suffix can replace an encoded value. A partial
                    # warning needs only the already-known argument provenance;
                    # the fixed-input control has no external source to invent.
                    lines.extend([f'    box[0] = {write}', 'def caller():', f'    box = [{initial}]',
                                  '    populate(box)', f'    {sink}'])
                    self.assert_budgeted_mutation_sites(lines, kind, unsafe)

    def test_incomplete_return_keeps_possible_argument_aliases(self):
        for unsafe in (True, False):
            with self.subTest(unsafe=unsafe):
                actual = 'input()' if unsafe else '"fixed"'
                lines = ['def populate(box):', '    box.append("fixed")']
                lines.extend(f'    padding{index} = {index}' for index in range(100))
                lines.extend(['    return box', 'def caller():', '    box = []',
                              '    result = populate(box)', f'    result.append({actual})',
                              '    eval(box[0])'])
                self.assert_budgeted_mutation_sites(lines, 'eval', unsafe)

    def test_incomplete_return_keeps_observed_branch_sources(self):
        for container in (False, True):
            for unsafe in (True, False):
                with self.subTest(container=container, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    returned = f'[{actual}]' if container else actual
                    lines = ['def populate():', '    if flag:', f'        return {returned}']
                    lines.extend(f'    padding{index} = {index}' for index in range(100))
                    lines.extend(['    return "fixed"', 'def caller():',
                                  '    eval(populate()[0])' if container else '    eval(populate())'])
                    # capture() must retain the completed branch's value when
                    # a different reachable path exhausts the scope allowance.
                    self.assert_budgeted_mutation_sites(lines, 'eval', unsafe)

    def test_incomplete_generator_keeps_yield_from_completion_values_and_aliases(self):
        for alias in (False, True):
            for unsafe in (True, False):
                with self.subTest(alias=alias, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    lines = [f'def populate({"box" if alias else ""}):',
                             '    if flag:', f'        return {"box" if alias else actual}',
                             '    yield "fixed"']
                    lines.extend(f'    padding{index} = {index}' for index in range(100))
                    lines.extend([f'    return {"box" if alias else "None"}', 'def caller():'])
                    if alias:
                        lines.extend(['    box = []', '    result = yield from populate(box)',
                                      f'    result.append({actual})', '    eval(box[0])'])
                    else:
                        lines.extend(['    result = yield from populate()', '    eval(result)'])
                    # A generator has separate yielded-value and completion
                    # channels. The retained return observation must reach
                    # the value of yield-from, including its object identity.
                    self.assert_budgeted_mutation_sites(lines, 'eval', unsafe)

    def test_incomplete_exception_keeps_observed_payloads_in_callers(self):
        for mode in ('explicit', 'assert', 'delegated'):
            for unsafe in (True, False):
                with self.subTest(mode=mode, unsafe=unsafe):
                    actual = 'input()' if unsafe else '"fixed"'
                    lines = ['def raises():', f'    raise ValueError({actual})'] if mode == 'delegated' else []
                    lines.extend(['def populate():', '    if flag:'])
                    if mode == 'assert':
                        lines.append(f'        assert False, {actual}')
                    elif mode == 'delegated':
                        lines.append('        raises()')
                    else:
                        lines.append(f'        raise ValueError({actual})')
                    lines.extend(f'    padding{index} = {index}' for index in range(100))
                    exception = 'AssertionError' if mode == 'assert' else 'ValueError'
                    lines.extend(['    return "fixed"', 'def caller():', '    try:', '        populate()',
                                  f'    except {exception} as error:', '        eval(str(error))'])
                    # The exceptional branch finishes before a different
                    # reachable path exhausts its allowance. Its payload must
                    # survive the incomplete summary and reach the handler.
                    self.assert_budgeted_mutation_sites(lines, 'eval', unsafe, column=9)

    def test_failed_context_keeps_mutations_of_an_earlier_completed_context(self):
        source = '''def populate(callback, box):
    callback(box)
def dirty(box):
    box.append(input())
def stop(box):
    raise RuntimeError()
def first():
    box = []
    populate(dirty, box)
    eval(box[0])
def second():
    populate(stop, [])
'''
        for unsafe in (True, False):
            with self.subTest(unsafe=unsafe):
                selected = source if unsafe else source.replace('input()', '"fixed"')
                expected = {('eval', 10, 5)} if unsafe else set()
                complete = taint_py._Analysis(ast.parse(selected)).analyze()
                self.assertEqual({key[:3] for key in complete}, expected)
                engine = taint_py._Analysis(ast.parse(selected))
                populate = next(function for function in engine.functions if function.name == 'populate')
                # Base plus dirty context use twelve units (ten for the clean
                # control). The subsequent stop context needs five more. Its
                # cutoff cannot erase the earlier context's established write.
                engine.scope_limits[populate] = engine.scope_remaining[populate] = 14
                with self.assertRaises(AnalysisLimit) as raised:
                    engine.analyze()
                self.assertEqual({key[:3] for key in raised.exception.effects}, expected)
                self.assertIn('populate', str(raised.exception))

    def test_invalid_flow_limits_are_partial_native_reports(self):
        path = self.source('invalid-budget.py', 'response.headers["X-User"] = input()\n')
        for variable in ('UBS_PYTHON_FLOW_SCOPE_STEPS', 'UBS_PYTHON_FLOW_MAX_STEPS'):
            for value in ('0', '-1', 'unbounded', '1.5'):
                with self.subTest(variable=variable, value=value):
                    environment = self.environment(UBS_NO_CACHE='1', **{variable: value})
                    code, report, _records, diagnostic = self.driver([path], environment)
                    self.assertEqual(code, 2, diagnostic)
                    self.assertEqual(report['status'], 'partial', report)
                    self.assertEqual(report['module_error'], 'ANALYZER_ERROR', report)
                    self.assertIn(variable, diagnostic)

    def test_budget_changes_invalidate_completed_header_cache_and_never_cache_partial(self):
        lines = ['def expensive():']
        lines.extend(f'    value{index} = {index}' for index in range(300))
        lines.extend(['    response.headers["X-Expensive"] = input()',
                      'def after():', '    response.headers["X-After"] = input()'])
        path = self.source('cached-header.py', '\n'.join(lines) + '\n')
        cache = self.root / 'budget-cache'
        environment = self.environment(UBS_CACHE_DIR=str(cache), UBS_NO_CACHE='0', UBS_PROFILE='1',
                                       UBS_PYTHON_FLOW_SCOPE_STEPS='5000', UBS_PYTHON_FLOW_MAX_STEPS='100000')

        def sites(records):
            return sorted(row['line'] for row in records if row['rule'] == header_injection.RULE_ID)

        for hits in (0, 1):
            result = self.driver([path], environment)
            code, report, records, diagnostic = result
            self.assertEqual((code, report['status']), (1, 'ok'), result)
            self.assertEqual(report['profile']['cache_hits'], hits, result)
            self.assertEqual(sites(records), [len(lines) - 2, len(lines)], diagnostic)
        completed_entries = set(cache.glob('*/files/**/*.json'))
        self.assertTrue(completed_entries, 'The high-budget control must create a reusable completed entry')

        environment['UBS_PYTHON_FLOW_SCOPE_STEPS'] = '200'
        for _attempt in range(2):
            result = self.driver([path], environment)
            code, report, records, diagnostic = result
            self.assertEqual((code, report['status']), (2, 'partial'), result)
            self.assertEqual(report['profile']['cache_hits'], 0, result)
            self.assertEqual(sites(records), [len(lines)], diagnostic)
            self.assertIn('expensive', diagnostic)
            self.assertEqual(set(cache.glob('*/files/**/*.json')), completed_entries,
                             'Changing the allowance must not admit a partial header report')

        environment['UBS_PYTHON_FLOW_SCOPE_STEPS'] = '5000'
        code, report, records, diagnostic = self.driver([path], environment)
        self.assertEqual((code, report['status'], report['profile']['cache_hits']), (1, 'ok', 1), diagnostic)
        self.assertEqual(sites(records), [len(lines) - 2, len(lines)], diagnostic)

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
            self.assertEqual(document['module_error'], 'ANALYSIS_INCOMPLETE', result)
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

    def test_file_limit_during_foreign_scope_recovery_keeps_prefix_findings(self):
        library_source = 'def apply(callback):\n    eval(callback())\n' + ''.join(
            f'    padding{index} = "fixed"\n' for index in range(100))
        files = [self.source('aa_lib.py', library_source),
                 self.source('bb_app.py', 'from aa_lib import apply\ndef callback():\n'
                                         '    return input()\ndef run():\n    apply(callback)\n')]
        project = taint_py._Project(files, self.root)
        engines = {path.name: engine for path, _, engine, _ in project.sources}
        library = engines['aa_lib.py']
        apply = library.functions[0]
        solve = taint_py._Analysis.solve_function
        interrupted = False

        def limit_context(engine, function, context):
            nonlocal interrupted
            if engine.owner(function) is library and context and not interrupted:
                self.assertIn(library, project.ready)
                interrupted = True
                # The concrete callback's prefix establishes the sink before
                # its scope allowance expires. Recovery then exhausts the
                # small remaining file allowance while retaining summaries.
                library.scope_limits[function] = library.scope_remaining[function] = 30
                library.budget.remaining = 32
            return solve(engine, function, context)

        findings = []
        with patch.object(taint_py._Analysis, 'solve_function', limit_context), \
                self.assertRaises(AnalysisLimit) as raised:
            findings.extend(project.findings())
        self.assertTrue(interrupted)
        self.assertEqual({(path.name, rule, line, column) for path, rule, line, column, _ in findings},
                         {('aa_lib.py', 'py.taint.eval', 2, 5)}, findings)
        self.assertIn('input', findings[0][-1])
        for detail in ('aa_lib.py', 'apply', 'work limit'):
            self.assertIn(detail, str(raised.exception))
        self.assertLess(library.budget.remaining, 0)
        self.assertNotIn(apply, library.failed_scopes,
                         'Failed recovery cannot advertise a sentinel that was never constructed')
        self.assertNotIn(engines['bb_app.py'], project.ready)
        self.assertIsNone(library.local_journal)

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
        # The bounded helper has an opaque return, so input still reaches its
        # caller's eval at line 32. Retain that finding as well as both other
        # files; partial status and the cache barrier must remain unchanged.
        # Top-level findings have no guaranteed order, so compare the taint rows sorted.
        self.assertEqual(sorted((Path(row['file']).name, row['rule_id'], row['line'])
                                for row in report['findings'] if row['rule_id'].startswith('python.taint.')),
                         sorted([('a_first.py', 'python.taint.eval', 1),
                                 ('m_callbacks.py', 'python.taint.eval', 32),
                                 ('z_last.py', 'python.taint.eval', 1)]), report)
        self.assertFalse(list((self.root / 'cache').glob('*/files/**/*.json')),
                         'A naturally exhausted scan must not admit partial cache entries')


class SemanticFailureCompletionTests(unittest.TestCase):
    """An unsupported body must not hide independent established findings."""

    def incomplete(self, source):
        engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(AnalysisLimit, 'incomplete') as caught:
            engine.analyze()
        return engine, caught.exception

    def sites(self, error):
        return {key[:3] for key in error.effects}

    def test_semantic_failure_keeps_later_independent_scopes(self):
        source = ('def unsupported(value):\n'
                  '    pending=(value for item in [0])\n'
                  '    value="fixed"\n'
                  '    return next(pending)\n'
                  'def clean():\n'
                  '    eval("fixed")\n'
                  'def vulnerable():\n'
                  '    eval(input())\n')
        engine, error = self.incomplete(source)
        self.assertEqual(self.sites(error), {('eval', 8, 5)})
        self.assertEqual({fn.name for fn in engine.failed_scopes}, {'unsupported'})
        self.assertTrue(engine.failed_summaries[next(iter(engine.failed_scopes))].incomplete)
        self.assertGreater(engine.budget.remaining, 0)
        self.assertEqual(len(error.components), 1)
        self.assertEqual(error.components[0]['symbol'], 'unsupported')
        self.assertEqual((error.components[0]['start_line'], error.components[0]['end_line']), (1, 4))
        self.assertIn('live delayed reads', error.components[0]['reason'])

    def test_incomplete_return_never_reuses_a_sanitizer_proof(self):
        helper = ('import html\n'
                  'def transform(value):\n'
                  '    if choice:\n'
                  '        return html.escape(value)\n'
                  '    pending=(value for item in [0])\n'
                  '    value="fixed"\n'
                  '    return next(pending)\n')
        for value, expected in (('input()', {('xss', 8, 1)}), ('"fixed"', set())):
            with self.subTest(value=value):
                engine, error = self.incomplete(helper + 'HttpResponse(transform(' + value + '))\n')
                self.assertEqual(self.sites(error), expected)
                for fact in error.effects.values():
                    self.assertTrue(all(taint_py._INCOMPLETE_PROOF in trace.sanitizers for trace in fact))
                function = next(fn for fn in engine.functions if fn.name == 'transform')
                self.assertTrue(all(summary.incomplete for key, summary in engine.summaries.items()
                                    if (key[0] if isinstance(key, tuple) else key) is function))

    def test_observed_heap_and_global_writes_survive_semantic_failure(self):
        for dirty in (False, True):
            source = ('code="fixed"\n'
                      'def update(box, value):\n'
                      '    global code\n'
                      '    code=value\n'
                      '    box.append(value)\n'
                      '    pending=(value for item in [0])\n'
                      '    value="fixed"\n'
                      'box=[]\n'
                      'update(box, ' + ('input()' if dirty else '"fixed"') + ')\n'
                      'eval(code)\n'
                      'eval(box[0])\n')
            with self.subTest(dirty=dirty):
                _engine, error = self.incomplete(source)
                self.assertEqual(self.sites(error), {('eval', 10, 1), ('eval', 11, 1)} if dirty else set())

    def test_incomplete_framework_providers_drop_return_and_yield_sanitizers(self):
        for definition, observation in (('def', 'return'), ('async def', 'return'), ('def', 'yield')):
            for early_return in (False, True):
                helper = ('from fastapi import Depends\nimport html\n'
                          + definition + ' transform(value: str):\n')
                if early_return:
                    helper += '    if choice:\n        ' + observation + ' html.escape(value)\n'
                helper += ('    pending=(value for item in [0])\n'
                           '    value=input()\n'
                           '    return next(pending)\n')
                for sink, expected in (('HttpResponse(code)', {'xss'}),
                                       ('HttpResponse(html.escape(code))', set()),
                                       ('eval(code)', {'eval'})):
                    source = helper + 'def endpoint(code=Depends(transform)):\n    ' + sink + '\n'
                    with self.subTest(definition=definition, observation=observation,
                                      early_return=early_return, sink=sink):
                        _engine, error = self.incomplete(source)
                        self.assertEqual({kind for kind, _line, _col in self.sites(error)}, expected)
                        if expected:
                            self.assertEqual({line for _kind, line, _col in self.sites(error)},
                                             {len(source.splitlines())})

    def test_constant_only_incomplete_framework_provider_does_not_invent_input(self):
        source = ('from fastapi import Depends\n'
                  'def transform():\n'
                  '    value="fixed"\n'
                  '    pending=(value for item in [0])\n'
                  '    value="safe"\n'
                  '    return next(pending)\n'
                  'def endpoint(code=Depends(transform)):\n'
                  '    eval(code)\n')
        _engine, error = self.incomplete(source)
        self.assertEqual(self.sites(error), set())

    def test_complete_downstream_dependency_can_establish_fresh_sanitizer_proof(self):
        helper = ('from fastapi import Depends\nimport html\n'
                  'def transform(value: str):\n'
                  '    pending=(value for item in [0])\n'
                  '    value=input()\n'
                  '    return next(pending)\n'
                  'def escaped(code=Depends(transform)):\n'
                  '    return html.escape(code)\n'
                  'def forwarded(code=Depends(escaped)):\n'
                  '    return code\n')
        for sink, expected in (('HttpResponse(code)', set()), ('eval(code)', {'eval'})):
            with self.subTest(sink=sink):
                source = helper + 'def endpoint(code=Depends(forwarded)):\n    ' + sink + '\n'
                _engine, error = self.incomplete(source)
                self.assertEqual({kind for kind, _line, _col in self.sites(error)}, expected)

    def test_imported_provider_quarantine_overrides_restored_shared_summary(self):
        root = Path('/__ubs_incomplete_framework_provider__')
        sources = {
            root / 'aa_lib.py': ('import html\nfrom fastapi import Query\n'
                                'def provide(callback, key=Query()):\n'
                                '    return html.escape(callback()[key])\n'),
            root / 'bb_bad.py': 'from aa_lib import provide\nprovide(globals,input())\n',
            root / 'zz_route.py': ('from fastapi import Depends\nfrom aa_lib import provide\n'
                                  'def endpoint(code=Depends(provide)):\n'
                                  '    HttpResponse(code)\n'
                                  'def independent():\n    eval(input())\n'),
        }
        with patch.object(taint_py, '_parse_source',
                          side_effect=lambda path: (sources[path], ast.parse(sources[path]))):
            project = taint_py._Project(list(sources), root)
        findings = []
        with self.assertRaises(AnalysisLimit):
            findings.extend(project.findings())
        self.assertEqual({(path.name, rule, line) for path, rule, line, _col, _description in findings},
                         {('zz_route.py', 'py.taint.xss', 4), ('zz_route.py', 'py.taint.eval', 6)})
        owner = next(engine for path, _text, engine, _offset in project.sources if path.name == 'aa_lib.py')
        provider = next(fn for fn in owner.functions if fn.name == 'provide')
        self.assertTrue(owner.failed_summaries[provider].incomplete)
        self.assertFalse(owner.summaries[provider].incomplete,
                         'This control must exercise rollback to the earlier shared summary')

    def test_all_failed_scopes_retain_untruncated_structured_locations(self):
        lines = []
        for index in range(12):
            lines.extend((f'def unsupported_{index}(value):',
                          '    pending=(value for item in [0])',
                          '    value="fixed"'))
        lines.extend(('def independent():', '    eval(input())'))
        _engine, error = self.incomplete('\n'.join(lines) + '\n')
        self.assertEqual(self.sites(error), {('eval', 38, 5)})
        self.assertIn('4 more failed scopes', str(error))
        self.assertEqual({item['symbol'] for item in error.components},
                         {f'unsupported_{index}' for index in range(12)})
        for item in error.components:
            index = int(item['symbol'].rsplit('_', 1)[1])
            self.assertEqual((item['start_line'], item['end_line']), (3 * index + 1, 3 * index + 3))

    def test_project_diagnostics_keep_every_input_and_source_coordinate(self):
        root = Path('/__ubs_semantic_failure_components__')
        sources = {root / f'bad{index}.py': 'def broken(:\n' for index in range(5)}
        sources[root / 'scoped.py'] = ('class Handler:\n'
                                      '    def unsupported(self, value):\n'
                                      '        pending=(value for item in [0])\n'
                                      '        value="fixed"\n'
                                      'def independent():\n'
                                      '    eval(input())\n')
        with patch('tokenize.open', side_effect=lambda path: io.StringIO(sources[path])):
            project = taint_py._Project(list(sources), root)
        findings = []
        with self.assertRaises(AnalysisLimit) as caught:
            findings.extend(project.findings())
        self.assertEqual({(path.name, rule, line) for path, rule, line, _col, _description in findings},
                         {('scoped.py', 'py.taint.eval', 6)})
        components = caught.exception.components
        self.assertEqual(len(components), 6)
        self.assertEqual({Path(item['file']).name for item in components},
                         {'bad0.py', 'bad1.py', 'bad2.py', 'bad3.py', 'bad4.py', 'scoped.py'})
        function = next(item for item in components if item['symbol'] != '<module>')
        self.assertEqual(function['symbol'], 'Handler.unsupported')
        self.assertEqual((function['start_line'], function['end_line']), (2, 4))

    def test_total_budget_failure_is_not_reclassified_as_a_recoverable_scope(self):
        engine = taint_py._Analysis(ast.parse('def later():\n    eval(input())\n'))
        engine.budget.remaining = 0
        with self.assertRaisesRegex(AnalysisLimit, 'UBS_PYTHON_FLOW_MAX_STEPS') as caught:
            engine.analyze()
        self.assertFalse(engine.failed_scopes)
        self.assertLess(engine.budget.remaining, 0)
        self.assertEqual(len(caught.exception.components), 1)
        self.assertEqual(caught.exception.components[0]['symbol'], '<module>')


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
                # The caller owns this returned stream and closes it, like io.open.
                return original_open(file, mode, buffering, encoding, errors,  # ubs:ignore[python.lifecycle.file_handle]
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
    if sys.argv[1:] == ['--large-budget-worker']:
        large_budget_worker()
    else:
        unittest.main()
