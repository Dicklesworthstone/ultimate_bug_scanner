"""Check loop/branch taint against an independent bounded concrete-path oracle.

The generated source is parsed, never executed. The oracle interprets only
its own small assignment/branch/loop DSL; it neither imports scanner flow
helpers nor invokes the rendered os.system/input calls.
"""
from __future__ import annotations

import ast
import importlib.util
import itertools
from pathlib import Path
import random
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'command_flow_oracle_subject', ROOT / 'modules/helpers/ubs_core/py_detectors/command_injection.py')
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


def make_body(rng, depth=0, in_loop=False):
    body = []
    for _ in range(rng.randrange(2, 6)):
        choices = ['assign', 'sink'] * 3
        if depth < 2:
            choices += ['if', 'loop']
        if in_loop:
            choices += ['break', 'continue']
        kind = rng.choice(choices)
        if kind == 'assign':
            body.append([kind, rng.choice('xyz'), rng.choice(['safe', 'taint', 'x', 'y', 'z'])])
        elif kind == 'sink':
            body.append([kind, rng.choice('xyz'), None])
        elif kind == 'if':
            body.append([kind, rng.randrange(2), make_body(rng, depth + 1, in_loop), make_body(rng, depth + 1, in_loop)])
        elif kind == 'loop':
            body.append([kind, rng.randrange(2), make_body(rng, depth + 1, True)])
        else:
            body.append([kind])
    return body


def render(body, lines, indent=''):
    for node in body:
        kind = node[0]
        if kind == 'assign':
            expr = {'safe': "'echo'", 'taint': 'input()'}.get(node[2], node[2])
            lines.append(f'{indent}{node[1]} = {expr}')
        elif kind == 'sink':
            lines.append(f'{indent}os.system({node[1]})')
            node[2] = len(lines)
        elif kind == 'if':
            lines.append(f'{indent}if flag{node[1]}:')
            render(node[2], lines, indent + '    ')
            lines.append(f'{indent}else:')
            render(node[3], lines, indent + '    ')
        elif kind == 'loop':
            lines.append(f'{indent}for iteration in range(count{node[1]}):')
            render(node[2], lines, indent + '    ')
        else:
            lines.append(indent + kind)


def concrete(body, values, flags, counts, hits):
    for node in body:
        kind = node[0]
        if kind == 'assign':
            values[node[1]] = {'safe': False, 'taint': True}.get(node[2], values.get(node[2], False))
        elif kind == 'sink':
            if values[node[1]]:
                hits.add(node[2])
        elif kind == 'if':
            stop = concrete(node[2] if flags[node[1]] else node[3], values, flags, counts, hits)
            if stop:
                return stop
        elif kind == 'loop':
            for _ in range(counts[node[1]]):
                stop = concrete(node[2], values, flags, counts, hits)
                if stop == 'break':
                    break
        else:
            return kind
    return None


class CommandConcretePathOracleTests(unittest.TestCase):
    def test_seeded_branches_and_loop_exits_never_lose_observed_taint(self):
        rng = random.Random(7312026)
        dangerous_sites = 0
        for index in range(1000):
            body = make_body(rng)
            lines = ['import os', "x = y = z = 'echo'"]
            render(body, lines)
            text = '\n'.join(lines) + '\n'
            expected = set()
            for flags in itertools.product((False, True), repeat=2):
                for counts in itertools.product(range(4), repeat=2):
                    concrete(body, dict.fromkeys('xyz', False), flags, counts, expected)
            dangerous_sites += len(expected)
            analyzer = subject.CommandInjectionAnalyzer(text, text.splitlines())
            analyzer.visit(ast.parse(text))
            with self.subTest(program=index):
                self.assertFalse(expected - set(analyzer.issues), text)
        self.assertEqual(dangerous_sites, 649, 'the seeded oracle corpus changed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
