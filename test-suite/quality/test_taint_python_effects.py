"""Mutable-object and framework integration regressions; fixtures are not executed."""
from __future__ import annotations

import unittest
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from test_taint_python_dataflow import ROOT, SourceTest


class MutableObjectEffectsTests(SourceTest):
    def test_aliases_observe_subscript_and_attribute_writes(self):
        for create, write, read in (("{}", "alias['code'] = input()", "box['code']"),
                                    ("[]", "alias.append(input())", "box[0]"),
                                    ("Object()", "alias.code = input()", "box.code")):
            with self.subTest(write=write):
                self.assert_rules(f'box = {create}\nalias = box\n{write}\neval({read})\n', 'eval')

    def test_output_parameter_writes_reach_caller(self):
        for write in ("target['code'] = value", "target.append(value)", "target.code = value"):
            with self.subTest(write=write):
                self.assert_rules(f'''\
                    def fill(target, value):
                        {write}
                    box = {{}}
                    fill(box, input())
                    eval(box['code'])
                ''', 'eval')
                self.assert_rules(f'''\
                    def fill(target, value):
                        {write}
                    box = {{}}
                    fill(box, 'safe')
                    eval(box['code'])
                ''')

    def test_nested_helpers_propagate_effects_without_using_the_return(self):
        self.assert_rules('''
            def fill(target, value):
                target['code'] = value
            def forward(output, query):
                fill(output, query)
            box = {}
            forward(box, input())
            eval(box['code'])
        ''', 'eval')

    def test_recursive_helpers_converge_with_mutation_effects(self):
        self.assert_rules('''
            def first(target, value):
                if condition:
                    second(target, value)
                target['code'] = value
            def second(target, value):
                first(target, value)
            box = {}
            second(box, input())
            eval(box['code'])
        ''', 'eval')

    def test_returned_parameter_alias_keeps_caller_identity(self):
        self.assert_rules('''
            def identity(target):
                return target
            box = {}
            alias = identity(box)
            alias['code'] = input()
            eval(box['code'])
        ''', 'eval')

    def test_returned_local_object_retains_its_mutations(self):
        self.assert_rules('''
            def build(value):
                box = {}
                alias = box
                alias['code'] = value
                return box
            eval(build(input())['code'])
        ''', 'eval')
        self.assert_rules('''
            def build(unused):
                box = {'code': 'safe'}
                return box
            eval(build(input())['code'])
        ''')

    def test_rebinding_does_not_mutate_the_original_object(self):
        self.assert_rules('''
            box = {'code': 'safe'}
            alias = box
            alias = {}
            alias['code'] = input()
            eval(box['code'])
        ''')
        self.assert_rules('''
            def replace(target, value):
                target = {}
                target['code'] = value
            box = {'code': 'safe'}
            replace(box, input())
            eval(box['code'])
        ''')

    def test_different_allocations_are_not_conflated(self):
        self.assert_rules('''
            left = {}
            right = {'code': 'safe'}
            left['code'] = input()
            eval(right['code'])
        ''')

    def test_conditional_alias_preserves_both_possible_targets(self):
        self.assert_rules('''
            left = {}
            right = {}
            alias = left if condition else right
            alias['code'] = input()
            eval(left['code'])
            eval(right['code'])
        ''', 'eval', 'eval')

    def test_mutation_after_a_read_does_not_retroactively_taint_it(self):
        self.assert_rules('''
            box = {'code': 'safe'}
            eval(box['code'])
            alias = box
            alias['code'] = input()
        ''')

    def test_partial_clean_write_does_not_clean_the_whole_object(self):
        self.assert_rules('''
            box = {}
            box['code'] = input()
            box['other'] = 'safe'
            eval(box['code'])
        ''', 'eval')

    def test_mutation_sanitizers_remain_sink_specific(self):
        self.assert_rules('''
            def fill(target, value):
                target['html'] = html.escape(value)
            box = {}
            fill(box, input())
            HttpResponse(box['html'])
            cursor.execute(box['html'])
        ''', 'sql')

    def test_closure_and_global_object_writes_reach_the_owner(self):
        self.assert_rules('''
            box = {}
            def fill(value):
                box['code'] = value
            fill(input())
            eval(box['code'])
        ''', 'eval')
        self.assert_rules('''
            def outer(value):
                box = {}
                def fill():
                    box['code'] = value
                fill()
                eval(box['code'])
            outer(input())
        ''', 'eval')

    def test_mutable_default_uses_definition_time_identity(self):
        self.assert_rules('''
            box = {}
            def fill(value, target=box):
                target['code'] = value
            fill(input())
            eval(box['code'])
        ''', 'eval')

    def test_literal_keyword_maps_preserve_output_identity(self):
        self.assert_rules('''
            def fill(*, target, value):
                target['code'] = value
            box = {}
            fill(**{'target': box, 'value': input()})
            eval(box['code'])
        ''', 'eval')

    def test_argument_rebinding_does_not_retarget_an_earlier_argument(self):
        self.assert_rules('''
            def fill(target, unused):
                target['code'] = input()
            box = {}
            original = box
            fill(box, box := {})
            eval(original['code'])
            eval(box['code'])
        ''', 'eval')

    def test_later_argument_mutation_is_visible_to_the_callee(self):
        self.assert_rules('''
            def run(target, unused):
                eval(target[0])
            box = []
            run(box, box.append(input()))
        ''', 'eval')

    def test_assignment_target_expressions_are_evaluated(self):
        self.assert_rules("box = {}\nbox[eval(input())] = 'safe'\n", 'eval')
        self.assert_rules("Object(eval(input())).value = 'safe'\n", 'eval')


class FrameworkMutationEffectsTests(SourceTest):
    def test_request_parameter_reaches_a_mutated_output(self):
        self.assert_rules('''
            from fastapi import Query
            def fill(target, value):
                target['code'] = value
            def route(code=Query()):
                box = {}
                fill(box, code)
                eval(box['code'])
        ''', 'eval')

    def test_dependency_returns_a_mutated_local_object(self):
        self.assert_rules('''
            from fastapi import Query, Depends
            def fill(target, value):
                target['code'] = value
            def provider(code=Query()):
                box = {}
                fill(box, code)
                return box
            def route(box=Depends(provider)):
                eval(box['code'])
        ''', 'eval')

    def test_dependency_sanitization_keeps_its_domain(self):
        self.assert_rules('''
            from fastapi import Query, Depends
            def provider(code=Query()):
                box = {}
                alias = box
                alias['html'] = html.escape(code)
                return box
            def route(box=Depends(provider)):
                HttpResponse(box['html'])
                cursor.execute(box['html'])
        ''', 'sql')

    def test_yielded_and_returned_object_values_remain_distinct(self):
        for yielded, returned, expected in (("{'code': 'safe'}", "{'code': code}", ()),
                                           ("{'code': code}", "{'code': 'safe'}", ('eval',))):
            with self.subTest(yielded=yielded):
                self.assert_rules(f'''\
                    from fastapi import Query, Depends
                    def provider(code=Query()):
                        yield {yielded}
                        return {returned}
                    def route(box=Depends(provider)):
                        eval(box['code'])
                ''', *expected)

    def test_dependency_yields_a_mutated_object(self):
        self.assert_rules('''
            from fastapi import Query, Depends
            def provider(code=Query()):
                box = {}
                alias = box
                alias['code'] = code
                yield box
                return {'code': 'safe'}
            def route(box=Depends(provider)):
                eval(box['code'])
        ''', 'eval')

    def test_safe_provider_does_not_inherit_unused_input(self):
        self.assert_rules('''
            from fastapi import Query, Depends
            def provider(code=Query()):
                box = {'code': 'safe'}
                scratch = {}
                scratch['code'] = code
                return box
            def route(box=Depends(provider)):
                eval(box['code'])
        ''')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'Set UBS_TAINT_E2E=1 for real CLI scans')
class MutableObjectCliTests(unittest.TestCase):
    def test_real_json_and_sarif_report_mutable_flows_without_alias_false_positives(self):
        cases = {
            'alias': ("box = {}\nalias = box\nalias['code'] = input()\neval(box['code'])\n", True),
            'helper': ("def fill(box, code):\n    box['code'] = code\nbox = {}\nfill(box, input())\neval(box['code'])\n", True),
            'safe-rebind': ("box = {'code': 'safe'}\nalias = box\nalias = {}\nalias['code'] = input()\neval(box['code'])\n", False),
            'provider': ("from fastapi import Query, Depends\ndef provider(code=Query()):\n    box = {}\n    alias = box\n    alias['code'] = code\n    return box\ndef route(box=Depends(provider)):\n    eval(box['code'])\n", True),
        }
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-mutable-effects'
        artifacts.mkdir(parents=True, exist_ok=True)

        def rule_ids(value):
            if isinstance(value, dict):
                found = {str(value[key]) for key in ('rule', 'ruleId') if key in value}
                return found | set().union(*(rule_ids(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(rule_ids(child) for child in value))
            return set()

        with tempfile.TemporaryDirectory(prefix='ubs-mutable-cli-') as directory:
            target = Path(directory) / 'route.py'
            for name, (source, unsafe) in cases.items():
                target.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, format=output):
                        started = time.monotonic()
                        print(f'[python-mutable-{name}-{output}] RUN', flush=True)
                        result = subprocess.run(
                            [str(ROOT / 'ubs'), str(target), '--only=python', '--ci', f'--format={output}'],
                            cwd=directory, capture_output=True, text=True, timeout=90,
                            env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_SKIP_SIZE_CHECK='1', UBS_NO_CACHE='1'))
                        (artifacts / f'{name}-{output}.json').write_text(result.stdout, encoding='utf-8')
                        (artifacts / f'{name}-{output}.stderr.log').write_text(result.stderr, encoding='utf-8')
                        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        ids = rule_ids(report)
                        self.assertEqual(bool(ids & {'py.taint.eval', 'python.taint.eval'}), unsafe, report)
                        print(f'[python-mutable-{name}-{output}] PASS ({time.monotonic() - started:.3f}s)', flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
