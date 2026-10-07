"""Finite callable identities, receiver snapshots, and recursive lambda summaries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_taint_python_dataflow import ROOT, SourceTest


class CallableFlowTests(SourceTest):
    def test_builtin_and_qualified_sink_aliases(self):
        for name, kind in (('eval', 'eval'), ('exec', 'eval'), ('os.system', 'command'),
                           ('subprocess.run', 'command'), ('cursor.execute', 'sql'), ('HttpResponse', 'xss')):
            with self.subTest(name=name):
                self.assert_rules(f'run = {name}\nrun(input())\n', kind)

    def test_source_callable_aliases(self):
        for source in ('input', 'builtins.input', 'request.args.get'):
            with self.subTest(source=source):
                self.assert_rules(f'obtain = {source}\neval(obtain())\n', 'eval')

    def test_module_alias_and_import_alias_chains(self):
        self.assert_rules('import subprocess as process\nmodule = process\nrun = module.run\nrun(input())', 'command')
        self.assert_rules('from os import system as execute\nrun = execute\nrun(input())', 'command')

    def test_tuple_unpacking_and_literal_selection(self):
        self.assert_rules('run, read = eval, input\nrun(read())', 'eval')
        self.assert_rules('run = (eval, print)[0]\nrun(input())', 'eval')
        self.assert_rules('run = (eval, print)[1]\nrun(input())')

    def test_conditional_callable_preserves_possible_sink(self):
        self.assert_rules('run = eval if flag else print\nrun(input())', 'eval')
        self.assert_rules('if flag:\n    run = eval\nelse:\n    run = print\nrun(input())', 'eval')
        self.assert_rules('run = eval\nif flag:\n    run = print\nrun(input())', 'eval')

    def test_join_with_unassigned_builtin_preserves_the_builtin_path(self):
        self.assert_rules('if flag:\n    eval = print\neval(input())', 'eval')

    def test_reassignment_is_a_strong_update(self):
        self.assert_rules('run = eval if flag else print\nrun = print\nrun(input())')

    def test_every_possible_sanitizer_must_be_safe_for_the_sink(self):
        self.assert_rules('escape = html.escape if flag else str\nHttpResponse(escape(input()))', 'xss')
        self.assert_rules('escape = html.escape if flag else markupsafe.escape\nHttpResponse(escape(input()))')
        self.assert_rules('escape = html.escape if flag else shlex.quote\ncursor.execute(escape(input()))', 'sql')

    def test_branch_qualified_modules_preserve_command_sink(self):
        self.assert_rules('module = os if flag else other\nrun = module.system\nrun(input())', 'command')

    def test_returned_known_callable_is_invoked(self):
        self.assert_rules('def executor():\n    return eval\nexecutor()(input())', 'eval')
        self.assert_rules('def source():\n    return input\neval(source()())', 'eval')
        self.assert_rules('def escape():\n    return html.escape\nHttpResponse(escape()(input()))')

    def test_source_alias_is_snapshotted_before_prompt_evaluation(self):
        self.assert_rules('read = input\nq = read((read := print))\neval(q)', 'eval')

    def test_safe_shadowed_callables_are_not_builtins(self):
        self.assert_rules('eval = print\nrun = eval\nrun(input())')
        self.assert_rules('def route(eval):\n    run = eval\n    run(input())\nroute(print)')
        self.assert_rules('from project import eval as run\nrun(input())')
        self.assert_rules('HttpResponse = print\nHttpResponse(input())')

    def test_possible_helpers_preserve_sink_and_mutation_effects(self):
        self.assert_rules("def fill(dst):\n    dst['code'] = input()\ndef ignore(dst):\n    pass\nrun = fill if flag else ignore\npayload = {}\nrun(payload)\neval(str(payload))", 'eval')
        self.assert_rules('def execute(code):\n    eval(code)\nrun = execute if flag else print\nrun(input())', 'eval')

    def test_recursive_factory_has_no_spurious_unknown_return(self):
        self.assert_rules('def factory():\n    if flag:\n        return factory()\n    return html.escape\nHttpResponse(factory()(input()))')

    def test_bound_mutator_alias_preserves_its_receiver(self):
        self.assert_rules('payload = []\nappend = payload.append\nappend(input())\neval(str(payload))', 'eval')
        self.assert_rules('payload = []\nalias = payload\nappend = payload.append\npayload = []\nappend(input())\neval(str(alias))', 'eval')
        self.assert_rules('payload = []\nappend = payload.append\npayload = []\nappend(input())\neval(str(payload))')

    def test_returned_bound_mutator_preserves_argument_identity(self):
        self.assert_rules('def adder(dst):\n    return dst.append\npayload = []\nadd = adder(payload)\nadd(input())\neval(str(payload))', 'eval')

    def test_conditional_qualified_source_preserves_possible_input(self):
        self.assert_rules('module = sys if flag else other\neval(module.argv[1])', 'eval')
        self.assert_rules('module = os if flag else other\neval(module.environ["CODE"])', 'eval')

    def test_alternative_target_mutations_are_joined(self):
        self.assert_rules('a = []\nb = []\nappend = a.append if flag else b.append\nappend(input())\neval(str(a))\neval(str(b))', 'eval', 'eval')

    def test_known_callables_do_not_execute_fixture_code(self):
        self.assert_rules("run = eval\nrun('raise SystemExit(12)')")

    def test_framework_source_reaches_an_aliased_sink(self):
        self.assert_rules('from fastapi import Query\ndef route(code=Query()):\n    run = eval if condition else print\n    run(code)', 'eval')

    def test_typed_request_bound_source_alias(self):
        self.assert_rules('from fastapi import Request\nasync def route(req: Request):\n    read = req.body\n    code = await read()\n    eval(code)', 'eval')

    def test_fastapi_router_identity_survives_callable_resolution(self):
        self.assert_rules('from fastapi import FastAPI\napp = FastAPI()\n@app.get("/")\ndef route(code: str):\n    run = eval\n    run(code)', 'eval')

    def test_generator_yielded_callable_is_not_its_final_return(self):
        for yielded, returned, expected in (('html.escape', 'eval', ()), ('eval', 'html.escape', ('eval',))):
            with self.subTest(yielded=yielded):
                self.assert_rules(f'def provider():\n    yield {yielded}\n    return {returned}\nfor run in provider():\n    ' +
                                  ('HttpResponse(run(input()))' if not expected else 'run(input())'), *expected)


class ClassCallableFlowTests(SourceTest):
    """Class-qualified function identity, without inventing instance dispatch."""

    def test_static_helpers_propagate_sinks_sources_and_clean_returns(self):
        for body, call, rules in (
                ('eval(value)', 'Service.run(input())', ('eval',)),
                ('return input()', 'eval(Service.run("safe"))', ('eval',)),
                ('return "safe"', 'eval(Service.run(input()))', ()),
                ('return value', 'eval(Service.run(input()))', ('eval',))):
            with self.subTest(body=body):
                self.assert_rules('class Service:\n    @staticmethod\n    def run(value):\n        ' +
                                  body + '\n' + call, *rules)

    def test_static_sanitizer_domains_are_not_interchangeable(self):
        definition = ('class Service:\n    @staticmethod\n    def escape(value):\n'
                      '        return html.escape(value)\n')
        self.assert_rules(definition + 'HttpResponse(Service.escape(input()))')
        self.assert_rules(definition + 'eval(Service.escape(input()))', 'eval')
        self.assert_rules(definition + 'cursor.execute(Service.escape(input()))', 'sql')

    def test_class_alias_and_captured_static_callback(self):
        definition = 'class Service:\n    @staticmethod\n    def run(value):\n        eval(value)\n'
        for use in ('Alias = Service\nAlias.run(input())',
                    'run = Service.run\nrun(input())',
                    'def apply(callback, value):\n    callback(value)\napply(Service.run, input())'):
            with self.subTest(use=use):
                self.assert_rules(definition + use, 'eval')

    def test_staticmethod_identity_is_binding_based(self):
        for imported, descriptor in (('', 'staticmethod'), ('import builtins\n', 'builtins.staticmethod'),
                                     ('from builtins import staticmethod as static\n', 'static'),
                                     ('static = staticmethod\n', 'static')):
            with self.subTest(descriptor=descriptor):
                self.assert_rules(imported + f'class Service:\n    @{descriptor}\n'
                                  '    def run(value):\n        eval(value)\nService.run(input())', 'eval')
        # A same-spelled decorator can replace its function. It cannot prove
        # that its return is the original clean method.
        for binding in ('staticmethod = unknown\n', 'from application import staticmethod\n'):
            with self.subTest(binding=binding):
                self.assert_rules(binding + 'class Service:\n    @staticmethod\n'
                                  '    def clean(value):\n        return "safe"\n'
                                  'eval(Service.clean(input()))', 'eval')

    def test_unbound_method_uses_explicit_receiver_argument(self):
        definition = 'class Service:\n    def run(self, value):\n        eval(value)\n'
        self.assert_rules(definition + 'Service.run(None, input())', 'eval')
        self.assert_rules(definition + 'Service.run(input(), "safe")')
        self.assert_rules(definition + 'Service.run(value=input(), self=None)', 'eval')

    def test_class_passed_to_or_returned_from_helper_keeps_identity(self):
        definition = 'class Service:\n    @staticmethod\n    def run(value):\n        eval(value)\n'
        self.assert_rules(definition + 'def apply(cls, value):\n    cls.run(value)\n'
                          'apply(Service, input())', 'eval')
        self.assert_rules(definition + 'def select():\n    return Service\nselect().run(input())', 'eval')

    def test_class_global_namespace_is_not_its_method_closure(self):
        # The class assignment must not shadow the module's input() binding
        # inside the method. The reverse case protects benign module bindings.
        self.assert_rules('class Service:\n    input = "safe"\n    @staticmethod\n'
                          '    def run():\n        eval(input())\nService.run()', 'eval')
        self.assert_rules('input = str\nclass Service:\n    @staticmethod\n'
                          '    def run():\n        eval(input())\nService.run()')

    def test_class_namespace_does_not_inherit_module_bindings(self):
        self.assert_rules('clean = html.escape\nclass Service:\n    pass\n'
                          'HttpResponse(Service.clean(input()))', 'xss')

    def test_rebinding_class_name_does_not_rebind_captured_method(self):
        definition = 'class Service:\n    @staticmethod\n    def run(value):\n        eval(value)\n'
        self.assert_rules(definition + 'run = Service.run\nService = other\nrun(input())', 'eval')
        self.assert_rules(definition + 'Service = other\nService.run(input())')

    def test_class_mutations_revoke_known_clean_member_contract(self):
        definition = 'class Service:\n    @staticmethod\n    def clean(value):\n        return "safe"\n'
        for mutation in ('Service.clean = unknown', 'alias = Service\nalias.clean = unknown',
                         'configure(Service)', 'if flag:\n    Service.clean = unknown',
                         'def change(cls):\n    cls.clean = unknown\nchange(Service)'):
            with self.subTest(mutation=mutation):
                self.assert_rules(definition + mutation + '\neval(Service.clean(input()))', 'eval')
        self.assert_rules(definition + 'clean = Service.clean\nService.clean = unknown\n'
                          'eval(clean(input()))')

    def test_mutual_class_method_recursion_reaches_fixed_point(self):
        self.assert_rules('class Service:\n    @staticmethod\n    def first(value, stop):\n'
                          '        return Service.second(value, stop)\n    @staticmethod\n'
                          '    def second(value, stop):\n        if stop:\n            return value\n'
                          '        return Service.first(value, stop)\neval(Service.first(input(), flag))', 'eval')

    def test_helper_global_class_lookup_uses_invocation_time_contract(self):
        definition = ('class Service:\n    @staticmethod\n    def clean(value):\n        return "safe"\n'
                      'def run(value):\n    return Service.clean(value)\n')
        self.assert_rules(definition + 'Service.clean = unknown\neval(run(input()))', 'eval')
        # The same helper has distinct proven and revoked class contexts.
        # Later mutation does not retroactively change its earlier return.
        findings = self.assert_rules(definition + 'eval(run(input()))\nService.clean = unknown\n'
                                     'eval(run(input()))', 'eval')
        self.assertEqual(findings[0]['line'], 9)
        self.assert_rules(definition + 'def change(cls):\n    cls.clean = unknown\n'
                          'change(Service)\neval(run(input()))', 'eval')

    def test_class_helpers_propagate_heap_effects_and_raised_payloads(self):
        self.assert_rules('class Service:\n    @staticmethod\n    def fill(box, value):\n'
                          '        box.append(value)\nbox=[]\nService.fill(box,input())\neval(box[0])', 'eval')
        self.assert_rules('class Service:\n    @staticmethod\n    def raise_value(value):\n'
                          '        raise ValueError(value)\ntry:\n    Service.raise_value(input())\n'
                          'except ValueError as error:\n    eval(str(error))', 'eval')

    def test_async_static_helpers_run_only_when_awaited(self):
        definition = 'class Service:\n    @staticmethod\n    async def run(value):\n        eval(value)\n'
        self.assert_rules(definition + 'Service.run(input())')
        self.assert_rules(definition + 'async def app():\n    await Service.run(input())', 'eval')

    def test_unsupported_class_construction_does_not_prove_clean(self):
        for prefix in ('@decorate\nclass Service:', 'class Service(Base):',
                       'class Service(metaclass=Factory):'):
            with self.subTest(prefix=prefix):
                self.assert_rules(prefix + '\n    @staticmethod\n    def clean(value):\n'
                                  '        return "safe"\neval(Service.clean(input()))', 'eval')
        for decorator in ('classmethod', 'property', 'unknown'):
            with self.subTest(decorator=decorator):
                self.assert_rules(f'class Service:\n    @{decorator}\n    def clean(value):\n'
                                  '        return "safe"\neval(Service.clean(input()))', 'eval')


class FiniteCallableTests(SourceTest):
    def scan(self, source):
        # These fixtures are parsed in a bounded subprocess, never executed.
        probe = ('import json,sys;sys.path.insert(0,sys.argv[1]);'
                 'from test_taint_python_dataflow import SourceTest;'
                 'print(json.dumps(SourceTest().scan(sys.stdin.read())))')
        result = subprocess.run([sys.executable, '-B', '-c', probe, str(Path(__file__).resolve().parent)],
                                input=source, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_loop_callable_joins_converge(self):
        self.assert_rules('run = print\nwhile flag:\n    run = eval if other else run\nrun(input())', 'eval')

    def test_nonreturning_recursive_lambda_does_not_crash(self):
        self.assert_rules('spin = lambda value: spin(value)\neval(spin(input()))')

    def test_recursive_lambda_return_reaches_fixed_point(self):
        self.assert_rules('choose = lambda value: choose(value) if condition else value\neval(choose(input()))', 'eval')

    def test_recursive_lambda_preserves_sanitizer_domain(self):
        self.assert_rules('clean = lambda value: clean(value) if condition else html.escape(value)\nHttpResponse(clean(input()))')
        self.assert_rules('clean = lambda value: clean(value) if condition else html.escape(value)\neval(clean(input()))', 'eval')

    def test_mutually_recursive_lambdas_share_summaries(self):
        self.assert_rules('first = lambda value: second(value)\nsecond = lambda value: first(value) if condition else value\neval(first(input()))', 'eval')

    def test_recursive_lambda_sink_effect_is_not_lost(self):
        self.assert_rules('run = lambda value: (eval(value), run(value))\nrun(input())', 'eval')

    def test_recursive_lambda_mutation_reaches_caller_alias(self):
        self.assert_rules('fill = lambda box, value: fill(box, value) if condition else box.append(value)\nbox = []\nfill(box, input())\neval(str(box))', 'eval')

    def test_deep_lambda_chain_has_no_inline_depth_limit(self):
        source = '\n'.join(f'f{i} = lambda value: f{i + 1}(value)' for i in range(40))
        self.assert_rules(source + '\nf40 = lambda value: value\neval(f0(input()))', 'eval')

    def test_lambda_capture_is_symbolic_and_isolated(self):
        self.assert_rules('def wrap(value):\n    obtain = lambda: value\n    return obtain()\neval(wrap(input()))', 'eval')
        self.assert_rules("value = input()\ndef wrap(value):\n    obtain = lambda: value\n    return obtain()\neval(wrap('safe'))")

    def test_lambda_return_dependencies_remain_parameter_specific(self):
        self.assert_rules("choose = lambda selected, ignored: selected\neval(choose('safe', input()))")
        self.assert_rules("choose = lambda selected, ignored: selected\neval(choose(input(), 'safe'))", 'eval')

    def test_lambda_defaults_and_keywords(self):
        self.assert_rules('run = lambda *, value=input(): eval(value)\nrun()', 'eval')
        self.assert_rules("run = lambda *, value=input(): eval(value)\nrun(value='safe')")

    def test_lambda_returned_alias_observes_mutation(self):
        self.assert_rules("identity = lambda box: box\nsource = {}\nalias = identity(source)\nalias['x'] = input()\neval(str(source))", 'eval')

    def test_lambda_returned_callable_keeps_sink_identity(self):
        self.assert_rules('obtain = lambda: eval\nexecute = obtain()\nexecute(input())', 'eval')

    def test_attribute_alias_loop_has_a_finite_identity_domain(self):
        self.assert_rules('def walk(node):\n    while condition:\n        node = node.parent\n    return node\neval(walk(input()))', 'eval')

    def test_branching_attribute_aliases_reach_a_fixed_point(self):
        self.assert_rules('node = root\nwhile condition:\n    node = node.left if branch else node.right\neval(input())', 'eval')

    def test_loop_attribute_identity_preserves_heap_receiver(self):
        self.assert_rules('values = []\nnode = values\nwhile condition:\n    node = node.next\nnode.append(input())\neval(str(values))', 'eval')

    def test_loop_attribute_identity_preserves_request_sources(self):
        self.assert_rules('node = root\nwhile condition:\n    node = node.next\neval(node.request.args["code"])', 'eval')

    def test_recursive_attribute_alias_does_not_erase_input(self):
        self.assert_rules('def walk(node):\n    return walk(node.next) if condition else node\neval(walk(input()))', 'eval')

    def test_long_unknown_paths_never_become_trusted_sanitizers(self):
        prefix = 'root' + '.next' * 60
        self.assert_rules(f'HttpResponse({prefix}.html.escape(input()))', 'xss')
        self.assert_rules(f'eval({prefix}.django.http.request.body)', 'eval')
        self.assert_rules('HttpResponse(django.utils.html.escape(input()))')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'Set UBS_TAINT_E2E=1 for real CLI scans')
class CallableCliTests(unittest.TestCase):
    def test_real_json_and_sarif_preserve_callable_flows_and_clean_controls(self):
        cases = (
            ('alias', 'run = eval if condition else print\nrun(input())\n', 'eval'),
            ('alias-cleared', 'run = eval if condition else print\nrun = print\nrun(input())\n', None),
            ('recursive', 'choose = lambda value: choose(value) if condition else value\neval(choose(input()))\n', 'eval'),
            ('recursive-clean', 'clean = lambda value: clean(value) if condition else html.escape(value)\nHttpResponse(clean(input()))\n', None),
            ('class-sink', 'class Service:\n    @staticmethod\n    def run(value):\n        eval(value)\nService.run(input())\n', 'eval'),
            ('class-clean', 'class Service:\n    @staticmethod\n    def clean(value):\n        return "safe"\neval(Service.clean(input()))\n', None),
            ('class-replaced', 'class Service:\n    @staticmethod\n    def clean(value):\n        return "safe"\ndef run(value):\n    return Service.clean(value)\nService.clean = other\neval(run(input()))\n', 'eval'),
        )
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-callable-effects'
        artifacts.mkdir(parents=True, exist_ok=True)

        def collect(value):
            if isinstance(value, dict):
                return {item for key, item in value.items() if key in {'rule', 'rule_id', 'ruleId'}
                        and isinstance(item, str)} | set().union(*(collect(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(collect(child) for child in value))
            return set()

        for name, source, expected in cases:
            for output in ('json', 'sarif'):
                with self.subTest(case=name, format=output), tempfile.TemporaryDirectory(prefix='ubs-callable-cli-') as tmp:
                    target = Path(tmp) / 'route.py'
                    target.write_text(source, encoding='utf-8')
                    result = subprocess.run(
                        [str(ROOT / 'ubs'), str(target), '--only=python', '--ci', f'--format={output}'],
                        cwd=tmp, text=True, capture_output=True, timeout=90,
                        env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_SKIP_SIZE_CHECK='1', UBS_NO_CACHE='1'))
                    (artifacts / f'{name}-{output}.json').write_text(result.stdout, encoding='utf-8')
                    (artifacts / f'{name}-{output}.stderr.log').write_text(result.stderr, encoding='utf-8')
                    self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    if output == 'sarif':
                        rules = {item.get('ruleId', '') for run in report.get('runs', []) for item in run.get('results', [])}
                    else:
                        self.assertEqual(report.get('status'), 'ok', report)
                        rules = collect(report)
                    relevant = {rule.split('.')[-1] for rule in rules if rule.startswith(('py.taint.', 'python.taint.'))}
                    self.assertEqual(relevant, {expected} if expected else set(), report)
                    print('CALLABLE_CLI_PASS', name, output, flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
