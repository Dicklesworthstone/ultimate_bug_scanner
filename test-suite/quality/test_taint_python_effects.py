"""Mutable-object regressions; the execution oracle replaces input and eval."""
from __future__ import annotations

import ast
import unittest
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
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


class MutableIterableLoopTests(SourceTest):
    def test_append_reaches_a_later_iteration(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                eval(value)
                values.append(input())
        ''', 'eval')

    def test_alias_write_reaches_a_later_iteration(self):
        self.assert_rules('''
            values = ['safe']
            alias = values
            for value in values:
                eval(value)
                alias.append(input())
        ''', 'eval')

    def test_output_parameter_write_reaches_a_later_iteration(self):
        self.assert_rules('''
            def fill(target, value):
                target.append(value)
            values = ['safe']
            for value in values:
                eval(value)
                fill(values, input())
        ''', 'eval')

    def test_symbolic_iterable_in_helper_observes_its_writes(self):
        self.assert_rules('''
            def consume(values, incoming):
                for value in values:
                    eval(value)
                    values.append(incoming)
            consume(['safe'], input())
        ''', 'eval')

    def test_continue_preserves_mutations_for_next_iteration(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                eval(value)
                values.append(input())
                continue
        ''', 'eval')

    def test_finally_write_on_continue_reaches_next_iteration(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                eval(value)
                try:
                    continue
                finally:
                    values.append(input())
        ''', 'eval')

    def test_break_does_not_invent_another_iteration(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                eval(value)
                values.append(input())
                break
        ''')

    def test_return_does_not_invent_another_iteration(self):
        self.assert_rules('''
            def consume():
                values = ['safe']
                for value in values:
                    eval(value)
                    values.append(input())
                    return
            consume()
        ''')

    def test_raise_does_not_invent_another_iteration(self):
        self.assert_rules('''
            values = ['safe']
            try:
                for value in values:
                    eval(value)
                    values.append(input())
                    raise RuntimeError()
            except RuntimeError:
                pass
        ''')

    def test_iterable_rebinding_does_not_retarget_saved_iterator(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                eval(value)
                values = [input()]
        ''')

    def test_saved_iterator_keeps_alias_after_original_name_is_rebound(self):
        self.assert_rules('''
            values = ['safe']
            original = values
            for value in values:
                eval(value)
                values = []
                original.append(input())
        ''', 'eval')

    def test_unrelated_mutation_does_not_taint_iterator(self):
        self.assert_rules('''
            values = ['safe']
            other = []
            for value in values:
                eval(value)
                other.append(input())
        ''')

    def test_same_iteration_scalar_read_is_not_retroactively_tainted(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                values.append(input())
                eval(value)
                break
        ''')

    def test_clean_append_does_not_remove_original_taint(self):
        self.assert_rules('''
            values = [input()]
            for value in values:
                eval(value)
                values.append('safe')
        ''', 'eval')

    def test_appended_sanitized_value_retains_its_sink_domain(self):
        self.assert_rules('''
            values = ['safe']
            for value in values:
                HttpResponse(value)
                cursor.execute(value)
                values.append(html.escape(input()))
        ''', 'sql')

    def test_iteration_over_returned_alias_observes_later_mutations(self):
        self.assert_rules('''
            def identity(values):
                return values
            values = ['safe']
            for value in identity(values):
                eval(value)
                values.append(input())
        ''', 'eval')


class ComprehensionEffectsTests(SourceTest):
    def test_eager_collection_writes_reach_the_enclosing_scope(self):
        for expression in ('[box.append(input()) for item in values]',
                           '{box.append(input()) for item in values}',
                           '{item: box.append(input()) for item in values}'):
            with self.subTest(expression=expression):
                self.assert_rules(f'box = []\n{expression}\neval(box[0])\n', 'eval')

    def test_rejected_filter_keeps_its_writes_but_skips_the_element(self):
        self.assert_rules('''
            box = []
            [eval(input()) for item in values if box.append(input()) and False]
            eval(box[0])
        ''', 'eval')

    def test_false_filters_skip_later_filters_and_inner_iterables(self):
        for tail in ('if False if box.append(input())',
                     'if False for inner in box.append(input())',
                     'if False and box.append(input())'):
            with self.subTest(tail=tail):
                self.assert_rules(f'box = []\n[eval(input()) for item in values {tail}]\neval(box[0])\n')

    def test_unknown_filter_retains_both_reachable_paths(self):
        self.assert_rules('''
            box = []
            [box.append(input()) for item in values if condition]
            eval(box[0])
        ''', 'eval')

    def test_short_circuit_filter_preserves_walrus_alias(self):
        self.assert_rules('''
            box = []
            alias = []
            [0 for item in values if condition and (alias := box)]
            alias.append(input())
            eval(box[0])
        ''', 'eval')

    def test_nested_clauses_propagate_helper_output_writes(self):
        self.assert_rules('''
            def fill(target, value):
                target.append(value)
            box = []
            [fill(box, code) for row in rows if condition for code in request.args.values()]
            eval(box[0])
        ''', 'eval')

    def test_comprehension_writes_participate_in_function_summaries(self):
        self.assert_rules('''
            def fill(target, value):
                [target.append(value) for item in flags]
            def forward(target, value):
                fill(target, value)
            box = []
            forward(box, input())
            eval(box[0])
        ''', 'eval')

    def test_output_writes_keep_sanitizer_domains(self):
        self.assert_rules('''
            def fill(target, value):
                [target.append(html.escape(value)) for item in flags]
            box = []
            fill(box, input())
            HttpResponse(box[0])
            cursor.execute(box[0])
        ''', 'sql')

    def test_comprehension_result_has_mutable_object_identity(self):
        self.assert_rules('''
            box = [value for value in ['safe']]
            alias = box
            alias.append(input())
            eval(box[0])
        ''', 'eval')

    def test_walrus_alias_and_callable_escape_the_comprehension(self):
        self.assert_rules('''
            box = []
            alias = []
            [alias := box for item in values]
            alias.append(input())
            eval(box[0])
        ''', 'eval')
        self.assert_rules('''
            import os
            run = lambda value: None
            [run := os.system for item in values]
            run(input())
        ''', 'command')

    def test_guaranteed_walrus_sanitizer_keeps_its_callable_binding(self):
        self.assert_rules('''
            escape = lambda value: value
            [escape := html.escape for item in [0]]
            HttpResponse(escape(input()))
        ''')

    def test_lambda_walrus_is_not_an_enclosing_assignment(self):
        self.assert_rules('''
            escape = html.escape
            [lambda: (escape := unknown) for item in [0]]
            HttpResponse(escape(input()))
        ''')

    def test_targets_do_not_shadow_enclosing_global_callables(self):
        self.assert_rules('''
            from os import system as run
            def handle():
                [run for run in []]
                run(input())
        ''', 'command')
        self.assert_rules('''
            from html import escape
            def handle():
                [escape for escape in values]
                HttpResponse(escape(input()))
        ''')

    def test_lambda_captures_comprehension_targets_not_outer_names(self):
        self.assert_rules('''
            item = 'safe'
            [(lambda: eval(item))() for item in [input()]]
            eval(item)
        ''', 'eval')
        self.assert_rules('''
            item = input()
            [(lambda: eval(item))() for item in ['safe']]
        ''')

    def test_outer_iterable_lambda_uses_enclosing_scope(self):
        self.assert_rules('''
            item = input()
            values = [item for item in (lambda: [item])()]
            eval(values[0])
        ''', 'eval')

    def test_called_helper_reads_its_module_not_the_comprehension_target(self):
        self.assert_rules('''
            code = 'safe'
            def run():
                eval(code)
            [run() for code in [input()]]
        ''')
        self.assert_rules('''
            code = input()
            def run():
                eval(code)
            [run() for code in ['safe']]
        ''', 'eval')

    def test_literals_preserve_element_aliases_and_callable_identities(self):
        self.assert_rules('''
            box = []
            [target.append(input()) for target in [box]]
            eval(box[0])
        ''', 'eval')
        self.assert_rules('''
            import os
            [run(input()) for run in [os.system]]
        ''', 'command')

    def test_destructured_literal_elements_keep_separate_facts(self):
        self.assert_rules('''
            [eval(clean) for clean, unused in [('safe', input())]]
        ''')
        self.assert_rules('''
            [eval(code) for unused, code in [('safe', input())]]
        ''', 'eval')

    def test_empty_literals_and_false_filters_have_no_body_effects(self):
        for iterable in ('[]', '()', '{}', "''", "b''"):
            with self.subTest(iterable=iterable):
                self.assert_rules(f'[eval(input()) for item in {iterable}]\n')
        for expression in ('[eval(input()) for item in values if False]',
                           '{eval(input()) for item in values if False}',
                           '{eval(input()): 0 for item in values if False}'):
            with self.subTest(expression=expression):
                self.assert_rules(expression)

    def test_dictionary_iteration_yields_keys_not_values(self):
        self.assert_rules("[eval(key) for key in {'safe': input()}]\n")
        self.assert_rules("[eval(key) for key in {input(): 'safe'}]\n", 'eval')

    def test_singleton_has_no_invented_back_edge(self):
        self.assert_rules('''
            code = 'safe'
            [eval(code) or (code := input()) for item in [0]]
        ''')
        self.assert_rules('''
            code = 'safe'
            [eval(code) or (code := input()) for item in [0, 1]]
        ''', 'eval')

    def test_mutable_iterable_reaches_a_fixed_point(self):
        self.assert_rules('''
            values = ['safe']
            [eval(value) or values.append(input()) for value in values]
        ''', 'eval')

    def test_rebinding_does_not_retarget_an_existing_iterator(self):
        self.assert_rules('''
            values = ['safe']
            [eval(value) or (values := [input()]) for value in values]
        ''')

    def test_exception_edges_keep_heap_and_restore_target_bindings(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            from os import system as run
            box = []
            try:
                [(box.append(input()), stop()) for run in [0]]
            except ValueError:
                eval(box[0])
                run(input())
        ''', 'eval', 'command')

    def test_nonreturning_singleton_has_no_normal_continuation(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            [stop() for item in [0]]
            eval(input())
        ''')
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            [stop() for item in unknown]
            eval(input())
        ''', 'eval')

    def test_dictionary_key_precedes_value(self):
        self.assert_rules('''
            box = []
            {box.append(input()): eval(box[0]) for item in [0]}
        ''', 'eval')
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            {stop(): eval(input()) for item in [0]}
        ''')

    def test_precision_budget_falls_back_without_dropping_flows(self):
        literals = ', '.join("'safe'" for _ in range(80)) + ', input()'
        self.assert_rules(f'[eval(item) for item in [{literals}]]\n', 'eval')
        self.assert_rules('''
            box = []
            [[box.append(input()) for inner in [0, 1]] for outer in [0, 1]]
            eval(box[0])
        ''', 'eval')

    def test_cpython_execution_oracle_agrees_on_order_scope_and_filters(self):
        # These small programs never execute input as code: eval is a recorder,
        # and input returns an inert marker. CPython is the semantic oracle,
        # independent from analyzer facts or expected-output regeneration.
        cases = {
            'heap': ("box=[]\n[box.append(input()) for item in [0]]\neval(box[0])", True),
            'rejected-write': ("box=[]\n[eval(input()) for item in [0] if box.append(input()) and False]\neval(box[0])", True),
            'false-filter': ("[eval(input()) for item in [0] if False]", False),
            'empty': ("[eval(input()) for item in []]", False),
            'singleton': ("code='safe'\n[eval(code) or (code:=input()) for item in [0]]", False),
            'second-iteration': ("code='safe'\n[eval(code) or (code:=input()) for item in [0,1]]", True),
            'dictionary-order': ("box=[]\n{box.append(input()):eval(box[0]) for item in [0]}", True),
            'scope': ("item='safe'\n[(lambda:eval(item))() for item in [input()]]\neval(item)", True),
            'bounded-append': ("values=['safe']\n[eval(value) or (values.append(input()) if len(values)==1 else None) for value in values]", True),
        }
        for name, (source, unsafe) in cases.items():
            with self.subTest(case=name):
                started = time.monotonic()
                print(f'[python-comprehension-oracle-{name}] RUN', flush=True)
                observed = []
                namespace = {'input': lambda: 'TAINT_MARKER', 'eval': observed.append}
                exec(compile(textwrap.dedent(source), '<comprehension-oracle>', 'exec'), namespace)
                self.assertEqual('TAINT_MARKER' in observed, unsafe, observed)
                self.assert_rules(source, *(('eval',) if unsafe else ()))
                print(f'[python-comprehension-oracle-{name}] PASS ({time.monotonic() - started:.3f}s)', flush=True)


class LiteralArgumentUnpackingTests(SourceTest):
    def test_unpacked_output_parameters_retain_object_identity(self):
        for arguments in ('*[box, input()]', '*(box, input())', '*[box], *(input(),)',
                          '*[*[box], *[input()]]'):
            with self.subTest(arguments=arguments):
                self.assert_rules(f'''
                    def fill(target, value):
                        target.append(value)
                    box = []
                    fill({arguments})
                    eval(box[0])
                ''', 'eval')

    def test_clean_output_argument_is_not_contaminated_by_unused_input(self):
        self.assert_rules('''
            def fill(target, value, unused):
                target.append(value)
            box = []
            fill(*[box, 'safe', input()])
            eval(box[0])
        ''')

    def test_unpacked_parameters_propagate_across_helper_summaries(self):
        self.assert_rules('''
            def fill(target, value):
                target.append(value)
            def forward(target, value):
                fill(*[target], value=value)
            box = []
            forward(*(box, input()))
            eval(box[0])
        ''', 'eval')

    def test_returned_parameter_alias_is_visible_to_the_caller(self):
        self.assert_rules('''
            def identity(target):
                return target
            box = []
            alias = identity(*(box,))
            alias.append(input())
            eval(box[0])
        ''', 'eval')

    def test_direct_returned_receiver_and_captured_method_keep_identity(self):
        for invocation in ('identity(box).append(input())',
                           'identity(*[box]).append(*[input()])',
                           'append = identity(*[box]).append\nappend(input())'):
            with self.subTest(invocation=invocation):
                self.assert_rules('def identity(value): return value\nbox=[]\n' + invocation + '\neval(box[0])', 'eval')

    def test_returned_receiver_does_not_mutate_other_allocations(self):
        self.assert_rules('''
            def identity(value):
                return value
            left = []
            right = ['safe']
            identity(*[left]).append(input())
            eval(right[0])
        ''')

    def test_unknown_returned_method_cannot_gain_a_sanitizer_identity(self):
        self.assert_rules('''
            def identity(value):
                return value
            unknown = Object()
            HttpResponse(identity(*[unknown]).escape(input()))
        ''', 'xss')

    def test_returned_callable_preserves_its_sink_identity(self):
        self.assert_rules('''
            def identity(value):
                return value
            execute = identity(*[eval])
            execute(input())
        ''', 'eval')

    def test_empty_packs_do_not_hide_definition_time_defaults(self):
        for arguments in ('*[]', '*()', '*[], *()'):
            with self.subTest(arguments=arguments):
                self.assert_rules(f'''
                    def execute(value=input()):
                        eval(value)
                    execute({arguments})
                ''', 'eval')

    def test_empty_pack_preserves_mutable_default_alias(self):
        self.assert_rules('''
            box = []
            def identity(value=box):
                return value
            identity(*[]).append(input())
            eval(box[0])
        ''', 'eval')

    def test_sql_bind_parameters_are_not_query_source(self):
        for call in ("cursor.execute(*['SELECT ?', (input(),)])",
                     "query(*['SELECT ?', (input(),)])"):
            with self.subTest(call=call):
                self.assert_rules(f'''
                    def query(sql, parameters):
                        cursor.execute(sql, parameters)
                    {call}
                ''')
        self.assert_rules("cursor.execute(*[input(), ('safe',)])", 'sql')

    def test_eval_namespace_argument_is_not_executable_source(self):
        self.assert_rules("eval(*['1', {'data': input()}])")
        self.assert_rules("eval(*(input(), {}))", 'eval')

    def test_process_argv_separates_data_and_interpreter_code(self):
        for argv, unsafe in (("['echo', input()]", False),
                             ("['sh', '-c', input()]", True),
                             ("['python', '-c', input()]", True),
                             ("[input(), 'safe']", True)):
            with self.subTest(argv=argv):
                self.assert_rules(f'subprocess.run(*[{argv}])', *(('command',) if unsafe else ()))

    def test_sanitizer_domains_survive_unpacked_calls(self):
        self.assert_rules("HttpResponse(*[html.escape(*[input()])])")
        self.assert_rules("cursor.execute(*[html.escape(*[input()])])", 'sql')
        self.assert_rules("os.system(*[shlex.quote(*[input()])])")
        self.assert_rules("eval(*[shlex.quote(*[input()])])", 'eval')

    def test_earlier_argument_keeps_alias_when_later_argument_rebinds_name(self):
        self.assert_rules('''
            def fill(target, value, unused):
                target.append(value)
            box = []
            original = box
            fill(*[box, input(), (box := [])])
            eval(original[0])
            eval(box[0])
        ''', 'eval')

    def test_later_argument_writes_reach_earlier_object_snapshot(self):
        self.assert_rules('''
            def execute(target, unused):
                eval(target[0])
            box = []
            execute(*[box, box.append(input())])
        ''', 'eval')

    def test_scalar_snapshot_is_not_retroactively_tainted(self):
        self.assert_rules('''
            def execute(code, unused):
                eval(code)
            code = 'safe'
            execute(*[code, (code := input())])
        ''')

    def test_callee_is_captured_before_argument_evaluation(self):
        self.assert_rules('''
            def execute(code, unused):
                eval(code)
            def harmless(code, unused):
                return 'safe'
            callback = execute
            callback(*[input(), (callback := harmless)])
        ''', 'eval')

    def test_nonreturning_argument_prevents_later_effects_and_invocation(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            def execute(code, unused):
                eval(code)
            execute(*[stop(), input()])
            eval(input())
        ''')

    def test_keyword_effects_follow_all_positional_expansions(self):
        self.assert_rules('''
            def execute(code, unused):
                eval(code)
            code = 'safe'
            execute(unused=(code := input()), *[code])
        ''')

    def test_opaque_unpacking_stays_conservative(self):
        self.assert_rules('''
            def execute(first, second):
                eval(second)
            execute(*[input(), *unknown])
        ''')
        self.assert_rules('''
            def execute(first, second):
                eval(second)
            execute(*unknown, *[input()])
        ''', 'eval')
        self.assert_rules('''
            def execute(first, second):
                eval(second)
            execute(*request.args.values())
        ''', 'eval')

    def test_coroutine_resume_retains_normalized_arguments_and_return_alias(self):
        self.assert_rules('''
            import asyncio
            async def identity(value):
                return value
            box = []
            alias = asyncio.run(*[identity(*[box])])
            alias.append(input())
            eval(box[0])
        ''', 'eval')
        self.assert_rules('''
            async def identity(value):
                return value
            async def route():
                box = []
                alias = await identity(*[box])
                alias.append(input())
                eval(box[0])
        ''', 'eval')

    def test_generator_yielded_alias_survives_normalized_call(self):
        self.assert_rules('''
            def values(box):
                yield box
            box = []
            for alias in values(*[box]):
                alias.append(input())
            eval(box[0])
        ''', 'eval')

    def test_framework_dependency_accepts_literal_positional_unpacking(self):
        for annotation in ('Depends(*[provider])', 'Depends(*(provider,))'):
            with self.subTest(annotation=annotation):
                self.assert_rules(f'''
                    from fastapi import Query, Depends
                    def provider(value=Query()):
                        return value
                    def route(value={annotation}):
                        eval(value)
                ''', 'eval')
                self.assert_rules(f'''
                    from fastapi import Depends
                    def provider():
                        return 'safe'
                    def route(value={annotation}):
                        eval(value)
                ''')

    def test_loop_call_sites_keep_finite_allocation_identities(self):
        self.assert_rules('''
            def identity(value):
                return value
            box = []
            while condition:
                alias = identity(*[box])
                alias.append(input())
            eval(box[0])
        ''', 'eval')

    def test_normalized_call_view_does_not_mutate_source_ast(self):
        from ubs_core.analyzers.taint_py import _Analysis
        source = ast.parse('fill(*[box, *(input(),)], *[])')
        before = ast.dump(source, include_attributes=True)
        analysis = _Analysis(source)
        call = source.body[0].value
        normalized = analysis.call_sites[call]
        self.assertIsNot(call, normalized)
        self.assertEqual(len(normalized.args), 2)
        self.assertEqual(ast.dump(source, include_attributes=True), before)
        self.assertEqual((normalized.lineno, normalized.col_offset), (call.lineno, call.col_offset))
        self.assertIs(analysis.call_sites[call], normalized)

    def test_cpython_unpacking_oracle_agrees_on_identity_order_and_defaults(self):
        cases = {
            'output-alias': ("def fill(out, value): out.append(value)\nbox=[]\nfill(*[box, input()])\neval(box[0])", True),
            'returned-alias': ("def identity(out): return out\nbox=[]\nidentity(*(box,)).append(input())\neval(box[0])", True),
            'default': ("def execute(code=input()): eval(code)\nexecute(*[])", True),
            'unused': ("def execute(code, unused): eval(code)\nexecute(*['safe', input()])", False),
            'scalar-snapshot': ("def execute(code, unused): eval(code)\ncode='safe'\nexecute(*[code, (code:=input())])", False),
            'keyword-order': ("def execute(code, unused): eval(code)\ncode='safe'\nexecute(unused=(code:=input()), *[code])", False),
            'nested': ("def execute(unused, code): eval(code)\nexecute(*[*['safe'], *(input(),)])", True),
        }
        for name, (source, unsafe) in cases.items():
            with self.subTest(case=name):
                print(f'[python-unpacking-oracle-{name}] RUN', flush=True)
                observed = []
                namespace = {'input': lambda: 'TAINT_MARKER', 'eval': observed.append}
                exec(compile(source, '<unpacking-oracle>', 'exec'), namespace)
                self.assertEqual('TAINT_MARKER' in observed, unsafe, observed)
                self.assert_rules(source, *(('eval',) if unsafe else ()))
                print(f'[python-unpacking-oracle-{name}] PASS', flush=True)


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
            'loop-append': ("values = ['safe']\nfor value in values:\n    eval(value)\n    values.append(input())\n", True),
            'loop-break': ("values = ['safe']\nfor value in values:\n    eval(value)\n    values.append(input())\n    break\n", False),
            'loop-rebind': ("values = ['safe']\nfor value in values:\n    eval(value)\n    values = [input()]\n", False),
            'comprehension-write': ("box = []\n[box.append(input()) for item in [0]]\neval(box[0])\n", True),
            'comprehension-filter-write': ("box = []\n[0 for item in [0] if box.append(input()) and False]\neval(box[0])\n", True),
            'comprehension-false': ("[eval(input()) for item in [0] if False]\n", False),
            'comprehension-empty': ("[eval(input()) for item in []]\n", False),
            'comprehension-alias': ("box=[]\nalias=[]\n[alias := box for item in [0]]\nalias.append(input())\neval(box[0])\n", True),
            'comprehension-singleton': ("code='safe'\n[eval(code) or (code := input()) for item in [0]]\n", False),
            'unpacking-output': ("def fill(box, value): box.append(value)\nbox=[]\nfill(*[box, input()])\neval(box[0])\n", True),
            'unpacking-returned-alias': ("def identity(box): return box\nbox=[]\nidentity(*(box,)).append(input())\neval(box[0])\n", True),
            'unpacking-default': ("def execute(value=input()): eval(value)\nexecute(*[])\n", True),
            'unpacking-unused': ("def execute(value, unused): eval(value)\nexecute(*['safe', input()])\n", False),
            'unpacking-namespace': ("eval(*['1', {'data': input()}])\n", False),
            'unpacking-provider': ("from fastapi import Query, Depends\ndef provider(value=Query()): return value\ndef route(value=Depends(*[provider])): eval(value)\n", True),
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
