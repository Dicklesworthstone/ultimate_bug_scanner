"""Command-injection flow regressions; sources are parsed, never executed."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'modules/helpers/ubs_core/py_detectors/command_injection.py'
spec = importlib.util.spec_from_file_location('command_flow_subject', SOURCE)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class CommandControlFlowTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = any(test is self for test, _ in result.failures + result.errors)
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - self.started:.3f}s)', flush=True)

    def check(self, code):
        code = textwrap.dedent(code).lstrip('\n')
        expected = [i for i, line in enumerate(code.splitlines(), 1) if '# HIT' in line]
        analyzer = subject.CommandInjectionAnalyzer(code, code.splitlines())
        analyzer.visit(ast.parse(code))
        self.assertEqual(sorted(analyzer.issues), expected, code)
        self.assertEqual(len(analyzer.issues), len(set(analyzer.issues)), code)
        return analyzer

    def test_conditional_clean_assignment_does_not_kill_other_path(self):
        self.check('''
            import os
            command = input()
            if use_fixed:
                command = 'echo fixed'
            os.system(command)  # HIT
        ''')

    def test_both_branch_orders_keep_taint(self):
        for first, second in [("input()", "'echo'"), ("'echo'", "input()")]:
            with self.subTest(first=first):
                self.check(f'''
                    import os
                    if condition:
                        command = {first}
                    else:
                        command = {second}
                    os.system(command)  # HIT
                ''')

    def test_both_branches_overwrite_with_constants(self):
        self.check('''
            import os
            command = input()
            if condition:
                command = 'echo first'
            else:
                command = 'echo second'
            os.system(command)
        ''')

    def test_unconditional_kill_after_branch(self):
        self.check('''
            import os
            if condition:
                command = input()
            command = 'echo fixed'
            os.system(command)
        ''')

    def test_reassignment_is_not_retroactive(self):
        self.check('''
            import os
            command = 'echo fixed'
            os.system(command)
            command = input()
            os.system(command)  # HIT
            command = 'echo fixed'
            os.system(command)
        ''')

    def test_loop_carried_taint_reaches_earlier_sink(self):
        self.check('''
            import os
            command = 'echo fixed'
            while keep_running:
                os.system(command)  # HIT
                command = input()
        ''')

    def test_zero_iteration_retains_entry_taint(self):
        for header in ['while condition:', 'for item in values:']:
            with self.subTest(header=header):
                self.check(f'''
                    import os
                    command = input()
                    {header}
                        command = 'echo fixed'
                    os.system(command)  # HIT
                ''')

    def test_loop_strong_kill_before_sink_stays_clean(self):
        self.check('''
            import os
            command = input()
            while condition:
                command = 'echo fixed'
                os.system(command)
                command = input()
        ''')

    def test_continue_carries_taint_and_skips_dead_kill(self):
        self.check('''
            import os
            command = 'echo fixed'
            while condition:
                os.system(command)  # HIT
                command = input()
                continue
                command = 'echo never'
        ''')

    def test_break_bypasses_loop_else_sanitizer(self):
        self.check('''
            import os
            command = input()
            while condition:
                break
            else:
                command = 'echo fixed'
            os.system(command)  # HIT
        ''')

    def test_unbroken_loop_else_kill(self):
        self.check('''
            import os
            command = input()
            for item in values:
                command = input()
            else:
                command = 'echo fixed'
            os.system(command)
        ''')

    def test_break_only_while_true_has_no_phantom_zero_iteration(self):
        self.check('''
            import os
            command = input()
            while True:
                command = 'echo fixed'
                break
            os.system(command)
        ''')

    def test_nested_break_belongs_to_inner_loop(self):
        self.check('''
            import os
            command = 'echo fixed'
            while condition:
                for item in values:
                    command = input()
                    break
                os.system(command)  # HIT
        ''')

    def test_for_target_receives_request_provenance(self):
        self.check('''
            import os
            import sys
            for command in sys.argv:
                os.system(command)  # HIT
        ''')

    def test_dead_constant_branches_and_post_return_do_not_report(self):
        self.check('''
            import os
            if False:
                os.system(input())
            while False:
                os.system(input())
            def handler():
                return
                os.system(input())
        ''')

    def test_returning_branch_does_not_pollute_reachable_continuation(self):
        self.check('''
            import os
            def handler():
                command = input()
                if condition:
                    return
                else:
                    command = 'echo fixed'
                os.system(command)
        ''')

    def test_sibling_function_locals_do_not_leak(self):
        self.check('''
            import os
            def producer():
                command = input()
                os.system(command)  # HIT
            def unrelated(command):
                os.system(command)
        ''')

    def test_function_body_cannot_sanitize_an_outer_binding(self):
        self.check('''
            import os
            command = input()
            def unrelated():
                command = 'echo fixed'
            os.system(command)  # HIT
        ''')

    def test_global_read_is_preserved_but_local_parameter_shadows(self):
        self.check('''
            import os
            command = input()
            def reads_global():
                os.system(command)  # HIT
            def shadows_global(command):
                os.system(command)
        ''')

    def test_local_is_bound_for_entire_function(self):
        self.check('''
            import os
            command = input()
            def handler():
                os.system(command)
                command = 'echo fixed'
        ''')

    def test_nested_closure_reads_enclosing_taint(self):
        self.check('''
            import os
            def outer():
                command = input()
                def inner():
                    os.system(command)  # HIT
        ''')

    def test_async_function_has_isolated_scope(self):
        self.check('''
            import os
            async def first():
                command = input()
                os.system(command)  # HIT
            async def second(command):
                os.system(command)
        ''')

    def test_sink_imports_do_not_leak_between_functions(self):
        self.check('''
            def first():
                from os import system as dispatch
                dispatch(input())  # HIT
            def second(dispatch):
                dispatch(input())
        ''')

    def test_parameter_shadows_sink_module_and_direct_import(self):
        self.check('''
            import subprocess
            from os import system as dispatch
            def handler(subprocess, dispatch):
                subprocess.run(input())
                dispatch(input())
        ''')

    def test_conditional_sink_import_is_a_may_binding(self):
        self.check('''
            if condition:
                from os import system as dispatch
            else:
                from subprocess import run as dispatch
            dispatch(input())  # HIT
        ''')

    def test_rebound_sink_alias_is_not_called_as_original(self):
        self.check('''
            from os import system as dispatch
            dispatch = custom
            dispatch(input())
        ''')

    def test_class_local_does_not_hide_method_global_or_escape_class(self):
        self.check('''
            import os
            command = input()
            class Handler:
                command = 'echo fixed'
                def run(self):
                    os.system(command)  # HIT
            os.system(command)  # HIT
        ''')

    def test_class_body_sink_still_checked(self):
        self.check('''
            import os
            class Handler:
                command = input()
                os.system(command)  # HIT
        ''')

    def test_lambda_parameter_shadows_outer_binding(self):
        self.check('''
            import os
            command = input()
            handler = lambda command: os.system(command)
            os.system(command)  # HIT
        ''')

    def test_definition_defaults_are_checked_in_outer_scope(self):
        self.check('''
            import os
            def handler(command=os.system(input())):  # HIT
                return command
        ''')

    def test_exception_handler_retains_taint_before_possible_failure(self):
        self.check('''
            import os
            command = input()
            try:
                might_fail()
                command = 'echo fixed'
            except Exception:
                os.system(command)  # HIT
        ''')

    def test_exception_handler_sees_intermediate_taint(self):
        self.check('''
            import os
            command = 'echo fixed'
            try:
                command = input()
                might_fail()
                command = 'echo fixed'
            except Exception:
                os.system(command)  # HIT
        ''')

    def test_try_else_kill_does_not_clean_exception_path(self):
        self.check('''
            import os
            command = input()
            try:
                might_fail()
            except Exception:
                pass
            else:
                command = 'echo fixed'
            os.system(command)  # HIT
        ''')

    def test_finally_kill_applies_to_every_continuing_path(self):
        self.check('''
            import os
            command = input()
            try:
                might_fail()
            except Exception:
                command = input()
            finally:
                command = 'echo fixed'
            os.system(command)
        ''')

    def test_finally_runs_on_return_path(self):
        self.check('''
            import os
            def handler():
                command = input()
                try:
                    return
                finally:
                    os.system(command)  # HIT
        ''')

    def test_finally_overrides_break_with_continue(self):
        self.check('''
            import os
            command = 'echo fixed'
            while condition:
                os.system(command)  # HIT
                try:
                    command = input()
                    break
                finally:
                    continue
        ''')

    def test_finally_sanitizer_is_not_used_before_it_executes(self):
        self.check('''
            import os
            command = input()
            try:
                os.system(command)  # HIT
            finally:
                command = 'echo fixed'
        ''')

    def test_named_expression_and_short_circuit_keep_alternate_state(self):
        self.check('''
            import os
            command = input()
            enabled and (command := 'echo fixed')
            os.system(command)  # HIT
            (command := input())
            os.system(command)  # HIT
        ''')

    def test_named_expression_clean_value_does_not_read_old_target(self):
        self.check('''
            import os
            command = input()
            os.system(command := 'echo fixed')
        ''')

    def test_conditional_expression_has_distinct_transfer_paths(self):
        self.check('''
            import os
            command = input()
            (command := 'echo fixed') if condition else None
            os.system(command)  # HIT
        ''')

    def test_formatted_conditional_value_remains_dynamic(self):
        self.check('''
            import os
            command = f'echo {value}' if condition else 'echo fixed'
            os.system(command)  # HIT
        ''')

    def test_augmented_assignment_preserves_request_flow(self):
        self.check('''
            import os
            command = 'echo '
            command += input()
            os.system(command)  # HIT
        ''')

    def test_mixed_scalar_and_argv_does_not_gain_argv_exemption(self):
        self.check('''
            import subprocess
            if condition:
                command = ['echo', input()]
            else:
                command = input()
            subprocess.run(command)  # HIT
        ''')

    def test_both_branches_fixed_argv_allow_untrusted_data_arguments(self):
        self.check('''
            import subprocess
            if condition:
                command = ['echo', input()]
            else:
                command = ['printf', '%s', input()]
            subprocess.run(command)
        ''')

    def test_shell_sanitizer_domain_does_not_authorize_executable(self):
        self.check('''
            import subprocess
            import shlex
            if condition:
                command = shlex.quote(input())
            else:
                command = 'echo'
            subprocess.run(command, shell=True)
            subprocess.run(command)  # HIT
        ''')

    @unittest.skipUnless(hasattr(ast, 'Match'), 'pattern matching requires Python 3.10+')
    def test_match_nonexhaustive_path_preserves_entry(self):
        self.check('''
            import os
            command = input()
            match choice:
                case 'fixed':
                    command = 'echo fixed'
            os.system(command)  # HIT
        ''')

    @unittest.skipUnless(hasattr(ast, 'Match'), 'pattern matching requires Python 3.10+')
    def test_match_exhaustive_clean_arms(self):
        self.check('''
            import os
            command = input()
            match choice:
                case 'fixed':
                    command = 'echo first'
                case _:
                    command = 'echo second'
            os.system(command)
        ''')

    @unittest.skipUnless(hasattr(ast, 'Match'), 'pattern matching requires Python 3.10+')
    def test_match_capture_receives_subject_taint(self):
        self.check('''
            import os
            match input():
                case command:
                    os.system(command)  # HIT
        ''')

    def test_ignore_marker_and_one_finding_per_line_survive_fixed_point(self):
        self.check('''
            import os
            command = 'echo fixed'
            while condition:
                os.system(command); os.system(command)  # HIT
                os.system(command)  # ubs:ignore
                command = input()
        ''')

    def test_fixed_point_requires_more_than_one_backedge(self):
        self.check('''
            import os
            first = second = third = fourth = 'echo fixed'
            while condition:
                os.system(first)  # HIT
                first = second
                second = third
                third = fourth
                fourth = input()
        ''')

    def test_nested_scopes_do_not_contaminate_exception_handler(self):
        self.check('''
            import os
            command = 'echo fixed'
            try:
                def unrelated():
                    command = input()
            except Exception:
                os.system(command)
        ''')

    def test_python39_without_pattern_matching_ast(self):
        from unittest import mock
        with mock.patch.dict(ast.__dict__):
            ast.__dict__.pop('Match', None)
            self.check('''
                import os
                command = input()
                if flag:
                    command = 'echo'
                os.system(command)  # HIT
            ''')

    def test_budget_exhaustion_is_an_error_not_a_clean_result(self):
        code = 'import os\nwhile condition:\n os.system(input())\n'
        analyzer = subject.CommandInjectionAnalyzer(code, code.splitlines(), max_steps=1)
        with self.assertRaises(subject.CommandAnalysisLimit):
            analyzer.visit(ast.parse(code))

    def test_comprehension_zero_iterations_cannot_clean_outer_variable(self):
        for expression in ("[(command := 'echo') for item in values]",
                           "{(command := 'echo') for item in values}",
                           "{item: (command := 'echo') for item in values}",
                           "((command := 'echo') for item in values)"):
            with self.subTest(expression=expression):
                self.check(f'''
                    import os
                    command = input()
                    result = {expression}
                    os.system(command)  # HIT
                ''')

    def test_comprehension_targets_are_scoped_and_values_follow_binding(self):
        self.check('''
            import os
            command = 'echo'
            [os.system(command) for command in request.args.values()]  # HIT
            os.system(command)
        ''')

    def test_comprehension_first_iterable_sees_outer_variable(self):
        self.check('''
            import os
            command = input()
            [os.system(command) for command in [command]]  # HIT
        ''')

    def test_comprehension_walrus_can_taint_outer_variable(self):
        self.check('''
            import os
            command = 'echo'
            result = [(command := input()) for item in values]
            os.system(command)  # HIT
        ''')

    def test_comprehension_filters_and_backedges_keep_reachable_taint(self):
        self.check('''
            import os
            command = 'echo'
            [(os.system(command), (command := input())) for item in values if allowed]  # HIT
        ''')

    def test_comprehension_local_facts_do_not_leak_into_handlers(self):
        self.check('''
            import os
            command = 'echo'
            try:
                [os.system(command) for command in request.args.values()]  # HIT
            except Exception:
                os.system(command)
        ''')

    def test_nested_comprehensions_keep_outer_iteration_binding(self):
        self.check('''
            import os
            command = 'echo'
            [[os.system(command) for item in values] for command in request.args.values()]  # HIT
            os.system(command)
        ''')

    def test_find_public_interface_has_exact_coordinates(self):
        with tempfile.TemporaryDirectory(prefix='ubs-command-flow-') as tmp:
            path = Path(tmp) / 'handler.py'
            path.write_text('import os\ncmd = input()\nif flag:\n cmd = "echo"\nos.system(cmd)\n')
            self.assertEqual(list(subject.find([path])), [(path, 5, 1, 'os.system(cmd)')])

    def test_nested_fixed_points_are_deterministic(self):
        code = '''
            import os
            command = 'echo fixed'
            while outer:
                while inner:
                    os.system(command)  # HIT
                    command = input()
        '''
        first = self.check(code)
        second = self.check(code)
        self.assertEqual(first.issues, second.issues)
        self.assertEqual(first.remaining_steps, second.remaining_steps)


if __name__ == '__main__':
    unittest.main(verbosity=2)
