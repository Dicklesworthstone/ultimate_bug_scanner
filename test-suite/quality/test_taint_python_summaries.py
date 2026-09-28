"""Module-local call/return and recursive summary regressions."""
import ast
import unittest
from test_taint_python_dataflow import SourceTest
from ubs_core.analyzers import taint_py


class FunctionSummaryTests(SourceTest):
    def test_argument_reaches_a_sink_inside_a_helper(self):
        findings = self.assert_rules('def execute(query):\n    cursor.execute(query)\nexecute(input())\n', 'sql')
        self.assertEqual(findings[0]['line'], 2)
        self.assertIn('query', findings[0]['message'])

    def test_returned_source_reaches_caller_sink(self):
        self.assert_rules('def obtain():\n    return input()\neval(obtain())\n', 'eval')

    def test_return_dependencies_preserve_both_parameters(self):
        for call in ("choose(input(), 'safe')", "choose('safe', input())"):
            with self.subTest(call=call):
                self.assert_rules(f'def choose(a, b):\n    return a if condition else b\neval({call})\n', 'eval')

    def test_constant_return_does_not_inherit_taint_from_unused_argument(self):
        self.assert_rules("def clean(value):\n    return 'safe'\neval(clean(input()))\n")

    def test_wrapped_sanitizers_remain_sink_specific(self):
        self.assert_rules('def escape(value):\n    return html.escape(value)\nHttpResponse(escape(input()))\n')
        self.assert_rules('def escape(value):\n    return html.escape(value)\ncursor.execute(escape(input()))\n', 'sql')
        self.assert_rules('def render(value):\n    HttpResponse(value)\nrender(html.escape(input()))\n')

    def test_keyword_only_default_and_variadic_parameters(self):
        self.assert_rules('def execute(*, code):\n    eval(code)\nexecute(code=input())\n', 'eval')
        self.assert_rules('def execute(code=input()):\n    eval(code)\nexecute()\n', 'eval')
        self.assert_rules("def execute(code=input()):\n    eval(code)\nexecute('safe')\n")
        self.assert_rules('def execute(*args):\n    eval(args[0])\nexecute(input())\n', 'eval')
        self.assert_rules('def execute(**kwargs):\n    eval(kwargs["code"])\nexecute(code=input())\n', 'eval')
        self.assert_rules('def execute(code):\n    eval(code)\nexecute(**{"code": input()})\n', 'eval')

    def test_function_alias_and_shadowing(self):
        self.assert_rules('def execute(code):\n    eval(code)\nalias = execute\nalias(input())\n', 'eval')
        self.assert_rules('def execute(code):\n    eval(code)\nexecute = other\nexecute(input())\n')

    def test_deep_call_chain_is_not_limited_to_five_passes(self):
        source = '\n'.join(f'def f{i}(value):\n    return f{i+1}(value)' for i in range(20))
        source += '\ndef f20(value):\n    return value\neval(f0(input()))\n'
        self.assert_rules(source, 'eval')

    def test_mutual_recursion_reaches_a_fixed_point(self):
        self.assert_rules('''
            def first(value):
                return second(value)
            def second(value):
                if condition:
                    return first(value)
                return value
            eval(first(input()))
        ''', 'eval')

    def test_recursive_sanitizer_and_nonreturning_recursion(self):
        self.assert_rules('''
            def clean(value):
                if condition:
                    return clean(value)
                return html.escape(value)
            HttpResponse(clean(input()))
        ''')
        self.assert_rules('def spin(value):\n    return spin(value)\neval(spin(input()))\n')

    def test_sink_effects_propagate_through_mutual_recursion(self):
        self.assert_rules('''
            def first(value):
                second(value)
            def second(value):
                if condition:
                    first(value)
                else:
                    eval(value)
            first(input())
        ''', 'eval')

    def test_unrelated_safe_call_does_not_clear_unsafe_context(self):
        for calls in ("execute('safe')\nexecute(input())", "execute(input())\nexecute('safe')"):
            with self.subTest(calls=calls):
                self.assert_rules(f'def execute(code):\n    eval(code)\n{calls}\n', 'eval')

    def test_globals_are_not_replaced_by_caller_locals(self):
        self.assert_rules('''
            q = input()
            def obtain():
                return q
            def caller():
                q = 'safe'
                eval(obtain())
            caller()
        ''', 'eval')
        self.assert_rules('''
            q = 'safe'
            def obtain():
                return q
            def caller():
                q = input()
                eval(obtain())
            caller()
        ''')

    def test_local_binding_does_not_inherit_global_taint(self):
        self.assert_rules("q = input()\ndef run():\n    eval(q)\n    q = 'safe'\n")

    def test_async_function_summaries(self):
        self.assert_rules('async def obtain(value):\n    return value\nasync def route():\n    eval(await obtain(input()))\n', 'eval')

    def test_shared_callee_keeps_parameter_origins_separate(self):
        self.assert_rules('''
            def merge(a, b):
                return a + b
            def wrap(left, right):
                return merge(html.escape(left), right)
            HttpResponse(wrap('safe', input()))
        ''', 'xss')
        self.assert_rules('''
            def merge(a, b):
                return a + b
            def wrap(left, right):
                return merge(html.escape(left), right)
            HttpResponse(wrap(input(), 'safe'))
        ''')

    def test_match_alternatives_and_capture_patterns(self):
        self.assert_rules('''
            def execute(payload):
                match payload:
                    case {'code': command}:
                        eval(command)
                    case _:
                        pass
            execute(input())
        ''', 'eval')
        self.assert_rules('''
            q = input()
            match tag:
                case 'escape':
                    value = html.escape(q)
                case _:
                    value = q
            HttpResponse(value)
        ''', 'xss')
        self.assert_rules('''
            q = input()
            match tag:
                case 'one':
                    q = 'safe'
                case _:
                    q = 'also safe'
            eval(q)
        ''')

    def test_definition_time_calls_are_analyzed(self):
        self.assert_rules('def run(value=eval(input())):\n    pass\n', 'eval')
        self.assert_rules('class Example(eval(input())):\n    pass\n', 'eval')


class PatternCaptureTests(SourceTest):
    def test_mapping_rest_reaches_sink_through_helper_return(self):
        self.assert_rules('''
            def remaining(payload):
                match payload:
                    case {'kind': _, **rest}:
                        return rest
                return {}
            eval(remaining(request.get_json())['code'])
        ''', 'eval')

    def test_nested_mapping_rest_reaches_helper_sink(self):
        self.assert_rules('''
            def execute(payload):
                match payload:
                    case {'body': {'kind': _, **rest}}:
                        cursor.execute(rest['query'])
            execute(request.get_json())
        ''', 'sql')

    def test_capture_revokes_stale_sanitizer_and_function_bindings(self):
        self.assert_rules('''
            import html as clean
            match other:
                case clean:
                    HttpResponse(clean.escape(input()))
        ''', 'xss')
        self.assert_rules('''
            def clean(value):
                return 'safe'
            match other:
                case clean:
                    eval(clean(input()))
        ''', 'eval')

    def test_mapping_rest_revokes_previous_import_identity(self):
        self.assert_rules('''
            import html as rest
            match payload:
                case {**rest}:
                    HttpResponse(rest.escape(input()))
        ''', 'xss')

    def test_whole_subject_capture_preserves_callable_identity(self):
        self.assert_rules('''
            match eval:
                case execute:
                    execute(input())
        ''', 'eval')
        self.assert_rules('''
            def execute(value):
                cursor.execute(value)
            match execute:
                case alias:
                    alias(input())
        ''', 'sql')

    def test_captured_callable_is_returned_to_caller(self):
        self.assert_rules('''
            def executor():
                match eval:
                    case alias:
                        return alias
            executor()(input())
        ''', 'eval')

    def test_whole_subject_capture_preserves_sanitizer_identity(self):
        self.assert_rules('''
            import html
            match html.escape:
                case clean:
                    HttpResponse(clean(input()))
        ''')

    def test_captured_string_does_not_become_callable_identity(self):
        self.assert_rules('''
            match 'eval':
                case execute:
                    execute(input())
        ''')

    def test_capture_preserves_output_object_alias(self):
        self.assert_rules('''
            def fill(data, code):
                match data:
                    case alias:
                        alias['code'] = code
            data = {}
            fill(data, input())
            eval(data['code'])
        ''', 'eval')

    def test_as_pattern_preserves_original_container_alias(self):
        self.assert_rules('''
            data = {}
            match data:
                case {} as alias:
                    alias['code'] = input()
            eval(data['code'])
        ''', 'eval')

    def test_mapping_rest_and_star_allocate_distinct_containers(self):
        for subject, pattern, write in (("{'kind': 0}", "{'kind': _, **rest}", "rest['code'] = input()"),
                                        ('[]', '[*rest]', 'rest.append(input())')):
            with self.subTest(pattern=pattern):
                self.assert_rules(f'data = {subject}\nmatch data:\n    case {pattern}:\n        {write}\neval(data)\n')
                self.assert_rules(f'data = {subject}\nmatch data:\n    case {pattern}:\n        {write}\neval(rest)\n', 'eval')

    def test_strong_capture_replaces_old_heap_alias(self):
        self.assert_rules('''
            old = {}
            alias = old
            match {}:
                case alias:
                    alias['code'] = input()
            eval(old)
        ''')

    def test_or_pattern_joins_alias_and_fresh_container_possibilities(self):
        self.assert_rules('''
            data = {}
            match data:
                case [*alias] | alias:
                    alias['code'] = input()
            eval(data)
        ''', 'eval')

    def test_all_pattern_target_forms_are_lexically_local(self):
        function = ast.parse('''
def run(value):
    match value:
        case {'key': captured, **rest}:
            pass
        case [first, *tail] as whole:
            pass
        case Record(field=member):
            pass
''').body[0]
        self.assertEqual(taint_py._local_names(function),
                         {'value', 'captured', 'rest', 'first', 'tail', 'whole', 'member'})

    def test_pattern_captures_respect_global_nonlocal_and_child_scopes(self):
        function = ast.parse('''
def run(value):
    global external
    nonlocal outer
    match value:
        case {'key': external, **outer}:
            pass
    def child():
        match other:
            case nested:
                pass
''').body[0]
        self.assertEqual(taint_py._local_names(function), {'value', 'child'})


class PatternControlFlowTests(SourceTest):
    def test_false_guard_writes_flow_to_next_case_and_after_match(self):
        for suffix in ('    case _:\n        eval(code)\n', 'eval(code)\n'):
            with self.subTest(suffix=suffix):
                self.assert_rules("code = 'safe'\nmatch payload:\n"
                                  "    case _ if (code := input()) and False:\n"
                                  "        pass\n" + suffix, 'eval')

    def test_successful_pattern_captures_survive_a_false_guard(self):
        self.assert_rules('''
            match input():
                case code if False:
                    pass
                case _:
                    eval(code)
        ''', 'eval')

    def test_false_guard_does_not_execute_its_body(self):
        for guard in ('False', '0', 'None', "''", '(flag := False)', 'not True'):
            with self.subTest(guard=guard):
                self.assert_rules(f'match payload:\n    case _ if {guard}:\n        eval(input())\n')

    def test_literal_guard_short_circuits_sink_operands(self):
        for guard in ('False and eval(input())', 'True or eval(input())',
                      'not (False and eval(input()))', 'True if True else eval(input())'):
            with self.subTest(guard=guard):
                self.assert_rules(f'match payload:\n    case _ if {guard}:\n        pass\n')

    def test_unknown_short_circuit_preserves_both_dataflow_paths(self):
        self.assert_rules('''
            code = input()
            match payload:
                case _ if flag and (code := 'safe'):
                    pass
            eval(code)
        ''', 'eval')
        self.assert_rules('''
            code = input()
            match payload:
                case _ if flag or (code := 'safe'):
                    eval(code)
        ''', 'eval')

    def test_and_guard_executed_assignment_is_visible_only_on_selected_edge(self):
        self.assert_rules('''
            code = input()
            match payload:
                case _ if flag and (code := 'safe'):
                    eval(code)
        ''')

    def test_guard_failure_revokes_old_sanitizer_identity_for_later_cases(self):
        self.assert_rules('''
            import html as clean
            match payload:
                case _ if (clean := other) and False:
                    pass
                case _:
                    HttpResponse(clean.escape(input()))
        ''', 'xss')

    def test_true_guard_prevents_later_case_guard_and_body_effects(self):
        self.assert_rules('''
            match payload:
                case _ if True:
                    pass
                case _ if eval(input()):
                    pass
                case _:
                    eval(input())
        ''')

    def test_guards_are_ordered_and_subject_is_not_reevaluated(self):
        self.assert_rules('''
            def scan():
                code = input()
                match (code := 'safe'):
                    case _ if (code := input()) and False:
                        pass
                    case _:
                        return code
            eval(scan())
        ''', 'eval')

    def test_guard_mutation_is_visible_to_later_capture(self):
        self.assert_rules('''
            def fill(data):
                data['code'] = input()
                return False
            data = {}
            match data:
                case _ if fill(data):
                    pass
                case {'code': code}:
                    eval(code)
        ''', 'eval')

    def test_subject_identity_survives_guard_rebinding(self):
        self.assert_rules('''
            data = {}
            saved = data
            match data:
                case _ if (data := {}) and False:
                    pass
                case alias:
                    alias['code'] = input()
            eval(saved['code'])
        ''', 'eval')

    def test_pattern_mismatch_does_not_evaluate_guard(self):
        self.assert_rules('''
            match 'safe':
                case 'other' if eval(input()):
                    pass
                case _:
                    pass
        ''')

    def test_literal_first_match_prevents_later_tainted_return(self):
        self.assert_rules('''
            def code():
                match 'safe':
                    case 'safe':
                        return 'safe'
                    case _:
                        return input()
            eval(code())
        ''')

    def test_singleton_identity_is_distinct_from_literal_equality(self):
        self.assert_rules('''
            match 1:
                case True:
                    eval(input())
        ''')
        self.assert_rules('''
            match True:
                case 1:
                    eval(input())
        ''', 'eval')

    def test_strings_are_not_sequence_or_mapping_subjects(self):
        for pattern in ('[code]', '{**rest}'):
            with self.subTest(pattern=pattern):
                self.assert_rules(f"match 'x':\n    case {pattern}:\n        eval(input())\n")

    def test_unknown_pattern_keeps_unmatched_route_without_guard_effects(self):
        self.assert_rules('''
            code = input()
            match payload:
                case {'ok': _} if (code := 'safe'):
                    pass
                case _:
                    eval(code)
        ''', 'eval')

    def test_guard_exception_routes_to_handler_not_later_cases(self):
        self.assert_rules('''
            def fail():
                raise ValueError(input())
            try:
                match payload:
                    case _ if fail():
                        pass
                    case _:
                        cursor.execute(input())
            except ValueError as error:
                eval(str(error))
        ''', 'eval')

    def test_subject_exception_prevents_pattern_and_guard_effects(self):
        self.assert_rules('''
            def fail():
                raise ValueError('safe')
            match fail():
                case _ if eval(input()):
                    pass
        ''')

    def test_selected_return_still_runs_finally(self):
        self.assert_rules('''
            def scan():
                code = 'safe'
                try:
                    match payload:
                        case _ if (code := input()) and False:
                            pass
                        case _:
                            return 'safe'
                finally:
                    eval(code)
            scan()
        ''', 'eval')

    def test_loop_guard_writes_reach_break_and_continue_successors(self):
        for exit_ in ('break', 'continue'):
            with self.subTest(exit_=exit_):
                self.assert_rules(f"code = 'safe'\nfor payload in records:\n"
                                  "    match payload:\n"
                                  "        case _ if (code := input()) and False:\n"
                                  "            pass\n"
                                  f"        case _:\n            {exit_}\n"
                                  "eval(code)\n", 'eval')


if __name__ == "__main__":
    unittest.main(verbosity=2)
