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


class CallbackSummaryTests(SourceTest):
    def test_callback_parameter_reaches_builtin_sink(self):
        for callback, rule in [('eval', 'eval'), ('os.system', 'command'), ('cursor.execute', 'sql')]:
            with self.subTest(callback=callback):
                self.assert_rules(f'def apply(callback, value): callback(value)\napply({callback}, input())', rule)
                self.assert_rules(f"def apply(callback, value): callback(value)\napply({callback}, 'safe')")

    def test_source_callback_returns_input(self):
        self.assert_rules('def read(callback): return callback()\neval(read(input))', 'eval')
        self.assert_rules("def read(callback): return callback()\neval(read(lambda: 'safe'))")

    def test_safe_callback_does_not_inherit_unused_argument(self):
        self.assert_rules("def apply(callback, value): return callback(value)\neval(apply(lambda unused: 'safe', input()))")
        self.assert_rules('def apply(callback, value): return callback(value)\neval(apply(lambda used: used, input()))', 'eval')

    def test_callback_sanitizers_remain_domain_specific(self):
        self.assert_rules('def apply(callback, value): return callback(value)\nHttpResponse(apply(html.escape, input()))')
        self.assert_rules('def apply(callback, value): return callback(value)\neval(apply(html.escape, input()))', 'eval')
        self.assert_rules('def apply(callback, value): return callback(value)\nos.system(apply(shlex.quote, input()))')

    def test_unknown_callback_alternative_cannot_certify_sanitization(self):
        for choice in ['html.escape if flag else opaque', 'html.escape if flag else (lambda value: value)']:
            with self.subTest(choice=choice):
                self.assert_rules(f'def apply(callback, value): return callback(value)\nHttpResponse(apply({choice}, input()))', 'xss')

    def test_safe_and_unsafe_callback_contexts_do_not_pollute_each_other(self):
        for order in ['clean\nunsafe', 'unsafe\nclean']:
            calls = {'clean': "apply(lambda value: None, input())", 'unsafe': "apply(eval, 'safe')"}
            self.assert_rules('def apply(callback, value): callback(value)\n' + '\n'.join(calls[key] for key in order.splitlines()))
        self.assert_rules('def apply(callback, value): callback(value)\napply(lambda value: None, input())\napply(eval, input())', 'eval')

    def test_captured_callback_is_specialized_without_comprehension(self):
        for callback, expected in [('eval', ('eval',)), ('lambda value: None', ())]:
            self.assert_rules(f'def handler(code):\n    run = {callback}\n    def send(): run(code)\n    send()\nhandler(input())', *expected)

    def test_captured_callback_keeps_lexical_scope_in_comprehension(self):
        self.assert_rules('''
            def handler(code):
                run = eval
                def send(): run(code)
                [send() for run in [lambda value: None] for code in ['safe']]
            handler(input())
        ''', 'eval')
        self.assert_rules('''
            def handler(code):
                run = lambda value: None
                def send(): run(code)
                [send() for run in [eval] for code in [input()]]
            handler('safe')
        ''')

    def test_keyword_default_and_unpacked_callback_bindings(self):
        for call in ['apply(callback=eval, value=input())', 'apply(**{"callback": eval, "value": input()})', 'apply(*[eval, input()])']:
            self.assert_rules('def apply(callback, value): callback(value)\n' + call, 'eval')
        self.assert_rules('def apply(value, *, callback=eval): callback(value)\napply(input())', 'eval')
        self.assert_rules('def apply(value, *, callback=eval): callback(value)\napply(input(), callback=lambda value: None)')

    def test_callback_returns_an_alias_and_a_callable(self):
        self.assert_rules('''
            def apply(callback, value): return callback(value)
            box = []
            alias = apply(lambda value: value, box)
            alias.append(input())
            eval(box[0])
        ''', 'eval')
        self.assert_rules('def apply(callback): return callback()\napply(lambda: eval)(input())', 'eval')

    def test_callback_heap_mutations_reach_the_caller(self):
        self.assert_rules('''
            def fill(box): box.append(input())
            def apply(callback, box): callback(box)
            target = []
            apply(fill, target)
            eval(target[0])
        ''', 'eval')
        self.assert_rules('''
            def fill(box): box.append('safe')
            def apply(callback, box): callback(box)
            target = []
            apply(fill, target)
            eval(target[0])
        ''')

    def test_callback_exceptions_and_finally_preserve_tainted_payload(self):
        self.assert_rules('''
            def raise_code(value): raise ValueError(value)
            def apply(callback, code):
                try:
                    callback(code)
                except ValueError as error:
                    eval(str(error))
            apply(raise_code, input())
        ''', 'eval')
        self.assert_rules('''
            def raise_code(value): raise ValueError(value)
            def apply(callback, code):
                try:
                    callback(code)
                finally:
                    return 'safe'
            eval(apply(raise_code, input()))
        ''')

    def test_async_callback_identity_is_kept_until_await(self):
        self.assert_rules('''
            async def apply(callback, value): callback(value)
            async def route(): await apply(eval, input())
        ''', 'eval')
        self.assert_rules('async def apply(callback, value): callback(value)\napply(eval, input())')

    def test_generator_callback_yields_the_returned_value(self):
        self.assert_rules('''
            def values(callback, value): yield callback(value)
            for code in values(lambda value: value, input()): eval(code)
        ''', 'eval')
        self.assert_rules('''
            def values(callback, value): yield callback(value)
            for code in values(lambda value: 'safe', input()): eval(code)
        ''')

    def test_recursive_callback_context_reaches_a_fixed_point(self):
        self.assert_rules('''
            def apply(callback, value):
                if condition: return apply(callback, value)
                return callback(value)
            apply(eval, input())
        ''', 'eval')
        self.assert_rules('''
            def apply(callback, value):
                if condition: return apply(callback, value)
                return callback(value)
            HttpResponse(apply(html.escape, input()))
        ''')

    def test_callback_changes_across_mutual_recursion(self):
        self.assert_rules('''
            def first(callback, value):
                if condition: return second(eval, value)
                return callback(value)
            def second(callback, value): return first(callback, value)
            first(lambda value: None, input())
        ''', 'eval')

    def test_long_callback_forwarding_chain_has_no_inline_depth_limit(self):
        source = '\n'.join(f'def f{i}(callback, value): return f{i+1}(callback, value)' for i in range(24))
        self.assert_rules(source + '\ndef f24(callback, value): return callback(value)\nf0(eval, input())', 'eval')

    def test_context_keys_exclude_argument_taint_and_evidence(self):
        source = 'def apply(callback, value): return callback(value)\n'
        source += '\n'.join(f'apply(eval, {value})' for value in ['input()', "'safe'", 'request.args["x"]'] * 10)
        engine = taint_py._Analysis(ast.parse(source))
        engine.analyze()
        contexts = [key for key in engine.summaries if isinstance(key, tuple)]
        self.assertEqual(len(contexts), 1, contexts)

    def test_cpython_callback_and_capture_oracles(self):
        cases = [
            ('def apply(cb, value): cb(value)\napply(eval, input())', ['untrusted']),
            ('def apply(cb, value): cb(value)\napply(lambda value: None, input())', []),
            ('def handler(value):\n run=eval\n def send(): run(value)\n'
             " [send() for run in [lambda value: None] for value in ['safe']]\nhandler(input())", ['untrusted']),
            ('def apply(cb, value): return cb(value)\n'
             "eval(apply(lambda value: 'safe', input()))", ['safe']),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                events = []
                # This is an independent Python semantic oracle, not analyzer
                # execution of scanned code. Only fixed authored fixtures run;
                # eval/input are harmless collectors, not real builtins.
                namespace = {'__builtins__': {}, 'input': lambda: 'untrusted', 'eval': events.append}
                exec(compile(source, '<safe-callback-oracle>', 'exec'), namespace)
                self.assertEqual(events, expected)
                self.assert_rules(source, *(['eval'] if 'untrusted' in expected else []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
