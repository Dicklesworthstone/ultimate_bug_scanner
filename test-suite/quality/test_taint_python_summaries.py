"""Module-local call/return and recursive summary regressions."""
import unittest
from test_taint_python_dataflow import SourceTest


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
