"""Regression controls for expression-level reaching definitions and call sinks."""
import unittest
import ast
import subprocess
import sys
from test_taint_python_dataflow import SourceTest, taint_py


class ExpressionFlowTests(SourceTest):
    def test_python_without_pattern_matching_keeps_ordinary_flow_working(self):
        match = getattr(ast, 'Match', None)
        if match is not None:
            delattr(ast, 'Match')
        try:
            self.assert_rules('q = input()\neval(q)\n', 'eval')
        finally:
            if match is not None:
                ast.Match = match

    @unittest.skipUnless(sys.version_info >= (3, 12), 'generic function syntax needs Python 3.12+')
    def test_generic_function_uses_its_runtime_parameter_scope(self):
        self.assert_rules('def execute[T](code: T):\n    eval(code)\nexecute(input())\n', 'eval')

    def test_annotation_only_does_not_assign_a_clean_value(self):
        self.assert_rules('q = input()\nq: str\neval(q)\n', 'eval')
        self.assert_rules('def run(q):\n    q: str\n    eval(q)\nrun(input())\n', 'eval')

    def test_short_circuit_assignment_preserves_skipped_path(self):
        for expression in ("flag and (q := 'safe')", "flag or (q := 'safe')"):
            with self.subTest(expression=expression):
                self.assert_rules(f'q = input()\n{expression}\neval(q)\n', 'eval')
                self.assert_rules(f'def run(q):\n    {expression}\n    eval(q)\nrun(input())\n', 'eval')
        self.assert_rules("q = 'safe'\nflag and (q := input())\neval(q)\n", 'eval')
        self.assert_rules("q = input()\n(q := 'safe') and flag\neval(q)\n")

    def test_chained_comparison_can_skip_later_operands(self):
        self.assert_rules("q = input()\n1 > 2 > (q := 'safe')\neval(q)\n", 'eval')
        self.assert_rules("q = input()\n(q := 'safe') == value\neval(q)\n")
        self.assert_rules("q = input()\n1 > 2 > eval(q)\n", 'eval')

    def test_assert_message_is_not_unconditionally_executed(self):
        self.assert_rules("q = input()\nassert condition, (q := 'safe')\neval(q)\n", 'eval')
        self.assert_rules("assert condition, eval(input())\n", 'eval')

    def test_expanded_keywords_can_supply_source_to_sink(self):
        self.assert_rules("cursor.execute(**{'query': input()})\n", 'sql')
        self.assert_rules("HttpResponse(**{'content': input()})\n", 'xss')
        self.assert_rules("cursor.execute('select %s', **{'params': (input(),)})\n")

    def test_subprocess_executable_override_is_a_separate_sink(self):
        self.assert_rules("subprocess.run(['echo', 'safe'], executable=input())\n", 'command')
        self.assert_rules("subprocess.Popen(['echo'], executable=shlex.quote(input()))\n", 'command')
        self.assert_rules("subprocess.run(['echo', input()], executable='/bin/echo')\n")
        self.assert_rules("subprocess.run([input()], executable='/bin/echo')\n")

    def test_unknown_shell_setting_preserves_executable_risk(self):
        self.assert_rules('subprocess.run(shlex.quote(input()), shell=flag)\n', 'command')
        self.assert_rules("subprocess.run('echo ' + shlex.quote(input()), shell=True)\n")
        self.assert_rules("subprocess.run(['echo', input()], shell=flag)\n")

    def test_immediately_called_lambda_propagates_returns_and_sink_effects(self):
        self.assert_rules('eval((lambda: input())())\n', 'eval')
        self.assert_rules('(lambda code: eval(code))(input())\n', 'eval')
        self.assert_rules('eval((lambda code: code)(input()))\n', 'eval')
        self.assert_rules("eval((lambda code: 'safe')(input()))\n")
        self.assert_rules('(lambda code=input(): eval(code))()\n', 'eval')
        self.assert_rules('HttpResponse((lambda code: html.escape(code))(input()))\n')
        self.assert_rules('def run(code):\n    (lambda payload: eval(payload))(code)\nrun(input())\n', 'eval')

    def test_command_arguments_are_evaluated_once_in_source_order(self):
        self.assert_rules("q = input()\nsubprocess.run([q, (q := 'safe')])\neval(q)\n", 'command')
        self.assert_rules("q = 'safe'\nsubprocess.run([q, (q := input())])\neval(q)\n", 'eval')
        self.assert_rules("q = input()\nsubprocess.run(args=[q, (q := 'safe')])\n", 'command')

    def test_literal_keyword_expansion_preserves_argv_shape(self):
        self.assert_rules("subprocess.run(**{'args': ['echo', input()]})\n")
        self.assert_rules("subprocess.run(**{'args': [input(), 'data']})\n", 'command')
        self.assert_rules("cursor.execute(**{'query': 'select %s', 'params': (input(),)})\n")
        self.assert_rules("HttpResponse(**{'content': 'safe', 'headers': {'x': input()}})\n")

    def test_callee_is_resolved_before_argument_side_effects(self):
        self.assert_rules('def run(code):\n    eval(code)\nrun((run := other, input())[1])\n', 'eval')
        self.assert_rules('import html\nHttpResponse(html.escape((html := other, input())[1]))\n')


class NativeStringResultTests(SourceTest):
    METHODS = ('strip', 'lstrip', 'rstrip', 'removeprefix', 'removesuffix')

    def test_native_string_results_allow_membership_without_losing_sources(self):
        for method in self.METHODS:
            with self.subTest(method=method):
                self.assert_rules(
                    f'value = input().{method}(" ")\n'
                    'any(mark in value for mark in ("a", "b"))\neval(value)\n', 'eval')
                self.assert_rules(
                    f'value = " aba ".{method}(" ")\n'
                    'any(mark in value for mark in ("a", "b"))\neval(value)\n')

    def test_strip_none_and_existing_no_argument_forms_keep_native_identity(self):
        for method in ('strip', 'lstrip', 'rstrip'):
            for argument in ('', 'None', 'chars'):
                with self.subTest(method=method, argument=argument):
                    self.assert_rules(
                        'chars = None if flag else " "\n'
                        f'value = input().{method}({argument})\n'
                        'any(mark in value for mark in ("a", "b"))\neval(value)\n', 'eval')

    def test_captured_string_methods_keep_their_original_receiver(self):
        for method in self.METHODS:
            with self.subTest(method=method):
                self.assert_rules(
                    f'text = input()\nnormalize = text.{method}\ntext = "fixed"\n'
                    'value = normalize(" ")\n'
                    'any(mark in value for mark in ("a", "b"))\neval(value)\n', 'eval')
                self.assert_rules(
                    f'def capture(text):\n    return text.{method}\n'
                    'normalize = capture(input())\nvalue = normalize(" ")\n'
                    'any(mark in value for mark in ("a", "b"))\neval(value)\n', 'eval')
                self.assert_rules(
                    f'def normalize(text, chars):\n    return text.{method}(chars)\n'
                    'value = normalize(input(), " ")\n'
                    'any(mark in value for mark in ("a", "b"))\neval(value)\n', 'eval')

    def test_string_transforms_do_not_extend_sanitizer_domains(self):
        for method in self.METHODS:
            with self.subTest(method=method):
                self.assert_rules(
                    f'import html\nvalue = input().{method}(" ")\n'
                    'any(mark in value for mark in ("a", "b"))\n'
                    'HttpResponse(html.escape(value))\neval(html.escape(value))\n', 'eval')

    def test_custom_and_opaque_operands_do_not_gain_native_string_proof(self):
        operations = (
            'value = receiver.strip(" ")',
            'value = receiver.removeprefix(" ")',
            'value = input().strip(opaque)',
            'value = input().removeprefix(opaque)',
            'value = input().removesuffix(None)',
            'value = input().strip(b" ")',
            'value = input().strip(" ", "x")',
            'value = input().removeprefix()',
            'value = input().strip(chars=" ")',
            'value = input().removeprefix(prefix=" ")',
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(operation + '\nany(mark in value for mark in ("a", "b"))\n')

    def test_unproved_argument_producer_cannot_be_repaired_by_a_native_result(self):
        for method in self.METHODS:
            for expression in (f'input().{method}(render())', f'render().{method}(" ")'):
                with self.subTest(method=method, expression=expression):
                    # A native result has string identity, but cannot grant
                    # generator-consumer authority to an unresolved earlier
                    # producer. The existing join boundary requires both.
                    with self.assertRaisesRegex(taint_py.AnalysisLimit, 'producer effects'):
                        self.scan('def render():\n    owned = opaque()\n    return " "\n'
                                  f'value = {expression}\n'
                                  'value.join(mark for mark in ("a", "b"))\n')

    def test_native_runtime_results_and_argument_protocols(self):
        source = '''
text = ' aba '
for method in ('strip', 'lstrip', 'rstrip', 'removeprefix', 'removesuffix'):
    saved = getattr(text, method)
    value = saved(' ')
    assert type(value) is str
    assert any(mark in value for mark in ('a', 'b'))
for method in ('strip', 'lstrip', 'rstrip'):
    assert type(getattr(text, method)()) is str
    assert type(getattr(text, method)(None)) is str
class Argument:
    def __str__(self):
        raise AssertionError('custom string conversion must not run')
for method in ('strip', 'lstrip', 'rstrip', 'removeprefix', 'removesuffix'):
    try:
        getattr(text, method)(Argument())
    except TypeError:
        pass
    else:
        raise AssertionError('opaque argument was accepted')
class Receiver:
    def strip(self, chars):
        return {'custom': chars}
assert type(Receiver().strip(' ')) is dict
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-c', source],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
