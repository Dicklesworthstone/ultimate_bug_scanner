"""Regression controls for expression-level reaching definitions and call sinks."""
import unittest
import ast
import sys
from test_taint_python_dataflow import SourceTest


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
