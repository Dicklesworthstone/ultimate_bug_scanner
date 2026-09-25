"""Source-level regressions for Python taint flow, never executed fixtures."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.registry import RunContext


class SourceTest(unittest.TestCase):
    def scan(self, source: str):
        with tempfile.TemporaryDirectory(prefix='ubs-taint-dataflow-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text(textwrap.dedent(source).lstrip('\n'), encoding='utf-8')
            return list(taint_py.run(RunContext(lang='python', files=[path])))

    def assert_rules(self, source: str, *rules: str):
        findings = self.scan(source)
        self.assertEqual(sorted(f['rule'] for f in findings),
                         sorted(f'python.taint.{r}' for r in rules), findings)
        return findings


class SanitizerDomainTests(SourceTest):
    def test_html_escaping_is_not_sql_command_or_eval_sanitization(self):
        for sanitizer in ('html.escape', 'django.utils.html.escape', 'flask.escape', 'bleach.clean'):
            for sink, rule in (("cursor.execute('select ' + q)", 'sql'),
                               ('os.system(q)', 'command'), ('eval(q)', 'eval')):
                with self.subTest(sanitizer=sanitizer, sink=sink):
                    self.assert_rules(f"q = {sanitizer}(request.args['q'])\n{sink}\n", rule)

    def test_shell_quoting_only_protects_shell_code(self):
        for sink, expected in (("os.system('echo ' + q)", ()),
                               ('cursor.execute(q)', ('sql',)),
                               ('eval(q)', ('eval',)),
                               ('HttpResponse(q)', ('xss',)),
                               ('subprocess.run([q])', ('command',)),
                               ("os.execv(q, ['arg'])", ('command',))):
            with self.subTest(sink=sink):
                self.assert_rules(f"q = shlex.quote(input())\n{sink}\n", *expected)

    def test_marking_safe_does_not_escape(self):
        for marker in ('mark_safe', 'django.utils.safestring.mark_safe', 'Markup', 'markupsafe.Markup'):
            with self.subTest(marker=marker):
                self.assert_rules(f'HttpResponse({marker}(input()))\n', 'xss')

    def test_url_encoding_is_not_a_generic_sanitizer(self):
        self.assert_rules("eval(urllib.parse.quote(input()))\n", 'eval')

    def test_escaping_one_operand_does_not_hide_another(self):
        self.assert_rules("q = input()\nHttpResponse(html.escape(q) + q)\n", 'xss')
        self.assert_rules("q = input()\nHttpResponse(html.escape('safe') + q)\n", 'xss')
        self.assert_rules("q = input()\nHttpResponse(html.escape(q) + html.escape(q))\n")

    def test_sanitizer_name_in_a_string_is_not_a_sanitizer(self):
        self.assert_rules("q = input()\neval('html.escape' + q)\n", 'eval')

    def test_aliases_resolve_and_shadowing_revokes_sanitizer_identity(self):
        self.assert_rules('from html import escape as e\nHttpResponse(e(input()))\n')
        self.assert_rules('import html as h\nHttpResponse(h.escape(input()))\n')
        self.assert_rules('from html import escape as e\ne = other\nHttpResponse(e(input()))\n', 'xss')
        self.assert_rules('import html\nhtml = other\nHttpResponse(html.escape(input()))\n', 'xss')

    def test_configurable_cleaner_is_not_assumed_safe(self):
        self.assert_rules("HttpResponse(bleach.clean(input(), tags=['script']))\n", 'xss')


class SinkArgumentTests(SourceTest):
    def test_bound_sql_parameters_are_not_query_text(self):
        for query in ("'select * from t where k = %s'", "'select * from t where k = ?'",
                      "'select * from t where k = :key'"):
            with self.subTest(query=query):
                self.assert_rules(f'q = input()\ncursor.execute({query}, (q,))\n')
        self.assert_rules("q = input()\ncursor.execute('select ' + q, (123,))\n", 'sql')
        self.assert_rules("q = input()\ncursor.execute(query=q, params=('safe',))\n", 'sql')

    def test_literal_argv_arguments_are_not_executable_code(self):
        self.assert_rules("subprocess.run(['echo', input()])\n")
        self.assert_rules("subprocess.run(['echo', input()], shell=False)\n")
        self.assert_rules("subprocess.run([input(), 'safe'])\n", 'command')
        self.assert_rules("subprocess.run('echo ' + input(), shell=True)\n", 'command')
        self.assert_rules("subprocess.run(args=['echo', input()])\n")
        self.assert_rules("subprocess.run(args=[input(), 'safe'])\n", 'command')

    def test_eval_globals_are_not_executed_as_source(self):
        self.assert_rules("eval('1', {'data': input()})\n")
        self.assert_rules("eval(input(), {})\n", 'eval')

    def test_response_headers_are_not_response_html(self):
        self.assert_rules("HttpResponse('safe', headers={'x': input()})\n")
        self.assert_rules("HttpResponse(content=input())\n", 'xss')

    def test_alias_sources_and_sinks(self):
        self.assert_rules('from flask import request as req\nfrom os import system as execute\nexecute(req.args["q"])\n', 'command')
        self.assert_rules('from subprocess import run as launch\nlaunch(input(), shell=True)\n', 'command')
        self.assert_rules('eval(event["body"])\n', 'eval')


class ReachingDefinitionTests(SourceTest):
    def test_safe_reassignment_kills_taint(self):
        self.assert_rules("q = input()\nq = 'safe'\neval(q)\n")

    def test_later_assignment_does_not_taint_earlier_use(self):
        self.assert_rules("q = 'safe'\neval(q)\nq = input()\n")

    def test_distinct_function_scopes_do_not_leak(self):
        self.assert_rules('''
            def first():
                q = input()
            def second():
                q = 'safe'
                eval(q)
        ''')

    def test_both_branch_orders_keep_an_unsafe_reaching_definition(self):
        for left, right in (('html.escape(q)', 'q'), ('q', 'html.escape(q)')):
            with self.subTest(left=left):
                self.assert_rules(f"q = input()\nif condition:\n    x = {left}\nelse:\n    x = {right}\nHttpResponse(x)\n", 'xss')
        self.assert_rules("q = input()\nif condition:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = input()\nif condition:\n    q = 'safe'\nelse:\n    q = 'also safe'\neval(q)\n")

    def test_conditional_expression_and_walrus(self):
        self.assert_rules("q = input()\nx = html.escape(q) if condition else q\nHttpResponse(x)\n", 'xss')
        self.assert_rules("eval(q := input())\n", 'eval')
        self.assert_rules("q = 'a' if input() else 'b'\neval(q)\n")

    def test_loops_reach_a_fixed_point(self):
        self.assert_rules("a = 'safe'\nb = 'safe'\nwhile condition:\n    a = b\n    b = input()\neval(a)\n", 'eval')
        self.assert_rules("q = input()\nfor x in values:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("for q in request.args.values():\n    eval(q)\n", 'eval')

    def test_tuple_assignment_is_simultaneous(self):
        self.assert_rules("a = input()\nb = 'safe'\na, b = b, a\neval(b)\n", 'eval')
        self.assert_rules("a = input()\nb = 'safe'\na, b = b, a\neval(a)\n")

    def test_break_bypasses_loop_else_and_continue_skips_remaining_body(self):
        self.assert_rules("q = input()\nfor item in values:\n    break\nelse:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = 'safe'\nfor item in values:\n    continue\n    q = input()\neval(q)\n")
        self.assert_rules("q = 'safe'\nwhile condition:\n    q = input()\n    if other:\n        break\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = 'safe'\nwhile condition:\n    try:\n        break\n    finally:\n        q = input()\nelse:\n    q = 'safe'\neval(q)\n", 'eval')

    def test_exception_and_finally_paths_keep_taint(self):
        self.assert_rules("q = 'safe'\ntry:\n    q = input()\n    work()\n    q = 'safe'\nexcept Exception:\n    eval(q)\n", 'eval')
        self.assert_rules("def run():\n    q = 'safe'\n    try:\n        q = input()\n        return\n    finally:\n        eval(q)\n", 'eval')

    def test_multiline_calls_and_hashes_in_strings(self):
        findings = self.assert_rules("q = input()\ncursor.execute(\n    '# ' + q\n)\n", 'sql')
        self.assertEqual((findings[0]['line'], findings[0]['col']), (2, 1))

    def test_string_and_comment_examples_are_not_code(self):
        self.assert_rules('''
            example = "eval(input())"
            # eval(input())
            q = input()
            eval('q')
        ''')

    def test_comprehension_scope_and_container_write(self):
        self.assert_rules("values = [x for x in request.args.values()]\neval(values[0])\n", 'eval')
        self.assert_rules("q = 'safe'\nvalues = [q for q in request.args.values()]\neval(q)\n")
        self.assert_rules("items = {}\nitems['q'] = input()\nitems['safe'] = 'safe'\neval(items['q'])\n", 'eval')

    def test_rule_profile_disables_findings(self):
        with tempfile.TemporaryDirectory(prefix='ubs-taint-profile-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text('eval(input())\n')
            ctx = RunContext(lang='python', files=[path], profile={'disabled_rules': ['python.taint.eval']})
            self.assertEqual(list(taint_py.run(ctx)), [])

    def test_legacy_and_structured_outputs_agree(self):
        with tempfile.TemporaryDirectory(prefix='ubs-taint-dialects-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text(''.join('eval(input())\n' for _ in range(5)))
            findings = list(taint_py.run(RunContext(lang='python', files=[path])))
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(taint_py.main(['taint', tmp]), 0)
            rule, count, samples = buffer.getvalue().strip().split('\t')
            self.assertEqual(rule, 'py.taint.eval')
            self.assertEqual(int(count), len(findings))
            self.assertEqual(len(samples.split(',')), 3)


class SuppressionTests(SourceTest):
    def test_marker_inside_string_does_not_disable_security(self):
        self.assert_rules("label = 'ubs:ignore'\neval(input())\n", 'eval')
        self.assert_rules("eval(input() + 'ubs:ignore')\n", 'eval')

    def test_scoped_markers_preserve_other_rules(self):
        self.assert_rules('# ubs:ignore[python.taint.xss]\neval(input())\n', 'eval')
        self.assert_rules('# ubs:ignore[python.taint.eval]\neval(input())\n')
        self.assert_rules('# ubs:ignore[py.taint.eval]\neval(input())\n')

    def test_trailing_marker_belongs_to_previous_statement(self):
        self.assert_rules("safe = 1  # ubs:ignore\neval(input())\n", 'eval')
        self.assert_rules('eval(input())  # ubs:ignore\n')

    def test_multiline_statement_uses_shared_interval_ownership(self):
        self.assert_rules('cursor.execute(\n    input()  # ubs:ignore[py.taint.sql]\n)\n')
        self.assert_rules('''
            # ubs:ignore[py.taint.sql]
            result = cursor.execute(
                input()
            )
        ''')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 to run real runner integration')
class RunnerIntegrationTests(unittest.TestCase):
    def test_runner_emits_taint_findings_and_safe_parameter_control(self):
        for code, expected in (("q=html.escape(input())\ncursor.execute(q)\n", True),
                               ("q=input()\ncursor.execute('select %s', (q,))\n", False)):
            with self.subTest(code=code), tempfile.TemporaryDirectory(prefix='ubs-taint-e2e-') as tmp:
                path = Path(tmp) / 'view.py'
                path.write_text(code)
                env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_SKIP_SIZE_CHECK='1')
                result = subprocess.run([str(ROOT / 'ubs'), str(path), '--only=python', '--ci', '--format=json'],
                                        cwd=tmp, env=env, capture_output=True, text=True, timeout=180)
                self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report.get('status'), 'ok', result.stdout + result.stderr)
                # Inspect rule IDs, not general critical counts (other detectors
                # may independently report the deliberately unsafe source).
                def rules(value):
                    found = set()
                    if isinstance(value, dict):
                        for key, item in value.items():
                            if key in {'rule', 'rule_id', 'ruleId', 'id'} and isinstance(item, str):
                                found.add(item)
                            found.update(rules(item))
                    elif isinstance(value, list):
                        for item in value:
                            found.update(rules(item))
                    return found
                ids = rules(report)
                self.assertEqual(bool(ids & {'py.taint.sql', 'python.taint.sql'}), expected, report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
