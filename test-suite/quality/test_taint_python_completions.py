"""Source-only regressions for abrupt control flow and cleanup (D6)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_taint_python_dataflow import ROOT, SourceTest


class CompletionFlowTests(SourceTest):
    def test_assertion_message_only_runs_on_failure(self):
        self.assert_rules('assert True, eval(input())')
        self.assert_rules('''
            try:
                assert False, input()
            except AssertionError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_finally_return_replaces_pending_return(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return value
                finally:
                    return 'safe'
            eval(choose(input()))
        ''')
        self.assert_rules('''
            def choose(value):
                try:
                    return 'safe'
                finally:
                    return value
            eval(choose(input()))
        ''', 'eval')

    def test_finally_override_preserves_sanitizer_domain(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return value
                finally:
                    return html.escape(value)
            HttpResponse(choose(input()))
            cursor.execute(choose(input()))
        ''', 'sql')

    def test_nested_finally_uses_the_last_effective_return(self):
        self.assert_rules('''
            def choose(value):
                try:
                    try:
                        return value
                    finally:
                        return value
                finally:
                    return 'safe'
            eval(choose(input()))
        ''')

    def test_conditional_cleanup_does_not_erase_a_possible_return(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return value
                finally:
                    if condition:
                        return 'safe'
            eval(choose(input()))
        ''', 'eval')

    def test_return_expression_is_a_snapshot_before_cleanup(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return value
                finally:
                    value = 'safe'
            eval(choose(input()))
        ''', 'eval')
        self.assert_rules('''
            def choose(value):
                result = 'safe'
                try:
                    return result
                finally:
                    result = value
            eval(choose(input()))
        ''')

    def test_returned_object_observes_finally_mutation(self):
        self.assert_rules('''
            def choose(value):
                result = {}
                try:
                    return result
                finally:
                    result['code'] = value
            eval(choose(input())['code'])
        ''', 'eval')

    def test_overridden_object_return_does_not_taint_replacement(self):
        self.assert_rules('''
            def choose(value):
                result = {}
                try:
                    return result
                finally:
                    result['code'] = value
                    return {'code': 'safe'}
            eval(choose(input())['code'])
        ''')

    def test_finally_return_replaces_callable_identity(self):
        self.assert_rules('''
            def choose():
                try:
                    return eval
                finally:
                    return print
            choose()(input())
        ''')
        self.assert_rules('''
            def choose():
                try:
                    return print
                finally:
                    return eval
            choose()(input())
        ''', 'eval')

    def test_cleanup_sinks_survive_overriding_a_return(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return value
                finally:
                    eval(value)
                    return 'safe'
            eval(choose(input()))
        ''', 'eval')

    def test_exception_payload_reaches_handler_and_alias(self):
        for value, expected in (('input()', ('eval',)), ("'safe'", ())):
            with self.subTest(value=value):
                self.assert_rules(f'''
                    try:
                        raise ValueError({value})
                    except ValueError as error:
                        alias = error
                        eval(alias.args[0])
                ''', *expected)

    def test_typed_handlers_only_take_the_first_matching_exception(self):
        self.assert_rules('''
            try:
                raise ValueError(input())
            except KeyError as error:
                eval(error.args[0])
            except Exception:
                pass
        ''')
        self.assert_rules('''
            try:
                raise ValueError(input())
            except Exception:
                pass
            except ValueError as error:
                eval(error.args[0])
        ''')
        self.assert_rules('''
            try:
                raise ValueError(input())
            except (KeyError, ValueError) as error:
                eval(error.args[0])
        ''', 'eval')

    def test_imported_builtin_exception_alias(self):
        self.assert_rules('''
            from builtins import ValueError as Invalid
            try:
                raise Invalid(input())
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_reraise_keeps_payload_through_nested_finally(self):
        self.assert_rules('''
            try:
                try:
                    raise ValueError(input())
                except ValueError:
                    raise
                finally:
                    marker = 'safe'
            except Exception as error:
                eval(error.args[0])
        ''', 'eval')

    def test_exception_in_else_bypasses_sibling_handlers(self):
        self.assert_rules('''
            try:
                try:
                    value = 'safe'
                except ValueError:
                    pass
                else:
                    raise ValueError(input())
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_handler_raise_is_not_caught_by_a_later_sibling(self):
        self.assert_rules('''
            try:
                try:
                    raise KeyError('safe')
                except KeyError:
                    raise ValueError(input())
                except ValueError:
                    pass
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_exception_target_is_cleared_but_saved_alias_survives(self):
        self.assert_rules('''
            alias = 'safe'
            try:
                raise ValueError(input())
            except ValueError as error:
                alias = error
            eval(error)
            eval(alias.args[0])
        ''', 'eval')

    def test_replacement_exception_does_not_inherit_discarded_payload(self):
        self.assert_rules('''
            try:
                try:
                    raise ValueError(input())
                finally:
                    raise RuntimeError('safe')
            except RuntimeError as error:
                eval(error.args[0])
        ''')
        self.assert_rules('''
            try:
                try:
                    raise ValueError('safe')
                finally:
                    raise RuntimeError(input())
            except RuntimeError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_finally_break_replaces_pending_return(self):
        self.assert_rules('''
            def choose(value):
                while True:
                    try:
                        return value
                    finally:
                        break
                return 'safe'
            eval(choose(input()))
        ''')

    def test_finally_continue_does_not_escape_as_a_return(self):
        self.assert_rules('''
            def choose(value):
                for item in items:
                    try:
                        return value
                    finally:
                        continue
                return 'safe'
            eval(choose(input()))
        ''')

    def test_break_in_cleanup_bypasses_loop_else(self):
        self.assert_rules('''
            value = 'safe'
            while True:
                try:
                    continue
                finally:
                    break
            else:
                value = input()
            eval(value)
        ''')

    def test_finally_updates_continue_edge(self):
        self.assert_rules('''
            value = 'safe'
            while condition:
                eval(value)
                try:
                    continue
                finally:
                    value = input()
        ''', 'eval')

    def test_cleanup_runs_after_break_consumed_by_inner_loop(self):
        self.assert_rules('''
            try:
                while True:
                    break
                value = input()
            finally:
                eval(value)
        ''', 'eval')

    def test_only_normal_try_completion_enters_else(self):
        self.assert_rules('''
            def choose(value):
                try:
                    return 'safe'
                except Exception:
                    return 'safe'
                else:
                    eval(value)
            choose(input())
        ''')

    def test_generator_yield_survives_overriding_final_return(self):
        self.assert_rules('''
            def provider(value):
                try:
                    yield value
                    return value
                finally:
                    return 'safe'
            for item in provider(input()):
                eval(item)
        ''', 'eval')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'Set UBS_TAINT_E2E=1 for real scanner checks')
class CompletionCliTests(unittest.TestCase):
    def test_json_and_sarif_preserve_deferred_process_and_environment_flows(self):
        cases = (
            ('awaited-command', "import subprocess\nasync def vector(program, code):\n    return [program, '-c', code]\nasync def route():\n    subprocess.run(await vector('python', input()))\n", {'command'}),
            ('awaited-data', "import subprocess\nasync def vector(program, code):\n    return [program, '-c', code]\nasync def route():\n    subprocess.run(await vector('echo', input()))\n", set()),
            ('task-write', "import asyncio, subprocess\nasync def change(argv):\n    argv[0] = 'python'\nasync def route():\n    argv = ['echo', '-c', input()]\n    task = asyncio.create_task(change(argv))\n    await asyncio.sleep(0)\n    subprocess.run(argv)\n", {'command'}),
            ('unawaited-write', "import subprocess\nasync def change(argv):\n    argv[0] = 'python'\nasync def route():\n    argv = ['echo', '-c', input()]\n    pending = change(argv)\n    subprocess.run(argv)\n", set()),
            ('late-global', "import asyncio\ncode = 'safe'\nasync def read():\n    return code\npending = read()\ncode = input()\neval(asyncio.run(pending))\n", {'eval'}),
            ('cleared-global', "import asyncio\ncode = input()\nasync def read():\n    return code\npending = read()\ncode = 'safe'\neval(asyncio.run(pending))\n", set()),
            ('cleanup-command', "import subprocess\ndef vector(code):\n    try:\n        return ['echo', code]\n    finally:\n        return ['python', '-c', code]\nsubprocess.run(vector(input()))\n", {'command'}),
            ('cleanup-data', "import subprocess\ndef vector(code):\n    try:\n        return ['python', '-c', code]\n    finally:\n        return ['echo', code]\nsubprocess.run(vector(input()))\n", set()),
        )
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-completions'
        artifacts.mkdir(parents=True, exist_ok=True)
        for name, source, expected in cases:
            with tempfile.TemporaryDirectory(prefix='ubs-deferred-process-cli-') as tmp:
                target = Path(tmp) / 'route.py'
                target.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, format=output):
                        result = subprocess.run(
                            [str(ROOT / 'ubs'), str(target), '--only=python', '--ci', f'--format={output}'],
                            cwd=tmp, capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1'))
                        (artifacts / f'{name}-{output}.json').write_text(result.stdout, encoding='utf-8')
                        (artifacts / f'{name}-{output}.stderr.log').write_text(result.stderr, encoding='utf-8')
                        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report.get('status'), 'ok', report)
                            rules = {finding['rule_id'] for finding in report.get('findings', [])}
                        else:
                            rules = {finding['ruleId'] for run in report['runs'] for finding in run.get('results', [])}
                        domains = {rule.rsplit('.', 1)[-1] for rule in rules
                                   if rule.startswith(('py.taint.', 'python.taint.'))}
                        self.assertEqual(domains, expected, report)
                        print('DEFERRED_PROCESS_CLI_PASS', name, output, flush=True)

    def test_json_and_sarif_report_effective_cleanup_flows(self):
        cases = (
            ('payload', 'try:\n    raise ValueError(input())\nexcept ValueError as error:\n    eval(error.args[0])\n', True),
            ('safe-payload', "try:\n    raise ValueError('safe')\nexcept ValueError as error:\n    eval(error.args[0])\n", False),
            ('safe-return', "def choose(value):\n    try:\n        return value\n    finally:\n        return 'safe'\neval(choose(input()))\n", False),
            ('unsafe-return', "def choose(value):\n    try:\n        return 'safe'\n    finally:\n        return value\neval(choose(input()))\n", True),
            ('callee-payload', "def fail(value):\n    raise ValueError(value)\ntry:\n    fail(input())\nexcept ValueError as error:\n    eval(error.args[0])\n", True),
            ('callee-stop', "def fail():\n    raise ValueError('stop')\nfail()\neval(input())\n", False),
            ('async-payload', "async def fail(value):\n    raise ValueError(value)\nasync def route():\n    coroutine = fail(input())\n    try:\n        await coroutine\n    except ValueError as error:\n        eval(error.args[0])\n", True),
            ('unawaited', "async def consume(value):\n    eval(value)\ncoroutine = consume(input())\n", False),
        )
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-completions'
        artifacts.mkdir(parents=True, exist_ok=True)

        def collect(value):
            if isinstance(value, dict):
                return {str(value[key]) for key in ('rule', 'rule_id', 'ruleId') if key in value} | set().union(
                    *(collect(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(collect(child) for child in value))
            return set()

        with tempfile.TemporaryDirectory(prefix='ubs-completions-cli-') as tmp:
            target = Path(tmp) / 'route.py'
            for name, source, expected in cases:
                target.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, format=output):
                        result = subprocess.run(
                            [str(ROOT / 'ubs'), str(target), '--only=python', '--ci', f'--format={output}'],
                            cwd=tmp, capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1'))
                        (artifacts / f'{name}-{output}.json').write_text(result.stdout, encoding='utf-8')
                        (artifacts / f'{name}-{output}.stderr.log').write_text(result.stderr, encoding='utf-8')
                        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report.get('status'), 'ok', report)
                            rules = collect(report)
                        else:
                            rules = {item['ruleId'] for run in report['runs'] for item in run.get('results', [])}
                        self.assertEqual(bool(rules & {'py.taint.eval', 'python.taint.eval'}), expected, report)
                        print('COMPLETION_CLI_PASS', name, output, flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
