"""Call summaries must separate returned and exceptional continuations (D6)."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from test_taint_python_dataflow import ROOT, SourceTest, taint_py


class CoroutineProcessIntegrationTests(SourceTest):
    def test_awaited_vector_factory_keeps_program_and_operand_positions(self):
        for program, expected in (('python', ('command',)), ('echo', ())):
            with self.subTest(program=program):
                self.assert_rules(f'''
                    import subprocess
                    async def vector(program, value):
                        return [program, '-c', value]
                    async def route():
                        subprocess.run(await vector('{program}', input()))
                ''', *expected)

    def test_returned_coroutine_substitutes_command_values(self):
        for program, expected in (('python', ('command',)), ('echo', ())):
            with self.subTest(program=program):
                self.assert_rules(f'''
                    import subprocess
                    async def vector(program, value):
                        return [program, '-c', value]
                    def create(program, value):
                        return vector(program, value)
                    async def route():
                        subprocess.run(await create('{program}', input()))
                ''', *expected)

    def test_coroutine_arguments_keep_creation_time_literal_identity(self):
        self.assert_rules('''
            import subprocess
            async def vector(program, value):
                return [program, '-c', value]
            async def route():
                program = 'python'
                pending = vector(program, input())
                program = 'echo'
                subprocess.run(await pending)
        ''', 'command')
        self.assert_rules('''
            import subprocess
            async def vector(program, value):
                return [program, '-c', value]
            async def route():
                program = 'echo'
                pending = vector(program, input())
                program = 'python'
                subprocess.run(await pending)
        ''')

    def test_unawaited_coroutine_does_not_mutate_saved_argv(self):
        self.assert_rules('''
            import subprocess
            async def change(argv):
                argv[0] = 'python'
            async def route():
                argv = ['echo', '-c', input()]
                pending = change(argv)
                subprocess.run(argv)
        ''')

    def test_scheduled_clean_writes_invalidate_saved_argv(self):
        for scheduler in ('asyncio.create_task', 'asyncio.ensure_future', 'asyncio.gather'):
            with self.subTest(scheduler=scheduler):
                self.assert_rules(f'''
                    import asyncio, subprocess
                    async def change(argv):
                        argv[0] = 'python'
                    async def route():
                        argv = ['echo', '-c', input()]
                        task = {scheduler}(change(argv))
                        await asyncio.sleep(0)
                        subprocess.run(argv)
                ''', 'command')

    def test_task_failure_keeps_clean_writes_before_it(self):
        self.assert_rules('''
            import asyncio, subprocess
            async def change(argv):
                argv[0] = 'python'
                raise ValueError('stop')
            async def route():
                argv = ['echo', '-c', input()]
                task = asyncio.create_task(change(argv))
                await asyncio.sleep(0)
                subprocess.run(argv)
        ''', 'command')

    def test_exceptional_helper_clean_write_reaches_handler(self):
        self.assert_rules('''
            import subprocess
            def change(argv):
                argv[0] = 'python'
                raise ValueError('stop')
            argv = ['echo', '-c', input()]
            try:
                change(argv)
            except ValueError:
                subprocess.run(argv)
        ''', 'command')

    def test_cleanup_return_replaces_the_original_command_vector(self):
        self.assert_rules('''
            import subprocess
            def vector(value):
                try:
                    return ['python', '-c', value]
                finally:
                    return ['echo', value]
            subprocess.run(vector(input()))
        ''')
        self.assert_rules('''
            import subprocess
            def vector(value):
                try:
                    return ['echo', value]
                finally:
                    return ['python', '-c', value]
            subprocess.run(vector(input()))
        ''', 'command')

    def test_cleanup_exception_prevents_command_execution(self):
        self.assert_rules('''
            import subprocess
            def vector(value):
                try:
                    return ['python', '-c', value]
                finally:
                    raise ValueError('stop')
            subprocess.run(vector(input()))
        ''')

    def test_deferred_global_read_uses_resumption_value(self):
        self.assert_rules('''
            import asyncio
            code = 'safe'
            async def read():
                return code
            pending = read()
            code = input()
            eval(asyncio.run(pending))
        ''', 'eval')
        self.assert_rules('''
            import asyncio
            code = input()
            async def read():
                return code
            pending = read()
            code = 'safe'
            eval(asyncio.run(pending))
        ''')

    def test_deferred_closure_read_uses_the_current_owning_cell(self):
        self.assert_rules('''
            import asyncio
            async def route(code):
                async def read():
                    return code
                pending = read()
                code = input()
                eval(await pending)
            asyncio.run(route('safe'))
        ''', 'eval')
        self.assert_rules('''
            import asyncio
            async def route(code):
                async def read():
                    return code
                pending = read()
                code = 'safe'
                eval(await pending)
            asyncio.run(route(input()))
        ''')

    def test_caller_local_shadow_does_not_replace_a_deferred_global(self):
        self.assert_rules('''
            import asyncio
            code = input()
            async def read():
                return code
            async def route(code):
                pending = read()
                code = 'safe'
                eval(await pending)
            asyncio.run(route('trusted'))
        ''', 'eval')

    def test_deferred_scalar_parameter_remains_a_snapshot(self):
        self.assert_rules('''
            import asyncio
            async def read(code):
                return code
            code = input()
            pending = read(code)
            code = 'safe'
            eval(asyncio.run(pending))
        ''', 'eval')
        self.assert_rules('''
            import asyncio
            async def read(code):
                return code
            code = 'safe'
            pending = read(code)
            code = input()
            eval(asyncio.run(pending))
        ''')


class CallCompletionTests(SourceTest):
    def test_exception_prefix_keeps_global_before_later_clean_write(self):
        for incoming, expected in (('input()', [10]), ("'fixed'", [])):
            with self.subTest(incoming=incoming):
                findings = self.scan(f'''
                    code = {incoming}
                    def clean():
                        global code
                        code = 'fixed'
                    try:
                        may_fail()
                        clean()
                        may_fail()
                    except Exception:
                        eval(code)
                    else:
                        eval(code)
                ''')
                self.assertEqual([(hit['rule'], hit['line']) for hit in findings],
                                 [('python.taint.eval', line) for line in expected], findings)

    def test_exception_prefix_keeps_written_cell_for_escaped_reader(self):
        for incoming, expected in (('input()', [14]), ("'fixed'", [])):
            with self.subTest(incoming=incoming):
                findings = self.scan(f'''
                    def run():
                        code = 'fixed'
                        def store(value):
                            nonlocal code
                            code = value
                        def read():
                            return code
                        try:
                            may_fail()
                            store({incoming})
                            may_fail()
                            store('fixed')
                        except Exception:
                            eval(read())
                        else:
                            eval(read())
                    run()
                ''')
                self.assertEqual([(hit['rule'], hit['line']) for hit in findings],
                                 [('python.taint.eval', line) for line in expected], findings)

    def test_exception_prefix_keeps_rebound_cell_callable(self):
        for target, expected in (('eval', [7]), ('print', [])):
            with self.subTest(target=target):
                findings = self.scan(f'''
                    def run():
                        execute = print
                        def install():
                            nonlocal execute
                            execute = {target}
                        def invoke():
                            execute(input())
                        try:
                            may_fail()
                            install()
                            may_fail()
                        except Exception:
                            invoke()
                    run()
                ''')
                self.assertEqual([(hit['rule'], hit['line']) for hit in findings],
                                 [('python.taint.eval', line) for line in expected], findings)

    def test_loop_iterable_calls_reach_a_fixed_point_before_the_body(self):
        self.assert_rules('''
            def values(code):
                return [code]
            for code in values(input()):
                eval(code)
        ''', 'eval')
        self.assert_rules('''
            def values():
                raise ValueError('stop')
            for code in values():
                eval(input())
            eval(input())
        ''')

    def test_iterable_exception_payload_reaches_the_enclosing_handler(self):
        self.assert_rules('''
            def values(code):
                raise ValueError(code)
            try:
                for code in values(input()):
                    eval(input())
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_comprehension_creation_evaluates_the_outer_iterable(self):
        for expression in ('[value for value in values()]',
                           '{value for value in values()}',
                           '{value: value for value in values()}',
                           '(value for value in values())'):
            with self.subTest(expression=expression):
                self.assert_rules(f'''
                    def values():
                        raise ValueError('stop')
                    result = {expression}
                    eval(input())
                ''')

    def test_comprehension_body_may_be_skipped_but_iterable_effects_are_not(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            values = [stop() for item in unknown]
            eval(input())
        ''', 'eval')
        self.assert_rules('''
            values = [item for item in (code := input())]
            eval(code)
        ''', 'eval')

    def test_earlier_context_manager_handles_later_entry_exceptions(self):
        self.assert_rules('''
            from contextlib import suppress
            def stop():
                raise ValueError('stop')
            with suppress(ValueError), stop():
                eval(input())
            eval(input())
        ''', 'eval')
        self.assert_rules('''
            from contextlib import suppress
            def stop():
                raise ValueError('stop')
            with suppress(KeyError), stop():
                eval(input())
            eval(input())
        ''')

    def test_exception_during_first_context_creation_cannot_be_suppressed(self):
        self.assert_rules('''
            from contextlib import suppress
            def stop():
                raise ValueError('stop')
            with stop(), suppress(ValueError):
                pass
            eval(input())
        ''')

    def test_suppressed_exception_types_are_definition_time_values(self):
        self.assert_rules('''
            from contextlib import suppress
            Error = ValueError
            def fail():
                raise ValueError('stop')
            with suppress(Error):
                Error = KeyError
                fail()
            eval(input())
        ''', 'eval')
        self.assert_rules('''
            from contextlib import suppress
            Error = KeyError
            def fail():
                raise ValueError('stop')
            with suppress(Error):
                Error = ValueError
                fail()
            eval(input())
        ''')

    def test_asyncio_run_retains_an_unknown_awaitable_alternative(self):
        self.assert_rules('''
            import asyncio
            async def stop():
                raise ValueError('stop')
            coroutine = stop() if condition else unknown()
            asyncio.run(coroutine)
            eval(input())
        ''', 'eval')

    def test_asyncio_run_executes_and_transports_exceptions(self):
        self.assert_rules('''
            import asyncio
            async def fail(value):
                raise ValueError(value)
            try:
                asyncio.run(fail(input()))
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_scheduled_coroutine_is_not_lost_or_synchronously_raised(self):
        for scheduler in ('asyncio.create_task', 'asyncio.ensure_future', 'asyncio.gather'):
            with self.subTest(scheduler=scheduler):
                self.assert_rules(f'''
                    import asyncio
                    async def consume(value):
                        eval(value)
                        raise ValueError('stop')
                    async def route():
                        task = {scheduler}(consume(input()))
                        eval(input())
                ''', 'eval', 'eval')

    def test_awaiting_created_task_preserves_exception_payload(self):
        self.assert_rules('''
            import asyncio
            async def fail(value):
                raise ValueError(value)
            async def route():
                task = asyncio.create_task(fail(input()))
                try:
                    await task
                except ValueError as error:
                    eval(error.args[0])
        ''', 'eval')

    def test_context_manager_can_suppress_a_callee_exception(self):
        self.assert_rules('''
            from contextlib import suppress
            def fail():
                raise ValueError('stop')
            with suppress(ValueError):
                fail()
            eval(input())
        ''', 'eval')
        self.assert_rules('''
            from contextlib import suppress
            def fail():
                raise ValueError('stop')
            with suppress(KeyError):
                fail()
            eval(input())
        ''')

    def test_unknown_context_manager_may_suppress(self):
        self.assert_rules('''
            def fail():
                raise ValueError('stop')
            with manager:
                fail()
            eval(input())
        ''', 'eval')

    def test_unawaited_coroutine_does_not_terminate_its_creator(self):
        self.assert_rules('''
            async def fail(value):
                raise ValueError(value)
            coroutine = fail(input())
            eval(input())
        ''', 'eval')

    def test_unawaited_coroutine_does_not_run_its_body(self):
        self.assert_rules('''
            async def consume(value):
                eval(value)
            coroutine = consume(input())
        ''')

    def test_awaited_exception_payload_reaches_handler(self):
        self.assert_rules('''
            async def fail(value):
                raise ValueError(value)
            async def route():
                coroutine = fail(input())
                try:
                    await coroutine
                except ValueError as error:
                    eval(error.args[0])
        ''', 'eval')

    def test_awaited_nonreturning_coroutine_stops_later_sinks(self):
        self.assert_rules('''
            async def fail():
                raise ValueError('stop')
            async def route():
                await fail()
                eval(input())
        ''')

    def test_coroutine_arguments_are_bound_when_created(self):
        self.assert_rules('''
            async def identity(value):
                return value
            async def route():
                value = input()
                coroutine = identity(value)
                value = 'safe'
                eval(await coroutine)
        ''', 'eval')

    def test_coroutine_factory_preserves_symbolic_arguments(self):
        self.assert_rules('''
            async def consume(value):
                eval(value)
            def prepare(value):
                return consume(value)
            async def route():
                await prepare(input())
        ''', 'eval')

    def test_coroutine_object_arguments_observe_later_mutation(self):
        self.assert_rules('''
            async def consume(box):
                eval(box['code'])
            async def route():
                box = {}
                coroutine = consume(box)
                box['code'] = input()
                await coroutine
        ''', 'eval')

    def test_terminating_assert_message_does_not_create_an_assertion(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            try:
                assert False, stop()
            except AssertionError:
                eval(input())
        ''')

    def test_exception_payload_crosses_a_local_call(self):
        for value, expected in (('input()', ('eval',)), ("'safe'", ())):
            with self.subTest(value=value):
                self.assert_rules(f'''
                    def fail(value):
                        raise ValueError(value)
                    try:
                        fail({value})
                    except ValueError as error:
                        eval(error.args[0])
                ''', *expected)

    def test_payload_reaches_return_through_a_handler_helper(self):
        self.assert_rules('''
            def fail(value):
                raise ValueError(value)
            def unwrap(value):
                try:
                    fail(value)
                except ValueError as error:
                    return error.args[0]
            eval(unwrap(input()))
        ''', 'eval')

    def test_sanitizer_on_exception_payload_keeps_its_domain(self):
        self.assert_rules('''
            def fail(value):
                raise ValueError(html.escape(value))
            try:
                fail(input())
            except ValueError as error:
                HttpResponse(error.args[0])
                cursor.execute(error.args[0])
        ''', 'sql')

    def test_no_sinks_after_a_nonreturning_call(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            stop()
            eval(input())
        ''')

    def test_no_sinks_on_the_terminated_try_continuation(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            try:
                stop()
                eval(input())
            except ValueError:
                pass
        ''')

    def test_argument_failure_prevents_the_outer_sink_call(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            def consume(value, ignored):
                eval(value)
            consume(input(), stop())
        ''')

    def test_callee_failure_prevents_argument_evaluation(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            stop()(eval(input()))
        ''')

    def test_argument_sinks_before_failure_are_preserved(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            unknown(eval(input()), stop(), eval(input()))
        ''', 'eval')

    def test_expression_failure_prevents_later_operands(self):
        for expression in ('stop() + eval(input())', '(stop(), eval(input()))',
                           'stop()[eval(input())]', 'eval(stop())'):
            with self.subTest(expression=expression):
                self.assert_rules("def stop():\n    raise ValueError('stop')\n" + expression)

    def test_conditional_expression_keeps_only_returning_alternatives(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            eval('safe' if condition else stop())
        ''')
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            eval(input() if condition else stop())
        ''', 'eval')

    def test_short_circuit_can_bypass_nonreturning_operand(self):
        self.assert_rules('''
            def stop():
                raise ValueError('stop')
            eval(input() or stop())
        ''', 'eval')

    def test_unknown_calls_are_not_assumed_to_terminate(self):
        self.assert_rules('unknown()\neval(input())', 'eval')

    def test_helper_sink_before_raise_still_reports(self):
        self.assert_rules('''
            def stop(value):
                eval(value)
                raise RuntimeError('stop')
            stop(input())
        ''', 'eval')

    def test_fallthrough_helpers_can_return_normally(self):
        self.assert_rules('def noop():\n    pass\nnoop()\neval(input())', 'eval')

    def test_conditional_callee_has_a_returning_alternative(self):
        self.assert_rules('''
            def stop(value):
                raise ValueError('stop')
            def identity(value):
                return value
            run = stop if condition else identity
            eval(run(input()))
        ''', 'eval')

    def test_finally_raise_cancels_the_normal_call_continuation(self):
        self.assert_rules('''
            def stop(value):
                try:
                    return value
                finally:
                    raise RuntimeError('stop')
            stop(input())
            eval(input())
        ''')

    def test_finally_return_cancels_the_exceptional_call_continuation(self):
        self.assert_rules('''
            def choose(value):
                try:
                    raise ValueError(value)
                finally:
                    return 'safe'
            try:
                eval(choose(input()))
            except ValueError as error:
                eval(error.args[0])
        ''')

    def test_output_mutation_reaches_exception_handler(self):
        self.assert_rules('''
            def fill_then_fail(target, value):
                target['code'] = value
                raise ValueError('stop')
            box = {}
            try:
                fill_then_fail(box, input())
            except ValueError:
                eval(box['code'])
        ''', 'eval')

    def test_throwing_mutation_does_not_leak_into_normal_continuation(self):
        self.assert_rules('''
            def maybe(target, value):
                if condition:
                    target['code'] = value
                    raise ValueError('stop')
                return 'ok'
            box = {}
            try:
                maybe(box, input())
                eval(box['code'])
            except ValueError:
                pass
        ''')

    def test_normal_mutation_does_not_leak_into_exception_handler(self):
        self.assert_rules('''
            def maybe(target, value):
                if condition:
                    target['code'] = value
                    return 'ok'
                raise ValueError('stop')
            box = {}
            try:
                maybe(box, input())
            except ValueError:
                eval(box['code'])
        ''')

    def test_cleanup_write_reaches_exception_handler(self):
        self.assert_rules('''
            def fail(target, value):
                try:
                    raise ValueError('stop')
                finally:
                    target['code'] = value
            box = {}
            try:
                fail(box, input())
            except ValueError:
                eval(box['code'])
        ''', 'eval')

    def test_infinite_loop_has_no_normal_call_continuation(self):
        self.assert_rules('''
            def spin():
                while True:
                    pass
            spin()
            eval(input())
        ''')

    def test_break_is_a_normal_exit_from_an_infinite_loop(self):
        self.assert_rules('''
            def finish():
                while True:
                    break
            finish()
            eval(input())
        ''', 'eval')

    def test_condition_failure_prevents_body_sinks(self):
        self.assert_rules('''
            def stop():
                raise RuntimeError('stop')
            if stop():
                eval(input())
        ''')


class RecursiveCompletionTests(SourceTest):
    def scan(self, source):
        script = ('import json,sys;sys.path.insert(0,sys.argv[1]);'
                  'from test_taint_python_dataflow import SourceTest;'
                  'print(json.dumps(SourceTest().scan(sys.stdin.read())))')
        result = subprocess.run([sys.executable, '-B', '-c', script, str(Path(__file__).resolve().parent)],
                                input=source, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_nonreturning_recursion_has_no_following_sink(self):
        self.assert_rules('def spin(value):\n    return spin(value)\nspin(input())\neval(input())')

    def test_mutual_recursion_can_raise_without_returning(self):
        self.assert_rules('''
            def first(value):
                return second(value)
            def second(value):
                if condition:
                    raise ValueError(value)
                return first(value)
            try:
                first(input())
                eval(input())
            except ValueError as error:
                eval(error.args[0])
        ''', 'eval')

    def test_deep_exception_summary_chain_has_no_depth_cutoff(self):
        functions = '\n'.join(f'def f{i}(value):\n    return f{i+1}(value)' for i in range(35))
        self.assert_rules(functions + '''

def f35(value):
    raise ValueError(value)
try:
    f0(input())
except ValueError as error:
    eval(error.args[0])
''', 'eval')

    def test_recursive_returning_alternative_still_propagates(self):
        self.assert_rules('''
            def choose(value):
                if condition:
                    return value
                return choose(value)
            eval(choose(input()))
        ''', 'eval')


class GeneratorResumeTests(SourceTest):
    def assert_sites(self, source, *lines):
        findings = self.scan(source)
        self.assertEqual(sorted((item['rule'], item['line']) for item in findings),
                         [('python.taint.eval', line) for line in sorted(lines)], findings)

    def test_terminal_yield_reads_the_resumption_global(self):
        for initial, final, expected in (("'fixed'", 'input()', (6,)),
                                         ('input()', "'fixed'", ())):
            with self.subTest(initial=initial, final=final):
                self.assert_sites(f'''
                    code = {initial}
                    def values():
                        yield code
                    iterator = values()
                    code = {final}
                    eval(iterator.__next__())
                ''', *expected)

    def test_immediate_predicates_bound_private_loop_capture_lifetime(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            for predicate in ('any(code.startswith(prefix) for prefix in ("a", "b"))',
                              'all(code.startswith(prefix) for prefix in ("a", "b"))',
                              'next((code for unused in [0]), "fixed")'):
                with self.subTest(value=value, predicate=predicate):
                    self.assert_rules('def run():\n    for code in [' + value + ']:\n'
                                      '        ' + predicate + '\n        eval(code)\nrun()\n', *expected)

    def test_immediate_predicates_do_not_trust_replaced_or_opaque_consumers(self):
        sources = (
            "def run(any):\n    for code in ['fixed']:\n        any(code for unused in [0])\n"
            "run(unknown)\n",
            "import builtins\nbuiltins.any=unknown\ndef run():\n    for code in ['fixed']:\n"
            "        any(code for unused in [0])\nrun()\n",
            "exec('import builtins; builtins.next=unknown')\ndef run():\n"
            "    for code in ['fixed']:\n        next((code for unused in [0]),None)\nrun()\n",
            "def run():\n    for code in ['fixed']:\n        next((code for unused in opaque()),None)\nrun()\n",
            "def run():\n    for code in ['fixed']:\n        next((code for unused in [0]),(code:=input()))\nrun()\n",
            "def run():\n    code='fixed'\n    def alter():\n        nonlocal code\n"
            "        code=input()\n    for code in ['fixed']:\n        any(alter() or code for unused in [0])\nrun()\n",
            "def run():\n    for code in ['fixed']:\n        saved=(code for unused in [0])\n"
            "    code=input()\n    eval(saved.__next__())\nrun()\n",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_immediate_private_reads_finish_before_later_local_stores(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            for iterable in ('"ab"', "b'ab'", '(0, 1)'):
                with self.subTest(value=value, iterable=iterable):
                    self.assert_rules('def run():\n    code=' + value + '\n    saved=code\n'
                                      '    any(code for unused in ' + iterable + ')\n'
                                      "    code='fixed'\n    eval(saved)\nrun()\n", *expected)
        # An immediately consumed tuple of primitive values has no delayed
        # reads or user truth callback. Its walrus write happens before any()
        # observes the nonempty tuple and short-circuits.
        source = ("def run():\n    code='fixed'\n"
                  "    any((code, (code:=input())) for unused in [0])\n"
                  "    eval(code)\nrun()\n")
        observed = []
        exec(source, {'input': lambda: 'UNTRUSTED', 'eval': observed.append})
        self.assertEqual(observed, ['UNTRUSTED'])
        self.assert_rules(source, 'eval')

    def test_stable_module_literals_survive_symbolic_function_environments(self):
        for literal in ('3', "('fixed', (2, None))"):
            with self.subTest(literal=literal):
                self.assert_rules('VALUE=' + literal + '\ndef run(code):\n'
                                  '    values=(VALUE for unused in [0])\n'
                                  '    for value in values:\n        eval(code)\nrun(input())\n', 'eval')
        self.assert_rules("VALUE=frozenset({'fixed', 'other'})\ndef run():\n"
                          "    values=(VALUE for unused in [0])\n    for value in values:\n        print(value)\nrun()\n")
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            self.scan("VALUE=(['fixed'],)\ndef run():\n    values=(VALUE[0][0] for unused in [0])\n"
                      "    VALUE[0][0]=input()\n    eval(values.__next__())\nrun()\n")

    def test_delayed_free_reads_respect_nested_comprehension_binders(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            with self.subTest(value=value):
                self.assert_rules("item='fixed'\ndef run(code):\n"
                                  "    values=((code, any(item for item in ('x', 'y'))) for outer in (0,))\n"
                                  "    for value in values:\n        eval(value[0])\nitem=input()\nrun(" + value + ")\n",
                                  *expected)
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            self.scan("items=['fixed']\nvalues=(any(item for item in items) for outer in [0])\n"
                      "items=[input()]\neval(values.__next__())\n")

    def test_dominating_unpack_assignment_establishes_delayed_local(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            with self.subTest(value=value):
                self.assert_rules('def run():\n    label, (code, other) = (None, (' + value + ', 0))\n'
                                  '    values=(code for unused in [0])\n'
                                  '    for value in values:\n        eval(value)\nrun()\n', *expected)
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            self.scan("def run():\n    label, code=(None, 'fixed')\n    values=(code for unused in [0])\n"
                      "    label, code=(None, input())\n    eval(values.__next__())\nrun()\n")

    def test_mutable_iterator_root_must_not_release_or_escape_members(self):
        for operation, prelude in (('values.clear()', ''), ('values.pop()', ''),
                                   ('alias.clear()', '        alias=values\n'),
                                   ('clear(values)', '')):
            source = ("code='fixed'\ntainted=input()\nclass Trigger:\n    def __del__(self):\n"
                      "        global code\n        code=tainted\ndef clear(items):\n    items.clear()\n"
                      "def run():\n    for unused in [0]:\n        values=[Trigger()]\n" + prelude +
                      '        any(' + operation + ' or item for item in values)\n    return eval(code)\nrun()\n')
            with self.subTest(operation=operation), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_immediate_consumers_do_not_ignore_user_truthiness_callbacks(self):
        for method, result in (('__bool__', 'True'), ('__len__', '1')):
            for consumer in ('any(value for unused in [0])', 'all(value for unused in [0])',
                             'next((unused for unused in [0] if value), None)'):
                source = ("command='fixed'\ntainted=input()\nclass Trigger:\n    def " + method + "(self):\n"
                          "        global command\n        command=tainted\n        return " + result + '\n'
                          'def run():\n    for value in [Trigger()]:\n        ' + consumer + '\n'
                          '    return eval(command)\nrun()\n')
                with self.subTest(method=method, consumer=consumer), self.assertRaisesRegex(
                        taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_truthiness_proof_preserves_captured_alias_and_target_scope(self):
        prefix = ("command='fixed'\ntainted=input()\nclass Trigger:\n    def __bool__(self):\n"
                  "        global command\n        command=tainted\n        return True\n")
        cases = (
            "def run():\n    for unused in [0]:\n        alias=Trigger()\n        code=alias\n"
            "        alias='fixed'\n        any(code for item in [0])\n    return eval(command)\nrun()\n",
            "def run():\n    values=(Trigger(),)\n    code='fixed'\n    for flag in [1]:\n"
            "        any(code for code in values if flag)\n    return eval(command)\nrun()\n",
            "def run():\n    values=((Trigger(),0),)\n    code='fixed'\n    for flag in [1]:\n"
            "        any(code for code, other in values if flag)\n    return eval(command)\nrun()\n",
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(prefix + source)

    def test_stable_helper_identity_does_not_snapshot_delayed_dependencies(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            with self.subTest(value=value):
                self.assert_rules('def run():\n    def identity(value):\n        return value\n'
                                  '    values=(identity(value) for value in [' + value + '])\n'
                                  '    for value in values:\n        eval(value)\nrun()\n', *expected)
        for source in (
            "code='fixed'\ndef read():\n    return code\nvalues=(read() for unused in [0])\n"
            "code=input()\neval(values.__next__())\n",
            "def run():\n    code='fixed'\n    def read():\n        return code\n"
            "    values=(read() for unused in [0])\n    code=input()\n    eval(values.__next__())\nrun()\n",
            "box=['fixed']\ndef read():\n    return box[0]\nvalues=(read() for unused in [0])\n"
            "box[0]=input()\neval(values.__next__())\n",
            "def read():\n    return 'fixed'\ndef other():\n    return input()\n"
            "values=(read() for unused in [0])\nread.__code__=other.__code__\neval(values.__next__())\n",
            "def run():\n    def read():\n        return 'fixed'\n    saved=read\n"
            "    values=(read() for unused in [0])\n    unknown(saved)\n    eval(values.__next__())\nrun()\n",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_argument_and_default_values_are_creation_time_snapshots(self):
        for initial, final, expected in (('input()', "'fixed'", (6,)),
                                         ("'fixed'", 'input()', ())):
            for signature, call in (('saved', 'values(code)'), ('saved=code', 'values()')):
                with self.subTest(initial=initial, default='=' in signature):
                    self.assert_sites(f'''
                        code = {initial}
                        def values({signature}):
                            yield saved
                        iterator = {call}
                        code = {final}
                        eval(iterator.__next__())
                    ''', *expected)

    def test_aliases_share_exhaustion_without_a_normal_else_path(self):
        self.assert_sites('''
            code = input()
            def values():
                yield code
            iterator = values()
            alias = iterator
            iterator.__next__()
            try:
                alias.__next__()
            except StopIteration:
                eval(code)
            else:
                eval(code)
        ''', 10)

    def test_branch_join_retains_created_and_suspended_continuations(self):
        self.assert_sites('''
            code = input()
            def values():
                yield code
            iterator = values()
            if flag:
                iterator.__next__()
            try:
                eval(iterator.__next__())
            except StopIteration:
                eval(code)
        ''', 8, 10)

    def test_returned_instances_have_distinct_cursors(self):
        self.assert_sites('''
            code = 'fixed'
            def values():
                yield code
            def factory():
                return values()
            first = factory()
            second = factory()
            first.__next__()
            code = input()
            eval(second.__next__())
            try:
                first.__next__()
            except StopIteration:
                pass
            else:
                eval(input())
        ''', 10)

    def test_returned_next_method_preserves_its_instance(self):
        self.assert_sites('''
            code = 'fixed'
            def values():
                yield code
            def factory():
                return values().__next__
            advance = factory()
            code = input()
            eval(advance())
            try:
                advance()
            except StopIteration:
                pass
            else:
                eval(code)
        ''', 8)

    def test_missing_name_failure_occurs_on_first_resume(self):
        self.assert_sites('''
            def values():
                yield missing
            iterator = values()
            try:
                iterator.__next__()
            except NameError:
                eval(input())
            else:
                eval(input())
        ''', 7)

    def test_for_uses_its_original_instance_and_exhausts_it(self):
        self.assert_sites('''
            code = input()
            def values():
                yield code
            iterator = values()
            original = iterator
            for value in iterator:
                iterator = None
                eval(value)
            try:
                original.__next__()
            except StopIteration:
                eval(code)
            else:
                eval(code)
        ''', 8, 12)
        self.assert_sites('''
            code = input()
            def values():
                yield code
            def factory():
                return values()
            for value in factory():
                eval(value)
        ''', 7)

    def test_break_leaves_the_cursor_suspended(self):
        self.assert_sites('''
            code = 'fixed'
            def values():
                yield code
            iterator = values()
            for value in iterator:
                break
            code = input()
            try:
                iterator.__next__()
            except StopIteration:
                eval(code)
            else:
                eval(code)
        ''', 11)

    def test_inert_string_proof_does_not_sanitize_its_contents(self):
        for actual, expected in (('input()', ('command',)), ("'echo fixed'", ())):
            with self.subTest(actual=actual):
                self.assert_rules(f'''
                    import os
                    def values(value):
                        yield value
                    for command in values({actual}):
                        os.system(command)
                ''', *expected)

    def test_unsupported_protocols_keep_explicit_incompleteness(self):
        sources = (
            "code='fixed'\ndef values():\n    yield code\n    yield code\n"
            "g=values()\ncode=input()\neval(g.__next__())\n",
            "code='fixed'\ndef read(): return code\ndef values():\n    yield read()\n"
            "g=values()\ncode=input()\neval(g.__next__())\n",
            "code='fixed'\ng=(code for unused in [0])\ncode=input()\neval(g.__next__())\n",
            "def run():\n    code='fixed'\n    g=(code for unused in [0])\n"
            "    code=input()\n    eval(g.__next__())\nrun()\n",
            "def values():\n    yield 'fixed'\ng=values()\nlist(g)\n",
            "def values():\n    yield 'fixed'\ng=values()\nnext(g)\n",
            "def values():\n    yield 'fixed'\ng=values()\n[g]\n",
            "def values():\n    yield 'fixed'\ng=values()\na,b=g\n",
            "def values():\n    yield 'fixed'\ng=values()\n[x for x in g]\n",
            "def values():\n    yield 'fixed'\ng=values()\nother == g\n",
            "def values():\n    yield 'fixed'\ng=values()\ng.send(None)\n",
            "def values():\n    yield 'fixed'\ndef relay():\n    yield from values()\nrelay()\n",
            "def values(value):\n    yield value\nvalues()\n",
            "def values(value):\n    yield value\nvalues('fixed',value='other')\n",
            "def values(value):\n    yield value\nvalues(*unknown)\n",
        )
        for source in sources:
            with self.subTest(source=source):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)
        self.assert_sites("code='fixed'\ng=(item for item in [code])\ncode=input()\neval(g.__next__())\n")

    def test_live_global_mutation_channel_does_not_use_an_eager_fallback(self):
        source = '''
            eval(input())
            code = 'fixed'
            def add(box):
                box.append(code)
            def values(box):
                add(box)
                yield 'fixed'
            box = []
            iterator = values(box)
            code = input()
            for unused in iterator:
                pass
            eval(box[0])
        '''
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete') as raised:
            taint_py._Analysis(ast.parse(textwrap.dedent(source))).analyze()
        self.assertIn(('eval', 2, 1), {key[:3] for key in raised.exception.effects})

    def test_a_single_later_global_initialization_is_not_stable(self):
        for declaration in (
            "def values():\n    yield code\n    yield code\ng=values()\n",
            "def read(): return code\ndef values():\n    yield read()\ng=values()\n",
            "g=(code for unused in [0])\n",
        ):
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(declaration + "code=input()\neval(g.__next__())\n")

    def test_stable_generator_expression_bindings_use_their_lexical_owner(self):
        for value, expected in (('input()', ('eval',)), ("'fixed'", ())):
            for body in ("def run(value):\n    g=(value for unused in [0])\n    eval(g.__next__())\nrun(VALUE)\n",
                         "def run():\n    value=VALUE\n    g=(value for unused in [0])\n"
                         "    eval(g.__next__())\nrun()\n"):
                source = "def unrelated():\n    value='one'\n    value='two'\n" + body.replace('VALUE', value)
                with self.subTest(value=value, body=body):
                    self.assert_rules(source, *expected)
        for source in (
            "def run():\n    value='fixed'\n    def replace():\n        nonlocal value\n"
            "        value=input()\n    g=(value for unused in [0])\n    replace()\n"
            "    eval(g.__next__())\nrun()\n",
            "def run():\n    for unused in [0,1]:\n        value=input()\n"
            "        g=(value for item in [0])\n    eval(g.__next__())\nrun()\n",
        ):
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_direct_for_borrows_only_an_independently_retained_module_list(self):
        for actual, expected in (('input()', (6,)), ("'fixed'", ())):
            self.assert_sites("def values(box):\n    yield box\nbox=[]\n"
                              "for alias in values(*[box]):\n    alias.append(" + actual + ")\n"
                              "eval(box[0])\n", *expected)
        sources = (
            "def values(box):\n    yield box\nbox=[]\ng=values(box)\n",
            "def values(box):\n    yield box\ndef run():\n    box=[]\n"
            "    for alias in values(box):\n        alias.append(input())\nrun()\n",
            "def values(box):\n    yield box\nbox=[]\nfor alias in values(box):\n    del box\n",
            "def values(box):\n    yield box\nbox=[]\ndef replace():\n    global box\n"
            "    box=None\nfor alias in values(box):\n    replace()\n",
            "def values(box):\n    yield box\nbox=[]\nfor alias in values(box):\n"
            "    globals()['box']=None\n",
            "def values(box):\n    yield box\nbox=[]\nfor box in values(box):\n    pass\n",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_dynamic_loader_cannot_certify_an_inert_input_capture(self):
        source = '''
            import importlib as loader
            code = 'fixed'
            tainted = input()
            class Value(str):
                def __del__(self):
                    global code
                    code = tainted
            class Reader:
                def readline(self):
                    return Value('value')
            setattr(loader.import_module('s' + 'ys'), 'std' + 'in', Reader())
            def values(payload):
                yield None
            iterator = values(input())
            iterator = None
            eval(code)
        '''
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'captured value lifetime.*incomplete'):
            self.scan(source)

    def test_frame_capabilities_revoke_local_and_module_root_proofs(self):
        readonly = ("import sys as runtime\nimport os\ndef stack_filename():\n"
                    "    frame=runtime._getframe()\n    return frame.f_code.co_filename\n"
                    "def run(code):\n    g=(code for unused in [0])\n"
                    "    os.system(g.__next__())\nrun(input())\n")
        self.assert_rules(readonly, 'command')
        for replacement in ("runtime=unknown\n", "alias=runtime\nalias._getframe=unknown\n",
                            "runtime.__dict__['_getframe']=unknown\n"):
            with self.subTest(replacement=replacement):
                source = readonly.replace('import os\n', 'import os\n' + replacement)
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)
        for acquisition, call in (("import sys", 'sys._getframe()'),
                                  ("import inspect", 'inspect.currentframe()'),
                                  ("from sys import _getframe as frame", 'frame()'),
                                  ("from inspect import currentframe as frame", 'frame()')):
            with self.subTest(acquisition=acquisition):
                source = acquisition + "\ndef run():\n    code='fixed'\n"
                source += "    g=(code for unused in [0])\n    frame=" + call + "\n"
                source += "    getattr(frame,'f_'+'locals')['code']=input()\n    eval(g.__next__())\nrun()\n"
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)
                source = acquisition + "\ndef values(box):\n    yield None\nbox=[]\n"
                source += "for unused in values(box):\n    frame=" + call + "\n"
                source += "    del getattr(frame,'f_'+'globals')['box']\n"
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'captured value lifetime.*incomplete'):
                    self.scan(source)

    def test_borrowed_root_proof_covers_dynamic_execution_and_helper_aliases(self):
        prefix = ("code='fixed'\ntainted=input()\nclass Trigger:\n    def __del__(self):\n"
                  "        global code\n        code=tainted\ndef values(box):\n    yield None\nbox=[Trigger()]\n")
        for helper, action in (
            ('', "exec('del box')"),
            ('', "eval(\"globals().pop('box')\")"),
            ('execute=exec\n', "execute('del box')"),
            ("def remove():\n    exec('del box', globals())\n", 'remove()'),
            ("execute=exec\ndef remove(action):\n    action('del box')\n", 'remove(execute)'),
        ):
            source = prefix + helper + 'for unused in values(box):\n    ' + action + '\neval(code)\n'
            with self.subTest(action=action), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_default_builtin_and_lifetime_mutations_are_not_trusted(self):
        sources = (
            "import builtins\ndef values():\n    yield input\ng=values()\n"
            "builtins.input=eval\ng.__next__()(request.args['x'])\n",
            "def helper(): pass\ndef values():\n    yield input\ng=values()\n"
            "helper.__builtins__['input']=eval\ng.__next__()(request.args['x'])\n",
            "def values(saved='fixed'):\n    yield saved\nvalues.__defaults__=(input(),)\n"
            "g=values()\neval(g.__next__())\n",
            "def values(saved='fixed'):\n    yield saved\nsetattr(values,'__defaults__',(input(),))\n"
            "g=values()\neval(g.__next__())\n",
            "def values(*,saved='fixed'):\n    yield saved\nvalues.__kwdefaults__={'saved':input()}\n"
            "g=values()\neval(g.__next__())\n",
            "def values():\n    yield 'fixed'\ndef other():\n    yield input()\n"
            "values.__code__=other.__code__\ng=values()\neval(g.__next__())\n",
            "code='fixed'\nclass Finalizer:\n    def __del__(self):\n        global code\n"
            "        code=input()\ndef values(payload):\n    yield None\n"
            "g=values(Finalizer())\ng=None\neval(code)\n",
            "import sys\ncode='fixed'\nclass Value(str):\n    def __del__(self):\n"
            "        global code\n        code='tainted'\nclass Reader:\n"
            "    def readline(self): return Value('value')\nsys.stdin=Reader()\n"
            "def values(payload):\n    yield 'fixed'\ng=values(input())\ng=None\neval(code)\n",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)


class GeneratorProjectTests(unittest.TestCase):
    def project(self, sources):
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'generator-followup'
        artifacts.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='project-', dir=artifacts))
        files = []
        for name, source in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding='utf-8')
            files.append(path)
        return taint_py._Project(files, root)

    def test_mutated_defining_module_cannot_keep_stale_callable_identity(self):
        library = "selected=print\ndef values():\n    yield selected\n"
        for replacement in ('lib.selected=eval', 'alias=lib\nalias.selected=eval'):
            with self.subTest(replacement=replacement):
                project = self.project({'lib.py': library, 'app.py':
                    "import lib\ng=lib.values()\n" + replacement + "\ng.__next__()(input())\n"})
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'defining module namespace.*incomplete'):
                    list(project.findings())
        project = self.project({'lib.py': library, 'app.py':
            "import lib\ng=lib.values()\ng.__next__()(input())\n"})
        self.assertEqual(list(project.findings()), [])

    def test_unrelated_namespace_use_does_not_revoke_a_module_binding(self):
        for value, expected in (('input()', [('app.py', 'py.taint.eval', 7)]), ("'fixed'", [])):
            with self.subTest(value=value):
                project = self.project({
                    'app.py': "import sys\ncode=" + value + "\ndef values():\n"
                              "    yield {'value':code}\nfor item in values():\n"
                              "    selected=item['value']\n    eval(selected)\n",
                    'unrelated.py': 'import sys\nnamespace=globals()\n',
                })
                self.assertEqual([(path.name, rule, line) for path, rule, line, _col, _message in project.findings()],
                                 expected)

    def test_importer_cannot_mutate_a_delayed_owner_namespace(self):
        library = "code='fixed'\ndef values():\n    yield {'value':code}\n"
        for mutation in ('lib.code=input()', "lib.values.__globals__['code']=input()"):
            with self.subTest(mutation=mutation):
                project = self.project({'lib.py': library,
                    'app.py': "import lib\ng=lib.values()\n" + mutation + "\nfor item in g:\n    eval(item['value'])\n"})
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    list(project.findings())

    def test_related_dynamic_execution_invalidates_immediate_builtin_identity(self):
        helper = ("saved=[]\ndef install():\n"
                  "    exec('import builtins; builtins.any=lambda value: saved.append(value) or False')\n")
        app = ("import helper\nhelper.install()\ndef run():\n"
               "    for code in ['fixed', input()]:\n        any(code for unused in [0])\n"
               "    return eval(helper.saved[0].__next__())\nrun()\n")
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            list(self.project({'helper.py': helper, 'app.py': app}).findings())
        project = self.project({'unrelated.py': helper, 'app.py':
            "def run():\n    for code in ['fixed']:\n        any(code for unused in [0])\nrun()\n"})
        self.assertEqual(list(project.findings()), [])

    def test_related_namespace_mapping_invalidates_immediate_builtin_identity(self):
        for prefix, target in (("import builtins\n", "builtins.__dict__"),
                               ("import builtins\nnamespace=builtins.__dict__\n", 'namespace')):
            helper = prefix + 'saved=[]\ndef install():\n    ' + target + \
                "['any']=lambda value: saved.append(value) or False\n"
            app = ("import helper\nhelper.install()\ndef run():\n"
                   "    for code in ['fixed', input()]:\n        any(code for unused in [0])\n"
                   "    return eval(helper.saved[0].__next__())\nrun()\n")
            with self.subTest(target=target), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                list(self.project({'helper.py': helper, 'app.py': app}).findings())
            unrelated = self.project({'unrelated.py': helper, 'app.py':
                "def run():\n    for code in ['fixed']:\n        any(code for unused in [0])\nrun()\n"})
            self.assertEqual(list(unrelated.findings()), [])

    def test_ambiguous_module_keys_do_not_hide_selected_engines(self):
        project = self.project({
            'ambiguous.py': "VALUE='fixed'\n",
            'ambiguous/__init__.py': "VALUE='fixed'\n",
            'app.py': "def values(value):\n    yield value\ng=values(input())\neval(g.__next__())\n",
        })
        findings = list(project.findings())
        self.assertEqual([(path.name, rule, line) for path, rule, line, _col, _message in findings],
                         [('app.py', 'py.taint.eval', 4)])
        project = self.project({
            'ambiguous.py': "VALUE='fixed'\n",
            'ambiguous/__init__.py': "import builtins\nbuiltins.input=eval\n",
            'app.py': "def values():\n    yield input\ng=values()\ng.__next__()(request.args['x'])\n",
        })
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'builtin binding.*incomplete'):
            list(project.findings())


class NextGeneratorCompletionTests(SourceTest):
    def assert_native(self, source, expected_values):
        source = textwrap.dedent(source).lstrip('\n')
        observed = []

        def record(value):
            observed.append((sys._getframe(1).f_lineno, value))

        exec(compile(source, '<next-generator-witness>', 'exec'),
             {'input': lambda: 'UNTRUSTED', 'eval': record})
        self.assertEqual([value for _line, value in observed], expected_values)
        self.assertEqual(sorted((item['rule'], item['line']) for item in self.scan(source)),
                         [('python.taint.eval', line) for line in sorted({
                             line for line, value in observed if 'UNTRUSTED' in str(value)})])

    def test_first_yield_preserves_result_and_last_executed_write(self):
        cases = (("['fixed', input()]", ['fixed', 'fixed']),
                 ("[input(), 'fixed']", ['UNTRUSTED', 'UNTRUSTED']),
                 ("['', input()]", ['', '']),
                 ('[]', ['fallback', 'before']))
        for values, expected in cases:
            with self.subTest(values=values):
                self.assert_native("code = 'before'\n"
                                   f"chosen = next(((code := value) for value in {values}), 'fallback')\n"
                                   "eval(chosen)\neval(code)\n", expected)

    def test_default_runs_before_resume_but_after_outer_iterable_capture(self):
        cases = (("code for unused in [0]", ['UNTRUSTED', 'UNTRUSTED']),
                 ("value for value in [code]", ['fixed', 'UNTRUSTED']),
                 ("value for unused in [0] for value in [code]", ['UNTRUSTED', 'UNTRUSTED']))
        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.assert_native("code = 'fixed'\n"
                                   f"chosen = next(({expression}), (code := input()))\n"
                                   "eval(chosen)\neval(code)\n", expected)
        for values, expected in (("['fixed']", ['fixed']), ('[]', ['UNTRUSTED'])):
            with self.subTest(values=values):
                self.assert_native(f'eval(next((value for value in {values}), input()))\n', expected)

    def test_default_helpers_preserve_creation_and_resumption_values(self):
        for initial, replacement in (('input()', "'fixed'"), ("'fixed'", 'input()')):
            for expression in ('code for unused in [0]', 'value for value in [code]'):
                final = 'UNTRUSTED' if replacement == 'input()' else 'fixed'
                captured = 'UNTRUSTED' if initial == 'input()' else 'fixed'
                expected = final if expression.startswith('code ') else captured
                with self.subTest(initial=initial, expression=expression):
                    self.assert_native(f'code = {initial}\ndef fallback():\n'
                                       f'    global code\n    code = {replacement}\n    return "fallback"\n'
                                       f'chosen = next(({expression}), fallback())\n'
                                       'eval(chosen)\neval(code)\n', [expected, final])

    def test_filters_nested_clauses_and_targets_keep_their_own_effects(self):
        self.assert_native("code = input()\n"
                           "next(((code := value) for value in ['fixed', input()] for inner in [0, 1]), 'fallback')\n"
                           "eval(code)\n", ['fixed'])
        self.assert_native("code = input()\n"
                           "eval(next((value for value in [input()] if (code := '')), 'fallback'))\n"
                           "eval(code)\n", ['fallback', ''])
        self.assert_native("eval(next((value for value in [input()] for unused in []), 'fallback'))\n", ['fallback'])
        self.assert_native("value = input()\neval(next(value for value in ['fixed']))\neval(value)\n",
                           ['fixed', 'UNTRUSTED'])
        self.assert_native("eval(next(value for value in ['', input()] if value))\n", ['UNTRUSTED'])

    def test_exhaustion_selects_only_the_correct_continuation(self):
        cases = (
            ("next(value for value in [])", 'StopIteration', ['UNTRUSTED']),
            ("next((value for value in []), 'fallback')", 'StopIteration', []),
            ("next(value for value in ['fixed'])", 'StopIteration', []),
        )
        for expression, handler, expected in cases:
            with self.subTest(expression=expression):
                self.assert_native(f'try:\n    {expression}\nexcept {handler}:\n    eval(input())\n', expected)
        self.assert_native("try:\n    next(value for value in [])\n    eval(input())\n"
                           "except StopIteration:\n    pass\n", [])

    def test_conditional_and_boolean_yields_skip_unselected_effects(self):
        for expression in ("'fixed' if True else (code := input())",
                           "(code := input()) if False else 'fixed'",
                           "True or (code := input())", "False and (code := input())"):
            with self.subTest(expression=expression):
                self.assert_native("code = 'fixed'\n"
                                   f"next(({expression} for unused in [0]), 'fallback')\n"
                                   "eval(code)\n", ['fixed'])
        self.assert_native("code = input()\n"
                           "next(('fixed' if True else (code := 'fixed') for unused in [0]), 'fallback')\n"
                           "eval(code)\n", ['UNTRUSTED'])
        self.assert_native("eval(next((input() if True else 'fixed' for unused in [0]), 'fallback'))\n",
                           ['UNTRUSTED'])

    def test_primitive_helper_arguments_preserve_global_and_nonlocal_writes(self):
        for signature, call in (('value', 'replace(value)'), ('*, value', 'replace(value=value)')):
            with self.subTest(signature=signature):
                self.assert_native(f"code = 'fixed'\ndef replace({signature}):\n"
                                   "    global code\n    code = value\n    return value\n"
                                   f"chosen = next(({call} for value in [input(), 'fixed']), 'fallback')\n"
                                   "eval(chosen)\neval(code)\n", ['UNTRUSTED', 'UNTRUSTED'])
        self.assert_native('''
            def run():
                code = 'fixed'
                def replace(value):
                    nonlocal code
                    code = value
                    return value
                chosen = next((replace(value) for value in [input(), 'fixed']), 'fallback')
                eval(chosen)
                eval(code)
            run()
        ''', ['UNTRUSTED', 'UNTRUSTED'])

    def test_generator_and_eager_default_exceptions_remain_distinct(self):
        for expression, actual in (('next((fail() for unused in [0]), "fallback")', 'RuntimeError'),
                                   ('next(("fixed" for unused in [0]), fail())', 'StopIteration')):
            for handler in ('RuntimeError', 'StopIteration'):
                other = 'StopIteration' if handler == 'RuntimeError' else 'RuntimeError'
                with self.subTest(expression=expression, handler=handler):
                    self.assert_native("code = 'fixed'\ndef fail():\n"
                                       "    global code\n    code = input()\n    raise StopIteration('stop')\n"
                                       f'try:\n    {expression}\nexcept {handler}:\n    eval(code)\n'
                                       f'except {other}:\n    pass\n', ['UNTRUSTED'] if actual == handler else [])
        self.assert_native("code = 'fixed'\ndef fallback():\n    raise ValueError('stop')\n"
                           "try:\n    next(((code := input()) for unused in [0]), fallback())\n"
                           "except ValueError:\n    eval(code)\n", ['fixed'])

    def test_native_aliases_keep_first_value_selection(self):
        for declaration, consumer in (('', 'next'), ('consume = next\n', 'consume'),
                                      ('from builtins import next as consume\n', 'consume'),
                                      ('import builtins\n', 'builtins.next'),
                                      ('import builtins as native\n', 'native.next')):
            with self.subTest(declaration=declaration):
                self.assert_native(declaration + f"eval({consumer}(value for value in ['fixed', input()]))\n", ['fixed'])
                self.assert_native(declaration + f"eval({consumer}(value for value in [input(), 'fixed']))\n", ['UNTRUSTED'])

    def test_builtin_string_bytes_and_set_iterators_preserve_primitive_values(self):
        cases = (("'ab'", 'a'), ("b'ab'", 97), ("b'\\x00\\x01'", 0),
                 ("{'fixed'}", 'fixed'), ('{0}', 0), ('{False}', False))
        for iterable, first in cases:
            with self.subTest(iterable=iterable):
                self.assert_native(f"eval(next((value for value in {iterable}), input()))\n", [first])
        self.assert_native("letters = 'ab'\neval(next(value for value in letters))\n", ['a'])
        for iterable in ("''", "b''"):
            with self.subTest(empty=iterable):
                self.assert_native(f'eval(next((value for value in {iterable}), input()))\n', ['UNTRUSTED'])
                self.assert_native(f'try:\n    next(value for value in {iterable})\n    eval(input())\n'
                                   'except StopIteration:\n    pass\n', [])
        for iterable in ("{'first', 'second'}", '{0, 1}', '{0, 1.5}'):
            with self.subTest(unordered=iterable):
                # Set order is not a source-order guarantee. These effects are
                # the same for every possible first member of the set.
                self.assert_native("code = 'fixed'\n"
                                   f"next(((code := input()) for value in {iterable}), 'fallback')\n"
                                   'eval(code)\n', ['UNTRUSTED'])
                self.assert_rules(f'eval(next(value for value in {iterable}))\n')

    def test_computed_consumer_factories_cannot_hide_finalizers(self):
        prefix = ("code = 'fixed'\nclass Release:\n    def __del__(self):\n"
                  "        global code\n        code = input()\ndef choose():\n"
                  "    owned = Release()\n    return next\n")
        for call in ("chosen = choose()(code for unused in [0])\n",
                     "consume = choose()\nchosen = consume(code for unused in [0])\n"):
            source = prefix + call + 'eval(chosen)\n'
            with self.subTest(call=call):
                observed = []
                exec(source, {'input': lambda: 'UNTRUSTED', 'eval': observed.append})
                self.assertEqual(observed, ['UNTRUSTED'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_opaque_iterators_defaults_and_frame_lifetimes_remain_incomplete(self):
        sources = (
            "def run(items):\n    next((value for value in items), 'fixed')\n",
            "async def run(items):\n    next((value async for value in items), 'fixed')\n",
            "def run(default):\n    next((value for value in ['fixed']), default)\n",
            "class Release:\n    def __del__(self):\n        print('cleanup')\n"
            "next((value for value in [Release()]), 'fixed')\n",
            "class Release:\n    def __del__(self):\n        print('cleanup')\n"
            "def fallback():\n    owned = Release()\n    return 'fixed'\n"
            "next((value for value in ['fixed']), fallback())\n",
            "values = ['fixed']\nnext((value for value in values), values.clear())\n",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_changed_builtin_next_cannot_certify_any_call_shape_clean(self):
        sources = (
            "import builtins\nbuiltins.next = lambda values: input()\n"
            "eval(builtins.next(value for value in ['fixed']))\n",
            "import builtins as native\nnative.next = lambda values: input()\n"
            "eval(native.next(value for value in ['fixed']))\n",
            "import builtins\nbuiltins.next = lambda values: input()\n"
            "consume = builtins.next\neval(consume(value for value in ['fixed']))\n",
            "import builtins\nbuiltins.next = lambda values: input()\n"
            "values = (value for value in ['fixed'])\neval(builtins.next(values))\n",
            "import builtins\nbuiltins.next = lambda values: input()\n"
            "eval(builtins.next(iter(['fixed'])))\n",
            "import builtins\nbuiltins.next = lambda *, values: input()\n"
            "eval(builtins.next(values=(value for value in ['fixed'])))\n",
            "import builtins\nbuiltins.next = lambda: input()\neval(builtins.next())\n",
            "namespace = vars(next.__self__)\nnamespace['next'] = lambda values: input()\n"
            "eval(next(value for value in ['fixed']))\n",
            "import builtins\nbuiltins.__dict__['next'] = lambda values: input()\n"
            "eval(builtins.next(value for value in ['fixed']))\n",
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)
        self.assert_rules("def next(values):\n    return input()\n"
                          "eval(next(value for value in ['fixed']))\n", 'eval')

    def test_wildcard_imports_can_replace_native_consumers_and_module_aliases(self):
        cases = (('', 'next'), ('consume = next\n', 'consume'),
                 ('from builtins import next as consume\n', 'consume'),
                 ('import builtins as native\n', 'native.next'))
        for declaration, consumer in cases:
            source = (declaration + 'from consumer_exports import *\n'
                      "code = input()\n"
                      f"{consumer}((code := 'fixed') for unused in [0])\n"
                      'eval(code)\n')
            with self.subTest(declaration=declaration):
                # The external module supplies a consumer that never resumes
                # the generator. Its exported module alias is equally opaque.
                witness = ('import sys, types\n'
                           "exports = types.ModuleType('consumer_exports')\n"
                           "exports.next = exports.consume = lambda values: 'skipped'\n"
                           'exports.native = types.SimpleNamespace(next=exports.next)\n'
                           "sys.modules['consumer_exports'] = exports\n"
                           f"exec({source!r}, {{'input': lambda: 'UNTRUSTED', 'eval': print}})\n")
                native = subprocess.run([sys.executable, '-B', '-c', witness],
                                        capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(native.stdout, 'UNTRUSTED\n')
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def native_system_calls(self, source):
        # Each witness has its own builtin namespace. The executable sink is
        # recorded, so the fixture never runs a supplied shell command.
        witness = ("import builtins, os\nbuiltins.input = lambda: 'UNTRUSTED'\n"
                   'os.system = print\n' + source)
        native = subprocess.run([sys.executable, '-B', '-c', witness],
                                capture_output=True, text=True, timeout=10, check=True)
        return native.stdout.splitlines()

    def test_literal_eval_namespace_mutation_invalidates_repeated_consumers(self):
        mutation = "__import__('builtins').__dict__.__setitem__('next', lambda values: input())"
        bodies = (
            "chosen = next(value for value in ['fixed'])\n",
            "consume = next\nchosen = consume(value for value in ['fixed'])\n",
            "pending = (value for value in ['fixed'])\nchosen = next(pending)\n",
            "chosen = native.next(value for value in ['fixed'])\n",
        )
        cases = []
        for body in bodies:
            prefix = 'import builtins as native\n' if 'native.next' in body else ''
            statements = body + f'eval({mutation!r})\nos.system(chosen)\n'
            cases.append(prefix + 'for unused in [0, 1]:\n' + textwrap.indent(statements, '    '))
        cases.append('count = 0\nwhile count < 2:\n    count += 1\n'
                     "    chosen = next(value for value in ['fixed'])\n"
                     f'    eval({mutation!r})\n    os.system(chosen)\n')
        cases.append("def run():\n    chosen = next(value for value in ['fixed'])\n"
                     f'    eval({mutation!r})\n    os.system(chosen)\nrun()\nrun()\n')
        for body in cases:
            source = 'import os\n' + body
            with self.subTest(body=body):
                self.assertEqual(self.native_system_calls(source), ['fixed', 'UNTRUSTED'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'consumer identity.*incomplete'):
                    self.scan(source)

    def test_literal_execution_handles_bytes_nested_calls_and_binding_writes(self):
        mutation = "__import__('builtins').__dict__.__setitem__('next', lambda values: input())"
        expressions = (repr(mutation), repr(mutation.encode()), repr(' \t' + mutation + '\t '),
                       repr(b' \t' + mutation.encode() + b'\t '),
                       repr(f'eval({mutation!r})'), repr(f'eval({mutation.encode()!r})'),
                       repr('(next := lambda values: input())'))
        for expression in expressions:
            source = ("import os\nfor unused in [0, 1]:\n"
                      "    chosen = next(value for value in ['fixed'])\n"
                      f'    eval({expression})\n    os.system(chosen)\n')
            with self.subTest(expression=expression):
                self.assertEqual(self.native_system_calls(source), ['fixed', 'UNTRUSTED'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'consumer identity.*incomplete'):
                    self.scan(source)
        source = ("import os\nconsume = next\nfor unused in [0, 1]:\n"
                  "    chosen = consume(value for value in ['fixed'])\n"
                  "    eval('(consume := lambda values: input())')\n    os.system(chosen)\n")
        self.assertEqual(self.native_system_calls(source), ['fixed', 'UNTRUSTED'])
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'consumer identity.*incomplete'):
            self.scan(source)

    def test_literal_code_data_and_harmless_execution_keep_native_consumers(self):
        mutation = "__import__('builtins').__dict__.__setitem__('next', lambda values: input())"
        for code in ('1 + 2', ' \t1 + 2\t ', "'builtins'", repr(mutation),
                     '[value for value in [1]]', "b'__import__'"):
            source = ("import os\nfor unused in [0, 1]:\n"
                      "    chosen = next(value for value in ['fixed'])\n"
                      f'    eval({code!r})\n    os.system(chosen)\n')
            with self.subTest(code=code):
                self.assertEqual(self.native_system_calls(source), ['fixed', 'fixed'])
                self.assert_rules(source)
        source = (f'payload = {mutation!r}\n'
                  "import os\nfor unused in [0, 1]:\n"
                  "    os.system(next(value for value in ['fixed']))\n")
        self.assertEqual(self.native_system_calls(source), ['fixed', 'fixed'])
        self.assert_rules(source)

    def test_literal_authority_inspection_limits_cannot_certify_mutation_clean(self):
        mutation = "__import__('builtins').__dict__.__setitem__('next', lambda values: input())"
        for code in (mutation + ' ' * 65_536, '(' + '0,' * 4_500 + mutation + ')'):
            source = ("import os\nfor unused in [0, 1]:\n"
                      "    chosen = next(value for value in ['fixed'])\n"
                      f'    eval({code!r})\n    os.system(chosen)\n')
            with self.subTest(length=len(code)):
                self.assertEqual(self.native_system_calls(source), ['fixed', 'UNTRUSTED'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'consumer identity.*incomplete'):
                    self.scan(source)

    def test_malformed_literal_execution_preserves_independent_findings(self):
        for consumer in ('eval', 'exec'):
            for code in ('\ud800', b'\xff', 'value\x00'):
                source = 'import os\nos.system(input())\n'
                expected = ['UNTRUSTED']
                if consumer == 'eval':
                    source += "os.system(next(value for value in ['fixed']))\n"
                    expected.append('fixed')
                source += (f'try:\n    {consumer}({code!r})\n'
                           'except (SyntaxError, UnicodeError):\n    pass\n')
                with self.subTest(consumer=consumer, code=repr(code)):
                    self.assertEqual(self.native_system_calls(source), expected)
                    self.assert_rules(source, 'command')


class PredicateGeneratorCompletionTests(SourceTest):
    def test_short_circuit_keeps_the_last_executed_write(self):
        cases = (
            ('any', "['fixed', input()]", 'fixed', False),
            ('any', "['', input()]", 'UNTRUSTED', True),
            ('all', "['', input()]", '', False),
            ('all', "['fixed', input()]", 'UNTRUSTED', True),
            ('any', '[]', 'UNTRUSTED', True),
            ('all', '[]', 'UNTRUSTED', True),
        )
        for consumer, values, final, unsafe in cases:
            source = ("code = input()\n"
                      f"{consumer}((code := value) for value in {values})\n"
                      "eval(code)\n")
            with self.subTest(consumer=consumer, values=values):
                observed = []
                exec(source, {'input': lambda: 'UNTRUSTED', 'eval': observed.append})
                self.assertEqual(observed, [final])
                self.assertEqual([(item['rule'], item['line']) for item in self.scan(source)],
                                 [('python.taint.eval', 3)] if unsafe else [])

    def test_boolean_results_are_not_executable_input(self):
        for consumer in ('any', 'all'):
            with self.subTest(consumer=consumer):
                self.assert_rules(f'''
                    code = 'fixed'
                    accepted = {consumer}((code := input()) for unused in [0])
                    eval(accepted)
                    eval(code)
                ''', 'eval')

    def test_nonempty_primitive_containers_short_circuit_without_testing_items(self):
        for expression in ('((code := value),)', '[(code := value)]'):
            source = ("code = input()\n"
                      f"any({expression} for value in ['fixed', input()])\n"
                      "eval(code)\n")
            with self.subTest(expression=expression):
                observed = []
                exec(source, {'input': lambda: 'UNTRUSTED', 'eval': observed.append})
                self.assertEqual(observed, ['fixed'])
                self.assert_rules(source)

    def test_skipped_filters_and_nested_clauses_preserve_order(self):
        for consumer, stop in (('any', 'True'), ('all', 'False')):
            for expression in (
                f'{stop} for outer in [0, 1] for inner in [0, 1] if (code := input())',
                f'{stop} for unused in [0, 1] if (code := input())',
            ):
                with self.subTest(consumer=consumer, expression=expression):
                    self.assert_rules(f"code = 'fixed'\n{consumer}({expression})\neval(code)\n", 'eval')
            self.assert_rules(f"code = 'fixed'\n{consumer}((code := input()) for unused in [0] if False)\neval(code)\n")

    def test_short_circuit_does_not_execute_later_boolean_operands(self):
        for consumer, expression in (
            ('any', "True or (code := input())"),
            ('all', "False and (code := input())"),
        ):
            with self.subTest(consumer=consumer):
                self.assert_rules(f"code = 'fixed'\n{consumer}({expression} for unused in [0])\neval(code)\n")

    def test_global_and_nonlocal_callbacks_execute_before_the_result(self):
        for consumer in ('any', 'all'):
            with self.subTest(consumer=consumer, scope='global'):
                self.assert_rules(f'''
                    code = 'fixed'
                    def replace():
                        global code
                        code = input()
                        return True
                    {consumer}(replace() for unused in [0])
                    eval(code)
                ''', 'eval')
            with self.subTest(consumer=consumer, scope='nonlocal'):
                self.assert_rules(f'''
                    def run():
                        code = 'fixed'
                        def replace():
                            nonlocal code
                            code = input()
                            return False
                        {consumer}(replace() for unused in [0])
                        eval(code)
                    run()
                ''', 'eval')

    def test_exception_keeps_writes_before_the_throw(self):
        for consumer in ('any', 'all'):
            with self.subTest(consumer=consumer):
                self.assert_rules(f'''
                    code = 'fixed'
                    def replace():
                        global code
                        code = input()
                        raise ValueError('stop')
                    try:
                        {consumer}(replace() for unused in [0])
                    except ValueError:
                        eval(code)
                ''', 'eval')

    def test_bound_builtin_aliases_keep_the_captured_consumer(self):
        for consumer in ('any', 'all'):
            for declaration in (f'consume = {consumer}', f'from builtins import {consumer} as consume'):
                with self.subTest(consumer=consumer, declaration=declaration):
                    self.assert_rules(f"{declaration}\ncode = 'fixed'\n"
                                      "consume((code := input()) for unused in [0])\neval(code)\n", 'eval')

    def test_custom_consumer_keeps_deferred_reads_incomplete(self):
        for consumer in ('any', 'all'):
            source = textwrap.dedent(f'''
                saved = None
                def {consumer}(values):
                    global saved
                    saved = values
                    return False
                code = 'fixed'
                {consumer}(code for unused in [0])
                code = input()
                eval(next(saved))
            ''')
            with self.subTest(consumer=consumer):
                observed = []
                exec(source, {'input': lambda: 'UNTRUSTED', 'eval': observed.append})
                self.assertEqual(observed, ['UNTRUSTED'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_replaced_builtin_members_do_not_acquire_boolean_return_proofs(self):
        for consumer in ('any', 'all'):
            for module in ('builtins', 'native'):
                source = (f'import builtins as {module}\n'
                          f'{module}.{consumer} = lambda values: input()\n'
                          f'eval({module}.{consumer}([input()]))\n')
                with self.subTest(consumer=consumer, module=module):
                    self.assertEqual([(item['rule'], item['line']) for item in self.scan(source)],
                                     [('python.taint.eval', 3)])
            self.assert_rules(f'''
                import builtins
                def replace():
                    builtins.{consumer} = lambda values: input()
                replace()
                eval(builtins.{consumer}([input()]))
            ''', 'eval')

    def test_opaque_truth_protocol_and_finalizers_are_not_certified(self):
        for consumer in ('any', 'all'):
            for expression in ('Release() for unused in [0]',
                               "True for unused in [Release()]",
                               'value for value in unknown'):
                source = f'''
                    code = 'fixed'
                    class Release:
                        def __bool__(self):
                            global code
                            code = input()
                            return True
                        def __del__(self):
                            global code
                            code = input()
                    {consumer}({expression})
                    eval(code)
                '''
                with self.subTest(consumer=consumer, expression=expression):
                    with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                        self.scan(source)


class FormattedStringCompletionTests(SourceTest):
    def assert_native(self, source, expected_values, *, incomplete=False):
        source = textwrap.dedent(source).lstrip('\n')
        # Keep the actual builtin input and native formatting protocols. Only
        # the sink is recorded, so the witness never executes input as code.
        witness = ('import json, sys\nobserved = []\n'
                   "if hasattr(sys, 'set_int_max_str_digits'):\n    sys.set_int_max_str_digits(4300)\n"
                   'def record(value):\n'
                   '    observed.append((sys._getframe(1).f_lineno, value))\n'
                   + f"exec(compile({source!r}, '<formatted-string-witness>', 'exec'), {{'eval': record}})\n"
                   + 'sys.stderr.write(json.dumps(observed))\n')
        native = subprocess.run([sys.executable, '-I', '-B', '-c', witness],
                                input='UNTRUSTED\n' * 16, capture_output=True, text=True, timeout=10)
        self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
        observed = json.loads(native.stderr)
        self.assertEqual([value for _line, value in observed], expected_values)
        if incomplete:
            with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)
        else:
            self.assertEqual(sorted((item['rule'], item['line']) for item in self.scan(source)),
                             [('python.taint.eval', line) for line in sorted({
                                 line for line, value in observed if 'UNTRUSTED' in str(value)})])

    def test_captured_formatted_strings_keep_named_reducer_provenance(self):
        definition = 'def order(record):\n    return len(record)\n'
        for reducer in ('min', 'max', 'sorted'):
            for expression, expected in (("f'SELECT {input()}'", 'SELECT UNTRUSTED'),
                                         ("f'SELECT {1}'", 'SELECT 1')):
                selected = f'{reducer}(([query] for unused in (1, 2)), key=order)'
                if reducer == 'sorted':
                    selected += '[0]'
                with self.subTest(reducer=reducer, expression=expression):
                    self.assert_native(definition + f'query = {expression}\n'
                                       + f'selected = {selected}\neval(selected[0])\n', [expected])

    def test_formatted_aliases_keep_their_evaluated_values(self):
        for original, replacement, expected in (
                ('input()', "'fixed'", 'UNTRUSTED'), ("'fixed'", 'input()', 'fixed')):
            for consumer in ('next(value for value in [saved])', "''.join(value for value in [saved])"):
                source = (f'value = {original}\nsaved = f"{{value}}"\n'
                          f'value = {replacement}\neval({consumer})\n')
                with self.subTest(original=original, consumer=consumer):
                    self.assert_native(source, [expected])
        self.assert_native('''
            def run():
                original = f'{input()}'
                saved = original
                original = 'fixed'
                values = [saved]
                saved = 'changed'
                eval(next(value for value in values))
            run()
        ''', ['UNTRUSTED'])

    def test_native_conversions_and_literal_string_specs_are_inert(self):
        cases = (
            ("f'{input()}'", 'UNTRUSTED'),
            ("f'{input()!s}'", 'UNTRUSTED'),
            ("f'{input()!r}'", "'UNTRUSTED'"),
            ("f'{input()!a}'", "'UNTRUSTED'"),
            ("f'{input():}'", 'UNTRUSTED'),
            ("f'{input():>12}'", '   UNTRUSTED'),
            ("f'{input():*^13s}'", '**UNTRUSTED**'),
            ("f'{input():<12.20s}'", 'UNTRUSTED   '),
            ("f'{input()!r:*>13}'", "**'UNTRUSTED'"),
            ('f"{f\'{input()}\'}"', 'UNTRUSTED'),
        )
        for expression, expected in cases:
            with self.subTest(expression=expression):
                self.assert_native(f'query = {expression}\neval(next(value for value in [query]))\n',
                                   [expected])

    def test_joined_fields_preserve_taint_and_primitive_branch_alternatives(self):
        self.assert_native('''
            value = input() if input() else 'fixed'
            query = f'before {value} after {True!s}'
            eval(next(value for value in [query]))
        ''', ['before UNTRUSTED after True'])
        self.assert_native('''
            left = input()
            right = 'fixed'
            query = f'{left}:{right}'
            left = 'changed'
            right = input()
            eval(next(value for value in [query]))
        ''', ['UNTRUSTED:fixed'])

    def test_opaque_formatting_and_temporary_subclass_release_stay_incomplete(self):
        for method, arguments, expression in (
                ('__format__', ', spec', "f'prefix{Value()}'"),
                ('__str__', '', "f'prefix{Value()!s}'"),
                ('__repr__', '', "f'prefix{Value()!r}'"),
                ('__repr__', '', "f'prefix{Value()!a}'")):
            source = ("code = 'fixed'\nclass Text(str):\n"
                      '    def __del__(self):\n        global code\n        code = input()\n'
                      + f'class Value:\n    def {method}(self{arguments}):\n'
                      + "        return Text('fixed')\n"
                      + f'query = {expression}\n'
                      + 'min(query for unused in (1, 2))\neval(code)\n')
            with self.subTest(method=method, expression=expression):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)
        self.assert_native('''
            code = 'fixed'
            class Text(str):
                def __del__(self):
                    global code
                    code = input()
            class Value:
                def __format__(self, spec):
                    return Text('fixed')
            value = f'{Value()}'
            list(((value := 'fixed'), (code := 'fixed')) for unused in [value])
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)

    def test_opaque_prompt_and_helper_frame_lifetimes_stay_incomplete(self):
        self.assert_native('''
            code = 'fixed'
            class Prompt:
                def __str__(self):
                    global code
                    code = input()
                    return ''
            query = f'{input(Prompt())}'
            min(query for unused in (1, 2))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)
        self.assert_native('''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def render():
                owned = Owned()
                return 'fixed'
            query = f'{render()}'
            min(query for unused in (1, 2))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)

    def test_invalid_and_unknown_specs_do_not_certify_normal_completion(self):
        for expression in ("f'{1!s:d}'", "f'{1!s:{input()}}'"):
            source = ("code = 'fixed'\ntry:\n"
                      + f'    query = {expression}\n'
                      + "except ValueError:\n    code = input()\n    query = 'fixed'\n"
                      + 'next(value for value in [query])\neval(code)\n')
            with self.subTest(expression=expression):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_captured_helper_results_keep_opaque_frame_ancestry(self):
        for result, invocation in (("'fixed'", 'render()'), ('value', "render('fixed')")):
            parameters = 'value' if result == 'value' else ''
            for capture in ('saved = result', 'saved = alias = result\nsaved = alias'):
                source = ("code = 'fixed'\nclass Owned:\n"
                          '    def __del__(self):\n        global code\n        code = input()\n'
                          + f'def render({parameters}):\n    owned = Owned()\n    return {result}\n'
                          + f'result = {invocation}\n{capture}\n'
                          + "query = f'{saved}'\n"
                          + 'min(query for unused in (1, 2))\neval(code)\n')
                with self.subTest(result=result, capture=capture):
                    self.assert_native(source, ['UNTRUSTED'], incomplete=True)
        self.assert_native('''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def render():
                owned = Owned()
                return True
            saved = render()
            query = f'{saved}'
            min(query for unused in (1, 2))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)

    def test_captured_input_prompt_does_not_gain_format_authority(self):
        self.assert_native('''
            code = 'fixed'
            class Prompt:
                def __str__(self):
                    global code
                    code = input()
                    return ''
            saved = input(Prompt())
            alias = saved
            query = f'{alias}'
            min(query for unused in (1, 2))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)

    def test_inert_helper_results_keep_native_format_authority(self):
        for result, invocation, expected in (
                ("'fixed'", 'render()', 'fixed'), ('value', 'render(input())', 'UNTRUSTED')):
            parameters = 'value' if result == 'value' else ''
            source = (f'def render({parameters}):\n    return {result}\n'
                      + f'saved = {invocation}\n'
                      + "query = f'{saved}'\neval(next(value for value in [query]))\n")
            with self.subTest(result=result):
                self.assert_native(source, [expected])

    @unittest.skipUnless(hasattr(sys, 'set_int_max_str_digits'), 'Python has no integer conversion limit')
    def test_oversized_integer_formatting_keeps_exception_boundaries(self):
        # Hexadecimal literals parse without the decimal digit restriction.
        # Configure only the native witness, never the analyzed program.
        huge = '0x' + 'f' * 5000
        for conversion in ('', '!s', '!r', '!a'):
            for assignment, operand in (('', huge), (f'number = {huge}\n', 'number')):
                source = (assignment + "code = 'fixed'\ntry:\n"
                          + f"    query = f'{{{operand}{conversion}}}'\n"
                          + "except ValueError:\n    code = input()\n    query = 'fixed'\n"
                          + 'next(value for value in [query])\neval(code)\n')
                with self.subTest(conversion=conversion, captured=bool(assignment)):
                    self.assert_native(source, ['UNTRUSTED'], incomplete=True)
            self.assert_native(
                "code = 'fixed'\ntry:\n"
                + f"    query = next(f'{{number{conversion}}}' for number in [{huge}])\n"
                + "except ValueError:\n    code = input()\n    query = 'fixed'\n"
                + 'next(value for value in [query])\neval(code)\n', ['UNTRUSTED'], incomplete=True)

    @unittest.skipUnless(hasattr(sys, 'set_int_max_str_digits'), 'Python has no integer conversion limit')
    def test_helper_input_prompts_keep_integer_conversion_boundaries(self):
        huge = '0x' + 'f' * 5000
        for setup, prompt in (('', huge), (f'    number = {huge}\n', 'number')):
            source = ("code = 'fixed'\ndef render():\n" + setup
                      + f'    input({prompt})\n'
                      + "    return 'fixed'\ntry:\n    saved = render()\n"
                      + "except ValueError:\n    code = input()\n    saved = 'fixed'\n"
                      + "query = f'{saved}'\nnext(value for value in [query])\neval(code)\n")
            with self.subTest(captured=bool(setup)):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_discarded_module_next_rejects_opaque_format_protocols(self):
        # These are module-scope borrowing regressions. The private-local
        # producer-proof regressions below exercise the distinct retained
        # owner exemption without certifying earlier opaque effects.
        for method, arguments, expression in (
                ('__format__', ', spec', "f'{Opaque()}'"),
                ('__format__', ', spec', "f'prefix-{Opaque()}-suffix'"),
                ('__str__', '', "f'{Opaque()!s}'"),
                ('__repr__', '', "f'{Opaque()!r}'"),
                ('__repr__', '', "f'{Opaque()!a}'")):
            source = ("code = 'fixed'\nclass Opaque:\n"
                      + f'    def {method}(self{arguments}):\n'
                      + "        global code\n        code = input()\n        return 'fixed'\n"
                      + f'text = {expression}\n'
                      + 'next(text for unused in (0,))\neval(code)\n')
            with self.subTest(method=method, expression=expression):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)
        self.assert_native('''
            code = 'fixed'
            class Opaque:
                def __format__(self, spec):
                    global code
                    code = input()
                    return 'fixed'
            value = 'fixed'
            if input():
                value = Opaque()
            text = f'{value}'
            next(text for unused in (0,))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)
        self.assert_native('''
            code = 'fixed'
            class Subclass(str):
                def __format__(self, spec):
                    global code
                    code = input()
                    return 'fixed'
            value = Subclass('fixed')
            text = f'{value}'
            next(text for unused in (0,))
            eval(code)
        ''', ['UNTRUSTED'], incomplete=True)

    def test_discarded_module_next_rejects_unproved_finalizer_ancestry(self):
        owned = ("code = 'fixed'\nclass Owned:\n"
                 '    def __del__(self):\n        global code\n        code = input()\n')
        helper = "def helper():\n    owned = Owned()\n    return 'fixed'\n"
        cases = (
            ('captured helper', owned + helper + "value = helper()\ntext = f'{value}'\n"),
            ('inline helper', owned + helper + "text = f'{helper()}'\n"),
            ('owned walrus', owned + "old = Owned()\ntext = f\"{(old := 'fixed')}\"\n"),
            ('ordered fields', "code = 'fixed'\nclass Opaque:\n"
             '    def __format__(self, spec):\n        global code\n        code = input()\n'
             + "        return 'fixed'\nvalue = Opaque()\n"
             + "text = f\"{value}{(value := 'fixed')}\"\n"),
        )
        for label, prefix in cases:
            with self.subTest(case=label):
                self.assert_native(prefix + 'next(text for unused in (0,))\neval(code)\n',
                                   ['UNTRUSTED'], incomplete=True)

    def test_discarded_next_preserves_module_and_private_native_strings(self):
        for expression, expected in (("'fixed'", 'fixed'), ('input()', 'UNTRUSTED'),
                                     ("f'<{input()!s}>'", '<UNTRUSTED>'), ("f'<{1}>'", '<1>')):
            body = (f'text = {expression}\nsaved = text\nnext(text for unused in (0,))\n'
                    + "text = 'changed'\neval(saved)\n")
            for scope in ('module', 'private'):
                source = (body if scope == 'module'
                          else 'def run():\n' + textwrap.indent(body, '    ') + 'run()\n')
                with self.subTest(expression=expression, scope=scope):
                    self.assert_native(source, [expected])

    def test_discarded_private_next_keeps_opaque_arguments_retained(self):
        for body in ('next(value for unused in (0,))\neval(code)\n',
                     "saved = value\nnext(saved for unused in (0,))\nsaved = 'changed'\neval(code)\n"):
            # The parameter retains the object until run returns. Reading it
            # through next neither tests its truth nor releases that owner.
            source = ("code = 'fixed'\nclass Retained:\n"
                      + '    def __bool__(self):\n        raise AssertionError("unexpected truth test")\n'
                      + '    def __del__(self):\n        global code\n        code = input()\n'
                      + 'def run(value):\n' + textwrap.indent(body, '    ')
                      + 'run(Retained())\n')
            with self.subTest(body=body):
                self.assert_native(source, ['fixed'])

    def test_private_next_does_not_certify_earlier_format_protocol_effects(self):
        for method, arguments, expression in (
                ('__format__', ', spec', "f'{Opaque()}'"),
                ('__format__', ', spec', "f'prefix-{Opaque()}-suffix'"),
                ('__str__', '', "f'{Opaque()!s}'"),
                ('__repr__', '', "f'{Opaque()!r}'"),
                ('__repr__', '', "f'{Opaque()!a}'")):
            source = ("code = 'fixed'\nclass Opaque:\n"
                      + f'    def {method}(self{arguments}):\n'
                      + "        global code\n        code = input()\n        return 'fixed'\n"
                      + f'def run():\n    text = {expression}\n'
                      + '    saved = text\n    next(saved for unused in (0,))\n'
                      + '    eval(code)\nrun()\n')
            with self.subTest(method=method, expression=expression):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_private_next_keeps_owned_producer_frame_effects(self):
        for result, parameters, invocation in (
                ("'fixed'", '', 'render()'),
                ('value', 'value', "render('fixed')")):
            for formatted in (False, True):
                # Use a separate capture for formatting to keep Python 3.9
                # source syntax independent of quote reuse in f-strings.
                setup = (f'    saved = {invocation}\n    text = f"{{saved}}"\n'
                         if formatted else f'    text = {invocation}\n')
                source = ("code = 'fixed'\nclass Owned:\n"
                          + '    def __del__(self):\n        global code\n        code = input()\n'
                          + f'def render({parameters}):\n    owned = Owned()\n    return {result}\n'
                          + 'def run():\n' + setup
                          + '    alias = text\n    next(alias for unused in (0,))\n'
                          + '    eval(code)\nrun()\n')
                with self.subTest(result=result, formatted=formatted):
                    self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_returned_argument_cannot_erase_a_producer_frame(self):
        source = '''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def render(value):
                owned = Owned()
                return value
            def run(value):
                saved = render(value)
                next(saved for unused in (0,))
                eval(code)
            run('fixed')
        '''
        self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_private_native_producers_and_unexecuted_opaque_work_remain_complete(self):
        for expression, expected in (("'fixed'", 'fixed'), ('input()', 'UNTRUSTED'),
                                     ("f'<{input()}>'", '<UNTRUSTED>'),
                                     ('render(input())', 'UNTRUSTED')):
            source = ("code = 'fixed'\nclass Opaque:\n"
                      + '    def __format__(self, spec):\n        global code\n        code = input()\n'
                      + "        return 'fixed'\ndef render(value):\n    return value\n"
                      + 'def run():\n    if False:\n        ignored = f"{Opaque()}"\n'
                      + f'    text = {expression}\n    saved = text\n'
                      + '    next(saved for unused in (0,))\n    eval(saved)\nrun()\n')
            with self.subTest(expression=expression):
                self.assert_native(source, [expected])
        self.assert_native('''
            def run():
                number = 7
                saved = number
                next(saved for unused in (0,))
                eval('fixed')
            run()
        ''', ['fixed'])

    def test_transparent_alias_helpers_keep_independently_retained_arguments(self):
        for body in ('return value', 'alias = value\nreturn alias'):
            source = ('def identity(value):\n' + textwrap.indent(body, '    ') + '\n'
                      + 'def run(value):\n    saved = identity(value)\n'
                      + '    next(saved for unused in (0,))\n    eval(saved)\nrun(input())\n')
            with self.subTest(body=body):
                self.assert_native(source, ['UNTRUSTED'])
        self.assert_native('''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def identity(value):
                return value
            def run(value):
                saved = identity(value)
                next(saved for unused in (0,))
                eval(code)
            run(Owned())
        ''', ['fixed'])

    def test_native_string_methods_preserve_producer_authority(self):
        for method in ('strip', 'lstrip', 'rstrip', 'lower', 'upper',
                       'capitalize', 'casefold', 'swapcase', 'title'):
            source = (f'def run():\n    text = " fixed ".{method}()\n'
                      + '    next(text for unused in (0,))\n    eval("fixed")\nrun()\n')
            with self.subTest(method=method):
                self.assert_native(source, ['fixed'])
        self.assert_native('''
            def run():
                text = input().strip()
                next(text for unused in (0,))
                eval(text)
            run()
        ''', ['UNTRUSTED'])
        self.assert_native('''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def render():
                owned = Owned()
                return 'fixed'
            def run():
                text = render().strip()
                next(text for unused in (0,))
                eval(code)
            run()
        ''', ['UNTRUSTED'], incomplete=True)

    def test_transparent_helper_cannot_repair_earlier_producer_effects(self):
        for setup in ("text = fixed(render())", "value = render()\ntext = fixed(value)"):
            source = ("code = 'fixed'\nclass Owned:\n"
                      + '    def __del__(self):\n        global code\n        code = input()\n'
                      + "def render():\n    owned = Owned()\n    return 'fixed'\n"
                      + "def fixed(value):\n    return 'fixed'\ndef run():\n"
                      + textwrap.indent(setup, '    ') + '\n'
                      + '    next(text for unused in (0,))\n    eval(code)\nrun()\n')
            with self.subTest(setup=setup):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)


    def test_private_next_keeps_inline_native_helpers_and_unused_protocols(self):
        prefix = ("code = 'fixed'\nclass Unused:\n"
                  + '    def __format__(self, spec):\n        global code\n        code = input()\n'
                  + "        return 'fixed'\ndef render(value):\n    return value\n")
        for expression, expected in (("f'{render(input())}'", 'UNTRUSTED'),
                                     ("f'{render(\"fixed\")}'", 'fixed'),
                                     ("f'{input(\"prompt\")}'", 'UNTRUSTED')):
            source = (prefix + 'def run():\n'
                      + textwrap.indent(f'text = {expression}\nsaved = text\n'
                                        + 'next(text for unused in (0,))\neval(saved)\neval(code)\n', '    ')
                      + 'run()\n')
            with self.subTest(expression=expression):
                self.assert_native(source, [expected, 'fixed'])

    def test_private_next_producer_evidence_survives_helpers_vectors_and_joins(self):
        prefix = ("code = 'fixed'\nclass Opaque:\n"
                  + '    def __format__(self, spec):\n        global code\n        code = input()\n'
                  + "        return 'fixed'\ndef forward(value):\n    return value\n"
                  + 'def first(values):\n    return values[0]\n')
        for capture in ('saved = forward(text)', 'saved = [text][0]',
                        'saved = first([text])', "saved = text if input() else 'fixed'",
                        "saved = 'fixed'\nif input():\n    saved = text"):
            source = (prefix + 'def run():\n'
                      + textwrap.indent("text = f'{Opaque()}'\n" + capture + '\n'
                                        + 'next(saved for unused in (0,))\neval(code)\n', '    ')
                      + 'run()\n')
            with self.subTest(capture=capture):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)
        self.assert_native(prefix + 'def consume(text):\n'
                           + '    next(text for unused in (0,))\n    eval(code)\n'
                           + "consume(f'{Opaque()}')\n", ['UNTRUSTED'], incomplete=True)

    def test_private_next_keeps_projected_native_producer_controls(self):
        for expression, expected in (("input('prompt')", 'UNTRUSTED'),
                                     ('render(input())', 'UNTRUSTED'), ("render('fixed')", 'fixed')):
            for capture in ('saved = text', 'saved = [text][0]'):
                source = ('def render(value):\n    return value\ndef run():\n'
                          + textwrap.indent(f'text = {expression}\n{capture}\n'
                                            + 'next(saved for unused in (0,))\neval(saved)\n', '    ')
                          + 'run()\n')
                with self.subTest(expression=expression, capture=capture):
                    self.assert_native(source, [expected])

    def test_private_next_preserves_scalar_producer_uncertainty(self):
        prefix = ("code = 'fixed'\nclass Owned:\n"
                  + '    def __del__(self):\n        global code\n        code = input()\n')
        for scalar in ('7', 'True', 'None', "b'fixed'", '1.5', '2j'):
            for capture in ('saved = value', 'saved = [value][0]', 'saved = forward(value)'):
                source = (prefix + 'def render():\n    owned = Owned()\n'
                          + f'    return {scalar}\ndef forward(value):\n    return value\ndef run():\n'
                          + textwrap.indent('value = render()\n' + capture + '\n'
                                            + 'next(saved for unused in (0,))\neval(code)\n', '    ')
                          + 'run()\n')
                with self.subTest(scalar=scalar, capture=capture):
                    self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_private_next_keeps_native_scalar_and_retained_parameter_controls(self):
        for scalar in ('7', 'True', 'None', "b'fixed'", '1.5', '2j'):
            source = (f'def render():\n    return {scalar}\ndef run():\n'
                      + "    value = render()\n    next(value for unused in (0,))\n    eval('fixed')\nrun()\n")
            with self.subTest(scalar=scalar):
                self.assert_native(source, ['fixed'])
        self.assert_native('''
            code = 'fixed'
            class Owned:
                def __del__(self):
                    global code
                    code = input()
            def run(value):
                next(value for unused in (0,))
                eval(code)
            retained = Owned()
            run(retained)
            retained = None
        ''', ['fixed'])

    def test_generator_join_preserves_receiver_producer_effects(self):
        prefix = ("code = 'fixed'\nclass Owned:\n"
                  + '    def __del__(self):\n        global code\n        code = input()\n'
                  + "def render():\n    owned = Owned()\n    return '|'\n"
                  + 'def identity(value):\n    return value\n')
        for setup, receiver in (
                ('', 'render()'),
                ('separator = render()\n', 'separator'),
                ('separator = render()\nalias = separator\n', 'alias'),
                ('separator = render()\n', 'separator.strip()'),
                ('separator = render()\n', 'identity(separator)')):
            body = setup + f"{receiver}.join(part for part in ['a', 'b'])\neval(code)\n"
            for scope in ('module', 'private'):
                source = prefix + (body if scope == 'module'
                                   else 'def run():\n' + textwrap.indent(body, '    ') + 'run()\n')
                with self.subTest(receiver=receiver, scope=scope):
                    self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_generator_join_keeps_opaque_prompt_and_format_receiver_effects(self):
        for method, signature, expression in (
                ('__str__', '', 'input(Opaque())'),
                ('__format__', ', spec', "f'{Opaque()}'")):
            source = ("code = 'fixed'\nclass Opaque:\n"
                      + f'    def {method}(self{signature}):\n'
                      + "        global code\n        code = input()\n        return '|'\n"
                      + f'separator = {expression}\n'
                      + "separator.join(part for part in ['a', 'b'])\neval(code)\n")
            with self.subTest(method=method):
                self.assert_native(source, ['UNTRUSTED'], incomplete=True)

    def test_generator_join_keeps_native_receiver_and_taint_controls(self):
        for setup, receiver, expected in (
                ('', "'|'", 'a|b'),
                ("separator = '|'\n", 'separator', 'a|b'),
                ("separator = '|'\nalias = separator\n", 'alias', 'a|b'),
                ('', "render('|')", 'a|b'),
                ('separator = input()\n', 'separator', 'aUNTRUSTEDb'),
                ('separator = render(input())\n', 'separator', 'aUNTRUSTEDb'),
                ("separator = f'{input()}'\n", 'separator', 'aUNTRUSTEDb')):
            body = setup + f"result = {receiver}.join(part for part in ['a', 'b'])\neval(result)\n"
            for scope in ('module', 'private'):
                source = ('def render(value):\n    return value\n'
                          + (body if scope == 'module'
                             else 'def run():\n' + textwrap.indent(body, '    ') + 'run()\n'))
                with self.subTest(receiver=receiver, scope=scope, setup=setup):
                    self.assert_native(source, [expected])


class ImmediateGeneratorExpressionTests(SourceTest):
    def test_string_join_captures_values_before_later_rebinding(self):
        for receiver in ("''", 'separator'):
            for initial, later, expected in (
                ('input()', "'fixed'", [('python.taint.eval', 7)]),
                ("'fixed'", 'input()', []),
            ):
                source = f'''
                    def run():
                        separator = ''
                        code = {initial}
                        joined = {receiver}.join(code for unused in [0])
                        code = {later}
                        separator = 'changed'
                        eval(joined)
                    run()
                '''
                with self.subTest(receiver=receiver, initial=initial):
                    findings = self.scan(source)
                    self.assertEqual([(item['rule'], item['line']) for item in findings], expected)

    def test_string_join_global_writes_keep_iteration_order_and_collected_values(self):
        for initial, iterable, expected in (
            ("'fixed'", '[input()]', (3, 4)),
            ('input()', "['fixed']", ()),
            ('input()', '[]', (3,)),
            ("'fixed'", "[input(), 'fixed']", (4,)),
            ("'fixed'", "['fixed', input()]", (3, 4)),
        ):
            source = (f'code = {initial}\n'
                      f"joined = ''.join((code := part) for part in {iterable})\n"
                      'eval(code)\neval(joined)\n')
            with self.subTest(iterable=iterable):
                self.assertEqual([(item['rule'], item['line']) for item in self.scan(source)],
                                 [('python.taint.eval', line) for line in expected])

    def test_string_join_runs_global_and_nonlocal_helper_effects(self):
        for source, line in (("""
            code = 'fixed'
            def replace():
                global code
                code = input()
                return 'done'
            ''.join(replace() for unused in [0])
            eval(code)
        """, 7), ("""
            def run():
                code = 'fixed'
                def replace():
                    nonlocal code
                    code = input()
                    return 'done'
                ''.join(replace() for unused in [0])
                eval(code)
            run()
        """, 8)):
            with self.subTest(source=source):
                self.assertEqual([(item['rule'], item['line']) for item in self.scan(source)],
                                 [('python.taint.eval', line)])

    def test_string_join_filters_and_exceptions_preserve_actual_effects(self):
        self.assert_rules('''
            code = 'fixed'
            ''.join((code := input()) for unused in [0] if False)
            eval(code)
        ''')
        self.assert_rules('''
            code = 'fixed'
            ''.join('done' for unused in [0] if (code := input()))
            eval(code)
        ''', 'eval')
        self.assert_rules('''
            code = 'fixed'
            def replace():
                global code
                code = input()
                raise ValueError('stop')
            try:
                ''.join(replace() for unused in [0])
            except ValueError:
                eval(code)
        ''', 'eval')

    def test_string_join_custom_receiver_keeps_deferred_semantics(self):
        source = '''
            saved = None
            class Delayed:
                def join(self, values):
                    global saved
                    saved = values
                    return 'fixed'
            separator = Delayed()
            code = 'fixed'
            separator.join(code for unused in [0])
            code = input()
            eval(next(saved))
        '''
        observed = []
        exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
        self.assertEqual(observed, ['MARKER'])
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            self.scan(source)

    def test_string_join_does_not_certify_opaque_iterators_or_values(self):
        for expression in ("''.join(value for value in unknown)",
                           "''.join(Release() for unused in [0])",
                           "''.join('fixed' for unused in [Release()])",
                           "''.join('fixed' for unused in [0] if Release())"):
            source = f'''
                code = 'fixed'
                class Release:
                    def __del__(self):
                        global code
                        code = input()
                    def __bool__(self):
                        global code
                        code = input()
                        return True
                {expression}
                eval(code)
            '''
            with self.subTest(expression=expression), self.assertRaisesRegex(
                    taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_string_join_nonstring_elements_are_not_certified_successful(self):
        for value in ('0', "b'bytes'", "['fixed']"):
            with self.subTest(value=value), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(f"''.join(value for value in [{value}])\n")

    def test_materializers_preserve_creation_time_values_and_later_rebindings(self):
        for collector in ('list', 'tuple'):
            for initial, later, expected in (
                ('input()', "'fixed'", ('eval',)),
                ("'fixed'", 'input()', ()),
            ):
                with self.subTest(collector=collector, initial=initial):
                    self.assert_rules(f'''
                        def run():
                            code = {initial}
                            values = {collector}(code for unused in [0])
                            code = {later}
                            eval(values[0])
                        run()
                    ''', *expected)

    def test_walrus_global_writes_follow_actual_iteration_order(self):
        cases = (
            ("'fixed'", "[input()]", ('eval',)),
            ('input()', "['fixed']", ()),
            ('input()', '[]', ('eval',)),
            ("'fixed'", "[input(), 'fixed']", ()),
            ("'fixed'", "['fixed', input()]", ('eval',)),
        )
        for collector in ('list', 'tuple'):
            for initial, iterable, expected in cases:
                with self.subTest(collector=collector, iterable=iterable):
                    self.assert_rules(f'''
                        code = {initial}
                        values = {collector}((code := value) for value in {iterable})
                        eval(code)
                    ''', *expected)

    def test_global_and_nonlocal_helper_writes_run_during_consumption(self):
        self.assert_rules('''
            code = 'fixed'
            def replace():
                global code
                code = input()
                return 'done'
            values = list(replace() for unused in [0])
            eval(code)
        ''', 'eval')
        self.assert_rules('''
            def run():
                code = 'fixed'
                def replace():
                    nonlocal code
                    code = input()
                    return 'done'
                values = tuple(replace() for unused in [0])
                eval(code)
            run()
        ''', 'eval')

    def test_outer_iterable_is_evaluated_exactly_once(self):
        # A second evaluation would replace the captured unsafe value with
        # the already cleaned global and incorrectly lose the real flow.
        self.assert_rules('''
            code = input()
            previous = 'fixed'
            def items():
                global previous, code
                previous = code
                code = 'fixed'
                return [0]
            values = list(previous for unused in items())
            eval(values[0])
        ''', 'eval')

    def test_filters_preserve_writes_and_skip_unreachable_bodies(self):
        self.assert_rules('''
            code = 'fixed'
            values = list((code := input()) for unused in [0] if False)
            eval(code)
        ''')
        self.assert_rules('''
            code = 'fixed'
            values = tuple('fixed' for unused in [0] if (code := input()))
            eval(code)
        ''', 'eval')

    def test_exceptional_exhaustion_keeps_writes_before_the_throw(self):
        for header in ('list(replace() for unused in [0])',
                       "tuple('fixed' for unused in [0] if replace())"):
            with self.subTest(header=header):
                self.assert_rules(f'''
                    code = 'fixed'
                    def replace():
                        global code
                        code = input()
                        raise ValueError('stop')
                    try:
                        {header}
                    except ValueError:
                        eval(code)
                ''', 'eval')

    def test_known_collection_alias_keeps_primitive_snapshots(self):
        self.assert_rules('''
            code = input()
            parts = [code, 'fixed']
            code = 'fixed'
            values = tuple(value for value in parts)
            eval(values[0])
        ''', 'eval')

    def test_materializer_aliases_preserve_the_original_callable(self):
        self.assert_rules('''
            collect = list
            code = 'fixed'
            values = collect((code := input()) for unused in [0])
            eval(code)
        ''', 'eval')
        self.assert_rules('''
            from builtins import tuple as collect
            code = 'fixed'
            values = collect((code := 'changed') for unused in [0])
            code = input()
            eval(values[0])
        ''')
        self.assert_rules('''
            import builtins
            code = 'fixed'
            values = builtins.list(code for unused in [0])
            code = input()
            eval(values[0])
        ''')

    def test_reflectively_replaced_materializers_remain_deferred(self):
        for replacement in (
            "import builtins\nbuiltins.__setattr__('list', Delayed())",
            "print.__self__.__setattr__('list', Delayed())",
            "from operator import attrgetter as acquire\nacquire('__self__.__setattr__')(print)('list', Delayed())",
            "from builtins import vars as namespace\nnamespace(print.__self__)['list'] = Delayed()",
        ):
            source = '''
                saved = None
                class Delayed:
                    def __call__(self, values):
                        global saved
                        saved = values
                        return ()
            '''
            source = textwrap.dedent(source) + replacement
            source += "\ncode = 'fixed'\nvalues = list(code for unused in [0])\ncode = input()\neval(next(saved))\n"
            # Reflection really replaces the builtin, so isolate and restore
            # it around the native semantic control rather than the test runner.
            runtime = (
                'import builtins\noriginal = builtins.list\nobserved = []\n'
                "namespace = {'input': lambda: 'MARKER', 'eval': observed.append}\n"
                f'try:\n    exec({source!r}, namespace)\n'
                'finally:\n    builtins.list = original\n'
                "assert observed == ['MARKER'], observed\n"
            )
            with self.subTest(replacement=replacement):
                subprocess.run([sys.executable, '-I', '-c', runtime], capture_output=True, text=True, check=True)
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_custom_class_namespace_does_not_certify_a_builtin(self):
        source = '''
            saved = None
            class Delayed:
                def __call__(self, values):
                    global saved
                    saved = values
                    return ()
            class Namespace(dict):
                def __missing__(self, name):
                    if name == 'list':
                        return Delayed()
                    raise KeyError(name)
            class Meta(type):
                @classmethod
                def __prepare__(metacls, name, bases):
                    return Namespace()
            code = 'fixed'
            class Box(metaclass=Meta):
                values = list(code for unused in [0])
            code = input()
            eval(next(saved))
        '''
        observed = []
        exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
        self.assertEqual(observed, ['MARKER'])
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
            self.scan(source)

    def test_owned_finalizers_and_opaque_iteration_remain_incomplete(self):
        for expression in (
            "list(Release() for unused in [0])",
            "tuple('fixed' for unused in [Release()])",
            "list(value for value in unknown)",
            "list('fixed' for value in [0] if Release())",
        ):
            source = f'''
                code = 'fixed'
                class Release:
                    def __del__(self):
                        global code
                        code = input()
                    def __bool__(self):
                        global code
                        code = input()
                        return True
                {expression}
                eval(code)
            '''
            with self.subTest(expression=expression), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_helper_owned_finalizers_remain_incomplete_on_both_exits(self):
        for ending in ("return 'done'", "raise ValueError('stop')"):
            source = f'''
                code = 'fixed'
                tainted = input()
                class Release:
                    def __del__(self):
                        global code
                        code = tainted
                def replace():
                    global code
                    owned = Release()
                    code = 'fixed'
                    {ending}
                try:
                    values = list(replace() for unused in [0])
                except ValueError:
                    pass
                eval(code)
            '''
            with self.subTest(ending=ending):
                observed = []
                exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_helper_defaults_and_transitive_frames_require_lifetime_proofs(self):
        for declaration, expression in (
            ('''
                def replace(unused=Release()):
                    global code
                    code = 'fixed'
                    return 'done'
                ''', "replace('overridden')"),
            ('''
                def inner():
                    owned = Release()
                    return 'done'
                def replace():
                    global code
                    code = 'fixed'
                    return inner()
                ''', 'replace()'),
        ):
            prefix = '''
                code = 'fixed'
                class Release:
                    def __del__(self):
                        global code
                        code = input()
            '''
            source = textwrap.dedent(prefix) + textwrap.dedent(declaration)
            source += f'values = list({expression} for unused in [0])\neval(code)\n'
            compile(source, '<lifetime-control>', 'exec')
            with self.subTest(expression=expression), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)

    def test_replaced_opaque_bindings_require_a_release_proof(self):
        for expression in ("list((owned := 'fixed') for unused in [0])", 'list(replace() for unused in [0])'):
            source = f'''
                code = 'fixed'
                class Release:
                    def __del__(self):
                        global code
                        code = input()
                owned = Release()
                def replace():
                    global owned
                    owned = 'fixed'
                    return 'done'
                {expression}
                eval(code)
            '''
            with self.subTest(expression=expression):
                observed = []
                exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_opaque_protocols_cannot_hide_behind_primitive_results(self):
        for expression in ("'fixed' if opaque else 'also fixed'", "(opaque[0], 'fixed')[1]",
                           "(f'{opaque}', 'fixed')[1]"):
            source = f'''
                code = 'fixed'
                class Protocol:
                    def __bool__(self):
                        global code
                        code = input()
                        return True
                    def __getitem__(self, index):
                        global code
                        code = input()
                        return 'fixed'
                    def __format__(self, spec):
                        global code
                        code = input()
                        return 'fixed'
                opaque = Protocol()
                values = list({expression} for unused in [0])
                eval(code)
            '''
            with self.subTest(expression=expression):
                observed = []
                exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_unhashable_collections_preserve_construction_failures(self):
        for collection in ('{[]: 0}', '{([] ,): 0}', '{(({},),): 0}', '{[]}', '{({0} or {}): 0}'):
            for clauses in (f'for unused in {collection}',
                            f'for outer in [0] for unused in {collection}'):
                source = f'''
                    code = input()
                    try:
                        list((code := 'fixed') {clauses})
                    except TypeError:
                        eval(code)
                '''
                with self.subTest(collection=collection, clauses=clauses):
                    observed = []
                    exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
                    self.assertEqual(observed, ['MARKER'])
                    with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                        self.scan(source)

    def test_helper_collections_require_hashable_members(self):
        for constructor in ('unused = {[]: 0}', 'unused = {([] ,): 0}', 'unused = {[]}',
                            'key = []\nunused = {key: 0}'):
            source = "code = input()\ndef replace():\n    global code\n"
            source += textwrap.indent(constructor, '    ')
            source += "\n    code = 'fixed'\n    return 'done'\n"
            source += "try:\n    list(replace() for unused in [0])\nexcept TypeError:\n    eval(code)\n"
            with self.subTest(constructor=constructor):
                observed = []
                exec(source, {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)
        for constructor in ('{[]: 0}', '{[]}', '{(({},),): 0}'):
            source = f'''
                code = input()
                def items():
                    return {constructor}
                try:
                    list((code := 'fixed') for unused in items())
                except TypeError:
                    eval(code)
            '''
            with self.subTest(returned=constructor):
                observed = []
                exec(textwrap.dedent(source), {'input': lambda: 'MARKER', 'eval': observed.append})
                self.assertEqual(observed, ['MARKER'])
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                    self.scan(source)

    def test_hashable_tuple_keys_keep_materialization_effects(self):
        self.assert_rules('''
            code = 'fixed'
            values = tuple((code := input()) for unused in {('first', 1): 'fixed'})
            eval(code)
        ''', 'eval')
        self.assert_rules('''
            code = 'fixed'
            def replace():
                global code
                key = ('first', 1)
                unused = {key: 0}
                code = input()
                return 'done'
            values = list(replace() for unused in [0])
            eval(code)
        ''', 'eval')

    def test_custom_consumers_do_not_receive_synchronous_proofs(self):
        for declaration, collector in (
            ('def collect(values): return values', 'collect'),
            ('def list(values): return values', 'list'),
            ('collect = list if unknown else custom', 'collect'),
        ):
            source = f'''
                {declaration}
                code = 'fixed'
                values = {collector}(code for unused in [0])
                code = input()
                eval(values.__next__())
            '''
            with self.subTest(collector=collector), self.assertRaisesRegex(taint_py.AnalysisLimit, 'incomplete'):
                self.scan(source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
