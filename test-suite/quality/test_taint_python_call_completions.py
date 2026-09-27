"""Call summaries must separate returned and exceptional continuations (D6)."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from test_taint_python_dataflow import SourceTest


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
