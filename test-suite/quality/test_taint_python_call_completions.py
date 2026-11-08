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


if __name__ == '__main__':
    unittest.main(verbosity=2)
