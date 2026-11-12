"""Source-level oracle for module-global writes that outlive a helper call.

Fixtures are parsed and analyzed, never imported or executed. A global
assignment changes the defining module after either normal return or an
exception; an unrelated local or closure with the same spelling is unchanged.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import textwrap
import time
import unittest
import uuid

from test_taint_python_dataflow import ROOT, RunContext, taint_py


@dataclass(frozen=True)
class Case:
    name: str
    code: str

    @property
    def source(self):
        return textwrap.dedent(self.code).strip('\n') + '\n'

    @property
    def expected(self):
        return sorted((f'python.taint.{kind}', line)
                      for line, text in enumerate(self.source.splitlines(), 1)
                      for kind in re.findall(r'# expect:(eval|command|sql|xss)\b', text))


VALUE_CASES = (
    Case('helper_recreates_deleted_global_with_clean_callable', '''
        eval = lambda code: None
        def reset():
            global eval
            eval = lambda code: None
        del eval
        reset()
        callback = eval
        callback(input())
        '''),
    Case('direct_rebinding_clears_module_deletion_before_join', '''
        eval = lambda code: None
        def reset():
            global eval
            eval = lambda code: None
        if input():
            del eval
            eval = lambda code: None
        else:
            reset()
        callback = eval
        callback(input())
        '''),
    Case('module_deletion_does_not_block_unrelated_analysis', '''
        import zlib
        del zlib
        code = input()
        eval(code) # expect:eval
        '''),
    Case('setter_argument_reaches_caller', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        eval(code) # expect:eval
        '''),
    Case('setter_source_reaches_caller', '''
        import os
        command = 'echo safe'
        def replace():
            global command
            command = input()
        replace()
        os.system(command) # expect:command
        '''),
    Case('transitive_setter_reaches_caller', '''
        code = '1'
        def replace(value):
            global code
            code = value
        def forward(value):
            replace(value)
        def prepare(value):
            forward(value)
        prepare(input())
        eval(code) # expect:eval
        '''),
    Case('callback_sink_replacement', '''
        execute = print
        def replace():
            global execute
            execute = eval
        replace()
        execute(input()) # expect:eval
        '''),
    Case('callback_clean_replacement', '''
        execute = eval
        def replace():
            global execute
            execute = print
        replace()
        execute(input())
        '''),
    Case('strong_clean_replacement', '''
        code = input()
        def replace():
            global code
            code = '1'
        replace()
        eval(code)
        '''),
    Case('later_caller_assignment_remains_strong', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        code = '1'
        eval(code)
        '''),
    Case('later_helper_assignment_remains_strong', '''
        code = '1'
        def replace(value):
            global code
            code = value
        def prepare(value):
            replace(value)
            replace('1')
        prepare(input())
        eval(code)
        '''),
    Case('read_snapshot_precedes_later_write', '''
        code = '1'
        def replace(value):
            global code
            code = value
        before = code
        replace(input())
        eval(before)
        '''),
    Case('tainted_snapshot_survives_clean_replacement', '''
        code = input()
        def replace():
            global code
            code = '1'
        before = code
        replace()
        eval(before) # expect:eval
        '''),
    Case('global_reference_keeps_caller_alias', '''
        box = {}
        def replace(value):
            global box
            box = value
        incoming = {}
        replace(incoming)
        incoming['code'] = input()
        eval(box['code']) # expect:eval
        '''),
    Case('global_reference_rebind_keeps_old_object_clean', '''
        box = {}
        original = box
        def replace(value):
            global box
            box = value
        incoming = {}
        replace(incoming)
        incoming['code'] = input()
        eval(original['code'])
        '''),
    Case('new_global_object_retains_heap_write', '''
        box = {}
        def replace(value):
            global box
            box = {}
            box['code'] = value
        replace(input())
        eval(box['code']) # expect:eval
        '''),
    Case('global_partial_retains_captured_operand', '''
        from functools import partial
        pending = print
        def replace(value):
            global pending
            pending = partial(eval, value)
        replace(input())
        pending() # expect:eval
        '''),
    Case('reflective_literal_setter_reaches_caller', '''
        code = '1'
        def replace(value):
            globals()['code'] = value
        replace(input())
        eval(code) # expect:eval
        '''),
    Case('global_import_replaces_callable', '''
        execute = print
        def replace():
            global execute
            from os import system as execute
        replace()
        execute(input()) # expect:command
        '''),
    Case('string_join_captures_unsafe_value_before_rebinding', '''
        code = input()
        joined = ''.join(code for unused in [0])
        code = 'fixed'
        eval(joined) # expect:eval
        '''),
    Case('string_join_captures_clean_value_before_rebinding', '''
        code = 'fixed'
        joined = ''.join(code for unused in [0])
        code = input()
        eval(joined)
        '''),
    Case('string_join_applies_global_helper_effect', '''
        code = 'fixed'
        def replace():
            global code
            code = input()
            return 'done'
        ''.join(replace() for unused in [0])
        eval(code) # expect:eval
        '''),
)

CONTROL_CASES = (
    Case('direct_module_write_survives_helper_sibling_branch', '''
        code = '1'
        def reset():
            global code
            code = '1'
        if condition:
            code = input()
        else:
            reset()
        eval(code) # expect:eval
        '''),
    Case('reversed_helper_and_direct_module_branches_preserve_taint', '''
        code = '1'
        def reset():
            global code
            code = '1'
        if condition:
            reset()
        else:
            code = input()
        eval(code) # expect:eval
        '''),
    Case('direct_and_helper_clean_branches_replace_old_taint', '''
        code = input()
        def reset():
            global code
            code = '1'
        if condition:
            code = '1'
        else:
            reset()
        eval(code)
        '''),
    Case('direct_callback_branch_cannot_be_erased_by_helper', '''
        execute = print
        def reset():
            global execute
            execute = print
        if condition:
            execute = eval
        else:
            reset()
        execute(input()) # expect:eval
        '''),
    Case('shadowed_local_is_not_the_unwritten_global_branch', '''
        code = input()
        def reset():
            global code
            code = '1'
        def caller():
            code = '1'
            if condition:
                reset()
            eval(globals()['code']) # expect:eval
        caller()
        '''),
    Case('comprehension_projection_keeps_definite_global_reset', '''
        code = input()
        def reset():
            global code
            code = '1'
        if condition:
            [reset() for code in ['1']]
        else:
            code = '1'
        eval(code)
        '''),
    Case('nested_comprehension_projection_restores_global_visibility', '''
        code = input()
        def reset():
            global code
            code = '1'
        if condition:
            [[reset() for code in ['inner']] for code in ['outer']]
        else:
            code = '1'
        eval(code)
        '''),
    Case('exceptional_comprehension_projection_preserves_global_reset', '''
        code = input()
        def reset():
            global code
            code = '1'
            raise ValueError('stop')
        if condition:
            try:
                [reset() for code in ['local']]
            except ValueError:
                pass
        else:
            code = '1'
        eval(code)
        '''),
    Case('zero_iteration_comprehension_preserves_incoming_global', '''
        code = input()
        def reset():
            global code
            code = '1'
        [reset() for code in items]
        eval(code) # expect:eval
        '''),
    Case('zero_iteration_comprehension_keeps_clean_control', '''
        code = '1'
        def reset():
            global code
            code = '1'
        [reset() for code in items]
        eval(code)
        '''),
    Case('generator_outer_iterable_global_effect_is_immediate', '''
        code = '1'
        def replace():
            global code
            code = input()
            return [0]
        pending = (item for item in replace())
        eval(code) # expect:eval
        '''),
    Case('generator_iteration_target_does_not_replace_global', '''
        code = '1'
        def replace():
            global code
            code = input()
        replace()
        pending = (code for code in ['1'])
        eval(code) # expect:eval
        '''),
    Case('conditional_write_preserves_unwritten_taint', '''
        code = input()
        def maybe_replace():
            global code
            if condition:
                code = '1'
        maybe_replace()
        eval(code) # expect:eval
        '''),
    Case('conditional_write_preserves_written_taint', '''
        code = '1'
        def maybe_replace(value):
            global code
            if condition:
                code = value
        maybe_replace(input())
        eval(code) # expect:eval
        '''),
    Case('conditional_intermediary_preserves_incoming_rebinding', '''
        code = '1'
        def replace(value):
            global code
            code = value
        def maybe_replace():
            if condition:
                replace('1')
        replace(input())
        maybe_replace()
        eval(code) # expect:eval
        '''),
    Case('conditional_then_definite_reset_is_clean', '''
        code = input()
        def replace(value):
            global code
            code = value
        def prepare():
            if condition:
                replace(input())
            replace('1')
        prepare()
        eval(code)
        '''),
    Case('write_before_exception_reaches_handler', '''
        code = '1'
        def replace(value):
            global code
            code = value
            raise ValueError('stop')
        try:
            replace(input())
        except ValueError:
            eval(code) # expect:eval
        '''),
    Case('finally_write_overrides_pending_return', '''
        code = '1'
        def replace(value):
            global code
            try:
                return
            finally:
                code = value
        replace(input())
        eval(code) # expect:eval
        '''),
    Case('finally_clean_write_overrides_exceptional_value', '''
        code = input()
        def replace(value):
            global code
            try:
                code = value
                raise ValueError('stop')
            finally:
                code = '1'
        value = input()
        try:
            replace(value)
        except ValueError:
            eval(code)
        '''),
    Case('global_write_does_not_replace_same_name_local', '''
        code = '1'
        def replace(value):
            global code
            code = value
        def caller(value):
            code = '1'
            replace(value)
            eval(code)
        caller(input())
        eval(code) # expect:eval
        '''),
    Case('global_write_does_not_replace_same_name_closure', '''
        code = '1'
        def replace(value):
            global code
            code = value
        def outer(value):
            code = '1'
            def caller():
                replace(value)
                eval(code)
            caller()
        outer(input())
        eval(code) # expect:eval
        '''),
    Case('recursive_setter_effect_converges', '''
        code = '1'
        def first(value):
            global code
            if condition:
                second(value)
            code = value
        def second(value):
            first(value)
        second(input())
        eval(code) # expect:eval
        '''),
    Case('awaited_same_module_setter_reaches_caller', '''
        import asyncio
        code = '1'
        async def replace(value):
            global code
            code = value
        async def caller():
            await replace(input())
            eval(code) # expect:eval
        asyncio.run(caller())
        '''),
    Case('class_body_setter_reaches_enclosing_module', '''
        code = '1'
        def replace(value):
            global code
            code = value
        class Configuration:
            replace(input())
        eval(code) # expect:eval
        '''),
    Case('eager_comprehension_setter_reaches_caller', '''
        code = '1'
        def replace(value):
            global code
            code = value
        [replace(input()) for item in [0]]
        eval(code) # expect:eval
        '''),
    Case('class_local_does_not_rebind_reflective_global', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        class Configuration:
            code = '1'
            eval(globals()['code']) # expect:eval
        '''),
    Case('comprehension_target_does_not_rebind_global', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        [code for code in ['1']]
        eval(code) # expect:eval
        '''),
    Case('class_local_reads_its_own_clean_value', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        class Configuration:
            code = '1'
            eval(code)
        '''),
    Case('class_reads_updated_global_before_local_assignment', '''
        code = '1'
        def replace(value):
            global code
            code = value
        replace(input())
        class Configuration:
            eval(code) # expect:eval
            code = '1'
        '''),
)

BOUNDARY_CASES = (
    Case('deleted_builtin_shadow_survives_helper_sibling_join', '''
        eval = lambda code: None
        def reset():
            global eval
            eval = lambda code: None
        if input():
            del eval
        else:
            reset()
        callback = eval
        callback(input())
        '''),
    Case('generator_expression_global_setter_is_explicitly_incomplete', '''
        code = '1'
        def replace():
            global code
            code = input()
        pending = (replace() for unused in [0])
        list(pending)
        eval(code)
        '''),
    Case('generator_expression_global_walrus_is_explicitly_incomplete', '''
        code = '1'
        pending = ((code := input()) for unused in [0])
        list(pending)
        eval(code)
        '''),
    Case('reflective_global_deletion_is_explicitly_incomplete', '''
        execute = print
        def remove():
            del globals()['execute']
        remove()
        execute(input())
        '''),
    Case('class_write_before_local_assignment_is_explicitly_incomplete', '''
        code = '1'
        def replace(value):
            global code
            code = value
        class Configuration:
            replace(input())
            eval(code)
            code = '1'
        '''),
    Case('global_deletion_is_explicitly_incomplete', '''
        execute = print
        def remove():
            global execute
            del execute
        remove()
        execute(input())
        '''),
    Case('generator_global_write_needs_resume_semantics', '''
        code = '1'
        def replace():
            global code
            code = input()
            yield code
        pending = replace()
        eval(code)
        '''),
    Case('string_join_opaque_iterator_stays_incomplete', '''
        ''.join(value for value in unknown)
        eval('fixed')
        '''),
    Case('scheduled_global_write_cannot_certify_clean', '''
        import asyncio
        code = '1'
        async def replace():
            global code
            code = input()
        async def caller():
            asyncio.create_task(replace())
            eval(code)
        asyncio.run(caller())
        '''),
)


class GlobalWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts/python-globals' / uuid.uuid4().hex[:12]
        cls.artifacts.mkdir(parents=True)
        cls.helper_hash = hashlib.sha256(Path(taint_py.__file__).read_bytes()).hexdigest()
        (cls.artifacts / 'source.json').write_text(json.dumps({
            'helper_sha256': cls.helper_hash,
        }, indent=2) + '\n', encoding='utf-8')
        print(f'Global write artifacts: {cls.artifacts}', flush=True)

    def check_cases(self, cases, *, boundary=False):
        for case in cases:
            with self.subTest(case=case.name):
                directory = self.artifacts / case.name
                directory.mkdir()
                source = directory / 'view.py'
                source.write_text(case.source, encoding='utf-8')
                ast.parse(case.source)
                started = time.monotonic()
                records, error, status = [], None, 'FAIL'
                try:
                    try:
                        records = list(taint_py.run(RunContext(lang='python', files=[source])))
                    except taint_py.AnalysisLimit as exc:
                        if not boundary:
                            raise
                        error, status = str(exc), 'INCOMPLETE'
                    else:
                        self.assertFalse(boundary, 'unsupported global effects must not certify a complete scan')
                        self.assertEqual(sorted((r['rule'], r['line']) for r in records),
                                         case.expected, (case.source, records))
                        status = 'PASS'
                except Exception as exc:
                    error = f'{type(exc).__name__}: {exc}'
                    raise
                finally:
                    (directory / 'result.json').write_text(json.dumps({
                        'case': case.name, 'expected': case.expected, 'status': status,
                        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'helper_sha256': self.helper_hash, 'elapsed': time.monotonic() - started,
                        'error': error, 'findings': records,
                    }, indent=2) + '\n', encoding='utf-8')
                    print(f'[{case.name}] {status}', flush=True)

    def test_values_bindings_references_and_snapshots(self):
        self.check_cases(VALUE_CASES)

    def test_control_flow_normal_exceptional_and_shadowed(self):
        self.check_cases(CONTROL_CASES)

    def test_unsupported_global_effects_are_explicitly_incomplete(self):
        self.check_cases(BOUNDARY_CASES, boundary=True)

    def test_foreign_module_write_cannot_certify_clean(self):
        directory = self.artifacts / 'foreign_module_write'
        directory.mkdir()
        helper = directory / 'helper.py'
        helper.write_text("code = '1'\ndef replace(value):\n    global code\n    code = value\n", encoding='utf-8')
        source = directory / 'view.py'
        source.write_text('import helper\nhelper.replace(input())\neval(helper.code)\n', encoding='utf-8')
        records, error = [], None
        try:
            with self.assertRaisesRegex(taint_py.AnalysisLimit, 'global'):
                records = list(taint_py.run(RunContext(lang='python', files=[source, helper])))
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            (directory / 'result.json').write_text(json.dumps({
                'error': error, 'findings': records, 'helper_sha256': self.helper_hash,
            }, indent=2) + '\n', encoding='utf-8')

    def test_interrupted_setter_retains_observed_global_taint(self):
        source = ("code = '1'\ndef replace(value):\n    global code\n    code = value\n"
                  + "    padding = 'fixed'\n" * 100
                  + 'replace(input())\neval(code)\n')
        directory = self.artifacts / 'interrupted_setter'
        directory.mkdir()
        (directory / 'view.py').write_text(source, encoding='utf-8')
        engine = taint_py._Analysis(ast.parse(source))
        setter = next(function for function in engine.functions if function.name == 'replace')
        engine.scope_limits[setter] = 60
        engine.scope_remaining[setter] = 60
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'replace.*function work limit') as caught:
            engine.analyze()
        actual = sorted(effect[:3] for effect in caught.exception.effects)
        (directory / 'result.json').write_text(json.dumps({
            'effects': actual, 'error': str(caught.exception), 'helper_sha256': self.helper_hash,
        }, indent=2) + '\n', encoding='utf-8')
        self.assertEqual(actual, [('eval', len(source.splitlines()), 1)])
        self.assertGreater(engine.budget.remaining, 0)


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1',
                     'Set UBS_TAINT_E2E=1 for real global-effects CLI scans')
class GlobalWriteCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        GlobalWriteTests.setUpClass.__func__(cls)

    def test_module_and_runner_json_sarif(self):
        wanted = {'setter_argument_reaches_caller', 'strong_clean_replacement', 'callback_sink_replacement',
                  'helper_recreates_deleted_global_with_clean_callable',
                  'write_before_exception_reaches_handler',
                  'string_join_captures_unsafe_value_before_rebinding',
                  'string_join_captures_clean_value_before_rebinding',
                  'string_join_applies_global_helper_effect'}
        cases = [case for case in (*VALUE_CASES, *CONTROL_CASES) if case.name in wanted]
        self.assertEqual(len(cases), 8)
        cases.append(next(case for case in BOUNDARY_CASES
                          if case.name == 'deleted_builtin_shadow_survives_helper_sibling_join'))
        cases.append(next(case for case in BOUNDARY_CASES
                          if case.name == 'string_join_opaque_iterator_stays_incomplete'))
        cases.append(Case('foreign_module_write', '''
            import helper
            helper.replace(input())
            eval(helper.code)
            '''))
        self.assert_cli_cases(cases)

    def test_predicate_generators_module_and_runner_json_sarif(self):
        cases = [
            Case('any_stops_before_unsafe_write', """
                code = input()
                any((code := value) for value in ['fixed', input()])
                eval(code)
                """),
            Case('any_preserves_executed_unsafe_write', """
                code = 'fixed'
                any((code := value) for value in ['', input()])
                eval(code) # expect:eval
                """),
            Case('all_stops_before_unsafe_write', """
                code = input()
                all((code := value) for value in ['', input()])
                eval(code)
                """),
            Case('all_preserves_executed_unsafe_write', """
                code = 'fixed'
                all((code := value) for value in ['fixed', input()])
                eval(code) # expect:eval
                """),
        ]
        self.assert_cli_cases(cases)

    def test_first_yield_generators_module_and_runner_json_sarif(self):
        cases = [
            Case('next_preserves_first_unsafe_write', """
                code = '1'
                next((code := value) for value in [input(), '1'])
                eval(code) # expect:eval
                """),
            Case('next_stops_before_unsafe_tail_write', """
                code = input()
                next((code := value) for value in ['1', input()])
                eval(code)
                """),
            Case('next_default_taints_before_resume', """
                code = '1'
                result = next((code for unused in [1]), (code := input()))
                eval(result) # expect:eval
                """),
            Case('next_default_cleans_before_resume', """
                code = input()
                result = next((code for unused in [1]), (code := '1'))
                eval(result)
                """),
            Case('next_uses_tainted_default_after_exhaustion', """
                result = next((value for value in []), input())
                eval(result) # expect:eval
                """),
            Case('next_discards_unused_tainted_default', """
                result = next((value for value in ['1']), input())
                eval(result)
                """),
            Case('next_readonly_builtin_alias_selects_first_value', """
                import builtins as native
                result = native.next(value for value in [input(), '1'])
                eval(result) # expect:eval
                """),
            Case('next_replaced_builtin_stays_incomplete', """
                import builtins
                builtins.next = lambda iterator: input()
                result = builtins.next(value for value in ['1'])
                eval(result)
                """),
        ]
        self.assert_cli_cases(cases)

    def test_literal_execution_revokes_next_authority_json_sarif(self):
        cases = [
            Case('literal_next_loop_replacement', """
                import os
                os.system(input()) # expect:command
                for unused in [0, 1]:
                    result = next(value for value in ["'fixed'"])
                    eval("__import__('builtins').__dict__.__setitem__('next', lambda values: input())")
                    os.system(result)
                """),
            Case('literal_next_saved_cursor_replacement', """
                import os
                os.system(input()) # expect:command
                pending = (value for value in ["'fixed'"])
                eval("__import__('builtins').__dict__.__setitem__('next', lambda values: input())")
                result = next(pending)
                os.system(result)
                """),
            Case('literal_next_repeated_function_replacement', """
                import os
                os.system(input()) # expect:command
                def read():
                    result = next(value for value in ["'fixed'"])
                    eval("__import__('builtins').__dict__.__setitem__('next', lambda values: input())")
                    return result
                os.system(read())
                os.system(read())
                """),
        ]
        self.assert_cli_cases(cases)

    def test_captured_formatted_values_module_and_runner_json_sarif(self):
        cases = [
            Case('formatted_min_named_key_keeps_source', """
                def order(record):
                    return len(record)
                code = f"{input()}"
                selected = min(([code] for unused in (1, 2)), key=order)
                eval(selected[0]) # expect:eval
                """),
            Case('formatted_max_named_key_keeps_clean_replacement', """
                def order(record):
                    return (len(record), record[0])
                code = input()
                code = f"{'1'}"
                selected = max(([code] for unused in (1, 2)), key=order)
                eval(selected[0])
                """),
            Case('formatted_sorted_keeps_captured_unsafe_alias', """
                def order(record):
                    return record[0]
                code = f"{input()}"
                saved = code
                code = '1'
                selected = sorted(([saved] for unused in (1, 2)), key=order)[0]
                eval(selected[0]) # expect:eval
                """),
            Case('formatted_min_keeps_captured_clean_alias', """
                code = f"{'1'}"
                saved = code
                code = input()
                selected = min(([saved] for unused in (1, 2)), key=len)
                eval(selected[0])
                """),
            Case('formatted_next_keeps_native_string_spec', """
                code = f"{input()!s:>3}"
                selected = next(value for value in [code])
                eval(selected) # expect:eval
                """),
            Case('formatted_next_keeps_native_numeric_value', """
                code = f"{1}"
                selected = next(value for value in [code])
                eval(selected)
                """),
            Case('formatted_min_preserves_taint_at_branch_join', """
                if input():
                    code = f"{input()}"
                else:
                    code = f"{'1'}"
                selected = min(([code] for unused in (1, 2)), key=len)
                eval(selected[0]) # expect:eval
                """),
            Case('formatted_next_reads_live_value_on_resume', """
                code = '1'
                pending = (code for unused in [0])
                code = f"{input()}"
                selected = next(pending)
                eval(selected) # expect:eval
                """),
        ]
        self.assert_cli_cases(cases)

    def assert_cli_cases(self, cases):
        for case in cases:
            incomplete = case.name in {'foreign_module_write', 'deleted_builtin_shadow_survives_helper_sibling_join',
                                       'string_join_opaque_iterator_stays_incomplete',
                                       'next_replaced_builtin_stays_incomplete',
                                       'literal_next_loop_replacement',
                                       'literal_next_saved_cursor_replacement',
                                       'literal_next_repeated_function_replacement',
                                       'formatted_max_named_key_keeps_clean_replacement',
                                       'formatted_min_preserves_taint_at_branch_join',
                                       'formatted_next_reads_live_value_on_resume'}
            # The full scanner also warns about eval syntax independently of
            # whether its operand is tainted. Keep those existing rules in
            # the oracle; the strong reset must remove only the taint finding.
            syntax_sites = ([] if case.name in {'callback_sink_replacement',
                                               'helper_recreates_deleted_global_with_clean_callable',
                                               'deleted_builtin_shadow_survives_helper_sibling_join'} else [
                ('py.eval-exec', len(case.source.splitlines())),
                ('py.security.eval-exec-usage', len(case.source.splitlines()))])
            expected_sites = sorted([*case.expected, *syntax_sites])
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=case.name, meta=meta, format=output):
                        name = ('runner' if meta else 'module') + '-' + output
                        directory = self.artifacts / case.name / name
                        directory.mkdir(parents=True)
                        source = directory / 'view.py'
                        source.write_text(case.source, encoding='utf-8')
                        if case.name == 'foreign_module_write':
                            (directory / 'helper.py').write_text(
                                "code = '1'\ndef replace(value):\n    global code\n    code = value\n",
                                encoding='utf-8')
                        temporary = directory / 'temporary'
                        temporary.mkdir()
                        cache = directory / 'cache'
                        command = ([str(ROOT / 'ubs'), '--only=python'] if meta else
                                   ['bash', str(ROOT / 'modules/ubs-python.sh')])
                        command += ['--ci', '--fail-on-warning', '--format=' + output,
                                    '--skip=' + ','.join(str(category) for category in range(1, 24)
                                                        if category != 7),
                                    str(directory if case.name == 'foreign_module_write' else source)]
                        environment = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                                           UBS_CACHE_DIR=str(cache), XDG_CACHE_HOME=str(cache),
                                           TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
                        started = time.monotonic()
                        print(f'[{case.name}:{name}] RUN', flush=True)
                        result = subprocess.run(command, cwd=directory, env=environment,
                                                text=True, capture_output=True, timeout=120)
                        (directory / 'stdout.log').write_text(result.stdout, encoding='utf-8')
                        (directory / 'stderr.log').write_text(result.stderr, encoding='utf-8')
                        (directory / 'command.json').write_text(json.dumps({
                            'command': command, 'cwd': str(directory), 'returncode': result.returncode,
                            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                            'helper_sha256': self.helper_hash, 'elapsed': time.monotonic() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, 2 if incomplete else int(bool(expected_sites)),
                                         (result.stdout, result.stderr))
                        payload = json.loads(result.stdout)
                        actual, all_sites = [], []
                        if output == 'sarif':
                            self.assertEqual(payload['version'], '2.1.0', payload)
                            self.assertTrue(payload['runs'], payload)
                            failed = any(invocation.get('executionSuccessful') is False
                                         for run in payload['runs'] for invocation in run.get('invocations', []))
                            self.assertEqual(failed, incomplete, payload)
                            for run in payload['runs']:
                                for record in run.get('results', []):
                                    location = record['locations'][0]['physicalLocation']
                                    all_sites.append((record['ruleId'], location['region']['startLine']))
                                    if record['ruleId'].startswith(('py.taint.', 'python.taint.')):
                                        self.assertTrue(location['artifactLocation']['uri'].endswith('view.py'))
                                        actual.append((record['ruleId'], location['region']['startLine']))
                        else:
                            self.assertEqual(payload['status'], 'partial' if incomplete else 'ok', payload)
                            if not incomplete:
                                totals = payload['totals'] if meta else payload
                                self.assertEqual(totals['critical'], len(expected_sites), payload)
                                self.assertEqual(totals['warning'], 0, payload)
                            for record in payload.get('findings', []):
                                rule = record.get('rule_id', record.get('rule', ''))
                                sites = ([(rule, record['line'])] if meta else
                                         [(rule, sample['line']) for sample in record['samples']])
                                all_sites.extend(sites)
                                if rule.startswith(('py.taint.', 'python.taint.')):
                                    if not meta:
                                        self.assertEqual(record['count'], len(record['samples']), record)
                                    actual.extend(sites)
                        if incomplete:
                            diagnostic = ('foreign module global write' if case.name == 'foreign_module_write'
                                          else 'generator materialization reads an opaque operand'
                                          if case.name == 'string_join_opaque_iterator_stays_incomplete'
                                          else 'generator next computed callable lifetime is unresolved'
                                          if case.name == 'next_replaced_builtin_stays_incomplete'
                                          else 'generator next consumer identity is unresolved'
                                          if case.name.startswith('literal_next_')
                                          else 'generator expression live delayed reads require resume-state analysis'
                                          if case.name.startswith('formatted_')
                                          else 'conditional global creation or deletion')
                            self.assertIn(diagnostic, result.stdout + result.stderr)
                            if case.name.startswith('formatted_'):
                                # Captured formatting does not yet model a
                                # delayed global read across multiple stores.
                                # Keep these boundaries explicit and retain
                                # both syntax findings in the partial report.
                                self.assertEqual(actual, [], payload)
                                self.assertEqual(sorted(all_sites), sorted(syntax_sites), payload)
                                if output == 'json':
                                    totals = payload['totals'] if meta else payload
                                    self.assertEqual(totals['critical'], len(syntax_sites), payload)
                                    self.assertEqual(totals['warning'], 0, payload)
                            if case.name.startswith('literal_next_'):
                                # Refusing later dynamic execution must retain
                                # the already observed command-injection sink.
                                self.assertEqual(sorted(actual), case.expected, payload)
                        else:
                            self.assertEqual(sorted(actual), case.expected, payload)
                            self.assertEqual(sorted(all_sites), expected_sites, payload)
                        print(f'[{case.name}:{name}] PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
