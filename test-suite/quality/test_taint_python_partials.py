"""Independent security oracle for deferred functools.partial calls.

The fixtures follow Python's public binding contract, not analyzer internals:
https://docs.python.org/3.14/library/functools.html#functools.partial
Bound positional arguments precede call-time arguments; call-time keywords
replace bound keywords. Values are captured when the partial is constructed,
while captured mutable objects and function closure cells remain shared.

All snippets are parsed and statically analyzed, never imported or executed.
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
import sys
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


BINDING_CASES = (
    Case('immediate_eval', '''
        from functools import partial
        partial(eval, input())() # expect:eval
        '''),
    Case('deferred_system', '''
        import functools as ft
        import os
        run = ft.partial(os.system, input())
        run() # expect:command
        '''),
    Case('local_helper_sink', '''
        from functools import partial
        def execute(code):
            eval(code) # expect:eval
        partial(execute, input())()
        '''),
    Case('uninvoked_sink_remains_deferred', '''
        from functools import partial
        import os
        pending_eval = partial(eval, input())
        pending_command = partial(os.system, input())
        '''),
    Case('uninvoked_local_helper_remains_deferred', '''
        from functools import partial
        def execute(code):
            eval(code)
        pending = partial(execute, input())
        '''),
    Case('import_alias', '''
        from functools import partial as bind
        runner = bind(eval)
        runner(input()) # expect:eval
        '''),
    Case('shadowed_constructor_uses_local_contract', '''
        from functools import partial
        def partial(function, value):
            return print
        pending = partial(eval, input())
        pending()
        '''),
    Case('captured_constructor_survives_rebinding', '''
        from functools import partial
        bind = partial
        partial = print
        bind(eval, input())() # expect:eval
        '''),
    Case('captured_constructor_survives_module_member_write', '''
        import functools
        bind = functools.partial
        functools.partial = print
        bind(eval, input())() # expect:eval
        '''),
    Case('target_is_captured_before_argument_evaluation', '''
        from functools import partial
        execute = eval
        pending = partial(execute, input(execute := print))
        pending() # expect:eval
        '''),
    Case('captured_sink_survives_rebinding', '''
        from functools import partial
        execute = eval
        pending = partial(execute, input())
        execute = print
        pending() # expect:eval
        '''),
    Case('captured_harmless_target_stays_harmless', '''
        from functools import partial
        execute = print
        pending = partial(execute, input())
        execute = eval
        pending()
        '''),
    Case('tainted_scalar_is_snapshotted', '''
        from functools import partial
        code = input()
        pending = partial(eval, code)
        code = '1'
        pending() # expect:eval
        '''),
    Case('safe_scalar_is_snapshotted', '''
        from functools import partial
        code = '1'
        pending = partial(eval, code)
        code = input()
        pending()
        '''),
    Case('nested_positional_binding', '''
        from functools import partial
        outer = partial(partial(eval), input())
        outer() # expect:eval
        '''),
    Case('bound_classmethod_keeps_receiver_and_code_argument', '''
        from functools import partial
        class Service:
            @classmethod
            def execute(owner, code):
                eval(code) # expect:eval
        pending = partial(Service.execute, input())
        pending()
        '''),
    Case('bound_classmethod_clean_return', '''
        from functools import partial
        class Service:
            @classmethod
            def clean(owner, ignored):
                return '1'
        pending = partial(Service.clean, input())
        eval(pending())
        '''),
)

KEYWORD_CASES = (
    Case('call_keyword_replaces_tainted_binding', '''
        from functools import partial
        def execute(*, code):
            eval(code)
        pending = partial(execute, code=input())
        pending(code='1')
        '''),
    Case('call_keyword_replaces_clean_binding', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        pending = partial(execute, code='1')
        pending(code=input())
        '''),
    Case('outer_partial_replaces_tainted_keyword', '''
        from functools import partial
        def execute(*, code):
            eval(code)
        pending = partial(partial(execute, code=input()), code='1')
        pending()
        '''),
    Case('outer_partial_replaces_clean_keyword', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        pending = partial(partial(execute, code='1'), code=input())
        pending()
        '''),
    Case('call_positional_arguments_follow_bound_arguments', '''
        from functools import partial
        def execute(label, code):
            eval(code) # expect:eval
        pending = partial(execute, 'fixed-label')
        pending(input())
        '''),
    Case('irrelevant_bound_argument_does_not_taint_code', '''
        from functools import partial
        def execute(label, code):
            eval(code)
        pending = partial(execute, input())
        pending('1')
        '''),
    Case('invocation_overrides_both_nested_keyword_bindings', '''
        from functools import partial
        def execute(*, code):
            eval(code)
        inner = partial(execute, code='1')
        outer = partial(inner, code=input())
        outer(code='1')
        '''),
    Case('nested_clean_keyword_does_not_hide_call_keyword', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        inner = partial(execute, code=input())
        outer = partial(inner, code='1')
        outer(code=input())
        '''),
)

SUMMARY_CASES = (
    Case('helper_returns_partial', '''
        from functools import partial
        def bind(code):
            return partial(eval, code)
        pending = bind(input())
        pending() # expect:eval
        '''),
    Case('callback_parameter_invokes_partial', '''
        from functools import partial
        def invoke(callback):
            callback() # expect:eval
        invoke(partial(eval, input()))
        '''),
    Case('closure_is_read_at_invocation', '''
        from functools import partial
        code = '1'
        def execute():
            eval(code) # expect:eval
        pending = partial(execute)
        code = input()
        pending()
        '''),
    Case('mutable_bound_argument_observes_later_write', '''
        from functools import partial
        def execute(values):
            eval(values[0]) # expect:eval
        values = ['1']
        pending = partial(execute, values)
        values[0] = input()
        pending()
        '''),
    Case('bound_mutator_keeps_receiver_identity', '''
        from functools import partial
        values = []
        alias = values
        append = partial(values.append, input())
        values = []
        append()
        eval(str(alias)) # expect:eval
        '''),
    Case('bound_receiver_is_captured_before_argument_evaluation', '''
        from functools import partial
        values = []
        original = values
        pending = partial(values.append, input(values := []))
        pending()
        eval(str(original)) # expect:eval
        '''),
    Case('bound_sanitizer_preserves_domain', '''
        from functools import partial
        from html import escape
        escape_html = partial(escape, quote=True)
        HttpResponse(escape_html(input()))
        '''),
    Case('bound_sanitizer_does_not_cross_domains', '''
        from functools import partial
        from html import escape
        escape_html = partial(escape, quote=True)
        eval(escape_html(input())) # expect:eval
        '''),
)

CELL_CASES = (
    Case('nonlocal_target_can_become_a_sink_after_binding', '''
        from functools import partial
        def factory(callback):
            def execute(code):
                callback(code) # expect:eval
            def replace(new):
                nonlocal callback
                callback = new
                return partial(execute, input())
            return replace
        replace = factory(print)
        pending = replace(print)
        replace(eval)
        pending()
        '''),
    Case('nonlocal_target_can_become_harmless_after_binding', '''
        from functools import partial
        def factory(callback):
            def execute(code):
                callback(code)
            def replace(new):
                nonlocal callback
                callback = new
                return partial(execute, input())
            return replace
        replace = factory(eval)
        pending = replace(eval)
        replace(print)
        pending()
        '''),
    Case('nonlocal_value_is_live_inside_partial_target', '''
        from functools import partial
        def factory(value):
            def execute():
                eval(value) # expect:eval
            def replace(new):
                nonlocal value
                value = new
                return partial(execute)
            return replace
        replace = factory('1')
        pending = replace('1')
        replace(input())
        pending()
        '''),
    Case('nonlocal_clean_write_kills_previous_value', '''
        from functools import partial
        def factory(value):
            def execute():
                eval(value)
            def replace(new):
                nonlocal value
                value = new
                return partial(execute)
            return replace
        replace = factory('1')
        pending = replace(input())
        replace('1')
        pending()
        '''),
    Case('returned_partials_do_not_merge_argument_snapshots', '''
        from functools import partial
        def bind(value):
            return partial(eval, value)
        unsafe = bind(input())
        clean = bind('1')
        clean()
        unsafe() # expect:eval
        '''),
    Case('uninvoked_partial_does_not_pollute_another_instance', '''
        from functools import partial
        def bind(value):
            return partial(eval, value)
        clean = bind('1')
        uninvoked = bind(input())
        clean()
        '''),
)

PROCESS_CASES = (
    Case('global_bool_update_through_intermediary_preserves_interpreter_source', '''
        from functools import partial
        import subprocess
        flag = True
        def bind():
            return partial(subprocess.run, shell=flag)
        def replace():
            global flag
            flag = False
        def prepare():
            replace()
            return bind()
        pending = prepare()
        pending(['python3', '-c', input()]) # expect:command
        '''),
    Case('global_bool_update_through_intermediary_keeps_interpreter_tail_safe', '''
        from functools import partial
        import subprocess
        flag = False
        def bind():
            return partial(subprocess.run, shell=flag)
        def replace():
            global flag
            flag = True
        def prepare():
            replace()
            return bind()
        pending = prepare()
        pending(['python3', '-c', input()])
        '''),
    Case('captured_shell_true_executes_dynamic_source', '''
        from functools import partial
        import subprocess
        shell = True
        pending = partial(subprocess.run, shell=shell)
        shell = False
        pending(input()) # expect:command
        '''),
    Case('captured_shell_false_keeps_argv_data_safe', '''
        from functools import partial
        import subprocess
        shell = False
        pending = partial(subprocess.run, ['echo', input()], shell=shell)
        shell = True
        pending()
        '''),
    Case('captured_shell_false_keeps_interpreter_code_executable', '''
        from functools import partial
        import subprocess
        shell = False
        pending = partial(subprocess.run, ['python3', '-c', input()], shell=shell)
        shell = True
        pending() # expect:command
        '''),
    Case('captured_shell_true_keeps_interpreter_tail_as_data', '''
        from functools import partial
        import subprocess
        shell = True
        pending = partial(subprocess.run, ['python3', '-c', input()], shell=shell)
        shell = False
        pending()
        '''),
    Case('helper_preserves_captured_shell_true', '''
        from functools import partial
        import subprocess
        def bind(shell):
            return partial(subprocess.run, ['python3', '-c', input()], shell=shell)
        pending = bind(True)
        pending()
        '''),
    Case('helper_preserves_captured_shell_false', '''
        from functools import partial
        import subprocess
        def bind(shell):
            return partial(subprocess.run, ['python3', '-c', input()], shell=shell)
        pending = bind(False)
        pending() # expect:command
        '''),
    Case('shell_false_call_keyword_overrides_true_binding', '''
        from functools import partial
        import subprocess
        pending = partial(subprocess.run, ['echo', input()], shell=True)
        pending(shell=False)
        '''),
    Case('shell_true_call_keyword_overrides_false_binding', '''
        from functools import partial
        import subprocess
        pending = partial(subprocess.run, shell=False)
        pending(input(), shell=True) # expect:command
        '''),
    Case('executable_override_selects_interpreter_payload', '''
        from functools import partial
        import subprocess
        pending = partial(subprocess.run, ['echo', '-c', input()], executable='python3')
        pending() # expect:command
        '''),
    Case('executable_override_makes_interpreter_arguments_data', '''
        from functools import partial
        import subprocess
        pending = partial(subprocess.run, ['python3', '-c', input()], executable='/bin/echo')
        pending()
        '''),
    Case('partial_shell_sanitizer_contract_is_preserved', '''
        from functools import partial
        import shlex
        import subprocess
        pending = partial(subprocess.run, shell=True)
        pending('echo ' + shlex.quote(input()))
        '''),
    Case('partial_quote_cannot_sanitize_executable_selection', '''
        from functools import partial
        import shlex
        import subprocess
        pending = partial(subprocess.run, ['echo'], executable=shlex.quote(input()))
        pending() # expect:command
        '''),
)

BOUNDARY_CASES = (
    # Requests invokes auth(request) before sending. A known HTTP URL sink
    # does not account for execution of an otherwise unmodeled callback.
    # https://requests.readthedocs.io/en/stable/user/advanced/#custom-authentication
    Case('http_auth_partial_helper_cannot_certify_clean', '''
        from functools import partial
        import requests
        def authorize(code, prepared):
            eval(code) # expect:eval
            return prepared
        requests.get('https://example.invalid/', auth=partial(authorize, input()))
        '''),
    Case('http_saved_auth_partial_cannot_certify_clean', '''
        from functools import partial
        import requests
        def authorize(code, prepared):
            eval(code) # expect:eval
            return prepared
        auth = partial(authorize, input())
        requests.request('GET', 'https://example.invalid/', auth=auth)
        '''),
    # Flask renders inside an actual application context, and the Jinja
    # template explicitly invokes the supplied callable.
    # https://jinja.palletsprojects.com/en/stable/templates/#other-operators
    Case('template_partial_callback_cannot_certify_clean', '''
        from functools import partial
        from flask import Flask, render_template_string
        app = Flask(__name__)
        with app.app_context():
            render_template_string('{{ action() }}', action=partial(eval, input())) # expect:eval
        '''),
    Case('placeholder_cannot_hide_dynamic_code', '''
        from functools import partial, Placeholder
        pending = partial(eval, Placeholder)
        pending(input()) # expect:eval
        '''),
    Case('unknown_starred_arguments_cannot_certify_clean', '''
        from functools import partial
        pending = partial(eval, *request.args.getlist('code'))
        pending() # expect:eval
        '''),
    Case('mutated_keywords_cannot_reuse_stale_clean_binding', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        pending = partial(execute, code='1')
        pending.keywords['code'] = input()
        pending()
        '''),
    Case('keyword_alias_mutation_cannot_certify_clean', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        pending = partial(execute, code='1')
        keywords = pending.keywords
        keywords.update(code=input())
        pending()
        '''),
    Case('unknown_keyword_expansion_can_override_bound_code', '''
        from functools import partial
        def execute(*, code):
            eval(code) # expect:eval
        pending = partial(execute, code='1')
        pending(**request.args)
        '''),
    Case('partial_in_container_cannot_lose_its_sink', '''
        from functools import partial
        callbacks = [partial(eval, input())]
        callbacks[0]() # expect:eval
        '''),
    Case('partial_in_object_field_cannot_lose_its_sink', '''
        from functools import partial
        class Holder:
            pass
        holder = Holder()
        holder.callback = partial(eval, input())
        holder.callback() # expect:eval
        '''),
    Case('unresolved_callback_consumer_cannot_certify_clean', '''
        from functools import partial
        register(partial(eval, input())) # expect:eval
        '''),
    Case('async_exec_preexec_callback_cannot_certify_clean', '''
        import asyncio
        from functools import partial
        async def start():
            pending = partial(eval, input())
            await asyncio.create_subprocess_exec('echo', preexec_fn=pending) # expect:eval
        asyncio.run(start())
        '''),
    Case('async_shell_preexec_callback_cannot_certify_clean', '''
        import asyncio
        from functools import partial
        async def start():
            pending = partial(eval, input())
            await asyncio.create_subprocess_shell('echo safe', preexec_fn=pending) # expect:eval
        asyncio.run(start())
        '''),
    Case('preexec_callback_consumer_cannot_certify_clean', '''
        from functools import partial
        import subprocess
        subprocess.run(['echo'], preexec_fn=partial(eval, input())) # expect:eval
        '''),
    Case('preexec_saved_callback_cannot_certify_clean', '''
        from functools import partial
        import subprocess
        pending = partial(eval, input())
        subprocess.Popen(['echo'], preexec_fn=pending) # expect:eval
        '''),
    Case('preexec_helper_callback_cannot_certify_clean', '''
        from functools import partial
        import subprocess
        def run(callback):
            subprocess.run(['echo'], preexec_fn=callback) # expect:eval
        run(partial(eval, input()))
        '''),
    Case('framework_dependency_cannot_certify_clean', '''
        from functools import partial
        from fastapi import FastAPI, Depends
        app = FastAPI()
        @app.get('/')
        def endpoint(value=Depends(partial(eval, input()))): # expect:eval
            return value
        '''),
)


class PartialFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / 'test-suite/artifacts/python-partials' / uuid.uuid4().hex[:12]
        cls.artifacts.mkdir(parents=True)
        paths = (Path(__file__), Path(taint_py.__file__))
        identity = {
            'python': sys.version,
            'executable': sys.executable,
            'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                            text=True, timeout=30).strip(),
            'sources': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in paths},
        }
        (cls.artifacts / 'source-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
        print(f'[{cls.__name__}] artifacts: {cls.artifacts}', flush=True)

    def check_cases(self, cases, *, incomplete_allowed=False):
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
                        if not incomplete_allowed:
                            raise
                        error = f'{type(exc).__name__}: {exc}'
                        status = 'INCOMPLETE'
                    else:
                        actual = sorted((record['rule'], record['line']) for record in records)
                        self.assertEqual(actual, case.expected, (case.source, records))
                        for record in records:
                            self.assertEqual(Path(record['path']).name, 'view.py', record)
                            self.assertGreater(record['col'], 0, record)
                            self.assertEqual(record['layer'], 'taint', record)
                            self.assertEqual(record['lang'], 'python', record)
                        status = 'PASS'
                except Exception as exc:
                    error = f'{type(exc).__name__}: {exc}'
                    raise
                finally:
                    (directory / 'result.json').write_text(json.dumps({
                        'case': case.name, 'expected': case.expected, 'status': status,
                        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'elapsed': time.monotonic() - started, 'error': error, 'findings': records,
                    }, indent=2) + '\n', encoding='utf-8')
                    print(f'[{case.name}] {status}', flush=True)

    def test_deferred_binding_and_snapshots(self):
        self.check_cases(BINDING_CASES)

    def test_call_arguments_and_keyword_override(self):
        self.check_cases(KEYWORD_CASES)

    def test_summaries_mutables_and_sanitizers(self):
        self.check_cases(SUMMARY_CASES)

    def test_live_closure_cells_and_partial_instance_isolation(self):
        self.check_cases(CELL_CASES)

    def test_subprocess_binding_preserves_code_and_data_roles(self):
        self.check_cases(PROCESS_CASES)

    def test_unsupported_binding_cannot_silently_certify_clean(self):
        self.check_cases(BOUNDARY_CASES, incomplete_allowed=True)


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1',
                     'Set UBS_TAINT_E2E=1 for real partial CLI scans')
class PartialCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PartialFlowTests.setUpClass.__func__(cls)

    def test_public_module_and_runner_json_sarif(self):
        wanted = {'immediate_eval', 'deferred_system', 'uninvoked_sink_remains_deferred',
                  'helper_returns_partial', 'captured_shell_true_executes_dynamic_source',
                  'captured_shell_false_keeps_argv_data_safe'}
        cases = tuple(case for group in (BINDING_CASES, SUMMARY_CASES, PROCESS_CASES)
                      for case in group if case.name in wanted)
        self.assertEqual(len(cases), len(wanted))
        for case in cases:
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=case.name, meta=meta, format=output):
                        name = ('runner' if meta else 'module') + '-' + output
                        directory = self.artifacts / case.name / name
                        directory.mkdir(parents=True)
                        source = directory / 'view.py'
                        source.write_text(case.source, encoding='utf-8')
                        temporary = directory / 'temporary'
                        temporary.mkdir()
                        cache = directory / 'cache'
                        command = ([str(ROOT / 'ubs'), '--only=python'] if meta else
                                   ['bash', str(ROOT / 'modules/ubs-python.sh')])
                        command += ['--ci', '--fail-on-warning', '--format=' + output,
                                    '--skip=' + ','.join(str(category) for category in range(1, 24)
                                                        if category != 7), str(source)]
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
                            'elapsed': time.monotonic() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, int(bool(case.expected)),
                                         (result.stdout, result.stderr))
                        payload = json.loads(result.stdout)
                        actual = []
                        if output == 'sarif':
                            self.assertEqual(payload['version'], '2.1.0', payload)
                            self.assertTrue(payload['runs'], payload)
                            for run in payload['runs']:
                                self.assertFalse(any(item.get('executionSuccessful') is False
                                                     for item in run.get('invocations', [])), run)
                                for record in run.get('results', []):
                                    if record['ruleId'].startswith(('py.taint.', 'python.taint.')):
                                        location = record['locations'][0]['physicalLocation']
                                        self.assertTrue(location['artifactLocation']['uri'].endswith('view.py'))
                                        actual.append((record['ruleId'], location['region']['startLine']))
                        else:
                            self.assertEqual(payload['status'], 'ok', payload)
                            totals = payload['totals'] if meta else payload
                            self.assertEqual(totals['critical'], len(case.expected), payload)
                            for record in payload.get('findings', []):
                                rule = record.get('rule_id', record.get('rule', ''))
                                if rule.startswith(('py.taint.', 'python.taint.')):
                                    if meta:
                                        actual.append((rule, record['line']))
                                    else:
                                        self.assertEqual(record['count'], len(record['samples']), record)
                                        actual.extend((rule, sample['line']) for sample in record['samples'])
                        self.assertEqual(sorted(actual), case.expected, payload)
                        print(f'[{case.name}:{name}] PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
