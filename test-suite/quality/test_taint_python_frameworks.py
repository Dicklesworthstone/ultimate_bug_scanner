"""Framework entry-point regressions. Fixture source is parsed, never imported."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_taint_python_dataflow import ROOT, SourceTest


class FastAPIInputTests(SourceTest):
    def test_explicit_parameter_markers_reach_all_sink_domains(self):
        for marker in ('Query', 'Path', 'Body', 'Form', 'Header', 'Cookie', 'File'):
            for sink, rule in (('eval(value)', 'eval'), ('cursor.execute(value)', 'sql'),
                               ('os.system(value)', 'command'), ('HttpResponse(value)', 'xss')):
                with self.subTest(marker=marker, sink=sink):
                    self.assert_rules(f'from fastapi import {marker}\ndef endpoint(value={marker}()):\n    {sink}\n', rule)

    def test_annotated_and_keyword_only_parameters(self):
        self.assert_rules('''
            from typing import Annotated
            from fastapi import Query
            async def endpoint(*, value: Annotated[str, Query()] = 'default'):
                eval(value)
        ''', 'eval')

    def test_import_and_type_aliases(self):
        for imports, annotation in (
            ('from typing_extensions import Annotated as A\nfrom fastapi import Header as H', 'A[str, H()]'),
            ('import typing as t\nimport fastapi as api', 't.Annotated[str, api.Cookie()]'),
            ('from typing import Annotated\nfrom fastapi import Body\nPayload = Annotated[str, Body()]', 'Payload'),
        ):
            with self.subTest(annotation=annotation):
                self.assert_rules(imports + f'\ndef endpoint(value: {annotation}):\n    eval(value)\n', 'eval')

    def test_forward_annotation_is_parsed_not_executed(self):
        self.assert_rules('''
            from typing import Annotated
            from fastapi import Query
            def endpoint(value: 'Annotated[str, Query()]'):
                eval(value)
        ''', 'eval')
        self.assert_rules('def endpoint(value: "__import__(\'no_such_module\').run()"):\n    eval(value)\n')

    def test_function_summaries_propagate_framework_parameters(self):
        findings = self.assert_rules('''
            from fastapi import Body
            def execute(text):
                cursor.execute(text)
            def endpoint(payload=Body()):
                execute(payload)
        ''', 'sql')
        self.assertEqual(findings[0]['line'], 3)
        self.assertIn('Body', findings[0]['message'])
        self.assertIn('payload', findings[0]['message'])

    def test_strong_updates_and_sink_specific_sanitizers(self):
        self.assert_rules("from fastapi import Query\ndef endpoint(value=Query()):\n    value = 'safe'\n    eval(value)\n")
        self.assert_rules('from fastapi import Query\ndef endpoint(value=Query()):\n    HttpResponse(html.escape(value))\n')
        self.assert_rules('from fastapi import Query\ndef endpoint(value=Query()):\n    cursor.execute(html.escape(value))\n', 'sql')
        self.assert_rules("from fastapi import Query\ndef endpoint(value=Query()):\n    cursor.execute('select ?',(value,))\n")
        self.assert_rules("from fastapi import Query\ndef endpoint(value=Query()):\n    subprocess.run(['echo', value])\n")

    def test_unrelated_and_shadowed_marker_names_are_not_sources(self):
        for prefix in ('', 'from pathlib import Path', 'from elsewhere import Query',
                       'from fastapi import Query\nQuery = other', 'import fastapi\nfastapi = other'):
            marker = 'fastapi.Query' if prefix.startswith('import fastapi') else 'Path' if 'pathlib' in prefix else 'Query'
            with self.subTest(prefix=prefix):
                self.assert_rules(prefix + f'\ndef ordinary(value={marker}()):\n    eval(value)\n')

    def test_marker_identity_is_captured_at_definition_time(self):
        self.assert_rules('from fastapi import Query\ndef endpoint(value=Query()):\n    eval(value)\nQuery = other\n', 'eval')

    def test_scope_local_import_and_marker_shadowing(self):
        self.assert_rules('''
            def factory():
                from fastapi import Query as Q
                def endpoint(value=Q()):
                    eval(value)
        ''', 'eval')
        self.assert_rules('''
            from fastapi import Query
            def factory(Query):
                def ordinary(value=Query()):
                    eval(value)
        ''')

    def test_real_router_decorators_supply_implicit_inputs(self):
        for constructor in ('FastAPI', 'APIRouter'):
            self.assert_rules(f'''
                from fastapi import {constructor}
                api = {constructor}()
                @api.get('/search')
                def endpoint(q: str = 'default'):
                    eval(q)
            ''', 'eval')

    def test_router_and_constructor_aliases(self):
        self.assert_rules('''
            import fastapi as api
            make = api.FastAPI
            app = make()
            router = app
            @router.post('/query')
            async def endpoint(query: str):
                cursor.execute(query)
        ''', 'sql')

    def test_non_router_decorators_do_not_taint_ordinary_parameters(self):
        self.assert_rules("@cache.get('key')\ndef ordinary(value):\n    eval(value)\n")
        self.assert_rules("from fastapi import FastAPI\nFastAPI = other\napp = FastAPI()\n@app.get('/')\ndef ordinary(value):\n    eval(value)\n")

    def test_request_sources_do_not_escape_through_constant_returns(self):
        self.assert_rules('''
            from fastapi import Query
            def endpoint(value=Query()):
                return 'safe'
            eval(endpoint('trusted'))
        ''')

    def test_dependency_and_response_parameters_are_not_blindly_tainted(self):
        self.assert_rules('''
            from fastapi import FastAPI, Depends, Response, BackgroundTasks
            app = FastAPI()
            @app.get('/')
            def endpoint(connection=Depends(database), response: Response=None, tasks: BackgroundTasks=None):
                eval(connection)
                eval(response.status_code)
                eval(tasks)
        ''')


class TypedRequestTests(SourceTest):
    def test_request_members_are_sources_regardless_of_parameter_name(self):
        for import_ in ('from fastapi import Request', 'from starlette.requests import Request'):
            for member in ('query_params', 'path_params', 'headers', 'cookies', 'body()', 'json()', 'form()'):
                with self.subTest(import_=import_, member=member):
                    self.assert_rules(import_ + f'\nasync def endpoint(incoming: Request):\n    eval(incoming.{member})\n', 'eval')

    def test_typed_request_alias_and_reassignment(self):
        self.assert_rules('''
            from fastapi import Request as R
            def endpoint(incoming: R):
                other = incoming
                eval(other.query_params['q'])
        ''', 'eval')
        self.assert_rules('''
            from fastapi import Request
            def endpoint(incoming: Request):
                incoming = trusted
                eval(incoming.query_params['q'])
        ''')

    def test_request_service_state_is_not_assumed_attacker_controlled(self):
        self.assert_rules('''
            from fastapi import FastAPI, Request
            app = FastAPI()
            @app.get('/')
            def endpoint(incoming: Request):
                eval(incoming.state.trusted_code)
        ''')

    def test_unrelated_request_type_does_not_introduce_sources(self):
        self.assert_rules('from elsewhere import Request\ndef ordinary(incoming: Request):\n    eval(incoming.headers)\n')
        self.assert_rules('from fastapi import Request\nRequest = other\ndef ordinary(incoming: Request):\n    eval(incoming.headers)\n')

    def test_untyped_standard_request_members(self):
        for member in ('query_params', 'path_params', 'headers', 'cookies', 'COOKIES', 'META'):
            with self.subTest(member=member):
                self.assert_rules(f'def endpoint(request):\n    eval(request.{member}["q"])\n', 'eval')

    def test_inline_suppression_and_finding_deduplication(self):
        self.assert_rules('from fastapi import Query\ndef endpoint(value=Query()):\n    eval(value)  # ubs:ignore python.taint.eval\n')
        self.assert_rules('from fastapi import Query\ndef endpoint(a=Query(), b=Query()):\n    eval(a+b)\n', 'eval')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real-scanner checks')
class FrameworkRunnerTests(unittest.TestCase):
    def test_framework_sources_reach_the_actual_scanner(self):
        cases = (
            ('query-eval', 'from fastapi import Query\ndef endpoint(q=Query()):\n    eval(q)\n', 'eval', 3),
            ('body-sql', 'from typing import Annotated\nfrom fastapi import Body\ndef endpoint(q: Annotated[str, Body()]):\n    cursor.execute(q)\n', 'sql', 4),
            ('header-command', 'from fastapi import Header\ndef endpoint(q=Header()):\n    os.system(q)\n', 'command', 3),
            ('typed-request', 'from fastapi import Request\ndef endpoint(incoming: Request):\n    HttpResponse(incoming.query_params["q"])\n', 'xss', 3),
            ('safe-sql', 'from fastapi import Query\ndef endpoint(q=Query()):\n    cursor.execute("select ?", (q,))\n', None, None),
            ('safe-html', 'from fastapi import Query\ndef endpoint(q=Query()):\n    HttpResponse(html.escape(q))\n', None, None),
        )
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-framework-sources'
        artifacts.mkdir(parents=True, exist_ok=True)
        for name, code, kind, line in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix='ubs-framework-e2e-') as tmp:
                source = Path(tmp) / 'view.py'
                source.write_text(code, encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(source), '--only=python', '--ci', '--format=json'],
                                        cwd=tmp, env=dict(os.environ, UBS_NO_AUTO_UPDATE='1'),
                                        capture_output=True, text=True, timeout=180)
                (artifacts / f'{name}.json').write_text(result.stdout)
                (artifacts / f'{name}.stderr.log').write_text(result.stderr)
                self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report.get('status'), 'ok', result.stdout + result.stderr)
                findings = [f for f in report['findings'] if f['rule_id'].startswith('python.taint.')]
                expected = [(f'python.taint.{kind}', line)] if kind else []
                self.assertEqual([(f['rule_id'], f['line']) for f in findings], expected, report)
                print(f'[framework-{name}] PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
