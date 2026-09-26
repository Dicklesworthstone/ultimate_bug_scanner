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


class DependencyInputTests(SourceTest):
    def test_local_dependency_return_becomes_a_handler_input(self):
        self.assert_rules('''
            from fastapi import Depends, Query
            def obtain(q=Query()):
                return q
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''', 'eval')

    def test_plain_dependency_arguments_are_request_parameters(self):
        self.assert_rules('''
            from fastapi import Depends
            def obtain(q: str = 'default'):
                return q
            def endpoint(code=Depends(obtain)):
                cursor.execute(code)
        ''', 'sql')
        self.assert_rules("def ordinary(q: str = 'default'):\n    eval(q)\n")

    def test_annotated_dependency_alias_and_keyword_callable(self):
        self.assert_rules('''
            from fastapi import Depends as D
            from typing import Annotated as A
            def obtain(q: str):
                return q
            Code = A[str, D(dependency=obtain)]
            def endpoint(code: Code):
                eval(code)
        ''', 'eval')

    def test_nested_dependencies_preserve_source_provenance(self):
        findings = self.assert_rules('''
            from fastapi import Depends, Cookie
            def obtain(q=Cookie()):
                return q
            async def decorate(code=Depends(obtain)):
                return 'select ' + code
            async def endpoint(query=Depends(decorate)):
                cursor.execute(query)
        ''', 'sql')
        self.assertIn('Cookie', findings[0]['message'])
        self.assertIn('decorate()', findings[0]['message'])

    def test_deep_dependency_chain_has_no_arbitrary_depth_cutoff(self):
        code = 'from fastapi import Depends\ndef d0(q: str):\n    return q\n'
        for i in range(1, 24):
            code += f'def d{i}(q=Depends(d{i-1})):\n    return q\n'
        code += 'def endpoint(code=Depends(d23)):\n    eval(code)\n'
        self.assert_rules(code, 'eval')

    def test_dependency_sink_side_effects_are_analyzed(self):
        self.assert_rules('''
            from fastapi import Depends
            def validate(q: str):
                eval(q)
                return 'safe'
            def endpoint(code=Depends(validate)):
                pass
        ''', 'eval')

    def test_route_decorator_dependencies_are_invocations(self):
        self.assert_rules('''
            from fastapi import Depends, FastAPI
            app = FastAPI()
            def validate(q: str):
                eval(q)
            @app.get('/', dependencies=[Depends(validate)])
            def endpoint():
                pass
        ''', 'eval')

    def test_constant_dependency_return_does_not_inherit_unused_input(self):
        self.assert_rules('''
            from fastapi import Depends, Query
            def obtain(q=Query()):
                return 'trusted'
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''')

    def test_returned_sanitizer_is_only_valid_in_its_sink_domain(self):
        code = '''
            from fastapi import Depends, Query
            def obtain(q=Query()):
                return html.escape(q)
            def endpoint(code=Depends(obtain)):
                SINK
        '''
        self.assert_rules(code.replace('SINK', 'HttpResponse(code)'))
        self.assert_rules(code.replace('SINK', 'cursor.execute(code)'), 'sql')

    def test_yielding_dependency_exposes_the_yielded_value(self):
        self.assert_rules('''
            from fastapi import Depends, Query
            def obtain(q=Query()):
                yield q
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''', 'eval')
        self.assert_rules('''
            from fastapi import Depends, Query
            def obtain(q=Query()):
                yield 'trusted'
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''')

    def test_security_uses_the_same_dependency_summary(self):
        self.assert_rules('''
            from fastapi import Security, Header
            def obtain(q=Header()):
                return q
            def endpoint(code=Security(obtain, scopes=['read'])):
                eval(code)
        ''', 'eval')

    def test_rebinding_does_not_change_a_captured_dependency(self):
        self.assert_rules('''
            from fastapi import Depends
            def obtain(q: str):
                return q
            def endpoint(code=Depends(obtain)):
                eval(code)
            obtain = other
        ''', 'eval')
        self.assert_rules('''
            from fastapi import Depends
            def obtain(q: str):
                return q
            obtain = other
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''')

    def test_generator_return_summary_propagates_to_ordinary_consumers(self):
        self.assert_rules('''
            def values(q):
                yield q
            for code in values(input()):
                eval(code)
        ''', 'eval')

    def test_sanitized_global_is_rechecked_after_summary_substitution(self):
        self.assert_rules('''
            value = html.escape(input())
            def endpoint():
                HttpResponse(value)
        ''')
        self.assert_rules('''
            value = html.escape(input())
            def endpoint():
                cursor.execute(value)
        ''', 'sql')

    def test_dependency_callable_binding_is_captured_before_later_arguments(self):
        code = '''
            from fastapi import Depends
            def unsafe(q: str):
                return q
            def trusted(q: str):
                return 'trusted'
            provider = FIRST
            def endpoint(code=Depends(provider, use_cache=(provider := SECOND))):
                eval(code)
        '''
        self.assert_rules(code.replace('FIRST', 'unsafe').replace('SECOND', 'trusted'), 'eval')
        self.assert_rules(code.replace('FIRST', 'trusted').replace('SECOND', 'unsafe'))

    def test_constructed_and_annotated_dependencies_retain_callable_identity(self):
        code = '''
            from fastapi import Depends
            from typing import Annotated
            def unsafe(q: str):
                return q
            def trusted(q: str):
                return 'trusted'
            provider = FIRST
            marker = Depends(provider)
            Code = Annotated[str, marker, (provider := SECOND)]
            def endpoint(code: Code):
                eval(code)
        '''
        self.assert_rules(code.replace('FIRST', 'unsafe').replace('SECOND', 'trusted'), 'eval')
        self.assert_rules(code.replace('FIRST', 'trusted').replace('SECOND', 'unsafe'))

    def test_literal_keyword_mappings_preserve_dependency_invocations(self):
        for marker in ('Depends', 'Security'):
            with self.subTest(marker=marker):
                code = f'''
                    from fastapi import {marker}
                    def obtain(q: str):
                        return VALUE
                    def endpoint(code={marker}(**{{'dependency': obtain}})):
                        eval(code)
                '''
                self.assert_rules(code.replace('VALUE', 'q'), 'eval')
                self.assert_rules(code.replace('VALUE', "'trusted'"))
        code = '''
            from fastapi import Depends, FastAPI
            app = ROUTER
            def validate(q: str):
                eval(q)
            @app.get('/', **{'dependencies': [Depends(validate)]})
            def endpoint():
                pass
        '''
        self.assert_rules(code.replace('ROUTER', 'FastAPI()'), 'eval')
        self.assert_rules(code.replace('ROUTER', 'cache'))

    def test_assignment_expressions_retain_dependency_and_metadata_bindings(self):
        code = '''
            from fastapi import Depends
            from typing import Annotated
            def unsafe(q: str):
                return q
            def trusted(q: str):
                return 'trusted'
            def endpoint(code=Depends((provider := PROVIDER))):
                eval(code)
        '''
        self.assert_rules(code.replace('PROVIDER', 'unsafe'), 'eval')
        self.assert_rules(code.replace('PROVIDER', 'trusted'))
        code = code[:code.index('            def endpoint')] + '''
            Code = Annotated[str, Depends(unsafe), (marker := Depends(PROVIDER))]
            def endpoint(code: Code):
                eval(code)
        '''
        self.assert_rules(code.replace('PROVIDER', 'unsafe'), 'eval')
        self.assert_rules(code.replace('PROVIDER', 'trusted'))

    def test_route_dependency_binding_precedes_later_keyword_reassignment(self):
        code = '''
            from fastapi import Depends, FastAPI
            app = FastAPI()
            def unsafe(q: str):
                eval(q)
            def trusted(q: str):
                pass
            provider = FIRST
            @app.get('/', dependencies=[Depends(provider)], openapi_extra=(provider := SECOND))
            def endpoint():
                pass
        '''
        self.assert_rules(code.replace('FIRST', 'unsafe').replace('SECOND', 'trusted'), 'eval')
        self.assert_rules(code.replace('FIRST', 'trusted').replace('SECOND', 'unsafe'))
        self.assert_rules('''
            from fastapi import Depends, FastAPI
            app = FastAPI()
            def validate(q: str):
                eval(q)
            @app.get('/')
            @cache.get(dependencies=[Depends(validate)])
            def endpoint():
                pass
        ''')

    def test_generator_return_is_separate_from_injected_yielded_value(self):
        self.assert_rules('''
            from fastapi import Depends
            def obtain(q: str):
                yield 'trusted'
                return q
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''')
        findings = self.assert_rules('''
            from fastapi import Depends
            def child(q):
                yield 'trusted'
                return q
            def obtain(q: str):
                value = yield from child(q)
                eval(value)
            def endpoint(code=Depends(obtain)):
                eval(code)
        ''', 'eval')
        self.assertEqual([finding['line'] for finding in findings], [7])

    def test_framework_provider_inputs_do_not_taint_ordinary_clean_calls(self):
        findings = self.assert_rules('''
            from fastapi import Depends
            def obtain(q: str):
                return q
            def endpoint(code=Depends(obtain)):
                eval(code)
            eval(obtain('trusted'))
        ''', 'eval')
        self.assertEqual([finding['line'] for finding in findings], [5])


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
            ('dependency-sql', 'from fastapi import Depends\ndef obtain(q: str):\n    return q\ndef endpoint(code=Depends(obtain)):\n    cursor.execute(code)\n', 'sql', 5),
            ('dependency-safe-html', 'from fastapi import Depends\ndef obtain(q: str):\n    return html.escape(q)\ndef endpoint(code=Depends(obtain)):\n    HttpResponse(code)\n', None, None),
            ('dependency-yield', 'from fastapi import Depends\ndef obtain(q: str):\n    yield q\ndef endpoint(code=Depends(obtain)):\n    eval(code)\n', 'eval', 5),
            ('dependency-side-effect', 'from fastapi import Depends, FastAPI\napp = FastAPI()\ndef validate(q: str):\n    eval(q)\n@app.get("/", dependencies=[Depends(validate)])\ndef endpoint():\n    pass\n', 'eval', 4),
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
