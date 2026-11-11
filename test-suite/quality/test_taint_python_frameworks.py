"""Framework entry-point regressions. Fixture source is parsed, never imported."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import time
import unittest
from test_taint_python_dataflow import ROOT, SourceTest
from ubs_core.analyzers import taint_py
from ubs_core.io import temporary_directory
from ubs_core.registry import RunContext


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


class LiteralMappingTests(SourceTest):
    """A lookup selects stored values; request bytes do not become those values."""

    def setUp(self):
        self.started = time.monotonic()
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix='literal-mapping-', dir=artifacts))
        self.case = 0
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        print(f'[{self.id()}] END ({time.monotonic() - self.started:.3f}s)', flush=True)

    def scan(self, source):
        self.case += 1
        path = self.work / f'case-{self.case}.py'
        path.write_text(textwrap.dedent(source).lstrip('\n'), encoding='utf-8')
        return list(taint_py.run(RunContext(lang='python', files=[path])))

    def test_fixed_values_do_not_acquire_selection_key_taint(self):
        for lookup in ('choices.get(key)', 'choices[key]', 'lookup(key)'):
            with self.subTest(lookup=lookup):
                self.assert_rules(f'''
                    choices = {{'home': 'home', 'about': 'about'}}
                    lookup = choices.get
                    key = input()
                    HttpResponse({lookup})
                ''')
                self.assert_rules(f'''
                    choices = {{'home': 'home'}}
                    def view(key):
                        lookup = choices.get
                        return {lookup}
                    HttpResponse(view(input()))
                ''')

    def test_fastapi_constant_lookup_is_not_response_content(self):
        self.assert_rules('''
            from fastapi import FastAPI, HTTPException
            from fastapi.responses import Response
            app = FastAPI()
            VIEW_INDEX = {'home': 'home'}
            @app.get('/view/{name}')
            def view(name: str):
                canon = VIEW_INDEX.get(name)
                if canon is None:
                    raise HTTPException(404)
                body = render(canon)
                return Response(body, media_type='application/json')
        ''')

    def test_defaults_and_unknown_values_remain_tainted(self):
        for source in (
            "choices = {'home': 'home'}\nHttpResponse(choices.get(input(), input()))\n",
            "choices = {'home': input()}\nHttpResponse(choices.get('home'))\n",
            "choices = {'home': input()}\nHttpResponse(choices['home'])\n",
            "choices = external\nHttpResponse(choices.get(input()))\n",
            "choices = {'home': 'home'} if condition else external\nHttpResponse(choices.get(input()))\n",
            "choices = {'home': 'home'} if condition else external\nHttpResponse(choices[input()])\n",
        ):
            with self.subTest(source=source):
                self.assert_rules(source, 'xss')

    def test_writes_through_aliases_revoke_the_literal_contract(self):
        for write in (
            "alias['home'] = input()",
            "alias.update({'home': input()})",
            "alias.setdefault('new', input())",
            "alias.__setitem__('home', input())",
        ):
            for lookup in ("choices.get('home')", "choices['home']", "lookup('home')"):
                with self.subTest(write=write, lookup=lookup):
                    self.assert_rules(f'''
                        choices = {{'home': 'home'}}
                        lookup = choices.get
                        alias = choices
                        {write}
                        HttpResponse({lookup})
                    ''', 'xss')

    def test_local_helper_writes_and_argument_evaluation_revoke_contracts(self):
        for lookup in ('choices.get(replace())', 'choices[replace()]',
                       "choices.get('home', replace())", 'lookup(replace())'):
            with self.subTest(lookup=lookup):
                self.assert_rules(f'''
                    choices = {{'home': 'home'}}
                    lookup = choices.get
                    def replace():
                        choices['home'] = input()
                        return 'home'
                    HttpResponse({lookup})
                ''', 'xss')
        self.assert_rules('''
            def replace(choices, value):
                choices['home'] = value
            choices = {'home': 'home'}
            replace(choices, input())
            HttpResponse(choices.get('home'))
        ''', 'xss')

    def test_captured_method_keeps_its_original_receiver(self):
        self.assert_rules('''
            choices = {'home': 'home'}
            lookup = choices.get
            choices = {'home': input()}
            HttpResponse(lookup(input()))
        ''')
        self.assert_rules('''
            def lookup(read, choices, value):
                choices['home'] = value
                return read('home')
            choices = {'home': 'home'}
            HttpResponse(lookup(choices.get, choices, input()))
        ''', 'xss')

    def test_local_helpers_and_closures_preserve_literal_mapping_identity(self):
        self.assert_rules('''
            def choose(choices, key):
                return choices.get(key)
            HttpResponse(choose({'home': 'home'}, input()))
        ''')
        self.assert_rules('''
            def make():
                choices = {'home': 'home'}
                def choose(key):
                    return choices.get(key)
                return choose
            HttpResponse(make()(input()))
        ''')
        self.assert_rules('''
            def make():
                return {'home': 'home'}
            HttpResponse(make().get(input()))
        ''')

    def test_opaque_escapes_do_not_reuse_literal_mapping_proofs(self):
        for escape in ('unknown(choices)', 'holder.mapping = choices',
                       'unknown([choices])', "holder['mapping'] = choices"):
            with self.subTest(escape=escape):
                self.assert_rules(f'''
                    choices = {{'home': 'home'}}
                    {escape}
                    HttpResponse(choices.get(input()))
                ''', 'xss')
                self.assert_rules(f'''
                    choices = {{'home': 'home'}}
                    {escape}
                    def choose(key):
                        return choices.get(key)
                    HttpResponse(choose(input()))
                ''', 'xss')
                self.assert_rules(f'''
                    from fastapi import FastAPI
                    app = FastAPI()
                    choices = {{'home': 'home'}}
                    {escape}
                    @app.get('/view/{{name}}')
                    def view(name: str):
                        return HttpResponse(choices.get(name))
                ''', 'xss')

    def test_dynamic_and_nested_mapping_values_are_not_literal_contracts(self):
        self.assert_rules('''
            values = ['fixed']
            choices = {'home': values}
            values.append(input())
            HttpResponse(choices.get('home'))
        ''', 'xss')
        self.assert_rules('''
            class Lookup:
                def get(self, key):
                    return key
            HttpResponse(Lookup().get(input()))
        ''', 'xss')

    def test_custom_key_protocols_retain_taint_and_revoke_later_reads(self):
        setup = '''
            choices = {'home': 'home'}
            lookup = choices.get
            class Key:
                def __init__(self, payload):
                    self.payload = payload
                def __hash__(self):
                    choices['home'] = self.payload
                    return hash('home')
                def __eq__(self, other):
                    return other == 'home'
            key = Key(input())
        '''
        for selection in ('choices.get(key)', 'choices[key]', 'lookup(key)'):
            with self.subTest(selection=selection):
                self.assert_rules(textwrap.dedent(setup) + f'HttpResponse({selection})\n', 'xss')
                self.assert_rules(textwrap.dedent(setup) + f'''
def choose(key):
    return {selection}
HttpResponse(choose(key))
''', 'xss')
                self.assert_rules(textwrap.dedent(setup) + f'''
{selection}
HttpResponse(choices.get('home'))
''', 'xss')

    def test_framework_string_proofs_do_not_apply_to_ordinary_calls(self):
        for selection in ('choices.get(name)', 'choices[name]', 'lookup(name)'):
            with self.subTest(selection=selection):
                self.assert_rules(f'''
                    from fastapi import FastAPI
                    app = FastAPI()
                    choices = {{'home': 'home'}}
                    lookup = choices.get
                    class Key:
                        def __init__(self, payload):
                            self.payload = payload
                        def __hash__(self):
                            choices['home'] = self.payload
                            return hash('home')
                        def __eq__(self, other):
                            return other == 'home'
                    @app.get('/view/{{name}}')
                    def view(name: str):
                        return {selection}
                    HttpResponse(view(Key(input())))
                ''', 'xss')
        self.assert_rules('''
            from fastapi import FastAPI
            app = FastAPI()
            choices = {'home': 'home'}
            def choose(name):
                return choices.get(name)
            @app.get('/view/{name}')
            def view(name: str):
                return HttpResponse(choose(name))
        ''')

    def test_unknown_and_custom_annotated_keys_do_not_prove_inert_hashing(self):
        for annotation, imports in (
            ('Key', ''),
            ('Annotated[str, AfterValidator(make_key)]',
             'from typing import Annotated\nfrom pydantic import AfterValidator\n'),
        ):
            with self.subTest(annotation=annotation):
                self.assert_rules(imports + f'''
from fastapi import FastAPI
app = FastAPI()
choices = {{'home': 'home'}}
@app.get('/view/{{name}}')
def view(name: {annotation}):
    return HttpResponse(choices.get(name))
''', 'xss')
        self.assert_rules('''
            choices = {'home': 'home'}
            key = input() if condition else external(input())
            HttpResponse(choices.get(key))
        ''', 'xss')

    def test_global_key_replacement_does_not_reuse_primitive_proof(self):
        self.assert_rules('''
            choices = {'home': 'home'}
            key = input()
            def choose():
                return choices.get(key)
            key = external(input())
            HttpResponse(choose())
            key = input()
        ''', 'xss')

    def test_postponed_annotation_aliases_do_not_prove_native_keys(self):
        for annotation, before, replacement in (
            ('Alias', 'Alias = str', 'Alias = Annotated[str, AfterValidator(Key)]'),
            ('str', '', 'str = Annotated[str, AfterValidator(Key)]'),
        ):
            with self.subTest(annotation=annotation):
                self.assert_rules(f'''
                    from __future__ import annotations
                    from fastapi import FastAPI, Depends
                    from fastapi.responses import Response
                    from typing import Annotated
                    from pydantic import AfterValidator
                    choices = {{'home': 'safe'}}
                    class Key:
                        def __init__(self, payload):
                            self.payload = payload
                        def __hash__(self):
                            choices['home'] = self.payload
                            return hash('home')
                        def __eq__(self, other):
                            return other == 'home'
                    {before}
                    def choose(name: {annotation}):
                        return choices.get(name)
                    {replacement}
                    app = FastAPI()
                    @app.get('/view')
                    def view(value=Depends(choose)):
                        return Response(value, media_type='text/html')
                ''', 'xss')
        self.assert_rules('''
            from __future__ import annotations
            from fastapi import FastAPI
            app = FastAPI()
            choices = {'home': 'home'}
            @app.get('/view/{name}')
            def view(name: str):
                return HttpResponse(choices.get(name))
        ''')

    def test_imported_helpers_preserve_framework_and_ordinary_call_contexts(self):
        for ordinary in (False, True):
            with self.subTest(ordinary=ordinary):
                directory = self.work / ('ordinary' if ordinary else 'injected')
                directory.mkdir()
                helper = directory / 'helper.py'
                helper.write_text("choices = {'home': 'home'}\ndef choose(name):\n"
                                  "    return choices.get(name)\n", encoding='utf-8')
                source = directory / 'view.py'
                source.write_text('from fastapi import FastAPI\nfrom helper import choose\n'
                                  'app = FastAPI()\n@app.get("/view/{name}")\n'
                                  'def view(name: str):\n    return HttpResponse(choose(name))\n'
                                  + ('HttpResponse(choose(external(input())))\n' if ordinary else ''),
                                  encoding='utf-8')
                findings = list(taint_py.run(RunContext(lang='python', files=[source, helper],
                                                       profile={'project_dir': str(directory)})))
                self.assertEqual([(row['rule'], row['line']) for row in findings],
                                 [('python.taint.xss', 7)] if ordinary else [])

    def test_deferred_provider_annotation_mutations_remain_opaque(self):
        self.assert_rules('''
            from fastapi import FastAPI, Depends
            from typing import Annotated
            from pydantic import AfterValidator
            choices = {'home': 'safe'}
            class Key:
                def __init__(self, payload):
                    self.payload = payload
                def __hash__(self):
                    choices['home'] = self.payload
                    return hash('home')
                def __eq__(self, other):
                    return other == 'home'
            def choose(name: str):
                return choices.get(name)
            choose.__annotations__['name'] = Annotated[str, AfterValidator(Key)]
            app = FastAPI()
            @app.get('/view')
            def view(value=Depends(choose)):
                return HttpResponse(value)
        ''', 'xss')
        self.assert_rules('''
            from fastapi import FastAPI, Depends
            choices = {'home': 'home'}
            def choose(name: str):
                return choices.get(name)
            configure(choose)
            app = FastAPI()
            @app.get('/view')
            def view(value=Depends(choose)):
                return HttpResponse(value)
        ''', 'xss')

    def test_wrapped_route_annotations_do_not_prove_native_inputs(self):
        self.assert_rules('''
            from fastapi import FastAPI
            from functools import wraps
            app = FastAPI()
            choices = {'home': 'home'}
            @app.get('/view')
            @wraps(custom_signature)
            def view(name: str):
                return HttpResponse(choices.get(name))
        ''', 'xss')

    def test_dictionary_pairs_keep_python_evaluation_order(self):
        self.assert_rules('''
            value = input()
            choices = {'first': (saved := value), (value := 'safe'): 0}
            HttpResponse(saved)
        ''', 'xss')
        self.assert_rules('''
            value = 'safe'
            choices = {'first': (saved := value), (value := input()): 0}
            HttpResponse(saved)
        ''')

    def test_lookup_results_and_immutable_values_are_snapshots(self):
        for lookup in ("choices['home']", "choices.get('home')"):
            with self.subTest(lookup=lookup):
                self.assert_rules(f'''
                    choices = {{'home': 'home'}}
                    saved = {lookup}
                    choices['home'] = input()
                    HttpResponse(saved)
                ''')
        self.assert_rules('''
            saved = 'home'
            choices = {'home': saved, 'unsafe': input()}
            choices['home'] = input()
            HttpResponse(saved)
        ''')

    def test_global_replacements_do_not_reuse_literal_contracts(self):
        self.assert_rules('''
            choices = {'home': 'home'}
            def choose(key):
                return choices.get(key)
            def outer(key):
                return choose(key)
            saved = choices
            choices = unknown
            HttpResponse(outer(input()))
            choices = saved
        ''', 'xss')
        self.assert_rules('''
            choices = {'home': 'home'}
            def choose(key):
                return choices[key]
            def mutate(value):
                choices['home'] = value
            mutate(input())
            HttpResponse(choose('home'))
        ''', 'xss')


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
    def test_literal_mapping_and_awaited_task_module_runner_formats(self):
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='literal-mapping-public-', dir=artifacts))
        helper = ROOT / 'modules/helpers/ubs_core/analyzers/taint_py.py'
        helper_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
        header = ("from fastapi import FastAPI\nfrom fastapi.responses import Response\n"
                  "app = FastAPI()\nCHOICES = {'home': 'home'}\n"
                  "@app.get('/view/{name}')\ndef view(name: str):\n")
        cases = (
            ('fixed-values', header + '    return Response(CHOICES.get(name))\n', []),
            ('tainted-default', header + '    return Response(CHOICES.get(name, name))\n', [7]),
            ('mutated-values', header + "    CHOICES['home'] = name\n"
             "    return Response(CHOICES.get('home'))\n", [8]),
            ('awaited-name', textwrap.dedent('''
                import asyncio
                from fastapi.responses import Response
                async def handler():
                    async def watch():
                        await asyncio.sleep(1)
                    watcher = asyncio.create_task(watch())
                    try:
                        return Response('ok')
                    finally:
                        watcher.cancel()
                        try:
                            await watcher
                        except asyncio.CancelledError:
                            pass
            ''').lstrip('\n'), []),
        )
        environment = dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_CACHE='1',
                           UBS_NO_AUTO_UPDATE='1', UBS_ENABLE_AUTO_UPDATE='0',
                           XDG_CACHE_HOME=str(work / 'cache'), UBS_CACHE_DIR=str(work / 'cache'),
                           XDG_DATA_HOME=str(work / 'data'), XDG_CONFIG_HOME=str(work / 'config'),
                           PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
        skip = '--skip=' + ','.join(str(category) for category in range(1, 24) if category != 7)
        for label, source, expected in cases:
            selected = work / label
            selected.mkdir()
            path = selected / 'view.py'
            path.write_text(source, encoding='utf-8')
            temporary = selected / 'temporary'
            temporary.mkdir()
            for module in (True, False):
                for output_format in ('json', 'sarif'):
                    with self.subTest(case=label, module=module, format=output_format):
                        prefix = (['bash', str(ROOT / 'modules/ubs-python.sh'), '--no-uv'] if module else
                                  ['bash', str(ROOT / 'ubs'), '--only=python'])
                        command = [*prefix, '--ci', '--format=' + output_format, skip, str(path)]
                        name = ('module' if module else 'runner') + '-' + output_format
                        print(f'[literal-mapping:{label}:{name}] RUN', flush=True)
                        started = time.monotonic()
                        result = subprocess.run(command, cwd=work, env={**environment, 'TMPDIR': str(temporary)},
                                                capture_output=True, text=True, timeout=180)
                        (selected / f'{name}.stdout').write_text(result.stdout, encoding='utf-8')
                        (selected / f'{name}.stderr').write_text(result.stderr, encoding='utf-8')
                        (selected / f'{name}.receipt.json').write_text(json.dumps({
                            'command': command, 'returncode': result.returncode,
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'helper_sha256': helper_hash, 'elapsed': time.monotonic() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, int(bool(expected)), (command, result.stdout, result.stderr))
                        payload = json.loads(result.stdout)
                        if output_format == 'json':
                            self.assertEqual(payload['status'], 'ok', payload)
                            totals = payload if module else payload['totals']
                            self.assertEqual(totals['critical'], len(expected), payload)
                            rows = [row for row in payload.get('findings', [])
                                    if row['rule' if module else 'rule_id'] == 'python.taint.xss']
                            samples = [sample for row in rows for sample in row['samples']] if module else rows
                            self.assertEqual([row['line'] for row in samples], expected, payload)
                            for row in samples:
                                self.assertEqual(Path(row['file']).name, 'view.py')
                        else:
                            self.assertEqual(payload['version'], '2.1.0', payload)
                            self.assertTrue(payload['runs'], payload)
                            rows = [row for run in payload['runs'] for row in run.get('results', [])
                                    if row['ruleId'] == 'python.taint.xss']
                            self.assertEqual([row['locations'][0]['physicalLocation']['region']['startLine']
                                              for row in rows], expected, payload)
                            self.assertTrue(all(invocation.get('executionSuccessful') is not False
                                                for run in payload['runs']
                                                for invocation in run.get('invocations', [])), payload)
                        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(), helper_hash)
                        print(f'[literal-mapping:{label}:{name}] PASS', flush=True)

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
            with self.subTest(case=name), temporary_directory(prefix='ubs-framework-e2e-') as tmp:
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
