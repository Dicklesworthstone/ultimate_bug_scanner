"""Source-only HTTP destination regressions; no fixture makes network calls."""
from __future__ import annotations

import contextlib
import io
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


class HTTPDestinationTests(SourceTest):
    def setUp(self):
        self.started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        print(f'[{self.id()}] END ({time.monotonic() - self.started:.3f}s)', flush=True)

    def test_convenience_methods_track_only_url(self):
        for module in ('requests', 'requests.api', 'httpx'):
            for method in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'):
                with self.subTest(module=module, method=method):
                    call = f'{module}.{method}'
                    self.assert_rules(f'import {module}\n{call}(input())\n', 'ssrf')
                    self.assert_rules(f'import {module}\n{call}(url=input())\n', 'ssrf')
                    self.assert_rules(f'''import {module}
{call}('https://example.invalid', params={{'q': input()}}, headers={{'X-Value': input()}})
''')
        for module in ('requests', 'httpx'):
            self.assert_rules(f"import {module}\n{module}.post('https://example.invalid', data=input())\n")
            self.assert_rules(f"import {module}\n{module}.post('https://example.invalid', json={{'q': input()}})\n")

    def test_method_argument_is_not_the_destination(self):
        for call in ('requests.request', 'requests.api.request', 'httpx.request', 'httpx.stream'):
            module = call.rsplit('.', 1)[0]
            with self.subTest(call=call):
                self.assert_rules(f'import {module}\n{call}("GET", input())\n', 'ssrf')
                self.assert_rules(f'import {module}\n{call}("GET", url=input())\n', 'ssrf')
                self.assert_rules(f'import {module}\n{call}(method="GET", url=input())\n', 'ssrf')
                self.assert_rules(f'import {module}\n{call}(input(), "https://example.invalid", data=input())\n')

    def test_imports_aliases_callable_alternatives_and_shadowing(self):
        self.assert_rules('from requests import get as fetch\nfetch(input())\n', 'ssrf')
        self.assert_rules('import httpx as client\nfetch = client.get\nfetch(input())\n', 'ssrf')
        self.assert_rules('''
            import requests
            import httpx
            fetch = requests.get if choose else httpx.get
            fetch(input())
        ''', 'ssrf')
        for source in (
            'def get(value):\n    return value\nget(input())\n',
            'cache.get(input())\n',
            'requests.get(input())\n',
            'import requests\nrequests = cache\nrequests.get(input())\n',
            'from requests import get\nget = unrelated\nget(input())\n',
            'import requests\ndef use(requests):\n    requests.get(input())\n',
        ):
            with self.subTest(source=source):
                self.assert_rules(source)

    def test_literal_and_opaque_argument_expansions(self):
        self.assert_rules('import requests\nrequests.request(*["GET", input()])\n', 'ssrf')
        self.assert_rules('import requests\nrequests.request(*[input(), "https://example.invalid"])\n')
        self.assert_rules('import httpx\nhttpx.request(**{"method": "GET", "url": input()})\n', 'ssrf')
        self.assert_rules('import httpx\nhttpx.get(**{"url": "https://example.invalid", "params": input()})\n')
        self.assert_rules('import requests\nrequests.request("GET", *input())\n', 'ssrf')
        self.assert_rules('import requests\nrequests.request(*input(), "https://example.invalid")\n', 'ssrf')
        self.assert_rules('import requests\nrequests.request("GET", "https://example.invalid", *input())\n')
        self.assert_rules('import requests\nrequests.get(**input())\n', 'ssrf')

    def test_local_helpers_defaults_and_callable_returns(self):
        findings = self.assert_rules('''
            import requests
            def fetch(destination):
                return requests.get(destination)
            def forward(value):
                return fetch(value)
            forward(input())
        ''', 'ssrf')
        self.assertEqual(findings[0]['line'], 3)
        self.assertIn('fetch()', findings[0]['message'])
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assert_rules('''
            import requests
            def fetch(destination='https://example.invalid'):
                return requests.get(destination)
            fetch()
            fetch(destination='https://example.invalid/safe')
        ''')
        self.assert_rules('''
            import requests
            def choose():
                return requests.get
            choose()(input())
        ''', 'ssrf')

    def test_control_flow_and_reassignment(self):
        self.assert_rules('''
            import httpx
            target = input()
            if condition:
                target = 'https://example.invalid'
            httpx.get(target)
        ''', 'ssrf')
        self.assert_rules('import requests\ntarget = input()\ntarget = "https://example.invalid"\nrequests.get(target)\n')
        self.assert_rules('''
            import httpx
            def fetch(value):
                if again:
                    return fetch(value)
                return httpx.get(value)
            fetch(input())
        ''', 'ssrf')

    def test_other_domains_do_not_sanitize_a_destination(self):
        for expression in ('html.escape(input())', 'shlex.quote(input())', 'urllib.parse.quote(input())'):
            with self.subTest(expression=expression):
                self.assert_rules(f'import requests, html, shlex, urllib.parse\nrequests.get({expression})\n', 'ssrf')

    @staticmethod
    def url_guard_source(condition='parsed.scheme == "https" and parsed.hostname in HOSTS'):
        return f'''import requests
from urllib.parse import urlparse
HOSTS = {{"api.example.com", "images.example.com"}}
def approved(target):
    if not target:
        return False
    parsed = urlparse(target)
    return {condition}
'''

    def test_exact_url_guard_and_terminating_validator(self):
        source = self.url_guard_source()
        self.assert_rules(source + '''
target = input()
if not approved(target):
    raise ValueError("blocked")
requests.get(target)
''')
        self.assert_rules(source + '''
def validate(target):
    if not approved(target):
        raise ValueError("blocked")
    return target
def forward(target):
    return validate(target)
requests.get(forward(input()))
''')
        self.assert_rules(source + '''
target = input()
if approved(target):
    requests.get(target)
''')

    def test_helper_url_guard_preserves_parser_binding_and_failure_paths(self):
        validator = '''
def validate(target):
    if not approved(target):
        raise ValueError("blocked")
    return target
'''
        for body, rules in (
            ('return validate(target)', ()),
            ('checked = validate(target)\n    return checked', ()),
            ('validate(target)\n    return input()', ('ssrf',)),
            ('try:\n        return validate(target)\n    except ValueError:\n        return target', ('ssrf',)),
        ):
            with self.subTest(body=body):
                self.assert_rules(self.url_guard_source() + validator +
                                  '\ndef forward(target):\n    ' + body +
                                  '\nrequests.get(forward(input()))\n', *rules)
        # A restored module binding must not certify the earlier call made
        # while the parser was replaced.
        self.assert_rules(self.url_guard_source() + validator + '''
saved_parser = urlparse
urlparse = unknown_parser
requests.get(validate(input()))
urlparse = saved_parser
''', 'ssrf')
        # A same-named closure is a different binding from the module import.
        self.assert_rules('''
import requests
from urllib.parse import urlparse
HOSTS = {"api.example.com"}
def forward(target, parser):
    urlparse = parser
    def approved(value):
        parsed = urlparse(value)
        return parsed.scheme == "https" and parsed.hostname in HOSTS
    if not approved(target):
        raise ValueError("blocked")
    return target
requests.get(forward(input(), unknown_parser))
''', 'ssrf')

    def test_url_guard_requires_both_exact_checks_and_a_real_parser(self):
        suffix = '''
target = input()
if not approved(target):
    raise ValueError("blocked")
requests.get(target)
'''
        for condition in (
            'parsed.scheme == "http" and parsed.hostname in HOSTS',
            'parsed.scheme == "https" or parsed.hostname in HOSTS',
            'parsed.scheme == "https" and parsed.hostname not in HOSTS',
            'parsed.scheme == "https" and parsed.hostname.startswith("api.example.com")',
            'parsed.hostname in HOSTS',
        ):
            with self.subTest(condition=condition):
                self.assert_rules(self.url_guard_source(condition) + suffix, 'ssrf')
        for alteration in (
            '\nHOSTS.add(input())\n',
            '\nHOSTS = {input()}\n',
            '\nother = HOSTS\nother.add(input())\n',
            '\nopaque(HOSTS)\n',
            '\nfrom config import HOSTS\n',
            '\nimport config as HOSTS\n',
            '\nglobals()["HOSTS"] = {input()}\n',
            '\nurlparse = unknown_parser\n',
            '\ndef approved(target):\n    return True\n',
        ):
            with self.subTest(alteration=alteration):
                self.assert_rules(self.url_guard_source() + alteration + suffix, 'ssrf')
        self.assert_rules(self.url_guard_source() + '''
urlparse = unknown_parser
def forward(urlparse):
    target = input()
    if not approved(target):
        raise ValueError("blocked")
    requests.get(target)
from urllib.parse import urlparse as stdlib_parser
forward(stdlib_parser)
''', 'ssrf')

    def test_url_guard_is_branch_value_and_domain_specific(self):
        for continuation, rule in (
            ('if not approved(target):\n    pass\nrequests.get(target)\n', 'ssrf'),
            ('if not approved(target):\n    raise ValueError()\ntarget = input()\nrequests.get(target)\n', 'ssrf'),
            ('try:\n    if not approved(target):\n        raise ValueError()\nexcept ValueError:\n    pass\nrequests.get(target)\n', 'ssrf'),
            ('if not approved(target):\n    raise ValueError()\neval(target)\n', 'eval'),
        ):
            with self.subTest(continuation=continuation):
                self.assert_rules(self.url_guard_source() + '\ntarget = input()\n' + continuation, rule)

    def test_url_guard_rejects_non_assignment_allowlist_bindings(self):
        suffix = '''
target = input()
if not approved(target):
    raise ValueError("blocked")
requests.get(target)
'''
        # These binding targets are strings in the AST, not Name(Store)
        # nodes. Each can replace the literal allow-list with an arbitrary
        # iterable while keeping the guard's exact spelling unchanged.
        for binding in (
            'match {input()}:\n    case HOSTS:\n        pass\n',
            'match [{input()}]:\n    case [HOSTS]:\n        pass\n',
            'match [input()]:\n    case [*HOSTS]:\n        pass\n',
            'match {input(): True}:\n    case {**HOSTS}:\n        pass\n',
            '''class EveryHost(type):
    def __contains__(cls, hostname):
        return True
class HOSTS(metaclass=EveryHost):
    pass
''',
            'from configuration import *\n',
        ):
            with self.subTest(binding=binding):
                self.assert_rules(self.url_guard_source() + binding + suffix, 'ssrf')
        # Exception targets are another string-valued lexical binding. Keep
        # the request inside the handler, before Python clears that target.
        self.assert_rules(self.url_guard_source() + '''
class HostFailure(Exception):
    def __contains__(self, hostname):
        return True
try:
    raise HostFailure(input())
except HostFailure as HOSTS:
    target = input()
    if not approved(target):
        raise ValueError("blocked")
    requests.get(target)
''', 'ssrf')

    def test_url_allowlists_keep_independent_mutation_and_binding_proofs(self):
        source = '''
import requests
from urllib.parse import urlparse
PRIMARY = {"api.example.com"}
SECONDARY = ("images.example.com",)
def primary_allowed(value):
    parsed = urlparse(value)
    return parsed.scheme == "https" and parsed.hostname in PRIMARY
def secondary_allowed(value):
    parsed = urlparse(value)
    return parsed.scheme == "https" and parsed.hostname in SECONDARY
SECONDARY = (input(),)
first = input()
if not primary_allowed(first):
    raise ValueError("blocked")
requests.get(first)
second = input()
if not secondary_allowed(second):
    raise ValueError("blocked")
requests.get(second)
'''
        findings = self.assert_rules(source, 'ssrf')
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]['line'], source.strip().splitlines().index('requests.get(second)') + 1)

    def test_async_execution_and_framework_inputs(self):
        self.assert_rules('''
            import requests, asyncio
            async def fetch(value):
                return requests.get(value)
            asyncio.run(fetch(input()))
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            from fastapi import FastAPI
            app = FastAPI()
            @app.get('/fetch')
            def view(url: str):
                return httpx.get(url)
        ''', 'ssrf')

    def test_rule_suppression_and_disable_are_scoped(self):
        for name in ('py.taint.ssrf', 'python.taint.ssrf'):
            with self.subTest(rule=name):
                self.assert_rules(f'import requests\n# ubs:ignore[{name}]\nrequests.get(input())\n')
                with tempfile.TemporaryDirectory(prefix='ubs-http-disabled-') as temporary:
                    path = Path(temporary, 'view.py')
                    path.write_text('import requests\nrequests.get(input())\n', encoding='utf-8')
                    ctx = RunContext(lang='python', files=[path], profile={'disabled_rules': [name]})
                    self.assertEqual(list(taint_py.run(ctx)), [])
        self.assert_rules('import requests\n# ubs:ignore[python.taint.eval]\nrequests.get(input())\n', 'ssrf')

    def test_tabular_entrypoint_keeps_the_same_rule_and_site(self):
        with tempfile.TemporaryDirectory(prefix='ubs-http-tabular-') as temporary:
            path = Path(temporary, 'view.py')
            path.write_text('import requests\nrequests.get(input())\n', encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(taint_py.main(['taint', temporary]), 0)
            self.assertIn('py.taint.ssrf\t1\tview.py:2 ', output.getvalue())
            self.assertIn('HTTP request URL', output.getvalue())

    def test_cross_file_calls_and_local_module_shadowing(self):
        with tempfile.TemporaryDirectory(prefix='ubs-http-modules-') as temporary:
            root = Path(temporary)
            main = root / 'app.py'
            helper = root / 'transport.py'
            main.write_text('from transport import fetch\nfetch(input())\n', encoding='utf-8')
            helper.write_text('import requests\ndef fetch(url):\n    return requests.get(url)\n', encoding='utf-8')
            for paths in ([main, helper], [helper, main]):
                found = list(taint_py.run(RunContext(lang='python', files=paths,
                                                   profile={'project_dir': str(root)})))
                self.assertEqual([(f['rule'], f['path'], f['line']) for f in found],
                                 [('python.taint.ssrf', str(helper), 3)], found)
            local = root / 'requests.py'
            local.write_text('def get(value):\n    return value\n', encoding='utf-8')
            found = list(taint_py.run(RunContext(lang='python', files=[main, helper, local],
                                               profile={'project_dir': str(root)})))
            self.assertEqual(found, [])

    @unittest.skipUnless(os.environ.get('UBS_HTTP_E2E') == '1', 'opt-in real scanner integration')
    def test_real_runner_json_and_sarif(self):
        def ids(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {'rule', 'ruleId', 'rule_id'} and isinstance(item, str):
                        yield item
                    yield from ids(item)
            elif isinstance(value, list):
                for item in value:
                    yield from ids(item)
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-http-taint'
        artifacts.mkdir(parents=True, exist_ok=True)
        guarded_request = '''target = input()
if not approved(target):
    raise ValueError("blocked")
requests.get(target)
'''
        cases = (
            ('safe', False, 'import requests\nrequests.post("https://example.invalid", data=input())\n'),
            ('unsafe', True, 'import requests\nrequests.post(input(), data=input())\n'),
            ('guard-literal', False, self.url_guard_source() + guarded_request),
            ('guard-match', True, self.url_guard_source() +
             'match {input()}:\n    case HOSTS:\n        pass\n' + guarded_request),
        )
        with tempfile.TemporaryDirectory(prefix='ubs-http-cli-') as temporary:
            path = Path(temporary, 'view.py')
            for case_name, unsafe, source in cases:
                path.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    result = subprocess.run([str(ROOT / 'ubs'), '--ci', '--no-auto-update', '--no-color',
                                             '--only=python', f'--format={output}', str(path)],
                                            capture_output=True, text=True, timeout=120,
                                            env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1'})
                    tag = f'{case_name}-{output}'
                    (artifacts / f'{tag}.stdout.log').write_text(result.stdout, encoding='utf-8')
                    (artifacts / f'{tag}.stderr.log').write_text(result.stderr, encoding='utf-8')
                    self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                    try:
                        report = json.loads(result.stdout)
                    except json.JSONDecodeError as exc:
                        self.fail(f'Invalid {output} report at {exc.lineno}:{exc.colno}: {exc.msg}; '
                                  f'exit={result.returncode}; stderr={result.stderr}')
                    self.assertEqual(bool(set(ids(report)) & {'python.taint.ssrf', 'py.taint.ssrf'}),
                                     unsafe, result.stdout + result.stderr)
                    if unsafe:
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    print(f'[python-http-{tag}] PASS', flush=True)


class PooledHTTPClientTests(SourceTest):
    """Native pooled clients retain destination identity through local flow."""

    def test_session_constructors_aliases_and_bound_methods(self):
        for setup, constructor in (
            ('import requests', 'requests.Session'),
            ('import requests', 'requests.session'),
            ('import requests.sessions as pools', 'pools.Session'),
            ('from requests.sessions import session as make', 'make'),
            ('from requests import Session as make', 'make'),
            ('import httpx as transport', 'transport.Client'),
        ):
            with self.subTest(constructor=constructor):
                self.assert_rules(f'{setup}\nclient = {constructor}()\nclient.get(input())\n', 'ssrf')
                self.assert_rules(f'{setup}\nclient = {constructor}()\nfetch = client.get\n'
                                  'client = unrelated\nfetch(input())\n', 'ssrf')

    def test_context_managers_and_inline_receivers(self):
        for module, constructor in (('requests', 'Session'), ('httpx', 'Client')):
            with self.subTest(module=module):
                self.assert_rules(f'import {module}\nwith {module}.{constructor}() as client:\n'
                                  '    client.get(input())\n', 'ssrf')
                self.assert_rules(f'import {module}\n{module}.{constructor}().get(input())\n', 'ssrf')

    def test_methods_select_the_url_not_metadata(self):
        for constructor in ('requests.Session', 'httpx.Client'):
            for method in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request'):
                prefix = '"GET", ' if method == 'request' else ''
                setup = f'import requests, httpx\nclient = {constructor}()\n'
                with self.subTest(constructor=constructor, method=method):
                    self.assert_rules(setup + f'client.{method}({prefix}input())\n', 'ssrf')
                    self.assert_rules(setup + f'client.{method}({prefix}url=input())\n', 'ssrf')
                    self.assert_rules(setup + f'client.{method}({prefix}"https://example.invalid", '
                                      'params={"q": input()}, headers={"X-Data": input()})\n')
            self.assert_rules(setup + 'client.post("https://example.invalid", data=input())\n')
            self.assert_rules(setup + 'client.request(*["GET", input()])\n', 'ssrf')
            self.assert_rules(setup + 'client.request(**{"method": "GET", "url": input()})\n', 'ssrf')

    def test_constructor_metadata_is_not_a_destination(self):
        self.assert_rules('import httpx\nclient = httpx.Client(headers={"X-Data": input()}, '
                          'params={"q": input()}, auth=("name", input()))\n'
                          'client.get("https://example.invalid")\n')
        self.assert_rules('import httpx\nclient = httpx.Client(base_url=input())\n')

    def test_base_url_is_used_only_by_relative_requests(self):
        for path in ('/relative', 'relative', '', '//still-relative.example/path'):
            with self.subTest(path=path):
                self.assert_rules(f'import httpx\nclient = httpx.Client(base_url=input())\n'
                                  f'client.get({path!r})\n', 'ssrf')
        self.assert_rules('import httpx\nclient = httpx.Client(base_url=input())\n'
                          'client.get("https://example.invalid/fixed")\n')
        self.assert_rules('import httpx\nclient = httpx.Client(base_url="https://example.invalid")\n'
                          'client.get(input())\n', 'ssrf')

    def test_client_and_method_summaries(self):
        self.assert_rules('''
            import requests
            def fetch(client, target):
                return client.get(target)
            fetch(requests.Session(), input())
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            def make(base):
                return httpx.Client(base_url=base)
            def fetch(client, target):
                return client.get(target)
            fetch(make(input()), '/relative')
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            def make(base):
                return httpx.Client(base_url=base)
            def fetch(client, target):
                return client.get(target)
            fetch(make(input()), 'https://example.invalid/fixed')
        ''')
        self.assert_rules('''
            import requests
            def make():
                return requests.Session().get
            def fetch(call, target):
                return call(target)
            fetch(make(), input())
        ''', 'ssrf')

    def test_host_presence_controls_httpx_absolute_overrides(self):
        for destination in ('https://user@/relative', 'https://:443/relative',
                            'https:relative', 'http:/relative', '//host.invalid/relative'):
            with self.subTest(destination=destination):
                self.assert_rules(f'import httpx\nclient = httpx.Client(base_url=input())\n'
                                  f'client.get({destination!r})\n', 'ssrf')
        self.assert_rules('import httpx\nclient = httpx.Client(base_url=input())\n'
                          'client.get("https://user@safe.invalid/relative")\n')
        with self.assertRaises(taint_py.AnalysisLimit):
            self.scan('import httpx\nclient = httpx.Client(base_url=input())\n'
                      'client.get(httpx.URL("https://safe.invalid/fixed"))\n')

    def test_non_native_constructors_and_rebinding_do_not_get_contracts(self):
        for source in (
            'client = Session()\nclient.get(input())\n',
            'from other import Session\nclient = Session()\nclient.get(input())\n',
            'from .httpx import Client\nclient = Client()\nclient.get(input())\n',
            'import httpx\nhttpx = other\nclient = httpx.Client()\nclient.get(input())\n',
            'from httpx import Client\nClient = other\nclient = Client()\nclient.get(input())\n',
            'import requests\nclient = requests.Session()\nclient = other\nclient.get(input())\n',
        ):
            with self.subTest(source=source):
                self.assert_rules(source)

    def test_async_requests_only_execute_when_consumed(self):
        self.assert_rules('''
            import httpx
            async def fetch():
                async with httpx.AsyncClient() as client:
                    await client.get(input())
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            client = httpx.AsyncClient()
            pending = client.get(input())
        ''')
        self.assert_rules('''
            import httpx, asyncio
            client = httpx.AsyncClient()
            pending = client.get(input())
            asyncio.run(pending)
        ''', 'ssrf')
        self.assert_rules('''
            import httpx, asyncio
            async def fetch():
                client = httpx.AsyncClient()
                task = asyncio.create_task(client.get(input()))
        ''', 'ssrf')

    def test_stream_contexts_execute_at_entry(self):
        self.assert_rules('''
            import httpx
            client = httpx.Client()
            pending = client.stream('GET', input())
        ''')
        self.assert_rules('''
            import httpx
            client = httpx.Client()
            with client.stream('GET', input()) as response:
                pass
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            async def fetch():
                client = httpx.AsyncClient()
                async with client.stream('GET', input()) as response:
                    pass
        ''', 'ssrf')

    def test_async_and_stream_summaries_preserve_pending_requests(self):
        self.assert_rules('''
            import httpx
            def prepare(client, target):
                return client.get(target)
            async def fetch():
                client = httpx.AsyncClient()
                await prepare(client, input())
        ''', 'ssrf')
        self.assert_rules('''
            import httpx
            def prepare(target):
                return httpx.Client().stream('GET', target)
            with prepare(input()) as response:
                pass
        ''', 'ssrf')

    def test_scheduled_http_keeps_other_coroutine_effects(self):
        self.assert_rules('''
            import httpx, asyncio
            async def execute(value):
                eval(value)
            async def fetch():
                client = httpx.AsyncClient()
                await asyncio.gather(client.get(input()), execute(input()))
        ''', 'ssrf', 'eval')
        self.assert_rules('''
            import httpx, asyncio
            async def execute(value):
                eval(value)
            async def fetch():
                client = httpx.AsyncClient()
                await asyncio.gather(client.get('https://example.invalid'), execute(input()))
        ''', 'eval')

    def test_custom_clients_and_deferred_mutation_remain_explicit(self):
        for source in (
            'import httpx\nclient = httpx.Client(auth=custom_auth)\nclient.get("https://safe.invalid")\n',
            'import httpx\nclient = httpx.Client()\nclient.get("https://safe.invalid", auth=custom_auth)\n',
            'import httpx\nclient = httpx.Client(transport=custom_transport)\n',
            'import httpx\nclient = httpx.Client(event_hooks={"request": [change_url]})\n',
            'import httpx\nclient = httpx.Client()\nclient.send(client.build_request("GET", input()))\n',
            'import httpx\nclient = httpx.Client()\npending = client.stream("GET", "/relative")\n'
            'client.base_url = input()\nwith pending:\n    pass\n',
            'import httpx\nasync def fetch():\n    client = httpx.AsyncClient()\n'
            '    pending = client.get("/relative")\n    client.base_url = input()\n    await pending\n',
        ):
            with self.subTest(source=source):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(source)
        self.assert_rules('import httpx\nclient = httpx.Client(event_hooks={}, mounts={})\n'
                          'client.get("https://example.invalid", auth=("user", input()))\n')

    def test_mutated_and_escaped_clients_refuse_complete_clean(self):
        for body in (
            'client.base_url = input()\nclient.get("/relative")',
            'alias = client\nalias.get = replacement\nclient.get(input())',
            'configure(client)\nclient.get(input())',
        ):
            with self.subTest(body=body):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('import httpx\nclient = httpx.Client()\n' + body + '\n')
        for source in (
            'import httpx\nhttpx.Client = replacement\nhttpx.Client().get(input())\n',
            'import requests\nrequests.Session.get = replacement\nrequests.Session().get(input())\n',
        ):
            with self.subTest(source=source):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(source)


class UrllibDestinationTests(SourceTest):
    """The stdlib opener consumes a URL; Request construction does not."""

    def test_native_url_sinks_and_selected_operands(self):
        for name in ('urlopen', 'urlretrieve'):
            for imports, call in (
                ('import urllib.request', f'urllib.request.{name}'),
                ('from urllib import request as client', f'client.{name}'),
                (f'from urllib.request import {name} as send', 'send'),
            ):
                with self.subTest(name=name, imports=imports):
                    self.assert_rules(f'{imports}\n{call}(input())\n', 'ssrf')
                    self.assert_rules(f'{imports}\n{call}(url=input())\n', 'ssrf')
                    self.assert_rules(f'{imports}\n{call}(**{{"url": input()}})\n', 'ssrf')
                    self.assert_rules(f'{imports}\n{call}("https://safe.invalid", data=input())\n')
            self.assert_rules(f'import urllib.request\nfetch = urllib.request.{name}\n'
                              'urllib = other\nfetch(input())\n', 'ssrf')
        self.assert_rules('from urllib.request import urlopen\n'
                          'urlopen(*["https://safe.invalid", input()])\n')
        self.assert_rules('from urllib.request import urlretrieve\n'
                          'urlretrieve("https://safe.invalid", filename=input(), reporthook=None, data=input())\n')
        self.assert_rules('from urllib.request import urlopen\nurlopen(*input())\n', 'ssrf')

    def test_request_url_is_consumed_at_open_not_construction(self):
        for imports, constructor in (
            ('import urllib.request', 'urllib.request.Request'),
            ('from urllib.request import Request as make', 'make'),
            ('from urllib import request as client', 'client.Request'),
        ):
            with self.subTest(constructor=constructor):
                source = imports + f'\nrequest = {constructor}(input())\n'
                self.assert_rules(source)
                self.assert_rules(source + 'from urllib.request import urlopen\nurlopen(request)\n', 'ssrf')
        self.assert_rules('from urllib.request import Request, urlopen\n'
                          'urlopen(Request(url=input()))\n', 'ssrf')
        self.assert_rules('from urllib.request import Request, urlopen\n'
                          'urlopen(Request(**{"url": input()}))\n', 'ssrf')

    def test_request_body_headers_and_method_are_not_destinations(self):
        self.assert_rules('''
            from urllib.request import Request, urlopen
            request = Request('https://safe.invalid', data=input(),
                              headers={'X-User': input()}, method=input(),
                              origin_req_host=input(), unverifiable=True)
            urlopen(request, data=input(), timeout=3)
        ''')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            request = Request('https://safe.invalid', input(), {'X-User': input()})
            urlopen(request)
        ''')
        self.assert_rules('''
            from urllib.request import Request
            request = Request(input())
            eval(str(request))
        ''')

    def test_request_aliases_readers_and_saved_constructors(self):
        self.assert_rules('''
            import urllib.request as native
            make = native.Request
            native = other
            request = make(input())
            alias = request
            request = unrelated
            from urllib.request import urlopen
            urlopen(alias)
        ''', 'ssrf')
        for expression in ('request.full_url', 'request.get_full_url()'):
            with self.subTest(expression=expression):
                self.assert_rules('from urllib.request import Request, urlopen\n'
                                  f'request = Request(input())\nurlopen({expression})\n', 'ssrf')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            request = Request(input())
            read = request.get_full_url
            request = unrelated
            urlopen(read())
        ''', 'ssrf')

    def test_local_helpers_and_closures_preserve_selected_request_url(self):
        self.assert_rules('''
            from urllib.request import Request, urlopen
            def prepare(target):
                return Request(target)
            def forward(request):
                return urlopen(request)
            forward(prepare(input()))
        ''', 'ssrf')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            def prepare(data):
                return Request('https://safe.invalid', data=data)
            def forward(request):
                return urlopen(request)
            forward(prepare(input()))
        ''')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            def prepare(target):
                request = Request(target)
                def send():
                    return urlopen(request)
                return send
            prepare(input())()
        ''', 'ssrf')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            def reader(request):
                return request.get_full_url
            urlopen(reader(Request(input()))())
        ''', 'ssrf')

    def test_default_openers_use_fullurl_argument(self):
        self.assert_rules('''
            from urllib.request import build_opener, Request
            opener = build_opener()
            opener.open(Request(input()))
        ''', 'ssrf')
        self.assert_rules('''
            import urllib.request
            opener = urllib.request.build_opener()
            send = opener.open
            opener = other
            send(fullurl=input())
        ''', 'ssrf')
        self.assert_rules('''
            from urllib.request import build_opener
            def factory():
                return build_opener()
            def fetch(opener, target):
                return opener.open(target)
            fetch(factory(), input())
        ''', 'ssrf')
        self.assert_rules('''
            from urllib.request import build_opener
            build_opener().open('https://safe.invalid', data=input())
        ''')

    def test_url_guard_and_strong_overwrite_remain_clean(self):
        prefix = HTTPDestinationTests.url_guard_source()
        self.assert_rules(prefix + '''
import urllib.request
target = input()
if not approved(target):
    raise ValueError('blocked')
urllib.request.urlopen(urllib.request.Request(target))
''')
        self.assert_rules('''
            from urllib.request import Request, urlopen
            target = input()
            target = 'https://safe.invalid'
            urlopen(Request(target))
        ''')
        for sanitizer in ('html.escape', 'shlex.quote'):
            with self.subTest(sanitizer=sanitizer):
                self.assert_rules(f'import urllib.request, html, shlex\n'
                                  f'urllib.request.urlopen(urllib.request.Request({sanitizer}(input())))\n', 'ssrf')

    def test_shadowed_imports_and_unrelated_open_methods_stay_clean(self):
        for source in (
            'from .urllib.request import urlopen\nurlopen(input())\n',
            'from other import urlopen\nurlopen(input())\n',
            'import urllib.request\nurllib = other\nurllib.request.urlopen(input())\n',
            'from urllib.request import urlopen\nurlopen = other\nurlopen(input())\n',
            'def urlopen(target):\n    return None\nurlopen(input())\n',
            'opener = other()\nopener.open(input())\n',
            'import urllib.request\ndef fetch(urllib):\n    urllib.request.urlopen(input())\n',
        ):
            with self.subTest(source=source):
                self.assert_rules(source)

    def test_request_mutation_and_escape_stay_explicit(self):
        for mutation in (
            'request.full_url = input()',
            'alias = request\nalias.host = input()',
            'request.set_proxy(input(), "https")',
            'configure(request)',
            'stored = [request]',
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('from urllib.request import Request, urlopen\n'
                              'request = Request("https://safe.invalid")\n'
                              + mutation + '\nurlopen(request)\n')
        for member in ('Request', 'urlopen', 'urlretrieve', 'build_opener', '_opener'):
            with self.subTest(member=member):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(f'import urllib.request\nurllib.request.{member} = replacement\n'
                              'urllib.request.urlopen("https://safe.invalid")\n')

    def test_custom_opener_and_retrieval_callbacks_stay_explicit(self):
        for source in (
            'import urllib.request\nurllib.request.install_opener(custom)\n'
            'urllib.request.urlopen("https://safe.invalid")\n',
            'from urllib.request import build_opener\nbuild_opener(custom).open("https://safe.invalid")\n',
            'from urllib.request import build_opener\nopener = build_opener()\n'
            'opener.add_handler(custom)\nopener.open("https://safe.invalid")\n',
            'from urllib.request import urlretrieve\n'
            'urlretrieve("https://safe.invalid", reporthook=callback)\n',
            'from urllib.request import urlretrieve\n'
            'urlretrieve("https://safe.invalid", "output", callback)\n',
            'from urllib.request import Request, urlopen\nurlopen(Request(**options))\n',
        ):
            with self.subTest(source=source):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(source)

    def test_argument_effects_and_sink_locations_are_preserved(self):
        found = self.assert_rules('''
            from urllib.request import Request, urlopen
            request = Request(input(), headers={'X-User': eval(input())})
            urlopen(request, data=eval(input()))
        ''', 'eval', 'eval', 'ssrf')
        self.assertEqual(sorted((row['rule'], row['line']) for row in found),
                         [('python.taint.eval', 2), ('python.taint.eval', 3), ('python.taint.ssrf', 3)])

    def test_native_request_destinations_without_network(self):
        from urllib import request as native
        from urllib.response import addinfourl
        from unittest.mock import patch

        seen = []

        class Capture(native.BaseHandler):
            def default_open(self, request):
                seen.append((request.full_url, request.data, request.get_header('X-user')))
                response = addinfourl(io.BytesIO(b'ok'), {}, request.full_url, 200)
                response.msg = 'OK'
                return response

        opener = native.build_opener(native.ProxyHandler({}), Capture())
        with temporary_directory(prefix='ubs-urllib-native-') as temporary:
            target = 'https://untrusted.invalid/items'
            request = native.Request(target, data=b'body', headers={'X-User': 'metadata'})
            self.assertEqual(seen, [])
            self.assertEqual(request.get_full_url(), target)
            with patch.object(native, '_opener', opener):
                with native.urlopen(request) as response:
                    self.assertEqual(response.read(), b'ok')
                with opener.open(fullurl='https://safe.invalid', data=b'untrusted-body') as response:
                    self.assertEqual(response.read(), b'ok')
                output = str(Path(temporary, 'download'))
                saved, _headers = native.urlretrieve(target, filename=output)
                self.assertEqual(saved, output)
                self.assertEqual(Path(saved).read_bytes(), b'ok')
            self.assertEqual(seen, [(target, b'body', 'metadata'),
                                   ('https://safe.invalid', b'untrusted-body', None),
                                   (target, None, None)])

    def test_joined_request_and_string_destinations_keep_both_branches(self):
        for destination in ('Request(input()) if choose else "https://safe.invalid"',
                            'Request("https://safe.invalid") if choose else input()',
                            'Request(input()) if choose else Request("https://safe.invalid")'):
            with self.subTest(destination=destination):
                self.assert_rules('from urllib.request import Request, urlopen\n'
                                  f'destination = {destination}\nurlopen(destination)\n', 'ssrf')
        self.assert_rules('from urllib.request import Request, urlopen\n'
                          'destination = Request("https://safe.invalid") if choose else "https://safe.invalid/other"\n'
                          'urlopen(destination)\n')

    def test_handles_never_borrow_unproved_protocols(self):
        for source in (
            'from urllib.request import Request, urlopen\nr = Request(input())\nurlopen(r.get_full_url)\n',
            'from urllib.request import Request, urlretrieve\nurlretrieve(Request(input()))\n',
            'from urllib.request import Request\nwith Request(input()):\n    pass\n',
            'from urllib.request import build_opener\nwith build_opener():\n    pass\n',
            'from urllib.request import Request\nr = Request(input())\ngetattr(r, "full_url")\n',
        ):
            with self.subTest(source=source):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan(source)

    def test_reflective_namespace_and_class_replacement_are_explicit(self):
        for operation in (
            'setattr(native, "urlopen", replacement)',
            'configure(native)',
            'native.Request.__new__ = replacement',
            'native.Request.__str__ = replacement',
            'native.OpenerDirector.open = replacement',
            'native.__dict__["urlopen"] = replacement',
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('import urllib.request as native\n' + operation +
                              '\nnative.urlopen(native.Request("https://safe.invalid"))\n')

    def test_custom_header_iteration_and_key_callbacks_stay_explicit(self):
        for headers in ('custom_headers', '{custom_key: "value"}', '{**custom_headers}'):
            with self.subTest(headers=headers):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('from urllib.request import Request, urlopen\n'
                              f'urlopen(Request("https://safe.invalid", headers={headers}))\n')
        self.assert_rules('from urllib.request import Request, urlopen\n'
                          'headers = {"X-Value": input()}\n'
                          'urlopen(Request("https://safe.invalid", headers=headers))\n')

    def test_custom_url_string_conversion_cannot_certify_clean(self):
        for method in (
            'return input()',
            'global target\n        target = input()\n        return "https://safe.invalid"',
        ):
            with self.subTest(method=method):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('from urllib.request import Request, urlopen\n'
                              'target = "https://safe.invalid"\nclass URL:\n'
                              f'    def __str__(self):\n        {method}\n'
                              'request = Request(URL())\nurlopen(request)\nurlopen(target)\n')
        with self.assertRaises(taint_py.AnalysisLimit):
            self.scan('from urllib.request import Request, urlopen\n'
                      'urlopen(Request(opaque_url))\n')

    def test_custom_request_subclasses_cannot_borrow_native_identity(self):
        for initializer in ('super().__init__(input())', 'Request.__init__(self, input())'):
            with self.subTest(initializer=initializer):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('from urllib.request import Request, urlopen\n'
                              'class Custom(Request):\n    def __init__(self):\n'
                              f'        {initializer}\nurlopen(Custom())\n')
        for call in ('urlopen(opaque_request)', 'build_opener().open(opaque_request)'):
            with self.subTest(call=call):
                with self.assertRaises(taint_py.AnalysisLimit):
                    self.scan('from urllib.request import urlopen, build_opener\n' + call + '\n')

    @unittest.skipUnless(os.environ.get('UBS_URLLIB_E2E') == '1', 'opt-in verified urllib scanner integration')
    def test_public_module_and_runner_formats(self):
        cases = (
            ('direct', 'from urllib.request import urlopen\nurlopen(input())\n', 2, False, 2),
            ('request-alias', 'from urllib.request import Request, urlopen\n'
             'request = Request(input())\nalias = request\nurlopen(alias)\n', 4, False, 4),
            ('opener-alias', 'from urllib.request import build_opener\n'
             'opener = build_opener()\nsend = opener.open\nsend(fullurl=input())\n', 4, False, None),
            ('safe-metadata', 'from urllib.request import Request, urlopen\n'
             'request = Request("https://safe.invalid", data=input(), headers={"X-Value": input()})\n'
             'urlopen(request)\n', None, False, 3),
            ('suppressed', 'from urllib.request import urlopen\n'
             'urlopen(input())  # ubs:ignore[python.taint.ssrf]\n', None, False, 2),
            ('partial-mutation', 'from urllib.request import Request, urlopen\n'
             'request = Request("https://safe.invalid")\nrequest.full_url = input()\n'
             'urlopen(request)\n', None, True, 4),
            ('partial-retained', 'from urllib.request import urlopen, build_opener\n'
             'urlopen(input())\nbuild_opener(custom)\n', 2, True, 2),
        )
        with temporary_directory(prefix='ubs-urllib-public-') as temporary:
            directory = Path(temporary)
            # This matrix targets the security category; the source cohort
            # independently checks interactions with existing HTTP analyzers.
            skip = '--skip=' + ','.join(str(value) for value in range(1, 25) if value != 7)
            env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'ENABLE_UV_TOOLS': '0',
                   'UBS_KEEP_TEMP': '1', 'UBS_NO_CACHE': '1', 'UBS_ALLOW_PARTIAL': '0'}
            for case, source, line, partial, timeout_line in cases:
                path = directory / (case + '.py')
                path.write_text(source, encoding='utf-8')
                expected = sorted((rule, path.name, site) for rule, site in (
                    ('python.taint.ssrf', line), ('py.security.http-timeout', timeout_line)) if site is not None)
                for runner in (False, True):
                    entrypoint = ROOT / 'ubs' if runner else ROOT / 'modules' / 'ubs-python.sh'
                    for output in ('json', 'sarif'):
                        with self.subTest(case=case, runner=runner, output=output):
                            tag = f'{case}-{"runner" if runner else "module"}-{output}'
                            command = [str(entrypoint), '--ci', '--no-color', skip, '--format=' + output]
                            command += ['--only=python'] if runner else ['--no-uv']
                            result = subprocess.run([*command, str(path)], cwd=directory, env=env,
                                                    capture_output=True, text=True, timeout=120)
                            (directory / (tag + '.stdout')).write_text(result.stdout, encoding='utf-8')
                            (directory / (tag + '.stderr')).write_text(result.stderr, encoding='utf-8')
                            detail = (tag, result.returncode, result.stdout, result.stderr)
                            self.assertEqual(result.returncode, 2 if partial else 1 if line else 0, detail)
                            document = json.loads(result.stdout)
                            if output == 'json':
                                self.assertEqual(document['status'], 'partial' if partial else 'ok', detail)
                                totals = document['totals'] if runner else document
                                self.assertEqual(totals['files'], 1, detail)
                                self.assertEqual(totals['critical'], int(line is not None), detail)
                                self.assertEqual(totals['warning'], int(timeout_line is not None), detail)
                                self.assertEqual(totals['info'], 0, detail)
                                rows = document['findings']
                                self.assertEqual(len(rows), len(expected), detail)
                                if runner:
                                    actual = [(row['rule_id'], Path(row['file']).name, row['line']) for row in rows]
                                    self.assertTrue(all(row['col'] == 1 for row in rows), detail)
                                else:
                                    self.assertTrue(all(row['count'] == 1 and len(row['samples']) == 1
                                                        for row in rows), detail)
                                    actual = [(row['rule_id'], Path(sample['file']).name, sample['line'])
                                              for row in rows for sample in row['samples']]
                                self.assertEqual(sorted(actual), expected, detail)
                            else:
                                runs = document['runs']
                                self.assertTrue(runs, detail)
                                rows = [row for run in runs for row in run['results']]
                                self.assertEqual(len(rows), len(expected), detail)
                                actual = []
                                for row in rows:
                                    self.assertEqual(len(row['locations']), 1, detail)
                                    location = row['locations'][0]['physicalLocation']
                                    self.assertTrue(location['artifactLocation']['uri'].endswith(path.name), detail)
                                    self.assertEqual(location['region']['startColumn'], 1, detail)
                                    actual.append((row['ruleId'], path.name, location['region']['startLine']))
                                self.assertEqual(sorted(actual), expected, detail)
                                for run in runs:
                                    if partial:
                                        invocation = run['invocations'][0]
                                        self.assertIs(invocation['executionSuccessful'], False, detail)
                                        self.assertEqual(invocation['exitCode'], 2, detail)
                                    else:
                                        self.assertTrue(all(inv['executionSuccessful'] is True
                                                            for inv in run.get('invocations', [])), detail)
                            print(f'[{tag}] PASS', flush=True)


if __name__ == '__main__':
    unittest.main()
