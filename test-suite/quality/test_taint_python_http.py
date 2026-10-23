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


if __name__ == '__main__':
    unittest.main()
