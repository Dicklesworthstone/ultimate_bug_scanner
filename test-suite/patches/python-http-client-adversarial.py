"""Independent pooled-client source probes; fixtures are analyzed, never executed.

This checkpoint is intentionally outside unittest discovery. Run explicitly:
    python3 test-suite/patches/python-http-client-adversarial.py [REPOSITORY]

The frozen 34-case oracle passed 14 cases and failed 20 against baseline
f0f99f9. No pooled-client implementation was executed against this oracle.
Only repository-path packaging changed after that run; this packaged copy
has not executed. Temporary source fixtures remain under test-suite/artifacts.
"""
import json
from pathlib import Path
import sys
import tempfile
import textwrap

repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo / 'modules/helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.registry import RunContext
from ubs_core.taint_flow import AnalysisLimit

# 'unsafe' accepts a precise destination finding or an explicit coverage
# boundary. 'exact' requires complete analysis and exactly the listed rules.
CASES = {
    'base_relative_url': ('unsafe', '''import httpx
client = httpx.Client(base_url=input())
client.get('/resource')
''', [('ssrf', 3)]),
    'base_empty_url': ('unsafe', '''import httpx
client = httpx.Client(base_url=input())
client.get('')
''', [('ssrf', 3)]),
    'base_absolute_url_overrides': ('exact', '''import httpx
client = httpx.Client(base_url=input())
client.get('https://safe.invalid/resource')
''', []),
    'base_alias_relative': ('unsafe', '''from httpx import Client as Pool
base = input()
client = Pool(base_url=base)
alias = client
alias.request('GET', '/resource')
''', [('ssrf', 5)]),
    'fixed_base_does_not_sanitize_absolute_input': ('unsafe', '''import httpx
client = httpx.Client(base_url='https://safe.invalid')
client.get(input())
''', [('ssrf', 3)]),
    'base_unknown_kwargs': ('unsafe', '''import httpx
client = httpx.Client(**request.json)
client.get('/resource')
''', [('ssrf', 3)]),
    'base_exact_kwargs': ('unsafe', '''import httpx
client = httpx.Client(**{'base_url': input()})
client.get('/resource')
''', [('ssrf', 3)]),
    'ctor_header_not_destination': ('exact', '''import httpx
client = httpx.Client(base_url='https://safe.invalid', headers={'X-User': input()})
client.get('/resource')
''', []),
    'ctor_auth_not_destination': ('exact', '''import httpx
client = httpx.Client(base_url='https://safe.invalid', auth=('user', input()))
client.get('/resource')
''', []),
    'request_body_not_destination': ('exact', '''import httpx
client = httpx.Client(base_url='https://safe.invalid')
client.post('/resource', json={'url': input()})
''', []),
    'base_changed_to_input': ('unsafe', '''import httpx
client = httpx.Client(base_url='https://safe.invalid')
client.base_url = input()
client.get('/resource')
''', [('ssrf', 4)]),
    'base_changed_through_alias': ('unsafe', '''import httpx
client = httpx.Client(base_url='https://safe.invalid')
alias = client
alias.base_url = input()
client.get('/resource')
''', [('ssrf', 5)]),
    'escaped_receiver': ('unsafe', '''import httpx
client = httpx.Client(base_url='https://safe.invalid')
configure(client)
client.get(input())
''', [('ssrf', 4)]),
    'saved_method_receiver_rebound': ('unsafe', '''import httpx
client = httpx.Client()
send = client.get
client = cache
send(input())
''', [('ssrf', 5)]),
    'saved_constructor_module_rebound': ('unsafe', '''import httpx
Pool = httpx.Client
httpx = cache
Pool().get(input())
''', [('ssrf', 4)]),
    'native_method_saved_before_instance_mutation': ('unsafe', '''import httpx
client = httpx.Client()
send = client.get
client.get = lambda value: value
send(input())
''', [('ssrf', 5)]),
    'constructor_member_monkeypatch': ('boundary', '''import httpx
httpx.Client = replacement
httpx.Client().get(input())
''', []),
    'instance_method_monkeypatch': ('boundary', '''import httpx
client = httpx.Client()
client.get = replacement
client.get(input())
''', []),
    'class_method_monkeypatch': ('boundary', '''import httpx
httpx.Client.get = replacement
httpx.Client().get(input())
''', []),
    'opaque_constructor_options_before_fixed_url': ('boundary', '''import httpx
client = httpx.Client(**options)
client.get('https://safe.invalid')
''', []),
    'relative_import_shadow': ('exact', '''from .httpx import Client
Client().get(input())
''', []),
    'local_function_constructor_shadow': ('exact', '''import httpx
def run(httpx):
    client = httpx.Client()
    client.get(input())
''', []),
    'conditional_native_client': ('unsafe', '''import httpx
client = httpx.Client() if condition else cache
client.get(input())
''', [('ssrf', 3)]),
    'client_return_constant_helper': ('exact', '''import httpx
def destination(value):
    return 'https://safe.invalid'
client = httpx.Client()
client.get(destination(input()))
''', []),
    'safe_url_guard_client': ('exact', '''import httpx
from urllib.parse import urlparse
HOSTS = {'safe.invalid'}
def approved(value):
    parsed = urlparse(value)
    return parsed.scheme == 'https' and parsed.hostname in HOSTS
value = input()
if not approved(value):
    raise ValueError('blocked')
httpx.Client().get(value)
''', []),
    'constructor_argument_eval_effect': ('effects', '''import httpx
client = httpx.Client(headers={'X-User': eval(input())})
client.get('https://safe.invalid')
''', [('eval', 2)]),
    'method_argument_eval_effect': ('effects', '''import httpx
client = httpx.Client()
client.get('https://safe.invalid', headers={'X-User': eval(input())})
''', [('eval', 3)]),
    'exact_kwargs_non_url_source': ('exact', '''import requests
client = requests.Session()
client.get(**{'url': 'https://safe.invalid', 'params': {'url': input()}})
''', []),
    'client_method_unknown_starred_url': ('unsafe', '''import requests
client = requests.Session()
client.request(*input())
''', [('ssrf', 3)]),
    'client_method_exact_starred_method_only_source': ('exact', '''import requests
client = requests.Session()
client.request(*(input(), 'https://safe.invalid'))
''', []),
    'async_client_constructed_unused': ('exact', '''import httpx
client = httpx.AsyncClient()
pending = client.get(input())
''', []),
    'async_client_awaited': ('unsafe', '''import httpx
async def fetch():
    client = httpx.AsyncClient()
    await client.get(input())
''', [('ssrf', 4)]),
    'stream_context_unused': ('exact', '''import httpx
client = httpx.Client()
pending = client.stream('GET', input())
''', []),
    'stream_context_entered': ('unsafe', '''import httpx
client = httpx.Client()
with client.stream('GET', input()) as response:
    pass
''', [('ssrf', 3)]),
}

artifacts = repo / 'test-suite/artifacts'
artifacts.mkdir(parents=True, exist_ok=True)
root = Path(tempfile.mkdtemp(prefix='independent-http-adversarial-', dir=artifacts))
failures = []
for name, (mode, source, expected) in CASES.items():
    path = root / (name + '.py')
    path.write_text(textwrap.dedent(source), encoding='utf-8')
    records = []
    error = None
    incomplete = False
    try:
        records.extend(taint_py.run(RunContext(lang='python', files=[path])))
    except Exception as exc:
        incomplete = isinstance(exc, AnalysisLimit)
        error = type(exc).__name__ + ': ' + str(exc)
    actual = sorted((row['rule'].removeprefix('python.taint.'), row['line']) for row in records)
    wanted = sorted(expected)
    if mode == 'exact':
        okay = error is None and actual == wanted
    elif mode == 'unsafe':
        okay = actual == wanted or incomplete
    elif mode == 'effects':
        okay = set(wanted).issubset(actual) and all(rule != 'ssrf' for rule, _line in actual)
    else:
        okay = incomplete and not actual
    row = {'case': name, 'mode': mode, 'expected': wanted, 'actual': actual,
           'incomplete': incomplete, 'error': error, 'passed': okay}
    print(json.dumps(row), flush=True)
    if not okay:
        failures.append(name)
print(json.dumps({'repo': str(repo), 'cases': len(CASES), 'passed': len(CASES)-len(failures),
                  'failures': failures, 'artifacts': str(root)}))
sys.exit(bool(failures))
