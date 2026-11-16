"""Independent source contracts for pooled HTTP clients; never execute fixtures."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.registry import RunContext
from ubs_core.taint_flow import AnalysisLimit


# Exact contracts require both complete analysis and a precise destination
# location. Boundaries never count as a precise detection.
CASES = {
    'session_factory': ('exact', '''
        from requests import Session
        def pool():
            return Session()
        pool().get(input())
        ''', [('ssrf', 4)]),
    'client_factory_relative': ('exact', '''
        import httpx
        def pool(base):
            return httpx.Client(base_url=base)
        client = pool(input())
        client.request('GET', '/items')
        ''', [('ssrf', 5)]),
    'client_factory_absolute': ('exact', '''
        import httpx
        def pool(base):
            return httpx.Client(base_url=base)
        client = pool(input())
        client.request('GET', 'https://safe.invalid/items')
        ''', []),
    'bound_method_through_two_helpers': ('exact', '''
        import httpx
        def method(pool):
            return pool.get
        def forward(call, target):
            return call(target)
        forward(method(httpx.Client()), input())
        ''', [('ssrf', 5)]),
    'async_saved_pending_alias': ('exact', '''
        import httpx
        async def run():
            client = httpx.AsyncClient()
            saved = client.get(input())
            alias = saved
            client = unrelated
            await alias
        ''', [('ssrf', 4)]),
    'async_pending_from_helper': ('exact', '''
        import httpx
        def prepare(client, target):
            return client.get(target)
        async def run():
            pending = prepare(httpx.AsyncClient(), input())
            await pending
        ''', [('ssrf', 3)]),
    'async_pending_helper_unused': ('exact', '''
        import httpx
        def prepare(client, target):
            return client.get(target)
        pending = prepare(httpx.AsyncClient(), input())
        ''', []),
    'stream_from_helper': ('exact', '''
        import httpx
        def prepare(target):
            return httpx.Client().stream('GET', target)
        with prepare(input()):
            pass
        ''', [('ssrf', 3)]),
    'async_stream_entered': ('exact', '''
        import httpx
        async def run():
            client = httpx.AsyncClient()
            pending = client.stream('GET', input())
            async with pending:
                pass
        ''', [('ssrf', 4)]),
    'async_stream_unused': ('exact', '''
        import httpx
        client = httpx.AsyncClient()
        pending = client.stream('GET', input())
        ''', []),
    'joined_client_and_cache': ('exact', '''
        import httpx
        client = httpx.Client() if condition else cache
        client.get(input())
        ''', [('ssrf', 3)]),
    'constructor_metadata_and_query': ('exact', '''
        import httpx
        client = httpx.Client(headers={'X-User': input()}, params={'q': input()})
        client.get('https://safe.invalid', params={'q': input()})
        ''', []),
    'known_scalar_options': ('exact', '''
        import httpx
        client = httpx.Client(timeout=3, verify=True, trust_env=False, follow_redirects=False)
        client.get('https://safe.invalid')
        ''', []),
    'conditional_url_still_unsafe': ('exact', '''
        import httpx
        target = input() if condition else 'https://safe.invalid'
        httpx.Client().get(target)
        ''', [('ssrf', 3)]),
    'literal_url_strong_overwrite': ('exact', '''
        import httpx
        target = input()
        target = 'https://safe.invalid'
        httpx.Client().get(target)
        ''', []),
    'callback_native_client_return': ('exact', '''
        import httpx
        def outer():
            client = httpx.Client()
            def send(target):
                return client.get(target)
            return send
        outer()(input())
        ''', [('ssrf', 5)]),
    'async_schedule_task': ('exact', '''
        import httpx, asyncio
        async def run():
            client = httpx.AsyncClient()
            task = asyncio.create_task(client.get(input()))
        ''', [('ssrf', 4)]),
    'sync_stream_direct_entry': ('exact', '''
        import httpx
        with httpx.Client().stream('GET', input()) as response:
            pass
        ''', [('ssrf', 2)]),
    'base_mutation_after_pending': ('boundary', '''
        import httpx
        async def run():
            client = httpx.AsyncClient(base_url='https://safe.invalid')
            pending = client.get('/items')
            client.base_url = input()
            await pending
        ''', []),
    'custom_transport_boundary': ('boundary', '''
        import httpx
        client = httpx.Client(transport=unknown)
        client.get('https://safe.invalid')
        ''', []),
    'custom_event_hooks_boundary': ('boundary', '''
        import httpx
        client = httpx.Client(event_hooks=hooks)
        client.get('https://safe.invalid')
        ''', []),
    'opaque_options_boundary': ('boundary', '''
        import httpx
        client = httpx.Client(**options)
        client.get('https://safe.invalid')
        ''', []),
    'prepared_request_boundary': ('boundary', '''
        import httpx
        client = httpx.Client()
        request = client.build_request('GET', input())
        client.send(request)
        ''', []),
    'relative_constructor_shadow': ('exact', '''
        from .httpx import Client
        client = Client()
        client.get(input())
        ''', []),
}


def main():
    out = Path(tempfile.mkdtemp(prefix='pooled-http-independent-extra-', dir=ROOT/'test-suite/artifacts'))
    started = time.monotonic()
    before = hashlib.sha256((ROOT/'modules/helpers/ubs_core/analyzers/taint_py.py').read_bytes()).hexdigest()
    rows = []
    for name, (mode, source, expected) in CASES.items():
        path = out / f'{name}.py'
        path.write_text(textwrap.dedent(source).lstrip('\n'), encoding='utf-8')
        records = []
        error = None
        incomplete = False
        try:
            records.extend(taint_py.run(RunContext(lang='python', files=[path])))
        except Exception as exc:
            incomplete = isinstance(exc, AnalysisLimit)
            error = f'{type(exc).__name__}: {exc}'
        actual = sorted((row['rule'].removeprefix('python.taint.'), row['line']) for row in records)
        passed = error is None and actual == sorted(expected) if mode == 'exact' else incomplete and not actual
        row = {'case':name, 'mode':mode, 'expected':expected, 'actual':actual,
               'passed':passed, 'incomplete':incomplete, 'error':error, 'records':records}
        rows.append(row)
        print(json.dumps(row), flush=True)
    result = {'artifact':str(out), 'source_sha256_before':before,
              'source_sha256_after':hashlib.sha256((ROOT/'modules/helpers/ubs_core/analyzers/taint_py.py').read_bytes()).hexdigest(),
              'python':sys.version, 'elapsed':time.monotonic()-started, 'cases':len(rows),
              'passed':sum(row['passed'] for row in rows), 'rows':rows}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:value for key,value in result.items() if key!='rows'}))
    return int(result['passed'] != result['cases'])


if __name__ == '__main__':
    raise SystemExit(main())
