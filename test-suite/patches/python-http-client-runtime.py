"""Native client mutation/deferred-execution witnesses with no network I/O.

This checkpoint is intentionally outside unittest discovery. Run explicitly
with optional HTTPX installed in the selected interpreter:
    python3 test-suite/patches/python-http-client-runtime.py

All seven assertions passed through HTTPX 0.28.1 before the execution
workspace disconnected. The session-specific dependency search path was
removed for packaging; this packaged copy has not executed. No HTTP
dependency is added to the scanner's ordinary runtime.
"""
import asyncio
import json

try:
    import httpx
except ModuleNotFoundError as exc:
    raise SystemExit("This optional native witness requires httpx in the selected interpreter") from exc

seen = []
checks = []

def capture(request):
    seen.append(str(request.url))
    return httpx.Response(200, text='ok')

def checked(name, action, expected):
    before = len(seen)
    action()
    actual = seen[before:]
    assert actual == expected, (name, expected, actual)
    checks.append({'case': name, 'expected': expected, 'actual': actual})

with httpx.Client(transport=httpx.MockTransport(capture), trust_env=False,
                  base_url='https://safe.invalid/') as client:
    saved = client.get
    client.base_url = 'https://untrusted.invalid/base/'
    checked('base_mutation', lambda: client.get('/resource'),
            ['https://untrusted.invalid/base/resource'])
    checked('saved_method_reads_live_base', lambda: saved('/live'),
            ['https://untrusted.invalid/base/live'])
    checked('absolute_url_overrides_live_base', lambda: client.get('https://safe.invalid/fixed'),
            ['https://safe.invalid/fixed'])
    client.get = lambda url: url
    checked('replaced_method_does_not_send', lambda: client.get('https://untrusted.invalid/no-send'), [])
    checked('saved_method_survives_method_replacement', lambda: saved('https://untrusted.invalid/send'),
            ['https://untrusted.invalid/send'])

with httpx.Client(transport=httpx.MockTransport(capture), trust_env=False) as client:
    before = len(seen)
    pending = client.stream('GET', 'https://untrusted.invalid/stream')
    assert len(seen) == before
    with pending:
        pass
    assert seen[before:] == ['https://untrusted.invalid/stream']
    checks.append({'case': 'stream_sends_only_on_enter', 'actual': seen[before:]})

async def async_requests():
    async with httpx.AsyncClient(transport=httpx.MockTransport(capture), trust_env=False) as client:
        before = len(seen)
        pending = client.get('https://untrusted.invalid/async')
        assert len(seen) == before
        await pending
        assert seen[before:] == ['https://untrusted.invalid/async']
        checks.append({'case': 'async_sends_only_on_await', 'actual': seen[before:]})

asyncio.run(async_requests())
print(json.dumps({'httpx': httpx.__version__, 'checks': checks, 'passed': len(checks)}))
