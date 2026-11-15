# Pooled Python HTTP client SSRF checkpoint

## State

This is an **unfinished, unactivated implementation**, based on main
`f0f99f9da8cf6fdfee0a5cb458d422e25a7563e1`.
No production analyzer, automatic test, integrity pin or release version is
changed by this checkpoint.

The native Python taint analyzer recognizes module-level Requests and HTTPX
calls but misses destination flows through common pooled clients. Examples such
as `requests.Session().get(input())`, a client returned by a helper, and an
awaited `httpx.AsyncClient().get(input())` were complete and empty in the
baseline. Merely adding all methods named `get` would also flag dictionary
lookups and unrelated classes, so this needs actual import and receiver identity.

The runtime ran out of disk space, then disconnected and was explicitly marked
unavailable during migration. Functional dispatch was not finished. Preserved
source cannot be described as a working scanner enhancement.

## Preserved work

- `python-pooled-http-candidate.patch` contains the exact preliminary edits
  and 11-method regression oracle saved before the outage. It adds finite
  constructor/client/pending-request markers, contract lookup and initial mutation
  boundaries. Constructor dispatch, method resolution, destination transfer,
  context entry, deferred execution and complete escape handling remain unfinished.
- `python-http-client-adversarial.py` contains the separate 34-case
  qualification corpus. Source fixtures are analyzed, never executed.
- `python-http-client-runtime.py` preserves seven real HTTPX behavior
  witnesses using an in-process transport without network traffic.

The candidate patch was reconstructed from recorded manual edits, then replayed
forward and backward against immutable GitHub blobs. Reconstructed source and test
SHA-256 values match the hashes read from the copied checkout immediately before
disconnection:

- Analyzer: `39fee0d398ab87a5af3e4f73a7f032392e95e72334ef79bca987a0be133a973a`.
- Test file: `afdbb6a04d1e126882e213f8de86b9f45acaefb58b26ab5970db53aa6387cb39`.

This proves checkpoint integrity, not execution correctness. The standalone
oracles' portable paths/entrypoints were packaged after the outage and have not
been rerun in that packaged form.

## Observed evidence

All source checks used the actual DSR native executor and CPython 3.14.10.

| Check | Observed result |
| --- | --- |
| Maintained pooled-client oracle | 11 methods, 31 failing assertions/subcases on unchanged production |
| Independent basic source corpus | Nine missed unsafe flows; all five safe controls passed |
| Independent adversarial source corpus | 14 passed, 20 failed as complete-empty results |
| Native HTTPX mutation/deferred-execution witness | Seven actual behavior checks passed |
| Additional Requests/HTTPX transport witness | Eight actual operations reached their expected destinations |
| Candidate implementation replay | Not executed; implementation unfinished |

The adversarial corpus's 20 baseline failures contain 16 unsafe-use cases and four
explicit boundary expectations. Unsafe cases require a finding or an explicit
incomplete result; safe controls require complete analysis and their exact expected
findings. That distinction must remain visible: an incomplete result is not a
precise finding and must not be counted as one.

The safe controls protect fixed absolute destinations, unrelated data passed as
body/headers/authentication, shadowed APIs, constant helpers, selected URL guards,
independent argument-side effects, and unconsumed async/stream handles.

Recorded DSR receipts:

- Maintained baseline: `dsr-python-http-pooled-baseline-ocoEQHOd/output.log`,
  SHA-256 `6f95ebd71c397583c598eff9accbae27117f541209fc77a3dc60fca4b88eb171`.
- Independent basic baseline: `dsr-independent-python-baseline-jpDXTYsk/output.log`,
  SHA-256 `6b8c02385a529624c83956128b9af279c4cc281ff006efc2efd997f339c41226`.
- Independent adversarial baseline:
  `dsr-http-adversarial-baseline-xMLVUID3/output.log`,
  SHA-256 `9df0fdc01f81f0f0f56c0f32c512a0cab6943d3721b0259e7e584a9b796e9611`.
- Seven native HTTPX witnesses:
  `dsr-http-native-mutation-final-eU0jRWFB/output.log`,
  SHA-256 `26c6ff0251d9787dabad763e42411cccd723e8b911de3171fa30dd697e1019fe`.
- Eight additional native transport operations:
  `dsr-http-native-contracts-CSbEzL9C/output.log`,
  SHA-256 `b8934944c88f191246347c288b4dd59700f454465bb18e43e64b5285bdba0201`.

These are recorded receipt identifiers and hashes. The disconnected environment's
complete log bytes are not included.

## Semantics the implementation must preserve

Native observations used HTTPX 0.28.1 and Requests 2.34.2 with in-process transports.

- A client is a handle, not itself an input string. Its metadata must stay clean.
  Track `base_url` as a receiver fact rather than tainting every use of the handle.
- HTTPX relative and empty destinations inherit the client's base; absolute URLs
  override it. A leading slash does not discard HTTPX's base path.
- Saved bound methods read the receiver's live base URL. Mutating that base after
  saving a method must not freeze stale authority.
- Replacing an instance method can make later calls inert; a method saved before
  replacement still invokes its original implementation.
- Async requests execute when awaited or scheduled. `Client.stream` sends on
  context entry. Merely creating an unused coroutine or stream must not fabricate
  a reached network sink.
- Bodies, query parameters, headers and authentication are not URL operands.
  Evaluate their independent effects without treating them as destinations.
- Unknown mutation, custom hooks/transports and opaque storage/escape must not
  silently grant clean results. Conversely, do not reject harmless known options
  merely to make a boundary test pass.

The intended bounded implementation reuses `_BoundCallable` receiver slots and
existing summary substitution to transport symbolic base-URL facts and alias
identity without putting concrete provenance into context-cache keys.

## Continuation

Finish the actual constructor/method/context/deferred-execution transfer logic
before enabling the maintained tests. Re-run both fixed source oracles and the
native witnesses, then broader Python taint/summarization tests and real
module/meta-runner JSON/SARIF checks. Cover exact rule locations, statuses, counts,
suppression, selection and cache invalidation. Refresh the canonical integrity
chain only after source validation and follow the existing release gates.

No full-suite, final candidate, public-output, release or D6-completion claim is made.
