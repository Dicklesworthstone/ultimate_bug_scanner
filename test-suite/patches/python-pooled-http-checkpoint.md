# Pooled Python HTTP client SSRF checkpoint

## November 20 activation: native HTTPX prepared requests

Development version **5.5.98** adds native `httpx.Request`,
`Client`/`AsyncClient.build_request`, `Client.send` and consumed
`AsyncClient.send` analysis to the current production implementation. This
activation uses freshly qualified source and maintained tests on main through
`8dbd2999e83f6fd7eb0a642b90fba48377043905`. The interrupted patch descriptions
below remain historical recovery records.

A request retains its construction-time URL and builder base through aliases,
saved methods, selected helpers and closed factory callbacks. Sending it through
another client does not add that client's base. Synchronous `send(stream=True)`
sends immediately; asynchronous sends remain deferred until await/scheduling.
Reports preserve send-site coordinates and selected-project ownership. URL facts
remain distinct from body, query, header and credential metadata, with fixed URL,
validation, overwrite and unused-handle controls.

Native HTTPX observations exposed credential encoding, URL subclass, timeout,
boolean-option and redirect-comparison callbacks that can mutate a previously
built request. The implementation proves inert native constructor/request/send
inputs and keeps other protocols explicit incomplete boundaries. Pending async
sends retain option aliases for resume-time mutation checks. Custom transports,
hooks, proxies/limits, unknown option classes, prepared-object mutation and
opaque escape remain incomplete; established findings survive. This does not
implement Requests Session prepared sends.

### Recreated and executed evidence

After execution resumed, the maintained and independent tests were recreated
with new identities; they are not claimed to be the lost earlier test bytes.
The initial maintained class had 20 active methods and three opt-in public
methods. Before source activation, immutable main's Python analyzer failed six
assertions/subcases and raised 24 `AnalysisLimit` errors. Three later maintained
methods cover the independently demonstrated identity/alias/constructor-option
hazards. No expected findings or completion requirements were weakened.

The final HTTP cohort collected **106 methods: 97 executed and passed, nine
opt-in methods skipped**. The new feature's three public methods were separately
enabled and passed **35 actual module/runner calls**, including JSON/SARIF,
selection, suppression, retained findings on incomplete input, cache hits and
helper-edit invalidation. The final feature class contains 23 active source/native
methods and three opt-in methods.

Two unchanged independent corpora pass **43/43 scanner outcomes** (27 exact
results and 16 explicit boundaries) and **43/43 native HTTPX observations**,
using in-process transports with network access blocked. The first 37-case
corpus matched 14/37 on immutable main; native observations were already 37/37.
The later six-case option corpus captured three concrete callback hazards and
three primitive controls before the constructor guard was extended.

The broader Python cohort is **not aggregate green**: 580 methods collected,
570 passed, eight skipped, and two failed. Both unchanged failures reproduce
on immutable `b577b7e`: the recursive-global `None` summary assertion and stdlib
`argparse` generator-expression completeness. An initial staged CLI checksum
failure disappeared in the isolated checkout with canonically refreshed pins;
no integrity bypass or changed test expectation was used.

| DSR check | Log SHA256 |
| --- | --- |
| Resumed frozen maintained baseline | `12635a091ae4f4e5669b9d01c059bdd1beb0fc44ff4dfff3890de3e7a08c13e7` |
| Final HTTP cohort, 97 passed / nine opt-in skips | `883e34b3f43aed5c8156f8193c2e0fcd2f11134266ec120abc4f4c1d53e350f2` |
| Independent 37 native/scanner cases | `47b20e3ff41626956592ffc624a4909d52252bf514d84e8b1c219bed1be7cd34` |
| Independent six option native/scanner cases | `5e41e3b60616b9fd9d43fff2abdea53bf9d2d6467493ca61006603ce2cd4f709` |
| Final 35 public calls | `eea1fc349bcd21dad6d37aabb2e71341b62d1a48f21167c33fb5d95332d83572` |
| Broader cohort, two retained failures | `918f36502f7dbd6137462169aa1dcd005dba22f68bff04578f17aa135d81df17` |
| Exact two failures on immutable baseline | `eb2e1c868c43d31c49d39c74c352e17221576b3440c882676b6afc38579d198c` |
| Final integrated HTTP/SQL and integrity qualification | `ce2c584312fe3907d57190db1fea4c80de6502abe56ac93157eaa057b29fabca` |

The final 5.5.98 integration preserves both SQL additions and passes canonical
integrity, shell syntax and whitespace checks. Its combined HTTP/SQL invocation
collected 346 methods: 340 passed and six unrelated public opt-ins were skipped.
This includes re-executing all 35 new HTTPX public calls and eight schema-default
public calls on the actual integrated tree.

Source SHA256:
`0c85924a88114bc8397ee6e5cb71ccf93c40a1612783272be8947ff7b8ce98a4`
(Git blob `a735206dc3733e862f6b9b7e3ef3533431f71fa4`).
Maintained test SHA256:
`a65b19edccb9e0254d425cca4ca7bec868812a38cf1ee0f9d70352da3d5fd6d9`
(Git blob `ffdf9f615ef3ffa8fcda51f650c86a78b8addd6a`).
Independent corpus SHA256 values:
`0fca07246952982641eb24842ede4dc728fa5c08d5193d17509a2930b6eae889`
and `45cae57bb76a8ee15a63d5daafcad0cf9ca19c1ceed69b49becb77084b2b1086`.
Receipts live under `test-suite/artifacts/httpx-prepared-resumed-20261121/`,
`httpx-prepared-public-20261121/` and `independent-semantic-resume-20261121/`
in the respective retained checkouts. Runtime: CPython 3.12.14, HTTPX 0.28.1.
The pooled-HTTP and broader dataflow umbrellas remain open; no full-suite or
release qualification is claimed.

## November 15 continuation on a603d20

This remains an **unfinished, unactivated implementation**. The current
`python-pooled-http-candidate.patch` targets
`a603d20fbb11508c03f916e83e566d106678ee92` and replaces the earlier archived
patch. Production source, automatic discovery tests, version and checksum pins
remain unchanged.

The executor disconnected after two source edits and the maintained test edit
succeeded, before constructor/method dispatch could be completed or the candidate
could be run. The partial source contains calls to `http_call` and
`consume_http` but neither method is defined. **Do not activate this patch as a
working scanner.** It preserves the precise interruption point.

### Preserved implementation and tests

- Finite native Requests/HTTPX constructor, client and pending-request markers,
  with actual import qualifiers and separate receiver facts.
- Explicit client/API mutation and container/opaque-escape boundaries.
- Initial context-entry and call-dispatch integration hooks; their transfer
  methods and deferred-consumption paths remain unfinished.
- The unchanged original 11-method pooled-client oracle, plus five additional
  methods for pending aliases/exact sink locations, captured clients, deferred
  base mutation, harmless options, and unsupported extensions.
- Existing HTTP test temporary directories use the shared retention helper.
- The separate 24-case exact/boundary oracle is preserved in
  `python-http-client-exact.py`. Its fixture labels and sources were fixed
  before implementation; it supplements the original 34-case adversarial oracle.

### Observed evidence before disconnection

The unchanged baseline analyzer SHA-256 was
`432418f82a864109b16d8ee04a4452ce4a1b541ba8f9a089255e833ad8c366e7`.
Runs used CPython 3.12.14. HTTPX 0.28.1 was available; Requests was absent.

| Check | Observed result |
| --- | --- |
| Original independent 34-case source oracle | 14 passed, 20 failed; all failures were complete-empty results |
| Additional 24-case exact/boundary oracle | 7 passed, 17 failed: 12 precise unsafe-flow misses and five missing incomplete-analysis boundaries |
| Frozen HTTPX native behavior witness | Seven of seven assertions passed, without network I/O |
| DSR maintained HTTP suite | Started; completion was not observed |
| Partial candidate / public module and runner checks | Not executed |

The original 34-case oracle permits explicit incomplete analysis for its unsafe
cases. Therefore a future 34/34 result must still report precise detections and
incomplete boundaries separately. The extra oracle has 19 exact source cases
and five explicit boundaries; its unsafe cases require the stated exact sites.

Observed receipt locations in the unavailable workspace:

- `test-suite/artifacts/pooled-http-baseline-review-io8ws6ml/result.json`:
  exit 1, 0.315 seconds; fixtures `independent-http-adversarial-4m8tno6c`.
- `test-suite/artifacts/pooled-http-independent-extra-phdn39g6/result.json`:
  exit 1, 0.243 seconds.
- `test-suite/artifacts/pooled-http-native-review-sx2_xh5g/result.json`:
  exit 0, 0.166 seconds. The existing native witness script SHA-256 was
  `bf73d4c80ea40af5972cb99a95c7b1abd14fd3fc7897e134c356181a1187f56e`.
- `test-suite/artifacts/dsr-pooled-http-maintained-baseline-zv9TMuwA`:
  no completed result was observed.

These summaries were returned by tools before disconnection. Full logs were not
recovered; the identifiers above are not links to currently available receipts.

### Reconstructed checkpoint identity

After the outage, the exact successful manual edits were reconstructed from
immutable GitHub base files and recorded patch inputs. Two independent reviews
replayed all eight source hunks and six test hunks forward and backward exactly.
GitHub readback matched the patch. This verifies recovery, not Python execution;
no post-edit live-checkout hashes had been captured.

| Artifact | SHA-256 |
| --- | --- |
| Combined candidate patch | `d8ac4cf5e969621f9bc8225fe60acc4a785cf69d409f37309d2d5f7e7f825f22` |
| Partial analyzer after applying patch | `4cbb77601a24669afa1744d30dc49df0a6f4825bf390f2672ceee8be605df92c` |
| Maintained tests after applying patch | `2a71c368021a31969e7c31597884803f815c1045975c6a9104bb0711a13dd80e` |
| Additional exact/boundary oracle | `bb74a751a36c0e2541cba5558bf4db73dc4226f6e05af2efb0a61fa3d82516ee` |

### Required continuation

1. Resume from the current candidate on its stated base; do not overlay the
   historical preliminary patch.
2. Implement native constructor/method dispatch, correct URL argument binding,
   destination transfer and context-manager identity through helper summaries.
3. Implement await/scheduling and sync/async stream entry. Unused handles must
   remain clean. Keep request call-site locations and independent argument effects.
4. Treat base URLs as live client state. Until mutations are supported, retain
   explicit incomplete boundaries rather than freezing a stale base. Absolute
   HTTPX destinations require both scheme and host; `//host/path` remains relative.
5. Keep summary facts outside finite context keys. Resolve helper-factory frame
   effects and captured authority; custom auth/transport/hooks and prepared
   requests must not silently borrow native contracts.
6. Re-run both unchanged independent corpora and the maintained oracle, with
   precise findings distinguished from incomplete analysis. Run native Requests
   and HTTPX witnesses, the broader Python suites, real module/runner JSON/SARIF,
   selection/suppression/cache checks and canonical integrity/release gates.
7. Keep `ultimate_bug_scanner-python-pooled-http` and D6 open until the original
   acceptance criteria are met. No candidate-pass, full-suite or release claim is
   established by this checkpoint.

---

## Historical preliminary checkpoint

The following records the earlier interrupted attempt. Its patch description and
candidate hashes are superseded by the current section above.


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
