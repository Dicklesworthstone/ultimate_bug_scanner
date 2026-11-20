# Python urllib SSRF source-regression checkpoint

## Active implementation and qualification — November 20, 2026

The preserved regression cases now accompany an active implementation of native
`urllib.request` destination tracking. Actual imported `urlopen`, `urlretrieve`,
`Request` and default `build_opener` identities carry URL provenance through
aliases, selected helpers, closures, `full_url`, saved `get_full_url` and saved
opener methods. Constructing a Request is not itself a network sink, and its
handle, body and headers do not become the selected destination. Fixed URLs,
strong replacement and domain-specific guards retain their clean behavior.

Mutation, custom handlers/proxies, callback options, opaque escapes, reflection,
custom URL coercion and Request subclasses remain explicit incomplete-analysis
boundaries. Independent review reproduced four previously complete-clean
protocol cases; these now report incomplete coverage. Request and opener objects
do not acquire context-manager authority.

The implementation was merged with the concurrent stdin-buffer change on main;
that upstream dataflow support remains intact. Final analyzer SHA-256:
`6ec01af84496010e9c4b30260e1d4472178c52023445419e7ac02f40bda495f3`.
HTTP regression file SHA-256:
`e52f82fafca8701a3a4b82532ee619489be1420a790baad0f0866a1e1fb9d4e2`.

Observed DSR checks, using retained fixtures and the inherited deletion fence:

- The merged HTTP/dataflow/callable cohort passed 261 methods with six opt-in
  skips (267 collected), including the upstream stdin buffer tests. Log SHA-256:
  `b5603cfb0b8faa0e78c668706de8fb54f9d96d2f15511d950da3701b6f4e44df`.
- All 28 actual module/runner JSON/SARIF calls passed exact rule, location,
  severity-total, status and exit assertions for direct URLs, Request aliases,
  saved openers, clean metadata, suppression and partial scans with retained
  findings. Log SHA-256:
  `6942ebb4f4600ac3c963a48b1e9ac49b80d355cf9670825140b5d1d1227c50fe`.
- The standard-library no-network witness passed. It uses real urllib request
  objects and an in-process handler; it does not contact external destinations.

The first completed public matrix exposed two new harness adapter errors:
omitted existing timeout warnings and an incorrect assumption that runner JSON
used the module's grouped finding shape. Both were corrected while preserving
all fixture sources, SSRF expectations, sink sites, exits and status assertions.
The final matrix explicitly checks each ancillary timeout rule/site and both
documented JSON shapes. The unsuccessful initial log remains retained:
`47abb26456c61210041af79dfdf1c1386c5cb93ac841736eb8a354bff8f02911`.

This is bounded urllib support. aiohttp, generalized callback/transport behavior
and full repository/release qualification remain open.

Final integration preserves main's subsequent shared findings-ledger/Rust fix
at `796afcda299cd02a434879d4d2507a1eb6d07357` and uses development version 5.5.87.
All 89 public CLI cases pass again on that combined tree, with the original
assertions and per-call limits unchanged:

| Matrix | Actual calls | DSR log SHA-256 |
| --- | ---: | --- |
| JavaScript sort, suppression and cache | 25 | `20d18c28f68b22e96abb4572d821b604c328197179baedd23aace3e55b7cae15` |
| Go closure results | 24 | `717f51ec4dc53a2c9bc54ffb10ebc3238515408100ae099d0a8973968decdaf8` |
| Go retained-scratch reports | 12 | `24163b692b1f377457ea982c900efe1b87ea2dc7e31051588dbd70f83aedc373` |
| Python urllib destinations | 28 | `db5e6df14e8cb6b6eb2935e4609e3e0e8cd0b546a608d10a12e493bfbb65be99` |

Final canonical checksums, SHA256SUMS, shell syntax and diff whitespace checks
pass. The full ShellCheck command was killed with exit 137. The repository suite
passed checksums and all 12 rule inventories, then reported missing Swift fixture
pairs and exceeded its 120-second DSR envelope during quality discovery. The
manifest, Swift fixtures and rule-quality harness are unchanged from the session
baseline; later error/failure markers have no completed traceback summary.
Repository-suite log SHA-256:
`ae2462214a7a43441dfb94d43f55fb3ecb82baf4fa88448b6ff221bccf58e51c`.

The Python helper's UBS selfscan is partial (exit 2): zero critical findings,
56 warnings, and explicit generator/live-cell/step-budget limits. Review maps
52 warnings to unchanged lines. Four diagnostics concern two new exact-string
checks for header keys; accepting string subclasses would weaken the modeled
protocol boundary, so those checks are intentionally retained. No clean
selfscan or full-suite pass is claimed. Selfscan log SHA-256:
`627b45fa6d3a217fcec6f29e82c4e16e73df677875dc617bd42b5de469c9f297`.

The following sections preserve the earlier inactive checkpoint and are
superseded by this status.

## Historical status

This preserves executed failing source regressions and unfinished implementation
work. The execution environment became unavailable before the urllib transfer
functions were implemented or tested. No production activation or completion
claim is made.

Starting revision: f1c06ea3f80497432a29581871b3719ad8462f9d.

The existing Requests/HTTPX pooled-client implementation was already active
despite its older unfinished checkpoint. Its frozen adversarial oracle passed
34/34 contracts and the exact/boundary oracle passed 24/24 contracts on the
actual production helper. The first exact-oracle invocation failed before
scanning because test-suite/artifacts did not exist; the rerun succeeded after
creating that parent. These are direct helper checks, not public CLI/full-suite
qualification. The adversarial oracle allows explicit incomplete analysis for
unsafe cases; 34/34 does not mean 34 precise detections.

The successful exact rerun reported CPython 3.12.14, 0.740832 seconds and unchanged
analyzer SHA-256 bedc80134454de1d28fe77fc547bd52e6cdd3fe53dc77dc03b81f97e1664b073.

## Reproduced source gaps

The real taint_py.run returned complete, empty findings for both programs:

~~~python
import urllib.request
urllib.request.urlopen(input())
~~~

~~~python
from urllib.request import Request, urlopen
request = Request(input())
urlopen(request)
~~~

Fixtures were analyzed, never executed. Additional complete-empty residuals were
observed for an awaited aiohttp.ClientSession request and a Requests response
hook that writes a URL later consumed by a session. Those remain outside this
urllib slice. An unused module-level httpx.stream call was reported as a sink;
HTTPX's contextmanager source defers sending until entry, but no native witness
for that correction completed in this session.

## Frozen test patch and recovery identity

Confirmed local edits add a retention-helper import and twelve
UrllibDestinationTests methods to the existing HTTP suite, preserving all old
assertions. They cover native imports and saved callees, URL argument slots,
Request construction/aliases/readers, helper and closure transport, default
openers, safe URL guards, domain-specific sanitizers, fixed destinations,
metadata/body clean controls, mutation/escape/custom-handler boundaries,
argument effects, exact sites and a native no-network witness.

| Object | Git blob SHA |
| --- | --- |
| Original test_taint_python_http.py | 462e0c6b3985b2cd63e6bfaab0e5dabe8fbcddb3 |
| Reconstructed test file, 906 lines | 65a6ab63adc49e63b5d24fa697dff0c2122da3be |
| Original recovered test patch, two hunks, 261 lines | 6d3649d78198668219309ecc778ec50f13fcc965 |
| Source-reviewed native-adapter test file | 86886a679c7f9275451b0069f41445c7ee706616 |
| Source-reviewed native-adapter patch to resume | e1446c598fbe0b7416e80cebb099797c95bc0ef3 |
| Original production taint_py.py | cc81824ccd9b96aa6aad144cf806fc8c5684bccd |

Recovery used the immutable base and exact successful manual edits recorded by
tools. Forward/reverse patch replay matched in code mode; GitHub blob readback
matched both complete contents. This verifies recovery, not an observed local
post-edit hash or Python execution after the outage.

Keep the regression patch outside automatic discovery until implementation and
qualification succeed.

## Observed DSR baseline and native limitation

The twelve-method pre-implementation run used DSR's native quality executor and
the retained-fixture/seccomp harness:

- Native exit 1; 12 methods; 31 failing source assertions/subcases and one native
  witness adapter error.
- Unittest elapsed 37.057 seconds; DSR envelope 67,891 ms; timeout 120 seconds.
- Observed log: test-suite/artifacts/session-20261116/urllib-baseline.log.
- Observed log SHA-256:
  24142abb5f6f2bccbca7bd000f44b4c1ecadd6423c05770d3b551d81997a9d2c.

Failures include missing destination findings, missing explicit incomplete
boundaries, and false taint from a Request's inert string representation. They
are not a whole-corpus recall estimate.

The native witness uses a real urllib BaseHandler and in-process responses,
without sockets. Its first run stopped because the synthetic HTTP response
lacked the msg field expected by HTTPErrorProcessor. The confirmed test-only
fix sets response.msg = 'OK', with every assertion unchanged. The corrected
native-only DSR rerun was submitted, but no completion was observed before the
environment failed. The recovered patch includes this fix; no passing native witness is
claimed. Subsequent primary-source review found one further adapter error:
urllib capitalizes stored header keys, but get_header performs a case-sensitive
lookup. The patch to resume changes only get_header('X-User') to
get_header('X-user'), leaving the request, expected metadata and every assertion
unchanged. That second correction was authored after the outage, never applied
or executed locally; the original recovered file/patch remain separately
identified above. Both corrected blobs were read back exactly from GitHub.
See [CPython Request implementation](https://github.com/python/cpython/blob/main/Lib/urllib/request.py).
Full baseline log bytes and the pending native receipt were not
recovered; the path/digest identify output observed before the outage.

## Remaining implementation and qualification

Only an initial registry/marker edit was submitted before the service stalled
(URL positions, default-opener kind, protected members, finite _UrllibRequest).
That apply call never returned; its execution status is unknown. No working
urllib candidate was completed.

Resume from current production plus the frozen tests:

1. Run the corrected native witness and unchanged source baseline through DSR.
2. Carry Request URL facts in existing receiver/summary slots, keeping the
   handle, body, headers and other metadata distinct from the URL.
3. Implement actual urlopen/urlretrieve identity and URL slots; default
   build_opener().open uses the parameter fullurl, not url.
4. Preserve aliases, helper returns, closures, exact sink sites and independent
   argument effects. A bound get_full_url method is not itself a Request.
5. Keep member/API mutation, custom handlers, proxy changes, opaque storage,
   reflection and callback options explicit unless modeled. urlretrieve's
   reporthook executes user code and cannot be treated as inert metadata.
6. Do not grant context-manager authority to Request or default opener objects
   when extending pooled-client contract helpers.
7. Complete broader source regressions, real module/runner JSON/SARIF,
   selection/suppression/cache checks and canonical integrity/repository gates
   before activation or completion.

Primary references: [Python 3.14 urllib.request documentation](https://docs.python.org/3.14/library/urllib.request.html)
and the installed CPython 3.12.14 urllib.request source, read for Request setters,
OpenerDirector.open, urlopen and urlretrieve.

No old assertion, timeout, detector threshold or public rule ID was weakened.
No full-suite, platform, release or bead-closure claim is made.
