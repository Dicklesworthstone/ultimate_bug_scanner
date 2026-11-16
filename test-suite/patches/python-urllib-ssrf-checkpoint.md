# Python urllib SSRF source-regression checkpoint

## Status

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
