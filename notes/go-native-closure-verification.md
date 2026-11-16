# Go closure parameter transfer: qualification and exact recovery

## Scope and status

Base: `f1c06ea3f80497432a29581871b3719ad8462f9d`.

Current main already contained the native Go environment/import implementation; the older checkpoint was stale. This change fixes a distinct remaining gap: invoked function-literal parameters retained only environment getter metadata, losing the existing native HTML escaper, JSON/XML decoder, reader and pointer contracts.

The production change passes the existing `_ValueInfo` metadata into closure parameter cells. Actual function arguments remain value snapshots for immediate calls, `defer` and `go`; captured outer cells keep their separate delayed-execution uncertainty. Native handles do not become request contents. Nine source regression methods cover unsafe decoded payloads, clean error results, actual sanitizer identity, SQL/command domain preservation, unknown alternatives, pointer/decoder receivers, argument effects and callback snapshots.

This is bounded closure-parameter support. General closure result-tuple transport and post-call captured heap effects remain outside this change. The broader Go/D6 beads remain open. No native compiler, public scanner, full-suite, release or tag pass is claimed.

## Observed execution

Checks used DSR's unchanged `src/quality_gates.sh::_qg_run_single_check` executor, Python 3.12.14, retained fixtures and the repository's inherited libseccomp deletion fence. DSR single-check receipts below are not a passing, source-bound aggregate receipt.

| Check | Observed result |
| --- | --- |
| New nine-method source oracle on the incumbent | 20 failing assertions/subcases; native unittest duration 0.216 s; DSR 834 ms |
| First candidate focused cohort | 73 discovered, 72 passed, one existing native opt-in skip; native 6.739 s; DSR 10,050 ms |
| First four-suite attempt | Timeout exit 124 at unchanged 120 s limit; DSR observed 144,871 ms; 157 PASS markers and no failure marker before termination |
| Final-source four-suite retry | Timeout exit 124 at unchanged 120 s limit; DSR observed 123,072 ms; 257 PASS markers and one FAIL marker before termination |
| Preserved independent environment corpus on final source | 23/23 exact cases passed; DSR 9,945 ms, limit 60 s |
| Initializers/packages follow-up | Start observed, completion not recovered |
| Final Go-only cache/focused rerun | Not started: writing its temporary harness failed when the executor became unavailable |

### Qualification timing

The successful 72-test focused run preceded the final refinement that adds decoder metadata only when `info.decoder is not None`. The refinement avoids introducing an empty decoder state at joins. It also preceded addition of the optional compiled witness.

All nine newly added source methods were observed passing in the final-source retry. That retry nevertheless failed the existing `HigherOrderContextLimitTests.test_exhausted_context_budget_is_partial_and_never_cached_as_complete` method (FAIL marker duration 9.052 s), then timed out later in `InitializerCacheTests`. There was no completed cohort denominator or final unittest traceback.

During that retry, a separate root-owned scratch-retention candidate temporarily made `go_scan` refuse category 17 unconditionally in retention mode. The existing context/cache test calls the static driver directly and expects repaired complete scans to become cache hits. That temporary refusal is a plausible cause of the observed failure, not a proven traceback diagnosis. Root subsequently separated the shell bridge refusal behind a private flag, but the corrected Go-only recheck was not executed. The source/test blobs listed below contain none of those separate runner/module/driver retention changes.

The final independent 23-case pass occurred after the decoder-metadata refinement. The Go-only follow-up was intended to load immutable-base `go_scan.py` and rerun the failing cache method plus the focused cohort. Its artifact write returned an explicit failure after 52 seconds; the sequential DSR command never started.

The optional new native witness asserts real rendered bytes and captured query values before exact analyzer IDs, lines and columns. It uses only the Go standard library, offline module/toolchain settings, `go build -work` and the deletion fence. It was authored but never compiled or executed. The executable named `go` on the original PATH was a board game; a genuine compiler was not available before the environment loss.

## Receipt and log identities

The following SHA-256 values were returned by observed DSR receipts. Full log bytes were not recovered after the executor became unavailable; these are recorded log identities, not new readback verification of those logs.

- Baseline: `baseline.log`, SHA-256 `8faff21825944c1ebb47a356905643e1c5832e2a35bb970302dfc27ecbfa2a1a`.
- Focused candidate: `candidate.log`, SHA-256 `27d493f402f4d9ff0ca38f9255f526f1724a6c2a5ab2a7ba02c374e253025a79`.
- First broad attempt: `cohort.log`, SHA-256 `604030fb7fbbe754f01d1df6433d3b35666cec977385b930953ed22da0a7fb20`.
- Final-source broad retry: `cohort-retry.log`, SHA-256 `7f34476dad4dcaf4debaecdbef794f75ee3d84101c54b07937f8d0f5d0f7a9cf`.
- Final independent corpus: `environment-independent.log`, SHA-256 `aa7c107c8048dae72cacf8ba09b3ee740488784045917f074db946f6a10eb842`.

Original artifact prefix: `test-suite/artifacts/go-native-closure/`. No passing result is inferred from a log path.

## Exact recovered files

All three final file SHA-256 values were recorded from the live filesystem before the outage. Recovery applied only the known manual edit hunks to the immutable base files. Every reconstructed digest matched its recorded live-file digest. Every uploaded blob was fetched back and compared byte-for-byte, and reverse hunk replay recovered the immutable base exactly.

| File | GitHub blob SHA | SHA-256 |
| --- | --- | --- |
| `modules/helpers/ubs_core/analyzers/taint_go.py` | `8078b38f1d23c0c9f44bfa6f83992db493fbc829` | `ba995c7c1a65d826e7e9bcd8a3bace07d568a4c86e2a66452a4ab2fe9e909052` |
| `test-suite/quality/test_taint_go_domains.py` | `3bb52a375899a05571a05fbe273f0a03ac899950` | `2e156d47bd7091ca8d838ccdf1a47bf76820a3a4c4a3cf91b230ce4d2450ef22` |
| `test-suite/quality/test_taint_go_decoding.py` | `b2ab63cc6f4ee1ea52325ea5e03ef1686c0afad2` | `ab2f206863eee5c16e5d61e5c36a810624df80205baca188a24f59300e8f4fde` |

No source changes beyond those frozen files, commit, ref update, bead closure or release action were made by the Go subagent. Integration and canonical integrity pins remain root-owned.
