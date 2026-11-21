# Python SQL nested-generator checkpoint

**Status: active, bounded production support, qualified during the 2026-11-20 session.** The SQL detector and companion Python taint analyzer now complete the supported direct nested-generator cases. Existing incomplete boundaries and the broader self-scan failure described below remain explicit.

## Implemented behavior

The SQL detector streams each inner-generator yield into its consumer before the next producer step. It preserves interleaved SQL stores and sinks, captured query values, early stopping, exhaustion and consumer exception state. Captured producer cursors now count as observable effects when selecting the `any()`/`all()` model; the original checkpoint's dispatch blocker is resolved.

Public qualification exposed a separate taint-analyzer refusal. Its companion change removes only private, direct identity-forwarding frames of the form `(item for item in INNER_GENERATOR)`, under the existing proven native-consumer path. The existing transfer evaluates the selected producer with the same stopping policy and lifetime checks. This supports common nested list/tuple/join and boolean-consumer forms without adding an eager drainer or a general resumable-cursor model. Original AST parent mappings and consumer-authority checks remain intact.

Three existing completion tests now use asynchronous generator consumption as their real unsupported fixture. They retain their original assertions for diagnostic identity, text/JSON parity, partial acceptance, infrastructure-failure precedence and preserved independent findings.

Exact qualified helper identities:

| Helper | SHA256 | Git blob |
| --- | --- | --- |
| `py_detectors/sql_injection.py` | `f41f12d0d739d96ee0ecd5a0163fc3a732973c9e7e92c0ad6bed388c8022965f` | `feaa305f40ced4ce8126c25878c6b4c62d0a39b3` |
| `analyzers/taint_py.py` | `abbb391f94c9a38957a7d2d525fd8732748143232ec0b64b5171d9f845f73e9e` | `1555d7addbd7c2000ba73bde5292960aaa3cd376` |

## Observed DSR qualification

All checks used the unchanged native quality executor from DSR commit `5f06876`. Receipts record each command, exit status, timeout and log hash; these are individual checks, not an aggregate release receipt. Per-invocation test deadlines and expected outcomes were retained.

| Check | Observed result |
| --- | --- |
| Three new SQL source methods | All 26 cases passed: seven scalar cases, eleven real SQLite witnesses and eight explicit refusal controls. The incumbent failed the eighteen complete cases. |
| Independent SQL oracle | 17/17 native SQLite/scanner cases passed, versus 3/17 on the immutable incumbent; six additional exception/finally witnesses also passed. |
| Immediate-generator taint regressions | All 30 methods passed, including 26 existing methods and four new methods. |
| Independent taint oracle | 12/12 native Python/scanner cases passed, versus 3/12 on the incumbent: nine complete cases and three preserved boundaries. |
| Public nested-generator matrix | All 16 invocations passed: four clean/unsafe/bound-query fixtures through module and runner, each in JSON and SARIF. Complete status, exits and exact SQL findings were unchanged assertions. |
| Completion compatibility | All three methods passed: worker transport, eight runner text/JSON partial-policy invocations and three module text/JSON/SARIF mixed-failure invocations. |
| Canonical integrity regeneration | Both canonical checksum scripts completed successfully before the public checks. |

The combined Python integration checkout also passed canonical checksums, release `SHA256SUMS`, runner syntax and whitespace through DSR in 24,170 ms (log SHA256 `c3eea48de2ce54116bfe7c1f4d5e6a0540ed7ad7c5f7fe9f43f9cb398c8d6f32`). Its four SQL, JavaScript and Python helper hashes match the independently reviewed frozen sources.

Retained primary logs under `test-suite/artifacts/python-nested-20261120/`:

- `candidate-1.log`: `00daed08cb3ab6a64d1accc6ec55db318f0f84c9c9f41e5c6aa0ea4d4d959220`.
- `taint-immediate-full.log`: `cb67061bd900a4f77b3437cc3a194105ef5eb4bb067d1367190f2ff5cecd8f1f`.
- `public-nested-2.log`: `e7dd49e65f10eda5cbb45a8b7a0afcc492d5e07dd427ca6f2f4c366b45fee8b8`.
- `completion-2.log`: `a743714ec970271212b527338e9c322677798ac274437931f98a3821de5d2a6d`.

## Broader source cohort and remaining failure

The 185-method SQL value-capture/sink-argument cohort completed with 183 passing methods, one native SQLite subprocess timeout and one existing semantic refusal. Its aggregate receipt is **failed**, not green (`source-cohort-3.log`, SHA256 `535c1911ebd85dad29deb30f3fdfe520401d7890c2b6838c572702c0323652b2`). Two earlier aggregate attempts timed out and are not counted as passes.

The exact timed-out method, `test_generator_reducer_fresh_list_record_provenance`, passed all 21 cases on rerun with its original 30-second child deadline (`native-timeout-rerun.log`, SHA256 `8ed0932c34b80f74848c6ae548be3ed2c1ffec70d77bf03149d2247a8b3f35c5`). This yields observed passing results for 184 of the 185 methods across the retained runs, without rewriting the failed aggregate result.

`test_core_tests_literal_sql_fits_the_original_budget` still raises `SQL generator reducer binding is unresolved; analysis is incomplete`. The immutable incumbent helper, SHA256 `92d50483da6428e3d83a58456a8cecf48c33688552bd3ea2e7d7e3aa8c26bf3e`, reproduces the same failure against the unchanged test (`baseline-core-budget.log`, SHA256 `87b31ef3141aa69dba0f7ac3e7135ad1ec0bdc62b6cc43dcbbe00d261d83fbe4`). Neither its expected result nor analyzer budget was weakened.

## Explicit bounds and historical provenance

SQL frames with overlapping comprehension locals, unproved callback writes, uncertain namespaces, finalizer protocols and unsupported partially resumed cursors remain incomplete. The companion taint path still refuses unproved iterators/lifetimes, non-forwarding or filtered outer frames, saved aliases and unresolved helper-frame lifetimes. The independent oracles preserve these boundaries alongside the newly complete cases.

The original 2026-11-15 unactivated proposal remains in `test-suite/patches/python-nested-generators-streaming.patch` (blob `d476b02beb79b19f84ade4837a767289759bb530`) and `test-suite/patches/python-nested-generators-completion.apply-patch`. Its base was `f1c06ea3f80497432a29581871b3719ad8462f9d`, detector blob `885e99149e2dd67313095221f0a6e01e886a5c22` and test blob `16d85079e9c74e415aae9c0a10844f4d0d6e4173`. These archives record the proposal; the active source also includes the dispatch and companion-analyzer fixes above. Bytes joins and simple captured-list closures were already supported and are not claimed as new work.

The D6 and release-self-scan beads remain open. These bounded feature checks do not establish repository-wide or release qualification.
