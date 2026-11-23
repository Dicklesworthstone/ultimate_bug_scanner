# Go native read-into recovery checkpoint

**Status: incomplete and unactivated. Do not apply this patch to production without completing the implementation and validation.**

Base commit: `d6c529ee94ae565ed6b66724d558b2de98d400d2`.

The accompanying patch reconstructs exactly the three manual edits applied before the execution environment became unavailable on 2026-11-23 UTC. Immutable base files were fetched through GitHub after the disconnect, all 25 manual hunks matched in order, and the resulting unified diff was replayed forward and backward in memory with exact content equality. This verifies recovery of recorded edits; it is not a Python syntax check, test run, or comparison with inaccessible post-edit disk bytes.

Base source blob: `ceb92e859c13b940408804aed7682de329fb2cbb`.
Base regression-test blob: `6ac3b39223cf6c56c78391205a991b87f21593b1`.

## Reproduced defect and intended behavior

On the base analyzer, `buffer := make([]byte, 128); io.ReadFull(r.Body, buffer); db.Query(string(buffer))` returns no findings and no incomplete-analysis error. Native `io.ReadFull` and `io.ReadAtLeast` must carry known Reader contents through byte-slice destination writes, while byte counts and native reader errors remain separate from payloads. Slice aliases share backing contents; string snapshots and independent allocations do not. Short reads can leave a mutated prefix, so a later read from a fixed stream must not erase earlier provenance.

Official semantic reference: https://go.dev/src/io/io.go, ReadAtLeast lines 329–344 and ReadFull lines 353–355. ReadAtLeast with min <= 0 or min > len(buffer) does not invoke the Reader; ReadFull delegates with min = len(buffer). Thus a provably zero-length/no-read operation can complete even with an otherwise unknown Reader protocol.

## Observed baseline evidence

Nine newly added source regression methods ran through the real DSR `_qg_run_single_check` execution path on the unchanged production analyzer:

- Result: **9 methods; 12 failing assertions; 1 error**. These are expected-red defect witnesses, not a passing feature.
- Retained receipt directory: `test-suite/artifacts/session-go-readinto-baseline-picMLvz2/`.
- Observed log SHA-256: `f23d9d734eb3212892f8ce96b821bb2caa21ab64a83dab30b5846717ae9778f6`.
- Command: `cd test-suite/quality && PYTHONPATH=../../modules/helpers python -m unittest`, followed by the nine `NativeScanningFlowTests.test_readinto_*` source methods added in the patch, excluding the opt-in native compiler witness.
- The opt-in `UBS_GO_READINTO_NATIVE=1` real Go witness was authored but **not executed**.

A separately authored root-agent probe is preserved as `test-suite/patches/go-read-into-independent.py`, blob `5c493a97abcef905d4d274e7d40358433652b4ae`. Its independently reported baseline is 18 cases: 10 exact, 1 incomplete, 7 incorrect-complete. Receipt: `test-suite/artifacts/session-independent-go-baseline-ZkFvcMBR/`; observed log SHA-256: `7ac1fd7e2c99abc572bb1d720455498b3667651a683afae5dc82665553af1fb6`. Preserve those labels and assertions on replay.

## What the partial patch contains

- Nine source regression methods plus one opt-in native Go witness in the existing decoding test suite.
- io operation identities and a bounded byte-buffer capability scaffold in the existing Go value domain.
- Buffer metadata joins, initial escape/write fields, literal/buffer-expression recognition, and partial integration into metadata lookup.

**The read-into transfer does not exist yet. The patch is not a functional fix. No candidate test or syntax run was completed.**

## Required continuation

1. Complete native ReadFull/ReadAtLeast dispatch and destination weak writes. Keep no-read bounds, payload/result separation, and exact file-local import/callable authority.
2. Finish buffer backing-cell initialization, assignment/rebinding, slice/alias reads, nil declarations, and generic/callback escape handling. Avoid false clean results for unknown/custom readers, escaped buffers, live backing readers, mutable globals, or delayed writes.
3. Integrate buffer capabilities into selected-helper contexts, parameter writes, result transport, immediate closures, and summary joins. Treat unsupported escaping local allocations explicitly. Keep finite work/context bounds unchanged.
4. Fix two known scaffold concerns before testing: `value_info` currently handles the bare identifier `nil` before reaching the new nil buffer recognition; byte-literal length calculation currently looks at masked rune contents and can mistake a nonempty literal for zero length. No runtime evidence validates either path.
5. Replay all unchanged new source regressions and the independent probe, then enable the real Go witness. Run the related Go decoding, domains, packages, and initializer cohorts. Add real module/meta-runner JSON/SARIF coverage with exact sites, totals, selection/suppression, cache invalidation, and prior-finding retention on incomplete results.
6. After a complete validated implementation, regenerate canonical checksum pins and follow the repository's version/release rules. Run prescribed broad checks through DSR. Do not weaken detectors, budgets, partial-result policy, test assertions, or release gates.

Only checkpoint artifacts should be activated while this work remains incomplete. Production analyzer, test discovery, checksum pins, version mirrors, and broad bead status must not be changed by applying this partial candidate.
