# Go native read-into-buffer candidate checkpoint

Date: 2026-11-23
Bead: `ultimate_bug_scanner-1b9j.6.18`
Base commit: `b27c0dcc126a4181ca0766a69ed91cffb9ed305e`
Candidate patch blob: `636a11e95ac737b93cdf5c13d5090708bd5d215e`

## Status

**Unexecuted, unvalidated recovery candidate. Do not activate or close the bead from this checkpoint.**

The candidate patch updates `modules/helpers/ubs_core/analyzers/taint_go.py` and `test-suite/quality/test_taint_go_decoding.py`. It contains the four manual source patches that successfully applied before the executor failed, the ten unchanged checkpoint regression methods, the subsequently drafted summary integration, two review fixes, and nine additional source/cache/public-report regression methods. The final combination has not been applied or executed in the recovered executor.

The 45 unified hunks were checked against the two immutable base file strings in memory and reconstruct the intended candidate strings exactly. That is a patch reconstruction check, not a syntax check, DSR receipt, disk-byte comparison, runtime test, or native Go validation.

## Recovery provenance

- Successfully applied patch-state reconstruction: GitHub blob `4bb8637c6f57bfc07fd4abb749148ab08671c3f1`. It preserves the four successful manual patch texts, resulting reconstructed file contents, base blob references, and the fresh baseline evidence. The recovered bytes were checked by forward/reverse patch reconstruction; the lost executor could not provide a final disk-byte comparison.
- Pending summary integration origin: GitHub blob `d4a93003da5f79b3dbd36a1897b2d1c0783e6d7f`. The original tool attempt failed before reading the file. Its changes are now included in this combined candidate.
- Source base blob: `f8deebfd78029c5d77f6574f4403691877e34c44`.
- Test base blob: `a4020ab4c7cee6b2604d422ef74bc1f66b281ee3`.

## Intended behavior awaiting validation

Bounded native `io.ReadFull`, `io.ReadAtLeast`, and supported native `Read` methods write source provenance into proven byte-slice backing cells. Aliases and supported reslices share backing contents; count/error values and `len`/`cap` stay clean. Short reads weakly join prior contents. Known zero length, nonpositive minimum, and impossible minimum bounds avoid reads before Reader protocol validation. Selected helper summaries carry buffer writes and escapes separately from slice-variable rebinding.

Unknown Reader protocols, unknown destination capabilities, escaped backing storage, delayed writes, captured buffer-header replacement, and returned helper-local allocations remain explicit unsupported boundaries. Existing decoded/native/callable domains are intended to remain intact.

The final two review fixes preserve empty-slice views after writes through longer aliases and avoid classifying unrelated captured scalar assignments as unsupported buffer replacement.

## Evidence actually obtained

A fresh unchanged-production baseline ran the ten original restored methods through actual DSR `_qg_run_single_check`:

```
PYTHONPATH=../modules/helpers:quality python3 -m unittest -v \
  quality.test_taint_go_decoding.NativeScanningFlowTests -k readinto
```

Result: 10 discovered, 9 executed, 12 failures, 1 error, 1 optional native witness skipped. Baseline full log SHA-256: `37a2e3a74821a882d8b84ccbd05c1112e572d3ed7c56740c69e507962aae0149`.

No candidate test has run. No candidate native Go witness, public JSON/SARIF run, package-cache run, independent 18-case replay, adjacent Go suite, or integrity gate has passed.

## Resume and remaining gaps

1. Restore the candidate against the stated base and inspect the diff.
2. Execute the unchanged ten-method regression gate and the added source methods through DSR. Fix failures before making completion claims.
3. Execute the retained native Go witness, the unchanged independent 18-case corpus, package-cache mutation test, and public module/runner JSON/SARIF cases through DSR. Check exact locations, totals, exit codes, suppression, partial status, selected-file behavior, and cache invalidation.
4. Run the required adjacent Go and repository integrity gates; update production hashes only after qualification.
5. Review literal byte-length inference: Go byte escapes such as `"\\xff"` differ from Python UTF-8 encoding; comments after a trailing comma in a byte-slice literal may affect inferred length. These are unvalidated correctness risks, not established passing behavior.
6. Native read writes in immediate closures are included. General captured buffer index assignment is not newly modeled by the native-read write-summary hook; inspect existing behavior and preserve an explicit unsupported boundary where effects cannot be proven.
7. Helper-local returned buffers and captured buffer-header replacement remain intentionally unsupported in this bounded candidate.

The candidate is not evidence that sections 15–16 or the Go read-buffer bead are complete.


## Additional root recovery review

Root independently replayed all 45 hunks forward and backward against the
immutable source/test files and recovered the originals exactly. No execution
result is implied. The original successful-edit snapshot remains separate from
the final in-memory combination, as described above.

Further static follow-ups to exercise before activation:

- Raw Go strings discard carriage returns; Go hex/octal escapes contribute one
  byte rather than Python's UTF-8 length of the decoded character. Preserve exact
  byte extents or keep the proof unknown.
- Ignore comment-only pieces after a byte-slice literal's trailing comma when
  counting elements; do not invent an additional destination byte.
- Record ordinary indexed writes in buffer write effects for immediate closures;
  unproved delayed writes must remain incomplete. Native-read write hooks alone
  do not prove arbitrary captured indexed assignment behavior.
