# Native JavaScript Array.sort: pending regression checkpoint

## Current recovery status — November 15, 2026 follow-up

**The implementation is preserved but is not activated or qualified.** The current
`test-suite/patches/javascript-array-sort-candidate.patch` replaces the earlier
test-only patch with a combined analyzer/test candidate. It includes all 14
original regression methods unchanged, plus five additional methods. The
production scanner, canonical checksums, release version and Bead status must
not be changed solely on this checkpoint.

The candidate extends the existing native-array machinery with in-place sort
permutation, receiver/return aliases, selected local summaries, sparse occupied
prefixes, named-property separation, joined-target weak mutation, method capture
before argument effects, and sort/flatMap postfix chains. Custom comparator
execution, object coercion and unresolved indexed-property protocols report
incomplete analysis. This is a bounded candidate, not general JavaScript
comparison or coercion modeling.

The final source review found that an optional clean element and an absent
element share empty provenance. The implementation must count every represented
numeric slot toward the possible occupied prefix; only definite presence proves
its minimum length. The final correction uses `present = list(numeric.values())`
and adds two native-witness subcases under
`test_sort_optional_clean_slots_still_contribute_to_possible_extent`.
The edit tool reported both patches successful, and a later local diff reported
the expected line totals, but **neither this correction nor its new method was
executed before the environment became unavailable**.

### Observed verification, including failures

| Invocation | Observed result | Limit on the evidence |
| --- | --- | --- |
| Initial direct execution of the unchanged 14 sort methods | 14 methods, 20 failing subcases, 4.878 seconds | Establishes the missing behavior against the original helper. Some native controls ran, but this was not a replay of every historical Node witness. |
| First DSR baseline replay | 14 methods, 20 failing subcases; unittest reported 15.126 seconds | The module had loaded before the source edit, but later per-case receipts hashed the changed on-disk helper. This is **not** immutable paired-source evidence. |
| First implementation through DSR and the retained-fixture/deletion-fenced harness | Native exit 124 at the unchanged 120-second suite deadline; receipt duration 120381 ms | Several scanner assertions completed, while Node subprocess checks reported errors during executor stalls. No complete passing denominator was observed. |
| Extended candidate through the same DSR harness | Native exit 124 at the unchanged 120-second deadline; receipt duration 192134 ms | Executor transport was intermittently stalled. Native errors were present before termination. This is a failed run, not a candidate pass or performance result. |
| Final optional-slot correction and fifth added method | Successful edit results and a later local diff only | No scanner, native runtime, syntax, cohort, public-format or work-budget qualification on this final candidate. |

The initial direct run identified the pre-change helper SHA256 as
`a188f4a2ba0ca0c3ef0a5650c61cb5e09ecb68f4f8c80304ff600033cb9ff617`.
The DSR receipts and logs were written under
`test-suite/artifacts/javascript-sort/` in the execution workspace, which later
became unavailable. Their current local availability is not asserted. Two
observed receipt log digests were:

- `implementation-dsr.log`:
  `0cec76e808df391360a32b383329ce708f9fe7286f14795314adc62482c8c7a7`.
- `focused-dsr.log`:
  `e38ec9ab84f390d2ad9723ca5996c2b4a0d12c2fbb751fb62191308478a64dd1`.

Per-method printed PASS labels are not a substitute for unittest subcase
results or the native process exit. No skipped native assertion, increased
per-Node timeout, relaxed scanner expectation, or narrower original oracle is
counted as passing. No complete scanner-only/native split was executed after
the outage; that was a proposed next step.

### Exact recovery provenance

The reconstruction used immutable commit
`f1c06ea3f80497432a29581871b3719ad8462f9d`:

| Asset | Immutable base blob | Recovered candidate blob |
| --- | --- | --- |
| `modules/helpers/ubs_core/analyzers/taint_js.py` | `2cb933721b14cd026e1989d87a96338230003656` | `1f0e8ee69945b5dd30949cd15ed7d40d4d954a86` |
| `test-suite/quality/test_taint_js_heap.py` | `c2587297fad74839615e2759c2246e6e28251165` | `932fb753a49aee496af1113dc99229f72d8f6514` |
| Combined candidate patch | Original test-only patch `395f9d164f471b582a17432d4c18abdcf8025b35` | `987d33a04414b25f0907851f5841d382eb9a38fd` |

The source was reconstructed from 17 exact, unique manual-edit anchors. The
test file was reconstructed by replaying both original patch hunks exactly,
then the five successful manual additions. Reverse replay returned the exact
immutable base contents. All three candidate blobs were fetched back from
GitHub and compared byte for byte with the reconstructed strings.

The last successful local diff reported 83 additions/16 deletions in the helper
(net +67 lines) and 212 additions in the tests. The reconstructed contents have
the same net line changes. **This line-count consistency and exact replay are
weaker than byte-identical proof against the final local files**: the executor
failed before final local object hashes could be obtained. The recovered patch
uses different context alignment from Git's local diff and must be checked
against the base before use. No commit or branch update was performed by the
recovery worker; the blobs alone do not activate a scanner change.

### Remaining qualification

1. Restore execution and verify the combined patch against the immutable base
   or a later tree whose relevant files remain identical. Check the resulting
   file object hashes against the recovered candidate blobs above.
2. Run all 19 scanner methods, preserving the original 14 methods and every
   assertion. If native controls are split into separate invocations to
   diagnose executor stalls, retain every collected source/expected-output
   pair and execute the original native assertion with its unchanged
   15-second subprocess timeout and 5000-ms VM timeout. A split must be
   reported as such, not silently called a completed original suite.
3. Run the unchanged heap/array and related taint/security cohort; verify
   sparse maximum extents and work-budget behavior, selected files,
   suppressions and cache invalidation.
4. Run actual JavaScript module and meta-runner JSON/SARIF cases with exact
   finding IDs, sites, counts, status and exit expectations. No such public
   qualification completed in this follow-up.
5. Complete canonical integrity and required repository/release gates before
   activation. Keep `ultimate_bug_scanner-array-sort` in progress until its
   original acceptance is established. No full-suite, release, performance,
   native-callback-completeness or Bead-closure claim is made here.

The sections below preserve the earlier investigation and its original
test-only checkpoint as historical evidence. Their baseline source and
observations precede the unqualified implementation above.

## Historical checkpoint status

At the earlier checkpoint, only investigation and unactivated test work had been preserved. No Array.sort transfer had been implemented. The 14 proposed regression methods had not been run: the execution workspace disconnected after their local edit and before the first focused test invocation. There is no candidate correctness, public CLI, performance, full-suite, release, or Bead-closure claim.

Tracked by `ultimate_bug_scanner-array-sort`, related to the open
`ultimate_bug_scanner-array-fill` work and the D6 umbrella. Existing native fill, own-method identity, splice and copyWithin behavior must be preserved. The older `javascript-array-fill-candidate.patch` is historical and must not be reapplied to current main.

## Baseline identity and observations

The live baseline was the checkout of main at `a603d20fbb11508c03f916e83e566d106678ee92`. The unchanged test source fetched through GitHub has blob SHA `df3aee07d336ecd9401215864ee25099d1378326`. Actual analyzer calls used `taint_js.run(RunContext(lang="javascript", files=[fixture]))`. Each authored fixture also ran in Node's `vm.runInNewContext` with a 5000 ms timeout, `req.query.html = "aa-input"`, and a collecting `res.send`.

All seven native Node controls exited 0. Four programs sent the request marker while the analyzer returned complete with no findings. The return-alias positive and two clean controls already behaved correctly. This is a bounded, seven-case baseline, not a whole-scanner accuracy estimate.

The original run wrote source and JSON results under `test-suite/artifacts/array-sort-baseline-_96vvrv5/`; that workspace became unavailable. The exact source/output observations are preserved below so the baseline can be replayed independently. No local log availability is asserted.

```json
[
  {
    "id": "dirty-moves",
    "source": "const items=[\"zz-clean\", req.query.html]; items.sort(); res.send(items[0]);",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "aa-input"
    ],
    "assessment": "unsafe complete miss"
  },
  {
    "id": "dirty-alias",
    "source": "const items=[\"zz-clean\", req.query.html]; const a=items; a.sort(); res.send(items[0]);",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "aa-input"
    ],
    "assessment": "unsafe complete miss"
  },
  {
    "id": "return-alias",
    "source": "const items=[\"zz-clean\", req.query.html]; const a=items.sort(); res.send(a[0]);",
    "scanner": {
      "status": "ok",
      "rules": [
        "javascript.taint.xss"
      ],
      "line": 1,
      "col": 65
    },
    "node": [
      "aa-input"
    ],
    "assessment": "existing positive preserved"
  },
  {
    "id": "clean",
    "source": "const items=[\"zz-clean\", \"aa-clean\"]; items.sort(); res.send(items[0]);",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "aa-clean"
    ],
    "assessment": "existing clean control"
  },
  {
    "id": "callback-write",
    "source": "const box={html:\"safe\"}; const items=[\"b\", \"a\"]; items.sort((a,b)=>{box.html=req.query.html; return 0;}); res.send(box.html);",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "aa-input"
    ],
    "assessment": "unsafe complete miss"
  },
  {
    "id": "object-conversion",
    "source": "const box={html:\"safe\"}; const items=[\"b\", {toString(){box.html=req.query.html;return \"a\";}}]; items.sort(); res.send(box.html);",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "aa-input"
    ],
    "assessment": "unsafe complete miss"
  },
  {
    "id": "custom-own",
    "source": "const items=[\"safe\"]; items.sort=function(){return \"clean\";}; res.send(items.sort(req.query.html));",
    "scanner": {
      "status": "ok",
      "rules": []
    },
    "node": [
      "clean"
    ],
    "assessment": "existing clean control"
  }
]
```

## Historical test-only patch

Before this follow-up, `test-suite/patches/javascript-array-sort-candidate.patch` was a unified diff against the unchanged `test-suite/quality/test_taint_js_heap.py` blob above. It adds the retained-artifact `scan_sort` helper, the hashlib import, and 14 methods. It adds no analyzer implementation and changes no existing assertion.

The proposed tests cover ignored calls, aliases, literal computed dispatch, helper summaries, cleanup through the returned receiver, sparse holes, named properties, sanitizer domains, joined receivers, argument order, zero/singleton callback behavior, own overrides, comparator/coercion/descriptor/prototype boundaries and maximum sparse extent. Selected source programs have independent Node witnesses. Review and run these tests before activation; they are not asserted to be a verified oracle merely because they were authored.

## Proposed implementation, not executed

Extend the existing bounded native array transfer in `modules/helpers/ubs_core/analyzers/taint_js.py`; add sort to native dispatch and computed-key method invalidation. Capture the receiver and callee before evaluating arguments. The native method returns the same array.

For ordinary indexed data properties with a proven extent and presence, preserve all possible element permutations in the occupied prefix and remove only proven trailing holes. Preserve named properties, length, source provenance, sanitizer domains and object identity. Joined receivers must use the existing weak mutation merge. Sparse maximum-length arrays must charge work by represented slots, without expanding billions of holes.

Default sorting can invoke object-to-string code; supplied comparator callbacks can mutate captures, throw or coerce their result. Unsupported execution must produce explicit incomplete analysis while retaining independent findings, rather than a clean report. No comparison occurs with zero or one present element, but an invalid comparator can still throw before sorting. Descriptor/prototype effects and unknown overrides remain explicit boundaries; selected own methods retain their actual bodies instead of borrowing native identity.

The normative reference consulted was [ECMAScript Array.prototype.sort, SortIndexedProperties and CompareArrayElements](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.sort).

## Resume checks

First replay the seven baseline rows, inspect the pending tests, then implement and run the focused methods through DSR. Extend the existing real module/runner JSON and SARIF tests for exact rule IDs, locations, totals, exits and complete/partial status. Run the unchanged JS taint/security cohort under retention, refresh canonical pins/version, and preserve all original work budgets and full-suite gates. No Actions execution is authorized by this checkpoint.
