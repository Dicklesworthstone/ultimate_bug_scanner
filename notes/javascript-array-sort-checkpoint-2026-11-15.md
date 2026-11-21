# Native JavaScript array sorting and copying

## Copying methods — November 21, 2026

The native array transfer now models `toSorted`, `toReversed`, `toSpliced`
and `with`. Each operation creates a distinct outer array while retaining
shallow references to its element objects. Replacing an outer slot cannot
silently clean the other array; writing a nested object through a copy remains
visible through the original and its other copies. Reverse, splice and
replacement preserve supported literal slot locations and negative indices.
Copies densify sparse holes into present undefined entries, omit named
properties and leave the source array unchanged. Selected helper summaries,
copy chains, captured receivers and sink-specific sanitizer provenance remain
connected to the resulting values.

The frozen original eight-case witness set exposed six complete-clean XSS
misses and two false positives; all eight native Node observations agreed with
their fixed expectations. The candidate matches all eight scanner expectations.
A separate frozen 23-case oracle improves from 13/23 on the incumbent to 23/23
on the candidate, with all 23 native Node programs matching the independent
expectations. This is bounded regression evidence, not an estimate of overall
scanner accuracy.

| Check | Observed result |
| --- | --- |
| New copying-method source cohort | 12 methods pass, no skips; DSR 18.141 seconds. |
| Existing sort source cohort | All 19 unchanged methods pass, no skips; DSR 2.904 seconds. |
| Original native/scanner witnesses | 8/8 native observations and 8/8 scanner expectations pass; DSR 3.730 seconds. |
| Independent oracle | 23/23 candidate cases pass, versus 13/23 incumbent cases; all 23 native observations match. |
| Public module/meta-runner integration | Both methods pass, no skips: 21 actual calls (16 JSON/SARIF and selected-file checks, 5 cache/invalidation/suppression checks). Unittest 29.750 seconds; DSR 30.083 seconds, exit 0. |

The source cohorts contain 31 maintained methods in total. The independent
oracle, original witnesses and public calls are separate evidence populations
and are not summed as unique cases. DSR ran the checks with retained artifacts.
The public subprocess deadline remains 45 seconds per invocation. An earlier
public invocation lost its execution session before any test result; its
header-only log and empty receipt remain retained separately from this
complete passing rerun.

`toSorted` conservatively retains possible element provenance rather than
proving scalar sort order. Comparator execution, object coercion, unresolved
indices, unknown overrides and altered indexed-property contracts retain
explicit incomplete-analysis boundaries when they cannot be modeled safely.
For a known zero/singleton occupied set, a selected comparator does not
create an artificial execution boundary. Selected own-method bodies retain their actual
behavior. Dense copy allocation is charged against the existing work budget
before expansion. This does not add general comparator, coercion, descriptor,
borrowed-method or custom-prototype execution support.

Final helper SHA-256:
`8a48a8e0ab112275dbea3f73fcfd105079200bed65dc6b8d46fb59038137f86f`.
Final heap-test SHA-256:
`ab80ab541b8069b6712ee8f841327885aab9a661bfc7281a599e313ecd40d0e2`.
New-source DSR log SHA-256:
`c83e3d00a6adddbf56c650bc57d39d0aeb73266f6f54cf2781348854dacc9dcb`.
Existing-sort DSR log SHA-256:
`f91cbabffd0b20df07010a56ffd3212662175b7291e1069fea24f72bc486af33`.
Original-witness DSR log SHA-256:
`055d19ffbe9699a624268c1a0954d8004d127003a9a778386468da1a3cabb28d`.
Independent DSR log SHA-256:
`c928a63144f2ba131b4fea57a2632949de51fd3bb26f8bc5ce90ac938ba435a4`.
Public DSR log SHA-256: `dece255168c6d5837545e880a111855488117a32ecf5421f2a5db1e7885d04f7`.

The earlier 497-method result below belongs to the previous sort activation;
that full population was not rerun for this copying-method slice. No new
full-suite, release, performance or Bead-closure qualification is claimed here.


## Activated implementation — November 20, 2026

The recovered implementation is now active. All 19 original sort methods pass,
including real Node witnesses, versus 31 failed assertions on the unchanged
baseline. Two additional methods validate 25 actual module/meta-runner JSON and
SARIF invocations, exact findings/locations/totals/exits, incomplete coverage,
selected-file isolation, cache invalidation and suppression. The combined JS
cohorts pass 497 distinct methods; one unrelated TypeScript compiler resolver
oracle remains skipped. DSR ran every check with retained fixtures and unchanged
assertions and deadlines. The existing 55-case heap CLI matrix passed in 89.575
seconds. Canonical checksum verification passes. The repository-wide ShellCheck
attempt was killed with exit 137; full-suite/release qualification is not claimed.
Comparator/coercion effects retain the explicit incomplete boundary described
below. The remaining checkpoint sections document historical, inactive evidence.

Final helper SHA-256: `b27555e01b1e4968a7e5d9729a711c9355fadfb4b3c53195c71aa4dd4391d0e1`.
Public DSR log SHA-256: `57818c2cd0b0824267c2c6117bbed46f1676d6185883c380546be69c26d2da0d`.

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
