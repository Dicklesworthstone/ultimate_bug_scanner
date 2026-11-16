# Native JavaScript Array.sort: pending regression checkpoint

## Status

This checkpoint preserves investigation and unactivated test work only. No Array.sort transfer was implemented. The 14 proposed regression methods have not been run: the execution workspace disconnected after their local edit and before the first focused test invocation. There is no candidate correctness, public CLI, performance, full-suite, release, or Bead-closure claim.

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

## Pending test patch

`test-suite/patches/javascript-array-sort-candidate.patch` is a unified diff against the unchanged `test-suite/quality/test_taint_js_heap.py` blob above. It adds the retained-artifact `scan_sort` helper, the hashlib import, and 14 methods. It adds no analyzer implementation and changes no existing assertion.

The proposed tests cover ignored calls, aliases, literal computed dispatch, helper summaries, cleanup through the returned receiver, sparse holes, named properties, sanitizer domains, joined receivers, argument order, zero/singleton callback behavior, own overrides, comparator/coercion/descriptor/prototype boundaries and maximum sparse extent. Selected source programs have independent Node witnesses. Review and run these tests before activation; they are not asserted to be a verified oracle merely because they were authored.

## Proposed implementation, not executed

Extend the existing bounded native array transfer in `modules/helpers/ubs_core/analyzers/taint_js.py`; add sort to native dispatch and computed-key method invalidation. Capture the receiver and callee before evaluating arguments. The native method returns the same array.

For ordinary indexed data properties with a proven extent and presence, preserve all possible element permutations in the occupied prefix and remove only proven trailing holes. Preserve named properties, length, source provenance, sanitizer domains and object identity. Joined receivers must use the existing weak mutation merge. Sparse maximum-length arrays must charge work by represented slots, without expanding billions of holes.

Default sorting can invoke object-to-string code; supplied comparator callbacks can mutate captures, throw or coerce their result. Unsupported execution must produce explicit incomplete analysis while retaining independent findings, rather than a clean report. No comparison occurs with zero or one present element, but an invalid comparator can still throw before sorting. Descriptor/prototype effects and unknown overrides remain explicit boundaries; selected own methods retain their actual bodies instead of borrowing native identity.

The normative reference consulted was [ECMAScript Array.prototype.sort, SortIndexedProperties and CompareArrayElements](https://tc39.es/ecma262/multipage/indexed-collections.html#sec-array.prototype.sort).

## Resume checks

First replay the seven baseline rows, inspect the pending tests, then implement and run the focused methods through DSR. Extend the existing real module/runner JSON and SARIF tests for exact rule IDs, locations, totals, exits and complete/partial status. Run the unchanged JS taint/security cohort under retention, refresh canonical pins/version, and preserve all original work budgets and full-suite gates. No Actions execution is authorized by this checkpoint.
