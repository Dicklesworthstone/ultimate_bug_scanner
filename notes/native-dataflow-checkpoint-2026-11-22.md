# Native dataflow recovery checkpoint — November 22, 2026

## Status and scope

The execution environment became unavailable while implementing three high-value
dataflow repairs against `d6c529ee94ae565ed6b66724d558b2de98d400d2`.
GitHub remained accessible. This checkpoint preserves manually authored changes
and independently written probes; it does **not** activate an unfinished analyzer
or claim a completed repository/release qualification.

Production analyzer files, registered tests, version and checksum pins remain
unchanged. The candidate patches must be reviewed, applied and validated in a
working execution environment before activation. No GitHub Actions were used.

Read `docs/planning/PLAN_TO_REFLECT_AGENT_FEEDBACK.md`, the active checklist and
the authoritative Beads before continuing. Several open source-coverage beads
already have substantial implementations; these three gaps were reproduced on
the current implementation rather than inferred from stale task status.

## JavaScript: native Array.from mapper and copy semantics

Bead: `ultimate_bug_scanner-1b9j.6.16`.

On the unchanged analyzer, mapper-return and captured-state sources can disappear:

```javascript
const out = Array.from([1], value => req.query.html);
res.send(out[0]);
```

The inverse also misbehaves: a mapper returning a fixed safe string can retain the
input's taint. The candidate reuses the shared callback/heap engine for native
array iteration, live length changes, dense holes, two mapper arguments,
`thisArg`, optional mapping, saved native aliases, helper contexts, exceptions,
fresh outer arrays and borrowed element identity. Unsupported array-like,
custom-iterator and constructor protocols remain explicit incomplete boundaries.

### Preserved material

- `test-suite/patches/javascript-array-from-candidate.patch`: production and
  14 maintained regression methods. Base source blob:
  `d70808fb7607166eddc7a97891acd461ed27307d`; base test blob:
  `e058dc04b1740625f1b10aeb350238f38a346c4d`.
- `test-suite/patches/javascript-array-from-independent.py`: unchanged
  18-case exploratory corpus, with all native Node outcomes checked on baseline.
  Its exception records require inspection; exit zero alone is not an accuracy
  or completeness gate.

### Executed evidence before the outage

- Maintained baseline: 14 methods, 41 failing subcase assertions.
  DSR log SHA-256:
  `3611d9f557c07003b2399c8f99cc3a2dbb2cf639e0919a19e9a14908e2d0ff28`.
- Corrected maintained candidate: all 14 methods pass, no skips.
  DSR log SHA-256:
  `055dc3d4ba70988e5075b514aab232f7e330331865a4b743701875b158ea2d4e`.
- Independent baseline: 5 exact results, 13 incorrect complete results and zero
  partial results across 18 cases. These include both missed sources and false
  alarms. All 18 Node behaviors match their predeclared labels.
  DSR log SHA-256:
  `1943b731f809af321812a7aa39ead3f4b0b3c173e46341ad2df685798a96e278`.
- Full prescribed ShellCheck on the unchanged starting tree passed in 38.316 s.
  DSR log SHA-256:
  `7b7e51ecf6f6b1db4368353a2a6707e8f1030c4470e700b6cdd4a273213bde96`.

The runtime logs were in the disconnected workspace. Their recorded receipts
survived in tool output; the complete logs have not been recovered. Exact patch
forward/reverse replay against the fetched base was verified in tool memory;
this checks reconstruction and is not a rerun of Python or Node.

### Activation blockers

1. Review and fix mixed mapper alternatives, such as a selected function joined
   with `undefined`. A possible identity-copy path must not acquire the mapper's
   definite cleanup. This was identified after the focused pass and is not fixed
   in the archived tested bytes.
2. Replay the unchanged independent corpus. A candidate run was started but no
   completed result was recovered; no candidate accuracy total is claimed.
3. Run adjacent JS heap, callback, module and work-budget tests through DSR.
4. Exercise real module and runner JSON/SARIF, exact locations/severity,
   selection, suppression, cache invalidation and retained findings on partial
   scans. These checks were not completed.
5. Refresh canonical nested checksum pins and development version only after
   the candidate is complete. Run the prescribed integrity, self-scan and suite
   gates; retain existing failures without weakening budgets or expectations.

The parent D6 and release self-scan beads remain open.

## Python: lazy filter(None, stdin) contents

Bead: `ultimate_bug_scanner-1b9j.6.17`.

The unchanged analyzer certifies the following source flow complete with no
finding:

```python
import sys
eval(next(filter(None, sys.stdin)))
```

The candidate reuses native iterator ownership and consumption tracking for
text, buffered and raw stdin. It preserves clean lazy handles separately from
consumed content, native callable aliases, supported helper factories, loops,
comprehensions, next and list/tuple consumers. Unknown predicates/protocols and
uncertain resumption remain explicit boundaries.

Preserved material:

- `test-suite/patches/python-stdin-filter.patch`: exact tested source and ten
  maintained regression methods, including the outstanding failed assertion.
- `test-suite/patches/python-stdin-filter-receipts.json`: original recorded DSR
  receipt fields, source blob identities and recovery limits.
- `test-suite/patches/python-stdin-filter-independent.py`: unchanged 17-case
  independently authored exploratory corpus with native Python witnesses.

Executed evidence:

- Maintained baseline: ten methods, 54 failing assertions.
  Log SHA-256:
  `fd61157adf49aebb846141d8db9693f179260a55f151bc49e6499fd3cc54edc3`.
- Candidate: ten methods, one diagnostic-label assertion failure; aggregate
  result remains failed. The uncalled symbolic-predicate helper correctly
  reports incomplete analysis, but its message names a native zip helper rather
  than filter. The other behavior, source, clean-control, retained-finding and
  native text/buffer/raw witness assertions pass.
  Log SHA-256:
  `0e5c02995662370b8f2795db3ac53a5c9d8d9079022fe4e3667ba1555fcb2610`.
- Independent baseline: 5 exact results and 12 incorrect complete results
  across 17 cases; all native outcomes match the predeclared labels.
  Log SHA-256:
  `e58c45fcc159226d75daa449ba02ac19d5d2207331c4d54bed4037367acbfe92`.
  No candidate replay is claimed.

Before activation, fix the filter diagnostic, implement native text/bytes join
consumption (currently explicitly incomplete), replay the unchanged independent
corpus and run the public/report/cache, adjacent and prescribed gates. Preserve
the original assertion; do not widen it merely to turn this receipt green.
Canonical pins and version have not been regenerated for this inactive patch.
The stdin-provenance, D6 and release-self-scan umbrella goals remain open.

Reconstruction was checked by exact forward/reverse application in tool memory.
Original full runtime logs were not recovered; the saved receipt fields are not
a replacement for them or for rerunning the final tree.
