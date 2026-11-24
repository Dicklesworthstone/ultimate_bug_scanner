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

## Go: io.ReadFull and io.ReadAtLeast destination writes

Bead: `ultimate_bug_scanner-1b9j.6.18`.

The unchanged analyzer can report no findings and complete analysis for:

```go
buffer := make([]byte, 128)
io.ReadFull(r.Body, buffer)
db.Query(string(buffer))
```

The intended shared model must carry Reader contents into byte-slice backing
storage, preserve aliases and partial writes, and separate payloads from counts
and errors. Proven zero-length and invalid-minimum no-read operations must keep
their actual behavior.

Preserved material:

- `test-suite/patches/go-read-into-candidate.patch`: exact partial edits.
- `test-suite/patches/go-read-into-checkpoint.md`: detailed reconstruction,
  observed evidence and implementation instructions.
- `test-suite/patches/go-read-into-independent.py`: unchanged 18-case independent
  source probe.

The maintained baseline ran nine methods: 12 failed assertions and one error.
DSR log SHA-256:
`f23d9d734eb3212892f8ce96b821bb2caa21ab64a83dab30b5846717ae9778f6`.
The separate independent baseline produced 10 exact, one partial and seven
incorrect complete results; log SHA-256:
`7ac1fd7e2c99abc572bb1d720455498b3667651a683afae5dc82665553af1fb6`.

This candidate is **unfinished implementation**, not just pending qualification.
The native read-into transfer, destination backing-cell writes and helper-summary
integration still need implementation. The added scaffold has two identified
issues (nil recognition order and masked rune-literal lengths) recorded in the
detailed checkpoint. No candidate syntax or runtime test completed. The opt-in
real Go witness was written but not executed.

Finish those contracts, replay unchanged source and native witnesses, then run
real reports and existing affected suites through DSR. Refresh pins/version only
after functional completion and run prescribed gates. Keep the broader Go input,
D6 and release goals open. All 25 recorded manual hunks were checked against the
immutable base and the recovery patch replayed both ways in tool memory; this
does not establish that the unfinished candidate executes correctly.

## November 23 continuation — candidates remain unactivated

The starting revision was `b27c0dcc126a4181ca0766a69ed91cffb9ed305e`.
The workspace filesystem ran out of space, so the session copied its checkout
and DSR into a separate temporary filesystem without deleting the originals.
The execution service subsequently disconnected again. Interrupted launches and
missing receipts are not test passes. These commits preserve implementations
and regression tests for qualification in a working executor; the production
analyzers and integrity pins are not changed by the checkpoint commits.

### JavaScript Array.from

The updated `javascript-array-from-candidate.patch` applies to the starting
revision above. It includes the native mapper/copy implementation, 20 maintained
and opt-in public methods, evaluated-mapper identity checks, explicit incomplete
handling for mixed mapper alternatives, and native-member deletion tracking.
Saved native aliases remain distinct from later property deletion. The public
methods specify 16 format/selection calls and seven cache/edit/suppression/partial
calls; they have not run.

Static review also found that native Array.from probing must follow existing
SQL receiver dispatch. The final candidate preserves that dispatch order and
adds a bound/raw Drizzle regression. These review follow-ups were reconstructed
in tool memory after the disconnect, not applied or executed in the lost workspace.

Recovery objects: exact last authored snapshot patch
`6685704650bbc56dfd8029ed64f1693c9d9fa522`; reviewed final patch
`393101150245677e54b00a818438a3c90d7151fa`. Both target the immutable
base source/test blobs documented in the patch. Root independently replayed the
final patch forward and backward against those base files with exact equality.
That establishes patch reconstruction only. The candidate DSR run and unchanged
18-case independent replay produced no recovered completion; no new JavaScript
runtime pass, accuracy result, activation or release qualification is claimed.

Before activation, run the maintained and independent cases, the new public
methods and affected heap/callback/SQL cohorts, then regenerate canonical pins
and complete the original Bead's DSR gates. Keep `1b9j.6.16` in progress.

### Python native filter and join consumption

The updated `python-stdin-filter.patch` now targets `b27c0dcc` and includes
native text/bytes join consumption, typed scalar iterator contents and distinct
filter-helper obligations. The exact original diagnostic assertion is preserved
and now passes. The candidate's bound bytes-join receiver proof was corrected
after seven initial errors in the newly added binary-join cases.

A genuine DSR check of the authored candidate completed successfully: all 12
maintained/native methods passed (the original ten plus two join methods).
Receipt `py-filter-candidate-joins.Wr7iQYmK` recorded exit 0, 2,963 ms and
log SHA-256 `066770cf77c8666ae4d49617f2093164584fb2cac785c55384d6a84a14738d8d`.
The fresh unchanged-source baseline's raw unittest output recorded 66 failed
subcase assertions and two errors across those 12 methods; executor loss
interrupted its receipt serialization. The earlier failed candidate receipt
is preserved in `python-stdin-filter-receipts.json` alongside the passing fields.

The final combined patch additionally contains two unexecuted public methods
specifying 20 module/runner JSON/SARIF calls and seven cache/edit/suppression/
partial-nonreuse calls. Those additions are not covered by the 12-method pass.
The unchanged 17-case independent corpus and adjacent suites have not completed.
Static independent review found no concrete false-clean blocker in the native
filter/join paths; it supplied mixed text/binary helper-context and cursor-reuse
witnesses for the still-pending runtime qualification. Nested filters, arbitrary
predicates, opaque join receivers and uncertain resumption remain explicit
incomplete-analysis boundaries.

Recovery patch: `6dc3814e689dc61aef86ceb874b3888c9f3ce5e0`.
Source associated with the observed pass: `407278c2ad00577666272667e13b82da27c6666f`.
Maintained-only test snapshot: `103e986d6dcd3e2f0706fe7963bf3c752c802a64`;
complete test draft: `0534ea179a042417cc824c95f491e6817ef0e113`.
Root independently replayed the patch forward/backward against immutable base
files and matched the reconstructed source/test blobs exactly. Comparison to the
lost local files remains unavailable; this is recovery evidence, not an additional
runtime pass. Keep `1b9j.6.17` in progress until its original independent,
public, adjacent and canonical integrity/DSR gates are complete.

### Go native destination buffers

The updated `go-read-into-candidate.patch` targets `b27c0dcc`. It adds native
`io.ReadFull`/`io.ReadAtLeast` and selected `Read` transfer paths, backing-cell
identity, reslice/alias handling, no-read bounds, clean metadata, helper write
contracts and escape/closure boundaries. Ten original regression methods are
preserved and nine source/cache/public methods are added. This final combination
is unexecuted and unvalidated; it is not ready for production activation.

The fresh DSR baseline discovered ten original methods: nine executed, with 12
failed assertions and one error; the optional native witness skipped. Log SHA-256
`37a2e3a74821a882d8b84ccbd05c1112e572d3ed7c56740c69e507962aae0149`.
No candidate/native/independent/public test completion was observed.

Final combined patch: `636a11e95ac737b93cdf5c13d5090708bd5d215e`.
The prior successful-edit reconstruction is preserved by
`4bb8637c6f57bfc07fd4abb749148ab08671c3f1`; the later, originally unapplied
summary integration is preserved by `d4a93003da5f79b3dbd36a1897b2d1c0783e6d7f`.
Root independently checked exact forward/reverse replay of the final 45 hunks
against immutable source/test blobs. This does not establish Python syntax,
native Go semantics, final disk-byte identity or a passing DSR gate.

Before activation, resolve literal byte-length proof risks (Go hex/octal escapes,
raw-string CR handling and comments after trailing commas) and ordinary captured
buffer-index writes. Run the unchanged native/independent corpus and added
methods, affected Go suites, public reports and canonical integrity checks.
Returned helper-local buffers and captured buffer-header replacement remain
intentional incomplete-analysis boundaries. The detailed current checkpoint is
`test-suite/patches/go-read-into-checkpoint.md`; keep `1b9j.6.18` in progress.

## November 24 source review — mixed JavaScript heap updates

Bead: `ultimate_bug_scanner-js-mixed-heap-updates`.

The reviewed baseline is `34fcffa6744c4d15b0fc939b753ff29b31d9e599`.
Read the feedback plan, active checklist, reality-check bridge plan and current
Beads before selecting this work. Several older open beads already contain
substantial implementations; this candidate addresses a separate current
destructive-update defect.

The shared `write_property` path refuses strong updates when the receiver has
a scalar alternative. Property deletion and the literal array-length fast path
omit that same proof. For example, `const target=flag?box:0; delete target.html;`
can erase `box.html` in analysis even though the scalar branch leaves the
original object unchanged. Likewise, `target.length=0` can discard the original
array's tainted elements when the target might be a scalar. These are
source-traced predicted false-clean cases, not executed baseline results.

Preserved candidate:

- `test-suite/patches/javascript-mixed-heap-updates.patch`, Git blob
  `00a68981a6961c13d81ec39799ffa114fba46111`.
- Base analyzer: `modules/helpers/ubs_core/analyzers/taint_js.py`,
  blob `70f5bd3b0649718653829a61f25cc345fb48a704`.
- Base tests: `test-suite/quality/test_taint_js_heap.py`,
  blob `a849087682a0be68b9de139f0bee6bbf9db57432`.
- Two production guards reuse the existing scalar-alternative proof. Six
  maintained methods specify 24 scanner subcases and 40 optional Node witness
  calls: unsafe original/aliased/helper cases, projection aliases, honest
  incomplete projections after weak updates, and exact-target clean controls.
  Primitive length-write witnesses intentionally use ordinary non-strict scripts.

Root independently inspected the two update paths and checked every patch hunk
against the immutable source, including exact forward/reverse reconstruction.
That is text reconstruction only. No Python/Node execution, scanner baseline,
syntax check, DSR gate, ShellCheck, public CLI, cache or full-suite result was
obtained: this session exposes neither an attached computer nor an attachment
or DSR execution tool. GitHub Actions are forbidden by repository policy and
were not used. The production analyzer, version and canonical pins are unchanged.

Before activation, run the new methods on the unchanged and candidate sources
through DSR with Node available, retain the original recursive-clone controls,
and run the affected heap/scan-cost and real module/runner report, selection,
suppression, partial-result and cache checks. Refresh canonical integrity pins
and the development version only for the qualified production edit, then run
the prescribed checks without weakening existing limits or expectations.

This does not implement `Object.keys` shape refinement or close
`ultimate_bug_scanner-1b9j.6.22`, D6, or release qualification.
