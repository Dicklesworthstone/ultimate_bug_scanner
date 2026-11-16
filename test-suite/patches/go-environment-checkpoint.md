# Go native environment-source implementation checkpoint

## Subsequent static review — candidate remains unactivated

This section records unexecuted amendments to the source-qualified candidate in
commit `e245471af51fb287ee6ac41249ed1ce6d7b84720`. That commit's complete patch and
evidence remain available in Git history. The current patch still targets
`a603d20fbb11508c03f916e83e566d106678ee92`; its production analyzer and automatic
tests are not changed by saving this archive.

The execution environment disconnected during this review's first baseline and
test-edit attempts, then reported unavailable. No analyzer, native compiler,
public scanner or quality-gate result was recovered by this review. The earlier
285 passing source tests below qualify the preceding candidate, **not the new
amendments or newly added cases**.

### Amendments and retained work

The current patch preserves the preceding native import/getter implementation,
the newer `_call_code` normalizer, all existing matchers, and the complete
maintained tests, including per-case retained evidence and the 150 KB masked
literal regression. It adds:

- A refresh of possible native getter operations after argument evaluation.
- Whole-expression result-parenthesis forwarding in `values()`, retaining the
  caller's original `value_results` key and inner call locations.
- Three maintained regression methods: grouped getter/helper payload/presence,
  grouped reader/helper payload/error, and an immediate closure installing an
  environment getter.
- Eight independent exact-outcome cases covering grouping, reader errors,
  immediate versus unused closures, copied escapers and inner-copy mutation.

The maintained insertion now contains 22 source methods plus the two optional
native/public methods. The standalone independent oracle retains its original
15 labels and evaluator unchanged and now contains 23 cases. All new cases are
unexecuted; partial analysis does not satisfy an exact-finding case.

The old `_NATIVE_CALL` matcher is still absent. Do not apply the historical
`go-environment-grouping-followup.patch` to the current candidate.

### Additional activation blocker: captured getter writes

Independent source review found a remaining transfer gap:

```go
read := html.EscapeString
func() {
    read = environment.Getenv
}()
fmt.Fprint(w, read("HTML"))
```

The current closure path invalidates the old callable's authority but does not
preserve the newly installed getter operation in the outer cell. With a literal
key, fallback contributes no source. This is a **predicted complete-clean miss
from static inspection, not an observed execution failure in this review**.
The refreshed candidate does not repair that closure transfer.

The maintained and independent cases keep the exact desired finding and are not
xfailed or weakened. Fix the captured-write transfer and preserve unused-closure,
saved-copy and inner-copy controls before activation. If a selected flow cannot
be modeled, report an explicit incomplete boundary; do not count that boundary
as a passing exact-finding test.

### Structural checks and executable continuation

Forward and reverse in-memory text replay against the immutable base matched
all hunk counts and context lines without fuzzy application. Original oracle
labels and the evaluator were compared unchanged. These checks verify archive
construction only; no Python syntax, scanner behavior, native execution or
performance pass is claimed for the amendments.

Before activation, complete the closure repair and execute the full current
source and independent oracles, then the existing grouped JSON/XML decoder
tests, grouped `ReadAll` and selected-helper tuple controls, and source-budget
checks. The tuple normalization affects shared machinery. Run the required
native witness, public module/meta-runner formats and canonical quality gates
on the final source. Preserve the qualification and no-deletion requirements
below; keep the bead and D6 incomplete until their own acceptance evidence is
available.

---

## Prior candidate: November 15 source qualification (base a603d20)

This remains an **unactivated source-level candidate**. The replacement
`go-environment-native-candidate.patch` targets the immutable base named below
and contains the tested production/test changes. Forward and reverse hunk replay
against the reconstructed bytes passed. Its SHA-256 is
`827b4062685857bc84b77d7e455dcc0e2a24c4004aebe877acf27364491db61c`. Do not apply the older
`go-environment-grouping-followup.patch` to this replacement: it is retained
only as history of the earlier matcher.

The source implementation and maintained tests were ported manually to
`a603d20fbb11508c03f916e83e566d106678ee92` and executed before the workspace
became unavailable. The existing parenthesis normalizer from that commit
replaces the earlier archived candidate's proposed matcher, so neither the archived
leading-whitespace regex nor its grouped-decoder regression is introduced.

The port changes only native standard-library identity and environment result
transfer in the production analyzer. Exact `os.Getenv` and `os.LookupEnv` calls,
including aliases and selected helper/captured function values, introduce input
provenance. The presence result remains clean. Taking a function value, local
shadowing and nonstandard same-named packages do not invent environment input.
The existing domain-specific sanitizer and parameter-binding behavior remains
covered.

### Observed results

| Check | Current incumbent | Candidate |
| --- | --- | --- |
| Preserved 18-method maintained source oracle | 16 failing assertions/subcases | All 18 methods pass |
| Frozen independent source corpus | 4/15 exact cases | 15/15 exact cases |
| Four Go source suites under DSR | Not rerun as a broad baseline | 295 methods: 285 pass, 10 opt-in skips |
| New 150 KB masked-literal regression in that cohort | Not run separately | Exact source location preserved; 1.514 seconds |

The independent incumbent's 11 failing cases comprise nine unsafe misses and
two false positives. These are cases, not a precision/recall corpus claim.
The 10 skipped methods are five native compiler witnesses and five public
module/meta-runner methods. A compiler named `go` was not present on the original
PATH (`/usr/bin/go` was a board game). Compiler installation and public/integrity
qualification had not completed when the execution environment disconnected.

The successful broad run used the actual DSR
`src/quality_gates.sh::_qg_run_single_check` executor and CPython 3.12.14.
A fixture-retention wrapper preserves all TemporaryDirectory files while leaving
assertions unchanged; the repository's seccomp helper denies deletion in the
test process and all descendants. Existing grouped JSON/XML decoder tests pass.

The full DSR receipt was read back before the disconnect. It is reproduced
below. Its log path identifies the lost runtime; full log bytes were not
recovered, and the recorded log hash is not a newly verified digest of an
available artifact.

```json
{
  "command": "PYTHONDONTWRITEBYTECODE=1 python3 test-suite/artifacts/go-env-session-20261115/run_retained.py test_taint_go_domains test_taint_go_decoding test_taint_go_initializers test_taint_go_packages",
  "status": "passed",
  "executed": true,
  "passed": true,
  "exit_code": 0,
  "cwd": "/workspace/scratch/d51c62bc617a/ultimate_bug_scanner",
  "duration_ms": 28311,
  "timeout_seconds": 120,
  "output_preview": "lper_does_not_resolve_to_package_function] RUN\n[test_taint_go_packages.PackageFlowTests.test_shadowed_helper_does_not_resolve_to_package_function] PASS (0.003s)\nok\ntest_source_returned_by_another_file_reaches_sink (test_taint_go_packages.PackageFlowTests.test_source_returned_by_another_file_reaches_sink) ... [test_taint_go_packages.PackageFlowTests.test_source_returned_by_another_file_reaches_sink] RUN\n[test_taint_go_packages.PackageFlowTests.test_source_returned_by_another_file_reaches_sink] PASS (0.005s)\nok\ntest_variants_preserve_parameter_dependent_effects (test_taint_go_packages.PackageFlowTests.test_variants_preserve_parameter_dependent_effects) ... [test_taint_go_packages.PackageFlowTests.test_variants_preserve_parameter_dependent_effects] RUN\n[test_taint_go_packages.PackageFlowTests.test_variants_preserve_parameter_dependent_effects] PASS (0.006s)\nok\n\n----------------------------------------------------------------------\nRan 295 tests in 27.037s\n\nOK (skipped=10)\n\n# exit_code: 0\n",
  "log_path": "/workspace/scratch/d51c62bc617a/ultimate_bug_scanner/test-suite/artifacts/go-env-session-20261115/go-cohort.log",
  "log_sha256": "80d5ad2484e66bc245a7e95bc0518942c8cb218cebdee8891c718251d0e6d292"
}
```

### Reconstructed source identity

After the executor became unavailable, source and test bytes were reconstructed
from immutable base files, the preserved test insertion, and the exact recorded
manual edits. Their line deltas match the observed live diff: production
`+20/-5` and maintained tests `+331`. No live-checkout file hashes had been
captured, so the following hashes identify the reconstructed files, not a
claimed comparison against lost-disk hashes. Uploaded blob bytes were fetched
back and compared exactly to the reconstruction.

- Analyzer SHA-256: `32eca786a5ed5c1624ad7aca87244579cdc3e224f1b12756a144874ea298c770`.
- Analyzer Git blob: `d3b4dc983e932868224680ba2715728d91d2f048`.
- Maintained tests SHA-256: `f15c846665f2c5487f6521212c09304cfb52eff31e91da950b6f87db6057143f`.
- Maintained tests Git blob: `744ea668a7d8b39a3e497b03b204feb0c1c34532`.

### Exact retention harness used

Save this exact harness at
`test-suite/artifacts/go-env-session-20261115/run_retained.py` to reproduce
the recorded command on Python 3.12+. This changes fixture lifetime only;
it does not skip assertions, substitute scanner outputs or weaken deadlines.

```python
"""Execute unchanged selected tests while retaining all temporary fixtures."""
from pathlib import Path
import os
import sys
import tempfile
import unittest

root = Path(__file__).resolve().parents[3]
artifacts = Path(__file__).resolve().parent / 'retained'
artifacts.mkdir(parents=True, exist_ok=True)
os.environ['TMPDIR'] = str(artifacts)
os.environ['UBS_KEEP_TEMP'] = '1'
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
tempfile.tempdir = str(artifacts)
sys.path.insert(0, str(root / 'test-suite' / 'quality'))
sys.path.insert(0, str(root / 'modules' / 'helpers'))

original_temporary_directory = tempfile.TemporaryDirectory


class RetainedTemporaryDirectory(original_temporary_directory):
    def __init__(self, *args, **kwargs):
        kwargs['delete'] = False
        super().__init__(*args, **kwargs)
        self._finalizer.detach()

    def cleanup(self):
        self._finalizer.detach()


tempfile.TemporaryDirectory = RetainedTemporaryDirectory
from test_keep_temp import prevent_child_deletion

prevent_child_deletion()
print('Retention: fixture cleanup disabled; source assertions unchanged; '
      'kernel blocks deletion in this test process and every subprocess.', flush=True)
unittest.main(module=None, argv=[__file__, '-v', *sys.argv[1:]])
```

### Remaining qualification

No Go module retention changes were made. The module still has cleanup
commands, and the top-level runner rejects Go under `UBS_KEEP_TEMP=1`.
The newly preserved native witness and category-scoped JSON/SARIF matrix remain
unexecuted. Broader repository self-scan/full-suite, native runtime, platform
and signed release/tag qualification are not established by the source results.
Keep the environment-source Bead and D6 umbrella open for these boundaries.

The historical checkpoint and unactivated patch details below describe the
earlier attempt; its matcher must not replace the current structural normalizer.

---

## State

This is an **unactivated implementation checkpoint**, based on main
`f0f99f9da8cf6fdfee0a5cb458d422e25a7563e1`.
The production analyzer, automatic test suite, version and integrity pins are unchanged
by this checkpoint. The execution environment ran out of filesystem space, then
disconnected during migration to available temporary storage. It was explicitly
marked unavailable before the final correction, native witness or public module
matrix could run.

Files in this directory preserve the actual implementation work and fixed test
expectations. They do not claim that the scanner is repaired or released.

## User-visible gap and implementation

The current Go source recognizer misses standard-library environment values through
aliased imports and `os.LookupEnv`. Its name-only `os.Getenv` pattern also
treats taking a function value, a shadowed receiver and an unrelated imported package
as environment reads.

The candidate adds actual `os` package identity to the existing native-call
machinery. Getter results carry input provenance into SQL, shell-command and HTML
sinks. `LookupEnv` keeps its value and Boolean-presence slots distinct.
Existing selected-helper, captured-function, alias, branch and sanitizer handling
is reused. The patch also adds parenthesized native-call recognition so dropping
the old name regex does not lose valid grouped getter calls.

The implementation and maintained tests are in
`go-environment-native-candidate.patch`. The independently labeled
15-case source corpus is `go-environment-independent.py`.
The standalone oracle preserves the tested cases and exact rule/line expectations;
its portable argument/artifact-path packaging was reconstructed after the outage
and has not itself been rerun.

## Observed results before the outage

All these executions used the actual DSR native quality-check executor and
CPython 3.14.10. Source fixtures were analyzed, not executed as Go programs.

| Check | Original analyzer | Candidate |
| --- | --- | --- |
| Maintained environment-source oracle, 18 methods | 16 failing assertions/subcases | 18 methods passed |
| Independent fixed source corpus, 15 cases | 4 passed; nine missed unsafe flows and two false positives | 15 passed |
| Broader Go cohort, 284 methods | Not rerun as a cohort in this session | Two actual grouped-decoder regressions, 204 test-cleanup errors, seven opt-in skips |

The cleanup errors came from explicit `TemporaryDirectory.cleanup()` calls
under the kernel no-deletion guard. Setting `delete=False` only preserves
context-manager cleanup; explicit cleanup still attempts deletion. The external
test runner was corrected to retain those directories without changing assertions,
but the corrected broad run could not execute after the environment disconnected.
Those errors are not classified as passing tests.

Receipts retained before disconnection:

- Maintained baseline: `dsr-go-env-baseline-Q9Oy0uET/output.log`,
  SHA-256 `5a7287582f4c3b4e2f9bdf1fd3f835ccbbdfe30dbeedd91af415a8eaf3f80c4d`.
- Maintained candidate: `dsr-go-env-candidate-ZHGtWozX/output.log`,
  SHA-256 `be25a99c47f674f498a4b8bc38e12287bb360b7fe13c593afce7288d92ea1bb6`.
- Independent baseline: `dsr-independent-go-baseline-Lk4Kazc5/output.log`,
  SHA-256 `9d73eff371ec5fc28429568e06b59458e9af2ef98ab970ee9df4dff7472ea7a4`.
- Independent candidate: `dsr-independent-go-candidate-mISd4KMA/output.log`,
  SHA-256 `059bf2123a494f11b26da93d9693a1cb0879aaef32751759aa199b8c7d1bbd1a`.
- Broader candidate log SHA-256:
  `a5dc927bf280ad728e587dff104d7e1895639f6a4b5a48376c886470c01cd2cb`.

These are recorded receipt identifiers and hashes; the lost environment's log
bytes are not included in this checkpoint.

## Known activation blocker

The broad suite caught a real regression for a decoder constructor wrapped in
result parentheses, for example `(codec.NewDecoder(r.Body))`. The candidate's
new call matcher counts an outer result-group opening as if it grouped only the
callee, so decoder identity is lost. Existing JSON and XML tests catch the result:
the payload sink is missed and the error-result sink is wrongly tainted.

`go-environment-grouping-followup.patch` contains the proposed correction:
only an opening parenthesis whose matching close precedes the invocation's
argument opening belongs to callee grouping. This correction received static
review but was neither applied in the last live checkout nor executed.
Do not activate the first patch alone.

## Required continuation

1. Apply the candidate and grouping follow-up to an isolated checkout of the
   stated base, or port them explicitly to newer main without overwriting incoming work.
2. Re-run the unchanged 18-method oracle and independent 15-case corpus.
3. Re-run the broader Go suites, including both existing grouped JSON/XML decoder
   regressions, using retained scratch under the repository's no-deletion policy.
4. Run the optional compiled environment witness and exact module JSON/SARIF
   matrix added by the candidate. They were authored but never executed here.
   Meta-runner Go retention remains unsupported; do not bypass that refusal or
   describe a module-only result as a full runner result.
5. Refresh canonical helper/module/release checksums only after the final source
   is verified. Follow the existing version/release requirements and prescribed
   gates; do not relax a test to accept a partial or mismatched result.

The prescribed full ShellCheck command was attempted on the unmodified baseline
and was killed with exit 137 after approximately 14.5 seconds. It did not pass.
No full-suite, platform, release, tag or broad D6-completion claim is made.

## Additional static review concern

After preserving the patches, review identified a possible scan-cost problem:
the new `_NATIVE_CALL` expression starts with `s*` and is also used by
`finditer` over masked source. Long inert whitespace/string spans may cause
the regex to retry over the same span repeatedly. This is an unexecuted static
concern, not a measured performance regression. Review the search/match split,
bound leading-whitespace handling at whole-expression call sites, and exercise
long-string/source-budget controls before activation. The grouping follow-up
does not address this separate concern.
