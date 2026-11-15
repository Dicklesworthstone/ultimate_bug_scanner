# Go native environment-source implementation checkpoint

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
