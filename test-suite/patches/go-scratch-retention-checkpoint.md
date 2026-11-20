# Go scratch retention: active support and qualification

## Active support and remaining audit — November 20, 2026

The reviewed retention bridge is now active: Go uses the shared scratch-removal
primitive, the runner accepts Go in retention mode, and the module explicitly
reports the compiled lifecycle layer unavailable unless category 17 is omitted.
Direct static-core callers keep their previous completion/cache semantics.
Optional Go compiler adapters refuse retention-unsafe execution; read-only
formatting remains available. The adapter regression and unchanged direct-core
cache/context tests pass through DSR.

Strict syscall audit execution is blocked here: `strace` reports
`PTRACE_TRACEME: Operation not permitted`. The audit assertions remain unchanged
and are not counted as passing. A separate real report-contract test passes all
12 module/runner JSON/SARIF cases, covering unsafe, clean and refused-helper
outcomes with exact findings, coverage status and exit assertions. The initial
aggregate timed out during severe execution delays; the unchanged retry passed
in 8,089 ms through DSR. Log SHA-256:
`4c865c1e98c076bd785dcb5016f8217d807075d602eebef937ce48d4cfd97bea`.
The Go shell module also passes ShellCheck. The kernel no-deletion guard remained
enabled throughout execution, but no zero-deletion-attempt trace is claimed.
The historical inactive-candidate record follows; broader qualification stays open.

## Historical candidate status (superseded above)

This is an inactive source/test patch, preserved after the execution workspace
became unavailable. It is separate from the Go closure-parameter fix committed
in `7e5ebf11ec118bf13754a5e1b75f894f605b2a83`. None of this retention candidate
is active in the scanner.

Patch: `test-suite/patches/go-scratch-retention-candidate.apply-patch`.
Base for exact contextual replay: `f1c06ea3f80497432a29581871b3719ad8462f9d`.
Patch Git blob: `4cf427fdd8d761d73e17bcb051744eea90973b84`.
Patch SHA-256: `dbd34ef758f72cf5a44080527c1112bbe7d853ca6c10d229d3d489ed384e9b22`.

## Implemented candidate

The Go module routes its existing scratch cleanup through the shared
`ubs_remove_temp` primitive and joins the runner's retention allowlist.
Static findings remain enabled. The compiled category-17 lifecycle helper
cannot promise scratch retention, so the module explicitly passes a private
`--lifecycle-refused` flag to the Go core. Reports then retain static findings
and expose partial coverage in every format. Selecting `--skip=17` omits that
layer explicitly. Direct callers of the static core do not request the shell
module's compiled bridge and therefore do not receive this refusal.

Installed `go vet` and `govulncheck` adapters refuse execution in retention
mode with partial coverage. Read-only `gofmt` remains available. Ordinary
cleanup mode keeps its existing behavior.

Tests add twelve real module/runner JSON/SARIF invocations spanning unsafe,
clean and refused-helper cases, plus text/rule-listing checks, using the
existing syscall-observation harness. A focused adapter test proves that
compiler adapters are not invoked while formatting findings are retained.

## Observed evidence and unresolved checks

Only the focused adapter unittest completed: one test passed through DSR in
3,024 ms, with retained fixtures and the inherited deletion fence. Its mocks
verify adapter dispatch; it is not a native compiler or public scanner proof.
Observed receipt log SHA-256:
`2141ff580259a457d1c87fefef8f96b543e0ca7c07ce27c304d5a75a81d7c2c8`.

A public scanner verification command was submitted, but no execution result
or receipt was recovered before the workspace became unavailable. There is
no successful public-format, zero-deletion-syscall, cache, full-suite or
default-cleanup-equivalence claim.

An earlier intermediate candidate checked the environment unconditionally
inside `go_scan`. That could wrongly mark direct static-core calls partial
and is a plausible contributor to the failed context/cache test documented
in `notes/go-native-closure-verification.md`. The final patch uses the
explicit module flag; its isolated rerun did not execute. Preserve the
original cache assertions and rerun them before activation.

## Recovery and next verification

The archived final patch was reconstructed from the successful manual-edit
payloads. All 22 line-aligned hunks replay exactly against seven immutable
base files, and reversing them recovers those files exactly. GitHub blob
readback matches the archived patch. No final local-file digest was recovered,
so this establishes contextual patch validity, not byte equality to a final
filesystem snapshot or executed correctness.

After execution returns, run the unchanged direct-core context/cache tests,
the new public retention matrix and existing Go adapter/CLI suites. Inspect
real syscall traces and maintain all finding, status and exit assertions.
Resolve failures before adding Go to the active retention allowlist. Refresh
canonical helper/module/runner checksums only when activating the qualified
implementation. Broader retention and full-suite beads remain open.
