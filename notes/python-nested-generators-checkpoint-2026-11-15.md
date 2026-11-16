# Python SQL nested-generator checkpoint

**Status: unactivated implementation candidate, with known unresolved behavior.** No candidate or new regression was executed. The workspace became unavailable before the production patch could be written.

## Recoverable work

- Base commit: `f1c06ea3f80497432a29581871b3719ad8462f9d`.
- Implementation and regression patch: `test-suite/patches/python-nested-generators-streaming.patch`.
- Immutable patch blob: `d476b02beb79b19f84ade4837a767289759bb530`.
- Base detector blob: `885e99149e2dd67313095221f0a6e01e886a5c22`.
- Base test blob: `16d85079e9c74e415aae9c0a10844f4d0d6e4173`.
- Related diagnostic-fixture patch: `test-suite/patches/python-nested-generators-completion.apply-patch`.

The production proposal streams each inner-generator yield into the outer consumer before the next producer step. This is intended to preserve interleaved SQL writes, live captures, early stopping, exhaustion and exception state instead of eagerly flattening the producer. Overlapping lexical frames, callback writes, uncertain namespaces and finalizer protocols remain explicit incomplete boundaries.

Four new test methods contain seven scalar composition cases, eleven SQLite witnesses, eight refusal controls and four public module/runner cases intended to exercise sixteen format invocations. These are authored expectations, not passed tests.

## Baseline evidence

Direct Python 3.12 detector probes on the base produced these observed outcomes:

| Probe | Observed base result |
| --- | --- |
| Bytes join with concatenated generator elements beside constant SQL | Complete, no SQL findings |
| Simple captured-list closure beside constant SQL | Complete, no SQL findings |
| `list(x for x in (y for y in (1, 2)))` beside constant SQL | `SQLFlowLimit: SQL nested generator iteration is unsupported; analysis is incomplete` |
| Nested generator composition carrying interpolated SQL | The same nested-generator refusal |

The first two reports were already supported on current main. The nested cases establish the selected remaining coverage gap.

## Verification limits and known blocker

The initial production `apply_patch` failed before reading the target file. The final checkpoint was reconstructed from that manual proposal; namespace/finalizer guards and regression cases were authored afterward. No new source, SQLite witness or public scan executed.

All nine unified-diff hunks match the exact immutable base. Forward in-memory replay and reverse replay succeeded, restoring byte-identical original files. The four separate diagnostic-fixture hunks passed the same contextual replay. These checks establish recoverability only; they do not establish Python syntax, runtime semantics or analyzer correctness.

Static review found that `generator_call` selects the `any()`/`all()` model through `generator_has_writes_or_sinks`, which does not count a generator captured as the outermost iterable as an observable cursor effect. Consequently the new short-circuit-prefix witness can still enter the read-only projection path and refuse. Resolve captured-producer classification before claiming that case is supported; do not weaken its expected outcome.

Also review consumer-exception forwarding, nested lexical restoration, multiple comprehension clauses, producer cursor mutation, exhausted/partially consumed producers and generator finalization before activation.

## Diagnostic gate preservation

Once simple nested generators are supported, three existing tests in `test_python_completion.py` can no longer use that shape to force a semantic coverage error. The companion patch replaces it with an asynchronous generator consumption boundary. It retains all assertions for diagnostic identity, text/JSON parity, partial acceptance, failure precedence and preserved findings. That replacement itself has not run.

## Remaining activation work

Resolve the known dispatch blocker, then run the new SQLite and refusal cases, complete SQL detector/value-capture/sink-argument suites, Python completion tests and real module/runner JSON/SARIF matrix. Preserve separate incomplete results from other analyzers if encountered; a SQL-detector improvement alone is not proof of end-to-end scan completion. Regenerate canonical integrity pins and run required checks through DSR before activating production code.

The D6 and release-self-scan beads remain open. This checkpoint does not change scanner behavior or provide repository/release qualification.
