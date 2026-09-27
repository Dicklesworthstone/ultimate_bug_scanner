# Editor diagnostics over LSP

`ubs-lsp` is an optional, stdlib-only POSIX stdio adapter for editors that can
launch a Language Server Protocol server. It runs the ordinary UBS scanner on
saved files and publishes its merged findings as editor diagnostics. It does
not import project code, write editor buffers into the checkout, implement a
second detector engine, or provide warmed in-process analysis.

From a trusted checkout, configure the editor's generic LSP client to launch:

```bash
python3 -I /trusted/ultimate_bug_scanner/ubs-lsp --repo /absolute/project
```

Python 3.10 or newer is required. The adjacent executable `ubs` is used by
default; `--scanner=/absolute/path/to/ubs` selects an explicit trusted runner.
`--profile=strict|loose` and `--fail-on-warning` select the launch-time scanner
policy. That policy applies identically to individual and grouped scans; editor
requests cannot supply arbitrary scanner flags or commands.
The editor's `rootUri`, when supplied, must match `--repo`. Documents outside
that root, nonlocal URIs, and symlinked files or path components are refused.
There is no automatic installation, editor registration, daemon startup, or
PATH search for a replacement scanner. This executable is currently available
from the checkout, not included in installed or signed portable releases.

## Saved-source contract

The adapter advertises full document synchronization and processes `didOpen`,
`didChange`, `didSave` and `didClose`. A saved document is scanned on open and
save. Changes cancel obsolete work and immediately replace previous findings
with an informational **save to verify** diagnostic. An unsaved buffer is never
scanned as though it were the disk version. UTF-8 BOM and newline normalization
are permitted for editor/disk comparison; source bytes are never rewritten.

Source bytes and file identity are checked before scanning, after scanning,
and immediately before publication. Diagnostics carry the editor's document
version. Closing or reopening a document invalidates old results, even when
the editor restarts version numbering. Invalid synchronization messages suspend
verification until a valid full-text change restores synchronization.

Clean diagnostics are published only after a successful, well-formed scan.
Timeouts, malformed output, partial reports, unsupported/no-target files and
source races appear as explicit unverified diagnostics. The scanner's stderr
never contaminates the LSP stream. Shutdown cancels request process groups,
including helpers holding output pipes; no scanner is left running intentionally.

## Cross-file context and dependency changes

The advertised LSP command **`ubs.scanOpenDocuments`** queues one ordinary UBS
invocation containing all currently open documents. Invoke it through the
editor's LSP command interface (`workspace/executeCommand`, no arguments), not
as a shell command. Its immediate `queued` response acknowledges scheduling,
not successful verification. Diagnostics arrive through the usual publication
notifications, routed back to the correct source document.

Grouping lets the scanner use its selected-file cross-module analysis. It does
not discover unopened source files, invent import resolution, or widen the
workspace root. All group members must be synchronized and saved. One unsaved
or invalid member suspends the whole group rather than allowing dependents to
look clean using different disk bytes. Ignored or unsupported members that make
the scanner's file coverage differ from the selected set produce an explicit
unverified result, not a clean diagnostic list for the omitted file.

Changes or closes to any member cancel the entire pending/running group and
invalidate its published peers. This relationship is retained after a group
completes, so editing a dependency also invalidates already-published clean
results. Source identities for the complete group are checked before publishing
any member. Ordinary open/save still supports individual-file scans; use the
group command again to renew cross-file verification after saving all members.

The adapter handles `workspace/didChangeWatchedFiles` events for files inside
the configured repository. Creation, change and deletion notifications queue a
group rescan of open documents, with bursts coalesced before scanner startup.
For editors advertising dynamic watch registration and relative-pattern support,
the server requests a `**/*` watch rooted explicitly at `--repo`. Rejected
registration is reported through `window/logMessage`; the manual group command
remains available. No extra filesystem watcher process is started.

This depends on the editor delivering file-change events. Global configuration,
external Git metadata and tool installations outside the configured root are
not watched. Full-document synchronization is required; incremental range-only
updates are rejected rather than applied approximately.

## Findings and positions

The adapter reads both `findings` and the optional report-only `ast_findings`
channel. Suppressed findings are omitted. Critical, warning and info severities
map to LSP Error, Warning and Information; rule IDs become diagnostic codes.
Project-level findings are visibly labelled rather than given invented source
locations. In a grouped scan, another selected document's findings are routed to
that document. Findings outside the selected documents or the display limit
produce a summary notice rather than silently disappearing as a clean result.
Reported severity counts must be covered by the counted findings ledger;
advisory AST evidence cannot excuse a missing counted finding.

Ranges intentionally cover the complete reported source line. UBS producers do
not establish a uniform column unit across all languages, so the adapter does
not guess whether a column is bytes or code points. Line ranges use UTF-16 code
units, as negotiated in the LSP initialization response. It provides diagnostics
only: no completion, navigation, unsaved-buffer analysis, or automatic fixes.

## Bounds and validation

The default concurrency is two scanners (`--jobs=1..4`); scans are bounded by
`--scan-timeout` (default 120 seconds). The server retains at most 64 open
documents, 2 MiB per source and 16 MiB of synchronized text. Scanner streams are
bounded to 8 MiB each. LSP headers, message bodies and queued outbound bytes are
also bounded; a stalled consumer cannot accumulate unlimited reports.
Per-document diagnostics also have a byte budget, including Unicode message
expansion; exceeding the display budget retains an explicit omission notice.

```bash
python3 -m unittest discover -s test-suite/quality -p 'test_lsp*.py' -v
UBS_LSP_E2E=1 python3 -m unittest discover -s test-suite/quality -p 'test_lsp*.py' -v
```

The ordinary suite uses a labelled scanner protocol double with real subprocess
and stdio communication. The opt-in integration cases invoke actual UBS and
check `python.taint.eval` detection followed by a saved clean edit, plus a
cross-file caller/helper sink through a grouped scan. The read-only Editor
Diagnostics workflow enables those cases with the full scanner toolchain.
A successful protocol-double test is not evidence of scanner/toolchain parity.

The protocol subset follows Microsoft's LSP 3.17 document synchronization,
lifecycle and `textDocument/publishDiagnostics` definitions. Client process
startup/shutdown is explicit and owned by the editor.
