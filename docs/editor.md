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

## Findings and positions

The adapter reads both `findings` and the optional report-only `ast_findings`
channel. Suppressed findings are omitted. Critical, warning and info severities
map to LSP Error, Warning and Information; rule IDs become diagnostic codes.
Project-level findings are visibly labelled rather than given invented source
locations. Findings outside the document or the display limit produce a summary
notice rather than silently disappearing as a clean result.

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

```bash
python3 -m unittest discover -s test-suite/quality -p test_lsp.py -v
UBS_LSP_E2E=1 python3 -m unittest discover -s test-suite/quality -p test_lsp.py -v
```

The ordinary suite uses a labelled scanner protocol double with real subprocess
and stdio communication. The opt-in integration case invokes actual UBS and
checks `python.taint.eval` detection followed by a saved clean edit. The read-only
Editor Diagnostics workflow enables that case with the full scanner toolchain.
A successful protocol-double test is not evidence of scanner/toolchain parity.

The protocol subset follows Microsoft's LSP 3.17 document synchronization,
lifecycle and `textDocument/publishDiagnostics` definitions. Client process
startup/shutdown is explicit and owned by the editor.
