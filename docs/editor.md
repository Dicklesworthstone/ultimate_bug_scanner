# Editor diagnostics over LSP

`ubs-lsp` is an optional, stdlib-only POSIX stdio adapter for editors that can
launch a Language Server Protocol server. It runs the ordinary UBS scanner and
publishes its merged findings as editor diagnostics. Saved-source analysis is
the default; an explicit snapshot mode also analyzes unsaved editor buffers.
The adapter does not import project code or implement a second detector engine.

From a trusted checkout, configure the editor's generic LSP client to launch:

```bash
python3 -I /trusted/ultimate_bug_scanner/ubs-lsp --repo /absolute/project
```

Python 3.10 or newer is required. The adjacent executable `ubs` is used by
default; `--scanner=/absolute/path/to/ubs` selects an explicit trusted runner.
`--profile=strict|loose` and `--fail-on-warning` select the launch-time scanner
policy. That policy applies to individual, grouped and buffer-snapshot scans;
editor requests cannot supply arbitrary scanner flags or commands.
The editor's `rootUri`, when supplied, must match `--repo`. Documents outside
that root, nonlocal URIs, and symlinked files or path components are refused.
There is no automatic installation, editor registration, daemon startup, or
PATH search for a replacement scanner. This executable is currently available
from the checkout, not included in installed or signed portable releases.

## Incremental document synchronization

The adapter advertises UTF-16 incremental synchronization and processes
`didOpen`, `didChange`, `didSave` and `didClose`. Full-text replacements remain
supported. Ranged edits are applied in the order received, each against the
result of the preceding edit. Original BOM and CR/LF/CRLF text is retained for
coordinate mapping; normalized text is used only for editor/disk comparison.
An edit may not split a UTF-16 surrogate pair. Characters beyond a line's end
are clamped to that end, without entering its newline sequence.

An invalid change batch is rejected atomically and cancels outstanding work.
Verification remains suspended until a newer full-text replacement restores
synchronization. A rejected higher version advances the version high-water
mark, so an older replacement cannot revive stale content. Closing and reopening
a document resets that document's version sequence but not its generation.
The adapter bounds edit count, intermediate text sizes and edit-processing work;
clients can send one full replacement when a large batch exceeds those limits.

## Default: saved-source analysis

With the default `--buffer-mode=saved`, a saved document is scanned on open and save.
Changes cancel obsolete work and immediately replace previous findings with an
informational **save to verify** diagnostic. Unsaved text is not written into
the checkout or presented as a scan of disk contents. UTF-8 BOM and newline
normalization are permitted for editor/disk comparison; source bytes are not
rewritten.

Source bytes and file identity are checked before scanning, after scanning,
and immediately before publication. Diagnostics carry the editor's document
version. Clean diagnostics are published only after a successful, well-formed
scan. Timeouts, malformed output, partial reports, unsupported/no-target files
and source races appear as explicit unverified diagnostics. The scanner's
stderr never contaminates the LSP stream. Shutdown cancels request process
groups, including helpers holding output pipes.

## Opt in: unsaved-buffer snapshots

To analyze edits before saving, explicitly launch snapshot mode:

```bash
python3 -I /trusted/ultimate_bug_scanner/ubs-lsp \
  --repo /absolute/project --buffer-mode=snapshot --profile=strict
```

Open, change and save events coalesce into a grouped scan of **all open,
synchronized documents**, using the latest editor text. Newly created unsaved
files with local `file:` URIs inside the configured repository are supported,
including files whose parent directories do not yet exist. `untitled:` scratch
buffers and documents outside the root are not supported. Any unsynchronized
member blocks the group; partial synchronization is not treated as clean input.

For each scan, the adapter creates an owner-only temporary workspace outside
`--repo`, copies the complete repository context, and substitutes exact buffer
text at the corresponding relative paths. Copied support files do not become
extra scan targets: the normal scanner still receives only the selected open
documents, together in one invocation. This preserves relative import context
and lets the scanner apply its own language selection, ignore and analysis
policy. The adapter uses real copies, never hard links back to the checkout.
It does not modify original files, create new buffer paths in the checkout,
or save buffers through the editor.

Diagnostics are routed back to the original document URIs and versions, not
temporary paths. Each diagnostic includes `data.ubsSourceMode: "buffer"`; the
initialization response also reports `capabilities.experimental.ubs.sourceMode`
as `buffer` or `saved`, so an empty diagnostic list can be interpreted in the
correct mode. A buffer result describes the selected editor versions against
the copied context, **not** the current saved versions of those documents.

A new edit cancels the obsolete group, invalidates peer results and queues the
latest versions. Closing a document rechecks the remaining open buffers with
the closed file's disk contents as support context. The original repository's
file and directory metadata is checked after copying, after scanning, and again
before any grouped diagnostics are published. External edits, atomic saves,
new files appearing during a scan, and changed context invalidate the result.
Ordinary completion, cancellation, timeout and error paths remove the temporary
workspace. A hard-killed process or system crash can leave temporary files.

### Snapshot boundaries

This is an **input snapshot, not an execution sandbox**. The trusted scanner and
its tools retain their ordinary behavior. The adapter does not guarantee that
external tools cannot execute project code or access paths outside the copy.
Changing the working root can affect absolute-path-dependent configuration;
global configuration, remote advisory data and tool installations are not
copied or certified by this snapshot.

The complete copied tree, including hidden files, ignored files and Git object
storage, is limited to 20,000 entries and 128 MiB. Substituted buffer bytes and
new parent directories also count toward those limits. Copying, scanning and
validation share the scan deadline. There is no silent truncation or fallback
to disk analysis when snapshot creation fails.

All symlinks and special files in the copied tree are refused. Linked worktrees,
Git alternate/object-directory redirections, `GIT_*` environment overrides,
and path-dependent repository Git configuration are rejected conservatively.
A served subdirectory that inherits a parent Git repository is not accepted in
snapshot mode. Ordinary self-contained Git roots are supported. Keep the
system temporary directory outside `--repo`; an in-repository temporary base
is rejected before creating snapshot files. These restrictions may make saved
mode more suitable for large or symlink-heavy projects.

Snapshot mode is not warmed in-process analysis and makes no latency claim.
It copies context again for each accepted scan. Only open documents are targets;
this does not discover every project source or prove whole-project correctness.

### Reuse unchanged context between buffer edits

Select `--buffer-mode=incremental` to retain one private workspace between
successful buffer scans. It has the same selected-buffer, policy and isolation
boundaries as `snapshot`, but unchanged support files keep their private inodes
and paths. Only changed buffers and changed regular support files are rewritten. The ordinary scanner is
still invoked on every accepted scan; this is not a cache of clean reports or
a warmed in-process analysis engine.

```bash
python3 -I /trusted/ultimate_bug_scanner/ubs-lsp \
  --repo /absolute/project --buffer-mode=incremental --profile=strict
```

The first copy is byte-checked before retention. Every lease validates the
complete original and private metadata inventories, including inode and change
time, then checks them again after scanning and before diagnostic publication.
Each generation retains its own validation records. Saved edits and atomic
replacements of existing regular files are refreshed incrementally after a
complete bounded inventory check. Unsaved editor text remains authoritative for
selected buffers even when an autosave updates their disk versions. Changed
support files are streamed into authenticated private counterparts; other files
are not recopied. Original and overlaid workspace sizes are both bounded.

Added, removed or retyped paths, or changes to the selected document set, cause
a fresh complete snapshot. Unknown or unsafe input is not silently omitted.
Restoring only modification times does not preserve eligibility. Changes during
enumeration or copying reject the entire partial refresh before a scanner can
use it. Updated Git configuration is subject to the original redirection checks.

Private-tree mutation by a scanner, cancellation, timeout or scanner failure
discards the retained workspace. A later request must rebuild it from original
context. Only one scanner may lease the workspace, and shutdown joins scanner
work before removing it. Unlike one-shot `snapshot`, this opt-in mode retains
private source copies between scans, until disposal, last-document close or
shutdown. Cleanup waits for an active scanner to be reaped before removing its
workspace, and reopening documents after an idle cleanup is supported. All existing
128-MiB/20,000-entry bounds and the no-hard-link/no-symlink checks still apply.
Tools that write into the copied project may therefore need one-shot mode.

The initialization response exposes `experimental.ubs.workspaceStrategy` as
`original`, `snapshot` or `incremental`. Stable private paths allow the normal
scanner to apply its existing cache policy, but no end-to-end latency or cache-hit
guarantee is implied. External configurations and tools remain trusted session
inputs, not part of a certified project snapshot.

## Grouped saved scans and dependency changes

The advertised LSP command **`ubs.scanOpenDocuments`** queues one ordinary UBS
invocation containing all currently open documents. Invoke it through the
editor's LSP command interface (`workspace/executeCommand`, no arguments), not
as a shell command. Its immediate `queued` response acknowledges scheduling,
not successful verification. Diagnostics arrive through the usual publication
notifications, routed back to the correct source document.

In saved mode, all group members must be synchronized and saved. One unsaved
or invalid member suspends the whole group. Changes or closes to any member
cancel pending/running work and invalidate its published peers, including
already-published clean results. Ordinary saved-mode open/save still supports
individual-file scans; use the group command again to renew cross-file
verification after saving all members. In snapshot mode, the command refreshes
the current buffer group without requiring a save.

The adapter handles `workspace/didChangeWatchedFiles` events for files inside
the configured repository. Creation, change and deletion notifications queue a
group rescan of open documents, with bursts coalesced before scanner startup.
For editors advertising dynamic watch registration and relative-pattern support,
the server requests a `**/*` watch rooted explicitly at `--repo`. Rejected
registration is reported through `window/logMessage`; the manual group command
remains available. No extra filesystem watcher process is started.

This depends on the editor delivering file-change events. Global configuration,
external Git metadata and tool installations outside the configured root are
not watched. Snapshot validation rejects changed context while a scan is in
flight; it is not a replacement for notifications after publication.

## Findings and positions

The adapter reads both `findings` and the optional report-only `ast_findings`
channel. Suppressed findings are omitted. Critical, warning and info severities
map to LSP Error, Warning and Information; rule IDs become diagnostic codes.
Project-level findings are visibly labelled rather than given invented source
locations. In a grouped scan, another selected document's findings are routed
to that document. Findings outside the selected documents or the display limit
produce a summary notice rather than silently disappearing as a clean result.
Reported severity counts must be covered by the counted findings ledger;
advisory AST evidence cannot excuse a missing counted finding. Ignored or
unsupported members that make file coverage differ from the selected set are
unverified, not clean.

Ranges cover the complete reported source line. UBS producers do not establish
a uniform column unit across languages, so the adapter does not guess whether
a column is bytes or code points. Line ranges use UTF-16 code units, including
astral characters and a retained first-line BOM. This adapter provides no
completion, navigation or automatic fixes.

## Bounds and validation

The default concurrency is two scanners (`--jobs=1..4`); scans are bounded by
`--scan-timeout` (default 120 seconds). Grouped buffer mode permits one snapshot
scan at a time. The server retains at most 64 open documents, 2 MiB of UTF-8
text per source and 16 MiB of synchronized wire text, plus its normalized
comparison representation. Scanner streams are bounded to 8 MiB each. LSP
headers, message bodies and queued outbound bytes are also bounded.
Per-document diagnostics have a byte budget, including Unicode expansion;
exceeding the display budget retains an explicit omission notice.

```bash
python3 -m unittest discover -s test-suite/quality -p 'test_lsp*.py' -v
UBS_LSP_E2E=1 python3 -m unittest discover -s test-suite/quality -p 'test_lsp*.py' -v
```

The ordinary suite uses labelled scanner protocol doubles with real subprocess,
filesystem and stdio communication. It covers UTF-16 edits, error recovery,
unsaved files, grouped buffers, context races, cleanup and checkout preservation.
The opt-in integration cases invoke actual UBS for saved and unsaved
`python.taint.eval` findings and cross-file caller/helper analysis. The read-only
Editor Diagnostics workflow enables those cases with the full scanner toolchain.
A successful protocol-double test is not evidence of scanner/toolchain parity
or compatibility with every GUI editor.

The protocol subset follows Microsoft's LSP 3.17 document synchronization,
lifecycle and `textDocument/publishDiagnostics` definitions. Client process
startup/shutdown is explicit and owned by the editor.
