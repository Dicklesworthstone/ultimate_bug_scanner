# Pull diagnostics for editors

`ubs-lsp` supports LSP 3.17 `textDocument/diagnostic` in addition to its legacy
push-diagnostics interface. Launch the same checkout-only adapter described in
[editor.md](editor.md); no new server, detector, dependency or background service
is required.

## Negotiation and requests

A client opts in by advertising an object at `capabilities.textDocument.diagnostic`
during `initialize`. The server then advertises diagnostic provider `ubs`, with
inter-file dependencies and without workspace-wide pull support. In this mode it
answers pull requests instead of duplicating them through
`textDocument/publishDiagnostics`. Clients that do not advertise pull support
retain the existing push behavior.

Open and synchronize the document first. The request parameters are:

```json
{
  "textDocument": {"uri": "file:///path/to/project/src/main.py"},
  "identifier": "ubs",
  "previousResultId": "opaque-id-from-the-previous-response"
}
```

`identifier` and `previousResultId` are optional. A first or changed result is a
`full` report with `items` and an opaque `resultId`; a matching subsequent result
is `unchanged` with its `resultId` and no repeated diagnostic array. Result ids
are scoped to the server session, document URI, editor version/content and the
complete displayed diagnostics.

**Unchanged does not mean that analysis was skipped.** A pull joins an already
pending/current scan or starts a fresh ordinary scan. Completed results are not
reused as proof that disk, dependency or policy inputs are unchanged. The
existing saved-source checks, isolated buffer modes, source confinement,
scanner timeout, report validation and incomplete-display diagnostics still
apply. An unsaved document in saved mode, a scanner failure, or an unsupported
file is not reported as verified clean.

Only currently open documents under the configured `--repo` are accepted. A
pull cannot broaden the workspace, select an arbitrary closed file, change the
scanner policy, or substitute its own source bytes. The existing
`ubs.scanOpenDocuments` command remains available for grouped analysis.

## Cancellation, invalidation and refresh

`$/cancelRequest` detaches one diagnostic subscriber and returns
`RequestCancelled` (`-32800`). It does not terminate shared work another request
still needs. Edits, synchronization failures and dependency notifications
invalidate obsolete requests with `ServerCancelled` (`-32802`) and
`retriggerRequest: true`. Closing a document or shutting down finishes its
outstanding requests without requesting a retry.

There are at most 64 outstanding diagnostic requests. Each has an absolute
deadline of the configured scan timeout plus one second, including queue time.
Admission and deadline failures return explicit errors with automatic retrigger
disabled, not empty successful reports. Request string ids and previous result
ids are limited to 256 characters.

Clients advertising `capabilities.workspace.diagnostics.refreshSupport: true`
receive coalesced `workspace/diagnostic/refresh` requests after input/lifecycle
changes. Refresh requests start only after `initialized`; there is at most one
unacknowledged refresh at a time. A rejected refresh or a ten-second missing
acknowledgement disables refresh requests and logs a warning for that session.
Pull requests and their completion never trigger refresh themselves, avoiding a
refresh/scan feedback loop. Without refresh support, configure the client to
pull after saves and dependency changes, or invoke a fresh diagnostic pull.

## Verification

```bash
python3 -m unittest discover -s test-suite/quality -p test_lsp_pull.py -v
```

The regression suite exercises the actual adapter and its stdio framing with
explicit scanner protocol doubles. It covers protocol behavior, not the UBS
language detectors or the full scanner manifest suite.
