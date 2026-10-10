# Local scan service (K4)

The canonical commands are `ubs serve`, `ubs --client`, and
`ubs daemon watch|status|stop|cancel`. They reach the same optional service as
the standalone `ubs-daemon` command. The runner verifies its matching regular
daemon payload against an embedded SHA-256 pin and executes those verified
bytes with isolated Python startup. Installation and self-update carry the
matching companion; keeping parser and analysis state warm remains unfinished.

The service requires POSIX (Linux, macOS or another supported Unix). On Windows
Git Bash, MSYS and Cygwin, installed save and Git hooks use ordinary `ubs`
scans; use the ordinary scanner directly there. WSL uses the Linux service.

```bash
./ubs serve --repo /path/to/project --jobs=2
./ubs --client --repo /path/to/project src/main.py
./ubs daemon status --repo /path/to/project
./ubs daemon stop --repo /path/to/project
```

Put the service selector first. The remaining options follow the service
interface below. `ubs --client` defaults to JSON and retains one-shot fallback
when no matching daemon is running. Unsupported options produce errors rather
than silently changing the scan selection.

```bash
./ubs-daemon serve --repo /path/to/project
# In another terminal, with the same environment:
./ubs-daemon client --repo /path/to/project src/main.py src/util.py
./ubs-daemon status --repo /path/to/project
./ubs-daemon stop --repo /path/to/project
```

`client` prints the scanner's original stdout/stderr and returns its exit status.
Its default format is JSON. Text, JSONL and SARIF are also supported, together
with `--profile=strict|loose` and `--fail-on-warning`. Relative source names are
resolved against `--repo`; use `--` before names starting with a dash. Select
explicit regular files, one directory, or a Git-scoped scan as described below.
Custom-rule and baseline requests still use the normal `ubs` command.

Installers publish a regular `ubs.daemon.<SHA256>.py` companion beside the
runner before atomically replacing the runner. Self-update retains older
companions so an older process still has its own matching bytes. A failed
download, checksum, size check or publication leaves the old runner usable.
The loader prefers its exact generation, then the pinned `ubs-daemon` adjacent
to a checkout or portable bundle. Renamed runners retain their actual scanner
path. Neither the project nor PATH supplies replacement daemon code.

The release payload and checksum manifest include `ubs-daemon`.
`scripts/verify.sh` binds its digest to both the authenticated manifest and
the runner pin, then includes it in exported portable bundles. Local installs
require the matching local companion without downloading a replacement.
Host tools remain separate dependencies and no service starts automatically.
An upgrade from a runner predating the service may require running the new
installer once to provision its companion.

A missing daemon or a different invocation environment/scanner falls back to an
ordinary scan. `--require-daemon` disables that fallback. Authentication, protocol
and scanner failures are errors, never silent fallback to cached success.
Neither the client nor server starts background services automatically.

The server uses a mode-0600 Unix socket in a private mode-0700 directory under
`$XDG_RUNTIME_DIR`, falling back to `$XDG_CACHE_HOME` (or `~/.cache`). Both peers
must have the same kernel-reported uid (Linux SO_PEERCRED or BSD/macOS
getpeereid); there is no TCP listener. A per-repository lock prevents stealing a
live socket, and replacing the served root invalidates service. The server
exits after 900 idle seconds by default (`--idle-timeout`).

Eligible explicit-file reports are retained in a bounded in-memory LRU (32 MiB by default,
`--cache-mib=0` disables it). Reuse requires matching source selection, policy,
format, environment, and a fresh byte snapshot of the repository and adjacent
runtime modules. Global Git configuration and ordinary tool executable updates
also invalidate reuse. Inputs are checked before and after each scan; failures
and scans spanning edits are not cached. Cached reports retain their original
scan timestamp. Symlinks, special files, unreadable input, more than 20,000 input
entries, or over 128 MiB of snapshot input disable reuse rather than skip scans.
Runtime-directory environment overrides, redirected/linked Git metadata,
inherited parent repositories and Git external include/exclude configuration
also disable reuse. Active custom rule directories from `.ubs.json` or
`UBS_RULES` disable whole-report reuse because their rule graphs can reference
files outside the snapshot; each request still uses the scanner's native
incremental cache. Python text reports can include live dependency audits;
they are not reused unless the caller explicitly selects native-only analysis
with `ENABLE_UV_TOOLS=0`. The frontend never silently disables those tools.

Cache snapshots verify the entire input inventory again after hashing, not only
each file immediately after its read. Concurrent changes to earlier sources,
directory inventories, optional global policy files or tool executables
(including Git) invalidate reuse. Reads use nonblocking, component-wise
no-follow descriptors, so file/parent symlink substitutions and FIFO swaps do
not redirect or block snapshot reads. A failed snapshot causes an ordinary scan;
it is never a clean result. These are input observations, not filesystem freezes.

The toolchain and other external configuration that its programs load remain
trusted session inputs; restart the daemon after changing tool libraries or
external tool configuration. For installed scanners without an adjacent `modules`
directory, report reuse is disabled. Installed requests still run the ordinary
scanner with its verified module downloads and incremental cache. Portable
runtimes include the adjacent module graph for report reuse.

Misses still run the standard CLI, preserving its verified modules and existing
Merkle cache. This does not claim sub-100 ms edited-file scans: keeping parsers
and analysis state warm remains K4 work. Scanner
wall time is bounded (`--scan-timeout`, default 120 seconds); outputs are capped
at 8 MiB per stream and timeout/overflow yields an environment error, not a
truncated clean report. Requests and retained report memory are also bounded.

## Project, directory and Git-scoped scans

```bash
./ubs-daemon client --repo /path/to/project .
./ubs-daemon client --repo /path/to/project src/
./ubs-daemon client --repo /path/to/project --staged --fail-on-warning
./ubs-daemon client --repo /path/to/project --diff
```

The service forwards a directory or `--staged` / `--diff` to the ordinary
scanner; it does not construct a competing file list, copy worktree files over
index contents, or implement its own ignore/language policy. Staged scans use
the scanner's index semantics, and diff scans use its working-tree semantics.
All existing format/profile/failure-policy options, cancellation, admission
limits and missing-daemon fallback apply. A no-target result keeps exit 3.

A directory request accepts exactly one existing directory within `--repo`.
Mixed files/directories and escaping symlinks are rejected. Git requests take
no positional paths and require `--repo` to equal the Git worktree root; a
served subdirectory cannot silently expand to its parent repository. Linked
worktrees are supported. Without paths or a Git-selection flag, the client
still errors rather than accidentally scanning an entire project.

Directory and Git-scoped requests always invoke the scanner. They do not reuse
whole reports: project-level optional tools/build phases and Git object state
can depend on inputs outside the explicit-file report cache's snapshot. The
scanner's own incremental cache remains available. The frontend does not
silently disable optional analysis or builds; directory scans inherit the
ordinary scanner's tool execution, including Rust build phases when enabled.
Use the scanner's documented environment controls identically for server and
client when intentionally selecting static-only analysis.

Protocol clients opt in with `selection: "directory"` and one directory in
`paths`, or `selection: "staged"|"diff"` and `paths: []`. Omitting `selection`
retains the explicit-files-only protocol. Older servers reject these new fields
as errors; that rejection is not permission to run a fallback scanner.

## Parallel requests, backpressure and shutdown

Socket I/O and lifecycle commands run independently of scanning. `status` stays
available during scans and includes `active_scans`, `queued_scans` and
`max_scans`. `stop` cancels all active scans, rejects waiting work, and reaps
their process groups before releasing the repository lock. Cancellation errors
are never cached as scan results. The idle timeout starts again after work
completes; it does not abort active scans.

One scanner worker remains the default. Select `serve --jobs=2` (up to 8) to run
independent requests concurrently. Report-cache access is synchronized.
Identical requests wait without occupying another worker, so an unrelated scan
can proceed. Waiting is not permission to reuse a result: the waiter validates
its current files, policy and complete byte snapshot when it runs. Changes
during the first scan or uncacheable inputs cause a fresh scan, not borrowed
success. Request identifiers do not change this scheduling or cache identity.

Up to eight scan requests may be admitted at once, including active work and
replies awaiting delivery, with at most 32 client connections. Queued requests
have three seconds to start. Saturation or an expired queue wait returns exit 2
without asking the client to launch a fallback scanner. Each undelivered scan
reply reserves one worker slot; the transport can retain at most `--jobs` scan
replies, rather than accumulating more large reports behind stalled readers.
Increasing concurrency also increases the possible scanner and report memory
footprint; the existing per-stream, cache and admission limits still apply.

Frames and replies have absolute three-second I/O deadlines. Each connection
carries one length-prefixed request and response. A client may close its write
half after the complete request without losing the scan result. Disconnects
are not a portable cancellation signal; use the explicit cancellation command
below, or `stop` to cancel all service work.

Scanner output is drained through both pipes, including helper output after the
runner exits. Pipe backpressure enforces stream limits without growing temporary
files. Deadlines apply while helpers hold the pipes open, and remaining processes
in the request's process group are terminated even after a successful result.

## Cancel one obsolete scan

Give a client request a unique identifier, then cancel that request from another
terminal or agent without stopping the daemon or another request:

```bash
./ubs-daemon client --repo /path/to/project --require-daemon \
  --request-id edit-42 src/main.py
./ubs-daemon cancel --repo /path/to/project --request-id edit-42
```

Identifiers are 1–64 ASCII letters, digits, underscores or hyphens. They are
optional for ordinary clients and must be unique among outstanding requests.
Duplicate identifiers are rejected rather than replacing another scan. A
cancellation acknowledgement reports `status: "cancelling"`; the original
client subsequently receives exit 2, empty stdout and a cancellation diagnostic.
The acknowledgement is not a claim that the process group has already exited.
Queued targets are never launched. Running targets interrupt both snapshot
work and scanner supervision. Cancelling one identical waiter or its predecessor
does not cancel the other request or turn an incomplete scan into a cache hit.

Cancellation uses the same private socket, kernel uid check and exact repository
identity as scans. Unknown or completed identifiers, malformed requests and
wrong repositories are errors. Cancellation never falls back to one-shot
execution. `--require-daemon` in the example ensures the named scan is actually
managed by the service; ordinary clients still retain their existing fallback.
Unnamed requests remain supported and can be stopped with `stop`.

## Continuous feedback for files and directories

Start the daemon explicitly, then keep a foreground watcher running for the
source files being edited:

```bash
./ubs-daemon serve --repo /path/to/project
# In another terminal with the same environment:
./ubs-daemon watch --repo /path/to/project --debounce=0.3 src/main.py src/util.py
# Or rescan a directory as files are created, renamed, edited or removed:
./ubs-daemon watch --repo /path/to/project src/
```

The watcher observes the bytes and file identity of each **explicitly named
file**, plus the automatically discovered `.ubs.json` policy described below.
The default polling interval is 0.25 seconds (`--watch-interval`, minimum
0.1); a 0.3-second quiet period combines rapid saves into one scan (`--debounce`).
Atomic replacement and same-size edits with restored mtimes trigger another
generation. Missing, unreadable, oversized, non-regular or escaping files
produce an `invalid` event with exit code 2, not a clean result. Restoring the
file resumes scanning. Watched input is bounded to 256 source files, 256
additional dependency paths, 20,000 graph entries and 128 MiB of unique contents.

On every observed edit the previous report is invalidated immediately. A
superseded scan is cancelled using its own unique request id; the watcher never
stops the daemon or cancels somebody else's work. It rechecks the watched files
at completion and discards outdated results. Ctrl-C/SIGTERM cancels outstanding
watch work and exits 130. Transport timeouts also attempt cancellation. Client
I/O uses an absolute request deadline, so a trickling response cannot extend a
request indefinitely; pending transfers are locally interruptible.

Stdout is always a sequence of **JSONL event envelopes**, schema `ubs.watch/1`:
`changed`, `scanning`, `superseded`, `result`, `invalid`, or `error`. Each carries
a generation, source fingerprint and the watched paths. A `changed` event means
the preceding report is no longer current. `result` includes the scanner's
original `stdout`, `stderr`, `exit_code` and cache marker. The requested
`--format=text|json|jsonl|sarif` controls that inner scanner payload, not the
outer event stream. Profiles and fail-on-warning policy are preserved.

Watch mode requires a compatible running daemon with the same scanner and
environment. It never starts a service, falls back to a second scanner, or
silently masks service failures. Git selection and caller-assigned request ids
are rejected for watch mode; use `client` for staged/diff scans.
The save hook remains a single-edit client; watch mode runs separately.

### Recursive project observation with directory scans

With one directory target, `watch` observes the **entire served repository tree**
while passing only that selected directory to the ordinary scanner. This catches
new source files, directory renames and removals, sibling dependency edits, and
root-level ignore/configuration changes without expanding scan scope. The normal
scanner still owns file selection and ignore policy. All entries, including Git
storage, hidden files and ignored dependencies, count toward the observation's
20,000-entry/128-MiB bounds; there is no silently truncated "clean" project view.

An empty directory can return exit 3 and remains watched; adding source resumes
scanning. If the selected directory disappears, becomes a file or escapes the
root through a symlink, the observation is invalid until repaired. Missing or
unsafe nested inputs also prevent result publication. Directory requests never
reuse whole reports, preserving the existing project-tool execution policy.
Events expose `selection: "directory"`, the original scan `paths`, and `.` in
`watch_inputs`. Explicit-file events use `selection: "files"`.

The default is bounded byte/metadata polling; Linux notifications are opt-in below.
External Git metadata (for example linked-worktree administration), global
configuration and tool installations outside the served root are not observed;
restart the watcher after changing those inputs. Large repositories with vendor
or build trees should use explicit files and narrower `--watch-input` paths.

### Dependency and policy invalidation

The `.ubs.json` selected by ordinary CLI discovery is watched automatically,
including its creation, edits, removal, and a change in its location after Git
is initialized. A single resolved file uses its nearest Git worktree root, or
its parent outside Git; multiple resolved files use the served directory's Git
root, or the served directory outside Git. Duplicate names and internal aliases
do not change this selection. This one automatic input does not consume the
256 explicit dependency slots or add source files to the scan. If the policy
lies outside the served directory, watch mode reports an error directing you
to serve and watch the Git worktree root with `--repo`.

Use repeatable `--watch-input=PATH` options to watch dependency files, entire
dependency trees or policy files **without adding them to the scan targets**:

```bash
./ubs-daemon watch --repo /path/to/project \
  --watch-input=lib/ --watch-input=.ubsignore --watch-input=pyproject.toml \
  src/main.py
```

A watched dependency path may initially be absent. Its creation, removal or
recreation triggers a new generation; an absent optional policy is not a source
error. The explicitly scanned source files still must exist and remain regular
files. Dependency directories are traversed recursively, including hidden and
ignored files: the observer does not replace the scanner's selection policy.
Renames, added directories and same-size edits with restored mtimes are detected.
Use `--watch-input=.` to observe the whole repository while scanning a fixed file
set, subject to the same aggregate limits. Large vendor trees may exceed them;
narrow the watched inputs instead of silently dropping part of the graph.

Internal symlinks are observed as a finite graph; their contents are read once
per canonical path. Escaping/broken links, special files, read errors or exceeded
limits invalidate the observation and suspend scans until repaired. Opens are
anchored to a repository file descriptor with no-follow checks at each component,
and a final metadata pass detects edits to earlier files during enumeration.
Every event includes `watch_inputs` separately from the unchanged scan `paths`.
Dependency-only edits also cancel obsolete requests. A restored exact snapshot
may reuse a valid report, but it is emitted under the new observation generation.

This is not a warmed analysis engine. Beyond the automatic `.ubs.json` input,
unnamed dependencies, other configuration, ignore files and tools do **not**
trigger a new generation in explicit-file polling mode. Name in-repository
inputs explicitly, or request a fresh scan after changing external inputs.
Keep generated reports, cache directories and service sockets outside watched
trees to avoid self-triggered rescans or special-file errors. The underlying
scanner still owns dependency analysis and cache validation on every request.
The source fingerprint is an observation marker, not a certificate that the
entire repository or external tool environment is unchanged. No edited-file
latency improvement is claimed.

### Linux filesystem notifications

```bash
./ubs-daemon watch --repo /path/to/project --watch-backend=inotify \
  --watch-reconcile=5 src/
```

`--watch-backend=poll` remains the default. `inotify` selects Linux kernel
notifications and fails explicitly if the API, procfs descriptor access or watch
quota is unavailable. `auto` attempts the same backend and falls back to byte
polling on backend failure; it does not launch a fallback scanner. The event
envelope's `observer` object reports the active `backend`, fallback `reason`,
`reconcile_seconds`, `byte_passes`, `event_batches` and `resyncs`.

Notifications wake the observer without re-reading unchanged source on every
idle tick. Directory marks discover additions and moves; file-inode marks also
cover writes through hard links. Lexical-parent marks cover symlink replacement.
Every byte observation rebuilds the subscription graph, including moved-in
subdirectories. Overflow, lost watches or a saturated event drain force a fresh
observation rather than being interpreted as an unchanged tree. Backend resources
are bounded and released on rebuild or shutdown. Conservative parent notifications
can cause extra unchanged-source rescans, but never broaden the scan target list.

A quiet notification stream is **not** proof that bytes are unchanged. Inotify
does not cover all remote-filesystem or memory-mapped writes, and mount changes
can hide watched inodes (see `inotify(7)`, Limitations and caveats). The observer
therefore retains periodic full byte reconciliation, default five seconds of
idle time (`--watch-reconcile`, 0.1 to 60 seconds). Event-invisible edits may wait
until that reconciliation; select polling for workloads requiring its shorter
configured observation interval. Every scan dispatch and result publication
still forces a full byte check, regardless of notification silence. Changes
during subscription setup invalidate the observation. Existing source limits,
confinement, debounce, cancellation and failure policy remain in force.

Validation:

```bash
UBS_DAEMON_E2E=1 python3 -m unittest discover \
  -s test-suite/quality -p 'test_daemon*.py' -v
```

Protocol tests use an explicitly identified scanner double; the opt-in integration
case invokes the actual scanner and compares its findings across cold, warm,
one-shot and edited-source requests. Linux is exercised locally; the BSD/macOS
credential path and Windows's unsupported-platform diagnostic need platform CI.

## Save-hook integration

The checkout's `.claude/hooks/on-file-write.sh` uses the verified `ubs --client`
when the selected runner carries a daemon pin. It does not execute a separate
PATH frontend in that case. Runners without a pin retain the existing optional
standalone client and one-shot route. Start the service with the same environment
as the agent. It resolves the
served root from `CLAUDE_PROJECT_DIR`, otherwise from the edited file's Git root,
otherwise from the file's parent directory. Paths outside an explicit project
root are refused rather than silently scanned under a different context.

The hook requests text reports for explicit files, including Bash sources. It
keeps clean/no-target edits silent, surfaces findings as blocking feedback, and
reports scanner or service failures separately as **not verified**. It does not
automatically start a daemon, change your hook registrations, or redirect Git
staged scans to worktree contents. An absent or context-mismatched daemon uses
one-shot scanning; a missing pinned payload or service/authentication error is
reported as a failure.

The checkout and installer embed the same save hook. A runner carrying a daemon pin
uses `ubs --client` without a standalone frontend on PATH. Re-run the installer
to update an existing project's hook. Neither route starts a daemon automatically.

The generated Git pre-commit hook also uses the canonical client when the
runner has a pin. It preserves its full-project `--fail-on-warning` gate and
propagates the scanner's failure through its output pipeline. It does not replace
that gate with changed-file or staged-only selection. Installer-written agent
quick references include canonical client and explicit service-start commands.

The real native save-hook integration test explicitly sets `ENABLE_UV_TOOLS=0`
for both peers to avoid online package auditing. Separate tests retain the
external-audit no-reuse rule and failure feedback. The read-only Local Scan
Service workflow exercises active source, real scanner parity and checksum
verification; it never applies a candidate patch or modifies refs.
