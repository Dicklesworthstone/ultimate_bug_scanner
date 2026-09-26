# Local scan service (K4)

The checkout now provides `ubs-daemon serve` and `ubs-daemon client`. This is a
standalone optional frontend to the real scanner, not a replacement detector
engine. `ubs serve` / `ubs --client`, automatic installation and in-process
analysis are not implemented yet.

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
resolved against `--repo`; use `--` before names starting with a dash. Only
explicit regular files inside the repository are accepted. Directory, staged,
diff, custom-rule and baseline requests still use the normal `ubs` command.

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

Reports are retained in a bounded in-memory LRU (32 MiB by default,
`--cache-mib=0` disables it). Reuse requires matching source selection, policy,
format, environment, and a fresh byte snapshot of the repository and adjacent
runtime modules. Global Git configuration and ordinary tool executable updates
also invalidate reuse. Inputs are checked before and after each scan; failures
and scans spanning edits are not cached. Cached reports retain their original
scan timestamp. Symlinks, special files, unreadable input, more than 20,000 input
entries, or over 128 MiB of snapshot input disable reuse rather than skip scans.
Runtime-directory environment overrides, redirected/linked Git metadata,
inherited parent repositories and Git external include/exclude configuration
also disable reuse. Python text reports can include live dependency audits;
they are not reused unless the caller explicitly selects native-only analysis
with `ENABLE_UV_TOOLS=0`. The frontend never silently disables those tools.

The toolchain and other external configuration that its programs load remain
trusted session inputs; restart the daemon after changing tool libraries or
external tool configuration. For installed scanners without an adjacent `modules`
directory, report reuse is disabled. Run this frontend from a trusted checkout;
it is not included in exported portable runtimes or installed by `install.sh`.

Misses still run the standard CLI, preserving its verified modules and existing
Merkle cache. This does not claim sub-100 ms edited-file scans: keeping parsers
and analysis state warm and adding filesystem watchers remain K4 work. Scanner
wall time is bounded (`--scan-timeout`, default 120 seconds); outputs are capped
at 8 MiB per stream and timeout/overflow yields an environment error, not a
truncated clean report. Requests and retained report memory are also bounded.

Validation:

```bash
UBS_DAEMON_E2E=1 python3 -m unittest discover \
  -s test-suite/quality -p test_daemon.py -v
```

Protocol tests use an explicitly identified scanner double; the opt-in integration
case invokes the actual scanner and compares its findings across cold, warm,
one-shot and edited-source requests. Linux is exercised locally; the BSD/macOS
credential path and Windows's unsupported-platform diagnostic need platform CI.

## Save-hook integration

The checkout's `.claude/hooks/on-file-write.sh` uses `ubs-daemon` when that trusted
executable is on PATH, passing the same `ubs` executable selected for one-shot
scans. Start the service with the same environment as the agent. It resolves the
served root from `CLAUDE_PROJECT_DIR`, otherwise from the edited file's Git root,
otherwise from the file's parent directory. Paths outside an explicit project
root are refused rather than silently scanned under a different context.

The hook requests text reports for explicit files, including Bash sources. It
keeps clean/no-target edits silent, surfaces findings as blocking feedback, and
reports scanner or service failures separately as **not verified**. It does not
automatically start a daemon, change your hook registrations, or redirect Git
staged scans to worktree contents. A missing frontend or absent/context-mismatched
daemon still uses one-shot scanning; service/authentication errors are visible.

This integration is in the checkout hook. The standalone installer still embeds
its original one-shot hook template, so existing installed hooks do not acquire
daemon support automatically. Automatic distribution and installation of the
frontend and updated template remain part of K4.

The real native save-hook integration test explicitly sets `ENABLE_UV_TOOLS=0`
for both peers to avoid online package auditing. Separate tests retain the
external-audit no-reuse rule and failure feedback. The read-only Local Scan
Service workflow exercises active source, real scanner parity and checksum
verification; it never applies a candidate patch or modifies refs.
