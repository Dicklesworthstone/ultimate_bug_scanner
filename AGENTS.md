# AGENTS.md — ultimate_bug_scanner

> Guidelines for AI coding agents working in this Bash/Shell codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`.** A `master` branch exists on the remote purely as a legacy-URL mirror; nothing in the code, docs, workflows, or install URLs may reference it (the one sanctioned mention is this section).

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere else, it's a bug that needs fixing (update it to `main`)
- **Mirror maintenance is the maintainer's job, not an agent's:** the maintainer keeps the legacy mirror in sync after pushing to `main` (`git push origin main:master`); agents do not push to it

---

## Toolchain: Bash & Shell

UBS is a **pure Bash project** — the meta-runner (`ubs`) and all language modules (`modules/ubs-*.sh`) are Bash scripts. Helper assets use Python and Go/JS for AST-level analysis.

- **Shell dialect:** Bash 5+ with `set -Eeuo pipefail`
- **Package management:** Nix flake (`flake.nix`) for reproducible dev shells and packaging; `pyproject.toml` (uv-managed, Python 3.14) for helper tooling only
- **Core runtime dependencies:** `bash`, `jq`, `ripgrep`, `git`, `curl`, `python3`
- **Version:** Tracked in `VERSION` (and mirrored in `UBS_VERSION` inside `ubs` and the README badge); `scripts/check-version-tag-drift.sh` fails CI when `main`'s module checksums no longer match the last `v*` tag, so every module change needs a version bump + tag before or with it
- **Unsafe code:** N/A (shell scripts)

### Key Dependencies

| Tool / Library | Purpose |
|----------------|---------|
| `bash` | Meta-runner and all language module scripts |
| `ripgrep` (`rg`) | Fast file scanning within language modules |
| `jq` | JSON/SARIF output merging in the meta-runner |
| `python3` | AST helpers (resource lifecycle, type narrowing), ignore-file parsing, checksum updates |
| `curl` | Lazy module download from GitHub |
| `shellcheck` | Linting for shell scripts (dev shell) |
| `cmake` | Build dependency for certain test fixtures |
| `minisign` / `cosign` | Release artifact and OCI image signing |

### Nix Packaging

The project provides a Nix flake with:
- **`packages.default`** — installs `ubs` to `$out/bin/ubs`
- **`devShells.default`** — `bashInteractive`, `shellcheck`, `git`, `cmake`, `python3`, `jq`, `ripgrep`, `uv`
- **`nixosModules.ubs`** — NixOS module with `programs.ubs.enable`
- **Docker** — `Dockerfile` based on `debian:bookworm-slim`

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `ubs-pythonV2.sh`
- `ubs-python_improved.sh`
- `ubs-python_enhanced.sh`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Quality Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Lint all shell scripts with ShellCheck
shellcheck ubs modules/ubs-*.sh scripts/*.sh

# Verify module checksums are current
./scripts/update_checksums.sh

# Run the test suite
cd test-suite && ./run_all.sh

# Verify SHA256SUMS
./scripts/verify_sha256sums.sh
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

The test suite lives in `test-suite/` and is organized by language. Each language has `buggy/` (known-bad) and `clean/` (known-good) fixtures to validate detection accuracy and false-positive rates.

Tests must not write into the checkout: the only places a test may create files are `test-suite/artifacts/` (and `test-suite/goldens/` when regenerating). `test-suite/run_all.sh` compares the untracked-file set before and after every step and names the step that left files behind; in CI (or with `UBS_TEST_HYGIENE=strict`) that fails the run, locally it warns because other agents create files in the checkout concurrently. Use a scratch cwd (tempfile) for any check that runs `ubs` with report flags.

### Running Tests

```bash
# Run all test suites
cd test-suite && ./run_all.sh

# Run via manifest (structured, tracks expected results)
python3 test-suite/run_manifest.py

# Run a specific language module directly
modules/ubs-rust.sh test-suite/rust/buggy/
modules/ubs-python.sh test-suite/python/buggy/

# Run the meta-runner on the whole project
./ubs .

# CI mode (stable timestamps, strict)
./ubs . --ci --fail-on-warning
```

### Test Categories

| Directory | Focus Areas |
|-----------|-------------|
| `test-suite/buggy/` | Multi-language intentionally buggy files for cross-language scanning |
| `test-suite/clean/` | Clean files that must produce zero findings (false-positive regression) |
| `test-suite/rust/` | Rust-specific test cases (`buggy/`, `clean/`, `async_errors/`) |
| `test-suite/python/` | Python-specific test cases |
| `test-suite/js/` | JavaScript/TypeScript test cases |
| `test-suite/cpp/` | C/C++ test cases |
| `test-suite/golang/` | Go test cases |
| `test-suite/java/` | Java test cases |
| `test-suite/ruby/` | Ruby test cases |
| `test-suite/swift/` | Swift test cases |
| `test-suite/csharp/` | C#/.NET test cases |
| `test-suite/kotlin/` | Kotlin test cases |
| `test-suite/edge-cases/` | Tricky edge cases across languages |
| `test-suite/frameworks/` | Framework-specific patterns |
| `test-suite/realistic/` | Real-world-style code samples |
| `test-suite/shareable/` | Shareable test utilities |
| `test-suite/artifacts/` | Generated test artifacts (gitignored) |

### Test Fixtures

The `test-suite/manifest.json` tracks expected outcomes per file so `run_manifest.py` can detect regressions automatically.

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## ultimate_bug_scanner — This Project

**This is the project you're working on.** The Ultimate Bug Scanner (`ubs`) is a multi-language static analysis meta-runner that dispatches language-specific scanning modules concurrently, merges their outputs, and reports findings in text, JSON, JSONL, SARIF, or TOON format. It covers 10 languages: JavaScript/TypeScript, Python, C/C++, Rust, Go, Java (plus Kotlin via the Java module), Ruby, Swift, C#, and Elixir. UBS cannot yet scan Bash, the language it is written in (bead `ultimate_bug_scanner-7mga.1`).

### What It Does

Detects real bugs and security issues using fast regex/heuristic-based analysis modules, each tailored to language-specific bug patterns. Runs in under a second on targeted files and supports CI integration with `--fail-on-warning` mode.

### Architecture

```
Invocation → Parse CLI args → Detect languages → ┬─ ubs-js.sh      (JS/TS)
                                                  ├─ ubs-python.sh  (Python)
                                                  ├─ ubs-cpp.sh     (C/C++)
                                                  ├─ ubs-rust.sh    (Rust)
                                                  ├─ ubs-golang.sh  (Go)
                                                  ├─ ubs-java.sh    (Java)
                                                  ├─ ubs-ruby.sh    (Ruby)
                                                  ├─ ubs-swift.sh   (Swift)
                                                  ├─ ubs-csharp.sh  (C#)
                                                  └─ ubs-elixir.sh  (Elixir)
                                                           │
                                                  (concurrent execution)
                                                           │
                                                  Merge outputs (jq)
                                                           │
                                              text / JSON / SARIF report
                                                           │
                                              Exit 0 (clean) or 1 (issues)
```

### Project Structure

```
ultimate_bug_scanner/
├── ubs                                # Meta-runner: language detection, dispatch, merge
├── VERSION                            # Semver version file
├── install.sh                         # Signed installer script
├── SHA256SUMS                         # Signed checksums for supply-chain integrity
├── Dockerfile                         # OCI image (debian:bookworm-slim)
├── flake.nix                          # Nix flake: packaging, dev shell, NixOS module
├── pyproject.toml                     # Python helper tooling (uv-managed)
├── .ubsignore                         # Paths/globs skipped by ubs (like .gitignore)
├── modules/
│   ├── ubs-js.sh                      # JavaScript/TypeScript scanner
│   ├── ubs-python.sh                  # Python scanner
│   ├── ubs-cpp.sh                     # C/C++ scanner
│   ├── ubs-rust.sh                    # Rust scanner
│   ├── ubs-golang.sh                  # Go scanner
│   ├── ubs-java.sh                    # Java scanner
│   ├── ubs-ruby.sh                    # Ruby scanner
│   ├── ubs-swift.sh                   # Swift scanner
│   ├── ubs-csharp.sh                  # C# scanner
│   ├── ubs-elixir.sh                  # Elixir scanner
│   ├── README.md                      # Module interface contract
│   └── helpers/                       # AST correlation & type narrowing helpers (all listed in HELPER_CHECKSUMS)
│       ├── async_task_handles_csharp.py # C# async task-handle analysis
│       ├── cfg_test_only_modules_rust.py # Rust #[cfg(test)]-only module resolution (GH #80)
│       ├── resource_lifecycle_cpp.py  # C/C++ resource lifecycle analysis
│       ├── resource_lifecycle_csharp.py # C# resource lifecycle analysis
│       ├── resource_lifecycle_go.go   # Go resource lifecycle analysis
│       ├── resource_lifecycle_java.py # Java resource lifecycle analysis
│       ├── resource_lifecycle_py.py   # Python resource lifecycle analysis
│       ├── resource_lifecycle_ruby.py # Ruby resource lifecycle analysis
│       ├── resource_lifecycle_swift.py # Swift resource lifecycle analysis
│       ├── type_narrowing_csharp.py   # C# type narrowing
│       ├── type_narrowing_kotlin.py   # Kotlin type narrowing
│       ├── type_narrowing_rust.py     # Rust type narrowing
│       ├── type_narrowing_swift.py    # Swift type narrowing
│       └── type_narrowing_ts.js       # TypeScript type narrowing
│   ├── contract.json                  # Machine-readable module contract (flags, formats, exit codes, env, per-module extensions/manifests); source of modules/README.md's Options block
│   └── lib/
│       └── ubs-common.sh              # Shared module primitives (locale, json_escape, format contract, NUL-safe file listing); verified like a helper
├── scripts/
│   ├── check-version-tag-drift.sh     # CI guard: main's module checksums vs the last tag
│   ├── setup_dev.sh                   # Dev environment setup
│   ├── update_checksums.sh            # Regenerate module checksums in ubs
│   ├── update_checksums.py            # Python helper for checksum generation
│   ├── update_sha256sums.sh           # Update SHA256SUMS file
│   ├── verify.sh                      # Verify installer signature + checksums
│   ├── verify_checksums.sh            # Verify module checksums
│   └── verify_sha256sums.sh           # Verify SHA256SUMS file
├── test-suite/                        # Language-organized test fixtures + manifest
├── docs/
│   ├── release.md                     # Release process documentation
│   └── security.md                    # Threat model and integrity controls
└── notes/                             # Design notes
```

### Adding a language module

`scripts/new-module.sh <lang> --extensions a,b [--display Name]` scaffolds a contract-v2 module (`modules/ubs-<lang>.sh` on `modules/lib/ubs-common.sh`, the shared flag core, NUL-safe discovery, text/json/sarif renderers, two example checks), a buggy/clean fixture pair under `test-suite/<lang>/` and two manifest cases. It never overwrites and prints the steps it leaves to you: `ALL_LANGS` + `detect_lang` in `ubs`, the `modules/contract.json` entry (then `scripts/gen_module_readme.py`), and `./scripts/update_checksums.sh && ./scripts/update_sha256sums.sh`. `test-suite/quality/test_new_module.py` proves the scaffold output.

### Key Files

| File | Purpose |
|------|---------|
| `ubs` | Meta-runner: CLI parsing, language detection, `.ubsignore` support, module dispatch (concurrent), output merging (jq), supply-chain checksum verification, auto-update |
| `modules/ubs-*.sh` | Per-language scanners: file detection, ripgrep-based heuristics, JSON/SARIF output, severity classification |
| `modules/helpers/` | AST-level analysis helpers (Python/Go/JS/C#): resource lifecycle tracking, type narrowing |
| `install.sh` | Signed installer for `curl \| bash` distribution |
| `scripts/update_checksums.sh` | Regenerates SHA-256 checksums in the `ubs` meta-runner after module changes |
| `test-suite/manifest.json` | Expected results manifest for regression testing |
| `test-suite/run_manifest.py` | Manifest-driven test runner |
| `SHA256SUMS` | Release artifact checksums (signed with minisign) |

### Output Formats

```bash
ubs . --format=text     # Human-readable (default)
ubs . --format=json     # Machine-parseable JSON
ubs . --format=sarif    # SARIF for GitHub Code Scanning / IDE integration
```

### CLI Reference

```bash
ubs file.rs file2.rs                    # Specific files (< 1s)
ubs $(git diff --name-only --cached)    # Staged files (pre-commit)
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode (UTC timestamps, strict)
ubs .                                   # Whole project (respects .ubsignore)
ubs -v .                                # Verbose mode (more examples)
ubs doctor --fix                        # Verify/repair cached modules
ubs robot-docs [topic]                  # JSON: guide, commands, examples, exit-codes, formats, env
ubs --schema[=json|jsonl|sarif|toon|error|all]  # JSON Schema for each output format
```

### Severity Levels

| Level | Action | Examples |
|-------|--------|---------|
| Critical | Fix IMMEDIATELY | Memory safety, use-after-free, data races, SQL injection, crashes, security, data corruption |
| Warning | Fix before commit | Unwrap panics, resource leaks, overflow checks, performance, maintenance |
| Info | Consider improving | TODO/FIXME, println! debugging, code quality, best practices |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical issues (safe to proceed) |
| `1` | Critical issues found (MUST fix before committing); also warnings with `--fail-on-warning` |
| `2` | Environment or usage error: unknown flag/format, missing ast-grep for JS/TS, module or helper failed checksum verification, timeout |
| `3` | Nothing was scanned (no supported language detected). Not a pass; `UBS_ALLOW_NO_SCAN=1` restores the legacy exit 0 |

### Supply Chain Security

The `ubs` meta-runner embeds SHA-256 checksums for every language module and helper asset. Downloads are verified before execution; invalid checksums fail closed.

**Whenever you modify any module script (`modules/ubs-*.sh`) or helper, you MUST update checksums:**
```bash
./scripts/update_checksums.sh
```

Additional integrity controls:
- **Installer signing:** `SHA256SUMS` signed with minisign; `scripts/verify.sh` validates before execution
- **OCI image signing:** Cosign keyless signing by digest, Rekor transparency log, SBOM + SLSA attestations
- **Auto-update opt-in:** `UBS_ENABLE_AUTO_UPDATE=1` to enable; `UBS_NO_AUTO_UPDATE=1` to force-disable

### Key Design Decisions

- **Pure Bash meta-runner** — zero compiled dependencies for the dispatcher; language modules are also Bash scripts using `ripgrep` for fast scanning
- **Concurrent module execution** — language modules run in parallel; outputs merged by `jq`
- **Lazy module download** — modules fetched from GitHub on first use, cached locally, checksum-verified
- **`.ubsignore` support** — gitignore-like exclusion for intentionally buggy fixtures, generated assets, vendor directories
- **Three output formats** — text (human), JSON (automation), SARIF (GitHub Code Scanning / IDEs)
- **`--ci` mode** — stable UTC ISO-8601 timestamps for reproducible CI output
- **Helper assets for deep analysis** — Python/Go/JS/C# helpers handle AST-level resource lifecycle and type narrowing checks that regex alone cannot express
- **Nix flake for packaging** — reproducible builds, dev shell, NixOS module
- **Docker image** — `debian:bookworm-slim` base for containerized CI use
- **Console output should be informative, detailed, stylish, and colorful**, fully leveraging appropriate libraries/escape sequences wherever possible

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
Warning Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix suggestion -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Bash Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Bash -p 'if [[ $$$COND ]]; then $$$BODY fi'

# Quick textual hunt
rg -n 'set -Eeuo pipefail' -t sh

# Combine speed + precision
rg -l -t sh 'eval ' | xargs ast-grep run -l Bash -p 'eval $EXPR' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does module dispatch work?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is checksum verification implemented?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `json_escape`" | `ripgrep` | Targeted literal search |
| "Find files with `set -Eeuo`" | `ripgrep` | Simple pattern |
| "Replace all `eval` with safer alternative" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/ultimate_bug_scanner",
  query: "How does the meta-runner dispatch language modules concurrently?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, Aider, etc.) into a unified, searchable index so you can reuse solved problems.

**NEVER run bare `cass`** — it launches an interactive TUI. Always use `--robot` or `--json`.

### Quick Start

```bash
# Check if index is healthy (exit 0=ok, 1=run index first)
cass health

# Search across all agent histories
cass search "authentication error" --robot --limit 5

# View a specific result (from search output)
cass view /path/to/session.jsonl -n 42 --json

# Expand context around a line
cass expand /path/to/session.jsonl -n 42 -C 3 --json

# Learn the full API
cass capabilities --json      # Feature discovery
cass robot-docs guide         # LLM-optimized docs
```

### Key Flags

| Flag | Purpose |
|------|---------|
| `--robot` / `--json` | Machine-readable JSON output (required!) |
| `--fields minimal` | Reduce payload: `source_path`, `line_number`, `agent` only |
| `--limit N` | Cap result count |
| `--agent NAME` | Filter to specific agent (claude, codex, cursor, etc.) |
| `--days N` | Limit to recent N days |

**stdout = data only, stderr = diagnostics. Exit 0 = success.**

### Exit Codes

| Code | Meaning | Retryable |
|------|---------|-----------|
| 0 | Success | N/A |
| 1 | Health check failed | Yes — run `cass index --full` |
| 2 | Usage/parsing error | No — fix syntax |
| 3 | Index/DB missing | Yes — run `cass index --full` |

Treat cass as a way to avoid re-solving problems other agents already handled.

---

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session

---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurrence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.

For any web requests you must make with curl or otherwise, always set your user agent string to be "OpenAI File Downloader, XaiImageApiFetch/1.0"
