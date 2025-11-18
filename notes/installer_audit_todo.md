# Installer & Type Narrowing TODOs

_Updated: 2025-11-18 01:30 UTC_

## Issue Ownership
- `ultimate_bug_scanner-46h` – Type narrowing fixtures + manifest (TS focus)
- `ultimate_bug_scanner-dit` – Installer + CLI updates for type narrowing (skip flag, diagnostics)
- `ultimate_bug_scanner-8d7` – Cross-language narrowing heuristics (Rust/Kotlin, AST-first)
- `ultimate_bug_scanner-ir4` – Instant Confidence Onboarding (auto doctor + session insights)
- `ultimate_bug_scanner-4se` – Type Narrowing Full Coverage (Swift/Kotlin/ObjC follow-ups)
- `ultimate_bug_scanner-4sm` – Resource Lifecycle Packs (Go/Python/Java symmetry)
- `ultimate_bug_scanner-1nr` – Shareable Reports (HTML diff, SARIF comparisons)

## Detailed Task List

### 0. Growth / Differentiators Backlog (new beads)
- [ ] **ultimate_bug_scanner-ir4** – “Instant Confidence Onboarding”  
  - [x] Run `ubs doctor` automatically after install (opt-out flag).  
  - [x] Generate `~/.config/ubs/session.md` summary of install + doctor output.  
  - [ ] Enrich session summary with readiness facts (typos/ripgrep/t narrowing).  
  - [ ] Provide CLI command (`ubs sessions`) to tail/format summaries.  
  - [ ] Surface next-action prompts if doctor finds missing deps.
- [ ] **ultimate_bug_scanner-4se** – “Type Narrowing Full Coverage”  
  - [x] Kotlin smart-cast & Elvis heuristics (null-safe + guard reasoning).  
  - [x] Swift guard-let helper + Java wiring.  
  - [ ] Extend Swift coverage (optional chaining, Objective-C bridging misuse).  
  - [ ] Add fixtures + manifest rows for Kotlin coroutine/Swift optional cases.  
  - [ ] Doc updates for Swift/Kotlin guard rules, CLI flag references.
- [x] **ultimate_bug_scanner-4sm** – “Resource Lifecycle Packs”  
  - [x] Python: context managers / file/socket close symmetry.  
  - [x] Go: `defer` pairing for files, db handles, mutexes.  
  - [x] Java: try-with-resources coverage (auto-closeable).  
  - [x] Publish pack toggle (`--category resource-lifecycle`).  
  - [x] Manifest coverage per language.
- [x] **ultimate_bug_scanner-1nr** – “Shareable Reports”  
  - [x] HTML report preview (diff vs previous run).  
  - [x] SARIF enhancements with run comparison metadata.  
  - [x] Embed GitHub file:line permalinks in JSON/text output.  
  - [x] CLI flag for “comparison mode” (baseline file).
- [ ] **ultimate_bug_scanner-k2r** – “Developer Happiness Set”  
  - [ ] `ubs configure` wizard for `.ubsignore`, default languages, env settings.  
  - [ ] Optional “fix suggestion” snippets per category (text + JSON).  
  - [ ] Alias helper to pipe findings into AI prompts.
- [ ] **ultimate_bug_scanner-m5n** – “Visibility & Trust”  
  - [ ] Blog-series pipeline (“UBS Hall of Bugs”) with anonymized story template.  
  - [ ] Publish metrics dashboard (installs, average scan time, top findings).  
  - [ ] README badge hooking into metric snapshot.

### 1. TypeScript Fixtures & Manifest (46h)
- [x] Re-read new TS fixtures (buggy/clean) for correctness + clarity (verified guard/exit semantics on 2025-11-17).
- [x] Confirm manifest entries assert expected counts for new category (js-type-narrowing cases pass via `uv run`).
- [x] Update `test-suite/README.md` fixtures + expected output table (documented TS + cross-language rows).
- [x] Document CLI flag/manifest guidance in `README.md` or dedicated section (README already covers `--skip-type-narrowing`; sanity checked).

### 2. Installer + CLI Skip Flag (dit)
- [x] Audit CLI `--skip-type-narrowing` plumbing (env var, config, help text) end-to-end (config + help updated 2025-11-17).
- [x] Ensure installer + diagnostics honor skip flag (TypeScript readiness logging no longer trips `set -e`).
- [x] Extend installer dry-run/logging coverage for new routines. *(npm install helper + readiness block respect dry-run.)*
- [x] Add `--self-test` follow-up coverage (installer harness now runs a dedicated `--self-test` regression unless invoked recursively).
- [x] Refresh README/INSTALL docs for diagnostics + skip flag usage (README safety-net/table updated with Node/TypeScript note).

### 3. Cross-language Heuristics (8d7)
- [x] Validate new Rust helper + fixtures; ensure manifest/test coverage (helper handles single files; JS/Rust cases pass via `uv run`).
- [x] Investigate Kotlin (or other language) heuristic feasibility + design plan.
- [x] Hook optional rules into CLI config/flags (parallel to TS case).
- [x] Update docs to mention multi-language coverage & how to toggle.
- [x] Evaluate migrating the Rust helper to ast-grep rules (Bash wrapper now collects ast-grep JSON and feeds the helper, with regex fallback when ast-grep/python unavailable).

### 4. Typos Spellchecker Integration
- [x] Confirm `install_typos` handles macOS/Linux/Windows, dry-run, retries (binary download + brew/cargo paths verified).
- [x] Add detection logic + diagnostics (installer + verification now report Typos status/skips).
- [x] Provide `--skip-typos` flag/config + documentation (README safety-net table + flag wiring updated).
- [x] Extend smoke tests to exercise Typos install/skip paths (installer harness updated with regression coverage).

### 5. Installer Reliability + UX
- [x] Review locking/tempfile helpers (self-test releases locks; harness ensures no stray `/tmp/ubs-install.lock`).
- [x] Ensure cleanup only deletes tracked temp paths; add coverage in tests. *(WORKDIR override + safe removal guard + harness asserts workdir cleanup.)*
- [x] Polish log formatting + section headings (consistent emojis/colors?). *(log_section now prints framed titles.)*
- [x] Improve `install.sh --help` text (options grouped, new flags described).
- [x] Add PATH shadow warning and summary reminder (post-install `warn_if_stale_binary` now runs; consider further summary polish).

### 6. Test Coverage & Tooling
- [x] Fix `test-suite/install/run_tests.sh` to accommodate new diagnostics + Typos (captures exit code + tolerates readiness probe).
- [x] Run entire install test suite locally (CI parity) and capture output (`bash test-suite/install/run_tests.sh`).
- [x] Execute UBS manifest or targeted tests for new fixtures (JS/Rust type narrowing cases run via `uv`).
- [x] Run `ubs .` (or scoped) after code changes per AGENTS.md. *(./ubs --ci . run 2025-11-18; warnings 0 after async helper + JSON heuristics refinements.)*

### 7. Fresh-Eyes Review & Follow-ups
- [x] Re-read modified installer + module code for obvious bugs/regressions.
- [x] File new beads for any follow-up work discovered mid-review *(none identified during this pass).* 
- [x] Summarize findings + scanner results in final handoff (documented in 2025-11-18 status reply).

### 8. Instant Confidence Onboarding (ir4)
- [x] Capture readiness facts (ripgrep/jq/typos/type narrowing) during installer run and feed into session summary bullet list.
- [x] Include last `ubs doctor` exit status + pointer to session log path in completion banner.
- [x] Implement `ubs sessions` (or `ubs session-log`) subcommand:
  - [x] Show tail of `~/.config/ubs/session.md` with optional `--entries`/`--raw` flags.
  - [x] Respect `NO_COLOR` and provide helpful error if log absent.
- [x] Installer: mention new CLI command in quickstart text + README.
- [x] Test: extend `test-suite/install/run_tests.sh` to stub HOME, run installer with `--skip-doctor` false, then assert `ubs sessions --entries 1` prints latest block without error (maybe by invoking CLI script with env pointing to temp config).

### 9. Type Narrowing Full Coverage (4se)
- [x] Kotlin helper: add coroutine/optional-chain awareness (e.g., guard `if (job?.isActive == true)` before `job!!`).
- [x] Swift helper: detect optional chaining misuse (guard `if foo?.bar != nil` then later `foo!.bar`), and bridging cases.
- [x] Add fixtures under `test-suite/kotlin/type_narrowing/` and `test-suite/swift/type_narrowing/` for new heuristics; update manifest counts accordingly.
- [x] README/test-suite docs: new Swift/Kotlin coverage table row plus CLI flag mention.
- [x] UBS CLI help text: mention cross-language coverage + `--skip-type-narrowing` effects (ensuring help section includes languages).
- [x] Tests: run targeted manifest cases + `test-suite/run_all.sh` to verify metrics.

### 10. Java Lifecycle AST Coverage (6x4)
- [x] Generate ast-grep rules for ExecutorService shutdown, raw Thread join, and JDBC connection close detection.
- [x] Wire `emit_ast_rule_group` + shared AST result caching into `ubs-java.sh` so resource heuristics use AST first with regex fallback.
- [x] Keep manifest expectations stable (java-resource-lifecycle) via summary strings + new rule IDs.

### 11. Python Resource Helper (41t)
- [x] Enhance `resource_lifecycle_py.py` to understand `with/async with`, alias imports, and attribute `.open()` / `.connect()` patterns (pathlib, DB handles, etc.).
- [x] Ensure helper output powers Category 19 so regex heuristics are only a fallback when Python 3 or the helper file is unavailable.
- [x] Update fixtures/docs to note the AST-driven detection and re-run manifest suites.

### 12. Universal AST Adoption (7g7)
- [x] Document the AST coverage story in README (JS/TS, Python, Go, C++, Rust, Java, Ruby, Swift, Kotlin) so the epic has a single source of truth.
- [x] Verify every language module now has AST-powered detectors for its flagship categories (type narrowing, resource lifecycle, taint/async errors) with regex only as a fallback.
- [x] Re-run `test-suite/run_all.sh` + `./ubs --ci .` to prove the AST stack is stable across languages.

### 13. Docs & Polish Follow-ups (new)
- [x] Expand README + test-suite docs with concrete Go/Python resource lifecycle examples (buggy vs clean snippets + helper output narrations).
- [x] Ensure CLI and README help text highlight the AST-backed lifecycle coverage + `ubs sessions` workflow where appropriate.
- [x] Investigate `go-resource-lifecycle` manifest expectations to assert on deterministic helper output (add/restore specific substrings if missing).
- [x] Housekeeping: verify helpers/installers leave no `__pycache__` or stray temp directories; document guardrails if needed (checked 2025-11-18 via find/installer harness cleanup).
- [x] After changes, run a fresh-eyes pass on installer + Go/Python modules before scans/tests.

### 14. JDBC Lifecycle Follow-ups (java-resource expansion)
- [x] Extend coverage to Statements/PreparedStatements (helper-powered `Statement/PreparedStatement not closed` + metadata entries replacing the planned ast-grep rule for now).
- [x] Update Java fixtures (buggy + clean) to exercise Statement, PreparedStatement, and ResultSet leaks vs. guarded patterns.
- [x] Expand manifest `java-resource-lifecycle` expectations to assert on new summary strings.
- [x] Refresh README resource-lifecycle bullet to mention Statement/PreparedStatement coverage (already documents new helper block).
- [x] Re-run Java manifest + full `test-suite/run_all.sh` + `./ubs --ci .`; document outcomes.

### 15. Swift Module Wiring (6x4 / 41t / 7g7 cross-over)
- [x] Re-enable all categories by fixing `should_skip` inversion so scans emit findings again.
- [x] Repair the banner heredoc + startup logging so the script parses under `set -e`.
- [x] Count Swift sources separately and gate the guard helper on actual `.swift` files.
- [x] Wire `run_swift_type_narrowing_checks` (helper + `UBS_SKIP_TYPE_NARROWING`) into Category 1 with proper logging.
- [x] Update manifest/test-suite docs/README to run Swift cases via `--only=swift` and advertise the dedicated module.
- [x] Patch the multi-line counter pipelines/Heredoc regression so the Swift module executes without syntax errors and surfaces guard warnings.
