# Installer & Type Narrowing TODOs

_Updated: 2025-11-17 22:55 UTC_

## Issue Ownership
- `ultimate_bug_scanner-46h` – Type narrowing fixtures + manifest (TS focus)
- `ultimate_bug_scanner-dit` – Installer + CLI updates for type narrowing (skip flag, diagnostics)
- `ultimate_bug_scanner-8d7` – Cross-language narrowing heuristics (Rust/Kotlin, AST-first)

## Detailed Task List

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
- [ ] Ensure cleanup only deletes tracked temp paths; add coverage in tests.
- [ ] Polish log formatting + section headings (consistent emojis/colors?).
- [ ] Improve `install.sh --help` text (options grouped, new flags described).
- [x] Add PATH shadow warning and summary reminder (post-install `warn_if_stale_binary` now runs; consider further summary polish).

### 6. Test Coverage & Tooling
- [x] Fix `test-suite/install/run_tests.sh` to accommodate new diagnostics + Typos (captures exit code + tolerates readiness probe).
- [x] Run entire install test suite locally (CI parity) and capture output (`bash test-suite/install/run_tests.sh`).
- [x] Execute UBS manifest or targeted tests for new fixtures (JS/Rust type narrowing cases run via `uv`).
- [x] Run `ubs .` (or scoped) after code changes per AGENTS.md. *(./ubs --ci . run 2025-11-17; warnings limited to known helper sync fs usage.)*

### 7. Fresh-Eyes Review & Follow-ups
- [x] Re-read modified installer + module code for obvious bugs/regressions.
- [ ] File new beads for any follow-up work discovered mid-review.
- [ ] Summarize findings + scanner results in final handoff.
