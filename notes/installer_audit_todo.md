# Installer Audit TODO

## Test + Verification Backlog

- [x] Run `bash test-suite/run_all.sh` (or equivalent manifest entry point) with fresh env to see current failures after the "major module revisions". *(2025-11-17: all 48 manifest cases PASS; no failures to triage, but logs archived in shell history.)*
  - [x] Capture exact failing test IDs/paths with logs for repro. *(none failed; PASS log kept)*
  - [x] Classify for each failure whether the regression is in code, fixtures, or the test harness itself. *(n/a this run.)*
  - [ ] When tests appear brittle/invalid, sketch the AST-grep-based approach we actually want instead of brute-force regex, and note blockers.
- [x] Run `bash test-suite/install/run_tests.sh` before any installer edits to have baseline evidence. *(2025-11-17 run: both smoke cases PASS.)*
- [x] Run `bash test-suite/install/run_tests.sh` again after every installer change batch (include a `--self-test` flag coverage check once implemented). *(2025-11-17 post-change run: both smoke cases PASS.)*
- [x] Capture dry-run installer output (e.g., `bash install.sh --dry-run --no-path-modify`) for doc snippets + regression comparison. *(Saved `/tmp/ubs-dry-run.log` from `bash install.sh --dry-run --no-path-modify --skip-hooks --non-interactive`.)*

## Installer Improvements (In Progress)

- [x] Fix `detect_coding_agents()` so it never exits non-zero under `set -e` and always returns success (guard each heuristic, add explicit `return 0`, ensure `.replit` detection uses both repo and `$HOME` paths).
- [x] Ensure `--no-path-modify` also skips `create_alias()` (log that alias creation is skipped instead of writing to rc files).
- [x] Synchronize the installer `VERSION` constant with the root `VERSION` file (target 4.6.0 everywhere).
- [x] Add installer regression tests under `test-suite/install/` that spin up a disposable HOME, run `install.sh` with non-interactive flags, and assert the run reaches post-install verification without touching rc files when `--no-path-modify` is set.
- [x] Document the new behavior in README/INSTALL notes (alias skipping, how to run installer tests, updated version badge/info).
- [x] Improve network error logging:
  - [x] Capture stderr for `check_for_updates`. *(mktemp log + shared helper.)*
  - [x] Capture stderr for `download_binary_release` and mention final error line. *(helper now emits tail automatically.)*
  - [x] Reuse helper for future network operations. *(Added `log_network_failure` used by both code paths.)*
- [ ] Introduce a `--dry-run` flag:
  - [x] Parse flag and expose `dry_run_enabled`. *(already present; confirmed usage across helpers.)*
  - [x] Wrap mutating operations (fs writes, PATH edits, hook installs, downloads) to log instead of executing when dry run is active. *(install_scanner, installer deps, PATH/alias, hooks, AGENTS, etc. now short-circuit with `[dry-run]` logs.)*
  - [x] Ensure verification + smoke test steps are skipped or clearly logged in dry-run mode. *(verify_installation + self-test + stale warning all emit `[dry-run]` notices.)*
- [x] Logging polish:
  - [x] Use `log_section` for major banners (post-install verification, diagnostics).
  - [x] Consider padding/checkmark alignment for success/warn/error output. *(Unified icon formatter now aligns multi-line messages.)*
- [x] Harden cleanup/locking:
  - [x] Track temp paths with `register_temp_path` and remove broad `/tmp/ripgrep-*` deletions.
  - [x] Replace directory lock with `flock` (fallback to mkdir) and ensure release uses helper. *(Already enforced in helper; verified again.)*
  - [x] Update help text to mention new behavior if needed. *(Usage block now documents `--dry-run` semantics + `--self-test` requirements.)*
- [x] Provide a `--self-test` flag:
  - [x] Flag triggers running `test-suite/install/run_tests.sh` after install (or a lighter inline check) and fails if smoke suite fails.
  - [x] Useful for CI pipelines wanting automated validation. *(Documented flag in README + INSTALL_ENHANCEMENTS.)*
- [x] Detect stale `ubs` binaries:
  - [x] After installation, compare `command -v ubs` result with `$install_dir/ubs` and warn if they differ.
  - [x] Document expected behavior in README.
- [x] Integrate Typos CLI:
  - [x] Provide `check_typos` + installer prompts/dry-run support akin to ripgrep/jq.
  - [x] Hook into verification + README/INSTALL docs.
  - [x] Add `--skip-typos` flag and config entry.
- [x] Ensure `install_ripgrep`, `install_jq`, hook setup/removal, PATH edits, etc., respect `dry_run_enabled()` with descriptive log messages (audit each helper once the flag exists).
- [x] Clean up legacy `/tmp/*install.log` writing; consolidate around `mktemp_in_workdir` + `register_temp_path`.
- [x] Expand locking helper coverage so every call site honors `acquire_lock`/`release_lock` (look for manual `mkdir` or `trap` logic still hanging around). *(Audited entire script; confirmed centralized helpers.)*

## Documentation + Readme Touchpoints

- [x] README / INSTALL_ENHANCEMENTS updates for: `--dry-run`, `--self-test`, lock/cleanup behavior, and new logging snippets.
- [x] Document how/when to run install smoke tests plus any new environment variables. *(README install test section now references `--self-test` flag.)*
- [x] Add troubleshooting entry for stale PATH vs `command -v ubs` mismatch warnings. *(Installer note in README’s safety nets section.)*
- [x] Note AST-grep-first guidance for JS module tests to keep future contributors aligned. *(README installer-test section now calls this out.)*

## Fresh-Eyes Review Checklist (post-change)

- [x] Re-read all installer changes with fresh eyes (search for `# shellcheck` suppressions, quoting hazards, untracked temp paths). *(Manually inspected modified functions; no obvious quoting regressions spotted.)*
- [ ] Re-run shellcheck or static lint if available (document results if command not run). *(ShellCheck installed 2025-11-17; see remediation backlog below.)*
- [x] Double-check doc snippets for accuracy with final CLI flag names. *(README + INSTALL_ENHANCEMENTS + test-suite README now aligned.)*
- [x] Log any follow-up issues discovered via bd (use discovered-from links where appropriate). *(ultimate_bug_scanner-8zv notes updated; future work limited to logging alignment + help text.)*

### ShellCheck Remediation (2025-11-17 run)

- [ ] Add `-r` to `read` in `ask()` to avoid backslash mangling (SC2162).
- [ ] Restructure trailing `check_ast_grep` / `check_ripgrep` blocks ShellCheck flagged as unreachable (SC2317) so they’re actually executed or removed.
- [ ] Replace the `$(echo "$ver" | sed 's/[^0-9.]/./g')` helpers with parameter expansion and quote the numeric comparisons (SC2001, SC2086).
- [ ] Remove or use `tarball_dir` in the ripgrep BSD branch (SC2034).
- [ ] Replace `A && B || C` logging patterns (hook checks, agent detection, etc.) with explicit `if/else` blocks to avoid SC2015.
- [ ] Split `local foo="$(...)"` declarations into `local foo; foo="$(...)"` where flagged (SC2155).
- [ ] Swap `ls ... | wc -l` and follow-up `ls` output with `find`/`printf` equivalents for module cache reporting (SC2012).
- [ ] Group multi-line `>>` appends (rc files, config files) inside `{ ...; } >> file` to clear SC2129.
- [ ] Re-run `shellcheck install.sh` once all items above are handled and archive the clean log.
