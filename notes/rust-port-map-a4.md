# A4-rust Port Map — modules/ubs-rust.sh → contract v2 (bead 0xjg.7)

Status: PORT COMPLETE (executor CyanMarsh, 2026-09-06). v2 LIVE behind
UBS_CONTRACT_V2_RUST=1; legacy default untouched (gate-off byte-identical);
UBS_LEGACY_MODULE_RUST=1 escape; sarif falls through to the legacy path.
Language key for Main's central run_lang forwarding pass: `rust` (module gained
--report-json; v2 copies the NDJSON sink to it).

GATES (all green at commit):
- rust manifest sweep under the gate: 65/66 PASS (run_manifest.py; only
  pre-existing rust-clean fails due to bead ultimate_bug_scanner-jtfn toolchain
  drift on RCH workers).
- Parity on test-suite/rust/buggy: 124 critical, 155 warning, 134 info — byte-identical
  counts vs legacy run on the same environment.
- shellcheck -S warning on ubs-rust.sh: clean (zero new findings).
- contract_conformance.py: ubs-rust.sh format_json emits language+status (passes
  all checks cleanly).
- Process budget: 1 list + 1 rule-gen python + ast-grep scan + 1 rust_scan ≈ 4-6
  processes (<= 25 target).
- Checksums refreshed via update_checksums.sh + update_sha256sums.sh.

IMPLEMENTED LAYERS
- ubs_core/rust_scan.py: orchestrator (in-process rg-line engine, AST filtering,
  computed checks, legacy text renderer, K2 sink), handles categories 1-11 and 15-24.
- ubs_core/rust_rules.py: consolidated ast-grep rule generation (142 patterns into
  sgconfig-rust.yml, UNPARSEABLE_RULES, RUN_MODE_RULES).
- ubs_core/rust_ast.py: consolidated ast-grep scanner running the generated sgconfig
  plus run-mode pattern spawns.
- ubs_core/rust_detectors/: specialized heredoc ports (command_executable, etc.).
- modules/ubs-rust.sh: gate block for UBS_CONTRACT_V2_RUST=1 + cargo bridges
  (categories 12/13/14) + --report-json forwarding.

LEGACY QUIRKS PRESERVED (parity-critical):
- shell_command check uses AST-or-RG fallback (`shell_command_ast > 0 ? shell_command_ast : shell_command_rg`).
- Mutex::lock().unwrap()/expect() and await in loop sum AST + RG matches.
- Cargo phases (12/13/14) run via subprocess cargo machinery with exit 103 partial degradation handling.
- Legacy format=json summary includes language, project, files, critical, warning, info, timestamp, status.

KNOWN DIVERGENCES (documented, parity-neutral on the manifest):
- File list via ubs_list_files rather than ad-hoc find/rg.
- SARIF mode uses the legacy path.
- In-process consolidation reduces process spawning from ~140 to <= 25.
