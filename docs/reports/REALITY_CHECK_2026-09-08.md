# Reality Check — 2026-09-08 (v5.4.0, `main` @ ab5cf41)

A code-versus-docs audit of UBS: what the README and AGENTS promise, what the code actually does in v5.4.0, measurements across all dimensions, comparison against the 2026-09-02 baseline (`5da893d`), and the bridge plan for remaining gaps.

---

## Verdict

UBS has achieved monumental architectural progress between 2026-09-02 and 2026-09-08. Over the past 6 days, **105 beads were closed** (bringing total closed issues to 257 out of 284). The engine core has been completely transformed:
1. **Epic A (Engine Core) is 100% Complete**: All 12 modules (`bash`, `cpp`, `csharp`, `elixir`, `golang`, `java`, `js`, `kotlin`, `python`, `ruby`, `rust`, `swift`) have been ported to Contract v2, sourcing `modules/lib/ubs-common.sh` and backed by `modules/helpers/ubs_core`. The fragile, 250+ process legacy Bash architectures and dead code paths have been deleted.
2. **Epic B (Meta-Runner Truthfulness) is 100% Complete**: Whole-project shadow copies (`rsync` into `/tmp`) have been completely eliminated (`test_no_shadow_copy_for_whole_project`). The file-list pipeline feeds `--files-from` directly to Contract v2 modules. Documented flags (`OUTPUT_FILE`, `--include-ext`, `--rules`, `--no-color`, `--list-categories`, `--exclude` as path globs) are fully implemented and verified.
3. **Epic C (Performance Core) has Landed**: Necessary-literal prefilter (C2), Merkle-keyed incremental cache (C4), and Graham LPT scheduler with fitted cost model and work-stealing shards (C5) are implemented and active. Single-file scan latency dropped from 4.6–5.8s down to 1.25s (JS) and 2.6s (Python).
4. **Epic J & Docs Truth Synchronized**: `scripts/check_docs_claims.py` now validates 13 distinct claim categories (166 CLI flags, 12 languages, 344 helpers, version 5.4.0, Python 3.14 pin, exit codes, installer flags). All 13 checks pass cleanly.
5. **Supply Chain Hardened**: SHA256SUMS and embedded checksum tables now cover all 12 modules and 344 helpers. Modules fail closed if helpers or shared libraries fail verification.

### The Brutally Honest Reality: The Remaining Gaps

Despite these massive architectural victories, UBS has a critical blind spot that breaks its own self-hosting promise:

1. **Self-Scan Gate is Red (`./ubs . --ci --fail-on-warning` fails with Exit 1)**:
   - When running `./ubs .`, UBS reports **133 critical findings, 713 warnings, and 5,125 info items** across 379 files.
   - **Root Cause A (Detector Source Ingestion)**: The creation of `modules/helpers/ubs_core/` added 344 Python files containing raw detector definitions, static analysis regexes, and vulnerability fixtures (e.g. `tempfile.mktemp` detection, literal `is` comparisons, SQL injection regexes). UBS scans its own detector definitions and flags them as vulnerabilities in UBS itself.
   - **Root Cause B (`resource_lifecycle_go.go` ignores `.ubsignore` / `--files-from`)**: In `modules/ubs-golang.sh`, category 17 invokes `go run helpers/resource_lifecycle_go.go -- "$PROJECT_DIR"`. The Go helper ignores `.ubsignore` and `--files-from`, performing its own unconstrained filesystem walk of `.` and scanning `test-suite/golang/buggy/`, producing 3 critical findings.
   - **CI Impact**: Step `Self-scan (UBS must pass on its own sources)` in `.github/workflows/ci.yml:99-100` (`jq -e '.totals.critical == 0 and .totals.warning == 0'`) fails immediately on `main`.
2. **Universal AST Rule Coverage is Uneven (Epic D5 Open)**:
   - While Rust has 77 ast-grep rules, Go 64, Python 52, JS 37, Java 34, C++ 32, and Ruby 28; **Elixir has 0 rules**, **Swift has 1 rule**, and **C# has 4 rules**.
3. **Dataflow Taint Engine is Incomplete (Epic D6 Open)**:
   - Taint tracking across function boundaries (monotone dataflow engine with Kildall worklist and Sharir–Pnueli summaries) remains open in `ubs_core`.
4. **Platform Verification Pending (Epic G / F7 / E5)**:
   - Windows Git Bash, macOS, Nix, and keyless cosign CI workflows are authored but await live CI observation (`ultimate_bug_scanner-s2k5.7`).
5. **Streaming Output & Daemon Mode (C6, K4 Open)**:
   - Memory streaming to guarantee RSS < 200 MB on 400K-line monorepos (C6) and `ubs serve` / `ubs --client` (K4) are not yet implemented.

---

## Evidence Comparison: 2026-09-02 Baseline vs 2026-09-08 Current State

| Check | 2026-09-02 Baseline (v5.3.13) | 2026-09-08 Reality Check (v5.4.0) | Trend |
|---|---|---|---|
| **Beads Total / Closed / Open** | 20 open / 3 in progress / 152 closed (schema-0 DB) | 284 total / 257 closed / 23 actionable open / 4 in progress | **+105 closed** (Massive progress) |
| **Manifest Test Cases** | 440 cases (440 pass, 31m52s) | 474 cases (all pass) | **+34 test cases** |
| **`python3 scripts/check_docs_claims.py`** | Failed (drifted flags, helpers, versions) | 13 / 13 check suites PASS | **Fixed (100% truthful docs)** |
| **`python3 scripts/contract_conformance.py`** | 10 modules, failed on several flags | 12 / 12 modules conform to Contract v2 | **100% Conformance** |
| **Single-file Scan Latency (JS)** | 4.6 s | **1.25 s** (measured on clean JS) | **3.7x faster** |
| **Single-file Scan Latency (Python)** | 5.8 s | **2.65 s** (measured on clean Python) | **2.2x faster** |
| **Whole-project Shadow Workspace** | Copied entire repository into `/tmp` via `rsync` | **Eliminated**; direct scan via `--files-from` list | **Fixed (Zero disk copy)** |
| **Module Process Count** | ~250–400 processes per run | ≤ 25 processes per module run | **10x–15x reduction** |
| **Supported Languages** | 10 languages (Bash missing, Kotlin tied to Java) | 12 languages (Bash added, Kotlin split) | **+2 languages** |
| **Self-Scan (`./ubs . --ci --fail-on-warning`)** | Exit 1 (9 critical, all CT-compare false positives) | Exit 1 (133 critical, 707 warning on `ubs_core` + Go helper) | **REGRESSED (Self-gate broken)** |
| **Supply Chain Checksums** | Covered only `ubs` + `install.sh` | Covers `ubs`, `install.sh`, 12 modules, and 344 helpers | **Comprehensive Fail-Closed** |
| **Inline Suppression** | Broken outside JS; previous-line counted | Statement-interval engine in `ubs_core.suppression` across all langs | **Fixed** |
| **Severity Normalization** | Only in `ubs-swift.sh` | Shared in `modules/lib/ubs-common.sh` for all 12 modules | **Fixed** |
| **Documented CLI Flags** | 5 documented flags missing from parser | 166 accepted flags verified against docs | **100% parity** |

---

## 27-Point Vision Checklist Audit

Status Categories:
- `WORKING`: Code exists, passes tests, verified end-to-end.
- `PARTIAL`: Implementation exists but is incomplete or has known gaps.
- `STUB`: Placeholder or mock code only.
- `UNPROVEN`: Code exists but lacks live test/CI verification.
- `MISSING`: Not implemented.
- `REGRESSED`: Previously working or closed, currently broken.
- `NO_BEAD`: Vision gap not covered by any open bead.

| # | Promise (Source) | Status | Evidence in v5.4.0 |
|---|---|---|---|
| 1 | One-command install; Homebrew; Scoop; Nix; Docker | **WORKING** | `install.sh` first-install abort fixed (F1); two-pass CLI parsing fixed (F2); Dockerfile upgraded to Debian trixie with `python3`, `unzip`, and pre-provisioned `ast-grep` (G1); Scoop false claims cleanly removed from docs (G2); `toon_rust` auto-installed (F8). |
| 2 | Auto-detect languages, concurrent modules, merged report | **WORKING** | All 12 modules detected; concurrent dispatch with LPT scheduler (C5); Merkle cache (C4); unified JSON/SARIF merging in meta-runner. |
| 3 | Sub-5s feedback, <1s/file, 10K+ lines/s, <100MB memory | **PARTIAL** | Single-file scan down to 1.25s (JS) and 2.6s (Python). Shadow workspace eliminated. Prefilter (C2), cache (C4), and scheduler (C5) active. However, C6 (streaming output, memory < 200MB on 400K lines) and C7 (perf table) remain open. |
| 4 | `--format=text\|json\|jsonl\|sarif\|toon` in meta-runner & modules | **WORKING** | All 12 modules natively implement `text`, `json`, and `sarif` via Contract v2. Meta-runner derives `jsonl` and `toon` from JSON. K5 (`--format=toon` exits 2 when `tru` is missing) implemented and verified. |
| 5 | Exit code contract 0 / 1 / 2 / 3 | **WORKING** | Enforced across meta-runner and all 12 modules via `ubs-common.sh`. Unknown flags and formats reject with exit 2. Exit 3 for no scan targets. |
| 6 | CLI reference (README §Command-Line Options) | **WORKING** | `OUTPUT_FILE`, `--include-ext`, `--rules=DIR`, `--no-color`, `--list-categories` all implemented (B1). `--exclude` matches path globs; `--exclude-langs` matches languages (B2). Verified by `scripts/check_docs_claims.py`. |
| 7 | Supply chain fail-closed for modules & helpers; signed releases | **PARTIAL** | `SHA256SUMS` and `MODULE_CHECKSUMS` cover all 12 modules and 344 helpers. Modules fail closed if assets are unverified (E1, E2). Release script `scripts/cut-release.sh` enforces atomicity (E3). Pinned dependency binaries verified (E4). Cosign keyless signatures & SLSA provenance (E5) open awaiting CI observation. |
| 8 | Inline `ubs:ignore` placements across all languages | **WORKING** | Statement-interval index in `ubs_core.suppression` (A7) handles same-line and previous-line ignore markers with rule scoping across all languages. |
| 9 | `normalize_severity()` in each module | **WORKING** | Standardized in `modules/lib/ubs-common.sh` (A1) and called by all 12 modules. |
| 10 | Cross-language detector parity | **PARTIAL** | Two-tier constant-time compare vocabulary (D2) landed. deep_guard correlation across languages (D3) landed. Type narrowing across languages (D4) landed. However, D6 (dataflow taint engine) remains open. |
| 11 | Universal AST adoption across all languages | **PARTIAL** | Rust (77), Go (64), Python (52), JS (37), Java (34), C++ (32), Ruby (28) are extensive. Elixir (0), Swift (1), and C# (4) have minimal rule packs. Open bead D5 covers this. |
| 12 | Blended false-positive rate 8–12% | **UNPROVEN** | Bead D2 eliminated the 9 constant-time false positives. However, stratified FP corpus with split-conformal confidence (D7) is open. |
| 13 | 12+ coding agents auto-configured; Claude Code hooks installed | **WORKING** | Claude Code `PostToolUse` and `PreToolUse` (`git_safety_guard.py`) hooks registered and tested (F3). Uninstall cleanly removes them (F5). |
| 14 | `--staged` / `--diff` quick scans | **WORKING** | Fully tested in `test-suite/shareable/test_meta_runner_modes.py` with ignore filtering. |
| 15 | Shareable reports with permalinks in text/JSON/SARIF | **WORKING** | `git.*` metadata attached to stdout JSON; permalinks rendered; HTML comparison column fixed (B5). Verified by `test_shareable_reports.py`. |
| 16 | `--category=resource-lifecycle` | **WORKING** | Language-prefixed category IDs and per-language skip/whitelist mapping implemented in `ubs-common.sh` and meta-runner (A5). |
| 17 | `--profile=strict\|loose` | **WORKING** | Normalized across modules and `ubs_core` pattern thresholds. |
| 18 | Custom ast-grep rules `--rules=DIR` | **WORKING** | Meta-runner parses `--rules=DIR` and forwards to all modules (B1). |
| 19 | `.ubsignore`, default ignores, size guard | **REGRESSED · NO_BEAD** | Size guard and meta-runner respect `.ubsignore` and content-scoped ignores (`bin`, `obj`, `env`). HOWEVER, `modules/helpers/resource_lifecycle_go.go` walks the filesystem directly without `.ubsignore`, breaking ignore isolation during self-scans. |
| 20 | `ubs doctor`, `ubs sessions` | **WORKING** | `ubs doctor --format=json` and `doctor --fix` cover modules, helpers, lib, and `ast-grep` repair (B9). |
| 21 | Opt-in auto-update, off in CI | **WORKING** | `CI=true` disables auto-update; `FORCE_SELF_UPDATE` works (B3). |
| 22 | Test suite and CI | **PARTIAL** | Unified `ci.yml` workflow with 4-way sharding (H1); goldens bot (H2); stronger rule-id assertions (H3); repo-root hygiene guard (H9). Nightly job (H4), metamorphic testing (H6), and scenario runner (H8) are open. |
| 23 | Docs as source of truth for agents | **WORKING** | `AGENTS.md`, `README.md`, and `modules/README.md` synchronized to v5.4.0, 12 languages, 344 helpers, and Python 3.14 pin. `scripts/check_docs_claims.py` guarantees automated alignment. |
| 24 | Shell/Bash scanning | **WORKING** | `modules/ubs-bash.sh` implemented, contract v2 compliant, tested on real shell bugs (I1). |
| 25 | Windows (Git Bash/WSL) and macOS | **UNPROVEN** | Python resolution on Windows resolved (G7). macOS (G3), Windows (G4), and Nix (G5) jobs authored, awaiting live CI observation (G6). |
| 26 | Version-tag drift never bites users | **WORKING** | `scripts/cut-release.sh` enforces atomic version/checksum/tag releases. `scripts/check-version-tag-drift.sh` guards every commit with zero false positives. |
| 27 | No dead code / tech debt | **WORKING** | Legacy module code paths deleted (A9). 1,857 lines of dead Java code removed. All modules share `ubs-common.sh`. |

---

## The Five Core Reality Check Questions

### 1. What specifically IS working right now?
- **Unified Engine Architecture**: All 12 language modules run under Contract v2. Each module sources `modules/lib/ubs-common.sh` for parameter parsing, format validation, suppression filtering, and finding output.
- **Zero-Copy Meta-Runner**: Whole-project scans do not copy files to `/tmp`. The file-list pipeline computes language subsets and supplies `--files-from` to modules scanning the source tree directly.
- **Incremental Caching & Scheduling**: The Merkle-keyed incremental cache (C4) skips re-scanning unchanged files; the Graham LPT scheduler (C5) balances module execution across available processor slots.
- **Contract Conformance**: All 12 modules pass automated contract conformance testing (`scripts/contract_conformance.py`), verifying CLI flags, formats, error handling, and process budgets (≤ 25 processes).
- **Truthful Documentation**: All 13 doc claim suites in `scripts/check_docs_claims.py` pass without error, ensuring complete synchronization between code, flags, versions, and docs.
- **Supply Chain Integrity**: Every module and helper is checksummed in `SHA256SUMS` and verified prior to execution. Drift between git tags and module checksums is strictly prevented.
- **Extensive Regression Test Suite**: 474 manifest test cases across all 12 languages pass cleanly.

### 2. What is NOT working or not yet implemented?
- **Self-Scan Gate Failure**: The self-scan gate (`./ubs . --ci --fail-on-warning`) fails with 133 critical findings and 707 warnings. This is caused by `ubs` scanning its own internal rule definitions in `modules/helpers/ubs_core/` and `modules/helpers/resource_lifecycle_go.go` bypassing `.ubsignore` to scan `test-suite/golang/buggy/`.
- **AST Rule Pack Parity (D5)**: Elixir has 0 ast-grep rules, Swift has 1, and C# has 4.
- **Dataflow Taint Engine (D6)**: Monotone dataflow engine with function summaries is not implemented.
- **Cross-Platform CI Verification (G6)**: Windows, macOS, Nix, and Cosign releases require observation on live GitHub Actions infrastructure.
- **Full Memory Streaming (C6)**: Shell output collection still uses intermediate buffers rather than true end-to-end streaming.
- **Daemon Mode (K4)**: `ubs serve` / `ubs --client` is not yet implemented.

### 3. What is blocking us from getting there?
- **Self-Scan Noise**: Until `ubs_core` source files are either excluded from AST inspection or annotated with scoped ignore comments, and `resource_lifecycle_go.go` is taught to respect `--files-from` / `.ubsignore`, the repo's primary CI gate cannot pass cleanly.
- **External CI Dependencies**: Completing Epic G (macOS/Windows/Nix) and Epic E5 (Cosign) requires pushing commits to GitHub and observing the CI runners.

### 4. If we were to implement all open and in-progress beads, would we close the gap completely? Why or why not?
**Almost completely, with ONE critical exception.**
The 23 actionable open beads and 4 in-progress beads directly target:
- Epic D: AST rule packs (D5), Dataflow taint (D6), FP corpus (D7).
- Epic G: macOS (G3), Windows (G4), Nix (G5), CI observation (G6).
- Epic E: Keyless Cosign signatures (E5).
- Epic F: Installer CI tests (F7).
- Epic H: Nightly runner (H4), Metamorphic tests (H6), E2E runner (H8).
- Epic C: Memory streaming (C6), Performance table (C7).
- Epic K: Daemon mode (K4).

**The Missing Exception**:
There is **NO OPEN BEAD** for the Self-Scan Regression on `modules/helpers/ubs_core/` and the `resource_lifecycle_go.go` directory traversal bug! Bead `D8` was closed prematurely before `ubs_core` was introduced. Without a dedicated bead to fix this, the self-gate in CI remains permanently broken.

### 5. What goals from the vision are NOT covered by ANY existing bead?
1. **Self-Gate Repair for `ubs_core` & Go Lifecycle Helper (`NO_BEAD`)**:
   - Teach `modules/helpers/resource_lifecycle_go.go` to accept `--files-from` or respect `.ubsignore`.
   - Prevent `ubs` from flagging its own static analysis pattern definitions in `modules/helpers/ubs_core/` (either via targeted suppression markers, pattern literal encoding, or appropriate analyzer whitelisting).
2. **Terminal UX / Streaming Progress (`NO_BEAD`)**:
   - The README promises interactive, stylish terminal progress with live spinners during multi-module execution. When scanning large repositories in interactive mode, the meta-runner currently waits silently until modules complete before rendering results.

---

## The Bridge Plan: Closing the Remaining Gaps

```
Phase 1: Reality Check Complete (This Document)
    ↓
Phase 2: Bridge Plan
    ├─ Track 1: Self-Gate & Hygiene (NEW BEAD: D8b)
    │   ├─ Patch resource_lifecycle_go.go to accept --files-from
    │   └─ Resolve ubs_core detector self-scan false positives
    ├─ Track 2: Detector Parity & Calibration (Epic D)
    │   ├─ Implement D5: Elixir, Swift, C# ast-grep rule packs
    │   ├─ Implement D6: Monotone dataflow taint engine
    │   └─ Implement D7: False-positive corpus & conformal prediction
    ├─ Track 3: Distribution & Platform CI (Epic G, E, F)
    │   ├─ Complete G3 (macOS), G4 (Windows), G5 (Nix)
    │   ├─ Observe G6 on GitHub Actions
    │   └─ Complete E5 (Cosign / SLSA) and F7 (Installer CI)
    ├─ Track 4: Scale & Ergonomics (Epic C, K, H)
    │   ├─ Implement C6 (streaming output, memory < 200MB)
    │   ├─ Implement K4 (ubs serve daemon)
    │   └─ Implement H4 (nightly) & H8 (E2E scenarios)
    ↓
Phase 3a: Bead Creation & Refinement
```
