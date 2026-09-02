# Reality Check — 2026-09-02 (v5.3.13, `main` @ 5da893d)

A code-versus-docs audit of UBS: what the README/AGENTS promise, what the code does, what was measured, and the bridge plan that resulted (tracked as beads). Numbers here are the baseline for the next reality check.

## Verdict

UBS is a mature, shipping v5.3 tool with a real 10-language engine, a 440-case regression manifest that passes, and a release/self-update supply chain that was genuinely hardened in #87. The README, however, describes a product roughly one third ahead of the code. The biggest gaps are claims the code does not keep: the speed and memory numbers, the "every module does X" parity claims, the flag reference, and the inline-suppression / severity-normalization promises. The full test-suite workflow had been red since 2026-08-17 for test-infrastructure reasons, which let a real regression (JS/TS `--format=sarif` failing with a duplicate rule id) ship in v5.3.12/13 unnoticed. The beads tracker was unusable (a `bd`-era database) and its 20 open beads covered none of the gaps below.

## Evidence

| Check | Result |
|---|---|
| `test-suite/run_manifest.py` (440 cases) | 440 / 440 pass, 31m52s wall, avg 4.3 s per case |
| `test-suite/run_all.sh` | Failed at step 2 (Go rule-inventory order differs under `en_US.UTF-8`), then would fail in the rule-quality harness (stale golden expecting a buggy twin for a clean-only Rust fixture), then in the JS rule-pack SARIF check (duplicate rule id). All three fixed on 2026-09-02. |
| GitHub "UBS Test Suite" workflow | Red since 2026-08-17 (harness assertion); "CI" and "UBS Manifest" green |
| `./ubs . --ci` (self-scan) | Exit 1, 9 critical — all false positives of the Python constant-time-compare detector (`sig`, `token` parser variables) |
| `shellcheck -S warning` | 9 warnings in `ubs`, 93 across modules (CI gates `-S error` only) |
| Version-tag drift, SHA256SUMS, module checksums | All pass at the start of the session (the JS SARIF fix now drifts `ubs-js.sh` vs `v5.3.13` until the next tag) |
| Single-file scan latency | 4.6 s (JS), 5.8 s (Python); README: "< 1s" |
| 15-file repo (this repo) | 9.1 s |
| 514-file, 29K-line fixture tree (10 languages) | 40 s; README: "3.2s for 50K lines", "10,000+ lines/second" (measured ≈ 730 lines/s) |
| Real Python project, 597 files, 124K lines | 143 s; README: "200K lines: 12s" |
| Real TS monorepo, 407 files, 407K lines (`--only=js`) | 300 s module timeout, reported as `files: 0, critical: 1`, 840 MB RSS; README: "Memory usage <100MB" |
| Same repo without `UBS_SKIP_SIZE_CHECK` | Refused: the size guard measures the whole tree (1142 MB) even with `--only=js` |
| JS module alone on 407 TS files | > 900 s (killed); without type narrowing > 900 s; without type narrowing and the security/taint category 417 s; CPU/wall ≈ 0.18 (fork/exec-bound) |
| Beads | DB was schema-0 (`bd` format); rebuilt from JSONL after normalizing 69 dependency records; 20 open / 3 in progress / 152 closed before the bridge-plan beads were added |
| Open GitHub issues | 0 (16 closed in the previous 4 weeks) |

## Vision checklist

Status: WORKING · PARTIAL · STUB · UNPROVEN · MISSING. NO_BEAD = no open bead covered the gap before this audit (all now covered by the epics listed at the end).

| # | Promise (source) | Status | Evidence |
|---|---|---|---|
| 1 | One-command install; Homebrew; Scoop; Nix; Docker | PARTIAL · NO_BEAD | Installer aborts under `set -e` at `install.sh:1314` (`((errors++))`) whenever `ubs` is not yet on PATH — the default first install. Scoop bucket lives outside the repo. Docker image has no `python3`, `unzip` or ast-grep, so helpers and JS/TS scans cannot run in the container. |
| 2 | Auto-detect 10 languages, concurrent modules, merged report | WORKING | `ubs:304`, `ubs:3710-3738`; verified on the fixture tree |
| 3 | Sub-5-second feedback, <1 s per file, 10K+ lines/s, <100 MB memory | MISSING · NO_BEAD | See evidence table. Meta-runner overhead alone ≈ 1.7 s (shadow-workspace copy, fan-out). |
| 4 | `--format=text\|json\|jsonl\|sarif\|toon` in the meta-runner and each module (README:106) | PARTIAL · NO_BEAD | Meta-runner json/jsonl/sarif real; toon delegates to external `tru` and silently emits JSON labelled toon when absent. Modules: 0 of 10 implement toon/jsonl; 8 silently fall back to text. No `--format` validation. JS/TS SARIF was broken since v5.3.12 (fixed). |
| 5 | Exit code contract 0/1/2/3 | WORKING | `ubs:3565`, `:3789`, `:3890`; unknown flags become scan targets and exit 2 with a misleading message |
| 6 | CLI reference (README §Command-Line Options) | PARTIAL · NO_BEAD | Absent from the meta-runner: `OUTPUT_FILE`, `--include-ext`, `--rules=DIR`, `--no-color`, `--list-categories`. `--exclude` means languages in code, paths in README. `CI=true` does not disable auto-update; `FORCE_SELF_UPDATE` is hard-coded 0; `UBS_SKIP_TYPE_NARROWING` env is clobbered. |
| 7 | Supply chain fail-closed for modules and helpers; signed releases; verified self-update | PARTIAL · NO_BEAD | Release-pinned install + minisign + verified self-update are real. Helper mismatch during a scan warns, re-downloads and continues; modules never verify helpers; `SHA256SUMS` covers only `ubs` + `install.sh`; installer prefers an unverified `./ubs` in CWD; dependency binaries downloaded without checksums. |
| 8 | Inline `ubs:ignore` placements "across all 10 languages" (README:1287-1294) | PARTIAL · NO_BEAD | GH #91 semantics implemented in JS only; every module's `count_lines()` is same-line-only, so a previous-line marker hides the sample but still counts. |
| 9 | `normalize_severity()` in each module (README:1413) | STUB · NO_BEAD | Exists in `ubs-swift.sh:93` only |
| 10 | Cross-language detector parity | PARTIAL · NO_BEAD | Taint in all 10 (3 architectures, no function scoping); deep_guard 3/10; type narrowing 5/10; constant-time detector 4/10 with only Rust carrying the GH #85 fix; ast-grep rule packs rust 77 / go 64 / py 52 / js 37 / java 34 / cpp 32 / ruby 28 / csharp 4 / swift 1 / elixir 0 |
| 11 | "Universal AST Adoption epic complete" (README:221) | PARTIAL · NO_BEAD | Elixir has no ast-grep integration; Swift has one generated rule; C# four |
| 12 | Blended false-positive rate 8-12% | UNPROVEN · NO_BEAD | No measurement exists; the project's own gate fails on 9 findings that are 100% false |
| 13 | 12+ coding agents auto-configured; Claude Code save hook + `git_safety_guard.py` installed | PARTIAL · NO_BEAD | 10/12 real (TabNine, Replit detect-only). The Claude hook is never registered in `.claude/settings.json` and reads non-hook env vars; `git_safety_guard.py` is never installed. `--uninstall --non-interactive` cannot work (flag order); guardrail removal is a no-op that prints success. |
| 14 | `--staged` / `--diff` quick scans | WORKING (diff untested) | `ubs:1022-1145` |
| 15 | Shareable reports with permalinks in text/JSON/SARIF | WORKING (thin) | Permalinks text-only; stdout JSON has no `git.*` block; HTML shows a zero baseline column without `--comparison` |
| 16 | `--category=resource-lifecycle` | PARTIAL | Force-selects csharp which ignores the filter; 4 modules honor it |
| 17 | `--profile=strict\|loose` | PARTIAL | loose honored by 2/10 modules |
| 18 | Custom ast-grep rules `--rules=DIR` | MISSING at meta level | Modules accept it (except elixir); `ubs` never parses it |
| 19 | `.ubsignore`, default ignores, size guard | WORKING (rough edges) | Size guard ignores `--only`; `bin`/`obj`/`env` blanket-ignored; `.next` not ignored; `node_modules/.bun` layout scanned by the JS module |
| 20 | `ubs doctor`, `ubs sessions` | WORKING | |
| 21 | Opt-in auto-update, off in CI | PARTIAL | `CI=true` env not honored |
| 22 | Test suite and CI | PARTIAL | Manifest green; `run_all.sh` and the full workflow were red; installer tests invoked by nothing; 48% of cases assert totals only; one case pins a rule id; zero tests for `--diff`, `--beads-jsonl`, jsonl, `--rules`, `doctor --fix`, tamper refusal, ast-grep provisioning, macOS/Windows |
| 23 | Docs as source of truth for agents | PARTIAL · NO_BEAD | AGENTS.md: version 5.0.7, 9 languages, 10 of 14 helpers, exit codes without 2/3, `master` push instruction. SKILL.md: 8 languages, `ubs:ignore-next-line`. modules/README.md: no elixir/jsonl/toon. README: "v5.0"/"v4.4", "No temp files created", "<100MB", speed table, uninstall one-liner, `--exclude` semantics |
| 24 | Shell/Bash scanning | MISSING · NO_BEAD | The tool is 77K lines of Bash and cannot scan itself |
| 25 | Windows (Git Bash/WSL) and macOS | UNPROVEN | No CI outside ubuntu-latest |
| 26 | Version-tag drift never bites users | WORKING (fragile) | Auto-issues fired 3 times in 3 weeks (#83, #86, #97) |
| 27 | No dead code / tech debt | PARTIAL · NO_BEAD | `ubs-java.sh:3997-5854` is 1,857 dead lines behind `if false`; Java also scans `.swift` and double-counts Swift guard warnings; 4 `count_lines` bodies, 5 `json_escape` bodies, 7 file-count implementations |

## The five questions

1. **Working:** language detection, concurrent dispatch, jq merge; text/json/sarif/jsonl at the meta level; exit-code contract incl. exit 3; `.ubsignore` and size guard; `--staged`; doctor/sessions; release-pinned verified install and self-update; module lazy download with checksum verification; 440-case manifest; a large real detector surface (taint in all 10 languages, 300+ generated ast-grep rules, resource-lifecycle helpers for 7 languages, TS/Rust/Kotlin/Swift/C# type narrowing, React hooks analysis); Homebrew formula generation; Nix flake; signed OCI images.
2. **Not working / not implemented:** the performance envelope; five documented CLI flags; per-module toon/jsonl; suppression semantics outside JS; severity normalization; detector parity; the Claude Code save hook and safety-guard install; first-install abort; uninstall; Docker runtime deps; shell scanning; helper fail-open; docs drift; the full test-suite workflow.
3. **Blocking:** no performance instrumentation; no cross-module abstraction (fixes never propagate); tests strong on fixtures and weak on the meta-runner, installer and supply-chain paths; docs written ahead of code with no verification step.
4. **Would the pre-existing open beads close the gap?** No. They were 12 TOON-installer tasks (six duplicated as "legacy" copies), robot-docs/schema, a crates.io publish for another repo, a dependency update, and stale "study the repo" tasks.
5. **Goals with no bead:** items 1, 3, 4, 6–13, 18, 22–24, 27 — every gap that matters. Now covered by the epics below.

## What changed on 2026-09-02

- Beads: dependency records normalized for `br` 0.5.7; database rebuilt (old family kept as `.beads/beads.db.bad_20260902T032752Z*`); 11 epics + 82 tasks created for the bridge plan and refined over five review rounds (release labels `release-5-4` … `release-6-0`).
- Test gates: `run_all.sh` sorts rule ids under `LC_ALL=C`; `rust-loop-scope-collection-push-clean` lost a stray `security` tag; both goldens regenerated.
- Fix: `modules/ubs-js.sh` SARIF mode scans base rules and per-grammar variants separately and merges runs (`run_sarif_rule_pack_scan`).
- Dependency refresh: ast-grep 0.45.3 (+digests), jq 1.8.2, ripgrep 15.2.0, uv 0.12.9, syft v1.51.1, cosign v3.1.3 / cosign-installer v4.1.2, GitHub Actions majors, toon_rust v0.2.4, nixpkgs 26.05, Debian trixie; `SHA256SUMS`/`MODULE_CHECKSUMS` regenerated. Verified: ast-grep 0.40.1 and 0.45.3 produce identical rule-pack results on the JS and Rust corpora.

## Bridge plan epics (beads)

| Epic | Bead | Scope |
|---|---|---|
| A Engine core | `ultimate_bug_scanner-0xjg` | shared library, `ubs_core`, contract v2, ten module ports, suppression index, conformance harness |
| B Meta-runner truthfulness | `ultimate_bug_scanner-cvxv` | documented flags, `--exclude` semantics, env contract, file-list pipeline, error envelope, fingerprinted baselines |
| C Performance | `ultimate_bug_scanner-q150` | profiling + bench with CUSUM alarms, necessary-literal prefilter, Merkle cache, LPT scheduler, streaming |
| D Detector parity | `ultimate_bug_scanner-1b9j` | registry, two-tier constant-time vocabulary, deep-guard/narrowing everywhere, rule packs, dataflow taint engine, FP corpus + conformal confidence, self-gate |
| E Supply chain | `ultimate_bug_scanner-7vb8` | verified helpers/lib, fail-closed scans, `cut-release.sh`, verified dependency binaries, cosign/SLSA, tamper tests |
| F Installer | `ultimate_bug_scanner-oaci` | first-install abort, flag order, Claude hooks, uninstall, hygiene, installer tests in CI |
| G Distribution | `ultimate_bug_scanner-s2k5` | Docker runtime deps, Scoop, macOS, Windows, Nix smoke |
| H Test infrastructure | `ultimate_bug_scanner-aom8` | one workflow with sharding and OS matrix, goldens bot, rule-id assertions, nightly, shellcheck warnings, SARIF regression cases |
| I Languages | `ultimate_bug_scanner-7mga` | Bash module (self-hosting), Kotlin split |
| J Docs and process | `ultimate_bug_scanner-jtst` | corrected docs now, generated sections + claim checker, changelog discipline, beads hygiene, Python pin decision |
| K Agent ergonomics | `ultimate_bug_scanner-7qy7` | robot-docs/schema, findings parity, explain, `ubs serve` daemon, toon exit 2 |
