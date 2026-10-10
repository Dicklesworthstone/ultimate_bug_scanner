# Ultimate Bug Scanner – Work Log & TODOs

All tasks reference Beads issue IDs so progress stays traceable. Update this list whenever you discover new work or finish a sub-task.

## 1. Root UBS triage (ultimate_bug_scanner-9dk)
- [x] Run per-language UBS scans to get baseline counts. (`./ubs --format=json --ci --only=<lang> .`)
- [x] Record baseline in notes/root-scan-2025-11-16.md.
- [ ] Triage JS critical categories (group by filename / category, identify quick wins).
- [ ] Create Beads sub-issues for JS hotspots (null safety, math pitfalls, parsing, security).
- [ ] Repeat triage for Python, Go, Rust, C++, Java, Ruby, and Swift after JS plan is in place.

## 2. Manifest coverage expansion (ultimate_bug_scanner-d5z, ultimate_bug_scanner-aqd, ultimate_bug_scanner-o3l)
- [x] Go: enable buggy/clean manifest entries with `--only=golang` + substring requirement.
- [ ] Add substring/rule expectations for Rust/C++/Java/Ruby fixtures once ready.
- [ ] Create dedicated manifest cases for each language (buggy + clean).
- [ ] Add edge-case directories (unicode/timezone/fp) with explicit thresholds.
- [ ] Wire `test-suite/run_manifest.py` into CI so regressions fail PRs.

## 3. Framework & module hygiene (ultimate_bug_scanner-dmo)
- [ ] Fix `modules/ubs-js.sh` file counting so both module + meta-runner agree.
- [ ] Audit other modules for similar counting or summary issues.

## 4. Documentation / developer experience
- [ ] Merge Beads instructions + manifest workflow into README sections as they mature.
- [ ] Ensure AGENTS.md references Beads issue IDs whenever handoffs occur.

## 5. Resource lifecycle fixtures (ultimate_bug_scanner-6ig)
- [x] Investigate `modules/ubs-python.sh` single-file runs (resource_lifecycle) reporting zero files/warnings.
- [x] Do the same for Go and Java fixtures (confirm detection logic).
- [x] Restore warnings so `--fail-on-warning` triggers and manifest passes.

## 6. Resource/Shareable follow-up (tracking new CLI/features)
- [x] Document lifecycle heuristics + shareable workflow in README/test-suite docs.
- [x] Update per-language module help text to mention category filter env support.
- [x] Tighten manifest expectations for python/go/java resource cases (assert new messages).
- [x] Add automated regression that runs `ubs --report-json/--html-report/--comparison` and validates outputs.

## 7. AST migration backlog
- [ ] See beads `ultimate_bug_scanner-mma`, `ultimate_bug_scanner-5wx`, `ultimate_bug_scanner-6x4`, `ultimate_bug_scanner-41t`, `ultimate_bug_scanner-7g7` for the plan to move lifecycle heuristics + non-AST modules onto ast-grep/semantic helpers.

_Last updated: 2025-11-16 22:58 UTC_

## 8. October 2026 execution checklist

The user requested implementation of the reality-check plan and all remaining Beads, with a complete granular TODO. Sections 1–7 above are historical. Beads remain authoritative for claims, ownership, dependencies and cited acceptance evidence. An unchecked item is unfinished; a plan or expected-red probe does not complete an implementation. This active checklist retires to history when its tasks are verified.

### Runtime and immediate correctness

- [ ] `mj1j.1`: extend the existing Python-floor suite; run real CPython 3.9 imports, JS/Python/non-JS positive and clean CLI cases, JSON/SARIF and usage-error controls; retain baseline logs.
- [ ] `mj1j.2`: repair unsupported runtime constructs without raising the floor or removing analyzer registration; re-run floor and current-interpreter semantic tests; update verified digests/version.
- [ ] `mj1j.3/.4`: independently probe and fix JVM redirect/path binding, safe-name identity bypass, literal reassignment, branches, selected helper summaries, dominating validation and invalidation; preserve exact public IDs.
- [ ] `mj1j.5/.6`: independently probe and fix Ruby URL/path facts across assignments, methods/blocks and selected validators; cover both observed errors, lexical decoys and scope isolation.
- [ ] `mj1j.15/.16`: qualify finished but dormant Java/Ruby/JS checks individually, wire ordinary CLI policy/counting, and test exact IDs, clean cases, deduplication, suppressions/profiles and JSON/SARIF agreement.

### Native language semantics and ownership

- [ ] `mj1j.7/.8`: Swift helper/guard proof for exact redirect/path values, literal kills, optional bindings and unrelated guards; actual CLI regressions.
- [ ] `mj1j.9/.10`: Elixir selected clauses, rebinding, pipelines, case/cond joins and sink-specific validation; explicit unsupported/budget states.
- [ ] `mj1j.11/.12`: bounded C/C++ binding/guard proof with macro, overload and preprocessing uncertainty; preserve lifecycle checks and avoid mandatory compiler dependencies.
- [ ] `mj1j.13/.14`: native Kotlin coroutine/cancellation/job and null-safety rules; structured ownership, dispatcher and shadowing controls; no blanket launch/!! warnings.
- [ ] `mj1j.17/.18`: Ruby handle/thread and Kotlin resource ownership; normal/exception exits, transfer and double release; joined Ruby collections and Kotlin use{} clean controls.
- [ ] `mj1j.19/.20`: Swift FileHandle/task and Elixir File/Port/Task per-binding obligations; defer/callback/supervision semantics; remove only proven equivalent aggregate alerts.

### Broader high-value detector families

- [ ] `mj1j.21/.22`: selected JDBC/Kotlin, ActiveRecord, Dapper and Ecto SQL provenance/actual parameter binding; interpolated-query negatives and genuine bound-query controls.
  - 2026-10-10: bounded raw Ecto SQL execution now follows request provenance through aliases, local helpers, iodata and branch joins; actual same-file SQL-backed repositories and selected imports are supported. Independent unsafe/bound-value controls precede implementation. Lazy stream consumption, query macros, external repository resolution, Kotlin/JDBC and Dapper remain open; this slice does not close the umbrella.
- [ ] `mj1j.23/.24`: framework-identified explicit TLS/JWT/CORS/cookie/CSRF/output hazards for Spring/Ktor/Rails/ASP.NET/Phoenix; unresolved config stays unknown.
- [ ] `mj1j.25/.26`: configured client deadlines and inherited cancellation context; bounded APIs, ownership and safe defaults; no missing-timeout-token heuristic.
- [ ] `mj1j.27/.28`: actual crypto/comparator API identity and secret context; public tokens/checksums, shadowed functions and strong alternatives remain clean.
- [ ] `mj1j.29/.30`: native failure-bearing results, rescue/tuple/future/async observation; logging/recovery/return controls and no duplicate cancellation alerts.

### Useful new ecosystems and project configuration

- [ ] `mj1j.31/.32`: bounded PHP request-to-sink module with PDO/mysqli binding and safe output contexts; coherent detection/contract/registry/ignore/profile/format/integrity integration.
- [ ] `mj1j.33/.34`: PostgreSQL SQL lexer/parser and explicit function/privilege hazards; comments/identifiers/dollar quotes, dialect/version and dynamic-unknown controls.
- [ ] `mj1j.35/.36`: HCL provider/resource-specific rules and selected literal/local provenance; unresolved variables/modules are unknown; safe/contradictory configuration controls.
- [ ] `mj1j.39/.40`: validated persistent scan configuration with defaults/project/environment/CLI precedence; excludes/languages/rules, explicit errors and shared cache/daemon policy identity.

### Existing work, gates and delivery

- [ ] `mj1j.37/.38`: resolve the exact full ShellCheck gate using real control-flow fixes or narrowly justified annotations; no severity downgrade or blanket suppression.
- [ ] `mj1j.41` and D7 (`1b9j.7`): independent held-out labels/splits, explicit precision/recall/FP denominators and intervals, unknown confidence, valid filtering/conformal semantics and SPRT budgets; real corpus/nightly evidence.
- [ ] `mj1j.42` and J1 (`jtst.1`): all registered languages and effective counted/advisory/gated/unavailable coverage; real CLI provenance, stale-evidence refusal and idempotent generated docs.
- [ ] D5/D6 (`1b9j.5/.6`): complete original ordinary-CLI inventory and selected-flow acceptance using receiver probe evidence; preserve owners and do not close umbrella goals on one slice.
- [ ] D9/H6 (`1b9j.9`, `aom8.6`): effective-rule smoke coverage and mathematically valid selection; binding-preserving metamorphic controls; explicit uncovered witnesses where infeasible.
- [ ] C6/C7/K4 (`q150.6/.7`, `7qy7.4`): preserve streaming RSS and edited-source latency targets; measure frozen cold/warm/changed-source cases, dependency/policy invalidation and live incumbents for competitive claims.
- [ ] G3/G4/G5/G6 (`s2k5.3/.4/.5/.7`): real macOS/Windows/Nix/full-workflow observations, runtime/tool failures and current release journeys; platform files alone are not proof.
- [ ] E5/F7/H8/H4 (`7vb8.5`, `oaci.7`, `aom8.8/.4`): verified signatures/provenance, installer/daemon/encoder assets, actual user journeys and nightly gates; require exact authorization before deletion/uninstall execution.
- [ ] `a1oa`: finish JS operator lexical-decoy regressions with actual findings and no strings/comments/regex false positives.
- [ ] After substantive code changes: prescribed full ShellCheck, checksum regeneration, test suite and SHA256SUMS verification; preserve tests/goldens and disclose environment/cleanup/platform limits.
- [ ] Before each closure: fresh verification against original acceptance, exact source/revision and artifact references; distinguish solo re-verification from independent review; run `br dep cycles` and sync the authoritative JSONL.

_Execution started: 2026-10-06 21:07 UTC. Current task: `ultimate_bug_scanner-mj1j.1`._
