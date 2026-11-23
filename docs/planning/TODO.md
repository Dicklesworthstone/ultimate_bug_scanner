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
  - 2026-11-11: verified Servlet parameter/header arrays, maps and enumerations now carry contents through selected extraction, aliases, helpers and iteration into path, redirect, response-header and outbound-URL checks. Native collection metadata remains clean, while Kotlin extensions must prove applicable signatures before borrowing collection or String identity. The final 584-observation corpus passes (the old helper missed 326 unsafe outcomes and produced 40 false alarms), alongside 71 native regressions and 16 independent overload checks. Final category-scoped Kotlin module JSON/SARIF matches 45 files and 105 critical findings; the broader runner preserves findings but remains partial on two mutable-extension SQL fixtures. Field/default initialization, arbitrary heap/cross-file framework resolution and full-run acceptance remain open.
  - 2026-11-06: selected Servlet getters and Ktor call/request member properties now use declared API identity across redirect, path, response-header and outbound-URL analysis. Aliases, bounded same-file helpers, collection extraction and local lookalike controls have independent regressions and native scanner report/cache checks. Unmodeled request field initialization reports incomplete; implicit Ktor route receivers, extension-only APIs and broader cross-file framework binding remain open. Public JVM wrapper qualification remains outstanding in the retained test environment, so the umbrella remains open.
  - 2026-11-10: Kotlin synthetic Servlet properties (`queryString`, `requestURI`, `pathInfo`, `servletPath`) now share the verified getter source model across redirect, path, response-header and outbound-URL checks. Nullable receivers, aliases, selected helpers and String sanitizers retain their own semantics; local lookalikes and same-named extension calls do not acquire Servlet identity. Executable property field initializers and parameter defaults report incomplete. Independent property/control probes and ordinary JSON/SARIF, suppression and cache tests cover this slice; arbitrary object fields, hierarchy dispatch and cross-file framework resolution remain open.
- [ ] `mj1j.5/.6`: independently probe and fix Ruby URL/path facts across assignments, methods/blocks and selected validators; cover both observed errors, lexical decoys and scope isolation.
  - 2026-11-11: Rack/Rails body reads, output-buffer aliases, cookies and selected request-map extraction/iteration now feed the shared path, outbound URL, SQL, execution, redirect and response-header policies. Unknown IO operations report incomplete; local lookalikes, shadowed accessors and fixed values retain clean controls. Independent review and 83 labelled content cases accompany 433 targeted tests (two existing skips), six incomplete-boundary cases, and native JSON/SARIF, selection, suppression and cache checks. General mutable-Hash precision and body cursor/EOF semantics remain open; this is a bounded source-coverage slice.
  - 2026-10-30: selected `Pathname` receivers now expose filesystem traversal through reads, writes, directory/metadata operations and helper flow. Independent baseline: 18 unsafe misses and 11 passing safe controls; all 29 cases now pass, together with 447 Ruby tests and 32 ordinary module/runner JSON/SARIF scans. Published on main in `ec507b7a`; broader Ruby coverage remains open.
  - 2026-11-10: open redirects through live response-header aliases and selected helpers now use the same receiver identity as header-injection analysis. `Location` assignments, setters and bounded one-map updates preserve source values, possible keys at joins, exact duplicate-key overwrites and sink-specific validation. Ordinary/request hashes, detached copies and shadowed accessors remain distinct. Opaque or mutated maps, computed keys and case/type key collisions report incomplete when their response effect cannot be established. Independent source/clean/boundary cases and public format/cache tests cover this slice; general mutable-hash and response read-after-write analysis remain open.
- [ ] `mj1j.15/.16`: qualify finished but dormant Java/Ruby/JS checks individually, wire ordinary CLI policy/counting, and test exact IDs, clean cases, deduplication, suppressions/profiles and JSON/SARIF agreement.

### Native language semantics and ownership

- [ ] `mj1j.7/.8`: Swift helper/guard proof for exact redirect/path values, literal kills, optional bindings and unrelated guards; actual CLI regressions.
- [ ] `mj1j.9/.10`: Elixir selected clauses, rebinding, pipelines, case/cond joins and sink-specific validation; explicit unsupported/budget states.
  - 2026-10-10: selected anonymous functions now preserve lexical captures and argument flow through direct invocation and synchronous finite-list Enum callbacks. Request SQL/path/redirect effects and local resource cleanup share the callback frontend; unused closures do not execute. Dynamic/deferred callbacks and external code evaluation remain explicit incomplete boundaries, so the broader language/framework work stays open.
- [ ] `mj1j.11/.12`: bounded C/C++ binding/guard proof with macro, overload and preprocessing uncertainty; preserve lifecycle checks and avoid mandatory compiler dependencies.
- [ ] `mj1j.13/.14`: native Kotlin coroutine/cancellation/job and null-safety rules; structured ownership, dispatcher and shadowing controls; no blanket launch/!! warnings.
- [ ] `mj1j.17/.18`: Ruby handle/thread and Kotlin resource ownership; normal/exception exits, transfer and double release; joined Ruby collections and Kotlin use{} clean controls.
- [ ] `mj1j.19/.20`: Swift FileHandle/task and Elixir File/Port/Task per-binding obligations; defer/callback/supervision semantics; remove only proven equivalent aggregate alerts.

### Broader high-value detector families

- [ ] `mj1j.21/.22`: selected JDBC/Kotlin, ActiveRecord, Dapper and Ecto SQL provenance/actual parameter binding; interpolated-query negatives and genuine bound-query controls.
  - 2026-11-11: Dapper eager `ExecuteReader[Async]` and `QueryMultiple[Async]` now preserve executable SQL through verified receivers, named/static calls and captured `CommandDefinition` values; separately bound parameters remain clean. Published on main in `d1abedca`. Independent baseline: 27 missed/unsupported outcomes across 33 cases. Final C# SQL tests passed 148/148 plus 17 actual module/runner invocations for JSON/SARIF, selection, suppression, cache/edit invalidation and incomplete boundaries. Deferred queries, unsupported dispatch/overloads and broader SQL framework qualification remain open.
  - 2026-10-10: bounded raw Ecto SQL execution now follows request provenance through aliases, local helpers, iodata and branch joins; actual same-file SQL-backed repositories and selected imports are supported. Independent unsafe/bound-value controls precede implementation. Lazy stream consumption, query macros, external repository resolution, Kotlin/JDBC and Dapper remain open; this slice does not close the umbrella.
  - 2026-10-10: bounded C# Dapper text-SQL execution now follows resolved ASP.NET Core request and ADO.NET connection identities through aliases, local helpers, branch joins and sync/async calls. Actual named and Type-leading argument slots separate SQL text from bound values. Independent source labels and the missed-finding baseline precede implementation; deferred execution, CommandDefinition, multimapping, cross-file effects and remaining Kotlin/framework adapters stay open.
- [ ] `mj1j.23/.24`: framework-identified explicit TLS/JWT/CORS/cookie/CSRF/output hazards for Spring/Ktor/Rails/ASP.NET/Phoenix; unresolved config stays unknown.
- [ ] `mj1j.25/.26`: configured client deadlines and inherited cancellation context; bounded APIs, ownership and safe defaults; no missing-timeout-token heuristic.
- [ ] `mj1j.27/.28`: actual crypto/comparator API identity and secret context; public tokens/checksums, shadowed functions and strong alternatives remain clean.
- [ ] `mj1j.29/.30`: native failure-bearing results, rescue/tuple/future/async observation; logging/recovery/return controls and no duplicate cancellation alerts.

### Useful new ecosystems and project configuration

- [ ] `mj1j.31/.32`: bounded PHP request-to-sink module with PDO/mysqli binding and safe output contexts; coherent detection/contract/registry/ignore/profile/format/integrity integration.
  - 2026-10-10: native PHP/PHTML scanning adds six critical rules for SQL, command/code execution, includes, deserialization and output. The bounded local-flow slice includes PDO/mysqli template identity, context-specific escaping, explicit incomplete results and ordinary runner/report/cache integration. Independent unsafe and clean labels precede implementation; broader framework resolution and corpus calibration remain open, so the umbrella stays open.
- [ ] `mj1j.33/.34`: PostgreSQL SQL lexer/parser and explicit function/privilege hazards; comments/identifiers/dollar quotes, dialect/version and dynamic-unknown controls.
  - 2026-10-30: native PostgreSQL module implements selected migration function identity, search paths, PUBLIC execution privileges, transaction publication and savepoints. Independent unsafe/clean/unsupported cases precede implementation, with public JSON/SARIF, cache, suppression and selection checks. Cross-file migration ordering, deployed catalog proof, procedures, dynamic SQL and broader DML analysis remain open; this bounded slice does not close the umbrella.
- [ ] `mj1j.35/.36`: HCL provider/resource-specific rules and selected literal/local provenance; unresolved variables/modules are unknown; safe/contradictory configuration controls.
  - 2026-11-06: native Terraform scanning now covers explicit AWS administrative ingress, public S3 ACLs, unrestricted IAM identity-policy grants and disabled AWS provider TLS verification. Literal/local context, bounded JSON encoding, provider identity, incomplete outcomes and ordinary reporting/cache integration are implemented. Generated policy data sources, variables/modules, other providers and deployed-state proof remain outside this bounded slice; the umbrella remains open.
- [ ] `mj1j.39/.40`: validated persistent scan configuration with defaults/project/environment/CLI precedence; excludes/languages/rules, explicit errors and shared cache/daemon policy identity.

### Existing work, gates and delivery

- [ ] `mj1j.37/.38`: resolve the exact full ShellCheck gate using real control-flow fixes or narrowly justified annotations; no severity downgrade or blanket suppression.
- [ ] `mj1j.41` and D7 (`1b9j.7`): independent held-out labels/splits, explicit precision/recall/FP denominators and intervals, unknown confidence, valid filtering/conformal semantics and SPRT budgets; real corpus/nightly evidence.
- [ ] `mj1j.42` and J1 (`jtst.1`): all registered languages and effective counted/advisory/gated/unavailable coverage; real CLI provenance, stale-evidence refusal and idempotent generated docs.
- [ ] D5/D6 (`1b9j.5/.6`): complete original ordinary-CLI inventory and selected-flow acceptance using receiver probe evidence; preserve owners and do not close umbrella goals on one slice.
  - 2026-11-05: selected Python local closures retain live lexical cells through returned callbacks, shared `nonlocal` updates, exceptional exits and coroutine resumption. Caller-name collisions no longer supply captures; subprocess vectors, process stdin contracts and header sanitizer identities use the same cell transport. Canonical summary identities keep concrete provenance outside context keys, with bounded allocation contexts. This completes a closure-flow slice, not the broader D5/D6 acceptance work.
- [ ] D9/H6 (`1b9j.9`, `aom8.6`): effective-rule smoke coverage and mathematically valid selection; binding-preserving metamorphic controls; explicit uncovered witnesses where infeasible.
- [ ] C6/C7/K4 (`q150.6/.7`, `7qy7.4`): preserve streaming RSS and edited-source latency targets; measure frozen cold/warm/changed-source cases, dependency/policy invalidation and live incumbents for competitive claims.
- [ ] G3/G4/G5/G6 (`s2k5.3/.4/.5/.7`): real macOS/Windows/Nix/full-workflow observations, runtime/tool failures and current release journeys; platform files alone are not proof.
- [ ] E5/F7/H8/H4 (`7vb8.5`, `oaci.7`, `aom8.8/.4`): verified signatures/provenance, installer/daemon/encoder assets, actual user journeys and nightly gates; require exact authorization before deletion/uninstall execution.
- [ ] `a1oa`: finish JS operator lexical-decoy regressions with actual findings and no strings/comments/regex false positives.
- [ ] After substantive code changes: prescribed full ShellCheck, checksum regeneration, test suite and SHA256SUMS verification; preserve tests/goldens and disclose environment/cleanup/platform limits.
- [ ] Before each closure: fresh verification against original acceptance, exact source/revision and artifact references; distinguish solo re-verification from independent review; run `br dep cycles` and sync the authoritative JSONL.

_Execution started: 2026-10-06 21:07 UTC. Current task: `ultimate_bug_scanner-mj1j.1`._

## 9. November 15, 2026 source-correctness session

Current base: `a603d20fbb11508c03f916e83e566d106678ee92`. Beads remain authoritative.
The executor became unavailable during implementation. Completed source probes
are distinct from feature activation; no unfinished implementation is counted as
complete.

### Native Go environment sources (`ultimate_bug_scanner-go-environment-native`)

- [x] Read the comprehensive feedback plan, active checklist and authoritative Beads; inspect current implementation before choosing work.
- [x] Reproduce the fixed source oracle and independent corpus against current main: 16 maintained failing subcases; independent 4/15 with nine unsafe misses and two false positives.
- [x] Port native `os.Getenv`/`os.LookupEnv` import and saved-callable identity onto the existing structural call normalizer; keep value/presence slots separate.
- [x] Preserve safe SQL bindings, literal overwrites, sanitizer domains, shadowed APIs and grouping/decoder behavior.
- [x] Run all 18 maintained source methods and all 15 independent exact cases successfully.
- [x] Run the four Go source suites through the actual DSR native quality executor: 285 passed, 10 optional native/public checks skipped; a 150 KB masked-literal regression also passed.
- [x] Recover the exact recorded source/test edits after the outage; verify forward/reverse patch replay and immutable GitHub blob readback.
- [x] Preserve the corrected candidate and observed DSR receipt in the existing patch/checkpoint files.
- [ ] Finish the compiled runtime witness and real module/meta-runner JSON/SARIF matrix. The original Bead requires these before activation; no passing result was observed.
- [ ] Complete Go scratch retention without bypassing the runner's current refusal, then run the unchanged public checks.
- [ ] Activate only after the required gates; refresh canonical integrity pins, version/release handling and prescribed repository checks.
- [ ] Close the Bead only on complete cited acceptance evidence; the candidate remains unactivated.

### Pooled Python HTTP clients (`ultimate_bug_scanner-python-pooled-http`)

- [x] Reproduce the original independent 34-case baseline: 14 passed, 20 complete-empty failures.
- [x] Freeze an additional 24-case oracle with exact unsafe sites and explicit boundaries: baseline 7 passed, 17 failed.
- [x] Run seven real HTTPX mutation/deferred-execution witnesses without network I/O; all passed.
- [x] Preserve all 11 original maintained methods, add five location/capture/boundary methods, and route existing HTTP fixtures through retained temporary directories.
- [x] Add finite native-client/pending markers and initial mutation, escape, call and context hooks in the archived candidate.
- [x] Recover both source/test edits and independently verify exact forward/reverse replay and immutable blob readback.
- [ ] Implement the missing `http_call` and `consume_http` methods; the archived source is currently unexecutable.
- [ ] Complete actual constructor/method identity, URL slots, base handling and helper-factory proof.
- [ ] Complete await/task/stream consumption without reporting unused handles as reached sinks or freezing mutable receiver state.
- [ ] Run unchanged maintained/independent/native and public-format suites, then integrity/version/release gates before activation.
- [ ] Close only after the original acceptance criteria pass; baseline and native-library observations do not establish a candidate pass.

### Native JavaScript array sorting (`ultimate_bug_scanner-array-sort`)

- [x] Confirm reporting-integration Beads already have active fixes; avoid duplicating their implementations.
- [x] Inspect the current array machinery; native fill/splice/copyWithin are already active.
- [x] Compare seven scanner fixtures with actual Node behavior; identify four complete-clean misses involving sorting and callback/coercion writes.
- [x] Preserve 14 proposed regression methods, retained-artifact helper, exact fixture programs, observations and implementation design.
- [x] Verify the recovered two-hunk patch against the immutable baseline and reverse it exactly.
- [ ] Implement bounded default native sort mutation, preserving receiver aliases, holes, named properties and sanitizer domains.
- [ ] Model comparator/coercion effects or explicitly report unsupported analysis; preserve own-method identity and work limits.
- [ ] Execute the proposed regressions, existing array/heap suites and actual module/runner formats before activating or closing.

Production scanners and discovery tests remain unchanged in these checkpoint
commits. The interrupted execution environment blocks the remaining qualification;
all three functional Beads stay open/in progress.

## 10. November 20, 2026 native dataflow gaps

Original base: `06222fb6b9069ec95d2c72d6f753403613804702`; publication integrates
concurrent SQL, JavaScript array-copy and Python nested-generator work through
`e0032f0295173827fb5184a09fa1bb50fba1cac1`.
This session follows the comprehensive feedback plan and current Beads. Earlier
open source-coverage tasks were checked against active code before selecting
these three gaps.

### JavaScript synchronous array callbacks (`1b9j.6.1`)

- [x] Freeze native Node witnesses and unsafe/clean scanner cases before implementation; the initial 16-method baseline exposes 29 failed assertions/subcases.
- [x] Reuse bounded native array traversal for `map`, `flatMap` and `forEach`, including live element reads, captured length, holes, per-index map results, aliases and callback writes/throws.
- [x] Preserve `thisArg`, helper contexts, selected own methods, empty callbacks and sink-specific sanitizer behavior; unknown property/callback protocols remain explicitly incomplete.
- [x] Repair independently discovered nested callback captures without executing unused callbacks; all six outer `map`/`forEach` and inner `map`/`forEach`/`flatMap` combinations retain the unsafe write.
- [x] Pass the final 38 focused methods, including native Node witnesses and the existing 19-method `flatMap` cohort. Returned closures outside the selected escape model remain an explicit boundary.
- [x] Pass all 29 actual module/meta-runner JSON/SARIF, selected-file, suppression and cache/edit checks against the isolated original-base publication tree. The original aggregate timeout is retained; unchanged cases pass in 12/12/5-call shards, with each subprocess still bounded at 45 seconds.
- [x] Preserve concurrent native array-copy implementation and tests; the merged source cohort passes all 50 methods (the previous 38 plus 12 incoming copy regressions). DSR log SHA256: `68cfdcddb074fa74b2e2e01ac474f291c674702e122d69e90046b5d2a757714e`.
- [x] Verify the final combined 5.5.93 tree with all 12 public value/selected-file cases for dirty map, dirty forEach and clean mapping across module/runner JSON/SARIF. DSR log SHA256: `bf37c213d8949b27123020517487c5fdaad61ac53a33c73b41f5bc04136ffd1f`. The other 17 public boundary/cache cases retain their original-base passing receipts; no full-matrix merged replay is claimed.
- [x] Publish the implementation and evidence directly to `main` with canonical integrity pins and development version 5.5.91; the broader Bead acceptance remains open.

### Python aiohttp destinations (`1b9j.6.2`)

- [x] Freeze 12 source methods before implementation: 51 failed assertions on the incumbent; verify lazy construction, await, async context and task behavior with real aiohttp and no network traffic.
- [x] Track actual `ClientSession`/module API identities, aliases, selected same-file helper flow, URL slots and base URLs through deferred requests.
- [x] Distinguish session requests that support await and async context entry from the context-only module API; unused handles do not become reached sinks.
- [x] Preserve fixed destinations and payload/metadata controls; expose proxy, custom callback/transport, receiver mutation, reflection and unsupported cross-file pending requests explicitly.
- [x] Pass all 14 independent source cases and the final 29 focused methods; rerun the two unchanged subprocess checks that timed out during the interrupted broader run.
- [x] Preserve incoming nested-generator forwarding and its tests while merging the aiohttp change. The merged HTTP/callable/immediate-generator cohort passes 204 tests with 7 opt-in skips; DSR log SHA256: `df9ad803e344482a85952730012f88bc91e5b4b41686550c3d4e6d87b6da3d87`.
- [x] Observe all 39 distinct public format, selection, suppression and cache/edit cases passing: 12 unsafe/context/base calls on the original frozen source, then 12 safe/suppression and 15 partial/module-context/cache calls on the merged source. Merged logs: `6f3191c173ba96e150509e809e1c72ec995954f1051d139d22ec19fc7adec0df`, `e02f3cfc6c2d998821fbd8be0c528c3626e21796ed96a66d281beb0867edf0e2`.
- [x] Correct new test oracles to actual awaited source columns and the documented optional empty runner findings field; retain both failed receipts. Unsafe reports still require their canonical findings, and safe reports require exact empty scanner arrays, zero totals, successful status and exits. The added assertions also pass against the retained safe reports (`9be1c1d49d753e4963278dbcf23c8ac2daa79a20fcd71f5d71247b7906555ef1`).
- [x] Publish the verified implementation and evidence directly to `main` with development version 5.5.93 and final combined integrity pins.

### Go formatted input (`1b9j.6.3`)

- [x] Reproduce missing native `fmt.Scan*`, `Fscan*` and `Sscan*` destination writes before implementation, including incorrect count/error payload propagation.
- [x] Add stdlib identity and bounded builtin text destination proofs, pointer aliases, selected helpers, weak writes and clean result slots; preserve fixed inputs and bound SQL.
- [x] Refuse custom Scanner/readers, encoded/dynamic formats, global destinations and unproved type/dispatch protocols explicitly; guard native source capabilities when stored or replaced.
- [x] Verify package/local builtin-type shadow controls and compile a real Go witness with retained build files. The final focused source/native run passes 18 methods without skips.
- [x] Run the independent 14-case review: 13 precise outcomes pass and a callable replaced during argument evaluation remains explicitly incomplete, never silently clean.
- [x] Pass the final four Go suites against the final shared source guards: 337 passed, 15 opt-in skips. DSR log SHA256: `c467645dea6ebc933444fd9b86df9e1eb3ef8e15eaa2783ced656e0301454526`.
- [x] Observe all 32 distinct module/meta-runner JSON/SARIF/selection cases passing. The two full public methods retain failed timeout receipts: 15 unsafe/metadata and 13 clean/boundary cases passed there; the exact missing saved/meta JSON case and three encoded-boundary cases passed unchanged 45-second replays. Replay log SHA256s: `ea426eb6d643c2a726c21379563e3aade5b8d3636c76584ad2cd8832ecc3a4b0`, `00f7f25f2132dac333ecc25a11af9444cb6c0d2b83365636943c9fc25e04f776`.
- [x] Publish the verified implementation and evidence directly to `main` with refreshed canonical pins and development version 5.5.92.

### Combined qualification and tracking

- [x] Preserve historical Beads content, restore one missing historical comment identity required by the Beads importer, and add the three scoped implementation tasks; blocking dependencies are acyclic.
- [x] Retain failed and interrupted test attempts; execution-environment stalls and killed processes are not passing evidence.
- [x] Verify the JavaScript publication's combined module/helper/SHA256 pins, runner syntax and whitespace after preserving concurrent Python generator changes. DSR log SHA256: `db6a583422cee43bfd426cdae930cb864cabeb6e08bf625895724093b5844d34`.
- [x] Verify final combined module/helper/SHA256 pins, runner syntax and whitespace for all three features on development version 5.5.93. DSR log SHA256: `2e21b47c566827ce263acd0713fe644aa179d08896b4d638a46e648b831be323`.
- [ ] Complete touched-source self-scan and the prescribed full repository suite. Final combined-tree attempts are retained and do not establish a pass:
  - Staged-source self-scan selected the three modified analyzers after the repository's test-suite ignore rule, started Python scanning, then timed out after 90 seconds (exit 124) without a completed JSON report. DSR log SHA256: `ad99eff75946af7e63cb3f4c517b7e375b6f95164581b6977863baf2b1cc6b31`.
  - The prescribed `test-suite/run_all.sh` passed its integrity and generated-rule inventory steps, reproduced missing buggy/clean Swift fixture pairs in the rule-quality harness, and reached its 180-second aggregate limit during unit discovery (exit 124, observed duration 182.253 seconds). Discovery under uv-selected CPython 3.14.10 reported errors and a failure before interruption; final per-test tracebacks were not produced, so these are unresolved and are not attributed to a particular cause. The inherited no-deletion guard and retained temporary directories were active. DSR log SHA256: `982a80caa07904685580056ea86b671a90ee51fd87e263e21fab21e77d705e9c`.
- [x] Record unresolved whole-repository and release gates without closing the D6 or release umbrellas. The prescribed full ShellCheck process was killed after about 100 seconds without diagnostics; no lint pass is claimed (log SHA256 `fd3acc0c811ea35ba92a919db4fe88e1ea0e737d912bd19d95be19bab141d8cd`). Scoped Beads retain delivered feature evidence and remaining boundaries; no release tag or full qualification is claimed.

## 11. November 20, 2026 continuation: native callback and input transport

Base: `c026e11535a5bd54d0f02e9c9a6f8c63353d7945`. The plan, Beads and
active implementations were checked again before selecting these gaps.

### Python deferred HTTP origins across selected modules (`1b9j.6.4`)

- [x] Freeze helper-returned request cases before implementation: 19 aiohttp subcases fail the old foreign-origin guard; the missing-owner guard also exposes an unsafe bypass. Existing HTTPX, requests and urllib controls remain valid.
- [x] Share selected-project AST ownership across all pending HTTP contracts. Preserve the defining helper's path, line, column and suppression context through returns, forwarding, await and supported context consumption. Missing or foreign project identities remain explicitly incomplete.
- [x] Verify actual aiohttp 3.14.5 and HTTPX 0.28.1 behavior without network traffic. The HTTP source cohort passes 79 tests with five opt-in skips; DSR log SHA256 `d3a0bc8772fe218085f436cfaebcd7a30c23bb7377043418494d539f92820446`.
- [x] Pass all 27 planned public module/runner JSON/SARIF checks on isolated development version 5.5.94: returned aiohttp await, HTTPX stream, safe/unused/suppressed handles, findings retained during partial analysis and cold/warm/helper-edit cache behavior. Exact locations, totals, statuses and exits are asserted. DSR log SHA256 `927b81ed876b6b1583d2c793aa545648d8588edc33e49041543d1ea8abbbec69`.
- [x] Verify canonical module/helper/SHA256 pins, runner syntax and whitespace. DSR log SHA256 `50f09ec7dcb995beb31b7d09f18f06dc53e43d1c60cce2fa3fbdee321e769f7d`.
- [x] Retain the failed shared-checkout public receipt: it correctly rejected stale pins before its first case; the passing matrix uses the isolated pinned publisher without bypasses.
- [ ] Resolve broader module/call-summary qualification. The 491-test cohort reports 16 skips and three failures: recursive global override and argparse delayed-generator expectations reproduce unchanged on clean `c026e115` (baseline log SHA256 `15e43affbc9acb23d2246085c3b0f4c100a9969a76b4bd938beb3134e74328d1`); an embedded staged CLI check refused the shared checkout's stale pins. Neither the whole cohort nor the full-repository/release gates are claimed passing.

### JavaScript native reductions (`1b9j.6.5`)

- [x] Freeze 14 native witnesses and exact scanner outcomes: the incumbent has five unsafe misses and four clean-control false positives, all incorrectly reported as complete.
- [x] Implement `reduce` and `reduceRight` through the common native array traversal and callback summaries, preserving accumulator identity, strong replacement, sparse directional traversal, seed semantics, source mutation, callback writes and throws.
- [x] Pass all 56 focused source/native methods, including existing map/forEach/flatMap behavior and the 18 new reduction methods. DSR log SHA256 `3021451279f884534137365c0a918c69fde251a78bb96ef115c2b1d4e115208d`.
- [x] Pass an independent 21-case source/native corpus, including mutable accumulator aliases, live shrink/regrow/shift/unshift traversal, finally/throw paths and own-method evaluation order. Exact findings and complete status match every case; DSR log SHA256 `4bb880f903f17539634d22ef28ff44e82d50f130bd05381c1c00e5b226a94e85`.
- [x] Pass all 17 planned public calls on pinned development version 5.5.95: 12 module/runner JSON/SARIF unsafe, clean and partial/selection checks plus five cold/warm/edit/suppression checks. The formats replay log SHA256 is `b40747fa2de6b50206f5d36ad50d3b63c9cb498be7985a8710c65e234cea17df`; cache checks passed in retained initial receipt `js-reduce-public.jWk7sIyy`.
- [x] Retain the initial four clean-format failures caused by the correct existing empty-catch warning. Replace the empty catch in that new fixture with an observable fixed output, verify its exact native output, and rerun all 12 format calls without changing production code or weakening assertions.
- [x] Publish the implementation directly to main with version 5.5.95 and canonical integrity pins; syntax and whitespace pass. Integrity DSR log SHA256 `fafd5570f1a0f182d9996d897e09db393405f13911021dc861b00d073f2a8edc`. Unknown callbacks, ambiguous defaults/this/escaped contexts and opaque array property protocols remain explicit; predicate-based array operations are outside this slice.

### Go buffered input and native Reader payloads (`1b9j.6.6`)

- [x] Reproduce complete-clean misses through Scanner.Text, aliased Reader.ReadString, io.ReadAll(os.Stdin) and JSON decoding from stdin, plus a metadata false positive on a literal reader. Real Go 1.24.4 witnesses distinguish pre-Scan empty text, scanned stdin and fixed text.
- [x] Add a shared native Reader capability for stdin, strings/bytes readers and bufio receivers. Preserve Scanner lifecycle, saved methods, aliases, distinct helper allocations, input payload slots and clean metadata; reuse the proof in ReadAll, JSON/XML decoders and fmt scanning.
- [x] Pass four Go suites and three actual Go compiler witnesses: 380 tests with 16 opt-in skips. DSR log SHA256 `c4dcd8047b9ca4e2819ae73ff71bef67b1dbd4c42994dcd837de39961921ac1e`. Preserve selected-helper fixed-point bottom until its Reader identity is available.
- [x] Independently pass 19 supported source cases and all 21 native witnesses, then three selected-helper source/native follow-ups on the final implementation. Preserve two real failures where incomplete analysis loses earlier findings; those motivate the separate `1b9j.6.8` change, not a claim that the full independent review passed.
- [x] Pass all 32 public module/runner JSON/SARIF combinations on the pinned reader tree, including exact locations/counts, pre-Scan and metadata cleanliness, suppression, selection and explicit custom/mutation boundaries. Data log SHA256 `3311cbc3f0e1f3a5cd8386258d0ddb0f1f98526a5cf71c5e106b49abb0f4104e`; controls log `381f4203618e8e66c153c9af430a167a3043bd51dfb31627eb05d83509589a44`. Publisher cache/selection log `3365b49badb89e29bd837ff49629b83b30521a58d285ccb5ced89f09b6f01ff3`.
- [x] Correct the intended native safe fixture's missing strings import while preserving its body/assertion; retain unresolved and source-producing local-lookalike controls. Correct the new SARIF test's assumption that complete legacy runs require optional invocation metadata; partial reports still require failed invocation/error metadata and exit 2. Keep all initial failed receipts.
- [x] Preserve concurrent SQL changes through `8dbd2999`, refresh canonical integrity and development version 5.5.98, and verify syntax/whitespace. Merged integrity log SHA256 `3dc4fe26e03dac75cf4b868a4f6412a240ae38d644b8d06d7661475f6831cdc5`.
- [x] Pass all 32 unchanged public combinations again on that combined tree, plus eight unsafe/partial smoke calls (40 total); DSR log SHA256 `b542ed79a6f0bd8b1812487ec6cb1f58c32232b3dda148341ca6f8824fe56ba5`. Preserve the later HTTPX prepared-request commit `896158b4` for publication, with the exact same Go source/tests and canonical development version 5.5.99.
- [ ] General mutable backing-buffer aliases remain outside this bounded Reader model; native destination/receiver mutation, unknown readers/splitters and unsupported handle transport remain explicit boundaries. Broad repository/release qualification is separate.

### Rust executable provenance (`1b9j.6.7`)

- [x] Freeze 21 exact source cases: 17 fail on the active name-based command detector, including arbitrary-name environment inputs, fixed assignments with suspicious names, helper contexts and import/namespace shadows.
- [x] Compile and run a real Rust witness that inspects `Command::get_program` without spawning commands; environment/argument inputs and fixed-program controls match. Baseline DSR log SHA256 `c53b9532ef810c4273dbc0ad046e12f5fc8eccb49adcf2c8b97bdb5c6e4667e5`.
- [ ] Reuse the structured Rust flow engine with command-specific source/sink and import proof, preserving lexical scope, overwrites and selected helper summaries. URL validation must never sanitize executable provenance.
- [ ] Pass original command controls, shared redirect regressions, independent/native checks and exact public format/cache/selection checks before publication.

### Go findings during partial analysis (`1b9j.6.8`)

- [x] Freeze three exact losses: reached SQL/XSS/command findings before an unsupported reader, completed-helper findings before a failing helper, and selected packages on either side of a failed package. All three baseline assertions fail; DSR log SHA256 `dc832719096cd7610f36afee911af424c8ebce79a80fe0e59674ecd096593afe`.
- [x] Preserve reached concrete effects without installing unfinished call summaries. Continue independent sink domains and selected packages, then raise the explicit incomplete-analysis error after emitting retained findings.
- [x] Pass the three frozen probes and eight maintained source/module-adapter methods, including initializer effects, parameter-only exclusions, bound SQL, HTML sanitization and unfinished-helper return controls. The failed package is not resumed past its unsupported operation.
- [x] Pass four Go source suites and native witnesses: 388 tests, 16 opt-in skips. DSR log SHA256 `9083bdd1fcaa88b2b17efd6b023735b55e295c27d5126b1981cca6b125213fe9`.
- [ ] Verify actual public JSON/SARIF failure metadata, selection, suppression and repeated partial scans that remain uncached, then publish separately from native Reader support.

### Continuation qualification

- [x] Publish Python selected-module HTTP origins in `ce89ed53` and JavaScript reductions in `82687fc4` directly to main through GitHub, with exact blob hash checks and non-forced expected-parent updates.
- [ ] Complete prescribed full ShellCheck. The unchanged command against the pinned 5.5.95 tree ended without diagnostics after 12.118 seconds (retained launcher exit 247). This is not a lint pass. DSR log SHA256 `fecef879c5b16be04085abf345ff8485e80a1b7681ea4ea816aabd0a16495eac`.

The broad D6 and release umbrellas remain open. All public scanner matrices are
serialized against isolated, canonically pinned feature trees; source checks may
run concurrently. Failed and interrupted receipts remain retained.

## 12. November 21, 2026: preserve real source flows and partial findings

Base: `7711639529bb1ff289aed854f5b96d417cdb17d5`. The comprehensive feedback
plan, current Beads and active implementations were reviewed before selecting
these gaps. Existing broad detector and release goals remain open.

### Go retained findings (`1b9j.6.8`)

- [x] Reproduce all eight original source/adapter regressions on the baseline.
- [x] Preserve reached concrete effects from initializers, helpers, build
  variants and closures without publishing incomplete callable summaries.
- [x] Continue independent sink domains and selected packages before reporting
  an explicit incomplete-analysis error; never resume the failed body.
- [x] Preserve symbolic-parameter exclusions, bound-query and sanitizer controls.
- [x] Verify actual module and runner JSON/SARIF retain exact source locations,
  partial status and exit 2; repeated partial scans have zero cache hits.
- [x] Finish all 18 actual module/runner calls, including selected-file,
  suppression and clean-repair controls; original timed/missing-tool attempts
  remain retained and the complete matrix passes with ast-grep available.
- [x] Publish the bounded fix with canonical integrity pins.
- [x] Replay the three unchanged cache tests under their original deadlines:
  all three pass in 28.954 seconds. Across the original 390-test cohort and
  these replays, all 371 executed methods pass and 19 opt-in methods skip.
  The original run's timeout receipts are retained.
- [ ] Complete repository-wide qualification. The changed-source self-scan
  reports partial analysis with exit 2; full-suite and release gates remain open.

### Native JavaScript filter (`1b9j.6.9`)

- [x] Freeze missed callback effects and false-positive controls against Node.
- [x] Implement native filter through the shared finite array callback engine.
- [x] Pass all 15 maintained source/native methods; their baseline has 25
  failed assertions. The independent corpus passes 17 of 18 scanner cases and
  all 36 native observations; the remaining scanner result is an existing
  false positive for cleanup through a computed callback index.
- [x] Pass all 17 actual public calls on pinned version 5.5.102: 12 module/runner
  JSON/SARIF reports and five cache/edit/suppression controls. Exact locations,
  statuses, exits and counts pass; log SHA256
  `e87eac12bdced0be3cf4e8cb1001aec53363d0be29ee7030e08fd3c892f873f3`.
- [x] Finish the adjacent callback cohort: all 72 methods pass across the
  initial run and an unchanged isolated replay. Three native Node timeouts in
  one reduction method all pass on replay (six subcases, 1.296 seconds); the
  original 15-second deadlines and failed receipts are preserved.
- [ ] Resolve full-heap/repository qualification. The earlier full heap run
  was interrupted after 283 started methods with eight error entries and no
  final traceback summary; it is not a passing cohort.
- [x] Publish the bounded feature with canonical integrity pins. Keep computed
  callback-index precision and whole-repository/release qualification open.

### Native Python stdin enumeration (`stdin-provenance`)

- [x] Reproduce complete-clean misses through enumerate, next and helper flow.
- [x] Preserve consumed payloads and clean numeric indices through native
  aliases, pairs, materialization and bounded helpers.
- [x] Independently review mutation, default-value and producer authority.
- [ ] Verify mixed valid/invalid iterator alternatives and opaque expansions.
- [ ] Verify actual JSON/SARIF, clean controls and explicit partial results.
- [ ] Publish the bounded feature with canonical integrity pins.

## 13. November 22, 2026: reverse searches and native callable/input flow

The plan and current Beads were reviewed before choosing these changes. Work
preserves concurrent Rust executable-flow, forward JavaScript search and Python
zip/cursor implementations. Whole-repository and release qualification remain
separate from the bounded feature checks below.

### JavaScript reverse predicate searches

- [x] Freeze `findLast` and `findLastIndex` unsafe, clean and native controls;
  the incumbent has 55 failed assertions across the selected regression methods.
- [x] Extend the existing array callback engine, preserving native identity,
  reverse traversal, pre-callback values, shallow aliases, live lower slots,
  holes/defaults, callback writes/throws and stopped paths.
- [x] Charge remaining sparse visits in the selected direction while allowing
  immediate first-call stops and throws to complete.
- [x] Pass all 14 new source/native methods and the adjacent callback cohort:
  110 executed methods pass, with 11 opt-in public methods skipped in that cohort.
  Source log SHA256 `4bf435fa71a9e6160db364b4fd9bb994509ada9bac56e2d96b32cba5af4e832f`;
  adjacent log `fe6af20f835a1a983d29bbf30617d4f3b1e4d4ef4e3dbd6d5c08a78674a152d4`.
- [x] Independently review the exact source diff and pass 17 real module/runner
  calls covering JSON/SARIF, exact locations/statuses, selected files,
  cold/warm cache, edits and suppression. Public log SHA256
  `15682323faa44e0521429d012f9d8246afc72021deccbdc213a7da937a966965`.
- [ ] Complete broad self-scan, full-suite and release qualification.

### Native Rust callable identity (`1b9j.6.11`)

- [x] Prove saved constructors and environment readers through aliases,
  branches and supported helpers without treating inert function values as input.
  The frozen baseline fails one assertion and raises five errors across four
  new methods; both real rustc witnesses inspect `Command::get_program`
  without spawning a selected command.
- [x] Preserve namespace/shadow controls and existing redirect behavior.
  Independent review froze nine failed assertions covering nested constant
  storage, indirect parameter calls, callable collection indexing and address
  metadata. The corrected implementation preserves explicit boundaries and
  retains concrete findings before an incomplete operation.
- [x] Pass the final shared Rust suite: 228 methods, three opt-in public skips;
  the existing cross-language Rust input-boundary method also passes. The
  33 focused command methods are included in that cohort, not extra passes.
  DSR log SHA256
  `e1cb23f5351523d3b581ec530c60abe2093c6cbf28695782ff3ea31e5ee9efb1`.
- [x] Pass two added public methods comprising 19 actual scanner invocations:
  12 module/runner JSON/SARIF combinations plus seven cache, edit, scoped
  suppression and repeated-partial checks. Selected files, exact sites,
  critical counts, retained partial findings and exit 2 are asserted. Rust's
  module JSON summary is paired with its documented findings JSONL sidecar;
  the initial test's incorrect inline-ledger assumption is retained as a
  failed receipt. Public log SHA256
  `01f194b5256e0d8b0e5c906d0934606913628c8d04338789bfdb9677b3c620d3`.
- [x] Refresh canonical helper/module/release pins and development version
  5.5.111, preserving the concurrent Python zip EOF fix in `b1303533`.
  The broad executable-flow and release umbrellas stay open.
- [ ] General callable storage, opaque callable escapes and indirect
  callable-parameter execution remain explicit incomplete-analysis boundaries.

### Repository qualification limits

- [ ] Complete the prescribed whole-repository suite. The 240-second DSR
  attempt timed out during cache checks; log SHA256
  `82024db77a1a8b4dbbb6e3a56f886e14e3f190b1265b9ea0140d065e9e74b937`.
  Its cache-prune assertion was caused by inherited `UBS_KEEP_TEMP=1`; the
  exact test passes with that retention override unset. This isolated replay
  is not a full-suite pass.
- [ ] Complete full ShellCheck and broad self-scan/release qualification.
  The prescribed ShellCheck invocation was killed with exit 137. The earlier
  JavaScript changed-source scan returned partial analysis with zero critical
  findings; neither result is a passing broad gate.
  The Rust changed-source scan also returns partial (log SHA256
  `587f7e25cbde442d3ef8f721380d7a3abd52b5bb97ecc928179cfcd8da6c2903`):
  four critical records identify the two native-test compiler invocations
  using the explicit `UBS_TEST_RUSTC` environment override, twice each via
  independent Python rules. These are intentional test-tool configuration,
  not production command dispatch; no suppression or gate change was made.

### Native Python enumeration (`1b9j.6.12`)

- [x] Reuse the native iterator/cursor and positional-row model for text,
  binary and raw stdin. Preserve payloads separately from clean numeric
  indices through next/default, saved next methods, aliases, loops,
  comprehensions and supported pure factory helpers.
- [x] Preserve native callable identity, valid routes within known-invalid
  alternatives, and explicit boundaries for unresolved input/start protocols,
  unbounded materialization and captured iterator transport. Reached findings
  survive partial analysis; ordinary generic enumeration keeps its existing
  transfer behavior.
- [x] Fix the independently reproduced finite-zip regression: a finite or
  empty companion bounds a callable reader even when its sentinel differs
  from EOF. Native witnesses preserve final-read column ordering.
- [x] Preserve all concurrent `b1303533` source and regression changes.
  Native regular-file witnesses show raw-stream enumeration resuming after
  EOF and seek, with its index advancing from 7 to 8. Unproved resumption
  remains explicitly incomplete rather than becoming permanently clean.
- [x] Pass the final dataflow cohort: 158 methods, 151 executed passes and
  seven opt-in skips. Its 36 zip/enumeration methods, including native
  runtime witnesses, are a subset of that total. DSR log SHA256
  `133d55a1ce50b32405c88df68d92db077db4d3f04049690f29143fbddcbb21c9`.
- [x] Pass the final two public methods comprising 25 actual scanner calls:
  16 module/runner JSON/SARIF combinations and nine cache/edit/suppression/
  repeated-partial calls. Exact sites, severity, selection, retained findings,
  and incomplete-result nonreuse are asserted for opaque-start and EOF cases.
  Candidate public log SHA256
  `942bc0ed27a7ee00e26213c194dfd7edffa060b6ae019cfcfe2666135b1fe6f1`.
- [x] Replay all 25 unchanged public calls on the combined Rust/Python tree
  with canonical development version 5.5.112; log SHA256
  `6b6513daba37cdbbfa9ac6d91814e018329969d3fc7d3fc3363b02e4e6794842`.
  Canonical module/helper/release hashes, runner syntax and whitespace pass;
  integrity log `ccef15bdbdbb29fe10fad7e1c70f20fc376b450cc88161390fbdc858ede83114`.
- [x] Retain all frozen failures and exact phase provenance in evidence blob
  `e9781ed51ecfffe6414ee578bf2d78a61c75a1b8`. Earlier adjacent call-completion,
  module and expression checks passed on the earlier reviewed candidate;
  they are not represented as final merged-tree executions.
- [ ] Complete the broader summary and stdin-provenance goals. Two summary
  failures reproduce on pristine `5ad0246`: a `None` versus `ast.Constant(None)`
  expectation and existing delayed-generator boundaries in `argparse`.
  The added generic-enumeration obligation was fixed, and the later summary
  run reports exactly the two baseline failure reasons without weakening tests.
  Arbitrary iterator protocols, unbounded list/tuple materialization and
  captured iterator transport remain outside this bounded implementation.
- [ ] Complete changed-source self-scan qualification. The first attempt's
  analyzer process was killed while other checks ran. The isolated replay
  completes with partial analysis (exit 2), not a clean pass; log SHA256
  `2898b3e369c09e9601d35df547469f84a74c0144e631300dd3e87d79291b89d2`.
  Its one critical record is the existing LDAP heuristic misclassifying
  `self.http_parameters.add(request.parameter)`, an analyzer set update, as
  a directory sink. No suppression or gate change was added.

## 14. November 22 continuation: native flattening, callable helpers and LDAP

The comprehensive feedback plan and current Beads were reread at `3d3fc4f5`.
Prioritize missing semantic behavior using the existing shared engines. The
three implementation tracks remain separate meaningful commits on main.

### Native JavaScript flattening (`1b9j.6.13`)

- [x] Freeze the missing native `Array.flat` behavior: 11 initial methods
  expose 26 failed assertions and one error on the unchanged analyzer.
- [x] Extend the array heap model with depth conversion, sparse compaction,
  fresh outer results, repeated nested arrays and shallow object identity.
  Unknown array/scalar alternatives retain uncertain positions and payloads;
  custom protocols, unproved extents and traversal limits remain explicit.
- [x] Freeze and fix a further logical-assignment gap: `&&=`, `||=` and `??=`
  must preserve array/scalar return alternatives. All three Node-backed
  regressions fail before the fix and pass afterward.
- [x] Pass the final full heap cohort: 427 methods, 407 executed passes and
  20 opt-in public skips. Log SHA256
  `61118225f279002c3a05a0acff22e9a62f66a024bbc1beab539b567fa2b492eb`.
- [x] Pass two public methods comprising 19 module/runner JSON/SARIF and
  cache/edit/suppression/partial-nonreuse calls. Candidate log SHA256
  `d6511120b50e9156d6224f99dc1d5e5cf54b07f34036305e7f206ee67f6cedcb`.
- [x] Repeat all 19 public calls on the publication tree, followed by both
  canonical integrity verifiers, Bash syntax and diff checks; all pass.
  Publication log SHA256
  `e584eee3e539ab3d8e80c8bf8c88bbb10cfbc24fef957a4d2e39ed4bce4e92d3`.
- [x] Independently review the source and freeze 18 native witnesses. All
  18 Node outcomes pass; 17 scanner expectations match. The remaining
  original depth-two helper expectation requires an unproved scalar input
  type and correctly remains partial. Keep that wider corpus unchanged.
  Two supported shallow/deep-object helper contexts pass separately; a
  native witness demonstrates that array-valued input changes output width.
  Follow-up log SHA256
  `9bf2823eb4265d3f3c7c7ad9056eb4ba08d15cf33eacfa2392aed8b8264d7ac8`.
- [ ] Broader protocol, source-type and release qualification remain open.
- [ ] Changed-source self-scan remains incomplete (exit 2): 42 unsupported
  Python scopes, zero critical findings, five parameter-count warnings,
  six JSON test-parse warnings and 1,164 informational records. No suppression or gate
  change was added. Log SHA256
  `e6b113664258497bb58955571f895e4d391e3f8bad51c11ad1648a8d95c1ecaa`.
- [x] Preserve all 33 scoped evidence files, including seven failed originals,
  in GitHub blob `c1228e3396525ce2fa4131f623718c4bbd1361b6`.
  All 15 receipt/log hash pairs and both publication source hashes match.

### Selected Rust callable helpers (`1b9j.6.14`)

- [x] Reuse the bounded summary worklist with finite callable identities,
  preserving symbolic data parameters, recursion and caller separation.
- [x] Preserve native and selected local wrappers, clean metadata, exact
  sink sites and explicit unknown-callback boundaries.
- [x] Freeze native helper misses and independent local-wrapper/source-reader
  misses on the original analyzer. Imported callback targets also remain
  explicit partial cases when no constructor spelling appears locally.
- [x] Pass 244 shared methods: 237 executed passes and seven public skips,
  including four real rustc witnesses. Log SHA256
  `b6f2225b8b89c157df4f7890a372942e65aa1fcd09af5a220f90ff74e998cb53`.
- [x] Independently review the final source and replay the unchanged 11-case
  corpus: ten exact complete results and one expected mixed-callable partial.
  Log SHA256
  `ba5590a236a0e461a80469150344cee76dbf2193b9f243111510c0f536e2aace`.
- [x] Pass 27 public module/runner JSON/SARIF, selection, cache, suppression
  and partial-nonreuse calls on the publication tree, followed by both
  integrity verifiers, Bash syntax and diff checks. Log SHA256
  `f4129c2bcda6eb293f94e8712f3fda56510bd2dfe39253f76ff769bc1abed96b`.
- [x] Preserve 34 candidate evidence files in GitHub blob
  `629c2dbe22f47888930bd4a717b6ef51d83ece54`, including failed baselines.
- [x] Preserve publication and broad-gate evidence, attributed to `2527a61`,
  in GitHub blob `ee49bf0c7569d37400ca375ea2c02cc63a56ceaf`.
- [ ] General closure/collection transport, imported bodies, mixed callable
  dispatch and broad Rust/release qualification remain open.
- [ ] Changed-source self-scan remains incomplete (18 unsupported Python
  scopes, exit 2). Eight critical records are paired reports on four native
  test witnesses intentionally selecting rustc from `UBS_TEST_RUSTC`; the
  compiler path is test-runner configuration, not a production request.
  Ten warnings and 617 informational records are also retained. Do not
  reinterpret this as a passing self-scan or suppress the compiler probes.
  Log SHA256
  `faebeb1f91a9f1f990e86e687103017ed06b34d6dd47990077a6703a32d7fe3a`.

### Python LDAP provenance (`1b9j.6.15`)

- [x] Replace the flat visitor with a shared-flow adapter proving native
  receiver identities, API-specific operands and separate filter/DN escaping.
- [x] Preserve helpers, branches, captured methods, conservative opaque
  operations and valid builtin-set receiver exclusions.
- [x] Freeze 31 failed subcase assertions on the original flat visitor.
  Real offline ldap3 witnesses distinguish escaping domains and execute
  instance, saved and unbound class-method operations.
- [x] Fix four independently reproduced false cleans from native unbound
  methods: the actual API identity selects operands after explicit `self`.
  Keep keyword operands, projection metadata and native escaping distinct.
- [x] Remove an optimistic constructor-field shortcut after three independent
  escaped-alias probes expose false cleans. The final unchanged 22-case
  independent corpus passes, including those lifetime cases; log SHA256
  `d28e3fe68ddf3ed626ad0056b446541d292854d6c22a6c1bb83a00b79e10c8d5`.
- [x] Pass 27 real public calls (20 module/runner JSON/SARIF and seven cache,
  edit, suppression and partial-nonreuse calls), all 22 independent cases,
  both integrity verifiers, Bash syntax and diff checks on the publication
  tree. Publication log SHA256
  `1671ee6a9a34e5f0db83fb1482c1538542dc3622f63c16d1212e7c032a3a98d7`.
- [ ] Full precision qualification remains open: 154 methods produce 148
  passes, four opt-in skips, one failure and one error. The two failures
  reproduce on unchanged main: the C# annotation-regex test references a
  removed symbol, and the index-arithmetic self-scan exceeds its warning
  threshold. Final log SHA256
  `3ac1950c113221989ee2cebf4b1f1250718eb2fab1e226ab9c25a95eb398871c`.
- [ ] Keep the broader constructor-precision cohort open with all three
  original clean expectations intact. Its explicit opt-in execution still
  has three failed subcases (also reproduced on original main). Final log
  `bd09a9892df95aee6438c9d9d4dcc92d68de2b402ce1d55a0377e88d2fdfaee4`;
  baseline log `f34a96efa7595ceb629bc83484b60806e0e23260fcfb9d32a218e5d04362e396`.
  The scoped native functionality is implemented; the Bead stays in progress
  for those precision gaps, without redefining false positives as successes.
- [ ] The own-analyzer LDAP probe remains partial (103 unsupported scopes,
  four conservative set-field findings). The original request-parameter
  set update and ten local-set false positives are gone. Do not call the
  broader probe clean; log SHA256
  `f50180a9a1bb7d3c23027b6ec0bdcc61816a9dbe9df271b9a8e8ea0fe90f5382`.
- [ ] Changed-source self-scan remains partial (exit 2, 67 unsupported
  components). Its one critical record is in the public subprocess test
  harness; three JSON test-parse warnings and 467 informational records are
  retained. Log SHA256
  `81fe577d0109b48ea39c5d07109b5703f4cdbc1391d5e9a33d403f888d3e283c`.

### Continuation qualification

- [x] The exact prescribed full ShellCheck command passes on the unchanged
  continuation base in the current environment (35.617 seconds); log SHA256
  `cfc2a13b85405aca2ebd0ad6463149da682569588967064cab7387d2813a5e5d`.
  This supersedes the earlier environment-killed attempts for that base;
  whole-repository and release qualification still require their own results.
- [x] Repeat the prescribed full ShellCheck command on the published JS/Rust
  tree `2527a61`: pass (40.097 seconds), log SHA256
  `8314b2cb6d44a86122fc06527601869651e03b19c183d08d952d9d6f0f45c68a`.
- [x] Repeat full ShellCheck on the combined LDAP publication tree: pass
  (35.761 seconds), log SHA256
  `c7a14b8405535afb34925aa82de8ac032eba492537afa488a58c1c1a9f16b4ea`.
- [ ] Whole-suite qualification remains open. The DSR `run_all.sh` attempt
  on `2527a61` passes all 12 rule inventories, then records missing Swift
  buggy/clean fixture pairs in the rule-quality harness. The exact harness
  failure reproduces on unchanged `3d3fc4f`; baseline log SHA256
  `b542f8060b2d1a52fdbf44d0f7cfcc41844fce5398a92bf24bcba994c48a3c9d`.
  Quality tests continue until the 420-second overall budget expires, so
  there is no completed whole-suite result. Attempt log SHA256
  `4b6de775aaf47cd99735c812e325797839b35fd35067d80d612725010800e9d2`.
  No fixture expectations, tests or gates were weakened.

## 15. November 22: native dataflow work interrupted by executor loss

At `d6c529ee`, independent probes reproduced silent native dataflow misses.
The execution workspace became unavailable before full validation and publication.
Recoverable implementations and unchanged probes are preserved as **unactivated**
patches; see [the checkpoint](../../notes/native-dataflow-checkpoint-2026-11-22.md).
This is preserved source work, not an activated scanner repair or release claim.

- [ ] `1b9j.6.16`: finish native JavaScript `Array.from`. The November 23
  checkpoint rebases the candidate to `b27c0dcc` and adds mixed-mapper,
  deleted-native-member, SQL-dispatch and public-report regressions (20 methods).
  The final patch replays exactly in both directions; its runtime, independent,
  public and adjacent/full checks remain unexecuted after executor loss. The
  earlier 14-method pass applies only to the older archived candidate.
- [ ] `1b9j.6.17`: qualify Python `filter(None, stdin)` and native text/bytes
  join consumption. The November 23 implementation fixes the exact diagnostic
  and passed all 12 maintained/native methods through DSR. The updated patch
  adds two unexecuted public methods. Independent replay, adjacent suites,
  public reports and canonical integrity/full gates remain pending; no
  production activation is claimed.
- [ ] `1b9j.6.18`: complete Go native read-into-buffer transport. The archived
  patch contains failing regression witnesses and a partial capability scaffold;
  native transfer, alias/backing writes and helper integration are unfinished.
  No candidate runtime qualification is claimed.

## 16. Native copy, HTTP destinations and command constructors

- [x] `1b9j.6.19`: implement native JavaScript `Array.slice` range selection,
  sparse slots, fresh outer arrays and shared element identities (`69f8f7af`).
  The unchanged independent 28-case corpus has 25 exact results, three
  explicitly incomplete results and no incorrect complete results
  (baseline: 11 exact, 17 incorrect complete).
- [x] Finish the final JS public/cache replay on the published slice tree:
  genuine DSR passes all 15 methods without skips, including 17 real public
  scanner calls. Source/config snapshots match. Receipt SHA256
  `8112261df6689263b7997edbf0705d509e257f6f393113b720b66bedbb5013e0`.
  The earlier ENOSPC failure remains retained.
- [x] `1b9j.6.20`: implement native `urllib3.request` and `PoolManager` URL
  provenance across aliases, saved methods and selected helper summaries.
  Keep request metadata separate and reject mutable/custom dispatch proofs.
  Genuine DSR passes all 13 selected methods, including 19 public scanner
  invocations; both integrity verifiers and source-stability checks pass.
  Ten intercepted native requests independently confirm argument positions
  and eager send behavior. Direct-import registry/reflection escapes are
  covered by regressions after independent review exposed initial misses.
- [x] `1b9j.6.21`: identify native Go `os/exec` constructors through imports,
  saved functions, helper summaries, pointers and supported captures. Keep
  contexts and ordinary arguments distinct from executable/program operands.
  Genuine DSR passes 81 of 84 focused methods (three opt-in skips), the
  separate compiled witness and all 24 public module/runner JSON/SARIF calls.
  Source/native receipt SHA256
  `0027280d2dc589105c246c4d5ac5f3a648022afcdb60893051ae19602f283ed8`;
  final public receipt SHA256
  `af101643c158d486db69433af592ab1001bc24aeccd05094b2d1dac61b0e0729`.
- [x] Preserve and explain the Go public harness correction. The initial
  16-pass/8-failure run exposed the separate name-based informational
  `go.exec-command-without-context` advisory on two custom-binding controls.
  Eight unchanged-baseline public reports prove identical advisory records.
  The final harness asserts those exact records plus zero security findings;
  source fixtures, coordinates, completion/exit assertions and deadlines
  stay unchanged. No suppression or filtering was introduced.
- [ ] Broader qualification remains open. The strict changed-Python-helper
  self-scan is partial (0 critical, 66 warnings); its integration receipt
  remains failed 3/5
  (`035659a23da88c784333611efe3ab72561ab302ab70d786611b885b31cbfee6e`).
  The final combined runtime passes both integrity verifiers and diff checks,
  but the full ShellCheck process again exits 137. The changed-Go-helper
  self-scan is partial (1 critical, 0 warnings). Its sole critical metadata
  comparison is unchanged, and the raw baseline scan reproduces that finding
  and incomplete status (exit 2; receipt SHA256
  `b054fed4b9d1f9fb39f1398c6eea1f774770f89b7e4819cc8f7694d3aae86898`).
  Final runtime receipt remains failed 3/5:
  `8dd56b328b033f8653fdcc47bc91a6288c998ec28ad7fdcaa2abb1a852d14765`.
  Full language cohorts, whole-repository and release qualification remain
  open; unsupported native protocols continue to report incomplete analysis.
