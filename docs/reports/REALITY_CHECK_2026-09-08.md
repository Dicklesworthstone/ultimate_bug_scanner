# Reality Check — updated 2026-10-06 (v5.4.23)

This update supersedes the September conclusions below. The historical report is retained intact for comparison. Scanner code was inspected at `40cc563`; the working checkout subsequently advanced to `b9de7ef` through another agent's fixture and evidence commits. No scanner implementation was changed by this audit.

## Current verdict

UBS is a substantial, functioning analysis tool with uneven language depth. Its dispatcher, common finding pipeline, integrity controls, and all twelve language entry points work on this Linux/Python 3.14 environment. The strongest frontends now perform bounded dataflow and function-summary analysis. Several weaker security frontends still make decisions from helper names and nearby text. The product has progressed well beyond a collection of shell grep pipelines, but reliable coverage across languages, measured accuracy, consistent feedback latency, and a verified current release pipeline remain unfinished.

Two important corrections to the September report: the native project self-scan now returns exit 0 with **zero critical findings and zero warnings**, and the architecture is already shared across all twelve modules. Neither a fresh core rewrite nor another round of contract-v2 ports is needed. Conversely, closed beads, generated documentation, and a large rule-pack inventory do not prove the claimed precision or ordinary CLI activation of every analyzer.

The immediate actionable regression is the advertised Python 3.9 runtime floor: `@dataclass(slots=True)` in `modules/helpers/ubs_core/analyzers/taint_js.py:784` and `:822` needs a newer interpreter. Eager analyzer imports spread the failure beyond JavaScript. The current Taint Integration and Python Closure Taint workflows reproduce it. Keep the documented floor working rather than raising it to make a gate green.

GitHub currently reports **CI, UBS Test Suite, and Release as `disabled_manually`**. Focused checks continue to run, including successful editor/service workflows, but that does not establish a current green full test or release pipeline. The reason for disabling those workflows was not established; this audit did not change their state.

## Scope, evidence, and limits

README.md (2,880 lines), repository AGENTS.md (873 lines), and `/data/projects/AGENTS.md` were read in full. The planning documents, language port maps, module contract, coverage registry, test runner, security/release/editor/service documentation, previous reality checks, current open work, and the corresponding implementation paths were examined. The current audit applies both `reality-check-for-project` and `idea-wizard`; implementation remains future work.

| Check | Current evidence | Interpretation |
|---|---|---|
| Module/helper checksum verification | Passed | Current embedded digests match the checkout |
| SHA256SUMS verification | Passed | Listed release entry files match; this is not a live signature/provenance proof |
| Documentation claim checker | 13/13 checks passed | Selected mechanical claims agree, including 169 flags, 12 languages, 353 helpers, and version 5.4.23 |
| Embedded core self-tests | 427/427 passed | Broad internal regression evidence |
| Native buggy/clean CLI cases | 24/24 passed across all 12 modules | Every current module runs and meets its existing fixture assertions |
| Native SARIF entry points | 12/12 emitted parseable SARIF 2.1.0 envelopes | Minimal clean sources; optional compiler/dependency phases disabled where applicable; envelope validation is not full schema or detection-accuracy proof |
| Focused Python/C#/Rust/secret-comparison tests | 354 run: 350 passed, 4 skipped | Stronger semantic evidence; three optional Rust E2Es and one optional taint E2E were skipped |
| Full 490-case manifest | 490/490 passed; zero failures, zero skipped | Existing expectations retained without modification; all twelve languages represented |
| Native project self-scan | Exit 0; 443 files; 0 critical, 0 warning, 6,054 info; no failed modules | September's red self-scan finding is superseded; informational noise still deserves scrutiny |
| Prescribed full ShellCheck command | Exit 1: 193 info and 4 style diagnostics; no warnings or errors | The exact gate is not green. Most findings are SC2317 on indirectly invoked functions; do not weaken it casually |
| Version/tag drift checker | Exit 0, `status: skipped`, current tag absent | A skipped check is not verification of release coherence |

All new audit artifacts are under `test-suite/artifacts/`. Temporary files were retained, with cleanup intercepted in the test environment to honor the explicit no-deletion instruction. Finding assertions were unchanged. The first retention harness was defective and its failing run was rejected; the corrected harness produced the results above. This audit **does not certify cleanup behavior or an unmodified full `run_all.sh` run**. The self-scan overlapped other work and is not a controlled performance benchmark. Optional compiler, dependency-audit, macOS, Windows, and Nix paths were not locally verified.

Artifacts: `reality-core-20261006-6bfga367` (core); `reality-cli-20261006-HPO8eX` (24-case sweep); `reality-cli-20261006-wEWXr6/unittest.log` (focused tests); `reality-cli-20261006-uUTBu5` (full manifest); `reality-cli-20261006-Mo0Mc0` (self-scan); `reality-port-probes-0lu8r1nq/results.json` (six analyzer probes); `reality-cli-20261006-dI9tvS/probe-results.json` (the same six through the actual meta-runner, each scanning one file successfully); `reality-cli-20261006-aOH8C0/sarif-envelope-results.json` (twelve native SARIF envelopes). These are ignored scratch evidence, not release artifacts.

The latest published release inspected was [v5.4.17, October 1](https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/tag/v5.4.17). Its asset list does not contain `ubs-daemon` or Sigstore bundles. Checkout service functionality and current installer wiring cannot therefore be assumed to exist in that release. The LSP documentation explicitly describes a checkout-only entry point, which is honest. Current focused CI evidence includes failing [Taint Integration](https://github.com/Dicklesworthstone/ultimate_bug_scanner/actions/runs/37518311400) and [Python Closure Taint](https://github.com/Dicklesworthstone/ultimate_bug_scanner/actions/runs/37518311268), and passing [Editor Diagnostics](https://github.com/Dicklesworthstone/ultimate_bug_scanner/actions/runs/37443556613) and [Local Scan Service](https://github.com/Dicklesworthstone/ultimate_bug_scanner/actions/runs/37438172383).

## Vision checklist

`WORKING` below is bounded to the stated evidence, not universal correctness. `PARTIAL` means useful code exists with material scope limits. `UNPROVEN` means the promised property lacks adequate evidence. Bead suffixes use the `ultimate_bug_scanner-` prefix.

| # | Promised user outcome | Reality | Evidence / bridge |
|---|---|---|---|
| 1 | One CLI scans polyglot repositories | WORKING locally | Twelve real modules; 24-case sweep; current self-scan |
| 2 | Bash dispatcher with lightweight deployment | WORKING with clarification | Bash wrappers dispatch substantial Python `ubs_core` analysis; Python is a runtime dependency |
| 3 | Uniform module flags/formats/exit meanings | WORKING in tested paths | Contract v2, shared library, core tests; external-tool paths need H8/G6 |
| 4 | Respect selected files, ignores, and exclusions | WORKING with context limits | Direct file lists for whole-project scans; diff/staged and unsaved-buffer snapshots intentionally carry selected context |
| 5 | Structured findings through text/JSON/JSONL/SARIF/TOON | WORKING in tested paths | Shared sink, merge/fingerprints, schemas and renderer tests; release encoder journeys remain G6 |
| 6 | No false clean result on scanner/environment failure | PARTIAL / current regression | Failure envelopes exist, but Python 3.9 eager imports currently fail; add a runtime-floor fix and real invocation probe |
| 7 | Downloaded executable/helper integrity | WORKING locally | Digests match and fail-closed checks exist; trusted local/PATH module overrides are a separate documented trust boundary |
| 8 | Verified signed release provenance | PARTIAL | E5/G6 remain open; release workflow disabled; current published asset proof incomplete |
| 9 | Fresh install and repair on Linux/macOS/Windows | PARTIAL | Installer and doctor code exist; F7/G3/G4/G5/G6/H8 retain platform and user-journey proof gaps |
| 10 | Complete AST adoption means equivalent semantic depth | PARTIAL | Structural packs exist everywhere; activation and semantic scope differ sharply; D5 and new activation work |
| 11 | Guard/type narrowing checks available to CLI users | PARTIAL | Several registered analyzers default off; `--enable-new-analyzers` is a Python-engine argument without ordinary Bash CLI exposure |
| 12 | Request-to-sink security analysis | PARTIAL | Strong Python/JS/Go subsets and scoped Rust/C# engines; name-trusting weak frontends fail diagnostic probes; D6 |
| 13 | Resource lifecycle correlation | PARTIAL | Real ownership-aware helpers exist; Elixir still uses aggregate differences and Kotlin lacks comparable native idioms |
| 14 | Async/concurrency bugs beyond simple syntax | PARTIAL | Useful Python/JS/Go/Rust/C# checks; receiver-specific task and cancellation semantics uneven |
| 15 | Accurate, low-noise findings | UNPROVEN at claimed percentages | Clean fixtures are useful, but no finished held-out corpus establishes README's layer/blended FP percentages; D7 |
| 16 | Calibrated confidence | UNPROVEN / misleading presentation | `explain.py` prints `(calibrated)` without matching calibration evidence; D7 needs statistically valid acceptance |
| 17 | Subsecond files / consistent sub-five-second feedback | UNPROVEN as general claim | README contains contradictory speed claims and historical measurements; C7 needs a reproducible table |
| 18 | Bounded streaming memory on very large inputs | PARTIAL | Streaming machinery exists; C6's 400K-line/RSS target remains in progress |
| 19 | Fast unchanged incremental scans | WORKING service subset | Merkle/report caches and tested invalidation exist |
| 20 | Edited-source feedback under 100 ms | PARTIAL / UNPROVEN target | Daemon is real, but edited requests still invoke the scanner rather than hold all analysis state warm; K4 |
| 21 | Useful editor diagnostics | WORKING tested checkout subset | Real stdio LSP, snapshots, UTF-16 ranges, push/pull, cancellation and invalidation; focused CI green; distribution still separate |
| 22 | Baselines, suppressions, profiles, and explainability | WORKING tested subsets | Shared machinery and fixtures exist; confidence and activation provenance need improvement |
| 23 | Generated docs describe actual coverage | PARTIAL | Current registry has ten columns and stale planned statuses; generated agreement does not prove effective invocation coverage; J1 |
| 24 | Reliable current full CI/release pipeline | UNPROVEN / operational gap | Three main workflows disabled; focused successes cannot replace them; G6/H8 |
| 25 | Current release exposes current capabilities | PARTIAL | Checkout 5.4.23 versus published 5.4.17; daemon asset absent; release observation required |
| 26 | Native Kotlin coverage matches advertised breadth | PARTIAL / inadequately tracked | Twenty-two headings but one native Pattern and one native AST rule; borrowed Java security/path logic supplies much of the substance |
| 27 | Broad usefulness across today's project stacks | PARTIAL / NO_BEAD for missing languages | PHP, SQL, HCL, PowerShell, Dart, and Lua have no modules; stage additions by real ecosystem value and proof cost |
| 28 | Persistent repository scan settings from feedback plan §4.1 | NOT_STARTED / NO_BEAD | README recommends a shell wrapper; session `--config-dir` and installer `install.conf` do not implement scan excludes/languages/rule overrides |

### Answers to the five reality-check questions

1. **What works?** The native CLI, all twelve entry points, common output/integrity machinery, many concrete security and correctness detectors, shared finite dataflow primitives, and tested local service/editor paths. These are implemented code, not stubs.
2. **What does not meet the vision?** Python 3.9 currently breaks; effective language depth is unequal; some implemented checks remain inaccessible or advisory; empirical accuracy/confidence and general latency promises are unproven; the latest published distribution and disabled full workflows do not establish a current complete release journey.
3. **What blocks completion?** Receiver-specific binding/flow semantics, independent positive and negative controls, trustworthy calibration data, maintained runtime/platform probes, current release observation, and measured incremental analysis work. Additional headings or rule counts will not remove those blockers.
4. **Would all existing open work close the gap?** No. Before this audit, 263 of 289 visible beads were closed, with 17 open and 9 in progress. D5/D6/D7/J1/C6/C7/K4/H8/G6 cover major programs, but their descriptions sometimes lag the code or specify invalid guarantees. They do not explicitly cover the new runtime regression, all activation gaps, native Kotlin depth, the demonstrated weak-frontend errors, or missing-language additions. The closed-count ratio says little about delivered accuracy.
5. **Which goals lack adequate tracked work?** The runtime regression needs a new concrete bug/probe; activation needs an ordinary-user integration task; weak-module upgrades need named receiver/sink scopes; Kotlin needs native detectors with proof; PHP/SQL/HCL need new language tasks; persistent scan configuration from the original feedback plan has no matching open task. Existing accuracy/docs/release/performance beads should be refined rather than duplicated.

## Module rankings

These are engineering judgments, **not measured precision percentages**. Quality weighs useful default CLI behavior, scope correctness, negative controls, and proof maturity. Sophistication weighs parsing/binding, control/dataflow, summaries, resource/async reasoning, and framework context. Breadth counts only when checks actually reach users. All rankings assume the functioning Python 3.14 environment; the runtime-floor regression affects the shared product. Middle/lower placements are less certain than the strongest and weakest tiers.

| Quality rank | Module | Sophistication rank | Why it earns this position | Most consequential limitation |
|---|---|---|---|---|
| 1 | Python | 1 | Actual Python AST; alias/framework-aware sources; branch/loop/recursive summaries, selected modules, heap effects and cleanup reasoning; broad adversarial tests | Selected import/heap model, not arbitrary whole-program Python; calibration absent; narrowing default off |
| 2 | JavaScript / TypeScript | 2 | Broad security and async families; robust lexical views, templates/regexes, selected ES/CommonJS summaries, heap aliases and sink effects | Main taint frontend is lexical, not TypeScript compiler analysis; only 19/37 built-in AST IDs join the normal counted ledger |
| 3 | Go | 3 | Strong security breadth, bounded branch/loop/package summaries, JSON/XML decoder effects, Go-AST lifecycle helper, substantial controls | Lexical taint scope is selected same-directory packages; closures/imports and several gated/advisory checks remain limited |
| 4 | Rust | 4 | Rich structural pack; scoped redirect/path/SQL/header reasoning, helper and receiver summaries, namespaces, loops/matches; good adversarial tests | No general rustc ownership/type/macro model; sophisticated subsets do not imply universal Rust taint |
| 5 | C# | 5 | Typed same-file helper resolution, bounded flow, branch/recursive effects, ref/out handling, task handles, disposal, and guards | Lexical frontend; cross-file/virtual/heap behavior limited; small general security breadth relative to Python/JS |
| 6 | C / C++ | 7 | Useful memory/resource and pointer checks; broad structural pack, command/archive/security coverage | Custom lexical/structural reasoning lacks compiler/preprocessor/type context; older taint passes still trust names |
| 7 | Java | 6 | Resource helper, structural checks, meaningful Spring/JDBC/security coverage; new path engine already has bounded summaries and control flow | Redirect and some sanitizer checks remain name-based; most AST pack rules are advisory rather than counted |
| 8 | Bash | 11 | Valuable shell-specific mistakes, mature optional ShellCheck integration, clear relevance to UBS itself | Only two manifest cases; small native AST pack; little interprocedural/resource reasoning |
| 9 | Swift | 8 | Guard narrowing, lifecycle/helper work, URLSession correlation, plist/security checks, active structural pack | Redirect/path taint still shallow and name-trusting; actor/task/receiver ownership modeling incomplete |
| 10 | Ruby | 9 | Rails/Rack security breadth, lifecycle helper, structural pack | One AST ID contributes to ordinary counted findings; URL/path taint has demonstrated kill/sanitizer errors; narrowing gated |
| 11 | Elixir | 10 | Phoenix/Ecto patterns, request security and active structural pack | Aggregate task/resource differences can attribute findings to unrelated lines; weak flow; no equivalent per-binding lifecycle analyzer |
| 12 | Kotlin | 12 | Reuses useful Java security detectors and the newer bounded Java/Kotlin path engine; native narrowing | Native breadth is extremely thin; little coroutine/cancellation/use ownership analysis despite numerous category headings |

Java's path-analysis sophistication is a reason to extend its existing engine, not to classify every Java/Kotlin taint path as obsolete. Bash's lower sophistication is compatible with better practical quality than several richer but less precise frontends. Conversely, Kotlin's isolated shared dataflow capability does not compensate for missing native breadth.

### Why pack counts are misleading

Source inventories at this snapshot: Rust 142 AST-pattern entries; Go 64 base AST rules; Python 50; Java 37; JS 37; C++ 32; Ruby 29; Elixir 26; C# 24; Swift 22; Bash 4; Kotlin 1. These are different representations and are not comparable coverage units. Rust generates 137 of those entries, with three separate run-mode patterns and two parser-incompatible entries. Python excludes six parser-incompatible entries from generated configs. Go has 51 IDs/55 consumption entries in its explicit consumption table, plus additional computed handling.

For normal counted AST findings, JS explicitly allows 19 built-in IDs, Java nine, and Ruby one. Other pack results may remain visible in ancillary AST reports or SARIF; they should not be described as nonexistent, and their presence should not be described as ordinary exit-gating coverage. C++, C#, Swift and Elixir consume their packs more broadly. Python's single severity override does **not** mean a single active AST rule: valid pack findings otherwise count normally.

Default-off analyzers are a separate issue: Python narrowing; C++ narrowing; Go generic guards/narrowing; Ruby narrowing; Java generic guards; Elixir guards/narrowing; C# generic guards; Swift regex analysis. Their engine-side `--enable-new-analyzers` argument is not surfaced by the module wrappers. Closed library implementation beads therefore do not establish available CLI behavior.

The manifest has 140 JS, 95 Python, 66 Rust, 43 Go, 25 C#, 23 Ruby, 21 C++, 21 Java, 20 Swift, 18 Elixir, 16 Kotlin and two Bash cases. Its ordinary assertions often permit warning ranges or require message substrings; six JS cases explicitly pin `expect.rule_ids`. Additional quality suites provide stronger exact-ID and semantic controls, so this is a manifest limitation rather than a claim that the entire suite lacks precise tests.

“Clean” fixture directories are not a calibrated globally bug-free corpus. The current sweep allows six Rust, three Go and one Ruby warning in its clean cases. Some Go warnings reflect real omitted cleanup in a security-specific example; others are heuristics. A concrete Ruby false positive is already visible: `test-suite/ruby/clean/performance.rb` appends `Thread.new` values to a collection and calls `threads.each(&:join)`, yet reports `ruby.lifecycle.thread_join`. Any transferred ownership mechanism must handle that idiom. Qualify donor semantics independently rather than copying every donor heuristic.

### Six diagnostic probes: concrete porting targets

These first invoked the actual registered analyzers, then reproduced through the ordinary meta-runner with native module dispatch, JSON output and one scanned file per case. Four unsafe cases returned exit 0; the two clean reassignments returned exit 1 with one critical finding. They establish these six CLI errors, not full-module precision rates.

| Language / case | Expected | Actual |
|---|---|---|
| Java: request target passed through identity function named `safeRedirect` | Unsafe redirect finding | Zero findings: false negative |
| Java: request target overwritten with `"/fixed"` before redirect | No redirect finding | One `java.taint.open_redirect`: false positive |
| Ruby: request URL through identity function named `safe_url` | Unsafe outbound URL finding | Zero findings: false negative |
| Ruby: request URL overwritten with a fixed HTTPS health URL | No outbound URL finding | One `ruby.taint.outbound_url`: false positive |
| Swift: request target through identity `safeRedirect` | Unsafe redirect finding | Zero findings: false negative |
| Elixir: request target through identity `safe_redirect` | Unsafe redirect finding | Zero findings: false negative |

The actionable principle is to prove a sanitizer from its selected binding/body and dominating guard, attach that proof to the correct value/sink, and invalidate it on unsafe transformations. A function's reassuring name is not such proof. A fixed literal assignment must kill the old fact where language semantics permit it. Nearby guards must not protect unrelated variables or functions.

## Missing languages: value and feasible scope

This is a prioritization inference, not a popularity-only ranking. Adoption, bug severity, existing infrastructure, parser/tool dependencies, false-positive risk, and maintenance cost all matter. GitHub's [2025 Octoverse contributor ranking](https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/) includes PHP and HCL in its top ten; both are missing here. C and TypeScript are already covered and should not be counted as new languages.

| Priority | Addition | Why it broadens usefulness | Initial valuable scope and cost |
|---|---|---|---|
| 1 | PHP | Large unserved server-side web ecosystem; high-value request/security analysis fits UBS | Superglobals and selected Laravel/WordPress request sources; PDO/mysqli binding, command/include/unserialize sinks, safe output contexts. Existing ast-grep PHP grammar lowers entry cost. Dynamic framework binding remains substantial work |
| 2 | SQL, starting PostgreSQL migrations/functions | Application-language scans miss deployment-time privilege and database security mistakes | SECURITY DEFINER search_path and PUBLIC EXECUTE risks, selected privilege/RLS misconfigurations, carefully scoped destructive DML. Explicit PostgreSQL dialect, dollar-quote lexer/parser, migration context, unknown dynamic behavior; greater parser cost |
| 3 | HCL / Terraform | Covers infrastructure generated alongside application code; useful network/IAM/storage/TLS defects | Provider-specific resource policy packs and literal/expression provenance. Variables/modules/provider defaults can be unknown; no pretending a partial source scan equals a Terraform plan. Existing HCL grammar makes this a plausible earlier shipping candidate than SQL |
| 4 | PowerShell | Closes an important Windows automation gap rather than treating Bash as universal shell coverage | `.ps1/.psm1/.psd1`, Invoke-Expression and tainted command construction, script/error semantics, credentials; native PowerShell AST/PSScriptAnalyzer adapter with explicit missing-tool status |
| 5 | Dart / Flutter | Reaches a mobile/UI ecosystem where async lifecycle errors are consequential | BuildContext across await, mounted receiver checks, unobserved futures, stream/subscription/timer disposal; use native analyzer semantics rather than generic text warnings |
| 6 | Lua | Adds embedded/server/editor/game tooling with a readily available grammar | Tainted shell execution, dynamic loading, selected resource ownership. Lua and Luau are distinct targets; do not claim one parser covers both |
| Later | Scala, R, Objective-C; then narrower Zig/Solidity niches | Real use cases, but smaller immediate return or higher semantic/runtime cost | Revisit after the above and existing-module precision work; reuse JVM, scientific-code, or Swift/C++ expertise where applicable |

PHP powers **69.8% of websites whose server-side language W3Techs could identify** on the inspected October 6 page, not 69.8% of all websites. That supports the first-place recommendation without overstating the denominator. [W3Techs PHP comparison](https://w3techs.com/technologies/comparison/pl-php)

The [official ast-grep language list](https://ast-grep.github.io/reference/yaml) includes PHP, HCL, and Lua. Local ast-grep 0.45.3 probes successfully matched PHP execution syntax, an HCL resource block, and a Lua command call. Parser availability proves a feasible starting point, not a functioning module. SQL, PowerShell, and Dart need different parser/tool strategies. PostgreSQL's own [CREATE FUNCTION guidance](https://www.postgresql.org/docs/current/sql-createfunction.html) provides concrete SECURITY DEFINER/search_path/privilege requirements. Microsoft's [PSScriptAnalyzer documentation](https://learn.microsoft.com/en-us/powershell/module/psscriptanalyzer/invoke-scriptanalyzer) supplies a mature optional PowerShell route. Dart already documents [BuildContext across async gaps](https://dart.dev/tools/diagnostics/use_build_context_synchronously) and [unawaited futures](https://dart.dev/tools/diagnostics/unawaited_futures), useful semantics for a future adapter.

YAML, Dockerfiles, GitHub Actions, and Kubernetes deserve configuration policy packs, but a generic YAML grammar alone does not provide those semantics. They should not be inflated into new language support without domain-specific checks.

## Idea-wizard: 30 candidates, best five, next ten

Each candidate was considered against robustness, reliability, performance, intuitive behavior, user friendliness, ergonomics, usefulness, appeal, incremental value, and implementation practicality. Scores below are explicit planning judgments, not empirical measures. The ten-digit vector follows that order, each digit 1–5. Weighted score doubles usefulness/practicality and multiplies incremental value by 1.5. Synergy and existing work determine the final order; a numerical tie is not a measured distinction. No selected idea scores below three on average or one in any dimension.

| # | Candidate | Judgment vector | Decision / reason |
|---|---|---|---|
| 1 | Verified flow and sanitizer proofs in weaker frontends | 5544445544 | Best five; directly fixes demonstrated misses and noise; reuse D6/core |
| 2 | Native Kotlin coroutine, cancellation and ownership depth | 4444455544 | Best five; fills the thinnest advertised module with valuable native semantics |
| 3 | Activate well-proven dormant checks with honest CLI accounting | 4445555445 | Best five; obtains user value from existing implementation without uncontrolled rule inflation |
| 4 | Per-binding resource/task obligations in Ruby/Swift/Elixir/Kotlin | 5544445543 | Best five; replaces misleading aggregate correlation with receiver-aware evidence |
| 5 | Transfer strong negative-control tests and measured precision to weaker modules | 5554445544 | Best five; use D7/H6/H8, avoid a second calibration infrastructure |
| 6 | Parameter-binding and SQL provenance across JVM/Ruby/C#/Elixir | 5444445544 | Next ten; adapt existing Python/Go/Rust source/sink reasoning to real library calls |
| 7 | Framework-aware explicit security misconfiguration checks | 4444555544 | Next ten; Spring/Ktor/Rails/ASP.NET/Phoenix have reachable high-severity mistakes |
| 8 | Deadline, cancellation and failure-propagation checks | 4444445544 | Next ten; respect client/context defaults and task ownership rather than flag every call |
| 9 | Security-context crypto and constant-time semantics | 5444445544 | Next ten; reuse shared metadata hardening and actual API identities, not vocabulary alone |
| 10 | Native error/result observation | 4444455444 | Next ten; Ruby rescue, Elixir result tuples, JVM/Swift outcome APIs need tailored treatment |
| 11 | Effective twelve-language capability/provenance ledger | 5555555445 | Next ten; finish J1/D5 using active/advisory/gated/unavailable states and proof cases |
| 12 | PHP module with request-to-sink semantics | 4444555543 | Next ten; greatest new ecosystem reach, bounded first release |
| 13 | PostgreSQL SQL module | 4444445543 | Next ten; distinct security surface, strict dialect boundaries |
| 14 | HCL/Terraform module | 4444555544 | Next ten; feasible structural start, provider-specific semantics |
| 15 | Warm parsed-state and dependency caching for edited scans | 4454555543 | Next ten; extend K4/C6/C7, preserve correctness and benchmark honestly |
| 16 | PowerShell module | 4444445443 | Defer behind first three additions; optional native runtime/dependency cost |
| 17 | Dart/Flutter module | 4444445443 | Defer; native analyzer integration needed for credible receiver semantics |
| 18 | Lua module | 4444444444 | Defer; feasible but lower broad reach than PHP/HCL |
| 19 | Vue/Svelte/Astro/Blade embedded-language analysis | 4434445443 | Defer until selected host parsing and source-map locations are reliable |
| 20 | YAML/GitHub Actions/Kubernetes policy packs | 4444455443 | Defer; configuration context is valuable but distinct from generic YAML scanning |
| 21 | Narrow user-controlled fix previews | 4434554343 | Defer; detection precision comes first; no automatic code modification |
| 22 | Optional compiler-backed binding adapters | 5533445442 | Defer; useful precision ceilings, substantial dependency and deployment cost |
| 23 | Rust macro-aware analysis | 4433344342 | Defer; specialized scope and compiler coupling |
| 24 | Cross-language API/schema boundary analysis | 3323334342 | Cut from near-term plan; unresolved oracle and scope cost |
| 25 | Whole-program universal heap/type engine | 5522224421 | Cut; impractical for this product's lightweight constraints |
| 26 | Suppression reason/expiry review | 4444454344 | Defer; existing suppression semantics work, lower return than missed bugs |
| 27 | Validated persistent repository scan configuration | 4445554444 | Lower-priority bridge work for feedback-plan §4.1; current wrapper/session/installer configuration is not this capability |
| 28 | Fresh signed/platform release journey verification | 5554555544 | Prerequisite maintenance, reuse E5/F7/G6/H8; do not create a competing release program |
| 29 | New module scaffolding framework | 4444443344 | Reject as duplicate; `scripts/new-module.sh` and scaffold proof already exist |
| 30 | Streaming RSS/performance campaign | 4454445543 | Reuse C6/C7; a separate campaign would duplicate open work |

### The five best adaptations, in order

**1. Transfer proven value-flow and sanitizer reasoning.** Donors: Python AST binding/branch analysis, JS value/alias summaries, Rust scoped helper/receiver resolution, C# body-validated guards, and common `taint_flow.py`. Receivers: Java/Kotlin redirects, Ruby URL/path, Swift redirect/path, Elixir redirect/path; later C++. Keep the newer Java/Kotlin path engine and improve its remaining named-sanitizer shortcut. Begin with same-file bindings, literal kills, joins, dominating exits, helper summaries, and sink-specific proof. Extend cross-file analysis only for explicitly selected dependencies. Preserve established public rule IDs, but do not preserve false findings for parity. Acceptance must include the six reproduced cases, ordinary positive controls, misleading names, shadowed APIs, helper redefinitions, late/partial validation, unrelated functions, loops, multiline syntax, and malformed/unsupported inputs. Unsupported or exhausted analysis must be explicit, never a clean result. Cost: medium/high, in separate receiver slices.

**2. Give Kotlin a genuinely native module.** Borrow C# task-handle obligations, Python cancellation/cleanup semantics, Go context propagation, Rust lock/await structure, and existing Java resource primitives. Implement Kotlin-specific `use {}` ownership, swallowed `CancellationException`, selected blocking operations in suspend contexts, detached/unobserved jobs, and justified null assertions/guard fallthrough. Resolve imports/receivers and coroutine scopes; do not assume every `launch` requires a local `join`, every `!!` is a bug, or every resource escaping a function leaks. Compiler-backed precision is optional later. Cost: medium; a few reliable families beat twenty-two empty headings.

**3. Bring mature dormant rules into real CLI behavior.** Audit Java, Ruby and JS advisory packs plus default-off narrowing/guard analyzers. A rule becomes default counted only after independent positive, safe, lexical-decoy, suppression, profile/category, cache and JSON/SARIF tests. Otherwise identify it honestly as advisory, gated or unavailable. Deduplicate equivalent observations by stable rule/location semantics, not indiscriminately by line. Missing AST/compiler tools and malformed custom rules must preserve explicit degraded/error behavior. This improves user coverage from code already paid for while controlling alert noise. Cost: low/medium, rule-specific qualification.

**4. Track resource and task obligations by binding.** Borrow Python AST ownership/context-manager analysis, Go deferred release, C# disposal/task handles, and Rust scoped async checks. Extend Ruby blocks/ensure, Swift defer/disposal/task observation, Kotlin use/coroutine scopes, and Elixir File/Port/Task semantics. Stop subtracting global acquire/release counts and reporting the first N lines as leaks. Account for transfer, return, exception/cancellation paths, double release and supervised task ownership; Elixir's supervision model is not a C# task copied into another syntax. Cost: medium/high; first prove a bounded resource family per receiver.

**5. Transfer the strongest proof practices and measure actual precision.** Python/JS/Rust/C# tests already exercise identity, branches, scopes and negative controls more deeply than ordinary fixture count thresholds. Extend that pattern to each weak module and Bash, with exact public rule IDs, independent realistic clean corpora, and changed-source metamorphic cases. Finish D7 rather than invent a second suite. Publish held-out precision/recall and uncertainty with the corpus/source versions and sample sizes; report confidence unknown where not calibrated. Split conformal prediction's marginal coverage is not a guarantee that findings above a confidence threshold have that probability of being true positives. Correct that acceptance claim without replacing it with weaker marketing. [Primary conformal-prediction tutorial](https://arxiv.org/html/2107.07511v6)

### The next ten, with implementation boundaries

6. **SQL provenance:** reuse common source/sink tags and value summaries, add API-specific parameter binding for JDBC/Kotlin database libraries, ActiveRecord, Dapper and Ecto. A parameter argument does not sanitize an interpolated query string; static SQL and placeholders need clean controls. Complement this with resource cleanup, not a duplicate taint engine.
7. **Framework security:** adapt explicit TLS/JWT/CORS/cookie/CSRF/autoescape checks to Spring/Ktor/Rails/ASP.NET/Phoenix configurations and middleware identities. Prioritize explicit insecure settings; absence of a local setting may mean framework defaults or configuration elsewhere. Tie request sources to framework APIs, not variable names.
8. **Deadlines/cancellation:** adapt existing Python/Go/C# mechanisms to JVM, Ruby, Swift and Elixir clients. Model configured clients, inherited contexts, cancellation ownership and known bounded APIs. Missing timeout syntax alone is not enough. Require request/task scope and identity evidence.
9. **Crypto/constant-time checks:** port actual API/algorithm context and recent secret-comparison scope metadata. Distinguish cryptographic secrets from parser tokens and public checksums, weak password hashing from a harmless content hash, and real comparators from similarly named user functions. Existing Python/JS/Go/Rust analyzers are donors; JavaScript's latest lexical views are reused within that frontend. Extend receiver detectors and controls without assuming a universal constant-time engine already exists.
10. **Error/result observation:** borrow Bash's status-masking insights and JS/C# asynchronous outcome checks, but encode native semantics: rescue swallowing, ignored `{:error, reason}`, failure-bearing JVM futures and Swift operations. Recognize logging, intentional recovery, escalation and returned errors. Keep cancellation rules under Kotlin/task work to avoid duplicate alerts.
11. **Effective coverage ledger:** finish J1's twelve-language registry from real CLI invocation state, tool readiness, counted/advisory status, selected analysis boundary and proof case IDs. Existing ten-column planned/implemented registry is stale. Generate docs from this evidence; avoid a new dashboard-only metrics project.
12. **PHP:** use the existing scaffold and common contract, add a bounded semantic frontend and a few high-value request-to-sink families; PDO prepared statements, comments/strings, local identifiers and framework defaults need negative controls. Extend ALL_LANGS/detection/contract, integrity/version and manifests coherently.
13. **PostgreSQL SQL:** use a dedicated lexer/parser for comments, identifiers, strings and dollar quotes. Start with explicit SECURITY DEFINER privilege/search_path hazards. Identify dialect/version and unresolved dynamic behavior. Do not claim source text proves deployed RLS or migration safety.
14. **HCL/Terraform:** use the existing parser with typed provider/resource rules. Resolve selected literals/locals; mark unresolved variables, modules and provider defaults unknown. A public-looking expression is not proof of an internet-exposed deployed resource. Add contradictory and safe config controls.
15. **Edited-source latency:** extend the real daemon/LSP with warm lexical/AST state and selected dependency summaries keyed by source, policy, helper/tool identities, configuration and context. Preserve bounds, cancellation and authentication. Compare changed-source output to cold scans, including dependency edits and policy changes. Benchmarks must run a live incumbent in the same invocation before claiming a competitive win; self-speedup alone is maintenance. Report any loss directly and abandon that lever.

## Bridge plan and work graph

**First repair delivery credibility.** Address Python 3.9 and prove real CLI scans at the supported interpreter floor. Use G6/H8/E5/F7 to observe the intended full/platform/release workflows and resolve current failures. A disabled workflow is an operational fact to investigate, not authority to enable or publish anything automatically. Check daemon and encoder release assets, installer/doctor journeys, signature provenance, and current module hashes. Preserve the existing release process and module/version/tag discipline.

Resolve the exact prescribed ShellCheck gate as maintenance: classify actual control-flow/style issues and prove indirect callback reachability before narrowly annotating a false positive. Do not replace the command with a lower-severity invocation or blanket suppression. If any gate is genuinely defective, the legitimate gate-fix evidence standard and admitted win/loss split still apply.

**Then obtain immediate analysis value.** Qualify dormant checks, fix the named-sanitizer/literal-kill failures, implement Kotlin native semantics, and replace per-file resource/task arithmetic. Prioritize dangerous missed bugs plus false positives in daily workflows. No wholesale engine rewrite is required. Keep each receiver slice independent so a blocked Elixir parser does not block a Java literal-kill fix.

**Then broaden proven families and ecosystems.** Add database binding, framework configuration, deadlines, crypto identity and error/result semantics; integrate precise coverage/calibration evidence. PHP is the first new module. HCL may ship before SQL because parser availability reduces its entry cost, even though SQL ranks higher in strategic value. PowerShell/Dart/Lua remain considered future work rather than immediate graph clutter.

The feedback plan's remaining optional persistent scan settings deserve a bounded lower-priority task: one validated declarative schema, clear defaults/project/environment/CLI precedence, no executable shell configuration, and policy identity in cache/daemon invalidation. A session-log directory flag or installer defaults must not be counted as implementing it.

**Finally meet quantified scale/latency targets.** Continue C6/C7/K4 with controlled cold/warm/edited-source measurements, actual context invalidation, and memory limits. Keep the original performance target visible while labeling unverified claims honestly. Do not weaken a gate, regenerate goldens to bless a defect, or count plan edits as implementation progress.

Every implementation task must name current donor/receiver files, selected semantic boundary, risks, public findings, prerequisites, and independent acceptance examples. Companion probes must exercise the real CLI or module in JSON and SARIF, check exact expected and forbidden public rule IDs and locations, and record command/tool/source identity, elapsed time, exit status and complete stdout/stderr under `test-suite/artifacts/`. Tests include comments/strings, shadowing, unrelated scopes, sanitizer mutation, malformed inputs, optional-tool failure, timeout/budget exhaustion, selected-file/ignore behavior, suppression/profile behavior, and cache/context invalidation where relevant. Required checksums/version/release work follows any future module/helper implementation; this audit did not change those assets.

Three ambition rounds strengthened this plan: (1) reuse existing engines and require ordinary-user availability rather than library completeness; (2) make sanitizer/ownership evidence binding- and sink-specific rather than copy pattern counts; (3) make empirical calibration, release observation and edited-source correctness explicit barriers to broad quality/performance claims. The corresponding beads and refinement evidence are recorded below after graph access is acquired. Existing owners and graph structure are preserved; no existing implementation bead is closed by this audit.

## Preserved historical report — September 8

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
