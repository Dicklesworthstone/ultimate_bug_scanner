# A4-swift Port Map — modules/ubs-swift.sh → contract v2 (bead 0xjg.11)

Status: PORT COMPLETE (executor PortSwift, 2026-09-05). v2 LIVE behind
UBS_CONTRACT_V2_SWIFT=1; legacy default untouched (gate-off byte-identical);
UBS_LEGACY_MODULE_SWIFT=1 escape; sarif/--list-rules/--dump-rules fall through
to the legacy path. Language key for Main's central run_lang forwarding pass:
`swift` (module parser gained --report-json; v2 copies the NDJSON sink to it,
exactly like ruby).

GATES (all green at commit):
- swift manifest sweep under the gate: 20/20 PASS (run_manifest.py, including
  substring assertions and --skip/--fail-on-warning permutations).
- Parity: /tmp artifacts diff — per-case totals (rc/critical/warning/info/files)
  byte-identical to the legacy run on the same env for all 20 cases
  (/tmp/swift_legacy_baseline.tsv vs /tmp/swift_v2_results.tsv style).
- shellcheck -S warning on ubs-swift.sh: 16 findings, ALL pre-existing
  (identical SC2034 set vs git HEAD); zero new.
- contract_conformance.py: ubs-swift.sh format_json now emits
  language+status+version (the dated XFAIL expectation for bead 0xjg.11);
  K2 --report-json receives the raw NDJSON sink.
- Process budget: 1 list + 1 rule-gen python + ≤1 ast-grep per 400-path batch
  + 1 swift_scan ≈ 4-6 processes (≤25 target).
- Checksums refreshed via update_checksums.sh + update_sha256sums.sh.

IMPLEMENTED LAYERS
- ubs_core/swift_scan.py: orchestrator (py/ruby_scan semantics; Pattern engine
  with threshold ladders, sibling-tier max_count, count_lines marker filter,
  grep -A<N> ordered-stream emulation for the intent pipelines; DERIVED hooks
  for cross-count checks; swift_detectors loader; registry analyzers
  taint/narrowing/lifecycle (regex_swift gated off — no legacy counter
  impact); legacy text renderer (all 23 category headers + subheaders + good
  notes + samples, MAX_DETAILED cap) + --json-out UBS summary with
  language/status and the issue-64 report payload; sink-recount totals.
- swift_patterns/: foundations (cat 1-2 incl. async-vs-await derived),
  closures_networking (3-4), errors_security (5, 6-rg, 7-rg + Process-residual
  derived), threading_perf (8-10, FileHandle-imbalance + @MainActor derived),
  debug_quality (11-14, print/NSLog ladder split), misc_cats (15 components
  sum, 17-19 rg, 20-21 derived, 22-23).
- swift_detectors/: verbatim heredoc ports — archive_extraction,
  shell_execution (ubs#101 semantics; count_findings() feeds the residual
  derived check), security_randomness (string-keeping stripper variant),
  header_injection + outbound_url (the two taint heredocs that had no A2
  analyzer), plist_checks (ATS + entitlements, plistlib), urlsession_correlation
  (ast-guided; consumes ctx.ast_records; legacy degradation branches: ast
  missing → info-0, rg precheck → good, empty stream → info-0 "Could not build
  ast-grep per-file index", all-resumed → good).
- Analyzers replace their heredocs: taint_swift_traversal/redirect
  (swift.taint.request_path_traversal / request_open_redirect, cat 6),
  narrowing_swift (cat 1; renderer aggregates to ONE "Swift guard let
  else-block may continue" bucket with "Examples: path:line:col → msg"),
  lifecycle_swift (cat 16, per-record RESOURCE_LIFECYCLE_SUMMARY titles).
- swift_rules.py + swift_ast.py: ONE pack rule (c04-urlsession-task-no-resume,
  byte-identical YAML) + user --rules=DIR into a single sgconfig; the config
  lives at the pack root pointing at ./rules (ast-grep parses every file under
  ruleDirs, so a config inside its own ruleDir fails to parse itself — the
  original bug that killed the AG layer in the first integration attempt).
  The stream feeds BOTH the correlation detector and the rule-pack summary
  buckets; run_ast_rules is NOT gated by --skip (legacy prints it outside
  categories 1-23), only marker suppression applies.

LEGACY QUIRKS PRESERVED (parity-critical):
- cat 3.1 strong-self pipeline: the legacy rg pattern has an unmatched ")" and
  NEVER compiles — the check always prints the good note. v2 keeps the spec +
  good note and emits no Pattern (the dead regex is documented in
  closures_networking.py).
- cat 6 Process info residual = rg count − shell-detector criticals (can go
  negative → check suppressed); shell-exec good note only when both are 0.
- cat 15 sums four RNI marker counts per (component,line) — a line with two
  markers counts twice (Pattern.components).
- cat 20 Package.swift gate + "Package.swift not found" info-0; cat 21
  storyboards = unpruned os.walk (legacy find semantics).
- plist/entitlements walk the scan root unpruned (legacy os.walk), findings
  carry absolute paths like the heredocs.
- Force-unwrap >30/>0 ladder, print/NSLog >50/>10/>0 and tech-debt >20/>10/>0
  ladders as sibling patterns; "Task usages" prints "Info (0 found)" at zero
  (Pattern.always).
- UBS_SKIP_TYPE_NARROWING=1 → info-0 degradation record; no .swift files →
  info-0 "No Swift sources detected".

KNOWN DIVERGENCES (documented, parity-neutral on the manifest):
- File list via ubs_list_files (no --hidden, no --max-filesize) vs legacy
  `rg --files --hidden` — strict-superset differences only on hidden files.
- Narrowing "Examples:" preview paths are scan-root-relative (legacy helper
  prints CWD-absolute); titles/counts/messages identical, meta path-restore
  normalizes both under the runner.
- v2 text skips the owl banner/preamble/tip lines (totals + asserted
  substrings unaffected); optional-analyzer passthrough runs the REAL legacy
  shell functions (swiftlint/swiftformat/periphery/xcodebuild say-lines
  byte-identical).
- --summary-json/--report-md/--emit-csv/--emit-html/--baseline/--dump-rules/
  --explain-rule/--list-rules are ignored under the v2 path (same policy as
  the shipped js/py v2); sarif mode uses the legacy path; correlation samples
  capped at 3 without -v (verbose raises DETAIL_LIMIT in legacy).
- Detector walks use rglob/sorted order; only affects sample ORDER, never
  counts.

FOR MAIN (central pass):
- run_lang --report-json forwarding list: add `swift` (module flag now exists;
  json-mode K2 merge is sink-shape-keyed NDJSON).
- contract.json swift entry: FLIP DECISION (contract: 2 + default-on +
  UBS_LEGACY_MODULE_SWIFT escape) belongs to Main; extra_flags should gain
  --report-json when the flip lands (hunk intentionally NOT committed here).
