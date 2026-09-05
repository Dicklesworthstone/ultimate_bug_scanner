# A4-golang Port Map — modules/ubs-golang.sh → contract v2 (bead 0xjg.6)

Status: PORT COMPLETE (executor PortGolang, 2026-09-05). v2 LIVE behind
UBS_CONTRACT_V2_GO=1; legacy default untouched; UBS_LEGACY_MODULE_GO=1
escape; sarif falls through to the legacy path. The v2 gate additionally
requires ast-grep + python3 (both detection-critical for Go) and falls
through to legacy otherwise — mirroring the js arc's env-error parity.

GATES:
- golang manifest 43/43 under UBS_CONTRACT_V2_GO=1 (= legacy 43/43 baseline).
- PER-CASE TOTAL PARITY: critical/warning/info byte-identical to legacy on
  all 43 cases (artifact result.json diff: 43 identical / 0 differing) —
  see "Per-case parity" below.
- contract_conformance PASS (10/10 modules); ubs_core self-test 404/404;
  shellcheck -S warning: 13 SC2034 = exact pre-existing baseline, 0 new;
  check_docs_claims: module-contract PASS; only the pre-existing `helpers`
  checker failure remains (same on HEAD; its on_disk set is non-recursive
  while HELPER_CHECKSUMS pins helpers/ubs_core/ subdirs — checker bug).
- K2 sink verified end-to-end: module --report-json writes the NDJSON sink;
  `ubs_core findings-merge` folds it into combined findings[]
  (23/23 records on the ssrf fixture).
- Process budget ≈ 7-9 (rg list + rule-gen py + go_scan py + ≤2 ast-grep
  batches per sgconfig + go-run lifecycle bridge + parity-bridge py),
  vs legacy ~250-400.

IMPLEMENTED LAYERS
- ubs_core/go_scan.py: orchestrator (js_scan/py_scan semantics). Pattern
  engine = distinct matching lines, marker lines dropped (count_lines
  parity), per-pattern threshold ladders, exclude_regex/require_regex for
  legacy `grep -v`/`grep -E` post-filters. Loaders: go_patterns (rg
  pipelines), go_detectors (heredoc ports), registered analyzers
  (taint_go + ctcompare_go; guards_generic/narrowing_go have NO legacy Go
  counterpart → gated behind --enable-new-analyzers like python's
  narrowing), go_ast bridge, computed_checks, sink-recount totals, legacy
  text renderer + json summary.
- ubs_core/go_patterns/: 14 patterns — cats 1/2 censuses (goroutine
  launches, select), cat 6 (blank discards; fmt.Errorf w/o %w via
  exclude+require), cat 7 (json.Unmarshal), cat 8 (io.ReadAll >10), cat 9
  (weak crypto), cat 10 (unsafe/reflect), cat 12 (toolchain/replace), cat
  14 (fmt >50; sensitive logs, grep -i), cat 15 (ctx-not-first-param).
- ubs_core/go_detectors/: 14 heredoc ports (archive_extraction,
  path_traversal, open_redirect, header_injection, outbound_url,
  host_header, reverse_proxy_ssrf, request_body_limit (cat 8),
  security_randomness, hardcoded_secrets, jwt_verification,
  cookie_security, cors_credentials, request_regex). Verified
  byte-identical (line, detail) streams vs the original heredocs across
  all 36 security/suppression fixtures (incl. per-fixture zeros and
  marker windows: 2-line standard, 3-line body-limit, statement-level
  secrets/jwt/cookie).
- ubs_core/go_rules.py + go_ast.py: 64 base rules + go.async.goroutine-
  err-no-check (own sgconfig-go-async.yml, mirroring the legacy separate
  `scan --rule` spawn so the cat-16 tally matches AST_JSON). generate()
  byte-reproduces the YAML pack (verified vs sed extraction); this
  ast-grep build parses all 65 rules (no _UNPARSEABLE_RULES). go_ast
  scans per 400-path batch, no marker filtering, text severities from the
  per-callsite AST_CONSUMPTION table (legacy print_finding severity is
  callsite-hardcoded, YAML severity only matters for SARIF). Multi-category
  rules emit one record per consumption entry (go.sql.begin-without-defer-
  rollback → cat 5 warning + cat 21 info; the three defer-before-err rules
  → cats 4/5 + cat 20), preserving legacy double counting.
- computed_checks in go_scan: multi-count bash ratios (WaitGroup, mutex,
  Tx begin/end, os.Open/Close, DB context-less, http.Server/Shutdown,
  t.Parallel) and AST-count-gated regex fallbacks (tls-insecure-skip
  composite incl. the count_indirect_tls_insecure_skip heredoc port with
  wc_num no-marker-filter parity; exec-sh-c; time-after-in-loop window;
  http-response-body-not-closed; sql-rows-not-closed) plus the
  index_project inventory (go.mod version/1.23 gate, go.sum, go.work,
  test files, multi-module drift).
- ubs-golang.sh gate: run_contract_v2_go + run_v2_legacy_parity_bridges_go
  (after the --list-rules block, before banner). Bridge = cat 17 lifecycle
  `go run helpers/resource_lifecycle_go.go` TSV → sink records + text
  (rule go.lifecycle.<kind>, legacy tables 142-182), record-less legacy
  section headers, cat-16 rule tally (via --tally-out sidecar), cat 18
  static info-0 note, Summary Statistics block, legacy exit formula
  (7935-7937). UBS_CATEGORY_FILTER=resource-lifecycle → whitelist 5,17 →
  v2 skip mapping (py precedent). Module grew --report-json= parsing
  (REPORT_JSON) + contract.json golang extra_flags entry.

KNOWN DIVERGENCES (parity-neutral, all documented)
- legacy `grep -v "(ctx[[:space:]]+context\.Context"` in the cat-15
  pipeline is BRE (`+` = literal) so the exclusion NEVER fires; the v2
  exclude_regex reproduces the BRE semantics byte-faithfully. An
  ERE-correct exclusion would drop legacy findings (caught via the
  per-case totals diff).
- Dead checks go.context.cancel-defer-before-shadow/-delayed (counted but
  never generated in legacy) emit nothing. Orphan rules (generated, never
  printed: go.resource.timer-no-stop, go.sort-slice-mutates,
  go.content-type-prefix-match, go.os-remove-no-error-check,
  go.missing-sync-before-remove, go.fmt-errorf-no-wrap,
  go.json-decode-no-limit, go.exec-pgrep-unanchored,
  go.context.cancel-defer-before-err-check) surface only in the cat-16
  tally, exactly like legacy AST_JSON.
- v2 ast layer scans the ubs_list_files file list instead of the raw
  project dir (legacy ast-grep saw vendor/ etc.; rg/detector layers never
  did — fixtures unaffected).
- --strict (YAML severity sed) has no v2 effect: legacy text severities
  are callsite-hardcoded, so --strict never changed text output.
- --only-changed narrows only legacy grep pipelines (partially honored in
  legacy itself); --go-tools (cat 18) raw passthrough stays legacy-only;
  v2 prints the same info-0 disabled note.
- Info-tier static notes (go.work not found / No test files found) are
  printed with 0 counts in legacy and carry no records in v2 (counter
  parity: 0).
- Meta-runner run_lang --report-json forwarding (ubs ~5619) is CONTENDED:
  per Main, each port reports its language key and Main adds all four
  terms centrally. golang key requested: `golang`.

Per-case parity (legacy env vs UBS_CONTRACT_V2_GO=1, totals c/w/i):
  golang-buggy 30/40/98, golang-clean 0/4/32, golang-taint-buggy 10/1/12,
  golang-taint-clean 0/0/11, redos-regex 0/3/0 & 0/0/0,
  host-header 5/0/0 & 0/0/0, ssrf 7/0/0 & 0/0/0, reverse-proxy 3/0/0 &
  0/0/0, open-redirect 4/0/0 & 0/0/0, header-injection 5/0/0 & 0/0/0,
  cors 8/0/0 & 0/0/0, cookie 0/4/0 & 0/0/0, tls 0/4/0 & 0/0/0,
  path-traversal 6/0/0 & 0/0/0, archive 2/0/0 & 0/0/0, body-limit 0/6/1 &
  0/0/0, random 7/0/0 & 0/0/0, ctcompare 9/0/0 & 5/0/0 (parser-token) &
  0/0/0, jwt 7/0/0 & 0/0/0, secrets 10/0/0 & 0/0/0, async 0/1/7 & 0/0/8,
  resource-lifecycle 1/6/4, suppression markers 0/0/2 & nomarkers 4/1/2.
  Exit codes identical per case; 43/43 PASS both envs.
