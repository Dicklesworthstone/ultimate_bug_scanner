# A4-ruby Port Map — modules/ubs-ruby.sh → contract v2 (bead 0xjg.10)

Status: PORT COMPLETE (executor PortRuby, 2026-09-05). v2 LIVE behind
UBS_CONTRACT_V2_RUBY=1; legacy default untouched; UBS_LEGACY_MODULE_RUBY=1
escape; sarif falls through to legacy. Language key for Main's central
run_lang forwarding pass: `ruby` (module has --report-json; v2 copies the
NDJSON sink to it).

GATES: ruby manifest 23/23 PASS under the gate (run_manifest.py, substring
assertions included); totals per case byte-identical to the legacy run on
the same env (/tmp/ruby_legacy_results.tsv vs /tmp/ruby_v2_results.tsv
style artifacts; 23/23 identical rc/critical/warning/info); shellcheck -S
warning: 13 pre-existing, zero new; contract_conformance PASS for
ubs-ruby.sh (format_json now emits language+status, dated expectation
bead 0xjg.10); checksums refreshed via update_checksums.sh +
update_sha256sums.sh.

IMPLEMENTED LAYERS
- ubs_core/ruby_scan.py: orchestrator (py_scan semantics; Pattern engine
  with max_count if/elif ladder tiers + cat-14 component sums; ruby_detectors
  loader; registry analyzers taint/lifecycle/guards, narrowing gated off;
  sink-recount totals; legacy text renderer; --json-out summary).
- ruby_patterns/: foundations (1-2), collections_cmp (3-4), exceptions (5),
  security_rg (6 rg subset), shell_io (7-8 rg), parsing_flow (9-10),
  debug_perf (11-12), vars_quality (13-14), regex_conc (15-17). grep -A3
  pipelines encoded as bounded cross-line regexes (py_patterns.flow
  precedent).
- ruby_detectors/: archive_extraction, open_redirect,
  response_header_injection, security_randomness (verbatim heredoc ports,
  shared _common.py helpers), json_parse_no_rescue (count-difference check),
  frozen_string_literal (project threshold >25 preserved).
- Analyzers replace their heredocs: taint_ruby_traversal (path traversal),
  taint_ruby_url (outbound URL), lifecycle_ruby (cat 8, shell severity
  table applied: file_handle=critical), guards_ruby (cat 1 deep chains;
  ruby.guards.guarded records dropped — legacy counted unguarded only).
- ruby_rules.py + ruby_ast.py: 29-rule pack (write_ast_rules 28 verbatim +
  run_async_error_checks rule), ONE sgconfig, scan -c per 400-path batch.
  count_only=CATEGORY_MAP — legacy ruby never converted pack output into
  counters (cat 18 was a --json-out/--sarif-out passthrough); ONLY the
  cat-16 async rule joins the sink/totals.

PROCESS BUDGET: 1 lister + 1 rule-gen python3 + ≤1 ast-grep per 400 paths +
1 ruby_scan + 1 bridge python3 ≈ 5-6 (≤25 target). Bundler tools (cat 19)
are a raw passthrough bridge, never sink records.

KNOWN DIVERGENCES (all parity-neutral on the manifest, documented):
- grep -A3 context pipelines: intent encoding (bounded cross-line regex);
  several headers reaching one target line each produce one record each.
- frozen_string_literal walks the v2 file list (module INCLUDE_EXT, rg
  excludes) instead of the legacy find pruning only .git/vendor/
  node_modules — a strict subset on fixture trees.
- Deep-chain good note ("Deep chains guarded") and per-subheader good lines
  are collapsed to per-category good notes in the renderer; guarded-chain
  records are dropped from the sink (legacy counted them 0).
- Legacy cat-16 "ast-grep scan failed" info line (the async rule YAML is
  invalid under this ast-grep build — `$$` metavariable — so legacy itself
  never counted it here) is represented record-less: the parity bridge
  always prints the "Async error path coverage" subheader, and the pack
  config yields zero records exactly like the legacy consolidated scan
  (which also fails under `scan -c` when that rule is in it). On an
  ast-grep build that parses the rule, both paths light up identically.
- --json-out/--sarif-out/--dump-rules/--summary-json/--only-rules/
  --disable-rules/--ag-* flags are ignored under the v2 path (same policy
  as the shipped js/py v2); sarif mode uses the legacy path.
- contract.json stays contract:1 — FLIP DECISION (contract:2 + default-on +
  UBS_LEGACY_MODULE_RUBY escape) belongs to Main, as does the central
  run_lang --report-json forwarding term (`ruby`) + K2 findings-merge list.
- contract.json ruby extra_flags gained --report-json (module parser flag,
  v2 sink copy); the hunk is left UNCOMMITTED for Main's central pass.
