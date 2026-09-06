# A4-elixir Port Map — modules/ubs-elixir.sh → contract v2 (bead 0xjg.13)

Status: PORT COMPLETE (executor PortElixir, 2026-09-05). v2 LIVE behind
UBS_CONTRACT_V2_ELIXIR=1; legacy default untouched (gate-off 18/18 re-verified
after the module edits); UBS_LEGACY_MODULE_ELIXIR=1 escape; sarif falls through
to legacy. Language key for Main's central run_lang forwarding pass: `elixir`
(the module now parses --report-json; the v2 path copies the NDJSON sink to
it — K2 parity records flow exactly like ruby).

GATES (all green before commit):
- Manifest: 18/18 elixir cases PASS under UBS_CONTRACT_V2_ELIXIR=1
  (run_manifest.py, substring + exit assertions included), and every case's
  rc/critical/warning/info is IDENTICAL to the legacy run on the same env
  (/tmp/elixir_legacy_results.tsv vs /tmp/elixir_v2_results.tsv diff = empty;
  legacy re-swept 18/18 after the module edits to prove the default path
  didn't move). V2 sweep ~18s vs legacy ~35s.
- shellcheck -S warning: 11 pre-existing SC2034, zero new.
- contract_conformance.py modules/ubs-elixir.sh: PASS 8/8 checks run
  (format_json now emits language+status — ruby-precedent prep for Main's
  contract:2 flip; list_categories/rule_inventory/process_budget stay
  skipped while contract:1). --list-categories is implemented (16-category
  map, early exit 0) and --report-json is parsed, so the contract.json
  extra_flags update is additive-only.
- ubs_core self-test: 404/404; elixir registry analyzers' 16 self-tests OK.
- Checksums: ubs MODULE_CHECKSUMS[elixir] + all 36 elixir_scan/patterns/
  detectors HELPER_CHECKSUMS entries match the committed files (surgical
  update — sibling rust/swift entries left at their committed values);
  SHA256SUMS refreshed for the new ubs hash.
- Process budget (v2 manifest path): ~12 sequential spawns (3 mktemp + 1 rg
  lister + 1 orchestrator python3 + tr/wc + 1 bridge python3 + cat + 3 rm),
  max 1-2 concurrent — well under 25. No ast layer at all: the elixir module
  ships no ast-grep pack (contract.json routes custom rules to "all modules
  except elixir").

IMPLEMENTED LAYERS
- ubs_core/elixir_scan.py: orchestrator (ruby_scan semantics + a declarative
  extension set the elixir heredocs needed — see below; Pattern engine
  line-scoped like cpp_scan, marker-filtered like count_lines; sink-recount
  totals; legacy text renderer; --json-out summary with language+status and
  the issue-64 report payload).
- elixir_patterns/ (7 modules, 60 patterns): foundations (cats 1-3),
  security_rg (cat 4 rg checks), phoenix (cat 5, IS_PHOENIX-gated),
  ecto_concurrency (cats 6-8), debug_quality (cats 9+11), perf_misc (cats
  10/12/13/15), mix_deps (cat 14, mix.exs-scoped).
- elixir_detectors/ (7 modules): verbatim heredoc ports — archive_extraction,
  response_header_injection, outbound_url, security_randomness,
  hardcoded_secrets — plus the two filesystem checks config_runtime_exs
  (cat 12) and mix_lockfile (cat 14). The four subtly different
  logical_statement variants of the heredocs are preserved per detector
  (documented in elixir_detectors/__init__); only the self-walking rglob is
  replaced by the v2 file list.
- Analyzers: taint_elixir_traversal + taint_elixir_redirect (registered bead
  A2) replace their cat-4 heredocs; both map to category 4. guards_elixir
  (guards_generic) and narrowing_elixir have NO legacy elixir counterpart —
  both stay off unless --enable-new-analyzers (ruby-narrowing precedent).

ELIXIR-SPECIFIC ENGINE EXTENSIONS (all declarative Pattern fields, beyond
ruby's components/max_count/exclude):
- diff_regexes: legacy NET counts (Task.async−await, ets.new−read_concurrency,
  File.open−close−stream, Port open−close, binary_to_term−[:safe], unpinned
  deps, and the shell-exec info remainder all−critical−variable). The record
  count equals the NET number (first N main hits); thresholds resolve
  against the NET count, so negative/zero diffs never emit.
- suppress_if: legacy count conjunctions (def>50 AND guarded<5; transaction>5
  AND no Multi; async:true>5 AND no Sandbox; def>20 AND @spec<5; actions>10
  AND auth==0).
- output_filter_regex / output_keep_regex: legacy `grep -v/-E` ran on rg's
  OUTPUT LINES (path:line:code) — path-based test/ filters, IO.puts'
  mix.exs filter, IO.inspect's bare `#\s*` (drops any line containing '#'),
  init/1's {:ok,|:ignore|:stop filter, and the sleep-in-tests KEEP filter are
  re-applied against the same pseudo-line, so path- and text-level legacy
  filtering is byte-faithful.
- gate (path_regex, content_regex): IS_PHOENIX — category 5 runs only when a
  listed mix.exs mentions :phoenix (single-file targets and plain projects
  stay silent like legacy; the counter-less "Not a Phoenix project" note is
  not reproduced, matching the record-less bridge policy).
- zero_finding: force_ssl count==0 → info "1" fallback (cpp precedent).

MODULE-SIDE (ubs-elixir.sh)
- run_contract_v2_elixir: ONE ubs_list_files list (tolerant: `rg --files`
  exit 1 on a no-match tree is an EMPTY scan like legacy, only a hard error
  with no readable entries aborts; single-file targets pass the file as the
  list), ONE ubs_core.elixir_scan process, NDJSON sink, numeric --skip /
  --only inversion, --fail-on-warning forwarded, json format writes the
  summary doc to /dev/fd/3 with `exec 3>&1` so standalone --format=json
  works (cpp/golang/java/ruby crash there; js/python/swift pattern), text
  format renders to a temp file (fd/1 capture safety, ruby precedent).
- run_v2_ex_tools: cat-16 mix-tool bridge — tool text passthrough verbatim;
  legacy print_finding counts are mirrored into TOOL_COUNTS (v2_tool_finding)
  because legacy mix tools DID bump counters (unlike ruby's bundler tools).
- run_v2_legacy_parity_bridges_elixir: record-less section headers for
  non-skipped categories without records + Summary Statistics (sink recount
  + tool counts) + legacy exit formula.
- --report-json: v2 copies the NDJSON sink (K2); legacy path writes the
  summary counters object (ruby precedent). NOT yet forwarded by run_lang —
  Main owns the forwarding term + contract.json extra_flags.

KNOWN DIVERGENCES (parity-neutral on the 18-case manifest, documented):
- Counter-less "good" notes and print_subheader detail lines are not
  reproduced in v2 text (record-less bridge policy, ruby precedent); no
  manifest case asserts them.
- NET-count patterns emit a deterministic prefix of the main hits as their
  records (e.g. Task.async diff) — the TOTAL matches legacy print_finding
  exactly; which specific lines get displayed may differ.
- Mix-tool findings (cat 16) are text passthrough + bridge counts; the v2
  --json-out summary reflects sink-only counters, so a local mix run's tool
  criticals bump text/exit but not the json doc (tools are unavailable on
  every CI/manifest environment; sink records are the K2 contract).
- v2 "Files scanned" counts the ubs_list_files list (rg, gitignore-aware);
  legacy TOTAL_FILES uses find -p (gitignore-blind). Identical on the
  fixture trees; identical totals reported per case.
- contract.json stays contract:1 — the flip (contract:2, default-on,
  UNPORTED_ALLOWLIST shrink, run_lang `elixir` --report-json forwarding,
  extra_flags += --report-json/--list-categories) belongs to Main's central
  pass, as for the six shipped languages.
