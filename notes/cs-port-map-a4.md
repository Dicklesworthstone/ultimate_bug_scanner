# A4-csharp Port Map — modules/ubs-csharp.sh → contract v2 (bead 0xjg.12)

Status: PORT COMPLETE (executor PortCsharp, 2026-09-05). v2 LIVE behind
UBS_CONTRACT_V2_CSHARP=1; legacy default untouched; UBS_LEGACY_MODULE_CSHARP=1
escape; sarif AND active-dotnet runs (HAS_DOTNET=1 without --no-dotnet and at
least one dotnet step enabled) fall through to the legacy path.

GATES:
- csharp manifest 25/25 PASS under UBS_CONTRACT_V2_CSHARP=1 (run_manifest.py,
  substring assertions included — both A7 suppression cases and the
  --format=json helpers-status case pass through the real meta-runner flow).
- PER-CASE TOTAL PARITY: rc + critical/warning/info/files byte-identical to
  the legacy run on the same env for all 25 cases (legacy baseline
  /tmp/cs_legacy_totals.tsv vs the gate-env artifact result.json diff;
  25 identical / 0 differing). Legacy baseline capture: 25/25 PASS pre-port.
- contract_conformance PASS (10/10 modules); ubs_core self-test 404/404;
  shellcheck -S warning: ZERO findings on ubs-csharp.sh (whole file, not just
  the new block); check_docs_claims: only the two pre-existing failures
  (`helpers` checker non-recursive on_disk set — fails on HEAD the same way;
  `module-contract` "…--report-json is accepted by N modules but not in
  contract.json" — one more module than before my change, see FOR MAIN).
- K2 sink verified end-to-end: module --emit-findings-json (and --report-json)
  write the NDJSON sink; `ubs_core findings-merge` folds it into combined
  top-level findings[] with fingerprints + scanners[].findings_sink=true
  (12 records on the ssrf fixture; 26 on the buggy dir via `ubs --format=json`).
- Process budget: strace -f -c ⇒ 31 execve total, 5 heavyweight spawns
  (1 rg file list, 1 rule-gen python3, 1 csharp_scan python3, ≤1 ast-grep per
  400-path batch, 1 bridge python3) — same envelope as go/java.
  Fixture sweep wall time ~0.4-1.0s/case vs ~1.5-5.7s legacy.

IMPLEMENTED LAYERS
- ubs_core/csharp_scan.py: orchestrator (js/py/go/java/ruby semantics).
  Pattern engine = LINE-ANCHORED matching (rg never matches across lines;
  python finditer over full text would — e.g. `[^)]*` in the cat-7
  Path.Combine pattern), marker lines dropped (count_lines parity),
  exclude_regex re-applied over the rg output form `path:line:content` for
  `grep -v` parity, gate_regex = project-wide precondition (cat-20 await
  census). Loaders: csharp_patterns (42 patterns), csharp_detectors (4
  heredoc ports), registered analyzers (taint x2, lifecycle, narrowing,
  async-handles; guards_csharp has NO legacy counterpart → gated behind
  --enable-new-analyzers, python.narrowing/java.guards precedent),
  cat-18 inventory computed check, consolidated ast layer, sink-recount
  totals, legacy-flavored text renderer, --fail-critical/--fail-warning
  thresholds, UBS_SKIP_TYPE_NARROWING honored in-process.
- ubs_core/csharp_patterns/: foundations (cat 1 null-forgiving / #nullable
  disable / throw-new-Exception), concurrency (cat 2 HttpClient +
  stream-no-using with the BRE `[[:space:]]*using` exclude; cat 3 async void,
  .Result, .Wait(, GetAwaiter().GetResult(, Thread.Sleep(), correctness
  (cats 4/5/6/7/10), security_rg (cat 8 weak crypto, TLS callback, shell
  Process API, SQL concat, hardcoded secrets; `[[:space:]]` transliterated to
  `[ \t]` — identical for single-line matching), quality (cats 9/11/15/16/
  21/22/23/24), async_locks (cat 20 lock-in-async needs_no_ast+await gate,
  SemaphoreSlim.Wait).
- ubs_core/csharp_detectors/: verbatim heredoc ports — archive_extraction,
  header_injection, outbound_url, security_randomness (find(files, base_dir)
  protocol; statement joining / comment stripping / ubs:ignore placement /
  PATH_LIMIT taint windows byte-faithful; strip_line_comments_block for the
  randomness heredoc's /* */ handling). The path-traversal and open-redirect
  heredocs are NOT re-ported — taint_csharp_request / taint_csharp_redirect
  (bead A2) already replace them via run(ctx); this port is their first
  production caller.
- ubs_core/csharp_rules.py + csharp_ast.py: the 4-rule pack (write_ast_rules
  verbatim) into ONE sgconfig-csharp.yml, `scan -c --json=stream` per
  400-path batch. UNLIKE ruby/java, EVERY pack rule joins the counters
  (legacy cat 17 ingested the whole scan): dedup by (rule, display, line,
  col) across batches, CURRENT-line-only ubs:ignore check (legacy
  is_ignored never looked at the previous line), severity from
  SEVERITY_MAP (= legacy AST_RULE_SEVERITY, all warning), titles from
  SUMMARY_MAP (= legacy AST_RULE_SUMMARY).
- ubs-csharp.sh: run_contract_v2_csharp + run_v2_legacy_parity_bridges_csharp
  + gate inside main() after the --list-rules block (so --list-rules stays
  legacy). Bridge = record-less section headers + static dotnet dim notes +
  helper good-notes + cat-17 unavailable/clean notes + cat-20 ast note +
  Summary Statistics (legacy two-space indent) + legacy exit formula
  (sink recount; fail thresholds) + the summary document (compact JSON,
  legacy emit_summary_json shape + helpers statuses derived from the sink +
  findings[]). --report-json AND --emit-findings-json both copy the NDJSON
  sink (K2). --dump-rules copies the generated pack. Banner/Project/tools
  notes printed shell-side in text mode (legacy wording, --ci icon set).

PARITY DECISIONS
- narrowing_csharp IS legacy (helpers/type_narrowing_csharp.py thin entry):
  runs under v2 mapped to cat 1 with the legacy summary line; the analyzer's
  per-kind rule ids (negative_guard/positive_guard/try_get_value) merge into
  ONE renderer bucket — legacy printed one "Null/type guard fallthrough
  issues (N)" line. Same bucketing for csharp.lifecycle.* (one
  "Potential resource lifecycle leaks (helper): N" line).
- async_handles rule remapped csharp.lifecycle.unobserved_task_handle →
  csharp.async.unobserved_task_handle (the legacy module's add_finding id).
- cat 20: lock/await heuristic needs_no_ast — suppressed exactly when the
  ast pack ran (legacy AST_GREP_STATUS used/clean), gated on the project-wide
  await census (legacy second rg pass).
- cat 18 inventory: sln/csproj census via in-process depth-3 walk (find
  -maxdepth 3 semantics incl. single-file project targets), TFM census over
  the scanned list (legacy rg only ever saw INCLUDE_EXT files → csproj tags
  were never counted there either).
- Path relativization: patterns keep the ubs_list_files paths (rg form);
  detectors/analyzers/ast records relativized to the project base
  (legacy heredoc TSV display form) — java precedent.
- Record-backed sections render in legacy order; record-less section headers
  append after (ruby precedent) — layout divergence only, counters identical.

KNOWN DIVERGENCES (all parity-neutral on the manifest, documented)
- File list = ubs_list_files (rg, gitignore-respecting) vs legacy
  build_file_list (--no-ignore unless --strict-gitignore). A strict subset on
  fixture trees (no ignored .cs fixtures); go documented the same.
- v2 falls through to legacy when dotnet steps would actually run
  (HAS_DOTNET=1, NO_DOTNET=0, ≥1 step enabled). All manifest cases pass
  --no-dotnet; the pure-static path is what v2 covers. --no-build/--no-test/
  --no-format/--no-deps combinations that disable EVERY step still take v2.
- UBS_METRICS_DIR (persist_metric_json tools/helpers/dotnet blobs) is not
  written under v2 (same policy as the shipped js/py v2 for non-counter
  seams; no manifest case consumes it for csharp).
- --baseline/--max-samples/--max-detailed ignored under v2 (module never had
  them); -v raises the renderer sample cap via --detail-limit (legacy
  DETAIL_LIMIT) but the sink always carries every finding.
- Info-tier text diffs: renderer prints "🚨/[CRIT] title (n)" summary lines
  built from the legacy templates; sample lines reproduce print_matches
  (`path:line:code`) and helper TSV (`path:line:col - message`) forms.
- The one remainder: legacy FINDINGS (--emit-findings-json) capped rg-check
  samples at DETAIL_LIMIT; the v2 sink carries every finding (K2 point) and
  is NDJSON rather than the legacy object — shape-keyed downstream
  (merge_json_scanners skips it; findings-merge folds it).

FOR THE INTEGRATOR (Main, shared files untouched by this bead)
1. contract.json csharp extra_flags: add "--report-json" (module parses it
   since this bead; check_docs_claims module-contract currently counts
   csharp in the "accepted by N modules but not in contract.json" failure —
   pre-existing class, one module worse).
2. run_lang --report-json forwarding: NO CHANGE NEEDED for K2 — run_lang
   already passes --emit-findings-json="$TMPDIR_RUN/csharp.findings.json"
   for csharp, and this bead made that flag write the NDJSON sink, which
   `ubs_core findings-merge` folds (verified). If Main prefers the
   --report-json naming symmetry with the other ports, the central pass can
   switch the csharp branch — both flags work identically.
3. contract.json contract: 2 + default-on flip for csharp: belongs to Main
   (same as every A4 port); UBS_LEGACY_MODULE_CSHARP=1 is the escape.
4. This bead's scripts/update_checksums.sh run refreshed ubs against the
   current tree, which also pins the (un)committed elixir/swift/rust files
   present on disk — last-writer-wins as per the A4 flow; re-run before the
   final integration commit.

Verification artifacts: /tmp/cs_legacy_totals.tsv (legacy baseline per-case
rc+totals), /tmp/cs_parity_final.log (direct-module legacy-vs-v2 sweep),
test-suite/artifacts/csharp-*/result.json (gate-env manifest run).
