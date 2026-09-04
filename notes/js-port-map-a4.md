# A4-js Port Map — modules/ubs-js.sh → contract v2 (bead 0xjg.4)

Read-only recon by the A4-js integrator (GLM-Flash session, 2026-09-04).
Full machine-readable report: '/home/ubuntu/.omp/agent/sessions/--data-projects-ultimate_bug_scanner--/2026-09-03T23-12-19-842Z_01a0698b-6b81-776a-8098-4b623f304fa7/JsPortRecon.md' (scout transcript).
Status: Pattern layer DONE (65 patterns, 16/19 categories) AND the v2 dual
path is LIVE behind UBS_CONTRACT_V2_JS=1 (commit 402ffcb): run_contract_v2_js
in ubs-js.sh (ONE ubs_list_files list, ONE ubs_core.js_scan process, NDJSON
sink, legacy text labels, fd3 json summary with module-level findings[],
--report-json receives the raw sink = K2 parity records flow TODAY).
js_ast.py scans consolidated sgconfigs (scan -c --json=stream per grammar,
marker suppression, severity overrides) — integration pending js_rules.py
(37-rule generator port, in flight). REMAINING: wire js_rules.generate +
js_ast.scan_all into run_contract_v2_js, AST-group categories (5/6/19
primary), heredoc completions, then flip the default (legacy becomes
UBS_LEGACY_MODULE_JS=1 escape hatch) and close with the 138-case js
manifest diff.

## Current state (v4.7, 10,877 lines, contract v1)
- Engines: ~100 rg pipelines (GREP_RN/RNI/RNW, 381-398; count_lines 402), ad-hoc
  `ast-grep --pattern` (~41 spawns), generated 37-file ast-grep rule pack
  (write_ast_rules 3134-3624, ensure_ast_rule_results 3631-3659 = 40+ `scan --rule`
  spawns), ~37 python heredocs (self-walking, inline ubs:ignore).
- ~350-400 process spawns per scan (target ≤ 25).
- print_finding (427-487) funnels all findings; counters CRITICAL/WARNING/INFO_COUNT.
- Stable `js.<slug>` ids live in the META-RUNNER (category_slug_for 4526-4547):
  1 null-undefined … 19 resource-lifecycle. Keep numbering stable or update table + docs.
- Output: text labels "Files scanned:/Critical issues:/Warning issues:/Info items:"
  (10804-10809) parsed by postprocess summary_from_text; --format=json emits ONE
  summary object on fd-3 (10872-10879); --report-json=FILE (=$TMPDIR_RUN/js.findings.json)
  writes per-CATEGORY records {severity,count,title,description} — NO per-sample
  file/line (this is the K2 gap).
- SARIF: run_sarif_rule_pack_scan (3075-3132) already groups rule files into ≤4
  `scan -c` invocations + jq merge — the consolidation pattern to reuse.
- ubs:ignore suppression points: count_lines(402), show_detailed_finding(637),
  emit_ast_rule_group(572-577), every heredoc inline, window.open rg(5941),
  PLUS meta-runner postprocess ubs_core.suppression (A7) — dual-layer by design.
- ubs_core analyzers taint_js.py / ctcompare_js.py / guards_js.py exist as verbatim
  duplicates awaiting this port to call them.

## Target architecture (contract v2, per bead spec)
1. Source lib/ubs-common.sh (already); --files-from NUL list via ubs_list_files
   (seam exists); ONE file list.
2. ONE NDJSON findings sink (tmp file): records {lang, rule_id, category_id,
   severity, confidence, file, line, col, message, remediation, fix, fingerprint,
   suppressed}. `emit_finding` appends; renderers + summary counters derive from it.
3. ≤ 3 `ast-grep scan -c` invocations: merge 37 base rules + 3 __variants into ≤3
   sgconfigs (reuse run_sarif_rule_pack_scan's grouping); consume --json=stream ONCE
   per group through one python parser into the sink.
4. ONE `python3 -m ubs_core` invocation covering taint/guards/ctcompare (analyzers
   already migrated in A2) instead of 3 heredocs; remaining heredocs port category
   by category into ubs_core analyzers (A2 pattern: main() byte-parity + run(ctx)).
5. ONE rg pass (or python single-walk) feeding rg-based categories.
6. Renderers (text/json/sarif) read the sink; summary_from_text labels preserved
   verbatim; category_slug_for numbering unchanged.
7. Dual path: UBS_LEGACY_MODULE_JS=1 keeps the old code path for one release
   (seam: module preamble self-location, cf. postprocess-vs-legacy_postprocess
   pattern in ubs 5429-5441). Test seams that must survive both paths:
   UBS_TEST_FORCE_NO_AST_GREP, UBS_AST_GREP_BIN, UBS_METRICS_DIR, bin_shims.
8. K2 (7qy7.2): meta-runner merges the sink into combined findings[] and derives
   --beads-jsonl per-finding records + SARIF results + toon (json passthrough).
   Merge side is sink-shape-keyed (NDJSON vs summary) so it lands before the port
   completes; parity lights up per language as each A4 port lands.

## Port order (category-by-category, manifest totals diffed after each)
Async rules (5) → error-handling (6) → resource-lifecycle (19) → null-safety (1) →
math (2) → type-coercion (4) → parsing (9) → control-flow (10) → vars (13) →
debug (11) → perf (12) → code-quality (14) → regex (15) → dom (16) → typescript
(17) → node (18) → function-scope (8) → proto-object (3) → security (7, largest:
30 checks, many already in ubs_core).

## Verification gates per step
- 138 js manifest cases (list in scout report; totals must not move).
- shellcheck -S warning; ./scripts/update_checksums.sh + update_sha256sums.sh.
- contract.json js entry: contract: 2; extra_flags re-check via check_docs_claims.
- UBS_PROFILE process count ≤ 25 on test-suite/js.
