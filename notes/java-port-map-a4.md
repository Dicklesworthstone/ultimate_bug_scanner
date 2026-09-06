# A4-java Port Map — modules/ubs-java.sh → contract v2 (bead 0xjg.8)

Status: PORT COMPLETE (executor PortJava, 2026-09-05, commit e1608f2). v2 LIVE
behind UBS_CONTRACT_V2_JAVA=1; legacy default untouched;
UBS_LEGACY_MODULE_JAVA=1 escape; --format=sarif and ast-grep-less
environments fall through to the legacy path (env-error parity).
GATES: java+kotlin manifest 37/37 under the gate (= legacy 37/37 baseline,
totals byte-identical on 10 direct fixture runs); contract_conformance PASS
(10/10 modules); ubs_core self-test 404/404; shellcheck -S warning: no new
warnings (28 before = 28 after); K2 sink verified through
`ubs_core findings-merge` (NDJSON records normalize with fingerprints).

IMPLEMENTED LAYERS (commit e1608f2)
- ubs_core/java_scan.py: orchestrator — Pattern engine (line-anchored, so
  `[^)]`-style classes never cross newlines; count_lines same-line marker
  semantics), java_patterns loader, registered analyzers (java: taint only;
  kotlin: narrowing only), java_detectors loader, consolidated ast layer,
  sink-recount totals, legacy text renderer (+cat-15 staging note,
  rule-prefix good notes), --json-out summary with findings[].
- java_patterns/: 42 Patterns (foundations / concurrency_io / quality /
  security_rg / resource_lifecycle) covering cats 1-22 single-regex rg
  pipelines; require_regex expresses `grep -E` post-pipes, exclude_regex
  `grep -v` filters.
- java_detectors/: 15 heredoc ports — security_randomness, header_injection,
  ssrf_outbound_url, archive_extraction (verbatim taint engines incl. Kotlin
  statement joining), optional_get, equals_hashcode, runtime_exec, io_loops,
  tech_debt (info/warning tier as rule-id switch), collections_foreach,
  streams_concat, sql_concat_fallback (gated on both primary counts),
  control_flow (switch delta checks), resource_leaks (executor-per-file).
- java_rules.py + java_ast.py: the 35-rule pack + 2 async rules generated
  into ONE sgconfig — ONE `scan -c` per 400-path batch. Counted ids only:
  5 resource (emit_ast_rule_group severities, NO marker check) + 2 async
  (warning, marker check current+prev) + cat-1 isPresent probe (info) +
  cat-21 `String $K = $V;` ast_search conjunct (warning) — the rest of the
  pack is an informational dump exactly as legacy.
- ubs-java.sh: run_contract_v2_java + run_v2_legacy_parity_bridges_java
  (record-less section headers + cat-17 project/java line + Summary
  Statistics + legacy exit formula) + gate before the startup banner;
  --report-json=FILE parsing added (copies the NDJSON sink = K2).

PARITY DECISIONS
- lifecycle_java analyzer does NOT run under v2: with ast-grep at the gate,
  legacy cat 19 uses the ast rule group and the helper is only the
  no-ast-grep fallback. guards_java (bead D3) has no legacy java counterpart
  — gated behind --enable-new-analyzers (python.narrowing precedent).
- ast_search conjuncts of cat 3/4 checks contribute nothing on any manifest
  fixture; the v2 keeps the rg halves (single count) — documented divergence.
- cat 9/13 delta checks anchor `diff` records on the trailing case/switch
  lines so summed counters equal the legacy printed counts.
- Analyzers' paths relativized to --project-dir (legacy heredoc relpath
  form); patterns/detectors keep list paths (legacy rg form).

PROCESS BUDGET: core pipeline = 5 heavyweight spawns (1 rg file-list,
1 rule-gen python3, 1 java_scan python3, 1 ast-grep scan, 1 bridge python3);
strace total ~30 execs including the legacy-parity arg-parsing preamble
(xargs/echo x6, shared with legacy) and coreutils (mktemp/rm/dirname/etc.).
Fixture sweep wall time ~4-5s vs ~25-60s legacy.

FOR THE INTEGRATOR (Main, shared files untouched by this bead)
1. ubs run_lang (~5620): add `|| "$lang" == "java"` to the --report-json
   forwarding condition (java module parses the flag since e1608f2).
2. ubs HELPER_CHECKSUMS/pinned module hashes: add entries for
   modules/ubs-java.sh and helpers/ubs_core/java_scan.py, java_ast.py,
   java_rules.py, java_patterns/{__init__,foundations,concurrency_io,
   quality,resource_lifecycle,security_rg}.py, java_detectors/{__init__,
   _common,optional_get,equals_hashcode,runtime_exec,security_randomness,
   header_injection,ssrf_outbound_url,archive_extraction,io_loops,tech_debt,
   collections_foreach,streams_concat,sql_concat_fallback,control_flow,
   resource_leaks}.py (SHA256SUMS pins only install.sh/ubs).
3. contract.json java entry already carries --report-json (this bead,
   java-only hunk).
