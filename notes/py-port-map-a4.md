# A4-python Port Map — modules/ubs-python.sh → contract v2 (bead 0xjg.5)

Recon by PyPortRecon (scout) for the A4-python integrator (GLM-Flash), 2026-09-05.
Architecture decision: ONE `python3 -m ubs_core.py_scan` process (py_patterns
Pattern table + in-process analyzers) emitting the K2 NDJSON sink; dispatch
gated UBS_CONTRACT_V2_PY=1, escape UBS_LEGACY_MODULE_PY=1 — mirroring the
completed A4-js arc (notes/js-port-map-a4.md, implemented in modules/ubs-js.sh
run_contract_v2_js + modules/helpers/ubs_core/js_scan.py).

Status: RECON COMPLETE. Executor follows the js playbook wave order.

# A4-python Port Map — modules/ubs-python.sh → contract v2 (bead 0xjg.5)

Read-only recon by the A4-python scout (PyPortRecon, 2026-09-05). No files were written; the integrator persists this report to `notes/py-port-map-a4.md`.
Template: `notes/js-port-map-a4.md`. Implemented reference: `modules/ubs-js.sh` `run_contract_v2_js` (3898-3963) + `run_v2_legacy_parity_bridges` (3726+) and `modules/helpers/ubs_core/js_scan.py`.

Status: python is the EASIEST A4 port — every detector is already python (37 inline heredocs + 2 helper files), so the v2 orchestrator (`ubs_core/py_scan.py`, js_scan-pattern) can run 100% of detection in ONE process with zero ast-grep and zero rg. The 5 python analyzers are ALREADY registered in ubs_core. REMAINING: write `py_scan.py` + `py_patterns/` pattern table, wire the dual-path gate, K2 sink flip of `--report-json`, contract.json `contract: 2`, then 82-case manifest parity + flip.

## Current state (v3.1, 11,879 lines, contract v1)

- Engines: ~57 static rg pipeline sites (`GREP_RN`/`GREP_RNI`/`GREP_RNW` arrays built at 447-470, `--pcre2 --hidden -j $JOBS --max-filesize $MAX_FILE_SIZE`) each followed by `count_lines` (471: `grep -v ubs:ignore | awk`, +2 procs) and often 1-2 ad-hoc `grep -A/-v` filters; `show_detailed_finding` (579-588) re-runs rg + `head` per finding with samples.
- ~37 python heredoc detectors (`python3 - "$PROJECT_DIR" <<'PY'`) that self-walk the tree with `ast` — line numbers below. Two output dialects: (a) TSV `rule_id\tcount\tsamples` consumed with metadata assoc-arrays (taint 785-971, async-errors 674-784, resource-lifecycle helper), (b) `__FINDING__\t<sev>\t<count>` / `__SAMPLE__\tfile\tline\tcode` consumed by a `while IFS=$'\t' read -r tag a b c` case (all 33 security heredocs).
- 51-file ast-grep rule pack: `write_ast_rules` (9313-10002) emits `.yml` files into a mktemp dir + sgconfig.yml; `run_ast_rules` (10004-10150) spawns ONE `scan -r <file>` PER RULE (51 spawns text mode; again in sarif mode; AGAIN in emit_summary_json's histogram 11692-11702). Plus 4 ad-hoc `ast-grep run -p` (`ast_search` 9232-9239 for deep-attr 10350, division `$A / $B` 10444-10447, `analyze_py_attr_guards` 9240-9312 two spawns) and 1 rule in `run_async_error_checks` (686-703).
- print_finding (506-553) funnels everything; counters CRITICAL_COUNT/WARNING_COUNT/INFO_COUNT; `bump_category_count` (483-490) fills `CAT_COUNTS[1..23]` (ast-pack header sets `CURRENT_CATEGORY=0`, so pack findings count in totals but not per-category).
- Findings scratch for --report-json/SARIF: TSV records `F\tsev\tcount\ttitle\tdesc` / `S\tfile\tline\tcode` appended by `record_json_finding`/`record_json_sample` (492-505) — per-CATEGORY records, ≤3 samples (MAX_JSON_SAMPLES), NO rule ids. This is the K2 gap; js parity = the sink IS the report (`cp "$sink" "$REPORT_JSON"`).
- Stable ids: legacy metadata tables only — `TAINT_RULE_IDS` (172-190: py.taint.xss/sql/command/eval, all critical), `ASYNC_ERROR_RULE_IDS` (159-169: py.async.task-no-await, warning), `RESOURCE_LIFECYCLE_*` (364-388: kinds file_handle[critical]/socket_handle/popen_handle/asyncio_task[warning] with acquire/release regexes), 52 ast-grep rule ids (below), SARIF heuristics run mints `python.heuristic.<slug(title)>`. Category ids `python.<slug>` live in the META-RUNNER (`category_slug_for` ubs 4658-4682); v2 sink records carry `category_id: "python.<slug>"` exactly as js_scan emits `js.<slug>`.
- ubs_core python analyzers ALREADY auto-registered (lang="python"): lifecycle_py, taint_py, guards_py, ctcompare_py, narrowing_py (§6).
- Suppression points (dual-layer by design, A7): `count_lines` drops marker lines from counts (471); `show_detailed_finding` skips marker lines (581-582); every heredoc checks `ubs:ignore` inline (e.g. taint 897-898 current+prev line); ast-pack parser checks current+previous line (10083-10090); PLUS meta-runner postprocess `ubs_core.suppression` statement-interval engine (A7, `python-suppression-intervals-*` manifest cases) — v2 must keep flat same-line exclusion in the pattern layer and let A7 do placements, as js_scan does.

## 1. CATEGORY INVENTORY (the port checklist)

Slugs are the meta-runner's `category_slug_for python` (ubs 4658-4682) — numbering is contract: 1 none, 2 numeric, 3 collections, 4 comparison, 5 async, 6 error-handling, 7 security, 8 functions, 9 parsing, 10 control-flow, 11 debug, 12 perf, 13 variables, 14 code-quality, 15 regex, 16 io, 17 typing, 18 modules, 19 resource-lifecycle, 20 uv-tools, 21 deprecations, 22 packaging, 23 notebooks. `category_name_for` python table: ubs 4377-4402. Module-local index printed by `--list-categories` (281-288). `UBS_CATEGORY_FILTER=resource-lifecycle` → module whitelist "16,19" (139-145). `UBS_PROFILE=loose` pre-skips 11,14 (147-154).

Legacy rg pipelines have NO rule ids; the v2 Pattern table mints `py.<cat-slug>.<name>` ids like js (contract.json rule_id_grammar: `<lang>.<family>.<name>`, e.g. py.json.loads-no-try). Severity ladders are threshold-descending (first match wins), mirroring js `thresholds` tuples.

**Cat 1 none — "1. NONE / DEFENSIVE PROGRAMMING" (10307-10387)**
- `== None / != None`: rg `==[[:space:]]*None|!=[[:space:]]*None`, warning >0, else good "No None equality comparisons" [10315-10322]. (Pack duplicate: `py.none-eq` warning, 9351-9360.)
- Attribute chains depth ≥4: count via `ast_search '$X.$Y.$Z.$W'` or rg fallback [10324-10352]; guard split via `analyze_py_attr_guards` (9240-9312: 2 ast-grep runs + PYHELP heredoc → unguarded/guarded JSON) + parse heredoc [10332]; ladders info >15 "Deep attribute access ($count)", info >0 "Some deep attribute access detected", good "$guarded_inside" "Deep attribute chains guarded" [10356-10366]. → REPLACED by `guards_py` (python.guards.deep_attr_chain, info, GH #90).
- dict.get no default then deref: rg `\.get\(['"][^'"]+['"]\)(\.|\[)`, warning >10 [10381-10386].

**Cat 2 numeric — (10389-10486)**
- Division by variable: AST-backed (temp py script 10401-10406, `ast-grep run -p '$A / $B'` piped in 10444-10447) → warning >25 "Division by variable - verify non-zero", info >0 "Division operations found - check divisors" [10456-10471].
- Float equality: rg `==[[:space:]]*[0-9]+\.[0-9]+`, warning >3 [10474-10479].
- Modulo by variable: rg `%[[:space:]]*ident`, info >10 [10481-10485].

**Cat 3 collections — (10488-10571)**
- Index arithmetic `arr[i±1]`: rg, warning >12, info >0 [10496-10503].
- Mutation during iteration: heredoc (10506-10563) → warning "Possible mutation during iteration" + per-fix desc.
- len(x)==0: rg, info >8 [10566-10570].

**Cat 4 comparison — (10573-10591)**
- `run_is_literal_comparison_checks` (9037-9217): heredoc w/ `warnings` filter (9069) → warning "Using 'is' with literals"; rg fallback when no python3 (9040-9048); good otherwise. Manifest issue-66. (Pack: `py.is-literal` warning 9362-9373.)
- type(x)==T / is T: rg, warning >0 "type equality used" [10585-10590]. (Pack: `py.type-equality` warning 9660-9669.)

**Cat 5 async — (10593-10626)**
- async/await census: rg counts; info "Async functions found"; warning ratio "Possible un-awaited async paths" [10600-10607].
- await inside loops: rg+grep pipeline, info >3 [10609-10615]. (Pack: `py.await-in-loop` info 9708-9717.)
- Blocking calls in async def: rg pipeline, warning >0 [10617-10624]. (Pack: `py.async-blocking` warning 9691-9706.)
- `run_async_error_checks` (674-784): writes 1-rule pack `py.async.task-no-await` (686-698: `$TASK = asyncio.create_task($$$)` without add_done_callback/await; severity warning), `scan -r`, parse heredoc (727), emits via ASYNC_ERROR_* arrays. KEEP rule id stable.

**Cat 6 error-handling — (10628-10659)**
- Bare except: rg `^\s*except\s*:\s*$`, critical >0, good fallback [10636-10643]. (Pack: `py.bare-except` error 9384-9395.)
- except…pass: rg, warning >3 [10645-10650]. (Pack: `py.except-pass` warning 9397-9408.)
- raise e: rg pipeline, warning >0 [10652-10658]. (Pack: `py.raise-e` warning 9410-9419; `py.except-broad` warning 9376-9382 pack-only.)

**Cat 7 security — (10661-11060; detectors 590-9035)** — inline rg + 33 heredocs:
- eval/exec: rg, critical "eval()/exec() present", good fallback [10669-10677]. (Pack `py.eval-exec` error 9439-9448.)
- pickle.load/loads: rg, critical "Insecure pickle usage" [10679-10685]. (Pack `py.pickle-load` error 9450-9459.)
- yaml.load without Loader: rg pipeline (grep -v Loader=), critical "yaml.load without SafeLoader" [10687-10693]. (Pack `py.yaml-unsafe` error 9461-9471.)
- shell=True / os.system: 2× rg summed, critical "Shell command injection risk" [10697-10707]. (Pack `py.subprocess-shell` error 9473-9486, `py.os-system` warning 9488-9495.)
- requests verify=False: rg, warning "TLS verification disabled" [10719-10724]. (Pack `py.requests-verify` warning 9497-9507.)
- Weak hash: rg `hashlib\.(md5|sha1)\(`, warning "Weak hash usage" [10726-10731]. (Pack `py.hashlib-weak` warning 9509-9518.)
- tempfile.mktemp: rg, critical "Insecure tempfile.mktemp usage" [11038-11040]. (Pack `py.tempfile-mktemp` error 9719-9726.)
- Hardcoded secrets: heredoc (10743-11037), critical "Potential hardcoded secrets" + TSV samples [11026-11027].
- Heredoc detectors, each `print_finding` title + severity (all AST walkers with inline ubs:ignore; all have good-lines):
  - run_unsafe_deserialization_checks 3587-3796 — critical "Unsafe Python deserialization loader"
  - run_command_injection_checks 3108-3428 — critical "User-controlled command reaches shell or executable selection"
  - run_subprocess_timeout_checks 3430-3585 — warning "Subprocess call has no bounded timeout"
  - run_sql_injection_checks 973-1386 — critical "Interpolated SQL reaches execution sink" + warning "Interpolated SQL with unproven-static values reaches execution sink" (GH #94 provenance downgrade; static-fstring clean case)
  - run_nosql_injection_checks 1388-1667 — critical "Request-controlled NoSQL filter reaches database sink"
  - run_regex_dos_checks 1669-1928 — critical "Request-controlled regex pattern reaches regex engine"
  - run_template_injection_checks 1930-2186 — critical "Request-controlled template source reaches renderer"
  - run_header_injection_checks 2188-2491 — critical "Request-controlled value reaches HTTP response header"
  - run_email_header_injection_checks 2493-2831 — critical "Request-controlled value reaches email header or envelope sink"
  - run_ldap_injection_checks 2833-3106 — critical "Request-controlled LDAP filter or DN reaches directory sink"
  - run_password_hashing_checks 3798-4044 — critical "Weak or plaintext password hashing configured"
  - run_crypto_misuse_checks 4046-4297 — critical "Weak cryptographic mode, cipher, or static IV/nonce"
  - run_constant_time_compare_checks 4299-4554 — critical "Secret, signature, or token compared with ==/!=" → ALREADY `ctcompare_py`
  - run_security_assert_checks 4556-4737 — critical "Security-sensitive assert stripped by -O" (tests/conftest suppression, #64)
  - run_file_permission_checks 4739-4945 — critical "World-writable file mode or permissive umask"
  - run_http_timeout_checks 4947-5195 — warning "Outbound HTTP call has no explicit timeout"
  - run_archive_extraction_checks 5197-5405 — critical "Archive extraction path traversal risk"
  - run_open_redirect_checks 5407-5609 — critical "Unvalidated redirect from request data"
  - run_host_header_poisoning_checks 5611-5917 — critical "Request Host header used to build absolute URL"
  - run_ssrf_checks 5919-6206 — critical "Request-derived URL reaches outbound HTTP client"
  - run_path_traversal_checks 6208-6466 — critical "Request-derived path reaches file read/download/write sink"
  - run_jwt_verification_checks 6468-6636 — critical "JWT decode disables signature or claim verification"
  - run_cors_misconfig_checks 6638-6898 — critical "CORS allows credentials with wildcard origins"
  - run_cookie_security_checks 6900-7099 — critical "Insecure web cookie/session configuration"
  - run_csrf_disable_checks 7101-7343 — critical "CSRF protection explicitly disabled"
  - run_template_autoescape_checks 7345-7582 — critical "Template autoescape explicitly disabled"
  - run_safe_html_xss_checks 7584-7851 — critical "Request-controlled value marked as safe HTML"
  - run_mass_assignment_checks 7853-8062 — critical "Request data mass-assigned into model/object"
  - run_debug_host_config_checks 8064-8257 — critical "Production debug mode or wildcard host allow-list"
  - run_xml_parser_security_checks 8259-8525 — critical "Unsafe XML parser on untrusted input"
  - run_insecure_random_security_checks 8527-8747 — critical "Security token generated with non-cryptographic random"
  - run_tls_verification_checks 8749-9035 — critical "HTTP/TLS client disables certificate verification"
  - run_taint_analysis_checks 785-971 — TSV rules via TAINT_* arrays: py.taint.xss/sql/command/eval, all critical, 3-sample cap, good "No tainted sources reach dangerous sinks" → ALREADY `taint_py`

**Cat 8 functions — (11062-11101)**
- Mutable default args: rg, critical >0, good fallback [11070-11077]. (Pack `py.mutable-defaults` error 9421-9437.)
- >6 params: rg, warning >3 [11079-11084].
- Nested function declarations: rg pipeline, info >10 [11086-11092].
- Missing returns heuristic: def vs return count ratio, info [11094-11100].

**Cat 9 parsing — (11103-11175)**
- json.loads without try: heredoc (11112-11167), warning "json.loads without error handling". (Pack `py.json.loads-no-try` warning 9834-9850, `py.json-load-no-try` warning 9931-9941 — the contract.json example id.)
- String concat + digits: rg pipeline, info >5 [11169-11174].

**Cat 10 control-flow — (11177-11206)**
- finally transfer: rg pipeline, warning "Control transfer in finally" [11185-11191].
- Nested ternary: rg, info >3 [11193-11198].
- Unreachable after return: rg pipeline, info >5 [11200-11206].

**Cat 11 debug — (11208-11241)**
- print statements: rg, warning >50 / info >20 / good "Minimal print usage" [11216-11224].
- breakpoint/pdb: rg, critical "Debugger calls present" [11226-11233].
- Sensitive logs: RNI, critical "Sensitive data in logs" [11235-11240]. (Pack `py.logging-secrets` warning 9784-9794.)

**Cat 12 perf — (11243-11274)**
- String concat in loops: rg pipeline, info >8 [11251-11256].
- re.compile in loops: rg pipeline, info [11258-11264].
- I/O in loops: rg pipeline, warning >5 [11266-11273].

**Cat 13 variables — (11276-11293)**
- global/nonlocal: rg, info >5 [11284-11288].
- Wildcard imports: rg, warning [11290-11292]. (Pack `py.wildcard-import` warning 9671-9678.)

**Cat 14 code-quality — (11295-11327)**
- TODO/FIXME/HACK/XXX/NOTE: 5× RNI (11303-11307); warning >20 "Significant technical debt" / info >10 / info >0 / good [11309-11318]. (Skipped in UBS_PROFILE=loose.)

**Cat 15 regex — (11329-11349)**
- Nested quantifiers: rg, warning >3 "Potential catastrophic regex" [11337-11342]. (Pack `py.re-catastrophic` warning 9757-9766.)
- Dynamic re.compile: rg, info >3 [11344-11348].

**Cat 16 io — (11351-11381)**
- open() without with: ratio rg (open vs with-open), warning diff "open() calls missing 'with'", good "File usage appears context-managed" [11359-11367]. (Pack `py.open-no-with` warning 9534-9549 — manifest issue-67.)
- open() missing encoding: rg pipeline, info [11369-11374]. (Pack `py.open-no-encoding` info 9551-9583, binary-mode exempt.)
- rmtree(ignore_errors=True): rg, info [11376-11380].

**Cat 17 typing — (11383-11404)**
- `Any` usage: rg, info >10 / >0 [11391-11397]. (Pack `py.any-typing` info 9746-9755.)
- type: ignore: rg, info >5 [11399-11403]. (Pack `py.type-ignore` info 9737-9744.)

**Cat 18 modules — (11406-11421)**
- os.system: rg, warning "os.system used (shell)" [11414-11416].
- Dynamic imports: rg, info [11418-11420]. (Pack `py.importlib-dynamic` info 9680-9689.)

**Cat 19 resource-lifecycle — (11424-11432)** → `run_resource_lifecycle_checks` (590-672): helper `modules/helpers/resource_lifecycle_py.py` (thin entry over ubs_core.analyzers.lifecycle_py) + per-kind rg acquire/release loop (637-646 — the WORST budget offender: 4 kinds × 1 list rg + 2-3 rg per candidate file). → FULLY replaced by `lifecycle_py` (python.lifecycle.{file_handle|socket_handle|popen_handle|asyncio_task}; critical/warning/warning/warning). Manifest expects substring "open() calls missing 'with'" (which is cat 16's text) + "resource_lifecycle.py" path.

**AST-GREP RULE PACK header (11434-11449, `CURRENT_CATEGORY=0`)**: `run_ast_rules` (10004-10150) — text mode: 51 × `scan -r --json=stream` + parser heredoc (10079-10148: severity map error/critical/fatal→critical, warn→warning, else info; `py.assert-used` suppressed in test/conftest files; per-rule current+prev-line ubs:ignore) → print_finding per rule bucket + samples. SARIF mode: 51 × `scan -r --format=sarif` + merge heredoc (10017) → AST_SARIF_BUFFER. Pack contents (51 rules, id → line, severity): py.none-eq 9352 warning, py.is-literal 9363 warning, py.except-broad 9377 warning, py.bare-except 9385 error, py.except-pass 9398 warning, py.raise-e 9411 warning, py.mutable-defaults 9422 error, py.eval-exec 9440 error, py.pickle-load 9451 error, py.yaml-unsafe 9462 error, py.subprocess-shell 9474 error, py.os-system 9489 warning, py.requests-verify 9498 warning, py.hashlib-weak 9510 warning, py.random-secrets 9521 info, py.open-no-with 9535 warning, py.open-no-encoding 9552 info, py.resource.open-no-close 9586 warning, py.resource.Popen-no-wait 9603 warning, py.resource.asyncio-task-no-await 9623 warning, py.assert-used 9641 info, py.datetime-naive 9650 info, py.type-equality 9661 warning, py.wildcard-import 9672 warning, py.importlib-dynamic 9681 info, py.async-blocking 9692 warning, py.await-in-loop 9709 info, py.tempfile-mktemp 9720 error, py.sql-fstring 9729 warning, py.type-ignore 9738 info, py.any-typing 9747 info, py.re-catastrophic 9758 warning, py.subprocess-no-check 9770 info, py.logging-secrets 9785 warning, py.path-join-plus 9797 info, py.floating-task 9806 warning, py.requests-timeout-missing 9820 info, py.json.loads-no-try 9835 warning, py.sql-string-format-percent 9854 warning, py.sql-fstring-params 9863 warning, py.contextlib-suppress-broad 9873 info, py.aiohttp-session-no-close 9883 warning, py.logging-exception-no-exc-info 9898 info, py.asyncio.get_event_loop-legacy 9911 info, py.imp-module 9920 warning, py.json-load-no-try 9932 warning, py.stub-function-pass 9944 info, py.stub-function-ellipsis 9955 info, py.env-get-empty-string 9966 info, py.sqlite-no-retry 9979 info, py.signal-handler-io 9993 info. Plus `py.async.task-no-await` (687, warning) living in run_async_error_checks' own temp dir. RECOMMENDATION (js playbook §3): python v2 needs NO ast-grep layer — every pack rule is expressible as a Pattern entry or is redundant with an analyzer; the pack's informational dump is what the text header "AST-GREP RULE PACK FINDINGS" prints; if byte-parity of that section is required initially, keep ONE consolidated `scan -c` (sgconfig) as a bridge, then drop it in wave 2.

**Cat 20 uv-tools — (11452-11567)**: `UV_TOOLS` CSV (default `ruff,bandit,pip-audit`; `--no-uv` disables; `--uv-tools=` selects; per-tool `--timeout-seconds`/UV_TIMEOUT budget via `run_uv_tool_text` 10166-10183 with TIMEOUT_CMD).
- ruff: `uvx ruff check --output-format=json` → raw output cat'd + python3 count heredoc (11475) → info "Ruff emitted findings" / info 1 "Ruff output needs review" / good "Ruff clean".
- bandit: `uvx bandit -q -r DIR -x <excludes>` RAW TEXT passthrough + info 0 "Bandit scan completed". NOTE (js parity): bandit's own `Location:` findings are NOT parsed into UBS counters by design — document the same exclusion for python v2: external-tool text is printed, never converted to sink records.
- pip-audit: raw passthrough + info 0 "pip-audit run (if available)".
- optional: mypy / detect-secrets / safety — raw passthrough via `run_system_or_uv_tool` (10185-10188).
→ v2: keep as legacy-parity BRIDGE subprocesses outside py_scan (or behind an env opt-out); they are the only category that cannot run in-process.

**Cat 21 deprecations — (11570-11582)**: imp import / asyncio.get_event_loop rg, warning "Deprecated API usage". (Pack `py.imp-module` warning 9919-9925, `py.asyncio.get_event_loop-legacy` info 9910-9917.)

**Cat 22 packaging — (11584-11601)**: requirements.txt unpinned lines (plain grep on the file), info; `-e`/`file://` refs rg, info.

**Cat 23 notebooks — (11603-11614)**: `"outputs": [{` rg, info >5 "Notebooks contain outputs".

**Cross-cutting seams that must survive both paths**: env-venv `env/` exclusion probe (424-441, `find -maxdepth 3` + pyvenv.cfg check — reproduce in ubs_list_files usage or py_scan's own skip logic), MAX_FILE_SIZE rg flag, `--rules DIR` user rule merge (9330-9333 — v2: forward to ast bridge or ignore like js), UBS_TEST_FORCE_NO_AST_GREP / UBS_AST_GREP_BIN (check_ast_grep 9220-9230), UBS_METRICS_DIR.

## 2. OUTPUT ASSEMBLY (meta-runner contract)

- Text labels (parsed by postprocess `summary_from_text`; verbatim, keep exactly): `Files scanned:` / `Critical issues:` / `Warning issues:` / `Info items:` (11647-11650) under a `Summary Statistics:` header (11645); plus `Report generated:`-style footer lines. Fallback parser `parse_text_to_json` (ubs 5657-5690) also accepts `Files:` and bare `CRITICAL/Warning/Info`. Exit formula (11869-11872): 1 if critical>0; 1 if --fail-on-warning and crit+warn>0.
- `--format=json`: `emit_summary_json` (11717-11712 area: printf-built ONE object) → keys `project, files, critical, warning, info, timestamp, format, uv_tools, categories{"1".."23"}, ast_grep_rules[{id,count}]` on MACHINE_FD (fd3, or fd4 tee to OUTPUT_FILE; fd1→fd2 for logs, 330-345). run_lang (ubs 5614-5619) requires a JSON object with numeric files/critical/warning/info or falls back to legacy text mode — py_scan's summary doc must satisfy that plus carry `findings[]` like js_scan does (that's what `python-json-findings-parity` asserts: "findings", title, "samples").
- `--report-json=FILE` (meta-runner passes `--report-json=$TMPDIR_RUN/python.findings.json`, ubs 5521-5524): legacy payload `{version, timestamp, files, critical, warning, info, findings:[{severity,count,title,description,samples:[{file,line,code}]}]}` assembled from the TSV scratch (11811-11844). v2 (js parity): `cp "$sink" "$REPORT_JSON"` — K2 NDJSON records flow to findings-merge TODAY. merge_json_scanners EXCLUDES `*.findings.json` from the summary merge (ubs 5720-5726) and `ubs_core findings-merge` folds the NDJSON into combined `findings[]` (ubs 5829-5840) — sink-shape-keyed, no meta-runner change needed.
- SARIF (`--format=sarif`): `emit_merged_sarif` (11737-11808) = buffered ast-grep run + `ubs-python-heuristics` run; heuristic rule ids `python.heuristic.<slug(title)>`, one result per recorded sample (physical location required) + `properties.occurrences`/`recorded_samples`; LEVELS critical→error/warning→warning/info→note. v2: sarif stays on the legacy path initially (js gate excludes sarif: `"$FORMAT" != "sarif"`), later via meta-runner merge.
- `--summary-json FILE`: emit_summary_json to file. `--baseline FILE`: python3 delta heredoc (11636-11655).

## 3. PROCESS BUDGET (legacy spawn census by class)

| class | count |
|---|---|
| rg pipelines (GREP_RN/RNI/RNW + count_lines grep+awk + grep -A/-v filters) | ~57 static sites + ~20 show_detailed_finding re-runs + resource-lifecycle per-file loop (4×N×2-3) ≈ **100-150** |
| python3 heredocs | 37 detectors + ~10 infra (async parse 727, guards 9255+10332, division 10446, pack parse 10079, sarif merge 10017, ruff count 11475, baseline 11636, histogram 11702, report-json 11812, emit_merged_sarif 11738) ≈ **47** |
| ast-grep | 4 ad-hoc `run -p` + 51 `scan -r` (text) + 51 (sarif) + 51 (summary-json histogram) + 1 async ≈ **56 / 158 / 209** by format |
| uv/external tools | 3 default (ruff, bandit, pip-audit; each uvx may double-spawn) |
| inventory | rg --files + wc + awk =3; env-venv find =1; meta-runner detect rg =1 |
| TOTAL | **~250-400** per scan (target ≤ 25) |

v2: 1× ubs_list_files list (in-bash) + 1× `python3 -m ubs_core.py_scan` + ≤3 uv bridges + postprocess (shared) ≈ **5-8**. Verified js precedent: js_scan = ONE process for patterns+analyzers+ast consumption.

## 4. FLAGS & CONTRACT

- Arg parser (223-277): `-v/--verbose, -q/--quiet, --format=, --ci, --no-color, --force-color, --timeout-seconds=, --baseline=, --list-categories, --max-file-size=, --include-ext=, --exclude=, --jobs=, --skip=, --fail-on-warning, --rules=, --no-uv, --uv-tools=, --summary-json=, --report-json=, --max-samples=, --max-detailed=, -h`; positionals PROJECT_DIR/OUTPUT_FILE with the dot-heuristic (279-290). Env: JOBS, NO_COLOR, CI, UV_TIMEOUT, TIMEOUT_SECONDS, MAX_FILE_SIZE, UBS_CATEGORY_FILTER, UBS_PROFILE.
- contract.json python entry (modules/contract.json 237-262): file ubs-python.sh, extensions py/pyi/pyx/pxd/pxi/ipynb, manifest_files pyproject.toml/setup.py/setup.cfg/requirements*/Pipfile/poetry.lock/uv.lock/.env*, `contract: 1` → **2** at flip, extra_flags [--baseline --force-color --list-categories --max-detailed --max-file-size --max-samples --no-uv --report-json --rules --summary-json --timeout-seconds --uv-tools] (re-check via scripts/check_docs_claims.py after port).
- Meta-runner: project detection `rg -q … '*.py' pyproject.toml requirements.txt setup.py` (ubs 3537-3541); run_lang forwards --ci/--fail-on-warning/-v/-q/--jobs/--include-ext/--rules/--exclude/--skip (combined global+per-lang, issue #52) + `--report-json` for lang==python (5521-5522); `category_slug_for python` 4658-4682 (23 slugs above; reverse lookup `category_from_slug` walks cats ≤35, 4895-4900); findings-merge consumes `python.findings.json` (5833-5839); JSONL/beads path prefers top-level findings[] (5948-5952).

## 5. MANIFEST — all 82 python cases (test-suite/manifest.json)

Schema: args `["--only=python", (--fail-on-warning), (--skip=1,2,3,4,5,6,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23)]` — the 30-char skip list (skips everything except cat 7) is used by every security case; expectations are exit_code + totals{critical/warning{min,max}} + require/forbid_substrings.

1. python-buggy — test-suite/python/buggy — nonzero, crit≥1 warn≥1, require "ASYNC/AWAIT PITFALLS"
2. python-clean — test-suite/python/clean — zero, crit≤0 warn≤6
3. python-taint-buggy — buggy/taint_analysis.py — nonzero crit≥1, require "Lightweight taint analysis"
4. python-taint-clean — clean/taint_analysis.py — zero, crit≤0 warn≤2
5-34. security pairs (buggy: nonzero crit≥1 + require title; clean: zero + forbid title), all `--skip=1,2,3,4,5,6,8,…,23`:
   python-command-injection-{buggy,clean} ("User-controlled command reaches shell or executable selection"), python-subprocess-timeout-* (warn≥1 / "Subprocess call has no bounded timeout"), python-sql-injection-* ("Interpolated SQL reaches execution sink"), python-nosql-injection-* ("Request-controlled NoSQL filter reaches database sink"), python-redos-regex-* ("Request-controlled regex pattern reaches regex engine"), python-template-injection-* ("Request-controlled template source reaches renderer"), python-header-injection-* ("Request-controlled value reaches HTTP response header"), python-email-header-injection-* ("Request-controlled value reaches email header or envelope sink"), python-ldap-injection-* ("Request-controlled LDAP filter or DN reaches directory sink"), python-archive-extraction-* ("Archive extraction path traversal risk"), python-open-redirect-* ("Unvalidated redirect from request data"), python-host-header-poisoning-* ("Request Host header used to build absolute URL"), python-ssrf-* ("Request-derived URL reaches outbound HTTP client"), python-http-timeout-* (warn≥1 / "Outbound HTTP call has no explicit timeout"), python-path-traversal-* ("Request-derived path reaches file read/download/write sink"), python-jwt-verification-* ("JWT decode disables signature or claim verification"), python-cors-misconfig-* ("CORS allows credentials with wildcard origins"), python-cookie-security-* ("Insecure web cookie/session configuration"), python-csrf-disable-* ("CSRF protection explicitly disabled"), python-template-autoescape-* ("Template autoescape explicitly disabled"), python-safe-html-xss-* ("Request-controlled value marked as safe HTML"), python-mass-assignment-* ("Request data mass-assigned into model/object"), python-unsafe-deserialization-* ("Unsafe Python deserialization loader"), python-password-hashing-* ("Weak or plaintext password hashing configured"), python-crypto-misuse-* ("Weak cryptographic mode, cipher, or static IV/nonce"), python-constant-time-compare-* ("Secret, signature, or token compared with ==/!="), python-assert-security-* ("Security-sensitive assert stripped by -O"), python-file-permissions-* ("World-writable file mode or permissive umask"), python-debug-host-config-* ("Production debug mode or wildcard host allow-list"), python-xml-parser-* ("Unsafe XML parser on untrusted input"), python-hardcoded-secrets-* ("Potential hardcoded secrets"), python-random-security-* ("Security token generated with non-cryptographic random"), python-tls-verification-* ("HTTP/TLS client disables certificate verification")
67-68. python-assert-security-tests-dir-{buggy,clean} — security/assert_tests_dir_{buggy,clean} dirs — issue-64: asserts keep firing in production dirs; tests/conftest asserts suppressed
69. python-json-findings-parity — constant_time_compare_buggy.py, `--format=json` — require "\"findings\"", title, "\"samples\""
70-71. python-async-errors-{buggy,clean} — async_errors/{buggy,clean} — buggy: nonzero warn≥1; clean: zero, warn≤4 (no skip list)
72. python-resource-lifecycle — buggy/resource_lifecycle.py — nonzero warn≥1, require "resource_lifecycle.py" + "open() calls missing 'with'" (no skip list)
73-74. python-is-literal-{buggy,clean} — quality/is_literal_*.py — issue-66, `--skip=1,2,3,5,6,7,…` (keeps 4) — warning≥1 / zero, "Using 'is' with literals"
75-76. python-open-with-encoding-{buggy,clean} — quality/open_with_encoding_*.py — issue-67, skip keeps only 16 — require/forbid "py.open-no-with" + "py.open-no-encoding" (NOTE: clean case forbids the AST PACK rule ids — v2 must keep those two rules' ids or remap)
77-78. python-parser-token-compare-{buggy,clean} — security/parser_token_compare_*.py — GH #85: buggy crit≥4; clean zero (two-tier vocabulary in ctcompare_py)
79. python-sql-static-fstring-clean — clean/sql_static_fstring.py — GH #94: zero, forbid both SQL titles (provenance: module-constant f-string is static)
80. python-sql-unknown-provenance-warning — buggy/sql_unknown_provenance.py — GH #94: crit≤0 warn≥1, require "Interpolated SQL with unproven-static values…", forbid the critical title
81. python-suppression-intervals-markers — suppression/suppression_buggy.py — A7 #91: zero exit, forbid "suppression_buggy.py:" (no skip list; whole-module suppression)
82. python-suppression-intervals-nomarkers — suppression_buggy_nomarkers.py — control: nonzero, crit≥1, require "suppression_buggy_nomarkers.py:"

(Adjacent multi-language SARIF case ~8850-8920 also requires py rule id `py.assert-used` in merged SARIF results — keep the id if the ast bridge survives.)

## 6. EXISTING ubs_core PY ANALYZERS (already auto-registered)

| analyzer | layer | rule id(s) | severity | replaces |
|---|---|---|---|---|
| lifecycle_py.py | lifecycle | `python.lifecycle.{file_handle,socket_handle,popen_handle,asyncio_task}` | critical, warning, warning, warning | run_resource_lifecycle_checks (cat 19) + helpers/resource_lifecycle_py.py; AST-based (TARGET_SIGS open/socket/Popen/create_task, RELEASE_METHODS close/shutdown/wait/communicate/terminate/kill/cancel, with-statement safe marking, asyncio.gather/wait release) |
| taint_py.py | taint | `python.taint.{xss,sql,command,eval}` | all critical | run_taint_analysis_checks heredoc verbatim (SOURCE_PATTERNS/SANITIZER_REGEXES/SINKS identical; scan_file_findings drops the 3-sample cap on the structured path) |
| guards_py.py | guards | `python.guards.deep_attr_chain` | info (GH #90) | analyze_py_attr_guards ast-grep+heredoc (cat 1 attribute chains): pure-ast depth-4 chain detection with if-body guard regions |
| ctcompare_py.py | ctcompare | `python.ctcompare.secret_eq` | critical | run_constant_time_compare_checks heredoc (two-tier vocabulary, GH #85) |
| narrowing_py.py | narrowing | `python.narrowing.partial_none_guard` | warning | NOTHING in legacy python (bead D4 new detector: log-only `is None` guard + later dereference). PARITY DECISION: including it adds findings legacy never printed — gate it (profile disabled_rules or py_scan flag) until parity sweep, like the js analyzers were handled |

Registry notes: `analyzers_for_lang("python")` returns all five; RunContext(lang="python", files=...) is all run(ctx) needs; `--files-from` NUL list matches js. Legacy module ids use the `py.` prefix (metadata + ast pack) while ubs_core emits `python.` — the sink's `rule` field is what K2/SARIF surface; keep ubs_core's `python.*` ids and map legacy pack ids only if the ast bridge is kept.

## 7. DUAL-PATH SEAMS (mirror ubs-js.sh exactly)

1. **Module gate** — insert at ubs-python.sh immediately after the ast/env setup block and before `# CATEGORY 1` (i.e. just before line 10307; js analog: 3956-3964):
   `if [[ "${UBS_CONTRACT_V2_PY:-0}" == "1" && "${UBS_LEGACY_MODULE_PY:-0}" != "1" && "$FORMAT" != "sarif" ]]; then if command -v python3 >/dev/null 2>&1; then v2_status=0; run_contract_v2_py || v2_status=$?; exit "$v2_status"; fi; fi` — env-error fall-through: without python3 the legacy path's exact "python3 not available" info findings/behavior must survive (python's analog of js's `check_ast_grep` gate; NO ast-grep requirement — that is the point of this port).
2. **run_contract_v2_py** (js analog 3898-3963): mktemp list+sink; `ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"}` (single-file target → the file IS the list); scan_args `--files-from --sink --project-dir [--skip "$SKIP_CATEGORIES"] [--fail-on-warning]`; FORMAT json → `--json-out /dev/fd/3 --project "$SOURCE_PROJECT_DIR"`; text → mktemp text_out + `--text-out`; then `PYTHONPATH="$helpers_dir" python3 -m ubs_core.py_scan "${scan_args[@]}" --version "$UBS_PY_VERSION"`; bridge hooks for cat 20 (uv tools) + optional consolidated ast pack; `[[ -n "$REPORT_JSON" ]] && cp "$sink" "$REPORT_JSON"` (K2); cleanup; return exit_code.
3. **Meta-runner**: NO changes required — run_lang already passes --report-json for python (5521), postprocess/legacy_postprocess seam (5399-5447) is language-agnostic, findings-merge (5829-5840) is sink-shape-keyed, summary merge already excludes *.findings.json. py_scan's `--json-out` document must satisfy the run_lang jq object check (files/critical/warning/info numeric) and carry findings[] for python-json-findings-parity.
4. **contract.json**: python `contract: 1 → 2` at flip (modules/contract.json:260); check_docs_claims + gen_module_readme re-run.
5. **Escape hatch**: after parity, flip default = v2 unless `UBS_LEGACY_MODULE_PY=1` (one release), mirroring the js postprocess-vs-legacy_postprocess pattern.
6. **Test seams to preserve on both paths**: UBS_CATEGORY_FILTER (→ py_scan `--skip` mapping 16,19), UBS_PROFILE=loose (skip 11,14), UBS_TEST_FORCE_NO_AST_GREP (no-op once ast layer drops, keep accepted), UBS_AST_GREP_BIN, UBS_METRICS_DIR, --rules DIR, `ubs:ignore` semantics (flat same-line in pattern layer + A7 statement intervals in postprocess).

## Port order (category waves, manifest totals diffed after each)

Skeleton (py_scan.py + gate + sink + text renderer with section headers/subheaders/good lines + fd-3 summary) → cat 7 security rg-pipeline subset (smallest parity risk) → cat 7 heredocs batch 1 (injection family: command/sql/nosql/redos/template/header/email/ldap — most are copy-adapt taint_py-style analyzers or Pattern entries) → cat 7 heredocs batch 2 (crypto/auth/tls family) + taint/ctcompare wiring (analyzers exist) → cats 1-6,8-10 (rg ladders → Pattern table; guards_py + async rule) → cats 11-18 → cat 19 (lifecycle_py wiring; delete the rg loop) → cats 20-23 (bridge/uv + trivial patterns) → ast pack decision (bridge vs drop) → flip + escape hatch.

## Verification gates per step

- `jq '.cases[] | select(.language=="python") | .id' test-suite/manifest.json` = the 82 cases above; sweep under UBS_CONTRACT_V2_PY=1 vs legacy totals per case (exit code + totals + substring assertions).
- Bandit/ruff/pip-audit passthrough: external-tool output is printed verbatim and NOT converted to v2 records (js precedent: bandit Location: lines excluded by design) — document in the module header and here when cat 20 bridges.
- `shellcheck -S warning modules/ubs-python.sh`; `./scripts/update_checksums.sh && ./scripts/update_sha256sums.sh` after every module edit.
- contract.json: contract stays 1 until flip; extra_flags re-check via scripts/check_docs_claims.py.
- UBS_PROFILE=1 process count ≤ 25 on test-suite/python; K2 sink emitted (`python.findings.json` NDJSON with rule/category_id/path/line/col/severity/message/suppressed).
- Rules: python 3.9+ stdlib only in ubs_core; no file deletion; never break the legacy default pre-parity; bead owner/integrator = GLM-Flash (hub 'Main') if blocked; track state in notes/py-port-map-a4.md.
