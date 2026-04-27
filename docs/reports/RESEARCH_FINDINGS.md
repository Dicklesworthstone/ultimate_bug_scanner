# RESEARCH FINDINGS: UBS (Ultimate Bug Scanner) - TOON Integration Analysis

**Researcher**: CrimsonForge (claude-code, claude-opus-4-5)
**Date**: 2026-01-23
**Bead**: bd-1bd
**Tier**: 1 (High Impact - Large JSON reports make this a prime TOON candidate)

---

## 1. Project Audit

### Architecture
UBS is a **bash-based meta-runner** (`ubs` script, ~2,657 lines) that dispatches to per-language scanner modules. It is NOT a Rust project despite what the bead template assumed.

### Key Files
| File | Purpose |
|------|---------|
| `ubs` | Main bash meta-runner script |
| `modules/ubs-*.sh` | Per-language scanner modules (js, python, rust, go, cpp, java, ruby, swift) |
| `modules/helpers/` | AST analysis helpers (Python, Go, JS) |
| `test-suite/manifest.json` | Test case definitions |
| `test-suite/run_manifest.py` | Test runner |

### Existing Output Formats
UBS already supports **5 output formats** via `--format=`:
1. **text** (default) - ANSI-colored terminal output
2. **json** - Combined summary with findings array
3. **jsonl** - Line-delimited JSON (streaming/Beads integration)
4. **sarif** - GitHub code scanning standard
5. **html** - Shareable standalone reports (via `--html-report`)

### Serialization Patterns
- **No compiled serialization library** - bash uses `printf`/`jq` for JSON generation
- **`jq`** handles complex transforms (merging, aggregation)
- **Direct string building** in module scripts via `printf`/`echo`
- **Python** for supplementary report generation (HTML, shareable reports)

### JSON Output Structure
```json
{
  "project": "/path/to/scanned/dir",
  "timestamp": "2026-01-23 17:50:39",
  "scanners": [
    {
      "project": "...",
      "files": 20,
      "critical": 40,
      "warning": 210,
      "info": 1008,
      "version": "4.7",
      "language": "js",
      "extras": { "deep_guard": { "unguarded": 5, "samples": [...] } },
      "findings": [
        { "severity": "critical", "count": 9, "title": "...", "description": "..." }
      ]
    }
  ],
  "totals": { "critical": 40, "warning": 210, "info": 1008, "files": 20 },
  "git": { "repository": "...", "commit": "...", "blob_base": "..." }
}
```

---

## 2. Output Analysis

### Sample Output Sizes (test-suite/buggy, 20 JS files)

| Metric | JSON | TOON | Savings |
|--------|------|------|---------|
| **Bytes** | 15,042 | 7,582 | **49.6%** |
| **Estimated Tokens** | ~2,431 | ~1,600 | **34.2%** |

### Tabular Data Candidates (HIGH opportunity)

1. **`findings` array** (65 items with uniform keys: severity, count, title, description)
   - JSON: Repeated keys + braces for every entry
   - TOON: `findings[65]{severity,count,title,description}:` + CSV-like rows
   - **Savings: ~55-60% for this section alone**

2. **`extras.deep_guard.samples`** (uniform: file, line, code)
   - TOON: `samples[3]{file,line,code}:` + compact rows

3. **`scanners` array** (when multi-language, uniform keys)
   - TOON: `scanners[N]{project,files,critical,warning,info,timestamp,format,language}:`

### Key Folding Opportunities

- `git.repository`, `git.commit`, `git.blob_base` → dotted paths
- `extras.deep_guard.unguarded`, `extras.deep_guard.guarded`
- `totals.critical`, `totals.warning`, etc.

### TOON Output Sample (actual conversion)
```
project: /data/projects/ultimate_bug_scanner/test-suite/buggy
timestamp: "2026-01-23 17:52:01"
scanners[1]:
  - project: /data/projects/ultimate_bug_scanner/test-suite/buggy
    timestamp: "2026-01-23T22:52:01Z"
    files: 20
    critical: 40
    warning: 210
    info: 1008
    version: "4.7"
    language: js
    extras:
      deep_guard:
        unguarded: 5
        guarded: 0
        samples[3]{file,line,code}:
          .../01-null-safety.js,16,return user.profile.address.city;
          .../01-null-safety.js,26,const result = data.results.items.filter(...)
          .../17-dom-manipulation.js,130,return element.parentElement...
    findings[65]{severity,count,title,description}:
      warning,25,DOM queries not immediately null-checked,"Consider: ..."
      critical,3,Direct NaN comparison (always false!),Use Number.isNaN(x)
      critical,9,Loose equality causes type coercion bugs,Always prefer strict equality
      ...
totals:
  critical: 40
  warning: 210
  info: 1008
  files: 20
```

---

## 3. Integration Assessment

### Complexity Rating: **Simple-to-Medium**

The format switch is already extensible. Adding TOON requires:
1. A new case in the format dispatch (bash: ~20 lines)
2. Piping existing JSON output through the toon_rust encoder binary (`tru`)
3. Optionally: native TOON emission in bash (harder but avoids a subprocess dependency)

### Recommended Approach: **Pattern A - Pipe through `tru`**

Since UBS already generates JSON output internally (even for text format, it builds JSON summaries), the simplest approach is:

```bash
case "$FORMAT" in
  toon)
    # Generate JSON internally, pipe through tru
    local json_output
    json_output=$(generate_json_report)
    echo "$json_output" | tru --encode
    ;;
esac
```

This avoids rewriting any serialization logic and leverages the existing `--report-json` infrastructure.

### Alternative Approach: **Pattern B - Native bash TOON emission**

For maximum performance (avoid tru process spawn), emit TOON directly:
```bash
emit_toon_findings() {
  local count="${#FINDINGS[@]}"
  printf "findings[%d]{severity,count,title,description}:\n" "$count"
  for f in "${FINDINGS[@]}"; do
    # emit CSV-like rows
    printf "  %s,%d,%s,%s\n" "$sev" "$cnt" "$title" "$desc"
  done
}
```

This is more work but eliminates the tru dependency.

### Key Integration Points

| File/Location | Change Required |
|---------------|-----------------|
| `ubs` line ~145 | Add "toon" to valid FORMAT values |
| `ubs` line ~369-425 | CLI arg parsing (already handles `--format=*`) |
| `ubs` line ~2407-2452 | Output emission switch - add toon case |
| `install.sh` | Optionally bundle `tru` binary |
| `modules/ubs-*.sh` | No changes needed (they emit JSON internally) |

### Dependencies
- **tru binary** must be available in PATH (or bundled)
- No Cargo.toml changes needed (UBS is bash, not Rust)
- No serde patterns to modify

### Backwards Compatibility
- Zero risk: new `--format=toon` flag, does not affect existing formats
- Existing `--format=json` output unchanged
- No breaking changes to any API

---

## 4. Token Savings Projections

| Scan Scenario | JSON Tokens | TOON Tokens | Savings |
|---------------|-------------|-------------|---------|
| Small scan (1 language, 13 files) | ~100 | ~65 | ~35% |
| Medium scan (1 language, 20 files, 65 findings) | ~2,431 | ~1,600 | ~34% |
| Large scan (5 languages, 100+ files) | ~8,000+ | ~4,500+ | ~44% |
| Multi-language with extras | ~12,000+ | ~6,000+ | ~50% |

The **findings array** is the primary savings driver. With 65+ uniform findings objects, TOON tabular format eliminates all repeated key names and braces.

---

## 5. Special Considerations

### Language-Specific Notes
- UBS is **bash** (not Rust as the bead template assumed)
- Integration via `tru` binary subprocess is the natural approach
- No Cargo.toml, no serde, no Rust dependencies

### Implementation Order
1. Add `--format=toon` CLI flag recognition
2. Pipe existing JSON through `tru --encode`
3. Add `--stats` flag (already in tru: `tru --stats`)
4. Add env var `UBS_OUTPUT_FORMAT=toon`
5. Test with manifest.json test cases
6. Document in ubs help output

### Risk Assessment
- **Low risk**: New format, no existing behavior changes
- **Dependency risk**: Requires `tru` binary in PATH
- **Mitigation**: Fallback to JSON if `tru` not found, with warning

---

## 6. Deliverables Checklist

- [x] RESEARCH_FINDINGS.md created (this file)
- [ ] Project-level beads created in .beads/ (see below)
- [ ] bd-269 (Integrate TOON into ubs) updated with actual findings

---

## 7. Recommended Project-Level Beads

The following beads should be created in `/data/projects/ultimate_bug_scanner/.beads/`:

1. **ubs-toon-flag**: Add `--format=toon` CLI flag to meta-runner
2. **ubs-toon-pipe**: Implement JSON-to-TOON piping via `tru` binary
3. **ubs-toon-env**: Add `UBS_OUTPUT_FORMAT` env var support
4. **ubs-toon-stats**: Add `--stats` flag for token comparison display
5. **ubs-toon-fallback**: Graceful fallback if `tru` not in PATH
6. **ubs-toon-test**: Add TOON format test cases to manifest.json
7. **ubs-toon-docs**: Update `ubs --help` and README with TOON documentation
8. **ubs-toon-jsonl**: Consider TOON for JSONL format variant

---

## 8. Integration Brief (bd-247) — UBS TOON Research Summary

### Output Surfaces (commands, flags, output shapes)
- **CLI entrypoint**: `ubs` meta-runner script
  - Default format: `FORMAT="text"` and `--format=FMT` flag (`text|json|jsonl|sarif`).
  - Help text exposes formats in `usage()`.
- **Machine outputs**:
  - `--format=json`: combined summary JSON (scanners + totals + optional findings)
  - `--format=jsonl`: line-delimited findings + scanner summaries + totals
  - `--format=sarif`: merged SARIF runs across modules
  - `--format=text`: colorful per-language output + combined summary

**Key locations:**
- Default format and help: `ubs` `# CLI` block (`/data/projects/ultimate_bug_scanner/ubs:145,208`) 
- Arg parsing: `--format=*) FORMAT="${1#*=}"` (`/data/projects/ultimate_bug_scanner/ubs:369-370`)
- Unified output switch: `case "$FORMAT" in ...` (`/data/projects/ultimate_bug_scanner/ubs:2426-2504`)
- JSON merge: `merge_json_scanners()` + `generate_combined_json()` (`/data/projects/ultimate_bug_scanner/ubs:2087-2155`)
- JSONL: `write_jsonl_summary()` (`/data/projects/ultimate_bug_scanner/ubs:2206-2234`)
- SARIF merge: `merge_sarif_runs()` (`/data/projects/ultimate_bug_scanner/ubs:2160-2204`)

### Serialization Entry Points (files + functions)
- **Meta-runner JSON aggregation**: `merge_json_scanners()` → `generate_combined_json()`
- **JSONL emission**: `write_jsonl_summary()` (uses jq to expand findings into JSONL lines)
- **Module JSON summaries**: per-language modules emit JSON summaries when `--format=json`.
  - Example: Python module `emit_summary_json` + format branch (`/data/projects/ultimate_bug_scanner/modules/ubs-python.sh:2958-2961`).

### Format Flags & Env Precedence (current + proposed)
- **Current**: CLI only (`--format=text|json|jsonl|sarif`). No env override exists.
- **Proposed per bd-r9m**:
  - `UBS_OUTPUT_FORMAT` (tool-specific)
  - `TOON_DEFAULT_FORMAT` (global)
  - Precedence: CLI > `UBS_OUTPUT_FORMAT` > `TOON_DEFAULT_FORMAT` > default

### TOON Strategy (json vs toon vs toonl)
- **Recommended**: Add `--format=toon` to meta-runner and pipe combined JSON through `tru`.
  - Implement as new `case "toon")` branch in unified output switch (`/data/projects/ultimate_bug_scanner/ubs:2426+`).
  - Use `generate_combined_json` → `cat "$COMBINED_JSON_FILE" | tru --encode`.
- **JSONL**: keep `jsonl` unchanged (streaming records). If needed, add a separate `toonl` later.
- **SARIF**: **must remain unchanged** (protocol-bound output).

### Protocol Constraints
- No external protocol locks; CLI only. JSONL is used by Beads integration and must remain stable.
- SARIF output must remain spec-compliant and byte-identical to current behavior.

### Docs to Update
- `ubs --help` usage block (add `toon` in formats list)
- `README.md` output formats section
- `AGENTS.md` TOON quick-reference section (from `/data/projects/toon_robot_help_template.txt`)

### Fixtures to Capture
Commands (run in ubs repo):
- Small JSON: `./ubs --format=json test-suite/buggy > test-suite/fixtures/ubs_buggy.json`
- JSONL: `./ubs --format=jsonl test-suite/buggy > test-suite/fixtures/ubs_buggy.jsonl`
- SARIF: `./ubs --format=sarif test-suite/buggy > test-suite/fixtures/ubs_buggy.sarif`
- TOON: `./ubs --format=toon test-suite/buggy > test-suite/fixtures/ubs_buggy.toon`

### Test Plan (unit + e2e)
- **Unit**: format precedence (CLI/env), TOON round-trip, JSONL unchanged, SARIF unchanged.
- **E2E**: run json vs toon and compare `tru --decode` output; capture stdout/stderr + exit codes.

### Risks & Edge Cases
- `tru` binary missing → warn + fallback to JSON
- Large outputs: ensure `tru` piping handles big JSON without truncation
- JSONL behavior must remain stable unless `toonl` introduced
