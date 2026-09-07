#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE GO BUG SCANNER v7.1 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Go (Go 1.23+) on contract v2.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-golang.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="429b8972c082f4767985a1b5ebe6a0d6c14dbb4747600a9af70c08bc0b63efbb"
UBS_MODULE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
  if [[ -f "${UBS_VERIFIED_ASSET_DIR}/lib/ubs-common.sh" ]]; then
    UBS_MODULE_LIB_DIR="$UBS_VERIFIED_ASSET_DIR"
  elif [[ -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
    if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
      echo "warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified lib at ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" >&2
    else
      echo "✗ ${BASH_SOURCE[0]}: lib/ubs-common.sh found at unverified location; refusing to load unverified library (set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" >&2
      exit 2
    fi
  fi
fi
if [[ -z "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
  if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
    : # override allows unverified
  elif [[ -n "${UBS_LIB_CHECKSUM:-}" && -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
    _lib_sha=""
    if command -v sha256sum >/dev/null 2>&1; then
      _lib_sha="$(sha256sum "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      _lib_sha="$(shasum -a 256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
      _lib_sha="$(openssl dgst -sha256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $NF}')"
    fi
    if [[ -n "$_lib_sha" && "$_lib_sha" != "$UBS_LIB_CHECKSUM" ]]; then
      echo "✗ ${BASH_SOURCE[0]}: lib/ubs-common.sh failed checksum verification (expected $UBS_LIB_CHECKSUM, got $_lib_sha); refusing to load unverified library (run 'ubs doctor --fix' or reinstall)" >&2
      exit 2
    fi
  fi
fi
if [[ ! -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
  echo "✗ ${BASH_SOURCE[0]}: missing ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh (run 'ubs doctor --fix' or reinstall)" >&2
  exit 2
fi
# shellcheck source=lib/ubs-common.sh
source "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh"
shopt -s lastpipe
shopt -s extglob

# Pre-init colors as empty so ERR trap is safe before CLI parsing
RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; GRAY=""
BOLD=""; DIM=""; RESET=""

VERSION="7.1.4"

# Color-safe error trap (works before colors are initialized)
on_err() {
  local ec=$? cmd=${BASH_COMMAND} line=${BASH_LINENO[0]} src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  local _RED=${RED:-} _BOLD=${BOLD:-} _RESET=${RESET:-} _DIM=${DIM:-} _WHITE=${WHITE:-}
  printf "\n%s%sUnexpected error (exit %s)%s %sat %s:%s%s\n%sLast command:%s %s%s%s\n" \
    "${_RED}" "${_BOLD}" "$ec" "${_RESET}" "${_DIM}" "$src" "$line" "${_RESET}" \
    "${_DIM}" "${_RESET}" "${_WHITE}" "$cmd" "${_RESET}" >&2
  exit "$ec"
}
trap on_err ERR

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
SARIF_RICH=1           # Enrich SARIF (helpUri + tags) when python3 is available; disable with --sarif-plain
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="go,tmpl,gotmpl,tpl"
INCLUDE_NAMES="go.mod,go.sum,go.work,go.work.sum"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DUMP_RULES_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1
LIST_RULES=0
RUN_GO_TOOLS=0
GOTEST_PKGS="./..."
CATEGORY_WHITELIST=""
ONLY_CHANGED=0
STRICT_MODE=0
BASELINE_FILE=""
NO_BANNER=0
REPORT_JSON=""         # --report-json=FILE: NDJSON findings sink copy (contract v2 K2)
ALLOW_NPX=0
FILES_FROM=""

case "${UBS_CATEGORY_FILTER:-}" in
  resource-lifecycle)
    CATEGORY_WHITELIST="5,17"
    ;;
esac

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --sarif-plain            Do not post-process SARIF (disable helpUri/tags enrichment)
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: ${INCLUDE_EXT}) e.g. go,tmpl
  --include-names=CSV      Exact file names (default: ${INCLUDE_NAMES}) e.g. go.mod,go.sum
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --list-rules             List built-in AST rule ids, then exit
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --dump-rules=DIR         Persist generated ast-grep rules to DIR for test validation
  --go-tools               Also run gofmt -s -l, go vet, and govulncheck (if available)
  --test-pkgs=PKGS         Package pattern for tests/vet (default: ./...)
  --only-changed           Scan only files changed vs git merge-base (if in git repo)
  --strict                 Treat more findings as warnings/errors (aggressive)
  --baseline=FILE          Compare against a previous text report (heuristic deltas)
  --no-banner              Disable ASCII banner
  --report-json=FILE       Also write the NDJSON findings sink to FILE (contract v2)
  --allow-npx              Allow npx fallback for ast-grep
  -h, --help               Show help

Env:
  JOBS, NO_COLOR, CI, UBS_CATEGORY_FILTER
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
contract: v2
USAGE
}

list_categories() {
  cat <<'CATS'
1  Concurrency & Goroutine Safety
2  Channels & Select
3  Context Propagation & Cancellation
4  HTTP Client/Server Safety
5  Resource Lifecycle & Defer
6  Error Handling & Wrapping
7  JSON & Encoding
8  Filesystem & I/O
9  Cryptography & Security
10 Reflection & Unsafe
11 Import Hygiene
12 Module & Build Hygiene
13 Testing Practices
14 Logging & Printf
15 Style & Modernization
16 Panic/Recover & Time Patterns (AST Pack)
17 Resource Lifecycle Correlation
18 Go Tooling (Optional)
19 Dependency & Build Drift
20 Nil Panics From Defer Ordering (AST)
21 Database & SQL Robustness
22 Shutdown & Resource Release (HTTP/Net)
CATS
}

# Parse CLI
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --list-categories) list_categories; exit 0;;
    --sarif-plain) SARIF_RICH=0; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --include-names=*) INCLUDE_NAMES="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --go-tools)   RUN_GO_TOOLS=1; shift;;
    --test-pkgs=*) GOTEST_PKGS="${1#*=}"; shift;;
    --only-changed) ONLY_CHANGED=1; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --no-banner)  NO_BANNER=1; shift;;
    --strict)     STRICT_MODE=1; shift;;
    --baseline=*) BASELINE_FILE="${1#*=}"; shift;;
    --allow-npx)  ALLOW_NPX=1; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ "$PROJECT_DIR" == "." && ! "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" && ! "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, use the meta-runner 'ubs'. To save a report, pass a fresh (non-existing) path." >&2
          exit 2
        fi
        OUTPUT_FILE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      ;;
  esac
done

: "$VERBOSE" "$DETAIL_LIMIT" "$MAX_DETAILED" "$JOBS" "$DISABLE_PIPEFAIL_DURING_SCAN"
: "$SARIF_RICH" "$INCLUDE_NAMES" "$RUN_GO_TOOLS" "$GOTEST_PKGS" "$ONLY_CHANGED" "$STRICT_MODE" "$BASELINE_FILE" "$NO_BANNER" "$ALLOW_NPX"

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
: "$CI_MODE"

# Machine formats must keep stdout clean and timestamps stable.
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi
: "$QUIET"

USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
fi
: "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$GRAY" "$WHITE" "$BOLD" "$DIM" "$RESET" "$RED"

# Redirect output early to capture everything (text mode only; json/sarif should remain clean stdout)
if [[ -n "${OUTPUT_FILE}" && "$FORMAT" == "text" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

list_generated_ast_rule_ids() {
  local rules_dir="$1"
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$rules_dir"/*.yml 2>/dev/null || true ) | sort -u
}

if [[ "$LIST_RULES" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 && ! command -v sg >/dev/null 2>&1; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-gov2-rules.XXXXXX)"
  if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.go_rules import generate
generate(Path('$ast_rule_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
    echo "ERROR: failed to generate AST rules" >&2
    rm -rf "$ast_rule_dir" 2>/dev/null || true
    exit 2
  fi
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR"
    cp -R "$ast_rule_dir"/rules/. "$DUMP_RULES_DIR"/ 2>/dev/null || true
  fi
  list_generated_ast_rule_ids "$ast_rule_dir/rules"
  rm -rf "$ast_rule_dir" 2>/dev/null || true
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
# Contract-v2 path (bead 0xjg.6): ONE file list (ubs_list_files), ONE python
#    orchestrator (ubs_core.go_scan), NDJSON findings sink (K2 schema).
# ── Legacy-parity bridges for the contract-v2 path ──────────────────────────
run_v2_legacy_parity_bridges_go(){
  local sink="$1" list_file="$2" go_exit="$3" text_out="${4:-}" skip_csv="${5:-}" \
        tally_file="${6:-}" life_raw_path="${7:-}" life_status_raw="${8:-0}" run_life_raw="${9:-0}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "$skip_csv" \
    "$go_exit" "$tally_file" "$life_raw_path" "$life_status_raw" "$run_life_raw" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import os
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, go_exit_raw,
 tally_file, life_raw_path, life_status_raw, run_life_raw) = sys.argv[1:11]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
go_exit = int(go_exit_raw or "0")
life_status = int(life_status_raw or "0")
run_life = run_life_raw == "1"
as_text = bool(text_out)

# Mirror go_scan._CATEGORY_SLUGS/_SECTION_HEADERS (legacy print_header titles).
SLUG = {1: "concurrency", 2: "channels", 3: "context", 4: "http",
        5: "resource-lifecycle", 6: "error-handling", 7: "json-encoding",
        8: "filesystem", 9: "security", 10: "reflection-unsafe",
        11: "imports", 12: "build", 13: "testing", 14: "logging",
        15: "style", 16: "panic-time", 17: "lifecycle-correlation",
        18: "tooling", 19: "dependencies", 20: "defer-nil", 21: "database",
        22: "shutdown"}
SECTION = {1: "1. CONCURRENCY & GOROUTINE SAFETY", 2: "2. CHANNELS & SELECT",
           3: "3. CONTEXT PROPAGATION & CANCELLATION", 4: "4. HTTP CLIENT/SERVER SAFETY",
           5: "5. RESOURCE LIFECYCLE & DEFER", 6: "6. ERROR HANDLING & WRAPPING",
           7: "7. JSON & ENCODING", 8: "8. FILESYSTEM & I/O",
           9: "9. CRYPTOGRAPHY & SECURITY", 10: "10. REFLECTION & UNSAFE",
           11: "11. IMPORT HYGIENE", 12: "12. MODULE & BUILD HYGIENE",
           13: "13. TESTING PRACTICES", 14: "14. LOGGING & PRINTF",
           15: "15. STYLE & MODERNIZATION", 16: "16. PANIC/RECOVER & TIME PATTERNS (AST Pack)",
           17: "17. RESOURCE LIFECYCLE CORRELATION", 18: "18. GO TOOLING (OPTIONAL)",
           19: "19. DEPENDENCY & BUILD DRIFT", 20: "20. NIL PANICS FROM DEFER ORDERING (AST)",
           21: "21. DATABASE & SQL ROBUSTNESS", 22: "22. SHUTDOWN & RESOURCE RELEASE (HTTP/NET)"}

LIFE_SEVERITY = {"context_cancel": "critical", "ticker_stop": "warning",
                 "timer_stop": "warning", "file_handle": "warning",
                 "db_handle": "warning", "mutex_lock": "warning"}
LIFE_SUMMARY = {"context_cancel": "context.With* without deferred cancel",
                "ticker_stop": "time.NewTicker not stopped",
                "timer_stop": "time.NewTimer not stopped",
                "file_handle": "os.Open/OpenFile without defer Close()",
                "db_handle": "sql.Open without DB.Close()",
                "mutex_lock": "Mutex Lock without Unlock()"}
LIFE_REMEDIATION = {
    "context_cancel": "Store the cancel func and defer cancel() immediately after acquiring the context",
    "ticker_stop": "Keep the ticker handle and call Stop() when finished",
    "timer_stop": "Stop or drain timers to avoid leaks",
    "file_handle": "Call defer f.Close() immediately after Open to avoid FD leaks",
    "db_handle": "Close sql.DB handles when shutting down or prefer context-managed lifecycle",
    "mutex_lock": "Pair Lock() with defer Unlock() to avoid deadlocks when returning early",
}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

out = []

def emit(line=""):
    out.append(line)

# Bridge 1: run_resource_lifecycle_checks (cat 17) → sink records + text.
if run_life:
    raw = ""
    if life_raw_path and os.path.isfile(life_raw_path):
        with open(life_raw_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    rows = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 1 and parts[0].strip():
            rows.append(parts)
    new_records = []
    if rows:
        for parts in rows:
            location = parts[0]
            kind = parts[1] if len(parts) > 1 else ""
            message = parts[2] if len(parts) > 2 else ""
            severity = LIFE_SEVERITY.get(kind, "warning")
            summary = LIFE_SUMMARY.get(kind, "Resource imbalance")
            remediation = LIFE_REMEDIATION.get(kind, "Ensure matching cleanup call")
            desc = f"{remediation}: {message}" if message else remediation
            new_records.append({
                "rule": f"go.lifecycle.{kind or 'imbalance'}",
                "category_id": "golang.lifecycle-correlation",
                "path": location,
                "line": 0,
                "col": 1,
                "severity": severity,
                "message": f"{summary} [{location}] — {desc}"[:300],
                "suppressed": False,
            })
        with open(sink_path, "a", encoding="utf-8") as fh:
            for rec in new_records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        records.extend(new_records)
        if as_text:
            for rec in new_records:
                emit(f"[{rec['severity']}] {LIFE_SUMMARY.get(rec['rule'].rsplit('.', 1)[-1], rec['message'])} (1 found) — {rec['rule']}")
                location = rec["path"]
                emit(f"    {location}  {rec['message'][:180]}")
    elif life_status == 0:
        if as_text:
            emit("good: All tracked resource acquisitions have matching cleanups")
    elif as_text:
        emit("Info (0 found)")
        emit("    AST helper failed (go run resource_lifecycle_go.go)")

# Final severity recount over the whole sink (legacy 7935-7937 inputs).
counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

# Bridge 2 + 3 (text format only; json/sarif stdout stays machine-clean):
# record-less legacy section headers, the category-16 rule tally, and the
# trailing "Summary Statistics:" block with the legacy exit formula.
if as_text:
    covered = {str(rec.get("category_id", "")) for rec in records}
    tally = {}
    if tally_file and os.path.isfile(tally_file):
        try:
            with open(tally_file, encoding="utf-8") as fh:
                tally = json.load(fh)
        except (ValueError, OSError):
            tally = {}
    for num in sorted(SECTION):
        if num in skip:
            continue
        if f"golang.{SLUG[num]}" in covered and num != 16:
            continue
        emit("")
        emit(SECTION[num])
        if num == 16:
            emit("ast-grep produced structured matches. Tally by rule id:")
            for rid, n in sorted(tally.items()):
                emit(f"  • {rid:<44} {n:>5}")
        if num == 17 and not run_life:
            emit("Info (0 found)")
            emit("    Go toolchain unavailable — Install Go to run the AST helper")
        if num == 18:
            emit("Info (0 found)")
            emit("    Go tools disabled (use --go-tools) or Go not found")
    emit("")
    emit("Summary Statistics:")
    emit(f"Files scanned: {files_n}")
    emit(f"Critical issues: {counts['critical']}")
    emit(f"Warning issues: {counts['warning']}")
    emit(f"Info items: {counts['info']}")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

exit_code = 1 if counts["critical"] else go_exit
if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

run_contract_v2_go(){
  local list_file sink exit_code=0 text_out="" tally_file="" ast_rule_dir="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$CATEGORY_WHITELIST" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$CATEGORY_WHITELIST"
    for c in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  if command -v ast-grep >/dev/null 2>&1 || command -v sg >/dev/null 2>&1; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-gov2-rules.XXXXXX)"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.go_rules import generate
generate(Path('$ast_rule_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
      ast_rule_dir=""
    fi
  fi
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.go_rules import generate
generate(Path('$DUMP_RULES_DIR'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
    cp -R "$DUMP_RULES_DIR"/rules/. "$DUMP_RULES_DIR"/ 2>/dev/null || true
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  tally_file="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-tally.XXXXXX)"
  scan_args+=(--tally-out "$tally_file")
  case "$FORMAT" in
    json)
      exec 3>&1
      scan_args+=(--json-out /dev/fd/3 --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 golang path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.go_scan \
    "${scan_args[@]}" --version "$VERSION" || exit_code=$?
  if [[ "$FORMAT" == "sarif" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" || exit_code=$?
    rm -f "$v2_json_out" 2>/dev/null || true
  else
    local life_raw="" life_status=0 run_life=0
    local go_life_helper=""
    ubs_resolve_helper go_life_helper "helpers/resource_lifecycle_go.go" || go_life_helper=""
    if [[ ",$v2_skip," != *",17,"* && -n "$go_life_helper" && -f "$go_life_helper" ]] && command -v go >/dev/null 2>&1; then
      life_raw="$(mktemp 2>/dev/null || mktemp -t ubs-gov2-life.XXXXXX)"
      if go run "$go_life_helper" -- "$PROJECT_DIR" >"$life_raw" 2>/dev/null; then
        life_status=0
      else
        life_status=$?
      fi
      run_life=1
    fi
    run_v2_legacy_parity_bridges_go "$sink" "$list_file" "$exit_code" "$text_out" \
      "$v2_skip" "$tally_file" "$life_raw" "$life_status" "$run_life" || exit_code=$?
    if [[ -n "$text_out" ]]; then
      cat "$text_out" 2>/dev/null || true
      rm -f "$text_out" 2>/dev/null || true
    fi
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  rm -f "$list_file" "$sink" "$tally_file" "${life_raw:-}" 2>/dev/null || true
  [[ -n "$ast_rule_dir" ]] && rm -rf -- "$ast_rule_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_go || v2_status=$?
exit "$v2_status"
