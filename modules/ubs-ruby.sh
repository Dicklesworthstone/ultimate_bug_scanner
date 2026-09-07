#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# RUBY ULTIMATE BUG SCANNER - Contract-v2 Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Ruby (3.3+) using:
#   • ast-grep (rule packs; language: ruby)
#   • ripgrep/grep heuristics for fast code smells
#   • optional Bundler-powered extra analyzers
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-ruby.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="9cbde85cf097681dc2942fc7c5c8e8321fc7fc9e94c1e50245d426686d109b0a"
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
umask 022
shopt -s lastpipe
shopt -s extglob

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure predictable IFS for loops (restored on exit)
ORIG_IFS=${IFS}
IFS=$' \t\n'

# ────────────────────────────────────────────────────────────────────────────
# Temp paths / cleanup
# ────────────────────────────────────────────────────────────────────────────
KEEP_TEMP=${UBS_KEEP_TEMP:-0}
TEMP_PATHS=()

cleanup_add() { [[ -n "${1:-}" ]] && TEMP_PATHS+=("$1"); }

cleanup() {
  IFS=${ORIG_IFS}
  [[ "${KEEP_TEMP}" -eq 1 ]] && return 0
  local p
  for p in "${TEMP_PATHS[@]:-}"; do
    [[ -n "$p" && "$p" != "/" && "$p" != "." ]] && rm -rf -- "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

# ────────────────────────────────────────────────────────────────────────────
# Error trapping
# ────────────────────────────────────────────────────────────────────────────
on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  local _RED=${RED:-}; local _BOLD=${BOLD:-}; local _RESET=${RESET:-}; local _DIM=${DIM:-}; local _WHITE=${WHITE:-}
  trap - ERR
  echo -e "\n${_RED}${_BOLD}Unexpected error (exit $ec)${_RESET} ${_DIM}at ${src}:${line}${_RESET}\n${_DIM}Last command:${_RESET} ${_WHITE}${cmd}${_RESET}" >&2
  trap on_err ERR
  exit "$ec"
}
trap on_err ERR

# ────────────────────────────────────────────────────────────────────────────
# Color / Icons
# ────────────────────────────────────────────────────────────────────────────
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
  BOLD=''; DIM=''; RESET=''
fi

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; BULLET="•"; FIRE="🔥"
: "$CHECK" "$CROSS" "$WARN" "$INFO" "$BULLET" "$FIRE" "$RED" "$GREEN" "$BLUE" "$MAGENTA" "$CYAN" "$WHITE"

say() { echo -e "$*"; }
print_subheader() { say "\n${YELLOW}${BOLD}• $1${RESET}"; }

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="rb,rake,ru,gemspec,erb,haml,slim,rbi,rbs,jbuilder"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DUMP_RULES_DIR=""
LIST_RULES=0
JSON_OUT=""
SARIF_OUT=""
SUMMARY_JSON=""
REPORT_JSON=""
ONLY_RULES=""
DISABLE_RULES=""
AG_THREADS=""
AG_FIXABLE_ONLY=0
AG_PREVIEW_FIX=0
ENABLE_BUNDLER_TOOLS=1
RB_TOOLS=${RB_TOOLS:-"rubocop,brakeman,bundler-audit"}
RB_TIMEOUT=${RB_TIMEOUT:-120}
FILES_FROM=""

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  --very-verbose           Max code samples (DETAIL=25)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --json-out=FILE          Save full JSON report to file (text still prints)
  --sarif-out=FILE         Save SARIF to file (text still prints)
  --summary-json=FILE      Save brief summary counters JSON
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --only-rules=GLOB        Restrict to ast-grep rules matching GLOB (e.g. rb.*)
  --disable-rules=GLOB     Disable ast-grep rules matching GLOB
  --include-ext=CSV        File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --only=CSV               Only run these category numbers/names
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --ag-threads=N           Threads for ast-grep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --dump-rules=DIR         Persist generated ast-grep rules to DIR for test validation
  --list-rules             List generated ast-grep rule IDs and exit
  --report-json=FILE       Also write the NDJSON findings record stream (contract-v2 sink)
  --ag-fixable-only        Limit AST output to rules that provide fixes
  --ag-preview-fix         Preview ast-grep fixes (no writes) in diff form
  --no-bundler             Disable bundler-based extra analyzers
  --rb-tools=CSV           Which extra tools to run (default: $RB_TOOLS)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI, RB_TIMEOUT, UBS_METRICS_DIR
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
contract: v2
USAGE
}

list_categories() {
  cat <<'CATS'
1  Nil & Type Coercion Hazards
2  Numeric & Arithmetic Pitfalls
3  Collections & Mutability
4  Metaprogramming & Dynamic Dispatch
5  Exceptions & Error Handling
6  Security Vulnerabilities
7  Shell / Subprocess Safety
8  I/O & Resource Lifecycle Correlation
9  Parsing & Type Conversion Bugs
10 Control Flow Gotchas
11 Debugging & Production Code
12 Performance & Memory
13 Variable & Scope
14 Code Quality Markers
15 Regex & String Safety
16 Concurrency & Parallelism
17 Ruby/Rails Practicals
18 AST-Grep Rule Pack Findings
19 Bundler-Powered Extra Analyzers
CATS
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    --very-verbose) VERBOSE=2; DETAIL_LIMIT=25; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --list-categories) list_categories; exit 0;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --only-rules=*) ONLY_RULES="${1#*=}"; shift;;
    --disable-rules=*) DISABLE_RULES="${1#*=}"; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --ag-threads=*) AG_THREADS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --ag-fixable-only) AG_FIXABLE_ONLY=1; shift;;
    --ag-preview-fix) AG_PREVIEW_FIX=1; shift;;
    --no-bundler) ENABLE_BUNDLER_TOOLS=0; shift;;
    --rb-tools=*) RB_TOOLS="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, use the meta-runner 'ubs'. To save a report, pass a fresh (non-existing) path." >&2
          exit 2
        fi
        OUTPUT_FILE="$1"
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      shift;;
  esac
done

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi

HAS_BUNDLE=0
BUNDLE_EXEC=()
if command -v bundle >/dev/null 2>&1 && [[ -f "$PROJECT_DIR/Gemfile" ]]; then
  HAS_BUNDLE=1
  BUNDLE_EXEC=(bundle exec)
fi

with_timeout() {
  local to="$1"; shift || true
  if command -v timeout >/dev/null 2>&1; then timeout "$to" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$to" "$@"
  else "$@"; fi
}

run_rb_tool_text() {
  local tool="$1"; shift || true
  if [[ "$ENABLE_BUNDLER_TOOLS" -eq 1 && "$HAS_BUNDLE" -eq 1 ]]; then
    if [[ "$tool" == "bundle" ]]; then with_timeout "$RB_TIMEOUT" bundle "$@" || true
    else with_timeout "$RB_TIMEOUT" "${BUNDLE_EXEC[@]}" "$tool" "$@" || true; fi
  else
    if command -v "$tool" >/dev/null 2>&1; then with_timeout "$RB_TIMEOUT" "$tool" "$@" || true; fi
  fi
}

run_bundle_audit() {
  if [[ "$HAS_BUNDLE" -eq 1 && -f "$PROJECT_DIR/Gemfile.lock" ]]; then
    with_timeout "$RB_TIMEOUT" bundle audit check --update || true
  elif command -v bundler-audit >/dev/null 2>&1; then
    with_timeout "$RB_TIMEOUT" bundler-audit check --update || true
  elif command -v bundle-audit >/dev/null 2>&1; then
    with_timeout "$RB_TIMEOUT" bundle-audit check --update || true
  else
    say "  ${GRAY}${INFO} bundler-audit not available; skipping${RESET}"
  fi
}

# Silence options unused in contract-v2 for shellcheck
: "$VERBOSE" "$DETAIL_LIMIT" "$JOBS" "$USER_RULE_DIR" "$QUIET" "$CI_MODE" "$USE_COLOR"
: "$ONLY_RULES" "$DISABLE_RULES" "$AG_THREADS" "$AG_FIXABLE_ONLY" "$AG_PREVIEW_FIX"
: "$GREEN" "$BLUE" "$MAGENTA" "$CYAN"
: "${SCRIPT_DIR}" "${PROJECT_DIR}" "${OUTPUT_FILE:-}" "${SOURCE_PROJECT_DIR:-}"

if [[ "$LIST_RULES" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-rbv2-rules.XXXXXX)"
  cleanup_add "$tmp_rules"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.ruby_rules import generate
generate(Path('$tmp_rules'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml 2>/dev/null || true ) | sort -u
  exit 0
fi

# ── Legacy-parity bridge: bundler tools (category 19) ───────────────────────
run_v2_rb_tools(){
  if [[ "$ENABLE_BUNDLER_TOOLS" -ne 1 ]]; then
    say "  ${GRAY}${INFO} bundler-based analyzers disabled (--no-bundler)${RESET}"
    return 0
  fi
  local TOOL
  IFS=',' read -r -a RBTOOLS <<< "$RB_TOOLS"
  for TOOL in "${RBTOOLS[@]}"; do
    case "$TOOL" in
      rubocop)
        print_subheader "rubocop (lint/style)"
        run_rb_tool_text rubocop --format clang --force-exclusion "$PROJECT_DIR" || true
        ;;
      brakeman)
        print_subheader "brakeman (Rails security)"
        if [[ -d "$PROJECT_DIR/app" || -d "$PROJECT_DIR/config" ]]; then
          run_rb_tool_text brakeman -q -w2 -z "$PROJECT_DIR" || true
        else
          say "  ${GRAY}${INFO} Rails app structure not detected; brakeman may be N/A${RESET}"
          run_rb_tool_text brakeman -q -z "$PROJECT_DIR" || true
        fi
        ;;
      bundler-audit)
        print_subheader "bundler-audit (dependency vulns)"
        run_bundle_audit
        ;;
      reek)
        print_subheader "reek (code smells)"
        run_rb_tool_text reek --single-line "$PROJECT_DIR" || true
        ;;
      fasterer)
        print_subheader "fasterer (perf idioms)"
        run_rb_tool_text fasterer "$PROJECT_DIR" || true
        ;;
      *)
        say "  ${GRAY}${INFO} Unknown tool '$TOOL' ignored${RESET}"
        ;;
    esac
  done
}

# ── Legacy-parity bridges: record-less section headers + summary + exit ─────
run_v2_legacy_parity_bridges_ruby(){
  local sink="$1" list_file="$2" scan_exit="$3" text_out="${4:-}" skip_csv="${5:-}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "$skip_csv" \
    "$scan_exit" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, scan_exit_raw) = sys.argv[1:7]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
scan_exit = int(scan_exit_raw or "0")
as_text = bool(text_out)

# Mirror ruby_scan._CATEGORY_SLUGS/_SECTION_HEADERS (legacy print_header
# titles). Category 18 has no slug (its pack findings never joined totals).
SLUG = {1: "nil", 2: "numeric", 3: "collections", 4: "comparison",
        5: "exceptions", 6: "security", 7: "shell", 8: "io", 9: "parsing",
        10: "control-flow", 11: "debug", 12: "perf", 13: "variables",
        14: "code-quality", 15: "regex", 16: "concurrency", 17: "rails",
        19: "bundler"}
SECTION = {1: "1. NIL / DEFENSIVE PROGRAMMING", 2: "2. NUMERIC / ARITHMETIC PITFALLS",
           3: "3. COLLECTION SAFETY", 4: "4. COMPARISON & IDIOMS",
           5: "5. EXCEPTIONS & ERROR HANDLING", 6: "6. SECURITY VULNERABILITIES",
           7: "7. SHELL / SUBPROCESS SAFETY", 8: "8. I/O & RESOURCE LIFECYCLE CORRELATION",
           9: "9. PARSING & TYPE CONVERSION BUGS", 10: "10. CONTROL FLOW GOTCHAS",
           11: "11. DEBUGGING & PRODUCTION CODE", 12: "12. PERFORMANCE & MEMORY",
           13: "13. VARIABLE & SCOPE", 14: "14. CODE QUALITY MARKERS",
           15: "15. REGEX & STRING SAFETY", 16: "16. CONCURRENCY & PARALLELISM",
           17: "17. RUBY/RAILS PRACTICALS", 18: "AST-GREP RULE PACK FINDINGS",
           19: "19. BUNDLER-POWERED EXTRA ANALYZERS"}
SUBHEAD = {8: "Resource lifecycle correlation",
           16: "Async error path coverage"}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

# Final severity recount over the whole sink, legacy exit formula inputs.
counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

out = []

def emit(line=""):
    out.append(line)

# Record-less section headers (text format only; json stdout stays machine-clean).
if as_text:
    covered = {str(rec.get("category_id", "")) for rec in records}
    for num in sorted(SECTION):
        if num in skip:
            continue
        slug = SLUG.get(num)
        if slug is not None and f"ruby.{slug}" in covered:
            continue
        if slug is None and records:
            continue
        emit(SECTION[num])
        if num in SUBHEAD:
            emit(SUBHEAD[num])
    emit("")
    emit("Summary Statistics:")
    emit(f"Files scanned: {files_n}")
    emit(f"Critical issues: {counts['critical']}")
    emit(f"Warning issues: {counts['warning']}")
    emit(f"Info items: {counts['info']}")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

exit_code = 1 if counts["critical"] else scan_exit
if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

run_contract_v2_ruby(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-rbv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-rbv2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  # --only whitelist -> v2 skip mapping: skip every category NOT whitelisted
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)

  local ast_rule_dir=""
  if command -v ast-grep >/dev/null 2>&1 && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-rbv2-rules.XXXXXX)"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.ruby_rules import generate
generate(Path('$ast_rule_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
      ast_rule_dir=""
    fi
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.ruby_rules import generate
generate(Path('$DUMP_RULES_DIR'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  fi

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-rbv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-rbv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 ruby path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.ruby_scan \
    "${scan_args[@]}" --version "2.0.1" || exit_code=$?

  if [[ ",$v2_skip," != *",19,"* && "$FORMAT" == "text" ]]; then
    run_v2_rb_tools
  fi

  run_v2_legacy_parity_bridges_ruby "$sink" "$list_file" "$exit_code" "$text_out" \
    "$v2_skip" || exit_code=$?

  if [[ "$FORMAT" == "sarif" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null || true
    fi
  fi

  if [[ -n "$text_out" ]]; then
    cat "$text_out" 2>/dev/null || true
    rm -f "$text_out" 2>/dev/null || true
  fi
  if [[ -n "$v2_json_out" && "$FORMAT" == "json" ]]; then
    cat "$v2_json_out" 2>/dev/null || true
  fi

  if [[ -n "$SARIF_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" > "$SARIF_OUT" 2>/dev/null || true
  fi
  if [[ -n "$JSON_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    cp "$v2_json_out" "$JSON_OUT" 2>/dev/null || true
  fi
  if [[ -n "$SUMMARY_JSON" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    cp "$v2_json_out" "$SUMMARY_JSON" 2>/dev/null || true
  fi

  if [[ -n "$v2_json_out" ]]; then
    rm -f "$v2_json_out" 2>/dev/null || true
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  [[ -n "$ast_rule_dir" ]] && rm -rf -- "$ast_rule_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_ruby || v2_status=$?
exit "$v2_status"
