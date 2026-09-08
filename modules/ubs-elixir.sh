#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ELIXIR ULTIMATE BUG SCANNER v1.0.2 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Elixir (1.15+) on contract v2.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-elixir.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="a8a629d02e687e041e51c41f839dc6ae018131a2252c3c2029e3acabe12ce4ce"
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

# ────────────────────────────────────────────────────────────────────────────
# Globals & defaults
# ────────────────────────────────────────────────────────────────────────────

VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
LIST_CATS=0
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="ex,exs,eex,heex,leex,sface"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
DISABLE_PIPEFAIL_DURING_SCAN=1

ENABLE_MIX_TOOLS=1
EX_TOOLS="dialyzer,credo,sobelow,doctor,inch,mix_audit"
EX_TIMEOUT="${EX_TIMEOUT:-1200}"

SUMMARY_JSON=""
REPORT_JSON=""                         # --report-json=FILE: NDJSON findings record stream (K2)
FILES_FROM=""
SARIF_OUT=""
JSON_OUT=""

CHECK="✓"; WARN="⚠"; INFO="ℹ"; BULLET="•"; FIRE="🔥"

# Color handling
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
: "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$GRAY" "$WHITE" "$BOLD" "$DIM" "$RESET" "$RED"

# ────────────────────────────────────────────────────────────────────────────
# Error handling
# ────────────────────────────────────────────────────────────────────────────

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  if [[ "${FORMAT:-text}" == "json" || "${FORMAT:-text}" == "sarif" ]]; then
    echo "{\"error\":{\"exit\":$ec,\"file\":\"$src\",\"line\":$line,\"cmd\":\"${cmd//\"/\\\"}\"}}" >&2; exit "$ec"
  fi
  echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2
  exit "$ec"
}
trap on_err ERR

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
  --report-json=FILE       Also write the NDJSON findings record stream (contract-v2 sink)
  --list-categories        Print numeric category map and exit
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --only=CSV               Only run these category numbers/names
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --no-mix                 Disable Mix-based extra analyzers
  --ex-tools=CSV           Which extra tools to run (default: $EX_TOOLS)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI, EX_TIMEOUT, UBS_METRICS_DIR
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
contract: v2
USAGE
}

safe_count_files(){ tr -cd '\0' | wc -c | tr -d ' '; }

# CLI parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    --very-verbose) VERBOSE=2; DETAIL_LIMIT=25; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    --list-categories) LIST_CATS=1; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --no-mix)     ENABLE_MIX_TOOLS=0; shift;;
    --ex-tools=*) EX_TOOLS="${1#*=}"; shift;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
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
: "$JSON_OUT" "$SARIF_OUT" "$SUMMARY_JSON"

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
: "$CI_MODE"
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

# Redirect output early to capture everything (honors machine formats too)
if [[ -n "${OUTPUT_FILE}" ]]; then
  if command -v tee >/dev/null 2>&1; then
    exec > >(tee "${OUTPUT_FILE}") 2>&1
  else
    exec > "${OUTPUT_FILE}" 2>&1
  fi
fi

is_machine_format(){ [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; }

# If machine format: silence all user-facing text immediately.
if is_machine_format; then
  QUIET=1
  USE_COLOR=0
fi

# ── Early list-categories helper ────────────────────────────────────────────
if [[ "$LIST_CATS" -eq 1 ]]; then
  cat <<CATS
1  Pattern Matching & Guards
2  Error Handling & Exceptions
3  Process & OTP Lifecycle
4  Security Vulnerabilities
5  Phoenix-Specific Issues
6  Ecto & Database
7  Concurrency & Messaging
8  I/O & Resource Lifecycle
9  Debugging & Production Code
10 Performance & Memory
11 Code Quality Markers
12 Configuration & Environment
13 Testing Patterns
14 Dependency & Mix Hygiene
15 String & Binary Safety
16 Mix-Powered Extra Analyzers
CATS
  exit 0
fi

say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }
print_subheader() { say "\n${YELLOW}${BOLD}$BULLET $1${RESET}"; }
print_finding() {
  local severity=$1
  case $severity in
    good) local title=$2; say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}" ;;
    *)
      local raw_count=$2; local title=$3; local description="${4:-}"
      local count; count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
      case $severity in
        critical) say "  ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"; say "    ${RED}${BOLD}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
        warning)  say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"; say "    ${YELLOW}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
        info)     say "  ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"; say "    ${BLUE}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
      esac
      ;;
  esac
}

with_timeout() {
  local seconds="$1"; shift || true
  if command -v timeout >/dev/null 2>&1; then timeout "$seconds" "$@"; else "$@"; fi
}

HAS_MIX=0
IS_PHOENIX=0
check_mix() {
  if command -v mix >/dev/null 2>&1 && [[ -f "$PROJECT_DIR/mix.exs" ]]; then
    HAS_MIX=1; return 0
  fi
  HAS_MIX=0; return 1
}

check_phoenix() {
  if [[ -f "$PROJECT_DIR/mix.exs" ]] && grep -q ':phoenix' "$PROJECT_DIR/mix.exs" 2>/dev/null; then
    IS_PHOENIX=1; return 0
  fi
  IS_PHOENIX=0; return 1
}

run_mix_tool() {
  local tool_cmd="$1"; shift || true
  if [[ "$ENABLE_MIX_TOOLS" -eq 1 && "$HAS_MIX" -eq 1 ]]; then
    ( cd "$PROJECT_DIR" && with_timeout "$EX_TIMEOUT" mix $tool_cmd "$@" ) || true
  else
    say "  ${GRAY}${INFO} mix not available or tools disabled; skipping${RESET}"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# Contract-v2 path (bead 0xjg.13): ONE file list (ubs_list_files), ONE python
#    orchestrator (ubs_core.elixir_scan), NDJSON findings sink (K2 schema).
# ── Legacy-parity bridge: mix-powered analyzers (category 16) ──────────────
TOOL_COUNTS=""
v2_tool_finding(){
  local severity=$1 count=$2 title=$3 description="${4:-}"
  print_finding "$severity" "$count" "$title" "$description"
  [[ "$severity" == "good" ]] && return 0
  TOOL_COUNTS="${TOOL_COUNTS:+$TOOL_COUNTS,}$severity:$count"
}

run_v2_ex_tools(){
  if [[ "$ENABLE_MIX_TOOLS" -ne 1 || "$HAS_MIX" -ne 1 ]]; then
    say "  ${GRAY}${INFO} Mix-based analyzers disabled (--no-mix or mix not found)${RESET}"
    return 0
  fi
  local TOOL
  IFS=',' read -r -a EXTOOLS <<< "$EX_TOOLS"
  for TOOL in "${EXTOOLS[@]}"; do
    case "$TOOL" in
      dialyzer)
        print_subheader "dialyxir / mix dialyzer (static type analysis)"
        if ( cd "$PROJECT_DIR" && mix help dialyzer >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix dialyzer (this may take a while on first run)...${RESET}"
          output=$(run_mix_tool "dialyzer" --format short 2>&1 || true)
          if [[ -n "$output" ]]; then
            errs=$(echo "$output" | grep -c -E "error:|warning:" || true)
            if [ "$errs" -gt 0 ]; then
              v2_tool_finding "warning" "$errs" "Dialyzer found type discrepancies" "Run 'mix dialyzer' for full details"
            else
              print_finding "good" "Dialyzer passed with no warnings"
            fi
          else
            print_finding "good" "Dialyzer analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} dialyxir not installed; add {:dialyxir, \"~> 1.4\", only: [:dev], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      credo)
        print_subheader "credo (code quality / style)"
        if ( cd "$PROJECT_DIR" && mix help credo >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix credo --strict...${RESET}"
          output=$(run_mix_tool "credo" --strict --format flycheck 2>&1 || true)
          if [[ -n "$output" ]]; then
            issues=$(echo "$output" | grep -c -E "^.+:[0-9]+:" || true)
            if [ "$issues" -gt 0 ]; then
              v2_tool_finding "info" "$issues" "Credo found code quality issues" "Run 'mix credo --strict' for full details"
            else
              print_finding "good" "Credo passed with no issues"
            fi
          else
            print_finding "good" "Credo analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} credo not installed; add {:credo, \"~> 1.7\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      sobelow)
        print_subheader "sobelow (Phoenix security analysis)"
        if [[ "$IS_PHOENIX" -eq 1 ]]; then
          if ( cd "$PROJECT_DIR" && mix help sobelow >/dev/null 2>&1 ); then
            say "  ${DIM}Running mix sobelow --config...${RESET}"
            output=$(run_mix_tool "sobelow" --config --format txt 2>&1 || true)
            if [[ -n "$output" ]]; then
              vulns=$(echo "$output" | grep -c -E "^\[" || true)
              if [ "$vulns" -gt 0 ]; then
                v2_tool_finding "warning" "$vulns" "Sobelow found security issues" "Run 'mix sobelow --config' for full details"
              else
                print_finding "good" "Sobelow found no security issues"
              fi
            else
              print_finding "good" "Sobelow security scan clean"
            fi
          else
            say "  ${GRAY}${INFO} sobelow not installed; add {:sobelow, \"~> 0.13\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
          fi
        else
          say "  ${GRAY}${INFO} Not a Phoenix project; sobelow scan skipped${RESET}"
        fi
        ;;
      doctor)
        print_subheader "doctor (documentation / typespec checking)"
        if ( cd "$PROJECT_DIR" && mix help doctor >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix doctor...${RESET}"
          output=$(run_mix_tool "doctor" 2>&1 || true)
          if [[ -n "$output" ]]; then
            issues=$(echo "$output" | grep -c -E "FAILED|WARN" || true)
            if [ "$issues" -gt 0 ]; then
              v2_tool_finding "info" "$issues" "Doctor found documentation/typespec issues" "Run 'mix doctor' for full details"
            else
              print_finding "good" "Doctor check passed"
            fi
          else
            print_finding "good" "Doctor analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} doctor not installed; add {:doctor, \"~> 0.21\", only: :dev} to mix.exs${RESET}"
        fi
        ;;
      inch)
        print_subheader "inch_ex (documentation coverage)"
        if ( cd "$PROJECT_DIR" && mix help inch >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix inch...${RESET}"
          output=$(run_mix_tool "inch" 2>&1 || true)
          if [[ -n "$output" ]]; then
            undoc=$(echo "$output" | grep -c -E "\[U\]|\[C\]" || true)
            if [ "$undoc" -gt 5 ]; then
              v2_tool_finding "info" "$undoc" "inch_ex found undocumented/incomplete modules" "Run 'mix inch' for full coverage report"
            else
              print_finding "good" "Documentation coverage looks good"
            fi
          else
            print_finding "good" "inch_ex analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} inch_ex not installed; add {:inch_ex, \"~> 2.0\", only: [:dev, :test]} to mix.exs${RESET}"
        fi
        ;;
      mix_audit)
        print_subheader "mix_audit (dependency vulnerability audit)"
        if ( cd "$PROJECT_DIR" && mix help deps.audit >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix deps.audit...${RESET}"
          output=$(run_mix_tool "deps.audit" 2>&1 || true)
          if [[ -n "$output" ]]; then
            vulns=$(echo "$output" | grep -c -E "Vulnerability found|advisory" || true)
            if [ "$vulns" -gt 0 ]; then
              v2_tool_finding "critical" "$vulns" "MixAudit found dependency vulnerabilities" "Run 'mix deps.audit' and update affected dependencies"
            else
              print_finding "good" "No known dependency vulnerabilities"
            fi
          else
            print_finding "good" "Dependency audit clean"
          fi
        elif command -v mix_audit >/dev/null 2>&1; then
          say "  ${DIM}Running mix_audit...${RESET}"
          output=$( ( cd "$PROJECT_DIR" && with_timeout "$EX_TIMEOUT" mix_audit ) 2>&1 || true)
          if [[ -n "$output" ]]; then
            vulns=$(echo "$output" | grep -c -E "Vulnerability found|advisory" || true)
            if [ "$vulns" -gt 0 ]; then
              v2_tool_finding "critical" "$vulns" "MixAudit found dependency vulnerabilities"
            else
              print_finding "good" "No known dependency vulnerabilities"
            fi
          fi
        else
          say "  ${GRAY}${INFO} mix_audit not installed; add {:mix_audit, \"~> 2.1\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      *)
        say "  ${GRAY}${INFO} Unknown tool '$TOOL' ignored${RESET}"
        ;;
    esac
  done
}

# ── Legacy-parity bridges: record-less section headers + summary + exit ─────
run_v2_legacy_parity_bridges_elixir(){
  local sink="$1" list_file="$2" scan_exit="$3" text_out="${4:-}" skip_csv="${5:-}" tool_counts="${6:-}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "$skip_csv" \
    "$scan_exit" "$tool_counts" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, scan_exit_raw, tool_counts) = sys.argv[1:8]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
scan_exit = int(scan_exit_raw or "0")
as_text = bool(text_out)

SLUG = {1: "pattern-matching", 2: "error-handling", 3: "process-otp",
        4: "security", 5: "phoenix", 6: "ecto", 7: "concurrency", 8: "io",
        9: "debug", 10: "perf", 11: "code-quality", 12: "config",
        13: "testing", 14: "mix", 15: "binary-safety", 16: "analyzers"}
SECTION = {1: "1. PATTERN MATCHING & GUARDS", 2: "2. ERROR HANDLING & EXCEPTIONS",
           3: "3. PROCESS & OTP LIFECYCLE", 4: "4. SECURITY VULNERABILITIES",
           5: "5. PHOENIX-SPECIFIC ISSUES", 6: "6. ECTO & DATABASE",
           7: "7. CONCURRENCY & MESSAGING", 8: "8. I/O & RESOURCE LIFECYCLE",
           9: "9. DEBUGGING & PRODUCTION CODE", 10: "10. PERFORMANCE & MEMORY",
           11: "11. CODE QUALITY MARKERS", 12: "12. CONFIGURATION & ENVIRONMENT",
           13: "13. TESTING PATTERNS", 14: "14. DEPENDENCY & MIX HYGIENE",
           15: "15. STRING & BINARY SAFETY", 16: "16. MIX-POWERED EXTRA ANALYZERS"}

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

# Mix-tool counts from the module-side bridge (legacy print_finding bumps).
for chunk in (tool_counts or "").split(","):
    chunk = chunk.strip()
    if not chunk or ":" not in chunk:
        continue
    sev, _, raw = chunk.rpartition(":")
    sev = sev.strip()
    try:
        n = int(raw)
    except ValueError:
        continue
    if sev in counts and n > 0:
        counts[sev] += n

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
        if slug is not None and f"elixir.{slug}" in covered:
            continue  # the renderer already announced this section
        emit(SECTION[num])
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

run_contract_v2_elixir(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-exv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-exv2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  local list_rc=0
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  else
    ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file" || list_rc=$?
  fi
  if [[ "$list_rc" -gt 1 ]] && ! [[ -s "$list_file" ]]; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  case "$FORMAT" in
    json)
      exec 3>&1
      scan_args+=(--json-out /dev/fd/3 --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-exv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-exv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 elixir path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.elixir_scan \
    "${scan_args[@]}" --version "1.0.2" || exit_code=$?
  if [[ "$FORMAT" == "sarif" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" || exit_code=$?
    rm -f "$v2_json_out" 2>/dev/null || true
  else
    # Category 16 parity bridge: raw mix-tool passthrough
    if [[ ",$v2_skip," != *",16,"* ]]; then
      check_mix || true
      check_phoenix || true
      run_v2_ex_tools
    fi
    # Record-less section headers + Summary Statistics + legacy exit formula.
    run_v2_legacy_parity_bridges_elixir "$sink" "$list_file" "$exit_code" "$text_out" \
      "$v2_skip" "$TOOL_COUNTS" || exit_code=$?
    if [[ -n "$text_out" ]]; then
      cat "$text_out" 2>/dev/null || true
      rm -f "$text_out" 2>/dev/null || true
    fi
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_elixir || v2_status=$?
exit "$v2_status"
