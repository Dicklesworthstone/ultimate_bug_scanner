#!/usr/bin/env bash
# shellcheck disable=SC2002,SC2015,SC2034,SC2317
# ═══════════════════════════════════════════════════════════════════════════
# RUST ULTIMATE BUG SCANNER v3.0.1 - Industrial-Grade Rust Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for Rust on contract v2.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-rust.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="7cd29440599983c0aed356590be935b32c15a631d07deec39c6cff9a47940db8"
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
shopt -s lastpipe 2>/dev/null || true

# Centralized cleanup & robust error handler
TMP_FILES=()
cleanup() {
  local ec=$?
  if [[ ${#TMP_FILES[@]} -gt 0 ]]; then
    for f in "${TMP_FILES[@]}"; do
      [[ -e "$f" ]] && rm -rf -- "$f" 2>/dev/null || true
    done
  fi
  exit "$ec"
}
trap cleanup EXIT

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  local _RED=${RED-}; local _BOLD=${BOLD-}; local _RESET=${RESET-}; local _DIM=${DIM-}; local _WHITE=${WHITE-}
  set +o pipefail
  echo -e "\n${_RED}${_BOLD}Unexpected error (exit $ec)${_RESET} ${_DIM}at ${src}:${line}${_RESET}\n${_DIM}Last command:${_RESET} ${_WHITE}$cmd${_RESET}" >&2
  exit "$ec"
}
trap on_err ERR

# Color / Icons
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi

init_colors() {
  if [[ "$USE_COLOR" -eq 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
  else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
    BOLD=''; DIM=''; RESET=''
  fi
}
init_colors

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; WRENCH="🛠"; ROCKET="🚀"
: "$CHECK" "$CROSS" "$WARN" "$INFO" "$ARROW" "$BULLET" "$MAGNIFY" "$BUG" "$FIRE" "$SPARKLE" "$SHIELD" "$WRENCH" "$ROCKET"
: "$RED" "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$WHITE" "$GRAY" "$BOLD" "$DIM" "$RESET"

say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

print_header() {
  [[ -n "${1:-}" ]] || return 0
  say "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  say "${WHITE}${BOLD}$1${RESET}"
  say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

print_category() {
  say "\n${MAGENTA}${BOLD}▓▓▓ $1${RESET}"
  say "${DIM}$2${RESET}"
}

print_subheader() { say "\n${YELLOW}${BOLD}$BULLET $1${RESET}"; }

print_finding() {
  local severity=$1
  case $severity in
    good)
      local title=$2
      say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}"
      ;;
    *)
      local raw_count=$2; local title=$3; local description="${4:-}"; local category="${5:-}"
      local count; count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
      case $severity in
        critical)
          CRITICAL_COUNT=$((CRITICAL_COUNT + count))
          say "  ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"
          say "    ${RED}${BOLD}$title${RESET}"
          [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          ;;
        warning)
          WARNING_COUNT=$((WARNING_COUNT + count))
          say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"
          say "    ${YELLOW}$title${RESET}"
          [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          ;;
        info)
          INFO_COUNT=$((INFO_COUNT + count))
          say "  ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"
          say "    ${BLUE}$title${RESET}"
          [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          ;;
      esac
      ;;
  esac
}

# CLI Parsing & Configuration
VERSION="3.0.1"
SELF_NAME="$(basename "$0")"

VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="rs"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
RUN_CARGO=1
CARGO_FEATURES_ALL=1
CARGO_TARGETS_ALL=1
FAIL_CRITICAL_THRESHOLD=1
FAIL_WARNING_THRESHOLD=0
SUMMARY_JSON=""
REPORT_JSON=""
EMIT_FINDINGS_JSON=""
LIST_CATEGORIES=0
DUMP_RULES_DIR=""
LIST_RULES=0
STRICT_GITIGNORE=0
EXCLUDE_TESTS=0
FILES_FROM=""

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose              More code samples per finding (DETAIL=10)
  -q, --quiet                Reduce non-essential output
  --list-categories          Print category index and exit
  --list-rules               List generated ast-grep rule ids, then exit
  --dump-rules=DIR           Persist generated ast-grep rules to DIR
  --format=FMT               Output format: text|json|sarif (default: text)
  --ci                       CI mode (stable timestamps, no screen clear)
  --no-color                 Force disable ANSI color
  --include-ext=CSV          File extensions (default: rs)
  --exclude=GLOB[,..]        Additional glob(s)/dir(s) to exclude
  --exclude-dir=GLOB[,..]    Additional directory to exclude
  --jobs=N                   Parallel jobs for ripgrep (default: auto)
  --skip=CSV                 Skip categories by number (e.g. --skip=2,7,11)
  --only=CSV                 Run only the specified categories (overrides --skip)
  --fail-on-warning          Exit non-zero on warnings or critical
  --rules=DIR                Additional ast-grep rules directory (merged)
  --no-cargo                 Static analysis only: skip every cargo phase
  --no-all-features          Do not pass --all-features to cargo
  --no-all-targets           Do not pass --all-targets to cargo
  --summary-json=FILE        Write a machine-readable summary (JSON)
  --emit-findings-json=FILE  Write full findings (structured JSON)
  --strict-gitignore         Honor .gitignore even without ripgrep
  --exclude-tests            Exclude matches inside test functions/modules
  --fail-critical=N          Exit non-zero if critical issues >= N (default: 1)
  --fail-warning=N           Exit non-zero if warnings  >= N (default: 0)
  -h, --help                 Show help

contract: v2
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --list-categories) LIST_CATEGORIES=1; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --dump-rules) DUMP_RULES_DIR="${2:-}"; shift 2;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --format)     FORMAT="${2:-}"; ubs_validate_format "$FORMAT"; shift 2;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --exclude-dir=*) EXTRA_EXCLUDES="${1#*=}"; shift;;
    --include=*)  shift;;
    --binary-files=*) shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --no-cargo)   RUN_CARGO=0; shift;;
    --no-all-features) CARGO_FEATURES_ALL=0; shift;;
    --no-all-targets)  CARGO_TARGETS_ALL=0; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --emit-findings-json=*) EMIT_FINDINGS_JSON="${1#*=}"; shift;;
    --strict-gitignore) STRICT_GITIGNORE=1; shift;;
    --exclude-tests) EXCLUDE_TESTS=1; shift;;
    --fail-critical=*) FAIL_CRITICAL_THRESHOLD="${1#*=}"; shift;;
    --fail-warning=*)  FAIL_WARNING_THRESHOLD="${1#*=}"; shift;;
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
      fi;;
  esac
done

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
CARGO_SKIP_REASON=""
CARGO_INVOKED=()
CARGO_SKIPPED_CATEGORIES=()
if [[ "$RUN_CARGO" -eq 0 ]]; then
  CARGO_SKIP_REASON="--no-cargo (static analysis only)"
elif [[ -n "${UBS_SKIP_RUST_BUILD:-}" && "${UBS_SKIP_RUST_BUILD}" != "0" ]]; then
  RUN_CARGO=0
  CARGO_SKIP_REASON="UBS_SKIP_RUST_BUILD=${UBS_SKIP_RUST_BUILD} (static analysis only)"
fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
init_colors
if [[ "$USE_COLOR" -eq 0 ]]; then export NO_COLOR=1; export CARGO_TERM_COLOR=never; fi
if [[ -n "${OUTPUT_FILE}" ]]; then mkdir -p "$(dirname -- "$OUTPUT_FILE")" 2>/dev/null || true; exec > >(tee "${OUTPUT_FILE}") 2>&1; fi
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi

DATE_FMT='%Y-%m-%d %H:%M:%S'
now() { if [[ "$CI_MODE" -eq 1 ]]; then date -u '+%Y-%m-%dT%H:%M:%SZ'; else date +"$DATE_FMT"; fi; }

# Global counters & state
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0
V2_CRITICAL=0
V2_WARNING=0
V2_INFO=0

HAS_AST_GREP=0
if command -v ast-grep >/dev/null 2>&1 && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
  HAS_AST_GREP=1
fi
HAS_CARGO=0
HAS_CLIPPY=0
HAS_FMT=0
HAS_AUDIT=0
HAS_DENY=0
HAS_UDEPS=0
HAS_OUTDATED=0

# Findings recording
FIND_SEV=()
FIND_CNT=()
FIND_TTL=()
FIND_DESC=()
FIND_CAT=()
FIND_SAMPLES=()

add_finding() {
  local severity="$1" count="$2" title="$3" desc="${4:-}" category="${5:-}" samples="${6:-[]}"
  FIND_SEV+=("$severity")
  FIND_CNT+=("$count")
  FIND_TTL+=("$title")
  FIND_DESC+=("$desc")
  FIND_CAT+=("$category")
  FIND_SAMPLES+=("$samples")
}

emit_findings_json() {
  local out="$1"
  {
    echo '{'
    printf '  "meta": {"version":"%s","project_dir":"%s","timestamp":"%s",' \
      "$(json_escape "$VERSION")" "$(json_escape "$PROJECT_DIR")" "$(json_escape "$(now)")"
    local cargo_status="skipped" cargo_reason="$CARGO_SKIP_REASON" i
    if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then cargo_status="ran"; cargo_reason=""; fi
    printf '"cargo_execution":{"status":"%s","reason":"%s","invoked":[' "$cargo_status" "$(json_escape "$cargo_reason")"
    for ((i=0;i<${#CARGO_INVOKED[@]};i++)); do
      [[ $i -gt 0 ]] && printf ','
      printf '"%s"' "$(json_escape "${CARGO_INVOKED[$i]}")"
    done
    printf '],"skipped_categories":['
    for ((i=0;i<${#CARGO_SKIPPED_CATEGORIES[@]};i++)); do
      [[ $i -gt 0 ]] && printf ','
      printf '"%s"' "$(json_escape "${CARGO_SKIPPED_CATEGORIES[$i]}")"
    done
    printf ']}},\n'
    echo '  "summary": {'
    printf '    "files": %s, "critical": %s, "warning": %s, "info": %s\n' \
      "$TOTAL_FILES" "$V2_CRITICAL" "$V2_WARNING" "$V2_INFO"
    echo '  },'
    echo '  "findings": ['
    local first=1 n
    n=${#FIND_SEV[@]}
    for ((i=0;i<n;i++)); do
      [[ $first -eq 0 ]] && echo ','
      first=0
      printf '    {"severity":"%s","count":%s,"category":"%s","title":"%s","description":"%s","samples":%s}' \
        "$(json_escape "${FIND_SEV[$i]}")" "$(printf '%s' "${FIND_CNT[$i]}" | awk 'END{print $0+0}')" \
        "$(json_escape "${FIND_CAT[$i]}")" \
        "$(json_escape "${FIND_TTL[$i]}")" \
        "$(json_escape "${FIND_DESC[$i]}")" \
        "${FIND_SAMPLES[$i]:-[]}"
    done
    echo
    echo '  ]'
    echo '}'
  } > "$out"
}

# Category names
declare -A CATEGORY_NAME=()
CATEGORY_NAME[1]="Ownership & Error Handling"
CATEGORY_NAME[2]="Unsafe & Memory Operations"
CATEGORY_NAME[3]="Concurrency & Async Pitfalls"
CATEGORY_NAME[4]="Numeric & Floating-Point"
CATEGORY_NAME[5]="Collections & Iterators"
CATEGORY_NAME[6]="String & Allocation Smells"
CATEGORY_NAME[7]="Filesystem & Process"
CATEGORY_NAME[8]="Security Findings"
CATEGORY_NAME[9]="Code Quality Markers"
CATEGORY_NAME[10]="Module & Visibility Issues"
CATEGORY_NAME[11]="Tests & Benches Hygiene"
CATEGORY_NAME[12]="Lints & Style (fmt/clippy)"
CATEGORY_NAME[13]="Build Health (check/test)"
CATEGORY_NAME[14]="Dependency Hygiene"
CATEGORY_NAME[15]="API Misuse (Common)"
CATEGORY_NAME[16]="Domain-Specific Heuristics"
CATEGORY_NAME[17]="AST-Grep Rule Pack Findings"
CATEGORY_NAME[18]="Meta Statistics & Inventory"
CATEGORY_NAME[19]="Resource Lifecycle Correlation"
CATEGORY_NAME[20]="Async Locking Across Await"
CATEGORY_NAME[21]="Panic Surfaces & Unwinding"
CATEGORY_NAME[22]="Suspicious Casts & Truncation"
CATEGORY_NAME[23]="Parsing & Validation Robustness"
CATEGORY_NAME[24]="Perf/DoS Hotspots"

list_categories() {
  cat <<'CATS'
1  Ownership & Error Handling
2  Unsafe & Memory Operations
3  Concurrency & Async Pitfalls
4  Numeric & Floating-Point
5  Collections & Iterators
6  String & Allocation Smells
7  Filesystem & Process
8  Security Findings
9  Code Quality Markers
10 Module & Visibility Issues
11 Tests & Benches Hygiene
12 Lints & Style (fmt/clippy)
13 Build Health (check/test)
14 Dependency Hygiene
15 API Misuse (Common)
16 Domain-Specific Heuristics
17 AST-Grep Rule Pack Findings
18 Meta Statistics & Inventory
19 Resource Lifecycle Correlation
20 Async Locking Across Await
21 Panic Surfaces & Unwinding
22 Suspicious Casts & Truncation
23 Parsing & Validation Robustness
24 Perf/DoS Hotspots
CATS
}

if [[ "$LIST_CATEGORIES" -eq 1 ]]; then
  list_categories
  exit 0
fi

if [[ "$LIST_RULES" -eq 1 ]]; then
  if [[ "$HAS_AST_GREP" -eq 0 ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
import tempfile
from ubs_core.rust_rules import generate
with tempfile.TemporaryDirectory() as td:
    m = generate(Path(td))
    for k in sorted(m.keys()):
        print(k)
"
  exit 0
fi

category_enabled() {
  local cat=$1
  if [ -n "$ONLY_CATEGORIES" ]; then
    local -a only_arr
    IFS=',' read -r -a only_arr <<< "$ONLY_CATEGORIES"
    for o in "${only_arr[@]}"; do
      if [ "$o" = "$cat" ]; then return 0; fi
    done
    return 1
  fi
  if [ -n "$SKIP_CATEGORIES" ]; then
    local -a skip_arr
    IFS=',' read -r -a skip_arr <<< "$SKIP_CATEGORIES"
    for s in "${skip_arr[@]}"; do
      if [ "$s" = "$cat" ]; then return 1; fi
    done
    return 0
  fi
  return 0
}

# Cargo helpers
check_cargo() {
  HAS_CARGO=0
  HAS_CLIPPY=0
  HAS_FMT=0
  HAS_AUDIT=0
  HAS_DENY=0
  HAS_UDEPS=0
  HAS_OUTDATED=0

  if [[ "$RUN_CARGO" -eq 0 ]]; then
    return
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    CARGO_SKIP_REASON="cargo not found on PATH"
    return
  fi
  if [[ ! -f "$PROJECT_DIR/Cargo.toml" ]]; then
    CARGO_SKIP_REASON="no Cargo.toml in scan root (targeted or shadow-workspace scan)"
    return
  fi

  HAS_CARGO=1
  if command -v cargo-fmt >/dev/null 2>&1 || command -v rustfmt >/dev/null 2>&1; then HAS_FMT=1; fi
  if command -v cargo-clippy >/dev/null 2>&1; then HAS_CLIPPY=1; fi
  if command -v cargo-audit >/dev/null 2>&1; then HAS_AUDIT=1; fi
  if command -v cargo-deny >/dev/null 2>&1; then HAS_DENY=1; fi
  if command -v cargo-udeps >/dev/null 2>&1; then HAS_UDEPS=1; fi
  if command -v cargo-outdated >/dev/null 2>&1; then HAS_OUTDATED=1; fi
}

run_cargo_subcmd() {
  local name="$1" logfile="$2"; shift 2
  local ec=0
  if [[ "$RUN_CARGO" -eq 0 || "$HAS_CARGO" -eq 0 ]]; then
    : >"$logfile"; echo 0 >"$logfile.ec"; return 0
  fi
  CARGO_INVOKED+=("$name")
  set +e
  trap - ERR
  ( cd "$PROJECT_DIR" && CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}" "$@" ) >"$logfile" 2>&1
  ec=$?
  trap on_err ERR
  set -e
  echo "$ec" >"$logfile.ec"
  return 0
}

cargo_phase_ec() {
  cat "$1.ec" 2>/dev/null || echo 0
}

count_warnings_errors() {
  local file="$1"
  local w e
  w=$(grep -E -c "^warning: |: warning:" "$file" 2>/dev/null || true)
  e=$(grep -E -c "^error: |: error:" "$file" 2>/dev/null || true)
  echo "${w:-0} ${e:-0}"
}

CARGO_UNAVAILABLE=0
CARGO_UNAVAILABLE_MSG=""
V2_SINK=""
_v2_sink_bucket(){
  local severity="$1" count="$2" title="$3" desc="${4:-}" cat_slug="${5:-}" cat_name="${6:-}" rule="${7:-rust.cargo.phase}"
  [[ -n "$V2_SINK" ]] || return 0
  printf '{"rule":"%s","category_id":"rust.%s","path":"","line":1,"col":1,"severity":"%s","message":"%s","suppressed":false,"count":%s,"title":"%s","description":"%s","category_name":"%s"}\n' \
    "$(json_escape "$rule")" "$cat_slug" "$severity" "$(json_escape "$title")" "$count" \
    "$(json_escape "$title")" "$(json_escape "$desc")" "$(json_escape "$cat_name")" >>"$V2_SINK"
}

_v2_add_finding(){
  local severity="$1" count="$2" title="$3" desc="${4:-}" category="${5:-}" samples_json="${6:-[]}"
  add_finding "$severity" "$count" "$title" "$desc" "$category" "$samples_json"
  _v2_sink_bucket "$severity" "$(printf '%s' "$count" | awk 'END{print $0+0}')" "$title" "$desc" \
    "${V2_CARGO_SLUG:-}" "${category:-}" "${V2_CARGO_RULE:-}"
}

_v2_report_cargo_failure() {
  local severity="$1" logfile="$2" category="$3" title="$4"
  local ec last
  ec="$(cargo_phase_ec "$logfile")"
  last="$(grep -v '^[[:space:]]*$' "$logfile" 2>/dev/null | tail -n 1 | cut -c1-200)"
  if [[ "$severity" == "critical" || "$severity" == "warning" ]]; then
    severity="warning"
    if [[ "$CARGO_UNAVAILABLE" -eq 0 ]]; then
      CARGO_UNAVAILABLE=1
      CARGO_UNAVAILABLE_MSG="${title} (exit ${ec}): ${last:-no output captured}"
    fi
    print_finding "info" 1 "Not evaluated: ${title%% could not run*}${title%% failed without diagnostics*}" "cargo returned exit $ec without diagnostics; the result is partial"
    _v2_add_finding "info" 1 "Not evaluated: ${title%% could not run*}${title%% failed without diagnostics*}" "cargo returned exit $ec without diagnostics; the result is partial" "$category"
  fi
  print_finding "$severity" 1 "$title (exit $ec)" "${last:-no output captured}"
  _v2_add_finding "$severity" 1 "$title (exit $ec)" "${last:-no output captured}" "$category"
}

_v2_report_cargo_skipped() {
  local category="$1" what="$2"
  CARGO_SKIPPED_CATEGORIES+=("$category")
  print_finding "info" 1 "Not evaluated: $what" "cargo phases skipped: $CARGO_SKIP_REASON"
  _v2_add_finding "info" 1 "Not evaluated: $what" "cargo phases skipped: $CARGO_SKIP_REASON" "$category"
}

run_v2_cargo_phases(){
  if category_enabled 12; then
    print_header "12. LINTS & STYLE (fmt/clippy)"
    print_category "Runs: cargo fmt -- --check, cargo clippy" \
      "Formatter and lints help maintain consistent style and catch many issues"
    V2_CARGO_SLUG="lints"; V2_CARGO_RULE="rust.lints.phase"
    if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
      local FMT_LOG CLIPPY_LOG
      FMT_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-fmt.XXXXXX)"; CLIPPY_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-clippy.XXXXXX)"; TMP_FILES+=("$FMT_LOG" "$CLIPPY_LOG")
      if [[ "$HAS_FMT" -eq 1 ]]; then
        run_cargo_subcmd "fmt" "$FMT_LOG" cargo fmt -- --check
        local r_ec
        r_ec=$(cargo_phase_ec "$FMT_LOG")
        if [[ "$r_ec" -eq 0 ]]; then
          print_finding "good" "Formatting is clean"
        elif grep -q -E '^Diff in |^[-+]' "$FMT_LOG" 2>/dev/null; then
          print_finding "warning" 1 "Formatting issues (cargo fmt --check failed)" "Run: cargo fmt"
          _v2_add_finding "warning" 1 "Formatting issues (cargo fmt --check failed)" "Run: cargo fmt" "${CATEGORY_NAME[12]}"
        else
          _v2_report_cargo_failure "warning" "$FMT_LOG" "${CATEGORY_NAME[12]}" "cargo fmt --check could not run"
        fi
      else
        print_finding "info" 1 "rustfmt not installed; skipping format check"
        _v2_add_finding "info" 1 "rustfmt not installed; skipping format check" "" "${CATEGORY_NAME[12]}"
      fi
      if [[ "$HAS_CLIPPY" -eq 1 ]]; then
        local -a clippy_args=(clippy)
        [[ "$CARGO_FEATURES_ALL" -eq 1 ]] && clippy_args+=(--all-features)
        [[ "$CARGO_TARGETS_ALL" -eq 1 ]] && clippy_args+=(--all-targets)
        clippy_args+=(-- -D warnings)
        run_cargo_subcmd "clippy" "$CLIPPY_LOG" cargo "${clippy_args[@]}"
        local w_e w e
        w_e=$(count_warnings_errors "$CLIPPY_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
        if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "Clippy errors"; _v2_add_finding "critical" "$e" "Clippy errors" "" "${CATEGORY_NAME[12]}"; fi
        if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Clippy warnings"; _v2_add_finding "warning" "$w" "Clippy warnings" "" "${CATEGORY_NAME[12]}"; fi
        if [[ "$w" -eq 0 && "$e" -eq 0 ]]; then
          if [[ "$(cargo_phase_ec "$CLIPPY_LOG")" -eq 0 ]]; then
            print_finding "good" "No clippy warnings/errors"
          else
            _v2_report_cargo_failure "warning" "$CLIPPY_LOG" "${CATEGORY_NAME[12]}" "cargo clippy could not run"
          fi
        fi
      else
        print_finding "info" 1 "clippy not installed; skipping lint pass"
        _v2_add_finding "info" 1 "clippy not installed; skipping lint pass" "" "${CATEGORY_NAME[12]}"
      fi
    else
      _v2_report_cargo_skipped "${CATEGORY_NAME[12]}" "formatting (cargo fmt --check) and lints (cargo clippy)"
    fi
  fi
  if category_enabled 13; then
    print_header "13. BUILD HEALTH (check/test)"
    print_category "Runs: cargo check, cargo test --no-run" \
      "Ensures the project compiles and tests build"
    V2_CARGO_SLUG="build"; V2_CARGO_RULE="rust.build.phase"
    if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
      local CHECK_LOG TEST_LOG
      CHECK_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-check.XXXXXX)"; TEST_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-test.XXXXXX)"; TMP_FILES+=("$CHECK_LOG" "$TEST_LOG")
      run_cargo_subcmd "check" "$CHECK_LOG" cargo check
      local w_e w e
      w_e=$(count_warnings_errors "$CHECK_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
      if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "cargo check errors"; _v2_add_finding "critical" "$e" "cargo check errors" "" "${CATEGORY_NAME[13]}"; fi
      if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "cargo check warnings"; _v2_add_finding "warning" "$w" "cargo check warnings" "" "${CATEGORY_NAME[13]}"; fi
      if [[ "$w" -eq 0 && "$e" -eq 0 ]]; then
        if [[ "$(cargo_phase_ec "$CHECK_LOG")" -eq 0 ]]; then
          print_finding "good" "cargo check clean"
        else
          _v2_report_cargo_failure "critical" "$CHECK_LOG" "${CATEGORY_NAME[13]}" "cargo check could not run"
        fi
      fi
      run_cargo_subcmd "test-no-run" "$TEST_LOG" cargo test --no-run
      w_e=$(count_warnings_errors "$TEST_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
      if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "Tests failed to build (cargo test --no-run)"; _v2_add_finding "critical" "$e" "Tests failed to build (cargo test --no-run)" "" "${CATEGORY_NAME[13]}"; fi
      if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Test build warnings"; _v2_add_finding "warning" "$w" "Test build warnings" "" "${CATEGORY_NAME[13]}"; fi
      if [[ "$w" -eq 0 && "$e" -eq 0 ]]; then
        if [[ "$(cargo_phase_ec "$TEST_LOG")" -eq 0 ]]; then
          print_finding "good" "Tests build clean"
        else
          _v2_report_cargo_failure "critical" "$TEST_LOG" "${CATEGORY_NAME[13]}" "cargo test --no-run could not run"
        fi
      fi
    else
      _v2_report_cargo_skipped "${CATEGORY_NAME[13]}" "compilation (cargo check) and test build (cargo test --no-run)"
    fi
  fi
  if category_enabled 14; then
    print_header "14. DEPENDENCY HYGIENE"
    print_category "Runs: cargo audit, cargo deny check, cargo udeps, cargo outdated" \
      "Keeps dependencies safe, minimal, and up-to-date"
    V2_CARGO_SLUG="dependencies"; V2_CARGO_RULE="rust.dependencies.phase"
    if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
      if [[ "$HAS_AUDIT" -eq 1 ]]; then
        local AUDIT_LOG
        AUDIT_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-audit.XXXXXX)"; TMP_FILES+=("$AUDIT_LOG"); run_cargo_subcmd "audit" "$AUDIT_LOG" cargo audit
        local audit_vuln
        audit_vuln=$(grep -c -E "Vulnerability|RUSTSEC" "$AUDIT_LOG" 2>/dev/null || true); audit_vuln=${audit_vuln:-0}
        if [[ "$audit_vuln" -gt 0 ]]; then print_finding "critical" "$audit_vuln" "Advisories found by cargo-audit"; _v2_add_finding "critical" "$audit_vuln" "Advisories found by cargo-audit" "" "${CATEGORY_NAME[14]}"
        elif [[ "$(cargo_phase_ec "$AUDIT_LOG")" -ne 0 ]]; then _v2_report_cargo_failure "warning" "$AUDIT_LOG" "${CATEGORY_NAME[14]}" "cargo audit could not run"
        else print_finding "good" "No known advisories (cargo-audit)"; fi
      else
        print_finding "info" 1 "cargo-audit not installed; skipping advisory scan"
        _v2_add_finding "info" 1 "cargo-audit not installed; skipping advisory scan" "" "${CATEGORY_NAME[14]}"
      fi
      if [[ "$HAS_DENY" -eq 1 ]]; then
        local -a DENY_CHECKS=(advisories bans sources)
        if [[ -f "$PROJECT_DIR/deny.toml" || -f "$PROJECT_DIR/.cargo/deny.toml" || -f "$PROJECT_DIR/.deny.toml" ]]; then
          DENY_CHECKS+=(licenses)
        else
          print_finding "info" 1 "cargo-deny licenses check skipped: no deny.toml (cargo-deny allows no license until one is listed there)"
          _v2_add_finding "info" 1 "cargo-deny licenses check skipped: no deny.toml" "" "${CATEGORY_NAME[14]}"
        fi
        local DENY_LOG
        DENY_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-deny.XXXXXX)"; TMP_FILES+=("$DENY_LOG"); run_cargo_subcmd "deny" "$DENY_LOG" cargo deny check "${DENY_CHECKS[@]}"
        local deny_err deny_warn
        deny_err=$(grep -c -E "error\[[^)]+\]|[[:space:]]error:" "$DENY_LOG" 2>/dev/null || true); deny_err=${deny_err:-0}
        deny_warn=$(grep -c -E "[[:space:]]warning:" "$DENY_LOG" 2>/dev/null || true); deny_warn=${deny_warn:-0}
        if [[ "$deny_err" -gt 0 ]]; then print_finding "critical" "$deny_err" "cargo-deny errors"; _v2_add_finding "critical" "$deny_err" "cargo-deny errors" "" "${CATEGORY_NAME[14]}"; fi
        if [[ "$deny_warn" -gt 0 ]]; then print_finding "warning" "$deny_warn" "cargo-deny warnings"; _v2_add_finding "warning" "$deny_warn" "cargo-deny warnings" "" "${CATEGORY_NAME[14]}"; fi
        if [[ "$deny_err" -eq 0 && "$deny_warn" -eq 0 ]]; then
          if [[ "$(cargo_phase_ec "$DENY_LOG")" -eq 0 ]]; then print_finding "good" "cargo-deny clean"
          else _v2_report_cargo_failure "warning" "$DENY_LOG" "${CATEGORY_NAME[14]}" "cargo deny could not run"; fi
        fi
      else
        print_finding "info" 1 "cargo-deny not installed; skipping policy checks"
        _v2_add_finding "info" 1 "cargo-deny not installed; skipping policy checks" "" "${CATEGORY_NAME[14]}"
      fi
      if [[ "$HAS_UDEPS" -eq 1 ]]; then
        local UDEPS_LOG
        UDEPS_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-udeps.XXXXXX)"; TMP_FILES+=("$UDEPS_LOG"); run_cargo_subcmd "udeps" "$UDEPS_LOG" cargo udeps --all-targets
        local udeps_count
        udeps_count=$(grep -c -E "(unused dependency|possibly unused|not used)" "$UDEPS_LOG" 2>/dev/null || true); udeps_count=${udeps_count:-0}
        if [[ "$udeps_count" -gt 0 ]]; then print_finding "info" "$udeps_count" "Unused dependencies (cargo-udeps)"; _v2_add_finding "info" "$udeps_count" "Unused dependencies (cargo-udeps)" "" "${CATEGORY_NAME[14]}"
        elif [[ "$(cargo_phase_ec "$UDEPS_LOG")" -ne 0 ]]; then _v2_report_cargo_failure "info" "$UDEPS_LOG" "${CATEGORY_NAME[14]}" "cargo udeps could not run (needs nightly)"
        else print_finding "good" "No unused dependencies"; fi
      else
        print_finding "info" 1 "cargo-udeps not installed; skipping unused dep scan"
        _v2_add_finding "info" 1 "cargo-udeps not installed; skipping unused dep scan" "" "${CATEGORY_NAME[14]}"
      fi
      if [[ "$HAS_OUTDATED" -eq 1 ]]; then
        local OUT_LOG
        OUT_LOG="$(mktemp 2>/dev/null || mktemp -t ubs-rust-outdated.XXXXXX)"; TMP_FILES+=("$OUT_LOG"); run_cargo_subcmd "outdated" "$OUT_LOG" cargo outdated -R
        local outdated_count
        outdated_count=$(grep -E -c "Minor|Major|Patch" "$OUT_LOG" 2>/dev/null || true); outdated_count=${outdated_count:-0}
        if [[ "$outdated_count" -gt 0 ]]; then print_finding "info" "$outdated_count" "Outdated dependencies (cargo-outdated)"; _v2_add_finding "info" "$outdated_count" "Outdated dependencies (cargo-outdated)" "" "${CATEGORY_NAME[14]}"
        elif [[ "$(cargo_phase_ec "$OUT_LOG")" -ne 0 ]]; then _v2_report_cargo_failure "info" "$OUT_LOG" "${CATEGORY_NAME[14]}" "cargo outdated could not run"
        else print_finding "good" "Dependencies up-to-date"; fi
      else
        print_finding "info" 1 "cargo-outdated not installed; skipping update report"
        _v2_add_finding "info" 1 "cargo-outdated not installed; skipping update report" "" "${CATEGORY_NAME[14]}"
      fi
    else
      _v2_report_cargo_skipped "${CATEGORY_NAME[14]}" "dependency hygiene (cargo audit / deny / udeps / outdated)"
    fi
  fi
}

run_v2_cat_17_18(){
  if category_enabled 17 && [[ "$FORMAT" == "text" ]]; then
    print_header "17. AST-GREP RULE PACK FINDINGS"
    if [[ "$HAS_AST_GREP" -eq 1 ]]; then
      print_finding "info" 0 "AST rule pack staged" "Run with --format=sarif to emit SARIF from the rule pack"
    else
      say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
    fi
  fi
  if category_enabled 18; then
    print_header "18. META STATISTICS & INVENTORY"
    print_category "Detects: crate counts, bin/lib targets, feature flags (Cargo.toml heuristic)" \
      "High-level view of the project layout"
    print_subheader "Cargo.toml features (heuristic count)"
    local cargo_toml="$PROJECT_DIR/Cargo.toml"
    if [[ -f "$cargo_toml" ]]; then
      local feature_count bin_count workspace
      feature_count=$(grep -c "^\[features\]" "$cargo_toml" 2>/dev/null || true)
      bin_count=$(grep -E -c "^\s*\[\[bin\]\]" "$cargo_toml" 2>/dev/null || true)
      workspace=$(grep -c "^\s*\[workspace\]" "$cargo_toml" 2>/dev/null || echo 0)
      say "  ${BLUE}${INFO} Info${RESET} ${WHITE}(features sections:${RESET} ${CYAN}${feature_count}${RESET}${WHITE}, bins:${RESET} ${CYAN}${bin_count}${RESET}${WHITE}, workspace:${RESET} ${CYAN}${workspace}${RESET}${WHITE})${RESET}"
    else
      print_finding "info" 1 "No Cargo.toml at project root (workspace? set PROJECT_DIR accordingly)"
      _v2_add_finding "info" 1 "No Cargo.toml at project root (workspace? set PROJECT_DIR accordingly)" "" "${CATEGORY_NAME[18]}"
    fi
  fi
}

run_v2_recount(){
  python3 - "$1" <<'PYV2COUNT'
import json, sys

counts = {"critical": 0, "warning": 0, "info": 0}
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            sev = rec.get("severity", "info")
            if sev not in counts:
                sev = "info"
            try:
                counts[sev] += int(rec.get("count", 1))
            except (TypeError, ValueError):
                counts[sev] += 1
except OSError:
    pass
print(counts["critical"], counts["warning"], counts["info"])
PYV2COUNT
}

run_v2_summary_text(){
  echo ""
  say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
  say "${BOLD}${CYAN}                    🎯 SCAN COMPLETE 🎯                                  ${RESET}"
  say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
  echo ""
  say "${WHITE}${BOLD}Summary Statistics:${RESET}"
  say "  ${WHITE}Files scanned:${RESET}    ${CYAN}$TOTAL_FILES${RESET}"
  say "  ${RED}${BOLD}Critical issues:${RESET}  ${RED}$V2_CRITICAL${RESET}"
  say "  ${YELLOW}Warning issues:${RESET}   ${YELLOW}$V2_WARNING${RESET}"
  say "  ${BLUE}Info items:${RESET}       ${BLUE}$V2_INFO${RESET}"
  if [[ "$CARGO_UNAVAILABLE" -eq 1 ]]; then
    say "  ${YELLOW}${BOLD}Partial:${RESET} [CARGO_UNAVAILABLE] ${YELLOW}cargo could not run — compilation, tests and lints were not evaluated${RESET}"
    say "  ${DIM}${CARGO_UNAVAILABLE_MSG}${RESET}"
  fi
  echo ""
  say "${BOLD}${WHITE}Priority Actions:${RESET}"
  if [ "$V2_CRITICAL" -gt 0 ]; then
    say "  ${RED}${FIRE} ${BOLD}FIX CRITICAL ISSUES IMMEDIATELY${RESET}"
    say "  ${DIM}These cause crashes, security vulnerabilities, or data corruption${RESET}"
  fi
  if [ "$V2_WARNING" -gt 0 ]; then
    say "  ${YELLOW}${WARN} ${BOLD}Review and fix WARNING items${RESET}"
    say "  ${DIM}These cause bugs, performance issues, or maintenance problems${RESET}"
  fi
  if [ "$V2_INFO" -gt 0 ]; then
    say "  ${BLUE}${INFO} ${BOLD}Consider INFO suggestions${RESET}"
    say "  ${DIM}Code quality improvements and best practices${RESET}"
  fi
  if [ "$V2_CRITICAL" -eq 0 ] && [ "$V2_WARNING" -eq 0 ]; then
    if [ "${#CARGO_SKIPPED_CATEGORIES[@]}" -gt 0 ]; then
      say "\n  ${GREEN}${BOLD}${SPARKLE} No critical or warning issues found by static analysis ${SPARKLE}${RESET}"
      say "  ${YELLOW}${WARN} Not evaluated (cargo phases skipped: ${CARGO_SKIP_REASON}): $(IFS='; '; echo "${CARGO_SKIPPED_CATEGORIES[*]}")${RESET}"
    else
      say "\n  ${GREEN}${BOLD}${SPARKLE} EXCELLENT! No critical or warning issues found ${SPARKLE}${RESET}"
    fi
  fi
  echo ""
  say "${DIM}Scan completed at: $(now)${RESET}"
  if [[ -n "$OUTPUT_FILE" ]]; then
    say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
  fi
  echo ""
  if [ "$VERBOSE" -eq 0 ]; then
    say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
  fi
  say "${DIM}Add to CI: ./ubs --ci --fail-on-warning . > rust-bug-scan.txt${RESET}"
  echo ""
}

run_v2_summary_json(){
  local status_json='"status":"ok"'
  if [[ "$CARGO_UNAVAILABLE" -eq 1 ]]; then
    status_json="$(printf '"status":"partial","module_error":"CARGO_UNAVAILABLE","message":"%s"' \
      "$(json_escape "cargo could not run, so compilation, tests and lints were not evaluated: ${CARGO_UNAVAILABLE_MSG}")")"
  fi
  printf '{"language":"rust","project":"%s","files":%s,"critical":%s,"warning":%s,"info":%s,"timestamp":"%s","format":"json",%s}\n' \
    "$(json_escape "$PROJECT_DIR")" "$TOTAL_FILES" "$V2_CRITICAL" "$V2_WARNING" "$V2_INFO" "$(json_escape "$(now)")" "$status_json"
}

run_v2_legacy_parity_bridges_rust(){
  local sink="$1" text_out="$2"
  if [[ "$FORMAT" == "json" ]]; then
    run_v2_cargo_phases >/dev/null
    run_v2_cat_17_18 >/dev/null
  else
    run_v2_cargo_phases >>"$text_out"
    run_v2_cat_17_18 >>"$text_out"
  fi
  local counts
  counts="$(run_v2_recount "$sink")"
  V2_CRITICAL="$(echo "$counts" | awk '{print $1}')"
  V2_WARNING="$(echo "$counts" | awk '{print $2}')"
  V2_INFO="$(echo "$counts" | awk '{print $3}')"
  if [[ "$FORMAT" == "json" ]]; then
    run_v2_summary_json
  else
    run_v2_summary_text >>"$text_out"
  fi
  local exit_code=0
  if (( V2_CRITICAL >= FAIL_CRITICAL_THRESHOLD )); then exit_code=1; fi
  if (( FAIL_ON_WARNING == 1 )) && (( V2_CRITICAL + V2_WARNING > 0 )); then exit_code=1; fi
  if (( FAIL_WARNING_THRESHOLD > 0 )) && (( V2_WARNING >= FAIL_WARNING_THRESHOLD )); then exit_code=1; fi
  return "$exit_code"
}

run_contract_v2_rust(){
  local helpers_dir="" list_file sink checks text_out="" rule_dir="" exit_code=0 v2_json_out=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-rustv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-rustv2-sink.XXXXXX)"
  checks="$(mktemp 2>/dev/null || mktemp -t ubs-rustv2-checks.XXXXXX)"
  TMP_FILES+=("$list_file" "$sink" "$checks")
  V2_SINK="$sink"

  check_cargo

  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  TOTAL_FILES="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c | awk '{print $1}')"

  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in $(seq 1 24); do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi

  if [[ "$HAS_AST_GREP" -eq 1 && "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-rustv2-rules.XXXXXX)"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.rust_rules import generate
generate(Path('$rule_dir'))
" 2>/dev/null; then
      rule_dir=""
    fi
  fi
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.rust_rules import generate
generate(Path('$DUMP_RULES_DIR'))
" 2>/dev/null || true
    cp -R "$DUMP_RULES_DIR"/rules/. "$DUMP_RULES_DIR"/ 2>/dev/null || true
  fi

  text_out="$(mktemp 2>/dev/null || mktemp -t ubs-rustv2-text.XXXXXX)"
  TMP_FILES+=("$text_out")
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --checks-out "$checks"
    --text-out "$text_out"
    --project-dir "$PROJECT_DIR" --skip "$v2_skip" --detail-limit "$DETAIL_LIMIT")
  [[ -n "$rule_dir" ]] && scan_args+=(--ast-rule-dir "$rule_dir")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  [[ "${EXCLUDE_TESTS:-0}" -eq 1 ]] && scan_args+=(--exclude-tests)
  [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]] && scan_args+=(--skip-type-narrowing)
  [[ "$QUIET" -eq 1 ]] && scan_args+=(--quiet)
  [[ "${JOBS:-0}" -gt 0 ]] && scan_args+=(--jobs "$JOBS")

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-rustv2-json.XXXXXX)"
      TMP_FILES+=("$v2_json_out")
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
  esac

  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.rust_scan \
    "${scan_args[@]}" --version "2.0.1" || exit_code=$?

  if [[ -n "$EMIT_FINDINGS_JSON" ]]; then
    while IFS=$'\t' read -r sev cnt cat ttl desc samples; do
      add_finding "$sev" "$cnt" "$ttl" "$desc" "$cat" "$samples"
    done < <(PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 - "$checks" <<'PYV2FIND'
import json, sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
for f in doc.get("findings", []):
    samples = json.dumps(f.get("samples") or [])
    print("\t".join([
        f.get("severity", "info"), str(f.get("count", 0)),
        f.get("category", ""), f.get("title", ""), f.get("description", ""),
        samples,
    ]))
PYV2FIND
)
  fi

  run_v2_legacy_parity_bridges_rust "$sink" "$text_out" || exit_code=$?

  if [[ "$FORMAT" == "text" ]]; then
    cat "$text_out" 2>/dev/null || true
  elif [[ "$FORMAT" == "sarif" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null || true
    fi
  fi

  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true
  fi
  if [[ -n "$EMIT_FINDINGS_JSON" ]]; then
    emit_findings_json "$EMIT_FINDINGS_JSON"
    say "${GREEN}${CHECK} Findings JSON: ${CYAN}$EMIT_FINDINGS_JSON${RESET}"
  fi
  if [[ -n "$SUMMARY_JSON" ]]; then
    run_v2_summary_json > "$SUMMARY_JSON"
    say "${GREEN}${CHECK} Summary JSON: ${CYAN}$SUMMARY_JSON${RESET}"
  fi

  [[ -n "$rule_dir" ]] && rm -rf -- "$rule_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_rust || v2_status=$?
exit "$v2_status"
