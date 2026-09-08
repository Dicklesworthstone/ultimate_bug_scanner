#!/usr/bin/env bash
# shellcheck disable=SC2002,SC2015,SC2034,SC2317
# ═══════════════════════════════════════════════════════════════════════════
# SWIFT ULTIMATE BUG SCANNER v3.0.1 - Industrial-Grade Swift Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for Swift on contract v2.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-swift.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="50f395a69a0aa2a7ba8814db2f6385ee647167349e23ef04231c4dae43357933"
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
KEEP_TEMP=${UBS_KEEP_TEMP:-0}
TEMP_PATHS=()
cleanup_add() { [[ -n "${1:-}" ]] && TEMP_PATHS+=("$1"); }

cleanup() {
  local ec=$?
  if [[ "${KEEP_TEMP}" -eq 1 ]]; then exit "$ec"; fi
  local p
  for p in "${TEMP_PATHS[@]:-}"; do
    [[ -n "$p" && "$p" != "/" && "$p" != "." ]] && rm -rf -- "$p" 2>/dev/null || true
  done
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
COLOR_MODE="auto"
FORCE_COLOR=0
NO_COLOR_FLAG=0

init_colors() {
  if [[ "$NO_COLOR_FLAG" -eq 1 || "$COLOR_MODE" == "never" || ( "$COLOR_MODE" == "auto" && ( -n "${NO_COLOR:-}" || ! -t 1 ) && "$FORCE_COLOR" -eq 0 ) ]]; then
    USE_COLOR=0
  else
    USE_COLOR=1
  fi
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

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; ROCKET="🚀"
: "$CHECK" "$CROSS" "$WARN" "$INFO" "$ARROW" "$BULLET" "$MAGNIFY" "$BUG" "$FIRE" "$SPARKLE" "$SHIELD" "$ROCKET"
: "$RED" "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$WHITE" "$GRAY" "$BOLD" "$DIM" "$RESET"

say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

print_header() {
  say "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  say "${WHITE}${BOLD}$1${RESET}"
  say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
print_category() { say "\n${MAGENTA}${BOLD}▓▓▓ $1${RESET}\n${DIM}$2${RESET}"; }
print_subheader() { say "\n${YELLOW}${BOLD}$BULLET $1${RESET}"; }

# CLI Parsing & Configuration
VERSION="3.0.1"
SCRIPT_NAME="$(basename "$0")"

PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
LIST_CATEGORIES=0
MAX_FILE_SIZE="${MAX_FILE_SIZE:-25M}"
INCLUDE_EXT="swift,mm,m,metal,plist,xib,storyboard,xcconfig"
QUIET=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
SUMMARY_JSON=""
REPORT_JSON=""
REPORT_MD=""
EMIT_CSV=""
EMIT_HTML=""
TIMEOUT_CMD=""
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"
SDK_KIND="${SDK_KIND:-ios}"
LIST_RULES=0
PROGRESS=0
RESPECT_IGNORE=0
NO_IGNORE_ALL=0
DUMP_RULES_DIR=""
EXPLAIN_RULE_ID=""
BASELINE=""
FILES_FROM=""

CATEGORY_WHITELIST=""
case "${UBS_CATEGORY_FILTER:-}" in
  resource-lifecycle) CATEGORY_WHITELIST="16,19" ;;
esac

csv_contains(){
  local csv="${1:-}" needle="${2:-}"
  needle="${needle//[[:space:]]/}"
  [[ -z "$needle" ]] && return 1
  local IFS=',' item
  for item in $csv; do
    item="${item//[[:space:]]/}"
    [[ -z "$item" ]] && continue
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

csv_add_unique(){
  local csv="${1:-}" add="${2:-}"
  add="${add//[[:space:]]/}"
  [[ -z "$add" ]] && { printf '%s' "$csv"; return 0; }
  if csv_contains "$csv" "$add"; then printf '%s' "$csv"; return 0; fi
  if [[ -z "$csv" ]]; then printf '%s' "$add"; else printf '%s,%s' "$csv" "$add"; fi
}

print_usage() {
  cat >&2 <<USAGE
Usage: $SCRIPT_NAME [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  --list-categories          Print numbered categories and exit
  --list-rules               Print embedded ast-grep rule IDs and exit
  --dump-rules=DIR           Write the merged ast-grep rules to DIR and exit
  --explain-rule=ID          Print YAML for a rule id and exit
  --keep-temp                Keep temporary files (debugging)

  --timeout-seconds=N        Global per-tool timeout budget
  --baseline=FILE            Compare against a previous run's summary JSON
  --max-file-size=SIZE       Limit ripgrep file size (default: $MAX_FILE_SIZE)
  --force-color              Force ANSI even if not TTY
  --color=MODE               always|auto|never (default: auto)
  -v, --verbose              More code samples per finding (DETAIL=10)
  -q, --quiet                Reduce non-essential output
  --format=FMT               Output: text|json|sarif (default: text)
  --ci                       CI mode (UTC timestamps)
  --no-color                 Disable ANSI color
  --include-ext=CSV          File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]        Additional glob(s)/dir(s) to exclude
  --jobs=N                   Parallel jobs for ripgrep (default: auto)
  --skip=CSV                 Skip categories by number (e.g., --skip=2,7,11)
  --only=CSV                 Only run these categories (e.g., --only=1,2,4)
  --fail-on-warning          Exit non-zero on warnings or critical
  --rules=DIR                Additional ast-grep rules dir (merged)
  --summary-json=FILE        Write machine-readable summary JSON
  --report-md=FILE           Write a Markdown summary
  --emit-csv=FILE            Write a CSV of per-category counts
  --emit-html=FILE           Write an HTML summary
  --max-detailed=N           Cap total code samples printed (default: $MAX_DETAILED)
  --sdk=KIND                 ios|macos|tvos|watchos (default: $SDK_KIND)
  --progress                 Show minimal progress dots
  --respect-ignore           Respect ignore files for ripgrep
  --no-ignore                Ignore ALL ignore files for ripgrep
  --version                  Print version and exit
  -h, --help                 Show help

contract: v2
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --format)     FORMAT="${2:-}"; ubs_validate_format "$FORMAT"; shift 2;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --force-color) FORCE_COLOR=1; COLOR_MODE="always"; shift;;
    --color=*)    COLOR_MODE="${1#*=}"; shift;;
    --version)    echo "ubs-swift ${VERSION}"; exit 0;;
    --timeout-seconds=*) TIMEOUT_SECONDS="${1#*=}"; shift;;
    --baseline=*) BASELINE="${1#*=}"; shift;;
    --list-categories) LIST_CATEGORIES=1; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --dump-rules) DUMP_RULES_DIR="${2:-}"; shift 2;;
    --explain-rule=*) EXPLAIN_RULE_ID="${1#*=}"; shift;;
    --keep-temp)  KEEP_TEMP=1; shift;;
    --max-file-size=*) MAX_FILE_SIZE="${1#*=}"; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --emit-csv=*) EMIT_CSV="${1#*=}"; shift;;
    --emit-html=*) EMIT_HTML="${1#*=}"; shift;;
    --max-detailed=*) MAX_DETAILED="${1#*=}"; shift;;
    --sdk=*)      SDK_KIND="${1#*=}"; shift;;
    --progress)   PROGRESS=1; shift;;
    --respect-ignore) RESPECT_IGNORE=1; shift;;
    --no-ignore)  NO_IGNORE_ALL=1; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    --) shift; break;;
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

if [[ "${UBS_PROFILE:-}" == "loose" ]]; then
  SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "11")"
  SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "15")"
  SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "22")"
fi

case "$SDK_KIND" in ios|macos|tvos|watchos) ;; *) SDK_KIND="ios";; esac

if [[ "$LIST_CATEGORIES" -eq 1 ]]; then
  cat <<'CAT'
1 Optionals/Force Ops 2 Concurrency/Task 3 Closures/Captures 4 URLSession
5 Error Handling 6 Security 7 Crypto/Hashing 8 Files & I/O
9 Threading/Main 10 Performance 11 Debug/Prod 12 Regex
13 SwiftUI/Combine 14 Memory/Retain 15 Code Quality 16 Resource Lifecycle
17 Info.plist/ATS 18 Deprecated APIs 19 Build/Signing 20 Packaging/SPM
21 UI Safety 22 Tests Hygiene 23 Localization
CAT
  exit 0
fi

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
init_colors

if [[ -n "${OUTPUT_FILE}" ]]; then
  mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
  if [[ "$FORMAT" == "text" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; else exec > >(tee "${OUTPUT_FILE}"); fi
fi

safe_date() {
  if [[ "$CI_MODE" -eq 1 ]]; then command date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || command date '+%Y-%m-%dT%H:%M:%SZ'; else command date '+%Y-%m-%d %H:%M:%S'; fi
}

HAS_AST_GREP=0
check_ast_grep(){
  if command -v ast-grep >/dev/null 2>&1; then HAS_AST_GREP=1; return 0; fi
  if command -v sg >/dev/null 2>&1; then
    local out=""
    out="$(sg --version 2>&1 || true)"
    if printf '%s\n' "$out" | grep -qi "ast-grep"; then
      HAS_AST_GREP=1; return 0
    fi
  fi
  HAS_AST_GREP=0
  return 1
}
check_ast_grep || true

list_generated_ast_rule_ids() {
  local rules_dir="$1"
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$rules_dir"/rules/*.yml "$rules_dir"/*.yml 2>/dev/null || true ) | sort -u
}

explain_generated_ast_rule() {
  local rules_dir="$1"
  local rule_id="$2"
  local f id
  shopt -s nullglob
  for f in "$rules_dir"/rules/*.yml "$rules_dir"/*.yml; do
    id="$(awk '/^id:[[:space:]]*/{print $2; exit}' "$f" 2>/dev/null || true)"
    if [[ "$id" == "$rule_id" ]]; then
      cat "$f"
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob
  return 1
}

if [[ "$LIST_RULES" -eq 1 || -n "$EXPLAIN_RULE_ID" ]]; then
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  ast_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-sw-rules.XXXXXX)"
  cleanup_add "$ast_dir"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.swift_rules import generate
generate(Path('$ast_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true

  if [[ "$LIST_RULES" -eq 1 ]]; then
    list_generated_ast_rule_ids "$ast_dir"
    exit 0
  fi
  if [[ -n "$EXPLAIN_RULE_ID" ]]; then
    if explain_generated_ast_rule "$ast_dir" "$EXPLAIN_RULE_ID"; then
      exit 0
    fi
    echo "ERROR: unknown Swift ast-grep rule id: $EXPLAIN_RULE_ID" >&2
    exit 1
  fi
fi

resolve_timeout(){
  if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout"; return 0; fi
  if command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout"; return 0; fi
  TIMEOUT_CMD=""
}
with_timeout(){
  if [[ -n "$TIMEOUT_CMD" && "${TIMEOUT_SECONDS:-0}" -gt 0 ]]; then "$TIMEOUT_CMD" "$TIMEOUT_SECONDS" "$@"; else "$@"; fi
}

OPT_CRIT=0
OPT_WARN=0
OPT_INFO=0
opt_push_counts(){
  if [[ "${UBS_INCLUDE_OPTIONALS_IN_TOTALS:-0}" -ne 1 ]]; then return 0; fi
  local sev="$1" cnt="$2"
  case "$sev" in
    critical) OPT_CRIT=$((OPT_CRIT + cnt));;
    warning)  OPT_WARN=$((OPT_WARN + cnt));;
    info)     OPT_INFO=$((OPT_INFO + cnt));;
  esac
}

run_swiftlint(){
  print_subheader "SwiftLint"
  if command -v swiftlint >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t ubs_swiftlint.XXXXXX)"
    cleanup_add "$tmp"
    if [[ -d "$PROJECT_DIR" ]]; then
      (cd "$PROJECT_DIR" && with_timeout swiftlint --reporter json --strict >"$tmp" 2>/dev/null || true)
    else
      (cd "$(dirname "$PROJECT_DIR")" && with_timeout swiftlint --reporter json --strict "$(basename "$PROJECT_DIR")" >"$tmp" 2>/dev/null || true)
    fi
    if [[ -s "$tmp" ]] && command -v python3 >/dev/null 2>&1; then
      local errs warns files
      read -r errs warns files <<<"$(python3 - "$tmp" <<'PY'
import json, sys
try:
  arr=json.load(open(sys.argv[1],'r',encoding='utf-8'))
except: print("0 0 0"); sys.exit(0)
e=w=0; files=set()
for it in arr:
  lvl=(it.get("severity") or "").lower()
  files.add(it.get("file") or "?")
  if lvl in ("error","serious"): e+=1
  elif lvl in ("warning",): w+=1
print(f"{e} {w} {len(files)}")
PY
)"
      if [[ "${warns:-0}" -gt 0 || "${errs:-0}" -gt 0 ]]; then
        say " ${YELLOW}${WARN} SwiftLint suggestions:${RESET} ${WHITE}errors=${errs} warnings=${warns}${RESET}"
        opt_push_counts warning "$((warns))"
        opt_push_counts critical "$((errs))"
      else
        say " ${GREEN}${CHECK} No SwiftLint findings${RESET}"
      fi
    fi
  else
    say " ${GRAY}${INFO} SwiftLint not installed${RESET}"
  fi
}

run_swiftformat(){
  print_subheader "SwiftFormat (lint mode)"
  if command -v swiftformat >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t ubs_swiftformat.XXXXXX)"
    cleanup_add "$tmp"
    with_timeout swiftformat "$PROJECT_DIR" --lint --quiet >"$tmp" 2>/dev/null || true
    local c; c=$(wc -l <"$tmp" | awk '{print $1+0}')
    if [[ "$c" -gt 0 ]]; then
      say " ${YELLOW}${WARN} SwiftFormat suggestions:${RESET} ${WHITE}${c}${RESET}"
      opt_push_counts info "$c"
    else
      say " ${GREEN}${CHECK} No SwiftFormat findings${RESET}"
    fi
  else
    say " ${GRAY}${INFO} SwiftFormat not installed${RESET}"
  fi
}

run_periphery(){
  print_subheader "Periphery (dead code)"
  if command -v periphery >/dev/null 2>&1; then
    local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t ubs_periphery.XXXXXX)"
    cleanup_add "$tmp"
    if [[ -d "$PROJECT_DIR" ]]; then
      (cd "$PROJECT_DIR" && with_timeout periphery scan --quiet >"$tmp" 2>/dev/null || true)
    else
      say " ${GRAY}${INFO} Periphery skipped (requires directory scan)${RESET}"
      return 0
    fi
    local unused; unused=$(grep -cE 'unused' "$tmp" 2>/dev/null || echo 0)
    if [[ "$unused" -gt 0 ]]; then
      say " ${YELLOW}${WARN} Periphery unused symbols:${RESET} ${WHITE}${unused}${RESET}"
      opt_push_counts info "$unused"
    else
      say " ${GREEN}${CHECK} No obvious dead code reported${RESET}"
    fi
  else
    say " ${GRAY}${INFO} Periphery not installed${RESET}"
  fi
}

run_xcodebuild_analyze(){
  print_subheader "xcodebuild analyze (Clang static analyzer)"
  local xcw xcp SCHEME=""
  xcw=$(find "$PROJECT_DIR" -maxdepth 6 -name "*.xcworkspace" 2>/dev/null | head -n1 || true)
  xcp=$(find "$PROJECT_DIR" -maxdepth 6 -name "*.xcodeproj" 2>/dev/null | head -n1 || true)
  local sdkflag=""
  case "$SDK_KIND" in
    ios) sdkflag="-sdk iphonesimulator" ;;
    macos) sdkflag="-sdk macosx" ;;
    tvos) sdkflag="-sdk appletvsimulator" ;;
    watchos) sdkflag="-sdk watchsimulator" ;;
  esac
  if command -v xcodebuild >/dev/null 2>&1; then
    if [[ -n "$xcw" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        SCHEME=$(xcodebuild -list -json -workspace "$xcw" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); s=(d.get("workspace",{}) or {}).get("schemes") or []; print(s[0] if s else "")' 2>/dev/null || true)
      fi
      [[ -z "$SCHEME" ]] && SCHEME="$(basename "$xcw" .xcworkspace)"
      local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t ubs_xc_analyze.XXXXXX)"
      cleanup_add "$tmp"
      with_timeout xcodebuild -workspace "$xcw" -scheme "$SCHEME" analyze $sdkflag >"$tmp" 2>&1 || true
      local w e; w=$(grep -c "warning:" "$tmp" 2>/dev/null || true); e=$(grep -c "error:" "$tmp" 2>/dev/null || true)
      if [[ "$w" -gt 0 || "$e" -gt 0 ]]; then
        say " ${YELLOW}${WARN} Analyzer:${RESET} ${WHITE}${w}${RESET} warnings, ${RED}${e}${RESET} errors"
        opt_push_counts warning "$w"; opt_push_counts critical "$e"
      else
        say " ${GREEN}${CHECK} No analyzer issues surfaced${RESET}"
      fi
    elif [[ -n "$xcp" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        SCHEME=$(xcodebuild -list -json -project "$xcp" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); s=(d.get("project",{}) or {}).get("schemes") or []; print(s[0] if s else "")' 2>/dev/null || true)
      fi
      [[ -z "$SCHEME" ]] && SCHEME="$(basename "$xcp" .xcodeproj)"
      local tmp; tmp="$(mktemp 2>/dev/null || mktemp -t ubs_xc_analyze.XXXXXX)"
      cleanup_add "$tmp"
      with_timeout xcodebuild -project "$xcp" -scheme "$SCHEME" analyze $sdkflag >"$tmp" 2>&1 || true
      local w e; w=$(grep -c "warning:" "$tmp" 2>/dev/null || true); e=$(grep -c "error:" "$tmp" 2>/dev/null || true)
      if [[ "$w" -gt 0 || "$e" -gt 0 ]]; then
        say " ${YELLOW}${WARN} Analyzer:${RESET} ${WHITE}${w}${RESET} warnings, ${RED}${e}${RESET} errors"
        opt_push_counts warning "$w"; opt_push_counts critical "$e"
      else
        say " ${GREEN}${CHECK} No analyzer issues surfaced${RESET}"
      fi
    fi
  else
    say " ${GRAY}${INFO} xcodebuild not installed${RESET}"
  fi
}

run_contract_v2_swift(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-swv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-swv2-sink.XXXXXX)"
  cleanup_add "$list_file" "$sink"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ ! -e "$PROJECT_DIR" ]]; then
    echo -e "${RED}${BOLD}Project path not found:${RESET} ${WHITE}$PROJECT_DIR${RESET}" >&2
    return 2
  fi
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  local v2_skip="$SKIP_CATEGORIES" c allowed w
  local -a _wl
  if [[ -n "$ONLY_CATEGORIES" || -n "$CATEGORY_WHITELIST" ]]; then
    local keep="" source_csv="${ONLY_CATEGORIES:-$CATEGORY_WHITELIST}"
    IFS=',' read -r -a _wl <<<"$(echo "$source_csv" | tr -d ' ')"
    for c in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]] && scan_args+=(--skip-type-narrowing)
  [[ "${VERBOSE:-0}" -eq 1 ]] && scan_args+=(--detail-limit 10)

  local ast_rule_dir="" ast_available=0
  if check_ast_grep && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    ast_available=1
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-swv2-rules.XXXXXX)"
    cleanup_add "$ast_rule_dir"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.swift_rules import generate
generate(Path('$ast_rule_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
      ast_rule_dir=""
    fi
  fi
  [[ "$ast_available" -eq 1 ]] && scan_args+=(--ast-available)
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  if [[ -n "$DUMP_RULES_DIR" && -n "$ast_rule_dir" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    cp -R "$ast_rule_dir"/* "$DUMP_RULES_DIR"/ 2>/dev/null || true
  fi

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-swv2-json.XXXXXX)"
      cleanup_add "$v2_json_out"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-swv2-text.XXXXXX)"
      cleanup_add "$text_out"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 swift path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac

  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.swift_scan \
    "${scan_args[@]}" --max-detailed "$MAX_DETAILED" --version "$VERSION" || exit_code=$?

  if [[ -n "$text_out" && "$FORMAT" == "text" ]]; then
    cat "$text_out" 2>/dev/null || true
  fi

  if [[ "$FORMAT" == "text" ]]; then
    print_header "OPTIONAL ANALYZERS (if installed)"
    resolve_timeout || true
    run_swiftlint
    run_swiftformat
    run_periphery
    run_xcodebuild_analyze
  fi

  local crit warn infos
  read -r crit warn infos <<<"$(PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import json, sys
counts = {'critical': 0, 'warning': 0, 'info': 0}
try:
    with open(sys.argv[1], encoding='utf-8') as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            sev = rec.get('severity', 'info')
            if sev in counts:
                counts[sev] += int(rec.get('count', 1) or 0)
except OSError:
    pass
print(counts['critical'], counts['warning'], counts['info'])
" "$sink" 2>/dev/null)" || true
  crit=$(( ${crit:-0} + OPT_CRIT ))
  warn=$(( ${warn:-0} + OPT_WARN ))
  infos=$(( ${infos:-0} + OPT_INFO ))

  local files_n
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"

  if [[ "$FORMAT" == "text" ]]; then
    echo ""
    say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
    say "${BOLD}${CYAN} 🎯 SCAN COMPLETE 🎯 ${RESET}"
    say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
    echo ""
    say "${WHITE}${BOLD}Summary Statistics:${RESET}"
    say "  ${WHITE}Files scanned:${RESET}    ${CYAN}$files_n${RESET}"
    say "  ${RED}${BOLD}Critical issues:${RESET}  ${RED}$crit${RESET}"
    say "  ${YELLOW}Warning issues:${RESET}   ${YELLOW}$warn${RESET}"
    say "  ${BLUE}Info items:${RESET}       ${BLUE}$infos${RESET}"
    echo ""
    say "${BOLD}${WHITE}Priority Actions:${RESET}"
    if [[ "$crit" -gt 0 ]]; then
      say "  ${RED}${FIRE} ${BOLD}FIX CRITICAL ISSUES IMMEDIATELY${RESET}"
      say "  ${DIM}These cause crashes, security vulnerabilities, or deadlocks${RESET}"
    fi
    if [[ "$warn" -gt 0 ]]; then
      say "  ${YELLOW}${WARN} ${BOLD}Review and fix WARNING items${RESET}"
      say "  ${DIM}These cause bugs, performance issues, or maintenance problems${RESET}"
    fi
    if [[ "$infos" -gt 0 ]]; then
      say "  ${BLUE}${INFO} ${BOLD}Consider INFO suggestions${RESET}"
      say "  ${DIM}Code quality improvements and best practices${RESET}"
    fi
  elif [[ "$FORMAT" == "json" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      cat "$v2_json_out"
    fi
  elif [[ "$FORMAT" == "sarif" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null || true
    fi
  fi

  if [[ -n "${REPORT_JSON:-}" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true
  fi
  if [[ -n "${SUMMARY_JSON:-}" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      cp "$v2_json_out" "$SUMMARY_JSON" 2>/dev/null || true
    else
      printf '{"language":"swift","status":"ok","version":"%s","project":"%s","files":%s,"critical":%s,"warning":%s,"info":%s,"timestamp":"%s"}\n' \
        "$(json_escape "$VERSION")" "$(json_escape "$PROJECT_DIR")" "$files_n" "$crit" "$warn" "$infos" "$(json_escape "$(safe_date)")" > "$SUMMARY_JSON"
    fi
  fi

  if [[ -n "${EMIT_CSV:-}" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 - "$sink" > "$EMIT_CSV" 2>/dev/null <<'PYCSV' || true
import json, sys
cat_counts = {i: {"critical": 0, "warning": 0, "info": 0} for i in range(1, 24)}
try:
    with open(sys.argv[1], encoding='utf-8') as fh:
        for line in fh:
            if not line.strip(): continue
            try: rec = json.loads(line)
            except: continue
            cat = rec.get("category")
            if isinstance(cat, int) and 1 <= cat <= 23:
                sev = rec.get("severity", "info")
                if sev not in ("critical", "warning", "info"): sev = "info"
                cat_counts[cat][sev] += int(rec.get("count", 1) or 0)
except: pass
print("category,total,critical,warning,info")
for i in range(1, 24):
    c = cat_counts[i]
    tot = c["critical"] + c["warning"] + c["info"]
    print(f"{i},{tot},{c['critical']},{c['warning']},{c['info']}")
PYCSV
  fi

  if [[ -n "${EMIT_HTML:-}" ]]; then
    cat > "$EMIT_HTML" <<HTML
<!doctype html><meta charset='utf-8'><title>UBS Swift Report</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial} table{border-collapse:collapse} td,th{padding:.4rem .6rem;border:1px solid #ddd} .ok{color:#2a7} .warn{color:#c80} .crit{color:#c22}</style>
<h1>UBS Swift Report</h1>
<p><strong>Project:</strong> $(printf %s "$PROJECT_DIR" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')</p>
<p><strong>Files:</strong> $files_n</p>
<p><strong>Timestamp:</strong> $(safe_date)</p>
<h2>Totals</h2>
<table><tr><th>Critical</th><th>Warning</th><th>Info</th></tr>
<tr><td class='crit'>$crit</td><td class='warn'>$warn</td><td class='ok'>$infos</td></tr></table>
HTML
  fi

  exit_code=0
  if [[ "$crit" -gt 0 ]]; then exit_code=1; fi
  if [[ "$FAIL_ON_WARNING" -eq 1 && $((crit + warn)) -gt 0 ]]; then exit_code=1; fi
  return "$exit_code"
}

v2_status=0
run_contract_v2_swift || v2_status=$?
exit "$v2_status"
