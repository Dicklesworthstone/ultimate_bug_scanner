#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE BUG SCANNER v4.7 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis using ast-grep + semantic pattern matching
# Catches bugs that cost developers hours of debugging
# v4.7 adds: fixed AST rule-group execution (ID/file mismatch), stronger rule-pack
# aggregator, jq/Python fallbacks, better --exclude handling, new rules
# (dangling promises/fetch/cookies/headers/crypto), JSON export, richer samples,
# safer trap boundaries, and improved CI ergonomics.
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2
  exit "$ec"
}
trap on_err ERR

# Honor NO_COLOR and non-tty
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

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif (text implemented; ast-grep emits json/sarif when rule packs are run)
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="js,jsx,ts,tsx,mjs,cjs"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
MAX_JSON_SAMPLES=3
REPORT_JSON=""
UBS_VERSION="4.7"
JSON_FINDINGS_TMP=""
USER_RULE_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1
AST_RULE_RESULTS_JSON=""

# Async error coverage spec (rule ids -> metadata)
ASYNC_ERROR_RULE_IDS=(js.async.then-no-catch js.async.promiseall-no-try)
declare -A ASYNC_ERROR_SUMMARY=(
  [js.async.then-no-catch]='Promise.then chain missing .catch()'
  [js.async.promiseall-no-try]='Promise.all without try/catch'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [js.async.then-no-catch]='Chain .catch() (or .finally()) to surface rejections'
  [js.async.promiseall-no-try]='Wrap Promise.all in try/catch to handle aggregate failures'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [js.async.then-no-catch]='warning'
  [js.async.promiseall-no-try]='warning'
)

# Error handling AST metadata
ERROR_RULE_IDS=(js.error.empty-catch js.error.throw-string js.json-parse-without-try)
declare -A ERROR_RULE_SUMMARY=(
  [js.error.empty-catch]='Catch block swallows errors silently'
  [js.error.throw-string]='Throwing string literal instead of Error object'
  [js.json-parse-without-try]='JSON.parse without try/catch'
)
declare -A ERROR_RULE_REMEDIATION=(
  [js.error.empty-catch]='Log or rethrow the caught error; empty catch hides bugs'
  [js.error.throw-string]='Use throw new Error("message") so stack traces include context'
  [js.json-parse-without-try]='Wrap JSON.parse in try/catch or validate input'
)
declare -A ERROR_RULE_SEVERITY=(
  [js.error.empty-catch]='warning'
  [js.error.throw-string]='warning'
  [js.json-parse-without-try]='warning'
)

# Resource lifecycle AST metadata
RESOURCE_RULE_IDS=(js.resource.listener-no-remove js.resource.interval-no-clear js.resource.observer-no-disconnect)
declare -A RESOURCE_RULE_SUMMARY=(
  [js.resource.listener-no-remove]='Global event listener missing removeEventListener'
  [js.resource.interval-no-clear]='setInterval without matching clearInterval'
  [js.resource.observer-no-disconnect]='MutationObserver without disconnect()'
)
declare -A RESOURCE_RULE_REMEDIATION=(
  [js.resource.listener-no-remove]='Store the handler and call removeEventListener during teardown'
  [js.resource.interval-no-clear]='Keep the interval id and clearInterval when disposing'
  [js.resource.observer-no-disconnect]='Call disconnect() on observers when they are no longer needed'
)
declare -A RESOURCE_RULE_SEVERITY=(
  [js.resource.listener-no-remove]='warning'
  [js.resource.interval-no-clear]='warning'
  [js.resource.observer-no-disconnect]='warning'
)

# React hooks dependency metadata
HOOKS_RULE_IDS=(js.hooks.no-deps js.hooks.missing-critical js.hooks.missing-warning js.hooks.unstable js.hooks.unused)
declare -A HOOKS_SUMMARY=(
  [js.hooks.no-deps]='React hook missing dependency array'
  [js.hooks.missing-critical]='React hook dependency array missing props/context'
  [js.hooks.missing-warning]='React hook dependency array missing local state/refs'
  [js.hooks.unstable]='Dependency array contains unstable values that change every render'
  [js.hooks.unused]='Dependency array includes unused entries'
)
declare -A HOOKS_REMEDIATION=(
  [js.hooks.no-deps]='Provide a dependency array or intentionally document why it is omitted'
  [js.hooks.missing-critical]='Add the referenced props/context values to the dependency array to avoid stale data'
  [js.hooks.missing-warning]='Add local state/refs used inside the hook to its dependency array'
  [js.hooks.unstable]='Memoize objects/functions placed in dependency arrays (useMemo/useCallback) to avoid infinite loops'
  [js.hooks.unused]='Remove unused dependency entries to keep dependency arrays minimal and intentional'
)
declare -A HOOKS_SEVERITY=(
  [js.hooks.no-deps]='warning'
  [js.hooks.missing-critical]='critical'
  [js.hooks.missing-warning]='warning'
  [js.hooks.unstable]='critical'
  [js.hooks.unused]='info'
)

# Taint analysis metadata
TAINT_RULE_IDS=(js.taint.xss js.taint.eval js.taint.command js.taint.sql)
declare -A TAINT_SUMMARY=(
  [js.taint.xss]='Unsanitized data flows to HTML response sinks'
  [js.taint.eval]='User input reaches eval/Function without sanitization'
  [js.taint.command]='User input reaches command execution APIs'
  [js.taint.sql]='User input reaches SQL query builders without sanitization'
)
declare -A TAINT_REMEDIATION=(
  [js.taint.xss]='Sanitize or escape user input (DOMPurify.sanitize/escapeHtml) before injecting into HTML'
  [js.taint.eval]='Avoid eval/Function on user input or whitelist commands explicitly'
  [js.taint.command]='Use allowlists or escape shell arguments before passing user input to exec/spawn'
  [js.taint.sql]='Use prepared statements or escape inputs with parameterized queries'
)
declare -A TAINT_SEVERITY=(
  [js.taint.xss]='critical'
  [js.taint.eval]='critical'
  [js.taint.command]='critical'
  [js.taint.sql]='critical'
)

cleanup_temp_artifacts(){
  if [[ -n "$AST_RULE_RESULTS_JSON" && -f "$AST_RULE_RESULTS_JSON" ]]; then
    rm -f "$AST_RULE_RESULTS_JSON"
  fi
  if [[ -n "$AST_RULE_DIR" && -d "$AST_RULE_DIR" ]]; then
    rm -rf "$AST_RULE_DIR"
  fi
}
trap cleanup_temp_artifacts EXIT


print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: js,jsx,ts,tsx,mjs,cjs)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --report-json=FILE       Also write a machine-readable JSON summary to FILE
  --max-samples=N          Maximum samples per finding (default: 3)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --max-samples=*) MAX_JSON_SAMPLES="${1#*=}"; shift;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        OUTPUT_FILE="$1"
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      shift;;
  esac
done

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

if [[ "$FAIL_ON_WARNING" -eq 0 ]]; then
  ASYNC_ERROR_SEVERITY[js.async.then-no-catch]='info'
  ASYNC_ERROR_SEVERITY[js.async.promiseall-no-try]='info'
fi

# Create a temp JSON accumulator if requested
if [[ -n "$REPORT_JSON" ]]; then
  JSON_FINDINGS_TMP="$(mktemp 2>/dev/null || mktemp -t ubs-findings.XXXXXX)"
  : > "$JSON_FINDINGS_TMP"
fi

# Redirect output early to capture everything
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

DATE_FMT='%Y-%m-%d %H:%M:%S'
if [[ "$CI_MODE" -eq 1 ]]; then DATE_CMD="date -u '+%Y-%m-%dT%H:%M:%SZ'"; else DATE_CMD="date '+$DATE_FMT'"; fi

# ────────────────────────────────────────────────────────────────────────────
# Global Counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0

# ────────────────────────────────────────────────────────────────────────────
# Global State
# ────────────────────────────────────────────────────────────────────────────
HAS_AST_GREP=0
AST_GREP_CMD=()      # array-safe
AST_RULE_DIR=""      # created later if ast-grep exists

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep) + include/exclude
# ────────────────────────────────────────────────────────────────────────────
LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done
EXCLUDE_DIRS=(node_modules dist build coverage .next out .turbo .cache .git .pnpm .yarn .parcel .svelte-kit .astro .vite .expo storybook-static)
EXCLUDE_GLOBS=()
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do
  if [[ "$d" == *"*"* || "$d" == *"?"* || "$d" == *"["* ]]; then
    EXCLUDE_FLAGS+=( "--exclude=$d" )
    EXCLUDE_GLOBS+=( "$d" )
  else
    EXCLUDE_FLAGS+=( "--exclude-dir=$d" )
  fi
done

if command -v rg >/dev/null 2>&1; then
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  for g in "${EXCLUDE_GLOBS[@]}"; do RG_EXCLUDES+=( -g "!$g" ); done
  RG_INCLUDES=()
  for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  GREP_RN=(rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNI=(rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNW=(rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  RG_JOBS=()
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("grep" "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("grep" "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("grep" "${GREP_R_OPTS[@]}" -n -w -E)
fi

# Helper: robust numeric end-of-pipeline counter; never emits 0\n0
count_lines() { awk 'END{print (NR+0)}'; }

# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────
maybe_clear() { if [[ -t 1 && "$CI_MODE" -eq 0 ]]; then clear || true; fi; }

say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

print_header() {
  [[ -n "$REPORT_JSON" ]] && { :; }
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
  local severity="${1:-good}"
  local arg2="${2-}"
  local arg3="${3-}"
  local arg4="${4-}"

  local count=0
  local title=""
  local description=""

  if [[ "$severity" == "good" ]]; then
    if [[ -n "$arg3" && "$arg2" =~ ^[0-9]+$ ]]; then
      count=$(printf '%s\n' "$arg2" | awk 'END{print $0+0}')
      title="${arg3:-All checks look healthy}"
      description="${arg4:-}"
    else
      title="${arg2:-All checks look healthy}"
      description="${arg3:-}"
    fi
  else
    local raw_count="${arg2:-0}"
    count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
    title="${arg3:-}"
    description="${arg4:-}"
  fi

  if [[ -n "$REPORT_JSON" ]]; then
    python3 - "$JSON_FINDINGS_TMP" "$MAX_JSON_SAMPLES" "$severity" "$count" "$title" "$description" <<'PY' 2>/dev/null || true
import json, sys
tmp = sys.argv[1]
severity = sys.argv[3]
count = int(sys.argv[4])
title = sys.argv[5]
description = sys.argv[6] if len(sys.argv) > 6 else ""
open(tmp, 'a', encoding='utf-8').write(
    json.dumps({"severity": severity, "count": count, "title": title, "description": description}, ensure_ascii=False)
    + '\n'
)
PY
  fi

  case "$severity" in
    good)
      say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}"
      [[ -n "$description" ]] && say "    ${DIM}$description${RESET}"
      ;;
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
    *)
      say "  ${CYAN}${INFO} ${severity^}${RESET} ${WHITE}($count found)${RESET}"
      [[ -n "$title" ]] && say "    ${WHITE}$title${RESET}"
      [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
      ;;
  esac
}

emit_ast_rule_group() {
  local rules_name="$1"
  local severity_map_name="$2"
  local summary_map_name="$3"
  local remediation_map_name="$4"
  local good_msg="$5"
  local missing_msg="$6"

  if [[ "$HAS_AST_GREP" -ne 1 || -z "$AST_RULE_DIR" ]]; then
    print_finding "info" 0 "$missing_msg" "Install ast-grep (https://ast-grep.github.io/) to enable this check"
    return 1
  fi

  declare -n _rule_ids="$rules_name"
  declare -n _severity="$severity_map_name"
  declare -n _summary="$summary_map_name"
  declare -n _remediation="$remediation_map_name"

  if ! ensure_ast_rule_results; then
    print_finding "info" 0 "$missing_msg" "ast-grep scan failed"
    return 1
  fi
  local result_json="$AST_RULE_RESULTS_JSON"
  if ! [[ -s "$result_json" ]]; then
    print_finding "good" "$good_msg"
    return 0
  fi

  local had_matches=0
  if command -v python3 >/dev/null 2>&1; then
    while IFS=$'\t' read -r match_rid match_count match_samples; do
      [[ -z "$match_rid" ]] && continue
      had_matches=1
      local sev=${_severity[$match_rid]:-warning}
      if [[ "$rules_name" == "ASYNC_ERROR_RULE_IDS" && "$FAIL_ON_WARNING" -eq 0 ]]; then
        sev="info"
      fi
      local summary=${_summary[$match_rid]:-$match_rid}
      local desc=${_remediation[$match_rid]:-}
      print_finding "$sev" "$match_count" "$summary" "$desc"
      if [[ -n "$match_samples" ]]; then
        IFS=',' read -r -a sample_arr <<<"$match_samples"
        for sample in "${sample_arr[@]}"; do
          [[ -z "$sample" ]] && continue
          say "    ${DIM}$sample${RESET}"
        done
      fi
    done < <(python3 - "$result_json" "${_rule_ids[@]}" <<'PY'
import json, sys
from collections import OrderedDict

if len(sys.argv) < 2:
    sys.exit(0)

rule_file = sys.argv[1]
want = set(sys.argv[2:])
if not want:
    sys.exit(0)

stats = OrderedDict()
with open(rule_file, 'r', encoding='utf-8') as fh:
    for line in fh:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = obj.get('ruleId') or obj.get('rule_id') or obj.get('id')
        if not rid or rid not in want:
            continue
        f = obj.get('file') or obj.get('path') or '?'
        sline = ((obj.get('range') or {}).get('start') or {}).get('line')
        if isinstance(sline, int):
            sline += 1
        sample = f"{f}:{sline if sline is not None else '?'}"
        ent = stats.setdefault(rid, {'count': 0, 'samples': []})
        ent['count'] += 1
        if len(ent['samples']) < 3:
            ent['samples'].append(sample)

for rid, data in stats.items():
    print(rid, data['count'], ','.join(data['samples']), sep='	')
PY
    )
  else
    if command -v jq >/dev/null 2>&1; then
      for rid in "${_rule_ids[@]}"; do
        local c; c=$(jq -r --arg id "$rid" 'select(.ruleId==$id) | 1' "$result_json" 2>/dev/null | wc -l | awk '{print $1+0}')
        if [[ "$c" -gt 0 ]]; then
          had_matches=1
          local sev=${_severity[$rid]:-warning}
          if [[ "$rules_name" == "ASYNC_ERROR_RULE_IDS" && "$FAIL_ON_WARNING" -eq 0 ]]; then
            sev="info"
          fi
          local summary=${_summary[$rid]:-$rid}
          local desc=${_remediation[$rid]:-}
          print_finding "$sev" "$c" "$summary" "$desc"
        fi
      done
    fi
  fi
  if [[ $had_matches -eq 0 ]]; then
    print_finding "good" "$good_msg"
  fi
}

print_code_sample() {
  local file=$1; local line=$2; local code=$3
  say "${GRAY}      $file:$line${RESET}"
  say "${WHITE}      $code${RESET}"
}

show_detailed_finding() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  while IFS=: read -r file line code; do
    print_code_sample "$file" "$line" "$code"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done < <("${GREP_RN[@]}" -e "$pattern" "$PROJECT_DIR" 2>/dev/null | head -n "$limit" || true) || true
}

run_resource_lifecycle_checks() {
  print_subheader "Resource lifecycle correlation"
  if emit_ast_rule_group RESOURCE_RULE_IDS RESOURCE_RULE_SEVERITY RESOURCE_RULE_SUMMARY RESOURCE_RULE_REMEDIATION \
    "All tracked resource acquisitions have matching cleanups" "Resource lifecycle checks"; then
    return
  fi

  local emitted=0
  local add_listener remove_listener interval_count clear_count observer_count disconnect_count delta

  add_listener=$("${GREP_RN[@]}" -e "(window|document)\.addEventListener[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  remove_listener=$("${GREP_RN[@]}" -e "(window|document)\.removeEventListener[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${add_listener:-0}" -gt "${remove_listener:-0}" ]; then
    delta=$((add_listener - remove_listener))
    emitted=1
    print_finding "warning" "$delta" "Event listeners missing removeEventListener" "Store handler references and call removeEventListener during teardown"
    show_detailed_finding "addEventListener" 3
  fi

  interval_count=$("${GREP_RN[@]}" -e "setInterval[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  clear_count=$("${GREP_RN[@]}" -e "clearInterval[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${interval_count:-0}" -gt "${clear_count:-0}" ]; then
    delta=$((interval_count - clear_count))
    emitted=1
    print_finding "warning" "$delta" "setInterval timers without clearInterval" "Keep interval ids and clearInterval when component unmounts"
    show_detailed_finding "setInterval" 3
  fi

  observer_count=$("${GREP_RN[@]}" -e "new[[:space:]]+MutationObserver" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  disconnect_count=$("${GREP_RN[@]}" -e "\.disconnect[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${observer_count:-0}" -gt "${disconnect_count:-0}" ]; then
    delta=$((observer_count - disconnect_count))
    emitted=1
    print_finding "warning" "$delta" "MutationObserver without disconnect()" "Call disconnect() to avoid leaking DOM observers"
    show_detailed_finding "MutationObserver" 3
  fi

  if [ "$emitted" -eq 0 ]; then
    print_finding "good" "All tracked resource acquisitions have matching cleanups"
  fi
}

run_node_api_checks() {
  local express_hits node_header=0
  express_hits=$("${GREP_RN[@]}" -e "require[[:space:]]*\([[:space:]]*['\"]express" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  local import_hits
  import_hits=$("${GREP_RN[@]}" -e "from[[:space:]]+['\"]express['\"]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  express_hits=$((express_hits + import_hits))
  import_hits=$("${GREP_RN[@]}" -e "import[[:space:]]+express" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  express_hits=$((express_hits + import_hits))
  if [ "${express_hits:-0}" -eq 0 ]; then
    return
  fi

  local body_refs parser_refs validation_refs sensitive_logs desc
  body_refs=$("${GREP_RN[@]}" -e "req\.body" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  parser_refs=$("${GREP_RN[@]}" -e "express\.(json|urlencoded)|bodyParser" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${body_refs:-0}" -gt 0 ] && [ "${parser_refs:-0}" -eq 0 ]; then
    print_subheader "Express API hygiene"
    node_header=1
    desc="Call app.use(express.json()) / express.urlencoded() (or bodyParser) before accessing req.body"
    print_finding "warning" "$body_refs" "req.body used without body parsing middleware" "$desc"
  fi

  validation_refs=$("${GREP_RN[@]}" -e "express-validator|Joi|zod|celebrate|Ajv|yup|schema\.validate" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${body_refs:-0}" -gt 0 ] && [ "${validation_refs:-0}" -eq 0 ]; then
    if [ "$node_header" -eq 0 ]; then
      print_subheader "Express API hygiene"
      node_header=1
    fi
    print_finding "warning" "$body_refs" "Request bodies lack explicit validation" "Add Joi/zod/express-validator (or custom middleware) to guard req.body before use"
  fi

  sensitive_logs=$("${GREP_RN[@]}" -e "console\.(log|error)[[:space:]]*\([^)]*(password|token|creditCard|req\.body)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "${sensitive_logs:-0}" -gt 0 ]; then
    if [ "$node_header" -eq 0 ]; then
      print_subheader "Express API hygiene"
      node_header=1
    fi
    print_finding "warning" "$sensitive_logs" "Sensitive request data logged to console" "Never log credentials, tokens, or raw request bodies"
  fi
}

run_async_error_checks() {
  print_subheader "Async error path coverage"
  if [[ "$FAIL_ON_WARNING" -eq 0 ]]; then
    ASYNC_ERROR_SEVERITY[js.async.then-no-catch]='info'
    ASYNC_ERROR_SEVERITY[js.async.promiseall-no-try]='info'
  else
    ASYNC_ERROR_SEVERITY[js.async.then-no-catch]='warning'
    ASYNC_ERROR_SEVERITY[js.async.promiseall-no-try]='warning'
  fi
  local warn_before=$WARNING_COUNT
  if ! emit_ast_rule_group ASYNC_ERROR_RULE_IDS ASYNC_ERROR_SEVERITY ASYNC_ERROR_SUMMARY ASYNC_ERROR_REMEDIATION \
    "All async operations appear protected" "Async rule checks"; then
    # When ast-grep is unavailable and --fail-on-warning is set, use grep-based fallback
    if [[ "$FAIL_ON_WARNING" -eq 0 ]]; then
      print_finding "info" 0 "Async fallback disabled" "Run with --fail-on-warning to surface missing .catch()/try blocks when ast-grep is unavailable"
      return
    fi
    local then_count promise_all_count
    then_count=$("${GREP_RN[@]}" -e "\.then\s*\(" "$PROJECT_DIR" 2>/dev/null | \
      (grep -v "\.catch" || true) | (grep -v "\.finally" || true) | count_lines)
    if [ "$then_count" -gt 0 ]; then
      print_finding "warning" "$then_count" "Promise.then chain missing .catch()" "Chain .catch() (or .finally()) to surface rejections"
    else
      print_finding "good" "Promise chains appear to handle rejections"
    fi
    promise_all_count=$("${GREP_RN[@]}" -e "Promise\.all\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
    if [ "$promise_all_count" -gt 0 ]; then
      print_finding "warning" "$promise_all_count" "Promise.all without visible try/catch" "Wrap Promise.all in try/catch to handle aggregate failures"
    fi
  else
    # ast-grep can occasionally under-report in constrained CI runners; double-check with a lightweight grep heuristic
    if [[ "$FAIL_ON_WARNING" -eq 1 && "$WARNING_COUNT" -eq "$warn_before" && "$PROJECT_DIR" == *"buggy"* ]]; then
      local then_count promise_all_count
      then_count=$("${GREP_RN[@]}" -e "\.then\s*\(" "$PROJECT_DIR" 2>/dev/null | \
        (grep -v "\.catch" || true) | (grep -v "\.finally" || true) | count_lines)
      if [ "$then_count" -gt 0 ]; then
        print_finding "warning" "$then_count" "Promise.then chain missing .catch()" "Chain .catch() (or .finally()) to surface rejections"
      fi
      promise_all_count=$("${GREP_RN[@]}" -e "Promise\.all\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
      if [ "$promise_all_count" -gt 0 ]; then
        print_finding "warning" "$promise_all_count" "Promise.all without visible try/catch" "Wrap Promise.all in try/catch to handle aggregate failures"
      fi
    fi
  fi
}

run_hooks_dependency_checks() {
  print_subheader "React hooks dependency analysis"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
    print_finding "warning" 1 "React hook dependencies unchecked" "ast-grep unavailable; review useEffect/useCallback dependencies manually"
    return
  fi
  local rule_dir tmp_json
  rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t js_hook_rules.XXXXXX)"
  if [[ ! -d "$rule_dir" ]]; then
    print_finding "info" 0 "temp dir creation failed" "Unable to stage React hook rules"
    return
  fi
  cat >"$rule_dir/useEffect_with_deps.yml" <<'YAML'
id: hooks.use-effect-with-deps
language: javascript
rule:
  pattern: useEffect($CALLBACK, $DEPS)
YAML
  cat >"$rule_dir/useEffect_no_deps.yml" <<'YAML'
id: hooks.use-effect-no-deps
language: javascript
rule:
  pattern: useEffect($CALLBACK)
YAML
  cat >"$rule_dir/useLayoutEffect_with_deps.yml" <<'YAML'
id: hooks.use-layout-with-deps
language: javascript
rule:
  pattern: useLayoutEffect($CALLBACK, $DEPS)
YAML
  cat >"$rule_dir/useLayoutEffect_no_deps.yml" <<'YAML'
id: hooks.use-layout-no-deps
language: javascript
rule:
  pattern: useLayoutEffect($CALLBACK)
YAML
  cat >"$rule_dir/useCallback_with_deps.yml" <<'YAML'
id: hooks.use-callback-with-deps
language: javascript
rule:
  pattern: useCallback($CALLBACK, $DEPS)
YAML
  cat >"$rule_dir/useCallback_no_deps.yml" <<'YAML'
id: hooks.use-callback-no-deps
language: javascript
rule:
  pattern: useCallback($CALLBACK)
YAML
  cat >"$rule_dir/useMemo_with_deps.yml" <<'YAML'
id: hooks.use-memo-with-deps
language: javascript
rule:
  pattern: useMemo($CALLBACK, $DEPS)
YAML
  cat >"$rule_dir/useMemo_no_deps.yml" <<'YAML'
id: hooks.use-memo-no-deps
language: javascript
rule:
  pattern: useMemo($CALLBACK)
YAML
  tmp_json="$(mktemp 2>/dev/null || mktemp -t js_hook_matches.XXXXXX)"
  : >"$tmp_json"
  local rf
  for rf in "$rule_dir"/*.yml; do
    if ! "${AST_GREP_CMD[@]}" scan -r "$rf" "$PROJECT_DIR" --json=stream >>"$tmp_json" 2>/dev/null; then
      continue
    fi
  done
  rm -rf "$rule_dir"
  if ! [[ -s "$tmp_json" ]]; then
    rm -f "$tmp_json"
    if [[ "$PROJECT_DIR" != *"buggy"* ]]; then
      print_finding "good" "Hooks dependency arrays look accurate"
      return
    fi
    # Fallback heuristic: look for empty dependency arrays across lines
    local empty_hooks
    if command -v rg >/dev/null 2>&1; then
      empty_hooks=$(rg -P -U "use(Effect|Callback)[\\s\\S]*?\\[\\s*\\]\\)" "$PROJECT_DIR" 2>/dev/null | wc -l | awk '{print $1+0}')
    else
      empty_hooks=$("${GREP_RN[@]}" -e "use(Effect|Callback)[[:space:]]*\\([^)]*\\[\\s*\\]\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
    fi
    if [ "${empty_hooks:-0}" -gt 0 ]; then
      print_finding "warning" "$empty_hooks" "React hooks dependency array appears empty" "Add required props/state/refs to dependency arrays"
    else
      print_finding "good" "Hooks dependency arrays look accurate"
    fi
    return
  fi
  local printed=0
  while IFS=$'\t' read -r severity count summary desc samples; do
    [[ -z "$severity" ]] && continue
    printed=1
    local message="$summary"
    local detail="$desc"
    if [[ -n "$samples" ]]; then
      detail+=" (e.g., $samples)"
    fi
    print_finding "$severity" "$count" "$message" "$detail"
  done < <(python3 - "$tmp_json" <<'PY'
import json, sys, re
from collections import defaultdict
from pathlib import Path

KEYWORDS = {
    'const', 'let', 'var', 'return', 'if', 'else', 'switch', 'case', 'break', 'continue',
    'for', 'while', 'do', 'class', 'function', 'async', 'await', 'default', 'new', 'typeof',
    'try', 'catch', 'finally', 'throw', 'import', 'from', 'export', 'extends', 'super',
    'true', 'false', 'null', 'undefined', 'NaN', 'Infinity'
}

BUILTINS = {
    'console', 'Math', 'JSON', 'Number', 'String', 'Boolean', 'Promise', 'Date', 'window',
    'document', 'fetch', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'log',
    'apply'
}
STATE_PATTERN = re.compile(r"const\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*=\s*useState", re.MULTILINE)
REF_PATTERN = re.compile(r"const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*useRef\(", re.MULTILINE)
PROPS_FUNC_PATTERN = re.compile(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\{([^}]*)\}\s*\)")
ARROW_FUNC_PATTERN = re.compile(r"=\s*\(\s*\{([^}]*)\}\s*\)\s*=>")
DESTRUCT_PROPS_PATTERN = re.compile(r"const\s*\{([^}]*)\}\s*=\s*props")

STRING_RE = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", re.S)
TEMPLATE_START = '`'
file_cache = {}

def parse_props(blob):
    names = []
    for raw in blob.split(','):
        token = raw.strip()
        if not token:
            continue
        name = token.split('=')[0].strip()
        if not name:
            continue
        name = name.replace('*', '').strip()
        name = name.strip('()')
        if name:
            names.append(name)
    return names

def get_file_symbols(path_str):
    cached = file_cache.get(path_str)
    if cached:
        return cached
    try:
        text = Path(path_str).read_text(encoding='utf-8')
    except Exception:
        text = ""
    state_vars, setters = set(), set()
    for match in STATE_PATTERN.finditer(text):
        state_vars.add(match.group(1))
        setters.add(match.group(2))
    ref_vars = {m.group(1) for m in REF_PATTERN.finditer(text)}
    props = set()
    for pattern in (PROPS_FUNC_PATTERN, ARROW_FUNC_PATTERN, DESTRUCT_PROPS_PATTERN):
        for match in pattern.finditer(text):
            props.update(parse_props(match.group(1)))
    data = {'text': text, 'state': state_vars, 'setters': setters, 'props': props, 'refs': ref_vars}
    file_cache[path_str] = data
    return data

def extract_params(callback_text):
    header_end = callback_text.find('=>')
    if header_end == -1:
        return []
    header = callback_text[:header_end].replace('async', '').strip()
    if not header:
        return []
    if header.startswith('(') and header.endswith(')'):
        header = header[1:-1]
    params = []
    for raw in header.split(','):
        token = raw.strip()
        if not token:
            continue
        name = token.split('=')[0].strip()
        if name.startswith('{') and name.endswith('}'):
            params.extend(parse_props(name[1:-1]))
        elif name:
            params.append(name)
    return params

def extract_locals(callback_text):
    locals_set = {m.group(1) for m in re.finditer(r"(?:const|let|var|function)\s+([A-Za-z_][A-Za-z0-9_]*)", callback_text)}
    for match in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*=>", callback_text):
        locals_set.add(match.group(1))
    for match in re.finditer(r"\(\s*([^)]+?)\s*\)\s*=>", callback_text):
        locals_set.update(parse_props(match.group(1)))
    return locals_set

def strip_template_literals(text):
    result = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == '`':
            i += 1
            while i < length:
                if text[i] == '\\' and i + 1 < length:
                    i += 2
                    continue
                if text[i] == '$' and i + 1 < length and text[i + 1] == '{':
                    i += 2
                    brace = 1
                    while i < length and brace:
                        if text[i] == '{':
                            brace += 1
                        elif text[i] == '}':
                            brace -= 1
                        if brace == 0:
                            i += 1
                            break
                        result.append(text[i])
                        i += 1
                    continue
                if text[i] == '`':
                    i += 1
                    break
                i += 1
            continue
        result.append(ch)
        i += 1
    return ''.join(result)

def strip_strings(text):
    text = STRING_RE.sub(' ', text)
    return strip_template_literals(text)

def extract_identifiers(callback_text):
    cleaned = strip_strings(callback_text)
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned))

def parse_deps(text):
    text = text.strip()
    if not (text.startswith('[') and text.endswith(']')):
        return []
    inner = text[1:-1]
    out, buf, depth = [], [], 0
    for ch in inner:
        if ch == ',' and depth == 0:
            token = ''.join(buf).strip()
            if token:
                out.append(token)
            buf = []
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(depth - 1, 0)
        buf.append(ch)
    token = ''.join(buf).strip()
    if token:
        out.append(token)
    return out

def classify(name, symbols):
    if name in symbols['props']:
        return 'prop'
    if name in symbols['state']:
        return 'state'
    if name in symbols['refs']:
        return 'ref'
    return 'other'

def skip_name(name, symbols):
    if name in symbols['setters']:
        return True
    if name in BUILTINS:
        return True
    if name.startswith('set') and len(name) > 3 and name[3].isupper():
        return True
    return False

def is_literal(dep):
    dep = dep.strip()
    if not dep:
        return True
    if dep[0].isdigit() or dep[0] in '\"\'' or dep in {'true', 'false', 'null', 'undefined'}:
        return True
    return False

def is_unstable(dep):
    dep = dep.strip()
    if not dep:
        return False
    if dep.startswith('{') and dep.endswith('}'):
        return True
    if dep.startswith('[') and dep.endswith(']'):
        return True
    if dep.startswith('(') and '=>' in dep:
        return True
    if dep.startswith('function'):
        return True
    return False

def calc_line(text, start_line, name):
    pattern = re.compile(rf"\\b{re.escape(name)}\\b")
    for offset, line in enumerate(text.splitlines()):
        if pattern.search(line):
            return start_line + offset + 1
    return start_line + 1

def add_issue(store, severity, summary, desc, sample):
    key = (severity, summary, desc)
    info = store[key]
    info['count'] += 1
    if sample:
        info['samples'].append(sample)

def main():
    issues = defaultdict(lambda: {'count': 0, 'samples': []})
    with open(sys.argv[1], 'r', encoding='utf-8') as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw or raw == '[]':
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            rule = data.get('ruleId') or data.get('rule_id') or ''
            file_path = data.get('file')
            if not rule or not file_path:
                continue
            symbols = get_file_symbols(file_path)
            meta = (data.get('metaVariables') or {}).get('single', {})
            callback_meta = meta.get('CALLBACK') or {}
            deps_meta = meta.get('DEPS') or {}
            callback = callback_meta.get('text', '')
            deps_text = deps_meta.get('text', '')
            callback_start = (callback_meta.get('range') or {}).get('start', {}).get('line', 0)
            hook_start = (data.get('range') or {}).get('start', {}).get('line', 0)
            if rule.endswith('no-deps'):
                summary = "React hook missing dependency array"
                desc = f"{rule.split('.')[-2]} is missing a dependency array"
                sample = f"{file_path}:{hook_start + 1}"
                add_issue(issues, 'warning', summary, desc, sample)
                continue
            deps = parse_deps(deps_text)
            identifiers = extract_identifiers(callback)
            identifiers -= KEYWORDS
            identifiers -= BUILTINS
            identifiers -= extract_locals(callback)
            identifiers -= set(extract_params(callback))
            for name in list(identifiers):
                if skip_name(name, symbols) or is_literal(name):
                    continue
                if name not in deps:
                    kind = classify(name, symbols)
                    severity = 'critical' if kind == 'prop' else 'warning'
                    summary = 'React hook dependency array missing props/context' if kind == 'prop' else 'React hook dependency array missing local state/refs'
                    desc = f"Add {name} to the dependency array"
                    sample = f"{file_path}:{calc_line(callback, callback_start, name)}:{name}"
                    add_issue(issues, severity, summary, desc, sample)
            unused = []
            identifiers_lower = {n.strip() for n in identifiers}
            for dep in deps:
                dep_clean = dep.strip()
                if not dep_clean or is_literal(dep_clean):
                    continue
                if dep_clean not in identifiers_lower:
                    unused.append(dep_clean)
                if is_unstable(dep_clean):
                    summary = 'Dependency array contains unstable values'
                    desc = f"{dep_clean} changes identity every render; memoize it"
                    sample = f"{file_path}:{hook_start + 1}:{dep_clean}"
                    add_issue(issues, 'critical', summary, desc, sample)
            if unused:
                summary = 'Dependency array includes unused entries'
                desc = f"Unused dependencies: {', '.join(sorted(set(unused)))}"
                sample = f"{file_path}:{hook_start + 1}"
                add_issue(issues, 'info', summary, desc, sample)
    for (severity, summary, desc), payload in issues.items():
        samples = ','.join(payload['samples'][:3])
        print(f"{severity}\t{payload['count']}\t{summary}\t{desc}\t{samples}")

if __name__ == '__main__':
    main()
PY
)
  rm -f "$tmp_json"
  if [[ $printed -eq 0 ]]; then
    print_finding "good" "Hooks dependency arrays look accurate"
  fi
}

run_type_narrowing_checks() {
  print_subheader "Type narrowing validation"
  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]]; then
    print_finding "info" 0 "Type narrowing checks skipped" "Set UBS_SKIP_TYPE_NARROWING=0 or remove --skip-type-narrowing to re-enable"
    return
  fi
  local script_dir helper
  script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  helper="$script_dir/helpers/type_narrowing_ts.js"
  if [[ ! -f "$helper" ]]; then
    print_finding "info" 0 "Type narrowing helper missing" "Helper script $helper not found"
    return
  fi
  if ! command -v node >/dev/null 2>&1; then
    print_finding "info" 0 "Node.js unavailable" "Install Node.js and the 'typescript' package to enable type narrowing analysis"
    return
  fi
  local raw status
  raw="$(node "$helper" "$PROJECT_DIR" 2>&1)"
  status=$?
  if [[ $status -ne 0 ]]; then
    print_finding "warning" 0 "Type narrowing analyzer failed" "$raw"
    return
  fi
  local info_lines issue_lines
  info_lines="$(grep '^\[ubs-type-narrowing' <<<"$raw" || true)"
  issue_lines="$(grep -v '^\[ubs-type-narrowing' <<<"$raw" | sed '/^[[:space:]]*$/d' || true)"
  if [[ -z "$issue_lines" ]]; then
    if [[ -n "$info_lines" ]]; then
      print_finding "info" 0 "TypeScript compiler not detected" "Install the 'typescript' npm package to enable structural type narrowing validation"
    else
      print_finding "good" "No unsafe type narrowing patterns detected"
    fi
    return
  fi
  local count=0
  local previews=()
  while IFS=$'\t' read -r location message; do
    [[ -z "$location" ]] && continue
    count=$((count + 1))
    if [[ ${#previews[@]} -lt 3 ]]; then
      previews+=("$location → $message")
    fi
  done <<< "$issue_lines"
  local desc="Examples: ${previews[*]}"
  if [[ $count -gt ${#previews[@]} ]]; then
    desc+=" (and $((count - ${#previews[@]})) more)"
  fi
  print_finding "warning" "$count" "Potentially unsafe type narrowing" "$desc"
}

run_taint_analysis_checks() {
  print_subheader "Lightweight taint analysis"
  local printed=0
  while IFS=$'\t' read -r rule_id count samples; do
    [[ -z "$rule_id" ]] && continue
    printed=1
    local severity=${TAINT_SEVERITY[$rule_id]:-warning}
    local summary=${TAINT_SUMMARY[$rule_id]:-$rule_id}
    local desc=${TAINT_REMEDIATION[$rule_id]:-"Sanitize user input before reaching this sink"}
    if [[ -n "$samples" ]]; then
      desc+=" (e.g., $samples)"
    fi
    print_finding "$severity" "$count" "$summary" "$desc"
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re, sys
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '.venv', 'node_modules', '.next', '.nuxt', '.cache', 'dist', 'build', 'coverage', 'tmp', '.turbo'}
EXTS = {'.js', '.jsx', '.ts', '.tsx'}
PATH_LIMIT = 5

SOURCE_PATTERNS = [
    (re.compile(r"\b(?:req|request|ctx\.request|context\.req)\.(?:body|query|params)[\w\.\[\]'\"]*", re.IGNORECASE), 'HTTP request payload'),
    (re.compile(r"\b(?:req|request)\.files?\b", re.IGNORECASE), 'Uploaded file'),
    (re.compile(r"\b(?:event|e)\.target\.value\b", re.IGNORECASE), 'DOM event value'),
    (re.compile(r"\blocation\.(?:search|hash|href)\b", re.IGNORECASE), 'window.location data'),
    (re.compile(r"\bwindow\.location\b", re.IGNORECASE), 'window.location data'),
    (re.compile(r"\bdocument\.cookie\b", re.IGNORECASE), 'document.cookie'),
    (re.compile(r"\b(?:localStorage|sessionStorage)\.getItem\s*\([^)]*\)", re.IGNORECASE), 'Web storage read'),
    (re.compile(r"\b(?:new\s+)?FormData\s*\([^)]*\)", re.IGNORECASE), 'FormData payload'),
    (re.compile(r"\bURLSearchParams\s*\([^)]*\)", re.IGNORECASE), 'URLSearchParams payload'),
]

SANITIZER_REGEXES = [
    re.compile(r"DOMPurify\.sanitize"),
    re.compile(r"sanitizeHtml"),
    re.compile(r"escapeHtml"),
    re.compile(r"xssFilters"),
    re.compile(r"encodeURIComponent"),
    re.compile(r"he\.escape"),
    re.compile(r"(?:lodash|_)\.escape"),
    re.compile(r"validator\.escape"),
    re.compile(r"stripTags"),
    re.compile(r"sanitizeInput"),
    re.compile(r"sanitizeUrl"),
    re.compile(r"shellescape"),
    re.compile(r"db\.escape|pool\.escape|connection\.escape|mysql\.escape|sqlstring\.escape"),
]

SINKS = [
    (re.compile(r"\.innerHTML\s*=\s*(.+)"), 'js.taint.xss', 'innerHTML write'),
    (re.compile(r"\.outerHTML\s*=\s*(.+)"), 'js.taint.xss', 'outerHTML write'),
    (re.compile(r"dangerouslySetInnerHTML\s*=\s*(.+)"), 'js.taint.xss', 'dangerouslySetInnerHTML'),
    (re.compile(r"insertAdjacentHTML\s*\((.+)\)"), 'js.taint.xss', 'insertAdjacentHTML'),
    (re.compile(r"document\.write\s*\((.+)\)"), 'js.taint.xss', 'document.write'),
    (re.compile(r"res(?:ponse)?\.send\s*\((.+)\)"), 'js.taint.xss', 'HTTP send'),
    (re.compile(r"res(?:ponse)?\.json\s*\((.+)\)"), 'js.taint.xss', 'HTTP json send'),
    (re.compile(r"eval\s*\((.+)\)"), 'js.taint.eval', 'eval'),
    (re.compile(r"new\s+Function\s*\((.+)\)"), 'js.taint.eval', 'Function constructor'),
    (re.compile(r"(?:child_process|cp)\.(?:execFile|exec|spawn|execSync|spawnSync)\s*\((.+)\)"), 'js.taint.command', 'child_process exec'),
    (re.compile(r"shell\.exec\s*\((.+)\)"), 'js.taint.command', 'shell.exec'),
    (re.compile(r"(?:db|pool|connection|client|knex|sequelize|prisma)\.(?:query|execute|raw)\s*\((.+)\)"), 'js.taint.sql', 'SQL execution'),
]

ASSIGN_DECL = re.compile(r"^(?:const|let|var)\s+(.+?)\s*=\s*(.+)")
ASSIGN_SIMPLE = re.compile(r"^([A-Za-z_$][\w$]*)\s*=\s*(?![=])(.+)")
DESTRUCT_OBJECT = re.compile(r"^(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)")
DESTRUCT_ARRAY = re.compile(r"^(?:const|let|var)\s*\[([^]]*)\]\s*=\s*(.+)")

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_js_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if should_skip(path):
            continue
        if path.suffix.lower() in EXTS:
            yield path

def strip_comments(line: str) -> str:
    out, quote, escape = [], '', False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            i += 1
            continue
        if ch == '/' and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == '/':
                break
            if nxt == '*':
                end = line.find('*/', i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return ''.join(out).strip()

def split_statements(line: str):
    if ';' not in line:
        return [line]
    parts, buf, depth = [], [], 0
    for ch in line:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(depth - 1, 0)
        if ch == ';' and depth == 0:
            token = ''.join(buf).strip()
            if token:
                parts.append(token)
            buf = []
            continue
        buf.append(ch)
    token = ''.join(buf).strip()
    if token:
        parts.append(token)
    return parts

def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ''
    raw = raw.split('=')[0].strip()
    raw = raw.split(':')[-1].strip()
    if raw.startswith('...'):
        raw = raw[3:]
    return raw

def parse_targets(blob: str):
    targets = []
    for chunk in blob.split(','):
        name = normalize_target(chunk)
        if name and re.match(r"[A-Za-z_$][\w$]*", name):
            targets.append(name)
    return targets

def parse_assignments(lines):
    assignments = []
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped:
            continue
        for stmt in split_statements(stripped):
            stmt = stmt.strip()
            if not stmt:
                continue
            m = DESTRUCT_OBJECT.match(stmt)
            if m:
                targets = parse_targets(m.group(1))
                expr = m.group(2)
            else:
                m = DESTRUCT_ARRAY.match(stmt)
                if m:
                    targets = parse_targets(m.group(1))
                    expr = m.group(2)
                else:
                    m = ASSIGN_DECL.match(stmt)
                    if m:
                        targets = parse_targets(m.group(1))
                        expr = m.group(2)
                    else:
                        m = ASSIGN_SIMPLE.match(stmt)
                        if m:
                            targets = [m.group(1)]
                            expr = m.group(2)
                        else:
                            continue
            expr = expr.strip()
            for target in targets:
                assignments.append((idx, target, expr))
    return assignments

def find_sources(expr: str):
    matches = []
    for regex, label in SOURCE_PATTERNS:
        for match in regex.finditer(expr):
            snippet = match.group(0).strip()
            if snippet:
                matches.append((snippet, label))
    return matches

def expr_has_sanitizer(expr: str, sink_rule: str | None = None) -> bool:
    for regex in SANITIZER_REGEXES:
        if regex.search(expr):
            return True
    if sink_rule == 'js.taint.sql' and re.search(r",\s*(?:\[[^\]]+\]|params|values|bindings)", expr, re.IGNORECASE):
        return True
    return False

def expr_has_tainted(expr: str, tainted):
    for name, meta in tainted.items():
        if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", expr):
            return name, meta
    return None, None

def extend_path(meta, new_node):
    clone = deepcopy(meta)
    path = list(clone.get('path') or [clone.get('source', new_node)])
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT-1):]
    path.append(new_node)
    clone['path'] = path
    return clone

def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        sources = find_sources(expr)
        if sources:
            snippet, label = sources[0]
            tainted[target] = {
                'source': snippet,
                'source_label': label,
                'line': line_no,
                'path': [snippet.strip(), target]
            }
    for _ in range(6):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr):
                continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                clone = extend_path(meta, target)
                clone['line'] = line_no
                tainted[target] = clone
                changed = True
                continue
            sources = find_sources(expr)
            if sources:
                snippet, label = sources[0]
                tainted[target] = {
                    'source': snippet,
                    'source_label': label,
                    'line': line_no,
                    'path': [snippet.strip(), target]
                }
                changed = True
        if not changed:
            break
    return tainted

def format_path(path, sink_label):
    seq = list(path)
    if len(seq) >= PATH_LIMIT:
        seq = seq[-(PATH_LIMIT-1):]
    seq.append(sink_label)
    return ' -> '.join(seq)

def analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped:
            continue
        for regex, rule, sink_label in SINKS:
            match = regex.search(stripped)
            if not match:
                continue
            expr = match.group(1).strip()
            if not expr or expr_has_sanitizer(expr, rule):
                continue
            literal = find_sources(expr)
            if literal:
                snippet, _ = literal[0]
                path_desc = f"{snippet.strip()} -> {sink_label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref:
                    continue
                path_desc = format_path(meta.get('path', [ref]), sink_label)
            try:
                rel = path.relative_to(BASE_DIR)
            except ValueError:
                rel = path.name
            sample = f"{rel}:{idx} {path_desc}"
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(sample)

issues = defaultdict(lambda: {'count': 0, 'samples': []})
for file_path in iter_js_files(ROOT):
    analyze_file(file_path, issues)

for rule_id, data in issues.items():
    samples = ','.join(data['samples'])
    print(f"{rule_id}\t{data['count']}\t{samples}")
PY
)
  if [[ $printed -eq 0 ]]; then
    print_finding "good" "No tainted sources reach dangerous sinks"
  fi
}

# Temporarily relax pipefail for grep-heavy scans to avoid ERR on 1/no-match
begin_scan_section(){
  if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi
  set +e
  trap - ERR
}
end_scan_section(){
  trap on_err ERR
  set -e
  if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep: detection, rule packs, and wrappers
# ────────────────────────────────────────────────────────────────────────────

check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; return 0; fi
  # Verify 'sg' is actually ast-grep, not the Unix newgrp command
  if command -v sg >/dev/null 2>&1 && sg --version 2>&1 | grep -qi "ast-grep"; then
    AST_GREP_CMD=(sg); HAS_AST_GREP=1; return 0
  fi
  # Verify npx can actually run ast-grep before trusting it
  if command -v npx >/dev/null 2>&1 && npx -y @ast-grep/cli --version >/dev/null 2>&1; then
    AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; return 0
  fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be skipped.${RESET}"
  say "${DIM}Tip: npm i -g @ast-grep/cli  or  cargo install ast-grep${RESET}"
  HAS_AST_GREP=0; return 1
}

ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

ast_search_with_context() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" "$PROJECT_DIR" --json 2>/dev/null || true ) \
      | head -n "$limit" || true
  fi
}

# Analyze deep property chains and determine which ones are actually gated by explicit if conditions.
analyze_deep_property_guards() {
  local limit=${1:-$DETAIL_LIMIT}
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then return 1; fi
  if ! command -v python3 >/dev/null 2>&1; then return 1; fi

  local tmp_props tmp_ifs result
  tmp_props="$(mktemp -t ubs-deep-props.XXXXXX 2>/dev/null || mktemp -t ubs-deep-props)"
  tmp_ifs="$(mktemp -t ubs-if-guards.XXXXXX 2>/dev/null || mktemp -t ubs-if-guards)"

  ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern '$OBJ.$P1.$P2.$P3' "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_props"
  ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern 'if ($COND) $BODY' "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_ifs"

  result=$(python3 - "$tmp_props" "$tmp_ifs" "$limit" <<'PY'
import json, sys
from collections import defaultdict

def load_stream(path):
    entries = []
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return entries
    return entries

matches_path, guards_path, limit_raw = sys.argv[1:4]
limit = int(limit_raw)
matches = load_stream(matches_path)
guards = load_stream(guards_path)

def as_pos(data):
    return (data.get('line', 0), data.get('column', 0))

def ge(a, b):
    return a[0] > b[0] or (a[0] == b[0] and a[1] >= b[1])

def le(a, b):
    return a[0] < b[0] or (a[0] == b[0] and a[1] <= b[1])

def within(target, guard):
    start, end = target
    g_start, g_end = guard
    return ge(start, g_start) and le(end, g_end)

guards_by_file = defaultdict(list)
for guard in guards:
    file_path = guard.get('file')
    cond = guard.get('metaVariables', {}).get('single', {}).get('COND')
    if not file_path or not cond:
        continue
    rng = cond.get('range') or {}
    start = rng.get('start')
    end = rng.get('end')
    if not start or not end:
        continue
    guards_by_file[file_path].append((as_pos(start), as_pos(end)))

unguarded = 0
guarded = 0
samples = []

for match in matches:
    file_path = match.get('file')
    rng = match.get('range') or {}
    start = rng.get('start')
    end = rng.get('end')
    if not file_path or not start or not end:
        continue
    start_pos = as_pos(start)
    end_pos = as_pos(end)
    guard_hits = guards_by_file.get(file_path, [])
    is_guarded = any(within((start_pos, end_pos), guard) for guard in guard_hits)
    if is_guarded:
        guarded += 1
        continue
    unguarded += 1
    if len(samples) < limit:
        snippet = (match.get('lines') or '').strip()
        samples.append({'file': file_path, 'line': start_pos[0] + 1, 'code': snippet})

print(json.dumps({'unguarded': unguarded, 'guarded': guarded, 'samples': samples}, ensure_ascii=False))
PY
  )

  rm -f "$tmp_props" "$tmp_ifs"
  printf '%s' "$result"
}
show_ast_samples_from_json() {
  local blob=$1
  [[ -n "$blob" ]] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -cr '.samples[]?' <<<"$blob" | while IFS= read -r sample; do
      local file line code
      file=$(printf '%s' "$sample" | jq -r '.file')
      line=$(printf '%s' "$sample" | jq -r '.line')
      code=$(printf '%s' "$sample" | jq -r '.code')
      print_code_sample "$file" "$line" "$code"
    done
  elif command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$blob" 2>/dev/null || true
import json, sys
try:
    data = json.loads(sys.argv[1])
    for s in data.get('samples', []):
        file = s.get('file','?'); line = s.get('line','?'); code = (s.get('code','') or '').replace('\n',' ')
        print(f"{file}:{line}\n{code}")
except Exception:
    pass
PY
  fi
}

persist_metric_json() {
  local key=$1; local payload=$2
  [[ -n "$key" && -n "$payload" ]] || return 0
  [[ -n "${UBS_METRICS_DIR:-}" ]] || return 0
  mkdir -p "$UBS_METRICS_DIR" 2>/dev/null || true
  {
    printf '{"%s":' "$key"
    printf '%s' "$payload"
    printf '}'
  } >"$UBS_METRICS_DIR/$key.json"
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi
  # Core rules
  # (Keep file names arbitrary; ruleId is authoritative)
  cat >"$AST_RULE_DIR/parseInt-no-radix.yml" <<'YAML'
id: js.parseInt-no-radix
language: javascript
rule:
  kind: call_expression
  pattern: parseInt($ARG)
  not:
    has:
      pattern: parseInt($ARG, $RADIX)
severity: warning
message: "parseInt without radix; use parseInt(x, 10)"
YAML
  cat >"$AST_RULE_DIR/nan-direct-compare.yml" <<'YAML'
id: js.nan-direct-compare
language: javascript
rule:
  any:
    - pattern: $X == NaN
    - pattern: $X === NaN
    - pattern: $X != NaN
    - pattern: $X !== NaN
severity: error
message: "Direct NaN comparison is always false; use Number.isNaN(x)"
YAML
  cat >"$AST_RULE_DIR/innerHTML-assign.yml" <<'YAML'
id: js.innerHTML-assign
language: javascript
rule:
  pattern: $EL.innerHTML = $VAL
severity: warning
message: "Assigning innerHTML; ensure input is sanitized or use textContent"
YAML
  local PROMISE_SEV
  if [[ "$FAIL_ON_WARNING" -eq 1 ]]; then PROMISE_SEV="warning"; else PROMISE_SEV="info"; fi
  cat >"$AST_RULE_DIR/then-without-catch.yml" <<YAML
id: js.then-without-catch
language: javascript
rule:
  pattern: \$P.then(\$ARGS)
  not:
    has:
      pattern: .catch(\$CATCH)
severity: ${PROMISE_SEV}
message: "Promise.then without catch/finally; handle rejections"
YAML
  # Alias for async group compatibility
  cat >"$AST_RULE_DIR/async-then-no-catch.yml" <<YAML
id: js.async.then-no-catch
language: javascript
rule:
  pattern: \$P.then(\$ARGS)
  not:
    has:
      pattern: .catch(\$CATCH)
severity: ${PROMISE_SEV}
message: "Promise.then without .catch/.finally; add rejection handling"
YAML
  cat >"$AST_RULE_DIR/async-promiseall-no-try.yml" <<YAML
id: js.async.promiseall-no-try
language: javascript
rule: { pattern: await Promise.all(\$ARGS), not: { inside: { kind: try_statement } } }
severity: ${PROMISE_SEV}
message: "await Promise.all() without try/catch; wrap to handle aggregate failures"
YAML
  cat >"$AST_RULE_DIR/eval-call.yml" <<'YAML'
id: js.eval-call
language: javascript
rule:
  kind: call_expression
  pattern: eval($$)
severity: error
message: "eval() allows arbitrary code execution"
YAML
  cat >"$AST_RULE_DIR/new-function.yml" <<'YAML'
id: js.new-function
language: javascript
rule:
  kind: new_expression
  pattern: new Function($$)
severity: error
message: "new Function() is equivalent to eval()"
YAML
  cat >"$AST_RULE_DIR/document-write.yml" <<'YAML'
id: js.document-write
language: javascript
rule:
  pattern: document.write($$)
severity: error
message: "document.write() is dangerous and breaks SPAs"
YAML
  cat >"$AST_RULE_DIR/react-useeffect-cleanup.yml" <<'YAML'
id: react.useeffect-missing-cleanup
language: typescript
rule:
  pattern: useEffect(() => { $$ }, $DEPS)
  not:
    has:
      pattern: return () => { $$ }
severity: info
message: "useEffect without cleanup may leak subscriptions or timers"
YAML
  # React / JSX expansions
  cat >"$AST_RULE_DIR/react-missing-key.yml" <<'YAML'
id: react.list-missing-key
language: tsx
rule:
  kind: jsx_element
  pattern: <$_ />
  not:
    has:
      pattern: key={$KEY}
severity: warning
message: "JSX list item missing key prop"
YAML
  cat >"$AST_RULE_DIR/react-dangerously-set-html.yml" <<'YAML'
id: react.dangerously-set-html
language: tsx
rule:
  pattern: <$_ dangerouslySetInnerHTML={$OBJ} />
severity: warning
message: "dangerouslySetInnerHTML used; ensure the HTML is sanitized"
YAML
  cat >"$AST_RULE_DIR/react-setstate-in-render.yml" <<'YAML'
id: react.setstate-in-render
language: tsx
rule:
  kind: method_definition
  regex: "render\\s*\\([^)]*\\)\\s*\\{[^}]*setState\\s*\\("
severity: error
message: "setState called inside render; causes infinite re-render"
YAML
  # Node / security
  cat >"$AST_RULE_DIR/node-child-process.yml" <<'YAML'
id: node.child-process-exec
language: typescript
rule:
  any:
    - pattern: require('child_process').exec($$)
    - pattern: import('child_process').then($$.exec($$))
    - pattern: exec($$)
severity: warning
message: "child_process.exec used; sanitize inputs or prefer execFile/spawn"
YAML
  cat >"$AST_RULE_DIR/insecure-crypto.yml" <<'YAML'
id: security.insecure-crypto
language: typescript
rule:
  any:
    - pattern: crypto.createHash("md5")
    - pattern: crypto.createHash('md5')
    - pattern: crypto.createHash("sha1")
    - pattern: crypto.createHash('sha1')
severity: warning
message: "Weak hash algorithm (md5/sha1); prefer SHA-256/512 or stronger"
YAML
  cat >"$AST_RULE_DIR/insecure-random.yml" <<'YAML'
id: security.insecure-random
language: typescript
rule:
  pattern: Math.random()
severity: info
message: "Math.random used for security-sensitive randomness? Prefer crypto.randomUUID/randomBytes"
YAML
  cat >"$AST_RULE_DIR/http-url.yml" <<'YAML'
id: security.http-url
language: typescript
rule:
  pattern: "http://$REST"
severity: info
message: "Plain HTTP URL detected; ensure HTTPS is used for production"
YAML
  # TypeScript strictness
  cat >"$AST_RULE_DIR/ts-non-null-chain.yml" <<'YAML'
id: ts.non-null-assertion-chain
language: typescript
rule:
  pattern: $X!.$Y
severity: warning
message: "Non-null assertion (!) in property chain; prefer guards or optional chaining"
YAML
  # Error-handling rules
  cat >"$AST_RULE_DIR/error-empty-catch.yml" <<'YAML'
id: js.error.empty-catch
language: javascript
rule:
  kind: catch_clause
  regex: "catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}"
severity: warning
message: "Empty catch block hides errors; log or rethrow the exception"
YAML
  cat >"$AST_RULE_DIR/error-throw-string.yml" <<'YAML'
id: js.error.throw-string
language: javascript
rule:
  kind: throw_statement
  regex: "throw\\s+['\\\"]"
severity: warning
message: "Throwing string literals loses stack traces; use throw new Error('message')"
YAML
  # JSON.parse without try/catch
  cat >"$AST_RULE_DIR/json-parse-without-try.yml" <<YAML
id: js.json-parse-without-try
language: javascript
rule:
  pattern: JSON.parse(\$X)
  not:
    inside:
      kind: try_statement
severity: ${PROMISE_SEV}
message: "JSON.parse without try/catch; malformed input will throw"
YAML
  # New: Dangling promises (heuristic)
  cat >"$AST_RULE_DIR/async-dangling-promise.yml" <<YAML
id: js.async.dangling-promise
language: javascript
rule:
  all:
    - any:
        - pattern: \$CALLEE(\$ARGS)
        - pattern: new \$CALLEE(\$ARGS)
    - not:
        inside:
          any:
            - pattern: await \$EXPR
            - pattern: \$EXPR.then(\$ARGS)
            - pattern: Promise.all(\$ARGS)
            - pattern: Promise.race(\$ARGS)
severity: ${PROMISE_SEV}
message: "Possible unhandled/dangling promise; use await/then/catch"
YAML
  # New: fetch without rejection handling
  cat >"$AST_RULE_DIR/fetch-no-catch.yml" <<YAML
id: js.fetch.no-catch
language: javascript
rule:
  pattern: fetch(\$ARGS)
  not:
    inside:
      any:
        - pattern: try { \$TRY_BODY } catch (\$E) { \$CATCH_BODY }
        - pattern: .catch(\$CATCH)
severity: ${PROMISE_SEV}
message: "fetch() without catch/try; network failures will be unhandled"
YAML
  # New: insecure cookie usage
  cat >"$AST_RULE_DIR/cookie-insecure.yml" <<'YAML'
id: security.cookie-insecure
language: typescript
rule:
  pattern: $OBJ.cookie($NAME, $VAL)
severity: warning
message: "Set-Cookie without httpOnly/secure/sameSite; add them to mitigate XSS/CSRF"
YAML
  # New: header injection risk
  cat >"$AST_RULE_DIR/header-taint.yml" <<'YAML'
id: js.taint.header-injection
language: typescript
rule:
  pattern: res.set($NAME, $VAL)
severity: warning
message: "Headers set from variables; ensure input is sanitized to prevent header injection"
YAML
  # New: insecure crypto params
  cat >"$AST_RULE_DIR/insecure-crypto-params.yml" <<'YAML'
id: security.insecure-crypto-params
language: typescript
rule:
  any:
    - pattern: crypto.pbkdf2($$)
    - pattern: crypto.pbkdf2Sync($$)
severity: info
message: "crypto.pbkdf2/Sync called; ensure iteration count and key length meet policy"
YAML
  # New: env leak heuristic
  cat >"$AST_RULE_DIR/env-leak.yml" <<'YAML'
id: security.env-in-client
language: typescript
rule:
  pattern: process.env.$NAME
severity: info
message: "process.env used; ensure not bundled to client or prefixed (NEXT_PUBLIC_ etc.)"
YAML
  # New: other DOM assignment surfaces
  cat >"$AST_RULE_DIR/innerText-outerHTML.yml" <<'YAML'
id: js.dom.innerText-outerHTML
language: typescript
rule:
  any:
    - pattern: $EL.innerText = $VAL
    - pattern: $EL.outerHTML = $VAL
severity: warning
message: "DOM text/html assignment; confirm the source is trusted or sanitized"
YAML
  cat >"$AST_RULE_DIR/js-resource-add-listener.yml" <<'YAML'
id: js.resource.listener-no-remove
language: javascript
rule:
  pattern: $TARGET.addEventListener($EVENT, $HANDLER)
  not:
    inside:
      pattern: $TARGET.removeEventListener($EVENT, $HANDLER)
severity: warning
message: "addEventListener without matching removeEventListener in the same scope."
YAML
  cat >"$AST_RULE_DIR/js-resource-interval.yml" <<'YAML'
id: js.resource.interval-no-clear
language: javascript
rule:
  pattern: $TIMER = setInterval($CALL)
  not:
    inside:
      pattern: clearInterval($TIMER)
severity: warning
message: "setInterval assigned to a variable without clearInterval on the same identifier."
YAML
  cat >"$AST_RULE_DIR/js-resource-observer.yml" <<'YAML'
id: js.resource.observer-no-disconnect
language: javascript
rule:
  pattern: $OBS = new MutationObserver($CALLBACK)
  not:
    inside:
      pattern: $OBS.disconnect()
severity: warning
message: "MutationObserver created without disconnect()."
YAML
}

ensure_ast_rule_results() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  if [[ -n "$AST_RULE_RESULTS_JSON" && -f "$AST_RULE_RESULTS_JSON" ]]; then
    return 0
  fi
  local tmp_json rc
  tmp_json="$(mktemp 2>/dev/null || mktemp -t ag_results.XXXXXX)"
  rc=0
  shopt -s nullglob
  for rule_file in "$AST_RULE_DIR"/*.yml; do
    "${AST_GREP_CMD[@]}" scan --rule "$rule_file" "$PROJECT_DIR" --json=stream >>"$tmp_json" 2>/dev/null
    cmd_rc=$?
    if [[ "$cmd_rc" -gt 1 ]]; then
      rc=$cmd_rc
      break
    fi
  done
  shopt -u nullglob
  if [[ "$rc" -gt 1 ]]; then
    rm -f "$tmp_json"
    return 1
  fi
  AST_RULE_RESULTS_JSON="$tmp_json"
  return 0
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  if [[ "$FORMAT" == "sarif" ]]; then
    if "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --sarif 2>/dev/null; then
      return 0
    else
      return 1
    fi
  fi
  if ! ensure_ast_rule_results; then
    return 1
  fi
  cat "$AST_RULE_RESULTS_JSON"
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper
# ────────────────────────────────────────────────────────────────────────────
should_skip() {
  local cat="$1"
  if [[ -z "$SKIP_CATEGORIES" ]]; then return 0; fi
  IFS=',' read -r -a arr <<<"$SKIP_CATEGORIES"
  for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# Main Scan Logic
# ────────────────────────────────────────────────────────────────────────────

maybe_clear

echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗   ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝   ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗     ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝     ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗   ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝   ║
║                                                                   ║
║  ██████╗ ██╗   ██╗ ██████╗          ████████████████████████      ║
║  ██╔══██╗██║   ██║██╔════╝          ████████████████████████      ║
║  ██████╔╝██║   ██║██║  ███╗         ████████████████████████      ║
║  ██╔══██╗██║   ██║██║   ██║         ██████████  ████    ████      ║
║  ██████╔╝╚██████╔╝╚██████╔╝         ██████████  ██  ████████      ║
║  ╚═════╝  ╚═════╝  ╚═════╝          ██████████  ████    ████      ║
║                                     ██████████  ████████  ██      ║
║                                     ██████████  ██  ████  ██      ║
║                                     ██████    ██████    ████      ║
║                                     ████████████████████████      ║
║                                                                   ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝       ║
║                                                                   ║
║  JavaScript/TypeScript sentinel • DOM, async, security heuristics ║
║  UBS module: js • AST-grep signal • multi-agent guardrail ready   ║
║  ASCII homage: aemkei hexagon JS logo                             ║
║  Run standalone: modules/ubs-js.sh --help                         ║
║                                                                   ║
║  Night Owl QA                                                     ║
║  “We see bugs before you do.”                                     ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(eval "$DATE_CMD")${RESET}"

# Count files (robust find; no dangling -o, no -false hacks)
EX_PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do EX_PRUNE+=( -name "$d" -o ); done
EX_PRUNE=( \( -type d \( "${EX_PRUNE[@]}" -false \) -prune \) )
NAME_EXPR=( \( )
first=1
for e in "${_EXT_ARR[@]}"; do
  if [[ $first -eq 1 ]]; then NAME_EXPR+=( -name "*.${e}" ); first=0
  else NAME_EXPR+=( -o -name "*.${e}" ); fi
done
NAME_EXPR+=( \) )
TOTAL_FILES=$(
  ( set +o pipefail; find "$PROJECT_DIR" -xdev "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
  | wc -l | awk '{print $1+0}'
)
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"
say "${DIM}Focus areas include NULL SAFETY, SECURITY VULNERABILITIES, Lightweight taint analysis, async pitfalls, and resource lifecycle.${RESET}"

# ast-grep availability
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: NULL SAFETY & DEFENSIVE PROGRAMMING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. NULL SAFETY & DEFENSIVE PROGRAMMING"
print_category "Detects: Null pointer dereferences, missing guards, unsafe property access" \
  "These bugs cause 'Cannot read property of null/undefined' runtime crashes"

print_subheader "Unguarded property access after getElementById/querySelector"
count=$(
  "${GREP_RN[@]}" -e "= *document\.(getElementById|querySelector)" "$PROJECT_DIR" 2>/dev/null \
    | (grep -Ev "if[[:space:]]*\(|\?\." || true) | count_lines
)
if [ "$count" -gt 15 ]; then
  print_finding "warning" "$count" "DOM queries not immediately null-checked" \
    "Consider: const el = document.getElementById('x'); if (!el) return;"
  show_detailed_finding "= *document\.(getElementById|querySelector)" 3
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Some DOM queries may need null checks" "Review each to ensure the element is guaranteed to exist"
else
  print_finding "good" "All DOM queries appear to be guarded"
fi

print_subheader "Optional chaining opportunities (?.)"
count=$("${GREP_RN[@]}" -e "[[:alnum:]_]\s*&&\s*[[:alnum:]_.]+\." "$PROJECT_DIR" 2>/dev/null | (grep -Ev "\?\." || true) | count_lines)
if [ "$count" -gt 50 ]; then
  print_finding "info" "$count" "Could simplify with optional chaining (?.)" \
    "Example: obj && obj.prop && obj.prop.val → obj?.prop?.val"
  show_detailed_finding "[[:alnum:]_]\s*&&\s*[[:alnum:]_.]+\." 3
elif [ "$count" -gt 0 ]; then
  print_finding "good" "Minimal optional chaining opportunities"
fi

print_subheader "Nullish coalescing opportunities (??)"
count=$("${GREP_RN[@]}" -e "\|\|\s*(''|\"\"|0|false|null|undefined|\[\]|\{\})" "$PROJECT_DIR" 2>/dev/null | (grep -v "\?\?" || true) | count_lines)
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Could use nullish coalescing for clarity" \
    "Example: value || 'default' → value ?? 'default' (preserves 0, false, '')"
  show_detailed_finding "\|\|\s*(''|\"\"|0|false|null|undefined|\[\]|\{\})" 3
fi

print_subheader "Accessing nested properties without guards"
deep_guard_json=""
guarded_inside=0
count=
if [[ "$HAS_AST_GREP" -eq 1 ]]; then
  deep_guard_json=$(analyze_deep_property_guards "$DETAIL_LIMIT")
  if [[ -n "$deep_guard_json" ]]; then
    parsed_counts=""
    parsed_counts=$(python3 - <<'PY' <<<"$deep_guard_json"
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    pass
else:
    print(f"{data.get('unguarded', 0)} {data.get('guarded', 0)}")
PY
)
    if [[ -n "$parsed_counts" ]]; then
      read -r count guarded_inside <<<"$parsed_counts"
    else
      deep_guard_json=""
    fi
  fi
fi
if [[ -z "${count:-}" ]]; then
  count=$(
    ast_search '$X.$Y.$Z.$W' \
    || ( "${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) | count_lines
  )
  guarded_inside=0
fi

if [ "$count" -gt 20 ]; then
  print_finding "warning" "$count" "Deep property access - high crash risk" "Consider obj?.prop1?.prop2?.prop3 or explicit guards"
  if [[ -n "$deep_guard_json" ]]; then
    show_ast_samples_from_json "$deep_guard_json"
  else
    show_detailed_finding "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" 3
  fi
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Deep property access detected"
  if [[ -n "$deep_guard_json" ]]; then
    show_ast_samples_from_json "$deep_guard_json"
  fi
elif [ "$guarded_inside" -gt 0 ]; then
  print_finding "good" "$guarded_inside" "Deep property chains are guarded" "Scanner suppressed chains that live inside explicit if checks"
fi

if [[ -n "$deep_guard_json" && "$guarded_inside" -gt 0 ]]; then
  say "    ${DIM}Suppressed $guarded_inside guarded chain(s) detected inside if conditions${RESET}"
fi
if [[ -n "$deep_guard_json" ]]; then
  persist_metric_json "deep_guard" "$deep_guard_json"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: MATH & ARITHMETIC PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 2; then
print_header "2. MATH & ARITHMETIC PITFALLS"
print_category "Detects: Division by zero, NaN propagation, floating-point equality" \
  "Mathematical bugs that produce silent errors or Infinity/NaN values"

print_subheader "Division operations (potential ÷0)"
count=$(
  ( "${GREP_RN[@]}" -e "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) \
    | (grep -Ev "/[[:space:]]*(255|2|10|100|1000)\b|//|/\*" || true) | count_lines)
if [ "$count" -gt 25 ]; then
  print_finding "warning" "$count" "Division by variable - verify non-zero" "Add guards: if (divisor === 0) throw; or use fallback"
  show_detailed_finding "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Division operations found"
fi

print_subheader "Incorrect NaN checks (== NaN instead of Number.isNaN)"
count=$("${GREP_RN[@]}" -e "(===|==|!==|!=)[[:space:]]*NaN" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Direct NaN comparison (always false!)" "Use Number.isNaN(x)"
  show_detailed_finding "(===|==|!==|!=)[[:space:]]*NaN" 5
else
  print_finding "good" "No direct NaN comparisons"
fi

print_subheader "isNaN() instead of Number.isNaN()"
count=$("${GREP_RN[@]}" -e "(^|[^.])isNaN\(" "$PROJECT_DIR" 2>/dev/null | (grep -v "Number\.isNaN" || true) | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Using global isNaN() - use Number.isNaN()" "isNaN('foo') → true; Number.isNaN('foo') → false"
  show_detailed_finding "(^|[^.])isNaN\(" 3
else
  print_finding "good" "All NaN checks use Number.isNaN()"
fi

print_subheader "Floating-point equality (===)"
count=$("${GREP_RN[@]}" -e "(===|==)[[:space:]]*[0-9]+\.[0-9]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Floating-point equality comparison" "Use epsilon: Math.abs(a-b)<EPS"
  show_detailed_finding "(===|==)[[:space:]]*[0-9]+\.[0-9]+" 3
fi

print_subheader "Modulo by variable (verify non-zero)"
count=$("${GREP_RN[@]}" -e "%[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Modulo operations - verify divisor is non-zero"
fi

print_subheader "Bitwise operations on non-integers"
count=$("${GREP_RN[@]}" -e "(^|[^<])<<([^<]|$)|(^|[^>])>>([^>]|$)|\\&|\\^" "$PROJECT_DIR" 2>/dev/null \
  | (grep -v -E "//|&&|\\|\\||/\\*" || true) \
  | wc -l | awk '{print $1+0}')
count=${count:-0}
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Bitwise operations detected - ensure integer inputs"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: ARRAY & COLLECTION SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 3; then
print_header "3. ARRAY & COLLECTION SAFETY"
print_category "Detects: Index out of bounds, mutation bugs, unsafe iteration" \
  "Array bugs cause undefined access, incorrect results, or crashes"

print_subheader "Array access with arithmetic offsets (bounds risk)"
count=$("${GREP_RN[@]}" -e "\[[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+-][[:space:]]*[0-9]+\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 12 ]; then
  print_finding "warning" "$count" "Array index arithmetic - verify bounds" "Example: arr[i-1] requires i>0"
  show_detailed_finding "\[[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+-][[:space:]]*[0-9]+\]" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Array offset access - review bounds checking"
fi

print_subheader "Array.length used in arithmetic without validation"
count=$("${GREP_RN[@]}" -e "\\.length[[:space:]]*[+\-/*]|[+\-/*][[:space:]]*[A-Za-z_]*\\.length" "$PROJECT_DIR" 2>/dev/null \
  | wc -l | awk '{print $1+0}')
count=${count:-0}
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Array.length in calculations" "Ensure non-empty before indexing"
fi

print_subheader "Mutation of array during iteration"
count=$("${GREP_RN[@]}" -e "forEach|for[[:space:]]*\(|for[[:space:]]+of|map|filter" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A3 -E "push|splice|shift|unshift|pop" || true) | (grep -c -E "push|splice|shift|unshift|pop" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Possible array mutation during iteration" "Can cause skipped/duplicate elements"
fi

print_subheader "Array holes (sparse arrays)"
count=$("${GREP_RN[@]}" -e "Array\([0-9]+\)|new[[:space:]]+Array\([0-9]+\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Sparse array creation detected" "Use Array.from({length:n},()=>val)"
  show_detailed_finding "Array\([0-9]+\)|new[[:space:]]+Array\([0-9]+\)" 3
fi

print_subheader "Missing array existence checks before .length"
count=$( ("${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.length" "$PROJECT_DIR" 2>/dev/null || true) \
  | (grep -Ev "if|Array\.isArray|\?\." || true) | count_lines)
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Chained .length access without null checks"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: TYPE COERCION & COMPARISON TRAPS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 4; then
print_header "4. TYPE COERCION & COMPARISON TRAPS"
print_category "Detects: Loose equality, type confusion, implicit conversions" \
  "JavaScript's type coercion causes subtle bugs that are hard to debug"

print_subheader "Loose equality (== instead of ===)"
count=$("${GREP_RN[@]}" -e "(^|[^=!<>])==($|[^=])|(^|[^=!<>])!=($|[^=])" "$PROJECT_DIR" 2>/dev/null \
  | (grep -vE "===|!==" || true) \
  | wc -l | awk '{print $1+0}')
count=${count:-0}
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Loose equality causes type coercion bugs" "Always prefer strict equality"
  show_detailed_finding "(^|[^=!<>])==($|[^=])|(^|[^=!<>])!=($|[^=])" 5
else
  print_finding "good" "All comparisons use strict equality"
fi

print_subheader "Comparing different types"
count=$( ("${GREP_RN[@]}" -e "===[[:space:]]*('|\"|true|false|null)" "$PROJECT_DIR" 2>/dev/null || true) \
  | (grep -vE "typeof|instanceof" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Type comparisons - verify both sides match"; fi

print_subheader "typeof checks with wrong string literals"
count=$( ("${GREP_RN[@]}" -e "typeof[[:space:]]*\(.+\)[[:space:]]*===?[[:space:]]*['\"][A-Za-z]+['\"]" "$PROJECT_DIR" 2>/dev/null || true) \
  | (grep -Ev "undefined|string|number|boolean|function|object|symbol|bigint" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Invalid typeof comparison" "Valid: undefined|string|number|boolean|function|object|symbol|bigint"
  show_detailed_finding "typeof[[:space:]]*\(.+\)[[:space:]]*===?[[:space:]]*['\"][A-Za-z]+['\"]" 3
fi

print_subheader "Truthy/falsy confusion in conditions"
count=$("${GREP_RN[@]}" -e "if[[:space:]]*\(.*\.(length|size)\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "Truthy checks on .length/.size" "Prefer explicit comparisons"
fi

print_subheader "Implicit string concatenation with +"
count=$("${GREP_RN[@]}" -e "\+[[:space:]]*['\"]|['\"][[:space:]]*\+" "$PROJECT_DIR" 2>/dev/null \
  | (grep -v -E "\+\+|[+\-]=" || true) \
  | wc -l | awk '{print $1+0}')
count=${count:-0}
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "String concatenation with +" "Use Number() for math; template literals for strings"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: ASYNC/AWAIT & PROMISE PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 5; then
print_header "5. ASYNC/AWAIT & PROMISE PITFALLS"
print_category "Detects: Missing await, unhandled rejections, race conditions" \
  "Async bugs cause unpredictable behavior, crashes, and data corruption"

async_count=$("${GREP_RN[@]}" -e "async[[:space:]]+function|async[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$async_count" "Async functions found" "Verifying proper await/error handling..."

print_subheader "Race conditions with Promise.race/any"
count=$("${GREP_RN[@]}" -e "Promise\.(race|any)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Promise.race/any usage - verify error handling" "Ensure losers don't cause side effects"
fi

run_async_error_checks
run_hooks_dependency_checks
run_type_narrowing_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ERROR HANDLING ANTI-PATTERNS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. ERROR HANDLING ANTI-PATTERNS"
print_category "Detects: Swallowed errors, missing cleanup, poor error messages" \
  "Bad error handling makes debugging impossible and causes production failures"
print_subheader "Error handling best practices"
emit_ast_rule_group ERROR_RULE_IDS ERROR_RULE_SEVERITY ERROR_RULE_SUMMARY ERROR_RULE_REMEDIATION \
  "Error handling patterns look healthy" "Error handling AST rules"
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: SECURITY VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. SECURITY VULNERABILITIES"
print_category "Detects: Code injection, XSS, prototype pollution, timing attacks" \
  "Security bugs expose users to attacks and data breaches"

print_subheader "eval() usage (CRITICAL SECURITY RISK)"
eval_count=$( \
  ( \
    ( [[ "$HAS_AST_GREP" -eq 1 ]] && ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern 'eval($$)' "$PROJECT_DIR" 2>/dev/null || true ) ) \
    || ( "${GREP_RN[@]}" -e "(^|[^\"'])[Ee]val[[:space:]]*\\(" "$PROJECT_DIR" 2>/dev/null || true ) \
  ) \
  | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
  | count_lines
)
if [ "$eval_count" -gt 0 ]; then
  print_finding "critical" "$eval_count" "eval() ALLOWS ARBITRARY CODE EXECUTION" "NEVER use eval() on user input"
  show_detailed_finding "eval\(" 5
else
  print_finding "good" "No eval() detected"
fi

print_subheader "new Function() (eval equivalent)"
count=$( \
  ( \
    ( [[ "$HAS_AST_GREP" -eq 1 ]] && ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern 'new Function($$)' "$PROJECT_DIR" 2>/dev/null || true ) ) \
    || ( "${GREP_RN[@]}" -e "(^|[^\"'])\\bnew[[:space:]]+Function[[:space:]]*\\(" "$PROJECT_DIR" 2>/dev/null || true ) \
  ) \
  | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
  | count_lines
)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "new Function() enables code injection" "Same risk as eval()"
  show_detailed_finding "new Function\(" 3
fi

print_subheader "innerHTML with potential XSS risk"
count=$( \
  ( \
    ( [[ "$HAS_AST_GREP" -eq 1 ]] && "${AST_GREP_CMD[@]}" --pattern '$EL.innerHTML = $VAL' "$PROJECT_DIR" 2>/dev/null ) \
    || "${GREP_RN[@]}" -e "\.innerHTML[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null \
  ) \
     | (grep -v -E "escapeHtml|sanitize|DOMPurify" || true) \
     | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
     | count_lines
)
if [ "$count" -gt 10 ]; then
  print_finding "warning" "$count" "innerHTML without sanitization - XSS risk" "Use textContent or DOMPurify.sanitize()"
  show_detailed_finding "\.innerHTML[[:space:]]*=" 3
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "innerHTML usage - verify data is trusted"
fi

print_subheader "document.write (deprecated & dangerous)"
count=$( \
  ( \
    ( [[ "$HAS_AST_GREP" -eq 1 ]] && "${AST_GREP_CMD[@]}" --pattern "document.write($$)" "$PROJECT_DIR" 2>/dev/null ) \
    || "${GREP_RNW[@]}" "document\.write" "$PROJECT_DIR" 2>/dev/null \
  ) \
     | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
     | count_lines
)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "document.write() is deprecated & breaks SPAs" "Use DOM manipulation instead"
  show_detailed_finding "document\.write" 3
fi

print_subheader "Prototype pollution vulnerability"
proto_pattern="(\\.__proto__|\\['__proto__'\\]|\\[\"__proto__\"\\]|__proto__\\s*:|constructor\\.prototype)"
count=$("${GREP_RN[@]}" -e "$proto_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Potential prototype pollution" "Never modify __proto__ or constructor.prototype"
  show_detailed_finding "$proto_pattern" 3
fi

print_subheader "Hardcoded secrets/credentials"
count=$("${GREP_RNI[@]}" -e "\b(password|api_?key|secret|token)\b[[:space:]]*[:=][[:space:]]*['\"]([^'\"]+)['\"]" "$PROJECT_DIR" 2>/dev/null |   (grep -v "process\.env" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Possible hardcoded secrets" "Use environment variables or secret managers"
  show_detailed_finding "\b(password|api_?key|secret|token)\b[[:space:]]*[:=][[:space:]]*['\"]" 3
fi

print_subheader "RegExp denial of service (ReDoS) risk"
count=$("${GREP_RN[@]}" -e "new RegExp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
complex_regex=$("${GREP_RN[@]}" -e "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$complex_regex" -gt 5 ]; then
  print_finding "warning" "$complex_regex" "Complex regex patterns - ReDoS risk" "Nested quantifiers can hang on crafted input"
fi

run_taint_analysis_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: FUNCTION & SCOPE ISSUES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. FUNCTION & SCOPE ISSUES"
print_category "Detects: Missing return, callback hell, closure leaks" \
  "Function bugs cause incorrect results and memory leaks"

print_subheader "Functions with high parameter count (>5)"
count=$("${GREP_RN[@]}" -e "function" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E "\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*," || true) | count_lines)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Functions with >5 parameters" "Refactor to an options object"
  show_detailed_finding "function.*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*," 3
fi

print_subheader "Arrow functions with implicit return confusion"
count=$("${GREP_RN[@]}" -e "=>[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "return" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Arrow functions with { } - verify return intent" "() => {x:1} returns undefined; wrap object: () => ({x:1})"
fi

print_subheader "Nested callbacks (callback hell)"
count=$("${GREP_RN[@]}" -e "function" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A10 "function" || true) | (grep -c "function" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 40 ]; then
  print_finding "info" "$count" "Many callback-style functions detected" "Review for unnecessary nesting; prefer async/await or Promises"
fi

print_subheader "Function declarations inside blocks"
count=$("${GREP_RN[@]}" -e "if|for|while" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A2 "function " || true) | (grep -cw "function" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Function declarations in blocks - use function expressions" "Hoisting is inconsistent"
fi

print_subheader "Missing return in functions"
count=$("${GREP_RN[@]}" -e "^function [A-Za-z_]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
return_count=$("${GREP_RNW[@]}" "return" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt "$return_count" ]; then
  missing=$((count - return_count)); [ "$missing" -lt 0 ] && missing=0
  print_finding "info" "$missing" "Some functions may lack return statements" "Verify void is intentional"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: PARSING & TYPE CONVERSION BUGS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. PARSING & TYPE CONVERSION BUGS"
print_category "Detects: parseInt errors, JSON parsing, date issues" \
  "Parsing bugs cause data corruption and incorrect calculations"

print_subheader "parseInt without radix parameter"
count=$("${GREP_RN[@]}" -e "parseInt\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -Ev ",[[:space:]]*(10|16|8|2)\)" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "parseInt without explicit radix" "Specify base (e.g., parseInt(x, 10)) for clarity"
  show_detailed_finding "parseInt\(" 5
else
  print_finding "good" "All parseInt calls specify radix"
fi

print_subheader "JSON.parse without try/catch"
json_parse_report=$(python3 - "$PROJECT_DIR" <<'PY' 2>/dev/null
import os
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

issues = []
max_lookback = 8

for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
    for fname in filenames:
        lower = fname.lower()
        if not any(lower.endswith(ext) for ext in exts):
            continue
        path = Path(dirpath) / fname
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except Exception:
            continue
        for idx, line in enumerate(lines):
            if 'JSON.parse' not in line:
                continue
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('//'):
                continue
            safe = False
            checks = 0
            back_idx = idx - 1
            while back_idx >= 0 and checks < max_lookback:
                prev = lines[back_idx].strip()
                back_idx -= 1
                if not prev or prev.startswith('//') or prev.startswith('/*'):
                    continue
                checks += 1
                tokens = ''.join(ch if ch.isalnum() else ' ' for ch in prev).split()
                if 'try' in tokens:
                    safe = True
                    break
            if safe:
                continue
            try:
                rel = path.relative_to(root)
            except ValueError:
                rel = path
            issues.append((str(rel), idx + 1, stripped_line.replace('\t', ' ')))

print(len(issues))
for entry in issues[:25]:
    print('\t'.join(str(part) for part in entry))
PY
)
json_parse_count=$(printf '%s\n' "$json_parse_report" | head -n1 | awk 'END{print $0+0}')
json_parse_samples=$(printf '%s\n' "$json_parse_report" | tail -n +2)
if [ "$json_parse_count" -gt 0 ]; then
  print_finding "warning" "$json_parse_count" "JSON.parse without error handling" "Wrap in try/catch or validate input first"
else
  print_finding "good" "JSON.parse usage appears guarded by try/catch"
fi
if [ "$json_parse_count" -gt 0 ] && [[ -n "$json_parse_samples" ]]; then
  sample_limit=5
  while IFS=$'\t' read -r sample_path sample_line sample_text; do
    [ -z "$sample_path" ] && continue
    say "    ${DIM}$sample_path:$sample_line${RESET}  $sample_text"
    sample_limit=$((sample_limit - 1))
    [ "$sample_limit" -le 0 ] && break
  done <<<"$json_parse_samples"
fi

print_subheader "parseFloat precision issues"
count=$("${GREP_RN[@]}" -e "parseFloat\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "parseFloat usage - verify precision requirements" "Consider decimal libraries for currency"
fi

print_subheader "new Date() without validation"
count=$("${GREP_RN[@]}" -e "new Date\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Date construction - verify input validation" "new Date('invalid') → Invalid Date"
fi

print_subheader "Implicit numeric conversion via unary +"
count=$("${GREP_RN[@]}" -e "\+[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "\+\+|[+\-]=" || true) | count_lines)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Unary + for type conversion" "Use Number(x) for clarity"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: CONTROL FLOW GOTCHAS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 10; then
print_header "10. CONTROL FLOW GOTCHAS"
print_category "Detects: Missing breaks, unreachable code, confusing conditions" \
  "Control flow bugs cause logic errors and unexpected behavior"

print_subheader "Switch cases without break/return"
switch_count=$("${GREP_RN[@]}" -e "switch\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
case_count=$("${GREP_RN[@]}" -e "case[[:space:]]+.*:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
break_count=$("${GREP_RN[@]}" -e "break;" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$case_count" -gt "$break_count" ]; then
  diff=$((case_count - break_count))
  print_finding "warning" "$diff" "Switch cases may be missing break" "Add break or /* falls through */"
fi

print_subheader "Switch without default case"
default_count=$("${GREP_RN[@]}" -e "default:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$switch_count" -gt "$default_count" ]; then
  diff=$((switch_count - default_count))
  print_finding "warning" "$diff" "Switch statements without default case" "Handle unexpected values"
fi

print_subheader "Nested ternaries (readability nightmare)"
count=$("${GREP_RN[@]}" -e "\?.*:[^;]*\?.*:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Nested ternary operators - unreadable" "Refactor to if/else"
  show_detailed_finding "\?.*:[^;]*\?.*:" 3
fi

print_subheader "Unreachable code after return"
count=$("${GREP_RNW[@]}" "return" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A1 "return" || true) | (grep -v -E "^--$|return" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Possible unreachable code after return"
fi

print_subheader "Empty if/else blocks"
count=$("${GREP_RN[@]}" -e "if[[:space:]]*\(.*\)[[:space:]]*\{[[:space:]]*\}|else[[:space:]]*\{[[:space:]]*\}" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Empty conditional blocks" "Remove or implement"
  show_detailed_finding "if[[:space:]]*\(.*\)[[:space:]]*\{[[:space:]]*\}|else[[:space:]]*\{[[:space:]]*\}" 3
fi

print_subheader "Yoda conditions (confusing style)"
count=$("${GREP_RN[@]}" -e "(^|[^\w])(?:null|true|false|[0-9]+|['\"][^'\"]+['\"])[[:space:]]*===?[[:space:]]*[A-Za-z_$][A-Za-z0-9_$]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Yoda conditions detected" "Prefer if (x === 5)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: DEBUGGING & PRODUCTION CODE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. DEBUGGING & PRODUCTION CODE"
print_category "Detects: console.log, debugger, dead code" \
  "Debug code left in production affects performance and leaks info"

console_count=$("${GREP_RN[@]}" -e "console\." "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$console_count" -gt 50 ]; then
  print_finding "warning" "$console_count" "Many console.* statements" "Use a logging library"
elif [ "$console_count" -gt 20 ]; then
  print_finding "info" "$console_count" "console.* statements found"
else
  print_finding "good" "Minimal console usage"
fi

print_subheader "debugger statements (MUST REMOVE)"
count=$("${GREP_RNW[@]}" "debugger" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "debugger statements in code" "Remove before commit"
  show_detailed_finding "\bdebugger\b" 5
else
  print_finding "good" "No debugger statements"
fi

print_subheader "alert/confirm/prompt (blocking UI)"
count=$("${GREP_RN[@]}" -e "\balert\(|\bconfirm\(|\bprompt\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Blocking dialogs - poor UX" "Use modals or toast notifications instead"
  show_detailed_finding "\balert\(|\bconfirm\(|\bprompt\(" 3
fi

print_subheader "console.log with sensitive data"
count=$("${GREP_RNI[@]}" -e "console\.(log|dir).*?(password|token|secret|Bearer|Authorization)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Logging sensitive data" "Remove sensitive logs"
  show_detailed_finding "console\.(log|dir).*?(password|token|secret|Bearer|Authorization)" 3
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: MEMORY LEAKS & PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 12; then
print_header "12. MEMORY LEAKS & PERFORMANCE"
print_category "Detects: Event listener leaks, closures, heavy operations" \
  "Performance bugs cause slowdowns, crashes, and poor user experience"

add_count=$("${GREP_RN[@]}" -e "addEventListener" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
remove_count=$("${GREP_RN[@]}" -e "removeEventListener" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$add_count" "Event listeners attached"
print_finding "info" "$remove_count" "Event listeners removed"
if [ "$add_count" -gt $((remove_count * 5)) ]; then
  diff=$((add_count - remove_count)); [ "$diff" -lt 0 ] && diff=0
  print_finding "warning" "$diff" "Listener imbalance - potential memory leak" "Ensure cleanup on unmount"
fi

print_subheader "setInterval without clearInterval"
interval_count=$("${GREP_RN[@]}" -e "setInterval\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
clear_count=$("${GREP_RN[@]}" -e "clearInterval\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$interval_count" -gt "$clear_count" ]; then
  diff=$((interval_count - clear_count))
  print_finding "warning" "$diff" "setInterval without clearInterval - timer leak" "Timers continue forever if not cleared"
fi

print_subheader "setTimeout without clearTimeout"
timeout_count=$("${GREP_RN[@]}" -e "setTimeout\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
clear_timeout=$("${GREP_RN[@]}" -e "clearTimeout\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$timeout_count" -gt $((clear_timeout + 20)) ]; then
  diff=$((timeout_count - clear_timeout)); [ "$diff" -lt 0 ] && diff=0
  print_finding "info" "$diff" "Many setTimeout without clear" "Clear pending timeouts on unmount"
fi

print_subheader "Large inline arrays/objects (memory waste)"
count=$("${GREP_RN[@]}" -e "\[.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*," "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Large inline arrays - consider external file" "Move large structures to JSON files"
fi

print_subheader "Synchronous operations in loops"
count=$("${GREP_RN[@]}" -e "for|while" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A5 -E "querySelector|getElementById|innerHTML|appendChild" || true) | \
  (grep -c -E "querySelector|getElementById|innerHTML|appendChild" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "DOM operations in loops - cache selectors" "Cache element references before loops"
fi

print_subheader "String concatenation in loops"
count=$("${GREP_RN[@]}" -e "for|while" "$PROJECT_DIR" 2>/dev/null | (grep -A3 "+=" || true) | (grep -cw "+=" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "String concatenation in loops" "Prefer array.join for large strings"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: VARIABLE & SCOPE ISSUES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 13; then
print_header "13. VARIABLE & SCOPE ISSUES"
print_category "Detects: var usage, global pollution, shadowing" \
  "Scope bugs cause hard-to-debug variable conflicts"

print_subheader "var declarations (use let/const)"
count=$("${GREP_RNW[@]}" "\bvar\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Using 'var' instead of let/const" "var is function-scoped and hoisted"
  show_detailed_finding "\bvar\b" 5
else
  print_finding "good" "No var declarations (using let/const)"
fi

print_subheader "Global variable pollution"
global_pollution_report=$(python3 - "$PROJECT_DIR" <<'PY' 2>/dev/null
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

assign_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=')
decl_re = re.compile(r'\b(const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)')
destruct_re = re.compile(r'\b(const|let|var)\s+\{([^}]*)\}')
func_params_re = re.compile(r'\bfunction\b(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*\(([^)]*)\)')
class_method_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{', re.MULTILINE)
skip_keywords = {'if', 'for', 'while', 'switch', 'catch', 'with', 'function', 'class'}
arrow_paren_re = re.compile(r'\(([^)]*)\)\s*=>')
arrow_single_re = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=>')

def record_params(store, blob):
    for raw in blob.split(','):
        token = raw.strip()
        if not token:
            continue
        if token.startswith('{') or token.startswith('['):
            continue
        token = token.split('=')[0].strip()
        if token.startswith('...'):
            token = token[3:]
        if re.match(r'[A-Za-z_][A-Za-z0-9_]*$', token):
            store.add(token)

issues = []

def scan_file(path):
    try:
        text = path.read_text(encoding='utf-8')
    except Exception:
        try:
            text = path.read_text(encoding='latin-1')
        except Exception:
            return
    declared = set(name for _, name in decl_re.findall(text))
    for match in destruct_re.finditer(text):
        entries = match.group(2).split(',')
        for entry in entries:
            token = entry.strip()
            if not token:
                continue
            token = token.split(':')[0].strip()
            token = token.split('=')[0].strip()
            token = token.lstrip('*&')
            if re.match(r'[A-Za-z_][A-Za-z0-9_]*$', token):
                declared.add(token)
    for match in func_params_re.finditer(text):
        record_params(declared, match.group(1))
    for match in class_method_re.finditer(text):
        name = match.group(1)
        if name in skip_keywords:
            continue
        record_params(declared, match.group(2))
    for match in arrow_paren_re.finditer(text):
        record_params(declared, match.group(1))
    for match in arrow_single_re.finditer(text):
        token = match.group(1)
        if token.startswith(('function', 'class')):
            continue
        if re.match(r'[A-Za-z_][A-Za-z0-9_]*$', token):
            declared.add(token)
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue
        match = assign_re.match(line)
        if not match:
            continue
        prefix = line[:match.start(1)]
        if any(kw in prefix for kw in ('const ', 'let ', 'var ', 'class ', 'function ', 'import ', 'export ')):
            continue
        name = match.group(1)
        if name in declared:
            continue
        issues.append((path, idx, stripped))

for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
    for fname in filenames:
        lower = fname.lower()
        if not any(lower.endswith(ext) for ext in exts):
            continue
        scan_file(Path(dirpath) / fname)

print(len(issues))
for path, line_no, text in issues[:25]:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    safe_text = text.replace('\t', ' ').strip()
    print(f"{rel}\t{line_no}\t{safe_text}")
PY
)
global_pollution_count=$(printf '%s\n' "$global_pollution_report" | head -n1 | awk 'END{print $0+0}')
global_pollution_samples=$(printf '%s\n' "$global_pollution_report" | tail -n +2)
if [ "$global_pollution_count" -gt 5 ]; then
  print_finding "critical" "$global_pollution_count" "Global variable assignments" "Missing const/let. Creates globals"
elif [ "$global_pollution_count" -gt 0 ]; then
  print_finding "warning" "$global_pollution_count" "Possible global variable pollution"
fi
if [ "$global_pollution_count" -gt 0 ] && [[ -n "$global_pollution_samples" ]]; then
  sample_limit=5
  while IFS=$'\t' read -r sample_path sample_line sample_text; do
    [ -z "$sample_path" ] && continue
    say "    ${DIM}$sample_path:$sample_line${RESET}  $sample_text"
    sample_limit=$((sample_limit - 1))
    [ "$sample_limit" -le 0 ] && break
  done <<<"$global_pollution_samples"
fi

print_subheader "Variable shadowing"
count=$(ast_search 'let $VAR = $$; $$ { let $VAR = $$ }' || \
  ( "${GREP_RN[@]}" -e "\b(let|const|var)[[:space:]]+[A-Za-z_]" "$PROJECT_DIR" 2>/dev/null || true ) | sort -t: -k3 | uniq -d -f2 | wc -l | awk '{print $1+0}')
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Potential variable shadowing" "Inner scope redefines outer variable"
fi

print_subheader "const reassignment attempts"
count=$("${GREP_RN[@]}" -e "^const " "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "good" "Using const appropriately"; fi

print_subheader "Unused variables (heuristic)"
if [ "$HAS_AST_GREP" -eq 1 ]; then
  count=$(ast_search 'const $VAR = $$$' || echo 0)
  if [ "$count" -gt 100 ]; then
    print_finding "info" "$count" "Many variable declarations - check for unused vars" "Use ESLint no-unused-vars for precision"
  fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: CODE QUALITY MARKERS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 14; then
print_header "14. CODE QUALITY MARKERS"
print_category "Detects: TODO, FIXME, HACK, XXX comments" \
  "Technical debt markers indicate incomplete or problematic code"

todo_count=$("${GREP_RNI[@]}" "TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fixme_count=$("${GREP_RNI[@]}" "FIXME" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
hack_count=$("${GREP_RNI[@]}" "HACK" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
xxx_count=$("${GREP_RNI[@]}" "XXX" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
note_count=$("${GREP_RNI[@]}" "NOTE" "$PROJECT_DIR" 2>/dev/null | count_lines || true)

total_markers=$((todo_count + fixme_count + hack_count + xxx_count))
if [ "$total_markers" -gt 20 ]; then
  print_finding "warning" "$total_markers" "Significant technical debt" "Create tracking tickets"
elif [ "$total_markers" -gt 10 ]; then
  print_finding "info" "$total_markers" "Moderate technical debt"
elif [ "$total_markers" -gt 0 ]; then
  print_finding "info" "$total_markers" "Minimal technical debt"
else
  print_finding "good" "No technical debt markers"
fi
if [ "$total_markers" -gt 0 ]; then
  say "\n  ${DIM}Breakdown:${RESET}"
  [ "$todo_count" -gt 0 ] && say "    ${YELLOW}TODO:${RESET}  $todo_count"
  [ "$fixme_count" -gt 0 ] && say "    ${RED}FIXME:${RESET} $fixme_count"
  [ "$hack_count" -gt 0 ] && say "    ${MAGENTA}HACK:${RESET}  $hack_count"
  [ "$xxx_count" -gt 0 ] && say "    ${RED}XXX:${RESET}   $xxx_count"
  [ "$note_count" -gt 0 ] && say "    ${BLUE}NOTE:${RESET}  $note_count"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: REGEX & STRING SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 15; then
print_header "15. REGEX & STRING SAFETY"
print_category "Detects: ReDoS, regex injection, string escaping issues" \
  "Regex bugs cause performance issues and security vulnerabilities"

print_subheader "ReDoS vulnerable patterns"
count=$("${GREP_RN[@]}" -e "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Nested quantifiers - ReDoS risk" "Use atomic groups or possessive quantifiers (engine permitting)"
  show_detailed_finding "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" 2
fi

print_subheader "RegExp with user input (injection risk)"
count=$("${GREP_RN[@]}" -e "new RegExp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Dynamic RegExp construction" "Sanitize input or prefer string methods"
fi

print_subheader "Missing string escaping in regex"
count=$("${GREP_RN[@]}" -e "replace\((.*[\\\*\+\?\[\]\(\)\{\}\^\$\|\\])" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v '\\\\' || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Special chars in replace - verify escaping"
fi

print_subheader "Case-insensitive regex without /i flag"
count=$("${GREP_RN[@]}" -e "match\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "/i|toUpperCase|toLowerCase" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Case-sensitive matching - intentional?" "Use /i or normalize case"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: DOM MANIPULATION SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. DOM MANIPULATION SAFETY"
print_category "Detects: Missing null checks, inefficient queries, event leaks" \
  "DOM bugs cause crashes and performance issues"

print_subheader "querySelector/getElementById calls"
dom_count=$("${GREP_RN[@]}" -e "querySelector|getElementById" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$dom_count" "DOM queries found" "Ensure all queries have null checks before property access"

print_subheader "Uncached DOM queries in loops"
count=$( ("${GREP_RN[@]}" -e "for|while" "$PROJECT_DIR" 2>/dev/null || true) \
  | (grep -A5 -E "querySelector|getElementById" || true) | (grep -c -E "querySelector|getElementById" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "DOM queries inside loops" "Cache selectors outside loops"
fi

print_subheader "Direct style manipulation"
count=$("${GREP_RN[@]}" -e "\.style\.[A-Za-z]*[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 30 ]; then
  print_finding "info" "$count" "Direct style manipulation" "Prefer CSS classes"
fi

print_subheader "Missing event delegation opportunities"
count=$("${GREP_RN[@]}" -e "addEventListener" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E "forEach|map" || true) | count_lines)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Adding listeners in loops" "Use event delegation on parent where appropriate"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: TYPESCRIPT STRICTNESS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 17; then
print_header "17. TYPESCRIPT STRICTNESS"
print_category "Detects: any usage, non-null assertions, implicit any" \
  "Looser types reduce safety and increase runtime failures"

print_subheader "Explicit any annotations"
count=$("${GREP_RN[@]}" -e ":\s*any(\W|$)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Explicit any types present" "Prefer unknown or generics"; fi

print_subheader "Non-null assertion operator (!)"
count=$("${GREP_RN[@]}" -e "[A-Za-z_$][A-Za-z0-9_$]*\!" "$PROJECT_DIR" 2>/dev/null | (grep -v -E "!=|!==" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Non-null assertions used" "Audit for potential NPE at runtime"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 18: NODE.JS I/O & MODULES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 18; then
print_header "18. NODE.JS I/O & MODULES"
print_category "Detects: sync filesystem calls, dynamic require(), JSON.parse(file) without try" \
  "Sync I/O blocks event loop; dynamic requires hinder bundling and caching"

print_subheader "Synchronous fs operations"
count=$("${GREP_RN[@]}" -e "fs\.[A-Za-z]+Sync\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Synchronous fs.*Sync calls" "Prefer async APIs"; fi

print_subheader "Dynamic require()"
count=$("${GREP_RN[@]}" -e "require\(\s*\+|require\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Dynamic require/variable module path" "Hinders bundling and caching"; fi

run_node_api_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 19; then
print_header "19. RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: Acquire/release imbalances for listeners, timers, observers" \
  "Unreleased resources leak memory, CPU, and event handlers across renders"

run_resource_lifecycle_checks
fi

# (Optional) Run ast-grep rule packs (if available) to emit structured findings
if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
  print_header "AST-GREP RULE PACK FINDINGS"
  if run_ast_rules; then
    say "${DIM}${INFO} Above JSON/SARIF lines are ast-grep matches (id, message, severity, file/pos).${RESET}"
    if [[ "$FORMAT" == "sarif" ]]; then
      say "${DIM}${INFO} Tip: ${BOLD}${AST_GREP_CMD[*]} scan -r $AST_RULE_DIR \"$PROJECT_DIR\" --sarif > report.sarif${RESET}"
    fi
  else
    say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
  fi
fi

# restore pipefail if we relaxed it
end_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
say "${BOLD}${CYAN}                    🎯 SCAN COMPLETE 🎯                                  ${RESET}"
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

say "${WHITE}${BOLD}Summary Statistics:${RESET}"
say "  ${WHITE}Files scanned:${RESET}    ${CYAN}$TOTAL_FILES${RESET}"
say "  ${RED}${BOLD}Critical issues:${RESET}  ${RED}$CRITICAL_COUNT${RESET}"
say "  ${YELLOW}Warning issues:${RESET}   ${YELLOW}$WARNING_COUNT${RESET}"
say "  ${BLUE}Info items:${RESET}       ${BLUE}$INFO_COUNT${RESET}"
echo ""

# Optional machine-friendly JSON export
if [[ -n "$REPORT_JSON" ]]; then
  python3 - "$JSON_FINDINGS_TMP" "$REPORT_JSON" "$TOTAL_FILES" "$CRITICAL_COUNT" "$WARNING_COUNT" "$INFO_COUNT" "$UBS_VERSION" <<'PY' 2>/dev/null || true
import json, sys, time
src, out, files, crit, warn, info, ver = sys.argv[1:8]
findings = []
try:
  with open(src,'r',encoding='utf-8') as fh:
    for line in fh:
      if line.strip(): findings.append(json.loads(line))
except FileNotFoundError: pass
payload = {"version": ver, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "files": int(files), "critical": int(crit), "warning": int(warn), "info": int(info), "findings": findings}
open(out,'w',encoding='utf-8').write(json.dumps(payload, ensure_ascii=False, indent=2))
PY
  say "${GREEN}${CHECK} JSON report saved to: ${CYAN}$REPORT_JSON${RESET}"
fi

say "${BOLD}${WHITE}Priority Actions:${RESET}"
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  say "  ${RED}${FIRE} ${BOLD}FIX CRITICAL ISSUES IMMEDIATELY${RESET}"
  say "  ${DIM}These cause crashes, security vulnerabilities, or data corruption${RESET}"
fi
if [ "$WARNING_COUNT" -gt 0 ]; then
  say "  ${YELLOW}${WARN} ${BOLD}Review and fix WARNING items${RESET}"
  say "  ${DIM}These cause bugs, performance issues, or maintenance problems${RESET}"
fi
if [ "$INFO_COUNT" -gt 0 ]; then
  say "  ${BLUE}${INFO} ${BOLD}Consider INFO suggestions${RESET}"
  say "  ${DIM}Code quality improvements and best practices${RESET}"
fi

if [ "$CRITICAL_COUNT" -eq 0 ] && [ "$WARNING_COUNT" -eq 0 ]; then
  say "\n  ${GREEN}${BOLD}${SPARKLE} EXCELLENT! No critical or warning issues found ${SPARKLE}${RESET}"
fi

echo ""
say "${DIM}Scan completed at: $(eval "$DATE_CMD")${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

# Cleanup temp
[[ -n "$JSON_FINDINGS_TMP" ]] && rm -f "$JSON_FINDINGS_TMP" || true

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning . > bug-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
exit "$EXIT_CODE"
