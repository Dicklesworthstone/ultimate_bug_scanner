#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# RUBY ULTIMATE BUG SCANNER v1.5 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Ruby (3.3+) using:
#   • ast-grep (rule packs; language: ruby)
#   • ripgrep/grep heuristics for fast code smells
#   • optional Bundler-powered extra analyzers:
#       - rubocop (lint/style), brakeman (Rails security),
#         bundler-audit (dependency vulns), reek (code smells), fasterer (perf)
#
# Focus:
#   • nil & defensive checks     • exceptions & error handling
#   • shell/subprocess safety     • security & crypto hygiene
#   • I/O & resource handling     • typing/idioms & metaprogramming risks
#   • regex safety (ReDoS)        • code quality markers & performance
#
# Supports:
#   --format text|json|sarif (json/sarif => pure machine output)
#   --rules DIR   (merge user ast-grep rules)
#   --fail-on-warning, --skip, --only, --jobs, --ag-threads, --include-ext, --exclude
#   --ci, --no-color, --list-rules, --ag-fixable-only, --ag-preview-fix
#   --json-out, --sarif-out, --summary-json
#   CI-friendly timestamps, robust find, safe pipelines, auto parallel jobs
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
umask 022
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

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; GEM="💎"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif (json/sarif => pure machine output)
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="rb,rake,ru,gemspec,erb,haml,slim,rbi,rbs,jbuilder"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1

ENABLE_BUNDLER_TOOLS=1
RB_TOOLS="rubocop,brakeman,bundler-audit,reek,fasterer"
RB_TIMEOUT="${RB_TIMEOUT:-1200}"

AG_THREADS=0
LIST_RULES=0
AG_FIXABLE_ONLY=0
AG_PREVIEW_FIX=0
SUMMARY_JSON=""
SARIF_OUT=""
JSON_OUT=""

# Async error coverage metadata
ASYNC_ERROR_RULE_IDS=(ruby.async.thread-no-rescue)
declare -A ASYNC_ERROR_SUMMARY=(
  [ruby.async.thread-no-rescue]='Thread.new block lacks rescue'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [ruby.async.thread-no-rescue]='Wrap thread bodies in begin/rescue to log or propagate errors'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [ruby.async.thread-no-rescue]='warning'
)

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --json-out=FILE          Save full JSON report to file (text still prints)
  --sarif-out=FILE         Save SARIF to file (text still prints)
  --summary-json=FILE      Save brief summary counters JSON
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --only=CSV               Only run these category numbers/names
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --ag-threads=N           Threads for ast-grep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --list-rules             List enabled ast-grep rule IDs and exit
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
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --ag-threads=*) AG_THREADS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --ag-fixable-only) AG_FIXABLE_ONLY=1; shift;;
    --ag-preview-fix) AG_PREVIEW_FIX=1; shift;;
    --no-bundler) ENABLE_BUNDLER_TOOLS=0; shift;;
    --rb-tools=*) RB_TOOLS="${1#*=}"; shift;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        OUTPUT_FILE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      ;;
  esac
done

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

# Redirect output early to capture everything
if [[ -n "${OUTPUT_FILE}" ]]; then
  if command -v tee >/dev/null 2>&1; then
    exec > >(tee "${OUTPUT_FILE}") 2>&1
  else
    exec > "${OUTPUT_FILE}" 2>&1
  fi
fi

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
AST_GREP_CMD=()
AST_RULE_DIR=""
HAS_RIPGREP=0
HAS_BUNDLE=0
BUNDLE_EXEC=()

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(file_handle thread_join http_session)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [file_handle]="critical"
  [thread_join]="warning"
  [http_session]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [file_handle]='File\.open'
  [thread_join]='Thread\.new'
  [http_session]='Net::HTTP\.start'
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [file_handle]='\.close|File\.open[^\n]*do\b|File\.open[^\n]*\{[[:space:]]*\|'
  [thread_join]='\.join'
  [http_session]='\.finish\(|Net::HTTP\.start[^\n]*(do\b|\{[[:space:]]*\|)'
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [file_handle]='File handles opened without close or block'
  [thread_join]='Ruby threads started without join'
  [http_session]='Net::HTTP sessions missing finish()'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [file_handle]='Use File.open with a block or ensure close() in ensure'
  [thread_join]='Join threads or monitor them to avoid background zombies'
  [http_session]='Call finish() or use the block form of Net::HTTP.start'
)

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep) + include/exclude
# ────────────────────────────────────────────────────────────────────────────
LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done

EXCLUDE_DIRS=(.git .hg .svn .bzr .bundle vendor/bundle vendor/cache log tmp .yardoc coverage .tox .nox .cache .idea .vscode .history node_modules dist build pkg doc public/assets storage .sass-cache .rubocop-cache .reek .bundle-audit .solargraph .gem spec/fixtures test/fixtures)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
  HAS_RIPGREP=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden --pcre2 "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
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

# Helper: robust numeric end-of-pipeline counter
count_lines() { awk 'END{print (NR+0)}'; }

# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────
maybe_clear() { if [[ -t 1 && "$CI_MODE" -eq 0 ]]; then clear || true; fi; }
say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

print_header() {
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
      local raw_count=$2; local title=$3; local description="${4:-}"
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
  local header_shown=0
  local rid
  for rid in "${RESOURCE_LIFECYCLE_IDS[@]}"; do
    local acquire_regex="${RESOURCE_LIFECYCLE_ACQUIRE[$rid]:-}"
    local release_regex="${RESOURCE_LIFECYCLE_RELEASE[$rid]:-}"
    [[ -z "$acquire_regex" || -z "$release_regex" ]] && continue
    local file_list
    file_list=$("${GREP_RN[@]}" -e "$acquire_regex" "$PROJECT_DIR" 2>/dev/null | cut -d: -f1 | sort -u || true)
    [[ -n "$file_list" ]] || continue
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      local acquire_hits release_hits
      acquire_hits=$("${GREP_RN[@]}" -e "$acquire_regex" "$file" 2>/dev/null | count_lines || true)
      release_hits=$("${GREP_RN[@]}" -e "$release_regex" "$file" 2>/dev/null | count_lines || true)
      acquire_hits=${acquire_hits:-0}
      release_hits=${release_hits:-0}
      if (( acquire_hits > release_hits )); then
        if [[ $header_shown -eq 0 ]]; then
          print_subheader "Resource lifecycle correlation"
          header_shown=1
        fi
        local delta=$((acquire_hits - release_hits))
        local relpath=${file#"$PROJECT_DIR"/}
        [[ "$relpath" == "$file" ]] && relpath="$file"
        local summary="${RESOURCE_LIFECYCLE_SUMMARY[$rid]:-Resource imbalance}"
        local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$rid]:-Ensure matching cleanup call}"
        local severity="${RESOURCE_LIFECYCLE_SEVERITY[$rid]:-warning}"
        local title="$summary [$relpath]"
        local desc="$remediation (acquire=$acquire_hits, release=$release_hits)"
        print_finding "$severity" "$delta" "$title" "$desc"
      fi
    done <<<"$file_list"
  done
  if [[ $header_shown -eq 0 ]]; then
    print_subheader "Resource lifecycle correlation"
    print_finding "good" "All tracked resource acquisitions have matching cleanups"
  fi
}

run_async_error_checks() {
  print_subheader "Async error path coverage"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
    print_finding "info" 0 "ast-grep not available" "Install ast-grep to analyze Thread error handling"
    return
  fi
  local rule_file tmp_json
  rule_file="$(mktemp 2>/dev/null || mktemp -t rb_async_rules.XXXXXX)"
  cat >"$rule_file" <<'YAML'
rules:
  - id: ruby.async.thread-no-rescue
    language: ruby
    rule:
      pattern: |
        Thread.new($ARGS) do
          $$
        end
      not:
        contains:
          kind: rescue_clause
YAML
  tmp_json="$(mktemp 2>/dev/null || mktemp -t rb_async_matches.XXXXXX)"
  if ! "${AST_GREP_CMD[@]}" scan -r "$rule_file" "$PROJECT_DIR" --json >"$tmp_json" 2>/dev/null; then
    rm -f "$rule_file" "$tmp_json"
    print_finding "info" 0 "ast-grep scan failed" "Unable to compute async error coverage"
    return
  fi
  rm -f "$rule_file"
  if ! [[ -s "$tmp_json" ]]; then
    rm -f "$tmp_json"
    print_finding "good" "Thread bodies appear to handle exceptions"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r rid count samples; do
    [[ -z "$rid" ]] && continue
    printed=1
    local severity=${ASYNC_ERROR_SEVERITY[$rid]:-warning}
    local summary=${ASYNC_ERROR_SUMMARY[$rid]:-$rid}
    local desc=${ASYNC_ERROR_REMEDIATION[$rid]:-"Handle thread exceptions"}
    if [[ -n "$samples" ]]; then
      desc+=" (e.g., $samples)"
    fi
    print_finding "$severity" "$count" "$summary" "$desc"
  done < <(python3 - "$tmp_json" <<'PY'
import json, sys
from collections import OrderedDict
path = sys.argv[1]
stats = OrderedDict()
with open(path, 'r', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = obj.get('rule_id') or obj.get('id')
        if not rid:
            continue
        rng = obj.get('range') or {}
        start = rng.get('start') or {}
        line_no = start.get('row', 0) + 1
        file_path = obj.get('file', '?')
        entry = stats.setdefault(rid, {'count': 0, 'samples': []})
        entry['count'] += 1
        if len(entry['samples']) < 3:
            entry['samples'].append(f"{file_path}:{line_no}")
for rid, data in stats.items():
    print(f"{rid}\t{data['count']}\t{','.join(data['samples'])}")
PY
  )
  rm -f "$tmp_json"
  if [[ $printed -eq 0 ]]; then
    print_finding "good" "Thread bodies appear to handle exceptions"
  fi
}

show_ast_samples_from_json() {
  local blob=$1
  [[ -n "$blob" ]] || return 0
  if ! command -v jq >/dev/null 2>&1; then return 0; fi
  jq -cr '.samples[]?' <<<"$blob" | while IFS= read -r sample; do
    local file line code
    file=$(printf '%s' "$sample" | jq -r '.file')
    line=$(printf '%s' "$sample" | jq -r '.line')
    code=$(printf '%s' "$sample" | jq -r '.code')
    print_code_sample "$file" "$line" "$code"
  done
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

with_timeout() {
  # with_timeout <seconds> <command...>
  local seconds="$1"; shift || true
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep: detection, rule packs, and wrappers
# ────────────────────────────────────────────────────────────────────────────
check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; return 0; fi
  if command -v sg       >/dev/null 2>&1; then AST_GREP_CMD=(sg);       HAS_AST_GREP=1; return 0; fi
  if command -v npx      >/dev/null 2>&1; then AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; return 0; fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be skipped.${RESET}"
  say "${DIM}Tip: npm i -g @ast-grep/cli  or  cargo install ast-grep${RESET}"
  HAS_AST_GREP=0; return 1
}

ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang ruby "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

analyze_rb_chain_guards() {
  local limit=${1:-$DETAIL_LIMIT}
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  local tmp_chains result
  tmp_chains="$(mktemp -t ubs-rb-chains.XXXXXX 2>/dev/null || mktemp -t ubs-rb-chains)"

  # Long call chains (4+ hops). Sample-friendly stream output
  ( set +o pipefail; "${AST_GREP_CMD[@]}" --lang ruby \
      --pattern '$A.$B.$C.$D' \
      --json=stream "$PROJECT_DIR" 2>/dev/null || true ) >"$tmp_chains"

  result=$(python3 - "$tmp_chains" "$limit" <<'PYHELP'
import json, sys, re
def load_stream(path):
    data = []
    try:
        for line in open(path, 'r', encoding='utf-8'):
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return data

matches_path, limit_raw = sys.argv[1:3]
limit = int(limit_raw)
matches = load_stream(matches_path)
unguarded = 0; guarded = 0; samples = []
safe_nav = re.compile(r'\&\.')
for m in matches:
    file_path = m.get('file')
    code = (m.get('lines') or '').strip()
    rng = m.get('range') or {}
    line = (rng.get('start') or {}).get('line', 0) + 1
    # basic suppression: safe navigation or explicit nil guard in same line
    suppressed = bool(safe_nav.search(code)) or bool(re.search(r'\bif\b.+\bnil\?', code))
    if suppressed:
        guarded += 1
    else:
        unguarded += 1
        if len(samples) < limit:
            samples.append({'file': file_path, 'line': line, 'code': code})
print(json.dumps({'unguarded': unguarded, 'guarded': guarded, 'samples': samples}))
PYHELP
  )

  rm -f "$tmp_chains"
  printf '%s' "$result"
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t rb_ag_rules.XXXXXX)"
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # ── Core Ruby rules (expanded) ───────────────────────────────────────────
  cat >"$AST_RULE_DIR/nil-eq.yml" <<'YAML'
id: rb.nil-eq
language: ruby
rule:
  any:
    - pattern: $X == nil
    - pattern: $X != nil
severity: warning
message: "Prefer x.nil? / !x.nil? instead of == nil / != nil"
fix: |
  if ($MATCH =~ /==\s*nil/)
    {{X}}.nil?
  else
    !{{X}}.nil?
  end
YAML

  cat >"$AST_RULE_DIR/is-literal.yml" <<'YAML'
id: rb.equal-literal
language: ruby
rule:
  any:
    - pattern: $X.equal?(true)
    - pattern: $X.equal?(false)
    - pattern: $X.equal?(0)
severity: info
message: "Avoid identity checks with literals; use == (and nil? for nil)"
YAML

  cat >"$AST_RULE_DIR/bare-rescue.yml" <<'YAML'
id: rb.bare-rescue
language: ruby
rule:
  pattern: |
    begin
      $A
    rescue
      $B
    end
severity: warning
message: "Bare rescue catches StandardError broadly; rescue specific errors"
YAML

  cat >"$AST_RULE_DIR/rescue-exception.yml" <<'YAML'
id: rb.rescue-exception
language: ruby
rule:
  pattern: |
    begin
      $A
    rescue Exception => $e
      $B
    end
severity: critical
message: "Rescuing Exception also catches system exits/interrupts; avoid"
YAML

  cat >"$AST_RULE_DIR/raise-e.yml" <<'YAML'
id: rb.raise-e
language: ruby
rule:
  pattern: |
    begin
      $A
    rescue $E => $ex
      raise $ex
    end
severity: warning
message: "Use 'raise' (without arg) to preserve original backtrace"
YAML

  cat >"$AST_RULE_DIR/mutable-const.yml" <<'YAML'
id: rb.mutable-const
language: ruby
rule:
  any:
    - pattern: $C = []
    - pattern: $C = {}
constraints:
  C:
    regex: '^[A-Z][A-Z0-9_]*$'
severity: info
message: "Mutable constants may be modified; consider freezing or dup on read"
YAML

  cat >"$AST_RULE_DIR/eval-exec.yml" <<'YAML'
id: rb.eval-exec
language: ruby
rule:
  any:
    - pattern: eval($ARG)
    - pattern: instance_eval($ARG)
    - pattern: class_eval($ARG)
severity: critical
message: "eval*/_*eval with strings can lead to code injection"
YAML

  cat >"$AST_RULE_DIR/marshal-load.yml" <<'YAML'
id: rb.marshal-load
language: ruby
rule:
  any:
    - pattern: Marshal.load($ANY)
    - pattern: Marshal.restore($ANY)
severity: critical
message: "Unmarshalling untrusted data is insecure; prefer JSON or safer formats"
YAML

  cat >"$AST_RULE_DIR/yaml-unsafe.yml" <<'YAML'
id: rb.yaml-unsafe
language: ruby
rule:
  pattern: YAML.load($ARG)
severity: warning
message: "YAML.load may instantiate objects; prefer YAML.safe_load with permitted_classes"
YAML

  cat >"$AST_RULE_DIR/digest-weak.yml" <<'YAML'
id: rb.digest-weak
language: ruby
rule:
  any:
    - pattern: Digest::MD5.hexdigest($$)
    - pattern: Digest::SHA1.hexdigest($$)
    - pattern: OpenSSL::Digest::MD5.new($$)
    - pattern: OpenSSL::Digest::SHA1.new($$)
severity: warning
message: "Weak hash algorithm (MD5/SHA1); prefer SHA256/512"
YAML

  cat >"$AST_RULE_DIR/random-insecure.yml" <<'YAML'
id: rb.random-insecure
language: ruby
rule:
  any:
    - pattern: rand($$)
    - pattern: Random.rand($$)
severity: info
message: "rand/Random are not cryptographic; use SecureRandom for secrets/tokens"
YAML

  cat >"$AST_RULE_DIR/http-verify-none.yml" <<'YAML'
id: rb.http-verify-none
language: ruby
rule:
  any:
    - pattern: OpenSSL::SSL::VERIFY_NONE
    - pattern: $OBJ.verify_mode = OpenSSL::SSL::VERIFY_NONE
severity: warning
message: "SSL verification disabled; enable peer verification"
YAML

  cat >"$AST_RULE_DIR/send-dynamic.yml" <<'YAML'
id: rb.send-dynamic
language: ruby
rule:
  any:
    - pattern: $OBJ.send($NAME, $$)
    - pattern: $OBJ.__send__($NAME, $$)
severity: info
message: "Dynamic dispatch via send; ensure $NAME is validated"
YAML

  cat >"$AST_RULE_DIR/sql-interp.yml" <<'YAML'
id: rb.sql-interp
language: ruby
rule:
  all:
    - any:
        - pattern: ActiveRecord::Base.connection.execute($SQL)
        - pattern: $X.find_by_sql($SQL)
    - has:
        regex: '#\{.+\}'
severity: warning
message: "Interpolated SQL; prefer parameterized queries (e.g., where(name: ?))"
YAML

  cat >"$AST_RULE_DIR/system-single-string.yml" <<'YAML'
id: rb.system-single-string
language: ruby
rule:
  any:
    - pattern: system($CMD)
    - pattern: exec($CMD)
constraints:
  CMD:
    kind: string
severity: critical
message: "Shell invocation via single string; use argv array to avoid injection."
YAML

  cat >"$AST_RULE_DIR/open-pipe.yml" <<'YAML'
id: rb.open-pipe
language: ruby
rule:
  pattern: open($STR)
constraints:
  STR:
    regex: '^\s*["'\'']\|'
severity: warning
message: "Kernel#open with leading '|' spawns a subshell; avoid or validate inputs."
YAML

  cat >"$AST_RULE_DIR/json-parse.yml" <<'YAML'
id: rb.json-parse
language: ruby
rule:
  pattern: JSON.parse($ARG)
severity: info
message: "Ensure JSON.parse is wrapped with rescue JSON::ParserError."
YAML

  cat >"$AST_RULE_DIR/file-open-no-block.yml" <<'YAML'
id: rb.file-open-no-block
language: ruby
rule:
  all:
    - pattern: File.open($ARGS)
    - not:
        has:
          regex: '\bdo\s*\||\{.*\|'
severity: warning
message: "File.open without a block; may leak descriptors; use a block to auto-close."
YAML

  cat >"$AST_RULE_DIR/tmp-no-block.yml" <<'YAML'
id: rb.tmp-no-block
language: ruby
rule:
  any:
    - pattern: Dir.mktmpdir($$)
    - pattern: Tempfile.new($$)
severity: info
message: "Tempfile/tmpdir without block can leak; use block form to ensure cleanup."
YAML

  cat >"$AST_RULE_DIR/ruby-resource-thread.yml" <<'YAML'
id: ruby.resource.thread-no-join
language: ruby
rule:
  pattern: $VAR = Thread.new($ARGS)
  not:
    inside:
      pattern: $VAR.join
severity: warning
message: "Thread handle created without join() in the same scope."
YAML

  cat >"$AST_RULE_DIR/rails-constantize.yml" <<'YAML'
id: rails.constantize
language: ruby
rule:
  any:
    - pattern: $X.constantize
severity: info
message: "constantize may raise NameError; prefer safe_constantize when input is user-controlled."
YAML

  cat >"$AST_RULE_DIR/rails-update-attributes.yml" <<'YAML'
id: rails.update-attributes
language: ruby
rule:
  any:
    - pattern: $REC.update_attributes($$)
severity: info
message: "update_attributes is deprecated; prefer update with strong params."
YAML

  cat >"$AST_RULE_DIR/rails-permit-bang.yml" <<'YAML'
id: rails.permit-bang
language: ruby
rule:
  pattern: $P.permit!
severity: warning
message: "Strong params permit! found; review carefully."
YAML

  cat >"$AST_RULE_DIR/rails-csrf-skip.yml" <<'YAML'
id: rails.csrf-skip
language: ruby
rule:
  any:
    - pattern: skip_before_action :verify_authenticity_token
severity: warning
message: "CSRF protections skipped in controllers."
YAML

  cat >"$AST_RULE_DIR/float-eq.yml" <<'YAML'
id: rb.float-eq
language: ruby
rule:
  pattern: $LHS == $FLOAT
constraints:
  FLOAT:
    regex: '^[0-9]+\.[0-9]+$'
severity: warning
message: "Exact float equality; use tolerance (|(a-b).abs < EPS)."
YAML

  cat >"$AST_RULE_DIR/and-or.yml" <<'YAML'
id: rb.and-or
language: ruby
rule:
  any:
    - pattern: $A and $B
    - pattern: $A or $B
severity: info
message: "'and'/'or' have lower precedence than &&/||; prefer &&/|| in expressions."
YAML

  cat >"$AST_RULE_DIR/retry.yml" <<'YAML'
id: rb.retry
language: ruby
rule:
  pattern: retry
severity: info
message: "Ensure bounded retries with backoff."
YAML

  # ── Done writing rules ────────────────────────────────────────────────────
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  local outfmt="--json"; [[ "$FORMAT" == "sarif" ]] && outfmt="--sarif"
  local threads=()
  if [[ "$AG_THREADS" -gt 0 ]]; then
    threads=(--threads "$AG_THREADS")
  else
    local n="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"
    [[ "$n" -gt 0 ]] && threads=(--threads "$n")
  fi
  local extra=()
  [[ "$AG_FIXABLE_ONLY" -eq 1 ]] && extra+=(--only-fixable)

  if [[ "$AG_PREVIEW_FIX" -eq 1 ]]; then
    "${AST_GREP_CMD[@]}" fix -r "$AST_RULE_DIR" "$PROJECT_DIR" --dry-run --diff "${threads[@]}" 2>/dev/null || true
    return 0
  fi

  if "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" $outfmt "${threads[@]}" "${extra[@]}" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# Bundler/toolchain helpers
# ────────────────────────────────────────────────────────────────────────────
check_bundler() {
  if command -v bundle >/dev/null 2>&1 && [[ -f "$PROJECT_DIR/Gemfile" ]]; then
    HAS_BUNDLE=1; BUNDLE_EXEC=(bundle exec); return 0
  fi
  HAS_BUNDLE=0; BUNDLE_EXEC=(); return 1
}

run_rb_tool_text() {
  # run_rb_tool_text <tool> [args...]
  local tool="$1"; shift || true
  if [[ "$ENABLE_BUNDLER_TOOLS" -eq 1 && "$HAS_BUNDLE" -eq 1 ]]; then
    if [[ "$tool" == "bundle" ]]; then
      with_timeout "$RB_TIMEOUT" bundle "$@" || true
    else
      with_timeout "$RB_TIMEOUT" "${BUNDLE_EXEC[@]}" "$tool" "$@" || true
    fi
  else
    if command -v "$tool" >/dev/null 2>&1; then
      with_timeout "$RB_TIMEOUT" "$tool" "$@" || true
    fi
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

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper
# ────────────────────────────────────────────────────────────────────────────
should_skip() {
  local cat="$1"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    IFS=',' read -r -a arr <<<"$ONLY_CATEGORIES"
    for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 0; done
    return 1
  fi
  if [[ -z "$SKIP_CATEGORIES" ]]; then return 0; fi
  IFS=',' read -r -a arr <<<"$SKIP_CATEGORIES"
  for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# Init
# ────────────────────────────────────────────────────────────────────────────
maybe_clear

echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗  ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝  ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗    ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝    ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗  ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝  ║
║                                     __________________           ║
║  ██████╗ ██╗   ██╗ ██████╗        .-'  \ _.-''-._ /  '-.         ║
║  ██╔══██╗██║   ██║██╔════╝      .-/\   .'.      .'.   /\-.       ║
║  ██████╔╝██║   ██║██║  ███╗    _'/  \.'   '.  .'   './  \'_      ║
║  ██╔══██╗██║   ██║██║   ██║   :======:======::======:======:     ║
║  ██████╔╝╚██████╔╝╚██████╔╝    '. '.  \     ''     /  .' .'      ║
║  ╚═════╝  ╚═════╝  ╚═════╝       '. .  \   :  :   /  . .'        ║
║                                    '.'  \  '  '  /  '.'          ║
║                                      ':  \:    :/  :'            ║
║                                        '. \    / .'              ║
║                                          '.\  /.'                ║
║                                            '\/'                  ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ║
║                                                                  ║
║  Ruby module • Rails security, metaprogramming, bundler audits   ║
║  UBS module: ruby • Rubocop, Brakeman, bundler-audit automation  ║
║  ASCII homage: Joan G. Stark gemstone sketch                     ║
║  Run standalone: modules/ubs-ruby.sh --help                      ║
║                                                                  ║
║  Night Owl QA                                                    ║
║  “We see bugs before you do.”                                    ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(eval "$DATE_CMD")${RESET}"

# Count files with robust find
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
  ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print0 \) 2>/dev/null || true ) \
  | tr -cd '\0' | wc -c | awk '{print $1+0}'
)
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

# ast-grep availability
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
  if [[ "$LIST_RULES" -eq 1 ]]; then
    (grep -RHAn --include '*.yml' '^id:' "$AST_RULE_DIR" || true) | sed 's/.*id:\s*//' | sort -u
    exit 0
  fi
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

# bundler availability
if check_bundler; then
  say "${GREEN}${CHECK} Bundler detected - ${DIM}will run extra analyzers via bundle exec${RESET}"
else
  say "${YELLOW}${WARN} Bundler or Gemfile not detected - will run tools if globally installed${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: NIL / DEFENSIVE PROGRAMMING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. NIL / DEFENSIVE PROGRAMMING"
print_category "Detects: nil equality, deep method chains without guards, dig? usage" \
  "Prefer x.nil?, safe navigation (&.), and Hash#dig to avoid NoMethodError."

print_subheader "== nil or != nil (prefer .nil?)"
count=$("${GREP_RN[@]}" -e "==[[:space:]]*nil|!=[[:space:]]*nil" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Equality to nil" "Use x.nil? / !x.nil?"
  show_detailed_finding "==[[:space:]]*nil|!=[[:space:]]*nil" 5
else
  print_finding "good" "No nil equality comparisons"
fi

print_subheader "Deep method chains (use &. / guards)"
deep_chain_json=""
guarded_chain_count=0
count=
if [[ "$HAS_AST_GREP" -eq 1 ]]; then
  deep_chain_json=$(analyze_rb_chain_guards "$DETAIL_LIMIT")
  if [[ -n "$deep_chain_json" ]]; then
    parsed_counts=""
    parsed_counts=$(python3 - <<'PY' <<<"$deep_chain_json"
import json, sys
try:
    data = json.load(sys.stdin)
    print(f"{data.get('unguarded', 0)} {data.get('guarded', 0)}")
except Exception:
    pass
PY
)
    if [[ -n "$parsed_counts" ]]; then
      read -r count guarded_chain_count <<<"$parsed_counts"
    else
      deep_chain_json=""
    fi
  fi
fi
if [[ -z "${count:-}" ]]; then
  count=$(
    ast_search '$A.$B.$C.$D' \
    || ( "${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) | count_lines
  )
  guarded_chain_count=0
fi
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Fragile deep chaining" "Consider &. or guard clauses"
  if [[ -n "$deep_chain_json" ]]; then
    show_ast_samples_from_json "$deep_chain_json"
  else
    show_detailed_finding "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" 3
  fi
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Some deep chaining detected"
  [[ -n "$deep_chain_json" ]] && show_ast_samples_from_json "$deep_chain_json"
elif [ "$guarded_chain_count" -gt 0 ]; then
  print_finding "good" "$guarded_chain_count" "Deep chains guarded" "Scanner suppressed method chains guarded by explicit patterns"
fi
if [[ -n "$deep_chain_json" && "$guarded_chain_count" -gt 0 ]]; then
  say "    ${DIM}Suppressed $guarded_chain_count guarded chain(s) (safe-nav or inline guard)${RESET}"
fi
if [[ -n "$deep_chain_json" ]]; then
  persist_metric_json "deep_guard" "$deep_chain_json"
fi

print_subheader "Hash#[] chained without dig"
count=$("${GREP_RN[@]}" -e "\[[^\]]+\]\[[^\]]+\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "Nested [] access" "Consider Hash#dig(:a,:b)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: NUMERIC / ARITHMETIC PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 2; then
print_header "2. NUMERIC / ARITHMETIC PITFALLS"
print_category "Detects: division by variable, float equality, modulo hazards" \
  "Guard divisors and avoid exact float equality."

print_subheader "Division by variable (possible ÷0)"
count=$(
  ( "${GREP_RN[@]}" -e "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) \
  | (grep -E -v "/[[:space:]]*(255|2|10|100|1000)\b|//|/\*" || true) | count_lines)
if [ "$count" -gt 25 ]; then
  print_finding "warning" "$count" "Division by variable - verify non-zero" "Guard: raise if denom.zero?"
  show_detailed_finding "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Division operations found - check divisors"
fi

print_subheader "Float equality (==)"
count=$("${GREP_RN[@]}" -e "==[[:space:]]*[0-9]+\.[0-9]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Float equality comparison" "Use tolerance: (a-b).abs < EPS"
  show_detailed_finding "==[[:space:]]*[0-9]+\.[0-9]+" 3
fi

print_subheader "Modulo by variable (verify non-zero)"
count=$("${GREP_RN[@]}" -e "%[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Modulo operations - verify divisor non-zero"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: COLLECTION SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 3; then
print_header "3. COLLECTION SAFETY"
print_category "Detects: index risks, mutation during iteration, length checks" \
  "Collection misuse leads to IndexError or subtle logic bugs."

print_subheader "Index arithmetic like arr[i±1]"
count=$("${GREP_RN[@]}" -e "\[[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+\-][[:space:]]*[0-9]+[[:space:]]*\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 12 ]; then
  print_finding "warning" "$count" "Array index arithmetic - verify bounds" "Ensure i±k within range"
  show_detailed_finding "\[[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+\-][[:space:]]*[0-9]+[[:space:]]*\]" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Index arithmetic present - review bounds"
fi

print_subheader "Mutation during each/map"
count=$("${GREP_RN[@]}" -e "\.(each|map|select|reject)\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -A3 "\.(push|<<|insert|delete|delete_if|pop|shift|unshift|clear)\b" || true) | \
  (grep -E -c "(push|<<|insert|delete|delete_if|pop|shift|unshift|clear)" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Possible mutation during iteration" "Iterate over dup or collect to new array"
fi

print_subheader "length/size explicit zero checks"
count=$("${GREP_RN[@]}" -e "\.(length|size)[[:space:]]*(==|!=|<|>|<=|>=)[[:space:]]*0" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "length/size == 0 checks" "Prefer empty?/any?"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: COMPARISON & IDIOMS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 4; then
print_header "4. COMPARISON & IDIOMS"
print_category "Detects: 'and/or' precedence, object identity, case equality misuse" \
  "Prefer &&/|| for precedence; avoid === misuse outside case."

print_subheader "'and'/'or' usage (precedence traps)"
count=$("${GREP_RN[@]}" -e "[^&] and [^&]|[^|] or [^|]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "and/or used; precedence differs from &&/||" "Prefer &&/|| in expressions"
fi

print_subheader "Case equality (===) outside case/when"
count=$("${GREP_RN[@]}" -e "===[[:space:]]*[A-Za-z_]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "when[[:space:]]" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "=== used directly" "Ensure intent; === can be surprising"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: EXCEPTIONS & ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 5; then
print_header "5. EXCEPTIONS & ERROR HANDLING"
print_category "Detects: bare rescue, rescue Exception, swallowed errors, raise e" \
  "Proper exception handling preserves backtraces and avoids masking bugs."

print_subheader "Bare rescue"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*rescue[[:space:]]*($|#)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Bare rescue without class" "Rescue specific errors"
  show_detailed_finding "^[[:space:]]*rescue[[:space:]]*($|#)" 5
else
  print_finding "good" "No bare rescue blocks"
fi

print_subheader "rescue Exception"
count=$("${GREP_RN[@]}" -e "rescue[[:space:]]+Exception\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Rescuing Exception" "Rescue StandardError or specific subclasses"
  show_detailed_finding "rescue[[:space:]]+Exception" 5
fi

print_subheader "rescue => e; raise e"
count=$("${GREP_RN[@]}" -e "rescue[[:space:]]+[^=]+=>[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -A2 "raise[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*$" || true) | \
  (grep -E -c "raise[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*$" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Use 'raise' not 'raise e' to keep traceback"
fi

print_subheader "rescue modifier (foo rescue nil)"
count=$("${GREP_RN[@]}" -e "rescue[[:space:]]+nil" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 2 ]; then
  print_finding "warning" "$count" "Silencing errors with 'rescue nil'" "Log or handle specifically"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: SECURITY VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. SECURITY VULNERABILITIES"
print_category "Detects: code injection, unsafe deserialization, TLS off, weak crypto" \
  "Security bugs expose users to attacks and data breaches."

print_subheader "eval/instance_eval/class_eval"
count=$("${GREP_RN[@]}" -e "(^|[^A-Za-z0-9_])(eval|instance_eval|class_eval)[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "^[[:space:]]*#" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "eval*/_*eval present" "Avoid executing dynamic code"
  show_detailed_finding "(^|[^A-Za-z0-9_])(eval|instance_eval|class_eval)[[:space:]]*\(" 5
else
  print_finding "good" "No eval*/_*eval detected"
fi

print_subheader "Marshal/YAML unsafe loads"
count=$("${GREP_RN[@]}" -e "Marshal\.(load|restore)\(|YAML\.load\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "YAML\.safe_load" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Unsafe deserialization" "Use YAML.safe_load or JSON"
  show_detailed_finding "Marshal\.(load|restore)\(|YAML\.load\(" 5
fi

print_subheader "Backticks / %x() command execution"
count=$("${GREP_RN[@]}" -e '\`[^`]*\`|%x\([^)]*\)' "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Backtick command execution" "Prefer system with argv array and validate inputs"
  show_detailed_finding '\`[^`]*\`|%x\([^)]*\)' 3
fi

print_subheader "system/exec with single string (shell)"
count=$("${GREP_RN[@]}" -e "(^|[^A-Za-z0-9_])(system|exec|Open3\.(capture2|capture3|popen3))\((['\"]).*\1\)" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "," || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Shell invocation risk (single-string)" "Use argv array: system('cmd', arg1, ...)"
  show_detailed_finding "(^|[^A-Za-z0-9_])(system|exec|Open3\.(capture2|capture3|popen3))\(" 3
fi

print_subheader "TLS verify disabled"
count=$("${GREP_RN[@]}" -e "VERIFY_NONE|verify_mode[[:space:]]*=[[:space:]]*OpenSSL::SSL::VERIFY_NONE" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "SSL verification disabled" "Enable VERIFY_PEER"
  show_detailed_finding "VERIFY_NONE|verify_mode[[:space:]]*=" 3
fi

print_subheader "Weak hash algorithms"
count=$("${GREP_RN[@]}" -e "Digest::(MD5|SHA1)\.hexdigest|OpenSSL::Digest::(MD5|SHA1)\.new" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Weak hash usage" "Use Digest::SHA256"
  show_detailed_finding "Digest::(MD5|SHA1)\.hexdigest|OpenSSL::Digest::(MD5|SHA1)\.new" 3
fi

print_subheader "Hardcoded secrets"
count=$("${GREP_RNI[@]}" -e "\b(password|api_?key|client_secret|private_?key|bearer|authorization|token)\b[[:space:]]*[:=][[:space:]]*['\"][^\"']+['\"]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "(^|/)(spec|test)/fixtures/" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Potential hardcoded secrets" "Use env vars or credentials store"
  show_detailed_finding "\b(password|api_?key|client_secret|private_?key|bearer|authorization|token)\b[[:space:]]*[:=][[:space:]]*['\"][^\"']+['\"]" 5
fi

print_subheader "SecureRandom absent where tokens generated"
count=$("${GREP_RN[@]}" -e "token|secret|nonce|password" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v -i "SecureRandom" || true) | count_lines)
if [ "$count" -gt 20 ]; then
  print_finding "info" "$count" "Potential token generation sites" "Ensure SecureRandom is used"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: SHELL/SUBPROCESS SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. SHELL / SUBPROCESS SAFETY"
print_category "Detects: system single-string, backticks, Kernel#open pipelines" \
  "Prefer argv array to avoid shell injection."

print_subheader "Kernel#open with pipe"
count=$("${GREP_RN[@]}" -e "open\([[:space:]]*['\"]\|" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "open('|cmd') spawns subshell"; fi

print_subheader "system with interpolation"
count=$("${GREP_RN[@]}" -e "system\((\"|')[^\"']*#\{[^}]+\}[^\"']*(\"|')\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Interpolated shell commands - sanitize inputs"; fi

print_subheader "Preferred exec form"
count=$("${GREP_RN[@]}" -e "system\(['\"][^'\",]+['\"]\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 2 ]; then print_finding "info" "$count" "Use system('cmd', arg1, ...) to avoid shell"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: I/O & RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. I/O & RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: File.open without block, Dir.chdir global effects, Tempfile misuse" \
  "Use blocks to auto-close and avoid global state surprises."

print_subheader "File.open without block"
count=$("${GREP_RN[@]}" -e "File\.open\([^\)]*\)" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "do[[:space:]]*\||\{[[:space:]]*\|[^\|]*\|" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "File.open used without block" "Use File.open(...){|f| ... }"
fi

print_subheader "Dir.chdir (global working dir)"
count=$("${GREP_RN[@]}" -e "Dir\.chdir\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Dir.chdir affects global state" "Prefer chdir blocks or absolute paths"
fi

print_subheader "Tempfile / Dir.mktmpdir without blocks"
count=$("${GREP_RN[@]}" -e "Tempfile\.new\(|Dir\.mktmpdir\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "do[[:space:]]*\||\{[[:space:]]*\|[^\|]*\|" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Tempfile/tmpdir without block may leak"; fi

run_resource_lifecycle_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: PARSING & TYPE CONVERSION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. PARSING & TYPE CONVERSION BUGS"
print_category "Detects: JSON.load/parse without rescue, Integer(x) vs to_i, time parsing" \
  "Prefer strict conversions with exceptions where appropriate."

print_subheader "JSON.parse without rescue"
count=$("${GREP_RN[@]}" -e "JSON\.parse\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
trycatch_count=$("${GREP_RNW[@]}" -B2 "begin" "$PROJECT_DIR" 2>/dev/null || true | (grep -E -c "JSON\.parse" || true))
trycatch_count=$(printf '%s\n' "$trycatch_count" | awk 'END{print $0+0}')
if [ "$count" -gt "$trycatch_count" ]; then
  ratio=$((count - trycatch_count))
  print_finding "warning" "$ratio" "JSON.parse without error handling" "Rescue JSON::ParserError"
fi

print_subheader "String#to_i fallback vs Integer() strict"
count=$("${GREP_RN[@]}" -e "\.to_i(\)|\([[:space:]]*base:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 20 ]; then
  print_finding "info" "$count" "Frequent to_i usage" "Consider Integer(str, 10) for strictness"
fi

print_subheader "Time.parse without zone/validation"
count=$("${GREP_RN[@]}" -e "Time\.parse\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then print_finding "info" "$count" "Time.parse used" "Validate inputs; prefer iso8601"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: CONTROL FLOW GOTCHAS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 10; then
print_header "10. CONTROL FLOW GOTCHAS"
print_category "Detects: return in ensure, retry, nested ternary, next/break in ensure" \
  "Flow pitfalls cause lost exceptions or confusing semantics."

print_subheader "return/break/next inside ensure"
count=$("${GREP_RN[@]}" -e "ensure[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -A3 "return|break|next" || true) | (grep -E -c "return|break|next" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Control transfer in ensure" "May swallow exceptions"
fi

print_subheader "Nested ternary (?:)"
count=$("${GREP_RN[@]}" -e "\?.*:[^;]*\?.*:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Nested ternary expressions" "Prefer if/elsif"
  show_detailed_finding "\?.*:[^;]*\?.*:" 3
fi

print_subheader "retry usage"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*retry[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 2 ]; then
  print_finding "info" "$count" "retry used" "Ensure bounded retries with backoff"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: DEBUGGING & PRODUCTION CODE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. DEBUGGING & PRODUCTION CODE"
print_category "Detects: puts/p, pry/binding.irb, sensitive logs" \
  "Debug artifacts degrade performance or leak secrets."

print_subheader "puts/p/pp statements"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*(puts|p|pp)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 40 ]; then
  print_finding "warning" "$count" "Many puts/p/pp statements" "Use Logger with levels"
elif [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "puts/p/pp statements found"
else
  print_finding "good" "Minimal direct printing"
fi

print_subheader "pry/binding.irb/breakpoint"
count=$("${GREP_RN[@]}" -e "binding\.pry|binding\.irb|byebug|debugger" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Debugger calls present" "Remove before commit"
  show_detailed_finding "binding\.pry|binding\.irb|byebug|debugger" 5
else
  print_finding "good" "No debugger calls"
fi

print_subheader "Logging sensitive data"
count=$("${GREP_RNI[@]}" -e "logger\.(debug|info|warn|error|fatal)\(.*(password|token|secret|Bearer|Authorization)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Sensitive data in logs" "Mask or remove secrets"
  show_detailed_finding "logger\.(debug|info|warn|error|fatal)\(.*(password|token|secret|Bearer|Authorization)" 3
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: PERFORMANCE & MEMORY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 12; then
print_header "12. PERFORMANCE & MEMORY"
print_category "Detects: string concat in loops, regex compile in loops, gsub in loops" \
  "Micro-optimizations can matter in hot paths."

print_subheader "String concatenation in loops"
count=$("${GREP_RN[@]}" -e "for[[:space:]]|each[[:space:]]+do|\bwhile[[:space:]]" "$PROJECT_DIR" 2>/dev/null | (grep -E -A3 "<<|\+=\"" || true) | (grep -E -cw "<<|\+=\"" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "String concat in loops" "Use String#<< with capacity or Array#join"
fi

print_subheader "Regexp.new / %r in loops (compile each iteration)"
count=$("${GREP_RN[@]}" -e "for[[:space:]]|each[[:space:]]+do|\bwhile[[:space:]]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -A3 "Regexp\.new\(|%r\{" || true) | (grep -E -cw "Regexp\.new|%r\{" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Regex compiled in loop" "Precompile outside loop"
fi

print_subheader "gsub in loops"
count=$("${GREP_RN[@]}" -e "for[[:space:]]|each[[:space:]]+do|\bwhile[[:space:]]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -A3 "\.gsub\(" || true) | (grep -E -cw "\.gsub\(" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "gsub in loops" "Consider bulk operations"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: VARIABLE & SCOPE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 13; then
print_header "13. VARIABLE & SCOPE"
print_category "Detects: global variables, class variables, monkey patching core" \
  "Scope issues cause hard-to-debug conflicts and side effects."

print_subheader "Global variables (\$var)"
count=$("${GREP_RN[@]}" -e "[$][A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "warning" "$count" "Use of global variables" "Prefer dependency injection or constants"
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Some globals present"
fi

print_subheader "Class variables (@@var)"
count=$("${GREP_RN[@]}" -e "@@[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Class variables used" "Prefer class instance variables"
fi

print_subheader "Core class reopen (monkey patch)"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*class[[:space:]]+(String|Array|Hash|Numeric|Integer|Float|Symbol|Object|Kernel)\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Monkey patching core classes"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: CODE QUALITY MARKERS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 14; then
print_header "14. CODE QUALITY MARKERS"
print_category "Detects: TODO, FIXME, HACK, XXX, NOTE" \
  "Technical debt markers indicate incomplete or problematic code."

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
print_category "Detects: ReDoS, dynamic regex with input, escaping issues" \
  "Regex bugs cause performance issues and security vulnerabilities."

print_subheader "Nested quantifiers (ReDoS risk)"
count=$("${GREP_RN[@]}" -e "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Potential catastrophic regex" "Use atomic groups or simplify patterns"
  show_detailed_finding "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" 2
fi

print_subheader "Regexp.new from variables"
count=$("${GREP_RN[@]}" -e "Regexp\.new\([[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Dynamic regex construction" "Sanitize inputs or anchor carefully"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: CONCURRENCY & PARALLELISM
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. CONCURRENCY & PARALLELISM"
print_category "Detects: Thread.new without join, Ractor misuse patterns" \
  "Concurrency bugs lead to leaks and nondeterminism."

print_subheader "Thread.new without join at callsite"
count=$("${GREP_RN[@]}" -e "Thread\.new\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E -v "\.join|\bjoin\b" || true) | count_lines )
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Detached threads" "Ensure lifecycle, join, or thread pool"
fi

print_subheader "Ractor.new heavy usage"
count=$("${GREP_RN[@]}" -e "Ractor\.new\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Ractor usage - verify isolation & shareable objects"; fi

run_async_error_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: RUBY/RAILS PRACTICALS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 17; then
print_header "17. RUBY/RAILS PRACTICALS"
print_category "Detects: frozen_string_literal pragma, mass assignment hints, csrf skip" \
  "Rails conventions and Ruby pragmas that impact safety/perf."

print_subheader "Missing 'frozen_string_literal: true' pragma (heuristic)"
rb_files=$(
  ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name "*.rb" -print \) 2>/dev/null || true )
)
missing_pragma=0
while IFS= read -r f; do
  # check first two lines for pragma
  if ! head -n 2 "$f" 2>/dev/null | grep -q "frozen_string_literal:\s*true"; then
    missing_pragma=$((missing_pragma+1))
  fi
done <<<"$rb_files"
if [ "$missing_pragma" -gt 25 ]; then
  print_finding "info" "$missing_pragma" "Files missing frozen_string_literal pragma" "Consider enabling globally if beneficial"
fi

print_subheader "Rails: protect_from_forgery skipped?"
count=$("${GREP_RN[@]}" -e "skip_before_action[[:space:]]+:verify_authenticity_token" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "CSRF protections skipped in controllers"; fi

print_subheader "Rails: strong parameters bypass (permit!)"
count=$("${GREP_RN[@]}" -e "\.permit!\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Strong params permit! found - review carefully"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 18: AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 18; then
print_header "AST-GREP RULE PACK FINDINGS"
  if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
    if [[ "$AG_PREVIEW_FIX" -eq 1 ]]; then
      run_ast_rules
    elif [[ "$FORMAT" == "sarif" || -n "$SARIF_OUT" ]]; then
      if run_ast_rules | tee "${SARIF_OUT:-/dev/null}" >/dev/null; then
        [[ "$FORMAT" == "sarif" ]] && exit 0
      fi
    elif [[ "$FORMAT" == "json" || -n "$JSON_OUT" ]]; then
      if run_ast_rules | tee "${JSON_OUT:-/dev/null}" >/dev/null; then
        [[ "$FORMAT" == "json" ]] && exit 0
      fi
    else
      run_ast_rules || say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
    fi
  else
    say "${YELLOW}${WARN} ast-grep not available; install ast-grep or skip category 18.${RESET}"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: BUNDLER-POWERED EXTRA ANALYZERS (optional)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 19; then
print_header "19. BUNDLER-POWERED EXTRA ANALYZERS"
print_category "Rubocop (lint), Brakeman (Rails security), Bundler-Audit (deps), Reek (smells), Fasterer (perf)" \
  "These tools augment ast-grep/rg results."

if [[ "$ENABLE_BUNDLER_TOOLS" -eq 1 ]]; then
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
else
  say "  ${GRAY}${INFO} bundler-based analyzers disabled (--no-bundler)${RESET}"
fi
fi

# restore pipefail if we relaxed it
end_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

# If machine format is requested globally, produce pure output and exit
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  # run_ast_rules already streamed the artifact and exited earlier.
  exit 0
fi

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
if [[ -n "$SUMMARY_JSON" ]]; then
  mkdir -p "$(dirname "$SUMMARY_JSON")" 2>/dev/null || true
  printf '{"timestamp":"%s","files":%s,"critical":%s,"warning":%s,"info":%s}\n' \
     "$(eval "$DATE_CMD")" "$TOTAL_FILES" "$CRITICAL_COUNT" "$WARNING_COUNT" "$INFO_COUNT" >"$SUMMARY_JSON"
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning . > rb-bug-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
exit "$EXIT_CODE"
