#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# PYTHON ULTIMATE BUG SCANNER v3.1 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Python (3.13+) using:
#   • ast-grep (rule packs; language: python)
#   • ripgrep/grep heuristics for fast code smells
#   • optional uv-powered extra analyzers (ruff, bandit, pip-audit, mypy, safety, detect-secrets)
#   • optional mypy/pyright (if installed) for type-checking touchpoints
#
# Focus:
#   • None/defensive checks   • exceptions & error handling
#   • async/await pitfalls    • security & supply-chain risks
#   • subprocess misuse       • I/O & resource handling
#   • typing hygiene          • regex safety (ReDoS)
#   • code quality markers    • performance & style hazards
#
# Supports:
#   --format text|json|sarif (ast-grep passthrough for json/sarif)
#   --rules DIR   (merge user ast-grep rules)
#   --fail-on-warning, --skip, --jobs, --include-ext, --exclude, --ci, --no-color, --force-color
#   --summary-json FILE  (machine-readable run summary with rule histogram)
#   --max-detailed N     (cap detailed code samples)
#   --list-categories    (print category index and exit)
#   --timeout-seconds N  (global external tool timeout budget)
#   --baseline FILE      (compare current totals to prior summary JSON)
#   --max-file-size SIZE (ripgrep limit, e.g., 25M)
#
# CI-friendly timestamps, robust find, safe pipelines, auto parallel jobs.
# Heavily leverages ast-grep for Python via rule packs; complements with rg.
# Integrates uv (if installed) to run ruff/bandit/pip-audit/mypy without setup.
# Adds portable timeout resolution (timeout/gtimeout) and UTF‑8-safe output.
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob
shopt -s compat31 || true

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2
  exit "$ec"
}
trap on_err ERR

# Honor NO_COLOR and non-tty
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi
FORCE_COLOR=0

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
  BOLD=''; DIM=''; RESET=''
fi

# Symbols (ensure UTF-8 output; run grep under LC_ALL=C separately)
SAFE_LOCALE="C"
if locale -a 2>/dev/null | grep -qiE '^(C\.UTF-8|en_US\.UTF-8)$'; then SAFE_LOCALE="C.UTF-8"; fi
export LC_CTYPE="${SAFE_LOCALE}"
export LC_MESSAGES="${SAFE_LOCALE}"
export LANG="${SAFE_LOCALE}"

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; ROCKET="🚀"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
CI_MODE=0
FAIL_ON_WARNING=0
BASELINE=""
LIST_CATEGORIES=0
MAX_FILE_SIZE="${MAX_FILE_SIZE:-25M}"
INCLUDE_EXT="py,pyi,pyx,pxd,pxi,ipynb"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1
ENABLE_UV_TOOLS=${ENABLE_UV_TOOLS:-1}               # try uv integrations by default
UV_TOOLS=${UV_TOOLS:-"ruff,bandit,pip-audit"}      # subset via --uv-tools=
UV_TIMEOUT="${UV_TIMEOUT:-1200}"      # generous time budget per tool
ENABLE_EXTRA_TOOLS=1                  # mypy/safety/detect-secrets if present
SUMMARY_JSON=""
TIMEOUT_CMD=""                        # resolved later
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"
AST_PASSTHROUGH=0
AST_TEXT_SUMMARY=1

# Category filtering from meta-runner (e.g., UBS_CATEGORY_FILTER=resource-lifecycle)
CATEGORY_WHITELIST=""
case "${UBS_CATEGORY_FILTER:-}" in
  resource-lifecycle)
    CATEGORY_WHITELIST="16,19"
    ;;
esac

if [[ "${UBS_PROFILE:-}" == "loose" ]]; then
  # Skip Debug/Prod(11) and Code Quality(14) in loose mode
  if [[ -z "$SKIP_CATEGORIES" ]]; then
    SKIP_CATEGORIES="11,14"
  else
    SKIP_CATEGORIES="$SKIP_CATEGORIES,11,14"
  fi
fi

# Async error coverage metadata
ASYNC_ERROR_RULE_IDS=(py.async.task-no-await)
declare -A ASYNC_ERROR_SUMMARY=(
  [py.async.task-no-await]='asyncio.create_task result ignored'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [py.async.task-no-await]='Await or cancel tasks created with asyncio.create_task'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [py.async.task-no-await]='warning'
)

# Taint analysis metadata
TAINT_RULE_IDS=(py.taint.xss py.taint.sql py.taint.command py.taint.eval)
declare -A TAINT_SUMMARY=(
  [py.taint.xss]='Unsanitized request data reaches HTML/response sinks'
  [py.taint.sql]='User input flows into SQL execute() without parameters'
  [py.taint.command]='User input reaches subprocess/os.system'
  [py.taint.eval]='User input flows into eval/exec'
)
declare -A TAINT_REMEDIATION=(
  [py.taint.xss]='Escape or sanitize template context (html.escape, mark_safe only on trusted data)'
  [py.taint.sql]='Use parameterized queries (cursor.execute(sql, params)) or ORM query bindings'
  [py.taint.command]='Use shlex.quote or pass args list with shell=False'
  [py.taint.eval]='Avoid eval/exec on user input; whitelist actions explicitly'
)
declare -A TAINT_SEVERITY=(
  [py.taint.xss]='critical'
  [py.taint.sql]='critical'
  [py.taint.command]='critical'
  [py.taint.eval]='critical'
)

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  --list-categories       Print numbered categories and exit
  --timeout-seconds=N     Override global per-tool timeout budget (also sets UV_TIMEOUT)
  --baseline=FILE         Compare against a previous run's summary JSON and show deltas
  --max-file-size=SIZE    Limit ripgrep file size (e.g. 10M, 250M). Default: $MAX_FILE_SIZE
  --force-color           Force ANSI even if not TTY (overrides auto disable)
  -v, --verbose           More code samples per finding (DETAIL=10)
  -q, --quiet             Reduce non-essential output
  --format=FMT            Output format: text|json|sarif (default: text)
  --ci                    CI mode (no clear, stable timestamps)
  --no-color              Force disable ANSI color
  --include-ext=CSV       File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]     Additional glob(s)/dir(s) to exclude
  --jobs=N                Parallel jobs for ripgrep (default: auto)
  --skip=CSV              Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning       Exit non-zero on warnings or critical
  --rules=DIR             Additional ast-grep rules directory (merged)
  --no-uv                 Disable uv-powered extra analyzers
  --uv-tools=CSV          Which uv tools to run (default: $UV_TOOLS)
  --summary-json=FILE     Also write machine-readable summary JSON
  --max-detailed=N        Cap number of detailed code samples (default: $MAX_DETAILED)
  -h, --help              Show help
Env:
  JOBS, NO_COLOR, CI, UV_TIMEOUT, TIMEOUT_SECONDS, MAX_FILE_SIZE, UBS_CATEGORY_FILTER
Args:
  PROJECT_DIR             Directory to scan (default: ".")
  OUTPUT_FILE             File to save the report (optional)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --force-color) FORCE_COLOR=1; shift;;
    --timeout-seconds=*) TIMEOUT_SECONDS="${1#*=}"; UV_TIMEOUT="$TIMEOUT_SECONDS"; shift;;
    --baseline=*) BASELINE="${1#*=}"; shift;;
    --list-categories) LIST_CATEGORIES=1; shift;;
    --max-file-size=*) MAX_FILE_SIZE="${1#*=}"; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --no-uv)      ENABLE_UV_TOOLS=0; shift;;
    --uv-tools=*) UV_TOOLS="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --max-detailed=*) MAX_DETAILED="${1#*=}"; shift;;
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

# Category index helper
if [[ "$LIST_CATEGORIES" -eq 1 ]]; then
  cat <<'CAT'
1 None/Defensive  2 Numeric/Arithmetic  3 Collections  4 Comparison/Type
5 Async/Await     6 Error Handling      7 Security     8 Functions/Scope
9 Parsing/Convert 10 Control Flow       11 Debug/Prod  12 Perf/Memory
13 Vars/Scope     14 Code Quality       15 Regex       16 I/O & Resources
17 Typing         18 Module Usage       19 Lifecycle   20 Extra Analyzers
21 Deprecations   22 Packaging/Config   23 Notebooks
CAT
  exit 0
fi

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ -n "${OUTPUT_FILE}" && "$FORCE_COLOR" -eq 0 && "$NO_COLOR_FLAG" -eq 0 ]]; then
  USE_COLOR=0
fi

# Redirect output early to capture everything
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

safe_date() {
  if [[ "$CI_MODE" -eq 1 ]]; then command date -u '+%Y-%m-%dT%H:%M:%SZ' || command date '+%Y-%m-%dT%H:%M:%SZ'; else command date '+%Y-%m-%d %H:%M:%S'; fi
}
DATE_CMD="safe_date"

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
HAS_RIPGREP=0
UVX_CMD=()           # (uvx -q or uv -qx) if available
HAS_UV=0
RG_MAX_SIZE_FLAGS=()

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(file_handle socket_handle popen_handle asyncio_task)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [file_handle]="critical"
  [socket_handle]="warning"
  [popen_handle]="warning"
  [asyncio_task]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [file_handle]='open\('
  [socket_handle]='socket\.socket\('
  [popen_handle]='subprocess\.Popen\('
  [asyncio_task]='asyncio\.create_task'
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [file_handle]='\.close\(|with[[:space:]]+[[:alnum:]_.]*open'
  [socket_handle]='\.close\('
  [popen_handle]='\.wait\(|\.communicate\(|\.terminate\(|\.kill\('
  [asyncio_task]='\.cancel\(|await[[:space:]]+asyncio\.(gather|wait)'
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [file_handle]='File handles opened without context manager/close'
  [socket_handle]='Sockets opened without matching close()'
  [popen_handle]='Popen handles not waited or terminated'
  [asyncio_task]='asyncio tasks spawned without cancellation/await'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [file_handle]='Use "with open(...)" or explicitly call .close()'
  [socket_handle]='Use contextlib closing() or call sock.close() in finally/defer'
  [popen_handle]='Capture the Popen object and call wait/communicate/terminate on it'
  [asyncio_task]='Await the task result or cancel/monitor it before shutdown'
)

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep) + include/exclude
# ────────────────────────────────────────────────────────────────────────────
# Keep printing UTF-8 while running grep in C-locale
GREP_ENV=(env LC_ALL=C)

IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done

EXCLUDE_DIRS=(.git .hg .svn .bzr .tox .nox .venv venv env .mypy_cache .pytest_cache __pycache__ .ruff_cache .cache .coverage dist build site-packages .eggs .pdm-build .poetry .idea .vscode .history .ipynb_checkpoints .pytype .hypothesis .maturin .hatch .pants .ninja)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
  HAS_RIPGREP=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  if [[ "${JOBS}" -le 0 ]]; then JOBS=1; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden --pcre2 "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=()
  for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  RG_MAX_SIZE_FLAGS=(--max-filesize "$MAX_FILE_SIZE")
  GREP_RN=("${GREP_ENV[@]}" rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
  GREP_RNI=("${GREP_ENV[@]}" rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
  GREP_RNW=("${GREP_ENV[@]}" rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -w -E)
fi

# Helper: robust numeric end-of-pipeline counter
count_lines() { awk 'END{print (NR+0)}'; }
num_clamp() { local v=${1:-0}; printf '%s' "$v" | awk 'END{print ($0+0)}'; }

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
  print_subheader "Resource lifecycle correlation"
  local helper="$SCRIPT_DIR/helpers/resource_lifecycle_py.py"
  if [[ -f "$helper" ]] && command -v python3 >/dev/null 2>&1; then
    local output
    if output=$(python3 "$helper" "$PROJECT_DIR" 2>/dev/null); then
      if [[ -z "$output" ]]; then
        print_finding "good" "All tracked resource acquisitions have matching cleanups"
      else
        while IFS=$'\t' read -r location kind message; do
          [[ -z "$location" ]] && continue
          local summary="${RESOURCE_LIFECYCLE_SUMMARY[$kind]:-Resource imbalance}"
          local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$kind]:-Ensure matching cleanup call}"
          local severity="${RESOURCE_LIFECYCLE_SEVERITY[$kind]:-warning}"
          local detail="$remediation"
          [[ -n "$message" ]] && detail="$message"
          print_finding "$severity" 1 "$summary [$location]" "$detail"
        done <<<"$output"
      fi
      return
    else
      print_finding "info" 0 "AST helper failed" "See stderr for details"
    fi
  else
    if [[ ! -f "$helper" ]]; then
      print_finding "info" 0 "Resource helper missing" "Expected $helper"
    elif ! command -v python3 >/dev/null 2>&1; then
      print_finding "info" 0 "python3 not available" "Install Python 3 to run AST helper"
    fi
  fi

  # Regex fallback
  local rid
  local header_shown=0
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
      local context_hits=0
      if [[ "$rid" == "file_handle" ]]; then
        context_hits=$("${GREP_RN[@]}" -e "with[[:space:]]+[[:alnum:]_.]*open" "$file" 2>/dev/null | count_lines || true)
      fi
      acquire_hits=${acquire_hits:-0}
      release_hits=${release_hits:-0}
      if (( acquire_hits > release_hits )); then
        if [[ $header_shown -eq 0 ]]; then
          header_shown=1
        fi
        local delta=$((acquire_hits - release_hits))
        local relpath=${file#"$PROJECT_DIR"/}
        [[ "$relpath" == "$file" ]] && relpath="$file"
        local summary="${RESOURCE_LIFECYCLE_SUMMARY[$rid]:-Resource imbalance}"
        local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$rid]:-Ensure matching cleanup call}"
        local severity="${RESOURCE_LIFECYCLE_SEVERITY[$rid]:-warning}"
        local extra=""
        if [[ "$rid" == "file_handle" ]]; then
          extra=", context-managed=${context_hits:-0}"
        fi
        local desc="$remediation (acquire=$acquire_hits, release=$release_hits$extra)"
        print_finding "$severity" "$delta" "$summary [$relpath]" "$desc"
      fi
    done <<<"$file_list"
  done
  if [[ $header_shown -eq 0 ]]; then
    print_finding "good" "All tracked resource acquisitions have matching cleanups"
  fi
}

run_async_error_checks() {
  print_subheader "Async error path coverage"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
    print_finding "info" 0 "ast-grep not available" "Install ast-grep to enable async error coverage"
    return
  fi
  local rule_dir tmp_json
  rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t py_async_rules.XXXXXX)"
  if [[ ! -d "$rule_dir" ]]; then
    print_finding "info" 0 "temp dir creation failed" "Unable to stage ast-grep rules"
    return
  fi
  cat >"$rule_dir/py.async.task-no-await.yml" <<'YAML'
id: py.async.task-no-await
language: python
rule:
  pattern: $TASK = asyncio.create_task($ARGS)
  not:
    any:
      - inside: { pattern: await $TASK }
      - inside: { pattern: $TASK.cancel() }
      - inside: { pattern: $TASK.add_done_callback($CB) }
severity: warning
message: "asyncio.create_task result neither awaited nor cancelled"
YAML
  tmp_json="$(mktemp 2>/dev/null || mktemp -t py_async_matches.XXXXXX)"
  : >"$tmp_json"
  local rule_file
  for rule_file in "$rule_dir"/*.yml; do
    if ! "${AST_GREP_CMD[@]}" scan -r "$rule_file" "$PROJECT_DIR" --json=stream >>"$tmp_json" 2>/dev/null; then
      rm -rf "$rule_dir"
      rm -f "$tmp_json"
      print_finding "info" 0 "ast-grep scan failed" "Unable to compute async error coverage"
      return
    fi
  done
  rm -rf "$rule_dir"
  if ! [[ -s "$tmp_json" ]]; then
    rm -f "$tmp_json"
    print_finding "good" "All async operations appear protected"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r rid count samples; do
    [[ -z "$rid" ]] && continue
    printed=1
    local severity=${ASYNC_ERROR_SEVERITY[$rid]:-warning}
    local summary=${ASYNC_ERROR_SUMMARY[$rid]:-$rid}
    local desc=${ASYNC_ERROR_REMEDIATION[$rid]:-"Handle async errors"}
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
        rid = obj.get('rule_id') or obj.get('id') or obj.get('ruleId')
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
    print_finding "good" "All async operations appear protected"
  fi
}

run_taint_analysis_checks() {
  print_subheader "Lightweight taint analysis"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable taint flow checks"
    return
  fi
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
import re, sys, os
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
EXTS = {'.py', '.pyi'}
PATH_LIMIT = 5

SOURCE_PATTERNS = [
    re.compile(r"request\.(?:args|get_json|json|form|values|data|body|GET|POST)", re.IGNORECASE),
    re.compile(r"flask\.request", re.IGNORECASE),
    re.compile(r"django\.http\.request", re.IGNORECASE),
    re.compile(r"input\s*\(", re.IGNORECASE),
    re.compile(r"raw_input\s*\(", re.IGNORECASE),
    re.compile(r"sys\.argv", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"event\['body'\]", re.IGNORECASE),
    re.compile(r"params\[[^\]]+\]", re.IGNORECASE),
]

SANITIZER_REGEXES = [
    re.compile(r"html\.escape"),
    re.compile(r"django\.utils\.html\.escape"),
    re.compile(r"flask\.escape"),
    re.compile(r"mark_safe"),
    re.compile(r"bleach\.clean"),
    re.compile(r"shlex\.quote"),
    re.compile(r"urllib\.parse\.quote"),
]

SINKS = [
    (re.compile(r"render_template(?:_string)?\s*\((.+)\)"), 'py.taint.xss', 'render_template'),
    (re.compile(r"HttpResponse\((.+)\)"), 'py.taint.xss', 'HttpResponse'),
    (re.compile(r"Response\((.+)\)"), 'py.taint.xss', 'Flask Response'),
    (re.compile(r"(?:cursor|session|conn)\.(?:execute|executemany)\s*\((.+)\)"), 'py.taint.sql', 'SQL execute'),
    (re.compile(r"(?:engine|db)\.(?:execute|text)\s*\((.+)\)"), 'py.taint.sql', 'SQL engine execute'),
    (re.compile(r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\((.+)\)"), 'py.taint.command', 'subprocess execution'),
    (re.compile(r"os\.(?:system|popen|execv)\s*\((.+)\)"), 'py.taint.command', 'os command execution'),
    (re.compile(r"eval\s*\((.+)\)"), 'py.taint.eval', 'eval'),
    (re.compile(r"exec\s*\((.+)\)"), 'py.taint.eval', 'exec'),
]

ASSIGN_SIMPLE = re.compile(r"^(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*=\s*(?P<expr>.+)")

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file(): continue
        if should_skip(path): continue
        if path.suffix.lower() in EXTS: yield path

def strip_comments(line: str) -> str:
    if '#' in line:
        idx = line.find('#')
        if idx >= 0: line = line[:idx]
    return line

def parse_assignments(lines):
    assignments = []
    for idx, raw in enumerate(lines, start=1):
        line = strip_comments(raw).strip()
        if not line or '=' not in line: continue
        if '==' in line or '>=' in line or '<=' in line or '!=' in line: continue
        match = ASSIGN_SIMPLE.match(line)
        if not match: continue
        lhs = match.group('targets'); expr = match.group('expr')
        for target in [t.strip() for t in lhs.split(',') if t.strip()]:
            assignments.append((idx, target, expr))
    return assignments

def find_sources(expr: str):
    matches = []
    for regex in SOURCE_PATTERNS:
        for m in regex.finditer(expr):
            matches.append(m.group(0))
    return matches

def expr_has_sanitizer(expr: str, sink_rule: str | None = None) -> bool:
    expr_lower = expr.lower()
    for regex in SANITIZER_REGEXES:
        if regex.search(expr_lower): return True
    if sink_rule == 'py.taint.sql':
        if re.search(r'%(?!\()|\.format\(|f["\']', expr): return False
        if re.search(r",\s*(?:\(|\[|params|data|values|bindings)", expr_lower): return True
    return False

def expr_has_tainted(expr: str, tainted):
    for name, meta in tainted.items():
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
        if re.search(pattern, expr): return name, meta
    return None, None

def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        if expr_has_sanitizer(expr, None): continue
        sources = find_sources(expr)
        if sources:
            tainted[target] = {'source': sources[0], 'line': line_no, 'path': [sources[0], target]}
    for _ in range(5):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr, None): continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                new_path = list(meta.get('path', [ref]))
                if len(new_path) >= 5: new_path = new_path[-4:]
                new_path.append(target)
                tainted[target] = {'source': meta.get('source', ref), 'line': line_no, 'path': new_path}
                changed = True
        if not changed: break
    return tainted

def analyze_file(path, issues):
    try:
        text = path.read_text(encoding='utf-8')
    except Exception:
        return
    lines = text.splitlines()
    assignments = parse_assignments(lines)
    tainted = record_taint(assignments)
    for idx, raw in enumerate(lines, start=1):
        stripped = strip_comments(raw)
        if not stripped: continue
        for regex, rule, label in SINKS:
            match = regex.search(stripped)
            if not match: continue
            expr = match.group(1)
            if not expr or expr_has_sanitizer(expr, rule): continue
            direct = find_sources(expr)
            if direct:
                path_desc = f"{direct[0]} -> {label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref: continue
                seq = list(meta.get('path', [ref]))
                if len(seq) >= 5: seq = seq[-4:]
                seq.append(label)
                path_desc = ' -> '.join(seq)
            try: rel = path.relative_to(ROOT)
            except ValueError: rel = path.name
            sample = f"{rel}:{idx} {path_desc}"
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(sample)

issues = defaultdict(lambda: {'count': 0, 'samples': []})
for file_path in iter_files(ROOT):
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

begin_scan_section(){ if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi; set +e; trap - ERR; }
end_scan_section(){ trap on_err ERR; set -e; if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi; }

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
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang python "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

analyze_py_attr_guards() {
  local limit=${1:-$DETAIL_LIMIT}
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then return 1; fi
  if ! command -v python3 >/dev/null 2>&1; then return 1; fi
  local tmp_attrs tmp_ifs result
  tmp_attrs="$(mktemp -t ubs-py-attrs.XXXXXX 2>/dev/null || mktemp -t ubs-py-attrs)"
  tmp_ifs="$(mktemp -t ubs-py-ifs.XXXXXX 2>/dev/null || mktemp -t ubs-py-ifs)"

  # Attribute chains of depth >= 4
  ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern '$A.$B.$C.$D' --lang python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_attrs"
  # Capture the BODY of any if statement (less brittle)
  ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern $'if $COND:\n  $BODY' --lang python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_ifs"

  result=$(python3 - "$tmp_attrs" "$tmp_ifs" "$limit" <<'PYHELP'
import json, sys
from collections import defaultdict

def load_stream(path):
    data = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: data.append(json.loads(line))
                except json.JSONDecodeError: pass
    except FileNotFoundError: return data
    return data

matches_path, guards_path, limit_raw = sys.argv[1:4]
limit = int(limit_raw)
matches = load_stream(matches_path)
guards = load_stream(guards_path)

def as_pos(node):
    return (node.get('line', 0), node.get('column', 0))

def ge(a, b):
    return a[0] > b[0] or (a[0] == b[0] and a[1] >= b[1])

def le(a, b):
    return a[0] < b[0] or (a[0] == b[0] and a[1] <= b[1])

def within(target, region):
    start, end = target
    rs, re = region
    return ge(start, rs) and le(end, re)

# Store BODY ranges per file
bodies_by_file = defaultdict(list)
for guard in guards:
    file_path = guard.get('file')
    body = guard.get('metaVariables', {}).get('single', {}).get('BODY')
    if not file_path or not body: continue
    rng = body.get('range') or {}
    start = rng.get('start'); end = rng.get('end')
    if not start or not end: continue
    bodies_by_file[file_path].append((as_pos(start), as_pos(end)))

unguarded = 0
guarded = 0
samples = []

for match in matches:
    file_path = match.get('file')
    rng = match.get('range') or {}
    start = rng.get('start'); end = rng.get('end')
    if not file_path or not start or not end: continue
    start_pos = as_pos(start); end_pos = as_pos(end)
    regions = bodies_by_file.get(file_path, [])
    if any(within((start_pos, end_pos), region) for region in regions):
        guarded += 1; continue
    unguarded += 1
    if len(samples) < limit:
        snippet = (match.get('lines') or '').strip()
        samples.append({'file': file_path, 'line': start_pos[0] + 1, 'code': snippet})

print(json.dumps({'unguarded': unguarded, 'guarded': guarded, 'samples': samples}, ensure_ascii=False))
PYHELP
  )

  rm -f "$tmp_attrs" "$tmp_ifs"
  printf '%s' "$result"
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t py_ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # Core Python rules (security, reliability, correctness)
  cat >"$AST_RULE_DIR/none-eq.yml" <<'YAML'
id: py.none-eq
language: python
rule:
  any:
    - pattern: $X == None
    - pattern: $X != None
severity: warning
message: "Use 'is (not) None' instead of '== None' or '!= None'"
YAML

  cat >"$AST_RULE_DIR/is-literal.yml" <<'YAML'
id: py.is-literal
language: python
rule:
  any:
    - pattern: $X is True
    - pattern: $X is False
    - pattern: $X is 0
    - pattern: $X is 1
severity: warning
message: "Avoid 'is' for literal comparison; use '==' (except None uses 'is')"
YAML

  # Broad except and suppress
  cat >"$AST_RULE_DIR/except-broad.yml" <<'YAML'
id: py.except-broad
language: python
rule: { pattern: "except Exception as $E:\n  $B" }
severity: warning
message: "Catches broad Exception; consider narrowing"
YAML

  cat >"$AST_RULE_DIR/bare-except.yml" <<'YAML'
id: py.bare-except
language: python
rule:
  pattern: |
    try:
      $A
    except:
      $B
severity: error
message: "Bare 'except' catches all exceptions including SystemExit/KeyboardInterrupt"
YAML

  cat >"$AST_RULE_DIR/except-pass.yml" <<'YAML'
id: py.except-pass
language: python
rule:
  pattern: |
    try:
      $X
    except $E as $N:
      pass
severity: warning
message: "Exception swallowed with 'pass'; log or re-raise"
YAML

  cat >"$AST_RULE_DIR/raise-e.yml" <<'YAML'
id: py.raise-e
language: python
rule:
  pattern: |
    except $E as $ex:
      raise $ex
severity: warning
message: "Use 'raise' to preserve traceback, not 'raise e'"
YAML

  cat >"$AST_RULE_DIR/mutable-defaults.yml" <<'YAML'
id: py.mutable-defaults
language: python
rule:
  any:
    - pattern: |
        def $NAME($A = [], $$):
          $BODY
    - pattern: |
        def $NAME($A = {}, $$):
          $BODY
    - pattern: |
        def $NAME($A = set(), $$):
          $BODY
severity: error
message: "Mutable default argument; use default=None and set in body"
YAML

  cat >"$AST_RULE_DIR/eval-exec.yml" <<'YAML'
id: py.eval-exec
language: python
rule:
  any:
    - pattern: eval($$)
    - pattern: exec($$)
severity: error
message: "Avoid eval/exec; leads to code injection"
YAML

  cat >"$AST_RULE_DIR/pickle-load.yml" <<'YAML'
id: py.pickle-load
language: python
rule:
  any:
    - pattern: pickle.load($$)
    - pattern: pickle.loads($$)
severity: error
message: "Unpickling untrusted data is insecure; prefer safer formats"
YAML

  cat >"$AST_RULE_DIR/yaml-unsafe.yml" <<'YAML'
id: py.yaml-unsafe
language: python
rule:
  pattern: yaml.load($ARGS)
  not:
    has:
      pattern: Loader=$L
severity: error
message: "yaml.load without Loader=SafeLoader; prefer yaml.safe_load"
YAML

  cat >"$AST_RULE_DIR/subprocess-shell.yml" <<'YAML'
id: py.subprocess-shell
language: python
rule:
  any:
    - pattern: subprocess.run($$, shell=True)
    - pattern: subprocess.call($$, shell=True)
    - pattern: subprocess.check_output($$, shell=True)
    - pattern: subprocess.Popen($$, shell=True)
severity: error
message: "shell=True is dangerous; prefer exec array with shell=False"
YAML

  cat >"$AST_RULE_DIR/os-system.yml" <<'YAML'
id: py.os-system
language: python
rule:
  pattern: os.system($$)
severity: warning
message: "os.system is shell-invocation; prefer subprocess without shell"
YAML

  cat >"$AST_RULE_DIR/requests-verify.yml" <<'YAML'
id: py.requests-verify
language: python
rule:
  any:
    - pattern: requests.$M($URL, $$, verify=False)
    - pattern: requests.$M($URL, verify=False, $$)
    - pattern: requests.$M($URL, verify = False, $$)
severity: warning
message: "requests with verify=False disables TLS verification"
YAML

  cat >"$AST_RULE_DIR/hashlib-weak.yml" <<'YAML'
id: py.hashlib-weak
language: python
rule:
  any:
    - pattern: hashlib.md5($$)
    - pattern: hashlib.sha1($$)
severity: warning
message: "Weak hash algorithm (md5/sha1); prefer sha256/sha512"
YAML

  cat >"$AST_RULE_DIR/random-secrets.yml" <<'YAML'
id: py.random-secrets
language: python
rule:
  any:
    - pattern: random.random($$)
    - pattern: random.randint($$)
    - pattern: random.randrange($$)
    - pattern: random.choice($$)
    - pattern: random.choices($$)
severity: info
message: "random module is not cryptographically secure; use secrets module"
YAML

  cat >"$AST_RULE_DIR/open-no-with.yml" <<'YAML'
id: py.open-no-with
language: python
rule:
  pattern: open($$)
  not:
    inside:
      pattern: |
        with open($$) as $F:
          $BODY
severity: warning
message: "open() outside of a 'with' block; risk of leaking file handles"
YAML

  cat >"$AST_RULE_DIR/open-no-encoding.yml" <<'YAML'
id: py.open-no-encoding
language: python
rule:
  any:
    - pattern: open($FNAME)
    - pattern: pathlib.Path($P).open($$)
  not:
    has:
      pattern: encoding=$ENC
  not:
    any:
      - has: { pattern: "mode='b'" }
      - has: { pattern: "mode=\"b\"" }
      - has: { pattern: "mode='rb'" }
      - has: { pattern: "mode=\"rb\"" }
severity: info
message: "open() without encoding=... may be non-deterministic across locales"
YAML

  cat >"$AST_RULE_DIR/resource-open-no-close.yml" <<'YAML'
id: py.resource.open-no-close
language: python
rule:
  pattern: $VAR = open($ARGS)
  not:
    inside:
      pattern: $VAR.close()
severity: warning
message: "open() assigned to a variable without close() in the same block."
YAML

  cat >"$AST_RULE_DIR/resource-popen-no-wait.yml" <<'YAML'
id: py.resource.Popen-no-wait
language: python
rule:
  pattern: $PROC = subprocess.Popen($ARGS)
  not:
    inside:
      pattern: $PROC.wait()
  not:
    inside:
      pattern: $PROC.communicate($$)
  not:
    inside:
      pattern: $PROC.terminate()
  not:
    inside:
      pattern: $PROC.kill()
severity: warning
message: "subprocess.Popen handle created without wait/communicate/terminate in the same scope."
YAML

  cat >"$AST_RULE_DIR/resource-asyncio-task.yml" <<'YAML'
id: py.resource.asyncio-task-no-await
language: python
rule:
  pattern: $TASK = asyncio.create_task($ARGS)
  not:
    inside:
      pattern: await $TASK
  not:
    inside:
      pattern: $TASK.cancel()
severity: warning
message: "asyncio.create_task result neither awaited nor cancelled."
YAML

  cat >"$AST_RULE_DIR/assert-used.yml" <<'YAML'
id: py.assert-used
language: python
rule:
  pattern: assert $COND
severity: info
message: "assert is stripped with -O; avoid for runtime checks"
YAML

  cat >"$AST_RULE_DIR/datetime-naive.yml" <<'YAML'
id: py.datetime-naive
language: python
rule:
  any:
    - pattern: datetime.datetime.utcnow($$)
    - pattern: datetime.datetime.now()
severity: info
message: "Naive datetime; prefer timezone-aware (e.g., datetime.now(tz=UTC))"
YAML

  cat >"$AST_RULE_DIR/type-equality.yml" <<'YAML'
id: py.type-equality
language: python
rule:
  any:
    - pattern: type($X) == $T
    - pattern: type($X) is $T
severity: warning
message: "Use isinstance(x, T) instead of type(x) == T"
YAML

  cat >"$AST_RULE_DIR/wildcard-import.yml" <<'YAML'
id: py.wildcard-import
language: python
rule:
  pattern: from $M import *
severity: warning
message: "Wildcard import pollutes namespace; import names explicitly"
YAML

  cat >"$AST_RULE_DIR/importlib-dynamic.yml" <<'YAML'
id: py.importlib-dynamic
language: python
rule:
  any:
    - pattern: __import__($NAME)
    - pattern: importlib.import_module($NAME)
severity: info
message: "Dynamic imports hinder static analysis and packaging"
YAML

  cat >"$AST_RULE_DIR/async-blocking.yml" <<'YAML'
id: py.async-blocking
language: python
rule:
  pattern: |
    async def $FN($$):
      $STMTS
  has:
    any:
      - pattern: time.sleep($$)
      - pattern: requests.$M($$)
      - pattern: subprocess.run($$)
      - pattern: open($$)
severity: warning
message: "Blocking call inside async function; consider async equivalent"
YAML

  cat >"$AST_RULE_DIR/await-in-loop.yml" <<'YAML'
id: py.await-in-loop
language: python
rule:
  pattern: |
    for $I in $IT:
      await $CALL
severity: info
message: "await inside loops may be slow; consider gathering with asyncio.gather"
YAML

  cat >"$AST_RULE_DIR/tempfile-mktemp.yml" <<'YAML'
id: py.tempfile-mktemp
language: python
rule:
  pattern: tempfile.mktemp($$)
severity: error
message: "tempfile.mktemp is insecure; use NamedTemporaryFile or mkstemp"
YAML

  cat >"$AST_RULE_DIR/sql-fstring.yml" <<'YAML'
id: py.sql-fstring
language: python
rule:
  regex: 'f"\\s*SELECT\\s+.*"'
severity: warning
message: "Interpolated SQL; prefer parameterized queries"
YAML

  cat >"$AST_RULE_DIR/type-ignore-heavy.yml" <<'YAML'
id: py.type-ignore
language: python
rule:
  pattern: "# type: ignore$REST"
severity: info
message: "Frequent 'type: ignore' may hide type issues"
YAML

  cat >"$AST_RULE_DIR/any-typing.yml" <<'YAML'
id: py.any-typing
language: python
rule:
  any:
    - pattern: Any
    - pattern: typing.Any
severity: info
message: "Use precise types; 'Any' weakens type guarantees"
YAML

  cat >"$AST_RULE_DIR/re-catastrophic.yml" <<'YAML'
id: py.re-catastrophic
language: python
rule:
  any:
    - regex: 're\\.compile\\("(.+\\+)+.+"\\)'
    - regex: 're\\.compile\\("(.\\*)\\+"\\)'
severity: warning
message: "Potential catastrophic backtracking; check regex"
YAML

  # Additional high-value rules
  cat >"$AST_RULE_DIR/subprocess-no-check.yml" <<'YAML'
id: py.subprocess-no-check
language: python
rule:
  pattern: subprocess.run($ARGS)
  not:
    has:
      pattern: check=$C
severity: info
message: "subprocess.run without check=... may silently ignore failures; consider check=True"
YAML

  cat >"$AST_RULE_DIR/logging-secrets.yml" <<'YAML'
id: py.logging-secrets
language: python
rule:
  pattern: logging.$L($MSG)
  has:
    any:
      - regex: "(?i)(password|token|secret|apikey|api_key|authorization|bearer)"
severity: warning
message: "Sensitive-looking value referenced in logging call; mask or avoid"
YAML

  cat >"$AST_RULE_DIR/path-join-plus.yml" <<'YAML'
id: py.path-join-plus
language: python
rule:
  pattern: "$BASE + '/' + $NAME"
severity: info
message: "Use os.path.join or pathlib.Path instead of string concatenation for paths"
YAML

  cat >"$AST_RULE_DIR/floating-task.yml" <<'YAML'
id: py.floating-task
language: python
rule:
  pattern: asyncio.create_task($CALL)
  not:
    inside:
      pattern: |
        $VAR = asyncio.create_task($CALL)
severity: warning
message: "create_task() result unused; keep a reference and handle exceptions"
YAML

  # Requests timeout missing
  cat >"$AST_RULE_DIR/requests-timeout-missing.yml" <<'YAML'
id: py.requests-timeout-missing
language: python
rule:
  pattern: requests.$M($URL, $$)
  not:
    has:
      pattern: timeout=$T
severity: info
message: "requests call without timeout=... may hang"
YAML

  # JSON loads without try/except
  cat >"$AST_RULE_DIR/json-loads-no-try.yml" <<'YAML'
id: py.json.loads-no-try
language: python
rule:
  pattern: json.loads($DATA)
  not:
    inside:
      pattern: |
        try:
          $A
        except $E:
          $B
severity: warning
message: "json.loads without exception handling"
YAML

  # SQL interpolation via % and f-strings
  cat >"$AST_RULE_DIR/sql-interpolation-percent.yml" <<'YAML'
id: py.sql-string-format-percent
language: python
rule:
  pattern: $CURSOR.$EXEC("SELECT " + $QS % $ARGS)
severity: warning
message: "Interpolated SQL via % operator; use parameters"
YAML

  cat >"$AST_RULE_DIR/sql-interpolation-fstring.yml" <<'YAML'
id: py.sql-fstring-params
language: python
rule:
  regex: 'execute\\(f["\\\']\\s*(SELECT|UPDATE|INSERT|DELETE)\\b'
severity: warning
message: "Interpolated SQL via f-string; use parameters"
YAML

  # contextlib.suppress broad
  cat >"$AST_RULE_DIR/contextlib-suppress-broad.yml" <<'YAML'
id: py.contextlib-suppress-broad
language: python
rule:
  pattern: contextlib.suppress(Exception)
severity: info
message: "contextlib.suppress(Exception) hides all errors"
YAML

  # aiohttp session not closed
  cat >"$AST_RULE_DIR/aiohttp-session-no-close.yml" <<'YAML'
id: py.aiohttp-session-no-close
language: python
rule:
  pattern: $S = aiohttp.ClientSession($$)
  not:
    inside:
      any:
        - pattern: await $S.close()
        - pattern: async with aiohttp.ClientSession($$) as $S:
severity: warning
message: "aiohttp ClientSession not closed/used as async context manager"
YAML

  # logging.exception without exc_info
  cat >"$AST_RULE_DIR/logging-exc-info.yml" <<'YAML'
id: py.logging-exception-no-exc-info
language: python
rule:
  pattern: logging.$L($MSG)
  not:
    has:
      pattern: exc_info=True
severity: info
message: "logging call missing exc_info=True when reporting exceptions"
YAML

  # Deprecations / 3.13 migration
  cat >"$AST_RULE_DIR/asyncio-get-event-loop-legacy.yml" <<'YAML'
id: py.asyncio.get_event_loop-legacy
language: python
rule:
  pattern: asyncio.get_event_loop()
severity: info
message: "get_event_loop() legacy usage; prefer get_running_loop() or asyncio.run()"
YAML

  cat >"$AST_RULE_DIR/imp-module.yml" <<'YAML'
id: py.imp-module
language: python
rule: { pattern: import imp }
severity: warning
message: "imp is deprecated; use importlib"
YAML

  # Done writing rules
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  if [[ "$FORMAT" == "sarif" ]]; then
    "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --sarif 2>/dev/null || return 1
    AST_PASSTHROUGH=1; return 0
  fi
  if [[ "$FORMAT" == "json" ]]; then
    "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json 2>/dev/null || return 1
    AST_PASSTHROUGH=1; return 0
  fi
  # text summary
  local tmp_stream; tmp_stream="$(mktemp -t ag_stream.XXXXXX 2>/dev/null || mktemp -t ag_stream)"
  ( set +o pipefail; "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_stream"
  if [[ ! -s "$tmp_stream" ]]; then rm -f "$tmp_stream"; return 0; fi
  print_subheader "ast-grep rule-pack summary"
  python3 - "$tmp_stream" "$DETAIL_LIMIT" <<'PY'
import json, sys, collections
path, limit = sys.argv[1], int(sys.argv[2])
buckets = collections.OrderedDict()
def add(obj):
    rid = obj.get('rule_id') or obj.get('id') or 'unknown'
    sev = (obj.get('severity') or '').lower() or 'info'
    file = obj.get('file','?')
    # Suppress asserts in test files
    if rid == 'py.assert-used' and ('test' in file.lower() or 'conftest' in file.lower()):
        return
    rng  = obj.get('range') or {}
    ln = (rng.get('start') or {}).get('row',0)+1
    msg = obj.get('message') or rid
    b = buckets.setdefault(rid, {'severity': sev, 'message': msg, 'count': 0, 'samples': []})
    b['count'] += 1
    if len(b['samples']) < limit:
        code = (obj.get('lines') or '').strip().splitlines()[:1]
        b['samples'].append((file, ln, code[0] if code else ''))
with open(path, 'r', encoding='utf-8') as fh:
    for line in fh:
        line=line.strip()
        if not line: continue
        try: add(json.loads(line))
        except: pass
sev_rank = {'critical':0, 'warning':1, 'info':2, 'good':3}
for rid, data in sorted(buckets.items(), key=lambda kv:(sev_rank.get(kv[1]['severity'],9), -kv[1]['count'])):
    sev = data['severity']; cnt=data['count']; title=data['message']
    if sev=='critical': print(f"__FINDING__\tcritical\t{cnt}\t{rid}\t{title}")
    elif sev=='warning': print(f"__FINDING__\twarning\t{cnt}\t{rid}\t{title}")
    else: print(f"__FINDING__\tinfo\t{cnt}\t{rid}\t{title}")
    for f,l,c in data['samples']:
        s=c.replace('\t',' ').strip()
        print(f"__SAMPLE__\t{f}\t{l}\t{s}")
PY
  while IFS=$'\t' read -r tag a b c d; do
    case "$tag" in
      __FINDING__) print_finding "$a" "$(num_clamp "$b")" "$c: $d" ;;
      __SAMPLE__)  print_code_sample "$a" "$b" "$c" ;;
    esac
  done <"$tmp_stream"
  rm -f "$tmp_stream"
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# uv integrations & timeout resolution
# ────────────────────────────────────────────────────────────────────────────
check_uv() {
  if command -v uvx >/dev/null 2>&1; then UVX_CMD=(uvx -q); HAS_UV=1; return 0; fi
  if command -v uv  >/dev/null 2>&1; then UVX_CMD=(uv -qx); HAS_UV=1; return 0; fi
  HAS_UV=0; return 1
}

resolve_timeout() {
  if [[ "${TIMEOUT_SECONDS:-0}" -gt 0 ]]; then UV_TIMEOUT="$TIMEOUT_SECONDS"; fi
  if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout"; return 0; fi
  if command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout"; return 0; fi
  TIMEOUT_CMD=""
}

run_uv_tool_text() {
  local tool="$1"; shift
  if [[ "$HAS_UV" -eq 1 ]]; then
    if [[ -n "$TIMEOUT_CMD" ]]; then
      ( set +o pipefail; "$TIMEOUT_CMD" "$UV_TIMEOUT" "${UVX_CMD[@]}" "$tool" "$@" || true )
    else
      ( set +o pipefail; "${UVX_CMD[@]}" "$tool" "$@" || true )
    fi
  else
    if command -v "$tool" >/dev/null 2>&1; then
      if [[ -n "$TIMEOUT_CMD" ]]; then
        ( set +o pipefail; "$TIMEOUT_CMD" "$UV_TIMEOUT" "$tool" "$@" || true )
      else
        ( set +o pipefail; "$tool" "$@" || true )
      fi
    fi
  fi
}

run_system_or_uv_tool() {
  local tool="$1"; shift
  if [[ "$HAS_UV" -eq 1 ]]; then ( set +o pipefail; "${UVX_CMD[@]}" "$tool" "$@" || true ); return; fi
  if command -v "$tool" >/dev/null 2>&1; then ( set +o pipefail; "$tool" "$@" || true ); fi
}

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper
# ────────────────────────────────────────────────────────────────────────────
should_skip() {
  local cat="$1"
  if [[ -n "$CATEGORY_WHITELIST" ]]; then
    local allowed=1
    IFS=',' read -r -a allow <<<"$CATEGORY_WHITELIST"
    for s in "${allow[@]}"; do [[ "$s" == "$cat" ]] && allowed=0; done
    [[ $allowed -eq 1 ]] && return 1
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
╔═══════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗   ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝   ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗     ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝     ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗   ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝   ║
║                                                                   ║
║  ██████╗ ██╗   ██╗ ██████╗                /^\/^\                  ║
║  ██╔══██╗██║   ██║██╔════╝              _|__|  O|                 ║
║  ██████╔╝██║   ██║██║  ███╗            /~     \_/ \               ║
║  ██╔══██╗██║   ██║██║   ██║           |__________/ \              ║
║  ██████╔╝╚██████╔╝╚██████╔╝            \_______    \              ║
║  ╚═════╝  ╚═════╝  ╚═════╝                     `\   \             ║
║                                                  |   |            ║
║                                                 /   /             ║
║                                                /   /              ║
║                                                                   ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝       ║
║                                                                   ║
║  Python module • async/await, serialization, venv heuristics      ║
║  UBS module: python • catches None bugs & async blocking          ║
║  ASCII homage: classic snake (ASCII Art Archive)                  ║
║  Run standalone: modules/ubs-python.sh --help                     ║
║                                                                   ║
║  Night Owl QA                                                     ║
║  “We see bugs before you do.”                                     ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(eval "$DATE_CMD")${RESET}"

# Validate target path (allow single files as well as directories)
if [[ ! -e "$PROJECT_DIR" ]]; then
  echo -e "${RED}${BOLD}Project path not found:${RESET} ${WHITE}$PROJECT_DIR${RESET}" >&2
  exit 2
fi

# Resolve portable timeout
resolve_timeout || true

# Count files with robust find / rg
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
if [[ "$HAS_RIPGREP" -eq 1 ]]; then
  TOTAL_FILES=$(
    ( set +o pipefail; rg --files "$PROJECT_DIR" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}" 2>/dev/null || true ) \
    | wc -l | awk '{print $1+0}'
  )
else
  TOTAL_FILES=$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
    | wc -l | awk '{print $1+0}'
  )
fi
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

# ast-grep availability
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

# uv availability
if check_uv; then
  say "${GREEN}${CHECK} uv detected - ${DIM}uvx ephemeral analyzers enabled${RESET}"
else
  say "${YELLOW}${WARN} uv not found - ruff/bandit/pip-audit via system if present${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: NONE / DEFENSIVE PROGRAMMING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. NONE / DEFENSIVE PROGRAMMING"
print_category "Detects: None equality, truthy confusions, deep attribute chains" \
  "Pythonic checks use 'is (not) None' and safe attribute access patterns."

print_subheader "== None or != None (should use 'is' / 'is not')"
count=$("${GREP_RN[@]}" -e "==[[:space:]]*None|!=[[:space:]]*None" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Equality to None" "Prefer 'is None' / 'is not None'"
  show_detailed_finding "==[[:space:]]*None|!=[[:space:]]*None" 5
else
  print_finding "good" "No None equality comparisons"
fi

print_subheader "Attribute chains depth (fragile without guards)"
deep_guard_json=""
guarded_inside=0
count=
if [[ "$HAS_AST_GREP" -eq 1 ]]; then
  deep_guard_json=$(analyze_py_attr_guards "$DETAIL_LIMIT")
  if [[ -n "$deep_guard_json" ]]; then
    parsed_counts=""
    parsed_counts=$(python3 - <<'PY' <<<"$deep_guard_json"
import json, sys
try:
    data = json.load(sys.stdin)
    print(f"{data.get('unguarded', 0)} {data.get('guarded', 0)}")
except Exception:
    pass
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
    ( ast_search '$X.$Y.$Z.$W' ) \
    || ( ( "${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) | count_lines )
  )
  guarded_inside=0
fi

if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Deep attribute access ($count)" "Guard with checks or use dataclass/attrs for structure"
  if [[ -n "$deep_guard_json" ]]; then
    show_ast_samples_from_json "$deep_guard_json"
  else
    show_detailed_finding "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" 3
  fi
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Some deep attribute access detected"
  [[ -n "$deep_guard_json" ]] && show_ast_samples_from_json "$deep_guard_json"
elif [ "$guarded_inside" -gt 0 ]; then
  print_finding "good" "$guarded_inside" "Deep attribute chains guarded" "Scanner suppressed chains guarded by explicit if checks"
fi

if [[ -n "$deep_guard_json" && "$guarded_inside" -gt 0 ]]; then
  say "    ${DIM}Suppressed $guarded_inside guarded attribute chain(s) inside conditionals${RESET}"
fi
if [[ -n "$deep_guard_json" ]]; then
  persist_metric_json "deep_guard" "$deep_guard_json"
fi

print_subheader "dict.get(key) without default used immediately"
count=$("${GREP_RN[@]}" -e "\.get\([[:space:]]*['\"][^'\"]+['\"][[:space:]]*\)[[:space:]]*(\.|\[)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "warning" "$count" "dict.get(...) used without default then dereferenced" "Provide default or handle None"
  show_detailed_finding "\.get\([[:space:]]*['\"][^'\"]+['\"][[:space:]]*\)[[:space:]]*(\.|\[)" 5
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: NUMERIC / ARITHMETIC PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 2; then
print_header "2. NUMERIC / ARITHMETIC PITFALLS"
print_category "Detects: Division by variable, float equality, modulo hazards" \
  "Silent numeric bugs propagate incorrect results or ZeroDivisionError."

print_subheader "Division by variable (possible ÷0)"
count=$(
  ( "${GREP_RN[@]}" -e "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) \
  | (grep -Ev "/[[:space:]]*(255|2|10|100|1000)\b|//|/\*" || true) | count_lines)
if [ "$count" -gt 25 ]; then
  print_finding "warning" "$count" "Division by variable - verify non-zero" "Guard before division"
  show_detailed_finding "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Division operations found - check divisors"
fi

print_subheader "Floating-point equality (==)"
count=$("${GREP_RN[@]}" -e "==[[:space:]]*[0-9]+\.[0-9]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Float equality comparison" "Use tolerance: abs(a-b) < eps"
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
print_category "Detects: Index risks, mutation during iteration, len checks" \
  "Collection misuse leads to IndexError or logical errors."

print_subheader "Index arithmetic like arr[i±1]"
count=$("${GREP_RN[@]}" -e "\[[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+\-][[:space:]]*[0-9]+[[:space:]]*\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 12 ]; then
  print_finding "warning" "$count" "Array index arithmetic - verify bounds" "Ensure i±k within range"
  show_detailed_finding "\[[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[+\-][[:space:]]*[0-9]+[[:space:]]*\]" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Index arithmetic present - review"
fi

print_subheader "Mutation during iteration"
mapfile -t MUTATION_REPORT < <(python3 - "$PROJECT_DIR" <<'PY' 2>/dev/null || true
import ast, pathlib, sys
root = pathlib.Path(sys.argv[1])
skip = {'.git', '.hg', '.svn', '.venv', '.tox', '__pycache__'}
mutating_attrs = {"append","extend","insert","pop","remove","clear","update","discard","add"}

def should_skip(path: pathlib.Path) -> bool:
    return any(part in skip for part in path.parts)

def body_mutates(body, name):
    module = ast.Module(body=body, type_ignores=[])
    for node in ast.walk(module):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == name and func.attr in mutating_attrs:
                    return True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return True
        elif isinstance(node, ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == name:
                return True
    return False

count = 0
examples = []
for path in root.rglob("*.py"):
    if should_skip(path.relative_to(root)):
        continue
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Name):
            col = node.iter.id
            if body_mutates(node.body, col):
                count += 1
                if len(examples) < 3:
                    examples.append(f"{path.relative_to(root)}:{node.lineno}")

print(count)
for ex in examples:
    print(ex)
PY
)
mutation_count="${MUTATION_REPORT[0]:-0}"
mutation_count=$(printf '%s\n' "$mutation_count" | awk 'END{print $0+0}')
if [ "$mutation_count" -gt 0 ]; then
  local_desc="Copy or iterate over snapshot"
  if [ "${#MUTATION_REPORT[@]}" -gt 1 ]; then
    IFS=', ' read -r -a _samples <<<"${MUTATION_REPORT[*]:1}"
    local_desc="Examples: ${MUTATION_REPORT[*]:1}"
  fi
  print_finding "warning" "$mutation_count" "Possible mutation during iteration" "$local_desc"
fi

print_subheader "len(x) comparisons"
count=$("${GREP_RN[@]}" -e "len\([^)]+\)[[:space:]]*(==|!=|<|>|<=|>=)[[:space:]]*0" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "len(x) == 0 checks" "Prefer truthiness: if not x:"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: COMPARISON & TYPE CHECKING TRAPS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 4; then
print_header "4. COMPARISON & TYPE CHECKING TRAPS"
print_category "Detects: 'is' with literals, type() equality, truthiness with bools" \
  "Prefer idiomatic Python comparisons and isinstance."

print_subheader "'is' with literals"
count=$("${GREP_RN[@]}" -e " is[[:space:]]*(True|False|[0-9]+|''|\"\"|'.*'|\".*\")" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Using 'is' with literals" "Use '==' (only None uses 'is')"
  show_detailed_finding " is[[:space:]]*(True|False|[0-9]+|''|\"\"|'.*'|\".*\")" 5
else
  print_finding "good" "No 'is' literal comparisons"
fi

print_subheader "type(x) == T instead of isinstance"
count=$("${GREP_RN[@]}" -e "type\([^)]+\)[[:space:]]*(==|is)[[:space:]]*[A-Za-z_][A-Za-z0-9_\.]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "type equality used" "Use isinstance(x, T)"
  show_detailed_finding "type\([^)]+\)[[:space:]]*(==|is)[[:space:]]*[A-Za-z_][A-Za-z0-9_\.]*" 5
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: ASYNC/AWAIT PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 5; then
print_header "5. ASYNC/AWAIT PITFALLS"
print_category "Detects: blocking calls in async, await in loops, floating tasks" \
  "Async bugs cause unpredictable latency and deadlocks."

async_count=$("${GREP_RN[@]}" -e "async[[:space:]]+def[[:space:]]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
await_count=$("${GREP_RNW[@]}" "await" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$async_count" "Async functions found"
if [ "$async_count" -gt "$await_count" ]; then
  ratio=$((async_count - await_count))
  print_finding "warning" "$ratio" "Possible un-awaited async paths" "Check for floating tasks"
fi

print_subheader "await inside loops (performance)"
count=$("${GREP_RN[@]}" -e "for[[:space:]]+.*:|while[[:space:]]+.*:" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A3 -w "await" || true) | (grep -cw "await" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "await inside loops" "Consider asyncio.gather"
fi

print_subheader "Blocking calls in async def"
count=$("${GREP_RN[@]}" -e "async[[:space:]]+def[[:space:]]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A6 -E "time\.sleep\(|requests\.[a-z]+\(.*\)|subprocess\.run\(|open\(" || true) | \
  (grep -c -E "time\.sleep|requests\.|subprocess\.run|open\(" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Blocking calls inside async functions" "Use async equivalents"
fi
run_async_error_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. ERROR HANDLING ANTI-PATTERNS"
print_category "Detects: bare except, swallowed errors, poor re-raise" \
  "Proper exception handling simplifies debugging and recovery."

print_subheader "Bare except"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*except[[:space:]]*:[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Bare except" "Except without class catches BaseException"
  show_detailed_finding "^[[:space:]]*except[[:space:]]*:[[:space:]]*$" 5
else
  print_finding "good" "No bare except blocks"
fi

print_subheader "except ...: pass"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*except[[:space:]]+[^:]+:[[:space:]]*pass[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Exception swallowed with pass" "Log or handle"
  show_detailed_finding "^[[:space:]]*except[[:space:]]+[^:]+:[[:space:]]*pass[[:space:]]*$" 5
fi

print_subheader "raise e (loses traceback)"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*except[[:space:]].*as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A2 -E "raise[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*$" || true) | (grep -c -E "raise[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*$" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Use 'raise' not 'raise e' to preserve traceback"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: SECURITY VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. SECURITY VULNERABILITIES"
print_category "Detects: code injection, unsafe deserialization, weak crypto, TLS off" \
  "Security bugs expose users to attacks and data breaches."

print_subheader "eval/exec usage"
count=$("${GREP_RN[@]}" -e "(^|[^A-Za-z0-9_])eval\(|(^|[^A-Za-z0-9_])exec\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -Ev "^[[:space:]]*#" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "eval()/exec() present" "Never use on untrusted input"
  show_detailed_finding "eval\(|exec\(" 5
else
  print_finding "good" "No eval/exec detected"
fi

print_subheader "pickle.load/loads"
count=$("${GREP_RN[@]}" -e "pickle\.(load|loads)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Insecure pickle usage" "Avoid unpickling untrusted data"
  show_detailed_finding "pickle\.(load|loads)\(" 3
fi

print_subheader "yaml.load without Loader"
count=$("${GREP_RN[@]}" -e "yaml\.load\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "Loader[[:space:]]*=" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "yaml.load without SafeLoader" "Use yaml.safe_load or specify Loader=SafeLoader"
  show_detailed_finding "yaml\.load\(" 3
fi

print_subheader "subprocess shell=True / os.system"
count=$("${GREP_RN[@]}" -e "subprocess\.(run|call|check_output|Popen)\(.*shell\s*=\s*True" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "os\.system\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "critical" "$total" "Shell command injection risk" "Pass argv list with shell=False"
  show_detailed_finding "subprocess\.(run|call|check_output|Popen)\(.*shell\s*=\s*True|os\.system\(" 5
else
  print_finding "good" "No shell=True / os.system detected"
fi

print_subheader "requests verify=False (TLS disabled)"
count=$("${GREP_RN[@]}" -e "requests\.[a-z]+\([^)]*verify\s*=\s*False" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "TLS verification disabled" "Remove verify=False"
  show_detailed_finding "requests\.[a-z]+\([^)]*verify\s*=\s*False" 3
fi

print_subheader "Weak hash algorithms (md5/sha1)"
count=$("${GREP_RN[@]}" -e "hashlib\.(md5|sha1)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Weak hash usage" "Use hashlib.sha256/512"
  show_detailed_finding "hashlib\.(md5|sha1)\(" 3
fi

print_subheader "Hardcoded secrets"
count=$("${GREP_RNI[@]}" -e "(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^\"']+['\"]" "$PROJECT_DIR" 2>/dev/null | \
  (grep -vE "#.*(password|api_?key|secret|token)|['\"]\\$" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Potential hardcoded secrets" "Use secret manager or env vars"
  show_detailed_finding "(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^\"']+['\"]" 5
fi

print_subheader "tempfile.mktemp (insecure)"
count=$("${GREP_RN[@]}" -e "tempfile\.mktemp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "Insecure tempfile.mktemp usage" "Use NamedTemporaryFile/mkstemp"; fi

run_taint_analysis_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: FUNCTION & SCOPE ISSUES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. FUNCTION & SCOPE ISSUES"
print_category "Detects: mutable defaults, many params, nested defs, returns" \
  "Function-level bugs cause subtle state leaks and readability problems."

print_subheader "Mutable default arguments"
count=$("${GREP_RN[@]}" -e "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^\)]*(\[\]|{}|set\(\))[^\)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Mutable default arguments" "Use None + set default in body"
  show_detailed_finding "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^\)]*(\[\]|{}|set\(\))[^\)]*\)" 5
else
  print_finding "good" "No mutable default arguments"
fi

print_subheader "Functions with high parameter count (>6)"
count=$("${GREP_RN[@]}" -e "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*[,)]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Functions with >6 parameters" "Refactor to dataclass/options object"
  show_detailed_finding "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*[,)]" 5
fi

print_subheader "Nested function declarations"
count=$("${GREP_RN[@]}" -e "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A2 -E "^[[:space:]]+def[[:space:]]" || true) | (grep -cw "def" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Nested functions - verify closures and lifetimes"
fi

print_subheader "Missing returns heuristic"
def_count=$("${GREP_RN[@]}" -e "^[[:space:]]*def[[:space:]]+[A-Za-z_]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
ret_count=$("${GREP_RNW[@]}" "return" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$def_count" -gt "$ret_count" ]; then
  diff=$((def_count - ret_count)); [ "$diff" -lt 0 ] && diff=0
  print_finding "info" "$diff" "Some functions may lack return statements" "Void intended?"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: PARSING & TYPE CONVERSION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. PARSING & TYPE CONVERSION BUGS"
print_category "Detects: json.loads without try, str+num concat, int() edge cases" \
  "Parsing bugs cause runtime exceptions and data corruption."

print_subheader "json.loads without try/catch"
mapfile -t JSON_LOADS_REPORT < <(python3 - "$PROJECT_DIR" <<'PY' 2>/dev/null || true
import ast, pathlib, sys
root = pathlib.Path(sys.argv[1])
skip = {'.git', '.hg', '.svn', '.venv', '.tox', '__pycache__'}

def should_skip(path: pathlib.Path) -> bool:
    return any(part in skip for part in path.parts)

def annotate(node, parent=None):
    for child in ast.iter_child_nodes(node):
        child.parent = node
        annotate(child, node)

def in_try(node):
    current = getattr(node, 'parent', None)
    while current is not None:
        if isinstance(current, ast.Try):
            return True
        current = getattr(current, 'parent', None)
    return False

count = 0
examples = []
for path in root.rglob("*.py"):
    if should_skip(path.relative_to(root)):
        continue
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
    except Exception:
        continue
    annotate(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "loads":
                if isinstance(func.value, ast.Name) and func.value.id == "json":
                    if not in_try(node):
                        count += 1
                        if len(examples) < 3:
                            rel = path.relative_to(root)
                            examples.append(f"{rel}:{node.lineno}")
print(count)
for ex in examples:
    print(ex)
PY
)
json_bad="${JSON_LOADS_REPORT[0]:-0}"
json_bad=$(printf '%s\n' "$json_bad" | awk 'END{print $0+0}')
if [ "$json_bad" -gt 0 ]; then
  desc="Wrap in try/except ValueError"
  if [ "${#JSON_LOADS_REPORT[@]}" -gt 1 ]; then
    desc="Examples: ${JSON_LOADS_REPORT[*]:1}"
  fi
  print_finding "warning" "$json_bad" "json.loads without error handling" "$desc"
fi

print_subheader "String concatenation with + adjacent to digits (possible type mix)"
count=$("${GREP_RN[@]}" -e "\+[[:space:]]*['\"]|['\"][[:space:]]*\+" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "\+\+|[+\-]=" || true) | wc -l | awk '{print $1+0}')
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "String concatenation with +" "Use f-strings"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: CONTROL FLOW GOTCHAS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 10; then
print_header "10. CONTROL FLOW GOTCHAS"
print_category "Detects: return/break in finally, nested ternary, unreachable code" \
  "Flow pitfalls cause surprising behavior and lost exceptions."

print_subheader "return/break/continue inside finally"
count=$("${GREP_RN[@]}" -e "finally:[[:space:]]*$" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A3 -E "return|break|continue" || true) | (grep -c -E "return|break|continue" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Control transfer in finally" "It may swallow exceptions"
fi

print_subheader "Nested conditional expressions"
count=$("${GREP_RN[@]}" -e " if .* else .* if .* else " "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Nested ternary expressions" "Refactor to if/elif"
  show_detailed_finding " if .* else .* if .* else " 3
fi

print_subheader "Unreachable code after return"
count=$("${GREP_RNW[@]}" "return" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A1 "return" || true) | (grep -v -E "^--$|return|^[[:space:]]*$" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Possible unreachable code after return"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: DEBUGGING & PRODUCTION CODE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. DEBUGGING & PRODUCTION CODE"
print_category "Detects: print, breakpoint/pdb, sensitive logs" \
  "Debug artifacts degrade performance and leak information."

print_subheader "print statements"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*print\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 50 ]; then
  print_finding "warning" "$count" "Many print() statements - prefer logging"
elif [ "$count" -gt 20 ]; then
  print_finding "info" "$count" "print() statements found"
else
  print_finding "good" "Minimal print usage"
fi

print_subheader "breakpoint() / pdb.set_trace()"
count=$("${GREP_RN[@]}" -e "breakpoint\(|pdb\.set_trace\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Debugger calls present" "Remove before commit"
  show_detailed_finding "breakpoint\(|pdb\.set_trace\(" 5
else
  print_finding "good" "No debugger calls"
fi

print_subheader "Logging sensitive data"
count=$("${GREP_RNI[@]}" -e "logging\.(debug|info|warning|error|exception)\(.*(password|token|secret|Bearer|Authorization)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Sensitive data in logs" "Remove or mask secrets"
  show_detailed_finding "logging\.(debug|info|warning|error|exception)\(.*(password|token|Bearer|Authorization)" 3
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: PERFORMANCE & MEMORY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 12; then
print_header "12. PERFORMANCE & MEMORY"
print_category "Detects: string concat in loops, regex compile in loops, I/O in loops" \
  "Performance anti-patterns reduce throughput and increase latency."

print_subheader "String concatenation in loops"
count=$("${GREP_RN[@]}" -e "for[[:space:]]+.*:|while[[:space:]]+.*:" "$PROJECT_DIR" 2>/dev/null | (grep -A3 "+=" || true) | (grep -cw "+=" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 8 ]; then
  print_finding "info" "$count" "String concatenation in loops" "Use list-join pattern"
fi

print_subheader "re.compile inside loops"
count=$("${GREP_RN[@]}" -e "for[[:space:]]+.*:|while[[:space:]]+.*:" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A3 -E "re\.compile\(" || true) | (grep -cw "re\.compile" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Regex compiled in loop" "Precompile outside loop"
fi

print_subheader "I/O heavy ops in loops"
count=$("${GREP_RN[@]}" -e "for|while" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A5 -E "open\(|read\(|write\(|requests\." || true) | \
  (grep -c -E "open\(|read\(|write\(|requests\." || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "I/O in loops" "Batch or buffer where possible"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: VARIABLE & SCOPE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 13; then
print_header "13. VARIABLE & SCOPE"
print_category "Detects: global/nonlocal usage, wildcard imports" \
  "Scope issues cause hard-to-debug conflicts and side effects."

print_subheader "global/nonlocal statements"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*(global|nonlocal)[[:space:]]+[A-Za-z_]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Frequent global/nonlocal usage" "Refactor to dependency injection"
fi

print_subheader "Wildcard imports"
count=$("${GREP_RN[@]}" -e "from[[:space:]]+[A-Za-z0-9_\.]+[[:space:]]+import[[:space:]]+\*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Wildcard imports deter tooling"; fi
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
  print_finding "warning" "$count" "Potential catastrophic regex" "Review with regex101 or safe-regex"
  show_detailed_finding "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" 2
fi

print_subheader "Dynamic re.compile from variables"
count=$("${GREP_RN[@]}" -e "re\.compile\([[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "Dynamic regex construction" "Sanitize input or use fixed patterns"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: I/O & RESOURCE SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. I/O & RESOURCE SAFETY"
print_category "Detects: open without with, missing encoding, rmtree(ignore_errors)" \
  "I/O bugs leak resources and produce nondeterministic behavior."

print_subheader "open(...) without context manager"
open_calls=$("${GREP_RN[@]}" -e "open\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
with_calls=$("${GREP_RN[@]}" -e "with[[:space:]]+[^:]*open\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$open_calls" -gt 0 ] && [ "$with_calls" -lt "$open_calls" ]; then
  diff=$((open_calls - with_calls))
  print_finding "warning" "$diff" "open() calls missing 'with'" "Wrap file handles in context managers or close them explicitly"
else
  print_finding "good" "File usage appears context-managed"
fi

print_subheader "open() without explicit encoding"
no_encoding=$("${GREP_RN[@]}" -e "open\([^)]*\)" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "encoding[[:space:]]*=" || true) | count_lines)
if [ "$no_encoding" -gt 0 ]; then
  print_finding "info" "$no_encoding" "open() missing encoding" "Pass encoding='utf-8' (or desired charset) for portability"
fi

print_subheader "shutil.rmtree(ignore_errors=True)"
rmtree_ignore=$("${GREP_RN[@]}" -e "shutil\.rmtree\([^)]*ignore_errors\s*=\s*True" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$rmtree_ignore" -gt 0 ]; then
  print_finding "info" "$rmtree_ignore" "rmtree(ignore_errors=True) hides failures"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: TYPING STRICTNESS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 17; then
print_header "17. TYPING STRICTNESS"
print_category "Detects: Any usage, type: ignore density" \
  "Type hygiene reduces runtime errors."

print_subheader "'Any' usage"
count=$("${GREP_RN[@]}" -e "(:|->)[[:space:]]*Any\b|typing\.Any\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Frequent 'Any' usage" "Consider generics/Protocol"
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Some 'Any' usage present"
fi

print_subheader "type: ignore comments"
count=$("${GREP_RN[@]}" -e "#[[:space:]]*type:[[:space:]]*ignore" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Many 'type: ignore' pragmas" "Keep them targeted"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 18: PYTHON I/O & MODULE USAGE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 18; then
print_header "18. PYTHON I/O & MODULE USAGE"
print_category "Detects: os.system, wildcard imports, dynamic import" \
  "Prefer safer subprocess APIs and explicit imports."

print_subheader "os.system invocations"
count=$("${GREP_RN[@]}" -e "os\.system\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "os.system used (shell)"; fi

print_subheader "Dynamic imports"
count=$("${GREP_RN[@]}" -e "__import__\(|importlib\.import_module\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Dynamic imports present"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 19; then
print_header "19. RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: File handles, subprocesses, and async tasks missing cleanup" \
  "Unreleased resources leak descriptors, zombie processes, and pending tasks"

run_resource_lifecycle_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough or text summary)
# ═══════════════════════════════════════════════════════════════════════════
if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
  print_header "AST-GREP RULE PACK FINDINGS"
  if run_ast_rules; then
    if [[ "$AST_PASSTHROUGH" -eq 1 ]]; then
      say "${DIM}${INFO} Above JSON/SARIF lines are ast-grep matches (id, message, severity, file/pos).${RESET}"
      if [[ "$FORMAT" == "sarif" ]]; then
        say "${DIM}${INFO} Tip: ${BOLD}${AST_GREP_CMD[*]} scan -r $AST_RULE_DIR \"$PROJECT_DIR\" --sarif > report.sarif${RESET}"
      fi
    fi
  else
    say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 20: UV-POWERED EXTRA ANALYZERS (optional)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 20; then
print_header "20. UV-POWERED EXTRA ANALYZERS"
print_category "Ruff linting, Bandit security, Pip-audit, Mypy, Safety, Detect-secrets" \
  "Uses uvx when available; falls back to system tools if installed."

if [[ "$ENABLE_UV_TOOLS" -eq 1 ]]; then
  IFS=',' read -r -a UVLIST <<< "$UV_TOOLS"
  for TOOL in "${UVLIST[@]}"; do
    case "$TOOL" in
      ruff)
        print_subheader "ruff (lint)"
        run_uv_tool_text ruff check "$PROJECT_DIR" --output-format=json || true
        ruff_count=$(run_uv_tool_text ruff check "$PROJECT_DIR" --output-format=concise | grep -c "^" || true)
        if [ "${ruff_count:-0}" -gt 0 ]; then print_finding "info" "$ruff_count" "Ruff emitted findings" "Review ruff output above"; else print_finding "good" "Ruff clean"; fi
        ;;
      bandit)
        print_subheader "bandit (security)"
        _EXC=""; for d in "${EXCLUDE_DIRS[@]}"; do _EXC="${_EXC:+$_EXC,}$d"; done
        if run_uv_tool_text bandit -q -r "$PROJECT_DIR" -x "${_EXC:-}" ; then
          print_finding "info" 0 "Bandit scan completed" "See output above"
        else
          say "  ${GRAY}${INFO} bandit not executed${RESET}"
        fi
        ;;
      pip-audit)
        print_subheader "pip-audit (dependencies)"
        if [ -f "$PROJECT_DIR/requirements.txt" ]; then
          run_uv_tool_text pip-audit -r "$PROJECT_DIR/requirements.txt" || true
        elif [ -f "$PROJECT_DIR/pyproject.toml" ]; then
          run_uv_tool_text pip-audit --path "$PROJECT_DIR/pyproject.toml" || true
        else
          run_uv_tool_text pip-audit --path "$PROJECT_DIR" || true
        fi
        print_finding "info" 0 "pip-audit run (if available)" "Review advisories above"
        ;;
      mypy)
        print_subheader "mypy (type-check)"
        run_uv_tool_text mypy --hide-error-context "$PROJECT_DIR" || true
        ;;
      detect-secrets)
        print_subheader "detect-secrets (secrets)"
        run_system_or_uv_tool detect-secrets scan "$PROJECT_DIR" || true
        ;;
      safety)
        print_subheader "safety (dependency vulns)"
        if [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
          run_system_or_uv_tool safety check -r "$PROJECT_DIR/requirements.txt" --full-report || true
        else
          run_system_or_uv_tool safety check --full-report || true
        fi
        ;;
      *)
        say "  ${GRAY}${INFO} Unknown uv tool '$TOOL' ignored${RESET}"
        ;;
    esac
  done
else
  say "  ${GRAY}${INFO} uv extra analyzers disabled (--no-uv)${RESET}"
fi
fi

# restore pipefail if we relaxed it
end_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 21: DEPRECATIONS & PY3.13 MIGRATIONS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 21; then
print_header "21. DEPRECATIONS & PY3.13 MIGRATIONS"
print_category "Detects: deprecated modules/APIs likely to break on newer Python" \
  "Proactive remediation avoids upgrade surprises."

print_subheader "Deprecated modules/APIs"
count=$("${GREP_RN[@]}" -e "^from[[:space:]]+imp[[:space:]]+import|^import[[:space:]]+imp|asyncio\.get_event_loop\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Deprecated API usage" "Replace 'imp' with importlib; prefer get_running_loop()/asyncio.run"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 22: PACKAGING & CONFIG HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 22; then
print_header "22. PACKAGING & CONFIG HYGIENE"
print_category "Detects: unpinned requirements, editable installs, local paths" \
  "Supply-chain & reproducibility safeguards."

print_subheader "Requirements without pins"
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
  count=$(grep -E '^[A-Za-z0-9._-]+( *[#].*)?$' "$PROJECT_DIR/requirements.txt" 2>/dev/null | count_lines || true)
  if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Unpinned dependencies" "Pin versions to avoid drift"; fi
fi

print_subheader "Editable installs / local paths"
count=$("${GREP_RN[@]}" -e "^-e[[:space:]]+|file:[/]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Editable/local dependency references"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 23: NOTEBOOK HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 23; then
print_header "23. NOTEBOOK HYGIENE"
print_category "Detects: large cell outputs, execution counts, trusted state" \
  "Keeps VCS diffs clean and reproducible."

print_subheader "Large embedded outputs"
count=$("${GREP_RN[@]}" -e '"outputs":[[:space:]]*\[[[:space:]]*{' "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then print_finding "info" "$count" "Notebooks contain outputs" "Clear outputs before commit"; fi
fi

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

# Baseline compare (if provided)
if [[ -n "$BASELINE" && -f "$BASELINE" ]]; then
  say "${BOLD}${WHITE}Baseline Comparison:${RESET}"
  CRITICAL_COUNT="$CRITICAL_COUNT" WARNING_COUNT="$WARNING_COUNT" INFO_COUNT="$INFO_COUNT" python3 - "$BASELINE" <<'PY'
import json,sys,os
try:
  with open(sys.argv[1],'r',encoding='utf-8') as fh:
    b=json.load(fh)
except Exception:
  print("  (could not read baseline)")
  sys.exit(0)
def get(k): 
  try: return int(b.get(k,0))
  except: return 0
from_now={'critical':int(os.environ.get('CRITICAL_COUNT',0)),
          'warning':int(os.environ.get('WARNING_COUNT',0)),
          'info':int(os.environ.get('INFO_COUNT',0))}
for k in ['critical','warning','info']:
  prior=get(k); now=from_now[k]; delta=now-prior
  arrow = '↑' if delta>0 else ('↓' if delta<0 else '→')
  print(f"  {k.capitalize():<8}: {now:>4}  (baseline {prior:>4})  {arrow} {delta:+}")
PY
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

# Optional machine-readable summary
if [[ -n "$SUMMARY_JSON" ]]; then
  {
    printf '{'
    printf '"project":"%s",' "$(printf %s "$PROJECT_DIR" | sed 's/"/\\"/g')"
    printf '"files":%s,' "$TOTAL_FILES"
    printf '"critical":%s,' "$CRITICAL_COUNT"
    printf '"warning":%s,' "$WARNING_COUNT"
    printf '"info":%s,' "$INFO_COUNT"
    printf '"timestamp":"%s",' "$(eval "$DATE_CMD")"
    printf '"format":"%s",' "$FORMAT"
    printf '"uv_tools":"%s",' "$(printf %s "$UV_TOOLS" | sed 's/"/\\"/g')"
    printf '"categories":{'
    printf '"1":%s,"2":%s,"3":%s,"4":%s,"5":%s,"6":%s,"7":%s,"8":%s,' \
      "$(num_clamp "${CAT1:-0}")" "$(num_clamp "${CAT2:-0}")" "$(num_clamp "${CAT3:-0}")" "$(num_clamp "${CAT4:-0}")" "$(num_clamp "${CAT5:-0}")" "$(num_clamp "${CAT6:-0}")" "$(num_clamp "${CAT7:-0}")" "$(num_clamp "${CAT8:-0}")"
    printf '"9":%s,"10":%s,"11":%s,"12":%s,"13":%s,"14":%s,"15":%s,"16":%s,' \
      "$(num_clamp "${CAT9:-0}")" "$(num_clamp "${CAT10:-0}")" "$(num_clamp "${CAT11:-0}")" "$(num_clamp "${CAT12:-0}")" "$(num_clamp "${CAT13:-0}")" "$(num_clamp "${CAT14:-0}")" "$(num_clamp "${CAT15:-0}")" "$(num_clamp "${CAT16:-0}")"
    printf '"17":%s,"18":%s,"19":%s,"20":%s,"21":%s,"22":%s,"23":%s},' \
      "$(num_clamp "${CAT17:-0}")" "$(num_clamp "${CAT18:-0}")" "$(num_clamp "${CAT19:-0}")" "$(num_clamp "${CAT20:-0}")" "$(num_clamp "${CAT21:-0}")" "$(num_clamp "${CAT22:-0}")" "$(num_clamp "${CAT23:-0}")"
    # ast-grep histogram if available
    if [[ -n "$AST_RULE_DIR" && "$HAS_AST_GREP" -eq 1 ]]; then
      printf '"ast_grep_rules":['
      ( set +o pipefail; "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json=stream 2>/dev/null || true ) \
        | python3 - <<'PY'
import json,sys,collections
seen=collections.Counter()
for line in sys.stdin:
  line=line.strip()
  if not line: continue
  try: rid=(json.loads(line).get('rule_id') or 'unknown'); seen[rid]+=1
  except: pass
print(",".join(json.dumps({"id":k,"count":v}) for k,v in seen.items()))
PY
      printf ']'
    else printf '"ast_grep_rules":[]'; fi
    printf '}\n'
  } > "$SUMMARY_JSON" 2>/dev/null || true
  say "${DIM}Summary JSON written to: ${SUMMARY_JSON}${RESET}"
fi

echo ""
say "${DIM}Scan completed at: $(eval "$DATE_CMD")${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning --summary-json=.ubs-summary.json . > py-bug-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
exit "$EXIT_CODE"
