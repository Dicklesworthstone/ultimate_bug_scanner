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

# Bail early on ancient bash (macOS ships bash 3.2; `shopt -s lastpipe`
# requires 4.2+ and would silently abort the module under `set -e`).
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-python.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob
shopt -s compat31 || true

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default color vars early so on_err can't trip set -u before init_colors runs
RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
BOLD=''; DIM=''; RESET=''

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]-${BASH_SOURCE[0]}}
  echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2
  exit "$ec"
}
trap on_err ERR

# Honor NO_COLOR and non-tty
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi
FORCE_COLOR=0

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

# Symbols (ensure UTF-8 output; run grep under LC_ALL=C separately)
SAFE_LOCALE="C"
if locale -a 2>/dev/null | grep -qiE '^C\.UTF-8$'; then
  SAFE_LOCALE="C.UTF-8"
elif locale -a 2>/dev/null | grep -qiE '^C\.utf8$'; then
  SAFE_LOCALE="C.utf8"
elif locale -a 2>/dev/null | grep -qiE '^en_US\.UTF-8$'; then
  SAFE_LOCALE="en_US.UTF-8"
elif locale -a 2>/dev/null | grep -qiE '^en_US\.utf8$'; then
  SAFE_LOCALE="en_US.utf8"
fi
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
        # When PROJECT_DIR is still the default ".", allow a single positional arg to
        # be interpreted as OUTPUT_FILE (common with --format=json/--format=sarif).
        # Heuristic: if the arg doesn't exist and its basename contains a dot (e.g., report.json),
        # treat it as OUTPUT_FILE; otherwise treat it as a project path.
        if [[ "$PROJECT_DIR" == "." && -z "$OUTPUT_FILE" && ! -e "$1" ]]; then
          base="${1##*/}"
          case "$1" in
            *.py|*.pyi|*.pyx|*.pxd|*.pxi|*.ipynb) PROJECT_DIR="$1" ;;
            *)
              if [[ "$base" == *.* ]]; then OUTPUT_FILE="$1"; else PROJECT_DIR="$1"; fi
              ;;
          esac
        else
          PROJECT_DIR="$1"
        fi
        shift
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, pass them via --paths-from=FILE, or use the meta-runner 'ubs'." >&2
          echo "       To write the report somewhere, pass a fresh (non-existing) path as the second positional argument." >&2
          exit 2
        fi
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
if [[ "$FORCE_COLOR" -eq 1 && "$NO_COLOR_FLAG" -eq 0 ]]; then USE_COLOR=1; fi
if [[ -n "${OUTPUT_FILE}" && "$FORMAT" == "text" && "$FORCE_COLOR" -eq 0 && "$NO_COLOR_FLAG" -eq 0 ]]; then
  USE_COLOR=0
fi
init_colors

# OUTPUT_FILE handling:
# - text: tee full report (stdout+stderr) into OUTPUT_FILE
# - json/sarif: treat OUTPUT_FILE as machine-output destination (keep logs on stderr)
MACHINE_OUT_FILE=""
if [[ -n "${OUTPUT_FILE}" && ( "$FORMAT" == "json" || "$FORMAT" == "sarif" ) ]]; then
  MACHINE_OUT_FILE="$OUTPUT_FILE"
elif [[ -n "${OUTPUT_FILE}" ]]; then
  exec > >(tee "${OUTPUT_FILE}") 2>&1
fi

# Structured formats: keep machine output on original stdout, send logs to stderr.
# - If FORMAT is json/sarif we redirect fd1 -> fd2, and use fd3 (or fd4 tee) for machine output.
MACHINE_FD=1
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  exec 3>&1
  exec 1>&2
  if [[ -n "${MACHINE_OUT_FILE:-}" ]]; then
    # Duplicate machine output to both OUTPUT_FILE and original stdout.
    exec 4> >(tee "$MACHINE_OUT_FILE" >&3)
    MACHINE_FD=4
  else
    MACHINE_FD=3
  fi
fi

safe_date() {
  if [[ "$CI_MODE" -eq 1 ]]; then command date -u '+%Y-%m-%dT%H:%M:%SZ' || command date '+%Y-%m-%dT%H:%M:%SZ'; else command date '+%Y-%m-%d %H:%M:%S'; fi
}

# ────────────────────────────────────────────────────────────────────────────
# Global Counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0
CURRENT_CATEGORY=0
declare -A CAT_COUNTS=()

# ────────────────────────────────────────────────────────────────────────────
# Global State
# ────────────────────────────────────────────────────────────────────────────
HAS_AST_GREP=0
AST_GREP_CMD=()      # array-safe
AST_RULE_DIR=""      # created later if ast-grep exists
AST_CONFIG_FILE=""   # temp sgconfig.yml pointing at AST_RULE_DIR (ast-grep 0.40+)
HAS_RIPGREP=0
UVX_CMD=()           # (uvx or `uv -q tool run`) if available
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
count_lines() { grep -v 'ubs:ignore' | awk 'END{print (NR+0)}'; }
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

bump_category_count() {
  local delta=${1:-0}
  [[ "${CURRENT_CATEGORY:-0}" =~ ^[0-9]+$ ]] || return 0
  [[ "${CURRENT_CATEGORY:-0}" -gt 0 ]] || return 0
  CAT_COUNTS["$CURRENT_CATEGORY"]=$(( ${CAT_COUNTS["$CURRENT_CATEGORY"]:-0} + (delta+0) ))
}

print_finding() {
  local severity=$1
  case $severity in
    good)
      # Support both:
      #   print_finding good "Message"
      #   print_finding good <count> "Message" ["Details..."]
      if [[ "${2:-}" =~ ^[0-9]+$ && -n "${3:-}" ]]; then
        local count=$2; local title=$3; local description="${4:-}"
        say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET} ${WHITE}($count)${RESET}"
        [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
      else
        local title=$2
        say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}"
      fi
      ;;
    *)
      local raw_count=$2; local title=$3; local description="${4:-}"
      local count; count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
      case $severity in
        critical)
          CRITICAL_COUNT=$((CRITICAL_COUNT + count))
          bump_category_count "$count"
          say "  ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"
          say "    ${RED}${BOLD}$title${RESET}"
          [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          ;;
        warning)
          WARNING_COUNT=$((WARNING_COUNT + count))
          bump_category_count "$count"
          say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"
          say "    ${YELLOW}$title${RESET}"
          [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          ;;
        info)
          INFO_COUNT=$((INFO_COUNT + count))
          bump_category_count "$count"
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
  [[ "$QUIET" -eq 1 ]] && return 0
  # Use printf to avoid echo -e interpreting user code (e.g., "-n", "\t", "\c")
  printf '%b%s%b\n' "$GRAY" "      $file:$line" "$RESET"
  printf '%b%s%b\n' "$WHITE" "      $code" "$RESET"
}

# Parse grep/rg output line handling Windows drive letters (C:/path...)
# Sets: PARSED_FILE, PARSED_LINE, PARSED_CODE
parse_grep_line() {
  local rawline="$1"
  PARSED_FILE="" PARSED_LINE="" PARSED_CODE=""
  # Windows drive letter pattern first (C:/path:line:code), then Unix (/path:line:code)
  if [[ "$rawline" =~ ^([A-Za-z]:.+):([0-9]+):(.*)$ ]] || [[ "$rawline" =~ ^(.+):([0-9]+):(.*)$ ]]; then
    PARSED_FILE="${BASH_REMATCH[1]}"
    PARSED_LINE="${BASH_REMATCH[2]}"
    PARSED_CODE="${BASH_REMATCH[3]}"
    return 0
  fi
  return 1
}

show_detailed_finding() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  while IFS= read -r rawline; do
    [[ -z "$rawline" ]] && continue
    [[ "$rawline" == *"ubs:ignore"* ]] && continue
    parse_grep_line "$rawline" || continue
    print_code_sample "$PARSED_FILE" "$PARSED_LINE" "$PARSED_CODE"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done < <("${GREP_RN[@]}" -e "$pattern" "$PROJECT_DIR" 2>/dev/null | head -n "$limit" || true) || true
}

run_resource_lifecycle_checks() {
  print_subheader "Resource lifecycle correlation"
  local helper="$SCRIPT_DIR/helpers/resource_lifecycle_py.py"
  if [[ -f "$helper" ]] && command -v python3 >/dev/null 2>&1; then
    local output helper_err helper_err_preview helper_err_tmp
    helper_err="/dev/null"
    if helper_err_tmp="$(mktemp -t ubs-py-resource-lifecycle.XXXXXX 2>/dev/null || mktemp)"; then
      helper_err="$helper_err_tmp"
    fi
    if output=$(python3 "$helper" "$PROJECT_DIR" 2>"$helper_err"); then
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
      [[ "$helper_err" != "/dev/null" ]] && rm -f "$helper_err" 2>/dev/null || true
      return
    else
      helper_err_preview="$(head -n 1 "$helper_err" 2>/dev/null || true)"
      [[ -z "$helper_err_preview" ]] && helper_err_preview="Run: python3 $helper $PROJECT_DIR"
      print_finding "info" 0 "AST helper failed" "$helper_err_preview"
      [[ "$helper_err" != "/dev/null" ]] && rm -f "$helper_err" 2>/dev/null || true
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
  pattern: $TASK = asyncio.create_task($$$)
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
      [[ -n "$rule_dir" && "$rule_dir" != "/" && "$rule_dir" != "." ]] && rm -rf -- "$rule_dir" 2>/dev/null || true
      rm -f "$tmp_json"
      print_finding "info" 0 "ast-grep scan failed" "Unable to compute async error coverage"
      return
    fi
  done
  [[ -n "$rule_dir" && "$rule_dir" != "/" && "$rule_dir" != "." ]] && rm -rf -- "$rule_dir" 2>/dev/null || true
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
file_cache = {}

def check_suppression(fpath, line_no):
    if not fpath or line_no <= 0: return False
    if fpath not in file_cache:
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as src:
                file_cache[fpath] = src.readlines()
        except Exception:
            file_cache[fpath] = []
    
    lines = file_cache[fpath]
    idx = line_no - 1
    if 0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]: return True
    if 0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx-1]: return True
    return False

with open(path, 'r', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = obj.get('ruleId') or obj.get('rule_id') or obj.get('id')
        if not rid:
            continue
        rng = obj.get('range') or {}
        start = rng.get('start') or {}
        line0 = start.get('row')
        if line0 is None:
            line0 = start.get('line', 0)
        line_no = int(line0) + 1
        file_path = obj.get('file', '?')

        if check_suppression(file_path, line_no): continue

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
        if 'ubs:ignore' in raw: continue
        if idx > 1 and 'ubs:ignore' in lines[idx-2]: continue
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

run_sql_injection_checks() {
  print_subheader "Interpolated SQL execution"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable SQL injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Interpolated SQL reaches execution sink" "Use parameterized queries, SQLAlchemy bind parameters, or ORM bindings instead of f-strings, format(), %, or string concatenation"
        else
          print_finding "good" "No interpolated SQL execution detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
SQL_RE = re.compile(r'\b(?:select|insert|update|delete|with|merge|call|exec|create|drop|alter|truncate)\b', re.IGNORECASE)
EXECUTE_METHODS = {'execute', 'executemany', 'executescript', 'raw', 'read_sql', 'read_sql_query', 'scalar', 'scalars'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def string_parts(node):
    parts = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return parts

def literal_sql_text(node, text):
    parts = string_parts(node)
    segment = ast.get_source_segment(text, node) or ''
    return ' '.join(parts + [segment])

def looks_like_sql(node, text):
    return bool(SQL_RE.search(literal_sql_text(node, text)))

def all_static_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all_static_strings(node.left) and all_static_strings(node.right)
    return False

class SQLInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.unsafe_sql_vars = set()
        self.issues = []

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def unsafe_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.unsafe_sql_vars)

    def is_text_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        return name == 'text' or name.endswith('.text')

    def is_interpolated_sql(self, node):
        if isinstance(node, ast.JoinedStr):
            return looks_like_sql(node, self.text) and any(isinstance(part, ast.FormattedValue) for part in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return looks_like_sql(node, self.text) and not all_static_strings(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return looks_like_sql(node.func.value, self.text)
        return False

    def contains_interpolation(self, node):
        if isinstance(node, ast.JoinedStr) and any(isinstance(part, ast.FormattedValue) for part in node.values):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)) and not all_static_strings(node):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return any(self.contains_interpolation(child) for child in ast.iter_child_nodes(node))

    def contains_unsafe_sql(self, node):
        if self.is_interpolated_sql(node) or self.unsafe_names_in(node):
            return True
        if self.is_text_call(node) and node.args:
            return self.contains_unsafe_sql(node.args[0])
        return any(self.is_interpolated_sql(child) for child in ast.walk(node))

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def mark_assignment(self, names, value):
        if self.contains_unsafe_sql(value):
            self.unsafe_sql_vars.update(names)
        else:
            for name in names:
                self.unsafe_sql_vars.discard(name)

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            if node.target.id in self.unsafe_sql_vars or self.contains_unsafe_sql(node.value):
                self.unsafe_sql_vars.add(node.target.id)
        self.generic_visit(node)

    def sql_argument(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short in EXECUTE_METHODS:
            return node.args[0] if node.args else None
        if short == 'extra':
            for keyword in node.keywords:
                if keyword.arg == 'where':
                    return keyword.value
        return None

    def visit_Call(self, node):
        if has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        arg = self.sql_argument(node)
        if arg is not None and self.contains_unsafe_sql(arg):
            self.issues.append((self.relative_path(), node.lineno, source_line(self.lines, node.lineno)))
        elif call_name(node.func).rsplit('.', 1)[-1] == 'extra':
            for keyword in node.keywords:
                if keyword.arg == 'where' and self.contains_interpolation(keyword.value):
                    self.issues.append((self.relative_path(), node.lineno, source_line(self.lines, node.lineno)))
                    break
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SQLInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_nosql_injection_checks() {
  print_subheader "NoSQL query injection"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable NoSQL injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled NoSQL filter reaches database sink" "Build Mongo/PyMongo filters from explicit allow-listed fields and reject operator keys such as \$where, \$ne, \$regex, \$or, and \$expr"
        else
          print_finding "good" "No request-controlled NoSQL filters detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
FILTER_METHODS = {
    'find', 'find_one', 'find_raw_batches', 'delete_one', 'delete_many',
    'count_documents',
}
UPDATE_METHODS = {
    'update_one', 'update_many', 'replace_one', 'find_one_and_update',
    'find_one_and_replace', 'find_one_and_delete',
}
PIPELINE_METHODS = {'aggregate', 'watch'}
COMMAND_METHODS = {'command'}
DANGEROUS_OPERATORS = {
    '$where', '$regex', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    '$or', '$and', '$nor', '$expr', '$function', '$accumulator',
}
REQUEST_NAMES = {'request'}
UNTRUSTED_ATTRS = {'args', 'form', 'values', 'json', 'data', 'body', 'GET', 'POST'}
UNTRUSTED_CALLS = {'get_json', 'json', 'dict', 'to_dict'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

class NoSQLInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.untrusted_objects = set()
        self.unsafe_queries = set()
        self.request_values = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_untrusted_object(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.untrusted_objects or node.id in self.unsafe_queries
        if isinstance(node, ast.Attribute):
            return rooted_at_request(node) and node.attr in UNTRUSTED_ATTRS
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if rooted_at_request(node.func) and short in UNTRUSTED_CALLS:
                return True
            if short == 'dict' and any(self.expr_is_untrusted_object(arg) for arg in node.args):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'copy', 'dict'}:
                return self.expr_is_untrusted_object(node.func.value)
        if isinstance(node, ast.Subscript):
            root = call_name(node.value)
            return root in {'request.json', 'request.data', 'request.body'} or (
                isinstance(node.value, ast.Name) and node.value.id in self.untrusted_objects
            )
        return False

    def expr_has_request_source(self, node):
        if rooted_at_request(node):
            return True
        return any(self.expr_has_request_source(child) for child in ast.iter_child_nodes(node))

    def expr_contains_request_data(self, node):
        if isinstance(node, ast.Name) and node.id in self.request_values:
            return True
        if self.expr_is_untrusted_object(node):
            return True
        if rooted_at_request(node):
            return True
        return any(self.expr_contains_request_data(child) for child in ast.iter_child_nodes(node))

    def value_contains_untrusted_object(self, node):
        if self.expr_is_untrusted_object(node):
            return True
        return any(self.value_contains_untrusted_object(child) for child in ast.iter_child_nodes(node))

    def dict_expr_is_unsafe(self, node):
        for key, value in zip(node.keys, node.values):
            if key is None:
                if self.expr_contains_request_data(value):
                    return True
                continue
            key_text = const_string(key)
            if key_text is None:
                if self.expr_contains_request_data(key) or self.expr_contains_request_data(value):
                    return True
                continue
            if key_text.startswith('$'):
                if key_text in {'$where', '$function', '$accumulator'}:
                    return True
                if key_text in DANGEROUS_OPERATORS and self.expr_contains_request_data(value):
                    return True
                if self.value_contains_untrusted_object(value):
                    return True
            elif self.value_contains_untrusted_object(value):
                return True
        return False

    def query_expr_is_unsafe(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.untrusted_objects or node.id in self.unsafe_queries
        if isinstance(node, ast.Dict):
            return self.dict_expr_is_unsafe(node)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self.query_expr_is_unsafe(elt) for elt in node.elts)
        if isinstance(node, ast.Call) and call_name(node.func).rsplit('.', 1)[-1] == 'dict':
            return any(self.query_expr_is_unsafe(arg) for arg in node.args)
        return self.expr_is_untrusted_object(node)

    def mark_assignment(self, names, value):
        is_untrusted = self.expr_is_untrusted_object(value)
        is_unsafe_query = self.query_expr_is_unsafe(value)
        has_request_value = self.expr_has_request_source(value)
        for name in names:
            if is_untrusted:
                self.untrusted_objects.add(name)
            else:
                self.untrusted_objects.discard(name)
            if is_unsafe_query:
                self.unsafe_queries.add(name)
            else:
                self.unsafe_queries.discard(name)
            if has_request_value:
                self.request_values.add(name)
            else:
                self.request_values.discard(name)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def sink_args(self, node, short):
        args = []
        if short in FILTER_METHODS:
            if node.args:
                args.append(node.args[0])
        elif short in UPDATE_METHODS:
            args.extend(node.args[:2])
        elif short in PIPELINE_METHODS:
            if node.args:
                args.append(node.args[0])
        elif short in COMMAND_METHODS:
            args.extend(node.args)
        for keyword in node.keywords:
            if keyword.arg in {'filter', 'query', 'pipeline', 'command', 'spec', 'where', 'update'}:
                args.append(keyword.value)
        return args

    def visit_Call(self, node):
        short = call_name(node.func).rsplit('.', 1)[-1]
        if short in (FILTER_METHODS | UPDATE_METHODS | PIPELINE_METHODS | COMMAND_METHODS):
            if any(self.query_expr_is_unsafe(arg) for arg in self.sink_args(node, short)):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = NoSQLInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_regex_dos_checks() {
  print_subheader "Request-controlled regex patterns"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable request-controlled regex checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled regex pattern reaches regex engine" "Use fixed allow-listed regexes or escape user input with re.escape before building patterns"
        else
          print_finding "good" "No request-controlled regex patterns detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REGEX_SINKS = {'compile', 'match', 'fullmatch', 'search', 'findall', 'finditer', 'split', 'sub', 'subn'}
PANDAS_REGEX_SINKS = {'contains', 'match', 'fullmatch', 'replace', 'extract', 'extractall', 'split'}
REQUEST_NAMES = {'request'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def keyword_value(node, name):
    for keyword in getattr(node, 'keywords', []):
        if keyword.arg == name:
            return keyword.value
    return None

def is_false(node):
    return isinstance(node, ast.Constant) and node.value is False

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

class RegexPatternAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.regex_modules = {'re', 'regex'}
        self.regex_functions = {}
        self.escape_functions = set()
        self.tainted_patterns = set()
        self.safe_patterns = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in {'re', 'regex'}:
                self.regex_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in {'re', 'regex'}:
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in REGEX_SINKS:
                    self.regex_functions[local] = alias.name
                elif alias.name == 'escape':
                    self.escape_functions.add(local)
        self.generic_visit(node)

    def is_regex_escape_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        if name in self.escape_functions:
            return True
        parts = name.split('.')
        return len(parts) >= 2 and parts[-1] == 'escape' and parts[-2] in self.regex_modules

    def expr_is_sanitized_regex(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_patterns
        if self.is_regex_escape_call(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_sanitized_regex(node.left) and self.expr_is_sanitized_regex(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_sanitized_regex(value.value):
                    continue
                return False
            return True
        if isinstance(node, ast.Call) and call_name(node.func) in {'str', 'bytes'} and node.args:
            return self.expr_is_sanitized_regex(node.args[0])
        return False

    def expr_contains_untrusted_pattern(self, node):
        if self.expr_is_sanitized_regex(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_patterns
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_untrusted_pattern(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_sanitized_regex(value)
        is_tainted = (not is_safe) and self.expr_contains_untrusted_pattern(value)
        for name in names:
            if is_safe:
                self.safe_patterns.add(name)
            else:
                self.safe_patterns.discard(name)
            if is_tainted:
                self.tainted_patterns.add(name)
            else:
                self.tainted_patterns.discard(name)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def regex_pattern_arg(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        parts = name.split('.')
        if isinstance(node.func, ast.Name) and node.func.id in self.regex_functions:
            return node.args[0] if node.args else keyword_value(node, 'pattern')
        if len(parts) >= 2 and parts[-1] in REGEX_SINKS and parts[-2] in self.regex_modules:
            return node.args[0] if node.args else keyword_value(node, 'pattern')
        if short in PANDAS_REGEX_SINKS and '.str.' in f'.{name}.':
            regex_keyword = keyword_value(node, 'regex')
            if regex_keyword is not None and is_false(regex_keyword):
                return None
            return node.args[0] if node.args else keyword_value(node, 'pat')
        return None

    def visit_Call(self, node):
        pattern = self.regex_pattern_arg(node)
        if pattern is not None and self.expr_contains_untrusted_pattern(pattern):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = RegexPatternAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_template_injection_checks() {
  print_subheader "Server-side template injection"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable template injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled template source reaches renderer" "Render fixed templates and pass user data only as escaped context values"
        else
          print_finding "good" "No request-controlled template sources detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
TEMPLATE_SOURCE_KEYWORDS = {'source', 'text', 'template', 'template_string', 'string'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def keyword_value(node, names):
    for keyword in getattr(node, 'keywords', []):
        if keyword.arg in names:
            return keyword.value
    return None

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

class TemplateInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.template_modules = {'jinja2', 'mako.template', 'django.template'}
        self.template_constructors = {'Template'}
        self.render_template_string_names = {'render_template_string'}
        self.tainted_templates = set()
        self.safe_templates = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in {'jinja2', 'mako.template', 'django.template'}:
                self.template_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in {'flask'}:
            for alias in node.names:
                if alias.name == 'render_template_string':
                    self.render_template_string_names.add(alias.asname or alias.name)
        if node.module in {'jinja2', 'mako.template', 'django.template'}:
            for alias in node.names:
                if alias.name == 'Template':
                    self.template_constructors.add(alias.asname or alias.name)
        self.generic_visit(node)

    def expr_is_safe_template(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_templates
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_template(node.left) and self.expr_is_safe_template(node.right)
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(value, ast.Constant) for value in node.values)
        return False

    def expr_contains_untrusted_template(self, node):
        if self.expr_is_safe_template(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_templates
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_untrusted_template(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_template(value)
        is_tainted = (not is_safe) and self.expr_contains_untrusted_template(value)
        for name in names:
            if is_safe:
                self.safe_templates.add(name)
            else:
                self.safe_templates.discard(name)
            if is_tainted:
                self.tainted_templates.add(name)
            else:
                self.tainted_templates.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_templates)
        old_tainted = set(self.tainted_templates)
        self.safe_templates.clear()
        self.tainted_templates.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_templates = old_safe
        self.tainted_templates = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def constructor_template_source(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        parts = name.split('.')
        if (
            short in self.template_constructors
            or name in self.template_constructors
            or (len(parts) >= 2 and parts[-1] == 'Template' and '.'.join(parts[:-1]) in self.template_modules)
        ):
            return node.args[0] if node.args else keyword_value(node, TEMPLATE_SOURCE_KEYWORDS)
        return None

    def render_template_string_source(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if name in self.render_template_string_names or short in self.render_template_string_names:
            return node.args[0] if node.args else keyword_value(node, {'source', 'template_string', 'string'})
        if short == 'from_string':
            return node.args[0] if node.args else keyword_value(node, {'source', 'template_string', 'string'})
        return None

    def visit_Call(self, node):
        source = self.render_template_string_source(node) or self.constructor_template_source(node)
        if source is not None and self.expr_contains_untrusted_template(source):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = TemplateInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_header_injection_checks() {
  print_subheader "HTTP response header injection"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable response header injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled value reaches HTTP response header" "Reject CR/LF, use fixed header names, and encode filenames with framework-safe helpers before setting headers"
        else
          print_finding "good" "No request-controlled response headers detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
HEADER_DICT_KEYWORDS = {'headers', 'response_headers'}
FILENAME_KEYWORDS = {'download_name', 'attachment_filename', 'filename', 'as_attachment_filename'}
HEADER_METHODS = {'add', 'set', 'setdefault', 'append', 'update'}
RESPONSE_FACTORIES = {
    'Response', 'flask.Response', 'make_response', 'flask.make_response',
    'HttpResponse', 'django.http.HttpResponse',
    'JsonResponse', 'django.http.JsonResponse',
    'StreamingHttpResponse', 'django.http.StreamingHttpResponse',
    'HTMLResponse', 'PlainTextResponse', 'JSONResponse',
    'starlette.responses.HTMLResponse', 'starlette.responses.PlainTextResponse',
    'starlette.responses.JSONResponse', 'fastapi.responses.HTMLResponse',
    'fastapi.responses.PlainTextResponse', 'fastapi.responses.JSONResponse',
    'FileResponse', 'django.http.FileResponse',
    'RedirectResponse', 'starlette.responses.RedirectResponse',
}
FILE_RESPONSE_FACTORIES = {
    'send_file', 'flask.send_file', 'FileResponse', 'django.http.FileResponse',
    'starlette.responses.FileResponse', 'fastapi.responses.FileResponse',
}
SAFE_HEADER_FUNCS = {
    'secure_filename', 'werkzeug.utils.secure_filename',
    'quote', 'urllib.parse.quote', 'quote_plus', 'urllib.parse.quote_plus',
    'urlquote', 'url_quote', 'escape_uri_path', 'iri_to_uri',
    'quote_header_value', 'sanitize_header_value', 'validate_header_value',
    'safe_header_value', 'clean_header_value',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

def keyword_values(node, names):
    return [keyword.value for keyword in getattr(node, 'keywords', []) if keyword.arg in names]

def dict_values(node):
    if not isinstance(node, ast.Dict):
        return []
    return [value for key, value in zip(node.keys, node.values) if key is not None]

class HeaderInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_safe_header(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_HEADER_FUNCS or short in SAFE_HEADER_FUNCS:
                return True
            if name in {'str', 'bytes'} and node.args:
                return self.expr_is_safe_header(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_header(node.left) and self.expr_is_safe_header(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_header(value.value):
                    continue
                return False
            return True
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_header(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_header(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        if any(self.assignment_target_is_header(target) for target in node.targets):
            if self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            if self.assignment_target_is_header(node.target) and self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def assignment_target_is_header(self, target):
        if not isinstance(target, ast.Subscript):
            return False
        owner = call_name(target.value)
        header_name = const_string(target.slice)
        if owner.endswith('.headers'):
            return True
        if header_name and (owner in HEADER_DICT_KEYWORDS or owner.endswith('_headers')):
            return True
        if header_name and any(part in owner.lower() for part in {'response', 'resp', 'httpresponse'}):
            return True
        if header_name and any(part in header_name.lower() for part in {'header', 'content-', 'location', 'etag', 'cache-control'}):
            return True
        return False

    def call_header_values(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if short in HEADER_METHODS and receiver is not None and call_name(receiver).endswith('.headers'):
            if short == 'update':
                for arg in node.args:
                    if isinstance(arg, ast.Dict):
                        values.extend(dict_values(arg))
                    else:
                        values.append(arg)
                values.extend(keyword.value for keyword in node.keywords)
            else:
                values.extend(node.args)
                values.extend(keyword.value for keyword in node.keywords if keyword.arg in {'value', 'default'})
        if name in RESPONSE_FACTORIES or short in RESPONSE_FACTORIES:
            for header_dict in keyword_values(node, HEADER_DICT_KEYWORDS):
                if isinstance(header_dict, ast.Dict):
                    values.extend(dict_values(header_dict))
                else:
                    values.append(header_dict)
        if name in FILE_RESPONSE_FACTORIES or short in FILE_RESPONSE_FACTORIES:
            values.extend(keyword_values(node, FILENAME_KEYWORDS))
        return values

    def visit_Call(self, node):
        if any(self.expr_contains_taint(value) for value in self.call_header_values(node)):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = HeaderInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_email_header_injection_checks() {
  print_subheader "Email header injection"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable email header injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled value reaches email header or envelope sink" "Reject CR/LF, validate email addresses, and sanitize subject/from/to/cc/bcc/reply-to/custom headers before sending mail"
        else
          print_finding "good" "No request-controlled email headers detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
EMAIL_CONSTRUCTORS = {
    'EmailMessage', 'django.core.mail.EmailMessage',
    'EmailMultiAlternatives', 'django.core.mail.EmailMultiAlternatives',
    'Message', 'flask_mail.Message',
}
SEND_MAIL_FUNCS = {
    'send_mail', 'django.core.mail.send_mail',
    'mail_admins', 'django.core.mail.mail_admins',
    'mail_managers', 'django.core.mail.mail_managers',
}
SEND_MASS_FUNCS = {'send_mass_mail', 'django.core.mail.send_mass_mail'}
SMTP_SEND_FUNCS = {'sendmail', 'send_message'}
EMAIL_HEADER_METHODS = {'add_header', 'replace_header'}
EMAIL_HEADER_NAMES = {
    'subject', 'from', 'to', 'cc', 'bcc', 'reply-to', 'sender',
    'return-path', 'resent-from', 'resent-to', 'resent-cc', 'resent-bcc',
}
HEADER_DICT_KEYWORDS = {'headers', 'extra_headers'}
EMAIL_VALUE_KEYWORDS = {
    'subject', 'from_email', 'from_addr', 'sender', 'recipient_list',
    'recipients', 'to', 'cc', 'bcc', 'reply_to', 'reply_to_email',
}
SAFE_EMAIL_FUNCS = {
    'sanitize_email_header', 'sanitize_email_address',
    'validate_email_header', 'validate_email_address',
    'allowlisted_email_address', 'allowlisted_email_header',
    'forbid_multi_line_headers', 'django.core.mail.message.forbid_multi_line_headers',
    'Header', 'email.header.Header',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

def keyword_values(node, names):
    return [keyword.value for keyword in getattr(node, 'keywords', []) if keyword.arg in names]

def dict_values(node):
    if not isinstance(node, ast.Dict):
        return []
    return [value for key, value in zip(node.keys, node.values) if key is not None]

class EmailHeaderInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_safe_email(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_EMAIL_FUNCS or short in SAFE_EMAIL_FUNCS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_safe_email(node.func.value) and all(
                    self.expr_is_safe_email(arg) for arg in node.args
                ) and all(self.expr_is_safe_email(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_email(node.left) and self.expr_is_safe_email(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_email(value.value):
                    continue
                return False
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.expr_is_safe_email(elt) for elt in node.elts)
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_email(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_email(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        if any(self.assignment_target_is_email_header(target) for target in node.targets):
            if self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            if self.assignment_target_is_email_header(node.target) and self.expr_contains_taint(node.value):
                self.remember_issue(node.lineno)
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def assignment_target_is_email_header(self, target):
        if not isinstance(target, ast.Subscript):
            return False
        owner = call_name(target.value)
        header_name = const_string(target.slice)
        if not header_name:
            return False
        owner_lower = owner.lower()
        header_lower = header_name.lower()
        if owner.endswith('_headers') and any(part in owner_lower for part in {'mail', 'email', 'mime', 'message'}):
            return True
        if any(part in owner_lower for part in {'msg', 'message', 'mail', 'email', 'mime'}):
            return header_lower in EMAIL_HEADER_NAMES or header_lower.startswith('x-')
        return False

    def constructor_values(self, node, short, name):
        values = []
        if short in EMAIL_CONSTRUCTORS or name in EMAIL_CONSTRUCTORS:
            if short == 'Message' or name == 'flask_mail.Message':
                arg_indexes = (0, 1, 4, 5, 6, 8, 11)
            elif short == 'EmailMultiAlternatives' or name == 'django.core.mail.EmailMultiAlternatives':
                arg_indexes = (0, 2, 3, 4, 8, 9)
            else:
                arg_indexes = (0, 2, 3, 4, 7, 8, 9)
            for idx in arg_indexes:
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(keyword_values(node, EMAIL_VALUE_KEYWORDS))
            for header_dict in keyword_values(node, HEADER_DICT_KEYWORDS):
                if isinstance(header_dict, ast.Dict):
                    values.extend(dict_values(header_dict))
                else:
                    values.append(header_dict)
        return values

    def send_mail_values(self, node, short, name):
        values = []
        if short in SEND_MAIL_FUNCS or name in SEND_MAIL_FUNCS:
            for idx in (0, 2, 3):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(keyword_values(node, EMAIL_VALUE_KEYWORDS | HEADER_DICT_KEYWORDS))
        if short in SEND_MASS_FUNCS or name in SEND_MASS_FUNCS:
            if node.args:
                values.append(node.args[0])
            values.extend(keyword_values(node, EMAIL_VALUE_KEYWORDS | HEADER_DICT_KEYWORDS))
        if short == 'sendmail':
            for idx in (0, 1):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(keyword_values(node, {'from_addr', 'to_addrs', 'sender', 'recipients', 'to'}))
        if short == 'send_message':
            for idx in (1, 2):
                if len(node.args) > idx:
                    values.append(node.args[idx])
            values.extend(keyword_values(node, {'from_addr', 'to_addrs', 'sender', 'recipients', 'to'}))
        return values

    def method_values(self, node, short):
        if short in EMAIL_HEADER_METHODS:
            return list(node.args[1:]) + [keyword.value for keyword in node.keywords]
        return []

    def visit_Call(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        values.extend(self.constructor_values(node, short, name))
        values.extend(self.send_mail_values(node, short, name))
        values.extend(self.method_values(node, short))
        if values and any(self.expr_contains_taint(value) for value in values):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = EmailHeaderInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_ldap_injection_checks() {
  print_subheader "LDAP filter/DN injection"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable LDAP injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled LDAP filter or DN reaches directory sink" "Escape LDAP filter values with escape_filter_chars(), escape DN fragments with escape_dn_chars(), or use fixed allow-lists before LDAP operations"
        else
          print_finding "good" "No request-controlled LDAP filters or DNs detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
LDAP_SEARCH_METHODS = {
    'search', 'search_s', 'search_st', 'search_ext', 'search_ext_s',
    'paged_search', 'paged_search_s', 'paged_search_ext_s',
}
LDAP_SECOND_ARG_FILTER_METHODS = {'search', 'paged_search'}
LDAP_DN_METHODS = {
    'add', 'add_s', 'delete', 'delete_s', 'modify', 'modify_s',
    'modify_dn', 'modify_dn_s', 'rename', 'rename_s', 'compare_s',
    'simple_bind_s', 'bind_s', 'rebind', 'rebind_s',
}
LDAP_CONSTRUCTORS = {'LDAPSearch', 'django_auth_ldap.config.LDAPSearch'}
FILTER_KEYWORDS = {'search_filter', 'filterstr', 'ldap_filter'}
DN_KEYWORDS = {'dn', 'user', 'user_dn', 'bind_dn', 'base_dn'}
SAFE_LDAP_FUNCS = {
    'escape_filter_chars', 'ldap.filter.escape_filter_chars',
    'escape_dn_chars', 'ldap.dn.escape_dn_chars',
    'validate_ldap_filter_value', 'validate_ldap_dn_value',
    'sanitize_ldap_filter_value', 'sanitize_ldap_dn_value',
    'allowlisted_ldap_value', 'allowlisted_ldap_dn',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

def keyword_values(node, names):
    return [keyword.value for keyword in getattr(node, 'keywords', []) if keyword.arg in names]

class LDAPInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_safe_ldap(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_LDAP_FUNCS or short in SAFE_LDAP_FUNCS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_safe_ldap(node.func.value) and all(
                    self.expr_is_safe_ldap(arg) for arg in node.args
                ) and all(self.expr_is_safe_ldap(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_safe_ldap(node.left) and self.expr_is_safe_ldap(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_safe_ldap(value.value):
                    continue
                return False
            return True
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_safe_ldap(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_safe_ldap(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def search_filter_args(self, node, short):
        args = []
        if short in LDAP_SECOND_ARG_FILTER_METHODS:
            if len(node.args) >= 2:
                args.append(node.args[1])
        elif short in LDAP_SEARCH_METHODS:
            if len(node.args) >= 3:
                args.append(node.args[2])
        if short in LDAP_CONSTRUCTORS:
            if len(node.args) >= 3:
                args.append(node.args[2])
        args.extend(keyword_values(node, FILTER_KEYWORDS))
        return args

    def dn_args(self, node, short):
        args = []
        if short in LDAP_DN_METHODS and node.args:
            args.append(node.args[0])
        args.extend(keyword_values(node, DN_KEYWORDS))
        return args

    def visit_Call(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        values = []
        if short in LDAP_SEARCH_METHODS or short in LDAP_CONSTRUCTORS or name in LDAP_CONSTRUCTORS:
            values.extend(self.search_filter_args(node, short))
        if short in LDAP_DN_METHODS:
            values.extend(self.dn_args(node, short))
        if values and any(self.expr_contains_taint(value) for value in values):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = LDAPInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_command_injection_checks() {
  print_subheader "Command injection dataflow"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable command injection checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "User-controlled command reaches shell or executable selection" "Use a fixed executable with argv arrays, validate command allow-lists before dispatch, and avoid shell=True or shell -c"
        else
          print_finding "good" "No command injection dataflow detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import os
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
SUBPROCESS_CALLS = {'run', 'call', 'check_call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}
OS_COMMAND_CALLS = {'system', 'popen'}
OS_EXEC_CALLS = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execle', 'execlp', 'execlpe'}
OS_SPAWN_CALLS = {'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe'}
SHELL_NAMES = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'cmd', 'powershell', 'pwsh'}
SHELL_FLAGS = {'-c', '-lc', '/c', '-command', '-encodedcommand'}
SOURCE_RE = re.compile(
    r"(?:request\.(?:args|form|values|json|data|body|GET|POST|get_json)|"
    r"flask\.request|django\.http\.request|sys\.argv|os\.environ|"
    r"event\s*\[|params\s*\[|input\s*\(|raw_input\s*\()",
    re.IGNORECASE,
)
SANITIZER_RE = re.compile(r"\b(?:shlex\.quote|pipes\.quote)\s*\(", re.IGNORECASE)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

def is_true(node):
    return isinstance(node, ast.Constant) and node.value is True

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def all_static_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all_static_strings(node.left) and all_static_strings(node.right)
    return False

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def shell_name(value):
    if not value:
        return ''
    return os.path.basename(value).lower()

class CommandInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.subprocess_modules = {'subprocess'}
        self.os_modules = {'os'}
        self.direct_calls = {}
        self.tainted_names = set()
        self.shell_command_vars = set()
        self.executable_vars = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_sanitized(self, node):
        return bool(SANITIZER_RE.search(self.segment(node)))

    def expr_has_source(self, node):
        return bool(SOURCE_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def expr_is_tainted(self, node):
        if self.expr_is_sanitized(node):
            return False
        return self.expr_has_source(node) or bool(self.names_in(node) & self.tainted_names)

    def expr_is_dynamic_string(self, node):
        if self.expr_is_tainted(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) for part in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not all_static_strings(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return False

    def arg_is_shell_command(self, node):
        if isinstance(node, ast.Name) and node.id in self.shell_command_vars:
            return True
        return self.expr_is_dynamic_string(node)

    def executable_is_dynamic(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.executable_vars or node.id in self.tainted_names
        return self.expr_is_dynamic_string(node)

    def shell_c_payload(self, node):
        if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 3:
            return None
        executable = const_string(node.elts[0])
        flag = const_string(node.elts[1])
        if shell_name(executable) in SHELL_NAMES and flag and flag.lower() in SHELL_FLAGS:
            return node.elts[2]
        return None

    def list_executable_is_dynamic(self, node):
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            return self.executable_is_dynamic(node.elts[0])
        return False

    def canonical_call(self, node):
        name = call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for module in self.subprocess_modules:
            for func in SUBPROCESS_CALLS:
                if name == f'{module}.{func}':
                    return f'subprocess.{func}'
        for module in self.os_modules:
            for func in OS_COMMAND_CALLS | OS_EXEC_CALLS | OS_SPAWN_CALLS:
                if name == f'{module}.{func}':
                    return f'os.{func}'
        return ''

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'subprocess':
                self.subprocess_modules.add(local)
            elif alias.name == 'os':
                self.os_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'subprocess' and alias.name in SUBPROCESS_CALLS:
                self.direct_calls[local] = f'subprocess.{alias.name}'
            elif module == 'os' and alias.name in (OS_COMMAND_CALLS | OS_EXEC_CALLS | OS_SPAWN_CALLS):
                self.direct_calls[local] = f'os.{alias.name}'
        self.generic_visit(node)

    def mark_assignment(self, names, value):
        tainted = self.expr_is_tainted(value)
        shell_command = self.expr_is_dynamic_string(value)
        dynamic_executable = self.list_executable_is_dynamic(value)
        for name in names:
            if tainted:
                self.tainted_names.add(name)
            else:
                self.tainted_names.discard(name)
            if shell_command:
                self.shell_command_vars.add(name)
            else:
                self.shell_command_vars.discard(name)
            if dynamic_executable:
                self.executable_vars.add(name)
            else:
                self.executable_vars.discard(name)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def subprocess_arg_is_unsafe(self, node):
        if not node.args:
            return False
        command = node.args[0]
        shell_payload = self.shell_c_payload(command)
        if shell_payload is not None:
            return self.arg_is_shell_command(shell_payload)
        if is_true(keyword_value(node, 'shell')):
            return self.arg_is_shell_command(command)
        return self.list_executable_is_dynamic(command) or (
            isinstance(command, ast.Name) and command.id in self.executable_vars
        )

    def os_exec_arg_is_unsafe(self, node, func):
        if func in OS_SPAWN_CALLS:
            executable_index = 1
        else:
            executable_index = 0
        if len(node.args) <= executable_index:
            return False
        return self.executable_is_dynamic(node.args[executable_index])

    def visit_Call(self, node):
        canonical = self.canonical_call(node)
        if canonical:
            module, func = canonical.rsplit('.', 1)
            unsafe = False
            if module == 'subprocess':
                if func in {'getoutput', 'getstatusoutput'}:
                    unsafe = bool(node.args and self.arg_is_shell_command(node.args[0]))
                else:
                    unsafe = self.subprocess_arg_is_unsafe(node)
            elif module == 'os' and func in OS_COMMAND_CALLS:
                unsafe = bool(node.args and self.arg_is_shell_command(node.args[0]))
            elif module == 'os' and func in (OS_EXEC_CALLS | OS_SPAWN_CALLS):
                unsafe = self.os_exec_arg_is_unsafe(node, func)
            if unsafe:
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = CommandInjectionAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_subprocess_timeout_checks() {
  print_subheader "Subprocess calls without timeouts"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable subprocess timeout checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "warning" "$a" "Subprocess call has no bounded timeout" "Pass timeout=... to subprocess.run/call/check_* or wrap long-running process execution with an explicit deadline"
        else
          print_finding "good" "No subprocess calls missing explicit timeouts detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
TIMEOUT_CAPABLE_CALLS = {'run', 'call', 'check_call', 'check_output'}
NO_TIMEOUT_API_CALLS = {'getoutput', 'getstatusoutput'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

def timeout_value_is_bounded(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value in {None, False}:
        return False
    return True

class SubprocessTimeoutAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.subprocess_modules = {'subprocess'}
        self.direct_calls = {}
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def canonical_call(self, node):
        name = call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for module in self.subprocess_modules:
            for func in TIMEOUT_CAPABLE_CALLS | NO_TIMEOUT_API_CALLS:
                if name == f'{module}.{func}':
                    return f'subprocess.{func}'
        return ''

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'subprocess':
                self.subprocess_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        if module == 'subprocess':
            for alias in node.names:
                if alias.name in (TIMEOUT_CAPABLE_CALLS | NO_TIMEOUT_API_CALLS):
                    self.direct_calls[alias.asname or alias.name] = f'subprocess.{alias.name}'
        self.generic_visit(node)

    def visit_Call(self, node):
        canonical = self.canonical_call(node)
        if canonical:
            func = canonical.rsplit('.', 1)[-1]
            if func in NO_TIMEOUT_API_CALLS or not timeout_value_is_bounded(keyword_value(node, 'timeout')):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SubprocessTimeoutAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_unsafe_deserialization_checks() {
  print_subheader "Unsafe deserialization loaders"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable unsafe deserialization checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Unsafe Python deserialization loader" "Avoid pickle-compatible loaders for untrusted data; use JSON/schema formats or explicitly safe artifact loading"
        else
          print_finding "good" "No unsafe Python deserialization loaders detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}

MODULE_CALLS = {
    'marshal': {'load', 'loads'},
    'dill': {'load', 'loads'},
    'cloudpickle': {'load', 'loads'},
    'joblib': {'load'},
    'jsonpickle': {'decode', 'loads'},
    'shelve': {'open'},
    'pandas': {'read_pickle'},
    'yaml': {'unsafe_load', 'unsafe_load_all'},
}
SPECIAL_CALLS = {
    'numpy': {'load'},
    'torch': {'load'},
}
MODULE_ALIASES = {
    'marshal': {'marshal'},
    'dill': {'dill'},
    'cloudpickle': {'cloudpickle'},
    'joblib': {'joblib', 'sklearn.externals.joblib'},
    'jsonpickle': {'jsonpickle'},
    'shelve': {'shelve'},
    'pandas': {'pandas'},
    'yaml': {'yaml'},
    'numpy': {'numpy'},
    'torch': {'torch'},
}
FROM_MODULES = {
    'marshal': 'marshal',
    'dill': 'dill',
    'cloudpickle': 'cloudpickle',
    'joblib': 'joblib',
    'sklearn.externals.joblib': 'joblib',
    'jsonpickle': 'jsonpickle',
    'shelve': 'shelve',
    'pandas': 'pandas',
    'yaml': 'yaml',
    'numpy': 'numpy',
    'torch': 'torch',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def is_true(node):
    return isinstance(node, ast.Constant) and node.value is True

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

class UnsafeDeserializerAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.modules = {key: set(value) for key, value in MODULE_ALIASES.items()}
        self.direct_calls = {}
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            canonical = FROM_MODULES.get(alias.name)
            if canonical:
                self.modules[canonical].add(alias.asname or alias.name)
            elif alias.name.endswith('.joblib'):
                self.modules['joblib'].add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        if module == 'sklearn.externals':
            for alias in node.names:
                if alias.name == 'joblib':
                    self.modules['joblib'].add(alias.asname or alias.name)
            self.generic_visit(node)
            return
        canonical = FROM_MODULES.get(module)
        if canonical:
            allowed = MODULE_CALLS.get(canonical, set()) | SPECIAL_CALLS.get(canonical, set())
            for alias in node.names:
                if alias.name in allowed:
                    self.direct_calls[alias.asname or alias.name] = f'{canonical}.{alias.name}'
        self.generic_visit(node)

    def canonical_call(self, node):
        name = call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for canonical, funcs in {**MODULE_CALLS, **SPECIAL_CALLS}.items():
            for alias in self.modules.get(canonical, set()):
                for func in funcs:
                    if name == f'{alias}.{func}':
                        return f'{canonical}.{func}'
        if name.endswith('.joblib.load'):
            return 'joblib.load'
        return ''

    def is_unsafe_call(self, node):
        canonical = self.canonical_call(node)
        if not canonical:
            return False
        module, func = canonical.rsplit('.', 1)
        if module == 'numpy' and func == 'load':
            return is_true(keyword_value(node, 'allow_pickle'))
        if module == 'torch' and func == 'load':
            return not is_true(keyword_value(node, 'weights_only'))
        return True

    def visit_Call(self, node):
        if self.is_unsafe_call(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = UnsafeDeserializerAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_password_hashing_checks() {
  print_subheader "Password hashing misconfiguration"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable password hashing checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Weak or plaintext password hashing configured" "Use Argon2, bcrypt, scrypt, or PBKDF2-SHA256 with current work factors"
        else
          print_finding "good" "No weak password hashing configurations detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
WEAK_SCHEMES = {
    'plain', 'plaintext', 'md5', 'sha1', 'unsalted_md5', 'unsalted_sha1',
    'md5_crypt', 'des_crypt', 'ldap_md5', 'ldap_salted_md5', 'pbkdf2_sha1',
}
WEAK_DJANGO_HASHER_RE = re.compile(r'(?:^|\.)(?:((?:un)?salted)?(?:md5|sha1)|pbkdf2sha1)passwordhasher$|(?:^|\.)cryptpasswordhasher$', re.IGNORECASE)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [call_name(target)]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def normalized_scheme(value):
    text = value.strip().lower()
    if ':' in text:
        return text.split(':', 1)[0]
    return text

def is_weak_scheme_string(value):
    scheme = normalized_scheme(value)
    lowered = value.strip().lower()
    return scheme in WEAK_SCHEMES or lowered.startswith('pbkdf2:sha1') or bool(WEAK_DJANGO_HASHER_RE.search(value))

def string_literals(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            yield from string_literals(elt)
    elif isinstance(node, ast.Dict):
        for key in node.keys:
            if key is not None:
                yield from string_literals(key)
        for value in node.values:
            yield from string_literals(value)

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

class PasswordHashingAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []
        self.seen_lines = set()
        self.werkzeug_modules = {'werkzeug.security'}
        self.generate_password_hash_names = {'generate_password_hash'}
        self.crypt_context_names = {'CryptContext', 'passlib.context.CryptContext'}
        self.make_password_names = {'make_password', 'django.contrib.auth.hashers.make_password'}
        self.passlib_hash_modules = {'passlib.hash'}
        self.weak_passlib_hashers = set(WEAK_SCHEMES)

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'werkzeug.security':
                self.werkzeug_modules.add(local)
            elif alias.name == 'passlib.hash':
                self.passlib_hash_modules.add(local)
            elif alias.name == 'passlib.context':
                self.crypt_context_names.add(f'{local}.CryptContext')
            elif alias.name == 'django.contrib.auth.hashers':
                self.make_password_names.add(f'{local}.make_password')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'werkzeug.security' and alias.name == 'generate_password_hash':
                self.generate_password_hash_names.add(local)
            elif module == 'passlib.context' and alias.name == 'CryptContext':
                self.crypt_context_names.add(local)
            elif module == 'django.contrib.auth.hashers' and alias.name == 'make_password':
                self.make_password_names.add(local)
            elif module == 'passlib.hash':
                if alias.name in WEAK_SCHEMES:
                    self.weak_passlib_hashers.add(local)
        self.generic_visit(node)

    def is_generate_password_hash(self, name):
        return name in self.generate_password_hash_names or any(name == f'{module}.generate_password_hash' for module in self.werkzeug_modules)

    def is_crypt_context(self, name):
        return name in self.crypt_context_names

    def is_make_password(self, name):
        return name in self.make_password_names

    def passlib_hasher_is_weak(self, name):
        parts = name.split('.')
        if len(parts) >= 2 and parts[-1] in {'hash', 'verify'}:
            owner = parts[-2]
            if owner in self.weak_passlib_hashers or owner in WEAK_SCHEMES:
                return True
        for module in self.passlib_hash_modules:
            prefix = f'{module}.'
            if name.startswith(prefix):
                rest = name[len(prefix):].split('.')
                if rest and rest[0] in WEAK_SCHEMES:
                    return True
        return False

    def call_uses_weak_method(self, node, keyword, positional_index=None):
        value = keyword_value(node, keyword)
        if value is None and positional_index is not None and len(node.args) > positional_index:
            value = node.args[positional_index]
        literal = const_string(value) if value is not None else None
        return bool(literal and is_weak_scheme_string(literal))

    def crypt_context_is_weak(self, node):
        schemes = keyword_value(node, 'schemes')
        if schemes is None:
            return False
        return any(is_weak_scheme_string(value) for value in string_literals(schemes))

    def password_hashers_value_is_weak(self, node):
        return any(is_weak_scheme_string(value) for value in string_literals(node))

    def visit_Assign(self, node):
        if any(name.endswith('PASSWORD_HASHERS') for target in node.targets for name in target_names(target)):
            if self.password_hashers_value_is_weak(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        if self.is_generate_password_hash(name) and self.call_uses_weak_method(node, 'method', positional_index=1):
            self.remember_issue(node.lineno)
        elif self.is_crypt_context(name) and self.crypt_context_is_weak(node):
            self.remember_issue(node.lineno)
        elif self.is_make_password(name) and self.call_uses_weak_method(node, 'hasher', positional_index=1):
            self.remember_issue(node.lineno)
        elif self.passlib_hasher_is_weak(name):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = PasswordHashingAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_crypto_misuse_checks() {
  print_subheader "Weak or static cryptography configuration"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable cryptography misuse checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Weak cryptographic mode, cipher, or static IV/nonce" "Use AEAD modes such as AES-GCM or ChaCha20-Poly1305 with fresh random nonces, and avoid ECB/DES/ARC4/static IVs"
        else
          print_finding "good" "No weak crypto modes or static IV/nonces detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
WEAK_ALGORITHMS = {'ARC2', 'ARC4', 'Blowfish', 'CAST5', 'DES', 'IDEA', 'SEED', 'TripleDES'}
IV_MODES = {'CBC', 'CFB', 'CFB8', 'OFB', 'CTR', 'GCM'}
STATIC_PARAM_NAMES = {'iv', 'nonce', 'initial_value', 'initial_counter'}
AEAD_CONSTRUCTORS = {'AESCCM', 'AESGCM', 'ChaCha20Poly1305'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def short_name(name):
    return name.rsplit('.', 1)[-1] if name else ''

def owner_short_name(name):
    parts = name.split('.')
    return parts[-2] if len(parts) >= 2 else ''

def is_int_constant(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, int)

def is_static_literal(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return len(node.value) > 0
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, (ast.Tuple, ast.List)):
        return bool(node.elts) and all(isinstance(elt, ast.Constant) for elt in node.elts)
    return False

def is_static_material(node, static_names):
    if isinstance(node, ast.Name):
        return node.id in static_names
    if is_static_literal(node):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return is_static_material(node.left, static_names) and is_static_material(node.right, static_names)
        if isinstance(node.op, ast.Mult):
            return (
                is_static_material(node.left, static_names) and is_int_constant(node.right)
            ) or (
                is_static_material(node.right, static_names) and is_int_constant(node.left)
            )
    if isinstance(node, ast.Call):
        name = call_name(node.func)
        short = short_name(name)
        if short in {'bytes', 'bytearray'} and node.args and is_int_constant(node.args[0]):
            return True
        if name in {'bytes.fromhex', 'bytearray.fromhex'} and node.args and is_static_literal(node.args[0]):
            return True
        if short in {'b64decode', 'urlsafe_b64decode', 'unhexlify'} and node.args and is_static_literal(node.args[0]):
            return True
    return False

def is_mode_attr(node, mode_name):
    name = call_name(node)
    return name == f'MODE_{mode_name}' or name.endswith(f'.MODE_{mode_name}')

def is_ecb_mode(node):
    name = call_name(node)
    short = short_name(name)
    if isinstance(node, ast.Call):
        return short == 'ECB'
    return is_mode_attr(node, 'ECB')

def is_iv_mode(node):
    name = call_name(node)
    short = short_name(name)
    if isinstance(node, ast.Call):
        return short in IV_MODES
    return any(is_mode_attr(node, mode) for mode in IV_MODES)

class CryptoMisuseAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.static_names = set()
        self.aead_vars = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def mark_assignment(self, names, value):
        constructs_aead = self.call_constructs_aead(value)
        is_static = is_static_material(value, self.static_names)
        for name in names:
            if constructs_aead:
                self.aead_vars.add(name)
            else:
                self.aead_vars.discard(name)
            if is_static:
                self.static_names.add(name)
            else:
                self.static_names.discard(name)

    def call_constructs_aead(self, node):
        return isinstance(node, ast.Call) and short_name(call_name(node.func)) in AEAD_CONSTRUCTORS

    def call_uses_weak_algorithm(self, node):
        name = call_name(node.func)
        short = short_name(name)
        owner = owner_short_name(name)
        return short in WEAK_ALGORITHMS or (short == 'new' and owner in WEAK_ALGORITHMS)

    def call_uses_static_iv_or_nonce(self, node):
        name = call_name(node.func)
        short = short_name(name)
        owner = owner_short_name(name)

        for keyword in node.keywords:
            if keyword.arg in STATIC_PARAM_NAMES and is_static_material(keyword.value, self.static_names):
                return True

        if short in IV_MODES and node.args and is_static_material(node.args[0], self.static_names):
            return True

        if short == 'new' and len(node.args) >= 3 and owner in {'AES', 'DES', 'DES3', 'Blowfish', 'CAST', 'ARC2'}:
            mode = node.args[1]
            if is_iv_mode(mode) and is_static_material(node.args[2], self.static_names):
                return True

        if short in {'encrypt', 'decrypt'} and node.args:
            receiver = call_name(node.func.value) if isinstance(node.func, ast.Attribute) else ''
            receiver_short = short_name(receiver)
            if receiver_short in AEAD_CONSTRUCTORS or receiver in self.aead_vars:
                return is_static_material(node.args[0], self.static_names)

        return False

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        if is_ecb_mode(node) or self.call_uses_weak_algorithm(node) or self.call_uses_static_iv_or_nonce(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = CryptoMisuseAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_constant_time_compare_checks() {
  print_subheader "Timing-safe comparison for secrets"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable constant-time comparison checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Secret, signature, or token compared with ==/!=" "Use hmac.compare_digest() or secrets.compare_digest() for HMACs, API keys, CSRF tokens, reset tokens, and other secret material"
        else
          print_finding "good" "No timing-sensitive secret equality comparisons detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
SENSITIVE_RE = re.compile(
    r'(hmac|mac|signature|sig|token|secret|api_?key|csrf|xsrf|nonce|digest|password|passwd|reset|auth|bearer|webhook)',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def name_is_sensitive(name):
    return bool(name and SENSITIVE_RE.search(name))

class ConstantTimeCompareAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.sensitive_names = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_sensitive(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.sensitive_names or name_is_sensitive(node.id)
        if isinstance(node, ast.Attribute):
            return name_is_sensitive(node.attr) or name_is_sensitive(call_name(node))
        if isinstance(node, ast.Subscript):
            key = const_string(node.slice)
            return name_is_sensitive(key or '') or self.expr_is_sensitive(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            owner = name.rsplit('.', 1)[0] if '.' in name else ''
            return (
                name_is_sensitive(name)
                or short in {'digest', 'hexdigest'}
                or name in {'hmac.new', 'hashlib.pbkdf2_hmac'}
                or owner == 'hmac'
            )
        if isinstance(node, ast.BinOp):
            return self.expr_is_sensitive(node.left) or self.expr_is_sensitive(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_sensitive(value) for value in node.values)
        return False

    def mark_assignment(self, names, value):
        value_sensitive = self.expr_is_sensitive(value)
        for name in names:
            if name_is_sensitive(name) or value_sensitive:
                self.sensitive_names.add(name)
            else:
                self.sensitive_names.discard(name)

    def visit_FunctionDef(self, node):
        old_sensitive = set(self.sensitive_names)
        self.sensitive_names.clear()
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if name_is_sensitive(arg.arg):
                self.sensitive_names.add(arg.arg)
        if node.args.vararg and name_is_sensitive(node.args.vararg.arg):
            self.sensitive_names.add(node.args.vararg.arg)
        if node.args.kwarg and name_is_sensitive(node.args.kwarg.arg):
            self.sensitive_names.add(node.args.kwarg.arg)
        for stmt in node.body:
            self.visit(stmt)
        self.sensitive_names = old_sensitive

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            values = [node.left] + list(node.comparators)
            if any(self.expr_is_sensitive(value) for value in values):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = ConstantTimeCompareAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_security_assert_checks() {
  print_subheader "Security-sensitive assert statements"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable security-sensitive assert checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Security-sensitive assert stripped by -O" "Use explicit if/raise checks for authorization, ownership, CSRF, token, and permission validation"
        else
          print_finding "good" "No security-sensitive assert statements detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
SECURITY_RE = re.compile(
    r'(auth|authori[sz]e|permission|perm|privilege|role|admin|staff|superuser|owner|tenant|account|session|csrf|xsrf|token|secret|api_?key|signature|password|passwd|jwt|bearer|credential|scope|acl|access|login|authenticated|has_?perm|can_)',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def name_is_security_sensitive(name):
    return bool(name and SECURITY_RE.search(name))

def expr_is_security_sensitive(node):
    if isinstance(node, ast.Name):
        return name_is_security_sensitive(node.id)
    if isinstance(node, ast.Attribute):
        return name_is_security_sensitive(node.attr) or name_is_security_sensitive(call_name(node))
    if isinstance(node, ast.Subscript):
        key = const_string(node.slice)
        return name_is_security_sensitive(key or '') or expr_is_security_sensitive(node.value)
    if isinstance(node, ast.Call):
        return (
            name_is_security_sensitive(call_name(node.func))
            or any(expr_is_security_sensitive(arg) for arg in node.args)
            or any(name_is_security_sensitive(keyword.arg or '') or expr_is_security_sensitive(keyword.value) for keyword in node.keywords)
        )
    if isinstance(node, ast.Compare):
        return expr_is_security_sensitive(node.left) or any(expr_is_security_sensitive(value) for value in node.comparators)
    if isinstance(node, ast.BoolOp):
        return any(expr_is_security_sensitive(value) for value in node.values)
    if isinstance(node, ast.UnaryOp):
        return expr_is_security_sensitive(node.operand)
    if isinstance(node, ast.BinOp):
        return expr_is_security_sensitive(node.left) or expr_is_security_sensitive(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return name_is_security_sensitive(node.value)
    return False

class SecurityAssertAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.context_names = []
        self.issues = []

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def context_is_security_sensitive(self):
        return any(name_is_security_sensitive(name) for name in self.context_names)

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def visit_ClassDef(self, node):
        self.context_names.append(node.name)
        self.generic_visit(node)
        self.context_names.pop()

    def visit_FunctionDef(self, node):
        self.context_names.append(node.name)
        self.generic_visit(node)
        self.context_names.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assert(self, node):
        if expr_is_security_sensitive(node.test) or self.context_is_security_sensitive():
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SecurityAssertAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_file_permission_checks() {
  print_subheader "Unsafe filesystem permission modes"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable filesystem permission checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "World-writable file mode or permissive umask" "Avoid 0o777/0o666-style modes and umask(0); use least-privilege modes such as 0o700 for directories and 0o600/0o640 for files"
        else
          print_finding "good" "No world-writable file modes or permissive umasks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
STAT_MODE_BITS = {
    'S_IRUSR': 0o400, 'S_IWUSR': 0o200, 'S_IXUSR': 0o100,
    'S_IRGRP': 0o040, 'S_IWGRP': 0o020, 'S_IXGRP': 0o010,
    'S_IROTH': 0o004, 'S_IWOTH': 0o002, 'S_IXOTH': 0o001,
    'S_IRWXU': 0o700, 'S_IRWXG': 0o070, 'S_IRWXO': 0o007,
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

def short_name(name):
    return name.rsplit('.', 1)[-1] if name else ''

def mode_value(node, mode_names):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in mode_names:
            return mode_names[node.id]
        if node.id in STAT_MODE_BITS:
            return STAT_MODE_BITS[node.id]
    if isinstance(node, ast.Attribute):
        name = call_name(node)
        attr = short_name(name)
        if attr in STAT_MODE_BITS and (name.startswith('stat.') or attr == name):
            return STAT_MODE_BITS[attr]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = mode_value(node.left, mode_names)
        right = mode_value(node.right, mode_names)
        if left is not None and right is not None:
            return left | right
    return None

def is_world_writable(mode):
    return mode is not None and bool(mode & 0o002)

def has_insecure_mode_arg(node, mode_names, positional_index):
    mode_node = keyword_value(node, 'mode')
    if mode_node is None and len(node.args) > positional_index:
        mode_node = node.args[positional_index]
    return is_world_writable(mode_value(mode_node, mode_names))

class FilePermissionAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.mode_names = {}
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def mark_assignment(self, names, value):
        value = mode_value(value, self.mode_names)
        for name in names:
            if value is None:
                self.mode_names.pop(name, None)
            else:
                self.mode_names[name] = value

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        short = short_name(name)
        if short in {'chmod', 'lchmod', 'fchmod', 'fchmodat'}:
            mode_index = 0 if isinstance(node.func, ast.Attribute) and not name.startswith('os.') else 1
            if has_insecure_mode_arg(node, self.mode_names, positional_index=mode_index):
                self.remember_issue(node.lineno)
        elif short in {'mkdir', 'makedirs'}:
            mode_index = 0 if isinstance(node.func, ast.Attribute) and not name.startswith('os.') else 1
            if has_insecure_mode_arg(node, self.mode_names, positional_index=mode_index):
                self.remember_issue(node.lineno)
        elif name == 'os.open' or short == 'open':
            if name == 'os.open' and has_insecure_mode_arg(node, self.mode_names, positional_index=2):
                self.remember_issue(node.lineno)
        elif short == 'umask':
            mode_node = node.args[0] if node.args else keyword_value(node, 'mask')
            if mode_value(mode_node, self.mode_names) == 0:
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = FilePermissionAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_http_timeout_checks() {
  print_subheader "Outbound HTTP calls without timeouts"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable outbound HTTP timeout checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "warning" "$a" "Outbound HTTP call has no explicit timeout" "Pass timeout=... or configure the HTTP client with a bounded timeout"
        else
          print_finding "good" "No outbound HTTP calls missing explicit timeouts detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'send'}
URLLIB3_METHODS = {'request', 'request_encode_url', 'request_encode_body', 'urlopen'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None

def timeout_value_is_bounded(node):
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value in {None, False}:
        return False
    return True

def has_bounded_timeout(call):
    return timeout_value_is_bounded(keyword_value(call, 'timeout'))

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

class HttpTimeoutAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []
        self.seen_lines = set()
        self.requests_modules = {'requests'}
        self.httpx_modules = {'httpx'}
        self.urllib_request_modules = {'urllib.request'}
        self.urllib3_modules = {'urllib3'}
        self.aiohttp_modules = {'aiohttp'}
        self.direct_calls = {}
        self.http_client_vars = {}

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'requests':
                self.requests_modules.add(local)
            elif alias.name == 'httpx':
                self.httpx_modules.add(local)
            elif alias.name == 'urllib.request':
                self.urllib_request_modules.add(local)
            elif alias.name == 'urllib3':
                self.urllib3_modules.add(local)
            elif alias.name == 'aiohttp':
                self.aiohttp_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'requests', 'httpx'} and alias.name in HTTP_METHODS:
                self.direct_calls[local] = module
            elif module == 'urllib.request' and alias.name == 'urlopen':
                self.direct_calls[local] = 'urllib.request'
            elif module == 'urllib3' and alias.name in {'PoolManager', 'ProxyManager'}:
                self.direct_calls[local] = f'urllib3.{alias.name}'
            elif module == 'aiohttp' and alias.name == 'ClientSession':
                self.direct_calls[local] = 'aiohttp.ClientSession'
        self.generic_visit(node)

    def is_requests_or_httpx_module_call(self, name, short):
        if self.direct_calls.get(name) in {'requests', 'httpx'}:
            return True
        return short in HTTP_METHODS and (
            any(name == f'{module}.{short}' for module in self.requests_modules)
            or any(name == f'{module}.{short}' for module in self.httpx_modules)
        )

    def is_urlopen_call(self, name):
        return (
            self.direct_calls.get(name) == 'urllib.request'
            or any(name == f'{module}.urlopen' for module in self.urllib_request_modules)
        )

    def is_http_client_constructor(self, name):
        if self.direct_calls.get(name) in {'aiohttp.ClientSession', 'urllib3.PoolManager', 'urllib3.ProxyManager'}:
            return True
        return (
            any(name in {f'{module}.Client', f'{module}.AsyncClient'} for module in self.httpx_modules)
            or any(name == f'{module}.ClientSession' for module in self.aiohttp_modules)
            or any(name in {f'{module}.PoolManager', f'{module}.ProxyManager'} for module in self.urllib3_modules)
        )

    def client_var_has_timeout(self, owner):
        return self.http_client_vars.get(owner, False)

    def call_missing_timeout(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        if self.is_http_client_constructor(name):
            return not has_bounded_timeout(node)
        if self.is_requests_or_httpx_module_call(name, short):
            return not has_bounded_timeout(node)
        if self.is_urlopen_call(name):
            return not has_bounded_timeout(node)
        if owner in self.http_client_vars and short in (HTTP_METHODS | URLLIB3_METHODS):
            return not (has_bounded_timeout(node) or self.client_var_has_timeout(owner))
        return False

    def remember_client_assignments(self, targets, value):
        if not isinstance(value, ast.Call):
            return
        if self.is_http_client_constructor(call_name(value.func)):
            safe = has_bounded_timeout(value)
            for target in targets:
                for name in target_names(target):
                    self.http_client_vars[name] = safe

    def visit_Assign(self, node):
        self.remember_client_assignments(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.remember_client_assignments([node.target], node.value)
        self.generic_visit(node)

    def visit_With(self, node):
        self.visit_with_like(node)

    def visit_AsyncWith(self, node):
        self.visit_with_like(node)

    def visit_with_like(self, node):
        old_clients = dict(self.http_client_vars)
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and item.optional_vars is not None:
                self.remember_client_assignments([item.optional_vars], item.context_expr)
        for item in node.items:
            self.visit(item.context_expr)
        for stmt in node.body:
            self.visit(stmt)
        self.http_client_vars = old_clients

    def visit_Call(self, node):
        if self.call_missing_timeout(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = HttpTimeoutAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_archive_extraction_checks() {
  print_subheader "Archive extraction path traversal"
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Archive extraction path traversal risk" "Validate every archive member stays under the destination, or use tarfile extraction filters where available"
        else
          print_finding "good" "No unvalidated archive extract()/extractall() calls detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
SAFE_CONTEXT_RE = re.compile(
    r'\b(?:safe_extract|safe_members|validate_archive|validate_member|is_safe_archive|commonpath|is_relative_to|resolve|normpath|abspath)\b'
    r'|\.{2}',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def strip_comments(line: str) -> str:
    return line.split('#', 1)[0]

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ''

def call_is_tar_open(call, tar_modules, tar_open_names):
    name = call_name(call.func)
    return name in tar_open_names or any(name == f"{module}.open" for module in tar_modules)

def call_is_zip_open(call, zip_modules, zip_ctor_names):
    name = call_name(call.func)
    return name in zip_ctor_names or any(name == f"{module}.ZipFile" for module in zip_modules)

def mark_archive_vars(node, archive_vars, archive_contexts, tar_modules, zip_modules, tar_open_names, zip_ctor_names):
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        kind = None
        if call_is_tar_open(node.value, tar_modules, tar_open_names):
            kind = 'tar'
        elif call_is_zip_open(node.value, zip_modules, zip_ctor_names):
            kind = 'zip'
        if kind:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    archive_vars[target.id] = kind
    if isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                continue
            if call_is_tar_open(item.context_expr, tar_modules, tar_open_names):
                archive_contexts.append((item.optional_vars.id, 'tar', node.lineno, getattr(node, 'end_lineno', node.lineno)))
            elif call_is_zip_open(item.context_expr, zip_modules, zip_ctor_names):
                archive_contexts.append((item.optional_vars.id, 'zip', node.lineno, getattr(node, 'end_lineno', node.lineno)))

def extraction_kind(call, archive_vars, archive_contexts, tar_modules, zip_modules, tar_open_names, zip_ctor_names, saw_archive_import):
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in {'extract', 'extractall'}:
        return None
    owner = func.value
    if isinstance(owner, ast.Name):
        for name, kind, start_line, end_line in reversed(archive_contexts):
            if name == owner.id and start_line <= call.lineno <= end_line:
                return kind
        if owner.id in archive_vars:
            return archive_vars[owner.id]
    if isinstance(owner, ast.Call):
        if call_is_tar_open(owner, tar_modules, tar_open_names):
            return 'tar'
        if call_is_zip_open(owner, zip_modules, zip_ctor_names):
            return 'zip'
    if func.attr == 'extractall':
        return 'unknown' if saw_archive_import else None
    return None

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def constant_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def is_safe_tar_filter(node):
    literal = constant_string(node)
    if literal == 'data':
        return True
    name = call_name(node)
    return name in {'data_filter', 'tarfile.data_filter'}

def has_safe_archive_context(kind, call, lines):
    method = call.func.attr if isinstance(call.func, ast.Attribute) else ''
    if kind == 'tar' and method == 'extractall':
        filter_value = keyword_value(call, 'filter')
        if filter_value is not None and is_safe_tar_filter(filter_value):
            return True
    if method == 'extract' or keyword_value(call, 'members') is not None:
        context = '\n'.join(strip_comments(line) for line in lines[max(0, call.lineno - 16):call.lineno])
        if SAFE_CONTEXT_RE.search(context):
            return True
    return False

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    tar_modules = {'tarfile'}
    zip_modules = {'zipfile'}
    tar_open_names = set()
    zip_ctor_names = {'ZipFile'}
    saw_archive_import = False
    archive_vars = {}
    archive_contexts = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == 'tarfile':
                    tar_modules.add(alias.asname or alias.name)
                    saw_archive_import = True
                elif alias.name == 'zipfile':
                    zip_modules.add(alias.asname or alias.name)
                    saw_archive_import = True
        elif isinstance(node, ast.ImportFrom):
            if node.module == 'tarfile':
                saw_archive_import = True
                for alias in node.names:
                    if alias.name == 'open':
                        tar_open_names.add(alias.asname or alias.name)
            elif node.module == 'zipfile':
                saw_archive_import = True
                for alias in node.names:
                    if alias.name == 'ZipFile':
                        zip_ctor_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        mark_archive_vars(node, archive_vars, archive_contexts, tar_modules, zip_modules, tar_open_names, zip_ctor_names)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not hasattr(node, 'lineno'):
            continue
        if has_ignore(lines, node.lineno):
            continue
        kind = extraction_kind(node, archive_vars, archive_contexts, tar_modules, zip_modules, tar_open_names, zip_ctor_names, saw_archive_import)
        if kind is None or has_safe_archive_context(kind, node, lines):
            continue
        try:
            rel = path.relative_to(BASE_DIR)
        except ValueError:
            rel = path.name
        issues.append((str(rel), node.lineno, source_line(lines, node.lineno)))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:25]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_open_redirect_checks() {
  print_subheader "Open redirect sinks"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable open redirect checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Unvalidated redirect from request data" "Validate redirect targets with an allow-list or same-origin check before redirecting"
        else
          print_finding "good" "No request-derived open redirect sinks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|GET|POST|query_params|cookies|url|full_path)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|cookies)\b',
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:url_has_allowed_host_and_scheme|is_safe_url|is_safe_redirect|validate_redirect|'
    r'validate_next|safe_redirect_target|safe_next_url|same_origin|allowed_redirect|'
    r'sanitize_redirect|url_for|reverse)\b'
    r'|\.netloc\b|\.scheme\b',
    re.IGNORECASE,
)
REDIRECT_SINKS = {
    'redirect',
    'flask.redirect',
    'django.shortcuts.redirect',
    'HttpResponseRedirect',
    'HttpResponsePermanentRedirect',
    'RedirectResponse',
    'starlette.responses.RedirectResponse',
    'fastapi.responses.RedirectResponse',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

class RedirectAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.issues = []

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def is_request_source(self, node):
        return bool(REQUEST_SOURCE_RE.search(self.segment(node)))

    def has_safe_expression(self, node):
        return bool(SAFE_VALIDATOR_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def tainted_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.tainted)

    def safe_validation_context(self, names, line_no):
        start = max(0, line_no - 10)
        context = '\n'.join(self.lines[start:line_no])
        if not SAFE_VALIDATOR_RE.search(context):
            return False
        if not names:
            return True
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def redirect_argument(self, node):
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg in {'url', 'location', 'redirect_to'}:
                return keyword.value
        return None

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            value = node.value
            if self.has_safe_expression(value):
                for name in names:
                    self.tainted.pop(name, None)
            elif self.is_request_source(value):
                for name in names:
                    self.tainted[name] = 'request'
            else:
                refs = self.tainted_names_in(value)
                if refs:
                    for name in names:
                        self.tainted[name] = refs[0]
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            if self.has_safe_expression(node.value):
                self.tainted.pop(node.target.id, None)
            elif self.is_request_source(node.value):
                self.tainted[node.target.id] = 'request'
            else:
                refs = self.tainted_names_in(node.value)
                if refs:
                    self.tainted[node.target.id] = refs[0]
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        if name in REDIRECT_SINKS or short_name in REDIRECT_SINKS:
            arg = self.redirect_argument(node)
            if arg is not None and not has_ignore(self.lines, node.lineno):
                direct = self.is_request_source(arg)
                refs = self.tainted_names_in(arg)
                if (direct or refs) and not self.has_safe_expression(arg) and not self.safe_validation_context(refs, node.lineno):
                    try:
                        rel = self.path.relative_to(BASE_DIR)
                    except ValueError:
                        rel = self.path.name
                    self.issues.append((str(rel), node.lineno, source_line(self.lines, node.lineno)))
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = RedirectAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_host_header_poisoning_checks() {
  print_subheader "Host header trusted for absolute URLs"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable host header poisoning checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request Host header used to build absolute URL" "Use a configured canonical base URL or validate the host against an allow-list before generating password reset, email, redirect, or callback links"
        else
          print_finding "good" "No Host-header-derived absolute URLs detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
URLISH_NAMES = {
    'url', 'uri', 'link', 'callback', 'redirect', 'next', 'return_to',
    'reset', 'confirm', 'verify', 'invite', 'activation', 'absolute',
}
HOST_SINKS = {
    'send_mail', 'django.core.mail.send_mail',
    'EmailMessage', 'django.core.mail.EmailMessage',
    'EmailMultiAlternatives', 'django.core.mail.EmailMultiAlternatives',
    'Message', 'flask_mail.Message',
    'render', 'django.shortcuts.render',
    'render_template', 'flask.render_template',
    'render_template_string', 'flask.render_template_string',
    'jsonify', 'flask.jsonify',
    'JsonResponse', 'django.http.JsonResponse',
    'Response', 'flask.Response',
    'redirect', 'flask.redirect',
    'HttpResponseRedirect', 'django.http.HttpResponseRedirect',
    'HttpResponsePermanentRedirect', 'django.http.HttpResponsePermanentRedirect',
    'RedirectResponse', 'starlette.responses.RedirectResponse',
}
SAFE_HOST_FUNCS = {
    'validate_host', 'validate_allowed_host', 'allowed_host', 'allowlisted_host',
    'trusted_host', 'is_allowed_host', 'is_trusted_host', 'get_canonical_host',
    'canonical_host', 'canonical_base_url', 'public_base_url', 'site_base_url',
    'absolute_url_from_settings', 'build_absolute_url_from_settings',
    'url_has_allowed_host_and_scheme',
}
SAFE_CONFIG_NAMES = {
    'SITE_URL', 'PUBLIC_BASE_URL', 'BASE_URL', 'CANONICAL_URL',
    'CANONICAL_BASE_URL', 'CANONICAL_HOST', 'SERVER_NAME',
    'settings.SITE_URL', 'settings.PUBLIC_BASE_URL', 'settings.BASE_URL',
    'settings.CANONICAL_URL', 'settings.CANONICAL_BASE_URL',
    'settings.CANONICAL_HOST', 'settings.SERVER_NAME',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return const_string(node.slice)

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def truthy_constant(node):
    return isinstance(node, ast.Constant) and bool(node.value) is True

def name_is_urlish(name):
    lowered = name.lower()
    return any(token in lowered for token in URLISH_NAMES)

class HostHeaderPoisoningAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.host_tainted = set()
        self.safe_values = set()
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_uses_safe_config(self, node):
        for child in ast.walk(node):
            name = call_name(child)
            if name in SAFE_CONFIG_NAMES:
                return True
            if isinstance(child, ast.Subscript):
                owner = call_name(child.value)
                key = subscript_key(child)
                if owner.endswith('.config') and key in SAFE_CONFIG_NAMES:
                    return True
                if owner in {'os.environ', 'environ'} and key in SAFE_CONFIG_NAMES:
                    return True
        return False

    def expr_is_safe(self, node):
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if self.expr_uses_safe_config(node):
            return True
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            if name in SAFE_HOST_FUNCS or short in SAFE_HOST_FUNCS:
                return True
            if short in {'urljoin', 'urlunsplit', 'urlunparse'} and self.expr_uses_safe_config(node):
                return True
        return False

    def expr_is_host_source(self, node):
        name = call_name(node)
        if isinstance(node, ast.Call) and rooted_at_request(node.func):
            short = name.rsplit('.', 1)[-1]
            return short in {'get_host', 'build_absolute_uri'}
        if isinstance(node, ast.Attribute) and rooted_at_request(node.value):
            return node.attr in {'host', 'host_url', 'url_root', 'base_url', 'url'}
        if isinstance(node, ast.Subscript):
            key = subscript_key(node)
            owner = call_name(node.value)
            if key and key.lower() in {'host', 'http_host', 'x-forwarded-host', 'x_host'}:
                return rooted_at_request(node.value) or owner.endswith('.headers') or owner.endswith('.META') or owner.endswith('.environ')
        return False

    def expr_contains_host_taint(self, node):
        if self.expr_is_safe(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.host_tainted
        if self.expr_is_host_source(node):
            return True
        return any(self.expr_contains_host_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value, line_no):
        is_safe = self.expr_is_safe(value)
        is_tainted = (not is_safe) and self.expr_contains_host_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
                self.host_tainted.discard(name)
            elif is_tainted:
                self.host_tainted.add(name)
                self.safe_values.discard(name)
                if name_is_urlish(name):
                    self.remember_issue(line_no)
            else:
                self.host_tainted.discard(name)
                self.safe_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.host_tainted)
        self.safe_values.clear()
        self.host_tainted.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.host_tainted = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value, node.lineno)
        self.generic_visit(node)

    def call_uses_implicit_host(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short == 'build_absolute_uri' and rooted_at_request(node.func):
            return True
        if short == 'url_for' and truthy_constant(keyword_value(node, '_external')):
            return not self.expr_uses_safe_config(node)
        return False

    def call_is_host_sensitive_sink(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        return name in HOST_SINKS or short in HOST_SINKS

    def visit_Call(self, node):
        if self.call_uses_implicit_host(node):
            self.remember_issue(node.lineno)
        elif self.call_is_host_sensitive_sink(node):
            values = list(node.args) + [keyword.value for keyword in node.keywords]
            if any(self.expr_contains_host_taint(value) for value in values):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = HostHeaderPoisoningAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_ssrf_checks() {
  print_subheader "SSRF-prone outbound HTTP targets"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable SSRF checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-derived URL reaches outbound HTTP client" "Validate outbound URLs with an allow-list and block private/link-local hosts before fetching"
        else
          print_finding "good" "No request-derived outbound HTTP targets detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|GET|POST|query_params|cookies|json|get_json|data|body|url|full_path)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|cookies|json|data|body)\b'
    r"|event\.get\(['\"]queryStringParameters['\"]\)"
    r"|event\[['\"](?:queryStringParameters|body)['\"]\]",
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:is_allowed_url|is_safe_url|is_trusted_url|validate_url|validate_outbound_url|'
    r'validate_fetch_url|safe_fetch_url|safe_outbound_url|allowlisted_url|allowed_url|'
    r'allowed_host|allowlisted_host|deny_private|reject_private|block_private|'
    r'is_private_address|is_public_host|same_origin)\b'
    r'|\.hostname\b|\.netloc\b|\.scheme\b|ipaddress\.',
    re.IGNORECASE,
)
HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
REQUEST_METHODS = {'request', 'stream'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

class SSRFAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.http_clients = set()
        self.modules = {
            'requests': {'requests'},
            'httpx': {'httpx'},
            'urllib_request': {'urllib.request'},
        }
        self.direct_http_calls = {}
        self.issues = []

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def is_request_source(self, node):
        return bool(REQUEST_SOURCE_RE.search(self.segment(node)))

    def has_safe_expression(self, node):
        return bool(SAFE_VALIDATOR_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def tainted_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.tainted)

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def safe_validation_context(self, names, line_no):
        if not names:
            return False
        start = max(0, line_no - 12)
        context = '\n'.join(self.lines[start:line_no])
        if not SAFE_VALIDATOR_RE.search(context):
            return False
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def remember_import(self, module, alias):
        if module == 'requests':
            self.modules['requests'].add(alias)
        elif module == 'httpx':
            self.modules['httpx'].add(alias)
        elif module == 'urllib.request':
            self.modules['urllib_request'].add(alias)

    def visit_Import(self, node):
        for alias in node.names:
            self.remember_import(alias.name, alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'requests', 'httpx'}:
                if alias.name in HTTP_METHODS:
                    self.direct_http_calls[local] = 0
                elif alias.name in REQUEST_METHODS:
                    self.direct_http_calls[local] = 1
                elif alias.name in {'Session', 'Client', 'AsyncClient'}:
                    self.direct_http_calls[local] = 'client_ctor'
            elif module == 'urllib.request' and alias.name in {'urlopen', 'Request'}:
                self.direct_http_calls[local] = 0
        self.generic_visit(node)

    def call_creates_http_client(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        if self.direct_http_calls.get(name) == 'client_ctor':
            return True
        for module in self.modules['requests']:
            if name == f'{module}.Session':
                return True
        for module in self.modules['httpx']:
            if name in {f'{module}.Client', f'{module}.AsyncClient'}:
                return True
        return 'aiohttp.ClientSession' in name or 'urllib3.PoolManager' in name

    def mark_assignment(self, target_names, value):
        if self.call_creates_http_client(value):
            self.http_clients.update(target_names)
            return
        if self.has_safe_expression(value):
            for name in target_names:
                self.tainted.pop(name, None)
            return
        if self.is_request_source(value):
            for name in target_names:
                self.tainted[name] = 'request'
            return
        refs = self.tainted_names_in(value)
        if refs:
            for name in target_names:
                self.tainted[name] = refs[0]

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def visit_With(self, node):
        self.mark_context_clients(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node):
        self.mark_context_clients(node)
        self.generic_visit(node)

    def mark_context_clients(self, node):
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name) and self.call_creates_http_client(item.context_expr):
                self.http_clients.add(item.optional_vars.id)

    def url_argument(self, node):
        name = call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        for keyword in node.keywords:
            if keyword.arg in {'url', 'href'}:
                return keyword.value

        if short_name in self.direct_http_calls:
            index = self.direct_http_calls[short_name]
            if isinstance(index, int) and len(node.args) > index:
                return node.args[index]

        for module in self.modules['requests'] | self.modules['httpx']:
            if short_name in HTTP_METHODS and name == f'{module}.{short_name}' and node.args:
                return node.args[0]
            if short_name in REQUEST_METHODS and name == f'{module}.{short_name}' and len(node.args) > 1:
                return node.args[1]

        for module in self.modules['urllib_request']:
            if name in {f'{module}.urlopen', f'{module}.Request'} and node.args:
                return node.args[0]

        if isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id in self.http_clients:
                if short_name in HTTP_METHODS and node.args:
                    return node.args[0]
                if short_name in REQUEST_METHODS and len(node.args) > 1:
                    return node.args[1]
            owner_text = self.segment(owner)
            if ('ClientSession(' in owner_text or 'Session(' in owner_text or 'PoolManager(' in owner_text):
                if short_name in HTTP_METHODS and node.args:
                    return node.args[0]
                if short_name in REQUEST_METHODS and len(node.args) > 1:
                    return node.args[1]
        return None

    def visit_Call(self, node):
        if has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        arg = self.url_argument(node)
        if arg is not None:
            direct = self.is_request_source(arg)
            refs = self.tainted_names_in(arg)
            if (direct or refs) and not self.has_safe_expression(arg) and not self.safe_validation_context(refs, node.lineno):
                try:
                    rel = self.path.relative_to(BASE_DIR)
                except ValueError:
                    rel = self.path.name
                self.issues.append((str(rel), node.lineno, source_line(self.lines, node.lineno)))
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SSRFAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_path_traversal_checks() {
  print_subheader "Request-derived filesystem paths"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable path traversal checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-derived path reaches file read/download/write sink" "Validate paths with safe_join, secure_filename, or a resolved-base containment check before opening, sending, or saving files"
        else
          print_finding "good" "No request-derived filesystem paths detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:args|values|form|headers|META|GET|POST|query_params|path_params|match_info|cookies|files|FILES)\b'
    r'|\b(?:self\.)?request\.(?:GET|POST|query_params|path_params|match_info|headers|META|FILES)\b',
    re.IGNORECASE,
)
UPLOAD_SOURCE_RE = re.compile(
    r'\b(?:flask\.)?request\.(?:files|FILES)\b'
    r'|\b(?:self\.)?request\.FILES\b',
    re.IGNORECASE,
)
SAFE_VALIDATOR_RE = re.compile(
    r'\b(?:safe_join|secure_filename|validate_path|validate_file|validate_filename|'
    r'safe_path|safe_filename|sanitize_path|sanitize_filename|allowed_path|allowed_file|'
    r'is_safe_path|is_safe_file|commonpath|relative_to|is_relative_to)\b',
    re.IGNORECASE,
)
PATH_METHODS = {'open', 'read_text', 'read_bytes', 'write_text', 'write_bytes'}
PATH_FUNCTION_SINKS = {
    'open',
    'io.open',
    'send_file',
    'flask.send_file',
    'FileResponse',
    'django.http.FileResponse',
    'starlette.responses.FileResponse',
    'fastapi.responses.FileResponse',
}
FILE_RESPONSE_SINKS = {'FileResponse', 'django.http.FileResponse', 'starlette.responses.FileResponse', 'fastapi.responses.FileResponse'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

class PathTraversalAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted = {}
        self.upload_file_vars = set()
        self.issues = []

    def segment(self, node):
        return ast.get_source_segment(self.text, node) or ''

    def is_request_source(self, node):
        return bool(REQUEST_SOURCE_RE.search(self.segment(node)))

    def is_upload_source(self, node):
        return bool(UPLOAD_SOURCE_RE.search(self.segment(node)))

    def has_safe_expression(self, node):
        return bool(SAFE_VALIDATOR_RE.search(self.segment(node)))

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def tainted_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.tainted)

    def upload_file_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.upload_file_vars)

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def safe_validation_context(self, names, line_no):
        if not names:
            return False
        start = max(0, line_no - 12)
        context = '\n'.join(self.lines[start:line_no])
        if not SAFE_VALIDATOR_RE.search(context):
            return False
        return any(re.search(rf'\b{re.escape(name)}\b', context) for name in names)

    def mark_assignment(self, names, value):
        if self.has_safe_expression(value):
            for name in names:
                self.tainted.pop(name, None)
                self.upload_file_vars.discard(name)
            return
        if self.is_request_source(value):
            for name in names:
                self.tainted[name] = 'request'
                if self.is_upload_source(value):
                    self.upload_file_vars.add(name)
            return
        upload_refs = self.upload_file_names_in(value)
        if upload_refs:
            for name in names:
                self.tainted[name] = upload_refs[0]
                self.upload_file_vars.add(name)
            return
        refs = self.tainted_names_in(value)
        if refs:
            for name in names:
                self.tainted[name] = refs[0]
            return
        for name in names:
            self.tainted.pop(name, None)
            self.upload_file_vars.discard(name)

    def visit_Assign(self, node):
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def sink_argument(self, node):
        name = call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        if name in PATH_FUNCTION_SINKS or short_name in PATH_FUNCTION_SINKS:
            for keyword in node.keywords:
                if keyword.arg in {'file', 'filename', 'path'}:
                    return keyword.value
            if node.args:
                if (name in FILE_RESPONSE_SINKS or short_name in FILE_RESPONSE_SINKS) and self.call_is_open(node.args[0]):
                    return None
                return node.args[0]
        if isinstance(node.func, ast.Attribute) and short_name in PATH_METHODS:
            return node.func.value
        if isinstance(node.func, ast.Attribute) and short_name == 'save' and node.args:
            owner = node.func.value
            if self.is_upload_source(owner) or self.upload_file_names_in(owner):
                return node.args[0]
        if isinstance(node.func, ast.Attribute) and short_name == 'save':
            owner = node.func.value
            if self.is_upload_source(owner) or self.upload_file_names_in(owner):
                for keyword in node.keywords:
                    if keyword.arg in {'dst', 'destination', 'file', 'filename', 'path'}:
                        return keyword.value
        return None

    def call_is_open(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        short_name = name.rsplit('.', 1)[-1]
        return name in {'open', 'io.open'} or short_name == 'open'

    def visit_Call(self, node):
        if has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        arg = self.sink_argument(node)
        if arg is not None:
            direct = self.is_request_source(arg)
            refs = self.tainted_names_in(arg)
            if (direct or refs) and not self.has_safe_expression(arg) and not self.safe_validation_context(refs, node.lineno):
                try:
                    rel = self.path.relative_to(BASE_DIR)
                except ValueError:
                    rel = self.path.name
                self.issues.append((str(rel), node.lineno, source_line(self.lines, node.lineno)))
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = PathTraversalAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_jwt_verification_checks() {
  print_subheader "JWT verification bypass"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable JWT verification checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "JWT decode disables signature or claim verification" "Require explicit algorithms and keep signature/expiration/audience/issuer verification enabled"
        else
          print_finding "good" "No JWT verification bypass patterns detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
VERIFY_OPTION_KEYS = {'verify_signature', 'verify_exp', 'verify_aud', 'verify_iss', 'verify_iat', 'verify_nbf'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def is_false(node):
    return const_value(node) is False

def contains_none_algorithm(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() == 'none'
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(contains_none_algorithm(elt) for elt in node.elts)
    return False

def disables_verify_option(node):
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values):
        name = key_name(key)
        if name in VERIFY_OPTION_KEYS and is_false(value):
            return True
    return False

class JWTAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.jwt_modules = {'jwt'}
        self.decode_names = set()
        self.issues = []

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name in {'jwt', 'jose.jwt'}:
                self.jwt_modules.add(local)
                self.jwt_modules.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'jwt', 'jose.jwt'} and alias.name == 'decode':
                self.decode_names.add(local)
            elif module == 'jose' and alias.name == 'jwt':
                self.jwt_modules.add(local)
        self.generic_visit(node)

    def is_jwt_decode(self, node):
        name = call_name(node.func)
        if isinstance(node.func, ast.Name):
            return node.func.id in self.decode_names
        return any(name == f'{module}.decode' for module in self.jwt_modules) or name in {'jwt.decode', 'jose.jwt.decode'}

    def call_is_unsafe(self, node):
        for keyword in node.keywords:
            if keyword.arg == 'verify' and is_false(keyword.value):
                return True
            if keyword.arg == 'options' and disables_verify_option(keyword.value):
                return True
            if keyword.arg == 'algorithms' and contains_none_algorithm(keyword.value):
                return True
        if len(node.args) > 2 and contains_none_algorithm(node.args[2]):
            return True
        if len(node.args) > 3 and disables_verify_option(node.args[3]):
            return True
        return False

    def visit_Call(self, node):
        if not has_ignore(self.lines, node.lineno) and self.is_jwt_decode(node) and self.call_is_unsafe(node):
            try:
                rel = self.path.relative_to(BASE_DIR)
            except ValueError:
                rel = self.path.name
            self.issues.append((str(rel), node.lineno, source_line(self.lines, node.lineno)))
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = JWTAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_cors_misconfig_checks() {
  print_subheader "Credentialed wildcard CORS"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable CORS configuration checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "CORS allows credentials with wildcard origins" "Use an explicit origin allow-list whenever cookies or Authorization headers are allowed"
        else
          print_finding "good" "No wildcard credentialed CORS configurations detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
ORIGIN_KEYS = {'origins', 'allow_origins'}
CREDENTIAL_KEYS = {'supports_credentials', 'allow_credentials'}
DJANGO_WILDCARD_SETTINGS = {'CORS_ALLOW_ALL_ORIGINS', 'CORS_ORIGIN_ALLOW_ALL'}
DJANGO_ORIGIN_LIST_SETTINGS = {'CORS_ALLOWED_ORIGINS', 'CORS_ORIGIN_WHITELIST'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_true(node):
    return const_value(node) is True

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def contains_wildcard_origin(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip() == '*'
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(contains_wildcard_origin(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return any(contains_wildcard_origin(value) for value in node.values)
    return False

def dict_has_unsafe_cors_pair(node):
    if not isinstance(node, ast.Dict):
        return False
    saw_origin_key = False
    has_wildcard = False
    has_credentials = False
    for key, value in zip(node.keys, node.values):
        name = key_name(key)
        if name in ORIGIN_KEYS:
            saw_origin_key = True
            if contains_wildcard_origin(value):
                has_wildcard = True
        elif name in CREDENTIAL_KEYS and is_true(value):
            has_credentials = True
        elif dict_has_unsafe_cors_pair(value):
            return True
    return has_credentials and (has_wildcard or not saw_origin_key)

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def has_wildcard_origin_kw(call):
    return any(
        keyword_value(call, key) is not None and contains_wildcard_origin(keyword_value(call, key))
        for key in ORIGIN_KEYS
    )

def has_credentials_kw(call):
    return any(
        keyword_value(call, key) is not None and is_true(keyword_value(call, key))
        for key in CREDENTIAL_KEYS
    )

def has_send_wildcard_kw(call):
    value = keyword_value(call, 'send_wildcard')
    return value is not None and is_true(value)

def resources_are_unsafe(call):
    resources = keyword_value(call, 'resources')
    return resources is not None and dict_has_unsafe_cors_pair(resources)

def positional_resources(call):
    return call.args[1] if len(call.args) > 1 else None

def flask_cors_is_unsafe(call):
    if resources_are_unsafe(call):
        return True
    positional = positional_resources(call)
    if positional is not None and dict_has_unsafe_cors_pair(positional):
        return True
    if not has_credentials_kw(call):
        return False
    resources = keyword_value(call, 'resources')
    if resources is not None and contains_wildcard_origin(resources):
        return True
    if has_wildcard_origin_kw(call) or has_send_wildcard_kw(call):
        return True
    if positional is not None and contains_wildcard_origin(positional):
        return True
    return keyword_value(call, 'origins') is None and keyword_value(call, 'resources') is None and positional is None

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

class CORSAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.cors_calls = {'CORS', 'cross_origin', 'flask_cors.CORS', 'flask_cors.cross_origin'}
        self.middleware_calls = {'CORSMiddleware', 'starlette.middleware.cors.CORSMiddleware', 'fastapi.middleware.cors.CORSMiddleware'}
        self.django_wildcard_origin_lines = []
        self.django_credential_lines = []
        self.issues = []

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == 'flask_cors':
                self.cors_calls.add(f'{local}.CORS')
                self.cors_calls.add(f'{local}.cross_origin')
            elif alias.name in {'starlette.middleware.cors', 'fastapi.middleware.cors'}:
                self.middleware_calls.add(f'{local}.CORSMiddleware')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'flask_cors' and alias.name in {'CORS', 'cross_origin'}:
                self.cors_calls.add(local)
            elif module in {'starlette.middleware.cors', 'fastapi.middleware.cors'} and alias.name == 'CORSMiddleware':
                self.middleware_calls.add(local)
        self.generic_visit(node)

    def remember_django_setting(self, name, value, line_no):
        if name in DJANGO_WILDCARD_SETTINGS and is_true(value):
            self.django_wildcard_origin_lines.append(line_no)
        elif name in DJANGO_ORIGIN_LIST_SETTINGS and contains_wildcard_origin(value):
            self.django_wildcard_origin_lines.append(line_no)
        elif name == 'CORS_ALLOW_CREDENTIALS' and is_true(value):
            self.django_credential_lines.append(line_no)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in target_names(target):
                self.remember_django_setting(name, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        for name in target_names(node.target):
            if node.value is not None:
                self.remember_django_setting(name, node.value, node.lineno)
        self.generic_visit(node)

    def call_is_unsafe(self, node):
        name = call_name(node.func)
        if name in self.cors_calls or name.rsplit('.', 1)[-1] in {'CORS', 'cross_origin'}:
            return flask_cors_is_unsafe(node)
        if name in self.middleware_calls or name.rsplit('.', 1)[-1] == 'CORSMiddleware':
            return has_wildcard_origin_kw(node) and has_credentials_kw(node)
        if name.endswith('.add_middleware') and node.args:
            middleware_name = call_name(node.args[0])
            if middleware_name in self.middleware_calls or middleware_name.rsplit('.', 1)[-1] == 'CORSMiddleware':
                return has_wildcard_origin_kw(node) and has_credentials_kw(node)
        return False

    def visit_Call(self, node):
        if self.call_is_unsafe(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def finalize(self):
        if self.django_wildcard_origin_lines and self.django_credential_lines:
            self.remember_issue(self.django_credential_lines[0])

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = CORSAnalyzer(path, lines)
    analyzer.visit(tree)
    analyzer.finalize()
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_cookie_security_checks() {
  print_subheader "Cookie/session security flags"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable cookie/session checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Insecure web cookie/session configuration" "Set Secure and HttpOnly on session/CSRF cookies and avoid SameSite=None without Secure"
        else
          print_finding "good" "No insecure cookie/session flags detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
FALSE_IS_BAD = {'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'CSRF_COOKIE_HTTPONLY'}
SAMESITE_SETTINGS = {'SESSION_COOKIE_SAMESITE', 'CSRF_COOKIE_SAMESITE'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_false(node):
    return const_value(node) is False

def is_true(node):
    return const_value(node) is True

def is_samesite_none(node):
    value = const_value(node)
    if value is None or value is False:
        return True
    return isinstance(value, str) and value.lower() == 'none'

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return key_name(node.slice)

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

class CookieSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.secure_true_settings = set()
        self.samesite_candidates = []
        self.issues = []

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def check_setting_value(self, name, value, line_no):
        if name in FALSE_IS_BAD and is_false(value):
            self.remember_issue(line_no)
        elif name in {'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE'} and is_true(value):
            self.secure_true_settings.add(name)
        elif name in SAMESITE_SETTINGS and is_samesite_none(value):
            self.samesite_candidates.append((name, line_no))

    def visit_Assign(self, node):
        for target in node.targets:
            for name in target_names(target):
                self.check_setting_value(name, node.value, node.lineno)
            key = subscript_key(target)
            if key is not None:
                self.check_setting_value(key, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            for name in target_names(node.target):
                self.check_setting_value(name, node.value, node.lineno)
            key = subscript_key(node.target)
            if key is not None:
                self.check_setting_value(key, node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            secure_true = any(keyword.arg == 'SESSION_COOKIE_SECURE' and is_true(keyword.value) for keyword in node.keywords)
            for keyword in node.keywords:
                if keyword.arg is None:
                    continue
                if keyword.arg in FALSE_IS_BAD:
                    self.check_setting_value(keyword.arg, keyword.value, node.lineno)
                elif keyword.arg in SAMESITE_SETTINGS and is_samesite_none(keyword.value) and not secure_true:
                    self.remember_issue(node.lineno)

        short_name = name.rsplit('.', 1)[-1]
        if short_name in {'set_cookie', 'set_signed_cookie'}:
            secure = keyword_value(node, 'secure')
            httponly = keyword_value(node, 'httponly')
            samesite = keyword_value(node, 'samesite')
            if secure is not None and is_false(secure):
                self.remember_issue(node.lineno)
            if httponly is not None and is_false(httponly):
                self.remember_issue(node.lineno)
            if samesite is not None and is_samesite_none(samesite) and not (secure is not None and is_true(secure)):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def finalize(self):
        for name, line_no in self.samesite_candidates:
            secure_key = 'CSRF_COOKIE_SECURE' if name.startswith('CSRF_') else 'SESSION_COOKIE_SECURE'
            if secure_key not in self.secure_true_settings:
                self.remember_issue(line_no)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = CookieSecurityAnalyzer(path, lines)
    analyzer.visit(tree)
    analyzer.finalize()
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_csrf_disable_checks() {
  print_subheader "CSRF protection disabled"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable CSRF disable checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "CSRF protection explicitly disabled" "Remove CSRF exemptions or require request signatures / same-site tokens on state-changing routes"
        else
          print_finding "good" "No explicit CSRF disable patterns detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
FALSE_DISABLE_KEYS = {'WTF_CSRF_ENABLED', 'WTF_CSRF_CHECK_DEFAULT', 'CSRF_ENABLED', 'CSRF_CHECK_DEFAULT'}
TRUE_DISABLE_KEYS = {'CSRF_EXEMPT'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_false(node):
    value = const_value(node)
    return value is False or value == 0 or (isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'})

def is_true(node):
    value = const_value(node)
    return value is True or value == 1 or (isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'})

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return key_name(node.slice)

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def csrf_owner(name):
    return 'csrf' in name.lower() or 'xsrf' in name.lower()

def config_value_disables_csrf(name, value):
    if not name:
        return False
    key = name.upper()
    return (key in FALSE_DISABLE_KEYS and is_false(value)) or (key in TRUE_DISABLE_KEYS and is_true(value))

def dict_disables_csrf(node):
    if not isinstance(node, ast.Dict):
        return False
    return any(config_value_disables_csrf(key_name(key), value) for key, value in zip(node.keys, node.values))

class CSRFDisableAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.csrf_exempt_names = {'csrf_exempt'}
        self.csrf_objects = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'django.views.decorators.csrf' and alias.name == 'csrf_exempt':
                self.csrf_exempt_names.add(local)
        self.generic_visit(node)

    def check_config_value(self, name, value, line_no):
        if config_value_disables_csrf(name, value):
            self.remember_issue(line_no)

    def call_creates_csrf_object(self, node):
        if not isinstance(node, ast.Call):
            return False
        return call_name(node.func).rsplit('.', 1)[-1] in {'CSRFProtect', 'CsrfProtect', 'SeaSurf'}

    def decorator_disables_csrf(self, decorator):
        expr = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = call_name(expr)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        return (
            name in self.csrf_exempt_names
            or short == 'csrf_exempt'
            or (short == 'exempt' and (csrf_owner(owner) or owner in self.csrf_objects))
        )

    def call_disables_csrf(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        if name in self.csrf_exempt_names or short == 'csrf_exempt':
            return True
        if short == 'exempt' and (csrf_owner(owner) or owner in self.csrf_objects):
            return True
        enabled = keyword_value(node, 'enabled')
        if enabled is not None and is_false(enabled) and call_name(node.func).rsplit('.', 1)[-1] in {'CSRFProtect', 'CsrfProtect', 'SeaSurf'}:
            return True
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            return any(keyword.arg is not None and self.keyword_disables_csrf(keyword) for keyword in node.keywords) or any(dict_disables_csrf(arg) for arg in node.args)
        return False

    def keyword_disables_csrf(self, keyword):
        if keyword.arg is None:
            return False
        return config_value_disables_csrf(keyword.arg, keyword.value)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in target_names(target):
                if self.call_creates_csrf_object(node.value):
                    self.csrf_objects.add(name)
                self.check_config_value(name, node.value, node.lineno)
            key = subscript_key(target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(target, ast.Attribute):
                self.check_config_value(target.attr, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            for name in target_names(node.target):
                self.check_config_value(name, node.value, node.lineno)
            key = subscript_key(node.target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(node.target, ast.Attribute):
                self.check_config_value(node.target.attr, node.value, node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if self.decorator_disables_csrf(decorator):
                self.remember_issue(getattr(decorator, 'lineno', node.lineno))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        for decorator in node.decorator_list:
            if self.decorator_disables_csrf(decorator):
                self.remember_issue(getattr(decorator, 'lineno', node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_csrf(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = CSRFDisableAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_template_autoescape_checks() {
  print_subheader "Template autoescape disabled"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable template autoescape checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Template autoescape explicitly disabled" "Keep template autoescape enabled for HTML/XML templates; mark only audited trusted fragments safe"
        else
          print_finding "good" "No explicit template autoescape disables detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
ENV_FACTORY_NAMES = {'Environment', 'Template', 'SandboxedEnvironment'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_false(node):
    value = const_value(node)
    return value is False or value == 0 or (isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'})

def returns_false(node):
    if isinstance(node, ast.Lambda):
        return is_false(node.body)
    return False

def disables_autoescape_value(node):
    return is_false(node) or returns_false(node)

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def dict_has_autoescape_false(node):
    if not isinstance(node, ast.Dict):
        return False
    return any(key_name(key) == 'autoescape' and disables_autoescape_value(value) for key, value in zip(node.keys, node.values))

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [call_name(target)]
    return []

def subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return key_name(node.slice)

def has_jinja_context(name):
    lowered = name.lower()
    return 'jinja' in lowered or 'template' in lowered or lowered.endswith('autoescape')

class TemplateAutoescapeAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.jinja_modules = {'jinja2'}
        self.env_factories = set(ENV_FACTORY_NAMES)
        self.select_autoescape_names = {'select_autoescape'}
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'jinja2':
                self.jinja_modules.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module in {'jinja2', 'jinja2.environment', 'jinja2.sandbox'}:
                if alias.name in ENV_FACTORY_NAMES:
                    self.env_factories.add(local)
                elif alias.name == 'select_autoescape':
                    self.select_autoescape_names.add(local)
        self.generic_visit(node)

    def is_env_factory_call(self, name):
        short = name.rsplit('.', 1)[-1]
        if name in self.env_factories or short in self.env_factories:
            return True
        if '.' not in name:
            return False
        first = name.split('.', 1)[0]
        return first in self.jinja_modules and short in ENV_FACTORY_NAMES

    def is_select_autoescape_call(self, name):
        short = name.rsplit('.', 1)[-1]
        if name in self.select_autoescape_names or short in self.select_autoescape_names:
            return True
        if '.' not in name:
            return False
        first = name.split('.', 1)[0]
        return first in self.jinja_modules and short == 'select_autoescape'

    def call_disables_autoescape(self, node):
        name = call_name(node.func)
        autoescape = keyword_value(node, 'autoescape')
        if autoescape is not None and disables_autoescape_value(autoescape) and self.is_env_factory_call(name):
            return True
        if self.is_select_autoescape_call(name):
            default = keyword_value(node, 'default')
            default_for_string = keyword_value(node, 'default_for_string')
            if default is not None and is_false(default):
                return True
            if default_for_string is not None and is_false(default_for_string):
                return True
        if name.endswith('.jinja_options.update') or name.endswith('.jinja_env.options.update'):
            return any(keyword.arg == 'autoescape' and disables_autoescape_value(keyword.value) for keyword in node.keywords) or any(dict_has_autoescape_false(arg) for arg in node.args)
        return False

    def visit_Assign(self, node):
        for target in node.targets:
            key = subscript_key(target)
            target_name = call_name(target)
            if key == 'autoescape' and has_jinja_context(target_name) and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(target, ast.Attribute) and target.attr == 'autoescape' and has_jinja_context(call_name(target.value)) and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif any(has_jinja_context(name) for name in target_names(target)) and dict_has_autoescape_false(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(target, ast.Name) and target.id == 'autoescape' and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            key = subscript_key(node.target)
            target_name = call_name(node.target)
            if key == 'autoescape' and has_jinja_context(target_name) and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(node.target, ast.Attribute) and node.target.attr == 'autoescape' and has_jinja_context(call_name(node.target.value)) and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
            elif any(has_jinja_context(name) for name in target_names(node.target)) and dict_has_autoescape_false(node.value):
                self.remember_issue(node.lineno)
            elif isinstance(node.target, ast.Name) and node.target.id == 'autoescape' and disables_autoescape_value(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_autoescape(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = TemplateAutoescapeAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_safe_html_xss_checks() {
  print_subheader "Request-controlled values marked safe HTML"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable safe HTML XSS checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled value marked as safe HTML" "Escape with html.escape()/markupsafe.escape(), sanitize with bleach/nh3, or render as normal escaped template context instead of marking user input safe"
        else
          print_finding "good" "No request-controlled values marked safe HTML detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
REQUEST_NAMES = {'request'}
SAFE_HTML_SINKS = {
    'mark_safe', 'django.utils.safestring.mark_safe',
    'SafeString', 'django.utils.safestring.SafeString',
    'SafeText', 'django.utils.safestring.SafeText',
    'Markup', 'markupsafe.Markup', 'flask.Markup', 'jinja2.Markup',
}
HTML_SAFE_FUNCS = {
    'html.escape', 'markupsafe.escape', 'flask.escape',
    'django.utils.html.escape', 'conditional_escape', 'django.utils.html.conditional_escape',
    'bleach.clean', 'nh3.clean', 'sanitize_html', 'clean_html', 'sanitize_fragment',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def rooted_at_request(node):
    if isinstance(node, ast.Name):
        return node.id in REQUEST_NAMES or node.id.endswith('_request')
    if isinstance(node, ast.Attribute):
        return rooted_at_request(node.value)
    if isinstance(node, ast.Call):
        return rooted_at_request(node.func)
    if isinstance(node, ast.Subscript):
        return rooted_at_request(node.value)
    return False

def direct_untrusted_source(node):
    name = call_name(node)
    if rooted_at_request(node):
        return True
    if isinstance(node, ast.Call) and name in {'input', 'sys.stdin.read', 'sys.stdin.readline'}:
        return True
    if isinstance(node, ast.Subscript) and call_name(node.value) in {'sys.argv', 'os.environ'}:
        return True
    return False

class SafeHtmlXssAnalyzer(ast.NodeVisitor):
    def __init__(self, path, text, lines):
        self.path = path
        self.text = text
        self.lines = lines
        self.tainted_values = set()
        self.safe_values = set()
        self.safe_html_sinks = set(SAFE_HTML_SINKS)
        self.html_safe_funcs = set(HTML_SAFE_FUNCS)
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name in {'markupsafe', 'flask', 'jinja2', 'django.utils.safestring', 'django.utils.html'}:
                self.safe_html_sinks.add(f'{local}.Markup')
                self.safe_html_sinks.add(f'{local}.mark_safe')
                self.safe_html_sinks.add(f'{local}.SafeString')
                self.safe_html_sinks.add(f'{local}.SafeText')
                self.html_safe_funcs.add(f'{local}.escape')
                self.html_safe_funcs.add(f'{local}.conditional_escape')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            qualified = f'{module}.{alias.name}' if module else alias.name
            if qualified in SAFE_HTML_SINKS or alias.name in SAFE_HTML_SINKS:
                self.safe_html_sinks.add(local)
            if qualified in HTML_SAFE_FUNCS or alias.name in HTML_SAFE_FUNCS:
                self.html_safe_funcs.add(local)
        self.generic_visit(node)

    def call_is_html_safe_func(self, node):
        name = call_name(node)
        short = name.rsplit('.', 1)[-1]
        return name in self.html_safe_funcs or ('.' not in name and short in self.html_safe_funcs)

    def expr_is_html_safe(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, bool, type(None))):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.safe_values
        if isinstance(node, ast.Call):
            if self.call_is_html_safe_func(node.func):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return self.expr_is_html_safe(node.func.value) and all(
                    self.expr_is_html_safe(arg) for arg in node.args
                ) and all(self.expr_is_html_safe(keyword.value) for keyword in node.keywords)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.expr_is_html_safe(node.left) and self.expr_is_html_safe(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.Constant):
                    continue
                if isinstance(value, ast.FormattedValue) and self.expr_is_html_safe(value.value):
                    continue
                return False
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.expr_is_html_safe(elt) for elt in node.elts)
        return False

    def expr_contains_taint(self, node):
        if self.expr_is_html_safe(node):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_values
        if direct_untrusted_source(node):
            return True
        return any(self.expr_contains_taint(child) for child in ast.iter_child_nodes(node))

    def mark_assignment(self, names, value):
        is_safe = self.expr_is_html_safe(value)
        is_tainted = (not is_safe) and self.expr_contains_taint(value)
        for name in names:
            if is_safe:
                self.safe_values.add(name)
            else:
                self.safe_values.discard(name)
            if is_tainted:
                self.tainted_values.add(name)
            else:
                self.tainted_values.discard(name)

    def visit_FunctionDef(self, node):
        old_safe = set(self.safe_values)
        old_tainted = set(self.tainted_values)
        self.safe_values.clear()
        self.tainted_values.clear()
        for stmt in node.body:
            self.visit(stmt)
        self.safe_values = old_safe
        self.tainted_values = old_tainted

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if (name in self.safe_html_sinks or short in self.safe_html_sinks) and any(
            self.expr_contains_taint(arg) for arg in node.args
        ):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SafeHtmlXssAnalyzer(path, text, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_mass_assignment_checks() {
  print_subheader "Request-derived mass assignment"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable mass-assignment checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request data mass-assigned into model/object" "Map allowed fields explicitly before constructing or updating domain objects"
        else
          print_finding "good" "No request-derived mass assignment patterns detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
MODELISH_OWNER_RE = ('user', 'account', 'profile', 'model', 'object', 'obj', 'entity', 'record', 'instance', 'customer', 'member', 'admin', 'role', 'permission')

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

def is_request_attr_name(name):
    lowered = name.lower()
    return (
        lowered.startswith('request.')
        or '.request.' in lowered
        or lowered.startswith('flask.request.')
        or lowered.startswith('self.request.')
    ) and any(part in lowered for part in ('.json', '.form', '.values', '.args', '.data', '.post', '.get', '.files', '.body'))

def is_request_source_expr(node, tainted):
    if isinstance(node, ast.Name):
        return node.id in tainted
    name = call_name(node)
    if name and is_request_attr_name(name):
        return True
    if isinstance(node, ast.Call):
        func_name = call_name(node.func)
        if is_request_attr_name(func_name):
            return True
        if func_name.rsplit('.', 1)[-1] in {'dict', 'to_dict', 'copy'} and is_request_source_expr(node.func, tainted):
            return True
    if isinstance(node, ast.Subscript):
        return is_request_source_expr(node.value, tainted)
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node))

def looks_like_model_constructor(name):
    short = name.rsplit('.', 1)[-1]
    return bool(short) and short[0].isupper() and short not in {'dict', 'list', 'set', 'tuple', 'Response', 'JsonResponse'}

def looks_like_model_create(name):
    lowered = name.lower()
    short = name.rsplit('.', 1)[-1]
    return (
        short in {'create', 'update', 'bulk_create', 'bulk_update', 'from_dict', 'from_json'}
        or lowered.endswith('.objects.create')
        or lowered.endswith('.query.update')
        or lowered.endswith('.model_validate')
        or lowered.endswith('.parse_obj')
    )

def owner_looks_modelish(owner):
    lowered = owner.lower()
    return any(token in lowered for token in MODELISH_OWNER_RE)

class MassAssignmentAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.tainted = set()
        self.loop_tainted = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def expr_is_request_source(self, node):
        return is_request_source_expr(node, self.tainted | self.loop_tainted)

    def mark_targets_from_source(self, targets, value):
        if self.expr_is_request_source(value):
            for target in targets:
                self.tainted.update(target_names(target))

    def call_is_mass_assignment(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        owner = name.rsplit('.', 1)[0] if '.' in name else ''
        for keyword in node.keywords:
            if keyword.arg is None and self.expr_is_request_source(keyword.value):
                if looks_like_model_constructor(name) or looks_like_model_create(name):
                    return True
            elif keyword.arg in {'data', 'defaults', 'values'} and self.expr_is_request_source(keyword.value) and looks_like_model_create(name):
                return True
        if short in {'update', 'from_dict', 'from_json'} and node.args and self.expr_is_request_source(node.args[0]):
            return owner_looks_modelish(owner) or looks_like_model_create(name)
        if short in {'create', 'bulk_create', 'bulk_update'} and node.args and self.expr_is_request_source(node.args[0]):
            return True
        if short in {'model_validate', 'parse_obj'} and node.args and self.expr_is_request_source(node.args[0]):
            return True
        if name == 'setattr' and len(node.args) >= 3:
            return self.expr_is_request_source(node.args[1])
        if short == 'populate_obj' and node.args:
            return owner_looks_modelish(call_name(node.args[0]))
        return False

    def visit_Assign(self, node):
        self.mark_targets_from_source(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.mark_targets_from_source([node.target], node.value)
        self.generic_visit(node)

    def visit_For(self, node):
        old_loop = set(self.loop_tainted)
        if self.expr_is_request_source(node.iter):
            self.loop_tainted.update(target_names(node.target))
        self.generic_visit(node)
        self.loop_tainted = old_loop

    def visit_Call(self, node):
        if self.call_is_mass_assignment(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = MassAssignmentAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_debug_host_config_checks() {
  print_subheader "Debug mode and host allow-list"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable debug/host configuration checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Production debug mode or wildcard host allow-list" "Disable debug mode and replace wildcard ALLOWED_HOSTS with explicit production hostnames"
        else
          print_finding "good" "No production debug or wildcard host settings detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_enabled(node):
    value = const_value(node)
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 1:
        return True
    if isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'}:
        return True
    return False

def is_debug_name(name):
    return name in {'DEBUG', 'FLASK_DEBUG'} or name.endswith('_DEBUG')

def key_name(node):
    value = const_value(node)
    return value if isinstance(value, str) else None

def contains_wildcard_host(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        host = node.value.strip()
        return host in {'*', '*.*'} or host.startswith('*.') or (host.startswith('.') and len(host) > 1)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(contains_wildcard_host(elt) for elt in node.elts)
    return False

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None

def subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    return key_name(node.slice)

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

class DebugHostAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def check_config_value(self, name, value, line_no):
        if is_debug_name(name) and is_enabled(value):
            self.remember_issue(line_no)
        elif name == 'ALLOWED_HOSTS' and contains_wildcard_host(value):
            self.remember_issue(line_no)

    def visit_Assign(self, node):
        for target in node.targets:
            for name in target_names(target):
                self.check_config_value(name, node.value, node.lineno)
            key = subscript_key(target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(target, ast.Attribute):
                self.check_config_value(target.attr, node.value, node.lineno)
                if target.attr == 'debug' and is_enabled(node.value):
                    self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            for name in target_names(node.target):
                self.check_config_value(name, node.value, node.lineno)
            key = subscript_key(node.target)
            if key is not None:
                self.check_config_value(key, node.value, node.lineno)
            if isinstance(node.target, ast.Attribute):
                self.check_config_value(node.target.attr, node.value, node.lineno)
                if node.target.attr == 'debug' and is_enabled(node.value):
                    self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        if name.endswith('.config.update') or name.endswith('.config.from_mapping') or name in {'config.update', 'config.from_mapping'}:
            for keyword in node.keywords:
                if keyword.arg is not None:
                    self.check_config_value(keyword.arg, keyword.value, node.lineno)
        if name.endswith('.run') or name in {'run', 'uvicorn.run', 'hypercorn.run'}:
            debug = keyword_value(node, 'debug')
            if debug is not None and is_enabled(debug):
                self.remember_issue(node.lineno)
            use_debugger = keyword_value(node, 'use_debugger')
            if use_debugger is not None and is_enabled(use_debugger):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = DebugHostAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_xml_parser_security_checks() {
  print_subheader "Unsafe XML parser exposure"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable XML parser security checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Unsafe XML parser on untrusted input" "Use defusedxml or disable DTD/entity resolution before parsing request, upload, or stdin XML"
        else
          print_finding "good" "No unsafe XML parser exposure detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
UNSAFE_MODULES = {
    'xml.etree.ElementTree',
    'xml.dom.minidom',
    'xml.sax',
    'lxml.etree',
}
SAFE_MODULE_PREFIXES = ('defusedxml',)
PARSE_FUNCS = {'fromstring', 'XML', 'parseString', 'parse'}
STRING_PARSE_FUNCS = {'fromstring', 'XML', 'parseString'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_enabled(node):
    value = const_value(node)
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 1:
        return True
    if isinstance(value, str) and value.strip().lower() in {'1', 'true', 'yes', 'on'}:
        return True
    return False

def is_disabled(node):
    value = const_value(node)
    if value is False:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 0:
        return True
    if isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'}:
        return True
    return False

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return []

def expr_text(node):
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ''

class XmlSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.issues = []
        self.unsafe_aliases = set()
        self.safe_aliases = set()
        self.unsafe_functions = set()
        self.safe_functions = set()
        self.tainted = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name.startswith(SAFE_MODULE_PREFIXES):
                self.safe_aliases.add(local)
            elif alias.name in UNSAFE_MODULES or alias.name == 'lxml.etree':
                self.unsafe_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            full_name = f'{module}.{alias.name}' if module else alias.name
            if module.startswith(SAFE_MODULE_PREFIXES):
                self.safe_aliases.add(local)
                self.safe_functions.add(local)
            elif module == 'lxml' and alias.name == 'etree':
                self.unsafe_aliases.add(local)
            elif full_name in UNSAFE_MODULES or module in UNSAFE_MODULES:
                if alias.name in PARSE_FUNCS or alias.name == 'XMLParser':
                    self.unsafe_functions.add(local)
                else:
                    self.unsafe_aliases.add(local)
            elif module == 'xml.etree' and alias.name == 'ElementTree':
                self.unsafe_aliases.add(local)
        self.generic_visit(node)

    def is_untrusted_expr(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            name = call_name(node).lower()
            return (
                'request.' in name and name.rsplit('.', 1)[-1] in {'data', 'body', 'text', 'content', 'files', 'stream'}
            ) or name in {'sys.stdin', 'stdin'}
        if isinstance(node, ast.Subscript):
            name = call_name(node.value).lower()
            return 'request.files' in name or 'request.files' in expr_text(node) or self.is_untrusted_expr(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node.func).lower()
            text = expr_text(node)
            if name in {'input', 'raw_input', 'sys.stdin.read', 'stdin.read'}:
                return True
            if 'request.' in name and name.endswith(('.get_data', '.get_json', '.read')):
                return True
            if name.endswith('.read') and any(marker in text for marker in ('request', 'upload', 'file', 'stream', 'stdin')):
                return True
            return any(self.is_untrusted_expr(arg) for arg in node.args)
        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.Tuple, ast.List, ast.Set)):
            return any(self.is_untrusted_expr(child) for child in ast.iter_child_nodes(node))
        return False

    def is_safe_name(self, name):
        first = name.split('.', 1)[0]
        return first in self.safe_aliases or name in self.safe_functions or name.startswith('defusedxml.')

    def is_unsafe_parse_call(self, name):
        if not name or self.is_safe_name(name):
            return False
        if name in self.unsafe_functions:
            return True
        if '.' not in name:
            return False
        prefix, func = name.rsplit('.', 1)
        first = prefix.split('.', 1)[0]
        if func not in PARSE_FUNCS:
            return False
        if first in self.unsafe_aliases:
            return True
        return any(prefix.endswith(module) for module in UNSAFE_MODULES)

    def is_lxml_parser_call(self, name):
        if not name or self.is_safe_name(name):
            return False
        if name in self.unsafe_functions and name.endswith('XMLParser'):
            return True
        if not name.endswith('.XMLParser'):
            return False
        prefix = name.rsplit('.', 1)[0]
        first = prefix.split('.', 1)[0]
        return first in self.unsafe_aliases or prefix.endswith('lxml.etree')

    def parser_has_dangerous_flags(self, node):
        for keyword in node.keywords:
            if keyword.arg in {'resolve_entities', 'load_dtd', 'huge_tree'} and is_enabled(keyword.value):
                return True
            if keyword.arg == 'no_network' and is_disabled(keyword.value):
                return True
        return False

    def visit_Assign(self, node):
        if self.is_untrusted_expr(node.value):
            for target in node.targets:
                self.tainted.update(target_names(target))
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self.is_untrusted_expr(node.value):
            self.tainted.update(target_names(node.target))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = call_name(node.func)
        if self.is_lxml_parser_call(name) and self.parser_has_dangerous_flags(node):
            self.remember_issue(node.lineno)
        if self.is_unsafe_parse_call(name) and node.args:
            func = name.rsplit('.', 1)[-1]
            if func in STRING_PARSE_FUNCS and self.is_untrusted_expr(node.args[0]):
                self.remember_issue(node.lineno)
            elif func == 'parse' and self.is_untrusted_expr(node.args[0]):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = XmlSecurityAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_insecure_random_security_checks() {
  print_subheader "Security-sensitive random module usage"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable security randomness checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Security token generated with non-cryptographic random" "Use secrets.token_urlsafe/token_hex/randbelow or random.SystemRandom for tokens, sessions, OTPs, salts, and keys"
        else
          print_finding "good" "No security-sensitive random module usage detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
RANDOM_FUNCS = {'random', 'randint', 'randrange', 'choice', 'choices', 'sample', 'shuffle', 'getrandbits', 'randbytes', 'uniform'}
SECURITY_NAME_RE = re.compile(r'(token|secret|session|csrf|nonce|otp|password|passwd|api_?key|auth|salt|reset|invite|verification|cookie|credential|signing|hmac|jwt|key)', re.IGNORECASE)

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    return ''

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def expr_has_security_name(*parts):
    return any(SECURITY_NAME_RE.search(part or '') for part in parts)

class SecurityRandomAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.random_aliases = {'random'}
        self.random_functions = set()
        self.random_instances = set()
        self.safe_instances = set()
        self.function_stack = []
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no):
            return
        if line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'random':
                self.random_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'random' and alias.name in RANDOM_FUNCS:
                self.random_functions.add(local)
            elif module == 'random' and alias.name == 'Random':
                self.random_functions.add(local)
            elif module == 'random' and alias.name == 'SystemRandom':
                self.safe_instances.add(local)
        self.generic_visit(node)

    def is_random_constructor(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        if name in self.random_functions and name.endswith('Random') and name not in self.safe_instances:
            return True
        return any(name == f'{alias}.Random' for alias in self.random_aliases)

    def is_insecure_random_call(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short not in RANDOM_FUNCS:
            return False
        if name in self.random_functions:
            return True
        if '.' in name:
            prefix = name.rsplit('.', 1)[0]
            if 'SystemRandom' in prefix.split('.'):
                return False
            first = prefix.split('.', 1)[0]
            return first in self.random_aliases or first in self.random_instances
        return False

    def expr_uses_insecure_random(self, node):
        return any(isinstance(child, ast.Call) and self.is_insecure_random_call(child) for child in ast.walk(node))

    def visit_FunctionDef(self, node):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Assign(self, node):
        names = []
        for target in node.targets:
            names.extend(target_names(target))
        if self.is_random_constructor(node.value):
            self.random_instances.update(names)
        elif names and expr_has_security_name(*names) and self.expr_uses_insecure_random(node.value):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        names = target_names(node.target)
        if node.value is not None:
            if self.is_random_constructor(node.value):
                self.random_instances.update(names)
            elif names and expr_has_security_name(*names) and self.expr_uses_insecure_random(node.value):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node):
        current = self.function_stack[-1] if self.function_stack else ''
        if node.value is not None and expr_has_security_name(current) and self.expr_uses_insecure_random(node.value):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.expr_uses_insecure_random(node):
            name = call_name(node.func)
            keyword_names = [keyword.arg or '' for keyword in node.keywords]
            line = source_line(self.lines, node.lineno)
            if expr_has_security_name(name, line, *keyword_names):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = SecurityRandomAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
}

run_tls_verification_checks() {
  print_subheader "Disabled TLS certificate verification"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable TLS verification checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "HTTP/TLS client disables certificate verification" "Keep certificate and hostname verification enabled; use explicit CA bundles for private trust roots"
        else
          print_finding "good" "No disabled TLS verification patterns detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import ast
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'stream'}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def const_value(node):
    return node.value if isinstance(node, ast.Constant) else None

def is_false(node):
    value = const_value(node)
    return value is False or value == 0 or (isinstance(value, str) and value.strip().lower() in {'0', 'false', 'no', 'off'})

def is_cert_none(node, cert_none_names, ssl_aliases):
    value = const_value(node)
    if isinstance(value, str) and value.strip().upper() in {'CERT_NONE', 'NONE'}:
        return True
    name = call_name(node)
    if name in cert_none_names:
        return True
    return any(name == f'{alias}.CERT_NONE' for alias in ssl_aliases)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

class TLSVerificationAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.ssl_aliases = {'ssl'}
        self.httpx_aliases = {'httpx'}
        self.requests_aliases = {'requests'}
        self.aiohttp_aliases = {'aiohttp'}
        self.urllib3_aliases = {'urllib3'}
        self.httpx_direct = set()
        self.requests_direct = set()
        self.aiohttp_connector_names = set()
        self.aiohttp_session_names = set()
        self.urllib3_pool_names = set()
        self.unverified_context_names = set()
        self.cert_none_names = set()
        self.client_vars = set()
        self.issues = []
        self.seen_lines = set()

    def remember_issue(self, line_no):
        if has_ignore(self.lines, line_no) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        try:
            rel = self.path.relative_to(BASE_DIR)
        except ValueError:
            rel = self.path.name
        self.issues.append((str(rel), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == 'ssl':
                self.ssl_aliases.add(local)
            elif alias.name == 'httpx':
                self.httpx_aliases.add(local)
            elif alias.name == 'requests':
                self.requests_aliases.add(local)
            elif alias.name == 'aiohttp':
                self.aiohttp_aliases.add(local)
            elif alias.name == 'urllib3':
                self.urllib3_aliases.add(local)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            local = alias.asname or alias.name
            if module == 'ssl':
                if alias.name == '_create_unverified_context':
                    self.unverified_context_names.add(local)
                elif alias.name == 'CERT_NONE':
                    self.cert_none_names.add(local)
            elif module == 'httpx' and alias.name in HTTP_METHODS | {'Client', 'AsyncClient'}:
                self.httpx_direct.add(local)
            elif module == 'requests' and alias.name in HTTP_METHODS | {'Session'}:
                self.requests_direct.add(local)
            elif module == 'aiohttp':
                if alias.name == 'TCPConnector':
                    self.aiohttp_connector_names.add(local)
                elif alias.name == 'ClientSession':
                    self.aiohttp_session_names.add(local)
            elif module == 'urllib3' and alias.name in {'PoolManager', 'ProxyManager'}:
                self.urllib3_pool_names.add(local)
        self.generic_visit(node)

    def keyword(self, call, key):
        for keyword in call.keywords:
            if keyword.arg == key:
                return keyword.value
        return None

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
        return names

    def is_ssl_unverified_context(self, node):
        name = call_name(node)
        return name in self.unverified_context_names or any(name == f'{alias}._create_unverified_context' for alias in self.ssl_aliases)

    def is_httpx_or_requests_call(self, name):
        if name in self.httpx_direct or name in self.requests_direct:
            return True
        if '.' not in name:
            return False
        prefix, short = name.rsplit('.', 1)
        first = prefix.split('.', 1)[0]
        return short in HTTP_METHODS | {'Client', 'AsyncClient', 'Session'} and (first in self.httpx_aliases or first in self.requests_aliases)

    def is_aiohttp_connector_call(self, name):
        if name in self.aiohttp_connector_names:
            return True
        return any(name == f'{alias}.TCPConnector' for alias in self.aiohttp_aliases)

    def is_aiohttp_session_call(self, name):
        if name in self.aiohttp_session_names:
            return True
        return any(name == f'{alias}.ClientSession' for alias in self.aiohttp_aliases)

    def is_urllib3_pool_call(self, name):
        if name in self.urllib3_pool_names:
            return True
        return any(name in {f'{alias}.PoolManager', f'{alias}.ProxyManager'} for alias in self.urllib3_aliases)

    def has_unsafe_connector(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self.is_aiohttp_connector_call(call_name(child.func)):
                ssl_value = self.keyword(child, 'ssl')
                if ssl_value is not None and is_false(ssl_value):
                    return True
        return False

    def call_disables_tls(self, node):
        name = call_name(node.func)
        if self.is_ssl_unverified_context(node.func):
            return True
        verify = self.keyword(node, 'verify')
        if verify is not None and is_false(verify) and self.is_httpx_or_requests_call(name):
            return True
        if self.is_aiohttp_connector_call(name):
            ssl_value = self.keyword(node, 'ssl')
            if ssl_value is not None and is_false(ssl_value):
                return True
        if self.is_aiohttp_session_call(name):
            connector = self.keyword(node, 'connector')
            if connector is not None and self.has_unsafe_connector(connector):
                return True
        if self.is_urllib3_pool_call(name):
            cert_reqs = self.keyword(node, 'cert_reqs')
            assert_hostname = self.keyword(node, 'assert_hostname')
            if cert_reqs is not None and is_cert_none(cert_reqs, self.cert_none_names, self.ssl_aliases):
                return True
            if assert_hostname is not None and is_false(assert_hostname):
                return True
        if '.' in name:
            prefix, short = name.rsplit('.', 1)
            first = prefix.split('.', 1)[0]
            ssl_value = self.keyword(node, 'ssl')
            if short in HTTP_METHODS and ssl_value is not None and is_false(ssl_value):
                return first in self.aiohttp_aliases or first in self.client_vars or 'aiohttp' in prefix
        return False

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            name = call_name(node.value.func)
            if self.is_httpx_or_requests_call(name) or self.is_aiohttp_session_call(name) or self.is_urllib3_pool_call(name):
                self.client_vars.update(self.target_names(node.targets))
            if self.call_disables_tls(node.value):
                self.remember_issue(node.lineno)
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                attr = target.attr
                target_owner = call_name(target.value)
                if attr == 'verify_mode' and is_cert_none(node.value, self.cert_none_names, self.ssl_aliases):
                    self.remember_issue(node.lineno)
                elif attr == 'check_hostname' and is_false(node.value):
                    self.remember_issue(node.lineno)
                elif attr == 'verify' and target_owner in self.client_vars and is_false(node.value):
                    self.remember_issue(node.lineno)
                elif attr == '_create_default_https_context' and target_owner in self.ssl_aliases and self.is_ssl_unverified_context(node.value):
                    self.remember_issue(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.call_disables_tls(node):
            self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = TLSVerificationAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)
print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
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
  if command -v sg       >/dev/null 2>&1; then
    # `sg` can be either ast-grep or util-linux; validate before accepting.
    if sg --version 2>&1 | grep -qi 'ast-grep'; then AST_GREP_CMD=(sg); HAS_AST_GREP=1; return 0; fi
  fi
  if command -v npx      >/dev/null 2>&1; then AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; return 0; fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be skipped.${RESET}"
  say "${DIM}Tip: npm i -g @ast-grep/cli  or  cargo install ast-grep${RESET}"
  HAS_AST_GREP=0; return 1
}

ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    # ast-grep 0.40+ requires the `run` subcommand (pattern search)
    ( set +o pipefail; "${AST_GREP_CMD[@]}" run -p "$pattern" -l python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
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
  ( set +o pipefail; "${AST_GREP_CMD[@]}" run -p '$A.$B.$C.$D' -l python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_attrs"
  # Capture the BODY of any if statement (less brittle)
  ( set +o pipefail; "${AST_GREP_CMD[@]}" run -p $'if $COND:\n  $BODY' -l python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_ifs"

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
    row = node.get('row')
    if row is None:
        row = node.get('line', 0)
    return (row, node.get('column', 0))

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
    if not file_path:
        continue
    # ast-grep versions vary in whether metaVariables are included in JSON output.
    # Prefer the BODY meta range when present; otherwise fall back to the whole match range.
    start = end = None
    body = guard.get('metaVariables', {}).get('single', {}).get('BODY')
    if body:
        rng = body.get('range') or {}
        start = rng.get('start'); end = rng.get('end')
    if not start or not end:
        rng = guard.get('range') or {}
        start = rng.get('start'); end = rng.get('end')
    if not start or not end:
        continue
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
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t py_ag_rules.XXXXXX)"
  AST_CONFIG_FILE="$(mktemp -t ubs-sgconfig.XXXXXX 2>/dev/null || mktemp -t ubs-sgconfig)"
  trap '[[ -n "${AST_RULE_DIR:-}" && "${AST_RULE_DIR:-}" != "/" && "${AST_RULE_DIR:-}" != "." ]] && rm -rf -- "$AST_RULE_DIR" || true; [[ -n "${AST_CONFIG_FILE:-}" ]] && rm -f "$AST_CONFIG_FILE" || true' EXIT
  # ast-grep 0.40+ scans a directory of rules via an sgconfig.yml (ruleDirs).
  printf 'ruleDirs:\n- %s\n' "$AST_RULE_DIR" >"$AST_CONFIG_FILE" 2>/dev/null || true
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
        def $NAME($A = [], $$$):
          $BODY
    - pattern: |
        def $NAME($A = {}, $$$):
          $BODY
    - pattern: |
        def $NAME($A = set(), $$$):
          $BODY
severity: error
message: "Mutable default argument; use default=None and set in body"
YAML

  cat >"$AST_RULE_DIR/eval-exec.yml" <<'YAML'
id: py.eval-exec
language: python
rule:
  any:
    - pattern: eval($$$)
    - pattern: exec($$$)
severity: error
message: "Avoid eval/exec; leads to code injection"
YAML

  cat >"$AST_RULE_DIR/pickle-load.yml" <<'YAML'
id: py.pickle-load
language: python
rule:
  any:
    - pattern: pickle.load($$$)
    - pattern: pickle.loads($$$)
severity: error
message: "Unpickling untrusted data is insecure; prefer safer formats"
YAML

  cat >"$AST_RULE_DIR/yaml-unsafe.yml" <<'YAML'
id: py.yaml-unsafe
language: python
rule:
  pattern: yaml.load($$$)
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
    - pattern: subprocess.run($$$, shell=True)
    - pattern: subprocess.call($$$, shell=True)
    - pattern: subprocess.check_output($$$, shell=True)
    - pattern: subprocess.check_call($$$, shell=True)
    - pattern: subprocess.Popen($$$, shell=True)
    - pattern: $FN($$$, shell=True)
severity: error
message: "shell=True is dangerous; prefer exec array with shell=False"
YAML

  cat >"$AST_RULE_DIR/os-system.yml" <<'YAML'
id: py.os-system
language: python
rule:
  pattern: os.system($$$)
severity: warning
message: "os.system is shell-invocation; prefer subprocess without shell"
YAML

  cat >"$AST_RULE_DIR/requests-verify.yml" <<'YAML'
id: py.requests-verify
language: python
rule:
  any:
    - pattern: requests.$M($URL, $$$, verify=False)
    - pattern: requests.$M($URL, verify=False, $$$)
    - pattern: requests.$M($URL, verify = False, $$$)
severity: warning
message: "requests with verify=False disables TLS verification"
YAML

  cat >"$AST_RULE_DIR/hashlib-weak.yml" <<'YAML'
id: py.hashlib-weak
language: python
rule:
  any:
    - pattern: hashlib.md5($$$)
    - pattern: hashlib.sha1($$$)
severity: warning
message: "Weak hash algorithm (md5/sha1); prefer sha256/sha512"
YAML

  cat >"$AST_RULE_DIR/random-secrets.yml" <<'YAML'
id: py.random-secrets
language: python
rule:
  any:
    - pattern: random.random($$$)
    - pattern: random.randint($$$)
    - pattern: random.randrange($$$)
    - pattern: random.choice($$$)
    - pattern: random.choices($$$)
severity: info
message: "random module is not cryptographically secure; use secrets module"
YAML

  cat >"$AST_RULE_DIR/open-no-with.yml" <<'YAML'
id: py.open-no-with
language: python
rule:
  pattern: open($$$)
  not:
    inside:
      pattern: |
        with open($$$) as $F:
          $BODY
severity: warning
message: "open() outside of a 'with' block; risk of leaking file handles"
YAML

  cat >"$AST_RULE_DIR/open-no-encoding.yml" <<'YAML'
id: py.open-no-encoding
language: python
rule:
  all:
    - any:
        - pattern: open($$$)
        - pattern: pathlib.Path($P).open($$$)
    - not:
        has:
          pattern: encoding=$ENC
    - not:
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
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $VAR = open($$$)
    - not:
        has:
          pattern: $VAR.close()
severity: warning
message: "open() assigned to a variable without close() in the same function."
YAML

  cat >"$AST_RULE_DIR/resource-popen-no-wait.yml" <<'YAML'
id: py.resource.Popen-no-wait
language: python
rule:
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $PROC = subprocess.Popen($$$)
    - not:
        any:
          - has: { pattern: $PROC.wait() }
          - has: { pattern: $PROC.communicate($$$) }
          - has: { pattern: $PROC.terminate() }
          - has: { pattern: $PROC.kill() }
severity: warning
message: "subprocess.Popen handle created without wait/communicate/terminate in the same function."
YAML

  cat >"$AST_RULE_DIR/resource-asyncio-task.yml" <<'YAML'
id: py.resource.asyncio-task-no-await
language: python
rule:
  all:
    - pattern: |
        def $FN($$$):
          $BODY
    - has:
        pattern: $TASK = asyncio.create_task($$$)
    - not:
        any:
          - has: { pattern: await $TASK }
          - has: { pattern: $TASK.cancel() }
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
    - pattern: datetime.datetime.utcnow($$$)
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
    async def $FN($$$):
      $STMTS
  has:
    any:
      - pattern: time.sleep($$$)
      - pattern: requests.$M($$$)
      - pattern: subprocess.run($$$)
      - pattern: open($$$)
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
  pattern: tempfile.mktemp($$$)
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
  pattern: subprocess.run($$$)
  not:
    any:
      - has:
          pattern: check=$C
      - regex: 'check\s*='
      - regex: 'shell\s*='
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
  pattern: requests.$M($URL, $$$)
  not:
    any:
      - has:
          pattern: timeout=$T
      - regex: 'timeout\s*='
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
  pattern: $S = aiohttp.ClientSession($$$)
  not:
    inside:
      any:
        - pattern: await $S.close()
        - pattern: async with aiohttp.ClientSession($$$) as $S:
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

  # ───── Session-mined bug patterns (cass flywheel) ──────────────────────────
  # Rules derived from bugs found via iterative deep-audit sessions
  # across mcp_agent_mail, misc_coding_agent_tips, and other Python codebases.

  cat >"$AST_RULE_DIR/json-load-no-try.yml" <<'YAML'
id: py.json-load-no-try
language: python
rule:
  pattern: json.load($F)
  not:
    inside:
      kind: try_statement
severity: warning
message: "json.load() without try/except crashes on malformed JSON or empty files"
YAML

  cat >"$AST_RULE_DIR/stub-function-pass.yml" <<'YAML'
id: py.stub-function-pass
language: python
rule:
  pattern: |
    def $NAME($$$):
        pass
severity: info
message: "Function body is just 'pass'; will silently do nothing at runtime"
YAML

  cat >"$AST_RULE_DIR/stub-function-ellipsis.yml" <<'YAML'
id: py.stub-function-ellipsis
language: python
rule:
  pattern: |
    def $NAME($$$):
        ...
severity: info
message: "Function body is just '...'; will silently do nothing at runtime"
YAML

  cat >"$AST_RULE_DIR/env-get-empty-truthy.yml" <<'YAML'
id: py.env-get-empty-string
language: python
rule:
  any:
    - pattern: os.environ.get($KEY)
    - pattern: os.getenv($KEY)
  inside:
    kind: if_statement
severity: info
message: "os.getenv returns '' for set-but-empty vars (falsy); verify empty-string handling is intentional"
YAML

  cat >"$AST_RULE_DIR/retry-missing-decorator.yml" <<'YAML'
id: py.sqlite-no-retry
language: python
rule:
  any:
    - pattern: cursor.execute($$$)
    - pattern: conn.execute($$$)
  not:
    inside:
      kind: try_statement
severity: info
message: "Database execute without exception handling; consider retry logic for OperationalError/SQLITE_BUSY"
YAML

  cat >"$AST_RULE_DIR/signal-handler-too-complex.yml" <<'YAML'
id: py.signal-handler-io
language: python
rule:
  pattern: signal.signal($SIG, $HANDLER)
severity: info
message: "Signal handlers should be minimal (set a flag); avoid I/O, locks, or complex logic inside them"
YAML

  # Done writing rules
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" && -n "${AST_CONFIG_FILE:-}" ]] || return 1
  if [[ "$FORMAT" == "sarif" ]]; then
    # Build SARIF by scanning each rule independently, then merging runs.
    # This avoids a single invalid rule file breaking the entire SARIF output.
    local sarif_tmp; sarif_tmp="$(mktemp -t ag_sarif_stream.XXXXXX 2>/dev/null || mktemp -t ag_sarif_stream)"
    : >"$sarif_tmp"
    local rule_file
    for rule_file in "$AST_RULE_DIR"/*.yml "$AST_RULE_DIR"/*.yaml; do
      [[ -f "$rule_file" ]] || continue
      ( set +o pipefail; "${AST_GREP_CMD[@]}" scan -r "$rule_file" "$PROJECT_DIR" --format sarif 2>/dev/null || true ) >>"$sarif_tmp"
      printf '\n__UBS_SARIF_SPLIT__\n' >>"$sarif_tmp"
    done
    python3 - "$sarif_tmp" <<'PY' >&"$MACHINE_FD" || { rm -f "$sarif_tmp"; return 1; }
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="replace")
parts = [p.strip() for p in text.split("__UBS_SARIF_SPLIT__") if p.strip()]

version = None
runs = []
for part in parts:
    try:
        obj = json.loads(part)
    except Exception:
        continue
    if version is None:
        v = obj.get("version")
        if isinstance(v, str) and v:
            version = v
    r = obj.get("runs")
    if isinstance(r, list):
        runs.extend(r)

out = {"runs": runs, "version": version or "0.0.0"}
sys.stdout.write(json.dumps(out))
sys.stdout.write("\n")
PY
    rm -f "$sarif_tmp"
    AST_PASSTHROUGH=1; return 0
  fi
  # text summary
  local tmp_stream; tmp_stream="$(mktemp -t ag_stream.XXXXXX 2>/dev/null || mktemp -t ag_stream)"
  : >"$tmp_stream"
  local rule_file
  for rule_file in "$AST_RULE_DIR"/*.yml "$AST_RULE_DIR"/*.yaml; do
    [[ -f "$rule_file" ]] || continue
    ( set +o pipefail; "${AST_GREP_CMD[@]}" scan -r "$rule_file" "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >>"$tmp_stream"
  done
  if [[ ! -s "$tmp_stream" ]]; then rm -f "$tmp_stream"; return 0; fi
  print_subheader "ast-grep rule-pack summary"
  while IFS=$'\t' read -r tag a b c d; do
    case "$tag" in
      __FINDING__) print_finding "$a" "$(num_clamp "$b")" "$c: $d" ;;
      __SAMPLE__)  print_code_sample "$a" "$b" "$c" ;;
    esac
  done < <(python3 - "$tmp_stream" "$DETAIL_LIMIT" <<'PY'
import json, sys, collections
path, limit = sys.argv[1], int(sys.argv[2])
buckets = collections.OrderedDict()
file_cache = {}

def check_suppression(fpath, line_no):
    if not fpath or line_no <= 0: return False
    if fpath not in file_cache:
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as src:
                file_cache[fpath] = src.readlines()
        except Exception:
            file_cache[fpath] = []
    
    lines = file_cache[fpath]
    idx = line_no - 1
    if 0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]: return True
    if 0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx-1]: return True
    return False

def add(obj):
    rid = obj.get('ruleId') or obj.get('rule_id') or obj.get('id') or 'unknown'
    sev_raw = (obj.get('severity') or '').lower().strip()
    if sev_raw in ('critical', 'error', 'fatal'):
        sev = 'critical'
    elif sev_raw in ('warning', 'warn'):
        sev = 'warning'
    else:
        sev = 'info'
    file = obj.get('file','?')
    # Suppress asserts in test files
    if rid == 'py.assert-used' and ('test' in file.lower() or 'conftest' in file.lower()):
        return
    rng  = obj.get('range') or {}
    start = (rng.get('start') or {})
    ln0 = start.get('row')
    if ln0 is None:
        ln0 = start.get('line', 0)
    ln = int(ln0) + 1

    if file != '?' and check_suppression(file, ln): return

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
  )
  rm -f "$tmp_stream"
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# uv integrations & timeout resolution
# ────────────────────────────────────────────────────────────────────────────
check_uv() {
  # uvx does NOT accept -q (quiet is a top-level `uv` flag), so keep uvx plain.
  if command -v uvx >/dev/null 2>&1; then UVX_CMD=(uvx); HAS_UV=1; return 0; fi
  if command -v uv  >/dev/null 2>&1; then UVX_CMD=(uv -q tool run); HAS_UV=1; return 0; fi
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
  if [[ -z "$SKIP_CATEGORIES" ]]; then CURRENT_CATEGORY="$cat"; return 0; fi
  IFS=',' read -r -a arr <<<"$SKIP_CATEGORIES"
  for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  CURRENT_CATEGORY="$cat"
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
say "${WHITE}Started:${RESET}  ${GRAY}$(safe_date)${RESET}"

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
    parsed_counts=$(python3 - "$deep_guard_json" <<'PY'
import json, sys
try:
    data = json.loads(sys.argv[1])
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
count=0
division_report=""
if [[ "$HAS_AST_GREP" -eq 1 ]] && command -v python3 >/dev/null 2>&1; then
  # SC2259 fix: write the Python script to a temp file so the pipe-to-
  # stdin path actually reaches sys.stdin. Previously `python3 - <<'PY'`
  # had the heredoc override the pipe, making sys.stdin empty and
  # silently returning count=0 for every run.
  _ubs_py_script=$(mktemp "${TMPDIR:-/tmp}/ubs-div-XXXXXX.py")
  cat >"$_ubs_py_script" <<'PY'
import json
import re
import sys

limit = int(sys.argv[1])
count = 0
samples: list[str] = []

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        continue

    singles = (obj.get("metaVariables") or {}).get("single") or {}
    denom = (singles.get("B") or {}).get("text") or ""
    if not re.match(r"^[A-Za-z_]", denom):
        continue

    count += 1
    if len(samples) >= limit:
        continue

    file = obj.get("file") or ""
    start_line = ((obj.get("range") or {}).get("start") or {}).get("line")
    line = (start_line + 1) if isinstance(start_line, int) else 0
    code = (obj.get("lines") or "").strip()
    if file and line and code:
        samples.append(f"{file}:{line}:{code}")

print(count)
for sample in samples:
    print(sample)
PY
  division_report=$(
    ( set +o pipefail; "${AST_GREP_CMD[@]}" run -p '$A / $B' -l python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) \
      | python3 "$_ubs_py_script" "$DETAIL_LIMIT"
  )
  rm -f "$_ubs_py_script"
  count=$(printf '%s\n' "$division_report" | head -n 1 | awk 'END{print $0+0}')
else
  count=$(
    ( "${GREP_RN[@]}" -e "[A-Za-z0-9_)\\]][[:space:]]*/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) \
      | (grep -Ev "//|/\*" || true) | count_lines
  )
fi
if [ "$count" -gt 25 ]; then
  print_finding "warning" "$count" "Division by variable - verify non-zero" "Guard before division"
  if [[ -n "$division_report" ]]; then
    printed=0
    while IFS= read -r rawline; do
      [[ -z "$rawline" ]] && continue
      parse_grep_line "$rawline" || continue
      print_code_sample "$PARSED_FILE" "$PARSED_LINE" "$PARSED_CODE"
      printed=$((printed+1))
      [[ $printed -ge 5 ]] && break
    done < <(printf '%s\n' "$division_report" | tail -n +2)
  else
    show_detailed_finding "[A-Za-z0-9_)\\]][[:space:]]*/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" 5
  fi
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
print_category "Detects: code injection, unsafe deserialization, weak crypto, TLS/CSRF/autoescape off" \
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
pickle_pattern="(^|[^A-Za-z0-9_])pickle\.(load|loads)\("
count=$("${GREP_RN[@]}" -e "$pickle_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Insecure pickle usage" "Avoid unpickling untrusted data"
  show_detailed_finding "$pickle_pattern" 3
fi

print_subheader "yaml.load without Loader"
count=$("${GREP_RN[@]}" -e "yaml\.load\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "Loader[[:space:]]*=" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "yaml.load without SafeLoader" "Use yaml.safe_load or specify Loader=SafeLoader"
  show_detailed_finding "yaml\.load\(" 3
fi

run_unsafe_deserialization_checks

print_subheader "subprocess shell=True / os.system"
shell_true_pattern="^[^#]*\b[A-Za-z_][A-Za-z0-9_\.]*\([^#]*shell\s*=\s*True"
count=$("${GREP_RN[@]}" -e "$shell_true_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "os\.system\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "critical" "$total" "Shell command injection risk" "Pass argv list with shell=False"
  show_detailed_finding "$shell_true_pattern|os\.system\(" 5
else
  print_finding "good" "No shell=True / os.system detected"
fi

run_command_injection_checks
run_subprocess_timeout_checks
run_sql_injection_checks
run_nosql_injection_checks
run_regex_dos_checks
run_template_injection_checks
run_header_injection_checks
run_email_header_injection_checks
run_ldap_injection_checks

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

run_password_hashing_checks
run_crypto_misuse_checks
run_constant_time_compare_checks
run_security_assert_checks
run_file_permission_checks

print_subheader "Hardcoded secrets"
if ! command -v python3 >/dev/null 2>&1; then
  print_finding "info" 0 "python3 not available" "Install python3 to enable hardcoded secret checks"
else
  hardcoded_secret_report=$(python3 - "$PROJECT_DIR" <<'PY' 2>/dev/null
import ast
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.cache', 'build', 'dist'}
EXTS = {'.py', '.pyi', '.pyx'}

SECRET_WORD_RE = re.compile(
    r'(?:'
    r'\bsecret\b|\bpassword\b|\bpasswd\b|\bpwd\b|\btoken\b|\bapi[_-]?key\b|'
    r'\bprivate[_-]?key\b|\bclient[_-]?secret\b|\bwebhook[_-]?secret\b|'
    r'\bjwt[_-]?secret\b|\baccess[_-]?token\b|\brefresh[_-]?token\b|'
    r'\bsession[_-]?secret\b|\bcookie[_-]?secret\b|\bsigning[_-]?secret\b|'
    r'\bencryption[_-]?key\b|\bsecret[_-]?key[_-]?base\b|\bcredential(?:s)?\b'
    r')'
)
SECRET_PHRASE_RE = re.compile(
    r'\b(?:'
    r'api\s+key|private\s+key|client\s+secret|webhook\s+secret|jwt\s+secret|'
    r'access\s+token|refresh\s+token|session\s+secret|cookie\s+secret|'
    r'signing\s+secret|encryption\s+key|secret\s+key\s+base'
    r')\b'
)
PLACEHOLDERS = {
    'example', 'sample', 'dummy', 'placeholder', 'changeme', 'change_me',
    'not_a_secret', 'your_secret_here', 'your-api-key', 'localhost',
    '127.0.0.1', 'http://localhost', 'https://localhost', 'https://example.com',
}

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def relpath(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def normalize_name(name: str) -> str:
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', str(name or ''))
    text = re.sub(r'[^A-Za-z0-9]+', '_', text)
    return text.lower().strip('_')

def is_sensitive_name(name: str) -> bool:
    normalized = normalize_name(name)
    spaced = normalized.replace('_', ' ')
    return bool(SECRET_WORD_RE.search(normalized) or SECRET_WORD_RE.search(spaced) or SECRET_PHRASE_RE.search(spaced))

def literal_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None

def looks_like_secret_literal(value: str) -> bool:
    compact = value.strip()
    lowered = compact.lower()
    if len(compact) < 8:
        return False
    if lowered in PLACEHOLDERS:
        return False
    if 'example.' in lowered or lowered.startswith(('example_', 'sample_', 'dummy_')):
        return False
    if not re.search(r'[A-Za-z0-9]', compact):
        return False
    return True

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''

def subscript_key_name(node):
    target = node.slice if isinstance(node, ast.Subscript) else None
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value
    if isinstance(target, ast.Index) and isinstance(target.value, ast.Constant) and isinstance(target.value.value, str):
        return target.value.value
    return ''

def target_names(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.Subscript):
        key = subscript_key_name(node)
        return [key] if key else []
    if isinstance(node, (ast.Tuple, ast.List)):
        names = []
        for elt in node.elts:
            names.extend(target_names(elt))
        return names
    return []

class HardcodedSecretAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path = path
        self.lines = lines
        self.os_aliases = {'os'}
        self.environ_aliases = {'environ'}
        self.getenv_aliases = set()
        self.issues = []
        self.issue_lines = set()

    def remember_issue(self, node):
        line_no = getattr(node, 'lineno', 0)
        if line_no <= 0 or line_no in self.issue_lines or has_ignore(self.lines, line_no):
            return
        self.issue_lines.add(line_no)
        self.issues.append((relpath(self.path), line_no, source_line(self.lines, line_no)))

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'os':
                self.os_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == 'os':
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == 'environ':
                    self.environ_aliases.add(local)
                elif alias.name == 'getenv':
                    self.getenv_aliases.add(local)
        self.generic_visit(node)

    def env_fallback(self, node):
        if not isinstance(node, ast.Call):
            return False
        name = call_name(node.func)
        is_getenv = name in self.getenv_aliases or any(name == f'{alias}.getenv' for alias in self.os_aliases)
        is_environ_get = any(name == f'{alias}.get' for alias in self.environ_aliases)
        is_os_environ_get = any(name == f'{alias}.environ.get' for alias in self.os_aliases)
        if not (is_getenv or is_environ_get or is_os_environ_get):
            return False
        if not node.args:
            return False
        env_name = literal_string(node.args[0]) or ''
        default_node = node.args[1] if len(node.args) > 1 else None
        for keyword in node.keywords:
            if keyword.arg == 'default':
                default_node = keyword.value
        default = literal_string(default_node) if default_node is not None else None
        return bool(is_sensitive_name(env_name) and default is not None and looks_like_secret_literal(default))

    def value_is_hardcoded_secret(self, node):
        literal = literal_string(node)
        if literal is not None:
            return looks_like_secret_literal(literal)
        return self.env_fallback(node)

    def check_argument_defaults(self, node):
        positional_args = list(getattr(node.args, 'posonlyargs', [])) + list(node.args.args)
        positional_defaults = list(node.args.defaults)
        if positional_defaults:
            for arg, default in zip(positional_args[-len(positional_defaults):], positional_defaults):
                if is_sensitive_name(arg.arg) and self.value_is_hardcoded_secret(default):
                    self.remember_issue(default)
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if default is not None and is_sensitive_name(arg.arg) and self.value_is_hardcoded_secret(default):
                self.remember_issue(default)

    def visit_Assign(self, node):
        sensitive_target = any(is_sensitive_name(name) for target in node.targets for name in target_names(target))
        if sensitive_target and self.value_is_hardcoded_secret(node.value):
            self.remember_issue(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        sensitive_target = any(is_sensitive_name(name) for name in target_names(node.target))
        if sensitive_target and node.value is not None and self.value_is_hardcoded_secret(node.value):
            self.remember_issue(node)
        self.generic_visit(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            key_name = literal_string(key) if key is not None else None
            if key_name and is_sensitive_name(key_name) and self.value_is_hardcoded_secret(value):
                self.remember_issue(value)
        self.generic_visit(node)

    def visit_Call(self, node):
        if self.env_fallback(node):
            self.remember_issue(node)
        for keyword in node.keywords:
            if keyword.arg and is_sensitive_name(keyword.arg) and self.value_is_hardcoded_secret(keyword.value):
                self.remember_issue(keyword.value)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'setdefault' and len(node.args) >= 2:
            key_name = literal_string(node.args[0]) or ''
            if is_sensitive_name(key_name) and self.value_is_hardcoded_secret(node.args[1]):
                self.remember_issue(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)

    def visit_Lambda(self, node):
        self.check_argument_defaults(node)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = HardcodedSecretAnalyzer(path, lines)
    analyzer.visit(tree)
    issues.extend(analyzer.issues)

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f'__COUNT__\t{len(issues)}')
for file_name, line_no, code in issues[:25]:
    print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
PY
)
  hardcoded_secret_count=0
  hardcoded_secret_samples=""
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__) hardcoded_secret_count=$((a + 0));;
      __SAMPLE__) hardcoded_secret_samples+="${a}"$'\t'"${b}"$'\t'"${c}"$'\n';;
    esac
  done <<<"$hardcoded_secret_report"
  if [ "$hardcoded_secret_count" -gt 0 ]; then
    print_finding "critical" "$hardcoded_secret_count" "Potential hardcoded secrets" "Use secret manager or required env vars; do not keep literal fallbacks for secret env vars"
    sample_limit=3
    while IFS=$'\t' read -r sample_path sample_line sample_text; do
      [ -z "$sample_path" ] && continue
      print_code_sample "$sample_path" "$sample_line" "$sample_text"
      sample_limit=$((sample_limit - 1))
      [ "$sample_limit" -le 0 ] && break
    done <<<"$hardcoded_secret_samples"
  fi
fi

print_subheader "tempfile.mktemp (insecure)"
count=$("${GREP_RN[@]}" -e "tempfile\.mktemp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "Insecure tempfile.mktemp usage" "Use NamedTemporaryFile/mkstemp"; fi

run_archive_extraction_checks
run_open_redirect_checks
run_host_header_poisoning_checks
run_ssrf_checks
run_http_timeout_checks
run_path_traversal_checks
run_jwt_verification_checks
run_cors_misconfig_checks
run_cookie_security_checks
run_csrf_disable_checks
run_template_autoescape_checks
run_safe_html_xss_checks
run_mass_assignment_checks
run_debug_host_config_checks
run_xml_parser_security_checks
run_insecure_random_security_checks
run_tls_verification_checks
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
count=$("${GREP_RN[@]}" -e "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^\)]*=[[:space:]]*(\[\]|\{\}|set\(\))[^\)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Mutable default arguments" "Use None + set default in body"
  show_detailed_finding "def[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\([^\)]*=[[:space:]]*(\[\]|\{\}|set\(\))[^\)]*\)" 5
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
  CURRENT_CATEGORY=0
  print_header "AST-GREP RULE PACK FINDINGS"
  if run_ast_rules; then
    if [[ "$AST_PASSTHROUGH" -eq 1 ]]; then
      say "${DIM}${INFO} Above JSON/SARIF lines are ast-grep matches (id, message, severity, file/pos).${RESET}"
      if [[ "$FORMAT" == "sarif" ]]; then
        say "${DIM}${INFO} Tip: ${BOLD}${AST_GREP_CMD[*]} scan -r <rule.yml> \"$PROJECT_DIR\" --format sarif > report.sarif${RESET}"
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
        ruff_stdout="$(mktemp -t ubs-ruff.XXXXXX 2>/dev/null || mktemp)"
        ruff_stderr="$(mktemp -t ubs-ruff.XXXXXX 2>/dev/null || mktemp)"
        run_uv_tool_text ruff check "$PROJECT_DIR" --output-format=json >"$ruff_stdout" 2>"$ruff_stderr" || true
        ruff_trimmed="$(tr -d '[:space:]' <"$ruff_stdout" 2>/dev/null || true)"
        if [[ "$ruff_trimmed" == "[]" ]]; then
          print_finding "good" "Ruff clean"
        else
          ruff_count=0
          if command -v python3 >/dev/null 2>&1; then
            ruff_count=$(python3 - "$ruff_stdout" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print(0)
    sys.exit(0)
print(len(data) if isinstance(data, list) else 0)
PY
            )
          fi
          cat "$ruff_stdout" 2>/dev/null || true
          if [[ -s "$ruff_stderr" ]]; then
            say "  ${DIM}ruff stderr:${RESET}"
            cat "$ruff_stderr" 2>/dev/null || true
          fi
          if [ "${ruff_count:-0}" -gt 0 ]; then
            print_finding "info" "$ruff_count" "Ruff emitted findings" "Review ruff output above"
          else
            print_finding "info" 1 "Ruff output needs review" "Non-empty output (or parse failure)"
          fi
        fi
        ;;
      bandit)
        print_subheader "bandit (security)"
        _EXC=""
        for d in "${EXCLUDE_DIRS[@]}"; do
          if [[ "$d" == /* ]]; then
            _EXC="${_EXC:+$_EXC,}$d"
          else
            _EXC="${_EXC:+$_EXC,}$PROJECT_DIR/$d"
          fi
        done
        # Expand .ubsignore glob patterns (e.g. **/test_*.py) into real
        # paths that Bandit's -x flag can understand.  Simple dir names
        # like "tests" are already handled above; here we only expand
        # entries that contain glob meta-characters.
        if [[ -n "$EXTRA_EXCLUDES" ]]; then
          IFS=',' read -r -a _ign_pats <<< "$EXTRA_EXCLUDES"
          for _pat in "${_ign_pats[@]}"; do
            # Skip patterns already covered as plain dir names above
            [[ "$_pat" != *'*'* && "$_pat" != *'?'* && "$_pat" != *'['* ]] && continue
            while IFS= read -r _match; do
              [[ -z "$_match" ]] && continue
              _EXC="${_EXC:+$_EXC,}$_match"
            done < <(find "$PROJECT_DIR" -path "$PROJECT_DIR/$_pat" 2>/dev/null || true)
          done
        fi
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
emit_summary_json() {
  printf '{'
  printf '"project":"%s",' "$(printf %s "$PROJECT_DIR" | sed 's/"/\\"/g')"
  printf '"files":%s,' "$TOTAL_FILES"
  printf '"critical":%s,' "$CRITICAL_COUNT"
  printf '"warning":%s,' "$WARNING_COUNT"
  printf '"info":%s,' "$INFO_COUNT"
  printf '"timestamp":"%s",' "$(safe_date)"
  printf '"format":"%s",' "$FORMAT"
  printf '"uv_tools":"%s",' "$(printf %s "$UV_TOOLS" | sed 's/"/\\"/g')"
  printf '"categories":{'
  printf '"1":%s,"2":%s,"3":%s,"4":%s,"5":%s,"6":%s,"7":%s,"8":%s,' \
    "$(num_clamp "${CAT_COUNTS[1]:-0}")" "$(num_clamp "${CAT_COUNTS[2]:-0}")" "$(num_clamp "${CAT_COUNTS[3]:-0}")" "$(num_clamp "${CAT_COUNTS[4]:-0}")" "$(num_clamp "${CAT_COUNTS[5]:-0}")" "$(num_clamp "${CAT_COUNTS[6]:-0}")" "$(num_clamp "${CAT_COUNTS[7]:-0}")" "$(num_clamp "${CAT_COUNTS[8]:-0}")"
  printf '"9":%s,"10":%s,"11":%s,"12":%s,"13":%s,"14":%s,"15":%s,"16":%s,' \
    "$(num_clamp "${CAT_COUNTS[9]:-0}")" "$(num_clamp "${CAT_COUNTS[10]:-0}")" "$(num_clamp "${CAT_COUNTS[11]:-0}")" "$(num_clamp "${CAT_COUNTS[12]:-0}")" "$(num_clamp "${CAT_COUNTS[13]:-0}")" "$(num_clamp "${CAT_COUNTS[14]:-0}")" "$(num_clamp "${CAT_COUNTS[15]:-0}")" "$(num_clamp "${CAT_COUNTS[16]:-0}")"
  printf '"17":%s,"18":%s,"19":%s,"20":%s,"21":%s,"22":%s,"23":%s},' \
    "$(num_clamp "${CAT_COUNTS[17]:-0}")" "$(num_clamp "${CAT_COUNTS[18]:-0}")" "$(num_clamp "${CAT_COUNTS[19]:-0}")" "$(num_clamp "${CAT_COUNTS[20]:-0}")" "$(num_clamp "${CAT_COUNTS[21]:-0}")" "$(num_clamp "${CAT_COUNTS[22]:-0}")" "$(num_clamp "${CAT_COUNTS[23]:-0}")"
  # ast-grep histogram if available
  if [[ -n "$AST_RULE_DIR" && -n "${AST_CONFIG_FILE:-}" && "$HAS_AST_GREP" -eq 1 ]]; then
    printf '"ast_grep_rules":['
    local tmp_hist; tmp_hist="$(mktemp -t ag_hist.XXXXXX 2>/dev/null || mktemp -t ag_hist)"
    : >"$tmp_hist"
    for _rf in "$AST_RULE_DIR"/*.yml "$AST_RULE_DIR"/*.yaml; do
      [[ -f "$_rf" ]] || continue
      ( set +o pipefail; "${AST_GREP_CMD[@]}" scan -r "$_rf" "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >>"$tmp_hist"
    done
    python3 - "$tmp_hist" <<'PY'
import json,sys,collections
path=sys.argv[1]
seen=collections.Counter()
with open(path,'r',encoding='utf-8',errors='replace') as fh:
  for line in fh:
    line=line.strip()
    if not line:
      continue
    try:
      obj=json.loads(line)
    except Exception:
      continue
    rid=(obj.get('ruleId') or obj.get('rule_id') or obj.get('ruleId') or 'unknown')
    seen[rid]+=1
print(",".join(json.dumps({"id":k,"count":v}) for k,v in seen.items()))
PY
    rm -f "$tmp_hist"
    printf ']'
  else
    printf '"ast_grep_rules":[]'
  fi
  printf '}\n'
}

if [[ -n "$SUMMARY_JSON" ]]; then
  emit_summary_json > "$SUMMARY_JSON" 2>/dev/null || true
  say "${DIM}Summary JSON written to: ${SUMMARY_JSON}${RESET}"
fi

# --format=json: emit machine-readable summary JSON to original stdout
if [[ "$FORMAT" == "json" ]]; then
  emit_summary_json >&"$MACHINE_FD"
fi

echo ""
say "${DIM}Scan completed at: $(safe_date)${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  if [[ "$FORMAT" == "text" ]]; then
    say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
  else
    say "${GREEN}${CHECK} Machine output saved to: ${CYAN}$OUTPUT_FILE${RESET}"
  fi
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
