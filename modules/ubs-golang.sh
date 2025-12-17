#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE GO BUG SCANNER v7.1 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Go (Go 1.23+) using ast-grep
# + smart ripgrep/grep heuristics and module/build hygiene checks.
#
# Design goals:
#   • Prefer false positives over false negatives for mechanically detectable bugs
#   • Leverage ast-grep for structural hazards that grep/linters often miss
#   • Be robust under set -Eeuo pipefail, in CI, and without optional deps
#   • Provide deterministic machine output for --format=json|sarif
#
# v7.1 highlights (vs v7.0):
#   • Fixed ast-grep detection: avoid util-linux `sg` false positives
#   • Reworked color init: --no-color and NO_COLOR fully honored
#   • Project indexing once: prevents set -u crashes and improves performance
#   • Robust ast-grep JSON counting via python (fallback-safe)
#   • Added --strict, --only-changed, --baseline, --no-banner, --allow-npx
#   • Expanded AST rulepack:
#       - defer-ordering nil panics (http.Do/os.Open/sql.Query)
#       - rows.Err() not checked after Next loops
#       - Tx begin without deferred rollback
#       - context.Background inside HTTP handlers
#       - http.Transport missing timeouts, CloseIdleConnections hygiene
#       - err shadowing, empty if err blocks, dropped err returns
#       - unbounded JSON decode from req.Body (MaxBytesReader heuristic)
#       - dynamic SQL string at Exec/Query sinks, strings.Fields in exec
#   • New categories 20–22 for crashers, DB robustness, and shutdown hygiene
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
shopt -s lastpipe
shopt -s extglob

# Pre-init colors as empty so ERR trap is safe before CLI parsing
RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; GRAY=""
BOLD=""; DIM=""; RESET=""

VERSION="7.1"

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
DISABLE_PIPEFAIL_DURING_SCAN=1
LIST_RULES=0
AST_JSON=""
AST_SARIF=""
AST_SCAN_OK=0
RUN_GO_TOOLS=0
GOTEST_PKGS="./..."
CATEGORY_WHITELIST=""
ONLY_CHANGED=0
STRICT_MODE=0
BASELINE_FILE=""
NO_BANNER=0
ALLOW_NPX=0

case "${UBS_CATEGORY_FILTER:-}" in
  resource-lifecycle)
    CATEGORY_WHITELIST="5,17"
    ;;
esac

# Async error coverage metadata
ASYNC_ERROR_RULE_IDS=(go.async.goroutine-err-no-check)
declare -A ASYNC_ERROR_SUMMARY=(
  [go.async.goroutine-err-no-check]='goroutine body ignores returned error'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [go.async.goroutine-err-no-check]='Handle errors inside goroutines or pass them to an error channel/errgroup'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [go.async.goroutine-err-no-check]='warning'
)

# Taint analysis metadata
TAINT_RULE_IDS=(go.taint.xss go.taint.sql go.taint.command)
declare -A TAINT_SUMMARY=(
  [go.taint.xss]='User input flows into fmt.Fprintf/template Execute/ResponseWriter.Write'
  [go.taint.sql]='User input concatenated into db.Exec/db.Query SQL strings'
  [go.taint.command]='User input reaches exec.Command/CommandContext'
)
declare -A TAINT_REMEDIATION=(
  [go.taint.xss]='Escape with html/template or html.EscapeString before writing to the response'
  [go.taint.sql]='Use parameterized queries or database/sql placeholders instead of string concat'
  [go.taint.command]='Validate/sanitize shell arguments (allowlists, filepath.Clean) or avoid shell invocation'
)
declare -A TAINT_SEVERITY=(
  [go.taint.xss]='critical'
  [go.taint.sql]='critical'
  [go.taint.command]='critical'
)

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(context_cancel ticker_stop timer_stop file_handle db_handle mutex_lock)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [context_cancel]="critical"
  [ticker_stop]="warning"
  [timer_stop]="warning"
  [file_handle]="warning"
  [db_handle]="warning"
  [mutex_lock]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [context_cancel]='context\.With(Cancel|Timeout|Deadline)\('
  [ticker_stop]='time\.NewTicker\('
  [timer_stop]='time\.NewTimer\('
  [file_handle]='os\.(Open|OpenFile)\('
  [db_handle]='sql\.Open(DB)?\('
  [mutex_lock]='\.Lock\('
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [context_cancel]='cancel\('
  [ticker_stop]='\.Stop\('
  [timer_stop]='\.Stop\('
  [file_handle]='\.Close\('
  [db_handle]='\.Close\('
  [mutex_lock]='\.Unlock\('
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [context_cancel]='context.With* without deferred cancel'
  [ticker_stop]='time.NewTicker not stopped'
  [timer_stop]='time.NewTimer not stopped'
  [file_handle]='os.Open/OpenFile without defer Close()'
  [db_handle]='sql.Open without DB.Close()'
  [mutex_lock]='Mutex Lock without Unlock()'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [context_cancel]='Store the cancel func and defer cancel() immediately after acquiring the context'
  [ticker_stop]='Keep the ticker handle and call Stop() when finished'
  [timer_stop]='Stop or drain timers to avoid leaks'
  [file_handle]='Call defer f.Close() immediately after Open to avoid FD leaks'
  [db_handle]='Close sql.DB handles when shutting down or prefer context-managed lifecycle'
  [mutex_lock]='Pair Lock() with defer Unlock() to avoid deadlocks when returning early'
)

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
  --go-tools               Also run gofmt -s -l, go vet, and govulncheck (if available)
  --test-pkgs=PKGS         Package pattern for tests/vet (default: ./...)
  --only-changed           Scan only files changed vs git merge-base (if in git repo)
  --strict                 Treat more findings as warnings/errors (aggressive)
  --baseline=FILE          Compare against a previous text report (heuristic deltas)
  --no-banner              Disable ASCII banner
  --allow-npx              Allow using npx @ast-grep/cli when ast-grep isn't installed
  -h, --help               Show help

Env:
  JOBS, NO_COLOR, CI, UBS_CATEGORY_FILTER
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
USAGE
}

# Parse CLI
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
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
    --go-tools)   RUN_GO_TOOLS=1; shift;;
    --test-pkgs=*) GOTEST_PKGS="${1#*=}"; shift;;
    --only-changed) ONLY_CHANGED=1; shift;;
    --strict)     STRICT_MODE=1; shift;;
    --baseline=*) BASELINE_FILE="${1#*=}"; shift;;
    --no-banner)  NO_BANNER=1; shift;;
    --allow-npx)  ALLOW_NPX=1; shift;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ "$PROJECT_DIR" == "." && ! "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" && ! "$1" =~ ^- ]]; then
        OUTPUT_FILE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      ;;
  esac
done

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi

USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; GRAY=""
  BOLD=""; DIM=""; RESET=""
fi

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; HAMMER="🔧"

DATE_FMT='%Y-%m-%d %H:%M:%S'
if [[ "$CI_MODE" -eq 1 ]]; then DATE_CMD="date -u '+%Y-%m-%dT%H:%M:%SZ'"; else DATE_CMD="date '+$DATE_FMT'"; fi

# Redirect output early to capture everything (text mode only; json/sarif should remain clean stdout)
if [[ -n "${OUTPUT_FILE}" && "$FORMAT" == "text" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

# ────────────────────────────────────────────────────────────────────────────
# Global Counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0

# ────────────────────────────────────────────────────────────────────────────
# Indexed project stats (avoid cross-category set -u hazards)
# ────────────────────────────────────────────────────────────────────────────
GO_FILES_COUNT=0
TEST_FILES_COUNT=0
MODS_COUNT=0
GO_SUM_COUNT=0
GO_WORK_COUNT=0
MOD_FILES=""
GO_SUM_FILES=""
GO_WORK_FILES=""

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
IFS=',' read -r -a _NAME_ARR <<<"$INCLUDE_NAMES"

# Build include patterns: exact names and extensions
INCLUDE_GLOBS_GREP=()
for n in "${_NAME_ARR[@]}"; do n="$(echo "$n" | xargs)"; [[ -n "$n" ]] && INCLUDE_GLOBS_GREP+=( "--include=$n" ); done
for e in "${_EXT_ARR[@]}";  do e="$(echo "$e" | xargs)"; [[ -n "$e" ]] && INCLUDE_GLOBS_GREP+=( "--include=*.$e" ); done

INCLUDE_GLOBS_RG=()
for n in "${_NAME_ARR[@]}"; do n="$(echo "$n" | xargs)"; [[ -n "$n" ]] && INCLUDE_GLOBS_RG+=( -g "$n" ); done
for e in "${_EXT_ARR[@]}";  do e="$(echo "$e" | xargs)"; [[ -n "$e" ]] && INCLUDE_GLOBS_RG+=( -g "*.$e" ); done

EXCLUDE_DIRS=(.git .svn .hg vendor third_party Godeps node_modules .cache build dist bin out tmp .idea .vscode .vs bazel-* _bazel go.work.d)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi

EXCLUDE_FLAGS_GREP=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS_GREP+=( "--exclude-dir=$d" ); done

HAS_RG=0
if command -v rg >/dev/null 2>&1; then
  HAS_RG=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  GREP_RN=(rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${INCLUDE_GLOBS_RG[@]}")
  GREP_RNI=(rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${INCLUDE_GLOBS_RG[@]}")
  GREP_RNW=(rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${INCLUDE_GLOBS_RG[@]}")
  RG_JOBS=()
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS_GREP[@]}" "${INCLUDE_GLOBS_GREP[@]}")
  GREP_RN=("grep" "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("grep" "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("grep" "${GREP_R_OPTS[@]}" -n -w -E)
fi

# Helper: robust numeric end-of-pipeline counter
count_lines() { awk 'END{print (NR+0)}'; }
wc_num(){ wc -l | awk '{print $1+0}'; }

now() { eval "$DATE_CMD"; }

# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────
maybe_clear() { if [[ -t 1 && "$CI_MODE" -eq 0 && "$QUIET" -eq 0 ]]; then clear || true; fi; }

say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

diag() {
  if [[ "$FORMAT" == "text" ]]; then
    say "$*"
  else
    echo -e "$*" 1>&2
  fi
}

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
      local count; count=$(printf '%s\n' "${raw_count:-0}" | awk 'END{print ($1+0)}')
      case $severity in
        critical|error)
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
  [[ -n "$code" ]] && say "${WHITE}      $code${RESET}" || true
}

# show_detailed_finding expects a regex pattern (grep/rg); AST samples have dedicated helper.
show_detailed_finding() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  local targets
  targets="$(rg_or_grep_targets)"
  if [[ -z "$targets" ]]; then
    return 0
  fi
  while IFS=: read -r file line code; do
    print_code_sample "$file" "$line" "$code"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done < <(
    ( set +o pipefail;
      printf '%s\n' "$targets" | while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        "${GREP_RN[@]}" -e "$pattern" "$t" 2>/dev/null || true
      done
    ) | head -n "$limit" || true
  ) || true
}

# Determine scan targets respecting --only-changed (git-aware)
rg_or_grep_targets() {
  if [[ "$ONLY_CHANGED" -ne 1 ]]; then
    echo "$PROJECT_DIR"
    return 0
  fi
  if ! command -v git >/dev/null 2>&1; then
    echo "$PROJECT_DIR"
    return 0
  fi
  local root
  root="$(git -C "$PROJECT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
  if [[ -z "$root" ]]; then
    echo "$PROJECT_DIR"
    return 0
  fi
  local base
  base="$(git -C "$root" merge-base HEAD origin/HEAD 2>/dev/null || git -C "$root" merge-base HEAD origin/main 2>/dev/null || git -C "$root" merge-base HEAD origin/master 2>/dev/null || true)"
  if [[ -z "$base" ]]; then
    base="$(git -C "$root" merge-base HEAD HEAD~1 2>/dev/null || true)"
  fi
  if [[ -z "$base" ]]; then
    echo "$PROJECT_DIR"
    return 0
  fi
  local files
  files="$(git -C "$root" diff --name-only "$base"...HEAD 2>/dev/null || true)"
  if [[ -z "$files" ]]; then
    echo "$PROJECT_DIR"
    return 0
  fi
  # Filter to included extensions/names and ensure paths exist under PROJECT_DIR
  local f
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # Exclude directories
    local skip=0
    local d
    for d in "${EXCLUDE_DIRS[@]}"; do
      [[ "$f" == "$d/"* ]] && skip=1
    done
    [[ $skip -eq 1 ]] && continue

    if [[ -f "$root/$f" ]]; then
      # Only include if it matches include names/exts
      local ok=0
      local n
      for n in "${_NAME_ARR[@]}"; do
        [[ "$f" == */"$n" || "$f" == "$n" ]] && ok=1
      done
      local e
      for e in "${_EXT_ARR[@]}"; do
        [[ "$f" == *".${e}" ]] && ok=1
      done
      [[ $ok -eq 1 ]] && echo "$root/$f"
    fi
  done <<<"$files"
}

# Resource lifecycle correlation helper (optional)
run_resource_lifecycle_checks() {
  local helper="$SCRIPT_DIR/helpers/resource_lifecycle_go.go"
  print_subheader "Resource lifecycle correlation"
  if [[ ! -f "$helper" ]]; then
    print_finding "info" 0 "Resource helper missing" "Expected $helper"
    return
  fi
  if ! command -v go >/dev/null 2>&1; then
    print_finding "info" 0 "Go toolchain unavailable" "Install Go to run the AST helper"
    return
  fi
  local output
  if ! output=$(go run "$helper" -- "$PROJECT_DIR" 2>/dev/null); then
    print_finding "info" 0 "AST helper failed" "See stderr for details"
    return
  fi
  if [[ -z "$output" ]]; then
    print_finding "good" "All tracked resource acquisitions have matching cleanups"
    return
  fi
  while IFS=$'\t' read -r location kind message; do
    [[ -z "$location" ]] && continue
    local summary="${RESOURCE_LIFECYCLE_SUMMARY[$kind]:-Resource imbalance}"
    local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$kind]:-Ensure matching cleanup call}"
    local severity="${RESOURCE_LIFECYCLE_SEVERITY[$kind]:-warning}"
    local desc="$remediation"
    [[ -n "$message" ]] && desc="$message"
    print_finding "$severity" 1 "$summary [$location]" "$desc"
  done <<<"$output"
}

run_async_error_checks() {
  print_subheader "Async error path coverage"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
    print_finding "info" 0 "ast-grep not available" "Install ast-grep to analyze goroutine error handling"
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to summarize ast-grep matches for async checks"
    return
  fi

  local rule_dir tmp_json
  rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t go_async_rules.XXXXXX)"
  if [[ ! -d "$rule_dir" ]]; then
    print_finding "info" 0 "temp dir creation failed" "Unable to stage ast-grep rules"
    return
  fi

  cat >"$rule_dir/go.async.goroutine-err-no-check.yml" <<'YAML'
id: go.async.goroutine-err-no-check
language: go
rule:
  all:
    - pattern: |
        go func($PARAMS) {
          $$$BODY
        }()
    - any:
        - has: { pattern: err := $CALL }
        - has: { pattern: $VAL, err := $CALL }
    - not:
        has:
          pattern: |
            if err != nil {
              $$$
            }
severity: warning
message: "goroutine body ignores returned error; handle it or propagate via channel/errgroup."
YAML

  tmp_json="$(mktemp -t go_async_matches.XXXXXX.json 2>/dev/null || mktemp -t go_async_matches.XXXXXX)"
  if ! "${AST_GREP_CMD[@]}" scan -r "$rule_dir" "$PROJECT_DIR" --json 2>/dev/null >"$tmp_json"; then
    rm -rf "$rule_dir"
    rm -f "$tmp_json"
    print_finding "info" 0 "ast-grep scan failed" "Unable to compute async error coverage"
    return
  fi
  rm -rf "$rule_dir"

  if ! [[ -s "$tmp_json" ]]; then
    rm -f "$tmp_json"
    print_finding "good" "All goroutines handle errors explicitly"
    return
  fi

  local printed=0
  while IFS=$'\t' read -r rid count samples; do
    [[ -z "$rid" ]] && continue
    printed=1
    local severity=${ASYNC_ERROR_SEVERITY[$rid]:-warning}
    local summary=${ASYNC_ERROR_SUMMARY[$rid]:-$rid}
    local desc=${ASYNC_ERROR_REMEDIATION[$rid]:-"Handle goroutine errors"}
    if [[ -n "$samples" ]]; then desc+=" (e.g., $samples)"; fi
    print_finding "$severity" "$count" "$summary" "$desc"
    [[ "$VERBOSE" -eq 1 && "$count" -gt 0 ]] && show_ast_samples "$rid" "$DETAIL_LIMIT" || true
  done < <(python3 - "$tmp_json" <<'PY'
import json, sys
from collections import OrderedDict

path = sys.argv[1]
stats = OrderedDict()

def iter_match_objs(blob):
    if isinstance(blob, list):
        for it in blob:
            yield from iter_match_objs(it)
    elif isinstance(blob, dict):
        # Most ast-grep match objects include rule id + file + range.
        if ("range" in blob and ("file" in blob or "path" in blob)
            and (blob.get("id") or blob.get("rule_id") or blob.get("ruleId"))):
            yield blob
        for v in blob.values():
            yield from iter_match_objs(v)

raw = open(path, "r", encoding="utf-8", errors="ignore").read().strip()
if not raw:
    sys.exit(0)

root = None
try:
    root = json.loads(raw)
except Exception:
    # Some versions can stream JSON objects; fall back line-by-line.
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for match in iter_match_objs(obj):
            rid = match.get("rule_id") or match.get("id") or match.get("ruleId")
            if not rid:
                continue
            rng = match.get("range") or {}
            start = rng.get("start") or {}
            line_no = int(start.get("row", 0)) + 1
            file_path = match.get("file") or match.get("path") or "?"
            entry = stats.setdefault(rid, {"count": 0, "samples": []})
            entry["count"] += 1
            if len(entry["samples"]) < 3:
                entry["samples"].append(f"{file_path}:{line_no}")
else:
    for match in iter_match_objs(root):
        rid = match.get("rule_id") or match.get("id") or match.get("ruleId")
        if not rid:
            continue
        rng = match.get("range") or {}
        start = rng.get("start") or {}
        line_no = int(start.get("row", 0)) + 1
        file_path = match.get("file") or match.get("path") or "?"
        entry = stats.setdefault(rid, {"count": 0, "samples": []})
        entry["count"] += 1
        if len(entry["samples"]) < 3:
            entry["samples"].append(f"{file_path}:{line_no}")

for rid, data in stats.items():
    print(f"{rid}\t{data['count']}\t{','.join(data['samples'])}")
PY
)
  rm -f "$tmp_json"
  if [[ $printed -eq 0 ]]; then print_finding "good" "All goroutines handle errors explicitly"; fi
}

# ────────────────────────────────────────────────────────────────────────────
# Lightweight taint analysis
# ────────────────────────────────────────────────────────────────────────────
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
import re, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', 'vendor', '.cache', 'bin', 'dist', '.idea'}
EXTS = {'.go'}
PATH_LIMIT = 6

SOURCE_PATTERNS = [
    re.compile(r"\.FormValue\(", re.IGNORECASE),
    re.compile(r"URL\.Query\(\)\.Get", re.IGNORECASE),
    re.compile(r"os\.Getenv", re.IGNORECASE),
    re.compile(r"bufio\.NewReader\(os\.Stdin\)", re.IGNORECASE),
    re.compile(r"io\.ReadAll\([^)]*req\.Body", re.IGNORECASE),
    re.compile(r"json\.NewDecoder\([^)]*req\.Body", re.IGNORECASE),
]

SANITIZER_REGEXES = [
    re.compile(r"html\.EscapeString"),
    re.compile(r"template\.HTMLEscapeString"),
    re.compile(r"url\.QueryEscape"),
    re.compile(r"path\.Clean"),
    re.compile(r"filepath\.Clean"),
]

SINKS = [
    (re.compile(r"fmt\.Fprint[fLn]?\s*\((.+)\)"), 'go.taint.xss', 'fmt.Fprintf'),
    (re.compile(r"[A-Za-z0-9_]+\.Write\s*\((.+)\)"), 'go.taint.xss', 'ResponseWriter.Write'),
    (re.compile(r"template\.(?:Must\()?[A-Za-z0-9_]+\.Execute\s*\((.+)\)"), 'go.taint.xss', 'template.Execute'),
    (re.compile(r"\bdb\.(?:Exec|Query|Raw|NamedQuery)\s*\((.+)\)"), 'go.taint.sql', 'db query'),
    (re.compile(r"exec\.Command(?:Context)?\s*\((.+)\)"), 'go.taint.command', 'exec.Command'),
]

ASSIGN_PATTERNS = [
    re.compile(r"^\s*(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*:=\s*(?P<expr>.+)"),
    re.compile(r"^\s*(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)\s*=\s*(?P<expr>.+)"),
    re.compile(r"^\s*var\s+(?P<targets>[A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)(?:\s+[A-Za-z0-9_\*\[\]]+)?\s*=\s*(?P<expr>.+)")
]

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
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

def parse_assignments(lines):
    assignments = []
    for idx, raw in enumerate(lines, start=1):
        line = strip_comments(raw)
        if not line or '=' not in line:
            continue
        for pattern in ASSIGN_PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            targets = match.group('targets')
            expr = match.group('expr')
            for target in [t.strip() for t in targets.split(',') if t.strip()]:
                assignments.append((idx, target, expr))
            break
    return assignments

def find_sources(expr: str):
    matches = []
    for regex in SOURCE_PATTERNS:
        for m in regex.finditer(expr):
            matches.append(m.group(0))
    return matches

def expr_has_sanitizer(expr: str, sink_rule=None) -> bool:
    for regex in SANITIZER_REGEXES:
        if regex.search(expr):
            return True
    if sink_rule == 'go.taint.sql':
        if re.search(r"\?", expr) and ',' in expr:
            return True
        if re.search(r",\s*(?:\(|args|params|values)\b", expr, re.IGNORECASE):
            return True
    return False

def expr_has_tainted(expr: str, tainted):
    for name, meta in tainted.items():
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
        if re.search(pattern, expr):
            return name, meta
    return None, None

def record_taint(assignments):
    tainted = {}
    for line_no, target, expr in assignments:
        if expr_has_sanitizer(expr, None):
            continue
        sources = find_sources(expr)
        if sources:
            tainted[target] = {'source': sources[0], 'line': line_no, 'path': [sources[0], target]}
    for _ in range(7):
        changed = False
        for line_no, target, expr in assignments:
            if target in tainted or expr_has_sanitizer(expr, None):
                continue
            ref, meta = expr_has_tainted(expr, tainted)
            if ref:
                seq = list(meta.get('path', [ref]))
                if len(seq) >= PATH_LIMIT:
                    seq = seq[-(PATH_LIMIT-1):]
                seq.append(target)
                tainted[target] = {'source': meta.get('source', ref), 'line': line_no, 'path': seq}
                changed = True
        if not changed:
            break
    return tainted

def analyze_file(path: Path, issues):
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
        for regex, rule, label in SINKS:
            match = regex.search(stripped)
            if not match:
                continue
            expr = match.group(1)
            raw_match = regex.search(raw)
            expr_raw = raw_match.group(1) if raw_match else expr
            if rule == 'go.taint.sql' and expr_raw and '?' in expr_raw and ',' in expr_raw:
                continue
            if not expr or expr_has_sanitizer(expr_raw or expr, rule):
                continue
            direct = find_sources(expr)
            if direct:
                path_desc = f"{direct[0]} -> {label}"
            else:
                ref, meta = expr_has_tainted(expr, tainted)
                if not ref:
                    continue
                seq = list(meta.get('path', [ref]))
                if len(seq) >= PATH_LIMIT:
                    seq = seq[-(PATH_LIMIT-1):]
                seq.append(label)
                path_desc = ' -> '.join(seq)
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

# Temporarily relax pipefail for grep-heavy scans
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
# Baseline capture (best-effort, text-only)
# ────────────────────────────────────────────────────────────────────────────
BASELINE_TMP=""
setup_baseline_capture() {
  [[ -n "$BASELINE_FILE" && "$FORMAT" == "text" ]] || return 0
  [[ -n "$OUTPUT_FILE" ]] || return 0
  BASELINE_TMP="$(mktemp -t ubs_baseline_new.XXXXXX 2>/dev/null || mktemp -t ubs_baseline_new.XXXXXX)"
  exec > >(tee "$OUTPUT_FILE" "$BASELINE_TMP") 2>&1
}

# ────────────────────────────────────────────────────────────────────────────
# Cleanup (temp dirs/files)
# ────────────────────────────────────────────────────────────────────────────
cleanup() {
  local ec=$?
  [[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" 2>/dev/null || true
  [[ -n "${AST_JSON:-}" ]] && rm -f "$AST_JSON" 2>/dev/null || true
  [[ -n "${BASELINE_TMP:-}" ]] && rm -f "$BASELINE_TMP" 2>/dev/null || true
  exit "$ec"
}
trap cleanup EXIT

setup_baseline_capture || true

# ────────────────────────────────────────────────────────────────────────────
# Find helpers (portable prune expression)
# ────────────────────────────────────────────────────────────────────────────
EX_PRUNE=()
build_find_prune_expr() {
  local d
  local parts=()
  for d in "${EXCLUDE_DIRS[@]}"; do parts+=( -name "$d" -o ); done
  EX_PRUNE=( \( -type d \( "${parts[@]}" -false \) -prune \) )
}

# Project indexing (counts and file lists used across categories)
index_project() {
  build_find_prune_expr

  local name_expr=( \( )
  local first=1
  local n e

  for n in "${_NAME_ARR[@]}"; do
    [[ -z "$n" ]] && continue
    if [[ $first -eq 1 ]]; then name_expr+=( -name "$n" ); first=0
    else name_expr+=( -o -name "$n" ); fi
  done
  for e in "${_EXT_ARR[@]}"; do
    [[ -z "$e" ]] && continue
    if [[ $first -eq 1 ]]; then name_expr+=( -name "*.${e}" ); first=0
    else name_expr+=( -o -name "*.${e}" ); fi
  done
  name_expr+=( \) )

  TOTAL_FILES=$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${name_expr[@]}" -print \) 2>/dev/null || true ) | wc_num
  )

  GO_FILES_COUNT=$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name '*.go' -print \) 2>/dev/null || true ) | wc_num
  )
  TEST_FILES_COUNT=$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name '*_test.go' -print \) 2>/dev/null || true ) | wc_num
  )

  MOD_FILES="$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name 'go.mod' -print \) 2>/dev/null || true )
  )"
  MODS_COUNT=$(printf "%s\n" "$MOD_FILES" | sed '/^$/d' | wc_num)

  GO_SUM_FILES="$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name 'go.sum' -print \) 2>/dev/null || true )
  )"
  GO_SUM_COUNT=$(printf "%s\n" "$GO_SUM_FILES" | sed '/^$/d' | wc_num)

  GO_WORK_FILES="$(
    ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name 'go.work' -print \) 2>/dev/null || true )
  )"
  GO_WORK_COUNT=$(printf "%s\n" "$GO_WORK_FILES" | sed '/^$/d' | wc_num)
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep JSON caching + robust counting
# ────────────────────────────────────────────────────────────────────────────
ensure_ast_scan_json(){
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  [[ -n "$AST_JSON" && -f "$AST_JSON" ]] && return 0
  AST_JSON="$(mktemp -t ag_json.XXXXXX.json 2>/dev/null || mktemp -t ag_json.XXXXXX)"
  if "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json 2>/dev/null >"$AST_JSON"; then
    AST_SCAN_OK=1
    return 0
  fi
  AST_SCAN_OK=0
  rm -f "$AST_JSON"
  AST_JSON=""
  return 1
}

ast_count(){
  local rid="$1"
  [[ -n "$rid" && -n "$AST_JSON" && -f "$AST_JSON" ]] || { echo 0; return 0; }
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$AST_JSON" "$rid" <<'PY'
import json, sys
path, rid = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path, "r", encoding="utf-8", errors="ignore"))
except Exception:
    print(0)
    sys.exit(0)

c = 0
def walk(o):
    global c
    if isinstance(o, dict):
        rr = o.get("id") or o.get("rule_id") or o.get("ruleId")
        # count only objects that look like matches (have file+range)
        if rr == rid and ("range" in o) and ("file" in o or "path" in o):
            c += 1
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for it in o:
            walk(it)

walk(data)
print(c)
PY
  else
    grep -o "\"id\"[[:space:]]*:[[:space:]]*\"${rid//\//\\/}\"" "$AST_JSON" 2>/dev/null | wc_num
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep: detection, rule packs, and wrappers (Go heavy)
# ────────────────────────────────────────────────────────────────────────────
check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then
    AST_GREP_CMD=(ast-grep)
    HAS_AST_GREP=1
    return 0
  fi

  # Beware: many Unix systems have a different `sg` command (setgid util).
  # Verify that `sg` is actually ast-grep's CLI before using it.
  if command -v sg >/dev/null 2>&1; then
    local out
    out="$(sg --help 2>&1 || true)"
    if printf '%s\n' "$out" | grep -qiE 'ast-grep|astgrep|ast grep'; then
      AST_GREP_CMD=(sg)
      HAS_AST_GREP=1
      return 0
    fi
    out="$(sg --version 2>&1 || true)"
    if printf '%s\n' "$out" | grep -qiE 'ast-grep|astgrep|ast grep'; then
      AST_GREP_CMD=(sg)
      HAS_AST_GREP=1
      return 0
    fi
  fi

  if [[ "$ALLOW_NPX" -eq 1 ]] && command -v npx >/dev/null 2>&1; then
    AST_GREP_CMD=(npx -y @ast-grep/cli)
    HAS_AST_GREP=1
    return 0
  fi

  HAS_AST_GREP=0
  return 1
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t go_ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # ───── Concurrency & Goroutines ───────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-defer-in-loop.yml" <<'YAML'
id: go.defer-in-loop
language: go
rule:
  pattern: defer $CALL
  inside:
    kind: for_statement
severity: warning
message: "defer inside loop may delay cleanup and grow stack; consider explicit close or scoped function."
YAML

  cat >"$AST_RULE_DIR/go-recover-not-in-defer.yml" <<'YAML'
id: go.recover-not-in-defer
language: go
rule:
  pattern: recover()
  not:
    inside:
      pattern: defer func($$) { $$ }
severity: warning
message: "recover() is only effective inside a deferred function."
YAML

  cat >"$AST_RULE_DIR/go-panic-call.yml" <<'YAML'
id: go.panic-call
language: go
rule:
  pattern: panic($$)
severity: warning
message: "panic used; prefer error returns in libraries and recover at process boundaries."
YAML

  cat >"$AST_RULE_DIR/go-go-in-loop.yml" <<'YAML'
id: go.goroutine-in-loop
language: go
rule:
  pattern: go $EXPR
  inside:
    kind: for_statement
severity: info
message: "goroutine launched inside loop; ensure captured values are correct and rate-limited."
YAML

  cat >"$AST_RULE_DIR/go.loop-var-capture.yml" <<'YAML'
id: go.loop-var-capture
language: go
rule:
  pattern: |
    for $I := range $$ {
      go func() { $$ $I $$ }()
    }
severity: warning
message: "Loop variable captured by goroutine closure; pass it as a parameter to avoid capture bugs."
YAML

  cat >"$AST_RULE_DIR/go.select-no-default.yml" <<'YAML'
id: go.select-no-default
language: go
rule:
  pattern: |
    select { $$ }
  not:
    has:
      pattern: default:
severity: info
message: "select without a default may block indefinitely; confirm this is intended or add a timeout/default."
YAML

  # ───── Contexts ───────────────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-context-without-cancel.yml" <<'YAML'
id: go.context-without-cancel
language: go
rule:
  all:
    - any:
        - pattern: $CTX, $CANCEL := context.WithCancel($PARENT)
        - pattern: $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
        - pattern: $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
        - pattern: $CTX, $CANCEL = context.WithCancel($PARENT)
        - pattern: $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
        - pattern: $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
    - not:
        inside:
          has:
            pattern: defer $CANCEL()
severity: warning
message: "context.With* assigns a cancel func but no defer cancel() is present in the containing scope (heuristic)."
YAML

  cat >"$AST_RULE_DIR/go-context-todo.yml" <<'YAML'
id: go.context-todo
language: go
rule:
  pattern: context.TODO()
severity: info
message: "context.TODO() present; replace with ctx or With* for production flows."
YAML

  cat >"$AST_RULE_DIR/go-resource-ticker.yml" <<'YAML'
id: go.resource.ticker-no-stop
language: go
rule:
  all:
    - any:
        - pattern: $TICKER := time.NewTicker($ARGS)
        - pattern: $TICKER = time.NewTicker($ARGS)
    - not:
        inside:
          has:
            any:
              - pattern: defer $TICKER.Stop()
              - pattern: $TICKER.Stop()
severity: warning
message: "time.NewTicker result not stopped in the containing scope."
YAML

  cat >"$AST_RULE_DIR/go-resource-timer.yml" <<'YAML'
id: go.resource.timer-no-stop
language: go
rule:
  all:
    - any:
        - pattern: $TIMER := time.NewTimer($ARGS)
        - pattern: $TIMER = time.NewTimer($ARGS)
    - not:
        inside:
          has:
            any:
              - pattern: defer $TIMER.Stop()
              - pattern: $TIMER.Stop()
              - pattern: <-$TIMER.C
severity: warning
message: "time.NewTimer result not stopped/drained in the containing scope."
YAML

  # ───── HTTP Client/Server ────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-http-default-client.yml" <<'YAML'
id: go.http-default-client
language: go
rule:
  any:
    - pattern: http.Get($$)
    - pattern: http.Post($$)
    - pattern: http.Head($$)
    - pattern: http.DefaultClient.Do($$)
severity: warning
message: "Default http.Client has no Timeout; prefer custom client with Timeout or context-aware requests."
YAML

  cat >"$AST_RULE_DIR/go.http-newrequest-without-context.yml" <<'YAML'
id: go.http-newrequest-without-context
language: go
rule:
  pattern: http.NewRequest($$, $$, $$)
severity: info
message: "Use http.NewRequestWithContext(ctx, ...) to propagate cancellation."
YAML

  cat >"$AST_RULE_DIR/go.exec-command-without-context.yml" <<'YAML'
id: go.exec-command-without-context
language: go
rule:
  pattern: exec.Command($$)
severity: info
message: "Prefer exec.CommandContext(ctx, ...) to enforce timeouts and cancellation."
YAML

  cat >"$AST_RULE_DIR/go-http-client-without-timeout.yml" <<'YAML'
id: go.http-client-without-timeout
language: go
rule:
  pattern: http.Client{$$}
  not:
    has:
      pattern: Timeout: $X
severity: warning
message: "http.Client without Timeout configured."
YAML

  cat >"$AST_RULE_DIR/go-http-server-no-timeouts.yml" <<'YAML'
id: go.http-server-no-timeouts
language: go
rule:
  pattern: http.Server{$$}
  not:
    any:
      - has: { pattern: ReadTimeout: $X }
      - has: { pattern: WriteTimeout: $X }
      - has: { pattern: IdleTimeout: $X }
      - has: { pattern: ReadHeaderTimeout: $X }
severity: info
message: "http.Server constructed without timeouts; vulnerable to slowloris and resource exhaustion."
YAML

  cat >"$AST_RULE_DIR/go.tls-minversion-missing.yml" <<'YAML'
id: go.tls-minversion-missing
language: go
rule:
  pattern: &cfg tls.Config{$$}
  not:
    any:
      - has: { pattern: MinVersion: tls.VersionTLS12 }
      - has: { pattern: MinVersion: tls.VersionTLS13 }
severity: info
message: "tls.Config without MinVersion; set to at least tls.VersionTLS12 (prefer TLS 1.3)."
YAML

  # ───── Time & tickers ────────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-time-tick.yml" <<'YAML'
id: go.time-tick
language: go
rule:
  pattern: time.Tick($$)
severity: warning
message: "time.Tick leaks; prefer time.NewTicker and Stop() it."
YAML

  cat >"$AST_RULE_DIR/go-time-after-in-loop.yml" <<'YAML'
id: go.time-after-in-loop
language: go
rule:
  pattern: time.After($$)
  inside:
    kind: for_statement
severity: info
message: "time.After in loop allocates per-iteration; prefer a reusable time.Timer."
YAML

  # ───── Encoding/JSON ─────────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-json-decode-without-disallow.yml" <<'YAML'
id: go.json-decode-without-disallow
language: go
rule:
  any:
    - pattern: json.NewDecoder($R).Decode($V)
    - pattern: |
        $DEC := json.NewDecoder($R)
        $DEC.Decode($V)
  not:
    has:
      pattern: DisallowUnknownFields()
severity: info
message: "json.Decoder used without DisallowUnknownFields; may hide input mistakes (heuristic)."
YAML

  # ───── Security & exec ───────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-exec-sh-c.yml" <<'YAML'
id: go.exec-sh-c
language: go
rule:
  any:
    - pattern: exec.Command("sh", "-c", $CMD)
    - pattern: exec.CommandContext($CTX, "sh", "-c", $CMD)
    - pattern: exec.Command("bash", "-c", $CMD)
    - pattern: exec.CommandContext($CTX, "bash", "-c", $CMD)
severity: error
message: "shell invocation via sh -c; sanitize inputs or avoid shell."
YAML

  cat >"$AST_RULE_DIR/go-tls-insecure-skip.yml" <<'YAML'
id: go.tls-insecure-skip
language: go
rule:
  pattern: &tls http.Transport{ $$ }
  has:
    pattern: InsecureSkipVerify: true
severity: warning
message: "TLS InsecureSkipVerify=true disables cert verification."
YAML

  # ───── Imports & modernization ───────────────────────────────────────────
  cat >"$AST_RULE_DIR/go-dot-import.yml" <<'YAML'
id: go.dot-import
language: go
rule:
  pattern: import . "$PKG"
severity: warning
message: "dot-import pollutes namespace; avoid except in tests/examples."
YAML

  cat >"$AST_RULE_DIR/go-blank-import.yml" <<'YAML'
id: go.blank-import
language: go
rule:
  pattern: import _ "$PKG"
severity: info
message: "blank import; ensure side-effect import is intentional."
YAML

  cat >"$AST_RULE_DIR/go-ioutil.yml" <<'YAML'
id: go.ioutil-deprecated
language: go
rule:
  pattern: ioutil.$FN($$)
severity: info
message: "ioutil package is deprecated; prefer io/os equivalents."
YAML

  cat >"$AST_RULE_DIR/go-interface-empty.yml" <<'YAML'
id: go.interface-empty
language: go
rule:
  pattern: interface{}
severity: info
message: "Prefer 'any' for empty interface in modern Go."
YAML

  # Strict mode severity bumps (best-effort)
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    sed -i.bak -E 's/^severity:[[:space:]]*info$/severity: warning/' "$AST_RULE_DIR"/*.yml 2>/dev/null || true
    rm -f "$AST_RULE_DIR"/*.bak 2>/dev/null || true
  fi
}

write_ast_rules_v7_extras() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  [[ -n "$AST_RULE_DIR" && -d "$AST_RULE_DIR" ]] || return 0

  # Defer ordering nil panics (real crashers)
  cat >"$AST_RULE_DIR/go.http.defer-body-before-err-check.yml" <<'YAML'
id: go.http.defer-body-before-err-check
language: go
rule:
  any:
    - pattern: |
        $RESP, $ERR := $CLIENT.Do($REQ)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = $CLIENT.Do($REQ)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := $CLIENT.Get($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = $CLIENT.Get($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Get($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = http.Get($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Head($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = http.Head($URL)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Post($$)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = http.Post($$)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.PostForm($URL, $DATA)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR = http.PostForm($URL, $DATA)
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := $CLIENT.Do($REQ)
        defer func() { _ = $RESP.Body.Close() }()
    - pattern: |
        $RESP, $ERR := http.Get($URL)
        defer func() { _ = $RESP.Body.Close() }()
    - pattern: |
        $RESP, $ERR := http.Post($$)
        defer func() { _ = $RESP.Body.Close() }()
severity: error
message: "defer resp.Body.Close() occurs before checking err; resp may be nil and will panic. Check err first, then defer Close()."
YAML

  cat >"$AST_RULE_DIR/go.defer-close-before-err-check.yml" <<'YAML'
id: go.defer-close-before-err-check
language: go
rule:
  any:
    - pattern: |
        $F, $ERR := os.Open($P)
        defer $F.Close()
    - pattern: |
        $F, $ERR := os.Create($P)
        defer $F.Close()
    - pattern: |
        $F, $ERR := os.OpenFile($P, $M, $PERM)
        defer $F.Close()
    - pattern: |
        $F, $ERR = os.Open($P)
        defer $F.Close()
    - pattern: |
        $F, $ERR = os.Create($P)
        defer $F.Close()
    - pattern: |
        $F, $ERR = os.OpenFile($P, $M, $PERM)
        defer $F.Close()
severity: error
message: "defer f.Close() occurs before checking err; f may be nil or stale and will panic/close the wrong handle. Check err first, then defer Close()."
YAML

  cat >"$AST_RULE_DIR/go.sql.defer-rows-close-before-err-check.yml" <<'YAML'
id: go.sql.defer-rows-close-before-err-check
language: go
rule:
  any:
    - pattern: |
        $ROWS, $ERR := $DB.Query($$)
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR := $DB.QueryContext($CTX, $$)
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR = $DB.Query($$)
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR = $DB.QueryContext($CTX, $$)
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR := $DB.Query($$)
        defer func() { _ = $ROWS.Close() }()
    - pattern: |
        $ROWS, $ERR := $DB.QueryContext($CTX, $$)
        defer func() { _ = $ROWS.Close() }()
severity: error
message: "defer rows.Close() occurs before checking err; rows may be nil and will panic. Check err first, then defer Close()."
YAML

  # rows.Next without rows.Err check
  cat >"$AST_RULE_DIR/go.sql.rows-err-not-checked.yml" <<'YAML'
id: go.sql.rows-err-not-checked
language: go
rule:
  all:
    - pattern: |
        for $ROWS.Next() {
          $$$
        }
    - not:
        has:
          pattern: |
            if err := $ROWS.Err(); err != nil {
              $$$
            }
severity: info
message: "rows.Next loop without rows.Err() check; errors may be missed after iteration."
YAML

  # Tx Begin without deferred rollback (heuristic)
  cat >"$AST_RULE_DIR/go.sql.begin-without-defer-rollback.yml" <<'YAML'
id: go.sql.begin-without-defer-rollback
language: go
rule:
  all:
    - any:
        - pattern: $TX, $ERR := $DB.Begin($$)
        - pattern: $TX, $ERR := $DB.BeginTx($$)
        - pattern: $TX, $ERR = $DB.Begin($$)
        - pattern: $TX, $ERR = $DB.BeginTx($$)
    - not:
        inside:
          has:
            any:
              - pattern: defer $TX.Rollback()
              - pattern: defer func() { _ = $TX.Rollback() }()
              - pattern: defer func() { $TX.Rollback() }()
severity: warning
message: "Transaction begun without a deferred tx.Rollback() in the containing scope."
YAML

  # HTTP handler using context.Background instead of r.Context
  cat >"$AST_RULE_DIR/go.http-handler-background.yml" <<'YAML'
id: go.http-handler-background
language: go
rule:
  all:
    - pattern: |
        func($W http.ResponseWriter, $R *http.Request) {
          $$$
        }
    - has:
        pattern: context.Background()
severity: warning
message: "HTTP handler uses context.Background(); prefer r.Context() for cancellation and deadlines."
YAML

  # http.Transport missing timeouts (connect/response/headers)
  cat >"$AST_RULE_DIR/go.http-transport-missing-timeouts.yml" <<'YAML'
id: go.http-transport-missing-timeouts
language: go
rule:
  pattern: http.Transport{$$}
  not:
    all:
      - has: { pattern: ResponseHeaderTimeout: $X }
      - has: { pattern: TLSHandshakeTimeout: $Y }
severity: info
message: "http.Transport missing ResponseHeaderTimeout/TLSHandshakeTimeout (heuristic)."
YAML

  # http.Client without explicit Transport (informational)
  cat >"$AST_RULE_DIR/go.http-client-without-transport.yml" <<'YAML'
id: go.http-client-without-transport
language: go
rule:
  pattern: http.Client{$$}
  not:
    has:
      pattern: Transport: $T
severity: info
message: "http.Client created without explicit Transport; defaults may be fine but review for timeouts/proxy settings."
YAML

  # HTTP response body not closed (very rough)
  cat >"$AST_RULE_DIR/go.http-response-body-not-closed.yml" <<'YAML'
id: go.http-response-body-not-closed
language: go
rule:
  all:
    - any:
        - pattern: $RESP, $ERR := $CLIENT.Do($REQ)
        - pattern: $RESP, $ERR = $CLIENT.Do($REQ)
        - pattern: $RESP, $ERR := http.Get($URL)
        - pattern: $RESP, $ERR = http.Get($URL)
        - pattern: $RESP, $ERR := http.Head($URL)
        - pattern: $RESP, $ERR = http.Head($URL)
        - pattern: $RESP, $ERR := http.Post($$)
        - pattern: $RESP, $ERR = http.Post($$)
        - pattern: $RESP, $ERR := http.PostForm($URL, $DATA)
        - pattern: $RESP, $ERR = http.PostForm($URL, $DATA)
        - pattern: $RESP, $ERR := $CLIENT.Get($URL)
        - pattern: $RESP, $ERR = $CLIENT.Get($URL)
    - not:
        inside:
          has:
            any:
              - pattern: defer $RESP.Body.Close()
              - pattern: defer func() { $RESP.Body.Close() }()
              - pattern: defer func() { _ = $RESP.Body.Close() }()
severity: warning
message: "HTTP response body not obviously closed; defer resp.Body.Close() on success to avoid leaking connections."
YAML

  # CloseIdleConnections during shutdown (informational)
  cat >"$AST_RULE_DIR/go.http-client-close-idle-missing.yml" <<'YAML'
id: go.http-client-close-idle-missing
language: go
rule:
  all:
    - pattern: $C := &http.Client{$$}
    - not:
        inside:
          has:
            pattern: $C.CloseIdleConnections()
severity: info
message: "http.Client created; consider CloseIdleConnections() during shutdown for long-running services."
YAML

  # Timer not drained after Stop (heuristic)
  cat >"$AST_RULE_DIR/go.resource.timer-not-drained.yml" <<'YAML'
id: go.resource.timer-not-drained
language: go
rule:
  all:
    - pattern: $T := time.NewTimer($$)
    - not:
        inside:
          has:
            pattern: <-$T.C
severity: info
message: "time.NewTimer created but channel never drained; if Stop() fails, timer may fire later (heuristic)."
YAML

  # WaitGroup Add without Done in same function (heuristic)
  cat >"$AST_RULE_DIR/go.waitgroup-add-no-done.yml" <<'YAML'
id: go.waitgroup-add-no-done
language: go
rule:
  all:
    - pattern: $WG.Add($N)
    - not:
        inside:
          has:
            pattern: $WG.Done()
severity: info
message: "WaitGroup.Add without Done in same function (heuristic)."
YAML

  # err shadowing: ':=' with err in multi-assign
  cat >"$AST_RULE_DIR/go.err-shadow.yml" <<'YAML'
id: go.err-shadow
language: go
rule:
  pattern: $X, err := $CALL
severity: info
message: "Potential err shadowing via ':='; ensure you check the correct err variable."
YAML

  # Empty if err != nil { } blocks
  cat >"$AST_RULE_DIR/go.iferr-empty.yml" <<'YAML'
id: go.iferr-empty
language: go
rule:
  pattern: |
    if err != nil {
    }
severity: warning
message: "Empty if err != nil block; likely unfinished or swallowed error."
YAML

  # Dropped error: if err != nil { return nil }
  cat >"$AST_RULE_DIR/go.iferr-return-nil.yml" <<'YAML'
id: go.iferr-return-nil
language: go
rule:
  pattern: |
    if err != nil {
      return nil
    }
severity: error
message: "Error checked but dropped (return nil). Likely should return err or wrap it."
YAML

  # exec.Command with strings.Fields (argument splitting hazard)
  cat >"$AST_RULE_DIR/go.exec-strings-fields.yml" <<'YAML'
id: go.exec-strings-fields
language: go
rule:
  any:
    - pattern: exec.Command($CMD, strings.Fields($ARGS)...)
    - pattern: exec.CommandContext($CTX, $CMD, strings.Fields($ARGS)...)
severity: warning
message: "exec.Command called with strings.Fields(...); verify argument safety and avoid shell-like parsing."
YAML

  # for-loop variable captured by goroutine closure (i := 0; ...; i++)
  cat >"$AST_RULE_DIR/go.loop-var-capture-for.yml" <<'YAML'
id: go.loop-var-capture-for
language: go
rule:
  pattern: |
    for $I := $INIT; $$$; $$$ {
      go func() { $$$ $I $$$ }()
    }
severity: warning
message: "For-loop variable captured by goroutine closure; pass it as a parameter to avoid capture bugs."
YAML

  # JSON decoder without io.LimitReader / http.MaxBytesReader (heuristic, handler-oriented)
  cat >"$AST_RULE_DIR/go.json.decoder-unbounded-body.yml" <<'YAML'
id: go.json.decoder-unbounded-body
language: go
rule:
  all:
    - pattern: json.NewDecoder($R.Body).Decode($V)
    - not:
        inside:
          has:
            pattern: http.MaxBytesReader($W, $R.Body, $N)
severity: info
message: "json.NewDecoder(r.Body) without http.MaxBytesReader; consider bounding request size."
YAML

  # Dynamic SQL string into Exec/Query (very heuristic)
  cat >"$AST_RULE_DIR/go.sql-dynamic-string.yml" <<'YAML'
id: go.sql-dynamic-string
language: go
rule:
  any:
    - pattern: $DB.Exec($Q + $X, $$)
    - pattern: $DB.Query($Q + $X, $$)
    - pattern: $DB.ExecContext($CTX, $Q + $X, $$)
    - pattern: $DB.QueryContext($CTX, $Q + $X, $$)
severity: warning
message: "Potential dynamic SQL via string concatenation at Exec/Query sink; use placeholders/parameters."
YAML

  # Deferred Close() return value ignored (heuristic)
  cat >"$AST_RULE_DIR/go.close-error-ignored.yml" <<'YAML'
id: go.close-error-ignored
language: go
rule:
  pattern: defer $C.Close()
  not:
    inside:
      has:
        pattern: |
          if err := $C.Close(); err != nil {
            $$$
          }
severity: info
message: "Deferred Close() return value ignored; for writers/files, Close can fail (flush errors)."
YAML

  # SQL: tx.Rollback deferred before err check (panic/rollback wrong tx)
  cat >"$AST_RULE_DIR/go.sql.defer-rollback-before-err-check.yml" <<'YAML'
id: go.sql.defer-rollback-before-err-check
language: go
rule:
  any:
    - pattern: |
        $TX, $ERR := $DB.Begin($$)
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR := $DB.BeginTx($$)
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR = $DB.Begin($$)
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR = $DB.BeginTx($$)
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR := $DB.BeginTx($$)
        defer func() { _ = $TX.Rollback() }()
severity: error
message: "defer tx.Rollback() occurs before checking err; tx may be nil/stale and will panic/rollback wrong tx. Check err first, then defer Rollback()."
YAML

  # SQL: tx.Rollback deferred late after Begin (statements between err check and defer)
  cat >"$AST_RULE_DIR/go.sql.defer-rollback-delayed.yml" <<'YAML'
id: go.sql.defer-rollback-delayed
language: go
rule:
  any:
    - pattern: |
        $TX, $ERR := $DB.Begin($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR := $DB.BeginTx($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR = $DB.Begin($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR = $DB.BeginTx($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $TX.Rollback()
    - pattern: |
        $TX, $ERR := $DB.BeginTx($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer func() { _ = $TX.Rollback() }()
severity: warning
message: "defer tx.Rollback() is not placed immediately after a successful Begin; early returns between may leak/skip rollback."
YAML

  # SQL: rows from Query not closed (Close pairing)
  cat >"$AST_RULE_DIR/go.sql.rows-not-closed.yml" <<'YAML'
id: go.sql.rows-not-closed
language: go
rule:
  all:
    - any:
        - pattern: $ROWS, $ERR := $DB.Query($$)
        - pattern: $ROWS, $ERR := $DB.QueryContext($CTX, $$)
        - pattern: $ROWS, $ERR = $DB.Query($$)
        - pattern: $ROWS, $ERR = $DB.QueryContext($CTX, $$)
    - not:
        inside:
          has:
            any:
              - pattern: defer $ROWS.Close()
              - pattern: $ROWS.Close()
              - pattern: defer func() { _ = $ROWS.Close() }()
              - pattern: defer func() { $ROWS.Close() }()
severity: warning
message: "sql.Rows from Query not obviously closed; defer rows.Close() after successful query."
YAML

  # SQL: rows.Close deferred late after err check (statements in between)
  cat >"$AST_RULE_DIR/go.sql.defer-rows-close-delayed.yml" <<'YAML'
id: go.sql.defer-rows-close-delayed
language: go
rule:
  any:
    - pattern: |
        $ROWS, $ERR := $DB.Query($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR := $DB.QueryContext($CTX, $$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR = $DB.Query($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR = $DB.QueryContext($CTX, $$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $ROWS.Close()
    - pattern: |
        $ROWS, $ERR := $DB.QueryContext($CTX, $$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer func() { _ = $ROWS.Close() }()
severity: info
message: "defer rows.Close() is not placed immediately after a successful Query; early returns between may leak rows/connections."
YAML

  # HTTP: resp.Body.Close deferred late after err check (statements in between)
  cat >"$AST_RULE_DIR/go.http.defer-body-close-delayed.yml" <<'YAML'
id: go.http.defer-body-close-delayed
language: go
rule:
  any:
    - pattern: |
        $RESP, $ERR := $CLIENT.Do($REQ)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Get($URL)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Post($$)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Head($URL)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.PostForm($URL, $DATA)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer $RESP.Body.Close()
    - pattern: |
        $RESP, $ERR := http.Get($URL)
        if $ERR != nil { $$$ }
        $S
        $$$
        defer func() { _ = $RESP.Body.Close() }()
severity: info
message: "defer resp.Body.Close() is not placed immediately after a successful request; early returns between may leak connections."
YAML

  # Context: cancel() deferred late after With* assignment
  cat >"$AST_RULE_DIR/go.context.cancel-defer-delayed.yml" <<'YAML'
id: go.context.cancel-defer-delayed
language: go
rule:
  any:
    - pattern: |
        $CTX, $CANCEL := context.WithCancel($PARENT)
        $S
        $$$
        defer $CANCEL()
    - pattern: |
        $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
        $S
        $$$
        defer $CANCEL()
    - pattern: |
        $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
        $S
        $$$
        defer $CANCEL()
    - pattern: |
        $CTX, $CANCEL = context.WithCancel($PARENT)
        $S
        $$$
        defer $CANCEL()
    - pattern: |
        $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
        $S
        $$$
        defer $CANCEL()
    - pattern: |
        $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
        $S
        $$$
        defer $CANCEL()
severity: info
message: "cancel() is deferred later than the With* assignment; defer immediately to avoid leaks on early return."
YAML

  # Context: cancel() deferred conditionally inside if after With* assignment
  cat >"$AST_RULE_DIR/go.context.cancel-defer-in-if.yml" <<'YAML'
id: go.context.cancel-defer-in-if
language: go
rule:
  any:
    - pattern: |
        $CTX, $CANCEL := context.WithCancel($PARENT)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
    - pattern: |
        $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
    - pattern: |
        $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
    - pattern: |
        $CTX, $CANCEL = context.WithCancel($PARENT)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
    - pattern: |
        $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
    - pattern: |
        $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
        if $COND {
          $$$
          defer $CANCEL()
          $$$
        }
severity: warning
message: "cancel() is deferred conditionally inside if; prefer unconditional defer cancel() immediately after With*."
YAML

  # Context: defer cancel() occurs before cancel is re-assigned/shadowed
  cat >"$AST_RULE_DIR/go.context.cancel-defer-before-shadow.yml" <<'YAML'
id: go.context.cancel-defer-before-shadow
language: go
rule:
  any:
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL := context.WithCancel($PARENT)
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL := context.WithTimeout($PARENT, $DUR)
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL := context.WithDeadline($PARENT, $DL)
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL = context.WithCancel($PARENT)
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL = context.WithTimeout($PARENT, $DUR)
    - pattern: |
        defer $CANCEL()
        $$$
        $CTX, $CANCEL = context.WithDeadline($PARENT, $DL)
severity: warning
message: "defer cancel() occurs before cancel is (re)assigned; you may be deferring the wrong cancel (shadowing/reassign bug)."
YAML

  # Ignored errors: blank identifier discards Write error
  cat >"$AST_RULE_DIR/go.write-error-ignored.yml" <<'YAML'
id: go.write-error-ignored
language: go
rule:
  any:
    - pattern: $N, _ := $W.Write($$)
    - pattern: $N, _ = $W.Write($$)
    - pattern: _, _ := $W.Write($$)
    - pattern: _, _ = $W.Write($$)
severity: info
message: "Write(...) error is ignored via blank identifier; consider handling/propagating the error."
YAML

  # Ignored errors: http.ResponseWriter.Write(...) return values discarded
  cat >"$AST_RULE_DIR/go.http.responsewriter-write-ignored.yml" <<'YAML'
id: go.http.responsewriter-write-ignored
language: go
rule:
  all:
    - pattern: $W.Write($$)
    - inside:
        kind: expression_statement
    - inside:
        any:
          - pattern: func($W http.ResponseWriter, $R *http.Request) { $$$ }
          - pattern: func($W http.ResponseWriter, $R *http.Request, $$) { $$$ }
          - pattern: func ($REC $T) $NAME($W http.ResponseWriter, $R *http.Request) { $$$ }
          - pattern: func ($REC $T) $NAME($W http.ResponseWriter, $R *http.Request, $$) { $$$ }
severity: info
message: "http.ResponseWriter.Write(...) return values ignored; consider checking error (or explicitly discarding with _, _ = ...)."
YAML

  # Ignored errors: fmt.Fprintf return values discarded
  cat >"$AST_RULE_DIR/go.fmt.fprintf-error-ignored.yml" <<'YAML'
id: go.fmt.fprintf-error-ignored
language: go
rule:
  any:
    - all:
        - pattern: fmt.Fprintf($$)
        - inside:
            kind: expression_statement
    - pattern: $N, _ := fmt.Fprintf($$)
    - pattern: $N, _ = fmt.Fprintf($$)
    - pattern: _, _ := fmt.Fprintf($$)
    - pattern: _, _ = fmt.Fprintf($$)
severity: info
message: "fmt.Fprintf return error ignored; consider handling it (especially when writing to network/file)."
YAML

  # Ignored errors: json.NewEncoder(...).Encode(...) return error discarded
  cat >"$AST_RULE_DIR/go.json.encode-error-ignored.yml" <<'YAML'
id: go.json.encode-error-ignored
language: go
rule:
  all:
    - pattern: json.NewEncoder($X).Encode($V)
    - inside:
        kind: expression_statement
severity: warning
message: "json.Encoder.Encode(...) return error ignored; consider handling it."
YAML

  # Ignored errors: template Execute(...) return error discarded
  cat >"$AST_RULE_DIR/go.template.execute-error-ignored.yml" <<'YAML'
id: go.template.execute-error-ignored
language: go
rule:
  any:
    - all:
        - pattern: $T.Execute($W, $D)
        - inside:
            kind: expression_statement
    - all:
        - pattern: $T.ExecuteTemplate($W, $NAME, $D)
        - inside:
            kind: expression_statement
severity: warning
message: "template Execute(...) error ignored; consider handling it."
YAML
}

emit_sarif_rich() {
  local tmp
  tmp="$(mktemp -t ubs_sarif.XXXXXX.json 2>/dev/null || mktemp -t ubs_sarif.XXXXXX)"
  if ! "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --sarif 2>/dev/null >"$tmp"; then
    rm -f "$tmp" 2>/dev/null || true
    return 1
  fi

  # Optional enrichment (tags + helpUri) for GitHub code scanning friendliness
  if [[ "$SARIF_RICH" -ne 1 ]] || ! command -v python3 >/dev/null 2>&1; then
    cat "$tmp"
    rm -f "$tmp" 2>/dev/null || true
    return 0
  fi

  if ! python3 - "$tmp" <<'PY'
import json, sys

sarif_path = sys.argv[1]
with open(sarif_path, "r", encoding="utf-8") as f:
    sarif = json.load(f)

HELP_SNIPPETS = {
    "go.http.defer-body-before-err-check": """Safe pattern:
```go
resp, err := client.Do(req)
if err != nil {
  return err
}
defer resp.Body.Close()
```""",
    "go.http-response-body-not-closed": """Close response bodies to avoid leaking connections:
```go
resp, err := http.Get(url)
if err != nil {
  return err
}
defer resp.Body.Close()
```""",
    "go.sql.defer-rollback-before-err-check": """Safe pattern:
```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
  return err
}
defer tx.Rollback()
```""",
    "go.sql.begin-without-defer-rollback": """Best practice:
```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
  return err
}
defer tx.Rollback()
```""",
    "go.sql.defer-rows-close-before-err-check": """Safe pattern:
```go
rows, err := db.QueryContext(ctx, q, args...)
if err != nil {
  return err
}
defer rows.Close()
```""",
    "go.sql.rows-not-closed": """Close rows to avoid holding connections:
```go
rows, err := db.QueryContext(ctx, q, args...)
if err != nil {
  return err
}
defer rows.Close()
```""",
    "go.context-without-cancel": """Prefer deferring cancel() immediately:
```go
ctx, cancel := context.WithTimeout(parent, 2*time.Second)
defer cancel()
```""",
    "go.context.cancel-defer-before-shadow": """Bug pattern: deferring an older cancel, then shadowing it:
```go
defer cancel()            // refers to outer cancel
ctx, cancel := context.WithTimeout(parent, d) // shadows cancel
```""",
}

def tags_for(rule_id: str) -> list[str]:
    rid = (rule_id or "").lower()
    t = {"go", "ubs", "ast-grep"}
    if rid.startswith("go.http"):
        t |= {"http", "network"}
    if rid.startswith("go.sql"):
        t |= {"sql", "database"}
    if rid.startswith("go.context"):
        t |= {"context", "concurrency"}
    if rid.startswith("go.async") or "goroutine" in rid:
        t |= {"concurrency", "goroutine"}
    if rid.startswith("go.taint"):
        t |= {"taint", "security"}
    if rid.startswith("go.exec") or "command" in rid:
        t |= {"exec", "security"}
    if rid.startswith("go.tls") or "tls" in rid or "crypto" in rid:
        t |= {"crypto", "security", "tls"}
    if rid.startswith("go.resource") or rid.startswith("go.time") or "leak" in rid or "close" in rid or "stop" in rid:
        t |= {"resource-leak"}
    if "panic" in rid or "recover" in rid:
        t |= {"panic"}
    if "error" in rid or "iferr" in rid or "ignored" in rid:
        t |= {"error-handling"}
    if "ioutil" in rid or rid.startswith("go.io"):
        t |= {"io"}
    if "unsafe" in rid or "reflect" in rid:
        t |= {"unsafe"}
    if "template" in rid or "xss" in rid:
        t |= {"web"}
    return sorted(t)

for run in sarif.get("runs", []) or []:
    driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
    rules = driver.get("rules", []) or []
    rule_tags: dict[str, list[str]] = {}

    for rule in rules:
        rid = rule.get("id") or rule.get("name") or rule.get("ruleId") or rule.get("ruleID")
        if not rid:
            continue
        tags = tags_for(rid)
        rule_tags[rid] = tags

        rule.setdefault("helpUri", f"urn:ubs-golang:{rid}")

        props = rule.setdefault("properties", {})
        existing = props.get("tags")
        if isinstance(existing, list):
            tags = sorted(set(existing) | set(tags))
        props["tags"] = tags

        # Provide a help markdown block to make GitHub code scanning UI more actionable.
        if "help" not in rule:
            sd = (rule.get("shortDescription", {}) or {}).get("text") or ""
            fd = (rule.get("fullDescription", {}) or {}).get("text") or ""
            msg = fd or sd
            md = f"**{rid}**\n\n{msg}\n"
            snippet = HELP_SNIPPETS.get(rid)
            if snippet:
                md += "\n" + snippet.strip() + "\n"
            rule["help"] = {"markdown": md}

    for res in run.get("results", []) or []:
        rid = res.get("ruleId") or res.get("ruleID") or res.get("rule_id")
        tags = rule_tags.get(rid)
        if not tags:
            continue
        props = res.setdefault("properties", {})
        existing = props.get("tags")
        if isinstance(existing, list):
            tags = sorted(set(existing) | set(tags))
        props["tags"] = tags

json.dump(sarif, sys.stdout, ensure_ascii=False)
PY
  then
    cat "$tmp"
  fi
  rm -f "$tmp" 2>/dev/null || true
}

run_ast_rules_machine() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  if [[ "$FORMAT" == "sarif" ]]; then
    emit_sarif_rich
  else
    "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json 2>/dev/null
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper (return 0 to run category)
# ────────────────────────────────────────────────────────────────────────────
should_run_category() {
  local cat="$1"
  if [[ -n "$CATEGORY_WHITELIST" ]]; then
    local ok=1
    IFS=',' read -r -a allow <<<"$CATEGORY_WHITELIST"
    local s
    for s in "${allow[@]}"; do [[ "$s" == "$cat" ]] && ok=0; done
    [[ $ok -eq 1 ]] && return 1
  fi
  if [[ -n "$SKIP_CATEGORIES" ]]; then
    IFS=',' read -r -a arr <<<"$SKIP_CATEGORIES"
    local s
    for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  fi
  return 0
}
should_skip() { should_run_category "$@"; }

# ────────────────────────────────────────────────────────────────────────────
# Banner
# ────────────────────────────────────────────────────────────────────────────
print_banner() {
  [[ "$NO_BANNER" -eq 1 || "$QUIET" -eq 1 || "$FORMAT" != "text" ]] && return 0
  echo -e "${BOLD}${CYAN}"
  cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗      ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝      ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗        ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝        ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗      ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝      ║
║                                                                      ║
║  Go module • goroutine, context, HTTP client/server guardrails       ║
║  UBS module: golang • AST packs + gofmt/go test integration          ║
║  ASCII homage: Renee French gopher lineage                           ║
║                                                                      ║
║  Night Owl QA                                                        ║
║  “We see bugs before you do.”                                        ║
╚══════════════════════════════════════════════════════════════════════╝
BANNER
  echo -e "${RESET}"
}

# ────────────────────────────────────────────────────────────────────────────
# AST JSON helpers: show sample locations/snippets for a rule id (best effort)
# ────────────────────────────────────────────────────────────────────────────
show_ast_samples() {
  local rid="$1" limit="${2:-$DETAIL_LIMIT}"
  [[ -n "$rid" && -f "${AST_JSON:-}" && "$HAS_AST_GREP" -eq 1 ]] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  python3 - "$AST_JSON" "$rid" "$limit" <<'PY' | while IFS=$'\t' read -r loc code; do
import json, sys
path, rid, lim = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
    sys.exit(0)

out = []
def walk(o):
    if len(out) >= lim:
        return
    if isinstance(o, dict):
        rr = o.get("id") or o.get("rule_id") or o.get("ruleId")
        if rr == rid and ("file" in o or "path" in o) and "range" in o:
            f = o.get("file") or o.get("path") or "?"
            rng = o.get("range") or {}
            start = rng.get("start") or {}
            line = int(start.get("row", 0)) + 1
            text = o.get("text") or o.get("snippet") or ""
            text = " ".join(str(text).split())
            if text:
                out.append((f"{f}:{line}", text[:220]))
            else:
                out.append((f"{f}:{line}", ""))
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for it in o:
            walk(it)

walk(data)
for loc, text in out:
    print(loc + "\t" + text)
PY
    file="${loc%:*}"; line="${loc##*:}"
    print_code_sample "$file" "$line" "${code:-}"
  done
}

# ────────────────────────────────────────────────────────────────────────────
# Main Scan Logic
# ────────────────────────────────────────────────────────────────────────────

maybe_clear
print_banner

index_project

if [[ "$FORMAT" == "text" ]]; then
  say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
  say "${WHITE}Started:${RESET}  ${GRAY}$(now)${RESET}"
  say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES${RESET} ${DIM}(${INCLUDE_EXT}; ${INCLUDE_NAMES})${RESET}"
fi

# ast-grep availability + rulepack staging
if check_ast_grep; then
  [[ "$FORMAT" == "text" ]] && say ""
  diag "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
  write_ast_rules_v7_extras || true
  if [[ "$LIST_RULES" -eq 1 ]]; then
    ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$AST_RULE_DIR"/*.yml 2>/dev/null || true ) | sort -u
    exit 0
  fi
  ensure_ast_scan_json || true
else
  diag "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
  if [[ "$FORMAT" != "text" ]]; then
    :
  fi
fi

# Machine-output mode: emit JSON/SARIF and exit with terse summary on stderr
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
    run_ast_rules_machine
  else
    if [[ "$FORMAT" == "sarif" ]]; then
      cat <<'SARIF'
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ubs-golang",
          "informationUri": "https://ast-grep.github.io/",
          "rules": []
        }
      },
      "results": []
    }
  ]
}
SARIF
    else
      echo '[]'
    fi
  fi
  {
    echo ""
    echo "Summary (machine output emitted on stdout):"
    echo "  Version: $VERSION"
    echo "  Files:   $TOTAL_FILES"
    echo "  Go:      $GO_FILES_COUNT"
  } 1>&2
  exit 0
fi

# In text mode, run the broader heuristic scans
begin_scan_section

# Grep helpers that respect --only-changed (counts still approximate when using grep fallback)
grep_count_scoped() {
  local pat="$1"
  local targets; targets="$(rg_or_grep_targets)"
  ( set +o pipefail;
    printf '%s\n' "$targets" | while IFS= read -r t; do
      [[ -z "$t" ]] && continue
      "${GREP_RN[@]}" -e "$pat" "$t" 2>/dev/null || true
    done
  ) | count_lines
}
grep_count_scoped_i() {
  local pat="$1"
  local targets; targets="$(rg_or_grep_targets)"
  ( set +o pipefail;
    printf '%s\n' "$targets" | while IFS= read -r t; do
      [[ -z "$t" ]] && continue
      "${GREP_RNI[@]}" -e "$pat" "$t" 2>/dev/null || true
    done
  ) | count_lines
}

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: CONCURRENCY & GOROUTINE SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. CONCURRENCY & GOROUTINE SAFETY"
print_category "Detects: goroutines in loops, WaitGroup imbalance, manual lock/unlock, tickers not stopped" \
  "Race-prone constructs and lifecycle mistakes cause leaks and deadlocks"

print_subheader "Goroutines launched"
go_count=$(grep_count_scoped "^[[:space:]]*go[[:space:]]+")
print_finding "info" "$go_count" "goroutine launches found"
[[ "$VERBOSE" -eq 1 && "$go_count" -gt 0 ]] && show_detailed_finding "^[[:space:]]*go[[:space:]]+" "$DETAIL_LIMIT" || true

print_subheader "go inside loops (ensure capture correctness)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.goroutine-in-loop" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "goroutine launches inside loops"; fi

print_subheader "loop variable captured by goroutine (closure)"
cap=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.loop-var-capture" || echo 0)
if [ "$cap" -gt 0 ]; then print_finding "warning" "$cap" "Loop variable captured by goroutine closure"; fi
[[ "$VERBOSE" -eq 1 && "$cap" -gt 0 ]] && show_ast_samples "go.loop-var-capture" "$DETAIL_LIMIT" || true
print_subheader "for-loop variable captured by goroutine closure (classic i++ capture bug)"
cap2=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.loop-var-capture-for" || echo 0)
if [ "$cap2" -gt 0 ]; then print_finding "warning" "$cap2" "For-loop variable captured by goroutine closure"; fi
[[ "$VERBOSE" -eq 1 && "$cap2" -gt 0 ]] && show_ast_samples "go.loop-var-capture-for" "$DETAIL_LIMIT" || true


print_subheader "sync.WaitGroup Add/Done balance (heuristic)"
wg_add=$(grep_count_scoped "\.Add\(")
wg_done=$(grep_count_scoped "\.Done\(")
if [ "$wg_add" -gt $((wg_done + 1)) ]; then
  diff=$((wg_add - wg_done))
  print_finding "warning" "$diff" "WaitGroup Add exceeds Done (heuristic)"
fi
wg_ast=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.waitgroup-add-no-done" || echo 0)
if [ "$wg_ast" -gt 0 ]; then print_finding "info" "$wg_ast" "WaitGroup.Add without nearby Done (AST heuristic)"; fi

print_subheader "Mutex manual Lock/Unlock (prefer defer after Lock)"
lock_count=$(grep_count_scoped "\.Lock\(")
defer_unlock=$(grep_count_scoped "defer[[:space:]]+.*\.Unlock\(")
if [ "$lock_count" -gt 0 ]; then
  if [ "$defer_unlock" -lt $((lock_count/2)) ]; then
    print_finding "warning" "$lock_count" "Manual Lock without matching defer Unlock (heuristic)" "Place 'defer mu.Unlock()' immediately after Lock"
  else
    print_finding "good" "Most locks appear paired with deferred unlock"
  fi
fi

print_subheader "time.NewTicker without Stop"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.resource.ticker-no-stop" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Ticker created without Stop (AST)"; fi

run_async_error_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: CHANNELS & SELECT
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 2; then
print_header "2. CHANNELS & SELECT"
print_category "Detects: select without default, send/receive in loops w/out backpressure, time.After in loop" \
  "Channel misuse leads to deadlocks or unbounded growth"

print_subheader "select statements (review for default/backpressure)"
sel_count=$(grep_count_scoped "^[[:space:]]*select[[:space:]]*\{")
print_finding "info" "$sel_count" "select statements present"
if [[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]]; then
  s_nd=$(ast_count "go.select-no-default")
  if [ "$s_nd" -gt 0 ]; then print_finding "info" "$s_nd" "select without default (check for intended blocking/timeouts)"; fi
fi

print_subheader "time.After used inside loops"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.time-after-in-loop" || echo 0)
if [ "$count" -eq 0 ]; then
  count=$(
    ( set +o pipefail;
      "${GREP_RN[@]}" -e "for[[:space:]]*.*\{" "$PROJECT_DIR" 2>/dev/null \
        | (grep -A8 -E "time\.After\(" || true) \
        | (grep -c -E "time\.After\(" || true)
    ) | awk 'END{print ($1+0)}'
  )
fi
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "time.After allocations in loops - prefer reusable timer"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: CONTEXT PROPAGATION & CANCELLATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 3; then
print_header "3. CONTEXT PROPAGATION & CANCELLATION"
print_category "Detects: WithCancel/Timeout without cancel, Background() in handlers, ctx not first parameter (heuristic)" \
  "Proper context usage avoids leaks and enables graceful shutdowns"

print_subheader "cancel() defer placement (AST path-sensitive-ish)"
c_shadow=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.context.cancel-defer-before-shadow" || echo 0)
if [ "$c_shadow" -gt 0 ]; then
  print_finding "warning" "$c_shadow" "defer cancel() occurs before cancel is (re)assigned/shadowed (likely wrong cancel deferred)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.context.cancel-defer-before-shadow" 6 || true
fi

c_in_if=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.context.cancel-defer-in-if" || echo 0)
if [ "$c_in_if" -gt 0 ]; then
  print_finding "warning" "$c_in_if" "cancel() deferred conditionally inside if after context.With* (prefer unconditional defer cancel())"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.context.cancel-defer-in-if" 6 || true
fi

c_delayed=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.context.cancel-defer-delayed" || echo 0)
if [ "$c_delayed" -gt 0 ]; then
  print_finding "info" "$c_delayed" "cancel() deferred late after context.With* assignment (early returns between may leak)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.context.cancel-defer-delayed" 6 || true
fi

c_missing=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.context-without-cancel" || echo 0)
if [ "$c_missing" -gt 0 ]; then
  print_finding "warning" "$c_missing" "context.With* assigns cancel but no defer cancel() in containing scope (AST heuristic)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.context-without-cancel" 6 || true
elif [[ "$HAS_AST_GREP" -ne 1 || ! -f "$AST_JSON" ]]; then
  with_calls=$(grep_count_scoped "context\.With(Cancel|Timeout|Deadline)\(")
  cancel_defers=$(grep_count_scoped "defer[[:space:]]+cancel\(\)")
  if [ "$with_calls" -gt "$cancel_defers" ]; then
    diff=$((with_calls - cancel_defers))
    print_finding "info" "$diff" "Possible missing cancel() defers (regex heuristic): context.With*=$with_calls defer cancel()=$cancel_defers"
  fi
fi

print_subheader "context.Background() used inside HTTP handlers"
bg=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-handler-background" || echo 0)
if [ "$bg" -gt 0 ]; then print_finding "warning" "$bg" "Use r.Context() instead of context.Background() in handlers"; fi

print_subheader "context.TODO usage"
todo=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.context-todo" || echo 0)
if [ "$todo" -gt 0 ]; then print_finding "info" "$todo" "context.TODO() present - ensure it’s not shipping to prod"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: HTTP CLIENT/SERVER SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 4; then
print_header "4. HTTP CLIENT/SERVER SAFETY"
print_category "Detects: default client use, missing client/server timeouts, resp.Body leaks" \
  "Networking bugs leak resources and cause hangs"

print_subheader "Default http.Client usage (Get/Post/Head/DefaultClient.Do)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-default-client" || echo 0)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Default http.Client without Timeout"
else
  print_finding "good" "No obvious default client usage"
fi

print_subheader "http.Client without Timeout"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-client-without-timeout" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "http.Client constructed without Timeout"; fi

print_subheader "http.Client without explicit Transport (informational)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-client-without-transport" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "http.Client created without explicit Transport"; fi

print_subheader "http.Transport missing key timeouts (heuristic)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-transport-missing-timeouts" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "http.Transport missing key timeouts"; fi

print_subheader "http.Server without timeouts (none set)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-server-no-timeouts" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "http.Server lacks timeouts"; fi

print_subheader "http.NewRequest without context"
nr=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-newrequest-without-context" || echo 0)
if [ "$nr" -gt 0 ]; then print_finding "info" "$nr" "Prefer http.NewRequestWithContext"; fi

print_subheader "Response body Close() (AST heuristic + regex fallback)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-response-body-not-closed" || echo 0)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "HTTP response bodies not obviously closed (AST heuristic)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.http-response-body-not-closed" 6 || true
else
  http_calls=$(grep_count_scoped "http\.(Get|Post|Head)\(|\.Do\(")
  body_close=$(grep_count_scoped "\.Body\.Close\(")
  if [ "$http_calls" -gt 0 ] && [ "$body_close" -lt "$http_calls" ]; then
    diff=$((http_calls - body_close))
    print_finding "warning" "$diff" "Possible missing resp.Body.Close() (regex heuristic)"
  else
    print_finding "good" "Response bodies likely closed (heuristic)"
  fi
fi

print_subheader "defer resp.Body.Close() placed late after err check (AST path-sensitive-ish)"
body_close_late=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http.defer-body-close-delayed" || echo 0)
if [ "$body_close_late" -gt 0 ]; then
  print_finding "info" "$body_close_late" "defer resp.Body.Close() placed late after success (early returns between may leak connections)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.http.defer-body-close-delayed" 6 || true
fi

print_subheader "resp.Body.Close() deferred before err check (panic risk)"
bad_defer=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http.defer-body-before-err-check" || echo 0)
if [ "$bad_defer" -gt 0 ]; then print_finding "critical" "$bad_defer" "defer resp.Body.Close() before checking err"; fi
[[ "$VERBOSE" -eq 1 && "$bad_defer" -gt 0 ]] && show_ast_samples "go.http.defer-body-before-err-check" "$DETAIL_LIMIT" || true

print_subheader "TLS MinVersion missing"
minv=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.tls-minversion-missing" || echo 0)
if [ "$minv" -gt 0 ]; then print_finding "info" "$minv" "tls.Config without MinVersion"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: RESOURCE LIFECYCLE & DEFER
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 5; then
print_header "5. RESOURCE LIFECYCLE & DEFER"
print_category "Detects: defer in loops, missing Close/Stop, DB rows leaks" \
  "Resource mistakes show up as FD leaks and memory growth"

print_subheader "defer inside loops"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.defer-in-loop" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "defer inside loops"; fi

print_subheader "defer Close() before err check (panic risk)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.defer-close-before-err-check" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "defer Close() before checking err"; fi
[[ "$VERBOSE" -eq 1 && "$count" -gt 0 ]] && show_ast_samples "go.defer-close-before-err-check" "$DETAIL_LIMIT" || true

print_subheader "rows.Close() deferred before err check (panic risk)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.defer-rows-close-before-err-check" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "defer rows.Close() before checking err"; fi
[[ "$VERBOSE" -eq 1 && "$count" -gt 0 ]] && show_ast_samples "go.sql.defer-rows-close-before-err-check" "$DETAIL_LIMIT" || true

print_subheader "Rows not closed (AST heuristic)"
rows_nc=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.rows-not-closed" || echo 0)
if [ "$rows_nc" -gt 0 ]; then
  print_finding "warning" "$rows_nc" "sql.Rows from Query/QueryContext not obviously closed (defer rows.Close())"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.sql.rows-not-closed" 6 || true
else
  rows_open=$(grep_count_scoped "\.Query(Row|Context)?\(")
  rows_close=$(grep_count_scoped "\.Close\(\)")
  if [ "$rows_open" -gt 0 ] && [ "$rows_close" -lt "$rows_open" ]; then
    diff=$((rows_open - rows_close))
    print_finding "info" "$diff" "Potential missing Close() calls for rows/files/etc. (broad heuristic)"
  fi
fi

print_subheader "rows.Close() deferred late after err check (AST path-sensitive-ish)"
rows_close_late=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.defer-rows-close-delayed" || echo 0)
if [ "$rows_close_late" -gt 0 ]; then
  print_finding "info" "$rows_close_late" "defer rows.Close() is placed late after a successful Query (early returns between may leak rows/conn)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.sql.defer-rows-close-delayed" 6 || true
fi

print_subheader "tx.Rollback() deferred before err check (panic risk)"
tx_rb_before=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.defer-rollback-before-err-check" || echo 0)
if [ "$tx_rb_before" -gt 0 ]; then
  print_finding "critical" "$tx_rb_before" "defer tx.Rollback() occurs before checking err; tx may be nil/stale"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.sql.defer-rollback-before-err-check" 6 || true
fi

print_subheader "database/sql Tx Commit/Rollback (heuristic)"
tx_begin=$(grep_count_scoped "\b(Begin|BeginTx)\(")
tx_end=$(grep_count_scoped "\.(Commit|Rollback)\(")
if [ "$tx_begin" -gt 0 ] && [ "$tx_end" -lt "$tx_begin" ]; then
  diff=$((tx_begin - tx_end))
  print_finding "warning" "$diff" "Tx started without Commit/Rollback (heuristic)"
fi

print_subheader "Tx Begin without deferred Rollback (AST heuristic)"
tx_rb=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.begin-without-defer-rollback" || echo 0)
if [ "$tx_rb" -gt 0 ]; then
  print_finding "warning" "$tx_rb" "Transaction begun without a deferred tx.Rollback()"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.sql.begin-without-defer-rollback" 6 || true
fi

print_subheader "tx.Rollback() deferred late after Begin (AST path-sensitive-ish)"
tx_rb_late=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.defer-rollback-delayed" || echo 0)
if [ "$tx_rb_late" -gt 0 ]; then
  print_finding "warning" "$tx_rb_late" "defer tx.Rollback() is placed late after Begin (early returns between may skip rollback)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.sql.defer-rollback-delayed" 6 || true
fi

print_subheader "time.Tick usage"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.time-tick" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "time.Tick leaks; prefer NewTicker"; fi

print_subheader "time.NewTimer channel not drained (heuristic)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.resource.timer-not-drained" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "time.NewTimer channel never drained"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ERROR HANDLING & WRAPPING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. ERROR HANDLING & WRAPPING"
print_category "Detects: ignored errors, fmt.Errorf without %w, panic in library code, recover outside defer" \
  "Robust error paths prevent crashes and lost context"

print_subheader "Ignored errors via blank identifier (heuristic)"
ignored=$(grep_count_scoped ",[[:space:]]*_[[:space:]]*:=")
if [ "$ignored" -gt 0 ]; then print_finding "info" "$ignored" "Assignments discarding secondary return values (could be error)"; fi

print_subheader "Ignored errors: common patterns (AST)"
c_write_blank=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.write-error-ignored" || echo 0)
if [ "$c_write_blank" -gt 0 ]; then
  print_finding "info" "$c_write_blank" "Write(...) error ignored via blank identifier (AST)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.write-error-ignored" 6 || true
fi

c_rw_write=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http.responsewriter-write-ignored" || echo 0)
if [ "$c_rw_write" -gt 0 ]; then
  print_finding "info" "$c_rw_write" "http.ResponseWriter.Write(...) return values discarded (AST)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.http.responsewriter-write-ignored" 6 || true
fi

c_fprintf_ignored=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.fmt.fprintf-error-ignored" || echo 0)
if [ "$c_fprintf_ignored" -gt 0 ]; then
  print_finding "info" "$c_fprintf_ignored" "fmt.Fprintf return error ignored (AST)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.fmt.fprintf-error-ignored" 6 || true
fi

c_json_encode_ignored=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.json.encode-error-ignored" || echo 0)
if [ "$c_json_encode_ignored" -gt 0 ]; then
  print_finding "warning" "$c_json_encode_ignored" "json.NewEncoder(...).Encode(...) error ignored (AST)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.json.encode-error-ignored" 6 || true
fi

c_tmpl_exec_ignored=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.template.execute-error-ignored" || echo 0)
if [ "$c_tmpl_exec_ignored" -gt 0 ]; then
  print_finding "warning" "$c_tmpl_exec_ignored" "template Execute(...) error ignored (AST)"
  [[ "$VERBOSE" -eq 1 ]] && show_ast_samples "go.template.execute-error-ignored" 6 || true
fi

print_subheader "Empty if err != nil blocks"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.iferr-empty" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Empty if err != nil { } blocks"; fi

print_subheader "if err != nil then return nil (likely dropped error)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.iferr-return-nil" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "err checked but dropped (return nil)"; fi
[[ "$VERBOSE" -eq 1 && "$count" -gt 0 ]] && show_ast_samples "go.iferr-return-nil" "$DETAIL_LIMIT" || true

print_subheader "fmt.Errorf without %w when wrapping err"
count=$(
  ( set +o pipefail;
    "${GREP_RN[@]}" -e "fmt\.Errorf\(" "$PROJECT_DIR" 2>/dev/null \
      | (grep -v "%w" || true) \
      | (grep -E "err[),]" || true) \
      | count_lines
  ) | awk 'END{print ($1+0)}'
)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Consider using %w when wrapping errors"; fi

print_subheader "err shadowing via := (heuristic)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.err-shadow" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "err shadowed via :=; ensure correct error is checked"; fi

print_subheader "panic usage"
panic_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.panic-call" || echo 0)
if [ "$panic_count" -gt 0 ]; then print_finding "warning" "$panic_count" "panic used; prefer errors in libraries"; fi

print_subheader "recover outside deferred func"
rec_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.recover-not-in-defer" || echo 0)
if [ "$rec_count" -gt 0 ]; then print_finding "warning" "$rec_count" "recover() outside defer is ineffective"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: JSON & ENCODING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. JSON & ENCODING"
print_category "Detects: Decoder without DisallowUnknownFields, unchecked Unmarshal, unbounded request bodies" \
  "Parsing mistakes silently lose data or crash later"

print_subheader "json.Decoder without DisallowUnknownFields"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.json-decode-without-disallow" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Consider Decoder.DisallowUnknownFields()"; fi

print_subheader "Unbounded JSON request decode (no MaxBytesReader)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.json.decoder-unbounded-body" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Request JSON decode without MaxBytesReader (DOS risk)"; fi

print_subheader "json.Unmarshal calls"
u_count=$(grep_count_scoped "json\.Unmarshal\(")
if [ "$u_count" -gt 0 ]; then print_finding "info" "$u_count" "json.Unmarshal found - ensure errors handled and input validated"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: FILESYSTEM & I/O
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. FILESYSTEM & I/O"
print_category "Detects: ioutil (deprecated), ReadAll on bodies, Close leaks, defer Close ordering hazards" \
  "I/O mistakes cause memory spikes and descriptor leaks"

print_subheader "ioutil package usage (deprecated)"
ioutil_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.ioutil-deprecated" || echo 0)
if [ "$ioutil_count" -gt 0 ]; then print_finding "info" "$ioutil_count" "Replace ioutil.* with io/os equivalents"; fi

print_subheader "io.ReadAll usage"
ra_count=$(grep_count_scoped "io\.ReadAll\(")
if [ "$ra_count" -gt 10 ]; then print_finding "info" "$ra_count" "Many ReadAll calls - ensure bounded inputs"; fi

print_subheader "File open without Close (heuristic)"
open_count=$(grep_count_scoped "os\.Open(File)?\(")
close_count=$(grep_count_scoped "\.Close\(")
if [ "$open_count" -gt 0 ] && [ "$close_count" -lt "$open_count" ]; then
  diff=$((open_count - close_count))
  print_finding "warning" "$diff" "Potential missing Close() calls (heuristic)"
fi

print_subheader "defer Close() error ignored (flush/commit may fail)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.close-error-ignored" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Deferred Close() without checking error"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: CRYPTOGRAPHY & SECURITY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. CRYPTOGRAPHY & SECURITY"
print_category "Detects: weak hashes, math/rand for security, InsecureSkipVerify, shell exec, dynamic SQL strings" \
  "Security footguns are easy to miss and costly to fix"

print_subheader "Weak hashes (md5/sha1) and RC4"
count=$(grep_count_scoped "md5|sha1|rc4")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Weak crypto primitives detected - use SHA-256/512, AES-GCM, etc."; fi

print_subheader "math/rand used for secrets"
rand_count=$(grep_count_scoped "\bmath/rand\b|\brand\.Seed\(|\brand\.Read\(")
if [ "$rand_count" -gt 0 ]; then print_finding "info" "$rand_count" "math/rand present - avoid for secrets; prefer crypto/rand"; fi

print_subheader "TLS InsecureSkipVerify=true"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.tls-insecure-skip" || echo 0)
if [ "$count" -eq 0 ] && [[ "$HAS_RG" -eq 1 ]]; then
  count=$(rg --no-config --no-messages -g '*.go' -n "InsecureSkipVerify:[[:space:]]*true" "$PROJECT_DIR" 2>/dev/null | wc_num)
fi
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "InsecureSkipVerify enabled"; fi

print_subheader "exec sh -c (command injection risk)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.exec-sh-c" || echo 0)
if [ "$count" -eq 0 ] && [[ "$HAS_RG" -eq 1 ]]; then
  count=$(rg --no-config --no-messages -g '*.go' -n 'exec\.Command(Context)?\(\s*"(sh|bash)"\s*,\s*"-?c"' "$PROJECT_DIR" 2>/dev/null | wc -l | awk '{print $1+0}')
fi
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "exec.Command(*, \"sh\", \"-c\", ...) detected"; fi
[[ "$VERBOSE" -eq 1 && "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" && "$count" -gt 0 ]] && show_ast_samples "go.exec-sh-c" "$DETAIL_LIMIT" || true

print_subheader "exec without context"
cmdctx=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.exec-command-without-context" || echo 0)
if [ "$cmdctx" -gt 0 ]; then print_finding "info" "$cmdctx" "Prefer exec.CommandContext(ctx, ...)"; fi

print_subheader "exec.Command with strings.Fields(...)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.exec-strings-fields" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "exec.Command called with strings.Fields(...); verify argument safety"; fi

print_subheader "Dynamic SQL string construction at Exec/Query sinks (AST heuristic)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql-dynamic-string" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Potential dynamic SQL strings reaching Exec/Query"; fi
[[ "$VERBOSE" -eq 1 && "$count" -gt 0 ]] && show_ast_samples "go.sql-dynamic-string" "$DETAIL_LIMIT" || true

run_taint_analysis_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: REFLECTION & UNSAFE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 10; then
print_header "10. REFLECTION & UNSAFE"
print_category "Detects: unsafe package usage, heavy reflect, interface{} prevalence" \
  "These features bypass type safety and may hide bugs"

print_subheader "unsafe package usage"
unsafe_count=$(grep_count_scoped "import[[:space:]]+\"unsafe\"|unsafe\.")
if [ "$unsafe_count" -gt 0 ]; then print_finding "info" "$unsafe_count" "unsafe usage present - verify invariants and alignment"; fi

print_subheader "reflect usage"
refl_count=$(grep_count_scoped "\breflect\.")
if [ "$refl_count" -gt 0 ]; then print_finding "info" "$refl_count" "reflect usage present - consider generics or interfaces"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: IMPORT HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. IMPORT HYGIENE"
print_category "Detects: dot-imports, blank imports" \
  "Clean imports improve readability and safety"

print_subheader "dot-imports"
dot_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.dot-import" || echo 0)
if [ "$dot_count" -gt 0 ]; then print_finding "warning" "$dot_count" "dot-imports found"; fi

print_subheader "blank imports"
blank_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.blank-import" || echo 0)
if [ "$blank_count" -gt 0 ]; then print_finding "info" "$blank_count" "blank imports present"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: MODULE & BUILD HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 12; then
print_header "12. MODULE & BUILD HYGIENE"
print_category "Detects: go.mod version < 1.23, missing go.sum, toolchain directive, go.work drift" \
  "Build settings directly affect correctness and performance"

print_subheader "go.mod presence and version directive"
if [ "$MODS_COUNT" -gt 0 ]; then
  print_finding "info" "$MODS_COUNT" "go.mod file(s) present"
  up_to_date=0; outdated=0
  while IFS= read -r mf; do
    [[ -z "$mf" ]] && continue
    gv=$(grep -E '^[[:space:]]*go[[:space:]]+[0-9]+\.[0-9]+' "$mf" 2>/dev/null | head -n1 | awk '{print $2}')
    if [[ -n "$gv" && "$gv" =~ ^1\.(2[3-9]|[3-9][0-9])$ ]]; then
      up_to_date=$((up_to_date+1))
    else
      outdated=$((outdated+1))
    fi
  done <<<"$MOD_FILES"
  if [ "$outdated" -gt 0 ]; then
    print_finding "warning" "$outdated" "go.mod with go directive < 1.23" "Set 'go 1.23' (or newer) where appropriate"
  else
    print_finding "good" "All modules declare go >= 1.23"
  fi
else
  print_finding "warning" 1 "No go.mod found" "Use modules; GOPATH mode is legacy"
fi

print_subheader "go.sum presence"
if [ "$GO_SUM_COUNT" -eq 0 ]; then print_finding "info" 1 "go.sum not found"; else print_finding "good" "go.sum present"; fi

print_subheader "go.work presence (informational)"
if [ "$GO_WORK_COUNT" -gt 0 ]; then print_finding "info" "$GO_WORK_COUNT" "go.work detected (workspace mode)"; else print_finding "info" 0 "go.work not found"; fi

print_subheader "toolchain directive usage (informational)"
tool_count=$(grep_count_scoped "^[[:space:]]*toolchain[[:space:]]+go[0-9]+\.[0-9]+")
if [ "$tool_count" -gt 0 ]; then print_finding "info" "$tool_count" "toolchain directive present"; fi

print_subheader "replace directives (informational)"
repl=$(grep_count_scoped "^[[:space:]]*replace[[:space:]]+")
if [ "$repl" -gt 0 ]; then print_finding "info" "$repl" "replace directives present - validate dev overrides not shipped"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: TESTING PRACTICES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 13; then
print_header "13. TESTING PRACTICES"
print_category "Detects: tests existence, t.Parallel usage (heuristic), race-prone patterns" \
  "Healthy tests parallelize safely and fail fast"

print_subheader "Test files"
if [ "$TEST_FILES_COUNT" -gt 0 ]; then
  print_finding "info" "$TEST_FILES_COUNT" "Test files detected"
else
  print_finding "info" 0 "No test files found"
fi

print_subheader "t.Parallel usage (heuristic)"
test_funcs=$(grep_count_scoped "^func[[:space:]]+Test[[:alnum:]_]*\(t[[:space:]]+\*testing\.T\)")
tpar=$(grep_count_scoped "t\.Parallel\(\)")
if [ "$test_funcs" -gt 0 ] && [ "$tpar" -eq 0 ]; then print_finding "info" "$test_funcs" "Consider t.Parallel() for independent tests"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: LOGGING & PRINTF
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 14; then
print_header "14. LOGGING & PRINTF"
print_category "Detects: fmt.Print in libraries, log with secrets (heuristic)" \
  "Logging should be structured, leveled, and scrubbed"

print_subheader "fmt.Print/Printf/Println usage"
fmt_count=$(grep_count_scoped "fmt\.Print(f|ln)?\(")
if [ "$fmt_count" -gt 50 ]; then print_finding "info" "$fmt_count" "Heavy fmt.* logging - consider structured logging"; fi

print_subheader "Logging secrets (heuristic)"
secret_logs=$(grep_count_scoped_i "log\.(Print|Printf|Println|Fatal|Panic).*?(password|secret|token|authorization|bearer)")
if [ "$secret_logs" -gt 0 ]; then print_finding "critical" "$secret_logs" "Possible logging of sensitive data"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: STYLE & MODERNIZATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 15; then
print_header "15. STYLE & MODERNIZATION"
print_category "Detects: interface{} vs any, context parameter position (heuristic)" \
  "Modern idioms reduce boilerplate and mistakes"

print_subheader "interface{} occurrences"
iface_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.interface-empty" || echo 0)
if [ "$iface_count" -gt 0 ]; then print_finding "info" "$iface_count" "Prefer 'any' over 'interface{}'"; fi

print_subheader "context.Context parameter not first (heuristic)"
ctx_mispos=$(
  ( set +o pipefail;
    "${GREP_RN[@]}" -e "^func[[:space:]]*(\([^)]+\)[[:space:]]*)?[A-Za-z_][A-Za-z0-9_]*\([^)]*context\.Context" "$PROJECT_DIR" 2>/dev/null \
      | (grep -v "(ctx[[:space:]]+context\.Context" || true) \
      | count_lines
  ) | awk 'END{print ($1+0)}'
)
if [ "$ctx_mispos" -gt 0 ]; then print_finding "info" "$ctx_mispos" "Place ctx context.Context first param"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: PANIC/RECOVER & TIME PATTERNS (AST Pack)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. PANIC/RECOVER & TIME PATTERNS (AST Pack)"
print_category "AST-detected: panic(), recover outside defer, time.Tick, time.After in loop" \
  "Codifies common pitfalls as precise AST rules"

if [[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]]; then
  say "${DIM}${INFO} ast-grep produced structured matches. Tally by rule id:${RESET}"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$AST_JSON" <<'PY'
import json, sys
from collections import Counter

path = sys.argv[1]
try:
    data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
    data = None

ids = []
def walk(obj):
    if isinstance(obj, dict):
        rid = obj.get("id") or obj.get("rule_id") or obj.get("ruleId")
        if isinstance(rid, str) and ("range" in obj) and ("file" in obj or "path" in obj):
            ids.append(rid)
        for v in obj.values():
            walk(v)
    elif isinstance(obj, list):
        for it in obj:
            walk(it)
walk(data)

c = Counter(ids)
for rid, n in sorted(c.items()):
    print(f"  • {rid:<44} {n:>5}")
PY
  else
    ids=$(grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' "$AST_JSON" 2>/dev/null | sed -E 's/.*"id"[ ]*:[ ]*"([^"]*)".*/\1/' || true)
    if [[ -n "$ids" ]]; then
      printf "%s\n" "$ids" | sort | uniq -c | awk '{printf "  • %-40s %5d\n",$2,$1}'
    else
      say "  (no matches)"
    fi
  fi
else
  say "${YELLOW}${WARN} ast-grep not available; AST categories summarized via regex only.${RESET}"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 17; then
print_header "17. RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: context.With* without cancel, tickers/timers without Stop" \
  "Go resources must be explicitly cleaned up to avoid leaks"

run_resource_lifecycle_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 18: GO TOOLING (OPTIONAL)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 18; then
print_header "18. GO TOOLING (OPTIONAL)"
print_category "Detects: formatting drift, vet findings, known vulnerabilities (govulncheck)" \
  "This section runs only with --go-tools and if Go tools are available"
if [ "$RUN_GO_TOOLS" -eq 1 ] && command -v go >/dev/null 2>&1; then
  print_subheader "gofmt -s -l (unformatted files)"
  gofmt_out="$(
    ( set +o pipefail;
      find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name '*.go' -print0 \) 2>/dev/null \
        | xargs -0 gofmt -s -l 2>/dev/null || true
    )
  )"
  gf_count=$(printf "%s\n" "$gofmt_out" | sed '/^$/d' | wc -l | awk '{print $1+0}')
  if [ "$gf_count" -gt 0 ]; then
    print_finding "info" "$gf_count" "Files not gofmt -s clean"
    printf "%s\n" "$gofmt_out" | head -n "$DETAIL_LIMIT" | sed "s/^/${DIM}      /;s/$/${RESET}/"
  else
    print_finding "good" "All Go files are gofmt -s clean"
  fi

  print_subheader "go vet"
  out_vet="$( ( set +o pipefail; cd "$PROJECT_DIR" && go vet "$GOTEST_PKGS" 2>&1 || true ) )"
  vet_lines=$(printf "%s" "$out_vet" | sed '/^$/d' | wc -l | awk '{print $1+0}')
  if [ "$vet_lines" -gt 0 ]; then
    print_finding "warning" "$vet_lines" "go vet findings (review output)"
    printf "%s\n" "$out_vet" | head -n "$((DETAIL_LIMIT*3))" | sed "s/^/${DIM}      /;s/$/${RESET}/"
  else
    print_finding "good" "go vet reported no issues"
  fi

  print_subheader "govulncheck"
  if command -v govulncheck >/dev/null 2>&1; then
    gv_out="$( ( set +o pipefail; cd "$PROJECT_DIR" && govulncheck -format=text "$GOTEST_PKGS" 2>/dev/null || true ) )"
    gv_cnt=$(printf "%s" "$gv_out" | grep -E -c '^(Vulnerability|module:|package:|symbol:)')
    if [ "$gv_cnt" -gt 0 ]; then
      print_finding "warning" "$gv_cnt" "govulncheck reported potential vulnerabilities"
      printf "%s\n" "$gv_out" | head -n "$((DETAIL_LIMIT*4))" | sed "s/^/${DIM}      /;s/$/${RESET}/"
    else
      print_finding "good" "govulncheck did not report known vulnerabilities"
    fi
  else
    print_finding "info" 0 "govulncheck not installed"
  fi
else
  print_finding "info" 0 "Go tools disabled (use --go-tools) or Go not found"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: DEPENDENCY & BUILD DRIFT
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 19; then
print_header "19. DEPENDENCY & BUILD DRIFT"
print_category "Detects: multiple modules, inconsistent go directives" \
  "Prevents subtle build reproducibility problems"

if [ "$MODS_COUNT" -gt 1 ]; then
  print_subheader "Multiple modules detected"
  print_finding "info" "$MODS_COUNT" "Multiple go.mod; check for monorepo consistency"
fi

print_subheader "Inconsistent go directive versions across modules (heuristic)"
if [ "$MODS_COUNT" -gt 1 ]; then
  versions="$(
    while IFS= read -r mf; do
      [[ -z "$mf" ]] && continue
      gv=$(grep -E '^[[:space:]]*go[[:space:]]+[0-9]+\.[0-9]+' "$mf" 2>/dev/null | head -n1 | awk '{print $2}')
      printf "%s  %s\n" "${gv:-unknown}" "$mf"
    done <<<"$MOD_FILES"
  )"
  base_ver="$(printf "%s\n" "$versions" | head -n1 | awk '{print $1}')"
  diff_ver=$(printf "%s\n" "$versions" | awk -v b="$base_ver" '$1!=b{print}' | wc -l | awk '{print $1+0}')
  if [ "$diff_ver" -gt 0 ]; then
    print_finding "info" "$diff_ver" "Mixed module 'go' directives; align to a single baseline"
    printf "%s\n" "$versions" | head -n "$((DETAIL_LIMIT*2))" | sed "s/^/${DIM}      /;s/$/${RESET}/"
  else
    print_finding "good" "All modules share the same 'go' directive"
  fi
else
  print_finding "good" "Single module repository"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 20: NIL PANICS FROM DEFER ORDERING (AST)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 20; then
print_header "20. NIL PANICS FROM DEFER ORDERING (AST)"
print_category "Detects: defer Close() before err check for os.Open/http.Do/sql.Query results" \
  "These are real-world crashers: defer executes even when the resource is nil on error."

if [[ "$HAS_AST_GREP" -ne 1 || ! -f "$AST_JSON" ]]; then
  print_finding "info" 0 "ast-grep not available" "Enable ast-grep for defer-ordering crash checks"
else
  print_subheader "os.Open/OpenFile: defer f.Close() before err check"
  c=$(ast_count "go.defer-close-before-err-check")
  if [ "$c" -gt 0 ]; then print_finding "critical" "$c" "defer file.Close() before checking err"; else print_finding "good" "No obvious defer-before-err for os.Open/OpenFile"; fi

  print_subheader "HTTP: defer resp.Body.Close() before err check"
  c=$(ast_count "go.http.defer-body-before-err-check")
  if [ "$c" -gt 0 ]; then print_finding "critical" "$c" "defer resp.Body.Close() before checking err"; else print_finding "good" "No obvious defer-before-err for HTTP responses"; fi

  print_subheader "SQL: defer rows.Close() before err check"
  c=$(ast_count "go.sql.defer-rows-close-before-err-check")
  if [ "$c" -gt 0 ]; then print_finding "critical" "$c" "defer rows.Close() before checking err"; else print_finding "good" "No obvious defer-before-err for sql.Rows"; fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 21: DATABASE & SQL ROBUSTNESS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 21; then
print_header "21. DATABASE & SQL ROBUSTNESS"
print_category "Detects: rows.Err() not checked, Begin without deferred rollback, context-less queries" \
  "Database bugs hide in missing checks; this section prefers false positives to missed failures."

print_subheader "rows.Err() not checked after Next loop"
c=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.rows-err-not-checked" || echo 0)
if [ "$c" -gt 0 ]; then print_finding "info" "$c" "rows.Next loop without rows.Err() check"; fi

print_subheader "Tx begun without defer Rollback"
c=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.sql.begin-without-defer-rollback" || echo 0)
if [ "$c" -gt 0 ]; then print_finding "info" "$c" "Tx begun without deferred rollback"; fi

print_subheader "Context-less DB calls (regex heuristic)"
q_noctx=$(grep_count_scoped "\.(Query|Exec|QueryRow)\(")
q_ctx=$(grep_count_scoped "\.(QueryContext|ExecContext|QueryRowContext)\(")
if [ "$q_noctx" -gt 0 ] && [ "$q_ctx" -eq 0 ]; then
  print_finding "info" "$q_noctx" "DB calls without context; consider *Context variants"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 22: SHUTDOWN & RESOURCE RELEASE (HTTP/NET)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 22; then
print_header "22. SHUTDOWN & RESOURCE RELEASE (HTTP/NET)"
print_category "Detects: custom http.Client without CloseIdleConnections, missing server shutdown patterns" \
  "Long-running services need explicit shutdown paths to avoid leaked goroutines and sockets."

print_subheader "Custom http.Client without CloseIdleConnections (AST heuristic)"
c=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-client-close-idle-missing" || echo 0)
if [ "$c" -gt 0 ]; then print_finding "info" "$c" "Consider CloseIdleConnections() during shutdown"; fi

print_subheader "http.Server without Shutdown usage (regex heuristic)"
srv_new=$(grep_count_scoped "http\.Server\{")
srv_sd=$(grep_count_scoped "\.Shutdown\(")
if [ "$srv_new" -gt 0 ] && [ "$srv_sd" -eq 0 ]; then
  print_finding "info" "$srv_new" "http.Server constructed but no Shutdown() call seen; ensure graceful shutdown"
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
say "  ${WHITE}Version:${RESET}        ${CYAN}$VERSION${RESET}"
say "  ${WHITE}Files scanned:${RESET}  ${CYAN}$TOTAL_FILES${RESET}"
say "  ${WHITE}Go files:${RESET}       ${CYAN}$GO_FILES_COUNT${RESET}"
say "  ${WHITE}Test files:${RESET}     ${CYAN}$TEST_FILES_COUNT${RESET}"
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
say "${DIM}Scan completed at: $(now)${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

# Baseline compare / creation (text mode only)
if [[ -n "$BASELINE_FILE" && "$FORMAT" == "text" ]]; then
  if [[ -f "$BASELINE_FILE" ]]; then
    base_crit=0; base_warn=0; base_info=0
    if command -v python3 >/dev/null 2>&1; then
      read -r base_crit base_warn base_info < <(python3 - "$BASELINE_FILE" <<'PY'
import re, sys
txt = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
def grab(label):
    m = re.search(rf"{re.escape(label)}\s*([0-9]+)", txt)
    return int(m.group(1)) if m else 0
crit = grab("Critical issues:")
warn = grab("Warning issues:")
info = grab("Info items:")
print(crit, warn, info)
PY
)
    else
      base_crit=$(grep -E "Critical issues:" "$BASELINE_FILE" | head -n1 | grep -oE '[0-9]+' | head -n1 | awk '{print $1+0}')
      base_warn=$(grep -E "Warning issues:" "$BASELINE_FILE" | head -n1 | grep -oE '[0-9]+' | head -n1 | awk '{print $1+0}')
      base_info=$(grep -E "Info items:" "$BASELINE_FILE" | head -n1 | grep -oE '[0-9]+' | head -n1 | awk '{print $1+0}')
    fi
    dcrit=$((CRITICAL_COUNT - base_crit))
    dwarn=$((WARNING_COUNT - base_warn))
    dinfo=$((INFO_COUNT - base_info))
    say ""
    say "${BOLD}${WHITE}Baseline Comparison:${RESET} ${DIM}(${BASELINE_FILE})${RESET}"
    if [[ "$dcrit" -gt 0 || "$dwarn" -gt 0 ]]; then
      say "  ${YELLOW}${WARN} Findings increased vs baseline:"
      [[ "$dcrit" -ne 0 ]] && say "    ${RED}Critical delta:${RESET} ${dcrit}"
      [[ "$dwarn" -ne 0 ]] && say "    ${YELLOW}Warning delta:${RESET}  ${dwarn}"
      [[ "$dinfo" -ne 0 ]] && say "    ${BLUE}Info delta:${RESET}     ${dinfo}"
    else
      say "  ${GREEN}${CHECK} No increase in critical/warning findings vs baseline"
    fi
  else
    # Create baseline if possible (requires baseline capture)
    if [[ -n "${BASELINE_TMP:-}" && -f "${BASELINE_TMP:-}" ]]; then
      cp -f "$BASELINE_TMP" "$BASELINE_FILE" 2>/dev/null || true
      say ""
      say "${GREEN}${CHECK} Baseline created: ${CYAN}$BASELINE_FILE${RESET}"
    else
      say ""
      say "${BLUE}${INFO} Baseline file not found and could not be created (no capture).${RESET}"
    fi
  fi
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs-golang.sh --ci --fail-on-warning . > go-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi

exit "$EXIT_CODE"
