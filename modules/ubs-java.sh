#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# JAVA ULTIMATE BUG SCANNER v1.2 - Industrial-Grade Java 21+ Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for Java using ast-grep + semantic patterns
# + build-tool checks (Maven/Gradle), formatting/lint integrations (optional)
# Focus: Null/Optional pitfalls, equals/hashCode, concurrency/async, security,
# I/O/resources, performance, regex/strings, serialization, code quality.
#
# Enhancements in v1.2:
#   - Safer date handling (no eval), robust file counting with proper -prune
#   - New flags: --no-emoji, --min-severity, --sarif-out, --json-out
#   - Output filtering by severity for text format
#   - Stronger AST rules (plain HTTP, ReDoS, Closeable without TWR, Optional negation)
#   - Consolidated duplicate findings; fixed stray detection outside category
#   - Better CI/TUI handling and IFS hygiene
#
# Features:
#   - Colorful, CI-friendly TTY output with NO_COLOR support and optional NO_EMOJI
#   - Robust find/rg search with include/exclude globs
#   - Heuristics + AST rule packs (Java) written on-the-fly
#   - JSON/SARIF passthrough & optional files from ast-grep rule scans
#   - Category skip/selection, verbosity, sample snippets
#   - Parallel jobs for ripgrep
#   - Exit on critical or optionally on warnings
#   - Optional Maven/Gradle compile + lint task runners (best-effort)
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob
set -o errtrace

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure predictable IFS for loops (restored on exit)
ORIG_IFS=${IFS}
IFS=$' \t\n'

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
NO_EMOJI=${NO_EMOJI:-0}

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
  BOLD=''; DIM=''; RESET=''
fi

if [[ "${NO_EMOJI}" -eq 1 ]]; then
  CHECK="OK"; CROSS="X"; WARN="WARN"; INFO="INFO"; ARROW="->"; BULLET="*"; MAGNIFY="[sg]"; BUG="[bug]"; FIRE="CRIT"; SPARKLE=""; SHIELD="[sec]"; WRENCH="[fix]"; ROCKET="[run]"
else
  CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; WRENCH="🛠"; ROCKET="🚀"
fi

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
ONLY_CATEGORIES=""
DETAIL_LIMIT_OVERRIDE=""
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="java,kt,kts"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1
SARIF_OUT=""
JSON_OUT=""
MIN_SEVERITY="info"     # info|warning|critical

RUN_BUILD=1
JAVA_REQUIRED_MAJOR=21
JAVA_VERSION_STR=""
JAVA_MAJOR=0

# Async error coverage metadata
ASYNC_ERROR_RULE_IDS=(java.async.future-get-no-try java.async.then-no-exceptionally)
declare -A ASYNC_ERROR_SUMMARY=(
  [java.async.future-get-no-try]='CompletableFuture get()/join() without try/catch'
  [java.async.then-no-exceptionally]='CompletableFuture chains missing exceptionally()/handle()'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [java.async.future-get-no-try]='Wrap blocking future.get()/join() calls in try/catch to handle ExecutionException'
  [java.async.then-no-exceptionally]='Attach .exceptionally(...) or .handle(...) to promise chains to surface errors'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [java.async.future-get-no-try]='warning'
  [java.async.then-no-exceptionally]='warning'
)

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose              More code samples per finding (DETAIL=10)
  -q, --quiet                Reduce non-essential output
  --format=FMT               Output format: text|json|sarif (default: text)
  --ci                       CI mode (stable timestamps, no screen clear)
  --no-color                 Force disable ANSI color
  --no-emoji                 Disable emoji/pictograms in output
  --only=CSV                 Run only these categories (numbers), e.g. --only=1,4,16
  --detail=N                 Show up to N code samples per finding (overrides -v/-q)
  --include-ext=CSV          File extensions (default: java)
  --exclude=GLOB[,..]        Additional glob(s)/dir(s) to exclude
  --jobs=N                   Parallel jobs for ripgrep (default: auto)
  --skip=CSV                 Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning          Exit non-zero on warnings or critical
  --rules=DIR                Additional ast-grep rules directory (merged)
  --no-build                 Skip Maven/Gradle compile/lint tasks
  --sarif-out=FILE           Save ast-grep SARIF to FILE (independent of --format)
  --json-out=FILE            Save ast-grep JSON stream to FILE (independent of --format)
  --min-severity=LEVEL       Filter text output: info|warning|critical (default: info)
  -h, --help                 Show help

Env:
  JOBS, NO_COLOR, NO_EMOJI, CI, UBS_CATEGORY_FILTER

Args:
  PROJECT_DIR                Directory to scan (default: ".")
  OUTPUT_FILE                File to save the report (optional)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-emoji)   NO_EMOJI=1; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --detail=*)   DETAIL_LIMIT_OVERRIDE="${1#*=}"; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --no-build)   RUN_BUILD=0; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --json-out=*)  JSON_OUT="${1#*=}"; shift;;
    --min-severity=*) MIN_SEVERITY="${1#*=}"; shift;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ "$PROJECT_DIR" == "." && ! "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" && ! "$1" =~ ^- ]]; then
        OUTPUT_FILE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi;;
  esac
done

if [[ "${UBS_CATEGORY_FILTER:-}" == "resource-lifecycle" ]]; then
  if [[ -z "$ONLY_CATEGORIES" ]]; then
    ONLY_CATEGORIES="5,19"
  fi
fi
if [[ -n "$DETAIL_LIMIT_OVERRIDE" ]]; then DETAIL_LIMIT="$DETAIL_LIMIT_OVERRIDE"; fi
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

# Stable timestamp function (no eval)
DATE_FMT='%Y-%m-%d %H:%M:%S'
now() { if [[ "$CI_MODE" -eq 1 ]]; then date -u '+%Y-%m-%dT%H:%M:%SZ'; else date "+${DATE_FMT}"; fi; }

# ────────────────────────────────────────────────────────────────────────────
# Global counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0
HAS_KOTLIN_FILES=0
HAS_SWIFT_FILES=0

# ────────────────────────────────────────────────────────────────────────────
# Global state
# ────────────────────────────────────────────────────────────────────────────
HAS_AST_GREP=0
AST_GREP_CMD=()
AST_RULE_DIR=""
AST_RULE_RESULTS_JSON=""
HAS_RG=0

HAS_JAVA=0
HAS_MAVEN=0
HAS_GRADLE=0
GRADLEW=""
MVNW=""
JAVA_TOOLCHAIN_OK=0
START_TS=""
END_TS=""
START_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%s')"

# Resource lifecycle correlation spec (AST + regex fallback)
RESOURCE_LIFECYCLE_RULE_IDS=(
  java.resource.executor-no-shutdown
  java.resource.thread-no-join
  java.resource.jdbc-no-close
  java.resource.resultset-no-close
  java.resource.statement-no-close
)
declare -A RESOURCE_LIFECYCLE_RULE_SEVERITY=(
  [java.resource.executor-no-shutdown]="critical"
  [java.resource.thread-no-join]="warning"
  [java.resource.jdbc-no-close]="warning"
  [java.resource.resultset-no-close]="warning"
  [java.resource.statement-no-close]="warning"
)
declare -A RESOURCE_LIFECYCLE_RULE_SUMMARY=(
  [java.resource.executor-no-shutdown]='ExecutorService created without shutdown'
  [java.resource.thread-no-join]='Thread started without join()'
  [java.resource.jdbc-no-close]='JDBC connection acquired without close()'
  [java.resource.resultset-no-close]='ResultSet not closed after use'
  [java.resource.statement-no-close]='Statement/Prepared/CallableStatement not closed after use'
)
declare -A RESOURCE_LIFECYCLE_RULE_REMEDIATION=(
  [java.resource.executor-no-shutdown]='Store the ExecutorService and call shutdown()/shutdownNow() in finally blocks'
  [java.resource.thread-no-join]='Join threads or use executors to avoid orphaned workers'
  [java.resource.jdbc-no-close]='Use try-with-resources or explicitly close java.sql.Connection objects'
  [java.resource.resultset-no-close]='Close java.sql.ResultSet objects or wrap them in try-with-resources'
  [java.resource.statement-no-close]='Close Statement/PreparedStatement handles or wrap them in try-with-resources'
)

RESOURCE_LIFECYCLE_REGEX_IDS=(executor_shutdown thread_join jdbc_close)
declare -A RESOURCE_LIFECYCLE_REGEX_SEVERITY=(
  [executor_shutdown]="critical"
  [thread_join]="warning"
  [jdbc_close]="warning"
)
declare -A RESOURCE_LIFECYCLE_REGEX_ACQUIRE=(
  [executor_shutdown]='Executors?\.[A-Za-z_]+\('
  [thread_join]='new[[:space:]]+Thread\('
  [jdbc_close]='(DriverManager|DataSource)\.getConnection\('
)
declare -A RESOURCE_LIFECYCLE_REGEX_RELEASE=(
  [executor_shutdown]='\.shutdown(Now)?\('
  [thread_join]='\.join\('
  [jdbc_close]='\.close\(|try[[:space:]]*\([^)]*Connection[[:space:]]+[A-Za-z_][A-Za-z0-9_]*'
)
declare -A RESOURCE_LIFECYCLE_REGEX_SUMMARY=(
  [executor_shutdown]='ExecutorService created without shutdown'
  [thread_join]='Thread started without join()'
  [jdbc_close]='JDBC connection acquired without close()'
)
declare -A RESOURCE_LIFECYCLE_REGEX_REMEDIATION=(
  [executor_shutdown]='Store the ExecutorService and call shutdown()/shutdownNow() in finally blocks'
  [thread_join]='Join threads or use executors to avoid orphaned workers'
  [jdbc_close]='Use try-with-resources or explicitly close connections'
)

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep)
# ────────────────────────────────────────────────────────────────────────────
LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done

EXCLUDE_DIRS=(target build out .gradle .idea .vscode .git .settings .mvn .generated node_modules dist coverage .cache .hg .svn .DS_Store .tox .venv .pnpm-store .yarn .yarn/cache)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
  HAS_RG=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden --colors=never "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=()
  for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  GREP_RN=(rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNI=(rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNW=(rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
else
  GREP_R_OPTS=(-R --binary-files=without-match --line-number "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("grep" "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("grep" "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("grep" "${GREP_R_OPTS[@]}" -n -w -E)
fi

count_lines() { awk 'END{print (NR+0)}'; }
severity_allows() {
  declare -A rank=( [info]=1 [warning]=2 [critical]=3 )
  local s="$1"; local want="${MIN_SEVERITY}"
  [[ ${rank[$s]:-0} -ge ${rank[$want]:-1} ]]
}

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
          if severity_allows "critical"; then
            say "  ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"
            say "    ${RED}${BOLD}$title${RESET}"
            [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          fi
          ;;
        warning)
          WARNING_COUNT=$((WARNING_COUNT + count))
          if severity_allows "warning"; then
            say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"
            say "    ${YELLOW}$title${RESET}"
            [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          fi
          ;;
        info)
          INFO_COUNT=$((INFO_COUNT + count))
          if severity_allows "info"; then
            say "  ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"
            say "    ${BLUE}$title${RESET}"
            [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true
          fi
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
    [[ -z "$file" || -z "$line" ]] && continue
    print_code_sample "$file" "$line" "$code"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done < <("${GREP_RN[@]}" -e "$pattern" "$PROJECT_DIR" 2>/dev/null | head -n "$limit" || true) || true
}

run_resource_lifecycle_checks() {
  print_subheader "Resource lifecycle correlation"
  if emit_ast_rule_group RESOURCE_LIFECYCLE_RULE_IDS RESOURCE_LIFECYCLE_RULE_SEVERITY RESOURCE_LIFECYCLE_RULE_SUMMARY RESOURCE_LIFECYCLE_RULE_REMEDIATION \
    "All tracked resource acquisitions have matching cleanups" "Resource lifecycle checks"; then
    return
  fi

  local emitted=0
  mapfile -t exec_meta < <(java_pattern_scan executor_leak)
  local exec_count="${exec_meta[0]:-0}"
  local exec_samples="${exec_meta[1]:-}"
  if [ "${exec_count:-0}" -gt 0 ]; then
    emitted=1
    local desc="Call shutdown()/shutdownNow() on ExecutorService instances"
    if [ -n "$exec_samples" ]; then
      desc+=" (e.g., ${exec_samples%%,*})"
    fi
    print_finding "warning" "$exec_count" "ExecutorService created without shutdown" "$desc"
  fi

  mapfile -t stream_meta < <(java_pattern_scan stream_leak)
  local stream_count="${stream_meta[0]:-0}"
  local stream_samples="${stream_meta[1]:-}"
  if [ "${stream_count:-0}" -gt 0 ]; then
    emitted=1
    local desc="Wrap FileInputStream/FileOutputStream in try-with-resources or call close()"
    if [ -n "$stream_samples" ]; then
      desc+=" (e.g., ${stream_samples%%,*})"
    fi
    print_finding "warning" "$stream_count" "File streams opened without close()" "$desc"
  fi

  local jdbc_helper="$SCRIPT_DIR/helpers/resource_lifecycle_java.py"
  if [[ -f "$jdbc_helper" ]] && command -v python3 >/dev/null 2>&1; then
    local helper_output
    if helper_output="$(python3 "$jdbc_helper" "$PROJECT_DIR" 2>/dev/null)" && [[ -n "$helper_output" ]]; then
      local stmt_count=0 rs_count=0
      local -a stmt_samples=()
      local -a rs_samples=()
      while IFS=$'\t' read -r location kind _; do
        [[ -z "$location" || -z "$kind" ]] && continue
        case "$kind" in
          statement_handle)
            stmt_count=$((stmt_count+1))
            [[ ${#stmt_samples[@]} -lt 3 ]] && stmt_samples+=("$location")
            ;;
          resultset_handle)
            rs_count=$((rs_count+1))
            [[ ${#rs_samples[@]} -lt 3 ]] && rs_samples+=("$location")
            ;;
        esac
      done <<<"$helper_output"
      if [ "$stmt_count" -gt 0 ]; then
        emitted=1
        local desc="Use try-with-resources and ensure Statement/Prepared/CallableStatement handles call close()"
        if [ "${#stmt_samples[@]}" -gt 0 ]; then
          desc+=" (e.g., ${stmt_samples[0]})"
        fi
        print_finding "warning" "$stmt_count" "Statement/Prepared/CallableStatement not closed after use" "$desc"
      fi
      if [ "$rs_count" -gt 0 ]; then
        emitted=1
        local desc="Close ResultSet handles or wrap the query in try-with-resources"
        if [ "${#rs_samples[@]}" -gt 0 ]; then
          desc+=" (e.g., ${rs_samples[0]})"
        fi
        print_finding "warning" "$rs_count" "ResultSet not closed after use" "$desc"
      fi
    fi
  fi

  if [ "$emitted" -eq 0 ]; then
    print_finding "good" "All tracked resource acquisitions have matching cleanups"
  fi
}

java_pattern_scan() {
  local mode="$1"
  python3 - "$PROJECT_DIR" "$mode" <<'PY'
import re, sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
base = root if root.is_dir() else root.parent
exts = ('.java', '.kt')
if root.is_file():
    candidates = [root] if root.suffix.lower() in exts else []
else:
    candidates = []
    for ext in exts:
        candidates.extend(base.rglob(f'*{ext}'))

def relpath(path):
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)

def read_lines(path):
    try:
        return path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return []

def search_line(pattern):
    count = 0
    samples = []
    for path in candidates:
        lines = read_lines(path)
        if not lines:
            continue
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                count += 1
                if len(samples) < 3:
                    samples.append(f"{relpath(path)}:{idx}")
    return count, samples

if mode == "runtime_exec":
    pat = re.compile(r"Runtime\.getRuntime\(\)\.exec")
    count, samples = search_line(pat)
elif mode == "sql_concat":
    pat = re.compile(r"\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*\"[ \t]*\+")
    count, samples = search_line(pat)
elif mode == "executor_leak":
    pat = re.compile(r"Executors\.(?:new[A-Za-z]+)\s*\(|new\s+ThreadPoolExecutor\s*\(")
    shutdown_pat = re.compile(r"\.shutdown(?:Now)?\s*\(")
    count = 0
    samples = []
    for path in candidates:
        lines = read_lines(path)
        if not lines:
            continue
        text = "\n".join(lines)
        if not pat.search(text):
            continue
        if shutdown_pat.search(text):
            continue
        count += 1
        if len(samples) < 3:
            for idx, line in enumerate(lines, start=1):
                if pat.search(line):
                    samples.append(f"{relpath(path)}:{idx}")
                    break
elif mode == "stream_leak":
    pat = re.compile(r"new\s+File(?:Input|Output)Stream\s*\(")
    close_pat = re.compile(r"\.close\s*\(")
    count = 0
    samples = []
    for path in candidates:
        lines = read_lines(path)
        if not lines:
            continue
        text = "\n".join(lines)
        if not pat.search(text):
            continue
        if close_pat.search(text):
            continue
        matches = pat.findall(text)
        count += len(matches) or 1
        if len(samples) < 3:
            for idx, line in enumerate(lines, start=1):
                if pat.search(line):
                    samples.append(f"{relpath(path)}:{idx}")
                    break
else:
    count = 0
    samples = []

print(count)
print(",".join(samples))
PY
}

run_kotlin_type_narrowing_checks() {
  if [[ "$HAS_KOTLIN_FILES" -ne 1 ]]; then
    return 0
  fi
  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]]; then
    print_finding "info" 0 "Kotlin type narrowing checks skipped" "Set UBS_SKIP_TYPE_NARROWING=0 or remove --skip-type-narrowing to re-enable"
    return 0
  fi
  local script_dir helper
  script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  helper="$script_dir/helpers/type_narrowing_kotlin.py"
  if [[ ! -f "$helper" ]]; then
    print_finding "info" 0 "Kotlin type narrowing helper missing" "$helper not found"
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 unavailable for Kotlin helper" "Install python3 to enable Kotlin guard analysis"
    return 0
  fi
  local output status
  output="$(python3 "$helper" "$PROJECT_DIR" 2>&1)"
  status=$?
  if [[ $status -ne 0 ]]; then
    print_finding "info" 0 "Kotlin type narrowing helper failed" "$output"
    return 0
  fi
  if [[ -z "$output" ]]; then
    print_finding "good" "No Kotlin guard clauses missing exits"
    return 0
  fi
  local count=0
  local previews=()
  while IFS=$'\t' read -r location message; do
    [[ -z "$location" ]] && continue
    count=$((count + 1))
    if [[ ${#previews[@]} -lt 3 ]]; then
      previews+=("$location → $message")
    fi
  done <<< "$output"
  local desc="Examples: ${previews[*]}"
  if [[ $count -gt ${#previews[@]} ]]; then
    desc+=" (and $((count - ${#previews[@]})) more)"
  fi
  print_finding "warning" "$count" "Kotlin guard without exit before '!!'" "$desc"
}

run_swift_type_narrowing_checks() {
  if [[ "$HAS_SWIFT_FILES" -ne 1 ]]; then
    return 0
  fi
  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]]; then
    print_finding "info" 0 "Swift type narrowing checks skipped" "Set UBS_SKIP_TYPE_NARROWING=0 or remove --skip-type-narrowing to re-enable"
    return 0
  fi
  local script_dir helper
  script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  helper="$script_dir/helpers/type_narrowing_swift.py"
  if [[ ! -f "$helper" ]]; then
    print_finding "info" 0 "Swift type narrowing helper missing" "$helper not found"
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 unavailable for Swift helper" "Install python3 to enable Swift guard analysis"
    return 0
  fi
  local output status
  output="$(python3 "$helper" "$PROJECT_DIR" 2>&1)"
  status=$?
  if [[ $status -ne 0 ]]; then
    print_finding "info" 0 "Swift type narrowing helper failed" "$output"
    return 0
  fi
  if [[ -z "$output" ]]; then
    print_finding "good" "Swift guard clauses appear to exit safely"
    return 0
  fi
  local count=0
  local previews=()
  while IFS=$'\t' read -r location message; do
    [[ -z "$location" ]] && continue
    count=$((count + 1))
    if [[ ${#previews[@]} -lt 3 ]]; then
      previews+=("$location → $message")
    fi
  done <<< "$output"
  local desc="Examples: ${previews[*]}"
  if [[ $count -gt ${#previews[@]} ]]; then
    desc+=" (and $((count - ${#previews[@]})) more)"
  fi
  print_finding "warning" "$count" "Swift guard let else-block may continue" "$desc"
}

run_async_error_checks() {
  print_subheader "Async error path coverage"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
    # Fallback: use grep to detect unguarded async patterns
    if [[ "$FAIL_ON_WARNING" -eq 0 ]]; then
      print_finding "info" 0 "Async fallback disabled" "Run with --fail-on-warning to check async patterns when ast-grep is unavailable"
      return
    fi
    local get_count then_count tmp_get tmp_then
    # Check for .get() calls which may block without proper try/catch
    tmp_get=$("${GREP_RN[@]}" -e '\.get\s*\(\s*\)' "$PROJECT_DIR" || true)
    get_count=$(echo "$tmp_get" | count_lines)
    # Check for .then* calls without .exceptionally()
    tmp_then=$("${GREP_RN[@]}" -e '\.(thenApply|thenCompose|thenAccept|thenRun)\s*\(' "$PROJECT_DIR" || true)
    tmp_then=$(echo "$tmp_then" | grep -v 'exceptionally' || true)
    then_count=$(echo "$tmp_then" | count_lines)
    if [ "$get_count" -gt 0 ]; then
      print_finding "warning" "$get_count" "CompletableFuture.get() calls" "Wrap .get() calls in try/catch or use CompletableFuture chaining"
    fi
    if [ "$then_count" -gt 0 ]; then
      print_finding "warning" "$then_count" "CompletableFuture chains without error handling" "Add .exceptionally() or .handle() to chains"
    fi
    if [ "$get_count" -eq 0 ] && [ "$then_count" -eq 0 ]; then
      print_finding "good" "CompletableFuture usage appears guarded"
    fi
    return
  fi
  local rule_dir tmp_json
  rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t java_async_rules.XXXXXX)"
  if [[ ! -d "$rule_dir" ]]; then
    print_finding "info" 0 "temp dir creation failed" "Unable to stage ast-grep rules"
    return
  fi
  cat >"$rule_dir/java.async.future-get-no-try.yml" <<'YAML'
id: java.async.future-get-no-try
language: java
rule:
  pattern: $F.get()
  not:
    inside:
      kind: try_statement
YAML

  cat >"$rule_dir/java.async.then-no-exceptionally.yml" <<'YAML'
id: java.async.then-no-exceptionally
language: java
rule:
  any:
    - pattern: $CF.thenApply($ARG)
    - pattern: $CF.thenCompose($ARG)
    - pattern: $CF.thenAccept($ARG)
  not:
    inside:
      pattern: $CF.exceptionally($HANDLER)
YAML
  tmp_json="$(mktemp 2>/dev/null || mktemp -t java_async_matches.XXXXXX)"
  : >"$tmp_json"
  local rule_file
  for rule_file in "$rule_dir"/*.yml; do
    if ! "${AST_GREP_CMD[@]}" scan -r "$rule_file" "$PROJECT_DIR" --json=stream >>"$tmp_json" 2>/dev/null; then
      rm -rf "$rule_dir"; rm -f "$tmp_json"
      print_finding "info" 0 "ast-grep scan failed" "Unable to compute async error coverage"
      return
    fi
  done
  rm -rf "$rule_dir"
  if ! [[ -s "$tmp_json" ]]; then
    rm -f "$tmp_json"
    print_finding "good" "CompletableFuture usage appears guarded"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r rid count samples; do
    [[ -z "$rid" ]] && continue
    printed=1
    local severity=${ASYNC_ERROR_SEVERITY[$rid]:-warning}
    local summary=${ASYNC_ERROR_SUMMARY[$rid]:-$rid}
    local desc=${ASYNC_ERROR_REMEDIATION[$rid]:-"Handle async exceptions"}
    if [[ -n "$samples" ]]; then desc+=" (e.g., $samples)"; fi
    print_finding "$severity" "$count" "$summary" "$desc"
  done < <(python3 - "$tmp_json" <<'PY'
import json, sys
from collections import OrderedDict
path = sys.argv[1]
stats = OrderedDict()
with open(path, 'r', encoding='utf-8') as fh:
    for line in fh:
        line=line.strip()
        if not line: continue
        try:
            obj=json.loads(line)
        except json.JSONDecodeError:
            continue
        rid=(obj.get('rule_id') or obj.get('id') or obj.get('ruleId'))
        if not rid: continue
        rng=obj.get('range') or {}
        start=rng.get('start') or {}
        line_no=(start.get('row', 0) + 1)
        file_path=obj.get('file','?')
        entry=stats.setdefault(rid, {'count':0,'samples':[]})
        entry['count']+=1
        if len(entry['samples'])<3:
            entry['samples'].append(f"{file_path}:{line_no}")
for rid,data in stats.items():
    print(f"{rid}\t{data['count']}\t{','.join(data['samples'])}")
PY
)
  rm -f "$tmp_json"
  if [[ $printed -eq 0 ]]; then
    print_finding "good" "CompletableFuture usage appears guarded"
  fi
}

show_ast_examples() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    while IFS=: read -r file line col rest; do
      local code=""
      if [[ -f "$file" && -n "$line" ]]; then code="$(sed -n "${line}p" "$file" | sed $'s/\t/  /g')"; fi
      print_code_sample "$file" "$line" "${code:-$rest}"
      printed=$((printed+1)); [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
    done < <( ( set +o pipefail; "${AST_GREP_CMD[@]}" --lang java --pattern "$pattern" -n "$PROJECT_DIR" 2>/dev/null || true ) | head -n "$limit" )
  fi
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

# ────────────────────────────────────────────────────────────────────────────
# Tool detection
# ────────────────────────────────────────────────────────────────────────────
check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; return 0; fi
  # Verify 'sg' is actually ast-grep, not the Unix newgrp command
  if command -v sg >/dev/null 2>&1 && sg --version 2>&1 | grep -qi "ast-grep"; then
    AST_GREP_CMD=(sg); HAS_AST_GREP=1; return 0
  fi
  # Skip npx in CI environments where download might fail/timeout
  if [[ -z "${CI:-}" ]] && command -v npx >/dev/null 2>&1 && npx -y @ast-grep/cli --version >/dev/null 2>&1; then
    AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; return 0
  fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be limited.${RESET}"
  say "${DIM}Tip: cargo install ast-grep  or  npm i -g @ast-grep/cli${RESET}"
  HAS_AST_GREP=0; return 1
}

check_java_env() {
  if command -v java >/dev/null 2>&1; then
    HAS_JAVA=1
    # java may exist but still return non-zero (e.g., stub prompting install); avoid killing the scan
    JAVA_VERSION_STR="$(java -version 2>&1 | head -n1 || true)"
  fi
  local javac_str; javac_str="$(javac -version 2>&1 || true)"
  if [[ -z "$JAVA_VERSION_STR" && -n "$javac_str" ]]; then JAVA_VERSION_STR="$javac_str"; fi
  local ver
  ver="$( (echo "$JAVA_VERSION_STR" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo '') )"
  if [[ -z "$ver" ]]; then ver="$(echo "$JAVA_VERSION_STR" | grep -oE '[0-9]+' | head -n1 || true)"; fi
  JAVA_MAJOR="$(echo "$ver" | awk -F. '{print ($1+0)}')"
  if [[ "$JAVA_MAJOR" -ge "$JAVA_REQUIRED_MAJOR" ]]; then JAVA_TOOLCHAIN_OK=1; fi

  [[ -f "$PROJECT_DIR/mvnw" && -x "$PROJECT_DIR/mvnw" ]] && MVNW="$PROJECT_DIR/mvnw"
  [[ -f "$PROJECT_DIR/gradlew" && -x "$PROJECT_DIR/gradlew" ]] && GRADLEW="$PROJECT_DIR/gradlew"
  if command -v mvn >/dev/null 2>&1 || [[ -n "$MVNW" ]]; then HAS_MAVEN=1; fi
  if command -v gradle >/dev/null 2>&1 || [[ -n "$GRADLEW" ]]; then HAS_GRADLE=1; fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep helpers
# ────────────────────────────────────────────────────────────────────────────
ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --lang java --pattern "$pattern" "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # ====== General panic-prone / debug ======
  cat >"$AST_RULE_DIR/printStackTrace.yml" <<'YAML'
id: java.print-stacktrace
language: java
rule:
  pattern: $E.printStackTrace()
severity: warning
message: "printStackTrace() leaks sensitive details; use a logger"
YAML

  cat >"$AST_RULE_DIR/println.yml" <<'YAML'
id: java.system-println
language: java
rule:
  any:
    - pattern: System.out.println($$)
    - pattern: System.err.println($$)
severity: info
message: "System.out/err.println detected; prefer structured logging"
YAML

  # ====== Optional refinements ======
  cat >"$AST_RULE_DIR/optional-isPresent-then-get.yml" <<'YAML'
id: java.optional-isPresent-then-get
language: java
rule:
  pattern: |
    if ($O.isPresent()) {
      $$ $O.get() $$
    }
severity: info
message: "Optional.isPresent() followed by get(); prefer ifPresent/map/orElseThrow"
YAML

  cat >"$AST_RULE_DIR/optional-orElse-null.yml" <<'YAML'
id: java.optional-orElse-null
language: java
rule:
  pattern: $O.orElse(null)
severity: info
message: "Optional.orElse(null) reintroduces null; reconsider design"
YAML

  # New: not-preferred !isEmpty()
  cat >"$AST_RULE_DIR/optional-isEmpty-negation.yml" <<'YAML'
id: java.optional-isempty-negation
language: java
rule:
  pattern: if (!$O.isEmpty()) { $$ }
severity: info
message: "Prefer isPresent() to !isEmpty() for clarity or use ifPresent(...)"
YAML

  # ====== Logging best practices ======
  cat >"$AST_RULE_DIR/logging-concat.yml" <<'YAML'
id: java.logging-concat
language: java
rule:
  any:
    - pattern: $L.debug($A + $B, $$)
    - pattern: $L.info($A + $B, $$)
    - pattern: $L.warn($A + $B, $$)
    - pattern: $L.error($A + $B, $$)
    - pattern: $L.debug($A + $B)
    - pattern: $L.info($A + $B)
    - pattern: $L.warn($A + $B)
    - pattern: $L.error($A + $B)
severity: info
message: "String concatenation in logging; prefer parameterized logging"
YAML

  # ====== Path building ======
  cat >"$AST_RULE_DIR/paths-get-plus.yml" <<'YAML'
id: java.paths-get-plus
language: java
rule:
  any:
    - pattern: java.nio.file.Paths.get($A + $B)
    - pattern: java.nio.file.Paths.get($A, $B + $C)
severity: info
message: "Paths.get with '+' concatenation; prefer resolve() or multiple args"
YAML

  # ====== Secrets heuristics (basic) ======
  cat >"$AST_RULE_DIR/hardcoded-secrets.yml" <<'YAML'
id: java.hardcoded-secrets
language: java
rule:
  pattern: String $K = $V;
  constraints:
    K:
      regex: (?i).*(password|passwd|pwd|secret|token|api[-_]?key|auth|credential).*
    V:
      kind: string_literal
severity: warning
message: "Hardcoded secret-like identifier"
YAML

  # ====== Optional / Null ======
  cat >"$AST_RULE_DIR/optional-get.yml" <<'YAML'
id: java.optional-get
language: java
rule:
  pattern: $O.get()
severity: warning
message: "Optional.get() may throw NoSuchElementException; prefer orElse, orElseThrow, or ifPresent"
YAML

  # ====== Equality / Collections ======
  cat >"$AST_RULE_DIR/string-eq-operator.yml" <<'YAML'
id: java.string-eq-operator
language: java
rule:
  any:
    - pattern: $X == $Y
      constraints:
        X:
          kind: string_literal
    - pattern: $X == $Y
      constraints:
        Y:
          kind: string_literal
severity: warning
message: "String compared with '=='; use equals()/Objects.equals()"
YAML

  cat >"$AST_RULE_DIR/bigdecimal-equals.yml" <<'YAML'
id: java.bigdecimal-equals
language: java
rule:
  pattern: $BD.equals($OTHER)
  inside:
    pattern: BigDecimal $BD_NAME = $BD_EXPR;
severity: info
message: "BigDecimal.equals checks scale; prefer compareTo() == 0 for numeric equality"
YAML

  # ====== Concurrency ======
  cat >"$AST_RULE_DIR/synchronized-this.yml" <<'YAML'
id: java.synchronized-this
language: java
rule:
  pattern: synchronized(this) { $$ }
severity: info
message: "synchronized(this) exposes lock to external code; prefer private lock"
YAML

  cat >"$AST_RULE_DIR/thread-start.yml" <<'YAML'
id: java.thread-start
language: java
rule:
  pattern: new Thread($$).start()
severity: info
message: "Manual Thread management; consider executors or virtual threads in Java 21+"
YAML

  cat >"$AST_RULE_DIR/executors-cached.yml" <<'YAML'
id: java.executors-cached
language: java
rule:
  pattern: java.util.concurrent.Executors.newCachedThreadPool($$)
severity: warning
message: "newCachedThreadPool has unbounded threads; ensure backpressure"
YAML

  cat >"$AST_RULE_DIR/java-resource-executor.yml" <<'YAML'
id: java.resource.executor-no-shutdown
language: java
rule:
  pattern: java.util.concurrent.ExecutorService $EXEC = java.util.concurrent.Executors.$FACTORY($ARGS);
  not:
    inside:
      pattern: $EXEC.shutdown()
  not:
    inside:
      pattern: $EXEC.shutdownNow()
severity: warning
message: "ExecutorService created without shutdown()/shutdownNow() in the same scope."
YAML

  cat >"$AST_RULE_DIR/java-resource-thread.yml" <<'YAML'
id: java.resource.thread-no-join
language: java
rule:
  pattern: |
    Thread $T = new Thread($ARGS);
    $T.start();
  not:
    inside:
      pattern: $T.join($$)
severity: warning
message: "Thread started without a matching join(); join threads or await termination."
YAML

  cat >"$AST_RULE_DIR/java-resource-jdbc.yml" <<'YAML'
id: java.resource.jdbc-no-close
language: java
rule:
  pattern: java.sql.Connection $C = java.sql.DriverManager.getConnection($$);
  not:
    inside:
      pattern: $C.close()
  not:
    inside:
      kind: try_with_resources_statement
severity: warning
message: "JDBC Connection acquired without close(); wrap in try-with-resources or close in finally."
YAML


  cat >"$AST_RULE_DIR/thread-sleep-in-sync.yml" <<'YAML'
id: java.thread-sleep-in-synchronized
language: java
rule:
  pattern: synchronized($L) { $$ java.lang.Thread.sleep($D); $$ }
severity: info
message: "Thread.sleep inside synchronized block may block other threads unnecessarily"
YAML

  cat >"$AST_RULE_DIR/notify.yml" <<'YAML'
id: java.notify
language: java
rule:
  pattern: $O.notify()
severity: info
message: "notify() wakes a single waiter; ensure this is intended (notifyAll?)"
YAML

  # ====== Security ======
  cat >"$AST_RULE_DIR/insecure-random.yml" <<'YAML'
id: java.insecure-random
language: java
rule:
  pattern: new java.util.Random($$)
severity: info
message: "java.util.Random is not cryptographically secure; prefer SecureRandom for secrets"
YAML

  cat >"$AST_RULE_DIR/trust-all-cert.yml" <<'YAML'
id: java.insecure-ssl
language: java
rule:
  any:
    - pattern: javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(($H, $S) -> true)
    - pattern: $X.setHostnameVerifier(($H, $S) -> true)
    - pattern: new javax.net.ssl.X509TrustManager { $$ public void checkServerTrusted($$, $$) { } $$ }
severity: error
message: "SSL/TLS verification disabled; enables MITM"
YAML

  cat >"$AST_RULE_DIR/weak-hash.yml" <<'YAML'
id: java.weak-hash
language: java
rule:
  any:
    - pattern: java.security.MessageDigest.getInstance("MD5")
    - pattern: java.security.MessageDigest.getInstance("SHA-1")
severity: warning
message: "Weak hash algorithm detected (MD5/SHA-1); prefer SHA-256/512"
YAML

  # Plain HTTP literals via AST + regex
  cat >"$AST_RULE_DIR/plain-http.yml" <<'YAML'
id: java.plain-http
language: java
rule:
  all:
    - kind: string_literal
    - regex: '^"http://'
severity: info
message: "Plain HTTP URL detected; ensure HTTPS for production"
YAML

  cat >"$AST_RULE_DIR/deserialization.yml" <<'YAML'
id: java.insecure-deserialization
language: java
rule:
  any:
    - pattern: new java.io.ObjectInputStream($$).readObject()
    - pattern: $IN.readObject()
severity: warning
message: "Java deserialization can be dangerous; validate types or avoid if possible"
YAML

  # ====== I/O & Charset ======
  cat >"$AST_RULE_DIR/inputstreamreader-no-charset.yml" <<'YAML'
id: java.inputstreamreader-no-charset
language: java
rule:
  pattern: new java.io.InputStreamReader($S)
severity: info
message: "InputStreamReader without explicit charset uses platform default; specify charset"
YAML

  cat >"$AST_RULE_DIR/string-no-charset.yml" <<'YAML'
id: java.string-bytes-no-charset
language: java
rule:
  any:
    - pattern: new String($B)
    - pattern: $S.getBytes()
severity: info
message: "String/bytes without charset; specify StandardCharsets.UTF_8 (or required encoding)"
YAML

  # ====== Streams / Parallel ======
  cat >"$AST_RULE_DIR/parallel-foreach.yml" <<'YAML'
id: java.parallel-foreach-side-effects
language: java
rule:
  pattern: $SRC.parallel().forEach($$)
severity: info
message: "parallel().forEach may reorder and run side effects concurrently; ensure thread-safety"
YAML

  # ====== Reflection ======
  cat >"$AST_RULE_DIR/reflection.yml" <<'YAML'
id: java.reflection
language: java
rule:
  any:
    - pattern: Class.forName($$)
    - pattern: $C.getDeclaredField($$)
    - pattern: $C.getDeclaredMethod($$)
    - pattern: $M.invoke($$)
    - pattern: $F.setAccessible(true)
severity: info
message: "Reflection reduces type safety; ensure strict validation"
YAML

  # ====== Regex (ReDoS) ======
  cat >"$AST_RULE_DIR/regex-nested-quant.yml" <<'YAML'
id: java.regex-redos
language: java
rule:
  all:
    - kind: string_literal
    - regex: '(".*(\(\?:?[^"]*[+*][^"]*\)[+*][^"]*)+")'
severity: warning
message: "Regex with nested quantifiers; potential ReDoS"
YAML

  # ====== Collections / Legacy ======
  cat >"$AST_RULE_DIR/legacy-collections.yml" <<'YAML'
id: java.legacy-collections
language: java
rule:
  any:
    - pattern: new java.util.Vector($$)
    - pattern: new java.util.Hashtable($$)
severity: info
message: "Legacy synchronized collections; prefer java.util.concurrent alternatives"
YAML

  # ====== Virtual threads / Structured Concurrency (Java 21+) ======
  cat >"$AST_RULE_DIR/virtual-threads.yml" <<'YAML'
id: java.virtual-threads
language: java
rule:
  any:
    - pattern: java.lang.Thread.ofVirtual().start($$)
    - pattern: java.lang.Thread.ofVirtual().factory()
severity: info
message: "Virtual threads detected; ensure blocking I/O is appropriate or use async APIs"
YAML

  cat >"$AST_RULE_DIR/java-resource-resultset.yml" <<'YAML'
id: java.resource.resultset-no-close
language: java
rule:
  any:
    - pattern: java.sql.ResultSet $R = $EXPR.executeQuery($$);
    - pattern: ResultSet $R = $EXPR.executeQuery($$);
  not:
    any:
      - inside:
          pattern: $R.close()
      - inside:
          kind: try_with_resources_statement
severity: warning
message: "ResultSet acquired without close(); wrap in try-with-resources or close explicitly."
YAML

  cat >"$AST_RULE_DIR/java-resource-statement.yml" <<'YAML'
id: java.resource.statement-no-close
language: java
rule:
  any:
    - pattern: java.sql.Statement $S = $EXPR.createStatement($$);
    - pattern: Statement $S = $EXPR.createStatement($$);
    - pattern: java.sql.PreparedStatement $S = $EXPR.prepareStatement($$);
    - pattern: PreparedStatement $S = $EXPR.prepareStatement($$);
    - pattern: java.sql.CallableStatement $S = $EXPR.prepareCall($$);
    - pattern: CallableStatement $S = $EXPR.prepareCall($$);
  not:
    any:
      - inside:
          pattern: $S.close()
      - inside:
          kind: try_with_resources_statement
severity: warning
message: "Statement/PreparedStatement acquired without close(); wrap in try-with-resources or close explicitly."
YAML
  # ====== Closeable without try-with-resources (heuristic) ======
  cat >"$AST_RULE_DIR/closeable-no-twr.yml" <<'YAML'
id: java.closeable-no-twr
language: java
rule:
  pattern: |
    $T $V = new $C($$);
  constraints:
    C:
      regex: '.*(Stream|Reader|Writer|Scanner|Connection|Channel).*'
  not:
    inside:
      kind: try_with_resources_statement
severity: info
message: "Closeable created outside try-with-resources; ensure it is closed"
YAML
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  local outfmt="--json"; [[ "$FORMAT" == "sarif" ]] && outfmt="--sarif"
  if [[ -n "$SARIF_OUT" ]]; then "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --sarif > "$SARIF_OUT" 2>/dev/null || true; fi
  if [[ -n "$JSON_OUT" ]]; then "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json=stream > "$JSON_OUT" 2>/dev/null || true; fi
  "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" $outfmt 2>/dev/null
}


ensure_ast_rule_results() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  if [[ -n "$AST_RULE_RESULTS_JSON" && -f "$AST_RULE_RESULTS_JSON" ]]; then
    return 0
  fi
  local tmp_json
  tmp_json="$(mktemp 2>/dev/null || mktemp -t java_ast_results.XXXXXX)"
  if [[ ! -f "$tmp_json" ]]; then
    return 1
  fi
  if ! "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json=stream >"$tmp_json" 2>/dev/null; then
    rm -f "$tmp_json"
    return 1
  fi
  AST_RULE_RESULTS_JSON="$tmp_json"
  trap '[[ -n "${AST_RULE_RESULTS_JSON:-}" ]] && rm -f "$AST_RULE_RESULTS_JSON" || true; [[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  return 0
}

emit_ast_rule_group() {
  local rules_name="$1"
  local severity_map_name="$2"
  local summary_map_name="$3"
  local remediation_map_name="$4"
  local good_msg="$5"
  local missing_msg="$6"

  if [[ "$HAS_AST_GREP" -ne 1 || -z "$AST_RULE_DIR" ]]; then
    print_finding "info" 0 "$missing_msg" "Install ast-grep to enable this check"
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
    while IFS=$'	' read -r match_rid match_count match_samples; do
      [[ -z "$match_rid" ]] && continue
      had_matches=1
      local sev=${_severity[$match_rid]:-warning}
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
    done < <(python3 - "$result_json" "${_rule_ids[@]}" <<'PYRULE'
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
        rng = obj.get('range') or {}
        start = rng.get('start') or {}
        line_no = start.get('line')
        if isinstance(line_no, int):
            line_no += 1
        sample = f"{f}:{line_no if line_no is not None else '?'}"
        entry = stats.setdefault(rid, {'count': 0, 'samples': []})
        entry['count'] += 1
        if len(entry['samples']) < 3:
            entry['samples'].append(sample)

for rid, data in stats.items():
    print(rid, data['count'], ','.join(data['samples']), sep='	')
PYRULE
    )
  else
    for rid in "${_rule_ids[@]}"; do
      local c
      c=$(grep -c "\"ruleId\": \"$rid\"" "$result_json" 2>/dev/null || echo 0)
      if [[ "$c" -gt 0 ]]; then
        had_matches=1
        local sev=${_severity[$rid]:-warning}
        local summary=${_summary[$rid]:-$rid}
        local desc=${_remediation[$rid]:-}
        print_finding "$sev" "$c" "$summary" "$desc"
      fi
    done
  fi

  if [[ $had_matches -eq 0 ]]; then
    print_finding "good" "$good_msg"
  fi
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# Build helpers (Maven/Gradle best-effort)
# ────────────────────────────────────────────────────────────────────────────
run_cmd_log() {
  local logfile="$1"; shift
  local ec=0
  ( set +e; "$@" >"$logfile" 2>&1; ec=$?; echo "$ec" >"$logfile.ec"; exit 0 )
}

count_warnings_errors_text() {
  local file="$1"
  local w e
  w=$(grep -E "^[Ww]arning: |: warning:|\\bWARNING\\b" "$file" 2>/dev/null | wc -l | awk '{print $1+0}')
  e=$(grep -E "^[Ee]rror: |: error:|\\bERROR\\b" "$file" 2>/dev/null | wc -l | awk '{print $1+0}')
  echo "$w $e"
}

detect_gradle_tasks() {
  local tlist="$1"
  local grep_task; grep_task() { grep -q -E "^\s*$1\s" "$tlist"; }
  GREP_TASK_FN="grep_task"
}

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper
# ────────────────────────────────────────────────────────────────────────────
should_run() {
  local cat="$1"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    IFS=',' read -r -a only_arr <<<"$ONLY_CATEGORIES"
    for s in "${only_arr[@]}"; do [[ "$s" == "$cat" ]] && return 0; done
    return 1
  fi
  if [[ -z "$SKIP_CATEGORIES" ]]; then return 0; fi
  IFS=',' read -r -a skip_arr <<<"$SKIP_CATEGORIES"
  for s in "${skip_arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# JSON summary emitter (for --format=json)
# ────────────────────────────────────────────────────────────────────────────
emit_json_summary() {
  local started="$START_TS"
  local finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%s')"
  printf '{ "project":"%s","files":%s,"critical":%s,"warnings":%s,"info":%s,"started":"%s","finished":"%s","java":"%s","format":"%s" }\n' \
    "$(printf %s "$PROJECT_DIR" | sed 's/"/\\"/g')" "$TOTAL_FILES" "$CRITICAL_COUNT" "$WARNING_COUNT" "$INFO_COUNT" \
    "$started" "$finished" "$(printf %s "${JAVA_VERSION_STR:-unknown}" | sed 's/"/\\"/g')" "$FORMAT"
}

# ────────────────────────────────────────────────────────────────────────────
# Startup banner
# ────────────────────────────────────────────────────────────────────────────
maybe_clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔════════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗    ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝    ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗      ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝      ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗    ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ║
║                                            (  )   (   )  )         ║
║  ██████╗ ██╗   ██╗ ██████╗                  ) (   )  (  (          ║
║  ██╔══██╗██║   ██║██╔════╝                  ( )  (    ) )          ║
║  ██████╔╝██║   ██║██║  ███╗                 _____________          ║
║  ██╔══██╗██║   ██║██║   ██║                <_____________> ___     ║
║  ██████╔╝╚██████╔╝╚██████╔╝                |             |/ _ \    ║
║  ╚═════╝  ╚═════╝  ╚═════╝                 |               | | |   ║
║                                            |               |_| |   ║
║                                         ___|             |\___/    ║
║                                        /    \___________/    \     ║
║                                        \_____________________/     ║
║                                                                    ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗    ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗   ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝   ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗   ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║   ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝        ║
║                                                                    ║
║  Java module • nullability, concurrency, serialization checks      ║
║  UBS module: java • Maven/Gradle compile + AST security packs      ║
║  ASCII homage: ASCII coffee cup (Art Archive)                      ║
║  Run standalone: modules/ubs-java.sh --help                        ║
║                                                                    ║
║  Night Owl QA                                                      ║
║  “We see bugs before you do.”                                      ║
╚════════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(now)${RESET}"

# Count files (robust prune + include patterns)
EX_PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do EX_PRUNE+=( -name "$d" -o ); done
EX_PRUNE+=( -false )
NAME_EXPR=( \( )
first=1
for e in "${_EXT_ARR[@]}"; do
  if [[ $first -eq 1 ]]; then
    NAME_EXPR+=( -name "*.$e" )
    first=0
  else
    NAME_EXPR+=( -o -name "*.$e" )
  fi
done
NAME_EXPR+=( \) )
TOTAL_FILES=$(
  ( set +o pipefail;
    find "$PROJECT_DIR" \
      \( -type d \( "${EX_PRUNE[@]}" \) -prune \) -o \
      \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true
  ) | wc -l | awk '{print $1+0}'
)
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

if ( set +o pipefail;
     find "$PROJECT_DIR" \
       \( -type d \( "${EX_PRUNE[@]}" \) -prune \) -o \
       \( -type f \( -name '*.kt' -o -name '*.kts' \) -print -quit \) 2>/dev/null
   ) | grep -q .; then
  HAS_KOTLIN_FILES=1
fi

if ( set +o pipefail;
     find "$PROJECT_DIR" \
       \( -type d \( "${EX_PRUNE[@]}" \) -prune \) -o \
       \( -type f -name '*.swift' -print -quit \) 2>/dev/null
   ) | grep -q .; then
  HAS_SWIFT_FILES=1
fi

# Tool detection
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex-only heuristics where needed${RESET}"
fi

check_java_env
if [[ "$HAS_JAVA" -eq 1 ]]; then
  say "${GREEN}${CHECK} Java detected:${RESET} ${DIM}$JAVA_VERSION_STR${RESET}"
  if [[ "$JAVA_TOOLCHAIN_OK" -ne 1 ]]; then
    say "${YELLOW}${WARN} Java major version $JAVA_MAJOR < $JAVA_REQUIRED_MAJOR; some rules assume Java 21 semantics${RESET}"
  else
    say "${GREEN}${CHECK} Java 21+ toolchain suitable${RESET}"
  fi
else
  say "${YELLOW}${WARN} java/javac not found on PATH; build checks may be skipped${RESET}"
fi
[[ "$HAS_MAVEN" -eq 1 ]]  && say "  ${GREEN}${CHECK}${RESET} Maven available"
[[ "$HAS_GRADLE" -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} Gradle available"
[[ -n "$MVNW" ]]          && say "  ${BLUE}${INFO}${RESET} Using wrapper: ${CYAN}$MVNW${RESET}"
[[ -n "$GRADLEW" ]]       && say "  ${BLUE}${INFO}${RESET} Using wrapper: ${CYAN}$GRADLEW${RESET}"

# relax pipefail for scanning
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: NULL & OPTIONAL PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_run 1; then
print_header "1. NULL & OPTIONAL PITFALLS"
print_category "Detects: Optional.get(), == null checks misuse, Objects.equals opportunities" \
  "Unnecessary NPEs and Optional misuse are common sources of production failures"

print_subheader "Optional.get() usage (potential NoSuchElementException)"
opt_get_ast=$(ast_search '$O.get()' || echo 0)
opt_get_rg=$("${GREP_RN[@]}" -e "\.get\(\s*\)" "$PROJECT_DIR" 2>/dev/null | (grep -vE "\.getClass\(" || true) | count_lines || true)
opt_total=$(( (opt_get_ast>0) ? opt_get_ast : opt_get_rg ))
if [ "$opt_total" -gt 0 ]; then
  print_finding "warning" "$opt_total" "Optional.get() detected" "Prefer orElse/orElseThrow or ifPresent"
  show_detailed_finding "\.get\(\)" 5
else
  print_finding "good" "No Optional.get() calls"
fi

print_subheader "Optional.isPresent() followed by get()"
isp_get_ast=$(ast_search 'if ($O.isPresent()) { $$ $O.get() $$ }' || echo 0)
if [ "$isp_get_ast" -gt 0 ]; then print_finding "info" "$isp_get_ast" "isPresent()+get() pattern"; fi

print_subheader "Null checks using '==' with Strings (prefer Objects.equals)"
str_eq_null=$("${GREP_RN[@]}" -e "==[[:space:]]*null|null[[:space:]]*==" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$str_eq_null" -gt 0 ]; then print_finding "info" "$str_eq_null" "Null equality checks present - consider Objects.isNull/nonNull where expressive"; fi

if [[ "$HAS_KOTLIN_FILES" -eq 1 ]]; then
  print_subheader "Kotlin guard clauses without exit"
  run_kotlin_type_narrowing_checks
fi
if [[ "$HAS_SWIFT_FILES" -eq 1 ]]; then
  print_subheader "Swift guard let validation"
  run_swift_type_narrowing_checks
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: EQUALITY & HASHCODE
# ═══════════════════════════════════════════════════════════════════════════
if should_run 2; then
print_header "2. EQUALITY & HASHCODE"
print_category "Detects: String '==' compares, BigDecimal equals(), equals/hashCode mismatch" \
  "Equality issues cause subtle logic bugs and inconsistent collections behavior"

print_subheader "String compared with '=='"
str_eq_ast=$(ast_search '$X == $Y' || echo 0)
str_eq_lit=$("${GREP_RN[@]}" -e "==[[:space:]]*\"|\"[[:space:]]*==" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$str_eq_lit" -gt 0 ]; then
  print_finding "warning" "$str_eq_lit" "String compared with '=='" "Use equals() or Objects.equals(a,b)"
  show_detailed_finding "==[[:space:]]*\"|\"[[:space:]]*==" 5
else
  print_finding "good" "No String '==' comparisons detected"
fi

print_subheader "BigDecimal.equals vs compareTo"
bd_eq=$("${GREP_RN[@]}" -e "BigDecimal" "$PROJECT_DIR" 2>/dev/null | (grep -E "\.equals\(" || true) | count_lines || true)
if [ "$bd_eq" -gt 0 ]; then print_finding "info" "$bd_eq" "BigDecimal.equals usage - consider compareTo()==0"; fi

print_subheader "equals() overridden without hashCode()"
while IFS= read -r f; do
  eqc=$(grep -nE "boolean[[:space:]]+equals\s*\(" "$f" 2>/dev/null | wc -l | awk '{print $1+0}')
  hcc=$(grep -nE "int[[:space:]]+hashCode\s*\(" "$f" 2>/dev/null | wc -l | awk '{print $1+0}')
  if [ "$eqc" -gt 0 ] && [ "$hcc" -eq 0 ]; then
    print_finding "warning" 1 "equals without hashCode in $f" "Objects used in HashMap/Set will misbehave"
    print_code_sample "$f" "$(grep -nE 'boolean[[:space:]]+equals\s*\(' "$f" | head -n1 | cut -d: -f1)" "equals(...) missing hashCode()"
  fi
done < <(find "$PROJECT_DIR" -type f \( -name "*.java" -o -name "*.kt" \) -print 2>/dev/null)

print_subheader "Boxed primitives compared with '==' (heuristic)"
boxed_eq=$("${GREP_RN[@]}" -e "\b(Integer|Long|Short|Byte|Boolean|Double|Float)\b[^;\n]*==[^;\n]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$boxed_eq" -gt 0 ]; then print_finding "info" "$boxed_eq" "Boxed primitives using '==' - consider equals()/Objects.equals()"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: CONCURRENCY & THREADING
# ═══════════════════════════════════════════════════════════════════════════
if should_run 3; then
print_header "3. CONCURRENCY & THREADING"
print_category "Detects: synchronized(this), Thread.start, newCachedThreadPool, sleep in synchronized, notify()" \
  "Concurrency misuse leads to deadlocks and performance issues"

print_subheader "synchronized(this) blocks"
syn_this=$(( $(ast_search 'synchronized(this) { $$ }' || echo 0) + $("${GREP_RN[@]}" -e "synchronized\s*\(\s*this\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$syn_this" -gt 0 ]; then print_finding "info" "$syn_this" "synchronized(this) used - prefer private lock objects"; fi

print_subheader "Manual thread management"
thr_start=$(( $(ast_search 'new Thread($$).start()' || echo 0) + $("${GREP_RN[@]}" -e "new[[:space:]]+Thread\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$thr_start" -gt 0 ]; then print_finding "info" "$thr_start" "Manual thread creation detected"; fi

print_subheader "Executors.newCachedThreadPool (unbounded)"
cached_pool=$(( $(ast_search 'java.util.concurrent.Executors.newCachedThreadPool($$)' || echo 0) + $("${GREP_RN[@]}" -e "Executors\.newCachedThreadPool\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$cached_pool" -gt 0 ]; then print_finding "warning" "$cached_pool" "newCachedThreadPool unbounded threads"; fi

print_subheader "Thread.sleep in synchronized blocks"
sleep_sync=$(( $(ast_search 'synchronized($L) { $$ java.lang.Thread.sleep($D); $$ }' || echo 0) + $("${GREP_RN[@]}" -e "synchronized\s*\([^\)]+\)\s*\{[^}]*Thread\.sleep\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$sleep_sync" -gt 0 ]; then print_finding "info" "$sleep_sync" "Thread.sleep within synchronized block"; fi

print_subheader "notify() usage"
notify_count=$(( $(ast_search '$O.notify()' || echo 0) + $("${GREP_RN[@]}" -e "\.notify\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$notify_count" -gt 0 ]; then print_finding "info" "$notify_count" "notify() calls detected - ensure correct semantics"; fi

run_async_error_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: SECURITY
# ═══════════════════════════════════════════════════════════════════════════
if should_run 4; then
print_header "4. SECURITY"
print_category "Detects: Insecure SSL, weak hashes, http://, insecure deserialization, Random for secrets" \
  "Security misconfigurations expose users to attacks and data breaches"

print_subheader "SSL verification disabled (CRITICAL)"
ssl_insecure=$(( $(ast_search 'javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(($H, $S) -> true)' || echo 0) + $(ast_search 'new javax.net.ssl.X509TrustManager { $$ }' || echo 0) + $("${GREP_RN[@]}" -e "HostnameVerifier\W*\(\W*.*->\W*true\W*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$ssl_insecure" -gt 0 ]; then print_finding "critical" "$ssl_insecure" "SSL/TLS validation disabled"; fi

print_subheader "Weak hash algorithms (MD5/SHA-1)"
weak_hash=$(( $(ast_search 'java.security.MessageDigest.getInstance("MD5")' || echo 0) + $(ast_search 'java.security.MessageDigest.getInstance("SHA-1")' || echo 0) + $("${GREP_RN[@]}" -e "MessageDigest\.getInstance\(\"(MD5|SHA-1)\"\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$weak_hash" -gt 0 ]; then print_finding "warning" "$weak_hash" "Weak hash detected - prefer SHA-256/512"; fi

print_subheader "Plain HTTP URLs"
http_url=$(( $(ast_search 'all: [ { kind: string_literal }, { regex: "^\"http://" } ]' || echo 0) + $("${GREP_RN[@]}" -e "http://[A-Za-z0-9]" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$http_url" -gt 0 ]; then print_finding "info" "$http_url" "Plain HTTP URL(s) present"; fi

print_subheader "Java deserialization"
deser=$(( $(ast_search 'new java.io.ObjectInputStream($$).readObject()' || echo 0) + $("${GREP_RN[@]}" -e "ObjectInputStream\(.+\)\.readObject\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$deser" -gt 0 ]; then print_finding "warning" "$deser" "Object deserialization detected"; fi

print_subheader "java.util.Random usage"
rand=$(( $(ast_search 'new java.util.Random($$)' || echo 0) + $("${GREP_RN[@]}" -e "new[[:space:]]+Random\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$rand" -gt 0 ]; then print_finding "info" "$rand" "Random used; prefer SecureRandom for secrets"; fi

print_subheader "Runtime.exec command execution"
cmd_exec=$("${GREP_RN[@]}" -e "Runtime\\.getRuntime\\(\\)\\.exec" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$cmd_exec" -gt 0 ]; then
  print_finding "critical" "$cmd_exec" "Runtime.exec invoked" "Sanitize command arguments or avoid spawning shell commands"
  show_detailed_finding "Runtime\\.getRuntime\\(\\)\\.exec" 3
else
  mapfile -t runtime_meta < <(java_pattern_scan runtime_exec)
  runtime_count="${runtime_meta[0]:-0}"
  runtime_samples="${runtime_meta[1]:-}"
  if [ "${runtime_count:-0}" -gt 0 ]; then
    runtime_desc="Sanitize command arguments or avoid spawning shell commands"
    if [ -n "$runtime_samples" ]; then
      runtime_desc+=" (e.g., ${runtime_samples%%,*})"
    fi
    print_finding "critical" "$runtime_count" "Runtime.exec invoked" "$runtime_desc"
  fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: I/O & RESOURCES
# ═══════════════════════════════════════════════════════════════════════════
if should_run 5; then
print_header "5. I/O & RESOURCES"
print_category "Detects: missing charset, blocking reads in loops, delete() unchecked" \
  "I/O patterns that cause correctness or performance issues"

print_subheader "InputStreamReader without charset"
isr=$(( $(ast_search 'new java.io.InputStreamReader($S)' || echo 0) + $("${GREP_RN[@]}" -e "new[[:space:]]+InputStreamReader\([^)]+\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$isr" -gt 0 ]; then print_finding "info" "$isr" "InputStreamReader without charset"; fi

print_subheader "new String(bytes) without charset or getBytes() without charset"
str_bytes=$(( $(ast_search 'new String($B)' || echo 0) + $(ast_search '$S.getBytes()' || echo 0) + $("${GREP_RN[@]}" -e "new[[:space:]]+String\(\s*[A-Za-z0-9_]+\s*\)|\.getBytes\(\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$str_bytes" -gt 0 ]; then print_finding "info" "$str_bytes" "Charset not specified in String/bytes conversion"; fi

print_subheader "Files.readAllBytes / large reads inside loops"
read_all_bytes_loop=$("${GREP_RN[@]}" -e "for[[:space:]]*\(|while[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | (grep -A4 -F "Files.readAllBytes(" || true) | (grep -c -F "Files.readAllBytes(" || true))
read_all_bytes_loop=$(echo "$read_all_bytes_loop" | awk 'END{print $0+0}')
if [ "$read_all_bytes_loop" -gt 0 ]; then print_finding "warning" "$read_all_bytes_loop" "Files.readAllBytes in loop - consider streaming"; fi

print_subheader "Try-with-resources coverage"
twr_candidates=$("${GREP_RN[@]}" -e "new[[:space:]]+(File(Input|Output)Stream|Buffered(Reader|Writer)|Scanner|FileReader|FileWriter|Connection|PreparedStatement)\(" "$PROJECT_DIR" 2>/dev/null | grep -vE "try[[:space:]]*\\(" | count_lines || true)
if [ "$twr_candidates" -gt 0 ]; then
  print_finding "warning" "$twr_candidates" "Closeable created outside try-with-resources" "Wrap AutoCloseable objects in try-with-resources or close them in finally blocks"
  show_detailed_finding "new[[:space:]]+(File(Input|Output)Stream|Buffered(Reader|Writer)|Scanner|Connection|PreparedStatement)\(" 3
else
  print_finding "good" "Closeable resources appear wrapped in try-with-resources"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: LOGGING & DEBUGGING
# ═══════════════════════════════════════════════════════════════════════════
if should_run 6; then
print_header "6. LOGGING & DEBUGGING"
print_category "Detects: System.out/err.println, printStackTrace, TODO/FIXME/HACK markers" \
  "Debug code left in production affects performance and leaks info"

print_subheader "System.out/err.println"
println_cnt=$(( $(ast_search 'System.out.println($$)' || echo 0) + $(ast_search 'System.err.println($$)' || echo 0) + $("${GREP_RN[@]}" -e "System\.(out|err)\.println\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$println_cnt" -gt 0 ]; then print_finding "info" "$println_cnt" "System.out/err.println present - prefer logger"; fi

print_subheader "printStackTrace calls"
pst_cnt=$(( $(ast_search '$E.printStackTrace()' || echo 0) + $("${GREP_RN[@]}" -e "\.printStackTrace\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$pst_cnt" -gt 0 ]; then print_finding "warning" "$pst_cnt" "printStackTrace leaks details"; fi

print_subheader "Technical debt markers"
todo_count=$("${GREP_RNI[@]}" "TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fixme_count=$("${GREP_RNI[@]}" "FIXME" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
hack_count=$("${GREP_RNI[@]}" "HACK" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
note_count=$("${GREP_RNI[@]}" "NOTE" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total_markers=$((todo_count + fixme_count + hack_count))
if [ "$total_markers" -gt 20 ]; then
  print_finding "warning" "$total_markers" "Significant technical debt"
elif [ "$total_markers" -gt 0 ]; then
  print_finding "info" "$total_markers" "TODO/FIXME/HACK markers present"
else
  print_finding "good" "No technical debt markers"
fi

print_subheader "String concatenation inside logging calls"
log_concat_ast=$(ast_search '$L.debug($A + $B)' || echo 0)
log_concat_rg=$("${GREP_RN[@]}" -e "(logger|LOG|log)\.(trace|debug|info|warn|error)\s*\([^)]*\+[^)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
log_concat_total=$(( log_concat_ast + log_concat_rg ))
if [ "$log_concat_total" -gt 0 ]; then print_finding "info" "$log_concat_total" "Logging concatenation - prefer parameterized logging"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: REGEX & STRING PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_run 7; then
print_header "7. REGEX & STRING PITFALLS"
print_category "Detects: ReDoS patterns, Pattern.compile with variables, toLowerCase/equals" \
  "String/regex bugs cause performance issues and subtle mismatches"

print_subheader "Nested quantifiers (ReDoS risk)"
redos_cnt=$("${GREP_RN[@]}" -e "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$redos_cnt" -gt 0 ]; then print_finding "warning" "$redos_cnt" "Regex contains nested quantifiers - potential ReDoS"; show_detailed_finding "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" 3; fi

print_subheader "Pattern.compile with variables (injection risk)"
dyn_pat=$("${GREP_RN[@]}" -e "Pattern\.compile\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$dyn_pat" -gt 0 ]; then print_finding "info" "$dyn_pat" "Dynamic Pattern.compile detected - sanitize/escape user input"; fi

print_subheader "Case handling via toLowerCase()/toUpperCase() then equals"
case_cmp=$("${GREP_RN[@]}" -e "\.to(Lower|Upper)Case\(\)\.equals\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$case_cmp" -gt 0 ]; then print_finding "info" "$case_cmp" "Prefer equalsIgnoreCase or use Locale"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: COLLECTIONS & GENERICS
# ═══════════════════════════════════════════════════════════════════════════
if should_run 8; then
print_header "8. COLLECTIONS & GENERICS"
print_category "Detects: raw types, legacy Vector/Hashtable, remove in foreach" \
  "Raw types and mutation during iteration cause runtime errors"

print_subheader "Raw generic types (List/Map/Set without <...>)"
raw_types=$("${GREP_RN[@]}" -e "\b(List|Map|Set)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(=|;)" "$PROJECT_DIR" 2>/dev/null | (grep -v '<' || true) | count_lines)
if [ "$raw_types" -gt 0 ]; then print_finding "warning" "$raw_types" "Raw generic types used"; fi

print_subheader "Legacy synchronized collections"
legacy=$(( $(ast_search 'new java.util.Vector($$)' || echo 0) + $(ast_search 'new java.util.Hashtable($$)' || echo 0) + $("${GREP_RN[@]}" -e "new[[:space:]]+(Vector|Hashtable)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$legacy" -gt 0 ]; then print_finding "info" "$legacy" "Vector/Hashtable detected"; fi

print_subheader "Collection modification during foreach (heuristic)"
mod_foreach=$("${GREP_RN[@]}" -e "for\s*\([^)]+:[^)]+\)\s*\{" "$PROJECT_DIR" 2>/dev/null | (grep -A3 -F ".remove(" || true) | (grep -c -F ".remove(" || true))
mod_foreach=$(echo "$mod_foreach" | awk 'END{print $0+0}')
if [ "$mod_foreach" -gt 0 ]; then print_finding "warning" "$mod_foreach" "Possible modification of collection during iteration"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: SWITCH & CONTROL FLOW
# ═══════════════════════════════════════════════════════════════════════════
if should_run 9; then
print_header "9. SWITCH & CONTROL FLOW"
print_category "Detects: fall-through (classic switch), switch without default" \
  "Control flow bugs cause unexpected behavior"

print_subheader "Classic switch fall-through (ignore '->' labels)"
switch_count=$("${GREP_RN[@]}" -e "switch\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
case_count=$("${GREP_RN[@]}" -e "case[[:space:]]+.*:" "$PROJECT_DIR" 2>/dev/null | (grep -v -- "->" || true) | count_lines || true)
break_count=$("${GREP_RN[@]}" -e "\bbreak\s*;" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$case_count" -gt "$break_count" ] && [ "$case_count" -gt 0 ]; then
  diff=$((case_count - break_count))
  print_finding "warning" "$diff" "Switch cases may be missing break (classic switch)"
fi

print_subheader "Switch without default (classic switch)"
default_count=$("${GREP_RN[@]}" -e "default[[:space:]]*:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$switch_count" -gt "$default_count" ] && [ "$switch_count" -gt 0 ]; then
  diff=$((switch_count - default_count))
  print_finding "info" "$diff" "Some switch statements have no default case (classic syntax)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: STREAMS & PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════
if should_run 10; then
print_header "10. STREAMS & PERFORMANCE"
print_category "Detects: parallel().forEach, String concatenation in loops" \
  "Performance pitfalls that scale poorly"

print_subheader "parallel().forEach side-effect risk"
par_for_each=$(( $(ast_search '$SRC.parallel().forEach($$)' || echo 0) + $("${GREP_RN[@]}" -e "\.parallel\(\)\.forEach\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$par_for_each" -gt 0 ]; then print_finding "info" "$par_for_each" "parallel forEach detected - ensure thread-safe side effects"; fi

print_subheader "String concatenation in loops"
str_plus_loop=$("${GREP_RN[@]}" -e "for\s*\(|while\s*\(" "$PROJECT_DIR" 2>/dev/null | (grep -A3 "\+=\"" || true) | (grep -cw "\+=\"" || true))
str_plus_loop=$(echo "$str_plus_loop" | awk 'END{print $0+0}')
if [ "$str_plus_loop" -gt 0 ]; then print_finding "info" "$str_plus_loop" "String '+=' in loops - prefer StringBuilder"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: SERIALIZATION & COMPATIBILITY
# ═══════════════════════════════════════════════════════════════════════════
if should_run 11; then
print_header "11. SERIALIZATION & COMPATIBILITY"
print_category "Detects: implements Serializable, readObject/writeObject" \
  "Serialization hazards and maintenance burdens"

print_subheader "Serializable implementations (inventory)"
serializable=$("${GREP_RN[@]}" -e "implements\s+Serializable\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$serializable" -gt 0 ]; then print_finding "info" "$serializable" "Classes implement Serializable - audit necessity"; fi

print_subheader "Custom readObject/writeObject methods"
custom_ser=$("${GREP_RN[@]}" -e "void\s+readObject\s*\(|void\s+writeObject\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$custom_ser" -gt 0 ]; then print_finding "info" "$custom_ser" "Custom serialization hooks present - validate invariants"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: JAVA 21 FEATURES (INFO)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 12; then
print_header "12. JAVA 21 FEATURES (INFO)"
print_category "Detects: Virtual Threads, Structured Concurrency, Sequenced Collections" \
  "Inventory of modern APIs to guide reviews for correct usage"

print_subheader "Virtual Threads"
virt_threads=$(( $(ast_search 'java.lang.Thread.ofVirtual().start($$)' || echo 0) + $("${GREP_RN[@]}" -e "Thread\.ofVirtual\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$virt_threads" -gt 0 ]; then print_finding "info" "$virt_threads" "Virtual threads in use - ensure blocking operations are appropriate"; fi

print_subheader "StructuredTaskScope"
scope_cnt=$("${GREP_RN[@]}" -e "StructuredTaskScope" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$scope_cnt" -gt 0 ]; then print_finding "info" "$scope_cnt" "StructuredTaskScope in use - validate proper join/shutdown handling"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: SQL CONSTRUCTION (HEURISTICS)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 13; then
print_header "13. SQL CONSTRUCTION (HEURISTICS)"
print_category "Detects: string-concatenated SQL, Statement.executeQuery with + operator" \
  "Prefer prepared statements with parameters to avoid injection"

print_subheader "String-concatenated SQL"
sql_concat=$("${GREP_RN[@]}" -e "\"(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"[[:space:]]*\\+[[:space:]]*[A-Za-z0-9_]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$sql_concat" -gt 0 ]; then
  print_finding "warning" "$sql_concat" "SQL built via concatenation - prefer parameters"
  show_detailed_finding "execute(Query|Update)\s*\([^)]*\+" 3
fi

print_subheader "Statement.executeQuery with concatenation"
exec_concat=$("${GREP_RN[@]}" -e "execute(Query|Update)\s*\(" "$PROJECT_DIR" 2>/dev/null | (grep "\+" || true) | count_lines)
if [ "$exec_concat" -gt 0 ]; then
  print_finding "warning" "$exec_concat" "execute* called with concatenated query string"
  show_detailed_finding "execute(Query|Update)\s*\([^)]*\+" 3
elif [ "$sql_concat" -eq 0 ]; then
  mapfile -t sql_meta < <(java_pattern_scan sql_concat)
  sql_fallback="${sql_meta[0]:-0}"
  sql_samples="${sql_meta[1]:-}"
  if [ "${sql_fallback:-0}" -gt 0 ]; then
    sql_desc="Prefer PreparedStatement parameters over string concatenation"
    if [ -n "$sql_samples" ]; then
      sql_desc+=" (e.g., ${sql_samples%%,*})"
    fi
    print_finding "warning" "$sql_fallback" "SQL built via concatenation - prefer parameters" "$sql_desc"
  fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: ANNOTATIONS & NULLNESS (HEURISTICS)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 14; then
print_header "14. ANNOTATIONS & NULLNESS (HEURISTICS)"
print_category "Detects: @Nullable without guard (approx), @Deprecated usages" \
  "Annotation-driven contracts must be respected"

print_subheader "@Nullable parameters used without null guard (approx)"
nullable_params=$("${GREP_RN[@]}" -e "@Nullable" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$nullable_params" -gt 0 ]; then print_finding "info" "$nullable_params" "@Nullable present - ensure null checks at use sites"; fi

print_subheader "Usage of @Deprecated APIs"
deprecated_use=$("${GREP_RN[@]}" -e "@Deprecated|@deprecated" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$deprecated_use" -gt 0 ]; then print_finding "info" "$deprecated_use" "Deprecated annotations present - verify migration plans"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 15; then
print_header "15. AST-GREP RULE PACK FINDINGS"
if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
  run_ast_rules || true
  say "${DIM}${INFO} Above JSON/SARIF lines are ast-grep matches (id, message, severity, file/pos).${RESET}"
  if [[ "$FORMAT" == "sarif" ]]; then
    say "${DIM}${INFO} Tip: ${BOLD}${AST_GREP_CMD[*]} scan -r $AST_RULE_DIR \"$PROJECT_DIR\" --sarif > report.sarif${RESET}"
  fi
else
  say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: BUILD HEALTH (Maven/Gradle best-effort)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 16; then
print_header "16. BUILD HEALTH (Maven/Gradle)"
print_category "Runs: compile/test-compile tasks; optional lint tasks if configured" \
  "Ensures the project compiles; inventories warnings/errors"

if [[ "$RUN_BUILD" -eq 1 ]]; then
  # Maven compile
  if [[ "$HAS_MAVEN" -eq 1 && -f "$PROJECT_DIR/pom.xml" ]]; then
    MVN_BIN="${MVNW:-mvn}"
    MVN_LOG="$(mktemp)"
    run_cmd_log "$MVN_LOG" bash -lc "cd \"$PROJECT_DIR\" && \"$MVN_BIN\" -q -e -T1C -DskipTests=true -DskipITs=true -Dmaven.test.skip.exec=true -Dspotbugs.skip=true -Dpmd.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -Dgpg.skip=true -Dlicense.skip=true -Drat.skip=true -Djacoco.skip=true -Danimal.sniffer.skip=true -Dskip.npm -Dskip.yarn -Dskip.node -DskipFrontend -Dfrontend.skip=true -U -B compile"
    mvn_ec=$(cat "$MVN_LOG.ec" 2>/dev/null || echo 0)
    w_e=$(count_warnings_errors_text "$MVN_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
    if [[ "$mvn_ec" -ne 0 || "$e" -gt 0 ]]; then print_finding "critical" "$e" "Maven compile errors detected"; else print_finding "good" "Maven compile OK"; fi
    if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Maven compile warnings"; fi
  fi

  # Gradle compile
  if [[ "$HAS_GRADLE" -eq 1 && ( -f "$PROJECT_DIR/build.gradle" || -f "$PROJECT_DIR/build.gradle.kts" ) ]]; then
    GR_BIN="${GRADLEW:-gradle}"
    GR_TASKS="$(mktemp)"
    run_cmd_log "$GR_TASKS" bash -lc "cd \"$PROJECT_DIR\" && \"$GR_BIN\" --no-daemon -q tasks --all"
    GR_LOG="$(mktemp)"
    run_cmd_log "$GR_LOG" bash -lc "cd \"$PROJECT_DIR\" && \"$GR_BIN\" --no-daemon -q classes testClasses -x test"
    gr_ec=$(cat "$GR_LOG.ec" 2>/dev/null || echo 0)
    w_e=$(count_warnings_errors_text "$GR_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
    if [[ "$gr_ec" -ne 0 || "$e" -gt 0 ]]; then print_finding "critical" "$e" "Gradle compile errors detected"; else print_finding "good" "Gradle compile OK"; fi
    if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Gradle compile warnings"; fi

    # Try optional lint tasks if they exist
    if grep -q "checkstyleMain" "$GR_TASKS"; then
      CS_LOG="$(mktemp)"; run_cmd_log "$CS_LOG" bash -lc "cd \"$PROJECT_DIR\" && \"$GR_BIN\" --no-daemon -q checkstyleMain -x test"
      w_e=$(count_warnings_errors_text "$CS_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
      if [[ "$e" -gt 0 ]]; then print_finding "warning" "$e" "Checkstyle issues (Gradle)"; fi
    fi
    if grep -q "pmdMain" "$GR_TASKS"; then
      PMD_LOG="$(mktemp)"; run_cmd_log "$PMD_LOG" bash -lc "cd \"$PROJECT_DIR\" && \"$GR_BIN\" --no-daemon -q pmdMain -x test"
      w_e=$(count_warnings_errors_text "$PMD_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
      if [[ "$e" -gt 0 || "$w" -gt 0 ]]; then print_finding "warning" "$((w+e))" "PMD issues (Gradle)"; fi
    fi
    if grep -q "spotbugsMain" "$GR_TASKS"; then
      SB_LOG="$(mktemp)"; run_cmd_log "$SB_LOG" bash -lc "cd \"$PROJECT_DIR\" && \"$GR_BIN\" --no-daemon -q spotbugsMain -x test"
      if grep -qi "bug" "$SB_LOG"; then
        sb_cnt=$(grep -i "bug" "$SB_LOG" | wc -l | awk '{print $1+0}')
        print_finding "warning" "$sb_cnt" "SpotBugs reported potential issues"
      fi
    fi
  fi
else
  print_finding "info" 1 "Build checks disabled (--no-build)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: META STATISTICS & INVENTORY
# ═══════════════════════════════════════════════════════════════════════════
if should_run 17; then
print_header "17. META STATISTICS & INVENTORY"
print_category "Detects: project type (Maven/Gradle), Java version" \
  "High-level overview of the project"

proj_type="Unknown"
if [[ -f "$PROJECT_DIR/pom.xml" ]]; then proj_type="Maven"; fi
if [[ -f "$PROJECT_DIR/build.gradle" || -f "$PROJECT_DIR/build.gradle.kts" ]]; then proj_type="Gradle"; fi
say "  ${BLUE}${INFO} Info${RESET} ${WHITE}(project:${RESET} ${CYAN}${proj_type}${RESET}${WHITE}, java:${RESET} ${CYAN}${JAVA_VERSION_STR:-unknown}${RESET}${WHITE})${RESET}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 18: MISC API MISUSE
# ═══════════════════════════════════════════════════════════════════════════
if should_run 18; then
print_header "18. MISC API MISUSE"
print_category "Detects: System.runFinalizersOnExit, Thread.stop, setAccessible(true)" \
  "Legacy and unsafe APIs"

print_subheader "Legacy/unsafe API calls"
finalizers=$("${GREP_RN[@]}" -e "System\.runFinalizersOnExit\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
thread_stop=$("${GREP_RN[@]}" -e "Thread\.stop\(|Thread\.suspend\(|Thread\.resume\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
set_access=$("${GREP_RN[@]}" -e "\.setAccessible\(\s*true\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$finalizers" -gt 0 ]; then print_finding "critical" "$finalizers" "System.runFinalizersOnExit used - do not use"; fi
if [ "$thread_stop" -gt 0 ]; then print_finding "critical" "$thread_stop" "Thread.stop/suspend/resume used - unsafe"; fi
if [ "$set_access" -gt 0 ]; then print_finding "info" "$set_access" "setAccessible(true) used - restrict usage"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: RESOURCE SAFETY & RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_run 19; then
print_header "19. RESOURCE SAFETY & RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: stream/reader/writer creation; nudge toward try-with-resources" \
  "Prefer try-with-resources to ensure deterministic close()"

print_subheader "I/O stream/reader/writer instantiations (audit for try-with-resources)"
io_ctor=$("${GREP_RN[@]}" -e "new[[:space:]]+(File(Input|Output)Stream|FileReader|FileWriter|Buffered(Input|Output)Stream|Buffered(Reader|Writer)|InputStreamReader|OutputStreamWriter|PrintWriter|Scanner)\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$io_ctor" -gt 0 ]; then
  print_finding "info" "$io_ctor" "I/O constructors present - ensure try-with-resources"
  show_detailed_finding "new[[:space:]]+(File(Input|Output)Stream|FileReader|FileWriter|Buffered(Input|Output)Stream|Buffered(Reader|Writer)|InputStreamReader|OutputStreamWriter|PrintWriter|Scanner)\s*\(" 5
else
  print_finding "good" "No I/O constructors detected"
fi

print_subheader "ExecutorService shutdown tracking"
exec_leak=$("${GREP_RN[@]}" -e "ExecutorService[[:space:]]+[A-Za-z0-9_]+[[:space:]]*=\s*Executors\." "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$exec_leak" -gt 0 ]; then
  print_finding "warning" "$exec_leak" "ExecutorService created without shutdown" "Call shutdown()/shutdownNow() in finally blocks"
  show_detailed_finding "ExecutorService[[:space:]]+[A-Za-z0-9_]+[[:space:]]*=\s*Executors\." 3
fi

run_resource_lifecycle_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 20: PATH HANDLING & FILESYSTEM
# ═══════════════════════════════════════════════════════════════════════════
if should_run 20; then
print_header "20. PATH HANDLING & FILESYSTEM"
print_category "Detects: Paths.get with '+', unchecked delete(), risky temp file patterns" \
  "Use platform-safe composition and verify filesystem effects"

print_subheader "Paths.get with '+' concatenation"
paths_plus=$(( $(ast_search 'java.nio.file.Paths.get($A + $B)' || echo 0) + $("${GREP_RN[@]}" -e "Paths\.get\([^)]*\+[^)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$paths_plus" -gt 0 ]; then print_finding "info" "$paths_plus" "Paths.get with '+' - prefer resolve()/varargs"; fi

print_subheader "Unchecked File.delete()"
del_unchecked=$("${GREP_RN[@]}" -e "\.delete\(\)\s*;" "$PROJECT_DIR" 2>/dev/null | (grep -vE "if\s*\(|assert|check|ensure|\\?:" || true) | count_lines)
if [ "$del_unchecked" -gt 0 ]; then print_finding "info" "$del_unchecked" "File.delete() return value not checked"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 21: HARD-CODED SECRETS (heuristics)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 21; then
print_header "21. HARD-CODED SECRETS (HEURISTICS)"
print_category "Detects: string literals bound to secret-like identifiers" \
  "Avoid storing secrets in source; prefer env/secret manager"

print_subheader "Probable hard-coded secrets"
secrets_ast=$(ast_search 'String $K = $V;' || echo 0)
secrets_rg=$("${GREP_RNI[@]}" -e "(password|passwd|pwd|secret|token|api[_-]?key|auth|credential)[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
secrets_total=$(( secrets_ast + secrets_rg ))
if [ "$secrets_total" -gt 0 ]; then print_finding "warning" "$secrets_total" "Potential hard-coded secrets found"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 22: LOGGING BEST PRACTICES (SLF4J-style)
# ═══════════════════════════════════════════════════════════════════════════
if should_run 22; then
print_header "22. LOGGING BEST PRACTICES"
print_category "Detects: concatenation in logger calls, Throwable lost at end" \
  "Prefer parameterized logging; include Throwable as last argument"

print_subheader "Logger calls with concatenation (extended)"
log_concat_more=$("${GREP_RN[@]}" -e "\.(trace|debug|info|warn|error)\s*\([^)]*\+[^)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$log_concat_more" -gt 0 ]; then print_finding "info" "$log_concat_more" "Concatenation in log calls - use placeholders"; fi

print_subheader "Logger calls with Throwable not last (heuristic)"
log_throwable_pos=$("${GREP_RN[@]}" -e "\.(trace|debug|info|warn|error)\s*\(.*Throwable[[:space:]]*,[[:space:]]*[^)]*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$log_throwable_pos" -gt 0 ]; then print_finding "info" "$log_throwable_pos" "Throwable not last in logger call"; fi
fi

# restore pipefail
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
END_TS="$(now)"
say "${DIM}Scan completed at: ${END_TS}${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to CI: ./ubs --ci --fail-on-warning . > java-bug-scan.txt${RESET}"
echo ""

if [[ "$FORMAT" == "json" ]]; then
  emit_json_summary
fi

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
IFS=${ORIG_IFS}
exit "$EXIT_CODE"
