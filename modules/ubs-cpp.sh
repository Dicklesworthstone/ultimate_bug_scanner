#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE C++ BUG SCANNER v7.0 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern C++ (C++20+) using ast-grep
# + smart regex/ripgrep heuristics and CMake build hygiene checks.
# Detects: RAII violations, lifetime bugs, exception pitfalls, concurrency
# hazards, UB-prone code, preprocessor traps, modernization gaps, and more.
# v7.0 adds: single-pass ast-grep with cached JSON, path-list aware scanning,
# stronger regexes, mac/BSD portability, fixed min/max regex, ruleset expansion,
# detail wrappers, category list command, and correctness/robustness fixes.
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob

# Predefine colors in case an early ERR trap fires before normal init
RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
BOLD=''; DIM=''; RESET=''

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
fi

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; HAMMER="🔧"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif|counts
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="cpp,cc,cxx,cppm,mpp,ixx,h,hpp,hxx,hh,ipp,tpp"
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
RESPECT_GITIGNORE=1
SCAN_HIDDEN=0
MAX_FILESIZE=""
PATHS_FILE=""
LIST_CATS=0

# Async error coverage metadata
ASYNC_ERROR_RULE_IDS=(cpp.async.std-async-no-try cpp.async.future-no-get)
declare -A ASYNC_ERROR_SUMMARY=(
  [cpp.async.std-async-no-try]='std::async call outside try/catch'
  [cpp.async.future-no-get]='std::future never get()/wait()'
)
declare -A ASYNC_ERROR_REMEDIATION=(
  [cpp.async.std-async-no-try]='Wrap std::async usage in try/catch to surface exceptions'
  [cpp.async.future-no-get]='Call future.get()/wait() (ideally inside try/catch) to observe errors'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [cpp.async.std-async-no-try]='warning'
  [cpp.async.future-no-get]='warning'
)

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif|counts (default: text)
  --list-categories        Print numeric category map and exit
  --counts                 Output only per-category counts (machine-friendly)
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: ${INCLUDE_EXT})
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --only=CSV               Run only these categories (e.g. --only=1,7,12)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --respect-gitignore[=0|1]  Respect VCS ignore (default: 1)
  --hidden[=0|1]           Scan hidden files/dirs (default: 0)
  --max-filesize=SIZE      Max file size for rg (e.g. 1M, 5M)
  --paths-from=FILE        Read newline-separated files to scan
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
    --list-categories) LIST_CATS=1; shift;;
    --counts)     FORMAT="counts"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --respect-gitignore=*) RESPECT_GITIGNORE="${1#*=}"; shift;;
    --respect-gitignore)   RESPECT_GITIGNORE=1; shift;;
    --hidden=*)   SCAN_HIDDEN="${1#*=}"; shift;;
    --hidden)     SCAN_HIDDEN=1; shift;;
    --max-filesize=*) MAX_FILESIZE="${1#*=}"; shift;;
    --paths-from=*) PATHS_FILE="${1#*=}"; shift;;
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

# Early list-categories helper
if [[ "${LIST_CATS:-0}" -eq 1 ]]; then
  cat <<CATS
1  Memory & RAII
2  Exceptions & Error Handling
3  Concurrency & Atomics
4  Modernization (C++20+)
5  Pointer & Lifetime Hazards
6  Numeric & Arithmetic Pitfalls
7  Undefined Behavior Risk Zone
8  Header & Include Hygiene
9  STL & Algorithms
10 String & I/O Safety
11 Macros & Preprocessor Traps
12 CMake & Build Hygiene
13 Code Quality Markers
14 Performance & Allocation Pressure
15 Test/Debug Leftovers
16 Resource Lifecycle Correlation
AST AST-Grep Rule Pack Findings
CATS
  exit 0
fi

# Redirect output early to capture everything
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

DATE_FMT='%Y-%m-%d %H:%M:%S'
now_iso()   { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
now_local() { date "+${DATE_FMT}"; }
now()       { if [[ "$CI_MODE" -eq 1 ]]; then now_iso; else now_local; fi; }

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
ASTG_VERSION=""
AST_JSON_FILE=""

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(thread_join malloc_heap fopen_handle)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [thread_join]="warning"
  [malloc_heap]="warning"
  [fopen_handle]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [thread_join]='std::thread'
  [malloc_heap]='\b(malloc|calloc|realloc)\('
  [fopen_handle]='fopen\('
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [thread_join]='\.join\('
  [malloc_heap]='free\('
  [fopen_handle]='fclose\('
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [thread_join]='std::thread started without join/detach'
  [malloc_heap]='malloc/calloc/realloc without free'
  [fopen_handle]='fopen without fclose'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [thread_join]='Join or detach std::thread instances to avoid std::terminate'
  [malloc_heap]='Balance heap allocations with free() or prefer smart pointers'
  [fopen_handle]='Track FILE* handles and call fclose() or wrap in RAII'
)

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep) + include/exclude
# ────────────────────────────────────────────────────────────────────────────
LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done
EXCLUDE_DIRS=(.git .svn .hg build cmake-build-* out dist bin lib obj target .vscode .vs .cache .idea _deps third_party vendor bazel-*)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null 2>&1 && nproc) || sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename "${RG_JOBS[@]}")
  [[ "$RESPECT_GITIGNORE" -eq 1 ]] || RG_BASE+=( --no-ignore --no-ignore-parent --no-ignore-vcs )
  [[ "$SCAN_HIDDEN" -eq 1 ]] && RG_BASE+=( --hidden )
  [[ -n "$MAX_FILESIZE" ]] && RG_BASE+=( --max-filesize "$MAX_FILESIZE" )
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

# Targets placeholder; populated after SCAN_PATHS is finalized
TARGETS=()

# ─── Unified search wrappers (path-list aware) ─────────────────────────────
run_search_raw() { "${GREP_RN[@]}" -e "$1" "${TARGETS[@]}" 2>/dev/null || true; }
run_search_raw_i() { "${GREP_RNI[@]}" -e "$1" "${TARGETS[@]}" 2>/dev/null || true; }
search_count() { run_search_raw "$1" | count_lines; }
search_count_i() { run_search_raw_i "$1" | count_lines; }
search_files_for() { run_search_raw "$1" | cut -d: -f1 | sort -u || true; }
search_show() { local p=$1; local n=${2:-$DETAIL_LIMIT}; run_search_raw "$p" | head -n "$n"; }

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
  search_show "$pattern" "$limit" | while IFS=: read -r file line code; do
    [[ -z "$file" ]] && continue
    print_code_sample "$file" "$line" "$code"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done || true
}

run_resource_lifecycle_checks() {
  local header_shown=0
  local rid
  for rid in "${RESOURCE_LIFECYCLE_IDS[@]}"; do
    local acquire_regex="${RESOURCE_LIFECYCLE_ACQUIRE[$rid]:-}"
    local release_regex="${RESOURCE_LIFECYCLE_RELEASE[$rid]:-}"
    [[ -z "$acquire_regex" || -z "$release_regex" ]] && continue
    local file_list
    file_list=$(search_files_for "$acquire_regex")
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
  local files has_issues=0
  files=$(search_files_for "std::async[[:space:]]*\\(")
  if [[ -z "$files" ]]; then
    print_finding "good" "No std::async usage detected"
    return
  fi
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    local future_count get_count
    future_count=$("${GREP_RN[@]}" -e "std::future" "$file" 2>/dev/null | count_lines || true)
    get_count=$("${GREP_RN[@]}" -e "\\.get[[:space:]]*\\(" "$file" 2>/dev/null | count_lines || true)
    if (( future_count > 0 && get_count == 0 )); then
      has_issues=1
      local rel="${file#"$PROJECT_DIR"/}"
      print_finding "warning" 1 "std::future from std::async without get()" "Call get()/wait() on futures to surface exceptions ($rel)"
    fi
  done <<<"$files"
  if [[ $has_issues -eq 0 ]]; then
    print_finding "good" "std::async usage appears guarded"
  fi
}

# Temporarily relax pipefail for grep-heavy scans
begin_scan_section(){
  if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi
  set +e
}
end_scan_section(){
  set -e
  if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep: detection, rule packs, and wrappers (C++ heavy)
# ────────────────────────────────────────────────────────────────────────────

check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; fi
  if [[ "$HAS_AST_GREP" -eq 0 ]] && command -v sg >/dev/null 2>&1; then AST_GREP_CMD=(sg); HAS_AST_GREP=1; fi
  if [[ "$HAS_AST_GREP" -eq 0 ]] && command -v npx >/dev/null 2>&1; then AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; fi
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ASTG_VERSION="$("${AST_GREP_CMD[@]}" --version 2>/dev/null || true)"
    return 0
  fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be skipped.${RESET}"
  say "${DIM}Tip: npm i -g @ast-grep/cli  or  cargo install ast-grep${RESET}"
  HAS_AST_GREP=0; return 1
}

ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang cpp "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

ast_search_with_context() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang cpp "$PROJECT_DIR" --json 2>/dev/null || true ) \
      | head -n "$limit" || true
  fi
}

# Try multiple CLI layouts for scan (backward/forward compatibility)
astg_scan_rules() {
  local fmt="$1" # json|sarif
  local ok=1
  "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" -f "$fmt" 2>/dev/null && ok=0
  if [[ $ok -ne 0 ]]; then "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --"$fmt" 2>/dev/null && ok=0; fi
  if [[ $ok -ne 0 ]]; then "${AST_GREP_CMD[@]}" scan --rules "$AST_RULE_DIR" "$PROJECT_DIR" -f "$fmt" 2>/dev/null && ok=0; fi
  return $ok
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t cpp_ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # ───── Memory & RAII ──────────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-raw-new.yml" <<'YAML'
id: cpp.raw-new
language: cpp
rule:
  any:
    - pattern: new $T($$)
    - pattern: new $T
severity: warning
message: "Raw new detected; prefer std::make_unique/make_shared (RAII)."
YAML

  cat >"$AST_RULE_DIR/cpp-raw-new-array.yml" <<'YAML'
id: cpp.raw-new-array
language: cpp
rule:
  pattern: new $T[$N]
severity: warning
message: "Raw new[] detected; prefer std::vector or std::unique_ptr<T[]>."
YAML

  cat >"$AST_RULE_DIR/cpp-raw-delete.yml" <<'YAML'
id: cpp.raw-delete
language: cpp
rule:
  pattern: delete $X
severity: error
message: "Manual delete; prefer smart pointers or RAII to avoid leaks/UB."
YAML

  cat >"$AST_RULE_DIR/cpp-malloc-free.yml" <<'YAML'
id: cpp.malloc-free
language: cpp
rule:
  any:
    - pattern: malloc($$)
    - pattern: free($$)
severity: warning
message: "C allocation APIs in C++ code; prefer containers or smart pointers."
YAML

  # ───── Exceptions & error handling ────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-throw-in-dtor.yml" <<'YAML'
id: cpp.throw-in-destructor
language: cpp
rule:
  pattern: throw $EX
  inside:
    kind: destructor_definition
severity: error
message: "Throwing in destructor can call std::terminate during stack unwinding."
YAML

  cat >"$AST_RULE_DIR/cpp-catch-by-value.yml" <<'YAML'
id: cpp.catch-by-value
language: cpp
rule:
  pattern: catch ($T $E)
  not:
    has:
      regex: '&'
severity: warning
message: "Catch exceptions by const reference to avoid slicing and copies."
YAML

  cat >"$AST_RULE_DIR/cpp-exception-spec-dynamic.yml" <<'YAML'
id: cpp.dynamic-exception-spec
language: cpp
rule:
  pattern: "throw($$)"
severity: warning
message: "Deprecated dynamic exception specification; use noexcept."
YAML

  cat >"$AST_RULE_DIR/cpp-throw-string.yml" <<'YAML'
id: cpp.throw-string
language: cpp
rule:
  pattern: throw "$TXT"
severity: info
message: "Throwing string literal; prefer exceptions derived from std::exception."
YAML

  cat >"$AST_RULE_DIR/cpp-throw-raw-value.yml" <<'YAML'
id: cpp.throw-raw-value
language: cpp
rule:
  any:
    - pattern: throw 0
    - pattern: throw 1
    - pattern: throw -1
severity: info
message: "Throwing raw value; use typed exceptions."
YAML

  # ───── Concurrency & atomics ─────────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-mutex-lock-unlock.yml" <<'YAML'
id: cpp.manual-mutex-lock
language: cpp
rule:
  any:
    - pattern: $M.lock()
    - pattern: $M.unlock()
severity: warning
message: "Manual lock/unlock; prefer std::lock_guard/std::unique_lock (RAII)."
YAML

  cat >"$AST_RULE_DIR/cpp-async-no-policy.yml" <<'YAML'
id: cpp.async-without-policy
language: cpp
rule:
  pattern: std::async($$)
  not:
    has:
      regex: "std::launch::(async|deferred)"
severity: info
message: "std::async without explicit launch policy can be surprising."
YAML

  cat >"$AST_RULE_DIR/cpp-atomic-relaxed.yml" <<'YAML'
id: cpp.atomic-relaxed
language: cpp
rule:
  any:
    - pattern: std::memory_order_relaxed
    - pattern: std::memory_order_consume
severity: info
message: "Weak memory order; ensure correctness with happens-before."
YAML

  cat >"$AST_RULE_DIR/cpp-c-style-cast.yml" <<'YAML'
id: cpp.c-style-cast
language: cpp
rule:
  kind: c_style_cast_expression
severity: warning
message: "C-style cast; prefer C++-style casts for clarity and safety."
YAML

  # ───── Modernization & best practices ─────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-using-namespace-std-header.yml" <<'YAML'
id: cpp.using-namespace-std-in-header
language: cpp
rule:
  pattern: using namespace std;
severity: warning
message: "Avoid 'using namespace std' especially in headers."
YAML

  cat >"$AST_RULE_DIR/cpp-auto-ptr.yml" <<'YAML'
id: cpp.auto_ptr
language: cpp
rule:
  pattern: std::auto_ptr<$T>
severity: error
message: "std::auto_ptr is removed; use std::unique_ptr."
YAML

  cat >"$AST_RULE_DIR/cpp-bind.yml" <<'YAML'
id: cpp.std-bind
language: cpp
rule:
  pattern: std::bind($$)
severity: info
message: "Prefer lambdas over std::bind for clarity and type safety."
YAML

  cat >"$AST_RULE_DIR/cpp-string-view-from-temporary.yml" <<'YAML'
id: cpp.string_view-from-temporary
language: cpp
rule:
  pattern: std::string_view($X)
severity: warning
message: "Ensure argument outlives string_view to avoid dangling references."
YAML

  cat >"$AST_RULE_DIR/cpp-move-const.yml" <<'YAML'
id: cpp.move-of-const
language: cpp
rule:
  pattern: std::move($X)
  has:
    regex: "const"
severity: warning
message: "std::move on const object does not move; results in a copy."
YAML

  cat >"$AST_RULE_DIR/cpp-move-into-constref.yml" <<'YAML'
id: cpp.move-into-constref
language: cpp
rule:
  pattern: const $T& $N = std::move($X)
severity: warning
message: "Moving into const& has no effect; value will not be moved."
YAML

  cat >"$AST_RULE_DIR/cpp-return-move.yml" <<'YAML'
id: cpp.return-move
language: cpp
rule:
  pattern: return std::move($X);
severity: info
message: "return std::move(x) can inhibit NRVO; prefer 'return x;'"
YAML

  # ───── C APIs & unsafe functions ─────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-unsafe-c-apis.yml" <<'YAML'
id: cpp.unsafe-c-apis
language: cpp
rule:
  any:
    - pattern: gets($$)
    - pattern: strcpy($$)
    - pattern: strcat($$)
    - pattern: sprintf($$)
    - pattern: scanf($$)
severity: error
message: "Unsafe C APIs; prefer safer alternatives (snprintf, std::string, streams, fmt)."
YAML

  cat >"$AST_RULE_DIR/cpp-atoi-family.yml" <<'YAML'
id: cpp.atoi-family
language: cpp
rule:
  any:
    - pattern: atoi($$)
    - pattern: atof($$)
    - pattern: atol($$)
    - pattern: atoll($$)
severity: info
message: "atoi/atof family: prefer std::from_chars or std::stoi with validation."
YAML

  cat >"$AST_RULE_DIR/cpp-rand.yml" <<'YAML'
id: cpp.rand
language: cpp
rule:
  any:
    - pattern: rand()
    - pattern: srand($$)
severity: info
message: "Prefer <random> facilities; rand() has poor quality and shared state."
YAML

  # ───── Lifetime & iterator safety (heuristics) ───────────────────────────
  cat >"$AST_RULE_DIR/cpp-iterator-invalidated-erase.yml" <<'YAML'
id: cpp.erase-in-loop-iterator-use
language: cpp
rule:
  any:
    - pattern: $C.erase($IT)
    - pattern: $C.erase($B, $E)
severity: info
message: "Erasing invalidates iterators; verify loop iteration is safe."
YAML

  cat >"$AST_RULE_DIR/cpp-resource-thread.yml" <<'YAML'
id: cpp.resource.thread-no-join
language: cpp
rule:
  pattern: std::thread $HANDLE($ARGS);
  not:
    inside:
      pattern: $HANDLE.join()
  not:
    inside:
      pattern: $HANDLE.detach()
severity: warning
message: "std::thread created without join()/detach() in the same scope."
YAML

  cat >"$AST_RULE_DIR/cpp-resource-malloc.yml" <<'YAML'
id: cpp.resource.malloc-no-free
language: cpp
rule:
  pattern: $VAR = malloc($ARGS);
  not:
    inside:
      pattern: free($VAR)
severity: warning
message: "malloc assigned to a variable without free() in the same scope."
YAML

  cat >"$AST_RULE_DIR/cpp-return-local-ref.yml" <<'YAML'
id: cpp.return-local-reference
language: cpp
rule:
  pattern: return $X;
  inside:
    kind: function_definition
severity: warning
message: "Returning reference to local or temporary can dangle (heuristic)."
YAML

  # ───── Modules (C++20) & headers ─────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-module-global-fragment-include.yml" <<'YAML'
id: cpp.module-global-fragment-include
language: cpp
rule:
  pattern: module;
severity: info
message: "Global module fragment present; ensure correct include hygiene."
YAML

  # ───── Misc robustness ───────────────────────────────────────────────────
  cat >"$AST_RULE_DIR/cpp-non-virtual-dtor-polymorphic.yml" <<'YAML'
id: cpp.non-virtual-dtor-heuristic
language: cpp
rule:
  pattern: class $C { $$ };
severity: info
message: "If class is polymorphic, ensure virtual destructor (heuristic)."
YAML

  # Additional safety
  cat >"$AST_RULE_DIR/cpp-delete-this.yml" <<'YAML'
id: cpp.delete-this
language: cpp
rule:
  pattern: delete this
severity: error
message: "Deleting this is error-prone and dangerous."
YAML

  cat >"$AST_RULE_DIR/cpp-vector-bool.yml" <<'YAML'
id: cpp.vector-bool
language: cpp
rule:
  pattern: std::vector<bool>
severity: info
message: "std::vector<bool> uses proxy references; be careful with references and addresses."
YAML

  cat >"$AST_RULE_DIR/cpp-unique-reset-raw.yml" <<'YAML'
id: cpp.unique-reset-raw
language: cpp
rule:
  pattern: delete $X; $X = nullptr
severity: info
message: "Use unique_ptr::reset(nullptr) instead of manual delete then null."
YAML

  cat >"$AST_RULE_DIR/cpp-endl.yml" <<'YAML'
id: cpp.std-endl
language: cpp
rule:
  pattern: std::endl
severity: info
message: "std::endl flushes the stream; prefer '\n' unless flushing is required."
YAML
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  local f="json"; [[ "$FORMAT" == "sarif" ]] && f="sarif"
  astg_scan_rules "$f"
}

# Single-pass AST scan to JSON and keep it around for category checks
run_ast_once() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  AST_JSON_FILE="$(mktemp -t ubs_ast_XXXXXX.json)"
  trap '[[ -n "${AST_JSON_FILE:-}" ]] && rm -f "$AST_JSON_FILE" || true' EXIT
  if astg_scan_rules "json" >"$AST_JSON_FILE"; then return 0; fi
  rm -f "$AST_JSON_FILE" || true
  AST_JSON_FILE=""
  return 1
}

ast_count() {
  local id="$1"
  [[ -n "$AST_JSON_FILE" && -f "$AST_JSON_FILE" ]] || { printf '0\n'; return 0; }
  grep -o "\"id\"[[:space:]]*:[[:space:]]*\"${id//\//\\/}\"" "$AST_JSON_FILE" | count_lines
}

# ────────────────────────────────────────────────────────────────────────────
# Category skipping helper
# ────────────────────────────────────────────────────────────────────────────
should_skip() {
  local cat="$1"
  # If ONLY is set, everything not in ONLY is considered skipped
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    IFS=',' read -r -a only_arr <<<"$ONLY_CATEGORIES"
    local in_only=1
    for s in "${only_arr[@]}"; do [[ "$s" == "$cat" ]] && in_only=0; done
    [[ $in_only -eq 0 ]] || return 1
  fi
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
╔══════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗  ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝  ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗    ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝    ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗  ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝  ║
║                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒             ║
║  ██████╗ ██╗   ██╗ ██████╗           ▒▒▒▒▄██████▄▒▒▒             ║
║  ██╔══██╗██║   ██║██╔════╝           ▒▒▒██████████▒▒             ║
║  ██████╔╝██║   ██║██║  ███╗          ▒▒███▀▒▒▒▒▀██▌▒             ║
║  ██╔══██╗██║   ██║██║   ██║          ▒▐██▌▒▒▒▒▒▒▒▒▒▒             ║
║  ██████╔╝╚██████╔╝╚██████╔╝          ▒▐██▌▒▒▒▄█▄▒▄█▄             ║
║  ╚═════╝  ╚═════╝  ╚═════╝           ▒▐██▌▒▒▒▒▀▒▒▒▀▒             ║
║                                      ▒▒███▄▒▒▒▒▄██▌▒             ║
║                                      ▒▒▒██████████▒▒             ║
║                                      ▒▒▒▒▀██████▀▒▒▒             ║
║                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒             ║
║                                                                  ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ║
║                                                                  ║
║  C/C++ module • UB hunts, RAII nudges, sanitizer hygiene         ║
║  UBS module: cpp • AST-grep + clang heuristics for legacy        ║
║  ASCII homage: gear/cog motif (EmojiCombos)                      ║
║  Run standalone: modules/ubs-cpp.sh --help                       ║
║                                                                  ║
║  Night Owl QA                                                    ║
║  “We see bugs before you do.”                                    ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(now)${RESET}"

# Potentially restrict scan to explicit path list
SCAN_PATHS=( "$PROJECT_DIR" )
if [[ -n "$PATHS_FILE" ]]; then
  if [[ -f "$PATHS_FILE" ]]; then
    mapfile -t SCAN_PATHS < <(sed -e 's/\r$//' "$PATHS_FILE" | awk 'NF{print}')
  else
    say "${YELLOW}${WARN} --paths-from file not found: $PATHS_FILE. Falling back to PROJECT_DIR.${RESET}"
    SCAN_PATHS=( "$PROJECT_DIR" )
  fi
fi

# refresh search targets now that SCAN_PATHS is finalized
TARGETS=( "${SCAN_PATHS[@]}" )

# Count files (robust find; avoid dangling -o)
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
  ( set +o pipefail; find "${SCAN_PATHS[@]}" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
  | wc -l | awk '{print $1+0}'
)
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

# ast-grep availability
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  [[ -n "$ASTG_VERSION" ]] && say "${DIM}${INFO} ast-grep version: ${ASTG_VERSION}${RESET}"
  write_ast_rules || true
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: MEMORY & RAII
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. MEMORY & RAII"
print_category "Detects: raw new/delete, C-style casts, const_cast, nullptr misuse, delete[] vs delete" \
  "Manual memory and unsafe casts are primary sources of UB and leaks"

print_subheader "Raw new allocations (prefer make_unique/make_shared)"
count1=$(ast_count "cpp.raw-new")
count2=$(ast_count "cpp.raw-new-array")
total=$((count1 + count2))
if [ "$total" -gt 0 ]; then
  print_finding "warning" "$total" "Raw new/new[] found" "Use std::make_unique/std::make_shared or containers"
  show_detailed_finding "\\bnew[[:space:]]+[A-Za-z_:][A-Za-z0-9_:<>]*" 5
else
  print_finding "good" "No raw new detected"
fi

print_subheader "Manual delete (leaks/double free risk)"
count=$(search_count "(^|[^A-Za-z0-9_])delete[[:space:]]*(\\[\\])?")
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Manual delete/delete[] present" "Prefer RAII via smart pointers or containers"
  show_detailed_finding "\\bdelete(\\[\\])?" 5
else
  print_finding "good" "No delete/delete[] detected"
fi

print_subheader "C-style casts"
count_ast_cstyle=$(ast_count "cpp.c-style-cast")
count=$((count_ast_cstyle))
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "C-style casts used" "Use static_cast/dynamic_cast/reinterpret_cast/const_cast"
  show_detailed_finding "\\([[:space:]]*[A-Za-z_][A-Za-z0-9_:<>]*[[:space:]]*\\)" 5
fi

print_subheader "const_cast/reinterpret_cast (dangerous)"
count=$(search_count "const_cast<|reinterpret_cast<")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Dangerous casts present" "Verify lifetime/aliasing"; fi

print_subheader "NULL used instead of nullptr"
count=$(search_count "\\bNULL\\b")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Use nullptr in C++ code"; fi

fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: EXCEPTIONS & ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 2; then
print_header "2. EXCEPTIONS & ERROR HANDLING"
print_category "Detects: throw in destructor, catch by value, deprecated specs, generic throws" \
  "Exception safety errors cause terminate(), leaks, and slicing"

print_subheader "Throw in destructor"
count=$(ast_count "cpp.throw-in-destructor")
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Throwing in destructor" "May call std::terminate during unwinding"
else
  print_finding "good" "No throws in destructors"
fi

print_subheader "Catch by value (prefer const&)"
count=$(run_search_raw "catch[[:space:]]*\\([[:space:]]*[A-Za-z_:][A-Za-z0-9_:<>]*[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\\)" | (grep -v "&" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Catching exceptions by value" "Use 'catch(const T& e)'"
  show_detailed_finding "catch[[:space:]]*\\([^)]+\\)" 5
fi

print_subheader "Deprecated dynamic exception specification"
count=$(search_count "throw[[:space:]]*\\([[:space:]]*[^)]")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Deprecated 'throw(...)' found" "Use noexcept"; fi

print_subheader "Generic throw types"
count_ast_raw=$(ast_count "cpp.throw-raw-value")
count_ast_str=$(ast_count "cpp.throw-string")
count=$((count_ast_raw + count_ast_str))
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Throwing raw values/strings"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: CONCURRENCY & ATOMICS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 3; then
print_header "3. CONCURRENCY & ATOMICS"
print_category "Detects: manual lock/unlock, async without policy, weak memory orders" \
  "Concurrency bugs are catastrophic under load and hard to reproduce"

print_subheader "Manual mutex lock/unlock (prefer RAII)"
lock_count=$(search_count "\\.lock\\(|\\.unlock\\(")
if [ "$lock_count" -gt 0 ]; then
  print_finding "warning" "$lock_count" "Manual lock/unlock usage" "Use std::lock_guard/std::unique_lock"
  show_detailed_finding "\\.lock\\(|\\.unlock\\(" 5
else
  print_finding "good" "No manual lock/unlock"
fi

print_subheader "std::async without explicit launch policy"
count=$(run_search_raw "std::async[[:space:]]*\\(" | (grep -v "std::launch::" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Async without policy (behavior may vary)"; fi

print_subheader "Weak memory-order usage"
count=$(search_count "memory_order_relaxed|memory_order_consume")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Weak memory order in atomics - verify correctness"; fi

run_async_error_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: MODERNIZATION (C++20+)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 4; then
print_header "4. MODERNIZATION (C++20+)"
print_category "Detects: using-namespace in headers, removed types, bind, nullptr, modules" \
  "Keeps codebase aligned with modern idioms & readability"

print_subheader "'using namespace std;' especially in headers"
count=$(search_count "using[[:space:]]+namespace[[:space:]]+std")
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "using namespace std found" "Avoid polluting global namespace"
  show_detailed_finding "using[[:space:]]+namespace[[:space:]]+std" 5
fi

print_subheader "Removed/legacy types: std::auto_ptr"
count=$(search_count "std::auto_ptr<")
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "std::auto_ptr used (removed)"; fi

print_subheader "std::bind (prefer lambdas)"
count=$(search_count "std::bind[[:space:]]*\\(")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "std::bind present - lambdas are clearer"; fi

print_subheader "Modules/global module fragment presence"
count=$(search_count "^[[:space:]]*module;|^[[:space:]]*export[[:space:]]+module")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "C++20 Modules in use - verify partition & BMI strategy"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: POINTER & LIFETIME HAZARDS (Heuristics)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 5; then
print_header "5. POINTER & LIFETIME HAZARDS"
print_category "Detects: string_view from temporary, return local ref, move-of-const" \
  "Lifetime bugs compile fine and explode at runtime"

print_subheader "std::string_view from temporary"
count=$(run_search_raw "std::string_view[[:space:]]*\\(" | (grep -v "&" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Potential dangling string_view (heuristic)"; fi

print_subheader "Returning reference/value risks (heuristic)"
count=$(search_count "return[[:space:]]*&[[:space:]]*[A-Za-z_]")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Return by reference - verify lifetime"; fi

print_subheader "std::move on const"
count=$(search_count "std::move[[:space:]]*\\([^)]*\\bconst\\b")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "std::move(const T) is a copy, not a move"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: NUMERIC & ARITHMETIC PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. NUMERIC & ARITHMETIC PITFALLS"
print_category "Detects: division by variable, integer overflow-prone code, fp equality" \
  "Silent overflows/fp comparisons trigger logic bugs and UB"

print_subheader "Division by variable (check non-zero)"
count=$(run_search_raw "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" | (grep -Ev "/[[:space:]]*(2|10|100|1000)\\b|//|/\\*" || true) | count_lines)
if [ "$count" -gt 15 ]; then
  print_finding "warning" "$count" "Division by variable - add guards"
  show_detailed_finding "/[[:space:]]*[A-Za-z_][A-Za-z0-9_]*" 5
fi

print_subheader "Floating-point equality checks"
count=$(search_count "==[[:space:]]*[0-9]+\\.[0-9]+")
if [ "$count" -gt 3 ]; then print_finding "info" "$count" "Floating-point equality - prefer epsilon comparison"; fi

print_subheader "Modulo by variable"
count=$(search_count "%[[:space:]]*[A-Za-z_][A-Za-z0-9_]*")
if [ "$count" -gt 10 ]; then print_finding "info" "$count" "Modulo by variable - ensure non-zero"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: UNDEFINED BEHAVIOR RISK ZONE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. UNDEFINED BEHAVIOR RISK ZONE"
print_category "Detects: dangerous casts, unsafe C APIs, dangling, delete mismatch" \
  "UB can pass tests and still crash in production"

print_subheader "Dangerous functions (strcpy/gets/scanf/sprintf)"
count=$(search_count "\\b(gets|strcpy|strcat|sprintf|scanf)\\s*\\(")
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Unsafe C APIs present" "Use safer std/fmt equivalents"
  show_detailed_finding "\\b(gets|strcpy|strcat|sprintf|scanf)\\s*\\(" 5
else
  print_finding "good" "No unsafe C APIs found"
fi

print_subheader "reinterpret_cast/const_cast occurrences"
count=$(search_count "reinterpret_cast<|const_cast<")
if [ "$count" -gt 5 ]; then print_finding "warning" "$count" "Many low-level casts - scrutinize for UB"; fi

print_subheader "delete vs delete[] mismatch (heuristic)"
count=$(search_count "(^|[^A-Za-z0-9_])delete[[:space:]]*(\\[\\])?[[:space:]]*[A-Za-z_][A-Za-z0-9_]*")
if [ "$count" -gt 2 ]; then print_finding "info" "$count" "Verify delete/delete[] matches allocation form"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: HEADER & INCLUDE HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. HEADER & INCLUDE HYGIENE"
print_category "Detects: using-namespace in headers, C headers, excessive includes, pragma once" \
  "Header hygiene prevents ODR violations and compile-time blow-ups"

print_subheader "Header guards or #pragma once missing (heuristic)"
{
  mapfile -t _hdrs < <( set +o pipefail; find "${SCAN_PATHS[@]}" "${EX_PRUNE[@]}" -o \( -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hh" -o -name "*.hxx" \) -print \) 2>/dev/null || true )
  if ((${#_hdrs[@]}==0)); then count=0; else
    count=$(
      for f in "${_hdrs[@]}"; do
        head -n 50 "$f" | grep -Eq "#pragma once|#ifndef|#if[[:space:]]+!defined" || echo "$f"
      done | count_lines
    )
  fi
}
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Headers missing guard/#pragma once (heuristic)"
fi

print_subheader "C headers included in C++"
count=$(search_count "#include[[:space:]]*<(stdio|stdlib|string|math)\\.h>")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Prefer <cstdio>/<cstdlib>/<cstring>/<cmath>"; fi

print_subheader "using namespace std in headers"
{
  mapfile -t _hdrs2 < <( set +o pipefail; find "${SCAN_PATHS[@]}" "${EX_PRUNE[@]}" -o \( -type f \( -name "*.h" -o -name "*.hpp" -o -name "*.hh" -o -name "*.hxx" \) -print \) 2>/dev/null || true )
  if ((${#_hdrs2[@]}==0)); then count=0; else
    count=$(
      "${GREP_RN[@]}" -e "using[[:space:]]+namespace[[:space:]]+std" "${_hdrs2[@]}" 2>/dev/null | count_lines
    )
  fi
}
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "using namespace std in headers is harmful"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: STL & ALGORITHMS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. STL & ALGORITHMS"
print_category "Detects: erase invalidation, std::move misuse, std::bind, raw loops" \
  "Make idiomatic use of algorithms to reduce bugs"

print_subheader "erase while iterating (invalidates iterators)"
count=$(search_count "\\.erase\\([[:space:]]*[A-Za-z_]|\\.erase\\([[:space:]]*begin|\\.erase\\([[:space:]]*end")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Verify loop structure when erasing from containers"; fi

print_subheader "Manual loops where algorithm fits (heuristic)"
count=$(search_count "for[[:space:]]*\\([^)]+;[^)^:]*;[^\\)]+\\)")
if [ "$count" -gt 20 ]; then print_finding "info" "$count" "Consider ranges/algorithms instead of index loops"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: STRING & I/O SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 10; then
print_header "10. STRING & I/O SAFETY"
print_category "Detects: printf-family, dangerous scanf formats, fmt migration" \
  "Type-safety and format correctness prevent latent crashes"

print_subheader "printf/scanf/sprintf family usage"
count=$(search_count "\\b(printf|fprintf|sprintf|snprintf|scanf|sscanf)\\s*\\(")
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "C-format APIs in C++" "Prefer std::format/fmt for type-safe formatting"
  show_detailed_finding "\\b(printf|fprintf|sprintf|snprintf|scanf|sscanf)\\s*\\(" 5
fi

print_subheader "std::endl usage"
endl_ast=$(ast_count "cpp.std-endl")
if [ "$endl_ast" -gt 0 ]; then print_finding "info" "$endl_ast" "std::endl flushes the stream; prefer '\\n' unless flushing"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: MACROS & PREPROCESSOR TRAPS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. MACROS & PREPROCESSOR TRAPS"
print_category "Detects: min/max macros, debug leftovers, macro side effects" \
  "Macros can silently rewrite code and cause ODR/symbol issues"

print_subheader "min/max macro definitions"
count=$(search_count "#[[:space:]]*define[[:space:]]+min\\(|#[[:space:]]*define[[:space:]]+max\\(")
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "min/max macros detected - conflict with std::min/std::max"; fi

print_subheader "DEBUG/TRACE macros enabled (heuristic)"
count=$(search_count "#[[:space:]]*define[[:space:]]+(DEBUG|TRACE|VERBOSE)")
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Debug macros enabled"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: CMAKE & BUILD HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 12; then
print_header "12. CMAKE & BUILD HYGIENE"
print_category "Detects: non-C++20 standard settings, missing warnings, no sanitizers, RTTI/exceptions flags" \
  "Build settings are part of correctness and performance"

print_subheader "CMAKE_CXX_STANDARD and target_compile_features"
cxxstd=$(search_count "CMAKE_CXX_STANDARD|target_compile_features")
if [ "$cxxstd" -eq 0 ]; then
  print_finding "info" 1 "CMake lacks explicit C++ standard settings" "Set CMAKE_CXX_STANDARD 20 and/or target_compile_features(... cxx_std_20)"
else
  print_finding "info" "$cxxstd" "C++ standard declarations present"
fi

print_subheader "Warnings enabled (-Wall -Wextra -Wpedantic)"
warns=$(search_count "(-Wall|-Wextra|-Wpedantic)")
if [ "$warns" -eq 0 ]; then print_finding "info" 1 "No common warnings in CMake found"; else print_finding "good" "Common warnings appear enabled"; fi

print_subheader "Sanitizers configured (ASan/UBSan)"
san=$(search_count "fsanitize=(address|undefined)")
if [ "$san" -eq 0 ]; then print_finding "info" 1 "No sanitizers detected in CMake"; else print_finding "good" "Sanitizers appear configured"; fi

print_subheader "Exceptions/RTTI disabled?"
flags=$(search_count "fno-exceptions|fno-rtti")
if [ "$flags" -gt 0 ]; then print_finding "info" "$flags" "fno-exceptions/RTTI used - verify library requirements"; fi

print_subheader "Position Independent Code and LTO (optional)"
pic=$(search_count "POSITION_INDEPENDENT_CODE|-fPIC")
lto=$(search_count "INTERPROCEDURAL_OPTIMIZATION|flto")
if [ "$pic" -eq 0 ]; then print_finding "info" 1 "PIC not detected (fine for static, check for shared libs)"; fi
if [ "$lto" -eq 0 ]; then print_finding "info" 1 "LTO not detected (optional)"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: CODE QUALITY MARKERS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 13; then
print_header "13. CODE QUALITY MARKERS"
print_category "Detects: TODO, FIXME, HACK, XXX comments" \
  "Technical debt markers indicate areas needing attention"

todo_count=$("${GREP_RNI[@]}" "TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fixme_count=$("${GREP_RNI[@]}" "FIXME" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
hack_count=$("${GREP_RNI[@]}" "HACK" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
xxx_count=$("${GREP_RNI[@]}" "XXX" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
note_count=$("${GREP_RNI[@]}" "NOTE" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
todo_count=$(printf '%s\n' "$todo_count" | awk 'END{print $0+0}')
fixme_count=$(printf '%s\n' "$fixme_count" | awk 'END{print $0+0}')
hack_count=$(printf '%s\n' "$hack_count" | awk 'END{print $0+0}')
xxx_count=$(printf '%s\n' "$xxx_count" | awk 'END{print $0+0}')
note_count=$(printf '%s\n' "$note_count" | awk 'END{print $0+0}')

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
# CATEGORY 14: PERFORMANCE & ALLOCATION PRESSURE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 14; then
print_header "14. PERFORMANCE & ALLOCATION PRESSURE"
print_category "Detects: tight-loop string concatenation, many small allocations, I/O in loops" \
  "Performance bugs degrade latency and throughput"

print_subheader "String concatenation in tight loops (+=)"
count=$("${GREP_RN[@]}" -e "for|while" "${TARGETS[@]}" 2>/dev/null | (grep -A3 "\\+=" || true) | (grep -cw "\\+=" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 8 ]; then print_finding "info" "$count" "String += in loops - consider reserve/ostringstream/fmt::memory_buffer"; fi

print_subheader "I/O in loops (heuristic)"
count=$("${GREP_RN[@]}" -e "for|while" "${TARGETS[@]}" 2>/dev/null \
  | (grep -A5 -E "std::cout|std::cerr|printf|fprintf|std::printf" || true) \
  | (grep -c -E "cout|cerr|printf" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then print_finding "info" "$count" "I/O inside loops - buffer or batch"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: TEST/DEBUG LEFTOVERS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 15; then
print_header "15. TEST/DEBUG LEFTOVERS"
print_category "Detects: assert/abort left enabled, debug prints" \
  "Debug artifacts can affect performance and user experience"

print_subheader "assert/abort present"
count=$("${GREP_RN[@]}" -e "\\bassert\\s*\\(|\\babort\\s*\\(" "${TARGETS[@]}" 2>/dev/null | count_lines)
if [ "$count" -gt 50 ]; then print_finding "warning" "$count" "Many asserts/abort calls - ensure controlled by NDEBUG"; fi

print_subheader "Debug prints (std::cout/cerr)"
cout_count=$("${GREP_RN[@]}" -e "std::cout|std::cerr" "${TARGETS[@]}" 2>/dev/null | count_lines)
if [ "$cout_count" -gt 50 ]; then print_finding "info" "$cout_count" "Many std::cout/cerr statements - consider a logging library"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: std::thread spawn w/o join, malloc/calloc without free, fopen without fclose" \
  "Manual resources must be paired with cleanup to avoid leaks and crashes"

run_resource_lifecycle_checks
fi

# ═══════════════════════════════════════════════════════════════════════════
# AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough)
# ═══════════════════════════════════════════════════════════════════════════
if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
  print_header "AST-GREP RULE PACK FINDINGS"
  # Run once to JSON for category lookups and summaries
  run_ast_once || true
  if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
    if [[ "$FORMAT" == "json" && -n "$AST_JSON_FILE" && -f "$AST_JSON_FILE" ]]; then
      cat "$AST_JSON_FILE"
    elif run_ast_rules; then :; else
      say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
    fi
    say "${DIM}${INFO} Above lines are ast-grep matches (id, message, severity, file/pos).${RESET}"
  else
    # Show short textual summary by running JSON and summarizing counts by id.
    if [[ -n "$AST_JSON_FILE" && -f "$AST_JSON_FILE" ]]; then
      say "${DIM}${INFO} ast-grep produced structured matches. Showing brief tally by rule id:${RESET}"
      ids=$(grep -o '"id"[:][ ]*"[^"]*"' "$AST_JSON_FILE" | sed -E 's/.*"id"[ ]*:[ ]*"([^"]*)".*/\1/' || true)
      if [[ -n "$ids" ]]; then
        printf "%s\n" "$ids" | sort | uniq -c | awk '{printf "  • %-40s %5d\n",$2,$1}'
      else
        say "  (no matches)"
      fi
    else
      say "${YELLOW}${WARN} ast-grep scan subcommand unavailable; rule-pack mode skipped.${RESET}"
    fi
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

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning . > cpp-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi

# Optional machine-readable counts format for CI parsers
if [[ "$FORMAT" == "counts" ]]; then
  echo "files=$TOTAL_FILES critical=$CRITICAL_COUNT warning=$WARNING_COUNT info=$INFO_COUNT"
fi

exit "$EXIT_CODE"
