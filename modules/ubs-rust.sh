#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# RUST ULTIMATE BUG SCANNER v1.1 - Industrial-Grade Rust Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for Rust using ast-grep + semantic patterns
# + cargo-driven checks (check, clippy, fmt, audit, deny, udeps, outdated)
# Focus: Ownership/borrowing pitfalls, error handling, async/concurrency,
# unsafe/raw operations, performance/memory, security, code quality.
#
# Features:
#   - Colorful, CI-friendly TTY output with NO_COLOR support
#   - Robust find/rg search with include/exclude globs
#   - Heuristics + AST rule packs (Rust language) written on-the-fly
#   - JSON/SARIF passthrough from ast-grep rule scans
#   - Category skip/selection, verbosity, sample snippets
#   - Parallel jobs for ripgrep
#   - Exit on critical or optionally on warnings
#   - Optional JSON summary & flexible failure thresholds
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe
shopt -s extglob

# ---------------------------------------------------------------------------
# Centralized cleanup & robust error handler
# ---------------------------------------------------------------------------
TMP_FILES=()
AST_RULE_DIR=""
cleanup() {
  local ec=$?
  if [[ -n "${AST_RULE_DIR:-}" && -d "$AST_RULE_DIR" ]]; then rm -rf "$AST_RULE_DIR" || true; fi
  if [[ ${#TMP_FILES[@]} -gt 0 ]]; then for f in "${TMP_FILES[@]}"; do [[ -e "$f" ]] && rm -f "$f" || true; done; fi
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

# ────────────────────────────────────────────────────────────────────────────
# Color / Icons
# ────────────────────────────────────────────────────────────────────────────
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

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; WRENCH="🛠"; ROCKET="🚀"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif (text implemented; ast-grep emits json/sarif in rule-pack mode)
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="rs"
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
RUN_CARGO=1
CARGO_FEATURES_ALL=1
CARGO_TARGETS_ALL=1
FAIL_CRITICAL_THRESHOLD=1
FAIL_WARNING_THRESHOLD=0
SUMMARY_JSON=""

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose              More code samples per finding (DETAIL=10)
  -q, --quiet                Reduce non-essential output
  --format=FMT               Output format: text|json|sarif (default: text)
  --ci                       CI mode (stable timestamps, no screen clear)
  --no-color                 Force disable ANSI color
  --include-ext=CSV          File extensions (default: rs)
  --exclude=GLOB[,..]        Additional glob(s)/dir(s) to exclude
  --jobs=N                   Parallel jobs for ripgrep (default: auto)
  --skip=CSV                 Skip categories by number (e.g. --skip=2,7,11)
  --only=CSV                 Run only the specified categories (overrides --skip)
  --fail-on-warning          Exit non-zero on warnings or critical
  --rules=DIR                Additional ast-grep rules directory (merged)
  --no-cargo                 Skip cargo-based checks (check, clippy, fmt, etc.)
  --no-all-features          Do not pass --all-features to cargo
  --no-all-targets           Do not pass --all-targets to cargo
  --summary-json=FILE        Write a machine-readable summary (JSON)
  --fail-critical=N          Exit non-zero if critical issues >= N (default: 1)
  --fail-warning=N           Exit non-zero if warnings  >= N (default: 0)
  -h, --help                 Show help

Env:
  JOBS, NO_COLOR, CI

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
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --no-cargo)   RUN_CARGO=0; shift;;
    --no-all-features) CARGO_FEATURES_ALL=0; shift;;
    --no-all-targets)  CARGO_TARGETS_ALL=0; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --fail-critical=*) FAIL_CRITICAL_THRESHOLD="${1#*=}"; shift;;
    --fail-warning=*)  FAIL_WARNING_THRESHOLD="${1#*=}"; shift;;
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

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ "$USE_COLOR" -eq 0 ]]; then export NO_COLOR=1; export CARGO_TERM_COLOR=never; fi
if [[ -n "${OUTPUT_FILE}" ]]; then mkdir -p "$(dirname -- "$OUTPUT_FILE")" 2>/dev/null || true; exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

DATE_FMT='%Y-%m-%d %H:%M:%S'
now() { if [[ "$CI_MODE" -eq 1 ]]; then date -u '+%Y-%m-%dT%H:%M:%SZ'; else date +"$DATE_FMT"; fi; }

# ────────────────────────────────────────────────────────────────────────────
# Global counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0

# ────────────────────────────────────────────────────────────────────────────
# Global state
# ────────────────────────────────────────────────────────────────────────────
HAS_AST_GREP=0
AST_GREP_CMD=()
HAS_RG=0
HAS_CARGO=0
HAS_CLIPPY=0
HAS_FMT=0
HAS_AUDIT=0
HAS_DENYHALT=0
HAS_DENY=0
HAS_UDEPS=0
HAS_OUTDATED=0

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(thread_join tokio_spawn tcp_shutdown)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [thread_join]="critical"
  [tokio_spawn]="warning"
  [tcp_shutdown]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [thread_join]='std::thread::spawn'
  [tokio_spawn]='tokio::spawn'
  [tcp_shutdown]='TcpStream::connect'
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [thread_join]='\.join\('
  [tokio_spawn]='\.await'
  [tcp_shutdown]='\.shutdown\('
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [thread_join]='std::thread::spawn without join()'
  [tokio_spawn]='tokio::spawn tasks not awaited/cancelled'
  [tcp_shutdown]='TcpStream without shutdown()'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [thread_join]='Store the JoinHandle and call join() or detach intentionally'
  [tokio_spawn]='Await the JoinHandle result or abort/cancel the task explicitly'
  [tcp_shutdown]='Call shutdown() or drop connections explicitly when done'
)

# ────────────────────────────────────────────────────────────────────────────
# Category gating
# ────────────────────────────────────────────────────────────────────────────
category_enabled() {
  local n="$1"
  if [[ -n "${ONLY_CATEGORIES}" ]]; then [[ ",${ONLY_CATEGORIES}," == *",${n},"* ]]; return; fi
  [[ ",${SKIP_CATEGORIES}," != *",${n},"* ]]
}

# ────────────────────────────────────────────────────────────────────────────
# Search engine configuration (rg if available, else grep)
# ────────────────────────────────────────────────────────────────────────────
LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done

EXCLUDE_DIRS=(target .git .cargo .rustup .idea .vscode .DS_Store .svn .hg .vcpkg build dist coverage node_modules .tox .mypy_cache .pytest_cache .cache)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
  HAS_RG=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=()
  for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  GREP_RN=(rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNI=(rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNW=(rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("grep" "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("grep" "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("grep" "${GREP_R_OPTS[@]}" -n -w -E)
fi

count_lines() { awk 'END{print (NR+0)}'; }

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

show_ast_examples() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    while IFS=: read -r file line col rest; do
      local code=""
      if [[ -f "$file" && -n "$line" ]]; then code="$(sed -n "${line}p" "$file" | sed $'s/\t/  /g')"; fi
      print_code_sample "$file" "$line" "${code:-$rest}"
      printed=$((printed+1)); [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
    done < <( ( set +o pipefail; "${AST_GREP_CMD[@]}" --lang rust --pattern "$pattern" -n "$PROJECT_DIR" 2>/dev/null || true ) | head -n "$limit" )
  fi
}

begin_scan_section(){ if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi; set +e; trap - ERR; }
end_scan_section(){ trap on_err ERR; set -e; if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi; }

# ────────────────────────────────────────────────────────────────────────────
# Tool detection
# ────────────────────────────────────────────────────────────────────────────
check_ast_grep() {
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; return 0; fi
  if command -v sg       >/dev/null 2>&1; then AST_GREP_CMD=(sg);       HAS_AST_GREP=1; return 0; fi
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be limited.${RESET}"
  say "${DIM}Tip: cargo install ast-grep  or  npm i -g @ast-grep/cli${RESET}"
  HAS_AST_GREP=0; return 1
}

check_cargo() {
  if command -v cargo >/dev/null 2>&1; then HAS_CARGO=1; else HAS_CARGO=0; fi
  if [[ "$HAS_CARGO" -eq 1 ]]; then
    if cargo clippy -V >/dev/null 2>&1; then HAS_CLIPPY=1; fi
    if rustfmt -V  >/dev/null 2>&1 || cargo fmt -V >/dev/null 2>&1; then HAS_FMT=1; fi
    if cargo audit -V >/dev/null 2>&1; then HAS_AUDIT=1; fi
    if cargo deny --version >/dev/null 2>&1; then HAS_DENY=1; fi
    if cargo udeps -V >/dev/null 2>&1; then HAS_UDEPS=1; fi
    if cargo outdated -V >/dev/null 2>&1; then HAS_OUTDATED=1; fi
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep helpers
# ────────────────────────────────────────────────────────────────────────────
ast_search() {
  local pattern=$1
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --lang rust --pattern "$pattern" "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ag_rules.XXXXXX)"
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

  # Ownership/error handling macros and panics
  cat >"$AST_RULE_DIR/unwrap.yml" <<'YAML'
id: rust.unwrap-call
language: rust
rule:
  pattern: $X.unwrap()
severity: warning
message: "unwrap() may panic on None/Err; prefer `?` or handle errors explicitly"
YAML

  cat >"$AST_RULE_DIR/expect.yml" <<'YAML'
id: rust.expect-call
language: rust
rule:
  pattern: $X.expect($MSG)
severity: warning
message: "expect() may panic; prefer `?` or provide robust recovery"
YAML

  cat >"$AST_RULE_DIR/panic.yml" <<'YAML'
id: rust.panic-macro
language: rust
rule:
  pattern: panic!($$)
severity: critical
message: "panic! in non-test code can crash the process"
YAML

  cat >"$AST_RULE_DIR/todo.yml" <<'YAML'
id: rust.todo-macro
language: rust
rule:
  pattern: todo!($$)
severity: warning
message: "todo! placeholder present; implement or gate behind cfg(test)"
YAML

  cat >"$AST_RULE_DIR/unimplemented.yml" <<'YAML'
id: rust.unimplemented-macro
language: rust
rule:
  pattern: unimplemented!($$)
severity: warning
message: "unimplemented! present; implement or remove"
YAML

  cat >"$AST_RULE_DIR/unreachable.yml" <<'YAML'
id: rust.unreachable-macro
language: rust
rule:
  pattern: unreachable!($$)
severity: warning
message: "unreachable! will panic if reached; ensure logic guards this"
YAML

  cat >"$AST_RULE_DIR/dbg.yml" <<'YAML'
id: rust.dbg-macro
language: rust
rule:
  pattern: dbg!($$)
severity: info
message: "dbg! macro present; remove in production builds"
YAML

  cat >"$AST_RULE_DIR/println.yml" <<'YAML'
id: rust.println-macro
language: rust
rule:
  pattern: println!($$)
severity: info
message: "println! detected; prefer structured logging for production"
YAML

  cat >"$AST_RULE_DIR/eprintln.yml" <<'YAML'
id: rust.eprintln-macro
language: rust
rule:
  pattern: eprintln!($$)
severity: info
message: "eprintln! detected; prefer structured logging for production"
YAML

  # Unsafe / raw / memory
  cat >"$AST_RULE_DIR/unsafe-block.yml" <<'YAML'
id: rust.unsafe-block
language: rust
rule:
  pattern: unsafe { $$ }
severity: info
message: "unsafe block present; verify invariants and minimal scope"
YAML

  cat >"$AST_RULE_DIR/transmute.yml" <<'YAML'
id: rust.mem-transmute
language: rust
rule:
  any:
    - pattern: std::mem::transmute($$)
    - pattern: mem::transmute($$)
    - pattern: transmute($$)
severity: critical
message: "std::mem::transmute is unsafe and error-prone; prefer safe conversions"
YAML

  cat >"$AST_RULE_DIR/uninitialized.yml" <<'YAML'
id: rust.mem-uninitialized
language: rust
rule:
  any:
    - pattern: std::mem::uninitialized::<$T>()
    - pattern: mem::uninitialized::<$T>()
severity: critical
message: "std::mem::uninitialized is UB; use MaybeUninit instead"
YAML

  cat >"$AST_RULE_DIR/zeroed.yml" <<'YAML'
id: rust.mem-zeroed
language: rust
rule:
  any:
    - pattern: std::mem::zeroed::<$T>()
    - pattern: mem::zeroed::<$T>()
severity: critical
message: "std::mem::zeroed can be UB for many types; use MaybeUninit instead"
YAML

  cat >"$AST_RULE_DIR/forget.yml" <<'YAML'
id: rust.mem-forget
language: rust
rule:
  any:
    - pattern: std::mem::forget($$)
    - pattern: mem::forget($$)
severity: warning
message: "mem::forget leaks memory; ensure this is intentional"
YAML

  cat >"$AST_RULE_DIR/cstr-unchecked.yml" <<'YAML'
id: rust.cstr-from-bytes-unchecked
language: rust
rule:
  pattern: std::ffi::CStr::from_bytes_with_nul_unchecked($$)
severity: warning
message: "from_bytes_with_nul_unchecked requires strict invariants; prefer checked API"
YAML

  cat >"$AST_RULE_DIR/unsafe-send-sync.yml" <<'YAML'
id: rust.unsafe-auto-traits
language: rust
rule:
  any:
    - pattern: unsafe impl Send for $T { $$ }
    - pattern: unsafe impl Sync for $T { $$ }
severity: warning
message: "Unsafe impl of Send/Sync; ensure type invariants truly uphold thread-safety"
YAML

  cat >"$AST_RULE_DIR/get-unchecked.yml" <<'YAML'
id: rust.get-unchecked
language: rust
rule:
  any:
    - pattern: $S.get_unchecked($I)
    - pattern: $S.get_unchecked_mut($I)
severity: warning
message: "Unsafe unchecked indexing; ensure bounds invariants are proven"
YAML

  cat >"$AST_RULE_DIR/utf8-unchecked.yml" <<'YAML'
id: rust.from-utf8-unchecked
language: rust
rule:
  any:
    - pattern: std::str::from_utf8_unchecked($$)
    - pattern: std::string::String::from_utf8_unchecked($$)
severity: warning
message: "from_utf8_unchecked requires strict invariants; prefer checked APIs"
YAML

  cat >"$AST_RULE_DIR/raw-parts.yml" <<'YAML'
id: rust.slice-from-raw-parts
language: rust
rule:
  any:
    - pattern: std::slice::from_raw_parts($$)
    - pattern: std::slice::from_raw_parts_mut($$)
severity: warning
message: "from_raw_parts may violate aliasing/lifetime rules; validate invariants"
YAML

  cat >"$AST_RULE_DIR/ptr-cast.yml" <<'YAML'
id: rust.ptr-cast
language: rust
rule:
  any:
    - pattern: $X as *const $T
    - pattern: $X as *mut $T
severity: info
message: "Raw pointer cast; verify layouts and lifetimes"
YAML

  # Concurrency / async
  cat >"$AST_RULE_DIR/arc-mutex.yml" <<'YAML'
id: rust.arc-mutex
language: rust
rule:
  pattern: Arc<Mutex<$T>>
severity: info
message: "Arc<Mutex<..>> used; verify lock contention and potential deadlocks"
YAML

  cat >"$AST_RULE_DIR/rc-refcell.yml" <<'YAML'
id: rust.rc-refcell
language: rust
rule:
  pattern: Rc<RefCell<$T>>
severity: warning
message: "Rc<RefCell<..>> used; runtime borrow panics possible; prefer &mut or owning designs"
YAML

  cat >"$AST_RULE_DIR/lock-unwrap.yml" <<'YAML'
id: rust.mutex-lock-unwrap
language: rust
rule:
  pattern: $M.lock().unwrap()
severity: warning
message: "Mutex::lock().unwrap(); poisoned lock panics; handle error explicitly"
YAML

  cat >"$AST_RULE_DIR/lock-expect.yml" <<'YAML'
id: rust.mutex-lock-expect
language: rust
rule:
  pattern: $M.lock().expect($MSG)
severity: warning
message: "Mutex::lock().expect(..); consider error handling for poisoned lock"
YAML

  cat >"$AST_RULE_DIR/await-in-for.yml" <<'YAML'
id: rust.await-in-for
language: rust
rule:
  pattern: for $P in $I { $$ $F.await $$ }
severity: info
message: "await inside loop; consider batching with join_all or try_join for concurrency"
YAML

  cat >"$AST_RULE_DIR/sleep-in-async.yml" <<'YAML'
id: rust.thread-sleep-in-async
language: rust
rule:
  pattern: std::thread::sleep($$)
  inside:
    pattern: async fn $NAME($$) { $$ }
severity: warning
message: "Blocking sleep in async fn; prefer tokio::time::sleep or async timers"
YAML

  cat >"$AST_RULE_DIR/fs-in-async.yml" <<'YAML'
id: rust.blocking-fs-in-async
language: rust
rule:
  any:
    - pattern: std::fs::read($$)
    - pattern: std::fs::read_to_string($$)
    - pattern: std::fs::write($$)
    - pattern: std::fs::remove_file($$)
    - pattern: std::fs::rename($$)
    - pattern: std::fs::copy($$)
  inside:
    pattern: async fn $NAME($$) { $$ }
severity: info
message: "Blocking std::fs in async fn; prefer tokio::fs equivalents"
YAML

  cat >"$AST_RULE_DIR/block_on-in-async.yml" <<'YAML'
id: rust.block-on-in-async
language: rust
rule:
  any:
    - pattern: futures::executor::block_on($$)
    - pattern: tokio::runtime::Runtime::block_on($$)
  inside:
    pattern: async fn $N($$) { $$ }
severity: warning
message: "block_on called within async fn; can deadlock runtime"
YAML

  cat >"$AST_RULE_DIR/tokio-blocking.yml" <<'YAML'
id: rust.tokio-block-in-place
language: rust
rule:
  pattern: tokio::task::block_in_place($$)
  inside:
    pattern: async fn $N($$) { $$ }
severity: info
message: "block_in_place inside async; ensure this is truly needed and guarded"
YAML

  cat >"$AST_RULE_DIR/thread-spawn-in-async.yml" <<'YAML'
id: rust.thread-spawn-in-async
language: rust
rule:
  pattern: std::thread::spawn($$)
  inside:
    pattern: async fn $NAME($$) { $$ }
severity: warning
message: "std::thread::spawn inside async fn; prefer tokio::spawn or task::spawn_blocking"
YAML

  # Performance / allocation
  cat >"$AST_RULE_DIR/clone-any.yml" <<'YAML'
id: rust.clone-call
language: rust
rule:
  pattern: $X.clone()
severity: info
message: "clone() allocates/copies; verify necessity and scope"
YAML

  cat >"$AST_RULE_DIR/clone-in-loop.yml" <<'YAML'
id: rust.clone-in-loop
language: rust
rule:
  pattern: for $P in $I { $$ $X.clone() $$ }
severity: warning
message: "clone() inside loop; assess per-iteration cost or refactor ownership"
YAML

  cat >"$AST_RULE_DIR/map-clone.yml" <<'YAML'
id: rust.map-clone
language: rust
rule:
  pattern: $I.map(|$p| $x.clone())
severity: info
message: "map(|x| x.clone()) can often be replaced with .cloned()"
YAML

  cat >"$AST_RULE_DIR/to-owned-to-string.yml" <<'YAML'
id: rust.to-owned-to-string
language: rust
rule:
  pattern: $X.to_owned().to_string()
severity: info
message: "to_owned().to_string() chain; prefer to_string() or into_owned() directly"
YAML

  cat >"$AST_RULE_DIR/format-literal.yml" <<'YAML'
id: rust.format-literal-no-vars
language: rust
rule:
  pattern: format!($S)
  constraints:
    S:
      regex: '^".*"|^r#".*"#$'
severity: info
message: "format!(\"literal\") allocates; prefer .to_string() for plain literals"
YAML

  cat >"$AST_RULE_DIR/collect-vec-for.yml" <<'YAML'
id: rust.collect-then-for
language: rust
rule:
  pattern: for $P in $I.collect::<Vec<$T>>() { $$ }
severity: info
message: "Iterating over collected Vec; consider iterating stream directly or use iter()"
YAML

  cat >"$AST_RULE_DIR/nth-zero.yml" <<'YAML'
id: rust.iter-nth-zero
language: rust
rule:
  pattern: $I.nth(0)
severity: info
message: "nth(0) is same as next(); prefer next() for clarity and potential perf"
YAML

  # Security
  cat >"$AST_RULE_DIR/reqwest-insecure.yml" <<'YAML'
id: rust.reqwest-danger-accept
language: rust
rule:
  pattern: reqwest::ClientBuilder::new().danger_accept_invalid_certs(true)
severity: warning
message: "reqwest builder accepts invalid certs; avoid in production"
YAML

  cat >"$AST_RULE_DIR/openssl-no-verify.yml" <<'YAML'
id: rust.openssl-no-verify
language: rust
rule:
  any:
    - pattern: openssl::ssl::SslVerifyMode::NONE
    - pattern: SslVerifyMode::NONE
severity: critical
message: "OpenSSL verification disabled; enables MITM"
YAML

  cat >"$AST_RULE_DIR/native-tls-danger.yml" <<'YAML'
id: rust.native-tls-danger
language: rust
rule:
  pattern: native_tls::TlsConnector::builder().danger_accept_invalid_certs(true)
severity: warning
message: "native-tls builder accepts invalid certs; disable for production"
YAML

  cat >"$AST_RULE_DIR/md5-sha1.yml" <<'YAML'
id: rust.insecure-hash
language: rust
rule:
  any:
    - pattern: md5::$F($$)
    - pattern: md5::compute($$)
    - pattern: sha1::$F($$)
    - pattern: sha1::Sha1::new($$)
    - pattern: ring::digest::SHA1_FOR_LEGACY_USE_ONLY
    - pattern: openssl::hash::MessageDigest::md5()
    - pattern: openssl::hash::MessageDigest::sha1()
severity: warning
message: "Weak hash algorithm (MD5/SHA1) detected; prefer SHA-256/512"
YAML

  cat >"$AST_RULE_DIR/http-url.yml" <<'YAML'
id: rust.plain-http-url
language: rust
rule:
  pattern: "http://$REST"
severity: info
message: "Plain HTTP URL found; ensure HTTPS for production"
YAML

  cat >"$AST_RULE_DIR/regex-new-unwrap.yml" <<'YAML'
id: rust.regex-new-unwrap
language: rust
rule:
  pattern: regex::Regex::new($re).unwrap()
severity: info
message: "Regex::new(...).unwrap(); consider compile-time regex! or handle error with context"
YAML

  # Code quality markers
  cat >"$AST_RULE_DIR/todo-comment.yml" <<'YAML'
id: rust.todo-comment
language: rust
rule:
  pattern: // TODO $REST
severity: info
message: "TODO marker present"
YAML

  cat >"$AST_RULE_DIR/fixme-comment.yml" <<'YAML'
id: rust.fixme-comment
language: rust
rule:
  pattern: // FIXME $REST
severity: info
message: "FIXME marker present"
YAML
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  local outfmt="--json"; [[ "$FORMAT" == "sarif" ]] && outfmt="--sarif"
  "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" $outfmt 2>/dev/null
}

# ────────────────────────────────────────────────────────────────────────────
# Cargo helpers
# ────────────────────────────────────────────────────────────────────────────
run_cargo_subcmd() {
  local name="$1"; shift
  local logfile="$1"; shift
  local -a args=("$@")
  local ec=0
  if [[ "$RUN_CARGO" -eq 0 || "$HAS_CARGO" -eq 0 ]]; then
    echo "" >"$logfile"; echo 0 >"$logfile.ec"; return 0
  fi
  ( set +e; "${args[@]}" >"$logfile" 2>&1; ec=$?; echo "$ec" >"$logfile.ec"; exit 0 )
}

count_warnings_errors() {
  local file="$1"
  local w e
  w=$(grep -E "^warning: |: warning:" "$file" 2>/dev/null | wc -l | awk '{print $1+0}')
  e=$(grep -E "^error: |: error:" "$file" 2>/dev/null | wc -l | awk '{print $1+0}')
  echo "$w $e"
}

# ────────────────────────────────────────────────────────────────────────────
# Startup banner
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
║                                            /\                     ║ 
║  ██████╗ ██╗   ██╗ ██████╗                ( /   @ @    ()         ║ 
║  ██╔══██╗██║   ██║██╔════╝                 \  __| |__  /          ║ 
║  ██████╔╝██║   ██║██║  ███╗                 -/   "   \-           ║ 
║  ██╔══██╗██║   ██║██║   ██║                /-|       |-\          ║ 
║  ██████╔╝╚██████╔╝╚██████╔╝               / /-\     /-\ \         ║ 
║  ╚═════╝  ╚═════╝  ╚═════╝                 / /-`---'-\ \          ║ 
║                                             /         \           ║ 
║                                                                   ║ 
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   ║ 
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  ║ 
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  ║ 
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  ║ 
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  ║ 
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝       ║ 
║                                                                   ║ 
║  Rust module • ownership sanity, unsafe & async spotlights        ║ 
║  UBS module: rust • cargo-aware targeting, low-noise caching      ║ 
║  ASCII homage: Ferris crab (ASCII Art Archive)                    ║ 
║  Run standalone: modules/ubs-rust.sh --help                       ║ 
║                                                                   ║ 
║  Night Owl QA                                                     ║ 
║  “We see bugs before you do.”                                     ║ 
╚═══════════════════════════════════════════════════════════════════╝ 
                                                                      
BANNER
echo -e "${RESET}"

say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(now)${RESET}"

# Count files
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
  ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
  | wc -l | awk '{print $1+0}'
)
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

# Tool detection
echo ""
if check_ast_grep; then
  say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
else
  say "${YELLOW}${WARN} ast-grep unavailable - using regex-only heuristics where needed${RESET}"
fi

check_cargo
if [[ "$RUN_CARGO" -eq 1 ]]; then
  if [[ "$HAS_CARGO" -eq 1 ]]; then
    say "${GREEN}${CHECK} cargo detected${RESET}"
    [[ "$HAS_CLIPPY" -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} clippy available" || say "  ${YELLOW}${WARN}${RESET} clippy not installed"
    [[ "$HAS_FMT"    -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} rustfmt available" || say "  ${YELLOW}${WARN}${RESET} rustfmt not installed"
    [[ "$HAS_AUDIT"  -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} cargo-audit available" || say "  ${YELLOW}${WARN}${RESET} cargo-audit not installed"
    [[ "$HAS_DENY"   -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} cargo-deny available" || say "  ${YELLOW}${WARN}${RESET} cargo-deny not installed"
    [[ "$HAS_UDEPS"  -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} cargo-udeps available" || say "  ${YELLOW}${WARN}${RESET} cargo-udeps not installed"
    [[ "$HAS_OUTDATED" -eq 1 ]] && say "  ${GREEN}${CHECK}${RESET} cargo-outdated available" || say "  ${YELLOW}${WARN}${RESET} cargo-outdated not installed"
  else
    say "${YELLOW}${WARN} cargo not found. Skipping cargo-based checks.${RESET}"
  fi
else
  say "${YELLOW}${WARN} --no-cargo set: skipping cargo-based checks.${RESET}"
fi

# relax pipefail for scanning
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: OWNERSHIP & ERROR HANDLING MACROS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 1; then
print_header "1. OWNERSHIP & ERROR HANDLING MACROS"
print_category "Detects: unwrap/expect, panic/unreachable/todo/unimplemented, dbg/println" \
  "Panic-prone and debug macros frequently leak into production and cause crashes"

print_subheader "unwrap()/expect() usage"
u_count_ast=$(ast_search '$X.unwrap()' || echo 0)
e_count_ast=$(ast_search '$X.expect($MSG)' || echo 0)
u_count_rg=$("${GREP_RN[@]}" -e "\.unwrap\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
e_count_rg=$("${GREP_RN[@]}" -e "\.expect\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
u_total=$(( u_count_ast>0?u_count_ast:u_count_rg ))
e_total=$(( e_count_ast>0?e_count_ast:e_count_rg ))
ue_total=$((u_total + e_total))
if [ "$ue_total" -gt 0 ]; then
  print_finding "warning" "$ue_total" "Potential panics via unwrap/expect" "Prefer \`?\` or match to propagate/handle errors"
  show_detailed_finding "\.(unwrap|expect)\(" 5
else
  print_finding "good" "No unwrap/expect detected"
fi

print_subheader "panic!/unreachable!/todo!/unimplemented!"
p_count=$(( $(ast_search 'panic!($$)' || echo 0) + $("${GREP_RN[@]}" -e "panic!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
u_count=$(( $(ast_search 'unreachable!($$)' || echo 0) + $("${GREP_RN[@]}" -e "unreachable!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
t_count=$(( $(ast_search 'todo!($$)' || echo 0) + $("${GREP_RN[@]}" -e "todo!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
ui_count=$(( $(ast_search 'unimplemented!($$)' || echo 0) + $("${GREP_RN[@]}" -e "unimplemented!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$p_count" -gt 0 ]; then print_finding "critical" "$p_count" "panic! macro(s) present" "Avoid panic! in library code"; show_detailed_finding "panic!\(" 5; else print_finding "good" "No panic! macros"; fi
if [ "$u_count" -gt 0 ]; then print_finding "warning" "$u_count" "unreachable! may panic if reached" "Double-check logic"; fi
if [ "$t_count" -gt 0 ]; then print_finding "warning" "$t_count" "todo! placeholders present" "Implement or gate with cfg(test)"; fi
if [ "$ui_count" -gt 0 ]; then print_finding "warning" "$ui_count" "unimplemented! placeholders present" "Implement or remove"; fi

print_subheader "dbg!/println!/eprintln!"
dbg_count=$(( $(ast_search 'dbg!($$)' || echo 0) + $("${GREP_RN[@]}" -e "dbg!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
pln_count=$(( $(ast_search 'println!($$)' || echo 0) + $("${GREP_RN[@]}" -e "println!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
epln_count=$(( $(ast_search 'eprintln!($$)' || echo 0) + $("${GREP_RN[@]}" -e "eprintln!\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$dbg_count" -gt 0 ]; then print_finding "info" "$dbg_count" "dbg! macros present"; fi
if [ "$pln_count" -gt 0 ]; then print_finding "info" "$pln_count" "println! found - prefer logging"; fi
if [ "$epln_count" -gt 0 ]; then print_finding "info" "$epln_count" "eprintln! found - prefer logging"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: UNSAFE & MEMORY OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 2; then
print_header "2. UNSAFE & MEMORY OPERATIONS"
print_category "Detects: unsafe blocks, transmute/uninitialized/forget/zeroed, raw ffi hazards" \
  "These patterns may introduce UB, memory leaks, or hard-to-debug crashes"

print_subheader "unsafe { ... } blocks"
unsafe_count=$(( $(ast_search 'unsafe { $$ }' || echo 0) + $("${GREP_RN[@]}" -e "unsafe[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$unsafe_count" -gt 0 ]; then print_finding "info" "$unsafe_count" "unsafe blocks present" "Ensure invariants and narrow scope"; else print_finding "good" "No unsafe blocks detected"; fi

print_subheader "transmute, uninitialized, zeroed, forget"
transmute_count=$(( $(ast_search 'std::mem::transmute($$)' || echo 0) + $("${GREP_RN[@]}" -e "transmute\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
uninit_count=$(( $(ast_search 'std::mem::uninitialized::<$T>()' || echo 0) + $("${GREP_RN[@]}" -e "uninitialized::<" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
zeroed_count=$(( $(ast_search 'std::mem::zeroed::<$T>()' || echo 0) + $("${GREP_RN[@]}" -e "zeroed::<" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
forget_count=$(( $(ast_search 'std::mem::forget($$)' || echo 0) + $("${GREP_RN[@]}" -e "mem::forget\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$transmute_count" -gt 0 ]; then print_finding "critical" "$transmute_count" "mem::transmute usage"; show_detailed_finding "transmute\(" 3; fi
if [ "$uninit_count" -gt 0 ]; then print_finding "critical" "$uninit_count" "mem::uninitialized usage"; show_detailed_finding "uninitialized::<" 3; fi
if [ "$zeroed_count" -gt 0 ]; then print_finding "critical" "$zeroed_count" "mem::zeroed usage"; show_detailed_finding "zeroed::<" 3; fi
if [ "$forget_count" -gt 0 ]; then print_finding "warning" "$forget_count" "mem::forget leaks memory"; show_detailed_finding "mem::forget\(" 3; fi

print_subheader "CStr::from_bytes_with_nul_unchecked"
cstr_count=$(( $(ast_search 'std::ffi::CStr::from_bytes_with_nul_unchecked($$)' || echo 0) + $("${GREP_RN[@]}" -e "from_bytes_with_nul_unchecked\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$cstr_count" -gt 0 ]; then print_finding "warning" "$cstr_count" "CStr unchecked conversion used"; fi

print_subheader "get_unchecked / from_utf8_unchecked / from_raw_parts"
guc_count=$(( $(ast_search '$S.get_unchecked($I)' || echo 0) + $(ast_search '$S.get_unchecked_mut($I)' || echo 0) ))
u8u_count=$(( $(ast_search 'std::str::from_utf8_unchecked($$)' || echo 0) + $(ast_search 'std::string::String::from_utf8_unchecked($$)' || echo 0) ))
raw_parts=$(( $(ast_search 'std::slice::from_raw_parts($$)' || echo 0) + $(ast_search 'std::slice::from_raw_parts_mut($$)' || echo 0) ))
if [ "$guc_count" -gt 0 ]; then print_finding "warning" "$guc_count" "Unchecked indexing APIs in use"; fi
if [ "$u8u_count" -gt 0 ]; then print_finding "warning" "$u8u_count" "UTF-8 unchecked conversion APIs"; fi
if [ "$raw_parts" -gt 0 ]; then print_finding "warning" "$raw_parts" "slice::from_raw_parts(_mut) usage"; fi

print_subheader "Unsafe Send/Sync impls"
autos_count=$(( $(ast_search 'unsafe impl Send for $T { $$ }' || echo 0) + $(ast_search 'unsafe impl Sync for $T { $$ }' || echo 0) ))
if [ "$autos_count" -gt 0 ]; then print_finding "warning" "$autos_count" "Unsafe Send/Sync implementations"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: CONCURRENCY & ASYNC PITFALLS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 3; then
print_header "3. CONCURRENCY & ASYNC PITFALLS"
print_category "Detects: Arc<Mutex>, Rc<RefCell>, blocking ops in async, await-in-loop, spawn misuse" \
  "Concurrency misuse leads to deadlocks, head-of-line blocking, and performance issues"

print_subheader "Arc<Mutex<..>> / Rc<RefCell<..>> / RwLock"
arc_mutex=$(( $(ast_search 'Arc<Mutex<$T>>' || echo 0) + $("${GREP_RN[@]}" -e "Arc<\s*Mutex<" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
rc_refcell=$(( $(ast_search 'Rc<RefCell<$T>>' || echo 0) + $("${GREP_RN[@]}" -e "Rc<\s*RefCell<" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
rwlock_count=$("${GREP_RN[@]}" -e "RwLock<" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$arc_mutex" -gt 0 ]; then print_finding "info" "$arc_mutex" "Arc<Mutex<..>> detected - verify contention"; fi
if [ "$rc_refcell" -gt 0 ]; then print_finding "warning" "$rc_refcell" "Rc<RefCell<..>> borrow panics possible"; fi
if [ "$rwlock_count" -gt 0 ]; then print_finding "info" "$rwlock_count" "RwLock in use - verify read/write patterns"; fi

print_subheader "Mutex::lock().unwrap()/expect()"
mu_unwrap=$(( $(ast_search '$M.lock().unwrap()' || echo 0) + $("${GREP_RN[@]}" -e "\.lock\(\)\.unwrap\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
mu_expect=$(( $(ast_search '$M.lock().expect($MSG)' || echo 0) + $("${GREP_RN[@]}" -e "\.lock\(\)\.expect\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
mu_total=$((mu_unwrap + mu_expect))
if [ "$mu_total" -gt 0 ]; then print_finding "warning" "$mu_total" "Poisoned lock handling via unwrap/expect"; show_detailed_finding "\.lock\(\)\.(unwrap|expect)\(" 5; fi

print_subheader "await inside loops (sequentialism)"
await_loop=$(( $(ast_search 'for $P in $I { $$ $F.await $$ }' || echo 0) + $("${GREP_RN[@]}" -e "for[^(]*\{[^\}]*\.[[:alnum:]_]+\.await" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$await_loop" -gt 0 ]; then print_finding "info" "$await_loop" "await inside loop; consider batched concurrency"; fi

print_subheader "Blocking ops inside async (thread::sleep, std::fs)"
sleep_async=$(( $(ast_search 'std::thread::sleep($$)' || echo 0) + $("${GREP_RN[@]}" -e "thread::sleep\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
fs_async=$(( $(ast_search 'std::fs::read($$)' || echo 0) + $("${GREP_RN[@]}" -e "std::fs::(read|read_to_string|write|rename|copy|remove_file)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$sleep_async" -gt 0 ]; then print_finding "warning" "$sleep_async" "thread::sleep in async"; fi
if [ "$fs_async" -gt 0 ]; then print_finding "info" "$fs_async" "Blocking std::fs in async code"; fi

print_subheader "block_on within async context"
block_on=$(( $(ast_search 'futures::executor::block_on($$)' || echo 0) + $(ast_search 'tokio::runtime::Runtime::block_on($$)' || echo 0) ))
if [ "$block_on" -gt 0 ]; then print_finding "warning" "$block_on" "block_on within async function"; fi

print_subheader "std::thread::spawn within async"
spawn_in_async=$(( $(ast_search 'std::thread::spawn($$)' || echo 0) ))
if [ "$spawn_in_async" -gt 0 ]; then print_finding "warning" "$spawn_in_async" "std::thread::spawn inside async fn"; fi

print_subheader "tokio::spawn usage (heuristic for detached tasks)"
spawn_count=$("${GREP_RN[@]}" -e "tokio::spawn\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
join_handle_used=$("${GREP_RN[@]}" -e "JoinHandle<|\.await" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$spawn_count" -gt 0 ] && [ "$join_handle_used" -lt "$spawn_count" ]; then
  print_finding "info" "$((spawn_count - join_handle_used))" "spawn without awaiting JoinHandle (heuristic)" "Ensure detached tasks handle errors appropriately"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: NUMERIC & FLOATING-POINT
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 4; then
print_header "4. NUMERIC & FLOATING-POINT"
print_category "Detects: float equality, division/modulo by variable, potential overflow hints" \
  "Numeric bugs cause subtle logic errors or panics in debug builds (overflow)"

print_subheader "Floating-point equality comparisons"
# literals or obvious float identifiers on either side
fp_eq=$("${GREP_RN[@]}" -e "([[:alnum:]_]\s*(==|!=)\s*[[:alnum:]_]*\.[[:alnum:]_]+)|((==|!=)[[:space:]]*[0-9]+\.[0-9]+)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$fp_eq" -gt 0 ]; then print_finding "info" "$fp_eq" "Float equality/inequality check" "Consider epsilon comparisons"; show_detailed_finding "(==|!=)[[:space:]]*[0-9]+\.[0-9]+" 3; else print_finding "good" "No direct float equality checks detected"; fi

print_subheader "Division/modulo by variable (verify non-zero)"
div_var=$("${GREP_RN[@]}" -e "/[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*" "$PROJECT_DIR" 2>/dev/null | grep -Ev "https?://|//|/\*" || true | count_lines)
mod_var=$("${GREP_RN[@]}" -e "%[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*" "$PROJECT_DIR" 2>/dev/null | grep -Ev "//|/\*" || true | count_lines)
if [ "$div_var" -gt 0 ]; then print_finding "info" "$div_var" "Division by variables - guard zero divisors"; fi
if [ "$mod_var" -gt 0 ]; then print_finding "info" "$mod_var" "Modulo by variables - guard zero divisors"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: COLLECTIONS & ITERATORS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 5; then
print_header "5. COLLECTIONS & ITERATORS"
print_category "Detects: clone in loops, collect then iterate, nth(0), length checks" \
  "Iterator misuse often leads to unnecessary allocations or slow paths"

print_subheader "clone() occurrences & clone() in loops"
clone_any=$(( $(ast_search '$X.clone()' || echo 0) + $("${GREP_RN[@]}" -e "\.clone\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
clone_loop=$(( $(ast_search 'for $P in $I { $$ $X.clone() $$ }' || echo 0) ))
if [ "$clone_any" -gt 0 ]; then print_finding "info" "$clone_any" "clone() usages - audit for necessity"; fi
if [ "$clone_loop" -gt 0 ]; then print_finding "warning" "$clone_loop" "clone() inside loops - potential perf hit"; fi

print_subheader "collect::<Vec<_>>() then for"
collect_for=$(( $(ast_search 'for $P in $I.collect::<Vec<$T>>() { $$ }' || echo 0) + $("${GREP_RN[@]}" -e "collect::<\s*Vec<" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$collect_for" -gt 0 ]; then print_finding "info" "$collect_for" "Collecting to Vec before iterate - consider streaming"; fi

print_subheader "nth(0) → next()"
nth0=$(( $(ast_search '$I.nth(0)' || echo 0) + $("${GREP_RN[@]}" -e "\.nth\(\s*0\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$nth0" -gt 0 ]; then print_finding "info" "$nth0" "nth(0) detected - prefer next()"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: STRING & ALLOCATION SMELLS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 6; then
print_header "6. STRING & ALLOCATION SMELLS"
print_category "Detects: needless allocations, format!(literal), to_owned().to_string()" \
  "Unnecessary allocations and conversions reduce performance"

print_subheader "to_owned().to_string() chain"
to_owned_to_string=$(( $(ast_search '$X.to_owned().to_string()' || echo 0) + $("${GREP_RN[@]}" -e "\.to_owned\(\)\.to_string\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$to_owned_to_string" -gt 0 ]; then print_finding "info" "$to_owned_to_string" "to_owned().to_string() chain - simplify"; fi

print_subheader "format!(\"literal\") with no placeholders"
fmt_lit=$(( $(ast_search 'format!($S)' || echo 0) ))
fmt_lit_rg=$("${GREP_RN[@]}" -e "format!\(\s*([rR]?#?\"[^\{\}]*\"#?)\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fmt_total=$((fmt_lit + fmt_lit_rg))
if [ "$fmt_total" -gt 0 ]; then print_finding "info" "$fmt_total" "format!(literal) allocates - use .to_string()"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: FILESYSTEM & PROCESS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 7; then
print_header "7. FILESYSTEM & PROCESS"
print_category "Detects: blocking std::fs in async, process::Command usage heuristics" \
  "I/O misuse or command construction from untrusted input can be risky"

print_subheader "std::fs usage (general inventory)"
fs_any=$("${GREP_RN[@]}" -e "std::fs::" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$fs_any" -gt 0 ]; then print_finding "info" "$fs_any" "std::fs operations present - consider async equivalents where applicable"; fi

print_subheader "std::process::Command usage"
cmd_count=$("${GREP_RN[@]}" -e "std::process::Command::new\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$cmd_count" -gt 0 ]; then print_finding "info" "$cmd_count" "Command::new detected - ensure args are sanitized and errors handled"; show_detailed_finding "std::process::Command::new\(" 3; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: SECURITY FINDINGS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 8; then
print_header "8. SECURITY FINDINGS"
print_category "Detects: TLS verification disabled, weak hash algos, HTTP URLs, secrets" \
  "Security misconfigurations can lead to credential leaks and MITM attacks"

print_subheader "Weak hash algorithms (MD5/SHA1)"
weak_hash=$(( $(ast_search 'md5::$F($$)' || echo 0) + $(ast_search 'sha1::$F($$)' || echo 0) + $("${GREP_RN[@]}" -e "SHA1_FOR_LEGACY_USE_ONLY|MessageDigest::(md5|sha1)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$weak_hash" -gt 0 ]; then print_finding "warning" "$weak_hash" "Weak hash algorithm usage (MD5/SHA1)"; show_detailed_finding "md5::|sha1::|SHA1_FOR_LEGACY_USE_ONLY|MessageDigest::(md5|sha1)" 5; else print_finding "good" "No MD5/SHA1 found"; fi

print_subheader "TLS verification disabled"
tls_insecure=$(( $(ast_search 'reqwest::ClientBuilder::new().danger_accept_invalid_certs(true)' || echo 0) \
  + $("${GREP_RN[@]}" -e "danger_accept_invalid_certs\(\s*true\s*\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) \
  + $("${GREP_RN[@]}" -e "SslVerifyMode::NONE" "$PROJECT_DIR" 2>/dev/null | count_lines || true) \
  + $("${GREP_RN[@]}" -e "TlsConnector::builder\(\)\.danger_accept_invalid_certs\(true\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$tls_insecure" -gt 0 ]; then print_finding "critical" "$tls_insecure" "TLS verification disabled"; fi

print_subheader "Plain http:// URLs"
http_url=$(( $(ast_search '"http://$REST"' || echo 0) + $("${GREP_RN[@]}" -e "http://[A-Za-z0-9]" "$PROJECT_DIR" 2>/dev/null | count_lines || true) ))
if [ "$http_url" -gt 0 ]; then print_finding "info" "$http_url" "Plain HTTP URL(s) detected"; fi

print_subheader "Hardcoded secrets/credentials (heuristic)"
secret_heur=$("${GREP_RNI[@]}" -e "password[[:space:]]*=|api_?key[[:space:]]*=|secret[[:space:]]*=|token[[:space:]]*=|BEGIN RSA PRIVATE KEY" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$secret_heur" -gt 0 ]; then print_finding "critical" "$secret_heur" "Possible hardcoded secrets"; show_detailed_finding "password[[:space:]]*=|api_?key[[:space:]]*=|secret[[:space:]]*=|token[[:space:]]*=|BEGIN RSA PRIVATE KEY" 3; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: CODE QUALITY MARKERS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 9; then
print_header "9. CODE QUALITY MARKERS"
print_category "Detects: TODO, FIXME, HACK, NOTE" \
  "Technical debt markers indicate incomplete or problematic code"

todo_count=$("${GREP_RNI[@]}" "TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fixme_count=$("${GREP_RNI[@]}" "FIXME" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
hack_count=$("${GREP_RNI[@]}" "HACK" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
note_count=$("${GREP_RNI[@]}" "NOTE" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total_markers=$((todo_count + fixme_count + hack_count))
if [ "$total_markers" -gt 20 ]; then
  print_finding "warning" "$total_markers" "Significant technical debt"; say "    ${YELLOW}TODO:${RESET} $todo_count  ${RED}FIXME:${RESET} $fixme_count  ${MAGENTA}HACK:${RESET} $hack_count  ${BLUE}NOTE:${RESET} $note_count"
elif [ "$total_markers" -gt 0 ]; then
  print_finding "info" "$total_markers" "Technical debt markers present"; say "    ${YELLOW}TODO:${RESET} $todo_count  ${RED}FIXME:${RESET} $fixme_count  ${MAGENTA}HACK:${RESET} $hack_count  ${BLUE}NOTE:${RESET} $note_count"
else
  print_finding "good" "No TODO/FIXME/HACK markers found"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: MODULE & VISIBILITY ISSUES
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 10; then
print_header "10. MODULE & VISIBILITY ISSUES"
print_category "Detects: pub use wildcards, glob imports, re-exports" \
  "Overly broad visibility complicates API stability and encapsulation"

print_subheader "Wildcard imports (use crate::* or ::*)"
glob_imports=$("${GREP_RN[@]}" -e "use\s+[a-zA-Z0-9_:]+::\*\s*;" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$glob_imports" -gt 0 ]; then print_finding "info" "$glob_imports" "Wildcard imports found; prefer explicit names"; show_detailed_finding "use\s+[a-zA-Z0-9_:]+::\*\s*;" 3; else print_finding "good" "No wildcard imports detected"; fi

print_subheader "pub use re-exports (inventory)"
pub_use=$("${GREP_RN[@]}" -e "pub\s+use\s+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$pub_use" -gt 0 ]; then print_finding "info" "$pub_use" "pub use re-exports present - verify API surface"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: TESTS & BENCHES HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 11; then
print_header "11. TESTS & BENCHES HYGIENE"
print_category "Detects: ignored tests, todo! in tests, println!/dbg! in tests" \
  "Ensure tests do not hide failures or produce noisy output"

print_subheader "#[ignore] tests"
ignored_tests=$("${GREP_RN[@]}" -e "#\[ignore\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$ignored_tests" -gt 0 ]; then print_finding "info" "$ignored_tests" "#[ignore] tests present - verify intent"; fi

print_subheader "todo!/unimplemented! in tests"
test_todo=$("${GREP_RN[@]}" -e "#\[test\]" "$PROJECT_DIR" 2>/dev/null | (grep -A5 -E "todo!|unimplemented!" || true) | (grep -Ec "todo!|unimplemented!" || true))
test_todo=$(echo "$test_todo" | awk 'END{print $0+0}')
if [ "$test_todo" -gt 0 ]; then print_finding "info" "$test_todo" "todo!/unimplemented! seen near #[test]"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: LINTS & STYLE (fmt/clippy)
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 12; then
print_header "12. LINTS & STYLE (fmt/clippy)"
print_category "Runs: cargo fmt -- --check, cargo clippy" \
  "Formatter and lints help maintain consistent style and catch many issues"

FMT_LOG="$(mktemp)"; CLIPPY_LOG="$(mktemp)"; TMP_FILES+=("$FMT_LOG" "$CLIPPY_LOG")
if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
  # cargo fmt -- --check
  if [[ "$HAS_FMT" -eq 1 ]]; then
    run_cargo_subcmd "fmt" "$FMT_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo fmt -- --check"
    r_ec=$(cat "$FMT_LOG.ec" 2>/dev/null || echo 0)
    if [[ "$r_ec" -ne 0 ]]; then
      print_finding "warning" 1 "Formatting issues (cargo fmt --check failed)" "Run: cargo fmt"
    else
      print_finding "good" "Formatting is clean"
    fi
  else
    print_finding "info" 1 "rustfmt not installed; skipping format check"
  fi

  # cargo clippy
  if [[ "$HAS_CLIPPY" -eq 1 ]]; then
    extra1=(); [[ "$CARGO_FEATURES_ALL" -eq 1 ]] && extra1+=(--all-features)
    extra2=(); [[ "$CARGO_TARGETS_ALL" -eq 1 ]] && extra2+=(--all-targets)
    run_cargo_subcmd "clippy" "$CLIPPY_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo clippy ${extra1[*]} ${extra2[*]} -- -D warnings"
    w_e=$(count_warnings_errors "$CLIPPY_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
    if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "Clippy errors"; fi
    if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Clippy warnings"; fi
    if [[ "$w" -eq 0 && "$e" -eq 0 ]]; then print_finding "good" "No clippy warnings/errors"; fi
  else
    print_finding "info" 1 "clippy not installed; skipping lint pass"
  fi
else
  print_finding "info" 1 "cargo not available or disabled; style/lints skipped"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: BUILD HEALTH (check/test)
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 13; then
print_header "13. BUILD HEALTH (check/test)"
print_category "Runs: cargo check, cargo test --no-run" \
  "Ensures the project compiles and tests build"

CHECK_LOG="$(mktemp)"; TEST_LOG="$(mktemp)"; TMP_FILES+=("$CHECK_LOG" "$TEST_LOG")
if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
  run_cargo_subcmd "check" "$CHECK_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo check"
  w_e=$(count_warnings_errors "$CHECK_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
  if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "cargo check errors"; fi
  if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "cargo check warnings"; else print_finding "good" "cargo check clean"; fi

  run_cargo_subcmd "test-no-run" "$TEST_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo test --no-run"
  w_e=$(count_warnings_errors "$TEST_LOG"); w=$(echo "$w_e" | awk '{print $1}'); e=$(echo "$w_e" | awk '{print $2}')
  if [[ "$e" -gt 0 ]]; then print_finding "critical" "$e" "Tests failed to build (cargo test --no-run)"; fi
  if [[ "$w" -gt 0 ]]; then print_finding "warning" "$w" "Test build warnings"; else print_finding "good" "Tests build clean"; fi
else
  print_finding "info" 1 "cargo disabled/unavailable; build checks skipped"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: DEPENDENCY HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 14; then
print_header "14. DEPENDENCY HYGIENE"
print_category "Runs: cargo audit, cargo deny check, cargo udeps, cargo outdated" \
  "Keeps dependencies safe, minimal, and up-to-date"

if [[ "$RUN_CARGO" -eq 1 && "$HAS_CARGO" -eq 1 ]]; then
  if [[ "$HAS_AUDIT" -eq 1 ]]; then
    AUDIT_LOG="$(mktemp)"; TMP_FILES+=("$AUDIT_LOG"); run_cargo_subcmd "audit" "$AUDIT_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo audit"
    audit_vuln=$(grep -c -E "Vulnerability|RUSTSEC" "$AUDIT_LOG" 2>/dev/null || true); audit_vuln=${audit_vuln:-0}
    if [[ "$audit_vuln" -gt 0 ]]; then print_finding "critical" "$audit_vuln" "Advisories found by cargo-audit"; else print_finding "good" "No known advisories (cargo-audit)"; fi
  else
    print_finding "info" 1 "cargo-audit not installed; skipping advisory scan"
  fi

  if [[ "$HAS_DENY" -eq 1 ]]; then
    DENY_LOG="$(mktemp)"; TMP_FILES+=("$DENY_LOG"); run_cargo_subcmd "deny" "$DENY_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo deny check advisories bans licenses sources"
    deny_err=$(grep -c -E "error\[[^)]+\]|[[:space:]]error:" "$DENY_LOG" 2>/dev/null || true); deny_err=${deny_err:-0}
    deny_warn=$(grep -c -E "[[:space:]]warning:" "$DENY_LOG" 2>/dev/null || true); deny_warn=${deny_warn:-0}
    if [[ "$deny_err" -gt 0 ]]; then print_finding "critical" "$deny_err" "cargo-deny errors"; fi
    if [[ "$deny_warn" -gt 0 ]]; then print_finding "warning" "$deny_warn" "cargo-deny warnings"; fi
    if [[ "$deny_err" -eq 0 && "$deny_warn" -eq 0 ]]; then print_finding "good" "cargo-deny clean"; fi
  else
    print_finding "info" 1 "cargo-deny not installed; skipping policy checks"
  fi

  if [[ "$HAS_UDEPS" -eq 1 ]]; then
    UDEPS_LOG="$(mktemp)"; TMP_FILES+=("$UDEPS_LOG"); run_cargo_subcmd "udeps" "$UDEPS_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo udeps --all-targets"
    udeps_count=$(grep -c -E "(unused dependency|possibly unused|not used)" "$UDEPS_LOG" 2>/dev/null || true); udeps_count=${udeps_count:-0}
    if [[ "$udeps_count" -gt 0 ]]; then print_finding "info" "$udeps_count" "Unused dependencies (cargo-udeps)"; else print_finding "good" "No unused dependencies"; fi
  else
    print_finding "info" 1 "cargo-udeps not installed; skipping unused dep scan"
  fi

  if [[ "$HAS_OUTDATED" -eq 1 ]]; then
    OUT_LOG="$(mktemp)"; TMP_FILES+=("$OUT_LOG"); run_cargo_subcmd "outdated" "$OUT_LOG" bash -lc "cd \"$PROJECT_DIR\" && CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto} cargo outdated -R"
    outdated_count=$(grep -E "Minor|Major|Patch" "$OUT_LOG" 2>/dev/null | wc -l | awk '{print $1+0}')
    if [[ "$outdated_count" -gt 0 ]]; then print_finding "info" "$outdated_count" "Outdated dependencies (cargo-outdated)"; else print_finding "good" "Dependencies up-to-date"; fi
  else
    print_finding "info" 1 "cargo-outdated not installed; skipping update report"
  fi
else
  print_finding "info" 1 "cargo disabled/unavailable; dependency checks skipped"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: API MISUSE (COMMON)
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 15; then
print_header "15. API MISUSE (COMMON)"
print_category "Detects: nth(0), DefaultHasher, expect_err/unwrap_err, Option::unwrap_or_default in hot paths" \
  "Common footguns and readability hazards"

print_subheader "std::collections::hash_map::DefaultHasher"
def_hasher=$("${GREP_RN[@]}" -e "DefaultHasher" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$def_hasher" -gt 0 ]; then print_finding "info" "$def_hasher" "DefaultHasher detected - not for cryptographic or stable hashing"; fi

print_subheader "unwrap_err()/expect_err() usage inventory"
unwrap_err=$("${GREP_RN[@]}" -e "unwrap_err\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
expect_err=$("${GREP_RN[@]}" -e "expect_err\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$unwrap_err" -gt 0 ] || [ "$expect_err" -gt 0 ]; then print_finding "info" "$((unwrap_err+expect_err))" "unwrap_err/expect_err present - ensure test-only or justified"; fi

print_subheader "Option::unwrap_or_default inventory"
uod=$("${GREP_RN[@]}" -e "\.unwrap_or_default\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$uod" -gt 0 ]; then print_finding "info" "$uod" "unwrap_or_default present - validate default semantics"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: DOMAIN-SPECIFIC HEURISTICS
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 16; then
print_header "16. DOMAIN-SPECIFIC HEURISTICS"
print_category "Detects: reqwest builder, SQL string concatenation (heuristic), serde_json::from_str without context" \
  "Domain patterns that often hint at bugs"

print_subheader "reqwest::ClientBuilder inventory"
reqwest_builder=$("${GREP_RN[@]}" -e "reqwest::ClientBuilder::new\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$reqwest_builder" -gt 0 ]; then print_finding "info" "$reqwest_builder" "reqwest ClientBuilder usage - review TLS, timeouts, redirects"; fi

print_subheader "serde_json::from_str without error context (heuristic)"
from_str=$("${GREP_RN[@]}" -e "serde_json::from_str::<" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$from_str" -gt 0 ]; then print_finding "info" "$from_str" "serde_json::from_str uses - ensure error context and validation"; fi

print_subheader "SQL string concatenation (heuristic)"
sql_concat=$("${GREP_RN[@]}" -e "(SELECT|INSERT|UPDATE|DELETE)[^;]*\+[[:space:]]*[_a-zA-Z0-9\"]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$sql_concat" -gt 0 ]; then print_finding "warning" "$sql_concat" "Possible SQL construction via concatenation - prefer parameters"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 17: AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough)
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 17; then
print_header "17. AST-GREP RULE PACK FINDINGS"
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
# CATEGORY 18: META STATISTICS & INVENTORY
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 18; then
print_header "18. META STATISTICS & INVENTORY"
print_category "Detects: crate counts, bin/lib targets, feature flags (Cargo.toml heuristic)" \
  "High-level view of the project layout"

print_subheader "Cargo.toml features (heuristic count)"
cargo_toml="$PROJECT_DIR/Cargo.toml"
if [[ -f "$cargo_toml" ]]; then
  feature_count=$(grep -n "^\[features\]" "$cargo_toml" 2>/dev/null | wc -l | awk '{print $1+0}')
  bin_count=$(grep -E "^\s*\[\[bin\]\]" "$cargo_toml" 2>/dev/null | wc -l | awk '{print $1+0}')
  workspace=$(grep -c "^\[workspace\]" "$cargo_toml" 2>/dev/null || echo 0)
  say "  ${BLUE}${INFO} Info${RESET} ${WHITE}(features sections:${RESET} ${CYAN}${feature_count}${RESET}${WHITE}, bins:${RESET} ${CYAN}${bin_count}${RESET}${WHITE}, workspace:${RESET} ${CYAN}${workspace}${RESET}${WHITE})${RESET}"
else
  print_finding "info" 1 "No Cargo.toml at project root (workspace? set PROJECT_DIR accordingly)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 19: RESOURCE LIFECYCLE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
if category_enabled 19; then
print_header "19. RESOURCE LIFECYCLE CORRELATION"
print_category "Detects: std::thread::spawn without join, tokio::spawn without await, TcpStream without shutdown" \
  "Rust relies on explicit joins/shutdowns even with RAII—leaks create zombie work"

run_resource_lifecycle_checks
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

if [[ -n "$SUMMARY_JSON" ]]; then
  cat >"$SUMMARY_JSON" <<JSON
{
  "files": $TOTAL_FILES,
  "critical": $CRITICAL_COUNT,
  "warning": $WARNING_COUNT,
  "info": $INFO_COUNT,
  "timestamp": "$(now)"
}
JSON
  say "${GREEN}${CHECK} Summary JSON: ${CYAN}$SUMMARY_JSON${RESET}"
fi

EXIT_CODE=0
if (( CRITICAL_COUNT >= FAIL_CRITICAL_THRESHOLD )); then EXIT_CODE=1; fi
if (( FAIL_ON_WARNING == 1 )) && (( CRITICAL_COUNT + WARNING_COUNT > 0 )); then EXIT_CODE=1; fi
if (( FAIL_WARNING_THRESHOLD > 0 )) && (( WARNING_COUNT >= FAIL_WARNING_THRESHOLD )); then EXIT_CODE=1; fi
exit "$EXIT_CODE"
