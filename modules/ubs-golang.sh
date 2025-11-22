#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE GO BUG SCANNER v6.2 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Go (Go 1.23+) using ast-grep
# + smart ripgrep/grep heuristics and module/build hygiene checks.
# Detects: goroutine leaks, context misuse, HTTP client/server timeouts,
# resource leaks, panic/recover pitfalls, error handling issues, crypto risks,
# unsafe/reflect hazards, import hygiene problems, and modernization gaps.
# v6.2 adds: fixed embedded Python bug, new AST rules (context.TODO),
# corrected http.Client Timeout rule, safer AST cache counting,
# better test & DB Tx heuristics, optional gofmt/vet/govulncheck section,
# improved list-rules, dependency/build drift checks, and sturdier scans.
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
shopt -s lastpipe
shopt -s extglob

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

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; HAMMER="🔧"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
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
  [go.async.goroutine-err-no-check]='Handle errors inside goroutines or pass them to an error channel'
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
  [go.taint.command]='Validate and sanitize shell arguments (path.Clean, allowlists) or avoid shell invocation'
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
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

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

if command -v rg >/dev/null 2>&1; then
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

# ────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────────────────────────────────
maybe_clear() { if [[ -t 1 && "$CI_MODE" -eq 0 && "$QUIET" -eq 0 ]]; then clear || true; fi; }

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
      local count; count=$(printf '%s\n' "${raw_count:-0}" | awk 'END{print ($1+0)}')
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
        - has:
            pattern: err := $CALL
        - has:
            pattern: $VAL, err := $CALL
    - not:
        has:
          pattern: if err != nil {
            $$$
          }
YAML
  tmp_json="$(mktemp 2>/dev/null || mktemp -t go_async_matches.XXXXXX)"
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
    print_finding "good" "All goroutines handle errors explicitly"
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
import re, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', 'vendor', '.cache', 'bin', 'dist', '.idea'}
EXTS = {'.go'}
PATH_LIMIT = 5

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

def expr_has_sanitizer(expr: str, sink_rule: str | None = None) -> bool:
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
    for _ in range(5):
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

# AST results cache helpers
ensure_ast_scan_json(){
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  [[ -n "$AST_JSON" && -f "$AST_JSON" ]] && return 0
  AST_JSON="$(mktemp -t ag_json.XXXXXX.json 2>/dev/null || mktemp -t ag_json.XXXXXX)"
  if "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json 2>/dev/null >"$AST_JSON"; then
    AST_SCAN_OK=1
  else
    AST_SCAN_OK=0
    rm -f "$AST_JSON"
    AST_JSON=""
    return 1
  fi
}
ast_count(){
  local id="$1"
  [[ -n "$AST_JSON" && -f "$AST_JSON" ]] || { echo 0; return 0; }
  grep -o "\"id\"[[:space:]]*:[[:space:]]*\"${id//\//\\/}\"" "$AST_JSON" 2>/dev/null | wc -l | awk '{print $1+0}'
}

# ────────────────────────────────────────────────────────────────────────────
# ast-grep: detection, rule packs, and wrappers (Go heavy)
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
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang go "$PROJECT_DIR" 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
  else
    return 1
  fi
}

ast_search_with_context() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "$pattern" --lang go "$PROJECT_DIR" --json 2>/dev/null || true ) \
      | head -n "$limit" || true
  fi
}

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
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
  any:
    - pattern: context.WithCancel($$)
    - pattern: context.WithTimeout($$)
    - pattern: context.WithDeadline($$)
  not:
    inside:
      pattern: defer $CANCEL()
severity: info
message: "context.With* called without a deferred cancel() in the same scope (heuristic)."
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
  pattern: $TICKER := time.NewTicker($ARGS)
  not:
    inside:
      pattern: $TICKER.Stop()
severity: warning
message: "time.NewTicker result not stopped in the same scope."
YAML

  cat >"$AST_RULE_DIR/go-resource-timer.yml" <<'YAML'
id: go.resource.timer-no-stop
language: go
rule:
  pattern: $TIMER := time.NewTimer($ARGS)
  not:
    inside:
      pattern: $TIMER.Stop()
severity: warning
message: "time.NewTimer result not stopped or drained in the same scope."
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
}

run_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]] || return 1
  local outfmt="--json"; [[ "$FORMAT" == "sarif" ]] && outfmt="--sarif"
  if "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" $outfmt 2>/dev/null; then
    return 0
  else
    return 1
  fi
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
# Main Scan Logic
# ────────────────────────────────────────────────────────────────────────────

maybe_clear

[[ "$QUIET" -eq 1 || "$FORMAT" != "text" ]] || echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗      ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝      ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗        ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝        ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗      ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝      ║
║                                           ,_---~~~~~----._           ║
║  ██████╗ ██╗   ██╗ ██████╗         _,,_,*^____      _____``*g*\"*,   ║
║  ██╔══██╗██║   ██║██╔════╝        / __/ /'     ^.  /      \ ^@q   f  ║
║  ██████╔╝██║   ██║██║  ███╗      [  @f | @))    |  | @))   l  0 _/   ║
║  ██╔══██╗██║   ██║██║   ██║       \`/   \~____ / __ \_____/    \     ║
║  ██████╔╝╚██████╔╝╚██████╔╝        |           _l__l_           I    ║
║  ╚═════╝  ╚═════╝  ╚═════╝         }          [______]           I   ║
║                                    ]            | | |            |   ║
║                                    ]             ~ ~             |   ║
║                                    |                            |    ║
║                                     |                           |    ║
║                                                                      ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗      ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗     ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝     ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗     ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║     ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝          ║
║                                                                      ║
║  Go module • goroutine, context, HTTP client/server guardrails       ║
║  UBS module: golang • AST packs + gofmt/go test integration          ║
║  ASCII homage: Renee French gopher lineage                           ║
║  Run standalone: modules/ubs-golang.sh --help                        ║
║                                                                      ║
║  Night Owl QA                                                        ║
║  “We see bugs before you do.”                                        ║
╚══════════════════════════════════════════════════════════════════════╝
BANNER
[[ "$QUIET" -eq 1 || "$FORMAT" != "text" ]] || echo -e "${RESET}"

[[ "$FORMAT" == "text" ]] && {
  say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
  say "${WHITE}Started:${RESET}  ${GRAY}$(eval "$DATE_CMD")${RESET}"
}

# Count files (robust find; avoid dangling -o)
EX_PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do EX_PRUNE+=( -name "$d" -o ); done
EX_PRUNE=( \( -type d \( "${EX_PRUNE[@]}" -false \) -prune \) )
NAME_EXPR=( \( )
first=1
# exact names
for n in "${_NAME_ARR[@]}"; do
  if [[ $first -eq 1 ]]; then NAME_EXPR+=( -name "$n" ); first=0
  else NAME_EXPR+=( -o -name "$n" ); fi
done
# extensions
for e in "${_EXT_ARR[@]}"; do
  if [[ $first -eq 1 ]]; then NAME_EXPR+=( -name "*.${e}" ); first=0
  else NAME_EXPR+=( -o -name "*.${e}" ); fi
done
NAME_EXPR+=( \) )
TOTAL_FILES=$(
  ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) | wc -l | awk '{print $1+0}'
)
[[ "$FORMAT" == "text" ]] && say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES${RESET} ${DIM}(${INCLUDE_EXT}; ${INCLUDE_NAMES})${RESET}"

# ast-grep availability
echo ""
if check_ast_grep; then
  [[ "$FORMAT" == "text" ]] && say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
  write_ast_rules || true
  if [[ "$LIST_RULES" -eq 1 ]]; then
    awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$AST_RULE_DIR"/*.yml | sort -u
    exit 0
  fi
  ensure_ast_scan_json || true
else
  [[ "$FORMAT" == "text" ]] && say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# Machine-output mode: emit JSON/SARIF and exit with terse summary
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    if [[ "$FORMAT" == "json" ]]; then
      "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --json 2>/dev/null
    else
      "${AST_GREP_CMD[@]}" scan -r "$AST_RULE_DIR" "$PROJECT_DIR" --sarif 2>/dev/null
    fi
  fi
  end_scan_section
  {
    echo ""
    echo "Summary (machine output emitted on stdout):"
    echo "  Files: $TOTAL_FILES"
  } 1>&2
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: CONCURRENCY & GOROUTINE SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 1; then
print_header "1. CONCURRENCY & GOROUTINE SAFETY"
print_category "Detects: goroutines in loops, WaitGroup imbalance, manual lock/unlock, tickers not stopped" \
  "Race-prone constructs and lifecycle mistakes cause leaks and deadlocks"

print_subheader "Goroutines launched"
go_count=$("${GREP_RN[@]}" -e "^[[:space:]]*go[[:space:]]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$go_count" "goroutine launches found"

print_subheader "go inside loops (ensure capture correctness)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.goroutine-in-loop" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "goroutine launches inside loops"; fi

print_subheader "loop variable captured by goroutine (closure)"
cap=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.loop-var-capture" || echo 0)
if [ "$cap" -gt 0 ]; then print_finding "warning" "$cap" "Loop variable captured by goroutine closure"; fi

print_subheader "sync.WaitGroup Add/Done balance (heuristic)"
wg_add=$("${GREP_RN[@]}" -e "\.Add\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
wg_done=$("${GREP_RN[@]}" -e "\.Done\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$wg_add" -gt $((wg_done + 1)) ]; then
  diff=$((wg_add - wg_done)); print_finding "warning" "$diff" "WaitGroup Add exceeds Done (heuristic)"; fi

print_subheader "Mutex manual Lock/Unlock (prefer defer after Lock)"
lock_count=$("${GREP_RN[@]}" -e "\.Lock\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
defer_unlock=$("${GREP_RN[@]}" -e "defer[[:space:]]+.*\.Unlock\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$lock_count" -gt 0 ]; then
  if [ "$defer_unlock" -lt $((lock_count/2)) ]; then
    print_finding "warning" "$lock_count" "Manual Lock without matching defer Unlock (heuristic)" "Place 'defer mu.Unlock()' immediately after Lock"
  else
    print_finding "good" "Most locks appear paired with deferred unlock"
  fi
fi

print_subheader "time.NewTicker without Stop (heuristic)"
ticker_new=$("${GREP_RN[@]}" -e "time\.NewTicker\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
ticker_stop=$("${GREP_RN[@]}" -e "\.Stop\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$ticker_new" -gt 0 ] && [ "$ticker_stop" -lt "$ticker_new" ]; then
  diff=$((ticker_new - ticker_stop)); print_finding "warning" "$diff" "Ticker created without Stop (heuristic)"; fi

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
sel_count=$("${GREP_RN[@]}" -e "^[[:space:]]*select[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$sel_count" "select statements present"
if [[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]]; then
  s_nd=$((ast_count "go.select-no-default"))
  if [ "$s_nd" -gt 0 ]; then print_finding "info" "$s_nd" "select without default (check for intended blocking/timeouts)"; fi
fi

print_subheader "time.After used inside loops"
count=$("${GREP_RN[@]}" -e "for[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | (grep -A5 "time\.After\(" || true) | (grep -cw "time\.After\(" || true))
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

print_subheader "context.With* calls without cancel (heuristic)"
with_calls=$("${GREP_RN[@]}" -e "context\.With(Cancel|Timeout|Deadline)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
cancel_calls=$("${GREP_RN[@]}" -e "\bcancel\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$with_calls" -gt "$cancel_calls" ]; then diff=$((with_calls - cancel_calls)); print_finding "warning" "$diff" "With* without cancel (heuristic)"; else print_finding "good" "Cancel seems used with context.With*"; fi

print_subheader "http handlers using context.Background() (heuristic)"
count=$("${GREP_RN[@]}" -e "func[[:space:]]*\([[:space:]]*w[[:space:]]+http\.ResponseWriter,[[:space:]]*r[[:space:]]+\*http\.Request[[:space:]]*\)" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A5 "context\.Background\(" || true) | (grep -cw "context\.Background\(" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Use r.Context() instead of context.Background() in handlers"; fi

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
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Default http.Client without Timeout"; else print_finding "good" "No obvious default client usage"; fi

print_subheader "http.Client without Timeout"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-client-without-timeout" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "http.Client constructed without Timeout"; fi

print_subheader "http.Server without timeouts (none set)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-server-no-timeouts" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "http.Server lacks timeouts"; fi

print_subheader "http.NewRequest without context"
nr=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.http-newrequest-without-context" || echo 0)
if [ "$nr" -gt 0 ]; then print_finding "info" "$nr" "Prefer http.NewRequestWithContext"; fi

print_subheader "Response body Close() (heuristic)"
http_calls=$("${GREP_RN[@]}" -e "http\.(Get|Post|Head)\(|\.Do\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
body_close=$("${GREP_RN[@]}" -e "\.Body\.Close\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$http_calls" -gt 0 ] && [ "$body_close" -lt "$http_calls" ]; then
  diff=$((http_calls - body_close)); print_finding "warning" "$diff" "Possible missing resp.Body.Close() (heuristic)"
else
  print_finding "good" "Response bodies likely closed (heuristic)"
fi

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

print_subheader "database/sql Rows/Tx Close (heuristic)"
rows_open=$("${GREP_RN[@]}" -e "\.Query(Row|Context)?\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
rows_close=$("${GREP_RN[@]}" -e "\.(Rows|Row)\.Close\(|rows\.Close\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$rows_open" -gt 0 ] && [ "$rows_close" -lt "$rows_open" ]; then
  diff=$((rows_open - rows_close)); print_finding "info" "$diff" "Potential missing rows.Close() (heuristic)"
fi

print_subheader "database/sql Tx Commit/Rollback (heuristic)"
tx_begin=$("${GREP_RN[@]}" -e "\b(Begin|BeginTx)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
tx_end=$("${GREP_RN[@]}" -e "\.(Commit|Rollback)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$tx_begin" -gt 0 ] && [ "$tx_end" -lt "$tx_begin" ]; then
  diff=$((tx_begin - tx_end)); print_finding "warning" "$diff" "Tx started without Commit/Rollback (heuristic)"; fi

print_subheader "time.Tick usage"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.time-tick" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "time.Tick leaks; prefer NewTicker"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ERROR HANDLING & WRAPPING
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. ERROR HANDLING & WRAPPING"
print_category "Detects: ignored errors, fmt.Errorf without %w, panic in library code, recover outside defer" \
  "Robust error paths prevent crashes and lost context"

print_subheader "Ignored errors via blank identifier (heuristic)"
ignored=$("${GREP_RN[@]}" -e ",[[:space:]]*_[[:space:]]*:=" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$ignored" -gt 0 ]; then print_finding "info" "$ignored" "Assignments discarding secondary return values (could be error)"; fi

print_subheader "fmt.Errorf without %w when wrapping err"
count=$("${GREP_RN[@]}" -e "fmt\.Errorf\(" "$PROJECT_DIR" 2>/dev/null | (grep -v "%w" || true) | (grep -E "err[),]" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Consider using %w when wrapping errors"; fi

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
print_category "Detects: Decoder without DisallowUnknownFields, unchecked Unmarshal, heavy ReadAll" \
  "Parsing mistakes silently lose data or crash later"

print_subheader "json.Decoder without DisallowUnknownFields"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.json-decode-without-disallow" || echo 0)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Consider Decoder.DisallowUnknownFields()"; fi

print_subheader "json.Unmarshal calls"
u_count=$("${GREP_RN[@]}" -e "json\.Unmarshal\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$u_count" -gt 0 ]; then print_finding "info" "$u_count" "json.Unmarshal found - ensure errors handled and input validated"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: FILESYSTEM & I/O
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 8; then
print_header "8. FILESYSTEM & I/O"
print_category "Detects: ioutil (deprecated), ReadAll on bodies, Close leaks" \
  "I/O mistakes cause memory spikes and descriptor leaks"

print_subheader "ioutil package usage (deprecated)"
ioutil_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.ioutil-deprecated" || echo 0)
if [ "$ioutil_count" -gt 0 ]; then print_finding "info" "$ioutil_count" "Replace ioutil.* with io/os equivalents"; fi

print_subheader "io.ReadAll usage"
ra_count=$("${GREP_RN[@]}" -e "io\.ReadAll\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$ra_count" -gt 10 ]; then print_finding "info" "$ra_count" "Many ReadAll calls - ensure bounded inputs"; fi

print_subheader "File open without Close (heuristic)"
open_count=$("${GREP_RN[@]}" -e "os\.Open(File)?\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
close_count=$("${GREP_RN[@]}" -e "\.Close\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$open_count" -gt 0 ] && [ "$close_count" -lt "$open_count" ]; then
  diff=$((open_count - close_count)); print_finding "warning" "$diff" "Potential missing Close() calls (heuristic)"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: CRYPTOGRAPHY & SECURITY
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 9; then
print_header "9. CRYPTOGRAPHY & SECURITY"
print_category "Detects: weak hashes, math/rand for security, InsecureSkipVerify, exec sh -c" \
  "Security footguns are easy to miss and costly to fix"

print_subheader "Weak hashes (md5/sha1) and RC4"
count=$("${GREP_RN[@]}" -e "md5|sha1|rc4" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "Weak crypto primitives detected - use SHA-256/512, AES-GCM, etc."; fi

print_subheader "math/rand used for secrets"
rand_count=$("${GREP_RN[@]}" -e "\bmath/rand\b|\brand\.Seed\(|\brand\.Read\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$rand_count" -gt 0 ]; then print_finding "info" "$rand_count" "math/rand present - avoid for secrets; prefer crypto/rand"; fi

print_subheader "TLS InsecureSkipVerify=true"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.tls-insecure-skip" || echo 0)
if [ "$count" -eq 0 ] && command -v rg >/dev/null 2>&1; then
  count=$(rg --no-config --no-messages -g '*.go' -n "InsecureSkipVerify:[[:space:]]*true" "$PROJECT_DIR" 2>/dev/null | wc_num)
fi
if [ "$count" -gt 0 ]; then print_finding "warning" "$count" "InsecureSkipVerify enabled"; fi

print_subheader "exec sh -c (command injection risk)"
count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.exec-sh-c" || echo 0)
if [ "$count" -eq 0 ]; then
  count=$(rg --no-config --no-messages -g '*.go' -n 'exec\.Command(Context)?\(\s*"(sh|bash)"\s*,\s*"-?c"' "$PROJECT_DIR" 2>/dev/null | wc -l | awk '{print $1+0}')
fi
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "exec.Command(*, \"sh\", \"-c\", ...) detected"; fi

print_subheader "exec without context"
cmdctx=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.exec-command-without-context" || echo 0)
if [ "$cmdctx" -gt 0 ]; then print_finding "info" "$cmdctx" "Prefer exec.CommandContext(ctx, ...)"; fi

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
unsafe_count=$("${GREP_RN[@]}" -e "import[[:space:]]+\"unsafe\"|unsafe\." "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$unsafe_count" -gt 0 ]; then print_finding "info" "$unsafe_count" "unsafe usage present - verify invariants and alignment"; fi

print_subheader "reflect usage"
refl_count=$("${GREP_RN[@]}" -e "\breflect\." "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$refl_count" -gt 0 ]; then print_finding "info" "$refl_count" "reflect usage present - consider generics or interfaces"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: IMPORT HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 11; then
print_header "11. IMPORT HYGIENE"
print_category "Detects: dot-imports, blank imports, duplicate module trees" \
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
print_category "Detects: go.mod version < 1.23, missing go.sum, toolchain directive" \
  "Build settings directly affect correctness and performance"

print_subheader "go.mod presence and version directive"
mod_files=$( ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name "go.mod" -print \) 2>/dev/null || true ) )
mods_count=$(printf "%s\n" "$mod_files" | sed '/^$/d' | wc -l | awk '{print $1+0}')
if [ "$mods_count" -gt 0 ]; then
  print_finding "info" "$mods_count" "go.mod file(s) present"
  up_to_date=0; outdated=0
  while IFS= read -r mf; do
    gv=$(grep -E '^[[:space:]]*go[[:space:]]+[0-9]+\.[0-9]+' "$mf" 2>/dev/null | head -n1 | awk '{print $2}')
    if [[ -n "$gv" && "$gv" =~ ^1\.(2[3-9]|[3-9][0-9])(\.[0-9]+)?$ ]]; then up_to_date=$((up_to_date+1)); else outdated=$((outdated+1)); fi
  done <<<"$mod_files"
  if [ "$outdated" -gt 0 ]; then print_finding "warning" "$outdated" "go.mod with go directive < 1.23" "Set 'go 1.23' (or newer) where appropriate"; else print_finding "good" "All modules declare go >= 1.23"; fi
else
  print_finding "warning" 1 "No go.mod found" "Use modules; GOPATH mode is legacy"
fi

print_subheader "go.sum presence"
sum_files=$( ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name "go.sum" -print \) 2>/dev/null || true ) )
s_count=$(printf "%s\n" "$sum_files" | sed '/^$/d' | wc -l | awk '{print $1+0}')
if [ "$s_count" -eq 0 ]; then print_finding "info" 1 "go.sum not found"; else print_finding "good" "go.sum present"; fi

print_subheader "toolchain directive usage (informational)"
tool_count=$("${GREP_RN[@]}" -e "^[[:space:]]*toolchain[[:space:]]+go[0-9]+\.[0-9]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$tool_count" -gt 0 ]; then print_finding "info" "$tool_count" "toolchain directive present"; fi

print_subheader "replace directives (informational)"
repl=$("${GREP_RN[@]}" -e "^[[:space:]]*replace[[:space:]]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
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
tests=$("${GREP_RN[@]}" -e "_test\.go$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$tests" -gt 0 ]; then print_finding "info" "$tests" "Test files detected"; else print_finding "info" 0 "No test files found"; fi

print_subheader "t.Parallel usage (heuristic)"
test_funcs=$("${GREP_RN[@]}" -e "^func[[:space:]]+Test[[:alnum:]_]*\(t[[:space:]]+\*testing\.T\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
tpar=$("${GREP_RN[@]}" -e "t\.Parallel\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
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
fmt_count=$("${GREP_RN[@]}" -e "fmt\.Print(f|ln)?\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$fmt_count" -gt 50 ]; then print_finding "info" "$fmt_count" "Heavy fmt.* logging - consider structured logging"; fi

print_subheader "Logging secrets (heuristic)"
secret_logs=$("${GREP_RNI[@]}" -e "log\.(Print|Printf|Println|Fatal|Panic).*?(password|secret|token|authorization|bearer)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$secret_logs" -gt 0 ]; then print_finding "critical" "$secret_logs" "Possible logging of sensitive data"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: STYLE & MODERNIZATION
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 15; then
print_header "15. STYLE & MODERNIZATION"
print_category "Detects: interface{} vs any, dot-imports, context parameter position (heuristic)" \
  "Modern idioms reduce boilerplate and mistakes"

print_subheader "interface{} occurrences"
iface_count=$([[ "$HAS_AST_GREP" -eq 1 && -f "$AST_JSON" ]] && ast_count "go.interface-empty" || echo 0)
if [ "$iface_count" -gt 0 ]; then print_finding "info" "$iface_count" "Prefer 'any' over 'interface{}'"; fi

print_subheader "context.Context parameter not first (heuristic)"
ctx_mispos=$("${GREP_RN[@]}" -e "^func[[:space:]]*(\([^)]+\)[[:space:]]*)?[A-Za-z_][A-Za-z0-9_]*\([^)]*context\.Context" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "(ctx[[:space:]]+context\.Context" || true) | count_lines)
if [ "$ctx_mispos" -gt 0 ]; then print_finding "info" "$ctx_mispos" "Place ctx context.Context first param"; fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: PANIC/RECOVER & TIME PATTERNS (AST Pack echo)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 16; then
print_header "16. PANIC/RECOVER & TIME PATTERNS (AST Pack)"
print_category "AST-detected: panic(), recover outside defer, time.Tick, time.After in loop" \
  "Codifies common pitfalls as precise AST rules"

# Summarize AST rule counts (if any)
if [[ "$HAS_AST_GREP" -eq 1 && -n "$AST_RULE_DIR" ]]; then
  ensure_ast_scan_json || true
  if [[ -f "$AST_JSON" ]]; then
    tmp_json="$AST_JSON"
  else
    tmp_json="$(mktemp)"
    run_ast_rules >"$tmp_json" || true
  fi
  say "${DIM}${INFO} ast-grep produced structured matches. Tally by rule id:${RESET}"
  ids=$(grep -o '"id"[:][ ]*"[^"]*"' "$tmp_json" | sed -E 's/.*"id"[ ]*:[ ]*"([^"]*)".*/\1/' || true)
  if [[ -n "$ids" ]]; then
    printf "%s\n" "$ids" | sort | uniq -c | awk '{printf "  • %-40s %5d\n",$2,$1}'
  else
    say "  (no matches)"
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
  gofmt_out="$( ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f -name '*.go' -print \) 2>/dev/null || true ) | xargs -r gofmt -s -l 2>/dev/null || true )"
  gf_count=$(printf "%s\n" "$gofmt_out" | sed '/^$/d' | wc -l | awk '{print $1+0}')
  if [ "$gf_count" -gt 0 ]; then print_finding "info" "$gf_count" "Files not gofmt -s clean"
    printf "%s\n" "$gofmt_out" | head -n "$DETAIL_LIMIT" | sed "s/^/${DIM}      /;s/$/${RESET}/" | sed "s/^/$(printf '')/"
  else
    print_finding "good" "All Go files are gofmt -s clean"
  fi

  print_subheader "go vet"
  if out_vet=$( ( set +o pipefail; cd "$PROJECT_DIR" && go vet "$GOTEST_PKGS" 2>&1 || true ) ); then
    vet_lines=$(printf "%s" "$out_vet" | sed '/^$/d' | wc -l | awk '{print $1+0}')
    if [ "$vet_lines" -gt 0 ]; then print_finding "warning" "$vet_lines" "go vet findings (review output)"
      printf "%s\n" "$out_vet" | head -n "$((DETAIL_LIMIT*3))" | sed "s/^/${DIM}      /;s/$/${RESET}/"
    else
      print_finding "good" "go vet reported no issues"
    fi
  else
    print_finding "info" 0 "go vet skipped"
  fi

  print_subheader "govulncheck"
  if command -v govulncheck >/dev/null 2>&1; then
    gv_out="$( ( set +o pipefail; cd "$PROJECT_DIR" && govulncheck -format=text "$GOTEST_PKGS" 2>/dev/null || true ) )"
    gv_cnt=$(printf "%s" "$gv_out" | grep -E -c '^(Vulnerability|module:|package:|symbol:)')
    if [ "$gv_cnt" -gt 0 ]; then print_finding "warning" "$gv_cnt" "govulncheck reported potential vulnerabilities"
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
print_category "Detects: multiple modules, inconsistent go directives, missing replace cleanup" \
  "Prevents subtle build reproducibility problems"
mods_mismatch=0
if [ "$mods_count" -gt 1 ]; then
  print_subheader "Multiple modules detected"
  print_finding "info" "$mods_count" "Multiple go.mod; check for monorepo consistency"
fi

print_subheader "Inconsistent go directive versions across modules (heuristic)"
if [ "$mods_count" -gt 1 ]; then
  versions="$( while IFS= read -r mf; do grep -E '^[[:space:]]*go[[:space:]]+[0-9]+\.[0-9]+' "$mf" 2>/dev/null | head -n1 | awk '{print $2"  "FILENAME}'; done <<<"$mod_files" )"
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
say "${DIM}Scan completed at: $(eval "$DATE_CMD")${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning . > go-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
exit "$EXIT_CODE"
