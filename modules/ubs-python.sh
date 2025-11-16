#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# PYTHON ULTIMATE BUG SCANNER v2.0 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Python (3.13+) using:
#   • ast-grep (rule packs; language: python)
#   • ripgrep/grep heuristics for fast code smells
#   • optional uv-powered extra analyzers (ruff, bandit, pip-audit)
#   • optional mypy/pyright (if installed) for type-checking touchpoints
#   • optional safety / detect-secrets if available
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
#   --fail-on-warning, --skip, --jobs, --include-ext, --exclude, --ci, --no-color
#   --summary-json FILE  (machine-readable run summary)
#   --max-detailed N     (cap detailed code samples)
#
# CI-friendly timestamps, robust find, safe pipelines, auto parallel jobs.
# Heavily leverages ast-grep for Python via rule packs; complements with rg.
# Integrates uv (if installed) to run ruff/bandit/pip-audit without setup.
# Adds portable timeout resolution (timeout/gtimeout) and UTF‑8-safe output.
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

# Symbols (ensure UTF-8 output; run grep under LC_ALL=C separately)
SAFE_LOCALE="C"
if locale -a 2>/dev/null | grep -qi '^C\.UTF-8$'; then SAFE_LOCALE="C.UTF-8"; fi
export LC_CTYPE="$SAFE_LOCALE"
export LC_MESSAGES="$SAFE_LOCALE"

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
ENABLE_UV_TOOLS=1                     # try uv integrations by default
UV_TOOLS="ruff,bandit,pip-audit"      # subset via --uv-tools=
UV_TIMEOUT="${UV_TIMEOUT:-1200}"      # generous time budget per tool
ENABLE_EXTRA_TOOLS=1                  # mypy/pyright/safety/detect-secrets if present
SUMMARY_JSON=""
TIMEOUT_CMD=""                        # resolved later

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --no-uv                  Disable uv-powered extra analyzers
  --uv-tools=CSV           Which uv tools to run (default: $UV_TOOLS)
  --summary-json=FILE      Also write machine-readable summary JSON
  --max-detailed=N         Cap number of detailed code samples (default: $MAX_DETAILED)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI, UV_TIMEOUT
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
HAS_RIPGREP=0
UVX_CMD=()           # (uvx -q or uv -qx) if available
HAS_UV=0

# Resource lifecycle correlation spec (acquire vs release pairs)
RESOURCE_LIFECYCLE_IDS=(file_handle popen_handle asyncio_task)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [file_handle]="critical"
  [popen_handle]="warning"
  [asyncio_task]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [file_handle]='open\('
  [popen_handle]='subprocess\.Popen\('
  [asyncio_task]='asyncio\.create_task'
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
  [file_handle]='\.close\(|with[[:space:]]+open'
  [popen_handle]='\.wait\(|\.communicate\(|\.terminate\(|\.kill\('
  [asyncio_task]='\.cancel\(|await[[:space:]]+asyncio\.(gather|wait)'
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [file_handle]='File handles opened without context manager/close'
  [popen_handle]='Popen handles not waited or terminated'
  [asyncio_task]='asyncio tasks spawned without cancellation/await'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [file_handle]='Use "with open(...)" or explicitly call .close()'
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
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden --pcre2 "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=()
  for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  GREP_RN=("${GREP_ENV[@]}" rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNI=("${GREP_ENV[@]}" rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNW=("${GREP_ENV[@]}" rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("${GREP_ENV[@]}" grep "${GREP_R_OPTS[@]}" -n -w -E)
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
  # Capture BODY region (root-cause fix: previously captured COND)
  ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern $'if $COND:\n    $BODY' --lang python "$PROJECT_DIR" --json=stream 2>/dev/null || true ) >"$tmp_ifs"

  result=$(python3 - "$tmp_attrs" "$tmp_ifs" "$limit" <<'PYHELP'
import json, sys
from collections import defaultdict

def load_stream(path):
    data = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return data
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
    if not file_path or not body:
        continue
    rng = body.get('range') or {}
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
    if not file_path or not start or not end:
        continue
    start_pos = as_pos(start); end_pos = as_pos(end)
    regions = bodies_by_file.get(file_path, [])
    if any(within((start_pos, end_pos), region) for region in regions):
        guarded += 1
        continue
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
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
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

  cat >"$AST_RULE_DIR/bare-except.yml" <<'YAML'
id: py.bare-except
language: python
rule:
  pattern: |
    try:
      $A
    except:
      $B
severity: critical
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
severity: critical
message: "Mutable default argument; use default=None and set in body"
YAML

  cat >"$AST_RULE_DIR/eval-exec.yml" <<'YAML'
id: py.eval-exec
language: python
rule:
  any:
    - pattern: eval($$)
    - pattern: exec($$)
severity: critical
message: "Avoid eval/exec; leads to code injection"
YAML

  cat >"$AST_RULE_DIR/pickle-load.yml" <<'YAML'
id: py.pickle-load
language: python
rule:
  any:
    - pattern: pickle.load($$)
    - pattern: pickle.loads($$)
severity: critical
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
severity: critical
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
severity: critical
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
  pattern: open($FNAME)
  not:
    has:
      pattern: encoding=$ENC
  not:
    has:
      pattern: "mode='b'"
severity: info
message: "open() without encoding=... may be non-deterministic across locales"
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
severity: critical
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

  # Done writing rules
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
# uv integrations & timeout resolution
# ────────────────────────────────────────────────────────────────────────────
check_uv() {
  if command -v uvx >/dev/null 2>&1; then UVX_CMD=(uvx -q); HAS_UV=1; return 0; fi
  if command -v uv  >/dev/null 2>&1; then UVX_CMD=(uv -qx); HAS_UV=1; return 0; fi
  HAS_UV=0; return 1
}

resolve_timeout() {
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

# Validate project dir
if [[ ! -d "$PROJECT_DIR" ]]; then
  echo -e "${RED}${BOLD}Project directory not found:${RESET} ${WHITE}$PROJECT_DIR${RESET}" >&2
  exit 2
fi

# Resolve portable timeout
resolve_timeout || true

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
  ( set +o pipefail; find "$PROJECT_DIR" "${EX_PRUNE[@]}" -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
  | wc -l | awk '{print $1+0}'
)
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
if [[ "$HAS_AST_GREP" -eq 1 ]]; then
  # High-level heuristic: count loops; detailed evidence shown elsewhere
  count=$("${AST_GREP_CMD[@]}" --lang python --pattern $'for $I in $C:\n    $B' "$PROJECT_DIR" --json=stream 2>/dev/null | grep -c . || true)
else
  count=$("${GREP_RN[@]}" -e "for[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+in[[:space:]]+[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fi
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Possible mutation during iteration" "Copy or iterate over snapshot"
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
  (grep -v "#.*(password|api_?key|secret|token)" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Potential hardcoded secrets" "Use secret manager or env vars"
  show_detailed_finding "(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*['\"][^\"']+['\"]" 5
fi

print_subheader "tempfile.mktemp (insecure)"
count=$("${GREP_RN[@]}" -e "tempfile\.mktemp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "critical" "$count" "Insecure tempfile.mktemp usage" "Use NamedTemporaryFile/mkstemp"; fi
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
count=$("${GREP_RN[@]}" -e "json\.loads\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
trycatch_count=$("${GREP_RNW[@]}" -B2 "try" "$PROJECT_DIR" 2>/dev/null || true | (grep -c "json\.loads" || true))
trycatch_count=$(printf '%s\n' "$trycatch_count" | awk 'END{print $0+0}')
if [ "$count" -gt "$trycatch_count" ]; then
  ratio=$((count - trycatch_count))
  print_finding "warning" "$ratio" "json.loads without error handling" "Wrap in try/except ValueError"
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
  show_detailed_finding "logging\.(debug|info|warning|error|exception)\(.*(password|token|secret|Bearer|Authorization)" 3
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
count=$("${GREP_RN[@]}" -e "open\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "with[[:space:]]+open\(" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "open() outside 'with' block" "Wrap in 'with' to ensure close()"
fi

print_subheader "open() without explicit encoding"
count=$("${GREP_RN[@]}" -e "open\([^\)]*\)" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "encoding[[:space:]]*=" || true) | count_lines
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "No encoding in open()" "Specify encoding= 'utf-8' etc."
fi

print_subheader "shutil.rmtree(ignore_errors=True)"
count=$("${GREP_RN[@]}" -e "shutil\.rmtree\([^)]*ignore_errors\s*=\s*True" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "rmtree(ignore_errors=True) hides failures"; fi
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
# AST-GREP RULE PACK FINDINGS (JSON/SARIF passthrough)
# ═══════════════════════════════════════════════════════════════════════════
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

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 20: UV-POWERED EXTRA ANALYZERS (optional)
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 20; then
print_header "20. UV-POWERED EXTRA ANALYZERS"
print_category "Ruff linting, Bandit security, Pip-audit (supply chain)" \
  "Uses uvx when available; falls back to system tools if installed."

if [[ "$ENABLE_UV_TOOLS" -eq 1 ]]; then
  IFS=',' read -r -a UVLIST <<< "$UV_TOOLS"
  for TOOL in "${UVLIST[@]}"; do
    case "$TOOL" in
      ruff)
        print_subheader "ruff (lint)"
        # Use ruff's counting mode to quantify diagnostics, also emit JSON for context
        run_uv_tool_text ruff check "$PROJECT_DIR" --output-format=json || true
        ruff_count=$(run_uv_tool_text ruff check "$PROJECT_DIR" --output-format=count | tail -n1 | awk '{print $1+0}')
        if [ "${ruff_count:-0}" -gt 0 ]; then print_finding "info" "$ruff_count" "Ruff emitted findings" "Review ruff output above"; else print_finding "good" "Ruff clean"; fi
        ;;
      bandit)
        print_subheader "bandit (security)"
        _EXC=""; for d in "${EXCLUDE_DIRS[@]}"; do _EXC="${_EXC:+$_EXC,}$d"; done
        if run_uv_tool_text bandit -q -r "$PROJECT_DIR" -x "$_EXC"; then
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
          run_uv_tool_text pip-audit -P "$PROJECT_DIR/pyproject.toml" || true
        else
          run_uv_tool_text pip-audit || true
        fi
        print_finding "info" 0 "pip-audit run (if available)" "Review advisories above"
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
    printf '"uv_tools":"%s"' "$(printf %s "$UV_TOOLS" | sed 's/"/\\"/g')"
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
