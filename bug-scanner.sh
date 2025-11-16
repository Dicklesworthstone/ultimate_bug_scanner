#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ULTIMATE BUG SCANNER v4.4 - Industrial-Grade Code Quality Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis using ast-grep + semantic pattern matching
# Catches bugs that cost developers hours of debugging
# v4.4 adds: robust find, safe pipelines, richer AST rules, --no-color, --rules,
# improved ERR diagnostics, auto jobs, JSON/SARIF passthrough
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
USER_RULE_DIR=""
DISABLE_PIPEFAIL_DURING_SCAN=1

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
EXCLUDE_DIRS=(node_modules dist build coverage .next out .turbo .cache .git)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

if command -v rg >/dev/null 2>&1; then
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

# Temporarily relax pipefail for grep-heavy scans to avoid ERR on 1/no-match
begin_scan_section(){ if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi; }
end_scan_section(){ if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi; }

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

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ag_rules.XXXXXX)"
  trap '[[ -n "${AST_RULE_DIR:-}" ]] && rm -rf "$AST_RULE_DIR" || true' EXIT
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi
  # Core rules
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
severity: critical
message: "Direct NaN comparison is always false; use Number.isNaN(x)"
YAML
  cat >"$AST_RULE_DIR/await-non-async.yml" <<'YAML'
id: js.await-non-async
language: javascript
rule:
  pattern: await $EXPR
  not:
    inside:
      pattern: async function $FN($$) { $$ }
severity: critical
message: "await used inside non-async function"
YAML
  cat >"$AST_RULE_DIR/innerHTML-assign.yml" <<'YAML'
id: js.innerHTML-assign
language: javascript
rule:
  pattern: $EL.innerHTML = $VAL
severity: warning
message: "Assigning innerHTML; ensure input is sanitized or use textContent"
YAML
  cat >"$AST_RULE_DIR/then-without-catch.yml" <<'YAML'
id: js.then-without-catch
language: javascript
rule:
  pattern: $P.then($$)
  not:
    has:
      pattern: .catch($$)
severity: warning
message: "Promise.then without catch/finally; handle rejections"
YAML
  cat >"$AST_RULE_DIR/eval-call.yml" <<'YAML'
id: js.eval-call
language: javascript
rule:
  kind: call_expression
  pattern: eval($$)
severity: critical
message: "eval() allows arbitrary code execution"
YAML
  cat >"$AST_RULE_DIR/new-function.yml" <<'YAML'
id: js.new-function
language: javascript
rule:
  kind: new_expression
  pattern: new Function($$)
severity: critical
message: "new Function() is equivalent to eval()"
YAML
  cat >"$AST_RULE_DIR/document-write.yml" <<'YAML'
id: js.document-write
language: javascript
rule:
  pattern: document.write($$)
severity: critical
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
language: typescript
rule:
  kind: jsx_element
  inside:
    pattern: {$ARR.map($FN => $JSX)}
  not:
    has:
      pattern: key={$KEY}
severity: warning
message: "JSX list item missing key prop"
YAML
  cat >"$AST_RULE_DIR/react-dangerously-set-html.yml" <<'YAML'
id: react.dangerously-set-html
language: typescript
rule:
  pattern: <$_ dangerouslySetInnerHTML={$OBJ} />
severity: warning
message: "dangerouslySetInnerHTML used; ensure the HTML is sanitized"
YAML
  cat >"$AST_RULE_DIR/react-setstate-in-render.yml" <<'YAML'
id: react.setstate-in-render
language: typescript
rule:
  pattern: render($$) { $$.setState($$) }
severity: critical
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
  # JSON.parse without try/catch
  cat >"$AST_RULE_DIR/json-parse-no-try.yml" <<'YAML'
id: js.json-parse-without-try
language: typescript
rule:
  pattern: JSON.parse($X)
  not:
    inside:
      kind: try_statement
severity: warning
message: "JSON.parse without try/catch; malformed input will throw"
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
cat << 'BANNER'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗    ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝    ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗      ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝      ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗    ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ║
║                                                                      ║
BANNER
echo -e "║         ${BOLD}${GREEN}🔬 BUG SCANNER${RESET}${BOLD}${CYAN} v4.4 ${BLUE}━━━━━━━━━━━━━━━━━━━━━━━${CYAN}         ║"
cat << 'BANNER'
║                                                                      ║
║       🎯 Industrial-Grade JavaScript/TypeScript Analysis 🎯         ║
║          Powered by AST-Grep + Semantic Pattern Matching            ║
║              Catch 1000+ Bug Patterns Before Production             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
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
count=$(
  ast_search '$X.$Y.$Z.$W' \
  || ( "${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*" "$PROJECT_DIR" 2>/dev/null || true ) | count_lines
)
if [ "$count" -gt 20 ]; then
  print_finding "warning" "$count" "Deep property access - high crash risk" "Consider obj?.prop1?.prop2?.prop3 or explicit guards"
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Deep property access detected"
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
count=$(( $("${GREP_RN[@]}" -e "(^|[^<])<<([^<]|$)|(^|[^>])>>([^>]|$)|\&|\^" "$PROJECT_DIR" 2>/dev/null || true | \
  grep -v -E "//|&&|\|\||/\*" || true | wc -l | awk '{print $1+0}') ))
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
count=$(( $("${GREP_RN[@]}" -e "\.length[[:space:]]*[+\-/*]|[+\-/*][[:space:]]*[A-Za-z_]*\.length" "$PROJECT_DIR" 2>/dev/null || true | wc -l | awk '{print $1+0}') ))
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
count=$("${GREP_RN[@]}" -e "\.[A-Za-z_][A-Za-z0-9_]*\.length" "$PROJECT_DIR" 2>/dev/null || true | \
  (grep -Ev "if|Array\.isArray|\?\." || true) | count_lines)
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
count=$(( $("${GREP_RN[@]}" -e "(^|[^=!<>])==($|[^=])|(^|[^=!<>])!=($|[^=])" "$PROJECT_DIR" 2>/dev/null || true | \
  grep -vE "===|!==" || true | wc -l | awk '{print $1+0}') ))
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Loose equality causes type coercion bugs" "Always prefer strict equality"
  show_detailed_finding "(^|[^=!<>])==($|[^=])|(^|[^=!<>])!=($|[^=])" 5
else
  print_finding "good" "All comparisons use strict equality"
fi

print_subheader "Comparing different types"
count=$("${GREP_RN[@]}" -e "===[[:space:]]*('|\"|true|false|null)" "$PROJECT_DIR" 2>/dev/null || true | \
  (grep -vE "typeof|instanceof" || true) | count_lines)
if [ "$count" -gt 0 ]; then print_finding "info" "$count" "Type comparisons - verify both sides match"; fi

print_subheader "typeof checks with wrong string literals"
count=$("${GREP_RN[@]}" -e "typeof[[:space:]]*\(.+\)[[:space:]]*===?[[:space:]]*['\"][A-Za-z]+['\"]" "$PROJECT_DIR" 2>/dev/null || true | \
  (grep -Ev "undefined|string|number|boolean|function|object|symbol|bigint" || true) | count_lines)
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
count=$(( $("${GREP_RN[@]}" -e "\+[[:space:]]*['\"]|['\"][[:space:]]*\+" "$PROJECT_DIR" 2>/dev/null || true | \
  grep -v -E "\+\+|[+\-]=" || true | wc -l | awk '{print $1+0}') ))
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

print_subheader "Promises without .catch() or try/catch"
count=$("${GREP_RN[@]}" -e "\.then\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "\.catch\(|\.finally\(" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "critical" "$count" "Unhandled promise rejections" "Ensure .catch or try/catch around awaits"
  show_detailed_finding "\.then\(" 3
elif [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Some promises may lack error handling"
fi

print_subheader "Async function calls without await"
count=$("${GREP_RNW[@]}" "async" "$PROJECT_DIR" 2>/dev/null | (grep "function" || true) | count_lines)
await_count=$("${GREP_RNW[@]}" "await" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$async_count" -gt "$await_count" ]; then
  ratio=$((async_count - await_count))
  print_finding "warning" "$ratio" "More async functions than awaits" "Check for floating promises or unawaited calls"
fi

print_subheader "await inside loops (performance issue)"
count=$("${GREP_RN[@]}" -e "for[[:space:]]*\(|while[[:space:]]*\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A5 "await " || true) | (grep -cw "await" || true) )
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "await inside loops - consider Promise.all()" "Sequential awaits are slow"
fi

print_subheader "Missing 'async' keyword on functions using await"
count=$("${GREP_RNW[@]}" "await" "$PROJECT_DIR" 2>/dev/null || true | (grep -v "async" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "await used in non-async function" "SyntaxError in JS"
  show_detailed_finding "\bawait\b" 3
fi

print_subheader "Race conditions with Promise.race/any"
count=$("${GREP_RN[@]}" -e "Promise\.(race|any)\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Promise.race/any usage - verify error handling" "Ensure losers don't cause side effects"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ERROR HANDLING ANTI-PATTERNS
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 6; then
print_header "6. ERROR HANDLING ANTI-PATTERNS"
print_category "Detects: Swallowed errors, missing cleanup, poor error messages" \
  "Bad error handling makes debugging impossible and causes production failures"

print_subheader "Empty catch blocks (swallowing errors)"
count=$("${GREP_RN[@]}" -e "catch[[:space:]]*(\(.*\))?[[:space:]]*\{[[:space:]]*\}" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
silent_catch=$("${GREP_RN[@]}" -e "catch[[:space:]]*(\([^)]+\))?[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | \
  (grep -A1 -E "catch" || true) | (grep -v -E "console|log|error|throw|catch|--" || true) | count_lines)
total=$((count + silent_catch / 2))
if [ "$total" -gt 3 ]; then
  print_finding "critical" "$total" "Silent error swallowing detected" "At minimum: catch(e){ console.error(e) }"
  show_detailed_finding "catch[[:space:]]*(\(.*\))?[[:space:]]*\{[[:space:]]*\}" 3
elif [ "$total" -gt 0 ]; then
  print_finding "warning" "$total" "Some catch blocks may be too silent"
fi

print_subheader "Try without finally (resource leaks)"
try_count=$("${GREP_RN[@]}" -e "try[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
finally_count=$("${GREP_RN[@]}" -e "finally[[:space:]]*\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$try_count" -gt $((finally_count * 3)) ]; then
  ratio=$((try_count - finally_count))
  print_finding "warning" "$ratio" "Try blocks without finally - check resource cleanup" "Files, locks, timers need cleanup"
fi

print_subheader "Generic error messages"
count=$("${GREP_RN[@]}" -e "throw new Error\(['\"]Error" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Generic 'Error' messages - be specific" "Include context/ids"
  show_detailed_finding "throw new Error\(['\"]Error" 3
fi

print_subheader "Throwing strings instead of Error objects"
count=$("${GREP_RN[@]}" -e "throw[[:space:]]+['\"]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Throwing strings - use Error objects" "throw new Error('message')"
  show_detailed_finding "throw[[:space:]]+['\"]" 3
fi

print_subheader "Catch without error parameter"
count=$("${GREP_RN[@]}" -e "catch[[:space:]]*\{|catch[[:space:]]*\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Catch blocks ignoring error - intentional?" "Prefer catch(e){...}"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: SECURITY VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
if should_skip 7; then
print_header "7. SECURITY VULNERABILITIES"
print_category "Detects: Code injection, XSS, prototype pollution, timing attacks" \
  "Security bugs expose users to attacks and data breaches"

print_subheader "eval() usage (CRITICAL SECURITY RISK)"
eval_count=$(
  ( [[ "$HAS_AST_GREP" -eq 1 ]] && ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "eval($$)" "$PROJECT_DIR" 2>/dev/null || true ) ) \
  || ( "${GREP_RN[@]}" -e '(^|[^'"'"'"])[Ee]val[[:space:]]*\(' "$PROJECT_DIR" 2>/dev/null || true ) \
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
count=$(
  ( [[ "$HAS_AST_GREP" -eq 1 ]] && ( set +o pipefail; "${AST_GREP_CMD[@]}" --pattern "new Function($$)" "$PROJECT_DIR" 2>/dev/null || true ) ) \
  || ( "${GREP_RN[@]}" -e '(^|[^'"'"'"])\bnew[[:space:]]+Function[[:space:]]*\(' "$PROJECT_DIR" 2>/dev/null || true ) \
  | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
  | count_lines
)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "new Function() enables code injection" "Same risk as eval()"
  show_detailed_finding "new Function\(" 3
fi

print_subheader "innerHTML with potential XSS risk"
count=$(
  ( [[ "$HAS_AST_GREP" -eq 1 ]] && "${AST_GREP_CMD[@]}" --pattern "$EL.innerHTML = $VAL" "$PROJECT_DIR" 2>/dev/null ) \
  || "${GREP_RN[@]}" -e "\\.innerHTML[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null \
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
count=$(
  ( [[ "$HAS_AST_GREP" -eq 1 ]] && "${AST_GREP_CMD[@]}" --pattern "document.write($$)" "$PROJECT_DIR" 2>/dev/null ) \
  || "${GREP_RNW[@]}" "document\.write" "$PROJECT_DIR" 2>/dev/null \
     | (grep -Ev "^[[:space:]]*(//|/\*|\*)" || true) \
     | count_lines
)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "document.write() is deprecated & breaks SPAs" "Use DOM manipulation instead"
  show_detailed_finding "document\.write" 3
fi

print_subheader "Prototype pollution vulnerability"
count=$("${GREP_RN[@]}" -e "__proto__|constructor\.prototype" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Potential prototype pollution" "Never modify __proto__ or constructor.prototype"
  show_detailed_finding "__proto__|constructor\.prototype" 3
fi

print_subheader "Hardcoded secrets/credentials"
count=$("${GREP_RNI[@]}" -e "password[[:space:]]*=|api_?key[[:space:]]*=|secret[[:space:]]*=|token[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v "password.*:.*type\|//" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Possible hardcoded secrets" "Use environment variables or secret managers"
  show_detailed_finding "password[[:space:]]*=|api_?key[[:space:]]*=|secret[[:space:]]*=" 3
fi

print_subheader "RegExp denial of service (ReDoS) risk"
count=$("${GREP_RN[@]}" -e "new RegExp\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
complex_regex=$("${GREP_RN[@]}" -e "\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$complex_regex" -gt 5 ]; then
  print_finding "warning" "$complex_regex" "Complex regex patterns - ReDoS risk" "Nested quantifiers can hang on crafted input"
fi
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
if [ "$count" -gt 15 ]; then
  print_finding "warning" "$count" "Deep callback nesting detected" "Prefer async/await or Promises"
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
  print_finding "critical" "$count" "parseInt without radix - causes octal/format bugs" "Always use parseInt(x, 10)"
  show_detailed_finding "parseInt\(" 5
else
  print_finding "good" "All parseInt calls specify radix"
fi

print_subheader "JSON.parse without try/catch"
count=$("${GREP_RN[@]}" -e "JSON\.parse\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
trycatch_count=$("${GREP_RNW[@]}" -B2 "try" "$PROJECT_DIR" 2>/dev/null || true | (grep -c "JSON\.parse" || true))
trycatch_count=$(printf '%s\n' "$trycatch_count" | awk 'END{print $0+0}')
if [ "$count" -gt "$trycatch_count" ]; then
  ratio=$((count - trycatch_count))
  print_finding "warning" "$ratio" "JSON.parse without error handling" "Wrap in try/catch or validate input first"
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
count=$("${GREP_RN[@]}" -e "^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "^[[:space:]]*//|const|let|var|function|class|import|export" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "critical" "$count" "Global variable assignments" "Missing const/let. Creates globals"
  show_detailed_finding "^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=" 5
elif [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Possible global variable pollution"
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
count=$("${GREP_RN[@]}" -e "for|while" "$PROJECT_DIR" 2>/dev/null || true | \
  (grep -A5 -E "querySelector|getElementById" || true) | (grep -c -E "querySelector|getElementById" || true) )
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
say "${DIM}Add to pre-commit: ./scripts/bug-scanner.sh --ci --fail-on-warning . > bug-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi
exit "$EXIT_CODE"
