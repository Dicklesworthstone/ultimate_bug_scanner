#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# SWIFT ULTIMATE BUG SCANNER v1.8.0 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Swift (6.2+) for iOS & macOS using:
# • ast-grep (rule packs; language: swift)
# • precise Info.plist ATS parsing via plistlib (when Python 3 available)
# • ripgrep/grep heuristics for fast code smells
# • optional extra analyzers if available:
# - SwiftLint (linting/best practices)
# - SwiftFormat (formatting/style)
# - Periphery (dead code)
# - xcodebuild analyze (Clang static analyzer)
#
# Focus:
# • Optionals & force operations • async/await & Task lifecycle
# • URLSession pitfalls • memory cycles & capture lists
# • security/crypto • Info.plist ATS & entitlements
# • resource lifecycle (Timer, Notification tokens, FileHandle, CADisplayLink, KVO)
# • Combine/SwiftUI leaks • performance & main-thread issues
# • additional Swift pitfalls: URLComponents vs string, os.Logger privacy, etc.
#
# Supports:
# --format text|json|sarif (ast-grep passthrough for json/sarif)
# --rules DIR (merge user ast-grep rules)
# --fail-on-warning, --skip, --jobs, --include-ext, --exclude, --ci, --no-color, --force-color
# --summary-json FILE (machine-readable run summary with rule histogram)
# --report-md FILE (markdown summary)
# --emit-csv FILE (CSV of per-category counts)
# --emit-html FILE (HTML summary)
# --max-detailed N (cap detailed code samples across entire run)
# --list-categories (print category index and exit)
# --list-rules (print embedded + user ast-grep rule ids and exit)
# --timeout-seconds N (global external tool timeout budget)
# --baseline FILE (compare current totals to prior summary JSON)
# --max-file-size SIZE (ripgrep limit, e.g., 25M)
# --sdk ios|macos|tvos|watchos (for xcodebuild analyze heuristics)
# --only=CSV (only run the given category numbers)
# --color=always|auto|never
# --progress (lightweight progress dots)
# --respect-ignore (respect .gitignore/.ignore when using ripgrep; default is more exhaustive)
# --no-ignore (ignore no ignore-files at all when using ripgrep; maximum coverage)
# --dump-rules=DIR (write the final merged ast-grep rules into DIR and exit)
# --explain-rule=ID (print the YAML for a rule id from the merged rule set and exit)
# --keep-temp (do not delete temporary files; useful for debugging rule packs)
#
# CI-friendly timestamps, robust find, safe pipelines, auto parallel jobs.
# Heavily leverages ast-grep for Swift via rule packs; complements with rg.
# Adds portable timeout resolution (timeout/gtimeout) and UTF‑8-safe output.
# ═══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
shopt -s lastpipe || true
shopt -s extglob || true
shopt -s compat31 || true

VERSION="1.8.0"
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

STDOUT_IS_TTY=0
[[ -t 1 ]] && STDOUT_IS_TTY=1

KEEP_TEMP=0
TEMP_PATHS=()
cleanup_add(){ [[ -n "${1:-}" ]] && TEMP_PATHS+=("$1"); }
cleanup(){
 [[ "$KEEP_TEMP" -eq 1 ]] && return 0
 local p
 for p in "${TEMP_PATHS[@]:-}"; do
  [[ -n "$p" ]] && rm -rf "$p" 2>/dev/null || true
 done
}
trap cleanup EXIT

mktemp_dir(){
 local prefix="${1:-ubs_tmp}"
 local tmp="${TMPDIR:-/tmp}"
 mktemp -d "${tmp%/}/${prefix}.XXXXXXXX" 2>/dev/null || mktemp -d -t "${prefix}.XXXXXXXX" 2>/dev/null || mktemp -d
}
mktemp_file(){
 local prefix="${1:-ubs_tmp}"
 local tmp="${TMPDIR:-/tmp}"
 mktemp "${tmp%/}/${prefix}.XXXXXXXX" 2>/dev/null || mktemp -t "${prefix}.XXXXXXXX" 2>/dev/null || mktemp
}

normalize_severity(){
 local s="${1:-info}"
 s="${s,,}"
 case "$s" in
  good|ok|pass) printf '%s' "good" ;;
  critical|error|err|fatal|high|serious) printf '%s' "critical" ;;
  warning|warn|medium) printf '%s' "warning" ;;
  info|note|hint|low) printf '%s' "info" ;;
  *) printf '%s' "$s" ;;
 esac
}

json_escape(){
 local s="$1"
 s="${s//\\/\\\\}"
 s="${s//\"/\\\"}"
 s="${s//$'\n'/\\n}"
 s="${s//$'\r'/\\r}"
 s="${s//$'\t'/\\t}"
 printf '%s' "$s"
}

USE_COLOR=0; FORCE_COLOR=0; NO_COLOR_FLAG=0; COLOR_MODE="auto"
RED=''; GREEN=''; YELLOW=''; BLUE=''; ORANGE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
BOLD=''; DIM=''; RESET=''
init_colors() {
 local use=0
 case "$COLOR_MODE" in
  always) use=1 ;;
  never) use=0 ;;
  auto|*) [[ "$STDOUT_IS_TTY" -eq 1 ]] && use=1 || use=0 ;;
 esac
 [[ -n "${NO_COLOR:-}" || "$NO_COLOR_FLAG" -eq 1 ]] && use=0
 [[ "$FORCE_COLOR" -eq 1 ]] && use=1
 [[ -n "${OUTPUT_FILE:-}" && "$FORCE_COLOR" -eq 0 && "$COLOR_MODE" != "always" ]] && use=0
 USE_COLOR="$use"
  if [[ "$USE_COLOR" -eq 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'
  ORANGE=$'\033[0;33m'; MAGENTA=$'\033[0;35m'; CYAN=$'\033[0;36m'; WHITE=$'\033[1;37m'; GRAY=$'\033[0;90m'
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
  else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; ORANGE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''; BOLD=''; DIM=''; RESET=''
  fi
}

on_err() {
 local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
 echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2 || true
 exit "$ec"
}
trap on_err ERR

choose_safe_locale() {
  local lc="C"
  if locale -a 2>/dev/null | grep -qi '^C\.UTF-8$'; then lc="C.UTF-8"
  elif locale -a 2>/dev/null | grep -qi '^en_US\.UTF-8$'; then lc="en_US.UTF-8"
  fi
  printf '%s' "$lc"
}
SAFE_LOCALE="$(choose_safe_locale)"
export LC_CTYPE="${SAFE_LOCALE}"
export LC_MESSAGES="${SAFE_LOCALE}"
export LANG="${SAFE_LOCALE}"

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; ROCKET="🚀"

CURRENT_CATEGORY_ID=0

VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
BASELINE=""
LIST_CATEGORIES=0
MAX_FILE_SIZE="${MAX_FILE_SIZE:-25M}"
INCLUDE_EXT="swift,mm,m,metal,plist,xib,storyboard,xcconfig"
QUIET=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
DETAILED_EMITTED=0
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
SUMMARY_JSON=""
REPORT_MD=""
EMIT_CSV=""
EMIT_HTML=""
TIMEOUT_CMD=""
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"
AST_PASSTHROUGH=0
SDK_KIND="${SDK_KIND:-ios}"
LIST_RULES=0
PROGRESS=0
AG_STREAM_FILE=""
AG_STREAM_READY=0
AG_FILE_INDEX_FILE=""
AG_FILE_INDEX_READY=0
RG_PCRE2_OK=0
RESPECT_IGNORE=0
NO_IGNORE_ALL=0
DUMP_RULES_DIR=""
EXPLAIN_RULE_ID=""

die(){ echo -e "${RED}${BOLD}fatal:${RESET} ${WHITE}$*${RESET}" >&2; exit 2; }

CATEGORY_WHITELIST=""
case "${SUBS_CATEGORY_FILTER:-}" in
 resource-lifecycle) CATEGORY_WHITELIST="16,19" ;;
esac

csv_contains(){
 local csv="${1:-}" needle="${2:-}"
 needle="${needle//[[:space:]]/}"
 [[ -z "$needle" ]] && return 1
 local IFS=',' item
 for item in $csv; do
  item="${item//[[:space:]]/}"
  [[ -z "$item" ]] && continue
  [[ "$item" == "$needle" ]] && return 0
 done
 return 1
}
csv_add_unique(){
 local csv="${1:-}" add="${2:-}"
 add="${add//[[:space:]]/}"
 [[ -z "$add" ]] && { printf '%s' "$csv"; return 0; }
 if csv_contains "$csv" "$add"; then printf '%s' "$csv"; return 0; fi
 if [[ -z "$csv" ]]; then printf '%s' "$add"; else printf '%s,%s' "$csv" "$add"; fi
}

ASYNC_RULE_IDS=(swift.task.floating swift.continuation.no-resume swift.task.detached-no-handle)
declare -A ASYNC_ERROR_SUMMARY=(
 [swift.task.floating]='Task { ... } launched'
  [swift.continuation.no-resume]='withChecked/UnsafeContinuation without resume'
 [swift.task.detached-no-handle]='Task.detached launched'
)
declare -A ASYNC_ERROR_REMEDIATION=(
 [swift.task.floating]='Store handle and cancel on deinit/shutdown; prefer structured concurrency'
  [swift.continuation.no-resume]='Ensure every path calls continuation.resume(...) exactly once'
 [swift.task.detached-no-handle]='Avoid detached tasks; keep a reference or use structured concurrency'
)
declare -A ASYNC_ERROR_SEVERITY=(
  [swift.task.floating]='warning'
  [swift.continuation.no-resume]='critical'
  [swift.task.detached-no-handle]='warning'
)

RESOURCE_LIFECYCLE_IDS=(timer urlsession_task notification_token file_handle combine_sink dispatch_source cadisplaylink kvo_observer)
declare -A RESOURCE_LIFECYCLE_SEVERITY=(
  [timer]="warning"
  [urlsession_task]="warning"
  [notification_token]="warning"
  [file_handle]="critical"
  [combine_sink]="warning"
  [dispatch_source]="warning"
 [cadisplaylink]="warning"
 [kvo_observer]="warning"
)
declare -A RESOURCE_LIFECYCLE_ACQUIRE=(
  [timer]='Timer\.scheduledTimer|Timer\.publish\('
 [urlsession_task]='\.(dataTask|uploadTask|downloadTask)\s*\('
 [notification_token]='NotificationCenter\.default\.addObserver\([^)]*using:\s*\{|NotificationCenter\.default\.addObserver\([^)]*forName:'
 [file_handle]='FileHandle\s*\(\s*for(Reading|Writing|Updating)(From|To|AtPath)\s*:'
 [combine_sink]='\.sink\s*\('
  [dispatch_source]='DispatchSource\.(makeTimerSource|makeFileSystemObjectSource|makeReadSource|makeWriteSource)'
 [cadisplaylink]='CADisplayLink\s*\('
 [kvo_observer]='addObserver\([^)]*forKeyPath:'
)
declare -A RESOURCE_LIFECYCLE_RELEASE=(
 [timer]='\.invalidate\s*\('
 [urlsession_task]='\.resume\s*\(|\.cancel\s*\('
 [notification_token]='NotificationCenter\.default\.removeObserver\s*\('
 [file_handle]='\.close\s*\('
 [combine_sink]='\.store\s*\(\s*in:\s*&'
 [dispatch_source]='\.cancel\s*\(|\.resume\s*\('
 [cadisplaylink]='\.invalidate\s*\('
 [kvo_observer]='removeObserver\([^)]*forKeyPath:'
)
declare -A RESOURCE_LIFECYCLE_SUMMARY=(
  [timer]='Timer scheduled but never invalidated'
  [urlsession_task]='URLSession task created but not resumed/cancelled'
 [notification_token]='NotificationCenter observer token not removed'
  [file_handle]='FileHandle opened without close()'
  [combine_sink]='Combine sink not stored, may be dropped immediately'
 [dispatch_source]='DispatchSource created but not cancelled/resumed'
 [cadisplaylink]='CADisplayLink created but not invalidated'
 [kvo_observer]='KVO addObserver without removeObserver'
)
declare -A RESOURCE_LIFECYCLE_REMEDIATION=(
  [timer]='Keep a reference and call timer.invalidate() (e.g., deinit)'
  [urlsession_task]='Call task.resume(); cancel on teardown if needed'
  [notification_token]='Keep the token and call removeObserver(token)'
 [file_handle]='Call close() in defer; prefer APIs that manage lifetime for you'
  [combine_sink]='Store AnyCancellable in a Set<AnyCancellable>'
 [dispatch_source]='Call resume() and cancel() appropriately'
 [cadisplaylink]='Store and invalidate() in teardown'
 [kvo_observer]='Prefer NSKeyValueObservation or ensure removeObserver is called'
)

print_usage() {
  cat >&2 <<USAGE
Usage: $SCRIPT_NAME [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
 --list-categories Print numbered categories and exit
 --list-rules Print embedded ast-grep rule IDs and exit
 --dump-rules=DIR Write the merged ast-grep rules to DIR and exit
 --explain-rule=ID Print YAML for a rule id and exit
 --keep-temp Keep temporary files (debugging)

 --timeout-seconds=N Global per-tool timeout budget
 --baseline=FILE Compare against a previous run's summary JSON
 --max-file-size=SIZE Limit ripgrep file size (default: $MAX_FILE_SIZE)
 --force-color Force ANSI even if not TTY
 --color=MODE always|auto|never (default: auto)
 -v, --verbose More code samples per finding (DETAIL=10)
 -q, --quiet Reduce non-essential output
 --format=FMT Output: text|json|sarif (default: text)
 --ci CI mode (UTC timestamps)
 --no-color Disable ANSI color
 --include-ext=CSV File extensions (default: $INCLUDE_EXT)
 --exclude=GLOB[,..] Additional glob(s)/dir(s) to exclude
 --jobs=N Parallel jobs for ripgrep (default: auto)
 --skip=CSV Skip categories by number (e.g., --skip=2,7,11)
 --only=CSV Only run these categories (e.g., --only=1,2,4)
 --fail-on-warning Exit non-zero on warnings or critical
 --rules=DIR Additional ast-grep rules dir (merged)
 --summary-json=FILE Write machine-readable summary JSON
 --report-md=FILE Write a Markdown summary
 --emit-csv=FILE Write a CSV of per-category counts
 --emit-html=FILE Write an HTML summary
 --max-detailed=N Cap total code samples printed (default: $MAX_DETAILED)
 --sdk=KIND ios|macos|tvos|watchos (default: $SDK_KIND)
 --progress Show minimal progress dots
 --respect-ignore Respect ignore files for ripgrep (smaller scan scope)
 --no-ignore Ignore ALL ignore files for ripgrep (maximum coverage)

Env:
  JOBS, NO_COLOR, CI, TIMEOUT_SECONDS, MAX_FILE_SIZE, SUBS_CATEGORY_FILTER
 UBS_PROFILE=loose to auto-skip categories (11,15,22)
  UBS_INCLUDE_OPTIONALS_IN_TOTALS=1 to include external analyzer counts
Args:
 PROJECT_DIR Directory to scan (default: ".")
 OUTPUT_FILE File to save the report (optional)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
  -q|--quiet) VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
  --format=*) FORMAT="${1#*=}"; shift;;
  --ci) CI_MODE=1; shift;;
  --no-color) NO_COLOR_FLAG=1; shift;;
    --force-color) FORCE_COLOR=1; COLOR_MODE="always"; shift;;
    --color=*) COLOR_MODE="${1#*=}"; shift;;
  --version) echo "ubs-swift ${VERSION}"; exit 0;;
    --timeout-seconds=*) TIMEOUT_SECONDS="${1#*=}"; shift;;
    --baseline=*) BASELINE="${1#*=}"; shift;;
    --list-categories) LIST_CATEGORIES=1; shift;;
    --list-rules) LIST_RULES=1; shift;;
  --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
  --explain-rule=*) EXPLAIN_RULE_ID="${1#*=}"; shift;;
  --keep-temp) KEEP_TEMP=1; shift;;
    --max-file-size=*) MAX_FILE_SIZE="${1#*=}"; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
  --exclude=*) EXTRA_EXCLUDES="${1#*=}"; shift;;
  --jobs=*) JOBS="${1#*=}"; shift;;
  --skip=*) SKIP_CATEGORIES="${1#*=}"; shift;;
  --only=*) ONLY_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
  --rules=*) USER_RULE_DIR="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-md=*) REPORT_MD="${1#*=}"; shift;;
    --emit-csv=*) EMIT_CSV="${1#*=}"; shift;;
    --emit-html=*) EMIT_HTML="${1#*=}"; shift;;
    --max-detailed=*) MAX_DETAILED="${1#*=}"; shift;;
    --sdk=*) SDK_KIND="${1#*=}"; shift;;
    --progress) PROGRESS=1; shift;;
  --respect-ignore) RESPECT_IGNORE=1; shift;;
  --no-ignore) NO_IGNORE_ALL=1; shift;;
  -h|--help) print_usage; exit 0;;
  --) shift; break;;
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

if [[ "${UBS_PROFILE:-}" == "loose" ]]; then
 SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "11")"
 SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "15")"
 SKIP_CATEGORIES="$(csv_add_unique "$SKIP_CATEGORIES" "22")"
fi

case "$FORMAT" in
  text|json|sarif) ;;
  *) echo "Unsupported --format=$FORMAT (expected: text|json|sarif)" >&2; exit 2 ;;
esac
case "$SDK_KIND" in ios|macos|tvos|watchos) ;; *) SDK_KIND="ios";; esac

if [[ "$LIST_CATEGORIES" -eq 1 ]]; then
  cat <<'CAT'
1 Optionals/Force Ops 2 Concurrency/Task 3 Closures/Captures 4 URLSession
5 Error Handling 6 Security 7 Crypto/Hashing 8 Files & I/O
9 Threading/Main 10 Performance 11 Debug/Prod 12 Regex
13 SwiftUI/Combine 14 Memory/Retain 15 Code Quality 16 Resource Lifecycle
17 Info.plist/ATS 18 Deprecated APIs 19 Build/Signing 20 Packaging/SPM
21 UI/UX Safety 22 Tests/Hygiene 23 Localize/Intl
CAT
  exit 0
fi

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi

if [[ -n "${OUTPUT_FILE}" ]]; then
 mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
 if command -v tee >/dev/null 2>&1; then
  if [[ "$FORMAT" == "text" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; else exec > >(tee "${OUTPUT_FILE}"); fi
 else
  if [[ "$FORMAT" == "text" ]]; then exec >"${OUTPUT_FILE}" 2>&1; else exec >"${OUTPUT_FILE}"; fi
 fi
fi

init_colors

safe_date() {
  if [[ "$CI_MODE" -eq 1 ]]; then command date -u '+%Y-%m-%dT%H:%M:%SZ' || command date '+%Y-%m-%dT%H:%M:%SZ'; else command date '+%Y-%m-%d %H:%M:%S'; fi
}
DATE_CMD="safe_date"

CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0
SWIFT_FILE_COUNT=0
HAS_SWIFT_FILES=0

for __i in $(seq 1 23); do
  eval "CAT${__i}=0"
  eval "CAT${__i}_critical=0"
  eval "CAT${__i}_warning=0"
  eval "CAT${__i}_info=0"
done

set_category(){ CURRENT_CATEGORY_ID="$1"; }
inc_category_total(){
 local c="${1:-0}" id="${CURRENT_CATEGORY_ID:-0}"
 [[ "${id:-0}" -gt 0 ]] || return 0
 local vname="CAT${id}"
  eval "$vname=\$(( \${$vname:-0} + c ))"
}
_bump_counts(){
 local sev="$1" cnt="$2" id="${CURRENT_CATEGORY_ID:-0}"
  case "$sev" in
  critical)
   CRITICAL_COUNT=$((CRITICAL_COUNT + cnt))
   [[ "$id" -gt 0 ]] && eval "CAT${id}_critical=\$(( \${CAT${id}_critical:-0} + cnt ))"
   ;;
  warning)
   WARNING_COUNT=$((WARNING_COUNT + cnt))
   [[ "$id" -gt 0 ]] && eval "CAT${id}_warning=\$(( \${CAT${id}_warning:-0} + cnt ))"
   ;;
  info)
   INFO_COUNT=$((INFO_COUNT + cnt))
   [[ "$id" -gt 0 ]] && eval "CAT${id}_info=\$(( \${CAT${id}_info:-0} + cnt ))"
   ;;
  esac
  inc_category_total "$cnt"
}

HAS_AST_GREP=0
AST_GREP_CMD=()
AST_RULE_DIR=""

HAS_RIPGREP=0
RG_PCRE2_OK=0
RG_MAX_SIZE_FLAGS=()

AG_RULE_INDEX_BUILT=0
declare -A AG_RULE_CATEGORY=()
declare -A AG_RULE_FILE=()
declare -A AG_RULE_SEVERITY=()
declare -A AG_RULE_MESSAGE=()

IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=()
for e in "${_EXT_ARR[@]}"; do
 e="$(echo "$e" | xargs)"
 [[ -n "$e" ]] && INCLUDE_GLOBS+=( "--include=*.$e" )
done

EXCLUDE_DIRS=(.git .hg .svn .bzr .build build DerivedData .swiftpm .sourcery .periphery .mint .cache .xcarchive .xcresult .xcassets Pods Carthage vendor .idea .vscode .history .swiftformat .swiftlint)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=()
for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

rg_supports_flag(){ rg --help 2>/dev/null | grep -q -- "$1"; }

RG_EXTRA_FLAGS=()
if command -v rg >/dev/null 2>&1; then
  HAS_RIPGREP=1
 rg_supports_flag '--pcre2' && RG_PCRE2_OK=1 || RG_PCRE2_OK=0

 if [[ "$NO_IGNORE_ALL" -eq 1 ]]; then
  rg_supports_flag '--no-ignore' && RG_EXTRA_FLAGS+=(--no-ignore)
 elif [[ "$RESPECT_IGNORE" -eq 0 ]]; then
  rg_supports_flag '--no-ignore-vcs' && RG_EXTRA_FLAGS+=(--no-ignore-vcs)
 fi

  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  if [[ "${JOBS}" -le 0 ]]; then JOBS=1; fi
 RG_JOBS=(); [[ "$JOBS" -gt 0 ]] && RG_JOBS=(-j "$JOBS")

 RG_PCRE2=(); [[ "$RG_PCRE2_OK" -eq 1 ]] && RG_PCRE2=(--pcre2)

 RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden "${RG_EXTRA_FLAGS[@]}" "${RG_PCRE2[@]}" "${RG_JOBS[@]}")
  RG_EXCLUDES=()
  for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=()
 for e in "${_EXT_ARR[@]}"; do e="$(echo "$e" | xargs)"; [[ -n "$e" ]] && RG_INCLUDES+=( -g "*.$e" ); done
  RG_MAX_SIZE_FLAGS=(--max-filesize "$MAX_FILE_SIZE")

  GREP_RN=(env LC_ALL="${SAFE_LOCALE}" rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
  GREP_RNI=(env LC_ALL="${SAFE_LOCALE}" rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
  GREP_RNW=(env LC_ALL="${SAFE_LOCALE}" rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}")
else
  GREP_R_OPTS=(-R --binary-files=without-match --line-number --with-filename "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=(env LC_ALL="${SAFE_LOCALE}" grep "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=(env LC_ALL="${SAFE_LOCALE}" grep "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=(env LC_ALL="${SAFE_LOCALE}" grep "${GREP_R_OPTS[@]}" -n -w -E)
fi

count_lines(){ awk 'END{print (NR+0)}'; }
num_clamp(){ local v=${1:-0}; printf '%s' "$v" | awk 'END{print ($0+0)}'; }

resolve_timeout(){
  if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout"; return 0; fi
  if command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout"; return 0; fi
  TIMEOUT_CMD=""
}
with_timeout(){
  if [[ -n "$TIMEOUT_CMD" && "${TIMEOUT_SECONDS:-0}" -gt 0 ]]; then "$TIMEOUT_CMD" "$TIMEOUT_SECONDS" "$@"; else "$@"; fi
}

maybe_clear(){ if [[ -t 1 && "$CI_MODE" -eq 0 ]]; then clear || true; fi; }
say(){ [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }
tick(){ [[ "$PROGRESS" -eq 1 && "$QUIET" -eq 0 ]] && printf "%s" "."; }

print_header(){
  say "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  say "${WHITE}${BOLD}$1${RESET}"
  say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
print_category(){ say "\n${MAGENTA}${BOLD}▓▓▓ $1${RESET}\n${DIM}$2${RESET}"; }
print_subheader(){ say "\n${YELLOW}${BOLD}$BULLET $1${RESET}"; }

print_finding(){
 local severity; severity="$(normalize_severity "$1")"
 case "$severity" in
    good)
      local title=$2
   say " ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}"
      ;;
    *)
      local raw_count=${2:-0}; local title=$3; local description="${4:-}"
      local count; count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
      _bump_counts "$severity" "$count"
   case "$severity" in
        critical)
     say " ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"
     say " ${RED}${BOLD}$title${RESET}"
     [[ -n "$description" ]] && say " ${DIM}$description${RESET}" || true
          ;;
        warning)
     say " ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"
     say " ${YELLOW}$title${RESET}"
     [[ -n "$description" ]] && say " ${DIM}$description${RESET}" || true
          ;;
        info)
     say " ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"
     say " ${BLUE}$title${RESET}"
     [[ -n "$description" ]] && say " ${DIM}$description${RESET}" || true
          ;;
      esac
      ;;
  esac
}

print_code_sample(){
 [[ "$DETAILED_EMITTED" -ge "$MAX_DETAILED" ]] && return 0
 local file=$1; local line=$2; local code=$3
 DETAILED_EMITTED=$((DETAILED_EMITTED + 1))
 say "${GRAY} $file:$line${RESET}"
 say "${WHITE} $code${RESET}"
}

show_detailed_finding(){
 local pattern=$1
 local limit=${2:-$DETAIL_LIMIT}
 local printed=0
 [[ "$DETAILED_EMITTED" -ge "$MAX_DETAILED" ]] && return 0
 while IFS=: read -r file line code; do
  print_code_sample "$file" "$line" "$code"
  printed=$((printed + 1))
  [[ $printed -ge $limit || "$DETAILED_EMITTED" -ge "$MAX_DETAILED" ]] && break
 done < <("${GREP_RN[@]}" -e "$pattern" "$PROJECT_DIR" 2>/dev/null | head -n "$limit" || true) || true
 [[ "$DETAILED_EMITTED" -ge "$MAX_DETAILED" ]] && say "${DIM}(max detailed samples reached; increase --max-detailed to see more)${RESET}"
}

begin_scan_section(){ set +e; trap - ERR; set +o pipefail; }
end_scan_section(){ trap on_err ERR; set -e; set -o pipefail; }

check_ast_grep(){
  if command -v ast-grep >/dev/null 2>&1; then AST_GREP_CMD=(ast-grep); HAS_AST_GREP=1; return 0; fi
 if command -v sg >/dev/null 2>&1; then AST_GREP_CMD=(sg); HAS_AST_GREP=1; return 0; fi
 if command -v npx >/dev/null 2>&1; then AST_GREP_CMD=(npx -y @ast-grep/cli); HAS_AST_GREP=1; return 0; fi
 HAS_AST_GREP=0
  say "${YELLOW}${WARN} ast-grep not found. Advanced AST checks will be skipped.${RESET}"
 say "${DIM}Tip: npm i -g @ast-grep/cli or cargo install ast-grep${RESET}"
 return 1
}

build_ag_rule_index(){
 [[ "$HAS_AST_GREP" -eq 1 && -n "${AST_RULE_DIR:-}" && -d "${AST_RULE_DIR:-}" ]] || return 1
 AG_RULE_INDEX_BUILT=1
 shopt -s nullglob
 local f id sev msg base cat
 for f in "$AST_RULE_DIR"/*.yml; do
  id="$(awk '/^id:[[:space:]]*/{print $2; exit}' "$f" 2>/dev/null || true)"
  [[ -n "$id" ]] || continue
  sev="$(awk '/^severity:[[:space:]]*/{print $2; exit}' "$f" 2>/dev/null || true)"
  msg="$(awk '/^message:[[:space:]]*/{sub(/^message:[ ]*/,""); print; exit}' "$f" 2>/dev/null || true)"
  base="$(basename "$f")"
  cat=0
  if [[ "$base" =~ ^c([0-9]{2})- ]]; then cat=$((10#${BASH_REMATCH[1]})); fi
  AG_RULE_CATEGORY["$id"]="$cat"
  AG_RULE_FILE["$id"]="$f"
  AG_RULE_SEVERITY["$id"]="${sev:-info}"
  AG_RULE_MESSAGE["$id"]="${msg:-}"
 done
 shopt -u nullglob
 return 0
}

ensure_ag_stream(){
 [[ "$HAS_AST_GREP" -eq 1 && -n "${AST_RULE_DIR:-}" && -d "${AST_RULE_DIR:-}" ]] || return 1
 if [[ "$AG_STREAM_READY" -eq 1 && -n "${AG_STREAM_FILE:-}" && -s "${AG_STREAM_FILE:-}" ]]; then return 0; fi

 AG_STREAM_FILE="$(mktemp_file ubs_ag_stream)"
 cleanup_add "$AG_STREAM_FILE"
 local err_file; err_file="$(mktemp_file ubs_ag_err)"
 cleanup_add "$err_file"
 : >"$AG_STREAM_FILE"; : >"$err_file"

 local cfg_file; cfg_file="$(mktemp_file ubs_sgconfig)"
 cleanup_add "$cfg_file"
 printf 'ruleDirs:\n- %s\n' "$AST_RULE_DIR" >"$cfg_file" 2>/dev/null || true

 with_timeout "${AST_GREP_CMD[@]}" scan -c "$cfg_file" "$PROJECT_DIR" --json=stream >"$AG_STREAM_FILE" 2>"$err_file" || true

 if [[ -s "$AG_STREAM_FILE" ]]; then AG_STREAM_READY=1; return 0; fi
 AG_STREAM_READY=0

 if [[ -s "$err_file" && "$QUIET" -eq 0 ]]; then
  say "${YELLOW}${WARN} ast-grep bulk scan produced no stream output; falling back to per-rule scans.${RESET}"
  say "${DIM}ast-grep stderr (first 10 lines):${RESET}"
  head -n 10 "$err_file" | while IFS= read -r l; do say " ${GRAY}$l${RESET}"; done
 fi

 : >"$AG_STREAM_FILE"
 shopt -s nullglob
 for f in "$AST_RULE_DIR"/*.yml; do
  with_timeout "${AST_GREP_CMD[@]}" scan -r "$f" "$PROJECT_DIR" --json=stream >>"$AG_STREAM_FILE" 2>>"$err_file" || true
  tick
 done
 shopt -u nullglob

 [[ -s "$AG_STREAM_FILE" ]] && AG_STREAM_READY=1 || AG_STREAM_READY=0
 return 0
}

ag_build_file_index(){
 [[ "$HAS_AST_GREP" -eq 1 && -n "${AST_RULE_DIR:-}" && -d "${AST_RULE_DIR:-}" ]] || return 1
 ensure_ag_stream || return 1
 [[ "$AG_STREAM_READY" -eq 1 && -n "${AG_STREAM_FILE:-}" && -s "${AG_STREAM_FILE:-}" ]] || return 1
 command -v python3 >/dev/null 2>&1 || return 1
 if [[ "$AG_FILE_INDEX_READY" -eq 1 && -n "${AG_FILE_INDEX_FILE:-}" && -s "${AG_FILE_INDEX_FILE:-}" ]]; then return 0; fi
 AG_FILE_INDEX_FILE="$(mktemp_file ubs_ag_index)"
 cleanup_add "$AG_FILE_INDEX_FILE"
 python3 - "$AG_STREAM_FILE" >"$AG_FILE_INDEX_FILE" <<'PY'
import json, sys, collections
stream=sys.argv[1]
idx=collections.defaultdict(list)
def first_line(s):
 if not s: return ""
 ls=str(s).splitlines()
 return (ls[0] if ls else "").rstrip("\n")
with open(stream,'r',encoding='utf-8',errors='ignore') as fh:
 for line in fh:
  line=line.strip()
  if not line: continue
  try: o=json.loads(line)
  except: continue
  file=o.get('file')
  if not file: continue
  rid=o.get('rule_id') or o.get('id') or 'unknown'
  rng=o.get('range') or {}
  st=(rng.get('start') or {})
  row=int(st.get('row',0) or 0)
  col=int(st.get('column',0) or 0)
  sev=(o.get('severity') or o.get('level') or 'info')
  msg=(o.get('message') or '')
  code=first_line(o.get('lines') or '')
  idx[file].append({'rid':rid,'row':row,'col':col,'severity':sev,'message':msg,'code':code})
print(json.dumps(idx, ensure_ascii=False))
PY
 [[ -s "$AG_FILE_INDEX_FILE" ]] && AG_FILE_INDEX_READY=1 || AG_FILE_INDEX_READY=0
 return 0
}

write_ast_rules(){
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
 AST_RULE_DIR="$(mktemp_dir swift_ag_rules)"
 cleanup_add "$AST_RULE_DIR"

 # CATEGORY 01 — Optionals / Force Ops
 cat >"$AST_RULE_DIR/c01-force-unwrap.yml" <<'YAML'
id: swift.force-unwrap
language: swift
rule:
  pattern: $X!
severity: warning
message: "Force unwrap; prefer optional binding (if let/guard let)."
YAML

 cat >"$AST_RULE_DIR/c01-try-bang.yml" <<'YAML'
id: swift.try-bang
language: swift
rule:
  pattern: try! $X
severity: error
message: "try! will crash on error; use try? or do/catch."
YAML

 cat >"$AST_RULE_DIR/c01-force-cast.yml" <<'YAML'
id: swift.force-cast
language: swift
rule:
  pattern: $X as! $T
severity: warning
message: "Force cast as! may crash at runtime; use as? with guard."
YAML

 cat >"$AST_RULE_DIR/c01-iuo-decl.yml" <<'YAML'
id: swift.implicitly-unwrapped
language: swift
rule:
  regex: "(:|->)\\s*[A-Za-z_][A-Za-z0-9_<>?:\\.\\[\\] ]*!\\b"
severity: warning
message: "Implicitly unwrapped optional; prefer regular optional and safe binding."
YAML

 cat >"$AST_RULE_DIR/c01-url-string-bang.yml" <<'YAML'
id: swift.url.string.bang
language: swift
rule:
  regex: "URL\\(string:\\s*[^\\)]*\\)!\\b"
severity: warning
message: "URL(string:) force-unwrapped; validate URL and handle nil."
YAML

 cat >"$AST_RULE_DIR/c01-iboutlet-iuo.yml" <<'YAML'
id: swift.iboutlet.iuo
language: swift
rule:
  regex: "@IBOutlet\\s+weak\\s+var\\s+[A-Za-z_][A-Za-z0-9_]*\\s*:\\s*[^!\\n]*!\\b"
severity: info
message: "@IBOutlet implicitly unwrapped; ensure safe lifecycle assumptions."
YAML

 # CATEGORY 02 — Concurrency / Task
 cat >"$AST_RULE_DIR/c02-task-launch.yml" <<'YAML'
id: swift.task.floating
language: swift
rule:
  regex: "\\bTask\\s*\\{"
severity: warning
message: "Task { ... } launched; review cancellation and lifetime."
YAML

 cat >"$AST_RULE_DIR/c02-task-detached.yml" <<'YAML'
id: swift.task.detached-no-handle
language: swift
rule:
  regex: "\\bTask\\.detached\\b"
severity: warning
message: "Task.detached used; detached tasks often outlive scope—review cancellation/lifetime."
YAML

 cat >"$AST_RULE_DIR/c02-continuation-no-resume.yml" <<'YAML'
id: swift.continuation.no-resume
language: swift
rule:
  regex: "with(Checked|Unsafe)(Throwing)?Continuation\\s*\\{[\\s\\S]*\\}"
  not:
    regex: "\\bresume\\s*\\("
severity: error
message: "Continuation body has no resume(); verify every path resumes exactly once."
YAML

 cat >"$AST_RULE_DIR/c02-task-sleep-units.yml" <<'YAML'
id: swift.task.sleep.units
language: swift
rule:
  regex: "\\bTask\\.sleep\\s*\\(\\s*[0-9_]+\\s*\\)"
severity: warning
message: "Task.sleep expects nanoseconds; small literals often indicate seconds confusion."
YAML

 cat >"$AST_RULE_DIR/c02-main-sync.yml" <<'YAML'
id: swift.dispatch.main.sync
language: swift
rule:
  regex: "DispatchQueue\\.main\\.sync\\s*\\{"
severity: warning
message: "DispatchQueue.main.sync risks deadlock; prefer async or @MainActor."
YAML

 cat >"$AST_RULE_DIR/c02-dispatchgroup-enter.yml" <<'YAML'
id: swift.dispatchgroup.enter-leave.maybe-imbalance
language: swift
rule:
  regex: "\\.enter\\s*\\(\\s*\\)"
severity: info
message: "DispatchGroup enter() used; verify balanced leave() on all paths."
YAML

 cat >"$AST_RULE_DIR/c02-async-let.yml" <<'YAML'
id: swift.async-let.used
language: swift
rule:
  regex: "\\basync\\s+let\\b"
severity: info
message: "async let used; verify every async-let value is awaited/consumed."
YAML

 cat >"$AST_RULE_DIR/c02-unchecked-sendable.yml" <<'YAML'
id: swift.unchecked.sendable
language: swift
rule:
  regex: "@unchecked\\s+Sendable"
severity: warning
message: "@unchecked Sendable used; review for data races and actor isolation violations."
YAML

 cat >"$AST_RULE_DIR/c02-nonisolated-unsafe.yml" <<'YAML'
id: swift.nonisolated.unsafe
language: swift
rule:
  regex: "nonisolated\\s*\\(\\s*unsafe\\s*\\)"
severity: warning
message: "nonisolated(unsafe) used; review for concurrency correctness and thread-safety."
YAML

 # CATEGORY 03 — Closures / Captures
 cat >"$AST_RULE_DIR/c03-unowned-self.yml" <<'YAML'
id: swift.closure.unowned-self-escaping
language: swift
rule:
  regex: "\\[\\s*unowned\\s+self\\s*\\]"
severity: warning
message: "Escaping closure capturing unowned self may crash; prefer [weak self] + guard."
YAML

 cat >"$AST_RULE_DIR/c03-weak-self-guard.yml" <<'YAML'
id: swift.closure.weak-self.guarded
language: swift
rule:
  regex: "\\[[^\\]]*weak\\s+self[^\\]]*\\]"
severity: info
message: "weak self captured; ensure self is safely unwrapped (guard let self = self)."
YAML

 cat >"$AST_RULE_DIR/c03-strong-self.yml" <<'YAML'
id: swift.closure.capture-strong-self
language: swift
rule:
  regex: "\\{[\\s\\S]{0,250}\\bself\\."
severity: info
message: "Closure references self; for long-lived work consider [weak self] to avoid cycles."
YAML

 # CATEGORY 04 — URLSession / Networking
 cat >"$AST_RULE_DIR/c04-data-contents-of.yml" <<'YAML'
id: swift.data-contents-of
language: swift
rule:
  pattern: Data(contentsOf: $X)
severity: warning
message: "Data(contentsOf:) is blocking; avoid for remote URLs and large files."
YAML

 cat >"$AST_RULE_DIR/c04-http-literal.yml" <<'YAML'
id: swift.http-literal
language: swift
rule:
  regex: "\"http://[^\"]+\""
severity: warning
message: "http:// literal detected; prefer https and ATS-compliant networking."
YAML

 cat >"$AST_RULE_DIR/c04-url-http.yml" <<'YAML'
id: swift.url.http-literal
language: swift
rule:
  regex: "URL\\(string:\\s*\"http://[^\"]*\"\\)"
severity: warning
message: "URL(string:) with http:// literal; prefer https unless ATS exception is justified."
YAML

 cat >"$AST_RULE_DIR/c04-urlsession-task-no-resume.yml" <<'YAML'
id: swift.urlsession.task-no-resume
language: swift
rule:
  regex: "\\.(dataTask|uploadTask|downloadTask)\\s*\\("
severity: info
message: "URLSession task created (correlation will check resume/cancel); ensure lifecycle management."
YAML

 cat >"$AST_RULE_DIR/c04-urlsession-trust.yml" <<'YAML'
id: swift.urlsession.delegate.tls-trust
language: swift
rule:
  regex: "didReceiveChallenge\\s*\\(.*URLAuthenticationChallenge.*\\)[\\s\\S]*?completionHandler\\s*\\(\\s*\\.useCredential\\s*,\\s*URLCredential\\(trust:"
severity: error
message: "URLSession delegate trusts server trust directly; TLS pinning bypass risk."
YAML

 cat >"$AST_RULE_DIR/c04-urlcomponents-manual.yml" <<'YAML'
id: swift.urlcomponents.manual-string
language: swift
rule:
  any:
    - regex: "URL\\(string:\\s*\"https?://[^\"\\?]+\\?[^\"\\)]*\"\\s*\\)"
    - regex: "\"[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+\\?([A-Za-z0-9_%-]+=[A-Za-z0-9_%-]+&?)+\""
severity: info
message: "Query strings built manually; prefer URLComponents to avoid encoding bugs."
YAML

 # CATEGORY 05 — Error Handling
 cat >"$AST_RULE_DIR/c05-empty-catch.yml" <<'YAML'
id: swift.error.empty-catch
language: swift
rule:
  regex: "\\bcatch\\s*\\{\\s*\\}"
severity: warning
message: "Empty catch block; handle or propagate error."
YAML

 cat >"$AST_RULE_DIR/c05-json-try-bang.yml" <<'YAML'
id: swift.json.decode.try-bang
language: swift
rule:
  any:
    - regex: "try!\\s*JSONDecoder\\s*\\(\\s*\\)\\s*\\.decode\\s*\\("
    - regex: "try!\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\.decode\\s*\\("
severity: error
message: "JSON decode with try! may crash; use do/catch and surface decoding errors."
YAML

 cat >"$AST_RULE_DIR/c05-json-try-q.yml" <<'YAML'
id: swift.json.decode.try-question
language: swift
rule:
  any:
    - regex: "try\\?\\s*JSONDecoder\\s*\\(\\s*\\)\\s*\\.decode\\s*\\("
    - regex: "try\\?\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\.decode\\s*\\("
severity: info
message: "Decoding with try? discards errors; ensure this is intentional and logged."
YAML

 cat >"$AST_RULE_DIR/c05-fatal-precondition.yml" <<'YAML'
id: swift.fatal-or-precondition
language: swift
rule:
  any:
    - regex: "\\bfatalError\\s*\\("
    - regex: "\\bpreconditionFailure\\s*\\("
severity: warning
message: "Crash calls present; confirm they are not reachable in production."
YAML

 cat >"$AST_RULE_DIR/c05-nil-coalesce-fatal.yml" <<'YAML'
id: swift.nil-coalescing-fatal
language: swift
rule:
  regex: "\\?\\?\\s*fatalError\\s*\\("
severity: warning
message: "Using ?? fatalError for control flow; prefer throwing or early returns."
YAML

 # CATEGORY 06 — Security
 cat >"$AST_RULE_DIR/c06-hardcoded-secrets.yml" <<'YAML'
id: swift.hardcoded.secret
language: swift
rule:
  regex: "(?i)(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*\\\"[^\\\"]+\\\""
severity: error
message: "Hardcoded secret lookalike in source; rotate secrets and load from secure storage."
YAML

 cat >"$AST_RULE_DIR/c06-userdefaults-secrets.yml" <<'YAML'
id: swift.userdefaults.secrets
language: swift
rule:
  regex: "(?i)UserDefaults\\.[A-Za-z_]+\\.set\\s*\\([^)]*(password|token|secret|apikey|api_key|authorization|bearer)[^)]*\\)"
severity: warning
message: "Sensitive-looking value stored in UserDefaults; prefer Keychain."
YAML

 cat >"$AST_RULE_DIR/c06-process-shell.yml" <<'YAML'
id: swift.process.shell-injection
language: swift
rule:
  regex: "\\b(Process\\s*\\(|system\\s*\\(|posix_spawn\\s*\\()"
severity: info
message: "Process/system invocation present; ensure untrusted input is sanitized."
YAML

 cat >"$AST_RULE_DIR/c06-process-suspicious-args.yml" <<'YAML'
id: swift.process.suspicious-args
language: swift
rule:
  regex: "Process\\s*\\(\\s*[^)]*arguments:\\s*\\[[^\\]]*(;|\\|\\||\\|\\s*grep|\\|\\s*sh)[^\\]]*\\]"
severity: warning
message: "Process arguments contain a shell pipeline; avoid shell invocation via arguments."
YAML

 cat >"$AST_RULE_DIR/c06-nskeyedunarchiver-insecure.yml" <<'YAML'
id: swift.nskeyedunarchiver.insecure
language: swift
rule:
  any:
    - regex: "\\bNSKeyedUnarchiver\\.unarchiveObject\\(with:"
    - regex: "\\bunarchiveTopLevelObjectWithData\\s*\\("
severity: warning
message: "Potentially unsafe unarchiving; ensure secure coding and trusted data."
YAML

 cat >"$AST_RULE_DIR/c06-nskeyedarchiver-insecurecoding.yml" <<'YAML'
id: swift.nskeyedarchiver.securecoding.false
language: swift
rule:
  regex: "requiresSecureCoding\\s*:\\s*false"
severity: warning
message: "requiresSecureCoding: false weakens deserialization safety; prefer true + NSSecureCoding."
YAML

 cat >"$AST_RULE_DIR/c06-keychain-accessible-always.yml" <<'YAML'
id: swift.keychain.accessible.always
language: swift
rule:
  regex: "kSecAttrAccessibleAlways"
severity: warning
message: "Keychain kSecAttrAccessibleAlways used; prefer more restrictive accessibility."
YAML

 cat >"$AST_RULE_DIR/c06-fileprotection-none.yml" <<'YAML'
id: swift.fileprotection.none
language: swift
rule:
  regex: "FileProtectionType\\.none"
severity: warning
message: "FileProtectionType.none used; consider stronger file protection."
YAML

 cat >"$AST_RULE_DIR/c06-unsafe-bitcast.yml" <<'YAML'
id: swift.unsafe.bitcast
language: swift
rule:
  regex: "\\bunsafeBitCast\\s*\\("
severity: warning
message: "unsafeBitCast used; review memory safety and type invariants."
YAML

 cat >"$AST_RULE_DIR/c06-unsafe-pointer.yml" <<'YAML'
id: swift.unsafe.pointer
language: swift
rule:
  regex: "\\bUnsafe(Raw)?(Mutable)?Pointer\\b"
severity: info
message: "Unsafe pointer usage; review for memory safety and lifetime rules."
YAML

 # CATEGORY 07 — Crypto / Hashing
 cat >"$AST_RULE_DIR/c07-commoncrypto-weak.yml" <<'YAML'
id: swift.commoncrypto.weak
language: swift
rule:
  any:
    - regex: "\\bCC_MD5\\b"
    - regex: "\\bCC_SHA1\\b"
severity: warning
message: "Weak hash algorithm (MD5/SHA1) via CommonCrypto."
YAML

 cat >"$AST_RULE_DIR/c07-cryptokit-insecure.yml" <<'YAML'
id: swift.cryptokit.insecure
language: swift
rule:
  any:
    - regex: "\\bInsecure\\.SHA1\\b"
    - regex: "\\bInsecure\\.MD5\\b"
severity: warning
message: "CryptoKit Insecure.* algorithm used; prefer SHA256/512."
YAML

 cat >"$AST_RULE_DIR/c07-ecb.yml" <<'YAML'
id: swift.commoncrypto.ecb
language: swift
rule:
  regex: "\\bkCCOptionECBMode\\b"
severity: warning
message: "ECB mode detected; use authenticated encryption modes instead."
YAML

 cat >"$AST_RULE_DIR/c07-insecure-rand.yml" <<'YAML'
id: swift.crypto.insecure.rand
language: swift
rule:
  regex: "\\brand\\s*\\("
severity: warning
message: "rand() is not cryptographically secure; prefer SecRandomCopyBytes/CryptoKit."
YAML

 # CATEGORY 08 — Files & I/O
 cat >"$AST_RULE_DIR/c08-filehandle-open.yml" <<'YAML'
id: swift.filehandle.open
language: swift
rule:
  regex: "\\bFileHandle\\s*\\(\\s*for(Reading|Writing|Updating)(From|To|AtPath)\\s*:"
severity: info
message: "FileHandle opened; ensure close() in defer and handle errors."
YAML

 cat >"$AST_RULE_DIR/c08-string-contents-of.yml" <<'YAML'
id: swift.string.contents-of
language: swift
rule:
  regex: "\\bString\\s*\\(\\s*contentsOf:\\s*"
severity: warning
message: "String(contentsOf:) can block; avoid on main thread and validate encoding/size."
YAML

 cat >"$AST_RULE_DIR/c08-path-join-string.yml" <<'YAML'
id: swift.path.join.string-plus
language: swift
rule:
  regex: "\"/\"\\s*\\+\\s*[A-Za-z_][A-Za-z0-9_]*"
severity: info
message: "Path building via string concatenation; prefer URL.appendingPathComponent."
YAML

 cat >"$AST_RULE_DIR/c08-try-removeitem-question.yml" <<'YAML'
id: swift.filemanager.remove.try-question
language: swift
rule:
  regex: "try\\?\\s*FileManager\\.[A-Za-z_]+\\.removeItem\\s*\\("
severity: info
message: "try? removeItem discards errors; ensure you log/handle failures."
YAML

 # CATEGORY 09 — Threading / Main
 cat >"$AST_RULE_DIR/c09-main-thread-sleep.yml" <<'YAML'
id: swift.main-thread.sleep
language: swift
rule:
  regex: "DispatchQueue\\.main\\.(async|sync)\\s*\\{[\\s\\S]{0,250}\\b(u?sleep)\\s*\\("
severity: warning
message: "Blocking sleep on main queue."
YAML

 # CATEGORY 10 — Performance
 cat >"$AST_RULE_DIR/c10-dateformatter-loop.yml" <<'YAML'
id: swift.dateformatter.in-loop
language: swift
rule:
  regex: "for[\\s\\S]{0,150}DateFormatter\\s*\\(\\s*\\)"
severity: info
message: "DateFormatter constructed near a loop; cache formatters for performance."
YAML

 cat >"$AST_RULE_DIR/c10-numberformatter-loop.yml" <<'YAML'
id: swift.numberformatter.in-loop
language: swift
rule:
  regex: "for[\\s\\S]{0,150}NumberFormatter\\s*\\(\\s*\\)"
severity: info
message: "NumberFormatter constructed near a loop; cache formatters for performance."
YAML

 cat >"$AST_RULE_DIR/c10-jsondecoder-loop.yml" <<'YAML'
id: swift.jsondecoder.in-loop
language: swift
rule:
  regex: "for[\\s\\S]{0,150}JSONDecoder\\s*\\(\\s*\\)"
severity: info
message: "JSONDecoder constructed near a loop; reuse decoders to reduce allocations."
YAML

 # CATEGORY 11 — Debug / Production
 cat >"$AST_RULE_DIR/c11-print-nslog.yml" <<'YAML'
id: swift.print.nslog
language: swift
rule:
  any:
    - regex: "^[^\\S\\n]*print\\s*\\("
    - regex: "\\bNSLog\\s*\\("
severity: info
message: "Print/NSLog found; ensure debug-only or use os.Logger with privacy."
YAML

 cat >"$AST_RULE_DIR/c11-debug-only.yml" <<'YAML'
id: swift.debug.only.code
language: swift
rule:
  regex: "#if\\s+DEBUG"
severity: info
message: "#if DEBUG blocks present; ensure release behavior is correct."
YAML

 cat >"$AST_RULE_DIR/c11-oslogger-privacy.yml" <<'YAML'
id: swift.oslogger.privacy
language: swift
rule:
  regex: "\\blogger\\.[a-zA-Z]+\\([^\\)]*\\(\\s*[^\\)]*\\)[^\\)]*\\)"
  not:
    regex: "privacy:\\s*\\.(private|public)"
severity: info
message: "os.Logger interpolation without explicit privacy; be explicit."
YAML

 # CATEGORY 12 — Regex
 cat >"$AST_RULE_DIR/c12-regex-nested.yml" <<'YAML'
id: swift.regex.nested-quantifiers
language: swift
rule:
  regex: "NSRegularExpression\\(pattern:[^\\n\\)]*(\\+\\+|\\*\\+|\\+\\*|\\*\\*)"
severity: warning
message: "Potential catastrophic backtracking (nested quantifiers) in regex."
YAML

 cat >"$AST_RULE_DIR/c12-nspredicate-format.yml" <<'YAML'
id: swift.nspredicate.format
language: swift
rule:
  regex: "\\bNSPredicate\\s*\\(\\s*format:\\s*\\\""
severity: info
message: "NSPredicate(format:) uses format strings; validate against injection and type issues."
YAML

 # CATEGORY 13 — SwiftUI / Combine
 cat >"$AST_RULE_DIR/c13-combine-sink.yml" <<'YAML'
id: swift.combine.sink-no-store
language: swift
rule:
  regex: "\\.sink\\s*\\("
severity: warning
message: "Combine sink used; ensure AnyCancellable is retained (store(in:))."
YAML

 cat >"$AST_RULE_DIR/c13-swiftui-onreceive.yml" <<'YAML'
id: swift.swiftui.onreceive
language: swift
rule:
  regex: "\\.onReceive\\s*\\("
severity: info
message: "SwiftUI .onReceive used; ensure captures do not create cycles."
YAML

 cat >"$AST_RULE_DIR/c13-uiimage-named.yml" <<'YAML'
id: swift.uiimage.named
language: swift
rule:
  any:
    - regex: "\\bUIImage\\s*\\(\\s*named:"
    - regex: "\\bNSImage\\s*\\(\\s*named:"
severity: info
message: "Image by name; ensure caching/asset catalog usage to avoid repeated loads."
YAML

 # CATEGORY 14 — Memory / Retain
 cat >"$AST_RULE_DIR/c14-timer.yml" <<'YAML'
id: swift.timer.scheduled
language: swift
rule:
  regex: "\\bTimer\\.scheduledTimer\\b"
severity: warning
message: "Timer.scheduledTimer used; ensure it is invalidated and does not strongly capture self."
YAML

 cat >"$AST_RULE_DIR/c14-notification-block.yml" <<'YAML'
id: swift.notification.addobserver.block
language: swift
rule:
  regex: "NotificationCenter\\.default\\.addObserver\\([^\\)]*forName:"
severity: warning
message: "Block-based NotificationCenter observer; ensure token stored and removed."
YAML

 cat >"$AST_RULE_DIR/c14-cadisplaylink.yml" <<'YAML'
id: swift.cadisplaylink.created
language: swift
rule:
  regex: "\\bCADisplayLink\\s*\\("
severity: warning
message: "CADisplayLink created; ensure invalidate() on teardown."
YAML

 # CATEGORY 18 — Deprecated APIs
 cat >"$AST_RULE_DIR/c18-nsurlconnection.yml" <<'YAML'
id: swift.deprecated.nsurlconnection
language: swift
rule:
  any:
    - regex: "\\bNSURLConnection\\b"
    - regex: "NSURLConnection\\.sendSynchronousRequest\\s*\\("
severity: info
message: "NSURLConnection deprecated; use URLSession."
YAML

 cat >"$AST_RULE_DIR/c18-uiwebview.yml" <<'YAML'
id: swift.deprecated.uiwebview
language: swift
rule:
  regex: "\\bUIWebView\\b"
severity: warning
message: "UIWebView is deprecated and banned on App Store; use WKWebView."
YAML

 cat >"$AST_RULE_DIR/c18-userdefaults-sync.yml" <<'YAML'
id: swift.deprecated.userdefaults.synchronize
language: swift
rule:
  regex: "\\bUserDefaults\\.[A-Za-z_]+\\.synchronize\\s*\\("
severity: info
message: "UserDefaults.synchronize() is deprecated; remove and rely on system syncing."
YAML

 cat >"$AST_RULE_DIR/c18-uiapp-keywindow.yml" <<'YAML'
id: swift.deprecated.uiapplication.keywindow
language: swift
rule:
  regex: "\\bUIApplication\\.shared\\.keyWindow\\b"
severity: info
message: "UIApplication.shared.keyWindow is deprecated; use windows/scenes APIs."
YAML

 cat >"$AST_RULE_DIR/c18-statusbar.yml" <<'YAML'
id: swift.deprecated.statusbar
language: swift
rule:
  regex: "statusBarFrame|setStatusBarHidden"
severity: info
message: "Deprecated status bar API usage; migrate to modern APIs."
YAML

 # Misc existing rule IDs preserved (compat / reference)
 cat >"$AST_RULE_DIR/c04-timer-not-invalidated.yml" <<'YAML'
id: swift.timer.not-invalidated
language: swift
rule:
  regex: "Timer\\.scheduledTimer"
severity: warning
message: "Timer scheduled; ensure timer.invalidate() occurs (heuristic)."
YAML

 cat >"$AST_RULE_DIR/c14-notification-token-not-removed.yml" <<'YAML'
id: swift.notification.token-not-removed
language: swift
rule:
  regex: "NotificationCenter\\.default\\.addObserver\\("
severity: warning
message: "NotificationCenter observer added; ensure removal/token lifecycle (heuristic)."
YAML

 cat >"$AST_RULE_DIR/c13-combine-sink-no-store-compat.yml" <<'YAML'
id: swift.combine.sink-no-store.compat
language: swift
rule:
  regex: "\\.sink\\s*\\("
severity: info
message: "Combine sink detected (compat rule); retention must be ensured."
YAML

 cat >"$AST_RULE_DIR/c06-hardcoded-bearer.yml" <<'YAML'
id: swift.http.header.bearer-literal
language: swift
rule:
  regex: "(?i)Authorization\\\"?\\s*:\\s*\\\"?Bearer\\s+[A-Za-z0-9\\._\\-]+\\\"?"
severity: warning
message: "Hardcoded Bearer token-like Authorization header."
YAML

 cat >"$AST_RULE_DIR/c06-userdefaults-boolean-security.yml" <<'YAML'
id: swift.userdefaults.boolean-security
language: swift
rule:
  regex: "UserDefaults\\.(standard|shared)\\.bool\\(forKey:\\s*\"(?i)(debug|insecure|allowhttp|disableats)\"\\)"
severity: warning
message: "Security-toggling feature flag via UserDefaults; ensure release build locks this down."
YAML

 cat >"$AST_RULE_DIR/c06-ats-flag-disable.yml" <<'YAML'
id: swift.ats.flag.disable
language: swift
rule:
  regex: "(?i)UserDefaults\\.(standard|shared)\\.(set|register)\\([^\\)]*(disableats|allowhttp|insecure)[^\\)]*\\)"
severity: info
message: "Security-affecting feature flag toggled via UserDefaults; ensure release build constraints."
YAML

 cat >"$AST_RULE_DIR/c03-kvc-literal.yml" <<'YAML'
id: swift.kvc.literal
language: swift
rule:
  regex: "\\.setValue\\s*\\([^\\)]*,\\s*forKey:\\s*\"[A-Za-z0-9_\\.]+\"\\s*\\)"
severity: info
message: "KVC string key; prefer typed APIs to avoid runtime key typos."
YAML

 cat >"$AST_RULE_DIR/c03-anyobject-cast.yml" <<'YAML'
id: swift.anyobject-cast
language: swift
rule:
  regex: "\\bas\\s+AnyObject\\b"
severity: info
message: "Casting to AnyObject erases types; avoid unless required by ObjC APIs."
YAML

 cat >"$AST_RULE_DIR/c02-actor-detached.yml" <<'YAML'
id: swift.actor.escaping-reference
language: swift
rule:
  regex: "@MainActor[\\s\\S]{0,500}Task\\.detached\\s*\\{"
severity: info
message: "Detached task inside @MainActor context; verify actor boundary crossings."
YAML

 cat >"$AST_RULE_DIR/c04-urlsession-task-no-cancel.yml" <<'YAML'
id: swift.urlsession.task-no-cancel-on-deinit
language: swift
rule:
  regex: "let\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*.*\\.(dataTask|uploadTask|downloadTask)\\s*\\("
severity: info
message: "URLSession task captured; ensure cancel() on teardown if needed."
YAML

 cat >"$AST_RULE_DIR/c10-nscache.yml" <<'YAML'
id: swift.nscache.misuse
language: swift
rule:
  regex: "NSCache<\\s*[^,>]+\\s*,\\s*[^>]+\\s*>\\s*\\("
severity: info
message: "Check NSCache key/value for class types and memory behaviors."
YAML

 cat >"$AST_RULE_DIR/c02-dispatchsemaphore-main.yml" <<'YAML'
id: swift.dispatchsemaphore.main
language: swift
rule:
  regex: "DispatchQueue\\.main\\.[a-z]+\\s*\\{[\\s\\S]{0,250}DispatchSemaphore\\s*\\(\\s*value:\\s*[0-9]+\\s*\\)[\\s\\S]{0,250}\\.wait\\s*\\("
severity: warning
message: "Semaphore wait on main queue can deadlock."
YAML

 cat >"$AST_RULE_DIR/c21-ibaction-iuo.yml" <<'YAML'
id: swift.ibaction.iuo
language: swift
rule:
  regex: "@IBAction\\s+func\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\([^\\)]*!\\)"
severity: info
message: "@IBAction with IUO parameter; prefer non-IUO where possible."
YAML

 # merge user rules dir
  if [[ -n "$USER_RULE_DIR" && -d "$USER_RULE_DIR" ]]; then
    cp -R "$USER_RULE_DIR"/. "$AST_RULE_DIR"/ 2>/dev/null || true
  fi

 build_ag_rule_index || true

 if [[ -n "$DUMP_RULES_DIR" ]]; then
  mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || die "Cannot create --dump-rules dir: $DUMP_RULES_DIR"
  cp -R "$AST_RULE_DIR"/. "$DUMP_RULES_DIR"/ 2>/dev/null || die "Failed copying rules to $DUMP_RULES_DIR"
  say "${GREEN}${CHECK} Rules written to: ${CYAN}$DUMP_RULES_DIR${RESET}"
  exit 0
 fi

 if [[ -n "$EXPLAIN_RULE_ID" ]]; then
  local f="${AG_RULE_FILE[$EXPLAIN_RULE_ID]:-}"
  [[ -n "$f" && -f "$f" ]] || die "Rule id not found in merged rules: $EXPLAIN_RULE_ID"
  say "${WHITE}${BOLD}Rule: ${EXPLAIN_RULE_ID}${RESET}"
  say "${DIM}File: $f${RESET}"
  echo ""
  cat "$f"
  exit 0
  fi

  if [[ "$LIST_RULES" -eq 1 ]]; then
    say "${WHITE}${BOLD}ast-grep rules (embedded + user):${RESET}"
    shopt -s nullglob
  local f id sev msg base cat
    for f in "$AST_RULE_DIR"/*.yml; do
   id="$(awk '/^id:/{print $2; exit}' "$f" 2>/dev/null || true)"
   sev="$(awk '/^severity:/{print $2; exit}' "$f" 2>/dev/null || true)"
   msg="$(awk '/^message:/{sub(/^message:[ ]*/,""); print; exit}' "$f" 2>/dev/null || true)"
   base="$(basename "$f")"
   cat=0
   [[ "$base" =~ ^c([0-9]{2})- ]] && cat=$((10#${BASH_REMATCH[1]}))
   [[ -n "$id" ]] || continue
   if [[ "$cat" -gt 0 ]]; then say " - ${id} [${sev:-info}] (cat $cat) ${msg}"; else say " - ${id} [${sev:-info}] ${msg}"; fi
    done
    shopt -u nullglob
    exit 0
  fi
}

run_ast_rules(){
 [[ "$HAS_AST_GREP" -eq 1 && -n "${AST_RULE_DIR:-}" ]] || return 1
 ensure_ag_stream || return 1
 [[ "$AG_STREAM_READY" -eq 1 && -s "$AG_STREAM_FILE" ]] || return 0

  print_subheader "ast-grep rule-pack summary"

  if command -v python3 >/dev/null 2>&1; then
  local tmp_sum; tmp_sum="$(mktemp_file ubs_ag_summary)"
  cleanup_add "$tmp_sum"
  python3 - "$AG_STREAM_FILE" "$DETAIL_LIMIT" >"$tmp_sum" <<'PY'
import json
import sys
import collections

path, limit = sys.argv[1], int(sys.argv[2])
buckets = collections.OrderedDict()

def sev_map(s: str) -> str:
    s = (s or "").lower().strip()
    if s in {"error", "fatal", "critical", "high", "serious"}:
        return "critical"
    if s in {"warning", "warn", "medium"}:
        return "warning"
    if s in {"info", "note", "hint", "low"}:
        return "info"
    return "info"

def start_line(obj: dict) -> int:
    rng = obj.get("range") or {}
    start = rng.get("start") or {}
    ln0 = start.get("row")
    if ln0 is None:
        ln0 = start.get("line", 0)
    try:
        return int(ln0) + 1
    except Exception:
        return 1

def add(obj: dict) -> None:
    rid = obj.get("ruleId") or obj.get("rule_id") or obj.get("id") or "unknown"
    sev = sev_map(obj.get("severity") or obj.get("level") or "info")
    file = obj.get("file", "?")
    msg = obj.get("message") or rid
    b = buckets.setdefault(rid, {"severity": sev, "message": msg, "count": 0, "samples": []})
    b["count"] += 1
    if len(b["samples"]) < limit:
        ln = start_line(obj)
        lines = (obj.get("lines") or "").strip().splitlines()
        code = (lines[0] if lines else "").strip()
        b["samples"].append((file, ln, code))

with open(path, "r", encoding="utf-8", errors="replace") as fh:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        try:
            add(json.loads(raw))
        except Exception:
            continue

sev_rank = {"critical": 0, "warning": 1, "info": 2, "good": 3}
for rid, data in sorted(
    buckets.items(),
    key=lambda kv: (sev_rank.get(kv[1]["severity"], 9), -kv[1]["count"], kv[0]),
):
    print(f"__FINDING__\t{data['severity']}\t{data['count']}\t{rid}\t{data['message']}")
    for f, l, c in data["samples"]:
        s = (c or "").replace("\t", " ").strip()
        print(f"__SAMPLE__\t{f}\t{l}\t{s}")
PY
  while IFS=$'\t' read -r tag a b c d; do
    case "$tag" in
    __FINDING__)
     local sev cnt rid msg cat
     sev="$(normalize_severity "$a")"
     cnt="$(num_clamp "$b")"
     rid="$c"; msg="$d"
     cat="${AG_RULE_CATEGORY[$rid]:-0}"
     set_category "$cat"
     print_finding "$sev" "$cnt" "$rid: $msg"
     ;;
    __SAMPLE__) print_code_sample "$a" "$b" "$c" ;;
   esac
  done <"$tmp_sum"
 else
  declare -A counts=()
  local line rid
  while IFS= read -r line; do
   rid="$(printf '%s' "$line" | sed -nE 's/.*"(ruleId|rule_id)"[[:space:]]*:[[:space:]]*"([^"]+)".*/\2/p')"
   [[ -n "$rid" ]] || continue
   counts["$rid"]=$(( ${counts["$rid"]:-0} + 1 ))
  done <"$AG_STREAM_FILE"
  for rid in "${!counts[@]}"; do
   set_category "${AG_RULE_CATEGORY[$rid]:-0}"
   print_finding "info" "${counts[$rid]}" "$rid"
  done
 fi
  return 0
}

run_urlsession_task_correlation(){
 print_subheader "URLSession task correlation (resume/cancel) [AST-guided]"
 if [[ "$HAS_AST_GREP" -ne 1 ]]; then
  print_finding "info" 0 "Correlation skipped" "ast-grep unavailable"
  return 0
 fi
 if ! command -v python3 >/dev/null 2>&1; then
  print_finding "info" 0 "Correlation skipped" "python3 unavailable"
  return 0
 fi
 ag_build_file_index || {
  print_finding "info" 0 "Correlation skipped" "Could not build ast-grep per-file index"
  return 0
 }
 [[ -n "${AG_FILE_INDEX_FILE:-}" && -s "${AG_FILE_INDEX_FILE:-}" ]] || {
  print_finding "info" 0 "Correlation skipped" "Empty ast-grep per-file index"
  return 0
 }

 local tmp; tmp="$(mktemp_file ubs_urlsession_corr)"
 cleanup_add "$tmp"

 python3 - "$AG_FILE_INDEX_FILE" "$PROJECT_DIR" "$DETAIL_LIMIT" >"$tmp" <<'PY'
import json, sys, os, re, collections

index_path=sys.argv[1]
project_dir=sys.argv[2]
limit=int(sys.argv[3])

TASK_RID="swift.urlsession.task-no-resume"
TASK_CALL_RE=re.compile(r"\.(dataTask|uploadTask|downloadTask)\s*\(")

def norm_path(p):
 if os.path.isabs(p): return p
 return os.path.normpath(os.path.join(project_dir,p))

def rel(p):
 try:
  rp=os.path.relpath(p, project_dir)
  return rp if not rp.startswith("..") else p
 except: return p

def add_finding(out, fid, sev, title, desc, sample):
 b=out.setdefault(fid, {"severity":sev, "title":title, "desc":desc, "count":0, "samples":[]})
 b["count"]+=1
 if sample and len(b["samples"]) < limit:
  f,ln,code=sample
  code=(code or "").replace("\t"," ").strip()
  b["samples"].append((f,ln,code))

class Lex:
 __slots__=("line_comment","block_comment","in_string","raw_hashes","triple")
 def __init__(self):
  self.line_comment=False
  self.block_comment=0
  self.in_string=False
  self.raw_hashes=0
  self.triple=False

def startswith_at(s, i, lit):
 return s.startswith(lit, i)

def is_escaped(s, i):
 j=i-1
 bs=0
 while j>=0 and s[j]=='\\':
  bs+=1; j-=1
 return (bs%2)==1

def enter_string(s, i, lex):
 if s[i] == '"':
  if startswith_at(s,i,'"""'):
   lex.in_string=True; lex.raw_hashes=0; lex.triple=True
   return i+3
  lex.in_string=True; lex.raw_hashes=0; lex.triple=False
  return i+1
 if s[i] == '#':
  j=i
  while j < len(s) and s[j] == '#': j+=1
  if j < len(s) and s[j] == '"':
   if startswith_at(s,j,'"""'):
    lex.in_string=True; lex.raw_hashes=j-i; lex.triple=True
    return j+3
   lex.in_string=True; lex.raw_hashes=j-i; lex.triple=False
   return j+1
 return i+1

def scan_balanced(s, start, open_ch, close_ch):
 i=start
 depth=0
 lex=Lex()
 while i < len(s):
  ch=s[i]
  nxt=s[i+1] if i+1 < len(s) else ''
  if lex.line_comment:
   if ch == '\n': lex.line_comment=False
   i+=1; continue
  if lex.block_comment>0:
   if ch=='/' and nxt=='*':
    lex.block_comment+=1; i+=2; continue
   if ch=='*' and nxt=='/':
    lex.block_comment-=1; i+=2; continue
   i+=1; continue
  if lex.in_string:
   if lex.triple:
    end_delim = '"""' + ('#'*lex.raw_hashes)
    if startswith_at(s,i,end_delim):
     lex.in_string=False; i+=len(end_delim); continue
    i+=1; continue
   else:
    if lex.raw_hashes>0:
     end_delim = '"' + ('#'*lex.raw_hashes)
     if startswith_at(s,i,end_delim):
      lex.in_string=False; i+=len(end_delim); continue
     i+=1; continue
    else:
     if ch=='"' and not is_escaped(s,i):
      lex.in_string=False; i+=1; continue
     i+=1; continue
  if ch=='/' and nxt=='/':
   lex.line_comment=True; i+=2; continue
  if ch=='/' and nxt=='*':
   lex.block_comment=1; i+=2; continue
  if ch=='"' or ch=='#':
   i=enter_string(s,i,lex); continue
  if ch==open_ch:
   depth+=1; i+=1; continue
  if ch==close_ch:
   depth-=1; i+=1
   if depth==0: return i
   continue
  i+=1
 return None

def skip_ws(s, i):
 n=len(s)
 while i < n and s[i].isspace(): i+=1
 return i

def parse_call_end(s, call_start):
 open_paren = s.find('(', call_start)
 if open_paren < 0: return None
 end_args = scan_balanced(s, open_paren, '(', ')')
 if end_args is None: return None
 i=end_args
 while True:
  i=skip_ws(s,i)
  if i >= len(s): break
  if s[i] == '{':
   end_cl = scan_balanced(s, i, '{', '}')
   if end_cl is None: return i
   i=end_cl
   continue
  m=re.match(r'[A-Za-z_]\w*\s*:\s*', s[i:])
  if m:
   j=i+m.end()
   j=skip_ws(s,j)
   if j < len(s) and s[j] == '{':
    end_cl = scan_balanced(s, j, '{', '}')
    if end_cl is None: return j
    i=end_cl
    continue
  break
 return i

def chained_lifecycle(s, call_end):
 i=skip_ws(s, call_end)
 if i >= len(s): return None
 if s[i] in '?!':
  j=skip_ws(s, i+1)
  if j < len(s) and s[j] == '.': i=j
  else: return None
 if s[i] != '.': return None
 j=skip_ws(s, i+1)
 for name in ("resume","cancel"):
  if s.startswith(name, j):
   k=skip_ws(s, j+len(name))
   if k < len(s) and s[k] == '(':
    return name
 return None

def find_last_assignment_eq(seg):
 for pos in range(len(seg)-1, -1, -1):
  if seg[pos] != '=': continue
  prev = seg[pos-1] if pos>0 else ''
  nxt = seg[pos+1] if pos+1 < len(seg) else ''
  if prev=='=' or nxt=='=': continue
  if prev in '<>!' : continue
  if nxt == '>' : continue
  return pos
 return -1

def extract_lhs_var(lines, row, call_col):
 def extract_from_lhs(lhs):
  lhs=lhs.strip()
  m=re.search(r'\b(?:let|var)\s+([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)', lhs)
  if m:
   return re.sub(r'\s*', '', m.group(1))
  m=re.search(r'([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?\s*$', lhs)
  if m:
   return re.sub(r'\s*', '', m.group(1))
  return None

 if row < 0 or row >= len(lines): return None
 line=lines[row]
 call_col=max(0, min(call_col, len(line)))
 prefix=line[:call_col]
 eq=find_last_assignment_eq(prefix)
 if eq != -1:
  lhs=prefix[:eq]
  return extract_from_lhs(lhs)
 if row-1 >= 0:
  prev=lines[row-1]
  if re.search(r'=\s*$', prev):
   eq=find_last_assignment_eq(prev)
   if eq != -1:
    lhs=prev[:eq]
    return extract_from_lhs(lhs)
 return None

def build_line_offsets(lines):
 offs=[0]*(len(lines)+1)
 p=0
 for i,ln in enumerate(lines):
  offs[i]=p
  p+=len(ln)
 offs[len(lines)]=p
 return offs

def compile_resume_patterns(var_base, property_like):
 vb=re.escape(var_base)
 if property_like:
  assign_re=re.compile(rf'\b(?:self\s*\.\s*)?{vb}\s*=')
  resume_re=re.compile(rf'\b(?:self\s*\.\s*)?{vb}\s*(?:\?|\!)?\s*\.\s*resume\s*\(')
  cancel_re=re.compile(rf'\b(?:self\s*\.\s*)?{vb}\s*(?:\?|\!)?\s*\.\s*cancel\s*\(')
  ret_re=re.compile(rf'\breturn\s+(?:self\s*\.\s*)?{vb}\b')
 else:
  assign_re=re.compile(rf'(?<!\.)\b{vb}\b\s*=')
  resume_re=re.compile(rf'(?<!\.)\b{vb}\b\s*(?:\?|\!)?\s*\.\s*resume\s*\(')
  cancel_re=re.compile(rf'(?<!\.)\b{vb}\b\s*(?:\?|\!)?\s*\.\s*cancel\s*\(')
  ret_re=re.compile(rf'\breturn\s+{vb}\b')
 return assign_re, resume_re, cancel_re, ret_re

idx=json.load(open(index_path,'r',encoding='utf-8'))
out=collections.OrderedDict()

for fkey, events in idx.items():
 cands=[e for e in events if (e.get('rid') == TASK_RID)]
 if not cands: continue
 path=norm_path(fkey)
 if not os.path.exists(path):
  continue
 try:
  text=open(path,'r',encoding='utf-8',errors='ignore').read()
 except:
  continue
 lines=text.splitlines(True)
 offs=build_line_offsets(lines)

 seen=set()
 for e in cands:
  try:
   row=int(e.get('row',0)); col=int(e.get('col',0))
  except:
   continue
  if row < 0 or row >= len(lines): continue
  line=lines[row]
  col=max(0, min(col, len(line)))
  seg=line[col:]
  m=TASK_CALL_RE.search(seg)
  if m:
   call_col=col+m.start()
  else:
   m=TASK_CALL_RE.search(line)
   if not m: continue
   call_col=m.start()
  if (row,call_col) in seen: continue
  seen.add((row,call_col))

  call_start=offs[row]+call_col
  call_end=parse_call_end(text, call_start)
  if call_end is None: continue

  chain=chained_lifecycle(text, call_end)
  if chain == "resume":
   continue

  var_expr=extract_lhs_var(lines, row, call_col)
  code=(line.strip() if line else "").replace("\t"," ")
  sample=(rel(path), row+1, code)

  if not var_expr:
   prefix=line[:call_col]
   if re.search(r'\breturn\b', prefix):
    continue
   if chain == "cancel":
    continue
   add_finding(out,
    "ubs.correlation.urlsession.unassigned-no-resume",
    "warning",
    "URLSession task created but never resumed (result unused)",
    "Call .resume() on the returned task (or return/store it for the caller to resume).",
    sample)
   continue

  var_base=var_expr.split('.')[-1]
  property_like=('.' in var_expr)
  assign_re, resume_re, cancel_re, ret_re = compile_resume_patterns(var_base, property_like)

  region=text[call_end:]
  mnext=assign_re.search(region)
  region2 = region[:mnext.start()] if mnext else region

  if ret_re.search(region2):
   continue
  if resume_re.search(region2):
   continue
  if cancel_re.search(region2):
   add_finding(out,
    "ubs.correlation.urlsession.assigned-cancel-no-resume",
    "info",
    "URLSession task cancelled without resume()",
    "If intentional, ignore; otherwise call resume() to start the request (or return it).",
    sample)
   continue

  add_finding(out,
   "ubs.correlation.urlsession.assigned-no-resume",
   "warning",
   "URLSession task assigned but no resume() found (in-file)",
   "Call task.resume() after creation, or return/store the task and resume later (ensure lifecycle management).",
   sample)

for fid, data in out.items():
 title = data["title"].replace("\t"," ").strip()
 desc = data["desc"].replace("\t"," ").strip()
 sev = data["severity"].replace("\t"," ").strip()
 print(f"__FINDING__\t{sev}\t{data['count']}\t{fid}\t{title}\t{desc}")
 for f,ln,code in data["samples"]:
  print(f"__SAMPLE__\t{f}\t{ln}\t{code}")
PY

 local any=0
 while IFS=$'\t' read -r tag a b c d e; do
  case "$tag" in
   __FINDING__)
    any=1
    local sev cnt rid title desc
    sev="$(normalize_severity "$a")"
    cnt="$(num_clamp "$b")"
    rid="$c"; title="$d"; desc="$e"
    set_category 4
    print_finding "$sev" "$cnt" "$rid: $title" "$desc"
    ;;
   __SAMPLE__)
    print_code_sample "$a" "$b" "$c"
    ;;
  esac
 done <"$tmp"

 [[ "$any" -eq 0 ]] && print_finding "good" "No URLSession tasks appear to be missing resume()/cancel() in-file"
 return 0
}

run_resource_lifecycle_checks(){
  print_subheader "Resource lifecycle correlation (Swift)"
  local helper="$SCRIPT_DIR/helpers/resource_lifecycle_swift.py"
  if [[ -f "$helper" ]] && command -v python3 >/dev/null 2>&1; then
    local output
    if output=$(python3 "$helper" "$PROJECT_DIR" 2>/dev/null); then
      if [[ -z "$output" ]]; then
        print_finding "good" "All tracked resource acquisitions show matching cleanup or usage"
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
   return 0
    else
      print_finding "info" 0 "AST helper failed" "See stderr for details"
    fi
 fi

    if command -v python3 >/dev/null 2>&1; then
  local tmp_py; tmp_py="$(mktemp_file ubs_rlc_py)"
  cleanup_add "$tmp_py"
      cat >"$tmp_py" <<'PY'
import os, re, sys
root=sys.argv[1]
rules={
 'timer':(re.compile(r'Timer\.scheduledTimer'),re.compile(r'\.invalidate\s*\(')),
 'urlsession_task':(re.compile(r'\.(dataTask|uploadTask|downloadTask)\s*\('), re.compile(r'\.(resume|cancel)\s*\(')),
 'notification_token':(re.compile(r'NotificationCenter\.default\.addObserver\([^)]*(using:\s*\{|forName:)'), re.compile(r'removeObserver\s*\(')),
 'file_handle':(re.compile(r'FileHandle\s*\(\s*for(Reading|Writing|Updating)(From|To|AtPath)\s*:'), re.compile(r'\.close\s*\(')),
 'combine_sink':(re.compile(r'\.sink\s*\('), re.compile(r'\.store\s*\(\s*in:\s*&')),
 'dispatch_source':(re.compile(r'DispatchSource\.(makeTimerSource|makeFileSystemObjectSource|makeReadSource|makeWriteSource)'), re.compile(r'(\.cancel|\.(resume))\s*\(')),
 'cadisplaylink':(re.compile(r'CADisplayLink\s*\('), re.compile(r'\.invalidate\s*\(')),
 'kvo_observer':(re.compile(r'addObserver\([^)]*forKeyPath:'), re.compile(r'removeObserver\([^)]*forKeyPath:'))
}
for dp,_,fs in os.walk(root):
  for fn in fs:
    if not fn.endswith(('.swift','.mm','.m')): continue
    p=os.path.join(dp,fn)
  try: s=open(p,'r',encoding='utf-8',errors='ignore').read()
    except: continue
    for kind,(acq,rel) in rules.items():
      ac=len(acq.findall(s)); rl=len(rel.findall(s))
      if ac>rl:
        print(f"{p}\t{kind}\tacquire={ac} cleanup={rl}")
PY
      local out
      out=$(python3 "$tmp_py" "$PROJECT_DIR" 2>/dev/null || true)
      if [[ -n "$out" ]]; then
        while IFS=$'\t' read -r location kind message; do
          [[ -z "$location" ]] && continue
          local summary="${RESOURCE_LIFECYCLE_SUMMARY[$kind]:-Resource imbalance}"
          local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$kind]:-Ensure matching cleanup call}"
          local severity="${RESOURCE_LIFECYCLE_SEVERITY[$kind]:-warning}"
          print_finding "$severity" 1 "$summary [$location]" "$message; $remediation"
        done <<<"$out"
      else
        print_finding "good" "All tracked resource acquisitions show matching cleanup or usage"
      fi
  return 0
  fi

 local rid header_shown=0
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
   acquire_hits=${acquire_hits:-0}; release_hits=${release_hits:-0}
      if (( acquire_hits > release_hits )); then
    header_shown=1
        local delta=$((acquire_hits - release_hits))
        local relpath=${file#"$PROJECT_DIR"/}; [[ "$relpath" == "$file" ]] && relpath="$file"
        local summary="${RESOURCE_LIFECYCLE_SUMMARY[$rid]:-Resource imbalance}"
        local remediation="${RESOURCE_LIFECYCLE_REMEDIATION[$rid]:-Ensure matching cleanup call}"
        local severity="${RESOURCE_LIFECYCLE_SEVERITY[$rid]:-warning}"
        local desc="$remediation (acquire=$acquire_hits, cleanup=$release_hits)"
        print_finding "$severity" "$delta" "$summary [$relpath]" "$desc"
      fi
    done <<<"$file_list"
  done
 [[ "$header_shown" -eq 0 ]] && print_finding "good" "All tracked resource acquisitions have matching cleanups"
}

run_async_error_checks(){
 print_subheader "Async concurrency coverage (ast-grep)"
  if [[ "$HAS_AST_GREP" -ne 1 ]]; then
  print_finding "info" 0 "ast-grep not available" "Install ast-grep to enable richer concurrency checks"
  return 0
 fi
 ensure_ag_stream || true
 if [[ "$AG_STREAM_READY" -ne 1 || ! -s "$AG_STREAM_FILE" ]]; then
  print_finding "info" 0 "ast-grep stream unavailable" "Concurrency summary requires ast-grep JSON stream output"
  return 0
 fi
 if ! command -v python3 >/dev/null 2>&1; then
  print_finding "info" 0 "python3 not available" "Install python3 for concurrency summary"
  return 0
 fi

 python3 - "$AG_STREAM_FILE" <<'PY' | while IFS=$'\t' read -r rid count samples; do
import json
import sys
import collections

want = {"swift.task.floating", "swift.task.detached-no-handle", "swift.continuation.no-resume"}
stats = collections.OrderedDict()

with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            continue

        rid = obj.get("ruleId") or obj.get("rule_id") or obj.get("id")
        if rid not in want:
            continue

        file = obj.get("file", "?")
        rng = obj.get("range") or {}
        start = rng.get("start") or {}
        ln0 = start.get("row")
        if ln0 is None:
            ln0 = start.get("line", 0)
        try:
            ln = int(ln0) + 1
        except Exception:
            ln = 1

        b = stats.setdefault(rid, {"count": 0, "samples": []})
        b["count"] += 1
        if len(b["samples"]) < 3:
            b["samples"].append(f"{file}:{ln}")

for rid, data in stats.items():
    print(f"{rid}\t{data['count']}\t{','.join(data['samples'])}")
PY
    [[ -z "$rid" ]] && continue
  local severity="${ASYNC_ERROR_SEVERITY[$rid]:-warning}"
  local summary="${ASYNC_ERROR_SUMMARY[$rid]:-$rid}"
  local desc="${ASYNC_ERROR_REMEDIATION[$rid]:-"Fix concurrency misuse"}"
    [[ -n "$samples" ]] && desc+=" (e.g., $samples)"
    print_finding "$severity" "$count" "$summary" "$desc"
 done
}

run_swift_type_narrowing_checks(){
  print_subheader "Swift guard let validation"
  if [[ "$HAS_SWIFT_FILES" -eq 0 ]]; then
    print_finding "info" 0 "No Swift sources detected" "Place .swift files in the project root to enable guard analysis"
    return 0
  fi
  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -eq 1 ]]; then
  print_finding "info" 0 "Swift type narrowing checks skipped" "Set UBS_SKIP_TYPE_NARROWING=0 to re-enable"
    return 0
  fi
  local helper="$SCRIPT_DIR/helpers/type_narrowing_swift.py"
  if [[ ! -f "$helper" ]]; then
    print_finding "info" 0 "Swift type narrowing helper missing" "$helper not found"
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 unavailable for Swift helper" "Install python3 to enable guard analysis"
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
    print_finding "good" "Swift guard clauses exit before force unwraps"
    return 0
  fi
  local count=0
  local previews=()
  while IFS=$'\t' read -r location message; do
    [[ -z "$location" ]] && continue
    count=$((count + 1))
  [[ ${#previews[@]} -lt 3 ]] && previews+=("$location → $message")
 done <<<"$output"
  local desc=""
 [[ ${#previews[@]} -gt 0 ]] && desc="Examples: ${previews[*]}"
 [[ $count -gt ${#previews[@]} ]] && desc+=" (and $((count - ${#previews[@]})) more)"
  print_finding "warning" "$count" "Swift guard let else-block may continue" "$desc"
}

run_plist_checks(){
  print_subheader "Info.plist ATS precise parsing"
  if command -v python3 >/dev/null 2>&1; then
    local out
    out=$(python3 - "$PROJECT_DIR" <<'PY'
import os
import sys
import plistlib
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def check(fp: Path):
    try:
        with fp.open("rb") as fh:
            pl = plistlib.load(fh)
  except Exception:
    return []

    res = []
    if not isinstance(pl, dict):
  return res

    ats = pl.get("NSAppTransportSecurity") or {}
    if not isinstance(ats, dict):
        return res

    if ats.get("NSAllowsArbitraryLoads") is True:
        res.append(("warning", str(fp), "ATS arbitrary loads enabled", "NSAllowsArbitraryLoads=true"))
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        res.append(("info", str(fp), "Arbitrary loads in web content", "NSAllowsArbitraryLoadsInWebContent=true"))
    if ats.get("NSAllowsLocalNetworking") is True:
        res.append(("info", str(fp), "Local networking allowed", "NSAllowsLocalNetworking=true"))

    ex = ats.get("NSExceptionDomains") or {}
    if isinstance(ex, dict):
        for domain, cfg in ex.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                res.append(("warning", str(fp), f"HTTP allowed for {domain}", "NSExceptionAllowsInsecureHTTPLoads=true"))
            if cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads") is True:
                res.append(("info", str(fp), f"Temporary HTTP for {domain}", "NSTemporaryExceptionAllowsInsecureHTTPLoads=true"))
            if cfg.get("NSIncludesSubdomains") is True and ("*" in str(domain)):
                res.append(("warning", str(fp), f"Broad subdomain exception {domain}", "NSIncludesSubdomains with wildcard-like domain"))

    return res.copy()

acc = []
for dp, _, files in os.walk(root):
    for n in sorted(files):
        if n == "Info.plist":
            acc.extend(check(Path(dp) / n))

for sev, fp, title, detail in acc:
    print(f"{sev}\t{fp}\t{title}\t{detail}")
PY
)
    if [[ -n "$out" ]]; then
      while IFS=$'\t' read -r sev file title detail; do
        print_finding "$sev" 1 "$title [$file]" "$detail"
      done <<<"$out"
    else
      print_finding "good" "No problematic ATS settings found via plist parsing"
    fi
  else
    print_finding "info" 0 "python3 not available for ATS parsing" "Using regex heuristics below"
  fi
}

run_entitlements_checks(){
 print_subheader "Entitlements parsing (.entitlements)"
 if ! command -v python3 >/dev/null 2>&1; then
  print_finding "info" 0 "python3 not available for entitlements parsing" "Install python3 to enable precise entitlement checks"
  return 0
 fi
    local out
    out=$(python3 - "$PROJECT_DIR" <<'PY'
import os
import sys
import plistlib
from pathlib import Path

root = Path(sys.argv[1])

SUSPICIOUS = [
    ("get-task-allow", True, "warning", "get-task-allow enabled", "Debugging entitlement present; ensure Release builds disable this."),
    ("com.apple.security.cs.disable-library-validation", True, "warning", "Disable library validation", "Weakens Hardened Runtime; review justification."),
    ("com.apple.security.cs.allow-jit", True, "info", "JIT allowed", "JIT increases attack surface; ensure it is required."),
    ("com.apple.security.cs.allow-unsigned-executable-memory", True, "warning", "Unsigned executable memory", "High risk; avoid unless absolutely required."),
    ("com.apple.security.cs.allow-dyld-environment-variables", True, "warning", "DYLD env vars allowed", "High risk; avoid unless required for dev tooling."),
]

def check(fp: Path):
    try:
        with fp.open("rb") as fh:
            pl = plistlib.load(fh)
    except Exception:
        return []
    if not isinstance(pl, dict):
        return []
    res = []
    for key, val, sev, title, detail in SUSPICIOUS:
        if pl.get(key) == val:
            res.append((sev, str(fp), title, f"{key}={val}; {detail}"))
    return res

acc = []
for dp, _, files in os.walk(root):
    for n in files:
        if n.endswith(".entitlements"):
            acc.extend(check(Path(dp) / n))

for sev, fp, title, detail in acc:
    print(f"{sev}\t{fp}\t{title}\t{detail}")
PY
)
    if [[ -n "$out" ]]; then
      while IFS=$'\t' read -r sev file title detail; do
        print_finding "$sev" 1 "$title [$file]" "$detail"
      done <<<"$out"
    else
  print_finding "good" "No suspicious entitlements detected (heuristic set)"
 fi
}

opt_push_counts(){
 if [[ "${UBS_INCLUDE_OPTIONALS_IN_TOTALS:-0}" -ne 1 ]]; then return 0; fi
 local sev; sev="$(normalize_severity "$1")"
 local cnt="$2"
 case "$sev" in
  critical) CRITICAL_COUNT=$((CRITICAL_COUNT + cnt));;
  warning) WARNING_COUNT=$((WARNING_COUNT + cnt));;
  info) INFO_COUNT=$((INFO_COUNT + cnt));;
 esac
}

run_swiftlint(){
  print_subheader "SwiftLint"
  if command -v swiftlint >/dev/null 2>&1; then
  local tmp; tmp="$(mktemp_file ubs_swiftlint)"
  cleanup_add "$tmp"
    if [[ -d "$PROJECT_DIR" ]]; then
      (cd "$PROJECT_DIR" && with_timeout swiftlint --reporter json --strict >"$tmp" 2>/dev/null || true)
    else
      (cd "$(dirname "$PROJECT_DIR")" && with_timeout swiftlint --reporter json --strict "$(basename "$PROJECT_DIR")" >"$tmp" 2>/dev/null || true)
    fi
    if [[ -s "$tmp" ]] && command -v python3 >/dev/null 2>&1; then
      read -r errs warns files <<<"$(python3 - "$tmp" <<'PY'
import json,sys
try:
  arr=json.load(open(sys.argv[1],'r',encoding='utf-8'))
except: print("0 0 0"); sys.exit(0)
e=w=0; files=set()
for it in arr:
  lvl=(it.get("severity") or "").lower()
  files.add(it.get("file") or "?")
  if lvl in ("error","serious"): e+=1
 elif lvl in ("warning",): w+=1
print(e,w,len(files))
PY
)"
   say " ${WHITE}Files:${RESET} ${CYAN}${files}${RESET} ${RED}errors:${RESET} ${RED}${errs}${RESET} ${YELLOW}warnings:${RESET} ${YELLOW}${warns}${RESET}"
      opt_push_counts warning "$((warns))"
      opt_push_counts critical "$((errs))"
    else
   say " ${GRAY}${INFO} No SwiftLint issues or non-JSON output${RESET}"
    fi
  else
  say " ${GRAY}${INFO} SwiftLint not installed${RESET}"
  fi
}

run_swiftformat(){
  print_subheader "SwiftFormat (lint mode)"
  if command -v swiftformat >/dev/null 2>&1; then
  local tmp; tmp="$(mktemp_file ubs_swiftformat)"
  cleanup_add "$tmp"
    with_timeout swiftformat "$PROJECT_DIR" --lint --quiet >"$tmp" 2>/dev/null || true
    local c; c=$(wc -l <"$tmp" | awk '{print $1+0}')
    if [[ "$c" -gt 0 ]]; then
   say " ${YELLOW}${WARN} SwiftFormat suggestions:${RESET} ${WHITE}${c}${RESET}"
      opt_push_counts info "$c"
    else
   say " ${GREEN}${CHECK} No SwiftFormat findings${RESET}"
    fi
  else
  say " ${GRAY}${INFO} SwiftFormat not installed${RESET}"
  fi
}

run_periphery(){
  print_subheader "Periphery (dead code)"
  if command -v periphery >/dev/null 2>&1; then
  local tmp; tmp="$(mktemp_file ubs_periphery)"
  cleanup_add "$tmp"
    if [[ -d "$PROJECT_DIR" ]]; then
      (cd "$PROJECT_DIR" && with_timeout periphery scan --quiet >"$tmp" 2>/dev/null || true)
    else
   say " ${GRAY}${INFO} Periphery skipped (requires directory scan)${RESET}"
      return 0
    fi
    local unused; unused=$(grep -cE 'unused' "$tmp" 2>/dev/null || echo 0)
    if [[ "$unused" -gt 0 ]]; then
   say " ${YELLOW}${WARN} Periphery unused symbols:${RESET} ${WHITE}${unused}${RESET}"
      opt_push_counts info "$unused"
    else
   say " ${GREEN}${CHECK} No obvious dead code reported${RESET}"
    fi
  else
  say " ${GRAY}${INFO} Periphery not installed${RESET}"
  fi
}

run_xcodebuild_analyze(){
  print_subheader "xcodebuild analyze (Clang static analyzer)"
  local xcw xcp SCHEME=""
 xcw=$(find "$PROJECT_DIR" -maxdepth 6 -name "*.xcworkspace" 2>/dev/null | head -n1 || true)
 xcp=$(find "$PROJECT_DIR" -maxdepth 6 -name "*.xcodeproj" 2>/dev/null | head -n1 || true)
  local sdkflag=""
  case "$SDK_KIND" in
    ios) sdkflag="-sdk iphonesimulator" ;;
    macos) sdkflag="-sdk macosx" ;;
    tvos) sdkflag="-sdk appletvsimulator" ;;
    watchos) sdkflag="-sdk watchsimulator" ;;
  esac
  if command -v xcodebuild >/dev/null 2>&1; then
    if [[ -n "$xcw" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        SCHEME=$(xcodebuild -list -json -workspace "$xcw" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); s=(d.get("workspace",{}) or {}).get("schemes") or []; print(s[0] if s else "")' 2>/dev/null)
      fi
      [[ -z "$SCHEME" ]] && SCHEME="$(basename "$xcw" .xcworkspace)"
   local tmp; tmp="$(mktemp_file ubs_xc_analyze)"
   cleanup_add "$tmp"
      with_timeout xcodebuild -workspace "$xcw" -scheme "$SCHEME" analyze $sdkflag >"$tmp" 2>&1 || true
   local w e; w=$(grep -c "warning:" "$tmp" 2>/dev/null || true); e=$(grep -c "error:" "$tmp" 2>/dev/null || true)
      if [[ "$w" -gt 0 || "$e" -gt 0 ]]; then
    say " ${YELLOW}${WARN} Analyzer:${RESET} ${WHITE}${w}${RESET} warnings, ${RED}${e}${RESET} errors"
        opt_push_counts warning "$w"; opt_push_counts critical "$e"
      else
    say " ${GREEN}${CHECK} No analyzer issues surfaced${RESET}"
      fi
    elif [[ -n "$xcp" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        SCHEME=$(xcodebuild -list -json -project "$xcp" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); s=(d.get("project",{}) or {}).get("schemes") or []; print(s[0] if s else "")' 2>/dev/null)
      fi
      [[ -z "$SCHEME" ]] && SCHEME="$(basename "$xcp" .xcodeproj)"
   local tmp; tmp="$(mktemp_file ubs_xc_analyze)"
   cleanup_add "$tmp"
      with_timeout xcodebuild -project "$xcp" -scheme "$SCHEME" analyze $sdkflag >"$tmp" 2>&1 || true
   local w e; w=$(grep -c "warning:" "$tmp" 2>/dev/null || true); e=$(grep -c "error:" "$tmp" 2>/dev/null || true)
      if [[ "$w" -gt 0 || "$e" -gt 0 ]]; then
    say " ${YELLOW}${WARN} Analyzer:${RESET} ${WHITE}${w}${RESET} warnings, ${RED}${e}${RESET} errors"
        opt_push_counts warning "$w"; opt_push_counts critical "$e"
      else
    say " ${GREEN}${CHECK} No analyzer issues surfaced${RESET}"
      fi
    else
   say " ${GRAY}${INFO} No Xcode project/workspace found for analyze${RESET}"
    fi
  else
  say " ${GRAY}${INFO} xcodebuild not available${RESET}"
  fi
}

should_run_category(){
  local cat="$1"; cat="${cat//[[:space:]]/}"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local allowed=1
    IFS=',' read -r -a arr <<<"$(echo "$ONLY_CATEGORIES" | tr -d ' ')"
  local s
    for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && allowed=0; done
    [[ $allowed -eq 1 ]] && return 1
  fi
  if [[ -n "$CATEGORY_WHITELIST" ]]; then
    local allowed=1
    IFS=',' read -r -a allow <<<"$CATEGORY_WHITELIST"
  local s
    for s in "${allow[@]}"; do [[ "$s" == "$cat" ]] && allowed=0; done
    [[ $allowed -eq 1 ]] && return 1
  fi
 if [[ -n "$SKIP_CATEGORIES" ]]; then
  IFS=',' read -r -a arr <<<"$(echo "$SKIP_CATEGORIES" | tr -d ' ')"
  local s
  for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
 fi
  return 0
}

if [[ ! -e "$PROJECT_DIR" ]]; then
  echo -e "${RED}${BOLD}Project path not found:${RESET} ${WHITE}$PROJECT_DIR${RESET}" >&2
  exit 2
fi

resolve_timeout || true

EX_PRUNE=()
for d in "${EXCLUDE_DIRS[@]}"; do EX_PRUNE+=( -path "*/$d" -prune -o ); done
NAME_EXPR=( \( )
first=1
for e in "${_EXT_ARR[@]}"; do
 e="$(echo "$e" | xargs)"; [[ -n "$e" ]] || continue
  if [[ $first -eq 1 ]]; then NAME_EXPR+=( -name "*.${e}" ); first=0
  else NAME_EXPR+=( -o -name "*.${e}" ); fi
done
NAME_EXPR+=( \) )

if [[ "$HAS_RIPGREP" -eq 1 ]]; then
  TOTAL_FILES=$(
  ( rg --files "$PROJECT_DIR" --hidden "${RG_EXTRA_FLAGS[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}" 2>/dev/null || true ) \
   | wc -l | awk '{print $1+0}'
 )
 SWIFT_FILE_COUNT=$(
  ( rg --files "$PROJECT_DIR" --hidden "${RG_EXTRA_FLAGS[@]}" "${RG_EXCLUDES[@]}" "${RG_MAX_SIZE_FLAGS[@]}" -g '*.swift' 2>/dev/null || true ) \
    | wc -l | awk '{print $1+0}'
  )
else
  TOTAL_FILES=$(
  ( find "$PROJECT_DIR" \( "${EX_PRUNE[@]}" -false \) -o \( -type f "${NAME_EXPR[@]}" -print \) 2>/dev/null || true ) \
    | wc -l | awk '{print $1+0}'
  )
  SWIFT_FILE_COUNT=$(
  ( find "$PROJECT_DIR" \( "${EX_PRUNE[@]}" -false \) -o \( -type f -name '*.swift' -print \) 2>/dev/null || true ) \
    | wc -l | awk '{print $1+0}'
  )
fi
[[ "$SWIFT_FILE_COUNT" -gt 0 ]] && HAS_SWIFT_FILES=1 || HAS_SWIFT_FILES=0

# MACHINE-READABLE MODE: emit ONLY json/sarif to stdout and exit.
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
 QUIET=1; NO_COLOR_FLAG=1; init_colors
 check_ast_grep || die "ast-grep is required for --format=$FORMAT"
  write_ast_rules || true

 tmp_out="$(mktemp_file ubs_ast_out)"
 cleanup_add "$tmp_out"
 cfg_file="$(mktemp_file ubs_sgconfig)"
 cleanup_add "$cfg_file"
 printf 'ruleDirs:\n- %s\n' "$AST_RULE_DIR" >"$cfg_file" 2>/dev/null || true
  if [[ "$FORMAT" == "json" ]]; then
  with_timeout "${AST_GREP_CMD[@]}" scan -c "$cfg_file" "$PROJECT_DIR" --json >"$tmp_out" 2>/dev/null || true
  cat "$tmp_out"
  if command -v python3 >/dev/null 2>&1; then
   read -r CRITICAL_COUNT WARNING_COUNT INFO_COUNT <<<"$(python3 - "$tmp_out" <<'PY'
import json,sys
try:
 data=json.load(open(sys.argv[1],'r',encoding='utf-8'))
except Exception:
 print("0 0 0"); sys.exit(0)
c=w=i=0
for o in data if isinstance(data,list) else []:
 sev=(o.get('severity') or o.get('level') or 'info').lower()
 if sev in ('error','critical','fatal','high','serious'): c+=1
 elif sev in ('warning','warn','medium'): w+=1
    else: i+=1
print(c,w,i)
PY
    )"
  fi
  else
  with_timeout "${AST_GREP_CMD[@]}" scan -c "$cfg_file" "$PROJECT_DIR" --format sarif >"$tmp_out" 2>/dev/null || true
    cat "$tmp_out"
  if command -v python3 >/dev/null 2>&1; then
   read -r CRITICAL_COUNT WARNING_COUNT INFO_COUNT <<<"$(python3 - "$tmp_out" <<'PY'
import json,sys
try:
  sar=json.load(open(sys.argv[1],'r',encoding='utf-8'))
except Exception:
 print("0 0 0"); sys.exit(0)
levels=[]
for r in sar.get("runs") or []:
  for res in (r.get("results") or []):
    levels.append(((res.get("level") or "note").lower()))
crit=sum(1 for x in levels if x in ("error","critical"))
warn=sum(1 for x in levels if x in ("warning"))
info=len(levels)-crit-warn
print(crit, warn, info)
PY
    )"
  fi
 fi

  if [[ -n "$SUMMARY_JSON" ]]; then
    {
   printf '{'
   printf '"version":"%s",' "$(json_escape "$VERSION")"
   printf '"project":"%s",' "$(json_escape "$PROJECT_DIR")"
   printf '"files":%s,' "$TOTAL_FILES"
   printf '"critical":%s,' "${CRITICAL_COUNT:-0}"
   printf '"warning":%s,' "${WARNING_COUNT:-0}"
   printf '"info":%s,' "${INFO_COUNT:-0}"
   printf '"timestamp":"%s",' "$(eval "$DATE_CMD")"
   printf '"format":"%s",' "$(json_escape "$FORMAT")"
   printf '"sdk":"%s"' "$(json_escape "$SDK_KIND")"
   printf '}\n'
    } > "$SUMMARY_JSON" 2>/dev/null || true
  fi

  EXIT_CODE=0
 [[ "${CRITICAL_COUNT:-0}" -gt 0 ]] && EXIT_CODE=1
 [[ "$FAIL_ON_WARNING" -eq 1 && $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]] && EXIT_CODE=1
  exit "$EXIT_CODE"
fi

maybe_clear

echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║ ██╗ ██╗██╗ ████████╗██╗███╗ ███╗ █████╗ ████████╗███████╗ ║
║ ██║ ██║██║ ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝ ║
║ ██║ ██║██║ ██║ ██║██╔████╔██║███████║ ██║ █████╗ ║
║ ██╔══██╗██║ ██║ ██║██║╚██╔╝██║██╔══██║ ██║ ██╔══╝ ║
║ ╚██████╔╝███████╗██║ ██║██║ ╚═╝ ██║██║ ██║ ██║ ███████╗ ║
║ ╚═════╝ ╚══════╝╚═╝ ╚═╝╚═╝ ╚═╝╚═╝ ╚═╝ ╚═╝ ╚══════╝ ║
║ ===========::===== ║
║ ██████╗ ██╗ ██╗ ██████╗ ===-:=:===== .==== ║
║ ██╔══██╗██║ ██║██╔════╝ =====.::.=++ .=== ║
║ ██████╔╝██║ ██║██║ ███╗ ==++++= : .=== ║
║ ██╔══██╗██║ ██║██║ ██║ ==++++++=. .=== ║
║ ██████╔╝╚██████╔╝╚██████╔╝ ++=. ::: :++ ║
║ ╚═════╝ ╚═════╝ ╚═════╝ +++++-.. .-++:=+ ║
║ ****************** ║
║ ║
║ ███████╗ ██████╗ █████╗ ███╗ ██╗███╗ ██╗███████╗██████╗ ║
║ ██╔════╝ ██╔═══╝ ██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗ ║
║ ███████╗ ██║ ███████║██╔██╗ ██║██╔██╗ ██║█████╗ ██████╔╝ ║
║ ╚════██║ ██║ ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝ ██╔══██╗ ║
║ ███████║ ██████╗ ██║ ██║██║ ╚████║██║ ╚████║███████╗██║ ██║ ║
║ ╚══════╝ ╚═════╝ ╚═╝╚═╝ ╚═══╝╚═╝ ╚═══╝╚══════╝╚═╝ ╚═╝ ║
║ ║
║ Swift module • optionals, concurrency, URLSession, Combine ║
║ UBS module: swift • catches force ops & async lifecycle ║
║ ASCII homage: swift bird ║
║ ║
║ ║
║ Night Owl QA ║
║ “We see bugs before you do.” ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

say "${WHITE}Version:${RESET} ${CYAN}${VERSION}${RESET}"
say "${WHITE}Project:${RESET} ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET} ${GRAY}$(eval "$DATE_CMD")${RESET}"
say "${WHITE}Files:${RESET} ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"
if [[ "$HAS_RIPGREP" -eq 1 ]]; then
 say "${WHITE}Ripgrep:${RESET} ${CYAN}enabled${RESET} ${DIM}(pcre2=${RG_PCRE2_OK}, respect-ignore=${RESPECT_IGNORE}, no-ignore=${NO_IGNORE_ALL})${RESET}"
else
 say "${WHITE}Ripgrep:${RESET} ${CYAN}disabled${RESET}"
fi

echo ""
if check_ast_grep; then
 say "${GREEN}${CHECK} ast-grep available (${AST_GREP_CMD[*]}) - full AST analysis enabled${RESET}"
 write_ast_rules || true
else
 say "${YELLOW}${WARN} ast-grep unavailable - using regex fallback mode${RESET}"
fi

begin_scan_section

# CATEGORY 1
if should_run_category 1; then
set_category 1
print_header "1. OPTIONALS / FORCE OPERATIONS"
 print_category "Detects: force unwrap (!), try!, as!, IUO declarations, URL(string:)!" \
  "Avoid crashes by binding optionals and using safe casts/errors."
tick

print_subheader "Force unwrap (!) occurrences"
 count=$("${GREP_RN[@]}" -e '!([[:space:]]|\.|\(|\)|\[|\]|\{|\}|,|;|:|\?|$)' "$PROJECT_DIR" 2>/dev/null | grep "\.swift:" | count_lines || true)
 if [[ "${count:-0}" -gt 30 ]]; then
  print_finding "warning" "$count" "Heavy use of force unwrap"
  show_detailed_finding '!([[:space:]]|\.|\(|\)|\[|\]|\{|\}|,|;|:|\?|$)' 5
 elif [[ "${count:-0}" -gt 0 ]]; then
  print_finding "info" "$count" "Some force unwraps present"
 else
  print_finding "good" "No obvious force unwraps detected by heuristic"
fi
tick

print_subheader "try! and as! occurrences"
trybang=$("${GREP_RN[@]}" -e "\\btry\\!" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
asbang=$("${GREP_RN[@]}" -e "\\bas\\![[:space:]]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${trybang:-0}" -gt 0 ]]; then print_finding "critical" "$trybang" "try! used"; show_detailed_finding "\\btry!" 5; else print_finding "good" "No try!"; fi
 if [[ "${asbang:-0}" -gt 0 ]]; then print_finding "warning" "$asbang" "as! used"; show_detailed_finding "\\bas![[:space:]]" 5; else print_finding "good" "No as!"; fi
tick

print_subheader "Implicitly unwrapped optionals (T!)"
iuo=$("${GREP_RN[@]}" -e "(:|->)[[:space:]]*[A-Za-z_][A-Za-z0-9_<>?:\\.\\[\\] ]*!\\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${iuo:-0}" -gt 0 ]]; then print_finding "warning" "$iuo" "Implicitly unwrapped optionals"; show_detailed_finding "(:|->)[[:space:]]*[A-Za-z_][A-Za-z0-9_<>?:\\.\\[\\] ]*!\\b" 5; else print_finding "good" "No IUO types"; fi
 tick

 print_subheader "URL(string:) force unwrap (URL(...)!)"
 urlbang=$("${GREP_RN[@]}" -e "URL\\(string:[^\\)]*\\)!\\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${urlbang:-0}" -gt 0 ]]; then print_finding "warning" "$urlbang" "URL(string:) force-unwrapped"; show_detailed_finding "URL\\(string:[^\\)]*\\)!\\b" 5; else print_finding "good" "No URL(string:) force unwraps detected"; fi
tick

run_swift_type_narrowing_checks
tick
fi

# CATEGORY 2
if should_run_category 2; then
set_category 2
print_header "2. CONCURRENCY / TASK"
 print_category "Detects: Task launches, detached tasks, unsafe continuations, Sendable footguns" \
  "Structured concurrency avoids leaks and deadlocks."
tick

task_count=$("${GREP_RNW[@]}" "Task" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
async_count=$("${GREP_RN[@]}" -e "\\basync[[:space:]]+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
await_count=$("${GREP_RNW[@]}" "await" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
print_finding "info" "$task_count" "Task usages"
 if [[ "${async_count:-0}" -gt "${await_count:-0}" ]]; then
  diff=$((async_count - await_count)); [[ "$diff" -lt 0 ]] && diff=0
  print_finding "info" "$diff" "Possible un-awaited async paths"
fi
tick

 print_subheader "@unchecked Sendable / nonisolated(unsafe)"
 unchecked=$("${GREP_RN[@]}" -e "@unchecked[[:space:]]+Sendable|nonisolated\\(unsafe\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${unchecked:-0}" -gt 0 ]]; then
  print_finding "warning" "$unchecked" "Concurrency escape hatches used" "Review for thread-safety and actor isolation correctness"
  show_detailed_finding "@unchecked[[:space:]]+Sendable|nonisolated\\(unsafe\\)" 5
 else
  print_finding "good" "No @unchecked Sendable / nonisolated(unsafe) detected"
 fi
 tick

run_async_error_checks
fi

# CATEGORY 3
if should_run_category 3; then
set_category 3
print_header "3. CLOSURES / CAPTURE LISTS"
print_category "Detects: strong self in long-lived closures, unowned self hazards" \
  "Use [weak self] where closures outlive self; prefer guard let self."
tick

 print_subheader "Long-lived closures without [weak self] (heuristic)"
 count=$("${GREP_RN[@]}" -e "(URLSession\\.|DispatchQueue\\.(global|main)|Timer\\.scheduledTimer|NotificationCenter\\.default\\.addObserver|UIView\\.animate|NSAnimationContext\\.runAnimationGroup|\\.sink\\(|\\.onReceive\\()" "$PROJECT_DIR" 2>/dev/null \
  | (grep -A3 -E "\\{[[:space:]]*(\\[[^]]*\\])?" || true) \
  | (grep -vi "\\[weak self\\]" || true) \
  | count_lines || true
  )
 if [[ "${count:-0}" -gt 0 ]]; then
  print_finding "warning" "$count" "Potential strong self captures in long-lived closures" "Consider capture list [weak self] where appropriate"
 else
  print_finding "good" "No obvious long-lived closure sites lacking [weak self] by heuristic"
 fi
 tick

 print_subheader "[unowned self] captures"
 count=$("${GREP_RN[@]}" -e "\\[[^\\]]*unowned[[:space:]]+self[^\\]]*\\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then
  print_finding "warning" "$count" "[unowned self] in closures" "Unowned capture can crash if self deallocates; prefer weak + guard"
  show_detailed_finding "\\[[^\\]]*unowned[[:space:]]+self[^\\]]*\\]" 5
 else
  print_finding "good" "No [unowned self] captures detected"
 fi
fi

# CATEGORY 4
if should_run_category 4; then
set_category 4
print_header "4. URLSESSION / NETWORKING"
 print_category "Detects: URLSession tasks, http literals, Data(contentsOf:), insecure trust handlers, manual URL queries" \
  "Networking bugs cause hangs, security issues, and battery drain."
tick

 print_subheader "URLSession task creation sites (review resume/cancel)"
 count=$("${GREP_RN[@]}" -e "\\.(dataTask|uploadTask|downloadTask)\\s*\\(" "$PROJECT_DIR" 2>/dev/null | awk -F: '{print $1":"$2}' | sort -u | wc -l | awk '{print $1+0}' || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "URLSession tasks created"; else print_finding "good" "No URLSession task creation detected"; fi
 tick

 run_urlsession_task_correlation
tick

print_subheader "http:// literals"
count=$("${GREP_RN[@]}" -e "\"http://[^\"]+\"" "$PROJECT_DIR" 2>/dev/null | grep -v "http://www.apple.com/DTDs" | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "http:// URLs"; show_detailed_finding "\"http://[^\"]+\"" 5; else print_finding "good" "No http:// literals"; fi
tick

print_subheader "Blocking Data(contentsOf:)"
count=$("${GREP_RN[@]}" -e "Data\\(contentsOf:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Data(contentsOf:) usage may block"; show_detailed_finding "Data\\(contentsOf:" 5; else print_finding "good" "No Data(contentsOf:) usage detected"; fi
 tick

 print_subheader "Manual query string building (prefer URLComponents)"
 count=$("${GREP_RN[@]}" -e "URL\\(string:\\s*\"https?://[^\"\\?]+\\?[^\"\\)]*\"\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Manual URL query strings"; show_detailed_finding "URL\\(string:\\s*\"https?://[^\"\\?]+\\?[^\"\\)]*\"\\)" 5; else print_finding "good" "No obvious manual query URLs detected"; fi
fi

# CATEGORY 5
if should_run_category 5; then
set_category 5
print_header "5. ERROR HANDLING"
 print_category "Detects: empty catches, try? discards, fatalError misuse" \
  "Handle errors or propagate with throws."
tick

 print_subheader "Empty catch blocks"
count=$("${GREP_RN[@]}" -e "catch[[:space:]]*\\{[[:space:]]*\\}" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Empty catch blocks"; show_detailed_finding "catch[[:space:]]*\\{[[:space:]]*\\}" 5; else print_finding "good" "No empty catch blocks"; fi
tick

print_subheader "try? discarding errors"
count=$("${GREP_RN[@]}" -e "try\\?[[:space:]]*[A-Za-z_\\(]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 30 ]]; then print_finding "info" "$count" "Many try? sites - verify error handling strategy"; else print_finding "good" "try? usage not excessive by heuristic"; fi
tick

print_subheader "fatalError/preconditionFailure presence"
count=$("${GREP_RN[@]}" -e "fatalError\\(|preconditionFailure\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Crash sites"; show_detailed_finding "fatalError\\(|preconditionFailure\\(" 5; else print_finding "good" "No fatalError/preconditionFailure detected"; fi
fi

# CATEGORY 6
if should_run_category 6; then
set_category 6
print_header "6. SECURITY"
 print_category "Detects: trust-all URLSession delegate, hardcoded secrets, insecure unarchiving, Process misuse" \
  "Security bugs expose users and violate policies."
tick

print_subheader "Trust-all server trust delegates"
 count=$("${GREP_RN[@]}" -e "didReceiveChallenge\\(.*URLAuthenticationChallenge.*\\)" "$PROJECT_DIR" 2>/dev/null | (grep -E "useCredential|URLCredential\\(trust:" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "critical" "$count" "URLSession delegate accepts any trust"; show_detailed_finding "didReceiveChallenge\\(.*URLAuthenticationChallenge.*\\)" 5; else print_finding "good" "No obvious trust-all delegate patterns"; fi
tick

print_subheader "Hardcoded secrets"
count=$("${GREP_RNI[@]}" -e "(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*\"[^\"]+\"" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "critical" "$count" "Hardcoded secret lookalikes"; show_detailed_finding "(password|api_?key|secret|token)[[:space:]]*[:=][[:space:]]*\"[^\"]+\"" 5; else print_finding "good" "No obvious hardcoded secrets"; fi
 tick

 print_subheader "Insecure unarchiving (NSKeyedUnarchiver)"
 count=$("${GREP_RN[@]}" -e "NSKeyedUnarchiver\\.unarchiveObject\\(with:|unarchiveTopLevelObjectWithData\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Potentially unsafe deserialization"; show_detailed_finding "NSKeyedUnarchiver\\.unarchiveObject\\(with:|unarchiveTopLevelObjectWithData\\(" 5; else print_finding "good" "No obvious insecure unarchiving"; fi
tick

print_subheader "Process/posix shell usage"
count=$("${GREP_RN[@]}" -e "Process\\(|posix_spawn|system\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Shell/process invocation present - validate inputs"; show_detailed_finding "Process\\(|posix_spawn|system\\(" 5; else print_finding "good" "No Process/system invocations detected"; fi
fi

# CATEGORY 7
if should_run_category 7; then
set_category 7
print_header "7. CRYPTO / HASHING"
 print_category "Detects: weak algorithms via CommonCrypto & CryptoKit Insecure.*, ECB mode flags, rand()" \
  "Prefer SHA-256/512 and authenticated encryption."
tick

print_subheader "CommonCrypto MD5/SHA1"
count=$("${GREP_RN[@]}" -e "CC_MD5|CC_SHA1" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Weak hashing use"; show_detailed_finding "CC_MD5|CC_SHA1" 5; else print_finding "good" "No CommonCrypto MD5/SHA1"; fi
tick

print_subheader "CryptoKit Insecure.*"
count=$("${GREP_RN[@]}" -e "Insecure\\.SHA1|Insecure\\.MD5" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "CryptoKit Insecure algorithms"; show_detailed_finding "Insecure\\.SHA1|Insecure\\.MD5" 5; else print_finding "good" "No CryptoKit Insecure algorithms"; fi
 tick

 print_subheader "ECB mode flags (CommonCrypto)"
 count=$("${GREP_RN[@]}" -e "kCCOptionECBMode" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "ECB mode used"; show_detailed_finding "kCCOptionECBMode" 5; else print_finding "good" "No ECB mode flags"; fi
fi

# CATEGORY 8
if should_run_category 8; then
set_category 8
print_header "8. FILES & I/O"
print_category "Detects: FileHandle leaks, blocking reads, path string concat" \
  "Use URL and ensure closing handles."
tick

print_subheader "FileHandle open without close in file"
 count=$("${GREP_RN[@]}" -e "FileHandle\\s*\\(\\s*for(Reading|Writing|Updating)(From|To|AtPath)\\s*:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 closecount=$("${GREP_RN[@]}" -e "\\.close\\s*\\(\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 && "${closecount:-0}" -lt "${count:-0}" ]]; then
  diff=$((count - closecount)); [[ "$diff" -lt 0 ]] && diff=0
  print_finding "warning" "$diff" "FileHandle open without matching close"
 else
  print_finding "good" "No FileHandle close imbalance by heuristic"
fi
tick

 print_subheader "String(contentsOf:) usage"
 count=$("${GREP_RN[@]}" -e "String\\(contentsOf:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "String(contentsOf:) may block"; show_detailed_finding "String\\(contentsOf:" 5; else print_finding "good" "No String(contentsOf:)"; fi
tick

print_subheader "Path string concatenation"
count=$("${GREP_RN[@]}" -e "\"/\"\\s*\\+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 10 ]]; then print_finding "info" "$count" "String path join - use URL(fileURLWithPath:) or appendingPathComponent"; else print_finding "good" "No significant string path concatenation"; fi
fi

# CATEGORY 9
if should_run_category 9; then
set_category 9
print_header "9. THREADING / MAIN"
 print_category "Detects: sleeps/semaphores on main, missing MainActor hints" \
  "UI work must happen on the main actor."
tick

 print_subheader "UI frameworks used but no @MainActor annotations found (heuristic)"
ui_files=$("${GREP_RN[@]}" -e "UIKit|AppKit|SwiftUI" "$PROJECT_DIR" 2>/dev/null | cut -d: -f1 | sort -u | count_lines || true)
mainactor_annots=$("${GREP_RN[@]}" -e "@MainActor" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${ui_files:-0}" -gt 0 && "${mainactor_annots:-0}" -eq 0 ]]; then
  print_finding "info" "$ui_files" "UI frameworks used but no @MainActor annotations found"
 else
  print_finding "good" "MainActor annotation presence not obviously missing"
fi
tick

print_subheader "sleep/usleep on main queue"
 count=$("${GREP_RN[@]}" -e "DispatchQueue\\.main\\.(async|sync)\\s*\\{[\\s\\S]{0,250}(sleep\\(|usleep\\()" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "sleep on main queue"; show_detailed_finding "DispatchQueue\\.main\\.(async|sync)\\s*\\{[\\s\\S]{0,250}(sleep\\(|usleep\\()" 5; else print_finding "good" "No sleep/usleep on main queue"; fi
 tick

 print_subheader "DispatchQueue.main.sync usage"
 count=$("${GREP_RN[@]}" -e "DispatchQueue\\.main\\.sync\\s*\\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "DispatchQueue.main.sync (deadlock risk)"; show_detailed_finding "DispatchQueue\\.main\\.sync\\s*\\{" 5; else print_finding "good" "No DispatchQueue.main.sync"; fi
fi

# CATEGORY 10
if should_run_category 10; then
set_category 10
print_header "10. PERFORMANCE"
 print_category "Detects: String += in loops, regex compile in loops, formatter churn" \
  "Avoid obvious performance anti-patterns."
tick

 print_subheader "String concatenation in loops (heuristic)"
 count=$("${GREP_RN[@]}" -e 'for[[:space:]]+.+[[:space:]]+in[[:space:]]+.+\{' "$PROJECT_DIR" 2>/dev/null | (grep -A6 "\\+=" || true) | (grep -cE "\\+=" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
 if [[ "${count:-0}" -gt 5 ]]; then print_finding "info" "$count" "String += in loops - consider join/builders"; else print_finding "good" "No obvious string += loop patterns"; fi
tick

 print_subheader "NSRegularExpression init near loops (heuristic)"
 count=$("${GREP_RN[@]}" -e 'for[[:space:]]+.+[[:space:]]+in[[:space:]]+.+\{' "$PROJECT_DIR" 2>/dev/null | (grep -A10 -F "NSRegularExpression(" || true) | (grep -c -F "NSRegularExpression(" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Regex compiled inside/near loop"; else print_finding "good" "No NSRegularExpression-in-loop patterns"; fi
 tick

 print_subheader "DateFormatter/JSONDecoder churn"
 count=$("${GREP_RN[@]}" -e "DateFormatter\\(\\)|JSONDecoder\\(\\)|JSONEncoder\\(\\)|NumberFormatter\\(\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 50 ]]; then print_finding "info" "$count" "Many formatter/encoder/decoder constructions"; else print_finding "good" "No excessive formatter/decoder churn by heuristic"; fi
fi

# CATEGORY 11
if should_run_category 11; then
set_category 11
print_header "11. DEBUG / PRODUCTION"
print_category "Detects: print/NSLog, debug flags, assertions" \
  "Ensure debug artifacts are stripped from release."
tick

print_subheader "print/NSLog occurrences"
count=$("${GREP_RN[@]}" -e "^[[:space:]]*print\\s*\\(|\\bNSLog\\s*\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 50 ]]; then print_finding "warning" "$count" "Many print/NSLog calls"
 elif [[ "${count:-0}" -gt 10 ]]; then print_finding "info" "$count" "print/NSLog present"
 else print_finding "good" "Minimal print/NSLog"; fi
 tick

 print_subheader "#if DEBUG blocks"
 count=$("${GREP_RN[@]}" -e "#if[[:space:]]+DEBUG" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "#if DEBUG present"; else print_finding "good" "No #if DEBUG blocks detected"; fi
tick

print_subheader "assert(false) or assertionFailure()"
count=$("${GREP_RN[@]}" -e "assert\\(false\\)|assertionFailure\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Assertions that always fail"; show_detailed_finding "assert\\(false\\)|assertionFailure\\(" 5; else print_finding "good" "No always-failing assertions detected"; fi
fi

# CATEGORY 12
if should_run_category 12; then
set_category 12
print_header "12. REGEX"
 print_category "Detects: nested quantifiers (ReDoS), untrusted predicate formats" \
  "Regex bugs cause performance issues."
tick

print_subheader "Nested quantifiers (potential catastrophic backtracking)"
count=$("${GREP_RN[@]}" -e "NSRegularExpression\\(pattern:[^)]*(\\+\\+|\\*\\+|\\+\\*|\\*\\*)[^)]*\\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 1 ]]; then print_finding "warning" "$count" "Potential catastrophic regex"; show_detailed_finding "NSRegularExpression\\(pattern:[^)]*(\\+\\+|\\*\\+|\\+\\*|\\*\\*)[^)]*\\)" 5; else print_finding "good" "No obvious nested-quantifier patterns"; fi
 tick

 print_subheader "NSPredicate(format:) usage"
 count=$("${GREP_RN[@]}" -e "NSPredicate\\(format:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "NSPredicate(format:) used"; show_detailed_finding "NSPredicate\\(format:" 5; else print_finding "good" "No NSPredicate(format:) usage detected"; fi
fi

# CATEGORY 13
if should_run_category 13; then
set_category 13
print_header "13. SWIFTUI / COMBINE"
 print_category "Detects: sink without store, .onReceive patterns, subscription lifetimes" \
  "State management must retain subscriptions and avoid cycles."
tick

 print_subheader "Combine .sink without obvious .store(in:) nearby (heuristic)"
 count=$("${GREP_RN[@]}" -e "\\.sink\\(" "$PROJECT_DIR" 2>/dev/null | (grep -vF ".store(in:" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Combine sinks not stored"; show_detailed_finding "\\.sink\\(" 5; else print_finding "good" "No obvious unstored sink calls"; fi
 tick

 print_subheader "SwiftUI onReceive usage"
 count=$("${GREP_RN[@]}" -e "\\.onReceive\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "SwiftUI .onReceive present"; show_detailed_finding "\\.onReceive\\(" 5; else print_finding "good" "No .onReceive usage detected"; fi
fi

# CATEGORY 14
if should_run_category 14; then
set_category 14
print_header "14. MEMORY / RETAIN"
 print_category "Detects: retain cycles via Timer/Notification/closures, resource teardown" \
  "Break cycles with weak references or invalidation."
tick

 print_subheader "Timer scheduled (review invalidation & capture lists)"
 count=$("${GREP_RN[@]}" -e "Timer\\.scheduledTimer" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Timers scheduled"; show_detailed_finding "Timer\\.scheduledTimer" 5; else print_finding "good" "No Timer.scheduledTimer usage"; fi
 tick

 print_subheader "NotificationCenter block-based observers"
 count=$("${GREP_RN[@]}" -e "addObserver\\(forName:" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Block-based observer sites"; show_detailed_finding "addObserver\\(forName:" 5; else print_finding "good" "No block-based NotificationCenter observers"; fi
 tick

 print_subheader "CADisplayLink created (ensure invalidate)"
 count=$("${GREP_RN[@]}" -e "CADisplayLink\\s*\\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "CADisplayLink created"; show_detailed_finding "CADisplayLink\\s*\\(" 5; else print_finding "good" "No CADisplayLink usage detected"; fi
fi

# CATEGORY 15
if should_run_category 15; then
set_category 15
print_header "15. CODE QUALITY MARKERS"
 print_category "Detects: TODO, FIXME, HACK, XXX" \
  "Technical debt markers indicate work remaining."
tick

todo=$("${GREP_RNI[@]}" "TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
fixme=$("${GREP_RNI[@]}" "FIXME" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
hack=$("${GREP_RNI[@]}" "HACK" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
xxx=$("${GREP_RNI[@]}" "XXX" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((todo + fixme + hack + xxx))
 if [[ "${total:-0}" -gt 20 ]]; then print_finding "warning" "$total" "Significant technical debt"
 elif [[ "${total:-0}" -gt 10 ]]; then print_finding "info" "$total" "Moderate technical debt"
 elif [[ "${total:-0}" -gt 0 ]]; then print_finding "info" "$total" "Minimal technical debt"
else print_finding "good" "No technical debt markers"; fi
fi

# CATEGORY 16
if should_run_category 16; then
set_category 16
print_header "16. RESOURCE LIFECYCLE"
 print_category "Detects: Timer/URLSessionTask/Notification tokens/FileHandle/Combine/DispatchSource/CADisplayLink/KVO cleanups" \
  "Unreleased resources leak memory, file descriptors, or tasks."
tick
run_resource_lifecycle_checks
fi

# CATEGORY 17
if should_run_category 17; then
set_category 17
print_header "17. INFO.PLIST / ATS"
print_category "Detects: NSAppTransportSecurity exceptions, arbitrary loads" \
  "ATS exceptions require justification; avoid blanket disables."
tick

run_plist_checks

 print_subheader "ATS allows arbitrary loads (regex heuristic)"
 count=$("${GREP_RN[@]}" -e "NSAppTransportSecurity|NSAllowsArbitraryLoads" "$PROJECT_DIR" 2>/dev/null | (grep -E "true|YES" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "ATS arbitrary loads enabled"; else print_finding "good" "No obvious ATS arbitrary-loads strings"; fi
tick

print_subheader "NSAllowsArbitraryLoadsInWebContent"
 count=$("${GREP_RN[@]}" -e "NSAllowsArbitraryLoadsInWebContent" "$PROJECT_DIR" 2>/dev/null | (grep -E "true|YES" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Arbitrary loads in web content enabled"; else print_finding "good" "No NSAllowsArbitraryLoadsInWebContent=true found"; fi
fi

# CATEGORY 18
if should_run_category 18; then
set_category 18
print_header "18. DEPRECATED APIs"
 print_category "Detects: UIWebView/NSURLConnection, deprecated status bar APIs, keyWindow" \
  "Remove deprecated APIs before submission."
tick

print_subheader "UIWebView/NSURLConnection"
count=$("${GREP_RN[@]}" -e "UIWebView|NSURLConnection" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "warning" "$count" "Deprecated networking/webview APIs"; show_detailed_finding "UIWebView|NSURLConnection" 5; else print_finding "good" "No UIWebView/NSURLConnection detected"; fi
 tick

 print_subheader "Deprecated status bar APIs / keyWindow"
 count=$("${GREP_RN[@]}" -e "statusBarFrame|setStatusBarHidden|UIApplication\\.shared\\.keyWindow" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Deprecated UIKit status bar/keyWindow APIs"; show_detailed_finding "statusBarFrame|setStatusBarHidden|UIApplication\\.shared\\.keyWindow" 5; else print_finding "good" "No obvious deprecated status bar/keyWindow usage"; fi
fi

# CATEGORY 19
if should_run_category 19; then
set_category 19
print_header "19. BUILD / SIGNING"
 print_category "Detects: entitlements anomalies, debug signing in release" \
  "Ensure secure build settings."
tick

 run_entitlements_checks
tick

print_subheader "Debug signing identifiers in Release configs (heuristic)"
 count=$("${GREP_RN[@]}" -e "PROVISIONING_PROFILE_SPECIFIER|CODE_SIGN_IDENTITY" "$PROJECT_DIR" 2>/dev/null | (grep -i "debug" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Debug-like signing strings detected"; else print_finding "good" "No obvious debug signing strings"; fi
fi

# CATEGORY 20
if should_run_category 20; then
set_category 20
print_header "20. PACKAGING / SPM"
 print_category "Detects: unpinned SPM deps, branch deps, local paths, unsafeFlags" \
  "Pin dependencies for reproducibility."
tick

 print_subheader "Package.swift branch/revision/unsafeFlags"
 if [[ -f "$PROJECT_DIR/Package.swift" ]]; then
  count=$(grep -nE '\.branch\(|\.revision\(' "$PROJECT_DIR/Package.swift" 2>/dev/null | count_lines || true)
  [[ "${count:-0}" -gt 0 ]] && print_finding "info" "$count" "Branch/revision-based SPM dependencies" || print_finding "good" "No branch/revision SPM pins detected"
  count=$(grep -nE '\.unsafeFlags\(' "$PROJECT_DIR/Package.swift" 2>/dev/null | count_lines || true)
  [[ "${count:-0}" -gt 0 ]] && print_finding "warning" "$count" "SPM unsafeFlags used" || print_finding "good" "No SPM unsafeFlags detected"
 else
  print_finding "info" 0 "Package.swift not found" "Skipping SPM checks"
 fi
fi

# CATEGORY 21
if should_run_category 21; then
set_category 21
print_header "21. UI/UX SAFETY"
 print_category "Detects: IUO IBOutlets, large storyboards" \
  "Prefer safe IBOutlets and modular storyboards."
tick

print_subheader "IBOutlet IUO (T!)"
count=$("${GREP_RN[@]}" -e "@IBOutlet[[:space:]]+weak[[:space:]]+var[[:space:]]+[A-Za-z_][A-Za-z0-9_]*:[^!]*!" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "@IBOutlet implicitly unwrapped"; show_detailed_finding "@IBOutlet[[:space:]]+weak[[:space:]]+var[[:space:]]+[A-Za-z_][A-Za-z0-9_]*:[^!]*!" 5; else print_finding "good" "No IUO IBOutlets detected"; fi
tick

 print_subheader "Many storyboards (heuristic)"
count=$(( $(find "$PROJECT_DIR" -name "*.storyboard" 2>/dev/null | wc -l || echo 0) ))
 if [[ "${count:-0}" -gt 5 ]]; then print_finding "info" "$count" "Many storyboards - consider modularization"; else print_finding "good" "Storyboard count not high"; fi
fi

# CATEGORY 22
if should_run_category 22; then
set_category 22
print_header "22. TESTS / HYGIENE"
 print_category "Detects: XCTFail placeholders, sleeps in tests" \
  "Stable tests avoid sleeps and assert properly."
tick

print_subheader "XCTFail(\"TODO\")"
count=$("${GREP_RN[@]}" -e "XCTFail\\(\"TODO" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Placeholder XCTFail"; show_detailed_finding "XCTFail\\(\"TODO" 5; else print_finding "good" "No placeholder XCTFail(\"TODO\")"; fi
tick

print_subheader "sleep/usleep in tests"
 count=$("${GREP_RN[@]}" -e "XCTestCase|XCT" "$PROJECT_DIR" 2>/dev/null | (grep -A4 -E "sleep\\(|usleep\\(" || true) | (grep -cE "sleep\\(|usleep\\(" || true))
count=$(printf '%s\n' "$count" | awk 'END{print $0+0}')
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Sleep in tests - use expectations"; else print_finding "good" "No sleep/usleep patterns in tests by heuristic"; fi
fi

# CATEGORY 23
if should_run_category 23; then
set_category 23
print_header "23. LOCALIZATION / INTERNATIONALIZATION"
 print_category "Detects: user-facing strings without NSLocalizedString, locale-sensitive formatting risks" \
  "Localize strings and use locale-aware formatters."
tick

print_subheader "Hard-coded user-facing strings (heuristic)"
 count=$("${GREP_RN[@]}" -e "UILabel\\(|setTitle\\(|Text\\(\"" "$PROJECT_DIR" 2>/dev/null | (grep -v "NSLocalizedString" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "Possible user-facing strings without localization"; else print_finding "good" "No obvious unlocalized UI strings"; fi
 tick

 print_subheader "String(format:) without explicit locale (heuristic)"
 count=$("${GREP_RN[@]}" -e "String\\(format:" "$PROJECT_DIR" 2>/dev/null | (grep -v "locale:" || true) | count_lines || true)
 if [[ "${count:-0}" -gt 0 ]]; then print_finding "info" "$count" "String(format:) without explicit locale"; else print_finding "good" "No String(format:) without locale found"; fi
fi

print_header "AST-GREP RULE PACK FINDINGS"
if [[ "$HAS_AST_GREP" -eq 1 && -n "${AST_RULE_DIR:-}" ]]; then
 run_ast_rules || say "${YELLOW}${WARN} ast-grep scan failed/skipped.${RESET}"
else
  say "${YELLOW}${WARN} ast-grep not available; rule pack skipped.${RESET}"
fi

print_header "OPTIONAL ANALYZERS (if installed)"
resolve_timeout || true
run_swiftlint
run_swiftformat
run_periphery
run_xcodebuild_analyze

end_scan_section

echo ""
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
say "${BOLD}${CYAN} 🎯 SCAN COMPLETE 🎯 ${RESET}"
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

say "${WHITE}${BOLD}Summary Statistics:${RESET}"
say " ${WHITE}Files scanned:${RESET} ${CYAN}$TOTAL_FILES${RESET}"
say " ${RED}${BOLD}Critical issues:${RESET} ${RED}$CRITICAL_COUNT${RESET}"
say " ${YELLOW}Warning issues:${RESET} ${YELLOW}$WARNING_COUNT${RESET}"
say " ${BLUE}Info items:${RESET} ${BLUE}$INFO_COUNT${RESET}"
echo ""

if [[ -n "$BASELINE" && -f "$BASELINE" ]]; then
  say "${BOLD}${WHITE}Baseline Comparison:${RESET}"
 if command -v python3 >/dev/null 2>&1; then
  CRITICAL_COUNT="$CRITICAL_COUNT" WARNING_COUNT="$WARNING_COUNT" INFO_COUNT="$INFO_COUNT" python3 - "$BASELINE" <<'PY'
import json,sys,os
try:
  with open(sys.argv[1],'r',encoding='utf-8') as fh:
    b=json.load(fh)
except Exception:
 print(" (could not read baseline)")
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
 print(f" {k.capitalize():<8}: {now:>4} (baseline {prior:>4}) {arrow} {delta:+}")
PY
 else
  say " ${DIM}(python3 not available; baseline compare skipped)${RESET}"
 fi
fi

say "${BOLD}${WHITE}Priority Actions:${RESET}"
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
 say " ${RED}${FIRE} ${BOLD}FIX CRITICAL ISSUES IMMEDIATELY${RESET}"
 say " ${DIM}These cause crashes, security vulnerabilities, or deadlocks${RESET}"
fi
if [[ "$WARNING_COUNT" -gt 0 ]]; then
 say " ${YELLOW}${WARN} ${BOLD}Review and fix WARNING items${RESET}"
 say " ${DIM}These cause bugs, performance issues, or maintenance problems${RESET}"
fi
if [[ "$INFO_COUNT" -gt 0 ]]; then
 say " ${BLUE}${INFO} ${BOLD}Consider INFO suggestions${RESET}"
 say " ${DIM}Code quality improvements and best practices${RESET}"
fi

if [[ -n "$SUMMARY_JSON" ]]; then
  {
    printf '{'
  printf '"version":"%s",' "$(json_escape "$VERSION")"
  printf '"project":"%s",' "$(json_escape "$PROJECT_DIR")"
    printf '"files":%s,' "$TOTAL_FILES"
    printf '"critical":%s,' "$CRITICAL_COUNT"
    printf '"warning":%s,' "$WARNING_COUNT"
    printf '"info":%s,' "$INFO_COUNT"
  printf '"timestamp":"%s",' "$(json_escape "$(eval "$DATE_CMD")")"
  printf '"format":"%s",' "$(json_escape "$FORMAT")"
  printf '"sdk":"%s",' "$(json_escape "$SDK_KIND")"
    printf '"categories":{'
    for i in $(seq 1 23); do
      eval "t=\${CAT${i}:-0}"; eval "c=\${CAT${i}_critical:-0}"; eval "w=\${CAT${i}_warning:-0}"; eval "n=\${CAT${i}_info:-0}"
      printf '"%d":{"total":%s,"critical":%s,"warning":%s,"info":%s}' "$i" "$(num_clamp "$t")" "$(num_clamp "$c")" "$(num_clamp "$w")" "$(num_clamp "$n")"
   [[ $i -lt 23 ]] && printf ','
    done
    printf '},'
  if [[ -n "${AG_STREAM_FILE:-}" && -s "${AG_STREAM_FILE:-}" && "$HAS_AST_GREP" -eq 1 ]]; then
      printf '"ast_grep_rules":['
   if command -v python3 >/dev/null 2>&1; then
    cat "$AG_STREAM_FILE" 2>/dev/null | python3 - <<'PY'
import json,sys,collections
seen=collections.Counter()
for line in sys.stdin:
  line=line.strip()
  if not line: continue
  try:
    rid=(json.loads(line).get('rule_id') or 'unknown')
    seen[rid]+=1
  except:
    pass
print(",".join(json.dumps({"id":k,"count":v}) for k,v in seen.items()))
PY
   else
    awk -F'"' '/"rule_id":/{c[$4]++} END{first=1; for(k in c){ if(!first) printf ","; first=0; printf "{\"id\":%c%s%c,\"count\":%d}",34,k,34,c[k]} }' "$AG_STREAM_FILE" 2>/dev/null || true
   fi
      printf ']'
  else
   printf '"ast_grep_rules":[]'
  fi
    printf '}\n'
  } > "$SUMMARY_JSON" 2>/dev/null || true
  say "${DIM}Summary JSON written to: ${SUMMARY_JSON}${RESET}"
fi

if [[ -n "$REPORT_MD" ]]; then
  {
    echo "# UBS Swift Scan Report"
    echo ""
    echo "- Project: \`$PROJECT_DIR\`"
    echo "- Files: $TOTAL_FILES"
    echo "- Timestamp: $(eval "$DATE_CMD")"
    echo ""
    echo "## Totals"
    echo ""
    echo "| Critical | Warning | Info |"
    echo "|---:|---:|---:|"
    echo "| $CRITICAL_COUNT | $WARNING_COUNT | $INFO_COUNT |"
    echo ""
    echo "## Categories"
    echo ""
    echo "| # | Total | Critical | Warning | Info |"
    echo "|-:|---:|---:|---:|---:|"
    for i in $(seq 1 23); do
      eval "t=\${CAT${i}:-0}"; eval "c=\${CAT${i}_critical:-0}"; eval "w=\${CAT${i}_warning:-0}"; eval "n=\${CAT${i}_info:-0}"
      echo "| $i | $t | $c | $w | $n |"
    done
  } > "$REPORT_MD" 2>/dev/null || true
  say "${DIM}Markdown report written to: ${REPORT_MD}${RESET}"
fi

if [[ -n "$EMIT_CSV" ]]; then
  {
    echo "category,total,critical,warning,info"
    for i in $(seq 1 23); do
      eval "t=\${CAT${i}:-0}"; eval "c=\${CAT${i}_critical:-0}"; eval "w=\${CAT${i}_warning:-0}"; eval "n=\${CAT${i}_info:-0}"
      echo "$i,$t,$c,$w,$n"
    done
  } > "$EMIT_CSV" 2>/dev/null || true
  say "${DIM}CSV emitted to: ${EMIT_CSV}${RESET}"
fi

if [[ -n "$EMIT_HTML" ]]; then
  {
    echo "<!doctype html><meta charset='utf-8'><title>UBS Swift Report</title>"
    echo "<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial} table{border-collapse:collapse} td,th{padding:.4rem .6rem;border:1px solid #ddd} .ok{color:#2a7} .warn{color:#c80} .crit{color:#c22}</style>"
    echo "<h1>UBS Swift Report</h1>"
  echo "<p><strong>Project:</strong> $(printf %s "$PROJECT_DIR" | sed 's/&/&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')</p>"
    echo "<p><strong>Files:</strong> $TOTAL_FILES</p>"
    echo "<p><strong>Timestamp:</strong> $(eval "$DATE_CMD")</p>"
    echo "<h2>Totals</h2>"
    echo "<table><tr><th>Critical</th><th>Warning</th><th>Info</th></tr>"
    echo "<tr><td class='crit'>$CRITICAL_COUNT</td><td class='warn'>$WARNING_COUNT</td><td class='ok'>$INFO_COUNT</td></tr></table>"
    echo "<h2>Categories</h2>"
    echo "<table><tr><th>#</th><th>Total</th><th>Critical</th><th>Warning</th><th>Info</th></tr>"
    for i in $(seq 1 23); do
      eval "t=\${CAT${i}:-0}"; eval "c=\${CAT${i}_critical:-0}"; eval "w=\${CAT${i}_warning:-0}"; eval "n=\${CAT${i}_info:-0}"
      echo "<tr><td>$i</td><td>$t</td><td class='crit'>$c</td><td class='warn'>$w</td><td class='ok'>$n</td></tr>"
    done
    echo "</table>"
  } > "$EMIT_HTML" 2>/dev/null || true
  say "${DIM}HTML report written to: ${EMIT_HTML}${RESET}"
fi

echo ""
say "${DIM}Scan completed at: $(eval "$DATE_CMD")${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi

echo ""
if [[ "$VERBOSE" -eq 0 ]]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
fi
say "${DIM}Add to CI: ./$SCRIPT_NAME --ci --fail-on-warning --summary-json=.ubs-swift-summary.json . > swift-bug-scan-report.txt${RESET}"
echo ""

EXIT_CODE=0
[[ "$CRITICAL_COUNT" -gt 0 ]] && EXIT_CODE=1
[[ "$FAIL_ON_WARNING" -eq 1 && $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]] && EXIT_CODE=1
exit "$EXIT_CODE"
