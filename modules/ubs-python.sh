#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# PYTHON ULTIMATE BUG SCANNER - Contract-v2 Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Python (3.13+) using:
#   • ast-grep (rule packs; language: python)
#   • ripgrep/grep heuristics for fast code smells
#   • optional uv-powered extra analyzers
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-python.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="e58dbe44f2c4a4f052838d494e34372ce3d118c06a581015c911b55d989cea2c"
UBS_MODULE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
  if [[ -f "${UBS_VERIFIED_ASSET_DIR}/lib/ubs-common.sh" ]]; then
    UBS_MODULE_LIB_DIR="$UBS_VERIFIED_ASSET_DIR"
  elif [[ -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
    if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
      echo "warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified lib at ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" >&2
    else
      echo "✗ ${BASH_SOURCE[0]}: lib/ubs-common.sh found at unverified location; refusing to load unverified library (set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" >&2
      exit 2
    fi
  fi
fi
if [[ -z "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
  if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
    : # override allows unverified
  elif [[ -n "${UBS_LIB_CHECKSUM:-}" && -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
    _lib_sha=""
    if command -v sha256sum >/dev/null 2>&1; then
      _lib_sha="$(sha256sum "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      _lib_sha="$(shasum -a 256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
      _lib_sha="$(openssl dgst -sha256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" 2>/dev/null | awk '{print $NF}')"
    fi
    if [[ -n "$_lib_sha" && "$_lib_sha" != "$UBS_LIB_CHECKSUM" ]]; then
      echo "✗ ${BASH_SOURCE[0]}: lib/ubs-common.sh failed checksum verification (expected $UBS_LIB_CHECKSUM, got $_lib_sha); refusing to load unverified library (run 'ubs doctor --fix' or reinstall)" >&2
      exit 2
    fi
  fi
fi
if [[ ! -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
  echo "✗ ${BASH_SOURCE[0]}: missing ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh (run 'ubs doctor --fix' or reinstall)" >&2
  exit 2
fi
# shellcheck source=lib/ubs-common.sh
source "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh"
shopt -s lastpipe
shopt -s extglob
shopt -s compat31 || true

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure predictable IFS for loops (restored on exit)
ORIG_IFS=${IFS}
IFS=$' \t\n'

# ────────────────────────────────────────────────────────────────────────────
# Temp paths / cleanup
# ────────────────────────────────────────────────────────────────────────────
KEEP_TEMP=${UBS_KEEP_TEMP:-0}
TEMP_PATHS=()

cleanup_add() { [[ -n "${1:-}" ]] && TEMP_PATHS+=("$1"); }

cleanup() {
  IFS=${ORIG_IFS}
  [[ "${KEEP_TEMP}" -eq 1 ]] && return 0
  local p
  for p in "${TEMP_PATHS[@]:-}"; do
    [[ -n "$p" && "$p" != "/" && "$p" != "." ]] && rm -rf -- "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

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
: "$MAGENTA" "$CYAN"

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; BULLET="•"; FIRE="🔥"

say() { echo -e "$*"; }
print_subheader() { say "\n${YELLOW}${BOLD}${BULLET} $1${RESET}"; }
print_finding() {
  local severity=$1
  case $severity in
    good)
      local title=${2:-}
      if [[ "${2:-}" =~ ^[0-9]+$ && -n "${3:-}" ]]; then title=$3; fi
      say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}"
      ;;
    info)
      local count=$2 title=$3 desc="${4:-}"
      say "  ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"
      say "    ${WHITE}$title${RESET}"
      [ -n "$desc" ] && say "    ${DIM}$desc${RESET}" || true
      ;;
    warn|warning)
      # An analyzer that did not complete is reported here: silence would make
      # incomplete coverage indistinguishable from a clean result (issue #103).
      local count=$2 title=$3 desc="${4:-}"
      say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"
      say "    ${WHITE}$title${RESET}"
      [ -n "$desc" ] && say "    ${DIM}$desc${RESET}" || true
      ;;
    *)
      ;;
  esac
}

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
MAX_FILE_SIZE="25M"
USER_RULE_DIR=""
ENABLE_UV_TOOLS=${ENABLE_UV_TOOLS:-1}
UV_TOOLS=${UV_TOOLS:-"ruff,bandit,pip-audit"}
UV_TIMEOUT="${UV_TIMEOUT:-1200}"
SUMMARY_JSON=""
UBS_PY_VERSION="$(cat "$(dirname "${BASH_SOURCE[0]:-$0}")/../VERSION" 2>/dev/null || echo unknown)"
REPORT_JSON=""
MAX_JSON_SAMPLES=3
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"
LIST_CATEGORIES=0
LIST_RULES=0
DUMP_RULES_DIR=""
BASELINE=""
FILES_FROM=""

CATEGORY_WHITELIST=""
case "${UBS_CATEGORY_FILTER:-}" in
  resource-lifecycle)
    CATEGORY_WHITELIST="16,19"
    ;;
esac

if [[ "${UBS_PROFILE:-}" == "loose" ]]; then
  if [[ -z "$SKIP_CATEGORIES" ]]; then
    SKIP_CATEGORIES="11,14"
  else
    SKIP_CATEGORIES="$SKIP_CATEGORIES,11,14"
  fi
fi

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
  --dump-rules=DIR        Dump generated ast rules + config
  --list-rules            List generated ast-grep rule IDs and exit
  --no-uv                 Disable uv-powered extra analyzers
  --uv-tools=CSV          Which uv tools to run (default: $UV_TOOLS)
  --summary-json=FILE     Also write machine-readable summary JSON
  --report-json=FILE      Also write a machine-readable JSON findings report to FILE
  --max-samples=N         Cap code samples per finding in the JSON report (default: 3)
  --max-detailed=N        Cap number of detailed code samples (default: $MAX_DETAILED)
  -h, --help              Show help
Env:
  JOBS, NO_COLOR, CI, UV_TIMEOUT, TIMEOUT_SECONDS, MAX_FILE_SIZE, UBS_CATEGORY_FILTER
Args:
  PROJECT_DIR             Directory to scan (default: ".")
  OUTPUT_FILE             File to save the report (optional)
contract: v2
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
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
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --dump-rules) DUMP_RULES_DIR="${2:-}"; shift 2;;
    --list-rules) LIST_RULES=1; shift;;
    --no-uv)      ENABLE_UV_TOOLS=0; shift;;
    --uv-tools=*) UV_TOOLS="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --max-samples=*) MAX_JSON_SAMPLES="${1#*=}"; shift;;
    --max-detailed=*) MAX_DETAILED="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
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

# Early list-rules helper
if [[ "${LIST_RULES:-0}" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-py-rules.XXXXXX)"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.py_rules import generate
generate(Path('$tmp_rules'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    cp "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml "$DUMP_RULES_DIR/" 2>/dev/null || true
  fi
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml 2>/dev/null || true ) | sort -u
  rm -rf "$tmp_rules" 2>/dev/null || true
  exit 0
fi

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ "$FORCE_COLOR" -eq 1 && "$NO_COLOR_FLAG" -eq 0 ]]; then USE_COLOR=1; fi
if [[ -n "${OUTPUT_FILE}" && "$FORMAT" == "text" && "$FORCE_COLOR" -eq 0 && "$NO_COLOR_FLAG" -eq 0 ]]; then
  USE_COLOR=0
fi
init_colors

if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi

EXCLUDE_DIRS=(venv .venv env .env __pycache__ .git .mypy_cache .pytest_cache .ruff_cache .tox .nox build dist .eggs *.egg-info site-packages)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi

HAS_UV=0
UVX_CMD=()
if [[ "$ENABLE_UV_TOOLS" -eq 1 ]] && command -v uv >/dev/null 2>&1; then
  HAS_UV=1
  UVX_CMD=(uvx --quiet)
fi

TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout"
fi

# Optional-analyzer invocation status (issue #103). `|| true` used to discard
# it entirely, so a Ruff that exited 2 without producing findings was reported
# as "Ruff clean". UV_TOOL_STATUS is the process exit status; -1 means the tool
# was not available at all, which is a coverage gap rather than a failure.
UV_TOOL_STATUS=0
UV_TOOL_ERRORS=()

run_uv_tool_text() {
  local tool="$1"; shift
  local rc=0
  UV_TOOL_STATUS=0
  if [[ "$HAS_UV" -eq 1 ]]; then
    if [[ -n "$TIMEOUT_CMD" ]]; then
      ( set +o pipefail; "$TIMEOUT_CMD" "$UV_TIMEOUT" "${UVX_CMD[@]}" "$tool" "$@" ) || rc=$?
    else
      ( set +o pipefail; "${UVX_CMD[@]}" "$tool" "$@" ) || rc=$?
    fi
  else
    if command -v "$tool" >/dev/null 2>&1; then
      if [[ -n "$TIMEOUT_CMD" ]]; then
        ( set +o pipefail; "$TIMEOUT_CMD" "$UV_TIMEOUT" "$tool" "$@" ) || rc=$?
      else
        ( set +o pipefail; "$tool" "$@" ) || rc=$?
      fi
    else
      rc=-1
    fi
  fi
  UV_TOOL_STATUS="$rc"
  return 0
}

# Record an optional analyzer that was selected but did not complete.
record_uv_tool_failure(){
  UV_TOOL_ERRORS+=("$1")
}

run_system_or_uv_tool() {
  local tool="$1"; shift
  if [[ "$HAS_UV" -eq 1 ]]; then ( set +o pipefail; "${UVX_CMD[@]}" "$tool" "$@" || true ); return; fi
  if command -v "$tool" >/dev/null 2>&1; then ( set +o pipefail; "$tool" "$@" || true ); fi
}

# Silence options unused in contract-v2 for shellcheck
: "$VERBOSE" "$DETAIL_LIMIT" "$JOBS" "$MAX_JSON_SAMPLES" "$USER_RULE_DIR" "$QUIET" "$CI_MODE" "$USE_COLOR"
: "$BASELINE" "$MAX_FILE_SIZE" "$MAX_DETAILED" "$TIMEOUT_SECONDS" "$CROSS" "$WARN" "$FIRE"
: "${SCRIPT_DIR}" "${PROJECT_DIR}" "${OUTPUT_FILE:-}" "${SOURCE_PROJECT_DIR:-}"

# ── Legacy-parity bridge: uv tools (category 20) ────────────────────────────
run_v2_uv_tools_py(){
  local sink="$1"
  UV_EXTRA_INFO=0
  if [[ "$ENABLE_UV_TOOLS" -ne 1 ]]; then
    say "  ${GRAY}${INFO} uv extra analyzers disabled (--no-uv)${RESET}"
    return 0
  fi
  local TOOL ruff_stdout ruff_stderr ruff_trimmed ruff_count ruff_parsed ruff_rc _EXC _ign_pats _pat _match _pa_input _tool_out
  IFS=',' read -r -a UVLIST <<< "$UV_TOOLS"
  for TOOL in "${UVLIST[@]}"; do
    case "$TOOL" in
      ruff)
        print_subheader "ruff (lint)"
        ruff_stdout="$(mktemp -t ubs-ruff.XXXXXX 2>/dev/null || mktemp)"
        ruff_stderr="$(mktemp -t ubs-ruff.XXXXXX 2>/dev/null || mktemp)"
        # `ruff check` exits 0 with no violations, 1 with violations, and >=1
        # other codes for an error (unparseable source, bad configuration).
        # `--no-fix` because a project config that turns fixing on would let a
        # scan rewrite the tree it was asked to inspect.
        run_uv_tool_text ruff check "$PROJECT_DIR" --no-fix --output-format=json >"$ruff_stdout" 2>"$ruff_stderr"
        ruff_rc="$UV_TOOL_STATUS"
        ruff_trimmed="$(tr -d '[:space:]' <"$ruff_stdout" 2>/dev/null || true)"
        ruff_count=0
        ruff_parsed=0
        if command -v python3 >/dev/null 2>&1 && [[ -s "$ruff_stdout" ]]; then
          ruff_parsed=1
          ruff_count=$(python3 - "$ruff_stdout" <<'PYRUFF'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print(-1)
    sys.exit(0)
print(len(data) if isinstance(data, list) else -1)
PYRUFF
)
        fi
        if [[ "$ruff_rc" -eq -1 ]]; then
          say "  ${GRAY}${INFO} ruff not available; lint coverage not collected${RESET}"
        elif [[ -z "$ruff_trimmed" ]]; then
          # No result document at all: the analyzer never got far enough to
          # report anything (commonly a launcher that could not provision it
          # offline). That is missing coverage, not a clean lint — but it is
          # also not evidence that ruff itself failed, so it does not fail the
          # scan the way a real analyzer error does.
          say "  ${GRAY}${INFO} ruff produced no result document (exit $ruff_rc); lint coverage not collected${RESET}"
          if [[ -s "$ruff_stderr" ]]; then
            say "  ${DIM}ruff stderr:${RESET}"
            cat "$ruff_stderr" 2>/dev/null || true
          fi
        elif [[ "$ruff_rc" -ne 0 && "$ruff_rc" -ne 1 ]]; then
          # A failed invocation is never "clean", whatever it printed.
          print_finding "warn" 1 "Ruff did not complete (exit $ruff_rc)" "Lint coverage is incomplete for this scan"
          say "  ${DIM}ruff stderr:${RESET}"
          cat "$ruff_stderr" 2>/dev/null || true
          record_uv_tool_failure "ruff exited $ruff_rc"
        elif [[ "$ruff_parsed" -eq 1 && "${ruff_count:-0}" -lt 0 ]]; then
          print_finding "warn" 1 "Ruff output could not be parsed" "Expected a JSON array from --output-format=json"
          record_uv_tool_failure "ruff produced unparseable output"
        elif [[ "$ruff_parsed" -eq 1 ]] \
             && { [[ "$ruff_rc" -eq 0 && "${ruff_count:-0}" -gt 0 ]] || [[ "$ruff_rc" -eq 1 && "${ruff_count:-0}" -eq 0 ]]; }; then
          # Exit status and result document disagree: neither can be trusted.
          # Only checked when the document was actually parsed — without
          # python3 the count is unknown, not zero.
          print_finding "warn" 1 "Ruff exit status contradicts its output" "exit $ruff_rc with $ruff_count finding(s)"
          record_uv_tool_failure "ruff exit $ruff_rc contradicts $ruff_count finding(s)"
        elif [[ "$ruff_trimmed" == "[]" ]]; then
          print_finding "good" "Ruff clean"
        else
          cat "$ruff_stdout" 2>/dev/null || true
          if [[ -s "$ruff_stderr" ]]; then
            say "  ${DIM}ruff stderr:${RESET}"
            cat "$ruff_stderr" 2>/dev/null || true
          fi
          print_finding "info" "$ruff_count" "Ruff emitted findings" "Review ruff output above"
          UV_EXTRA_INFO=$((UV_EXTRA_INFO + ruff_count))
        fi
        rm -f "$ruff_stdout" "$ruff_stderr" 2>/dev/null || true
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
        if [[ -n "$EXTRA_EXCLUDES" ]]; then
          IFS=',' read -r -a _ign_pats <<< "$EXTRA_EXCLUDES"
          for _pat in "${_ign_pats[@]}"; do
            [[ "$_pat" != *'*'* && "$_pat" != *'?'* && "$_pat" != *'['* ]] && continue
            while IFS= read -r _match; do
              [[ -z "$_match" ]] && continue
              _EXC="${_EXC:+$_EXC,}$_match"
            done < <(find "$PROJECT_DIR" -path "$PROJECT_DIR/$_pat" 2>/dev/null || true)
          done
        fi
        # bandit exits 0 (no issues), 1 (issues reported) or 2 (error).
        _tool_out="$(mktemp -t ubs-bandit.XXXXXX 2>/dev/null || mktemp)"
        run_uv_tool_text bandit -q -r "$PROJECT_DIR" -x "${_EXC:-}" >"$_tool_out" 2>&1
        cat "$_tool_out" 2>/dev/null || true
        if [[ "$UV_TOOL_STATUS" -eq -1 ]]; then
          say "  ${GRAY}${INFO} bandit not available; security coverage not collected${RESET}"
        elif [[ "$UV_TOOL_STATUS" -ne 0 && ! -s "$_tool_out" ]]; then
          say "  ${GRAY}${INFO} bandit produced no output (exit $UV_TOOL_STATUS); security coverage not collected${RESET}"
        elif [[ "$UV_TOOL_STATUS" -eq 0 || "$UV_TOOL_STATUS" -eq 1 ]]; then
          print_finding "info" 0 "Bandit scan completed" "See output above"
        else
          print_finding "warn" 1 "Bandit did not complete (exit $UV_TOOL_STATUS)" "Security coverage is incomplete for this scan"
          record_uv_tool_failure "bandit exited $UV_TOOL_STATUS"
        fi
        rm -f "$_tool_out" 2>/dev/null || true
        ;;
      pip-audit)
        print_subheader "pip-audit (dependencies)"
        # pip-audit exits 0 (no known vulnerabilities), 1 (vulnerabilities
        # found) and other codes on error. Scanning a source tree without a
        # resolved environment is inventory coverage, not a clean audit — say
        # which input was used so the claim stays qualified.
        _pa_input="$PROJECT_DIR (source tree)"
        _tool_out="$(mktemp -t ubs-pipaudit.XXXXXX 2>/dev/null || mktemp)"
        if [ -f "$PROJECT_DIR/requirements.txt" ]; then
          _pa_input="requirements.txt"
          run_uv_tool_text pip-audit -r "$PROJECT_DIR/requirements.txt" >"$_tool_out" 2>&1
        elif [ -f "$PROJECT_DIR/pyproject.toml" ]; then
          _pa_input="pyproject.toml"
          run_uv_tool_text pip-audit --path "$PROJECT_DIR/pyproject.toml" >"$_tool_out" 2>&1
        else
          run_uv_tool_text pip-audit --path "$PROJECT_DIR" >"$_tool_out" 2>&1
        fi
        cat "$_tool_out" 2>/dev/null || true
        if [[ "$UV_TOOL_STATUS" -eq -1 ]]; then
          say "  ${GRAY}${INFO} pip-audit not available; dependency coverage not collected${RESET}"
        elif [[ "$UV_TOOL_STATUS" -ne 0 && ! -s "$_tool_out" ]]; then
          say "  ${GRAY}${INFO} pip-audit produced no output (exit $UV_TOOL_STATUS); dependency coverage not collected${RESET}"
        elif [[ "$UV_TOOL_STATUS" -eq 0 || "$UV_TOOL_STATUS" -eq 1 ]]; then
          print_finding "info" 0 "pip-audit ran against $_pa_input" "Review advisories above"
        else
          print_finding "warn" 1 "pip-audit did not complete (exit $UV_TOOL_STATUS)" "Dependency coverage is incomplete for this scan"
          record_uv_tool_failure "pip-audit exited $UV_TOOL_STATUS"
        fi
        rm -f "$_tool_out" 2>/dev/null || true
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
}

# ── Legacy-parity bridges: record-less section headers + summary + exit ─────
run_v2_legacy_parity_bridges_py(){
  local sink="$1" list_file="$2" py_exit="$3" text_out="${4:-}" extra_info="${5:-0}" skip_csv="${6:-}"
  local analyzer_errors="${7:-0}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "$skip_csv" \
    "$py_exit" "$extra_info" "$analyzer_errors" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, py_exit_raw, extra_raw,
 analyzer_errors_raw) = sys.argv[1:9]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
py_exit = int(py_exit_raw or "0")
extra_info = int(extra_raw or "0")
analyzer_errors = int(analyzer_errors_raw or "0")
as_text = bool(text_out)

# Mirror py_scan._CATEGORY_SLUGS/_SECTION_HEADERS (legacy print_header titles).
SLUG = {1: "none", 2: "numeric", 3: "collections", 4: "comparison", 5: "async",
        6: "error-handling", 7: "security", 8: "functions", 9: "parsing",
        10: "control-flow", 11: "debug", 12: "perf", 13: "variables",
        14: "code-quality", 15: "regex", 16: "io", 17: "typing", 18: "modules",
        19: "resource-lifecycle", 20: "uv-tools", 21: "deprecations",
        22: "packaging", 23: "notebooks"}
SECTION = {1: "1. NONE / DEFENSIVE PROGRAMMING", 2: "2. NUMERIC / ARITHMETIC PITFALLS",
           3: "3. COLLECTION SAFETY", 4: "4. COMPARISON & TYPE CHECKING TRAPS",
           5: "5. ASYNC/AWAIT PITFALLS", 6: "6. ERROR HANDLING ANTI-PATTERNS",
           7: "7. SECURITY VULNERABILITIES", 8: "8. FUNCTION & SCOPE ISSUES",
           9: "9. PARSING & TYPE CONVERSION BUGS", 10: "10. CONTROL FLOW GOTCHAS",
           11: "11. DEBUGGING & PRODUCTION CODE", 12: "12. PERFORMANCE & MEMORY",
           13: "13. VARIABLE & SCOPE", 14: "14. CODE QUALITY MARKERS",
           15: "15. REGEX & STRING SAFETY", 16: "16. I/O & RESOURCE SAFETY",
           17: "17. TYPING STRICTNESS", 18: "18. PYTHON I/O & MODULE USAGE",
           19: "19. RESOURCE LIFECYCLE CORRELATION", 20: "20. UV-POWERED EXTRA ANALYZERS",
           21: "21. DEPRECATIONS & PY3.13 MIGRATIONS", 22: "22. PACKAGING & CONFIG HYGIENE",
           23: "23. NOTEBOOK HYGIENE"}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

# Final severity recount over the whole sink (+ uv lump info), legacy
# 11876-11879 inputs.
counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1
counts["info"] += extra_info

out = []

def emit(line=""):
    out.append(line)

# Record-less section headers (text format only; json stdout stays machine-clean).
if as_text:
    covered = {str(rec.get("category_id", "")) for rec in records}
    for num in sorted(SECTION):
        if num in skip:
            continue
        if f"python.{SLUG[num]}" not in covered:
            emit(SECTION[num])
    emit("")
    emit("Summary Statistics:")
    emit(f"Files scanned: {files_n}")
    emit(f"Critical issues: {counts['critical']}")
    emit(f"Warning issues: {counts['warning']}")
    emit(f"Info items: {counts['info']}")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

# Issue #103: this recount used to overwrite an abnormal scanner status with
# the ordinary finding exit 1 whenever criticals existed, so "the scanner
# crashed" and "the scanner found bugs" became the same exit code. Execution
# failures dominate severity: a scan that did not complete is reported as
# incomplete (exit 2) whatever it managed to find, and the findings are still
# emitted so the partial evidence is not lost.
if py_exit not in (0, 1):
    exit_code = py_exit
elif analyzer_errors:
    exit_code = 2
else:
    exit_code = 1 if counts["critical"] else py_exit
    if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
        exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

run_contract_v2_py(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-pyv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-pyv2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  # UBS_CATEGORY_FILTER whitelist -> legacy should_skip mapping: skip every
  # category NOT whitelisted (139-145: resource-lifecycle allows 16,19).
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$CATEGORY_WHITELIST" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$CATEGORY_WHITELIST"
    for c in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  [[ "${JOBS:-0}" -gt 0 ]] && scan_args+=(--jobs "$JOBS")
  # Consolidated ast-grep layer: generate the 52-rule pack into ONE sgconfig
  # (one `scan -c` per path batch inside ubs_core.py_ast).
  local ast_rule_dir=""
  if command -v ast-grep >/dev/null 2>&1 && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-pyv2-rules.XXXXXX)"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.py_rules import generate
generate(Path('$ast_rule_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
      ast_rule_dir=""
    elif [[ -n "$DUMP_RULES_DIR" ]]; then
      mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
      cp "$ast_rule_dir"/rules/*.yml "$ast_rule_dir"/*.yml "$DUMP_RULES_DIR/" 2>/dev/null || true
    fi
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-pyv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-pyv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      # --summary-json is a delivery request, not a format: honour it in text
      # mode too rather than exiting 0 with nothing written (issue #106).
      if [[ -n "$SUMMARY_JSON" ]]; then
        v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-pyv2-json.XXXXXX)"
        scan_args+=(--json-out "$v2_json_out")
      fi
      ;;
    *) echo "ERROR: contract-v2 python path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.py_scan \
    "${scan_args[@]}" --version "${UBS_PY_VERSION:-unknown}" || exit_code=$?
  # Category 20 parity bridge: raw uv-tool passthrough (not sink records, text mode only).
  if [[ ",$v2_skip," != *",20,"* && "$FORMAT" == "text" ]]; then
    run_v2_uv_tools_py "$sink"
  fi
  # Record-less section headers + Summary Statistics + legacy exit formula.
  run_v2_legacy_parity_bridges_py "$sink" "$list_file" "$exit_code" "$text_out" \
    "${UV_EXTRA_INFO:-0}" "$v2_skip" "${#UV_TOOL_ERRORS[@]}" || exit_code=$?
  if [[ ${#UV_TOOL_ERRORS[@]} -gt 0 ]]; then
    printf 'ubs-python: analysis incomplete: %s\n' "${UV_TOOL_ERRORS[@]}" >&2
    # The JSON summary must not claim a completed scan either.
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]] && command -v python3 >/dev/null 2>&1; then
      UBS_UV_TOOL_ERRORS="$(printf '%s; ' "${UV_TOOL_ERRORS[@]}")" python3 - "$v2_json_out" <<'PYUVSTATUS' || true
import json, os, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, ValueError):
    sys.exit(0)
if not isinstance(doc, dict):
    sys.exit(0)
detail = os.environ.get("UBS_UV_TOOL_ERRORS", "").strip().rstrip(";")
doc["status"] = "partial"
doc["module_error"] = "ANALYZER_ERROR"
doc["message"] = ("Selected Python analyzers did not complete: " + detail)[:500]
with open(path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, ensure_ascii=False)
    fh.write("\n")
PYUVSTATUS
    fi
  fi

  if [[ "$FORMAT" == "sarif" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null || true
    fi
  fi

  if [[ -n "$text_out" ]]; then
    cat "$text_out" 2>/dev/null || true
    rm -f "$text_out" 2>/dev/null || true
  fi
  if [[ -n "$v2_json_out" && "$FORMAT" == "json" ]]; then
    cat "$v2_json_out" 2>/dev/null || true
  fi
  # Requested artifacts are a separate outcome from the analysis (issue #106):
  # if one was asked for and could not be written, the run reports an
  # environment error rather than exit 0 with nothing on disk.
  local delivery_failed=0
  if [[ -n "$SUMMARY_JSON" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      ubs_deliver_file "$v2_json_out" "$SUMMARY_JSON" "summary JSON" || delivery_failed=1
    else
      printf '✗ cannot write the requested summary JSON: this format produced no summary document\n' >&2
      delivery_failed=1
    fi
  fi
  if [[ -n "$v2_json_out" ]]; then
    rm -f "$v2_json_out" 2>/dev/null || true
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    # K2: the sink IS the findings record stream.
    ubs_deliver_file "$sink" "$REPORT_JSON" "findings report" || delivery_failed=1
  fi
  if [[ "$delivery_failed" -eq 1 ]]; then
    exit_code=2
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  [[ -n "$ast_rule_dir" ]] && rm -rf -- "$ast_rule_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_py || v2_status=$?
exit "$v2_status"
