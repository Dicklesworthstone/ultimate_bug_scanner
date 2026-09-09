#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# JAVASCRIPT / TYPESCRIPT ULTIMATE BUG SCANNER - Contract-v2 Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis using ast-grep + semantic pattern matching
# Catches bugs that cost developers hours of debugging
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-js.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="4bf03b39435aed8e99aaee4a4435a80e7fb9d35a36f460c04b71a931754b8117"
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
set -o errtrace

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

if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
  BOLD=''; DIM=''; RESET=''
fi

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="js,jsx,ts,tsx,mjs,cjs"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
JOBS="${JOBS:-0}"
MAX_JSON_SAMPLES=3
REPORT_JSON=""
USER_RULE_DIR=""
DUMP_RULES_DIR=""
LIST_RULES=0
FILES_FROM=""

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
  --dump-rules=DIR         Persist generated ast-grep rules to DIR for test validation
  --list-rules             List generated ast-grep rule ids, then exit
  --report-json=FILE       Also write a machine-readable JSON summary to FILE
  --max-samples=N          Maximum samples per finding (default: 3)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
contract: v2
USAGE
}

list_categories() {
  cat <<'CATS'
1  Null Safety & Defensive Programming
2  Math & Arithmetic Pitfalls
3  Array & Collection Safety
4  Type Coercion & Comparison Traps
5  Async/Await & Promise Pitfalls
6  Error Handling Anti-Patterns
7  Security Vulnerabilities
8  Function & Scope Issues
9  Parsing & Type Conversion Bugs
10 Control Flow Gotchas
11 Debugging & Production Code
12 Memory Leaks & Performance
13 Variable & Scope Issues
14 Code Quality Markers
15 Regex & String Safety
16 DOM Manipulation Safety
17 TypeScript Strictness
18 Node.js I/O & Modules
19 Resource Lifecycle Correlation
CATS
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --list-categories) list_categories; exit 0;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --rules=*)    USER_RULE_DIR="${1#*=}"; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --list-rules) LIST_RULES=1; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --max-samples=*) MAX_JSON_SAMPLES="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, use the meta-runner 'ubs'. To save a report, pass a fresh (non-existing) path." >&2
          exit 2
        fi
        OUTPUT_FILE="$1"
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      shift;;
  esac
done

if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi

IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
EXCLUDE_DIRS=(node_modules dist build out .next .nuxt .cache coverage .git vendor tmp temp .svelte-kit)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi

# Silence options unused in contract-v2 for shellcheck
: "$VERBOSE" "$DETAIL_LIMIT" "$JOBS" "$MAX_JSON_SAMPLES" "$USER_RULE_DIR" "$QUIET" "$CI_MODE" "$USE_COLOR"
: "$RED" "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$WHITE" "$GRAY" "$BOLD" "$DIM" "$RESET"
: "${SCRIPT_DIR}" "${PROJECT_DIR}" "${OUTPUT_FILE:-}" "${SOURCE_PROJECT_DIR:-}"

check_ast_grep() {
  if [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    return 1
  fi
  if [[ -n "${UBS_AST_GREP_BIN:-}" ]]; then
    local candidate="${UBS_AST_GREP_BIN}"
    if [[ -x "$candidate" ]] || command -v "$candidate" >/dev/null 2>&1; then
      return 0
    fi
  fi
  if command -v ast-grep >/dev/null 2>&1; then
    return 0
  fi
  if command -v sg >/dev/null 2>&1 && sg --version 2>&1 | grep -qi "ast-grep"; then
    return 0
  fi
  return 1
}

if [[ "$LIST_RULES" -eq 1 ]]; then
  if ! check_ast_grep; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-jsv2-rules.XXXXXX)"
  cleanup_add "$tmp_rules"
  UBS_JS_USER_RULES="${USER_RULE_DIR:-}" PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import os
from pathlib import Path
from ubs_core.js_rules import generate
user = os.environ.get('UBS_JS_USER_RULES', '')
generate(Path('$tmp_rules'), Path(user) if user else None)
" 2>/dev/null || true
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml 2>/dev/null || true ) | sort -u
  exit 0
fi

# ── Legacy-parity bridges for the contract-v2 path ──────────────────────────
run_v2_legacy_parity_bridges(){
  local sink="$1" list_file="$2" js_exit="$3" text_out="${4:-}"
  local run_tn=0 tn_status=0 tn_raw="" helper="" js_runner="" e
  local allow_ts=0
  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" -ne 1 ]]; then
    for e in "${_EXT_ARR[@]}"; do
      case "$(echo "$e" | xargs)" in
      ts|tsx) allow_ts=1 ;;
      esac
    done
    # has_ts probe over the v2 file list itself (same scope the scan used).
    local has_ts=0
    if [[ "$allow_ts" -eq 1 && -f "$list_file" ]]; then
      has_ts="$(tr '\0' '\n' <"$list_file" 2>/dev/null | grep -cE '\.tsx?$' || true)"
      [[ "${has_ts:-0}" -gt 0 ]] && has_ts=1 || has_ts=0
    fi
    if [[ "$has_ts" -eq 1 ]]; then
      helper=""
      ubs_resolve_helper helper "helpers/type_narrowing_ts.js" || helper=""
      if [[ -n "$helper" && -f "$helper" ]]; then
        if command -v node >/dev/null 2>&1; then
          js_runner="node"
        elif command -v bun >/dev/null 2>&1; then
          js_runner="bun"
        fi
        if [[ -n "$js_runner" ]]; then
          local -a helper_args=("$PROJECT_DIR")
          local helper_excludes=""
          local d
          for d in "${EXCLUDE_DIRS[@]}"; do
            [[ -z "$d" ]] && continue
            if [[ -n "$helper_excludes" ]]; then helper_excludes+=",$d"; else helper_excludes="$d"; fi
          done
          [[ -n "$helper_excludes" ]] && helper_args+=("--exclude=$helper_excludes")
          tn_raw="$(mktemp 2>/dev/null || mktemp -t ubs-jsv2-tn.XXXXXX)"
          if "$js_runner" "$helper" "${helper_args[@]}" >"$tn_raw" 2>&1; then
            tn_status=0
          else
            tn_status=$?
          fi
          run_tn=1
        fi
      fi
    fi
  fi
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "${SKIP_CATEGORIES:-}" \
    "$run_tn" "$tn_status" "$tn_raw" "$js_exit" "${UBS_SKIP_TYPE_NARROWING:-0}" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import os
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, run_tn_raw, tn_status_raw,
 tn_raw_path, js_exit_raw, skip_tn_raw) = sys.argv[1:11]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
run_tn = run_tn_raw == "1"
tn_status = int(tn_status_raw or "0")
js_exit = int(js_exit_raw or "0")
skip_tn = skip_tn_raw == "1"
as_text = bool(text_out)

# Mirror js_scan._CATEGORY_SLUGS/_SECTION_HEADERS (legacy print_header titles).
SLUG = {1: "null-undefined", 2: "equality", 3: "proto-object", 4: "type-coercion",
        5: "async", 6: "error-handling", 7: "security", 8: "function-scope",
        9: "parsing", 10: "control-flow", 11: "debug", 12: "perf",
        13: "vars", 14: "code-quality", 15: "regex", 16: "dom",
        17: "typescript", 18: "node", 19: "resource-lifecycle"}
SECTION = {1: "NULL SAFETY & DEFENSIVE PROGRAMMING", 2: "MATH & ARITHMETIC PITFALLS",
           3: "ARRAY & COLLECTION SAFETY", 4: "TYPE COERCION & COMPARISON TRAPS",
           5: "ASYNC/AWAIT & PROMISE PITFALLS", 6: "ERROR HANDLING ANTI-PATTERNS",
           7: "SECURITY VULNERABILITIES", 8: "FUNCTION & SCOPE ISSUES",
           9: "PARSING & TYPE CONVERSION BUGS", 10: "CONTROL FLOW GOTCHAS",
           11: "DEBUGGING & PRODUCTION CODE", 12: "MEMORY LEAKS & PERFORMANCE",
           13: "VARIABLE & SCOPE ISSUES", 14: "CODE QUALITY MARKERS",
           15: "REGEX & STRING SAFETY", 16: "DOM MANIPULATION SAFETY",
           17: "TYPESCRIPT STRICTNESS", 18: "NODE.JS I/O & MODULES",
           19: "RESOURCE LIFECYCLE CORRELATION"}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

out = []

def emit(line=""):
    out.append(line)

# Bridge 1: run_type_narrowing_checks output → sink records (+ text finding).
if run_tn:
    raw = ""
    if tn_raw_path and os.path.isfile(tn_raw_path):
        with open(tn_raw_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    raw_lines = raw.splitlines()
    issue_lines = [l for l in raw_lines if l.strip() and not l.startswith("[ubs-type-narrowing]")]
    if tn_status != 0:
        if as_text:
            emit("Type narrowing validation")
            emit("[warning] Type narrowing analyzer failed (0 found) — js.typescript.analyzer-failed")
            if raw.strip():
                emit("    " + " ".join(raw.split())[:240])
    elif issue_lines:
        count = len(issue_lines)
        previews = []
        new_records = []
        for line in issue_lines:
            loc, sep, msg = line.partition("\t")
            previews.append(f"{loc} → {msg}" if sep else loc)
            path, lineno, col = loc, 0, 1
            parts = loc.rsplit(":", 2)
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                path, lineno, col = parts[0], int(parts[1]), int(parts[2])
            new_records.append({
                "rule": "js.typescript.type-narrowing",
                "category_id": "js.typescript",
                "path": path,
                "line": lineno,
                "col": col,
                "severity": "warning",
                "message": (msg if sep else loc)[:240],
                "suppressed": False,
            })
        with open(sink_path, "a", encoding="utf-8") as fh:
            for rec in new_records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        records.extend(new_records)
        if as_text:
            if not any(r.get("category_id") == "js.typescript" for r in records[:-count]):
                emit("TYPESCRIPT STRICTNESS")
            emit("Type narrowing validation")
            desc = "Examples: " + " ".join(previews[:3])
            if count > 3:
                desc += f" (and {count - 3} more)"
            emit(f"[warning] Potentially unsafe type narrowing ({count} found) — js.typescript.type-narrowing")
            emit(f"    {desc}")
elif skip_tn and as_text:
    emit("Type narrowing validation")
    emit("  Type narrowing checks skipped")
    emit("    Set UBS_SKIP_TYPE_NARROWING=0 or remove --skip-type-narrowing to re-enable")

counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

if as_text:
    for num in sorted(SECTION):
        if num in skip:
            continue
        if not any(r.get("category_id") == f"js.{SLUG[num]}" for r in records):
            emit(SECTION[num])
    emit("")
    emit("Summary Statistics:")
    emit(f"Files scanned: {files_n}")
    emit(f"Critical issues: {counts['critical']}")
    emit(f"Warning issues: {counts['warning']}")
    emit(f"Info items: {counts['info']}")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

exit_code = 1 if counts["critical"] else js_exit
if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  if [[ -n "$tn_raw" ]]; then
    rm -f "$tn_raw" 2>/dev/null || true
  fi
  return "$bridge_rc"
}

run_contract_v2_js(){
  local list_file sink exit_code=0 ast_rule_dir="" text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-js-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-js-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "${SKIP_CATEGORIES}" ]] && scan_args+=(--skip "$SKIP_CATEGORIES")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)

  if ! check_ast_grep; then
    local has_sensitive=0
    if [[ -f "$list_file" ]]; then
      if tr '\0' '\n' <"$list_file" 2>/dev/null | grep -qE '\.(tsx?|jsx)$'; then
        has_sensitive=1
      fi
    fi
    if [[ "$has_sensitive" -eq 1 ]]; then
      echo ""
      echo -e "${RED}${BOLD}✗ Environment error: ast-grep is required for TS/TSX/JSX scans${RESET}"
      echo -e "${DIM}Without a syntax-aware AST engine, JS/TS scanning is too noisy to be trustworthy.${RESET}"
      echo -e "${DIM}Fix: install ast-grep (https://ast-grep.github.io/) or re-run the UBS installer.${RESET}"
      rm -f "$list_file" "$sink" 2>/dev/null || true
      return 2
    fi
    if [[ "$FORMAT" == "sarif" ]]; then
      echo -e "${RED}${BOLD}✗ Environment error: ast-grep rule pack unavailable for SARIF output${RESET}"
      rm -f "$list_file" "$sink" 2>/dev/null || true
      return 2
    fi
  fi

  if check_ast_grep; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-jsv2-rules.XXXXXX)"
    if ! UBS_JS_USER_RULES="${USER_RULE_DIR:-}" PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import os
from pathlib import Path
from ubs_core.js_rules import generate
user = os.environ.get('UBS_JS_USER_RULES', '')
generate(Path('$ast_rule_dir'), Path(user) if user else None)
" 2>/dev/null; then
      ast_rule_dir=""
    fi
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    UBS_JS_USER_RULES="${USER_RULE_DIR:-}" PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
import os
from pathlib import Path
from ubs_core.js_rules import generate
user = os.environ.get('UBS_JS_USER_RULES', '')
generate(Path('$DUMP_RULES_DIR'), Path(user) if user else None)
" 2>/dev/null || true
  fi

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-jsv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-jsv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 js path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac

  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.js_scan \
    "${scan_args[@]}" --version "4.7" || exit_code=$?

  run_v2_legacy_parity_bridges "$sink" "$list_file" "$exit_code" "$text_out" || exit_code=$?

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

  if [[ -n "$v2_json_out" ]]; then
    rm -f "$v2_json_out" 2>/dev/null || true
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  [[ -n "$ast_rule_dir" ]] && rm -rf "$ast_rule_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_js || v2_status=$?
exit "$v2_status"
