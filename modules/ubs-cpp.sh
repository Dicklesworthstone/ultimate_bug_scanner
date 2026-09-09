#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# C/C++ ULTIMATE BUG SCANNER - Industrial-Grade Static Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for C/C++ projects on contract v2.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-cpp.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="2e9e6277ff9edf438bd4b42469a9392b1d3f84ee91ed41efe6273cd434059e00"
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
: "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$GRAY" "$WHITE" "$BOLD" "$DIM" "$RESET" "$RED"

CHECK="✓"; WARN="⚠"; INFO="ℹ"; BULLET="•"; FIRE="🔥"; SPARKLE="✨"
: "$CHECK" "$WARN" "$INFO" "$BULLET" "$FIRE" "$SPARKLE"

# ────────────────────────────────────────────────────────────────────────────
# CLI Parsing & Configuration
# ────────────────────────────────────────────────────────────────────────────
VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif|counts
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="c,cpp,cc,cxx,cppm,mpp,ixx,h,hpp,hxx,hh,ipp,tpp,txx"
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
LIST_RULES=0
DUMP_RULES_DIR=""
REPORT_JSON=""
FILES_FROM=""

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif|counts (default: text)
  --list-categories        Print numeric category map and exit
  --report-json=FILE       Also write a machine-readable JSON summary to FILE
  --counts                 Output only per-category counts (machine-friendly)
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: cpp,cc,cxx,cppm,mpp,ixx,h,hpp,hxx,hh,ipp,tpp)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --only=CSV               Run only these categories (e.g. --only=1,7,12)
  --fail-on-warning        Exit non-zero on warnings or critical
  --rules=DIR              Additional ast-grep rules directory (merged)
  --dump-rules=DIR         Dump generated ast rules + config
  --list-rules             List generated ast-grep rule IDs and exit
  --respect-gitignore=0|1  Respect VCS ignore (default: 1)
  --hidden=0|1           Scan hidden files/dirs (default: 0)
  --max-filesize=SIZE      Max file size for rg (e.g. 1M, 5M)
  --paths-from=FILE        Read newline-separated files to scan
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
contract: v2
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --list-categories) LIST_CATS=1; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
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
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --dump-rules) DUMP_RULES_DIR="${2:-}"; shift 2;;
    --list-rules) LIST_RULES=1; shift;;
    --respect-gitignore=*) RESPECT_GITIGNORE="${1#*=}"; shift;;
    --respect-gitignore)   RESPECT_GITIGNORE=1; shift;;
    --hidden=*)   SCAN_HIDDEN="${1#*=}"; shift;;
    --hidden)     SCAN_HIDDEN=1; shift;;
    --max-filesize=*) MAX_FILESIZE="${1#*=}"; shift;;
    --paths-from=*) PATHS_FILE="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ -z "$PROJECT_DIR" || "$PROJECT_DIR" == "." ]] && ! [[ "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" ]] && ! [[ "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, use the meta-runner 'ubs'. To save a report, pass a fresh (non-existing) path." >&2
          exit 2
        fi
        OUTPUT_FILE="$1"; shift
      else
        echo "Unexpected argument: $1" >&2; exit 2
      fi
      ;;
  esac
done

: "$VERBOSE" "$DETAIL_LIMIT" "$MAX_DETAILED" "$JOBS" "$USER_RULE_DIR" "$DISABLE_PIPEFAIL_DURING_SCAN"
: "$RESPECT_GITIGNORE" "$SCAN_HIDDEN" "$MAX_FILESIZE" "$PATHS_FILE" "$CI_MODE"

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

is_machine_format() { [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" || "$FORMAT" == "counts" ]]; }
if is_machine_format; then
  QUIET=1
  USE_COLOR=0
fi
: "$QUIET" "$USE_COLOR"

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

# Early list-rules helper
if [[ "${LIST_RULES:-0}" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-cpp-rules.XXXXXX)"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.cpp_rules import generate
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

# Redirect output early to capture everything
if [[ -n "${OUTPUT_FILE}" ]]; then exec > >(tee "${OUTPUT_FILE}") 2>&1; fi

# ── Contract-v2 path (bead 0xjg.9): ONE file list (ubs_list_files), ONE python
#    orchestrator (ubs_core.cpp_scan), NDJSON findings sink (K2 schema).
# ── Legacy-parity bridges for the contract-v2 path ──────────────────────────
run_v2_legacy_parity_bridges_cpp(){
  local sink="$1" list_file="$2" scan_exit="$3" text_out="${4:-}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "${SKIP_CATEGORIES:-}" \
    "$scan_exit" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, scan_exit_raw) = sys.argv[1:7]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
scan_exit = int(scan_exit_raw or "0")
as_text = bool(text_out)

SECTION = {
    1: "1. MEMORY & RAII", 2: "2. EXCEPTIONS & ERROR HANDLING",
    3: "3. CONCURRENCY & ATOMICS", 4: "4. MODERNIZATION (C++20+)",
    5: "5. POINTER & LIFETIME HAZARDS", 6: "6. NUMERIC & ARITHMETIC PITFALLS",
    7: "7. UNDEFINED BEHAVIOR RISK ZONE", 8: "8. HEADER & INCLUDE HYGIENE",
    9: "9. STL & ALGORITHMS", 10: "10. STRING & I/O SAFETY",
    11: "11. MACROS & PREPROCESSOR TRAPS", 12: "12. CMAKE & BUILD HYGIENE",
    13: "13. CODE QUALITY MARKERS", 14: "14. PERFORMANCE & ALLOCATION PRESSURE",
    15: "15. TEST/DEBUG LEFTOVERS",
}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

def record_category(rec):
    rule = str(rec.get("rule", ""))
    cat = rec.get("category_id", "")
    if rule.startswith("cpp.taint.") or rule.startswith("cpp.async."):
        return 7
    if rule.startswith("cpp.resource."):
        return 1
    if cat.startswith("cpp."):
        slug = cat[4:]
        for num, title in SECTION.items():
            first_word = title.split(".", 1)[1].strip().split()[0].lower()
            if slug.startswith(first_word):
                return num
    return None

counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

if as_text:
    out = []
    for num in sorted(SECTION):
        if num in skip:
            continue
        if not any(record_category(rec) == num for rec in records):
            out.append(SECTION[num])
    out.append("")
    out.append("Summary Statistics:")
    out.append(f"Files scanned: {files_n}")
    out.append(f"Critical issues: {counts['critical']}")
    out.append(f"Warning issues: {counts['warning']}")
    out.append(f"Info items: {counts['info']}")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

exit_code = 1 if counts["critical"] else scan_exit
if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

run_contract_v2_cpp(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-cpp-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-cpp-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  else
    ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file" || true
  fi
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in $(seq 1 16); do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "${v2_skip}" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  case "$FORMAT" in
    json)
      exec 3>&1
      scan_args+=(--json-out /dev/fd/3 --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-cppv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}") ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-cppv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 cpp path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.cpp_scan \
    "${scan_args[@]}" --version "7.1" || exit_code=$?
  if [[ "$FORMAT" == "sarif" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" || exit_code=$?
    rm -f "$v2_json_out" 2>/dev/null || true
  else
    # Record-less section headers + Summary Statistics + legacy exit formula.
    run_v2_legacy_parity_bridges_cpp "$sink" "$list_file" "$exit_code" "$text_out" || exit_code=$?
    if [[ -n "$text_out" ]]; then
      cat "$text_out" 2>/dev/null || true
      rm -f "$text_out" 2>/dev/null || true
    fi
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_cpp || v2_status=$?
exit "$v2_status"
