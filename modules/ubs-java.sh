#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# JAVA / KOTLIN ULTIMATE BUG SCANNER - Contract-v2 Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for Java and Kotlin using ast-grep +
# semantic patterns + analyzers.
# Focus: Null/Optional pitfalls, equals/hashCode, concurrency/async, security,
# I/O/resources, performance, regex/strings, serialization, code quality.
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-java.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="ce30c96f669e7007bd4689f29bc7cab663b7edf9a3c2b4131d88dae4fca27a07"
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
NO_EMOJI=${NO_EMOJI:-0}

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
ONLY_CATEGORIES=""
DETAIL_LIMIT_OVERRIDE=""
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="java"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
DETAIL_LIMIT=3
JOBS="${JOBS:-0}"
USER_RULE_DIR=""
DUMP_RULES_DIR=""
LIST_RULES=0
SARIF_OUT=""
REPORT_JSON=""
JSON_OUT=""
MIN_SEVERITY="info"     # info|warning|critical
RUN_BUILD=1
FILES_FROM=""

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
  --list-rules               List generated ast-grep rule IDs and exit
  --dump-rules=DIR           Persist generated ast-grep rules to DIR for test validation
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
contract: v2
USAGE
}

list_categories() {
  cat <<'CATS'
1  Null & Optional Pitfalls
2  Equality & HashCode
3  Concurrency & Threading
4  Security
5  I/O & Resources
6  Logging & Debugging
7  Regex & String Pitfalls
8  Collections & Generics
9  Switch & Control Flow
10 Streams & Performance
11 Serialization & Compatibility
12 Java 21 Features (Info)
13 SQL Construction (Heuristics)
14 Annotations & Nullness (Heuristics)
15 AST-Grep Rule Pack Findings
16 Build Health (Maven/Gradle)
17 Meta Statistics & Inventory
18 Misc API Misuse
19 Resource Safety & Resource Lifecycle Correlation
20 Path Handling & Filesystem
21 Hard-Coded Secrets (Heuristics)
22 Logging Best Practices
CATS
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --list-categories) list_categories; exit 0;;
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
    --list-rules) LIST_RULES=1; shift;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --no-build)   RUN_BUILD=0; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --json-out=*)  JSON_OUT="${1#*=}"; shift;;
    --min-severity=*) MIN_SEVERITY="${1#*=}"; shift;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from)   FILES_FROM="${2:-}"; shift 2;;
    -h|--help)    print_usage; exit 0;;
    *)
      if [[ "$PROJECT_DIR" == "." && ! "$1" =~ ^- ]]; then
        PROJECT_DIR="$1"; shift
      elif [[ -z "$OUTPUT_FILE" && ! "$1" =~ ^- ]]; then
        if [[ -e "$1" && -s "$1" ]]; then
          echo "error: refusing to use existing non-empty file '$1' as OUTPUT_FILE (would be overwritten)." >&2
          echo "       To scan multiple paths, use the meta-runner 'ubs'. To save a report, pass a fresh (non-existing) path." >&2
          exit 2
        fi
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
if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
  QUIET=1
  CI_MODE=1
fi

if [[ -n "$ONLY_CATEGORIES" ]]; then
  IFS=',' read -r -a _only_arr <<<"$ONLY_CATEGORIES"
  _computed_skip=()
  for c in {1..22}; do
    _keep=0
    for o in "${_only_arr[@]}"; do
      if [[ "$o" -eq "$c" ]]; then _keep=1; break; fi
    done
    if [[ "$_keep" -eq 0 ]]; then _computed_skip+=("$c"); fi
  done
  _computed_skip_csv="$(IFS=','; echo "${_computed_skip[*]}")"
  if [[ -n "$SKIP_CATEGORIES" ]]; then
    SKIP_CATEGORIES="${SKIP_CATEGORIES},${_computed_skip_csv}"
  else
    SKIP_CATEGORIES="${_computed_skip_csv}"
  fi
fi

# Silence options unused in contract-v2 for shellcheck
: "$VERBOSE" "$DETAIL_LIMIT" "$JOBS" "$MIN_SEVERITY" "$USER_RULE_DIR" "$NO_EMOJI" "$QUIET" "$CI_MODE" "$USE_COLOR"
: "$GREEN" "$YELLOW" "$BLUE" "$MAGENTA" "$CYAN" "$GRAY"
: "${SCRIPT_DIR}" "${PROJECT_DIR}" "${OUTPUT_FILE:-}" "${SOURCE_PROJECT_DIR:-}"

if [[ "$LIST_RULES" -eq 1 ]]; then
  QUIET=1
  USE_COLOR=0
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-javav2-rules.XXXXXX)"
  cleanup_add "$tmp_rules"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.java_rules import generate
generate(Path('$tmp_rules'))
" 2>/dev/null || true
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml 2>/dev/null || true ) | sort -u
  exit 0
fi

# ── Legacy-parity bridges for the contract-v2 path ──────────────────────────
run_v2_legacy_parity_bridges_java(){
  local sink="$1" list_file="$2" java_exit="$3" text_out="${4:-}"
  local files_n bridge_rc=0 java_version="unknown" proj_type="Unknown"
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  if [[ "$RUN_BUILD" -eq 1 ]]; then
    if command -v java >/dev/null 2>&1; then
      java_version="$(java -version 2>&1 | head -n1 || true)"
    fi
  fi
  [[ -f "$PROJECT_DIR/pom.xml" ]] && proj_type="Maven"
  if [[ -f "$PROJECT_DIR/build.gradle" || -f "$PROJECT_DIR/build.gradle.kts" ]]; then proj_type="Gradle"; fi
  python3 - "$sink" "$text_out" "$files_n" "${FAIL_ON_WARNING:-0}" "${SKIP_CATEGORIES:-}" \
    "$java_exit" "$java_version" "$proj_type" <<'PYV2BRIDGE' || bridge_rc=$?
import json
import sys

(sink_path, text_out, files_raw, fow_raw, skip_csv, java_exit_raw,
 java_version, proj_type) = sys.argv[1:9]
files_n = int(files_raw or 0)
fail_on_warning = fow_raw == "1"
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
java_exit = int(java_exit_raw or "0")
as_text = bool(text_out)

# Mirror java_scan._CATEGORY_SLUGS/_SECTION_HEADERS (legacy print_header titles).
SLUG = {1: "null-optional", 2: "equality", 3: "concurrency", 4: "security",
        5: "io", 6: "logging", 7: "regex", 8: "collections",
        9: "control-flow", 10: "streams-perf", 11: "serialization", 12: "java21",
        13: "sql", 14: "annotations", 15: "ast-grep", 16: "build",
        17: "inventory", 18: "api-misuse", 19: "resource-lifecycle",
        20: "filesystem", 21: "secrets", 22: "logging-practices"}
SECTION = {1: "1. NULL & OPTIONAL PITFALLS", 2: "2. EQUALITY & HASHCODE",
           3: "3. CONCURRENCY & THREADING", 4: "4. SECURITY",
           5: "5. I/O & RESOURCES", 6: "6. LOGGING & DEBUGGING",
           7: "7. REGEX & STRING PITFALLS", 8: "8. COLLECTIONS & GENERICS",
           9: "9. SWITCH & CONTROL FLOW", 10: "10. STREAMS & PERFORMANCE",
           11: "11. SERIALIZATION & COMPATIBILITY", 12: "12. JAVA 21 FEATURES (INFO)",
           13: "13. SQL CONSTRUCTION (HEURISTICS)", 14: "14. ANNOTATIONS & NULLNESS (HEURISTICS)",
           15: "15. AST-GREP RULE PACK FINDINGS", 16: "16. BUILD HEALTH (Maven/Gradle)",
           17: "17. META STATISTICS & INVENTORY", 18: "18. MISC API MISUSE",
           19: "19. RESOURCE SAFETY & RESOURCE LIFECYCLE CORRELATION",
           20: "20. PATH HANDLING & FILESYSTEM", 21: "21. HARD-CODED SECRETS (HEURISTICS)",
           22: "22. LOGGING BEST PRACTICES"}

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except OSError:
    records = []

def record_category(rec):
    rule = str(rec.get("rule", ""))
    category_id = str(rec.get("category_id", ""))
    for prefix, num in (("java.taint.", 4), ("java.resource.", 19),
                        ("java.async.", 3), ("java.optional.", 1),
                        ("kotlin.narrowing.", 1)):
        if rule.startswith(prefix):
            return num
    for num, slug in SLUG.items():
        if category_id == f"java.{slug}":
            return num
    if rule.startswith("java."):
        rest = rule[5:]
        for num, slug in SLUG.items():
            if rest.startswith(f"{slug}."):
                return num
    return None

categories_with_records = {record_category(rec) for rec in records}

out = []
if as_text:
    for num in sorted(SECTION):
        if num in skip:
            continue
        if not any(record_category(rec) == num for rec in records):
            out.append(SECTION[num])
        if num == 17:
            out.append(f"[info] Info (project: {proj_type}, java: {java_version}) — java.inventory.meta")
    out.append("")
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

# Final severity recount over the whole sink (legacy 5795-5797 inputs).
counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

if as_text:
    lines = [
        "",
        "Summary Statistics:",
        f"Files scanned: {files_n}",
        f"Critical issues: {counts['critical']}",
        f"Warning issues: {counts['warning']}",
        f"Info items: {counts['info']}",
    ]
    with open(text_out, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

exit_code = 1 if counts["critical"] else java_exit
if fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1
sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

run_contract_v2_java(){
  local list_file sink exit_code=0 ast_rule_dir="" text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-javav2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-javav2-sink.XXXXXX)"
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

  if command -v ast-grep >/dev/null 2>&1 && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-javav2-rules.XXXXXX)"
    if ! PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.java_rules import generate
generate(Path('$ast_rule_dir'))
" 2>/dev/null; then
      ast_rule_dir=""
    fi
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.java_rules import generate
generate(Path('$DUMP_RULES_DIR'))
" 2>/dev/null || true
  fi

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-javav2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-javav2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 java path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac

  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.java_scan \
    "${scan_args[@]}" --version "1.2.2" || exit_code=$?
  run_v2_legacy_parity_bridges_java "$sink" "$list_file" "$exit_code" "$text_out" || exit_code=$?

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

  if [[ -n "$SARIF_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" > "$SARIF_OUT" 2>/dev/null || true
  fi
  if [[ -n "$JSON_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    cp "$v2_json_out" "$JSON_OUT" 2>/dev/null || true
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
run_contract_v2_java || v2_status=$?
exit "$v2_status"
