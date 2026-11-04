#!/usr/bin/env bash
# UBS module: PostgreSQL SQL. Bounded migration/function security analysis.
# contract: v2. Native SQL analysis requires Python; no database is contacted.
set -Eeuo pipefail

# Bootstrap the same checksum-pinned shared library as the other modules.
UBS_LIB_CHECKSUM="112e0656b4aeeb72652119a1d51f61b908cbe598f31fcc2e4a14b09152d08f3c"
UBS_MODULE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
  if [[ -f "${UBS_VERIFIED_ASSET_DIR}/lib/ubs-common.sh" ]]; then
    UBS_MODULE_LIB_DIR="$UBS_VERIFIED_ASSET_DIR"
  elif [[ -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
    if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
      echo "warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified lib at ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" >&2
    else
      echo "ERROR: lib/ubs-common.sh is outside the verified asset directory; refusing to load it" >&2
      exit 2
    fi
  fi
fi
if [[ ! -f "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh" ]]; then
  echo "ERROR: missing ${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh (run 'ubs doctor --fix' or reinstall)" >&2
  exit 2
fi
if [[ -z "${UBS_VERIFIED_ASSET_DIR:-}" && "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" != "1" ]]; then
  _lib_sha=""
  if command -v sha256sum >/dev/null 2>&1; then
    _lib_output="$(sha256sum "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh")" || exit 2
    _lib_sha="${_lib_output%% *}"
  elif command -v shasum >/dev/null 2>&1; then
    _lib_output="$(shasum -a 256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh")" || exit 2
    _lib_sha="${_lib_output%% *}"
  elif command -v openssl >/dev/null 2>&1; then
    _lib_output="$(openssl dgst -sha256 "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh")" || exit 2
    _lib_sha="${_lib_output##* }"
  fi
  if [[ -z "$_lib_sha" || "$_lib_sha" != "$UBS_LIB_CHECKSUM" ]]; then
    echo "ERROR: cannot verify lib/ubs-common.sh (run 'ubs doctor --fix' or reinstall)" >&2
    exit 2
  fi
fi
# shellcheck source-path=SCRIPTDIR source=lib/ubs-common.sh
source "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh"
ubs_export_locale

VERSION="0.1.0"
PROJECT_DIR="."
SOURCE_PROJECT_DIR=""
PROJECT_SET=0
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
VERBOSE=0
QUIET=0
JOBS=0
INCLUDE_EXT="sql,psql,pgsql"
EXCLUDE_GLOBS=""
SKIP_CSV=""
ONLY_CSV=""
REPORT_JSON=""
FILES_FROM=""
CUSTOM_RULES_REQUESTED=0
JSON_OUT=""
SARIF_OUT=""
SUMMARY_JSON=""
LIST_RULES=0
LIST_CATEGORIES=0

usage(){
  cat <<'USAGE'
Usage: ubs-sql.sh [PROJECT_DIR|FILE] [options] [OUTPUT_FILE]

PostgreSQL migration DDL only. Function bodies and deployed catalog/ACL state
are not executed; unresolved relevant state produces incomplete analysis.

Options:
--format=FMT        text|json|sarif (default: text); jsonl/toon come from the meta-runner
--ci                stable timestamps (UTC ISO8601)
--fail-on-warning   exit 1 when warnings are found
-v, --verbose       print detailed text findings
-q, --quiet         print only the summary
--no-color          accepted; this module emits no ANSI colour
--jobs=N            parallel hint (bounded native analysis is sequential)
--exclude=GLOBS     additional path globs to skip
--include-ext=CSV   extra file extensions (default: sql,psql,pgsql)
--skip=CSV          skip category numbers (1 search-path, 2 privileges)
--only=CSV          run only these category numbers
--report-json=FILE  write NDJSON findings to FILE
--files-from=FILE   scan this exact NUL-separated file list
--rules=DIR         unsupported for SQL; exits 2 rather than ignoring requested rules
--list-rules        print native PostgreSQL rule ids and exit
--list-categories   print the category table and exit
--json-out=FILE     write JSON report to FILE
--sarif-out=FILE    write SARIF report to FILE
--summary-json=FILE write summary JSON to FILE
--project=DIR       project root recorded in reports
--version           print module version and exit
-h, --help          this help
contract: v2
USAGE
}

fail_scan(){
  local message="$1"
  printf 'ERROR: %s\n' "$message" >&2
  case "$FORMAT" in
    json)
      printf '{"language":"sql","project":"%s","files":0,"critical":0,"warning":0,"info":0,"status":"error","module_error":"ANALYZER_ERROR","message":"%s","findings":[]}\n' \
        "$(json_escape "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")" "$(json_escape "$message")";;
    sarif)
      printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ubs-sql"}},"results":[],"invocations":[{"executionSuccessful":false,"exitCode":2,"toolExecutionNotifications":[{"level":"error","descriptor":{"id":"ANALYZER_ERROR"},"message":{"text":"%s"}}]}]}]}\n' \
        "$(json_escape "$message")";;
    text)
      printf 'UBS module: PostgreSQL SQL (contract v2)\nPartial: [ANALYZER_ERROR] %s\nFiles scanned: 0\nCritical issues: 0\nWarning issues: 0\nInfo items: 0\n' "$message";;
  esac
  exit 2
}

require_value(){
  if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
    fail_scan "$1 requires a value"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format=*) FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --format) require_value "$@"; FORMAT="$2"; ubs_validate_format "$FORMAT"; shift 2;;
    --ci) CI_MODE=1; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    -v|--verbose) VERBOSE=1; shift;;
    -q|--quiet) QUIET=1; shift;;
    --no-color) shift;;
    --jobs=*) JOBS="${1#*=}"; shift;;
    --jobs) require_value "$@"; JOBS="$2"; shift 2;;
    --exclude=*) EXCLUDE_GLOBS="${1#*=}"; shift;;
    --exclude) require_value "$@"; EXCLUDE_GLOBS="$2"; shift 2;;
    --include-ext=*) INCLUDE_EXT="${INCLUDE_EXT},${1#*=}"; shift;;
    --include-ext) require_value "$@"; INCLUDE_EXT="${INCLUDE_EXT},$2"; shift 2;;
    --skip=*) SKIP_CSV="${1#*=}"; shift;;
    --skip) require_value "$@"; SKIP_CSV="$2"; shift 2;;
    --only=*) require_value --only "${1#*=}"; ONLY_CSV="${1#*=}"; shift;;
    --only) require_value "$@"; ONLY_CSV="$2"; shift 2;;
    --report-json=*) require_value --report-json "${1#*=}"; REPORT_JSON="${1#*=}"; shift;;
    --report-json) require_value "$@"; REPORT_JSON="$2"; shift 2;;
    --files-from=*) require_value --files-from "${1#*=}"; FILES_FROM="${1#*=}"; shift;;
    --files-from) require_value "$@"; FILES_FROM="$2"; shift 2;;
    --rules=*) CUSTOM_RULES_REQUESTED=1; shift;;
    --rules) require_value "$@"; CUSTOM_RULES_REQUESTED=1; shift 2;;
    --json-out=*) require_value --json-out "${1#*=}"; JSON_OUT="${1#*=}"; shift;;
    --json-out) require_value "$@"; JSON_OUT="$2"; shift 2;;
    --sarif-out=*) require_value --sarif-out "${1#*=}"; SARIF_OUT="${1#*=}"; shift;;
    --sarif-out) require_value "$@"; SARIF_OUT="$2"; shift 2;;
    --summary-json=*) require_value --summary-json "${1#*=}"; SUMMARY_JSON="${1#*=}"; shift;;
    --summary-json) require_value "$@"; SUMMARY_JSON="$2"; shift 2;;
    --project=*) require_value --project "${1#*=}"; SOURCE_PROJECT_DIR="${1#*=}"; shift;;
    --project) require_value "$@"; SOURCE_PROJECT_DIR="$2"; shift 2;;
    --list-rules) LIST_RULES=1; shift;;
    --list-categories) LIST_CATEGORIES=1; shift;;
    --version) printf 'ubs-sql %s\n' "$VERSION"; exit 0;;
    -h|--help) usage; exit 0;;
    -*) fail_scan "unknown option: $1";;
    *)
      if [[ "$PROJECT_SET" -eq 0 ]]; then PROJECT_DIR="$1"; PROJECT_SET=1
      elif [[ -z "$OUTPUT_FILE" ]]; then OUTPUT_FILE="$1"
      else fail_scan "unexpected argument: $1"
      fi
      shift;;
  esac
done
[[ "$CUSTOM_RULES_REQUESTED" -eq 0 ]] || fail_scan "--rules is unsupported for PostgreSQL SQL; requested custom rules cannot be evaluated"
[[ "$JOBS" =~ ^[0-9]+$ ]] || fail_scan "--jobs must be a nonnegative integer"
if [[ "$LIST_CATEGORIES" -eq 1 ]]; then
  printf '1  search-path  SECURITY DEFINER schema search order\n2  privileges   SECURITY DEFINER PUBLIC execution privileges\n'
  exit 0
fi
command -v python3 >/dev/null 2>&1 || fail_scan "PostgreSQL SQL analysis requires python3"
helpers_dir=""
ubs_resolve_helpers_dir helpers_dir || fail_scan "PostgreSQL SQL analysis helpers are unavailable or unverified"
export PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}"
if [[ "$LIST_RULES" -eq 1 ]]; then
  python3 -c 'from ubs_core.sql_scan import RULES; print("\n".join(sorted(RULES)))' || exit 2
  exit 0
fi
[[ -f "$PROJECT_DIR" || -d "$PROJECT_DIR" ]] || fail_scan "scan target does not exist: $PROJECT_DIR"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ubs-sql.XXXXXX")" || fail_scan "cannot allocate SQL scan workspace"
# Invocation-owned scratch follows the shared UBS_KEEP_TEMP retention policy.
# shellcheck disable=SC2329
cleanup(){
  [[ "${UBS_KEEP_TEMP:-0}" != "1" ]] || return 0
  ubs_remove_temp -f -- "$work_dir/files" "$work_dir/findings" "$work_dir/findings.cache" \
    "$work_dir/summary" "$work_dir/sarif" "$work_dir/text" "$work_dir/complete"
  rmdir -- "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT
source_dir="$PROJECT_DIR"
[[ ! -f "$source_dir" ]] || source_dir="$(dirname -- "$source_dir")"
if [[ -n "$FILES_FROM" ]]; then
  ubs_list_files "$source_dir" --files-from "$FILES_FROM" >"$work_dir/files" || fail_scan "cannot read the selected SQL file list"
elif [[ -f "$PROJECT_DIR" ]]; then
  printf '%s\0' "$PROJECT_DIR" >"$work_dir/files" || fail_scan "cannot write the selected SQL file list"
else
  list_args=("$PROJECT_DIR" --ext "$INCLUDE_EXT")
  [[ -z "$EXCLUDE_GLOBS" ]] || list_args+=(--exclude "$EXCLUDE_GLOBS")
  ubs_list_files "${list_args[@]}" >"$work_dir/files" || fail_scan "cannot enumerate SQL source files"
fi

scan_args=(--files-from "$work_dir/files" --sink "$work_dir/findings"
  --project-dir "$source_dir" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}"
  --version "$VERSION" --json-out "$work_dir/summary" --completion-out "$work_dir/complete")
[[ "$FORMAT" != text ]] || scan_args+=(--text-out "$work_dir/text")
if [[ "$FORMAT" == sarif || -n "$SARIF_OUT" ]]; then scan_args+=(--sarif-out "$work_dir/sarif"); fi
[[ -z "$SKIP_CSV" ]] || scan_args+=(--skip "$SKIP_CSV")
[[ -z "$ONLY_CSV" ]] || scan_args+=(--only "$ONLY_CSV")
[[ "$CI_MODE" -eq 0 ]] || scan_args+=(--ci)
[[ "$VERBOSE" -eq 0 ]] || scan_args+=(--verbose)
[[ "$QUIET" -eq 0 ]] || scan_args+=(--quiet)
[[ "$FAIL_ON_WARNING" -eq 0 ]] || scan_args+=(--fail-on-warning)
exit_code=0
python3 -m ubs_core.sql_scan "${scan_args[@]}" || exit_code=$?
if [[ ! -s "$work_dir/complete" || ! -s "$work_dir/summary" || "$exit_code" -gt 2 ]]; then
  fail_scan "SQL helper did not complete its reports"
fi
if ! python3 - "$work_dir/complete" "$work_dir/summary" "$exit_code" <<'PYRECEIPT'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        receipt = json.load(source)
    with open(sys.argv[2], encoding="utf-8") as source:
        report = json.load(source)
    status = report["status"]
    valid = (isinstance(receipt, dict) and report["language"] == "sql"
             and receipt.get("language") == "sql" and receipt.get("status") == status
             and type(receipt.get("exit_code")) is int
             and receipt["exit_code"] == int(sys.argv[3])
             and status in {"ok", "partial", "error"}
             and (status == "ok") == (int(sys.argv[3]) in {0, 1})
             and isinstance(report["findings"], list)
             and all(type(report[key]) is int and report[key] >= 0
                     for key in ("files", "critical", "warning", "info")))
except (OSError, ValueError, TypeError, KeyError, RecursionError):
    valid = False
raise SystemExit(0 if valid else 1)
PYRECEIPT
then
  fail_scan "SQL helper produced an invalid completion receipt or report"
fi
[[ "$FORMAT" != text || -s "$work_dir/text" ]] || fail_scan "SQL helper did not finish its text report"
if [[ "$FORMAT" == sarif || -n "$SARIF_OUT" ]]; then
  [[ -s "$work_dir/sarif" ]] || fail_scan "SQL helper did not finish its SARIF report"
fi
[[ -f "$work_dir/findings" ]] || fail_scan "SQL helper did not finish its NDJSON findings"

if [[ -n "$REPORT_JSON" ]]; then ubs_deliver_file "$work_dir/findings" "$REPORT_JSON" "NDJSON findings" || fail_scan "cannot deliver the requested NDJSON findings"; fi
if [[ -n "$JSON_OUT" ]]; then ubs_deliver_file "$work_dir/summary" "$JSON_OUT" "JSON report" || fail_scan "cannot deliver the requested JSON report"; fi
if [[ -n "$SUMMARY_JSON" ]]; then ubs_deliver_file "$work_dir/summary" "$SUMMARY_JSON" "summary JSON" || fail_scan "cannot deliver the requested summary JSON"; fi
if [[ -n "$SARIF_OUT" ]]; then ubs_deliver_file "$work_dir/sarif" "$SARIF_OUT" "SARIF report" || fail_scan "cannot deliver the requested SARIF report"; fi
case "$FORMAT" in
  json) result_file="$work_dir/summary";;
  sarif) result_file="$work_dir/sarif";;
  text) result_file="$work_dir/text";;
esac
if [[ -n "$OUTPUT_FILE" ]]; then
  ubs_deliver_file "$result_file" "$OUTPUT_FILE" "primary report" || fail_scan "cannot deliver the requested primary report"
else
  cat -- "$result_file" || exit_code=2
fi
exit "$exit_code"
