#!/usr/bin/env bash
# UBS module: PHP (php). Bounded native request/security analysis.
# contract: v2. Native rules need Python; optional custom rules need ast-grep.
set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="6e151c30dee84dd013ebba3172eb298551cd88910e3e7c44d1c26e661811bc69"
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
INCLUDE_EXT="php,phtml"
EXCLUDE_GLOBS=""
SKIP_CSV=""
ONLY_CSV=""
REPORT_JSON=""
FILES_FROM=""
USER_RULE_DIR=""
JSON_OUT=""
SARIF_OUT=""
SUMMARY_JSON=""
LIST_RULES=0
NO_COLOR_FLAG="${NO_COLOR:-}"

usage(){
  cat <<'USAGE'
Usage: ubs-php.sh [PROJECT_DIR|FILE] [options] [OUTPUT_FILE]

Options:
--format=FMT       text|json|sarif (default: text); jsonl/toon come from the meta-runner
--ci               stable timestamps (UTC ISO8601)
--fail-on-warning  exit non-zero if any warnings or critical
-v, --verbose      print more samples in text mode
-q, --quiet        print only the summary
--no-color         disable ANSI colour
--jobs=N           parallel hint (native analysis is bounded and sequential)
--exclude=GLOBS    additional path globs to skip (forwarded by the meta-runner)
--include-ext=CSV  extra file extensions to scan (default: php,phtml)
--skip=CSV         skip category numbers (1 SQL, 2 execution, 3 includes, 4 deserialization, 5 output)
--only=CSV         run only these category numbers
--report-json=FILE write NDJSON findings sink to FILE
--files-from=FILE  NUL-separated file list to scan
--rules=DIR        run custom ast-grep rules as an additional policy
--list-rules       print native PHP rule ids and exit
--list-categories  print the category table and exit
--json-out=FILE    write JSON report to FILE
--sarif-out=FILE   write SARIF report to FILE
--summary-json=FILE write summary JSON to FILE
--project=DIR      project root recorded in reports
--version          print module version and exit
-h, --help         this help
contract: v2
USAGE
}

require_value(){
  if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
    printf 'ERROR: %s requires a value\n' "$1" >&2
    exit 2
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
    --no-color) NO_COLOR_FLAG=1; shift;;
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
    --rules=*) require_value --rules "${1#*=}"; USER_RULE_DIR="${1#*=}"; shift;;
    --rules) require_value "$@"; USER_RULE_DIR="$2"; shift 2;;
    --json-out=*) require_value --json-out "${1#*=}"; JSON_OUT="${1#*=}"; shift;;
    --json-out) require_value "$@"; JSON_OUT="$2"; shift 2;;
    --sarif-out=*) require_value --sarif-out "${1#*=}"; SARIF_OUT="${1#*=}"; shift;;
    --sarif-out) require_value "$@"; SARIF_OUT="$2"; shift 2;;
    --summary-json=*) require_value --summary-json "${1#*=}"; SUMMARY_JSON="${1#*=}"; shift;;
    --summary-json) require_value "$@"; SUMMARY_JSON="$2"; shift 2;;
    --project=*) require_value --project "${1#*=}"; SOURCE_PROJECT_DIR="${1#*=}"; shift;;
    --project) require_value "$@"; SOURCE_PROJECT_DIR="$2"; shift 2;;
    --list-rules) LIST_RULES=1; shift;;
    --list-categories)
      printf '1  sql              SQL query construction and binding\n2  execution        Shell commands and dynamic code\n3  includes         Dynamic file inclusion\n4  deserialization  Untrusted object deserialization\n5  output           HTML output contexts\n'
      exit 0;;
    --version) printf 'ubs-php %s\n' "$VERSION"; exit 0;;
    -h|--help) usage; exit 0;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2;;
    *) if [[ "$PROJECT_SET" -eq 0 ]]; then PROJECT_DIR="$1"; PROJECT_SET=1
       elif [[ -z "$OUTPUT_FILE" ]]; then OUTPUT_FILE="$1"
       else printf 'ERROR: unexpected argument: %s\n' "$1" >&2; exit 2
       fi; shift;;
  esac
done
: "$NO_COLOR_FLAG"
[[ "$JOBS" =~ ^[0-9]+$ ]] || { echo "ERROR: --jobs must be a nonnegative integer" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: PHP analysis requires python3" >&2; exit 2; }
helpers_dir=""
ubs_resolve_helpers_dir helpers_dir || { echo "ERROR: PHP analysis helpers are unavailable" >&2; exit 2; }
export PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}"
if [[ "$LIST_RULES" -eq 1 ]]; then
  python3 -c 'from ubs_core.analyzers.taint_php import RULES; print("\n".join(sorted(RULES)))' || exit 2
  exit 0
fi
[[ -f "$PROJECT_DIR" || -d "$PROJECT_DIR" ]] || { printf 'ERROR: scan target does not exist: %s\n' "$PROJECT_DIR" >&2; exit 2; }
[[ -z "$USER_RULE_DIR" || -d "$USER_RULE_DIR" ]] || { printf 'ERROR: custom rule directory does not exist: %s\n' "$USER_RULE_DIR" >&2; exit 2; }

# Keep the report and completion receipt in one private invocation workspace.
# A crash or failed write cannot be mistaken for a completed clean analysis.
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ubs-php.XXXXXX")" || { echo "ERROR: cannot allocate PHP scan workspace" >&2; exit 2; }
# Called by Bash when this scanner exits; these are invocation-owned artifacts.
# shellcheck disable=SC2329
cleanup(){ rm -f -- "$work_dir/files" "$work_dir/findings" "$work_dir/findings.cache" "$work_dir/summary" "$work_dir/sarif" "$work_dir/text" "$work_dir/complete"; rmdir -- "$work_dir" 2>/dev/null || true; }
trap cleanup EXIT
source_dir="$PROJECT_DIR"
[[ ! -f "$source_dir" ]] || source_dir="$(dirname -- "$source_dir")"
if [[ -n "$FILES_FROM" ]]; then
  ubs_list_files "$source_dir" --files-from "$FILES_FROM" >"$work_dir/files" || exit 2
elif [[ -f "$PROJECT_DIR" ]]; then
  printf '%s\0' "$PROJECT_DIR" >"$work_dir/files" || exit 2
else
  list_args=("$PROJECT_DIR" --ext "$INCLUDE_EXT")
  [[ -z "$EXCLUDE_GLOBS" ]] || list_args+=(--exclude "$EXCLUDE_GLOBS")
  ubs_list_files "${list_args[@]}" >"$work_dir/files" || exit 2
fi
scan_args=(--files-from "$work_dir/files" --sink "$work_dir/findings"
  --project-dir "$source_dir" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}"
  --version "$VERSION" --json-out "$work_dir/summary" --completion-out "$work_dir/complete")
[[ "$FORMAT" != text ]] || scan_args+=(--text-out "$work_dir/text")
if [[ "$FORMAT" == sarif || -n "$SARIF_OUT" ]]; then scan_args+=(--sarif-out "$work_dir/sarif"); fi
[[ -z "$SKIP_CSV" ]] || scan_args+=(--skip "$SKIP_CSV")
[[ -z "$ONLY_CSV" ]] || scan_args+=(--only "$ONLY_CSV")
[[ -z "$USER_RULE_DIR" ]] || scan_args+=(--custom-rules "$USER_RULE_DIR")
[[ "$CI_MODE" -eq 0 ]] || scan_args+=(--ci)
[[ "$VERBOSE" -eq 0 ]] || scan_args+=(--verbose)
[[ "$QUIET" -eq 0 ]] || scan_args+=(--quiet)
[[ "$FAIL_ON_WARNING" -eq 0 ]] || scan_args+=(--fail-on-warning)
exit_code=0
python3 -m ubs_core.php_scan "${scan_args[@]}" || exit_code=$?
if [[ ! -s "$work_dir/complete" || ! -s "$work_dir/summary" || "$exit_code" -gt 2 ]]; then
  echo "ERROR: PHP helper did not finish its reports; analysis is incomplete" >&2
  case "$FORMAT" in
    json) printf '{"language":"php","project":"%s","files":0,"critical":0,"warning":0,"info":0,"status":"error","module_error":"ANALYZER_ERROR","message":"PHP helper did not complete its reports","findings":[]}\n' "$(json_escape "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")";;
    sarif) printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ubs-php"}},"results":[],"invocations":[{"executionSuccessful":false,"toolExecutionNotifications":[{"level":"error","descriptor":{"id":"ANALYZER_ERROR"},"message":{"text":"PHP helper did not complete its reports"}}]}]}]}';;
    text) printf 'UBS module: PHP (contract v2)\nPartial: [ANALYZER_ERROR] PHP helper did not complete its reports\nFiles scanned: 0\nCritical issues: 0\nWarning issues: 0\nInfo items: 0\n';;
  esac
  exit 2
fi
if [[ -n "$REPORT_JSON" ]]; then ubs_deliver_file "$work_dir/findings" "$REPORT_JSON" "NDJSON findings" || exit_code=2; fi
if [[ -n "$JSON_OUT" ]]; then ubs_deliver_file "$work_dir/summary" "$JSON_OUT" "JSON report" || exit_code=2; fi
if [[ -n "$SUMMARY_JSON" ]]; then ubs_deliver_file "$work_dir/summary" "$SUMMARY_JSON" "summary JSON" || exit_code=2; fi
if [[ -n "$SARIF_OUT" ]]; then ubs_deliver_file "$work_dir/sarif" "$SARIF_OUT" "SARIF report" || exit_code=2; fi
case "$FORMAT" in
  json) result_file="$work_dir/summary";;
  sarif) result_file="$work_dir/sarif";;
  text) result_file="$work_dir/text";;
esac
if [[ -n "$OUTPUT_FILE" ]]; then ubs_deliver_file "$result_file" "$OUTPUT_FILE" "primary report" || exit_code=2
else cat -- "$result_file" || exit_code=2
fi
exit "$exit_code"
