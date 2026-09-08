#!/usr/bin/env bash
# UBS module: Kotlin (kotlin). Comprehensive static analysis for Kotlin.
# contract: v2
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-kotlin.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="1169d9fe7a4dceebc8c6c9a2f856fb2eab8864fb1792ffd1a258695ff907684c"
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
# shellcheck source=modules/lib/ubs-common.sh
source "${UBS_MODULE_LIB_DIR}/lib/ubs-common.sh"
ubs_export_locale

VERSION="0.1.0"
LANGUAGE="kotlin"
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
VERBOSE=0
QUIET=0
JOBS=0
INCLUDE_EXT="kt,kts"
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
NO_COLOR_FLAG="${NO_COLOR:-}"
REPORT_JSON=""
FILES_FROM=""
USER_RULE_DIR=""
AST_RULE_DIR=""
DUMP_RULES_DIR=""
LIST_RULES=0
LIST_CATS=0
JSON_OUT=""
SARIF_OUT=""
SUMMARY_JSON=""
SOURCE_PROJECT_DIR=""

usage(){
  cat <<'USAGE'
Usage: ubs-kotlin.sh [PROJECT_DIR|FILE] [options] [OUTPUT_FILE]

Options:
  --format=FMT         text|json|sarif (default: text); jsonl/toon come from the meta-runner
  --ci                 stable timestamps (UTC ISO8601)
  --fail-on-warning    exit non-zero if any warnings or critical
  -v, --verbose        print more samples in text mode
  -q, --quiet          print only the summary
  --no-color           disable ANSI colour
  --jobs=N             parallel hint (propagated to child tools)
  --exclude=GLOBS      additional path globs to skip (forwarded by the meta-runner)
  --include-ext=CSV    extra file extensions to scan (default: kt,kts)
  --skip=CSV           skip category numbers (1-22)
  --only=CSV           run only these category numbers
  --report-json=FILE   write NDJSON findings sink to FILE
  --files-from=FILE    NUL-separated file list to scan
  --rules=DIR          merge custom ast-grep rules into the built-in pack
  --ast-rule-dir=DIR   explicit ast-grep rule directory
  --dump-rules[=DIR]   write the generated ast-grep rules to DIR
  --list-rules         print generated ast-grep rule ids and exit
  --list-categories    print the category table and exit
  --json-out=FILE      write JSON report to FILE
  --sarif-out=FILE     write SARIF report to FILE
  --summary-json=FILE  write summary JSON to FILE
  --project=DIR        project root directory
  --version            print module version and exit
  -h, --help           this help
contract: v2
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format=*) FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
    --format) FORMAT="${2:-}"; ubs_validate_format "$FORMAT"; shift 2;;
    --ci) CI_MODE=1; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    -v|--verbose) VERBOSE=1; shift;;
    -q|--quiet) QUIET=1; shift;;
    --no-color) NO_COLOR_FLAG=1; shift;;
    --jobs=*) JOBS="${1#*=}"; shift;;
    --exclude=*) EXTRA_EXCLUDES="${1#*=}"; shift;;
    --include-ext=*) INCLUDE_EXT="${INCLUDE_EXT},${1#*=}"; shift;;
    --skip=*) SKIP_CATEGORIES="${1#*=}"; shift;;
    --only=*) ONLY_CATEGORIES="${1#*=}"; shift;;
    --report-json=*) REPORT_JSON="${1#*=}"; shift;;
    --report-json) REPORT_JSON="${2:-}"; shift 2;;
    --files-from=*) FILES_FROM="${1#*=}"; shift;;
    --files-from) FILES_FROM="${2:-}"; shift 2;;
    --rules=*) USER_RULE_DIR="${1#*=}"; shift;;
    --rules) USER_RULE_DIR="${2:-}"; shift 2;;
    --ast-rule-dir=*) AST_RULE_DIR="${1#*=}"; shift;;
    --ast-rule-dir) AST_RULE_DIR="${2:-}"; shift 2;;
    --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
    --dump-rules) DUMP_RULES_DIR="${2:-rules-dump}"; shift 2;;
    --list-rules) LIST_RULES=1; shift;;
    --list-categories) LIST_CATS=1; shift;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --json-out) JSON_OUT="${2:-}"; shift 2;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --sarif-out) SARIF_OUT="${2:-}"; shift 2;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --summary-json) SUMMARY_JSON="${2:-}"; shift 2;;
    --project=*) SOURCE_PROJECT_DIR="${1#*=}"; shift;;
    --project) SOURCE_PROJECT_DIR="${2:-}"; shift 2;;
    --version) echo "ubs-kotlin $VERSION"; exit 0;;
    -h|--help) usage; exit 0;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2;;
    *) if [[ -e "$1" || -z "$OUTPUT_FILE" ]]; then
         if [[ -z "$OUTPUT_FILE" && ! -e "$1" && "$PROJECT_DIR" != "." ]]; then
           OUTPUT_FILE="$1"
         else
           PROJECT_DIR="$1"
         fi
       else
         OUTPUT_FILE="$1"
       fi
       shift;;
  esac
done

: "$JOBS" "$VERBOSE" "$QUIET" "$NO_COLOR_FLAG" "$LANGUAGE" "$CI_MODE"

if [[ "$LIST_CATS" -eq 1 ]]; then
  printf '1   type-narrowing      Kotlin null-safety & type narrowing\n'
  printf '2   equality            Equality & comparison pitfalls\n'
  printf '3   concurrency         Concurrency & coroutines\n'
  printf '4   security            Security, taint, path traversal & SSRF\n'
  printf '5   io                  I/O & resources\n'
  printf '6   logging             Logging & debugging\n'
  printf '7   regex               Regex & string pitfalls\n'
  printf '8   collections         Collections & generics\n'
  printf '9   control-flow        Control flow & switch\n'
  printf '10  performance         Performance & streams\n'
  printf '11  serialization       Serialization & compatibility\n'
  printf '12  features            Kotlin features\n'
  printf '13  sql                 SQL construction\n'
  printf '14  annotations         Annotations & nullness\n'
  printf '15  ast-grep            ast-grep rule pack findings\n'
  printf '16  build               Build health (Gradle)\n'
  printf '17  inventory           Meta statistics & inventory\n'
  printf '18  api-misuse          API misuse\n'
  printf '19  resource-lifecycle  Resource lifecycle & cleanup\n'
  printf '20  filesystem          Path handling & filesystem\n'
  printf '21  secrets             Hard-coded secrets\n'
  printf '22  logging-practices   Logging best practices\n'
  exit 0
fi

if [[ "$LIST_RULES" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="${UBS_MODULE_LIB_DIR}/helpers"
  PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}" python3 -c "
from pathlib import Path
import tempfile
from ubs_core.kotlin_rules import generate
with tempfile.TemporaryDirectory() as td:
    for rule in generate(Path(td)):
        print(rule)
" 2>/dev/null || true
  exit 0
fi

if [[ -n "$DUMP_RULES_DIR" ]]; then
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="${UBS_MODULE_LIB_DIR}/helpers"
  mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
  PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}" python3 -c "
from pathlib import Path
from ubs_core.kotlin_rules import generate
generate(Path('$DUMP_RULES_DIR'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  echo "Dumped rules to $DUMP_RULES_DIR"
  exit 0
fi

# File discovery
LIST_FILE="$(mktemp 2>/dev/null || mktemp -t ubs-kt-list.XXXXXX)"
SINK_FILE="$(mktemp 2>/dev/null || mktemp -t ubs-kt-sink.XXXXXX)"
JSON_TMP="$(mktemp 2>/dev/null || mktemp -t ubs-kt-json.XXXXXX)"
TEXT_TMP="$(mktemp 2>/dev/null || mktemp -t ubs-kt-text.XXXXXX)"
cleanup() {
  rm -f "$LIST_FILE" "$SINK_FILE" "$JSON_TMP" "$TEXT_TMP"
}
trap cleanup EXIT

if [[ -f "$PROJECT_DIR" ]]; then
  printf '%s\0' "$PROJECT_DIR" > "$LIST_FILE"
elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} > "$LIST_FILE"; then
  echo "ERROR: contract-v2 file list failed" >&2
  exit 2
fi

if [[ ! -s "$LIST_FILE" ]]; then
  empty_json="{\"language\":\"kotlin\",\"project\":\"${SOURCE_PROJECT_DIR:-$PROJECT_DIR}\",\"files\":0,\"critical\":0,\"warning\":0,\"info\":0,\"status\":\"ok\",\"findings\":[],\"categories\":{},\"ast_grep_rules\":0,\"extras\":{},\"uv_tools\":[]}"
  case "$FORMAT" in
    json)
      echo "$empty_json" > "${OUTPUT_FILE:-/dev/stdout}"
      ;;
    sarif)
      echo '{"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"ubs-kotlin","version":"0.1.0","rules":[]}},"results":[]}]}' > "${OUTPUT_FILE:-/dev/stdout}"
      ;;
    text)
      printf "UBS module: kotlin (contract v2) — %s\nFiles scanned: 0\nCritical issues: 0\nWarning issues: 0\nInfo items: 0\n" "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}" > "${OUTPUT_FILE:-/dev/stdout}"
      ;;
  esac
  exit 0
fi

# Run python engine
helpers_dir=""
ubs_resolve_helpers_dir helpers_dir || helpers_dir="${UBS_MODULE_LIB_DIR}/helpers"

scan_args=(
  --files-from "$LIST_FILE"
  --sink "$SINK_FILE"
  --project-dir "$PROJECT_DIR"
  --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}"
  --version "$VERSION"
  --json-out "$JSON_TMP"
  --text-out "$TEXT_TMP"
)

if [[ -n "$AST_RULE_DIR" ]]; then
  scan_args+=(--ast-rule-dir "$AST_RULE_DIR")
fi
if [[ -n "$SKIP_CATEGORIES" ]]; then
  scan_args+=(--skip "$SKIP_CATEGORIES")
fi
if [[ -n "$ONLY_CATEGORIES" ]]; then
  computed_skip=$(python3 -c "
only_set = {int(x) for x in '$ONLY_CATEGORIES'.split(',') if x.strip().isdigit()}
all_set = set(range(1, 23))
print(','.join(str(x) for x in sorted(all_set - only_set)))
")
  scan_args+=(--skip "$computed_skip")
fi
if [[ "$FAIL_ON_WARNING" -eq 1 ]]; then
  scan_args+=(--fail-on-warning)
fi

exit_code=0
PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}" python3 -m ubs_core.kotlin_scan "${scan_args[@]}" || exit_code=$?

if [[ -n "$REPORT_JSON" ]]; then
  cp "$SINK_FILE" "$REPORT_JSON"
fi

if [[ -n "$JSON_OUT" ]]; then
  cp "$JSON_TMP" "$JSON_OUT"
fi

if [[ -n "$SUMMARY_JSON" ]]; then
  cp "$JSON_TMP" "$SUMMARY_JSON"
fi

case "$FORMAT" in
  json)
    if [[ -n "$OUTPUT_FILE" ]]; then
      cp "$JSON_TMP" "$OUTPUT_FILE"
    else
      cat "$JSON_TMP"
    fi
    ;;
  sarif)
    sarif_content=$(PYTHONPATH="${helpers_dir}${PYTHONPATH:+:${PYTHONPATH}}" python3 -c "
import json
from ubs_core.kotlin_scan import _render_sarif
records = [json.loads(line) for line in open('$SINK_FILE') if line.strip()]
counters = {'critical': 0, 'warning': 0, 'info': 0}
for r in records:
    sev = r.get('severity', 'info')
    counters[sev] = counters.get(sev, 0) + 1
files = [line for line in open('$LIST_FILE').read().split('\0') if line.strip()]
sarif = _render_sarif(records, counters, '${SOURCE_PROJECT_DIR:-$PROJECT_DIR}', files)
print(json.dumps(sarif, indent=2))
")
    if [[ -n "$SARIF_OUT" ]]; then
      echo "$sarif_content" > "$SARIF_OUT"
    fi
    if [[ -n "$OUTPUT_FILE" ]]; then
      echo "$sarif_content" > "$OUTPUT_FILE"
    else
      echo "$sarif_content"
    fi
    ;;
  text)
    if [[ -n "$OUTPUT_FILE" ]]; then
      cp "$TEXT_TMP" "$OUTPUT_FILE"
    else
      cat "$TEXT_TMP"
    fi
    ;;
esac

exit "$exit_code"
