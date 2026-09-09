#!/usr/bin/env bash
# UBS module: Bash (bash). Comprehensive static analysis for Bash/POSIX-sh.
# contract: v2
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-bash.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
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
ubs_export_locale

VERSION="0.1.0"
LANGUAGE="bash"
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"
CI_MODE=0
FAIL_ON_WARNING=0
VERBOSE=0
QUIET=0
JOBS=0
INCLUDE_EXT="sh,bash"
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
NO_SHELLCHECK=0
JSON_OUT=""
SARIF_OUT=""
SUMMARY_JSON=""
SOURCE_PROJECT_DIR=""

usage(){
  cat <<'USAGE'
Usage: ubs-bash.sh [PROJECT_DIR|FILE] [options] [OUTPUT_FILE]

Options:
  --format=FMT         text|json|sarif (default: text); jsonl/toon come from the meta-runner
  --ci                 stable timestamps (UTC ISO8601)
  --fail-on-warning    exit non-zero if any warnings or critical
  -v, --verbose        print more samples in text mode
  -q, --quiet          print only the summary
  --no-color           disable ANSI colour
  --jobs=N             parallel hint (propagated to child tools)
  --exclude=GLOBS      additional path globs to skip (forwarded by the meta-runner)
  --include-ext=CSV    extra file extensions to scan (default: sh,bash)
  --skip=CSV           skip category numbers (1-6)
  --only=CSV           run only these category numbers
  --report-json=FILE   write NDJSON findings sink to FILE
  --files-from=FILE    NUL-separated file list to scan
  --rules=DIR          merge custom ast-grep rules into the built-in pack
  --ast-rule-dir=DIR   explicit ast-grep rule directory
  --dump-rules[=DIR]   write the generated ast-grep rules to DIR
  --list-rules         print generated ast-grep rule ids and exit
  --list-categories    print the category table and exit
  --no-shellcheck      disable ShellCheck integration
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
    --no-shellcheck) NO_SHELLCHECK=1; shift;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --json-out) JSON_OUT="${2:-}"; shift 2;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --sarif-out) SARIF_OUT="${2:-}"; shift 2;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --summary-json) SUMMARY_JSON="${2:-}"; shift 2;;
    --project=*) SOURCE_PROJECT_DIR="${1#*=}"; shift;;
    --project) SOURCE_PROJECT_DIR="${2:-}"; shift 2;;
    --version) echo "ubs-bash $VERSION"; exit 0;;
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
  printf '1  syntax        Bash syntax & arithmetic gotchas\n'
  printf '2  control-flow  Control flow & exit codes\n'
  printf '3  security      Security & dangerous commands\n'
  printf '4  robustness    Defensive programming & robustness\n'
  printf '5  environment   Environment & locale hygiene\n'
  printf '6  shellcheck    ShellCheck analysis\n'
  exit 0
fi

if [[ "$LIST_RULES" -eq 1 ]]; then
  if ! command -v ast-grep >/dev/null 2>&1 || [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" == "1" ]]; then
    echo "ERROR: --list-rules requires ast-grep." >&2
    exit 2
  fi
  helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"
  tmp_rules="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-bashv2-rules.XXXXXX)"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.bash_rules import generate
generate(Path('$tmp_rules'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$tmp_rules"/rules/*.yml "$tmp_rules"/*.yml 2>/dev/null || true ) | sort -u
  rm -rf "$tmp_rules" 2>/dev/null || true
  exit 0
fi

run_contract_v2_bash(){
  local list_file sink exit_code=0 text_out="" v2_json_out=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-bashv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-bashv2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers"

  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" ${EXTRA_EXCLUDES:+--exclude "$EXTRA_EXCLUDES"} ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    rm -f "$list_file" "$sink" 2>/dev/null || true
    return 2
  fi

  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in 1 2 3 4 5 6; do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi

  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  [[ "$NO_SHELLCHECK" -eq 1 ]] && scan_args+=(--no-shellcheck)

  local ast_rule_dir="$AST_RULE_DIR"
  local created_ast_dir=""
  if [[ -z "$ast_rule_dir" ]] && command -v ast-grep >/dev/null 2>&1 && [[ "${UBS_TEST_FORCE_NO_AST_GREP:-0}" != "1" ]]; then
    created_ast_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-bashv2-rules.XXXXXX)"
    if PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.bash_rules import generate
generate(Path('$created_ast_dir'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null; then
      ast_rule_dir="$created_ast_dir"
    else
      rm -rf "$created_ast_dir" 2>/dev/null || true
      created_ast_dir=""
    fi
  fi
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")

  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR" 2>/dev/null || true
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from pathlib import Path
from ubs_core.bash_rules import generate
generate(Path('$DUMP_RULES_DIR'), Path('$USER_RULE_DIR') if '$USER_RULE_DIR' else None)
" 2>/dev/null || true
  fi

  case "$FORMAT" in
    json|sarif)
      v2_json_out="$(mktemp 2>/dev/null || mktemp -t ubs-bashv2-json.XXXXXX)"
      scan_args+=(--json-out "$v2_json_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    text)
      text_out="$(mktemp 2>/dev/null || mktemp -t ubs-bashv2-text.XXXXXX)"
      scan_args+=(--text-out "$text_out" --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}")
      ;;
    *) echo "ERROR: contract-v2 bash path supports text|json|sarif (got $FORMAT)" >&2; return 2 ;;
  esac

  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core.bash_scan \
    "${scan_args[@]}" --version "$VERSION" || exit_code=$?

  if [[ "$FORMAT" == "sarif" ]]; then
    if [[ -n "$v2_json_out" && -f "$v2_json_out" ]]; then
      if [[ -n "$OUTPUT_FILE" ]]; then
        PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null | tee "$OUTPUT_FILE" || true
      else
        PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" 2>/dev/null || true
      fi
    fi
  fi

  if [[ -n "$text_out" ]]; then
    if [[ -n "$OUTPUT_FILE" ]]; then
      cat "$text_out" 2>/dev/null | tee "$OUTPUT_FILE" || true
    else
      cat "$text_out" 2>/dev/null || true
    fi
    rm -f "$text_out" 2>/dev/null || true
  fi

  if [[ -n "$v2_json_out" && "$FORMAT" == "json" ]]; then
    if [[ -n "$OUTPUT_FILE" ]]; then
      cat "$v2_json_out" 2>/dev/null | tee "$OUTPUT_FILE" || true
    else
      cat "$v2_json_out" 2>/dev/null || true
    fi
  fi

  if [[ -n "$SARIF_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m ubs_core findings-sarif --combined "$v2_json_out" > "$SARIF_OUT" 2>/dev/null || true
  fi
  if [[ -n "$JSON_OUT" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    cp "$v2_json_out" "$JSON_OUT" 2>/dev/null || true
  fi
  if [[ -n "$SUMMARY_JSON" && -n "$v2_json_out" && -f "$v2_json_out" ]]; then
    cp "$v2_json_out" "$SUMMARY_JSON" 2>/dev/null || true
  fi

  if [[ -n "$v2_json_out" ]]; then
    rm -f "$v2_json_out" 2>/dev/null || true
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  [[ -n "$created_ast_dir" ]] && rm -rf -- "$created_ast_dir" 2>/dev/null || true
  return "$exit_code"
}

v2_status=0
run_contract_v2_bash || v2_status=$?
exit "$v2_status"
