#!/usr/bin/env bash
# shellcheck disable=SC2002,SC2015,SC2034,SC2317
# UBS C# ULTIMATE BUG SCANNER v3.0.2
# Industrial-grade bug & footgun scanner for C#/.NET codebases on contract v2.
#
# Usage:
#   bash modules/ubs-csharp.sh [PROJECT_DIR] [options]
#
# Key options:
#   --format=text|json|sarif
#   --only=1,2,3        Run only specific categories
#   --skip=4,9          Skip categories
#   --ci                CI-friendly output + non-zero on critical
#   --strict-gitignore  Respect .gitignore
#   --no-dotnet         Skip dotnet build/test/format/list package checks
#   --summary-json=FILE Write machine-readable summary JSON
#   --emit-findings-json=FILE Write full findings JSON (same as stdout in --format=json)

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-csharp.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail

# Shared primitives (bead A1): locale export, json_escape, format contract,
# NUL-safe file listing. Shipped and checksum-verified next to the modules.
UBS_LIB_CHECKSUM="4f451cc49a55ab12cd481d07f570b330f933143802d06af309ffb50152efbe86"
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
shopt -s lastpipe 2>/dev/null || true

VERSION="3.0.2"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_DIR="."
FORMAT="text"        # text|json|sarif
CI_MODE=0
QUIET=0
VERBOSE=0
NO_COLOR_FLAG=0
DETAIL_LIMIT=5
JOBS=""
STRICT_GITIGNORE=0

ONLY_CATEGORIES=""
SKIP_CATEGORIES=""

INCLUDE_EXT="cs,csx"
EXCLUDE_DIRS=".git,.hg,.svn,bin,obj,.vs,.idea,.vscode,node_modules,packages,dist,build,out,artifacts,coverage,.terraform,.venv,target"
EXTRA_EXCLUDE_DIRS=""
EXCLUDE_GLOBS=""

SUMMARY_JSON=""
EMIT_FINDINGS_JSON=""
REPORT_JSON=""
FILES_FROM=""
DUMP_RULES_DIR=""
EXTRA_AST_RULES_DIRS=""
LIST_RULES=0

NO_DOTNET=0
NO_DOTNET_BUILD=0
NO_DOTNET_TEST=0
NO_DOTNET_FORMAT=0
NO_DOTNET_DEPS=0
DOTNET_TARGET=""

FAIL_ON_WARNING=0
FAIL_CRITICAL_N=""
FAIL_WARNING_N=""

# ---------- colors ----------
RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; DIM=""; RESET=""
init_colors() {
  if [[ "$NO_COLOR_FLAG" -eq 1 || -n "${NO_COLOR:-}" || ! -t 1 ]]; then
    return 0
  fi
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
  MAGENTA=$'\033[35m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'
  RESET=$'\033[0m'
}

ICON_OK="✅"; ICON_WARN="⚠️"; ICON_CRIT="🚨"; ICON_INFO="ℹ️"; ICON_DOT="•"

# ---------- traps ----------
TMP_DIR=""
cleanup() {
  [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR" || true
}
on_err() {
  local exit_code=$?
  local line=${1:-"?"}
  echo ""
  echo "${RED}${ICON_CRIT} UBS-C# crashed at line ${line} (exit ${exit_code}).${RESET}" >&2
  echo "${DIM}Tip: rerun with --verbose and/or --no-dotnet to isolate.${RESET}" >&2
  exit "$exit_code"
}
trap cleanup EXIT
trap 'on_err $LINENO' ERR

# ---------- helpers ----------
die() { echo "${RED}${ICON_CRIT} $*${RESET}" >&2; exit 2; }
note() { [[ "$QUIET" -eq 1 ]] && return 0; echo "${CYAN}${ICON_INFO} $*${RESET}"; }
warn() { [[ "$QUIET" -eq 1 ]] && return 0; echo "${YELLOW}${ICON_WARN} $*${RESET}"; }
ok()   { [[ "$QUIET" -eq 1 ]] && return 0; echo "${GREEN}${ICON_OK} $*${RESET}"; }

filter_file_list_with_globs() {
  local out="$1"
  [[ -n "$EXCLUDE_GLOBS" ]] || return 0
  [[ "$HAS_PYTHON" -eq 1 ]] || return 0

  local tmp="$TMP_DIR/filelist.exclude"
  python3 - "$PROJECT_DIR" "$out" "$tmp" "$EXCLUDE_GLOBS" <<'PY' 2>/dev/null || return 0
import fnmatch
import os
import sys

project_dir, in_path, out_path, csv = sys.argv[1:5]
patterns = []
for raw in csv.split(","):
    pat = raw.strip().replace("\\", "/")
    if not pat:
        continue
    if pat.startswith("./"):
        pat = pat[2:]
    if pat.startswith("/"):
        pat = pat[1:]
    patterns.append(pat.rstrip("/"))

with open(in_path, "rb") as fh:
    paths = [p.decode("utf-8", "ignore") for p in fh.read().split(b"\0") if p]

with open(out_path, "wb") as out:
    for path in paths:
        rel = os.path.relpath(path, project_dir).replace(os.sep, "/")
        skip = False
        for pat in patterns:
            if (
                fnmatch.fnmatch(rel, pat)
                or fnmatch.fnmatch(rel, f"{pat}/**")
                or rel.startswith(f"{pat}/")
                or fnmatch.fnmatch(os.path.basename(rel), pat)
            ):
                skip = True
                break
        if not skip:
            out.write(path.encode("utf-8", "ignore") + b"\0")
PY
  mv "$tmp" "$out"
}

# ---------- tool detection ----------
HAS_RG=0
HAS_AST_GREP=0
HAS_DOTNET=0
HAS_PYTHON=0
AST_GREP_CMD=()

ast_grep_candidate_valid() {
  local version=""
  if ! version="$("$@" --version 2>/dev/null)"; then
    return 1
  fi
  printf '%s' "$version" | grep -qi 'ast-grep'
}

set_ast_grep_candidate() {
  if ast_grep_candidate_valid "$@"; then
    HAS_AST_GREP=1
    AST_GREP_CMD=("$@")
    return 0
  fi
  return 1
}

detect_tools() {
  if command -v rg >/dev/null 2>&1; then HAS_RG=1; fi
  if command -v python3 >/dev/null 2>&1; then HAS_PYTHON=1; fi

  # Prefer ast-grep binary if present
  if command -v ast-grep >/dev/null 2>&1 && set_ast_grep_candidate ast-grep; then
    :
  elif command -v sg >/dev/null 2>&1; then
    # Avoid unix "sg" (setgid) collision: check it looks like ast-grep
    if set_ast_grep_candidate sg; then
      :
    fi
  elif command -v npx >/dev/null 2>&1 && set_ast_grep_candidate npx -y @ast-grep/cli; then
    # Fallback: node-based ast-grep
    :
  fi

  if command -v dotnet >/dev/null 2>&1; then HAS_DOTNET=1; fi
}

AST_GREP_RUN_STYLE=0
detect_ast_grep_style() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  if "${AST_GREP_CMD[@]}" run --help >/dev/null 2>&1; then
    AST_GREP_RUN_STYLE=1
  fi
}

# ---------- ast-grep rules ----------
AST_RULES_DIR=""
AST_CONFIG_FILE=""

write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULES_DIR="$TMP_DIR/ast-rules"
  mkdir -p "$AST_RULES_DIR"

  cat >"$AST_RULES_DIR/cs-async-discarded-task-run.yml"<<'YAML'
id: cs-async-discarded-task-run
message: "Task.Run result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Run($ARG);
    - pattern: _ = Task.Run($ARG);
YAML

  cat >"$AST_RULES_DIR/cs-async-discarded-startnew.yml"<<'YAML'
id: cs-async-discarded-startnew
message: "Task.Factory.StartNew result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Factory.StartNew($ARG);
    - pattern: _ = Task.Factory.StartNew($ARG);
YAML

  cat >"$AST_RULES_DIR/cs-await-in-lock.yml"<<'YAML'
id: cs-await-in-lock
message: "Await inside lock can deadlock or break monitor assumptions; move async work outside the lock."
severity: warning
language: csharp
rule:
  pattern: |
    lock ($OBJ) { await $EXPR; }
YAML

  cat >"$AST_RULES_DIR/cs-parallel-foreach-async-lambda.yml"<<'YAML'
id: cs-parallel-foreach-async-lambda
message: "Parallel.ForEach with async lambda does not await the async work; use Parallel.ForEachAsync or gather Tasks."
severity: warning
language: csharp
rule:
  any:
    - pattern: Parallel.ForEach($SRC, async $ITEM => $EXPR);
    - pattern: Parallel.ForEach($SRC, async ($ITEM) => $EXPR);
    - pattern: |
        Parallel.ForEach($SRC, async $ITEM => { await $EXPR; });
YAML

  # Config file
  AST_CONFIG_FILE="$TMP_DIR/astconfig.yml"
  cat >"$AST_CONFIG_FILE"<<YAML
ruleDirs:
  - $AST_RULES_DIR
YAML

  # Include extra rule dirs
  if [[ -n "$EXTRA_AST_RULES_DIRS" ]]; then
    local IFS=','; read -r -a extras <<<"$EXTRA_AST_RULES_DIRS"
    local d
    for d in "${extras[@]}"; do
      [[ -z "$d" ]] && continue
      echo "  - $d" >>"$AST_CONFIG_FILE"
    done
  fi

  if [[ -n "$DUMP_RULES_DIR" ]]; then
    mkdir -p "$DUMP_RULES_DIR"
    cp "$AST_RULES_DIR"/*.yml "$DUMP_RULES_DIR/" 2>/dev/null || true
  fi
}

list_generated_ast_rule_ids() {
  local rules_dir="$1"
  ( set +o pipefail; awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$rules_dir"/*.yml 2>/dev/null || true ) | sort -u
}

# ---------- categories ----------
declare -A CATEGORY_NAMES=(
  [1]="Exceptions & Nullability Hazards"
  [2]="Resources & IDisposable Footguns"
  [3]="Concurrency & Async Pitfalls"
  [4]="Numeric & Floating-Point Traps"
  [5]="Collections & LINQ Gotchas"
  [6]="Strings & Allocation Smells"
  [7]="Filesystem / Process / IO Risks"
  [8]="Security Red Flags"
  [9]="Code Quality Markers"
  [10]="API Misuse & Correctness"
  [11]="Tests / Debug Leftovers"
  [12]="Formatting & Analyzer Signals"
  [13]="Build & Test Health"
  [14]="Dependency Hygiene (NuGet)"
  [15]="Exception Handling Anti-patterns"
  [16]="ASP.NET / Web Pitfalls"
  [17]="AST-Grep Rule Pack"
  [18]="Project Inventory"
  [19]="Resource Lifecycle Correlation"
  [20]="Async Locks / Semaphores / Await-in-Lock"
  [21]="Exception Surfaces & Rethrow Issues"
  [22]="Suspicious Casts & Truncation"
  [23]="Parsing & Validation Robustness"
  [24]="Perf / DoS Hotspots"
)

list_categories() {
  local k
  for k in $(printf "%s\n" "${!CATEGORY_NAMES[@]}" | sort -n); do
    echo "$k - ${CATEGORY_NAMES[$k]}"
  done
}

# ---------- analysis steps ----------
banner() {
  if [[ "$QUIET" -eq 1 || "$FORMAT" != "text" ]]; then
    return 0
  fi
  cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║                  UBS C# ULTIMATE BUG SCANNER                     ║
║                     Industrial-Grade Edition                     ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
}

usage() {
  cat <<EOF
$SCRIPT_NAME v$VERSION - UBS C# ULTIMATE BUG SCANNER

Usage:
  $SCRIPT_NAME [PROJECT_DIR] [options]

Options:
  --format=text|json|sarif     Output format (default: text)
  --ci                         CI mode (no emojis, non-zero on critical)
  --quiet                      Less console output
  --verbose                    More sample findings per rule
  --no-color                   Disable colors
  --include-ext=cs,csx         File extensions to scan (default: $INCLUDE_EXT)
  --exclude-dirs=csv           Override excluded dir list
  --extra-exclude-dirs=csv     Add extra excluded dirs
  --exclude=csv                Additional ignore globs/directories (meta-runner compatible)
  --jobs=N                     rg threads
  --strict-gitignore           Respect .gitignore (and git check-ignore when rg missing)

  --only=1,2,3                 Run only these categories
  --skip=4,9                   Skip these categories
  --list-categories            Print category list and exit

  --rules=DIR[,DIR]            Extra ast-grep rule directories
  --dump-rules=DIR             Dump generated ast rules + config
  --list-rules                 List generated ast-grep rule IDs and exit

  --no-dotnet                  Skip all dotnet CLI checks
  --no-build                   Skip dotnet build
  --no-test                    Skip dotnet test
  --no-format                  Skip dotnet format
  --no-deps                    Skip dotnet list package
  --dotnet-target=PATH         Build/test/list packages against this .sln/.csproj

  --fail-on-warning            Non-zero if any warnings are found
  --fail-critical=N            Non-zero if critical findings >= N
  --fail-warning=N             Non-zero if warnings >= N

  --summary-json=FILE          Write summary JSON to file
  --emit-findings-json=FILE    Write full findings JSON to file (or use --format=json)
contract: v2

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0;;
      --format=*) FORMAT="${1#*=}"; ubs_validate_format "$FORMAT"; shift;;
      --ci) CI_MODE=1; shift;;
      --quiet|-q) QUIET=1; shift;;
      --verbose|-v) VERBOSE=1; DETAIL_LIMIT=15; shift;;
      --no-color) NO_COLOR_FLAG=1; shift;;
      --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
      --exclude-dirs=*) EXCLUDE_DIRS="${1#*=}"; shift;;
      --extra-exclude-dirs=*) EXTRA_EXCLUDE_DIRS="${1#*=}"; shift;;
      --exclude=*) EXCLUDE_GLOBS="${1#*=}"; shift;;
      --jobs=*) JOBS="${1#*=}"; shift;;
      --strict-gitignore) STRICT_GITIGNORE=1; shift;;

      --only=*) ONLY_CATEGORIES="${1#*=}"; shift;;
      --skip=*) SKIP_CATEGORIES="${1#*=}"; shift;;
      --list-categories) list_categories; exit 0;;

      --rules=*) EXTRA_AST_RULES_DIRS="${1#*=}"; shift;;
      --dump-rules=*) DUMP_RULES_DIR="${1#*=}"; shift;;
      --list-rules) LIST_RULES=1; shift;;

      --no-dotnet) NO_DOTNET=1; shift;;
      --no-build) NO_DOTNET_BUILD=1; shift;;
      --no-test) NO_DOTNET_TEST=1; shift;;
      --no-format) NO_DOTNET_FORMAT=1; shift;;
      --no-deps) NO_DOTNET_DEPS=1; shift;;
      --dotnet-target=*) DOTNET_TARGET="${1#*=}"; shift;;

      --fail-on-warning) FAIL_ON_WARNING=1; shift;;
      --fail-critical=*) FAIL_CRITICAL_N="${1#*=}"; shift;;
      --fail-warning=*) FAIL_WARNING_N="${1#*=}"; shift;;

      --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
      --emit-findings-json=*) EMIT_FINDINGS_JSON="${1#*=}"; shift;;
      --report-json=*) REPORT_JSON="${1#*=}"; shift;;
      --files-from=*) FILES_FROM="${1#*=}"; shift;;
      --files-from)   FILES_FROM="${2:-}"; shift 2;;

      --) shift; break;;
      -*)
        die "Unknown option: $1"
        ;;
      *)
        PROJECT_DIR="$1"; shift;;
    esac
  done

  case "$FORMAT" in
    text|json|sarif) ;;
    *) die "--format must be text|json|sarif";;
  esac

  if [[ "$CI_MODE" -eq 1 ]]; then
    NO_COLOR_FLAG=1
    ICON_OK="[OK]"; ICON_WARN="[WARN]"; ICON_CRIT="[CRIT]"; ICON_INFO="[INFO]"; ICON_DOT="*"
  fi
  if [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; then
    QUIET=1
    NO_COLOR_FLAG=1
  fi

  [[ -d "$PROJECT_DIR" || -f "$PROJECT_DIR" ]] || die "Project directory not found: $PROJECT_DIR"
  if [[ -d "$PROJECT_DIR" ]]; then
    PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
  else
    local project_dir_base project_dir_name
    project_dir_base="$(cd "$(dirname "$PROJECT_DIR")" && pwd)"
    project_dir_name="$(basename "$PROJECT_DIR")"
    PROJECT_DIR="$project_dir_base/$project_dir_name"
  fi
}

: "$VERBOSE" "$JOBS" "$NO_DOTNET_BUILD" "$NO_DOTNET_TEST" "$NO_DOTNET_DEPS" "$DOTNET_TARGET" "$AST_GREP_RUN_STYLE"
: "${AST_CONFIG_FILE:-}"

# ═══════════════════════════════════════════════════════════════════════════
# Contract-v2 path (bead 0xjg.12): ONE file list (ubs_list_files), ONE python
#    orchestrator (ubs_core.csharp_scan), NDJSON findings sink (K2 schema).
# ── Legacy-parity bridge: record-less headers + summary json + exit code ────
run_v2_legacy_parity_bridges_csharp(){
  local sink="$1" list_file="$2" scan_exit="$3" text_out="${4:-}" skip_csv="${5:-}" ast_ran="${6:-0}"
  local files_n bridge_rc=0
  files_n="$(tr -dc '\0' <"$list_file" 2>/dev/null | wc -c)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$SCRIPT_DIR/helpers"
  PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 - "$sink" "$text_out" "$files_n" "$scan_exit" "$skip_csv" \
    "${FAIL_ON_WARNING:-0}" "${FAIL_CRITICAL_N:-}" "${FAIL_WARNING_N:-}" \
    "$CI_MODE" "$FORMAT" "${SUMMARY_JSON:-}" \
    "${HAS_RG:-0}" "${HAS_AST_GREP:-0}" "${HAS_DOTNET:-0}" "${STRICT_GITIGNORE:-0}" \
    "$VERSION" "$NO_DOTNET" "$NO_DOTNET_FORMAT" \
    "${ast_ran:-0}" <<'PYV2BRIDGE' || bridge_rc=$?
import datetime
import json
import os
import sys

(sink_path, text_out, files_raw, scan_exit_raw, skip_csv, fow_raw, fcrit_raw,
 fwarn_raw, ci_raw, fmt, summary_json, has_rg, has_ast, has_dotnet,
 strict_gi, version, no_dotnet, no_dotnet_format, ast_ran) = sys.argv[1:20]
files_n = int(files_raw or 0)
scan_exit = int(scan_exit_raw or 0)
fail_on_warning = fow_raw == "1"
fail_crit = int(fcrit_raw) if fcrit_raw.strip().lstrip("-").isdigit() and int(fcrit_raw) >= 0 else -1
fail_warn = int(fwarn_raw) if fwarn_raw.strip().lstrip("-").isdigit() and int(fwarn_raw) >= 0 else -1
ci = ci_raw == "1"
as_text = bool(text_out)
skip = {int(x) for x in skip_csv.split(",") if x.strip().isdigit()}
ast_ran = ast_ran == "1"

try:
    with open(sink_path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
except (OSError, ValueError):
    records = []

counts = {"critical": 0, "warning": 0, "info": 0}
for rec in records:
    sev = rec.get("severity", "info")
    counts[sev if sev in counts else "info"] += 1

exit_code = 1 if counts["critical"] > 0 else (scan_exit if scan_exit in (0, 1) else scan_exit)
if fail_crit >= 0 and counts["critical"] >= fail_crit:
    exit_code = 1
if fail_warn >= 0 and counts["warning"] >= fail_warn:
    exit_code = 1
elif fail_on_warning and (counts["critical"] + counts["warning"]) > 0:
    exit_code = 1

# Helper statuses (legacy emit_summary_json "helpers" block), derived from
# the sink: the A2 analyzers always ran in-process when we got here.
def has_rule(prefix):
    return any(str(rec.get("rule", "")).startswith(prefix) for rec in records)

if os.environ.get("UBS_SKIP_TYPE_NARROWING", "0") == "1":
    type_narrowing = "skipped"
else:
    type_narrowing = "used" if has_rule("csharp.narrowing.") else "clean"
resource_lifecycle = "used" if has_rule("csharp.lifecycle.") else "clean"
async_handles = "used" if has_rule("csharp.async.unobserved_task_handle") else "clean"

# Summary document: legacy emit_summary_json shape + v2 sink records.
doc = {
    "language": "csharp",
    "project": os.environ.get("UBS_V2_PROJECT", ""),
    "files": files_n,
    "critical": counts["critical"],
    "warning": counts["warning"],
    "info": counts["info"],
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "format": fmt,
    "tool": "ubs-csharp",
    "version": version,
    "status": "ok",
    "tooling": {"rg": int(has_rg or 0), "ast_grep": int(has_ast or 0),
                "dotnet": int(has_dotnet or 0), "python3": 1},
    "helpers": {"type_narrowing": type_narrowing,
                "resource_lifecycle": resource_lifecycle,
                "async_task_handles": async_handles},
    "exit_code": exit_code,
    "findings": records,
}
if summary_json:
    try:
        with open(summary_json, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
            fh.write("\n")
    except OSError:
        pass

out = []

def emit(line=""):
    out.append(line)

# Record-less section headers + static notes (text format only).
if as_text:
    SECTION = {1: "[1] Exceptions & Nullability Hazards",
               2: "[2] Resources & IDisposable Footguns",
               3: "[3] Concurrency & Async Pitfalls",
               4: "[4] Numeric & Floating-Point Traps",
               5: "[5] Collections & LINQ Gotchas",
               6: "[6] Strings & Allocation Smells",
               7: "[7] Filesystem / Process / IO Risks",
               8: "[8] Security Red Flags",
               9: "[9] Code Quality Markers",
               10: "[10] API Misuse & Correctness",
               11: "[11] Tests / Debug Leftovers",
               12: "[12] Formatting & Analyzer Signals",
               13: "[13] Build & Test Health",
               14: "[14] Dependency Hygiene (NuGet)",
               15: "[15] Exception Handling Anti-patterns",
               16: "[16] ASP.NET / Web Pitfalls",
               17: "[17] AST-Grep Rule Pack",
               18: "[18] Project Inventory",
               19: "[19] Resource Lifecycle Correlation",
               20: "[20] Async Locks / Semaphores / Await-in-Lock",
               21: "[21] Exception Surfaces & Rethrow Issues",
               22: "[22] Suspicious Casts & Truncation",
               23: "[23] Parsing & Validation Robustness",
               24: "[24] Perf / DoS Hotspots"}
    SLUG = {1: "exceptions-null", 2: "resources", 3: "concurrency", 4: "numeric",
            5: "collections", 6: "strings", 7: "filesystem", 8: "security",
            9: "code-quality", 10: "api-misuse", 11: "debug", 12: "formatting",
            13: "build", 14: "dependencies", 15: "exceptions", 16: "aspnet",
            17: "ast-grep", 18: "inventory", 19: "resource-lifecycle",
            20: "async-locks", 21: "rethrow", 22: "casts", 23: "parsing", 24: "perf"}
    ok_icon = "[OK]" if ci else "✅"
    covered = {str(rec.get("category_id", "")) for rec in records}
    for num in sorted(SECTION):
        if num in skip:
            continue
        slug = SLUG.get(num)
        if slug is not None and f"csharp.{slug}" in covered:
            continue  # the renderer already announced this section
        if num == 17 and ast_ran:
            continue  # renderer's clean-note block owns the cat-17 section
        emit(SECTION[num])
        if num == 12:
            if no_dotnet == "1" or no_dotnet_format == "1":
                emit("dotnet format skipped (--no-dotnet/--no-format).")
            elif has_dotnet != "1":
                emit("dotnet not found.")
        elif num == 13:
            emit("dotnet build/test skipped (--no-dotnet or dotnet missing).")
        elif num == 14:
            emit("dotnet list package skipped (--no-dotnet/--no-deps or dotnet missing).")
        elif num == 17 and not ast_ran:
            emit("ast-grep not available (install ast-grep, or ensure 'sg' is ast-grep).")
        elif num == 20 and ast_ran:
            emit("Exact await-in-lock detection handled by ast-grep; skipping file-level lock/await heuristic.")
        if num == 1 and type_narrowing == "clean":
            emit(f"{ok_icon} No obvious null/type narrowing fallthrough bugs detected.")
        elif num == 3 and async_handles == "clean":
            emit(f"{ok_icon} No unobserved Task.Run/StartNew handles detected.")
        elif num == 19 and resource_lifecycle == "clean":
            emit(f"{ok_icon} No obvious disposable/resource leaks detected by helper.")
    emit("")
    emit("Summary Statistics:")
    emit(f"  Files scanned: {files_n}")
    emit(f"  Critical issues: {counts['critical']}")
    emit(f"  Warning issues: {counts['warning']}")
    emit(f"  Info items: {counts['info']}")
    emit(f"  Exit code    : {exit_code}")
    if has_ast == "1":
        emit("Tip: run with --format=sarif to generate SARIF from ast-grep rules.")

if as_text:
    try:
        with open(text_out, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    except OSError:
        pass
elif fmt == "json":
    json.dump(doc, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
elif fmt == "sarif":
    from ubs_core.findings_merge import to_sarif
    sarif = to_sarif(doc)
    json.dump(sarif, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")

sys.exit(exit_code)
PYV2BRIDGE
  return "$bridge_rc"
}

# ── Contract-v2 scan: ONE list, ONE orchestrator, optional ast-grep pack ────
run_contract_v2_csharp(){
  local list_file sink exit_code=0 text_out="" ast_rule_dir=""
  list_file="$(mktemp 2>/dev/null || mktemp -t ubs-csharpv2-list.XXXXXX)"
  sink="$(mktemp 2>/dev/null || mktemp -t ubs-csharpv2-sink.XXXXXX)"
  local helpers_dir=""
  ubs_resolve_helpers_dir helpers_dir || helpers_dir="$SCRIPT_DIR/helpers"
  if [[ -f "$PROJECT_DIR" ]]; then
    printf '%s\0' "$PROJECT_DIR" >"$list_file"   # single-file target: the file IS the list
  elif ! ubs_list_files "$PROJECT_DIR" --ext "$INCLUDE_EXT" \
      --exclude "$EXCLUDE_DIRS${EXTRA_EXCLUDE_DIRS:+,$EXTRA_EXCLUDE_DIRS}" \
      ${FILES_FROM:+--files-from "$FILES_FROM"} >"$list_file"; then
    echo "ERROR: contract-v2 file list failed" >&2
    return 2
  fi
  filter_file_list_with_globs "$list_file"   # legacy --exclude glob filter
  # --only whitelist -> v2 skip mapping: skip every category NOT whitelisted.
  local v2_skip="$SKIP_CATEGORIES"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    local keep="" c allowed w
    local -a _wl
    IFS=',' read -r -a _wl <<<"$ONLY_CATEGORIES"
    for c in $(seq 1 24); do
      allowed=0
      for w in "${_wl[@]}"; do [[ "$w" == "$c" ]] && allowed=1; done
      [[ $allowed -eq 0 ]] && keep="${keep:+$keep,}$c"
    done
    v2_skip="${SKIP_CATEGORIES:+$SKIP_CATEGORIES,}$keep"
  fi
  # Consolidated ast-grep layer: the 4-rule pack into ONE sgconfig (one
  # `scan -c` per 400-path batch inside ubs_core.csharp_ast).
  if [[ "$HAS_AST_GREP" -eq 1 ]]; then
    ast_rule_dir="$(mktemp -d 2>/dev/null || mktemp -d -t ubs-csv2-rules.XXXXXX)"
    if ! UBS_CONTRACT_V2_CSHARP_AST_DIR="$ast_rule_dir" UBS_CONTRACT_V2_CSHARP_USER_RULES="$EXTRA_AST_RULES_DIRS" \
      PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -c '
import os
from pathlib import Path
from ubs_core.csharp_rules import generate
user = os.environ.get("UBS_CONTRACT_V2_CSHARP_USER_RULES", "")
generate(Path(os.environ["UBS_CONTRACT_V2_CSHARP_AST_DIR"]), Path(user) if user else None)
' 2>/dev/null; then
      ast_rule_dir=""
    fi
    if [[ -n "$ast_rule_dir" && -n "$DUMP_RULES_DIR" ]]; then
      mkdir -p "$DUMP_RULES_DIR"
      cp "$ast_rule_dir"/rules/*.yml "$DUMP_RULES_DIR/" 2>/dev/null || true
    fi
  fi
  local -a scan_args=(--files-from "$list_file" --sink "$sink" --project-dir "$PROJECT_DIR" \
    --project "${SOURCE_PROJECT_DIR:-$PROJECT_DIR}" --version "$VERSION" --detail-limit "$DETAIL_LIMIT")
  [[ -n "$v2_skip" ]] && scan_args+=(--skip "$v2_skip")
  [[ -n "$ast_rule_dir" ]] && scan_args+=(--ast-rule-dir "$ast_rule_dir")
  [[ "$CI_MODE" -eq 1 ]] && scan_args+=(--ci)
  [[ "${FAIL_ON_WARNING:-0}" -eq 1 ]] && scan_args+=(--fail-on-warning)
  [[ -n "${FAIL_CRITICAL_N:-}" ]] && scan_args+=(--fail-critical "$FAIL_CRITICAL_N")
  [[ -n "${FAIL_WARNING_N:-}" ]] && scan_args+=(--fail-warning "$FAIL_WARNING_N")
  if [[ "$FORMAT" == "text" ]]; then
    text_out="$(mktemp 2>/dev/null || mktemp -t ubs-csv2-text.XXXXXX)"
    scan_args+=(--text-out "$text_out")
  fi
  local v2_ast_ran=0
  [[ -n "$ast_rule_dir" ]] && v2_ast_ran=1
  UBS_V2_PROJECT="${SOURCE_PROJECT_DIR:-$PROJECT_DIR}" \
    PYTHONPATH="$helpers_dir${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m ubs_core.csharp_scan "${scan_args[@]}" || exit_code=$?
  run_v2_legacy_parity_bridges_csharp "$sink" "$list_file" "$exit_code" "$text_out" \
    "$v2_skip" "$v2_ast_ran" || exit_code=$?
  if [[ -n "$text_out" ]]; then
    cat "$text_out" 2>/dev/null || true
    rm -f "$text_out" 2>/dev/null || true
  fi
  if [[ -n "$REPORT_JSON" ]]; then
    cp "$sink" "$REPORT_JSON" 2>/dev/null || true   # K2: the sink IS the findings record stream
  fi
  if [[ -n "$EMIT_FINDINGS_JSON" ]]; then
    cp "$sink" "$EMIT_FINDINGS_JSON" 2>/dev/null || true   # K2: NDJSON records (shape-keyed downstream)
  fi
  rm -f "$list_file" "$sink" 2>/dev/null || true
  [[ -n "$ast_rule_dir" ]] && rm -rf -- "$ast_rule_dir" 2>/dev/null || true
  return "$exit_code"
}

# ---------- main ----------
main() {
  parse_args "$@"
  init_colors
  TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ubs_csharp)"
  detect_tools
  detect_ast_grep_style

  if [[ "$LIST_RULES" -eq 1 ]]; then
    QUIET=1
    NO_COLOR_FLAG=1
    if [[ "$HAS_AST_GREP" -eq 0 ]]; then
      echo "ERROR: --list-rules requires ast-grep." >&2
      exit 2
    fi
    write_ast_rules || exit 2
    list_generated_ast_rule_ids "$AST_RULES_DIR"
    exit 0
  fi

  if [[ "$FORMAT" == "text" ]]; then
    banner
    echo "${DIM}Project: $PROJECT_DIR${RESET}"
    note "Tools: rg=$HAS_RG ast-grep=$HAS_AST_GREP dotnet=$HAS_DOTNET python3=$HAS_PYTHON"
    [[ "$STRICT_GITIGNORE" -eq 1 ]] && note "Strict .gitignore: ON" || note "Strict .gitignore: OFF (scanning beyond .gitignore)"
  fi
  local v2_status=0
  run_contract_v2_csharp || v2_status=$?
  exit "$v2_status"
}

main "$@"
