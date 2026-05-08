#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ELIXIR ULTIMATE BUG SCANNER v1.0.2 (Bash) - Industrial-Grade Code Analysis
# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive static analysis for modern Elixir (1.15+) using:
#   • ripgrep/grep heuristics for fast code smells
#   • optional Mix-powered extra analyzers:
#       - dialyxir (type discrepancies), credo (code quality/style),
#         sobelow (Phoenix security), doctor (docs/typespecs),
#         inch_ex (doc coverage), mix_audit (dependency vulns)
#
# Focus:
#   • pattern matching & guards    • process lifecycle & OTP
#   • error handling & exceptions  • security & crypto hygiene
#   • concurrency & messaging      • Phoenix-specific pitfalls
#   • Ecto query safety            • code quality markers & performance
#   • debugging artifacts          • dependency auditing
#
# Supports:
#   --format text|json|sarif (json/sarif => pure machine output)
#   --fail-on-warning, --skip, --only, --jobs, --include-ext, --exclude
#   --ci, --no-color, --summary-json
#   CI-friendly timestamps, robust find, safe pipelines, auto parallel jobs
# ═══════════════════════════════════════════════════════════════════════════

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-elixir.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail
umask 022
shopt -s lastpipe
shopt -s extglob

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ────────────────────────────────────────────────────────────────────────────
# Globals & defaults
# ────────────────────────────────────────────────────────────────────────────

VERBOSE=0
PROJECT_DIR="."
OUTPUT_FILE=""
FORMAT="text"          # text|json|sarif
CI_MODE=0
FAIL_ON_WARNING=0
INCLUDE_EXT="ex,exs,eex,heex,leex,sface"
QUIET=0
NO_COLOR_FLAG=0
EXTRA_EXCLUDES=""
SKIP_CATEGORIES=""
ONLY_CATEGORIES=""
DETAIL_LIMIT=3
MAX_DETAILED=250
JOBS="${JOBS:-0}"
DISABLE_PIPEFAIL_DURING_SCAN=1

ENABLE_MIX_TOOLS=1
EX_TOOLS="dialyzer,credo,sobelow,doctor,inch,mix_audit"
EX_TIMEOUT="${EX_TIMEOUT:-1200}"

SUMMARY_JSON=""
SARIF_OUT=""
JSON_OUT=""

CHECK="✓"; CROSS="✗"; WARN="⚠"; INFO="ℹ"; ARROW="→"; BULLET="•"; MAGNIFY="🔍"; BUG="🐛"; FIRE="🔥"; SPARKLE="✨"; SHIELD="🛡"; POTION="🧪"

# Color handling
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then USE_COLOR=0; fi
if [[ "$USE_COLOR" -eq 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
  MAGENTA='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'
  BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  : "${RED:=}" "${GREEN:=}" "${YELLOW:=}" "${BLUE:=}" "${MAGENTA:=}" "${CYAN:=}" "${WHITE:=}" "${GRAY:=}" "${BOLD:=}" "${DIM:=}" "${RESET:=}"
  RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; GRAY=''
  BOLD=''; DIM=''; RESET=''
fi

# ────────────────────────────────────────────────────────────────────────────
# Error handling
# ────────────────────────────────────────────────────────────────────────────

on_err() {
  local ec=$?; local cmd=${BASH_COMMAND}; local line=${BASH_LINENO[0]}; local src=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  if [[ "${FORMAT:-text}" == "json" || "${FORMAT:-text}" == "sarif" ]]; then
    echo "{\"error\":{\"exit\":$ec,\"file\":\"$src\",\"line\":$line,\"cmd\":\"${cmd//\"/\\\"}\"}}" >&2; exit "$ec"
  fi
  echo -e "\n${RED}${BOLD}Unexpected error (exit $ec)${RESET} ${DIM}at ${src}:${line}${RESET}\n${DIM}Last command:${RESET} ${WHITE}$cmd${RESET}" >&2
  exit "$ec"
}
trap on_err ERR

print_usage() {
  cat >&2 <<USAGE
Usage: $(basename "$0") [options] [PROJECT_DIR] [OUTPUT_FILE]

Options:
  -v, --verbose            More code samples per finding (DETAIL=10)
  --very-verbose           Max code samples (DETAIL=25)
  -q, --quiet              Reduce non-essential output
  --format=FMT             Output format: text|json|sarif (default: text)
  --json-out=FILE          Save full JSON report to file (text still prints)
  --sarif-out=FILE         Save SARIF to file (text still prints)
  --summary-json=FILE      Save brief summary counters JSON
  --ci                     CI mode (no clear, stable timestamps)
  --no-color               Force disable ANSI color
  --include-ext=CSV        File extensions (default: $INCLUDE_EXT)
  --exclude=GLOB[,..]      Additional glob(s)/dir(s) to exclude
  --only=CSV               Only run these category numbers/names
  --jobs=N                 Parallel jobs for ripgrep (default: auto)
  --skip=CSV               Skip categories by number (e.g. --skip=2,7,11)
  --fail-on-warning        Exit non-zero on warnings or critical
  --no-mix                 Disable Mix-based extra analyzers
  --ex-tools=CSV           Which extra tools to run (default: $EX_TOOLS)
  -h, --help               Show help
Env:
  JOBS, NO_COLOR, CI, EX_TIMEOUT, UBS_METRICS_DIR
Args:
  PROJECT_DIR              Directory to scan (default: ".")
  OUTPUT_FILE              File to save the report (optional)
USAGE
}

# CLI parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--verbose) VERBOSE=1; DETAIL_LIMIT=10; shift;;
    --very-verbose) VERBOSE=2; DETAIL_LIMIT=25; shift;;
    -q|--quiet)   VERBOSE=0; DETAIL_LIMIT=1; QUIET=1; shift;;
    --format=*)   FORMAT="${1#*=}"; shift;;
    --json-out=*) JSON_OUT="${1#*=}"; shift;;
    --sarif-out=*) SARIF_OUT="${1#*=}"; shift;;
    --summary-json=*) SUMMARY_JSON="${1#*=}"; shift;;
    --ci)         CI_MODE=1; shift;;
    --no-color)   NO_COLOR_FLAG=1; shift;;
    --include-ext=*) INCLUDE_EXT="${1#*=}"; shift;;
    --exclude=*)  EXTRA_EXCLUDES="${1#*=}"; shift;;
    --only=*)     ONLY_CATEGORIES="${1#*=}"; shift;;
    --jobs=*)     JOBS="${1#*=}"; shift;;
    --skip=*)     SKIP_CATEGORIES="${1#*=}"; shift;;
    --fail-on-warning) FAIL_ON_WARNING=1; shift;;
    --no-mix)     ENABLE_MIX_TOOLS=0; shift;;
    --ex-tools=*) EX_TOOLS="${1#*=}"; shift;;
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

# CI auto-detect + color override
if [[ -n "${CI:-}" ]]; then CI_MODE=1; fi
if [[ "$NO_COLOR_FLAG" -eq 1 ]]; then USE_COLOR=0; fi

# Redirect output early to capture everything (honors machine formats too)
if [[ -n "${OUTPUT_FILE}" ]]; then
  if command -v tee >/dev/null 2>&1; then
    exec > >(tee "${OUTPUT_FILE}") 2>&1
  else
    exec > "${OUTPUT_FILE}" 2>&1
  fi
fi

DATE_FMT='%Y-%m-%d %H:%M:%S'
safe_date() {
  if [[ "$CI_MODE" -eq 1 ]]; then
    command date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || command date '+%Y-%m-%dT%H:%M:%SZ'
  else
    command date "+$DATE_FMT"
  fi
}
is_machine_format(){ [[ "$FORMAT" == "json" || "$FORMAT" == "sarif" ]]; }

# If machine format: silence all user-facing text immediately.
if is_machine_format; then
  QUIET=1
  USE_COLOR=0
fi

# ────────────────────────────────────────────────────────────────────────────
# Global Counters
# ────────────────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
TOTAL_FILES=0

# ────────────────────────────────────────────────────────────────────────────
# Global State
# ────────────────────────────────────────────────────────────────────────────
HAS_RIPGREP=0
HAS_MIX=0
IS_PHOENIX=0

# ────────────────────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────────────────────
maybe_clear() { if [[ -t 1 && "$CI_MODE" -eq 0 ]] && ! is_machine_format; then clear || true; fi; }
say() { [[ "$QUIET" -eq 1 ]] && return 0; echo -e "$*"; }

json_escape() {
  local s="${1-}"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

emit_json_summary() {
  local ts json
  ts="$(safe_date)"
  json="$(printf '{"project":"%s","files":%s,"critical":%s,"warning":%s,"info":%s,"timestamp":"%s","format":"json"}\n' \
    "$(json_escape "$PROJECT_DIR")" "$TOTAL_FILES" "$CRITICAL_COUNT" "$WARNING_COUNT" "$INFO_COUNT" "$(json_escape "$ts")")"
  printf '%s' "$json"
  if [[ -n "$SUMMARY_JSON" ]]; then
    mkdir -p "$(dirname "$SUMMARY_JSON")" 2>/dev/null || true
    printf '%s' "$json" >"$SUMMARY_JSON"
  fi
}

emit_sarif() {
  printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ubs-elixir"}},"results":[]}]}'
}
print_header() { say "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; say "${WHITE}${BOLD}$1${RESET}"; say "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
print_category() { say "\n${MAGENTA}${BOLD}▓▓▓ $1${RESET}"; say "${DIM}$2${RESET}"; }
print_subheader() { say "\n${YELLOW}${BOLD}$BULLET $1${RESET}"; }
print_finding() {
  local severity=$1
  case $severity in
    good) local title=$2; say "  ${GREEN}${CHECK} OK${RESET} ${DIM}$title${RESET}" ;;
    *)
      local raw_count=$2; local title=$3; local description="${4:-}"
      local count; count=$(printf '%s\n' "$raw_count" | awk 'END{print $0+0}')
      case $severity in
        critical) CRITICAL_COUNT=$((CRITICAL_COUNT + count)); say "  ${RED}${BOLD}${FIRE} CRITICAL${RESET} ${WHITE}($count found)${RESET}"; say "    ${RED}${BOLD}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
        warning)  WARNING_COUNT=$((WARNING_COUNT + count)); say "  ${YELLOW}${WARN} Warning${RESET} ${WHITE}($count found)${RESET}"; say "    ${YELLOW}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
        info)     INFO_COUNT=$((INFO_COUNT + count));      say "  ${BLUE}${INFO} Info${RESET} ${WHITE}($count found)${RESET}"; say "    ${BLUE}$title${RESET}"; [ -n "$description" ] && say "    ${DIM}$description${RESET}" || true ;;
      esac
      ;;
  esac
}
print_code_sample() { local file=$1; local line=$2; local code=$3; say "${GRAY}      $file:$line${RESET}"; say "${WHITE}      $code${RESET}"; }

# Parse grep/rg output line handling Windows drive letters (C:/path...)
# Sets: PARSED_FILE, PARSED_LINE, PARSED_CODE
parse_grep_line() {
  local rawline="$1"
  PARSED_FILE="" PARSED_LINE="" PARSED_CODE=""
  if [[ "$rawline" =~ ^([A-Za-z]:.+):([0-9]+):(.*)$ ]] || [[ "$rawline" =~ ^(.+):([0-9]+):(.*)$ ]]; then
    PARSED_FILE="${BASH_REMATCH[1]}"
    PARSED_LINE="${BASH_REMATCH[2]}"
    PARSED_CODE="${BASH_REMATCH[3]}"
    return 0
  fi
  return 1
}

show_detailed_finding() {
  local pattern=$1; local limit=${2:-$DETAIL_LIMIT}; local printed=0
  while IFS= read -r rawline; do
    [[ -z "$rawline" ]] && continue
    [[ "$rawline" == *"ubs:ignore"* ]] && continue
    parse_grep_line "$rawline" || continue
    print_code_sample "$PARSED_FILE" "$PARSED_LINE" "$PARSED_CODE"; printed=$((printed+1))
    [[ $printed -ge $limit || $printed -ge $MAX_DETAILED ]] && break
  done < <("${GREP_RN[@]}" -e "$pattern" "$PROJECT_DIR" 2>/dev/null | head -n "$limit" || true) || true
}

run_archive_extraction_checks() {
  print_subheader "Archive extraction path traversal"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable archive extraction checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Archive extraction path traversal risk" "Validate archive entry names with Path.expand/2 and reject paths outside the extraction root before writing files"
        else
          print_finding "good" "No unvalidated archive extraction path construction detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
ARCHIVE_HINT_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip|zip_get|foldl|open|table)\b|'
    r'\b(?:Unzip|Zstream|ExArchive|Archive)\b',
    re.IGNORECASE,
)
DIRECT_CWD_EXTRACT_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip)\s*\([^#\n]*(?:\bcwd\s*:|\{:cwd\s*,)',
    re.IGNORECASE,
)
MEMORY_EXTRACT_RE = re.compile(r'(?<![A-Za-z0-9_]):(?:zip|erl_tar)\.(?:extract|unzip)\s*\([^#\n]*(?::memory|\[:memory)', re.IGNORECASE)
ENTRY_FN_RE = re.compile(
    r'\bfn\s+(?:\{\s*)?([A-Za-z_][A-Za-z0-9_?!]*)(?:\s*,|\s*\}|(?:\s+->))'
)
ENTRY_ALIAS_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*=\s*'
    r'(?:List\.to_string|to_string|IO\.iodata_to_binary|Path\.basename)?\s*\(?\s*'
    r'([A-Za-z_][A-Za-z0-9_?!]*)'
)
PATH_ALIAS_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*=\s*')
PATH_BUILD_RE = re.compile(
    r'\bPath\.(?:join|expand|relative_to)\s*\(|'
    r'\bFile\.(?:write!?|open!?|mkdir!?|mkdir_p!?|cp!?|rename!?|rm!?|touch!?)\s*\('
)
SINK_RE = re.compile(
    r'\bFile\.(?:write!?|open!?|mkdir!?|mkdir_p!?|cp!?|rename!?|rm!?|touch!?)\s*\('
)
ENTRY_NAME_HINT_RE = re.compile(
    r'^(?:entry_?)?(?:file_?)?(?:name|path|filename|member|entry|tar_entry|zip_entry)$',
    re.IGNORECASE,
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_archive_path|safeArchivePath|safe_extract_path|safeExtractPath|'
    r'validate_archive_entry|validateArchiveEntry|validate_zip_entry|validateZipEntry|'
    r'ensure_inside_destination|ensureInsideDestination|inside_destination\?|insideDestination\?|'
    r'assert_inside_destination|assertInsideDestination|safe_join|secure_join|secure_extract)\b',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = ' do' in statement or '->' in statement or balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = has_end or ' do' in next_line or '->' in next_line
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def context_around(lines, line_no):
    start = max(0, line_no - 8)
    end = min(len(lines), line_no + 10)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])

def has_safe_context(statement, context):
    if SAFE_NAMED_RE.search(statement) or SAFE_NAMED_RE.search(context):
        return True
    lower = context.lower()
    has_canonical = 'path.expand' in lower or 'path.relative_to' in lower
    has_anchor = 'string.starts_with?' in lower or 'path.relative_to' in lower
    has_reject = 'raise ' in lower or '{:error' in lower or 'throw(' in lower or 'return false' in lower
    return has_canonical and has_anchor and has_reject

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def references_any(statement, names):
    return any(re.search(rf'\b{re.escape(name)}\b', statement) for name in names)

def collect_entry_aliases(lines):
    aliases = set()
    text = '\n'.join(strip_line_comments(line) for line in lines)
    if not (':memory' in text or 'zip_get' in text or 'foldl' in text or 'table' in text):
        return aliases
    for raw in lines:
        line = strip_line_comments(raw)
        match = ENTRY_FN_RE.search(line)
        if match:
            name = match.group(1)
            if ENTRY_NAME_HINT_RE.search(name):
                aliases.add(name)
        match = ENTRY_ALIAS_RE.search(line)
        if match and (match.group(2) in aliases or ENTRY_NAME_HINT_RE.search(match.group(1))):
            aliases.add(match.group(1))
    return aliases

def collect_path_aliases(lines, entry_aliases):
    aliases = set()
    for idx, _ in enumerate(lines, start=1):
        statement = logical_statement(lines, idx)
        if not PATH_BUILD_RE.search(statement):
            continue
        if not references_any(statement, entry_aliases):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        match = PATH_ALIAS_RE.search(statement)
        if match:
            aliases.add(match.group(1))
    return aliases

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not ARCHIVE_HINT_RE.search(text):
        return
    lines = text.splitlines()
    entry_aliases = collect_entry_aliases(lines)
    path_aliases = collect_path_aliases(lines, entry_aliases)
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx)
        direct_cwd_extract = bool(DIRECT_CWD_EXTRACT_RE.search(statement))
        unsafe_path_build = bool(PATH_BUILD_RE.search(statement)) and references_any(statement, entry_aliases)
        unsafe_sink = bool(SINK_RE.search(statement)) and references_any(statement, path_aliases)
        memory_extract_write_context = bool(MEMORY_EXTRACT_RE.search(text)) and unsafe_path_build
        if not (direct_cwd_extract or unsafe_path_build or unsafe_sink or memory_extract_write_context):
            continue
        if has_safe_context(statement, context_around(lines, idx)):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((relpath(path), idx, source_line(lines, idx)))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_request_path_traversal_checks() {
  print_subheader "Request-derived filesystem paths"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable request path traversal checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-derived path reaches file read/write/serve sink" "Reduce conn params, request paths, and upload filenames to a basename or prove the expanded path stays under the allowed root before touching files."
        else
          print_finding "good" "No request-derived file path sinks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|path_info|request_path|query_string)\b|'
    r'\bparams\s*(?:\[|\|>)|'
    r'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.params)\b|'
    r'\bget_in\s*\(\s*(?:params|conn\.params)\b|'
    r'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,|'
    r'\b(?:conn|socket)\s*\|>\s*(?:Plug\.Conn\.)?get_req_header\s*\(|'
    r'\b[A-Za-z_][A-Za-z0-9_?!]*\.filename\b|'
    r'%Plug\.Upload\{[^}]*filename\s*:',
    re.IGNORECASE,
)
PATHISH_NAME_RE = re.compile(r'(path|file|name|dir|folder|target|destination|download|upload|export|key)', re.IGNORECASE)
SINK_RE = re.compile(
    r'\bFile\.(?:read!?|write!?|open!?|rm!?|cp!?|rename!?|mkdir!?|mkdir_p!?|stat!?|'
    r'ls!?|stream!?|exists\?)\s*\(|'
    r'\b(?:Plug\.Conn\.)?send_file\s*\(|'
    r'\b(?:Phoenix\.Controller\.)?send_download\s*\('
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_path|safePath|safe_file_name|safeFileName|safe_filename|safeFilename|'
    r'sanitize_filename|sanitizeFilename|sanitize_path|sanitizePath|validated_path|validatedPath|'
    r'validate_path|validatePath|safe_under_root|safeUnderRoot|resolve_under_root|resolveUnderRoot|'
    r'ensure_inside_root|ensureInsideRoot|inside_root\?|insideRoot\?|allowed_file|allowedFile|'
    r'canonical_path_inside|canonicalPathInside)\b',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 8:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def context_around(lines, line_no):
    start = max(0, line_no - 10)
    end = min(len(lines), line_no + 12)
    return '\n'.join(strip_line_comments(line) for line in lines[start:end])

def is_pathish(variable: str) -> bool:
    return bool(PATHISH_NAME_RE.search(variable))

def has_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        return True
    return bool(target_name and is_pathish(target_name) and re.search(r'\bparams\b', statement))

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement) or re.search(r'\bPath\.basename\s*\(', statement))

def has_containment_context(context: str) -> bool:
    lower = context.lower()
    has_canonical = 'path.expand' in lower or 'path.relative_to' in lower
    has_anchor = 'string.starts_with?' in lower or 'path.relative_to' in lower
    rejects_escape = 'raise ' in lower or '{:error' in lower or 'halt(' in lower or 'send_resp(' in lower
    return has_canonical and has_anchor and rejects_escape

def contains_tainted_path(statement: str, tainted: set[str]) -> bool:
    if has_source(statement):
        return True
    return any(re.search(rf'\b{re.escape(var)}\b', statement) for var in tainted)

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not re.search(r'\b(?:conn|params|Plug\.Upload|filename|send_file|send_download)\b', text):
        return
    lines = text.splitlines()
    tainted = set()
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            if is_safe_expression(rhs):
                tainted.discard(variable)
            elif has_source(rhs, variable) or contains_tainted_path(rhs, tainted):
                tainted.add(variable)
            else:
                tainted.discard(variable)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        if not contains_tainted_path(statement, tainted):
            continue
        if has_containment_context(context_around(lines, idx)):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((relpath(path), idx, source_line(lines, idx)))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_request_open_redirect_checks() {
  print_subheader "Request-derived open redirects"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable request-derived open redirect checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Unvalidated redirect from request data" "Validate redirect targets with local path checks or explicit scheme and host allow-lists before Phoenix/Plug redirects or Location headers."
        else
          print_finding "good" "No request-derived redirect sinks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
REDIRECT_KEY = r'(?:return[_-]?to|return[_-]?url|redirect(?:[_-]?url)?|next|continue|callback|target|destination|location|url|uri)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{REDIRECT_KEY}|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{REDIRECT_KEY}|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,[^)]*{REDIRECT_KEY}|'
    rf'\|>\s*Plug\.Conn\.get_req_header\s*\([^)]*{REDIRECT_KEY}',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params)\b|\bparams\b|'
    r'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,',
    re.IGNORECASE,
)
REDIRECTISH_NAME_RE = re.compile(
    r'(redirect|return|callback|next|continue|target|destination|location|url|uri)',
    re.IGNORECASE,
)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_redirect(?:_url|_uri|_target)?|safeRedirect(?:Url|Uri|Target)?|'
    r'validate_redirect(?:_url|_uri|_target)?|validateRedirect(?:Url|Uri|Target)?|'
    r'validated_redirect(?:_url|_uri|_target)?|validatedRedirect(?:Url|Uri|Target)?|'
    r'sanitize_redirect(?:_url|_uri|_target)?|sanitizeRedirect(?:Url|Uri|Target)?|'
    r'allowed_redirect(?:_url|_uri|_host|_target)?|allowedRedirect(?:Url|Uri|Host|Target)?|'
    r'local_redirect(?:_url|_uri|_target)?|localRedirect(?:Url|Uri|Target)?|'
    r'same_origin_redirect(?:_url|_target)?|sameOriginRedirect(?:Url|Target)?|'
    r'allowed_redirect_host\?|allowedRedirectHost\?|local_redirect\?|localRedirect\?|'
    r'is_local_redirect|isLocalRedirect)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\b(?:Phoenix\.Controller\.)?redirect\s*\([^)]*(?:to|external)\s*:|'
    r'\|\>\s*(?:Phoenix\.Controller\.)?redirect\s*\([^)]*(?:to|external)\s*:|'
    r'\b(?:Plug\.Conn\.)?put_resp_header\s*\([^)]*["\']location["\']\s*,|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(\s*["\']location["\']\s*,|'
    r'\b(?:Plug\.Conn\.)?resp\s*\([^)]*30[1278][^)]*["\']location["\']',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI\.parse|URI\.new!?)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowed_redirect_hosts|allowed_hosts|allowed_host|redirect_host_allowlist|trusted_redirect_hosts|@allowed_redirect_hosts|@allowed_hosts)\b|'
    r'\b(?:MapSet\.member\?|Enum\.member\?|String\.starts_with\?)\s*\(|'
    r'\bin\s+@?(?:allowed_redirect_hosts|allowed_hosts)\b|'
    r'==\s*"https"',
    re.IGNORECASE,
)
LOCAL_PATH_RE = re.compile(
    r'String\.starts_with\?\s*\(\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*,\s*["\']/["\']\s*\).*'
    r'not\s+String\.starts_with\?\s*\(\s*\1\s*,\s*["\']//["\']\s*\)|'
    r'not\s+String\.starts_with\?\s*\(\s*([A-Za-z_][A-Za-z0-9_?!]*)\s*,\s*["\']//["\']\s*\).*'
    r'String\.starts_with\?\s*\(\s*\2\s*,\s*["\']/["\']\s*\)',
    re.IGNORECASE | re.DOTALL,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 10:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 10:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement))

def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        if REDIRECTISH_NAME_RE.search(statement) or re.search(r'\b(?:conn|socket)\.(?:host|request_path|query_string)\b', statement):
            return True
    return bool(target_name and REDIRECTISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))

def refs_in_statement(statement: str, tainted: dict[str, dict]):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', statement)]

def taint_from_statement(statement: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(statement):
        return None
    if has_request_source(statement, target_name):
        source = REQUEST_SOURCE_RE.search(statement)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_statement(statement, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}

def has_redirect_validation_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_NAMED_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(
        (URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))
        or (LOCAL_PATH_RE.search(context) and REJECT_RE.search(context))
    )

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params)\b', text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)
            else:
                tainted.pop(variable, None)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_redirect_validation_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> redirect"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('redirect')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_request_response_header_checks() {
  print_subheader "Request-derived response headers"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable request-derived response header checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-controlled value reaches HTTP response header" "Reject or strip CR/LF before writing request data to response headers; encode Content-Disposition filenames or use a header-safe helper."
        else
          print_finding "good" "No request-derived response header sinks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
HEADER_KEY = r'(?:header|trace|name|file|filename|token|tenant|id|value|download|export|disposition|etag|cache|language|encoding|type)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params|path_params|body_params|cookies|req_cookies)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params|path_params|body_params|cookies|req_cookies))\b|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params|path_params|body_params|cookies|req_cookies))\b|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,|'
    rf'\b(?:conn|socket)\s*\|>\s*(?:Plug\.Conn\.)?get_req_header\s*\(|'
    rf'\b[A-Za-z_][A-Za-z0-9_?!]*\.filename\b|'
    rf'%Plug\.Upload\{{[^}}]*filename\s*:',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params|path_params|body_params|cookies|req_cookies)\b|\bparams\b|'
    r'\b(?:Plug\.Conn\.)?get_req_header\s*\(\s*(?:conn|socket)\s*,',
    re.IGNORECASE,
)
HEADERISH_NAME_RE = re.compile(HEADER_KEY, re.IGNORECASE)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_header(?:_value)?|safeHeader(?:Value)?|safe_response_header(?:_value)?|'
    r'sanitize_header(?:_value)?|sanitizeHeader(?:Value)?|sanitized_header(?:_value)?|'
    r'clean_header(?:_value)?|encode_header(?:_value)?|encoded_header(?:_value)?|'
    r'encoded_filename|safe_filename_for_header|safe_content_disposition_filename|'
    r'strip_crlf|remove_crlf|without_crlf|reject_crlf|valid_header_value\?|'
    r'is_header_value_safe\?|header_safe\?)\b',
    re.IGNORECASE,
)
ENCODING_RE = re.compile(r'\b(?:URI\.encode(?:_www_form)?|Base\.encode(?:16|32|64))\s*\(', re.IGNORECASE)
STRIP_RE = re.compile(
    r'\bString\.replace\s*\([^)]*(?:["\']\\[rn]["\']|~r/[^/]*\\[rn])|'
    r'\bRegex\.replace\s*\(\s*~r/[^/]*\\[rn]',
    re.IGNORECASE,
)
CRLF_CHECK_RE = re.compile(
    r'\\r|\\n|(?:\r|\n)|crlf|newline|'
    r'String\.contains\?\s*\([^)]*["\']\\[rn]["\']|'
    r'Regex\.match\?\s*\(\s*~r/[^/]*\\[rn]',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
SINK_RE = re.compile(
    r'\b(?:Plug\.Conn\.)?put_resp_header\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(|'
    r'\b(?:Plug\.Conn\.)?(?:put|merge)_resp_headers\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?(?:put|merge)_resp_headers\s*\(|'
    r'\b(?:Plug\.Conn\.)?put_resp_content_type\s*\(|'
    r'\|\>\s*(?:Plug\.Conn\.)?put_resp_content_type\s*\(',
    re.IGNORECASE,
)
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 10:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 10:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def identifier_search_text(expr: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escape:
                escape = False
                i += 1
                continue
            if ch == '\\':
                escape = True
                i += 1
                continue
            if ch == '#' and i + 1 < len(expr) and expr[i + 1] == '{':
                depth = 1
                j = i + 2
                interpolation = []
                while j < len(expr) and depth > 0:
                    current = expr[j]
                    if current == '{':
                        depth += 1
                    elif current == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    interpolation.append(current)
                    j += 1
                out.append(' ')
                out.append(''.join(interpolation))
                out.append(' ')
                i = j + 1
                continue
            if ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return ''.join(out)

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement) or ENCODING_RE.search(statement) or STRIP_RE.search(statement))

def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement):
        return True
    return bool(target_name and HEADERISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))

def refs_in_statement(statement: str, tainted: dict[str, dict]):
    code_text = re.sub(r'\b[a-z_][A-Za-z0-9_?!]*\s*:', ' ', identifier_search_text(statement))
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', code_text)]

def has_non_location_header_sink(statement: str) -> bool:
    keys = []
    keys.extend(re.findall(r'put_resp_header\s*\([^,]+,\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\|\>\s*(?:Plug\.Conn\.)?put_resp_header\s*\(\s*["\']([^"\']+)["\']', statement, re.IGNORECASE))
    keys.extend(re.findall(r'\{\s*["\']([^"\']+)["\']\s*,', statement))
    if re.search(r'put_resp_content_type\s*\(', statement, re.IGNORECASE):
        keys.append('content-type')
    if keys:
        return any(key.lower() != 'location' for key in keys)
    return True

def taint_from_statement(statement: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(statement):
        return None
    if has_request_source(statement, target_name):
        source = REQUEST_SOURCE_RE.search(statement)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_statement(statement, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}

def has_crlf_reject_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 18)
    context_lines = [strip_line_comments(line) for line in lines[start:line_no]]
    for ref in refs:
        ref_lines = [
            line for line in context_lines
            if re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line))
        ]
        if not ref_lines:
            continue
        if any(is_safe_expression(line) for line in ref_lines):
            return True
        for pos, line in enumerate(context_lines):
            if not re.search(rf'\b{re.escape(ref)}\b', identifier_search_text(line)):
                continue
            if not CRLF_CHECK_RE.search(line):
                continue
            reject_window = '\n'.join(context_lines[pos:pos + 5])
            if REJECT_RE.search(reject_window):
                return True
    return False

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params|cookies|req_cookies)\b', text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue
        if re.match(r'^\s*def(?:p|macro)?\b', statement):
            tainted.clear()

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)
            else:
                tainted.pop(variable, None)

        current_line = strip_line_comments(lines[idx - 1])
        if not SINK_RE.search(current_line) and SINK_RE.search(statement):
            continue
        if not SINK_RE.search(statement):
            continue
        if not has_non_location_header_sink(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_crlf_reject_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> response header"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('response header')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_request_outbound_url_checks() {
  print_subheader "Request-derived outbound HTTP URLs"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable request-derived outbound URL checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Request-derived URL reaches outbound HTTP client" "Validate outbound URLs with URI parsing plus explicit https scheme and host allow-lists before calling Req, HTTPoison, Finch, Tesla, hackney, Mint, or :httpc."
        else
          print_finding "good" "No request-derived outbound HTTP URL sinks detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
URL_KEY = r'(?:url|uri|host|origin|callback|webhook|redirect|endpoint|target|remote|link|location|referer|referrer|next)'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
REQUEST_SOURCE_RE = re.compile(
    rf'\b(?:conn|socket)\.(?:params|query_params)\s*(?:\[|\|>)|'
    rf'\bparams\s*(?:\[|\|>)|'
    rf'\bMap\.(?:get|fetch!?|take)\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{URL_KEY}|'
    rf'\bget_in\s*\(\s*(?:params|conn\.(?:params|query_params))\b[^)]*{URL_KEY}|'
    rf'\b(?:conn|socket)\.(?:host|request_path|query_string)\b|'
    rf'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,[^)]*{URL_KEY}|'
    rf'\|>\s*Plug\.Conn\.get_req_header\s*\([^)]*{URL_KEY}',
    re.IGNORECASE,
)
REQUEST_COLLECTION_RE = re.compile(
    r'\b(?:conn|socket)\.(?:params|query_params)\b|\bparams\b|'
    r'\bPlug\.Conn\.get_req_header\s*\(\s*conn\s*,',
    re.IGNORECASE,
)
URLISH_NAME_RE = re.compile(URL_KEY, re.IGNORECASE)
SAFE_NAMED_RE = re.compile(
    r'\b(?:safe_outbound_url|safeOutboundUrl|safe_outbound_uri|safeOutboundUri|'
    r'validate_outbound_url|validateOutboundUrl|validated_outbound_url|validatedOutboundUrl|'
    r'allowed_outbound_url|allowedOutboundUrl|allowlisted_url|allowlistedUrl|'
    r'trusted_url|trustedUrl|sanitize_url|sanitizeUrl|sanitize_uri|sanitizeUri|'
    r'resolve_allowed_url|resolveAllowedUrl|require_allowed_host|requireAllowedHost|'
    r'allowed_host\?|allowedHost\?|ensure_allowed_host|ensureAllowedHost)\b',
    re.IGNORECASE,
)
SINK_RE = re.compile(
    r'\bReq\.(?:get!?|post!?|put!?|patch!?|delete!?|request!?)\s*\(|'
    r'\bHTTPoison\.(?:get!?|post!?|put!?|patch!?|delete!?|request!?)\s*\(|'
    r'\bHTTPotion\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'\bFinch\.build\s*\(|'
    r'\bTesla\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'(?<![A-Za-z0-9_]):hackney\.(?:get|post|put|patch|delete|request)\s*\(|'
    r'(?<![A-Za-z0-9_]):httpc\.request\s*\(|'
    r'\bMint\.HTTP\.connect\s*\(',
    re.IGNORECASE,
)
URI_PARSE_RE = re.compile(r'\b(?:URI\.parse|URI\.new!?)\s*\(')
HOST_CHECK_RE = re.compile(
    r'\.(?:scheme|host)\b|'
    r'\b(?:allowed_hosts|allowed_host|host_allowlist|trusted_hosts|@allowed_hosts)\b|'
    r'\b(?:MapSet\.member\?|Enum\.member\?|String\.starts_with\?)\s*\(|'
    r'\bin\s+@?allowed_hosts\b|'
    r'==\s*"https"',
    re.IGNORECASE,
)
REJECT_RE = re.compile(r'(?:\b(?:raise|throw)\b|\{:error|\b(?:halt|send_resp)\s*\(|\bjson\s*\([^)]*\{:error)', re.IGNORECASE)
PATH_LIMIT = 4

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0
    lookahead = idx + 1
    while (balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def is_safe_expression(statement: str) -> bool:
    return bool(SAFE_NAMED_RE.search(statement))

def has_request_source(statement: str, target_name: str = '') -> bool:
    if REQUEST_SOURCE_RE.search(statement) and (URLISH_NAME_RE.search(statement) or re.search(r'\b(?:conn|socket)\.(?:host|request_path|query_string)\b', statement)):
        return True
    return bool(target_name and URLISH_NAME_RE.search(target_name) and REQUEST_COLLECTION_RE.search(statement))

def refs_in_statement(statement: str, tainted: dict[str, dict]):
    return [name for name in tainted if re.search(rf'\b{re.escape(name)}\b', statement)]

def taint_from_statement(statement: str, tainted: dict[str, dict], target_name: str = ''):
    if is_safe_expression(statement):
        return None
    if has_request_source(statement, target_name):
        source = REQUEST_SOURCE_RE.search(statement)
        return {'path': [(source.group(0) if source else target_name or 'request value').strip()]}
    refs = refs_in_statement(statement, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get('path', [ref]))
    if len(path) >= PATH_LIMIT:
        path = path[-(PATH_LIMIT - 1):]
    path.append(ref)
    return {'path': path}

def has_allowlist_context(lines, line_no, refs):
    if not refs:
        return False
    start = max(0, line_no - 24)
    context = '\n'.join(strip_line_comments(line) for line in lines[start:line_no])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if SAFE_NAMED_RE.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(URI_PARSE_RE.search(context) and HOST_CHECK_RE.search(context) and REJECT_RE.search(context))

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (re.search(r'\b(?:conn|params|Plug\.Conn|query_params)\b', text) and SINK_RE.search(text)):
        return
    lines = text.splitlines()
    tainted = {}
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement:
            continue

        assignment = ASSIGN_RE.search(statement)
        if assignment:
            variable, rhs = assignment.group(1), assignment.group(2)
            taint = taint_from_statement(rhs, tainted, variable)
            if taint:
                tainted[variable] = taint
            elif is_safe_expression(rhs):
                tainted.pop(variable, None)

        if not SINK_RE.search(statement):
            continue
        if is_safe_expression(statement):
            continue
        direct = has_request_source(statement)
        refs = refs_in_statement(statement, tainted)
        if not direct and not refs:
            continue
        if has_allowlist_context(lines, idx, refs):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        if direct:
            source = REQUEST_SOURCE_RE.search(statement)
            path_desc = f"{(source.group(0) if source else 'request source').strip()} -> outbound HTTP"
        else:
            ref = refs[0]
            seq = list(tainted.get(ref, {}).get('path', [ref]))
            if len(seq) >= PATH_LIMIT:
                seq = seq[-(PATH_LIMIT - 1):]
            seq.append('outbound HTTP')
            path_desc = ' -> '.join(seq)
        issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [{path_desc}]"))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_security_randomness_checks() {
  print_subheader "Security-sensitive non-crypto randomness"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable security randomness checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Security token generated with non-cryptographic randomness" "Use :crypto.strong_rand_bytes/1 plus Base.url_encode64/2, or a framework helper built on cryptographic randomness, for tokens, sessions, CSRF values, OTPs, salts, and API keys."
        else
          print_finding "good" "No security-sensitive non-crypto randomness detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}
VAR_RE = r'[a-z_][A-Za-z0-9_?!]*'
ASSIGN_RE = re.compile(rf'^\s*({VAR_RE})\s*=\s*(.+)')
SECURITY_NAME_RE = re.compile(
    r'(?:token|secret|password|passwd|pwd|session|cookie|csrf|xsrf|otp|totp|mfa|'
    r'nonce|salt|api[_-]?key|access[_-]?key|private[_-]?key|public[_-]?key|'
    r'\bkey\b|auth|bearer|credential|reset|invite|verification|confirm|'
    r'magic[_-]?link|recovery|signature|\bsig\b)',
    re.IGNORECASE,
)
UNSAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_]):(?:rand|random)\.(?:uniform(?:_s)?|bytes|seed|seed_s)\b|'
    r'\bEnum\.(?:random|take_random|shuffle)\s*\(|'
    r'\bSystem\.unique_integer\s*\(|'
    r'\b:erlang\.(?:unique_integer|monotonic_time|system_time|phash2)\s*\(',
    re.IGNORECASE,
)
SAFE_RANDOM_RE = re.compile(
    r'(?<![A-Za-z0-9_]):crypto\.strong_rand_bytes\s*\(|'
    r'\b(?:safe_token|secure_token|secure_random|crypto_random|'
    r'generate_secure_token|Phoenix\.Token\.sign|Plug\.Crypto)\b',
    re.IGNORECASE,
)
SECURITY_SINK_RE = re.compile(
    r'\b(?:put_session|configure_session|put_resp_cookie|put_private|assign)\s*\([^#\n]*(?:token|session|csrf|xsrf|otp|nonce|salt|api[_-]?key|secret|auth|credential)|'
    r'\b(?:Base\.encode(?:16|32|64)!?|Integer\.to_string|to_string)\s*\(',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    try:
        parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == '#':
            break
        out.append(ch)
        i += 1
    return ''.join(out)

def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    balance = statement.count('(') + statement.count('[') + statement.count('{')
    balance -= statement.count(')') + statement.count(']') + statement.count('}')
    has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
    lookahead = idx + 1
    while lookahead < len(lines) and lookahead < idx + 8:
        upcoming = strip_line_comments(lines[lookahead]).lstrip()
        if not upcoming:
            probe = lookahead + 1
            while probe < len(lines) and probe < idx + 8:
                upcoming = strip_line_comments(lines[probe]).lstrip()
                if upcoming:
                    break
                probe += 1
        if balance <= 0 and has_end and not upcoming.startswith('|>'):
            break
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += ' ' + next_line
        balance += next_line.count('(') + next_line.count('[') + next_line.count('{')
        balance -= next_line.count(')') + next_line.count(']') + next_line.count('}')
        has_end = balance <= 0 and not statement.rstrip().endswith(('=', '|>', ',', '->'))
        lookahead += 1
    return statement

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def relpath(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def is_continuation_line(lines, line_no):
    idx = line_no - 2
    while idx >= 0:
        previous = strip_line_comments(lines[idx]).strip()
        if not previous:
            idx -= 1
            continue
        return previous.endswith(('=', '|>', ',', '->'))
    return False

def function_context(lines, line_no):
    start = max(0, line_no - 14)
    for line in reversed(lines[start:line_no]):
        clean = strip_line_comments(line)
        if re.search(r'\bdefp?\s+[A-Za-z_][A-Za-z0-9_?!]*', clean):
            return clean
    return ''

def is_security_context(statement: str, variable: str, lines, line_no) -> bool:
    if variable and SECURITY_NAME_RE.search(variable):
        return True
    if SECURITY_NAME_RE.search(statement):
        return True
    return bool(SECURITY_NAME_RE.search(function_context(lines, line_no)))

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not UNSAFE_RANDOM_RE.search(text):
        return
    lines = text.splitlines()
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        if is_continuation_line(lines, idx):
            continue
        statement = logical_statement(lines, idx).strip()
        if not statement or not UNSAFE_RANDOM_RE.search(statement):
            continue
        if SAFE_RANDOM_RE.search(statement):
            continue
        assignment = ASSIGN_RE.search(statement)
        variable = assignment.group(1) if assignment else ''
        security_context = is_security_context(statement, variable, lines, idx)
        if not security_context:
            continue
        if not (assignment or SECURITY_SINK_RE.search(statement) or SECURITY_NAME_RE.search(statement) or security_context):
            continue
        key = (relpath(path), idx)
        if key in seen:
            continue
        seen.add(key)
        issues.append((relpath(path), idx, source_line(lines, idx)))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

run_hardcoded_secret_checks() {
  print_subheader "Hardcoded secrets/tokens/passwords"
  if ! command -v python3 >/dev/null 2>&1; then
    print_finding "info" 0 "python3 not available" "Install python3 to enable hardcoded secret checks"
    return
  fi
  local printed=0
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      __COUNT__)
        if [[ "$a" -gt 0 ]]; then
          print_finding "critical" "$a" "Hardcoded secrets/tokens in source" "Use runtime environment variables, secret stores, or release-time config for Phoenix secret_key_base, signing salts, JWT/API secrets, and token keys."
        else
          print_finding "good" "No hardcoded secrets/tokens detected"
        fi
        ;;
      __SAMPLE__)
        if [[ "$printed" -lt "$DETAIL_LIMIT" && "$printed" -lt "$MAX_DETAILED" ]]; then
          print_code_sample "$a" "$b" "$c"
          printed=$((printed + 1))
        fi
        ;;
    esac
  done < <(python3 - "$PROJECT_DIR" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
SKIP_DIRS = {'.git', '.hg', '.svn', '_build', 'deps', '.elixir_ls', '.hex', '.fetch', 'node_modules', 'dist', 'build', 'cover', 'doc', 'priv/static', '.cache', 'tmp', 'log'}
EXTS = {'.ex', '.exs', '.eex', '.heex', '.leex', '.sface'}

SECRET_KEY_RE = re.compile(
    r'(?:secret[_-]?key[_-]?base|signing[_-]?salt|encryption[_-]?salt|guardian[_-]?secret|'
    r'joken[_-]?secret|jwt[_-]?secret|client[_-]?secret|webhook[_-]?secret|api[_-]?key|'
    r'private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?secret|cookie[_-]?secret|'
    r'(?:^|[_-])secret(?:$|[_-])|password|passwd|pwd|token|credential)',
    re.IGNORECASE,
)
ASSIGNMENT_SECRET_RE = re.compile(
    r'(?P<key>@?[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s*'
    r'(?::|=>|=)\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
MODULE_ATTR_SECRET_RE = re.compile(
    r'(?P<key>@[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s+'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
CONFIG_SECRET_RE = re.compile(
    r'\bconfig\s+:[A-Za-z_][A-Za-z0-9_?!]*(?:\s*,\s*[A-Za-z0-9_.:]+)*\s*,\s*'
    r'(?P<key>:[A-Za-z_][A-Za-z0-9_?!]*(?:[_-][A-Za-z0-9_?!]+)*)\s*,\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)'
)
ENV_FALLBACK_RE = re.compile(
    r'\bSystem\.get_env\s*\(\s*(?P<env_quote>["\'])(?P<env>[A-Za-z0-9_]+)(?P=env_quote)\s*,\s*'
    r'(?P<quote>["\'])(?P<value>[^"\'\n]{8,})(?P=quote)\s*\)'
)
LOW_VALUE_LITERAL_RE = re.compile(
    r'^(?:example|sample|dummy|placeholder|change[_-]?me|please[_-]?change|'
    r'localhost|127\.0\.0\.1|https?://example\.com)$',
    re.IGNORECASE,
)

def should_skip(path: Path) -> bool:
    try:
        rel_parts = path.relative_to(BASE_DIR).parts
    except ValueError:
        rel_parts = path.parts
    if any(part in SKIP_DIRS for part in rel_parts):
        return True
    normalized = '/'.join(rel_parts)
    return (
        '/test/' in f'/{normalized}/'
        or normalized.endswith('_test.exs')
        or normalized == 'config/test.exs'
        or normalized.endswith('/config/test.exs')
    )

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS and not should_skip(root):
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in EXTS and not should_skip(path):
            yield path

def strip_line_comment(line: str) -> str:
    out = []
    quote = ''
    escape = False
    for ch in line:
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            continue
        if ch == '#':
            break
        out.append(ch)
    return ''.join(out)

def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )

def relpath(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace('\t', ' ')
    return ''

def looks_like_secret_literal(value: str) -> bool:
    raw = value.strip()
    if len(raw) < 8:
        return False
    if LOW_VALUE_LITERAL_RE.search(raw):
        return False
    if re.fullmatch(r'[\w.-]+', raw) and raw.upper() == raw and '_' in raw:
        return False
    return True

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return
    if not (SECRET_KEY_RE.search(text) or 'System.get_env' in text):
        return
    lines = text.splitlines()
    seen = set()
    for idx, _ in enumerate(lines, start=1):
        if has_ignore(lines, idx):
            continue
        statement = strip_line_comment(lines[idx - 1]).strip()
        for regex in (ASSIGNMENT_SECRET_RE, MODULE_ATTR_SECRET_RE, CONFIG_SECRET_RE):
            for match in regex.finditer(statement):
                key = match.group('key').lstrip('@:')
                value = match.group('value')
                if not SECRET_KEY_RE.search(key):
                    continue
                if not looks_like_secret_literal(value):
                    continue
                issue_key = (relpath(path), idx, key)
                if issue_key in seen:
                    continue
                seen.add(issue_key)
                issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [hardcoded {key}]"))
        for match in ENV_FALLBACK_RE.finditer(statement):
            env_name = match.group('env')
            value = match.group('value')
            if not (SECRET_KEY_RE.search(env_name) and looks_like_secret_literal(value)):
                continue
            issue_key = (relpath(path), idx, env_name)
            if issue_key in seen:
                continue
            seen.add(issue_key)
            issues.append((relpath(path), idx, f"{source_line(lines, idx)}  [literal fallback for {env_name}]"))

issues = []
for file_path in iter_files(ROOT):
    analyze(file_path, issues)

print(f"__COUNT__\t{len(issues)}")
for file_name, line_no, code in issues[:5]:
    print(f"__SAMPLE__\t{file_name}\t{line_no}\t{code}")
PY
)
}

persist_metric_json() {
  local key=$1; local payload=$2
  [[ -n "$key" && -n "$payload" ]] || return 0
  [[ -n "${UBS_METRICS_DIR:-}" ]] || return 0
  mkdir -p "$UBS_METRICS_DIR" 2>/dev/null || true
  {
    printf '{"%s":' "$key"
    printf '%s' "$payload"
    printf '}'
  } >"$UBS_METRICS_DIR/$key.json"
}

begin_scan_section(){ if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set +o pipefail; fi; set +e; trap - ERR; }
end_scan_section(){ trap on_err ERR; set -e; if [[ "$DISABLE_PIPEFAIL_DURING_SCAN" -eq 1 ]]; then set -o pipefail; fi; }

mktemp_dir() { mktemp -d 2>/dev/null || mktemp -d -t ubs-elixir.XXXXXX; }
mktemp_file(){ mktemp 2>/dev/null    || mktemp    -t ubs-elixir.XXXXXX; }

with_timeout() {
  local seconds="$1"; shift || true
  if command -v timeout >/dev/null 2>&1; then timeout "$seconds" "$@"; else "$@"; fi
}

# Path helpers & robust file discovery
abspath() { perl -MCwd=abs_path -e 'print abs_path(shift)' -- "$1" 2>/dev/null || python3 - "$1" <<'PY'
import os,sys; print(os.path.abspath(sys.argv[1]))
PY
}
count_lines() { grep -v 'ubs:ignore' | awk 'END{print (NR>0?NR:0)}'; }

LC_ALL=C
IFS=',' read -r -a _EXT_ARR <<<"$INCLUDE_EXT"
INCLUDE_GLOBS=(); for e in "${_EXT_ARR[@]}"; do INCLUDE_GLOBS+=( "--include=*.$(echo "$e" | xargs)" ); done
EXCLUDE_DIRS=(.git .hg .svn .bzr _build deps .elixir_ls .hex .fetch node_modules dist build cover doc priv/static .cache .idea .vscode .history tmp log)
if [[ -n "$EXTRA_EXCLUDES" ]]; then IFS=',' read -r -a _X <<<"$EXTRA_EXCLUDES"; EXCLUDE_DIRS+=("${_X[@]}"); fi
EXCLUDE_FLAGS=(); for d in "${EXCLUDE_DIRS[@]}"; do EXCLUDE_FLAGS+=( "--exclude-dir=$d" ); done

build_find_cmd() {
  local mode="${UBS_FIND_PRUNE_MODE:-path}" ; local -a prune=( )
  if [[ "$mode" == "path" ]]; then
    for d in "${EXCLUDE_DIRS[@]}"; do prune+=( -path "$PROJECT_DIR/$d" -o ); done
  else
    for d in "${EXCLUDE_DIRS[@]}"; do prune+=( -name "$d" -o ); done
  fi
  [[ ${#prune[@]} -gt 0 ]] && unset 'prune[${#prune[@]}-1]'
  local -a names=( ); local first=1
  for e in "${_EXT_ARR[@]}"; do if [[ $first -eq 1 ]]; then names+=( -name "*.$e" ); first=0; else names+=( -o -name "*.$e" ); fi; done
  FIND_CMD=(find "$PROJECT_DIR" \( -type d \( "${prune[@]}" \) -prune \) -o \( -type f \( "${names[@]}" \) -print0 \))
}
build_find_cmd
safe_count_files(){ tr -cd '\0' | awk 'END{print (length>0?gsub(/\0/,"")+0:0)}'; }

if command -v rg >/dev/null 2>&1; then
  HAS_RIPGREP=1
  if [[ "${JOBS}" -eq 0 ]]; then JOBS="$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 0 )"; fi
  RG_JOBS=(); if [[ "${JOBS}" -gt 0 ]]; then RG_JOBS=(-j "$JOBS"); fi
  RG_BASE=(--no-config --no-messages --line-number --with-filename --hidden --pcre2 "${RG_JOBS[@]}")
  RG_EXCLUDES=(); for d in "${EXCLUDE_DIRS[@]}"; do RG_EXCLUDES+=( -g "!$d/**" ); done
  RG_INCLUDES=(); for e in "${_EXT_ARR[@]}"; do RG_INCLUDES+=( -g "*.$(echo "$e" | xargs)" ); done
  GREP_RN=(rg "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNI=(rg -i "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  GREP_RNW=(rg -w "${RG_BASE[@]}" "${RG_EXCLUDES[@]}" "${RG_INCLUDES[@]}")
  RG_JOBS=()
else
  GREP_R_OPTS=(-R --binary-files=without-match "${EXCLUDE_FLAGS[@]}" "${INCLUDE_GLOBS[@]}")
  GREP_RN=("grep" "${GREP_R_OPTS[@]}" -n -E)
  GREP_RNI=("grep" "${GREP_R_OPTS[@]}" -n -i -E)
  GREP_RNW=("grep" "${GREP_R_OPTS[@]}" -n -w -E)
fi

# Mix/toolchain helpers
check_mix() {
  if command -v mix >/dev/null 2>&1 && [[ -f "$PROJECT_DIR/mix.exs" ]]; then
    HAS_MIX=1; return 0
  fi
  HAS_MIX=0; return 1
}

check_phoenix() {
  if [[ -f "$PROJECT_DIR/mix.exs" ]] && grep -q ':phoenix' "$PROJECT_DIR/mix.exs" 2>/dev/null; then
    IS_PHOENIX=1; return 0
  fi
  IS_PHOENIX=0; return 1
}

run_mix_tool() {
  local tool_cmd="$1"; shift || true
  if [[ "$ENABLE_MIX_TOOLS" -eq 1 && "$HAS_MIX" -eq 1 ]]; then
    ( cd "$PROJECT_DIR" && with_timeout "$EX_TIMEOUT" mix $tool_cmd "$@" ) || true
  else
    say "  ${GRAY}${INFO} mix not available or tools disabled; skipping${RESET}"
  fi
}

# Category gating (run if returns 0)
run_category() {
  local cat="$1"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    IFS=',' read -r -a arr <<<"$ONLY_CATEGORIES"
    for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 0; done
    return 1
  fi
  if [[ -z "$SKIP_CATEGORIES" ]]; then return 0; fi
  IFS=',' read -r -a arr <<<"$SKIP_CATEGORIES"
  for s in "${arr[@]}"; do [[ "$s" == "$cat" ]] && return 1; done
  return 0
}

# ────────────────────────────────────────────────────────────────────────────
# Init
# ────────────────────────────────────────────────────────────────────────────
maybe_clear

if ! is_machine_format; then
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗  ║
║  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝  ║
║  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗    ║
║  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝    ║
║  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗  ║
║   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝  ║
║                                                                  ║
║  ██████╗ ██╗   ██╗ ██████╗                                       ║
║  ██╔══██╗██║   ██║██╔════╝                                       ║
║  ██████╔╝██║   ██║██║  ███╗                                      ║
║  ██╔══██╗██║   ██║██║   ██║                                      ║
║  ██████╔╝╚██████╔╝╚██████╔╝                                     ║
║  ╚═════╝  ╚═════╝  ╚═════╝                                      ║
║                                                                  ║
║  ███████╗  ██████╗   █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║
║  ██╔════╝  ██╔═══╝  ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║
║  ███████╗  ██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║
║  ╚════██║  ██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ███████║  ██████╗  ██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║
║  ╚══════╝  ╚═════╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝      ║
║                                                                  ║
║  Elixir module • OTP, Phoenix security, Ecto, concurrency        ║
║  UBS module: elixir • Dialyxir, Credo, Sobelow, Doctor, MixAudit║
║  Run standalone: modules/ubs-elixir.sh --help                    ║
║                                                                  ║
║  Night Owl QA                                                    ║
║  "We see bugs before you do."                                    ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"
fi

PROJECT_DIR="$(abspath "$PROJECT_DIR")"
say "${WHITE}Project:${RESET}  ${CYAN}$PROJECT_DIR${RESET}"
say "${WHITE}Started:${RESET}  ${GRAY}$(safe_date)${RESET}"

# Count files with robust find
TOTAL_FILES=$( ( set +o pipefail; "${FIND_CMD[@]}" 2>/dev/null || true ) | safe_count_files )
TOTAL_FILES=$(( TOTAL_FILES + 0 ))
say "${WHITE}Files:${RESET}    ${CYAN}$TOTAL_FILES source files (${INCLUDE_EXT})${RESET}"

# Mix availability & Phoenix detection
say ""
if check_mix; then
  say "${GREEN}${CHECK} Mix detected - ${DIM}will run extra analyzers via mix${RESET}"
else
  say "${YELLOW}${WARN} Mix or mix.exs not detected - will skip tool-based analyzers${RESET}"
fi
if check_phoenix; then
  say "${GREEN}${CHECK} Phoenix framework detected${RESET}"
else
  say "${DIM}${INFO} No Phoenix framework detected (sobelow may be N/A)${RESET}"
fi

# relax pipefail for scanning (optional)
begin_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 1: PATTERN MATCHING & GUARDS
# ═══════════════════════════════════════════════════════════════════════════
if run_category 1; then
print_header "1. PATTERN MATCHING & GUARDS"
print_category "Detects: catch-all clauses, missing guards, unsafe pattern matches" \
  "Pattern matching is Elixir's strength but subtle errors cause MatchError."

print_subheader "Bare catch-all variable in case/cond (potential swallowed branch)"
count=$("${GREP_RN[@]}" -e "^\s*_\s*->" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Catch-all _ -> clauses" "Ensure these are intentional and not hiding missed cases"
  show_detailed_finding "^\s*_\s*->" 5
elif [ "$count" -gt 0 ]; then
  print_finding "good" "Limited catch-all clauses ($count found)"
fi

print_subheader "Matching on {:error, _} without logging/handling the reason"
count=$("${GREP_RN[@]}" -e "\{:error,\s*_\}" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Error tuples matched with {:error, _} - reason discarded" "Use {:error, reason} and log or handle the reason"
  show_detailed_finding "\{:error,\s*_\}" 5
else
  print_finding "good" "No discarded error reasons"
fi

print_subheader "Unguarded function heads (when guards missing on multi-clause functions)"
count=$("${GREP_RN[@]}" -e "def\s+\w+\(.*\)\s*do" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
guarded=$("${GREP_RN[@]}" -e "def\s+\w+\(.*\)\s+when\s+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 50 ] && [ "$guarded" -lt 5 ]; then
  print_finding "info" "$count" "Function definitions mostly lack when guards" "Consider guards for defensive multi-clause functions"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 2: ERROR HANDLING & EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════
if run_category 2; then
print_header "2. ERROR HANDLING & EXCEPTIONS"
print_category "Detects: bare rescue, raise without message, bang functions in unsafe contexts" \
  "Proper error handling prevents crashes and aids debugging."

print_subheader "Bare rescue without specific exception type"
count=$("${GREP_RN[@]}" -e "rescue\s*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "rescue\s+_\s*->" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count=$((count + count2))
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Bare rescue (catches all exceptions broadly)" "Rescue specific exception types, e.g., rescue RuntimeError ->"
  show_detailed_finding "rescue\s*((_\s*->)|$)" 5
else
  print_finding "good" "No bare rescue clauses"
fi

print_subheader "raise/throw without message or specific exception"
count=$("${GREP_RN[@]}" -e "raise\s*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "raise without error message or exception module" "Use raise \"message\" or raise SomeError, message: \"...\""
  show_detailed_finding "raise\s*$" 3
fi

print_subheader "Bang (!) functions in GenServer callbacks (crash risk)"
count=$("${GREP_RN[@]}" -e "def\s+handle_(call|cast|info).*!" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Bang functions in GenServer callbacks" "Crashes bring down the GenServer; use non-bang variants with pattern matching"
  show_detailed_finding "def\s+handle_(call|cast|info).*!" 3
fi

print_subheader "try/rescue blocks (prefer with/pattern matching)"
count=$("${GREP_RN[@]}" -e "^\s*try\s+do" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "try/rescue blocks found" "Elixir favors tagged tuples and with over try/rescue"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 3: PROCESS & OTP LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════
if run_category 3; then
print_header "3. PROCESS & OTP LIFECYCLE"
print_category "Detects: unsupervised processes, linked process risks, missing trap_exit" \
  "OTP supervision trees prevent cascading failures."

print_subheader "spawn/spawn_link without supervision (prefer Task.Supervisor)"
count=$("${GREP_RN[@]}" -e "\bspawn\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "\bspawn_link\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 5 ]; then
  print_finding "warning" "$total" "Unsupervised spawn/spawn_link calls" "Use Task.Supervisor.start_child/2 or add to supervision tree"
  show_detailed_finding "\bspawn(_link)?\s*\(" 5
elif [ "$total" -gt 0 ]; then
  print_finding "info" "$total" "spawn/spawn_link usage found - verify supervision"
fi

print_subheader "Process.exit/2 with :kill (untrappable, use carefully)"
count=$("${GREP_RN[@]}" -e "Process\.exit\(.*:kill" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Process.exit with :kill (untrappable signal)" "Use :shutdown or :normal for graceful termination"
  show_detailed_finding "Process\.exit\(.*:kill" 3
fi

print_subheader "GenServer without proper init/1 return"
count=$("${GREP_RN[@]}" -e "def\s+init\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  bad_init=$("${GREP_RN[@]}" -e "def\s+init\(" "$PROJECT_DIR" 2>/dev/null | \
    (grep -v -E "\{:ok,|:ignore|\{:stop," || true) | count_lines)
  if [ "$bad_init" -gt 0 ]; then
    print_finding "info" "$bad_init" "init/1 callbacks may not return {:ok, state}" "init/1 must return {:ok, state}, {:ok, state, opts}, :ignore, or {:stop, reason}"
  fi
fi

print_subheader "Task.async without Task.await (resource leak)"
async_count=$("${GREP_RN[@]}" -e "Task\.async\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
await_count=$("${GREP_RN[@]}" -e "Task\.await\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$async_count" -gt 0 ] && [ "$await_count" -lt "$async_count" ]; then
  diff=$((async_count - await_count))
  print_finding "warning" "$diff" "Task.async calls may lack matching Task.await" "Unmatched async tasks leak processes; use Task.await or Task.yield"
fi

print_subheader "send/2 to unregistered or hardcoded PIDs"
count=$("${GREP_RN[@]}" -e "\bsend\(\s*#PID" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Sending messages to hardcoded PIDs" "Use registered names or process references instead"
  show_detailed_finding "\bsend\(\s*#PID" 3
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 4: SECURITY VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
if run_category 4; then
print_header "4. SECURITY VULNERABILITIES"
print_category "Detects: code injection, request path traversal, open redirects, response header injection, outbound URL SSRF, archive traversal, SQL injection, crypto misuse, insecure token randomness, hardcoded secrets" \
  "Security issues in Elixir/Phoenix applications."

print_subheader "Code execution via Code.eval_string / Code.eval_quoted"
count=$("${GREP_RN[@]}" -e "Code\.eval_(string|quoted|file)\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "critical" "$count" "Dynamic code evaluation (Code.eval_*)" "Avoid eval with user input; use module attributes or compiled code"
  show_detailed_finding "Code\.eval_(string|quoted|file)\b" 5
fi

print_subheader "System command execution"
critical_pattern=':os\.cmd\b|System\.shell\b|Port\.open\(\s*\{:spawn,|System\.cmd\s*\(\s*"(((/usr)?/bin/)?(sh|bash|zsh)|cmd(\.exe)?|powershell|pwsh)"\s*,\s*\[[^]]*("-c"|"/C"|"-Command")|System\.cmd\s*\(\s*"/usr/bin/env"\s*,\s*\[[^]]*"(sh|bash|zsh)"[^]]*("-c")'
variable_pattern='System\.cmd\s*\(\s*[A-Za-z_][A-Za-z0-9_?!]*\s*,'
all_pattern='System\.cmd\b|System\.shell\b|:os\.cmd\b|Port\.open\(\s*\{:spawn,'
critical_count=$("${GREP_RN[@]}" -e "$critical_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$critical_count" -gt 0 ]; then
  print_finding "critical" "$critical_count" "Shell-backed command execution" "Avoid :os.cmd, System.shell, Port {:spawn, ...}, and System.cmd(\"sh\", [\"-c\", ...]); prefer fixed executables with argv lists."
  show_detailed_finding "$critical_pattern" 5
fi
variable_count=$("${GREP_RN[@]}" -e "$variable_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$variable_count" -gt 0 ]; then
  print_finding "warning" "$variable_count" "System.cmd executable comes from a variable" "Allowlist command names before passing them to System.cmd/3."
  show_detailed_finding "$variable_pattern" 3
fi
count=$("${GREP_RN[@]}" -e "$all_pattern" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
review_count=$((count - critical_count - variable_count))
if [ "$review_count" -lt 0 ]; then review_count=0; fi
if [ "$review_count" -gt 0 ]; then
  print_finding "info" "$review_count" "Fixed System.cmd/Port command execution present - validate argv boundaries"
  show_detailed_finding "$all_pattern" 3
elif [ "$critical_count" -eq 0 ] && [ "$variable_count" -eq 0 ]; then
  print_finding "good" "No System command execution detected"
fi

run_archive_extraction_checks
run_request_path_traversal_checks
run_request_open_redirect_checks
run_request_response_header_checks
run_request_outbound_url_checks

print_subheader "SQL injection: raw/fragment with interpolation in Ecto"
count=$("${GREP_RN[@]}" -e 'fragment\(".*#\{' "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e 'Ecto\.Adapters\.SQL\.query.*".*#\{' "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "critical" "$total" "Possible SQL injection via string interpolation in Ecto fragments/queries" "Use parameterized queries: fragment(\"... ?\", ^param)"
  show_detailed_finding 'fragment\(".*#\{|Ecto\.Adapters\.SQL\.query.*".*#\{' 5
fi

run_hardcoded_secret_checks

print_subheader "Weak crypto: :md5 or :sha (prefer :sha256+)"
count=$("${GREP_RN[@]}" -e ":crypto\.(hash|hmac)\(:(md5|sha)\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e ":md5\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "warning" "$total" "Weak hash algorithm (:md5 or :sha)" "Use :sha256 or :sha3_256 for security-sensitive hashing"
  show_detailed_finding ":crypto\.(hash|hmac)\(:(md5|sha)\b|:md5\b" 3
fi

run_security_randomness_checks

print_subheader "Atom creation from user input (atom table exhaustion)"
count=$("${GREP_RN[@]}" -e "String\.to_atom\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "String.to_atom/1 (atom table is finite, never GC'd)" "Use String.to_existing_atom/1 for user-supplied input"
  show_detailed_finding "String\.to_atom\b" 5
fi

print_subheader "Unsafe deserialization (:erlang.binary_to_term without :safe)"
count=$("${GREP_RN[@]}" -e ":erlang\.binary_to_term\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  safe=$("${GREP_RN[@]}" -e ":erlang\.binary_to_term\(.*\[:safe\]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  unsafe=$((count - safe))
  if [ "$unsafe" -gt 0 ]; then
    print_finding "critical" "$unsafe" "binary_to_term without [:safe] option" "Always pass [:safe] to prevent arbitrary atom/code execution"
    show_detailed_finding ":erlang\.binary_to_term\b" 3
  fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 5: PHOENIX-SPECIFIC ISSUES
# ═══════════════════════════════════════════════════════════════════════════
if run_category 5; then
print_header "5. PHOENIX-SPECIFIC ISSUES"
print_category "Detects: CSRF bypass, unsafe HTML, missing CORS, plug pipeline gaps" \
  "Phoenix framework security and correctness patterns."

if [[ "$IS_PHOENIX" -eq 1 ]]; then

print_subheader "CSRF protection disabled or skipped"
count=$("${GREP_RN[@]}" -e "plug\s+:protect_from_forgery.*false|delete_csrf_token" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "Plug\.CSRFProtection.*false" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "warning" "$total" "CSRF protection may be disabled" "Ensure CSRF is active on state-changing routes"
  show_detailed_finding "protect_from_forgery.*false|delete_csrf_token|CSRFProtection.*false" 3
fi

print_subheader "raw/2 in templates (XSS risk)"
count=$("${GREP_RN[@]}" -e "\braw\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "raw/2 usage in templates (bypasses HTML escaping)" "Sanitize content before using raw/2"
  show_detailed_finding "\braw\s*\(" 5
elif [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "raw/2 found - verify content is sanitized"
fi

print_subheader "Missing Plug.SSL / force_ssl in production"
count=$("${GREP_RNI[@]}" -e "force_ssl|Plug\.SSL" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -eq 0 ]; then
  print_finding "info" "1" "No force_ssl configuration detected" "Consider Plug.SSL or force_ssl: for production HTTPS"
fi

print_subheader "Controller actions without auth plug"
count=$("${GREP_RN[@]}" -e "def\s+(index|show|create|update|delete)\s*\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
auth=$("${GREP_RNI[@]}" -e "plug\s+:.*auth|plug\s+.*Auth" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ] && [ "$auth" -eq 0 ]; then
  print_finding "warning" "$count" "Controller actions found but no auth plugs detected" "Add authentication/authorization plugs to protect routes"
fi

else
  say "  ${GRAY}${INFO} Not a Phoenix project; skipping Phoenix-specific checks${RESET}"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 6: ECTO & DATABASE
# ═══════════════════════════════════════════════════════════════════════════
if run_category 6; then
print_header "6. ECTO & DATABASE"
print_category "Detects: N+1 queries, missing indexes, unsafe changesets" \
  "Database patterns that impact correctness and performance."

print_subheader "N+1 query patterns (association access in loops)"
count=$("${GREP_RN[@]}" -e "Enum\.(map|each|reduce)\(.*\.\w+\.\w+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Possible N+1 queries (association traversal in loops)" "Use Repo.preload/2 or Ecto.Query.preload/2"
  show_detailed_finding "Enum\.(map|each|reduce)\(.*\.\w+\.\w+" 5
fi

print_subheader "Repo.insert!/update!/delete! in non-test code (crash on failure)"
count=$("${GREP_RN[@]}" -e "Repo\.(insert|update|delete)!\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "Bang Repo operations outside tests" "Use Repo.insert/update/delete and pattern match on {:ok, _}/{:error, _}"
  show_detailed_finding "Repo\.(insert|update|delete)!\b" 5
fi

print_subheader "Changeset without validate_required"
count=$("${GREP_RN[@]}" -e "def\s+changeset\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
validated=$("${GREP_RN[@]}" -e "validate_required\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ] && [ "$validated" -eq 0 ]; then
  print_finding "warning" "$count" "Changeset functions found but no validate_required calls" "Add validate_required/3 to ensure mandatory fields"
fi

print_subheader "Transactions without Multi (complex multi-step writes)"
count=$("${GREP_RN[@]}" -e "Repo\.transaction\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
multi=$("${GREP_RN[@]}" -e "Ecto\.Multi\b|Multi\.new\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ] && [ "$multi" -eq 0 ]; then
  print_finding "info" "$count" "Repo.transaction without Ecto.Multi" "Consider Ecto.Multi for complex transactional workflows"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 7: CONCURRENCY & MESSAGING
# ═══════════════════════════════════════════════════════════════════════════
if run_category 7; then
print_header "7. CONCURRENCY & MESSAGING"
print_category "Detects: mailbox overflow risks, blocking calls, ETS misuse" \
  "Concurrency patterns that cause deadlocks or memory issues."

print_subheader "Potential mailbox overflow (send without flow control)"
count=$("${GREP_RN[@]}" -e "\bsend\(\s*self\(\)" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "warning" "$count" "send(self(), ...) patterns" "Self-sends in loops can overflow the mailbox; use handle_continue"
  show_detailed_finding "\bsend\(\s*self\(\)" 3
fi

print_subheader "GenServer.call with default timeout (5s may be too short)"
count=$("${GREP_RN[@]}" -e "GenServer\.call\([^,)]+\)\s*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "GenServer.call without explicit timeout" "Consider explicit timeouts for production calls"
fi

print_subheader "ETS table without :named_table or read_concurrency"
count=$("${GREP_RN[@]}" -e ":ets\.new\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  optimized=$("${GREP_RN[@]}" -e ":ets\.new.*read_concurrency" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "$optimized" -lt "$count" ]; then
    diff=$((count - optimized))
    print_finding "info" "$diff" "ETS tables without read_concurrency optimization" "Add read_concurrency: true for read-heavy tables"
  fi
fi

print_subheader "Agent misuse (Agent for complex state; prefer GenServer)"
count=$("${GREP_RN[@]}" -e "Agent\.(start|start_link|get|update|get_and_update)\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 20 ]; then
  print_finding "info" "$count" "Heavy Agent usage" "Agents suit simple state; consider GenServer for complex logic"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 8: I/O & RESOURCE LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════
if run_category 8; then
print_header "8. I/O & RESOURCE LIFECYCLE"
print_category "Detects: file handles without close, port leaks, socket management" \
  "Resource leaks exhaust file descriptors and ports."

print_subheader "File.open without File.close or block form"
open_count=$("${GREP_RN[@]}" -e "File\.open\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
close_count=$("${GREP_RN[@]}" -e "File\.close\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
stream_count=$("${GREP_RN[@]}" -e "File\.stream!\b|File\.open.*fn\s" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$open_count" -gt 0 ]; then
  unmatched=$((open_count - close_count - stream_count))
  if [ "$unmatched" -gt 2 ]; then
    print_finding "warning" "$unmatched" "File.open without matching File.close or stream" "Use File.open!/2 with a function or File.stream!/1"
    show_detailed_finding "File\.open\b" 3
  fi
fi

print_subheader "Port.open without Port.close"
port_open=$("${GREP_RN[@]}" -e "Port\.open\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
port_close=$("${GREP_RN[@]}" -e "Port\.close\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$port_open" -gt 0 ] && [ "$port_close" -lt "$port_open" ]; then
  diff=$((port_open - port_close))
  print_finding "warning" "$diff" "Port.open without matching Port.close" "Ensure ports are closed to prevent resource leaks"
fi

print_subheader "Large file reads (File.read! on potentially large files)"
count=$("${GREP_RN[@]}" -e "File\.read!\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "File.read! calls (loads entire file into memory)" "Use File.stream!/1 for large files"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 9: DEBUGGING & PRODUCTION CODE
# ═══════════════════════════════════════════════════════════════════════════
if run_category 9; then
print_header "9. DEBUGGING & PRODUCTION CODE"
print_category "Detects: IO.inspect, IEx.pry, dbg(), Logger misuse" \
  "Debug artifacts in production code and logging hygiene."

print_subheader "IO.inspect/2 left in code (debug artifact)"
count=$("${GREP_RN[@]}" -e "IO\.inspect\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs|#\s*" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "IO.inspect calls in non-test code" "Remove debug IO.inspect before production"
  show_detailed_finding "IO\.inspect\b" 5
fi

print_subheader "IEx.pry (interactive debugger breakpoint)"
count=$("${GREP_RN[@]}" -e "IEx\.pry\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "IEx.pry breakpoints in non-test code" "Remove before deployment"
  show_detailed_finding "IEx\.pry\b" 3
fi

print_subheader "dbg() macro (Elixir 1.14+ debug macro)"
count=$("${GREP_RN[@]}" -e "\bdbg\(\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs" || true) | count_lines)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "dbg() calls in non-test code" "Remove debug macros before production"
  show_detailed_finding "\bdbg\(\b" 3
fi

print_subheader "IO.puts for logging (prefer Logger)"
count=$("${GREP_RN[@]}" -e "IO\.puts\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs|mix\.exs" || true) | count_lines)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "IO.puts used instead of Logger" "Use Logger.info/warn/error for structured logging"
fi

print_subheader "TODO/FIXME/HACK/XXX markers"
count=$("${GREP_RNI[@]}" -e "\b(TODO|FIXME|HACK|XXX)\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "TODO/FIXME/HACK/XXX markers in code"
  show_detailed_finding "\b(TODO|FIXME|HACK|XXX)\b" 5
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 10: PERFORMANCE & MEMORY
# ═══════════════════════════════════════════════════════════════════════════
if run_category 10; then
print_header "10. PERFORMANCE & MEMORY"
print_category "Detects: string concatenation in loops, large binaries, inefficient patterns" \
  "Performance anti-patterns in Elixir applications."

print_subheader "String concatenation with <> in Enum loops"
count=$("${GREP_RN[@]}" -e "Enum\.(reduce|map).*<>" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "String concatenation in loops" "Use IO lists or Enum.join/2 instead of repeated <>"
  show_detailed_finding "Enum\.(reduce|map).*<>" 3
fi

print_subheader "Enum.count when length check suffices"
count=$("${GREP_RN[@]}" -e "Enum\.count\(.*[=!><]" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "Enum.count for size comparisons" "Use match?([_ | _], list) or length/1 for known-bounded checks"
fi

print_subheader "Recursive functions without tail-call optimization"
count=$("${GREP_RN[@]}" -e "def\s+(\w+).*\1\(" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Recursive function calls detected" "Ensure recursive calls are in tail position for TCO"
fi

print_subheader "Large binary literals in source"
count=$("${GREP_RN[@]}" -e '<<[^>]{500,}>>' "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Large binary literals in source" "Consider loading from files or priv/"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 11: CODE QUALITY MARKERS
# ═══════════════════════════════════════════════════════════════════════════
if run_category 11; then
print_header "11. CODE QUALITY MARKERS"
print_category "Detects: unused variables, long functions, complex nesting" \
  "Code quality indicators for maintainability."

print_subheader "Unused variables (prefixed with _ but still used, or vice versa)"
count=$("${GREP_RN[@]}" -e "warning:.*variable.*is unused" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Compiler warnings about unused variables"
fi

print_subheader "Deeply nested case/cond/with (complexity)"
count=$("${GREP_RN[@]}" -e "^\s{8,}(case|cond|with)\s" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Deeply nested control structures" "Extract to helper functions or use with for flat chaining"
  show_detailed_finding "^\s{8,}(case|cond|with)\s" 3
fi

print_subheader "@moduledoc false (undocumented public modules)"
count=$("${GREP_RN[@]}" -e "@moduledoc\s+false" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 10 ]; then
  print_finding "info" "$count" "Modules with @moduledoc false" "Consider adding documentation for public modules"
fi

print_subheader "@doc false (undocumented public functions)"
count=$("${GREP_RN[@]}" -e "@doc\s+false" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 15 ]; then
  print_finding "info" "$count" "Functions with @doc false" "Consider documenting public API functions"
fi

print_subheader "Missing @spec annotations"
def_count=$("${GREP_RN[@]}" -e "^\s*def\s+\w+\(" "$PROJECT_DIR" 2>/dev/null | \
  (grep -v -E "test/|_test\.exs" || true) | count_lines)
spec_count=$("${GREP_RN[@]}" -e "@spec\s+" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$def_count" -gt 20 ] && [ "$spec_count" -lt 5 ]; then
  print_finding "info" "$def_count" "Public functions mostly lack @spec annotations" "Add @spec for key public functions to enable Dialyzer"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 12: CONFIGURATION & ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════
if run_category 12; then
print_header "12. CONFIGURATION & ENVIRONMENT"
print_category "Detects: compile-time env reads, missing runtime config" \
  "Configuration mistakes that cause deploy issues."

print_subheader "Application.get_env at compile time (in module body)"
count=$("${GREP_RN[@]}" -e "^[^#]*@\w+\s+Application\.get_env\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "Application.get_env in module attribute (compile-time read)" "Use Application.get_env in functions or runtime.exs"
  show_detailed_finding "@\w+\s+Application\.get_env\b" 3
fi

print_subheader "System.get_env at compile time"
count=$("${GREP_RN[@]}" -e "^[^#]*@\w+\s+System\.get_env\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "warning" "$count" "System.get_env in module attribute (compile-time read)" "Use runtime.exs or read env vars in application start"
  show_detailed_finding "@\w+\s+System\.get_env\b" 3
fi

print_subheader "Missing runtime.exs (Elixir 1.11+ runtime config)"
if [[ -f "$PROJECT_DIR/config/config.exs" ]] && [[ ! -f "$PROJECT_DIR/config/runtime.exs" ]]; then
  print_finding "info" "1" "No config/runtime.exs found" "Consider using runtime.exs for deployment-time configuration"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 13: TESTING PATTERNS
# ═══════════════════════════════════════════════════════════════════════════
if run_category 13; then
print_header "13. TESTING PATTERNS"
print_category "Detects: flaky test patterns, missing assertions, async pitfalls" \
  "Test reliability and coverage markers."

print_subheader "Tests without assertions (empty or single-line tests)"
count=$("${GREP_RN[@]}" -e "test\s+\".*\"\s+do\s*$" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Test blocks found" "Verify each test has meaningful assertions"
fi

print_subheader ":timer.sleep in tests (flaky test risk)"
count=$("${GREP_RN[@]}" -e ":timer\.sleep\b|Process\.sleep\b" "$PROJECT_DIR" 2>/dev/null | \
  (grep -E "test/|_test\.exs" || true) | count_lines)
if [ "$count" -gt 3 ]; then
  print_finding "warning" "$count" "Sleep calls in tests (flaky)" "Use ExUnit.Assertions.assert_receive with timeout instead"
  show_detailed_finding ":timer\.sleep\b|Process\.sleep\b" 3
fi

print_subheader "async: true tests accessing shared database state"
count=$("${GREP_RN[@]}" -e "async:\s*true" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  sandbox=$("${GREP_RN[@]}" -e "Ecto\.Adapters\.SQL\.Sandbox" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
  if [ "$sandbox" -eq 0 ] && [ "$count" -gt 5 ]; then
    print_finding "warning" "$count" "Async tests without Ecto.Adapters.SQL.Sandbox" "Use Sandbox mode :manual with checkout for async DB tests"
  fi
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 14: DEPENDENCY & MIX HYGIENE
# ═══════════════════════════════════════════════════════════════════════════
if run_category 14; then
print_header "14. DEPENDENCY & MIX HYGIENE"
print_category "Detects: unpinned deps, git deps in prod, stale lock file" \
  "Dependency management practices."

if [[ -f "$PROJECT_DIR/mix.exs" ]]; then

print_subheader "Git dependencies (prefer Hex packages)"
count=$("${GREP_RN[@]}" -e "git:\s*\"" "$PROJECT_DIR/mix.exs" 2>/dev/null | count_lines || true)
if [ "$count" -gt 0 ]; then
  print_finding "info" "$count" "Git-sourced dependencies in mix.exs" "Prefer Hex packages for reproducible builds"
  show_detailed_finding "git:\s*\"" 3
fi

print_subheader "Dependencies without version constraints"
count=$("${GREP_RN[@]}" -e '\{:\w+,\s*"~>' "$PROJECT_DIR/mix.exs" 2>/dev/null | count_lines || true)
total_deps=$("${GREP_RN[@]}" -e '\{:\w+,' "$PROJECT_DIR/mix.exs" 2>/dev/null | count_lines || true)
unpinned=$((total_deps - count))
if [ "$unpinned" -gt 3 ]; then
  print_finding "info" "$unpinned" "Dependencies possibly without version constraints" "Pin versions with ~> for reproducible builds"
fi

print_subheader "mix.lock present and committed"
if [[ ! -f "$PROJECT_DIR/mix.lock" ]]; then
  print_finding "warning" "1" "No mix.lock file found" "Run mix deps.get and commit mix.lock for reproducible builds"
fi

fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 15: STRING & BINARY SAFETY
# ═══════════════════════════════════════════════════════════════════════════
if run_category 15; then
print_header "15. STRING & BINARY SAFETY"
print_category "Detects: unsafe string operations, encoding issues, regex pitfalls" \
  "String/binary handling safety in Elixir."

print_subheader "Regex with user input (ReDoS risk)"
count=$("${GREP_RN[@]}" -e "Regex\.(compile|run)\b.*#\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
count2=$("${GREP_RN[@]}" -e "~r/.*#\{" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
total=$((count + count2))
if [ "$total" -gt 0 ]; then
  print_finding "warning" "$total" "Regex with interpolated input (ReDoS risk)" "Validate/escape user input before regex compilation"
  show_detailed_finding "Regex\.(compile|run)\b.*#\{|~r/.*#\{" 3
fi

print_subheader "byte_size vs String.length confusion"
count=$("${GREP_RN[@]}" -e "\bbyte_size\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 5 ]; then
  print_finding "info" "$count" "byte_size/1 usage (returns bytes, not characters)" "Use String.length/1 for character count with Unicode"
fi

print_subheader "String.to_integer without rescue (crash on invalid input)"
count=$("${GREP_RN[@]}" -e "String\.to_integer\b" "$PROJECT_DIR" 2>/dev/null | count_lines || true)
if [ "$count" -gt 3 ]; then
  print_finding "info" "$count" "String.to_integer/1 (raises on invalid input)" "Use Integer.parse/1 for safe conversion with error handling"
fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# CATEGORY 16: MIX-POWERED EXTRA ANALYZERS (optional)
# ═══════════════════════════════════════════════════════════════════════════
if run_category 16; then
print_header "16. MIX-POWERED EXTRA ANALYZERS"
print_category "Dialyxir (types), Credo (quality), Sobelow (security), Doctor (docs), Inch (coverage), MixAudit (deps)" \
  "These tools augment ripgrep-based heuristic results."

if [[ "$ENABLE_MIX_TOOLS" -eq 1 && "$HAS_MIX" -eq 1 ]]; then
  IFS=',' read -r -a EXTOOLS <<< "$EX_TOOLS"
  for TOOL in "${EXTOOLS[@]}"; do
    case "$TOOL" in
      dialyzer)
        print_subheader "dialyxir / mix dialyzer (static type analysis)"
        if ( cd "$PROJECT_DIR" && mix help dialyzer >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix dialyzer (this may take a while on first run)...${RESET}"
          output=$(run_mix_tool "dialyzer" --format short 2>&1 || true)
          if [[ -n "$output" ]]; then
            errs=$(echo "$output" | grep -c -E "error:|warning:" || true)
            if [ "$errs" -gt 0 ]; then
              print_finding "warning" "$errs" "Dialyzer found type discrepancies" "Run 'mix dialyzer' for full details"
            else
              print_finding "good" "Dialyzer passed with no warnings"
            fi
          else
            print_finding "good" "Dialyzer analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} dialyxir not installed; add {:dialyxir, \"~> 1.4\", only: [:dev], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      credo)
        print_subheader "credo (code quality / style)"
        if ( cd "$PROJECT_DIR" && mix help credo >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix credo --strict...${RESET}"
          output=$(run_mix_tool "credo" --strict --format flycheck 2>&1 || true)
          if [[ -n "$output" ]]; then
            issues=$(echo "$output" | grep -c -E "^.+:[0-9]+:" || true)
            if [ "$issues" -gt 0 ]; then
              print_finding "info" "$issues" "Credo found code quality issues" "Run 'mix credo --strict' for full details"
            else
              print_finding "good" "Credo passed with no issues"
            fi
          else
            print_finding "good" "Credo analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} credo not installed; add {:credo, \"~> 1.7\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      sobelow)
        print_subheader "sobelow (Phoenix security analysis)"
        if [[ "$IS_PHOENIX" -eq 1 ]]; then
          if ( cd "$PROJECT_DIR" && mix help sobelow >/dev/null 2>&1 ); then
            say "  ${DIM}Running mix sobelow --config...${RESET}"
            output=$(run_mix_tool "sobelow" --config --format txt 2>&1 || true)
            if [[ -n "$output" ]]; then
              vulns=$(echo "$output" | grep -c -E "^\[" || true)
              if [ "$vulns" -gt 0 ]; then
                print_finding "warning" "$vulns" "Sobelow found security issues" "Run 'mix sobelow --config' for full details"
              else
                print_finding "good" "Sobelow found no security issues"
              fi
            else
              print_finding "good" "Sobelow security scan clean"
            fi
          else
            say "  ${GRAY}${INFO} sobelow not installed; add {:sobelow, \"~> 0.13\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
          fi
        else
          say "  ${GRAY}${INFO} Not a Phoenix project; sobelow scan skipped${RESET}"
        fi
        ;;
      doctor)
        print_subheader "doctor (documentation / typespec checking)"
        if ( cd "$PROJECT_DIR" && mix help doctor >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix doctor...${RESET}"
          output=$(run_mix_tool "doctor" 2>&1 || true)
          if [[ -n "$output" ]]; then
            issues=$(echo "$output" | grep -c -E "FAILED|WARN" || true)
            if [ "$issues" -gt 0 ]; then
              print_finding "info" "$issues" "Doctor found documentation/typespec issues" "Run 'mix doctor' for full details"
            else
              print_finding "good" "Doctor check passed"
            fi
          else
            print_finding "good" "Doctor analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} doctor not installed; add {:doctor, \"~> 0.21\", only: :dev} to mix.exs${RESET}"
        fi
        ;;
      inch)
        print_subheader "inch_ex (documentation coverage)"
        if ( cd "$PROJECT_DIR" && mix help inch >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix inch...${RESET}"
          output=$(run_mix_tool "inch" 2>&1 || true)
          if [[ -n "$output" ]]; then
            undoc=$(echo "$output" | grep -c -E "\[U\]|\[C\]" || true)
            if [ "$undoc" -gt 5 ]; then
              print_finding "info" "$undoc" "inch_ex found undocumented/incomplete modules" "Run 'mix inch' for full coverage report"
            else
              print_finding "good" "Documentation coverage looks good"
            fi
          else
            print_finding "good" "inch_ex analysis clean"
          fi
        else
          say "  ${GRAY}${INFO} inch_ex not installed; add {:inch_ex, \"~> 2.0\", only: [:dev, :test]} to mix.exs${RESET}"
        fi
        ;;
      mix_audit)
        print_subheader "mix_audit (dependency vulnerability audit)"
        if ( cd "$PROJECT_DIR" && mix help deps.audit >/dev/null 2>&1 ); then
          say "  ${DIM}Running mix deps.audit...${RESET}"
          output=$(run_mix_tool "deps.audit" 2>&1 || true)
          if [[ -n "$output" ]]; then
            vulns=$(echo "$output" | grep -c -E "Vulnerability found|advisory" || true)
            if [ "$vulns" -gt 0 ]; then
              print_finding "critical" "$vulns" "MixAudit found dependency vulnerabilities" "Run 'mix deps.audit' and update affected dependencies"
            else
              print_finding "good" "No known dependency vulnerabilities"
            fi
          else
            print_finding "good" "Dependency audit clean"
          fi
        elif command -v mix_audit >/dev/null 2>&1; then
          say "  ${DIM}Running mix_audit...${RESET}"
          output=$( ( cd "$PROJECT_DIR" && with_timeout "$EX_TIMEOUT" mix_audit ) 2>&1 || true)
          if [[ -n "$output" ]]; then
            vulns=$(echo "$output" | grep -c -E "Vulnerability found|advisory" || true)
            if [ "$vulns" -gt 0 ]; then
              print_finding "critical" "$vulns" "MixAudit found dependency vulnerabilities"
            else
              print_finding "good" "No known dependency vulnerabilities"
            fi
          fi
        else
          say "  ${GRAY}${INFO} mix_audit not installed; add {:mix_audit, \"~> 2.1\", only: [:dev, :test], runtime: false} to mix.exs${RESET}"
        fi
        ;;
      *)
        say "  ${GRAY}${INFO} Unknown tool '$TOOL' ignored${RESET}"
        ;;
    esac
  done
else
  say "  ${GRAY}${INFO} Mix-based analyzers disabled (--no-mix or mix not found)${RESET}"
fi
fi

# restore pipefail if we relaxed it
end_scan_section

# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

EXIT_CODE=0
if [ "$CRITICAL_COUNT" -gt 0 ]; then EXIT_CODE=1; fi
if [ "$FAIL_ON_WARNING" -eq 1 ] && [ $((CRITICAL_COUNT + WARNING_COUNT)) -gt 0 ]; then EXIT_CODE=1; fi

if [[ "$FORMAT" == "json" ]]; then
  emit_json_summary
  exit "$EXIT_CODE"
fi
if [[ "$FORMAT" == "sarif" ]]; then
  emit_sarif
  exit "$EXIT_CODE"
fi

echo ""
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
say "${BOLD}${CYAN}                    ${POTION} SCAN COMPLETE ${POTION}                                  ${RESET}"
say "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

say "${WHITE}${BOLD}Summary Statistics:${RESET}"
say "  ${WHITE}Files scanned:${RESET}    ${CYAN}$TOTAL_FILES${RESET}"
say "  ${RED}${BOLD}Critical issues:${RESET}  ${RED}$CRITICAL_COUNT${RESET}"
say "  ${YELLOW}Warning issues:${RESET}   ${YELLOW}$WARNING_COUNT${RESET}"
say "  ${BLUE}Info items:${RESET}       ${BLUE}$INFO_COUNT${RESET}"
echo ""

say "${BOLD}${WHITE}Priority Actions:${RESET}"
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  say "  ${RED}${FIRE} ${BOLD}FIX CRITICAL ISSUES IMMEDIATELY${RESET}"
  say "  ${DIM}These cause crashes, security vulnerabilities, or data corruption${RESET}"
fi
if [ "$WARNING_COUNT" -gt 0 ]; then
  say "  ${YELLOW}${WARN} ${BOLD}Review and fix WARNING items${RESET}"
  say "  ${DIM}These cause bugs, performance issues, or maintenance problems${RESET}"
fi
if [ "$INFO_COUNT" -gt 0 ]; then
  say "  ${BLUE}${INFO} ${BOLD}Consider INFO suggestions${RESET}"
  say "  ${DIM}Code quality improvements and best practices${RESET}"
fi

if [ "$CRITICAL_COUNT" -eq 0 ] && [ "$WARNING_COUNT" -eq 0 ]; then
  say "\n  ${GREEN}${BOLD}${SPARKLE} EXCELLENT! No critical or warning issues found ${SPARKLE}${RESET}"
fi

echo ""
say "${DIM}Scan completed at: $(safe_date)${RESET}"

if [[ -n "$OUTPUT_FILE" ]]; then
  say "${GREEN}${CHECK} Full report saved to: ${CYAN}$OUTPUT_FILE${RESET}"
fi
if [[ -n "$SUMMARY_JSON" ]]; then
  mkdir -p "$(dirname "$SUMMARY_JSON")" 2>/dev/null || true
  printf '{"timestamp":"%s","files":%s,"critical":%s,"warning":%s,"info":%s}\n' \
     "$(safe_date)" "$TOTAL_FILES" "$CRITICAL_COUNT" "$WARNING_COUNT" "$INFO_COUNT" >"$SUMMARY_JSON"
fi

echo ""
if [ "$VERBOSE" -eq 0 ]; then
  say "${DIM}Tip: Run with -v/--verbose for more code samples per finding.${RESET}"
elif [ "$VERBOSE" -eq 2 ]; then
  say "${DIM}Very-verbose mode: showing up to $DETAIL_LIMIT samples per finding.${RESET}"
fi
say "${DIM}Add to pre-commit: ./ubs --ci --fail-on-warning . > elixir-bug-scan-report.txt${RESET}"
echo ""

exit "$EXIT_CODE"
