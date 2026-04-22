#!/usr/bin/env bash
# shellcheck disable=SC2002,SC2015,SC2034,SC2317
# UBS C# ULTIMATE BUG SCANNER v3.0
# Industrial-grade bug & footgun scanner for C#/.NET codebases.
# Inspired by UBS rust/cpp scanners: uses ripgrep + ast-grep + dotnet CLI (optional).
#
# Usage:
#   bash modules/ubs-csharp.sh [PROJECT_DIR] [options]
#
# Key options:
#   --format=text|json|sarif
#   --only=1,2,3        Run only specific categories
#   --skip=4,9          Skip categories
#   --ci                CI-friendly output + non-zero on critical
#   --strict-gitignore  Respect .gitignore (even without rg, via git check-ignore)
#   --no-dotnet         Skip dotnet build/test/format/list package checks
#   --summary-json=FILE Write machine-readable summary JSON
#   --emit-findings-json=FILE Write full findings JSON (same as stdout in --format=json)

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
  echo "ERROR: ubs-csharp.sh requires bash >= 4.0 (you have ${BASH_VERSION:-unknown})." >&2
  echo "       On macOS: 'brew install bash' and re-run via /opt/homebrew/bin/bash." >&2
  exit 2
fi

set -Eeuo pipefail
shopt -s lastpipe 2>/dev/null || true

VERSION="3.0"
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
DUMP_RULES_DIR=""
EXTRA_AST_RULES_DIRS=""

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
die() { echo "${RED}${ICON_CRIT} $*${RESET}" >&2; exit 1; }
note() { [[ "$QUIET" -eq 1 ]] && return 0; echo "${CYAN}${ICON_INFO} $*${RESET}"; }
warn() { [[ "$QUIET" -eq 1 ]] && return 0; echo "${YELLOW}${ICON_WARN} $*${RESET}"; }
ok()   { [[ "$QUIET" -eq 1 ]] && return 0; echo "${GREEN}${ICON_OK} $*${RESET}"; }

count_lines() { awk '!/ubs:ignore/ { c++ } END { print c+0 }'; }

# JSON escape (safe for simple strings)
json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  echo -n "$s"
}

# ---------- findings model ----------
declare -a FINDINGS=()
declare -a FINDING_RULE_IDS=()
add_finding() {
  # args: severity category title file line snippet [rule_id]
  local sev="$1" cat="$2" title="$3" file="$4" line="$5" snippet="$6" rule_id="${7:-}"
  FINDINGS+=("${sev}|${cat}|${title}|${file}|${line}|${snippet}")
  FINDING_RULE_IDS+=("$rule_id")
}
emit_findings_json() {
  local out="$1"
  {
    echo '{'
    echo '  "meta": {"tool":"ubs-csharp","version":"'"$VERSION"'","project_dir":"'"$(json_escape "$PROJECT_DIR")"'","timestamp":"'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"},'
    echo '  "summary": {"files":'"${TOTAL_FILES:-0}"',"critical":'"${CRITICAL_FINDINGS:-0}"',"warning":'"${WARNING_FINDINGS:-0}"',"info":'"${INFO_FINDINGS:-0}"'},'
    echo '  "findings": ['
    local first=1
    local item rule_id i
    for ((i=0; i<${#FINDINGS[@]}; i++)); do
      item="${FINDINGS[$i]}"
      rule_id="${FINDING_RULE_IDS[$i]:-}"
      IFS='|' read -r sev cat title file line snippet <<<"$item"
      [[ $first -eq 0 ]] && echo ','
      first=0
      echo -n '    {"severity":"'"$(json_escape "$sev")"'","category":"'"$(json_escape "$cat")"'","title":"'"$(json_escape "$title")"'","file":"'"$(json_escape "$file")"'","line":'"${line:-0}"',"snippet":"'"$(json_escape "$snippet")"'"'
      if [[ -n "$rule_id" ]]; then
        echo -n ',"rule_id":"'"$(json_escape "$rule_id")"'"'
      fi
      echo -n '}'
    done
    echo ''
    echo '  ]'
    echo '}'
  } >"$out"
}

emit_summary_json() {
  local crit="${CRITICAL_FINDINGS:-0}" warnc="${WARNING_FINDINGS:-0}" infoc="${INFO_FINDINGS:-0}"
  echo '{'
  echo '  "project":"'"$(json_escape "$PROJECT_DIR")"'",'
  echo '  "files":'"${TOTAL_FILES:-0}"','
  echo '  "critical":'"$crit"','
  echo '  "warning":'"$warnc"','
  echo '  "info":'"$infoc"','
  echo '  "timestamp":"'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'",'
  echo '  "format":"'"$FORMAT"'",'
  echo '  "tool":"ubs-csharp",'
  echo '  "version":"'"$VERSION"'",'
  echo '  "tooling":{"rg":'"${HAS_RG:-0}"',"ast_grep":'"${HAS_AST_GREP:-0}"',"dotnet":'"${HAS_DOTNET:-0}"',"python3":'"${HAS_PYTHON:-0}"'},'
  echo '  "helpers":{"type_narrowing":"'"$(json_escape "${TYPE_NARROWING_HELPER_STATUS:-not_run}")"'","resource_lifecycle":"'"$(json_escape "${RESOURCE_LIFECYCLE_HELPER_STATUS:-not_run}")"'","async_task_handles":"'"$(json_escape "${ASYNC_TASK_HELPER_STATUS:-not_run}")"'"},'
  echo '  "exit_code":'"${EXIT_CODE:-0}"''
  echo '}'
}

persist_metric_json() {
  local key="$1" payload="$2"
  [[ -n "$key" && -n "$payload" ]] || return 0
  [[ -n "${UBS_METRICS_DIR:-}" ]] || return 0
  mkdir -p "$UBS_METRICS_DIR" 2>/dev/null || true
  {
    printf '{"%s":' "$key"
    printf '%s' "$payload"
    printf '}'
  } >"$UBS_METRICS_DIR/$key.json"
}

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

# ---------- file listing ----------
FILELIST_NUL=""
# Produces a NUL-delimited list of files under project dir that match include-ext and are not in excluded dirs.
build_file_list() {
  local out="$1"
  local IFS=','; read -r -a exts <<<"$INCLUDE_EXT"
  local IFS2=','; read -r -a exdirs <<<"$EXCLUDE_DIRS"
  read -r -a exdirs2 <<<"$EXTRA_EXCLUDE_DIRS"
  exdirs+=("${exdirs2[@]}")
  if [[ -f "$PROJECT_DIR" ]]; then
    : >"$out"
    local ext matched=0
    for ext in "${exts[@]}"; do
      ext="${ext#.}"
      if [[ "${PROJECT_DIR,,}" == *.${ext,,} ]]; then
        printf '%s\0' "$PROJECT_DIR" >"$out"
        matched=1
        break
      fi
    done
    if [[ "$matched" -eq 0 ]]; then
      : >"$out"
    fi
  else
    # Build find prune expression
    local find_cmd=(find "$PROJECT_DIR" -type d)
    local prune=()
    local d
    for d in "${exdirs[@]}"; do
      [[ -z "$d" ]] && continue
      prune+=( -name "$d" -o )
    done
    if [[ ${#prune[@]} -gt 0 ]]; then
      prune=("${prune[@]:0:${#prune[@]}-1}") # drop trailing -o
      find_cmd+=( \( "${prune[@]}" \) -prune -o )
    else
      find_cmd+=( -o )
    fi
    find_cmd+=( -type f \( )
    local e
    for e in "${exts[@]}"; do
      e="${e#.}"
      find_cmd+=( -iname "*.${e}" -o )
    done
    find_cmd=("${find_cmd[@]:0:${#find_cmd[@]}-1}") # drop trailing -o
    find_cmd+=( \) -print0 )

    "${find_cmd[@]}" >"$out"
  fi

  if [[ "$STRICT_GITIGNORE" -eq 1 && -d "$PROJECT_DIR/.git" ]] && command -v git >/dev/null 2>&1; then
    if [[ "$HAS_PYTHON" -eq 1 ]]; then
      # Filter ignored files using git check-ignore (expects paths relative to repo root)
      local tmp="$TMP_DIR/filelist.filtered"
      : >"$tmp"
      python3 - "$PROJECT_DIR" "$out" "$tmp" <<'PY' 2>/dev/null || true
import os, sys, subprocess
proj = sys.argv[1]
nul_list = sys.argv[2]
out = sys.argv[3]
try:
    root = subprocess.check_output(["git","-C",proj,"rev-parse","--show-toplevel"], text=True).strip()
except Exception:
    root = proj
paths=[]
with open(nul_list,'rb') as f:
    data=f.read().split(b'\0')
for b in data:
    if not b: continue
    p=b.decode('utf-8','ignore')
    rel=os.path.relpath(p, root)
    paths.append(rel)
if not paths:
    open(out,'wb').close(); sys.exit(0)
keep=[]
chunk=5000
for i in range(0,len(paths),chunk):
    part=paths[i:i+chunk]
    try:
        proc=subprocess.run(["git","-C",root,"check-ignore","--stdin"], input="\n".join(part), text=True, capture_output=True)
        ignored=set([ln.strip() for ln in proc.stdout.splitlines() if ln.strip()])
    except Exception:
        ignored=set()
    for rel in part:
        if rel in ignored: continue
        keep.append(os.path.join(root, rel))
with open(out,'wb') as f:
    for p in keep:
        f.write(p.encode('utf-8','ignore')+b'\0')
PY
      if [[ -s "$tmp" ]]; then
        mv "$tmp" "$out"
      fi
    fi
  fi

  filter_file_list_with_globs "$out"
}

# ---------- search backend ----------
# Print a few matches with context
print_matches() {
  local label="$1" _pattern_hint="$2" severity="$3" category="$4"
  local max="${5:-$DETAIL_LIMIT}"
  local shown=0
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  ${DIM}${line}${RESET}"
    # record as finding: file:line:content
    local file="${line%%:*}"
    local rest="${line#*:}"
    local ln="${rest%%:*}"
    local content="${rest#*:}"
    add_finding "$severity" "$category" "$label" "$file" "$ln" "$content"
    shown=$((shown+1))
    [[ $shown -ge $max ]] && break
  done
}

# rg wrapper that respects include/ext and excludes
rg_search() {
  local pattern="$1"
  local out="$2"
  local -a args=(--no-messages --line-number --with-filename --color never --hidden)
  # Excludes
  local IFS=','; read -r -a exdirs <<<"$EXCLUDE_DIRS"
  read -r -a exdirs2 <<<"$EXTRA_EXCLUDE_DIRS"
  exdirs+=("${exdirs2[@]}")
  local d
  for d in "${exdirs[@]}"; do
    [[ -z "$d" ]] && continue
    args+=(--glob "!${d}/**")
  done
  if [[ -n "$EXCLUDE_GLOBS" ]]; then
    local IFS3=','; read -r -a globs <<<"$EXCLUDE_GLOBS"
    local g
    for g in "${globs[@]}"; do
      g="${g#./}"
      g="${g#/}"
      g="${g%/}"
      [[ -z "$g" ]] && continue
      args+=(--glob "!${g}" --glob "!${g}/**")
    done
  fi
  # Include extensions
  local IFS=','; read -r -a exts <<<"$INCLUDE_EXT"
  local e
  for e in "${exts[@]}"; do
    e="${e#.}"
    args+=(--glob "**/*.${e}")
  done
  # Gitignore behavior: default is "scan everything" (ignore ignore-files)
  if [[ "$STRICT_GITIGNORE" -eq 0 ]]; then
    args+=(--no-ignore --no-ignore-vcs --no-ignore-parent)
  fi
  [[ -n "$JOBS" ]] && args+=(--threads "$JOBS")
  rg "${args[@]}" -e "$pattern" "$PROJECT_DIR" >"$out" 2>/dev/null || true
}

# Python regex search (fallback when rg missing). Pattern syntax: Python re.
py_search() {
  local pattern="$1"
  local out="$2"
  [[ -n "$FILELIST_NUL" && -f "$FILELIST_NUL" ]] || build_file_list "$FILELIST_NUL"
  python3 - "$FILELIST_NUL" "$pattern" "$out" <<'PY' 2>/dev/null || true
import sys, re
nul_list=sys.argv[1]
pattern=sys.argv[2]
out=sys.argv[3]
try:
    rx=re.compile(pattern)
except re.error:
    # If user passed a rg-style pattern that python rejects, degrade to literal search.
    rx=None
def iter_files():
    data=open(nul_list,'rb').read().split(b'\0')
    for b in data:
        if b: yield b.decode('utf-8','ignore')
with open(out,'w',encoding='utf-8',errors='ignore') as fo:
    for path in iter_files():
        try:
            with open(path,'r',encoding='utf-8',errors='ignore') as f:
                for i,line in enumerate(f,1):
                    if (rx.search(line) if rx else (pattern in line)):
                        fo.write(f"{path}:{i}:{line.rstrip()}\n")
        except Exception:
            pass
PY
}

# Basic grep fallback (last resort, ERE-ish); we sanitize a few common escapes.
grep_search_basic() {
  local pattern="$1"
  local out="$2"
  local p="$pattern"
  # Best-effort: make some patterns less hostile to ERE grep
  p="${p//\\s/[[:space:]]}"
  p="${p//\\b/}"  # drop word boundary (may increase false positives)
  p="${p//\\(/(}"
  p="${p//\\)/)}"
  # Build list if needed
  [[ -n "$FILELIST_NUL" && -f "$FILELIST_NUL" ]] || build_file_list "$FILELIST_NUL"
  : >"$out"
  # Convert NUL list to newline and grep per file
  while IFS= read -r -d '' f; do
    grep -nE "$p" "$f" 2>/dev/null | sed "s|^|$f:|" >>"$out" || true
  done <"$FILELIST_NUL"
}

search() {
  local pattern="$1" out="$2"
  if [[ "$HAS_RG" -eq 1 ]]; then
    rg_search "$pattern" "$out"
  elif [[ "$HAS_PYTHON" -eq 1 ]]; then
    py_search "$pattern" "$out"
  else
    grep_search_basic "$pattern" "$out"
  fi
}

# ---------- ast-grep ----------
AST_RULES_DIR=""
AST_CONFIG_FILE=""
AST_RULE_IDS=(
  cs-async-discarded-task-run
  cs-async-discarded-startnew
  cs-await-in-lock
  cs-parallel-foreach-async-lambda
)
declare -A AST_RULE_SEVERITY=(
  [cs-async-discarded-task-run]="warning"
  [cs-async-discarded-startnew]="warning"
  [cs-await-in-lock]="warning"
  [cs-parallel-foreach-async-lambda]="warning"
)
declare -A AST_RULE_SUMMARY=(
  [cs-async-discarded-task-run]="Task.Run result discarded without observation"
  [cs-async-discarded-startnew]="Task.Factory.StartNew result discarded without observation"
  [cs-await-in-lock]="Await used while holding a lock"
  [cs-parallel-foreach-async-lambda]="Parallel.ForEach async lambda drops asynchronous work"
)
write_ast_rules() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  AST_RULES_DIR="$TMP_DIR/ast-rules"
  mkdir -p "$AST_RULES_DIR"
  local rules_file="$AST_RULES_DIR/csharp-pack.yml"
  cat >"$rules_file"<<'YAML'
rules:
  - id: cs-async-discarded-task-run
    message: "Task.Run result discarded; await or retain the Task so failures are observed."
    severity: warning
    language: cs
    rule:
      any:
        - pattern: |
            Task.Run($$ARGS);
        - pattern: |
            _ = Task.Run($$ARGS);
  - id: cs-async-discarded-startnew
    message: "Task.Factory.StartNew result discarded; await or retain the Task so failures are observed."
    severity: warning
    language: cs
    rule:
      any:
        - pattern: |
            Task.Factory.StartNew($$ARGS);
        - pattern: |
            _ = Task.Factory.StartNew($$ARGS);
  - id: cs-await-in-lock
    message: "Await inside lock can deadlock or break monitor assumptions; move async work outside the lock."
    severity: warning
    language: cs
    rule:
      pattern: |
        lock ($OBJ) { $$PRE; await $EXPR; $$POST; }
  - id: cs-parallel-foreach-async-lambda
    message: "Parallel.ForEach with async lambda does not await the async work; use Parallel.ForEachAsync or gather Tasks."
    severity: warning
    language: cs
    rule:
      any:
        - pattern: |
            Parallel.ForEach($SRC, async ($ITEM) => { $$BODY });
        - pattern: |
            Parallel.ForEach($SRC, async $ITEM => { $$BODY });
        - pattern: |
            Parallel.ForEach($SRC, async ($ITEM) => $EXPR);
        - pattern: |
            Parallel.ForEach($SRC, async $ITEM => $EXPR);
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
    cp -R "$AST_RULES_DIR" "$DUMP_RULES_DIR/" 2>/dev/null || true
    cp "$AST_CONFIG_FILE" "$DUMP_RULES_DIR/" 2>/dev/null || true
  fi
}

ast_scan_json_stream() {
  [[ "$HAS_AST_GREP" -eq 1 ]] || return 0
  [[ -n "$AST_CONFIG_FILE" ]] || return 0
  "${AST_GREP_CMD[@]}" scan -c "$AST_CONFIG_FILE" "$PROJECT_DIR" --json 2>/dev/null || true
}

normalize_ast_severity() {
  local raw="${1:-warning}"
  case "${raw,,}" in
    critical|error) echo "critical" ;;
    info|note|hint) echo "info" ;;
    *) echo "warning" ;;
  esac
}

ast_scan_json_to_tsv() {
  local json_path="$1" out="$2"
  [[ "$HAS_PYTHON" -eq 1 ]] || return 1
  python3 - "$PROJECT_DIR" "$json_path" >"$out" <<'PY' 2>/dev/null
import json
import sys
from pathlib import Path

project_dir = Path(sys.argv[1]).resolve()
json_path = Path(sys.argv[2])
base = project_dir if project_dir.is_dir() else project_dir.parent

def iter_match_objs(blob):
    if isinstance(blob, list):
        for item in blob:
            yield from iter_match_objs(item)
    elif isinstance(blob, dict):
        if (
            "range" in blob
            and (blob.get("file") or blob.get("path"))
            and (blob.get("id") or blob.get("rule_id") or blob.get("ruleId"))
        ):
            yield blob
        for value in blob.values():
            yield from iter_match_objs(value)

def load_json_objects(raw):
    raw = raw.strip()
    if not raw:
        return []
    try:
        return [json.loads(raw)]
    except Exception:
        objs = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return objs

def normalize_path(raw_path):
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = (base / path).resolve()
    try:
        display = str(path.relative_to(base))
    except ValueError:
        display = str(path)
    return path, display

def normalize_line(start):
    if not isinstance(start, dict):
        return 1, 1
    if "row" in start:
        line = int(start.get("row", 0)) + 1
    else:
        line = int(start.get("line", 0)) + 1
    if "column" in start:
        col = int(start.get("column", 0)) + 1
    elif "col" in start:
        col = int(start.get("col", 0)) + 1
    else:
        col = 1
    return max(line, 1), max(col, 1)

def is_ignored(path, line_no, cache):
    try:
        lines = cache.setdefault(path, path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return False
    if 1 <= line_no <= len(lines):
        return "ubs:ignore" in lines[line_no - 1]
    return False

raw = json_path.read_text(encoding="utf-8", errors="ignore")
seen = set()
line_cache = {}

for obj in load_json_objects(raw):
    for match in iter_match_objs(obj):
        rule_id = match.get("rule_id") or match.get("id") or match.get("ruleId")
        raw_path = match.get("file") or match.get("path")
        if not rule_id or not raw_path:
            continue
        path, display = normalize_path(raw_path)
        rng = match.get("range") or {}
        start = rng.get("start") or {}
        line_no, col_no = normalize_line(start)
        if is_ignored(path, line_no, line_cache):
            continue
        message = match.get("message") or match.get("note") or ""
        severity = match.get("severity") or match.get("level") or ""
        key = (rule_id, display, line_no, col_no)
        if key in seen:
            continue
        seen.add(key)
        print(f"{rule_id}\t{display}\t{line_no}\t{col_no}\t{severity}\t{message}")
PY
}

emit_sarif() {
  local first=1 item level message rule_id i
  {
    echo '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ubs-csharp","version":"'"$VERSION"'"}},"results":['
    for ((i=0; i<${#FINDINGS[@]}; i++)); do
      item="${FINDINGS[$i]}"
      rule_id="${FINDING_RULE_IDS[$i]:-}"
      local sev cat title file line snippet
      IFS='|' read -r sev cat title file line snippet <<<"$item"
      case "$sev" in
        critical) level="error" ;;
        warning) level="warning" ;;
        *) level="note" ;;
      esac
      message="$title"
      [[ -n "$snippet" ]] && message="$message - $snippet"
      [[ $first -eq 0 ]] && echo ','
      first=0
      printf '  {"ruleId":"%s","level":"%s","message":{"text":"%s"}' \
        "$(json_escape "${rule_id:-csharp.category.$cat}")" "$(json_escape "$level")" "$(json_escape "$message")"
      if [[ -n "$file" ]]; then
        printf ',"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"}' "$(json_escape "$file")"
        if [[ "${line:-0}" -gt 0 ]]; then
          printf ',"region":{"startLine":%s}' "$line"
        fi
        printf '}}]}'
      fi
      printf '}'
    done
    echo
    echo ']}]}'
  }
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

category_enabled() {
  local cat="$1"
  if [[ -n "$ONLY_CATEGORIES" ]]; then
    [[ ",$ONLY_CATEGORIES," == *",$cat,"* ]] || return 1
  fi
  if [[ -n "$SKIP_CATEGORIES" ]]; then
    [[ ",$SKIP_CATEGORIES," == *",$cat,"* ]] && return 1
  fi
  return 0
}

# ---------- counters ----------
TOTAL_FILES=0
CRITICAL_FINDINGS=0
WARNING_FINDINGS=0
INFO_FINDINGS=0
TYPE_NARROWING_HELPER_STATUS="not_run"
TYPE_NARROWING_FINDINGS=0
RESOURCE_LIFECYCLE_HELPER_STATUS="not_run"
RESOURCE_LIFECYCLE_FINDINGS=0
ASYNC_TASK_HELPER_STATUS="not_run"
ASYNC_TASK_FINDINGS=0
AST_GREP_STATUS="not_run"
AST_GREP_SAMPLE_MATCHES=0
AST_GREP_FINDINGS=0

bump_counter() {
  local sev="$1" n="$2"
  case "$sev" in
    critical) CRITICAL_FINDINGS=$((CRITICAL_FINDINGS+n));;
    warning)  WARNING_FINDINGS=$((WARNING_FINDINGS+n));;
    info)     INFO_FINDINGS=$((INFO_FINDINGS+n));;
  esac
}

# ---------- dotnet helpers ----------
DOTNET_LOG=""
detect_dotnet_target() {
  [[ "$HAS_DOTNET" -eq 1 ]] || return 0
  [[ -n "$DOTNET_TARGET" ]] && return 0
  # pick a solution if one exists
  local sln
  sln="$(find "$PROJECT_DIR" -maxdepth 2 -name '*.sln' -print -quit 2>/dev/null || true)"
  if [[ -n "$sln" ]]; then
    DOTNET_TARGET="$sln"
    return 0
  fi
  local csproj
  csproj="$(find "$PROJECT_DIR" -maxdepth 2 -name '*.csproj' -print -quit 2>/dev/null || true)"
  if [[ -n "$csproj" ]]; then
    DOTNET_TARGET="$csproj"
  fi
}

require_dotnet_target() {
  detect_dotnet_target
  if [[ -z "$DOTNET_TARGET" ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}No .sln or .csproj found; skipping dotnet project checks.${RESET}"
    return 1
  fi
  return 0
}

run_dotnet_step() {
  local label="$1"; shift
  [[ "$HAS_DOTNET" -eq 1 ]] || { warn "$label: dotnet not found (skipping)"; return 0; }
  local logfile
  logfile="$TMP_DIR/dotnet.$(echo "$label" | tr ' ' '_' | tr -cd '[:alnum:]_').log"
  note "$label ..."
  ( set +e; dotnet "$@" >"$logfile" 2>&1; echo $? >"$logfile.exit" )
  local rc
  rc="$(cat "$logfile.exit" 2>/dev/null || echo 1)"
  if [[ "$rc" -eq 0 ]]; then
    ok "$label: OK"
  else
    warn "$label: exit $rc (see log in $logfile)"
  fi
  DOTNET_LOG="$logfile"
  return "$rc"
}

run_csharp_type_narrowing_checks() {
  local cat="$1"
  local helper="$SCRIPT_DIR/helpers/type_narrowing_csharp.py"
  local report="$TMP_DIR/csharp.type_narrowing.tsv"
  local helper_err="$TMP_DIR/csharp.type_narrowing.err"

  if [[ "${UBS_SKIP_TYPE_NARROWING:-0}" == "1" ]]; then
    TYPE_NARROWING_HELPER_STATUS="skipped"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# type narrowing helper skipped (UBS_SKIP_TYPE_NARROWING=1).${RESET}"
    return 0
  fi
  if [[ ! -f "$helper" ]]; then
    TYPE_NARROWING_HELPER_STATUS="missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# type narrowing helper missing: $helper${RESET}"
    return 0
  fi
  if [[ "$HAS_PYTHON" -eq 0 ]]; then
    TYPE_NARROWING_HELPER_STATUS="python-missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}python3 not found; skipping C# type narrowing helper.${RESET}"
    return 0
  fi

  if ! python3 "$helper" "$PROJECT_DIR" >"$report" 2>"$helper_err"; then
    TYPE_NARROWING_HELPER_STATUS="failed"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# type narrowing helper failed: $(head -n 1 "$helper_err" 2>/dev/null || echo "see $helper_err")${RESET}"
    return 0
  fi

  local hits=0
  hits=$(awk 'END { print NR+0 }' "$report")
  if [[ "$hits" -eq 0 ]]; then
    TYPE_NARROWING_HELPER_STATUS="clean"
    [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No obvious null/type narrowing fallthrough bugs detected.${RESET}"
    return 0
  fi

  TYPE_NARROWING_HELPER_STATUS="used"
  TYPE_NARROWING_FINDINGS="$hits"
  [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Null/type guard fallthrough issues ($hits) - guards do not safely narrow the fallthrough path${RESET}"

  local shown=0 location severity message file rest line
  while IFS=$'\t' read -r location severity message; do
    [[ -z "$location" ]] && continue
    file="${location%%:*}"
    rest="${location#*:}"
    line="${rest%%:*}"
    [[ -z "$severity" ]] && severity="warning"
    bump_counter "$severity" 1
    add_finding "$severity" "$cat" "$message" "$file" "${line:-0}" "" "csharp.type.guard-fallthrough"
    if [[ "$FORMAT" == "text" && "$shown" -lt "$DETAIL_LIMIT" ]]; then
      echo "  ${DIM}${location}${RESET} - $message"
      shown=$((shown+1))
    fi
  done <"$report"
}

run_csharp_resource_lifecycle_helper() {
  local cat="$1"
  local helper="$SCRIPT_DIR/helpers/resource_lifecycle_csharp.py"
  local report="$TMP_DIR/csharp.resource_lifecycle.tsv"
  local helper_err="$TMP_DIR/csharp.resource_lifecycle.err"

  if [[ ! -f "$helper" ]]; then
    RESOURCE_LIFECYCLE_HELPER_STATUS="missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# resource lifecycle helper missing: $helper${RESET}"
    return 1
  fi
  if [[ "$HAS_PYTHON" -eq 0 ]]; then
    RESOURCE_LIFECYCLE_HELPER_STATUS="python-missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}python3 not found; lifecycle correlation reduced (helper skipped).${RESET}"
    return 1
  fi
  if ! python3 "$helper" "$PROJECT_DIR" >"$report" 2>"$helper_err"; then
    RESOURCE_LIFECYCLE_HELPER_STATUS="failed"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# resource lifecycle helper failed: $(head -n 1 "$helper_err" 2>/dev/null || echo "see $helper_err")${RESET}"
    return 1
  fi

  local hits=0
  hits=$(awk 'END { print NR+0 }' "$report")
  if [[ "$hits" -eq 0 ]]; then
    RESOURCE_LIFECYCLE_HELPER_STATUS="clean"
    [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No obvious disposable/resource leaks detected by helper.${RESET}"
    return 0
  fi

  RESOURCE_LIFECYCLE_HELPER_STATUS="used"
  RESOURCE_LIFECYCLE_FINDINGS="$hits"
  [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Potential resource lifecycle leaks (helper): $hits${RESET}"

  local shown=0 location severity message file rest line
  while IFS=$'\t' read -r location severity message; do
    [[ -z "$location" ]] && continue
    file="${location%%:*}"
    rest="${location#*:}"
    line="${rest%%:*}"
    [[ -z "$severity" ]] && severity="warning"
    bump_counter "$severity" 1
    add_finding "$severity" "$cat" "$message" "$file" "${line:-0}" "" "csharp.resource.helper-leak"
    if [[ "$FORMAT" == "text" && "$shown" -lt "$DETAIL_LIMIT" ]]; then
      echo "  ${DIM}${location}${RESET} - $message"
      shown=$((shown+1))
    fi
  done <"$report"
  return 0
}

run_csharp_async_task_handle_helper() {
  local cat="$1"
  local helper="$SCRIPT_DIR/helpers/async_task_handles_csharp.py"
  local report="$TMP_DIR/csharp.async_task_handles.tsv"
  local helper_err="$TMP_DIR/csharp.async_task_handles.err"

  if [[ ! -f "$helper" ]]; then
    ASYNC_TASK_HELPER_STATUS="missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# async task-handle helper missing: $helper${RESET}"
    return 0
  fi
  if [[ "$HAS_PYTHON" -eq 0 ]]; then
    ASYNC_TASK_HELPER_STATUS="python-missing"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}python3 not found; skipping C# async task-handle helper.${RESET}"
    return 0
  fi
  if ! python3 "$helper" "$PROJECT_DIR" >"$report" 2>"$helper_err"; then
    ASYNC_TASK_HELPER_STATUS="failed"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}C# async task-handle helper failed: $(head -n 1 "$helper_err" 2>/dev/null || echo "see $helper_err")${RESET}"
    return 0
  fi

  local hits=0
  hits=$(awk 'END { print NR+0 }' "$report")
  if [[ "$hits" -eq 0 ]]; then
    ASYNC_TASK_HELPER_STATUS="clean"
    [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No unobserved Task.Run/StartNew handles detected.${RESET}"
    return 0
  fi

  ASYNC_TASK_HELPER_STATUS="used"
  ASYNC_TASK_FINDINGS="$hits"
  [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Task handles created but never observed ($hits)${RESET}"

  local shown=0 location severity kind message file rest line
  while IFS=$'\t' read -r location severity kind message; do
    [[ -z "$location" ]] && continue
    file="${location%%:*}"
    rest="${location#*:}"
    line="${rest%%:*}"
    [[ -z "$severity" ]] && severity="warning"
    [[ -z "$kind" ]] && kind="unobserved_task_handle"
    [[ -z "$message" ]] && message="Task handle created but never awaited/observed"
    bump_counter "$severity" 1
    add_finding "$severity" "$cat" "$message" "$file" "${line:-0}" "" "csharp.async.${kind}"
    if [[ "$FORMAT" == "text" && "$shown" -lt "$DETAIL_LIMIT" ]]; then
      echo "  ${DIM}${location}${RESET} - $message"
      shown=$((shown+1))
    fi
  done <"$report"
  return 0
}

emit_module_metrics() {
  persist_metric_json "tools" "$(printf '{"rg":%s,"ast_grep":%s,"dotnet":%s,"python3":%s,"strict_gitignore":%s,"total_files":%s}' \
    "${HAS_RG:-0}" "${HAS_AST_GREP:-0}" "${HAS_DOTNET:-0}" "${HAS_PYTHON:-0}" "${STRICT_GITIGNORE:-0}" "${TOTAL_FILES:-0}")"
  persist_metric_json "helpers" "$(printf '{"type_narrowing":{"status":"%s","findings":%s},"resource_lifecycle":{"status":"%s","findings":%s},"async_task_handles":{"status":"%s","findings":%s},"ast_grep":{"status":"%s","sample_matches":%s,"structured_findings":%s}}' \
    "$(json_escape "${TYPE_NARROWING_HELPER_STATUS:-not_run}")" "${TYPE_NARROWING_FINDINGS:-0}" \
    "$(json_escape "${RESOURCE_LIFECYCLE_HELPER_STATUS:-not_run}")" "${RESOURCE_LIFECYCLE_FINDINGS:-0}" \
    "$(json_escape "${ASYNC_TASK_HELPER_STATUS:-not_run}")" "${ASYNC_TASK_FINDINGS:-0}" \
    "$(json_escape "${AST_GREP_STATUS:-not_run}")" "${AST_GREP_SAMPLE_MATCHES:-0}" "${AST_GREP_FINDINGS:-0}")"
  persist_metric_json "dotnet" "$(printf '{"available":%s,"target_found":%s,"target":"%s","build_enabled":%s,"test_enabled":%s,"format_enabled":%s,"deps_enabled":%s}' \
    "${HAS_DOTNET:-0}" "$([[ -n "${DOTNET_TARGET:-}" ]] && echo 1 || echo 0)" "$(json_escape "${DOTNET_TARGET:-}")" \
    "$([[ "${NO_DOTNET_BUILD:-0}" -eq 0 ]] && echo 1 || echo 0)" \
    "$([[ "${NO_DOTNET_TEST:-0}" -eq 0 ]] && echo 1 || echo 0)" \
    "$([[ "${NO_DOTNET_FORMAT:-0}" -eq 0 ]] && echo 1 || echo 0)" \
    "$([[ "${NO_DOTNET_DEPS:-0}" -eq 0 ]] && echo 1 || echo 0)")"
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

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0;;
      --format=*) FORMAT="${1#*=}"; shift;;
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

count_project_files() {
  FILELIST_NUL="$TMP_DIR/filelist.nul"
  build_file_list "$FILELIST_NUL"
  if [[ "$HAS_PYTHON" -eq 1 ]]; then
    TOTAL_FILES=$(python3 - "$FILELIST_NUL" <<'PY' 2>/dev/null || echo 0
import sys
data=open(sys.argv[1],'rb').read().split(b'\0')
print(sum(1 for b in data if b))
PY
)
  else
    # Fallback: count entries in NUL-delimited list without python.
    TOTAL_FILES=$(LC_ALL=C tr '\000' '\n' <"$FILELIST_NUL" | awk 'NF{c++} END{print c+0}')
  fi
}

# ---------- category implementations ----------
category_1_exceptions_nullability() {
  local cat=1
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  local tmp="$TMP_DIR/cat1.txt"
  local hits=0

  # null-forgiving operator "!" after identifier (approx)
search '[A-Za-z_][A-Za-z0-9_]*\s*![\.\[]' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} null-forgiving operator usage (!.) - review nullability assumptions ($hits)${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Null-forgiving operator (!)" "!." "warning" "$cat" || true
  fi

  # #nullable disable
search '^\s*#nullable\s+disable\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} '#nullable disable' found ($hits) - may hide nullability bugs${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "#nullable disable" "#nullable disable" "warning" "$cat" || true
  fi

  run_csharp_type_narrowing_checks "$cat"

  # throwing System.Exception directly (smell)
search '\bthrow\s+new\s+Exception\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} throw new Exception(...) ($hits) - consider more specific exception types${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "throw new Exception" "throw new Exception" "info" "$cat" || true
  fi
}

category_2_resources_idisposable() {
  local cat=2
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  local tmp="$TMP_DIR/cat2.txt"
  local hits=0

  # new HttpClient without using/factory
search '\bnew\s+HttpClient\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} new HttpClient(...) ($hits) - prefer IHttpClientFactory or shared instance${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "new HttpClient()" "new HttpClient" "warning" "$cat" || true
  fi

  # FileStream/StreamReader/StreamWriter without using (approx: line contains new StreamReader but not using)
search '\bnew\s+(FileStream|StreamReader|StreamWriter)\s*\(' "$tmp"
  hits=$( (grep -v ':[[:space:]]*using\b' "$tmp" 2>/dev/null || true) | count_lines )
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Stream created without 'using' on same line (approx) ($hits)${RESET}"
    [[ "$FORMAT" == "text" ]] && ( head -n "$DETAIL_LIMIT" "$tmp" | grep -v ':[[:space:]]*using\b' || true ) | print_matches "Stream without using" "new Stream" "warning" "$cat" || true
  fi
}

category_3_concurrency_async() {
  local cat=3
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  local tmp="$TMP_DIR/cat3.txt"
  local hits=0

  # async void
search '\basync\s+void\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} async void methods ($hits) - exceptions can crash process; prefer Task${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "async void" "async void" "warning" "$cat" || true
  fi

  # .Result / .Wait() / GetAwaiter().GetResult()
  search '\.Result\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} Blocking on Task via .Result ($hits) - deadlock risk${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches ".Result" ".Result" "critical" "$cat" || true
  fi

search '\.Wait\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} Blocking on Task via Wait() ($hits) - deadlock risk${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches ".Wait()" ".Wait(" "critical" "$cat" || true
  fi

search 'GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} GetAwaiter().GetResult() ($hits) - deadlock risk${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "GetAwaiter().GetResult" "GetAwaiter().GetResult" "critical" "$cat" || true
  fi

  # Thread.Sleep in async contexts (heuristic)
search '\bThread\.Sleep\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Thread.Sleep(...) ($hits) - blocks thread; in async code prefer Task.Delay${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Thread.Sleep" "Thread.Sleep" "warning" "$cat" || true
  fi

  run_csharp_async_task_handle_helper "$cat"
}

category_4_numeric_fp() {
  local cat=4
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat4.txt"
  local hits=0

  # float/double/decimal equality (heuristic)
  search '\b(float|double|decimal)\b.*(==|!=)' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Floating/decimal equality comparisons ($hits) - review tolerance/precision${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "FP equality" "==" "info" "$cat" || true
  fi

  # unchecked casts to int
search '\(\s*int\s*\)\s*[A-Za-z_][A-Za-z0-9_]*' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Casts to int ($hits) - possible truncation/overflow${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "(int) cast" "(int)" "info" "$cat" || true
  fi
}

category_5_collections_linq() {
  local cat=5
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat5.txt"
  local hits=0

  # First() without Any() or check - heuristic
search '\.First\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} .First(...) usages ($hits) - may throw on empty sequences; consider FirstOrDefault + null check${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches ".First(" ".First(" "warning" "$cat" || true
  fi

  # Multiple enumeration smell: .Count() > 0
search '\.Count\s*\(\s*\)\s*>\s*0' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} .Count() > 0 ($hits) - prefer .Any() for IEnumerable to avoid full enumeration${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches ".Count() > 0" "Count() > 0" "info" "$cat" || true
  fi
}

category_6_strings_alloc() {
  local cat=6
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat6.txt"
  local hits=0

  # string concatenation in loops (heuristic: "+=" with string literal)
search '\+\=\s*"[^"]*"' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} String '+=' concatenation ($hits) - in loops consider StringBuilder${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "String +=" "+=" "info" "$cat" || true
  fi
}

category_7_io_process() {
  local cat=7
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat7.txt"
  local hits=0

  # Process.Start
search '\bProcess\.Start\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Process.Start(...) ($hits) - ensure inputs are validated/escaped${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Process.Start" "Process.Start" "warning" "$cat" || true
  fi

  # Path.Combine with suspicious user input names (heuristic)
search '\bPath\.Combine\s*\([^)]*(request|query|input|user|param|args)\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Path.Combine with user-ish input ($hits) - review for path traversal${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Path.Combine(user input)" "Path.Combine" "info" "$cat" || true
  fi
}

category_8_security() {
  local cat=8
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat8.txt"
  local hits=0

  # weak crypto
search '\b(MD5|SHA1)\.Create\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} Weak crypto (MD5/SHA1) ($hits)${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Weak crypto" "MD5/SHA1" "critical" "$cat" || true
  fi

  # insecure random
search '\bnew\s+Random\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} new Random() ($hits) - not crypto-secure (if used for secrets)${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "new Random" "new Random" "warning" "$cat" || true
  fi

  # TLS certificate validation disabled
search 'ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} TLS validation disabled via ServerCertificateCustomValidationCallback => true ($hits)${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "TLS validation disabled" "ServerCertificateCustomValidationCallback" "critical" "$cat" || true
  fi

  # SQL injection-ish string concatenation (very heuristic)
search '\b(SELECT|UPDATE|DELETE|INSERT)\b.*\+\s*' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} SQL string concatenation patterns ($hits) - prefer parameterized queries${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "SQL concat" "SELECT + ..." "warning" "$cat" || true
  fi

  # hardcoded secrets (heuristic)
search '\b(api[_-]?key|secret|password|token)\b\s*=\s*"[^"]{8,}"' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter critical "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} Possible hardcoded secrets ($hits) - rotate + move to secret store${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Hardcoded secret" "secret" "critical" "$cat" || true
  fi
}

category_9_quality_markers() {
  local cat=9
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat9.txt"
  local hits=0
  search '\b(TODO|FIXME|HACK|XXX)\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} TODO/FIXME/HACK markers ($hits)${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Markers" "TODO" "info" "$cat" || true
  fi
}

category_10_api_misuse() {
  local cat=10
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat10.txt"
  local hits=0

  # DateTime.Now in server code (heuristic)
  search '\bDateTime\.Now\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} DateTime.Now ($hits) - consider DateTime.UtcNow or TimeProvider for testability${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "DateTime.Now" "DateTime.Now" "info" "$cat" || true
  fi

  # GC.Collect
search '\bGC\.Collect\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} GC.Collect() ($hits) - usually indicates perf issues or misconception${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "GC.Collect" "GC.Collect" "warning" "$cat" || true
  fi
}

category_11_tests_debug() {
  local cat=11
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat11.txt"
  local hits=0

search '\bDebugger\.Break\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Debugger.Break() ($hits) - remove before shipping${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Debugger.Break" "Debugger.Break" "warning" "$cat" || true
  fi

search '^\s*#if\s+DEBUG\b' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} #if DEBUG blocks ($hits) - ensure no prod-only behavior hiding${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "#if DEBUG" "#if DEBUG" "info" "$cat" || true
  fi

search '\bConsole\.Write(Line)?\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Console.Write/WriteLine ($hits) - check for noisy logs/leaked secrets${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Console.WriteLine" "Console.Write" "info" "$cat" || true
  fi
}

category_12_format_analyzers() {
  local cat=12
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  if [[ "$NO_DOTNET" -eq 1 || "$NO_DOTNET_FORMAT" -eq 1 ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet format skipped (--no-dotnet/--no-format).${RESET}"
    return 0
  fi
  if [[ "$HAS_DOTNET" -eq 0 ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet not found.${RESET}"
    return 0
  fi

  require_dotnet_target || return 0

  # dotnet format verify (best-effort, may not be available)
  local rc=0
  if dotnet format --help >/dev/null 2>&1; then
    if [[ -n "$DOTNET_TARGET" ]]; then
      run_dotnet_step "dotnet format (verify)" format "$DOTNET_TARGET" --verify-no-changes || rc=$?
    else
      run_dotnet_step "dotnet format (verify)" format --verify-no-changes || rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
      bump_counter warning 1
      add_finding "warning" "$cat" "dotnet format reports formatting/analyzer issues" "$DOTNET_LOG" 0 ""
      [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} dotnet format indicates issues. See: $DOTNET_LOG${RESET}"
    else
      [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} dotnet format: no changes needed${RESET}"
    fi
  else
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet format not available in this SDK (skipping).${RESET}"
  fi
}

category_13_build_test() {
  local cat=13
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  if [[ "$NO_DOTNET" -eq 1 || "$HAS_DOTNET" -eq 0 ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet build/test skipped (--no-dotnet or dotnet missing).${RESET}"
    return 0
  fi

  require_dotnet_target || return 0

  if [[ "$NO_DOTNET_BUILD" -eq 0 ]]; then
    local rc=0
    if [[ -n "$DOTNET_TARGET" ]]; then
      if run_dotnet_step "dotnet build" build "$DOTNET_TARGET" -v minimal; then
        rc=0
      else
        rc=$?
      fi
    else
      if run_dotnet_step "dotnet build" build -v minimal; then
        rc=0
      else
        rc=$?
      fi
    fi
    if [[ "$rc" -ne 0 ]]; then
      bump_counter critical 1
      add_finding "critical" "$cat" "dotnet build failed" "$DOTNET_LOG" 0 ""
      [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} dotnet build failed. See: $DOTNET_LOG${RESET}"
    fi
  else
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet build skipped (--no-build).${RESET}"
  fi

  if [[ "$NO_DOTNET_TEST" -eq 0 ]]; then
    local rc2=0
    if [[ -n "$DOTNET_TARGET" ]]; then
      if run_dotnet_step "dotnet test" test "$DOTNET_TARGET" -v minimal --nologo; then
        rc2=0
      else
        rc2=$?
      fi
    else
      if run_dotnet_step "dotnet test" test -v minimal --nologo; then
        rc2=0
      else
        rc2=$?
      fi
    fi
    if [[ "$rc2" -ne 0 ]]; then
      bump_counter warning 1
      add_finding "warning" "$cat" "dotnet test failed" "$DOTNET_LOG" 0 ""
      [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} dotnet test failed. See: $DOTNET_LOG${RESET}"
    fi
  else
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet test skipped (--no-test).${RESET}"
  fi
}

category_14_deps_nuget() {
  local cat=14
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  if [[ "$NO_DOTNET" -eq 1 || "$NO_DOTNET_DEPS" -eq 1 || "$HAS_DOTNET" -eq 0 ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet list package skipped (--no-dotnet/--no-deps or dotnet missing).${RESET}"
    return 0
  fi

  require_dotnet_target || return 0

  local vuln_log="$TMP_DIR/dotnet.list.vuln.log"
  local outd_log="$TMP_DIR/dotnet.list.outdated.log"

  # Vulnerabilities (best effort)
  if dotnet list package --help 2>/dev/null | grep -q -- '--vulnerable'; then
    note "dotnet list package --vulnerable ..."
    if [[ -n "$DOTNET_TARGET" ]]; then
      ( set +e; dotnet list "$DOTNET_TARGET" package --vulnerable >"$vuln_log" 2>&1; echo $? >"$vuln_log.exit" )
    else
      ( set +e; dotnet list package --vulnerable >"$vuln_log" 2>&1; echo $? >"$vuln_log.exit" )
    fi
    local rc; rc="$(cat "$vuln_log.exit" 2>/dev/null || echo 1)"
    if [[ "$rc" -ne 0 ]]; then
      bump_counter warning 1
      add_finding "warning" "$cat" "dotnet list package --vulnerable failed" "$vuln_log" 0 ""
      [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} dotnet list package --vulnerable failed (exit $rc). See: $vuln_log${RESET}"
    else
      # Heuristic: count lines mentioning "Severity" or advisory URLs
      local vuln_hits
      vuln_hits=$(grep -E 'Severity|https?://|CVE-' "$vuln_log" | count_lines)
      if [[ "$vuln_hits" -gt 0 ]]; then
        bump_counter critical 1
        add_finding "critical" "$cat" "NuGet vulnerabilities reported (inspect dotnet list package --vulnerable output)" "$vuln_log" 0 ""
        [[ "$FORMAT" == "text" ]] && echo "${RED}${ICON_CRIT} NuGet vulnerabilities may be present. Review: $vuln_log${RESET}"
      else
        [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No obvious vulnerable packages reported.${RESET}"
      fi
    fi
  else
    [[ "$FORMAT" == "text" ]] && echo "${DIM}dotnet list package --vulnerable not supported by this SDK (skipping).${RESET}"
  fi

  # Outdated
  note "dotnet list package --outdated ..."
  if [[ -n "$DOTNET_TARGET" ]]; then
    ( set +e; dotnet list "$DOTNET_TARGET" package --outdated >"$outd_log" 2>&1; echo $? >"$outd_log.exit" )
  else
    ( set +e; dotnet list package --outdated >"$outd_log" 2>&1; echo $? >"$outd_log.exit" )
  fi
  local rc2; rc2="$(cat "$outd_log.exit" 2>/dev/null || echo 1)"
  if [[ "$rc2" -ne 0 ]]; then
    bump_counter info 1
    add_finding "info" "$cat" "dotnet list package --outdated failed" "$outd_log" 0 ""
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} dotnet list package --outdated failed (exit $rc2). See: $outd_log${RESET}"
  else
    local out_hits
    out_hits=$(grep -E '\bLatest\b|\bWanted\b' "$outd_log" | count_lines)
    if [[ "$out_hits" -gt 0 ]]; then
      bump_counter info 1
      add_finding "info" "$cat" "Some packages may be outdated (inspect dotnet list package --outdated output)" "$outd_log" 0 ""
      [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Some packages may be outdated. Review: $outd_log${RESET}"
    else
      [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No obvious outdated packages reported.${RESET}"
    fi
  fi
}

category_15_exception_handling() {
  local cat=15
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat15.txt"
  local hits=0

  # throw ex;
search '\bthrow\s+[A-Za-z_][A-Za-z0-9_]*\s*;' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} 'throw ex;' pattern ($hits) - resets stack trace, use 'throw;'${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "throw ex" "throw ex;" "warning" "$cat" || true
  fi

  # empty catch
search 'catch\s*\([^)]*\)\s*\{\s*\}' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Empty catch blocks ($hits) - exceptions swallowed${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "empty catch" "catch(...) { }" "warning" "$cat" || true
  fi

  # catch (Exception) blocks
search 'catch\s*\(\s*Exception\b[^)]*\)\s*\{' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} catch(Exception ...) blocks ($hits) - ensure you handle/log appropriately${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "catch(Exception)" "catch(Exception" "info" "$cat" || true
  fi
}

category_16_aspnet_web() {
  local cat=16
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat16.txt"
  local hits=0

  # CORS AllowAnyOrigin
search 'AllowAnyOrigin\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} AllowAnyOrigin() ($hits) - verify this is intended; can expose APIs to browsers${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "AllowAnyOrigin" "AllowAnyOrigin" "warning" "$cat" || true
  fi

  # UseDeveloperExceptionPage
search 'UseDeveloperExceptionPage\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ $hits -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} UseDeveloperExceptionPage() ($hits) - ensure only enabled in Development${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "UseDeveloperExceptionPage" "UseDeveloperExceptionPage" "warning" "$cat" || true
  fi
}

category_17_ast_grep_pack() {
  local cat=17
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  if [[ "$HAS_AST_GREP" -eq 0 ]]; then
    AST_GREP_STATUS="unavailable"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}ast-grep not available (install ast-grep, or ensure 'sg' is ast-grep).${RESET}"
    return 0
  fi

  write_ast_rules
  [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} ast-grep configured (language: cs). Running structured rule pack.${RESET}"

  local ast_json="$TMP_DIR/cat17.ast.json"
  local ast_err="$TMP_DIR/cat17.ast.err"
  local ast_tsv="$TMP_DIR/cat17.ast.tsv"
  local rc=0
  if "${AST_GREP_CMD[@]}" scan -c "$AST_CONFIG_FILE" "$PROJECT_DIR" --json >"$ast_json" 2>"$ast_err"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "$rc" -ne 0 && "$rc" -ne 1 ]]; then
    AST_GREP_STATUS="failed"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}ast-grep scan failed: $(head -n 1 "$ast_err" 2>/dev/null || echo "see $ast_err")${RESET}"
    return 0
  fi
  if ! ast_scan_json_to_tsv "$ast_json" "$ast_tsv"; then
    AST_GREP_STATUS="$([[ "$HAS_PYTHON" -eq 1 ]] && echo "failed" || echo "python-missing")"
    [[ "$FORMAT" == "text" ]] && echo "${DIM}python3 unavailable or parser failed; skipping structured ast-grep ingestion.${RESET}"
    return 0
  fi

  local s=0
  s=$(awk 'END { print NR+0 }' "$ast_tsv")
  AST_GREP_SAMPLE_MATCHES="$s"
  AST_GREP_FINDINGS="$s"
  if [[ "$s" -eq 0 ]]; then
    AST_GREP_STATUS="clean"
    [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} ast-grep found no structural-only C# findings.${RESET}"
    return 0
  fi

  AST_GREP_STATUS="used"
  declare -A rule_counts=()
  declare -A rule_samples=()
  declare -A rule_sample_counts=()
  local rule_id file line col raw_sev raw_message severity title
  while IFS=$'\t' read -r rule_id file line col raw_sev raw_message; do
    [[ -z "$rule_id" || -z "$file" ]] && continue
    severity="$(normalize_ast_severity "${AST_RULE_SEVERITY[$rule_id]:-${raw_sev:-warning}}")"
    title="${AST_RULE_SUMMARY[$rule_id]:-${raw_message:-$rule_id}}"
    bump_counter "$severity" 1
    add_finding "$severity" "$cat" "$title" "$file" "${line:-0}" "" "$rule_id"
    rule_counts["$rule_id"]=$(( ${rule_counts["$rule_id"]:-0} + 1 ))
    if [[ ${rule_sample_counts[$rule_id]:-0} -lt 3 ]]; then
      if [[ -n "${rule_samples[$rule_id]:-}" ]]; then
        rule_samples["$rule_id"]+=", "
      fi
      rule_samples["$rule_id"]+="$file:${line:-0}"
      rule_sample_counts["$rule_id"]=$(( ${rule_sample_counts[$rule_id]:-0} + 1 ))
    fi
  done <"$ast_tsv"

  if [[ "$FORMAT" == "text" ]]; then
    echo "${CYAN}${ICON_INFO} ast-grep emitted structured C# findings ($s).${RESET}"
    while IFS= read -r rule_id; do
      [[ -z "$rule_id" ]] && continue
      severity="$(normalize_ast_severity "${AST_RULE_SEVERITY[$rule_id]:-warning}")"
      title="${AST_RULE_SUMMARY[$rule_id]:-$rule_id}"
      case "$severity" in
        critical) echo "${RED}${ICON_CRIT} ${title} (${rule_counts[$rule_id]}) [${rule_id}]${RESET}" ;;
        warning) echo "${YELLOW}${ICON_WARN} ${title} (${rule_counts[$rule_id]}) [${rule_id}]${RESET}" ;;
        *) echo "${CYAN}${ICON_INFO} ${title} (${rule_counts[$rule_id]}) [${rule_id}]${RESET}" ;;
      esac
      [[ -n "${rule_samples[$rule_id]:-}" ]] && echo "  ${DIM}${rule_samples[$rule_id]}${RESET}"
    done < <(printf '%s\n' "${!rule_counts[@]}" | sort)
  fi
}

category_18_inventory() {
  local cat=18
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  local sln_count csproj_count
  sln_count=$(find "$PROJECT_DIR" -maxdepth 3 -name '*.sln' 2>/dev/null | wc -l | awk '{print $1+0}')
  csproj_count=$(find "$PROJECT_DIR" -maxdepth 3 -name '*.csproj' 2>/dev/null | wc -l | awk '{print $1+0}')
  local tfm_hits
  local tmp="$TMP_DIR/cat18.tfm.txt"
  search '<TargetFramework' "$tmp"
  tfm_hits=$(cat "$tmp" | count_lines)

  bump_counter info 1
  add_finding "info" "$cat" "Inventory: solutions=$sln_count projects=$csproj_count tfm_tags=$tfm_hits files=$TOTAL_FILES" "" 0 ""
  [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Solutions: $sln_count, Projects: $csproj_count, TargetFramework tags: $tfm_hits, C# files scanned: $TOTAL_FILES${RESET}"
  return 0
}

# Resource lifecycle correlation similar to Rust scanner
category_19_resource_lifecycle() {
  local cat=19
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"

  if run_csharp_resource_lifecycle_helper "$cat"; then
    return 0
  fi

  if [[ "$HAS_PYTHON" -eq 1 && "$RESOURCE_LIFECYCLE_HELPER_STATUS" != "python-missing" ]]; then
    RESOURCE_LIFECYCLE_HELPER_STATUS="fallback"
  fi

  if [[ "$HAS_PYTHON" -eq 0 ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}python3 not found; lifecycle correlation reduced (skipping).${RESET}"
    return 0
  fi

  local report="$TMP_DIR/cat19.lifecycle.txt"
  python3 - "$FILELIST_NUL" "$report" <<'PY' 2>/dev/null || true
import sys, re
nul_list=sys.argv[1]
out=sys.argv[2]

acquires = [
  ("CancellationTokenSource", re.compile(r'new\s+CancellationTokenSource\s*\('), re.compile(r'\.Dispose\s*\(')),
  ("Timer", re.compile(r'new\s+Timer\s*\('), re.compile(r'\.Dispose\s*\(')),
  ("HttpClient", re.compile(r'new\s+HttpClient\s*\('), re.compile(r'\.Dispose\s*\(')),
]
def load_files():
  data=open(nul_list,'rb').read().split(b'\0')
  return [b.decode('utf-8','ignore') for b in data if b]

findings=[]
for path in load_files():
  try:
    txt=open(path,'r',encoding='utf-8',errors='ignore').read()
  except Exception:
    continue
  for name, acq, rel in acquires:
    acq_hits=[]
    for m in acq.finditer(txt):
      window=txt[max(0,m.start()-40):m.start()+40]
      if 'using' in window:
        continue
      acq_hits.append(m.start())
    if not acq_hits:
      continue
    rel_hits=len(list(rel.finditer(txt)))
    if len(acq_hits) > rel_hits:
      findings.append((path,name,len(acq_hits),rel_hits))
with open(out,'w',encoding='utf-8') as f:
  for path,name,a,r in findings:
    f.write(f"{path}:0:{name} acquired {a}x but Dispose() seen {r}x (heuristic)\n")
PY

  local hits
  hits=$(cat "$report" | count_lines)
  RESOURCE_LIFECYCLE_FINDINGS="$hits"
  if [[ "$hits" -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} Potential resource lifecycle imbalances (heuristic): $hits${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$report" | print_matches "Resource lifecycle imbalance" "Dispose mismatch" "warning" "$cat" || true
  else
    [[ "$FORMAT" == "text" ]] && echo "${GREEN}${ICON_OK} No obvious per-file lifecycle imbalances detected (heuristic).${RESET}"
  fi
}

category_20_async_locks() {
  local cat=20
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat20.lock.txt"
  local hits=0

  if [[ "$AST_GREP_STATUS" == "used" || "$AST_GREP_STATUS" == "clean" ]]; then
    [[ "$FORMAT" == "text" ]] && echo "${DIM}Exact await-in-lock detection handled by ast-grep; skipping file-level lock/await heuristic.${RESET}"
  else
search '\block\s*\(' "$tmp"
    hits=$(cat "$tmp" | count_lines)
    if [[ "$hits" -gt 0 ]]; then
      local await_file="$TMP_DIR/cat20.await.txt"
      search '\bawait\b' "$await_file"
      local await_hits
      await_hits=$(cat "$await_file" | count_lines)
      if [[ "$await_hits" -gt 0 ]]; then
        bump_counter warning "$hits"
        [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} lock(...) used in files that also use await ($hits lock sites) - ensure you never await while holding a lock${RESET}"
        [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "lock in async code" "lock(" "warning" "$cat" || true
      else
        [[ "$FORMAT" == "text" ]] && echo "${DIM}lock(...) found, but no 'await' tokens in scan scope (skipping).${RESET}"
      fi
    fi
  fi

  # SemaphoreSlim.Wait() in async code (should prefer WaitAsync)
  local tmp2="$TMP_DIR/cat20.sem.txt"
search '\bSemaphoreSlim\b.*\.Wait\s*\(' "$tmp2"
  hits=$(cat "$tmp2" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} SemaphoreSlim.Wait() ($hits) - blocks; prefer WaitAsync with await${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp2" | print_matches "SemaphoreSlim.Wait" "Wait(" "warning" "$cat" || true
  fi
}

category_21_exception_surfaces() {
  local cat=21
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat21.txt"
  local hits=0

  # catch { }
search 'catch\s*\{\s*\}' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} catch { } blocks ($hits) - catches all exceptions; ensure logging/rethrow${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "catch { }" "catch { }" "warning" "$cat" || true
  fi

  # throwing new exception in catch blocks (heuristic)
search 'catch\s*\([^)]*\)\s*\{[^}]*throw\s+new\s+[A-Za-z_][A-Za-z0-9_]*Exception\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} catch ... throw new ...Exception(...) ($hits) - ensure you preserve original exception as InnerException${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "throw new Exception in catch" "throw new" "info" "$cat" || true
  fi
}

category_22_casts_truncation() {
  local cat=22
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat22.txt"
  local hits=0

  # unchecked keyword
search '\bunchecked\s*\{' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} unchecked { ... } blocks ($hits) - overflow intentionally ignored; review${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "unchecked" "unchecked" "info" "$cat" || true
  fi

  # Convert.ToInt32
search '\bConvert\.ToInt32\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} Convert.ToInt32(...) ($hits) - may throw/overflow; ensure bounds checks${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Convert.ToInt32" "Convert.ToInt32" "info" "$cat" || true
  fi
}

category_23_parsing_validation() {
  local cat=23
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat23.txt"
  local hits=0

  # Parse without TryParse
search '\b(int|long|double|decimal|DateTime|Guid)\.Parse\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter warning "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${YELLOW}${ICON_WARN} .Parse(...) calls ($hits) - can throw; prefer TryParse on untrusted input${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "Parse without TryParse" ".Parse(" "warning" "$cat" || true
  fi
}

category_24_perf_dos() {
  local cat=24
  category_enabled "$cat" || return 0
  [[ "$FORMAT" == "text" ]] && echo "" && echo "${BOLD}[$cat] ${CATEGORY_NAMES[$cat]}${RESET}"
  local tmp="$TMP_DIR/cat24.txt"
  local hits=0

  # new Regex inside code (heuristic)
search '\bnew\s+Regex\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} new Regex(...) ($hits) - consider RegexOptions.Compiled/static caching; beware ReDoS with untrusted patterns${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "new Regex" "new Regex" "info" "$cat" || true
  fi

  # LINQ in loops (very heuristic)
search '\b(for|foreach|while)\b.*\.(Select|Where|OrderBy|GroupBy)\s*\(' "$tmp"
  hits=$(cat "$tmp" | count_lines)
  if [[ "$hits" -gt 0 ]]; then
    bump_counter info "$hits"
    [[ "$FORMAT" == "text" ]] && echo "${CYAN}${ICON_INFO} LINQ in loops ($hits) - potential perf hotspots; consider hoisting/optimizing${RESET}"
    [[ "$FORMAT" == "text" ]] && head -n "$DETAIL_LIMIT" "$tmp" | print_matches "LINQ in loops" "Select(" "info" "$cat" || true
  fi
}

# ---------- main ----------
main() {
  parse_args "$@"
  init_colors
  TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ubs_csharp)"
  detect_tools
  detect_ast_grep_style
  banner

  if [[ "$FORMAT" == "text" ]]; then
    echo "${DIM}Project: $PROJECT_DIR${RESET}"
    note "Tools: rg=$HAS_RG ast-grep=$HAS_AST_GREP dotnet=$HAS_DOTNET python3=$HAS_PYTHON"
    [[ "$STRICT_GITIGNORE" -eq 1 ]] && note "Strict .gitignore: ON" || note "Strict .gitignore: OFF (scanning beyond .gitignore)"
  fi

  count_project_files

  # Run categories
  category_1_exceptions_nullability
  category_2_resources_idisposable
  category_3_concurrency_async
  category_4_numeric_fp
  category_5_collections_linq
  category_6_strings_alloc
  category_7_io_process
  category_8_security
  category_9_quality_markers
  category_10_api_misuse
  category_11_tests_debug
  category_12_format_analyzers
  category_13_build_test
  category_14_deps_nuget
  category_15_exception_handling
  category_16_aspnet_web
  category_17_ast_grep_pack
  category_18_inventory
  category_19_resource_lifecycle
  category_20_async_locks
  category_21_exception_surfaces
  category_22_casts_truncation
  category_23_parsing_validation
  category_24_perf_dos

  # Decide exit code
  EXIT_CODE=0
  if [[ -n "$FAIL_CRITICAL_N" ]]; then
    if [[ "$CRITICAL_FINDINGS" -ge "$FAIL_CRITICAL_N" ]]; then EXIT_CODE=1; fi
  elif [[ "$CRITICAL_FINDINGS" -gt 0 ]]; then
    EXIT_CODE=1
  fi

  if [[ -n "$FAIL_WARNING_N" ]]; then
    if [[ "$WARNING_FINDINGS" -ge "$FAIL_WARNING_N" ]]; then EXIT_CODE=1; fi
  elif [[ "$FAIL_ON_WARNING" -eq 1 && "$WARNING_FINDINGS" -gt 0 ]]; then
    EXIT_CODE=1
  fi

  if [[ "$FORMAT" == "text" ]]; then
    echo ""
    echo "${BOLD}Summary Statistics:${RESET}"
    echo "  Files scanned: $TOTAL_FILES"
    echo "  Critical issues: $CRITICAL_FINDINGS"
    echo "  Warning issues: $WARNING_FINDINGS"
    echo "  Info items: $INFO_FINDINGS"
    echo "  Exit code    : $EXIT_CODE"
    if [[ "$HAS_AST_GREP" -eq 1 ]]; then
      echo "${DIM}Tip: run with --format=sarif to generate SARIF from ast-grep rules.${RESET}"
    fi
  fi

  emit_module_metrics

  # Outputs
  if [[ -n "$EMIT_FINDINGS_JSON" ]]; then
    emit_findings_json "$EMIT_FINDINGS_JSON"
    [[ "$FORMAT" == "text" ]] && ok "Wrote findings JSON: $EMIT_FINDINGS_JSON"
  fi
  if [[ -n "$SUMMARY_JSON" ]]; then
    emit_summary_json >"$SUMMARY_JSON"
    [[ "$FORMAT" == "text" ]] && ok "Wrote summary JSON: $SUMMARY_JSON"
  fi

  if [[ "$FORMAT" == "json" ]]; then
    emit_summary_json
  elif [[ "$FORMAT" == "sarif" ]]; then
    emit_sarif
  fi

  exit "$EXIT_CODE"
}

main "$@"
