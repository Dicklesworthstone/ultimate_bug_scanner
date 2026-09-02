#!/usr/bin/env bash
# Shared primitives for the UBS language modules (bead A1, library v1).
#
# Sourced by every modules/ubs-<lang>.sh:
#   UBS_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$UBS_MODULE_DIR/lib/ubs-common.sh"
#
# Distributed and checksum-verified exactly like the helpers (HELPER_ASSETS /
# HELPER_CHECKSUMS in the meta-runner, key "lib/ubs-common.sh"), so a cached
# module always finds the library next to itself.
#
# Everything here used to exist in 4–7 drifted copies across the modules; the
# bugs those copies carried (LC_ALL assigned but never exported, json_escape
# bodies that break under `set -u` or skip control characters, silent text
# fallback for --format=toon/jsonl) are fixed once, here.

if [[ -n "${UBS_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
UBS_COMMON_LOADED=1
# Read by the modules and quality/test_ubs_common.py after sourcing.
# shellcheck disable=SC2034
UBS_COMMON_VERSION="1"

# ── Locale ──────────────────────────────────────────────────────────────────
# Child tools (sort, grep, awk, rg) must see the C locale for byte-stable
# ordering and matching; Python helpers keep UTF-8 I/O regardless.
ubs_export_locale(){
  export LC_ALL=C
  export LANG=C
  export PYTHONIOENCODING=utf-8
  export PYTHONUTF8=1
}

# ── Time / failure ──────────────────────────────────────────────────────────
ubs_now_ms(){
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local s="${EPOCHREALTIME%.*}" us="${EPOCHREALTIME#*.}"
    printf '%s\n' $(( s * 1000 + 10#${us:0:3} ))
  else
    local ns; ns="$(date +%s%N 2>/dev/null || echo 0)"
    printf '%s\n' $(( ns / 1000000 ))
  fi
}

# ubs_die MESSAGE [EXIT_CODE=2]: environment/usage errors exit 2 by contract.
ubs_die(){
  printf '✗ %s\n' "$1" >&2
  exit "${2:-2}"
}

# ubs_with_timeout SECONDS CMD...: run CMD under `timeout` when available
# (0 = no limit); exit status is the command's, or 124 on timeout.
ubs_with_timeout(){
  local secs="$1"; shift
  if [[ "$secs" =~ ^[0-9]+$ && "$secs" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@"
  fi
}

# ── JSON ────────────────────────────────────────────────────────────────────
# json_escape [STRING]: escape for a JSON string body (no surrounding quotes).
# Missing argument and empty string are both fine under `set -u`; with no
# argument stdin is used. Every control character U+0000–U+001F is escaped
# (\n \r \t \b \f by name, the rest as \u00XX); non-ASCII passes through.
json_escape(){
  local s=""
  if [[ $# -gt 0 ]]; then s="${1-}"; else s="$(cat 2>/dev/null || true)"; fi
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//$'\b'/\\b}
  s=${s//$'\f'/\\f}
  if [[ "$s" == *[$'\x01'-$'\x1f']* ]]; then
    local out="" ch code
    local i
    for (( i = 0; i < ${#s}; i++ )); do
      ch="${s:i:1}"
      printf -v code '%d' "'$ch"
      if (( code > 0 && code < 32 )); then
        printf -v ch '\\u%04x' "$code"
      fi
      out+="$ch"
    done
    s="$out"
  fi
  printf '%s' "$s"
}

# ── Severity ────────────────────────────────────────────────────────────────
# ubs_normalize_severity NAME: the four severities every module reports.
ubs_normalize_severity(){
  case "${1,,}" in
    critical|crit|error|err|high|fatal|blocker) printf 'critical' ;;
    warning|warn|medium|moderate|important) printf 'warning' ;;
    info|information|note|notice|low|minor|hint|style) printf 'info' ;;
    good|ok|pass|clean|none) printf 'good' ;;
    *) printf 'info' ;;
  esac
}

# ── Output format contract ──────────────────────────────────────────────────
# Modules render text, json and sarif. jsonl and toon are produced by the
# meta-runner from the module's json, so asking a module for them directly is
# a usage error (exit 2) — never a silent fallback to text.
ubs_validate_format(){
  case "${1:-text}" in
    text|json|sarif) return 0 ;;
    jsonl|toon)
      ubs_die "--format=$1 is produced by the meta-runner from this module's json; run 'ubs --format=$1' instead (module formats: text|json|sarif)" 2 ;;
    *)
      ubs_die "unknown --format value: $1 (expected text|json|sarif)" 2 ;;
  esac
}

# ── File listing ────────────────────────────────────────────────────────────
# ubs_list_files DIR [--ext CSV] [--exclude CSV] [--files-from FILE]
# Prints NUL-separated paths (safe for names with spaces or newlines).
#   --ext       comma-separated extensions without dots (js,ts); default: all
#   --exclude   comma-separated directory names or globs to skip
#   --files-from  a file with one path per line (or NUL-separated): only those
#                 that exist under DIR are listed (meta-runner file lists)
# Uses `rg --files -0` (respects .gitignore, skips hidden and binary files
# the way the modules already do) and falls back to `find -print0`.
ubs_list_files(){
  local dir="$1"; shift
  local exts="" excludes="" files_from=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ext) exts="$2"; shift 2 ;;
      --ext=*) exts="${1#*=}"; shift ;;
      --exclude) excludes="$2"; shift 2 ;;
      --exclude=*) excludes="${1#*=}"; shift ;;
      --files-from) files_from="$2"; shift 2 ;;
      --files-from=*) files_from="${1#*=}"; shift ;;
      *) ubs_die "ubs_list_files: unknown option $1" 2 ;;
    esac
  done
  [[ -d "$dir" ]] || return 0
  if [[ -n "$files_from" && -f "$files_from" ]]; then
    local f
    while IFS= read -r -d '' f || [[ -n "$f" ]]; do
      f="${f%$'\n'}"
      [[ -z "$f" ]] && continue
      if [[ "$f" == /* ]]; then
        [[ -f "$f" ]] && printf '%s\0' "$f"
      elif [[ -f "$dir/$f" ]]; then
        printf '%s\0' "$dir/$f"
      fi
    done < <(tr '\n' '\0' < "$files_from"; printf '\0')
    return 0
  fi
  local -a rg_args=(--files -0 --no-messages)
  local -a find_args=()
  local item
  if [[ -n "$exts" ]]; then
    local -a ext_list
    IFS=',' read -r -a ext_list <<<"$exts"
    for item in "${ext_list[@]}"; do
      item="${item#.}"
      [[ -z "$item" ]] && continue
      rg_args+=(-g "*.${item}")
      if [[ ${#find_args[@]} -eq 0 ]]; then find_args+=( '(' -name "*.${item}" ); else find_args+=( -o -name "*.${item}" ); fi
    done
    [[ ${#find_args[@]} -gt 0 ]] && find_args+=( ')' )
  fi
  local -a prune_args=()
  if [[ -n "$excludes" ]]; then
    local -a ex_list
    IFS=',' read -r -a ex_list <<<"$excludes"
    for item in "${ex_list[@]}"; do
      [[ -z "$item" ]] && continue
      rg_args+=(-g "!${item}")
      prune_args+=( -path "*/${item}" -prune -o -path "*/${item}/*" -prune -o )
    done
  fi
  if command -v rg >/dev/null 2>&1; then
    rg "${rg_args[@]}" -- "$dir" 2>/dev/null
  else
    find "$dir" -xdev "${prune_args[@]}" -type f "${find_args[@]}" -print0 2>/dev/null
  fi
}

# ubs_count_files DIR [options...]: number of files ubs_list_files would list.
ubs_count_files(){
  ubs_list_files "$@" | tr -cd '\0' | wc -c | awk '{print $1+0}'
}
