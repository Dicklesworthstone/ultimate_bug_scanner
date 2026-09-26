#!/usr/bin/env bash
# Ultimate Bug Scanner - Claude Code PostToolUse hook for Edit|Write|MultiEdit.
#
# Claude Code passes the tool call as JSON on stdin ({"tool_name": ..., "tool_input":
# {"file_path": ...}}). The hook scans just the file that was written and, when UBS
# reports critical findings, exits 2 so the scanner output is shown to Claude as
# feedback on the edit it just made. Clean files exit 0 silently. This checkout
# hook uses an optional trusted ubs-daemon on PATH; standalone installer hooks
# continue to work through the one-shot scanner without requiring that frontend.
set -u

payload="$(cat 2>/dev/null || true)"
file=""
if [[ -n "$payload" ]]; then
  if command -v jq >/dev/null 2>&1; then
    file="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null || true)"
  elif command -v python3 >/dev/null 2>&1; then
    file="$(printf '%s' "$payload" | python3 -c '
import json, sys
try:
    tool_input = json.load(sys.stdin).get("tool_input") or {}
    print(tool_input.get("file_path") or tool_input.get("path") or "")
except Exception:
    print("")
' 2>/dev/null || true)"
  fi
fi
# Legacy contract: earlier versions of this hook read $FILE_PATH from the environment.
[[ -z "$file" ]] && file="${FILE_PATH:-}"
[[ -z "$file" || ! -f "$file" ]] && exit 0

case "$file" in
  *.js|*.jsx|*.mjs|*.cjs|*.ts|*.tsx|*.py|*.pyw|*.pyi|*.c|*.cc|*.cpp|*.cxx|*.h|*.hh|*.hpp|*.hxx|*.rs|*.go|*.java|*.kt|*.kts|*.rb|*.swift|*.cs|*.csx|*.ex|*.exs|*.sh|*.bash) ;;
  *) exit 0 ;;
esac

scanner="$(type -P ubs || true)"
if [[ -z "$scanner" ]]; then
  echo 'UBS could not scan this edit: ubs is not available on PATH.' >&2
  exit 2
fi

# Canonicalize the directory without losing embedded or trailing newlines.
# A trailing slash protects command-substitution output from newline stripping.
directory=.
[[ "$file" == */* ]] && directory="${file%/*}"
[[ -n "$directory" ]] || directory=/
if ! directory="$(cd -P -- "$directory" && printf '%s/' "$PWD")"; then
  echo 'UBS could not resolve the edited file directory.' >&2
  exit 2
fi
file="$directory${file##*/}"
command=("$scanner" --ci --no-auto-update --no-color --format=text -- "$file")
client="$(type -P ubs-daemon || true)"
if [[ -n "$client" ]]; then
  root=''
  if [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
    root="$(cd -P -- "$CLAUDE_PROJECT_DIR" && printf '%s/' "$PWD")" || exit 2
    root="${root%/}"
    [[ -n "$root" ]] || root=/
  elif root="$(git -C "$directory" rev-parse --show-toplevel 2>/dev/null && printf '.')"; then
    root="${root%.}"
    root="${root%$'\n'}"
  else
    root="${directory%/}"
    [[ -n "$root" ]] || root=/
  fi
  # The client alone decides whether absence/context mismatch warrants a
  # one-shot fallback. Never hide a protocol, authentication or scanner error.
  command=("$client" client --repo "$root" --scanner "$scanner" --format=text -- "$file")
fi

status=0
report="$("${command[@]}" 2>&1)" || status=$?
case "$status" in
  0|3) exit 0 ;;
  1) message="UBS found critical issues in $file — fix them before moving on:" ;;
  *) message="UBS could not complete the scan of $file (exit $status); this edit has NOT been verified:" ;;
esac
{
  printf '%s\n' "$message"
  printf '%s\n' "$report" | tail -n 60
} >&2
exit 2
