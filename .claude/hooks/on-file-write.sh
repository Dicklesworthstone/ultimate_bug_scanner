#!/usr/bin/env bash
# Ultimate Bug Scanner - Claude Code PostToolUse hook for Edit|Write|MultiEdit.
#
# Claude Code passes the tool call as JSON on stdin ({"tool_name": ..., "tool_input":
# {"file_path": ...}}). The hook scans just the file that was written and, when UBS
# reports critical findings, exits 2 so the scanner output is shown to Claude as
# feedback on the edit it just made. Clean files exit 0 silently.
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
  *.js|*.jsx|*.mjs|*.cjs|*.ts|*.tsx|*.py|*.pyw|*.pyi|*.c|*.cc|*.cpp|*.cxx|*.h|*.hh|*.hpp|*.hxx|*.rs|*.go|*.java|*.kt|*.kts|*.rb|*.swift|*.cs|*.csx|*.ex|*.exs) ;;
  *) exit 0 ;;
esac

if ! command -v ubs >/dev/null 2>&1; then
  echo "ubs not found in PATH; install it (https://github.com/Dicklesworthstone/ultimate_bug_scanner) to scan edits." >&2
  exit 0
fi

if report="$(ubs "$file" --ci 2>&1)"; then
  exit 0
fi
{
  echo "UBS found critical issues in $file — fix them before moving on:"
  printf '%s\n' "$report" | tail -n 60
} >&2
exit 2
