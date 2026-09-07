#!/usr/bin/env bash
# Clean Bash script demonstrating idiomatic shell patterns
set -Eeuo pipefail

export LC_ALL=C

count=0
count=$((count + 1))
((count += 1))

run_step() {
  local output
  output="$(date +%s)"
  echo "Current timestamp: $output"
}

check_condition() {
  local a="hello"
  local b="world"
  if [[ -n "$a" && -n "$b" ]]; then
    echo "$a $b"
  fi
}

process_input() {
  local line
  while IFS= read -r line; do
    echo "Processing: $line"
  done < <(printf 'one\ntwo\n')
}

navigate() {
  local target="/tmp"
  cd "$target" || exit 1
  local tmp_file
  tmp_file="$(mktemp)"
  echo "safe" > "$tmp_file"
  rm -f "$tmp_file"
  cd - >/dev/null || exit 1
}

run_step
check_condition
process_input
navigate
