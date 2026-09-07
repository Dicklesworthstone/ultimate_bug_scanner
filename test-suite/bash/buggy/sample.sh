#!/usr/bin/env bash
# Buggy Bash script demonstrating common traps and anti-patterns
set -Eeuo pipefail

# Category 5: unexported LC_ALL
LC_ALL=C

count=0
# Category 1: post-increment under set -e fails when count is 0
((count++))

# Category 1: compound operator inside single brackets
a="foo"
b="bar"
if [ "$a" && "$b" ]; then
  echo "both set"
fi

buggy_function() {
  # Category 2: local declaration with command substitution masks exit code
  local out=$(date +%s)
  echo "$out"

  # Category 2: capturing $? after negated if condition is always 0
  if ! false; then
    status=$?
    echo "status: $status"
  fi
}

run_dangerous_commands() {
  local cmd="ls -la"
  # Category 3: eval of variable
  eval "$cmd"

  # Category 3: unverified curl piped directly to bash
  curl -fsSL https://example.com/install.sh | bash

  # Category 3: mktemp -u creates a TOCTOU race
  local tmp
  tmp=$(mktemp -u)
  echo "hello" > "$tmp"
}

unrobust_operations() {
  # Category 4: cd without exit or return check
  cd /tmp

  # Category 4: read without -r mangles backslashes
  read line < /dev/null
}

buggy_function
run_dangerous_commands
unrobust_operations
