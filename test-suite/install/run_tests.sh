#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"

tests_failed=0
tmpdirs=()
SELF_TEST_MODE="${UBS_INSTALLER_SELF_TEST:-0}"

mktemp_dir() {
  local base="${TMPDIR:-/tmp}"
  mktemp -d 2>/dev/null \
    || mktemp -d -t ubs-install-tests.XXXXXX 2>/dev/null \
    || mktemp -d "${base%/}/ubs-install-tests.XXXXXX" 2>/dev/null
}

check_sessions_command() {
  local home_dir="$1"
  local output_file="$2"
  local bin="$home_dir/.local/bin/ubs"
  if ! HOME="$home_dir" XDG_CONFIG_HOME="$home_dir/.config" "$bin" sessions --entries 1 >"$output_file" 2>&1; then
    echo "[FAIL] 'ubs sessions' failed (output: $output_file)"
    tail -n 60 "$output_file" || true
    tests_failed=1
    return 1
  fi
  if ! grep -q "Install Session" "$output_file"; then
    echo "[FAIL] session log missing header (output: $output_file)"
    tests_failed=1
    return 1
  fi
  if ! grep -q "Tool readiness" "$output_file"; then
    echo "[FAIL] readiness facts missing from session output"
    tests_failed=1
    return 1
  fi
  echo "[PASS] sessions_command"
}

cleanup() {
  for dir in "${tmpdirs[@]:-}"; do
    rm -rf "$dir"
  done
}
trap cleanup EXIT

run_installer() {
  local home_dir="$1"
  local log_file="$2"
  shift 2

  local bin_dir="$home_dir/.local/bin"
  mkdir -p "$bin_dir"
  local workdir_base="$home_dir/.ubs-workdir"
  mkdir -p "$workdir_base"
  local workdir_suffix="ubs-install-workdir.${RANDOM}${RANDOM}${RANDOM}"
  local workdir="$workdir_base/$workdir_suffix"
  while [ -e "$workdir" ]; do
    workdir_suffix="${workdir_suffix}.${RANDOM}${RANDOM}"
    workdir="$workdir_base/$workdir_suffix"
  done

  rm -rf /tmp/ubs-install.lock 2>/dev/null || true

  if UBS_INSTALLER_WORKDIR="$workdir" HOME="$home_dir" PATH="$bin_dir:$PATH" SHELL=/bin/bash \
      "$INSTALLER" \
        --non-interactive \
        --skip-ast-grep \
        --skip-ripgrep \
        --skip-jq \
        --skip-doctor \
        --skip-hooks \
        --skip-version-check \
        --no-path-modify \
        --install-dir "$bin_dir" \
        "$@" >"$log_file" 2>&1; then
    :
  else
    local status=$?
    echo "[FAIL] Installer exited with status $status (log: $log_file)"
    tail -n 80 "$log_file"
    tests_failed=1
    return 1
  fi

  if ! grep -q "POST-INSTALL VERIFICATION" "$log_file"; then
    echo "[FAIL] Verification block missing (log: $log_file)"
    tests_failed=1
    return 1
  fi

  if [ ! -x "$bin_dir/ubs" ]; then
    echo "[FAIL] ubs binary not installed at $bin_dir/ubs"
    tests_failed=1
    return 1
  fi

  if [ -d /tmp/ubs-install.lock ]; then
    echo "[FAIL] lock directory /tmp/ubs-install.lock left behind (log: $log_file)"
    rm -rf /tmp/ubs-install.lock 2>/dev/null || true
    tests_failed=1
    return 1
  fi

  if [ -d "$workdir" ]; then
    echo "[FAIL] installer workdir $workdir was not cleaned up"
    rm -rf "$workdir" 2>/dev/null || true
    tests_failed=1
    return 1
  fi

  return 0
}

test_basic_smoke() {
  echo "[TEST] basic_smoke"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home"
  local log="$ctx/install.log"
  local session_output="$ctx/session.out"

  if run_installer "$home" "$log"; then
    if grep -q "typos not found" "$log"; then
      echo "[PASS] typos warning emitted"
    elif grep -q "typos:" "$log"; then
      echo "[PASS] typos detected"
    else
      echo "[FAIL] expected typos status missing (log: $log)"
      tests_failed=1
      return
    fi
    check_sessions_command "$home" "$session_output"
    echo "[PASS] basic_smoke"
  fi
}

test_no_alias_written_when_no_path_modify() {
  echo "[TEST] no_alias_with_no_path_modify"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home"
  mkdir -p "$home"
  local rc_file="$home/.bashrc"
  echo "# Sentinel file" >"$rc_file"
  cp "$rc_file" "$rc_file.before"
  local log="$ctx/install.log"

  if run_installer "$home" "$log"; then
    if cmp -s "$rc_file" "$rc_file.before"; then
      echo "[PASS] no_alias_with_no_path_modify"
    else
      echo "[FAIL] rc file modified despite --no-path-modify"
      diff -u "$rc_file.before" "$rc_file" || true
      tests_failed=1
    fi
  fi
}

test_skip_typos_flag() {
  echo "[TEST] skip_typos_flag"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home"
  local log="$ctx/install.log"

  if run_installer "$home" "$log" --skip-typos; then
    if grep -q "typos not found" "$log"; then
      echo "[FAIL] typos warning appeared despite --skip-typos"
      tests_failed=1
    else
      echo "[PASS] skip_typos_flag"
    fi
  fi
}

test_self_test_flag() {
  echo "[TEST] self_test_flag"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home"
  local log="$ctx/install.log"

  if run_installer "$home" "$log" --skip-typos --self-test; then
    echo "[PASS] self_test_flag"
  fi
}

test_basic_smoke
test_no_alias_written_when_no_path_modify
test_skip_typos_flag
if [ "$SELF_TEST_MODE" -ne 1 ]; then
  test_self_test_flag
fi

if [ "$tests_failed" -ne 0 ]; then
  echo ""
  echo "[RESULT] Installer tests failed."
  exit 1
fi

echo ""
echo "[RESULT] All installer tests passed."
