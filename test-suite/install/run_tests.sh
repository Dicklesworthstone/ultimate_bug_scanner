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

test_fresh_home_no_path() {
  echo "[TEST] fresh_home_no_path"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home"
  local log="$ctx/install.log"
  local bin_dir="$home/.local/bin"
  mkdir -p "$bin_dir" "$home/.ubs-workdir"
  local workdir="$home/.ubs-workdir/fresh.${RANDOM}${RANDOM}"
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true

  # Regression for the first-install abort: the install dir is deliberately NOT
  # on PATH, so verify_installation takes its "ubs command not found in PATH"
  # branch. Before the fix that branch ran `((errors++))`, which returns 1 when
  # errors is 0 and, under `set -e`, killed the installer before the completion
  # banner, session log, and PATH advice were ever printed.
  local status=0
  UBS_INSTALLER_WORKDIR="$workdir" HOME="$home" PATH="/usr/local/bin:/usr/bin:/bin" SHELL=/bin/bash \
    "$INSTALLER" \
      --non-interactive \
      --skip-ast-grep \
      --skip-ripgrep \
      --skip-jq \
      --skip-doctor \
      --skip-hooks \
      --skip-version-check \
      --skip-typos \
      --no-path-modify \
      --install-dir "$bin_dir" >"$log" 2>&1 || status=$?

  if [ "$status" -ne 0 ]; then
    echo "[FAIL] installer exited with status $status when the install dir was off PATH (log: $log)"
    tail -n 60 "$log" || true
    tests_failed=1
    return 1
  fi
  local needle
  for needle in "ubs command not found in PATH" "INSTALLATION COMPLETE" "Almost Done"; do
    if ! grep -q "$needle" "$log"; then
      echo "[FAIL] expected '$needle' in installer output (log: $log)"
      tail -n 60 "$log" || true
      tests_failed=1
      return 1
    fi
  done
  if [ ! -x "$bin_dir/ubs" ]; then
    echo "[FAIL] ubs binary not installed at $bin_dir/ubs"
    tests_failed=1
    return 1
  fi
  echo "[PASS] fresh_home_no_path"
}

test_claude_hooks_registered() {
  echo "[TEST] claude_hooks_registered"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" proj="$ctx/proj" log="$ctx/install.log"
  mkdir -p "$home" "$proj/.claude"
  # Pre-existing settings must survive the merge.
  printf '{\n  "permissions": {\n    "allow": [\n      "Bash(ls:*)"\n    ]\n  }\n}\n' >"$proj/.claude/settings.json"
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true

  local rc=0
  (cd "$proj" && UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" SHELL=/bin/bash "$INSTALLER" --skip-version-check --setup-claude-hook) >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[FAIL] --setup-claude-hook exited $rc (log: $log)"
    tail -n 40 "$log" || true
    tests_failed=1
    return 1
  fi
  local settings="$proj/.claude/settings.json"
  if [ ! -x "$proj/.claude/hooks/on-file-write.sh" ] || [ ! -f "$proj/.claude/hooks/git_safety_guard.py" ]; then
    echo "[FAIL] hook files missing under $proj/.claude/hooks (log: $log)"
    tests_failed=1
    return 1
  fi
  if ! python3 - "$settings" << 'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data["permissions"]["allow"] == ["Bash(ls:*)"], "pre-existing settings were lost"
hooks = data["hooks"]
def commands(event):
    return [h["command"] for entry in hooks.get(event, []) for h in entry.get("hooks", [])]
assert commands("PostToolUse").count("$CLAUDE_PROJECT_DIR/.claude/hooks/on-file-write.sh") == 1, commands("PostToolUse")
assert commands("PreToolUse").count("$CLAUDE_PROJECT_DIR/.claude/hooks/git_safety_guard.py") == 1, commands("PreToolUse")
assert [e["matcher"] for e in hooks["PostToolUse"]] == ["Edit|Write|MultiEdit"]
PY
  then
    echo "[FAIL] settings.json does not contain the expected hook registrations ($settings)"
    cat "$settings" || true
    tests_failed=1
    return 1
  fi

  # Second run must be a no-op (idempotent merge).
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$proj" && UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" SHELL=/bin/bash "$INSTALLER" --skip-version-check --setup-claude-hook) >>"$log" 2>&1 || rc=$?
  if [ "$(grep -c 'on-file-write.sh' "$settings")" -ne 1 ] || [ "$(grep -c 'git_safety_guard.py' "$settings")" -ne 1 ]; then
    echo "[FAIL] hook registration is not idempotent ($settings)"
    tests_failed=1
    return 1
  fi

  # The hook reads Claude Code's JSON payload from stdin and scans only that file:
  # a buggy fixture must surface findings on stderr with exit 2, a non-source
  # file must exit 0 silently.
  local hook="$proj/.claude/hooks/on-file-write.sh"
  local hook_rc=0
  (cd "$ROOT_DIR" && printf '{"tool_name":"Write","tool_input":{"file_path":"%s"}}' "$ROOT_DIR/test-suite/buggy/02-security.js" \
    | PATH="$ROOT_DIR:$PATH" UBS_NO_AUTO_UPDATE=1 "$hook" >"$ctx/hook.out" 2>"$ctx/hook.err") || hook_rc=$?
  if [ "$hook_rc" -ne 2 ] || ! grep -q "UBS found critical issues" "$ctx/hook.err"; then
    echo "[FAIL] hook on a buggy file: expected exit 2 with findings on stderr, got $hook_rc"
    tail -n 20 "$ctx/hook.err" || true
    tests_failed=1
    return 1
  fi
  hook_rc=0
  (cd "$ROOT_DIR" && printf '{"tool_name":"Write","tool_input":{"file_path":"%s"}}' "$ROOT_DIR/README.md" \
    | PATH="$ROOT_DIR:$PATH" UBS_NO_AUTO_UPDATE=1 "$hook" >"$ctx/hook2.out" 2>"$ctx/hook2.err") || hook_rc=$?
  if [ "$hook_rc" -ne 0 ] || [ -s "$ctx/hook2.err" ]; then
    echo "[FAIL] hook on a non-source file: expected silent exit 0, got $hook_rc"
    tests_failed=1
    return 1
  fi
  echo "[PASS] claude_hooks_registered"
}

test_flag_order_independence() {
  echo "[TEST] flag_order_independence"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" log="$ctx/install.log"
  mkdir -p "$home"

  # --help must answer without taking the lock or touching the network.
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  local rc=0
  UBS_INSTALLER_WORKDIR="$ctx/work.help.${RANDOM}${RANDOM}" HOME="$home" "$INSTALLER" --help >"$ctx/help.out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q -- "--dry-run" "$ctx/help.out" || [ -d /tmp/ubs-install.lock ] || grep -qiE "Checking for updates|Fetching|release tag" "$ctx/help.out"; then
    echo "[FAIL] --help should print usage offline without locking (rc=$rc)"
    tail -n 20 "$ctx/help.out" || true
    tests_failed=1
    return 1
  fi

  # --setup-claude-hook --dry-run: dry-run must apply even though it comes second.
  local proj="$ctx/proj"
  mkdir -p "$proj/.claude"
  rc=0
  (cd "$proj" && UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" SHELL=/bin/bash "$INSTALLER" --skip-version-check --setup-claude-hook --dry-run) >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || [ -e "$proj/.claude/hooks/on-file-write.sh" ] || ! grep -q "Would write" "$log"; then
    echo "[FAIL] --setup-claude-hook --dry-run wrote files or did not report a dry run (rc=$rc, log: $log)"
    tail -n 20 "$log" || true
    tests_failed=1
    return 1
  fi

  # --uninstall --non-interactive (the README one-liner) must not prompt and
  # must remove the binary it installed. Uninstall also removes project-level
  # integrations relative to the CURRENT DIRECTORY (.claude/hooks, agent rule
  # files), so it must run from a throwaway project dir, never from the repo.
  local uninstall_proj="$ctx/uninstall-proj"
  mkdir -p "$uninstall_proj"
  if run_installer "$home" "$ctx/install-for-uninstall.log"; then
    rc=0
    (cd "$uninstall_proj" && UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" PATH="$home/.local/bin:$PATH" SHELL=/bin/bash \
      "$INSTALLER" --skip-version-check --uninstall --non-interactive --install-dir "$home/.local/bin") >"$ctx/uninstall.log" 2>&1 </dev/null || rc=$?
    if [ "$rc" -ne 0 ] || grep -q "Uninstall cancelled" "$ctx/uninstall.log" || [ -e "$home/.local/bin/ubs" ]; then
      echo "[FAIL] --uninstall --non-interactive did not complete (rc=$rc, log: $ctx/uninstall.log)"
      tail -n 30 "$ctx/uninstall.log" || true
      tests_failed=1
      return 1
    fi
  else
    return 1
  fi
  echo "[PASS] flag_order_independence"
}

test_basic_smoke
test_no_alias_written_when_no_path_modify
test_skip_typos_flag
test_fresh_home_no_path
test_claude_hooks_registered
test_flag_order_independence
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
