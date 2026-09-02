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

test_agent_detection() {
  # README's integration table promises: TabNine and Replit are DETECTED ONLY
  # (nothing is written), GitHub Copilot gets .github/copilot-instructions.md.
  # Fake all three, run a full easy-mode install from a throwaway project dir,
  # and shim `crontab` so the auto-update step can never touch the host.
  echo "[TEST] agent_detection"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" proj="$ctx/proj" shim="$ctx/bin" log="$ctx/install.log"
  mkdir -p "$home/.tabnine" "$home/.vscode/extensions/github.copilot-1.0.0" "$home/.local/bin" "$proj" "$shim"
  printf 'run = "npm start"\n' >"$proj/.replit"
  local replit_before
  replit_before="$(cksum "$proj/.replit")"
  cat >"$shim/crontab" <<'SHIM'
#!/usr/bin/env bash
# Test shim: records what the installer would have scheduled instead of
# editing the real user crontab.
case "${1:-}" in
  -l) [ -f "$CRONTAB_SHIM_FILE" ] && cat "$CRONTAB_SHIM_FILE"; exit 0 ;;
  -)  cat >"$CRONTAB_SHIM_FILE"; exit 0 ;;
  *)  exit 1 ;;
esac
SHIM
  chmod +x "$shim/crontab"
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true

  local rc=0
  (cd "$proj" && CRONTAB_SHIM_FILE="$ctx/crontab.txt" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$shim:$home/.local/bin:$PATH" SHELL=/bin/bash \
    "$INSTALLER" --easy-mode --skip-ast-grep --skip-ripgrep --skip-jq --skip-doctor \
      --skip-version-check --no-path-modify --install-dir "$home/.local/bin") >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[FAIL] easy-mode install exited $rc (log: $log)"
    tail -n 40 "$log" || true
    tests_failed=1
    return 1
  fi
  if ! grep -q 'copilot=1 tabnine=1 replit=1' "$log"; then
    echo "[FAIL] agent detection did not report copilot/tabnine/replit (log: $log)"
    grep -n 'Additional:' "$log" || true
    tests_failed=1
    return 1
  fi
  if [ ! -f "$proj/.github/copilot-instructions.md" ] || ! grep -q 'ubs' "$proj/.github/copilot-instructions.md"; then
    echo "[FAIL] Copilot instructions were not written to $proj/.github/copilot-instructions.md"
    tests_failed=1
    return 1
  fi
  if [ -n "$(ls -A "$home/.tabnine")" ] || [ "$(cksum "$proj/.replit")" != "$replit_before" ]; then
    echo "[FAIL] TabNine/Replit are documented as detect-only, but files were written"
    ls -la "$home/.tabnine" || true
    tests_failed=1
    return 1
  fi
  if [ ! -f "$ctx/crontab.txt" ] || ! grep -q -- '--update' "$ctx/crontab.txt"; then
    echo "[FAIL] easy mode did not route the auto-update cron job through the crontab shim"
    tests_failed=1
    return 1
  fi
  echo "[PASS] agent_detection"
}

test_verified_download() {
  # Dependency binaries must be digest-verified (bead E4). Serve a TAMPERED
  # ast-grep release archive from a local HTTP mirror; the installer must
  # refuse it, and --skip-verification must say exactly what it skipped.
  echo "[TEST] verified_download"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[SKIP] verified_download (python3 not available for the local mirror)"
    return 0
  fi
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" shim="$ctx/bin" www="$ctx/www" log="$ctx/install.log"
  mkdir -p "$home/.local/bin" "$shim" "$www/ast-grep/ast-grep/releases/download/0.45.3"
  head -c 4096 /dev/urandom >"$www/ast-grep/ast-grep/releases/download/0.45.3/app-x86_64-unknown-linux-gnu.zip"
  # Package managers must not be tried (they would install for real): shim them to fail fast.
  printf '#!/usr/bin/env bash\necho "shim: package manager disabled in tests" >&2\nexit 1\n' >"$shim/cargo"
  cp "$shim/cargo" "$shim/npm"
  chmod +x "$shim/cargo" "$shim/npm"
  local port
  port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  (cd "$www" && python3 -m http.server "$port" --bind 127.0.0.1 >"$ctx/http.log" 2>&1) &
  local http_pid=$!
  sleep 1
  local arch
  arch="$(uname -m)"
  if [[ "$arch" != "x86_64" || "$(uname -s)" != "Linux" ]]; then
    kill "$http_pid" 2>/dev/null || true
    echo "[SKIP] verified_download (needs linux x86_64 to hit the tampered asset name)"
    return 0
  fi

  local rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$ctx" && UBS_INSTALLER_BINARY_BASE="http://127.0.0.1:$port" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$shim:/usr/bin:/bin:$home/.local/bin" SHELL=/bin/bash \
    "$INSTALLER" --non-interactive --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks \
      --skip-version-check --no-path-modify --install-dir "$home/.local/bin") >"$log" 2>&1 || rc=$?
  if ! grep -q 'Checksum mismatch for app-x86_64-unknown-linux-gnu.zip' "$log"; then
    kill "$http_pid" 2>/dev/null || true
    echo "[FAIL] tampered ast-grep archive was not rejected by digest verification (exit $rc, log: $log)"
    grep -n -i -E 'ast-grep|checksum|mirror' "$log" | tail -n 20 || true
    tests_failed=1
    return 1
  fi
  if [ -e "$home/.local/bin/ast-grep" ]; then
    kill "$http_pid" 2>/dev/null || true
    echo "[FAIL] a tampered ast-grep binary was installed despite the checksum mismatch"
    tests_failed=1
    return 1
  fi

  # --skip-verification: allowed, but the skip is named explicitly in the log.
  rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$ctx" && UBS_INSTALLER_BINARY_BASE="http://127.0.0.1:$port" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$shim:/usr/bin:/bin:$home/.local/bin" SHELL=/bin/bash \
    "$INSTALLER" --non-interactive --skip-verification --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks \
      --skip-version-check --no-path-modify --install-dir "$home/.local/bin") >"$ctx/install-skip.log" 2>&1 || rc=$?
  kill "$http_pid" 2>/dev/null || true
  if ! grep -q 'Skipping checksum verification for app-x86_64-unknown-linux-gnu.zip' "$ctx/install-skip.log"; then
    echo "[FAIL] --skip-verification did not name the skipped verification (log: $ctx/install-skip.log)"
    grep -n -i 'verif' "$ctx/install-skip.log" | tail -n 10 || true
    tests_failed=1
    return 1
  fi
  echo "[PASS] verified_download"
}

test_local_requires_flag() {
  # A ./ubs in the current directory is never installed implicitly (bead E4):
  # without --local the installer ignores it and goes for the release (which
  # fails here because the artifact base points at a dead port); with --local
  # it installs exactly that file.
  echo "[TEST] local_requires_flag"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" proj="$ctx/proj" inst="$ctx/inst" log="$ctx/install.log"
  mkdir -p "$home/.local/bin" "$proj" "$inst"
  # Installer copied away from the checkout so the "repo checkout" rule does not apply.
  cp "$INSTALLER" "$inst/install.sh"
  printf '#!/usr/bin/env bash\n# Ultimate Bug Scanner (fake local runner for the installer test)\ncase "${1:-}" in --version) echo "UBS Meta-Runner v0.0.0-local-test";; *) echo "fake ubs: $*";; esac\nexit 0\n' >"$proj/ubs"
  chmod +x "$proj/ubs"

  local rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$proj" && UBS_ARTIFACT_BASE="http://127.0.0.1:9/dead" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$home/.local/bin:$PATH" SHELL=/bin/bash \
    bash "$inst/install.sh" --non-interactive --skip-ast-grep --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks \
      --skip-version-check --no-path-modify --install-dir "$home/.local/bin") >"$log" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ] || ! grep -q 'Ignoring ./ubs' "$log" || [ -e "$home/.local/bin/ubs" ]; then
    echo "[FAIL] ./ubs from the current directory was installed (or not ignored) without --local (exit $rc, log: $log)"
    grep -n -i -E 'ignoring|local file|installing' "$log" | tail -n 10 || true
    tests_failed=1
    return 1
  fi

  rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$proj" && UBS_ARTIFACT_BASE="http://127.0.0.1:9/dead" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$home/.local/bin:$PATH" SHELL=/bin/bash \
    bash "$inst/install.sh" --local --non-interactive --skip-ast-grep --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks \
      --skip-version-check --no-path-modify --install-dir "$home/.local/bin") >"$ctx/install-local.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! cmp -s "$proj/ubs" "$home/.local/bin/ubs"; then
    echo "[FAIL] --local did not install ./ubs from the current directory (exit $rc, log: $ctx/install-local.log)"
    tail -n 30 "$ctx/install-local.log" || true
    tests_failed=1
    return 1
  fi
  echo "[PASS] local_requires_flag"
}

test_uninstall_roundtrip() {
  # --uninstall must remove everything the installer wrote (bead F5): with
  # every agent faked, an easy-mode install followed by an uninstall leaves the
  # filesystem identical to the pre-install snapshot, except the rc backup the
  # uninstaller deliberately keeps.
  echo "[TEST] uninstall_roundtrip"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" proj="$ctx/proj" shim="$ctx/bin"
  mkdir -p "$home/.local/bin" "$home/.claude" "$home/.tabnine" "$home/.vscode/extensions/github.copilot-1.0.0" "$shim" \
    "$proj/.cursor" "$proj/.codex" "$proj/.gemini" "$proj/.windsurf" "$proj/.cline" "$proj/.opencode" "$proj/.continue"
  printf 'export PRE_EXISTING=1\n' >"$home/.bashrc"
  printf 'model: gpt-4o\n' >"$home/.aider.conf.yml"
  printf 'run = "npm start"\n' >"$proj/.replit"
  printf '# Cursor house rules\n\nBe terse.\n' >"$proj/.cursor/rules"
  (cd "$proj" && git init -q && git config user.email t@example.invalid && git config user.name t)
  cat >"$shim/crontab" <<'SHIM'
#!/usr/bin/env bash
case "${1:-}" in
  -l) [ -f "$CRONTAB_SHIM_FILE" ] && cat "$CRONTAB_SHIM_FILE"; exit 0 ;;
  -)  cat >"$CRONTAB_SHIM_FILE"; exit 0 ;;
  -r) rm -f "$CRONTAB_SHIM_FILE"; exit 0 ;;
  *)  exit 1 ;;
esac
SHIM
  chmod +x "$shim/crontab"

  snapshot() {
    (cd "$ctx" && find home proj -type f | LC_ALL=C sort | while IFS= read -r f; do cksum "$f"; done)
  }
  local before after
  before="$(snapshot)"

  local rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  # The install dir is deliberately NOT on PATH so the installer also writes
  # its PATH block and alias into ~/.bashrc, which the uninstall must strip.
  (cd "$proj" && CRONTAB_SHIM_FILE="$ctx/crontab.txt" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$shim:$PATH" SHELL=/bin/bash \
    "$INSTALLER" --easy-mode --skip-ast-grep --skip-ripgrep --skip-jq --skip-typos --skip-doctor \
      --skip-version-check --install-dir "$home/.local/bin") >"$ctx/install.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[FAIL] easy-mode install exited $rc (log: $ctx/install.log)"
    tail -n 40 "$ctx/install.log" || true
    tests_failed=1
    return 1
  fi
  # The install must actually have written the integrations we are about to remove.
  local written=0 f
  for f in "$home/.local/bin/ubs" "$proj/.claude/hooks/on-file-write.sh" "$proj/.claude/settings.json" \
    "$proj/.codex/rules/ubs.md" "$proj/.gemini/rules" "$proj/.continue/config.json" "$proj/.github/copilot-instructions.md" \
    "$proj/.git/hooks/pre-commit" "$ctx/crontab.txt" "$home/.config/ubs/session.md"; do
    [ -f "$f" ] && written=$((written + 1))
  done
  if [ "$written" -lt 10 ] || ! grep -q 'UBS Quick Reference' "$proj/.cursor/rules" || ! grep -q 'Ultimate Bug Scanner' "$home/.aider.conf.yml" || ! grep -q 'Ultimate Bug Scanner' "$home/.bashrc"; then
    echo "[FAIL] install did not write the expected integrations ($written/10 files; log: $ctx/install.log)"
    tests_failed=1
    return 1
  fi

  rc=0
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  (cd "$proj" && CRONTAB_SHIM_FILE="$ctx/crontab.txt" UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" \
    HOME="$home" PATH="$shim:$home/.local/bin:$PATH" SHELL=/bin/bash \
    "$INSTALLER" --uninstall --non-interactive --skip-version-check --install-dir "$home/.local/bin") >"$ctx/uninstall.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[FAIL] --uninstall exited $rc (log: $ctx/uninstall.log)"
    tail -n 40 "$ctx/uninstall.log" || true
    tests_failed=1
    return 1
  fi
  after="$(snapshot)"
  local diff_out
  diff_out="$(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | grep -E '^[<>]' | grep -v 'home/.bashrc.pre-uninstall-backup' || true)"
  if [ -n "$diff_out" ]; then
    echo "[FAIL] filesystem differs from the pre-install snapshot after --uninstall:"
    printf '%s\n' "$diff_out"
    echo "--- uninstall log tail ---"
    tail -n 30 "$ctx/uninstall.log" || true
    tests_failed=1
    return 1
  fi
  if [ -f "$ctx/crontab.txt" ] && grep -q 'Ultimate Bug Scanner' "$ctx/crontab.txt"; then
    echo "[FAIL] cron job survived --uninstall"
    tests_failed=1
    return 1
  fi
  echo "[PASS] uninstall_roundtrip"
}

test_dry_run_touches_nothing() {
  # README promises --dry-run audits without touching disk (bead F6): no lock
  # directory, no ~/.local/bin, no session.md, no hook or rule files.
  echo "[TEST] dry_run_touches_nothing"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" proj="$ctx/proj" log="$ctx/dry-run.log"
  mkdir -p "$home/.claude" "$proj/.cursor"
  printf 'export PRE_EXISTING=1\n' >"$home/.bashrc"
  snapshot() {
    (cd "$ctx" && find home proj | LC_ALL=C sort; find home proj -type f | LC_ALL=C sort | while IFS= read -r f; do cksum "$f"; done)
  }
  local before after
  before="$(snapshot)"
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  local rc=0
  (cd "$proj" && UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" PATH="/usr/bin:/bin" SHELL=/bin/bash \
    "$INSTALLER" --dry-run --non-interactive --skip-version-check) >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[FAIL] --dry-run exited $rc (log: $log)"
    tail -n 30 "$log" || true
    tests_failed=1
    return 1
  fi
  after="$(snapshot)"
  if [ "$before" != "$after" ]; then
    echo "[FAIL] --dry-run changed the filesystem:"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | grep -E '^[<>]' || true
    tests_failed=1
    return 1
  fi
  if [ -e /tmp/ubs-install.lock ]; then
    echo "[FAIL] --dry-run left /tmp/ubs-install.lock behind"
    rm -rf /tmp/ubs-install.lock 2>/dev/null || true
    tests_failed=1
    return 1
  fi
  if ! grep -q 'Would' "$log"; then
    echo "[FAIL] --dry-run log shows no planned actions (log: $log)"
    tests_failed=1
    return 1
  fi
  echo "[PASS] dry_run_touches_nothing"
}

test_stale_lock_recovered() {
  # A lock left by a killed installer (recorded PID no longer running) must
  # not block the next install (bead F6).
  echo "[TEST] stale_lock_recovered"
  local ctx
  ctx="$(mktemp_dir)"
  tmpdirs+=("$ctx")
  local home="$ctx/home" log="$ctx/install.log"
  mkdir -p "$home"
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  mkdir -p /tmp/ubs-install.lock
  # A PID that cannot be running: the max pid + 1 style value is not portable,
  # so use a child that has already exited.
  local dead_pid
  dead_pid="$(bash -c 'echo $$')"
  printf '%s\n' "$dead_pid" >/tmp/ubs-install.lock/pid
  # Invoked directly: run_installer clears the lock itself before every run.
  mkdir -p "$home/.local/bin"
  local rc=0
  (UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" PATH="$home/.local/bin:$PATH" SHELL=/bin/bash \
    "$INSTALLER" --non-interactive --skip-version-check --skip-ast-grep --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks --no-path-modify --install-dir "$home/.local/bin") >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || [ ! -x "$home/.local/bin/ubs" ]; then
    echo "[FAIL] install with a stale lock present failed (exit $rc, log: $log)"
    tail -n 20 "$log" || true
    tests_failed=1
    return 1
  fi
  if ! grep -q 'Removing stale installer lock' "$log"; then
    echo "[FAIL] installer did not report recovering the stale lock (log: $log)"
    tests_failed=1
    return 1
  fi
  if [ -e /tmp/ubs-install.lock ]; then
    echo "[FAIL] lock directory left behind after the run"
    rm -rf /tmp/ubs-install.lock 2>/dev/null || true
    tests_failed=1
    return 1
  fi
  # A live lock (this shell's PID) must still block.
  mkdir -p /tmp/ubs-install.lock
  printf '%s\n' "$$" >/tmp/ubs-install.lock/pid
  rc=0
  (UBS_INSTALLER_WORKDIR="$ctx/work.${RANDOM}${RANDOM}" HOME="$home" SHELL=/bin/bash \
    "$INSTALLER" --non-interactive --skip-version-check --skip-ast-grep --skip-ripgrep --skip-jq --skip-typos --skip-doctor --skip-hooks --no-path-modify --install-dir "$home/.local/bin") >"$ctx/blocked.log" 2>&1 || rc=$?
  rm -rf /tmp/ubs-install.lock 2>/dev/null || true
  if [ "$rc" -eq 0 ] || ! grep -q 'already in progress' "$ctx/blocked.log"; then
    echo "[FAIL] a live lock did not block the installer (exit $rc, log: $ctx/blocked.log)"
    tests_failed=1
    return 1
  fi
  echo "[PASS] stale_lock_recovered"
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
test_agent_detection
test_verified_download
test_local_requires_flag
test_uninstall_roundtrip
test_dry_run_touches_nothing
test_stale_lock_recovered
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
