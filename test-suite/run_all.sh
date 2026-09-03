#!/usr/bin/env bash
# Runs every UBS test gate and reports ALL failures at the end instead of
# stopping at the first one (bead H2), so one CI run tells you whether a golden
# is merely stale, a fixture regressed, and the installer broke — not just the
# first of those. Checksum verification stays a hard stop: nothing else is
# meaningful when the modules do not match the runner.
set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR" || exit 1

DEFAULT_TMPDIR=""
if [[ -d /data/tmp && -w /data/tmp ]]; then
  DEFAULT_TMPDIR="/data/tmp/ubs-test-suite"
elif [[ -d /var/tmp && -w /var/tmp ]]; then
  DEFAULT_TMPDIR="/var/tmp/ubs-test-suite"
fi
if [[ -z "${TMPDIR:-}" || ! -d "$TMPDIR" || ! -w "$TMPDIR" ]]; then
  if [[ -n "$DEFAULT_TMPDIR" ]]; then
    mkdir -p "$DEFAULT_TMPDIR"
    export TMPDIR="$DEFAULT_TMPDIR"
  else
    unset TMPDIR TMP TEMP
  fi
fi
if [[ -n "${TMPDIR:-}" ]]; then
  export TMP="${TMP:-$TMPDIR}"
  export TEMP="${TEMP:-$TMPDIR}"
fi
if command -v uv >/dev/null 2>&1 && [[ -z "${UV_PROJECT_ENVIRONMENT:-}" ]]; then
  UV_PROJECT_ENVIRONMENT="${TMPDIR:-/tmp}/ubs-test-suite-uv"
  export UV_PROJECT_ENVIRONMENT
fi

# CRITICAL: Verify checksums BEFORE running tests
# This prevents deploying broken code where modules don't match checksums
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Verifying module checksums..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if ! ../scripts/verify_checksums.sh; then
  echo ""
  echo "❌ CHECKSUM VERIFICATION FAILED"
  echo "Tests will NOT run until checksums are fixed."
  exit 1
fi
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Running test suite..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Every gate runs through run_step: a failure is recorded and the next gate
# still runs. The summary at the end lists every failed step by name.
FAILED_STEPS=()
PASSED_STEPS=()

# hygiene-guard-begin
# Repository hygiene guard (bead H9). A test that writes into the checkout
# (2026-09-02: a contract check left findings.jsonl, report.html, report.json
# and summary.json at the repo root) must be named by the step that did it.
# After every step the untracked-file set is compared with the snapshot taken
# before it; new paths outside the allowed prefixes are reported. In CI (or
# with UBS_TEST_HYGIENE=strict) that fails the run; locally it only warns,
# because other agents create files in this checkout while the suite runs and
# a red gate for their files would blame the wrong actor. Nothing is deleted.
HYGIENE_ALLOWED_PREFIXES=("test-suite/artifacts/" "test-suite/goldens/" ".beads/")
HYGIENE_MODE="${UBS_TEST_HYGIENE:-}"
if [[ -z "$HYGIENE_MODE" ]]; then
  if [[ -n "${CI:-}" ]]; then HYGIENE_MODE=strict; else HYGIENE_MODE=warn; fi
fi
HYGIENE_ISSUES=()
HYGIENE_SNAPSHOT=""
hygiene_untracked(){
  # Untracked paths relative to the repository root, outside the allowed prefixes.
  local root prefix path allowed
  root="$(git rev-parse --show-toplevel 2>/dev/null)" || return 0
  git -C "$root" status --porcelain --untracked-files=all 2>/dev/null | awk '/^\?\? /{print substr($0, 4)}' | while IFS= read -r path; do
    allowed=0
    for prefix in "${HYGIENE_ALLOWED_PREFIXES[@]}"; do
      [[ "$path" == "$prefix"* ]] && allowed=1
    done
    [[ "$allowed" -eq 0 ]] && printf '%s\n' "$path"
  done | LC_ALL=C sort
}
hygiene_snapshot(){ HYGIENE_SNAPSHOT="$(hygiene_untracked)"; }
hygiene_check(){
  local step="$1" now new list
  now="$(hygiene_untracked)"
  new="$(LC_ALL=C comm -13 <(printf '%s\n' "$HYGIENE_SNAPSHOT") <(printf '%s\n' "$now") | sed '/^$/d')"
  HYGIENE_SNAPSHOT="$now"
  [[ -z "$new" ]] && return 0
  list="$(printf '%s' "$new" | tr '\n' ' ')"
  if [[ "$HYGIENE_MODE" == "strict" ]]; then
    echo "❌ [$step] left untracked files in the checkout (UBS_TEST_HYGIENE=strict): $list"
    HYGIENE_ISSUES+=("$step left untracked files: $list")
  else
    echo "⚠️  [$step] new untracked files appeared during this step (not deleted; UBS_TEST_HYGIENE=strict makes this fatal): $list"
    HYGIENE_ISSUES+=("$step (warning) new untracked files: $list")
  fi
  return 0
}
hygiene_snapshot
# hygiene-guard-end
run_step() {
  local name="$1"; shift
  local started=$SECONDS
  echo "▶ [$name] $*"
  if "$@"; then
    PASSED_STEPS+=("$name")
    echo "✅ [$name] PASS ($((SECONDS - started))s)"
  else
    local rc=$?
    FAILED_STEPS+=("$name (exit $rc)")
    echo "❌ [$name] FAIL (exit $rc, $((SECONDS - started))s)"
  fi
  hygiene_check "$name"
  echo ""
}

check_rule_list() {
  local module="$1"
  local prefix_regex="$2"
  local min_count="$3"
  shift 3
  local artifact_dir dump_dir dumped_ids out
  artifact_dir="$ROOT_DIR/artifacts/rule_inventory/${module%.sh}-$$"
  dump_dir="$artifact_dir/dump"
  dumped_ids="$artifact_dir/dumped-rule-ids.txt"
  out="$artifact_dir/list-rule-ids.txt"
  mkdir -p "$dump_dir"
  if ! "../modules/$module" --dump-rules="$dump_dir" --list-rules >"$out"; then
    echo "❌ $module --list-rules failed" >&2
    return 1
  fi
  while IFS= read -r -d '' rule_file; do
    awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$rule_file"
  done < <(find "$dump_dir" -maxdepth 1 -type f -name '*.yml' -print0) | LC_ALL=C sort -u >"$dumped_ids"
  local count
  count="$(wc -l <"$out" | awk '{print $1+0}')"
  if [[ "$count" -lt "$min_count" ]]; then
    echo "❌ $module --list-rules returned $count rule ids; expected at least $min_count" >&2
    return 1
  fi
  if grep -Ev "^(${prefix_regex})\\.[A-Za-z0-9_.-]+$" "$out" >/dev/null; then
    echo "❌ $module --list-rules emitted non-rule output:" >&2
    grep -Env "^(${prefix_regex})\\.[A-Za-z0-9_.-]+$" "$out" >&2 || true
    return 1
  fi
  if ! cmp -s "$out" "$dumped_ids"; then
    echo "❌ $module --list-rules output differs from dumped YAML rule ids:" >&2
    diff -u "$dumped_ids" "$out" >&2 || true
    return 1
  fi
  local expected
  for expected in "$@"; do
    if ! grep -Fx "$expected" "$out" >/dev/null; then
      echo "❌ $module --list-rules missing expected id: $expected" >&2
      return 1
    fi
  done
}

echo "Checking generated AST rule inventory CLIs..."
run_step rule-inventory-js check_rule_list "ubs-js.sh" "js|ts|react|node|security" 30 \
  "js.eval-call" \
  "ts.non-null-assertion-chain" \
  "js.async.dangling-promise"
run_step rule-inventory-go check_rule_list "ubs-golang.sh" "go" 60 \
  "go.exec-sh-c" \
  "go.sql.rows-err-not-checked" \
  "go.http-client-without-timeout"
run_step rule-inventory-rust check_rule_list "ubs-rust.sh" "rust" 70 \
  "rust.unwrap-call" \
  "rust.unwrap-unchecked" \
  "rust.tokio-spawn-no-handle"

if command -v uv >/dev/null 2>&1; then
  PY=(uv run python)
else
  echo "[warn] uv not found – falling back to system python3. Run 'uv sync --python 3.14' for the supported toolchain." >&2
  PY=(python3)
fi

run_step rule-quality-harness "${PY[@]}" quality/rule_quality_harness.py
run_step quality-unittests "${PY[@]}" -m unittest discover -s quality -p 'test_*.py'
run_step manifest "${PY[@]}" ./run_manifest.py "$@"
run_step shareable-reports "${PY[@]}" shareable/test_shareable_reports.py
run_step meta-runner-modes "${PY[@]}" shareable/test_meta_runner_modes.py
run_step cli-contract "${PY[@]}" shareable/test_cli_contract.py
run_step supply-chain "${PY[@]}" shareable/test_supply_chain.py
run_step skip-categories "${PY[@]}" shareable/test_skip_categories.py
run_step python-resource-helper "${PY[@]}" python/tests/test_resource_helper.py
run_step java-resource-lifecycle-helper "${PY[@]}" java/tests/test_resource_lifecycle_helper.py
run_step csharp-helper-scanners "${PY[@]}" csharp/tests/test_helper_scanners.py
run_step docs-claims "${PY[@]}" ../scripts/check_docs_claims.py

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SUMMARY: ${#PASSED_STEPS[@]} passed, ${#FAILED_STEPS[@]} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ ${#HYGIENE_ISSUES[@]} -gt 0 ]]; then
  echo "Repository hygiene (${HYGIENE_MODE}):"
  for issue in "${HYGIENE_ISSUES[@]}"; do
    echo "  • $issue"
  done
  if [[ "$HYGIENE_MODE" == "strict" ]]; then
    FAILED_STEPS+=("hygiene (${#HYGIENE_ISSUES[@]} step(s) wrote into the checkout)")
  fi
fi
if [[ ${#FAILED_STEPS[@]} -gt 0 ]]; then
  for step in "${FAILED_STEPS[@]}"; do
    echo "❌ $step"
  done
  echo ""
  echo "Golden mismatches print the exact regenerate command; fixture regressions print the case id."
  exit 1
fi
echo "✅ All test gates passed."
