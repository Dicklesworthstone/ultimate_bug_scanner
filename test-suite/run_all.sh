#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

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

echo "Checking generated AST rule inventory CLIs..."
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
    exit 1
  fi
  while IFS= read -r -d '' rule_file; do
    awk 'BEGIN{FS=":"}/^id:[[:space:]]*/{gsub(/^[[:space:]]*id:[[:space:]]*/,"");print;}' "$rule_file"
  done < <(find "$dump_dir" -maxdepth 1 -type f -name '*.yml' -print0) | sort -u >"$dumped_ids"
  local count
  count="$(wc -l <"$out" | awk '{print $1+0}')"
  if [[ "$count" -lt "$min_count" ]]; then
    echo "❌ $module --list-rules returned $count rule ids; expected at least $min_count" >&2
    exit 1
  fi
  if grep -Ev "^(${prefix_regex})\\.[A-Za-z0-9_.-]+$" "$out" >/dev/null; then
    echo "❌ $module --list-rules emitted non-rule output:" >&2
    grep -Env "^(${prefix_regex})\\.[A-Za-z0-9_.-]+$" "$out" >&2 || true
    exit 1
  fi
  if ! cmp -s "$out" "$dumped_ids"; then
    echo "❌ $module --list-rules output differs from dumped YAML rule ids:" >&2
    diff -u "$dumped_ids" "$out" >&2 || true
    exit 1
  fi
  local expected
  for expected in "$@"; do
    if ! grep -Fx "$expected" "$out" >/dev/null; then
      echo "❌ $module --list-rules missing expected id: $expected" >&2
      exit 1
    fi
  done
}

check_rule_list "ubs-js.sh" "js|ts|react|node|security" 30 \
  "js.eval-call" \
  "ts.non-null-assertion-chain" \
  "js.async.dangling-promise"
check_rule_list "ubs-golang.sh" "go" 60 \
  "go.exec-sh-c" \
  "go.sql.rows-err-not-checked" \
  "go.http-client-without-timeout"
check_rule_list "ubs-rust.sh" "rust" 70 \
  "rust.unwrap-call" \
  "rust.unwrap-unchecked" \
  "rust.tokio-spawn-no-handle"
echo ""

if command -v uv >/dev/null 2>&1; then
  uv run python quality/rule_quality_harness.py
  uv run python -m unittest discover -s quality -p 'test_*.py'
  uv run python ./run_manifest.py "$@"
  uv run python shareable/test_shareable_reports.py
  uv run python shareable/test_meta_runner_modes.py
  uv run python python/tests/test_resource_helper.py
  uv run python java/tests/test_resource_lifecycle_helper.py
  uv run python csharp/tests/test_helper_scanners.py
else
  echo "[warn] uv not found – falling back to system python3. Run 'uv sync --python 3.13' for the supported toolchain." >&2
  python3 quality/rule_quality_harness.py
  python3 -m unittest discover -s quality -p 'test_*.py'
  python3 ./run_manifest.py "$@"
  python3 shareable/test_shareable_reports.py
  python3 shareable/test_meta_runner_modes.py
  python3 python/tests/test_resource_helper.py
  python3 java/tests/test_resource_lifecycle_helper.py
  python3 csharp/tests/test_helper_scanners.py
fi
