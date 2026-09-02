#!/usr/bin/env bash
# Enforce the invariant that issue #45 named: a runner pulled from `main`
# (whose UBS_VERSION is a "release-looking" number like 5.1.4) must be
# able to fetch its modules from the v$UBS_VERSION tag and have every
# module match the runner's embedded MODULE_CHECKSUMS table.
#
# Failure mode this catches: someone changes a module on `main`,
# regenerates MODULE_CHECKSUMS via `scripts/update_checksums.sh`, and
# pushes — but doesn't bump UBS_VERSION or cut a matching tag. End
# users who install via install.sh land on the new MODULE_CHECKSUMS
# table while their runner still fetches modules from the *old*
# v$UBS_VERSION tag, so `ubs doctor --fix` blows up with a checksum
# mismatch. The runtime now falls back to `main` (commit 6434e9a),
# but a CI gate is the only thing that prevents the drift in the
# first place.
#
# Exits 0 when every module/helper in MODULE_CHECKSUMS / HELPER_CHECKSUMS
# also exists at v$UBS_VERSION with the expected sha256, and 1
# otherwise. When the v$UBS_VERSION tag does not exist locally (e.g.
# pre-tag PR runs), the check is a no-op and exits 0 — the
# invariant is meaningful only against a published tag.
#
# Usage:
#   scripts/check-version-tag-drift.sh           # human-readable
#   scripts/check-version-tag-drift.sh --json    # machine-readable

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

OUTPUT_JSON=0
if [[ "${1:-}" == "--json" ]]; then
  OUTPUT_JSON=1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  if command -v shasum >/dev/null 2>&1; then
    # Compatibility shim for the external command: callers pass file
    # arguments or pipe stdin, exactly as with GNU sha256sum.
    # shellcheck disable=SC2120
    sha256sum() { shasum -a 256 "$@"; }
  else
    echo "ERROR: sha256sum or shasum required" >&2
    exit 2
  fi
fi

UBS_VERSION="$(grep -m1 '^UBS_VERSION=' ubs | cut -d'"' -f2)"
if [[ -z "$UBS_VERSION" ]]; then
  echo "ERROR: could not extract UBS_VERSION from ubs" >&2
  exit 2
fi

TAG="v${UBS_VERSION}"
if ! git rev-parse --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  if [[ "$OUTPUT_JSON" -eq 1 ]]; then
    printf '{"version":"%s","tag_exists":false,"drift":[],"status":"skipped"}\n' "$UBS_VERSION"
  else
    echo "tag ${TAG} does not exist locally — skipping drift check (no-op)"
  fi
  exit 0
fi

# Parse MODULE_CHECKSUMS from the runner the same way scripts/verify_checksums.sh does.
declare -A EXPECTED_MODULE_CHECKSUMS
while IFS='=' read -r key value; do
  if [[ $key =~ \[([a-z]+)\] ]]; then
    lang="${BASH_REMATCH[1]}"
    checksum=$(echo "$value" | sed "s/['\"]//g" | tr -d ' ')
    EXPECTED_MODULE_CHECKSUMS[$lang]=$checksum
  fi
done < <(sed -n '/^declare -A MODULE_CHECKSUMS=/,/^)/p' ubs | grep '^[[:space:]]*\[')

declare -A EXPECTED_HELPER_CHECKSUMS
helper_key_re="\\[[[:space:]]*['\\\"]([^'\\\"]+)['\\\"][[:space:]]*\\]"
while IFS='=' read -r key value; do
  if [[ $key =~ $helper_key_re ]]; then
    rel="${BASH_REMATCH[1]}"
    checksum=$(echo "$value" | sed "s/['\"]//g" | tr -d ' ')
    EXPECTED_HELPER_CHECKSUMS[$rel]=$checksum
  fi
done < <(sed -n '/^declare -A HELPER_CHECKSUMS=/,/^)/p' ubs | grep '^[[:space:]]*\[')

DRIFT_ENTRIES=()
DRIFT=0

verify_against_tag() {
  local kind="$1" name="$2" tag_path="$3" expected="$4"
  local tag_sha
  if ! tag_sha=$(git show "${TAG}:${tag_path}" 2>/dev/null | sha256sum | awk '{print $1}'); then
    DRIFT=1
    DRIFT_ENTRIES+=("${kind}|${name}|${expected}|MISSING_AT_TAG")
    return
  fi
  if [[ -z "$tag_sha" || "$tag_sha" == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]]; then
    # `git show` of a missing path can produce empty output (sha of empty
    # string). Treat it as missing so we don't silently pass on deletions.
    DRIFT=1
    DRIFT_ENTRIES+=("${kind}|${name}|${expected}|MISSING_AT_TAG")
    return
  fi
  if [[ "$tag_sha" != "$expected" ]]; then
    DRIFT=1
    DRIFT_ENTRIES+=("${kind}|${name}|${expected}|${tag_sha}")
  fi
}

for lang in "${!EXPECTED_MODULE_CHECKSUMS[@]}"; do
  verify_against_tag module "$lang" "modules/ubs-${lang}.sh" "${EXPECTED_MODULE_CHECKSUMS[$lang]}"
done

for rel in "${!EXPECTED_HELPER_CHECKSUMS[@]}"; do
  verify_against_tag helper "$rel" "modules/${rel}" "${EXPECTED_HELPER_CHECKSUMS[$rel]}"
done

if [[ "$OUTPUT_JSON" -eq 1 ]]; then
  printf '{"version":"%s","tag":"%s","tag_exists":true,"drift":[' "$UBS_VERSION" "$TAG"
  first=1
  for entry in "${DRIFT_ENTRIES[@]}"; do
    IFS='|' read -r kind name expected actual <<<"$entry"
    if [[ $first -eq 1 ]]; then
      first=0
    else
      printf ','
    fi
    printf '{"kind":"%s","name":"%s","expected_in_main":"%s","actual_at_tag":"%s"}' \
      "$kind" "$name" "$expected" "$actual"
  done
  if [[ $DRIFT -eq 0 ]]; then
    printf '],"status":"ok"}\n'
  else
    printf '],"status":"drift"}\n'
  fi
else
  echo "Checking module/helper checksums in main against tag ${TAG}..."
  if [[ $DRIFT -eq 0 ]]; then
    echo "  All ${#EXPECTED_MODULE_CHECKSUMS[@]} module(s) and ${#EXPECTED_HELPER_CHECKSUMS[@]} helper(s) match v${UBS_VERSION}."
  else
    echo "  DRIFT detected:" >&2
    for entry in "${DRIFT_ENTRIES[@]}"; do
      IFS='|' read -r kind name expected actual <<<"$entry"
      echo "    ${kind} ${name}: main expects ${expected}, ${TAG} has ${actual}" >&2
    done
    echo "" >&2
    echo "Fix one of:" >&2
    echo "  1. Bump UBS_VERSION in 'ubs' and cut a new tag whose modules match main." >&2
    echo "  2. Revert the module change on main so the runner stays compatible with v${UBS_VERSION}." >&2
    echo "  3. Cut/move tag ${TAG} to the current commit (only if no users are pinned to it)." >&2
  fi
fi

exit "$DRIFT"
