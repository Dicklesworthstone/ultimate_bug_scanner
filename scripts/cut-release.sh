#!/usr/bin/env bash
# Cut a UBS release in one step so the version string, the checksum tables and
# the tag can never drift apart (the recurring "version-tag checksum drift"
# issues #83/#86/#97 were all caused by doing these by hand in the wrong order).
#
#   scripts/cut-release.sh <version> [--dry-run] [--no-commit] [--allow-dirty] [--yes]
#
# Steps (see docs/release.md):
#   1. sanity: semver, tag not taken, clean tree on main (unless --allow-dirty)
#   2. bump VERSION, UBS_VERSION in ubs, the README version badge
#   3. regenerate MODULE_CHECKSUMS/HELPER_CHECKSUMS (in ubs) and SHA256SUMS
#   4. roll CHANGELOG.md: "## [Unreleased]" becomes "## [v<version>] - <date> [Release]"
#      and a fresh empty Unreleased section is inserted above it
#   5. verify: checksum scripts, bash -n, ./ubs --version
#   6. commit and annotated tag v<version>; requires --yes or an interactive
#      confirmation, never pushes, prints the push commands
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

usage() {
  sed -n '2,/^set -Eeuo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

VERSION_NEW=""
DRY_RUN=0
NO_COMMIT=0
ALLOW_DIRTY=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --no-commit) NO_COMMIT=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
    *) VERSION_NEW="$arg" ;;
  esac
done

if [[ -z "$VERSION_NEW" ]]; then usage >&2; exit 2; fi
if [[ ! "$VERSION_NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "error: '$VERSION_NEW' is not a semantic version (X.Y.Z or X.Y.Z-rc1)" >&2
  exit 2
fi
TAG="v$VERSION_NEW"
VERSION_OLD="$(tr -d '\r\n' < VERSION)"
TODAY="$(date -u +%Y-%m-%d)"

say() { printf '%s\n' "$*"; }
plan() { printf '  %s %s\n' "$([[ $DRY_RUN -eq 1 ]] && echo 'would' || echo '->')" "$*"; }

# 1. Sanity -------------------------------------------------------------------
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "error: tag $TAG already exists" >&2
  exit 1
fi
if [[ "$VERSION_NEW" == "$VERSION_OLD" ]]; then
  echo "error: VERSION is already $VERSION_OLD" >&2
  exit 1
fi
branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "main" && $ALLOW_DIRTY -eq 0 ]]; then
  echo "error: releases are cut from main (on '$branch'); pass --allow-dirty to override" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain --untracked-files=no)" && $ALLOW_DIRTY -eq 0 ]]; then
  echo "error: working tree has uncommitted changes; commit them first or pass --allow-dirty" >&2
  git status --short --untracked-files=no >&2
  exit 1
fi
if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
  echo "error: CHANGELOG.md has no '## [Unreleased]' section to roll into $TAG" >&2
  exit 1
fi

say "Cutting release $TAG (from $VERSION_OLD) on $branch in $ROOT_DIR"
plan "VERSION: $VERSION_OLD -> $VERSION_NEW"
plan "ubs: UBS_VERSION=\"$VERSION_NEW\""
plan "README.md: version badge -> $VERSION_NEW"
plan "regenerate MODULE_CHECKSUMS/HELPER_CHECKSUMS and SHA256SUMS"
plan "CHANGELOG.md: [Unreleased] -> [$TAG] - $TODAY [Release] (+ new empty Unreleased)"
if [[ $NO_COMMIT -eq 0 ]]; then
  plan "git commit + annotated tag $TAG"
fi
if [[ $DRY_RUN -eq 1 ]]; then
  say "dry run: nothing changed"
  exit 0
fi
# Committing and tagging is the one irreversible step; it needs a deliberate
# yes. A release script that gets run by accident (wrong directory, a broken
# shell chain) must stop here with nothing modified.
if [[ $NO_COMMIT -eq 0 && $ASSUME_YES -eq 0 ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Commit and tag $TAG in $ROOT_DIR? [y/N] " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
      say "aborted: nothing changed"
      exit 1
    fi
  else
    echo "error: refusing to commit and tag without --yes when stdin is not a terminal (use --dry-run to preview, --no-commit to only stage the changes)" >&2
    exit 1
  fi
fi

# 2. Bump version strings --------------------------------------------------------
# All rewrites are checked before any file is written, so a pattern that fails
# to match leaves the tree exactly as it was (no half-bumped state).
python3 - "$VERSION_NEW" <<'PY'
import re, sys
new = sys.argv[1]
edits = [
    ("ubs", r'^UBS_VERSION="[^"]+"$', f'UBS_VERSION="{new}"'),
    # pre-release versions contain a hyphen (5.4.0-rc1), so match up to "-blue.svg"
    ("README.md", r"badge/version-.+?-blue\.svg", f"badge/version-{new}-blue.svg"),
]
pending = []
for path, pattern, repl in edits:
    text = open(path, encoding="utf-8").read()
    text2, n = re.subn(pattern, repl, text, flags=re.M)
    if n != 1:
        raise SystemExit(f"{path}: expected 1 replacement for {pattern!r}, got {n}; nothing written")
    pending.append((path, text2))
pending.append(("VERSION", new + "\n"))
for path, text in pending:
    open(path, "w", encoding="utf-8").write(text)
PY

# 3. Checksums -------------------------------------------------------------------
bash scripts/update_checksums.sh >/dev/null
bash scripts/update_sha256sums.sh >/dev/null

# 4. Roll the changelog ------------------------------------------------------------
python3 - "$TAG" "$TODAY" <<'PY'
import sys
tag, today = sys.argv[1], sys.argv[2]
path = "CHANGELOG.md"
text = open(path, encoding="utf-8").read()
header = "## [Unreleased]"
idx = text.index(header)
rolled = (
    text[:idx]
    + "## [Unreleased]\n\n_No changes yet._\n\n---\n\n"
    + f"## [{tag}] - {today} [Release]"
    + text[idx + len(header):]
)
open(path, "w", encoding="utf-8").write(rolled)
PY

# 5. Verify ------------------------------------------------------------------------
bash -n ubs install.sh
bash scripts/verify_checksums.sh >/dev/null
bash scripts/verify_sha256sums.sh >/dev/null
if ! ./ubs --version | grep -q "v$VERSION_NEW"; then
  echo "error: ./ubs --version does not report $VERSION_NEW" >&2
  exit 1
fi
say "verified: checksums, SHA256SUMS, ubs --version -> $(./ubs --version)"

# 6. Commit + tag -------------------------------------------------------------------
if [[ $NO_COMMIT -eq 1 ]]; then
  say "changes staged in the working tree (--no-commit); review with: git diff"
  exit 0
fi
git add VERSION ubs README.md SHA256SUMS CHANGELOG.md
git commit -q -m "chore(release): bump version to $VERSION_NEW" \
  -m "VERSION, UBS_VERSION, the README badge, MODULE_CHECKSUMS/HELPER_CHECKSUMS and SHA256SUMS regenerated together by scripts/cut-release.sh so the $TAG tag matches main byte for byte."
git tag -a "$TAG" -m "UBS $TAG"
say "committed and tagged $TAG (not pushed). Next:"
say "  git push origin main --tags        # triggers .github/workflows/release.yml"
say "  scripts/check-version-tag-drift.sh # should report all modules/helpers match $TAG"
