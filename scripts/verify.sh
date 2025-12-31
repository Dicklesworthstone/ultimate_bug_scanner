#!/usr/bin/env bash
set -euo pipefail

# Ultimate Bug Scanner – verification helper
# Fetches release checksums + signature, validates them with minisign, then
# verifies install.sh before executing it. Fails closed unless --insecure.

COLOR=1
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ] || [ "${TERM:-dumb}" = "dumb" ]; then COLOR=0; fi
if [ "$COLOR" -eq 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

info() { printf "%b %s\n" "${BLUE}→${RESET}" "$*"; }
ok()   { printf "%b %s\n" "${GREEN}✓${RESET}" "$*"; }
warn() { printf "%b %s\n" "${YELLOW}⚠${RESET}" "$*"; }
err()  { printf "%b %s\n" "${RED}✗${RESET}" "$*" >&2; }
die()  { err "$*"; exit 1; }

normalize_version() {
  local raw="${1:-}"
  raw="${raw#v}"
  printf '%s' "$raw"
}

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
    return 0
  fi
  return 1
}

VERSION_FILE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/VERSION"
VERSION_DEFAULT="5.0.3"
VERSION="$(normalize_version "${UBS_VERSION:-$(cat "$VERSION_FILE" 2>/dev/null || echo "$VERSION_DEFAULT")}")" \
  || VERSION="$VERSION_DEFAULT"

ARTIFACT_BASE_DEFAULT="https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/download/v${VERSION}"
ARTIFACT_BASE="${UBS_ARTIFACT_BASE:-$ARTIFACT_BASE_DEFAULT}"
MINISIGN_PUBKEY="${UBS_MINISIGN_PUBKEY:-}"  # Must be set; fails closed otherwise
INSECURE=0

usage() {
  printf "%bUsage%b: verify.sh [--version X.Y.Z|vX.Y.Z] [--insecure] [--install-args \"--easy-mode\"]\n" "$BOLD" "$RESET"
  cat <<'USAGE'

Actions:
  - Downloads SHA256SUMS and SHA256SUMS.minisig for the chosen version.
  - Verifies signature with minisign and the configured public key.
  - Verifies the checksum for install.sh.
  - Executes install.sh locally with any extra args you pass via --install-args.

Environment:
  UBS_VERSION            Override version (defaults to ./VERSION or 5.0.3).
  UBS_ARTIFACT_BASE      Override release base URL.
  UBS_MINISIGN_PUBKEY    Required minisign public key (base64 line from `minisign -G`).
USAGE
}

INSTALL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$(normalize_version "$2")"
      ARTIFACT_BASE="https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/download/v${VERSION}"
      shift 2
      ;;
    --install-args)
      IFS=' ' read -r -a INSTALL_ARGS <<<"$2"; shift 2 ;;
    --insecure)
      INSECURE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      err "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

if [ "$INSECURE" -eq 1 ]; then
  info "Insecure mode requested: skipping signature and checksum verification."
fi

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  die "Need curl or wget to download release artifacts."
fi

if [ "$INSECURE" -eq 0 ]; then
  command -v minisign >/dev/null 2>&1 || die "minisign is required for verification (install via your package manager)."
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 \
    || die "No SHA256 tool found (need sha256sum, shasum, or openssl)."
  if [ -z "$MINISIGN_PUBKEY" ]; then
    die "UBS_MINISIGN_PUBKEY is not set. Export the minisign public key or rerun with --insecure."
  fi
fi

mktemp_dir() {
  local base="${TMPDIR:-/tmp}"
  mktemp -d 2>/dev/null \
    || mktemp -d -t ubs-verify.XXXXXX 2>/dev/null \
    || mktemp -d "${base%/}/ubs-verify.XXXXXX" 2>/dev/null
}

TMPDIR="$(mktemp_dir)" || die "Failed to create temporary directory (mktemp -d)"
cleanup() {
  local dir="${TMPDIR:-}"
  [[ -n "$dir" && "$dir" != "/" ]] || return 0
  rm -rf "$dir" 2>/dev/null || true
}
trap cleanup EXIT

download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 --compressed -o "$out" "$url"
  else
    wget --https-only --secure-protocol=TLSv1_2 --tries=3 --waitretry=1 --timeout=20 -O "$out" "$url"
  fi
}

S_FILE="$TMPDIR/SHA256SUMS"
SIG_FILE="$TMPDIR/SHA256SUMS.minisig"
INSTALL_FILE="$TMPDIR/install.sh"

info "Version: $VERSION"
info "Release base: $ARTIFACT_BASE"

download "$ARTIFACT_BASE/SHA256SUMS" "$S_FILE"
download "$ARTIFACT_BASE/SHA256SUMS.minisig" "$SIG_FILE"
download "$ARTIFACT_BASE/install.sh" "$INSTALL_FILE"

if [ "$INSECURE" -eq 0 ]; then
  minisign -Vm "$S_FILE" -P "$MINISIGN_PUBKEY" -x "$SIG_FILE" >/dev/null \
    || die "Signature verification failed for SHA256SUMS"
  expected_sum="$(awk '$2=="install.sh"{print $1}' "$S_FILE" | head -n 1)"
  [ -n "${expected_sum:-}" ] || die "install.sh entry missing in checksum file"
  actual_sum="$(compute_sha256 "$INSTALL_FILE")" || die "No SHA256 tool found (need sha256sum, shasum, or openssl)."
  if [[ "$expected_sum" != "$actual_sum" ]]; then
    err "Checksum verification failed for install.sh"
    err "Expected: ${expected_sum}"
    err "Got:      ${actual_sum}"
    exit 1
  fi
  ok "Signature + checksum verified"
else
  warn "Skipping signature and checksum verification (insecure mode)."
fi

ok "Executing installer"
exec bash "$INSTALL_FILE" "${INSTALL_ARGS[@]}"
