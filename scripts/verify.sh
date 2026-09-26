#!/usr/bin/env bash
set -euo pipefail

# Authenticate one release manifest, then stage every executable the installer
# consumes. The downloaded installer must not re-fetch an unsigned manifest or
# install a different runner after its own signature has been checked.

info() { printf '→ %s\n' "$*"; }
ok() { printf '✓ %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage_error() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

usage() {
  cat <<'USAGE'
Usage: verify.sh [--version X.Y.Z|vX.Y.Z] [--insecure] [-- INSTALLER_ARGS...]

Authenticate SHA256SUMS, verify install.sh, ubs and git_safety_guard.py against
that same manifest, and install the verified local payload. The caller's
working directory is preserved for project hook setup. Missing signatures,
missing or ambiguous checksums, and different release versions fail closed.

Options:
  --version VERSION       Select an exact release, including prerelease tags.
  --install-args "ARGS"   Legacy whitespace-separated arguments (no shell eval).
  -- ARGS...              Pass installer arguments without splitting or eval.
  --insecure              Explicitly skip ALL signature and checksum checks.
  -h, --help              Show help without downloading or installing anything.

Environment:
  UBS_VERSION             Version; otherwise use the checkout's VERSION file.
                          A standalone verifier requires an explicit version.
  UBS_ARTIFACT_BASE       HTTPS mirror containing the selected release assets.
  UBS_MINISIGN_PUBKEY     Trusted minisign key; selects minisign when provided.
  UBS_VERIFY_WITH         minisign | cosign; default is cosign without a key.

Cosign requires this repository's release.yml certificate on the EXACT selected
vVERSION tag, issued by GitHub Actions. Minisign additionally binds the requested
version to the authenticated runner's literal UBS_VERSION declaration.
USAGE
}

normalize_version() { printf '%s' "${1#v}"; }
VERSION_FILE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/VERSION"
VERSION="${UBS_VERSION:-$(cat "$VERSION_FILE" 2>/dev/null || true)}"
MINISIGN_PUBKEY="${UBS_MINISIGN_PUBKEY:-}"
VERIFY_WITH="${UBS_VERIFY_WITH:-}"
INSECURE=0
INSTALL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 && -n "$2" ]] || usage_error '--version requires a value'
      VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --install-args)
      [[ $# -ge 2 ]] || usage_error '--install-args requires a value'
      legacy_args=()
      IFS=' ' read -r -a legacy_args <<<"$2" || true
      INSTALL_ARGS+=("${legacy_args[@]}"); shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --) shift; INSTALL_ARGS+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "Unknown flag: $1" ;;
  esac
done

VERSION="$(normalize_version "$VERSION")"
version_pattern='^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.+-]*)?$'
[[ "$VERSION" =~ $version_pattern ]] \
  || usage_error 'Select a release with --version X.Y.Z (or set UBS_VERSION)'
ARTIFACT_BASE="${UBS_ARTIFACT_BASE:-https://github.com/Dicklesworthstone/ultimate_bug_scanner/releases/download/v${VERSION}}"
ARTIFACT_BASE="${ARTIFACT_BASE%/}"
[[ "$ARTIFACT_BASE" == https://* && "$ARTIFACT_BASE" != *$'\n'* && "$ARTIFACT_BASE" != *$'\r'* ]] \
  || usage_error 'UBS_ARTIFACT_BASE must be an HTTPS release URL'
COSIGN_IDENTITY="https://github.com/Dicklesworthstone/ultimate_bug_scanner/.github/workflows/release.yml@refs/tags/v${VERSION}"
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

if [[ "$INSECURE" -eq 0 ]]; then
  [[ -z "${UBS_COSIGN_IDENTITY_RE:-}" ]] \
    || usage_error 'UBS_COSIGN_IDENTITY_RE is not supported: verification requires the exact release identity'
  for argument in "${INSTALL_ARGS[@]}"; do
    case "$argument" in
      --local|--insecure|--skip-verification)
        usage_error "$argument would bypass the authenticated release; use the verifier's explicit --insecure opt-out instead" ;;
    esac
  done
  if [[ -z "$VERIFY_WITH" ]]; then
    if [[ -n "$MINISIGN_PUBKEY" ]]; then VERIFY_WITH=minisign; else VERIFY_WITH=cosign; fi
  fi
  case "$VERIFY_WITH" in
    minisign)
      command -v minisign >/dev/null 2>&1 || die 'minisign is required for this verification path'
      [[ -n "$MINISIGN_PUBKEY" ]] || die 'UBS_MINISIGN_PUBKEY must contain a trusted minisign public key' ;;
    cosign)
      command -v cosign >/dev/null 2>&1 || die 'Install cosign for keyless verification, or configure minisign and UBS_MINISIGN_PUBKEY' ;;
    *) die "UBS_VERIFY_WITH must be minisign or cosign (got '$VERIFY_WITH')" ;;
  esac
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 \
    || die 'Need sha256sum, shasum, or openssl to verify payload digests'
fi
# curl is already a UBS runtime dependency. Restrict both the initial URL and
# redirects: a nominal HTTPS URL must not redirect an executable to HTTP/FTP.
command -v curl >/dev/null 2>&1 || die 'curl is required to download release artifacts'

mktemp_dir() {
  local base="${TMPDIR:-/tmp}"
  (umask 077; mktemp -d "${base%/}/ubs-verify.XXXXXXXX")
}
VERIFY_DIR="$(mktemp_dir)" || die 'Could not create private release staging directory'
cleanup() {
  # Only this invocation's randomly created directory is ever removed.
  [[ -n "${VERIFY_DIR:-}" && "$VERIFY_DIR" != / ]] || return 0
  rm -rf -- "$VERIFY_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fetch_asset() {
  local name="$1"
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 180 --retry 3 --retry-delay 1 --compressed \
    -o "$VERIFY_DIR/$name" "$ARTIFACT_BASE/$name" \
    || die "Failed to download release asset: $name"
}

compute_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

expected_digest() {
  # Fixed, flat asset names only. Accept GNU text/binary markers and CRLF, but
  # never pick the first of duplicate entries or tolerate a malformed digest.
  LC_ALL=C awk -v name="$1" '
    { sub(/\r$/, "") }
    $2 == name || $2 == "*" name || $2 == "./" name || $2 == "*./" name {
      count++
      if (NF != 2 || length($1) != 64 || $1 ~ /[^[:xdigit:]]/) bad = 1
      digest = tolower($1)
    }
    END { if (count != 1 || bad) exit 1; print digest }
  ' "$VERIFY_DIR/SHA256SUMS"
}

verify_asset() {
  local expected actual
  expected="$(expected_digest "$1")" || die "Missing, malformed or duplicate checksum entry: $1"
  actual="$(compute_sha256 "$VERIFY_DIR/$1")" || die "Could not hash release asset: $1"
  [[ "$expected" == "$actual" ]] || die "Checksum verification failed for $1"
  ok "Checksum verified: $1"
}

info "Version: $VERSION"
info "Release base: $ARTIFACT_BASE"
if [[ "$INSECURE" -eq 0 ]]; then
  fetch_asset SHA256SUMS
  case "$VERIFY_WITH" in
    minisign)
      fetch_asset SHA256SUMS.minisig
      minisign -Vm "$VERIFY_DIR/SHA256SUMS" -P "$MINISIGN_PUBKEY" \
        -x "$VERIFY_DIR/SHA256SUMS.minisig" >/dev/null \
        || die 'Signature verification failed for SHA256SUMS (minisign)' ;;
    cosign)
      fetch_asset SHA256SUMS.sigstore.json
      cosign verify-blob --bundle "$VERIFY_DIR/SHA256SUMS.sigstore.json" \
        --certificate-identity "$COSIGN_IDENTITY" \
        --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
        "$VERIFY_DIR/SHA256SUMS" >/dev/null \
        || die 'Signature verification failed for SHA256SUMS (cosign)' ;;
  esac
  ok "Release manifest authenticated with $VERIFY_WITH"
  # Validate all required entries before fetching any executable payload.
  for asset in install.sh ubs git_safety_guard.py; do
    expected_digest "$asset" >/dev/null || die "Missing, malformed or duplicate checksum entry: $asset"
  done
  for asset in install.sh ubs git_safety_guard.py; do
    fetch_asset "$asset"
    verify_asset "$asset"
  done
  runner_version="$(awk '/^UBS_VERSION=/ { sub(/\r$/, ""); count++; value=$0 }
    END { if (count != 1) exit 1; print value }' "$VERIFY_DIR/ubs")" \
    || die 'Authenticated runner has no unique literal UBS_VERSION declaration'
  case "$runner_version" in
    "UBS_VERSION=\"${VERSION}\""|"UBS_VERSION='${VERSION}'"|"UBS_VERSION=${VERSION}") ;;
    *) die "Authenticated runner does not match requested version $VERSION" ;;
  esac
  # The installer recognizes ubs + VERSION next to itself as an explicit local
  # release source. The hook is likewise taken from the authenticated copy.
  # Keep the caller's cwd so project hooks are not installed into this staging
  # directory, and never pass --local (which would prefer a planted cwd/ubs).
  printf '%s\n' "$VERSION" > "$VERIFY_DIR/VERSION"
  mkdir -p "$VERIFY_DIR/.claude/hooks"
  cp "$VERIFY_DIR/git_safety_guard.py" "$VERIFY_DIR/.claude/hooks/git_safety_guard.py"
else
  warn 'Explicit insecure mode: signature and checksum verification are disabled'
  fetch_asset install.sh
fi

ok 'Executing installer'
status=0
UBS_ARTIFACT_BASE="$ARTIFACT_BASE" UBS_NO_AUTO_UPDATE=1 \
  bash "$VERIFY_DIR/install.sh" "${INSTALL_ARGS[@]}" || status=$?
# Do not exec: the parent owns staging cleanup on both success and failure.
exit "$status"
