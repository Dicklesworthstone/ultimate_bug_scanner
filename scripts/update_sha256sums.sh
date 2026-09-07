#!/usr/bin/env bash
set -euo pipefail

# Update SHA256SUMS with current release artifact checksums.
# Run this after modifying the ubs meta-runner or installer script.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR" || exit 1

for file in install.sh ubs; do
    if [[ ! -f "$file" ]]; then
        echo "Error: $file not found" >&2
        exit 1
    fi
done

# Compute SHA256 (portable: works on Linux and macOS)
compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        echo "Error: No SHA256 tool found (need sha256sum, shasum, or openssl)" >&2
        return 1
    fi
}

{
    echo "$(compute_sha256 install.sh)  install.sh"
    echo "$(compute_sha256 ubs)  ubs"
} > SHA256SUMS

echo "Updated SHA256SUMS:"
cat SHA256SUMS
