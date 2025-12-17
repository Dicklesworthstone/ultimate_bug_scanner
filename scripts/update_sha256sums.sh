#!/usr/bin/env bash
set -euo pipefail

# Update SHA256SUMS file with current ubs script checksum
# Run this after modifying the ubs meta-runner script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

if [[ ! -f "ubs" ]]; then
    echo "Error: ubs script not found" >&2
    exit 1
fi

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

CHECKSUM=$(compute_sha256 ubs)
echo "${CHECKSUM}  ubs" > SHA256SUMS

echo "Updated SHA256SUMS:"
cat SHA256SUMS
