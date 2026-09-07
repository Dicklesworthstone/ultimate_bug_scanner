#!/usr/bin/env bash
# Verify that SHA256SUMS matches the actual checksums of ubs and install.sh
# This script is called by git hooks and CI workflows to prevent checksum drift.
#
# Exit codes:
#   0 - All checksums match
#   1 - Checksum mismatch detected
#   2 - Missing required files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Compute SHA256 in a portable way
compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | awk '{print $NF}'
    else
        echo "Error: No SHA256 tool found" >&2
        return 1
    fi
}

cd "$ROOT_DIR" || exit 1

# Check required files exist
for file in ubs install.sh SHA256SUMS; do
    if [[ ! -f "$file" ]]; then
        echo -e "${RED}Error: $file not found${NC}" >&2
        exit 2
    fi
done

# Compute actual checksums
ACTUAL_UBS=$(compute_sha256 ubs)
ACTUAL_INSTALL=$(compute_sha256 install.sh)

# Extract expected checksums from SHA256SUMS (2>/dev/null suppresses error if malformed)
EXPECTED_UBS=$(grep '  ubs$' SHA256SUMS 2>/dev/null | awk '{print $1}' || echo "")
EXPECTED_INSTALL=$(grep '  install.sh$' SHA256SUMS 2>/dev/null | awk '{print $1}' || echo "")

MISMATCH=0

# Check ubs checksum
if [[ "$ACTUAL_UBS" != "$EXPECTED_UBS" ]]; then
    echo -e "${RED}MISMATCH: ubs${NC}"
    echo "  Expected: $EXPECTED_UBS"
    echo "  Actual:   $ACTUAL_UBS"
    MISMATCH=1
else
    echo -e "${GREEN}OK: ubs${NC}"
fi

# Check install.sh checksum
if [[ "$ACTUAL_INSTALL" != "$EXPECTED_INSTALL" ]]; then
    echo -e "${RED}MISMATCH: install.sh${NC}"
    echo "  Expected: $EXPECTED_INSTALL"
    echo "  Actual:   $ACTUAL_INSTALL"
    MISMATCH=1
else
    echo -e "${GREEN}OK: install.sh${NC}"
fi

if [[ "$MISMATCH" -eq 1 ]]; then
    echo ""
    echo -e "${YELLOW}To fix, run: ./scripts/update_checksums.sh${NC}"
    exit 1
fi

echo -e "${GREEN}All checksums verified!${NC}"
exit 0
