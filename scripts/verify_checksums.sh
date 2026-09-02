#!/usr/bin/env bash
# Verify that module checksums in ubs script match actual module files
# This MUST pass before any tests run

set -euo pipefail

# Change to project root directory
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Verifying module checksums..."

# Extract checksums from ubs script
declare -A EXPECTED_CHECKSUMS
while IFS='=' read -r key value; do
  if [[ $key =~ \[([a-z]+)\] ]]; then
    lang="${BASH_REMATCH[1]}"
    # Remove quotes and whitespace
    checksum=$(echo "$value" | sed "s/['\"]//g" | tr -d ' ')
    EXPECTED_CHECKSUMS[$lang]=$checksum
  fi
done < <(sed -n '/^declare -A MODULE_CHECKSUMS=/,/^)/p' ubs | grep '^\s*\[')

# Extract helper checksums from ubs script
declare -A EXPECTED_HELPER_CHECKSUMS
helper_key_re="\\[[[:space:]]*['\\\"]([^'\\\"]+)['\\\"][[:space:]]*\\]"
while IFS='=' read -r key value; do
  if [[ $key =~ $helper_key_re ]]; then
    rel="${BASH_REMATCH[1]}"
    checksum=$(echo "$value" | sed "s/['\"]//g" | tr -d ' ')
    EXPECTED_HELPER_CHECKSUMS[$rel]=$checksum
  fi
done < <(sed -n '/^declare -A HELPER_CHECKSUMS=/,/^)/p' ubs | grep '^\s*\[')

# Verify each module
FAILED=0
for module in modules/ubs-*.sh; do
  if [[ ! -f "$module" ]]; then
    continue
  fi
  
  # Extract language from filename
  lang=$(basename "$module" | sed 's/ubs-//;s/\.sh$//')
  
  # Calculate actual checksum
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$module" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$module" | awk '{print $1}')
  else
    echo -e "${RED}ERROR: No checksum tool found (sha256sum or shasum required)${NC}"
    exit 1
  fi
  
  expected="${EXPECTED_CHECKSUMS[$lang]:-MISSING}"
  
  if [[ "$actual" != "$expected" ]]; then
    echo -e "${RED}✗ CHECKSUM MISMATCH: $module${NC}"
    echo -e "  Expected: $expected"
    echo -e "  Actual:   $actual"
    echo -e "${YELLOW}  Run: ./scripts/update_checksums.sh${NC}"
    FAILED=1
  else
    echo -e "${GREEN}✓ $module${NC}"
  fi
done

echo ""
echo "Verifying helper checksums..."
for helper in modules/helpers/* modules/lib/*.sh; do
  if [[ ! -f "$helper" ]]; then
    continue
  fi

  rel="${helper#modules/}"

  # Calculate actual checksum
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$helper" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$helper" | awk '{print $1}')
  else
    echo -e "${RED}ERROR: No checksum tool found (sha256sum or shasum required)${NC}"
    exit 1
  fi

  expected="${EXPECTED_HELPER_CHECKSUMS[$rel]:-MISSING}"

  if [[ "$expected" == "MISSING" ]]; then
    echo -e "${RED}✗ CHECKSUM MISSING: ubs HELPER_CHECKSUMS[$rel]${NC}"
    echo -e "  File:     $helper"
    echo -e "  Actual:   $actual"
    FAILED=1
  elif [[ "$actual" != "$expected" ]]; then
    echo -e "${RED}✗ CHECKSUM MISMATCH: $helper${NC}"
    echo -e "  Expected: $expected"
    echo -e "  Actual:   $actual"
    FAILED=1
  else
    echo -e "${GREEN}✓ $helper${NC}"
  fi
done

if [[ $FAILED -eq 1 ]]; then
  echo ""
  echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║  CHECKSUM VERIFICATION FAILED                              ║${NC}"
  echo -e "${RED}║                                                            ║${NC}"
  echo -e "${RED}║  Checksums do NOT match ubs script!                        ║${NC}"
  echo -e "${RED}║  This means the tool will fail for end users.              ║${NC}"
  echo -e "${RED}║                                                            ║${NC}"
  echo -e "${RED}║  Fix: update checksums in ubs                              ║${NC}"
  echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
  exit 1
fi

echo -e "${GREEN}All checksums verified!${NC}"
