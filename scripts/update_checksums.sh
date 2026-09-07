#!/usr/bin/env bash
set -e
# Wrapper to run the python update script using the project venv if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Ensure we are in the root
cd "$ROOT_DIR" || exit 1

if [[ -x ".venv/bin/python3" ]]; then
    # Prefer an existing project venv if present (avoids uv re-creating it).
    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python3 scripts/update_checksums.py
elif command -v uv >/dev/null 2>&1; then
    # Run without discovering the project/workspace so uv doesn't create or mutate
    # the repo-local `.venv` while we're just updating pinned checksums.
    PYTHONDONTWRITEBYTECODE=1 uv run --no-project --script scripts/update_checksums.py
else
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/update_checksums.py
fi
