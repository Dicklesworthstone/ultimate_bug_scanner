#!/usr/bin/env python3
"""Run contract conformance harness (bead A8)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
QUALITY_DIR = REPO_ROOT / "test-suite" / "quality"
sys.path.insert(0, str(QUALITY_DIR))

import contract_conformance  # noqa: E402

if __name__ == "__main__":
    sys.exit(contract_conformance.main())
