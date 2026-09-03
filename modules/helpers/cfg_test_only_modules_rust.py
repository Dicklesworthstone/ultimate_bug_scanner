#!/usr/bin/env python3
"""Thin entrypoint — logic lives in ubs_core.analyzers.cfg_test_only_rust (bead A2)."""
from ubs_core.analyzers.cfg_test_only_rust import main

if __name__ == "__main__":
    raise SystemExit(main())
