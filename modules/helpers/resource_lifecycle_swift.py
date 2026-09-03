#!/usr/bin/env python3
"""Thin entrypoint — logic lives in ubs_core.analyzers.lifecycle_swift (bead A2)."""
from ubs_core.analyzers.lifecycle_swift import main

if __name__ == "__main__":
    raise SystemExit(main())
