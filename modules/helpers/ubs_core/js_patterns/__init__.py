"""ubs_core.js_patterns — regex category modules for the contract-v2 JS module (bead 0xjg.4).

Each submodule exports ``PATTERNS: list[Pattern]`` porting one cluster of the
legacy rg pipelines in modules/ubs-js.sh. ubs_core.js_scan aggregates them via
pkgutil — new cluster modules are picked up automatically.
"""
from __future__ import annotations
