"""ubs_core.cpp_patterns — Pattern-table ports of the legacy ubs-cpp.sh rg pipelines.

Every module exposes ``PATTERNS: list[Pattern]`` (see ubs_core.cpp_scan).
Pattern semantics mirror the legacy shell exactly: DISTINCT matching lines
project-wide, severity resolved once per pattern via threshold-descending
ladders, `ubs:ignore` marker lines dropped, legacy `grep -v` post-filters
expressed as ``exclude_regex``, and legacy `if count == 0` info fallbacks
expressed as ``zero_finding`` synthetic records (no source location).
"""
