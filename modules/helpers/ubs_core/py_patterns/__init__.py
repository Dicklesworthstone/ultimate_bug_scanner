"""ubs_core.py_patterns — Pattern-table ports of the legacy ubs-python.sh rg pipelines.

Every module exposes ``PATTERNS: list[Pattern]`` (see ubs_core.py_scan).
Pattern semantics mirror the legacy shell exactly: DISTINCT matching lines
project-wide, severity resolved once per pattern via threshold-descending
ladders, `ubs:ignore` marker lines dropped, legacy `grep -v` post-filters
expressed as ``exclude_regex``.
"""
