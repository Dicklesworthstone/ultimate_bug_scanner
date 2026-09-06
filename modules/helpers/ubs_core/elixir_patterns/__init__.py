"""ubs_core.elixir_patterns — ports of the legacy ubs-elixir.sh rg pipelines.

Every module exposes ``PATTERNS: list[Pattern]`` (see ubs_core.elixir_scan).
Regexes are line-scoped translations of the legacy GREP_RN/GREP_RNI EREs
(rg never matches across newlines, so ``\\s`` becomes ``[ \\t]`` and negated
classes gain explicit ``\\n`` exclusions); matching runs line by line with
``ubs:ignore`` marker lines dropped exactly like the legacy count_lines.
Legacy SUMS of separate pipelines use ``components``, legacy NET counts use
``diff_regexes``, legacy `grep -v/-E` output filters and count conjunctions
(``guarded < 5``) carry their legacy semantics verbatim.
"""
