"""ubs_core.ruby_patterns — ports of the legacy ubs-ruby.sh rg pipelines.

Every module exposes ``PATTERNS: list[Pattern]``. Regexes are line-scoped
translations of the legacy GREP_RN/GREP_RNI EREs; negated character classes
keep explicit ``\\n`` exclusions so whole-file matching cannot drift across
lines the way rg never could. ``grep -A3`` context windows are encoded as
bounded cross-line regexes (py_patterns.flow precedent); the three-tier
count ladders split into sibling patterns sharing a regex, disambiguated by
``max_count`` (the first matching tier wins, like the legacy if/elif chain).
"""
