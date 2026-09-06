"""ubs_core.ruby_patterns.regex_conc — categories 15, 16 and 17 rg subset (bead 0xjg.10).

Faithful ports of the legacy rg pipelines in modules/ubs-ruby.sh:
- CATEGORY 15 REGEX & STRING SAFETY (3285-3303): nested quantifiers,
  Regexp.new from variables.
- CATEGORY 16 CONCURRENCY & PARALLELISM (3307-3323 rg part): detached
  threads, Ractor usage. (run_async_error_checks is the consolidated pack
  rule ruby.async.thread-no-rescue, category-gated via ruby_rules.CATEGORY_MAP.)
- CATEGORY 17 RUBY/RAILS PRACTICALS (3427-3453 rg part): CSRF skip, permit!.
  (The frozen_string_literal pragma walk is a detector:
  ubs_core.ruby_detectors.frozen_string_literal.)
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 15: REGEX & STRING SAFETY ──────────────────────────────────
    Pattern(
        category=15,
        rule_id="ruby.regex.nested-quantifiers",
        title="Potential catastrophic regex",
        # legacy 3294: `\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\+`, warning >3,
        # "Use atomic groups or simplify patterns".
        regex=re.compile(r"\([^)\n]*\+[^)\n]*\)\+|\([^)\n]*\*[^)\n]*\)\+"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="ruby.regex.dynamic-regexp",
        title="Dynamic regex construction",
        # legacy 3300: `Regexp\.new\([[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\)`,
        # info >3, "Sanitize inputs or anchor carefully".
        regex=re.compile(r"Regexp\.new\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)"),
        thresholds=((3, "info"),),
    ),
    # ── Category 16: CONCURRENCY & PARALLELISM ──────────────────────────────
    Pattern(
        category=16,
        rule_id="ruby.concurrency.detached-threads",
        title="Detached threads",
        # legacy 3316: `Thread\.new\(` with `grep -E -v "\.join|\bjoin\b"`;
        # info >0, "Ensure lifecycle, join, or thread pool".
        regex=re.compile(r"Thread\.new\("),
        exclude_regex=re.compile(r"\.join|\bjoin\b"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=16,
        rule_id="ruby.concurrency.ractor",
        title="Ractor usage - verify isolation & shareable objects",
        # legacy 3321: `Ractor\.new\(`, info >0.
        regex=re.compile(r"Ractor\.new\("),
        thresholds=((0, "info"),),
    ),
    # ── Category 17: RUBY/RAILS PRACTICALS (rg part) ────────────────────────
    Pattern(
        category=17,
        rule_id="ruby.rails.csrf-skip",
        title="CSRF protections skipped in controllers",
        # legacy 3440: `skip_before_action[[:space:]]+:verify_authenticity_token`,
        # warning >0. (The identical rails.csrf-skip pack rule is a cat-18
        # passthrough that never joins totals — legacy quirk preserved.)
        regex=re.compile(r"skip_before_action[ \t]+:verify_authenticity_token"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=17,
        rule_id="ruby.rails.permit-bang",
        title="Strong params permit! found - review carefully",
        # legacy 3445: `\.permit!\b`. The \b after the non-word `!` can only
        # match when a word character follows — i.e. effectively never in
        # real code; the dead regex is preserved verbatim for parity.
        regex=re.compile(r"\.permit!\b"),
        thresholds=((0, "warning"),),
    ),
]
