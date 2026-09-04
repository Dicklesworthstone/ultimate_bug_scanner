"""ubs_core.js_patterns.fn_parse_perf — categories 8, 9, 12, 19 (bead 0xjg.4).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 8 FUNCTION & SCOPE (9533-9781, rg parts): >5 params, arrow
  implicit-return confusion, callback density, missing return. The legacy
  `grep -A10 "function"` stage is a no-op (every rg "function" line is itself
  re-emitted and re-matches), so the callback-hell pipeline reduces to a
  count of lines containing "function".
- CATEGORY 9 PARSING & TYPE CONVERSION (9782-9892, rg parts): parseInt
  without radix, parseFloat, new Date, unary + coercion. (The JSON.parse and
  block-function checks are python heredocs in the legacy module, not rg
  pipelines — out of scope for the Pattern layer.)
- CATEGORY 12 MEMORY LEAKS & PERFORMANCE (10255-10319): listener counts,
  listener/interval/timeout/object-URL acquire-vs-release gates, large
  inline arrays, DOM ops in loops, string concatenation in loops.
- CATEGORY 19 RESOURCE LIFECYCLE (10767-10777 -> run_resource_lifecycle_checks,
  rg-delta fallback at lines 680-705; the ast-grep rule pack is primary and
  emitted first when available): window/document listener, setInterval and
  MutationObserver acquire/release deltas.

Legacy acquire-vs-release gates compare TWO project-wide rg counts (e.g.
add_count > remove_count * 5). A single Pattern cannot reference a second
regex, so each gate is ported as an acquire-side pattern whose negative
lookahead requires that no release call occurs later in the same file
(`acquire(?![\\s\\S]*release)`): files whose acquire calls are followed by
matching release calls stay silent; files with trailing unreleased acquires
fire at the legacy severity. The exact project-wide ratio gate and diff
count are not reproducible from a single Pattern — divergences are
quantified in the bead report. `[^\\S\\n]` replaces legacy `[[:space:]]` to
keep rg's line scope (Python `\\s` would cross newlines when the engine
scans whole-file text).
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── CATEGORY 8: FUNCTION & SCOPE ISSUES ─────────────────────────────────
    # 9541-9547: rg "function" | grep -E "\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,
    # [^)]*," — line contains "function" AND a paren group with >= 6 commas
    # before the first ")". Anchored on "function" with a rest-of-line
    # lookahead; comma groups that appear before "function" on the line are
    # not matched (a single regex cannot scan backwards — rare shape).
    Pattern(
        category=8,
        rule_id="js.function-scope.high-param-count",
        title="Functions with >5 parameters",
        regex=re.compile(r"function(?=[^\n]*\((?:[^\n)]*,){6})"),
        thresholds=((3, "warning"),),
    ),
    # 9549-9554: rg "=>[[:space:]]*\{" | grep -v "return" (>5 -> info).
    # `grep -v "return"` is a plain substring filter (no word boundaries).
    Pattern(
        category=8,
        rule_id="js.function-scope.arrow-implicit-return",
        title="Arrow functions with { } - verify return intent",
        regex=re.compile(r"=>[^\S\n]*\{"),
        thresholds=((5, "info"),),
        exclude_regex=re.compile(r"return"),
    ),
    # 9556-9562: rg "function" | grep -A10 "function" | grep "function".
    # Every rg line already contains "function" and is re-emitted by -A10,
    # so the pipeline counts "function" lines (>40 -> info).
    Pattern(
        category=8,
        rule_id="js.function-scope.callback-density",
        title="Many callback-style functions detected",
        regex=re.compile(r"function"),
        thresholds=((40, "info"),),
    ),
    # 9773-9779: rg -e "^function [A-Za-z_]" vs GREP_RNW "return"; fires
    # (info, diff) only when decls > returns project-wide. The cross-regex
    # gate is inexpressible; ported as the declaration-side count.
    Pattern(
        category=8,
        rule_id="js.function-scope.missing-return",
        title="Some functions may lack return statements",
        regex=re.compile(r"^function [A-Za-z_]", re.MULTILINE),
        thresholds=((0, "info"),),
        # legacy two-count gate (decls > returns) approximated: silent when
        # any return statement exists project-wide (the common case).
        suppress_when_regex=re.compile(r"\breturn\b"),
    ),
    # ── CATEGORY 9: PARSING & TYPE CONVERSION BUGS ──────────────────────────
    # 9790-9798: rg "parseInt\(" | grep -Ev ",[[:space:]]*(10|16|8|2)\)".
    Pattern(
        category=9,
        rule_id="js.parsing.parseint-no-radix",
        title="parseInt without explicit radix",
        regex=re.compile(r"parseInt\("),
        thresholds=((0, "info"),),
        exclude_regex=re.compile(r",[^\S\n]*(?:10|16|8|2)\)"),
    ),
    # 9873-9877: rg "parseFloat\(" (>5 -> info).
    Pattern(
        category=9,
        rule_id="js.parsing.parsefloat-precision",
        title="parseFloat usage - verify precision requirements",
        regex=re.compile(r"parseFloat\("),
        thresholds=((5, "info"),),
    ),
    # 9879-9883: rg "new Date\(" (>5 -> info).
    Pattern(
        category=9,
        rule_id="js.parsing.new-date-validation",
        title="Date construction - verify input validation",
        regex=re.compile(r"new Date\("),
        thresholds=((5, "info"),),
    ),
    # 9885-9890: rg "\+[A-Za-z_][A-Za-z0-9_]*" | grep -v -E "\+\+|[+\-]="
    # (>10 -> info).
    Pattern(
        category=9,
        rule_id="js.parsing.unary-plus-coercion",
        title="Unary + for type conversion",
        regex=re.compile(r"\+[A-Za-z_][A-Za-z0-9_]*"),
        thresholds=((10, "info"),),
        exclude_regex=re.compile(r"\+\+|[+\-]="),
    ),
    # 10263-10266: unconditional info counts for add/removeEventListener
    # (legacy prints them even at 0; the engine stays silent at 0 matches).
    Pattern(
        category=12,
        rule_id="js.perf.listeners-attached",
        title="Event listeners attached",
        regex=re.compile(r"addEventListener"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="js.perf.listeners-removed",
        title="Event listeners removed",
        regex=re.compile(r"removeEventListener"),
        thresholds=((0, "info"),),
    ),
    # 10267-10270: warning when add_count > remove_count * 5 (project-wide).
    # Ported as attaches with no removeEventListener later in the file.
    Pattern(
        category=12,
        rule_id="js.perf.listener-imbalance",
        title="Listener imbalance - potential memory leak",
        regex=re.compile(r"addEventListener(?![\s\S]*removeEventListener)"),
        thresholds=((0, "warning"),),
    ),
    # 10272-10278: warning when interval_count > clear_count (project-wide).
    Pattern(
        category=12,
        rule_id="js.perf.interval-leak",
        title="setInterval without clearInterval - timer leak",
        regex=re.compile(r"setInterval\((?![\s\S]*clearInterval\()"),
        thresholds=((0, "warning"),),
    ),
    # 10280-10286: info when timeout_count > clear_timeout + 20.
    Pattern(
        category=12,
        rule_id="js.perf.timeout-uncleaned",
        title="Many setTimeout without clear",
        regex=re.compile(r"setTimeout\((?![\s\S]*clearTimeout\()"),
        thresholds=((0, "info"),),
    ),
    # 10288-10295: warning when object_url_count > revoke_url_count.
    Pattern(
        category=12,
        rule_id="js.perf.object-url-leak",
        title="Object URLs created without URL.revokeObjectURL",
        regex=re.compile(
            r"URL\.createObjectURL[^\S\n]*\((?![\s\S]*URL\.revokeObjectURL[^\S\n]*\()"
        ),
        thresholds=((0, "warning"),),
    ),
    # 10297-10301: rg "\[.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,.*,"
    # — a "[" followed by >= 16 commas later on the same line (>3 -> info).
    Pattern(
        category=12,
        rule_id="js.perf.large-inline-arrays",
        title="Large inline arrays - consider external file",
        regex=re.compile(r"\[(?:[^\n]*,){16}"),
        thresholds=((3, "info"),),
    ),
    # 10303-10310: rg "for|while" | grep -A5 -E DOM-ops | grep -E DOM-ops.
    # The -A5 stage runs on the already-filtered for/while stream, so every
    # stream line matching the DOM filter is itself a stage-2 match: the
    # context stage is a no-op and the pipeline counts lines containing
    # "for"/"while" AND a DOM op on the SAME line (>5 -> warning).
    Pattern(
        category=12,
        rule_id="js.perf.dom-ops-in-loops",
        title="DOM operations in loops - cache selectors",
        regex=re.compile(
            r"(?:for|while)(?=[^\n]*"
            r"(?:querySelector|getElementById|innerHTML|appendChild))"
        ),
        thresholds=((5, "warning"),),
    ),
    # 10312-10317: rg "for|while" | grep -A3 "+=" | grep -w "+=" (>8 -> info).
    # The -A3 context stage is a no-op for the same reason; counts lines
    # containing "for"/"while" AND a word-delimited "+=" on the SAME line.
    # grep -w requires "+=" to be delimited by non-word characters.
    Pattern(
        category=12,
        rule_id="js.perf.string-concat-in-loops",
        title="String concatenation in loops",
        regex=re.compile(r"(?:for|while)(?=[^\n]*(?<!\w)\+=(?!\w))"),
        thresholds=((8, "info"),),
    ),
    # ── CATEGORY 19: RESOURCE LIFECYCLE CORRELATION (rg-delta fallback) ─────
    # 680-687: (window|document).addEventListener vs .removeEventListener.
    Pattern(
        category=19,
        rule_id="js.resource-lifecycle.listener-delta",
        title="Event listeners missing removeEventListener",
        regex=re.compile(
            r"(?:window|document)\.addEventListener[^\S\n]*\("
            r"(?![\s\S]*(?:window|document)\.removeEventListener[^\S\n]*\()"
        ),
        thresholds=((0, "warning"),),
    ),
    # 689-696: setInterval vs clearInterval.
    Pattern(
        category=19,
        rule_id="js.resource-lifecycle.interval-delta",
        title="setInterval timers without clearInterval",
        regex=re.compile(
            r"setInterval[^\S\n]*\((?![\s\S]*clearInterval[^\S\n]*\()"
        ),
        thresholds=((0, "warning"),),
    ),
    # 698-705: new MutationObserver vs .disconnect().
    Pattern(
        category=19,
        rule_id="js.resource-lifecycle.observer-delta",
        title="MutationObserver without disconnect()",
        regex=re.compile(
            r"new[^\S\n]+MutationObserver(?![\s\S]*\.disconnect[^\S\n]*\()"
        ),
        thresholds=((0, "warning"),),
    ),
]
