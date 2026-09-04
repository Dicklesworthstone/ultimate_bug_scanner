"""ubs_core.js_patterns.proto_vars — categories 3 and 13 (bead 0xjg.4 wave).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 3 ARRAY & COLLECTION SAFETY (4072-4119): index arithmetic,
  .length arithmetic, mutation during iteration, sparse arrays,
  chained .length without existence checks.
- CATEGORY 13 VARIABLE & SCOPE ISSUES, rg parts (10320-10626): var
  declarations (rg FALLBACK variant — legacy prefers ast `var $X`),
  variable shadowing (heuristic regex for the ast-only
  `let $VAR = $$$; $$$ { let $VAR = $$$ }` pattern — legacy has no rg
  fallback, so expect undercount vs ast-grep).

Deliberately NOT ported (per legacy semantics):
- "const reassignment attempts" (10614-10616): legacy prints a "good"
  line, never a finding — no count to reproduce.
- "Unused variables (heuristic)" (10618-10624): ast-grep-primary
  (`const $VAR = $$$`), no rg fallback — skipped.
- "Global variable pollution" (10346-10606): bespoke inline Python
  scanner, not an rg pipeline — out of scope for rg ports.

Porting notes:
- POSIX [[:space:]] becomes [ \\t\\v\\f\\r]: the engine feeds whole-file
  text to re.finditer, and grep is line-based, so \\s (which crosses
  newlines) would invent cross-line matches the legacy never counted.
- The mutation pipeline (4098-4099) collapses exactly to a single-line
  conjunction: stage 2 (`grep -A3 mutation`) only emits stage-1 lines
  matching mutation plus 3 context lines; stage 3 re-filters for
  mutation keywords, and any surviving context line would itself have
  matched stage 2. Net: lines containing an iteration keyword AND a
  mutation call, expressed here as a two-directional conjunction (no
  word boundaries in the legacy EREs — kept verbatim).
- `var` declarations use `(?m)^` because legacy grep anchors per line.
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

# POSIX [[:space:]] minus newline — grep can never match across lines.
_SP = r"[ \t\v\f\r]"

PATTERNS: list[Pattern] = [
    # ── CATEGORY 3: ARRAY & COLLECTION SAFETY ─────────────────────────────
    Pattern(
        category=3,
        rule_id="js.proto-object.index-arithmetic",
        # legacy warning title: "Array index arithmetic - verify bounds"
        # legacy info tier (1..12): "Array offset access - review bounds checking"
        title="Array index arithmetic",
        regex=re.compile(r"\[[A-Za-z_][A-Za-z0-9_]*" + _SP + r"*[+-]" + _SP + r"*[0-9]+\]"),
        thresholds=((12, "warning"), (0, "info")),
    ),
    Pattern(
        category=3,
        rule_id="js.proto-object.length-arithmetic",
        title="Array.length in calculations",
        regex=re.compile(
            r"\.length" + _SP + r"*[+\-/*]|[+\-/*]" + _SP + r"*[A-Za-z_]*\.length"
        ),
        thresholds=((15, "info"),),
    ),
    Pattern(
        category=3,
        rule_id="js.proto-object.mutation-during-iteration",
        title="Possible array mutation during iteration",
        regex=re.compile(
            r"(?:forEach|for[ \t]*\(|for[ \t]+of|map|filter)"
            r".*(?:push|splice|shift|unshift|pop)"
            r"|(?:push|splice|shift|unshift|pop)"
            r".*(?:forEach|for[ \t]*\(|for[ \t]+of|map|filter)"
        ),
        thresholds=((5, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="js.proto-object.sparse-array",
        title="Sparse array creation detected",
        regex=re.compile(r"Array\([0-9]+\)|new" + _SP + r"+Array\([0-9]+\)"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=3,
        rule_id="js.proto-object.chained-length",
        title="Chained .length access without null checks",
        regex=re.compile(r"\.[A-Za-z_][A-Za-z0-9_]*\.length"),
        thresholds=((15, "info"),),
        exclude_regex=re.compile(r"if|Array\.isArray|\?\."),
    ),
    # ── CATEGORY 13: VARIABLE & SCOPE ISSUES (rg parts) ───────────────────
    Pattern(
        category=13,
        rule_id="js.vars.var-declarations",
        # rg FALLBACK variant (10333); legacy prefers ast-grep `var $X`.
        title="Using 'var' instead of let/const",
        regex=re.compile(r"(?m)^[ \t]*var[ \t]+[A-Za-z_$][A-Za-z0-9_$]*"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=13,
        rule_id="js.vars.shadowing",
        # Legacy is ast-only: `let $VAR = $$$; $$$ { let $VAR = $$$ }` —
        # no rg fallback exists. Single-line backreference heuristic for
        # the same shape (outer `let X = ...;` then a block redeclaring
        # `let X`); undercounts the ast-grep count on multi-line code.
        title="Potential variable shadowing",
        regex=re.compile(
            r"\blet[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b"
            r"[^;\n]*;[^{\n]*\{[^}\n]*\blet[ \t]+\1\b"
        ),
        thresholds=((3, "warning"),),
    ),
]
