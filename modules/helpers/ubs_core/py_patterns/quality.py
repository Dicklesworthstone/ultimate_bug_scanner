"""ubs_core.py_patterns.quality — categories 8, 9, 12, 14, 15, 22, 23 (bead 0xjg.5).

Faithful ports of the legacy rg pipelines in modules/ubs-python.sh:
- CATEGORY 8 FUNCTION & SCOPE (11351-11389): mutable default arguments,
  functions with >6 parameters, nested function declarations. The missing-
  returns heuristic (11383-11389) needs two project-wide counts and lives in
  ubs_core.py_detectors.missing_returns instead.
- CATEGORY 9 PARSING (11458-11463): string concatenation with `+` next to a
  quote. The json.loads heredoc is ubs_core.py_detectors.json_loads.
- CATEGORY 12 PERFORMANCE & MEMORY (11540-11562): string concat / re.compile /
  I/O inside loops.
- CATEGORY 14 CODE QUALITY MARKERS (11589-11615): TODO/FIXME/HACK/XXX.
  NOTE is measured for the legacy breakdown display only and never feeds the
  total, so it is not in the regex. The warning>20 / info>10 / info>0 ladder
  carries three legacy titles ("Significant technical debt" / "Moderate
  technical debt" / "Minimal technical debt"); like js.markers.todo-family,
  the titles merge into one neutral record-stream title.
- CATEGORY 15 REGEX & STRING SAFETY (11626-11637): nested quantifiers
  (ReDoS), dynamic re.compile from a bare variable.
- CATEGORY 22 PACKAGING (11887-11889): editable installs / local file:// refs.
  The requirements.txt unpinned-lines check (11881-11885) greps
  $PROJECT_DIR/requirements.txt directly — a file the v2 list never contains
  (.txt is outside INCLUDE_EXT) — and is a documented v2 divergence.
- CATEGORY 23 NOTEBOOK HYGIENE (11900-11902): embedded notebook outputs.

Equivalence notes:
- All sources are GREP_RN/GREP_RNI (ERE), never line-anchored unless the
  pattern itself had `^`; `[^)]`-style classes gain `\n` exclusions so a
  whole-text finditer cannot cross legacy line boundaries.
- Loop pipelines (`rg 'for...' | grep -A3 'X' | grep -w 'X'`) count exactly
  the lines containing BOTH the loop header and X, so they become
  MULTILINE-anchored composites; one line yields one match (count_lines
  counts lines). The `-w` filters keep their word-boundary semantics as
  lookarounds (`x+=1` without spaces never matched legacy either).
- Nested-defs: legacy stages 2+3 (`grep -A2 -E '^[[:space:]]+def[[:space:]]'`
  over path:line:text output) could never match — rg prefixes every line with
  `path:` — so the legacy check was dead and the info finding never fired.
  The port restores the evident intent (indented `def` lines).
- `^-e[[:space:]]+` in category 22 was equally dead behind the `path:` prefix;
  MULTILINE restores it for list-scoped requirement-like files.
- cat 9's counter was plain `wc -l` (no ubs:ignore strip) while the engine
  always skips marker lines — same accepted divergence class as the js port.
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── Category 8: FUNCTION & SCOPE ISSUES ─────────────────────────────────
    Pattern(
        category=8,
        rule_id="py.functions.mutable-default",
        title="Mutable default arguments",
        regex=re.compile(
            r"def[ \t]+[A-Za-z_][A-Za-z0-9_]*\([^)\n]*=[ \t]*(?:\[\]|\{\}|set\(\))[^)\n]*\)"
        ),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=8,
        rule_id="py.functions.high-param-count",
        title="Functions with >6 parameters",
        # Six commas inside the parens = >=7 parameters; `[^)]*,` x6 mirrors
        # the legacy repetition (commas may sit inside the span).
        regex=re.compile(
            r"def[ \t]+[A-Za-z_][A-Za-z0-9_]*\((?:[^)\n]*,){6}[^)\n]*[,)]"
        ),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=8,
        rule_id="py.functions.nested-defs",
        title="Nested functions - verify closures and lifetimes",
        # Intent of the (dead) pipeline: indented `def name(` lines.
        regex=re.compile(r"^[ \t]+def[ \t]+[A-Za-z_][A-Za-z0-9_]*\(", re.MULTILINE),
        thresholds=((10, "info"),),
    ),
    # ── Category 9: PARSING & TYPE CONVERSION ───────────────────────────────
    Pattern(
        category=9,
        rule_id="py.parsing.string-concat-plus",
        title="String concatenation with +",
        regex=re.compile(r"\+[ \t]*['\"]|['\"][ \t]*\+"),
        thresholds=((5, "info"),),
        exclude_regex=re.compile(r"\+\+|[+\-]="),  # legacy `grep -v -E '\+\+|[+\-]='`
    ),
    # ── Category 12: PERFORMANCE & MEMORY ───────────────────────────────────
    Pattern(
        category=12,
        rule_id="py.perf.string-concat-loop",
        title="String concatenation in loops",
        # Line holds a `for|while ... :` header AND a word-bounded `+=`.
        regex=re.compile(
            r"^(?=.*(?:for|while)[ \t]+.*:)(?=.*(?<![A-Za-z0-9_])\+=(?![A-Za-z0-9_]))",
            re.MULTILINE,
        ),
        thresholds=((8, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="py.perf.re-compile-loop",
        title="Regex compiled in loop",
        # Line holds a `for|while ... :` header AND a word-bounded re.compile.
        regex=re.compile(
            r"^(?=.*(?:for|while)[ \t]+.*:)(?=.*(?<![A-Za-z0-9_])re\.compile(?![A-Za-z0-9_]))",
            re.MULTILINE,
        ),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="py.perf.io-in-loop",
        title="I/O in loops",
        # Legacy stage 1 is a bare substring `for|while`; keep the looseness.
        regex=re.compile(
            r"^(?=.*(?:for|while))(?=.*(?:open\(|read\(|write\(|requests\.))",
            re.MULTILINE,
        ),
        thresholds=((5, "warning"),),
    ),
    # ── Category 14: CODE QUALITY MARKERS ───────────────────────────────────
    Pattern(
        category=14,
        rule_id="py.code-quality.tech-debt",
        title="Technical debt markers",
        # NOTE: breakdown-only in legacy, never in the total. RNI = -i.
        regex=re.compile(r"TODO|FIXME|HACK|XXX", re.IGNORECASE),
        thresholds=((20, "warning"), (10, "info"), (0, "info")),
        case_insensitive=True,
    ),
    # ── Category 15: REGEX & STRING SAFETY ──────────────────────────────────
    Pattern(
        category=15,
        rule_id="py.regex.nested-quantifiers",
        title="Potential catastrophic regex",
        regex=re.compile(r"\([^)\n]*\+[^)\n]*\)\+|\([^)\n]*\*[^)\n]*\)\+"),
        thresholds=((3, "warning"),),
    ),
    Pattern(
        category=15,
        rule_id="py.regex.dynamic-compile",
        title="Dynamic regex construction",
        regex=re.compile(r"re\.compile\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)"),
        thresholds=((3, "info"),),
    ),
    # ── Category 22: PACKAGING & CONFIG HYGIENE ─────────────────────────────
    Pattern(
        category=22,
        rule_id="py.packaging.editable-local",
        title="Editable/local dependency references",
        # No legacy description (bare print_finding title only).
        regex=re.compile(r"^-e[ \t]+|file:/", re.MULTILINE),
        thresholds=((0, "info"),),
    ),
    # ── Category 23: NOTEBOOK HYGIENE ───────────────────────────────────────
    Pattern(
        category=23,
        rule_id="py.notebooks.outputs-embedded",
        title="Notebooks contain outputs",
        regex=re.compile(r'"outputs":[ \t]*\[[ \t]*\{'),
        thresholds=((5, "info"),),
    ),
]
