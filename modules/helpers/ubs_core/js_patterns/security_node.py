r"""ubs_core.js_patterns.security_node — categories 7 and 18 (bead 0xjg.4).

Faithful ports of the legacy rg pipelines in modules/ubs-js.sh:
- CATEGORY 7 SECURITY (5568-5728, 5939-5946): eval(), new Function(),
  unsanitized innerHTML assignment, document.write, __proto__ /
  constructor.prototype pollution, window.open(_blank) without noopener.
- CATEGORY 18 NODE.JS I/O & MODULES (10756-10762) plus run_node_api_checks
  (712-751): fs.*Sync calls, dynamic require(), Express req.body without
  body-parser / without validation, sensitive console logs.

Four of the category 7 pipelines are ast-grep-primary in the legacy module
(eval 5579-5583, new Function 5598-5599, innerHTML 5612-5613, document.write
5711-5712); the rg FALLBACK variants are ported here per the v2 layering
(ast-grep coverage lives in the consolidated rule packs).

Deliberate divergences from the literal shell text (both verified by the
parity run, see bead report):
- The legacy `grep -Ev "^[[:space:]]*(//|/\*|\*)"` comment post-filters are
  INERT under rg mode: with `--with-filename --line-number` every output line
  is prefixed `path:line:` so the `^`-anchored filter never matches (grep -R -n
  behaves identically). Re-creating them as live per-line exclude_regex would
  under-count vs the legacy pipeline (e.g. `// Eval() with user input` comment
  lines), so they are not ported. Unanchored content filters
  (escapeHtml|sanitize|DOMPurify, noopener|noreferrer) ARE live in legacy and
  become exclude_regex.
- run_node_api_checks gates its findings on project-wide counts (express
  import present, zero parser / validator refs). The Pattern contract is
  per-line, so those gates are projected onto the req.body line itself;
  the projection is exact whenever the legacy gate passes, and the residual
  divergence is documented in the parity report.
- [^,\n]+ / [^)\n]* replace the legacy [^,]+ / [^)]* spans: rg is
  line-oriented and cannot match across newlines, while the engine's
  whole-text finditer can; the \n exclusion restores rg's line scope.
"""
from __future__ import annotations

import re

from ubs_core.js_scan import Pattern

PATTERNS: list[Pattern] = [
    # ── CATEGORY 7: SECURITY VULNERABILITIES ──────────────────────────────
    # ubs-js.sh 5577-5587: rg fallback "(^|[^\"'])[Ee]val[[:space:]]*\("
    # (ast-grep-primary 5579-5580). re.MULTILINE keeps the legacy per-line
    # `^` anchor under the engine's whole-text finditer.
    Pattern(
        category=7,
        rule_id="js.security.eval",
        title="eval() ALLOWS ARBITRARY CODE EXECUTION",
        regex=re.compile(r"(^|[^\"'])[Ee]val\s*\(", re.MULTILINE),
        thresholds=((0, "critical"),),
    ),
    # ubs-js.sh 5596-5602: rg fallback
    # "(^|[^\"'])\bnew[[:space:]]+Function[[:space:]]*\(" (ast-grep-primary 5598).
    Pattern(
        category=7,
        rule_id="js.security.new-function",
        title="new Function() enables code injection",
        regex=re.compile(r"(^|[^\"'])\bnew\s+Function\s*\(", re.MULTILINE),
        thresholds=((0, "critical"),),
    ),
    # ubs-js.sh 5610-5617: rg fallback "\.innerHTML[[:space:]]*="
    # (ast-grep-primary 5612) with the live `grep -v -E
    # "escapeHtml|sanitize|DOMPurify"` filter. Legacy ladder: >10 warning,
    # >0 info.
    Pattern(
        category=7,
        rule_id="js.security.innerhtml-unsanitized",
        title="innerHTML without sanitization - XSS risk",
        regex=re.compile(r"\.innerHTML\s*="),
        thresholds=((10, "warning"), (0, "info")),
        exclude_regex=re.compile(r"escapeHtml|sanitize|DOMPurify"),
    ),
    # ubs-js.sh 5709-5715: GREP_RNW "document\.write" (-w → \b…\b),
    # ast-grep-primary 5711.
    Pattern(
        category=7,
        rule_id="js.security.document-write",
        title="document.write() is deprecated & breaks SPAs",
        regex=re.compile(r"\bdocument\.write\b"),
        thresholds=((0, "critical"),),
    ),
    # ubs-js.sh 5723-5724: pure rg, no post-filters.
    Pattern(
        category=7,
        rule_id="js.security.prototype-pollution",
        title="Potential prototype pollution",
        regex=re.compile(
            r"(\.__proto__|\['__proto__'\]|\[\"__proto__\"\]|__proto__\s*:"
            r"|constructor\.prototype)"
        ),
        thresholds=((0, "critical"),),
    ),
    # ubs-js.sh 5940-5941: pure rg; legacy `grep -Ev
    # "noopener|noreferrer|ubs:ignore"` — the marker half is the engine's
    # built-in exclusion.
    Pattern(
        category=7,
        rule_id="js.security.window-open-blank",
        title="window.open(_blank) without noopener/noreferrer",
        regex=re.compile(r"window\.open\s*\([^,\n]+,\s*['\"]_blank['\"]"),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(r"noopener|noreferrer"),
    ),
    # ── CATEGORY 18: NODE.JS I/O & MODULES ────────────────────────────────
    # ubs-js.sh 10757: pure rg, warning >0.
    Pattern(
        category=18,
        rule_id="js.node.fs-sync",
        title="Synchronous fs.*Sync calls",
        regex=re.compile(r"fs\.[A-Za-z]+Sync\("),
        thresholds=((0, "warning"),),
    ),
    # ubs-js.sh 10761: pure rg, info >0.
    Pattern(
        category=18,
        rule_id="js.node.dynamic-require",
        title="Dynamic require/variable module path",
        regex=re.compile(
            r"require\(\s*\+|require\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\)"
        ),
        thresholds=((0, "info"),),
    ),
    # run_node_api_checks (ubs-js.sh 725-732): finding count is body_refs
    # (lines matching `req\.body`), gated on parser_refs == 0 project-wide.
    # Line-level projection: suppress req.body lines co-located with the
    # parser call (exact when the legacy gate passes).
    Pattern(
        category=18,
        rule_id="js.node.express-body-no-parser",
        title="req.body used without body parsing middleware",
        regex=re.compile(r"req\.body"),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(r"express\.(?:json|urlencoded)|bodyParser"),
        gate_regex=re.compile(
            r"require\(['\"]express['\"]\)|from ['\"]express['\"]|import express"
        ),
        suppress_when_regex=re.compile(r"express\.(?:json|urlencoded)|bodyParser"),
    ),
    # run_node_api_checks (ubs-js.sh 734-741): same body_refs count, gated on
    # validation_refs == 0 project-wide.
    Pattern(
        category=18,
        rule_id="js.node.express-body-no-validation",
        title="Request bodies lack explicit validation",
        regex=re.compile(r"req\.body"),
        thresholds=((0, "warning"),),
        exclude_regex=re.compile(
            r"express-validator|Joi|zod|celebrate|Ajv|yup|schema\.validate"
        ),
        gate_regex=re.compile(
            r"require\(['\"]express['\"]\)|from ['\"]express['\"]|import express"
        ),
        suppress_when_regex=re.compile(r"express\.(?:json|urlencoded)|bodyParser"),
    ),
    # run_node_api_checks (ubs-js.sh 743-750): pure rg, warning >0.
    Pattern(
        category=18,
        rule_id="js.node.sensitive-console-log",
        title="Sensitive request data logged to console",
        regex=re.compile(
            r"console\.(?:log|error)\s*\([^)\n]*"
            r"(?:password|token|creditCard|req\.body)"
        ),
        thresholds=((0, "warning"),),
    ),
]
