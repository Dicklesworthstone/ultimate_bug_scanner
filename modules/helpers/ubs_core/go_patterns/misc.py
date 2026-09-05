"""ubs_core.go_patterns.misc — categories 9/10/12/14/15 regex checks (bead 0xjg.6).

Faithful ports of the legacy rg pipelines in modules/ubs-golang.sh:
- CATEGORY 9 (7504-7565): weak crypto census (7510). The InsecureSkipVerify
  and exec-shell checks are AST-gated composites — computed_checks.
- CATEGORY 10 (7570-7585): unsafe/reflect census.
- CATEGORY 12 (7604-7651): toolchain/replace directives (7642/7646).
- CATEGORY 14 (7674-7689): fmt.* print census >50 (7680), logging secrets
  (7684, grep -i).
- CATEGORY 15 (7691-7712): ctx not-first-param heuristic (7701-7707).
"""
from __future__ import annotations

import re

from ubs_core.go_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=9,
        rule_id="go.security.weak-crypto",
        title="Weak crypto primitives detected - use SHA-256/512, AES-GCM, etc.",
        # legacy grep_count_scoped "md5|sha1|rc4" (7510)
        regex=re.compile(r"md5|sha1|rc4"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=10,
        rule_id="go.reflection-unsafe.unsafe-usage",
        title="unsafe usage present - verify invariants and alignment",
        # legacy grep_count_scoped "import[[:space:]]+\"unsafe\"|unsafe\." (7576)
        regex=re.compile(r'import[ \t]+"unsafe"|unsafe\.'),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=10,
        rule_id="go.reflection-unsafe.reflect-usage",
        title="reflect usage present - consider generics or interfaces",
        # legacy grep_count_scoped "\breflect\." (7580)
        regex=re.compile(r"\breflect\."),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="go.build.toolchain-directive",
        title="toolchain directive present",
        # legacy grep_count_scoped "^[[:space:]]*toolchain[[:space:]]+go[0-9]+\.[0-9]+" (7642)
        regex=re.compile(r"(?m)^[ \t]*toolchain[ \t]+go[0-9]+\.[0-9]+"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=12,
        rule_id="go.build.replace-directives",
        title="replace directives present - validate dev overrides not shipped",
        # legacy grep_count_scoped "^[[:space:]]*replace[[:space:]]+" (7646)
        regex=re.compile(r"(?m)^[ \t]*replace[ \t]+"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=14,
        rule_id="go.logging.heavy-fmt",
        title="Heavy fmt.* logging - consider structured logging",
        # legacy grep_count_scoped "fmt\.Print(f|ln)?\(" with >50 info (7680)
        regex=re.compile(r"fmt\.Print(f|ln)?\("),
        thresholds=((50, "info"),),
    ),
    Pattern(
        category=14,
        rule_id="go.logging.sensitive-data",
        title="Possible logging of sensitive data",
        # legacy grep_count_scoped_i (7684)
        regex=re.compile(r"log\.(Print|Printf|Println|Fatal|Panic).*?(password|secret|token|authorization|bearer)"),
        case_insensitive=True,
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=15,
        rule_id="go.style.ctx-not-first-param",
        title="Place ctx context.Context first param",
        # legacy pipeline 7701-7707: rg -e "^func..." | grep -v "(ctx context.Context"
        # The legacy grep -v is BRE, so `+` is a LITERAL plus there and the
        # exclusion never fires on real code — reproduced byte-faithfully
        # (an ERE-correct exclusion would drop legacy findings on fixtures).
        regex=re.compile(
            r"(?m)^func[ \t]*(\([^)]+\)[ \t]*)?[A-Za-z_][A-Za-z0-9_]*\([^)]*context\.Context"
        ),
        exclude_regex=re.compile(r"\(ctx[ \t]\+context\.Context"),
        thresholds=((0, "info"),),
    ),
]
