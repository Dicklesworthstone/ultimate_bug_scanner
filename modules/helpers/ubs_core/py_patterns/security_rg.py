"""ubs_core.py_patterns.security_rg — category 7 rg-pipeline subset (bead 0xjg.5).

Faithful ports of the simple rg pipelines inside CATEGORY 7 (modules/
ubs-python.sh 10958-11020, 11327-11329). The AST-heredoc detectors of the
same category live in ubs_core.py_detectors.*; the ast-grep pack overlaps
with several of these rules — legacy counted BOTH layers into totals, and so
does v2.

Legacy quirks preserved:
- eval/exec's `grep -Ev "^[[:space:]]*#"` post-filter was dead against rg's
  "path:line:code" output (the anchor can never match) — not reproduced.
- shell=True's `^[^#]*` anchor excludes comment-led source lines the same way
  it did against rg-prefixed output.
- yaml.load used to exclude lines mentioning `Loader=` (the one post-filter
  that worked against rg output). GH #102 replaced that with a regex that only
  matches single-argument calls: a positional Loader (`yaml.load(s,
  yaml.SafeLoader)`) is no longer a hit here, and every call that names a
  Loader is classified by ubs_core.py_detectors.unsafe_deserialization.
"""
from __future__ import annotations

import re

from ubs_core.py_scan import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        category=7,
        rule_id="py.security.eval-exec-usage",
        title="eval()/exec() present",
        regex=re.compile(r"(?<![A-Za-z0-9_])eval\(|(?<![A-Za-z0-9_])exec\("),
        thresholds=((0, "critical"),),
        exclude_regex=re.compile(r"pattern:|\bdef\s"),
    ),
    Pattern(
        category=7,
        rule_id="py.security.pickle-usage",
        title="Insecure pickle usage",
        regex=re.compile(r"(?<![A-Za-z0-9_])pickle\.(load|loads)\("),
        thresholds=((0, "critical"),),
        exclude_regex=re.compile(r"pattern:|\bdef\s"),
    ),
    Pattern(
        category=7,
        rule_id="py.security.yaml-load",
        title="yaml.load without SafeLoader",
        # GH #102: only a single-argument load / load_all call (no Loader,
        # keyword or positional) is a hit here. One nesting level of
        # parentheses is allowed inside the argument (a stream opened inline);
        # a call that supplies a Loader is classified by the AST detector
        # ubs_core.py_detectors.unsafe_deserialization instead.
        regex=re.compile(r"yaml\.load(?:_all)?\((?:[^(),\n]|\([^()\n]*\))*\)"),
        thresholds=((0, "critical"),),
        # `pattern:` keeps the ast-grep rule source (py_rules.py) out of the
        # self-scan; the old `Loader=` post-filter is subsumed by the regex.
        exclude_regex=re.compile(r"pattern:"),
    ),
    Pattern(
        category=7,
        rule_id="py.security.shell-true",
        title="Shell command injection risk",
        regex=re.compile(
            r"(?m)^[^#\n]*\b[A-Za-z_][A-Za-z0-9_.]*\([^#\n]*shell[ \t]*=[ \t]*True"
        ),
        thresholds=((0, "critical"),),
        exclude_regex=re.compile(r"pattern:"),
    ),
    Pattern(
        category=7,
        rule_id="py.security.os-system-shell",
        title="Shell command injection risk",
        regex=re.compile(r"os\.system\("),
        thresholds=((0, "critical"),),
        exclude_regex=re.compile(r"pattern:"),
    ),
    Pattern(
        category=7,
        rule_id="py.security.requests-verify-false",
        title="TLS verification disabled",
        regex=re.compile(r"requests\.[a-z]+\([^)]*verify[ \t]*=[ \t]*False"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="py.security.weak-hash",
        title="Weak hash usage",
        regex=re.compile(r"hashlib\.(md5|sha1)\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=7,
        rule_id="py.security.tempfile-mktemp-usage",
        title="Insecure tempfile.mktemp usage",
        regex=re.compile(r"tempfile\.mktemp\("),
        thresholds=((0, "critical"),),
    ),
]
