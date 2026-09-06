"""ubs_core.csharp_patterns.foundations — cat 1 (exceptions & nullability).

Legacy: category_1_exceptions_nullability (ubs-csharp.sh 1192-1228). The
type-narrowing half of cat 1 is the narrowing_csharp analyzer (run by the
orchestrator between the nullable-disable and throw-Exception checks).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

PATTERNS = [
    P(
        category=1, rule_id="cs.pattern.null-forgiving", seq=10,
        label="Null-forgiving operator (!)",
        text="null-forgiving operator usage (!.) - review nullability assumptions ({n})",
        regex=re.compile(r'[A-Za-z_][A-Za-z0-9_]*\s*![\.\[]'),
        severity="warning",
    ),
    P(
        category=1, rule_id="cs.pattern.nullable-disable", seq=20,
        label="#nullable disable",
        text="'#nullable disable' found ({n}) - may hide nullability bugs",
        regex=re.compile(r'^\s*#nullable\s+disable\b'),
        severity="warning",
    ),
    P(
        category=1, rule_id="cs.pattern.throw-new-exception", seq=30,
        label="throw new Exception",
        text="throw new Exception(...) ({n}) - consider more specific exception types",
        regex=re.compile(r'\bthrow\s+new\s+Exception\s*\('),
        severity="info",
    ),
]
