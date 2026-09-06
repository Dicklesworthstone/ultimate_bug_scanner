"""ubs_core.csharp_patterns.security_rg — cat 8 rg subset.

Legacy: category_8_security's five ripgrep checks (2889-2935). The heredoc
detectors and the taint analyzers cover the rest of cat 8; the orchestrator
runs everything in the legacy call order (weak crypto → randomness detector →
TLS callback → shell process → SQL concat → secrets → archive → path
traversal → open redirect → header injection → outbound URL).
"""
from __future__ import annotations

import re

from ubs_core.csharp_patterns._table import P

# Legacy $shell_proc_pattern (ubs-csharp.sh 2910) with [[:space:]]
# transliterated to [ \t] (identical for single-line matching).
_SHELL_PROC = (
    r'\b(Process\.Start|new[ \t]+ProcessStartInfo)[ \t]*\([ \t]*"(cmd([.]exe)?|powershell([.]exe)?|pwsh([.]exe)?|sh|bash)"'
    r'[ \t]*,[ \t]*"(/?[cC]|-[cC]|-[Cc]ommand|-[Ee]ncoded[Cc]ommand)'
    r'|\bFileName[ \t]*=[ \t]*"(cmd([.]exe)?|powershell([.]exe)?|pwsh([.]exe)?|sh|bash)"'
)

PATTERNS = [
    P(
        category=8, rule_id="cs.pattern.weak-crypto", seq=310,
        label="Weak crypto",
        text="Weak crypto (MD5/SHA1) ({n})",
        regex=re.compile(r'\b(MD5|SHA1)\.Create\s*\('),
        severity="critical",
    ),
    P(
        category=8, rule_id="cs.pattern.tls-validation-disabled", seq=330,
        label="TLS validation disabled",
        text="TLS validation disabled via ServerCertificateCustomValidationCallback => true ({n})",
        regex=re.compile(r'ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true'),
        severity="critical",
    ),
    P(
        category=8, rule_id="cs.pattern.process-shell-launch", seq=340,
        label="Process shell launch",
        text="Shell interpreter launched via Process API ({n}) - pass argv directly or strictly validate input",
        regex=re.compile(_SHELL_PROC),
        severity="critical",
    ),
    P(
        category=8, rule_id="cs.pattern.sql-concat", seq=350,
        label="SQL concat",
        text="SQL string concatenation patterns ({n}) - prefer parameterized queries",
        regex=re.compile(r'\b(SELECT|UPDATE|DELETE|INSERT)\b.*\+\s*'),
        severity="warning",
    ),
    P(
        category=8, rule_id="cs.pattern.hardcoded-secrets", seq=360,
        label="Hardcoded secret",
        text="Possible hardcoded secrets ({n}) - rotate + move to secret store",
        regex=re.compile(r'\b(api[_-]?key|secret|password|token)\b\s*=\s*"[^"]{8,}"'),
        severity="critical",
    ),
]
