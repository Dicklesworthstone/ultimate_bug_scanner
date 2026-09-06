"""swift_patterns.errors_security — categories 5, 6 (rg subset), 7 (rg subset).

Category 6's heredoc detectors (archive extraction, the four request-taint
analyses, shell execution) and category 7's randomness heredoc live in
ubs_core.swift_detectors; this module carries only the plain rg pipelines plus
the Process residual derived check.
"""
from __future__ import annotations

from ubs_core.swift_scan import Pattern

PATTERNS = [
    # 5. ERROR HANDLING
    Pattern(5, "swift.errors.empty-catch", "Empty catch blocks",
            r"catch\s*\{\s*\}", ((0, "warning"),), show_samples=True),
    Pattern(5, "swift.errors.try-question", "Many try? sites - verify error handling strategy",
            r"try\?\s*[A-Za-z_\(]", ((30, "info"),)),
    Pattern(5, "swift.errors.crash-sites", "Crash sites",
            r"fatalError\(|preconditionFailure\(", ((0, "warning"),), show_samples=True),
    # 6. SECURITY — rg checks
    Pattern(6, "swift.security.trust-all", "URLSession delegate accepts any trust",
            r"didReceiveChallenge\(.*URLAuthenticationChallenge.*\)",
            ((0, "critical"),),
            include_regex=r"useCredential|URLCredential\(trust:", show_samples=True),
    Pattern(6, "swift.security.secrets", "Hardcoded secret lookalikes",
            r"(password|api_?key|secret|token)\s*[:=]\s*\"[^\"]+\"",
            ((0, "critical"),), case_insensitive=True, show_samples=True),
    Pattern(6, "swift.security.unarchiving", "Potentially unsafe deserialization",
            r"NSKeyedUnarchiver\.unarchiveObject\(with:|unarchiveTopLevelObjectWithData\(",
            ((0, "warning"),), show_samples=True),
    # 7. CRYPTO / HASHING — rg checks
    Pattern(7, "swift.crypto.commoncrypto", "Weak hashing use",
            r"CC_MD5|CC_SHA1", ((0, "warning"),), show_samples=True),
    Pattern(7, "swift.crypto.insecure", "CryptoKit Insecure algorithms",
            r"Insecure\.SHA1|Insecure\.MD5", ((0, "warning"),), show_samples=True),
    Pattern(7, "swift.crypto.ecb", "ECB mode used",
            r"kCCOptionECBMode", ((0, "warning"),), show_samples=True),
]


def _process_residual(ctx):
    """Legacy cat 6 tail: rg Process count minus the shell detector criticals."""
    from ubs_core.swift_detectors import shell_execution

    import re

    shell_critical = shell_execution.count_findings(ctx)
    total = 0
    samples = []
    regex = re.compile(r"Process\(|posix_spawn|system\(|popen\(")
    for path in ctx.files:
        text = ctx.text_of(path)
        seen = set()
        for match in regex.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            if line_no in seen:
                continue
            seen.add(line_no)
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            line_text = text[line_start:line_end]
            if "ubs:ignore" in line_text:
                continue
            total += 1
            if len(samples) < 5:
                samples.append({"path": str(path), "line": line_no})
    info_count = total - shell_critical
    if info_count > 0:
        yield {
            "rule": "swift.security.process-other",
            "category": 6,
            "path": samples[0]["path"] if samples else "",
            "line": samples[0]["line"] if samples else 0,
            "severity": "info",
            "count": info_count,
            "title": "Other Process/posix invocations present - validate fixed executables and arguments",
            "message": "Other Process/posix invocations present - validate fixed executables and arguments",
            "samples": samples,
        }


DERIVED = [_process_residual]
