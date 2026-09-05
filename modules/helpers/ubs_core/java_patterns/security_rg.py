"""ubs_core.java_patterns.security_rg — category 4 rg-pipeline subset (bead 0xjg.8).

The regex halves of the legacy security checks: SSL verification, weak hashes,
plain HTTP URLs, Java deserialization and the ProcessBuilder shell-interpreter
pattern (the kotlin-security-command manifest cases). The taint heredocs run
as analyzers/detectors (java.taint.*, java_detectors.*).
"""
from __future__ import annotations

import re

from ubs_core.java_scan import Pattern

# Verbatim legacy pb_shell_pattern (ubs-java.sh 3569), POSIX classes translated.
_PB_SHELL = (
    r'(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"(sh|bash)"[ \t]*,[ \t]*"-?c"'
    r'|(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"cmd([.]exe)?"[ \t]*,[ \t]*"/[cC]"'
    r'|(new[ \t]+)?ProcessBuilder[ \t]*\([ \t]*"(powershell|pwsh)([.]exe)?"[ \t]*,[ \t]*"-(Command|EncodedCommand)"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"(sh|bash)"[ \t]*,[ \t]*"-?c"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"cmd([.]exe)?"[ \t]*,[ \t]*"/[cC]"'
    r'|ProcessBuilder[ \t]*\([ \t]*(listOf|arrayOf)[ \t]*\([ \t]*"(powershell|pwsh)([.]exe)?"[ \t]*,[ \t]*"-(Command|EncodedCommand)"'
)

PATTERNS: list[Pattern] = [
    Pattern(
        category=4,
        rule_id="java.security.ssl-insecure",
        title="SSL/TLS validation disabled",
        regex=re.compile(r"HostnameVerifier\W*\(\W*.*->\W*true\W*\)"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=4,
        rule_id="java.security.weak-hash",
        title="Weak hash detected - prefer SHA-256/512",
        regex=re.compile(r'MessageDigest\.getInstance\("(MD5|SHA-1)"\)'),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="java.security.plain-http",
        title="Plain HTTP URL(s) present",
        regex=re.compile(r"http://[A-Za-z0-9]"),
        thresholds=((0, "info"),),
    ),
    Pattern(
        category=4,
        rule_id="java.security.deserialization",
        title="Object deserialization detected",
        regex=re.compile(r"ObjectInputStream\(.+\)\.readObject\("),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=4,
        rule_id="java.security.processbuilder-shell",
        title="ProcessBuilder shell interpreter invoked",
        regex=re.compile(_PB_SHELL),
        thresholds=((0, "critical"),),
        description="Pass arguments directly as argv, or strictly validate and escape every shell fragment",
    ),
]
