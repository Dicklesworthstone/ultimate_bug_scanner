"""ubs_core.ruby_patterns.security_rg — category 6 rg-pipeline subset (bead 0xjg.10).

Faithful ports of the legacy rg checks in modules/ubs-ruby.sh 2908-2982:
eval family, Marshal/YAML unsafe loads, interpolated and plain backticks,
single-string shell invocations, shell interpreter argv modes, disabled TLS
verification, weak hashes, hardcoded secrets. The six heredoc detectors of
category 6 live in ubs_core.ruby_detectors.* / the registered taint
analyzers instead.
"""
from __future__ import annotations

import re

from ubs_core.ruby_scan import Pattern

_SHELL_CALL = (
    r"(?:^|[^A-Za-z0-9_])(?:system|exec|spawn|IO\.popen|"
    r"Open3\.(?:capture2|capture3|capture2e|capture3e|popen2|popen2e|popen3))\("
)

PATTERNS: list[Pattern] = [
    Pattern(
        category=6,
        rule_id="ruby.security.eval-family",
        title="eval*/_*eval present",
        # legacy 2916: `(^|[^A-Za-z0-9_])(eval|instance_eval|class_eval)[[:space:]]*\(`
        # (the trailing `grep -v "^[[:space:]]*#"` filtered on rg output lines
        # that always start with the path — dead code, so no exclusion here);
        # critical >0, "Avoid executing dynamic code".
        regex=re.compile(r"(?m)(?:^|[^A-Za-z0-9_])(?:eval|instance_eval|class_eval)[ \t]*\("),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.unsafe-deserialization",
        title="Unsafe deserialization",
        # legacy 2925: `Marshal\.(load|restore)\(|YAML\.load\(` with
        # `grep -E -v "YAML\.safe_load"`; critical >0, "Use YAML.safe_load or JSON".
        regex=re.compile(r"Marshal\.(?:load|restore)\(|YAML\.load\("),
        exclude_regex=re.compile(r"YAML\.safe_load"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.backticks-interpolated",
        title="Backtick command execution with interpolation",
        # legacy 2932-2933: `` \`[^`]*#\{[^}]+\}[^`]*\`|%x\([^)]*#\{[^}]+\}[^)]*\) ``,
        # critical >0, "use argv APIs such as Open3.capture2('cmd', arg)".
        regex=re.compile(
            r"`[^`\n]*#\{[^}\n]+\}[^`\n]*`|%x\([^)\n]*#\{[^}\n]+\}[^)\n]*\)"
        ),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.backticks",
        title="Backtick command execution",
        # legacy 2941: `` \`[^`]*\`|%x\([^)]*\) `` with `grep -E -v '#\{'`;
        # warning >0, "Prefer system with argv array and validate inputs".
        regex=re.compile(r"`[^`\n]*`|%x\([^)\n]*\)"),
        exclude_regex=re.compile(r"#\{"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.shell-single-string",
        title="Shell invocation risk (single-string)",
        # legacy 2949: shell-call family with ONE quoted argument and no
        # comma; critical >0, "Use argv array: system('cmd', arg1, ...)".
        regex=re.compile(_SHELL_CALL + r"[ \t]*['\"][^,)\n]*['\"][ \t]*\)"),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.shell-interpreter-argv",
        title="Shell interpreter command mode",
        # legacy 2957: shell-call family invoked as `('sh', '-c', ...)`
        # style interpreter argv; critical >0, "pass argv directly to the
        # target executable".
        regex=re.compile(
            _SHELL_CALL
            + r"[ \t]*['\"](?:sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)['\"]"
            + r"[ \t]*,[ \t]*['\"](?:-?c|/[cC]|-[Cc]ommand|-[Ee]ncoded[Cc]ommand)['\"]"
        ),
        thresholds=((0, "critical"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.tls-verify-disabled",
        title="SSL verification disabled",
        # legacy 2965: `VERIFY_NONE|verify_mode[[:space:]]*=[[:space:]]*OpenSSL::SSL::VERIFY_NONE`,
        # warning >0, "Enable VERIFY_PEER".
        regex=re.compile(r"VERIFY_NONE|verify_mode[ \t]*=[ \t]*OpenSSL::SSL::VERIFY_NONE"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.weak-hash",
        title="Weak hash usage",
        # legacy 2972: `Digest::(MD5|SHA1)\.hexdigest|OpenSSL::Digest::(MD5|SHA1)\.new`,
        # warning >0, "Use Digest::SHA256".
        regex=re.compile(r"Digest::(?:MD5|SHA1)\.hexdigest|OpenSSL::Digest::(?:MD5|SHA1)\.new"),
        thresholds=((0, "warning"),),
    ),
    Pattern(
        category=6,
        rule_id="ruby.security.hardcoded-secrets",
        title="Potential hardcoded secrets",
        # legacy 2979 (GREP_RNI): secret-name assignment to a quoted literal
        # with `grep -E -v "(^|/)(spec|test)/fixtures/"`; critical >0, "Use
        # env vars or credentials store". The rg layer already pruned the
        # fixture dirs, so the exclusion stays for line-level fidelity.
        regex=re.compile(
            r"\b(?:password|api_?key|client_secret|private_?key|bearer|authorization|token)\b"
            r"[ \t]*[:=][ \t]*['\"][^\"\n]+['\"]"
        ),
        case_insensitive=True,
        exclude_regex=re.compile(r"(?:^|/)(?:spec|test)/fixtures/"),
        thresholds=((0, "critical"),),
    ),
]
