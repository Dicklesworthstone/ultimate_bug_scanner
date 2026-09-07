"""ubs_core.kotlin_rules — ast-grep rule-pack generation for the Kotlin module (bead 7mga.2).

Defines the ast-grep rule pack and rule definitions for Kotlin scanning:
- ProcessBuilder shell execution
- Zip Slip archive extraction
- Insecure randomness for security tokens
- Null-safety and type narrowing checks

``generate(rule_dir, user_rules_dir=None)`` writes:
    <rule_dir>/rules/*.yml          the base rules
    <rule_dir>/sgconfig-kotlin.yml  single-grammar config listing every rule file
    <rule_dir>/manifest.json        rule_id -> {severity, language, file}
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "REMEDIATION_MAP",
    "generate",
]

SEVERITY_MAP: dict[str, str] = {
    "kotlin.security.processbuilder-shell": "critical",
    "kotlin.security.archive-extraction": "critical",
    "kotlin.security.insecure-randomness": "critical",
    "kotlin.narrowing.safecall_guard": "warning",
    "kotlin.narrowing.negative_guard": "warning",
    "kotlin.narrowing.positive_guard": "warning",
    "kotlin.narrowing.smart_cast": "warning",
    "kotlin.narrowing.elvis_force": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    "kotlin.security.processbuilder-shell": 4,
    "kotlin.security.archive-extraction": 4,
    "kotlin.security.insecure-randomness": 4,
    "kotlin.narrowing.safecall_guard": 1,
    "kotlin.narrowing.negative_guard": 1,
    "kotlin.narrowing.positive_guard": 1,
    "kotlin.narrowing.smart_cast": 1,
    "kotlin.narrowing.elvis_force": 1,
}

SUMMARY_MAP: dict[str, str] = {
    "kotlin.security.processbuilder-shell": "ProcessBuilder shell interpreter invoked",
    "kotlin.security.archive-extraction": "Archive extraction path traversal risk",
    "kotlin.security.insecure-randomness": "Security token generated with non-cryptographic randomness",
    "kotlin.narrowing.safecall_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.negative_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.positive_guard": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.smart_cast": "Kotlin guard without exit before '!!'",
    "kotlin.narrowing.elvis_force": "Kotlin guard without exit before '!!'",
}

REMEDIATION_MAP: dict[str, str] = {
    "kotlin.security.processbuilder-shell": "Pass arguments directly as argv, or strictly validate and escape every shell fragment",
    "kotlin.security.archive-extraction": "Verify destination path containment using target.normalize().startsWith(dest.normalize())",
    "kotlin.security.insecure-randomness": "Use java.security.SecureRandom for cryptographic tokens and secrets",
    "kotlin.narrowing.safecall_guard": "Return or throw early in the null branch so forced unwrap (!!) is safe or unnecessary",
    "kotlin.narrowing.negative_guard": "Exit (return or throw) in the null branch before forcing with !!",
    "kotlin.narrowing.positive_guard": "Exit early when not null or use safe calls (?.) instead of !!",
    "kotlin.narrowing.smart_cast": "Handle null or cast failure explicitly instead of forced !! unwrap",
    "kotlin.narrowing.elvis_force": "Exit early in the Elvis rhs (e.g. ?: return) instead of forcing with !!",
}

_RULES: list[tuple[str, str]] = [
    (
        "processbuilder-shell",
        r"""id: kotlin.security.processbuilder-shell
language: kotlin
severity: error
message: "ProcessBuilder shell interpreter invoked"
rule:
  any:
    - pattern: ProcessBuilder("sh", "-c", $$$ARGS)
    - pattern: ProcessBuilder("bash", "-c", $$$ARGS)
    - pattern: ProcessBuilder("cmd", "/C", $$$ARGS)
""",
    ),
]


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> list[str]:
    rule_dir.mkdir(parents=True, exist_ok=True)
    rules_sub = rule_dir / "rules"
    rules_sub.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, dict] = {}
    rule_files: list[str] = []

    for name, text in _RULES:
        path = rules_sub / f"{name}.yml"
        path.write_text(text, encoding="utf-8")
        rule_id = f"kotlin.security.{name}"
        manifest[rule_id] = {
            "severity": SEVERITY_MAP.get(rule_id, "error"),
            "language": "kotlin",
            "file": f"rules/{name}.yml",
        }
        rule_files.append(f"rules/{name}.yml")

    if user_rules_dir and user_rules_dir.is_dir():
        for p in sorted(user_rules_dir.glob("*.yml")):
            dest = rules_sub / p.name
            shutil.copy2(p, dest)
            manifest[p.stem] = {
                "severity": "warning",
                "language": "kotlin",
                "file": f"rules/{p.name}",
            }
            rule_files.append(f"rules/{p.name}")

    sgconfig = {
        "ruleDirs": ["rules"],
        "language": "kotlin",
    }
    (rule_dir / "sgconfig-kotlin.yml").write_text(
        json.dumps(sgconfig, indent=2) + "\n",
        encoding="utf-8",
    )
    (rule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    return sorted(manifest.keys())
