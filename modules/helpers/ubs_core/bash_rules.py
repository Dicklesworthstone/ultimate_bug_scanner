"""ubs_core.bash_rules — ast-grep rule-pack generation for the Bash module (bead 7mga.1).

Defines the ast-grep rule pack for Bash / POSIX sh scanning:
- eval dynamic execution
- local x=$(cmd) return code masking
- mktemp -u TOCTOU race
- test -a / -o obsolete operator

``generate(rule_dir, user_rules_dir=None)`` writes:
    <rule_dir>/rules/*.yml        the base rules
    <rule_dir>/sgconfig-bash.yml  single-grammar config listing every rule file
    <rule_dir>/manifest.json      rule_id -> {severity, language, file}
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
    "bash.security.eval-variable": "critical",
    "bash.variable.local-command-subst": "warning",
    "bash.security.mktemp-dry-run": "critical",
    "bash.syntax.test-compound": "warning",
}

CATEGORY_MAP: dict[str, int] = {
    "bash.security.eval-variable": 3,
    "bash.variable.local-command-subst": 2,
    "bash.security.mktemp-dry-run": 3,
    "bash.syntax.test-compound": 1,
}

SUMMARY_MAP: dict[str, str] = {
    "bash.security.eval-variable": "Dynamic code execution via eval",
    "bash.variable.local-command-subst": "local variable assignment masks command exit code",
    "bash.security.mktemp-dry-run": "mktemp -u creates a TOCTOU race condition",
    "bash.syntax.test-compound": "test -a / -o is obsolete and ambiguous in POSIX",
}

REMEDIATION_MAP: dict[str, str] = {
    "bash.security.eval-variable": "Avoid dynamic eval on variable input; use arrays or direct invocation",
    "bash.variable.local-command-subst": "Declare and assign separately: local x; x=$(cmd)",
    "bash.security.mktemp-dry-run": "Create and open temporary files atomically with mktemp without -u",
    "bash.syntax.test-compound": "Use separate [ ... ] && [ ... ] tests instead of [ ... -a ... ]",
}

_RULES: list[tuple[str, str]] = [
    (
        "eval-variable",
        r"""id: bash.security.eval-variable
language: bash
rule:
  pattern: eval $$$ARGS
severity: error
message: "Dynamic code execution via eval; avoid eval with variable arguments"
""",
    ),
    (
        "local-command-subst",
        r"""id: bash.variable.local-command-subst
language: bash
rule:
  kind: declaration_command
  has:
    kind: variable_assignment
    has:
      kind: command_substitution
severity: warning
message: "local x=$(cmd) masks command exit code; declare and assign separately"
""",
    ),
    (
        "mktemp-dry-run",
        r"""id: bash.security.mktemp-dry-run
language: bash
rule:
  any:
    - pattern: mktemp -u $$$ARGS
    - pattern: mktemp --dry-run $$$ARGS
severity: error
message: "mktemp -u creates a TOCTOU race condition; create the file atomically"
""",
    ),
    (
        "test-compound",
        r"""id: bash.syntax.test-compound
language: bash
rule:
  pattern: test $A -a $B
severity: warning
message: "test -a / -o is obsolete and has ambiguous precedence in POSIX; use test A && test B"
""",
    ),
]


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict[str, dict]:
    rule_dir.mkdir(parents=True, exist_ok=True)
    rules_sub = rule_dir / "rules"
    rules_sub.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, dict] = {}
    for name, content in _RULES:
        rule_file = rules_sub / f"{name}.yml"
        rule_file.write_text(content, encoding="utf-8")
        rid = None
        for line in content.splitlines():
            if line.startswith("id:"):
                rid = line.split(":", 1)[1].strip()
                break
        if rid:
            manifest[rid] = {
                "file": str(rule_file),
                "severity": SEVERITY_MAP.get(rid, "warning"),
                "language": "bash",
            }

    if user_rules_dir and user_rules_dir.is_dir():
        for pat in ("*.yml", "*.yaml"):
            for f in user_rules_dir.glob(pat):
                dest = rules_sub / f"user_{f.name}"
                shutil.copy2(f, dest)
                try:
                    for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                        if line.startswith("id:"):
                            urid = line.split(":", 1)[1].strip()
                            manifest[urid] = {
                                "file": str(dest),
                                "severity": "warning",
                                "language": "bash",
                            }
                            break
                except OSError:
                    pass

    sgconfig = rule_dir / "sgconfig-bash.yml"
    sgconfig.write_text(
        "ruleDirs:\n  - rules\n",
        encoding="utf-8",
    )
    (rule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
