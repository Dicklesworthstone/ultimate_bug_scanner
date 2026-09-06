"""ubs_core.csharp_rules — ast-grep rule-pack generation for the C# module (bead 0xjg.12).

C# port of the runtime ast-grep rule GENERATION in modules/ubs-csharp.sh
``write_ast_rules`` (522-593): the four concurrency rules (legacy cat 17
"AST-Grep Rule Pack"), byte-identical to the module heredocs.

``generate(rule_dir)`` writes::

    <rule_dir>/rules/*.yml        the 4 base rules (byte-identical to the
                                  legacy heredocs)
    <rule_dir>/sgconfig-csharp.yml  single-grammar config listing every rule
                                    file (one ``scan -c`` invocation total)
    <rule_dir>/manifest.json      rule_id -> {severity, language, file}

Unlike ruby/java, EVERY rule in the C# pack joins the legacy counters: cat
17 ingests the whole scan through ``ast_scan_json_to_tsv`` and bumps
counters per deduped match, with severity and title coming from the
module's AST_RULE_SEVERITY / AST_RULE_SUMMARY tables (all four rules are
warning-tier). Those tables live here as SEVERITY_MAP / SUMMARY_MAP and
csharp_ast consumes them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "REMEDIATION_MAP",
    "generate",
]

# Legacy AST_RULE_SEVERITY / AST_RULE_SUMMARY (ubs-csharp.sh 510-521): the
# severity the shell applied on ingest regardless of the YAML tier, and the
# print titles the per-rule summary (and add_finding) used.
SEVERITY_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "warning",
    "cs-async-discarded-startnew": "warning",
    "cs-await-in-lock": "warning",
    "cs-parallel-foreach-async-lambda": "warning",
}

SUMMARY_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "Task.Run result discarded without observation",
    "cs-async-discarded-startnew": "Task.Factory.StartNew result discarded without observation",
    "cs-await-in-lock": "Await used while holding a lock",
    "cs-parallel-foreach-async-lambda": "Parallel.ForEach async lambda drops asynchronous work",
}

REMEDIATION_MAP: dict[str, str] = {
    "cs-async-discarded-task-run": "Await or retain the Task so failures are observed",
    "cs-async-discarded-startnew": "Await or retain the Task so failures are observed",
    "cs-await-in-lock": "Move async work outside the lock",
    "cs-parallel-foreach-async-lambda": "Use Parallel.ForEachAsync or gather Tasks",
}

# Every pack rule was counted by legacy cat 17 (whole-pack ingestion).
CATEGORY_MAP: dict[str, int] = {
    "cs-async-discarded-task-run": 17,
    "cs-async-discarded-startnew": 17,
    "cs-await-in-lock": 17,
    "cs-parallel-foreach-async-lambda": 17,
}

_GRAMMAR = "csharp"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (normalize_ast_severity, 606-613)."""
    raw = (raw or "").lower().strip()
    if raw in ("critical", "error", "fatal"):
        return "critical"
    if raw in ("info", "note", "hint"):
        return "info"
    return "warning"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — verbatim heredoc bodies of write_ast_rules (527-570).
# ─────────────────────────────────────────────────────────────────────────────

_RULES: tuple[tuple[str, str], ...] = (
    (
        "cs-async-discarded-task-run",
        r'''id: cs-async-discarded-task-run
message: "Task.Run result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Run($ARG);
    - pattern: _ = Task.Run($ARG);
''',
    ),
    (
        "cs-async-discarded-startnew",
        r'''id: cs-async-discarded-startnew
message: "Task.Factory.StartNew result discarded; await or retain the Task so failures are observed."
severity: warning
language: csharp
rule:
  any:
    - pattern: Task.Factory.StartNew($ARG);
    - pattern: _ = Task.Factory.StartNew($ARG);
''',
    ),
    (
        "cs-await-in-lock",
        r'''id: cs-await-in-lock
message: "Await inside lock can deadlock or break monitor assumptions; move async work outside the lock."
severity: warning
language: csharp
rule:
  pattern: |
    lock ($OBJ) { await $EXPR; }
''',
    ),
    (
        "cs-parallel-foreach-async-lambda",
        r'''id: cs-parallel-foreach-async-lambda
message: "Parallel.ForEach with async lambda does not await the async work; use Parallel.ForEachAsync or gather Tasks."
severity: warning
language: csharp
rule:
  any:
    - pattern: Parallel.ForEach($SRC, async $ITEM => $EXPR);
    - pattern: Parallel.ForEach($SRC, async ($ITEM) => $EXPR);
    - pattern: |
        Parallel.ForEach($SRC, async $ITEM => { await $EXPR; });
''',
    ),
)


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, the sgconfig, and the manifest.

    Returns the manifest dict (rule_id -> {severity, language, file}); the
    same document is written to ``<rule_dir>/manifest.json``. Re-running on
    the same ``rule_dir`` reproduces the identical tree.
    """
    rule_dir = Path(rule_dir)
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # User rules (--rules DIR) are copied verbatim next to the base rules,
    # mirroring the legacy sgconfig extra ruleDirs entries (580-587).
    user_rule_files: list[Path] = []
    if user_rules_dir is not None:
        user_rules_dir = Path(user_rules_dir)
        if user_rules_dir.is_dir():
            import shutil

            shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)
            user_rule_files = sorted(
                path
                for path in rules_dir.iterdir()
                if path.is_file() and path.suffix in (".yml", ".yaml")
                and not any(stem == path.stem for stem, _ in _RULES)
            )

    manifest: dict[str, dict[str, str]] = {}
    config_entries: list[str] = []

    for stem, rule_text in _RULES:
        name = f"{stem}.yml"
        (rules_dir / name).write_text(rule_text, encoding="utf-8")
        rule_id = _first_match(_ID_RE, rule_text)
        manifest[rule_id] = {
            "severity": SEVERITY_MAP.get(
                rule_id, _map_severity(_first_match(_SEVERITY_RE, rule_text))
            ),
            "language": _first_match(_LANGUAGE_RE, rule_text),
            "file": f"rules/{name}",
        }
        config_entries.append(f"  - rules/{name}")

    for user_file in user_rule_files:
        config_entries.append(f"  - rules/{user_file.name}")

    (rule_dir / f"sgconfig-{_GRAMMAR}.yml").write_text(
        "ruleDirs:\n" + "\n".join(config_entries) + "\n", encoding="utf-8"
    )

    manifest_path = rule_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
