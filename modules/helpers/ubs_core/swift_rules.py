"""ubs_core.swift_rules — ast-grep rule-pack generation for the Swift module.

The legacy write_ast_rules (modules/ubs-swift.sh 770-798) emits exactly ONE
generated rule — swift.urlsession.task-no-resume — plus an optional copy of
the user's --rules=DIR. The YAML below is byte-identical to the heredoc.

Metadata maps mirror the module's consume side: AG_RULE_CATEGORY derives the
category from the c04- filename prefix (category 4, URLSession/Networking),
the YAML severity is info, and run_urlsession_task_correlation +
run_ast_rules both consume the same consolidated `scan --json=stream` output.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

__all__ = ["generate", "CATEGORY_MAP", "SEVERITY_MAP", "SUMMARY_MAP", "REMEDIATION_MAP"]

SEVERITY_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": "info",
}

CATEGORY_MAP: dict[str, int] = {
    "swift.urlsession.task-no-resume": 4,
}

SUMMARY_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": (
        "URLSession task created (correlation will check resume/cancel); "
        "ensure lifecycle management."
    ),
}

REMEDIATION_MAP: dict[str, str] = {
    "swift.urlsession.task-no-resume": (
        "Store the task and call .resume(); cancel on teardown if needed."
    ),
}

_GRAMMAR = "swift"

_LANGUAGE_RE = re.compile(r"^language:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)
_ID_RE = re.compile(r"^id:[ \t]*([^ \t]+)[ \t]*$", re.MULTILINE)
_SEVERITY_RE = re.compile(r"^severity:[ \t]*([A-Za-z]+)[ \t]*$", re.MULTILINE)

# ─────────────────────────────────────────────────────────────────────────────
# Base rule pack — the verbatim c04 heredoc body of write_ast_rules.
# ─────────────────────────────────────────────────────────────────────────────

_RULES: tuple[tuple[str, str], ...] = (
    (
        "c04-urlsession-task-no-resume.yml",
        """id: swift.urlsession.task-no-resume
language: swift
rule:
  pattern: $SESSION.$METHOD($$$)
constraints:
  METHOD:
    regex: '^(dataTask|uploadTask|downloadTask)$'
severity: info
message: "URLSession task created (correlation will check resume/cancel); ensure lifecycle management."
""",
    ),
)


def _map_severity(raw: str) -> str:
    """Legacy parser severity map (error/critical/fatal -> critical)."""
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict:
    """Write the ast-grep rule pack, the sgconfig, and the manifest."""
    # The sgconfig lives at the pack root and points at ./rules: ast-grep
    # treats every file under ruleDirs as a rule, so a config inside its own
    # ruleDir would fail to parse itself (empty AG stream).
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    if user_rules_dir and Path(user_rules_dir).is_dir():
        shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)

    manifest: dict[str, dict] = {}
    for filename, body in _RULES:
        (rules_dir / filename).write_text(body, encoding="utf-8")
        rid = _first_match(_ID_RE, body)
        if not rid:
            continue
        grammar = _first_match(_LANGUAGE_RE, body) or _GRAMMAR
        severity = _map_severity(_first_match(_SEVERITY_RE, body))
        cat_match = re.match(r"^c(\d{2})-", filename)
        category = int(cat_match.group(1)) if cat_match else 0
        manifest[rid] = {
            "file": f"rules/{filename}",
            "language": grammar,
            "severity": severity,
            "category": category,
        }

    config = rule_dir / "sgconfig-swift.yml"
    config.write_text("ruleDirs:\n- rules\n", encoding="utf-8")
    (rule_dir / "manifest.json").write_text(
        json_dumps(manifest), encoding="utf-8"
    )
    return manifest
def json_dumps(obj: dict) -> str:
    import json

    return json.dumps(obj, indent=1, sort_keys=True)
