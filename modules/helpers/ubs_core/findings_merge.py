"""ubs_core.findings_merge — combined findings[] assembly for the meta-runner (bead K2).

Contract-v2 modules write one NDJSON findings record per sample to
``<lang>.findings.json`` inside the run's temp dir. This module merges every
sink into a top-level ``findings[]`` array on the combined summary document:

    {lang, rule_id, category_id, severity, confidence, file, line, col,
     message, remediation, fix, fingerprint, suppressed}

Records without a ``rule`` key are not findings (module summary objects are
ignored), so the merge is safe to run unconditionally. Per-language parity
lights up as each A4 port starts writing the sink.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCANNER_SUMMARY_KEYS = {"language", "project", "files", "critical", "warning", "info", "timestamp", "status", "version"}


def _fingerprint(lang: str, rule: str, path: str, line: int, col: int) -> str:
    src = f"{lang}\x1f{rule}\x1f{path}\x1f{line}\x1f{col}"
    return hashlib.sha1(src.encode("utf-8", "replace")).hexdigest()[:16]


def _looks_like_finding(rec: object) -> bool:
    """A sink record must be an object with a rule id and a path."""
    if not isinstance(rec, dict) or "rule" not in rec or "path" not in rec:
        return False
    # Module summary objects share the file but never carry a rule key.
    return not (SCANNER_SUMMARY_KEYS >= set(rec.keys()) and "rule_id" not in rec)


def load_sink(sink: Path) -> list[dict]:
    """Parse one NDJSON sink, skipping blank/malformed/non-finding lines."""
    records: list[dict] = []
    try:
        raw_lines = sink.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return records
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if _looks_like_finding(rec):
            records.append(rec)
    return records


def _normalize(rec: dict, lang: str) -> dict:
    rule = str(rec.get("rule", ""))
    path = str(rec.get("path", ""))
    try:
        line_no = int(rec.get("line", 0) or 0)
    except (TypeError, ValueError):
        line_no = 0
    try:
        col = int(rec.get("col", 1) or 1)
    except (TypeError, ValueError):
        col = 1
    return {
        "lang": lang,
        "rule_id": rule,
        "category_id": str(rec.get("category_id", "")),
        "severity": str(rec.get("severity", "warning")),
        "confidence": str(rec.get("confidence", "")),
        "file": path,
        "line": line_no,
        "col": col,
        "message": str(rec.get("message", "")),
        "remediation": str(rec.get("remediation", "")),
        "fix": str(rec.get("fix", "")),
        "fingerprint": _fingerprint(lang, rule, path, line_no, col),
        "suppressed": bool(rec.get("suppressed", False)),
    }


def merge(tmp_dir: Path, combined_path: Path) -> int:
    """Merge every ``<lang>.findings.json`` NDJSON sink into combined findings[].

    Returns the number of records merged (0 when no module emitted a sink).
    Raises ValueError when the combined document is missing or invalid.
    """
    if not combined_path.is_file() or combined_path.stat().st_size == 0:
        raise ValueError(f"combined summary missing or empty: {combined_path}")
    doc = json.loads(combined_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("combined summary is not a JSON object")

    findings: list[dict] = []
    for sink in sorted(Path(tmp_dir).glob("*.findings.json")):
        lang = sink.name.split(".", 1)[0]
        records = load_sink(sink)
        if not records:
            continue
        for rec in records:
            findings.append(_normalize(rec, lang))
        for scanner in doc.get("scanners", []) or []:
            if isinstance(scanner, dict) and scanner.get("language") == lang:
                scanner["findings_sink"] = True

    if findings:
        doc["findings"] = findings
        combined_path.write_text(json.dumps(doc), encoding="utf-8")
    return len(findings)
