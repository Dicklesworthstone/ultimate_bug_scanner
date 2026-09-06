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


def to_sarif(
    doc: dict,
    *,
    git_blob_base: str = "",
    git_top: str = "",
    git_remote: str = "",
    git_commit: str = "",
    sarif_automation_id: str = "",
) -> dict:
    """Build a SARIF 2.1.0 document from the combined summary document and its findings[].

    Each module scanner is given a run. If scanners is empty, runs are formed
    from the distinct languages present in findings[], or a default 'ubs' run.
    """
    version = str(doc.get("version", "5.3.13"))
    scanners = doc.get("scanners", []) or []
    findings = doc.get("findings", []) or []

    # Map findings by language
    findings_by_lang: dict[str, list[dict]] = {}
    for f in findings:
        lang = str(f.get("lang") or "unknown")
        findings_by_lang.setdefault(lang, []).append(f)

    # Determine ordered list of languages for runs
    languages: list[str] = []
    if scanners:
        for s in scanners:
            if isinstance(s, dict):
                l = str(s.get("language") or "")
                if l and l not in languages:
                    languages.append(l)
    for l in findings_by_lang:
        if l not in languages:
            languages.append(l)
    if not languages:
        languages = ["ubs"]

    runs: list[dict] = []
    for lang in languages:
        driver_name = f"ubs-{lang}" if lang != "ubs" else "ubs"
        run: dict = {
            "tool": {
                "driver": {
                    "name": driver_name,
                    "version": version,
                    "informationUri": "https://github.com/Dicklesworthstone/ultimate_bug_scanner",
                }
            },
            "results": [],
        }
        if git_remote:
            prov = {"repositoryUri": git_remote}
            if git_commit:
                prov["revisionId"] = git_commit
            run["versionControlProvenance"] = [prov]
        if sarif_automation_id:
            run["automationDetails"] = {"id": sarif_automation_id}

        lang_findings = findings_by_lang.get(lang, [])
        for f in lang_findings:
            rule_id = str(f.get("rule_id") or "")
            sev = str(f.get("severity") or "warning").lower()
            level = "error" if sev == "critical" else ("warning" if sev == "warning" else "note")
            msg = str(f.get("message") or rule_id)
            res: dict = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
            }
            file_path = str(f.get("file") or "")
            if file_path:
                try:
                    line_no = max(1, int(f.get("line", 1) or 1))
                except (TypeError, ValueError):
                    line_no = 1
                try:
                    col_no = max(1, int(f.get("col", 1) or 1))
                except (TypeError, ValueError):
                    col_no = 1
                loc: dict = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {
                            "startLine": line_no,
                            "startColumn": col_no,
                        },
                    }
                }
                if git_blob_base:
                    rel = file_path
                    if rel.startswith("file://"):
                        rel = rel[7:]
                    if git_top and rel.startswith(git_top + "/"):
                        rel = rel[len(git_top) + 1:]
                    elif rel.startswith("./"):
                        rel = rel[2:]
                    loc["properties"] = {"permalink": f"{git_blob_base}/{rel}#L{line_no}"}
                res["locations"] = [loc]

            props: dict = {}
            if f.get("category_id"):
                props["category_id"] = str(f["category_id"])
            if f.get("fingerprint"):
                props["fingerprint"] = str(f["fingerprint"])
            if f.get("suppressed") is not None:
                props["suppressed"] = bool(f["suppressed"])
            if f.get("confidence"):
                props["confidence"] = str(f["confidence"])
            if f.get("remediation"):
                props["remediation"] = str(f["remediation"])
            if f.get("fix"):
                props["fix"] = str(f["fix"])
            if props:
                res["properties"] = props
            run["results"].append(res)

        runs.append(run)

    # Invocations for partial runs / failed modules
    if doc.get("status") == "partial" or doc.get("failed_modules"):
        failed = doc.get("failed_modules") or []
        notifications = []
        for fmod in failed:
            if isinstance(fmod, dict):
                st = str(fmod.get("status") or "error")
                flang = str(fmod.get("language") or "unknown")
                msg = str(fmod.get("message") or fmod.get("module_error") or "module did not complete")
                notifications.append({
                    "level": "error",
                    "descriptor": {"id": f"ubs/module-{st}"},
                    "message": {"text": f"{flang}: {st} — {msg}"},
                })
        for r in runs:
            r["invocations"] = [{
                "executionSuccessful": False,
                "toolExecutionNotifications": notifications,
            }]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }

