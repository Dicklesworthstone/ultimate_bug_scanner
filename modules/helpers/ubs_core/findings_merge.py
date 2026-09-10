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
import os
import re
from pathlib import Path

SCANNER_SUMMARY_KEYS = {"language", "project", "files", "critical", "warning", "info", "timestamp", "status", "version"}

KEYWORDS = frozenset({
    "if", "else", "elif", "then", "end", "while", "for", "in", "do", "return", "yield",
    "def", "class", "module", "function", "var", "let", "const", "import", "from", "as",
    "try", "catch", "except", "finally", "throw", "raise", "switch", "case", "default",
    "break", "continue", "new", "delete", "typeof", "instanceof", "void", "true", "false",
    "null", "undefined", "nil", "None", "True", "False", "async", "await", "fn", "mut",
    "pub", "struct", "enum", "impl", "trait", "package", "go", "select", "defer", "func",
    "type", "interface", "map", "chan", "range", "val", "public", "private", "protected",
    "static", "final", "override", "self", "this", "super", "where", "guard",
})


def normalize_statement(statement: str) -> str:
    """Normalize statement: strip comments, normalize strings and identifiers, collapse whitespace."""
    stmt = re.sub(r"(?://|#).*$", "", statement)
    stmt = re.sub(r'"(?:[^"\\]|\\.)*"', '""', stmt)
    stmt = re.sub(r"'(?:[^'\\]|\\.)*'", "''", stmt)

    def replace_ident(m: re.Match) -> str:
        w = m.group(0)
        return w if w in KEYWORDS else "_ID_"

    stmt = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", replace_ident, stmt)
    return re.sub(r"\s+", " ", stmt).strip()


def _relative_path(path: str, project_dir: str | Path = "") -> str:
    p_str = str(path or "").strip()
    if p_str.startswith("file://"):
        p_str = p_str[7:]
    if not project_dir:
        return p_str
    try:
        p_path = Path(p_str)
        proj_path = Path(project_dir).resolve()
        if p_path.is_absolute():
            return str(p_path.resolve().relative_to(proj_path))
        full = (proj_path / p_path).resolve()
        if full.is_relative_to(proj_path):
            return str(full.relative_to(proj_path))
        return p_str
    except Exception:
        return p_str


def _extract_statement(rec: dict, project_dir: str | Path = "") -> str:
    path = str(rec.get("path", ""))
    try:
        line_no = int(rec.get("line", 0) or 0)
    except (TypeError, ValueError):
        line_no = 0
    if path and line_no > 0:
        p = Path(path)
        if not p.is_file() and project_dir:
            p = Path(project_dir, path)
        if p.is_file():
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                if 1 <= line_no <= len(lines):
                    return lines[line_no - 1]
            except OSError:
                pass
    return str(rec.get("message", "")) or str(rec.get("rule", ""))


def _fingerprint(rule: str, rel_path: str, normalized_stmt: str, ordinal: int) -> str:
    src = f"{rule}\x1f{rel_path}\x1f{normalized_stmt}\x1f{ordinal}"
    return hashlib.sha256(src.encode("utf-8", "replace")).hexdigest()[:16]


def load_baseline_fingerprints(baseline_path: str | Path) -> set[str]:
    fps: set[str] = set()
    if not baseline_path:
        return fps
    p = Path(baseline_path)
    if not p.is_file():
        return fps
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return fps
    if isinstance(data, dict):
        for item in data.get("findings", []):
            if isinstance(item, dict) and item.get("fingerprint"):
                fps.add(str(item["fingerprint"]))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("fingerprint"):
                fps.add(str(item["fingerprint"]))
            elif isinstance(item, str):
                fps.add(item)
    return fps


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


def _normalize(rec: dict, lang: str, project_dir: str | Path = "", ordinals: dict | None = None) -> dict:
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
    rel_path = _relative_path(path, project_dir)
    stmt = _extract_statement(rec, project_dir)
    norm_stmt = normalize_statement(stmt)
    key = (rule, norm_stmt)
    ordinal = 0
    if ordinals is not None:
        file_map = ordinals.setdefault(rel_path, {})
        ordinal = file_map.get(key, 0)
        file_map[key] = ordinal + 1
    fp = _fingerprint(rule, rel_path, norm_stmt, ordinal)
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
        "fingerprint": fp,
        "suppressed": bool(rec.get("suppressed", False)),
    }


def merge(
    tmp_dir: Path,
    combined_path: Path,
    *,
    project_dir: str | Path = "",
    baseline_path: str | Path = "",
    new_only: bool = False,
) -> int:
    """Merge every ``<lang>.findings.json`` NDJSON sink into combined findings[].

    Returns the number of records merged (0 when no module emitted a sink).
    Raises ValueError when the combined document is missing or invalid.
    """
    if not combined_path.is_file() or combined_path.stat().st_size == 0:
        raise ValueError(f"combined summary missing or empty: {combined_path}")
    try:
        doc = json.loads(combined_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"combined summary is not valid JSON: {combined_path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("combined summary is not a JSON object")

    ordinals: dict[str, dict[tuple[str, str], int]] = {}
    findings: list[dict] = []
    for sink in sorted(Path(tmp_dir).glob("*.findings.json")):
        lang = sink.name.split(".", 1)[0]
        records = load_sink(sink)
        if not records:
            continue
        for rec in records:
            findings.append(_normalize(rec, lang, project_dir=project_dir, ordinals=ordinals))
        for scanner in doc.get("scanners", []) or []:
            if isinstance(scanner, dict) and scanner.get("language") == lang:
                scanner["findings_sink"] = True

    if baseline_path and new_only:
        base_fps = load_baseline_fingerprints(baseline_path)
        if base_fps:
            findings = [f for f in findings if f["fingerprint"] not in base_fps]
        # Recompute scanner and total counts to reflect new-only findings
        findings_by_lang: dict[str, list[dict]] = {}
        for f in findings:
            slang = str(f.get("lang") or "")
            findings_by_lang.setdefault(slang, []).append(f)
        for scanner in doc.get("scanners", []) or []:
            if isinstance(scanner, dict):
                slang = str(scanner.get("language") or "")
                s_list = findings_by_lang.get(slang, [])
                scanner["critical"] = sum(1 for f in s_list if f.get("severity") == "critical" and not f.get("suppressed"))
                scanner["warning"] = sum(1 for f in s_list if f.get("severity") == "warning" and not f.get("suppressed"))
                scanner["info"] = sum(1 for f in s_list if f.get("severity") == "info" and not f.get("suppressed"))
        tot_crit = sum(int(s.get("critical", 0) or 0) for s in doc.get("scanners", []))
        tot_warn = sum(int(s.get("warning", 0) or 0) for s in doc.get("scanners", []))
        tot_info = sum(int(s.get("info", 0) or 0) for s in doc.get("scanners", []))
        if not doc.get("scanners"):
            tot_crit = sum(1 for f in findings if f.get("severity") == "critical" and not f.get("suppressed"))
            tot_warn = sum(1 for f in findings if f.get("severity") == "warning" and not f.get("suppressed"))
            tot_info = sum(1 for f in findings if f.get("severity") == "info" and not f.get("suppressed"))
        if "totals" not in doc or not isinstance(doc["totals"], dict):
            doc["totals"] = {}
        doc["totals"]["critical"] = tot_crit
        doc["totals"]["warning"] = tot_warn
        doc["totals"]["info"] = tot_info
        # `status` is execution state, not a findings verdict. Filtering out
        # findings that were already in the baseline cannot turn a run in which
        # a scanner timed out or crashed into a complete one (issue #104): a
        # zero-new-findings result with a non-empty failed_modules[] used to be
        # relabelled "ok", contradicting the same document's own evidence.

    if findings or (baseline_path and new_only):
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
    default_lang = str(doc.get("language") or "")
    for f in findings:
        lang = str(f.get("lang") or default_lang or "unknown")
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
    if not languages and default_lang:
        languages = [default_lang]
    elif not languages:
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
            rule_id = str(f.get("rule_id") or f.get("rule") or "")
            sev = str(f.get("severity") or "warning").lower()
            level = "error" if sev == "critical" else ("warning" if sev == "warning" else "note")
            msg = str(f.get("message") or rule_id)
            res: dict = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
            }
            file_path = str(f.get("file") or f.get("path") or "")
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
                fp_str = str(f["fingerprint"])
                props["fingerprint"] = fp_str
                res["partialFingerprints"] = {"ubs/v1": fp_str}
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

    # Invocations for incomplete runs / failed modules. `exitCode` is part of
    # the failed-invocation identity, not decoration: consumers use it to tell
    # an environment failure (2) apart from a findings result, and dropping it
    # made a failed run look merely unsuccessful.
    if str(doc.get("status") or "ok") != "ok" or doc.get("failed_modules"):
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
        try:
            exit_code = int(doc.get("exit_code", 2))
        except (TypeError, ValueError):
            exit_code = 2
        for r in runs:
            r["invocations"] = [{
                "executionSuccessful": False,
                "exitCode": exit_code,
                "toolExecutionNotifications": notifications,
            }]

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }

