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
import sqlite3
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import lru_cache
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


def _relative_path(path: str, project_dir: str | Path = "", *, resolve_links: bool = True) -> str:
    # Whitespace is valid filename data. Stripping it aliases distinct source
    # files and can make a baseline suppress a genuinely new file.
    p_str = str(path or "")
    if p_str.startswith("file://"):
        p_str = p_str[7:]
    if not project_dir:
        return p_str
    try:
        p_path = Path(p_str)
        proj_path = Path(project_dir).resolve() if resolve_links else Path(os.path.abspath(project_dir))
        if p_path.is_absolute():
            full = p_path.resolve() if resolve_links else Path(os.path.abspath(p_path))
            return str(full.relative_to(proj_path))
        full = (proj_path / p_path).resolve() if resolve_links else Path(os.path.abspath(proj_path / p_path))
        if full.is_relative_to(proj_path):
            return str(full.relative_to(proj_path))
        return p_str
    except Exception:
        return p_str


def _extract_statement(
    rec: dict,
    project_dir: str | Path,
    source_lines: Callable[[Path], list[str]],
    source_root: str | Path = "",
) -> str:
    path = str(rec.get("path", ""))
    try:
        line_no = int(rec.get("line", 0) or 0)
    except (TypeError, ValueError):
        line_no = 0
    if path and line_no > 0:
        if source_root:
            # A staged scan reports worktree names but analyzed index bytes.
            # Resolve lexically: an unstaged symlink or deletion must neither
            # redirect fingerprints nor fall back to different worktree bytes.
            relative = Path(_relative_path(path, project_dir, resolve_links=False))
            p = None if relative.is_absolute() or ".." in relative.parts else Path(source_root, relative)
        else:
            p = Path(path)
            # The scan root owns relative paths, not the caller's cwd. A
            # same-named unrelated file must never supply the fingerprint.
            if not p.is_absolute() and project_dir:
                p = Path(project_dir, path)
        if p is not None and p.is_file():
            try:
                lines = source_lines(p)
                if 1 <= line_no <= len(lines):
                    return lines[line_no - 1]
            except OSError:
                pass
    return str(rec.get("message", "")) or str(rec.get("rule", ""))


def _fingerprint(rule: str, rel_path: str, normalized_stmt: str, ordinal: int) -> str:
    src = f"{rule}\x1f{rel_path}\x1f{normalized_stmt}\x1f{ordinal}"
    return hashlib.sha256(src.encode("utf-8", "replace")).hexdigest()[:16]


def _ast_report_sources(doc: dict) -> list[tuple[str, list[dict]]]:
    """Locate report-only AST evidence without adding it to counter findings."""
    reports: list[tuple[str, list[dict]]] = []
    for source in [doc, *(doc.get("scanners", []) or [])]:
        if not isinstance(source, dict):
            continue
        extras = source.get("extras", {})
        if not isinstance(extras, dict) or "ast_findings" not in extras:
            continue
        records = extras["ast_findings"]
        if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
            raise ValueError("extras.ast_findings must be an array of finding objects")
        reports.append((str(source.get("language") or doc.get("language") or "unknown"), records))
    return reports


def _baseline_records(baseline_path: str | Path) -> list[tuple[str, dict]]:
    """Read baseline identities without discarding their accounting metadata."""
    if not baseline_path:
        return []
    p = Path(baseline_path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read baseline {p}: {exc}") from exc
    if isinstance(data, dict):
        records = data.get("findings", [])
        if not isinstance(records, list):
            raise ValueError(f"baseline {p}: findings must be an array")
        items = [("counted", record) for record in records]
        for _, records in _ast_report_sources(data):
            items.extend(("report", record) for record in records)
    elif isinstance(data, list):
        # An explicit fingerprint list has no producer/channel metadata. Its
        # identities remain usable for single source occurrences, not for
        # arbitrary positive project weights.
        items = [("*" if isinstance(record, str) else "counted", record) for record in data]
    else:
        raise ValueError(f"baseline {p}: expected a report object or fingerprint array")
    records = []
    for channel, item in items:
        fp = item.get("fingerprint") if isinstance(item, dict) else item
        if not isinstance(fp, str) or not fp:
            raise ValueError(f"baseline {p}: every finding requires a nonempty fingerprint")
        records.append((channel, item if isinstance(item, dict) else {"fingerprint": fp}))
    return records


def load_baseline_fingerprints(baseline_path: str | Path) -> set[str]:
    """Return recorded identities; merge uses their richer matching policy below."""
    return {record["fingerprint"] for _, record in _baseline_records(baseline_path)}


@dataclass(frozen=True)
class _BaselineAllowance:
    scope: str | None
    severity: int | None
    count: int


class _BaselineFilter:
    """Match already-known occurrences, not just equal fingerprint strings.

    Suppressed baseline records cannot license active findings. A severity
    increase is a new diagnostic, and an aggregate can only subtract the
    recorded number of occurrences. Counted and report-only AST channels are
    separate so advisory evidence cannot suppress a newly counted defect.
    """

    _LEVELS = {"info": 0, "warning": 1, "critical": 2}

    def __init__(self, baseline_path: str | Path = "") -> None:
        self._allowances: dict[tuple[str, str, str], _BaselineAllowance] = {}
        self._remaining: dict[tuple[str, str, str], int] = {}
        for channel, record in _baseline_records(baseline_path):
            suppressed = record.get("suppressed", False)
            if not isinstance(suppressed, bool):
                raise ValueError("baseline finding suppressed must be a boolean")
            if suppressed:
                continue
            severity = record.get("severity")
            if "severity" in record and severity not in ("info", "warning", "critical"):
                raise ValueError("baseline finding severity must be critical, warning or info")
            scope = record.get("scope", "source")
            if scope not in ("source", "project", "project_aggregate"):
                raise ValueError("baseline finding has an invalid scope")
            if scope in ("project", "project_aggregate"):
                count = record.get("count")
                if (not isinstance(count, int) or isinstance(count, bool)
                        or (count != 0 if scope == "project" else count <= 0)):
                    raise ValueError("baseline project finding has an invalid occurrence count")
            else:
                count = 1
                if set(record) == {"fingerprint"}:
                    scope = None
            key = (channel, str(record.get("lang") or ""), record["fingerprint"])
            allowance = _BaselineAllowance(scope, self._LEVELS.get(severity), count)
            if key in self._allowances and self._allowances[key] != allowance:
                raise ValueError(f"baseline has conflicting records for fingerprint {key[-1]}")
            # Duplicate records are not additional occurrence credit.
            self._allowances[key] = allowance
            self._remaining[key] = count

    def retain(self, finding: dict, channel: str = "counted") -> dict | None:
        if not self._allowances:
            # Nothing can be removed. Preserve unfiltered, already-normalized
            # AST reports that historically allow an omitted fingerprint.
            return finding
        fp = finding.get("fingerprint")
        if not isinstance(fp, str) or not fp:
            raise ValueError("finding requires a nonempty fingerprint before baseline filtering")
        lang = str(finding.get("lang") or "")
        key = next((key for key in ((channel, lang, fp), (channel, "", fp),
                                   ("*", lang, fp), ("*", "", fp))
                    if key in self._allowances), None)
        if key is None:
            return finding
        allowance = self._allowances[key]
        scope = finding.get("scope", "source")
        if allowance.scope is not None and allowance.scope != scope:
            return finding
        severity = finding.get("severity", "warning")
        if severity not in ("info", "warning", "critical"):
            raise ValueError("finding severity must be critical, warning or info")
        if allowance.severity is not None and self._LEVELS[severity] > allowance.severity:
            return finding
        if scope == "project":
            return None  # Zero-count notes never consume occurrence credit.
        if scope == "project_aggregate" and allowance.scope != scope:
            return finding  # A bare fingerprint cannot prove any project weight.
        count = _occurrence_count(finding)
        matched = min(count, self._remaining[key])
        self._remaining[key] -= matched
        if matched == count:
            return None
        if matched and scope == "project_aggregate":
            return {**finding, "count": count - matched}
        return finding


def _looks_like_finding(rec: object) -> bool:
    """A sink record must be an object with a rule id and a path."""
    if not isinstance(rec, dict) or "rule" not in rec or "path" not in rec:
        return False
    # Module summary objects share the file but never carry a rule key.
    return not (SCANNER_SUMMARY_KEYS >= set(rec.keys()) and "rule_id" not in rec)


def load_sink(sink: Path) -> Iterator[dict]:
    """Stream findings, accepting blanks and summaries but rejecting corrupt data.

    A truncated record is not an empty result. In particular, silently
    skipping it lets baseline filtering publish zero counts for a failed
    producer. Include the physical line in errors and let merge's atomic
    publication preserve the original summary.
    """
    try:
        with sink.open(encoding="utf-8") as source:
            for line_no, line in enumerate(source, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    raise ValueError(f"invalid findings sink {sink}:{line_no}: {exc}") from exc
                if _looks_like_finding(rec):
                    yield rec
                elif not (isinstance(rec, dict) and "language" in rec
                          and any(key in rec for key in ("files", "critical", "warning", "info"))
                          and not any(key in rec for key in ("rule", "rule_id", "path", "file"))):
                    raise ValueError(f"invalid findings sink {sink}:{line_no}: "
                                     "expected a finding with rule/path or a module summary")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read findings sink {sink}: {exc}") from exc


class _OccurrenceOrdinals:
    """Preserve duplicate fingerprints without retaining every distinct key.

    Small scans stay in memory. After 4096 distinct statements, an ephemeral
    on-disk SQLite table holds the counters, including statements seen before
    the spill. The table lasts for exactly one merge and never caches findings.
    """

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], int] = {}
        self._db: sqlite3.Connection | None = None

    def next(self, path: str, rule: str, statement: str) -> int:
        key = (path, rule, statement)
        if self._db is None:
            if key in self._counts or len(self._counts) < 4096:
                ordinal = self._counts.get(key, 0)
                self._counts[key] = ordinal + 1
                return ordinal
            # An empty filename requests a private temporary database, not an
            # in-memory database; sqlite removes it when the connection closes.
            self._db = sqlite3.connect("")
            self._db.execute("PRAGMA cache_size = -2048")
            self._db.execute("CREATE TABLE counts (path TEXT, rule TEXT, statement TEXT, n INTEGER, "
                             "PRIMARY KEY (path, rule, statement)) WITHOUT ROWID")
            self._db.executemany("INSERT INTO counts VALUES (?, ?, ?, ?)",
                                 ((*key, count) for key, count in self._counts.items()))
            self._counts.clear()
        row = self._db.execute("SELECT n FROM counts WHERE path = ? AND rule = ? AND statement = ?",
                               key).fetchone()
        ordinal = row[0] if row is not None else 0
        self._db.execute("INSERT OR REPLACE INTO counts VALUES (?, ?, ?, ?)", (*key, ordinal + 1))
        return ordinal

    def close(self) -> None:
        if self._db is not None:
            self._db.close()


def _validate_project_record(rec: dict) -> None:
    """Explicit project records preserve counts without inventing source sites."""
    note = rec.get("scope") == "project"
    count = rec.get("count")
    valid_count = type(count) is int and (count == 0 if note else count > 0)  # ubs:ignore[py.comparison.type-equality,py.type-equality] - JSON counts must reject bool and int subclasses.
    valid_severity = (rec.get("severity") == "info" if note
                      else rec.get("severity") in ("info", "warning", "critical"))
    if (
        rec.get("scope") not in ("project", "project_aggregate")
        or any(rec.get(key, "") != "" for key in ("file", "path"))
        or type(rec.get("line")) is not int
        or rec["line"] != 0
        or not valid_severity
        or not valid_count
    ):
        label = "project note" if note else "project aggregate"
        expected = ("severity info and integer count 0" if note else
                    "severity info/warning/critical and positive integer count")
        raise ValueError(
            f"invalid {label}: requires no source path, integer line 0, {expected}"
        )


def _occurrence_count(finding: dict) -> int:
    """Use validated project weights; ordinary source records count once."""
    if finding.get("scope") in ("project", "project_aggregate"):
        return finding["count"]
    return 1


def _validate_baseline_coverage(doc: dict, observed: dict[str, dict[str, int]]) -> None:
    """Do not erase occurrences for which no fingerprint was actually read.

    Weighted project aggregates account for all their active occurrences,
    even when the baseline removes them. Suppressed records and report-only
    AST evidence never supply proof of the summary's active counts.
    A summary may undercount its ledger, but never the reverse: unseen
    occurrences cannot be declared pre-existing (or absent).
    """
    severities = ("critical", "warning", "info")

    def check(summary: dict, available: dict[str, int], label: str) -> None:
        for severity in severities:
            declared = summary.get(severity, 0)
            if not isinstance(declared, int) or isinstance(declared, bool) or declared < 0:
                raise ValueError(f"cannot apply baseline: {label} {severity} count "
                                 "must be a nonnegative integer")
            accounted = available.get(severity, 0)
            if declared > accounted:
                raise ValueError(f"cannot apply baseline: {label} reports {declared} {severity} "
                                 f"occurrences but the findings ledger accounts for {accounted}")

    scanners = doc.get("scanners", []) or []
    if not isinstance(scanners, list) or any(not isinstance(s, dict) for s in scanners):
        raise ValueError("cannot apply baseline: scanners must be an array of objects")
    for scanner in scanners:
        lang = str(scanner.get("language") or "")
        check(scanner, observed.get(lang, {}), lang or "unnamed scanner")
    totals = doc.get("totals", {})
    if not isinstance(totals, dict):
        raise ValueError("cannot apply baseline: totals must be an object")
    check(totals, {severity: sum(counts.get(severity, 0) for counts in observed.values())
                   for severity in severities}, "combined summary")


def _normalize(
    rec: dict,
    lang: str,
    source_lines: Callable[[Path], list[str]],
    project_dir: str | Path = "",
    ordinals: _OccurrenceOrdinals | None = None,
    source_root: str | Path = "",
) -> dict:
    project_scoped = rec.get("scope") in ("project", "project_aggregate")
    if project_scoped:
        # Validate original types before ordinary source normalization can
        # turn malformed line/count metadata into an apparently valid zero.
        _validate_project_record(rec)
    if not isinstance(rec.get("rule"), str) or not rec["rule"].strip():
        raise ValueError("finding requires a nonempty rule id")
    if not isinstance(rec.get("path"), str):
        raise ValueError("finding requires a string source path")
    if rec.get("severity", "warning") not in ("critical", "warning", "info"):
        raise ValueError("finding severity must be critical, warning or info")
    if not isinstance(rec.get("suppressed", False), bool):
        raise ValueError("finding suppressed must be a boolean")
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
    rel_path = _relative_path(path, project_dir, resolve_links=not bool(source_root))
    stmt = _extract_statement(rec, project_dir, source_lines, source_root)
    norm_stmt = normalize_statement(stmt)
    ordinal = ordinals.next(rel_path, rule, norm_stmt) if ordinals is not None else 0
    fp = _fingerprint(rule, rel_path, norm_stmt, ordinal)
    normalized = {
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
    if project_scoped:
        normalized["scope"] = rec["scope"]
        normalized["count"] = rec["count"]
    return normalized


def merge(
    tmp_dir: Path,
    combined_path: Path,
    *,
    project_dir: str | Path = "",
    source_root: str | Path = "",
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
    if new_only and not baseline_path:
        raise ValueError("new-only filtering requires a baseline path")

    # A monolith may contribute thousands of findings. Decode and split it
    # once, rather than once per finding. Keep only eight recent source files,
    # and discard the cache after this merge so the next run sees edits.
    @lru_cache(maxsize=8)
    def source_lines(path: Path) -> list[str]:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()

    ordinals = _OccurrenceOrdinals()
    count = 0
    counts_by_lang: dict[str, dict[str, int]] = {}
    observed_by_lang: dict[str, dict[str, int]] = {}
    baseline = _BaselineFilter(baseline_path if new_only else "")
    try:
        # The normalized ledger can be much larger than its source tree. Keep
        # it on disk throughout: neither raw records, normalized records nor
        # the final serialized document need a whole-report in-memory copy.
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as findings:
            for sink in sorted(Path(tmp_dir).glob("*.findings.json")):
                lang = sink.name.split(".", 1)[0]
                saw_record = False
                for rec in load_sink(sink):
                    saw_record = True
                    finding = _normalize(rec, lang, source_lines, project_dir=project_dir,
                                         ordinals=ordinals, source_root=source_root)
                    observed = observed_by_lang.setdefault(lang, {"critical": 0, "warning": 0, "info": 0})
                    # Summary counts are suppression-aware. A suppressed
                    # record cannot account for missing active diagnostics.
                    if not finding["suppressed"]:
                        observed[finding["severity"]] += _occurrence_count(finding)
                    # Assign occurrence ordinals BEFORE filtering. Otherwise
                    # duplicates after a baseline match acquire its identity.
                    finding = baseline.retain(finding)
                    if finding is None:
                        continue
                    findings.write(json.dumps(finding) + "\n")
                    count += 1
                    if not finding["suppressed"] and finding["severity"] in ("critical", "warning", "info"):
                        counts = counts_by_lang.setdefault(lang, {"critical": 0, "warning": 0, "info": 0})
                        counts[finding["severity"]] += _occurrence_count(finding)
                if saw_record:
                    for scanner in doc.get("scanners", []) or []:
                        if isinstance(scanner, dict) and scanner.get("language") == lang:
                            scanner["findings_sink"] = True

            ast_reports = _ast_report_sources(doc)
            for lang, records in ast_reports:
                normalized = []
                for record in records:
                    if "rule_id" in record and "file" in record:
                        finding = record
                    elif _looks_like_finding(record):
                        finding = _normalize(record, lang, source_lines, project_dir=project_dir,
                                             ordinals=ordinals, source_root=source_root)
                    else:
                        raise ValueError("AST report finding requires a rule id and source path")
                    finding = baseline.retain(finding, "report")
                    if finding is not None:
                        normalized.append(finding)
                records[:] = normalized

            if baseline_path and new_only:
                _validate_baseline_coverage(doc, observed_by_lang)
                # Accumulate the same weighted totals without grouping copies
                # of every finding by language. Report-only AST evidence never
                # contributes to these counters.
                for scanner in doc.get("scanners", []) or []:
                    if isinstance(scanner, dict):
                        counts = counts_by_lang.get(str(scanner.get("language") or ""), {})
                        for severity in ("critical", "warning", "info"):
                            scanner[severity] = counts.get(severity, 0)
                if not isinstance(doc.get("totals"), dict):
                    doc["totals"] = {}
                for severity in ("critical", "warning", "info"):
                    # Include every producer, even if its scanner metadata is
                    # absent; the ledger, not a partial metadata list, defines
                    # the retained findings.
                    doc["totals"][severity] = sum(counts[severity] for counts in counts_by_lang.values())
                # Execution state is invariant under baseline filtering (#104).

            if count or ast_reports or (baseline_path and new_only):
                # Publish only after all records have been normalized and the
                # full JSON is written. A read, validation or disk-write error
                # must leave the original summary usable for a partial report.
                with tempfile.TemporaryDirectory(prefix=".ubs-findings-", dir=combined_path.parent) as stage_dir:
                    staged = Path(stage_dir) / "combined.json"
                    with staged.open("w", encoding="utf-8") as output:
                        output.write("{")
                        for key, value in doc.items():
                            if key == "findings":
                                continue
                            output.write(json.dumps(key) + ": ")
                            json.dump(value, output)
                            output.write(", ")
                        output.write('"findings": [')
                        findings.seek(0)
                        for index, line in enumerate(findings):
                            if index:
                                output.write(", ")
                            output.write(line.rstrip("\n"))
                        output.write("]}")
                    os.replace(staged, combined_path)
    except (OSError, sqlite3.Error) as exc:
        raise ValueError(f"cannot assemble findings: {exc}") from exc
    finally:
        ordinals.close()
    return count


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
    ast_reports = _ast_report_sources(doc)
    ast_languages = {lang for lang, _ in ast_reports}

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
        if lang in ast_languages:
            driver_name += "-heuristics"
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
            project_scoped = f.get("scope") in ("project", "project_aggregate")
            if project_scoped:
                _validate_project_record(f)
            rule_id = str(f.get("rule_id") or f.get("rule") or "")
            sev = str(f.get("severity") or "warning").lower()
            level = "error" if sev == "critical" else ("warning" if sev == "warning" else "note")
            msg = str(f.get("message") or rule_id)
            res: dict = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
            }
            if f.get("scope") == "project":
                # SARIF 2.1.0 sections 3.27.9-10: informational results have
                # level none. Section 3.27.12 permits no source location.
                res["kind"] = "informational"
                res["level"] = "none"
            elif f.get("scope") == "project_aggregate":
                # A positive aggregate retains its diagnostic level. SARIF
                # requires kind fail for results whose level is not none.
                res["kind"] = "fail"
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
            if project_scoped:
                props["scope"] = f["scope"]
                props["count"] = f["count"]
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

    for lang, records in ast_reports:
        # Reuse the normal location/severity/provenance conversion. This leaf
        # document has no extras or scanners, so conversion stops after one
        # level and never counts report-only records in the JSON summary.
        pack = to_sarif(
            {"language": lang, "version": version, "findings": records},
            git_blob_base=git_blob_base, git_top=git_top,
            git_remote=git_remote, git_commit=git_commit,
            sarif_automation_id=sarif_automation_id,
        )
        for run in pack["runs"]:
            run["tool"]["driver"]["name"] = f"ubs-{lang}-ast"
        runs.extend(pack["runs"])

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
