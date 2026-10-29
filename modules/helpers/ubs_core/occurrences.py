"""Bounded occurrence-level JSONL export from the canonical findings ledger.

This opt-in reporting pass follows suppression, thresholds and baseline
filtering. Rule summaries account for ledger weights; scanner and totals
summaries retain their declared counts, exposing any missing occurrences.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tokenize
from typing import IO, Iterator

from ubs_core.findings_merge import _BaselineJSON, _relative_path
from ubs_core.io import temporary_directory

SEVERITIES = ("critical", "warning", "info")
CODE_LIMIT = 4096
SOURCE_WORK_LIMIT = 256 * 1024 * 1024
MAX_RULE_SUMMARIES = 10000
_SCANNER_KEYS = frozenset({
    "language", "status", "files", "critical", "warning", "info", "timestamp",
    "module_error", "message", "version", "module_timeout_secs",
})
_DOCUMENT_KEYS = frozenset({
    "project", "timestamp", "status", "failed_modules", "module_error",
    "error", "reason", "exit_code", "message",
})


def _subset(reader: _BaselineJSON, keys: frozenset[str]) -> dict:
    result = {}
    seen = set()
    for key in reader.members():
        if key in seen:
            raise ValueError(f"duplicate report field: {key}")
        seen.add(key)
        if key in keys:
            result[key] = reader.value()
        else:
            reader.skip()
    return result


def _metadata(path: Path) -> tuple[dict, bool]:
    """Read small report metadata without materializing any findings arrays."""
    doc: dict = {"scanners": []}
    present = False
    seen = set()
    with path.open(encoding="utf-8") as source:
        reader = _BaselineJSON(source)
        for key in reader.members():
            if key in seen:
                raise ValueError(f"duplicate report field: {key}")
            seen.add(key)
            if key == "findings":
                if reader.peek() != "[":
                    raise ValueError("canonical findings must be an array")
                present = True
                reader.skip()
            elif key == "scanners":
                for _ in reader.elements():
                    doc["scanners"].append(_subset(reader, _SCANNER_KEYS))
            elif key == "totals":
                doc[key] = _subset(reader, frozenset((*SEVERITIES, "files")))
            elif key in _DOCUMENT_KEYS:
                doc[key] = reader.value()
            else:
                reader.skip()
        if reader.peek():
            raise ValueError("trailing content after combined JSON")
    if "totals" not in doc:
        raise ValueError("combined report requires totals")
    return doc, present


def _findings(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as source:
        reader = _BaselineJSON(source)
        for key in reader.members():
            if key == "findings":
                for _ in reader.elements():
                    finding = reader.value()
                    if not isinstance(finding, dict):
                        raise ValueError("canonical findings must contain objects")
                    yield finding
            else:
                reader.skip()
        if reader.peek():
            raise ValueError("trailing content after combined JSON")


def _counts(summary: dict) -> dict[str, int]:
    result = {}
    for severity in SEVERITIES:
        value = summary.get(severity, 0)
        if type(value) is not int or value < 0:
            raise ValueError(f"reported {severity} count must be a nonnegative integer")
        result[severity] = value
    return result


class _CodeUnavailable(Exception):
    pass


class _SourceReader:
    """One bounded-chunk, physical-line reader; no whole-source allocation."""

    def __init__(self, path: Path, language: str):
        # A replaced source must not block in open() before the work budget
        # can apply. The preliminary check refuses devices; nonblocking open
        # and fstat also cover replacement with a FIFO after that check.
        if not stat.S_ISREG(path.stat().st_mode):
            raise _CodeUnavailable("source_not_regular")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise _CodeUnavailable("source_not_regular")
            raw = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        try:
            encoding = "utf-8"
            if language == "python":
                def header_line():
                    line = raw.readline(65537)
                    if len(line) > 65536:
                        raise _CodeUnavailable("encoding_header_limit")
                    return line
                encoding, _ = tokenize.detect_encoding(header_line)
                raw.seek(0)
            # Encoding detection and source lines must use the same opened
            # file, even if its pathname changes between those operations.
            self.stream = io.TextIOWrapper(raw, encoding=encoding, errors="strict", newline=None)
        except BaseException:
            raw.close()
            raise
        self.line = 0

    def read(self, requested: int, owner: "_SourceCode") -> tuple[str, bool]:
        if requested <= self.line:
            self.stream.seek(0)
            self.line = 0
        code, truncated = "", False
        while self.line < requested:
            chunk = owner.read_chunk(self.stream, CODE_LIMIT + 2)
            if not chunk:
                raise _CodeUnavailable("source_line_unavailable")
            text = chunk.removesuffix("\n")
            code, truncated = text[:CODE_LIMIT], len(text) > CODE_LIMIT
            while not chunk.endswith("\n"):
                chunk = owner.read_chunk(self.stream, 65536)
                if not chunk:
                    break
                truncated = True
            self.line += 1
        return code, truncated

    def close(self) -> None:
        self.stream.close()


class _SourceCode:
    """Bounded readers and requested-line cache, with an explicit work budget."""

    def __init__(self, project_dir: str | Path, source_root: str | Path):
        self.project = Path(project_dir or ".")
        if self.project.is_file():
            self.project = self.project.parent
        self.source_root = Path(source_root) if source_root else None
        self.readers: OrderedDict[tuple[str, str], _SourceReader | str] = OrderedDict()
        self.lines: OrderedDict[tuple[str, str, int], tuple[str, bool, bool, str]] = OrderedDict()
        self.work = 0

    def read_chunk(self, stream: IO[str], size: int) -> str:
        if self.work >= SOURCE_WORK_LIMIT:
            raise _CodeUnavailable("code_work_limit")
        chunk = stream.readline(min(size, SOURCE_WORK_LIMIT - self.work))
        self.work += len(chunk)
        return chunk

    def _path(self, path: str) -> Path:
        if self.source_root is not None:
            relative = Path(_relative_path(path, self.project, resolve_links=False))
            if relative.is_absolute() or ".." in relative.parts:
                raise _CodeUnavailable("source_outside_snapshot")
            return self.source_root / relative
        candidate = Path(path)
        return candidate if candidate.is_absolute() else self.project / candidate

    def code(self, path: str, line: int, language: str) -> tuple[str, bool, bool, str]:
        key = (path, language, line)
        if key in self.lines:
            self.lines.move_to_end(key)
            return self.lines[key]
        reader_key = (path, language)
        try:
            if reader_key not in self.readers:
                if len(self.readers) == 8:
                    _, previous = self.readers.popitem(last=False)
                    if isinstance(previous, _SourceReader):
                        previous.close()
                self.readers[reader_key] = _SourceReader(self._path(path), language)
            self.readers.move_to_end(reader_key)
            reader = self.readers[reader_key]
            if isinstance(reader, str):
                raise _CodeUnavailable(reader)
            code, truncated = reader.read(line, self)
            result = (code, True, truncated, "")
        except (OSError, UnicodeError, SyntaxError, LookupError, _CodeUnavailable) as exc:
            reason = str(exc) if isinstance(exc, _CodeUnavailable) else "source_code_unavailable"
            result = ("", False, False, reason)
            if not isinstance(exc, _CodeUnavailable):
                previous = self.readers.pop(reader_key, None)
                if isinstance(previous, _SourceReader):
                    previous.close()
            if reader_key not in self.readers and len(self.readers) < 8:
                self.readers[reader_key] = reason
        self.lines[key] = result
        if len(self.lines) > 1024:
            self.lines.popitem(last=False)
        return result

    def close(self) -> None:
        for reader in self.readers.values():
            if isinstance(reader, _SourceReader):
                reader.close()


@dataclass
class _Accounting:
    accounted: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    emitted: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    unlocated: int = 0
    limited: int = 0
    code_unavailable: int = 0
    code_truncated: int = 0
    locations_unverified: bool = False
    reasons: set[str] = field(default_factory=set)


def _qualification(summary: dict, accounting: _Accounting, *, limit: int,
                   analysis_complete: bool, ledger_present: bool) -> dict:
    declared = _counts(summary)
    counts = {
        severity: {"reported": declared[severity], "accounted": accounting.accounted[severity],
                   "emitted": accounting.emitted[severity],
                   "omitted": max(declared[severity], accounting.accounted[severity]) - accounting.emitted[severity]}
        for severity in SEVERITIES
    }
    mismatch = any(row["reported"] != row["accounted"] for row in counts.values())
    reasons = set(accounting.reasons)
    if mismatch:
        reasons.add("count_mismatch")
    if not ledger_present:
        reasons.add("missing_findings_ledger")
    if not analysis_complete:
        reasons.add("analysis_incomplete")
    if accounting.unlocated:
        reasons.add("unlocated_occurrences")
    if accounting.limited:
        reasons.add("occurrence_limit")
    if accounting.code_unavailable:
        reasons.add("code_unavailable")
    if accounting.code_truncated:
        reasons.add("code_truncated")
    locations_complete = (ledger_present and not mismatch and not accounting.unlocated
                          and not accounting.limited and not accounting.locations_unverified)
    return {
        "schema": "ubs.occurrence-export/1", "limit": limit,
        "complete": (analysis_complete and locations_complete and not accounting.code_unavailable
                     and not accounting.code_truncated and not accounting.reasons),
        "analysis_complete": analysis_complete, "locations_complete": locations_complete,
        "truncated": bool(accounting.limited or accounting.code_truncated),
        "reported": sum(declared.values()), "accounted": sum(accounting.accounted.values()),
        "emitted": sum(accounting.emitted.values()),
        "omitted": sum(row["omitted"] for row in counts.values()),
        "unlocated": accounting.unlocated, "code_unavailable": accounting.code_unavailable,
        "code_truncated": accounting.code_truncated, "reasons": sorted(reasons), "counts": counts,
    }


def _occurrence_id(finding: dict, project_dir: str | Path) -> str:
    identity = [finding["lang"], finding["rule_id"],
                _relative_path(finding["file"], project_dir, resolve_links=False),
                finding["line"], finding["col"], finding["fingerprint"]]
    serialized = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(serialized.encode("ascii")).hexdigest()


def export(combined: str | Path, output: str | Path, *, project_dir: str | Path = "",
           source_root: str | Path = "", max_occurrences: int = 100000,
           tmp_dir: str | Path = "") -> None:
    """Atomically write complete-mode JSONL, explicitly qualifying every limit.

    Source records count once; project aggregates and unusable locations enter
    rule accounting without fabricated source rows. Summaries are emitted even
    when no canonical ledger exists. Malformed input or write errors preserve
    the previous output rather than publishing a prefix as a complete report.
    """
    if type(max_occurrences) is not int or not 1 <= max_occurrences <= 1000000:
        raise ValueError("max-occurrences must be an integer from 1 through 1000000")
    combined, output = Path(combined), Path(output)
    if combined.resolve() == output.resolve():
        raise ValueError("occurrence output must differ from the combined input")
    doc, ledger_present = _metadata(combined)
    scanners = doc["scanners"]
    scanner_languages = set()
    ledgers = {}
    for scanner in scanners:
        lang = scanner.get("language")
        if (not isinstance(lang, str) or not lang or lang in scanner_languages
                or "/" in lang or "\\" in lang or lang in (".", "..")):
            raise ValueError("scanner summaries require distinct nonempty languages")
        scanner_languages.add(lang)
        _counts(scanner)
        ledgers[lang] = (Path(tmp_dir, lang + ".findings.json").is_file()
                        if tmp_dir else ledger_present)
    _counts(doc["totals"])
    project = str(project_dir or doc.get("project") or "")
    timestamp = doc.get("timestamp")
    failed = doc.get("failed_modules") or []
    if not isinstance(failed, list):
        raise ValueError("failed_modules must be an array")
    analysis_complete = (doc.get("status", "ok") == "ok" and not failed and not doc.get("module_error")
                         and all(s.get("status", "ok") == "ok" and not s.get("module_error")
                                 for s in scanners))
    total = _Accounting()
    per_language: dict[str, _Accounting] = {}
    per_rule: dict[tuple[str, str, str], dict] = {}
    source = _SourceCode(project, source_root)
    try:
        with temporary_directory(prefix=".ubs-occurrences-", dir=output.parent) as stage_dir:
            staged = Path(stage_dir) / "occurrences.jsonl"
            with staged.open("w", encoding="utf-8") as stream:
                def write(record):
                    stream.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")

                emitted = 0
                for finding in _findings(combined):
                    if not isinstance(finding.get("suppressed", False), bool):
                        raise ValueError("finding suppressed must be a boolean")
                    if finding.get("suppressed", False):
                        continue
                    weight = finding.get("count", 1)
                    if type(weight) is not int or weight < 0:
                        raise ValueError("finding count must be a nonnegative integer")
                    if weight == 0:
                        continue
                    lang, rule, severity = (finding.get("lang"), finding.get("rule_id"), finding.get("severity"))
                    if (not isinstance(lang, str) or not lang or not isinstance(rule, str)
                            or not rule or severity not in SEVERITIES):
                        raise ValueError("canonical finding requires a language, rule_id and standard severity")
                    local = per_language.setdefault(lang, _Accounting())
                    accounts = (total, local)
                    for account in accounts:
                        account.accounted[severity] += weight
                    rule_key = (lang, rule, severity)
                    rule_row = per_rule.get(rule_key)
                    if rule_row is None:
                        if len(per_rule) >= MAX_RULE_SUMMARIES:
                            raise ValueError(f"occurrence export exceeds {MAX_RULE_SUMMARIES} distinct rule summaries")
                        rule_row = {
                            "type": "rule_summary", "schema": "ubs.occurrence-export/1",
                            "project": project, "timestamp": timestamp, "language": lang,
                            "rule_id": rule, "severity": severity, "reported": 0, "emitted": 0,
                            "omitted": 0, "unlocated": 0,
                        }
                        per_rule[rule_key] = rule_row
                    rule_row["reported"] += weight
                    path, line, col = finding.get("file"), finding.get("line"), finding.get("col", 1)
                    located = (weight == 1 and finding.get("scope") not in ("project", "project_aggregate")
                               and isinstance(path, str) and bool(path) and type(line) is int and line > 0
                               and type(col) is int and col > 0)
                    if not located:
                        rule_row["unlocated"] += weight
                        for account in accounts:
                            account.unlocated += weight
                        continue
                    if emitted >= max_occurrences:
                        for account in accounts:
                            account.limited += 1
                        continue
                    if not isinstance(finding.get("fingerprint"), str) or not finding["fingerprint"]:
                        raise ValueError("canonical source finding requires a fingerprint")
                    finding["col"] = col
                    code, available, truncated, code_reason = source.code(path, line, lang)
                    record = {key: value for key, value in finding.items() if key not in {"lang", "timestamp"}}
                    record.update(type="finding", schema="ubs.occurrence/1", language=lang,
                                  project=project, timestamp=timestamp, count=1,
                                  title=finding.get("title") or finding.get("message") or rule,
                                  occurrence_id=_occurrence_id(finding, source.project), code=code,
                                  code_available=available, code_truncated=truncated)
                    if finding.get("timestamp") is not None:
                        record["finding_timestamp"] = finding["timestamp"]
                    if code_reason:
                        record["code_reason"] = code_reason
                    write(record)
                    emitted += 1
                    rule_row["emitted"] += 1
                    for account in accounts:
                        account.emitted[severity] += 1
                        account.code_unavailable += int(not available)
                        account.code_truncated += int(truncated)
                        if code_reason:
                            account.reasons.add(code_reason)
                for key in sorted(per_rule):
                    row = per_rule[key]
                    row["omitted"] = row["reported"] - row["emitted"]
                    write(row)
                for scanner in scanners:
                    lang = scanner["language"]
                    local = per_language.get(lang, _Accounting())
                    scanner_complete = (scanner.get("status", "ok") == "ok" and not scanner.get("module_error")
                                        and not any(isinstance(f, dict) and f.get("language") == lang for f in failed))
                    qualification = _qualification(scanner, local, limit=max_occurrences,
                                                   analysis_complete=scanner_complete,
                                                   ledger_present=ledgers[lang])
                    if not qualification["locations_complete"]:
                        total.locations_unverified = True
                        total.reasons.add("scanner_locations_incomplete")
                    if "count_mismatch" in qualification["reasons"]:
                        total.reasons.add("scanner_count_mismatch")
                    record = {**scanner, "type": "scanner", "project": project,
                              "timestamp": timestamp, "status": scanner.get("status", "ok"),
                              "occurrence_export": qualification}
                    if scanner.get("timestamp") is not None:
                        record["scanner_timestamp"] = scanner["timestamp"]
                    write(record)
                if set(per_language) - scanner_languages:
                    total.reasons.add("missing_scanner_summary")
                    total.locations_unverified = True
                for severity in SEVERITIES:
                    if sum(s.get(severity, 0) for s in scanners) != doc["totals"].get(severity, 0):
                        total.reasons.add("scanner_totals_mismatch")
                        total.locations_unverified = True
                qualification = _qualification(doc["totals"], total, limit=max_occurrences,
                                               analysis_complete=analysis_complete,
                                               ledger_present=(bool(scanners) and all(ledgers.values())
                                                               if tmp_dir else ledger_present))
                record = {"type": "totals", "project": project, "timestamp": timestamp,
                          "status": doc.get("status", "ok"), "failed_modules": failed,
                          **doc["totals"], "occurrence_export": qualification}
                for key in ("error", "reason", "exit_code", "message"):
                    if key in doc:
                        record[key] = doc[key]
                write(record)
            os.replace(staged, output)
    finally:
        source.close()
