"""ubs_core.swift_ast — consolidated ast-grep scanning for the Swift module.

Runs the single sgconfig produced by `ubs_core.swift_rules.generate` (one
`ast-grep scan -c <config> --json=stream` per path batch), parses the stream
once, and feeds BOTH legacy consumers of the shared AG stream:

  ctx.ast_records  source records including expression and METHOD capture
                   ranges, consumed by URLSession lifecycle correlation
  sink records     one record per actual occurrence, before report previews
                   are limited. Same-line/previous-line ubs:ignore suppression
                   and stream/YAML severity with manifest overrides apply.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def _file_lines(path: Path, cache: dict) -> list[str]:
    key = str(path)
    if key not in cache:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                cache[key] = fh.readlines()
        except OSError:
            cache[key] = []
    return cache[key]


def _has_marker(path: Path, line_no: int, cache: dict) -> bool:
    """Legacy check_suppression: same line or the line above."""
    lines = _file_lines(path, cache)
    idx = line_no - 1
    return any(
        0 <= i < len(lines) and "ubs:ignore" in lines[i]
        for i in (idx, idx - 1)
    )


def _sev_map(raw: str) -> str:
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def scan_all(rule_dir: Path, paths: Sequence[Path], ctx, sink, skip=None,
             detail_limit: int = 3, ast_grep_bin: str = _ASTGREP_BIN) -> dict:
    """Run the consolidated sgconfig; populate ctx.ast_records + sink records."""
    counters = {"critical": 0, "warning": 0, "info": 0}
    config = rule_dir / "sgconfig-swift.yml"
    path_list = [Path(p) for p in paths]

    manifest: dict = {}
    manifest_path = rule_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            manifest = {}

    stream: list[dict] = []
    if path_list and config.is_file():
        for start in range(0, len(path_list), _BATCH):
            batch = [str(p) for p in path_list[start : start + _BATCH]]
            try:
                proc = subprocess.run(
                    [ast_grep_bin, "scan", "-c", str(config), "--json=stream", *batch],
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue  # legacy: `|| true` on the scan invocation
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                stream.append(obj)

    # legacy AG_STREAM_FILE semantics: an empty stream means the ast layer is
    # unusable for correlation ("Could not build ast-grep per-file index")
    ctx.ast_stream_ok = bool(stream)
    ctx.ast_records = []
    for obj in stream:
        rid = str(obj.get("ruleId", "") or obj.get("rule_id", "") or obj.get("id", "") or "unknown")
        rng = obj.get("range") or {}
        start = rng.get("start") or {}
        row = int(start.get("row", start.get("line", 0)) or 0)
        col = int(start.get("column", 0) or 0)
        ctx.ast_records.append({
            "rid": rid,
            "file": str(obj.get("file", "") or ""),
            "row": row,
            "col": col,
            "range": rng,
            "method": ((obj.get("metaVariables") or {}).get("single") or {}).get("METHOD") or {},
            "severity": str(obj.get("severity") or obj.get("level") or "info"),
            "message": str(obj.get("message") or ""),
            "lines": str(obj.get("lines") or ""),
        })

    if not stream:
        return counters

    # Cache entries must contain only their own source's occurrences. Preview
    # limits belong to report rendering, after all selected records are joined.
    from ubs_core.swift_scan import slug_for_category

    cache: dict = {}
    for obj in stream:
        rid = str(obj.get("ruleId", "") or obj.get("rule_id", "") or obj.get("id", "") or "unknown")
        file_str = str(obj.get("file", "?") or "?")
        rng = obj.get("range") or {}
        start = rng.get("start") or {}
        row = int(start.get("row", start.get("line", 0)) or 0)
        line_no = row + 1
        col_no = int(start.get("column", 0) or 0) + 1
        message = str(obj.get("message") or rid)
        severity = _sev_map(str(obj.get("severity") or obj.get("level") or "info"))
        override = (manifest.get(rid) or {}).get("severity")
        if override:
            severity = _sev_map(override)
        meta = (manifest.get(rid) or {})
        category = int(meta.get("category", 0) or 0)

        # legacy parity: the AST RULE PACK FINDINGS section is NOT gated by
        # --skip (it sits outside categories 1..23); only marker suppression
        # applies
        if _has_marker(Path(file_str), line_no, cache):
            continue

        source_path = str(Path(file_str).resolve())
        lines = (obj.get("lines") or "").strip().splitlines()
        code = (lines[0] if lines else "").strip()
        counters[severity] = counters.get(severity, 0) + 1
        record = {
            "rule": rid,
            "source": "ast-grep",
            "category_id": f"swift.{slug_for_category(category)}" if category else "",
            "path": source_path,
            "line": line_no,
            "col": col_no,
            "severity": severity,
            "count": 1,
            "title": f"{rid}: {message}",
            "message": f"{rid}: {message}",
            "suppressed": False,
            "samples": [{"path": source_path, "line": line_no, "col": col_no, "code": code}],
        }
        sink.write(json.dumps(record, ensure_ascii=False) + "\n")
    return counters
