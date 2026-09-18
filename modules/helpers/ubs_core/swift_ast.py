"""ubs_core.swift_ast — consolidated ast-grep scanning for the Swift module.

Runs the single sgconfig produced by `ubs_core.swift_rules.generate` (one
`ast-grep scan -c <config> --json=stream` per path batch), parses the stream
once, and feeds BOTH legacy consumers of the shared AG stream:

  ctx.ast_records  source records including expression and METHOD capture
                   ranges, consumed by URLSession lifecycle correlation
  sink records     one record per actual occurrence, before report previews
                   are limited. Exact rule-aware statement suppression
                   and stream/YAML severity with manifest overrides apply.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence
from ubs_core.suppression import SourceSuppressions

_ASTGREP_BIN = "ast-grep"
_BATCH = 400  # paths per scan invocation (argv length safety)


def _sev_map(raw: str) -> str:
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def scan_all(rule_dir: Path, paths: Sequence[Path], ctx, sink, skip=None,
             detail_limit: int = 3, ast_grep_bin: str = _ASTGREP_BIN,
             errors: list[str] | None = None) -> dict:
    """Run the consolidated sgconfig; populate ctx.ast_records + sink records.

    Records already parsed from a failed batch are kept — a partial result is
    still evidence — but the failure itself is appended to ``errors`` so the
    caller can report the scan as incomplete. Issue #111 (the same shape #103
    fixed for Python): this layer used to swallow launch failures, timeouts and
    non-zero exits, so a rule pack that never ran was indistinguishable from
    one that ran and found nothing.
    """
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
            except FileNotFoundError:
                if errors is not None:
                    errors.append(f"ast-grep unavailable ({ast_grep_bin})")
                continue
            except OSError as exc:
                if errors is not None:
                    errors.append(f"ast-grep could not be launched: {exc}")
                continue
            except subprocess.TimeoutExpired:
                if errors is not None:
                    errors.append(f"ast-grep timed out on {config.name}")
                continue
            # ast-grep exits 0 with no error-level diagnostics and 1 when it
            # found some; anything else is a failed invocation, not a clean
            # one. The legacy behaviour was `|| true` on the scan.
            if proc.returncode not in (0, 1) and errors is not None:
                detail = (proc.stderr or "").strip().splitlines()
                errors.append(
                    f"ast-grep exited {proc.returncode} on {config.name}"
                    + (f": {detail[0][:160]}" if detail else "")
                )
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

    suppressions = SourceSuppressions("swift")
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
        if suppressions.is_suppressed(file_str, line_no, rid):
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
