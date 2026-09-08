"""ubs_core.bash_scan — contract-v2 orchestrator for the Bash / POSIX-sh module (bead 7mga.1).

Integrates:
1. Native regex & heuristic detectors for common Bash traps:
   - ((x++)) post-increment failure under set -e
   - local x=$(cmd) return code masking
   - if ! cmd; then rc=$? (always 0)
   - [ $a && $b ] compound operator syntax error
   - eval of variables
   - curl ... | bash unverified remote execution
   - mktemp -u dry-run TOCTOU race
   - cd without || exit
   - read without -r
   - LC_ALL=C assigned without export
2. ast-grep Bash rule pack (via sgconfig-bash.yml)
3. shellcheck integration (when installed on PATH, de-duplicated against native rules)

Emits standard NDJSON sink records and contract summary JSON.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ubs_core.registry import RunContext

MARKER = "ubs:ignore"

_CATEGORY_SLUGS = {
    1: "syntax",
    2: "control-flow",
    3: "security",
    4: "robustness",
    5: "environment",
    6: "shellcheck",
}

_SECTION_HEADERS = {
    1: "1. BASH SYNTAX & ARITHMETIC GOTCHAS",
    2: "2. CONTROL FLOW & EXIT CODES",
    3: "3. SECURITY & DANGEROUS COMMANDS",
    4: "4. DEFENSIVE PROGRAMMING & ROBUSTNESS",
    5: "5. ENVIRONMENT & LOCALE HYGIENE",
    6: "6. SHELLCHECK ANALYSIS",
}

_SUMMARY_TITLES: dict[str, str] = {
    "bash.arithmetic.post_increment_set_e": "Post-increment ((x++)) returns 1 when x=0 (fails under set -e)",
    "bash.syntax.test_compound_operator": "Single brackets [ ... ] used with && or || compound operator",
    "bash.syntax.posix_bashism": "Bashism in script with POSIX sh shebang",
    "bash.variable.local_command_subst": "local x=$(cmd) masks command exit code",
    "bash.control_flow.negated_if_rc": "Capturing $? inside then of negated if ! cmd always yields 0",
    "bash.security.eval_variable": "Dynamic code execution via eval on variable",
    "bash.security.curl_pipe_bash": "Piping curl/wget directly to bash/sh without verification",
    "bash.security.mktemp_dry_run": "mktemp -u creates a TOCTOU race condition",
    "bash.security.rm_unset_var": "rm with potentially unset or empty variable",
    "bash.robustness.cd_without_exit": "cd without || exit / || return",
    "bash.robustness.read_without_r": "read without -r mangles backslashes",
    "bash.locale.unexported_lc_all": "LC_ALL assigned without export",
}


def slug_for_category(category: int) -> str:
    return _CATEGORY_SLUGS.get(category, f"cat-{category}")


def category_for_slug(slug: str) -> int | None:
    cleaned = slug.strip().lower()
    for cat, name in _CATEGORY_SLUGS.items():
        if name == cleaned:
            return cat
    return None


def parse_skip(skip_str: str | None) -> set[int]:
    if not skip_str:
        return set()
    out: set[int] = set()
    for token in skip_str.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.add(int(token))
            continue
        except ValueError:
            pass
        cat = category_for_slug(token)
        if cat is not None:
            out.add(cat)
    return out


@dataclass(frozen=True)
class NativeCheck:
    rule_id: str
    category: int
    severity: str
    regex: re.Pattern
    title: str
    remediation: str


_NATIVE_CHECKS: list[NativeCheck] = [
    NativeCheck(
        rule_id="bash.arithmetic.post_increment_set_e",
        category=1,
        severity="warning",
        regex=re.compile(r"\(\(\s*(?:[a-zA-Z_][a-zA-Z0-9_]*\+\+|\+\+[a-zA-Z_][a-zA-Z0-9_]*)\s*\)\)"),
        title="Post-increment ((x++)) returns 1 when x=0 (fails under set -e)",
        remediation="Use x=$((x + 1)) or ((x += 1)) || true",
    ),
    NativeCheck(
        rule_id="bash.syntax.test_compound_operator",
        category=1,
        severity="critical",
        regex=re.compile(r"(?:^|[\s;&|])\[\s+[^\]\n]*(?:&&|\|\|)[^\]\n]*\]"),
        title="Single brackets [ ... ] used with && or || compound operator",
        remediation="Use [[ ... ]] in bash, or [ a ] && [ b ] for POSIX portability",
    ),
    NativeCheck(
        rule_id="bash.variable.local_command_subst",
        category=2,
        severity="warning",
        regex=re.compile(r"^\s*(?:local|declare)\s+[a-zA-Z_][a-zA-Z0-9_]*=[\"'\$\{]*(?:\$\((?!\()[^\n]+\)|`[^\n]+`)"),
        title="local x=$(cmd) masks command exit code",
        remediation="Declare and assign separately: local x; x=$(cmd)",
    ),
    NativeCheck(
        rule_id="bash.control_flow.negated_if_rc",
        category=2,
        severity="warning",
        regex=re.compile(r"if\s+!\s+[^;]+;\s*then\s*(?:\n\s*)?(?:[a-zA-Z_][a-zA-Z0-9_]*=)?\$\?"),
        title="Capturing $? inside then of negated if ! cmd always yields 0",
        remediation="Run command without '!' and check if [[ $? -ne 0 ]], or use if cmd; then ... else rc=$?; fi",
    ),
    NativeCheck(
        rule_id="bash.security.eval_variable",
        category=3,
        severity="critical",
        regex=re.compile(r"^\s*eval\s+.*?\$(?:\{)?[a-zA-Z_]"),
        title="Dynamic code execution via eval on variable",
        remediation="Avoid eval with variable input; use bash arrays, indirect expansion ${!var}, or functions",
    ),
    NativeCheck(
        rule_id="bash.security.curl_pipe_bash",
        category=3,
        severity="critical",
        regex=re.compile(r"\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        title="Piping curl/wget directly to bash/sh without verification",
        remediation="Download the script, verify cryptographic checksum/signature, then execute",
    ),
    NativeCheck(
        rule_id="bash.security.mktemp_dry_run",
        category=3,
        severity="critical",
        regex=re.compile(r"\bmktemp\b[^\n;&|]*\s(?:-u\b|--dry-run\b)"),
        title="mktemp -u creates a TOCTOU race condition",
        remediation="Create and open temporary files atomically with mktemp without -u",
    ),
    NativeCheck(
        rule_id="bash.robustness.cd_without_exit",
        category=4,
        severity="warning",
        regex=re.compile(r"^\s*cd\s+([^\n;&|]+?)\s*(?:#.*)?$"),
        title="cd without || exit / || return",
        remediation="Append '|| exit' or '|| return 1' so failures don't run commands in wrong directory",
    ),
    NativeCheck(
        rule_id="bash.robustness.read_without_r",
        category=4,
        severity="warning",
        regex=re.compile(r"^\s*(?:if\s+)?read\b(?![^#\n]*-[a-zA-Z]*r[a-zA-Z]*)[^#\n]*\b[a-zA-Z_]"),
        title="read without -r mangles backslashes",
        remediation="Use 'read -r' to prevent backslash escaping",
    ),
    NativeCheck(
        rule_id="bash.locale.unexported_lc_all",
        category=5,
        severity="warning",
        regex=re.compile(r"^\s*LC_ALL=[^\s;&|\n]+(?:\s*#.*)?$"),
        title="LC_ALL assigned without export",
        remediation="Use 'export LC_ALL=C' so child tools (sort, grep, awk) inherit locale",
    ),
]


def _has_suppression(lines: list[str], lineno: int, rule_id: str) -> bool:
    idx = lineno - 1
    target_lines = []
    if 0 <= idx < len(lines):
        target_lines.append(lines[idx])
    if idx > 0 and (idx - 1) < len(lines):
        target_lines.append(lines[idx - 1])
    for l in target_lines:
        if MARKER in l:
            m = re.search(r"ubs:ignore(?:\[([a-zA-Z0-9_.,-]+)\])?", l)
            if m:
                rules = m.group(1)
                if not rules or rule_id in rules.split(","):
                    return True
    return False


def scan_files_native(
    files: Sequence[Path],
    sink,
    skip: set[int],
    reported_locations: set[tuple[str, int]],
    prefilter: Any = None,
) -> dict[str, int]:
    counters = {"critical": 0, "warning": 0, "info": 0}

    for path in files:
        active_checks = _NATIVE_CHECKS
        cand = None
        if prefilter is not None and not prefilter.is_bypass:
            cand = prefilter.candidate_rules_for(path)
            active_checks = [c for c in _NATIVE_CHECKS if c.rule_id in cand]
            check_bashism = (1 not in skip and "bash.syntax.posix_bashism" in cand)
            if not active_checks and not check_bashism:
                continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = content.splitlines()
        file_str = str(path)

        # Check POSIX sh shebang for bashisms
        is_posix_sh = False
        if lines and lines[0].startswith("#!") and ("bin/sh" in lines[0] or "env sh" in lines[0]):
            is_posix_sh = True

        in_heredoc = False
        heredoc_delimiter = ""
        heredoc_strip_tabs = False

        for lineno, line in enumerate(lines, 1):
            if in_heredoc:
                check_line = line.lstrip("\t") if heredoc_strip_tabs else line
                if check_line.rstrip() == heredoc_delimiter:
                    in_heredoc = False
                    heredoc_delimiter = ""
                continue

            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check if this line starts a heredoc for subsequent lines
            m_hd = re.search(r"(?<!<)<<(-?)\s*(?:'([^']+)'|\"([^\"]+)\"|\\([a-zA-Z_0-9]+)|([a-zA-Z_0-9]+))", line)
            if m_hd:
                delim = m_hd.group(2) or m_hd.group(3) or m_hd.group(4) or m_hd.group(5)
                if delim:
                    in_heredoc = True
                    heredoc_delimiter = delim
                    heredoc_strip_tabs = (m_hd.group(1) == "-")

            is_print_line = bool(re.match(r"^\s*(?:echo|printf|log|warn|warning|info|error|debug)\b", line))
            has_subshell = bool(re.search(r"\$\(|`", line))
            is_static_print = is_print_line and not has_subshell

            if is_posix_sh and 1 not in skip and (cand is None or "bash.syntax.posix_bashism" in cand):
                # Check for bashisms in POSIX sh
                if re.search(r"(?:^|[\s;&|])\[\[\s+", line) or re.search(r"^\s*function\s+[a-zA-Z_]", line):
                    rule_id = "bash.syntax.posix_bashism"
                    if not _has_suppression(lines, lineno, rule_id):
                        key = (file_str, lineno)
                        reported_locations.add(key)
                        counters["warning"] += 1
                        sink.write(json.dumps({
                            "rule": rule_id,
                            "category_id": "bash.syntax",
                            "path": file_str,
                            "line": lineno,
                            "col": 1,
                            "severity": "warning",
                            "message": "Bashism detected in POSIX sh script: use #!/usr/bin/env bash or portable syntax",
                            "suppressed": False,
                        }) + "\n")

            for check in active_checks:
                if check.category in skip:
                    continue
                if is_static_print and check.rule_id in (
                    "bash.security.curl_pipe_bash",
                    "bash.security.eval_variable",
                    "bash.security.mktemp_dry_run",
                    "bash.robustness.cd_without_exit",
                    "bash.robustness.read_without_r",
                    "bash.locale.unexported_lc_all",
                    "bash.syntax.test_compound_operator",
                ):
                    continue
                if check.regex.search(line):
                    if _has_suppression(lines, lineno, check.rule_id):
                        continue
                    key = (file_str, lineno)
                    reported_locations.add(key)
                    counters[check.severity] += 1
                    sink.write(json.dumps({
                        "rule": check.rule_id,
                        "category_id": f"bash.{slug_for_category(check.category)}",
                        "path": file_str,
                        "line": lineno,
                        "col": 1,
                        "severity": check.severity,
                        "message": f"{check.title}: {line.strip()}"[:300],
                        "suppressed": False,
                    }) + "\n")

    return counters


def scan_shellcheck(
    files: Sequence[Path],
    sink,
    skip: set[int],
    reported_locations: set[tuple[str, int]],
) -> dict[str, int]:
    counters = {"critical": 0, "warning": 0, "info": 0}
    if 6 in skip or not shutil.which("shellcheck"):
        return counters

    # Run shellcheck on batches of files
    batch_size = 50
    file_strs = [str(p) for p in files]
    for i in range(0, len(file_strs), batch_size):
        batch = file_strs[i:i + batch_size]
        try:
            proc = subprocess.run(
                ["shellcheck", "-f", "json", *batch],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue

        try:
            items = json.loads(proc.stdout or "[]")
        except ValueError:
            continue

        for it in items:
            file_p = it.get("file", "")
            lineno = int(it.get("line", 1) or 1)
            col = int(it.get("column", 1) or 1)
            code = it.get("code")
            msg = it.get("message", "")
            level = it.get("level", "info")

            # De-duplicate against native detectors
            if (file_p, lineno) in reported_locations:
                continue

            # Skip style/informational checks that produce noise on valid scripts
            if code in (2148, 2034, 2155, 2164, 2162):
                continue

            if level == "error":
                sev = "critical"
            elif level == "warning":
                sev = "warning"
            else:
                sev = "info"

            rule_id = f"bash.shellcheck.SC{code}"
            counters[sev] += 1
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": "bash.shellcheck",
                "path": file_p,
                "line": lineno,
                "col": col,
                "severity": sev,
                "message": f"SC{code}: {msg}"[:300],
                "suppressed": False,
            }) + "\n")

    return counters


def scan_ast_rules(
    rule_dir: Path,
    files: Sequence[Path],
    sink,
    skip: set[int],
    reported_locations: set[tuple[str, int]],
    prefilter: Any = None,
) -> dict[str, int]:
    counters = {"critical": 0, "warning": 0, "info": 0}
    config = rule_dir / "sgconfig-bash.yml"
    if not config.is_file() or not shutil.which("ast-grep"):
        return counters

    target_files = files
    if prefilter is not None and not prefilter.is_bypass:
        target_files = prefilter.ast_files
    if not target_files:
        return counters

    batch_size = 50
    file_strs = [str(p) for p in target_files]
    for i in range(0, len(file_strs), batch_size):
        batch = file_strs[i:i + batch_size]
        try:
            proc = subprocess.run(
                ["ast-grep", "scan", "-c", str(config), "--json=stream", *batch],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
            except ValueError:
                continue
            rule_id = m.get("ruleId") or ""
            file_p = m.get("file") or ""
            rng = m.get("range", {}).get("start", {})
            lineno = int(rng.get("line", 0)) + 1
            col = int(rng.get("column", 0)) + 1
            message = m.get("message") or rule_id

            if (file_p, lineno) in reported_locations:
                continue

            sev_raw = (m.get("severity") or "warning").lower()
            if sev_raw in ("error", "critical", "fatal"):
                sev = "critical"
            elif sev_raw in ("warning", "warn"):
                sev = "warning"
            else:
                sev = "info"

            cat = 3 if "security" in rule_id else (2 if "variable" in rule_id else 1)
            if cat in skip:
                continue

            counters[sev] += 1
            reported_locations.add((file_p, lineno))
            sink.write(json.dumps({
                "rule": rule_id,
                "category_id": f"bash.{slug_for_category(cat)}",
                "path": file_p,
                "line": lineno,
                "col": col,
                "severity": sev,
                "message": f"{rule_id}: {message}"[:300],
                "suppressed": False,
            }) + "\n")

    return counters


def _render_text(args, files: Sequence[Path], counters: dict[str, int]) -> None:
    sink_path = Path(args.sink)
    records: list[dict] = []
    if sink_path.is_file():
        for line in sink_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if not rec.get("suppressed"):
                    records.append(rec)
            except ValueError:
                continue

    by_cat: dict[int, list[dict]] = {}
    for r in records:
        cat_slug = r.get("category_id", "").replace("bash.", "")
        cat_num = category_for_slug(cat_slug) or 1
        by_cat.setdefault(cat_num, []).append(r)

    out_lines: list[str] = [
        f"UBS module: Bash (contract v2) — {args.project_dir}",
        f"Files scanned: {len(files)}",
        "",
        "Summary Statistics:",
        f"Files scanned: {len(files)}",
        f"Critical issues: {counters['critical']}",
        f"Warning issues: {counters['warning']}",
        f"Info items: {counters['info']}",
        f"Report generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
    ]

    for cat in sorted(_SECTION_HEADERS.keys()):
        out_lines.append(_SECTION_HEADERS[cat])
        cat_recs = by_cat.get(cat, [])
        if not cat_recs:
            out_lines.append("good: clean")
            continue
        for r in cat_recs:
            rule = r.get("rule", "")
            msg = r.get("message", rule)
            p = r.get("path", "")
            ln = r.get("line", 1)
            sev = r.get("severity", "info")
            out_lines.append(f"[{sev}] {rule}: {msg}")
            out_lines.append(f"    {p}:{ln}")

    text_body = "\n".join(out_lines) + "\n"
    if getattr(args, "text_out", None):
        Path(args.text_out).write_text(text_body, encoding="utf-8")
    else:
        sys.stdout.write(text_body)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ubs_core.bash_scan")
    parser.add_argument("--files-from", required=True)
    parser.add_argument("--sink", required=True)
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--skip", default="")
    parser.add_argument("--fail-on-warning", action="store_true")
    parser.add_argument("--text-out")
    parser.add_argument("--json-out")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--ast-rule-dir")
    parser.add_argument("--no-shellcheck", action="store_true")
    parser.add_argument("--project", default="")
    args = parser.parse_args(argv)

    raw_list = Path(args.files_from).read_bytes()
    files = [
        Path(p.decode("utf-8", errors="replace"))
        for p in raw_list.split(b"\0")
        if p.strip()
    ]
    skip = parse_skip(args.skip)

    sink_path = Path(args.sink)
    sink_path.parent.mkdir(parents=True, exist_ok=True)

    from ubs_core.prefilter import build_prefilter_index, run_prefilter

    ast_rules_input = []
    if args.ast_rule_dir and Path(args.ast_rule_dir).is_dir():
        rules_dir = Path(args.ast_rule_dir) / "rules"
        search_dir = rules_dir if rules_dir.is_dir() else Path(args.ast_rule_dir)
        for rf in sorted(search_dir.glob("*.yml")) + sorted(search_dir.glob("*.yaml")):
            try:
                text = rf.read_text(encoding="utf-8", errors="ignore")
                id_m = re.search(r"id:\s*(\S+)", text)
                rid = id_m.group(1) if id_m else rf.stem
                ast_rules_input.append((rid, text))
            except OSError:
                pass

    all_patterns = list(_NATIVE_CHECKS) + [
        NativeCheck(
            rule_id="bash.syntax.posix_bashism",
            category=1,
            severity="warning",
            regex=re.compile(r"\[\[|\bfunction\b"),
            title="Bashism in script with POSIX sh shebang",
            remediation="Use portable POSIX sh syntax",
        )
    ]

    from ubs_core.cache import CapturingSink, ScanCache

    cache = ScanCache(
        lang="bash",
        project_dir=args.project_dir or args.project or ".",
        skip=args.skip,
        custom_rules=args.ast_rule_dir,
        extra=f"no_shellcheck={args.no_shellcheck}",
    )
    cached_findings, files_to_scan = cache.partition_files(files)

    capturing_sink = None
    if files_to_scan:
        prefilter_index = build_prefilter_index(
            ast_rules=ast_rules_input,
            patterns=all_patterns,
            analyzers=[],
            lang="bash",
        )
        prefilter_res = run_prefilter(files_to_scan, prefilter_index)

        reported_locations: set[tuple[str, int]] = set()
        capturing_sink = CapturingSink()
        scan_files_native(files_to_scan, capturing_sink, skip, reported_locations, prefilter=prefilter_res)
        if args.ast_rule_dir:
            scan_ast_rules(Path(args.ast_rule_dir), files_to_scan, capturing_sink, skip, reported_locations, prefilter=prefilter_res)
        if not args.no_shellcheck:
            scan_shellcheck(files_to_scan, capturing_sink, skip, reported_locations)
        cache.store_scanned_files(files_to_scan, capturing_sink.by_file)
    else:
        from ubs_core.prefilter import PrefilterResult
        prefilter_res = PrefilterResult(
            files_considered=0,
            files_after_prefilter=0,
            prefilter_ms=0,
            is_bypass=False,
        )

    prefilter_file = os.environ.get("UBS_PREFILTER_FILE")
    if prefilter_file:
        try:
            Path(prefilter_file).write_text(json.dumps(prefilter_res.to_dict()), encoding="utf-8")
        except OSError:
            pass

    with open(sink_path, "w", encoding="utf-8") as sink_file:
        for f in files:
            recs = cached_findings.get(f)
            if recs is None and capturing_sink is not None:
                recs = capturing_sink.get_for_file(f, project_dir=args.project_dir or args.project)
            if recs:
                for r in recs:
                    sink_file.write(json.dumps(r, ensure_ascii=False) + "\n")

    cache_file = os.environ.get("UBS_CACHE_FILE") or (os.path.splitext(sink_path)[0] + ".cache")
    cache.write_stats(cache_file)

    counters = {"critical": 0, "warning": 0, "info": 0}
    # Recount sink records to be 100% accurate
    if Path(sink_path).is_file():
        recount = {"critical": 0, "warning": 0, "info": 0}
        for line in Path(sink_path).read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if not rec.get("suppressed"):
                    sev = rec.get("severity", "info")
                    if sev in recount:
                        recount[sev] += 1
            except ValueError:
                continue
        counters = recount

    exit_code = 1 if counters["critical"] else 0
    if args.fail_on_warning and (counters["critical"] + counters["warning"]) > 0:
        exit_code = 1

    if args.json_out:
        records = [
            json.loads(line)
            for line in Path(sink_path).read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        profile_data = {
            "files_considered": prefilter_res.files_considered if files_to_scan else len(files),
            "files_after_prefilter": prefilter_res.files_after_prefilter if files_to_scan else 0,
            "prefilter_ms": prefilter_res.prefilter_ms if files_to_scan else 0,
            "cache_hits": cache.stats["hits"],
            "cache_misses": cache.stats["misses"],
            "cache_hit_rate": cache.stats["hit_rate"],
        }
        summary = {
            "language": "bash",
            "project": args.project or args.project_dir,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": len(files),
            "critical": counters["critical"],
            "warning": counters["warning"],
            "info": counters["info"],
            "version": args.version,
            "status": "ok",
            "findings": records,
            "extras": {"profile": profile_data},
        }
        if os.environ.get("UBS_PROFILE") == "1":
            summary["profile"] = profile_data
        Path(args.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.text_out:
        _render_text(args, files, counters)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
