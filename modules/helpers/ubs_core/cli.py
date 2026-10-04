"""ubs_core.cli — command line interface for the shared analyzer package (bead A2).

Usage:
    python3 -m ubs_core <layer> --lang <l> --files-from <nul-list> [--rules <pack.json>]
                        [--profile <path>] [--out <ndjson>]
    python3 -m ubs_core scan ...          # every layer registered for the language
    python3 -m ubs_core --self-test

`<layer>` is one of: taint, guards, narrowing, lifecycle, ctcompare, regex, prefilter.
`--files-from` names a file holding a NUL-separated path list (newline-separated is
accepted as a fallback for manual runs). Findings are written one JSON object per
line, either to `--out` or to stdout when `--out` is `-`/absent.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from ubs_core.io import parse_ndjson_lines
from ubs_core.registry import (
    LAYERS, RunContext, analyzers_for_lang, get as get_analyzer, run_layer, run_scan,
)

PROGRAM = "python3 -m ubs_core"


def _worker_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("jobs must be an integer between 1 and 64") from exc
    if not 1 <= count <= 64:
        raise argparse.ArgumentTypeError("jobs must be an integer between 1 and 64")
    return count


def _load_json_option(value: str | None) -> dict:
    if not value:
        return {}
    try:
        data = json.loads(Path(value).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"profile/rules JSON is not valid JSON: {value}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"profile/rules JSON must be an object: {value}")
    return data


def _read_files_from(path: str | None) -> list[Path]:
    if not path or path == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(path).read_bytes()
    if b"\0" in data:
        entries = data.split(b"\0")
    else:
        entries = data.splitlines()
    return [Path(raw.decode("utf-8", "surrogateescape")) for raw in entries if raw.strip()]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROGRAM, description="UBS shared analyzer core (bead A2)")
    parser.add_argument("--self-test", action="store_true", help="run embedded analyzer unit tests and exit")
    sub = parser.add_subparsers(dest="layer")

    def add_layer(name: str, help_text: str) -> "argparse.ArgumentParser":
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--lang", required=True, help="target language (python, java, rust, ...)")
        p.add_argument("--files-from", default="-", help="NUL-separated file list ('-' = stdin)")
        p.add_argument("--rules", default=None, help="rule pack JSON")
        p.add_argument("--profile", default=None, help="profile JSON (e.g. disabled_rules)")
        p.add_argument("--jobs", type=_worker_count, default=1,
                       help="analysis workers (1–64); cross-file input scopes are preserved")
        p.add_argument("--out", default="-", help="NDJSON output path ('-' = stdout)")
        return p

    for layer in LAYERS:
        add_layer(layer, f"run the {layer} layer")
    add_layer("scan", "run every layer registered for the language")
    suppress = sub.add_parser(
        "suppress",
        help="filter NDJSON findings through ubs:ignore statement-interval suppression (bead A7)",
    )
    suppress.add_argument("--lang", required=True, help="language of the scanned sources")
    suppress.add_argument("--findings", default="-", help="NDJSON findings file ('-' = stdin)")
    suppress.add_argument("--out", default="-", help="NDJSON output path ('-' = stdout)")
    fm = sub.add_parser(
        "findings-merge",
        help="merge per-module NDJSON findings sinks into the combined summary (bead K2)",
    )
    fm.add_argument("--tmp-dir", required=True, help="run temp dir holding <lang>.findings.json sinks")
    fm.add_argument("--combined", required=True, help="combined summary JSON document")
    fm.add_argument("--project-dir", default="", help="project directory for relative path resolution")
    fm.add_argument("--source-root", default="", help="source snapshot used to scan the reported project paths")
    fm.add_argument("--baseline", default="", help="baseline JSON document to compare against")
    fm.add_argument("--new-only", action="store_true", help="report only findings absent from baseline")
    fs = sub.add_parser(
        "findings-sarif",
        help="generate SARIF 2.1.0 document from combined summary findings (bead K2)",
    )
    fs.add_argument("--combined", required=True, help="combined summary JSON document")
    fs.add_argument("--blob", default="", help="git blob URL base for permalinks")
    fs.add_argument("--top", default="", help="git toplevel path")
    fs.add_argument("--repo", default="", help="git remote repository URI")
    fs.add_argument("--rev", default="", help="git commit SHA")
    fs.add_argument("--auto", default="", help="SARIF automation ID")
    exp = sub.add_parser(
        "explain",
        help="explain a rule: message, remediation, fixture examples, confidence, category (bead K3)",
    )
    exp.add_argument("rule_id", nargs="?", default=None, help="rule identifier to explain")
    exp.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    exp.add_argument("--repo-root", default=None, help="repository root path")
    exp.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return parser


def _run_suppress(args: argparse.Namespace) -> int:
    """Filter NDJSON findings through ubs:ignore statement-interval suppression."""
    import json

    from ubs_core.suppression import build_index

    if args.findings in ("-", ""):
        raw_lines = sys.stdin.read().splitlines()
    else:
        raw_lines = Path(args.findings).read_text(encoding="utf-8").splitlines()
    findings = parse_ndjson_lines(raw_lines, args.findings or "<stdin>")

    indexes: dict[str, object] = {}
    kept: list[dict] = []
    for finding in findings:
        path = str(finding.get("path", ""))
        if path not in indexes:
            try:
                text = Path(path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            indexes[path] = build_index(text, lang=args.lang)
        index = indexes[path]
        line = int(finding.get("line", 0) or 0)
        if index.is_suppressed(line, str(finding.get("rule", ""))):
            continue
        kept.append(finding)

    _write_ndjson(kept, args.out)
    return 0


def _write_ndjson(findings_iter, out_path: str) -> int:
    """Publish a complete analyzer result, never a prefix from a failed run.

    Stage output on disk before touching the destination. This also bounds
    writer memory independently of report size. A file target is replaced
    atomically in its own directory; stdout is copied only after every finding
    has been produced and encoded successfully. A broken stdout transfer can
    still be partial and is reported as an error, never a successful scan.
    """
    def write(handle):
        count = 0
        try:
            for finding in findings_iter:
                handle.write(json.dumps(finding, ensure_ascii=False, allow_nan=False) + "\n")
                count += 1
        except SystemExit as exc:
            # Only the CLI owns process completion. An analyzer calling
            # sys.exit(0) has not completed its requested finding stream.
            raise RuntimeError("Analyzer exited before report completion") from exc
        handle.flush()
        return count

    if out_path in ("-", ""):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8", newline="\n") as staged:
            count = write(staged)
            staged.seek(0)
            shutil.copyfileobj(staged, sys.stdout, length=65536)
            sys.stdout.flush()
            return count

    destination = Path(out_path).absolute()
    try:
        if not stat.S_ISREG(destination.lstat().st_mode):
            raise ValueError("--out must name a regular file, not a symlink or special file")
    except FileNotFoundError:
        pass
    # The temporary file and rename share a filesystem. Generated reports
    # are owner-only on POSIX, including when replacing a public report.
    with tempfile.TemporaryDirectory(prefix=".ubs-output-", dir=destination.parent) as directory:
        staged = Path(directory) / "findings.ndjson"
        with staged.open("w", encoding="utf-8", newline="\n") as handle:
            count = write(handle)
            staged.chmod(0o600)
        os.replace(staged, destination)
    return count


def _run_layer_cmd(layer: str, args: argparse.Namespace) -> int:
    files = _read_files_from(args.files_from)
    jobs = getattr(args, "jobs", 1)
    rules = _load_json_option(args.rules)
    profile = _load_json_option(args.profile)

    ctx = RunContext(lang=args.lang, files=files, rules=rules, profile=profile)
    findings = run_scan(ctx, jobs=jobs) if layer == "scan" else run_layer(layer, ctx, jobs=jobs)
    try:
        _write_ndjson(findings, args.out)
    finally:
        # Serialization/destination errors can stop consumption while producer
        # queues are full. Close explicitly, not eventually through refcounting
        # or cyclic GC, so the registry releases and joins its worker threads.
        close = getattr(findings, "close", None)
        if close is not None:
            close()
    return 0


def main(argv: list[str] | None = None) -> int:
    # Populate the registry before dispatch; analyzer modules self-register on import.
    from ubs_core import analyzers  # noqa: F401  (side-effect import)

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        from ubs_core.selftest import run_self_tests

        return run_self_tests()

    if args.layer == "findings-merge":
        from ubs_core.findings_merge import merge

        try:
            merged = merge(
                Path(args.tmp_dir),
                Path(args.combined),
                project_dir=args.project_dir,
                source_root=args.source_root,
                baseline_path=args.baseline,
                new_only=args.new_only,
            )
        except ValueError as exc:
            print(f"findings-merge: {exc}", file=sys.stderr)
            return 2
        sys.stdout.write(f"{merged}\n")
        return 0

    if args.layer == "findings-sarif":
        from ubs_core.findings_merge import to_sarif

        try:
            doc = json.loads(Path(args.combined).read_text(encoding="utf-8"))
            sarif = to_sarif(
                doc,
                git_blob_base=args.blob,
                git_top=args.top,
                git_remote=args.repo,
                git_commit=args.rev,
                sarif_automation_id=args.auto,
            )
            sys.stdout.write(json.dumps(sarif, indent=2) + "\n")
            return 0
        except Exception as exc:
            print(f"findings-sarif: {exc}", file=sys.stderr)
            return 2

    if args.layer == "explain":
        from ubs_core.explain import run_explain_cli

        return run_explain_cli(args)

    if not getattr(args, "layer", None):
        parser.print_help(sys.stderr)
        return 2

    if args.layer == "scan":
        if not analyzers_for_lang(args.lang):
            parser.error(f"no analyzers registered for lang={args.lang!r}")
    elif args.layer != "suppress":
        try:
            get_analyzer(args.layer, args.lang)
        except KeyError as exc:
            parser.error(str(exc.args[0]))

    try:
        if args.layer == "suppress":
            return _run_suppress(args)
        return _run_layer_cmd(args.layer, args)
    except SystemExit as exc:
        print(f"{PROGRAM}: analyzer exited before completion (code {exc.code!r})", file=sys.stderr)
        return 2
    except Exception as exc:
        # Analyzer/input/output errors are environment failures. Staged output
        # leaves any previous file report intact and emits no analysis prefix.
        print(f"{PROGRAM}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
