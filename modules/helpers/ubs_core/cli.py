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
import sys
from pathlib import Path

from ubs_core.registry import LAYERS, RunContext, get as get_analyzer, run_layer, run_scan

PROGRAM = "python3 -m ubs_core"


def _load_json_option(value: str | None) -> dict:
    if not value:
        return {}
    data = json.loads(Path(value).read_text(encoding="utf-8"))
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
        p.add_argument("--out", default="-", help="NDJSON output path ('-' = stdout)")
        return p

    for layer in LAYERS:
        add_layer(layer, f"run the {layer} layer")
    add_layer("scan", "run every layer registered for the language")
    return parser


def _write_ndjson(findings_iter, out_path: str) -> int:
    count = 0
    if out_path in ("-", ""):
        for finding in findings_iter:
            sys.stdout.write(json.dumps(finding, ensure_ascii=False) + "\n")
            count += 1
    else:
        with open(out_path, "w", encoding="utf-8") as handle:
            for finding in findings_iter:
                handle.write(json.dumps(finding, ensure_ascii=False) + "\n")
                count += 1
    return count


def _run_layer_cmd(layer: str, args: argparse.Namespace) -> int:
    ctx = RunContext(
        lang=args.lang,
        files=_read_files_from(args.files_from),
        rules=_load_json_option(args.rules),
        profile=_load_json_option(args.profile),
    )
    findings = run_scan(ctx) if layer == "scan" else run_layer(layer, ctx)
    return _write_ndjson(findings, args.out)


def main(argv: list[str] | None = None) -> int:
    # Populate the registry before dispatch; analyzer modules self-register on import.
    from ubs_core import analyzers  # noqa: F401  (side-effect import)

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        from ubs_core.selftest import run_self_tests

        return run_self_tests()

    if not getattr(args, "layer", None):
        parser.print_help(sys.stderr)
        return 2

    if args.layer != "scan":
        try:
            get_analyzer(args.layer, args.lang)
        except KeyError as exc:
            parser.error(str(exc.args[0]))

    return _run_layer_cmd(args.layer, args)


if __name__ == "__main__":
    raise SystemExit(main())
