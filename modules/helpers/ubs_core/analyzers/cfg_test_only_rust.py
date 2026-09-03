"""ubs_core.analyzers.cfg_test_only_rust — resolve #[cfg(test)]-only modules (bead A2).

Logic moved verbatim from modules/helpers/cfg_test_only_modules_rust.py, which
remains as a thin entrypoint. Part of the fix for GH #80: `--exclude-tests`
must also exclude files that are test-only because every `mod name;`
declaration referencing them is gated by `#[cfg(test)]` (directly or
transitively via another test-only file). A file that is also referenced by at
least one non-test `mod` declaration stays included.

Input:  --files-from FILE  (newline-delimited paths of the authoritative scan
        set; only paths from this set are ever reported)
Output: one path per line (spelled exactly as in the input list) for every
        file that is test-only.

Also exposes a structured `run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

# `mod name;` declaration (out-of-line module), optionally pub / pub(...).
MOD_DECL_RE = re.compile(
    r"^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
# A single outer attribute at the start of the remaining line text.
ATTR_PREFIX_RE = re.compile(r"^\s*#\[([^\]]*)\]")
# cfg(test) / cfg(all(test, ...)) / cfg(any? no - any(test,..) is NOT test-only)
CFG_TEST_RE = re.compile(r"^\s*cfg\s*\(\s*(?:test\s*\)|all\s*\(\s*test\s*[,)])")
PATH_ATTR_RE = re.compile(r'^\s*path\s*=\s*"([^"]+)"\s*$')
CRATE_ROOT_NAMES = {"lib.rs", "main.rs", "mod.rs"}


def strip_line_comment(line: str) -> str:
    """Drop // comments while respecting simple string literals."""
    out = []
    quote = ""
    escape = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == '"':
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def resolve_targets(declaring: Path, name: str, path_attr: str | None) -> list[Path]:
    """Candidate files a `mod name;` in `declaring` refers to."""
    parent = declaring.parent
    if path_attr:
        return [parent / path_attr]
    if declaring.name in CRATE_ROOT_NAMES:
        base = parent
    else:
        base = parent / declaring.stem
    return [base / f"{name}.rs", base / name / "mod.rs"]


def compute_test_only(raw_entries: list[str]) -> list[str]:
    """Return the test-only subset of a scan set, spelled as given and sorted.

    Only paths from the authoritative scan set are ever reported; unreferenced
    files are never test-only.
    """
    entries = [e for e in raw_entries if e.strip() and e.endswith(".rs")]
    by_resolved: dict[Path, str] = {}
    for entry in entries:
        try:
            by_resolved[Path(entry).resolve()] = entry
        except OSError:
            continue

    # target(resolved) -> list of (source_resolved, cfg_test_gated)
    refs: dict[Path, list[tuple[Path, bool]]] = {}

    for resolved, entry in by_resolved.items():
        try:
            text = Path(entry).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        pending_cfg_test = False
        pending_path: str | None = None
        for raw in text.splitlines():
            line = strip_line_comment(raw)
            if not line.strip():
                continue
            # Consume any leading attributes (supports `#[cfg(test)] mod x;`
            # on one line as well as attributes on preceding lines).
            rest = line
            while True:
                m = ATTR_PREFIX_RE.match(rest)
                if not m:
                    break
                inner = m.group(1)
                if CFG_TEST_RE.match(inner):
                    pending_cfg_test = True
                pm = PATH_ATTR_RE.match(inner)
                if pm:
                    pending_path = pm.group(1)
                rest = rest[m.end():]
            if not rest.strip():
                # Attribute-only line: state carries to the next line.
                continue
            dm = MOD_DECL_RE.match(rest)
            if dm:
                for target in resolve_targets(Path(entry), dm.group(1), pending_path):
                    try:
                        tr = target.resolve()
                    except OSError:
                        continue
                    if tr in by_resolved:
                        refs.setdefault(tr, []).append((resolved, pending_cfg_test))
            # Any non-attribute line terminates the pending attribute state.
            pending_cfg_test = False
            pending_path = None

    # Fixpoint: test-only if every reference is cfg(test)-gated or comes from
    # a file that is itself test-only. Unreferenced files are never test-only.
    test_only: set[Path] = set()
    changed = True
    while changed:
        changed = False
        for target, sources in refs.items():
            if target in test_only or not sources:
                continue
            if all(gated or src in test_only for src, gated in sources):
                test_only.add(target)
                changed = True

    return [by_resolved[r] for r in sorted(test_only, key=lambda p: by_resolved[p])]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--files-from", required=True)
    args = ap.parse_args()

    try:
        raw_entries = Path(args.files_from).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"cannot read file list: {exc}", file=sys.stderr)
        return 1

    for entry in compute_test_only(raw_entries):
        print(entry)
    return 0


_MESSAGE = "file is reachable only through #[cfg(test)]-gated `mod` declarations"


def run(ctx: RunContext) -> Iterable[dict]:
    for entry in compute_test_only([str(p) for p in ctx.files]):
        yield {
            "rule": "rust.prefilter.test_only_module",
            "path": entry,
            "line": 1,
            "layer": "prefilter",
            "lang": "rust",
            "severity": "info",
            "message": _MESSAGE,
        }


def _write_fixture(src: Path, lib_text: str) -> list[Path]:
    src.mkdir(parents=True, exist_ok=True)
    (src / "lib.rs").write_text(lib_text, encoding="utf-8")
    (src / "tests_support.rs").write_text(
        "pub fn helper_value() -> u32 {\n    let missing: Option<u32> = None;\n    missing.unwrap()\n}\n",
        encoding="utf-8",
    )
    return [src / "lib.rs", src / "tests_support.rs"]


def _selftest_cfg_gated_only() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_cfg_test_only_rust_") as tmp:
        files = _write_fixture(
            Path(tmp) / "src", "#[cfg(test)]\nmod tests_support;\n"
        )
        result = compute_test_only([str(p) for p in files])
    assert result == [str(files[1])], result


def _selftest_nongated_ref_keeps_file() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_cfg_test_only_rust_") as tmp:
        files = _write_fixture(Path(tmp) / "src", "mod tests_support;\n")
        result = compute_test_only([str(p) for p in files])
    assert result == [], result


def _selftest_run(tmp_prefix: str = "ubs_core_cfg_test_only_rust_run_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        files = _write_fixture(
            Path(tmp) / "src", "#[cfg(test)]\nmod tests_support;\n"
        )
        findings = list(run(RunContext(lang="rust", files=files)))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "rust.prefilter.test_only_module"
    assert findings[0]["path"] == str(files[1])
    assert findings[0]["severity"] == "info"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("cfg_gated_only_is_test_only", _selftest_cfg_gated_only),
    ("nongated_ref_keeps_file", _selftest_nongated_ref_keeps_file),
    ("run_reports_test_only", _selftest_run),
)

register(Analyzer(layer="prefilter", lang="rust", name="cfg_test_only_rust", run=run, selftests=SELF_TESTS))
