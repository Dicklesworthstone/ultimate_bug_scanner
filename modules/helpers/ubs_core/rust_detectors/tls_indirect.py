"""ubs_core.rust_detectors.tls_indirect — TLS verification disabled via flag (bead 0xjg.7).

Port of rust_tls_indirect_matches (modules/ubs-rust.sh 5461-5537), the
composite part of the legacy tls_insecure check: flags
``.danger_accept_invalid_certs(...)`` / ``.danger_accept_invalid_hostnames(...)``
calls whose argument names a ``const``/``static``/``let [mut] ... = true;``
binding collected earlier in the same file (comment-stripped lines;
lines whose stripped form is empty or comment-only are skipped, and the
``ubs:ignore`` probe runs on the comment-stripped line, exactly as legacy).

Path spelling (ported verbatim): the legacy heredoc resolved
UBS_RUST_FILE_LIST entries via ``Path(entry).resolve()`` and printed
``relpath(path)`` against the resolved root argument (the directory itself,
or its parent when the root is a file). ``find(files, root=None)`` keeps
that: pass the project root as ``root`` (or the ``--root`` CLI flag /
PROJECT_ROOT module constant); when omitted it defaults to the common
parent of the resolved files. The legacy rglob/skip_dirs fallback is
documentation-only: the orchestrator passes the already-filtered file list.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, Iterator, Sequence

MARKER = "ubs:ignore"

RULE_ID = "rust.security.tls-indirect"
CATEGORY = 8
TITLE = "TLS certificate or hostname verification disabled"
SEVERITY = "critical"
DESCRIPTION = ""

PROJECT_ROOT: Path | None = None

# Documentation only: legacy rglob fallback's skip list. The orchestrator
# passes the already-filtered file list, so this is never applied.
skip_dirs = {".git", "target", ".cargo", "node_modules"}
true_assignment_re = re.compile(
    r"\b(?:const|static|let)\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*bool)?\s*=\s*true\s*;"
)
danger_call_re = re.compile(
    r"\.danger_accept_invalid_(?:certs|hostnames)\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)


def code_line(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("//"):
        return ""
    return re.sub(r"//.*", "", line)


def relpath(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _base_dir(root: Path | None, resolved: list[Path]) -> Path:
    if root is not None:
        resolved_root = Path(root).resolve()
        return resolved_root if resolved_root.is_dir() else resolved_root.parent
    if resolved:
        common = Path(os.path.commonpath([str(p) for p in resolved]))
        return common if common.is_dir() else common.parent
    return Path.cwd()


def find(files: Sequence[Path], root: Path | None = None) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (relpath, line, col, code) per legacy finding, in legacy order."""
    if root is None:
        root = PROJECT_ROOT
    resolved: list[Path] = []
    for entry in files:
        path = Path(entry).resolve()  # legacy resolved list entries
        if path.suffix == ".rs":
            resolved.append(path)
    base = _base_dir(root, resolved)
    for path in resolved:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        true_names = set()
        for raw in lines:
            line = code_line(raw)
            if not line or MARKER in line:
                continue
            match = true_assignment_re.search(line)
            if match:
                true_names.add(match.group("name"))
        if not true_names:
            continue
        for idx, raw in enumerate(lines, start=1):
            line = code_line(raw)
            if not line or MARKER in line:
                continue
            match = danger_call_re.search(line)
            if match and match.group("name") in true_names:
                yield (relpath(path, base), idx, 1, line.strip())


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    cli_root = None
    if "--root" in args:
        i = args.index("--root")
        cli_root = Path(args[i + 1])
        del args[i:i + 2]
    root_files = [Path(p) for p in args]
    for found_path, line, col, code in find(root_files, cli_root):
        print(f"{found_path}:{line}:{code}")
