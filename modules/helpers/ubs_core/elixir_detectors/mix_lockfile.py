"""ubs_core.elixir_detectors.mix_lockfile — category 14 (bead 0xjg.13).

Port of the legacy filesystem check (modules/ubs-elixir.sh 2937-2940): when
the project has a mix.exs but no mix.lock, report one warning finding. The
project root is derived from the file list; the lock check hits the disk
exactly like the legacy `-f` test.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "ex.mix.lockfile-missing"
CATEGORY = 14
TITLE = "No mix.lock file found"
SEVERITY = "warning"
DESCRIPTION = "Run mix deps.get and commit mix.lock for reproducible builds"


def find(files: Sequence[Path]) -> Iterable[tuple]:
    root = None
    for path in files:
        if path.name == "mix.exs":
            root = path.parent
            break
    if root is None:
        return
    if not (root / "mix.lock").is_file():
        yield str(root / "mix.exs"), 1, 1, ""
