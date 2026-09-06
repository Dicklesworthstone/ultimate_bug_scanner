"""ubs_core.elixir_detectors.config_runtime_exs — category 12 (bead 0xjg.13).

Port of the legacy filesystem check (modules/ubs-elixir.sh 2874-2877):
when config/config.exs exists but config/runtime.exs does not, report one
info finding. Both paths are checked on disk under the project root derived
from the file list, exactly like the legacy `-f` tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "ex.config.runtime-exs-missing"
CATEGORY = 12
TITLE = "No config/runtime.exs found"
SEVERITY = "info"
DESCRIPTION = "Consider using runtime.exs for deployment-time configuration"


def _project_root(files: Sequence[Path]) -> Path | None:
    for path in files:
        if path.name == "config.exs" and path.parent.name == "config":
            return path.parent.parent
    return None


def find(files: Sequence[Path]) -> Iterable[tuple]:
    root = _project_root(files)
    if root is None:
        return
    config_exs = root / "config" / "config.exs"
    runtime_exs = root / "config" / "runtime.exs"
    if config_exs.is_file() and not runtime_exs.is_file():
        yield str(config_exs), 1, 1, ""
