"""ubs_core.analyzers — analyzer modules registered per language (bead A2).

Importing this package auto-imports every analyzer submodule; each registers
itself with `ubs_core.registry.register` on import. Entrypoint shims and the
`python3 -m ubs_core` CLI both rely on this side effect. New analyzer modules
are picked up automatically — no edits needed here.
"""
from __future__ import annotations

import importlib
import pkgutil


def _load_all() -> None:
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{module_info.name}")


_load_all()
