"""ubs_core.analyzers — analyzer modules registered per language (bead A2).

Importing this package imports every analyzer module; each registers itself with
`ubs_core.registry.register` on import. Entrypoint shims and the
`python3 -m ubs_core` CLI both rely on this side effect.
"""
from __future__ import annotations

from ubs_core.analyzers import lifecycle_java  # noqa: F401  (registers lifecycle/java)
