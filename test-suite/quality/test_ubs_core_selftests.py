#!/usr/bin/env python3
"""Every embedded ubs_core self-test runs in the gate.

Each analyzer ships SELF_TESTS next to its code, and ubs_core.selftest
collects them with the core library checks, but no gate ran the collection:
only five analyzers' tests ran, in one workflow. spec_hooks.run_record_shape
had been failing unnoticed since absolute finding paths landed (516a189).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HELPERS_DIR = Path(__file__).resolve().parents[2] / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core import analyzers  # noqa: E402,F401  (populates the registry)
from ubs_core.registry import all_analyzers  # noqa: E402
from ubs_core.selftest import _core_lib_tests  # noqa: E402


class EmbeddedSelfTests(unittest.TestCase):
    def test_every_embedded_selftest_passes(self) -> None:
        tests = list(_core_lib_tests())
        for analyzer in all_analyzers():
            tests.extend((f"{analyzer.name}.{name}", fn) for name, fn in analyzer.selftests)
        # A registry that silently lost its analyzers would pass vacuously.
        self.assertGreater(len(tests), 400)
        for name, fn in tests:
            with self.subTest(selftest=name):
                fn()


if __name__ == "__main__":
    unittest.main()
