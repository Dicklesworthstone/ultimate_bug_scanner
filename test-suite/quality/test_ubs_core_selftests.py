#!/usr/bin/env python3
"""Every embedded ubs_core self-test runs in the gate.

Each analyzer ships SELF_TESTS next to its code, and ubs_core.selftest
collects them with the core library checks, but no gate ran the collection:
only five analyzers' tests ran, in one workflow. spec_hooks.run_record_shape
had been failing unnoticed since absolute finding paths landed (516a189).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HELPERS_DIR = Path(__file__).resolve().parents[2] / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.registry import LANGS, all_analyzers  # noqa: E402
from ubs_core.selftest import _core_lib_tests  # noqa: E402


def registry_probe(lang: str = "all", extension: Path | None = None) -> dict:
    """Query a fresh interpreter so previous discovery cannot hide omissions."""
    code = textwrap.dedent("""
        import json, sys
        sys.path.insert(0, sys.argv[1])
        from ubs_core import analyzers
        from ubs_core.registry import all_analyzers, analyzers_for_lang, get
        if sys.argv[3]:
            analyzers.__path__.append(sys.argv[3])
        def identity(a):
            return [a.layer, a.lang, a.name, a.run.__module__, a.run.__qualname__,
                    [[name, fn.__module__, fn.__qualname__] for name, fn in a.selftests]]
        lang = sys.argv[2]
        selected = None if lang == 'all' else analyzers_for_lang(lang)
        selected_ids = None if selected is None else [identity(a) for a in selected]
        by_layer = {} if selected is None else {
            layer: [identity(a) for a in get(layer, lang)]
            for layer in sorted({a.layer for a in selected})}
        loaded = sorted(n for n in sys.modules if n.startswith('ubs_core.analyzers.'))
        complete = [identity(a) for a in all_analyzers()]
        repeated = None if selected is None else [identity(a) for a in analyzers_for_lang(lang)]
        print(json.dumps(dict(selected=selected_ids, by_layer=by_layer,
                              complete=complete, repeated=repeated, loaded=loaded)))
    """)
    result = subprocess.run(
        [sys.executable, "-c", code, str(HELPERS_DIR), lang, str(extension or "")],
        capture_output=True, text=True, check=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return json.loads(result.stdout)


class RegistryDiscoveryTests(unittest.TestCase):
    def test_language_first_matches_complete_discovery(self) -> None:
        complete = registry_probe()["complete"]
        self.assertEqual({a[1] for a in complete}, set(LANGS))
        self.assertGreaterEqual(len([a for a in complete if a[1] == "javascript"]), 45)
        for lang in LANGS:
            with self.subTest(lang=lang):
                result = registry_probe(lang)
                expected = [a for a in complete if a[1] == lang]
                self.assertEqual(result["selected"], expected)
                self.assertEqual(result["repeated"], expected)
                self.assertEqual(result["complete"], complete)
                self.assertEqual(result["by_layer"], {
                    layer: [a for a in expected if a[0] == layer]
                    for layer in {a[0] for a in expected}})
                if lang == "javascript":
                    self.assertNotIn("ubs_core.analyzers.taint_rust", result["loaded"])
                    self.assertNotIn("ubs_core.analyzers.taint_swift_traversal", result["loaded"])

    def test_unlisted_module_dependency_and_reentrant_queries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "extension_probe.py").write_text(textwrap.dedent("""
                from ubs_core.registry import Analyzer, register, all_analyzers, analyzers_for_lang, get
                from ubs_core.analyzers.taint_cpp_traversal import run
                for lang in ('javascript', 'python'):
                    register(Analyzer(layer='taint', lang=lang,
                                      name='extension_' + lang, run=run))
                assert sum(a.name.startswith('extension_') for a in all_analyzers()) == 2
                for lang in ('javascript', 'python'):
                    assert any(a.name == 'extension_' + lang for a in analyzers_for_lang(lang))
                    assert any(a.name == 'extension_' + lang for a in get('taint', lang))
            """), encoding="utf-8")
            for lang in ("javascript", "python"):
                with self.subTest(lang=lang):
                    result = registry_probe(lang, directory)
                    self.assertIn("extension_" + lang, [a[2] for a in result["selected"]])
                    self.assertIn("ubs_core.analyzers.taint_cpp_traversal", result["loaded"])
                    self.assertEqual(sum(a[2].startswith("extension_") for a in result["complete"]), 2)

    def test_unlisted_module_import_error_is_not_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "broken_extension.py").write_text(
                "raise RuntimeError('extension import failed')\n", encoding="utf-8")
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                registry_probe("javascript", directory)
            self.assertIn("RuntimeError: extension import failed", caught.exception.stderr)


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
