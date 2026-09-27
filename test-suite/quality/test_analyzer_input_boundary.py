#!/usr/bin/env python3
"""Analyzers must analyze the files they are handed (GH #151).

`run(ctx)` receives the selected input: runner discovery has already applied
.ubsignore, --exclude and the default build/dist/node_modules pruning. Several
analyzers re-applied their own SKIP_DIRS list to that input, against the
absolute path or the cwd-relative path, so a checkout that merely lived under
a directory named build/, dist/, .cache/ or node_modules/ lost its taint and
security findings while the other layers still reported on the same file.
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core import analyzers  # noqa: E402,F401  (populate the registry)
from ubs_core.registry import RunContext, all_analyzers  # noqa: E402

SAMPLES = {
    # analyzer name: (lang, file name, source)
    "taint_py": ("python", "app.py", "value = eval(input())\n"),
    "taint_cpp_redirect": ("cpp", "r.cpp",
                           'std::string url = req.getParam("next");\nres.redirect(url);\n'),
    "taint_cpp_traversal": ("cpp", "t.cpp",
                            'std::string p = req.getParam("file");\nstd::ifstream in(p);\n'),
    "sec_fetch_abort": ("javascript", "client.js", "await fetch('/api/x');\n"),
    "taint_elixir_redirect": ("elixir", "redirect_to.ex",
                              'def redirect_to(conn, params) do\n  target = params["url"]\n'
                              '  redirect(conn, external: target)\nend\n'),
}
ANCESTORS = ("neutral", "build", "dist", ".cache", "node_modules")
# taint_js.py is advanced through blob-pinned reviewed patches
# (.github/workflows/javascript-heap-*.yml); its run() still re-filters and
# is fixed through that pipeline. Remove the entry when it lands.
KNOWN_REFILTERS = {"javascript:taint_js"}


def _analyzer(name):
    for analyzer in all_analyzers():
        if analyzer.name == name:
            return analyzer
    raise AssertionError(f"analyzer {name} is not registered")


class AnalyzerInputBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="analyzer-boundary-", dir=artifacts)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def findings(self, name, path):
        lang = SAMPLES[name][0]
        return sorted((f["rule"], f["line"]) for f in _analyzer(name).run(RunContext(lang=lang, files=[path])))

    def test_ancestor_directory_names_do_not_hide_findings(self) -> None:
        for name, (_lang, filename, source) in SAMPLES.items():
            expected = None
            for ancestor in ANCESTORS:
                project = self.root / name / ancestor / "proj"
                project.mkdir(parents=True)
                target = project / filename
                target.write_text(source, encoding="utf-8")
                # Absolute input from an unrelated cwd, then relative input
                # from the directory above the ancestor (the cwd-relative case).
                for cwd, path in ((REPO_ROOT, target),
                                  (self.root / name, Path(ancestor) / "proj" / filename)):
                    with self.subTest(analyzer=name, ancestor=ancestor, path=str(path)):
                        with contextlib.chdir(cwd):
                            got = self.findings(name, path)
                        if expected is None:
                            expected = got
                            self.assertTrue(expected, f"{name} sample produced no finding")
                        self.assertEqual(got, expected)

    def test_run_does_not_refilter_its_input_by_directory_name(self) -> None:
        offenders = []
        for analyzer in all_analyzers():
            try:
                source = inspect.getsource(analyzer.run)
            except (OSError, TypeError):
                continue
            names = {node.id for node in ast.walk(ast.parse(textwrap.dedent(source)))
                     if isinstance(node, ast.Name)}
            if names & {"SKIP_DIRS", "should_skip"}:
                offenders.append(f"{analyzer.lang}:{analyzer.name}")
        self.assertEqual(sorted(set(offenders) - KNOWN_REFILTERS), [],
                         "run(ctx) must not re-apply discovery pruning")
        self.assertEqual(sorted(KNOWN_REFILTERS - set(offenders)), [],
                         "fixed: remove these from KNOWN_REFILTERS")


if __name__ == "__main__":
    os.environ.setdefault("UBS_NO_AUTO_UPDATE", "1")
    unittest.main()
