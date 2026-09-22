#!/usr/bin/env python3
"""Issue #136: build-output guesses must not hide scanner inputs.

Exercise the real listing function, with both ripgrep and the Python walk.
The deliberately stale SOURCE_EXTENSIONS in the harness proves that pruning
uses the same contract/shebang recognition as language selection, rather than
requiring another hand-maintained list to stay in sync. The end-to-end test
uses the real runner, modules, contract and default traversal configuration.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import tempfile
import unittest
from pathlib import Path

if __package__:
    from .test_scan_selection import (
        REPO_ROOT, UBS, bash_function, reported_files, run_helper, run_ubs,
        scanned_count, summary,
    )
else:
    from test_scan_selection import (
        REPO_ROOT, UBS, bash_function, reported_files, run_helper, run_ubs,
        scanned_count, summary,
    )

SHELL_SOURCE = '#!/usr/bin/env bash\ncd /tmp\nrm -rf "$1"\neval "$2"\n'


def listing_function() -> str:
    """Extract the real function without mistaking Python's } for its end."""
    source = UBS.read_text(encoding="utf-8")
    start = source.index("list_scan_files(){\n")
    lines = source[start:].splitlines(keepends=True)
    heredoc = False
    for index, line in enumerate(lines):
        if heredoc:
            if line.rstrip("\n") == "PY":
                heredoc = False
        elif "<<'PY'" in line:
            heredoc = True
        elif line.rstrip("\n") == "}":
            return "".join(lines[:index + 1])
    raise AssertionError("unterminated list_scan_files function")


class BuildOutputListingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="ubs-build-output-")
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)
        self.root = self.base / "project"
        self.root.mkdir()
        self.contract = REPO_ROOT / "modules" / "contract.json"
        self.spec = json.loads(self.contract.read_text(encoding="utf-8"))["modules"]

    def write(self, rel: str, content: str = SHELL_SOURCE) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def modes(self):
        return ("walk", "rg") if shutil.which("rg") else ("walk",)

    def listing(self, mode, *, contract=True, only="", exclude_langs="",
                include_ext="", ignore="", timeout=120):
        work = self.base / ("listing-" + mode)
        work.mkdir(exist_ok=True)
        out = work / "selected.files"
        source = UBS.read_text(encoding="utf-8")
        match = re.search(r'^SCAN_DATA_EXTENSIONS="([^"\n]*)"', source, re.MULTILINE)
        self.assertIsNotNone(match, "runner data-extension policy not found")
        script = "\n".join([
            "set -Eeuo pipefail",
            'TMPDIR_RUN="$3"; IGNORE_MATCHER_DIR=""',
            'GLOBAL_EXCLUDE_PATTERNS="$8"',
            'SCOPED_IGNORE_DIRS="obj,env,bin"',
            # Regression guard: this table must not decide what a scanner knows.
            'SOURCE_EXTENSIONS="py"; MAX_FILE_SIZE_MB=0',
            "SCAN_DATA_EXTENSIONS=" + shlex.quote(match.group(1)),
            'FORCE_WALK="$4"',
            'ensure_tmpdir_run(){ :; }',
            'need_cmd(){ if [[ "$1" == rg && "$FORCE_WALK" == walk ]]; then return 1; fi; command -v "$1" >/dev/null 2>&1; }',
            bash_function("ignore_globs_for_rg"),
            bash_function("ensure_ignore_matcher"),
            listing_function(),
            'list_scan_files "$1" "$2" "$9" "$3" "$5" "$6" "$7"',
        ])
        result = run_helper([
            "bash", "-c", script, "ubs-build-output-test",
            str(self.root), str(out), str(work), mode, only,
            exclude_langs, include_ext, ignore,
            str(self.contract) if contract else "",
        ], check=True, text=True, timeout=timeout)
        kept = {os.fsdecode(p) for p in out.read_bytes().split(b"\0") if p}
        by_lang = {
            path.stem: {os.fsdecode(p) for p in path.read_bytes().split(b"\0") if p}
            for path in work.glob("*.files") if path != out
        }
        stats = [int(value) for value in result.stdout.split()]
        self.assertEqual(len(stats), 6, "diagnostics must not corrupt listing stdout")
        return kept, by_lang, stats, result.stderr

    def test_shell_extensions_are_never_build_output(self) -> None:
        paths = {f"case-{i}/bin/deploy.{ext}" for i, ext in enumerate(("sh", "bash", "SH", "BASH"))}
        for rel in paths:
            self.write(rel)
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, languages, stats, stderr = self.listing(mode)
                self.assertEqual(kept, paths)
                self.assertEqual(languages["bash"], paths)
                self.assertEqual(stats[4], len(paths))
                self.assertNotIn("skipping", stderr)

    def test_extensionless_entrypoints_and_nested_bins(self) -> None:
        shebangs = (
            "#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env sh",
            "#!/usr/bin/env bash", "#!/usr/bin/env -S bash -eu",
            "#!/usr/bin/env --split-string=bash -eu",
        )
        paths = set()
        for i, shebang in enumerate(shebangs):
            rel = f"case-{i}/bin/nested/bin/launch"
            self.write(rel, shebang + '\neval "$1"\n')
            paths.add(rel)
        for rel in ("space dir/bin/entry point", "newline/bin/entry\npoint",
                    os.fsdecode(b"non-utf8/bin/entry-\xff")):
            self.write(rel)
            paths.add(rel)
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, languages, _, _ = self.listing(mode)
                self.assertEqual(kept, paths)
                self.assertEqual(languages["bash"], paths)

    def test_every_contract_extension_protects_its_bin(self) -> None:
        expected = {}
        for lang, spec in self.spec.items():
            expected[lang] = set()
            for index, ext in enumerate(spec.get("extensions", [])):
                rel = f"{lang}-{index}/bin/source.{ext}"
                self.write(rel, "fixture\n")
                expected[lang].add(rel)
        all_paths = set().union(*expected.values())
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, languages, _, _ = self.listing(mode)
                self.assertEqual(kept, all_paths)
                for lang, paths in expected.items():
                    self.assertTrue(paths <= languages[lang], (lang, paths - languages[lang]))

    def test_manifests_use_the_same_matcher_as_language_selection(self) -> None:
        paths = {"ruby/bin/Gemfile", "ruby-nested/bin/Rakefile",
                 "swift/bin/Package.swift", "js/bin/package.json", "python/bin/pyproject.toml"}
        for rel in paths:
            self.write(rel, "# fixture\n")
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, _, stats, _ = self.listing(mode)
                self.assertEqual(kept, paths)
                self.assertEqual(stats[4], len(paths))

    def test_offline_hints_and_include_ext_protect_inputs(self) -> None:
        paths = {"shell/bin/deploy.sh", "entry/bin/launch", "kotlin/bin/main.kt", "cpp/bin/main.cpp"}
        for rel in paths:
            self.write(rel)
        for mode in self.modes():
            with self.subTest(mode=mode, contract="unavailable"):
                kept, _, stats, _ = self.listing(mode, contract=False)
                self.assertEqual(kept, paths)
                self.assertEqual(stats[4], len(paths))
        custom = "custom/bin/script.custom"
        self.write(custom)
        for mode in self.modes():
            with self.subTest(mode=mode, include_ext="custom"):
                kept, languages, _, _ = self.listing(mode, only="bash", include_ext="custom")
                self.assertEqual(kept, paths | {custom})
                self.assertIn(custom, languages["bash"])

    def test_language_filters_do_not_change_what_counts_as_source(self) -> None:
        self.write("bin/deploy.sh")
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, languages, stats, stderr = self.listing(mode, only="python", exclude_langs="bash")
                self.assertEqual(kept, {"bin/deploy.sh"})
                self.assertEqual(languages["bash"], {"bin/deploy.sh"})
                self.assertEqual(stats[4], 0)
                self.assertNotIn("skipping", stderr)

    def test_opaque_build_output_is_pruned_with_one_notice(self) -> None:
        self.write("bin/program", "\x7fELF\0binary\n")
        self.write("bin/another-program", "\x7fELF\0binary\n")
        self.write("scripts/deploy.sh")
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, _, _, stderr = self.listing(mode)
                self.assertEqual(kept, {"scripts/deploy.sh"})
                notices = [line for line in stderr.splitlines() if "skipping 'bin'" in line]
                self.assertEqual(len(notices), 1, stderr)
                self.assertIn("build output", notices[0])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_nonregular_entry_does_not_block_shebang_detection(self) -> None:
        (self.root / "bin").mkdir()
        os.mkfifo(self.root / "bin" / "pipe")
        self.write("scripts/deploy.sh")
        # os.walk lists FIFOs. A shebang probe must not open one and hang.
        kept, languages, _, stderr = self.listing("walk", timeout=5)
        self.assertEqual(kept, {"scripts/deploy.sh"})
        self.assertEqual(languages["bash"], {"scripts/deploy.sh"})
        self.assertIn("skipping 'bin'", stderr)

    def test_identified_virtualenv_and_obj_pruning_is_visible(self) -> None:
        self.write("env/pyvenv.cfg", "home = /usr\n")
        self.write("env/site.py", "import os\n")
        self.write("obj/project.assets.json", "{}\n")
        self.write("obj/Generated.cs", "class G {}\n")
        self.write("source/env/app.py", "print('source')\n")
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, _, _, stderr = self.listing(mode)
                self.assertEqual(kept, {"source/env/app.py"})
                self.assertIn("skipping 'env'", stderr)
                self.assertIn("skipping 'obj'", stderr)

    def test_explicit_ignore_still_wins(self) -> None:
        self.write("bin/deploy.sh")
        self.write("nested/bin/keep.sh")
        for mode in self.modes():
            with self.subTest(mode=mode):
                kept, _, _, stderr = self.listing(mode, ignore="/bin/**")
                self.assertEqual(kept, {"nested/bin/keep.sh"})
                self.assertNotIn("skipping", stderr)


class BuildOutputEndToEndTest(unittest.TestCase):
    def test_issue_136_reports_the_same_critical_by_directory_or_explicit_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-136-e2e-") as scratch:
            base = Path(scratch)
            for no_rg in ("0", "1"):
                for directory, explicit in (("bin", False), ("scripts", False), ("bin", True)):
                    with self.subTest(no_rg=no_rg, directory=directory, explicit=explicit):
                        root = base / f"case-{no_rg}-{directory}-{explicit}"
                        script = root / directory / "deploy.sh"
                        script.parent.mkdir(parents=True)
                        script.write_text(SHELL_SOURCE, encoding="utf-8")
                        (root / "README.md").write_text("Issue 136 fixture\n", encoding="utf-8")
                        target = script if explicit else root
                        result = run_ubs(["--ci", "--no-cache", str(target)], root,
                                         {"UBS_TEST_NO_RG": no_rg})
                        self.assertEqual(result.returncode, 1, result.stderr[-4000:])
                        self.assertEqual(scanned_count(result), 1)
                        # Explicit-file mode reports project-relative paths;
                        # directory mode may report absolute paths.
                        reported = {str((root / path).resolve()) for path in reported_files(result)}
                        self.assertEqual(reported, {str(script.resolve())})
                        doc = summary(result)
                        self.assertGreater(doc["totals"]["critical"], 0)
                        self.assertIn("bash.security.eval-variable", json.dumps(doc))


if __name__ == "__main__":
    unittest.main()
