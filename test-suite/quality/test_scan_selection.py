#!/usr/bin/env python3
"""Regression tests for which files a scan selects and stages.

Issue #114: the ignore spec had three readers. ``ignore_globs_for_rg`` turned
``/ignored/**`` into the ripgrep glob ``!ignored/**``, but the no-rg directory
walk and the git shadow-list filter tested the raw pattern with ``fnmatch``
against a relative path, where a leading slash can never match. A root-anchored
exclude therefore applied on hosts with ripgrep and silently did nothing on
hosts without it. All three now share the generated ``ubs_ignore`` matcher,
whose contract is "mean exactly what the rg glob means".

Issue #113: a regular-file target outside the scan root kept its absolute or
``../`` spelling in the NUL-delimited list handed to ``copy_file_list``, whose
contract is paths relative to its source root. rsync sanitized the name away
and failed the whole run; the python tier would have joined it outside the
workspace. External files are now mirrored under the workspace and copied from
their own parent, and findings report the path the user actually named.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UBS = REPO_ROOT / "ubs"

# Every fixture file carries one unambiguous critical finding, so the set of
# files a run reports findings for is exactly the set it selected.
FINDING_SOURCE = "import os\neval(input())\n"  # ubs:ignore[python.taint.eval] -- literal positive scanner fixture, never executed

# Every child this file spawns is bounded, so a hung git/bash/rg fails the test
# with its command instead of stalling the suite.
HELPER_TIMEOUT = 120


def write_tree(root: Path, relatives) -> None:
    for rel in relatives:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(FINDING_SOURCE, encoding="utf-8")


def run_ubs(args, cwd, env_extra=None, timeout=600):
    env = os.environ.copy()
    env["UBS_NO_AUTO_UPDATE"] = "1"
    env.update(env_extra or {})
    return subprocess.run(  # ubs:ignore[py.security.command-injection] Fixed repo script and test-owned paths.
        [str(UBS), "--format=json", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=timeout,
    )


def summary(result):
    """The run's JSON document, with a readable failure when it is not JSON."""
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"ubs exited {result.returncode} without a JSON document ({exc})\n"
            f"--- stdout ---\n{result.stdout[-2000:]}\n"
            f"--- stderr ---\n{result.stderr[-2000:]}"
        ) from exc


def reported_files(result) -> set:
    """The files a run reported findings against.

    The top-level ``findings`` ledger carries one entry per finding and is not
    capped, unlike the per-rule ``samples`` lists, so it is the readout that
    can prove exactly which files a scan selected.
    """
    doc = summary(result)
    files = {finding["file"] for finding in doc.get("findings", [])}
    files.update(
        sample["file"]
        for scanner in doc.get("scanners", [])
        for finding in scanner.get("findings", [])
        for sample in finding.get("samples", [])
    )
    return files


def scanned_count(result) -> int:
    return summary(result)["totals"]["files"]


def run_helper(command, **kwargs):
    """A bounded local child: a hung helper must fail the test, not the run."""
    kwargs.setdefault("timeout", HELPER_TIMEOUT)
    kwargs.setdefault("capture_output", True)
    return subprocess.run(command, **kwargs)  # ubs:ignore[py.security.command-injection] Fixed repo sources and test-owned paths.


def bash_function(name: str) -> str:
    """The source of one top-level shell function from ``ubs``."""
    lines = UBS.read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(f"{name}(){{"):
            for end in range(index + 1, len(lines)):
                if lines[end].startswith("}"):
                    return "".join(lines[index:end + 1])
            break
    raise AssertionError(f"{name}() definition not found in {UBS}")


class IgnoreMatcherParityTest(unittest.TestCase):
    """The shared matcher must select exactly what the rg globs select."""

    TREE = (
        "keep.py",
        "ignored/bad.py",
        "nested/ignored/keep.py",
        "a/b/c.py",
        "x/a/b/c.py",
        "foo.py",
        "deep/foo.py",
        "deep/deeper/foo.py",
        "dir.with.dots/keep.py",
    )

    # The nested controls are the point: stripping a leading slash and matching
    # anywhere would wrongly drop nested/ignored/keep.py, and a glob with a
    # separator has to prune the subtree the way rg does when it matches a
    # directory.
    PATTERNS = (
        "/ignored/**", "ignored", "a/b", "/a/b/**", "**/foo.py", "foo.py",
        "deep/**", "**/ignored/**", "/keep.py", "*.py", "nested",
        "dir.with.dots", "/a/b/c.py", "**/deeper", "ignored/bad.py",
        "", "a,b",
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="ubs-matcher-parity-")
        cls.root = Path(cls._tmp.name) / "project"
        write_tree(cls.root, cls.TREE)
        cls.all_files = sorted(
            str(p.relative_to(cls.root)) for p in cls.root.rglob("*") if p.is_file())

        # Generate ubs_ignore.py exactly as a run would, then import it.
        cls._module_dir = tempfile.TemporaryDirectory(prefix="ubs-ignore-module-")
        script = (
            "set -Eeuo pipefail\n"
            f'TMPDIR_RUN="{cls._module_dir.name}"\n'
            "ensure_tmpdir_run(){ :; }\n"
            "IGNORE_MATCHER_DIR=\n"
            + bash_function("ensure_ignore_matcher")
            + "\nensure_ignore_matcher\n"
        )
        run_helper(["bash", "-c", script], check=True)
        import sys
        sys.path.insert(0, cls._module_dir.name)
        import ubs_ignore
        cls.ubs_ignore = ubs_ignore

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()
        cls._module_dir.cleanup()

    def rg_selection(self, spec: str):
        """What rg keeps, given the globs ignore_globs_for_rg emits for spec."""
        script = bash_function("ignore_globs_for_rg") + f'\nignore_globs_for_rg "{spec}"\n'
        globs = run_helper(["bash", "-c", script], check=True, text=True).stdout.split()
        args = ["rg", "--files", "--hidden", "--no-ignore", "--no-messages"]
        for glob in globs:
            args += ["-g", glob]
        listing = run_helper(args, cwd=str(self.root), text=True, check=False)
        return sorted(line.removeprefix("./") for line in listing.stdout.splitlines())

    def test_matcher_matches_ripgrep_for_every_pattern(self) -> None:
        if not shutil.which("rg"):
            self.skipTest("ripgrep is not installed")
        for spec in self.PATTERNS:
            with self.subTest(spec=spec):
                matcher = self.ubs_ignore.IgnoreMatcher(spec)
                kept = sorted(f for f in self.all_files if not matcher.excluded(f))
                self.assertEqual(kept, self.rg_selection(spec))

    def test_root_anchor_keeps_the_same_name_deeper_in_the_tree(self) -> None:
        matcher = self.ubs_ignore.IgnoreMatcher("/ignored/**")
        self.assertTrue(matcher.excluded("ignored/bad.py"))
        self.assertFalse(matcher.excluded("nested/ignored/keep.py"))

    def test_path_glob_prunes_the_whole_subtree(self) -> None:
        matcher = self.ubs_ignore.IgnoreMatcher("a/b")
        self.assertTrue(matcher.excluded("a/b"))
        self.assertTrue(matcher.excluded("a/b/c.py"))
        self.assertTrue(matcher.excluded("x/a/b/c.py"))
        self.assertFalse(matcher.excluded("a/bb/c.py"))

    def test_star_does_not_cross_a_separator(self) -> None:
        matcher = self.ubs_ignore.IgnoreMatcher("/a/*")
        self.assertTrue(matcher.excluded("a/b"))
        self.assertFalse(matcher.excluded("x/a/b"))

    def test_empty_spec_excludes_nothing(self) -> None:
        matcher = self.ubs_ignore.IgnoreMatcher("")
        for rel in self.all_files:
            self.assertFalse(matcher.excluded(rel))

    def test_degenerate_patterns_do_not_raise(self) -> None:
        # rg itself rejects the empty glob these produce, so they are checked
        # for "does not blow up and does not swallow the tree" only.
        for spec in ("/", ",", ",,", "["):
            with self.subTest(spec=spec):
                matcher = self.ubs_ignore.IgnoreMatcher(spec)
                self.assertFalse(matcher.excluded("keep.py"))
                self.assertFalse(matcher.excluded("a/b/c.py"))


class SelectionPathParityTest(unittest.TestCase):
    """The ripgrep path and the no-rg walk must select the same files."""

    # (pattern, the files it must remove from the tree). Leaving a same-named
    # directory deeper in the tree is what distinguishes a root anchor from an
    # anywhere-match, so those controls carry the test.
    CASES = (
        ("/ignored/**", ("ignored/bad.py",)),
        ("ignored", ("ignored/bad.py", "nested/ignored/keep.py")),
        ("a/b", ("a/b/c.py", "x/a/b/c.py")),
        ("/a/b/**", ("a/b/c.py",)),
        ("**/foo.py", ("foo.py", "deep/foo.py", "deep/deeper/foo.py")),
        ("deep/**", ("deep/foo.py", "deep/deeper/foo.py")),
    )

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="ubs-selection-parity-")
        cls.root = Path(cls._tmp.name) / "project"
        write_tree(cls.root, IgnoreMatcherParityTest.TREE)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_both_paths_scan_the_same_files(self) -> None:
        for pattern, removed in self.CASES:
            survivors = {str(self.root / rel)
                         for rel in IgnoreMatcherParityTest.TREE
                         if rel not in removed}
            with self.subTest(pattern=pattern):
                with_rg = run_ubs(["--exclude", pattern, str(self.root)], self.root)
                without_rg = run_ubs(["--exclude", pattern, str(self.root)], self.root,
                                     {"UBS_TEST_NO_RG": "1"})
                self.assertEqual(reported_files(with_rg), survivors,
                                 f"ripgrep path selected the wrong files for {pattern}")
                self.assertEqual(reported_files(without_rg), survivors,
                                 f"walk path selected the wrong files for {pattern}")
                self.assertEqual(scanned_count(with_rg), len(survivors))
                self.assertEqual(scanned_count(without_rg), len(survivors))


class GitShadowFilterTest(unittest.TestCase):
    """The staged-file filter reads the ignore spec the same way."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ubs-git-filter-")
        self.root = Path(self._tmp.name) / "repo"
        write_tree(self.root, ("keep.py", "ignored/bad.py", "nested/ignored/keep.py"))
        for command in (
            ["git", "init", "-q", "-b", "main"],
            ["git", "add", "-A"],
            ["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
             "commit", "-qm", "init"],
        ):
            run_helper(command, cwd=str(self.root), check=True)
        for rel in ("keep.py", "ignored/bad.py", "nested/ignored/keep.py"):
            path = self.root / rel
            path.write_text(path.read_text(encoding="utf-8") + "import sys\n",
                            encoding="utf-8")
        run_helper(["git", "add", "-A"], cwd=str(self.root), check=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_staged_scan_honours_root_anchored_exclude(self) -> None:
        result = run_ubs(["--staged", "--exclude", "/ignored/**", "."], self.root)
        # nested/ignored/keep.py is not at the root, so anchoring must keep it.
        self.assertEqual(scanned_count(result), 2)
        self.assertNotIn(str(self.root / "ignored/bad.py"), reported_files(result))


class ExternalTargetTest(unittest.TestCase):
    """Targets outside the scan root are staged, scanned and named correctly."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ubs-external-target-")
        base = Path(self._tmp.name)
        self.project = base / "project"
        write_tree(self.project, ("local.py",))
        write_tree(base, ("outside.py", "extdir/other.py"))
        self.outside = base / "outside.py"
        self.extdir = base / "extdir"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def assert_scanned(self, result, expected_paths) -> None:
        self.assertEqual(scanned_count(result), len(expected_paths))
        self.assertEqual(reported_files(result), {str(p) for p in expected_paths})
        for path in expected_paths:
            self.assertTrue(Path(path).exists(),
                            f"reported a path that does not exist: {path}")

    def test_absolute_external_file_is_scanned(self) -> None:
        result = run_ubs(["local.py", str(self.outside)], self.project)
        self.assert_scanned(result, [self.project / "local.py", self.outside])

    def test_parent_relative_external_file_is_scanned(self) -> None:
        result = run_ubs(["local.py", "../outside.py"], self.project)
        self.assert_scanned(result, [self.project / "local.py", self.outside])

    def test_external_file_and_directory_together(self) -> None:
        result = run_ubs(["local.py", "../outside.py", str(self.extdir)], self.project)
        self.assert_scanned(result, [self.project / "local.py", self.outside,
                                     self.extdir / "other.py"])

    def test_in_root_file_named_through_parent_is_not_treated_as_external(self) -> None:
        result = run_ubs(["local.py", "../project/local.py"], self.project)
        self.assert_scanned(result, [self.project / "local.py"])

    def test_missing_external_target_is_still_rejected(self) -> None:
        result = run_ubs(["local.py", "../nope.py"], self.project)
        self.assertEqual(result.returncode, 2)

    def test_external_targets_survive_the_python_copy_tier(self) -> None:
        """Without rsync or tar the python tier stages the same files.

        It joins each listed name onto the destination, so an absolute or
        ``..`` entry would land outside the workspace instead of being scanned.
        """
        stub_dir = Path(tempfile.mkdtemp(prefix="ubs-no-tar-"))
        try:
            stub = stub_dir / "tar"
            stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            env = {
                "UBS_TEST_NO_RSYNC": "1",
                "UBS_TEST_NO_TAR": "1",
                "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            }
            result = run_ubs(["local.py", "../outside.py"], self.project, env)
            self.assert_scanned(result, [self.project / "local.py", self.outside])
        finally:
            for child in stub_dir.iterdir():
                child.unlink()
            stub_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
