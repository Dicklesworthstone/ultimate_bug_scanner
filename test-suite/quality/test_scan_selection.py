#!/usr/bin/env python3
"""Regression tests for which files a scan selects and stages.

Issue #114: the ignore spec had four readers. ``ignore_globs_for_rg`` turned
``/ignored/**`` into the ripgrep glob ``!ignored/**``, but the no-rg directory
walk, the git shadow-list filter and the size guard's directory walk each
tested the raw pattern with ``fnmatch`` against a relative path, where a
leading slash can never match. A root-anchored exclude therefore applied on
hosts with ripgrep and silently did nothing on hosts without it, and the size
guard counted bytes the scan would not read. All four now share the generated
``ubs_ignore`` matcher, whose contract is "mean exactly what the rg glob
means".

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
import sys
import tempfile
import time
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
        # Single-component anchored patterns: the shape whose leading slash
        # used to be stripped and therefore matched at any depth (#121).
        "/ignored", "/nested", "/deep", "/foo.py",
        "dir.with.dots", "/a/b/c.py", "**/deeper", "ignored/bad.py",
        "", "a,b",
        # Bracket expressions, including the two spellings where a `]` directly
        # after `[` or `[!` is a member rather than the terminator.
        "[a-z]*.py", "keep[.]py", "[!k]eep.py", "[]]", "[!]]",
        # `**` that is not surrounded by separators, and the bare wildcards.
        "a**b", "**.py", "deep**foo.py", "a/**b", "**", "*", "a/**/c.py",
        "**/a/**", "/**/foo.py", "?eep.py", "deep/*/foo.py",
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

    def test_root_anchor_applies_to_a_single_component_pattern(self) -> None:
        # #121: the leading slash was stripped, so `/ignored` became the bare
        # glob `ignored`. A glob with no separator matches a component at any
        # depth in rg, so the anchor silently did nothing and nested/ignored
        # was dropped too — while `/ignored/**` anchored correctly, because it
        # kept a separator. The two spellings now agree.
        matcher = self.ubs_ignore.IgnoreMatcher("/ignored")
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
        # rg refuses these outright — an empty glob, or an unclosed character
        # class ("error parsing glob") — so there is no selection to compare
        # against and they are checked only for "does not blow up and does not
        # swallow the tree". An ignore pattern that cannot be translated must
        # never abort a scan, which an uncompilable regex previously did.
        for spec in ("/", ",", ",,", "[", "a[b", "[a-", "[]", "[!"):
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


class GitIndexSelectionTest(unittest.TestCase):
    """A pre-commit scan checks the index, including partially staged files."""

    CLEAN = "value = 1\n"

    def setUp(self) -> None:
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        self._tmp = tempfile.TemporaryDirectory(prefix="ubs-git-index-")
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir()
        self.artifacts = REPO_ROOT / "test-suite" / "artifacts" / "git-index-selection" / self._testMethodName
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.git("init", "--quiet", "-b", "main")

    def tearDown(self) -> None:
        result = self._outcome.result
        failed = any(test is self for test, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} "
              f"({time.monotonic() - self.started:.3f}s)", flush=True)
        self._tmp.cleanup()

    def git(self, *args, check=True):
        return run_helper(
            ["git", "-c", "user.name=UBS Test", "-c", "user.email=ubs-test@example.invalid",
             "-c", "commit.gpgsign=false", "-C", str(self.root), *args],
            text=True, check=check,
        )

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def initial_commit(self, files=None):
        for relative, content in (files or {"sample.py": "value = 0\n"}).items():
            self.write(relative, content)
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "initial fixture")

    def scan(self, label="staged", *, mode="--staged", target=".", cwd=None, env=None):
        result = run_ubs(
            ["--ci", "--only=python", mode, target], cwd or self.root,
            {"UBS_NO_CACHE": "1", "UBS_ENABLE_AUTO_UPDATE": "0", **(env or {})},
        )
        (self.artifacts / f"{label}.stdout.log").write_text(result.stdout, encoding="utf-8")
        (self.artifacts / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
        return result

    def assert_report(self, result, *, files, buggy=()):
        details = f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        self.assertEqual(result.returncode, 1 if buggy else 0, details)
        doc = summary(result)
        self.assertEqual(doc.get("status"), "ok", details)
        self.assertFalse(doc.get("failed_modules"), details)
        self.assertEqual(doc["totals"]["files"], len(files), details)
        self.assertEqual(reported_files(result), {str(self.root / name) for name in buggy}, details)
        tainted = {finding["file"] for finding in doc.get("findings", [])
                   if finding.get("rule_id") == "python.taint.eval"}
        self.assertEqual(tainted, {str(self.root / name) for name in buggy}, details)
        if not buggy:
            self.assertEqual(doc["totals"]["critical"], 0, details)
            self.assertEqual(doc["totals"]["warning"], 0, details)

    def test_staged_hazard_survives_unstaged_fix(self) -> None:
        self.initial_commit()
        self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        self.write("sample.py", self.CLEAN)
        self.assert_report(self.scan(), files=["sample.py"], buggy=["sample.py"])
        self.assert_report(self.scan("diff", mode="--diff"), files=["sample.py"])

    def test_unstaged_hazard_is_not_part_of_staged_scan(self) -> None:
        self.initial_commit()
        self.write("sample.py", self.CLEAN)
        self.git("add", "sample.py")
        self.write("sample.py", FINDING_SOURCE)
        self.assert_report(self.scan(), files=["sample.py"])
        self.assert_report(self.scan("diff", mode="--diff"),
                           files=["sample.py"], buggy=["sample.py"])

    def test_staged_source_missing_from_worktree_is_still_scanned(self) -> None:
        self.initial_commit()
        source = self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        source.rename(Path(self._tmp.name) / "parked.py")
        self.assertFalse(source.exists())
        self.assert_report(self.scan(), files=["sample.py"], buggy=["sample.py"])

    def test_initial_commit_scans_the_index_without_head(self) -> None:
        self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        self.assertNotEqual(self.git("rev-parse", "--verify", "HEAD", check=False).returncode, 0)
        self.write("sample.py", self.CLEAN)
        self.assert_report(self.scan(), files=["sample.py"], buggy=["sample.py"])

    def test_staged_rename_and_add_report_index_destinations(self) -> None:
        self.initial_commit({"old.py": FINDING_SOURCE})
        renamed = 'renamed "ü"\\name.py'
        added = "new source.py"
        self.git("mv", "old.py", renamed)
        self.write(added, FINDING_SOURCE)
        self.git("add", added)
        self.write(renamed, self.CLEAN)
        self.write(added, self.CLEAN)
        self.assert_report(self.scan(), files=[renamed, added], buggy=[renamed, added])

    def test_subdirectory_scope_does_not_scan_sibling_changes(self) -> None:
        self.initial_commit({"scope/sample.py": self.CLEAN, "sibling.py": self.CLEAN})
        for name in ("scope/sample.py", "sibling.py"):
            self.write(name, FINDING_SOURCE)
        self.git("add", "-A")
        for name in ("scope/sample.py", "sibling.py"):
            self.write(name, self.CLEAN)
        self.assert_report(self.scan(target="scope"),
                           files=["scope/sample.py"], buggy=["scope/sample.py"])
        self.assert_report(self.scan("scoped-cwd", cwd=self.root / "scope"),
                           files=["scope/sample.py"], buggy=["scope/sample.py"])

    def test_ignore_filter_preserves_newline_names_and_root_scope(self) -> None:
        self.write(".ubsignore", "/ignored/**\n")
        names = ["line\nbreak.py", "ignored/bad.py", "nested/ignored/keep.py"]
        for name in names:
            self.write(name, FINDING_SOURCE)
        self.git("add", "-A")
        for name in names:
            self.write(name, self.CLEAN)
        expected = ["line\nbreak.py", "nested/ignored/keep.py"]
        self.assert_report(self.scan(), files=expected, buggy=expected)

    def test_git_enumeration_failure_cannot_report_clean(self) -> None:
        self.initial_commit()
        self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        stub_dir = Path(self._tmp.name) / "bin"
        stub_dir.mkdir()
        wrapper = stub_dir / "git"
        wrapper.write_text(
            '#!/usr/bin/env bash\n'
            'for arg in "$@"; do\n'
            '  case "$arg" in diff|diff-index|diff-tree)\n'
            '    printf "%s\\n" "fatal: index enumeration test failure" >&2; exit 71;;\n'
            '  esac\n'
            'done\n'
            'exec "$UBS_TEST_REAL_GIT" "$@"\n', encoding="utf-8",
        )
        wrapper.chmod(0o755)
        env = {"PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
               "UBS_TEST_REAL_GIT": real_git}
        for mode in ("--staged", "--diff"):
            with self.subTest(mode=mode):
                result = self.scan(mode[2:], mode=mode, env=env)
                details = result.stdout + result.stderr
                self.assertEqual(result.returncode, 2, details)
                self.assertIn("index enumeration test failure", details)
                self.assertNotIn("No changed files to scan", details)

    def test_unmerged_index_cannot_report_clean(self) -> None:
        self.initial_commit()
        self.git("switch", "--quiet", "-c", "conflicting")
        self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        self.git("commit", "--quiet", "-m", "conflicting change")
        self.git("switch", "--quiet", "main")
        self.write("sample.py", self.CLEAN)
        self.git("add", "sample.py")
        self.git("commit", "--quiet", "-m", "main change")
        self.assertEqual(self.git("merge", "--no-edit", "conflicting", check=False).returncode, 1)
        self.assertTrue(self.git("ls-files", "--unmerged").stdout)
        result = self.scan()
        details = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, details)
        self.assertRegex(details.lower(), r"unmerged|unresolved|conflict")
        self.assertNotIn("No changed files to scan", details)

    def test_diff_without_head_fails_instead_of_reporting_clean(self) -> None:
        self.write("sample.py", FINDING_SOURCE)
        self.git("add", "sample.py")
        result = self.scan("diff", mode="--diff")
        details = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, details)
        self.assertIn("HEAD", details)
        self.assertNotIn("No changed files to scan", details)


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


class PostprocessStreamingTests(unittest.TestCase):
    """Exercise the live generated postprocessor, including large reports."""

    def setUp(self) -> None:
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        self._tmp = tempfile.TemporaryDirectory(prefix="ubs-postprocess-")
        self.root = Path(self._tmp.name)
        self.raw = self.root / "module.raw"
        self.text = self.root / "module.txt"
        self.summary = self.root / "module.json"
        self.findings = self.root / "module.findings.json"
        self.project = self.root / "project"
        self.project.mkdir()
        run_helper([
            "bash", "-c", 'TMPDIR_RUN="$1"\n' + bash_function("write_postprocess_script")
            + "\nwrite_postprocess_script\n", "postprocess-test", str(self.root),
        ], check=True)

    def tearDown(self) -> None:
        result = self._outcome.result
        failed = any(test is self for test, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} "
              f"({time.monotonic() - self.started:.3f}s)", flush=True)
        self._tmp.cleanup()

    def command(self, mode="text", **options):
        args = {
            "mode": mode, "lang": "python", "raw": self.raw, "txt": self.text,
            "json": self.summary, "findings": self.findings, "source": self.project,
            "project": self.project, "require-marker": "1", "timestamp": "fixed",
            "helpers-dir": REPO_ROOT / "modules" / "helpers",
        }
        args.update(options)
        command = [sys.executable, str(self.root / "postprocess.py")]
        for key, value in args.items():
            command.extend([f"--{key}", str(value)])
        return command

    def process(self, mode="text", expected_code=0, **options):
        result = run_helper(self.command(mode, **options), text=True)
        self.assertEqual(result.returncode, expected_code,
                         f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        return result

    def test_stream_preserves_counts_partial_paths_suppression_and_permalinks(self) -> None:
        workspace = self.root / "workspace"
        workspace.mkdir()
        source = "value = 1  # ubs:ignore[py.example]\nvalue = 2\n"
        (workspace / "sample.py").write_text(source, encoding="utf-8")
        (self.project / "sample.py").write_text(source, encoding="utf-8")
        raw = (
            "\x1b[34mUBS module: python (contract v2)\x1b[0m\r\n"
            "Files: 9\r\nWarning issues: 88\r\n"
            f"  {workspace}/sample.py:1:3 py.example hidden\r\n"
            f"  {workspace}/sample.py:2:3 py.example visible\r\n"
            "\x1b[31mPartial: [AST_UNAVAILABLE] analyzer unavailable\x1b[0m\r\n"
            "Partial: [OTHER_FAILURE] later reason\r\n"
            "Files scanned: 0\r\nCritical issues: 3\r\n"
            "Warning issues: 2\r\nInfo items: 1\x00\r\nfooter without newline"
        )
        self.raw.write_bytes(raw.encode("utf-8"))
        metrics = self.root / "metrics"
        metrics.mkdir()
        (metrics / "timings.json").write_text('{"elapsed_ms":123}', encoding="utf-8")
        blob = "https://example.test/repo/blob/revision"
        self.process(**{"workspace": workspace, "blob-base": blob,
                        "toplevel": self.project, "metrics-dir": metrics})
        expected = raw.replace("\r\n", "\n").replace(
            f"  {workspace}/sample.py:1:3 py.example hidden\n", ""
        ).replace(str(workspace), str(self.project)).replace(
            "py.example visible\n", f"py.example visible ({blob}/sample.py#L2)\n"
        )
        self.assertEqual(self.text.read_text(encoding="utf-8"), expected)
        self.assertEqual(json.loads(self.summary.read_text(encoding="utf-8")), {
            "language": "python", "project": str(self.project), "files": 9,
            "critical": 3, "warning": 2, "info": 1, "timestamp": "fixed",
            "status": "partial", "module_error": "AST_UNAVAILABLE",
            "message": "analyzer unavailable", "extras": {"elapsed_ms": 123},
        })

    def test_contract_rejection_preserves_text_without_inventing_summary(self) -> None:
        raw = "Critical issues: 99\nThis is not a contract report.\n"
        self.raw.write_text(raw, encoding="utf-8")
        self.process(expected_code=3)
        self.assertEqual(self.text.read_text(encoding="utf-8"), raw)
        self.assertFalse(self.summary.exists())

    def test_suppression_remains_correct_after_source_cache_eviction(self) -> None:
        rows = ["UBS module: python (contract v2)\n"]
        kept = []
        for number in [*range(12), 0]:
            path = self.project / f"source{number}.py"
            path.write_text("value = 1  # ubs:ignore[py.hidden]\n", encoding="utf-8")
            rows.append(f"{path}:1:1 py.hidden omitted\n")
            visible = f"{path}:1:1 py.visible retained\n"
            rows.append(visible)
            kept.append(visible)
        self.raw.write_text("".join(rows), encoding="utf-8")
        self.process()
        self.assertEqual(self.text.read_text(encoding="utf-8"), rows[0] + "".join(kept))

    def test_ndjson_restores_each_single_file_record_without_changing_messages(self) -> None:
        source = self.project / "nested" / 'quoted"name.py'
        source.parent.mkdir()
        source.write_text("value = 1\n", encoding="utf-8")
        records = [
            {"rule": "py.first", "path": source.name, "line": 1,
             "message": f"keep the literal {source.name} and {source}"},
            {"rule": "py.second", "path": str(source), "line": 1,
             "samples": [{"file": source.name, "uri": str(source)}]},
            {"rule": "py.third", "path": "other.py", "line": 1},
        ]
        self.findings.write_text("".join(json.dumps(record) + "\n" for record in records),
                                 encoding="utf-8")
        self.summary.write_text('{"files":1,"critical":0,"warning":3,"info":0}',
                                encoding="utf-8")
        self.process("json", **{"single-file": source})
        restored = [json.loads(line) for line in self.findings.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["path"] for record in restored],
                         ['nested/quoted"name.py', 'nested/quoted"name.py', "other.py"])
        self.assertEqual(restored[0]["message"], records[0]["message"])
        self.assertEqual(restored[1]["samples"],
                         [{"file": 'nested/quoted"name.py', "uri": 'nested/quoted"name.py'}])

    def test_ndjson_workspace_mirrors_take_precedence_and_keep_malformed_lines(self) -> None:
        workspace = self.root / "workspace"
        mirror = workspace / "external" / "sample.py"
        outside = self.root / "outside.py"
        mapping = self.root / "mirrors.0"
        mapping.write_bytes(f"{mirror}\0{outside}\0".encode("utf-8"))
        raw = (json.dumps({"rule": "py.a", "path": str(mirror), "line": 1}) + "\n\n"
               + "malformed line\n"
               + json.dumps({"rule": "py.b", "path": str(workspace / "local.py"), "line": 2}))
        self.findings.write_text(raw, encoding="utf-8")
        self.summary.write_text('{"files":2,"critical":0,"warning":2,"info":0}',
                                encoding="utf-8")
        self.process("json", **{"workspace": workspace, "mirror-map": mapping})
        self.assertEqual(self.findings.read_text(encoding="utf-8"),
                         raw.replace(str(mirror), str(outside)).replace(str(workspace), str(self.project)))

    @unittest.skipUnless(sys.platform.startswith("linux"), "peak RSS units are Linux KiB")
    def test_large_reports_stay_below_128_mib_and_preserve_every_byte(self) -> None:
        import hashlib

        # 400K physical output lines exercise the formerly unbounded raw-text,
        # split-lines and suppression buffers. This is a postprocessor probe,
        # not a claim about total memory of a 400K-line source-tree scan.
        with self.raw.open("w", encoding="utf-8") as stream:
            stream.write("UBS module: python (contract v2)\n")
            row = "  source.py:9:2 py.example " + "long diagnostic detail " * 6 + "\n"
            block = row * 1000
            for _ in range(400):
                stream.write(block)
            stream.write("Files scanned: 1\nCritical issues: 0\nWarning issues: 400000\nInfo items: 0\n")
        peak = self.root / "peak-rss.txt"
        wrapper = (
            "import pathlib, resource, runpy, sys\n"
            "peak = pathlib.Path(sys.argv.pop(1))\n"
            "sys.argv = sys.argv[1:]\n"
            "try:\n"
            "    runpy.run_path(sys.argv[0], run_name='__main__')\n"
            "finally:\n"
            "    peak.write_text(str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))\n"
        )
        result = run_helper([sys.executable, "-c", wrapper, str(peak),
                             *self.command(**{"no-suppress": "1"})[1:]], text=True)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        self.assertLess(int(peak.read_text()), 128 * 1024)

        def digest(path):
            with path.open("rb") as stream:
                return hashlib.file_digest(stream, "sha256").hexdigest()

        self.assertEqual(digest(self.raw), digest(self.text))
        doc = json.loads(self.summary.read_text(encoding="utf-8"))
        self.assertEqual((doc["files"], doc["critical"], doc["warning"], doc["info"]),
                         (1, 0, 400000, 0))

        # JSON scans used to read their NDJSON sink in full, then try to parse
        # it as one document. No restoration is needed for source-tree scans.
        with self.findings.open("w", encoding="utf-8") as stream:
            row = json.dumps({"rule": "py.example", "path": "sample.py", "line": 9,
                              "message": "long diagnostic detail " * 6}) + "\n"
            for _ in range(400):
                stream.write(row * 1000)
        expected_digest = digest(self.findings)
        result = run_helper([sys.executable, "-c", wrapper, str(peak),
                             *self.command("json")[1:]], text=True)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        self.assertLess(int(peak.read_text()), 128 * 1024)
        self.assertEqual(digest(self.findings), expected_digest)
        self.assertEqual(json.loads(self.summary.read_text(encoding="utf-8")), doc)


if __name__ == "__main__":
    unittest.main()


class SizeGuardExcludeTest(unittest.TestCase):
    """The size guard must measure what the scan will actually select.

    `dir_size_mb_filtered` is the fourth reader of the ignore spec, behind the
    two listing paths and the git filter. It had the same fnmatch mismatch, so
    a root-anchored exclude left the excluded bytes in the total and a project
    could be refused as "directory too large" over a directory the user had
    excluded (issue #114).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ubs-size-guard-")
        self.root = Path(self._tmp.name) / "project"
        (self.root / "ignored").mkdir(parents=True)
        (self.root / "nested" / "ignored").mkdir(parents=True)
        (self.root / "keep.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / "nested" / "ignored" / "keep.py").write_text("y = 2\n", encoding="utf-8")
        # Large enough that including or excluding it is unambiguous in whole MB.
        (self.root / "ignored" / "big.py").write_text("x = 1\n" * 900_000, encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def measure(self, spec: str) -> int:
        script = "".join([
            "set -uo pipefail\nTMPDIR_RUN=\nIGNORE_MATCHER_DIR=\nEARLY_TMP_PATHS=()\n",
            bash_function("ensure_tmpdir_run"),
            bash_function("need_cmd"),
            bash_function("ensure_ignore_matcher"),
            bash_function("dir_size_mb_filtered"),
            f'\ndir_size_mb_filtered "{self.root}" "{spec}"\n',
        ])
        out = run_helper(["bash", "-c", script], check=True, text=True).stdout
        return int(out.strip().splitlines()[-1])

    def test_root_anchored_exclude_removes_those_bytes_from_the_total(self) -> None:
        unfiltered = self.measure("")
        self.assertGreaterEqual(unfiltered, 5,
                                "fixture should be large enough to measure")
        # `/ignored/**` is root-anchored: the big file goes, the same-named
        # directory one level down stays (and is tiny either way).
        self.assertLess(self.measure("/ignored/**"), unfiltered - 4)
        # A bare name excludes that component at any depth.
        self.assertLess(self.measure("ignored"), unfiltered - 4)
        # An unrelated exclude must not remove the big file.
        self.assertGreaterEqual(self.measure("/nested/**"), unfiltered - 1)
