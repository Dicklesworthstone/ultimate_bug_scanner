"""modules/lib/ubs-common.sh (bead A1): the primitives every module shares.

Each test runs bash with the library sourced and checks observable behaviour:
json_escape on quotes/backslashes/control characters/unicode and under set -u,
the severity table, the output-format contract (jsonl/toon/unknown exit 2),
NUL-safe file listing with a newline in a file name, and the exported locale.
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB = REPO_ROOT / "modules" / "lib" / "ubs-common.sh"


def bash(script: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    full_env.pop("LC_ALL", None)
    if env:
        full_env.update(env)
    # ubs:ignore[py.security.command-injection] Scripts are test-authored Bash literals; paths and test data are positional arguments.
    return subprocess.run(
        ["bash", "-c", 'set -Eeuo pipefail; source "$1"; shift; ' + script, "bash", str(LIB), *args],
        capture_output=True, text=False, env=full_env, timeout=60, stdin=subprocess.DEVNULL,
    )


class JsonEscapeTests(unittest.TestCase):
    def check(self, raw: str) -> None:
        proc = bash('printf "\\"%s\\"" "$(json_escape "$1")"', raw)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.decode("utf-8")), raw)

    def test_quotes_backslashes_and_named_controls(self) -> None:
        self.check('he said "hi" \\ back\\slash')
        self.check("line1\nline2\r\ttabbed")
        self.check("bell\bform\f")

    def test_other_control_characters_become_u00xx(self) -> None:
        proc = bash('printf "%s" "$(json_escape "$1")"', "a\x01b\x1fc")
        self.assertEqual(proc.stdout, b"a\\u0001b\\u001fc")

    def test_unicode_passes_through(self) -> None:
        self.check("naïve — 日本語 ✓")

    def test_empty_and_missing_argument_under_set_u(self) -> None:
        self.assertEqual(bash('printf "[%s]" "$(json_escape "")"').stdout, b"[]")
        self.assertEqual(bash('printf "[%s]" "$(json_escape </dev/null)"').stdout, b"[]")
        self.assertEqual(bash('printf "[%s]" "$(printf "x\\"y" | json_escape)"').stdout, b'[x\\"y]')


class HelperIntegrityTests(unittest.TestCase):
    """Real helper bytes must be checked before the directory is returned."""

    assets = ("helpers/ubs_core/io.py", "helpers/ubs_core/kotlin_scan.py",
              "helpers/ubs_core/java_scan.py")

    def verify(self, directory: Path, digests: dict[str, str]) -> subprocess.CompletedProcess:
        args = [str(directory)]
        for name, digest in digests.items():
            args.extend((name, digest))
        return bash('''
UBS_MODULE_LIB_DIR="$1"; shift
UBS_VERIFIED_ASSET_DIR=""
UBS_ALLOW_UNVERIFIED_HELPERS=0
UBS_COMMON_HELPER_CHECKSUMS=()
while (( $# )); do
  UBS_COMMON_HELPER_CHECKSUMS["$1"]="$2"
  shift 2
done
ubs_resolve_helpers_dir result
printf '%s\\n' "$result"
''', *args)

    def case(self, suffix: str, tamper: str | None = None) -> None:
        # Retain the control artifacts under the caller's private disk TMPDIR.
        root = Path(tempfile.mkdtemp(prefix="ubs-helper-integrity-")) / suffix
        digests = {}
        for name in self.assets:
            source = REPO_ROOT / "modules" / name
            data = source.read_bytes()
            digests[name] = hashlib.sha256(data).hexdigest()
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data + (b"\n# tampered integrity control\n" if name == tamper else b""))
        proc = self.verify(root, digests)
        if tamper:
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn(tamper.encode(), proc.stderr)
            self.assertIn(b"failed checksum verification", proc.stderr)
            self.assertEqual(proc.stdout, b"")
        else:
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, os.fsencode(str(root / "helpers")) + b"\n")

    def test_all_intact_helpers_are_accepted(self) -> None:
        self.case("modules")

    def test_escaped_directory_names_keep_every_digest_bound_to_its_file(self) -> None:
        for suffix in ("space directory", "back\\slash", "line\nbreak"):
            with self.subTest(path=suffix):
                self.case(suffix)

    def test_each_tampered_helper_refuses_before_returning_the_directory(self) -> None:
        for asset in self.assets:
            with self.subTest(asset=asset):
                self.case("modules", tamper=asset)


class SeverityTests(unittest.TestCase):
    def test_table(self) -> None:
        for raw, expected in (("CRITICAL", "critical"), ("error", "critical"), ("high", "critical"),
                              ("Warning", "warning"), ("medium", "warning"), ("info", "info"),
                              ("note", "info"), ("low", "info"), ("good", "good"), ("weird", "info")):
            self.assertEqual(bash('ubs_normalize_severity "$1"', raw).stdout.decode(), expected)


class FormatContractTests(unittest.TestCase):
    def test_module_formats_accepted(self) -> None:
        for fmt in ("text", "json", "sarif"):
            self.assertEqual(bash('ubs_validate_format "$1"', fmt).returncode, 0, fmt)

    def test_meta_runner_formats_are_usage_errors(self) -> None:
        for fmt in ("jsonl", "toon"):
            proc = bash('ubs_validate_format "$1"', fmt)
            self.assertEqual(proc.returncode, 2, fmt)
            self.assertIn(b"produced by the meta-runner", proc.stderr)

    def test_unknown_format_exit2(self) -> None:
        proc = bash('ubs_validate_format "$1"', "xml")
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"unknown --format value", proc.stderr)


class ListFilesTests(unittest.TestCase):
    def test_literal_manifest_names_join_extensions_and_excludes_with_rg_and_find(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = ("go.mod", "go.sum", "go.work", "go.work.sum", "odd[1].mod",
                     "literal*.mod", "!bang.mod", "back\\slash.mod", "line\nbreak.mod",
                     "file{one}.mod", "#hash.mod", "question?.mod", "unclosed[.mod")
            expected = [root / "main.go", *(root / name for name in names)]
            for path in expected:
                path.write_text("")
            for name in ("README.txt", "odd1.mod", "literal-decoy.mod", "other.mod",
                         "fileone.mod", "questionX.mod"):
                (root / name).write_text("")
            (root / "vendor").mkdir()
            (root / "vendor" / "go.mod").write_text("")
            tools = root / "tools"
            tools.mkdir()
            # cat owns the listing's destination (4add1640), so the find-only
            # PATH still needs it.
            for name in ("bash", "cat", "find"):
                actual = shutil.which(name)
                self.assertIsNotNone(actual)
                (tools / name).symlink_to(actual)
            for label, env in (("rg", None), ("find", {"PATH": str(tools)})):
                with self.subTest(tool=label):
                    proc = bash('ubs_list_files "$1" --ext go --names "$2" --exclude vendor',
                                tmp, ",".join(names), env=env)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual(sorted(item for item in proc.stdout.split(b"\0") if item),
                                     sorted(os.fsencode(path) for path in expected), proc.stderr)

    def test_nul_safe_listing_with_extensions_and_excludes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "vendor").mkdir()
            (root / "src" / "a.py").write_text("x = 1\n")
            (root / "src" / "b.js").write_text("var x = 1;\n")
            (root / "src" / "odd\nname.py").write_text("y = 2\n")
            (root / "vendor" / "v.py").write_text("z = 3\n")
            proc = bash('ubs_list_files "$1" --ext py --exclude vendor', tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            listed = sorted(p for p in proc.stdout.decode("utf-8").split("\0") if p)
            self.assertEqual(listed, sorted([str(root / "src" / "a.py"), str(root / "src" / "odd\nname.py")]))
            count = bash('ubs_count_files "$1" --ext py,js --exclude vendor', tmp).stdout.decode().strip()
            self.assertEqual(count, "3")

    def test_files_from_keeps_only_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("")
            listing = root / "list.txt"
            listing.write_text("a.py\nmissing.py\n")
            proc = bash('ubs_list_files "$1" --files-from "$2"', tmp, str(listing))
            self.assertEqual([p for p in proc.stdout.decode().split("\0") if p], [str(root / "a.py")])

    def test_nul_files_from_preserves_embedded_and_trailing_newlines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = ["ordinary.py", "odd\nname.py", "trailing.py\n", "\nleading.py"]
            absolute = root / "absolute\npath.py"
            expected = [root / name for name in names] + [absolute]
            for path in expected:
                path.write_text("")
            # A splitter or newline trimmer would select these real decoys,
            # rather than merely dropping the requested paths.
            for name in ("odd", "name.py", "trailing.py", "leading.py"):
                (root / name).write_text("")
            listing = root / "files.0"
            entries = [*names, str(absolute), "missing.py"]
            listing.write_bytes(b"\0".join(os.fsencode(name) for name in entries) + b"\0")
            proc = bash('ubs_list_files "$1" --files-from "$2"', tmp, str(listing))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, b"".join(os.fsencode(path) + b"\0" for path in expected))


class LocaleTests(unittest.TestCase):
    def test_source_path_is_literal_even_with_quotes_and_expansion_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / 'library "$UNSET_LIBRARY_NAME".sh'
            shutil.copyfile(LIB, copied)
            with patch(__name__ + ".LIB", copied):
                proc = bash('printf %s "$UBS_COMMON_VERSION"')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, b"1")

    def test_export_locale_reaches_children(self) -> None:
        proc = bash('ubs_export_locale; bash -c "printf %s \\"\\$LC_ALL:\\$PYTHONIOENCODING\\""')
        self.assertEqual(proc.stdout.decode(), "C:utf-8")

    def test_double_source_is_harmless(self) -> None:
        proc = bash('source "$1"; printf %s "$UBS_COMMON_VERSION"', str(LIB))
        self.assertEqual(proc.stdout.decode(), "1")


def comma_decimal_locale() -> str | None:
    """A locale whose EPOCHREALTIME uses "," (ru_RU, de_DE...), or None if none is installed."""
    listed = subprocess.run(["locale", "-a"], capture_output=True, text=True).stdout.split()
    for name in ("ru_RU.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "ru_RU.utf8", "de_DE.utf8", "fr_FR.utf8"):
        if name in listed:
            probe = subprocess.run(["bash", "-c", 'printf %s "$EPOCHREALTIME"'], capture_output=True, text=True,
                                   env={**os.environ, "LC_ALL": "", "LC_NUMERIC": name})
            if "," in probe.stdout:
                return name
    return None


class EpochMillisecondsTests(unittest.TestCase):
    """GH #160: EPOCHREALTIME carries the LC_NUMERIC decimal separator, so splitting at a literal
    "." read the microsecond field as the epoch under ru_RU/de_DE (garbage or negative durations,
    and "value too great for base" when the fraction started with 0)."""

    def test_dot_and_comma_separators_give_the_same_milliseconds(self) -> None:
        for raw, expected in (("1791357093.406751", "1791357093406"), ("1791357093,406751", "1791357093406"),
                              ("1791357099,083236", "1791357099083"), ("1791357099.000999", "1791357099000")):
            proc = bash('ubs_epoch_ms "$1"', raw)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.decode().strip(), expected, raw)

    def test_runner_copy_matches(self) -> None:
        # The meta-runner keeps its own copy (it runs before any module library is sourced).
        runner = REPO_ROOT / "ubs"
        for raw, expected in (("1791357093,406751", "1791357093406"), ("1791357099.083236", "1791357099083")):
            proc = subprocess.run(
                ["bash", "-c", 'source <(sed -n "/^epoch_ms(){/,/^}/p" "$1"); epoch_ms "$2"', "bash", str(runner), raw],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), expected, raw)

    def test_now_ms_under_a_comma_decimal_locale(self) -> None:
        name = comma_decimal_locale()
        if name is None:
            self.skipTest("no comma-decimal locale installed")
        proc = bash('ubs_now_ms; date +%s', env={"LC_NUMERIC": name})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, b"")
        now_ms, epoch_s = (int(line) for line in proc.stdout.decode().split())
        self.assertLess(abs(now_ms - epoch_s * 1000), 5000)


if __name__ == "__main__":
    unittest.main()
