"""modules/lib/ubs-common.sh (bead A1): the primitives every module shares.

Each test runs bash with the library sourced and checks observable behaviour:
json_escape on quotes/backslashes/control characters/unicode and under set -u,
the severity table, the output-format contract (jsonl/toon/unknown exit 2),
NUL-safe file listing with a newline in a file name, and the exported locale.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB = REPO_ROOT / "modules" / "lib" / "ubs-common.sh"


def bash(script: str, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    full_env.pop("LC_ALL", None)
    if env:
        full_env.update(env)
    return subprocess.run(
        ["bash", "-c", f'set -Eeuo pipefail; source "{LIB}"; {script}', "bash", *args],
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


class LocaleTests(unittest.TestCase):
    def test_export_locale_reaches_children(self) -> None:
        proc = bash('ubs_export_locale; bash -c "printf %s \\"\\$LC_ALL:\\$PYTHONIOENCODING\\""')
        self.assertEqual(proc.stdout.decode(), "C:utf-8")

    def test_double_source_is_harmless(self) -> None:
        proc = bash(f'source "{LIB}"; printf %s "$UBS_COMMON_VERSION"')
        self.assertEqual(proc.stdout.decode(), "1")


if __name__ == "__main__":
    unittest.main()
