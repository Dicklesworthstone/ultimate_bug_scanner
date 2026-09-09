#!/usr/bin/env python3
"""Precision regressions for the Python layer (self-scan gate, bead D8).

`./ubs . --ci --fail-on-warning` on the ubs checkout itself reported 705
warnings and 0 criticals. Every one was a false positive, in six families;
each family is pinned here.

* ``py.numeric.division-heavy`` read ``pathlib`` joins as divisions
  (78 of 85 warnings were ``rules_dir / name``), and its text-prefix divisor
  test accepted an f-string denominator.
* ``py.debug.print`` counted every ``print(`` in the project, so a CLI whose
  job is writing to stdout failed its own gate (152 warnings across 76 files,
  75 of them command line entry points).
* ``py.collections.index-arithmetic`` matched the shape ``x[i + 1]`` with no
  notion of a bound, reporting 224 guarded neighbour lookups.
* ``py.io.open-missing-with`` counted the substring ``open(`` on raw lines, so
  docstrings and comments *about* open() counted as unmanaged file handles.
* ``py.comparison.is-literal`` / ``py.is-literal`` flagged ``x is True``,
  where the suggested ``==`` is not equivalent (``1 == True``).
* The pattern layer matched inside string literals, so a rule table that
  quotes ``$X == None`` or ``hashlib.md5($$$)`` reported itself.

Two real defects the fixed rules then found are pinned as well: the
``sg --version`` probe with no timeout, and the exponential-backtracking type
prefix in the Java/C# detectors.
"""
from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import parse_ndjson_lines, read_ndjson  # noqa: E402
from ubs_core.py_detectors import division, index_arithmetic, io_open_checks, is_literal  # noqa: E402
from ubs_core.py_patterns.debug_typing import PATTERNS as DEBUG_PATTERNS  # noqa: E402
from ubs_core.py_patterns.flow import PATTERNS as FLOW_PATTERNS  # noqa: E402
from ubs_core.py_patterns.foundations import PATTERNS as FOUNDATION_PATTERNS  # noqa: E402
from ubs_core.py_patterns.quality import PATTERNS as QUALITY_PATTERNS  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS as SECURITY_PATTERNS  # noqa: E402
from ubs_core.py_scan import scan_patterns  # noqa: E402


def pattern(rule_id: str):
    for group in (DEBUG_PATTERNS, FLOW_PATTERNS, FOUNDATION_PATTERNS,
                  QUALITY_PATTERNS, SECURITY_PATTERNS):
        for entry in group:
            if entry.rule_id == rule_id:
                return entry
    raise AssertionError(f"unknown pattern {rule_id}")


class _Sink:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def write(self, line: str) -> None:
        self.records.append(json.loads(line))


def run_patterns(rule_id: str, sources: dict[str, str]) -> list[dict]:
    """Run one pattern over a temporary project and return its records."""
    with tempfile.TemporaryDirectory(prefix="ubs_pyprec_") as tmp:
        paths = []
        for name, body in sources.items():
            target = Path(tmp) / name
            target.write_text(textwrap.dedent(body), encoding="utf-8")
            paths.append(target)
        sink = _Sink()
        scan_patterns([pattern(rule_id)], paths, sink, skip=set())
    return sink.records


def run_detector(module, sources: dict[str, str]) -> list[tuple]:
    with tempfile.TemporaryDirectory(prefix="ubs_pyprec_") as tmp:
        paths = []
        for name, body in sources.items():
            target = Path(tmp) / name
            target.write_text(textwrap.dedent(body), encoding="utf-8")
            paths.append(target)
        return list(module.find(paths))


# ────────────────────────────── division ──────────────────────────────
class PathlibIsNotDivisionTests(unittest.TestCase):
    CLEAN = '''
        from pathlib import Path

        BASE = Path("/srv")

        def build(rules_dir, name, args):
            fdir = Path(args.files_dir)
            rules_sub = rules_dir / "rules"
            parent = fdir.parent
            return [
                rules_sub / f"{name}.yml",
                rules_sub / name,
                BASE / name,
                Path.cwd() / name,
                parent / name,
                fdir.resolve() / name,
                get_cache_dir() / name,
            ]

        def get_cache_dir():
            return BASE
    '''

    def test_path_joins_are_not_divisions(self) -> None:
        self.assertEqual(run_detector(division, {"paths.py": self.CLEAN}), [])

    def test_real_variable_division_still_reported(self) -> None:
        hits = run_detector(division, {"math.py": '''
            def ratios(hits, total, counts, scale):
                a = hits / total
                b = sum(counts) / scale
                c = hits / counts[0]
                return a, b, c
        '''})
        self.assertEqual(len(hits), 3, hits)
        self.assertTrue(all(h[0].startswith("py.numeric.division") for h in hits))

    def test_fstring_denominator_is_not_a_divisor(self) -> None:
        # The legacy filter kept any denominator whose *text* began with a
        # letter, so `f"…"` looked like a variable named `f`.
        hits = run_detector(division, {"fmt.py": '''
            def build(base, name):
                return base / f"{name}.yml"
        '''})
        self.assertEqual(hits, [])

    def test_ladder_promotes_to_warning_above_threshold(self) -> None:
        body = "def f(n, d):\n    return (\n" + "".join(
            f"        n / d,  # {i}\n" for i in range(division.WARNING_ABOVE + 2)
        ) + "    )\n"
        hits = run_detector(division, {"many.py": body})
        self.assertGreater(len(hits), division.WARNING_ABOVE)
        self.assertTrue(all(h[0] == "py.numeric.division-heavy" for h in hits))


# ─────────────────────────── index arithmetic ───────────────────────────
class IndexArithmeticGuardTests(unittest.TestCase):
    GUARDED = '''
        MARKER = "x"

        def inline_and(i, line):
            if i + 1 < len(line) and line[i + 1] == "/":
                return True
            return False

        def chained(idx, lines):
            return 0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]

        def enclosing_if(i, line):
            if i + 1 < len(line):
                return line[i + 1]
            return ""

        def or_case_split(idx, text):
            return idx == 0 or text[idx - 1] != "_"

        def one_based(lines):
            for idx, _ in enumerate(lines, start=1):
                yield lines[idx - 1]

        def ranged(x):
            for i in range(len(x) - 1):
                yield x[i + 1]

        def ranged_from_one(x, n):
            for i in range(1, n):
                yield x[i - 1]

        def early_exit(index, lines):
            start = index
            for _ in range(8):
                if start <= 0:
                    break
                if lines[start - 1].strip():
                    return start
                start -= 1
            return ""

        def truthiness(start, lines):
            return lines[start - 1] if start else ""

        def truthy_statement(start, lines):
            if not start:
                return ""
            return lines[start - 1]

        def caught(x, i):
            try:
                return x[i + 1]
            except IndexError:
                return None

        def ternary_guard(i, x):
            return x[i + 1] if i + 1 < len(x) else None

        def comprehension(x, n):
            return [x[i + 1] for i in range(n) if i + 1 < len(x)]

        def while_guard(i, s):
            while i + 1 < len(s):
                if s[i + 1] == "a":
                    return i
                i += 1
            return -1

        def asserted(i, x):
            assert i + 1 < len(x)
            return x[i + 1]
    '''

    UNGUARDED = '''
        def neighbours(x, i, j, k):
            a = x[i + 1]
            b = x[j - 1]
            c = x[k + 2]
            return a, b, c

        def argv_value(args):
            i = args.index("--root")
            return args[i + 1]

        def plain_enumerate(seq):
            for i, _ in enumerate(seq):
                yield seq[i - 1]
    '''

    def test_guarded_offsets_are_silent(self) -> None:
        self.assertEqual(run_detector(index_arithmetic, {"guarded.py": self.GUARDED}), [])

    def test_truthiness_split_only_guards_the_true_branch(self) -> None:
        # `if not i:` proves i == 0 inside its own body — the opposite of a guard.
        hits = run_detector(index_arithmetic, {"branch.py": """
            def wrong_branch(i, x):
                if not i:
                    return x[i - 1]
                return x[i]

            def wrong_else(i, x):
                return x[i] if i else x[i - 1]

            def element_not_index(i, x):
                if x[i - 1]:
                    return x[i - 1]
                return None
        """})
        self.assertEqual(len(hits), 4, hits)

    def test_equality_only_guards_against_a_literal_boundary(self) -> None:
        # `idx == 0` is a boundary case split; `i == j` says nothing about range.
        hits = run_detector(index_arithmetic, {"eq.py": """
            def unrelated(i, j, x):
                if i == j:
                    return x[i - 1]
                return None

            def boundary(idx, text):
                return idx == 0 or text[idx - 1] != "_"
        """})
        self.assertEqual(len(hits), 1, hits)

    def test_unguarded_offsets_are_reported(self) -> None:
        hits = run_detector(index_arithmetic, {"unguarded.py": self.UNGUARDED})
        self.assertEqual(len(hits), 5, hits)

    def test_ladder_promotes_to_warning_above_threshold(self) -> None:
        body = "def f(x, i):\n    return (\n" + "".join(
            f"        x[i + {n}],\n" for n in range(1, index_arithmetic.WARNING_ABOVE + 3)
        ) + "    )\n"
        hits = run_detector(index_arithmetic, {"many.py": body})
        self.assertGreater(len(hits), index_arithmetic.WARNING_ABOVE)
        self.assertTrue(all(h[0] == "py.collections.index-arithmetic" for h in hits))

    def test_below_threshold_is_the_info_tier(self) -> None:
        hits = run_detector(index_arithmetic, {"few.py": "def f(x, i):\n    return x[i + 1]\n"})
        self.assertEqual([h[0] for h in hits], ["py.collections.index-arithmetic-info"])

    def test_marker_suppresses_and_leaves_the_count(self) -> None:
        hits = run_detector(index_arithmetic, {"marked.py": '''
            def f(x, i):
                # ubs:ignore[py.collections.index-arithmetic]
                return x[i + 1]
        '''})
        self.assertEqual(hits, [])

    def test_string_and_comment_shapes_are_not_code(self) -> None:
        hits = run_detector(index_arithmetic, {"docs.py": '''
            """Explains chars[i + 1] and lines[idx - 1] in prose."""
            PATTERN = r"\\[[A-Za-z_]+ *[+-] *[0-9]+\\]"
            # a comment about buf[n + 1]
        '''})
        self.assertEqual(hits, [])


# ─────────────────────────────── open() ───────────────────────────────
class OpenMissingWithTests(unittest.TestCase):
    def test_prose_about_open_is_not_a_handle(self) -> None:
        hits = run_detector(io_open_checks, {"prose.py": '''
            """Tracks handles created by ``tarfile.open()`` and open()."""
            import re
            OPEN_RE = re.compile(r"open\\(")
            # legacy counted every open( on the line
        '''})
        self.assertEqual(hits, [])

    def test_with_managed_handles_are_clean(self) -> None:
        hits = run_detector(io_open_checks, {"managed.py": '''
            import contextlib
            from pathlib import Path

            def read(p):
                with open(p, encoding="utf-8") as fh:
                    return fh.read()

            def read_path(p: Path):
                with p.open(encoding="utf-8") as fh:
                    return fh.read()

            def read_closing(p):
                with contextlib.closing(open(p, encoding="utf-8")) as fh:
                    return fh.read()

            def read_explicit(p):
                fh = open(p, encoding="utf-8")
                try:
                    return fh.read()
                finally:
                    fh.close()
        '''})
        self.assertEqual(hits, [])

    def test_unmanaged_handle_is_reported(self) -> None:
        hits = run_detector(io_open_checks, {"leak.py": '''
            import json

            def read(p):
                return open(p, encoding="utf-8").read()

            def load(p):
                return json.load(open(p, encoding="utf-8"))
        '''})
        self.assertEqual(len(hits), 2, hits)


# ───────────────────────────── is <literal> ─────────────────────────────
class IsLiteralSingletonTests(unittest.TestCase):
    def test_bool_singletons_are_idiomatic(self) -> None:
        hits = run_detector(is_literal, {"tri.py": '''
            def truthy(value):
                return value is True or value == 1

            def falsy(value):
                return value is False or value is None
        '''})
        self.assertEqual(hits, [])

    def test_other_literals_still_reported(self) -> None:
        hits = run_detector(is_literal, {"lit.py": '''
            def classify(status, code, values):
                if status is "ready":
                    return 1
                if code is 200:
                    return 2
                if values is []:
                    return 3
                return 0
        '''})
        self.assertEqual(len(hits), 3, hits)

    def test_ast_grep_rule_no_longer_names_bool(self) -> None:
        from ubs_core.py_rules import _RULES

        source = dict(_RULES)["is-literal"]
        self.assertNotIn("is True", source)
        self.assertNotIn("is False", source)
        self.assertIn("is 0", source)


# ─────────────────────── pattern layer: string masking ───────────────────────
class PatternStringMaskingTests(unittest.TestCase):
    RULE_TABLE = '''
        """A rule table: the snippets below are data, not code."""
        RULES = (
            "- pattern: $X == None",
            "- pattern: os.system($$$)",
            "- pattern: hashlib.md5($$$)",
            'message: "Use isinstance(x, T) instead of type(x) == T"',
            ("TODO", "FIXME", "HACK", "XXX"),
        )
    '''

    def test_snippets_in_literals_are_not_code(self) -> None:
        for rule_id in ("py.none.equality", "py.modules.os-system",
                        "py.security.weak-hash", "py.comparison.type-equality",
                        "py.code-quality.tech-debt"):
            with self.subTest(rule=rule_id):
                self.assertEqual(run_patterns(rule_id, {"rules.py": self.RULE_TABLE}), [])

    def test_real_code_still_matches(self) -> None:
        source = '''
            import hashlib
            import os

            def go(x, value):
                if value == None:
                    os.system("ls")
                return hashlib.md5(x).hexdigest(), type(x) == int
        '''
        for rule_id in ("py.none.equality", "py.modules.os-system",
                        "py.security.weak-hash", "py.comparison.type-equality"):
            with self.subTest(rule=rule_id):
                self.assertTrue(run_patterns(rule_id, {"live.py": source}), rule_id)

    def test_tech_debt_still_reads_comments(self) -> None:
        records = run_patterns("py.code-quality.tech-debt", {"c.py": '''
            def f():
                # TODO: finish this
                return 1  # FIXME later
        '''})
        self.assertEqual(len(records), 2, records)

    def test_masking_keeps_line_numbers_and_raw_samples(self) -> None:
        records = run_patterns("py.none.equality", {"n.py": '''
            def f(value):
                if value == None:
                    return 0
                return 1
        '''})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["line"], 3)
        self.assertIn("value == None", records[0]["message"])

    def test_notebook_json_is_not_masked_as_python(self) -> None:
        records = run_patterns("py.notebooks.outputs-embedded", {
            # One match per line: the scan counts distinct matching lines.
            "nb.ipynb": '{"cells": [\n' + '  {"outputs": [{"a": 1}]},\n' * 7 + "]}"
        })
        self.assertTrue(records)


class DeprecatedImpBoundaryTests(unittest.TestCase):
    def test_importlib_is_not_the_removed_imp_module(self) -> None:
        records = run_patterns("py.deprecations.deprecated-api", {"i.py": "import importlib\n"})
        self.assertEqual(records, [])

    def test_real_imp_import_still_reported(self) -> None:
        for source in ("import imp\n", "import imp as legacy\n", "from imp import reload\n",
                       "loop = asyncio.get_event_loop()\n"):
            with self.subTest(source=source.strip()):
                self.assertTrue(run_patterns("py.deprecations.deprecated-api", {"i.py": source}))


# ───────────────────────────── py.debug.print ─────────────────────────────
class DebugPrintCliRoleTests(unittest.TestCase):
    MANY_PRINTS = "".join(f'    print("line {i}")\n' for i in range(60))

    def test_cli_entry_point_may_print(self) -> None:
        for header in (
            "#!/usr/bin/env python3\ndef main():\n",
            "import argparse\ndef main():\n",
            "import sys\ndef main():\n    _ = sys.argv\n",
            'def main():\n    pass\nif __name__ == "__main__":\n    main()\ndef other():\n',
        ):
            with self.subTest(header=header.splitlines()[0]):
                records = run_patterns("py.debug.print", {"cli.py": header + self.MANY_PRINTS})
                self.assertEqual(records, [], header)

    def test_library_module_still_reported(self) -> None:
        records = run_patterns("py.debug.print", {"lib.py": "def emit():\n" + self.MANY_PRINTS})
        self.assertEqual(len(records), 60)
        self.assertTrue(all(r["severity"] == "warning" for r in records))

    def test_prose_about_argv_does_not_fake_a_cli_role(self) -> None:
        # The role test runs on the string-blanked view for exactly this case:
        # a docstring that *mentions* argparse/sys.argv/__main__ is not a CLI.
        source = (
            '"""A library module: no argparse, no sys.argv, no __main__ guard."""\n'
            "def emit():\n" + self.MANY_PRINTS
        )
        self.assertEqual(len(run_patterns("py.debug.print", {"lib.py": source})), 60)

    def test_print_inside_a_docstring_is_not_a_statement(self) -> None:
        records = run_patterns("py.debug.print", {"d.py": '''
            def f():
                """Example:

                print("hello")
                """
                return 1
        '''})
        self.assertEqual(records, [])


# ───────────────────── defects the fixed rules uncovered ─────────────────────
class RegexBacktrackingTests(unittest.TestCase):
    """The Java/C# type-prefix regexes were exponential on a long line."""

    ADVERSARIAL = "public " + "a " * 40 + "!"

    def test_csharp_method_regex_is_linear(self) -> None:
        from ubs_core.csharp_detectors import security_randomness as cs

        started = time.monotonic()
        cs.METHOD_RE.search(self.ADVERSARIAL)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_java_func_regex_is_linear(self) -> None:
        from ubs_core.java_detectors import security_randomness as java

        started = time.monotonic()
        java.FUNC_RE.search(self.ADVERSARIAL)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_csharp_annotated_param_regex_is_linear(self) -> None:
        from ubs_core.csharp_detectors import header_injection as hi

        started = time.monotonic()
        hi.ANNOTATED_PARAM_RE.search("[FromQuery] " + "a " * 40 + "!")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_type_prefix_still_matches_generics(self) -> None:
        from ubs_core.csharp_detectors import security_randomness as cs

        for line, name in (
            ("    public static List<int, string> Foo(int a) {", "Foo"),
            ("    private Dictionary<string, List<int>> Bar() {", "Bar"),
            ("    int[] Baz(string s) =>", "Baz"),
        ):
            with self.subTest(line=line.strip()):
                match = cs.METHOD_RE.search(line)
                self.assertIsNotNone(match)
                self.assertEqual(match.group("name"), name)

    def test_no_detector_regex_mixes_space_into_a_repeated_token_class(self) -> None:
        """The bug class: a class containing ' ' repeated next to \\s under a +."""
        offenders = []
        for path in (HELPERS_DIR / "ubs_core").rglob("*.py"):
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\[[^\]]* [^\]]*\]\+\\s\+\)\+", line):
                    offenders.append(f"{path.name}:{line_no}")
        self.assertEqual(offenders, [])


class AstGrepProbeTests(unittest.TestCase):
    def test_probe_is_bounded(self) -> None:
        from ubs_core import rust_scan

        started = time.monotonic()
        out = rust_scan._probe(sys.executable, "-c")
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertIsInstance(out, str)

    def test_probe_swallows_a_missing_binary(self) -> None:
        from ubs_core import rust_scan

        self.assertEqual(rust_scan._probe("/nonexistent/ubs-probe-target", "--version"), "")

    def test_probe_closes_stdin(self) -> None:
        """A probe target that reads stdin must see EOF, not block."""
        from ubs_core import rust_scan

        script = "import sys; sys.stdout.write('eof' if sys.stdin.read() == '' else 'data')"
        with tempfile.TemporaryDirectory(prefix="ubs_probe_") as tmp:
            target = Path(tmp) / "probe.py"
            target.write_text(script, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(target)], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, timeout=10,
            )
        self.assertEqual(completed.stdout, "eof")


class NdjsonReaderTests(unittest.TestCase):
    def test_malformed_line_is_skipped_not_fatal(self) -> None:
        stderr = io.StringIO()
        real, sys.stderr = sys.stderr, stderr
        try:
            records = parse_ndjson_lines(['{"a": 1}', "", "{truncated", '{"b": 2}'], "sink")
        finally:
            sys.stderr = real
        self.assertEqual(records, [{"a": 1}, {"b": 2}])
        self.assertIn("sink:3", stderr.getvalue())

    def test_non_object_records_are_dropped(self) -> None:
        self.assertEqual(parse_ndjson_lines(['{"a": 1}', "[1, 2]", "7"], "s"), [{"a": 1}])

    def test_missing_sink_yields_no_records(self) -> None:
        stderr = io.StringIO()
        real, sys.stderr = sys.stderr, stderr
        try:
            self.assertEqual(read_ndjson("/nonexistent/ubs-sink.ndjson"), [])
        finally:
            sys.stderr = real
        self.assertIn("cannot read NDJSON sink", stderr.getvalue())

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_ndjson_") as tmp:
            sink = Path(tmp) / "s.ndjson"
            sink.write_text('{"rule": "r", "line": 1}\n\n{"rule": "s", "line": 2}\n', encoding="utf-8")
            self.assertEqual(
                read_ndjson(sink),
                [{"rule": "r", "line": 1}, {"rule": "s", "line": 2}],
            )


class TrailingRootFlagTests(unittest.TestCase):
    """`--root` with no value used to raise IndexError from args[i + 1]."""

    def test_detectors_reject_a_valueless_root_flag(self) -> None:
        for module in ("ubs_core.rust_detectors.tls_indirect",
                       "ubs_core.rust_detectors.hardcoded_secrets"):
            with self.subTest(module=module):
                completed = subprocess.run(
                    [sys.executable, "-m", module, "--root"],
                    capture_output=True, text=True, cwd=str(HELPERS_DIR), timeout=60,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("IndexError", completed.stderr)
                self.assertIn("--root requires a directory argument", completed.stderr)


class SelfScanShapeTests(unittest.TestCase):
    """The detectors that were rewritten must stay quiet on ubs's own sources."""

    def setUp(self) -> None:
        self.sources = [
            path
            for path in (REPO_ROOT / "modules" / "helpers").rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        self.assertGreater(len(self.sources), 100)

    def test_open_handles_are_all_context_managed(self) -> None:
        self.assertEqual(list(io_open_checks.find(self.sources)), [])

    def test_index_arithmetic_stays_under_the_warning_tier(self) -> None:
        hits = list(index_arithmetic.find(self.sources))
        self.assertTrue(
            all(rule == "py.collections.index-arithmetic-info" for rule, *_ in hits),
            [h[1:3] for h in hits if h[0] != "py.collections.index-arithmetic-info"],
        )

    def test_division_stays_under_the_warning_tier(self) -> None:
        hits = list(division.find(self.sources))
        self.assertTrue(
            all(rule == "py.numeric.division" for rule, *_ in hits),
            [h[1:3] for h in hits if h[0] != "py.numeric.division"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
