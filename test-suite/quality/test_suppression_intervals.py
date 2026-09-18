#!/usr/bin/env python3
"""Unit tests for ubs_core.suppression — statement-interval index (bead A7)."""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.csharp_scan import render_text  # noqa: E402
from ubs_core import cpp_scan, java_scan, rust_scan, swift_scan  # noqa: E402
from ubs_core.lexer import strip_comments_and_strings  # noqa: E402
from ubs_core import rust_rules  # noqa: E402
from ubs_core.analyzers import ctcompare_rust  # noqa: E402
from ubs_core.rust_detectors import (  # noqa: E402
    cors_credential, hardcoded_secrets, host_header_url, jwt_verification,
    loop_context, open_redirect, request_regex, request_url, response_header,
    security_randomness, sql_injection, tls_indirect,
)
from ubs_core.suppression import (  # noqa: E402
    Interval, Marker, SourceSuppressions, SuppressionIndex, build_index,
    has_suppression_marker, may_have_markers, parse_markers,
)

# Line numbers are load-bearing in the assertions below; count carefully.
PY_CODE = '''import os


def handler(event):
    os.system(event["cmd"])  # ubs:ignore
    return None


def cleaner(event):
    # ubs:ignore
    os.system(event["cmd"])
    return None


def multi_line(event):
    os.system(
        # ubs:ignore
        event["cmd"]
    )
    return None


def formatter_case():
    if event:
    # ubs:ignore
        os.system(event["cmd"])


def rule_scoped(event):
    os.system(event["cmd"])  # ubs:ignore[py.taint]
    eval(event["x"])  # ubs:ignore[py.taint,py.eval]


def string_not_marker(event):
    doc = "never write ubs:ignore in strings"
    os.system(event["cmd"])
'''


class SuppressionLookupScalingTests(unittest.TestCase):
    @staticmethod
    def reference(index: SuppressionIndex, line: int, rule: str) -> bool:
        # Deliberately retain the pre-index algorithm as a differential oracle.
        matches = [item for item in index.intervals if item.start_line <= line <= item.end_line]
        interval = min(matches, key=lambda item: item.end_line - item.start_line, default=None)
        statement = interval if interval in index.statements else None
        return any(
            (marker.rules is None or rule in marker.rules) and (
                marker.line == line
                or (statement is not None and statement.contains(marker.line))
                or (marker.line in index.formatter_headers
                    and index.formatter_headers[marker.line].contains(line))
                or (marker.standalone and interval is not None and (
                    marker.line == interval.start_line - 1
                    or (marker.line == line + 1 and any(
                        block.start_line == line and block.contains(marker.line)
                        and block not in index.statements for block in index.intervals
                    ))
                ))
            ) for marker in index.markers
        )

    def test_randomized_overlaps_match_original_suppression(self) -> None:
        rng = random.Random(477)
        for _ in range(100):
            intervals = [Interval(rng.randrange(-2, 35), rng.randrange(-2, 35)) for _ in range(40)]
            # Equal values must count as statements even when identities differ.
            statements = [Interval(item.start_line, item.end_line) for item in intervals[::3]]
            markers = [Marker(rng.randrange(-3, 38), rng.choice([None, frozenset({"a"})]),
                              rng.choice([True, False])) for _ in range(10)]
            index = SuppressionIndex(intervals, markers, statements, {4: Interval(1, 3)})
            expected = {(line, rule): self.reference(index, line, rule)
                        for line in range(-4, 40) for rule in ("a", "b")}
            index._finalize()
            for (line, rule), suppressed in expected.items():
                self.assertEqual(index.is_suppressed(line, rule), suppressed, (line, rule))

    def test_equal_span_ties_boundaries_and_large_gaps(self) -> None:
        first, second = Interval(4, 8), Interval(2, 6)
        remote = Interval(10**12, 10**12 + 1)
        index = SuppressionIndex([first, second, remote, Interval(9, 7)])
        index._finalize()
        for line, expected in [(1, None), (2, second), (4, first), (6, first),
                               (8, first), (9, None), (10**12, remote), (10**12 + 2, None)]:
            self.assertIs(index._interval_for(line), expected)
        self.assertLessEqual(len(index._lookup.boundaries), 6)
        empty = SuppressionIndex()
        empty._finalize()
        self.assertIsNone(empty._interval_for(1))

    def test_mutable_indexes_and_replaced_snapshots_use_current_values(self) -> None:
        index = SuppressionIndex([Interval(1, 8)], [Marker(3, None)])
        self.assertFalse(index.is_suppressed(4, "a"))
        index.statements.append(Interval(1, 8))
        self.assertTrue(index.is_suppressed(4, "a"))
        index._finalize()
        index.statements = []
        self.assertFalse(index.is_suppressed(4, "a"))
        index._finalize()
        index.intervals = [Interval(4, 4)]
        self.assertEqual(index._interval_for(4), Interval(4, 4))
        self.assertIsNone(index._interval_for(3))

    def test_large_parsed_source_does_not_scan_intervals_per_finding(self) -> None:
        source = "fn run() {\n// ubs:ignore[other.rule]\n" + "call();\n" * 20000 + "}\n"
        index = build_index(source, lang="rust")
        calls = 0
        comparisons = 0
        original = Interval.contains
        original_eq = Interval.__eq__

        def count_contains(interval: Interval, line: int) -> bool:
            nonlocal calls
            calls += 1
            return original(interval, line)

        def count_comparisons(interval: Interval, other: object) -> bool:
            nonlocal comparisons
            comparisons += 1
            return original_eq(interval, other)

        with (patch.object(Interval, "contains", count_contains),
              patch.object(Interval, "__eq__", count_comparisons)):
            for line in range(3, 20003):
                self.assertFalse(index.is_suppressed(line, "public.rule"))
        self.assertEqual(calls, 0)
        self.assertLessEqual(comparisons, 20000)
        self.assertTrue(index.is_suppressed(1, "other.rule"))
        self.assertFalse(index.is_suppressed(20002, "other.rule"))


class PythonSuppressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.idx = build_index(PY_CODE, lang="python")

    def test_trailing_marker_suppresses(self) -> None:
        # Line 5: `os.system(event["cmd"])  # ubs:ignore`
        self.assertTrue(self.idx.is_suppressed(5, "py.taint"))

    def test_previous_line_marker_suppresses(self) -> None:
        # Line 11 is the finding; line 10 is the marker.
        self.assertTrue(self.idx.is_suppressed(11, "py.taint"))

    def test_marker_inside_multiline_statement(self) -> None:
        # The multi-line shell call opens on line 16; its marker is on line 17, a
        # physical line of the same logical statement.
        self.assertTrue(self.idx.is_suppressed(16, "py.taint"))

    def test_formatter_moved_marker(self) -> None:
        # `if event:` opens the block at line 24; the marker was relocated to
        # line 25, the first line inside the block.
        self.assertTrue(self.idx.is_suppressed(24, "py.taint"))

    def test_nested_formatter_marker_keeps_enclosing_and_sibling_statements(self) -> None:
        source = (
            "def run():\n"
            "    before()\n"
            "    if condition:\n"
            "        # ubs:ignore[py.taint]\n"
            "        risky()\n"
            "        same_block_sibling()\n"
            "    outer_sibling()\n"
        )
        index = build_index(source, lang="python")
        self.assertEqual([line for line in range(1, 8) if index.is_suppressed(line, "py.taint")],
                         [3, 4, 5])
        self.assertFalse(any(index.is_suppressed(line, "py.other") for line in range(1, 8)))

    def test_rule_scoped_only_listed_rules(self) -> None:
        self.assertTrue(self.idx.is_suppressed(30, "py.taint"))
        self.assertFalse(self.idx.is_suppressed(30, "py.other"))
        self.assertTrue(self.idx.is_suppressed(31, "py.taint"))
        self.assertTrue(self.idx.is_suppressed(31, "py.eval"))

    def test_string_contents_are_not_markers(self) -> None:
        self.assertFalse(self.idx.is_suppressed(36, "py.taint"))

    def test_unmarked_finding_not_suppressed(self) -> None:
        self.assertFalse(self.idx.is_suppressed(1, "py.taint"))

    def test_non_listed_rule_ignores_even_bareless_lines(self) -> None:
        # Line 12 (`return None` in `cleaner`) has no marker anchor.
        self.assertFalse(self.idx.is_suppressed(12, "py.other"))


# Line numbers are load-bearing; count carefully.
JS_CODE = '''function handler(req) {
  const {cmd} = req.query;
  child_process.exec(
    cmd, // ubs:ignore[js.taint]
    (err) => {}
  );
}

function nested(req) {
  if (req) {
    // ubs:ignore[js.deep]
    const x = req.a.b.c.d;
  }
  const y = req.p.q.r.s;
}
'''


class JsSuppressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.idx = build_index(JS_CODE, lang="javascript")

    def test_multiline_call_marker_any_line(self) -> None:
        # `child_process.exec(` opens at line 3; the marker is on line 4.
        self.assertTrue(self.idx.is_suppressed(3, "js.taint"))

    def test_block_formatter_case(self) -> None:
        # `if (req) {` opens at line 10; the marker was relocated to line 11.
        self.assertTrue(self.idx.is_suppressed(10, "js.deep"))

    def test_marker_in_inner_block_does_not_leak(self) -> None:
        # `const x` (line 12) is suppressed; the later `const y` is not.
        self.assertTrue(self.idx.is_suppressed(12, "js.deep"))
        self.assertFalse(self.idx.is_suppressed(14, "js.deep"))

    def test_scoped_marker_rejects_other_rule(self) -> None:
        self.assertFalse(self.idx.is_suppressed(3, "js.other"))


# Line numbers are load-bearing; count carefully.
RUBY_CODE = '''def handler(req)
  # ubs:ignore
  eval(req[:cmd])
end

def clean(req)
  eval(req[:cmd])
end
'''


class RubySuppressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.idx = build_index(RUBY_CODE, lang="ruby")

    def test_keyword_block_previous_line(self) -> None:
        self.assertTrue(self.idx.is_suppressed(3, "rb.taint"))

    def test_second_block_unaffected(self) -> None:
        self.assertFalse(self.idx.is_suppressed(7, "rb.taint"))


class MarkerParsingTests(unittest.TestCase):
    def test_bare_aliases_require_actual_comments_and_own_one_statement(self) -> None:
        for language, comment in (("python", "#"), ("cpp", "//"), ("rust", "//"),
                                  ("java", "//"), ("swift", "//"), ("csharp", "//")):
            for alias in ("nolint", "NOQA", "ubs: disable", "ubs:disable"):
                source = (
                    f'let note = "{alias}"; literal_call();\n'
                    f"first(); {comment} {alias} -- intentional\n"
                    "second();\n"
                    f"{comment} {alias}\n"
                    "third();\n"
                    "fourth();\n"
                )
                with self.subTest(language=language, alias=alias):
                    self.assertTrue(may_have_markers(source))
                    index = build_index(source, lang=language)
                    self.assertEqual([(marker.line, marker.standalone) for marker in index.markers],
                                     [(2, False), (4, True)])
                    for rule in ("public.rule", "other.rule"):
                        self.assertEqual([line for line in (1, 2, 3, 5, 6)
                                          if index.is_suppressed(line, rule)], [2, 5])
                    self.assertEqual(parse_markers(f'let {alias.split(":")[0].lower()} = 1;\n',
                                                   lang=language), [])

    def test_qualified_aliases_never_backtrack_to_bare(self) -> None:
        for alias in ("noqa:F841", "noqa: F841", "noqa [F841]", "nolint:some-rule",
                      "nolint[some-rule]", "noqa(other.rule)", "nolint/other.rule",
                      "nolint-next-line", "ubs: disable[other.rule]",
                      "ubs: disable: other.rule", "not_noqa", "nolinting"):
            with self.subTest(alias=alias):
                index = build_index(f"first(); // {alias}\nsecond();\n", lang="rust")
                self.assertEqual(index.markers, [])
                self.assertFalse(index.is_suppressed(1, "public.rule"))
                self.assertFalse(index.is_suppressed(2, "public.rule"))

    def test_alias_words_inside_rule_scopes_are_not_bare_directives(self) -> None:
        for marker in ("ubs:ignore[noqa]", "ubs:ignore[nolint, other.rule]",
                       "ubs:ignore[other.rule, noqa]", "ubs:ignore[noqa*]",
                       "ubs:ignore[noqa", "nolint[noqa]", "noqa: noqa",
                       "ubs: disable[nolint]", "nolint(noqa)"):
            with self.subTest(marker=marker):
                index = build_index(f"first(); // {marker}\nsecond();\n", lang="rust")
                self.assertFalse(index.is_suppressed(1, "public.rule"))
                self.assertFalse(index.is_suppressed(2, "public.rule"))
        index = build_index("first(); // ubs:ignore[noqa] -- nolint\n", lang="rust")
        self.assertTrue(index.is_suppressed(1, "public.rule"), "an independent actual bare alias still applies")

    def test_multiple_markers_on_one_line(self) -> None:
        markers = parse_markers("x()  # ubs:ignore[a] y() # ubs:ignore[b]\n", lang="python")
        self.assertEqual(len(markers), 2)
        self.assertEqual({m.line for m in markers}, {1})

    def test_empty_scope_is_bare(self) -> None:
        markers = parse_markers("x()  # ubs:ignore[]\n", lang="python")
        self.assertEqual(len(markers), 1)
        self.assertIsNone(markers[0].rules)

    def test_marker_in_block_comment_counts(self) -> None:
        markers = parse_markers("/* ubs:ignore */\nx()\n", lang="c_like")
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0].line, 1)


class SourceIntervalBoundaryTests(unittest.TestCase):
    def test_split_brace_marker_covers_only_its_control_header(self) -> None:
        for header in ("using (var digest = MD5.Create())", "if (check())", "lock (mutex)"):
            source = (
                "before();\n" + header + "\n"
                "{ // ubs:ignore[public.rule]\n"
                "    inside();\n"
                "}\n"
                "after();\n"
            )
            with self.subTest(header=header):
                index = build_index(source, lang="csharp")
                self.assertEqual([line for line in range(1, 7) if index.is_suppressed(line, "public.rule")],
                                 [2, 3])
                self.assertFalse(any(index.is_suppressed(line, "other.rule") for line in range(1, 7)))
        index = build_index("call();\n{ // ubs:ignore\n    other();\n}\n", lang="csharp")
        self.assertFalse(index.is_suppressed(1, "public.rule"))
        self.assertFalse(index.is_suppressed(3, "public.rule"))
        fixtures = REPO_ROOT / "test-suite" / "csharp" / "suppression"
        for filename, expected in (("suppression_buggy.cs", True),
                                   ("suppression_buggy_nomarkers.cs", False)):
            source = fixtures / filename
            lines = source.read_text(encoding="utf-8").splitlines()
            anchor = next(n for n, line in enumerate(lines, 1) if "using (var digest = MD5.Create())" in line)
            for rule in ("cs.pattern.weak-crypto", "cs-md5-create"):
                self.assertEqual(SourceSuppressions("csharp").is_suppressed(source, anchor, rule), expected,
                                 f"{filename}:{anchor} {rule}")

    def test_rust_lifetimes_characters_and_raw_strings_preserve_comment_boundaries(self) -> None:
        for literal in (
            "'x'", r"'\n'", r"'\''", r"'\x2f'", r"'\u{2f}'", "'λ'", "b'x'",
            'r"/* // ubs:ignore */"', 'r#"inner " // ubs:ignore"#',
            'br##"inner "# /* ubs:ignore */"##',
            'r###"line one\n"## // ubs:ignore\nline three"###',
        ):
            prefix = "fn parse(raw: &'static str) {\n    let note = " + literal + ";\n"
            source = prefix + "    call(); // ubs:ignore[public.rule]\n    next();\n}\n"
            anchor = prefix.count("\n") + 1
            with self.subTest(literal=literal):
                for strip_strings in (False, True):
                    masked = strip_comments_and_strings(source, lang="rust", strip_strings=strip_strings)
                    self.assertEqual(len(masked), len(source))
                    self.assertEqual([n for n, ch in enumerate(masked) if ch == "\n"],
                                     [n for n, ch in enumerate(source) if ch == "\n"])
                    self.assertIn("&'static str", masked)
                    if not strip_strings:
                        self.assertIn(literal, masked)
                index = build_index(source, lang="rust")
                self.assertEqual([(marker.line, marker.rules) for marker in index.markers],
                                 [(anchor, frozenset({"public.rule"}))])
                self.assertTrue(index.is_suppressed(anchor, "public.rule"))
                self.assertFalse(index.is_suppressed(anchor, "other.rule"))
                self.assertFalse(index.is_suppressed(anchor + 1, "public.rule"))
        source = "fn borrow<'a>(raw: &'a str) {\n    'work: loop {\n        call(); // ubs:ignore\n        break 'work;\n    }\n}\n"
        self.assertEqual([marker.line for marker in parse_markers(source, lang="rust")], [3])
        self.assertFalse(build_index(source, lang="rust").is_suppressed(4, "public.rule"))

    def test_comment_aliases_precede_native_pattern_thresholds(self) -> None:
        cpp_rule = "cpp.numeric.float-equality"
        java_rule = "java.equality.string-eq"
        cpp_pattern = next(pattern for pattern in cpp_scan.load_patterns() if pattern.rule_id == cpp_rule)
        java_pattern = next(pattern for pattern in java_scan.load_patterns() if pattern.rule_id == java_rule)
        with tempfile.TemporaryDirectory(prefix="ubs_alias_thresholds_") as temp:
            root = Path(temp)
            for alias in ("nolint", "noqa", "ubs: disable"):
                with self.subTest(alias=alias):
                    cpp = root / "source.cpp"
                    # Three unmarked hits are below the real >3 threshold.
                    # A filtered fourth hit must not turn them into findings.
                    cpp.write_text("bool same = value == 1.0;\n" * 3
                                   + f"bool same = value == 1.0; // {alias}\n", encoding="utf-8")
                    sink = StringIO()
                    counts = cpp_scan.scan_patterns([cpp_pattern], [cpp], sink, set())
                    self.assertEqual(counts, {"critical": 0, "warning": 0, "info": 0})
                    self.assertEqual(sink.getvalue(), "")
                    cpp.write_text("bool same = value == 1.0;\n" * 3
                                   + f'const char *note = "{alias}"; bool same = value == 1.0;\n',
                                   encoding="utf-8")
                    sink = StringIO()
                    counts = cpp_scan.scan_patterns([cpp_pattern], [cpp], sink, set())
                    self.assertEqual(counts, {"critical": 0, "warning": 0, "info": 4})
                    try:
                        records = [json.loads(line) for line in sink.getvalue().splitlines()]
                    except ValueError as exc:
                        self.fail(f"Invalid native C++ findings: {exc}\n{sink.getvalue()}")
                    self.assertEqual([(record["rule"], record["line"]) for record in records],
                                     [(cpp_rule, line) for line in range(1, 5)])

                    java = root / "Source.java"
                    java.write_text(
                        f'boolean first = value == "first"; // {alias}\n'
                        'boolean second = value == "second";\n'
                        f'String note = "{alias}"; boolean third = value == "third";\n',
                        encoding="utf-8",
                    )
                    sink = StringIO()
                    counts = java_scan.scan_patterns([java_pattern], [java], sink, set())
                    self.assertEqual(counts, {"critical": 0, "warning": 2, "info": 0})
                    try:
                        records = [json.loads(line) for line in sink.getvalue().splitlines()]
                    except ValueError as exc:
                        self.fail(f"Invalid native Java findings: {exc}\n{sink.getvalue()}")
                    self.assertEqual([(record["rule"], record["line"]) for record in records],
                                     [(java_rule, 2), (java_rule, 3)])

    def test_late_statement_marker_never_suppresses_block_siblings(self) -> None:
        source = (
            "void check() {\n"
            "    before();\n"
            "    call(\n"
            "        first,\n"
            "        second, // ubs:ignore[public.rule]\n"
            "        third\n"
            "    );\n"
            "    after();\n"
            "}\n"
        )
        for language in ("cpp", "rust", "java", "swift", "csharp"):
            with self.subTest(language=language):
                index = build_index(source, lang=language)
                self.assertEqual(
                    [line for line in range(1, 10) if index.is_suppressed(line, "public.rule")],
                    [3, 4, 5, 6, 7],
                )
                self.assertFalse(any(index.is_suppressed(line, "other.rule") for line in range(1, 10)))

    def test_only_standalone_marker_can_own_the_following_statement(self) -> None:
        source = (
            "first(); // ubs:ignore[public.rule]\n"
            "second();\n"
            "// ubs:ignore[public.rule]\n"
            "third();\n"
            'const char *note = "ubs:ignore"; fourth();\n'
        )
        for language in ("cpp", "rust", "java", "swift", "csharp"):
            with self.subTest(language=language):
                index = build_index(source, lang=language)
                self.assertTrue(index.is_suppressed(1, "public.rule"))
                self.assertFalse(index.is_suppressed(2, "public.rule"))
                self.assertTrue(index.is_suppressed(4, "public.rule"))
                self.assertFalse(index.is_suppressed(5, "public.rule"))
        python_index = build_index("'a string statement'  # ubs:ignore\nnext_call()\n", lang="python")
        self.assertFalse(python_index.is_suppressed(2, "public.rule"))

    def test_source_identity_and_fresh_invocation_keep_aggregate_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_source_scopes_") as temp:
            root = Path(temp)
            marked = root / "marked" / "same.java"
            unmarked = root / "unmarked" / "same.java"
            for path in (marked, unmarked):
                path.parent.mkdir()
            marked.write_text("call(); // ubs:ignore[public.rule]\n", encoding="utf-8")
            unmarked.write_text("call();\n", encoding="utf-8")
            records = [
                {"rule": "public.rule", "path": str(marked), "line": 1},
                {"rule": "other.rule", "path": str(marked), "line": 1},
                {"rule": "public.rule", "path": str(unmarked), "line": 1},
                {"rule": "public.rule", "path": "", "line": 0, "count": 0, "scope": "project"},
                {"rule": "public.rule", "path": "", "line": 0, "count": 2, "scope": "project_aggregate"},
                {"rule": "public.rule", "path": str(root / "unreadable.java"), "line": 1},
            ]
            self.assertEqual(SourceSuppressions("java").filter(records), records[1:])
            marked.write_text("call();\n", encoding="utf-8")
            self.assertEqual(SourceSuppressions("java").filter(records), records)


    def test_literal_comment_delimiter_cannot_turn_trailing_marker_into_standalone(self) -> None:
        for delimiter in ("/*", "//", "*/"):
            source = (
                f'const char *note = "{delimiter}";\n'
                "first(); // ubs:ignore[public.rule]\n"
                "second();\n"
            )
            for language in ("cpp", "rust", "java", "swift", "csharp"):
                with self.subTest(delimiter=delimiter, language=language):
                    index = build_index(source, lang=language)
                    self.assertEqual(len(index.markers), 1)
                    self.assertFalse(index.markers[0].standalone)
                    self.assertTrue(index.is_suppressed(2, "public.rule"))
                    self.assertFalse(index.is_suppressed(3, "public.rule"))
                    self.assertFalse(index.is_suppressed(2, "other.rule"))

    def test_comment_mask_preserves_regular_escaped_and_triple_strings(self) -> None:
        for language, literal, comment in (
            ("java", '"/* // */"', "// outside comment"),
            ("java", r'"escaped \" /* // */"', "// outside comment"),
            ("python", "'''/* # inside\nstring */'''", "# outside comment"),
        ):
            with self.subTest(language=language, literal=literal):
                source = "value = " + literal + "; " + comment + "\nnext_call();\n"
                expected = "value = " + literal + "; " + " " * len(comment) + "\nnext_call();\n"
                actual = strip_comments_and_strings(
                    source, lang=language, strip_strings=False, strip_comments=True,
                )
                self.assertEqual(actual, expected)
                self.assertEqual(len(actual), len(source))


class MarkerScopePredicateTests(unittest.TestCase):
    def test_exact_comma_list_and_multiple_markers(self) -> None:
        text = "// ubs:ignore[rust.panic.assert-macros, rust.security.request-url]"
        self.assertTrue(has_suppression_marker(text, "rust.panic.assert-macros"))
        self.assertTrue(has_suppression_marker(text, "rust.security.request-url"))
        for rule in (None, "rust.panic.assert", "rust.security.request", "rust.other"):
            with self.subTest(rule=rule):
                self.assertFalse(has_suppression_marker(text, rule))
        self.assertTrue(has_suppression_marker(text + " // ubs:ignore[rust.other]", "rust.other"))
        self.assertTrue(has_suppression_marker(text + " // ubs:ignore"))

    def test_bare_and_empty_scope_preserve_parser_behavior(self) -> None:
        for marker in ("ubs:ignore", "ubs:ignore[]", "ubs:ignore[ , ]"):
            for rule in (None, "rust.security.request-url"):
                with self.subTest(marker=marker, rule=rule):
                    self.assertTrue(has_suppression_marker(marker, rule))
            self.assertIsNone(parse_markers("// " + marker, lang="c_like")[0].rules)
        self.assertFalse(has_suppression_marker("ordinary source", "rust.other"))

    def test_malformed_scope_never_falls_back_to_bare(self) -> None:
        for marker in (
            "ubs:ignore[rust.panic.assert-macros*]",
            "ubs:ignore[rust.panic.assert-macros",
            "ubs:ignore[rust/panic/assert-macros]",
            "ubs:ignore[!!!]",
            "ubs:ignore[",
        ):
            with self.subTest(marker=marker):
                self.assertEqual(parse_markers("// " + marker, lang="c_like"), [])
                for rule in (None, "rust.panic.assert-macros", "rust.security.request-url"):
                    self.assertFalse(has_suppression_marker(marker, rule))


class RustDetectorSuppressionTests(unittest.TestCase):
    """Exercise real source parsing and taint flow at the existing anchors."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="ubs-rust-marker-")
        self.addCleanup(scratch.cleanup)
        self.source = Path(scratch.name) / "source.rs"

    def lines(self, detector, source: str, *args) -> list[int]:
        self.source.write_text(source, encoding="utf-8")
        return [hit[1] for hit in detector.find([self.source], *args)]

    def test_scoped_sources_preserve_downstream_taint(self) -> None:
        cases = (
            (request_url, 'let value = params.get("url");', 'client.get(value);'),
            (request_regex, 'let value = params.get("pattern");', 'Regex::new(value);'),
            (open_redirect, 'let value = params.get("next");', 'Redirect::to(value);'),
            (response_header, 'let value = params.get("name");',
             'Response::builder().header("X-Name", value);'),
            (host_header_url, 'let value = req.host();', 'format!("https://{value}/reset");'),
            (sql_injection, 'let value = req.query_string();',
             'sqlx::query(&format!("SELECT id FROM users WHERE name = {}", value));'),
            (security_randomness, 'let generator = rand::rngs::SmallRng::from_entropy();',
             'let token = generator.gen::<u64>();'),
        )
        for detector, source, sink in cases:
            def fixture(source_marker="", sink_marker=""):
                # The blank line keeps source annotations outside the existing
                # previous-line anchor of the sink at line 4.
                return f"fn exercise() {{\n    {source}{source_marker}\n\n    {sink}{sink_marker}\n}}\n"

            with self.subTest(detector=detector.__name__, marker="baseline"):
                self.assertEqual(self.lines(detector, fixture()), [4])
            for rule in (detector.RULE_ID, "rust.panic.assert-macros"):
                with self.subTest(detector=detector.__name__, source_rule=rule):
                    self.assertEqual(self.lines(detector, fixture(f" // ubs:ignore[{rule}]")), [4])
            with self.subTest(detector=detector.__name__, marker="unrelated sink"):
                self.assertEqual(self.lines(detector, fixture(sink_marker=" // ubs:ignore[rust.other]")), [4])
            with self.subTest(detector=detector.__name__, marker="bare source"):
                self.assertEqual(self.lines(detector, fixture(source_marker=" // ubs:ignore")), [])
            for marker in (f" // ubs:ignore[{detector.RULE_ID}]", " // ubs:ignore"):
                with self.subTest(detector=detector.__name__, sink_marker=marker):
                    self.assertEqual(self.lines(detector, fixture(sink_marker=marker)), [])

    def test_fixed_rule_candidates_keep_unrelated_scopes(self) -> None:
        cases = (
            (hardcoded_secrets, 'const API_SECRET: &str = "live-secret-123456";'),
            (jwt_verification, 'fn parse() { jsonwebtoken::dangerous::insecure_decode::<Claims>(token); }'),
            (cors_credential, 'fn policy() { CorsLayer::new().allow_origin(Any).allow_credentials(true); }'),
        )
        for detector, code in cases:
            with self.subTest(detector=detector.__name__, marker="baseline"):
                self.assertEqual(self.lines(detector, code + "\n"), [1])
            for marker, expected in (
                (" // ubs:ignore[rust.other]", [1]),
                (f" // ubs:ignore[{detector.RULE_ID}]", []),
                (" // ubs:ignore", []),
            ):
                with self.subTest(detector=detector.__name__, marker=marker):
                    self.assertEqual(self.lines(detector, code + marker + "\n"), expected)
                    self.assertEqual(self.lines(detector, marker + "\n" + code + "\n"),
                                     [2] if expected else [])

    def test_constant_time_public_scope_and_alias_taint(self) -> None:
        def fixture(source_marker="", sink_marker=""):
            return (
                "fn verify(provided: &str) {\n"
                f"    let alias = expected_signature;{source_marker}\n\n"
                f"    alias == provided;{sink_marker}\n"
                "}\n"
            )

        self.assertEqual([line for line, _ in ctcompare_rust.scan_file(fixture())], [4])
        public = "rust.security.constant-time-compare"
        for rule in (public, "rust.panic.assert-macros"):
            with self.subTest(source_rule=rule):
                self.assertEqual([line for line, _ in ctcompare_rust.scan_file(
                    fixture(source_marker=f" // ubs:ignore[{rule}]"),
                )], [4])
        for marker, expected in (
            (" // ubs:ignore[rust.ctcompare.secret_compare]", [4]),
            (" // ubs:ignore[rust.panic.assert-macros]", [4]),
            (f" // ubs:ignore[{public}]", []),
            (" // ubs:ignore", []),
        ):
            with self.subTest(sink_marker=marker):
                self.assertEqual([line for line, _ in ctcompare_rust.scan_file(
                    fixture(sink_marker=marker),
                )], expected)

    def test_loop_modes_preserve_second_finding_on_annotated_line(self) -> None:
        code = 'fn exercise() {\n    for item in items {\n        let copy = item.clone(); let text = format!("{item}");'
        for marker, clone_lines, allocation_lines in (
            ("", [3], [3]),
            (" // ubs:ignore[rust.collections.clone-in-loop]", [], [3]),
            (" // ubs:ignore[rust.perf.string-alloc-in-loop]", [3], []),
            (" // ubs:ignore", [], []),
        ):
            source = code + marker + "\n    }\n}\n"
            with self.subTest(marker=marker):
                self.assertEqual(self.lines(loop_context, source, "clone"), clone_lines)
                self.assertEqual(self.lines(loop_context, source, "string_alloc"), allocation_lines)

    def test_tls_public_scope_keeps_existing_comment_anchor(self) -> None:
        # TLS historically examines comment-stripped lines; block comments
        # survive that anchor while // comments do not. Preserve that boundary.
        for marker, expected in (
            ("", [3]),
            (" /* ubs:ignore[rust.security.tls-indirect] */", [3]),
            (" /* ubs:ignore[rust.security.tls-verification] */", []),
            (" /* ubs:ignore */", []),
            (" // ubs:ignore[rust.security.tls-verification]", [3]),
        ):
            source = (
                "let disable = true; /* ubs:ignore[rust.other] */\n\n"
                f"client.danger_accept_invalid_certs(disable);{marker}\n"
            )
            with self.subTest(marker=marker):
                self.assertEqual(self.lines(tls_indirect, source), expected)


class RustRcRefCellSourceTests(unittest.TestCase):
    def test_type_documentation_and_literals_do_not_hide_real_code(self) -> None:
        source = '''//! Rc<RefCell<State>> is discussed here.
/* Rc<RefCell<State>>
   still documentation: Rc<RefCell<State>> */
fn production() {
    let note = "Rc<RefCell<State>>";
    let raw = r##"Rc<RefCell<State>>
        Rc<RefCell<State>>"##;
    let escaped = "quoted \\\" Rc<RefCell<State>>";
    let live: Rc<RefCell<State>> = make_state();
    let note = "Rc<RefCell<State>>"; let second: Rc<RefCell<State>> = make_state();
    /* Rc<RefCell<State>> */ let third: Rc<RefCell<State>> = make_state();
}
'''
        with tempfile.TemporaryDirectory(prefix="ubs-rust-refcell-") as temp:
            root = Path(temp)
            path = root / "source.rs"
            path.write_text(source, encoding="utf-8")
            scan = rust_scan.Scan([path], root, False, set(), 3)
            renderer = rust_scan.Renderer(scan)
            rust_scan.cat_3(scan, renderer)
            records = [record for record in scan.records if record["rule"] == "rust.async.rc-refcell"]
            self.assertEqual([record["line"] for record in records], [9, 10, 11])
            self.assertTrue(all(record["severity"] == "warning" for record in records))
            self.assertEqual(scan.counters["warning"], 3)
            self.assertEqual([record["text"] for record in records], source.splitlines()[8:11])
            replay = rust_scan.Scan([path], root, False, set(), 3)
            rust_scan.replay_findings(replay, rust_scan.Renderer(replay), scan.records)
            self.assertEqual(replay.records, scan.records)
            self.assertEqual(replay.counters, scan.counters)

    def test_type_use_respects_only_its_public_suppression_scope(self) -> None:
        rule = "rust.async.rc-refcell"
        for prefix, suffix, expected in (
            ("", "", [3, 4]),
            ("", " // ubs:ignore[rust.panic.assert-macros]", [3, 4]),
            ("", f" // ubs:ignore[{rule}]", [4]),
            (f"// ubs:ignore[{rule}]", "", [4]),
            ("// ubs:ignore[rust.panic.assert-macros]", "", [3, 4]),
            ("", ' let note = "ubs:ignore";', [3, 4]),
            ("", f' let note = r#"ubs:ignore[{rule}]"#;', [3, 4]),
        ):
            with self.subTest(prefix=prefix, suffix=suffix):
                with tempfile.TemporaryDirectory(prefix="ubs-rust-refcell-scope-") as temp:
                    root = Path(temp)
                    path = root / "source.rs"
                    path.write_text(
                        "fn production() {\n    " + prefix + "\n"
                        "    let first: Rc<RefCell<State>> = make_state();" + suffix + "\n"
                        "    let second: Rc<RefCell<State>> = make_state();\n}\n",
                        encoding="utf-8",
                    )
                    scan = rust_scan.Scan([path], root, False, set(), 3)
                    rust_scan.cat_3(scan, rust_scan.Renderer(scan))
                    records = [record for record in scan.records if record["rule"] == rule]
                    self.assertEqual([record["line"] for record in records], expected)
                    self.assertEqual(scan.counters["warning"], len(expected))


class RustNativeSuppressionTests(unittest.TestCase):
    """Real ast-grep, line fallback, and cache replay must agree on rule scope."""

    def test_lifetime_raw_literal_and_comment_alias_sites_cold_warm_and_subset(self) -> None:
        ownership = "rust.ownership.unwrap-expect"
        parsing = "rust.parsing.parse-unwrap"
        header = "fn parse(raw: &'static str) {"
        # name, declaration, setup line, hazard-line prefix, trailing comment,
        # public rules retained on the first of two adjacent real parse calls.
        variants = [
            ("baseline", header, "", "", "", (ownership, parsing)),
            ("selective", header, "", "", f"ubs:ignore[{parsing}]", (ownership,)),
            ("named_lifetime", "fn parse<'a>(raw: &'a str) {", "", "",
             f"ubs:ignore[{parsing}]", (ownership,)),
            ("unknown", header, "", "", "ubs:ignore[rust.unknown]", (ownership, parsing)),
            ("malformed", header, "", "", f"ubs:ignore[{parsing}*]", (ownership, parsing)),
            ("characters", header, r"let chars = ('x', '\n', '\'', '\x2f', '\u{2f}');", "",
             f"ubs:ignore[{parsing}]", (ownership,)),
            ("raw_scope_literal", header, "", f'let note = r#"inner " // ubs:ignore[{parsing}]"#; ',
             "", (ownership, parsing)),
            ("raw_bare_literal", header, "", 'let note = br##"inner "# /* ubs:ignore */"##; ',
             "", (ownership, parsing)),
            ("raw_then_scope", header, "", 'let note = r#"inner " // ubs:ignore"#; ',
             f"ubs:ignore[{parsing}]", (ownership,)),
        ]
        for name, alias in (("nolint", "nolint"), ("noqa", "NOQA"), ("disable", "ubs: disable")):
            variants.extend([
                (f"{name}_literal", header, "", f'let note = "{alias}"; ', "", (ownership, parsing)),
                (f"{name}_comment", header, "", "", alias, ()),
                (f"{name}_above", header, f"// {alias}", "", "", ()),
            ])

        with tempfile.TemporaryDirectory(prefix="ubs_rust_lexical_markers_") as temp:
            root = Path(temp)
            rules = root / "rules"
            rust_rules.generate(rules)
            paths = []
            expected = {}
            for name, declaration, setup, prefix, marker, first_rules in variants:
                path = root / f"{name}.rs"
                first = "    " + prefix + "raw.parse::<i32>().unwrap();"
                path.write_text(
                    declaration + "\n    " + setup + "\n" + first
                    + (f" // {marker}" if marker else "") + "\n"
                    "    raw.parse::<i32>().unwrap();\n}\n",
                    encoding="utf-8",
                )
                paths.append(path)
                # Ownership unwrap retains the legacy `ast-grep run` whole-
                # line anchor (column1); the generated parsing rule uses the
                # exact AST expression column. Neither rule may borrow the
                # other's location contract during cold or cached rendering.
                expected[path] = sorted(
                    [(rule, 3, 1 if rule == ownership else first.index("raw.parse") + 1)
                     for rule in first_rules]
                    + [(ownership, 4, 1), (parsing, 4, 5)]
                )
            inputs = root / "inputs"
            sink = root / "findings.ndjson"
            output = root / "summary.json"
            report = root / "report.txt"
            env = dict(
                os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / "cache"),
                UBS_CACHE_FILE=str(root / "cache_stats.json"),
                UBS_PREFILTER_FILE=str(root / "prefilter.json"), UBS_PROFILE="1",
            )
            command = [
                sys.executable, "-m", "ubs_core.rust_scan", "--files-from", str(inputs),
                "--sink", str(sink), "--json-out", str(output), "--text-out", str(report),
                "--project-dir", str(root), "--ast-rule-dir", str(rules),
                "--skip", ",".join(str(n) for n in range(1, 25) if n not in (1, 23)),
                "--skip-type-narrowing", "--fail-on-warning",
            ]

            def scan(selected, hits, misses):
                inputs.write_bytes(b"\0".join(os.fsencode(path) for path in selected) + b"\0")
                proc = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed scanner module and fixture-only argv; bounded real subprocess
                context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                self.assertEqual(proc.returncode, 1, context)
                try:
                    doc = json.loads(output.read_text(encoding="utf-8"))
                    records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                except ValueError as exc:
                    self.fail(f"Invalid native Rust report: {exc}\n{context}")
                self.assertEqual(doc["status"], "ok", context)
                self.assertEqual(doc["files"], len(selected), context)
                self.assertEqual(doc["findings"], records, context)
                self.assertEqual((doc["profile"]["cache_hits"], doc["profile"]["cache_misses"]),
                                 (hits, misses), context)
                self.assertEqual((doc["critical"], doc["warning"], doc["info"]),
                                 (0, sum(len(expected[path]) for path in selected), 0), context)
                self.assertEqual(len(records), sum(len(expected[path]) for path in selected), context)
                for path in selected:
                    own = [record for record in records if (root / record["path"]).resolve() == path]
                    self.assertEqual(sorted((record["rule"], record["line"], record["col"]) for record in own),
                                     expected[path], f"{path.name}\n{context}")
                    self.assertTrue(all(record["severity"] == "warning" for record in own), context)
                if len(selected) == 1:
                    # Two sites per rule fit each native preview. Require the
                    # text's trusted rule metadata to represent exactly the
                    # same retained source identities as the real JSON/sink.
                    text = re.sub(r"\x1b\[[0-9;]*m", "", report.read_text(encoding="utf-8"))
                    samples = re.findall(r"^\s+(.+):(\d+):(\d+) \[rule:([^\]]+)\]", text, re.MULTILINE)
                    self.assertEqual(sorted((rule, int(line), int(col)) for _, line, col, rule in samples),
                                     expected[selected[0]], text + "\n" + context)
                    self.assertTrue(all((root / path).resolve() == selected[0] for path, _, _, _ in samples),
                                    text + "\n" + context)
                return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

            cold = scan(paths, 0, len(paths))
            self.assertEqual(scan(paths, len(paths), 0), cold)
            for path in paths:
                if path.stem.endswith(("_literal", "_comment", "_above")) or path.stem == "selective":
                    with self.subTest(subset=path.name):
                        own_cold = [record for record in cold if (root / record["path"]).resolve() == path]
                        self.assertEqual(scan([path], 1, 0), own_cold)

    def test_public_scopes_locations_and_counts_cold_and_warm(self) -> None:
        assertion = "rust.panic.assert-macros"
        security = "rust.security.constant-time-compare"
        variants = (
            ("baseline", "", True, True),
            ("unknown", "ubs:ignore[rust.unknown]", True, True),
            ("malformed", "ubs:ignore[rust.panic.assert-macros*]", True, True),
            ("unclosed", "ubs:ignore[rust.panic.assert-macros", True, True),
            ("internal", "ubs:ignore[rust.ast.assert,rust.ctcompare.secret_compare]", True, True),
            ("assertion", f"ubs:ignore[{assertion}]", False, True),
            ("security", f"ubs:ignore[{security}]", True, False),
            ("both", f"ubs:ignore[{assertion}, {security}]", False, False),
            ("bare", "ubs:ignore", False, False),
            ("empty", "ubs:ignore[]", False, False),
        )
        with tempfile.TemporaryDirectory(prefix="ubs-native-markers-") as temp:
            root = Path(temp)
            rules = root / "rules"
            rust_rules.generate(rules)
            paths = []
            for name, marker, _, _ in variants:
                path = root / f"{name}.rs"
                path.write_text(
                    "fn verify(provided_signature: &str, expected_signature: &str) {\n"
                    "    let matches = provided_signature == expected_signature; "
                    "assert!(matches); assert_eq!(matches, true);"
                    + (f" // {marker}" if marker else "") + "\n"
                    "    assert_ne!(matches, false);\n"
                    "}\n",
                    encoding="utf-8",
                )
                paths.append(path)
            inputs = root / "inputs"
            inputs.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
            for ast in (True, False):
                sink = root / f"findings-{ast}.ndjson"
                output = root / f"summary-{ast}.json"
                command = [
                    sys.executable, "-m", "ubs_core.rust_scan", "--files-from", str(inputs),
                    "--sink", str(sink), "--json-out", str(output), "--project-dir", str(root),
                    "--skip", ",".join(str(n) for n in range(1, 25) if n not in (8, 21)),
                    "--skip-type-narrowing", "--quiet", "--fail-on-warning",
                ]
                if ast:
                    command.extend(["--ast-rule-dir", str(rules)])
                env = dict(
                    os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                    UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / f"cache-{ast}"),
                    UBS_CACHE_FILE=str(root / f"stats-{ast}.json"),
                    UBS_PREFILTER_FILE=str(root / f"prefilter-{ast}.json"), UBS_PROFILE="1",
                )
                cold_records = None
                for warm in (False, True):
                    with self.subTest(ast=ast, warm=warm):
                        # Fixed local scanner argv and generated fixture paths;
                        # inherited environment supplies the real ast-grep binary.
                        proc = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed scanner module and fixture-only argv; bounded real subprocess
                        context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                        self.assertEqual(proc.returncode, 1, context)
                        self.assertTrue(output.is_file(), context)
                        self.assertTrue(sink.is_file(), context)
                        try:
                            doc = json.loads(output.read_text(encoding="utf-8"))
                            records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                        except ValueError as exc:
                            self.fail(f"Invalid native Rust report: {exc}\n{context}")
                        self.assertEqual(doc["status"], "ok", context)
                        self.assertEqual(doc["files"], len(paths), context)
                        self.assertEqual(doc["findings"], records, context)
                        self.assertEqual(doc["profile"]["cache_hits"], len(paths) if warm else 0, context)
                        self.assertEqual(doc["profile"]["cache_misses"], 0 if warm else len(paths), context)
                        expected_warnings = 0
                        expected_critical = 0
                        for path, (_, _, keep_assertion, keep_security) in zip(paths, variants):
                            # Native producers may retain a path relative to
                            # this subprocess's cwd; compare actual source files.
                            own = [record for record in records
                                   if (root / Path(record["path"])).resolve() == path.resolve()]
                            assertion_hits = [hit for hit in own if hit["rule"] == assertion]
                            expected_lines = ([2, 2] if ast else [2]) if keep_assertion else []
                            # The adjacent unannotated line must keep its own
                            # finding even when line 2 has a matching/bare marker.
                            expected_lines.append(3)
                            self.assertEqual(sorted(hit["line"] for hit in assertion_hits), expected_lines,
                                             f"{path.name}\n{context}")
                            if ast and keep_assertion:
                                self.assertEqual(len({hit["col"] for hit in assertion_hits if hit["line"] == 2}), 2,
                                                 f"both same-rule AST sites must survive: {path.name}\n{context}")
                            security_hits = [hit for hit in own if hit["rule"] == security]
                            self.assertEqual([hit["line"] for hit in security_hits], [2] if keep_security else [],
                                             f"{path.name}\n{context}")
                            expected_warnings += len(expected_lines)
                            expected_critical += int(keep_security)
                        self.assertEqual(doc["warning"], expected_warnings, context)
                        self.assertEqual(doc["critical"], expected_critical, context)
                        # Replay groups findings by file, while cold discovery
                        # groups by category. Preserve every field and duplicate
                        # when comparing the actual findings across those orders.
                        ordered_records = sorted(records, key=lambda record: json.dumps(record, sort_keys=True))
                        if warm:
                            self.assertEqual(ordered_records, cold_records, context)
                        else:
                            cold_records = ordered_records


class CSharpRenderedSuppressionTests(unittest.TestCase):
    def test_ast_samples_resolve_and_keep_unsuppressed_peer(self) -> None:
        fixtures = REPO_ROOT / "test-suite" / "csharp" / "suppression"
        marked = fixtures / "suppression_buggy.cs"
        unmarked = fixtures / "suppression_buggy_nomarkers.cs"
        records = []
        for source, anchor in (
            (marked, '        Process.Start("cmd.exe", "/C " + userInput);'),
            (marked, '        Process.Start("cmd.exe", "/C " +'),
            (unmarked, '        Process.Start("cmd.exe", "/C " + userInput);'),
        ):
            line = source.read_text(encoding="utf-8").splitlines().index(anchor) + 1
            records.append({
                "rule": "cs-process-start",
                "path": source.name,
                "line": line,
                "severity": "warning",
                "message": "Process.Start invocation requires strict input validation",
            })

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="csharp-suppression-", dir=artifacts) as temp:
            sink = Path(temp) / "findings.ndjson"
            output = Path(temp) / "report.txt"
            sink.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            for project in (marked, fixtures):
                with self.subTest(project=project):
                    render_text(SimpleNamespace(
                        sink=str(sink), text_out=str(output), project_dir=str(project),
                        project="", ci=True, detail_limit=5, skip="",
                    ), ast_ran=True, patterns=[])
                    samples = [
                        match for line in output.read_text(encoding="utf-8").splitlines()
                        if (match := re.match(r"^\s+(.+):(\d+) \[rule:([^\]]+)\]", line))
                    ]
                    self.assertEqual(len(samples), 3, "each hit must be suppressible independently")
                    suppressed = []
                    for match in samples:
                        source = Path(match.group(1))
                        self.assertTrue(source.is_absolute())
                        self.assertTrue(source.is_file(), "suppression must resolve the actual source")
                        self.assertEqual(match.group(3), "cs-process-start")
                        index = build_index(source.read_text(encoding="utf-8"), lang="csharp")
                        suppressed.append(index.is_suppressed(
                            int(match.group(2)), "cs-process-start",
                        ))
                    self.assertEqual(suppressed, [True, True, False])


class TextRuleProvenanceTests(unittest.TestCase):
    def test_cpp_and_java_locations_carry_record_id_before_message(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_text_scope_") as temp:
            root = Path(temp)
            for scanner, suffix, rule in (
                (cpp_scan, "cpp", "cpp.memory-raii.manual-delete"),
                (java_scan, "java", "java.resource.statement-no-close"),
            ):
                with self.subTest(rule=rule):
                    source = root / f"source.{suffix}"
                    source.write_text("call();\n", encoding="utf-8")
                    sink = root / "findings.ndjson"
                    report = root / "report.txt"
                    message = "Retain message [rule:unrelated.rule] exactly"
                    sink.write_text(json.dumps({
                        "rule": rule, "path": str(source), "line": 1,
                        "severity": "warning", "message": message,
                    }) + "\n", encoding="utf-8")
                    args = SimpleNamespace(sink=str(sink), text_out=str(report),
                                           project=str(root), project_dir=str(root), skip="")
                    counters = {"critical": 0, "warning": 1, "info": 0}
                    if scanner is java_scan:
                        scanner._render_text(args, [source], counters, ast_ran=True)
                    else:
                        scanner._render_text(args, [source], counters)
                    self.assertIn(f"    {source}:1 [rule:{rule}] {message}\n", report.read_text(encoding="utf-8"))

    def test_rust_native_wildcard_samples_keep_rule_through_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_rust_text_scope_") as temp:
            root = Path(temp)
            source = root / "source.rs"
            source.write_text("use crate::*; // ubs:ignore[rust.other]\n", encoding="utf-8")
            scan = rust_scan.Scan([source], root, False, set(), 3)
            renderer = rust_scan.Renderer(scan)
            rust_scan.cat_10(scan, renderer)
            expected = f"{source}:1:1 [rule:rust.modules.wildcard-imports]"
            self.assertIn(expected, renderer.text())
            self.assertEqual(len(scan.records), 1)
            replay = rust_scan.Scan([source], root, False, set(), 3)
            replay_renderer = rust_scan.Renderer(replay)
            rust_scan.replay_findings(replay, replay_renderer, scan.records)
            self.assertIn(expected, replay_renderer.text())
            self.assertEqual(replay.counters, scan.counters)
            self.assertEqual(replay.records, scan.records)

    def test_swift_embedded_and_narrowing_samples_keep_individual_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_swift_text_scope_") as temp:
            source = Path(temp) / "source.swift"
            source.write_text("first()\nsecond()\n", encoding="utf-8")
            rule = "swift.narrowing.guard_let_no_exit"
            records = [
                {"rule": rule, "path": str(source), "line": line, "col": 3,
                 "count": 1, "severity": "warning", "message": f"detail {line}"}
                for line in (1, 2)
            ]
            args = SimpleNamespace(max_detailed=10, detail_limit=3, ast_available=True,
                                   project="", project_dir="")
            renderer = swift_scan._Renderer(args, records)
            renderer.render_spec(next(spec for spec in swift_scan.CHECK_SPECS if spec.rule_id == "swift.narrowing"))
            for record in records:
                self.assertIn(f" {source}:{record['line']}:3 [rule:{rule}] → detail {record['line']}\n", renderer.text())
            self.assertNotIn("Examples: " + str(source), renderer.text())
            embedded = swift_scan._Renderer(args, [])
            embedded.embedded_samples([
                {"rule": "swift.force-try", "samples": [{"path": str(source), "line": 1}]},
                {"rule": "ubs.correlation.unresumed", "samples": [{"path": str(source), "line": 2}]},
            ])
            self.assertIn(f" {source}:1 [rule:swift.force-try]\n", embedded.text())
            self.assertIn(f" {source}:2 [rule:ubs.correlation.unresumed]\n", embedded.text())


class SwiftAggregateSuppressionTests(unittest.TestCase):
    def test_real_derived_async_counts_use_public_scope_before_aggregation(self) -> None:
        from ubs_core.swift_patterns.foundations import _unawaited_async

        rule = "swift.concurrency.unawaited-async"
        variants = (
            ("", "", 2),
            (" // ubs:ignore[unknown.rule]", "", 2),
            (" // ubs:ignore[swift.force-try]", "", 2),
            (f' let note = "ubs:ignore ubs:ignore[{rule}]";', "", 2),
            (f" // ubs:ignore[{rule}]", "", 1),
            (" // ubs:ignore", "", 1),
            ("", f"// ubs:ignore[{rule}]\n", 1),
        )
        with tempfile.TemporaryDirectory(prefix="ubs_swift_aggregate_scope_") as temp:
            root = Path(temp)
            source = root / "source.swift"
            for suffix, prefix, expected in variants:
                with self.subTest(suffix=suffix, prefix=prefix):
                    source.write_text(prefix + "func first() async { }" + suffix + "\n"
                                      "func second() async { }\n", encoding="utf-8")
                    ctx = swift_scan.ScanContext(files=[source], project_dir=root)
                    records = list(_unawaited_async(ctx))
                    self.assertEqual(len(records), 1)
                    self.assertEqual(records[0]["rule"], rule)
                    self.assertEqual(records[0]["count"], expected)
                    self.assertEqual(records[0]["scope"], "project_aggregate")
                    self.assertEqual((records[0]["path"], records[0]["line"], records[0]["severity"]),
                                     ("", 0, "info"))
            # The same exact scope applies to the balancing await side;
            # an unrelated marker must not inflate the difference.
            for scope, expected in (("unknown.rule", 0), (rule, 1)):
                with self.subTest(await_scope=scope):
                    source.write_text("func first() async { }\n"
                                      f"await first() // ubs:ignore[{scope}]\n", encoding="utf-8")
                    records = list(_unawaited_async(swift_scan.ScanContext(files=[source], project_dir=root)))
                    self.assertEqual(sum(record["count"] for record in records), expected)


if __name__ == "__main__":
    unittest.main()
