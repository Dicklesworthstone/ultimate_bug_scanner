#!/usr/bin/env python3
"""Unit tests for ubs_core.suppression — statement-interval index (bead A7)."""
from __future__ import annotations

import json
import importlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
from ubs_core.lexer import javascript_lexical_views, strip_comments_and_strings  # noqa: E402
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


class PhpSuppressionOwnershipTests(unittest.TestCase):
    RULE = "php.security.command-injection"

    def test_php_comment_forms_and_scoped_markers(self) -> None:
        source = ("<?php\n"
                  "system($_GET['x']); // ubs:ignore[" + self.RULE + "]\n"
                  "system($_GET['x']); # ubs:ignore[" + self.RULE + "]\n"
                  "/* ubs:ignore[" + self.RULE + "] */\n"
                  "system($_GET['x']);\n")
        self.assertEqual([marker.line for marker in parse_markers(source, "php")], [2, 3, 4])
        index = build_index(source, "php")
        for line in (2, 3, 5):
            self.assertTrue(index.is_suppressed(line, self.RULE))
            self.assertFalse(index.is_suppressed(line, "php.security.sql-injection"))

    def test_strings_and_template_html_do_not_own_markers(self) -> None:
        examples = (
            "<?php\n$example = '// ubs:ignore';\nsystem($_GET['x']);\n",
            "<?php\n$example = \"# ubs:ignore\";\nsystem($_GET['x']);\n",
            "<!-- ubs:ignore -->\n<?php system($_GET['x']); ?>\n",
            "<p>// ubs:ignore</p>\n<?php system($_GET['x']); ?>\n",
            "<?php\n#[Example('ubs:ignore')]\nfunction example() {}\nsystem($_GET['x']);\n",
        )
        for source in examples:
            with self.subTest(source=source):
                self.assertEqual(parse_markers(source, "php"), [])
                index = build_index(source, "php")
                self.assertFalse(any(index.is_suppressed(line, self.RULE)
                                     for line in range(1, len(source.splitlines()) + 1)))

    def test_heredoc_and_nowdoc_are_opaque_to_marker_parser(self) -> None:
        for opening in ("<<<EXAMPLE", "<<<'EXAMPLE'", '<<<"EXAMPLE"'):
            source = ("<?php\n$example = " + opening + "\n"
                      "# ubs:ignore\n// ubs:ignore\n/* ubs:ignore */\n"
                      "EXAMPLE;\nsystem($_GET['x']);\n")
            with self.subTest(opening=opening):
                self.assertEqual(parse_markers(source, "php"), [])
                self.assertFalse(build_index(source, "php").is_suppressed(7, self.RULE))

    def test_php_masks_preserve_offsets_and_newlines(self) -> None:
        source = "<p>Example</p>\n<?php\n# note\n$x = 'literal'; /* block\ncomment */\necho $x; ?>"
        masked = strip_comments_and_strings(source, "php")
        self.assertEqual(len(masked), len(source))
        self.assertEqual([i for i, c in enumerate(masked) if c == "\n"],
                         [i for i, c in enumerate(source) if c == "\n"])
        self.assertNotIn("Example", masked)
        self.assertNotIn("literal", masked)
        self.assertNotIn("comment", masked)
        self.assertIn("echo $x;", masked)


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


class JavaScriptAsyncSuppressionTests(unittest.TestCase):
    CASES = (
        ("async_map_ignored", "js.async.map-ignored", 'items.map(async (item) => { await work(item); });'),
        ("async_timer", "js.async.timer", 'setTimeout(async () => { await work(); }, 1);'),
        ("async_sort_comparator", "js.async.sort-comparator",
         'items.sort(async (left, right) => (await score(left)) - (await score(right)));'),
        ("async_map_awaited", "js.async.map-awaited", 'await items.map(async (item) => work(item));'),
        ("async_reduce", "js.async.reduce", 'items.reduce(async (total, item) => total + (await load(item)), 0);'),
        ("async_jsx_handler", "js.async.jsx-handler", 'const element = <button onClick={async () => { await work(); }}>Go</button>;'),
        ("async_react_effect", "js.async.react-effect", 'useEffect(async () => { await work(); }, []);'),
        ("async_promise_executor", "js.async.promise-executor", 'new Promise(async (resolve) => { resolve(await work()); });'),
        ("async_foreach", "js.async.foreach", 'items.forEach(async (item) => { await work(item); });'),
        ("async_promise_all_map", "js.async.promise-all-map", 'await Promise.all(items.map((item) => { work(item); }));'),
        ("async_flatmap", "js.async.flatmap", 'items.flatMap(async (item) => [await work(item)]);'),
        ("async_event_listener", "js.async.event-listener", "target.addEventListener('click', async () => { await work(); });"),
        ("async_predicates", "js.async.predicate", 'items.filter(async (item) => await keep(item));'),
        ("async_promise_all_foreach", "js.async.promise-all-foreach", 'Promise.all(items.forEach((item) => { work(item); }));'),
        ("async_event_emitter", "js.async.event-emitter", 'bus.on("message", async (payload) => { await work(payload); });'),
    )

    def test_direct_analyzers_use_exact_real_comment_ownership(self):
        from ubs_core.registry import RunContext

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="js-async-markers-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.tsx"
            for name, rule, statement in self.CASES:
                analyzer = importlib.import_module(f"ubs_core.analyzers.{name}")
                for variant, expected in (("unmarked", [2]), ("wrong", [2]), ("quoted", [2]),
                                          ("owned", []), ("bare", []), ("previous", []),
                                          ("previous-wrong", [3]), ("previous-quoted", [3])):
                    with self.subTest(analyzer=name, variant=variant):
                        lines = ['async function probe(items, target, bus) {', '  ' + statement, '}']
                        if variant in ("wrong", "owned", "bare"):
                            marker = ("ubs:ignore[unrelated.rule]" if variant == "wrong" else
                                      f"ubs:ignore[{rule}]" if variant == "owned" else "ubs:ignore")
                            lines[1] += ' // ' + marker
                        elif variant == "quoted":
                            lines[1] = '  const marker_note = "ubs:ignore"; ' + statement
                        elif variant.startswith("previous"):
                            lines.insert(1, '  const marker_note = "ubs:ignore";' if variant == "previous-quoted" else
                                         '  // ubs:ignore[unrelated.rule]' if variant == "previous-wrong" else
                                         f'  // ubs:ignore[{rule}]')
                        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        records = list(analyzer.run(RunContext(lang="javascript", files=[source])))
                        self.assertEqual([(record["rule"], record["line"]) for record in records],
                                         [(rule, line) for line in expected], records)

    def test_existing_analyzer_ownership_controls_remain_valid(self):
        # The original embedded controls independently require deep markers
        # inside six callback statements and the outer Promise.all marker.
        for name, _rule, _statement in self.CASES:
            analyzer = importlib.import_module(f"ubs_core.analyzers.{name}")
            for label, check in analyzer.SELF_TESTS:
                with self.subTest(analyzer=name, control=label):
                    check()

    def test_promise_all_owns_its_nested_diagnostic_without_hiding_the_next_call(self):
        from ubs_core.registry import RunContext

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="js-promise-ownership-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.ts"
            for name, rule, method in (
                ("async_promise_all_map", "js.async.promise-all-map", "map"),
                ("async_promise_all_foreach", "js.async.promise-all-foreach", "forEach"),
            ):
                analyzer = importlib.import_module(f"ubs_core.analyzers.{name}")
                for owner, marker, first_visible in (
                    (2, "", True), (2, "ubs:ignore[unrelated.rule]", True),
                    (2, f"ubs:ignore[{rule}]", False), (4, f"ubs:ignore[{rule}]", False),
                    (4, "ubs:ignore[unrelated.rule]", True),
                ):
                    with self.subTest(analyzer=name, owner=owner, marker=marker):
                        lines = ['async function probe(items) {', '  await Promise.all(',
                                 f'    items.{method}((item) => {{', '      work(item);',
                                 '    })', '  );',
                                 f'  await Promise.all(items.{method}((item) => {{ work(item); }}));', '}']
                        if marker:
                            lines[owner - 1] += ' // ' + marker
                        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        records = list(analyzer.run(RunContext(lang="javascript", files=[source])))
                        self.assertEqual([(record["rule"], record["line"]) for record in records],
                                         [(rule, line) for line in ([3, 7] if first_visible else [7])], records)

    def test_callback_windows_do_not_own_a_later_statement_marker(self):
        from ubs_core.registry import RunContext

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="js-async-next-marker-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.tsx"
            for name, rule, statement in self.CASES:
                with self.subTest(analyzer=name):
                    analyzer = importlib.import_module(f"ubs_core.analyzers.{name}")
                    source.write_text('async function probe(items, target, bus) {\n  ' + statement
                                      + '\n  report("finished"); // ubs:ignore\n}\n', encoding="utf-8")
                    records = list(analyzer.run(RunContext(lang="javascript", files=[source])))
                    self.assertEqual([(record["rule"], record["line"]) for record in records], [(rule, 2)], records)


class JavaScriptLexicalSuppressionTests(unittest.TestCase):
    def test_jsx_self_closing_tags_preserve_comments_and_executable_delimiters(self):
        prefixes = (
            'const view = <Widget data={value} />;',
            'const view = <Widget {...props} />;',
            'const view = <Widget data={a > b ? a : b} />;',
            'const view = <Widget child={<Inner data={value} />} />;',
            'const view = <Widget><Inner data={value} /></Widget>;',
            'const view = <Widget data={total / count} />;',
            'const view = <Widget render={() => ({value})} />;',
            'const view = (<Namespace.Widget data={value} />);',
            'const view = <custom-widget data={value} />;',
            'const view = <svg:path data={value} />;',
        )
        for prefix in prefixes:
            source = prefix + ' // ubs:ignore[js.real]\n'
            with self.subTest(source=source):
                comment_free, executable = javascript_lexical_views(source)
                self.assertEqual(comment_free.rstrip(), prefix)
                self.assertEqual(executable.rstrip(), prefix)
                self.assertEqual(len(comment_free), len(source))
                self.assertEqual(len(executable), len(source))
                self.assertEqual(parse_markers(source, lang='tsx'),
                                 [Marker(1, frozenset({'js.real'}), False)])
        source = ('const view = <Widget data={value /* ubs:ignore[js.inner] */} />; '
                  '// ubs:ignore[js.real]\n')
        self.assertEqual(parse_markers(source, lang='jsx'),
                         [Marker(1, frozenset({'js.inner'}), False),
                          Marker(1, frozenset({'js.real'}), False)])
        source = 'const view = <Widget data={/>/.test(value)} />; // ubs:ignore[js.real]\n'
        self.assertEqual(javascript_lexical_views(source)[1].rstrip(),
                         'const view = <Widget data={0  .test(value)} />;')
        self.assertEqual(parse_markers(source, lang='jsx'),
                         [Marker(1, frozenset({'js.real'}), False)])

    def test_jsx_slash_recognition_keeps_legal_regex_and_division(self):
        for prefix in (
            'const pattern = />ubs:ignore/;',
            'const pattern = />.+ubs:ignore/;',
            'const pattern = /[/>]ubs:ignore/;',
            'if (ready) {} />ubs:ignore/.test(value);',
            'if (a < b) {} />ubs:ignore/.test(value);',
            'const quotient = ({}) / divisor;',
            'const quotient = total / count;',
        ):
            source = prefix + ' // ubs:ignore[js.real]\n'
            with self.subTest(source=source):
                comment_free, executable = javascript_lexical_views(source)
                self.assertEqual(comment_free.rstrip(), prefix)
                self.assertEqual(len(executable), len(source))
                self.assertEqual(parse_markers(source, lang='javascript'),
                                 [Marker(1, frozenset({'js.real'}), False)])
                if 'pattern' in prefix or prefix.startswith('if '):
                    self.assertNotIn('ubs:ignore', executable)
                else:
                    self.assertIn(' / ', executable)

    def test_template_and_regex_literals_cannot_create_comment_directives(self):
        for source in (
            'const resetUrl = `https://${req.headers.host}/reset`; const note = "ubs:ignore";\n',
            'const text = `https://example.com/ubs:ignore`;\n',
            'const text = `hello ${format(`https://${host}/ubs:ignore`)}`; const note = "ubs:ignore";\n',
            'const text = `line1\nhttps://ubs:ignore\n${value}`; const note = "ubs:ignore";\n',
            'const text = `escaped \\` https://ubs:ignore`; const note = "ubs:ignore";\n',
            'const pattern = /[/*]ubs:ignore/; const note = "ubs:ignore";\n',
        ):
            with self.subTest(source=source):
                self.assertEqual(parse_markers(source, lang='javascript'), [])
                self.assertFalse(build_index(source, lang='javascript').is_suppressed(1, 'js.security.host-header'))

    def test_real_comments_inside_interpolation_and_after_literals_keep_exact_scopes(self):
        for source in (
            'const text = `https://ubs:ignore`; // ubs:ignore[js.real]\n',
            'const text = `x${value /* ubs:ignore[js.real] */}`;\n',
            'const text = `x${format(`https://${host}/ubs:ignore`) /* ubs:ignore[js.real] */}`;\n',
            'const pattern = /[/*]ubs:ignore/; // ubs:ignore[js.real]\n',
            'const ratio = total / count; // ubs:ignore[js.real]\n',
        ):
            for language in ('javascript', 'js', 'typescript', 'ts'):
                with self.subTest(source=source, language=language):
                    self.assertEqual(parse_markers(source, lang=language),
                                     [Marker(line=1, rules=frozenset({'js.real'}), standalone=False)])
                    index = build_index(source, lang=language)
                    self.assertTrue(index.is_suppressed(1, 'js.real'))
                    self.assertFalse(index.is_suppressed(1, 'unrelated.rule'))

    def test_template_line_offsets_and_following_statement_ownership(self):
        source = ('const text = `https://ubs:ignore\n${value /* ubs:ignore[js.real] */}`;\n'
                  'work();\n// ubs:ignore[js.next]\nnext();\n')
        for language in ('javascript', 'typescript'):
            with self.subTest(language=language):
                markers = parse_markers(source, lang=language)
                self.assertEqual(markers, [Marker(2, frozenset({'js.real'}), False),
                                           Marker(4, frozenset({'js.next'}), True)])
                index = build_index(source, lang=language)
                self.assertTrue(index.is_suppressed(1, 'js.real'))
                self.assertFalse(index.is_suppressed(3, 'js.real'))
                self.assertFalse(index.is_suppressed(3, 'js.next'))
                self.assertTrue(index.is_suppressed(5, 'js.next'))


class JavaScriptSecuritySuppressionTests(unittest.TestCase):
    CASES = (
        ('sec_fetch_abort', 'js.security.fetch-abort', [1], "fetch('/api/users');\n",
         "fetch('/api/users', { signal: AbortSignal.timeout(5000) });\n"),
        ('sec_ssrf_fetch', 'js.security.ssrf-fetch', [1],
         'fetch(req.query.url, { signal: AbortSignal.timeout(5000) });\n',
         "fetch('https://api.example.com/status', { signal: AbortSignal.timeout(5000) });\n"),
        ('sec_tls', 'js.security.tls', [1], 'new https.Agent({ rejectUnauthorized: false });\n',
         'new https.Agent({ rejectUnauthorized: true });\n'),
        ('sec_jwt', 'js.security.jwt', [2], "import jwt from 'jsonwebtoken';\njwt.decode(token);\n",
         "import jwt from 'jsonwebtoken';\njwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: 'trusted', audience: 'app' });\n"),
        ('sec_cors', 'js.security.cors', [1], "app.use(cors({ origin: '*', credentials: true }));\n",
         "app.use(cors({ origin: 'https://trusted.example.com', credentials: true }));\n"),
        ('sec_open_redirect', 'js.security.open-redirect', [1], 'router.push(searchParams.get("to"));\n',
         'router.push("/dashboard");\n'),
        ('sec_header_injection', 'js.security.header-injection', [1], "res.setHeader('X-Trace', req.query.name);\n",
         "res.setHeader('X-Trace', encodeURIComponent(req.query.name));\n"),
        ('sec_path_traversal', 'js.security.path-traversal', [1], 'res.download(path.join(ROOT, req.query.f));\n',
         "res.download('/srv/static/report.pdf');\n"),
        ('sec_host_header', 'js.security.host-header', [1], 'const resetUrl = `https://${req.headers.host}/reset`;\n',
         "const resetUrl = process.env.PUBLIC_BASE_URL + '/reset';\n"),
        ('sec_prototype_pollution', 'js.security.prototype-pollution', [1], 'const merged = Object.assign({}, req.body);\n',
         "const merged = Object.assign({}, { label: 'safe' });\n"),
        ('sec_hardcoded_secrets', 'js.security.hardcoded-secrets', [1],
         "const jwtSecret = process.env.JWT_SECRET || 'live-jwt-signing-key-9f3a';\n",
         'const jwtSecret = process.env.JWT_SECRET;\n'),
        ('sec_weak_random', 'js.security.weak-random', [1], 'const resetCode = Math.random().toString(36).slice(2);\n',
         'const resetCode = crypto.randomUUID();\n'),
        ('sec_message_origin', 'js.security.message-origin', [1],
         "window.addEventListener('message', (event) => { handle(event.data); });\n",
         "window.addEventListener('message', (event) => { if (event.origin !== 'https://trusted.example.com') return; handle(event.data); });\n"),
        ('sec_post_message', 'js.security.post-message', [1], "worker.postMessage(payload, '*');\n",
         "worker.postMessage(payload, 'https://trusted.example.com');\n"),
        ('ctcompare_js', 'javascript.ctcompare.unsafe_secret_compare', [1], 'const ok = authToken === expectedAuthToken;\n',
         'const ok = crypto.timingSafeEqual(Buffer.from(authToken), Buffer.from(expectedAuthToken));\n'),
        ('sec_cookies', 'js.security.cookies', [1], "res.cookie('session_id', sessionId);\n",
         "res.cookie('session_id', sessionId, { httpOnly: true, secure: true, sameSite: 'strict' });\n"),
        ('sec_request_regex', 'js.security.request-regex', [1], "new RegExp(req.query.get('q'));\n",
         "new RegExp('^[a-z]+$');\n"),
        ('sec_request_body', 'js.security.request-body', [2],
         'async function POST(request) {\n  const payload = await request.json();\n}\n',
         "async function POST(request) {\n  if (Number(request.headers.get('content-length')) > 1000000) throw new Error('large');\n  const payload = await request.json();\n}\n"),
        ('sec_reverse_proxy', 'js.security.reverse-proxy', [1], 'createProxyMiddleware({ target: req.query.upstream });\n',
         "createProxyMiddleware({ target: 'https://api.example.com' });\n"),
        ('sec_archive_entry', 'js.security.archive-entry', [1], 'const outputPath = path.join(destination, entry.entryName);\n',
         "const outputPath = path.join(destination, 'fixed-name.txt');\n"),
        ('sec_sql_injection', 'js.security.sql-injection', [1], "db.query(`SELECT * FROM users WHERE id = '${req.query.id}'`);\n",
         "db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);\n"),
        ('sec_jsx_target_blank', 'js.security.jsx-target-blank', [1], 'const link = <a href={href} target="_blank">link</a>;\n',
         'const link = <a href={href} target="_blank" rel="noopener noreferrer">link</a>;\n'),
        ('sec_dangerous_html', 'js.security.dangerous-html', [1], 'const view = <div dangerouslySetInnerHTML={{ __html: html }} />;\n',
         'const view = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;\n'),
    )
    FLOWS = (
        ('sec_ssrf_fetch', 'js.security.ssrf-fetch', (1,), [3],
         'const targetUrl = req.query.url;\ntouch();\nfetch(targetUrl, { signal: AbortSignal.timeout(5000) });\n'),
        ('sec_open_redirect', 'js.security.open-redirect', (1,), [3],
         'const target = searchParams.get("to");\ntouch();\nrouter.push(target);\n'),
        ('sec_header_injection', 'js.security.header-injection', (1,), [3],
         "const headerValue = req.query.name;\ntouch();\nres.setHeader('X-Trace', headerValue);\n"),
        ('sec_path_traversal', 'js.security.path-traversal', (1,), [3],
         'const requestedFile = req.query.f;\ntouch();\nres.download(path.join(ROOT, requestedFile));\n'),
        ('sec_host_header', 'js.security.host-header', (1,), [3],
         'const host = req.headers.host;\ntouch();\nconst resetUrl = `https://${host}/reset`;\n'),
        ('sec_prototype_pollution', 'js.security.prototype-pollution', (1,), [3],
         'const payload = req.body;\ntouch();\nconst merged = Object.assign({}, payload);\n'),
        ('sec_reverse_proxy', 'js.security.reverse-proxy', (1,), [3],
         'const target = req.query.upstream;\ntouch();\ncreateProxyMiddleware({ target });\n'),
        ('sec_archive_entry', 'js.security.archive-entry', (1, 2), [4],
         'const entry = new AdmZip(buffer).getEntries()[0];\nconst entryPath = entry.entryName;\ntouch();\n'
         'const outputPath = path.join(destination, entryPath);\n'),
        ('sec_request_regex', 'js.security.request-regex', (1,), [3],
         "const pattern = req.query.get('q');\ntouch();\nnew RegExp(pattern);\n"),
        ('sec_sql_injection', 'js.security.sql-injection', (1,), [3],
         "const tenant = req.query.tenant;\ntouch();\ndb.query(`SELECT * FROM users WHERE tenant = '${tenant}'`);\n"),
        ('sec_tls', 'js.security.tls', (1,), [3],
         'const rejectUnauthorized = false;\ntouch();\nnew https.Agent({ rejectUnauthorized });\n'),
        ('sec_fetch_abort', 'js.security.fetch-abort', (1,), [],
         "const requestInit = { signal: AbortSignal.timeout(5000) };\ntouch();\nfetch('/api/users', requestInit);\n"),
        ('ctcompare_js', 'javascript.ctcompare.unsafe_secret_compare', (1,), [3],
         'const lhs = authToken;\ntouch();\nconst ok = lhs === expected;\n'),
    )

    def setUp(self):
        artifacts = REPO_ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='js-security-ownership-', dir=artifacts)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def check_source(self, name, rule, label, text, expected):
        import time
        from ubs_core.registry import RunContext

        case = name + '-' + label
        started = time.monotonic()
        print(f'[{case}] RUN', flush=True)
        source = self.root / (case + '.tsx')
        source.write_text(text, encoding='utf-8')
        analyzer = importlib.import_module('ubs_core.analyzers.' + name)
        raw = list(analyzer.run(RunContext(lang='javascript', files=[source])))
        # Exercise the same final policy as the production suppress command;
        # an early receiver must not erase facts this boundary cannot recover.
        records = SourceSuppressions('javascript').filter(raw)
        (self.root / (case + '.json')).write_text(json.dumps({'raw': raw, 'final': records}, indent=2))
        actual = [(record['rule'], record['line']) for record in records]
        try:
            self.assertEqual(actual, [(rule, line) for line in expected], {'source': text, 'raw': raw, 'final': records})
        except AssertionError:
            print(f'[{case}] FAIL ({time.monotonic() - started:.3f}s) artifacts={self.root}', flush=True)
            raise
        print(f'[{case}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    def test_all_security_receivers_keep_unrelated_scopes_and_quoted_markers(self):
        for name, rule, sites, positive, negative in self.CASES:
            for variant in ('unmarked', 'quoted', 'wrong', 'owned', 'bare', 'previous', 'previous-wrong', 'previous-quoted'):
                with self.subTest(analyzer=name, variant=variant):
                    lines = positive.splitlines()
                    target = sites[0] - 1
                    expected = sites if variant in ('unmarked', 'quoted', 'wrong') else []
                    if variant == 'quoted':
                        lines[target] += '; const marker_note = "ubs:ignore";'
                    elif variant in ('wrong', 'owned', 'bare'):
                        marker = ('ubs:ignore[unrelated.rule]' if variant == 'wrong' else
                                  f'ubs:ignore[{rule}]' if variant == 'owned' else 'ubs:ignore')
                        lines[target] += ' // ' + marker
                    elif variant.startswith('previous'):
                        lines.insert(target, 'const marker_note = "ubs:ignore";' if variant == 'previous-quoted' else
                                     '// ubs:ignore[unrelated.rule]' if variant == 'previous-wrong' else
                                     f'// ubs:ignore[{rule}]')
                        expected = [line + 1 for line in sites] if variant != 'previous' else []
                    self.check_source(name, rule, variant, '\n'.join(lines) + '\n', expected)
            with self.subTest(analyzer=name, variant='safe'):
                self.check_source(name, rule, 'safe', negative, [])

    def test_source_annotations_preserve_later_sink_and_validation_facts(self):
        for name, rule, origins, sites, program in self.FLOWS:
            for origin in origins:
                for variant in ('unmarked', 'bare', 'owned', 'wrong', 'quoted', 'previous'):
                    with self.subTest(analyzer=name, origin=origin, variant=variant):
                        lines = program.splitlines()
                        expected = sites
                        if variant == 'quoted':
                            lines[origin - 1] += '; const marker_note = "ubs:ignore";'
                        elif variant == 'previous':
                            lines.insert(origin - 1, f'// ubs:ignore[{rule}]')
                            expected = [line + 1 for line in sites]
                        elif variant != 'unmarked':
                            marker = ('ubs:ignore' if variant == 'bare' else
                                      f'ubs:ignore[{rule}]' if variant == 'owned' else 'ubs:ignore[unrelated.rule]')
                            lines[origin - 1] += ' // ' + marker
                        self.check_source(name, rule, f'source-{origin}-{variant}', '\n'.join(lines) + '\n', expected)

    def test_later_statement_marker_cannot_hide_an_earlier_message_handler(self):
        name, rule, sites, positive, _negative = next(item for item in self.CASES if item[0] == 'sec_message_origin')
        for marker in ('ubs:ignore', f'ubs:ignore[{rule}]', 'ubs:ignore[unrelated.rule]'):
            with self.subTest(marker=marker):
                self.check_source(name, rule, 'later-' + marker.replace(':', '-'),
                                  positive + 'report("done"); // ' + marker + '\n', sites)

    def test_original_security_controls_remain_explicit(self):
        for name, _rule, _sites, _positive, _negative in self.CASES:
            analyzer = importlib.import_module('ubs_core.analyzers.' + name)
            for label, check in analyzer.SELF_TESTS:
                with self.subTest(analyzer=name, control=label):
                    check()

    def test_multiline_call_comments_own_the_call_and_only_their_rule(self):
        for name, rule, source, owner in (
            ('sec_cors', 'js.security.cors',
             "app.use(cors({\n  origin: '*',\n  credentials: true,\n}));\n", 3),
            ('sec_cookies', 'js.security.cookies',
             "res.cookie('auth_token', token, {\n  httpOnly: false,\n  secure: false,\n});\n", 2),
        ):
            for marker, expected in (('ubs:ignore', []), (f'ubs:ignore[{rule}]', []),
                                     ('ubs:ignore[unrelated.rule]', [1])):
                with self.subTest(analyzer=name, marker=marker):
                    lines = source.splitlines()
                    lines[owner - 1] += ' // ' + marker
                    program = '\n'.join(lines) + '\n'
                    self.check_source(name, rule, 'multiline-' + marker.replace(':', '-'), program, expected)


class GoPipelineSuppressionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('jq') and shutil.which('rg') and shutil.which('ast-grep'),
                         'native UBS dependencies required')
    def test_native_pattern_counts_exits_and_cache_honor_only_the_owning_comment(self):
        import time

        artifacts = REPO_ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        rule = 'go.logging.sensitive-data'
        with tempfile.TemporaryDirectory(prefix='go-native-pattern-marker-', dir=artifacts) as tmp:
            root = Path(tmp)
            source = root / 'case.go'
            selected = root / 'selected.nul'
            selected.write_bytes(os.fsencode(source) + b'\0')
            body = '    log.Printf("%s", token)'
            for variant, statement, expected in (
                ('unmarked', body, [4]),
                ('quoted', body + '; _ = "ubs:ignore"', [4]),
                ('wrong-scope', body + ' // ubs:ignore[unrelated.rule]', [4]),
                ('owned', body + f' // ubs:ignore[{rule}]', []),
                ('bare', body + ' // ubs:ignore', []),
                ('previous', f'    // ubs:ignore[{rule}]\n' + body, []),
            ):
                source.write_text('package probe\nimport "log"\nfunc emit(token string) {\n'
                                  + statement + '\n}\n', encoding='utf-8')
                for fmt in ('json', 'sarif'):
                    env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
                    env.update(UBS_NO_AUTO_UPDATE='1', UBS_PROFILE='1', PYTHONDONTWRITEBYTECODE='1',
                               UBS_CACHE_DIR=str(root / f'cache-{variant}-{fmt}'))
                    for mode in ('cold', 'warm', 'disabled'):
                        label = f'go-native-pattern-{variant}-{fmt}-{mode}'
                        with self.subTest(case=label):
                            print(f'[{label}] RUN', flush=True)
                            started = time.monotonic()
                            stats = root / (label + '.cache.json')
                            run_env = dict(env, UBS_NO_CACHE='1' if mode == 'disabled' else '0',
                                           UBS_CACHE_FILE=str(stats))
                            command = [str(REPO_ROOT / 'modules/ubs-golang.sh'), '--ci', f'--format={fmt}',
                                       '--files-from=' + str(selected), '--fail-on-warning',
                                       '--skip=' + ','.join(str(cat) for cat in range(1, 23) if cat != 14),
                                       str(root)]
                            proc = subprocess.run(command, cwd=root, env=run_env, capture_output=True,
                                                  text=True, timeout=120)
                            (root / (label + '.stdout')).write_text(proc.stdout)
                            (root / (label + '.stderr')).write_text(proc.stderr)
                            self.assertEqual(proc.returncode, int(bool(expected)), proc.stdout + proc.stderr)
                            report = json.loads(proc.stdout)
                            if fmt == 'json':
                                self.assertEqual(report['status'], 'ok', report)
                                self.assertEqual(report['critical'], len(expected), report)
                                self.assertEqual(report['warning'], 0, report)
                                self.assertEqual(report['info'], 0, report)
                                sites = [row['line'] for row in report['findings'] if row['rule'] == rule]
                            else:
                                results = [row for run in report['runs'] for row in run.get('results', [])]
                                self.assertEqual(len(results), len(expected), report)
                                self.assertTrue(all(row['level'] == 'error' for row in results), report)
                                sites = [row['locations'][0]['physicalLocation']['region']['startLine']
                                         for row in results if row['ruleId'] == rule]
                            self.assertEqual(sites, expected, report)
                            cache = json.loads(stats.read_text())
                            self.assertEqual(cache['hits'], int(mode == 'warm'), cache)
                            self.assertEqual(cache['misses'], int(mode != 'warm'), cache)
                            print(f'[{label}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    @unittest.skipUnless(shutil.which('ast-grep'), 'real ast-grep required')
    def test_ast_counts_use_the_public_id_without_erasing_computed_facts(self):
        from ubs_core import go_ast, go_rules, go_scan

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        ast_rule, computed_rule = 'go.tls-insecure-skip', 'go.crypto.insecureskipverify'
        with tempfile.TemporaryDirectory(prefix='go-ast-marker-', dir=artifacts) as tmp:
            root = Path(tmp)
            source = root / 'case.go'
            go_rules.generate(root / 'rules')
            for marker, ast_count, computed_count in (
                ('', 1, 1), (' // ubs:ignore[unrelated.rule]', 1, 1),
                (f' // ubs:ignore[{ast_rule}]', 0, 1),
                (f' // ubs:ignore[{computed_rule}]', 1, 0), (' // ubs:ignore', 0, 0),
                ('; var marker_note = "ubs:ignore"', 1, 1),
            ):
                with self.subTest(marker=marker):
                    source.write_text('package probe\nimport ("crypto/tls"; "net/http")\n'
                                      'var config = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}'
                                      + marker + '\n')
                    sink, errors = StringIO(), []
                    counts, matches = go_ast.scan_config(root / 'rules/sgconfig-go.yml', [source],
                        {ast_rule: [(9, 'warning', 'TLS disabled')]}, sink, errors=errors)
                    self.assertEqual(errors, [], errors)
                    self.assertEqual(counts.get(ast_rule, 0), ast_count, matches)
                    self.assertEqual(len(matches.get(ast_rule, [])), 1, matches)
                    rows = [json.loads(line) for line in sink.getvalue().splitlines()]
                    self.assertEqual(sum(row['rule'] == ast_rule for row in rows), ast_count * 2, rows)
                    computed = go_scan.computed_checks([source], matches,
                        {1, 2, 4, 5, 8, 12, 13, 19, 21, 22}, True)
                    self.assertEqual(sum(row['rule'] == computed_rule for row in computed), computed_count, computed)

    def test_patterns_count_only_the_owning_rule_before_thresholds(self):
        from ubs_core import go_scan

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = 'go.logging.sensitive-data'
        pattern = next(item for item in go_scan.load_patterns() if item.rule_id == rule)
        with tempfile.TemporaryDirectory(prefix="go-pattern-marker-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.go"
            for marker, expected in (('', [1]), (' // ubs:ignore[unrelated.rule]', [1]),
                                     ('; _ = "ubs:ignore"', [1]), (f' // ubs:ignore[{rule}]', [])):
                with self.subTest(marker=marker):
                    source.write_text('log.Printf("%s", token)' + marker + '\n', encoding='utf-8')
                    sink = StringIO()
                    counts = go_scan.scan_patterns([pattern], [source], sink, set())
                    rows = [json.loads(line) for line in sink.getvalue().splitlines()]
                    self.assertEqual([row['line'] for row in rows], expected)
                    self.assertEqual(counts, {'critical': len(expected), 'warning': 0, 'info': 0})

    def test_pipeline_and_real_cache_reapply_source_policy(self):
        import contextlib
        from ubs_core import go_scan

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = 'go.logging.sensitive-data'
        with tempfile.TemporaryDirectory(prefix="go-pipeline-marker-", dir=artifacts) as tmp:
            root = Path(tmp)
            source = root / 'case.go'
            selected = root / 'files.txt'
            selected.write_bytes(os.fsencode(source) + b'\0')
            sink, summary = root / 'findings.ndjson', root / 'summary.json'
            env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
            env.update(UBS_NO_AUTO_UPDATE='1', UBS_CACHE_DIR=str(root / 'cache'))
            args = ['--files-from', str(selected), '--sink', str(sink), '--json-out', str(summary),
                    '--project-dir', str(root), '--fail-on-warning']
            source.write_text('package probe\nimport "log"\nfunc emit(token string) {\n'
                              f'    log.Printf("%s", token) // ubs:ignore[{rule}]\n}}\n', encoding='utf-8')
            for mode in ('cold', 'warm', 'disabled'):
                with self.subTest(cache=mode), patch.dict(os.environ, dict(env, UBS_NO_CACHE='1' if mode == 'disabled' else '0'), clear=True):
                    with contextlib.redirect_stderr(StringIO()):
                        code = go_scan.main(args)
                    doc = json.loads(summary.read_text())
                    self.assertEqual(code, 0, doc)
                    self.assertEqual(doc['critical'], 0, doc)
                    self.assertEqual(doc['status'], 'ok', doc)
                    self.assertFalse(any(row['rule'] == rule for row in doc['findings']), doc)
                    if mode != 'disabled':
                        self.assertEqual(doc['extras']['profile']['cache_hits'], int(mode == 'warm'), doc)
                        entries = list((root / 'cache').glob('*/files/**/*.json'))
                        self.assertTrue(entries)
                        rows = [row for entry in entries for row in json.loads(entry.read_text()).get('findings', [])]
                        self.assertFalse(any(row['rule'] == rule for row in rows), rows)
            # Inject a stale/old producer answer into the real warm cache; the
            # output boundary must recheck source ownership before counting it.
            for entry in (root / 'cache').glob('*/files/**/*.json'):
                data = json.loads(entry.read_text())
                data.setdefault('findings', []).append({'rule': rule, 'path': str(source), 'line': 4,
                    'col': 1, 'severity': 'critical', 'message': 'old cached finding', 'category_id': 'golang.logging'})
                entry.write_text(json.dumps(data), encoding='utf-8')
            # Directory Merkle hits can bypass individual file entries.
            for entry in (root / 'cache').glob('*/dirs/**/*.json'):
                data = json.loads(entry.read_text())
                for rows in data.get('findings', {}).values():
                    rows.append({'rule': rule, 'path': str(source), 'line': 4, 'col': 1,
                        'severity': 'critical', 'message': 'old directory finding', 'category_id': 'golang.logging'})
                entry.write_text(json.dumps(data), encoding='utf-8')
            with patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(StringIO()):
                self.assertEqual(go_scan.main(args), 0)
            doc = json.loads(summary.read_text())
            self.assertEqual(doc['extras']['profile']['cache_hits'], 1, doc)
            self.assertFalse(any(row['rule'] == rule for row in doc['findings']), doc)

    def test_ratio_and_source_facts_do_not_disappear_for_unrelated_markers(self):
        from ubs_core import go_scan

        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = 'go.filesystem.open-close-imbalance'
        with tempfile.TemporaryDirectory(prefix="go-computed-marker-", dir=artifacts) as tmp:
            source = Path(tmp) / 'case.go'
            for marker, expected in (('', [1]), (' // ubs:ignore[unrelated.rule]', [1]),
                                     ('; _ = "ubs:ignore"', [1]), (f' // ubs:ignore[{rule}]', [])):
                with self.subTest(marker=marker):
                    source.write_text('file, err := os.Open(path)' + marker + '\n', encoding='utf-8')
                    self.assertEqual([row['line'] for row in go_scan.computed_checks([source], {}, {1, 2, 4, 5, 9, 12, 13, 19, 21, 22}, True)], expected)


class GoDetectorSuppressionTests(unittest.TestCase):
    CASES = (
        ("cookie_security", "go.security.cookie-security", 6,
         'package probes\n\nimport "net/http"\n\nfunc cookie(w http.ResponseWriter) {\n'
         '\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: "token"})\n}\n'),
        ("cors_credentials", "go.security.cors-credentials", 6,
         'package probes\n\nimport "net/http"\n\nfunc cors(w http.ResponseWriter) {\n'
         '\tw.Header().Set("Access-Control-Allow-Origin", "*"); w.Header().Set("Access-Control-Allow-Credentials", "true")\n}\n'),
        ("jwt_verification", "go.security.jwt-verification", 6,
         'package probes\n\nimport jwt "github.com/golang-jwt/jwt/v5"\n\nfunc decode(raw string) {\n'
         '\t_, _, _ = jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})\n}\n'),
        ("request_regex", "go.security.request-regex", 9,
         'package probes\n\nimport (\n\t"net/http"\n\t"regexp"\n)\n\n'
         'func expression(r *http.Request) (*regexp.Regexp, error) {\n'
         '\treturn regexp.Compile(r.URL.Query().Get("pattern"))\n}\n'),
        ("security_randomness", "go.security.insecure-random", 6,
         'package probes\n\nimport "math/rand"\n\nfunc token() int {\n\treturn rand.Int()\n}\n'),
        ("hardcoded_secrets", "go.security.hardcoded-secrets", 4,
         'package probes\n\nfunc value() string {\n\tsecret := "LivePassword123"\n\treturn secret\n}\n'),
        ("archive_extraction", "go.security.archive-extraction", 10,
         'package probes\n\nimport (\n\t"archive/tar"\n\t"os"\n\t"path/filepath"\n)\n\n'
         'func extract(entry *tar.Header, root string) error {\n'
         '\treturn os.WriteFile(filepath.Join(root, entry.Name), nil, 0600)\n}\n'),
    )
    FLOWS = (
        ("header_injection", "go.security.header-injection", 7, '"net/http"',
         'value := r.URL.Query().Get("name")', 'w.Header().Set("X-Result", value)'),
        ("host_header", "go.security.host-header", 7, '"net/http"',
         'value := r.Host', '_ = "https://" + value'),
        ("outbound_url", "go.security.outbound-url", 7, '"net/http"',
         'value := r.URL.Query().Get("url")', '_, _ = http.Get(value)'),
        ("reverse_proxy_ssrf", "go.security.reverse-proxy-ssrf", 8,
         '("net/http"; "net/http/httputil"; "net/url")',
         'value := r.URL.Query().Get("upstream")\n    target, _ := url.Parse(value)',
         '_ = httputil.NewSingleHostReverseProxy(target)'),
        ("open_redirect", "go.security.open-redirect", 7, '"net/http"',
         'value := r.URL.Query().Get("next")', 'http.Redirect(w, r, value, http.StatusFound)'),
        ("request_body_limit", "go.filesystem.request-body-limit", 7, '("io"; "net/http")',
         'body := r.Body', '_, _ = io.ReadAll(body)'),
        ("path_traversal", "go.security.path-traversal", 7, '("net/http"; "os")',
         'value := r.URL.Query().Get("path")', '_, _ = os.Open(value)'),
        ("request_body_limit", "go.filesystem.request-body-limit", 7,
         '("encoding/json"; "net/http")', 'body := r.Body',
         'decoder := json.NewDecoder(body)\n    var value any\n    _ = 0\n    _ = decoder.Decode(&value)'),
        ("request_regex", "go.security.request-regex", 11,
         '("net/http"; "regexp")', 'pattern := r.URL.Query().Get("pattern")',
         '_, _ = regexp.Compile(pattern)'),
    )

    def assert_sites(self, name, rule, source, expected):
        detector = importlib.import_module(f"ubs_core.go_detectors.{name}")
        self.assertEqual(detector.RULE_ID, rule)
        self.assertEqual([hit[1] for hit in detector.find([source])], expected)

    def test_security_randomness_requires_the_emitted_public_rule(self):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = "go.security.insecure-random"
        positive = ('package suppression\n\nimport (\n\t"fmt"\n\tmathrand "math/rand"\n)\n\n'
                    'func scopedRandomToken() string {\n'
                    '\ttoken := fmt.Sprintf("%d", mathrand.Int63())')
        safe = ('package suppression\n\nimport (\n\tcryptorand "crypto/rand"\n\t"encoding/hex"\n)\n\n'
                'func scopedRandomToken() string {\n\tvar bytes [16]byte\n'
                '\tif _, err := cryptorand.Read(bytes[:]); err != nil {\n\t\treturn ""\n\t}\n'
                '\treturn hex.EncodeToString(bytes[:])\n}\n')
        with tempfile.TemporaryDirectory(prefix="go-randomness-public-rule-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.go"
            # A distinct scoped ID cannot own this heuristic diagnostic.
            for marker, expected in (("", [9]), ("go.crypto.rand", [9]),
                                     (rule, []), (f"go.crypto.rand,{rule}", [])):
                with self.subTest(marker=marker):
                    comment = f" // ubs:ignore[{marker}]" if marker else ""
                    source.write_text(positive + comment + '\n\treturn token\n}\n', encoding="utf-8")
                    self.assert_sites("security_randomness", rule, source, expected)
            source.write_text(safe, encoding="utf-8")
            self.assert_sites("security_randomness", rule, source, [])

    def test_markers_require_real_comments_and_exact_rule_ownership(self):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        cases = list(self.CASES)
        for name, rule, line, imports, assignment, sink in self.FLOWS[:8]:
            text = ('package probe\nimport ' + imports + '\n'
                    'func handler(w http.ResponseWriter, r *http.Request) {\n    '
                    + assignment + '\n    _ = 0\n    _ = 0\n    ' + sink + '\n}\n')
            cases.append((name, rule, line, text))
        with tempfile.TemporaryDirectory(prefix="go-marker-ownership-", dir=artifacts) as tmp:
            source = Path(tmp) / "case.go"
            for name, rule, line, text in cases:
                for variant, expected in (("unmarked", [line]), ("wrong", [line]),
                                          ("quoted", [line]), ("owned", []), ("bare", []),
                                          ("previous", []), ("previous-wrong", [line + 1]),
                                          ("previous-quoted", [line + 1])):
                    with self.subTest(detector=name, sink=line, variant=variant):
                        lines = text.splitlines()
                        if variant in ("wrong", "owned", "bare"):
                            marker = ("ubs:ignore[unrelated.rule]" if variant == "wrong" else
                                      f"ubs:ignore[{rule}]" if variant == "owned" else "ubs:ignore")
                            lines[line - 1] += " // " + marker
                        elif variant == "quoted":
                            if name == "hardcoded_secrets":
                                # Keep the first-assignment anchor: the legacy
                                # greedy detector also misses an ordinary prefix.
                                lines[line - 1] += '; _ = "ubs:ignore"'
                            else:
                                lines[line - 1] = '_ = "ubs:ignore"; ' + lines[line - 1]
                        elif variant.startswith("previous"):
                            lines.insert(line - 1, '    _ = "ubs:ignore"' if variant == "previous-quoted" else
                                         "    // ubs:ignore[unrelated.rule]" if variant == "previous-wrong" else
                                         f"    // ubs:ignore[{rule}]")
                        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        self.assert_sites(name, rule, source, expected)

    def test_marked_sources_preserve_later_unmarked_flow_findings(self):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        cases = []
        for name, rule, line, imports, assignment, sink in self.FLOWS:
            if name == "request_regex":
                text = ('package probes\n\nimport (\n    "net/http"\n    "regexp"\n)\n\n'
                        'func expression(r *http.Request) {\n    ' + assignment + '\n\n    ' + sink + '\n}\n')
                source_line = 9
            else:
                text = ('package probe\nimport ' + imports + '\n'
                        'func handler(w http.ResponseWriter, r *http.Request) {\n    '
                        + assignment + '\n    _ = 0\n    _ = 0\n    ' + sink + '\n}\n')
                source_line = 4
            cases.append((name, rule, line, source_line, text))
        cases.append(("security_randomness", "go.security.insecure-random", 8, 6,
                      'package probes\n\nimport "math/rand"\n\nfunc sample() int {\n'
                      '\trng := rand.New(rand.NewSource(1))\n\n\ttoken := rng.Int(); return token\n}\n'))
        with tempfile.TemporaryDirectory(prefix="go-marker-flow-", dir=artifacts) as tmp:
            source = Path(tmp) / "flow.go"
            for name, rule, line, source_line, text in cases:
                for marker in ("", "ubs:ignore", f"ubs:ignore[{rule}]", 'quoted'):
                    with self.subTest(detector=name, sink=line, marker=marker):
                        lines = text.splitlines()
                        if marker == 'quoted':
                            lines[source_line - 1] += '; _ = "ubs:ignore"'
                        elif marker:
                            lines[source_line - 1] += ' // ' + marker
                        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        self.assert_sites(name, rule, source, [line])


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
                # Suppression applies to redirect findings, not source transfer
                # functions. An ignored source cannot erase a downstream sink.
                expected = [4] if detector is open_redirect else []
                self.assertEqual(self.lines(detector, fixture(source_marker=" // ubs:ignore")), expected)
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
            root = Path(temp).resolve()
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
                # Both structured AST paths report the actual expression
                # column, not the old run-mode whole-line anchor. Suppression
                # and cached rendering must preserve those precise locations.
                expected[path] = sorted(
                    [(rule, 3, first.index("raw.parse") + 1)
                     for rule in first_rules]
                    + [(ownership, 4, 5), (parsing, 4, 5)]
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


class RustExcludeTestsPreciseScopeTests(unittest.TestCase):
    """Persistent regression tests for Rust precise test-scope interval and span resolution."""

    def test_reject_name_only_authority_ungated_modules(self) -> None:
        """Ungated `mod tests` and `mod test` must remain scanned production code."""
        from ubs_core.rust_scan import build_test_scope_index

        code = """pub fn prod_one() {}

mod tests {
    fn helper() {
        panic!("ungated tests panic");
    }
}

mod test {
    fn helper() {
        panic!("ungated test panic");
    }
}

mod test_parser {
    fn parse() {
        panic!("test_parser panic");
    }
}
"""
        index = build_test_scope_index(code)
        self.assertEqual(len(index.line_intervals), 0, "Ungated modules must never be treated as test scope")

    def test_cfg_boolean_implication_of_test(self) -> None:
        """cfg(...) must provably imply test=True under conservative three-valued evaluation."""
        from ubs_core.rust_scan import cfg_implies_test, compute_test_intervals

        # Provably test-only:
        self.assertTrue(cfg_implies_test("test"))
        self.assertTrue(cfg_implies_test("all(unix, test)"))
        self.assertTrue(cfg_implies_test("all(test, any(feature = \"a\", feature = \"b\"))"))
        self.assertTrue(cfg_implies_test("not(not(test))"))
        self.assertTrue(cfg_implies_test("all(unix, test,)"))  # valid trailing comma

        # Root executable probe counterexamples:
        # 1. Custom key-value atom: test = "not-a-test-build" is NOT the Boolean test predicate
        self.assertFalse(cfg_implies_test('test = "not-a-test-build"'))
        # 2. Unclosed syntax must fail closed
        self.assertFalse(cfg_implies_test("all(test"))
        self.assertFalse(cfg_implies_test("any(test"))
        # 3. Trailing unconsumed input must fail closed
        self.assertFalse(cfg_implies_test("test, unix"))
        self.assertFalse(cfg_implies_test("all(test) extra"))
        # 4. Invalid not arity (not takes exactly one predicate)
        self.assertFalse(cfg_implies_test("not(not(test, unix))"))
        self.assertFalse(cfg_implies_test("not()"))
        self.assertFalse(cfg_implies_test("not(test, unix)"))

        # Other non-test predicates (compiles in production under some environment):
        self.assertFalse(cfg_implies_test("any(test, unix)"), "any(test, unix) compiles in production on Unix")
        self.assertFalse(cfg_implies_test("not(test)"))
        self.assertFalse(cfg_implies_test("all(unix, not(test))"))
        self.assertFalse(cfg_implies_test("any(test, feature = \"mock\")"))
        self.assertFalse(cfg_implies_test("feature = \"test-helpers\""))
        self.assertFalse(cfg_implies_test("unix"))
        self.assertFalse(cfg_implies_test('target_os = "linux"'))
        self.assertFalse(cfg_implies_test(""))

        # Verify compute_test_intervals does NOT hide production for cfg(test="not-a-test-build")
        kv_code = """#[cfg(test = "not-a-test-build")]
fn prod_helper() {
    panic!("must be reported");
}
"""
        intervals = compute_test_intervals(kv_code)
        self.assertEqual(intervals, [], "compute_test_intervals must not hide production for key-value cfg(test=...)")

    def test_restricted_known_test_runners(self) -> None:
        """Only proven test gating and known runners (test, tokio::test, asupersync::test) qualify."""
        from ubs_core.rust_scan import is_test_attr

        # Proven runners:
        self.assertTrue(is_test_attr("#[test]"))
        self.assertTrue(is_test_attr("#[tokio::test]"))
        self.assertTrue(is_test_attr("#[tokio::test(flavor = \"multi_thread\")]"))
        self.assertTrue(is_test_attr("#[asupersync::test]"))
        self.assertTrue(is_test_attr("#[cfg(test)]"))

        # Arbitrary / unproven attributes rejected:
        self.assertFalse(is_test_attr("#[criterion]"))
        self.assertFalse(is_test_attr("#[rstest]"))
        self.assertFalse(is_test_attr("#[quickcheck]"))
        self.assertFalse(is_test_attr("#[foo::test]"))
        self.assertFalse(is_test_attr("#[custom::test_runner]"))

    def test_same_line_production_after_test_item_preserved(self) -> None:
        """#[cfg(test)] fn t(){} fn production(){panic!(...)} must still report production panic."""
        from ubs_core.rust_scan import Scan

        code = """// line 1
#[cfg(test)] fn t(){} fn production(){ panic!("same line prod panic"); }
// line 3
"""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            scan = Scan([tmp_path], tmp_path.parent, exclude_tests=True, skip=set(), detail_limit=10)
            hits = scan.rg_lines(r"\bpanic!\(")
            self.assertEqual(len(hits), 1, "Production panic on same line as test item must be reported")
            self.assertEqual(hits[0].line, 2)
            self.assertIn("same line prod panic", hits[0].text)

            # Conservative line check must also not exclude line 2 because it has external code
            self.assertFalse(scan._is_test_line(str(tmp_path), 2), "Line with external code must not be excluded")
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def test_same_line_production_before_test_item_preserved(self) -> None:
        """fn prod_before(){panic!(...)} #[cfg(test)] fn t(){} must still report production panic."""
        from ubs_core.rust_scan import Scan

        code = """// line 1
fn prod_before(){ panic!("before panic"); } #[cfg(test)] fn t(){}
// line 3
"""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            scan = Scan([tmp_path], tmp_path.parent, exclude_tests=True, skip=set(), detail_limit=10)
            hits = scan.rg_lines(r"\bpanic!\(")
            self.assertEqual(len(hits), 1, "Production panic before test item on same line must be reported")
            self.assertEqual(hits[0].line, 2)
            self.assertIn("before panic", hits[0].text)
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def test_cfg_any_test_unix_reports_production_panic(self) -> None:
        """cfg(any(test, unix)) is production code on Unix and must report findings."""
        from ubs_core.rust_scan import Scan

        code = """#[cfg(any(test, unix))]
fn unix_fn() {
    panic!("unix production panic");
}
"""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            scan = Scan([tmp_path], tmp_path.parent, exclude_tests=True, skip=set(), detail_limit=10)
            hits = scan.rg_lines(r"\bpanic!\(")
            self.assertEqual(len(hits), 1, "cfg(any(test, unix)) panic must be reported with --exclude-tests")
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def test_early_cfg_test_import_and_interleaved_modules(self) -> None:
        """Early import and interleaved modules only exclude their own scopes."""
        from ubs_core.rust_scan import build_test_scope_index

        code = """// line 1
#[cfg(test)]
use std::collections::HashMap; // lines 2-3

pub struct BeforeProd { pub a: u32 } // line 5

#[cfg(test)]
mod alphabet_test { // line 8
    #[test]
    fn test_alpha() {
        panic!("alpha");
    }
} // line 14

pub struct AfterProd { pub b: u32 } // line 16
"""
        index = build_test_scope_index(code)
        # Check conservative line intervals
        self.assertTrue(index.contains(3))
        self.assertFalse(index.contains(5), "BeforeProd must not be in test scope")
        self.assertTrue(index.contains(9))
        self.assertTrue(index.contains(13))
        self.assertFalse(index.contains(16), "AfterProd must not be in test scope")

    def test_unclosed_braces_fail_conservatively(self) -> None:
        """Malformed / unclosed braces must never blind to EOF."""
        from ubs_core.rust_scan import build_test_scope_index

        code = """#[cfg(test)]
mod unclosed {
    fn broken() {
        // missing closing braces
"""
        index = build_test_scope_index(code)
        self.assertEqual(len(index.line_intervals), 0, "Unclosed braces must fail conservatively")
        self.assertFalse(index.contains(4))

    def test_cfg_key_value_test_build_reports_production_panic(self) -> None:
        """cfg(test = "not-a-test-build") is valid custom key-value cfg and must report panic."""
        from ubs_core.rust_scan import Scan

        code = """#[cfg(test = "not-a-test-build")]
fn custom_cfg_prod() {
    panic!("production panic under key-value cfg");
}
"""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            scan = Scan([tmp_path], tmp_path.parent, exclude_tests=True, skip=set(), detail_limit=10)
            hits = scan.rg_lines(r"\bpanic!\(")
            self.assertEqual(len(hits), 1, "Panic under cfg(test = ...) must be reported with --exclude-tests")
            self.assertIn("production panic under key-value cfg", hits[0].text)
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def test_cfg_string_literals_preserved_and_recognized(self) -> None:
        """cfg(all(test, feature = "x")) must preserve string literals and recognize test scope."""
        from ubs_core.rust_scan import compute_test_intervals, cfg_implies_test

        # 1. Direct implication evaluation
        self.assertTrue(cfg_implies_test('all(test, feature = "x")'))
        self.assertTrue(cfg_implies_test('all(test, target_os = "linux")'))

        # 2. Item-level attribute
        item_code = """pub fn prod_fn() {}
#[cfg(all(test, feature = "x"))]
mod tests {
    fn helper() {
        panic!("test panic");
    }
}
pub fn prod_after() {}
"""
        intervals = compute_test_intervals(item_code)
        self.assertEqual(intervals, [(2, 7)], "Item-level cfg with string literals must be recognized as test scope")

        # 3. Root inner attribute
        root_code = """#![cfg(all(test, feature = "x"))]

pub fn helper() {
    panic!("test panic");
}
"""
        root_intervals = compute_test_intervals(root_code)
        self.assertEqual(root_intervals, [(1, 5)], "Root inner attribute with string literals must exclude entire file")

    def test_cfg_comments_safely_handled(self) -> None:
        """Comments in and around test attributes must be safely handled without breaking parsing."""
        from ubs_core.rust_scan import compute_test_intervals, is_test_attr

        # Comments inside cfg predicate
        self.assertTrue(is_test_attr('#[cfg(/* block comment */ all(test, // line comment\n feature = "x"))]'))
        self.assertTrue(is_test_attr('#[/* outer */ test]'))
        self.assertTrue(is_test_attr('#[test /* trailing */]'))
        self.assertTrue(is_test_attr('#[/* outer */ cfg(test)]'))
        self.assertTrue(is_test_attr('#[cfg(test) /* trailing */]'))

        code = """pub fn prod_fn() {}
#[cfg(/* comment */ all(test, // line comment
    feature = "x"
))]
mod tests {
    fn helper() {}
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(2, 7)], "Attribute with comments must be correctly parsed and excluded")

    def test_cfg_recursion_and_token_limits(self) -> None:
        """Adversarial cfg expressions exceeding depth or token limits must fail closed without crashing."""
        from ubs_core.rust_scan import cfg_implies_test

        # Recursion depth exceeds _MAX_CFG_DEPTH (32)
        deep_expr = "all(" * 35 + "test" + ")" * 35
        self.assertFalse(cfg_implies_test(deep_expr), "Deeply nested cfg must fail closed")

        # Token count exceeds _MAX_CFG_TOKENS (256)
        many_tokens = "all(test, " + ", ".join(f'feat_{i} = "v"' for i in range(150)) + ")"
        self.assertFalse(cfg_implies_test(many_tokens), "High token count cfg must fail closed")


class ReceiverMarkerOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("shellcheck"), "real ShellCheck required")
    def test_shellcheck_uses_its_actual_rule_id_and_comment_ownership(self) -> None:
        from ubs_core import bash_scan
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = "bash.shellcheck.SC2086"
        with tempfile.TemporaryDirectory(prefix="shellcheck-marker-", dir=artifacts) as temporary:
            path = Path(temporary) / "case.sh"
            for marker, expected in (("", [3]), ('; marker_note="ubs:ignore"', [3]),
                                     (" # ubs:ignore[unrelated.rule]", [3]),
                                     (f" # ubs:ignore[{rule}]", [])):
                with self.subTest(marker=marker):
                    path.write_text("#!/usr/bin/env bash\nvalue=$1\nprintf '%s\\n' $value" + marker + "\n")
                    sink, errors = StringIO(), []
                    counts = bash_scan.scan_shellcheck([path], sink, set(), set(), errors)
                    self.assertEqual(errors, [])
                    rows = [json.loads(line) for line in sink.getvalue().splitlines()]
                    self.assertEqual([row["line"] for row in rows if row["rule"] == rule], expected)
                    self.assertEqual(counts, {"critical": 0, "warning": 0, "info": len(expected)})

    @unittest.skipUnless(shutil.which("jq") and shutil.which("rg") and shutil.which("ast-grep"),
                         "native UBS dependencies required")
    def test_native_bash_kotlin_cache_json_and_sarif_share_marker_policy(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="native-receiver-marker-", dir=artifacts) as temporary:
            root = Path(temporary)
            for lang, suffix, body, rule, scopes, comment in (
                ("bash", ".sh", 'eval "$command"', "bash.security.eval_variable",
                 "bash.security.eval_variable,bash.security.eval-variable", "#"),
                ("kotlin", ".kt", 'ProcessBuilder("sh", "-c", command)',
                 "kotlin.security.processbuilder-shell", "kotlin.security.processbuilder-shell", "//"),
            ):
                path = root / ("case" + suffix)
                for variant, source, expected in (
                    ("unmarked", body + "\n", [1]),
                    ("quoted", body + '; marker_note="ubs:ignore"\n', [1]),
                    ("wrong-scope", body + f" {comment} ubs:ignore[unrelated.rule]\n", [1]),
                    ("owned", body + f" {comment} ubs:ignore[{scopes}]\n", []),
                    ("previous", f"{comment} ubs:ignore[{scopes}]\n" + body + "\n", []),
                ):
                    path.write_text(source, encoding="utf-8")
                    for fmt in ("json", "sarif"):
                        env = {key: value for key, value in os.environ.items() if not key.startswith("UBS_")}
                        env.update(UBS_NO_AUTO_UPDATE="1", UBS_CACHE_DIR=str(root / f"cache-{lang}-{variant}-{fmt}"),
                                   UBS_PROFILE="1", PYTHONDONTWRITEBYTECODE="1", ENABLE_UV_TOOLS="0")
                        for mode in ("cold", "warm", "disabled"):
                            with self.subTest(lang=lang, marker=variant, format=fmt, cache=mode):
                                run_env = dict(env, UBS_NO_CACHE="1" if mode == "disabled" else "0")
                                command = [str(REPO_ROOT / "modules" / f"ubs-{lang}.sh"),
                                           "--ci", f"--format={fmt}", str(path)]
                                if lang == "bash":
                                    command.insert(1, "--skip=6")
                                proc = subprocess.run(command, cwd=root, env=run_env, capture_output=True,
                                                      text=True, timeout=120)
                                self.assertEqual(proc.returncode, int(bool(expected)), proc.stdout + proc.stderr)
                                report = json.loads(proc.stdout)
                                if fmt == "json":
                                    self.assertEqual(report["status"], "ok", report)
                                    self.assertEqual(report["critical"], len(expected), report)
                                    sites = [row["line"] for row in report["findings"] if row["rule"] == rule]
                                    if mode != "disabled":
                                        self.assertEqual(report["profile"]["cache_hits"], int(mode == "warm"), report)
                                        self.assertEqual(report["profile"]["cache_misses"], int(mode == "cold"), report)
                                else:
                                    sites = [row["locations"][0]["physicalLocation"]["region"]["startLine"]
                                             for run in report["runs"] for row in run.get("results", [])
                                             if row["ruleId"] == rule]
                                self.assertEqual(sites, expected, report)

    def test_bash_and_kotlin_patterns_use_statement_owned_comments(self) -> None:
        from ubs_core import bash_scan, kotlin_scan
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="receiver-marker-", dir=artifacts) as temporary:
            for lang, suffix, body, rule, comment in (
                ("bash", ".sh", 'eval "$command"', "bash.security.eval_variable", "#"),
                ("kotlin", ".kt", 'ProcessBuilder("sh", "-c", command)', "kotlin.security.processbuilder-shell", "//"),
            ):
                path = Path(temporary) / ("case" + suffix)
                for variant, source, expected in (
                    ("unmarked", body + "\n", [1]),
                    ("quoted", body + '; marker_note="ubs:ignore"\n', [1]),
                    ("wrong-scope", body + f" {comment} ubs:ignore[unrelated.rule]\n", [1]),
                    ("owned", body + f" {comment} ubs:ignore[{rule}]\n", []),
                    ("previous", f"{comment} ubs:ignore[{rule}]\n" + body + "\n", []),
                ):
                    with self.subTest(lang=lang, variant=variant):
                        path.write_text(source, encoding="utf-8")
                        sink = StringIO()
                        if lang == "bash":
                            bash_scan.scan_files_native([path], sink, set(), set())
                        else:
                            kotlin_scan.scan_patterns(kotlin_scan._PATTERNS, [path], sink, set())
                        records = [json.loads(line) for line in sink.getvalue().splitlines()]
                        self.assertEqual([record["line"] for record in records if record["rule"] == rule], expected)

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep required")
    def test_real_ast_adapters_preserve_unrelated_rules_and_quoted_markers(self) -> None:
        from ubs_core import js_ast, py_ast, ruby_ast, elixir_ast
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        rule = "ubs.a7.ast-ownership"
        with tempfile.TemporaryDirectory(prefix="ast-marker-", dir=artifacts) as temporary:
            root = Path(temporary)
            rules = root / "rules"
            rules.mkdir()
            config = root / "sgconfig.yml"
            config.write_text("ruleDirs:\n  - rules\n", encoding="utf-8")
            for lang, suffix, body, pattern, comment, adapter in (
                ("javascript", ".js", "eval(input)", "eval($X)", "//", js_ast),
                ("python", ".py", "eval(input)", "eval($X)", "#", py_ast),
                ("ruby", ".rb", "eval(input)", "eval($X)", "#", ruby_ast),
                ("elixir", ".ex", "Code.eval_string(input)", "Code.eval_string($X)", "#", elixir_ast),
            ):
                (rules / "ownership.yml").write_text(
                    f"id: {rule}\nlanguage: {lang}\nseverity: error\nmessage: owned marker oracle\n"
                    f"rule:\n  pattern: {pattern}\n", encoding="utf-8")
                path = root / ("case" + suffix)
                for variant, source, expected in (
                    ("unmarked", body + "\n", [1]),
                    ("quoted", body + '; marker_note="ubs:ignore"\n', [1]),
                    ("wrong-scope", body + f" {comment} ubs:ignore[unrelated.rule]\n", [1]),
                    ("owned", body + f" {comment} ubs:ignore[{rule}]\n", []),
                    ("previous", f"{comment} ubs:ignore[{rule}]\n" + body + "\n", []),
                ):
                    with self.subTest(lang=lang, variant=variant):
                        path.write_text(source, encoding="utf-8")
                        sink, errors = StringIO(), []
                        extra = {"lang": lang} if adapter is js_ast else {}
                        if adapter is ruby_ast:
                            extra["counted_rules"] = {rule}
                        counts = adapter.scan_config(config, [path], sink, errors=errors, **extra)
                        self.assertEqual(errors, [])
                        records = [json.loads(line) for line in sink.getvalue().splitlines()]
                        self.assertEqual([(row["rule"], row["line"]) for row in records],
                                         [(rule, line) for line in expected])
                        self.assertEqual(counts, {"critical": len(expected), "warning": 0, "info": 0})


class StatementBoundaryTests(unittest.TestCase):
    """A marker on one statement never leaks onto the next one."""

    def test_completed_literal_does_not_extend_suppression_to_next_statement(self) -> None:
        cases = (
            ("swift", 'let target = req.query["next"] ?? "/"', "//"),
            ("js", 'const target = req.query.next || "/"', "//"),
            ("python", 'target = request.GET["next"] + ""', "#"),
            ("ruby", "target = params[:next] + ''", "#"),
            ("elixir", 'target = params["next"] <> ""', "#"),
            ("golang", 'target := req.URL.Query().Get("next") + ""', "//"),
            ("kotlin", 'val target = request.getParameter("next") ?: "/"', "//"),
        )
        for lang, assignment, comment in cases:
            for directive in ("ubs:ignore", "ubs:ignore[target.rule]", "noqa"):
                with self.subTest(lang=lang, directive=directive):
                    source = f"{assignment} {comment} {directive}\nunsafe(target)\n"
                    index = build_index(source, lang=lang)
                    self.assertTrue(index.is_suppressed(1, "target.rule"))
                    self.assertFalse(index.is_suppressed(2, "target.rule"))
                    self.assertEqual(index._interval_for(2), Interval(2, 2))

    def test_literal_operand_completes_a_real_continued_statement(self) -> None:
        for lang, first, literal, comment in (
            ("swift", 'let target = req.query["next"] ??', '"/"', "//"),
            ("js", 'const target = request.query.next +', '"/"', "//"),
            ("ruby", "target = params[:next] +", "''", "#"),
            ("python", "target = request.GET['next'] + " + "\\", '""', "#"),
        ):
            with self.subTest(lang=lang):
                source = f"{first}\n    {literal} {comment} ubs:ignore[target.rule]\nunsafe(target)\n"
                index = build_index(source, lang=lang)
                self.assertTrue(index.is_suppressed(1, "target.rule"))
                self.assertTrue(index.is_suppressed(2, "target.rule"))
                self.assertFalse(index.is_suppressed(3, "target.rule"))
                self.assertFalse(index.is_suppressed(1, "other.rule"))

    def test_literal_delimiters_remain_opaque_inside_a_multiline_call(self) -> None:
        for lang, comment in (("swift", "//"), ("js", "//"), ("python", "#")):
            with self.subTest(lang=lang):
                source = ('use(\n    ")]} + else do" ' + comment +
                          ' ubs:ignore[target.rule]\n)\nnext_call()\n')
                index = build_index(source, lang=lang)
                self.assertEqual([line for line in range(1, 5)
                                  if index.is_suppressed(line, "target.rule")], [1, 2, 3])

    def test_identifier_ending_in_keyword_does_not_continue_python(self) -> None:
        code = (
            "def f(password, provided, todo):\n"
            "    expected = todo  # ubs:ignore[python.ctcompare.secret_eq]\n"
            "    return password == provided\n"
            "    pseudo = 1  # ubs:ignore\n"
            "    return password != provided\n"
        )
        index = build_index(code, lang="python")
        self.assertTrue(index.is_suppressed(2, "python.ctcompare.secret_eq"))
        self.assertFalse(index.is_suppressed(3, "python.ctcompare.secret_eq"))
        self.assertFalse(index.is_suppressed(5, "python.ctcompare.secret_eq"))

    def test_ruby_keyword_continuation_still_whole_word(self) -> None:
        code = "x = undo # ubs:ignore[ruby.rule]\nsecret == given\n"
        self.assertFalse(build_index(code, lang="ruby").is_suppressed(2, "ruby.rule"))
        code = "value = if ok then\n  secret == given # ubs:ignore[ruby.rule]\nend\n"
        self.assertTrue(build_index(code, lang="ruby").is_suppressed(1, "ruby.rule"))

    def test_postfix_increment_completes_statement(self) -> None:
        code = "i++ // ubs:ignore[go.rule]\nif token == expected {\n}\nj--\nok := a == b // ubs:ignore[go.rule]\n"
        index = build_index(code, lang="go")
        self.assertFalse(index.is_suppressed(2, "go.rule"))
        self.assertFalse(index.is_suppressed(4, "go.rule"))
        # A dangling binary operator still continues the statement.
        code = "total := a +\n    b // ubs:ignore[go.rule]\n"
        self.assertTrue(build_index(code, lang="go").is_suppressed(1, "go.rule"))


if __name__ == "__main__":
    unittest.main()
