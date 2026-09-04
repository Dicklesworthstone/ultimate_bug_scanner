#!/usr/bin/env python3
"""Unit tests for ubs_core.suppression — statement-interval index (bead A7)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.suppression import build_index, parse_markers  # noqa: E402

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
        # `os.system(` opens on line 16; the marker sits on line 17, a
        # physical line of the same logical statement.
        self.assertTrue(self.idx.is_suppressed(16, "py.taint"))

    def test_formatter_moved_marker(self) -> None:
        # `if event:` opens the block at line 24; the marker was relocated to
        # line 25, the first line inside the block.
        self.assertTrue(self.idx.is_suppressed(24, "py.taint"))

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


if __name__ == "__main__":
    unittest.main()
