#!/usr/bin/env python3
"""Unit tests for ubs_core stdlib helper library (bead A2)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import (
    extract_statement_region,
    find_block_end,
    format_location,
    line_col,
    skip_ws,
)
from ubs_core.lexer import (
    Interval,
    Span,
    strip_comments_and_strings,
)


class UbsCoreIoTests(unittest.TestCase):
    def test_line_col_basic(self) -> None:
        text = "hello\nworld\nfoo bar"
        self.assertEqual(line_col(text, 0), (1, 1))
        self.assertEqual(line_col(text, 4), (1, 5))
        self.assertEqual(line_col(text, 5), (1, 6))  # \n
        self.assertEqual(line_col(text, 6), (2, 1))  # 'w'
        self.assertEqual(line_col(text, 12), (3, 1))  # 'f'
        self.assertEqual(line_col(text, 16), (3, 5))  # 'b'

    def test_line_col_bounds(self) -> None:
        text = "abc"
        self.assertEqual(line_col(text, -5), (1, 1))
        self.assertEqual(line_col(text, 100), (1, 4))
        self.assertEqual(line_col("", 0), (1, 1))

    def test_format_location(self) -> None:
        base = Path("/repo")
        path = Path("/repo/src/main.rs")
        text = "fn main() {\n    println!();\n}"
        loc = format_location(base, path, 16, text)
        self.assertEqual(loc, "src/main.rs:2:5")

    def test_format_location_external_path(self) -> None:
        base = Path("/repo")
        path = Path("/tmp/other.rs")
        text = "fn test() {}"
        loc = format_location(base, path, 3, text)
        self.assertEqual(loc, "/tmp/other.rs:1:4")

    def test_find_block_end_nested(self) -> None:
        text = "{ if (true) { a = 1; } return a; }"
        end = find_block_end(text, 0)
        self.assertEqual(end, len(text) - 1)
        self.assertEqual(text[end], "}")

        inner_start = text.find("{", 1)
        inner_end = find_block_end(text, inner_start)
        self.assertEqual(text[inner_start : inner_end + 1], "{ a = 1; }")

    def test_find_block_end_custom_delimiters(self) -> None:
        text = "(1 + (2 * 3))"
        end = find_block_end(text, 0, open_char="(", close_char=")")
        self.assertEqual(end, len(text) - 1)

    def test_find_block_end_unbalanced(self) -> None:
        text = "{ unclosed"
        end = find_block_end(text, 0)
        self.assertEqual(end, len(text) - 1)

    def test_skip_ws(self) -> None:
        text = "   \t\n  hello"
        idx = skip_ws(text, 0)
        self.assertEqual(idx, 7)
        self.assertEqual(text[idx:], "hello")

    def test_extract_statement_region(self) -> None:
        text = "  { a = 1; b = 2; }  int c = 3;  int d = 4;"
        reg, nxt = extract_statement_region(text, 0)
        self.assertEqual(reg, "{ a = 1; b = 2; }")

        reg2, nxt2 = extract_statement_region(text, nxt)
        self.assertEqual(reg2, "int c = 3;")

        reg3, nxt3 = extract_statement_region(text, nxt2)
        self.assertEqual(reg3, "int d = 4;")


class UbsCoreLexerTests(unittest.TestCase):
    def test_span_and_interval(self) -> None:
        s1 = Span(10, 20)
        self.assertEqual(s1.length, 10)
        self.assertTrue(s1.contains(10))
        self.assertTrue(s1.contains(15))
        self.assertFalse(s1.contains(20))

        s2 = Span(15, 25)
        s3 = Span(20, 30)
        self.assertTrue(s1.overlaps(s2))
        self.assertFalse(s1.overlaps(s3))

        iv = Interval(10, 20, {"kind": "lock"})
        self.assertEqual(iv.span, s1)
        self.assertTrue(iv.contains(12))
        self.assertTrue(iv.overlaps(s2))

    def test_strip_comments_and_strings_c_like(self) -> None:
        code = (
            '// Single line comment\n'
            'int x = 42; /* block comment */\n'
            'char* msg = "hello \\"world\\"";\n'
            'char c = \'z\';\n'
        )
        stripped = strip_comments_and_strings(code, lang="c_like")
        self.assertEqual(len(stripped), len(code))
        self.assertEqual(stripped.count("\n"), code.count("\n"))
        self.assertNotIn("Single line comment", stripped)
        self.assertNotIn("block comment", stripped)
        self.assertNotIn("hello", stripped)
        self.assertIn("int x = 42;", stripped)

    def test_strip_comments_and_strings_swift(self) -> None:
        code = (
            '// Swift line comment\n'
            'let greeting = "Hello Swift"\n'
            '/* multi-line comment */\n'
        )
        stripped = strip_comments_and_strings(code, lang="swift")
        self.assertEqual(len(stripped), len(code))
        self.assertNotIn("Swift line comment", stripped)
        self.assertNotIn("Hello Swift", stripped)
        self.assertIn("let greeting =", stripped)

    def test_strip_comments_and_strings_hash_langs(self) -> None:
        code = (
            '# Python comment\n'
            'name = "Alice"\n'
            'doc = """multi\n'
            'line\n'
            'docstring"""\n'
            'active = True\n'
        )
        stripped = strip_comments_and_strings(code, lang="python")
        self.assertEqual(len(stripped), len(code))
        self.assertEqual(stripped.count("\n"), code.count("\n"))
        self.assertNotIn("Python comment", stripped)
        self.assertNotIn("Alice", stripped)
        self.assertNotIn("docstring", stripped)
        self.assertIn("name =", stripped)
        self.assertIn("active = True", stripped)


if __name__ == "__main__":
    unittest.main()
