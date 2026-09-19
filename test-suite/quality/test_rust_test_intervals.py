#!/usr/bin/env python3
"""Unit tests for Rust precise test interval computation and test-line filtering."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.rust_scan import (  # noqa: E402
    Scan,
    TestScopeIndex,
    compute_test_intervals,
    is_test_attr,
)


class TestIsTestAttr(unittest.TestCase):
    def test_runner_attributes(self):
        self.assertTrue(is_test_attr("#[test]"))
        self.assertTrue(is_test_attr("#[tokio::test]"))
        self.assertTrue(is_test_attr("#[tokio::test(flavor = \"multi_thread\")]"))
        self.assertTrue(is_test_attr("#[asupersync::test]"))
        self.assertTrue(is_test_attr("#[rstest]"))
        self.assertTrue(is_test_attr("#[rstest::rstest]"))
        self.assertTrue(is_test_attr("#[quickcheck]"))
        self.assertTrue(is_test_attr("#[test_case(1, 2)]"))
        self.assertTrue(is_test_attr("#[wasm_bindgen_test]"))

    def test_cfg_test_attributes(self):
        self.assertTrue(is_test_attr("#[cfg(test)]"))
        self.assertTrue(is_test_attr("#[cfg(all(unix, test))]"))
        self.assertTrue(is_test_attr("#[cfg(any(test, feature = \"mock\"))]"))

    def test_negative_attributes(self):
        # Production-only code with cfg(not(test))
        self.assertFalse(is_test_attr("#[cfg(not(test))]"))
        self.assertFalse(is_test_attr("#[cfg(all(unix, not(test)))]"))
        # Feature name containing "test"
        self.assertFalse(is_test_attr("#[cfg(feature = \"testing\")]"))
        self.assertFalse(is_test_attr("#[cfg(feature = \"test-helpers\")]"))
        # Standard non-test attributes
        self.assertFalse(is_test_attr("#[derive(Clone, Debug)]"))
        self.assertFalse(is_test_attr("#[inline]"))
        self.assertFalse(is_test_attr("#[allow(unused)]"))
        self.assertFalse(is_test_attr("#[must_use]"))


class TestComputeTestIntervals(unittest.TestCase):
    def test_file_level_inner_attribute(self):
        code = """#![cfg(test)]

pub fn helper() {
    panic!("helper panic");
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(1, 5)])

    def test_bare_mod_tests(self):
        code = """pub fn prod() {
    let x = 1;
}

mod tests {
    fn test_one() {
        panic!("test");
    }
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(5, 9)])

    def test_bare_mod_test_singular(self):
        code = """pub(crate) mod test {
    fn test_one() {}
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(1, 3)])

    def test_reject_module_name_contains_test_authority(self):
        """CRITICAL: mod test_parser must remain scanned unless cfg(test)."""
        code = """mod test_parser {
    pub fn parse() {
        panic!("prod error");
    }
}

pub mod fast_test_runner {
    pub fn run() {}
}

mod testing_utils {
    pub fn util() {}
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [], "Production modules containing 'test' must not be excluded!")

    def test_early_cfg_test_import(self):
        """Early #[cfg(test)] use ...; must NOT exclude subsequent production code."""
        code = """// Line 1
// Line 2
#[cfg(test)]
use std::collections::HashMap;

// Line 6
pub fn prod_function() {
    panic!("prod panic");
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(3, 4)])

    def test_interleaved_test_module(self):
        """Interleaved #[cfg(test)] mod only excludes within the module."""
        code = """pub struct BeforeProd {
    pub a: u32,
}

#[cfg(test)]
mod alphabet_test {
    #[test]
    fn test_alpha() {
        panic!("alpha test");
    }
}

pub struct QuickSelectOverlay {
    pub b: u32,
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(5, 11)])

    def test_array_param_semicolon_not_premature_terminator(self):
        """Semicolon in [u8; 32] parameter must not terminate item before opening brace."""
        code = """#[test]
fn test_array_param(buffer: [u8; 32]) {
    panic!("in test");
}

pub fn prod() {
    panic!("in prod");
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(1, 4)])

    def test_strings_and_comments_with_braces(self):
        """Braces inside strings and comments must not corrupt block boundaries."""
        code = """#[cfg(test)]
fn test_with_braces() {
    let s = "{ not a real brace }";
    let raw = r#"{"json": true}"#;
    /* { block comment } */
    // { line comment
}

pub fn prod() {}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(1, 7)])

    def test_unclosed_brace_conservative_failure(self):
        """Malformed/unclosed braces must fail conservatively and NEVER blind to EOF."""
        code = """#[cfg(test)]
mod broken {
    fn unclosed() {
        // missing closing braces
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [], "Unclosed braces must fail conservatively without blinding to EOF")

    def test_single_item_inside_function(self):
        """#[cfg(test)] decorating an if-statement inside a production function."""
        code = """fn prod_func() {
    let mut x = 1;
    #[cfg(test)]
    if x > 0 {
        panic!("test verification");
    }
    x += 1;
}
"""
        intervals = compute_test_intervals(code)
        self.assertEqual(intervals, [(3, 6)])


class TestTestScopeIndex(unittest.TestCase):
    def test_binary_search_index(self):
        index = TestScopeIndex([(10, 20), (30, 40)])
        self.assertFalse(index.contains(9))
        self.assertTrue(index.contains(10))
        self.assertTrue(index.contains(15))
        self.assertTrue(index.contains(20))
        self.assertFalse(index.contains(21))
        self.assertFalse(index.contains(29))
        self.assertTrue(index.contains(30))
        self.assertTrue(index.contains(35))
        self.assertTrue(index.contains(40))
        self.assertFalse(index.contains(41))

    def test_empty_index(self):
        index = TestScopeIndex([])
        self.assertFalse(index.contains(1))
        self.assertFalse(index.contains(100))


class TestScanFiltering(unittest.TestCase):
    def test_scan_is_test_line_integration(self):
        code = """// Line 1: prod
#[cfg(test)]
use std::collections::HashMap; // Line 3-4

pub fn prod_func() { // Line 6
    panic!("prod"); // Line 7
}

#[cfg(test)]
mod tests { // Line 11
    #[test]
    fn t1() { // Line 13
        panic!("test"); // Line 14
    }
} // Line 16
"""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(code)
            tmp_path = Path(f.name)

        try:
            # Without exclude_tests: nothing is excluded
            scan_no_ex = Scan([tmp_path], tmp_path.parent, exclude_tests=False, skip=set(), detail_limit=10)
            self.assertFalse(scan_no_ex._is_test_line(str(tmp_path), 2))
            self.assertFalse(scan_no_ex._is_test_line(str(tmp_path), 3))
            self.assertFalse(scan_no_ex._is_test_line(str(tmp_path), 6))
            self.assertFalse(scan_no_ex._is_test_line(str(tmp_path), 13))

            # With exclude_tests: lines in test intervals are excluded, production lines remain
            scan_ex = Scan([tmp_path], tmp_path.parent, exclude_tests=True, skip=set(), detail_limit=10)
            self.assertTrue(scan_ex._is_test_line(str(tmp_path), 2))  # #[cfg(test)]
            self.assertTrue(scan_ex._is_test_line(str(tmp_path), 3))  # use ...;
            self.assertFalse(scan_ex._is_test_line(str(tmp_path), 5)) # pub fn prod_func()
            self.assertFalse(scan_ex._is_test_line(str(tmp_path), 6)) # panic!("prod");
            self.assertTrue(scan_ex._is_test_line(str(tmp_path), 10)) # mod tests
            self.assertTrue(scan_ex._is_test_line(str(tmp_path), 13)) # panic!("test");
            self.assertTrue(scan_ex._is_test_line(str(tmp_path), 15)) # closing }
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
