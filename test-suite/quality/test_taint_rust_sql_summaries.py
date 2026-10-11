#!/usr/bin/env python3
"""Regression tests for interprocedural Rust SQL taint summaries."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))

from ubs_core.rust_detectors import sql_injection


class RustSqlSummaryTests(unittest.TestCase):
    def findings(self, source: str):
        with tempfile.TemporaryDirectory(prefix="ubs-rust-sql-summary-") as temp:
            target = Path(temp) / "main.rs"
            target.write_text(source, encoding="utf-8")
            return list(sql_injection.find([target]))

    def test_helper_return_propagates_dirty_sql(self):
        findings = self.findings(r'''
fn build(user: &str) -> String {
    format!("SELECT * FROM users WHERE name = '{user}'")
}

fn handler(params: Params, db: Db) {
    let user = params.get("user").unwrap_or_default();
    let query = build(user);
    db.execute(&query);
}
''')
        self.assertEqual(len(findings), 1)
        self.assertIn("build()", findings[0][3])
        self.assertIn("SQL execution", findings[0][3])

    def test_two_hop_return_summary_reaches_sink(self):
        findings = self.findings(r'''
fn build(user: &str) -> String {
    format!("SELECT * FROM users WHERE name = '{user}'")
}
fn wrap(user: &str) -> String {
    build(user)
}
fn handler(params: Params, db: Db) {
    let user = params.get("user").unwrap_or_default();
    let query = wrap(user);
    db.execute(&query);
}
''')
        self.assertEqual(len(findings), 1)
        self.assertIn("wrap()", findings[0][3])

    def test_sink_wrapper_propagates_parameter_effect(self):
        findings = self.findings(r'''
fn run_query(db: &Db, query: &str) {
    db.execute(query);
}
fn handler(params: Params, db: Db) {
    let user = params.get("user").unwrap_or_default();
    let query = format!("SELECT * FROM users WHERE name = '{user}'");
    run_query(&db, &query);
}
''')
        self.assertEqual(len(findings), 1)
        self.assertIn("run_query() SQL execution", findings[0][3])

    def test_static_query_through_wrapper_is_clean(self):
        findings = self.findings(r'''
fn run_query(db: &Db, query: &str) {
    db.execute(query);
}
fn handler(db: Db) {
    let query = "SELECT id FROM users WHERE active = true";
    run_query(&db, query);
}
''')
        self.assertEqual(findings, [])

    def test_bound_parameter_is_not_promoted_to_query_text(self):
        findings = self.findings(r'''
fn run_query(db: &Db, query: &str, user: &str) {
    db.query(query, &[user]);
}
fn handler(params: Params, db: Db) {
    let user = params.get("user").unwrap_or_default();
    run_query(&db, "SELECT * FROM users WHERE name = $1", user);
}
''')
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
