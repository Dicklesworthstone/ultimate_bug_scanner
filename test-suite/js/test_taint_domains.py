"""D6 regressions: sanitizer effects are local to one value and sink domain."""
from __future__ import annotations

from collections import Counter
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


class JavaScriptTaintDomainTests(unittest.TestCase):
    def findings(self, body: str):
        with tempfile.TemporaryDirectory(prefix="ubs-js-domain-") as scratch:
            path = Path(scratch) / "handler.js"
            path.write_text(body + "\n", encoding="utf-8")
            return list(taint_js.run(RunContext(lang="javascript", files=[path])))

    def assert_rules(self, body: str, *rules: str):
        findings = self.findings(body)
        self.assertEqual(Counter(f["rule"] for f in findings),
                         Counter("javascript.taint." + rule for rule in rules), findings)
        for finding in findings:
            self.assertGreater(finding["line"], 0)
            self.assertGreater(finding["col"], 0)
            self.assertEqual(finding["severity"], "critical")
            self.assertIn(" -> ", finding["message"])
        return findings

    def test_html_escape_does_not_sanitize_other_sink_domains(self):
        for sink, rule in (("eval", "eval"), ("db.query", "sql"), ("shell.exec", "command")):
            with self.subTest(sink=sink):
                self.assert_rules(f"{sink}(DOMPurify.sanitize(req.query.value));", rule)

    def test_sql_escape_does_not_sanitize_html_or_eval(self):
        self.assert_rules("res.send(db.escape(req.query.value));", "xss")
        self.assert_rules("eval(mysql.escape(req.query.value));", "eval")

    def test_shell_escape_does_not_sanitize_html_or_sql(self):
        self.assert_rules("res.send(shellescape(req.query.value));", "xss")
        self.assert_rules("db.query(shellescape(req.query.value));", "sql")

    def test_unproven_sanitizer_names_do_not_erase_taint(self):
        for name in ("sanitizeInput", "sanitizeUrl", "encodeURIComponent", "stripTags"):
            with self.subTest(name=name):
                self.assert_rules(f"eval({name}(req.query.value));", "eval")

    def test_sanitizer_must_be_called_not_merely_mentioned(self):
        self.assert_rules("res.send(DOMPurify.sanitize + req.query.value);", "xss")
        self.assert_rules("res.send(fakeDOMPurify.sanitize(req.query.value));", "xss")
        self.assert_rules("res.send(wrapper.DOMPurify.sanitize(req.query.value));", "xss")

    def test_unsanitized_sibling_survives_direct_sanitizer(self):
        self.assert_rules("res.send(DOMPurify.sanitize(req.query.safe) + req.query.raw);", "xss")
        self.assert_rules("res.send(req.query.raw + DOMPurify.sanitize(req.query.safe));", "xss")

    def test_unsanitized_sibling_survives_assignment(self):
        self.assert_rules("const raw = req.query.raw;\n"
                          "const mixed = DOMPurify.sanitize(raw) + raw;\n"
                          "res.send(mixed);", "xss")

    def test_sanitized_source_assignment_is_clean_in_its_domain(self):
        self.assert_rules("const clean = DOMPurify.sanitize(req.query.value);\n"
                          "res.send(clean);")

    def test_sanitizer_effect_propagates_only_in_its_domain(self):
        self.assert_rules("const raw = req.query.value;\n"
                          "const clean = DOMPurify.sanitize(raw);\n"
                          "const alias = clean;\n"
                          "res.send(alias);\n"
                          "eval(alias);\n"
                          "db.query(alias);\n"
                          "shell.exec(alias);", "eval", "sql", "command")

    def test_nested_sanitizer_calls_preserve_clean_html(self):
        self.assert_rules("res.send(DOMPurify.sanitize(transform(req.query.value)));")
        self.assert_rules("res.send(DOMPurify.sanitize(req.query.a) + escapeHtml(req.query.b));")

    def test_recognized_domain_specific_calls_remain_clean(self):
        self.assert_rules("db.query(mysql.escape(req.query.value));")
        self.assert_rules("shell.exec(shellescape(req.query.value));")
        self.assert_rules("res.send(he.escape(req.query.value));")

    def test_bound_values_do_not_sanitize_dynamic_query(self):
        for bindings in ("[req.query.id]", "params", "values", "bindings", "[]"):
            with self.subTest(bindings=bindings):
                self.assert_rules(f"db.query(req.query.sql, {bindings});", "sql")

    def test_bound_values_do_not_sanitize_propagated_query(self):
        self.assert_rules("const sql = req.query.sql;\n"
                          "db.query(sql, [req.query.id]);", "sql")

    def test_bound_values_in_static_query_are_not_query_taint(self):
        self.assert_rules("db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);")
        self.assert_rules("const value = req.query.id;\n"
                          "db.query('SELECT * FROM users WHERE id = ?', [value]);")

    def test_first_query_argument_respects_nested_delimiters(self):
        self.assert_rules("db.query(format(req.query.sql, [1, 2]), [3]);", "sql")
        self.assert_rules("db.query(makeQuery({a: [1, 2]}), [req.query.id]);")

    def test_child_process_aliases_use_domain_specific_sanitizers(self):
        self.assert_rules("const { exec: run } = require('node:child_process');\n"
                          "run(DOMPurify.sanitize(req.query.command));", "command")
        self.assert_rules("const { exec: run } = require('node:child_process');\n"
                          "run(shellescape(req.query.command));")

    def test_legacy_and_structured_entrypoints_agree(self):
        source = "\n".join("eval(DOMPurify.sanitize(req.query.value));" for _ in range(5))
        with tempfile.TemporaryDirectory(prefix="ubs-js-domain-parity-") as scratch:
            path = Path(scratch) / "handler.js"
            path.write_text(source + "\n", encoding="utf-8")
            findings = list(taint_js.run(RunContext(lang="javascript", files=[path])))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(taint_js.main(["taint_js", scratch]), 0)
            fields = output.getvalue().strip().split("\t")
            self.assertEqual(fields[:2], ["js.taint.eval", "5"])
            self.assertEqual(len(findings), 5)
            self.assertEqual(len(fields[2].split(",")), 3)

    def test_existing_selftests(self):
        for name, test in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                test()


if __name__ == "__main__":
    unittest.main(verbosity=2)
