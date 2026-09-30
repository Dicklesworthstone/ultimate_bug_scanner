#!/usr/bin/env python3
"""Values whose kind cannot carry an injection stay quiet (js-node-clean).

A global numeric conversion (parseInt, parseFloat, Number, Math.*) returns a
number; rows returned by a SQL call come from the database, not from its
bound parameters; and res.json() sends JSON, not HTML. Each is checked
against a control that must still report, and a same-named local function
is not mistaken for the global.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import taint_js  # noqa: E402
from ubs_core.registry import RunContext  # noqa: E402

HANDLER = (
    'const express = require("express");\n'
    'const { Pool } = require("pg");\n'
    "const pool = new Pool();\n"
    "const app = express();\n"
    'app.get("/x", async (req, res) => {\n'
    "{body}\n"
    "});\n"
)

QUIET = {
    "parseInt": "  const n = parseInt(req.query.page, 10);\n  res.send(`<p>${n}</p>`);",
    "parseFloat": "  res.send(String(parseFloat(req.query.x)));",
    "Number": "  const n = Number(req.body.count);\n  res.send(`${n}`);",
    "Number.parseInt": "  res.send(`${Number.parseInt(req.query.n, 10)}`);",
    "Math.min over parseInt": (
        "  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);\n"
        "  res.send(`${limit}`);"
    ),
    "parameterized query rows": (
        '  const { rows } = await pool.query("SELECT name FROM u WHERE id = $1", [req.params.id]);\n'
        "  res.send(`<p>${rows[0].name}</p>`);"
    ),
    "res.json": "  res.json({ echo: req.query.q });",
}

REPORTED = {
    "unconverted value": ("  const n = req.query.page;\n  res.send(`<p>${n}</p>`);", "js.taint.xss"),
    "local function named parseInt": (
        "  function parseInt(value) { return value; }\n"
        "  res.send(`<p>${parseInt(req.query.page)}</p>`);",
        "js.taint.xss",
    ),
    "member named parseInt": ("  res.send(helpers.parseInt(req.query.page));", "js.taint.xss"),
    "concatenated query": (
        '  const { rows } = await pool.query("SELECT * FROM u WHERE id = " + req.params.id);\n'
        "  res.send(rows.length ? \"ok\" : \"none\");",
        "js.taint.sql",
    ),
    "res.send": ("  res.send(req.query.q);", "js.taint.xss"),
}


class ValueKindTaintTests(unittest.TestCase):
    def rules(self, body: str) -> set[str]:
        with tempfile.TemporaryDirectory(prefix="taint-js-kinds-") as tmp:
            path = Path(tmp) / "handler.js"
            path.write_text(HANDLER.replace("{body}", body), encoding="utf-8")
            return {f["rule"] for f in taint_js.run(RunContext(lang="javascript", files=[path]))}

    def test_values_that_cannot_inject_are_not_reported(self) -> None:
        for name, body in QUIET.items():
            with self.subTest(name):
                self.assertEqual(self.rules(body), set())

    def test_controls_still_report(self) -> None:
        for name, (body, rule) in REPORTED.items():
            with self.subTest(name):
                self.assertIn(rule, {r.replace("javascript.taint.", "js.taint.") for r in self.rules(body)})


if __name__ == "__main__":
    unittest.main()
