#!/usr/bin/env python3
"""A property name that equals a tainted variable is not a read of it (GH #146).

After `const { email } = req.body`, `user.email`, `user?.email` and the key in
`{ email: ... }` name properties, not the tainted local. Shorthand, a same-named
key whose value is the local, spread, a ternary branch and a template
interpolation are real reads and must still reach the sink.
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
    "const app = express();\n"
    'app.post("/x", (req, res) => {\n'
    "  const { email } = req.body;\n"
    "  const flag = Math.random() > 0.5;\n"
    "  const user = lookup();\n"
    "  {body}\n"
    "});\n"
)
SINK_LINE = 7

PROPERTY_NAMES = {
    "member access": "res.send(user.email);",
    "optional member access": "res.send(user?.email);",
    "object key in a propagated value": (
        "const token = sign({ id: user.id, email: user.email }); res.send(token);"
    ),
    "object key at the sink": 'res.send({ email: "hidden" });',
}
REFERENCES = {
    "direct": "res.send(email);",
    "shorthand property": "res.send({ email });",
    "same-named key with the tainted value": "res.send({ email: email });",
    "spread": "res.send({ ...{ email } });",
    "ternary branch": 'res.send(flag ? email : "x");',
    "template interpolation": "res.send(`<p>${email}</p>`);",
}


class PropertyNameTaintTests(unittest.TestCase):
    def findings(self, body: str) -> list[tuple[str, int]]:
        with tempfile.TemporaryDirectory(prefix="taint-js-names-") as tmp:
            path = Path(tmp) / "handler.js"
            path.write_text(HANDLER.replace("{body}", body), encoding="utf-8")
            return [(f["rule"], f["line"]) for f in taint_js.run(RunContext(lang="javascript", files=[path]))]

    def test_property_names_do_not_carry_taint(self) -> None:
        for label, body in PROPERTY_NAMES.items():
            with self.subTest(label):
                self.assertEqual(self.findings(body), [])

    def test_real_references_still_reach_the_sink(self) -> None:
        for label, body in REFERENCES.items():
            with self.subTest(label):
                self.assertEqual(self.findings(body), [("javascript.taint.xss", SINK_LINE)])


if __name__ == "__main__":
    unittest.main()
