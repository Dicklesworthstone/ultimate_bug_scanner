#!/usr/bin/env python3
"""Unit tests for ubs_core.js_scan — contract-v2 pattern layer (bead 0xjg.4)."""
from __future__ import annotations

import json
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

import re  # noqa: E402

from ubs_core.js_scan import (  # noqa: E402
    Pattern,
    iter_matches,
    load_patterns,
    resolve_severity,
    scan_patterns,
)


def _pat(**overrides) -> Pattern:
    fields = dict(
        category=11,
        rule_id="js.debug.debugger",
        title="debugger statements",
        regex=re.compile(r"\bdebugger\b"),
        thresholds=((0, "critical"),),
    )
    fields.update(overrides)
    return Pattern(**fields)


class ThresholdTests(unittest.TestCase):
    def test_ladder_first_match_wins(self) -> None:
        p = _pat(thresholds=((50, "warning"), (20, "info")))
        self.assertEqual(resolve_severity(p, 51), "warning")
        self.assertEqual(resolve_severity(p, 21), "info")
        self.assertIsNone(resolve_severity(p, 20))  # exclusive: 20 is not > 20

    def test_exact_counts_are_exclusive(self) -> None:
        p = _pat(thresholds=((15, "warning"), (0, "info")))
        self.assertEqual(resolve_severity(p, 16), "warning")
        self.assertEqual(resolve_severity(p, 15), "info")


class MatchTests(unittest.TestCase):
    def test_marker_lines_excluded(self) -> None:
        p = _pat()
        text = "debugger;\ndebugger;  # ubs:ignore\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)

    def test_exclude_regex_drops_lines(self) -> None:
        p = _pat(
            regex=re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*!"),
            exclude_regex=re.compile(r"!=|!=="),
        )
        text = "a!.b;\nif (x !== y) { z!; }\n"
        hits = list(iter_matches(p, text))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 1)


class ScanTests(unittest.TestCase):
    def test_counters_and_sink_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n// TODO: x\n// FIXME: y\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            patterns = [
                _pat(),
                _pat(
                    category=14,
                    rule_id="js.markers.todo-family",
                    title="Technical debt markers",
                    regex=re.compile(r"TODO|FIXME"),
                    thresholds=((0, "info"),),
                ),
            ]
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns(patterns, [src], sink, skip=set())
            self.assertEqual(counters, {"critical": 1, "warning": 0, "info": 2})
            records = [json.loads(line) for line in sink_path.read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["rule"], "js.debug.debugger")
            self.assertEqual(records[0]["severity"], "critical")
            self.assertTrue(all(r["category_id"] for r in records))

    def test_skip_category_silences_patterns(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-jsv2-") as tmp:
            src = Path(tmp) / "s.js"
            src.write_text("debugger;\n", encoding="utf-8")
            sink_path = Path(tmp) / "sink.ndjson"
            with sink_path.open("w", encoding="utf-8") as sink:
                counters = scan_patterns([_pat()], [src], sink, skip={11})
            self.assertEqual(counters["critical"], 0)
            self.assertEqual(sink_path.read_text(), "")


class ExemplarPatternsTests(unittest.TestCase):
    def test_exemplar_module_loads(self) -> None:
        patterns = load_patterns()
        rules = {p.rule_id for p in patterns}
        self.assertIn("js.debug.debugger", rules)
        self.assertIn("js.markers.todo-family", rules)
        self.assertIn("js.typescript.non-null-assertion", rules)


if __name__ == "__main__":
    unittest.main()
