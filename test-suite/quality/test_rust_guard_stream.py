#!/usr/bin/env python3
"""Rust narrowing must preserve selected-file evidence in large AST reports."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core import external_tools, rust_scan


class RustGuardStreamTests(unittest.TestCase):
    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="rust-guard-stream-", dir=artifacts))
        self.project = self.root / "project"
        self.project.mkdir()
        self.source = self.project / "source with spaces:\nname.rs"
        self.source.write_text(
            "fn parse(value: Option<u8>) {\n"
            "    if let Some(inner) = value { consume(inner); }\n"
            "    value.unwrap();\n"
            "}\n", encoding="utf-8",
        )
        self.binary = self.root / "verified analyzer"
        environment = patch.dict(os.environ, {
            "UBS_AST_GREP_BIN": str(self.binary), "UBS_KEEP_TEMP": "1",
            "UBS_NO_CACHE": "1", "TMPDIR": str(self.root),
        })
        environment.start()
        self.addCleanup(environment.stop)

    def guard(self, expr: str = "value") -> dict:
        text = self.source.read_text(encoding="utf-8")
        start, end = text.index("if let"), text.index("}\n") + 1
        return {
            "file": str(self.source),
            "range": {"start": {"line": 1, "column": 4},
                      "end": {"line": 1, "column": 47},
                      "byteOffset": {"start": start, "end": end}},
            "text": text[start:end],
            "metaVariables": {"single": {"SOURCE": {"text": expr}}},
        }

    def executable(self, payload: bytes, *, code: int = 0, extra: str = "") -> None:
        # Other patterns have no matches. This also models actual run-mode
        # exit semantics (0 = matches, 1 = no matches).
        self.binary.write_text(
            f"#!{sys.executable}\nimport json, sys\n"
            "if 'Some($BIND)' not in ' '.join(sys.argv):\n    sys.exit(1)\n"
            f"sys.stdout.buffer.write({payload!r})\nsys.stdout.flush()\n"
            + extra + f"\nsys.exit({code})\n", encoding="utf-8",
        )
        self.binary.chmod(0o755)

    @staticmethod
    def payload(*rows) -> bytes:
        return ("\n".join(json.dumps(row) for row in rows) + "\n").encode("utf-8")

    def scan(self) -> rust_scan.Scan:
        return rust_scan.Scan([self.source], self.project, False, set(), 3)

    def test_guard_ingestion_has_no_total_output_cap_and_keeps_last_finding(self) -> None:
        # Match bodies can dominate a real ast-grep report. Only the final
        # match here refers to the source that is unwrapped after its guard.
        row = self.guard("unrelated")
        row["metaVariables"]["single"]["BODY"] = {"text": "x" * 16384}
        count = 1200
        self.assertGreater(len(self.payload(row)) * count, 16 * 1024 * 1024)
        self.executable(b"", extra=(
            f"row = {row!r}\n"
            f"for _ in range({count - 1}):\n"
            "    sys.stdout.write(json.dumps(row) + '\\n')\n"
            "row['metaVariables']['single']['SOURCE']['text'] = 'value'\n"
            "sys.stdout.write(json.dumps(row) + '\\n')\n"
        ))
        tracemalloc.start()
        try:
            result, incomplete = rust_scan._emit_guard_matches([self.source])
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertFalse(incomplete)
        self.assertIsNotNone(result)
        self.assertGreater(result.stat().st_size, 16 * 1024 * 1024)
        with result.open(encoding="utf-8") as stream:
            self.assertEqual(sum(1 for _ in stream), count)
        self.assertLess(peak, 4 * 1024 * 1024, f"ingestion retained {peak} bytes")

        # Exercise the native producer, including its final JSON and NDJSON
        # contracts, rather than stopping at a parser-only assertion.
        files, sink, summary = self.root / "files", self.root / "sink.jsonl", self.root / "summary.json"
        files.write_bytes(os.fsencode(self.source) + b"\0")
        environment = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), UBS_NO_CACHE="1")
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "ubs_core.rust_scan", "--files-from", str(files),
             "--project-dir", str(self.project), "--sink", str(sink), "--json-out", str(summary),
             "--skip", ",".join(str(n) for n in range(2, 25))],
            cwd=REPO_ROOT, env=environment, capture_output=True, text=True, timeout=60,
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        document = json.loads(summary.read_text(encoding="utf-8"))
        findings = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
        guards = [entry for entry in findings if entry.get("rule") == "rust.ownership.guarded-later-unwrap"]
        self.assertEqual(len(guards), 1, (document, findings, proc.stderr))
        self.assertEqual((guards[0]["path"], guards[0]["line"], guards[0]["col"]),
                         (str(self.source), 3, 5))
        self.assertFalse(any(entry.get("rule") == "ubs.scan.incomplete" for entry in findings), findings)
        self.assertEqual(document["status"], "ok", document)

    def test_stream_receives_exact_files_in_bounded_batches(self) -> None:
        arguments = self.root / "arguments.jsonl"
        self.binary.write_text(
            f"#!{sys.executable}\nimport json, sys\n"
            f"with open({str(arguments)!r}, 'a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "sys.exit(1)\n", encoding="utf-8",
        )
        self.binary.chmod(0o755)
        paths = [self.source, *(self.project / f"file-{n}.rs" for n in range(400))]
        result, incomplete = rust_scan._emit_guard_matches(paths)
        self.assertFalse(incomplete)
        self.assertEqual(result.read_text(), "")
        calls = [json.loads(line) for line in arguments.read_text().splitlines()]
        self.assertEqual(len(calls), 4)
        for offset in (0, 2):
            received = []
            for call in calls[offset:offset + 2]:
                self.assertIn("--json=stream", call)
                selected = call[call.index("--") + 1:]
                self.assertLessEqual(len(selected), 400)
                self.assertNotIn(str(self.project), selected)
                received.extend(selected)
            self.assertEqual(received, [str(path) for path in paths])

    def test_malformed_guard_reports_force_complete_selected_file_fallback(self) -> None:
        valid = self.guard("unrelated")
        bad_range = copy.deepcopy(self.guard())
        bad_range["range"]["byteOffset"]["end"] = "broken"
        bad_capture = copy.deepcopy(self.guard())
        bad_capture["metaVariables"]["single"]["SOURCE"]["text"] = []
        missing_capture = copy.deepcopy(self.guard())
        missing_capture.pop("metaVariables")
        cases = (
            (self.payload(valid) + b"{truncated\n", 0, ""),
            (self.payload(valid) + b"\xff\n", 0, ""),
            (self.payload(valid, bad_range), 0, ""),
            (self.payload(valid, bad_capture), 0, ""),
            (self.payload(valid, missing_capture), 0, ""),
            (self.payload(valid), 2, ""),
            (self.payload(valid), 1, ""),
            (b"", 0, ""),
            (self.payload(valid), 0, "sys.stderr.write('ERROR: source could not be read\\n')"),
        )
        for payload, code, extra in cases:
            with self.subTest(payload=payload[-100:], code=code, extra=extra):
                self.executable(payload, code=code, extra=extra)
                _, incomplete = rust_scan._emit_guard_matches([self.source])
                self.assertTrue(incomplete)
                hits = rust_scan.run_narrowing(self.scan(), False)
                self.assertEqual([(hit.line, hit.col) for hit in hits], [(3, 5)])

    def test_oversized_record_preserves_later_matches_and_triggers_fallback(self) -> None:
        row = self.guard()
        oversized = copy.deepcopy(row)
        oversized["text"] = "x" * 4096
        self.executable(self.payload(oversized, row))
        with patch.object(external_tools, "OUTPUT_RECORD_LIMIT", 2048):
            result, incomplete = rust_scan._emit_guard_matches([self.source])
        self.assertTrue(incomplete)
        records = [json.loads(line) for line in result.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["text"], row["text"])

    def test_empty_and_failed_streams_never_rewalk_excluded_files(self) -> None:
        excluded = self.project / "excluded.rs"
        excluded.write_text(self.source.read_text(), encoding="utf-8")
        from ubs_core.analyzers import narrowing_rust
        original = narrowing_rust.analyze_file_regex
        for code in (1, 2):
            with self.subTest(code=code):
                self.executable(b"", code=code)
                with patch.object(narrowing_rust, "analyze_file_regex", wraps=original) as fallback:
                    hits = rust_scan.run_narrowing(self.scan(), False)
                self.assertEqual([call.args[0] for call in fallback.call_args_list], [self.source])
                self.assertEqual([(hit.path, hit.line) for hit in hits], [(str(self.source), 3)])

    def test_verified_override_is_authoritative_over_cached_probe(self) -> None:
        with patch.object(rust_scan, "_AST_GREP_CACHE", "ambient-unverified-binary"):
            self.assertEqual(rust_scan._ast_grep_bin(), str(self.binary))
            # A missing configured binary is an attempted failed scan. Do not
            # silently fall back to another executable on PATH.
            result, incomplete = rust_scan._emit_guard_matches([self.source])
        self.assertIsNotNone(result)
        self.assertTrue(incomplete)

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep required")
    def test_real_stream_retains_guard_narrowing_and_unusual_filename(self) -> None:
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": shutil.which("ast-grep")}):
            result, incomplete = rust_scan._emit_guard_matches([self.source])
            self.assertFalse(incomplete, result.read_text())
            records = [json.loads(line) for line in result.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["metaVariables"]["single"]["SOURCE"]["text"], "value")
            hits = rust_scan.run_narrowing(self.scan(), False)
        self.assertEqual([(hit.path, hit.line, hit.col) for hit in hits], [(str(self.source), 3, 5)])


if __name__ == "__main__":
    unittest.main()
