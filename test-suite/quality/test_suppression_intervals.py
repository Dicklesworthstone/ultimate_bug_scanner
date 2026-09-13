#!/usr/bin/env python3
"""Unit tests for ubs_core.suppression — statement-interval index (bead A7)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.csharp_scan import render_text  # noqa: E402
from ubs_core import rust_rules  # noqa: E402
from ubs_core.analyzers import ctcompare_rust  # noqa: E402
from ubs_core.rust_detectors import (  # noqa: E402
    cors_credential, hardcoded_secrets, host_header_url, jwt_verification,
    loop_context, open_redirect, request_regex, request_url, response_header,
    security_randomness, sql_injection, tls_indirect,
)
from ubs_core.suppression import (  # noqa: E402
    build_index, has_suppression_marker, parse_markers,
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
                self.assertEqual(self.lines(detector, fixture(source_marker=" // ubs:ignore")), [])
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


class RustNativeSuppressionTests(unittest.TestCase):
    """Real ast-grep, line fallback, and cache replay must agree on rule scope."""

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
                        ci=True, detail_limit=5, skip="",
                    ), ast_ran=True, patterns=[])
                    samples = [
                        match for line in output.read_text(encoding="utf-8").splitlines()
                        if (match := re.match(r"^\s+(.+):(\d+):", line))
                    ]
                    self.assertEqual(len(samples), 3, "each hit must be suppressible independently")
                    suppressed = []
                    for match in samples:
                        source = Path(match.group(1))
                        self.assertTrue(source.is_absolute())
                        self.assertTrue(source.is_file(), "suppression must resolve the actual source")
                        index = build_index(source.read_text(encoding="utf-8"), lang="csharp")
                        suppressed.append(index.is_suppressed(
                            int(match.group(2)), "cs-process-start",
                        ))
                    self.assertEqual(suppressed, [True, True, False])


if __name__ == "__main__":
    unittest.main()
