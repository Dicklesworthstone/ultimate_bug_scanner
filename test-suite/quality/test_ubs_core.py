#!/usr/bin/env python3
"""Unit tests for ubs_core stdlib helper library (bead A2)."""
from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tempfile
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


class StructuredSourceIdentityTests(unittest.TestCase):
    def test_real_analyzers_keep_same_basename_sources_distinct(self) -> None:
        from ubs_core.registry import RunContext

        cases = (
            ("taint_py", "python", ".py", "python.taint.eval", 1,
             "value = eval(input())\n"),  # ubs:ignore[python.taint.eval] - literal unsafe source consumed by the real analyzer, never evaluated
            ("async_foreach", "js", ".js", "js.async.foreach", 1,
             "items.forEach(async (item) => { await consume(item); });\n"),
            ("taint_go", "go", ".go", "go.taint.xss", 4,
             "package main\nfunc handler(w http.ResponseWriter, r *http.Request) {\n"
             "  name := r.FormValue(\"name\")\n  fmt.Fprintf(w, \"hello \"+name)\n}\n"),
            ("taint_cpp_redirect", "cpp", ".cpp", "cpp.taint.open_redirect", 2,
             "std::string url = req.getParam(\"next\");\nres.redirect(url);\n"),
            ("taint_cpp_traversal", "cpp", ".cpp", "cpp.taint.path_traversal", 2,
             "std::string p = req.getParam(\"file\");\nstd::ifstream in(p);\n"),
            ("taint_elixir_redirect", "elixir", ".ex", "elixir.taint.open_redirect", 3,
             "def redirect_to(conn, params) do\n  target = params[\"url\"]\n"
             "  redirect(conn, external: target)\nend\n"),
            ("taint_elixir_traversal", "elixir", ".ex", "elixir.taint.request_path_traversal", 3,
             "def show(conn, _params) do\n  path = conn.params[\"file\"]\n"
             "  File.read(path)\nend\n"),
            ("taint_swift_redirect", "swift", ".swift", "swift.taint.request_open_redirect", 3,
             "func queryRedirect(req: Request) -> Response {\n"
             "  let target = req.query[\"returnUrl\"] ?? \"/\"\n"
             "  return req.redirect(to: target)\n}\n"),
            ("taint_swift_traversal", "swift", ".swift", "swift.taint.request_path_traversal", 4,
             "func readDownload(req: Request) throws -> String {\n"
             "  let requestedName = req.query[\"file\"] ?? \"index.html\"\n"
             "  let path = documentRoot + \"/\" + requestedName\n"
             "  return try String(contentsOfFile: path)\n}\n"),
        )
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="ubs-source-identity-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            nested = project / "nested"
            clean = project / "clean"
            outside = root / "outside"
            for directory in (nested, clean, outside):
                directory.mkdir(parents=True)
            try:
                for name, lang, suffix, rule, line, source in cases:
                    analyzer = importlib.import_module(f"ubs_core.analyzers.{name}")
                    paths = [directory / f"same{suffix}" for directory in (project, nested, clean)]
                    for path, text in zip(paths, (source, "\n" + source, "")):
                        path.write_text(text, encoding="utf-8")
                    baseline = None
                    for cwd in (project, nested, outside):
                        os.chdir(cwd)
                        for relative in (False, True):
                            with self.subTest(analyzer=name, cwd=cwd, relative=relative):
                                inputs = ([Path(os.path.relpath(path, cwd)) for path in paths]
                                          if relative else paths)
                                records = list(analyzer.run(RunContext(lang=lang, files=inputs)))
                                self.assertEqual(
                                    [(record["rule"], record["path"], record["line"]) for record in records],
                                    [(rule, str(paths[0]), line), (rule, str(paths[1]), line + 1)],
                                    records,
                                )
                                if baseline is None:
                                    baseline = records
                                else:
                                    # Path spelling and cwd must not change any
                                    # finding fields, counts, or source locations.
                                    self.assertEqual(records, baseline)
            finally:
                os.chdir(original_cwd)

    def test_real_cpp_detectors_keep_outside_sources_distinct(self) -> None:
        from ubs_core.cpp_detectors import async_errors, header_hygiene

        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="ubs-detector-identity-") as temp:
            root = Path(temp).resolve()
            first, second, outside = root / "first", root / "second", root / "outside"
            for directory in (first, second, outside):
                directory.mkdir()
            paths = [directory / "same.hpp" for directory in (first, second)]
            source = "#pragma once\nusing namespace std;\nstd::future<int> future = std::async(work);\n"
            for path in paths:
                path.write_text(source, encoding="utf-8")
            try:
                for cwd in (first, outside):
                    os.chdir(cwd)
                    inputs = [Path(os.path.relpath(path, cwd)) for path in paths]
                    with self.subTest(cwd=cwd):
                        futures = list(async_errors.find(inputs))
                        self.assertEqual(futures, [(str(path), 0, 1, async_errors.DESCRIPTION) for path in paths])
                        headers = list(header_hygiene.find(inputs))
                        self.assertEqual(headers, [
                            ("cpp.headers.using-namespace-std-header", str(path), 2, 1, "using namespace std;")
                            for path in paths
                        ])
            finally:
                os.chdir(original_cwd)

    def test_real_swift_correlation_keeps_source_identity_cold_and_warm(self) -> None:
        from ubs_core import swift_rules

        with tempfile.TemporaryDirectory(prefix="ubs-swift-identity-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            nested, clean, outside = project / "nested", project / "clean", root / "outside"
            for directory in (nested, clean, outside):
                directory.mkdir(parents=True)
            paths = [directory / "same.swift" for directory in (project, nested, clean)]
            source = (
                "func start(session: URLSession, url: URL) {\n"
                "  let task =\n    session.dataTask(with: url)\n}\n"
            )
            safe = source.replace("\n}", "\n  task.resume()\n}")
            for path, text in zip(paths, (source, "\n" + source, safe)):
                path.write_text(text, encoding="utf-8")
            rules = root / "rules"
            swift_rules.generate(rules)
            for cwd_index, cwd in enumerate((project, outside)):
                for relative in (False, True):
                    files_from = root / "files.txt"
                    inputs = [os.path.relpath(path, cwd) if relative else str(path) for path in paths]
                    files_from.write_text("\n".join(inputs) + "\n", encoding="utf-8")
                    sink, output = root / "findings.ndjson", root / "report.json"
                    command = [
                        sys.executable, "-m", "ubs_core.swift_scan", "--files-from", str(files_from),
                        "--sink", str(sink), "--json-out", str(output), "--project-dir", str(project),
                        "--ast-rule-dir", str(rules), "--ast-available", "--skip-type-narrowing",
                        "--skip", ",".join(str(n) for n in range(1, 24) if n != 4), "--fail-on-warning",
                    ]
                    env = dict(
                        os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                        UBS_NO_CACHE="0", UBS_CACHE_DIR=str(root / f"cache-{cwd_index}-{relative}"),
                        UBS_CACHE_FILE=str(root / "cache-stats.json"), UBS_PROFILE="1",
                    )
                    cold = None
                    for warm in (False, True):
                        with self.subTest(cwd=cwd, relative=relative, warm=warm):
                            proc = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed scanner argv and generated Swift fixtures; bounded real subprocess
                            context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                            self.assertEqual(proc.returncode, 1, context)
                            self.assertTrue(output.is_file(), context)
                            self.assertTrue(sink.is_file(), context)
                            try:
                                doc = json.loads(output.read_text(encoding="utf-8"))
                                records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                            except ValueError as exc:
                                self.fail(f"Invalid native Swift report: {exc}\n{context}")
                            self.assertEqual(doc["status"], "ok", context)
                            self.assertEqual(doc["files"], len(paths), context)
                            self.assertEqual(doc["findings"], records, context)
                            correlation = [record for record in records
                                           if record["rule"] == "ubs.correlation.urlsession.assigned-no-resume"]
                            self.assertEqual(len(correlation), 2, context)
                            self.assertEqual(sum(finding["count"] for finding in correlation), 2, context)
                            samples = [(sample["path"], sample["line"])
                                       for finding in correlation for sample in finding["samples"]]
                            # ast-grep may discover files in either order; every
                            # actual source occurrence must still appear once.
                            self.assertCountEqual(samples, [(str(paths[0]), 3), (str(paths[1]), 4)], context)
                            for finding in correlation:
                                self.assertEqual(finding["count"], 1, context)
                                self.assertEqual(len(finding["samples"]), 1, context)
                                sample = finding["samples"][0]
                                self.assertEqual((finding["path"], finding["line"]),
                                                 (sample["path"], sample["line"]), context)
                            self.assertEqual(doc["profile"]["cache_hits"], len(paths) if warm else 0, context)
                            self.assertEqual(doc["profile"]["cache_misses"], 0 if warm else len(paths), context)
                            self.assertEqual(doc["warning"], sum(int(record.get("count", 1)) for record in records
                                                                  if record["severity"] == "warning"), context)
                            ordered = sorted(records, key=lambda record: json.dumps(record, sort_keys=True))
                            if warm:
                                self.assertEqual(ordered, cold, context)
                            else:
                                cold = ordered

    def _native_swift(self, root, project, paths, cache, *, rules=None, hits=0, detail_limit=1):
        """Exercise the real scanner from outside the project with relative inputs."""
        outside = root / "outside"
        outside.mkdir(exist_ok=True)
        files_from, sink, output = root / "files.txt", root / "findings.ndjson", root / "report.json"
        files_from.write_text("\n".join(os.path.relpath(path, outside) for path in paths) + "\n", encoding="utf-8")
        command = [
            sys.executable, "-m", "ubs_core.swift_scan", "--files-from", str(files_from),
            "--sink", str(sink), "--json-out", str(output), "--project-dir", str(project),
            "--skip-type-narrowing", "--detail-limit", str(detail_limit), "--fail-on-warning",
            "--skip", ",".join(str(n) for n in range(1, 24) if n not in (4, 6, 7)),
        ]
        if rules is not None:
            command.extend(("--ast-rule-dir", str(rules), "--ast-available"))
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0", UBS_CACHE_DIR=str(cache), UBS_PROFILE="1")
        proc = subprocess.run(command, cwd=outside, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed scanner argv and local Swift fixtures; bounded real subprocess
        context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        self.assertTrue(output.is_file(), context)
        self.assertTrue(sink.is_file(), context)
        try:
            doc = json.loads(output.read_text(encoding="utf-8"))
            records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
        except ValueError as exc:
            self.fail(f"Invalid native Swift report: {exc}\n{context}")
        self.assertEqual(doc["status"], "ok", context)
        self.assertEqual(doc["files"], len(paths), context)
        self.assertEqual(doc["findings"], records, context)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], sum(int(record.get("count", 1)) for record in records
                                                 if record["severity"] == severity), context)
        self.assertEqual(proc.returncode, int(bool(doc["critical"] or doc["warning"])), context)
        self.assertEqual(doc["profile"]["cache_hits"], hits, context)
        self.assertEqual(doc["profile"]["cache_misses"], len(paths) - hits, context)
        return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

    def test_real_swift_security_detectors_keep_selected_occurrences(self) -> None:
        from ubs_core.swift_scan import ScanContext

        cases = (
            ("archive_extraction", 2,
             "let archive = Archive()\nlet output = destination.appendingPathComponent(entry.path)\n",
             "let archive = Archive()\nlet output = safeArchiveURL(entry.path)\n"),
            ("header_injection", 1,
             'response.headers["X-Name"] = req.query["name"]\n',
             'response.headers["X-Name"] = safeHeaderValue(req.query["name"])\n'),
            ("outbound_url", 1,
             'URLSession.shared.dataTask(with: req.query["url"])\n',
             'URLSession.shared.dataTask(with: safeURL(req.query["url"]))\n'),
            ("security_randomness", 1,
             "let sessionToken = Int.random(in: 0..<1000)\n",
             "let displayJitter = Int.random(in: 0..<1000)\n"),
            ("shell_execution", 1,
             'Darwin.system("date")\n',
             'let font = Font.system(size: 12)\nfunc system(_ value: String) {}\n'),
        )
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="ubs-swift-detectors-") as temp:
            root = Path(temp).resolve()
            project, outside = root / "project", root / "outside"
            project.mkdir()
            outside.mkdir()
            try:
                os.chdir(outside)
                for name, line, unsafe, safe in cases:
                    detector = importlib.import_module(f"ubs_core.swift_detectors.{name}")
                    # The old randomness preview retained 25 sites; other
                    # detectors retained three. Every later source must survive.
                    paths = [project / f"source-{i}" / "same.swift" for i in range(27)]
                    clean = project / "clean.swift"
                    for index, path in enumerate(paths):
                        path.parent.mkdir(exist_ok=True)
                        path.write_text("\n" * index + unsafe, encoding="utf-8")
                    clean.write_text(safe, encoding="utf-8")
                    for selected in (paths + [clean], [paths[-1]], [paths[0], clean], [clean]):
                        with self.subTest(detector=name, selected=selected):
                            ctx = ScanContext(files=[Path(os.path.relpath(p, outside)) for p in selected],
                                              project_dir=project)
                            records = list(detector.scan(ctx))
                            expected = [(str(path), line + paths.index(path)) for path in selected if path != clean]
                            self.assertEqual([(r["path"], r["line"]) for r in records], expected, records)
                            for record in records:
                                self.assertEqual(record["rule"], detector.RULE_ID)
                                self.assertEqual(record["count"], 1)
                                self.assertEqual(record["severity"], "critical")
                                self.assertEqual(len(record["samples"]), 1)
                                sample = record["samples"][0]
                                self.assertEqual((sample["path"], sample["line"]),
                                                 (record["path"], record["line"]))
            finally:
                os.chdir(original_cwd)

    def test_real_swift_duplicate_shell_sites_preserve_other_source_info(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-swift-shell-cache-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            shell, fixed = project / "shell:source.swift", project / "fixed.swift"
            shell.write_text('system("date"); posix_spawn(&pid, "/bin/sh", nil, nil, ["-c", "date"], nil)\n', encoding="utf-8")
            fixed.write_text('let process = Process()\nprocess.executableURL = URL(fileURLWithPath: "/usr/bin/stat")\nprocess.arguments = ["-f", "%z", path]\n', encoding="utf-8")
            cache = root / "cache"
            cold = self._native_swift(root, project, [shell, fixed], cache)
            shell_hits = [r for r in cold if r["rule"] == "swift.security.shell-exec"]
            self.assertEqual([(r["path"], r["line"], r["count"]) for r in shell_hits],
                             [(str(shell), 1, 1), (str(shell), 1, 1)], cold)
            residual = [r for r in cold if r["rule"] == "swift.security.process-other"]
            self.assertEqual([(r["path"], r["line"], r["count"]) for r in residual], [(str(fixed), 1, 1)], cold)
            self.assertEqual(self._native_swift(root, project, [shell, fixed], cache, hits=2), cold)
            subset = self._native_swift(root, project, [fixed], cache, hits=1)
            self.assertEqual([r for r in subset if r["rule"] == "swift.security.process-other"], residual)
            self.assertFalse(any(r["rule"] == "swift.security.shell-exec" for r in subset), subset)


if __name__ == "__main__":
    unittest.main()
