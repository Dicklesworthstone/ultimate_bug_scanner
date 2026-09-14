#!/usr/bin/env python3
"""Unit tests for ubs_core stdlib helper library (bead A2)."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
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


class UbsCorePackageImportTests(unittest.TestCase):
    def _isolated_python(self, script: str, *arguments: str) -> dict:
        command = [sys.executable, "-I", "-S", "-B", "-c", script, *arguments]
        proc = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, timeout=60)  # ubs:ignore[python.taint.command] - fixed isolated Python probes and local fixture paths, no external command source
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        try:
            return json.loads(proc.stdout)
        except ValueError as exc:
            self.fail(f"probe JSON failed: {exc}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")

    def test_lazy_package_exports_preserve_real_objects_and_import_forms(self) -> None:
        script = r'''
import importlib
import json
import sys
sys.path.insert(0, sys.argv[1])
import ubs_core

expected = {
    "CostModel": "scheduler", "ScheduleResult": "scheduler",
    "calculate_slot_utilization": "scheduler", "schedule_lpt": "scheduler",
    "ShardQueue": "shards", "make_shards": "shards",
    "parallel_file_map": "shards", "run_work_stealing": "shards",
    "extract_statement_region": "io", "find_block_end": "io",
    "format_location": "io", "line_col": "io", "skip_ws": "io",
    "Interval": "lexer", "Span": "lexer", "strip_comments_and_strings": "lexer",
}
deferred = {"ubs_core.scheduler", "ubs_core.shards"}
assert deferred.isdisjoint(sys.modules), sorted(deferred.intersection(sys.modules))
assert {"ubs_core.io", "ubs_core.lexer"}.issubset(sys.modules)
assert set(ubs_core.__all__) == set(expected)
assert len(ubs_core.__all__) == len(expected)
assert set(expected).issubset(dir(ubs_core))
assert deferred.isdisjoint(sys.modules), "dir must not load deferred modules"
try:
    getattr(ubs_core, "unknown_package_export")
except AttributeError as exc:
    assert "ubs_core" in str(exc) and "unknown_package_export" in str(exc)
else:
    raise AssertionError("unknown exports must raise AttributeError")
sentinel = object()
assert getattr(ubs_core, "unknown_package_export", sentinel) is sentinel
assert not hasattr(ubs_core, "unknown_package_export")
assert deferred.isdisjoint(sys.modules), "missing attributes must not load helpers"

mode = sys.argv[2]
if mode == "attribute":
    first = ubs_core.CostModel
    assert "ubs_core.scheduler" in sys.modules
    assert "ubs_core.shards" not in sys.modules
    assert first is ubs_core.CostModel
elif mode == "named":
    from ubs_core import (
        CostModel, ScheduleResult, calculate_slot_utilization, schedule_lpt,
        ShardQueue, make_shards, parallel_file_map, run_work_stealing,
        extract_statement_region, find_block_end, format_location, line_col,
        skip_ws, Interval, Span, strip_comments_and_strings,
    )
elif mode == "star":
    before_star = set(globals())
    from ubs_core import *
    assert set(globals()) - before_star - {"before_star"} == set(expected)
elif mode == "submodule":
    import ubs_core.scheduler
    assert "ubs_core.shards" not in sys.modules
    from ubs_core import shards
    assert ubs_core.scheduler is importlib.import_module("ubs_core.scheduler")
    assert shards is importlib.import_module("ubs_core.shards")
    assert ubs_core.shards is shards
else:
    raise AssertionError(mode)

for name, module_name in expected.items():
    exported = getattr(ubs_core, name)
    module = importlib.import_module("ubs_core." + module_name)
    assert exported is getattr(module, name), (mode, name)
    assert vars(ubs_core)[name] is exported, (mode, name, "not memoized")
    if mode in ("named", "star"):
        assert globals()[name] is exported, (mode, name)
assert ubs_core.line_col("first\nsecond", 6) == (2, 1)
assert len(ubs_core.make_shards(["one", "two", "three"], 2)) == 2
print(json.dumps({"mode": mode, "exports": sorted(expected),
                  "loaded": sorted(deferred.intersection(sys.modules))}))
'''
        for mode in ("attribute", "named", "star", "submodule"):
            with self.subTest(mode=mode):
                result = self._isolated_python(script, str(HELPERS_DIR), mode)
                self.assertEqual(result["mode"], mode)
                self.assertEqual(len(result["exports"]), 16)
                self.assertEqual(result["loaded"], ["ubs_core.scheduler", "ubs_core.shards"])

    def test_installed_helper_fingerprint_preserves_paths_extensions_and_full_bytes(self) -> None:
        script = r'''
import json
import os
import sys
sys.path.insert(0, sys.argv[1])
os.environ["UBS_NO_CACHE"] = "0"
os.environ["UBS_CACHE_DIR"] = sys.argv[2]
from ubs_core.cache import ScanCache
cache = ScanCache("python", project_dir=sys.argv[3], rulepack_hash="fixture-rules",
                  module_checksum="fixture-module", engine_version="fixture-engine")
assert cache.enabled
print(json.dumps({"source_hash": cache._derive_helper_source_hash(), "cache_key": cache.cache_key}))
'''
        with tempfile.TemporaryDirectory(prefix="ubs-helper-paths-") as temp:
            root = Path(temp)
            helpers = root / "helpers"
            package = helpers / "ubs_core"
            package.mkdir(parents=True)
            copied_names = ("__init__.py", "cache.py", "io.py", "lexer.py")
            for name in copied_names:
                shutil.copy2(HELPERS_DIR / "ubs_core" / name, package / name)
            nested = helpers / "nested λ"
            deeper = nested / "deeper"
            deeper.mkdir(parents=True)
            fixtures = {
                "...go": b"package fixture\n",
                "..py": b"VALUE = 1\n",
                ".js": b"ignored bare dotfile\n",
                "edge.js": b"const edge = 1;\r\n",
                "nested λ/Ω.js": b"header\x00" + b"x" * 8192 + b"\xff",
                "nested λ/deeper/worker.go": "package fixture // 雪\n".encode("utf-8"),
            }
            for relative, content in fixtures.items():
                (helpers / relative).write_bytes(content)
            bytecode = package / "__pycache__"
            bytecode.mkdir()
            (bytecode / "ignored.py").write_text("ignored cache source\n", encoding="utf-8")
            (helpers / "ignored.pyc").write_bytes(b"ignored bytecode")

            # Explicit traversal order is the installed-helper fingerprint
            # contract: root files, then sorted directory subtrees. Path.suffix
            # supplies the original interpreter's dotfile semantics (3.14
            # changed them), independently of the optimized classifier.
            ordered_paths = [
                name for name in ("...go", "..py", ".js", "edge.js")
                if Path(name).suffix in (".py", ".go", ".js")
            ] + ["nested λ/Ω.js", "nested λ/deeper/worker.go"] + [
                "ubs_core/" + name for name in copied_names
            ]

            def reference_hash() -> str:
                digest = hashlib.blake2b(digest_size=16)
                for relative in ordered_paths:
                    encoded = relative.encode("utf-8", "surrogateescape")
                    content = (helpers / relative).read_bytes()
                    digest.update(len(encoded).to_bytes(8, "big"))
                    digest.update(encoded)
                    digest.update(len(content).to_bytes(8, "big"))
                    digest.update(content)
                return digest.hexdigest()

            def actual_hash() -> dict:
                result = self._isolated_python(
                    script, str(helpers), str(root / "cache"), str(root),
                )
                self.assertEqual(result["source_hash"], reference_hash())
                return result

            baseline = actual_hash()
            for name in ("...go", "..py", ".js"):
                with self.subTest(filename=name, suffix=Path(name).suffix):
                    path = helpers / name
                    path.write_bytes(path.read_bytes() + b"changed\n")
                    changed = actual_hash()
                    if name in ordered_paths:
                        self.assertNotEqual(changed["source_hash"], baseline["source_hash"])
                        self.assertNotEqual(changed["cache_key"], baseline["cache_key"])
                    else:
                        self.assertEqual(changed, baseline)
                    baseline = changed
            source = nested / "Ω.js"
            original_stat = source.stat()
            source.write_bytes(fixtures["nested λ/Ω.js"][:-1] + b"\xfe")
            os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            changed = actual_hash()
            self.assertNotEqual(changed["source_hash"], baseline["source_hash"])
            self.assertNotEqual(changed["cache_key"], baseline["cache_key"])
            source.rename(nested / "雪.js")
            ordered_paths[ordered_paths.index("nested λ/Ω.js")] = "nested λ/雪.js"
            renamed = actual_hash()
            self.assertNotEqual(renamed["source_hash"], changed["source_hash"])
            self.assertNotEqual(renamed["cache_key"], changed["cache_key"])


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

    def _native_swift(self, root, project, paths, cache, *, rules=None, hits=0, detail_limit=1,
                      categories=(4, 6, 7), text_out=None):
        """Exercise the real scanner from outside the project with relative inputs."""
        outside = root / "outside"
        outside.mkdir(exist_ok=True)
        # A failed child must never reuse an earlier invocation's report.
        artifacts = Path(tempfile.mkdtemp(prefix="scan-", dir=root))
        files_from, sink, output = artifacts / "files.txt", artifacts / "findings.ndjson", artifacts / "report.json"
        files_from.write_text("\n".join(os.path.relpath(path, outside) for path in paths) + "\n", encoding="utf-8")
        command = [
            sys.executable, "-m", "ubs_core.swift_scan", "--files-from", str(files_from),
            "--sink", str(sink), "--json-out", str(output), "--project-dir", str(project),
            "--skip-type-narrowing", "--detail-limit", str(detail_limit), "--fail-on-warning",
            "--skip", ",".join(str(n) for n in range(1, 24) if n not in categories),
        ]
        if rules is not None:
            command.extend(("--ast-rule-dir", str(rules), "--ast-available"))
        if text_out is not None:
            command.extend(("--text-out", str(text_out)))
        env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                   UBS_NO_CACHE="0", UBS_CACHE_DIR=str(cache), UBS_PROFILE="1")
        proc = subprocess.run(command, cwd=outside, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed scanner argv and local Swift fixtures; bounded real subprocess
        context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        self.assertTrue(output.is_file(), context)
        self.assertTrue(sink.is_file(), context)
        if text_out is not None:
            self.assertTrue(text_out.is_file(), context)
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
             "let archive = Archive()\nlet output = destination.appendingPathComponent(entry.path)\nensureInsideDestination(output)\n"),
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

    def test_real_swift_ast_cache_subsets_partial_edits_and_preview_overflow(self) -> None:
        from ubs_core import swift_rules

        with tempfile.TemporaryDirectory(prefix="ubs-swift-partial-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            paths = [project / "same.swift", project / "nested" / "same.swift",
                     project / "peer.swift", project / "fourth.swift", project / "fifth.swift"]
            paths[1].parent.mkdir()
            clean = project / "clean.swift"
            source = ("func start(session: URLSession, url: URL) {\n"
                      "  let task =\n    session.dataTask(with: url)\n}\n"
                      "func force() {\n  try! risky()\n}\n")
            safe = source.replace("\n}", "\n  task.resume()\n}", 1).replace("try! risky()", "try? risky()")
            for path in paths:
                path.write_text(source, encoding="utf-8")
            clean.write_text(safe, encoding="utf-8")
            selected = paths + [clean]
            rules = root / "rules"
            swift_rules.generate(rules)
            cache = root / "cache"

            def assert_sites(records, expected):
                for rule, base_line, col in (("ubs.correlation.urlsession.assigned-no-resume", 3, 5),
                                              ("swift.force-try", 6, 3)):
                    actual = [r for r in records if r["rule"] == rule]
                    wanted = [(str(path), base_line + offset, col)
                              for path, offsets in expected.items() for offset in offsets]
                    self.assertCountEqual([(r["path"], r["line"], r["col"]) for r in actual], wanted, actual)
                    self.assertEqual(sum(r["count"] for r in actual), len(wanted), actual)
                    for record in actual:
                        self.assertEqual(record["count"], 1)
                        self.assertEqual(len(record["samples"]), 1)
                        sample = record["samples"][0]
                        self.assertEqual((sample["path"], sample["line"], sample["col"]),
                                         (record["path"], record["line"], record["col"]))

            cold = self._native_swift(root, project, selected, cache, rules=rules)
            assert_sites(cold, {path: [0] for path in paths})
            self.assertEqual(self._native_swift(root, project, selected, cache, rules=rules, hits=6), cold)
            self.assertEqual(self._native_swift(root, project, selected, cache, rules=rules, hits=6, detail_limit=5), cold)
            # Five positive sources exceed both the requested one-sample
            # preview and the former hard-coded three-sample correlation cap.
            for path in selected:
                with self.subTest(subset=path):
                    subset = self._native_swift(root, project, [path], cache, rules=rules, hits=1)
                    assert_sites(subset, {} if path == clean else {path: [0]})
                    reference = self._native_swift(root, project, [path], root / f"reference-{path.parent.name}-{path.name}", rules=rules)
                    self.assertEqual(subset, reference)

            paths[1].write_text(safe, encoding="utf-8")
            partial = self._native_swift(root, project, selected, cache, rules=rules, hits=5)
            assert_sites(partial, {path: [0] for path in paths if path != paths[1]})
            self.assertEqual(partial, self._native_swift(root, project, selected, root / "reference-partial-1", rules=rules))

            paths[0].write_text(safe, encoding="utf-8")
            # New unsafe bytes exercise two misses; restoring the exact old
            # content would correctly reuse its earlier content-addressed entry.
            paths[1].write_text(source + "// restored unsafe source\n", encoding="utf-8")
            partial = self._native_swift(root, project, selected, cache, rules=rules, hits=4)
            assert_sites(partial, {path: [0] for path in paths if path != paths[0]})
            self.assertEqual(partial, self._native_swift(root, project, selected, root / "reference-partial-2", rules=rules))

            paths[1].write_text(source + source, encoding="utf-8")
            partial = self._native_swift(root, project, selected, cache, rules=rules, hits=5)
            expected = {path: [0] for path in paths if path != paths[0]}
            expected[paths[1]] = [0, source.count("\n")]
            assert_sites(partial, expected)
            self.assertEqual(partial, self._native_swift(root, project, selected, root / "reference-partial-3", rules=rules))

    def test_real_swift_inline_and_split_task_lifecycle(self) -> None:
        from ubs_core import swift_rules

        cases = (
            ("inline-unused", "  let task = session.dataTask(with: url)\n", "assigned-no-resume", 2, 14),
            ("split-assignment", "  let task =\n    session.dataTask(with: url)\n", "assigned-no-resume", 3, 5),
            ("split-method", "  let task = session\n    .dataTask(with: url)\n", "assigned-no-resume", 2, 14),
            ("inline-resumed", "  let task = session.dataTask(with: url)\n  task.resume()\n", None, 0, 0),
            ("inline-cancelled", "  let task = session.dataTask(with: url)\n  task.cancel()\n", "assigned-cancel-no-resume", 2, 14),
            ("inline-returned", "  let task = session.dataTask(with: url)\n  return task\n", None, 0, 0),
            ("direct-return", "  return session.dataTask(with: url)\n", None, 0, 0),
            ("direct-unused", "  session.dataTask(with: url)\n", "unassigned-no-resume", 2, 3),
            ("discarded", "  _ = session.dataTask(with: url)\n", "unassigned-no-resume", 2, 7),
            ("chained-resume", "  session.dataTask(with: url).resume()\n", None, 0, 0),
            ("factory-unused", "  let task = makeSession().dataTask(with: url)\n", "assigned-no-resume", 2, 14),
            ("factory-resumed", "  let task = makeSession().dataTask(with: url)\n  task.resume()\n", None, 0, 0),
            ("member-resumed", "  self.task = session.dataTask(with: url)\n  self.task.resume()\n", None, 0, 0),
            ("utf8-crlf-unused", "  // café\r\n  let task = session.dataTask(with: url)\r\n", "assigned-no-resume", 3, 14),
            ("utf8-crlf-resumed", "  // café\r\n  let task = session.dataTask(with: url)\r\n  task.resume()\r\n", None, 0, 0),
        )
        with tempfile.TemporaryDirectory(prefix="ubs-swift-inline-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            paths, expected = [], []
            for name, body, suffix, line, col in cases:
                path = project / f"{name}.swift"
                # Preserve CRLF and UTF-8 bytes for the actual ast-grep ranges.
                path.write_bytes(("func start(session: URLSession, url: URL) {\n" + body + "}\n").encode("utf-8"))
                paths.append(path)
                if suffix is not None:
                    expected.append(("ubs.correlation.urlsession." + suffix, str(path), line, col,
                                     "info" if suffix == "assigned-cancel-no-resume" else "warning"))
            rules = root / "rules"
            swift_rules.generate(rules)
            cache = root / "cache"
            cold = self._native_swift(root, project, paths, cache, rules=rules)
            correlation = [r for r in cold if r["rule"].startswith("ubs.correlation.urlsession.")]
            self.assertCountEqual([(r["rule"], r["path"], r["line"], r["col"], r["severity"])
                                   for r in correlation], expected, correlation)
            self.assertEqual(sum(r["count"] for r in correlation), len(expected), correlation)
            for record in correlation:
                self.assertEqual(record["count"], 1)
                self.assertEqual(len(record["samples"]), 1)
                sample = record["samples"][0]
                self.assertEqual((sample["path"], sample["line"], sample["col"]),
                                 (record["path"], record["line"], record["col"]))
            self.assertEqual(self._native_swift(root, project, paths, cache, rules=rules, hits=len(paths)), cold)

    def test_real_swift_global_thresholds_and_pathless_facts_recompute(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-swift-global-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            first, second = project / "first.swift", project / "second.swift"
            first.write_text("let value = optional!\n" * 20 + "let handle = FileHandle(forReadingFrom: url)\n", encoding="utf-8")
            second.write_text("let value = optional!\n" * 11 + "handle.close()\n", encoding="utf-8")
            cache = root / "cache"

            def assert_global(records, force_rule, count, imbalance):
                force = [r for r in records if r["rule"] in ("swift.optionals.force-heavy", "swift.optionals.force-some")]
                self.assertEqual(len(force), count, records)
                self.assertEqual(sum(r["count"] for r in force), count, records)
                self.assertEqual({r["rule"] for r in force}, {force_rule})
                expected_severity = "warning" if force_rule.endswith("heavy") else "info"
                self.assertEqual({r["severity"] for r in force}, {expected_severity})
                handles = [r for r in records if r["rule"] == "swift.files.filehandle"]
                self.assertEqual([(r["path"], r["line"], r["count"]) for r in handles],
                                 [("", 0, imbalance)] if imbalance else [], records)

            cold = self._native_swift(root, project, [first, second], cache, categories=(1, 8))
            assert_global(cold, "swift.optionals.force-heavy", 31, 0)
            self.assertEqual(self._native_swift(root, project, [first, second], cache, hits=2, categories=(1, 8)), cold)
            subset = self._native_swift(root, project, [first], cache, hits=1, categories=(1, 8))
            assert_global(subset, "swift.optionals.force-some", 20, 1)
            self.assertEqual(subset, self._native_swift(root, project, [first], root / "reference-subset", categories=(1, 8)))

            second.write_text("let value = optional!\n" * 10, encoding="utf-8")
            partial = self._native_swift(root, project, [first, second], cache, hits=1, categories=(1, 8))
            assert_global(partial, "swift.optionals.force-some", 30, 1)
            self.assertEqual(partial, self._native_swift(root, project, [first, second], root / "reference-partial", categories=(1, 8)))
            first.write_text("let value = optional!\n" * 21 + "let handle = FileHandle(forReadingFrom: url)\nhandle.close()\n", encoding="utf-8")
            partial = self._native_swift(root, project, [first, second], cache, hits=1, categories=(1, 8))
            assert_global(partial, "swift.optionals.force-heavy", 31, 0)
            self.assertEqual(partial, self._native_swift(root, project, [first, second], root / "reference-restored", categories=(1, 8)))

    def test_real_swift_ancillary_findings_require_selected_sources(self) -> None:
        import plistlib

        with tempfile.TemporaryDirectory(prefix="ubs-swift-ancillary-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            swift = project / "clean.swift"
            swift.write_text("let value = 1\n", encoding="utf-8")
            package = project / "Package.swift"
            package.write_text('.package(url: "https://example.invalid/dependency", .branch("main"))\n'
                               'swiftSettings: [.unsafeFlags(["-Ounchecked"])]\n', encoding="utf-8")
            storyboards = [project / f"Scene-{i}.storyboard" for i in range(6)]
            for path in storyboards:
                path.write_text('<?xml version="1.0"?><document type="com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB"/>\n', encoding="utf-8")
            info, entitlements = project / "Info.plist", project / "App.entitlements"
            info.write_bytes(plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}))
            entitlements.write_bytes(plistlib.dumps({"get-task-allow": True}))
            categories = (17, 19, 20, 21)
            cache = root / "cache"
            ancillary_rules = {
                "swift.packaging.branch-pins", "swift.packaging.unsafe-flags",
                "swift.uisafety.storyboards", "swift.infoplist.ats-parse", "swift.build.entitlements",
            }

            def assert_ancillary(records, expected):
                actual = []
                for record in records:
                    if record["rule"] not in ancillary_rules:
                        continue
                    path = record["path"]
                    source = str((root / "outside" / path).resolve()) if path else ""
                    actual.append((record["rule"], source, record["line"], record["severity"], record["count"]))
                self.assertCountEqual(actual, expected, records)

            clean = self._native_swift(root, project, [swift], cache, categories=categories)
            assert_ancillary(clean, [])
            self.assertEqual(self._native_swift(root, project, [swift], cache, hits=1, categories=categories), clean)

            selected = [swift, package, *storyboards, info, entitlements]
            expected = [
                ("swift.packaging.branch-pins", str(package), 0, "info", 1),
                ("swift.packaging.unsafe-flags", str(package), 0, "warning", 1),
                ("swift.uisafety.storyboards", "", 0, "info", 6),
                ("swift.infoplist.ats-parse", str(info), 0, "warning", 1),
                ("swift.build.entitlements", str(entitlements), 0, "warning", 1),
            ]
            full = self._native_swift(root, project, selected, cache, hits=1, categories=categories)
            assert_ancillary(full, expected)
            self.assertEqual(self._native_swift(root, project, selected, cache, hits=len(selected), categories=categories), full)
            for subset, wanted in (([package], expected[:2]), ([info], [expected[3]]),
                                   ([entitlements], [expected[4]]), (storyboards, [expected[2]]),
                                   (storyboards[:5], []), ([swift], [])):
                with self.subTest(selected=subset):
                    records = self._native_swift(root, project, subset, cache, hits=len(subset), categories=categories)
                    assert_ancillary(records, wanted)

    def test_real_swift_generated_ast_findings_remain_visible_in_text(self) -> None:
        from ubs_core import swift_rules

        with tempfile.TemporaryDirectory(prefix="ubs-swift-ast-text-") as temp:
            root = Path(temp).resolve()
            project = root / "project"
            project.mkdir()
            first, second, clean = project / "first.swift", project / "second.swift", project / "clean.swift"
            source = "func dangerous() {\n  try! risky()\n}\n"
            first.write_text(source, encoding="utf-8")
            second.write_text("\n" + source, encoding="utf-8")
            clean.write_text(source.replace("try!", "try?"), encoding="utf-8")
            rules = root / "rules"
            swift_rules.generate(rules)
            cache = root / "cache"

            def assert_visible(records, report, expected):
                findings = [r for r in records if r["rule"] == "swift.force-try"]
                self.assertCountEqual([(r["path"], r["line"], r["col"], r["count"], r["severity"])
                                       for r in findings],
                                      [(str(path), line, 3, 1, "warning") for path, line in expected], records)
                for finding in findings:
                    self.assertEqual(finding["source"], "ast-grep", finding)
                self.assertIn("AST-GREP RULE PACK FINDINGS", report)
                lines = report.splitlines()
                titles = [index for index, line in enumerate(lines) if line.strip().startswith("swift.force-try:")]
                if not expected:
                    self.assertEqual(titles, [], report)
                    return
                self.assertEqual(len(titles), 1, report)
                index = titles[0]
                self.assertEqual(lines[index].strip(), findings[0]["title"], report)
                self.assertEqual(lines[index - 1].strip(), f"⚠ Warning ({len(expected)} found)", report)
                for path, line in expected:
                    self.assertIn(f" {path}:{line} [rule:swift.force-try]\n", report)
                self.assertEqual(report.count("  try! risky()"), len(expected), report)

            selected = [first, second, clean]
            cold_text = root / "cold.txt"
            cold = self._native_swift(root, project, selected, cache, rules=rules, categories=(),
                                      detail_limit=5, text_out=cold_text)
            report = cold_text.read_text(encoding="utf-8")
            assert_visible(cold, report, [(first, 2), (second, 3)])
            warm_text = root / "warm.txt"
            warm = self._native_swift(root, project, selected, cache, rules=rules, categories=(), hits=3,
                                      detail_limit=5, text_out=warm_text)
            self.assertEqual(warm, cold)
            self.assertEqual(warm_text.read_text(encoding="utf-8"), report)
            subset_text = root / "subset.txt"
            subset = self._native_swift(root, project, [second], cache, rules=rules, categories=(), hits=1,
                                        detail_limit=5, text_out=subset_text)
            subset_report = subset_text.read_text(encoding="utf-8")
            assert_visible(subset, subset_report, [(second, 3)])
            self.assertNotIn(str(first), subset_report)
            clean_text = root / "clean.txt"
            clean_records = self._native_swift(root, project, [clean], cache, rules=rules, categories=(), hits=1,
                                               detail_limit=5, text_out=clean_text)
            assert_visible(clean_records, clean_text.read_text(encoding="utf-8"), [])

    def _swift_module_report(self, root, project, paths, cache, output_format, *, hits, categories):
        outside = root / "outside"
        outside.mkdir(exist_ok=True)
        artifacts = Path(tempfile.mkdtemp(prefix="module-", dir=root))
        selected, summary = artifacts / "files.txt", artifacts / "summary.json"
        selected.write_text("\n".join(str(path) for path in paths) + "\n", encoding="utf-8")
        command = [
            "bash", str(REPO_ROOT / "modules" / "ubs-swift.sh"),
            f"--format={output_format}", "--only=" + ",".join(map(str, categories)),
            "--ci", "--no-color", "--fail-on-warning", f"--files-from={selected}",
            f"--summary-json={summary}", str(project),
        ]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                   UBS_CACHE_DIR=str(cache), UBS_PROFILE="1", UBS_SKIP_TYPE_NARROWING="1",
                   UBS_TEST_FORCE_NO_AST_GREP="0", UBS_ALLOW_UNVERIFIED_HELPERS="0")
        proc = subprocess.run(command, cwd=outside, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed repository module and selected local Swift fixtures, bounded CLI regression
        context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        self.assertTrue(summary.is_file(), context)
        try:
            doc = json.loads(summary.read_text(encoding="utf-8"))
            rendered = json.loads(proc.stdout)
        except ValueError as exc:
            self.fail(f"Swift module JSON/SARIF decode failed: {exc}\n{context}")
        self.assertEqual(doc["status"], "ok", context)
        self.assertEqual(doc["files"], len(paths), context)
        self.assertEqual(doc["profile"]["cache_hits"], hits, context)
        self.assertEqual(doc["profile"]["cache_misses"], len(paths) - hits, context)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(doc[severity], sum(record.get("count", 1) for record in doc["findings"]
                                                if record["severity"] == severity), context)
        self.assertEqual(proc.returncode, int(bool(doc["critical"] or doc["warning"])), context)
        return doc, rendered, context

    def test_real_swift_module_project_notes_preserve_json_sarif_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-swift-project-notes-") as temp:
            root = Path(temp).resolve()
            project, outside, cache = root / "project", root / "outside", root / "cache"
            project.mkdir()
            outside.mkdir()
            danger, control = project / "danger.swift", project / "control.swift"
            danger.write_text("func dangerous() {\n  try! risky()\n}\n", encoding="utf-8")
            control.write_text("func safe() {\n  try? risky()\n}\n", encoding="utf-8")
            task_rule = "swift.concurrency.task-usages"
            package_rule = "swift.packaging.no-manifest"
            force_rule = "swift.force-try"

            def run_module(paths, output_format, *, hits, task_source=None):
                doc, rendered, context = self._swift_module_report(
                    root, project, paths, cache, output_format, hits=hits, categories=(2, 20),
                )
                records = doc["findings"]
                expected_notes = {package_rule} if task_source else {package_rule, task_rule}
                notes = [record for record in records if record.get("scope") == "project"]
                self.assertEqual({record["rule"] for record in notes}, expected_notes, context)
                self.assertEqual(len(notes), len(expected_notes), context)
                for note in notes:
                    self.assertEqual((note["path"], note["line"], note["severity"], note["count"]),
                                     ("", 0, "info", 0), note)
                    self.assertTrue(note["message"], note)
                    self.assertFalse(note.get("samples"), note)
                task_findings = [record for record in records
                                 if record["rule"] == task_rule and record.get("scope") != "project"]
                self.assertEqual([(record["path"], record["line"], record["col"], record["count"])
                                  for record in task_findings],
                                 [(str(task_source), 2, 1, 1)] if task_source else [], context)
                force_findings = [record for record in records if record["rule"] == force_rule]
                self.assertEqual([(record["path"], record["line"], record["col"], record["count"])
                                  for record in force_findings],
                                 [(str(danger), 2, 3, 1)] if danger in paths else [], context)
                for finding in [*task_findings, *force_findings]:
                    self.assertNotIn("scope", finding, finding)
                if output_format == "json":
                    self.assertEqual(rendered, doc, context)
                else:
                    self.assertEqual(rendered["version"], "2.1.0", context)
                    results = [result for run in rendered["runs"] for result in run["results"]]
                    project_results = [result for result in results
                                       if result.get("properties", {}).get("scope") == "project"]
                    self.assertEqual({result["ruleId"] for result in project_results}, expected_notes, context)
                    self.assertEqual(len(project_results), len(expected_notes), context)
                    for result in project_results:
                        self.assertEqual((result["kind"], result["level"]), ("informational", "none"), result)
                        self.assertEqual(result["properties"]["count"], 0, result)
                        self.assertNotIn("locations", result, result)
                        self.assertTrue(result["message"]["text"], result)
                    for rule, source, line, column in (
                        (task_rule, task_source, 2, 1),
                        (force_rule, danger if danger in paths else None, 2, 3),
                    ):
                        source_results = [result for result in results if result["ruleId"] == rule
                                          and result.get("properties", {}).get("scope") != "project"]
                        self.assertEqual(len(source_results), int(source is not None), context)
                        for result in source_results:
                            self.assertNotEqual(result.get("kind"), "informational", result)
                            self.assertEqual(result["level"], "note" if rule == task_rule else "warning", result)
                            self.assertEqual(len(result["locations"]), 1, result)
                            location = result["locations"][0]["physicalLocation"]
                            self.assertEqual(location["artifactLocation"]["uri"], str(source), result)
                            self.assertEqual(location["region"]["startLine"], line, result)
                            self.assertEqual(location["region"]["startColumn"], column, result)
                return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

            full = [danger, control]
            cold = run_module(full, "json", hits=0)
            self.assertEqual(run_module(full, "sarif", hits=2), cold)
            control.write_text("func safe() {\n  Task { await work() }\n  try? risky()\n}\n", encoding="utf-8")
            partial = run_module(full, "json", hits=1, task_source=control)
            self.assertEqual(run_module(full, "sarif", hits=2, task_source=control), partial)
            run_module([danger], "sarif", hits=1)
            run_module([control], "json", hits=1, task_source=control)

    def test_real_swift_module_project_aggregates_recompute_counts_and_warning_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-swift-project-aggregates-") as temp:
            root = Path(temp).resolve()
            project, cache = root / "project", root / "cache"
            project.mkdir()
            first, second, balance = (project / name for name in ("first.swift", "second.swift", "balance.swift"))
            first.write_text(
                "import UIKit\nfunc first() async throws {\n"
                "  let first = try FileHandle(forReadingFrom: firstURL)\n}\n"
                "func second() async throws {\n"
                "  let second = try FileHandle(forReadingFrom: secondURL)\n}\n",
                encoding="utf-8",
            )
            second.write_text(
                "import SwiftUI\nfunc third() async throws {\n"
                "  let third = try FileHandle(forReadingFrom: thirdURL)\n}\n",
                encoding="utf-8",
            )
            balance.write_text("Task {\n  await work()\n}\nhandle.close()\n", encoding="utf-8")
            storyboards = [project / f"view-{index}.storyboard" for index in range(6)]
            for path in storyboards:
                path.write_text("<document/>\n", encoding="utf-8")
            async_rule = "swift.concurrency.unawaited-async"
            actor_rule = "swift.threading.main-actor"
            handle_rule = "swift.files.filehandle"
            storyboard_rule = "swift.uisafety.storyboards"
            task_rule = "swift.concurrency.task-usages"
            package_rule = "swift.packaging.no-manifest"

            def run_aggregates(paths, output_format, expected, *, hits, task_line=None):
                doc, rendered, context = self._swift_module_report(
                    root, project, paths, cache, output_format, hits=hits, categories=(2, 8, 9, 20, 21),
                )
                records = doc["findings"]
                aggregates = [record for record in records if record.get("scope") == "project_aggregate"]
                self.assertEqual({record["rule"]: record["count"] for record in aggregates}, expected, context)
                self.assertEqual(len(aggregates), len(expected), context)
                for record in aggregates:
                    self.assertIs(type(record["count"]), int, record)
                    self.assertGreater(record["count"], 0, record)
                    self.assertEqual((record["path"], record["line"]), ("", 0), record)
                    self.assertFalse(record.get("samples"), record)
                    self.assertEqual(record["severity"], "warning" if record["rule"] == handle_rule else "info", record)
                # No independent source warning may hide loss/demotion of the
                # aggregate warning in either the summary or the CLI exit gate.
                self.assertEqual(doc["critical"], 0, context)
                self.assertEqual(doc["warning"], expected.get(handle_rule, 0), context)
                self.assertEqual(doc["info"], sum(count for rule, count in expected.items() if rule != handle_rule)
                                 + int(task_line is not None), context)
                notes = [record for record in records if record.get("scope") == "project"]
                expected_notes = {package_rule} if task_line is not None else {package_rule, task_rule}
                self.assertEqual({record["rule"] for record in notes}, expected_notes, context)
                self.assertEqual(len(notes), len(expected_notes), context)
                for note in notes:
                    self.assertEqual((note["path"], note["line"], note["count"], note["severity"]),
                                     ("", 0, 0, "info"), note)
                task_findings = [record for record in records if record["rule"] == task_rule
                                 and record.get("scope") != "project"]
                self.assertEqual([(record["path"], record["line"], record["col"], record["count"])
                                  for record in task_findings],
                                 [(str(balance), task_line, 1, 1)] if task_line is not None else [], context)
                for finding in task_findings:
                    self.assertNotIn("scope", finding, finding)
                if output_format == "json":
                    self.assertEqual(rendered, doc, context)
                else:
                    self.assertEqual(rendered["version"], "2.1.0", context)
                    results = [result for run in rendered["runs"] for result in run["results"]]
                    aggregate_results = [result for result in results
                                         if result.get("properties", {}).get("scope") == "project_aggregate"]
                    self.assertEqual({result["ruleId"]: result["properties"]["count"]
                                      for result in aggregate_results}, expected, context)
                    self.assertEqual(len(aggregate_results), len(expected), context)
                    for result in aggregate_results:
                        self.assertEqual(result["kind"], "fail", result)
                        self.assertEqual(result["level"], "warning" if result["ruleId"] == handle_rule else "note", result)
                        self.assertIs(type(result["properties"]["count"]), int, result)
                        self.assertGreater(result["properties"]["count"], 0, result)
                        self.assertNotIn("locations", result, result)
                    project_results = [result for result in results
                                       if result.get("properties", {}).get("scope") == "project"]
                    self.assertEqual({result["ruleId"] for result in project_results}, expected_notes, context)
                    self.assertEqual(len(project_results), len(expected_notes), context)
                    for result in project_results:
                        self.assertEqual((result["kind"], result["level"], result["properties"]["count"]),
                                         ("informational", "none", 0), result)
                        self.assertNotIn("locations", result, result)
                    task_results = [result for result in results if result["ruleId"] == task_rule
                                    and result.get("properties", {}).get("scope") != "project"]
                    self.assertEqual(len(task_results), int(task_line is not None), context)
                    for result in task_results:
                        self.assertNotIn("scope", result.get("properties", {}), result)
                        self.assertEqual(result["level"], "note", result)
                        self.assertEqual(len(result["locations"]), 1, result)
                        location = result["locations"][0]["physicalLocation"]
                        self.assertEqual(location["artifactLocation"]["uri"], str(balance), result)
                        self.assertEqual((location["region"]["startLine"], location["region"]["startColumn"]),
                                         (task_line, 1), result)
                return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

            full = [first, second, balance, *storyboards]
            expected = {async_rule: 2, actor_rule: 2, handle_rule: 2, storyboard_rule: 6}
            cold = run_aggregates(full, "json", expected, hits=0, task_line=1)
            self.assertEqual(run_aggregates(full, "sarif", expected, hits=9, task_line=1), cold)
            run_aggregates([first, balance, *storyboards[:5]], "sarif",
                           {async_rule: 1, actor_rule: 1, handle_rule: 1}, hits=7, task_line=1)
            run_aggregates([first, second, *storyboards], "json",
                           {async_rule: 3, actor_rule: 2, handle_rule: 3, storyboard_rule: 6}, hits=8)
            balance.write_text(
                "@MainActor\nfunc settle() {\n  Task {\n"
                "    await work()\n    await moreWork()\n    await finalWork()\n  }\n"
                "  handle.close()\n  other.close()\n  third.close()\n}\n",
                encoding="utf-8",
            )
            partial = run_aggregates(full, "json", {storyboard_rule: 6}, hits=8, task_line=3)
            self.assertEqual(run_aggregates(full, "sarif", {storyboard_rule: 6}, hits=9, task_line=3), partial)
            run_aggregates([balance, *storyboards[:5]], "sarif", {}, hits=6, task_line=3)


class RustSqlSourceTests(unittest.TestCase):
    RULE = "rust.security.sql-injection"

    def _fixtures(self, root: Path):
        project = root / "project"
        project.mkdir()
        sources = {}
        expected = {}
        expressions = {
            "constructor": "Path(route_param()).0",
            "qualified-constructor": "axum::extract::Path(route_param()).0",
            "request": "req.path()",
            "query": 'query.get("tenant").cloned().unwrap_or_default()',
            "arguments": "std::env::args().nth(1).unwrap_or_default()",
        }
        for name, expression in expressions.items():
            path = project / f"{name}.rs"
            sources[path] = (
                "fn route(conn: &Connection, req: Request, query: QueryMap) {\n"
                f"    let tenant = {expression};\n"
                "    let alias = tenant;\n"
                '    let sql = format!("SELECT id FROM tenants WHERE name = \'{}\'", alias);\n'
                "    conn.execute(&sql, []);\n}\n"
            )
            expected[path] = 5
        extracted = project / "extractor.rs"
        sources[extracted] = (
            "fn route(Path(tenant): Path<String>, conn: &Connection) {\n"
            "    let alias = tenant;\n"
            '    let sql = format!("SELECT id FROM tenants WHERE name = \'{}\'", alias);\n'
            "    conn.execute(&sql, []);\n}\n"
        )
        expected[extracted] = 4
        for name, expression in (("filesystem", "temp.path()"),
                                 ("filesystem-spaced", "temp . path ()")):
            sources[project / f"{name}.rs"] = (
                # Keep a real request source in this same file, so rejecting
                # the filesystem case cannot rely on the file prefilter alone.
                "fn bound(Path(tenant): Path<String>, conn: &Connection) {\n"
                '    sqlx::query("SELECT id FROM tenants WHERE name = $1").bind(tenant);\n}\n'
                "fn inventory(conn: &Connection) {\n"
                '    let temp = tempfile::TempDir::new().expect("tempdir");\n'
                f'    let source_path = {expression}.join("session.jsonl");\n'
                "    let alias = source_path.display();\n"
                "    conn.execute_batch(&format!(\n"
                '        "CREATE TABLE sources (path TEXT); INSERT INTO sources VALUES (\'{}\');",\n'
                "        alias,\n    ));\n}\n"
            )
        sources[project / "parameterized-request.rs"] = (
            "fn bound(req: Request, conn: &Connection) {\n"
            "    let tenant = req.path();\n    let alias = tenant;\n"
            '    sqlx::query("SELECT id FROM tenants WHERE name = $1").bind(alias);\n}\n'
        )
        sources[project / "checked-query.rs"] = (
            "fn checked(query: QueryMap) {\n"
            '    let tenant = query.get("tenant");\n'
            '    sqlx::query!("SELECT id FROM tenants WHERE name = $1", tenant);\n}\n'
        )
        for path, source in sources.items():
            path.write_text(source, encoding="utf-8")
        return project, list(sources), expected

    def test_real_sql_detector_distinguishes_request_path_from_filesystem_path(self) -> None:
        from ubs_core.rust_detectors import sql_injection

        with tempfile.TemporaryDirectory(prefix="ubs-rust-sql-sources-") as temp:
            _project, paths, expected = self._fixtures(Path(temp).resolve())
            for selected in (paths, list(reversed(paths)), [p for p in paths if p not in expected]):
                with self.subTest(selected=selected):
                    findings = list(sql_injection.find(selected))
                    self.assertCountEqual(
                        [(path, line, col) for path, line, col, _text in findings],
                        [(path, expected[path], 1) for path in selected if path in expected],
                    )
                    for path, line, _col, text in findings:
                        self.assertIn(path.read_text(encoding="utf-8").splitlines()[line - 1].strip(), text)
                        self.assertIn("SQL execution", text)

    def test_public_rust_sql_sources_preserve_cold_warm_and_partial_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-rust-sql-public-") as temp:
            root = Path(temp).resolve()
            project, paths, expected = self._fixtures(root)
            cache = root / "cache"

            def scan(selected, output_format, expected_sites, hits):
                artifacts = Path(tempfile.mkdtemp(prefix="report-", dir=root))
                inputs, sink, stats = (artifacts / name for name in ("files.txt", "findings.ndjson", "cache.json"))
                inputs.write_text("\n".join(str(path) for path in selected) + "\n", encoding="utf-8")
                command = [
                    "bash", str(REPO_ROOT / "modules" / "ubs-rust.sh"),
                    "--ci", "--no-color", "--no-cargo", "--fail-on-warning", "--only=8",
                    f"--format={output_format}", f"--files-from={inputs}", f"--report-json={sink}", str(project),
                ]
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                           UBS_CACHE_DIR=str(cache), UBS_CACHE_FILE=str(stats), UBS_PROFILE="1",
                           UBS_SKIP_TYPE_NARROWING="1", UBS_TEST_FORCE_NO_AST_GREP="0",
                           UBS_ALLOW_UNVERIFIED_HELPERS="0", UBS_NO_AUTO_UPDATE="1")
                proc = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed repository scanner and local Rust source fixtures; bounded real CLI regression
                context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                self.assertEqual(proc.returncode, int(bool(expected_sites)), context)
                try:
                    payload = json.loads(proc.stdout)
                    records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                    cache_stats = json.loads(stats.read_text(encoding="utf-8"))
                except (ValueError, OSError) as exc:
                    self.fail(f"Invalid Rust SQL report: {exc}\n{context}")
                self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                                 (hits, len(selected) - hits), context)
                wanted = [(self.RULE, str(path), line, 1, "critical")
                          for path, line in expected_sites.items()]
                self.assertCountEqual(
                    [(record["rule"], record["path"], record["line"], record["col"], record["severity"])
                     for record in records], wanted, context,
                )
                self.assertTrue(all(record.get("count", 1) == 1 for record in records), context)
                if output_format == "json":
                    self.assertEqual(payload["status"], "ok", context)
                    self.assertEqual(payload["files"], len(selected), context)
                    self.assertEqual((payload["critical"], payload["warning"], payload["info"]),
                                     (len(wanted), 0, 0), context)
                else:
                    self.assertEqual(payload["version"], "2.1.0", context)
                    results = [result for run in payload["runs"] for result in run["results"]]
                    actual = []
                    for result in results:
                        self.assertEqual(len(result["locations"]), 1, result)
                        physical = result["locations"][0]["physicalLocation"]
                        actual.append((result["ruleId"], physical["artifactLocation"]["uri"],
                                       physical["region"]["startLine"], physical["region"]["startColumn"], result["level"]))
                    self.assertCountEqual(actual, [(rule, path, line, col, "error")
                                                   for rule, path, line, col, _severity in wanted], context)
                return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

            cold = scan(paths, "json", expected, 0)
            self.assertEqual(scan(paths, "sarif", expected, len(paths)), cold)
            clean = [path for path in paths if path not in expected]
            self.assertEqual(scan(clean, "json", {}, len(clean)), [])
            changed = project / "constructor.rs"
            changed.write_text(changed.read_text(encoding="utf-8").replace(
                "Path(route_param()).0", 'std::path::Path::new("local.db").display()'), encoding="utf-8")
            remaining = {path: line for path, line in expected.items() if path != changed}
            partial = scan(paths, "json", remaining, len(paths) - 1)
            self.assertEqual(partial, [record for record in cold if record["path"] != str(changed)])
            self.assertEqual(scan(paths, "sarif", remaining, len(paths)), partial)


if __name__ == "__main__":
    unittest.main()
