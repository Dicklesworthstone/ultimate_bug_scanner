#!/usr/bin/env python3
"""Unit tests for ubs_core stdlib helper library (bead A2)."""
from __future__ import annotations

import ast
import hashlib
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import (
    extract_statement_region,
    find_block_end,
    format_location,
    line_col,
    python_source_segment,
    skip_ws,
)
from ubs_core.lexer import (
    Interval,
    Span,
    strip_comments_and_strings,
)


def sarif_uri(path) -> str:
    """The SARIF 2.1.0 section 3.10 artifact URI of a native path, computed independently.

    An absolute path is a file URI (pathlib's own encoding); a relative path is
    a percent-encoded relative reference.
    """
    from urllib.parse import quote

    native = Path(path)
    return native.as_uri() if native.is_absolute() else quote(str(path))


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
    def test_python_source_segments_match_ast_byte_coordinates(self) -> None:
        sources = (
            "é = '💡'; answer = (\n    café[0]\n    + 1\n)\n",
            "value = 'inside\u2028separator';\fprint(value)\n",
            "def f():\n\treturn '''one\n two\n three'''\n",
            "# blank\n\nresult = call(\n    left,\n    right,\n)\n",
        )
        for source in sources:
            for newline in ('\n', '\r\n', '\r'):
                code = source.replace('\n', newline)
                with self.subTest(source=source, newline=newline):
                    for node in ast.walk(ast.parse(code)):
                        self.assertEqual(python_source_segment(code, node),
                                         ast.get_source_segment(code, node))

    def test_python_source_segment_missing_locations(self) -> None:
        self.assertIsNone(python_source_segment('value', ast.Name(id='value')))
        node = ast.parse('value').body[0]
        node.end_lineno = None
        self.assertIsNone(python_source_segment('value', node))

    def test_python_source_segment_cache_does_not_reuse_other_text(self) -> None:
        node = ast.parse('first = 12').body[0].value
        for source in ('first = 12', 'other = 34', 'first = 12'):
            self.assertEqual(python_source_segment(source, node),
                             ast.get_source_segment(source, node))

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


class KeepTempHelperTests(unittest.TestCase):
    """Real retention-mode helper operations; every artifact is left in place."""

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="ubs-keep-helper-", dir=artifacts))
        self.saved_environment = {key: os.environ.get(key)
                                  for key in ("UBS_KEEP_TEMP", "TMPDIR", "TEMP", "TMP")}
        self.saved_tempdir = tempfile.tempdir
        os.environ["UBS_KEEP_TEMP"] = "1"
        for key in ("TMPDIR", "TEMP", "TMP"):
            os.environ[key] = str(self.root)
        tempfile.tempdir = str(self.root)

    def tearDown(self) -> None:
        tempfile.tempdir = self.saved_tempdir
        for key, value in self.saved_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_directories_survive_normal_and_exceptional_exit(self) -> None:
        from ubs_core.io import temporary_directory

        with temporary_directory(prefix="success-") as success:
            (Path(success) / "evidence.txt").write_text("completed\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "retention probe"):
            with temporary_directory(prefix="failure-") as failure:
                (Path(failure) / "evidence.txt").write_text("partial\n", encoding="utf-8")
                raise RuntimeError("retention probe")
        self.assertEqual((Path(success) / "evidence.txt").read_text(encoding="utf-8"), "completed\n")
        self.assertEqual((Path(failure) / "evidence.txt").read_text(encoding="utf-8"), "partial\n")

    def test_named_and_anonymous_streams_retain_closed_bytes(self) -> None:
        from ubs_core.io import temporary_file

        for named in (False, True):
            with self.subTest(named=named):
                with temporary_file(mode="w+", encoding="utf-8", named=named) as stream:
                    path = Path(stream.name)
                    stream.write("retained \u03bb\n")
                    stream.seek(0)
                    self.assertEqual(stream.read(), "retained \u03bb\n")
                self.assertTrue(stream.closed)
                self.assertEqual(path.read_text(encoding="utf-8"), "retained \u03bb\n")
                with self.assertRaisesRegex(RuntimeError, "stream unwind"):
                    with temporary_file(mode="w+", encoding="utf-8", named=named) as failed:
                        failed_path = Path(failed.name)
                        failed.write("partial stream\n")
                        raise RuntimeError("stream unwind")
                self.assertTrue(failed.closed)
                self.assertEqual(failed_path.read_text(encoding="utf-8"), "partial stream\n")

    def test_fresh_process_avoids_tempdir_probe_and_rejects_invalid_override(self) -> None:
        script = r'''
import json
import os
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, sys.argv[1])
from ubs_core.io import temporary_directory, temporary_file
assert tempfile.tempdir is None
def reject_deletion(event, arguments):
    if event in {"os.remove", "os.rmdir"}:
        raise AssertionError(f"unexpected deletion: {event} {arguments!r}")
sys.addaudithook(reject_deletion)
root = Path(sys.argv[2])
with temporary_directory(prefix="fresh-dir-") as directory:
    (Path(directory) / "evidence.txt").write_text("fresh", encoding="utf-8")
with temporary_file(mode="w+", encoding="utf-8", prefix="fresh-file-") as stream:
    stream.write("fresh")
    filename = stream.name
assert tempfile.tempdir is None
assert Path(directory).parent == root
assert Path(filename).parent == root
assert Path(filename).read_text(encoding="utf-8") == "fresh"
os.environ["TMPDIR"] = str(root / "does-not-exist")
try:
    with temporary_directory():
        raise AssertionError("invalid TMPDIR accepted")
except NotADirectoryError:
    pass
else:
    raise AssertionError("invalid TMPDIR did not fail")
print(json.dumps({"directory": directory, "filename": filename}))
'''
        command = [sys.executable, "-B", "-c", script, str(HELPERS_DIR), str(self.root)]
        result = subprocess.run(command, cwd=self.root, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        evidence = json.loads(result.stdout)
        self.assertTrue(Path(evidence["directory"]).is_dir())
        self.assertTrue(Path(evidence["filename"]).is_file())

    def test_real_failed_subprocess_retains_stdout_stderr_and_exit(self) -> None:
        from ubs_core.external_tools import run_command_stream

        errors = []
        command = [sys.executable, "-B", "-c",
                   "import sys; sys.stdout.buffer.write(b'finding\\n'); "
                   "sys.stderr.buffer.write(b'diagnostic\\n'); sys.exit(7)"]
        with run_command_stream("retention probe", command, self.root, 10, errors) as output:
            self.assertIsNotNone(output, errors)
            self.assertEqual(output.returncode, 7)
            self.assertEqual(output.stdout.read(), b"finding\n")
            self.assertEqual(output.stderr, "diagnostic\n")
            self.assertIsNotNone(output.stderr_stream)
            stdout_path = Path(output.stdout.name)
            stderr_path = Path(output.stderr_stream.name)
        self.assertEqual(errors, [])
        self.assertEqual(stdout_path.read_bytes(), b"finding\n")
        self.assertEqual(stderr_path.read_bytes(), b"diagnostic\n")

    def test_merge_retains_staging_and_spool_without_changing_findings(self) -> None:
        from ubs_core.findings_merge import merge

        source = self.root / "sample.py"
        source.write_text("eval(value)\n", encoding="utf-8")
        summary = self.root / "combined.json"
        original = {"scanners": [{"language": "python", "critical": 1, "warning": 0, "info": 0}],
                    "totals": {"critical": 1, "warning": 0, "info": 0}}
        summary.write_text(json.dumps(original), encoding="utf-8")
        original_inode = summary.stat().st_ino
        sink = self.root / "python.findings.json"
        sink.write_text(json.dumps({"rule": "python.taint.eval", "path": str(source),
                                    "line": 1, "col": 1, "severity": "critical",
                                    "message": "untrusted evaluation"}) + "\n", encoding="utf-8")
        self.assertEqual(merge(self.root, summary, project_dir=self.root), 1)
        report = json.loads(summary.read_text(encoding="utf-8"))
        self.assertEqual(report["totals"], original["totals"])
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule_id"], "python.taint.eval")
        self.assertEqual(report["findings"][0]["severity"], "critical")
        self.assertEqual(report["findings"][0]["message"], "untrusted evaluation")
        if os.name == "posix":
            self.assertNotEqual(summary.stat().st_ino, original_inode)
        self.assertEqual(len(list(self.root.glob(".ubs-findings-*"))), 1)
        spools = list(self.root.glob("ubs-findings-*"))
        self.assertEqual(len(spools), 1)
        self.assertEqual(json.loads(spools[0].read_text(encoding="utf-8")), report["findings"][0])

        invalid = self.root / "invalid"
        invalid.mkdir()
        failed_summary = invalid / "combined.json"
        original_bytes = json.dumps(original).encode("utf-8")
        failed_summary.write_bytes(original_bytes)
        (invalid / "python.findings.json").write_text("{not-json}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid findings sink"):
            merge(invalid, failed_summary, project_dir=self.root)
        self.assertEqual(failed_summary.read_bytes(), original_bytes)
        self.assertEqual(len(list(self.root.glob("ubs-findings-*"))), 2)

    def test_sqlite_spills_retain_rows_and_journals_after_close(self) -> None:
        import sqlite3
        from ubs_core.findings_merge import _BaselineFilter, _OccurrenceOrdinals

        ordinals = _OccurrenceOrdinals()
        try:
            for index in range(4100):
                self.assertEqual(ordinals.next(f"file-{index}", "rule", "statement"), 0)
            self.assertEqual(ordinals.next("file-0", "rule", "statement"), 1)
            ordinal_path = Path(ordinals._db.execute("PRAGMA database_list").fetchone()[2])
            self.assertEqual(ordinals._db.execute("PRAGMA journal_mode").fetchone(), ("persist",))
            self.assertEqual(ordinals._db.execute("PRAGMA cache_size").fetchone(), (-2048,))
        finally:
            ordinals.close()
        self.assertTrue(Path(str(ordinal_path) + "-journal").is_file())
        connection = sqlite3.connect(ordinal_path.as_uri() + "?mode=ro", uri=True)
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM counts").fetchone(), (4100,))
            self.assertEqual(connection.execute("SELECT n FROM counts WHERE path = ?", ("file-0",)).fetchone(), (2,))
        finally:
            connection.close()

        baseline_path = self.root / "baseline.json"
        baseline_path.write_text(json.dumps([f"fp-{index}" for index in range(4100)]), encoding="utf-8")
        baseline = _BaselineFilter(baseline_path)
        try:
            finding = {"fingerprint": "fp-0", "lang": "python", "severity": "warning"}
            self.assertIsNone(baseline.retain(finding))
            self.assertEqual(baseline.retain(finding), finding)
            database_path = Path(baseline._db.execute("PRAGMA database_list").fetchone()[2])
            self.assertEqual(baseline._db.execute("PRAGMA temp_store").fetchone(), (2,))
        finally:
            baseline.close()
        self.assertTrue(Path(str(database_path) + "-journal").is_file())
        connection = sqlite3.connect(database_path.as_uri() + "?mode=ro", uri=True)
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM allowances").fetchone(), (4100,))
            self.assertEqual(connection.execute("SELECT remaining FROM allowances WHERE fingerprint = ?",
                                                (b"fp-0",)).fetchone(), ("0",))
        finally:
            connection.close()

    def test_cache_pruning_and_failed_atomic_write_retain_evidence(self) -> None:
        from ubs_core.cache import atomic_write_json, prune_cache

        cache = self.root / "cache"
        cache.mkdir()
        entry = cache / "entry.json"
        entry.write_text('{"critical": 1}\n', encoding="utf-8")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(prune_cache(cache, prune_all=True), (0, 0))
        self.assertIn("cache pruning skipped", stderr.getvalue())
        self.assertEqual(entry.read_text(encoding="utf-8"), '{"critical": 1}\n')

        # A directory destination is a real publication failure, without an
        # injected exception or a platform-dependent permission simulation.
        destination = cache / "directory.json"
        destination.mkdir()
        atomic_write_json(destination, {"partial": True})
        retained = list(cache.glob(".tmp.*"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(json.loads(retained[0].read_text(encoding="utf-8")), {"partial": True})
        self.assertTrue(destination.is_dir())

    def test_guarded_json_readers_report_bad_tail_and_retain_valid_prefix(self) -> None:
        from ubs_core.external_tools import GoFindings, _ReportErrors, _json_stream

        source = self.root / "source.go"
        source.write_text("package fixture\n", encoding="utf-8")
        vet_prefix = json.dumps({"fixture": {"printf": [
            {"posn": f"{source}:1:1", "message": "valid prefix diagnostic"}
        ]}}).encode("utf-8") + b"\n"
        for tail in (b'{"bad":tru}', b'{"bad":"\xff"}', b'NaN'):
            with self.subTest(tail=tail):
                stream_errors = []
                records = list(_json_stream(io.BytesIO(b'{"valid":1}\n' + tail),
                                            "reader probe", _ReportErrors(stream_errors, "reader probe")))
                self.assertEqual(records, [{"valid": 1}])
                self.assertTrue(any("invalid or truncated JSON report" in error for error in stream_errors))

                sink, vet_errors = io.StringIO(), []
                GoFindings([source], self.root, sink).vet(io.BytesIO(vet_prefix + tail), vet_errors)
                row = json.loads(sink.getvalue())
                self.assertEqual(row["message"], "valid prefix diagnostic")
                self.assertEqual(row["severity"], "warning")
                self.assertTrue(any("invalid or truncated JSON report" in error for error in vet_errors))


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


class PythonTaintDataflowTests(unittest.TestCase):
    """Source-to-sink regressions for the function-scoped Python frontend."""

    def run(self, result=None):
        result = result if result is not None else self.defaultTestResult()
        failures = len(result.failures) + len(result.errors)
        case = self.id().rsplit('.', 1)[-1]
        start = time.monotonic()
        print(f'[{case}] RUN', flush=True)
        super().run(result)
        status = 'PASS' if len(result.failures) + len(result.errors) == failures else 'FAIL'
        print(f'[{case}] {status} ({time.monotonic() - start:.3f}s)', flush=True)
        return result

    def test_local_names_of_a_function_scope(self):
        # A merge left a second, never-bound `scope_nodes` default inside
        # _local_names, so every function scope raised UnboundLocalError and
        # every Python scan that reached taint analysis exited 2.
        import ast
        from ubs_core.analyzers import taint_py

        function = ast.parse('def run(value, *rest, key=None):\n'
                             '    total = value\n'
                             '    for item in rest:\n'
                             '        pass\n'
                             '    return [x for x in rest]\n').body[0]
        expected = {'value', 'rest', 'key', 'total', 'item'}
        self.assertEqual(taint_py._local_names(function), expected)
        self.assertEqual(taint_py._local_names(function, tuple(taint_py._scope_nodes(function))), expected)
        _, records = self.findings('def run(value):\n    eval(value)\n')
        self.assertEqual(records, [])

    def findings(self, source: str) -> tuple[str, list[dict]]:
        from ubs_core.analyzers import taint_py
        from ubs_core.registry import RunContext

        source = textwrap.dedent(source).lstrip('\n')
        artifacts = REPO_ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='python-taint-', dir=artifacts) as tmp:
            path = Path(tmp) / 'flow.py'
            path.write_text(source, encoding='utf-8')
            records = list(taint_py.run(RunContext(lang='python', files=[path])))
        return source, records

    def assert_sites(self, source: str, expected: dict[str, str]) -> list[dict]:
        source, records = self.findings(source)
        wanted = {
            (f'python.taint.{kind}', number)
            for marker, kind in expected.items()
            for number, line in enumerate(source.splitlines(), 1)
            if f'# {marker}' in line
        }
        self.assertEqual(len(wanted), len(expected), f'missing fixture markers: {expected}\n{source}')
        self.assertEqual({(row['rule'], row['line']) for row in records}, wanted,
                         f'source:\n{source}\nfindings:\n{json.dumps(records, indent=2)}')
        self.assertEqual(len(records), len(wanted), records)
        return records

    def test_same_named_locals_and_assignment_order_are_independent(self) -> None:
        self.assert_sites('''
            def dangerous():
                value = request.args['value']
                eval(value)  # unsafe-local

            def unrelated(value):
                eval(value)

            def overwritten():
                value = request.args['value']
                value = '1 + 1'
                eval(value)

            def later_source():
                value = '1 + 1'
                eval(value)
                value = request.args['value']

            def unreachable():
                return
                eval(request.args['value'])
        ''', {'unsafe-local': 'eval'})

    def test_literals_comments_and_multiline_calls_use_python_syntax(self) -> None:
        self.assert_sites('''
            documentation = "eval(request.args['value'])"
            value = 'request.args.get("value")'
            eval(value)
            # eval(request.args['comment'])
            value = (
                request.args.get('value#still-inside-string')
            )
            eval(  # multiline-sink
                value
            )
        ''', {'multiline-sink': 'eval'})

    def test_local_return_and_sink_summaries_bind_keywords_and_defaults(self) -> None:
        records = self.assert_sites('''
            def identity(value):
                return value

            def constant(value):
                return '1 + 1'

            def source():
                return request.args.get('code')

            def execute(value, suffix=''):
                eval(value + suffix)  # helper-sink

            def default_source(value=request.args.get('default')):
                return value

            payload = request.args.get('code')
            copied = identity(value=payload)
            eval(copied)  # returned-value
            execute(suffix='', value=payload)
            eval(source())  # source-helper
            eval(default_source())  # default-value
            eval(constant(payload))
            execute(value='1 + 1')
        ''', {'helper-sink': 'eval', 'returned-value': 'eval', 'source-helper': 'eval', 'default-value': 'eval'})
        self.assertTrue(any('identity()' in row['message'] for row in records), records)
        self.assertTrue(any('execute()' in row['message'] for row in records), records)
        for row in records:
            self.assertIn('request.args', row['message'])
            self.assertTrue(row['message'].endswith(' -> eval)'), row)

    def test_branch_joins_keep_only_reachable_unsanitized_values(self) -> None:
        self.assert_sites('''
            def partly_clean(flag):
                value = request.args['value']
                if flag:
                    value = html.escape(value)
                Response(value)  # partly-escaped

            def fully_clean(flag):
                value = request.args['value']
                if flag:
                    value = 'safe'
                else:
                    value = html.escape(value)
                Response(value)

            def returned_branch(flag):
                value = request.args['value']
                if flag:
                    return value
                else:
                    value = 'safe'
                eval(value)
        ''', {'partly-escaped': 'xss'})

    def test_nested_helpers_capture_only_their_own_enclosing_scope(self) -> None:
        self.assert_sites('''
            def handler():
                value = request.args['code']
                def read():
                    return value
                def execute():
                    eval(value)  # captured-sink
                eval(read())  # captured-return
                execute()

            def unrelated():
                value = '1 + 1'
                def read():
                    return value
                eval(read())
        ''', {'captured-sink': 'eval', 'captured-return': 'eval'})

    def test_callable_rebinding_and_branch_imports_revoke_safe_summaries(self) -> None:
        self.assert_sites('''
            def clean(value):
                return 'safe'
            clean = lambda value: value
            os.system(clean(request.args['command']))  # rebound-helper

            if flag:
                from html import escape as escape_text
            else:
                escape_text = lambda value: value
            Response(escape_text(request.args['html']))  # branch-dependent-import

            if flag:
                from html import escape as other_escape
            else:
                Response(other_escape(request.args['html']))  # sibling-branch

            from html import escape as always_escape
            Response(always_escape(request.args['html']))
        ''', {'rebound-helper': 'command', 'branch-dependent-import': 'xss', 'sibling-branch': 'xss'})

    def test_global_values_are_bound_at_call_sites_and_finally_keeps_return_paths(self) -> None:
        self.assert_sites('''
            value = input()
            def run():
                eval(value)  # early-global-call
            run()
            value = 'safe'

            def handler(flag):
                code = 'safe'
                try:
                    if flag:
                        code = input()
                        return
                finally:
                    eval(code)  # finally-after-return
        ''', {'early-global-call': 'eval', 'finally-after-return': 'eval'})

    def test_conditional_assignments_definition_execution_and_unpacking(self) -> None:
        self.assert_sites('''
            value = input()
            flag and (value := 'safe')
            eval(value)  # short-circuit-assignment
            unused = None if flag else (value := 'safe')
            eval(value)  # conditional-assignment

            def configure(value=eval(input())):  # definition-default
                pass

            class Initialization:
                value = input()
                eval(value)  # class-body

            first = input()
            second = 'safe'
            first, second = second, first
            eval(second)  # simultaneous-unpacking
            eval(first)

            last = 'safe'
            [(last := input()) for _ in range(1)]
            eval(last)  # enclosing-comprehension-assignment

            pattern = input()
            formatted = pattern.format(pattern := 'safe')
            eval(formatted)  # receiver-before-arguments
        ''', {'short-circuit-assignment': 'eval', 'conditional-assignment': 'eval',
              'definition-default': 'eval', 'class-body': 'eval', 'simultaneous-unpacking': 'eval',
              'enclosing-comprehension-assignment': 'eval', 'receiver-before-arguments': 'eval'})

    def test_loop_and_recursive_summary_fixpoints_terminate_and_propagate(self) -> None:
        self.assert_sites('''
            def recursive(value, stop):
                if stop:
                    return value
                return recursive(value, True)

            eval(recursive(request.args['value'], False))  # recursive-return

            value = '1 + 1'
            while keep_going():
                eval(value)  # loop-carried
                value = request.args['next']
                if finished():
                    break

            value = request.args['code']
            while keep_going():
                value = 'safe'
                eval(value)
                continue
                eval(request.args['dead'])
        ''', {'recursive-return': 'eval', 'loop-carried': 'eval'})

    def test_local_helper_chains_have_no_five_assignment_limit(self) -> None:
        source = '\n'.join(
            f'def helper_{index}(value):\n    return helper_{index + 1}(value)\n'
            for index in range(12)
        )
        source += "def helper_12(value):\n    return value\n"
        source += "eval(helper_0(request.args['value']))  # long-chain\n"
        records = self.assert_sites(source, {'long-chain': 'eval'})
        self.assertIn('request.args', records[0]['message'])

    def test_sanitizers_are_specific_to_the_sink_and_each_flow(self) -> None:
        self.assert_sites('''
            import html as markup
            from shlex import quote as shell_quote
            from django.utils.safestring import mark_safe

            def render(value):
                Response(value)  # helper-html

            def clean_html(value):
                return markup.escape(value)

            value = request.args['value']
            escaped = clean_html(value)
            Response(escaped)
            cursor.execute(escaped)  # html-is-not-sql-escaping
            eval(escaped)  # html-is-not-code-escaping
            Response(mark_safe(value))  # trust-is-not-escaping
            Response(markup.escape(value) + request.args['raw'])  # mixed-flow
            render(escaped)
            render(value)
            os.system('printf %s ' + shell_quote(value))
            eval(shell_quote(value))  # shell-is-not-code-escaping
        ''', {'helper-html': 'xss', 'html-is-not-sql-escaping': 'sql', 'html-is-not-code-escaping': 'eval',
              'trust-is-not-escaping': 'xss', 'mixed-flow': 'xss', 'shell-is-not-code-escaping': 'eval'})
        self.assert_sites('''
            def render(value):
                Response(value)
            render(html.escape(request.args['value']))
        ''', {})

    def test_sql_parameters_and_fixed_subprocess_argv_are_data(self) -> None:
        self.assert_sites('''
            import subprocess as process
            from subprocess import run as execute_process
            value = request.args['value']
            cursor.execute('SELECT * FROM users WHERE name = ?', (value,))
            cursor.execute(query='SELECT * FROM users WHERE name = ?', parameters=[value])
            cursor.execute('SELECT * FROM ' + value, ())  # dynamic-query-with-params
            process.run(['printf', '%s', value], timeout=5)
            execute_process(args=['printf', '%s', value], shell=False, timeout=5)
            process.run([value, '--version'], timeout=5)  # executable
            execute_process(value, shell=True, timeout=5)  # shell-command
        ''', {'dynamic-query-with-params': 'sql', 'executable': 'command', 'shell-command': 'command'})

    def test_suppression_requires_real_comment_and_matching_rule(self) -> None:
        self.assert_sites('''
            value = request.args['value']
            text = 'ubs:ignore'
            eval(value)  # string-marker-is-not-suppression
            eval(value)  # wrong-rule ubs:ignore[python.taint.sql]
            eval(
                value  # ubs:ignore[python.taint.eval]
            )
            # ubs:ignore[py.taint.eval]
            eval(value)
        ''', {'string-marker-is-not-suppression': 'eval', 'wrong-rule': 'eval'})

    def test_fact_join_laws_include_sanitizer_variants(self) -> None:
        from ubs_core.analyzers.taint_py import CLEAN, TaintTrace, join_facts

        facts = [CLEAN, frozenset({TaintTrace('request.args', path=('request.args',))}),
                 frozenset({TaintTrace('request.args', sanitizers=frozenset({'xss'}), path=('request.args', 'escape'))}),
                 frozenset({TaintTrace('other', parameter='other', path=('other',))})]
        for first in facts:
            self.assertEqual(join_facts(first, first), first)
            for second in facts:
                self.assertEqual(join_facts(first, second), join_facts(second, first))
                for third in facts:
                    self.assertEqual(join_facts(join_facts(first, second), third),
                                     join_facts(first, join_facts(second, third)))

    def test_existing_python_taint_fixture_pair(self) -> None:
        from ubs_core.analyzers.taint_py import scan_file_findings

        buggy = REPO_ROOT / 'test-suite/python/buggy/taint_analysis.py'
        clean = REPO_ROOT / 'test-suite/python/clean/taint_analysis.py'
        self.assertEqual([(rule, line) for rule, line, _, _ in scan_file_findings(buggy)],
                         [('py.taint.sql', 17), ('py.taint.command', 22), ('py.taint.eval', 27)])
        self.assertEqual(list(scan_file_findings(clean)), [])

    def test_real_python_module_reports_helper_sinks_and_clean_controls(self) -> None:
        artifacts = REPO_ROOT / 'test-suite/artifacts/python-taint-module'
        project = artifacts / 'project'
        project.mkdir(parents=True, exist_ok=True)
        source = project / 'flow.py'
        source.write_text(textwrap.dedent('''
            def transform(value):
                return value.strip()

            def evaluate(value):
                eval(value)

            def handler():
                evaluate(transform(request.args['code']))

            def unrelated():
                value = 'safe'
                evaluate(value)
        ''').lstrip('\n'), encoding='utf-8')
        report = artifacts / 'findings.ndjson'
        command = [
            'bash', str(REPO_ROOT / 'modules/ubs-python.sh'), '--ci', '--no-color',
            '--format=json', '--skip=1,2,3,4,5,6,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23',
            f'--report-json={report}', str(project),
        ]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', UBS_NO_CACHE='1',
                   UBS_NO_AUTO_UPDATE='1', UBS_SKIP_TYPE_NARROWING='1')
        proc = subprocess.run(command, cwd=artifacts, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - real module over a fixed local source fixture with a bounded timeout
        (artifacts / 'stdout.log').write_text(proc.stdout, encoding='utf-8')
        (artifacts / 'stderr.log').write_text(proc.stderr, encoding='utf-8')
        (artifacts / 'result.json').write_text(proc.stdout, encoding='utf-8')
        context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, 1, context)
        try:
            payload = json.loads(proc.stdout)
            records = [json.loads(line) for line in report.read_text(encoding='utf-8').splitlines()]
        except (ValueError, OSError) as exc:
            self.fail(f'Invalid Python module report: {exc}\n{context}')
        self.assertEqual(payload['status'], 'ok', context)
        taint = [row for row in records if row['rule'].startswith('python.taint.')]
        self.assertEqual([(row['rule'], row['path'], row['line'], row['col']) for row in taint],
                         [('python.taint.eval', str(source.resolve()), 5, 5)], context)
        self.assertIn('request.args', taint[0]['message'], context)
        self.assertIn('evaluate()', taint[0]['message'], context)


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
                            self.assertEqual(location["artifactLocation"]["uri"], sarif_uri(source), result)
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
                        self.assertEqual(location["artifactLocation"]["uri"], sarif_uri(balance), result)
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
                    self.assertCountEqual(actual, [(rule, sarif_uri(path), line, col, "error")
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


class RustInputBoundaryTests(unittest.TestCase):
    URL_RULE = "rust.security.request-url"
    COMMAND_RULE = "rust.security.command-executable"

    def _fixtures(self, root: Path):
        project = root / "project"
        project.mkdir()
        sources = {}
        expected = []

        def add(name, source, url_lines=(), command_lines=(), companions=()):
            path = project / name
            sources[path] = source
            expected.extend((path, line, self.URL_RULE) for line in url_lines)
            expected.extend((path, line, self.COMMAND_RULE) for line in command_lines)
            expected.extend((path, line, rule) for line, rule in companions)

        add("cass-release-probes.rs", '''fn old_fixture() {
    let data_dir = std::env::args().nth(1);
    let db_path = data_dir;
    let build = reconstruct(db_path);
}
fn gather_live_release_observations() {
    let client = reqwest::blocking::Client::builder()
        .user_agent("cass/test")
        .build().ok();
    client.get("https://api.github.com/repos/example/example/releases/latest");
}
fn probe_json_version(client: &Client, url: &str) {
    let response = client.get(url).send().ok();
}
fn probe_text_version(client: &Client, url: &str) {
    let response = client.get(url).send().ok();
}
''')
        add("url-shadow.rs", '''fn route(req: Request, client: Client) {
    let url = req.query_string();
    {
        let url = "https://example.com/fixed";
        client.get(url);
    }
    client.get(url);
    fn independent(client: Client, url: &str) { client.get(url); }
    client.get(url);
    let callback = |url: &str| { client.get(url); };
    let captured = || { client.get(url); };
}
''', url_lines=(7, 9, 11))
        add("url-reassign.rs", '''fn route(req: Request, client: Client, flag: bool) {
    let mut url = req.query_string();
    url = "https://example.com/fixed";
    client.get(url);
    url = req.query_string();
    client.get(url);
    if flag { url = "https://example.com/branch"; }
    client.get(url);
}
''', url_lines=(6, 8))
        add("url-arguments.rs", '''fn route(req: Request, client: Client) {
    let method = req.query_string();
    client.request(method, "https://example.com/fixed");
    client.request(Method::GET, req.query_string());
    let host = req.host();
    client.get(format!("https://{host}/resource"));
    client.get("https://example.com/host");
}
''', url_lines=(4, 6), companions=((6, "rust.security.host-header-url"),))
        add("url-multiline.rs", '''fn route(req: Request, client: Client) {
    let url: String = req
        .query_string();
    let alias = url;
    client
        .get(
            alias
        );
}
''', url_lines=(5,))
        add("url-markers.rs", '''fn route(req: Request, client: Client) {
    let url = req.query_string(); // ubs:ignore[rust.security.request-url]

    client.get(url);
    client.get(url); // ubs:ignore[rust.other]
    client.get(url); // ubs:ignore[rust.security.request-url]
    client.get(url); // ubs:ignore
    client.get(url); let note = "ubs:ignore";
}
''', url_lines=(4, 5, 8))
        add("url-bare-source.rs", '''fn route(req: Request, client: Client) {
    let url = req.query_string(); // ubs:ignore

    client.get(url);
}
''')
        add("url-same-line-functions.rs", '''fn earlier(req: Request) { let url = req.query_string(); } fn later(url: &str, client: Client) { client.get(url); }
''')
        add("url-callee-collision.rs", '''fn route(req: Request, client: Client) {
    let build = req.query_string();
    let fixed = make_client().build();
    client.get(fixed);
    let url = req.query_string();
    client.get(normalize(url));
}
''', url_lines=(6,))
        add("url-validated.rs", '''fn route(req: Request, client: Client) {
    let url = req.query_string();
    let safe_url = validate_outbound_url(url);
    client.get(safe_url);
}
''')
        add("cass-cargo-binary.rs", '''fn robot_backfill_process(data_dir: &Path, db_path: &Path) {
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("cass"));
    command.arg("--db").arg(db_path).arg(data_dir);
    Command::new(std::path::Path::new("fixed-program"));
    Command::new(command::fixed_program());
    Command::new(format!("tool-{{user_program}}"));
}
''')
        add("command-values.rs", '''fn execute(user: User, command: String, path: PathBuf) {
    Command::new(user.program);
    std::process::Command::new(&command.as_str());
    Command::new(std::path::Path::new(&path));
    Command::new(command::normalize(user.program));
    Command::new(make_command!(user.program));
    Command::new(std::env::args().nth(1));
    Command::new(format!("tool-{command}"));
}
''', command_lines=(2, 3, 4, 5, 6, 7, 8))
        add("command-multiline.rs", '''fn execute(user: User) {
    std::process::Command::new(
        command::normalize(
            user.program
        )
    );
}
''', command_lines=(2,))
        add("command-markers.rs", '''fn execute(user: User) {
    Command::new(user.program); // ubs:ignore[rust.other]
    Command::new(user.program); // ubs:ignore[rust.security.command-executable]
    Command::new(user.program); // ubs:ignore
    Command::new(user.program); let note = "ubs:ignore";
    // ubs:ignore[rust.security.command-executable]
    Command::new(user.program);
}
''', command_lines=(2, 5))
        add("literal-source.rs", '''fn example() {
    let example = r#"std::env::args(); client.get(url); Command::new(user.program); // ubs:ignore"#;
}
''')
        for path, source in sources.items():
            path.write_text(source, encoding="utf-8")
        return project, sources, expected

    def test_real_request_url_bindings_and_command_operands(self) -> None:
        from ubs_core.rust_detectors import command_executable, request_url

        with tempfile.TemporaryDirectory(prefix="ubs-rust-input-boundary-") as temp:
            _project, sources, expected = self._fixtures(Path(temp).resolve())
            for detector, rule in ((request_url, self.URL_RULE),
                                   (command_executable, self.COMMAND_RULE)):
                for selected in (list(sources), list(reversed(sources))):
                    with self.subTest(detector=rule, reverse=selected != list(sources)):
                        findings = list(detector.find(selected))
                        self.assertCountEqual(
                            [(path, line, col) for path, line, col, _text in findings],
                            [(path, line, 1) for path, line, hit_rule in expected if hit_rule == rule],
                        )
                        for path, line, _col, code in findings:
                            self.assertIn(sources[path].splitlines()[line - 1].strip(), code)
                            self.assertEqual(code.count("outbound HTTP"), int(rule == self.URL_RULE))

    def test_public_input_boundaries_preserve_json_sarif_and_cache(self) -> None:
        for no_ast in ("0", "1"):
            with self.subTest(no_ast=no_ast), tempfile.TemporaryDirectory(prefix="ubs-rust-input-public-") as temp:
                root = Path(temp).resolve()
                project, sources, expected = self._fixtures(root)
                paths = list(sources)
                cache = root / "cache"

                def scan(selected, output_format, expected_sites, hits):
                    artifacts = Path(tempfile.mkdtemp(prefix="report-", dir=root))
                    listing, sink, stats = (artifacts / name for name in ("files.txt", "findings.ndjson", "cache.json"))
                    listing.write_text("\n".join(str(path) for path in selected) + "\n", encoding="utf-8")
                    command = [
                        "bash", str(REPO_ROOT / "modules" / "ubs-rust.sh"),
                        "--ci", "--no-color", "--no-cargo", "--fail-on-warning", "--only=8",
                        f"--format={output_format}", f"--files-from={listing}", f"--report-json={sink}", str(project),
                    ]
                    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", UBS_NO_CACHE="0",
                               UBS_CACHE_DIR=str(cache), UBS_CACHE_FILE=str(stats), UBS_PROFILE="1",
                               UBS_SKIP_TYPE_NARROWING="1", UBS_TEST_FORCE_NO_AST_GREP=no_ast,
                               UBS_ALLOW_UNVERIFIED_HELPERS="0", UBS_NO_AUTO_UPDATE="1")
                    proc = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=180)  # ubs:ignore[python.taint.command] - fixed repository scanner with local Rust source fixtures and bounded execution
                    context = f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
                    self.assertEqual(proc.returncode, int(bool(expected_sites)), context)
                    try:
                        payload = json.loads(proc.stdout)
                        records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
                        cache_stats = json.loads(stats.read_text(encoding="utf-8"))
                    except (ValueError, OSError) as exc:
                        self.fail(f"Invalid Rust input report: {exc}\n{context}")
                    self.assertEqual((cache_stats["hits"], cache_stats["misses"]),
                                     (hits, len(selected) - hits), context)
                    wanted = [(rule, str(path), line, 1, "critical") for path, line, rule in expected_sites]
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
                        self.assertCountEqual(actual, [(rule, sarif_uri(path), line, col, "error")
                                                       for rule, path, line, col, _severity in wanted], context)
                    return sorted(records, key=lambda record: json.dumps(record, sort_keys=True))

                cold = scan(paths, "json", expected, 0)
                self.assertEqual(scan(paths, "sarif", expected, len(paths)), cold)
                positive = {path for path, _line, _rule in expected}
                clean = [path for path in paths if path not in positive]
                self.assertEqual(scan(clean, "json", [], len(clean)), [])
                changed = project / "url-multiline.rs"
                changed.write_text('fn safe(client: Client) { client.get("https://example.com/fixed"); }\n', encoding="utf-8")
                remaining = [site for site in expected if site[0] != changed]
                partial = scan(paths, "json", remaining, len(paths) - 1)
                self.assertEqual(partial, [record for record in cold if record["path"] != str(changed)])
                self.assertEqual(scan(paths, "sarif", remaining, len(paths)), partial)


class AstIngestionTests(unittest.TestCase):
    """All AST adapters must distinguish an empty scan from lost evidence."""

    def setUp(self) -> None:
        from ubs_core import external_tools
        self.tools = external_tools
        scratch = tempfile.TemporaryDirectory(prefix="ubs-ast-ingestion-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.source = self.root / "source with spaces.py"
        self.source.write_text("value = 42\n", encoding="utf-8")
        self.config = self.root / "sgconfig-python.yml"
        self.config.write_text("ruleDirs: []\n", encoding="utf-8")
        self.binary = self.root / "cached analyzer"
        environment = patch.dict(os.environ, {"UBS_AST_GREP_BIN": str(self.binary)})
        environment.start()
        self.addCleanup(environment.stop)

    def diagnostic(self, **changes) -> dict:
        row = {"ruleId": "custom.critical", "file": str(self.source),
               "range": {"start": {"line": 0, "column": 2}},
               "severity": "error", "message": "project policy", "text": "value"}
        row.update(changes)
        return row

    def executable(self, payload: bytes, code: int = 0, suffix: str = "") -> None:
        self.binary.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"sys.stdout.buffer.write({payload!r})\nsys.stdout.flush()\n"
            + suffix + f"\nsys.exit({code})\n", encoding="utf-8",
        )
        self.binary.chmod(0o755)

    def payload(self, *rows) -> bytes:
        return ("\n".join(json.dumps(row) for row in rows) + "\n").encode("utf-8")

    def test_valid_records_survive_malformed_json_and_record_shapes(self) -> None:
        invalid = [None, [], False, "bad", {}, {"ruleId": []},
                   self.diagnostic(file="\0"), self.diagnostic(ruleId=3),
                   self.diagnostic(range={"start": {"line": True, "column": 0}}),
                   self.diagnostic(range={"start": {"line": -1, "column": 0}}),
                   self.diagnostic(range={"start": {"line": "0", "column": 0}}),
                   self.diagnostic(range={"start": {"line": 0}}),
                   self.diagnostic(severity=[]), self.diagnostic(severity="fatal-ish"),
                   self.diagnostic(message={}), self.diagnostic(text=None),
                   self.diagnostic(lines=[]), self.diagnostic(metaVariables=[]),
                   self.diagnostic(metaVariables={"single": {"METHOD": []}}),
                   self.diagnostic(range={"start": {"line": 0, "column": 2},
                                          "end": {"line": 0, "column": 1}}),
                   self.diagnostic(file="bad\udcff.py")]
        for row in invalid:
            with self.subTest(row=row):
                errors = []
                stream = self.payload(self.diagnostic(), row, self.diagnostic(ruleId="later"))
                records = list(self.tools.parse_ast_diagnostics(stream.decode(), errors))
                self.assertEqual([r["ruleId"] for r in records], ["custom.critical", "later"])
                self.assertEqual(len(errors), 1)
        errors = []
        self.assertEqual(list(self.tools.parse_ast_diagnostics("{\n", errors)), [])
        self.assertIn("malformed AST", errors[0])

    def test_bad_rows_are_counted_without_unbounded_error_messages(self) -> None:
        errors = []
        list(self.tools.parse_ast_diagnostics("null\n" * 5000, errors))
        self.assertEqual(len(errors), 1)
        self.assertIn("5000 malformed", errors[0])
        self.assertLess(len(errors[0]), 1000)

    def test_observed_corruption_survives_early_consumer_exit(self) -> None:
        valid = self.payload(self.diagnostic())
        for corrupt, detail in ((b"\xff\n", "UTF-8"), (b"null\n", "malformed AST"),
                                (b"x" * 4096 + b"\n", "output exceeds")):
            with self.subTest(detail=detail), patch.object(self.tools, "OUTPUT_RECORD_LIMIT", len(valid) + 8):
                errors = []
                records = self.tools.parse_ast_diagnostics(io.BytesIO(corrupt * 1000 + valid), errors)
                self.assertEqual(next(records)["ruleId"], "custom.critical")
                # Inspect before close: already-observed corruption cannot be
                # deferred until a caller happens to exhaust the iterator.
                self.assertEqual(len(errors), 1)
                self.assertIn("1000", errors[0])
                self.assertIn(detail, errors[0])
                records.close()
                self.assertEqual(len(errors), 1)
                self.assertLess(len(errors[0]), 1000)

    def test_stream_consumer_exception_is_not_a_capture_read_error(self) -> None:
        errors = []
        rows = self.tools.iter_output_lines(io.BytesIO(b"valid\n"), errors, context="test")
        self.assertEqual(next(rows), (1, "valid\n"))
        with self.assertRaisesRegex(OSError, "consumer failed"):
            rows.throw(OSError("consumer failed"))
        self.assertFalse(errors)

    def test_unicode_separators_inside_json_strings_are_not_record_boundaries(self) -> None:
        row = self.diagnostic(file="source\u2028name.py", message="one\u0085two\u2029three")
        errors = []
        actual = list(self.tools.parse_ast_diagnostics(json.dumps(row, ensure_ascii=False) + "\n", errors))
        self.assertEqual(actual, [row])
        self.assertFalse(errors)

    def test_error_accumulator_is_not_required_to_fail_closed(self) -> None:
        sink = []
        with self.assertRaisesRegex(RuntimeError, "malformed AST"):
            for row in self.tools.parse_ast_diagnostics(self.payload(self.diagnostic(), None).decode()):
                sink.append(row)
        self.assertEqual(len(sink), 1)

    def test_missing_or_nonregular_config_never_becomes_empty_success(self) -> None:
        for config in (self.root / "missing.yml", self.root):
            with self.subTest(config=config):
                errors = []
                self.assertEqual(list(self.tools.scan_ast_config(config, [self.source], errors)), [])
                self.assertIn("configuration", errors[0])
                with self.assertRaises(RuntimeError):
                    list(self.tools.scan_ast_config(config, [self.source]))

    def test_empty_selection_does_not_require_analyzer_or_config(self) -> None:
        errors = []
        self.assertEqual(list(self.tools.scan_ast_config(self.root / "missing", [], errors)), [])
        self.assertEqual(self.tools.ast_rule_configs(self.root / "missing", [], errors), [])
        self.assertFalse(errors)

    def test_missing_or_empty_rule_pack_is_reported(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        for folder in (empty, self.root / "missing"):
            errors = []
            self.assertEqual(self.tools.ast_rule_configs(folder, [self.source], errors), [])
            self.assertIn("cannot load requested rule pack", errors[0])

    def test_success_and_finding_exits_do_not_mean_incomplete(self) -> None:
        for code, rows in ((0, ()), (0, (self.diagnostic(severity="warning"),)),
                           (1, (self.diagnostic(),))):
            with self.subTest(code=code, rows=rows):
                self.executable(self.payload(*rows), code)
                errors = []
                result = list(self.tools.scan_ast_config(self.config, [self.source], errors))
                self.assertEqual(len(result), len(rows))
                self.assertFalse(errors)

    def test_finding_exit_without_diagnostics_is_incomplete(self) -> None:
        self.executable(b" \n", 1)
        errors = []
        self.assertEqual(list(self.tools.scan_ast_config(self.config, [self.source], errors)), [])
        self.assertTrue(any("findings exit without valid diagnostics" in error for error in errors))
        with self.assertRaisesRegex(RuntimeError, "findings exit without valid diagnostics"):
            list(self.tools.scan_ast_config(self.config, [self.source]))

    def test_failed_invocation_keeps_diagnostics(self) -> None:
        for code in (2, 3, 124, 127):
            with self.subTest(code=code):
                self.executable(self.payload(self.diagnostic()), code)
                errors = []
                result = list(self.tools.scan_ast_config(self.config, [self.source], errors))
                self.assertEqual(len(result), 1)
                self.assertIn(f"exited {code}", errors[-1])

    def test_verified_binary_override_is_authoritative(self) -> None:
        self.executable(self.payload(self.diagnostic()))
        errors = []
        records = list(self.tools.scan_ast_config(
            self.config, [self.source], errors, ast_grep_bin="does-not-exist",
        ))
        self.assertEqual(len(records), 1)
        self.assertFalse(errors)
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": str(self.root / "missing")}):
            self.assertEqual(list(self.tools.scan_ast_config(self.config, [self.source], errors)), [])
        self.assertIn("could not launch", errors[0])

    def test_timeout_keeps_completed_records(self) -> None:
        self.executable(self.payload(self.diagnostic()), suffix="time.sleep(30)\n")
        errors = []
        records = list(self.tools.scan_ast_config(self.config, [self.source], errors, timeout=2))
        self.assertEqual(len(records), 1)
        self.assertTrue(any("timed out" in e for e in errors))

    def test_record_limit_keeps_later_records_and_reports_oversized_row(self) -> None:
        valid = self.payload(self.diagnostic())
        self.executable(valid + b"x" * 2048 + b"\n" + self.payload(self.diagnostic(ruleId="later")))
        errors = []
        with patch.object(self.tools, "OUTPUT_RECORD_LIMIT", len(valid) + 8):
            records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual([record["ruleId"] for record in records], ["custom.critical", "later"])
        self.assertTrue(any("output exceeds" in e for e in errors))

    def test_large_diagnostic_stream_retains_every_location_with_bounded_memory(self) -> None:
        import tracemalloc
        row = self.diagnostic(text="x" * 1024)
        count = 20000
        self.assertGreater(len(self.payload(row)) * count, 16 * 1024 * 1024)
        self.executable(b"", suffix=(
            f"import json\nrow = {row!r}\n"
            f"for line in range({count}):\n"
            "    row['range']['start']['line'] = line\n"
            "    sys.stdout.write(json.dumps(row) + '\\n')\n"
        ))
        errors = []
        tracemalloc.start()
        try:
            actual = 0
            for diagnostic in self.tools.scan_ast_config(self.config, [self.source], errors):
                self.assertEqual(diagnostic["range"]["start"]["line"], actual)
                actual += 1
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(actual, count, errors)
        self.assertFalse(errors)
        # A higher total cap or a whole-file read would retain tens of MiB.
        # This budget measures ingestion, excluding caller-retained findings.
        self.assertLess(peak, 4 * 1024 * 1024, f"stream ingestion peaked at {peak} bytes")

    def test_whole_document_capture_retains_its_output_and_stderr_bounds(self) -> None:
        self.executable(b"x" * 2048, suffix="sys.stderr.write('e' * 8192)\n")
        errors = []
        with patch.object(self.tools, "OUTPUT_LIMIT", 512):
            output = self.tools.run_command("document tool", [str(self.binary)], self.root, 5, errors)
        self.assertIsNotNone(output)
        self.assertEqual(output.stdout, "x" * 512)
        self.assertEqual(output.stderr, "e" * 4096)
        self.assertEqual(output.returncode, 0)
        self.assertEqual(errors, ["document tool: output exceeds 512 bytes"])

    def test_whole_document_capture_preserves_strict_utf8_and_merged_stderr(self) -> None:
        self.executable(b"prefix\xff\n", suffix="sys.stderr.buffer.write(b'warning\\n')\nsys.stderr.flush()\n")
        for strict in (False, True):
            with self.subTest(strict=strict):
                errors = []
                output = self.tools.run_command("document tool", [str(self.binary)], self.root, 5, errors,
                                                merge_stderr=True, strict_utf8=strict)
                self.assertEqual(output.stdout, "prefix\ufffd\nwarning\n")
                self.assertEqual(output.stderr, "")
                self.assertEqual(bool(errors), strict)
                if strict:
                    self.assertIn("not valid UTF-8", errors[0])

    @unittest.skipUnless(os.name == "posix", "POSIX process groups")
    def test_exited_leader_with_live_child_is_partial_and_child_stops(self) -> None:
        import signal
        import time
        # The child writes its procfs identity: a sandbox may expose an outer
        # procfs while Popen/kill use namespace-local PIDs.
        child_state = self.root / "child-state.json"
        child_code = (
            "import json, os, time\nfrom pathlib import Path\n"
            "stat = Path('/proc/self/stat')\n"
            f"Path({str(child_state)!r}).write_text(json.dumps([os.getpid(), "
            "stat.read_text().partition(' ')[0] if stat.exists() else None]))\n"
            "time.sleep(30)\n"
        )
        local_pid_file = self.root / "child.pid"
        self.executable(self.payload(self.diagnostic()), suffix=(
            "import subprocess\nfrom pathlib import Path\n"
            f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
            f"Path({str(local_pid_file)!r}).write_text(str(child.pid))\n"
            f"while not Path({str(child_state)!r}).exists():\n    time.sleep(0.01)\n"
        ))
        errors = []
        started = time.monotonic()
        try:
            records = list(self.tools.scan_ast_config(self.config, [self.source], errors, timeout=3))
            self.assertEqual(len(records), 1, errors)
            self.assertTrue(any("exited before its process group completed" in error for error in errors))
            self.assertLess(time.monotonic() - started, 2)
            local_pid, proc_pid = json.loads(child_state.read_text())
            if Path("/proc").exists():
                state_file = Path(f"/proc/{proc_pid}/stat")
                try:
                    state = state_file.read_text().rpartition(")")[2].split()[0]
                except FileNotFoundError:
                    state = "gone"
                self.assertIn(state, ("Z", "X", "gone"))
        finally:
            if local_pid_file.exists():
                try:
                    os.kill(int(local_pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_completed_child_does_not_make_capture_partial(self) -> None:
        self.executable(self.payload(self.diagnostic()), suffix=(
            "import subprocess\n"
            "subprocess.run([sys.executable, '-c', 'pass'], check=True)\n"
        ))
        errors = []
        records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual(len(records), 1)
        self.assertFalse(errors)

    @unittest.skipUnless(os.name == "posix" and Path("/proc").exists(), "Linux parent cancellation")
    def test_parent_cancellation_stops_isolated_analyzer(self) -> None:
        import signal
        import time
        pid_file = self.root / "analyzer-identity.json"
        self.executable(self.payload(self.diagnostic()), suffix=(
            "import json, os\nfrom pathlib import Path\n"
            f"Path({str(pid_file)!r}).write_text(json.dumps([os.getpid(), "
            "Path('/proc/self/stat').read_text().partition(' ')[0]]))\n"
            "time.sleep(30)\n"
        ))
        driver_code = (
            "from pathlib import Path\nfrom ubs_core.external_tools import run_command_stream\n"
            f"with run_command_stream('fixture', [{str(self.binary)!r}], Path({str(self.root)!r}), 30, []):\n"
            "    pass\n"
        )
        driver = subprocess.Popen(
            [sys.executable, "-c", driver_code], cwd=self.root, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": str(HELPERS_DIR),
                                         "PYTHONDONTWRITEBYTECODE": "1"},
        )
        local_pid = None
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    local_pid, proc_pid = json.loads(pid_file.read_text())
                    break
                except (FileNotFoundError, ValueError):
                    self.assertIsNone(driver.poll(), "driver exited before launching analyzer")
                    self.assertLess(time.monotonic(), deadline, "analyzer did not start")
                    time.sleep(0.01)
            driver.send_signal(signal.SIGTERM)
            _stdout, stderr = driver.communicate(timeout=5)
            self.assertEqual(driver.returncode, 128 + signal.SIGTERM, stderr.decode("utf-8", "replace"))
            state_file = Path(f"/proc/{proc_pid}/stat")
            try:
                state = state_file.read_text().rpartition(")")[2].split()[0]
            except FileNotFoundError:
                state = "gone"
            self.assertIn(state, ("Z", "X", "gone"))
        finally:
            if driver.poll() is None:
                driver.terminate()
                try:
                    driver.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    driver.kill()
                    driver.wait(timeout=5)
            if driver.stderr is not None:
                driver.stderr.close()
            if local_pid is not None:
                try:
                    os.kill(local_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "POSIX child-exit policy")
    def test_ignored_sigchld_cannot_turn_failed_tool_into_complete_scan(self) -> None:
        import signal
        self.executable(self.payload(self.diagnostic()), code=2)
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            errors = []
            records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
            self.assertEqual(len(records), 1)
            self.assertTrue(any("cannot verify analyzer exit status" in error for error in errors))
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_corrupt_stream_records_have_bounded_error_detail(self) -> None:
        valid = self.payload(self.diagnostic())
        errors = []
        with patch.object(self.tools, "OUTPUT_RECORD_LIMIT", len(valid) + 8):
            records = list(self.tools.parse_ast_diagnostics(
                io.BytesIO((b"x" * 2048 + b"\n\xff\n") * 1000 + valid), errors,
            ))
        self.assertEqual(len(records), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("2000 unreadable output record(s)", errors[0])
        self.assertLess(len(errors[0]), 1000)

    def test_stream_capture_read_failure_keeps_evidence_and_fails_closed(self) -> None:
        class BrokenStream(io.BytesIO):
            def readline(self, size=-1):
                if self.tell() == len(self.getvalue()):
                    raise OSError("capture device failed")
                return super().readline(size)

        for accumulate in (True, False):
            records, errors = [], []
            with self.subTest(accumulate=accumulate):
                try:
                    for record in self.tools.parse_ast_diagnostics(
                        BrokenStream(self.payload(self.diagnostic())), errors if accumulate else None,
                    ):
                        records.append(record)
                except RuntimeError as exc:
                    self.assertFalse(accumulate)
                    self.assertIn("capture device failed", str(exc))
                else:
                    self.assertTrue(accumulate)
                    self.assertIn("capture device failed", errors[0])
                self.assertEqual(len(records), 1)

    def test_capture_handles_close_when_the_consumer_raises(self) -> None:
        self.executable(self.payload(self.diagnostic()))
        errors = []
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            with patch.object(self.tools, "temporary_file", side_effect=[stdout, stderr]):
                with self.assertRaisesRegex(OSError, "consumer failed"):
                    with self.tools.run_command_stream("test analyzer", [str(self.binary)], self.root, 5, errors) as output:
                        self.assertIsNotNone(output)
                        self.assertFalse(output.stdout.closed)
                        raise OSError("consumer failed")
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)
        self.assertFalse(errors)

    def test_capture_close_failure_keeps_consumer_error_and_closes_both_handles(self) -> None:
        self.executable(self.payload(self.diagnostic()))
        errors = []
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            class BrokenClose:
                def __getattr__(self, name):
                    return getattr(stderr, name)

                def close(self):
                    stderr.close()
                    raise OSError("capture close failed")

            with patch.object(self.tools, "temporary_file", side_effect=[stdout, BrokenClose()]):
                with self.assertRaisesRegex(OSError, "consumer failed"):
                    with self.tools.run_command_stream("test analyzer", [str(self.binary)], self.root, 5, errors):
                        raise OSError("consumer failed")
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)
        self.assertEqual(len(errors), 1)
        self.assertIn("could not close captured output: capture close failed", errors[0])

    def test_capture_seek_failure_closes_both_handles(self) -> None:
        self.executable(self.payload(self.diagnostic()))
        errors = []
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            class BrokenSeek:
                def __getattr__(self, name):
                    return getattr(stdout, name)

                def seek(self, *args):
                    raise OSError("capture seek failed")

            with patch.object(self.tools, "temporary_file", side_effect=[BrokenSeek(), stderr]):
                with self.tools.run_command_stream("test analyzer", [str(self.binary)], self.root, 5, errors) as output:
                    self.assertIsNone(output)
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)
        self.assertEqual(len(errors), 1)
        self.assertIn("capture seek failed", errors[0])

    def test_second_capture_open_failure_closes_first_handle_without_launching(self) -> None:
        with tempfile.TemporaryFile() as first:
            errors = []
            with patch.object(self.tools, "temporary_file", side_effect=[first, OSError("capture full")]), \
                    patch.object(self.tools.subprocess, "Popen") as launch:
                with self.tools.run_command_stream("test analyzer", [str(self.binary)], self.root, 5, errors) as output:
                    self.assertIsNone(output)
            launch.assert_not_called()
            self.assertTrue(first.closed)
        self.assertEqual(len(errors), 1)
        self.assertIn("could not launch or capture output: capture full", errors[0])

    def test_invalid_utf8_is_incomplete_but_valid_rows_remain(self) -> None:
        self.executable(self.payload(self.diagnostic()) + b"\xff\n")
        errors = []
        records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual(len(records), 1)
        self.assertTrue(any("UTF-8" in e for e in errors))

    def test_stderr_errors_beyond_preview_are_partial_with_bounded_detail(self) -> None:
        self.executable(self.payload(self.diagnostic()), suffix=(
            "sys.stderr.write('Warning: analyzer note\\n' * 300)\n"
            "sys.stderr.write('ERROR: source could not be read\\n' * 2000)\n"
        ))
        errors = []
        records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual(len(records), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("2000 analyzer error(s) on stderr", errors[0])
        self.assertLess(len(errors[0]), 1000)

    def test_ordinary_stderr_warning_is_not_an_incomplete_scan(self) -> None:
        self.executable(self.payload(self.diagnostic()), suffix="sys.stderr.write('Warning: analyzer note\\n')\n")
        errors = []
        self.assertEqual(len(list(self.tools.scan_ast_config(self.config, [self.source], errors))), 1)
        self.assertFalse(errors)

    def test_native_finding_summary_requires_matching_exit_and_valid_stdout(self) -> None:
        for code, valid in ((1, True), (1, False), (0, True)):
            with self.subTest(code=code, valid=valid):
                self.executable(self.payload(self.diagnostic()) if valid else b"", code=code,
                                suffix="sys.stderr.write('Error: 1 error(s) found in code.\\n')\n")
                errors = []
                records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
                self.assertEqual(len(records), int(valid))
                self.assertEqual(bool(errors), not (code == 1 and valid))

    def test_unreadable_stderr_records_preserve_stdout_findings(self) -> None:
        valid = self.payload(self.diagnostic())
        for bad in (b"\xff\n", b"x" * 2048 + b"\n"):
            with self.subTest(bad=bad[:20]), patch.object(self.tools, "OUTPUT_RECORD_LIMIT", len(valid) + 8):
                self.executable(valid, suffix=f"sys.stderr.buffer.write({bad!r})\n")
                errors = []
                records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
                self.assertEqual(len(records), 1)
                self.assertTrue(any("stderr" in error and "unreadable output" in error for error in errors))

    def test_stderr_capture_failure_does_not_erase_stdout_findings(self) -> None:
        self.executable(self.payload(self.diagnostic()))
        errors = []
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            class BrokenRead:
                def __getattr__(self, name):
                    return getattr(stderr, name)

                def read(self, *args):
                    raise OSError("stderr capture failed")

            with patch.object(self.tools, "temporary_file", side_effect=[stdout, BrokenRead()]):
                records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)
        self.assertEqual(len(records), 1)
        self.assertTrue(any("could not read captured stderr" in error for error in errors))

    def test_later_batches_run_after_an_earlier_failure(self) -> None:
        invocations = self.root / "invocations.jsonl"
        self.executable(b"", suffix=(
            "import json\nfrom pathlib import Path\n"
            f"log = Path({str(invocations)!r})\nfirst = not log.exists()\n"
            "with log.open('a') as sink:\n    sink.write(json.dumps(sys.argv) + '\\n')\n"
            "if first:\n    sys.stdout.write('null\\n'); sys.exit(2)\n"
            f"sys.stdout.buffer.write({self.payload(self.diagnostic())!r})\nsys.exit(1)\n"
        ))
        errors = []
        records = list(self.tools.scan_ast_config(
            self.config, [self.source, self.source], errors, batch_size=1,
        ))
        commands = [json.loads(line) for line in invocations.read_text().splitlines()]
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(records), 1)
        self.assertTrue(any("exited 2" in error for error in errors))
        self.assertTrue(any("malformed AST" in error for error in errors))
        self.assertTrue(all("--" in command for command in commands))

    def test_python_adapter_preserves_valid_finding_and_marks_corruption(self) -> None:
        from ubs_core import py_ast
        self.executable(self.payload(self.diagnostic(), None))
        sink, errors = io.StringIO(), []
        counts = py_ast.scan_config(self.config, [self.source], sink, errors=errors)
        self.assertEqual(counts, {"critical": 1, "warning": 0, "info": 0})
        self.assertEqual(json.loads(sink.getvalue())["col"], 3)
        self.assertTrue(errors)

    def test_python_filters_do_not_conceal_malformed_output(self) -> None:
        from ubs_core import py_ast
        self.executable(self.payload(self.diagnostic(), None))
        sink, errors = io.StringIO(), []
        counts = py_ast.scan_config(self.config, [self.source], sink, count_only=set(), errors=errors)
        self.assertEqual(sum(counts.values()), 0)
        self.assertFalse(sink.getvalue())
        self.assertTrue(errors)

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep is required")
    def test_real_ast_grep_output_and_error_severity_are_preserved(self) -> None:
        from ubs_core import py_ast
        rule = self.root / "policy.yaml"
        rule.write_text('id: policy-print\nlanguage: python\nseverity: error\n'
                        'message: No print calls\nrule:\n  pattern: print($$$)\n', encoding="utf-8")
        self.config.write_text("ruleDirs:\n  - " + json.dumps(str(rule)) + "\n", encoding="utf-8")
        self.source.write_text("print(42)\n", encoding="utf-8")
        sink, errors = io.StringIO(), []
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": shutil.which("ast-grep")}):
            counts = py_ast.scan_all(self.root, [self.source], sink, errors=errors)
        self.assertEqual(counts["critical"], 1)
        self.assertFalse(errors)
        self.assertEqual(json.loads(sink.getvalue())["rule"], "policy-print")

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep is required")
    def test_real_ast_grep_missing_source_is_partial_and_keeps_readable_sibling(self) -> None:
        rule = self.root / "policy.yaml"
        rule.write_text("id: policy-print\nlanguage: python\nseverity: warning\nrule:\n  pattern: print($$$)\n")
        self.config.write_text("ruleDirs: " + json.dumps([str(rule)]) + "\n")
        self.source.write_text("print(42)\n")
        errors = []
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": shutil.which("ast-grep")}):
            records = list(self.tools.scan_ast_config(self.config, [self.root / "missing.py", self.source], errors))
        self.assertEqual([row["ruleId"] for row in records], ["policy-print"])
        self.assertTrue(any("analyzer error(s) on stderr" in error for error in errors), errors)

    def test_python_complete_scan_and_partial_scan_are_not_cache_equivalent(self) -> None:
        from ubs_core.py_rules import generate
        rules = self.root / "rules"
        generate(rules)
        files = self.root / "files"
        files.write_bytes(os.fsencode(self.source) + b"\0")
        env = {**os.environ, "PYTHONPATH": str(HELPERS_DIR), "PYTHONDONTWRITEBYTECODE": "1",
               "UBS_NO_PREFILTER": "1", "UBS_CACHE_DIR": str(self.root / "cache"),
               "UBS_NO_CACHE": "0", "UBS_PROFILE": "1"}
        report, sink = self.root / "report.json", self.root / "findings.jsonl"
        command = [sys.executable, "-m", "ubs_core.py_scan", "--files-from", str(files),
                   "--project-dir", str(self.root), "--sink", str(sink), "--json-out", str(report),
                   "--ast-rule-dir", str(rules)]
        for broken in (True, True, False, False):
            self.executable(self.payload(self.diagnostic(), None) if broken else self.payload(self.diagnostic()))
            proc = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
            doc = json.loads(report.read_text())
            self.assertEqual(proc.returncode, 2 if broken else 1, proc.stderr)
            self.assertEqual(doc["status"], "partial" if broken else "ok")
            self.assertGreater(doc["critical"], 0)
            if broken:
                self.assertEqual(doc["module_error"], "ANALYZER_ERROR")
                self.assertEqual(doc["profile"]["cache_hits"], 0)
        self.assertEqual(doc["profile"]["cache_hits"], 1)

    ADAPTERS = ("py", "java", "csharp", "elixir", "go", "ruby", "rust", "swift")

    def adapter(self, name: str, errors: list[str], *, root: Path | None = None,
                prepare: bool = True) -> list[dict]:
        import importlib
        from types import SimpleNamespace
        module = importlib.import_module("ubs_core." + name + "_ast")
        root = root or self.root / name
        config = root / ("sgbase-java.yml" if name == "java" else f"sgconfig-{name}.yml")
        if prepare:
            root.mkdir(exist_ok=True)
            config.write_text("ruleDirs: []\n", encoding="utf-8")
        sink = io.StringIO()
        if name == "rust":
            from ubs_core import rust_rules
            with patch.object(rust_rules, "RUN_MODE_RULES", {}):
                _, matches = module.scan_all(root, [self.source], errors=errors)
            return [row for rows in matches.values() for row in rows]
        if name == "swift":
            module.scan_all(root, [self.source], SimpleNamespace(), sink, errors=errors)
        elif name == "go":
            module.scan_all(root, [self.source], {}, sink, errors=errors)
        else:
            module.scan_all(root, [self.source], sink, errors=errors)
        return [json.loads(line) for line in sink.getvalue().splitlines()]

    def test_every_adapter_keeps_valid_rows_around_corruption(self) -> None:
        self.executable(self.payload(self.diagnostic(), None, self.diagnostic(ruleId="later")))
        for name in self.ADAPTERS:
            with self.subTest(adapter=name):
                errors = []
                records = self.adapter(name, errors)
                self.assertEqual([r["rule"] for r in records], ["custom.critical", "later"])
                self.assertEqual([r["col"] for r in records], [3, 3])
                self.assertTrue(any("malformed AST" in e for e in errors))

    def test_every_adapter_marks_missing_pack_incomplete(self) -> None:
        for name in self.ADAPTERS:
            with self.subTest(adapter=name):
                errors = []
                self.assertEqual(self.adapter(name, errors, root=self.root / "missing", prepare=False), [])
                self.assertTrue(errors)

    def test_every_adapter_honors_verified_binary_and_failure_status(self) -> None:
        for code in (1, 2):
            self.executable(self.payload(self.diagnostic()), code)
            for name in self.ADAPTERS:
                with self.subTest(adapter=name, code=code):
                    errors = []
                    records = self.adapter(name, errors)
                    self.assertEqual(len(records), 1)
                    self.assertEqual(bool(errors), code == 2)
                    if name != "rust":
                        self.assertEqual(records[0]["severity"], "critical")
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": str(self.root / "absent")}):
            for name in self.ADAPTERS:
                errors = []
                self.assertEqual(self.adapter(name, errors), [])
                self.assertTrue(errors)

    def test_every_adapter_and_custom_policy_reject_empty_findings_exit(self) -> None:
        self.executable(b"", 1)
        for name in self.ADAPTERS:
            with self.subTest(adapter=name):
                errors = []
                self.assertEqual(self.adapter(name, errors), [])
                self.assertTrue(any("without valid diagnostics" in error for error in errors))
        policy = self.root / "policy.yaml"
        policy.write_text("id: policy\nlanguage: python\nrule:\n  pattern: print($$$)\n")
        sink, errors = io.StringIO(), []
        self.assertEqual(self.tools.scan_custom_rules(self.root, [self.source], sink, "python", errors), 0)
        self.assertFalse(sink.getvalue())
        self.assertTrue(any("without valid diagnostics" in error for error in errors))

    def test_every_adapter_preserves_stdout_when_stderr_reports_input_failure(self) -> None:
        self.executable(self.payload(self.diagnostic()), suffix="sys.stderr.write('ERROR: missing selected source\\n')\n")
        for name in self.ADAPTERS:
            with self.subTest(adapter=name):
                errors = []
                self.assertEqual(len(self.adapter(name, errors)), 1)
                self.assertTrue(any("analyzer error(s) on stderr" in error for error in errors))

    def test_config_discovery_preserves_java_base_pack_and_yaml_extension(self) -> None:
        (self.root / "sgbase-java.yaml").write_text("ruleDirs: []\n")
        errors = []
        configs = self.tools.ast_rule_configs(self.root, [self.source], errors, prefix="sgbase-")
        self.assertEqual([p.name for p in configs], ["sgbase-java.yaml"])
        self.assertFalse(errors)

    def test_rust_run_mode_records_validate_and_preserve_unusual_paths(self) -> None:
        from ubs_core.rust_ast import _parse_run_output
        row = self.diagnostic(file="source:with\nnewline.rs")
        row.pop("ruleId")
        row.pop("severity")
        errors = []
        records = _parse_run_output(self.payload(row, None, row).decode(), "rust.ast.unwrap", errors)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["path"], "source:with\nnewline.rs")
        self.assertEqual(records[0]["col"], 3)
        self.assertTrue(errors)

    def test_rust_run_mode_requires_consistent_match_exit(self) -> None:
        from ubs_core import rust_ast, rust_rules
        for code, has_record in ((0, False), (1, True), (0, True), (1, False)):
            with self.subTest(code=code, has_record=has_record):
                self.executable(self.payload(self.diagnostic()) if has_record else b"", code)
                errors = []
                with patch.object(rust_rules, "RUN_MODE_RULES", {"unwrap": "$A.unwrap()"}):
                    counts, matches = rust_ast._run_spawn_patterns([str(self.source)], str(self.binary), 400, errors)
                self.assertEqual(counts.get("rust.ast.unwrap", 0), int(has_record))
                self.assertEqual(bool(matches), has_record)
                self.assertEqual(bool(errors), has_record != (code == 0))

    def test_rust_run_mode_valid_duplicates_still_establish_match_exit(self) -> None:
        from ubs_core import rust_ast, rust_rules
        self.executable(self.payload(self.diagnostic()))
        errors = []
        with patch.object(rust_rules, "RUN_MODE_RULES", {"unwrap": "$A.unwrap()"}):
            counts, _ = rust_ast._run_spawn_patterns([str(self.source)] * 2, str(self.binary), 1, errors)
        self.assertEqual(counts["rust.ast.unwrap"], 1)
        self.assertFalse(errors)

    def test_rust_run_mode_stderr_failure_preserves_matches(self) -> None:
        from ubs_core import rust_ast, rust_rules
        self.executable(self.payload(self.diagnostic()), suffix="sys.stderr.write('ERROR: missing selected source\\n')\n")
        errors = []
        with patch.object(rust_rules, "RUN_MODE_RULES", {"unwrap": "$A.unwrap()"}):
            counts, _ = rust_ast._run_spawn_patterns([str(self.source)], str(self.binary), 400, errors)
        self.assertEqual(counts["rust.ast.unwrap"], 1)
        self.assertTrue(any("analyzer error(s) on stderr" in error for error in errors))

    def test_rust_nested_pattern_stream_has_no_total_output_cap(self) -> None:
        from ubs_core import rust_ast, rust_rules
        row = self.diagnostic(text="value." + "x" * 1024 + ".unwrap()")
        row.pop("ruleId")
        row.pop("severity")
        count = 18000
        self.assertGreater(len(self.payload(row)) * count, 16 * 1024 * 1024)
        self.executable(b"", suffix=(
            f"import json\nrow = {row!r}\n"
            f"for line in range({count}):\n"
            "    row['range']['start']['line'] = line\n"
            "    sys.stdout.write(json.dumps(row) + '\\n')\n"
        ))
        errors = []
        with patch.object(rust_rules, "RUN_MODE_RULES", {"unwrap": "$A.unwrap()"}):
            counts, matches = rust_ast._run_spawn_patterns([str(self.source)], str(self.binary), 400, errors)
        self.assertFalse(errors)
        self.assertEqual(counts, {"rust.ast.unwrap": count})
        self.assertEqual([match["line"] for match in matches["rust.ast.unwrap"]], list(range(1, count + 1)))
        self.assertTrue(all(match["text"] == row["text"] for match in matches["rust.ast.unwrap"]))

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep is required")
    def test_real_rust_nested_patterns_run_without_optional_manifest(self) -> None:
        from ubs_core import rust_ast
        folder = self.root / "rust-real"
        folder.mkdir()
        pack = folder / "pack"
        pack.mkdir()
        (pack / "sgconfig-rust.yml").write_text("ruleDirs: []\n")
        source = folder / "nested:with\nnewline.rs"
        source.write_text("fn main() { let x = Some(Some(1)); x.unwrap().unwrap(); }\n")
        errors = []
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": shutil.which("ast-grep")}):
            counts, matches = rust_ast.scan_all(pack, [source], errors=errors)
        self.assertFalse(errors)
        self.assertEqual(counts["rust.ast.unwrap"], 2)
        self.assertEqual([m["path"] for m in matches["rust.ast.unwrap"]], [str(source)] * 2)
        self.assertEqual([m["col"] for m in matches["rust.ast.unwrap"]], [36, 36])
        from ubs_core.rust_scan import Scan
        scan = Scan([source], folder, False, set(), 3)
        with patch.dict(os.environ, {"UBS_AST_GREP_BIN": shutil.which("ast-grep")}):
            scan.load_ast_matches(pack)
        self.assertEqual(len(scan.ast_hits(["unwrap"])), 2)
        self.assertFalse(scan.scan_errors)
        files, sink, report = folder / "files", folder / "findings.jsonl", folder / "summary.json"
        files.write_bytes(os.fsencode(source) + b"\0")
        env = {**os.environ, "UBS_AST_GREP_BIN": shutil.which("ast-grep"),
               "PYTHONPATH": str(HELPERS_DIR), "PYTHONDONTWRITEBYTECODE": "1",
               "UBS_NO_PREFILTER": "1", "UBS_CACHE_DIR": str(folder / "cache"),
               "UBS_NO_CACHE": "0", "UBS_PROFILE": "1"}
        command = [sys.executable, "-m", "ubs_core.rust_scan", "--files-from", str(files),
                   "--sink", str(sink), "--project-dir", str(folder), "--ast-rule-dir", str(pack),
                   "--json-out", str(report), "--quiet"]
        for _ in range(2):
            proc = subprocess.run(command, cwd=folder, env=env, capture_output=True, text=True, timeout=30)
            self.assertIn(proc.returncode, (0, 1), proc.stderr)
            doc = json.loads(report.read_text())
            self.assertEqual(doc["status"], "ok", doc)
            unwrap = [r for r in doc["findings"] if r["rule"] == "rust.ownership.unwrap-expect"]
            self.assertEqual(sum(r.get("count", 1) for r in unwrap), 2, unwrap)
        self.assertEqual(doc["profile"]["cache_hits"], 1)

    def test_python_partial_text_does_not_claim_unfinished_checks_are_good(self) -> None:
        from ubs_core import py_scan
        from types import SimpleNamespace
        sink, output = self.root / "empty.jsonl", self.root / "output.txt"
        sink.write_text("")
        args = SimpleNamespace(sink=str(sink), text_out=str(output), project="",
                               project_dir=str(self.root), skip="")
        py_scan._render_text(args, [self.source], {"critical": 0, "warning": 0, "info": 0}, complete=False)
        self.assertNotIn("good:", output.read_text())

    def test_every_core_cli_preserves_findings_and_retries_partial_analysis(self) -> None:
        import importlib
        cases = {
            "py": ("py", "value = 42\n", "custom.critical"),
            "java": ("java", "class Sample {}\n", "java.resource.executor-no-shutdown"),
            "csharp": ("cs", "class Sample {}\n", "cs-async-discarded-task-run"),
            "elixir": ("ex", "value = 42\n", "elixir.code-eval-string"),
            "go": ("go", "package sample\n", "go.async.goroutine-err-no-check"),
            "ruby": ("rb", "value = 42\n", "ruby.async.thread-no-rescue"),
            "rust": ("rs", "fn main() { let x = Some(1); }\n", "rust.ast.unwrap"),
            "swift": ("swift", "let value = 42\n", "swift.force-try"),
        }
        for name, (extension, text, rule) in cases.items():
            with self.subTest(language=name):
                root = self.root / ("cli-" + name)
                root.mkdir()
                source = root / ("sample." + extension)
                source.write_text(text)
                rules = root / "pack"
                importlib.import_module("ubs_core." + name + "_rules").generate(rules)
                files, sink, report = root / "files", root / "sink", root / "summary.json"
                files.write_bytes(os.fsencode(source) + b"\0")
                row = self.diagnostic(ruleId=rule, file=str(source), range={"start": {"line": 0, "column": 0}})
                self.executable(self.payload(row, None))
                env = {**os.environ, "PYTHONPATH": str(HELPERS_DIR), "PYTHONDONTWRITEBYTECODE": "1",
                       "UBS_NO_PREFILTER": "1", "UBS_CACHE_DIR": str(root / "cache"),
                       "UBS_NO_CACHE": "0", "UBS_PROFILE": "1"}
                command = [sys.executable, "-m", "ubs_core." + name + "_scan",
                           "--files-from", str(files), "--sink", str(sink),
                           "--project-dir", str(root),
                           "--ast-rule-dir", str(rules)]
                if name != "csharp":
                    command += ["--json-out", str(report)]
                for _ in range(2):
                    proc = subprocess.run(command, cwd=root, env=env, capture_output=True,
                                          text=True, timeout=45)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    if name == "csharp":
                        # C#'s wrapper renders the JSON summary; its core
                        # exposes the same failure through stderr and sink.
                        summary = json.loads(proc.stderr.splitlines()[-1])
                        self.assertTrue(summary["errors"])
                        rows = [json.loads(line) for line in sink.read_text().splitlines()]
                        self.assertTrue(any(r.get("rule") == rule for r in rows), rows)
                        continue
                    doc = json.loads(report.read_text())
                    self.assertEqual(doc["status"], "partial", doc)
                    self.assertEqual(doc["module_error"], "ANALYZER_ERROR", doc)
                    expected_rule = "rust.ownership.unwrap-expect" if name == "rust" else rule
                    self.assertTrue(any(r.get("rule") == expected_rule for r in doc["findings"]), doc)
                    self.assertEqual(doc["profile"]["cache_hits"], 0, doc)


class JavaKotlinDataflowTests(unittest.TestCase):
    """D6 increment: real frontend/CLI checks, with preserved fixture pairs."""

    def setUp(self) -> None:
        self.started = time.monotonic()
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='d6-java-kotlin-', dir=artifacts))

    def run(self, result=None):
        print(f'[{self.id()}] RUN', flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, 'test_case', None) is self
                     for test, _ in result.failures + result.errors)
        skipped = any(test is self for test, _ in result.skipped)
        state = 'FAIL' if failed else 'SKIP' if skipped else 'PASS'
        print(f'[{self.id()}] {state} ({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def helper(self, text, suffix='.java'):
        from ubs_core.analyzers.taint_java_traversal import Engine
        path = self.root / ('Sample' + suffix)
        path.write_text(textwrap.dedent(text).lstrip('\n'), encoding='utf-8')
        engine = Engine(path, path.read_text())
        return engine, engine.analyze()

    def lines(self, text, marker='// unsafe'):
        return {index for index, line in enumerate(text.splitlines(), 1) if marker in line}

    def decode_report(self, proc):
        try:
            return json.loads(proc.stdout)
        except ValueError as exc:
            self.fail(f'invalid scanner JSON: {exc}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}')

    def cli(self, path, lang, label, status=0, rule='path_traversal'):
        directory = self.root / label
        directory.mkdir()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_'))}
        env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                   UBS_SKIP_TYPE_NARROWING='1', ENABLE_UV_TOOLS='0',
                   XDG_DATA_HOME=str(directory / 'data'), XDG_CACHE_HOME=str(directory / 'cache'))
        command = [str(REPO_ROOT / 'ubs'), '--ci', '--no-color', '--no-cache',
                   '--format=json', '--only=' + lang, '--', str(path)]
        started = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=directory, env=env,
                                  capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired as exc:
            self.fail(f'{label} timed out\nstdout:\n{exc.stdout}\nstderr:\n{exc.stderr}')
        (directory / 'stdout.log').write_text(proc.stdout)
        (directory / 'stderr.log').write_text(proc.stderr)
        (directory / 'command.json').write_text(json.dumps({
            'case': self.id(), 'command': command, 'cwd': str(directory),
            'seconds': time.monotonic() - started, 'exit': proc.returncode,
            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        }, indent=2))
        context = f'{label}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, status, context)
        try:
            report = json.loads(proc.stdout)
        except ValueError as exc:
            self.fail(f'{exc}\n{context}')
        self.assertEqual(report['status'], 'ok', context)
        self.assertEqual(report['totals']['files'], 1, context)
        self.assertEqual(report['failed_modules'], [], context)
        self.assertEqual(len(report['scanners']), 1, context)
        self.assertEqual(report['scanners'][0]['status'], 'ok', context)
        findings = [finding for scanner in report['scanners'] for finding in scanner['findings']
                    if finding['rule'] == lang + '.taint.' + rule]
        return findings, context

    def test_shared_engine_branches_loops_local_summaries_and_evidence(self):
        text = '''class Flow {
  String relay(String value) { return value; }
  void save(String value) { Files.readString(value); } // unsafe
  String recursive(String value, int n) {
    if (n == 0) { return value; }
    return recursive(value, n - 1);
  }
  void handler(Request request, boolean again) {
    String value = "fixed";
    while (again) { value = request.getParameter("file"); }
    save(relay(recursive(value, 2)));
  }
  void zeroIterations(Request request, boolean again) {
    String value = request.getParameter("file");
    while (again) { value = "fixed"; }
    Files.readString(value); // unsafe
  }
  void branch(Request request, boolean condition) {
    String value = request.getParameter("file");
    if (condition) { value = "fixed"; } else { value = value; }
    Files.readString(value); // unsafe
  }
  void bothClean(Request request, boolean condition) {
    String value = request.getParameter("file");
    if (condition) { value = "fixed"; } else { value = "other"; }
    Files.readString(value);
  }
}'''
        engine, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))
        witness = next(iter(effects[3]))
        self.assertEqual(witness.evidence[0].kind, 'source')
        self.assertIn('call', {step.kind for step in witness.evidence})
        self.assertEqual(witness.evidence[-1].kind, 'sink')
        self.assertTrue(all(step.path == str(engine.path) and step.line > 0 and step.column > 0
                            for step in witness.evidence))
        self.assertTrue(all(len(trace.evidence) <= 12 for fact in effects.values() for trace in fact))

    def test_finally_replaces_or_preserves_the_evaluated_return(self):
        text = '''class Flow {
  String replaced(String value) { try { return value; } finally { return "fixed"; } }
  String preserved(String value) { try { return value; } finally { value = "fixed"; } }
  String nested(String value) {
    try { try { return value; } finally { return "fixed"; } }
    finally { return "outer"; }
  }
  void handler(Request request) {
    Files.readString(replaced(request.getParameter("file")));
    Files.readString(nested(request.getParameter("file")));
    Files.readString(preserved(request.getParameter("file"))); // unsafe
  }
}'''
        _, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))

    def test_native_json_and_sarif_preserve_helper_flow_evidence(self):
        cases = (
            ('java', '.java', '''class Flow {
  String relay(String value) { return value; }
  void handler(Request request) {
    String path = request.getParameter("file");
    Files.readString(relay(path));
  }
}''', 'request.getParameter("file")', 4, 5),
            ('kotlin', '.kt', '''fun relay(value: String): String { return value }
fun handler(request: Request) {
  val path = request.queryParameters["file"]
  Files.readString(relay(path))
}''', 'request.queryParameters["file"]', 3, 4),
        )
        for lang, suffix, text, request, source_line, sink_line in cases:
            with self.subTest(lang=lang):
                source = self.root / ('Flow' + suffix)
                source.write_text(text, encoding='utf-8')
                findings, context = self.cli(source, lang, lang + '-json', status=1)
                self.assertEqual(len(findings), 1, context)
                self.assertEqual(findings[0]['line'], sink_line, context)
                extras = findings[0]['extras']
                steps = extras['taint_path']
                self.assertEqual(extras['source_count'], 1, context)
                self.assertGreaterEqual(len(steps), 3, context)
                self.assertLessEqual(len(steps), 12, context)
                self.assertEqual((steps[0]['kind'], steps[0]['line']), ('source', source_line), context)
                self.assertEqual((steps[-1]['kind'], steps[-1]['line']), ('sink', sink_line), context)
                self.assertIn('call', {step['kind'] for step in steps}, context)
                self.assertTrue(all(Path(step['path']) == source.resolve() and step['col'] > 0
                                    and step['line'] > 0 and step['label'] for step in steps), context)

                directory = self.root / (lang + '-sarif')
                directory.mkdir()
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith(('UBS_', 'GIT_', 'XDG_'))}
                env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                           UBS_SKIP_TYPE_NARROWING='1', ENABLE_UV_TOOLS='0',
                           XDG_DATA_HOME=str(directory / 'data'), XDG_CACHE_HOME=str(directory / 'cache'))
                proc = subprocess.run([str(REPO_ROOT / 'ubs'), '--ci', '--no-color', '--no-cache',
                    '--format=sarif', '--only=' + lang, '--', str(source)], cwd=directory, env=env,
                    capture_output=True, text=True, timeout=180)
                (directory / 'stdout.log').write_text(proc.stdout)
                (directory / 'stderr.log').write_text(proc.stderr)
                context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                self.assertEqual(proc.returncode, 1, context)
                report = self.decode_report(proc)
                results = [finding for run in report['runs'] for finding in run['results']
                           if finding['ruleId'] == lang + '.taint.path_traversal']
                self.assertEqual(len(results), 1, context)
                self.assertEqual(results[0]['properties']['extras'], extras, context)
                locations = results[0]['codeFlows'][0]['threadFlows'][0]['locations']
                self.assertEqual(len(locations), len(steps), context)
                self.assertEqual([location['executionOrder'] for location in locations],
                                 list(range(len(steps))), context)
                for location, step in zip(locations, steps):
                    physical = location['location']['physicalLocation']
                    self.assertEqual(location['kinds'], [step['kind']], context)
                    self.assertEqual(physical['artifactLocation']['uri'], sarif_uri(step['path']), context)
                    self.assertEqual(physical['region'],
                                     {'startLine': step['line'], 'startColumn': step['col']}, context)

                module = REPO_ROOT / 'modules' / ('ubs-' + lang + '.sh')
                proc = subprocess.run([str(module), str(source), '--ci', '--no-color',
                    '--format=sarif'], cwd=directory, env=env,
                    capture_output=True, text=True, timeout=180)
                (directory / 'module-stdout.log').write_text(proc.stdout)
                (directory / 'module-stderr.log').write_text(proc.stderr)
                context = f'direct module exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                self.assertEqual(proc.returncode, 1, context)
                report = self.decode_report(proc)
                results = [finding for run in report['runs'] for finding in run['results']
                           if finding['ruleId'] == lang + '.taint.path_traversal']
                self.assertEqual(len(results), 1, context)
                self.assertEqual(results[0]['properties']['extras'], extras, context)
                self.assertEqual(results[0]['codeFlows'][0]['threadFlows'][0]['locations'], locations, context)

                source.write_text(text.replace(request, '"fixed"'), encoding='utf-8')
                clean, context = self.cli(source, lang, lang + '-clean')
                self.assertEqual(clean, [], context)

    def test_method_class_overload_and_lexical_shadow_identity(self):
        text = '''class First {
  String relay(String value) { return value; }
  String relay(String first, String second) { return "fixed"; }
  void handler(Request request) {
    String path = request.getParameter("file");
    { String other = "fixed"; Files.readString(other); }
    Files.readString(relay(path)); // unsafe
    Files.readString(relay(path, "other"));
  }
  void unrelated() { String path = "fixed"; Files.readString(path); }
}
class Second {
  String relay(String value) { return "fixed"; }
  void handler(Request request) { Files.readString(relay(request.getParameter("file"))); }
}'''
        _, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))
        kotlin = '''fun handler(request: Request) {
  val path = request.getParameter("file")
  if (true) {
    val path = path
    Files.readString(path) // unsafe
  }
  if (true) {
    val path = "fixed"
    Files.readString(path)
  }
  Files.readString(path) // unsafe
}'''
        _, effects = self.helper(kotlin, '.kt')
        self.assertEqual(set(effects), self.lines(kotlin))

    def test_annotation_is_concretized_at_entry_not_in_literal_local_calls(self):
        text = '''class Flow {
  String expose(@RequestParam String value) { return value; }
  void clean() { Files.readString(expose("fixed")); }
  void exposed(@RequestParam String value) { Files.readString(value); } // unsafe
  void alsoClean() { exposed("fixed"); }
}'''
        _, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))
        self.assertTrue(all('@request value' in trace.evidence[0].label
                            for trace in effects[4]))

    def test_comments_literals_sanitizers_and_unknown_calls(self):
        text = '''class Flow {
  String safeUnderRoot(String value) { return value; }
  void handler(Request request) {
    String path = request.getParameter("file");
    Files.readString("path");
    // Files.readString(path);
    String inert = "request.getParameter(x); Files.readString(path)";
    Files.readString(safeUnderRoot(path)); // unsafe: this selected helper is an identity
    Files.readString(unknown(path)); // unsafe
  }
}'''
        _, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))

    def test_enhanced_loops_and_continue_do_not_run_finally_prematurely(self):
        text = '''class Flow {
  void handler(Request request, boolean again) {
    String path = "fixed";
    try {
      while (again) {
        Files.readString(path); // unsafe
        path = request.getParameter("file");
        continue;
      }
    } finally { path = "fixed"; }
    Files.readString(path);
  }
  void elements(Request request) {
    for (String path : request.getParameterValues("files")) {
      Files.readString(path); // unsafe
    }
  }
}'''
        _, effects = self.helper(text)
        self.assertEqual(set(effects), self.lines(text))
        kotlin = '''fun handler(request: Request) {
  for (path in request.getParameterValues("files")) {
    Files.readString(path) // unsafe
  }
}'''
        _, effects = self.helper(kotlin, '.kt')
        self.assertEqual(set(effects), self.lines(kotlin))

    def test_executable_class_initialization_is_explicitly_incomplete(self):
        from ubs_core.analyzers.taint_java_traversal import Engine
        from ubs_core.taint_flow import AnalysisLimit
        for code in (
            'class A { String p = request.getParameter("x"); { Files.readString(p); } }',
            'class A { String p = request.getParameter("x"); { Files.readString(p); } void method() {} }',
        ):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, 'field-state.*incomplete'):
                Engine(self.root / 'Sample.java', code)
        engine = Engine(self.root / 'Sample.java', 'String p=request.getParameter("x"); Files.readString(p);')
        engine.budget.remaining = 0
        with self.assertRaisesRegex(AnalysisLimit, 'incomplete'):
            engine.analyze()

    def test_array_initializers_are_expressions_and_blocks_stay_incomplete(self):
        # GH #184: `T[] x = {...};` and `new T[]{...}` are JLS 10.6 array
        # initializers, not statement blocks; their elements carry data.
        clean = '''class Flow {
  void run(HttpServletRequest request) {
    final boolean[] flag = {false};
    boolean[] made = new boolean[] {true, false};
    int[][] grid = {{1, 2}, {3}, new int[]{4}};
    String[] fixed = {"a", "b"};
    Files.readString(Path.of("/srv/" + fixed[0]));
  }
}'''
        _, effects = self.helper(clean)
        self.assertEqual(effects, {})
        unsafe = '''class Flow {
  void run(HttpServletRequest request) {
    final boolean[] flag = {false};
    String name = request.getParameter("name");
    String[] names = {"fixed", name};
    java.util.List[] lists = new java.util.List[] {null};
    String[][] grid = {{"fixed"}, {name}};
    String legacy[] = {name};
    new File("/tmp/" + name); // unsafe
    Files.readString(Path.of(names[1])); // unsafe
    new File(grid[1][0]); // unsafe
    new File(legacy[0]); // unsafe
  }
}'''
        _, effects = self.helper(unsafe)
        self.assertEqual(set(effects), self.lines(unsafe))
        # Lambda and anonymous-class bodies contain statements, also when they
        # sit inside an initializer; Kotlin `= {` is a lambda. Still incomplete.
        for text, suffix in (
            ('class F { void f(Request r) { Runnable x = () -> { new File(r.getParameter("a")); }; } }', '.java'),
            ('class F { void f(Request r) { Runnable x = new Runnable() { public void run() {} }; } }', '.java'),
            ('class F { void f(Request r) { Runnable[] x = { () -> { new File(r.getParameter("a")); } }; } }', '.java'),
            ('class F { void f(Request r) { Object[] x = { new Object() { } }; new File(r.getParameter("a")); } }', '.java'),
            ('fun f(r: Request) { val x = { File(r.getParameter("a")) }; x() }', '.kt'),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'expression block.*incomplete'):
                self.helper(text, suffix)
        # The reported file: a brace initializer next to a real traversal flow
        # made the whole Java module exit 2; the flow is now reported.
        path = self.root / 'Repro.java'
        path.write_text(textwrap.dedent('''\
            import java.io.File;
            import javax.servlet.http.HttpServletRequest;

            public class Repro {
                void run(HttpServletRequest request) {
                    final boolean[] flag = {false};
                    String name = request.getParameter("name");
                    File f = new File("/tmp/" + name);
                    f.exists();
                }
            }
        '''), encoding='utf-8')
        findings, context = self.cli(path, 'java', 'gh184-array-initializer', status=1)
        self.assertEqual([finding['line'] for finding in findings], [8], context)

    def test_unmodeled_writes_bind_symbolic_escapes_without_rejecting_clean_setters(self):
        safe = '''class Flow {
  void field(String value) { this.path = value; }
  void element(String value) { values[0] = value; }
  void safe(Request request) {
    String value = request.getParameter("file");
    value = "fixed";
    field(value);
    element("fixed");
    Files.readString("fixed");
  }
}'''
        _, effects = self.helper(safe)
        self.assertEqual(effects, {})
        bad = '''class Flow {
  void field(String value) { this.path = value; }
  void handler(Request request) {
    field(request.getParameter("file"));
    Files.readString(this.path);
  }
}'''
        for text in (
            bad,
            'class Flow { void f(Request request) { values[0] = request.getParameter("x"); Files.readString(values[0]); } }',
            'class Flow { void f(@RequestParam String value) { this.path = value; Files.readString(this.path); } }',
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'heap-state.*incomplete'):
                self.helper(text)
        safe_path = self.root / 'SafeSetter.java'
        safe_path.write_text(safe)
        findings, context = self.cli(safe_path, 'java', 'clean-setter', 0)
        self.assertEqual(findings, [], context)
        bad_path = self.root / 'UnsafeSetter.java'
        bad_path.write_text(bad)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_'))}
        env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', ENABLE_UV_TOOLS='0')
        proc = subprocess.run([str(REPO_ROOT / 'ubs'), '--ci', '--no-color', '--no-cache',
                               '--format=json', '--only=java', '--', str(bad_path)],
                              cwd=self.root, env=env, capture_output=True, text=True, timeout=180)
        (self.root / 'unsafe-setter.stdout.log').write_text(proc.stdout)
        (self.root / 'unsafe-setter.stderr.log').write_text(proc.stderr)
        context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, 2, context)
        report = self.decode_report(proc)
        # The other Java layers ran, but traversal could not model this heap
        # write. Contract v2 preserves their results as partial, still exit 2.
        self.assertEqual(report['status'], 'partial', context)
        self.assertEqual(report['exit_code'], 2, context)
        self.assertEqual(len(report['failed_modules']), 1, context)
        failed = report['failed_modules'][0]
        self.assertEqual(failed['language'], 'java', context)
        self.assertEqual(failed['status'], 'partial', context)
        self.assertEqual(failed['module_error'], 'ANALYZER_ERROR', context)
        self.assertIn('heap-state', proc.stdout + proc.stderr, context)

    def test_kotlin_top_level_parameter_helpers_execute_with_original_offsets(self):
        for suffix in ('.kt', '.kts'):
            for unsafe in (True, False):
                text = ('import java.nio.file.Files\n'
                        'fun relay(value: String): String = value\n'
                        'val unused = request.getParameter("unused")\n'
                        'val path = ' + ('request.getParameter("file")' if unsafe else '"fixed"') + '\n'
                        'val content = Files.readString(relay(path))\n')
                with self.subTest(suffix=suffix, unsafe=unsafe):
                    _, effects = self.helper(text, suffix)
                    self.assertEqual(set(effects), {5} if unsafe else set())
                    path = self.root / ('TopLevel' + ('Unsafe' if unsafe else 'Safe') + suffix)
                    path.write_text(text)
                    findings, context = self.cli(path, 'kotlin', 'native-' + path.name, 1 if unsafe else 0)
                    self.assertEqual({row['line'] for row in findings}, {5} if unsafe else set(), context)
                    self.assertTrue(all(row['severity'] == 'critical' for row in findings), context)

    def test_kotlin_global_captures_are_clean_or_explicitly_incomplete(self):
        safe = ('val unused = request.getParameter("unused")\n'
                'val path = "fixed"\n'
                'fun read() { Files.readString(path) }\n'
                'read()\n')
        _, effects = self.helper(safe, '.kts')
        self.assertEqual(effects, {})
        unsafe = ('val path = request.getParameter("file")\n'
                  'fun read() { Files.readString(path) }\n'
                  'read()\n')
        for text in (
            unsafe,
            'var path=request.getParameter("file")\nfun read() { Files.readString(path) }\nread()\npath="fixed"\n',
            'var path=request.getParameter("file")\nfun read() { Files.readString(path) }\nfun call(path: String) { read() }\ncall("fixed")\npath="fixed"\n',
            'val path=request.getParameter("file")\nfun read() { Files.readString(path) }\n',
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'capture-state.*incomplete'):
                self.helper(text, '.kts')
        shadow = ('val path=request.getParameter("file")\n'
                  'fun read(path: String) { Files.readString(path) }\n'
                  'read("fixed")\n')
        _, effects = self.helper(shadow, '.kts')
        self.assertEqual(effects, {})
        safe_path = self.root / 'SafeCapture.kts'
        safe_path.write_text(safe)
        findings, context = self.cli(safe_path, 'kotlin', 'clean-capture', 0)
        self.assertEqual(findings, [], context)
        bad_path = self.root / 'UnsafeCapture.kts'
        bad_path.write_text(unsafe)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_'))}
        env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', ENABLE_UV_TOOLS='0')
        proc = subprocess.run([str(REPO_ROOT / 'ubs'), '--ci', '--no-color', '--no-cache',
                               '--format=json', '--only=kotlin', '--', str(bad_path)],
                              cwd=self.root, env=env, capture_output=True, text=True, timeout=180)
        (self.root / 'unsafe-capture.stdout.log').write_text(proc.stdout)
        (self.root / 'unsafe-capture.stderr.log').write_text(proc.stderr)
        context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, 2, context)
        report = self.decode_report(proc)
        self.assertEqual(report['status'], 'partial', context)
        self.assertEqual(report['exit_code'], 2, context)
        self.assertEqual(len(report['failed_modules']), 1, context)
        failure = report['failed_modules'][0]
        self.assertEqual((failure['language'], failure['status'], failure['module_error']),
                         ('kotlin', 'partial', 'ANALYZER_ERROR'), context)
        self.assertIn(str(bad_path), failure['message'], context)
        self.assertIn('capture-state', failure['message'], context)
        self.assertIn('analysis is incomplete', failure['message'], context)

    def test_kotlin_nonlocal_writes_preserve_symbolic_escape_polarity(self):
        safe = ('var path = "fixed"\n'
                'fun write(value: String) { path = value }\n'
                'fun read() { Files.readString(path) }\n'
                'val unused = request.getParameter("unused")\n'
                'write("fixed")\n'
                'read()\n')
        _, effects = self.helper(safe, '.kts')
        self.assertEqual(effects, {})
        direct = ('var path = "fixed"\n'
                  'fun write(request: Request) { path = request.getParameter("file") }\n'
                  'fun read() { Files.readString(path) }\n'
                  'write(request)\n'
                  'read()\n')
        symbolic = safe.replace('write("fixed")', 'write(request.getParameter("file"))')
        for text in (direct, symbolic):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'capture-state.*incomplete'):
                self.helper(text, '.kts')
        local = ('val path = "fixed"\n'
                 'fun local(request: Request) { val path = request.getParameter("file"); Files.readString(path) }\n'
                 'local(request)\n')
        _, effects = self.helper(local, '.kts')
        self.assertEqual(set(effects), {2})
        safe_path = self.root / 'SafeNonlocalWrite.kts'
        safe_path.write_text(safe)
        findings, context = self.cli(safe_path, 'kotlin', 'clean-nonlocal-write', 0)
        self.assertEqual(findings, [], context)
        bad_path = self.root / 'UnsafeNonlocalWrite.kts'
        bad_path.write_text(direct)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'GIT_', 'XDG_'))}
        env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', ENABLE_UV_TOOLS='0')
        proc = subprocess.run([str(REPO_ROOT / 'ubs'), '--ci', '--no-color', '--no-cache',
                               '--format=json', '--only=kotlin', '--', str(bad_path)],
                              cwd=self.root, env=env, capture_output=True, text=True, timeout=180)
        (self.root / 'unsafe-nonlocal-write.stdout.log').write_text(proc.stdout)
        (self.root / 'unsafe-nonlocal-write.stderr.log').write_text(proc.stderr)
        context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, 2, context)
        report = self.decode_report(proc)
        self.assertEqual(report['status'], 'partial', context)
        self.assertEqual(report['exit_code'], 2, context)
        self.assertEqual(len(report['failed_modules']), 1, context)
        failure = report['failed_modules'][0]
        self.assertEqual((failure['language'], failure['status'], failure['module_error']),
                         ('kotlin', 'partial', 'ANALYZER_ERROR'), context)
        self.assertIn(str(bad_path), failure['message'], context)
        self.assertIn('capture-state', failure['message'], context)
        self.assertIn('analysis is incomplete', failure['message'], context)

    def test_original_real_cli_scope_reductions(self):
        fixtures = {
            'java-unsafe': 'class Sample {\n  void unsafe(jakarta.servlet.http.HttpServletRequest request) throws java.io.IOException {\n    String path = request.getParameter("file");\n    java.nio.file.Files.readString(java.nio.file.Path.of(path));\n  }\n}\n',
            'java-clean-reassignment': 'class Sample {\n  void clean(jakarta.servlet.http.HttpServletRequest request) throws java.io.IOException {\n    String path = request.getParameter("file");\n    path = "fixed.txt";\n    java.nio.file.Files.readString(java.nio.file.Path.of(path));\n  }\n}\n',
            'java-clean-method': 'class Sample {\n  void first(jakarta.servlet.http.HttpServletRequest request) {\n    String path = request.getParameter("file");\n  }\n  void clean() throws java.io.IOException {\n    String path = "fixed.txt";\n    java.nio.file.Files.readString(java.nio.file.Path.of(path));\n  }\n}\n',
            'kotlin-unsafe': 'fun unsafe(request: jakarta.servlet.http.HttpServletRequest) {\n  val path = request.getParameter("file")\n  java.nio.file.Files.readString(java.nio.file.Path.of(path))\n}\n',
            'kotlin-clean-reassignment': 'fun clean(request: jakarta.servlet.http.HttpServletRequest) {\n  var path = request.getParameter("file")\n  path = "fixed.txt"\n  java.nio.file.Files.readString(java.nio.file.Path.of(path))\n}\n',
            'kotlin-clean-method': 'fun first(request: jakarta.servlet.http.HttpServletRequest) {\n  val path = request.getParameter("file")\n}\nfun clean() {\n  val path = "fixed.txt"\n  java.nio.file.Files.readString(java.nio.file.Path.of(path))\n}\n',
        }
        for lang, suffix, unsafe_line in (('java', '.java', 4), ('kotlin', '.kt', 3)):
            for case in ('unsafe', 'clean-reassignment', 'clean-method'):
                with self.subTest(lang=lang, case=case):
                    original = self.root / (lang + '-' + case + suffix)
                    original.write_text(fixtures[lang + '-' + case])
                    findings, context = self.cli(original, lang, f'{lang}-{case}', 1 if case == 'unsafe' else 0)
                    self.assertEqual([(row['rule'], row['line'], row['severity']) for row in findings],
                                     [(lang + '.taint.path_traversal', unsafe_line, 'critical')] if case == 'unsafe' else [], context)

    def test_real_cli_helpers_branch_loop_and_clean_controls(self):
        sources = {
            'java': '''class Sample {
  String relay(String value) { return value; }
  String safeUnderRoot(String value) { return "fixed"; }
  void save(String value) { java.nio.file.Files.readString(value); } // unsafe
  void handler(jakarta.servlet.http.HttpServletRequest request, boolean again) {
    String path = request.getParameter("file");
    if (again) { path = "fixed"; }
    java.nio.file.Files.readString(path); // unsafe
    String loop = "fixed";
    while (again) { loop = request.getParameter("file"); }
    java.nio.file.Files.readString(loop); // unsafe
    save(relay(request.getParameter("file")));
    java.nio.file.Files.readString(safeUnderRoot(path));
    java.nio.file.Files.readString("path");
    // java.nio.file.Files.readString(path);
  }
}''',
            'kotlin': '''fun relay(value: String): String { return value }
fun safeUnderRoot(value: String): String { return "fixed" }
fun save(value: String) { java.nio.file.Files.readString(value) } // unsafe
fun handler(request: jakarta.servlet.http.HttpServletRequest, again: Boolean) {
  var path = request.getParameter("file")
  if (again) { path = "fixed" }
  java.nio.file.Files.readString(path) // unsafe
  var loop = "fixed"
  while (again) { loop = request.getParameter("file") }
  java.nio.file.Files.readString(loop) // unsafe
  save(relay(request.getParameter("file")))
  java.nio.file.Files.readString(safeUnderRoot(path))
  java.nio.file.Files.readString("path")
  // java.nio.file.Files.readString(path)
}''',
        }
        for lang, suffix in (('java', '.java'), ('kotlin', '.kt')):
            with self.subTest(lang=lang):
                text = sources[lang]
                path = self.root / ('Interprocedural' + suffix)
                path.write_text(text)
                findings, context = self.cli(path, lang, 'interprocedural-' + lang, 1)
                self.assertEqual({row['line'] for row in findings}, self.lines(text), context)
                self.assertEqual(len(findings), len(self.lines(text)), context)
                self.assertTrue(all(row['severity'] == 'critical' for row in findings), context)

    def test_real_cli_unmodeled_initialization_cannot_be_reported_clean(self):
        path = self.root / 'Initializer.java'
        path.write_text('class A { String p = request.getParameter("x"); { java.nio.file.Files.readString(p); } void method() {} }')
        directory = self.root / 'initialization'
        directory.mkdir()
        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                   UBS_SKIP_TYPE_NARROWING='1', ENABLE_UV_TOOLS='0', PYTHONDONTWRITEBYTECODE='1')
        proc = subprocess.run([str(REPO_ROOT / 'ubs'), '--ci', '--format=json', '--no-cache',
                               '--only=java', '--', str(path)], cwd=directory, env=env,
                              capture_output=True, text=True, timeout=180)
        (directory / 'stdout.log').write_text(proc.stdout)
        (directory / 'stderr.log').write_text(proc.stderr)
        context = f'exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        self.assertEqual(proc.returncode, 2, context)
        report = self.decode_report(proc)
        self.assertEqual(report['status'], 'partial', context)
        self.assertEqual(report['exit_code'], 2, context)
        self.assertEqual(len(report['failed_modules']), 1, context)
        failed = report['failed_modules'][0]
        self.assertEqual(failed['language'], 'java', context)
        self.assertEqual(failed['status'], 'partial', context)
        self.assertEqual(failed['module_error'], 'ANALYZER_ERROR', context)
        self.assertIn('field-state', proc.stdout + proc.stderr, context)

    def test_existing_fixture_pairs_preserve_bytes_and_findings(self):
        cases = (
            ('java', 'test-suite/java/security/path_traversal_buggy.java',
             '6775a3f001ce3473642edec380199056bd857ec3bd657b4e7046a90fde59d639',
             {31, 36, 43, 44, 48, 49, 54, 55, 60, 61}),
            ('java', 'test-suite/java/security/path_traversal_clean.java',
             '2fd47fda15d868052b9812018c3a0ba6f1f2fdb0ccfa311c8c69427d1f5efd55', set()),
            ('kotlin', 'test-suite/kotlin/path_traversal_buggy/RequestPaths.kt',
             '06facb3d95e902bdf125512063ba1925d2a7d9cccbe3b5c748f51270b286c168',
             {27, 28, 33, 38, 39, 43, 44, 49, 50}),
            ('kotlin', 'test-suite/kotlin/path_traversal_clean/RequestPathsSafe.kt',
             '12bb84e6e16d4ea33a8ef99789a71cedf23286bc26a03538281964a3f6272e43', set()),
        )
        for lang, name, digest, expected in cases:
            with self.subTest(path=name):
                path = REPO_ROOT / name
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                findings, context = self.cli(path, lang, 'fixture-' + path.stem, 1 if expected else 0)
                self.assertEqual({row['line'] for row in findings}, expected, context)
                self.assertEqual(len(findings), len(expected), context)
                self.assertTrue(all(row['rule'] == lang + '.taint.path_traversal'
                                    and row['severity'] == 'critical' for row in findings), context)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_redirects_use_selected_bindings_and_assignment_kills(self):
        from ubs_core.analyzers.taint_java_redirect import run
        from ubs_core.registry import RunContext
        cases = (
            ('safe-name-identity', '''class A {
  String safeRedirect(String value) { return value; }
  void run(Request request) {
    String target = safeRedirect(request.getParameter("next"));
    response.sendRedirect(target); // unsafe
  }
}'''),
            ('literal-kill', '''class A {
  void run(Request request) {
    String target = request.getParameter("next");
    target = "/fixed";
    response.sendRedirect(target);
  }
}'''),
            ('bound-clean-helper', '''class A {
  String choose(String value) { return "/fixed"; }
  void run(Request request) {
    response.sendRedirect(choose(request.getParameter("next")));
  }
}'''),
            ('branch-join', '''class A {
  void run(Request request, boolean choice) {
    String target = request.getParameter("next");
    if (choice) { target = "/fixed"; }
    response.sendRedirect(target); // unsafe
  }
}'''),
            ('unrelated-scopes', '''class A {
  void source(Request request) { String target = request.getParameter("next"); }
  void sink() { String target = "/fixed"; response.sendRedirect(target); }
}'''),
            ('recursive-helper', '''class A {
  String relay(String value, int count) {
    if (count == 0) { return value; }
    return relay(value, count - 1);
  }
  void run(Request request) {
    response.sendRedirect(relay(request.getParameter("next"), 2)); // unsafe
  }
}'''),
            ('unbound-validator', '''class A {
  void run(Request request) {
    String target = request.getParameter("next");
    if (!isAllowedRedirect(target)) { throw new SecurityException("bad"); }
    response.sendRedirect(target); // unsafe
  }
}'''),
            ('different-sink-proof', '''class A {
  void run(Request request) {
    Path target = Paths.get(request.getParameter("next")).normalize();
    if (!target.startsWith(base)) { throw new SecurityException("bad"); }
    response.sendRedirect(target.toString()); // unsafe
  }
}'''),
        )
        for name, source in cases:
            with self.subTest(case=name):
                path = self.root / (name + '.java')
                path.write_text(source, encoding='utf-8')
                findings = list(run(RunContext(lang='java', files=[path])))
                expected = self.lines(source)
                self.assertEqual({f['line'] for f in findings}, expected, (source, findings))
                self.assertEqual(len(findings), len(expected), findings)
                self.assertTrue(all(f['rule'] == 'java.taint.open_redirect' and
                                    f['severity'] == 'critical' for f in findings), findings)

    def test_redirect_guards_validate_selected_values_and_keep_mutations(self):
        from ubs_core.analyzers.taint_java_redirect import run
        from ubs_core.registry import RunContext
        cases = (
            ('literal-guard', 'if (!"/home".equals(target)) { throw new SecurityException(); }', '', False),
            ('selected-predicate', 'if (!allowed(target)) { throw new SecurityException(); }', '', False),
            ('wrong-receiver', 'if (!other.allowed(target)) { throw new SecurityException(); }', '', True),
            ('partial-guard', 'if (choice) { if (!allowed(target)) { throw new SecurityException(); } }', '', True),
            ('later-mutation', 'if (!allowed(target)) { throw new SecurityException(); }', 'target = "//" + target;', True),
            ('later-source', 'if (!allowed(target)) { throw new SecurityException(); }', 'target = request.getParameter("again");', True),
            ('unknown-transform', 'if (!allowed(target)) { throw new SecurityException(); }', 'target = transform(target);', True),
            ('boolean-precedence', 'if (!allowed(target) || choice) { throw new SecurityException(); }', '', False),
        )
        for name, guard, mutation, unsafe in cases:
            with self.subTest(case=name):
                source = ('class A {\n'
                          ' boolean allowed(String value) { return "/home".equals(value); }\n'
                          ' void run(Request request, boolean choice) {\n'
                          ' String target = request.getParameter("next");\n'
                          f' {guard}\n {mutation}\n'
                          ' response.sendRedirect(target);\n }\n}\n')
                path = self.root / (name + '.java')
                path.write_text(source)
                findings = list(run(RunContext(lang='java', files=[path])))
                self.assertEqual([f['line'] for f in findings], [7] if unsafe else [], (source, findings))

    def test_uri_redirect_validator_requires_authority_and_selected_allowlist(self):
        from ubs_core.analyzers.taint_java_redirect import run
        from ubs_core.registry import RunContext
        cases = (
            ('java', 'test-suite/java/security/OpenRedirectClean.java', {37, 41, 46, 51, 56},
             'parsed.getRawAuthority() != null', 'false'),
            ('kotlin', 'test-suite/kotlin/open_redirect_clean/OpenRedirectClean.kt', {29, 34},
             'uri.rawAuthority == null', 'true'),
        )
        for lang, fixture, sink_lines, condition, missing in cases:
            source = (REPO_ROOT / fixture).read_text()
            suffix = '.java' if lang == 'java' else '.kt'
            variants = (
                ('complete', source, set()),
                ('alpha-renamed', source.replace('safeRedirectTarget', 'chooseTarget'), set()),
                ('network-path-bypass', source.replace(condition, missing), sink_lines),
            )
            if lang == 'kotlin':
                escaped = source.replace('setOf("app.example.com")',
                    'setOf("app.example.com", "accounts.example.com")').replace(
                    'fun redirectQuery(call: ApplicationCall) {',
                    'fun redirectQuery(call: ApplicationCall) { mutateHosts()')
                prefix, closing = escaped.rsplit('\n}', 1)
                escaped = prefix + ('\n    fun mutateHosts() {\n'
                    '        val alias = allowedHosts as MutableSet<String>\n'
                    '        alias.add("evil.example")\n    }\n}') + closing
                variants += (
                    ('escaped-allowlist', escaped, sink_lines),
                    ('public-allowlist', source.replace('private val allowedHosts',
                                                       'val allowedHosts'), sink_lines),
                    ('typed-host-factory', source.replace('import java.net.URI',
                        'import java.net.URI\nimport java.util.Set').replace(
                        '    private val allowedHosts = setOf("app.example.com")',
                        '    private val Set: HostFactory = HostFactory()\n'
                        '    private val allowedHosts = Set.of("app.example.com")') +
                        '\nclass HostFactory {\n'
                        '    fun of(value: String): kotlin.collections.Set<String> {\n'
                        '        return kotlin.collections.setOf("evil.example")\n    }\n}\n',
                        {line + 2 for line in sink_lines}),
                    ('typed-callable-set', source.replace(
                        '    private val allowedHosts = setOf("app.example.com")',
                        '    private val setOf: (String) -> Set<String> = '
                        '{ kotlin.collections.setOf("evil.example") }\n'
                        '    private val allowedHosts = setOf("app.example.com")'),
                        {line + 1 for line in sink_lines}),
                )
            for label, text, expected in variants:
                with self.subTest(language=lang, case=label):
                    path = self.root / (lang + '-' + label + suffix)
                    path.write_text(text)
                    findings = list(run(RunContext(lang=lang, files=[path])))
                    self.assertEqual({f['line'] for f in findings}, expected, (text, findings))
                    self.assertEqual(len(findings), len(expected), findings)

    def test_kotlin_uri_factory_shadow_cannot_validate_redirects(self):
        from ubs_core.analyzers.taint_java_redirect import run
        from ubs_core.registry import RunContext
        source = '''import java.net.URI
class Bogus(val raw: String) {
  val isAbsolute = true
  val scheme = "https"
  val host = "app.example.com"
  val path = "/home"
  val rawAuthority: String? = null
  override fun toString(): String = raw
}
class Factory {
  fun create(value: String): Bogus = Bogus(value)
}
class Sample {
  private val allowedHosts = setOf("app.example.com")
  fun choose(raw: String, URI: Factory): String {
    val uri = URI.create(raw)
    if (uri.isAbsolute) {
      require(uri.scheme == "https" && uri.host in allowedHosts) { "blocked" }
      return uri.toString()
    }
    require(uri.rawAuthority == null) { "blocked" }
    require(uri.path.startsWith("/") && !uri.path.startsWith("//")) { "blocked" }
    return uri.toString()
  }
  fun run(call: ApplicationCall) {
    call.respondRedirect(choose(call.request.queryParameters["next"] ?: "/", Factory()))
  }
}'''
        path = self.root / 'ShadowedUri.kt'
        path.write_text(source)
        findings = list(run(RunContext(lang='kotlin', files=[path])))
        self.assertEqual([(f['rule'], f['line']) for f in findings],
                         [('java.taint.open_redirect', 26)], findings)
        cli_findings, context = self.cli(path, 'kotlin', 'shadowed-uri', 1,
                                         rule='open_redirect')
        self.assertEqual([(f['rule'], f['line']) for f in cli_findings],
                         [('kotlin.taint.open_redirect', 26)], context)

        field_shadow = source.replace('  fun choose(raw: String, URI: Factory)',
            '  private val URI: Factory = Factory()\n  fun choose(raw: String)').replace(
            'choose(call.request.queryParameters["next"] ?: "/", Factory())',
            'choose(call.request.queryParameters["next"] ?: "/")')
        path = self.root / 'FieldShadowedUri.kt'
        path.write_text(field_shadow)
        findings = list(run(RunContext(lang='kotlin', files=[path])))
        self.assertEqual([f['line'] for f in findings], [27], findings)
        cli_findings, context = self.cli(path, 'kotlin', 'field-shadowed-uri', 1,
                                         rule='open_redirect')
        self.assertEqual([(f['rule'], f['line']) for f in cli_findings],
                         [('kotlin.taint.open_redirect', 27)], context)

        no_op = source.replace('URI: Factory', 'require: NoOp').replace(
            'Factory()))', 'NoOp()))').replace('class Factory {',
            'class NoOp { operator fun invoke(value: Boolean, message: () -> String) {} }\nclass Factory {')
        path = self.root / 'ShadowedRequire.kt'
        path.write_text(no_op)
        findings = list(run(RunContext(lang='kotlin', files=[path])))
        self.assertEqual([f['line'] for f in findings], [27], findings)

        field_require = no_op.replace('  fun choose(raw: String, require: NoOp)',
            '  private val require: NoOp = NoOp()\n  fun choose(raw: String)').replace(
            'choose(call.request.queryParameters["next"] ?: "/", NoOp())',
            'choose(call.request.queryParameters["next"] ?: "/")')
        path = self.root / 'FieldShadowedRequire.kt'
        path.write_text(field_require)
        findings = list(run(RunContext(lang='kotlin', files=[path])))
        self.assertEqual([f['line'] for f in findings], [28], findings)

    def test_real_cli_redirect_binding_and_uri_controls(self):
        cases = (
            ('java', '.java', '''class Sample {
  String safeRedirect(String value) { return value; }
  void run(Request request) {
    String target = safeRedirect(request.getParameter("next"));
    response.sendRedirect(target);
  }
}''', 5),
            ('kotlin', '.kt', '''fun safeRedirect(value: String): String { return value }
fun run(call: ApplicationCall) {
  var target = safeRedirect(call.request.queryParameters["next"] ?: "/")
  call.respondRedirect(target)
}''', 4),
        )
        for lang, suffix, source, sink_line in cases:
            variants = (
                ('misleading-helper', source, True),
                ('alpha-renamed', source.replace('safeRedirect', 'relay'), True),
                ('literal-overwrite', source.replace('    response.sendRedirect(target);',
                  '    target = "/fixed"; response.sendRedirect(target);').replace('  call.respondRedirect(target)',
                  '  target = "/fixed"; call.respondRedirect(target)'), False),
            )
            for label, text, unsafe in variants:
                with self.subTest(language=lang, case=label):
                    path = self.root / (lang + '-' + label + suffix)
                    path.write_text(text)
                    findings, context = self.cli(path, lang, lang + '-' + label,
                                                 1 if unsafe else 0, rule='open_redirect')
                    self.assertEqual([(f['rule'], f['line'], f['severity']) for f in findings],
                                     [(lang + '.taint.open_redirect', sink_line, 'critical')] if unsafe else [], context)
                    report = json.loads((self.root / (lang + '-' + label) / 'stdout.log').read_text())
                    self.assertEqual(report['totals']['critical'], int(unsafe), context)
                    self.assertEqual(report['totals']['warning'], 0, context)
                    if unsafe:
                        self.assertTrue(all(f['extras']['taint_path'] for f in findings), context)
                    directory = self.root / (lang + '-' + label + '-sarif')
                    directory.mkdir()
                    env = os.environ.copy()
                    env.update(PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1',
                               UBS_NO_CACHE='1', ENABLE_UV_TOOLS='0')
                    for tool, arguments in (
                        ('meta', [str(REPO_ROOT / 'ubs'), '--only=' + lang, '--format=sarif', '--ci', str(path)]),
                        ('module', [str(REPO_ROOT / 'modules' / ('ubs-' + lang + '.sh')), '--format=sarif', '--ci', str(path)]),
                    ):
                        started = time.monotonic()
                        proc = subprocess.run(arguments, cwd=directory, env=env,
                                              capture_output=True, text=True, timeout=180)
                        (directory / (tool + '.stdout.log')).write_text(proc.stdout)
                        (directory / (tool + '.stderr.log')).write_text(proc.stderr)
                        (directory / (tool + '.command.json')).write_text(json.dumps({
                            'case': self.id(), 'command': arguments, 'cwd': str(directory),
                            'seconds': time.monotonic() - started, 'exit': proc.returncode,
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        }, indent=2))
                        context = f'{arguments!r}: exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                        self.assertEqual(proc.returncode, int(unsafe), context)
                        sarif = self.decode_report(proc)
                        records = [record for run in sarif['runs'] for record in run.get('results', [])
                                   if record['ruleId'] == lang + '.taint.open_redirect']
                        self.assertEqual([record['locations'][0]['physicalLocation']['region']['startLine']
                                          for record in records], [sink_line] if unsafe else [], context)
                        if unsafe:
                            self.assertEqual(records[0]['properties']['extras'], findings[0]['extras'], context)
                            self.assertEqual(len(records[0]['codeFlows'][0]['threadFlows'][0]['locations']),
                                             len(findings[0]['extras']['taint_path']), context)


class JVMRedirectBindingTests(unittest.TestCase):
    """Binding-equivalent regressions specified before the JVM policy changes."""

    def setUp(self):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='jvm-bindings-', dir=artifacts))

    @staticmethod
    def path_operand_cases(lang):
        java = lang == 'java'

        def program(body):
            header = ('void handle(Request request, Path root)' if java else
                      'fun handle(request: Request, root: Path)')
            return 'class PathOperands {\n  ' + header + ' {\n' + body + '\n  }\n}\n'

        string = 'String' if java else 'var'
        path_type = 'Path' if java else 'val'
        getters = (
            ('path', 'Paths.get(request.getParameter("file")).getFileName().toString()' if java else
             'Path.of(request.getParameter("file")).fileName.toString()'),
            ('file', 'new File(request.getParameter("file")).getName()' if java else
             'File(request.getParameter("file")).name'),
        )
        reject = 'throw ' + ('new ' if java else '') + 'IllegalArgumentException("dot directory");'
        for getter, expression in getters:
            source = '    ' + string + ' leaf = ' + expression + ';\n'
            checks = 'leaf.equals(".") || leaf.equals("..")' if java else 'leaf == "." || leaf == ".."'
            guard = '    if (' + checks + ') { ' + reject + ' }\n'
            yield 'basename-' + getter + '-terminal-files', program(source +
                '    Files.readString(root.resolve(leaf));\n'
                '    Files.writeString(root.resolve(leaf), request.getParameter("body"));\n'
                '    Files.copy(Path.of("/srv/source.txt"), root.resolve(leaf));')
            yield 'basename-' + getter + '-child-component', program(source +
                '    Files.readString(root.resolve(leaf).resolve("secret.txt")); // unsafe')
            yield 'basename-' + getter + '-directory-walk', program(source +
                '    Files.walk(root.resolve(leaf)); // unsafe\n'
                '    Files.list(root.resolve(leaf)); // unsafe\n'
                '    Files.newDirectoryStream(root.resolve(leaf)); // unsafe')
            yield 'basename-' + getter + '-checked-directory', program(source + guard +
                '    Files.walk(root.resolve(leaf));\n'
                '    Files.newDirectoryStream(root.resolve(leaf));')
            yield 'basename-' + getter + '-partial-rejection', program(source +
                '    if (' + ('leaf.equals(".")' if java else 'leaf == "."') + ') { ' + reject + ' }\n'
                '    Files.walk(root.resolve(leaf)); // unsafe')
            yield 'basename-' + getter + '-unknown-transform', program(source +
                '    Files.readString(root.resolve(change(leaf))); // unsafe')
            yield 'basename-' + getter + '-real-path-is-absolute', program(source +
                '    Files.readString(root.resolve(Path.of(leaf).toRealPath())); // unsafe')
            yield 'basename-' + getter + '-canonical-path-is-absolute', program(source +
                '    Files.readString(root.resolve(' + ('new ' if java else '') +
                'File(leaf).getCanonicalPath())); // unsafe')
            yield 'basename-' + getter + '-changed-after-guard', program(source + guard +
                '    leaf = request.getParameter("other");\n'
                '    Files.readString(root.resolve(leaf)); // unsafe')
            yield 'basename-' + getter + '-directory-concatenation', program(source +
                '    Files.readString(Path.of("/srv/uploads/" + leaf + "/secret.txt")); // unsafe')

        yield 'write-string-content-is-not-path', program(
            '    Files.writeString(Path.of("/srv/content.txt"), request.getParameter("body"));')
        yield 'unknown-resolve-cannot-create-path-type', program(
            '    Files.readString(Path.of(change(request.getParameter("file")).resolve("fixed").getFileName())); // unsafe')
        yield 'actual-path-resolve-retains-path-type', program(
            '    Files.readString(Path.of(request.getParameter("file")).resolve("fixed").getFileName());')
        yield 'write-bytes-content-is-not-path', program(
            '    Files.write(Path.of("/srv/content.bin"), request.getParameter("body").' +
            ('getBytes()' if java else 'toByteArray()') + ');')
        yield 'write-result-preserves-only-path', program(
            '    ' + path_type + ' written = Files.writeString(Path.of("/srv/content.txt"), request.getParameter("body"));\n'
            '    Files.readString(written);')
        yield 'write-unsafe-path-and-return', program(
            '    ' + path_type + ' written = Files.writeString(Path.of(request.getParameter("file")), "fixed"); // unsafe\n'
            '    Files.readString(written); // unsafe')
        yield 'copy-and-move-both-path-operands', program(
            '    Files.copy(Path.of(request.getParameter("source")), Path.of("/srv/target")); // unsafe\n'
            '    Files.copy(Path.of("/srv/source"), Path.of(request.getParameter("target"))); // unsafe\n'
            '    Files.move(Path.of(request.getParameter("source")), Path.of("/srv/target")); // unsafe\n'
            '    Files.move(Path.of("/srv/source"), Path.of(request.getParameter("target"))); // unsafe')
        yield 'random-access-mode-is-not-path', program(
            '    ' + ('new ' if java else '') + 'RandomAccessFile("/srv/content.bin", request.getParameter("mode"));')
        yield 'path-basename-normalize-tofile-keeps-leaf-proof', program(
            '    ' + path_type + ' leaf = Path.of(request.getParameter("file")).' +
            ('getFileName()' if java else 'fileName') + ';\n'
            '    ' + ('new ' if java else '') + 'FileInputStream(leaf.normalize().toFile());')
        if java:
            yield 'path-equals-string-is-not-dot-rejection', program(
                '    Path leaf = Paths.get(request.getParameter("file")).getFileName();\n'
                '    if (leaf.equals(".") || leaf.equals("..")) { ' + reject + ' }\n'
                '    Files.walk(root.resolve(leaf)); // unsafe')
            yield 'path-rendered-dot-rejection', program(
                '    Path leaf = Paths.get(request.getParameter("file")).getFileName();\n'
                '    if (leaf.toString().equals(".") || leaf.toString().equals("..")) { ' + reject + ' }\n'
                '    Files.walk(root.resolve(leaf));')
        else:
            for method in ('normalize', 'getName', 'getFileName'):
                extension = 'fun String.' + method + '(): String = "../" + this\n'
                yield 'string-' + method + '-extension-is-not-path-proof', extension + program(
                    '    val leaf = File(request.getParameter("file")).name.' + method + '();\n'
                    '    Files.readString(root.resolve(leaf)); // unsafe')
            yield 'string-tofile-extension-is-not-path-conversion', '''fun String.toFile(): File = File("../" + this)
''' + program(
                '    val leaf = File(request.getParameter("file")).name.toFile();\n'
                '    FileInputStream(leaf); // unsafe')
            yield 'string-normalize-extension-direct-call-is-also-unsafe', '''fun String.normalize(): String = "../" + this
''' + program(
                '    val leaf = File(request.getParameter("file")).name;\n'
                '    Files.readString(root.resolve(leaf.normalize())); // unsafe')
            yield 'string-extension-does-not-replace-path-normalize', '''fun String.normalize(): String = "../" + this
''' + program(
                '    val leaf = Path.of(request.getParameter("file")).fileName;\n'
                '    FileInputStream(leaf.normalize().toFile());')
            for method, result, expression in (
                ('getCanonicalPath', 'String', '"../" + File(this).name'),
                ('getCanonicalFile', 'File', 'File("../" + File(this).name)'),
                ('toFile', 'File', 'File("../" + File(this).name)'),
            ):
                yield 'contained-string-' + method + '-extension-invalidates-proof', (
                    'fun String.' + method + '(): ' + result + ' = ' + expression + '\n' + '''class ConvertedPath {
  fun choose(root: Path, raw: String): Path {
    val target = root.resolve(raw).normalize()
    if (!target.startsWith(root)) { throw IllegalArgumentException("outside root") }
    return target
  }
  fun handle(request: Request, root: Path) {
    val escaped = choose(root, request.getParameter("file")).toString().''' + method + '''()
    FileInputStream(escaped) // unsafe
  }
}
''')

    @staticmethod
    def cases(lang):
        java = lang == 'java'
        def program(helper, body):
            definition = ('String ' + helper + '(String value) { return value; }' if java else
                          'fun ' + helper + '(value: String): String { return value }')
            handler = ('void handler(Request request, Response response)' if java else
                       'fun handler(request: Request, response: Response)')
            return 'class Controller {\n  ' + definition + '\n  ' + handler + ' {\n' + body + '\n  }\n}\n'
        declaration = 'String target' if java else 'var target'
        source = '    ' + declaration + ' = request.getParameter("next");\n'
        for name in ('safeRedirect', 'identity'):
            yield name, program(name, source + '    response.sendRedirect(' + name + '(target));'), 'open_redirect', {5}
        yield 'literal-overwrite', program('identity', source + '    target = "/fixed";\n    response.sendRedirect(target);'), 'open_redirect', set()
        guard = r'target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t")'
        reject = ('new ' if java else '') + 'SecurityException("blocked")'
        yield 'local-url-guard', program('identity', source + '    if (!(' + guard + ')) { throw ' + reject + '; }\n    response.sendRedirect(target);'), 'open_redirect', set()
        yield 'misleading-path-helper', program('safePath', source + '    ' + ('new ' if java else '') + 'FileInputStream(safePath(target));'), 'path_traversal', {5}
        yield 'branch-retains-unsafe-path', program('identity', source + '    if (request.isEnabled()) { target = "/fixed"; }\n    response.sendRedirect(target);'), 'open_redirect', {6}
        yield 'guard-overwritten', program('identity', source + '    if (!(' + guard + ')) { throw ' + reject + '; }\n    target = request.getParameter("other");\n    response.sendRedirect(target);'), 'open_redirect', {7}
        if java:
            yield 'inline-canonical-string-prefix', '''class C {
  File choose(String root, String raw) {
    File target=new File(raw);
    if (!target.getCanonicalPath().startsWith(root)) { throw new SecurityException(); }
    return target;
  }
  void handle(Request request) {
    new FileInputStream(choose("/srv/uploads", request.getParameter("file")));
  }
}''', 'path_traversal', {3, 8}
            yield 'chained-path-transform-invalidates-containment', '''class C {
  void handle(Request request) {
    Path root=Path.of("/srv/uploads");
    Path target=root.resolve(request.getParameter("file")).normalize();
    if (!target.startsWith(root)) { return; }
    Files.readString(target.normalize().resolveSibling("../../etc/passwd"));
  }
}''', 'path_traversal', {4, 6}
            yield 'selected-component-containment', '''class C {
  Path choose(Path root, String raw) {
    Path target=root.resolve(raw).normalize();
    if (!target.normalize().startsWith(root)) { throw new SecurityException(); }
    return target.normalize();
  }
  void handle(Request request) {
    Files.readString(choose(Path.of("/srv/uploads"), request.getParameter("file")));
  }
}''', 'path_traversal', set()
        else:
            yield 'inline-canonical-string-prefix', '''class C {
  fun choose(root: String, raw: String): File {
    val target=File(raw)
    if (!target.getCanonicalPath().startsWith(root)) { throw SecurityException() }
    return target
  }
  fun handle(request: Request) {
    FileInputStream(choose("/srv/uploads", request.getParameter("file")))
  }
}''', 'path_traversal', {3, 8}
            yield 'chained-path-transform-invalidates-containment', '''class C {
  fun handle(request: Request) {
    val root=Path.of("/srv/uploads")
    val target=root.resolve(request.getParameter("file")).normalize()
    if (!target.startsWith(root)) { return }
    Files.readString(target.normalize().resolveSibling("../../etc/passwd"))
  }
}''', 'path_traversal', {4, 6}
            yield 'selected-component-containment', '''class C {
  fun choose(root: Path, raw: String): Path {
    val target=root.resolve(raw).normalize()
    if (!target.normalize().startsWith(root)) { throw SecurityException() }
    return target.normalize()
  }
  fun handle(request: Request) {
    Files.readString(choose(Path.of("/srv/uploads"), request.getParameter("file")))
  }
}''', 'path_traversal', set()
            yield 'callable-parameter-shadows-helper', '''fun destination(value: String): String = "/fixed"
fun handler(request: Request, response: Response, destination: (String) -> String) {
  val target=request.getParameter("next")
  response.sendRedirect(destination(target))
}
''', 'open_redirect', {4}
            yield 'explicit-this-selects-method-despite-callable-parameter', '''class C {
  fun destination(value: String): String = "/fixed"
  fun handler(request: Request, response: Response, destination: (String) -> String) {
    response.sendRedirect(this.destination(request.getParameter("next")))
  }
}
''', 'open_redirect', set()
            yield 'nested-helper-is-not-visible-in-sibling', '''open class Base {
  fun destination(value: String): String = value
}
class Handler: Base() {
  fun unrelated() {
    fun destination(value: String): String = "/fixed"
  }
  fun handle(request: Request, response: Response) {
    response.sendRedirect(destination(request.getParameter("next")))
  }
}
''', 'open_redirect', {9}
            yield 'named-argument-return-is-unsafe', '''fun destination(ignored: String, raw: String): String = raw
fun handle(request: Request, response: Response) {
  response.sendRedirect(destination(raw=request.getParameter("next"), ignored="/fixed"))
}
''', 'open_redirect', {3}
            yield 'named-argument-ignored-is-safe', '''fun destination(ignored: String, raw: String): String = raw
fun handle(request: Request, response: Response) {
  response.sendRedirect(destination(raw="/fixed", ignored=request.getParameter("next")))
}
''', 'open_redirect', set()
            yield 'native-named-url-is-unsafe', '''suspend fun handle(request: Request, call: ApplicationCall) {
  call.respondRedirect(permanent=false, url=request.getParameter("next"))
}
''', 'open_redirect', {2}
            yield 'native-named-permanent-does-not-taint-url', '''suspend fun handle(request: Request, call: ApplicationCall) {
  call.respondRedirect(permanent=request.getParameter("permanent") == "true", url="/fixed")
}
''', 'open_redirect', set()
        if java:
            yield 'generic-request-body-guard', ('class C { void handler(@RequestBody Box<String> target) {\n'
                  'if (!(' + guard + ')) { return; }\n'
                  'response.sendRedirect(target.toString());\n} }'), 'open_redirect', {3}
            yield 'path-string-prefix', '''class C {
  String choose(Path root, String raw) {
    Path candidate=root.resolve(raw).normalize();
    String rendered=candidate.toString();
    String rootText=root.toString();
    if (!rendered.startsWith(rootText)) { throw new SecurityException(); }
    return rendered;
  }
  void handler(Request request, Path root) {
    Files.readString(Path.of(choose(root, request.getParameter("file"))));
  }
}''', 'path_traversal', {3, 10}
        if not java:
            yield 'imported-require', ('import app.validation.require\n'
                  'fun handler(request: Request, response: Response) {\n'
                  '  val target=request.getParameter("next")\n'
                  '  require(' + guard + ')\n'
                  '  response.sendRedirect(target)\n}\n'), 'open_redirect', {5}
            yield 'path-string-prefix', '''class C {
  fun choose(root: Path, raw: String): String {
    val candidate=root.resolve(raw).normalize()
    val rendered=candidate.toString()
    val rootText=root.toString()
    if (!rendered.startsWith(rootText)) { throw SecurityException() }
    return rendered
  }
  fun handler(request: Request, root: Path) {
    Files.readString(Path.of(choose(root, request.getParameter("file"))))
  }
}''', 'path_traversal', {3, 10}
            yield 'string-extension-uri-guard', '''import java.net.URI
fun String.isAbsolute(): Boolean = false
val String.rawAuthority: String? get() = null
fun handler(request: Request, response: Response) {
  val uri=URI.create(request.getParameter("next"))
  if (!uri.path.startsWith("/") || uri.path.startsWith("//")) { return }
  val target=uri.toString()
  if (target.isAbsolute() || target.rawAuthority != null || target.startsWith("//")) { return }
  response.sendRedirect(target)
}
''', 'open_redirect', {9}
        for label, code in JVMRedirectBindingTests.path_operand_cases(lang):
            expected = {line for line, text in enumerate(code.splitlines(), 1) if '// unsafe' in text}
            yield label, code, 'path_traversal', expected

    def scan(self, code, lang='java', domain='open_redirect'):
        from ubs_core.registry import RunContext
        from ubs_core.analyzers import taint_java_redirect, taint_java_traversal
        self.sequence = getattr(self, 'sequence', 0) + 1
        path = self.root / ('Case' + str(self.sequence) + ('.java' if lang == 'java' else '.kt'))
        code = textwrap.dedent(code).lstrip('\n')
        path.write_text(code, encoding='utf-8')
        analyzer = taint_java_redirect if domain == 'open_redirect' else taint_java_traversal
        return list(analyzer.run(RunContext(lang=lang, files=[path])))

    def check(self, code, lang='java', domain='open_redirect'):
        code = textwrap.dedent(code).lstrip('\n')
        expected = {line for line, text in enumerate(code.splitlines(), 1) if '// unsafe' in text}
        findings = self.scan(code, lang, domain)
        self.assertEqual({finding['line'] for finding in findings}, expected, (code, findings))
        self.assertEqual(len(findings), len(expected), (code, findings))
        self.assertTrue(all(finding['rule'] == 'java.taint.' + domain for finding in findings))
        return findings

    def test_baseline_cases_keep_binding_equivalence(self):
        for lang in ('java', 'kotlin'):
            for label, code, domain, expected in self.cases(lang):
                with self.subTest(lang=lang, label=label):
                    findings = self.scan(code, lang, domain)
                    self.assertEqual({finding['line'] for finding in findings}, expected, (code, findings))

    def test_path_api_semantics_independently_reject_prefix_and_transform_proofs(self):
        if shutil.which('java') is None:
            self.skipTest('Java runtime unavailable for the independent path API oracle')
        oracle = self.root / 'PathGuardOracle.java'
        oracle.write_text('''import java.io.File;
import java.nio.file.Path;
class PathGuardOracle { public static void main(String[] args) throws Exception {
  Path root=Path.of("/srv/uploads");
  File sibling=new File("/srv/uploads-evil/secret");
  if (!sibling.getCanonicalPath().startsWith(root.toString())) throw new AssertionError();
  if (sibling.getCanonicalFile().toPath().startsWith(root)) throw new AssertionError();
  Path target=root.resolve("user.txt").normalize();
  if (!target.normalize().startsWith(root)) throw new AssertionError();
  Path escaped=target.normalize().resolveSibling("../../etc/passwd").normalize();
  if (escaped.startsWith(root)) throw new AssertionError();
  System.out.println("string prefix admits sibling; chained transform escapes root");
} }''', encoding='utf-8')
        command = ['java', str(oracle)]
        started = time.monotonic()
        proc = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=30)
        (self.root / 'path-api-oracle.stdout.log').write_text(proc.stdout)
        (self.root / 'path-api-oracle.stderr.log').write_text(proc.stderr)
        (self.root / 'path-api-oracle.identity.json').write_text(json.dumps({
            'command': command, 'source_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
            'exit': proc.returncode, 'elapsed': time.monotonic() - started,
        }, indent=2))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip(), 'string prefix admits sibling; chained transform escapes root')

    def test_symlinked_sources_keep_canonical_taint_evidence_identity(self):
        from ubs_core.analyzers import taint_java_redirect, taint_java_traversal
        from ubs_core.registry import RunContext
        physical = self.root / 'physical'
        physical.mkdir()
        alias = self.root / 'selected-alias'
        alias.symlink_to(physical, target_is_directory=True)
        for lang in ('java', 'kotlin'):
            for label, code, domain, expected in self.cases(lang):
                if label not in {'safeRedirect', 'misleading-path-helper'}:
                    continue
                analyzer = taint_java_redirect if domain == 'open_redirect' else taint_java_traversal
                path = physical / (label + ('.java' if lang == 'java' else '.kt'))
                path.write_text(code, encoding='utf-8')
                canonical_extras = None
                for selected in (path, alias / path.name):
                    case = lang + '-' + label + '-' + selected.parent.name
                    started = time.monotonic()
                    print(f'[{case}] RUN', flush=True)
                    with self.subTest(case=case):
                        records = list(analyzer.run(RunContext(lang=lang, files=[selected])))
                        self.assertEqual({row['line'] for row in records}, expected, records)
                        self.assertEqual(len(records), len(expected), records)
                        self.assertTrue(all(row['rule'] == 'java.taint.' + domain for row in records), records)
                        extras = [row['extras'] for row in records]
                        (self.root / (case + '.json')).write_text(json.dumps({
                            'selected': str(selected), 'canonical': str(path.resolve()),
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'records': records,
                        }, indent=2), encoding='utf-8')
                        self.assertTrue(all(step['path'] == str(path.resolve())
                                            for item in extras for step in item['taint_path']), records)
                        if canonical_extras is None:
                            canonical_extras = extras
                        else:
                            self.assertEqual(extras, canonical_extras, records)
                        print(f'[{case}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    def test_basename_leaf_and_directory_semantics_with_real_java(self):
        if shutil.which('java') is None:
            self.skipTest('Java runtime unavailable for the independent basename API oracle')
        oracle = self.root / 'BasenameOperandOracle.java'
        oracle.write_text('''import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
class BasenameOperandOracle {
  public static void main(String[] args) throws Exception {
    Path sandbox = Path.of(args[0]).toAbsolutePath();
    Path root = Files.createDirectories(sandbox.resolve("uploads"));
    Path secret = sandbox.resolve("secret.txt");
    Files.writeString(secret, "outside the upload root");
    for (String dot : new String[]{".", ".."}) {
      if (!Path.of(dot).getFileName().toString().equals(dot)) throw new AssertionError();
      if (!new File(dot).getName().equals(dot)) throw new AssertionError();
      Path leaf = root.resolve(Path.of(dot).getFileName());
      try { Files.readString(leaf); throw new AssertionError("directory read as file"); }
      catch (IOException expected) { }
      try { Files.writeString(leaf, "must not write a directory"); throw new AssertionError("directory written as file"); }
      catch (IOException expected) { }
    }
    Path parent = root.resolve(Path.of("..").getFileName());
    if (!Files.readString(parent.resolve("secret.txt")).equals("outside the upload root")) throw new AssertionError();
    try (var paths = Files.walk(parent)) {
      if (!paths.anyMatch(path -> path.toAbsolutePath().normalize().equals(secret))) throw new AssertionError();
    }
    Path fixed = root.resolve("content.txt");
    Path returned = Files.writeString(fixed, "../this-is-content");
    if (!returned.equals(fixed) || !Files.readString(returned).equals("../this-is-content")) throw new AssertionError();
    Path localSecret = Files.writeString(Path.of("basename-secret.txt"), "absolute path escapes");
    String name = localSecret.getFileName().toString();
    for (Path absolute : new Path[]{Path.of(name).toRealPath(), new File(name).getCanonicalFile().toPath()}) {
      Path escaped = root.resolve(absolute);
      if (!absolute.isAbsolute() || escaped.startsWith(root)) throw new AssertionError();
      if (!Files.readString(escaped).equals("absolute path escapes")) throw new AssertionError();
    }
    if (root.resolve(new File(name).getCanonicalPath()).startsWith(root)) throw new AssertionError();
    if (!root.resolve(Path.of(name).normalize()).startsWith(root)) throw new AssertionError();
    System.out.println("dot leaves are directories; child and walk escape; write content does not select path");
  }
}''', encoding='utf-8')
        command = ['java', str(oracle), str(self.root / 'java-basename-oracle')]
        started = time.monotonic()
        proc = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=30)
        (self.root / 'basename-api.stdout.log').write_text(proc.stdout)
        (self.root / 'basename-api.stderr.log').write_text(proc.stderr)
        (self.root / 'basename-api.identity.json').write_text(json.dumps({
            'command': command, 'source_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
            'exit': proc.returncode, 'elapsed': time.monotonic() - started,
        }, indent=2))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip(),
                         'dot leaves are directories; child and walk escape; write content does not select path')

    def test_selected_helpers_recursion_loops_and_scope_isolation(self):
        code = '''class Flow {
  String safeRedirect(String x) { return x; }
  String fixed(String x) { return "/fixed"; }
  String recursive(String x, int n) { if (n == 0) { return x; } return recursive(x, n - 1); }
  void send(String x) { response.sendRedirect(x); } // unsafe
  void handler(Request request, boolean again) {
    String target = "/fixed";
    while (again) { target = request.getParameter("next"); }
    send(recursive(safeRedirect(target), 4));
    response.sendRedirect(fixed(target));
    response.sendRedirect(other.fixed(target)); // unsafe
  }
  void unrelated(Request request) { String target = request.getParameter("next"); }
  void clean() { String target = "/fixed"; response.sendRedirect(target); }
}'''
        findings = self.check(code)
        witness = findings[0]['extras']['taint_path']
        self.assertTrue({'source', 'call', 'return', 'sink'} <= {step['kind'] for step in witness}, witness)
        self.check('''fun safeRedirect(x: String): String = x
fun fixed(x: String): String = "/fixed"
fun recursive(x: String, n: Int): String {
  if (n == 0) { return x }
  return recursive(x, n - 1)
}
fun send(x: String) { response.sendRedirect(x) } // unsafe
fun handler(request: Request, again: Boolean) {
  var target = "/fixed"
  while (again) { target = request.getParameter("next") }
  send(recursive(safeRedirect(target), 4))
  response.sendRedirect(fixed(target))
}
fun unrelated(request: Request) { val target = request.getParameter("next") }
fun clean() { val target = "/fixed"; response.sendRedirect(target) }
''', 'kotlin')

    def test_guard_dominance_ignored_checks_other_values_and_mutations(self):
        guard = r'target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t")'
        prefix = 'String target = request.getParameter("next");\n'
        cases = (
            ('if (!(' + guard + ')) { return; }\nresponse.sendRedirect(target);', False),
            ('if (' + guard + ') { response.sendRedirect(target); }', False),
            ('if (!(' + guard + ')) { log("bad"); }\nresponse.sendRedirect(target);', True),
            ('boolean ignored = ' + guard + ';\nresponse.sendRedirect(target);', True),
            ('String other=request.getParameter("other"); if (!(' + guard.replace('target', 'other') + ')) { return; }\nresponse.sendRedirect(target);', True),
            ('if (!(' + guard + ')) { return; }\ntarget=request.getParameter("other"); response.sendRedirect(target);', True),
            ('if (!(' + guard + ')) { return; }\ntarget += request.getParameter("other"); response.sendRedirect(target);', True),
            ('if (!(' + guard + ')) { return; }\nresponse.sendRedirect(target.replace("/", "//"));', True),
            ('if (isAllowedRedirect(target)) { response.sendRedirect(target); }', True),
            ('if (!(target.startsWith("/") && !target.startsWith("//"))) { return; }\nresponse.sendRedirect(target);', True),
        )
        for body, unsafe in cases:
            with self.subTest(body=body):
                code = 'class C { void handler(Request request) {\n' + prefix + body + (' // unsafe' if unsafe else '') + '\n} }'
                self.check(code)

    def test_real_guard_in_a_renamed_helper_is_a_summary(self):
        guard = r'x.startsWith("/") && !x.startsWith("//") && !x.contains("\\") && !x.contains("\r") && !x.contains("\n") && !x.contains("\t")'
        for name in ('choose', 'safeRedirect', 'identity'):
            with self.subTest(name=name):
                self.check('class C { String ' + name + '(String x) { if (!(' + guard + ')) { throw new SecurityException(); } return x; }\n'
                           'void handler(Request request) { response.sendRedirect(' + name + '(request.getParameter("next"))); } }')

    def test_uri_original_weak_relative_guards_remain_positive(self):
        for filename in ('test-suite/java/security/OpenRedirectClean.java',
                         'test-suite/kotlin/open_redirect_clean/OpenRedirectClean.kt'):
            text = (REPO_ROOT / filename).read_text()
            lang = 'java' if filename.endswith('.java') else 'kotlin'
            self.assertEqual(self.scan(text, lang), [])
            weak = text.replace('        if (parsed.getRawAuthority() != null || parsed.toString().startsWith("//")) {\n            throw new IllegalArgumentException("blocked redirect authority");\n        }\n', '')
            weak = weak.replace('uri.rawAuthority == null && !uri.toString().startsWith("//") && ', '')
            findings = self.scan(weak, lang)
            self.assertEqual({finding['line'] for finding in findings}, {34, 38, 43, 48, 53} if lang == 'java' else {29, 34})
            # Authority checks alone still accept ///attacker.example/login:
            # java.net.URI removes two slashes from getPath(), while the
            # serialized redirect retains a browser-interpreted authority.
            authority_only = text.replace(' || parsed.toString().startsWith("//")', '').replace('!uri.toString().startsWith("//") && ', '')
            self.assertEqual(len(self.scan(authority_only, lang)), 5 if lang == 'java' else 2)

    def test_original_redirect_buggy_bytes_and_sink_locations_are_preserved(self):
        cases = (
            ('java', 'test-suite/java/security/OpenRedirectBuggy.java',
             'c672817f6f59f0dbb5ebd1cf2e998146d05b61814f8f09258688d778ee32d54f', {15, 19, 24, 29, 34}),
            ('kotlin', 'test-suite/kotlin/open_redirect_buggy/OpenRedirectBuggy.kt',
             '5ee622d88a02e4b18ecdf1460a4c6e08fa534e3afe9c2785348b9cdd64589549', {15, 20}),
        )
        for lang, filename, digest, expected in cases:
            path = REPO_ROOT / filename
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            findings = self.scan(path.read_text(), lang)
            self.assertEqual({finding['line'] for finding in findings}, expected)
            self.assertEqual(len(findings), len(expected))

    def test_uri_parser_oracle_rejects_the_original_clean_contract(self):
        if shutil.which('java') is None:
            self.skipTest('Java runtime unavailable for the independent URI oracle')
        source = self.root / 'URIOracle.java'
        source.write_text('''import java.net.URI;
class URIOracle { public static void main(String[] args) {
  URI uri = URI.create("//attacker.example/login");
  if (uri.isAbsolute() || !uri.getPath().startsWith("/") || uri.getPath().startsWith("//")) throw new AssertionError();
  if (!"attacker.example".equals(uri.getRawAuthority())) throw new AssertionError();
  if (!"https://attacker.example/login".equals(URI.create("https://app.example/").resolve(uri).toString())) throw new AssertionError();
  URI triple = URI.create("///attacker.example/login");
  if (triple.isAbsolute() || triple.getRawAuthority() != null || !triple.getPath().startsWith("/") || triple.getPath().startsWith("//")) throw new AssertionError();
  if (!"///attacker.example/login".equals(triple.toString())) throw new AssertionError();
  System.out.println("original guard accepts a cross-origin URI");
} }''')
        proc = subprocess.run(['java', str(source)], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        if shutil.which('node'):
            browser_url = subprocess.run(['node', '-e', 'if (new URL("///attacker.example/login", "https://app.example/").origin !== "https://attacker.example") process.exit(1)'],
                                         capture_output=True, text=True, timeout=30)
            self.assertEqual(browser_url.returncode, 0, browser_url.stdout + browser_url.stderr)

    def test_uri_wrong_value_or_changed_value_does_not_inherit_proof(self):
        fixture = (REPO_ROOT / 'test-suite/java/security/OpenRedirectClean.java').read_text()
        for before, after in (
            ('return parsed.toString();', 'return raw;'),
            ('return parsed.toString();', 'return parsed.getPath();'),
            ('return parsed.toString();', 'return parsed.toString().replace("https", "http");'),
            ('return parsed.toString();', 'parsed = URI.create(raw + "/other"); return parsed.toString();'),
            ('ALLOWED_HOSTS.contains(parsed.getHost())', 'ALLOWED_HOSTS.contains("app.example.com")'),
            ('private static final Set<String> ALLOWED_HOSTS', 'private static Set<String> ALLOWED_HOSTS'),
            ('String path = parsed.getPath();', 'String path = external.getPath(parsed);'),
        ):
            with self.subTest(after=after):
                findings = self.scan(fixture.replace(before, after))
                self.assertTrue(findings, after)

    def test_uri_helper_calls_do_not_share_guarded_object_identity(self):
        self.check('''class C {
  URI parse(String raw) { return URI.create(raw); }
  void handler(Request request) {
    URI first=parse(request.getParameter("first"));
    URI second=parse(request.getParameter("second"));
    if (first.isAbsolute() || first.getRawAuthority() != null || first.toString().startsWith("//")) { return; }
    String path=first.getPath();
    if (!path.startsWith("/") || path.startsWith("//")) { return; }
    response.sendRedirect(first.toString());
    response.sendRedirect(second.toString()); // unsafe
  }
}''')

    def test_host_allowlist_declarations_require_executable_tokens_and_owner(self):
        body = '''void handler(Request request) {
  URI uri=URI.create(request.getParameter("next"));
  if ("https".equals(uri.getScheme()) && HOSTS.contains(uri.getHost())) {
    response.sendRedirect(uri.toString()); // unsafe
  }
}'''
        declaration = 'private static final Set<String> HOSTS = Set.of("api.example");'
        for fake in ('// ' + declaration + '\n', '/* ' + declaration + ' */\n',
                     'String text="""\n' + declaration + '\n""";\n'):
            with self.subTest(fake=fake):
                self.check('class C {\n' + fake + body + '\n}')
        self.check('class Trusted { ' + declaration + ' }\nclass Other extends Untrusted {\n' + body + '\n}')
        self.check('class Trusted { ' + declaration + '\n' + body.replace(' // unsafe', '') + '\n}')

    def test_kotlin_string_extensions_cannot_claim_uri_object_guards(self):
        self.check('''import java.net.URI
fun String.isAbsolute(): Boolean = false
val String.rawAuthority: String? get() = null
fun handler(request: Request, response: Response) {
  val uri=URI.create(request.getParameter("next"))
  if (!uri.path.startsWith("/") || uri.path.startsWith("//")) { return }
  val target=uri.toString()
  if (target.isAbsolute() || target.rawAuthority != null || target.startsWith("//")) { return }
  response.sendRedirect(target) // unsafe: https://attacker.example/login passes these checks
}
''', 'kotlin')

    def test_imported_require_cannot_validate_redirects(self):
        guard = r'target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t")'
        body = ('fun handler(request: Request, response: Response) {\n'
                '  val target=request.getParameter("next")\n'
                '  require(' + guard + ')\n'
                '  response.sendRedirect(target) // unsafe\n}\n')
        for imported in ('app.validation.require', 'app.validation.check as require', 'app.validation.*'):
            with self.subTest(imported=imported):
                self.check('import ' + imported + '\n' + body, 'kotlin')
        self.check('import kotlin.require\n' + body.replace(' // unsafe', ''), 'kotlin')

    def test_kotlin_check_with_a_constant_lazy_message_guards_like_require(self):
        guard = r'target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t")'
        body = ('fun handler(request: Request, response: Response) {\n'
                '  val target=request.getParameter("next")\n'
                '  check(' + guard + ') { "unsafe redirect target" }\n'
                '  response.sendRedirect(target)\n}\n')
        self.check(body, 'kotlin')
        self.check('import kotlin.check\n' + body, 'kotlin')
        unsafe = body.replace('  response.sendRedirect(target)\n', '  response.sendRedirect(target) // unsafe\n')
        for imported in ('app.validation.check', 'app.validation.require as check', 'app.validation.*'):
            with self.subTest(imported=imported):
                self.check('import ' + imported + '\n' + unsafe, 'kotlin')
        with self.subTest(case='local-check-function'):
            self.check(unsafe + 'fun check(value: Boolean, message: () -> String) {}\n', 'kotlin')

    def test_kotlin_interpolation_invalidates_the_selected_redirect_guard(self):
        self.check(r'''fun handler(request: Request, response: Response) {
  val target = request.getParameter("next")
  if (!(target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t"))) { return }
  response.sendRedirect(target)
  response.sendRedirect("/$target") // unsafe
}''', 'kotlin')

    def test_generic_and_array_parameters_do_not_inherit_argument_types(self):
        guard = r'target.startsWith("/") && !target.startsWith("//") && !target.contains("\\") && !target.contains("\r") && !target.contains("\n") && !target.contains("\t")'
        for parameter in ('Box<String> target',):
            with self.subTest(parameter=parameter):
                self.check('class C { void handler(@RequestBody ' + parameter + ') {\n'
                           'if (!(' + guard + ')) { return; }\nresponse.sendRedirect(target.toString()); // unsafe\n} }')
        self.check('class C { void handler(@RequestBody String target) {\n'
                   'if (!(' + guard + ')) { return; }\nresponse.sendRedirect(target);\n} }')
        for parameter in ('target: Box<String>', 'target: Array<String>'):
            with self.subTest(parameter=parameter):
                self.check('fun handler(' + parameter + ') {\n'
                           'if (!(' + guard + ')) { return }\nresponse.sendRedirect(target.toString()) // unsafe\n}\n'
                           'fun entry(request: Request) { handler(external.wrap(request.getParameter("next"))) }', 'kotlin')
        for type_name in ('Box<Path>', 'Box<File>'):
            with self.subTest(type=type_name):
                self.check('class C { void handler(@RequestBody ' + type_name + ' target, Path root) {\n'
                           'if (!target.normalize().startsWith(root)) { return; }\n'
                           'Files.readString(Path.of(target.toString())); // unsafe\n} }', domain='path_traversal')
        from ubs_core.analyzers.taint_java_traversal import Engine
        for suffix, declarations in (('.java', ('String[] target', 'String target[]', 'String... target', 'Path[] path', 'Box<File> file')),
                                     ('.kt', ('target: Array<String>', 'target: List<Path>', 'target: Box<File>'))):
            engine = Engine(self.root / ('Types' + suffix), '')
            for declaration in declarations:
                with self.subTest(declaration=declaration):
                    self.assertEqual(engine.parameter_tags(declaration), frozenset())

    def test_path_text_prefix_is_not_component_containment(self):
        for conversion in ('candidate.toString()', 'candidate.normalize().toString()'):
            with self.subTest(conversion=conversion):
                self.check('''class C {
  String choose(Path root, String raw) {
    Path candidate=root.resolve(raw).normalize(); // unsafe
    String rendered=CONVERSION;
    String rootText=root.toString();
    if (!rendered.startsWith(rootText)) { throw new SecurityException(); }
    return rendered;
  }
  void handler(Request request, Path root) {
    Files.readString(Path.of(choose(root, request.getParameter("file")))); // unsafe
  }
}'''.replace('CONVERSION', conversion), domain='path_traversal')
        for conversion in ('candidate.getCanonicalPath()', 'candidate.getCanonicalFile().getCanonicalPath()'):
            with self.subTest(conversion=conversion):
                self.check('''class C {
  String choose(File root, String raw) {
    File candidate=new File(raw); // unsafe
    String rendered=CONVERSION;
    String rootText=root.getCanonicalPath();
    if (!rendered.startsWith(rootText)) { throw new SecurityException(); }
    return rendered;
  }
  void handler(Request request, File root) {
    new FileInputStream(choose(root, request.getParameter("file"))); // unsafe
  }
}'''.replace('CONVERSION', conversion), domain='path_traversal')
        self.check('''class C {
  String choose(Path root, String raw) {
    Path candidate=root.resolve(raw).normalize();
    if (!candidate.startsWith(root)) { throw new SecurityException(); }
    return candidate.toString();
  }
  void handler(Request request, Path root) {
    Files.readString(Path.of(choose(root, request.getParameter("file"))));
  }
}''', domain='path_traversal')
        if shutil.which('java'):
            oracle = self.root / 'PathPrefixOracle.java'
            oracle.write_text('''import java.nio.file.Path;
class PathPrefixOracle { public static void main(String[] args) {
  Path root=Path.of("/srv/root");
  Path target=Path.of("/srv/root-evil/secret").normalize();
  if (!target.toString().startsWith(root.toString()) || target.startsWith(root)) throw new AssertionError();
} }''')
            proc = subprocess.run(['java', str(oracle)], capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_uri_helper_calls_with_a_shared_source_keep_distinct_objects(self):
        self.check('''class C {
  URI parse(String raw) { return URI.create(raw); }
  void handler(Request request) {
    String raw=request.getParameter("next");
    URI first=parse(raw);
    URI second=parse(raw.replace("/safe", "//attacker.example"));
    if (first.isAbsolute() || first.getRawAuthority() != null || first.toString().startsWith("//")) { return; }
    String path=first.getPath();
    if (!path.startsWith("/") || path.startsWith("//")) { return; }
    response.sendRedirect(second.toString()); // unsafe
  }
}''')

    def test_path_names_getters_and_receiver_identity(self):
        self.check('''class C {
  String safePath(String p) { return p; }
  String getFileName(String p) { return p; }
  void handler(Request request) {
    String p = request.getParameter("file");
    new FileInputStream(safePath(p)); // unsafe
    new FileInputStream(getFileName(p)); // unsafe
    new FileInputStream(external.getFileName(p)); // unsafe
    new FileInputStream(Paths.get(p).getFileName().toString());
  }
}''', domain='path_traversal')

    def test_redirect_does_not_use_path_containment_or_basename_as_url_validation(self):
        self.check('''class C { void handler(Request request) {
  String p=request.getParameter("next");
  response.sendRedirect(Paths.get(p).getFileName().toString()); // unsafe
  if (!p.normalize().startsWith(root)) { return; }
  response.sendRedirect(p); // unsafe
} }''')

    def test_path_root_is_a_dependency_and_guarded_transforms_are_not_permanent(self):
        self.check('''class C {
  Path choose(Path root, String p) {
    Path target=root.resolve(p).normalize(); // unsafe
    if (!target.startsWith(root)) { throw new SecurityException(); }
    return target;
  }
  void handler(Request request) {
    Path untrusted=Path.of(request.getParameter("root")); // unsafe
    Files.readString(choose(untrusted, request.getParameter("file"))); // unsafe
  }
}''', domain='path_traversal')
        self.check('''class C {
  Path choose(Path root, String p) {
    Path target=root.resolve(p).normalize(); // unsafe
    if (!target.startsWith(root)) { throw new SecurityException(); }
    return target.resolve(p); // unsafe
  }
  void handler(Request request) {
    Path root=Path.of("/srv/uploads");
    Files.readString(choose(root, request.getParameter("file"))); // unsafe
    String raw=request.getParameter("raw");
    if (!raw.normalize().startsWith(root)) { return; }
    new FileInputStream(raw); // unsafe
  }
}''', domain='path_traversal')
        self.check('''class C { void handler(Request request) {
  Path root=Path.of("/srv/uploads");
  Path target=root.resolve(request.getParameter("file")).normalize(); // unsafe
  if (!target.startsWith(root)) { return; }
  Files.readString(target);
} }''', domain='path_traversal')
        self.check('''class C {
  Path choose(Path root, String p) {
    Path leaked=root.resolve(p); // unsafe
    Path target=root.resolve(p).normalize();
    if (!target.startsWith(root)) { throw new SecurityException(); }
    return target;
  }
  void handler(Request request, Path root) {
    Files.readString(choose(root, request.getParameter("file")));
  }
}''', domain='path_traversal')

    def test_rule_scoped_suppression_and_lexical_decoys(self):
        for lang in ('java', 'kotlin'):
            code = '''String target=request.getParameter("next");
response.sendRedirect(target); // ubs:ignore[LANG.taint.open_redirect]
response.sendRedirect(target); // ubs:ignore[LANG.taint.path_traversal] // unsafe
String inert="response.sendRedirect(request.getParameter(x))";
'''.replace('LANG', lang)
            if lang == 'kotlin':
                code = code.replace('String ', 'val ')
            self.check(code, lang)

    def test_incomplete_and_disabled_paths_are_explicit(self):
        from ubs_core.analyzers.taint_java_redirect import RedirectEngine, run
        from ubs_core.registry import RunContext
        from ubs_core.taint_flow import AnalysisLimit
        self.assertEqual(list(run(RunContext(lang='java', files=[Path('/absent.java')],
                                            profile={'disabled_rules': ['java.taint.open_redirect']}))), [])
        for code in ('response.sendRedirect(request.getParameter("next");',
                     'class C { String x=request.getParameter("next"); void h(){response.sendRedirect(x);} }'):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, 'incomplete'):
                self.scan(code)
        engine = RedirectEngine(self.root / 'Budget.java', 'response.sendRedirect(request.getParameter("next"));')
        engine.budget.remaining = 0
        with self.assertRaises(AnalysisLimit):
            engine.analyze()

    def test_binding_oracles_through_public_json_and_sarif(self):
        for lang, suffix in (('java', '.java'), ('kotlin', '.kt')):
            for label, code, rule, expected in self.cases(lang):
                path = self.root / (lang + '-' + label + suffix)
                path.write_text(code, encoding='utf-8')
                json_extras = []
                for fmt in ('json', 'sarif'):
                    with self.subTest(lang=lang, case=label, format=fmt):
                        case = lang + '-' + label + '-' + fmt
                        started = time.monotonic()
                        print(f'[{case}] RUN', flush=True)
                        command = [str(REPO_ROOT / 'modules' / ('ubs-' + lang + '.sh')),
                                   '--ci', '--only=4', '--no-color', '--format=' + fmt, str(path)]
                        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                                   PYTHONDONTWRITEBYTECODE='1', ENABLE_UV_TOOLS='0')
                        proc = subprocess.run(command, cwd=self.root, env=env,
                                              capture_output=True, text=True, timeout=120)
                        (self.root / (case + '.stdout.log')).write_text(proc.stdout)
                        (self.root / (case + '.stderr.log')).write_text(proc.stderr)
                        (self.root / (case + '.identity.json')).write_text(json.dumps({
                            'command': command, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'python': sys.version, 'exit': proc.returncode, 'elapsed': time.monotonic() - started,
                        }, indent=2))
                        context = f'{command!r}\nexit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                        self.assertEqual(proc.returncode, int(bool(expected)), context)
                        report = json.loads(proc.stdout)
                        if fmt == 'json':
                            self.assertEqual(report['status'], 'ok', context)
                            self.assertEqual(report['critical'], len(expected), context)
                            found = [f for f in report['findings'] if f['rule'] == lang + '.taint.' + rule]
                            actual = {f['line'] for f in found}
                            json_extras = [f['extras'] for f in found]
                            for finding in found:
                                steps = finding['extras']['taint_path']
                                self.assertEqual((steps[0]['kind'], steps[-1]['kind']), ('source', 'sink'), context)
                                self.assertEqual(steps[-1]['line'], finding['line'], context)
                                self.assertTrue(all(Path(step['path']) == path.resolve() and step['col'] > 0 for step in steps), context)
                                if label in {'safeRedirect', 'identity', 'misleading-path-helper'}:
                                    self.assertTrue({'call', 'return'} <= {step['kind'] for step in steps}, context)
                        else:
                            found = [f for run in report['runs'] for f in run['results']
                                     if f['ruleId'] == lang + '.taint.' + rule]
                            actual = {f['locations'][0]['physicalLocation']['region']['startLine'] for f in found}
                            self.assertEqual([f['properties']['extras'] for f in found], json_extras, context)
                            for finding, extras in zip(found, json_extras):
                                locations = finding['codeFlows'][0]['threadFlows'][0]['locations']
                                self.assertEqual(len(locations), len(extras['taint_path']), context)
                                for location, step in zip(locations, extras['taint_path']):
                                    physical = location['location']['physicalLocation']
                                    self.assertEqual(location['kinds'], [step['kind']], context)
                                    self.assertEqual(physical['artifactLocation']['uri'], sarif_uri(step['path']), context)
                                    self.assertEqual(physical['region'], {'startLine': step['line'], 'startColumn': step['col']}, context)
                        self.assertEqual(len(found), len(expected), context)
                        self.assertEqual(actual, expected, context)
                        print(f'[{case}] PASS ({time.monotonic() - started:.3f}s)', flush=True)


class CppSelectedRequestFlowTests(unittest.TestCase):
    """Independent C++ binding oracles frozen before the October rewrite.

    The initial 30 source programs compiled under C++20; 18 failed the old
    analyzers while 12 independent safe/unsafe controls passed. A second
    independent tranche covers references, namespaces and expression flow.
    Public module JSON/SARIF companions run with UBS_CPP_TAINT_E2E=1.
    """

    def setUp(self):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='cpp-selected-flow-', dir=artifacts))

    @staticmethod
    def cases():
        prelude = '''\
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
struct Request { std::string get_param_value(const char *) const; };
struct Response {
  void set_header(const std::string &, const std::string &);
  void set_redirect(const std::string &);
};
'''
        cases = (
            ('redirect', 'direct_header_control', '''
                void handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  res.set_header("Location", url); // SINK
                }
            '''),
            ('redirect', 'literal_header_control', '''
                void handle(const Request &req, Response &res) {
                  std::string ignored = req.get_param_value("next");
                  res.set_header("Location", "/home");
                }
            '''),
            ('redirect', 'actual_httplib_set_redirect', '''
                void handle(const Request &req, Response &res) {
                  res.set_redirect(req.get_param_value("next")); // SINK
                }
            '''),
            ('redirect', 'literal_set_redirect_control', '''
                void handle(const Request &req, Response &res) {
                  std::string ignored = req.get_param_value("next");
                  res.set_redirect("/home");
                }
            '''),
            ('redirect', 'safe_named_identity', '''
                std::string safe_redirect_target(std::string value) { return value; }
                void handle(const Request &req, Response &res) {
                  std::string url = safe_redirect_target(req.get_param_value("next"));
                  res.set_header("Location", url); // SINK
                }
            '''),
            ('redirect', 'alpha_renamed_identity_control', '''
                std::string identity(std::string value) { return value; }
                void handle(const Request &req, Response &res) {
                  std::string url = identity(req.get_param_value("next"));
                  res.set_header("Location", url); // SINK
                }
            '''),
            ('redirect', 'selected_constant_helper', '''
                std::string destination(std::string value) { return "/home"; }
                void handle(const Request &req, Response &res) {
                  std::string url = destination(req.get_param_value("next"));
                  res.set_header("Location", url);
                }
            '''),
            ('redirect', 'inverted_rejection_guard', '''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  if (url.starts_with("/") && !url.starts_with("//")) return false;
                  res.set_header("Location", url); // SINK
                  return true;
                }
            '''),
            ('redirect', 'unrelated_guard', '''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  std::string other = "/home";
                  if (!(other.starts_with("/") && !other.starts_with("//"))) return false;
                  res.set_header("Location", url); // SINK
                  return true;
                }
            '''),
            ('redirect', 'conditional_literal_overwrite', '''
                void handle(const Request &req, Response &res, bool flag) {
                  std::string url = req.get_param_value("next");
                  if (flag) {
                    url = "/home";
                  }
                  res.set_header("Location", url); // SINK
                }
            '''),
            ('redirect', 'unconditional_literal_overwrite_control', '''
                void handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  url = "/home";
                  res.set_header("Location", url);
                }
            '''),
            ('redirect', 'complete_local_guard_control', r'''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  if (!(url.starts_with("/") && !url.starts_with("//") &&
                        url.find_first_of("\\\r\n\t") == std::string::npos)) return false;
                  res.set_header("Location", url);
                  return true;
                }
            '''),
            ('redirect', 'weak_local_guard_allows_backslash', '''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  if (!(url.starts_with("/") && !url.starts_with("//"))) return false;
                  res.set_header("Location", url); // SINK
                  return true;
                }
            '''),
            ('redirect', 'guard_rebinding_retains_unsafe', r'''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  if (!(url.starts_with("/") && !url.starts_with("//") &&
                        url.find_first_of("\\\r\n\t") == std::string::npos)) return false;
                  url = req.get_param_value("next");
                  res.set_header("Location", url); // SINK
                  return true;
                }
            '''),
            ('redirect', 'selected_literal_allowlist_control', '''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  if (url != "/home" && url != "/account") return false;
                  res.set_header("Location", url);
                  return true;
                }
            '''),
            ('redirect', 'allowlist_for_different_value', '''
                bool handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  std::string other = req.get_param_value("other");
                  if (other != "/home" && other != "/account") return false;
                  res.set_header("Location", url); // SINK
                  return true;
                }
            '''),
            ('redirect', 'selected_validating_helper_control', r'''
                std::string destination(std::string value) {
                  if (value.starts_with("/") && !value.starts_with("//") &&
                      value.find_first_of("\\\r\n\t") == std::string::npos) return value;
                  return "/home";
                }
                void handle(const Request &req, Response &res) {
                  std::string url = destination(req.get_param_value("next"));
                  res.set_header("Location", url);
                }
            '''),
            ('redirect', 'source_key_is_not_destination_name', '''
                void handle(const Request &req, Response &res) {
                  auto value = req.get_param_value("q");
                  res.set_header("Location", value); // SINK
                }
            '''),
            ('redirect', 'direct_unknown_key', '''
                void handle(const Request &req, Response &res) {
                  res.set_header("Location", req.get_param_value("q")); // SINK
                }
            '''),
            ('redirect', 'literal_string_is_not_sanitizer', '''
                void handle(const Request &req, Response &res) {
                  auto url = req.get_param_value("next") + "safe_redirect_target";
                  res.set_header("Location", url); // SINK
                }
            '''),
            ('path', 'direct_path_control', '''
                void handle(const Request &req) {
                  std::string file = req.get_param_value("file");
                  std::ifstream input(file); // SINK
                }
            '''),
            ('path', 'literal_path_control', '''
                void handle(const Request &req) {
                  std::string ignored = req.get_param_value("file");
                  std::ifstream input("/srv/data/help.txt");
                }
            '''),
            ('path', 'safe_path_identity', '''
                std::string safe_path(std::string value) { return value; }
                void handle(const Request &req) {
                  std::string file = safe_path(req.get_param_value("file"));
                  std::ifstream input(file); // SINK
                }
            '''),
            ('path', 'path_literal_overwrite', '''
                void handle(const Request &req) {
                  std::string file = req.get_param_value("file");
                  file = "/srv/data/help.txt";
                  std::ifstream input(file);
                }
            '''),
            ('path', 'same_spelling_unrelated_scope', '''
                void remember(const Request &req) {
                  std::string file = req.get_param_value("file");
                }
                void fixed() {
                  std::string file = "/srv/data/help.txt";
                  std::ifstream input(file);
                }
            '''),
            ('path', 'unrelated_filename_is_not_proof', '''
                void handle(const Request &req) {
                  std::string file = req.get_param_value("file");
                  auto harmless = std::filesystem::path("help.txt").filename();
                  std::ifstream input(file); // SINK
                }
            '''),
            ('path', 'basename_reused_as_directory_prefix', '''
                void handle(const Request &req) {
                  auto leaf = std::filesystem::path(req.get_param_value("file")).filename();
                  auto file = std::filesystem::path("/srv/data") / leaf / "secret.txt";
                  std::ifstream input(file); // SINK
                }
            '''),
            ('path', 'terminal_basename_regular_file_control', '''
                void handle(const Request &req) {
                  auto leaf = std::filesystem::path(req.get_param_value("file")).filename();
                  auto file = std::filesystem::path("/srv/data") / leaf;
                  std::ifstream input(file);
                }
            '''),
            ('path', 'selected_canonical_root_control', '''
                void handle(const Request &req) {
                  auto root = std::filesystem::canonical("/srv/data");
                  auto file = std::filesystem::canonical(root / req.get_param_value("file"));
                  auto relative = file.lexically_relative(root);
                  if (relative.empty() || relative.is_absolute() || *relative.begin() == "..")
                    throw std::runtime_error("outside root");
                  std::ifstream input(file);
                }
            '''),
            ('path', 'canonical_guard_for_unrelated_file', '''
                void handle(const Request &req) {
                  auto root = std::filesystem::canonical("/srv/data");
                  auto checked = std::filesystem::canonical(root / "help.txt");
                  auto relative = checked.lexically_relative(root);
                  if (relative.empty() || relative.is_absolute() || *relative.begin() == "..")
                    throw std::runtime_error("outside root");
                  auto file = req.get_param_value("file");
                  std::ifstream input(file); // SINK
                }
            '''),
        )
        for domain, name, body in cases:
            source = prelude + textwrap.dedent(body).strip('\n') + '\n'
            expected = {i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line}
            rule = 'cpp.taint.' + ('open_redirect' if domain == 'redirect' else 'path_traversal')
            yield name, source, rule, expected
        yield from CppSelectedRequestFlowTests.heldout_cases()
        yield from CppSelectedRequestFlowTests.conditional_assignment_cases()

    @staticmethod
    def heldout_cases():
        prelude = '''\
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
struct Request { std::string get_param_value(const char *) const; };
struct Response {
  void set_header(const std::string &, const std::string &);
  void set_redirect(const std::string &, int = 302);
};
'''
        cases = (
            ('redirect', 'mutable_reference_helper_introduces_source', '''
                void fill(std::string &value, const Request &req) {
                  value = req.get_param_value("next");
                }
                void handle(const Request &req, Response &res) {
                  std::string url = "/home";
                  fill(url, req);
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'by_value_helper_does_not_mutate_caller', '''
                void fill(std::string value, const Request &req) {
                  value = req.get_param_value("next");
                }
                void handle(const Request &req, Response &res) {
                  std::string url = "/home";
                  fill(url, req);
                  res.set_redirect(url);
                }
            '''),
            ('redirect', 'mutable_reference_helper_clears_source', '''
                void replace(std::string &value) { value = "/home"; }
                void handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  replace(url);
                  res.set_redirect(url);
                }
            '''),
            ('redirect', 'reference_alias_reassignment_updates_original', '''
                void handle(const Request &req, Response &res) {
                  std::string url = "/home";
                  std::string &alias = url;
                  alias = req.get_param_value("next");
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'copy_reassignment_does_not_update_original', '''
                void handle(const Request &req, Response &res) {
                  std::string url = "/home";
                  std::string copy = url;
                  copy = req.get_param_value("next");
                  res.set_redirect(url);
                }
            '''),
            ('redirect', 'qualified_unsafe_helper_selected', '''
                namespace Unsafe { std::string safe_redirect_target(std::string x) { return x; } }
                namespace Safe { std::string safe_redirect_target(std::string x) { return "/home"; } }
                void handle(const Request &req, Response &res) {
                  auto url = Unsafe::safe_redirect_target(req.get_param_value("next"));
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'qualified_constant_helper_selected', '''
                namespace Unsafe { std::string safe_redirect_target(std::string x) { return x; } }
                namespace Safe { std::string safe_redirect_target(std::string x) { return "/home"; } }
                void handle(const Request &req, Response &res) {
                  auto url = Safe::safe_redirect_target(req.get_param_value("next"));
                  res.set_redirect(url);
                }
            '''),
            ('redirect', 'block_shadow_does_not_taint_outer', '''
                void handle(const Request &req, Response &res) {
                  std::string url = "/home";
                  {
                    std::string url = req.get_param_value("next");
                  }
                  res.set_redirect(url);
                }
            '''),
            ('redirect', 'block_shadow_does_not_clear_outer', '''
                void handle(const Request &req, Response &res) {
                  std::string url = req.get_param_value("next");
                  {
                    std::string url = "/home";
                  }
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'short_circuit_assignment_preserves_false_path', '''
                void handle(const Request &req, Response &res, bool flag) {
                  std::string url = req.get_param_value("next");
                  flag && ((url = "/home") == "/home");
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'ternary_assignment_preserves_false_path', '''
                void handle(const Request &req, Response &res, bool flag) {
                  std::string url = req.get_param_value("next");
                  flag ? (url = "/home") : (url = url);
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'status_argument_is_not_redirect_target', '''
                void handle(const Request &req, Response &res) {
                  int status = std::stoi(req.get_param_value("next"));
                  res.set_redirect("/home", status);
                }
            '''),
            ('redirect', 'unknown_sanitizer_declaration_is_not_proof', '''
                std::string validate_redirect_target(const std::string &);
                void handle(const Request &req, Response &res) {
                  auto url = validate_redirect_target(req.get_param_value("next"));
                  res.set_redirect(url); // SINK
                }
            '''),
            ('redirect', 'raw_string_decoy_is_not_request_flow', '''
                void handle(const Request &req, Response &res) {
                  std::string text = R"example(req.get_param_value("next"); res.set_redirect(text);)example";
                  res.set_redirect("/home");
                }
            '''),
            ('redirect', 'identity_macro_retains_request_value', '''
                #define AS_DESTINATION(value) (value)
                void handle(const Request &req, Response &res) {
                  auto url = AS_DESTINATION(req.get_param_value("next"));
                  res.set_redirect(url); // SINK
                }
            '''),
            ('path', 'fopen_mode_argument_is_not_path', '''
                void handle(const Request &req) {
                  auto mode = req.get_param_value("file");
                  FILE *input = fopen("/srv/data/help.txt", mode.c_str());
                  if (input) fclose(input);
                }
            '''),
            ('path', 'rename_destination_is_a_path', '''
                void handle(const Request &req) {
                  auto destination = req.get_param_value("file");
                  std::filesystem::rename("/srv/data/upload.tmp", destination); // SINK
                }
            '''),
            ('path', 'canonical_containment_cannot_trust_request_root', '''
                void handle(const Request &req) {
                  auto root = std::filesystem::canonical(req.get_param_value("root"));
                  auto file = std::filesystem::canonical(root / "secret.txt");
                  auto relative = file.lexically_relative(root);
                  if (relative.empty() || relative.is_absolute() || *relative.begin() == "..")
                    throw std::runtime_error("outside root");
                  std::ifstream input(file); // SINK
                }
            '''),
            ('path', 'canonical_containment_invalidated_by_rebinding', '''
                void handle(const Request &req) {
                  auto root = std::filesystem::canonical("/srv/data");
                  auto file = std::filesystem::canonical(root / req.get_param_value("file"));
                  auto relative = file.lexically_relative(root);
                  if (relative.empty() || relative.is_absolute() || *relative.begin() == "..")
                    throw std::runtime_error("outside root");
                  file = req.get_param_value("other");
                  std::ifstream input(file); // SINK
                }
            '''),
        )
        for domain, name, body in cases:
            source = prelude + textwrap.dedent(body).strip('\n') + '\n'
            expected = {i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line}
            rule = 'cpp.taint.' + ('open_redirect' if domain == 'redirect' else 'path_traversal')
            yield name, source, rule, expected

    @staticmethod
    def conditional_assignment_cases():
        prelude = '''\
#include <string>
struct Request { std::string get_param_value(const char *) const; };
struct Response { void set_redirect(const std::string &); };
'''
        cases = (
            ('short_circuit_assignment_introduces_source', '''
                void handle(const Request &req, Response &res, bool flag) {
                  std::string url = "/home";
                  flag && ((url = req.get_param_value("next")) == "/home");
                  res.set_redirect(url); // SINK
                }
            '''),
            ('ternary_assignment_introduces_source', '''
                void handle(const Request &req, Response &res, bool flag) {
                  std::string url = "/home";
                  flag ? (url = req.get_param_value("next")) : (url = url);
                  res.set_redirect(url); // SINK
                }
            '''),
        )
        for name, body in cases:
            source = prelude + textwrap.dedent(body).strip('\n') + '\n'
            expected = {i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line}
            yield name, source, 'cpp.taint.open_redirect', expected

        c_prelude = '#include <stdio.h>\n#include <stdlib.h>\nvoid set_header(const char *, const char *);\n'
        c_cases = (
            ('path_traversal', 'direct_file_operand', '''
                void handle(void) {
                  const char *path = getenv("QUERY_STRING");
                  FILE *file = fopen(path, "r"); // SINK
                }
            '''),
            ('path_traversal', 'literal_file_overwrite', '''
                void handle(void) {
                  const char *path = getenv("QUERY_STRING");
                  path = "/srv/public/index.html";
                  FILE *file = fopen(path, "r");
                }
            '''),
            ('open_redirect', 'selected_identity_helper', '''
                const char *safe_redirect(const char *value) { return value; }
                void handle(void) {
                  const char *target = safe_redirect(getenv("QUERY_STRING"));
                  set_header("Location", target); // SINK
                }
            '''),
            ('open_redirect', 'selected_constant_helper', '''
                const char *destination(const char *value) { return "/home"; }
                void handle(void) {
                  const char *target = destination(getenv("QUERY_STRING"));
                  set_header("Location", target);
                }
            '''),
            ('open_redirect', 'conditional_overwrite', '''
                void handle(int fallback) {
                  const char *target = getenv("QUERY_STRING");
                  if (fallback) { target = "/home"; }
                  set_header("Location", target); // SINK
                }
            '''),
        )
        for kind, name, body in c_cases:
            source = c_prelude + textwrap.dedent(body).strip('\n') + '\n'
            expected = {i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line}
            yield 'c_language_' + name, source, 'cpp.taint.' + kind, expected

        environment_prelude = ('#include <cstdlib>\n#include <fstream>\n#include <string>\n'
                               'struct Response { void set_redirect(const std::string &); };\n')
        environment_cases = (
            ('path_traversal', 'std_cgi_query', '''
                void handle() {
                  std::string path = std::getenv("QUERY_STRING");
                  std::ifstream input(path); // SINK
                }
            '''),
            ('path_traversal', 'std_cgi_path_info', '''
                void handle() {
                  std::string path = std::getenv("PATH_INFO");
                  std::ifstream input(path); // SINK
                }
            '''),
            ('open_redirect', 'std_http_referer', '''
                void handle(Response &res) {
                  std::string target = std::getenv("HTTP_REFERER");
                  res.set_redirect(target); // SINK
                }
            '''),
            ('path_traversal', 'ordinary_process_path', '''
                void handle() {
                  std::string path = std::getenv("PATH");
                  std::ifstream input(path);
                }
            '''),
            ('open_redirect', 'ordinary_process_language', '''
                void handle(Response &res) {
                  std::string target = std::getenv("LANG");
                  res.set_redirect(target);
                }
            '''),
            ('path_traversal', 'selected_namespaced_helper', '''
                namespace application {
                  std::string getenv(const char *) { return "/srv/public/index.html"; }
                }
                void handle() {
                  std::string path = application::getenv("QUERY_STRING");
                  std::ifstream input(path);
                }
            '''),
        )
        for kind, name, body in environment_cases:
            source = environment_prelude + textwrap.dedent(body).strip('\n') + '\n'
            expected = {i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line}
            yield 'environment_' + name, source, 'cpp.taint.' + kind, expected

    def test_independent_cpp_selected_bindings_and_real_operands(self):
        from ubs_core.analyzers import taint_cpp_redirect, taint_cpp_traversal
        from ubs_core.registry import RunContext
        for name, source, rule, expected in self.cases():
            with self.subTest(case=name):
                path = self.root / (name + ('.c' if name.startswith('c_language_') else '.cpp'))
                path.write_text(source, encoding='utf-8')
                analyzer = taint_cpp_redirect if rule.endswith('open_redirect') else taint_cpp_traversal
                started = time.monotonic()
                print(f'[cpp-{name}] RUN', flush=True)
                findings = list(analyzer.run(RunContext(lang='cpp', files=[path])))
                actual = {int(f['line']) for f in findings if f['rule'] == rule}
                context = json.dumps({'source': source, 'findings': findings}, indent=2)
                self.assertEqual(actual, expected, context)
                self.assertEqual(len(findings), len(expected), context)
                self.assertTrue(all(f['rule'] == rule and Path(f['path']) == path for f in findings), context)
                print(f'[cpp-{name}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    def test_cpp_clean_redirect_fixture_rejects_browser_authority_bypasses(self):
        compiler = shutil.which('g++') or shutil.which('clang++')
        node = shutil.which('node')
        if not compiler or not node:
            self.skipTest('C++ compiler and Node are required for the independent URL API oracle')
        fixture = REPO_ROOT / 'test-suite/cpp/security/open_redirect_clean.cpp'
        source = self.root / 'redirect-fixture-oracle.cpp'
        program = self.root / 'redirect-fixture-oracle'
        source.write_text('#include <iostream>\n#include ' + json.dumps(str(fixture)) + '\n' + r'''
void Response::redirect(const std::string&) {}
void Response::set_header(const std::string&, const std::string&) {}
int main() {
  const std::string denied[] = {
    "/\\evil.example/path", "/\t/evil.example/path", "/\n/evil.example/path", "/\r/evil.example/path",
    "//evil.example/path", "https://app.example.com@evil.example/profile",
    "https://app.example.com.evil.example/profile", "https://app.example.com\\@evil.example/profile",
    "https://app.example.com\t.evil.example/path", "http://app.example.com/path"
  };
  for (const auto& raw : denied) {
    try {
      safe_redirect_url(raw);
      std::cerr << "unsafe redirect accepted\n";
      return 1;
    } catch (const std::invalid_argument&) {}
  }
  for (const std::string raw : {"/dashboard", "https://app.example.com/profile", "https://accounts.example.com"}) {
    if (safe_redirect_url(raw) != raw) return 2;
    std::cout << raw << '\n';
  }
}
''', encoding='utf-8')
        browser_script = r'''
const fs = require("fs");
const rows = JSON.parse(fs.readFileSync(0, "utf8"));
const origins = rows.map(value => new URL(value, "https://trusted.example/start").origin);
if (origins.some(origin => origin !== "https://evil.example")) throw new Error(JSON.stringify(origins));
console.log(JSON.stringify(origins));
'''
        commands = (
            ('compile', [compiler, '-std=c++20', str(source), '-o', str(program)], None),
            ('fixture', [str(program)], None),
            ('browser', [node, '-e', browser_script],
             json.dumps(['/\\evil.example/path', '/\t/evil.example/path', '/\n/evil.example/path', '/\r/evil.example/path'])),
        )
        for name, command, stdin in commands:
            started = time.monotonic()
            print(f'[cpp-redirect-fixture-{name}] RUN', flush=True)
            proc = subprocess.run(command, input=stdin, cwd=self.root, text=True,
                                  capture_output=True, timeout=60)
            (self.root / (name + '.stdout.log')).write_text(proc.stdout, encoding='utf-8')
            (self.root / (name + '.stderr.log')).write_text(proc.stderr, encoding='utf-8')
            (self.root / (name + '.identity.json')).write_text(json.dumps({
                'command': command, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
                'python': sys.version, 'exit': proc.returncode, 'elapsed': time.monotonic() - started,
            }, indent=2) + '\n', encoding='utf-8')
            self.assertEqual(proc.returncode, 0, f'{command!r}\n{proc.stdout}\n{proc.stderr}')
            if name == 'fixture':
                self.assertEqual(proc.stdout.splitlines(), ['/dashboard', 'https://app.example.com/profile',
                                                           'https://accounts.example.com'])
            print(f'[cpp-redirect-fixture-{name}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    @unittest.skipUnless(os.environ.get('UBS_CPP_TAINT_E2E') == '1', 'set UBS_CPP_TAINT_E2E=1 for native C++ JSON/SARIF')
    def test_independent_cpp_cases_through_public_json_and_sarif(self):
        for name, source, rule, expected in self.cases():
            path = self.root / (name + ('.c' if name.startswith('c_language_') else '.cpp'))
            path.write_text(source, encoding='utf-8')
            for fmt in ('json', 'sarif'):
                with self.subTest(case=name, format=fmt):
                    label = 'cpp-' + name + '-' + fmt
                    print(f'[{label}] RUN', flush=True)
                    command = [str(REPO_ROOT / 'modules/ubs-cpp.sh'), '--ci', '--only=7',
                               '--no-color', '--format=' + fmt, str(path)]
                    env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1',
                               PYTHONDONTWRITEBYTECODE='1', ENABLE_UV_TOOLS='0')
                    started = time.monotonic()
                    proc = subprocess.run(command, cwd=self.root, env=env, capture_output=True,
                                          text=True, timeout=120)
                    (self.root / (label + '.stdout.log')).write_text(proc.stdout, encoding='utf-8')
                    (self.root / (label + '.stderr.log')).write_text(proc.stderr, encoding='utf-8')
                    (self.root / (label + '.identity.json')).write_text(json.dumps({
                        'command': command, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'python': sys.version, 'exit': proc.returncode, 'elapsed': time.monotonic() - started,
                    }, indent=2) + '\n', encoding='utf-8')
                    context = f'{command!r}\nexit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                    self.assertEqual(proc.returncode, int(bool(expected)), context)
                    report = json.loads(proc.stdout)
                    if fmt == 'json':
                        self.assertEqual(report['status'], 'ok', context)
                        self.assertEqual(report['critical'], len(expected), context)
                        findings = [f for f in report['findings'] if f['rule'] == rule]
                        actual = {int(f['line']) for f in findings}
                    else:
                        findings = [f for run in report['runs'] for f in run.get('results', []) if f['ruleId'] == rule]
                        actual = {int(f['locations'][0]['physicalLocation']['region']['startLine']) for f in findings}
                    self.assertEqual(actual, expected, context)
                    self.assertEqual(len(findings), len(expected), context)
                    print(f'[{label}] PASS ({time.monotonic() - started:.3f}s)', flush=True)


class JavaDetectorSuppressionTests(unittest.TestCase):
    """Real legacy receivers: suppress findings without deleting source facts."""

    @classmethod
    def setUpClass(cls):
        # Keep artifacts with this test file even when a baseline harness
        # selects a separate, immutable production checkout via REPO_ROOT.
        artifacts = Path(__file__).resolve().parents[2] / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix='a7-java-detectors-', dir=artifacts))
        print(f'[JavaDetectorSuppressionTests] artifacts={cls.root}', flush=True)

    @contextmanager
    def case(self, label):
        started = time.monotonic()
        identity = self.id() + ':' + label
        print(f'[{identity}] RUN', flush=True)
        state = 'FAIL'
        try:
            yield
            state = 'PASS'
        finally:
            elapsed = time.monotonic() - started
            print(f'[{identity}] {state} ({elapsed:.3f}s)', flush=True)
            with (self.root / 'cases.jsonl').open('a', encoding='utf-8') as output:
                output.write(json.dumps({'case': identity, 'state': state, 'seconds': elapsed}) + '\n')

    def programs(self):
        # Explicit line tables are independent of the detector's own matches.
        # Source lines are separated from sinks to expose lost alias state.
        return (
            ('archive_extraction', 'java.security.archive-extraction', 8, 5, '''import java.nio.file.Path;
import java.util.zip.ZipEntry;
class ArchiveProbe {
    void extract(Path destination, ZipEntry entry) {
        String value = entry.getName();
        int padding = 0;
        padding++;
        java.nio.file.Files.writeString(destination.resolve(value), "data");
    }
}
''', (('destination.resolve(value)', 'destination.resolve("fixed")'),)),
            ('header_injection', 'java.security.header-injection', 7, 4, '''import com.sun.net.httpserver.HttpExchange;
class HeaderProbe {
    void handle(HttpExchange request) {
        String value = request.getRequestURI().getQuery();
        int padding = 0;
        padding++;
        request.getResponseHeaders().add("X-Name", value);
    }
}
''', (('add("X-Name", value)', 'add("X-Name", "fixed")'),)),
            ('ssrf_outbound_url', 'java.security.ssrf-outbound-url', 9, 6, '''import com.sun.net.httpserver.HttpExchange;
import java.net.URI;
import java.net.http.HttpRequest;
class SsrfProbe {
    void handle(HttpExchange request) {
        String value = request.getRequestURI().getQuery();
        int padding = 0;
        padding++;
        HttpRequest.newBuilder(URI.create(value)).build();
    }
}
''', (('URI.create(value)', 'URI.create("https://example.com")'),)),
            ('security_randomness', 'java.security.insecure-randomness', 7, 4, '''import java.util.Random;
class RandomProbe {
    String generate() {
        Random rng = new Random();
        int padding = 0;
        padding++;
        int token = rng.nextInt();
        return Integer.toString(token);
    }
}
''', (('import java.util.Random;', 'import java.security.SecureRandom;'),
      ('Random rng = new Random()', 'SecureRandom rng = new SecureRandom()'))),
            ('collections_foreach', 'java.collections.foreach-remove', 6, 4, '''import java.util.List;
class CollectionsProbe {
    void mutate(List<String> items) {
        for (String item : items) {
            int padding = 0;
            items.remove(item);
        }
    }
}
''', (('items.remove(item)', 'items.contains(item)'),)),
            ('io_loops', 'java.io.readallbytes-loop', 7, 5, '''import java.nio.file.Files;
import java.nio.file.Path;
class IoProbe {
    void read(Path path) throws java.io.IOException {
        for (int i = 0; i < 2; i++) {
            int padding = 0;
            Files.readAllBytes(path);
        }
    }
}
''', (('Files.readAllBytes(path)', 'Files.exists(path)'),)),
            ('streams_concat', 'java.streams-perf.string-plus-loop', 6, 4, '''class StreamsProbe {
    String join(String[] items) {
        String result = "";
        for (String item : items) {
            int padding = 0;
            result += item;
        }
        return result;
    }
}
''', (('String result = "";', 'StringBuilder result = new StringBuilder();'),
      ('result += item;', 'result.append(item);'), ('return result;', 'return result.toString();'))),
            ('optional_get', 'java.null-optional.optional-get', 4, None, '''import java.util.Optional;
class OptionalProbe {
    String read(Optional<String> value) {
        return value.get();
    }
}
''', (('value.get()', 'value.orElse("")'),)),
            ('resource_leaks', 'java.resource.executor-leak', 4, None, '''import java.util.concurrent.Executors;
class ExecutorProbe {
    void launch() {
        Executors.newSingleThreadExecutor();
    }
}
''', (('Executors.newSingleThreadExecutor();', 'Executors.newSingleThreadExecutor().shutdown();'),)),
            ('runtime_exec', 'java.security.runtime-exec', 3, None, '''class ExecProbe {
    void run(String value) throws java.io.IOException {
        Runtime.getRuntime().exec(value);
    }
}
''', (('Runtime.getRuntime().exec(value);', 'System.out.println(value);'),)),
            ('equals_hashcode', 'java.equality.equals-no-hashcode', 2, None, '''class EqualityProbe {
    public boolean equals(Object other) {
        return this == other;
    }
}
''', (('class EqualityProbe {', 'class EqualityProbe {\n    public int hashCode() { return System.identityHashCode(this); }'),)),
            ('sql_concat_fallback', 'java.sql.concat-fallback', 3, None, '''class SqlProbe {
    String query(String value) {
        return "SELECT id FROM users WHERE id = " + (value);
    }
}
''', (('"SELECT id FROM users WHERE id = " + (value)', '"SELECT id FROM users WHERE id = 1"'),)),
            ('control_flow', 'java.control-flow.switch-fallthrough', 4, None, '''class FallthroughProbe {
    void run(int value) {
        switch (value) {
            case 1: System.out.println(value);
            default: return;
        }
    }
}
''', (('case 1: System.out.println(value);', 'case 1: System.out.println(value); break;'),)),
            ('control_flow', 'java.control-flow.switch-no-default', 3, None, '''class DefaultProbe {
    void run(int value) {
        switch (value) {
            case 1: System.out.println(value); break;
        }
    }
}
''', (('case 1: System.out.println(value); break;', 'case 1: System.out.println(value); break;\n            default: break;'),)),
            ('tech_debt', 'java.logging.tech-debt', 3, None, '''class DebtProbe {
    void work() {
        int item = 0; // TODO finish work
    }
}
''', (('// TODO finish work', '// completed work'),)),
            ('tech_debt', 'java.logging.tech-debt-significant', 3, None,
             self.debt_program(22), (('TODO', 'completed'),)),
        )

    def debt_program(self, count):
        return ('class SignificantDebtProbe {\n    void work() {\n' + ''.join(
            f'        int item{index:02d} = 0; // TODO {index:02d}\n'
            for index in range(1, count + 1)) + '    }\n}\n')

    def variant(self, text, line, mode, rule, language='java'):
        lines = text.splitlines()
        index = line - 1
        marker = 'ubs:ignore' if mode.endswith('bare') else f'ubs:ignore[{rule}]'
        if mode.startswith('previous-'):
            lines.insert(index, '        // ' + marker)
        elif mode.endswith('quoted'):
            raw = lines[index]
            declaration = ('val marker = "ubs:ignore";' if language == 'kotlin'
                           else 'String marker = "ubs:ignore";')
            if mode.startswith('source-') or raw.rstrip().endswith('{'):
                lines[index] += ' ' + declaration
            elif raw.lstrip().startswith(('case ', 'default:')):
                lines[index] = raw.replace(':', ': ' + declaration, 1)
            else:
                indent = raw[:len(raw) - len(raw.lstrip())]
                lines[index] = indent + declaration + ' ' + raw.lstrip()
        else:
            lines[index] += ' // ' + marker
        return '\n'.join(lines) + '\n'

    def direct(self, module_name, text, label, expected):
        module = importlib.import_module('ubs_core.java_detectors.' + module_name)
        path = self.root / (label + '.java')
        path.write_text(text, encoding='utf-8')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            hits = list(module.find([path]))
        (self.root / (label + '.direct.json')).write_text(json.dumps({
            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'expected': expected, 'hits': hits, 'stdout': stdout.getvalue(), 'stderr': stderr.getvalue(),
        }, default=str, indent=2), encoding='utf-8')
        actual = []
        for hit in hits:
            self.assertEqual(len(hit), 5 if hasattr(module, 'RULES') else 4, repr(hits))
            if hasattr(module, 'RULES'):
                rule, source, line, col, detail = hit
            else:
                source, line, col, detail = hit
                rule = module.RULE_ID
            self.assertEqual(Path(source), path)
            self.assertTrue(detail)
            actual.append((rule, line, col))
        self.assertEqual(sorted(actual), sorted(expected), repr(hits))

    def test_all_java_receivers_exact_sites_and_marker_ownership(self):
        for number, (module, rule, line, _, text, replacements) in enumerate(self.programs()):
            sites = list(range(3, 25)) if rule.endswith('tech-debt-significant') else [line]
            for mode in ('unmarked', 'safe', 'bare', 'exact', 'unrelated', 'quoted',
                         'previous-exact', 'previous-unrelated'):
                label = f'java-{number:02d}-{module}-{mode}'
                with self.subTest(case=label), self.case(label):
                    code, expected_lines = text, sites
                    if mode == 'safe':
                        for old, new in replacements:
                            self.assertIn(old, code)
                            code = code.replace(old, new)
                        expected_lines = []
                    elif mode != 'unmarked':
                        marker_rule = 'java.unrelated.rule' if 'unrelated' in mode else rule
                        code = self.variant(text, line, mode, marker_rule)
                        shift = int(mode.startswith('previous-'))
                        expected_lines = [site + shift for site in sites
                                          if mode not in ('bare', 'exact', 'previous-exact') or site != line]
                    self.direct(module, code, label, [(rule, site, 1) for site in expected_lines])

    def test_marked_sources_preserve_later_unmarked_sinks(self):
        for module, rule, line, source_line, text, _ in self.programs():
            if source_line is None:
                continue
            for mode in ('source-bare', 'source-exact', 'source-unrelated', 'source-quoted'):
                label = module + '-' + mode
                with self.subTest(case=label), self.case(label):
                    marker_rule = 'java.unrelated.rule' if mode.endswith('unrelated') else rule
                    code = self.variant(text, source_line, mode, marker_rule)
                    self.direct(module, code, label, [(rule, line, 1)])

    def test_public_rule_selection_preserves_counter_and_primary_facts(self):
        fallthrough = 'java.control-flow.switch-fallthrough'
        no_default = 'java.control-flow.switch-no-default'
        two_rules = '''class TwoRulesProbe {
    void run(int value) {
        switch (value) {
            case 1: System.out.println(value);
        }
    }
}
'''
        for label, line, marker_rule, expected in (
            ('switch-other-public', 3, fallthrough, [(fallthrough, 4, 1), (no_default, 3, 1)]),
            ('case-other-public', 4, no_default, [(fallthrough, 4, 1), (no_default, 3, 1)]),
            ('switch-owned', 3, no_default, [(fallthrough, 4, 1)]),
            ('case-owned', 4, fallthrough, [(no_default, 3, 1)]),
        ):
            with self.subTest(case=label), self.case(label):
                self.direct('control_flow', self.variant(two_rules, line, 'exact', marker_rule), label, expected)
        safe_switch = '''class SafeSwitchProbe {
    void run(int value) {
        switch (value) {
            case 1: System.out.println(value);
                break;
            default: return;
        }
    }
}
'''
        for fact, line, rule in (('break', 5, fallthrough), ('default', 6, no_default)):
            for mode in ('bare', 'exact', 'unrelated', 'quoted'):
                label = 'switch-safe-fact-' + fact + '-' + mode
                with self.subTest(case=label), self.case(label):
                    marker_rule = 'java.unrelated.rule' if mode == 'unrelated' else rule
                    self.direct('control_flow', self.variant(safe_switch, line, mode, marker_rule), label, [])
        for count in (20, 21):
            rule = 'java.logging.tech-debt' + ('-significant' if count > 20 else '')
            for mode, marker_rule in (('unmarked', rule), ('exact', rule),
                                      ('unrelated', 'java.unrelated.rule'),
                                      ('other-public', 'java.logging.tech-debt' if count > 20
                                       else 'java.logging.tech-debt-significant')):
                label = f'debt-tier-{count}-{mode}'
                with self.subTest(case=label), self.case(label):
                    text = self.debt_program(count)
                    if mode != 'unmarked':
                        text = self.variant(text, 3, 'exact', marker_rule)
                    first = 4 if mode == 'exact' else 3
                    self.direct('tech_debt', text, label,
                                [(rule, line, 1) for line in range(first, count + 3)])
        primary = self.programs()[11][4].replace(' + (value)', ' + value')
        for mode, marker_rule in (('unmarked', 'java.sql.concat'), ('bare', 'java.sql.concat'),
                                  ('exact', 'java.sql.concat'), ('fallback-exact', 'java.sql.concat-fallback'),
                                  ('unrelated', 'java.unrelated.rule'), ('quoted', 'java.sql.concat')):
            label = 'sql-primary-facts-' + mode
            with self.subTest(case=label), self.case(label):
                text = primary if mode == 'unmarked' else self.variant(primary, 3, mode, marker_rule)
                self.direct('sql_concat_fallback', text, label, [])

    def test_kotlin_adapter_uses_actual_public_ids_and_keeps_source_state(self):
        from ubs_core.kotlin_scan import scan_detectors
        programs = (
            ('archive-extraction', 7, 4, '''import java.nio.file.Path
import java.util.zip.ZipEntry
fun extract(destination: Path, entry: ZipEntry) {
    val value = entry.getName();
    val padding = 0;
    println(padding);
    java.nio.file.Files.writeString(destination.resolve(value), "data");
}
''', ('destination.resolve(value)', 'destination.resolve("fixed")')),
            ('header-injection', 6, 3, '''import com.sun.net.httpserver.HttpExchange
fun handle(request: HttpExchange) {
    val value = request.getRequestURI().getQuery();
    val padding = 0;
    println(padding);
    request.getResponseHeaders().add("X-Name", value);
}
''', ('add("X-Name", value)', 'add("X-Name", "fixed")')),
            ('ssrf-outbound-url', 8, 5, '''import com.sun.net.httpserver.HttpExchange
import java.net.URI
import java.net.http.HttpRequest
fun handle(request: HttpExchange) {
    val value = request.getRequestURI().getQuery();
    val padding = 0;
    println(padding);
    HttpRequest.newBuilder(URI.create(value)).build();
}
''', ('URI.create(value)', 'URI.create("https://example.com")')),
            ('insecure-randomness', 6, 3, '''import java.util.Random
fun generate(): String {
    val rng = Random();
    val padding = 0;
    println(padding);
    val token = rng.nextInt();
    return token.toString();
}
''', ('Random', 'java.security.SecureRandom')),
        )
        for slug, line, source_line, text, safe_change in programs:
            rule = 'kotlin.security.' + slug
            for mode in ('unmarked', 'safe', 'bare', 'exact', 'unrelated', 'quoted',
                         'previous-exact', 'previous-unrelated', 'java-public',
                         'source-bare', 'source-exact', 'source-unrelated', 'source-quoted'):
                label = 'kotlin-' + slug + '-' + mode
                with self.subTest(case=label), self.case(label):
                    code = text
                    if mode == 'safe':
                        if slug == 'insecure-randomness':
                            code = code.replace('import java.util.Random', 'import java.security.SecureRandom')
                            code = code.replace('Random()', 'SecureRandom()')
                        else:
                            code = code.replace(*safe_change)
                    elif mode != 'unmarked':
                        marker_rule = ('java.security.' + slug if mode == 'java-public' else
                                       'kotlin.unrelated.rule' if 'unrelated' in mode else rule)
                        target = source_line if mode.startswith('source-') else line
                        code = self.variant(text, target, mode, marker_rule, language='kotlin')
                    path = self.root / (label + '.kt')
                    path.write_text(code, encoding='utf-8')
                    sink = io.StringIO()
                    scan_detectors([path], sink, set())
                    records = [json.loads(raw) for raw in sink.getvalue().splitlines()]
                    (self.root / (label + '.ndjson')).write_text(sink.getvalue(), encoding='utf-8')
                    expected = [] if mode in ('safe', 'bare', 'exact', 'previous-exact') else [
                        (rule, line + int(mode.startswith('previous-')), 1, 'critical')]
                    self.assertEqual([(row['rule'], row['line'], row['col'], row['severity'])
                                      for row in records], expected, records)
                    self.assertTrue(all(Path(row['path']) == path for row in records))

    def test_native_sql_fallback_json_and_sarif_positive_safe_and_owned(self):
        rule = 'java.sql.concat-fallback'
        text = self.programs()[11][4]
        for mode in ('unmarked', 'safe', 'unrelated', 'quoted', 'exact', 'previous-exact'):
            code = text
            if mode == 'safe':
                code = code.replace('"SELECT id FROM users WHERE id = " + (value)',
                                    '"SELECT id FROM users WHERE id = 1"')
            elif mode != 'unmarked':
                code = self.variant(text, 3, mode, 'java.unrelated.rule' if mode == 'unrelated' else rule)
            path = self.root / ('native-sql-' + mode + '.java')
            path.write_text(code, encoding='utf-8')
            expected = [] if mode in ('safe', 'exact', 'previous-exact') else [(rule, 3, 1)]
            for fmt in ('json', 'sarif'):
                label = 'native-sql-' + mode + '-' + fmt
                with self.subTest(case=label), self.case(label):
                    directory = self.root / label
                    directory.mkdir()
                    command = [str(REPO_ROOT / 'modules/ubs-java.sh'), '--ci', '--no-color',
                               '--only=13', '--fail-on-warning', '--format=' + fmt, str(path)]
                    env = dict(os.environ, UBS_NO_CACHE='1', UBS_NO_AUTO_UPDATE='1',
                               PYTHONDONTWRITEBYTECODE='1', ENABLE_UV_TOOLS='0')
                    started = time.monotonic()
                    proc = subprocess.run(command, cwd=directory, env=env, capture_output=True,
                                          text=True, timeout=120)
                    (directory / 'stdout.log').write_text(proc.stdout, encoding='utf-8')
                    (directory / 'stderr.log').write_text(proc.stderr, encoding='utf-8')
                    (directory / 'identity.json').write_text(json.dumps({
                        'case': self.id() + ':' + label, 'command': command, 'cwd': str(directory),
                        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'exit': proc.returncode, 'seconds': time.monotonic() - started,
                    }, indent=2), encoding='utf-8')
                    context = f'{command!r}\nexit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
                    self.assertNotIn('Traceback (most recent call last)', proc.stderr, context)
                    self.assertEqual(proc.returncode, int(bool(expected)), context)
                    summaries = [json.loads(raw) for raw in proc.stderr.splitlines()
                                 if raw.startswith('{"counters":')]
                    self.assertEqual(len(summaries), 1, context)
                    self.assertEqual(summaries[0]['counters'],
                                     {'critical': 0, 'warning': len(expected), 'info': 0}, context)
                    self.assertEqual(summaries[0]['errors'], [], context)
                    report = json.loads(proc.stdout)
                    if fmt == 'json':
                        self.assertEqual(report['status'], 'ok', context)
                        self.assertEqual(report['files'], 1, context)
                        self.assertEqual({key: report[key] for key in ('critical', 'warning', 'info')},
                                         {'critical': 0, 'warning': len(expected), 'info': 0}, context)
                        actual = [(row['rule'], row['line'], row['col']) for row in report['findings']]
                        self.assertTrue(all(Path(row['path']) == path for row in report['findings']), context)
                    else:
                        results = [row for run in report['runs'] for row in run['results']]
                        actual = [(row['ruleId'], row['locations'][0]['physicalLocation']['region']['startLine'],
                                   row['locations'][0]['physicalLocation']['region']['startColumn']) for row in results]
                        self.assertTrue(all(row['level'] == 'warning' for row in results), context)
                        self.assertTrue(all(row['locations'][0]['physicalLocation']['artifactLocation']['uri']
                                            == sarif_uri(path) for row in results), context)
                    self.assertEqual(actual, expected, context)

    def test_literal_only_sql_concatenation_completes_the_java_module(self):
        # GH #183: with no primary hit, the fallback branch yielded 3-tuples and
        # java_scan's single-rule unpacking crashed the whole module (exit 2).
        from ubs_core.java_detectors import sql_concat_fallback
        from ubs_core.java_scan import run_detectors

        path = self.root / 'Gh183Repro.java'
        path.write_text('public class Repro {\n'
                        '    void run(java.sql.Statement st) throws Exception {\n'
                        '        st.execute("INSERT INTO t(a) " +\n'
                        '                   "VALUES (1)");\n'
                        '    }\n'
                        '}\n', encoding='utf-8')
        self.assertEqual([hit[1:3] for hit in sql_concat_fallback.find([path])], [(3, 1)])
        sink, errors = io.StringIO(), []
        run_detectors([path], sink, set(), errors=errors)
        self.assertEqual(errors, [])
        records = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertIn(('java.sql.concat-fallback', 3, 1),
                      [(row['rule'], row['line'], row['col']) for row in records])
        label = 'gh183-literal-sql'
        with self.case(label):
            directory = self.root / label
            directory.mkdir()
            command = [str(REPO_ROOT / 'modules/ubs-java.sh'), '--ci', '--no-color',
                       '--format=json', str(path)]
            env = dict(os.environ, UBS_NO_CACHE='1', UBS_NO_AUTO_UPDATE='1',
                       PYTHONDONTWRITEBYTECODE='1', ENABLE_UV_TOOLS='0')
            proc = subprocess.run(command, cwd=directory, env=env, capture_output=True,
                                  text=True, timeout=120)
            context = f'{command!r}\nexit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
            self.assertNotIn('ValueError', proc.stderr, context)
            self.assertEqual(proc.returncode, 0, context)
            report = json.loads(proc.stdout)
            self.assertEqual(report['status'], 'ok', context)
            # Literal-plus-literal SQL is static: SQL qualification keeps it quiet.
            self.assertEqual([row for row in report['findings'] if row['rule'].startswith('java.sql')],
                             [], context)


class SwiftCppSuppressionTests(unittest.TestCase):
    """Real legacy producers must retain facts before suppressing owned diagnostics."""

    SECURITY_CASES = (
        ("swift_detectors.header_injection", "swift", "swift.taint.header-injection", 2, 4, [4],
         'func displayName(req: Request, response: inout Response) {\n'
         '    let name = req.query["displayName"] ?? "guest"\n    _ = 0\n'
         '    response.headers["X-Display-Name"] = name\n}\n',
         'func displayName(req: Request, response: inout Response) {\n'
         '    let name = safeHeaderValue(req.query["displayName"] ?? "guest")\n    _ = 0\n'
         '    response.headers["X-Display-Name"] = name\n}\n',
         "swift/header_injection_clean/HeadersSafe.swift"),
        ("swift_detectors.outbound_url", "swift", "swift.taint.outbound-url", 2, 4, [4],
         'func fetchQueryURL(req: Request) {\n'
         '    let target = req.query["url"] ?? "https://example.com"\n    _ = 0\n'
         '    URLSession.shared.dataTask(with: URL(string: target)!).resume()\n}\n',
         'func fetchQueryURL(req: Request) throws {\n'
         '    let target = try safeOutboundURL(req.query["url"] ?? "https://api.example.com")\n'
         '    _ = 0\n    URLSession.shared.dataTask(with: target).resume()\n}\n',
         "swift/ssrf_clean/RequestURLsSafe.swift"),
        ("swift_detectors.archive_extraction", "swift", "swift.security.archive-extraction", 2, 4, [4],
         'func archiveTarget(entry: ArchiveEntry, destination: URL) -> URL {\n'
         '    let name = entry.path\n    _ = 0\n'
         '    return destination.appendingPathComponent(name)\n}\n',
         'func archiveTarget(entry: ArchiveEntry, destination: URL) throws -> URL {\n'
         '    let name = entry.path\n    _ = 0\n'
         '    return try safeArchiveURL(destination: destination, entryPath: name)\n}\n',
         "swift/archive_extraction_clean/ZipSlipSafe.swift"),
        ("swift_detectors.security_randomness", "swift", "swift.crypto.weak-randomness", 2, 4, [2, 4],
         'func issueApiKey() -> String {\n    var rng = SystemRandomNumberGenerator()\n'
         '    _ = 0\n' + r'    return "ak_\(rng.next())"' + '\n}\n',
         'import Security\nfunc sessionToken() -> [UInt8] {\n'
         '    var bytes = [UInt8](repeating: 0, count: 32)\n'
         '    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)\n'
         '    guard status == errSecSuccess else { return [] }\n    return bytes\n}\n',
         "swift/security_randomness_clean/Tokens.swift"),
        ("analyzers.taint_swift_traversal", "swift", "swift.taint.request_path_traversal", 2, 4, [4],
         'func readDownload(req: Request) throws -> String {\n'
         '    let path = req.query["file"] ?? "index.html"\n    _ = 0\n'
         '    return try String(contentsOfFile: path)\n}\n',
         'func readDownload(req: Request) throws -> String {\n'
         '    let requested = req.query["file"] ?? "index.html"\n'
         '    let path = URL(fileURLWithPath: requested).lastPathComponent\n'
         '    return try String(contentsOfFile: path)\n}\n',
         "swift/path_traversal_clean/RequestPathsSafe.swift"),
        ("analyzers.taint_swift_redirect", "swift", "swift.taint.request_open_redirect", 2, 4, [4],
         'func queryRedirect(req: Request) -> Response {\n'
         '    let target = req.query["returnUrl"] ?? "/"\n    _ = 0\n'
         '    return req.redirect(to: target)\n}\n',
         'func localOnly(req: Request) throws -> Response {\n'
         '    let target = req.query["returnUrl"] ?? "/"\n'
         '    guard let url = URL(string: target), let host = url.host, allowedHosts.contains(host) else {\n'
         '        throw Abort(.badRequest)\n    }\n    return req.redirect(to: target)\n}\n',
         "swift/open_redirect_clean/RedirectsSafe.swift"),
        ("cpp_detectors.header_injection", "cpp", "cpp.detector.header-injection", 2, 4, [4],
         'void display_name(const Request& req, Response& response) {\n'
         '    auto name = req.get_param_value("display_name");\n    (void)0;\n'
         '    response.set_header("X-Display-Name", name);\n}\n',
         'void display_name(const Request& req, Response& response) {\n'
         '    auto name = safe_header_value(req.get_param_value("display_name"));\n    (void)0;\n'
         '    response.set_header("X-Display-Name", name);\n}\n',
         "cpp/security/header_injection_clean.cpp"),
        ("cpp_detectors.outbound_url", "cpp", "cpp.detector.outbound-url", 2, 5, [5],
         'void fetch_from_query(CURL* curl) {\n    const char* raw = getenv("QUERY_STRING");\n'
         '    std::string target = raw ? raw : "https://example.com";\n    (void)0;\n'
         '    curl_easy_setopt(curl, CURLOPT_URL, target.c_str());\n}\n',
         'void fetch_from_query(CURL* curl) {\n'
         '    const std::string target = safe_outbound_url(getenv("QUERY_STRING"));\n    (void)0;\n'
         '    curl_easy_setopt(curl, CURLOPT_URL, target);\n}\n',
         "cpp/security/ssrf_clean.cpp"),
        ("cpp_detectors.archive_entry", "cpp", "cpp.detector.archive-entry", 2, 4, [4],
         'void archive_target(archive_entry* entry, const fs::path& destination) {\n'
         '    const char* name = archive_entry_pathname(entry);\n    (void)0;\n'
         '    auto target = destination / name;\n}\n',
         'void archive_target(archive_entry* entry, const fs::path& destination) {\n'
         '    const char* name = archive_entry_pathname(entry);\n    (void)0;\n'
         '    auto target = safe_archive_path(destination, name);\n}\n',
         "cpp/archive_extraction_clean/zip_slip_safe.cpp"),
        ("cpp_detectors.weak_random", "cpp", "cpp.detector.weak-random", 3, 5, [3, 5],
         '#include <random>\nunsigned sessionToken() {\n    std::mt19937 rng(1);\n'
         '    (void)0;\n    return rng();\n}\n',
         'extern "C" int RAND_bytes(unsigned char* buf, int num);\n'
         'void sessionToken(unsigned char* bytes) {\n'
         '    if (RAND_bytes(bytes, 32) != 1) throw 1;\n}\n',
         "cpp/security_randomness_clean/tokens.cpp"),
        ("analyzers.taint_cpp_traversal", "cpp", "cpp.taint.path_traversal", 2, 4, [4],
         'void read_download(const Request& req) {\n'
         '    std::string path = req.getParam("file");\n    (void)0;\n'
         '    std::ifstream input(path);\n}\n',
         'void read_download(const Request& req) {\n'
         '    std::string path = sanitize_filename(req.getParam("file"));\n    (void)0;\n'
         '    std::ifstream input(path);\n}\n',
         "cpp/security/path_traversal_clean.cpp"),
        ("analyzers.taint_cpp_redirect", "cpp", "cpp.taint.open_redirect", 2, 4, [4],
         'void query_redirect(const Request& req, Response& res) {\n'
         '    std::string url = req.getParam("next");\n    (void)0;\n    res.redirect(url);\n}\n',
         'void query_redirect(const Request& req, Response& res) {\n'
         '    std::string url = validate_redirect_target(req.getParam("next"));\n'
         '    (void)0;\n    res.redirect(url);\n}\n',
         "cpp/security/open_redirect_clean.cpp"),
    )
    # main's C++/Swift flow engines (d3cc89c7, 65eeb694, 48725603) give an
    # unbound helper name or an undeclared allowlist no trust, so these inline
    # programs still reach the sink there (expected sink lines below). The
    # shipped clean fixtures (original-safe) carry the safe side for them.
    UNBOUND_SAFE = {
        "analyzers.taint_swift_redirect": [6],
        "analyzers.taint_cpp_traversal": [4],
        "analyzers.taint_cpp_redirect": [4],
    }
    DERIVED_CASES = (
        ("swift_patterns.errors_security", "_process_residual", "swift.security.process-other", "Case.swift", 3,
         'import Foundation\nfunc runFixedTool() throws {\n    let process = Process()\n'
         '    process.executableURL = URL(fileURLWithPath: "/usr/bin/stat")\n'
         '    process.arguments = ["--version"]\n    try process.run()\n}\n',
         'import Foundation\nfunc runShellTool() throws {\n    let process = Process()\n'
         '    process.executableURL = URL(fileURLWithPath: "/bin/sh")\n'
         '    process.arguments = ["-c", "ls"]\n    try process.run()\n}\n', 0),
        ("swift_patterns.threading_perf", "_filehandle_imbalance", "swift.files.filehandle", "Case.swift", 3,
         'import Foundation\nfunc readFile() throws {\n'
         '    let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/tmp/data"))\n'
         '    _ = 0\n}\n',
         'import Foundation\nfunc readFile() throws {\n'
         '    let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/tmp/data"))\n'
         '    _ = 0\n    try handle.close()\n}\n', 5),
        ("swift_patterns.threading_perf", "_main_actor_presence", "swift.threading.main-actor", "Case.swift", 1,
         'import SwiftUI\nfinal class ViewModel {}\n',
         'import SwiftUI\n@MainActor final class ViewModel {}\n', 2),
        ("swift_patterns.misc_cats", "_packaging", "swift.packaging.branch-pins", "Package.swift", 3,
         'import PackageDescription\nlet dependencies: [Package.Dependency] = [\n'
         '    .package(url: "https://example.com/pkg.git", .branch("main"))\n]\n'
         'let package = Package(name: "Demo", dependencies: dependencies)\n',
         'import PackageDescription\nlet dependencies: [Package.Dependency] = [\n'
         '    .package(url: "https://example.com/pkg.git", .exact("1.2.3"))\n]\n'
         'let package = Package(name: "Demo", dependencies: dependencies)\n', 0),
        ("swift_patterns.misc_cats", "_packaging", "swift.packaging.unsafe-flags", "Package.swift", 2,
         'import PackageDescription\nlet flags: [SwiftSetting] = [.unsafeFlags(["-Ounchecked"])]\n'
         'let package = Package(name: "Demo", targets: [.target(name: "Demo", swiftSettings: flags)])\n',
         'import PackageDescription\nlet flags: [SwiftSetting] = [.define("FEATURE")]\n'
         'let package = Package(name: "Demo", targets: [.target(name: "Demo", swiftSettings: flags)])\n', 0),
    )

    def setUp(self):
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(prefix="swift-cpp-suppression-", dir=artifacts)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    @staticmethod
    def marked(text, line, mode, rule, lang="swift"):
        lines = text.splitlines()
        marker = ('; _ = "ubs:ignore"' if lang == "swift" else ' (void)"ubs:ignore";') if mode == "quoted" else (
            " // ubs:ignore" if mode == "bare" else
            f" // ubs:ignore[{'unrelated.rule' if mode == 'wrong' else rule}]")
        lines[line - 1] += marker
        return "\n".join(lines) + "\n"

    def invoke(self, module_name, lang, filename, text, label, function=None):
        from ubs_core.registry import RunContext
        from ubs_core.swift_scan import ScanContext
        from ubs_core.suppression import SourceSuppressions

        directory = self.root / label
        directory.mkdir()
        path = directory / filename
        path.write_text(text, encoding="utf-8")
        module = importlib.import_module("ubs_core." + module_name)
        stdout, stderr = io.StringIO(), io.StringIO()
        started = time.monotonic()
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                if function is not None:
                    records = list(getattr(module, function)(ScanContext(files=[path], project_dir=directory)))
                elif module_name.startswith("swift_detectors."):
                    records = list(module.scan(ScanContext(files=[path], project_dir=directory)))
                elif module_name.startswith("cpp_detectors."):
                    records = [{"rule": module.RULE_ID, "path": str(source), "line": line,
                                "col": col, "detail": detail, "severity": module.SEVERITY}
                               for source, line, col, detail in module.find([path])]
                else:
                    records = list(module.run(RunContext(lang=lang, files=[path])))
        finally:
            (directory / "stdout.log").write_text(stdout.getvalue(), encoding="utf-8")
            (directory / "stderr.log").write_text(stderr.getvalue(), encoding="utf-8")
        policy = SourceSuppressions(lang)
        policy.index(path, text)
        final = policy.filter(records)
        (directory / "findings.json").write_text(json.dumps(
            {"raw": records, "final": final}, indent=2, default=str), encoding="utf-8")
        (directory / "identity.json").write_text(json.dumps({
            "case": self.id() + ":" + label, "module": module_name, "function": function,
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "producer_sha256": hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(),
            "seconds": time.monotonic() - started,
        }, indent=2), encoding="utf-8")
        return path, records, final

    def test_security_markers_preserve_exact_rules_and_source_facts(self):
        checked = 0
        for module, lang, rule, source_line, sink_line, baseline, positive, safe, original_safe in self.SECURITY_CASES:
            safe_variant = (("unbound-helper", safe, self.UNBOUND_SAFE[module]) if module in self.UNBOUND_SAFE
                            else ("safe", safe, []))
            variants = [("unmarked", positive, baseline), safe_variant,
                        ("original-safe", (REPO_ROOT / "test-suite" / original_safe).read_text(encoding="utf-8"), [])]
            for site, line in (("source", source_line), ("sink", sink_line)):
                for mode in ("bare", "exact", "wrong", "quoted"):
                    expected = [hit for hit in baseline if hit != line] if mode in ("bare", "exact") else baseline
                    variants.append((site + "-" + mode, self.marked(positive, line, mode, rule, lang), expected))
            for mode, text, expected in variants:
                label = module.replace(".", "-") + "-" + mode
                with self.subTest(producer=module, variant=mode):
                    path, records, final = self.invoke(module, lang, "Case." + ("swift" if lang == "swift" else "cpp"),
                                                       text, label)
                    expected_rows = [(rule, line, 1, "critical") for line in expected]
                    actual = lambda rows: [(row["rule"], row["line"], row.get("count", 1), row["severity"]) for row in rows]
                    self.assertEqual(actual(records), expected_rows, records)
                    self.assertEqual(actual(final), expected_rows, final)
                    self.assertTrue(all(Path(row["path"]) == path.resolve() for row in records), records)
                checked += 1
        self.assertEqual(checked, 132)

    def test_swift_derived_preserves_safe_facts_and_exact_contributions(self):
        checked = 0
        for module, function, rule, filename, line, positive, safe, fact_line in self.DERIVED_CASES:
            baseline = [(3, 1)] if function == "_process_residual" else [(0, 1)]
            variants = [("unmarked", positive, baseline), ("safe", safe, [])]
            for mode in ("bare", "exact", "wrong", "quoted"):
                # An absence aggregate is not owned by the UI import; real
                # MainActor evidence remains a fact under every marker.
                expected = [] if mode in ("bare", "exact") and function != "_main_actor_presence" else baseline
                variants.append(("sink-" + mode, self.marked(positive, line, mode, rule), expected))
                if fact_line:
                    variants.append(("fact-" + mode, self.marked(safe, fact_line, mode, rule), []))
            for mode, text, expected in variants:
                label = rule.replace(".", "-") + "-" + mode
                with self.subTest(rule=rule, variant=mode):
                    _path, records, final = self.invoke(module, "swift", filename, text, label, function)
                    expected_rows = [(rule, site, count) for site, count in expected]
                    actual = lambda rows: [(row["rule"], row["line"], row["count"]) for row in rows]
                    self.assertEqual(actual(records), expected_rows, records)
                    self.assertEqual(actual(final), expected_rows, final)
                checked += 1
        self.assertEqual(checked, 38)

    def test_original_taint_controls_are_unchanged(self):
        checked = 0
        for name in ("taint_swift_traversal", "taint_swift_redirect", "taint_cpp_traversal", "taint_cpp_redirect"):
            module = importlib.import_module("ubs_core.analyzers." + name)
            for label, original in module.SELF_TESTS:
                with self.subTest(analyzer=name, control=label):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    try:
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            original()
                    finally:
                        (self.root / (name + "-" + label + ".stdout.log")).write_text(stdout.getvalue(), encoding="utf-8")
                        (self.root / (name + "-" + label + ".stderr.log")).write_text(stderr.getvalue(), encoding="utf-8")
                checked += 1
        # main's rewritten engines embed 19 controls (SwiftPine's base had 15).
        self.assertEqual(checked, 19)


class SwiftLexicalFrontendTests(unittest.TestCase):
    """Selected Swift lexical contracts, not Foundation runtime proof."""

    LEXICAL_CASES = (
        ('plain', 'let target = req.query["returnUrl"] ?? "/"\n', True),
        ('literal', 'let note = "req.query // ubs:ignore[swift.taint.request_open_redirect]"\n', False),
        ('nested-comment', '/* outer /* inner */ req.query */\nlet fixed = 1\n', False),
        ('triple', 'let note = """\nreq.query // ubs:ignore[swift.taint.request_open_redirect]\n"""\n', False),
        ('raw-one', 'let note = #"quote " req.query // ubs:ignore[swift.taint.request_open_redirect]"#\n', False),
        ('raw-two', 'let note = ##"short closer "# req.query \\#(req.query)"##\n', False),
        ('raw-triple', 'let note = ##"""\nshort closer """# req.query\n"""##\n', False),
        ('interpolation', 'let target = "prefix \\(req.query["returnUrl"] ?? "/")"\n', True),
        ('triple-interpolation', 'let target = """\nprefix \\(req.query["returnUrl"] ?? "/")\n"""\n', True),
        ('raw-interpolation', 'let target = #"prefix \\#(req.query["returnUrl"] ?? "/")"#\n', True),
        ('wrong-raw-interpolation', 'let note = ##"\\(req.query) \\#(req.query)"##\n', False),
        ('two-raw-interpolation', 'let target = ##"\\##(req.query["returnUrl"] ?? "/")"##\n', True),
        ('nested-call', 'let target = "\\(String(describing: (req.query["returnUrl"] ?? "/")))"\n', True),
        ('comment-in-interpolation', 'let target = "\\(/* outer /* inner */ tail */ req.query["returnUrl"] ?? "/")"\n', True),
        ('escaped-interpolation', 'let note = "\\\\(req.query[\\"returnUrl\\"])"\n', False),
        ('unicode', 'let café = "雪 🐦 req.query"\nlet fixed = 1\n', False),
        ('division', 'let ratio = req.query.count / 2\n', True),
    )

    def test_swift_lexical_payloads_and_all_existing_view_modes(self):
        for name, source, active in self.LEXICAL_CASES:
            for strings, comments, preserve in ((True, True, False), (True, True, True),
                                                (False, True, False), (False, False, False)):
                with self.subTest(case=name, strings=strings, comments=comments, preserve=preserve):
                    actual = strip_comments_and_strings(source, lang="swift", strip_strings=strings,
                                                        strip_comments=comments, preserve_comments=preserve)
                    self.assertEqual(len(actual), len(source))
                    self.assertEqual([i for i, c in enumerate(actual) if c == '\n'],
                                     [i for i, c in enumerate(source) if c == '\n'])
                    if strings and not preserve:
                        self.assertEqual('req.query' in actual, active, actual)
                    if not strings and not comments:
                        self.assertEqual(actual, source)

    def test_swift_markers_in_literals_are_inert_and_interpolation_comments_are_real(self):
        from ubs_core.suppression import parse_markers
        rule = 'swift.taint.request_open_redirect'
        for source in ('let note = "// ubs:ignore[' + rule + ']"\n',
                       'let note = #"quote " // ubs:ignore[' + rule + ']"#\n',
                       'let note = ##"""\n"""# // ubs:ignore[' + rule + ']\n"""##\n',
                       'let pattern = #/ // ubs:ignore[' + rule + '] /#\n'):
            with self.subTest(source=source):
                self.assertEqual(parse_markers(source, 'swift'), [])
        source = 'let target = "\\(/* ubs:ignore[' + rule + '] */ req.query["returnUrl"] ?? "/")"\n'
        markers = parse_markers(source, 'swift')
        self.assertEqual([(m.line, m.rules) for m in markers], [(1, frozenset({rule}))])

    def test_swift_regex_literals_are_opaque_and_division_stays_code(self):
        # The Swift taint lexer reads these as regex literals too; SwiftPine's
        # lexer rejected them as unsupported (b2ca4d04).
        for source in ('let pattern = /req.query/\n', 'let pattern = #/req.query//#\n',
                       'if s.contains(/req.query/) {}\n', 'switch s { case /req.query/: break }\n',
                       'let pattern = #/\n  req.query // x\n/#\n'):
            with self.subTest(source=source):
                actual = strip_comments_and_strings(source, lang='swift')
                self.assertNotIn('req.query', actual)
                self.assertEqual([i for i, c in enumerate(actual) if c == '\n'],
                                 [i for i, c in enumerate(source) if c == '\n'])
        # A quote inside a regex literal opens no string.
        self.assertIn('req.query', strip_comments_and_strings(
            'let pattern = /a"b/\nlet target = req.query\n', lang='swift'))
        # Swift lexes these slashes as operators (SE-0354): after an operand,
        # before a blank, and an operator reference with no closing slash.
        for source in ('let n = req.query.count / 2\n', 'let r = (a) / b / req.query\n',
                       'let r = a! / req.query.count\n', 'let r = 10 / req.query.count / 2\n',
                       'x /= 2; let y = req.query\n', 'let r = xs.reduce(1, /)\nlet t = req.query\n'):
            with self.subTest(source=source):
                self.assertEqual(strip_comments_and_strings(source, lang='swift'), source)
        with self.assertRaisesRegex(ValueError, 'Unterminated Swift regex.*incomplete'):
            strip_comments_and_strings('let pattern = #/req.query\n', lang='swift')

    def test_swift_real_core_cli_keeps_partial_evidence_and_never_caches_incomplete_analysis(self):
        programs = (
            ('capture', 'func incomplete(req: Request) { let path = req.query["path"] ?? ""; '
             'func captured() -> String { return path }; _ = try String(contentsOfFile: captured()) }\n'),
            # A marker whose comment structure cannot be lexed has no provable
            # ownership: the file is excluded and the scan is partial.
            ('unlexable', '// ubs:ignore[swift.taint.request_open_redirect]\n'
             'func incomplete(req: Request) { _ = try String(contentsOfFile: req.query["path"] ?? "") }\n'
             '/* unterminated\n'),
            ('regex', 'func complete(req: Request) { let pattern = /req.query/; '
             '_ = try String(contentsOfFile: req.query["path"] ?? "") }\n'),
        )
        with tempfile.TemporaryDirectory(prefix='ubs_swift_partial_', dir=REPO_ROOT / 'test-suite/artifacts') as temporary:
            root = Path(temporary)
            supported = root / 'Supported.swift'
            supported.write_text('func route(req: Request) { _ = try String(contentsOfFile: req.query["path"] ?? "") }\n')
            for name, program in programs:
                folder = root / name
                folder.mkdir()
                other = folder / 'Other.swift'
                other.write_text(program)
                files = folder / 'files.nul'
                files.write_bytes(os.fsencode(supported.resolve()) + b'\0' + os.fsencode(other.resolve()) + b'\0')
                for stage, no_cache, skipped in (('cold', False, ''), ('repeat', False, ''),
                                                 ('disabled', True, ''), ('excluded-taint', True, '6'),
                                                 ('excluded-all', True, ','.join(str(category) for category in range(1, 24)))):
                    destination = folder / stage
                    destination.mkdir()
                    sink, summary = destination / 'findings.ndjson', destination / 'summary.json'
                    stats, text = destination / 'cache.json', destination / 'report.txt'
                    command = [sys.executable, '-B', '-m', 'ubs_core.swift_scan', '--files-from', str(files),
                               '--sink', str(sink), '--json-out', str(summary), '--text-out', str(text),
                               '--project-dir', str(root), '--skip', skipped]
                    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', UBS_PROFILE='1',
                                       UBS_CACHE_DIR=str(folder / 'cache'), UBS_CACHE_FILE=str(stats),
                                       UBS_NO_CACHE='1' if no_cache else '0')
                    environment['PYTHONPATH'] = str(HELPERS_DIR) + os.pathsep + environment.get('PYTHONPATH', '')
                    result = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                            text=True, timeout=60)  # ubs:ignore[python.taint.command] - fixed real core CLI with local retained source programs
                    (destination / 'stdout.log').write_text(result.stdout)
                    (destination / 'stderr.log').write_text(result.stderr)
                    (destination / 'invocation.json').write_text(json.dumps({'argv': command, 'cwd': str(root),
                                                                            'status': result.returncode}, indent=2))
                    with self.subTest(program=name, stage=stage):
                        document = json.loads(summary.read_text())
                        records = [json.loads(line) for line in sink.read_text().splitlines() if line]
                        findings = sorted((record['rule'], record['path'], record['line']) for record in records
                                          if record['rule'].startswith('swift.taint.'))
                        expected = [] if skipped else sorted(
                            ('swift.taint.request_path_traversal', str(path.resolve()), 1)
                            for path in ((supported, other) if name == 'regex' else (supported,)))
                        # Skipping taint does not disable the lexical gate: other
                        # categories still need marker ownership. Skipping every
                        # category selects no producer and has no such failure.
                        incomplete = name != 'regex' and (not skipped or (name == 'unlexable' and skipped == '6'))
                        self.assertEqual(findings, expected, records)
                        self.assertEqual(result.returncode, 2 if incomplete else 1 if expected else 0, result.stderr)
                        self.assertEqual(document['status'], 'partial' if incomplete else 'ok', document)
                        self.assertEqual(document.get('module_error'), 'ANALYZER_ERROR' if incomplete else None)
                        # Only a complete analysis enters the cache.
                        self.assertEqual(json.loads(stats.read_text())['hits'],
                                         2 if name == 'regex' and stage == 'repeat' else 0)
                        counter_log = [json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')][-1]
                        self.assertEqual(bool(counter_log['errors']), bool(incomplete), counter_log)
                        if name == 'unlexable' and incomplete:
                            self.assertEqual(len(counter_log['errors']), 1, counter_log)
                            self.assertIn('Swift lexical analysis', counter_log['errors'][0])
                            self.assertIn('Unterminated Swift comment', counter_log['errors'][0])
                        if incomplete:
                            self.assertNotIn('✓ OK', text.read_text())

    def test_swift_write_sink_excludes_declared_value_type_receivers(self):
        from ubs_core.analyzers import taint_swift_traversal as analyzer
        # SwiftPine's API-identity cases (snapshot 0c5659cd) plus receivers of
        # unknown type or class type, which may still be Foundation values.
        # None marks main's incomplete analysis for a request-derived
        # lookalike constructor ("needs field analysis").
        cases = (
            ('shadowed-String-api', 'struct String {}\n', '', '_ = String(contentsOfFile: path)', None, False),
            ('shadowed-Data-api', 'struct Data {}\n', '', '_ = Data(contentsOf: path)', None, False),
            ('unrelated-unknown-write-api', 'struct Recorder {}\n', ', recorder: Recorder', 'recorder.write(to: path)', [], False),
            ('foundation-string-write', '', ', text: String', 'try text.write(to: path, atomically: true, encoding: .utf8)', [4], True),
            ('foundation-data-write', '', ', data: Data', 'try data.write(to: path)', [4], True),
            ('qualified-data-write', 'import Foundation\nstruct Data {}\n', ', data: Foundation.Data', 'try data.write(to: path)', [5], True),
            ('qualified-foundation-string-write', 'import Foundation\nstruct String {}\n', ', text: Foundation.String', 'try text.write(to: path, atomically: true, encoding: .utf8)', [5], True),
            ('qualified-swift-string-write', 'import Foundation\nstruct String {}\n', ', text: Swift.String', 'try text.write(to: path, atomically: true, encoding: .utf8)', [5], True),
            ('annotated-data-write', '', '', 'let data: Data = Data(); try data.write(to: path)', [4], True),
            ('literal-string-write', '', '', 'try "fixed".write(to: path, atomically: true, encoding: .utf8)', [4], True),
            ('shadowed-data-write', 'struct Data {}\n', ', data: Data', 'data.write(to: path)', [], False),
            ('qualified-string-read', 'import Foundation\nstruct String {}\n', '', '_ = try Swift.String(contentsOfFile: path)', [5], False),
            ('valid-String-lookalike', 'struct String { init(contentsOfFile path: Swift.String) {} }\n', '',
             '_ = String(contentsOfFile: path)', None, False),
            ('valid-Data-lookalike', 'import Foundation\nstruct Data { init(contentsOf path: Foundation.URL) {} }\n', '',
             '_ = Data(contentsOf: path)', None, True),
            ('valid-write-lookalike', 'import Foundation\nstruct Recorder { func write(to path: Foundation.URL) {} }\n', ', recorder: Recorder',
             'recorder.write(to: path)', [], True),
            ('unknown-receiver-write', '', '', 'let data = loadPayload(); try data.write(to: path)', [4], True),
            ('final-class-write', 'import Foundation\nfinal class Archive {}\n', ', archive: Archive', 'try archive.write(to: path)', [5], True),
            ('open-class-write', 'import Foundation\nclass Archive {}\n', ', archive: Archive', 'try archive.write(to: path)', [5], True),
            ('enum-write', 'import Foundation\nenum Channel { case primary }\n', ', channel: Channel', 'channel.write(to: path)', [], True),
            ('constructed-struct-write', 'import Foundation\nstruct Recorder {}\n', '', 'let recorder = Recorder(); recorder.write(to: path)', [], True),
        )
        for name, declaration, parameters, sink, expected, destination_is_url in cases:
            source = (declaration or 'import Foundation\n') + 'func sample(req: Request' + parameters + ') throws {\n'
            path = 'URL(fileURLWithPath: req.query["path"] ?? "")' if destination_is_url else 'req.query["path"] ?? ""'
            source += '  let path = ' + path + '\n  ' + sink + '\n}\n'
            with self.subTest(case=name):
                if expected is None:
                    with self.assertRaisesRegex(ValueError, 'needs field analysis; analysis is incomplete'):
                        analyzer.scan_text(Path('F.swift'), source, Path('.'))
                else:
                    self.assertEqual([r[1] for r in analyzer.scan_text(Path('F.swift'), source, Path('.'))], expected)


class CompleteOccurrenceModuleTests(unittest.TestCase):
    """Issue #190: producer locations survive opt-in collection and cache replay."""

    def setUp(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="occurrence-modules-", dir=artifacts))
        self.project = self.root / "project"
        self.project.mkdir()
        self.sequence = 0

    def run(self, result=None):
        print(f"[{self.id()}] RUN", flush=True)
        started = time.monotonic()
        result = super().run(result)
        failed = any(test is self or getattr(test, "test_case", None) is self
                     for test, _ in result.failures + result.errors)
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} "
              f"({time.monotonic() - started:.3f}s)", flush=True)
        return result

    def native(self, language, paths, categories, *, complete):
        self.sequence += 1
        output = self.root / f"run-{self.sequence}"
        output.mkdir()
        files = output / "files.txt"
        files.write_bytes(b"\0".join(os.fsencode(path) for path in paths) + b"\0")
        sink, summary, stats = output / "findings.ndjson", output / "summary.json", output / "cache.json"
        maximum = {"rust": 24, "swift": 23, "elixir": 16}[language]
        command = [sys.executable, "-B", "-m", f"ubs_core.{language}_scan",
                   "--files-from", str(files), "--sink", str(sink), "--json-out", str(summary),
                   "--project-dir", str(self.project), "--skip",
                   ",".join(str(number) for number in range(1, maximum + 1) if number not in categories)]
        if language in ("rust", "swift"):
            command.append("--skip-type-narrowing")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("UBS_", "XDG_"))}
        environment.update(PYTHONPATH=str(HELPERS_DIR), PYTHONDONTWRITEBYTECODE="1",
                           UBS_NO_AUTO_UPDATE="1", UBS_KEEP_TEMP="1", UBS_NO_CACHE="0",
                           UBS_ALL_OCCURRENCES="1" if complete else "0", UBS_PROFILE="1",
                           UBS_CACHE_DIR=str(self.root / "cache"), UBS_CACHE_FILE=str(stats),
                           TMPDIR=str(self.root))
        process = subprocess.run(command, cwd=self.project, env=environment,
                                 capture_output=True, text=True, timeout=60)
        (output / "stdout.log").write_text(process.stdout, encoding="utf-8")
        (output / "stderr.log").write_text(process.stderr, encoding="utf-8")
        context = f"exit={process.returncode}\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        self.assertIn(process.returncode, (0, 1), context)
        try:
            document = json.loads(summary.read_text(encoding="utf-8"))
            records = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
            cache = json.loads(stats.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.fail(f"Invalid native {language} result: {exc}\n{context}")
        self.assertEqual(document["status"], "ok", context)
        for severity in ("critical", "warning", "info"):
            self.assertEqual(document[severity], sum(record.get("count", 1) for record in records
                                                     if record["severity"] == severity),
                             f"{records}\n{context}")
        self.assertEqual(process.returncode, int(document["critical"] > 0), context)
        return sorted(records, key=lambda record: json.dumps(record, sort_keys=True)), document, cache

    def test_rust_marker_sites_preserve_thresholds_and_cache_modes(self):
        first, second = self.project / "first.rs", self.project / "second.rs"
        first.write_text("// TODO: first\n" * 12 + "// TODO FIXME: two counted markers\n"
                         "// TODO: ignored ubs:ignore[rust.code-quality.tech-debt]\n", encoding="utf-8")
        second.write_text("// HACK: second\n" * 9, encoding="utf-8")
        paths = [first, second]
        ordinary, before, _ = self.native("rust", paths, (9,), complete=False)
        self.assertEqual(len(ordinary), 1, ordinary)
        self.assertEqual((ordinary[0]["count"], ordinary[0]["severity"]), (23, "warning"))

        records, after, cache = self.native("rust", paths, (9,), complete=True)
        expected = [(str(first), line) for line in range(1, 13)] + [(str(first), 13)] * 2
        expected += [(str(second), line) for line in range(1, 10)]
        self.assertCountEqual([(record["path"], record["line"]) for record in records], expected)
        self.assertEqual({record["severity"] for record in records}, {"warning"})
        self.assertEqual({record.get("count", 1) for record in records}, {1})
        self.assertEqual([before[key] for key in ("critical", "warning", "info")],
                         [after[key] for key in ("critical", "warning", "info")])
        self.assertEqual(cache["hits"], 0, "ordinary cache entries must not stand for full occurrences")
        warm, _, cache = self.native("rust", paths, (9,), complete=True)
        self.assertEqual(warm, records)
        self.assertEqual(cache["hits"], 2)
        restored, _, cache = self.native("rust", paths, (9,), complete=False)
        self.assertEqual(restored, ordinary)
        self.assertEqual(cache["hits"], 2)

        subset, _, cache = self.native("rust", [first], (9,), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertEqual(len(subset), 14)
        self.assertEqual({record["severity"] for record in subset}, {"info"})
        second.write_text("// HACK: changed selection\n", encoding="utf-8")
        partial, _, cache = self.native("rust", paths, (9,), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertEqual(len(partial), 15)
        self.assertEqual({record["severity"] for record in partial}, {"info"})

    def test_rust_test_stream_keeps_duplicate_counted_sites(self):
        first, second = self.project / "first.rs", self.project / "second.rs"
        first.write_text("#[test] fn first() { todo!(); }\n"
                         "#[test] fn second() { unimplemented!(); }\n", encoding="utf-8")
        second.write_text("#[test] fn third() { todo!(); }\n", encoding="utf-8")
        paths = [first, second]
        ordinary, _, _ = self.native("rust", paths, (11,), complete=False)
        self.assertEqual([(record["rule"], record["count"]) for record in ordinary],
                         [("rust.tests.test-todo", 6)])
        records, _, _ = self.native("rust", paths, (11,), complete=True)
        self.assertCountEqual([(record["path"], record["line"]) for record in records],
                              [(str(first), 1)] + [(str(first), 2)] * 2 + [(str(second), 1)] * 3)
        self.assertTrue(all(record.get("count", 1) == 1 for record in records))
        warm, _, cache = self.native("rust", paths, (11,), complete=True)
        self.assertEqual(cache["hits"], 2)
        self.assertEqual(warm, records)
        subset, _, cache = self.native("rust", [second], (11,), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertEqual([(record["path"], record["line"]) for record in subset], [(str(second), 1)])

    def test_rust_unlocated_counts_remain_aggregates_even_at_one(self):
        source = self.project / "tasks.rs"
        source.write_text("fn launch() {\n  let task = tokio::spawn(async {});\n"
                          "  std::thread::spawn(|| {});\n  std::thread::spawn(|| {});\n}\n", encoding="utf-8")
        ordinary, before, _ = self.native("rust", [source], (3, 19), complete=False)
        self.assertTrue(all(record["path"] == str(source) for record in ordinary))
        records, after, _ = self.native("rust", [source], (3, 19), complete=True)
        expected = {
            "rust.async.spawn-handle-heuristic": ("info", 1),
            "rust.async.tokio-task-no-await": ("warning", 1),
            "rust.resource-lifecycle.thread_join": ("critical", 2),
            "rust.resource-lifecycle.tokio_spawn": ("warning", 1),
        }
        self.assertEqual({record["rule"]: (record["severity"], record["count"])
                          for record in records}, expected)
        for record in records:
            self.assertEqual((record["scope"], record["path"], record["line"]),
                             ("project_aggregate", "", 0))
            self.assertEqual(record["extras"]["aggregate_source"], str(source))
        self.assertEqual([before[key] for key in ("critical", "warning", "info")],
                         [after[key] for key in ("critical", "warning", "info")])
        warm, _, cache = self.native("rust", [source], (3, 19), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertEqual(warm, records)
        peer = self.project / "awaited.rs"
        peer.write_text("async fn finish(task: Handle) { task.await; }\n", encoding="utf-8")
        partial, _, cache = self.native("rust", [source, peer], (3, 19), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertNotIn("rust.async.spawn-handle-heuristic", [record["rule"] for record in partial])
        self.assertEqual([record for record in records if record["rule"] != "rust.async.spawn-handle-heuristic"],
                         partial)

    def test_swift_packaging_sites_recompute_after_source_cache_replay(self):
        package, other = self.project / "Package.swift", self.project / "other.swift"
        source = ("import PackageDescription\n// dependency pins\n"
                  + 'let pin = .package(url: "https://example.invalid/dependency", .branch("main"))\n' * 7
                  + 'let pair = (.revision("first"), .branch("second"))\n'
                  + 'let ignored = .branch("ignored") // ubs:ignore[swift.packaging.branch-pins]\n// end pins\n'
                  + "// target settings\n"
                  + 'let setting = .unsafeFlags(["-Ounchecked"])\n' * 4
                  + 'let ignoredSetting = .unsafeFlags(["-Ounchecked"]) // ubs:ignore[swift.packaging.unsafe-flags]\n')
        package.write_text(source, encoding="utf-8")
        other.write_text("let safe = 1\n", encoding="utf-8")
        paths = [package, other]
        ordinary, before, _ = self.native("swift", paths, (20,), complete=False)
        self.assertCountEqual([(record["rule"], record["line"], record["count"]) for record in ordinary],
                              [("swift.packaging.branch-pins", 0, 8), ("swift.packaging.unsafe-flags", 0, 4)])
        records, after, cache = self.native("swift", paths, (20,), complete=True)
        self.assertEqual(cache["hits"], 2, "derived packaging checks must rerun even on all cache hits")
        expected = [("swift.packaging.branch-pins", line, "info") for line in range(3, 11)]
        expected += [("swift.packaging.unsafe-flags", line, "warning") for line in range(14, 18)]
        self.assertCountEqual([(record["rule"], record["line"], record["severity"]) for record in records], expected)
        self.assertTrue(all(record["path"] == str(package) and record["count"] == 1 for record in records))
        self.assertTrue(all(record["col"] > 0 for record in records))
        self.assertEqual([before[key] for key in ("critical", "warning", "info")],
                         [after[key] for key in ("critical", "warning", "info")])
        warm, _, cache = self.native("swift", paths, (20,), complete=True)
        self.assertEqual(warm, records)
        self.assertEqual(cache["hits"], 2)
        restored, _, _ = self.native("swift", paths, (20,), complete=False)
        self.assertEqual(restored, ordinary)
        package.write_text(source.replace('.branch("main")', '.exact("1.0")', 1), encoding="utf-8")
        partial, _, cache = self.native("swift", paths, (20,), complete=True)
        self.assertEqual(cache["hits"], 1)
        self.assertCountEqual([(record["rule"], record["line"], record["severity"]) for record in partial], expected[1:])

    def test_elixir_net_counts_are_unlocated_after_source_cache_replay(self):
        source, manifest = self.project / "app.ex", self.project / "mix.exs"
        source.write_text(
            ':erlang.binary_to_term(payload, [:safe])\n'
            ':erlang.binary_to_term(payload)\n'
            ':ets.new(:first, [:set, read_concurrency: true])\n'
            ':ets.new(:second, [:set])\n'
            'System.cmd(command, ["x"])\n'
            'System.cmd("ls", [])\n', encoding="utf-8")
        manifest.write_text(
            '[{:pinned, "~> 1.0"},\n'
            ' {:first, path: "first"},\n'
            ' {:second, path: "second"},\n'
            ' {:third, path: "third"},\n'
            ' {:fourth, path: "fourth"}]\n', encoding="utf-8")
        expected = {
            "ex.security.binary-to-term-unsafe": ("critical", 1),
            "ex.security.shell-exec-review": ("info", 1),
            "ex.concurrency.ets-read-concurrency": ("info", 1),
            "ex.mix.unpinned-deps": ("info", 4),
        }
        paths = [source, manifest]
        ordinary, before, _ = self.native("elixir", paths, (4, 7, 14), complete=False)
        for rule, (severity, count) in expected.items():
            found = [record for record in ordinary if record["rule"] == rule]
            self.assertEqual(len(found), count, rule)
            self.assertEqual({record["severity"] for record in found}, {severity}, rule)
        # The incumbent count is valid, but its convenient first site can be
        # safe. Full export must not silently certify that representative.
        binary = next(record for record in ordinary
                      if record["rule"] == "ex.security.binary-to-term-unsafe")
        self.assertEqual(binary["line"], 1)

        records, after, cache = self.native("elixir", paths, (4, 7, 14), complete=True)
        self.assertEqual(cache["hits"], 2, "delivery must qualify ordinary cached representatives too")
        for rule, (severity, count) in expected.items():
            found = [record for record in records if record["rule"] == rule]
            self.assertEqual(len(found), count, rule)
            self.assertEqual({record["severity"] for record in found}, {severity}, rule)
            for record in found:
                self.assertEqual((record["scope"], record["count"], record["path"], record["line"]),
                                 ("project_aggregate", 1, "", 0))
                self.assertIn(record["extras"]["aggregate_source"], {str(path) for path in paths})
        self.assertEqual([before[key] for key in ("critical", "warning", "info")],
                         [after[key] for key in ("critical", "warning", "info")])
        self.assertEqual([record for record in ordinary if record["rule"] not in expected],
                         [record for record in records if record["rule"] not in expected])
        warm, _, cache = self.native("elixir", paths, (4, 7, 14), complete=True)
        self.assertEqual(cache["hits"], 2)
        self.assertEqual(warm, records)
        restored, _, cache = self.native("elixir", paths, (4, 7, 14), complete=False)
        self.assertEqual(cache["hits"], 2)
        self.assertEqual(restored, ordinary)

    def test_rust_enabled_narrowing_failure_is_partial_and_not_cached(self):
        from ubs_core import rust_scan

        source = self.project / "app.rs"
        source.write_text("fn main() {}\n", encoding="utf-8")
        files = self.root / "files.txt"
        files.write_bytes(os.fsencode(source) + b"\0")

        def invoke(label, *, complete, fail=True, skipped=False, category_skipped=False):
            output = self.root / label
            output.mkdir()
            summary, stats = output / "summary.json", output / "cache.json"
            categories = range(1 if category_skipped else 2, 25)
            arguments = ["--files-from", str(files), "--sink", str(output / "findings.ndjson"),
                         "--json-out", str(summary), "--project-dir", str(self.project),
                         "--quiet", "--skip", ",".join(map(str, categories))]
            if skipped:
                arguments.append("--skip-type-narrowing")
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("UBS_", "XDG_"))}
            environment.update(UBS_ALL_OCCURRENCES="1" if complete else "0", UBS_NO_CACHE="0",
                               UBS_KEEP_TEMP="1", UBS_CACHE_DIR=str(self.root / "cache"),
                               UBS_CACHE_FILE=str(stats), TMPDIR=str(self.root))

            def narrowing(_scan, skip_type_narrowing):
                if fail and not skip_type_narrowing:
                    raise RuntimeError("injected enabled narrowing failure")
                return []

            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(rust_scan, "run_narrowing", side_effect=narrowing), \
                    patch.object(rust_scan.Scan, "load_ast_matches", return_value=None), \
                    redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                exit_code = rust_scan.main(arguments)
            return exit_code, json.loads(summary.read_text()), json.loads(stats.read_text())

        exit_code, ordinary, _ = invoke("ordinary", complete=False)
        self.assertEqual((exit_code, ordinary["status"]), (0, "ok"))
        exit_code, failed, cache = invoke("failed", complete=True)
        self.assertEqual((exit_code, failed["status"]), (2, "partial"))
        self.assertEqual(failed["module_error"], "ANALYZER_ERROR")
        self.assertIn("injected enabled narrowing failure", failed["message"])
        self.assertEqual(cache["hits"], 0)
        for label, options in (("explicit-skip", {"skipped": True}),
                               ("category-skip", {"category_skipped": True})):
            exit_code, document, _ = invoke(label, complete=True, **options)
            self.assertEqual((exit_code, document["status"]), (0, "ok"))
        exit_code, recovered, cache = invoke("recovered", complete=True, fail=False)
        self.assertEqual((exit_code, recovered["status"]), (0, "ok"))
        self.assertEqual(cache["hits"], 0, "an enabled failure must not become a completed cached answer")
        exit_code, warm, cache = invoke("warm", complete=True, fail=False)
        self.assertEqual((exit_code, warm["status"], cache["hits"]), (0, "ok", 1))


if __name__ == "__main__":
    unittest.main()
