#!/usr/bin/env python3
"""Unit tests for ubs_core stdlib helper library (bead A2)."""
from __future__ import annotations

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
                         [('python.taint.eval', str(source), 5, 5)], context)
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
                        self.assertCountEqual(actual, [(rule, path, line, col, "error")
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

    def test_capture_limit_keeps_complete_records_and_reports_truncation(self) -> None:
        valid = self.payload(self.diagnostic())
        self.executable(valid + b"x" * 2048)
        errors = []
        with patch.object(self.tools, "OUTPUT_LIMIT", len(valid) + 8):
            records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual(len(records), 1)
        self.assertTrue(any("output exceeds" in e for e in errors))

    def test_invalid_utf8_is_incomplete_but_valid_rows_remain(self) -> None:
        self.executable(self.payload(self.diagnostic()) + b"\xff\n")
        errors = []
        records = list(self.tools.scan_ast_config(self.config, [self.source], errors))
        self.assertEqual(len(records), 1)
        self.assertTrue(any("UTF-8" in e for e in errors))

    def test_later_batches_run_after_an_earlier_failure(self) -> None:
        outputs = [self.tools.ToolOutput(2, "null\n", "failed first batch"),
                   self.tools.ToolOutput(1, self.payload(self.diagnostic()).decode(), "")]
        errors = []
        with patch.object(self.tools, "run_command", side_effect=outputs) as run:
            records = list(self.tools.scan_ast_config(
                self.config, [self.source, self.source], errors, batch_size=1,
            ))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(len(records), 1)
        self.assertTrue(errors)
        self.assertIn("--", run.call_args.args[1])
        self.assertTrue(run.call_args.kwargs["strict_utf8"])

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


if __name__ == "__main__":
    unittest.main()
