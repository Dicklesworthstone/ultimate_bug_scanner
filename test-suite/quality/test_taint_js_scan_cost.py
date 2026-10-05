#!/usr/bin/env python3
"""JS taint cost stays linear in long callback bodies (GH #156).

The taint engine hands each expression, with its calls blanked, to
assignment_sources; for `describe(..., () => { ... })` that is the whole
test body as one run of spaces. ROUTE_PARAM_OBJECT's `^\\s*\\(?\\s*` split
such a run N ways on every failed match, so single Jest files hit the 300 s
module timeout. Measured here: the 30k-blank match takes ~2 ms (old: ~20 s,
bound 1 s) and the Jest-shaped file 0.5 s (old: 71.5 s, bound 30 s).
"""
from __future__ import annotations

import sys
import json
import os
import subprocess
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import taint_js  # noqa: E402
from ubs_core.registry import RunContext  # noqa: E402


class RouteParamObjectTests(unittest.TestCase):
    def test_accepts_the_same_forms(self) -> None:
        for expr in ("params", "  params  ", "(params)", "( params )", "await params",
                     "(await params)", "context.params", "(await context.params)",
                     "PARAMS", "(params", "params)"):
            with self.subTest(expr=expr):
                match = taint_js.ROUTE_PARAM_OBJECT.match(expr)
                self.assertIsNotNone(match)
                self.assertIn(match.group(1).lower(), {"params", "context.params"})
        for expr in ("params.id", "myparams", "params x", "await", "()", ""):
            with self.subTest(expr=expr):
                self.assertIsNone(taint_js.ROUTE_PARAM_OBJECT.match(expr))

    def test_failed_match_is_linear_in_whitespace(self) -> None:
        # ~2 ms linear; the quadratic form took ~9 s at 20k, so a regression
        # fails here within seconds instead of hanging the suite.
        blank = " " * 30_000
        for label, expr in (("blank", blank), ("trailing", "params" + blank + "x"),
                            ("paren", "(" + blank + "x")):
            with self.subTest(case=label):
                started = time.perf_counter()
                self.assertIsNone(taint_js.ROUTE_PARAM_OBJECT.match(expr))
                self.assertLess(time.perf_counter() - started, 1.0)


class ComponentSpanTests(unittest.TestCase):
    def run_case(self, name, check) -> None:
        started = time.perf_counter()
        print(f"[{name}] RUN", flush=True)
        try:
            check()
        except Exception:
            print(f"[{name}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            raise
        print(f"[{name}] PASS ({time.perf_counter() - started:.2f}s)", flush=True)

    def test_masked_lists_keep_component_coordinates(self) -> None:
        self.run_case("c6-component-coordinates", self.check_masked_lists)

    def check_masked_lists(self) -> None:
        code = taint_js._ComponentCode("LEFT{a,(b,c)}RIGHT", "{x,[y,z]}", 4)
        expected = {4: 12, 12: 4, 7: 11, 11: 7}
        self.assertEqual(taint_js._pairs(code, 4, 13), expected)
        self.assertEqual(taint_js._pairs(code), expected)
        chunks = list(taint_js._chunks(code, 5, 12))
        self.assertEqual(chunks, [(5, 6), (7, 12)])
        self.assertEqual([code[left:right] for left, right in chunks], ["x", "[y,z]"])

    def test_assignment_operators_across_span_boundaries_stay_intact(self) -> None:
        self.run_case("c6-component-operator-boundaries", self.check_assignment_operators)

    def check_assignment_operators(self) -> None:
        for text, start, end in (("!=value", 1, 2), ("x=>value", 1, 2),
                                 ("x==value", 1, 2), ("x<=value", 2, 3)):
            with self.subTest(text=text):
                code = taint_js._ComponentCode(text, text, 0)
                self.assertEqual(list(taint_js._chunks(code, start, end, '=')), [(start, end)])
        code = taint_js._ComponentCode("xx a=b yy", "a=b", 3)
        self.assertEqual(list(taint_js._chunks(code, 3, 6, '=')), [(3, 4), (5, 6)])

    def test_empty_and_reversed_spans_do_not_parse_incomplete_bindings(self) -> None:
        self.run_case("c6-component-empty-spans", self.check_empty_spans)

    def check_empty_spans(self) -> None:
        code = taint_js._ComponentCode("prefix {x,y} suffix", "{a,b}", 7)
        for start, end in ((7, 7), (9, 7), (1, -1)):
            with self.subTest(start=start, end=end):
                self.assertEqual(taint_js._pairs(code, start, end), {})
                self.assertEqual(list(taint_js._chunks(code, start, end)), [(start, end)])
        self.assertEqual(taint_js._binding_paths("{x,y"), [])


class JestShapedFileCostTests(unittest.TestCase):
    def test_long_describe_body_scans_in_bounded_time(self) -> None:
        lines = ["describe('orders', () => {"]
        for index in range(120):
            lines += [
                f"  it('case {index}', async () => {{",
                f"    const pattern = /^\\s*private async task{index}\\b/;",
                f"    const rows = await db.query('SELECT * FROM t WHERE id = $1', [{index}]);",
                "    expect(pattern.test(rows[0].src)).toBe(true);",
                "  });",
            ]
        lines.append("});")
        with tempfile.TemporaryDirectory(prefix="taint-js-cost-") as tmp:
            path = Path(tmp) / "orders.test.ts"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            started = time.perf_counter()
            findings = list(taint_js.run(RunContext(lang="javascript", files=[path])))
            elapsed = time.perf_counter() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 30.0, f"taint_js took {elapsed:.1f}s on {len(lines)} lines")


class RuleStateTests(unittest.TestCase):
    def test_heap_escapes_keep_borrowed_objects_cell_writes_and_exceptions(self) -> None:
        case = "c6-heap-escapes"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        try:
            self.check_heap_escapes()
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s)", flush=True)

    def check_heap_escapes(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "c6-heap-escapes"
        artifacts.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="corpus-", dir=artifacts) as tmp:
            root = Path(tmp)
            helper = root / "lib.ts"
            helper.write_text(
                "export let delivered;\n"
                "export function mutate(box, value) { const junk = {value: 'discard'}; "
                "box.value = value; box = null; return {status: 'ok', junk}; }\n"
                "export function publish(value) { const junk = {value: 'discard'}; "
                "delivered = {value}; delivered.loop = delivered; return 'fixed'; }\n"
                "export function reject(box, value) { const junk = {value: 'discard'}; "
                "box.value = value; throw {value}; }\n",
                encoding="utf-8",
            )
            main = root / "app.ts"
            main.write_text(
                "import {mutate, publish, reject, delivered} from './lib';\n"
                "const box = {value: 'safe'};\n"
                "mutate(box, req.query.value);\n"
                "res.send(box.value);\n"
                "mutate(box, 'safe');\n"
                "res.send(box.value);\n"
                "publish(req.query.value);\n"
                "res.send(delivered);\n"
                "try { reject(box, req.query.value); } catch (error) { res.send(error.value); }\n"
                "res.send(box.value);\n"
                "try { reject(box, 'safe'); } catch (error) { res.send(error.value); }\n"
                "res.send(box.value);\n",
                encoding="utf-8",
            )
            expected = Counter({("app.ts", "javascript.taint.xss", line): 1
                                for line in (4, 8, 9, 10)})
            for selected in ([main, helper], [helper, main]):
                with self.subTest(order=[path.name for path in selected]):
                    findings = list(taint_js.run(RunContext(lang="javascript", files=selected)))
                    actual = Counter((Path(item["path"]).name, item["rule"], item["line"])
                                     for item in findings)
                    self.assertEqual(actual, expected, findings)
                    for item in findings:
                        self.assertEqual(item["severity"], "critical", item)
                        self.assertIn("req.query.value", item["message"], item)

    def test_block_closures_keep_cells_and_call_time_heap_values(self) -> None:
        case = "c6-block-closures"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        try:
            self.check_block_closures()
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s)", flush=True)

    def check_block_closures(self) -> None:
        cases = {
            "escape-tainted": ("const box = {value: req.query.value};", "", 1),
            "escape-clean": ("const box = {value: 'safe'};", "", 0),
            "write-before-call": ("const box = {value: 'safe'};", "box.value = req.query.value;", 1),
            "clean-before-call": ("const box = {value: req.query.value};", "box.value = 'safe';", 0),
        }
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "c6-block-closures"
        artifacts.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="corpus-", dir=artifacts) as tmp:
            target = Path(tmp) / "closures.ts"
            for name, (binding, update, count) in cases.items():
                with self.subTest(case=name):
                    target.write_text(
                        "let render;\n"
                        "{\n"
                        f"  {binding}\n"
                        "  render = () => res.send(box.value);\n"
                        f"  {update}\n"
                        "}\n"
                        "render();\n",
                        encoding="utf-8",
                    )
                    findings = list(taint_js.run(RunContext(lang="javascript", files=[target])))
                    self.assertEqual(len(findings), count, findings)
                    for item in findings:
                        self.assertEqual((item["rule"], item["line"], item["severity"]),
                                         ("javascript.taint.xss", 4, "critical"), item)
                        self.assertIn("req.query.value", item["message"], item)

    def test_imported_heap_source_and_sanitizer_keep_rule_specific_findings(self) -> None:
        case = "c6-rule-state"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        try:
            self.check_rule_specific_findings()
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s)", flush=True)

    def check_rule_specific_findings(self) -> None:
        sources = {
            "lib.ts": (
                "export function read(req) { return {input: req.query.value}; }\n"
                "export function cleanHtml(value) { return DOMPurify.sanitize(value); }\n"
            ),
            "app.ts": (
                "import {read, cleanHtml} from './lib';\n"
                "import {exec as launch} from 'node:child_process';\n"
                "const box = read(req);\n"
                "res.send(box.input);\n"
                "eval(box.input);\n"
                "launch(box.input);\n"
                "db.query(box.input);\n"
                "res.send(cleanHtml(box.input));\n"
                "eval(cleanHtml(box.input));\n"
                "db.query('SELECT 1');\n"
                "res.send('constant');\n"
            ),
            "quiet.ts": (
                "export function collect(req) { return {input: req.query.value}; }\n"
                "const example = 'eval(req.query.value)';\n"
                "// res.send(req.query.value);\n"
            ),
        }
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "c6-rule-state"
        artifacts.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="taint-js-rules-", dir=artifacts) as tmp:
            root = Path(tmp)
            paths = []
            for name, source in sources.items():
                path = root / name
                path.write_text(source, encoding="utf-8")
                paths.append(path)
            expected = Counter({("app.ts", "javascript.taint.xss", 4): 1,
                                ("app.ts", "javascript.taint.eval", 5): 1,
                                ("app.ts", "javascript.taint.command", 6): 1,
                                ("app.ts", "javascript.taint.sql", 7): 1,
                                ("app.ts", "javascript.taint.eval", 9): 1})
            for selected in (paths, list(reversed(paths))):
                with self.subTest(order=[path.name for path in selected]):
                    findings = list(taint_js.run(RunContext(lang="javascript", files=selected)))
                    actual = Counter((Path(item["path"]).name, item["rule"], item["line"])
                                     for item in findings)
                    self.assertEqual(actual, expected, findings)
                    for item in findings:
                        self.assertEqual(item["severity"], "critical", item)
                        self.assertIn("req.query.value ->", item["message"], item)
                        if item["line"] == 9:
                            self.assertIn("lib.ts:cleanHtml() -> eval", item["message"], item)
            self.assertEqual(list(taint_js.run(RunContext(lang="javascript", files=[paths[-1]]))), [])


@unittest.skipUnless(sys.platform.startswith("linux"), "GNU time reports peak RSS in KiB")
class SinkFreeComponentCostTests(unittest.TestCase):
    def test_large_sink_free_import_component_stays_bounded(self) -> None:
        case = "c6-sink-free-component"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / case
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix="corpus-", dir=artifacts) as tmp:
                root = Path(tmp)
                for index in range(100):
                    body = [f"import {{next as importedNext}} from './part_{(index + 1) % 100:04d}';",
                            f"const payload = req.query.field{index};",
                            "export function next(value) {",
                            "  return {value, payload};", "}"]
                    for callback in range(199):
                        body += [f"export function visit{callback}(value) {{",
                                 "  const box = importedNext(value);", "  box.value = payload;",
                                 "  return box;", "}"]
                    self.assertEqual(len(body), 1000)
                    (root / f"part_{index:04d}.ts").write_text("\n".join(body) + "\n")
                script = (
                    "import json, sys; from pathlib import Path; "
                    "from ubs_core.analyzers import taint_js; "
                    "from ubs_core.registry import RunContext; "
                    "files = sorted(Path(sys.argv[1]).glob('*.ts')); "
                    "findings = list(taint_js.run(RunContext(lang='javascript', files=files))); "
                    "print(json.dumps({'selected': len(files), 'findings': findings}))"
                )
                env = dict(os.environ, PYTHONPATH=str(HELPERS_DIR))
                peak = artifacts / "peak-rss-kib.txt"
                result = subprocess.run(
                    ["/usr/bin/time", "-f", "%M", "-o", str(peak), sys.executable,
                     "-c", script, str(root)],
                    cwd=root, env=env, capture_output=True, text=True, timeout=60,
                )
                (artifacts / "stdout.log").write_text(result.stdout)
                (artifacts / "stderr.log").write_text(result.stderr)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"selected": 100, "findings": []})
                rss_kib = int(peak.read_text())
                self.assertLess(rss_kib, 200 * 1024,
                                f"sink-free component peaked at {rss_kib / 1024:.1f} MiB")
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            for name in ("stdout.log", "stderr.log"):
                path = artifacts / name
                if path.exists():
                    print(f"{name}:\n{path.read_text()}", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s, {rss_kib / 1024:.1f} MiB)", flush=True)


@unittest.skipUnless(sys.platform.startswith("linux"), "GNU time reports peak RSS in KiB")
class ProjectMemoryTests(unittest.TestCase):
    def test_400k_line_scan_preserves_findings_below_200_mib(self) -> None:
        self.check_project(connected=False)

    def test_400k_connected_scan_preserves_findings_below_200_mib(self) -> None:
        self.check_project(connected=True)

    def check_project(self, *, connected: bool) -> None:
        case = "c6-connected-source-memory" if connected else "c6-source-memory"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / case
        artifacts.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix="corpus-", dir=artifacts) as tmp:
                root = Path(tmp)
                sources = root / "sources"
                sources.mkdir()
                for index in range(400):
                    body = ([f"import './part_{max(0, index - 1):04d}';"]
                            if connected else [])
                    body += ["export function accumulate(value: number) {",
                             "  let result = value;"]
                    body.extend(["  result = result + 1;"] * (991 if connected else 992))
                    body += ["  return result;", "}"]
                    if index in (0, 399):
                        body += ["export function handle(req, res) {",
                                 "  const html = req.query.html;",
                                 "  res.send(html);", "}"]
                    else:
                        body += ["export function handle(req, res) {",
                                 "  const html = 'constant response';",
                                 "  res.send(html);", "}"]
                    self.assertEqual(len(body), 1000)
                    (sources / f"part_{index:04d}.ts").write_text(
                        "\n".join(body) + "\n", encoding="utf-8")
                env = os.environ.copy()
                env.update(UBS_NO_CACHE="1", UBS_NO_AUTO_UPDATE="1", UBS_PROFILE="1")
                peak = artifacts / "peak-rss-kib.txt"
                with (artifacts / "result.json").open("w", encoding="utf-8") as stdout, \
                        (artifacts / "stderr.log").open("w", encoding="utf-8") as stderr:
                    result = subprocess.run(
                        ["/usr/bin/time", "-f", "%M", "-o", str(peak),
                         str(REPO_ROOT / "ubs"), str(sources), "--only=js", "--ci", "--format=json"],
                        cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=300,
                    )
                diagnostic = (artifacts / "stderr.log").read_text(encoding="utf-8")
                doc = json.loads((artifacts / "result.json").read_text(encoding="utf-8"))
                self.assertEqual(result.returncode, 1, diagnostic)
                self.assertEqual(doc["status"], "ok", diagnostic)
                self.assertEqual(doc["failed_modules"], [], diagnostic)
                tainted = [(Path(f["file"]).name, f["line"]) for f in doc["findings"]
                           if f["rule_id"] == "javascript.taint.xss"]
                self.assertEqual(sorted(tainted), [("part_0000.ts", 999), ("part_0399.ts", 999)], diagnostic)
                self.assertEqual(doc["totals"]["critical"], 2, diagnostic)
                self.assertEqual(doc["totals"]["warning"], 0, diagnostic)
                self.assertEqual(doc["totals"]["files"], 400, diagnostic)
                self.assertEqual(doc["profile"]["cache_hits"], 0, diagnostic)
                rss_kib = int(peak.read_text(encoding="utf-8").splitlines()[-1])
                self.assertLess(rss_kib, 200 * 1024,
                                f"400K-line scan peaked at {rss_kib / 1024:.1f} MiB\n{diagnostic}")
        except Exception:
            print(f"[{case}] FAIL ({time.perf_counter() - started:.2f}s)", flush=True)
            for name in ("result.json", "stderr.log"):
                artifact = artifacts / name
                if artifact.exists():
                    print(f"{name}:\n{artifact.read_text(encoding='utf-8')}", flush=True)
            raise
        print(f"[{case}] PASS ({time.perf_counter() - started:.2f}s, {rss_kib / 1024:.1f} MiB)", flush=True)


if __name__ == "__main__":
    unittest.main()
