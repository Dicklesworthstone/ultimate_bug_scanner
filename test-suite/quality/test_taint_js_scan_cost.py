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


@unittest.skipUnless(sys.platform.startswith("linux"), "GNU time reports peak RSS in KiB")
class ProjectMemoryTests(unittest.TestCase):
    def test_400k_line_scan_preserves_findings_below_200_mib(self) -> None:
        case = "c6-source-memory"
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
                    body = ["export function accumulate(value: number) {",
                            "  let result = value;"]
                    body.extend(["  result = result + 1;"] * 992)
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
