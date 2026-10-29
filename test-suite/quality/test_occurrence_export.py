#!/usr/bin/env python3
"""Public occurrence export must retain real sites and account for omissions.

These tests run the checked-out scanner against generated source projects.
Fixtures and diagnostic evidence remain under test-suite/artifacts; the scanner
uses its ordinary cleanup for internal scratch, so many scans do not retain a
copy of the verified runtime for each invocation.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "test-suite" / "artifacts"
SEVERITIES = ("critical", "warning", "info")
PARAM_RULE = "py.functions.high-param-count"


def parameter_functions(count: int, prefix: str = "function") -> str:
    return "".join(
        f"def {prefix}_{index}(one, two, three, four, five, six, seven):\n"
        "    return one\n"
        for index in range(count)
    )


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("bash", "jq", "rg")),
    "public UBS requires Bash, jq and ripgrep",
)
class OccurrenceExportTests(unittest.TestCase):
    def setUp(self) -> None:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="occurrence-export-", dir=ARTIFACTS))
        self.project = self.root / "project"
        self.project.mkdir()
        scratch = self.root / "scratch"
        scratch.mkdir()
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("UBS_", "XDG_"))
        }
        self.env.update(
            NO_COLOR="1", UBS_NO_AUTO_UPDATE="1", UBS_KEEP_TEMP="0",
            UBS_PROFILE="0", ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1",
            TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_STATE_HOME=str(self.root / "state"),
        )
        self.started = time.monotonic()
        print(f"[{self.id()}] RUN evidence={self.root}", flush=True)

    def tearDown(self) -> None:
        print(f"[{self.id()}] END ({time.monotonic() - self.started:.3f}s)", flush=True)

    def source(self, name: str, text: str) -> Path:
        path = self.project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def decode(self, text: str, description: str):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            self.fail(f"{description}: invalid JSON: {exc}\n{text[:2000]}")

    def stream(self, text: str) -> list[dict]:
        # JSONL delimiters are LF, not the Unicode separators allowed in code.
        return [self.decode(line, "occurrence JSONL") for line in text.split("\n") if line]

    def scan(self, label: str, paths=(), *, languages="python", fmt="jsonl",
             occurrences=True, extra=(), cache=False, env=None):
        command = [
            "bash", str(REPO_ROOT / "ubs"), "--ci", "--no-config",
            "--ignore-file=/dev/null", "--module-dir=" + str(REPO_ROOT / "modules"),
            "--only=" + languages, "--format=" + fmt,
        ]
        if not cache:
            command.append("--no-cache")
        if occurrences:
            command.append("--all-occurrences")
        command.extend(extra)
        command.extend(str(path) for path in paths)
        result = subprocess.run(
            command, cwd=self.project, env={**self.env, **(env or {})},
            text=True, capture_output=True, timeout=120, check=False,
        )
        (self.root / (label + ".stdout")).write_text(result.stdout, encoding="utf-8")
        (self.root / (label + ".stderr")).write_text(result.stderr, encoding="utf-8")
        (self.root / (label + ".exit")).write_text(str(result.returncode) + "\n", encoding="utf-8")
        return result

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=" + str(self.root / "empty-hooks"), *arguments],
            cwd=self.project, env=self.env, capture_output=True, text=True,
            timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    @staticmethod
    def findings(rows, rule=None):
        return [
            row for row in rows
            if row.get("type") == "finding" and (rule is None or row["rule_id"] == rule)
        ]

    def assert_locations(self, rows, rule, expected, severity):
        findings = self.findings(rows, rule)
        actual = {(row["file"], row["line"]) for row in findings}
        self.assertEqual(len(findings), len(expected), findings)
        self.assertEqual(actual, expected)
        self.assertEqual({row["severity"] for row in findings}, {severity})
        for row in findings:
            self.assertIs(row["code_available"], True, row)
            self.assertIs(row["code_truncated"], False, row)
            source_lines = Path(row["file"]).read_text(encoding="utf-8").split("\n")
            self.assertEqual(row["code"], source_lines[row["line"] - 1], row)

    def assert_accounting(self, rows, *, complete=True, analysis_complete=True,
                          limit=100000):
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["type"], "totals", rows[-1])
        self.assertFalse(any(row["type"] == "error" for row in rows), rows)
        findings = self.findings(rows)
        ids = [row["occurrence_id"] for row in findings]
        self.assertEqual(len(ids), len(set(ids)), "different occurrences share an identity")
        for row in findings:
            self.assertEqual(row["schema"], "ubs.occurrence/1", row)
            self.assertRegex(row["occurrence_id"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(row["count"], 1, row)
            self.assertGreater(row["line"], 0, row)
            self.assertGreater(row["col"], 0, row)
            self.assertTrue(row["file"], row)
            self.assertIn(row["severity"], SEVERITIES)
            self.assertIsInstance(row["code"], str, row)
            self.assertIsInstance(row["code_available"], bool, row)
            self.assertIsInstance(row["code_truncated"], bool, row)

        summaries = [row for row in rows if row["type"] in ("scanner", "totals")]
        for summary in summaries:
            selected = [
                row for row in findings
                if summary["type"] == "totals" or row["language"] == summary["language"]
            ]
            metadata = summary["occurrence_export"]
            self.assertEqual(metadata["schema"], "ubs.occurrence-export/1", metadata)
            self.assertEqual(metadata["limit"], limit, metadata)
            self.assertEqual(metadata["reported"], sum(summary[level] for level in SEVERITIES))
            self.assertEqual(metadata["emitted"], len(selected), metadata)
            observed = Counter(row["severity"] for row in selected)
            expected_omitted = 0
            for severity in SEVERITIES:
                counts = metadata["counts"][severity]
                self.assertEqual(counts["reported"], summary[severity], metadata)
                self.assertEqual(counts["emitted"], observed[severity], metadata)
                omitted = max(summary[severity], counts["accounted"]) - observed[severity]
                self.assertEqual(counts["omitted"], omitted, metadata)
                expected_omitted += omitted
            self.assertEqual(metadata["omitted"], expected_omitted)
            self.assertEqual(
                metadata["accounted"],
                sum(metadata["counts"][level]["accounted"] for level in SEVERITIES),
            )
            if complete:
                self.assertIs(metadata["complete"], True, metadata)
                self.assertIs(metadata["locations_complete"], True, metadata)
                self.assertIs(metadata["analysis_complete"], True, metadata)
                self.assertEqual(metadata["reported"], metadata["accounted"], metadata)
                self.assertEqual(metadata["reported"], metadata["emitted"], metadata)
                for field in ("omitted", "unlocated", "code_unavailable", "code_truncated"):
                    self.assertEqual(metadata[field], 0, metadata)
                self.assertIs(metadata["truncated"], False, metadata)
                self.assertEqual(metadata["reasons"], [], metadata)
        total = rows[-1]["occurrence_export"]
        self.assertIs(total["complete"], complete, total)
        self.assertIs(total["analysis_complete"], analysis_complete, total)
        if not complete:
            self.assertTrue(total["reasons"], total)

        grouped = Counter((row["language"], row["rule_id"], row["severity"]) for row in findings)
        rule_rows = [row for row in rows if row["type"] == "rule_summary"]
        rule_keys = [(row["language"], row["rule_id"], row["severity"]) for row in rule_rows]
        self.assertEqual(len(rule_keys), len(set(rule_keys)), rule_rows)
        for row, key in zip(rule_rows, rule_keys):
            self.assertEqual(row["emitted"], grouped[key], row)
            self.assertEqual(row["reported"], row["emitted"] + row["omitted"], row)
        self.assertTrue(set(grouped) <= set(rule_keys), (grouped, rule_rows))
        if complete:
            self.assertEqual(sum(row["reported"] for row in rule_rows), total["reported"])
        return total

    def test_python_multifile_export_preserves_counts_and_three_sample_default(self):
        first = self.source("first file.py", parameter_functions(4, "first"))
        second = self.source("雪.py", parameter_functions(5, "second"))
        ordinary = self.scan("ordinary", [first, second], fmt="json", occurrences=False)
        exported = self.scan("complete", [first, second])
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(exported.returncode, ordinary.returncode, exported.stderr)
        document = self.decode(ordinary.stdout, "ordinary summary")
        preview = next(row for row in document["scanners"][0]["findings"]
                       if row["rule_id"] == PARAM_RULE)
        self.assertEqual((preview["count"], len(preview["samples"]), preview["severity"]),
                         (9, 3, "warning"))
        self.assertNotIn("occurrence_export", document)
        rows = self.stream(exported.stdout)
        self.assert_accounting(rows)
        self.assertEqual({level: rows[-1][level] for level in SEVERITIES},
                         {level: document["totals"][level] for level in SEVERITIES})
        expected = {(str(first), 2 * index + 1) for index in range(4)}
        expected |= {(str(second), 2 * index + 1) for index in range(5)}
        self.assert_locations(rows, PARAM_RULE, expected, "warning")

    def test_mixed_languages_reconcile_every_module_and_file(self):
        sources = []
        expected = {}
        cases = (
            ("ruby", "rb", "ruby.security.eval-family", "critical",
             lambda count: "  eval(user_input)\n" * count),
            ("swift", "swift", "swift.optionals.try-bang", "warning",
             lambda count: "".join(f"let value{index} = try! parse()\n" for index in range(count))),
        )
        for language, suffix, rule, severity, contents in cases:
            sites = set()
            for name, count in (("first", 4), ("second", 5)):
                source = self.source(f"{language}/{name}.{suffix}", contents(count))
                sources.append(source)
                sites.update((str(source), index + 1) for index in range(count))
            expected[rule] = (sites, severity)
        ordinary = self.scan("mixed-ordinary", sources, languages="ruby,swift",
                             fmt="json", occurrences=False)
        exported = self.scan("mixed-complete", sources, languages="ruby,swift")
        self.assertEqual(ordinary.returncode, 1, ordinary.stderr)
        self.assertEqual(exported.returncode, ordinary.returncode, exported.stderr)
        rows = self.stream(exported.stdout)
        self.assert_accounting(rows)
        self.assertEqual({row["language"] for row in rows if row["type"] == "scanner"},
                         {"ruby", "swift"})
        before = self.decode(ordinary.stdout, "mixed ordinary summary")
        for level in SEVERITIES:
            self.assertEqual(rows[-1][level], before["totals"][level])
        for rule, (sites, severity) in expected.items():
            self.assert_locations(rows, rule, sites, severity)

    def test_limit_bounds_output_and_reconciles_omissions_without_changing_exit(self):
        first = self.source("a.py", parameter_functions(4))
        second = self.source("b.py", parameter_functions(5))
        complete = self.scan("limit-control", [first, second], extra=("--fail-on-warning",))
        limited = self.scan("limit-three", [first, second],
                            extra=("--max-occurrences=3", "--fail-on-warning"))
        self.assertEqual(complete.returncode, 1, complete.stderr)
        self.assertEqual(limited.returncode, complete.returncode, limited.stderr)
        full_rows, rows = self.stream(complete.stdout), self.stream(limited.stdout)
        self.assert_accounting(full_rows)
        metadata = self.assert_accounting(rows, complete=False, limit=3)
        self.assertEqual(len(self.findings(rows)), 3)
        self.assertIs(metadata["truncated"], True, metadata)
        self.assertIs(metadata["locations_complete"], False, metadata)
        self.assertEqual(metadata["unlocated"], 0, metadata)
        self.assertEqual(metadata["reported"], full_rows[-1]["occurrence_export"]["reported"])
        self.assertEqual(metadata["omitted"], metadata["reported"] - 3)
        self.assertEqual(rows[-1]["status"], "ok", rows[-1])
        full_ids = {row["occurrence_id"] for row in self.findings(full_rows)}
        self.assertTrue({row["occurrence_id"] for row in self.findings(rows)} <= full_ids)

    def test_ids_survive_cache_warmth_file_order_and_repeated_source_lines(self):
        first = self.source("first.py", "value = eval(payload)\n" * 5)
        second = self.source("second.py", "value = eval(payload)\n" * 4)
        identities = []
        for index, (paths, cache) in enumerate((
            ([first, second], True), ([second, first], True), ([first, second], False),
        )):
            result = self.scan(f"identity-{index}", paths, cache=cache)
            self.assertEqual(result.returncode, 1, result.stderr)
            rows = self.stream(result.stdout)
            self.assert_accounting(rows)
            identities.append(sorted(
                (row["language"], row["rule_id"], row["file"], row["line"],
                 row["col"], row["occurrence_id"], row["code"])
                for row in self.findings(rows)
            ))
        self.assertEqual(identities[0], identities[1])
        self.assertEqual(identities[0], identities[2])

    def test_thresholds_and_python_raw_counts_remain_distinct(self):
        source = self.source("threshold.py", "")
        for count in (1, 3, 4):
            with self.subTest(count=count):
                source.write_text(parameter_functions(count), encoding="utf-8")
                sidecar = self.root / f"threshold-{count}.json"
                result = self.scan(f"threshold-{count}", [source],
                                   extra=("--python-pattern-counts=" + str(sidecar),))
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = self.stream(result.stdout)
                self.assert_accounting(rows)
                self.assertEqual(len(self.findings(rows, PARAM_RULE)), count if count > 3 else 0)
                raw = self.decode(sidecar.read_text(encoding="utf-8"), "Python pattern counts")
                self.assertIs(raw["complete"], True, raw)
                rule = next(row for row in raw["rules"] if row["rule_id"] == PARAM_RULE)
                self.assertEqual(rule["count"], count)
                self.assertEqual(rule["reported_severity"], "warning" if count > 3 else None)
                self.assertEqual(
                    [row["count"] for row in raw["counts"] if row["rule_id"] == PARAM_RULE],
                    [count],
                )

    def test_partial_python_analysis_keeps_known_sites_and_never_claims_completeness(self):
        good = self.source("good.py", parameter_functions(5))
        broken = self.source("broken.py", "def broken(:\n")
        result = self.scan("partial", [good, broken])
        self.assertEqual(result.returncode, 2, result.stderr)
        rows = self.stream(result.stdout)
        self.assert_accounting(rows, complete=False, analysis_complete=False)
        self.assertEqual(rows[-1]["status"], "partial", rows[-1])
        self.assertTrue(rows[-1]["failed_modules"], rows[-1])
        self.assert_locations(rows, PARAM_RULE,
                              {(str(good), 2 * index + 1) for index in range(5)}, "warning")
        broken.write_text("VALUE = 1\n", encoding="utf-8")
        recovered = self.scan("recovered", [good, broken])
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assert_accounting(self.stream(recovered.stdout))

    def test_staged_export_reads_index_code_and_restores_original_paths(self):
        self.git("init", "-q")
        source = self.source("first file.py", "VALUE = 1\n")
        self.git("add", "--", source.name)
        self.git("-c", "user.name=UBS Test", "-c", "user.email=ubs-test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "occurrence fixture")
        staged_text = parameter_functions(5, "staged")
        source.write_text(staged_text, encoding="utf-8")
        self.git("add", "--", source.name)
        direct = self.scan("index-control", [source])
        self.assertEqual(direct.returncode, 0, direct.stderr)
        direct_rows = self.stream(direct.stdout)
        self.assert_accounting(direct_rows)
        source.write_text("WORKTREE_ONLY = 99\n", encoding="utf-8")
        self.source("untracked.py", parameter_functions(8, "untracked"))
        # git write-tree may refresh the index's cache-tree metadata. The
        # staged modes, object IDs, conflict stages and paths must stay exact.
        index_before = self.git("ls-files", "--stage", "-z")
        result = self.scan("staged", extra=("--staged",))
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.stream(result.stdout)
        self.assert_accounting(rows)
        findings = self.findings(rows, PARAM_RULE)
        self.assertEqual({(row["file"], row["line"]) for row in findings},
                         {(str(source), 2 * index + 1) for index in range(5)})
        for row in findings:
            self.assertEqual(row["code"], staged_text.split("\n")[row["line"] - 1], row)
        self.assertEqual(
            {row["occurrence_id"] for row in findings},
            {row["occurrence_id"] for row in self.findings(direct_rows, PARAM_RULE)},
        )
        self.assertEqual(source.read_text(encoding="utf-8"), "WORKTREE_ONLY = 99\n")
        self.assertEqual(self.git("ls-files", "--stage", "-z"), index_before)
        self.assertEqual(self.git("show", f":{source.name}"), staged_text)

    def test_secondary_exports_keep_one_scan_counts_sarif_and_pattern_count_contracts(self):
        source = self.source("source.py", parameter_functions(5))
        jsonl, beads = self.root / "also.jsonl", self.root / "beads.jsonl"
        sarif, counts = self.root / "report.sarif", self.root / "counts.json"
        result = self.scan(
            "also", [source], fmt="json",
            extra=("--also=jsonl:" + str(jsonl), "--beads-jsonl=" + str(beads),
                   "--also=sarif:" + str(sarif), "--python-pattern-counts=" + str(counts)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = self.decode(result.stdout, "primary JSON summary")
        rows = self.stream(jsonl.read_text(encoding="utf-8"))
        self.assertEqual(rows, self.stream(beads.read_text(encoding="utf-8")))
        self.assert_accounting(rows)
        for severity in SEVERITIES:
            self.assertEqual(rows[-1][severity], document["totals"][severity])
        report = self.decode(sarif.read_text(encoding="utf-8"), "SARIF control")
        self.assertTrue(report["runs"], report)
        results = [item for run in report["runs"] for item in run.get("results", [])]
        self.assertEqual(sum(item["ruleId"] == PARAM_RULE for item in results), 5, results)
        raw = self.decode(counts.read_text(encoding="utf-8"), "pattern counts control")
        rule = next(item for item in raw["rules"] if item["rule_id"] == PARAM_RULE)
        self.assertEqual(rule["count"], 5)
        self.assertIs(raw["complete"], True)

    def test_project_aggregate_has_no_invented_source_occurrences(self):
        first = self.source("first.swift", "func first() async {}\nfunc second() async {}\n")
        second = self.source("second.swift", "func third() async {}\n")
        result = self.scan("aggregate", [first, second], languages="swift")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.stream(result.stdout)
        metadata = self.assert_accounting(rows, complete=False)
        rule = "swift.concurrency.unawaited-async"
        self.assertEqual(self.findings(rows, rule), [])
        summary = next(row for row in rows
                       if row["type"] == "rule_summary" and row["rule_id"] == rule)
        self.assertEqual((summary["reported"], summary["emitted"],
                          summary["omitted"], summary["unlocated"]), (3, 0, 3, 3))
        self.assertGreaterEqual(metadata["unlocated"], 3, metadata)
        self.assertIs(metadata["locations_complete"], False, metadata)
        self.assertIs(metadata["truncated"], False, metadata)

    def test_long_source_lines_report_code_truncation_separately_from_locations(self):
        text = parameter_functions(4)
        first, remainder = text.split("\n", 1)
        source = self.source("long.py", first + "  # " + "x" * 5000 + "\n" + remainder)
        result = self.scan("long-code", [source])
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.stream(result.stdout)
        metadata = self.assert_accounting(rows, complete=False)
        self.assertIs(metadata["locations_complete"], True, metadata)
        self.assertEqual(metadata["omitted"], 0, metadata)
        self.assertEqual(metadata["code_unavailable"], 0, metadata)
        self.assertGreaterEqual(metadata["code_truncated"], 1, metadata)
        long = next(row for row in self.findings(rows, PARAM_RULE) if row["line"] == 1)
        self.assertIs(long["code_available"], True, long)
        self.assertIs(long["code_truncated"], True, long)
        self.assertEqual(len(long["code"]), 4096)

    def test_invalid_options_are_rejected_before_running_modules(self):
        source = self.source("source.py", parameter_functions(5))
        cases = (
            ("zero", "jsonl", True, ("--max-occurrences=0",)),
            ("too-large", "jsonl", True, ("--max-occurrences=1000001",)),
            ("not-integer", "jsonl", True, ("--max-occurrences=no",)),
            ("negative", "jsonl", True, ("--max-occurrences=-1",)),
            ("limit-alone", "jsonl", False, ("--max-occurrences=3",)),
            ("no-jsonl-sink", "json", True, ()),
            ("summary-only", "jsonl", True, ("--jsonl-summary-only",)),
        )
        for label, fmt, occurrences, extra in cases:
            with self.subTest(case=label):
                result = self.scan(label, [source], fmt=fmt, occurrences=occurrences, extra=extra)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("Scanning python", result.stderr)

    def test_empty_selections_emit_explicit_incomplete_totals_to_every_jsonl_sink(self):
        self.git("init", "-q")
        self.git("-c", "user.name=UBS Test", "-c", "user.email=ubs-test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "empty fixture")
        empty = self.root / "empty-directory"
        empty.mkdir()
        for label, paths, fmt, selection, exit_code in (
            ("empty-staged", (), "jsonl", ("--staged",), 0),
            ("empty-diff", (), "json", ("--diff",), 0),
            ("empty-directory", (empty,), "jsonl", (), 3),
        ):
            with self.subTest(selection=label):
                additional = self.root / (label + ".also.jsonl")
                beads = self.root / (label + ".beads.jsonl")
                result = self.scan(
                    label, paths, fmt=fmt,
                    extra=(*selection, "--max-occurrences=7",
                           "--also=jsonl:" + str(additional), "--beads-jsonl=" + str(beads)),
                )
                self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
                rows = self.stream(additional.read_text(encoding="utf-8"))
                self.assertEqual(rows, self.stream(beads.read_text(encoding="utf-8")))
                if fmt == "jsonl":
                    self.assertEqual(rows, self.stream(result.stdout))
                else:
                    primary = self.decode(result.stdout, "empty primary JSON")
                    self.assertEqual(primary["totals"]["files"], 0, primary)
                metadata = self.assert_accounting(rows, complete=False,
                                                  analysis_complete=False, limit=7)
                self.assertEqual(self.findings(rows), [], rows)
                self.assertEqual(rows[-1]["files"], 0, rows[-1])
                self.assertEqual(metadata["reported"], 0, metadata)
                self.assertIn("no_files_scanned", metadata["reasons"], metadata)

    def test_versioned_jsonl_schema_accepts_complete_and_truncated_streams(self):
        import jsonschema

        source = self.source("source.py", parameter_functions(5))
        schema_result = subprocess.run(
            ["bash", str(REPO_ROOT / "ubs"), "--schema=jsonl"],
            cwd=self.project, env=self.env, text=True, capture_output=True,
            timeout=30, check=False,
        )
        (self.root / "schema.stdout").write_text(schema_result.stdout, encoding="utf-8")
        (self.root / "schema.stderr").write_text(schema_result.stderr, encoding="utf-8")
        self.assertEqual(schema_result.returncode, 0, schema_result.stderr)
        schema = self.decode(schema_result.stdout, "JSONL schema")
        validator = jsonschema.Draft202012Validator(schema)
        for label, extra in (("schema-complete", ()), ("schema-limited", ("--max-occurrences=2",))):
            result = self.scan(label, [source], extra=extra)
            self.assertEqual(result.returncode, 0, result.stderr)
            for row in self.stream(result.stdout):
                validator.validate(row)


if __name__ == "__main__":
    unittest.main()
