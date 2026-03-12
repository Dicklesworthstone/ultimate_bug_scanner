#!/usr/bin/env python3
"""Targeted regression tests for the UBS meta-runner contract."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UBS_BIN = REPO_ROOT / "ubs"


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def make_fake_ast_grep(path: Path) -> None:
    write_file(
        path,
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        case "${1:-}" in
          --version)
            echo "ast-grep 0.40.1"
            ;;
          scan)
            if [[ "${2:-}" == "-h" ]]; then
              echo "scan help"
              exit 0
            fi
            echo '{"matches":[]}'
            ;;
          run)
            echo '{"matches":[]}'
            ;;
          --pattern)
            echo '{"matches":[]}'
            ;;
          *)
            echo "ast-grep fake"
            ;;
        esac
        """,
    )
    path.chmod(0o755)


def make_fake_module(
    path: Path,
    language: str,
    critical: int,
    warning: int,
    info: int,
    findings: list[dict[str, object]] | None = None,
) -> None:
    findings_json = json.dumps({"findings": findings or []})
    write_file(
        path,
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        if [[ -n "${{UBS_TEST_ARGS_LOG:-}}" ]]; then
          printf '%s\\n' "$*" >> "$UBS_TEST_ARGS_LOG"
        fi
        format="text"
        report_json=""
        for arg in "$@"; do
          case "$arg" in
            --format=*) format="${{arg#--format=}}" ;;
            --report-json=*) report_json="${{arg#--report-json=}}" ;;
          esac
        done
        if [[ -n "$report_json" ]]; then
          cat <<'EOF' > "$report_json"
        {findings_json}
        EOF
        fi
        case "$format" in
          json)
            cat <<'EOF'
        {{"project":".","files":1,"critical":{critical},"warning":{warning},"info":{info},"timestamp":"2026-03-12T00:00:00Z"}}
        EOF
            ;;
          sarif)
            cat <<'EOF'
        {{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"ubs-{language}"}}}},"results":[{{"ruleId":"{language}-warning","level":"warning","message":{{"text":"warning from {language}"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"src/{language}.txt"}}}}}}]}}]}}]}}
        EOF
            ;;
          *)
            cat <<'EOF'
        Summary Statistics:
        Files scanned: 1
        Critical issues: {critical}
        Warning issues: {warning}
        Info items: {info}
        EOF
            ;;
        esac
        """,
    )
    path.chmod(0o755)


class MetaRunnerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ubs-meta-runner-"))
        self.project = self.tmpdir / "project"
        self.fake_bin = self.tmpdir / "bin"
        self.args_log = self.tmpdir / "module-args.log"
        self.project.mkdir()
        self.fake_bin.mkdir()
        make_fake_ast_grep(self.fake_bin / "ast-grep")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def run_ubs(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}:{env['PATH']}"
        env["UBS_NO_AUTO_UPDATE"] = "1"
        env["UBS_TEST_ARGS_LOG"] = str(self.args_log)
        return subprocess.run(
            [str(UBS_BIN), *args, str(self.project)],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
            env=env,
        )

    def test_detects_languages_and_merges_json_output(self) -> None:
        write_file(self.project / "web" / "app.js", "console.log('ok');\n")
        write_file(self.project / "package.json", '{"name":"demo"}\n')
        write_file(self.project / "worker.py", "print('ok')\n")
        make_fake_module(self.fake_bin / "ubs-js", "js", critical=0, warning=1, info=2)
        make_fake_module(self.fake_bin / "ubs-python", "python", critical=0, warning=0, info=3)

        result = self.run_ubs("--format=json", "--no-auto-update")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        payload = json.loads(result.stdout)
        scanners = {entry["language"]: entry for entry in payload["scanners"]}
        self.assertEqual(set(scanners), {"js", "python"})
        self.assertEqual(payload["totals"]["critical"], 0)
        self.assertEqual(payload["totals"]["warning"], 1)
        self.assertEqual(payload["totals"]["info"], 5)

    def test_jsonl_output_emits_scanner_and_totals_records(self) -> None:
        write_file(self.project / "src" / "main.js", "console.log('ok');\n")
        make_fake_module(
            self.fake_bin / "ubs-js",
            "js",
            critical=0,
            warning=2,
            info=1,
            findings=[
                {
                    "ruleId": "js.contract-warning",
                    "severity": "warning",
                    "message": "jsonl finding",
                    "path": "src/main.js",
                    "line": 1,
                }
            ],
        )

        result = self.run_ubs("--format=jsonl", "--no-auto-update")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        types = {record["type"] for record in records}
        self.assertIn("finding", types)
        self.assertIn("scanner", types)
        self.assertIn("totals", types)
        finding = next(record for record in records if record["type"] == "finding")
        scanner = next(record for record in records if record["type"] == "scanner")
        totals = next(record for record in records if record["type"] == "totals")
        self.assertEqual(finding["language"], "js")
        self.assertEqual(finding["message"], "jsonl finding")
        self.assertEqual(scanner["language"], "js")
        self.assertEqual(totals["warning"], 2)

    def test_sarif_output_merges_runs(self) -> None:
        write_file(self.project / "frontend.ts", "export const x = 1;\n")
        write_file(self.project / "service.py", "print('ok')\n")
        make_fake_module(self.fake_bin / "ubs-js", "js", critical=0, warning=1, info=0)
        make_fake_module(self.fake_bin / "ubs-python", "python", critical=0, warning=1, info=0)

        result = self.run_ubs("--format=sarif", "--no-auto-update")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        payload = json.loads(result.stdout)
        runs = payload["runs"]
        drivers = {run["tool"]["driver"]["name"] for run in runs}
        self.assertEqual(drivers, {"ubs-js", "ubs-python"})
        self.assertEqual(len(runs), 2)
        results = [result for run in runs for result in run["results"]]
        self.assertEqual(len(results), 2)
        uris = {
            loc["physicalLocation"]["artifactLocation"]["uri"]
            for run in runs
            for result in run["results"]
            for loc in result["locations"]
        }
        self.assertEqual(uris, {"src/js.txt", "src/python.txt"})

    def test_ci_and_fail_on_warning_propagate_and_fail_closed(self) -> None:
        write_file(self.project / "frontend.js", "console.log('ok');\n")
        make_fake_module(self.fake_bin / "ubs-js", "js", critical=0, warning=1, info=0)

        result = self.run_ubs("--format=json", "--ci", "--fail-on-warning", "--no-auto-update")
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["totals"]["warning"], 1)
        arg_log = self.args_log.read_text(encoding="utf-8")
        self.assertIn("--ci", arg_log)
        self.assertIn("--fail-on-warning", arg_log)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
