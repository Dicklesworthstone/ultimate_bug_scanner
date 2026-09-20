"""Optional analyzer execution and findings adapters (issue #128).

These results are invocation-local, never stored in the source-content cache:
configuration, dependency databases, tool versions and availability can change
without a source edit. A missing tool is optional; an attempted, incomplete
analysis is not a clean pass. Keep valid diagnostics even on an abnormal exit.

Exit contracts: RuboCop CLI Reference (0/1 complete, 2 error), Brakeman's
lib/brakeman.rb (3 warnings, 7 errors), Reek CLI::Status (2 smells, 1 error),
and rubysec/bundler-audit CLI#check (1 for vulnerabilities OR execution errors;
only a valid nonempty results document establishes the former). Fasterer's CLI
uses 1 for offenses; its statistics also expose otherwise-successful parse
failures. See the upstream CLI/report implementations, not stderr heuristics.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, TextIO

from ubs_core.suppression import SourceSuppressions

OUTPUT_LIMIT = 16 * 1024 * 1024
RUBY_TOOLS = {
    "rubocop": "rubocop", "brakeman": "brakeman",
    "bundler-audit": "bundle-audit", "reek": "reek", "fasterer": "fasterer",
}
RUBY_SOURCE_EXTENSIONS = {".rb", ".rake", ".ru", ".gemspec", ".rbi", ".jbuilder"}
RUBY_SOURCE_NAMES = {"Gemfile", "Rakefile", "Guardfile", "Vagrantfile", "Capfile"}


@dataclass(frozen=True)
class ToolOutput:
    returncode: int
    stdout: str
    stderr: str


def run_command(tool: str, argv: Sequence[str], root: Path, timeout: float,
                errors: list[str], *, env: dict[str, str] | None = None) -> ToolOutput | None:
    """Bound execution, reap timed-out process groups, and bound captured memory."""
    if not math.isfinite(timeout) or timeout <= 0:
        errors.append(f"{tool}: timeout must be a positive finite number")
        return None
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.Popen(
                list(argv), cwd=root, stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=stderr, env=env, start_new_session=os.name == "posix",
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                errors.append(f"{tool}: timed out after {timeout:g}s")
                try:
                    if os.name == "posix":
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                proc.wait()
            stdout.seek(0)
            raw = stdout.read(OUTPUT_LIMIT + 1)
            if len(raw) > OUTPUT_LIMIT:
                errors.append(f"{tool}: output exceeds {OUTPUT_LIMIT} bytes")
            stderr.seek(0)
            return ToolOutput(proc.returncode, raw[:OUTPUT_LIMIT].decode("utf-8", "replace"),
                              stderr.read(4096).decode("utf-8", "replace"))
    except OSError as exc:
        errors.append(f"{tool}: could not launch or capture output: {exc}")
        return None


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected a nonempty string")
    return value


def _positive(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("expected a positive integer location")
    return value


def _array(doc: object, key: str) -> list:
    if not isinstance(doc, dict) or not isinstance(doc.get(key), list):
        raise ValueError(f"expected {key!r} array")
    return doc[key]


class RubyFindings:
    def __init__(self, files: Sequence[Path], root: Path, sink: TextIO) -> None:
        self.root, self.sink = root, sink
        self.selected = {p.resolve(): str(p) for p in files}
        self.suppressions = SourceSuppressions("ruby")

    def emit(self, tool: str, rule: str, path: str, line: int, col: int,
             severity: str, message: str, *, project: bool = False,
             extras: dict | None = None) -> None:
        file = Path(path)
        file = (file if file.is_absolute() else self.root / file).resolve()
        if not project and file not in self.selected:
            return  # project analyzers must not re-admit excluded source files
        rule = "rb." + tool + "." + re.sub(r"[^A-Za-z0-9_.-]", "-", rule)
        if not project and self.suppressions.is_suppressed(file, line, rule):
            return
        record = {
            "rule": rule, "category_id": "ruby.bundler", "path": self.selected.get(file, str(file)),
            "line": line, "col": col, "severity": severity, "message": message[:500],
            "suppressed": False, "extras": {"tool": tool, **(extras or {})},
        }
        if project:
            record["extras"]["scope"] = "project"
        self.sink.write(json.dumps(record, ensure_ascii=False) + "\n")

    def rubocop(self, doc: object, errors: list[str]) -> int:
        count = 0
        for file in _array(doc, "files"):
            try:
                path = _text(file["path"])
                offenses = _array(file, "offenses")
            except (TypeError, KeyError, ValueError):
                errors.append("rubocop: malformed file record")
                continue
            count += len(offenses)
            for row in offenses:
                try:
                    rule, message = _text(row["cop_name"]), _text(row["message"])
                    severity = {"fatal": "critical", "error": "critical", "warning": "warning",
                                "convention": "info", "refactor": "info", "info": "info"}[row["severity"]]
                    loc = row["location"]
                    self.emit("rubocop", rule, path, _positive(loc["start_line"]),
                              _positive(loc["start_column"]), severity, message)
                except (KeyError, TypeError, ValueError):
                    errors.append("rubocop: malformed offense")
        return count

    def brakeman(self, doc: object, errors: list[str]) -> int:
        warnings = _array(doc, "warnings")
        for problem in _array(doc, "errors"):
            detail = problem.get("error", "analysis error") if isinstance(problem, dict) else str(problem)
            errors.append(f"brakeman: {str(detail)[:200]}")
        for row in warnings:
            try:
                code = row["warning_code"]
                if type(code) is not int or code < 0:
                    raise ValueError("invalid warning code")
                message = _text(row["message"])
                confidence = _text(row["confidence"]).lower()
                severity = {"high": "critical", "medium": "warning", "weak": "info"}[confidence]
                # Some dependency/configuration warnings have no source location.
                project = row.get("file") is None
                path = "Gemfile.lock" if project else _text(row["file"])
                line = 1 if row.get("line") is None else _positive(row["line"])
                self.emit("brakeman", str(code), path, line, 1, severity, message,
                          project=project, extras={"confidence": confidence})
            except (KeyError, TypeError, ValueError):
                errors.append("brakeman: malformed warning")
        return len(warnings)

    def audit(self, doc: object, errors: list[str]) -> int:
        rows = _array(doc, "results")
        for row in rows:
            try:
                if row["type"] == "unpatched_gem":
                    gem, advisory = row["gem"], row["advisory"]
                    name, version = _text(gem["name"]), _text(gem["version"])
                    rule, title = _text(advisory["id"]), _text(advisory["title"])
                    self.emit("bundler-audit", rule, "Gemfile.lock", 1, 1, "critical",
                              f"{name} {version}: {title} ({rule})", project=True,
                              extras={"gem": name, "advisory": advisory})
                elif row["type"] == "insecure_source":
                    source = _text(row["source"])
                    self.emit("bundler-audit", "insecure-source", "Gemfile.lock", 1, 1,
                              "warning", f"Insecure gem source: {source}", project=True)
                else:
                    raise ValueError("unknown audit result type")
            except (KeyError, TypeError, ValueError):
                errors.append("bundler-audit: malformed audit result")
        return len(rows)

    def reek(self, doc: object, errors: list[str]) -> int:
        if not isinstance(doc, list):
            raise ValueError("expected diagnostic array")
        for row in doc:
            try:
                lines = _array(row, "lines")
                if not lines:
                    raise ValueError("missing smell location")
                self.emit("reek", _text(row["smell_type"]), _text(row["source"]),
                          min(_positive(line) for line in lines), 1, "info", _text(row["message"]))
            except (KeyError, TypeError, ValueError):
                errors.append("reek: malformed smell")
        return len(doc)

    def fasterer(self, output: str, errors: list[str]) -> int:
        # Fasterer has no JSON formatter. Require its completion footer rather
        # than interpreting arbitrary stdout or a parser crash as a clean run.
        output = re.sub(r"\x1b\[[0-9;]*m", "", output)
        footer = re.search(r"(?m)^\d+ files? inspected, (\d+) offenses? detected(?:, (\d+) unparsable files? found)?\s*$", output)
        if not footer:
            errors.append("fasterer: missing completion statistics")
        elif footer[2] and int(footer[2]):
            errors.append(f"fasterer: {footer[2]} file(s) could not be parsed")
        count = 0
        for path, line, message in re.findall(r"(?m)^(.+):(\d+) (.+)$", output):
            count += 1
            self.emit("fasterer", "performance", path, _positive(int(line)), 1, "info", message)
        if footer and int(footer[1]) and not count:
            errors.append("fasterer: offenses reported without readable locations")
        return count


# Query the selected bundle, not the installer's/current shell's bundle. A
# missing gem is optional; a broken Bundler environment must not look absent.
_BUNDLE_PROBE = r'''
require "json"
result = {}
ARGV.each_slice(2) do |name, executable|
  spec = Gem.loaded_specs[name]
  result[name] = !!(spec && spec.executables.include?(executable))
end
STDOUT.write(JSON.generate(result))
'''


def scan_ruby_tools(files: Sequence[Path], sink: TextIO, project_dir: str,
                    tools: str, timeout: float, errors: list[str]) -> list[dict]:
    """Append fresh optional findings and return per-tool coverage metadata."""
    if not files or not tools.strip():
        return []
    project = Path(project_dir or ".").resolve()
    root = project.parent if project.is_file() else project
    requested = list(dict.fromkeys(part.strip() for part in tools.split(",") if part.strip()))
    findings = RubyFindings(files, root, sink)
    sources = [str(path) for path in findings.selected
               if path.suffix in RUBY_SOURCE_EXTENSIONS or path.name in RUBY_SOURCE_NAMES]
    env = dict(os.environ, NO_COLOR="1")
    bundle = shutil.which("bundle") if (root / "Gemfile").is_file() else None
    bundled: dict = {}
    outcomes = []
    candidates = []
    for tool in requested:
        reason = ""
        if tool not in RUBY_TOOLS:
            errors.append(f"{tool}: unknown Ruby analyzer")
            outcomes.append({"tool": tool, "status": "partial"})
            continue
        if tool in ("rubocop", "reek", "fasterer") and not sources:
            reason = "no selected Ruby source files"
        elif tool == "brakeman" and not ((root / "config/application.rb").is_file()
                                         or (root / "config/environment.rb").is_file()):
            reason = "not a Rails application"
        elif tool == "bundler-audit" and not (root / "Gemfile.lock").is_file():
            reason = "no Gemfile.lock"
        if reason:
            outcomes.append({"tool": tool, "status": "skipped", "reason": reason})
        else:
            candidates.append(tool)
    if bundle and candidates:
        env["BUNDLE_GEMFILE"] = str(root / "Gemfile")
        args = [item for tool in candidates for item in (tool, RUBY_TOOLS[tool])]
        before = len(errors)
        probe = run_command("bundler", [bundle, "exec", "ruby", "-e", _BUNDLE_PROBE, *args],
                            root, timeout, errors, env=env)
        try:
            if probe is None or probe.returncode != 0 or len(errors) != before:
                raise ValueError("bundle could not resolve optional analyzers")
            bundled = json.loads(probe.stdout)
            if not isinstance(bundled, dict) or any(type(bundled.get(t)) is not bool for t in candidates):
                raise ValueError("invalid Bundler executable map")
        except (ValueError, TypeError) as exc:
            detail = (probe.stderr.strip()[:160] if probe else "")
            errors.append(f"bundler ({', '.join(candidates)}): {exc}; {detail}")
            return outcomes + [{"tool": tool, "status": "partial"} for tool in candidates]
    for tool in candidates:
        before = len(errors)
        executable = RUBY_TOOLS[tool]
        if bundle and bundled.get(tool):
            command = [bundle, "exec", executable]
        elif tool == "bundler-audit":
            installed = shutil.which(executable) or shutil.which(tool)
            command = [installed] if installed else []
        elif not bundle:
            installed = shutil.which(executable)
            command = [installed] if installed else []
        else:
            command = []
        if not command:
            outcomes.append({"tool": tool, "status": "skipped", "reason": "not installed"})
            continue
        if tool == "rubocop":
            batches = [["--format", "json", "--no-parallel", "--force-exclusion", "--", *sources[i:i+50]]
                       for i in range(0, len(sources), 50)]
            parser, accepted, finding_exit = findings.rubocop, (0, 1), 1
        elif tool == "brakeman":
            batches = [["--quiet", "--format", "json", "--exit-on-warn", "--exit-on-error", "--path", str(root)]]
            parser, accepted, finding_exit = findings.brakeman, (0, 3), 3
        elif tool == "bundler-audit":
            batches = [["check", "--update", "--quiet", "--format", "json"]]
            parser, accepted, finding_exit = findings.audit, (0, 1), 1
        elif tool == "reek":
            batches = [["--format", "json", *sources[i:i+50]] for i in range(0, len(sources), 50)]
            parser, accepted, finding_exit = findings.reek, (0, 2), 2
        else:
            # Fasterer consumes only ARGV[0]; passing the complete list would
            # silently inspect just its first file.
            batches = [[source] for source in sources]
            parser, accepted, finding_exit = findings.fasterer, (0, 1), 1
        for args in batches:
            result = run_command(tool, [*command, *args], root, timeout, errors, env=env)
            if result is None:
                continue
            if result.returncode not in accepted:
                errors.append(f"{tool}: exited {result.returncode}: {result.stderr.strip()[:160]}")
            try:
                doc = result.stdout if tool == "fasterer" else json.loads(result.stdout)
                count = parser(doc, errors)
                if result.returncode == finding_exit and not count:
                    errors.append(f"{tool}: finding exit without diagnostics")
            except (ValueError, TypeError, KeyError, OSError, RuntimeError) as exc:
                errors.append(f"{tool}: invalid or incomplete report: {exc}")
        outcomes.append({"tool": tool, "status": "partial" if len(errors) != before else "ok"})
    return outcomes
