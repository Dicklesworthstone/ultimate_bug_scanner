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
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO, StringIO
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence, TextIO

from ubs_core.suppression import SourceSuppressions

OUTPUT_LIMIT = 16 * 1024 * 1024
# Streaming tools have no total-output ceiling. Bound a single encoded record
# so corrupt or runaway output cannot turn readline() into an unbounded slurp.
OUTPUT_RECORD_LIMIT = 16 * 1024 * 1024
_PROCESS_CLEANUP_GRACE = 1.0
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


@dataclass(frozen=True)
class ToolStreamOutput:
    returncode: int
    stdout: BinaryIO
    stderr: str
    stderr_stream: BinaryIO | None = None


def _process_group_running(pgid: int) -> bool:
    """Check for unfinished group members, excluding Linux zombies.

    Reaping the command itself does not close descriptors inherited by its
    children. A zombie, however, has already closed all its descriptors and
    cannot contribute more output. Inspect /proc only for groups that survive
    their leader; normal invocations need just the inexpensive killpg probe.
    Without reliable process state, conservatively treat the group as live.
    """
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    if sys.platform != "linux":
        return True
    try:
        with open("/proc/self/stat", "rb") as stat:
            if stat.read(4096).partition(b" ")[0] != str(os.getpid()).encode("ascii"):
                # A host-mounted procfs can expose different PID numbers from
                # killpg(). Never inspect an unrelated group's state there.
                return True
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    with open(f"/proc/{entry.name}/stat", "rb") as stat:
                        # The command name may contain spaces and parentheses.
                        fields = stat.read(4096).rpartition(b")")[2].split()
                except FileNotFoundError:
                    continue  # the process finished while being inspected
                if len(fields) < 3:
                    return True
                if fields[2] == str(pgid).encode("ascii") and fields[0] not in (b"Z", b"X"):
                    return True
    except OSError:
        return True
    return False


@contextmanager
def run_command_stream(tool: str, argv: Sequence[str], root: Path, timeout: float,
                       errors: list[str], *, env: dict[str, str] | None = None,
                       merge_stderr: bool = False) -> Iterator[ToolStreamOutput | None]:
    """Spool complete output to disk with bounded execution and memory.

    The stream is valid only inside the context. Consumers must read it in
    bounded records or chunks. Timeouts and cancellation retain the same
    process-group cleanup as whole-document capture; completed output remains
    readable after an analyzer fails or times out. The eager stderr preview
    is limited to 4 KiB; its full stream uses the same bounded readers as
    stdout. Spooling also avoids pipe deadlocks on noisy analyzers.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        errors.append(f"{tool}: timeout must be a positive finite number")
        yield None
        return
    if os.name == "posix" and signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
        # POSIX auto-reaps children under SIG_IGN. Popen then substitutes exit
        # 0 when waitpid cannot obtain the actual status, even if the tool
        # failed. Keep the caller's signal policy and any output, but never
        # treat that unverifiable status as complete analysis.
        errors.append(f"{tool}: cannot verify analyzer exit status while SIGCHLD is ignored")
    stdout = stderr = None
    try:
        try:
            stdout = tempfile.TemporaryFile()
            stderr = tempfile.TemporaryFile()
            # The only tainted argv reaching here is the operator's
            # UBS_AST_GREP_BIN override (scan_ast_config); argv is a list, no shell.
            proc = subprocess.Popen(  # ubs:ignore[python.taint.command] - executable comes from operator configuration, not request input.
                list(argv), cwd=root, stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=stdout if merge_stderr else stderr, env=env,
                start_new_session=os.name == "posix",
            )

            def stop() -> bool:
                try:
                    if os.name == "posix":
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                # Killing the group is asynchronous. Do not read through a
                # live writer's shared file offset or wait indefinitely for an
                # uninterruptible process. Cleanup has its own small grace,
                # never another full analyzer timeout.
                deadline = time.monotonic() + _PROCESS_CLEANUP_GRACE
                try:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    errors.append(f"{tool}: could not stop analyzer during cleanup")
                    return False
                while os.name == "posix" and _process_group_running(proc.pid):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        errors.append(f"{tool}: could not confirm process group stopped during cleanup")
                        return False
                    time.sleep(min(0.01, remaining))
                return True

            def cancel(signum, _frame) -> None:
                # GNU timeout signals the module group, but the analyzer is
                # isolated from it. Unwind through stop() before exiting.
                raise SystemExit(128 + signum)

            previous_handlers = {}
            capture_ready = True
            try:
                if os.name == "posix" and threading.current_thread() is threading.main_thread():
                    for signum in (signal.SIGTERM, signal.SIGHUP):
                        previous = signal.getsignal(signum)
                        if previous == signal.SIG_DFL:
                            previous_handlers[signum] = previous
                            signal.signal(signum, cancel)
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    errors.append(f"{tool}: timed out after {timeout:g}s")
                    capture_ready = stop()
                else:
                    if os.name == "posix" and _process_group_running(proc.pid):
                        errors.append(f"{tool}: analyzer exited before its process group completed")
                        capture_ready = stop()
            except BaseException:
                # KeyboardInterrupt, parent deadlines and caller cancellation
                # must not leave the isolated analyzer (or its children) alive.
                stop()
                raise
            finally:
                for signum, previous in previous_handlers.items():
                    signal.signal(signum, previous)
            if capture_ready:
                stdout.seek(0)
                stderr_preview = ""
                stderr_stream = stderr
                try:
                    stderr.seek(0)
                    stderr_preview = stderr.read(4096).decode("utf-8", "replace")
                    stderr.seek(0)
                except OSError as exc:
                    # Losing stderr does not erase independently captured
                    # stdout findings. The missing evidence still fails the
                    # completeness gate, and both handles remain owned here.
                    errors.append(f"{tool}: could not read captured stderr: {exc}")
                    stderr_stream = None
                output = ToolStreamOutput(proc.returncode, stdout, stderr_preview, stderr_stream)
            else:
                output = None  # output cannot be frozen while writers survive
        except OSError as exc:
            errors.append(f"{tool}: could not launch or capture output: {exc}")
            output = None
        # Keep caller exceptions outside the capture handler: an OSError in a
        # consumer must never make this context manager attempt a second yield.
        yield output
    finally:
        for stream in (stderr, stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError as exc:
                    # Preserve a consumer exception and still close the other
                    # handle. Cleanup failures must reach the coverage gate.
                    errors.append(f"{tool}: could not close captured output: {exc}")


def run_command(tool: str, argv: Sequence[str], root: Path, timeout: float,
                errors: list[str], *, env: dict[str, str] | None = None,
                merge_stderr: bool = False, strict_utf8: bool = False) -> ToolOutput | None:
    """Capture a bounded whole document for analyzers without a record stream."""
    with run_command_stream(tool, argv, root, timeout, errors,
                            env=env, merge_stderr=merge_stderr) as output:
        if output is None:
            return None
        try:
            raw = output.stdout.read(OUTPUT_LIMIT + 1)
        except OSError as exc:
            errors.append(f"{tool}: could not capture output: {exc}")
            return None
        if len(raw) > OUTPUT_LIMIT:
            errors.append(f"{tool}: output exceeds {OUTPUT_LIMIT} bytes")
        data = raw[:OUTPUT_LIMIT]
        if strict_utf8:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(f"{tool}: output is not valid UTF-8")
        return ToolOutput(output.returncode, data.decode("utf-8", "replace"), output.stderr)


def iter_output_lines(stream: BinaryIO, errors: list[str], *, context: str) -> Iterator[tuple[int, str]]:
    """Read every LF-delimited record, bounding memory and error detail.

    Oversized or non-UTF-8 rows are rejected as incomplete evidence, then the
    next record is still read. An arbitrarily long malformed row is drained in
    fixed chunks without accumulating it or discarding later diagnostics.
    """
    failures = 0
    details: list[str] = []
    failure_index = None
    number = 0
    while True:
        try:
            raw = stream.readline(OUTPUT_RECORD_LIMIT + 1)
            if not raw:
                break
            number += 1
            oversized = len(raw) > OUTPUT_RECORD_LIMIT
            if oversized:
                while raw and not raw.endswith(b"\n"):
                    raw = stream.readline(64 * 1024)
        except OSError as exc:
            errors.append(f"{context}: could not read captured output: {exc}")
            break
        if oversized:
            problem = f"record output exceeds {OUTPUT_RECORD_LIMIT} bytes"
        else:
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                problem = "output is not valid UTF-8"
            else:
                yield number, line
                continue
        failures += 1
        if len(details) < 4:
            details.append(f"row {number}: {problem}")
        if failure_index is None:
            failure_index = len(errors)
            errors.append("")
        # Update one bounded entry immediately: an early consumer exit must
        # not erase corruption that has already been observed.
        errors[failure_index] = f"{context}: {failures} unreadable output record(s) ({'; '.join(details)})"


def report_ast_stderr(output: ToolStreamOutput, errors: list[str], *, context: str) -> None:
    """Retain native ast-grep input errors even when its exit status is zero.

    ast-grep prints unreadable/missing-source errors as ``ERROR: ...`` on
    stderr but can still exit zero and emit findings from readable siblings.
    Check the full captured stream, not only the diagnostic preview. Ordinary
    warnings are not an input failure; Ruby/Go tools retain their own exit and
    report contracts instead of using this ast-grep-specific boundary.
    """
    lines = (iter_output_lines(output.stderr_stream, errors, context=f"{context} stderr")
             if output.stderr_stream is not None else enumerate(StringIO(output.stderr), 1))
    failures = 0
    details: list[str] = []
    for _number, line in lines:
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if output.returncode == 1 and re.fullmatch(r"Error: [1-9][0-9]* error\(s\) found in code\.", line):
            # The native scan CLI prints this summary for ordinary error-level
            # findings. The adapter separately requires valid stdout evidence
            # for exit 1; an empty/truncated report still fails that gate.
            continue
        if not re.match(r"(?:error|fatal):", line, re.IGNORECASE):
            continue
        failures += 1
        if len(details) < 4:
            details.append(line[:160])
    if failures:
        errors.append(f"{context}: {failures} analyzer error(s) on stderr ({'; '.join(details)})")


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


def ast_rule_configs(rule_dir: Path, paths: Sequence[Path],
                     errors: list[str] | None = None, *,
                     prefix: str = "sgconfig-") -> list[Path]:
    """Find a requested AST pack without mistaking its absence for a clean scan."""
    if not paths:
        return []
    try:
        # iterdir raises for a missing/unreadable directory; glob may hide it.
        configs = sorted(p for p in Path(rule_dir).iterdir()
                         if p.name.startswith(prefix) and p.suffix in {".yml", ".yaml"})
        if configs:
            return configs
        detail = f"no {prefix} rule configurations"
    except OSError as exc:
        detail = str(exc)
    message = f"ast-grep: cannot load requested rule pack {rule_dir}: {detail}"
    if errors is None:
        raise RuntimeError(message)
    errors.append(message)
    return []


def parse_ast_diagnostics(text: str | BinaryIO, errors: list[str] | None = None,
                          *, context: str = "ast-grep",
                          run_rule_id: str | None = None) -> Iterator[dict]:
    """Yield validated NDJSON evidence; report corruption instead of skipping it.

    A malformed row does not erase earlier or later valid findings. Limit the
    diagnostic detail, not the validation: every row is checked, even when a
    caller will subsequently filter its rule or category. Without an error
    accumulator, incomplete analysis raises rather than becoming a clean API
    result. Field aliases are normalized once for all language adapters.
    ``run --pattern`` has no diagnostic rule/severity fields: only that mode
    supplies ``run_rule_id`` from the caller's known pattern definition.
    """
    problems = errors if errors is not None else []
    failures = 0
    details: list[str] = []
    failure_index = None
    # NDJSON is delimited by LF, not by Unicode line separators that may
    # legitimately occur inside a JSON string (including a source filename).
    lines = (enumerate(StringIO(text), 1) if isinstance(text, str)
             else iter_output_lines(text, problems, context=context))
    for number, line in lines:
        if not line.strip():
            continue
        try:
            match = json.loads(line)
            if not isinstance(match, dict):
                raise ValueError("expected a diagnostic object")
            if run_rule_id is not None:
                match["ruleId"], match["severity"] = run_rule_id, "warning"
            rule = match.get("ruleId") or match.get("rule_id") or match.get("id")
            file = match.get("file") or match.get("path")
            for field, value in (("ruleId", rule), ("file", file)):
                if not isinstance(value, str) or not value.strip() or "\0" in value:
                    raise ValueError(f"invalid {field}")
                value.encode("utf-8")
            location = match.get("range")
            start = location.get("start") if isinstance(location, dict) else None
            if not isinstance(start, dict):
                raise ValueError("missing diagnostic location")
            for field in ("line", "column"):
                if type(start.get(field)) is not int or start[field] < 0:
                    raise ValueError(f"invalid location {field}")
            if "end" in location:
                end = location["end"]
                if not isinstance(end, dict) or any(
                    type(end.get(field)) is not int or end[field] < 0
                    for field in ("line", "column")
                ):
                    raise ValueError("invalid end location")
                if (end["line"], end["column"]) < (start["line"], start["column"]):
                    raise ValueError("reversed diagnostic range")
            if match.get("severity") not in (
                "error", "warning", "info", "hint", "off", "critical", "fatal", "warn", "note",
            ):
                raise ValueError("invalid diagnostic severity")
            for field in ("message", "text", "snippet", "lines"):
                if field in match:
                    value = match[field]
                    if not isinstance(value, str):
                        raise ValueError(f"invalid {field}")
                    value.encode("utf-8")
            # Swift's correlation layer consumes the optional METHOD capture.
            # Check its container types before it can erase other valid rows.
            if "metaVariables" in match:
                meta = match["metaVariables"]
                if not isinstance(meta, dict):
                    raise ValueError("invalid metaVariables")
                single = meta.get("single", {})
                if not isinstance(single, dict) or any(not isinstance(v, dict) for v in single.values()):
                    raise ValueError("invalid single capture")
            match["ruleId"], match["file"] = rule, file
        except (ValueError, UnicodeError, RecursionError) as exc:
            failures += 1
            if len(details) < 4:
                details.append(f"row {number}: {str(exc)[:160]}")
            if failure_index is None:
                failure_index = len(problems)
                problems.append("")
            problems[failure_index] = f"{context}: {failures} malformed AST diagnostic(s) ({'; '.join(details)})"
            continue
        yield match
    if errors is None and problems:
        raise RuntimeError("; ".join(problems))


def scan_ast_config(config: Path, paths: Sequence[Path],
                    errors: list[str] | None = None, *, ast_grep_bin: str = "ast-grep",
                    batch_size: int = 400, timeout: float = 600.0) -> Iterator[dict]:
    """Execute a pack with bounded capture, cancellation cleanup and strict input.

    The verified executable exported by the runner is authoritative. A broken
    explicit override must fail, not fall back to another installation. Valid
    output from failed/timed-out batches survives, and later batches still run.
    """
    if not paths:
        return
    if type(batch_size) is not int or batch_size <= 0:
        raise ValueError("AST batch size must be a positive integer")
    failures = errors if errors is not None else []
    config = Path(config)
    if not config.is_file():
        failures.append(f"ast-grep: missing or nonregular rule configuration: {config}")
    else:
        executable = os.environ.get("UBS_AST_GREP_BIN") or ast_grep_bin
        for start in range(0, len(paths), batch_size):
            batch = [str(p) for p in paths[start:start + batch_size]]
            with run_command_stream(
                "ast-grep", [executable, "scan", "-c", str(config.resolve()),
                             "--json=stream", "--", *batch],
                Path.cwd(), timeout, failures,
            ) as output:
                if output is None:
                    continue
                report_ast_stderr(output, failures, context=f"ast-grep ({config.name})")
                if output.returncode not in (0, 1):
                    detail = output.stderr.strip().splitlines()
                    failures.append(
                        f"ast-grep exited {output.returncode} on {config.name}"
                        + (f": {detail[0][:160]}" if detail else "")
                    )
                valid = False
                for diagnostic in parse_ast_diagnostics(output.stdout, failures, context=f"ast-grep ({config.name})"):
                    valid = True
                    yield diagnostic
                if output.returncode == 1 and not valid:
                    failures.append(f"ast-grep ({config.name}): findings exit without valid diagnostics")
    if errors is None and failures:
        raise RuntimeError("; ".join(failures))


_CUSTOM_SEVERITY = {
    "error": "critical", "critical": "critical", "fatal": "critical",
    "warning": "warning", "warn": "warning",
    "info": "info", "hint": "info", "note": "info",
}


def custom_rule_files(rules_dir: str | Path) -> list[Path]:
    """Every .yml/.yaml policy below ``rules_dir``; hidden paths are not rules."""
    root = Path(rules_dir)
    found = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith("."))
        found.extend(Path(directory) / name for name in sorted(names)
                     if not name.startswith(".") and Path(name).suffix in {".yml", ".yaml"})
    return found


def scan_custom_rules(rules_dir: str | Path, paths: Sequence[Path], sink: TextIO,
                      lang: str, errors: list[str], *, ast_grep_bin: str = "ast-grep") -> int:
    """Run the project's ``--rules`` policy over ``paths`` as its own layer.

    Built-in rule packs recalibrate severities and keep only the ids their
    legacy reports counted; a project policy is not a built-in rule and gets
    neither treatment. Every match keeps its rule id and its authored
    severity (ast-grep ``error`` is critical). ast-grep applies each rule only
    to files of the rule's language, so a module sees only its own matches.
    Source ``ubs:ignore`` markers apply as for any other finding. A policy
    that cannot be loaded or run is an incomplete scan, never a clean one.
    Returns the number of findings written.
    """
    if not paths:
        return 0
    rules = custom_rule_files(rules_dir)
    if not rules:
        errors.append(f"custom rules: no .yml or .yaml rules in {rules_dir}")
        return 0
    suppressions = SourceSuppressions(lang)
    written = 0
    with tempfile.TemporaryDirectory(prefix="ubs-custom-rules-") as tmp:
        config = Path(tmp) / "sgconfig.yml"
        # JSON strings are valid YAML scalars for any path spelling.
        config.write_text("ruleDirs: " + json.dumps([str(p.resolve()) for p in rules]) + "\n",
                          encoding="utf-8")
        for match in scan_ast_config(config, list(paths), errors, ast_grep_bin=ast_grep_bin):
            severity = _CUSTOM_SEVERITY.get(match["severity"])
            if severity is None:
                continue  # severity: off
            rule = match["ruleId"]
            start = match["range"]["start"]
            line = start["line"] + 1
            if suppressions.is_suppressed(match["file"], line, rule):
                continue
            message = (match.get("message") or "").strip() or rule
            sink.write(json.dumps({
                "rule": rule, "category_id": "custom", "path": match["file"],
                "line": line, "col": start["column"] + 1, "severity": severity,
                "message": f"{rule}: {message}"[:300], "suppressed": False,
            }, ensure_ascii=False) + "\n")
            written += 1
    return written


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


class _ReportErrors:
    """Keep coverage failures visible without retaining every malformed row."""
    def __init__(self, errors: list[str], tool: str):
        self.errors, self.tool = errors, tool
        self.count = 0
        self.overflow: int | None = None

    def append(self, message: str) -> None:
        self.count += 1
        if self.count <= 4:
            self.errors.append(message[:400])
            return
        if self.overflow is None:
            self.overflow = len(self.errors)
            self.errors.append("")
        self.errors[self.overflow] = f"{self.tool}: {self.count - 4} additional report error(s)"


class _JSONReportReader:
    """Read JSON containers incrementally, bounding each decoded value.

    A vet package or diagnostic array may be arbitrarily large. Traverse
    those containers without materializing them; only keys and individual
    diagnostics (or govulncheck messages) use value(). Binary framing keeps
    a corrupt UTF-8 tail from erasing valid values earlier in the same read.
    """
    _CHUNK = 64 * 1024
    _DEPTH = 128
    _STRING_TOKEN = re.compile(rb'["\\]')
    _CONTAINER_TOKEN = re.compile(rb'[{}\[\]"]')
    _SCALAR_END = re.compile(rb'[\[\]{},:" \t\r\n]')
    _NON_SPACE = re.compile(rb'[^ \t\r\n]')

    def __init__(self, output: str | BinaryIO):
        self.source = BytesIO(output.encode("utf-8")) if isinstance(output, str) else output
        self.buffer = b""
        self.position = 0
        self.offset = 0
        self.eof = False

    def peek(self) -> bytes:
        if self.position == len(self.buffer) and not self.eof:
            self.offset += self.position
            self.buffer = self.source.read(self._CHUNK)
            self.position = 0
            self.eof = not self.buffer
        return self.buffer[self.position:self.position + 1]

    def token(self) -> bytes:
        while self.peek():
            match = self._NON_SPACE.search(self.buffer, self.position)
            self.position = match.start() if match else len(self.buffer)
            if match:
                return self.peek()
        return b""

    def error(self, message: str) -> ValueError:
        return ValueError(f"{message} at byte {self.offset + self.position}")

    def expect(self, token: bytes) -> None:
        if self.token() != token:
            raise self.error(f"expected {token.decode('ascii')!r}")
        self.position += 1

    @staticmethod
    def invalid_constant(name: str):
        raise ValueError(f"non-JSON numeric constant {name}")

    def value(self):
        first = self.token()
        if not first or first in (b",", b":", b"}", b"]"):
            raise self.error("expected JSON value")
        raw = bytearray()

        def take(end: int) -> None:
            if len(raw) + end - self.position > OUTPUT_RECORD_LIMIT:
                raise self.error(f"JSON value exceeds {OUTPUT_RECORD_LIMIT} bytes")
            raw.extend(self.buffer[self.position:end])
            self.position = end

        stack = [b"}" if first == b"{" else b"]"] if first in (b"{", b"[") else []
        quoted, escaped = first == b'"', False
        if stack or quoted:
            take(self.position + 1)
            while True:
                if not self.peek():
                    raise self.error("unterminated JSON value")
                if quoted:
                    if escaped:
                        take(self.position + 1)
                        escaped = False
                        continue
                    match = self._STRING_TOKEN.search(self.buffer, self.position)
                    take(match.end() if match else len(self.buffer))
                    if match:
                        if match.group() == b"\\":
                            escaped = True
                        else:
                            quoted = False
                            if not stack:
                                break
                else:
                    match = self._CONTAINER_TOKEN.search(self.buffer, self.position)
                    take(match.end() if match else len(self.buffer))
                    if not match:
                        continue
                    token = match.group()
                    if token == b'"':
                        quoted = True
                    elif token in (b"{", b"["):
                        stack.append(b"}" if token == b"{" else b"]")
                        if len(stack) > self._DEPTH:
                            raise self.error(f"JSON value nesting exceeds {self._DEPTH}")
                    else:
                        if token != stack.pop():
                            raise self.error("mismatched JSON delimiters")
                        if not stack:
                            break
        else:
            while self.peek():
                match = self._SCALAR_END.search(self.buffer, self.position)
                take(match.start() if match else len(self.buffer))
                if match:
                    break
        # Decode only after framing: a later invalid byte never prevents
        # earlier, independently complete diagnostics from being delivered.
        return json.loads(raw.decode("utf-8"), parse_constant=self.invalid_constant)

    def members(self) -> Iterator[str]:
        self.expect(b"{")
        if self.token() == b"}":
            self.position += 1
            return
        while True:
            if self.token() != b'"':
                raise self.error("expected JSON object key")
            name = self.value()
            self.expect(b":")
            yield name
            if self.token() == b"}":
                self.position += 1
                return
            self.expect(b",")

    def elements(self) -> Iterator[None]:
        self.expect(b"[")
        if self.token() == b"]":
            self.position += 1
            return
        while True:
            yield None
            if self.token() == b"]":
                self.position += 1
                return
            self.expect(b",")

    def documents(self, *, vet: bool = False) -> Iterator[None]:
        while self.token():
            if vet and self.peek() in (b"#", b"g"):
                # These are the only non-JSON records emitted by Go's vet
                # driver. Never search through arbitrary error text for JSON.
                prefix = b"# " if self.peek() == b"#" else b"go: downloading "
                for byte in prefix:
                    if self.peek() != bytes((byte,)):
                        raise self.error("unexpected text before JSON report")
                    self.position += 1
                size = len(prefix)
                while self.peek():
                    end = self.buffer.find(b"\n", self.position)
                    limit = end + 1 if end >= 0 else len(self.buffer)
                    size += limit - self.position
                    if size > OUTPUT_RECORD_LIMIT:
                        raise self.error(f"package heading exceeds {OUTPUT_RECORD_LIMIT} bytes")
                    self.position = limit
                    if end >= 0:
                        break
                continue
            yield None


def _json_stream(output: str | BinaryIO, tool: str, errors: _ReportErrors):
    """Decode every bounded stream message and retain a valid prefix."""
    try:
        reader = _JSONReportReader(output)
        for _ in reader.documents():
            yield reader.value()
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        errors.append(f"{tool}: invalid or truncated JSON report: {exc}")


class GoFindings:
    """Adapters for gofmt, go vet JSON and govulncheck's v1 message stream."""
    def __init__(self, files: Sequence[Path], root: Path, sink: TextIO) -> None:
        self.root, self.sink = root, sink
        self.selected = {p.resolve(): str(p) for p in files}
        self.suppressions = SourceSuppressions("go")
        self.seen: set[tuple] = set()
        self.module = ""
        try:
            for line in (root / "go.mod").read_text(encoding="utf-8").splitlines():
                fields = shlex.split(line, comments=True)
                if len(fields) >= 2 and fields[0] == "module":
                    self.module = fields[1]
                    break
        except (OSError, ValueError):
            pass  # the actual tools report an invalid or unavailable module

    def path(self, path: str) -> Path:
        file = Path(path)
        return (file if file.is_absolute() else self.root / file).resolve()

    def emit(self, tool: str, rule: str, path: str, line: int, col: int,
             severity: str, message: str, *, project: bool = False,
             extras: dict | None = None) -> None:
        file = self.path(path)
        rule = "go." + tool + "." + re.sub(r"[^A-Za-z0-9_.-]", "-", rule)
        if not project and file not in self.selected:
            return
        if not project and self.suppressions.is_suppressed(file, line, rule):
            return
        key = (rule, str(file), line, col, message)
        if key in self.seen:
            return
        self.seen.add(key)
        metadata = {"tool": tool, **(extras or {})}
        if project:
            metadata["scope"] = "project"
        self.sink.write(json.dumps({
            "rule": rule, "category_id": "golang.tooling", "path": self.selected.get(file, str(file)),
            "line": line, "col": col, "severity": severity, "message": message[:500],
            "suppressed": False, "extras": metadata,
        }, ensure_ascii=False) + "\n")

    def vet(self, output: str | BinaryIO, errors: list[str]) -> None:
        # In JSON mode even analysis errors may exit 0. Inspect both the
        # package/analyzer error objects and the actual diagnostic arrays.
        # See Go's analysis/unitchecker and analysis/internal/analysisflags.
        documents = 0
        problems = _ReportErrors(errors, "go vet")
        try:
            reader = _JSONReportReader(output)
            for _ in reader.documents(vet=True):
                documents += 1
                if reader.token() != b"{":
                    reader.value()
                    problems.append("go vet: expected package object")
                    continue
                for package in reader.members():
                    if reader.token() != b"{":
                        reader.value()
                        problems.append(f"go vet: malformed package {package[:120]!r}")
                        continue
                    for analyzer in reader.members():
                        if reader.token() != b"[":
                            rows = reader.value()
                            if isinstance(rows, dict) and "error" in rows:
                                problems.append(f"go vet ({analyzer[:120]}): {str(rows['error'])[:200]}")
                            else:
                                problems.append(f"go vet ({analyzer[:120]}): expected diagnostic array")
                            continue
                        for _ in reader.elements():
                            row = reader.value()
                            try:
                                match = re.fullmatch(r"(.+):(\d+):(\d+)", _text(row["posn"]), re.S)
                                if not match:
                                    raise ValueError("invalid source position")
                                self.emit("vet", _text(analyzer), match[1], _positive(int(match[2])),
                                          _positive(int(match[3])), "warning", _text(row["message"]),
                                          extras={"package": package})
                            except (KeyError, TypeError, ValueError, OSError):
                                problems.append(f"go vet ({analyzer[:120]}): malformed diagnostic")
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            problems.append(f"go vet: invalid or truncated JSON report: {exc}")
        if not documents:
            problems.append("go vet: no JSON analysis report")

    def govulncheck(self, output: str | BinaryIO, errors: list[str]) -> None:
        # JSON mode exits 0 even with vulnerabilities. OSV messages are NOT
        # findings: they include advisories not affecting the loaded version.
        # Lower-precision module/package messages precede symbol findings.
        # https://pkg.go.dev/golang.org/x/vuln/internal/govulncheck
        advisories: dict[str, dict] = {}
        groups: dict[tuple[str, str], list[tuple[int, dict]]] = {}
        config = False
        problems = _ReportErrors(errors, "govulncheck")
        for index, doc in enumerate(_json_stream(output, "govulncheck", problems)):
            try:
                if not isinstance(doc, dict) or len(doc) != 1:
                    raise ValueError("expected one message field")
                kind, value = next(iter(doc.items()))
                if not isinstance(value, dict):
                    raise ValueError(f"invalid {kind} message")
                if index == 0 and kind != "config":
                    problems.append("govulncheck: missing initial configuration")
                if kind == "config":
                    if config or value.get("protocol_version") != "v1.0.0":
                        raise ValueError("duplicate or unsupported protocol configuration")
                    config = True
                    if value.get("scan_level", "symbol") != "symbol":
                        raise ValueError("symbol-level analysis did not run")
                elif kind == "osv":
                    advisories[_text(value["id"])] = value
                elif kind == "finding":
                    osv, trace = _text(value["osv"]), _array(value, "trace")
                    if not trace or any(not isinstance(frame, dict) for frame in trace):
                        raise ValueError("invalid finding trace")
                    first = trace[0]
                    module = _text(first["module"])
                    if any(not isinstance(first.get(k, ""), str) for k in ("package", "function", "version")):
                        raise ValueError("invalid vulnerable frame")
                    if not isinstance(value.get("fixed_version", ""), str):
                        raise ValueError("invalid fixed version")
                    level = 2 if first.get("function") else 1 if first.get("package") else 0
                    groups.setdefault((osv, module), []).append((level, value))
                elif kind not in ("progress", "SBOM"):
                    raise ValueError(f"unknown message {kind!r}")
            except (ValueError, KeyError, TypeError):
                problems.append("govulncheck: malformed or unsupported stream message")
        if not config:
            problems.append("govulncheck: no valid configuration message")
        for (osv, module), rows in sorted(groups.items()):
            strongest = max(level for level, _ in rows)
            for level, row in rows:
                if level != strongest:
                    continue
                trace = row["trace"]
                path, line, col, project = "go.mod", 1, 1, True
                local_positions = False
                invalid = False
                for frame in trace:
                    # Positions belong to the frame's MODULE, not the cwd.
                    # Never attribute a dependency's main.go to ours.
                    if not self.module or frame.get("module") != self.module:
                        continue
                    pos = frame.get("position")
                    if pos is None:
                        continue
                    try:
                        name = _text(pos["filename"])
                        loc_line, loc_col = _positive(pos["line"]), _positive(pos["column"])
                        local_positions = True
                        if self.path(name) in self.selected:
                            path, line, col, project = name, loc_line, loc_col, False
                            break
                    except (ValueError, KeyError, TypeError, OSError):
                        invalid = True
                        problems.append("govulncheck: malformed source location")
                if invalid or (local_positions and project):
                    continue  # a trace into unselected source is not a selected-file finding
                reachability = ("module", "package", "symbol")[level]
                advisory = advisories.get(osv, {})
                title = advisory.get("summary") or advisory.get("details") or "Known vulnerability"
                title = str(title).splitlines()[0][:240]
                version, fixed = trace[0].get("version", ""), row.get("fixed_version", "")
                detail = "vulnerable symbol called" if level == 2 else "no vulnerable call found"
                message = f"{osv}: {title}; {module}@{version} ({detail})"
                message += f"; fixed in {fixed}" if fixed else "; no fixed version reported"
                self.emit("govulncheck", osv, path, line, col,
                          "critical" if level == 2 else "info", message, project=project,
                          extras={"osv": osv, "module": module, "found_version": version,
                                  "fixed_version": fixed, "reachability": reachability, "trace": trace})


def scan_go_tools(files: Sequence[Path], sink: TextIO, project_dir: str,
                  packages: str, timeout: float, errors: list[str]) -> list[dict]:
    """Run opt-in Go tools, preserving selected source and project context.

    gofmt is read-only. go vet/govulncheck load whole packages to resolve types
    and calls, but source diagnostics cannot re-admit excluded files. Multiple
    selected modules are analyzed independently; tools never use the caller's
    unrelated working directory or a source-only cached tool report.
    """
    sources = list(dict.fromkeys(p.resolve() for p in files if p.suffix == ".go"))
    if not sources:
        return [{"tool": t, "status": "skipped", "reason": "no selected Go source files"}
                for t in ("gofmt", "go vet", "govulncheck")]
    try:
        patterns = shlex.split(packages)
        if not patterns or any(p.startswith("-") for p in patterns):
            raise ValueError("expected package patterns, not tool options")
    except ValueError as exc:
        errors.append(f"go tools: invalid --test-pkgs: {exc}")
        return [{"tool": "go tools", "status": "partial"}]
    project = Path(project_dir or ".").resolve()
    project = project.parent if project.is_file() else project
    roots: dict[Path, list[Path]] = {}
    for file in sources:
        root = next((p for p in file.parents if (p / "go.mod").is_file()), project)
        roots.setdefault(root, []).append(file)
    outcomes = []
    env = dict(os.environ, NO_COLOR="1")
    for root, selected in sorted(roots.items()):
        findings = GoFindings(selected, root, sink)
        for tool, executable in (("gofmt", "gofmt"), ("go vet", "go"), ("govulncheck", "govulncheck")):
            installed = shutil.which(executable)
            outcome = {"tool": tool, "root": str(root)}
            if not installed:
                outcomes.append({**outcome, "status": "skipped", "reason": "not installed"})
                continue
            before = len(errors)
            # One gofmt input makes its filename-only output unambiguous even
            # for names containing newlines. No -w: scanning never formats code.
            batches = [["-s", "-l", "--", str(p)] for p in selected] if tool == "gofmt" else [
                ["vet", "-json", "--", *patterns] if tool == "go vet"
                else ["-format=json", "-scan=symbol", *patterns]]
            for args in batches:
                if tool != "gofmt":
                    with run_command_stream(tool, [installed, *args], root, timeout, errors,
                                            env=env, merge_stderr=tool == "go vet") as result:
                        if result is None:
                            continue
                        # EOF establishes JSON framing, not native success.
                        # Both tools can leave useful findings on a bad exit;
                        # vet JSON analysis-error objects may even exit zero.
                        if result.returncode != 0:
                            errors.append(f"{tool}: exited {result.returncode}: {result.stderr.strip()[:160]}")
                        if tool == "go vet":
                            findings.vet(result.stdout, errors)
                        else:
                            findings.govulncheck(result.stdout, errors)
                    continue
                # A single filename cannot grow with the project's findings;
                # keep gofmt's existing bounded, exact-name report contract.
                result = run_command(tool, [installed, *args], root, timeout, errors, env=env)
                if result is None:
                    continue
                if result.returncode != 0:
                    errors.append(f"{tool}: exited {result.returncode}: {result.stderr.strip()[:160]}")
                if result.stdout == args[-1] + "\n":
                    findings.emit("gofmt", "format", args[-1], 1, 1, "info",
                                  "File differs from gofmt -s formatting")
                elif result.stdout:
                    errors.append("gofmt: unexpected filename report")
            outcomes.append({**outcome, "status": "partial" if len(errors) != before else "ok"})
    return outcomes
