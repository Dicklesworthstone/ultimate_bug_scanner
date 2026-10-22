#!/usr/bin/env python3
"""Real CLI checks for the four languages supporting UBS_KEEP_TEMP=1.

Run with PYTHONDONTWRITEBYTECODE=1. Every fixture, report and syscall trace is
retained below test-suite/artifacts/keep-temp-*. No cleanup-mode scan is run.
The repeat-run comparison checks determinism in retention mode; it does not
claim equivalence to an unexecuted cleanup-mode baseline or all 13 languages.
"""
from __future__ import annotations

import hashlib
import ctypes
import datetime
import errno
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "test-suite" / "artifacts"
SEVERITIES = ("critical", "warning", "info")
CASES = {
    "rust": ("rs", "rust.ownership.unwrap-expect", "warning",
             "pub fn number(text: &str) -> u32 {\n    text.parse::<u32>().unwrap()\n}\n",
             "pub fn number(text: &str) -> Result<u32, std::num::ParseIntError> {\n"
             "    text.parse::<u32>()\n}\n"),
    "python": ("py", "py.security.eval-exec-usage", "critical",
               "def evaluate(text):\n    return eval(text)\n",
               "def total(values):\n    return sum(values)\n"),
    "js": ("js", "js.security.eval", "critical",
           "export function evaluate(text) {\n  return eval(text);\n}\n",
           "export function double(value) {\n  return value + value;\n}\n"),
    "bash": ("sh", "bash.security.eval_variable", "critical",
             '#!/usr/bin/env bash\npayload="${1:-}"\neval "$payload"\n',
             "#!/usr/bin/env bash\nprintf '%s\\n' 'ready'\n"),
}
DELETION_GUARD = {"backend": "libseccomp.so.2", "default": "ALLOW",
                  "denied_syscalls": ["unlink", "unlinkat", "rmdir"],
                  "action": "ERRNO(EPERM)", "installed_before": "strace exec"}
RUST_PHASE_INFO = [
    ("rust.lints.phase", "Not evaluated: formatting (cargo fmt --check) and lints (cargo clippy)"),
    ("rust.build.phase", "Not evaluated: compilation (cargo check) and test build (cargo test --no-run)"),
    ("rust.dependencies.phase", "Not evaluated: dependency hygiene (cargo audit / deny / udeps / outdated)"),
    ("rust.dependencies.phase", "No Cargo.toml at project root (workspace? set PROJECT_DIR accordingly)"),
]


def seccomp_library():
    """Require the real system library; no subprocess or permissive fallback."""
    try:
        library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError as exc:
        raise RuntimeError("real CLI tests require libseccomp.so.2; no scanner was started") from exc
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                        ctypes.c_int, ctypes.c_uint]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_release.restype = None
    return library


def prevent_child_deletion() -> None:
    """Install a kernel safety fence, never substitute scanner results.

    Applied in the child before exec, inherited by its complete process tree.
    Any denied attempt remains a trace assertion failure, even if a scanner
    ignores EPERM. No deletion probe is used to check this guard.
    """
    try:
        library = seccomp_library()
        context = library.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
        if not context:
            raise RuntimeError(f"seccomp_init failed: errno={ctypes.get_errno()}")
        try:
            for name in DELETION_GUARD["denied_syscalls"]:
                number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
                if number < 0:
                    raise RuntimeError(f"cannot resolve seccomp syscall {name}: {number}")
                result = library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0)
                if result != 0:
                    raise RuntimeError(f"seccomp_rule_add({name}) failed: {result}")
            result = library.seccomp_load(context)
            if result != 0:
                raise RuntimeError(f"seccomp_load failed: {result}")
        finally:
            library.seccomp_release(context)  # void; no return value to ignore
        os.write(2, b"test_keep_temp: inherited seccomp no-deletion guard installed\n")
    except BaseException as exc:
        os.write(2, f"test_keep_temp: refusing execution; deletion guard failed: {exc}\n".encode())
        os._exit(126)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest(path: Path) -> str:
    if path.is_file():
        return digest(path)
    files = {str(file.relative_to(path)): digest(file)
             for file in sorted(path.rglob("*")) if file.is_file()}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def scanner_assets() -> dict[str, str]:
    """Bind execution to real runner/module/helper bytes, without changing pins."""
    paths = [ROOT / "ubs", ROOT / "modules" / "contract.json"]
    paths.extend((ROOT / "modules").glob("ubs-*.sh"))
    for directory in (ROOT / "modules" / "lib", ROOT / "modules" / "helpers"):
        paths.extend(path for path in directory.rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def trace_observations(lines: list[str], temp_root: Path) -> dict:
    """Inspect actual syscalls, including unsuccessful deletion attempts."""
    created: set[str] = set()
    removals: list[str] = []
    publications: list[dict] = []
    executions: list[str] = []
    prefix = str(temp_root) + os.sep
    for line in lines:
        call = re.match(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?([a-zA-Z0-9_]+)\(", line)
        if call is None:
            continue
        name = call.group(1)
        if name in ("unlink", "unlinkat", "rmdir"):
            removals.append(line)
        if name == "execve":
            executions.append(line)
        quoted = re.findall(r'"(?:[^"\\]|\\.)*"', line)
        if not quoted:
            continue
        try:
            path = json.loads(quoted[0])
        except json.JSONDecodeError as exc:
            raise AssertionError(f"unreadable syscall path: {line}") from exc
        if name in ("rename", "renameat", "renameat2"):
            if len(quoted) > 1 and re.search(r"\)\s+=\s+0\b", line):
                publications.append({"source": path, "destination": json.loads(quoted[1]),
                                     "syscall": line})
        if name in ("open", "openat", "openat2") and "O_CREAT" in line:
            result = re.search(r"\)\s+=\s+\d+<([^>]+)>", line)
            if result and result.group(1).startswith(prefix):
                created.add(result.group(1))
        elif name in ("mkdir", "mkdirat") and re.search(r"\)\s+=\s+0\b", line):
            if path.startswith(prefix):
                created.add(path)
    return {"created_paths": sorted(created), "removal_calls": removals,
            "publications": publications, "executions": executions}


def normalized_result(document: dict) -> dict:
    """Keep findings/counts; the schema permits an absent empty clean ledger."""
    return {
        "status": document.get("status"),
        "totals": document["totals"],
        "scanners": [{key: scanner[key] for key in ("language", "files", *SEVERITIES)}
                     for scanner in document["scanners"]],
        "findings": sorted(document.get("findings", []), key=lambda value: json.dumps(value, sort_keys=True)),
    }


def is_wrapper_exec(line: str) -> bool:
    """Do not mistake realpath/dirname's script argument for a Bash wrapper."""
    if not line.startswith("execve(") or not re.search(r"\)\s+=\s+0\b", line):
        return False
    words = re.findall(r'"(?:[^"\\]|\\.)*"', line)
    return (len(words) >= 3 and Path(json.loads(words[0])).name == "bash"
            and words[1] == '"bash"' and words[2] == json.dumps(str(ROOT / "ubs")))


def interrupt_live_analyzer(process: subprocess.Popen, run: Path) -> dict:
    """Signal only the owned wrapper after a real JS analyzer exec is observed."""
    offsets: dict[Path, int] = {}
    wrapper_fd = None
    evidence = {"sent": False, "wrapper_pid": None, "analyzer_pid": None}
    deadline = time.monotonic() + 120
    try:
        while process.poll() is None:
            for trace in run.glob("trace.*"):
                with trace.open(encoding="utf-8") as stream:
                    stream.seek(offsets.get(trace, 0))
                    lines = stream.readlines()
                    offsets[trace] = stream.tell()
                for line in lines:
                    if not line.startswith("execve(") or not re.search(r"\)\s+=\s+0\b", line):
                        continue
                    pid = int(trace.name.rsplit(".", 1)[1])
                    if wrapper_fd is None and is_wrapper_exec(line):
                        try:
                            status = Path(f"/proc/{pid}/status").read_text()
                            if re.search(rf"^PPid:\s+{process.pid}$", status, re.MULTILINE):
                                wrapper_fd = os.pidfd_open(pid)
                                evidence["wrapper_pid"] = pid
                        except (FileNotFoundError, ProcessLookupError):
                            continue  # The observed process already exited.
                    if '"ubs_core.js_scan"' in line:
                        evidence["analyzer_pid"] = pid
            if wrapper_fd is not None and evidence["analyzer_pid"] is not None:
                signal.pidfd_send_signal(wrapper_fd, signal.SIGINT)
                evidence["sent"] = True
                return evidence
            if time.monotonic() >= deadline:
                if wrapper_fd is None:
                    raise AssertionError("no owned UBS wrapper observed before interrupt deadline")
                signal.pidfd_send_signal(wrapper_fd, signal.SIGTERM)
                evidence["deadline_termination"] = True
                return evidence
            time.sleep(0.05)
        return evidence
    finally:
        if wrapper_fd is not None:
            os.close(wrapper_fd)


class TraceParsingTests(unittest.TestCase):
    def test_interrupt_identifies_only_actual_bash_script_exec(self) -> None:
        script = json.dumps(str(ROOT / "ubs"))
        self.assertTrue(is_wrapper_exec(f'execve("/usr/bin/bash", ["bash", {script}], 0x0) = 0'))
        for tool in ("realpath", "dirname"):
            self.assertFalse(is_wrapper_exec(
                f'execve("/usr/bin/{tool}", ["{tool}", {script}], 0x0) = 0'))

    def test_counts_real_creations_and_all_removal_attempts(self) -> None:
        tmp = Path("/retained-test/tmp")
        result = trace_observations([
            'openat(AT_FDCWD, "/retained-test/tmp/a", O_WRONLY|O_CREAT, 0600) = 3</retained-test/tmp/a>',
            'openat(AT_FDCWD, "/retained-test/tmp/missing", O_WRONLY|O_CREAT, 0600) = -1 EACCES',
            'openat(AT_FDCWD, "/retained-test/tmp/read-only", O_RDONLY) = 4</retained-test/tmp/read-only>',
            'mkdir("/retained-test/tmp/rules", 0700) = 0',
            'unlink("/retained-test/tmp/a") = -1 ENOENT',
            'unlinkat(AT_FDCWD, "/retained-test/tmp/b", 0) = 0',
            'rmdir("/retained-test/tmp/rules") = 0',
            'rename("/retained-test/tmp/a", "/retained-test/report") = 0',
            'execve("/usr/bin/python3", ["python3", "-c", "path.unlink()"], 0x0) = 0',
        ], tmp)
        self.assertEqual(result["created_paths"], [str(tmp / "a"), str(tmp / "rules")])
        self.assertEqual(len(result["removal_calls"]), 3)
        self.assertEqual(result["publications"][0]["destination"], "/retained-test/report")


@unittest.skipUnless(sys.platform == "linux", "Linux syscall/ seccomp integration checks")
class KeepTempCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        seccomp_library()  # Fail before any scan if the real library is absent.
        for tool in ("strace", "bash", "jq", "rg", "ast-grep", "python3"):
            if shutil.which(tool) is None:
                raise AssertionError(f"real CLI retention checks require {tool}; nothing was scanned")

    def setUp(self) -> None:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="keep-temp-", dir=ARTIFACTS))
        print(f"[{self.id()}] persistent artifacts: {self.root}", flush=True)
        self.sequence = 0
        self.git_sequence = 0

    def source(self, name: str, text: str) -> Path:
        project = self.root / (name + "-project")
        project.mkdir()
        path = project / name
        path.write_text(text, encoding="utf-8")
        return path

    def fixture_git(self, project: Path, *arguments: str,
                    input_text: str | None = None) -> str:
        """Real fixture Git commands inherit the same no-deletion fence."""
        self.git_sequence += 1
        evidence = self.root / f"git-setup-{self.git_sequence:02d}"
        evidence.mkdir()
        (evidence / "tmp").mkdir()
        env = dict(os.environ, TMPDIR=str(evidence / "tmp"),
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        command = ["strace", "-ff", "-qq", "-s", "4096", "-yy", "-e", "trace=%file",
                   "-o", str(evidence / "trace"), "git", "-c", "core.hooksPath=/dev/null",
                   "-c", "core.fsmonitor=false", "-C", str(project), *arguments]
        result = subprocess.run(command, env=env, capture_output=True, text=True,
                                input=input_text, check=False, timeout=30,
                                preexec_fn=prevent_child_deletion)
        (evidence / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (evidence / "stderr.log").write_text(result.stderr, encoding="utf-8")
        sys.stderr.write(result.stderr)
        lines = [line for path in sorted(evidence.glob("trace.*"))
                 for line in path.read_text(encoding="utf-8").splitlines()]
        observations = trace_observations(lines, evidence / "tmp")
        (evidence / "receipt.json").write_text(json.dumps(
            {"command": command, "exit": result.returncode, "deletion_guard": DELETION_GUARD,
             **observations}, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, f"fixture Git failed: {evidence}\n{result.stderr}")
        # Git init probes filesystem behavior with a temporary file. Its
        # attempted cleanup must be denied and retained, separately recorded
        # from scanner runs, where even an unsuccessful attempt is failure.
        for removal in observations["removal_calls"]:
            self.assertRegex(removal, r"= -1 EPERM\b", f"fixture deletion was not denied: {evidence}")
        return result.stdout

    def fixture_object(self, project: Path, kind: str, contents: str) -> str:
        """Write authentic loose objects without Git's temporary-object unlink.

        These are real Git objects, independently decoded by git cat-file;
        no scanner response, executable, or detector input is substituted.
        """
        payload = contents.encode("utf-8")
        encoded = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0" + payload
        object_id = hashlib.sha1(encoded, usedforsecurity=False).hexdigest()
        destination = project / ".git" / "objects" / object_id[:2] / object_id[2:]
        destination.parent.mkdir(exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(zlib.compress(encoded))
        self.assertEqual(self.fixture_git(project, "cat-file", kind, object_id), contents)
        return object_id

    def staged_project(self, name: str, *, unmerged: bool) -> tuple[Path, Path]:
        project = self.root / name
        project.mkdir()
        self.fixture_git(project, "init", "--object-format=sha1", "--initial-branch=main")
        empty_tree = self.fixture_object(project, "tree", "")
        commit = self.fixture_object(project, "commit",
            f"tree {empty_tree}\n"
            "author Retention Test <retention@example.invalid> 1700000000 +0000\n"
            "committer Retention Test <retention@example.invalid> 1700000000 +0000\n"
            "\nReal staged retention fixture\n")
        self.fixture_git(project, "update-ref", "refs/heads/main", commit)
        self.assertEqual(self.fixture_git(project, "symbolic-ref", "HEAD"), "refs/heads/main\n")
        self.assertEqual(self.fixture_git(project, "rev-parse", "HEAD"), commit + "\n")
        source = project / "control.py"
        source.write_text(CASES["python"][4], encoding="utf-8")
        bad = self.fixture_object(project, "blob", CASES["python"][3])
        if unmerged:
            base = self.fixture_object(project, "blob", "def total(values):\n    return len(values)\n")
            theirs = self.fixture_object(project, "blob", "def total(values):\n    return max(values)\n")
            entries = "".join(f"100644 {oid} {stage}\tcontrol.py\n"
                              for stage, oid in ((1, base), (2, bad), (3, theirs)))
        else:
            entries = f"100644 {bad} 0\tcontrol.py\n"
        self.fixture_git(project, "update-index", "--index-info", input_text=entries)
        actual = self.fixture_git(project, "ls-files", "--stage")
        self.assertEqual(actual, entries)
        return project, source

    def run_scan(self, language: str, target: Path, *extra: str,
                 environment: dict[str, str] | None = None,
                 command_mode: str | None = None,
                 report_destination: Path | None = None,
                 interrupt: bool = False) -> tuple[subprocess.CompletedProcess, dict, Path]:
        self.sequence += 1
        run = self.root / f"run-{self.sequence:02d}-{language}"
        run.mkdir()
        for name in ("cwd", "tmp", "config", "cache", "data", "state", "tools"):
            (run / name).mkdir()
        # Inherited UBS test seams or skip settings must not substitute a
        # partial detector for the normal CLI. HOME and PATH are preserved.
        env = {key: value for key, value in os.environ.items() if not key.startswith("UBS_")}
        env.update(UBS_KEEP_TEMP="1", UBS_NO_CACHE="1", UBS_NO_AUTO_UPDATE="1",
                   UBS_ENABLE_AUTO_UPDATE="0", PYTHONDONTWRITEBYTECODE="1",
                   NO_COLOR="1", TMPDIR=str(run / "tmp"), TMP=str(run / "tmp"),
                   TEMP=str(run / "tmp"), XDG_CONFIG_HOME=str(run / "config"),
                   XDG_CACHE_HOME=str(run / "cache"), XDG_DATA_HOME=str(run / "data"),
                   XDG_STATE_HOME=str(run / "state"), UBS_TOOLS_DIR=str(run / "tools"))
        if environment:
            env.update(environment)
        report_destination = report_destination or run / "requested-report.json"
        arguments = ([command_mode] if command_mode else [
            f"--module-dir={ROOT / 'modules'}", f"--only={language}",
            "--format=json", "--ci", "--no-cache", "--no-auto-update",
            "--fail-on-warning", f"--report-json={report_destination}", *extra, str(target),
        ])
        command = ["strace", "-ff", "-qq", "-s", "4096", "-yy", "-e", "trace=%file",
                   "-o", str(run / "trace"), "bash", str(ROOT / "ubs"),
                   *arguments]
        before_assets, before_source = scanner_assets(), source_digest(target)
        started = time.monotonic()
        interrupt_evidence = None
        if interrupt:
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise AssertionError("genuine interrupt check requires Linux pidfd support")
            probe = os.pidfd_open(os.getpid())
            os.close(probe)  # Capability check only; no signal or deletion probe.
            # Persistent streams also retain diagnostics if observation itself
            # raises, and cannot block a real analyzer on a full capture pipe.
            with (run / "stdout.json").open("w", encoding="utf-8") as stdout_file, \
                    (run / "stderr.log").open("w", encoding="utf-8") as stderr_file:
                process = subprocess.Popen(command, cwd=run / "cwd", env=env,
                                           stdout=stdout_file, stderr=stderr_file,
                                           start_new_session=True,
                                           preexec_fn=prevent_child_deletion)
                try:
                    interrupt_evidence = interrupt_live_analyzer(process, run)
                finally:
                    try:
                        process.wait(timeout=45)
                    except subprocess.TimeoutExpired:
                        # This session contains only this guarded invocation.
                        # A timeout remains failure, never a simulated SIGINT.
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=15)
                        if interrupt_evidence is not None:
                            interrupt_evidence["reap_timeout"] = True
            stdout = (run / "stdout.json").read_text(encoding="utf-8")
            stderr = (run / "stderr.log").read_text(encoding="utf-8")
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        else:
            result = subprocess.run(command, cwd=run / "cwd", env=env,
                                    capture_output=True, text=True, timeout=180, check=False,
                                    preexec_fn=prevent_child_deletion)
        (run / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (run / "stderr.log").write_text(result.stderr, encoding="utf-8")
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()
        trace_files = sorted(run.glob("trace.*"))
        lines = [line for path in trace_files for line in path.read_text(encoding="utf-8").splitlines()]
        observations = trace_observations(lines, run / "tmp")
        for publication in observations["publications"]:
            destination = Path(publication["destination"])
            if destination.is_file():
                publication["destination_sha256"] = digest(destination)
                publication["destination_bytes"] = destination.stat().st_size
        receipt = {"command": command, "exit": result.returncode,
                   "seconds": time.monotonic() - started, "target_sha256": before_source,
                   "test_source_sha256": digest(Path(__file__)),
                   "deletion_guard": DELETION_GUARD,
                   "interrupt": interrupt_evidence,
                   "scanner_assets": before_assets, "trace_files": len(trace_files),
                   **observations}
        (run / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        context = f"artifacts={run}, exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        self.assertTrue(trace_files, context)
        self.assertEqual(scanner_assets(), before_assets, "scanner execution changed verified assets\n" + context)
        self.assertEqual(source_digest(target), before_source, "scanner modified source\n" + context)
        self.assertEqual(observations["removal_calls"], [], "deletion syscall attempted\n" + context)
        publications = {record["source"]: record["destination"]
                        for record in observations["publications"]}
        for record in observations["publications"]:
            source, destination = Path(record["source"]), Path(record["destination"])
            self.assertTrue(source.is_absolute() and destination.is_absolute(), context)
            self.assertTrue(source.is_relative_to(run) and destination.is_relative_to(run), context)
            self.assertTrue(destination.is_file(), "published evidence disappeared\n" + context)
            self.assertEqual(digest(destination), record["destination_sha256"], context)
        # Atomic report publication retains the bytes at the destination,
        # rather than preserving an obsolete staging pathname. Other scratch
        # paths must still exist. Follow a publication chain, never a cycle.
        missing = []
        for path in observations["created_paths"]:
            current, visited = path, set()
            while current in publications:
                self.assertNotIn(current, visited, context)
                visited.add(current)
                current = publications[current]
            if not Path(current).exists():
                missing.append(path)
        self.assertEqual(missing, [], "scanner-created temporary paths disappeared\n" + context)
        return result, observations, run

    def checked_report(self, language: str, source: Path, *extra: str,
                       buggy: bool, finding_name: str | None = None) -> tuple[dict, int]:
        result, observations, run = self.run_scan(language, source, *extra)
        context = f"{run}\n{result.stdout}\n{result.stderr}"
        self.assertEqual(result.returncode, 1 if buggy else 0, context)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok", context)
        self.assertEqual(document["totals"]["files"], 1, context)
        self.assertEqual(len(document["scanners"]), 1, context)
        scanner = document["scanners"][0]
        self.assertIn(scanner["language"], (language, "javascript") if language == "js" else (language,), context)
        self.assertEqual(scanner["files"], 1, context)
        self.assertTrue(observations["created_paths"], "full scan created no observed temp paths\n" + context)
        self.assertTrue(list((run / "tmp").rglob("combined.json")), "no retained combined report\n" + context)
        published = json.loads((run / "requested-report.json").read_text(encoding="utf-8"))
        generated_at = published.pop("generated_at")
        self.assertIsInstance(generated_at, str, context)
        datetime.datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(published, document,
                         "published report differs beyond its documented generated_at metadata\n" + context)
        if language == "rust":
            # No Cargo.toml is supplied: the static detectors run, while the
            # four existing not-evaluated phase records must remain visible.
            # Neither a clean source nor retention means Cargo was evaluated.
            expected = sorted((rule, "info", "", 1, 1, message, False)
                              for rule, message in RUST_PHASE_INFO)
            actual = sorted((finding["rule_id"], finding["severity"], finding["file"],
                             finding["line"], finding["col"], finding["message"], finding["suppressed"])
                            for finding in document["findings"] if finding["severity"] == "info")
            self.assertEqual(actual, expected, context)
            self.assertEqual(document["totals"]["info"], 4, context)
        if buggy:
            _, rule, severity, _, _ = CASES[language]
            rules = (rule, "rust.parsing.parse-unwrap") if language == "rust" else (rule,)
            for expected_rule in rules:
                matching = [finding for finding in document["findings"] if finding.get("rule_id") == expected_rule]
                self.assertEqual(len(matching), 1, f"planted {expected_rule} lost or duplicated\n{context}")
                self.assertEqual(matching[0]["severity"], severity, context)
                self.assertEqual(matching[0]["line"], 3 if language == "bash" else 2, context)
                self.assertTrue(matching[0]["file"].endswith(finding_name or source.name), context)
            self.assertGreater(document["totals"][severity], 0, context)
            self.assertGreater(scanner[severity], 0, context)
        else:
            self.assertEqual({key: document["totals"][key] for key in SEVERITIES},
                             {"critical": 0, "warning": 0, "info": 4 if language == "rust" else 0}, context)
            if language != "rust":
                self.assertEqual(document.get("findings", []), [], context)
                self.assertEqual(scanner.get("findings", []), [], context)
        return normalized_result(document), result.returncode

    def test_four_languages_retain_temps_without_losing_findings(self) -> None:
        for language, (suffix, _, _, buggy, clean) in CASES.items():
            with self.subTest(language=language):
                bad = self.source("buggy-" + language + "." + suffix, buggy)
                good = self.source("clean-" + language + "." + suffix, clean)
                first = self.checked_report(language, bad, buggy=True)
                self.checked_report(language, good, buggy=False)
                repeated = self.checked_report(language, bad, buggy=True)
                self.assertEqual(repeated, first, "retention-mode findings, severities or exit changed across identical scans")

    def test_unsupported_php_refuses_before_module_execution(self) -> None:
        source = self.source("unsupported.php", '<?php eval($_GET["code"]);\n')
        (source.parent / "supported.py").write_text(CASES["python"][3], encoding="utf-8")
        for languages, target in (("php", source), ("python,php", source.parent)):
            with self.subTest(languages=languages):
                result, observations, run = self.run_scan(languages, target)
                context = f"{run}\n{result.stdout}\n{result.stderr}"
                self.assertEqual(result.returncode, 2, context)
                self.assertIn("UBS_KEEP_TEMP", result.stderr + result.stdout, context)
                self.assertIn("php", (result.stderr + result.stdout).lower(), context)
                self.assertEqual(json.loads(result.stdout)["reason"],
                                 "retention-unsupported-language", context)
                self.assertFalse(any(re.search(r"ubs-[a-z]+\.sh", line)
                                     for line in observations["executions"]), context)

    def test_early_retention_refusals_create_no_temporary_paths(self) -> None:
        source = self.source("control.py", CASES["python"][4])
        scenarios = [
            ("invalid-value", {"UBS_KEEP_TEMP": "invalid"}, None),
            ("legacy-compat-numeric", {"BASH_COMPAT": "50"}, None),
            ("legacy-compat-decimal", {"BASH_COMPAT": "5.0"}, None),
            *[(mode, {}, mode) for mode in ("doctor", "serve", "daemon", "--client", "--update")],
        ]
        for label, environment, mode in scenarios:
            with self.subTest(scenario=label):
                result, observations, run = self.run_scan(
                    "python", source, environment=environment, command_mode=mode)
                context = f"{run}\n{result.stdout}\n{result.stderr}"
                self.assertEqual(result.returncode, 2, context)
                self.assertIn("UBS_KEEP_TEMP", result.stderr + result.stdout, context)
                self.assertEqual(observations["created_paths"], [], context)
                self.assertFalse(any(re.search(r"ubs-[a-z]+\.sh", line)
                                     for line in observations["executions"]), context)

    def test_report_delivery_failure_keeps_completed_scan_evidence(self) -> None:
        source = self.source("control.py", CASES["python"][4])
        blocker = self.root / "regular-file-parent"
        blocker.write_text("preserve this regular file\n", encoding="utf-8")
        result, observations, run = self.run_scan(
            "python", source, report_destination=blocker / "report.json")
        context = f"{run}\n{result.stdout}\n{result.stderr}"
        self.assertEqual(result.returncode, 2, context)
        self.assertIn(str(blocker), result.stderr, context)
        self.assertEqual(blocker.read_text(encoding="utf-8"), "preserve this regular file\n", context)
        document = json.loads(result.stdout)
        self.assertEqual(document["totals"], {"files": 1, "critical": 0, "warning": 0, "info": 0}, context)
        self.assertTrue(observations["created_paths"], context)
        self.assertTrue(list((run / "tmp").rglob("combined.json")), context)
        self.assertFalse((blocker / "report.json").exists(), context)

    def test_large_valid_category_csv_preserves_the_planted_bug(self) -> None:
        source = self.source("large-control.py", CASES["python"][3])
        original = self.checked_report("python", source, buggy=True)
        # Category23 is valid but contributes no finding in this eval fixture.
        # Duplicates stress real shell CSV handling without suppressing either
        # security finding. Stay below Linux's per-argument128KiB limit.
        argument = "--skip=" + ",".join(["23"] * 22_000)
        self.assertGreater(len(argument.encode()), 64 * 1024)
        self.assertLess(len(argument.encode()), 128 * 1024)
        large = self.checked_report("python", source, argument, buggy=True)
        self.assertEqual(large, original, "large CSV changed findings, severities, counts or exit")

    def test_interrupt_retains_real_analyzer_scratch(self) -> None:
        source = self.source("interrupt.js", "".join(
            f"export function evaluate_{index}(text) {{ return eval(text); }}\n"
            for index in range(1_000)))
        result, observations, run = self.run_scan("js", source, interrupt=True)
        receipt = json.loads((run / "receipt.json").read_text(encoding="utf-8"))
        context = f"{run}\n{result.stdout}\n{result.stderr}"
        self.assertTrue(receipt["interrupt"]["sent"], context)
        self.assertNotIn("deadline_termination", receipt["interrupt"], context)
        self.assertNotIn("reap_timeout", receipt["interrupt"], context)
        self.assertIsNotNone(receipt["interrupt"]["analyzer_pid"], context)
        self.assertEqual(result.returncode, -signal.SIGINT, context)
        wrapper = run / f"trace.{receipt['interrupt']['wrapper_pid']}"
        self.assertIn("+++ killed by SIGINT +++", wrapper.read_text(encoding="utf-8"), context)
        self.assertTrue(observations["created_paths"], context)
        self.assertTrue(any(Path(path).is_file() for path in observations["created_paths"]), context)

    def test_staged_bug_uses_index_and_preserves_index_and_worktree(self) -> None:
        project, source = self.staged_project("staged-bug", unmerged=False)
        index = project / ".git" / "index"
        before_index, before_worktree = index.read_bytes(), source.read_bytes()
        # Actual staged blob contains eval; the unstaged working file is clean.
        self.checked_report("python", project, "--staged", buggy=True, finding_name="control.py")
        self.assertEqual(index.read_bytes(), before_index)
        self.assertEqual(source.read_bytes(), before_worktree)

    def test_unmerged_index_refuses_before_language_filter_and_modules(self) -> None:
        project, source = self.staged_project("unmerged-index", unmerged=True)
        index = project / ".git" / "index"
        before_index, before_worktree = index.read_bytes(), source.read_bytes()
        # Conflict is Python, but must be rejected even when only JS is selected.
        result, observations, run = self.run_scan("js", project, "--staged")
        context = f"{run}\n{result.stdout}\n{result.stderr}"
        self.assertEqual(result.returncode, 2, context)
        self.assertIn("unmerged", (result.stderr + result.stdout).lower(), context)
        self.assertEqual(json.loads(result.stdout)["reason"], "git-index-failed", context)
        self.assertFalse(any(re.search(r"ubs-[a-z]+\.sh", line)
                             for line in observations["executions"]), context)
        self.assertEqual(index.read_bytes(), before_index)
        self.assertEqual(source.read_bytes(), before_worktree)

    def test_unannotated_resource_leak_and_json_error_still_report(self) -> None:
        # Static source only: this code is never imported or executed. It must
        # remain reportable despite exact ownership/error-boundary annotations
        # on independently reviewed scanner helper call sites.
        source = self.source("unannotated.py",
            "import json\nimport tempfile\n"
            "def process(operator_text):\n"
            "    leaked = tempfile.NamedTemporaryFile(delete=False)\n"
            "    return json.loads(operator_text)\n")
        result, observations, run = self.run_scan("python", source)
        context = f"{run}\n{result.stdout}\n{result.stderr}"
        self.assertEqual(result.returncode, 1, context)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok", context)
        self.assertEqual(document["totals"]["files"], 1, context)
        self.assertEqual(len(document["scanners"]), 1, context)
        scanner = document["scanners"][0]
        self.assertEqual(scanner["language"], "python", context)
        self.assertEqual(scanner["files"], 1, context)
        for rule, severity, line in (("python.lifecycle.file_handle", "critical", 4),
                                     ("py.parsing.json-loads-no-try", "warning", 5)):
            matches = [finding for finding in document["findings"] if finding["rule_id"] == rule]
            self.assertEqual(len(matches), 1, context)
            self.assertEqual(matches[0]["severity"], severity, context)
            self.assertEqual(matches[0]["line"], line, context)
            self.assertTrue(matches[0]["file"].endswith("unannotated.py"), context)
            self.assertFalse(matches[0]["suppressed"], context)
            self.assertGreater(document["totals"][severity], 0, context)
            self.assertGreater(scanner[severity], 0, context)
        self.assertTrue(observations["created_paths"], context)
        self.assertTrue(list((run / "tmp").rglob("combined.json")), context)


if __name__ == "__main__":
    unittest.main(verbosity=2)
