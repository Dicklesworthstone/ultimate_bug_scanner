#!/usr/bin/env python3
"""Regression tests for shell file admission and NUL-delimited file counting.

Issue #81: safe_count_files() counted the NUL separators emitted by
``find -print0`` with awk's ``gsub(/\\0/, "")``. busybox awk terminates strings
at the first NUL, so that expression resolves to 0 and the scan reported zero
scanned files - which aborts the manifest case before it reaches any finding
assertion. The counter must not depend on awk's NUL handling at all.
"""
from __future__ import annotations

import json
import os
import shutil
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULES_WITH_COUNTER = ("modules/ubs-elixir.sh", "modules/ubs-ruby.sh")


def extract_safe_count_files(module_path: Path) -> str:
    for line in module_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("safe_count_files()"):
            return line
    raise AssertionError(f"safe_count_files() definition not found in {module_path}")


class SafeCountFilesTest(unittest.TestCase):
    def test_counts_nul_delimited_paths_without_awk(self) -> None:
        """The counter must survive an awk that cannot report NUL bytes.

        Stubbing awk out entirely is a stricter stand-in for busybox awk: if the
        count still depends on awk in any way the assertion below fails, exactly
        as it did before the fix.
        """
        stub_dir = Path(tempfile.mkdtemp(prefix="ubs-awk-stub-"))
        try:
            stub = stub_dir / "awk"
            stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"

            for rel in MODULES_WITH_COUNTER:
                with self.subTest(module=rel):
                    definition = extract_safe_count_files(REPO_ROOT / rel)
                    script = f"{definition}\nsafe_count_files\n"
                    result = subprocess.run(  # ubs:ignore[py.security.command-injection] Fixed repo module definition; no external input.
                        ["bash", "-c", script],
                        input=b"one.ex\0two.ex\0three.ex\0",
                        capture_output=True,
                        env=env,
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(
                        result.stdout.decode("utf-8", "replace").strip(),
                        "3",
                        f"{rel}: safe_count_files must count NUL-delimited paths "
                        f"without awk (stderr: {result.stderr!r})",
                    )
        finally:
            shutil.rmtree(stub_dir, ignore_errors=True)

    def test_counts_zero_for_empty_input(self) -> None:
        for rel in MODULES_WITH_COUNTER:
            with self.subTest(module=rel):
                definition = extract_safe_count_files(REPO_ROOT / rel)
                result = subprocess.run(  # ubs:ignore[py.security.command-injection] Fixed repo module definition; no external input.
                    ["bash", "-c", f"{definition}\nsafe_count_files\n"],
                    input=b"",
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.stdout.decode("utf-8", "replace").strip(), "0")


class ExtensionlessShellAdmissionTest(unittest.TestCase):
    def _check_extensionless_shell_admission(self, *, mode: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs-shell-admission-") as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            shell_scripts = {
                "env-bash": "#!/usr/bin/env bash",
                "env-sh": "#!/usr/bin/env sh",
                "env-split-bash": "#!/usr/bin/env -S bash -e",
                "direct-bash": "#!/bin/bash",
            }
            contents = {
                name: shebang + '\ncommand="${1:-}"\neval "$command"\n'
                for name, shebang in shell_scripts.items()
            }
            contents.update({
                "python-script": '#!/usr/bin/env python3\nprint("hello")\n',
                "ordinary-text": 'Shell documentation example:\neval "$command"\n',
                # The interpreter is Python; /bash is only an argument. Its
                # string literal must not be treated as executable shell code.
                "misleading-argument": (
                    '#!/usr/bin/env python3 /bash\n'
                    'example = """\neval "$command"\n"""\n'
                ),
            })
            for name, content in contents.items():
                path = project / name
                path.write_text(content, encoding="utf-8")
                path.chmod(0o755)

            if mode != "directory":
                (project / "unrequested-script").write_text(
                    '#!/usr/bin/env bash\ncommand="${1:-}"\neval "$command"\n',
                    encoding="utf-8",
                )
            if mode == "files":
                # Explicit paths must remain admitted even when a project
                # ignore pattern would omit them from a directory scan.
                (project / ".ubsignore").write_text("env-bash\n", encoding="utf-8")
                targets = [str(project / name) for name in contents]
            elif mode == "staged":
                for command in (
                    ["git", "init", "--initial-branch=main", str(project)],
                    ["git", "-C", str(project), "add", "--", *contents],
                ):
                    setup = subprocess.run(
                        command, cwd=project, capture_output=True, text=True,
                        check=False, timeout=30,
                    )
                    self.assertEqual(
                        setup.returncode, 0,
                        f"{command!r}\nstdout:\n{setup.stdout}\nstderr:\n{setup.stderr}",
                    )
                targets = ["--staged", str(project)]
            else:
                targets = [str(project)]
            result = subprocess.run(
                ["bash", str(REPO_ROOT / "ubs"), "--only=bash", "--format=json",
                 "--ci", "--no-cache", "--no-auto-update", *targets],
                cwd=project,
                env={**os.environ, "NO_COLOR": "1", "UBS_ENABLE_AUTO_UPDATE": "0"},
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
            context = (f"mode={mode}, exit={result.returncode}\n"
                       f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
            self.assertEqual(result.returncode, 1, context)
            try:
                document = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise AssertionError(f"Scanner stdout is not JSON: {exc}\n{context}") from exc

            self.assertEqual(document["status"], "ok", context)
            self.assertFalse(document.get("failed_modules"), context)
            self.assertEqual(document["totals"]["files"], 4, context)
            self.assertEqual(len(document["scanners"]), 1, context)
            scanner = document["scanners"][0]
            self.assertEqual(scanner["language"], "bash", context)
            self.assertEqual(scanner["files"], 4, context)

            self.assertIn("findings", document, context)
            findings = document["findings"]
            self.assertTrue(
                all(Path(finding["file"]).name in shell_scripts for finding in findings),
                context,
            )
            eval_locations = []
            for finding in findings:
                if finding["rule_id"] != "bash.security.eval_variable":
                    continue
                source = Path(finding["file"])
                if not source.is_absolute():
                    source = project / source
                eval_locations.append((source.resolve(), finding["line"]))
            self.assertCountEqual(
                eval_locations,
                [((project / name).resolve(), 3) for name in shell_scripts],
                context,
            )

    def test_directory_scan_admits_extensionless_shell_interpreters(self) -> None:
        self._check_extensionless_shell_admission(mode="directory")

    def test_explicit_file_scan_admits_extensionless_shell_interpreters(self) -> None:
        self._check_extensionless_shell_admission(mode="files")

    def test_staged_scan_admits_only_selected_extensionless_shell_scripts(self) -> None:
        self._check_extensionless_shell_admission(mode="staged")


@unittest.skipUnless(shutil.which("ast-grep"), "AST rule generation requires ast-grep")
class RubyTemporaryAllocationTest(unittest.TestCase):
    def test_failed_rule_directory_allocation_does_not_write_into_cwd(self) -> None:
        case_id = "ruby-rule-directory-allocation"
        started = time.monotonic()
        print(f"[{case_id}] RUN", flush=True)
        artifacts = REPO_ROOT / "test-suite/artifacts/module-temp-failure"
        artifacts.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="case-", dir=artifacts))
        cwd = root / "cwd"
        cwd.mkdir()
        scratch = root / "scratch"
        scratch.mkdir()
        tools = root / "tools"
        tools.mkdir()
        fixture = root / "clean.rb"
        fixture.write_text("def clean; 42; end\n", encoding="utf-8")
        real_mktemp = shutil.which("mktemp")
        self.assertIsNotNone(real_mktemp)
        # Inject only allocation failure, while executing the actual module
        # and allowing its temporary report files to use the real mktemp.
        shim = tools / "mktemp"
        shim.write_text(
            '#!/usr/bin/env bash\nfor arg do\n'
            '  if [[ "$arg" == "-d" ]]; then exit 1; fi\ndone\n'
            f'exec {shlex.quote(real_mktemp)} "$@"\n', encoding="utf-8",
        )
        shim.chmod(0o755)
        env = dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
                   PYTHONDONTWRITEBYTECODE="1",
                   PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""))
        try:
            result = subprocess.run(
                ["bash", str(REPO_ROOT / "modules/ubs-ruby.sh"), "--no-bundler",
                 "--format=json", str(fixture)],
                cwd=cwd, env=env, text=True, capture_output=True, timeout=45,
            )
            (root / "stdout.log").write_text(result.stdout, encoding="utf-8")
            (root / "stderr.log").write_text(result.stderr, encoding="utf-8")
            context = (f"exit={result.returncode}\nstdout:\n{result.stdout}"
                       f"\nstderr:\n{result.stderr}")
            self.assertEqual(result.returncode, 2, context)
            self.assertIn("temporary AST rule directory", result.stderr, context)
            self.assertFalse(result.stdout.strip(), context)
            self.assertEqual(list(cwd.iterdir()), [], context)
        except BaseException:
            print(f"[{case_id}] FAIL ({time.monotonic() - started:.3f}s)", flush=True)
            raise
        print(f"[{case_id}] PASS ({time.monotonic() - started:.3f}s)", flush=True)


@unittest.skipUnless(Path('/dev/full').exists(), 'requires /dev/full for bounded write-failure injection')
class ScanPreparationFailureTest(unittest.TestCase):
    """Actual module invocations must distinguish missing work from clean work."""

    cpp_module = REPO_ROOT / 'modules/ubs-cpp.sh'
    shared_library = REPO_ROOT / 'modules/lib/ubs-common.sh'

    def setUp(self) -> None:
        artifacts = REPO_ROOT / 'test-suite/artifacts/module-temp-failure'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='scan-io-', dir=artifacts))
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()
        self.project = self.root / 'project'
        self.project.mkdir()
        self.target = self.project / 'clean name.cpp'
        self.target.write_text('int main() { return 0; }\n', encoding='utf-8')
        self.counter = self.root / 'allocation-count'
        self.counter.write_text('0\n', encoding='ascii')
        self.startup = self.root / 'fault-injection.bash'
        # Bash loads this before the real module. Only the requested OS
        # operation fails; selection, scanning and rendering remain real.
        self.startup.write_text(r'''
mktemp(){
  local count=0
  if [[ -f "$UBS_IO_COUNTER" ]]; then read -r count < "$UBS_IO_COUNTER"; fi
  count=$((count + 1))
  builtin printf '%s\n' "$count" > "$UBS_IO_COUNTER"
  if [[ "${UBS_IO_FAIL_ALLOCATION:-0}" -gt 0 && "$count" -ge "$UBS_IO_FAIL_ALLOCATION" ]]; then
    echo 'injected mktemp allocation failure' >&2
    return 1
  fi
  command mktemp "$@"
}
printf(){
  if [[ "${UBS_IO_FAULT:-}" == 'list-write' && "${1:-}" == '%s\0' ]]; then
    builtin printf "$@" > /dev/full
  else
    builtin printf "$@"
  fi
}
cat(){
  if [[ "${UBS_IO_FAULT:-}" == 'text-write' && "$#" -gt 0 ]]; then
    command cat "$@" > /dev/full
  else
    command cat "$@"
  fi
}
''', encoding='utf-8')
        self.env = dict(os.environ, TMPDIR=str(self.scratch), TMP=str(self.scratch),
                        TEMP=str(self.scratch), BASH_ENV=str(self.startup),
                        UBS_IO_COUNTER=str(self.counter), UBS_IO_SOURCE=str(self.target), UBS_IO_FAIL_ALLOCATION='0',
                        UBS_IO_FAULT='', UBS_ALLOW_UNVERIFIED_HELPERS='1',
                        UBS_VERIFIED_ASSET_DIR=str(REPO_ROOT / 'modules'),
                        UBS_NO_CACHE='1', UBS_CACHE_DIR=str(self.root / 'cache'),
                        XDG_CACHE_HOME=str(self.root / 'cache'),
                        PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')

    def invoke(self, name: str, args: list[str], *, fault: str = '', allocation: int = 0,
               module: Path | None = None) -> subprocess.CompletedProcess:
        started = time.monotonic()
        print(f'[scan-io-{name}] RUN', flush=True)
        self.counter.write_text('0\n', encoding='ascii')
        result = subprocess.run(
            ['bash', str(module or self.cpp_module), *args], cwd=self.root,
            env={**self.env, 'UBS_IO_FAULT': fault, 'UBS_IO_FAIL_ALLOCATION': str(allocation)},
            text=True, capture_output=True, check=False, timeout=45,
        )
        (self.root / (name + '.stdout')).write_text(result.stdout, encoding='utf-8')
        (self.root / (name + '.stderr')).write_text(result.stderr, encoding='utf-8')
        print(f'[scan-io-{name}] EXIT {result.returncode} ({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def incomplete(self, result: subprocess.CompletedProcess) -> None:
        context = f'exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}'
        self.assertEqual(result.returncode, 2, context)
        self.assertIn('incomplete', result.stderr, context)

    def test_cpp_single_file_write_failure_never_becomes_empty_clean_report(self) -> None:
        for format_name in ('json', 'sarif', 'text'):
            with self.subTest(format=format_name):
                result = self.invoke('list-write-' + format_name,
                                     ['--format=' + format_name, str(self.target)], fault='list-write')
                self.incomplete(result)
                self.assertFalse(result.stdout.strip(), result.stdout)

    def test_all_contract_runners_check_single_file_list_writes(self) -> None:
        suffixes = {'bash': 'sh', 'csharp': 'cs', 'elixir': 'ex', 'golang': 'go',
                    'java': 'java', 'js': 'js', 'kotlin': 'kt', 'python': 'py',
                    'ruby': 'rb', 'rust': 'rs', 'swift': 'swift'}
        for language, suffix in suffixes.items():
            with self.subTest(language=language):
                target = self.project / ('clean.' + suffix)
                target.write_text('', encoding='utf-8')
                result = self.invoke('list-write-' + language,
                                     ['--format=json', str(target)], fault='list-write',
                                     module=REPO_ROOT / ('modules/ubs-' + language + '.sh'))
                self.incomplete(result)

    def test_cpp_temporary_allocations_fail_before_scanning(self) -> None:
        for allocation, format_name in ((1, 'json'), (2, 'json'), (3, 'text'), (3, 'sarif')):
            with self.subTest(allocation=allocation, format=format_name):
                result = self.invoke(f'allocation-{allocation}-{format_name}',
                                     ['--format=' + format_name, str(self.target)], allocation=allocation)
                self.incomplete(result)
                self.assertFalse(result.stdout.strip(), result.stdout)

    def test_cpp_empty_selection_and_real_source_remain_valid(self) -> None:
        empty = self.root / 'empty-project'
        empty.mkdir()
        for name, target, count in (('empty-control', empty, 0), ('source-control', self.target, 1)):
            with self.subTest(case=name):
                result = self.invoke(name, ['--format=json', str(target)])
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'ok', report)
                self.assertEqual(report['files'], count, report)
                self.assertEqual(report['critical'], 0, report)

    def test_cpp_directory_and_requested_list_failures_are_not_clean(self) -> None:
        missing_list = self.root / 'missing-selection.0'
        missing_project = self.root / 'missing-project'
        for name, arguments in (
            ('missing-list', ['--files-from=' + str(missing_list), str(self.project)]),
            ('missing-project', [str(missing_project)]),
        ):
            with self.subTest(case=name):
                result = self.invoke(name, ['--format=json', *arguments])
                self.incomplete(result)
                self.assertFalse(result.stdout.strip(), result.stdout)

    def test_cpp_report_delivery_failures_are_errors(self) -> None:
        parent_file = self.root / 'not-a-directory'
        parent_file.write_text('preserve me\n', encoding='utf-8')
        destination = parent_file / 'report.json'
        for name, args, fault in (
            ('findings-delivery', ['--format=json', '--report-json=' + str(destination), str(self.target)], ''),
            ('positional-delivery', ['--format=json', str(self.target), str(destination)], ''),
            ('text-delivery', ['--format=text', str(self.target)], 'text-write'),
        ):
            with self.subTest(case=name):
                result = self.invoke(name, args, fault=fault)
                self.incomplete(result)
        self.assertEqual(parent_file.read_text(), 'preserve me\n')

    def test_cpp_successful_delivery_preserves_report_and_finding_exit(self) -> None:
        unsafe = self.project / 'unsafe.cpp'
        unsafe.write_text('#include <cstdlib>\n#include <fstream>\n#include <string>\n'
                          'void load() {\n'
                          '  std::string path = std::getenv("QUERY_STRING");\n'
                          '  std::ifstream input(path);\n}\n', encoding='utf-8')
        for name, target, expected_exit in (('clean-delivery-control', self.target, 0),
                                             ('finding-delivery-control', unsafe, 1)):
            with self.subTest(case=name):
                output = self.root / (name + '.report')
                findings = self.root / (name + '.ndjson')
                result = self.invoke(name, ['--format=json', '--report-json=' + str(findings),
                                            str(target), str(output)])
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertEqual(output.read_text(), result.stdout)
                report = json.loads(result.stdout.splitlines()[0])
                self.assertEqual(report['files'], 1, report)
                self.assertEqual(report['status'], 'ok', report)
                records = [json.loads(line) for line in findings.read_text().splitlines()]
                self.assertEqual(records, report['findings'])
                if expected_exit:
                    self.assertTrue(any(record['rule'] == 'cpp.taint.path_traversal' for record in records), records)

    def test_shared_file_selection_checks_producer_and_writer_status(self) -> None:
        listing = self.root / 'files.0'
        listing.write_bytes(os.fsencode(self.target) + b'\0')
        cases = (
            ('directory-full', 'ubs_list_files "$2" --ext cpp > /dev/full', []),
            ('selected-full', 'ubs_list_files "$2" --files-from "$3" > /dev/full', [str(listing)]),
            ('enumerator-failure', 'rg(){ return 2; }; ubs_list_files "$2" --ext cpp', []),
            ('partial-enumerator', 'rg(){ printf "%s\\0" "$UBS_IO_SOURCE"; return 2; }; ubs_list_files "$2" --ext cpp', []),
        )
        for name, command, extra in cases:
            for pipefail in ('set +o pipefail', 'set -o pipefail'):
                with self.subTest(case=name, pipefail=pipefail):
                    # Deliberately invoke the helper in an OR-list, exactly
                    # where Bash disables implicit errexit protection.
                    script = f'source "$1"; {pipefail}; rc=0; {{ {command}; }} || rc=$?; exit "$rc"'
                    result = subprocess.run(
                        ['bash', '-c', script, 'listing', str(self.shared_library), str(self.project), *extra],
                        cwd=self.root, env=self.env, capture_output=True, check=False, timeout=15,
                    )
                    self.assertEqual(result.returncode, 2, (name, result.stdout, result.stderr))

    def test_cpp_bridge_preserves_failure_and_rejects_missing_sink(self) -> None:
        source = self.cpp_module.read_text(encoding='utf-8')
        begin = source.index('run_v2_legacy_parity_bridges_cpp(){')
        finish = source.index('\nrun_contract_v2_cpp(){', begin)
        definition = source[begin:finish]
        listing = self.root / 'files.0'
        listing.write_bytes(os.fsencode(self.target) + b'\0')
        findings = self.root / 'findings.ndjson'
        findings.write_text(json.dumps({'rule': 'cpp.taint.path_traversal', 'severity': 'critical'}) + '\n')
        for name, sink, scan_exit, text_out in (('partial-with-critical', findings, '2', ''),
                                               ('missing-sink', self.root / 'missing.ndjson', '0', ''),
                                               ('text-write-failure', findings, '0', '/dev/full')):
            with self.subTest(case=name):
                script = definition + '\nrc=0; run_v2_legacy_parity_bridges_cpp "$1" "$2" "$3" "$4" || rc=$?; exit "$rc"\n'
                result = subprocess.run(
                    ['bash', '-c', script, 'bridge', str(sink), str(listing), scan_exit, text_out],
                    cwd=self.root, env=self.env, capture_output=True, text=True, check=False, timeout=15,
                )
                self.assertEqual(result.returncode, 2, (name, result.stdout, result.stderr))


if __name__ == "__main__":
    unittest.main()
