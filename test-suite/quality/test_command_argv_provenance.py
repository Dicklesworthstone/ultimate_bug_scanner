"""Shell argv provenance regressions; fixture programs are never executed."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'command_argv_subject', ROOT / 'modules/helpers/ubs_core/py_detectors/command_injection.py')
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class CommandArgvProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.failures_before = len(result.failures) + len(result.errors)
        print(f'[{self.id()}] RUN', flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.failures_before
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} '
              f'({time.monotonic() - self.started:.3f}s)', flush=True)

    def check(self, code):
        code = textwrap.dedent(code).lstrip('\n')
        expected = [i for i, line in enumerate(code.splitlines(), 1) if '# HIT' in line]
        analyzer = subject.CommandInjectionAnalyzer(code, code.splitlines())
        analyzer.visit(ast.parse(code))
        self.assertEqual(sorted(analyzer.issues), expected, code)
        self.assertEqual(len(analyzer.issues), len(set(analyzer.issues)), code)

    def test_shell_vector_variable_and_alias_chain(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            alias = command
            copy = alias
            subprocess.run(copy)  # HIT
        ''')

    def test_all_subprocess_wrappers_accept_vector_alias(self):
        for function in ('run', 'call', 'check_call', 'check_output', 'Popen'):
            with self.subTest(function=function):
                self.check(f'''
                    import subprocess
                    command = ['bash', '-lc', input()]
                    subprocess.{function}(args=command)  # HIT
                ''')

    def test_annotated_tuple_shell_vector(self):
        self.check('''
            import subprocess
            command: tuple = ('sh', '-c', input())
            subprocess.run(command)  # HIT
        ''')

    def test_strong_overwrite_clears_shell_vector_facts(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            command = ['echo', input()]
            subprocess.run(command)
        ''')

    def test_conditional_overwrite_keeps_dangerous_vector_path(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            if fixed:
                command = ['echo', input()]
            subprocess.run(command)  # HIT
        ''')

    def test_loop_carried_vector_provenance(self):
        self.check('''
            import subprocess
            command = ['echo']
            while again:
                subprocess.run(command)  # HIT
                command = ['sh', '-c', input()]
        ''')

    def test_function_local_vector_does_not_leak(self):
        self.check('''
            import subprocess
            def first():
                command = ['sh', '-c', input()]
            def second(command):
                subprocess.run(command)
        ''')

    def test_shell_override_uses_vector_flag_not_display_name(self):
        self.check('''
            import subprocess
            command = ['display-name', '-c', input()]
            subprocess.run(command, executable='/bin/sh')  # HIT
        ''')

    def test_non_shell_override_neutralizes_shell_vector(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            subprocess.run(command, executable='/bin/echo')
        ''')

    def test_none_override_preserves_shell_vector(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            subprocess.run(command, executable=None)  # HIT
        ''')

    def test_shell_script_arguments_are_data(self):
        self.check('''
            import subprocess
            command = ['sh', 'fixed-script.sh', input()]
            subprocess.run(command)
        ''')

    def test_conditional_vector_expression_carries_shell_provenance(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()] if flag else ['echo']
            subprocess.run(command)  # HIT
        ''')

    def test_inline_conditional_shell_vector(self):
        self.check('''
            import subprocess
            subprocess.run(['sh', '-c', input()] if flag else ['echo'])  # HIT
        ''')

    def test_conditional_fixed_argv_is_not_executable_selection(self):
        self.check('''
            import subprocess
            command = ['echo', input()] if flag else ['printf', input()]
            subprocess.run(command)
            subprocess.run(['echo', input()] if flag else ['printf', input()])
        ''')

    def test_conditional_vector_dynamic_executable_is_still_detected(self):
        self.check('''
            import subprocess
            command = [input(), 'data'] if flag else ['echo']
            subprocess.run(command)  # HIT
        ''')

    def test_conditional_payload_with_fixed_shell_override(self):
        self.check('''
            import subprocess
            command = ['display', '-c', input()] if flag else ['echo']
            subprocess.run(command, executable='/bin/sh')  # HIT
        ''')

    def test_dead_conditional_vector_branch_is_not_a_source(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()] if False else ['echo']
            subprocess.run(command)
        ''')

    def test_windows_shell_names_are_host_independent(self):
        for program, flag in [(r'C:\Windows\System32\CMD.EXE', '/c'),
                              ('cmd.exe', '/C'), ('powershell.exe', '-Command'),
                              ('pwsh.exe', '-EncodedCommand')]:
            with self.subTest(program=program):
                self.check(f'''
                    import subprocess
                    command = [{program!r}, {flag!r}, input()]
                    subprocess.run(command)  # HIT
                    subprocess.run([{program!r}, {flag!r}, input()])  # HIT
                ''')

    def test_posix_quoting_does_not_sanitize_windows_program(self):
        self.check('''
            import subprocess, shlex
            escaped = shlex.quote(input())
            command = ['cmd.exe', '/c', escaped]
            subprocess.run(command)  # HIT
            subprocess.run(['powershell.exe', '-Command', escaped])  # HIT
        ''')

    def test_windows_override_preserves_raw_payload_provenance(self):
        self.check('''
            import subprocess, shlex
            command = ['display', '-Command', shlex.quote(input())]
            alias = command
            subprocess.run(alias, executable='powershell.exe')  # HIT
        ''')

    def test_existing_posix_quote_domain_is_preserved(self):
        self.check('''
            import subprocess, shlex
            command = ['sh', '-c', shlex.quote(input())]
            subprocess.run(command)
        ''')

    def test_exec_vector_family_recognizes_shell_payload(self):
        for function in ('execv', 'execve', 'execvp', 'execvpe'):
            tail = ', {}' if function.endswith('e') else ''
            with self.subTest(function=function):
                self.check(f'''
                    import os
                    command = ['display', '-c', input()]
                    os.{function}('/bin/sh', command{tail})  # HIT
                ''')

    def test_exec_variadic_family_recognizes_shell_payload(self):
        for function in ('execl', 'execle', 'execlp', 'execlpe'):
            tail = ', {}' if function.endswith('e') else ''
            with self.subTest(function=function):
                self.check(f'''
                    import os
                    os.{function}('/bin/sh', 'display', '-c', input(){tail})  # HIT
                ''')

    def test_spawn_vector_family_recognizes_shell_payload(self):
        for function in ('spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
            tail = ', {}' if function.endswith('e') else ''
            with self.subTest(function=function):
                self.check(f'''
                    import os
                    command = ['display', '-c', input()]
                    os.{function}(os.P_WAIT, '/bin/sh', command{tail})  # HIT
                ''')

    def test_spawn_variadic_family_recognizes_shell_payload(self):
        for function in ('spawnl', 'spawnle', 'spawnlp', 'spawnlpe'):
            tail = ', {}' if function.endswith('e') else ''
            with self.subTest(function=function):
                self.check(f'''
                    import os
                    os.{function}(os.P_WAIT, '/bin/sh', 'display', '-c', input(){tail})  # HIT
                ''')

    def test_exec_fixed_program_argv_zero_is_not_selector(self):
        self.check('''
            import os
            os.execv('/bin/echo', [input(), '-c', input()])
            os.execl('/bin/echo', input(), '-c', input())
            os.spawnv(os.P_WAIT, '/bin/echo', [input(), '-c', input()])
        ''')

    def test_variadic_environment_is_not_command_payload(self):
        self.check('''
            import os
            os.execle('/bin/sh', 'sh', '-c', 'echo', os.environ)
            os.spawnle(os.P_WAIT, '/bin/sh', 'sh', '-c', 'echo', os.environ)
        ''')

    def test_variadic_literal_star_expansion(self):
        self.check('''
            import os
            os.execl('/bin/sh', *['sh', '-c', input()])  # HIT
        ''')

    def test_os_popen_keyword(self):
        self.check('''
            import os
            os.popen(cmd=input())  # HIT
        ''')

    def test_direct_import_exec_alias(self):
        self.check('''
            from os import execvp as launch
            command = ['display', '-c', input()]
            launch('/bin/sh', command)  # HIT
        ''')

    def test_suppression_and_fixed_point_deduplication(self):
        self.check('''
            import subprocess
            command = ['echo']
            while again:
                subprocess.run(command)  # HIT
                subprocess.run(command)  # ubs:ignore
                command = ['sh', '-c', input()]
        ''')


if __name__ == '__main__':
    unittest.main(verbosity=2)
