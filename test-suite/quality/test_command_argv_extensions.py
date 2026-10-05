"""Safe argv tails must preserve both list shape and existing dangerous prefixes."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'command_argv_extension_subject', ROOT / 'modules/helpers/ubs_core/py_detectors/command_injection.py')
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class CommandArgvExtensionTests(unittest.TestCase):
    def check(self, source):
        text = textwrap.dedent(source).lstrip()
        expected = {line for line, source_line in enumerate(text.splitlines(), 1) if '# HIT' in source_line}
        analyzer = subject.CommandInjectionAnalyzer(text, text.splitlines())
        analyzer.visit(ast.parse(text))
        self.assertEqual(set(analyzer.issues), expected, text)

    def test_safe_options_do_not_make_a_shell_command(self):
        self.check('''
            import subprocess
            args = ['bash', str(module), f'--rules={custom}']
            args += ['--list-rules'] if metadata else ['--format=json', str(fixture)]
            subprocess.run(args)
        ''')

    def test_conditional_extension_preserves_shape_in_loop(self):
        self.check('''
            import subprocess, sys
            command = [sys.executable, '-m', 'ubs_core.' + name + '_scan']
            if name != 'csharp':
                command += ['--json-out', str(report)]
            for iteration in range(2):
                subprocess.run(command)
        ''')

    def test_preserves_shell_payload_provenance(self):
        self.check('''
            import subprocess
            command = ['sh', '-c', input()]
            command += ['ignored-argv0']
            subprocess.run(command)  # HIT
        ''')

    def test_preserves_dynamic_executable_provenance(self):
        self.check('''
            import subprocess
            command = [input(), '--version']
            command += ['--verbose']
            subprocess.run(command)  # HIT
        ''')

    def test_untrusted_tail_keeps_conservative_detection(self):
        self.check('''
            import subprocess
            command = ['sh']
            command += ['-c', input()]
            subprocess.run(command)  # HIT
        ''')

    def test_dynamic_payload_tail_keeps_conservative_detection(self):
        self.check('''
            import subprocess
            command = []
            command += ['sh', '-c', f'echo {value}']
            subprocess.run(command)  # HIT
        ''')

    def test_quoted_tail_cannot_hide_executable_selection(self):
        self.check('''
            import subprocess, shlex
            command = []
            command += [shlex.quote(input())]
            subprocess.run(command)  # HIT
        ''')

    def test_scalar_concatenation_is_not_an_argv_extension(self):
        self.check('''
            import os
            command = 'echo '
            command += input()
            os.system(command)  # HIT
        ''')


if __name__ == '__main__':
    unittest.main(verbosity=2)
