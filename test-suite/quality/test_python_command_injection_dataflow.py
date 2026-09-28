"""Regressions for the live Python command-injection detector.

Inputs are parsed, never executed. Run directly or with unittest discovery.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))

from ubs_core.py_detectors.command_injection import CommandInjectionAnalyzer, find


class CommandInjectionDataflowTests(unittest.TestCase):
    def findings(self, source):
        source = textwrap.dedent(source).strip() + '\n'
        analyzer = CommandInjectionAnalyzer(source, source.splitlines())
        analyzer.visit(ast.parse(source))
        return analyzer.issues

    def test_conditional_sanitizer_cannot_clean_other_branch(self):
        self.assertEqual(self.findings('''
            import os, shlex
            value = input()
            command = shlex.quote(value) if escape else value
            os.system(command)
        '''), [4])

    def test_unused_quoted_argument_cannot_clean_opaque_call(self):
        self.assertEqual(self.findings('''
            import os, shlex
            command = choose(input(), shlex.quote('fixed'))
            os.system(command)
        '''), [3])

    def test_quoted_collection_member_does_not_clean_sibling(self):
        self.assertEqual(self.findings('''
            import os, shlex
            commands = [input(), shlex.quote('fixed')]
            os.system(commands[0])
        '''), [3])

    def test_sanitizer_text_is_not_a_call(self):
        self.assertEqual(self.findings('''
            import os
            command = choose(input(), 'shlex.quote(value)')
            os.system(command)
        '''), [3])

    def test_similarly_named_method_is_not_a_sanitizer(self):
        self.assertEqual(self.findings('''
            import os
            os.system(custom.shlex.quote(input()))
        '''), [2])

    def test_shell_quoting_does_not_authorize_executable(self):
        for sink in ('os.execvp(value, [value])', 'os.spawnvp(0, value, [value])',
                     'subprocess.run([value])'):
            with self.subTest(sink=sink):
                self.assertEqual(self.findings(f'''
                    import os, shlex, subprocess
                    quoted = shlex.quote(input())
                    value = quoted
                    {sink}
                '''), [4])

    def test_inline_quoted_executable_is_still_untrusted(self):
        self.assertEqual(self.findings('''
            import subprocess, shlex
            subprocess.run([shlex.quote(input())])
        '''), [2])

    def test_actual_quote_result_remains_safe_for_shell(self):
        self.assertEqual(self.findings('''
            import os, shlex
            quoted = shlex.quote(input())
            alias = quoted
            os.system(alias)
            os.system(shlex.quote(input()))
        '''), [])

    def test_all_sanitized_conditional_branches_are_safe(self):
        self.assertEqual(self.findings('''
            import os, shlex
            command = shlex.quote(input()) if flag else shlex.quote(input())
            os.system(command)
        '''), [])

    def test_source_looking_strings_are_not_user_input(self):
        self.assertEqual(self.findings('''
            import os
            command = 'echo request.args input() os.environ'
            os.system(command)
        '''), [])

    def test_reassignment_clears_both_taint_domains(self):
        self.assertEqual(self.findings('''
            import os, shlex
            command = shlex.quote(input())
            command = 'fixed-program'
            os.execvp(command, [command])
            os.system(command)
        '''), [])

    def test_fixed_argv_data_is_not_an_executable(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(['echo', input()])
        '''), [])

    def test_existing_dynamic_string_checks_are_preserved(self):
        for expression in ('f"echo {value}"', '"echo " + value', '"echo %s" % value',
                           '"echo {}".format(value)'):
            with self.subTest(expression=expression):
                self.assertEqual(self.findings(f'import os\nos.system({expression})'), [2])

    def test_direct_sources_and_suppressions(self):
        self.assertEqual(self.findings('''
            import os
            os.system(input())
            os.system(input())  # ubs:ignore
            # ubs:ignore
            os.system(input())
            os.system(request.args['command'])
        '''), [2, 6])

    def test_file_entrypoint_preserves_location_and_deduplication(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / 'sample.pyi'
            path.write_text('import os, shlex\nos.system(choose(input(), shlex.quote("x")))\n',
                            encoding='utf-8')
            records = list(find([path]))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][:3], (path, 2, 1))
        self.assertIn('os.system', records[0][3])


if __name__ == '__main__':
    unittest.main()
