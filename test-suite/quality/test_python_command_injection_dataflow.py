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

    def test_subprocess_keyword_args_reach_shell(self):
        for function in ('run', 'call', 'check_call', 'check_output', 'Popen'):
            with self.subTest(function=function):
                self.assertEqual(self.findings(f'''
                    import subprocess
                    subprocess.{function}(args=input(), shell=True)
                '''), [2])

    def test_output_helpers_accept_cmd_keyword(self):
        for function in ('getoutput', 'getstatusoutput'):
            with self.subTest(function=function):
                self.assertEqual(self.findings(f'''
                    import subprocess
                    subprocess.{function}(cmd=input())
                '''), [2])

    def test_executable_override_is_checked_even_with_fixed_argv(self):
        for executable in ('input()', 'shlex.quote(input())'):
            with self.subTest(executable=executable):
                self.assertEqual(self.findings(f'''
                    import subprocess, shlex
                    subprocess.run(['fixed'], executable={executable})
                '''), [2])

    def test_literal_keyword_expansion_and_nested_mapping(self):
        for arguments in ("**{'args': input(), 'shell': True}",
                          "**{'args': ['fixed'], 'executable': input()}",
                          "**{'args': input(), **{'shell': 1}}"):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.findings(f'import subprocess\nsubprocess.run({arguments})'), [2])

    def test_literal_keyword_last_write_wins(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(**{'args': 'echo', 'executable': input(), 'executable': '/bin/echo'})
        '''), [])

    def test_positional_executable_argument(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.Popen(['fixed'], -1, input())
        '''), [2])

    def test_positional_shell_argument_and_literal_star_expansion(self):
        for arguments in ("input(), -1, None, None, None, None, None, True, True",
                          "*([input()],), shell=True",
                          "*(input(),), **{'shell': True}"):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.findings(f'import subprocess\nsubprocess.Popen({arguments})'), [2])

    def test_truthy_and_dynamic_shell_flags_are_not_false(self):
        for flag in ('1', 'configuration'):
            with self.subTest(flag=flag):
                self.assertEqual(self.findings(f'''
                    import subprocess
                    subprocess.run(['echo', input()], shell={flag})
                '''), [2])

    def test_false_shell_flags_leave_argv_data_safe(self):
        for flag in ('False', '0', 'None'):
            with self.subTest(flag=flag):
                self.assertEqual(self.findings(f'''
                    import subprocess
                    subprocess.run(args=['echo', input()], shell={flag})
                '''), [])

    def test_fixed_executable_overrides_untrusted_argv_zero(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(args=[input(), 'data'], executable='/bin/echo')
        '''), [])

    def test_none_executable_does_not_override_argv(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(args=[input()], executable=None)
        '''), [2])

    def test_shell_executable_override_interprets_payload(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(['arbitrary-name', '-c', input()], executable='/bin/sh')
        '''), [2])

    def test_nonshell_executable_override_does_not_interpret_payload(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run(['sh', '-c', input()], executable='/bin/echo')
        '''), [])

    def test_scalar_subprocess_args_select_executable(self):
        for argument in ('input()', 'shlex.quote(input())'):
            with self.subTest(argument=argument):
                self.assertEqual(self.findings(f'''
                    import subprocess, shlex
                    command = {argument}
                    subprocess.run(args=command, shell=False)
                '''), [3])

    def test_known_argv_aliases_do_not_turn_data_into_executable(self):
        self.assertEqual(self.findings('''
            import subprocess
            argv = ['echo', input()]
            alias = argv
            subprocess.run(args=alias)
        '''), [])

    def test_argv_aliases_retain_dynamic_executable(self):
        self.assertEqual(self.findings('''
            import subprocess
            argv = [input(), 'data']
            alias = argv
            subprocess.run(args=alias)
        '''), [4])

    def test_reassignment_clears_argv_shape(self):
        self.assertEqual(self.findings('''
            import subprocess
            command = ['echo', input()]
            command = input()
            subprocess.run(args=command)
        '''), [4])

    def test_dynamic_command_string_survives_alias(self):
        self.assertEqual(self.findings('''
            import os
            command = f'echo {value}'
            alias = command
            os.system(alias)
        '''), [4])

    def test_dynamic_scalar_executable_survives_alias(self):
        self.assertEqual(self.findings('''
            import subprocess
            command = f'/bin/{value}'
            alias = command
            subprocess.run(args=alias)
        '''), [4])

    def test_import_aliases_preserve_keyword_detection(self):
        self.assertEqual(self.findings('''
            from subprocess import run as launch
            import subprocess as process
            launch(args=input(), shell=True)
            process.Popen(args=['echo'], executable=input())
        '''), [3, 4])

    def test_missing_and_noncommand_keywords_are_not_sinks(self):
        self.assertEqual(self.findings('''
            import subprocess
            subprocess.run()
            subprocess.run(args=['echo'], input=input(), cwd=input())
            subprocess.getoutput(cmd='echo fixed')
        '''), [])


if __name__ == '__main__':
    unittest.main()
