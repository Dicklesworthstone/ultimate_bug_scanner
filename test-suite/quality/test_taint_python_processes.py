"""Executable source versus argv data in Python process APIs.

All payloads are static-analysis fixtures; the unit tests never execute them.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_taint_python_dataflow import ROOT, RunContext, SourceTest, taint_py


class InterpreterProcessTests(SourceTest):
    def test_shell_command_payloads_are_sinks(self):
        for shell in ('sh', 'bash', '/bin/dash', '/usr/bin/zsh', 'ksh', 'mksh'):
            for option in ('-c', '-lc'):
                with self.subTest(shell=shell, option=option):
                    self.assert_rules(f'subprocess.run([{shell!r}, {option!r}, input()])', 'command')

    def test_python_command_payloads_are_not_ordinary_argv(self):
        for program in ('python', 'python3', '/usr/bin/python3.14', 'pypy3', 'C:\\Python\\python.exe'):
            for option in ('-c', '-Ic', '-uc'):
                with self.subTest(program=program, option=option):
                    self.assert_rules(f'subprocess.run([{program!r}, {option!r}, input()])', 'command')

    def test_fixed_shell_program_positional_arguments_remain_data(self):
        self.assert_rules('subprocess.run(["sh", "-c", \'printf "%s" "$1"\', "name", input()])')
        self.assert_rules('subprocess.run(["bash", "-lc", "echo safe", input()])')

    def test_fixed_python_program_arguments_remain_data(self):
        self.assert_rules('subprocess.run(["python3", "-c", "import sys; print(sys.argv[1])", input()])')
        self.assert_rules('subprocess.run(["python3", "script.py", "-c", input()])')
        self.assert_rules('subprocess.run(["python3", "-m", "package", "-c", input()])')

    def test_option_values_are_not_interpreter_programs(self):
        self.assert_rules('subprocess.run(["python3", "-W", input(), "-X", input(), "-c", "print(1)"])')
        self.assert_rules('subprocess.run(["bash", "-o", "noclobber", "-c", "echo safe", input()])')
        self.assert_rules('subprocess.run(["python3", "--check-hash-based-pycs", "always", "-c", input()])', 'command')
        self.assert_rules('subprocess.run(["python3", "-Wignore::DeprecationWarning", "-c", input()])', 'command')
        self.assert_rules('subprocess.run(["python3", "-Xcheck", "-c", input()])', 'command')
        self.assert_rules('subprocess.run(["python3", "-Impackage", "-c", input()])')

    def test_options_after_bash_c_are_not_the_command(self):
        self.assert_rules('subprocess.run(["bash", "-c", "-l", input()])', 'command')
        self.assert_rules('subprocess.run(["bash", "-lc", "-o", "noclobber", input()])', 'command')

    def test_end_of_options_and_script_paths(self):
        self.assert_rules('subprocess.run(["bash", "--", "script.sh", "-c", input()])')
        self.assert_rules('subprocess.run(["python3", "--", "script.py", "-c", input()])')
        self.assert_rules('subprocess.run(["bash", "-c", "--", input()])', 'command')
        self.assert_rules('subprocess.run(["python3", input()])', 'command')

    def test_shell_quote_is_not_python_source_sanitization(self):
        self.assert_rules('subprocess.run(["python3", "-c", shlex.quote(input())])', 'command')
        self.assert_rules('subprocess.run(["bash", "-c", "echo " + shlex.quote(input())])')
        self.assert_rules('subprocess.run(["python3", "-c", html.escape(input())])', 'command')

    def test_local_helpers_preserve_strict_interpreter_domain(self):
        self.assert_rules('''
            def execute(program):
                subprocess.run(['python3', '-c', program])
            execute(shlex.quote(input()))
        ''', 'command')
        self.assert_rules('''
            def execute(program):
                subprocess.run(['bash', '-c', program])
            execute('echo ' + shlex.quote(input()))
        ''')
        self.assert_rules('''
            def execute(command, data):
                subprocess.run(['sh', '-c', command, 'name', data])
            execute('echo "$1"', input())
        ''')

    def test_all_subprocess_vector_entrypoints(self):
        for function in ('run', 'Popen', 'call', 'check_call', 'check_output'):
            with self.subTest(function=function):
                self.assert_rules(f'subprocess.{function}(["python3", "-c", input()])', 'command')
                self.assert_rules(f'subprocess.{function}(["echo", input()])')

    def test_keyword_vectors_and_literal_expansion(self):
        self.assert_rules('subprocess.run(args=["sh", "-c", input()])', 'command')
        self.assert_rules('subprocess.run(**{"args": ["python3", "-c", input()]})', 'command')
        self.assert_rules('subprocess.run(["python3", *["-c", input()]])', 'command')
        self.assert_rules('subprocess.run(["echo", *[input()]])')

    def test_dynamic_option_suffix_is_not_proven_safe(self):
        self.assert_rules('subprocess.run(["python3", options, input()])', 'command')
        self.assert_rules('subprocess.run(["sh", *options, input()])', 'command')

    def test_shell_true_does_not_execute_later_vector_items(self):
        self.assert_rules('subprocess.run(["python3", "-c", input()], shell=True)')
        self.assert_rules('subprocess.run([input(), "-c", "safe"], shell=True)', 'command')

    def test_executable_override_selects_the_real_interpreter(self):
        self.assert_rules('subprocess.run(["ignored", "-c", input()], executable="python3")', 'command')
        self.assert_rules('subprocess.run(["python3", "-c", input()], executable="/bin/echo")')
        self.assert_rules('subprocess.run([shlex.quote(input())], shell=True, executable="python3")', 'command')
        self.assert_rules('subprocess.run("echo " + shlex.quote(input()), shell=True, executable="/bin/bash")')
        self.assert_rules('subprocess.run("echo " + shlex.quote(input()), shell=True, executable=None)')
        self.assert_rules('program = "echo"\nsubprocess.run(["python3", "-c", input()], executable=program)')
        self.assert_rules('program = "python3"\nsubprocess.run(["echo", "-c", input()], executable=program)', 'command')

    def test_current_python_interpreter_identity(self):
        self.assert_rules('import sys\nsubprocess.run([sys.executable, "-c", input()])', 'command')

    def test_qualified_import_and_function_aliases(self):
        self.assert_rules('from subprocess import run as execute\nexecute(["sh", "-c", input()])', 'command')
        self.assert_rules('execute = subprocess.run\nexecute(["python3", "-c", input()])', 'command')
        self.assert_rules('from project import run\nrun(["python3", "-c", input()])')

    def test_asyncio_process_vectors_and_shell_source(self):
        self.assert_rules('asyncio.create_subprocess_exec("sh", "-c", input())', 'command')
        self.assert_rules('asyncio.create_subprocess_exec("python3", "-c", input())', 'command')
        self.assert_rules('asyncio.create_subprocess_exec("echo", input())')
        self.assert_rules('asyncio.create_subprocess_shell(input())', 'command')
        self.assert_rules('from asyncio import create_subprocess_exec as run\nrun("python", "-c", input())', 'command')

    def test_async_executable_override(self):
        self.assert_rules('asyncio.create_subprocess_exec("ignored", "-c", input(), executable="python3")', 'command')
        self.assert_rules('asyncio.create_subprocess_exec("python3", "-c", input(), executable="echo")')
        self.assert_rules('asyncio.create_subprocess_exec("echo", executable=input())', 'command')
        self.assert_rules('asyncio.create_subprocess_exec(input(), executable=maybe_none)', 'command')
        self.assert_rules('asyncio.create_subprocess_shell("echo " + shlex.quote(input()), executable=None)')
        self.assert_rules('program = "bash"\nasyncio.create_subprocess_shell("echo " + shlex.quote(input()), executable=program)')

    def test_rebound_api_and_literal_strings_are_not_callables(self):
        self.assert_rules('asyncio = service\nasyncio.create_subprocess_exec("sh", "-c", input())')
        self.assert_rules('run = "eval"\nrun(input())')
        self.assert_rules('read = "input"\neval(read())')

    def test_os_exec_vectors_and_spawn(self):
        for function in ('execv', 'execvp', 'execve', 'execvpe', 'posix_spawn', 'posix_spawnp'):
            extra = ', {}' if function.endswith('e') or function.startswith('posix_spawn') else ''
            with self.subTest(function=function):
                self.assert_rules(f'os.{function}("python3", ["ignored", "-c", input()]{extra})', 'command')
                self.assert_rules(f'os.{function}("echo", ["ignored", input()]{extra})')

    def test_os_exec_variadic_arguments(self):
        for function in ('execl', 'execlp', 'execle', 'execlpe'):
            extra = ', {}' if function.endswith('e') else ''
            with self.subTest(function=function):
                self.assert_rules(f'os.{function}("sh", "ignored", "-c", input(){extra})', 'command')
                self.assert_rules(f'os.{function}("echo", "ignored", input(){extra})')

    def test_shell_string_helpers_are_sinks(self):
        for function in ('subprocess.getoutput', 'subprocess.getstatusoutput', 'os.system', 'os.popen'):
            with self.subTest(function=function):
                self.assert_rules(f'{function}(input())', 'command')
                self.assert_rules(f'{function}("echo " + shlex.quote(input()))')

    def test_argument_facts_use_original_evaluation_order(self):
        self.assert_rules('q = input()\nsubprocess.run(["sh", "-c", q, (q := "safe")])', 'command')
        self.assert_rules('q = "safe"\nsubprocess.run(["sh", "-c", q, (q := input())])')
        self.assert_rules('subprocess.run(["python3", "-c", "print(1)", eval(input())])', 'eval')

    def test_framework_input_reaches_interpreter_via_helper(self):
        self.assert_rules('''
            from fastapi import Query
            def execute(code):
                subprocess.run(['python3', '-c', code])
            def route(code=Query()):
                execute(code)
        ''', 'command')


class SavedArgumentVectorTests(SourceTest):
    def test_saved_vectors_preserve_code_and_data_positions(self):
        for literal in ('["echo", input()]', '("echo", input())',
                        '["python3", "-c", "print(1)", input()]',
                        '["sh", "-c", \'printf "%s" "$1"\', "argv0", input()]'):
            with self.subTest(literal=literal):
                self.assert_rules(f'args = {literal}\nalias = args\nsubprocess.run(alias)')
        self.assert_rules('args = ["python3", "-c", input()]\nalias = args\nsubprocess.run(alias)', 'command')

    def test_branches_do_not_cross_pair_program_and_payload(self):
        self.assert_rules('args = ["echo", input()] if flag else ["python3", "-c", "print(1)"]\nsubprocess.run(args)')
        self.assert_rules('args = ["echo", input()] if flag else ["python3", "-c", input()]\nsubprocess.run(args)', 'command')
        self.assert_rules('if flag:\n args=["echo", input()]\nelse:\n args=["sh", "-c", "echo safe"]\nsubprocess.run(args)')

    def test_helper_built_vectors_substitute_each_parameter(self):
        for program, expected in (('python3', ('command',)), ('echo', ())):
            with self.subTest(program=program):
                self.assert_rules(f'''\
                    def build(program, code):
                        return [program, '-c', code]
                    def forward(value):
                        return build({program!r}, value)
                    subprocess.run(forward(input()))
                ''', *expected)

    def test_helper_vector_defaults_and_keywords(self):
        self.assert_rules('''
            def build(code, program='python3'):
                return [program, '-c', code]
            subprocess.run(build(code=input()))
        ''', 'command')
        self.assert_rules('''
            def build(code, program='python3'):
                return [program, '-c', code]
            subprocess.run(build(program='echo', code=input()))
        ''')

    def test_returned_vectors_keep_sanitizer_domains(self):
        self.assert_rules('def build(value):\n return ["python3", "-c", shlex.quote(value)]\nsubprocess.run(build(input()))', 'command')
        self.assert_rules('def build(value):\n return ["sh", "-c", "echo " + shlex.quote(value)]\nsubprocess.run(build(input()))')

    def test_source_snapshots_are_not_re_read_after_rebinding(self):
        self.assert_rules('code = input()\nargs = ["python3", "-c", code]\ncode = "safe"\nsubprocess.run(args)', 'command')
        self.assert_rules('code = "print(1)"\nargs = ["python3", "-c", code]\ncode = input()\nsubprocess.run(args)')

    def test_strong_rebinding_detaches_vector_aliases(self):
        self.assert_rules('args = ["python3", "-c", input()]\nargs = ["echo", input()]\nsubprocess.run(args)')
        self.assert_rules('args = ["echo", input()]\nalias = args\nalias = ["python3", "-c", input()]\nsubprocess.run(args)')

    def test_clean_writes_invalidate_argument_position_certainty(self):
        self.assert_rules('args = ["echo", "-c", input()]\nalias = args\nalias[0] = "python3"\nsubprocess.run(args)', 'command')
        self.assert_rules('args = ["echo", "-c", input()]\nargs.reverse()\nsubprocess.run(args)', 'command')
        self.assert_rules('args = ["echo", "-c", input()]\nargs.pop(0)\nsubprocess.run(args)', 'command')
        self.assert_rules('args = ["echo", "python3", "-c", input()]\ndel args[0]\nsubprocess.run(args)', 'command')

    def test_augmented_lists_keep_mutations_visible_to_aliases(self):
        self.assert_rules('args=["python3"]\nalias=args\nargs += ["-c", input()]\nsubprocess.run(alias)', 'command')
        self.assert_rules('args=("python3", "-c", "print(1)")\nalias=args\nargs += (input(),)\nsubprocess.run(alias)')
        self.assert_rules('args=["python3"]\nargs.__iadd__(["-c", input()])\nsubprocess.run(args)', 'command')

    def test_returned_vector_changed_in_finally_is_not_certified_safe(self):
        self.assert_rules('''
            def build(code):
                args = ['echo', '-c', code]
                try:
                    return args
                finally:
                    args[0] = 'python3'
            subprocess.run(build(input()))
        ''', 'command')

    def test_helper_clean_mutations_are_summary_effects(self):
        self.assert_rules('''
            def change(args):
                args[0] = 'python3'
            args = ['echo', '-c', input()]
            change(args)
            subprocess.run(args)
        ''', 'command')

    def test_unknown_calls_invalidate_escaped_vector_shapes(self):
        self.assert_rules('args = ["echo", "-c", input()]\nunknown(args)\nsubprocess.run(args)', 'command')
        self.assert_rules('''
            def forward(args):
                unknown(args)
            args = ['echo', '-c', input()]
            forward(args)
            subprocess.run(args)
        ''', 'command')

    def test_shape_is_invalidated_when_a_later_argument_mutates_it(self):
        self.assert_rules('args=["echo", "-c", input()]\nsubprocess.run(args, env=args.reverse())', 'command')

    def test_fixed_override_does_not_trust_a_mutated_vector(self):
        self.assert_rules('args=["ignored", "safe.py", input()]\nargs[1]="-c"\nsubprocess.run(args, executable="python3")', 'command')

    def test_os_exec_uses_saved_vectors_without_conflating_argv0(self):
        self.assert_rules('args=[input(), "-c", "print(1)"]\nos.execv("python3", args)')
        self.assert_rules('args=["ignored", "-c", input()]\nos.execv("python3", args)', 'command')
        self.assert_rules('args=["ignored", "-c", input()]\nos.execv("echo", args)')

    def test_framework_parameter_flows_through_vector_factory(self):
        self.assert_rules('''
            from fastapi import Query
            def build(code):
                return ['python3', '-c', code]
            def route(code=Query()):
                args = build(code)
                subprocess.run(args)
        ''', 'command')

    def test_recursion_does_not_grow_argument_vectors(self):
        # The analyzer uses a finite set of fixed vector shapes, not repeated
        # execution of a recursive builder. Timeout is a required safety gate.
        probe = ('import sys;sys.path.insert(0,sys.argv[1]);'
                 'from test_taint_python_dataflow import SourceTest;'
                 'SourceTest().assert_rules(sys.stdin.read(), "command")')
        import sys
        result = subprocess.run([sys.executable, '-B', '-c', probe, str(Path(__file__).parent)],
                                input='def build(code):\n return build(code) if flag else ["python3", "-c", code]\nsubprocess.run(build(input()))',
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class WrapperArgumentVectorTests(SourceTest):
    """Issue #200: summaries must distinguish argv[0] from ordinary arguments."""

    def test_issue_200_exact_direct_control(self):
        self.assert_rules('''
            import os
            import subprocess

            user = os.environ.get("SUDO_USER", "root")
            subprocess.run(["sshd", "-T", "-C", "user=" + user], check=False)
        ''')

    def test_issue_200_exact_variadic_reproduction(self):
        self.assert_rules('''
            import os
            import subprocess


            def run(*argv):
                return subprocess.run(argv, check=False)


            user = os.environ.get("SUDO_USER", "root")
            run("sshd", "-T", "-C", "user=" + user)
        ''')

    def test_issue_200_list_parameter_reproduction(self):
        self.assert_rules('''
            import os
            import subprocess


            def run(argv):
                return subprocess.run(argv, check=False)


            user = os.environ.get("SUDO_USER", "root")
            run(["sshd", "-T", "-C", "user=" + user])
        ''')

    def test_issue_200_exact_tainted_executable_control(self):
        self.assert_rules('''
            import os
            import subprocess

            subprocess.run([os.environ.get("TOOL", "true")])
        ''', 'command')

    def test_tainted_executable_survives_both_wrapper_forms(self):
        for parameter, invocation in (('*argv', 'run(os.environ["TOOL"], "-T")'),
                                      ('argv', 'run([os.environ["TOOL"], "-T"])')):
            with self.subTest(parameter=parameter):
                self.assert_rules(f'def run({parameter}):\n return subprocess.run(argv)\n{invocation}', 'command')

    def test_nested_variadic_and_list_wrappers(self):
        source = '''
            def run(argv):
                return subprocess.run(argv, check=False)
            def forward(*argv):
                return run(argv)
            def outer(argv):
                return forward(*argv)
        '''
        self.assert_rules(source + '\n            outer(["echo", input()])\n')
        self.assert_rules(source + '\n            outer([input(), "safe"])\n', 'command')
        self.assert_rules(source + '\n            outer(["python3", "-c", input()])\n', 'command')

    def test_multiple_call_sites_exclude_argument_only_provenance(self):
        for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
            safe_call = template.format('"sshd", "-T", harmless_argument')
            unsafe_call = template.format('unsafe_executable, "-T"')
            for calls in ((safe_call, unsafe_call), (unsafe_call, safe_call)):
                with self.subTest(parameter=parameter, calls=calls):
                    findings = self.assert_rules(
                        f'def run({parameter}):\n return subprocess.run(argv)\n'
                        'harmless_argument = os.environ["SUDO_USER"]\n'
                        'unsafe_executable = os.environ["TOOL"]\n' + '\n'.join(calls), 'command')
                    self.assertEqual(findings[0]['line'], 2)
                    self.assertIn('unsafe_executable', findings[0]['message'])
                    self.assertNotIn('harmless_argument', findings[0]['message'])
                    self.assertIn('subprocess executable', findings[0]['message'])

    def test_multiple_argument_only_sites_do_not_taint_executable(self):
        self.assert_rules('''
            def run(*argv):
                return subprocess.run(argv)
            run("sshd", "-T", input())
            run("echo", input())
            run("python3", "-c", "print(1)", input())
        ''')

    def test_literal_program_selection_stays_paired_with_its_arguments(self):
        self.assert_rules('''
            def run(argv):
                return subprocess.run(argv)
            argv = ["echo", "-c", input()] if flag else ["python3", "-c", "print(1)"]
            run(argv)
        ''')
        self.assert_rules('''
            def run(argv):
                return subprocess.run(argv)
            argv = ["echo", "-c", input()] if flag else ["python3", "-c", input()]
            run(argv)
        ''', 'command')

    def test_dynamic_executable_selection_is_not_proven_safe(self):
        self.assert_rules('''
            def run(argv):
                return subprocess.run(argv)
            program = "echo" if flag else os.environ["TOOL"]
            run([program, "safe"])
        ''', 'command')
        self.assert_rules('''
            def run(*argv):
                return subprocess.run(argv)
            program = "echo" if flag else "python3"
            run(program, "-c", input())
        ''', 'command')

    def test_unresolved_program_identity_keeps_possible_interpreter_flows(self):
        for expression in ('"py" + "thon3"', 'str("python3")',
                           'os.path.join("/usr/bin", "python3")'):
            for wrapper, invocation in (
                ('', 'subprocess.run([program, "-c", input()])'),
                ('def run(*argv):\n return subprocess.run(argv)\n', 'run(program, "-c", input())'),
                ('def run(argv):\n return subprocess.run(argv)\n', 'run([program, "-c", input()])'),
            ):
                with self.subTest(expression=expression, invocation=invocation):
                    self.assert_rules(wrapper + f'program = {expression}\n' + invocation, 'command')
        self.assert_rules('subprocess.run(["echo", "-c", input()])')

    def test_starred_call_keeps_alternative_interpreter_identity(self):
        self.assert_rules('''
            def run(program, *args):
                subprocess.run([program, *args])
            program = "echo" if flag else "python3"
            args = [program, "-c", input()]
            run(*args)
        ''', 'command')

    def test_executable_override_keeps_alternative_interpreter_identity(self):
        self.assert_rules('''
            def run(argv, program):
                subprocess.run(argv, executable=program)
            program = "echo" if flag else "python3"
            run(["ignored", "-c", input()], program)
        ''', 'command')

    def test_keyword_and_starred_forwarding_preserve_positions(self):
        for invocation in ('run(argv=["echo", input()])', 'run(*[["echo", input()]])',
                           'run(**{"argv": ["echo", input()]})'):
            with self.subTest(invocation=invocation):
                self.assert_rules('def run(argv):\n return subprocess.run(args=argv)\n' + invocation)
        self.assert_rules('def run(*argv):\n return subprocess.run(argv)\nrun(*["echo", input()])')
        self.assert_rules('def run(*argv):\n return subprocess.run(argv)\nrun(*[input(), "safe"])', 'command')

    def test_wrapper_vector_copies_and_prefixes(self):
        for command in ('[*argv]', '["echo", *argv]'):
            with self.subTest(command=command):
                self.assert_rules(f'def run(argv):\n return subprocess.run({command})\nrun(["echo", input()])')
        self.assert_rules('def run(argv):\n return subprocess.run([*argv])\nrun([input(), "safe"])', 'command')

    def test_all_subprocess_entrypoints_through_wrappers(self):
        for function in ('run', 'Popen', 'call', 'check_call', 'check_output'):
            for parameter, invocation in (('*argv', 'execute("echo", input())'),
                                          ('argv', 'execute(["echo", input()])')):
                with self.subTest(function=function, parameter=parameter):
                    source = f'def execute({parameter}):\n return subprocess.{function}(argv)\n'
                    self.assert_rules(source + invocation)
                    dangerous = 'execute(input())' if parameter.startswith('*') else 'execute([input()])'
                    self.assert_rules(source + dangerous, 'command')

    def test_shell_true_uses_command_position_not_later_arguments(self):
        self.assert_rules('def run(argv):\n return subprocess.run(argv, shell=True)\nrun(input())', 'command')
        self.assert_rules('def run(argv):\n return subprocess.run(argv, shell=True)\nrun([input(), "safe"])', 'command')
        self.assert_rules('def run(*argv):\n return subprocess.run(argv, shell=True)\nrun(input(), "safe")', 'command')
        self.assert_rules('def run(argv):\n return subprocess.run(argv, shell=True)\nrun(["echo safe", input()])')
        self.assert_rules('def run(*argv):\n return subprocess.run(argv, shell=True)\nrun("echo safe", input())')

    def test_interpreter_code_and_data_survive_wrapper_boundaries(self):
        for program in ('python3', 'sh'):
            for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
                with self.subTest(program=program, parameter=parameter):
                    source = f'def run({parameter}):\n return subprocess.run(argv)\n'
                    self.assert_rules(source + template.format(f'{program!r}, "-c", input()'), 'command')
                    self.assert_rules(source + template.format(f'{program!r}, "-c", "fixed", input()'))

    def test_wrapper_domains_keep_shell_quoting_specific_to_shell_code(self):
        source = 'def run(argv):\n return subprocess.run(argv)\n'
        self.assert_rules(source + 'run(["sh", "-c", "echo " + shlex.quote(input())])')
        self.assert_rules(source + 'run(["python3", "-c", shlex.quote(input())])', 'command')
        self.assert_rules(source + 'run([shlex.quote(input())])', 'command')
        self.assert_rules('def run(argv):\n return subprocess.run(argv, shell=True)\nrun("echo " + shlex.quote(input()))')

    def test_wrapper_executable_override_selects_the_actual_program(self):
        source = ('def run(argv, executable):\n'
                  ' return subprocess.run(argv, executable=executable)\n')
        self.assert_rules(source + 'run(["python3", "-c", input()], "echo")')
        self.assert_rules(source + 'run(["echo", "-c", input()], "python3")', 'command')
        self.assert_rules(source + 'run(["echo", "safe"], input())', 'command')

    def test_wrapper_stdin_depends_on_selected_interpreter_mode(self):
        source = 'def run(argv, payload):\n return subprocess.run(argv, input=payload)\n'
        self.assert_rules(source + 'run(["python3"], input())', 'command')
        self.assert_rules(source + 'run(["sh", "-s"], input())', 'command')
        self.assert_rules(source + 'run(["python3", "-c", "print(1)"], input())')
        self.assert_rules(source + 'run(["echo"], input())')

    def test_wrapper_returned_process_keeps_stdin_contract(self):
        source = 'def start(argv):\n return subprocess.Popen(argv, stdin=subprocess.PIPE)\n'
        self.assert_rules(source + 'p = start(["python3"])\np.communicate(input())', 'command')
        self.assert_rules(source + 'p = start(["echo"])\np.communicate(input())')

    def test_wrapper_mutation_revokes_argument_position_certainty(self):
        self.assert_rules('''
            def run(argv):
                argv.reverse()
                return subprocess.run(argv)
            run(["echo", input()])
        ''', 'command')
        self.assert_rules('''
            def run(argv):
                argv[0] = "python3"
                return subprocess.run(argv)
            run(["echo", "-c", input()])
        ''', 'command')

    def test_mutation_before_call_or_in_later_argument_revokes_shape(self):
        self.assert_rules('''
            def run(argv):
                return subprocess.run(argv)
            argv = ["echo", "-c", input()]
            argv[0] = "python3"
            run(argv)
        ''', 'command')
        self.assert_rules('''
            def run(argv, unused):
                return subprocess.run(argv)
            argv = ["echo", input()]
            run(argv, argv.reverse())
        ''', 'command')

    def test_unknown_length_prefix_can_expose_later_executable(self):
        for prefix in ('unknown', '([] if flag else ["echo"])'):
            for parameter, invocation in (('*argv', f'run(*{prefix}, input())'),
                                          ('argv', f'run([*{prefix}, input()])')):
                for options in ('', ', shell=True'):
                    with self.subTest(prefix=prefix, parameter=parameter, options=options):
                        self.assert_rules(
                            f'def run({parameter}):\n return subprocess.run(argv{options})\n' + invocation,
                            'command')

    def test_unknown_length_suffix_preserves_fixed_executable(self):
        for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
            source = f'def run({parameter}):\n return subprocess.run(argv)\n'
            with self.subTest(parameter=parameter):
                self.assert_rules(source + template.format('"echo", *unknown, input()'))
                self.assert_rules(source + template.format('"python3", *unknown, input()'), 'command')
                self.assert_rules(source + template.format('"sh", *unknown, input()'), 'command')

    def test_widened_vectors_keep_late_code_taint_and_selected_program(self):
        # Long argument vectors must not silently drop taint when summary
        # contexts widen their suffix to keep recursive analysis bounded.
        for program, option in (('python3', '-I'), ('sh', '-l')):
            options = ', '.join([repr(option)] * 40)
            padding = ', '.join(['"padding"'] * 40)
            for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
                source = f'def run({parameter}):\n return subprocess.run(argv)\n'
                with self.subTest(program=program, parameter=parameter):
                    self.assert_rules(source + template.format(
                        f'{program!r}, {options}, "-c", input()'), 'command')
                    self.assert_rules(source + template.format(
                        f'{program!r}, "-c", "fixed", {padding}, input()'))

    def test_interpreter_option_value_does_not_consume_unknown_suffix(self):
        for program, flag, option, value in (('python3', '-I', '-W', 'ignore'),
                                             ('python3', '-I', '-X', 'dev'),
                                             ('sh', '-l', '-o', 'errexit')):
            for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
                source = f'def run({parameter}):\n return subprocess.run(argv)\n'
                with self.subTest(program=program, option=option, parameter=parameter):
                    # The expansion may contain an option value followed by
                    # -c and source; it cannot be consumed as exactly one item.
                    self.assert_rules(source + template.format(
                        f'{program!r}, {option!r}, *input().split()'), 'command')
                    padding = ', '.join([repr(flag)] * 14)
                    self.assert_rules(source + template.format(
                        f'{program!r}, {padding}, {option!r}, {value!r}, "-c", input()'), 'command')
        for option in ('-c', '-m', '-Ic'):
            for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
                source = f'def run({parameter}):\n return subprocess.run(argv)\n'
                with self.subTest(option=option, parameter=parameter):
                    # An empty expansion exposes the later operand as source.
                    self.assert_rules(source + template.format(
                        f'"python3", {option!r}, *unknown, input()'), 'command')
                    self.assert_rules(source + template.format(
                        f'"python3", {option!r}, "fixed", *unknown, input()'))
        self.assert_rules('''
            def run(argv, payload):
                subprocess.run(argv, input=payload)
            run(["python3", "--", *unknown], input())
        ''', 'command')

    def test_repeated_shape_contexts_keep_branch_and_sanitizer_provenance(self):
        source = '''
            def run(argv):
                subprocess.run(argv)
            quoted_code = "echo " + shlex.quote(input())
            harmless_argument = input()
            argv = ["echo", "-c", harmless_argument] if flag else ["sh", "-c", quoted_code]
            run(argv)
        '''
        self.assert_rules(source)
        findings = self.assert_rules(source + '''
            unsafe_code = input()
            argv = ["echo", "-c", harmless_argument] if flag else ["sh", "-c", unsafe_code]
            run(argv)
        ''', 'command')
        self.assertIn('unsafe_code', findings[0]['message'])
        self.assertIn('subprocess execution', findings[0]['message'])
        self.assertNotIn('quoted_code', findings[0]['message'])
        self.assertNotIn('harmless_argument', findings[0]['message'])

    def test_callback_forwarding_preserves_vector_positions(self):
        source = '''
            def run(argv):
                return subprocess.run(argv)
            def invoke(callback, argv):
                return callback(argv)
        '''
        self.assert_rules(source + '\n            invoke(run, ["echo", input()])\n')
        self.assert_rules(source + '\n            invoke(run, [input(), "safe"])\n', 'command')

    def test_captured_defaults_preserve_each_factory_invocations_vector(self):
        source = '''
            def make(argv):
                def run(args=argv):
                    return subprocess.run(args)
                return run
        '''
        self.assert_rules(source + '\n            make(["echo", input()])()\n')
        self.assert_rules(source + '''
            make(["echo", input()])()
            make([input(), "safe"])()
        ''', 'command')

    def test_selected_modules_preserve_wrapper_positions_in_either_order(self):
        for parameter, template in (('*argv', 'run({})'), ('argv', 'run([{}])')):
            for operands, expected in (("'echo', input()", []),
                                       ("input(), 'safe'", ['python.taint.command'])):
                for reverse in (False, True):
                    with self.subTest(parameter=parameter, operands=operands, reverse=reverse):
                        with tempfile.TemporaryDirectory(prefix='ubs-wrapper-modules-') as tmp:
                            helper = Path(tmp) / 'helper.py'
                            helper.write_text('import subprocess\n'
                                              f'def run({parameter}):\n return subprocess.run(argv)\n', encoding='utf-8')
                            app = Path(tmp) / 'app.py'
                            app.write_text('from helper import run\n' + template.format(operands) + '\n', encoding='utf-8')
                            paths = [app, helper] if reverse else [helper, app]
                            findings = list(taint_py.run(RunContext(
                                lang='python', files=paths, profile={'project_dir': tmp})))
                        self.assertEqual([finding['rule'] for finding in findings], expected, findings)
                        if findings:
                            self.assertEqual((Path(findings[0]['path']).name, findings[0]['line']), ('helper.py', 3))

    def test_wrapper_observes_temporary_global_vector_at_call_time(self):
        self.assert_rules('''
            import subprocess
            argv = ["echo", input()]
            def run(argv):
                subprocess.run(argv)
            def invoke():
                run(argv)
            argv = [input()]
            invoke()
            argv = ["echo", input()]
        ''', 'command')

    def test_wrapper_observes_global_vector_rebound_inside_helper(self):
        self.assert_rules('''
            import subprocess
            argv = ["echo"]
            def run(argv):
                subprocess.run(argv)
            def invoke():
                run(argv)
            def update():
                global argv
                argv = [input()]
                invoke()
            update()
        ''', 'command')

    def test_recursive_wrapper_vector_growth_is_bounded(self):
        probe = ('import sys;sys.path.insert(0,sys.argv[1]);'
                 'from test_taint_python_dataflow import SourceTest;'
                 'SourceTest().assert_rules(sys.stdin.read(), "command")')
        import sys
        result = subprocess.run(
            [sys.executable, '-B', '-c', probe, str(Path(__file__).parent)],
            input='def run(argv):\n if flag: return run([*argv, "extra"])\n subprocess.run(argv)\nrun([input(), "safe"])',
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_issue_200_environment_output_dependency(self):
        # An unknown child's output can depend on its environment. This is a
        # different dependency from treating an ordinary argv item as argv[0].
        self.assert_rules('''
            import os
            import subprocess

            env = {"PATH": "/usr/bin", "SSH_CONNECTION": os.environ.get("SSH_CONNECTION", "")}
            wan = subprocess.run(["ip", "-j", "route"], capture_output=True, text=True, env=env).stdout.strip()
            subprocess.run([wan], check=False)
        ''', 'command')
        self.assert_rules('''
            import subprocess

            env = {"PATH": "/usr/bin", "SSH_CONNECTION": ""}
            wan = subprocess.run(["ip", "-j", "route"], capture_output=True, text=True, env=env).stdout.strip()
            subprocess.run([wan], check=False)
        ''')
        self.assert_rules('''
            env = {"SSH_CONNECTION": os.environ.get("SSH_CONNECTION", "")}
            subprocess.run(["ip", "-j", "route"], env=env)
        ''')


class InterpreterStdinTests(SourceTest):
    def test_input_keyword_is_source_only_when_interpreter_reads_code(self):
        for args in ('["python3"]', '["python3", "-"]', '["python3", "-I", "-"]',
                     '["sh"]', '["bash", "-s"]', '["bash", "-s", "argv0"]'):
            with self.subTest(args=args):
                self.assert_rules(f'subprocess.run({args}, input=input())', 'command')
        for args in ('["echo"]', '["python3", "-c", "print(1)"]', '["python3", "-m", "module"]',
                     '["python3", "script.py"]', '["bash", "-c", "cat"]', '["bash", "script.sh"]'):
            with self.subTest(args=args):
                self.assert_rules(f'subprocess.run({args}, input=input())')

    def test_stdin_source_domains_and_helper_substitution(self):
        self.assert_rules('subprocess.run(["python3", "-"], input=shlex.quote(input()))', 'command')
        self.assert_rules('subprocess.run(["bash", "-s"], input="echo " + shlex.quote(input()))')
        self.assert_rules('def execute(code):\n subprocess.run(["python3", "-"], input=code)\nexecute(shlex.quote(input()))', 'command')

    def test_shell_true_stdin_is_application_data(self):
        self.assert_rules('subprocess.run("cat", shell=True, input=input())')
        self.assert_rules('subprocess.run(["python3", "-c", "print(1)"], shell=True, input=input())')

    def test_saved_vector_stdin_respects_code_option_boundaries(self):
        self.assert_rules('args=["python3", "-"]\nsubprocess.run(args, input=input())', 'command')
        self.assert_rules('args=["python3", "-c", "print(1)"]\nsubprocess.run(args, input=input())')

    def test_popen_identity_gates_communicate_source(self):
        self.assert_rules('p=subprocess.Popen(["python3"], stdin=subprocess.PIPE)\np.communicate(input())', 'command')
        self.assert_rules('p=subprocess.Popen(["python3", "-c", "print(1)"], stdin=subprocess.PIPE)\np.communicate(input())')
        self.assert_rules('p=subprocess.Popen(["echo"], stdin=subprocess.PIPE)\np.communicate(input())')
        self.assert_rules('p=subprocess.Popen(["python3"])\np.communicate(input())')
        self.assert_rules('p=Other()\np.communicate(input())')

    def test_communicate_alias_captures_process_not_rebound_name(self):
        self.assert_rules('p=subprocess.Popen(["python3"], stdin=subprocess.PIPE)\nsend=p.communicate\np=Other()\nsend(input())', 'command')
        self.assert_rules('p=Other()\nsend=p.communicate\np=subprocess.Popen(["python3"], stdin=subprocess.PIPE)\nsend(input())')
        self.assert_rules('p=subprocess.Popen(["python3"],stdin=subprocess.PIPE)\np.communicate=print\np.communicate(input())')
        self.assert_rules('p=subprocess.Popen(["python3"],stdin=subprocess.PIPE)\nsend=p.communicate\np.communicate=print\nsend(input())', 'command')

    def test_returned_process_keeps_stdin_contract(self):
        self.assert_rules('def start():\n return subprocess.Popen(["python3"], stdin=subprocess.PIPE)\np=start()\np.communicate(input())', 'command')

    def test_literal_pipe_alias_is_resolved_at_construction(self):
        self.assert_rules('from subprocess import Popen, PIPE\np=Popen(["python3"],stdin=PIPE)\np.communicate(input=input())', 'command')
        self.assert_rules('p=subprocess.Popen(["python3"],stdin=-1)\np.communicate(input())', 'command')
        self.assert_rules('PIPE=None\np=subprocess.Popen(["python3"],stdin=PIPE)\np.communicate(input())')

    def test_async_process_input_contract_survives_await(self):
        self.assert_rules('async def run():\n p=await asyncio.create_subprocess_exec("python3", stdin=subprocess.PIPE)\n await p.communicate(input())', 'command')
        self.assert_rules('async def run():\n p=await asyncio.create_subprocess_exec("echo", stdin=subprocess.PIPE)\n await p.communicate(input())')

    def test_alternative_processes_preserve_possible_interpreter(self):
        self.assert_rules('if flag:\n p=subprocess.Popen(["python3"],stdin=subprocess.PIPE)\nelse:\n p=subprocess.Popen(["echo"],stdin=subprocess.PIPE)\np.communicate(input())', 'command')

    def test_request_body_can_be_an_interpreter_stdin_program(self):
        self.assert_rules('''
            from fastapi import Request
            async def route(req: Request):
                p = subprocess.Popen(['python3', '-'], stdin=subprocess.PIPE)
                p.communicate(await req.body())
        ''', 'command')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'Set UBS_TAINT_E2E=1 for real CLI scans')
class InterpreterCliTests(unittest.TestCase):
    def test_python_code(self):
        self.check_process('python-code', 'subprocess.run(["python3", "-c", input()])', True)

    def test_shell_code(self):
        self.check_process('shell-code', 'subprocess.run(["sh", "-c", input()])', True)

    def test_python_data(self):
        self.check_process('python-data', 'subprocess.run(["python3", "-c", "print(1)", input()])', False)

    def test_async_code(self):
        self.check_process('async-code', 'asyncio.create_subprocess_exec("sh", "-c", input())', True)

    def test_saved_argument_data(self):
        self.check_process('saved-data', 'args=["echo", input()]\nsubprocess.run(args)', False)

    def test_factory_code(self):
        self.check_process('factory-code', 'def build(code):\n return ["python3", "-c", code]\nsubprocess.run(build(input()))', True)

    def test_stdin_program(self):
        self.check_process('stdin-code', 'p=subprocess.Popen(["python3"],stdin=subprocess.PIPE)\np.communicate(input())', True)

    def test_stdin_data(self):
        self.check_process('stdin-data', 'subprocess.run(["python3", "-c", "print(1)"],input=input())', False)

    def check_process(self, name, source, unsafe):
        artifacts = ROOT / 'test-suite' / 'artifacts' / 'python-processes'
        artifacts.mkdir(parents=True, exist_ok=True)

        def collect(value):
            if isinstance(value, dict):
                return {item for key, item in value.items() if key in {'rule', 'rule_id', 'ruleId'}
                        and isinstance(item, str)} | set().union(*(collect(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(collect(child) for child in value))
            return set()

        for output in ('json', 'sarif'):
            with self.subTest(name=name, format=output), tempfile.TemporaryDirectory(prefix='ubs-process-cli-') as tmp:
                path = Path(tmp) / 'route.py'
                path.write_text(source + '\n', encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(path), '--only=python', '--ci', f'--format={output}'],
                                        cwd=tmp, text=True, capture_output=True, timeout=90,
                                        env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1'))
                (artifacts / f'{name}-{output}.json').write_text(result.stdout, encoding='utf-8')
                (artifacts / f'{name}-{output}.stderr.log').write_text(result.stderr, encoding='utf-8')
                self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                report = json.loads(result.stdout)
                if output == 'sarif':
                    rules = {item.get('ruleId') for run in report.get('runs', []) for item in run.get('results', [])}
                else:
                    self.assertEqual(report.get('status'), 'ok', report)
                    rules = collect(report)
                self.assertEqual(bool({'python.taint.command', 'py.taint.command'} & rules), unsafe, report)
                print('PROCESS_CLI_PASS', name, output, flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
