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

from test_taint_python_dataflow import ROOT, SourceTest


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
