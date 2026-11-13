"""Source-level regressions for Python taint flow, never executed fixtures."""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_py
from ubs_core.io import temporary_directory
from ubs_core.registry import RunContext


class SourceTest(unittest.TestCase):
    def scan(self, source: str):
        with temporary_directory(prefix='ubs-taint-dataflow-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text(textwrap.dedent(source).lstrip('\n'), encoding='utf-8')
            return list(taint_py.run(RunContext(lang='python', files=[path])))

    def assert_rules(self, source: str, *rules: str):
        findings = self.scan(source)
        self.assertEqual(sorted(f['rule'] for f in findings),
                         sorted(f'python.taint.{r}' for r in rules), findings)
        return findings


class SanitizerDomainTests(SourceTest):
    def test_html_escaping_is_not_sql_command_or_eval_sanitization(self):
        for sanitizer in ('html.escape', 'django.utils.html.escape', 'flask.escape', 'bleach.clean'):
            for sink, rule in (("cursor.execute('select ' + q)", 'sql'),
                               ('os.system(q)', 'command'), ('eval(q)', 'eval')):
                with self.subTest(sanitizer=sanitizer, sink=sink):
                    self.assert_rules(f"q = {sanitizer}(request.args['q'])\n{sink}\n", rule)

    def test_shell_quoting_only_protects_shell_code(self):
        for sink, expected in (("os.system('echo ' + q)", ()),
                               ('cursor.execute(q)', ('sql',)),
                               ('eval(q)', ('eval',)),
                               ('HttpResponse(q)', ('xss',)),
                               ('subprocess.run([q])', ('command',)),
                               ("os.execv(q, ['arg'])", ('command',))):
            with self.subTest(sink=sink):
                self.assert_rules(f"q = shlex.quote(input())\n{sink}\n", *expected)

    def test_marking_safe_does_not_escape(self):
        for marker in ('mark_safe', 'django.utils.safestring.mark_safe', 'Markup', 'markupsafe.Markup'):
            with self.subTest(marker=marker):
                self.assert_rules(f'HttpResponse({marker}(input()))\n', 'xss')

    def test_url_encoding_is_not_a_generic_sanitizer(self):
        self.assert_rules("eval(urllib.parse.quote(input()))\n", 'eval')

    def test_escaping_one_operand_does_not_hide_another(self):
        self.assert_rules("q = input()\nHttpResponse(html.escape(q) + q)\n", 'xss')
        self.assert_rules("q = input()\nHttpResponse(html.escape('safe') + q)\n", 'xss')
        self.assert_rules("q = input()\nHttpResponse(html.escape(q) + html.escape(q))\n")

    def test_sanitizer_name_in_a_string_is_not_a_sanitizer(self):
        self.assert_rules("q = input()\neval('html.escape' + q)\n", 'eval')

    def test_aliases_resolve_and_shadowing_revokes_sanitizer_identity(self):
        self.assert_rules('from html import escape as e\nHttpResponse(e(input()))\n')
        self.assert_rules('import html as h\nHttpResponse(h.escape(input()))\n')
        self.assert_rules('from html import escape as e\ne = other\nHttpResponse(e(input()))\n', 'xss')
        self.assert_rules('import html\nhtml = other\nHttpResponse(html.escape(input()))\n', 'xss')

    def test_configurable_cleaner_is_not_assumed_safe(self):
        self.assert_rules("HttpResponse(bleach.clean(input(), tags=['script']))\n", 'xss')


class SinkArgumentTests(SourceTest):
    def test_bound_sql_parameters_are_not_query_text(self):
        for query in ("'select * from t where k = %s'", "'select * from t where k = ?'",
                      "'select * from t where k = :key'"):
            with self.subTest(query=query):
                self.assert_rules(f'q = input()\ncursor.execute({query}, (q,))\n')
        self.assert_rules("q = input()\ncursor.execute('select ' + q, (123,))\n", 'sql')
        self.assert_rules("q = input()\ncursor.execute(query=q, params=('safe',))\n", 'sql')

    def test_literal_argv_arguments_are_not_executable_code(self):
        self.assert_rules("subprocess.run(['echo', input()])\n")
        self.assert_rules("subprocess.run(['echo', input()], shell=False)\n")
        self.assert_rules("subprocess.run([input(), 'safe'])\n", 'command')
        self.assert_rules("subprocess.run('echo ' + input(), shell=True)\n", 'command')
        self.assert_rules("subprocess.run(args=['echo', input()])\n")
        self.assert_rules("subprocess.run(args=[input(), 'safe'])\n", 'command')

    def test_eval_globals_are_not_executed_as_source(self):
        self.assert_rules("eval('1', {'data': input()})\n")
        self.assert_rules("eval(input(), {})\n", 'eval')

    def test_response_headers_are_not_response_html(self):
        self.assert_rules("HttpResponse('safe', headers={'x': input()})\n")
        self.assert_rules("HttpResponse(content=input())\n", 'xss')

    def test_alias_sources_and_sinks(self):
        self.assert_rules('from flask import request as req\nfrom os import system as execute\nexecute(req.args["q"])\n', 'command')
        self.assert_rules('from subprocess import run as launch\nlaunch(input(), shell=True)\n', 'command')
        self.assert_rules('eval(event["body"])\n', 'eval')


class EnvironmentSourceTests(SourceTest):
    def test_getters_reach_each_sink_domain(self):
        sinks = (("os.system(value)", 'command'),
                 ("eval(value)", 'eval'),
                 ("cursor.execute('SELECT ' + value)", 'sql'),
                 ("HttpResponse(value)", 'xss'),
                 ("requests.get(value)", 'ssrf'))
        for getter, key, convert in (('getenv', "'UBS_INPUT'", ''),
                                     ('getenvb', "b'UBS_INPUT'", '.decode()')):
            for sink, rule in sinks:
                with self.subTest(getter=getter, sink=sink):
                    self.assert_rules(
                        f'import os, requests\nvalue = os.{getter}({key}){convert}\n{sink}\n', rule)

    def test_getter_aliases_and_literal_defaults_keep_source_identity(self):
        for getter, key, default in (('getenv', "'UBS_INPUT'", "'fixed'"),
                                     ('getenvb', "b'UBS_INPUT'", "b'fixed'")):
            cases = (
                (f'import os as process_env\n', f'process_env.{getter}({key})'),
                (f'from os import {getter} as lookup\n', f'lookup({key}, {default})'),
                (f'import os\n', f'os.{getter}(key={key}, default={default})'),
                (f'import os\nlookup = os.{getter}\nos = None\n', f'lookup({key})'),
                (f'from os import {getter} as lookup\nsaved = lookup\nlookup = lambda key: {default}\n',
                 f'saved({key})'),
            )
            for setup, expression in cases:
                with self.subTest(getter=getter, expression=expression, setup=setup):
                    self.assert_rules(setup + f'eval({expression})\n', 'eval')

    def test_getter_is_captured_before_argument_rebinding(self):
        self.assert_rules('''
            import os
            value = os.getenv(((os := None), 'UBS_INPUT')[1])
            eval(value)
        ''', 'eval')
        self.assert_rules('''
            from os import getenv as lookup
            value = lookup(((lookup := lambda key: 'fixed'), 'UBS_INPUT')[1])
            eval(value)
        ''', 'eval')

    def test_getter_names_and_unused_callables_are_not_sources(self):
        self.assert_rules('''
            def getenv(key):
                return 'fixed'
            eval(getenv('UBS_INPUT'))
        ''')
        self.assert_rules('''
            import os
            class Settings:
                @staticmethod
                def getenv(key):
                    return 'fixed'
            os = Settings
            eval(os.getenv('UBS_INPUT'))
        ''')
        for module in ('custom_os', 'application.os', '.os', '..os'):
            with self.subTest(module=module):
                self.assert_rules(f'from {module} import getenv as lookup\neval(lookup("UBS_INPUT"))\n')
        self.assert_rules('import os\neval(os.getenv_extra("UBS_INPUT"))\n')
        self.assert_rules('from os import getenv as lookup\nHttpResponse(str(lookup))\n')
        self.assert_rules('''
            from os import getenv as lookup
            def read(lookup):
                return lookup('UBS_INPUT')
            eval(read(lambda key: 'fixed'))
        ''')

    def test_imported_source_collections_keep_their_values(self):
        for module, member, key in (('os', 'environ', "'UBS_INPUT'"),
                                    ('os', 'environb', "b'UBS_INPUT'"),
                                    ('sys', 'argv', '1')):
            with self.subTest(module=module, member=member):
                self.assert_rules(f'from {module} import {member} as values\neval(values[{key}])\n', 'eval')
        self.assert_rules('''
            from os import environ as settings
            saved = settings
            settings = {'UBS_INPUT': 'fixed'}
            eval(saved['UBS_INPUT'])
        ''', 'eval')
        self.assert_rules('''
            from os import environ as settings
            settings = {'UBS_INPUT': 'fixed'}
            eval(settings['UBS_INPUT'])
        ''')
        for module in ('.os', '..os'):
            with self.subTest(module=module):
                self.assert_rules(f'from {module} import environ as values\neval(values["UBS_INPUT"])\n')

    def test_collection_source_names_require_exact_stdlib_identity(self):
        for module, member in (('custom_os', 'environ'), ('application.os', 'environb'),
                               ('OS', 'environ'), ('os', 'environ_extra'),
                               ('os', 'ENVIRON'), ('mysys', 'argv'),
                               ('application.sys', 'argv'), ('SYS', 'argv'),
                               ('sys', 'argv_extra'), ('sys', 'ARGV'),
                               ('.os', 'environ'), ('..os', 'environb'),
                               ('.sys', 'argv'), ('..sys', 'argv')):
            with self.subTest(module=module, member=member, style='imported'):
                self.assert_rules(f'from {module} import {member} as values\neval(values[1])\n')
            relative_prefix = '.' * (len(module) - len(module.lstrip('.')))
            statement = (f'from {relative_prefix} import {module.lstrip(".")} as values'
                         if relative_prefix else f'import {module} as values')
            with self.subTest(module=module, member=member, style='qualified'):
                self.assert_rules(f'{statement}\neval(values.{member}[1])\n')

    def test_source_collection_members_reach_each_sink_domain(self):
        for setup, expression in (
                ('from os import environ as values', "values.get('UBS_INPUT', 'fixed')"),
                ('from os import environb as values', "values[b'UBS_INPUT'].decode()"),
                ('from sys import argv as values', 'values[1]')):
            for sink, rule in (("os.system(value)", 'command'), ("eval(value)", 'eval'),
                               ("cursor.execute('SELECT ' + value)", 'sql'),
                               ("HttpResponse(value)", 'xss'), ("requests.get(value)", 'ssrf')):
                with self.subTest(setup=setup, sink=sink):
                    self.assert_rules(f'import os, requests\n{setup}\nvalue = {expression}\n{sink}\n', rule)

    def test_saved_getter_and_collection_defaults_keep_definition_values(self):
        self.assert_rules('''
            import os
            def read(lookup=os.getenv):
                return lookup('UBS_INPUT')
            os = None
            eval(read())
        ''', 'eval')
        self.assert_rules('''
            from os import environ as values
            def read(values=values):
                return values['UBS_INPUT']
            values = {'UBS_INPUT': 'fixed'}
            eval(read())
        ''', 'eval')
        self.assert_rules('''
            from os import getenv as lookup
            lookup = lambda key: 'fixed'
            def read(lookup=lookup):
                return lookup('UBS_INPUT')
            eval(read())
        ''')

    def test_source_member_replacement_reports_incomplete(self):
        cases = (
            "import os\nos.getenv = lambda key: 'fixed'\neval(os.getenv('UBS_INPUT'))\n",
            "import os\nalias = os\nalias.getenvb = lambda key: b'fixed'\n"
            "eval(os.getenvb(b'UBS_INPUT'))\n",
            "import os\nos.getenv = lambda key: 'fixed'\n"
            "from os import getenv\neval(getenv('UBS_INPUT'))\n",
            "import os\nsaved = os.getenv\nos.getenv = lambda key: 'fixed'\n"
            "eval(saved('UBS_INPUT'))\n",
            "import os\nsaved = os.getenv\nos.environ = {'UBS_INPUT': 'fixed'}\n"
            "eval(saved('UBS_INPUT'))\n",
            "import os\nsaved = os.environ\nos.environ = {'UBS_INPUT': 'fixed'}\n"
            "eval(saved['UBS_INPUT'])\n",
            "import os\ndel os.environb\n",
            "import sys\nsys.argv = ['app', 'fixed']\neval(sys.argv[1])\n",
            "import os\ndef replace(module):\n    module.getenv = lambda key: 'fixed'\n"
            "replace(os)\neval(os.getenv('UBS_INPUT'))\n",
            "import os\ndef replace():\n    os.getenv = lambda key: 'fixed'\n"
            "replace()\ndef read():\n    import os\n    return os.getenv('UBS_INPUT')\n"
            "eval(read())\n",
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation'):
                    self.scan(source)

    def test_source_mutation_keeps_established_and_independent_findings(self):
        source = textwrap.dedent('''\
            eval(input())
            import os
            def replace():
                os.getenv = lambda key: 'fixed'
            def independent():
                eval(input())
            replace()
            independent()
        ''')
        engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation') as caught:
            engine.analyze()
        sites = {(kind, line) for (kind, line, _column, _label) in caught.exception.effects}
        self.assertEqual(sites, {('eval', 1), ('eval', 6)})

    def test_collection_item_writes_keep_other_environment_inputs(self):
        self.assert_rules('''
            import os
            os.environ['FIXED_SETTING'] = 'fixed'
            eval(os.getenv('OTHER_SETTING'))
        ''', 'eval')
        self.assert_rules('''
            from os import environ as values
            values['FIXED_SETTING'] = 'fixed'
            eval(values['OTHER_SETTING'])
        ''', 'eval')

    def test_environment_data_keeps_sink_specific_safety(self):
        self.assert_rules('''
            import os, subprocess, shlex
            value = os.getenv('UBS_INPUT', 'fixed')
            subprocess.run(['echo', value])
            os.system('echo ' + shlex.quote(value))
            cursor.execute('SELECT * FROM users WHERE name = %s', (value,))
            value = 'fixed'
            eval(value)
        ''')
        self.assert_rules('''
            from os import getenv as lookup
            def read_setting():
                return lookup('UBS_INPUT')
            eval(read_setting())
        ''', 'eval')
        for source in ("os.getenv('UBS_INPUT')", "values['UBS_INPUT']"):
            with self.subTest(source=source):
                self.assert_rules(f'import os, html\nfrom os import environ as values\n'
                                  f'HttpResponse(html.escape({source}))\n')
                self.assert_rules(f'import os, html\nfrom os import environ as values\n'
                                  f'eval(html.escape({source}))\n', 'eval')


class StdinSourceTests(SourceTest):
    def test_text_readers_reach_each_sink_domain(self):
        sinks = (("os.system(value)", 'command'), ("eval(value)", 'eval'),
                 ("cursor.execute('SELECT ' + value)", 'sql'),
                 ("HttpResponse(value)", 'xss'), ("requests.get(value)", 'ssrf'))
        for reader in ('read()', 'readline()', 'readlines()[0]'):
            for sink, rule in sinks:
                with self.subTest(reader=reader, sink=sink):
                    findings = self.assert_rules(
                        f'import sys, requests\nvalue = sys.stdin.{reader}\n{sink}\n', rule)
                    self.assertIn('sys.stdin', findings[0]['message'])

    def test_original_and_binary_stream_readers(self):
        for member in ('stdin', '__stdin__'):
            for suffix, readers in (('', ('read()', 'readline()', 'readlines()[0]', '__next__()')),
                                    ('.buffer', ('read()', 'read1()', 'peek()', 'readline()',
                                                 'readlines()[0]', '__next__()')),
                                    ('.buffer.raw', ('read()', 'readall()', 'readline()',
                                                     'readlines()[0]', '__next__()'))):
                for reader in readers:
                    with self.subTest(member=member, suffix=suffix, reader=reader):
                        self.assert_rules(f'import sys\neval(sys.{member}{suffix}.{reader})\n', 'eval')
        # Buffered-only methods do not establish a text-stream source API.
        self.assert_rules('import sys\neval(sys.stdin.read1())\n')
        self.assert_rules('import sys\neval(sys.stdin.readall())\n')

    def test_imports_and_saved_methods_keep_native_identity(self):
        cases = (
            'import sys as runtime\neval(runtime.stdin.read())\n',
            'from sys import stdin as stream\neval(stream.readline())\n',
            'from sys import __stdin__ as stream\neval(stream.buffer.read())\n',
            'import sys\nstream = sys.stdin.buffer\neval(stream.read1())\n',
            'import sys\nread = sys.stdin.read\neval(read())\n',
            'import sys\nread = sys.stdin.readline\nsys = None\neval(read())\n',
            'from sys import stdin as stream\nread = stream.read\nstream = None\neval(read())\n',
            'import sys\nread = sys.stdin.buffer.raw.read\neval(read())\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules(source, 'eval')

    def test_helpers_returned_handles_and_defaults_keep_provenance(self):
        cases = (
            'def read(stream):\n    return stream.read()\neval(read(sys.stdin))\n',
            'def read(reader):\n    return reader()\neval(read(sys.stdin.readline))\n',
            'def stream():\n    return sys.stdin\neval(stream().read())\n',
            'def read(stream=sys.stdin):\n    return stream.read()\neval(read())\n',
            'def read(reader=sys.stdin.buffer.read):\n    return reader()\neval(read())\n',
            'def read(stream):\n    return next(stream)\neval(read(sys.stdin))\n',
            'def consume(stream):\n    for line in stream:\n        eval(line)\nconsume(sys.stdin)\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import sys\n' + source, 'eval')

    def test_reader_is_captured_before_argument_rebinding(self):
        self.assert_rules('''
            import sys
            value = sys.stdin.read(((sys := None), 1)[1])
            eval(value)
        ''', 'eval')
        self.assert_rules('''
            import sys
            read = sys.stdin.readline
            value = read(((read := lambda size: 'fixed'), 1)[1])
            eval(value)
        ''', 'eval')

    def test_helper_global_streams_keep_native_consumption_identity(self):
        consumers = (
            'eval(next(stream))\n', 'eval(list(stream)[0])\n', 'eval(tuple(stream)[0])\n',
            'eval(next(iter(stream)))\n', 'for line in stream:\n    eval(line)\n',
            'lines = [line for line in stream]\neval(lines[0])\n',
        )
        for stream in ('sys.stdin', 'sys.__stdin__', 'sys.stdin.buffer'):
            for consumer in consumers:
                source = ('import sys\ndef consume():\n'
                          + textwrap.indent(f'stream = {stream}\n' + consumer, '    ') + 'consume()\n')
                with self.subTest(stream=stream, consumer=consumer):
                    self.assert_rules(source, 'eval')
        for expression in ('"".join(sys.stdin)', 'b"".join(sys.stdin.buffer)'):
            with self.subTest(expression=expression):
                self.assert_rules('import sys\ndef consume():\n'
                                  f'    eval({expression})\nconsume()\n', 'eval')
        self.assert_rules('import sys\ndef inspect():\n    return sys.stdin.encoding\neval(inspect())\n')
        self.assert_rules('import sys\ndef consume():\n    sys = None\n    eval(next(sys.stdin))\nconsume()\n')
        self.assert_rules('import sys\ndef consume():\n    eval("".join(sys.stdin.buffer))\nconsume()\n')

    def test_lines_are_sources_when_consumed(self):
        consumers = (
            'for line in stream:\n    eval(line)\n',
            'lines = [line for line in stream]\neval(lines[0])\n',
            'eval(next(stream))\n', 'eval(list(stream)[0])\n', 'eval(tuple(stream)[0])\n',
            'iterator = iter(stream)\neval(next(iterator))\n',
            'iterator = stream.__iter__()\neval(iterator.__next__())\n',
            'from builtins import next as consume\neval(consume(stream))\n',
        )
        for stream in ('sys.stdin', 'sys.__stdin__', 'sys.stdin.buffer', 'sys.stdin.buffer.raw'):
            for source in consumers:
                with self.subTest(stream=stream, source=source):
                    self.assert_rules(f'import sys\nstream = {stream}\n' + source, 'eval')
        self.assert_rules('import sys\neval("".join(sys.stdin))\n', 'eval')
        self.assert_rules('import sys\nseparator = ","\neval(separator.join(sys.stdin))\n', 'eval')
        self.assert_rules('import sys\neval(b"".join(sys.stdin.buffer))\n', 'eval')
        self.assert_rules('import sys\neval(b"".join(sys.stdin.buffer.raw))\n', 'eval')
        self.assert_rules('import sys\neval("".join(sys.stdin.buffer))\n')
        self.assert_rules('import sys\neval(b"".join(sys.stdin))\n')

    def test_helper_global_builtin_consumers_keep_native_identity(self):
        for expression in ('builtins.next(sys.stdin)', 'builtins.list(sys.stdin)[0]',
                           'builtins.tuple(sys.stdin)[0]', 'next(builtins.iter(sys.stdin))'):
            with self.subTest(expression=expression):
                self.assert_rules('import builtins, sys\ndef consume():\n'
                                  f'    eval({expression})\nconsume()\n', 'eval')
        self.assert_rules('import builtins as native, sys\ndef consume():\n'
                          '    eval(native.next(sys.stdin))\nconsume()\n', 'eval')
        self.assert_rules('import builtins, sys\nsaved = builtins.next\nbuiltins = None\n'
                          'def consume():\n    eval(saved(sys.stdin))\nconsume()\n', 'eval')
        self.assert_rules('''
            import builtins, sys
            class Local:
                @staticmethod
                def next(stream):
                    return 'fixed'
            def consume():
                builtins = Local
                eval(builtins.next(sys.stdin))
            consume()
        ''')
        self.assert_rules('import application.builtins as native, sys\ndef consume():\n'
                          '    eval(native.next(sys.stdin))\nconsume()\n')

    def test_stream_handles_and_metadata_are_not_input_contents(self):
        for stream in ('sys.stdin', 'sys.__stdin__', 'sys.stdin.buffer', 'sys.stdin.buffer.raw'):
            for expression in ('stream', 'stream.name', 'stream.closed', 'stream.fileno()',
                               'stream.isatty()', 'stream.readable()', 'stream.read',
                               'iter(stream)', 'stream.__iter__()'):
                with self.subTest(stream=stream, expression=expression):
                    self.assert_rules(f'import sys\nstream = {stream}\nHttpResponse(str({expression}))\n')
        self.assert_rules('import sys\neval(sys.stdin.encoding)\neval(sys.stdin.errors)\n')
        self.assert_rules('from sys import stdin as stream\nreader = stream.read\neval("1")\n')

    def test_stored_starred_arguments_keep_captured_positions(self):
        for consume in ('next(*arguments)', 'list(*arguments)[0]', 'tuple(*arguments)[0]',
                        'next(iter(*arguments))', '"".join(*arguments)'):
            with self.subTest(consume=consume):
                self.assert_rules('import sys\narguments = (sys.stdin,)\nsys = None\n'
                                  f'eval({consume})\n', 'eval')
        for stream, methods in (('sys.stdin', ('read', 'readline')),
                                ('sys.stdin.buffer', ('read', 'read1', 'readline'))):
            for method in methods:
                with self.subTest(stream=stream, method=method):
                    self.assert_rules('import sys\nsizes = (0,)\n'
                                      f'eval({stream}.{method}(*sizes))\n')
        self.assert_rules('import sys\nsizes = (1,)\neval(sys.stdin.read(*sizes))\n', 'eval')
        self.assert_rules('import sys\nsizes = ()\neval(sys.stdin.read(*sizes))\n', 'eval')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin iterator argument expansion'):
            self.scan('import sys\neval(next(*sys.stdin))\n')

    def test_zero_length_reads_are_empty_but_zero_hints_are_not(self):
        for stream, methods in (('sys.stdin', ('read', 'readline')),
                                ('sys.stdin.buffer', ('read', 'read1', 'readline')),
                                ('sys.stdin.buffer.raw', ('read', 'readline'))):
            for method in methods:
                for zero in ('0', 'size'):
                    with self.subTest(stream=stream, method=method, zero=zero):
                        self.assert_rules(f'import sys\nsize = 0\neval({stream}.{method}({zero}))\n')
            self.assert_rules(f'import sys\neval({stream}.readlines(0)[0])\n', 'eval')
        self.assert_rules('import sys\neval(sys.stdin.buffer.peek(0))\n', 'eval')
        self.assert_rules('''
            import sys
            def read(stream, size):
                return stream.read(size)
            eval(read(sys.stdin, 0))
        ''')

    def test_unrelated_modules_methods_and_shadowed_names_stay_clean(self):
        for module in ('application.sys', 'mysys', 'SYS', '.sys', '..sys'):
            with self.subTest(module=module):
                self.assert_rules(f'from {module} import stdin as stream\neval(stream.read())\n')
        for member in ('stdin_extra', 'STDIN', 'stdout', 'stderr'):
            with self.subTest(member=member):
                self.assert_rules(f'import sys\neval(sys.{member}.read())\n')
        for method in ('reader', 'read_extra', 'READ'):
            with self.subTest(method=method):
                self.assert_rules(f'import sys\neval(sys.stdin.{method}())\n')
        self.assert_rules('import sys\nsys = None\neval(sys.stdin.read())\n')
        self.assert_rules('import io\nstream = io.StringIO("fixed")\neval(stream.read())\n')
        self.assert_rules('''
            import sys
            def read(sys):
                return sys.stdin.read()
            eval(read(None))
        ''')
        self.assert_rules('''
            import sys
            def next(stream):
                return 'fixed'
            eval(next(sys.stdin))
        ''')
        self.assert_rules('''
            import sys
            def iter(stream):
                return ['fixed']
            for line in iter(sys.stdin):
                eval(line)
        ''')

    def test_local_rebinding_revokes_only_the_rebound_name(self):
        self.assert_rules('''
            from sys import stdin as stream
            import io
            stream = io.StringIO('fixed')
            eval(stream.read())
        ''')
        self.assert_rules('''
            import sys
            read = sys.stdin.read
            read = lambda: 'fixed'
            eval(read())
        ''')
        self.assert_rules('''
            import sys
            saved = sys.stdin.read
            read = saved
            read = lambda: 'fixed'
            eval(saved())
        ''', 'eval')

    def test_native_stream_and_method_replacements_are_incomplete(self):
        cases = (
            'import sys\nsys.stdin = other\n',
            'import sys as runtime\nruntime.__stdin__ = other\n',
            'import sys\nsys.stdin.read = lambda: "fixed"\n',
            'from sys import stdin as stream\nstream.readline = lambda: "fixed"\n',
            'import sys\nsys.stdin.buffer = other\n',
            'import sys\nsys.stdin.buffer.raw.read = lambda: b"fixed"\n',
            'import sys\ndef replace(stream):\n    stream.read = lambda: "fixed"\nreplace(sys.stdin)\n',
            'import sys\ndef replace():\n    sys.stdin.read = lambda: "fixed"\nreplace()\n',
            'import sys\ndef replace():\n    sys.stdin.buffer.raw.read = lambda: b"fixed"\nreplace()\n',
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation'):
                    self.scan(source)

    def test_unmodeled_mutation_and_generator_protocols_stay_incomplete(self):
        for operation in ('sys.stdin.buffer.readinto(buffer)', 'sys.stdin.buffer.readinto1(buffer)',
                          'sys.stdin.detach()', 'sys.stdin.buffer.detach()'):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin buffer mutation or detachment'):
                    self.scan('import sys\n' + operation + '\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'generator materialization'):
            self.scan('import sys\neval("".join(line for line in sys.stdin))\n')

    def test_stdin_join_keeps_captured_receiver_producer_obligations(self):
        prefix = ("import sys\ncode = 'fixed'\nclass Owned:\n"
                  + '    def __del__(self):\n        global code\n        code = input()\n'
                  + "def render():\n    owned = Owned()\n    return '|'\n")
        for capture, consumer in (
                ('', 'render().join'),
                ('separator = render()\n', 'separator.join'),
                ('joiner = render().join\n', 'joiner'),
                ('separator = render()\njoiner = separator.join\nseparator = "replacement"\n', 'joiner')):
            source = prefix + capture + consumer + '(sys.stdin)\neval(code)\n'
            with self.subTest(capture=capture, consumer=consumer):
                with temporary_directory(prefix='ubs-stdin-join-producer-') as tmp:
                    path = Path(tmp) / 'view.py'
                    path.write_text(source, encoding='utf-8')
                    findings = []
                    with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin join receiver producer'):
                        for finding in taint_py.run(RunContext(lang='python', files=[path])):
                            findings.append(finding)
                    self.assertEqual(findings, [])
        source = ('eval(input()) # independent\n' + prefix
                  + 'def consume(joiner):\n    joiner(sys.stdin)\n    eval(code)\n'
                  + 'def independent():\n    eval(input()) # independent\n'
                  + 'consume(render().join)\nindependent()\n')
        with temporary_directory(prefix='ubs-stdin-join-producer-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text(source, encoding='utf-8')
            findings = []
            with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin join receiver producer'):
                for finding in taint_py.run(RunContext(lang='python', files=[path])):
                    findings.append(finding)
            self.assertEqual({(finding['rule'], finding['line']) for finding in findings},
                             {('python.taint.eval', line)
                              for line, text in enumerate(source.splitlines(), 1) if '# independent' in text})
        for setup, expression in (
                ('', "'|'.join(sys.stdin)"),
                ("def separator():\n    return '|'\n", 'separator().join(sys.stdin)'),
                ('', "b'|'.join(sys.stdin.buffer)")):
            with self.subTest(setup=setup, expression=expression):
                self.assert_rules('import sys\n' + setup + f'eval({expression})\n', 'eval')
        self.assert_rules('import sys\neval("".join(sys.stdin.buffer))\n')
        self.assert_rules('import sys\neval(b"".join(sys.stdin))\n')

    def test_builtin_consumer_mutations_use_exact_namespace_identity(self):
        for source in (
            'import sys, builtins\nbuiltins.list = lambda stream: ["fixed"]\n'
            'eval(builtins.list(sys.stdin)[0])\n',
            'import sys, builtins as native\nnative.iter = lambda stream: iter(["fixed"])\n'
            'eval(next(iter(sys.stdin)))\n',
            'import sys, builtins\nsaved = builtins.list\nbuiltins.list = lambda stream: ["fixed"]\n'
            'eval(saved(sys.stdin)[0])\n',
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation'):
                    self.scan(source)
        self.assert_rules('''
            import sys
            class Settings:
                pass
            Settings.list = ['fixed']
            eval(list(sys.stdin)[0])
        ''', 'eval')

    def test_partial_stream_analysis_retains_independent_findings(self):
        source = textwrap.dedent('''\
            eval(input())
            import sys
            def replace():
                sys.stdin = other
            def independent():
                eval(input())
            replace()
            independent()
        ''')
        engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('eval', 1), ('eval', 6)})

    def test_variadic_stdin_transport_reports_its_unmodeled_boundary(self):
        cases = (
            'def read(*arguments):\n    return next(*arguments)\neval(read(sys.stdin))\n',
            'def read(*arguments):\n    return arguments[0].read()\neval(read(sys.stdin))\n',
            'def read(*readers):\n    return readers[0]()\neval(read(sys.stdin.read))\n',
            'def stream():\n    return sys.stdin\n'
            'def read(*readers):\n    return readers[0]()\neval(read(stream().read))\n',
            'def read(*arguments):\n    return next(*arguments)\n'
            'def consume():\n    eval(read(sys.stdin))\nconsume()\n',
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin handles through variadic helper'):
                    self.scan('import sys\n' + source)
        for stream, method in (('sys.stdin', 'read'), ('sys.stdin', 'readline'),
                               ('sys.stdin.buffer', 'read1')):
            with self.subTest(stream=stream, method=method), temporary_directory(prefix='ubs-stdin-size-') as tmp:
                path = Path(tmp) / 'view.py'
                path.write_text('import sys\ndef read(*sizes):\n'
                                f'    return {stream}.{method}(*sizes)\neval(read(0))\n', encoding='utf-8')
                emitted = []
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin read size through variadic'):
                    for finding in taint_py.run(RunContext(lang='python', files=[path])):
                        emitted.append(finding)
                self.assertEqual(emitted, [], 'An incomplete zero-size read must not emit a false critical')
        engine = taint_py._Analysis(ast.parse(textwrap.dedent('''\
            eval(input())
            import sys
            def read(*arguments):
                return next(*arguments)
            def independent():
                eval(input())
            read(sys.stdin)
            independent()
        ''')))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin handles through variadic helper') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('eval', 1), ('eval', 6)})
        engine = taint_py._Analysis(ast.parse(textwrap.dedent('''\
            eval(input())
            import sys
            def read(*sizes):
                return sys.stdin.read(*sizes)
            eval(read(0))
            def independent():
                eval(input())
            independent()
        ''')))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin read size through variadic') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('eval', 1), ('eval', 7)})

    def test_variadic_boundary_keeps_supported_data_and_fixed_parameters(self):
        self.assert_rules('''
            import sys
            def read(stream, *rest):
                return stream.read()
            eval(read(sys.stdin, 'unused'))
        ''', 'eval')
        self.assert_rules('''
            import sys
            def ignore(*arguments):
                return 'fixed'
            eval(ignore(sys.stdin))
        ''')
        self.assert_rules('''
            import sys
            def replace(*arguments):
                arguments = ('fixed',)
                return arguments[0]
            eval(replace(sys.stdin))
        ''')
        self.assert_rules('''
            def identity(*values):
                return values[0]
            eval(identity(input()))
        ''', 'eval')
        self.assert_rules('''
            def identity(*values):
                return values[0]
            eval(identity('fixed'))
        ''')
        self.assert_rules('''
            import sys
            def read(*sizes):
                return sys.stdin.readlines(*sizes)
            eval(read(0)[0])
        ''', 'eval')

    def test_stdin_data_keeps_sink_specific_safety(self):
        self.assert_rules('''
            import sys, subprocess, html, shlex
            value = sys.stdin.read()
            subprocess.run(['echo', value])
            os.system('echo ' + shlex.quote(value))
            cursor.execute('SELECT * FROM users WHERE name = %s', (value,))
            HttpResponse(html.escape(value))
            value = 'fixed'
            eval(value)
        ''')
        self.assert_rules('import sys, html\neval(html.escape(sys.stdin.read()))\n', 'eval')


class ReachingDefinitionTests(SourceTest):
    def test_safe_reassignment_kills_taint(self):
        self.assert_rules("q = input()\nq = 'safe'\neval(q)\n")

    def test_later_assignment_does_not_taint_earlier_use(self):
        self.assert_rules("q = 'safe'\neval(q)\nq = input()\n")

    def test_distinct_function_scopes_do_not_leak(self):
        self.assert_rules('''
            def first():
                q = input()
            def second():
                q = 'safe'
                eval(q)
        ''')

    def test_both_branch_orders_keep_an_unsafe_reaching_definition(self):
        for left, right in (('html.escape(q)', 'q'), ('q', 'html.escape(q)')):
            with self.subTest(left=left):
                self.assert_rules(f"q = input()\nif condition:\n    x = {left}\nelse:\n    x = {right}\nHttpResponse(x)\n", 'xss')
        self.assert_rules("q = input()\nif condition:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = input()\nif condition:\n    q = 'safe'\nelse:\n    q = 'also safe'\neval(q)\n")

    def test_conditional_expression_and_walrus(self):
        self.assert_rules("q = input()\nx = html.escape(q) if condition else q\nHttpResponse(x)\n", 'xss')
        self.assert_rules("eval(q := input())\n", 'eval')
        self.assert_rules("q = 'a' if input() else 'b'\neval(q)\n")

    def test_loops_reach_a_fixed_point(self):
        self.assert_rules("a = 'safe'\nb = 'safe'\nwhile condition:\n    a = b\n    b = input()\neval(a)\n", 'eval')
        self.assert_rules("q = input()\nfor x in values:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("for q in request.args.values():\n    eval(q)\n", 'eval')

    def test_tuple_assignment_is_simultaneous(self):
        self.assert_rules("a = input()\nb = 'safe'\na, b = b, a\neval(b)\n", 'eval')
        self.assert_rules("a = input()\nb = 'safe'\na, b = b, a\neval(a)\n")

    def test_break_bypasses_loop_else_and_continue_skips_remaining_body(self):
        self.assert_rules("q = input()\nfor item in values:\n    break\nelse:\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = 'safe'\nfor item in values:\n    continue\n    q = input()\neval(q)\n")
        self.assert_rules("q = 'safe'\nwhile condition:\n    q = input()\n    if other:\n        break\n    q = 'safe'\neval(q)\n", 'eval')
        self.assert_rules("q = 'safe'\nwhile condition:\n    try:\n        break\n    finally:\n        q = input()\nelse:\n    q = 'safe'\neval(q)\n", 'eval')

    def test_exception_and_finally_paths_keep_taint(self):
        self.assert_rules("q = 'safe'\ntry:\n    q = input()\n    work()\n    q = 'safe'\nexcept Exception:\n    eval(q)\n", 'eval')
        self.assert_rules("def run():\n    q = 'safe'\n    try:\n        q = input()\n        return\n    finally:\n        eval(q)\n", 'eval')

    def test_multiline_calls_and_hashes_in_strings(self):
        findings = self.assert_rules("q = input()\ncursor.execute(\n    '# ' + q\n)\n", 'sql')
        self.assertEqual((findings[0]['line'], findings[0]['col']), (2, 1))

    def test_string_and_comment_examples_are_not_code(self):
        self.assert_rules('''
            example = "eval(input())"
            # eval(input())
            q = input()
            eval('q')
        ''')

    def test_comprehension_scope_and_container_write(self):
        self.assert_rules("values = [x for x in request.args.values()]\neval(values[0])\n", 'eval')
        self.assert_rules("q = 'safe'\nvalues = [q for q in request.args.values()]\neval(q)\n")
        self.assert_rules("items = {}\nitems['q'] = input()\nitems['safe'] = 'safe'\neval(items['q'])\n", 'eval')

    def test_rule_profile_disables_findings(self):
        with temporary_directory(prefix='ubs-taint-profile-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text('eval(input())\n')
            ctx = RunContext(lang='python', files=[path], profile={'disabled_rules': ['python.taint.eval']})
            self.assertEqual(list(taint_py.run(ctx)), [])

    def test_legacy_and_structured_outputs_agree(self):
        with temporary_directory(prefix='ubs-taint-dialects-') as tmp:
            path = Path(tmp) / 'view.py'
            path.write_text(''.join('eval(input())\n' for _ in range(5)))
            findings = list(taint_py.run(RunContext(lang='python', files=[path])))
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(taint_py.main(['taint', tmp]), 0)
            rule, count, samples = buffer.getvalue().strip().split('\t')
            self.assertEqual(rule, 'py.taint.eval')
            self.assertEqual(int(count), len(findings))
            self.assertEqual(len(samples.split(',')), 3)


class FrameworkBindingControls(SourceTest):
    def test_runtime_strings_are_not_framework_markers_or_request_types(self):
        for default, sink in (("'Query()'", "eval(value)"), ("'Request'", "eval(value.headers)")):
            with self.subTest(default=default):
                self.assert_rules(f'from fastapi import Query, Request\ndef ordinary(value={default}):\n    {sink}\n')
        self.assert_rules('''
            from fastapi import FastAPI, Depends
            app = FastAPI()
            @app.get('/')
            def endpoint(value='Depends(service)'):
                eval(value)
        ''', 'eval')

    def test_annotated_metadata_strings_are_inert(self):
        self.assert_rules('''
            from typing import Annotated
            from fastapi import Query
            def ordinary(value: Annotated[str, 'Query()']):
                eval(value)
        ''')
        self.assert_rules('''
            from typing import Annotated
            from fastapi import FastAPI, Depends
            app = FastAPI()
            @app.get('/')
            def endpoint(value: Annotated[str, 'Depends(service)']):
                eval(value)
        ''', 'eval')

    def test_constructed_source_and_dependency_markers_keep_identity(self):
        for parameter in ('value=marker', 'value: Annotated[str, marker]'):
            with self.subTest(parameter=parameter):
                self.assert_rules(f'from typing import Annotated\nfrom fastapi import Query\nmarker = Query()\n'
                                  f'def endpoint({parameter}):\n    eval(value)\n', 'eval')
                self.assert_rules(f'from typing import Annotated\nfrom fastapi import FastAPI, Depends\n'
                                  f'marker = Depends(service)\napp = FastAPI()\n@app.get("/")\n'
                                  f'def endpoint({parameter}):\n    eval(value)\n')

    def test_each_default_captures_its_own_evaluated_identity(self):
        self.assert_rules('''
            from fastapi import Query
            def endpoint(value=Query(), ignored=(Query := other)):
                eval(value)
        ''', 'eval')
        self.assert_rules('''
            from fastapi import Query as real
            Query = other
            def ordinary(value=Query(), ignored=(Query := real)):
                eval(value)
        ''')

    def test_marker_and_router_callable_precede_argument_side_effects(self):
        self.assert_rules('''
            from fastapi import Query
            def endpoint(value=Query(default=(Query := other))):
                eval(value)
        ''', 'eval')
        self.assert_rules('''
            from fastapi import FastAPI
            app = FastAPI(title=(FastAPI := other))
            @app.get('/')
            def endpoint(value):
                eval(value)
        ''', 'eval')

    def test_decorator_identity_precedes_default_evaluation(self):
        self.assert_rules('''
            from fastapi import FastAPI
            app = FastAPI()
            @app.get('/')
            def endpoint(value, ignored=(app := other)):
                eval(value)
        ''', 'eval')
        self.assert_rules('''
            from fastapi import FastAPI
            real = FastAPI()
            app = other
            @app.get('/')
            def ordinary(value, ignored=(app := real)):
                eval(value)
        ''')

    def test_request_member_names_require_a_word_boundary(self):
        self.assert_rules('def ordinary(request):\n    eval(request.database)\n    eval(request.GETAWAY)\n')


class SuppressionTests(SourceTest):
    def test_marker_inside_string_does_not_disable_security(self):
        self.assert_rules("label = 'ubs:ignore'\neval(input())\n", 'eval')
        self.assert_rules("eval(input() + 'ubs:ignore')\n", 'eval')

    def test_scoped_markers_preserve_other_rules(self):
        self.assert_rules('# ubs:ignore[python.taint.xss]\neval(input())\n', 'eval')
        self.assert_rules('# ubs:ignore[python.taint.eval]\neval(input())\n')
        self.assert_rules('# ubs:ignore[py.taint.eval]\neval(input())\n')

    def test_trailing_marker_belongs_to_previous_statement(self):
        self.assert_rules("safe = 1  # ubs:ignore\neval(input())\n", 'eval')
        self.assert_rules('eval(input())  # ubs:ignore\n')

    def test_multiline_statement_uses_shared_interval_ownership(self):
        self.assert_rules('cursor.execute(\n    input()  # ubs:ignore[py.taint.sql]\n)\n')
        self.assert_rules('''
            # ubs:ignore[py.taint.sql]
            result = cursor.execute(
                input()
            )
        ''')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 to run real runner integration')
class RunnerIntegrationTests(unittest.TestCase):
    def test_runner_emits_taint_findings_and_safe_parameter_control(self):
        for code, expected in (("q=html.escape(input())\ncursor.execute(q)\n", True),
                               ("q=input()\ncursor.execute('select %s', (q,))\n", False),
                               ("import os\ncursor.execute('SELECT ' + os.getenv('UBS_INPUT'))\n", True),
                               ("from os import environ as values\ncursor.execute('SELECT ' + values['UBS_INPUT'])\n", True),
                               ("import os\ncursor.execute('SELECT %s', (os.getenv('UBS_INPUT'),))\n", False),
                               ("import sys\ncursor.execute('SELECT ' + sys.stdin.read())\n", True),
                               ("from sys import stdin as stream\ncursor.execute(stream.readline())\n", True),
                               ("import sys\ncursor.execute(sys.stdin.buffer.read().decode())\n", True),
                               ("import sys\nfor line in sys.stdin:\n    cursor.execute(line)\n", True),
                               ("import sys\nargs = (sys.stdin,)\ncursor.execute(next(*args))\n", True),
                               ("import sys\ncursor.execute('SELECT %s', (sys.stdin.read(),))\n", False),
                               ("import sys\ncursor.execute(sys.stdin.read(0))\n", False),
                               ("import sys\ncursor.execute(sys.stdin.encoding)\n", False),
                               ("match request.get_json():\n    case {**rest}:\n        cursor.execute(rest['query'])\n", True),
                               ("match cursor.execute:\n    case execute:\n        execute(input())\n", True),
                               ("match request.get_json():\n    case {**rest}:\n        cursor.execute('select %s', (rest,))\n", False),
                               ("q='safe'\nmatch payload:\n    case _ if (q := input()) and False:\n        pass\n"
                                "    case _:\n        cursor.execute(q)\n", True),
                               ("match payload:\n    case _ if False:\n        cursor.execute(input())\n", False)):
            with self.subTest(code=code), temporary_directory(prefix='ubs-taint-e2e-') as tmp:
                path = Path(tmp) / 'view.py'
                path.write_text(code)
                env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_SKIP_SIZE_CHECK='1')
                result = subprocess.run([str(ROOT / 'ubs'), str(path), '--only=python', '--ci', '--format=json'],
                                        cwd=tmp, env=env, capture_output=True, text=True, timeout=180)
                self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report.get('status'), 'ok', result.stdout + result.stderr)
                # Inspect rule IDs, not general critical counts (other detectors
                # may independently report the deliberately unsafe source).
                def rules(value):
                    found = set()
                    if isinstance(value, dict):
                        for key, item in value.items():
                            if key in {'rule', 'rule_id', 'ruleId', 'id'} and isinstance(item, str):
                                found.add(item)
                            found.update(rules(item))
                    elif isinstance(value, list):
                        for item in value:
                            found.update(rules(item))
                    return found
                ids = rules(report)
                self.assertEqual(bool(ids & {'py.taint.sql', 'python.taint.sql'}), expected, report)


if __name__ == '__main__':
    unittest.main(verbosity=2)
