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

    def test_binary_readinto_writes_reach_each_sink_domain(self):
        sinks = (("os.system(value)", 'command'), ("eval(value)", 'eval'),
                 ("cursor.execute('SELECT ' + value)", 'sql'),
                 ("HttpResponse(value)", 'xss'), ("requests.get(value)", 'ssrf'))
        for member in ('stdin', '__stdin__'):
            for suffix, method in (('.buffer', 'readinto'), ('.buffer', 'readinto1'),
                                   ('.buffer.raw', 'readinto')):
                for sink, rule in sinks:
                    with self.subTest(member=member, suffix=suffix, method=method, sink=sink):
                        findings = self.assert_rules(
                            f'import sys, requests\nbuffer = bytearray(4096)\n'
                            f'sys.{member}{suffix}.{method}(buffer)\n'
                            f'value = buffer.decode()\n{sink}\n', rule)
                        self.assertIn(f'sys.{member}{suffix}', findings[0]['message'])

    def test_binary_readinto_native_counts_aliases_and_empty_storage(self):
        # Exercise CPython's real stdin protocol without evaluating its data.
        # The count is scalar, aliases observe the write, and a prior immutable
        # copy cannot acquire data written after that copy was made.
        for method in ('buffer.readinto', 'buffer.readinto1', 'buffer.raw.readinto'):
            for capacity in (0, 8):
                with self.subTest(method=method, capacity=capacity):
                    program = ('import json,sys\n'
                               f'buffer = bytearray({capacity})\nalias = buffer\n'
                               'before = bytes(buffer)\n'
                               f'count = sys.stdin.{method}(alias)\n'
                               'print(json.dumps([count, list(buffer), list(before), alias is buffer]))\n')
                    result = subprocess.run([sys.executable, '-I', '-c', program],
                                            input=b'external-input', capture_output=True,
                                            timeout=15, check=True)
                    self.assertEqual(json.loads(result.stdout),
                                     [capacity, list(b'external'[:capacity]), [0] * capacity, True])

    def test_binary_readinto_preserves_buffer_and_reader_aliases(self):
        cases = (
            'alias = buffer\nsys.stdin.buffer.readinto(alias)\neval(buffer.decode())\n',
            'alias = buffer\nsys.stdin.buffer.readinto(buffer)\neval(alias.decode())\n',
            'read = sys.stdin.buffer.readinto\nsys = None\nread(buffer)\neval(buffer.decode())\n',
            'from sys import stdin as stream\nread = stream.buffer.readinto1\n'
            'stream = None\nread(buffer)\neval(buffer.decode())\n',
            'arguments = (buffer,)\nsys.stdin.buffer.readinto(*arguments)\neval(buffer.decode())\n',
            'sys.stdin.buffer.readinto((alias := buffer))\neval(alias.decode())\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import sys\nbuffer = bytearray(16)\n' + source, 'eval')
        for allocation in ('builtins.bytearray(16)', 'make(16)'):
            with self.subTest(allocation=allocation):
                self.assert_rules('import sys, builtins\nfrom builtins import bytearray as make\n'
                                  f'buffer = {allocation}\nsys.stdin.buffer.readinto(buffer)\n'
                                  'eval(buffer.decode())\n', 'eval')
        self.assert_rules('import sys\nmake = bytearray\nbytearray = lambda size: None\n'
                          'buffer = make(16)\nsys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n', 'eval')

    def test_binary_readinto_exports_mutations_from_fixed_helpers(self):
        cases = (
            'def fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\nfill(buffer)\n',
            'def fill(stream, buffer):\n    stream.readinto(buffer)\nfill(sys.stdin.buffer, buffer)\n',
            'def fill(read, buffer):\n    read(buffer)\nfill(sys.stdin.buffer.readinto, buffer)\n',
            'def fill(buffer, read=sys.stdin.buffer.readinto):\n    read(buffer)\nfill(buffer)\n',
            'def fill():\n    sys.stdin.buffer.readinto(buffer)\nfill()\n',
            'def fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\n'
            'def forward(buffer):\n    fill(buffer)\nforward(buffer)\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import sys\nbuffer = bytearray(16)\n' + source
                                  + 'eval(buffer.decode())\n', 'eval')
        self.assert_rules('import sys\ndef consume():\n    buffer = bytearray(16)\n'
                          '    sys.stdin.buffer.readinto(buffer)\n    eval(buffer.decode())\nconsume()\n', 'eval')

    def test_binary_readinto_count_empty_storage_and_unrelated_data_stay_clean(self):
        for allocation in ('bytearray()', 'bytearray(0)', 'bytearray(False)', 'bytearray(b"")'):
            with self.subTest(allocation=allocation):
                self.assert_rules('import sys\n' + f'buffer = {allocation}\n'
                                  'sys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n')
        self.assert_rules('import sys\nbuffer = bytearray(16)\n'
                          'count = sys.stdin.buffer.readinto(buffer)\nHttpResponse(str(count))\n')
        self.assert_rules('import sys\nbuffer = bytearray(16)\nother = bytearray(b"1")\n'
                          'sys.stdin.buffer.readinto(buffer)\neval(other.decode())\n')
        self.assert_rules('import sys\nbuffer = bytearray(b"1")\ncopy = bytes(buffer)\n'
                          'sys.stdin.buffer.readinto(buffer)\neval(copy.decode())\n')
        self.assert_rules('import sys\nbuffer = bytearray(16)\nsys.stdin.buffer.readinto(buffer)\n'
                          'buffer = bytearray(b"1")\neval(buffer.decode())\n')
        self.assert_rules('import sys\ndef fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\n'
                          'buffer = bytearray()\nfill(buffer)\neval(buffer.decode())\n')

    def test_binary_readinto_selected_helper_modules_specialize_before_qualification(self):
        for capacity, expected in ((0, []), (16, ['python.taint.eval'])):
            with self.subTest(capacity=capacity), temporary_directory(prefix='ubs-readinto-modules-') as directory:
                root = Path(directory)
                helper, caller = root / 'reader.py', root / 'app.py'
                helper.write_text('import sys\ndef fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\n',
                                  encoding='utf-8')
                caller.write_text('from reader import fill\n' + f'buffer = bytearray({capacity})\n'
                                  + 'fill(buffer)\neval(buffer.decode())\n', encoding='utf-8')
                findings = list(taint_py.run(RunContext(lang='python', files=[caller, helper])))
                self.assertEqual([finding['rule'] for finding in findings], expected, findings)
                if findings:
                    self.assertEqual(findings[0]['path'], str(caller))
                    self.assertEqual(findings[0]['line'], 4)

    def test_binary_readinto_resizing_and_control_flow_keep_possible_writes(self):
        self.assert_rules('import sys\nbuffer = bytearray()\nalias = buffer\nalias.extend(b" ")\n'
                          'sys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n', 'eval')
        self.assert_rules('import sys\nbuffer = bytearray(16)\nif enabled:\n'
                          '    sys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n', 'eval')
        self.assert_rules('import sys\nif enabled:\n    buffer = bytearray()\n'
                          'else:\n    buffer = bytearray(16)\nsys.stdin.buffer.readinto(buffer)\n'
                          'eval(buffer.decode())\n', 'eval')
        self.assert_rules('import sys\nbuffer = bytearray(16)\ntry:\n'
                          '    sys.stdin.buffer.readinto(buffer)\nexcept OSError:\n'
                          '    eval(buffer.decode())\n', 'eval')

    def test_binary_readinto_respects_bound_data_and_sanitizer_domains(self):
        prefix = ('import sys, html, shlex\nbuffer = bytearray(16)\n'
                  'sys.stdin.buffer.readinto(buffer)\nvalue = buffer.decode()\n')
        self.assert_rules(prefix + "cursor.execute('SELECT ?', (value,))\n")
        self.assert_rules(prefix + 'HttpResponse(html.escape(value))\n')
        self.assert_rules(prefix + "os.system('printf %s ' + shlex.quote(value))\n")
        self.assert_rules(prefix + 'eval(html.escape(value))\n', 'eval')

    def test_binary_readinto_invalid_calls_and_unrelated_names_do_not_write(self):
        for call in ('sys.stdin.buffer.readinto()', 'sys.stdin.buffer.readinto(b=buffer)',
                     'sys.stdin.buffer.readinto(buffer, 1)', 'sys.stdin.readinto(buffer)',
                     'sys.stdin.buffer.raw.readinto1(buffer)', 'sys.stdout.buffer.readinto(buffer)',
                     'sys.stdin.buffer.READINTO(buffer)'):
            with self.subTest(call=call):
                self.assert_rules('import sys\nbuffer = bytearray(16)\n' + call
                                  + '\neval(buffer.decode())\n')
        self.assert_rules('from . import sys\nbuffer = bytearray(16)\n'
                          'sys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n')
        self.assert_rules('import sys\nread = sys.stdin.buffer.readinto\nread = lambda b: 0\n'
                          'buffer = bytearray(16)\nread(buffer)\neval(buffer.decode())\n')

    def test_binary_readinto_unknown_buffers_and_mutated_native_apis_stay_incomplete(self):
        for buffer in ('unknown()', '[]', 'b"fixed"', 'memoryview(bytearray(16))', 'bytearray(size)'):
            with self.subTest(buffer=buffer), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin buffer mutation'):
                self.scan('import sys\nbuffer = ' + buffer + '\nsys.stdin.buffer.readinto(buffer)\n')
        for setup in ('builtins.bytearray = replacement',
                      'sys.stdin.buffer.readinto = replacement',
                      'sys.stdin.buffer.readinto1 = replacement'):
            with self.subTest(setup=setup), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation'):
                self.scan('import sys, builtins\n' + setup + '\nbuffer = bytearray(16)\n'
                          'sys.stdin.buffer.readinto(buffer)\n')
        for call in ('sys.stdin.buffer.readinto(*arguments)', 'sys.stdin.buffer.readinto(buffer, **options)'):
            with self.subTest(call=call), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin buffer mutation argument'):
                self.scan('import sys\nbuffer = bytearray(16)\n' + call + '\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin buffer mutation'):
            self.scan('import sys\ndef make():\n    owned = Owner()\n    return bytearray(16)\n'
                      'buffer = make()\nsys.stdin.buffer.readinto(buffer)\neval(buffer.decode())\n')
        for invocation in ('', 'fill(unknown())\n', 'register(fill)\nfill(bytearray(16))\n'):
            with self.subTest(invocation=invocation), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin buffer mutation'):
                self.scan('import sys\ndef fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\n' + invocation)

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


class ZipIteratorTests(SourceTest):
    def test_native_zip_stream_rows_reach_each_sink(self):
        sinks = (("eval(code)", 'eval'), ("os.system(code)", 'command'),
                 ("cursor.execute(code)", 'sql'), ("HttpResponse(code)", 'xss'),
                 ("requests.get(code)", 'ssrf'))
        for sink, rule in sinks:
            for prefix in ("for label, code in zip(['fixed'], sys.stdin):\n    ",
                           "label, code = next(zip(['fixed'], sys.stdin))\n",
                           "code = next(zip(['fixed'], sys.stdin))[1]\n"):
                with self.subTest(sink=sink, prefix=prefix):
                    self.assert_rules('import sys, os, requests\n' + prefix + sink + '\n', rule)

    def test_zip_preserves_clean_columns_and_exact_shortest_input(self):
        cases = (
            "for label, code in zip(['fixed'], sys.stdin):\n    eval(label)",
            "eval(next(zip(['fixed'], sys.stdin))[0])",
            "for code, label in zip(sys.stdin, []):\n    eval(code)",
            "for label, code in zip([], sys.stdin):\n    eval(code)",
            "for code in zip():\n    eval(input())",
            "rows = zip([input(), 'safe'], [])\nvalue = next(rows, 'safe')\neval(value)",
            "rows = zip(['safe'], ['safe', input()])\nnext(rows)\neval(next(rows, 'safe'))",
            "rows = zip(['safe'], [input()])\neval('fixed')",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import sys\n' + source + '\n')

    def test_zip_aliases_native_builtins_and_captured_streams(self):
        setups = (
            "rows = zip(['fixed'], sys.stdin)\nalias = rows\nvalue = next(alias)[1]",
            "from builtins import zip as pair\nvalue = next(pair(['fixed'], sys.stdin))[1]",
            "import builtins\npair = builtins.zip\nvalue = next(pair(['fixed'], sys.stdin))[1]",
            "pair = zip\nzip = lambda a, b: [('fixed', 'fixed')]\nvalue = next(pair(['fixed'], sys.stdin))[1]",
            "stream = iter(sys.stdin)\nrows = zip(stream, stream)\nvalue = next(rows)[1]",
            "rows = zip(['fixed'], sys.stdin).__iter__()\nread = rows.__next__\nvalue = read()[1]",
        )
        for source in setups:
            with self.subTest(source=source):
                self.assert_rules('import sys\n' + source + '\neval(value)\n', 'eval')

    def test_zip_materialization_and_comprehensions_keep_slot_identity(self):
        for consumer in ('list', 'tuple'):
            with self.subTest(consumer=consumer):
                self.assert_rules(f'import sys\nrows = {consumer}(zip(["fixed"], sys.stdin))\n'
                                  'eval(rows[0][1])\n', 'eval')
                self.assert_rules(f'import sys\nrows = {consumer}(zip(["fixed"], sys.stdin))\n'
                                  'eval(rows[0][0])\n')
        self.assert_rules('import sys\nvalues = [code for label, code in zip(["fixed"], sys.stdin)]\n'
                          'eval(values[0])\n', 'eval')
        self.assert_rules('import sys\nvalues = [label for label, code in zip(["fixed"], sys.stdin)]\n'
                          'eval(values[0])\n')

    def test_zip_cursor_aliases_do_not_replay_finite_rows(self):
        self.assert_rules('rows = zip([input(), "safe"], [0, 1])\nalias = rows\n'
                          'first = next(rows)\nsecond = next(alias)\neval(second[0])\n')
        self.assert_rules('rows = zip(["safe", input()], [0, 1])\nalias = rows\n'
                          'next(rows)\nsecond = next(alias)\neval(second[0])\n', 'eval')
        self.assert_rules('rows = zip([input()], [0])\nlist(rows)\n'
                          'eval(next(rows, "safe"))\n')

    def test_zip_loop_completion_preserves_callback_free_row_order(self):
        self.assert_rules('value = input()\nfor replacement, unused in zip(["safe"], [0]):\n'
                          '    value = replacement\neval(value)\n')
        self.assert_rules('value = "safe"\nfor replacement, unused in zip([input()], []):\n'
                          '    value = replacement\neval(value)\n')
        self.assert_rules('rows = zip(["safe", input()], [0, 1])\nfor code, unused in rows:\n'
                          '    break\neval(next(rows)[0])\n', 'eval')

    def test_zip_selected_helpers_construct_native_iterators(self):
        self.assert_rules('import sys\ndef pairs(stream):\n    return zip(["fixed"], stream)\n'
                          'eval(next(pairs(sys.stdin))[1])\n', 'eval')
        self.assert_rules('import sys\ndef consume(stream):\n'
                          '    for label, code in zip(["fixed"], stream):\n        eval(code)\n'
                          'consume(sys.stdin)\n', 'eval')
        self.assert_rules('import sys\ndef native_constructor():\n    return zip\n'
                          'eval(next(native_constructor()(["fixed"], sys.stdin))[1])\n', 'eval')

    def test_zip_does_not_change_unknown_tuple_assignment(self):
        self.assert_rules('left, right = unknown(input())\neval(right)\n', 'eval')
        self.assert_rules('def pair(value):\n    return unknown(value)\n'
                          'left, right = pair(input())\neval(right)\n', 'eval')
        self.assert_rules('values = [*unknown(input())]\neval(values[50])\n', 'eval')
        self.assert_rules('values = [*unknown(input())]\neval(values[-50])\n', 'eval')

    def test_zip_retains_unknown_producer_and_repeated_call_boundaries(self):
        cases = (
            'def factory():\n    owned = opaque()\n    return zip\n'
            'rows = factory()(["fixed"], sys.stdin)\neval(next(rows)[0])',
            'def factory():\n    owned = opaque()\n    return sys.stdin\n'
            'rows = zip(["fixed"], factory())\neval(next(rows)[0])',
            'def consume(stream):\n    for label, code in zip(["fixed"], stream):\n        eval(code)\n'
            'consume(sys.stdin)\nconsume(sys.stdin)',
            'def consume(stream):\n    for label, code in zip(["fixed"], stream):\n        eval(code)\n'
            'for unused in [0, 1]:\n    consume(sys.stdin)',
            'for unused in [0, 1]:\n    for label, code in zip(["fixed"], sys.stdin):\n        eval(opaque)',
            'def consume(stream):\n    for unused in [0, 1]:\n'
            '        for label, code in zip(["fixed"], stream):\n            eval(opaque)\n'
            'consume(sys.stdin)',
            'eval(opaque)\nrows = zip(["fixed"], sys.stdin)\neval(next(rows)[0])',
            'rows = zip(["fixed"], sys.stdin)\nrows()\neval(input())',
            'rows = zip(["fixed"], sys.stdin)\nvalue = rows[0]\neval(input())',
            'def unused(stream):\n    return zip(["fixed"], stream)',
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip'):
                self.scan('import sys\n' + source + '\n')

    def test_zip_shadowed_callable_retains_local_function_semantics(self):
        self.assert_rules('def zip(a, b):\n    return [("fixed", "fixed")]\n'
                          'for label, code in zip([input()], [0]):\n    eval(code)\n')
        self.assert_rules('def zip(a, b):\n    return [("fixed", input())]\n'
                          'for label, code in zip(["safe"], [0]):\n    eval(code)\n', 'eval')
        self.assert_rules('zip = opaque\neval(zip(input(), [0]))\n', 'eval')

    def test_unproved_zip_identity_cannot_discard_protected_source_inputs(self):
        cases = ('zip(["fixed"], sys.stdin)', 'zip(["fixed"], csv.reader(sys.stdin))',
                 'zip(["fixed"], iter(sys.stdin.readline, ""))',
                 'zip([input()], [0])', 'zip(unknown(input()), unknown())', 'zip()')
        for expression in cases:
            with self.subTest(expression=expression), self.assertRaises(taint_py.AnalysisLimit):
                self.scan('import sys, csv\ngetattr(opaque, "field")\nrows = ' + expression + '\n')

    def test_zip_mutable_backing_and_unknown_protocols_are_explicit(self):
        cases = (
            'values = ["safe"]\nrows = zip(values, [0])\nvalues[0] = input()\neval(next(rows)[0])',
            'rows = zip(opaque, [0])\nfor code, unused in rows:\n    eval(code)',
            'rows = zip(["safe"], sys.stdin, strict=True)\nlist(rows)\neval(input())',
            'rows = zip(*opaque)\neval(next(rows)[0])',
            'rows = zip(["safe"], sys.stdin)\nexternal(rows)\neval(next(rows)[1])',
            'rows = zip(["safe"], sys.stdin)\ndef take(values):\n    return next(values)\n'
            'eval(take(rows)[1])',
        )
        for source in cases:
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip'):
                self.scan('import sys\n' + source + '\n')
        # Rebinding a stdlib source member already has a module-wide boundary;
        # capturing a zip first must not turn that mutation into a clean result.
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdlib source member mutation'):
            self.scan('import sys\nrows = zip(["fixed"], sys.stdin)\nsys.stdin = None\n'
                      'eval(next(rows)[1])\n')

    def test_zip_partial_row_read_errors_never_certify_resumed_handles(self):
        consumers = ('    next(rows)\n', '    list(rows)\n',
                     '    for value, record in rows:\n        pass\n')
        for stream, exception in (('csv.reader(sys.stdin)', 'csv.Error'),
                                  ('sys.stdin', '(OSError, UnicodeError)'),
                                  ('iter(sys.stdin.readline, "")', '(OSError, UnicodeError)')):
            for consume in consumers:
                source = ('import sys, csv\nrows = zip(["safe", input()], ' + stream + ')\n'
                          'try:\n' + consume + 'except ' + exception + ':\n'
                          '    cursor.execute(next(rows)[0])\n')
                with self.subTest(stream=stream, consume=consume), \
                        self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                    self.scan(source)
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
            self.scan('import sys, csv\nrows = zip(["safe", input()], csv.reader(sys.stdin))\n'
                      'try:\n    next(rows)\nfinally:\n    cursor.execute(next(rows)[0])\n')
        # Ordinary selected helper loops remain supported; collecting their
        # exceptional summary is not itself a reason to refuse native zip.
        self.assert_rules('import sys\ndef consume(stream):\n'
                          '    for label, code in zip(["safe"], stream):\n        pass\n'
                          'try:\n    consume(sys.stdin)\nexcept OSError:\n    cursor.execute(input())\n', 'sql')

    def test_zip_empty_input_order_retains_native_read_failure_boundary(self):
        for consume in ('    next(rows)\n', '    list(rows)\n',
                        '    for value, record in rows:\n        pass\n'):
            suffix = ('try:\n' + consume + 'except csv.Error:\n'
                      '    cursor.execute(next(rows)[0])\n')
            with self.subTest(consume=consume, order='empty-first'):
                self.assert_rules('import sys, csv\nrows = zip([], csv.reader(sys.stdin))\n' + suffix)
            with self.subTest(consume=consume, order='reader-first'), \
                    self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                self.scan('import sys, csv\nrows = zip(csv.reader(sys.stdin), [])\n' + suffix)

    def test_zip_native_eof_does_not_certify_permanent_exhaustion(self):
        consumers = ('list(rows)\n', 'tuple(rows)\n',
                     'for value, record in rows:\n    pass\n', 'next(rows, None)\n')
        for stream in ('sys.stdin', 'csv.reader(sys.stdin)'):
            for consume in consumers:
                source = ('import sys, csv\nrows = zip(["safe", input()], ' + stream + ')\n'
                          'sys.stdin.read()\n' + consume + 'sys.stdin.seek(0)\n'
                          'cursor.execute(next(rows)[0])\n')
                with self.subTest(stream=stream, consume=consume), \
                        self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                    self.scan(source)
        # The cursor boundary covers aliases of the input and its seek method;
        # recognizing a particular spelling of seek cannot prove EOF stable.
        for reset in ('stream = sys.stdin\nstream.seek(0)\n',
                      'seek = sys.stdin.seek\nseek(0)\n'):
            with self.subTest(reset=reset), \
                    self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                self.scan('import sys\nrows = zip(["safe", input()], sys.stdin)\n'
                          'sys.stdin.read()\nlist(rows)\n' + reset +
                          'cursor.execute(next(rows)[0])\n')
        for construction in ('zip([], sys.stdin)', 'zip([input()], [0])'):
            with self.subTest(permanent=construction):
                self.assert_rules('import sys\nrows = ' + construction + '\nlist(rows)\n'
                                  'sys.stdin.seek(0)\ncursor.execute(next(rows, "SELECT 1"))\n')

    def test_native_zip_seek_after_eof_witnesses(self):
        artifacts = ROOT / 'test-suite/artifacts/python-zip-eof'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='native-', dir=artifacts))
        stdin_path = scratch / 'stdin.txt'
        stdin_path.write_text('SELECT supplied\n', encoding='utf-8')
        consumers = (('list', 'list(rows)\n'), ('tuple', 'tuple(rows)\n'),
                     ('for', 'for value, record in rows:\n    pass\n'),
                     ('next-default', 'next(rows, None)\n'))
        for stream_name, stream in (('stdin', 'sys.stdin'), ('csv', 'csv.reader(sys.stdin)')):
            for label, consume in consumers:
                with self.subTest(stream=stream_name, consumer=label):
                    source = ('import sys, csv\nrows = zip(["safe", input()], ' + stream + ')\n'
                              'sys.stdin.read()\n' + consume + 'sys.stdin.seek(0)\n'
                              'print(next(rows)[0])\n')
                    path = scratch / f'{stream_name}-{label}.py'
                    path.write_text(source, encoding='utf-8')
                    with stdin_path.open(encoding='utf-8') as source_file:
                        result = subprocess.run([sys.executable, str(path)], stdin=source_file,
                                                capture_output=True, text=True, timeout=15)
                    path.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
                    path.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, 'SELECT supplied\n')

    def test_native_zip_partial_row_error_witnesses(self):
        artifacts = ROOT / 'test-suite/artifacts/python-zip-exceptions'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='native-', dir=artifacts))
        for label, consume in (('next', '    next(rows)\n'), ('list', '    list(rows)\n'),
                               ('for', '    for value, record in rows:\n        pass\n')):
            with self.subTest(consumer=label):
                source = ('import sys, csv\nrows = zip(["safe", input()], csv.reader(sys.stdin))\n'
                          'try:\n' + consume + 'except csv.Error:\n    print(next(rows)[0])\n')
                path = scratch / f'{label}.py'
                path.write_text(source, encoding='utf-8')
                result = subprocess.run([sys.executable, str(path)],
                                        input='SELECT supplied\n' + 'x' * 140000 + '\nvalid\n',
                                        capture_output=True, text=True, timeout=15)
                (scratch / f'{label}.stdout').write_text(result.stdout, encoding='utf-8')
                (scratch / f'{label}.stderr').write_text(result.stderr, encoding='utf-8')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'SELECT supplied\n')

    def test_native_zip_runtime_witnesses(self):
        # Real builtin observations establish the source and cursor controls
        # without executing any security sink or scanner-produced program.
        source = '''
import io
stream = io.StringIO('40 + 2\\n41 + 1\\n')
rows = zip(['fixed', 'also'], stream)
assert next(rows) == ('fixed', '40 + 2\\n')
alias = rows
assert next(alias) == ('also', '41 + 1\\n')
assert next(rows, 'done') == 'done'
assert list(zip([], io.StringIO('payload'))) == []
assert list(zip(io.StringIO('payload'), [])) == []
assert list(zip()) == []
stream = io.StringIO('first\\nsecond\\nthird\\n')
assert list(zip(stream, stream)) == [('first\\n', 'second\\n')]
values = ['safe']
rows = zip(values, [0])
values[0] = 'payload'
assert next(rows) == ('payload', 0)
try:
    list(zip([1], [2, 3], strict=True))
except ValueError:
    pass
else:
    raise AssertionError('strict zip accepted unequal lengths')
print('native zip witnesses passed')
'''
        result = subprocess.run([sys.executable, '-c', textwrap.dedent(source)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'native zip witnesses passed')


class EagerStdinParserTests(SourceTest):
    def test_json_stream_contents_reach_each_sink_domain(self):
        sinks = (("os.system(value)", 'command'), ("eval(value)", 'eval'),
                 ("cursor.execute(value)", 'sql'), ("HttpResponse(value)", 'xss'),
                 ("requests.get(value)", 'ssrf'))
        for stream in ('sys.stdin', 'sys.__stdin__', 'sys.stdin.buffer', 'sys.__stdin__.buffer.raw'):
            for sink, rule in sinks:
                with self.subTest(stream=stream, sink=sink):
                    findings = self.assert_rules('import json, sys, os, requests\n'
                        f'value=json.load({stream})["value"]\n{sink}\n', rule)
                    self.assertIn('stdin', findings[0]['message'])

    def test_toml_reads_only_native_binary_stdin(self):
        for stream in ('sys.stdin.buffer', 'sys.__stdin__.buffer', 'sys.stdin.buffer.raw'):
            with self.subTest(stream=stream):
                self.assert_rules(f'import tomllib, sys\neval(tomllib.load({stream})["code"])\n', 'eval')
        self.assert_rules('import tomllib, sys\neval(tomllib.load(sys.stdin)["code"])\n')
        self.assert_rules('import tomllib, sys\neval(tomllib.load(fp=sys.stdin.buffer)["code"])\n')

    def test_loader_aliases_defaults_and_helper_summaries_keep_identity(self):
        cases = (
            'import json as wire\neval(wire.load(sys.stdin)["code"])\n',
            'from json import load as parse\neval(parse(sys.stdin)["code"])\n',
            'parse=json.load\njson=None\neval(parse(sys.stdin)["code"])\n',
            'def parse(stream):\n    return json.load(stream)\neval(parse(sys.stdin)["code"])\n',
            'def parse():\n    return json.load(sys.stdin)\neval(parse()["code"])\n',
            'def parse(loader,stream):\n    return loader(stream)\neval(parse(json.load,sys.stdin)["code"])\n',
            'def parser():\n    return json.load\neval(parser()(sys.stdin)["code"])\n',
            'def parse(stream=sys.stdin,loader=json.load):\n    return loader(stream)\neval(parse()["code"])\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import json, sys\n' + source, 'eval')
        self.assert_rules('from tomllib import load as parse\nimport sys\n'
                          'def consume():\n    return parse(sys.stdin.buffer)\neval(consume()["code"])\n', 'eval')

    def test_argument_binding_and_native_decoder_defaults(self):
        cases = (
            'eval(json.load(fp=sys.stdin)["code"])\n',
            'arguments=(sys.stdin,)\neval(json.load(*arguments)["code"])\n',
            'eval(json.load(**{"fp":sys.stdin})["code"])\n',
            'arguments={"fp":sys.stdin}\neval(json.load(**arguments)["code"])\n',
            'arguments={"fp":sys.stdin.buffer}\nalias=arguments\n'
            'eval(json.load(**alias)["code"])\n',
            'eval(json.load(sys.stdin,strict=False)["code"])\n',
            'eval(json.load(sys.stdin,cls=None,object_hook=None,object_pairs_hook=None,'
            'parse_int=None,parse_float=None,parse_constant=None)["code"])\n',
            'stream=sys.stdin\neval(json.load(((json := None),stream)[1])["code"])\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_rules('import json, sys\n' + source, 'eval')

    def test_custom_callbacks_and_unknown_options_report_incomplete(self):
        for option in ('cls=Decoder', 'object_hook=lambda value: {"code":"fixed"}',
                       'parse_float=custom', '**options'):
            with self.subTest(option=option), self.assertRaisesRegex(
                    taint_py.AnalysisLimit, 'stdin parser'):
                self.scan(f'import json, sys\neval(json.load(sys.stdin,{option})["code"])\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin parser callback'):
            self.scan('import tomllib, sys\neval(tomllib.load(sys.stdin.buffer,parse_float=custom)["code"])\n')
        for mutation in ('arguments["fp"]=unknown()', 'arguments.update(options)',
                         'alias=arguments\nalias["fp"]=unknown()'):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    taint_py.AnalysisLimit, 'stdin parser argument expansion'):
                self.scan('import json, sys\narguments={"fp":sys.stdin}\n' + mutation + '\n'
                          'eval(json.load(**arguments)["code"])\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin parser argument expansion'):
            self.scan('import json, sys\narguments={"fp":sys.stdin}\n'
                      'eval(json.load(**options,**arguments)["code"])\n')

    def test_execution_order_and_returned_loader_producers_remain_explicit(self):
        self.assert_rules('import json, sys\ndef parse():\n    return json.load(sys.stdin)\n'
                          'def wrapper():\n    return parse()\neval(wrapper()["code"])\n', 'eval')
        for returned, invocation in (
                ('json', 'factory().load(sys.stdin)'), ('sys', 'json.load(factory().stdin)'),
                ('sys.stdin', 'json.load(factory())')):
            with self.subTest(returned=returned):
                self.assert_rules('import json, sys\ndef factory():\n'
                                  f'    return {returned}\neval({invocation}["code"])\n', 'eval')
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin parser'):
                    self.scan('import json, sys\ndef factory():\n    owned=unknown()\n'
                              f'    return {returned}\neval({invocation}["code"])\n')
        for source in (
            'def parse():\n    return json.load(sys.stdin)\neval(input())\nparse()\n',
            'def parse():\n    return json.load(sys.stdin)\neval(parse()["code"])\nparse()\n',
            'for item in range(2):\n    eval(json.load(sys.stdin)["code"])\n',
            'exec(input())\neval(json.load(sys.stdin)["code"])\n',
            'def parser():\n    owned=unknown()\n    return json.load\n'
            'eval(parser()(sys.stdin)["code"])\n',
            'from json import load\ndef parser():\n    owned=unknown()\n    return load\n'
            'eval(parser()(sys.stdin)["code"])\n',
        ):
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin parser'):
                self.scan('import json, sys\n' + source)

    def test_native_loader_and_decoder_replacement_report_incomplete(self):
        replacements = (
            'json.load=lambda stream: {"code":"fixed"}',
            'json.loads=lambda text,**options: {"code":"fixed"}',
            'json.JSONDecoder=Decoder',
            'json._default_decoder=decoder',
            'json.load.__code__=replacement',
            'def replace():\n    json.loads=lambda text,**options: {"code":"fixed"}\nreplace()',
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement), self.assertRaises(taint_py.AnalysisLimit):
                self.scan('import json, sys\n' + replacement + '\neval(json.load(sys.stdin)["code"])\n')

    def test_unrelated_imports_and_local_shadows_are_not_native_parsers(self):
        for statement in ('from application.json import load', 'from .json import load'):
            with self.subTest(statement=statement):
                self.assert_rules(statement + '\nimport sys\neval(load(sys.stdin)["code"])\n')
        for statement in ('from . import json', 'from . import tomllib', 'json=unknown()', 'tomllib=unknown()'):
            parser = 'tomllib' if 'tomllib' in statement else 'json'
            with self.subTest(statement=statement):
                self.assert_rules(statement + f'\nimport sys\neval({parser}.load(sys.stdin.buffer)["code"])\n')
        self.assert_rules('''
            import json, sys
            class Local:
                @staticmethod
                def load(stream):
                    return {'code':'fixed'}
            json=Local
            eval(json.load(sys.stdin)['code'])
        ''')
        for operation in ('json.loads(sys.stdin)', 'json.dumps(sys.stdin)', 'json.load(sys.stdin.encoding)'):
            with self.subTest(operation=operation):
                self.assert_rules(f'import json, sys\neval({operation})\n')

    def test_parsed_values_retain_sink_specific_safety(self):
        self.assert_rules('''
            import json, sys, shlex, html, os
            value=json.load(sys.stdin)['value']
            cursor.execute('SELECT %s',(value,))
            os.system('echo '+shlex.quote(value))
            HttpResponse(html.escape(value))
        ''')
        self.assert_rules('import json, sys, html\neval(html.escape(json.load(sys.stdin)["code"]))\n', 'eval')

    def test_incomplete_parser_helpers_keep_independent_findings(self):
        source = textwrap.dedent('''\
            import json, sys
            eval(input())
            def parse():
                return json.load(sys.stdin,cls=Decoder)
            parse()
            eval(input())
        ''')
        engine = taint_py._Analysis(ast.parse(source))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin parser') as caught:
            engine.analyze()
        self.assertEqual({(kind,line) for kind,line,_column,_label in caught.exception.effects},
                         {('eval',2),('eval',6)})


class FilteredStdinTests(SourceTest):
    def test_native_filter_payload_reaches_each_sink_domain(self):
        for stream, convert in (('sys.stdin', ''), ('sys.__stdin__', ''),
                                ('sys.stdin.buffer', '.decode()'),
                                ('sys.stdin.buffer.raw', '.decode()')):
            for sink, rule in (("eval(value)", 'eval'), ("cursor.execute(value)", 'sql'),
                               ("os.system(value)", 'command'), ("HttpResponse(value)", 'xss'),
                               ("requests.get(value)", 'ssrf')):
                with self.subTest(stream=stream, sink=sink):
                    findings = self.assert_rules('import sys, os, requests\n'
                        f'value = next(filter(None, {stream})){convert}\n{sink}\n', rule)
                    self.assertEqual([finding['line'] for finding in findings], [3])
                    self.assertIn(stream, findings[0]['message'])

    def test_aliases_native_consumers_and_collections_keep_original_items(self):
        cases = (
            'rows = filter(None, sys.stdin)\nvalue = next(rows)',
            'rows = filter(None, sys.stdin)\nalias = rows\nvalue = next(iter(alias))',
            'rows = filter(None, sys.stdin)\nadvance = rows.__next__\nvalue = advance()',
            'rows = filter(None, sys.stdin).__iter__()\nvalue = next(rows)',
            'for line in filter(None, sys.stdin):\n    value = line',
            'value = [line for line in filter(None, sys.stdin)][0]',
            'value = list(filter(None, sys.stdin))[0]',
            'value = tuple(filter(None, sys.stdin))[0]',
            'from builtins import filter as select\nvalue = next(select(None, sys.stdin))',
            'import builtins as native\nvalue = native.next(native.filter(None, sys.stdin))',
            'select = filter\nfilter = lambda predicate, items: []\nvalue = next(select(None, sys.stdin))',
            'predicate = None\nvalue = next(filter(predicate, iter(sys.stdin)))',
            'arguments = (None, sys.stdin)\nvalue = next(filter(*arguments))',
            'value = next(filter(None, sys.stdin), "SELECT 1")',
        )
        for setup in cases:
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\ncursor.execute(value)\n', 'sql')

    def test_lazy_handles_and_strong_overwrites_remain_clean(self):
        cases = (
            'rows = filter(None, sys.stdin)\nvalue = "SELECT 1"',
            'rows = filter(None, sys.stdin)\nadvance = rows.__next__\nvalue = "SELECT 1"',
            'value = next(filter(None, sys.stdin))\nvalue = "SELECT 1"',
            'rows = filter(None, sys.stdin)\nrows = ["SELECT 1"]\nvalue = rows[0]',
            'value = next(filter(None, []), "SELECT 1")',
            'def filter(predicate, items):\n    return ["SELECT 1"]\nvalue = filter(None, sys.stdin)[0]',
            'from .builtins import filter\nvalue = next(filter(None, sys.stdin))',
            'from application.builtins import filter\nvalue = next(filter(None, sys.stdin))',
        )
        for setup in cases:
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\ncursor.execute(value)\n')

    def test_pure_filter_factories_keep_native_payload(self):
        cases = (
            'def rows(stream):\n    return filter(None, stream)\nvalue = next(rows(sys.stdin))',
            'def rows():\n    return filter(None, sys.stdin)\nvalue = next(rows())',
            'def rows(predicate, stream):\n    return filter(predicate, stream)\n'
            'value = next(rows(None, sys.stdin))',
            'def stream():\n    return sys.stdin\nvalue = next(filter(None, stream()))',
        )
        for setup in cases:
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\ncursor.execute(value)\n', 'sql')

    def test_unknown_predicates_and_iteration_protocols_remain_incomplete(self):
        for expression in ('filter(predicate, sys.stdin)', 'filter(lambda row: True, sys.stdin)',
                           'filter(None, sys.stdin if flag else opaque)',
                           'filter(*arguments)', 'filter(**options)'):
            with self.subTest(expression=expression), self.assertRaisesRegex(taint_py.AnalysisLimit, 'filter'):
                self.scan('import sys\nrows = ' + expression + '\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'filter'):
            self.scan('import sys\ndef rows(predicate):\n'
                      '    return filter(predicate, sys.stdin)\n')

    def test_replaced_native_filter_and_opaque_factories_remain_incomplete(self):
        for mutation in ('builtins.filter = replacement', 'del builtins.filter'):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(taint_py.AnalysisLimit, 'source member mutation'):
                self.scan('import sys, builtins\n' + mutation + '\nrows = builtins.filter(None, sys.stdin)\n')
        for source in (
                'def rows():\n    owner = Owner()\n    return filter(None, sys.stdin)\nrows()\n',
                'def stream():\n    owner = Owner()\n    return sys.stdin\nfilter(None, stream())\n'):
            with self.subTest(source=source), self.assertRaisesRegex(taint_py.AnalysisLimit, 'producer'):
                self.scan('import sys\n' + source)

    def test_shared_cursor_does_not_certify_resumption_after_possible_eof(self):
        for consume in ('list(rows)', 'tuple(rows)', 'next(rows, "SELECT 1")',
                        'for row in rows:\n    pass', "''.join(rows)",
                        "combine = ''.join\ncombine(rows)"):
            with self.subTest(consume=consume), self.assertRaisesRegex(taint_py.AnalysisLimit, 'cursor'):
                self.scan('import sys\nrows = filter(None, sys.stdin)\nalias = rows\n'
                          + consume + '\nsys.stdin.seek(0)\ncursor.execute(next(alias))\n')

    def test_partial_filter_keeps_findings_already_reached(self):
        engine = taint_py._Analysis(ast.parse(
            'import sys\ncursor.execute(input())\nrows = filter(predicate, sys.stdin)\n'))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'filter') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('sql', 2)})

    def test_filter_payload_preserves_parameter_binding_and_context_sanitizers(self):
        self.assert_rules('import sys, os, shlex, html\nvalue = next(filter(None, sys.stdin))\n'
                          'cursor.execute("SELECT ?", (value,))\n'
                          'os.system("echo " + shlex.quote(value))\nHttpResponse(html.escape(value))\n')
        self.assert_rules('import sys, html\nvalue = next(filter(None, sys.stdin))\n'
                          'eval(html.escape(value))\n', 'eval')

    def test_native_filter_witnesses_preserve_lines_and_resume_after_eof(self):
        artifacts = ROOT / 'test-suite/artifacts/python-filter-native'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='witness-', dir=artifacts))
        stdin_path = scratch / 'stdin.txt'
        stdin_path.write_bytes(b'\nSELECT supplied\n')
        for stream, convert in (('sys.stdin', ''), ('sys.stdin.buffer', '.decode()'),
                                ('sys.stdin.buffer.raw', '.decode()')):
            source = ('import json, sys\nrows = filter(None, ' + stream + ')\n'
                      'alias = rows\nfirst = next(alias)\nsecond = next(rows)\n'
                      'remaining = list(alias)\nsys.stdin.seek(0)\nagain = next(rows)\n'
                      f'print(json.dumps([first{convert}, second{convert}, remaining, again{convert}]))\n')
            with self.subTest(stream=stream):
                with stdin_path.open('rb') as source_file:
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', source], stdin=source_file,
                                            capture_output=True, text=True, timeout=15, check=True)
                self.assertEqual(json.loads(result.stdout), ['\n', 'SELECT supplied\n', [], '\n'])

    def test_native_join_consumes_matching_text_and_binary_filter_payloads(self):
        for stream, separator in (('sys.stdin', "''"), ('sys.__stdin__', "'\\n'"),
                                  ('sys.stdin.buffer', "b''"), ('sys.stdin.buffer.raw', "b' '")):
            for use in (f'value = {separator}.join(rows)',
                        f'combine = {separator}.join\nvalue = combine(rows)'):
                with self.subTest(stream=stream, use=use):
                    self.assert_rules('import sys\nrows = filter(None, ' + stream + ')\n'
                                      + use + '\neval(value)\n', 'eval')

    def test_incompatible_native_joins_have_no_executable_payload(self):
        for source in ("''.join(filter(None, sys.stdin.buffer))",
                       "b''.join(filter(None, sys.stdin))"):
            with self.subTest(source=source):
                self.assert_rules('import sys\nvalue = ' + source + '\neval(value)\n')


class EnumeratedStdinTests(SourceTest):
    def test_native_payload_reaches_each_sink_domain(self):
        for stream, convert in (('sys.stdin', ''), ('sys.stdin.buffer', '.decode()'),
                                ('sys.stdin.buffer.raw', '.decode()')):
            for sink, rule in (("eval(value)", 'eval'), ("cursor.execute(value)", 'sql'),
                               ("os.system(value)", 'command'), ("HttpResponse(value)", 'xss'),
                               ("requests.get(value)", 'ssrf')):
                with self.subTest(stream=stream, sink=sink):
                    findings = self.assert_rules('import sys, os, requests\n'
                        f'value = next(enumerate({stream}))[1]{convert}\n{sink}\n', rule)
                    self.assertEqual([finding['line'] for finding in findings], [3])
                    self.assertIn(stream, findings[0]['message'])

    def test_aliases_methods_and_loop_pairs_preserve_payload(self):
        for setup in (
                'rows = enumerate(sys.stdin)\nvalue = next(rows)[1]',
                'rows = enumerate(sys.stdin)\nalias = rows\nvalue = next(iter(alias))[-1]',
                'rows = enumerate(sys.stdin)\nadvance = rows.__next__\nvalue = advance()[1]',
                'rows = enumerate(sys.stdin).__iter__()\nindex, value = next(rows)',
                'for index, line in enumerate(sys.stdin):\n    value = line',
                'for pair in enumerate(sys.stdin):\n    value = pair[1]',
                'value = [line for index, line in enumerate(sys.stdin)][0]',
                'value = [pair[1] for pair in enumerate(sys.stdin)][0]',
                'from builtins import enumerate as number_lines\nvalue = next(number_lines(sys.stdin))[1]',
                'import builtins as native\nvalue = native.next(native.enumerate(sys.stdin))[1]',
                'make = enumerate\nvalue = next(make(sys.stdin))[1]',
                'arguments = (sys.stdin, 4)\nvalue = next(enumerate(*arguments))[1]',
                'value = next(enumerate(iter(sys.stdin.readline, "")))[1]',
                'value = next(enumerate(iterable=sys.stdin, start=4))[1]',
                'value = next(enumerate(sys.stdin, start=-4))[1]'):
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\neval(value)\n', 'eval')

    def test_numeric_indices_and_fixed_replacements_are_clean(self):
        for setup in (
                'value = next(enumerate(sys.stdin))[0]',
                'value = next(enumerate(sys.stdin))[-2]',
                'index, line = next(enumerate(sys.stdin))\nvalue = index',
                'for index, line in enumerate(sys.stdin):\n    value = index',
                'value = [index for index, line in enumerate(sys.stdin)][0]',
                'rows = enumerate(sys.stdin)\nvalue = "fixed"',
                'value = next(enumerate(sys.stdin))[1]\nvalue = "fixed"',
                'rows = enumerate(sys.stdin)\nrows = iter([(0, "fixed")])\nvalue = next(rows)[1]',
                'def enumerate(stream):\n    return [(0, "fixed")]\nvalue = enumerate(sys.stdin)[0][1]'):
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\ncursor.execute(str(value))\n')

    def test_pure_factories_preserve_native_rows(self):
        for setup in (
                'def make(stream):\n    return enumerate(stream)\nvalue = next(make(sys.stdin))[1]',
                'def make():\n    return enumerate(sys.stdin)\nvalue = next(make())[1]',
                'def number(stream, start):\n    return enumerate(stream, start)\nvalue = next(number(sys.stdin, 3))[1]'):
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\neval(value)\n', 'eval')

    def test_generic_enumeration_helpers_keep_ordinary_transfer(self):
        for source in (
                'def number(items):\n    return enumerate(items)\n',
                'def render(items):\n    for index, item in enumerate(items):\n        print(item)\n',
                'def number(items):\n    return enumerate(items)\nnumber(options)\n'):
            with self.subTest(source=source):
                self.assert_rules(source)
        self.assert_rules('def first(items):\n    return next(enumerate(items))[1]\n'
                          'cursor.execute(first([input()]))\n', 'sql')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'native zip'):
            self.scan('import sys\ndef number(other):\n'
                      '    return enumerate(sys.stdin if flag else other)\n')

    def test_next_default_keeps_each_pair_position(self):
        for expression, expected in (
                ('next(enumerate(sys.stdin), (0, "fixed"))[1]', ('sql',)),
                ('next(enumerate(sys.stdin), (0, "fixed"))[0]', ()),
                ('next(enumerate(sys.stdin), (0, input()))[1]', ('sql',))):
            with self.subTest(expression=expression):
                self.assert_rules('import sys\ncursor.execute(str(' + expression + '))\n', *expected)

    def test_shared_cursor_requires_proof_after_native_eof(self):
        for handle in ('rows', 'alias'):
            with self.subTest(handle=handle), self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                self.scan('import sys\nrows = enumerate(sys.stdin)\nalias = rows\n'
                    'for index, line in rows:\n    print(index)\n'
                    f'value = next({handle}, (0, "fixed"))[1]\ncursor.execute(value)\n')

    def test_enumeration_resumption_after_native_eof_remains_explicit(self):
        for consume in ('next(rows, None)\n', 'for index, line in rows:\n    pass\n'):
            for reset in ('sys.stdin.seek(0)\n', 'stream = sys.stdin\nstream.seek(0)\n',
                          'seek = sys.stdin.seek\nseek(0)\n'):
                source = ('import sys\nrows = enumerate(sys.stdin, start=7)\nalias = rows\n'
                          'sys.stdin.read()\n' + consume + reset +
                          'cursor.execute(next(alias)[1])\n')
                with self.subTest(consume=consume, reset=reset), \
                        self.assertRaisesRegex(taint_py.AnalysisLimit, 'zip cursor'):
                    self.scan(source)

    def test_native_enumeration_seek_after_eof_witness(self):
        artifacts = ROOT / 'test-suite/artifacts/python-enumeration-eof'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='native-', dir=artifacts))
        stdin_path = scratch / 'stdin.txt'
        stdin_path.write_text('SELECT supplied\n', encoding='utf-8')
        for stream, convert in (('sys.stdin', ''), ('sys.stdin.buffer', '.decode()')):
            for consume in ('next(rows, None)\n', 'for index, line in rows:\n    pass\n'):
                source = ('import json, sys\nrows = enumerate(' + stream + ', start=7)\n'
                          'next(rows)\n' + stream + '.read()\n' + consume + 'sys.stdin.seek(0)\n'
                          'index, value = next(rows)\nprint(json.dumps([index, value' + convert + ']))\n')
                with self.subTest(stream=stream, consume=consume):
                    with stdin_path.open('rb') as source_file:
                        result = subprocess.run([sys.executable, '-c', source], stdin=source_file,
                                                capture_output=True, text=True, timeout=15, check=True)
                    self.assertEqual(json.loads(result.stdout), [8, 'SELECT supplied\n'])

    def test_known_invalid_input_and_start_alternatives_preserve_valid_rows(self):
        for invalid in ('None', '42', 'False'):
            with self.subTest(invalid=invalid):
                self.assert_rules('import sys\nstream = sys.stdin if flag else ' + invalid + '\n'
                                  'eval(next(enumerate(stream))[1])\n', 'eval')
        self.assert_rules('import sys\nstart = 0 if flag else "invalid"\n'
                          'eval(next(enumerate(sys.stdin, start))[1])\n', 'eval')

    def test_opaque_inputs_start_and_expansions_remain_incomplete(self):
        for setup in ('rows = enumerate(sys.stdin if flag else opaque)',
                      'rows = enumerate(sys.stdin, start=opaque)',
                      'rows = enumerate(*arguments)', 'rows = enumerate(**options)'):
            with self.subTest(setup=setup), self.assertRaisesRegex(taint_py.AnalysisLimit, 'enumerate'):
                self.scan('import sys\n' + setup + '\n')
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'source member mutation'):
            self.scan('import builtins, sys\nbuiltins.enumerate = replacement\n'
                      'eval(next(builtins.enumerate(sys.stdin))[1])\n')

    def test_shared_native_iterator_boundaries_remain_explicit(self):
        for setup in ('value = list(enumerate(sys.stdin))',
                      'value = tuple(enumerate(sys.stdin))',
                      'def take(rows):\n    return next(rows)\nvalue = take(enumerate(sys.stdin))',
                      'rows = enumerate(sys.stdin)\nunknown(rows)',
                      'def make():\n    owned = Owner()\n    return enumerate(sys.stdin)\nrows = make()'):
            with self.subTest(setup=setup), self.assertRaisesRegex(taint_py.AnalysisLimit, 'native zip'):
                self.scan('import sys\n' + setup + '\n')

    def test_partial_enumeration_retains_reached_findings(self):
        engine = taint_py._Analysis(ast.parse(
            'import sys\neval(input())\nrows = enumerate(sys.stdin, start=opaque)\n'))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'enumerate') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('eval', 2)})

    def test_constructor_argument_errors_do_not_produce_payload(self):
        for expression in ('enumerate(sys.stdin, 0, 1)', 'enumerate(sys.stdin, unknown=True)',
                           'enumerate(sys.stdin, start="invalid")'):
            with self.subTest(expression=expression):
                self.assert_rules('import sys\ncursor.execute(' + expression + ')\n')

    def test_callable_sentinel_exhaustion_proof_survives_native_wrapping(self):
        self.assert_rules('import sys\nrows = enumerate(iter(sys.stdin.readline, "STOP"))\n'
                          'eval(next(rows)[1])\n', 'eval')
        for expression in ('enumerate(iter(sys.stdin.readline, "STOP"))',
                           'zip(iter(sys.stdin.readline, "STOP"))'):
            with self.subTest(expression=expression), self.assertRaisesRegex(taint_py.AnalysisLimit, 'exhaustion'):
                self.scan('import sys\nfor row in ' + expression + ':\n    cursor.execute(row)\n')

    def test_finite_zip_companions_bound_non_eof_callable_readers(self):
        for expression, column in (('zip(iter(sys.stdin.readline, "STOP"), [0])', 0),
                                   ('zip([0], iter(sys.stdin.readline, "STOP"))', 1)):
            with self.subTest(expression=expression):
                self.assert_rules('import sys\nfor row in ' + expression + ':\n'
                                  f'    cursor.execute(row[{column}])\n', 'sql')
                self.assert_rules('import sys\nrows = list(' + expression + ')\n'
                                  f'cursor.execute(rows[0][{column}])\n', 'sql')
        for expression in ('zip(iter(sys.stdin.readline, "STOP"), [])',
                           'zip([], iter(sys.stdin.readline, "STOP"))'):
            with self.subTest(empty=expression):
                self.assert_rules('import sys\nfor row in ' + expression + ':\n'
                                  '    cursor.execute(row)\n')
                self.assert_rules('import sys\nrows = tuple(' + expression + ')\n'
                                  'cursor.execute(rows)\n')

    def test_native_zip_non_eof_witness_preserves_column_read_order(self):
        for expression, expected in (
                ('zip(iter(sys.stdin.readline, "STOP"), [0])', [[['first\n', 0]], '']),
                ('zip([0], iter(sys.stdin.readline, "STOP"))', [[[0, 'first\n']], 'second\n']),
                ('zip(iter(sys.stdin.readline, "STOP"), [])', [[], 'second\n']),
                ('zip([], iter(sys.stdin.readline, "STOP"))', [[], 'first\n'])):
            source = ('import json, sys\nrows = list(' + expression + ')\n'
                      'print(json.dumps([rows, sys.stdin.readline()]))\n')
            with self.subTest(expression=expression):
                result = subprocess.run([sys.executable, '-c', source], input='first\nsecond\n',
                                        text=True, capture_output=True, timeout=15, check=True)
                self.assertEqual(json.loads(result.stdout), expected)

    def test_native_python_witnesses_preserve_indices_and_exhaustion(self):
        for stream, convert in (('sys.stdin', ''), ('sys.stdin.buffer', '.decode()')):
            source = ('import json, sys\nrows = enumerate(' + stream + ', start=7)\n'
                      'index, value = next(rows)\n'
                      'print(json.dumps([index, value' + convert + ']))\n'
                      'print(json.dumps(next(rows, (0, "fixed"))))\n')
            with self.subTest(stream=stream):
                result = subprocess.run([sys.executable, '-c', source], input='payload\n',
                                        text=True, capture_output=True, timeout=15, check=True)
                self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                                 [[7, 'payload\n'], [0, 'fixed']])


class CallableStdinIteratorTests(SourceTest):
    def test_native_reader_sentinel_iteration_reaches_each_sink_domain(self):
        for stream, sentinel, convert in (("sys.stdin", "''", ''),
                                          ("sys.stdin.buffer", "b''", '.decode()'),
                                          ("sys.stdin.buffer.raw", "b''", '.decode()')):
            for sink, rule in (("eval(value)", 'eval'), ("cursor.execute(value)", 'sql'),
                               ("os.system(value)", 'command'), ("HttpResponse(value)", 'xss'),
                               ("requests.get(value)", 'ssrf')):
                with self.subTest(stream=stream, sink=sink):
                    findings = self.assert_rules(
                        'import sys, os, requests\n'
                        f'rows = iter({stream}.readline, {sentinel})\n'
                        f'value = next(rows){convert}\n' + sink + '\n', rule)
                    self.assertEqual([finding['line'] for finding in findings], [4])
                    self.assertIn(stream, findings[0]['message'])

    def test_captured_readers_and_native_consumers_preserve_lazy_source(self):
        for setup in (
                "value = next(iter(sys.stdin.readline, ''))",
                "value = list(iter(sys.stdin.readline, ''))[0]",
                "value = tuple(iter(sys.stdin.readline, ''))[0]",
                "for line in iter(sys.stdin.readline, ''):\n    value = line",
                "value = [line for line in iter(sys.stdin.readline, '')][0]",
                "value = ''.join(iter(sys.stdin.readline, ''))",
                "rows = iter(sys.stdin.readline, '')\nalias = rows\nvalue = next(iter(alias))",
                "rows = iter(sys.stdin.readline, '')\nadvance = rows.__next__\nvalue = advance()",
                "rows = iter(sys.stdin.readline, '').__iter__()\nvalue = next(rows)",
                "read = sys.stdin.readline\nsys = None\nvalue = next(iter(read, ''))",
                "from sys import __stdin__ as stream\nvalue = next(iter(stream.readline, ''))",
                "import builtins as native\nmake = native.iter\nvalue = next(make(sys.stdin.readline, ''))",
                "arguments = (sys.stdin.readline, '')\nvalue = next(iter(*arguments))",
                "value = next(iter(sys.stdin.buffer.read1, b'')).decode()",
                "value = next(iter(sys.stdin.buffer.raw.readall, b'')).decode()"):
            with self.subTest(setup=setup):
                source = 'import sys\n' + setup + '\neval(value)\n'
                findings = self.assert_rules(source, 'eval')
                self.assertEqual([finding['line'] for finding in findings], [len(source.splitlines())])

    def test_selected_helpers_transport_reader_and_iterator_identity(self):
        for setup in (
                "def take(rows):\n    return next(rows)\nvalue = take(iter(sys.stdin.readline, ''))",
                "def make(read):\n    return iter(read, '')\nvalue = next(make(sys.stdin.readline))",
                "def make():\n    return iter(sys.stdin.readline, '')\nvalue = next(make())",
                "def make(read, sentinel):\n    return iter(read, sentinel)\n"
                "value = next(make(sys.stdin.readline, ''))",
                "def take(read=sys.stdin.readline):\n    return next(iter(read, ''))\nvalue = take()",
                "rows = iter(sys.stdin.readline, '')\ndef take():\n    return next(rows)\nvalue = take()"):
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\neval(value)\n', 'eval')

    def test_handles_and_safe_data_uses_remain_clean(self):
        for setup in (
                "rows = iter(sys.stdin.readline, '')\nvalue = '1'",
                "rows = iter(sys.stdin.readline, '')\nvalue = str(rows)",
                "rows = iter(sys.stdin.readline, '')\nvalue = repr(rows)",
                "rows = iter(sys.stdin.readline, '')\nvalue = str(bool(rows))",
                "rows = iter(sys.stdin.readline, '')\nrows = iter(['1'])\nvalue = next(rows)",
                "read = sys.stdin.readline\nread = lambda: '1'\nvalue = next(iter(read, ''))",
                "def iter(read, sentinel):\n    return ['1']\nvalue = next(iter(sys.stdin.readline, ''))"):
            with self.subTest(setup=setup):
                self.assert_rules('import sys\n' + setup + '\neval(value)\n')
        self.assert_rules('''
            import sys, html, shlex, os
            value = next(iter(sys.stdin.readline, ''))
            cursor.execute('SELECT ?', (value,))
            HttpResponse(html.escape(value))
            os.system('echo ' + shlex.quote(value))
        ''')
        self.assert_rules("import sys, html\neval(html.escape(next(iter(sys.stdin.readline, ''))))\n", 'eval')

    def test_opaque_sentinel_and_iterator_protocols_are_explicit(self):
        for setup in (
                "rows = iter(sys.stdin.readline, sentinel)",
                "rows = iter(sys.stdin.readline, Sentinel())",
                "rows = iter(sys.stdin.readline, '')\nunknown(rows)\nvalue = next(rows)",
                "rows = [iter(sys.stdin.readline, '')]\nvalue = next(rows[0])",
                "rows = iter(sys.stdin.readline, '')\nvalue = rows.read()"):
            with self.subTest(setup=setup), self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator'):
                self.scan('import sys\n' + setup + '\n')

    def test_native_callable_iterator_witnesses(self):
        for stream, sentinel, expected in (("sys.stdin", "'STOP\\n'", ['payload\n']),
                                           ("sys.stdin.buffer", "b'STOP\\n'", ['payload\n']),
                                           ("sys.stdin.buffer.raw", "b'STOP\\n'", ['payload\n'])):
            with self.subTest(stream=stream):
                source = ('import json, sys\n'
                          f'rows = iter({stream}.readline, {sentinel})\n'
                          "values = [line.decode() if isinstance(line, bytes) else line for line in rows]\n"
                          "print(json.dumps({'values': values, 'has_read': hasattr(rows, 'read')}))\n")
                result = subprocess.run([sys.executable, '-c', source], input='payload\nSTOP\nignored\n',
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'values': expected, 'has_read': False})

    def test_non_eof_sentinels_allow_next_but_do_not_prove_exhaustion(self):
        for reader, sentinel in (('sys.stdin.readline', "b''"),
                                 ('sys.stdin.buffer.readline', "''"),
                                 ('sys.stdin.readline', "'STOP\\n'"),
                                 ('sys.stdin.buffer.peek', "b''")):
            with self.subTest(reader=reader, sentinel=sentinel):
                self.assert_rules(f'import sys\neval(next(iter({reader}, {sentinel})))\n', 'eval')
                for consumer in ('list(rows)', 'tuple(rows)', '[line for line in rows]'):
                    with self.subTest(consumer=consumer):
                        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator exhaustion'):
                            self.scan(f'import sys\nrows = iter({reader}, {sentinel})\n' + consumer + '\n')
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator exhaustion'):
                    self.scan(f'import sys\nrows = iter({reader}, {sentinel})\nfor line in rows:\n    pass\n')
        self.assert_rules("import sys\neval(''.join(iter(sys.stdin.buffer.readline, b'')))\n")
        self.assert_rules("import sys\neval(b''.join(iter(sys.stdin.readline, '')))\n")

    def test_unqualified_sentinel_helpers_keep_an_explicit_obligation(self):
        for invocation in ('', 'make(unknown)', 'expose(make)'):
            with self.subTest(invocation=invocation):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator'):
                    self.scan('import sys\ndef make(sentinel):\n'
                              '    return iter(sys.stdin.readline, sentinel)\n' + invocation + '\n')

    def test_callable_iterators_do_not_acquire_stream_read_protocols(self):
        for parser in ('json', 'tomllib'):
            with self.subTest(parser=parser):
                self.assert_rules(f'import sys, {parser}\n'
                                  "rows = iter(sys.stdin.buffer.readline, b'')\n"
                                  f'eval({parser}.load(rows)["code"])\n')

    def test_partial_sentinel_scope_retains_independent_findings(self):
        engine = taint_py._Analysis(ast.parse(textwrap.dedent('''\
            import sys
            eval(input())
            def unsupported():
                return list(iter(sys.stdin.readline, Sentinel()))
            def independent():
                eval(input())
            unsupported()
            independent()
        ''')))
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator') as caught:
            engine.analyze()
        self.assertEqual({(kind, line) for kind, line, _column, _label in caught.exception.effects},
                         {('eval', 2), ('eval', 6)})

    def test_selected_modules_keep_primitive_sentinel_specialization(self):
        for supplied in ("''", "b''"):
            with self.subTest(sentinel=supplied), temporary_directory(prefix='ubs-calliter-modules-') as directory:
                root = Path(directory)
                helper, caller = root / 'reader.py', root / 'app.py'
                helper.write_text('import sys\ndef take(sentinel):\n'
                                  '    return next(iter(sys.stdin.readline, sentinel))\n', encoding='utf-8')
                caller.write_text(f'from reader import take\neval(take({supplied}))\n', encoding='utf-8')
                findings = list(taint_py.run(RunContext(lang='python', files=[caller, helper])))
                self.assertEqual([(finding['rule'], finding['path'], finding['line']) for finding in findings],
                                 [('python.taint.eval', str(caller), 2)], findings)

    def test_unknown_equality_can_change_data_without_yielding_a_row(self):
        program = textwrap.dedent('''\
            import json, sys
            observed = 'fixed'
            class Sentinel:
                def __eq__(self, line):
                    global observed
                    observed = line
                    return True
            rows = iter(sys.stdin.readline, Sentinel())
            result = next(rows, 'no row')
            print(json.dumps([observed, result]))
        ''')
        result = subprocess.run([sys.executable, '-c', program], input='external-payload\n',
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ['external-payload\n', 'no row'])
        with self.assertRaisesRegex(taint_py.AnalysisLimit, 'stdin callable iterator sentinel'):
            self.scan(program.replace('print(json.dumps([observed, result]))', 'eval(observed)'))

    def test_suppression_and_profiles_apply_to_real_selected_sink_sites(self):
        prefix = "import sys\nrows = iter(sys.stdin.readline, '')\n"
        self.assert_rules(prefix + "eval(next(rows))  # ubs:ignore[python.taint.eval]\n")
        findings = self.assert_rules(prefix + "eval(next(rows))  # ubs:ignore[python.taint.xss]\n", 'eval')
        self.assertEqual([finding['line'] for finding in findings], [3])
        with temporary_directory(prefix='ubs-calliter-profile-') as directory:
            path = Path(directory) / 'view.py'
            path.write_text(prefix + 'eval(next(rows))\n', encoding='utf-8')
            context = RunContext(lang='python', files=[path], profile={'disabled_rules': ['python.taint.eval']})
            self.assertEqual(list(taint_py.run(context)), [])


class CsvStdinParserTests(SourceTest):
    def test_consumed_rows_reach_each_sink_domain(self):
        for sink, rule in (("eval(value)", 'eval'), ("cursor.execute(value)", 'sql'),
                           ("os.system(value)", 'command'), ("HttpResponse(value)", 'xss'),
                           ("requests.get(value)", 'ssrf')):
            with self.subTest(sink=sink):
                findings = self.assert_rules('import csv, sys, os, requests\n'
                                            'value = next(csv.reader(sys.stdin))[0]\n' + sink + '\n', rule)
                self.assertEqual([finding['line'] for finding in findings], [3])

    def test_iterator_aliases_and_consumption_forms(self):
        setups = (
            'value = next(csv.reader(sys.stdin))[0]',
            'value = list(csv.reader(sys.stdin))[0][0]',
            'value = tuple(csv.reader(sys.stdin))[0][0]',
            'for row in csv.reader(sys.stdin):\n    value = row[0]',
            'value = [row[0] for row in csv.reader(sys.stdin)][0]',
            'rows = iter(csv.reader(sys.stdin))\nvalue = next(rows)[0]',
            'rows = csv.reader(sys.stdin)\nalias = rows\nvalue = next(alias)[0]',
            'rows = csv.reader(sys.stdin)\nadvance = rows.__next__\nvalue = advance()[0]',
            'rows = csv.reader(sys.stdin).__iter__()\nvalue = rows.__next__()[0]',
            'from csv import reader as parse\nvalue = next(parse(sys.stdin))[0]',
            'parse = csv.reader\ncsv = None\nvalue = next(parse(sys.stdin))[0]',
            'parsers = (csv.reader,)\nvalue = next(parsers[0](sys.stdin))[0]',
            'args = (sys.stdin,)\nvalue = next(csv.reader(*args))[0]',
            'value = next(csv.reader(sys.stdin, **{"delimiter": ","}))[0]',
            'value = next(csv.reader(sys.stdin), ["1"])[0]',
            'from sys import __stdin__ as stream\nvalue = next(csv.reader(stream))[0]',
        )
        for setup in setups:
            with self.subTest(setup=setup):
                self.assert_rules('import csv, sys\n' + setup + '\neval(value)\n', 'eval')

    def test_dict_rows_and_implicit_header_are_input(self):
        for setup in (
                'value = next(csv.DictReader(sys.stdin))["code"]',
                'value = next(csv.DictReader(f=sys.stdin))["code"]',
                'value = next(csv.DictReader(sys.stdin, fieldnames=["code"]))["code"]',
                'value = next(csv.DictReader(sys.stdin, ("code",)))["code"]',
                'value = next(csv.DictReader(sys.stdin, fieldnames="x"))["x"]',
                'value = next(csv.DictReader(**{"f": sys.stdin}, fieldnames=["code"]))["code"]',
                'rows = csv.DictReader(sys.stdin)\nvalue = rows.fieldnames[0]',
                'rows = csv.DictReader(sys.stdin)\nvalue = next(rows.reader)[0]',
                'header = None if condition else ["code"]\n'
                'rows = csv.DictReader(sys.stdin, fieldnames=header)\nvalue = rows.fieldnames[0]'):
            with self.subTest(setup=setup):
                self.assert_rules('import csv, sys\n' + setup + '\neval(value)\n', 'eval')

    def test_native_factories_and_consumer_helpers_preserve_identity(self):
        for setup in (
                'def parse(stream):\n    return csv.reader(stream)\nvalue = next(parse(sys.stdin))[0]',
                'def parse():\n    return csv.reader(sys.stdin)\nvalue = next(parse())[0]',
                'def parse(factory, stream):\n    return factory(stream)\n'
                'value = next(parse(csv.reader, sys.stdin))[0]',
                'def parse(stream):\n    return csv.DictReader(stream, fieldnames=["code"])\n'
                'value = next(parse(sys.stdin))["code"]',
                'def take(rows):\n    return next(rows)[0]\nvalue = take(csv.reader(sys.stdin))',
                'def identity(rows):\n    return rows\nvalue = next(identity(csv.reader(sys.stdin)))[0]',
                'def take(advance):\n    return advance()[0]\n'
                'rows = csv.reader(sys.stdin)\nvalue = take(rows.__next__)',
                'def factory():\n    return csv.reader\nvalue = next(factory()(sys.stdin))[0]'):
            with self.subTest(setup=setup):
                self.assert_rules('import csv, sys\n' + setup + '\neval(value)\n', 'eval')

    def test_handle_metadata_and_fixed_input_remain_clean(self):
        for setup in (
                'rows = csv.reader(sys.stdin)\nvalue = "1"',
                'rows = csv.reader(sys.stdin)\nvalue = rows.line_num',
                'rows = csv.reader(sys.stdin)\nnext(rows)\nvalue = rows.line_num',
                'rows = csv.reader(sys.stdin)\nvalue = rows.dialect.delimiter',
                'rows = csv.DictReader(sys.stdin)\nvalue = rows.line_num',
                'rows = csv.DictReader(sys.stdin, fieldnames=["1"])\nvalue = rows.fieldnames[0]',
                'value = next(csv.reader(io.StringIO("1\\n")))[0]',
                'value = next(csv.DictReader(io.StringIO("code\\n1\\n")))["code"]',
                'value = next(csv.reader(["1"]))[0]',
                'value = next(csv.reader(sys.stdin))[0]\nvalue = "1"',
                'from csv import reader\nreader = lambda stream: iter([["1"]])\nvalue = next(reader(sys.stdin))[0]',
                'from . import csv\nvalue = next(csv.reader(sys.stdin))[0]'):
            with self.subTest(setup=setup):
                self.assert_rules('import csv, sys, io\n' + setup + '\neval(value)\n')

    def test_literal_options_keep_rows_and_domain_safety(self):
        for options in (', dialect="excel-tab"', ', "unix"', ', delimiter=";", quotechar="\'"',
                        ', escapechar="\\\\", quoting=csv.QUOTE_NONE', ', strict=True, skipinitialspace=True'):
            with self.subTest(options=options):
                self.assert_rules('import csv, sys\nvalue = next(csv.reader(sys.stdin' + options + '))[0]\n'
                                  'eval(value)\n', 'eval')
        self.assert_rules('''
            import csv, sys, html, shlex, os
            value = next(csv.DictReader(sys.stdin))["code"]
            cursor.execute('SELECT ?', (value,))
            HttpResponse(html.escape(value))
            os.system('echo ' + shlex.quote(value))
        ''')
        self.assert_rules('import csv, sys, html\neval(html.escape(next(csv.reader(sys.stdin))[0]))\n', 'eval')

    def test_invalid_option_alternative_keeps_valid_reader_branch(self):
        for key, alternatives in (('delimiter', '"" if flag else ","'),
                                  ('quotechar', '"" if flag else "\\\""'),
                                  ('escapechar', '"" if flag else None'),
                                  ('lineterminator', '4 if flag else "\\r\\n"')):
            with self.subTest(key=key):
                self.assert_rules('import csv, sys\noption = ' + alternatives + '\n'
                                  'eval(next(csv.reader(sys.stdin, ' + key + '=option))[0])\n', 'eval')
        self.assert_rules('import csv, sys\noption = "" if flag else "long"\n'
                          'eval(next(csv.reader(sys.stdin, delimiter=option))[0])\n')

    def test_invalid_native_shapes_and_binary_streams_do_not_produce_rows(self):
        for expression in ('csv.reader(f=sys.stdin)', 'csv.reader(sys.stdin, "excel", "extra")',
                           'csv.DictReader(sys.stdin, f=sys.stdin)', 'csv.reader(sys.stdin, unsupported=True)',
                           'csv.reader(sys.stdin, delimiter="")', 'csv.reader(sys.stdin, lineterminator=4)',
                           'csv.reader(sys.stdin, quotechar=None, quoting=csv.QUOTE_ALL)'):
            with self.subTest(expression=expression):
                self.assert_rules('import csv, sys\neval(next(' + expression + ')[0])\n')
        for expression in ('next(csv.reader(sys.stdin), default=["1"])',
                           'list(csv.reader(sys.stdin), extra=True)',
                           'csv.reader(sys.stdin).__next__("bad")'):
            with self.subTest(expression=expression):
                self.assert_rules('import csv, sys\neval(' + expression + ')\n')
        self.assert_rules('''
            import csv, sys
            try:
                value = next(csv.reader(sys.stdin.buffer))[0]
            except csv.Error:
                value = '1'
            eval(value)
        ''')

    def test_opaque_dialects_headers_and_registry_effects_are_explicit(self):
        for setup in (
                'rows = csv.reader(sys.stdin, dialect=CustomDialect)',
                'rows = csv.reader(sys.stdin, delimiter=custom)',
                'rows = csv.reader(sys.stdin, quoting=csv.QUOTE_NONNUMERIC)',
                'rows = csv.DictReader(sys.stdin, fieldnames=custom)',
                'rows = csv.DictReader(sys.stdin, fieldnames=[input()])',
                'rows = csv.reader(sys.stdin, **options)',
                'options = {"f": sys.stdin}\nrows = csv.DictReader(**options, fieldnames=["code"])',
                'def make(**options):\n    return csv.DictReader(**options)\n'
                'rows = make(f=sys.stdin, fieldnames=["code"])',
                'csv.register_dialect("excel", delimiter=";")\nrows = csv.DictReader(sys.stdin)',
                'csv.DictReader.fieldnames = property(callback)\nrows = csv.DictReader(sys.stdin)',
                'csv.DictReader.line_num = property(callback)\nrows = csv.DictReader(sys.stdin)',
                'csv.reader = replacement\nrows = csv.reader(sys.stdin)'):
            with self.subTest(setup=setup):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'CSV reader'):
                    self.scan('import csv, sys\n' + setup + '\n')

    def test_reader_storage_mutation_and_producer_frames_are_explicit(self):
        for setup in (
                'rows = [csv.reader(sys.stdin)]\nvalue = next(rows[0])[0]',
                'rows = csv.DictReader(sys.stdin)\nrows.reader = opaque\nvalue = next(rows)["code"]',
                'rows = csv.reader(sys.stdin)\nunknown(rows)\nvalue = next(rows)[0]',
                'def make():\n    owned = Owner()\n    return csv.reader(sys.stdin)\n'
                'value = next(make())[0]',
                'def make(unused=Owner()):\n    return csv.reader(sys.stdin)\n'
                'value = next(make())[0]',
                'def make(unused):\n    return csv.reader(sys.stdin)\n'
                'value = next(make(Owner()))[0]'):
            with self.subTest(setup=setup):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'CSV reader'):
                    self.scan('import csv, sys\n' + setup + '\neval(value)\n')

    def test_unused_factory_results_cannot_hide_return_time_finalizers(self):
        for returned in ('csv.reader(sys.stdin)', 'csv.reader', 'csv', 'csv.reader(sys.stdin).__next__'):
            with self.subTest(returned=returned):
                with self.assertRaisesRegex(taint_py.AnalysisLimit, 'CSV reader producer'):
                    self.scan('import csv, sys\nvalue = "1"\n'
                              'class Owner:\n    def __del__(self):\n        global value\n'
                              '        value = sys.stdin.readline()\n'
                              'def make():\n    owned = Owner()\n    return ' + returned + '\n'
                              'unused = make()\neval(value)\n')


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
    def zip_public_report(self, target, artifact, *, meta, output, expected, partial=False, cache=False,
                          partial_label='zip'):
        command = ROOT / ('ubs' if meta else 'modules/ubs-python.sh')
        arguments = [str(command), str(target), '--ci', '--no-color', f'--format={output}']
        if meta:
            arguments.append('--only=python')
        result = subprocess.run(
            arguments, cwd=target.parent,
            env=dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1', UBS_PROFILE='1',
                     UBS_NO_CACHE='0' if cache else '1', UBS_CACHE_DIR=str(target.parent / 'cache')),
            capture_output=True, text=True, timeout=180)
        artifact.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
        artifact.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
        self.assertEqual(result.returncode, 2 if partial else (1 if expected else 0),
                         (arguments, result.stdout, result.stderr))
        report = json.loads(result.stdout)
        if output == 'json':
            self.assertEqual(report['status'], 'partial' if partial else 'ok', report)
            rule_key = 'rule_id' if meta else 'rule'
            findings = [row for row in report.get('findings', [])
                        if row[rule_key] == 'python.taint.sql']
            if meta:
                sites = [(row['line'], row['col']) for row in findings]
                locations = findings
            else:
                # The Python module's JSON contract groups findings by rule
                # and exposes sample lines; SARIF and meta JSON retain columns.
                locations = [sample for row in findings for sample in row['samples']]
                sites = [sample['line'] for sample in locations]
                expected = [line for line, _column in expected]
                self.assertEqual(sum(row['count'] for row in findings), len(expected), report)
            totals = report['totals'] if meta else report
            self.assertEqual(totals['files'], 1, report)
            for location in locations:
                self.assertEqual(Path(location['file']).name, target.name, location)
            for row in findings:
                self.assertEqual(row['severity'], 'critical', row)
                self.assertFalse(row.get('suppressed', False), row)
            if partial:
                self.assertIn(partial_label, result.stdout + result.stderr)
                if meta:
                    self.assertEqual(report['profile']['cache_hits'], 0, report)
        else:
            self.assertEqual(report['version'], '2.1.0', report)
            findings = [row for run in report['runs'] for row in run.get('results', [])
                        if row['ruleId'] == 'python.taint.sql']
            sites = []
            for row in findings:
                location = row['locations'][0]['physicalLocation']
                sites.append((location['region']['startLine'], location['region']['startColumn']))
                self.assertEqual(Path(location['artifactLocation']['uri']).name, target.name, row)
                self.assertEqual(row['level'], 'error', row)
            failed = [invocation for run in report['runs'] for invocation in run.get('invocations', [])
                      if invocation.get('executionSuccessful') is False]
            self.assertEqual(bool(failed), partial, report)
            for invocation in failed:
                self.assertEqual(invocation['exitCode'], 2, invocation)
                self.assertIn(partial_label, json.dumps(invocation))
        self.assertEqual(sites, expected, report)
        return report

    def test_zip_module_and_runner_json_sarif_keep_sites_status_and_selection(self):
        prefix = 'import sys\nfor label, query in zip(["SELECT 1"], sys.stdin):\n'
        cases = (
            ('unsafe', prefix + '    cursor.execute(query)\n', [(3, 5)], False),
            ('clean-column', prefix + '    cursor.execute(label)\n', [], False),
            ('empty', 'import sys\nfor query, label in zip(sys.stdin, []):\n'
             '    cursor.execute(query)\n', [], False),
            ('partial', 'import sys\ncursor.execute(input())\n'
             'rows = zip(["SELECT 1"], sys.stdin, strict=True)\n', [(2, 1)], True),
            ('interrupted-row', 'import sys, csv\ncursor.execute(input())\n'
             'rows = zip(["safe", input()], csv.reader(sys.stdin))\ntry:\n    next(rows)\n'
             'except csv.Error:\n    cursor.execute(next(rows)[0])\n', [(2, 1)], True),
            ('restarted-stream', 'import sys\ncursor.execute(input())\n'
             'rows = zip(["safe", input()], sys.stdin)\nsys.stdin.read()\nlist(rows)\n'
             'sys.stdin.seek(0)\ncursor.execute(next(rows)[0])\n', [(2, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/python-zip-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'view.py'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.py').write_text('cursor.execute(input())\n', encoding='utf-8')
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, output=output):
                        self.zip_public_report(target, project / f'{meta}-{output}', meta=meta,
                                               output=output, expected=expected, partial=partial)

    def test_zip_runner_cache_invalidation_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/python-zip-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'view.py'
        prefix = 'import sys\nfor label, query in zip(["SELECT 1"], sys.stdin):\n'
        unsafe = prefix + '    cursor.execute(query)\n'
        clean = prefix + '    cursor.execute(label)\n'
        suppressed = prefix + '    cursor.execute(query)  # ubs:ignore\n'
        for index, (source, expected, hits) in enumerate((
                (unsafe, [(3, 5)], 0), (unsafe, [(3, 5)], 1),
                (clean, [], 0), (suppressed, [], 0), (unsafe, [(3, 5)], 1))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.zip_public_report(target, scratch / f'cache-{index}', meta=True, output='json',
                                               expected=expected, cache=True)
                self.assertEqual(report['profile']['cache_hits'], hits, report)
        entries = set((scratch / 'cache').glob('*/files/**/*.json'))
        self.assertTrue(entries, 'Completed native zip scans must create reusable cache entries')
        partial_sources = (
            'import sys\ncursor.execute(input())\n'
            'rows = zip(["SELECT 1"], sys.stdin, strict=True)\n',
            'import sys\ncursor.execute(input())\nrows = zip(["safe", input()], sys.stdin)\n'
            'sys.stdin.read()\nlist(rows)\nsys.stdin.seek(0)\ncursor.execute(next(rows)[0])\n',
        )
        for case, source in enumerate(partial_sources):
            target.write_text(source, encoding='utf-8')
            for index in range(2):
                with self.subTest(partial=case, attempt=index):
                    self.zip_public_report(target, scratch / f'partial-{case}-{index}', meta=True,
                                           output='json', expected=[(2, 1)], partial=True, cache=True)
                    self.assertEqual(set((scratch / 'cache').glob('*/files/**/*.json')), entries,
                                     'An incomplete native zip scan must not enter the completed cache')

    def test_filtered_stdin_module_and_runner_reports_keep_sites_and_selection(self):
        cases = (
            ('text-join', 'import sys\nrows = filter(None, sys.stdin)\n'
             'query = "".join(rows)\ncursor.execute(query)\n', [(4, 1)], False),
            ('bytes-join', 'import sys\nrows = filter(None, sys.stdin.buffer)\n'
             'query = b"".join(rows).decode()\ncursor.execute(query)\n', [(4, 1)], False),
            ('helper', 'import sys\ndef select(stream):\n    return filter(None, stream)\n'
             'cursor.execute(next(select(sys.stdin)))\n', [(4, 1)], False),
            ('unused', 'import sys\nrows = filter(None, sys.stdin)\n'
             'cursor.execute("SELECT 1")\n', [], False),
            ('partial', 'import sys\ncursor.execute(input())\n'
             'rows = filter(predicate, sys.stdin)\n', [(2, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/python-filter-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'view.py'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.py').write_text('cursor.execute(input())\n', encoding='utf-8')
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, output=output):
                        self.zip_public_report(target, project / f'{meta}-{output}', meta=meta,
                                               output=output, expected=expected, partial=partial,
                                               partial_label='filter')

    def test_filtered_stdin_cache_invalidation_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/python-filter-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'view.py'
        prefix = 'import sys\nrows = filter(None, sys.stdin)\nquery = "".join(rows)\n'
        unsafe = prefix + 'cursor.execute(query)\n'
        clean = prefix + 'cursor.execute("SELECT 1")\n'
        suppressed = prefix + 'cursor.execute(query)  # ubs:ignore[python.taint.sql]\n'
        for index, (source, expected, hits) in enumerate((
                (unsafe, [(4, 1)], 0), (unsafe, [(4, 1)], 1),
                (clean, [], 0), (suppressed, [], 0), (unsafe, [(4, 1)], 1))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.zip_public_report(target, scratch / f'cache-{index}', meta=True, output='json',
                                               expected=expected, cache=True, partial_label='filter')
                self.assertEqual(report['profile']['cache_hits'], hits, report)
        entries = set((scratch / 'cache').glob('*/files/**/*.json'))
        self.assertTrue(entries, 'Completed native filter scans must create reusable cache entries')
        target.write_text('import sys\ncursor.execute(input())\n'
                          'rows = filter(predicate, sys.stdin)\n', encoding='utf-8')
        for index in range(2):
            with self.subTest(partial=index):
                self.zip_public_report(target, scratch / f'partial-{index}', meta=True, output='json',
                                       expected=[(2, 1)], partial=True, cache=True, partial_label='filter')
                self.assertEqual(set((scratch / 'cache').glob('*/files/**/*.json')), entries,
                                 'An incomplete native filter scan must not enter the completed cache')

    def test_enumerated_stdin_module_and_runner_reports_keep_sites_and_selection(self):
        prefix = ('import sys\ndef rows():\n    return enumerate(sys.stdin, start=7)\n'
                  'pending = rows()\nalias = iter(pending)\n'
                  'index, query = next(alias, (0, "SELECT 1"))\n')
        cases = (
            ('unsafe', prefix + 'cursor.execute(query)\n', [(7, 1)], False, 'enumerate'),
            ('clean-index', prefix + 'cursor.execute(index)\n', [], False, 'enumerate'),
            ('partial', 'import sys\ncursor.execute(input())\n'
             'rows = enumerate(sys.stdin, start=opaque)\n', [(2, 1)], True, 'enumerate'),
            ('restarted-stream', 'import sys\ncursor.execute(input())\n'
             'rows = enumerate(sys.stdin)\nsys.stdin.read()\nfor index, row in rows:\n    pass\n'
             'sys.stdin.seek(0)\ncursor.execute(next(rows)[1])\n', [(2, 1)], True, 'zip cursor'),
        )
        artifacts = ROOT / 'test-suite/artifacts/python-enumeration-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial, reason in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'view.py'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.py').write_text('cursor.execute(input())\n', encoding='utf-8')
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, output=output):
                        self.zip_public_report(target, project / f'{meta}-{output}', meta=meta,
                                               output=output, expected=expected, partial=partial,
                                               partial_label=reason)

    def test_enumerated_stdin_cache_invalidation_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/python-enumeration-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'view.py'
        prefix = 'import sys\nfor index, query in enumerate(sys.stdin, start=7):\n'
        unsafe = prefix + '    cursor.execute(query)\n'
        clean = prefix + '    cursor.execute(index)\n'
        suppressed = prefix + '    cursor.execute(query)  # ubs:ignore\n'
        for index, (source, expected, hits) in enumerate((
                (unsafe, [(3, 5)], 0), (unsafe, [(3, 5)], 1),
                (clean, [], 0), (suppressed, [], 0), (unsafe, [(3, 5)], 1))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.zip_public_report(target, scratch / f'cache-{index}', meta=True, output='json',
                                               expected=expected, cache=True)
                self.assertEqual(report['profile']['cache_hits'], hits, report)
        entries = set((scratch / 'cache').glob('*/files/**/*.json'))
        self.assertTrue(entries, 'Completed stdin enumeration scans must create reusable cache entries')
        partial_sources = (
            ('import sys\ncursor.execute(input())\n'
             'rows = enumerate(sys.stdin, start=opaque)\n', 'enumerate'),
            ('import sys\ncursor.execute(input())\nrows = enumerate(sys.stdin)\n'
             'sys.stdin.read()\nfor index, row in rows:\n    pass\n'
             'sys.stdin.seek(0)\ncursor.execute(next(rows)[1])\n', 'zip cursor'),
        )
        for case, (source, reason) in enumerate(partial_sources):
            target.write_text(source, encoding='utf-8')
            for index in range(2):
                with self.subTest(partial=case, attempt=index):
                    self.zip_public_report(target, scratch / f'partial-{case}-{index}', meta=True, output='json',
                                           expected=[(2, 1)], partial=True, cache=True, partial_label=reason)
                    self.assertEqual(set((scratch / 'cache').glob('*/files/**/*.json')), entries,
                                     'An incomplete enumeration scan must not enter the completed cache')

    def test_callable_stdin_iterator_json_and_sarif(self):
        prefix = ('import sys\ndef make(read):\n    return iter(read, "")\n'
                  'rows = make(sys.stdin.readline)\n')
        cases = (
            (prefix + 'cursor.execute(next(rows))\n', [5], 'ok', 1),
            (prefix + "cursor.execute('SELECT ?', (next(rows),))\n", [], 'ok', 0),
            ('import sys\ncursor.execute(input())\n'
             'rows = iter(sys.stdin.readline, Sentinel())\n', [2], 'partial', 2),
        )
        for source, expected_lines, status, exit_code in cases:
            with temporary_directory(prefix='ubs-calliter-cli-') as directory:
                path = Path(directory) / 'view.py'
                path.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    with self.subTest(source=source, format=output):
                        result = subprocess.run(
                            [str(ROOT / 'ubs'), str(path), '--only=python', '--ci', f'--format={output}'],
                            cwd=directory, env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1'),
                            capture_output=True, text=True, timeout=180)
                        self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report.get('status'), status, report)
                            findings = [finding for finding in report.get('findings', [])
                                        if finding['rule_id'] in {'py.taint.sql', 'python.taint.sql'}]
                            lines = [finding['line'] for finding in findings]
                        else:
                            findings = [finding for run in report['runs'] for finding in run.get('results', [])
                                        if finding['ruleId'] in {'py.taint.sql', 'python.taint.sql'}]
                            lines = [finding['locations'][0]['physicalLocation']['region']['startLine']
                                     for finding in findings]
                            successful = [invocation.get('executionSuccessful') for run in report['runs']
                                          for invocation in run.get('invocations', [])]
                            # Complete SARIF may omit invocations; partial runs
                            # must explicitly report unsuccessful execution.
                            if status == 'ok':
                                self.assertTrue(all(value is True for value in successful), report)
                            else:
                                self.assertTrue(successful, report)
                                self.assertTrue(all(value is False for value in successful), report)
                        self.assertEqual(lines, expected_lines, report)

    def test_readinto_json_and_sarif(self):
        prefix = ('import sys\ndef fill(buffer):\n    sys.stdin.buffer.readinto(buffer)\n'
                  'buffer = bytearray(64)\nfill(buffer)\n')
        cases = ((prefix + 'cursor.execute(buffer.decode())\n', True),
                 (prefix + "cursor.execute('SELECT ?', (buffer.decode(),))\n", False),
                 ('import sys\nbuffer = bytearray()\nsys.stdin.buffer.readinto(buffer)\n'
                  'cursor.execute(buffer.decode())\n', False))
        for source, expected in cases:
            with temporary_directory(prefix='ubs-readinto-cli-') as directory:
                path = Path(directory) / 'view.py'
                path.write_text(source, encoding='utf-8')
                for output in ('json', 'sarif'):
                    with self.subTest(source=source, format=output):
                        result = subprocess.run(
                            [str(ROOT / 'ubs'), str(path), '--only=python', '--ci', f'--format={output}'],
                            cwd=directory, env=dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1'),
                            capture_output=True, text=True, timeout=180)
                        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report.get('status'), 'ok', report)
                            findings = [finding for finding in report.get('findings', [])
                                        if finding['rule_id'] in {'py.taint.sql', 'python.taint.sql'}]
                            lines = [finding['line'] for finding in findings]
                        else:
                            findings = [finding for run in report['runs'] for finding in run.get('results', [])
                                        if finding['ruleId'] in {'py.taint.sql', 'python.taint.sql'}]
                            lines = [finding['locations'][0]['physicalLocation']['region']['startLine']
                                     for finding in findings]
                        self.assertEqual(lines, [6] if expected else [], report)

    def test_runner_emits_taint_findings_and_safe_parameter_control(self):
        for code, expected in (("q=html.escape(input())\ncursor.execute(q)\n", True),
                               ("q=input()\ncursor.execute('select %s', (q,))\n", False),
                               ("import os\ncursor.execute('SELECT ' + os.getenv('UBS_INPUT'))\n", True),
                               ("from os import environ as values\ncursor.execute('SELECT ' + values['UBS_INPUT'])\n", True),
                               ("import os\ncursor.execute('SELECT %s', (os.getenv('UBS_INPUT'),))\n", False),
                               ("import sys\ncursor.execute('SELECT ' + sys.stdin.read())\n", True),
                               ("from sys import stdin as stream\ncursor.execute(stream.readline())\n", True),
                               ("import sys\ncursor.execute(sys.stdin.buffer.read().decode())\n", True),
                               ("import sys\nbuffer=bytearray(64)\nsys.stdin.buffer.readinto(buffer)\n"
                                "cursor.execute(buffer.decode())\n", True),
                               ("import sys\ndef fill(buffer):\n    sys.stdin.buffer.readinto1(buffer)\n"
                                "buffer=bytearray(64)\nfill(buffer)\ncursor.execute(buffer.decode())\n", True),
                               ("import sys\nbuffer=bytearray(64)\nsys.stdin.buffer.readinto(buffer)\n"
                                "cursor.execute('SELECT ?', (buffer.decode(),))\n", False),
                               ("import sys\nfor line in sys.stdin:\n    cursor.execute(line)\n", True),
                               ("import sys\nargs = (sys.stdin,)\ncursor.execute(next(*args))\n", True),
                               ("import sys\ncursor.execute('SELECT %s', (sys.stdin.read(),))\n", False),
                               ("import sys\ncursor.execute(sys.stdin.read(0))\n", False),
                               ("import sys\ncursor.execute(sys.stdin.encoding)\n", False),
                               ("import json, sys\ncursor.execute(json.load(sys.stdin)['query'])\n", True),
                               ("import tomllib, sys\ncursor.execute(tomllib.load(sys.stdin.buffer)['query'])\n", True),
                               ("import json, sys\ncursor.execute('SELECT %s', (json.load(sys.stdin)['query'],))\n", False),
                               ("import tomllib, sys\ncursor.execute('SELECT %s', (tomllib.load(sys.stdin.buffer)['query'],))\n", False),
                               ("import json, sys\narguments={'fp':sys.stdin}\n"
                                "cursor.execute(json.load(**arguments)['query'])\n", True),
                               ("import csv, sys\ncursor.execute(next(csv.reader(sys.stdin))[0])\n", True),
                               ("import csv, sys\ncursor.execute(next(csv.DictReader(sys.stdin))['query'])\n", True),
                               ("import csv, sys\nfor row in csv.reader(sys.stdin):\n    cursor.execute(row[0])\n", True),
                               ("import csv, sys\ncursor.execute(csv.DictReader(sys.stdin).fieldnames[0])\n", True),
                               ("import csv, sys\ncursor.execute('SELECT ?', (next(csv.reader(sys.stdin))[0],))\n", False),
                               ("import csv, sys\nrows=csv.reader(sys.stdin)\nnext(rows)\ncursor.execute(rows.line_num)\n", False),
                               ("import csv, io\ncursor.execute(next(csv.reader(io.StringIO('SELECT 1')))[0])\n", False),
                               ("from json import load\nimport sys\nload=lambda stream: {'query':'SELECT 1'}\n"
                                "cursor.execute(load(sys.stdin)['query'])\n", False),
                               ("from . import json\nimport sys\ncursor.execute(json.load(sys.stdin)['query'])\n", False),
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
