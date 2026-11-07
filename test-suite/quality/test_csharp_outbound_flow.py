"""Independent C# outbound URL cases: actual destination and API identity.

The marked calls consume request-controlled destinations. Expected labels are
specified before the scoped implementation, including paired literal/guard
controls. Fixtures and public scanner output remain under artifacts/.
"""
from __future__ import annotations

import json
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.csharp_detectors import outbound_url
from ubs_core.taint_flow import AnalysisLimit, Budget

RULE = 'csharp.security.outbound-url'
HEADER = '''using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
'''


def program(body, helpers='', parameters='HttpRequest incoming, HttpClient transport, bool flag'):
    return (HEADER + 'class C {\n' + textwrap.dedent(helpers)
            + '\nvoid Handle(' + parameters + ') {\n'
            + textwrap.dedent(body) + '\n}\n}\n')


VALIDATOR = '''
static Uri Checked(string raw) {
    if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed) ||
        parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") {
        throw new InvalidOperationException();
    }
    return parsed;
}
'''

CASES = (
    ('arbitrary_input_key', program('transport.GetAsync(incoming.Query["q"]); // unsafe\n')),
    ('arbitrary_request_alias', program('''
        var source = incoming;
        var value = source.Headers["X-Destination"];
        transport.GetAsync(value); // unsafe
    ''')),
    ('literal_kill', program('''
        var value = incoming.Query["url"].ToString();
        value = "https://api.example.com/";
        transport.GetAsync(value);
    ''')),
    ('conditional_kill', program('''
        var value = incoming.Query["url"].ToString();
        if (flag) value = "https://api.example.com/";
        transport.GetAsync(value); // unsafe
    ''')),
    ('all_branches_kill', program('''
        var value = incoming.Query["url"].ToString();
        if (flag) value = "https://api.example.com/a";
        else value = "https://api.example.com/b";
        transport.GetAsync(value);
    ''')),
    ('safe_name_is_identity', program('''
        var value = SafeOutboundUrl(incoming.Query["q"]);
        transport.GetAsync(value); // unsafe
    ''', 'static string SafeOutboundUrl(string value) => value;')),
    ('unknown_safe_name_retains_input', program('''
        transport.GetAsync(External.SafeOutboundUrl(incoming.Query["url"])); // unsafe
    ''')),
    ('helper_sink', program('Send(incoming.Query["q"], transport);', '''
        static void Send(string destination, HttpClient peer) {
            peer.GetAsync(destination); // unsafe
        }
    ''')),
    ('helper_source', program('transport.GetAsync(Read(incoming)); // unsafe', '''
        static string Read(HttpRequest value) => value.Query["anything"];
    ''')),
    ('client_alias', program('''
        var peer = transport;
        peer.GetAsync(incoming.Query["q"]); // unsafe
    ''')),
    ('client_return', program('''
        var peer = Identity(transport);
        peer.GetAsync(incoming.Query["q"]); // unsafe
    ''', 'static HttpClient Identity(HttpClient peer) => peer;')),
    ('client_field', program('''
        _client.GetStringAsync(incoming.Query["q"]); // unsafe
    ''', 'private readonly HttpClient _client = new HttpClient();')),
    ('new_client', program('''
        var peer = new HttpClient();
        peer.GetAsync(incoming.Query["q"]); // unsafe
    ''')),
    ('named_url_argument', program('''
        transport.GetAsync(cancellationToken: default, requestUri: incoming.Query["q"]); // unsafe
    ''')),
    ('request_content_is_not_destination', program('''
        var body = new StringContent(incoming.Query["text"]);
        transport.PostAsync("https://api.example.com/", body);
    ''')),
    ('request_message', program('''
        var outgoing = new HttpRequestMessage(HttpMethod.Get, incoming.Query["q"]); // unsafe
        transport.SendAsync(outgoing); // unsafe
    ''')),
    ('request_message_literal', program('''
        var outgoing = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/");
        transport.SendAsync(outgoing);
    ''')),
    ('web_request', program('WebRequest.Create(requestUri: incoming.Query["q"]); // unsafe')),
    ('web_client', program('''
        using var peer = new WebClient();
        peer.DownloadString(incoming.Query["q"]); // unsafe
    ''')),
    ('genuine_validator', program('transport.GetAsync(Checked(incoming.Query["q"]));', VALIDATOR)),
    ('validated_raw_input', program('''
        var value = incoming.Query["q"].ToString();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") return;
        transport.GetAsync(value);
    ''')),
    ('validated_parsed_input', program('''
        var value = incoming.Query["q"].ToString();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") return;
        transport.GetAsync(parsed);
    ''')),
    ('guard_of_other_value', program('''
        var value = incoming.Query["q"].ToString();
        var other = incoming.Query["other"].ToString();
        if (!Uri.TryCreate(other, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") return;
        transport.GetAsync(value); // unsafe
    ''')),
    ('nonterminating_rejection', program('''
        var value = incoming.Query["q"].ToString();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") {
            Console.WriteLine("blocked");
        }
        transport.GetAsync(value); // unsafe
    ''')),
    ('guard_then_reassignment', program('''
        var value = incoming.Query["q"].ToString();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") return;
        value = incoming.Query["replacement"];
        transport.GetAsync(value); // unsafe
    ''')),
    ('scope_isolation', program('''
        var value = "https://api.example.com/";
        transport.GetAsync(value);
    ''', '''
        static string Other(HttpRequest request) {
            var value = request.Query["url"].ToString();
            return value;
        }
    ''')),
    ('local_client_lookalike', program('''
        peer.GetAsync(incoming.Query["q"]);
    ''', 'class LocalClient { public void GetAsync(string value) {} }',
         'HttpRequest incoming, LocalClient peer')),
    ('local_request_lookalike', HEADER + '''
class LocalRequest { public string Query(string key) => "https://api.example.com/"; }
class C { void Handle(LocalRequest incoming, HttpClient transport) {
    transport.GetAsync(incoming.Query("url"));
} }
'''),
    ('local_uri_lookalike', program('''
        var value = incoming.Query["q"].ToString();
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps || parsed.Host != "api.example.com") return;
        transport.GetAsync(value); // unsafe
    ''', '''
        class Uri {
            public const string UriSchemeHttps = "https";
            public string Scheme = "https", Host = "api.example.com";
            public static bool TryCreate(string value, UriKind kind, out Uri uri) {
                uri = new Uri(); return true;
            }
        }
    ''')),
    ('lexical_decoys', program('''
        var example = "transport.GetAsync(incoming.Query[\\\"url\\\"])";
        // transport.GetAsync(incoming.Query["url"]);
        transport.GetAsync("https://api.example.com/");
    ''')),
    ('inherited_http_client', program('''
        peer.GetAsync(incoming.Query["destination"]); // unsafe
    ''', 'class Transport : HttpClient {}', 'HttpRequest incoming, Transport peer')),
    ('inherited_http_client_alias', program('''
        var peer = client;
        peer.GetStringAsync(incoming.Query["destination"]); // unsafe
    ''', 'class Parent : HttpClient {}\nclass Transport : Parent {}',
         'HttpRequest incoming, Transport client')),
    ('local_member_hides_http_method', program('''
        peer.GetAsync(incoming.Query["destination"]);
    ''', '''class Transport : HttpClient {
        public new Task GetAsync(string value) => Task.CompletedTask;
    }''', 'HttpRequest incoming, Transport peer')),
    ('context_accessor_chain', program('''
        var context = accessor.HttpContext;
        var request = context.Request;
        transport.GetAsync(request.Query["destination"]); // unsafe
    ''', parameters='IHttpContextAccessor accessor, HttpClient transport')),
    ('controller_context_parameter', program('''
        transport.GetAsync(context.HttpContext.Request.Query["destination"]); // unsafe
    ''', parameters='Microsoft.AspNetCore.Mvc.ControllerContext context, HttpClient transport')),
    ('controller_context_property', HEADER + '''
class C : Microsoft.AspNetCore.Mvc.ControllerBase {
    void Handle(HttpClient transport) {
        transport.GetAsync(ControllerContext.HttpContext.Request.Query["destination"]); // unsafe
    }
}
'''),
    ('ordinary_context_names', program('''
        transport.GetAsync(accessor.HttpContext.Request.Query("destination"));
    ''', '''class Accessor { public Context HttpContext; }
        class Context { public Incoming Request; }
        class Incoming { public string Query(string key) => "https://api.example.com/"; }
    ''', 'Accessor accessor, HttpClient transport')),
    ('message_content_initializer', program('''
        var outgoing = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/") {
            Content = new StringContent(incoming.Query["body"])
        };
        transport.SendAsync(outgoing);
    ''')),
    ('inline_message_content_initializer', program('''
        transport.SendAsync(new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/") {
            Content = new StringContent(incoming.Query["body"])
        });
    ''')),
    ('message_destination_initializer', program('''
        var outgoing = new HttpRequestMessage() {
            RequestUri = new Uri(incoming.Query["destination"]), // unsafe
            Content = new StringContent("fixed")
        };
        transport.SendAsync(outgoing); // unsafe
    ''')),
    ('unused_field_setter', program('''
        transport.GetAsync("https://api.example.com/");
    ''', 'class Person { public string Name; }\n'
         'static void Rename(Person person, string name) { person.Name = name; }')),
    ('literal_field_setter_call', program('''
        Rename(person, "ordinary");
        transport.GetAsync("https://api.example.com/");
    ''', 'class Person { public string Name; }\n'
         'static void Rename(Person person, string name) { person.Name = name; }',
         'Person person, HttpClient transport')),
    ('ordinary_request_uri_property', program('''
        item.RequestUri = "ordinary";
        transport.GetAsync("https://api.example.com/");
    ''', 'class Item { public string RequestUri; }', 'Item item, HttpClient transport')),
)


class OutboundFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix='csharp-outbound-', dir=artifacts))

    def test_independently_labeled_destinations(self):
        for name, source in CASES:
            with self.subTest(name=name):
                path = self.root / (name + '.cs')
                path.write_text(source)
                expected = [line for line, text in enumerate(source.splitlines(), 1) if '// unsafe' in text]
                rows = list(outbound_url.find([path], self.root))
                self.assertEqual([row[1] for row in rows], expected, rows)

    def test_original_fixtures(self):
        fixtures = ROOT / 'test-suite/csharp/security'
        self.assertEqual(list(outbound_url.find([fixtures / 'SsrfClean.cs'])), [])
        rows = list(outbound_url.find([fixtures / 'SsrfBuggy.cs']))
        self.assertEqual([row[1] for row in rows], [15, 21, 27, 33, 34, 40, 47, 53])

    def test_framework_parameter_sources_and_attribute_shadowing(self):
        for attribute in ('FromQuery', 'FromHeader', 'FromRoute', 'FromForm', 'FromBody'):
            for kind in ('bound', 'overwritten', 'shadowed'):
                source = HEADER + 'using Microsoft.AspNetCore.Mvc;\n'
                if kind == 'shadowed':
                    source += f'class {attribute}Attribute : Attribute {{}}\n'
                source += ('class C {\nvoid Handle([' + attribute
                           + '] string destination, HttpClient transport) {\n')
                if kind == 'overwritten':
                    source += 'destination = "https://api.example.com/";\n'
                source += 'transport.GetAsync(destination);\n}\n}\n'
                path = self.root / f'attribute-{attribute}-{kind}.cs'
                path.write_text(source)
                with self.subTest(attribute=attribute, kind=kind):
                    rows = list(outbound_url.find([path], self.root))
                    line = next(index for index, text in enumerate(source.splitlines(), 1)
                                if 'transport.GetAsync' in text)
                    self.assertEqual([row[1] for row in rows], [line] if kind == 'bound' else [], rows)
        for name, directive, annotation in (
                ('alias', 'using Input = Microsoft.AspNetCore.Mvc.FromQueryAttribute;\n', 'Input'),
                ('qualified', '', 'global::Microsoft.AspNetCore.Mvc.FromHeader'),
                ('combined', 'using Microsoft.AspNetCore.Mvc;\nclass MarkerAttribute : Attribute {}\n', 'Marker, FromRoute'),
                ('targeted', 'using Microsoft.AspNetCore.Mvc;\n', 'param: FromQuery')):
            source = (HEADER + directive + 'class C {\nvoid Handle([' + annotation
                      + '] string destination, HttpClient transport) {\n'
                      'transport.GetAsync(destination); // unsafe\n}\n}\n')
            path = self.root / ('attribute-' + name + '.cs')
            path.write_text(source)
            with self.subTest(shape=name):
                rows = list(outbound_url.find([path], self.root))
                self.assertEqual([row[1] for row in rows],
                                 [line for line, text in enumerate(source.splitlines(), 1) if '// unsafe' in text])

    def test_named_attribute_arguments_preserve_parameters_and_real_defaults(self):
        marker = 'class MarkerAttribute : Attribute { public string Name { get; set; } }\n'
        for attribute in ('FromQuery', 'FromHeader', 'FromRoute', 'FromForm'):
            for kind in ('bound', 'overwritten', 'shadowed'):
                helper = (f'class {attribute}Attribute : Attribute {{ public string Name {{ get; set; }} }}\n'
                          if kind == 'shadowed' else '')
                body = ('destination = "https://api.example.com/";\n' if kind == 'overwritten' else '')
                body += 'transport.GetAsync(destination); // destination\n'
                source = ('using Microsoft.AspNetCore.Mvc;\n' + program(body, helper,
                          'HttpClient transport, [' + attribute + '(Name = "dest")] string destination'))
                path = self.root / f'attribute-name-{attribute}-{kind}.cs'
                path.write_text(source)
                with self.subTest(attribute=attribute, kind=kind):
                    rows = list(outbound_url.find([path], self.root))
                    expected = [line for line, text in enumerate(source.splitlines(), 1)
                                if '// destination' in text] if kind == 'bound' else []
                    self.assertEqual([row[1] for row in rows], expected, rows)
        for name, annotation, default in (
                ('combined', 'Marker(Name = "metadata"), FromRoute(Name = "q")', ''),
                ('optional', 'FromQuery(Name = "dest")', ' = "https://api.example.com/"')):
            source = ('using Microsoft.AspNetCore.Mvc;\n' + program(
                'transport.GetAsync(destination); // destination\n', marker,
                'HttpClient transport, [' + annotation + '] string destination' + default))
            path = self.root / ('attribute-name-' + name + '.cs')
            path.write_text(source)
            with self.subTest(shape=name):
                engine = outbound_url.OutboundFlow(path, source)
                handler = next(function for function in engine.parser.functions.values() if function.name == 'Handle')
                self.assertEqual(handler.parameters, ('transport', 'destination'))
                self.assertEqual(handler.parameter_types, ('HttpClient', 'string'))
                self.assertEqual(handler.defaults, 1 if default else 0)
                rows = list(outbound_url.find([path], self.root))
                self.assertEqual([row[1] for row in rows],
                                 [line for line, text in enumerate(source.splitlines(), 1) if '// destination' in text])
        for name, returned, unsafe in (('identity', 'raw', True),
                                       ('fixed', '"https://api.example.com/"', False)):
            helpers = (marker + 'static string Change([Marker(Name = "input")] string raw, '
                       '[Marker(Name = "mode")] string label = "x=y") => ' + returned + ';\n')
            source = program('transport.GetAsync(Change(incoming.Query["q"])); // destination\n', helpers)
            path = self.root / ('attribute-helper-default-' + name + '.cs')
            path.write_text(source)
            with self.subTest(helper=name):
                engine = outbound_url.OutboundFlow(path, source)
                helper = next(function for function in engine.parser.functions.values() if function.name == 'Change')
                self.assertEqual(helper.parameters, ('raw', 'label'))
                self.assertEqual(helper.defaults, 1)
                rows = list(outbound_url.find([path], self.root))
                expected = [line for line, text in enumerate(source.splitlines(), 1)
                            if '// destination' in text] if unsafe else []
                self.assertEqual([row[1] for row in rows], expected, rows)

    def test_uri_guards_bind_parser_scheme_and_allowlist_comparer(self):
        fake = '''class FakeUri {
            public string UriSchemeHttps = "https";
            public bool TryCreate(string value, UriKind kind, out System.Uri parsed) {
                parsed = new System.Uri("https://api.example.com/");
                return true;
            }
        }
        static FakeUri Uri = new FakeUri();
        '''
        for name, helper, parser, scheme, unsafe in (
                ('local-scheme', 'class Uri { public const string UriSchemeHttps = "http"; }',
                 'System.Uri', 'Uri', True),
                ('field-parser', fake, 'Uri', 'Uri', True),
                ('qualified-control', fake, 'System.Uri', 'System.Uri', False)):
            source = program(f'''
                var value = incoming.Query["url"].ToString();
                if (!{parser}.TryCreate(value, UriKind.Absolute, out var parsed) ||
                    parsed.Scheme != {scheme}.UriSchemeHttps || parsed.Host != "api.example.com") return;
                transport.GetAsync(value); // destination
            ''', helper)
            path = self.root / ('uri-identity-' + name + '.cs')
            path.write_text(source)
            with self.subTest(identity=name):
                rows = list(outbound_url.find([path], self.root))
                expected = [line for line, text in enumerate(source.splitlines(), 1)
                            if '// destination' in text] if unsafe else []
                self.assertEqual([row[1] for row in rows], expected, rows)
        factories = '''class AlwaysEqual : IEqualityComparer<string> {
            public bool Equals(string left, string right) { return true; }
            public int GetHashCode(string value) { return 0; }
        }
        class ComparerFactory {
            public IEqualityComparer<string> OrdinalIgnoreCase { get { return new AlwaysEqual(); } }
        }
        '''
        for name, initializer, shadowed in (
                ('default', '', False), ('builtin', 'StringComparer.OrdinalIgnoreCase', False),
                ('field', 'StringComparer.OrdinalIgnoreCase', True)):
            helper = ('private static readonly ComparerFactory StringComparer = new ComparerFactory();\n'
                      if shadowed else '')
            helper += ('private static readonly HashSet<string> Allowed = new HashSet<string>('
                       + initializer + ') { "api.example.com" };\n')
            source = ('using System.Collections.Generic;\n' + program('''
                var value = incoming.Query["url"].ToString();
                if (!System.Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
                    parsed.Scheme != System.Uri.UriSchemeHttps || !Allowed.Contains(parsed.Host)) return;
                transport.GetAsync(value); // destination
            ''', factories + helper))
            path = self.root / ('comparer-identity-' + name + '.cs')
            path.write_text(source)
            with self.subTest(comparer=name):
                rows = list(outbound_url.find([path], self.root))
                expected = [line for line, text in enumerate(source.splitlines(), 1)
                            if '// destination' in text] if shadowed else []
                self.assertEqual([row[1] for row in rows], expected, rows)

    def test_suppression_applies_to_sink_and_preserves_source(self):
        source = program('''
            var value = incoming.Query["q"]; // ubs:ignore[csharp.security.outbound-url]
            transport.GetAsync(value); // unsafe
            transport.GetAsync(value); // ubs:ignore[csharp.security.outbound-url]
        ''')
        path = self.root / 'suppressed.cs'
        path.write_text(source)
        rows = list(outbound_url.find([path], self.root))
        self.assertEqual([row[1] for row in rows],
                         [line for line, text in enumerate(source.splitlines(), 1) if '// unsafe' in text])

    def test_unresolved_dispatch_and_heap_writes_are_incomplete(self):
        cases = (
            program('transport.GetAsync(incoming.Query["q"]);',
                    parameters='HttpRequest incoming, dynamic transport'),
            program('transport.GetAsync(incoming.Query["q"]);',
                    'interface ITransport { Task GetAsync(string address); }',
                    'HttpRequest incoming, ITransport transport'),
            program('''
                var outgoing = new HttpRequestMessage();
                var alias = outgoing;
                alias.RequestUri = new Uri(incoming.Query["q"]);
                transport.SendAsync(outgoing);
            '''),
            program('''
                Rename(person, incoming.Query["q"]);
                transport.GetAsync(person.Name);
            ''', 'class Person { public string Name; }\n'
                 'static void Rename(Person person, string name) { person.Name = name; }',
                 'Person person, HttpRequest incoming, HttpClient transport'),
        )
        for index, source in enumerate(cases):
            with self.subTest(index=index):
                path = self.root / f'boundary-{index}.cs'
                path.write_text(source)
                with self.assertRaisesRegex(AnalysisLimit, 'incomplete'):
                    list(outbound_url.find([path], self.root))
        engine = outbound_url.OutboundFlow(self.root / 'budget.cs', CASES[0][1])
        engine.budget = Budget(1)
        with self.assertRaisesRegex(AnalysisLimit, 'incomplete'):
            list(engine.analyze())

    def test_incomplete_file_keeps_findings_in_other_files(self):
        from ubs_core.csharp_scan import run_detectors
        bad = self.root / 'a-incomplete.cs'
        good = self.root / 'z-detected.cs'
        bad.write_text(program('transport.GetAsync(incoming.Query["q"]);',
                               parameters='HttpRequest incoming, dynamic transport'))
        good.write_text(CASES[0][1])
        output, errors = io.StringIO(), []
        run_detectors([bad, good], output, set(), self.root, errors=errors)
        findings = [json.loads(row) for row in output.getvalue().splitlines()]
        self.assertTrue(any('outbound_url' in error and 'incomplete' in error for error in errors), errors)
        self.assertEqual([(Path(row['path']).name, row['rule']) for row in findings
                          if row['rule'] == RULE], [(good.name, RULE)])


@unittest.skipUnless(os.environ.get('UBS_CSHARP_OUTBOUND_PUBLIC') == '1',
                     'set UBS_CSHARP_OUTBOUND_PUBLIC=1 after verifying helper checksums')
class OutboundPublicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(exist_ok=True)
        cls.root = Path(tempfile.mkdtemp(prefix='csharp-outbound-public-', dir=artifacts))

    def execute(self, name, source, *, module=False, format_='json', extra=(), cache=False):
        folder = self.root / name
        folder.mkdir(exist_ok=True)
        path = folder / 'Example.cs'
        path.write_text(source)
        env = dict(os.environ, UBS_NO_AUTO_UPDATE='1', UBS_ENABLE_AUTO_UPDATE='0',
                   UBS_NO_CACHE='0' if cache else '1', UBS_KEEP_TEMP='1',
                   UBS_CACHE_DIR=str(self.root / 'cache'), UBS_CACHE_FILE=str(self.root / 'cache.json'),
                   UBS_MAX_DIR_SIZE_MB='0', PYTHONDONTWRITEBYTECODE='1')
        if module:
            command = [str(ROOT / 'modules/ubs-csharp.sh'), '--ci', '--no-dotnet', '--only=8']
        else:
            command = [str(ROOT / 'ubs'), '--ci', '--no-config', '--no-dotnet', '--only=csharp']
        command += ['--format=' + format_, *extra, str(path)]
        result = subprocess.run(command, cwd=folder, env=env, text=True, capture_output=True, timeout=90)
        (folder / (format_ + '.stdout')).write_text(result.stdout)
        (folder / (format_ + '.stderr')).write_text(result.stderr)
        self.assertIn(result.returncode, {0, 1, 2}, result.stderr)
        return result.returncode, json.loads(result.stdout), result.stderr

    def test_module_runner_json_and_sarif_agree(self):
        for module in (False, True):
            for format_ in ('json', 'sarif'):
                for label, source, unsafe in (
                    ('unsafe', CASES[5][1], True), ('clean', CASES[2][1], False),
                ):
                    with self.subTest(module=module, format=format_, label=label):
                        rc, doc, error = self.execute(f'{module}-{format_}-{label}', source,
                                                      module=module, format_=format_)
                        rows = doc['runs'][0]['results'] if format_ == 'sarif' else doc.get('findings', [])
                        expected = [line for line, text in enumerate(source.splitlines(), 1) if '// unsafe' in text]
                        observed = []
                        for row in rows:
                            if row.get('ruleId', row.get('rule_id', row.get('rule'))) != RULE:
                                continue
                            observed.append(row['locations'][0]['physicalLocation']['region']['startLine']
                                            if format_ == 'sarif' else row['line'])
                        self.assertEqual(observed, expected, (doc, error))
                        self.assertEqual(rc, 1 if unsafe else 0, (doc, error))

    def test_policy_and_cached_source_changes(self):
        source = CASES[0][1]
        rc, doc, error = self.execute('cache', source, cache=True)
        self.assertEqual(rc, 1, (doc, error))
        rc, doc, error = self.execute('cache', source, cache=True)
        self.assertEqual(rc, 1, (doc, error))
        rc, doc, error = self.execute('cache', CASES[2][1], cache=True)
        self.assertEqual(rc, 0, (doc, error))
        rc, doc, error = self.execute('skipped', source, module=True, extra=('--skip=8',))
        self.assertFalse(any(row.get('rule') == RULE for row in doc.get('findings', [])), (doc, error))
        rc, doc, error = self.execute('suppressed', source.replace('// unsafe', '// ubs:ignore[' + RULE + ']'))
        self.assertEqual(rc, 0, (doc, error))

    def test_incomplete_scan_cannot_become_clean_or_cached(self):
        source = program('transport.GetAsync(incoming.Query["q"]);',
                         parameters='HttpRequest incoming, dynamic transport')
        for index in range(2):
            rc, doc, error = self.execute('partial', source, cache=True)
            self.assertEqual(rc, 2, (doc, error))
            self.assertEqual(doc['status'], 'partial', (doc, error))


if __name__ == '__main__':
    unittest.main()
