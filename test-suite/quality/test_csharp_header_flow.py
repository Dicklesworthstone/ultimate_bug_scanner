"""Independent request-to-response-header cases for the bounded C# frontend.

The unsafe/clean labels below were fixed before implementing this policy.
They follow value identity, CLR string operations and reachable response
header writes; a helper's name or an unrelated validation cannot change them.
Public module/meta checks also exercise selection, formats and warm caches.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "modules/helpers"))
RULE = "csharp.security.header-injection"
ARTIFACTS = ROOT / "test-suite/artifacts/csharp-header-flow"
USINGS = """using System;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
"""


def source(body, *, helpers="", parameters="HttpContext context, bool flag", extra=""):
    body = textwrap.indent(textwrap.dedent(body).strip(), "        ")
    helpers = textwrap.indent(textwrap.dedent(helpers).strip(), "    ") if helpers else ""
    return (USINGS + extra + "\nclass Handler : Controller {\n" + helpers + "\n"
            + f"    public void Run({parameters}) {{\n{body}\n    }}\n}}\n")


@dataclass(frozen=True)
class Case:
    name: str
    code: str

    @property
    def expected(self):
        result = []
        for number, line in enumerate(self.code.splitlines(), 1):
            if "// @header " in line:
                statement, marker = line.split("// @header ", 1)
                marker = marker.strip()
                assert statement.count(marker) == 1, (self.name, number, marker)
                result.append((number, statement.index(marker) + 1))
        return result


CASES = (
    Case("query_index_write", source('''
        var value = context.Request.Query["unusual-key"];
        context.Response.Headers["X-Value"] = value; // @header context.Response.Headers
    ''')),
    Case("header_index_append_assignment", source('''
        Response.Headers["X-Value"] += context.Request.Query["q"]; // @header Response.Headers
    ''')),
    Case("content_type_append_assignment", source('''
        Response.ContentType += context.Request.Query["q"].ToString(); // @header Response
    ''')),
    Case("context_request_response_header_aliases", source('''
        var input = context.Request;
        var output = context.Response;
        var headers = output.Headers;
        var value = input.Form["display"];
        headers.Append("X-Value", value); // @header headers.Append
    ''')),
    Case("accessor_request_and_response", source('''
        var value = accessor.HttpContext.Request.Query["q"];
        accessor.HttpContext.Response.Headers.Append("X-Value", value); // @header accessor.HttpContext.Response.Headers.Append
    ''', parameters="IHttpContextAccessor accessor")),
    Case("controller_context_source", source('''
        var value = ControllerContext.HttpContext.Request.Query["q"];
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("typed_request_and_response_aliases", source('''
        output.Headers.Add(value: input.Query["q"], key: "X-Value"); // @header output.Headers.Add
    ''', parameters="Input input, Output output", extra='''
using Input = Microsoft.AspNetCore.Http.HttpRequest;
using Output = Microsoft.AspNetCore.Http.HttpResponse;
''')),
    Case("helper_name_is_not_proof", source('''
        var value = SafeHeaderValue(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', helpers='''
        string SafeHeaderValue(string raw) { return raw; }
    ''')),
    Case("real_helper_removes_both_controls", source(r'''
        var value = Sanitize(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value);
    ''', helpers=r'''
        string Sanitize(string raw) {
            return raw.Replace("\r", string.Empty).Replace("\n", string.Empty);
        }
    ''')),
    Case("one_control_is_insufficient", source(r'''
        var value = context.Request.Query["q"].ToString().Replace("\r", "");
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("escaped_text_is_not_a_control", source(r'''
        var value = context.Request.Query["q"].ToString().Replace("\\r", "").Replace("\\n", "");
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("crlf_sequence_leaves_lone_controls", source(r'''
        var value = context.Request.Query["q"].ToString().Replace("\r\n", "");
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("both_character_replacements_are_safe", source(r'''
        var value = context.Request.Query["q"].ToString().Replace('\r', ' ').Replace('\n', ' ');
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("named_string_replacement_can_insert_cr", source(r'''
        var value = context.Request.Query["q"].ToString();
        value = value.Replace(newValue: "\r", oldValue: "X").Replace("\n", "");
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("named_character_replacement_can_insert_cr", source(r'''
        var value = context.Request.Query["q"].ToString();
        value = value.Replace(newChar: '\r', oldChar: 'X').Replace('\n', ' ');
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("named_replacements_remove_both_controls", source(r'''
        var value = context.Request.Query["q"].ToString();
        value = value.Replace(newValue: "", oldValue: "\r").Replace(newValue: "", oldValue: "\n");
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("unicode_controls_are_removed", source(r'''
        var value = context.Request.Query["q"].ToString().Replace("\u000d", "").Replace("\u000a", "");
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("ignored_replacement_does_not_validate_original", source(r'''
        var value = context.Request.Query["q"].ToString();
        value.Replace("\r", "").Replace("\n", "");
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("reassuring_header_key_does_not_sanitize_value", source('''
        var value = context.Request.Query["q"];
        Response.Headers.Append("SafeHeaderValue", value); // @header Response.Headers.Append
    ''')),
    Case("terminating_guard_proves_exact_value", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (value.Contains("\r", StringComparison.Ordinal) || value.Contains("\n", StringComparison.Ordinal)) {
            return;
        }
        var alias = value;
        Response.Headers.Append("X-Value", alias);
    ''')),
    Case("separate_terminating_guards", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (value.Contains('\r')) { throw new ArgumentException(); }
        if (value.Contains('\n')) { return; }
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("wrong_value_guard_is_not_proof", source(r'''
        var value = context.Request.Query["q"].ToString();
        var other = context.Request.Query["other"].ToString();
        if (other.Contains('\r') || other.Contains('\n')) { return; }
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("inverted_guard_leaves_unsafe_branch", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (!value.Contains('\r') && !value.Contains('\n')) { return; }
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("nonterminating_guard_is_not_proof", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (value.Contains('\r') || value.Contains('\n')) { Console.WriteLine("bad"); }
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("sequence_check_is_not_proof", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (value.Contains("\r\n")) { return; }
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("rebound_value_loses_proof", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (value.Contains('\r') || value.Contains('\n')) { return; }
        value = context.Request.Query["other"].ToString();
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("one_clean_branch_keeps_unsafe_path", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (flag) { value = value.Replace("\r", "").Replace("\n", ""); }
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("both_clean_branches", source(r'''
        var value = context.Request.Query["q"].ToString();
        if (flag) { value = value.Replace("\r", "").Replace("\n", ""); }
        else { value = "fixed"; }
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("literal_rebinding_kills_taint", source('''
        var value = context.Request.Query["q"];
        value = "fixed";
        Response.Headers.Append("X-Value", value);
    ''')),
    Case("helper_sink_preserves_execution_location", source('''
        Write(context.Response, context.Request.Query["q"].ToString());
    ''', helpers='''
        void Write(HttpResponse output, string value) {
            output.Headers.Append("X-Value", value); // @header output.Headers.Append
        }
    ''')),
    Case("helper_returns_header_dictionary", source('''
        Headers(context).Append("X-Value", context.Request.Query["q"]); // @header Headers(context).Append
    ''', helpers='''
        static IHeaderDictionary Headers(HttpContext current) { return current.Response.Headers; }
    ''')),
    Case("helper_returned_header_keeps_constant_value_clean", source('''
        Headers(context).Append("X-Value", "fixed");
    ''', helpers='''
        static IHeaderDictionary Headers(HttpContext current) { return current.Response.Headers; }
    ''')),
    Case("safe_actual_argument_reaches_helper_sink", source(r'''
        var value = context.Request.Query["q"].ToString().Replace("\r", "").Replace("\n", "");
        Write(context.Response, value);
    ''', helpers='''
        void Write(HttpResponse output, string value) {
            output.Headers.Append("X-Value", value);
        }
    ''')),
    Case("ref_helper_updates_exact_storage", source(r'''
        var value = context.Request.Query["q"].ToString();
        Sanitize(ref value);
        Response.Headers.Append("X-Value", value);
    ''', helpers=r'''
        void Sanitize(ref string value) { value = value.Replace("\r", "").Replace("\n", ""); }
    ''')),
    Case("annotation_is_scoped_source", source('''
        Response.Headers.Set("X-Value", value); // @header Response.Headers.Set
    ''', parameters="[FromQuery] string value")),
    Case("combined_annotation_is_source", source('''
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', parameters='[Marker, FromRoute(Name = "q")] string value', extra='''
class MarkerAttribute : Attribute {}
''')),
    Case("targeted_annotation_is_source", source('''
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', parameters="[param: FromQuery] string value")),
    Case("aliased_annotation_is_source", source('''
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', parameters="[HeaderInput] string value", extra='''
using HeaderInput = Microsoft.AspNetCore.Mvc.FromHeaderAttribute;
''')),
    Case("qualified_annotation_is_source", source('''
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', parameters="[global::Microsoft.AspNetCore.Mvc.FromBody] string value")),
    Case("shadowed_combined_annotation_is_not_source", source('''
        Response.Headers.Append("X-Value", value);
    ''', parameters="[Marker, FromRoute] string value", extra='''
class MarkerAttribute : Attribute {}
class FromRouteAttribute : Attribute {}
''')),
    Case("annotation_source_can_be_overwritten", source('''
        value = "fixed";
        Response.Headers.Append("X-Value", value);
    ''', parameters="[FromForm] string value")),
    Case("annotation_does_not_poison_sibling_local", source('''
        var value = "fixed";
        Response.Headers.Append("X-Value", value);
    ''', helpers='''
        public void Other([FromQuery] string value) { Console.WriteLine(value); }
    ''')),
    Case("string_parameter_without_request_binding_is_clean", source('''
        Response.Headers.Append("X-Value", value);
    ''', parameters="string value")),
    Case("bcl_url_encoding_is_safe", source('''
        var value = WebUtility.UrlEncode(context.Request.Form["q"].ToString());
        Response.Headers.Append("Content-Disposition", "attachment; filename=" + value);
    ''')),
    Case("shadowed_encoder_is_not_proof", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', extra='''
class WebUtility { public static string UrlEncode(string value) { return value; } }
''')),
    Case("field_named_web_utility_is_not_bcl_encoder", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', helpers="static readonly FakeEncoder WebUtility = new FakeEncoder();", extra='''
class FakeEncoder { public string UrlEncode(string value) { return value; } }
''')),
    Case("global_web_utility_bypasses_field_name", source('''
        var value = global::System.Net.WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value);
    ''', helpers="static readonly FakeEncoder WebUtility = new FakeEncoder();", extra='''
class FakeEncoder { public string UrlEncode(string value) { return value; } }
''')),
    Case("field_named_uri_is_not_bcl_encoder", source('''
        var value = Uri.EscapeDataString(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', helpers="static readonly FakeEncoder Uri = new FakeEncoder();", extra='''
class FakeEncoder { public string EscapeDataString(string value) { return value; } }
''')),
    Case("global_uri_bypasses_field_name", source('''
        var value = global::System.Uri.EscapeDataString(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value);
    ''', helpers="static readonly FakeEncoder Uri = new FakeEncoder();", extra='''
class FakeEncoder { public string EscapeDataString(string value) { return value; } }
''')),
    Case("field_named_url_encoder_is_not_bcl_encoder", source('''
        var value = UrlEncoder.Default.Encode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''', helpers="static readonly FakeEncoder UrlEncoder = new FakeEncoder();", extra='''
using System.Text.Encodings.Web;
class FakeEncoder {
    public FakeEncoder Default => this;
    public string Encode(string value) { return value; }
}
''')),
    Case("global_url_encoder_bypasses_field_name", source('''
        var value = global::System.Text.Encodings.Web.UrlEncoder.Default.Encode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", value);
    ''', helpers="static readonly FakeEncoder UrlEncoder = new FakeEncoder();", extra='''
using System.Text.Encodings.Web;
class FakeEncoder {
    public FakeEncoder Default => this;
    public string Encode(string value) { return value; }
}
''')),
    Case("reinserting_control_invalidates_proof", source(r'''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        value = value + "\r\nInjected: yes";
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("transformed_request_can_reintroduce_controls", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        value = WebUtility.UrlDecode(value);
        Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
    ''')),
    Case("interpolation_can_reintroduce_controls", source(r'''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", $"{value}\r\nInjected: yes"); // @header Response.Headers.Append
    ''')),
    Case("interpolation_preserves_encoded_value", source(r'''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("Content-Disposition", $"attachment; filename={value}");
    ''')),
    Case("interpolation_escaped_control_text_is_inert", source(r'''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", $"{value}\\r\\n is text");
    ''')),
    Case("interpolation_only_reads_literal_controls", source(r'''
        var value = context.Request.Query["q"].ToString();
        Response.Headers.Append("X-Value", $"{value.Replace("\r", "").Replace("\n", "")}");
    ''')),
    Case("verbatim_interpolation_retains_newline", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        var header = $@"{value}
        Injected: yes";
        Response.Headers.Append("X-Value", header); // @header Response.Headers.Append
    ''')),
    Case("raw_interpolation_retains_content_newline", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        var header = $"""
        {value}
        Injected: yes
        """;
        Response.Headers.Append("X-Value", header); // @header Response.Headers.Append
    ''')),
    Case("raw_interpolation_discards_delimiter_newlines", source('''
        var value = WebUtility.UrlEncode(context.Request.Query["q"].ToString());
        var header = $"""
        {value}
        """;
        Response.Headers.Append("X-Value", header);
    ''')),
    Case("typed_header_assignment", source('''
        var value = context.Request.Query["q"].ToString();
        context.Response.GetTypedHeaders().ContentDisposition = // @header context.Response.GetTypedHeaders
            new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment") { FileName = value };
    ''')),
    Case("typed_header_constant_mutation_is_clean", source('''
        var disposition = new Microsoft.Net.Http.Headers.ContentDispositionHeaderValue("attachment");
        disposition.FileName = "fixed.txt";
        Response.GetTypedHeaders().ContentDisposition = disposition;
    ''')),
    Case("unused_setter_is_not_request_data", source('''
        Response.Headers.Append("X-Value", "fixed");
    ''', helpers='''
        string saved;
        void Save(string value) { saved = value; }
    ''')),
    Case("constant_helper_setter_is_clean", source('''
        Save("fixed");
        Response.Headers.Append("X-Value", saved);
    ''', helpers='''
        string saved;
        void Save(string value) { saved = value; }
    ''')),
    Case("dynamic_header_name_does_not_hide_value", source('''
        var name = flag ? "X-One" : "X-Two";
        Response.Headers[name] = context.Request.Query["q"]; // @header Response.Headers
    ''')),
    Case("location_keeps_redirect_rule", source('''
        Response.Headers["Location"] = context.Request.Query["q"];
        Response.Headers.Append("Location", context.Request.Query["q"]);
    ''')),
    Case("ordinary_dictionary_is_not_response", source('''
        var headers = new LocalHeaders();
        headers.Append("X-Value", context.Request.Query["q"].ToString());
    ''', extra='''
class LocalHeaders { public void Append(string key, string value) { } }
''')),
    Case("local_request_shadows_controller_source", source('''
        var Request = new LocalInput();
        Response.Headers.Append("X-Value", Request.Query);
    ''', extra='''
class LocalInput { public string Query = "fixed"; }
''')),
    Case("comment_and_literal_decoys_are_inert", source(r'''
        // Response.Headers.Append("X-Value", context.Request.Query["q"]);
        var documentation = @"Response.Headers.Append(""X-Value"", context.Request.Query[""q""]);";
        Response.Headers.Append("X-Value", "fixed");
    ''')),
    Case("unrelated_collection_add_does_not_require_request_cfg", source('''
        var values = new System.Collections.Generic.List<string>();
        values.Add("fixed");
        goto done;
        done: return;
    ''')),
)

INCOMPLETE_CASES = (
    Case("mutable_typed_header_request_value", source('''
        var disposition = new Microsoft.Net.Http.Headers.ContentDispositionHeaderValue("attachment");
        disposition.FileName = context.Request.Query["name"].ToString();
        Response.GetTypedHeaders().ContentDisposition = disposition;
    ''')),
    Case("controller_field_request_value", source('''
        Save(context.Request);
        Emit();
    ''', helpers='''
        string saved;
        void Save(HttpRequest incoming) { saved = incoming.Query["q"]; }
        void Emit() { Response.Headers.Append("X-Value", saved); }
    ''')),
    Case("helper_setter_request_argument", source('''
        Save(context.Request.Query["q"].ToString());
        Response.Headers.Append("X-Value", saved);
    ''', helpers='''
        string saved;
        void Save(string value) { saved = value; }
    ''')),
)


def materialize(cases=CASES):
    directory = ARTIFACTS / uuid.uuid4().hex
    directory.mkdir(parents=True)
    for case in cases:
        (directory / (case.name + ".cs")).write_text(case.code, encoding="utf-8")
    return directory


class HeaderFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ubs_core.csharp_detectors import header_injection
        cls.detector = header_injection
        cls.directory = materialize()

    def test_independent_security_cases(self):
        for case in CASES:
            with self.subTest(case=case.name):
                path = self.directory / (case.name + ".cs")
                rows = list(self.detector.find([path], base_dir=self.directory))
                self.assertEqual(case.expected, [(row[1], row[2]) for row in rows], rows)

    def test_existing_fixture_pairs(self):
        for name, expected in (("HeaderInjectionBuggy.cs", [10, 16, 22, 27, 33]),
                               ("HeaderInjectionClean.cs", [])):
            with self.subTest(name=name):
                path = ROOT / "test-suite/csharp/security" / name
                self.assertEqual(expected, [row[1] for row in self.detector.find([path])])

    def test_request_derived_heap_writes_are_incomplete(self):
        directory = materialize(INCOMPLETE_CASES)
        for case in INCOMPLETE_CASES:
            with self.subTest(case=case.name):
                with self.assertRaisesRegex(ValueError, "heap write.*incomplete"):
                    list(self.detector.find([directory / (case.name + ".cs")]))

    def test_incomplete_heap_write_preserves_known_findings(self):
        case = Case("known_and_incomplete", source('''
            var value = context.Request.Query["q"].ToString();
            Response.Headers.Append("X-Value", value); // @header Response.Headers.Append
            saved = value;
        ''', helpers="string saved;"))
        directory = materialize((case,))
        rows = []
        with self.assertRaisesRegex(ValueError, "heap write.*incomplete"):
            rows.extend(self.detector.find([directory / (case.name + ".cs")]))
        self.assertEqual(case.expected, [(row[1], row[2]) for row in rows])

    def test_suppression_owns_sink_and_does_not_erase_aliases(self):
        text = source('''
            var value = context.Request.Query["q"]; // ubs:ignore[csharp.security.header-injection]
            Response.Headers.Append("X-First", value); // ubs:ignore[csharp.security.header-injection]
            Response.Headers.Append("X-Second", value); // @header Response.Headers.Append
        ''')
        case = Case("suppression", text)
        directory = materialize((case,))
        rows = list(self.detector.find([directory / "suppression.cs"]))
        self.assertEqual(case.expected, [(row[1], row[2]) for row in rows])

    def test_selected_source_only(self):
        path = self.directory / "literal_rebinding_kills_taint.cs"
        self.assertEqual([], list(self.detector.find([path])))

    def test_conditional_compilation_cannot_report_clean(self):
        path = self.directory / "configured.cs"
        path.write_text(source('''
            var value = context.Request.Query["q"];
            #if FLAG
            value = "fixed";
            #endif
            Response.Headers.Append("X-Value", value);
        '''), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            list(self.detector.find([path]))


@unittest.skipUnless(os.environ.get("UBS_CSHARP_HEADER_PUBLIC") == "1", "set UBS_CSHARP_HEADER_PUBLIC=1 for CLI acceptance")
class HeaderPublicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("ast-grep"):
            raise unittest.SkipTest("ast-grep is required for real module output")
        wanted = {"query_index_write", "real_helper_removes_both_controls", "helper_sink_preserves_execution_location",
                  "field_named_web_utility_is_not_bcl_encoder", "global_web_utility_bypasses_field_name"}
        cls.cases = tuple(case for case in CASES if case.name in wanted)
        cls.directory = materialize(cls.cases)
        cls.cache = cls.directory / "cache"
        cls.capture = 0

    def run_cli(self, form, *options, meta=False, project=None, expected_codes=(0, 1)):
        project = self.directory if project is None else project
        if meta:
            command = [str(ROOT / "ubs"), "--ci", "--no-config", "--no-dotnet", "--only=csharp"]
        else:
            command = [str(ROOT / "modules/ubs-csharp.sh"), "--ci", "--no-dotnet", "--only=8"]
        command += [f"--format={form}"]
        command += [*options, str(project)]
        env = dict(os.environ, NO_COLOR="1", UBS_CACHE_DIR=str(self.cache),
                   UBS_CACHE_FILE=str(self.directory / "cache.json"), UBS_NO_CACHE="0",
                   UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0", UBS_KEEP_TEMP="1",
                   UBS_MAX_DIR_SIZE_MB="0", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(command, cwd=self.directory, env=env, text=True, capture_output=True, timeout=90)
        type(self).capture += 1
        stem = self.directory / f"capture-{type(self).capture}-{form}"
        stem.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        stem.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
        self.assertIn(result.returncode, expected_codes, result.stderr + result.stdout)
        return result

    @staticmethod
    def rows(payload):
        return [row for row in payload.get("findings", []) if row.get("rule_id", row.get("rule")) == RULE]

    def test_module_json_cold_warm_sarif_and_meta(self):
        cold = json.loads(self.run_cli("json").stdout)
        warm = json.loads(self.run_cli("json").stdout)
        expected = sorted((case.name + ".cs", line, col) for case in self.cases for line, col in case.expected)
        for payload in (cold, warm):
            actual = sorted((Path(row.get("file", row.get("path", ""))).name,
                             row["line"], row.get("column", row.get("col"))) for row in self.rows(payload))
            self.assertEqual(expected, actual, payload)
        sarif = json.loads(self.run_cli("sarif").stdout)
        results = [row for run in sarif["runs"] for row in run.get("results", []) if row.get("ruleId") == RULE]
        actual = sorted((Path(row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]).name,
                         row["locations"][0]["physicalLocation"]["region"]["startLine"],
                         row["locations"][0]["physicalLocation"]["region"]["startColumn"]) for row in results)
        self.assertEqual(expected, actual, sarif)
        meta = json.loads(self.run_cli("json", meta=True).stdout)
        actual = sorted((Path(row.get("file", row.get("path", ""))).name,
                         row["line"], row.get("column", row.get("col"))) for row in self.rows(meta))
        self.assertEqual(expected, actual, meta)

    def test_text_skip_and_selected_files(self):
        output = self.run_cli("text").stdout
        self.assertIn("Request-controlled value reaches HTTP response header", output)
        skipped = json.loads(self.run_cli("json", "--skip=8").stdout)
        self.assertEqual([], self.rows(skipped))
        selected = json.loads(self.run_cli("json", project=self.directory / "real_helper_removes_both_controls.cs").stdout)
        self.assertEqual([], self.rows(selected))

    def test_partial_heap_flow_preserves_findings_across_cached_scans(self):
        cases = (
            Case("a_partial", source('''
                var value = context.Request.Query["q"].ToString();
                Response.Headers.Append("X-Before", value); // @header Response.Headers.Append
                saved = value;
                Response.Headers.Append("X-After", value); // @header Response.Headers.Append
            ''', helpers="string saved;")),
            Case("z_neighbor", source('''
                Response.Headers.Append("X-Value", context.Request.Query["q"]); // @header Response.Headers.Append
            ''')),
        )
        directory = materialize(cases)
        expected = sorted((case.name + ".cs", line, col) for case in cases for line, col in case.expected)
        for meta in (False, True):
            for attempt in range(2):
                with self.subTest(meta=meta, attempt=attempt):
                    payload = json.loads(self.run_cli("json", meta=meta, project=directory,
                                                      expected_codes=(2,)).stdout)
                    report = payload["scanners"][0] if meta else payload
                    self.assertEqual((report["status"], report["module_error"]),
                                     ("partial", "ANALYSIS_INCOMPLETE"), payload)
                    actual = sorted((Path(row.get("file", row.get("path", ""))).name,
                                     row["line"], row.get("column", row.get("col")))
                                    for row in self.rows(payload))
                    self.assertEqual(expected, actual, payload)


if __name__ == "__main__":
    unittest.main()
