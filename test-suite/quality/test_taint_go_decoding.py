"""Source-only regressions for Go decoding destinations and error results.

JSON/XML decoding writes through its destination; its error return is not the
request payload. Fixtures are parsed as source and never imported or executed.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch
import test_taint_go_packages as packages
from ubs_core.io import temporary_directory


class DecodingFlowTests(packages.PackageTestCase):
    def check(self, body, *rules):
        self.source('handler.go', 'package app\nfunc h() {\n' + body + '\n}\n')
        findings = self.scan()
        self.assertEqual(sorted(f['rule'] for f in findings),
                         sorted('go.taint.' + rule for rule in rules), findings)
        return findings

    def test_inline_json_decoder_writes_request_fields(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p)\ndb.Query(p.SQL)', 'sql')

    def test_saved_decoder_and_alias_retain_input_provenance(self):
        self.check('dec := json.NewDecoder(r.Body)\nalias := dec\nvar p Payload\n'
                   'alias.Decode(&p)\nexec.Command("sh", "-c", p.Command)', 'command')

    def test_decoded_html_is_an_output_source(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p)\nfmt.Fprint(w, p.HTML)', 'xss')

    def test_unmarshal_writes_bytes_into_destination(self):
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\n'
                   'json.Unmarshal(raw, &p)\ndb.Query(p.SQL)', 'sql')

    def test_reader_alias_retains_body_origin(self):
        self.check('body := request.Body\nvar p Payload\n'
                   'json.NewDecoder(body).Decode(&p)\ndb.Query(p.SQL)', 'sql')

    def test_ioutil_readall_preserves_payload_and_error_positions(self):
        self.check('raw, err := ioutil.ReadAll(req.Body)\nvar p Payload\n'
                   'json.Unmarshal(raw, &p)\ndb.Query(p.SQL)\ndb.Query(err.Error())', 'sql')

    def test_readall_error_is_not_request_payload(self):
        self.check('_, err := io.ReadAll(r.Body)\ndb.Query(err.Error())')

    def test_decoder_error_is_not_request_payload(self):
        self.check('var p Payload\nerr := json.NewDecoder(r.Body).Decode(&p)\ndb.Query(err.Error())')

    def test_unmarshal_error_is_not_payload_or_destination(self):
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\n'
                   'err := json.Unmarshal(raw, &p)\ndb.Query(err.Error())')

    def test_xml_decoder_and_decode_element_mutate_destinations(self):
        for operation in ('Decode(&p)', 'DecodeElement(&p, &start)'):
            with self.subTest(operation=operation):
                self.check('var p Payload\nxml.NewDecoder(r.Body).' + operation + '\ndb.Query(p.SQL)', 'sql')

    def test_xml_unmarshal_writes_destination(self):
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\n'
                   'xml.Unmarshal(raw, &p)\ndb.Query(p.SQL)', 'sql')

    def test_clean_reader_does_not_make_a_source(self):
        self.check('var p Payload\njson.NewDecoder(strings.NewReader(`{"SQL":"SELECT 1"}`)).Decode(&p)\n'
                   'db.Query(p.SQL)')

    def test_clean_unmarshal_does_not_make_a_source(self):
        self.check('var p Payload\njson.Unmarshal([]byte(`{"SQL":"SELECT 1"}`), &p)\ndb.Query(p.SQL)')

    def test_clean_decode_does_not_erase_existing_fields(self):
        self.check('p := r.FormValue("q")\njson.Unmarshal([]byte(`{}`), &p)\ndb.Query(p)', 'sql')

    def test_nonpointer_unmarshal_argument_is_not_written(self):
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\n'
                   'json.Unmarshal(raw, p)\ndb.Query(p.SQL)')

    def test_pointer_alias_observes_later_mutation(self):
        self.check('var p Payload\nptr := &p\nalias := ptr\n'
                   'json.NewDecoder(r.Body).Decode(alias)\ndb.Query(p.SQL)\ndb.Query(ptr.SQL)', 'sql', 'sql')

    def test_pointer_to_a_field_updates_its_containing_object(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p.SQL)\ndb.Query(p.SQL)', 'sql')

    def test_new_pointer_destination_is_tracked(self):
        self.check('p := new(Payload)\njson.NewDecoder(r.Body).Decode(p)\ndb.Query(p.SQL)', 'sql')

    def test_addressed_composite_destination_is_tracked(self):
        self.check('p := &Payload{}\njson.NewDecoder(r.Body).Decode(p)\ndb.Query(p.SQL)', 'sql')

    def test_rebound_pointer_does_not_write_previous_target(self):
        self.check('var p, other Payload\nptr := &p\nptr = &other\n'
                   'json.NewDecoder(r.Body).Decode(ptr)\ndb.Query(p.SQL)\ndb.Query(other.SQL)', 'sql')

    def test_pointer_alias_does_not_snapshot_old_pointee_data(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p)\nptr := &p\n'
                   'p = Payload{}\ndb.Query(ptr.SQL)')

    def test_returned_destination_value_preserves_decoded_fields(self):
        self.source('helper.go', 'package app\nfunc read() Payload { var p Payload; '
                    'json.NewDecoder(r.Body).Decode(&p); return p }\n')
        self.check('p := read()\ndb.Query(p.SQL)', 'sql')

    def test_decoder_and_pointer_pairs_keep_parallel_assignment_order(self):
        self.check('var a, b Payload\np, q := &a, &b\np, q = q, p\n'
                   'dec := json.NewDecoder(r.Body)\ndec.Decode(p)\n'
                   'db.Query(a.SQL)\ndb.Query(b.SQL)', 'sql')

    def test_branch_pointer_targets_are_conservatively_joined(self):
        self.check('var a, b Payload\nptr := &a\nif choice { ptr = &b }\n'
                   'json.NewDecoder(r.Body).Decode(ptr)\ndb.Query(a.SQL)\ndb.Query(b.SQL)', 'sql', 'sql')

    def test_shadowed_pointer_leaves_outer_destination_untouched(self):
        self.check('var p, other Payload\nptr := &p\n'
                   '{ ptr := &other; json.NewDecoder(r.Body).Decode(ptr) }\n'
                   'db.Query(p.SQL)\ndb.Query(other.SQL)', 'sql')

    def test_rebound_decoder_loses_old_reader(self):
        self.check('dec := json.NewDecoder(r.Body)\ndec = json.NewDecoder(strings.NewReader(`{}`))\n'
                   'var p Payload\ndec.Decode(&p)\ndb.Query(p.SQL)')

    def test_decoder_branch_preserves_possible_input(self):
        self.check('dec := json.NewDecoder(strings.NewReader(`{}`))\n'
                   'if choice { dec = json.NewDecoder(r.Body) }\nvar p Payload\ndec.Decode(&p)\ndb.Query(p.SQL)', 'sql')

    def test_decoder_shadow_does_not_contaminate_outer_handle(self):
        self.check('dec := json.NewDecoder(strings.NewReader(`{}`))\n'
                   '{ dec := json.NewDecoder(r.Body); var inner Payload; dec.Decode(&inner) }\n'
                   'var p Payload\ndec.Decode(&p)\ndb.Query(p.SQL)')

    def test_parameterized_sql_data_remains_safe(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p)\ndb.Query("SELECT $1", p.SQL)')

    def test_html_sanitizer_stays_domain_specific_after_decoding(self):
        self.check('var p Payload\njson.NewDecoder(r.Body).Decode(&p)\n'
                   'safe := html.EscapeString(p.HTML)\nfmt.Fprint(w, safe)\ndb.Query(safe)', 'sql')

    def test_decode_inside_error_guard_reaches_following_code(self):
        self.check('var p Payload\nif err := json.NewDecoder(r.Body).Decode(&p); err != nil { return }\n'
                   'db.Query(p.SQL)', 'sql')

    def test_unknown_decode_method_is_not_a_request_source(self):
        self.check('var p Payload\ncustom.Decode(&p)\ndb.Query(p.SQL)')

    def test_decoder_tokens_return_input_not_errors(self):
        self.check('dec := json.NewDecoder(r.Body)\nvalue, err := dec.Token()\n'
                   'fmt.Fprint(w, value)\nfmt.Fprint(w, err)', 'xss')

    def test_decoder_options_and_predicates_return_no_payload(self):
        self.check('dec := json.NewDecoder(r.Body)\ndec.UseNumber()\ndec.DisallowUnknownFields()\n'
                   'fmt.Fprint(w, dec.More())\nfmt.Fprint(w, dec.InputOffset())')

    def test_package_helper_writes_destination_parameter(self):
        self.source('helper.go', 'package app\nfunc decode(raw []byte, dst *Payload) { json.Unmarshal(raw, dst) }\n')
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\ndecode(raw, &p)\ndb.Query(p.SQL)', 'sql')

    def test_package_helper_write_uses_correct_argument(self):
        self.source('helper.go', 'package app\nfunc decode(raw []byte, dst *Payload) { json.Unmarshal(raw, dst) }\n')
        self.check('raw, _ := io.ReadAll(r.Body)\nvar clean, p Payload\ndecode(raw, &p)\n'
                   'db.Query(clean.SQL)\ndb.Query(p.SQL)', 'sql')

    def test_helper_transitive_pointer_alias_writes_reach_caller(self):
        self.source('helper.go', 'package app\nfunc decode(raw []byte, dst *Payload) { alias := dst; json.Unmarshal(raw, alias) }\n'
                    'func relay(raw []byte, out *Payload) { decode(raw, out) }\n')
        self.check('raw, _ := io.ReadAll(r.Body)\nvar p Payload\nrelay(raw, &p)\ndb.Query(p.SQL)', 'sql')

    def test_helper_clean_input_does_not_make_a_source(self):
        self.source('helper.go', 'package app\nfunc decode(raw []byte, dst *Payload) { json.Unmarshal(raw, dst) }\n')
        self.check('var p Payload\ndecode([]byte(`{}`), &p)\ndb.Query(p.SQL)')

    def test_scalar_parameter_copy_does_not_become_a_pointer_alias(self):
        self.source('helper.go', 'package app\nfunc copy(v string) string { saved := v; '
                    'v = r.FormValue("q"); return saved }\n')
        self.check('db.Query(copy("SELECT 1"))')

    def test_scalar_parameter_copy_survives_original_clean_overwrite(self):
        self.source('helper.go', 'package app\nfunc copy(v string) string { saved := v; '
                    'v = "safe"; return saved }\n')
        self.check('db.Query(copy(r.FormValue("q")))', 'sql')

    def test_source_created_inside_helper_reaches_destination(self):
        self.source('helper.go', 'package app\nfunc decode(dst *Payload) { json.NewDecoder(r.Body).Decode(dst) }\n')
        self.check('var p Payload\ndecode(&p)\ndb.Query(p.SQL)', 'sql')

    def test_decoding_in_comments_and_raw_strings_is_inert(self):
        self.check('var p Payload\n_ = `json.NewDecoder(r.Body).Decode(&p)`\n'
                   '// json.NewDecoder(r.Body).Decode(&p)\ndb.Query(p.SQL)')


class NativeScanningFlowTests(packages.PackageTestCase):
    """Native formatted input writes selected text destinations, not return slots."""

    def setUp(self):
        self.started = time.monotonic()
        artifacts = packages.ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='go-native-scanning-', dir=artifacts))
        self.sources = {}
        print(f'[{self.id()}] RUN', flush=True)

    def check_scan(self, body, expected=(), *, imports='import ("fmt"; "strings"; "html"; "os/exec")', helpers=''):
        self.source('handler.go', 'package app\n' + imports + '\n' + textwrap.dedent(helpers)
                    + '\nfunc h() {\n' + textwrap.dedent(body) + '\n}\n')
        findings = self.scan()
        (self.root / 'findings.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
        source = self.sources['handler.go'].read_text()
        sites = []
        for marker, rule, sink in expected:
            lines = [(number, line) for number, line in enumerate(source.splitlines(), 1)
                     if '// ' + marker in line]
            self.assertEqual(len(lines), 1, (marker, source))
            number, line = lines[0]
            sites.append((number, line.index(sink) + 1, 'go.taint.' + rule))
        actual = [(row['line'], row['col'], row['rule']) for row in findings]
        self.assertEqual(sorted(actual), sorted(sites), (source, findings))
        return findings

    def test_stdin_scan_family_writes_text_and_preserves_result_slots(self):
        for operation, arguments in [('Scan', '&value'), ('Scanln', '&value'), ('Scanf', '"%s", &value')]:
            with self.subTest(operation=operation):
                self.check_scan('var value string\nn, err := fmt.' + operation + '(' + arguments + ')\n'
                                'db.Query(value) // query\nexec.Command("sh", "-c", value) // command\n'
                                'fmt.Fprint(w, value) // output\nfmt.Fprint(w, n, err)',
                                [('query', 'sql', 'db.Query'), ('command', 'command', 'exec.Command'),
                                 ('output', 'xss', 'fmt.Fprint')])

    def test_readinto_native_operations_write_payload_not_result_metadata(self):
        for operation, extra in (('ReadFull', ''), ('ReadAtLeast', ', 1')):
            with self.subTest(operation=operation):
                self.check_scan('buffer := make([]byte, 32)\n'
                                'n, err := io.' + operation + '(r.Body, buffer' + extra + ')\n'
                                'db.Query(string(buffer)) // query\n'
                                'exec.Command("sh", "-c", string(buffer)) // command\n'
                                'fmt.Fprint(w, string(buffer)) // output\n'
                                'fmt.Fprint(w, n, err)',
                                [('query', 'sql', 'db.Query'), ('command', 'command', 'exec.Command'),
                                 ('output', 'xss', 'fmt.Fprint')], imports='import ("io"; "fmt"; "os/exec")')

    def test_readinto_native_aliases_and_selected_reader_factory_keep_identity(self):
        self.check_scan('buffer := make([]uint8, 8)\n'
                        'read := stream.ReadFull\nsaved := read\n'
                        'source := factory()\nsaved(source, buffer)\n'
                        'db.Query(string(buffer)) // query', [('query', 'sql', 'db.Query')],
                        imports='import (stream "io"; environment "os")',
                        helpers='func factory() stream.Reader { return environment.Stdin }')

    def test_readinto_buffer_aliases_observe_backing_storage_and_rebinding(self):
        self.check_scan('buffer := make([]byte, 8)\nalias := buffer\n'
                        'snapshot := string(buffer)\nbuffer = make([]byte, 8)\n'
                        'io.ReadFull(r.Body, alias[1:])\n'
                        'db.Query(string(alias)) // alias\n'
                        'db.Query(string(buffer))\ndb.Query(snapshot)',
                        [('alias', 'sql', 'db.Query')], imports='import "io"')

    def test_readinto_zero_length_and_impossible_minimum_do_not_read(self):
        operations = (
            'io.ReadFull(custom, buffer[:0])',
            'io.ReadFull(custom, nil)',
            'io.ReadAtLeast(custom, buffer, 0)',
            'io.ReadAtLeast(custom, buffer, -1)',
            'io.ReadAtLeast(custom, buffer, 9)',
            'io.ReadAtLeast(custom, make([]byte, 0), count)',
        )
        for operation in operations:
            with self.subTest(operation=operation):
                self.check_scan('buffer := make([]byte, 8)\nn, err := ' + operation + '\n'
                                'db.Query(string(buffer))\nfmt.Fprint(w, n, err)',
                                imports='import ("io"; "fmt")')

    def test_readinto_reslicing_empty_capacity_may_read(self):
        self.check_scan('buffer := make([]byte, 0, 8)\nalias := buffer[:8]\n'
                        'io.ReadFull(r.Body, alias)\ndb.Query(string(alias)) // query',
                        [('query', 'sql', 'db.Query')], imports='import "io"')

    def test_readinto_fixed_bytes_weak_writes_and_sanitizer_domains(self):
        self.check_scan('fixed := make([]byte, 8)\nio.ReadFull(strings.NewReader("fixed"), fixed)\n'
                        'db.Query(string(fixed))\nbuffer := make([]byte, 8)\n'
                        'io.ReadFull(r.Body, buffer)\n'
                        'io.ReadFull(strings.NewReader("x"), buffer)\n'
                        'db.Query(string(buffer)) // preserved\n'
                        'db.Query("SELECT $1", string(buffer))\n'
                        'safe := html.EscapeString(string(buffer))\nfmt.Fprint(w, safe)\n'
                        'db.Query(safe) // domain',
                        [('preserved', 'sql', 'db.Query'), ('domain', 'sql', 'db.Query')],
                        imports='import ("io"; "strings"; "html"; "fmt")')

    def test_readinto_selected_helper_writes_a_slice_parameter(self):
        self.check_scan('buffer := make([]byte, 8)\nread(r.Body, buffer)\n'
                        'db.Query(string(buffer)) // query\n'
                        'empty := make([]byte, 0)\nread(r.Body, empty)\ndb.Query(string(empty))',
                        [('query', 'sql', 'db.Query')], imports='import "io"',
                        helpers='func read(source io.Reader, destination []byte) { io.ReadFull(source, destination) }')

    def test_readinto_import_decoys_and_lexical_shadows_do_not_borrow_io(self):
        for imports, helpers, call in (
            ('import io "example.org/io"', '', 'io.ReadFull(r.Body, buffer)'),
            ('import "io"', 'func h2() { io := custom; buffer := make([]byte, 8); '
             'io.ReadFull(r.Body, buffer); db.Query(string(buffer)) }', ''),
            ('import . "io"', 'func ReadFull(_ interface{}, _ []byte) {}', 'ReadFull(r.Body, buffer)'),
        ):
            with self.subTest(imports=imports, call=call):
                self.check_scan('buffer := make([]byte, 8)\n' + call + '\ndb.Query(string(buffer))',
                                imports=imports, helpers=helpers)

    def test_readinto_unknown_protocols_and_untracked_destinations_are_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit

        for body in (
            'buffer := make([]byte, 8)\nio.ReadFull(custom, buffer)',
            'buffer := external()\nio.ReadFull(r.Body, buffer)',
            'buffer := make([]byte, 8)\nread := io.ReadFull\nif choice { read = custom }\nread(r.Body, buffer)',
            'buffer := make([]byte, 8)\nexternal(buffer)\nio.ReadFull(r.Body, buffer)',
            'buffer := make([]byte, 8)\naliases := [][]byte{buffer}\nio.ReadFull(r.Body, buffer)',
            'buffer := make([]byte, 8)\nreader := bytes.NewReader(buffer)\nio.ReadFull(r.Body, buffer)',
            'buffer := make([]byte, 8)\ndefer func() { io.ReadFull(r.Body, buffer) }()',
        ):
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'reader|buffer'):
                self.check_scan(body, imports='import ("io"; "bytes")')

    @unittest.skipUnless(os.environ.get('UBS_GO_READINTO_NATIVE') == '1',
                         'set UBS_GO_READINTO_NATIVE=1 for real Go read-into witnesses')
    def test_readinto_native_witness_matches_payload_alias_and_no_read_semantics(self):
        source = textwrap.dedent('''
            package main
            import ("encoding/json"; "io"; "os"; "strings"; "fmt")
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string) { db.Queries = append(db.Queries, query) }
            func main() {
                db := &Recorder{}
                buffer := make([]byte, 4)
                alias := buffer
                snapshot := string(buffer)
                n, err := io.ReadFull(os.Stdin, buffer)
                db.Query(string(alias)) // payload
                db.Query(snapshot)
                db.Query(fmt.Sprint(n, ":", err))
                empty := buffer[:0]
                io.ReadFull(os.Stdin, empty)
                fixed := []byte("fixed")
                io.ReadAtLeast(os.Stdin, fixed, 6)
                io.ReadAtLeast(os.Stdin, fixed, -1)
                db.Query(string(fixed))
                io.ReadAtLeast(strings.NewReader(os.Getenv("UBS_GO_BUFFERED_INPUT")), buffer, 1)
                db.Query(string(alias)) // minimum
                io.ReadFull(strings.NewReader("x"), buffer)
                db.Query(string(alias)) // short
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        BufferedReaderFlowTests.run_native_reader(
            self, source, ['<std', '\0' * 4, '4:<nil>', 'fixed', '<sup', 'xsup'])
        findings = self.scan()
        expected = sorted((number, line.index('db.Query') + 1, 'go.taint.sql')
                          for number, line in enumerate(source.splitlines(), 1)
                          if any('// ' + marker in line for marker in ('payload', 'minimum', 'short')))
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings), expected, findings)

    def test_readinto_empty_alias_and_size_metadata_have_no_payload(self):
        self.check_scan('buffer := make([]byte, 0, 8)\nalias := buffer[:8]\n'
                        'io.ReadFull(r.Body, alias)\ndb.Query(string(buffer))\n'
                        'db.Query(fmt.Sprint(len(alias), cap(alias)))\n'
                        'db.Query(string(alias)) // query', [('query', 'sql', 'db.Query')],
                        imports='import ("io"; "fmt")')

    def test_readinto_nil_slices_and_rune_literals_keep_real_lengths(self):
        self.check_scan('var empty []byte\nio.ReadFull(custom, empty)\n'
                        'buffer := []byte{\'x\'}\nio.ReadFull(r.Body, buffer)\n'
                        'db.Query(string(buffer)) // query', [('query', 'sql', 'db.Query')],
                        imports='import "io"')

    def test_readinto_string_snapshots_and_copied_byte_allocations_stay_independent(self):
        self.check_scan('buffer := []byte("fixed")\nsnapshot := string(buffer)\n'
                        'copy := []byte(string(buffer))\nio.ReadFull(r.Body, buffer)\n'
                        'db.Query(snapshot)\ndb.Query(string(copy))\n'
                        'db.Query(string(buffer)) // query', [('query', 'sql', 'db.Query')],
                        imports='import "io"')

    def test_readinto_immediate_closure_writes_the_selected_backing_array(self):
        self.check_scan('buffer := make([]byte, 8)\n'
                        'func(destination []byte) { io.ReadFull(r.Body, destination) }(buffer)\n'
                        'db.Query(string(buffer)) // query', [('query', 'sql', 'db.Query')],
                        imports='import "io"')

    def test_readinto_selected_helper_returns_the_original_slice_alias(self):
        self.check_scan('buffer := make([]byte, 8)\nalias := identity(buffer)\n'
                        'io.ReadFull(r.Body, alias)\ndb.Query(string(buffer)) // query',
                        [('query', 'sql', 'db.Query')], imports='import "io"',
                        helpers='func identity(value []byte) []byte { return value }')

    def test_readinto_helper_destinations_and_mutable_globals_refuse_unknown_backing(self):
        from ubs_core.taint_flow import AnalysisLimit

        for body, helpers in (
            ('buffer := external()\nread(r.Body, buffer)',
             'func read(source io.Reader, value []byte) { io.ReadFull(source, value) }'),
            ('buffer := factory()\nio.ReadFull(r.Body, buffer)',
             'func factory() []byte { return make([]byte, 8) }'),
            ('alias := buffer\nio.ReadFull(r.Body, alias)', 'var buffer = make([]byte, 8)'),
            ('io.ReadFull(r.Body, buffer)', 'var buffer = make([]byte, 0)\n'
             'func change() { buffer = make([]byte, 8) }'),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'buffer'):
                self.check_scan(body, imports='import "io"', helpers=helpers)

    def test_readinto_backing_capability_is_not_a_decoder_output_pointer(self):
        self.check_scan('var changed []byte\njson.NewDecoder(r.Body).Decode(&changed)\n'
                        'db.Query(string(changed)) // decoded\n'
                        'untouched := make([]byte, 8)\njson.NewDecoder(r.Body).Decode(untouched)\n'
                        'db.Query(string(untouched))\njson.Unmarshal([]byte(r.FormValue("body")), untouched)\n'
                        'db.Query(string(untouched))', [('decoded', 'sql', 'db.Query')],
                        imports='import "encoding/json"')

    def test_readinto_borrowed_reader_consumes_stable_backing_contents(self):
        self.check_scan('buffer := make([]byte, 8)\nio.ReadFull(r.Body, buffer)\n'
                        'reader := bytes.NewReader(buffer)\ncontents, err := io.ReadAll(reader)\n'
                        'db.Query(string(contents)) // query\ndb.Query(fmt.Sprint(err))',
                        [('query', 'sql', 'db.Query')], imports='import ("io"; "bytes"; "fmt")')

    def test_readinto_opaque_mutation_refuses_native_buffer_and_reader_snapshots(self):
        from ubs_core.taint_flow import AnalysisLimit

        for body in (
            'io.ReadFull(strings.NewReader("fixed"), buffer)\nexternal.Mutate(buffer)',
            'reader := bytes.NewReader(buffer)\nexternal.Mutate(buffer)\n'
            'contents, _ := io.ReadAll(reader)\ndb.Query(string(contents))',
            'external.Mutate(buffer)\nreader := bytes.NewReader(buffer)',
        ):
            with self.subTest(body=body):
                source = 'package app\nimport ("io"; "bytes"; "strings")\nfunc h() {\n' + (
                    'db.Query(r.FormValue("before"))\nbuffer := make([]byte, 8)\n' + body + '\n}\n')
                self.source('handler.go', source)
                findings = []
                with self.assertRaisesRegex(AnalysisLimit, 'buffer'):
                    for finding in packages.taint_go.run(packages.RunContext(lang='go', files=list(self.sources.values()))):
                        findings.append(finding)
                self.assertEqual([(finding['line'], finding['rule']) for finding in findings],
                                 [(4, 'go.taint.sql')], findings)

    def test_readinto_reader_snapshots_refuse_indexed_and_decoder_mutation(self):
        from ubs_core.taint_flow import AnalysisLimit

        for mutation, helpers, boundary in (
            ('buffer[0] = os.Getenv("Q")[0]', '', 'buffer'),
            ('change(buffer)', 'func change(value []byte) { value[0] = os.Getenv("Q")[0] }', 'buffer'),
            ('json.Unmarshal([]byte(r.FormValue("json")), &buffer)', '', 'buffer'),
            ('json.NewDecoder(r.Body).Decode(&buffer)', '', 'buffer'),
            ('fmt.Sscan(r.FormValue("text"), &buffer)', '', 'formatted input'),
        ):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(AnalysisLimit, boundary):
                self.check_scan('buffer := make([]byte, 8)\nreader := bytes.NewReader(buffer)\n' +
                                mutation + '\ncontents, _ := io.ReadAll(reader)\n'
                                'db.Query(string(contents))',
                                imports='import ("io"; "bytes"; "os"; "fmt"; "encoding/json")',
                                helpers=helpers)

    def test_readinto_reader_borrow_refuses_fresh_helper_backing_without_identity(self):
        from ubs_core.taint_flow import AnalysisLimit

        with self.assertRaisesRegex(AnalysisLimit, 'buffer'):
            self.check_scan('buffer := fresh()\nreader := bytes.NewReader(buffer)\n'
                            'buffer[0] = os.Getenv("Q")[0]\ncontents, _ := io.ReadAll(reader)\n'
                            'db.Query(string(contents))', imports='import ("io"; "bytes"; "os")',
                            helpers='func fresh() []byte { return make([]byte, 8) }')

    def test_readinto_reader_borrow_keeps_rebinding_and_empty_backing_independent(self):
        self.check_scan('buffer := []byte("fixed")\nreader := bytes.NewReader(buffer)\n'
                        'buffer = []byte(r.FormValue("later"))\n'
                        'contents, _ := io.ReadAll(reader)\ndb.Query(string(contents))\n'
                        'db.Query(string(buffer)) // query\n'
                        'empty := bytes.NewReader(nil)\nnone, _ := io.ReadAll(empty)\n'
                        'db.Query(string(none))', [('query', 'sql', 'db.Query')],
                        imports='import ("io"; "bytes")')

    def test_readinto_opaque_slice_header_escape_invalidates_native_backing_proofs(self):
        from ubs_core.taint_flow import AnalysisLimit

        for body, helpers in (
            ('buffer := make([]byte, 8)\nio.ReadFull(strings.NewReader("fixed"), buffer)\n'
             'external.Mutate(&buffer)\ndb.Query(string(buffer))', ''),
            ('buffer := make([]byte, 8)\nreader := bytes.NewReader(buffer)\n'
             'external.Mutate(&buffer)\ncontents, _ := io.ReadAll(reader)\ndb.Query(string(contents))', ''),
            ('buffer := make([]byte, 8)\naddress := &buffer\nreader := bytes.NewReader(buffer)\n'
             'external.Mutate(address)\ncontents, _ := io.ReadAll(reader)\ndb.Query(string(contents))', ''),
            ('var buffer []byte\nexternal.Mutate(&buffer)\nio.ReadFull(r.Body, buffer)\n'
             'db.Query(string(buffer))', ''),
            ('buffer := make([]byte, 8)\nio.ReadFull(strings.NewReader("fixed"), buffer)\n'
             'mutate(&buffer)\ndb.Query(string(buffer))',
             'func mutate(value *[]byte) { external.Mutate(value) }'),
            ('var buffer []byte\nmutate(&buffer)\nio.ReadFull(r.Body, buffer)\ndb.Query(string(buffer))',
             'func mutate(value *[]byte) { external.Mutate(value) }'),
            ('buffer := make([]byte, 8)\nreader := bytes.NewReader(buffer)\n'
             'mutate(buffer)\ncontents, _ := io.ReadAll(reader)\ndb.Query(string(contents))',
             'func mutate(value []byte) { external.Mutate(&value) }'),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'buffer'):
                self.check_scan(body, imports='import ("io"; "bytes"; "strings")', helpers=helpers)

    def test_readinto_opaque_value_transport_preserves_empty_slice_header_length(self):
        for call, helpers in (
            ('external.Mutate(buffer)', ''),
            ('mutate(buffer)', 'func mutate(value []byte) { external.Mutate(value) }'),
        ):
            with self.subTest(call=call):
                self.check_scan('var buffer []byte\n' + call + '\nio.ReadFull(customReader, buffer)\n'
                                'db.Query(string(buffer))', imports='import "io"', helpers=helpers)

    def test_copy_native_byte_contents_and_clean_count(self):
        self.check_scan('buffer := make([]byte, 32)\n'
                        'n := copy(buffer, os.Getenv("UBS_COPY_INPUT"))\n'
                        'db.Query(string(buffer)) // query\n'
                        'exec.Command("sh", "-c", string(buffer)) // command\n'
                        'fmt.Fprint(w, string(buffer)) // output\nfmt.Fprint(w, n)',
                        [('query', 'sql', 'db.Query'), ('command', 'command', 'exec.Command'),
                         ('output', 'xss', 'fmt.Fprint')],
                        imports='import ("os"; "fmt"; "os/exec")')

    def test_copy_aliases_and_string_snapshots_remain_distinct(self):
        self.check_scan('buffer := make([]byte, 8)\nalias := buffer\n'
                        'snapshot := string(buffer)\nbuffer = make([]byte, 8)\n'
                        'copy(alias[1:], os.Getenv("UBS_COPY_INPUT"))\n'
                        'db.Query(string(alias)) // alias\n'
                        'db.Query(string(buffer))\ndb.Query(snapshot)',
                        [('alias', 'sql', 'db.Query')], imports='import "os"')

    def test_copy_buffer_sources_and_overlapping_slices_keep_payload(self):
        self.check_scan('source := make([]byte, 8)\nio.ReadFull(r.Body, source)\n'
                        'destination := make([]byte, 8)\n'
                        'n := copy(destination, source)\ncopy(destination[1:], destination)\n'
                        'db.Query(string(destination)) // destination\n'
                        'db.Query(string(source)) // source\nfmt.Fprint(w, n)',
                        [('destination', 'sql', 'db.Query'), ('source', 'sql', 'db.Query')],
                        imports='import ("io"; "fmt")')

    def test_copy_owned_buffer_string_conversion_preserves_contents(self):
        self.check_scan('source := make([]byte, 8)\nio.ReadFull(r.Body, source)\n'
                        'destination := make([]byte, 8)\nn := copy(destination, string(source))\n'
                        'db.Query(string(destination)) // query\nfmt.Fprint(w, n)',
                        [('query', 'sql', 'db.Query')], imports='import ("io"; "fmt")')

    def test_copy_saved_rune_reslice_does_not_prove_empty_destination(self):
        self.check_scan('buffer := make([]byte, 8)\n'
                        "alias := buffer[:'\\x01']\n"
                        'copy(alias, os.Getenv("UBS_COPY_INPUT"))\n'
                        'db.Query(string(buffer)) // query',
                        [('query', 'sql', 'db.Query')], imports='import "os"')

    def test_copy_rune_reslice_sources_do_not_drop_contents(self):
        for preparation, source in (
            ('', "buffer[:'\\x01']"),
            ("alias := buffer[:'\\x01']\n", 'alias'),
        ):
            with self.subTest(source=source):
                self.check_scan('buffer := make([]byte, 8)\nio.ReadFull(r.Body, buffer)\n'
                                'destination := make([]byte, 8)\n' + preparation +
                                'copy(destination, ' + source + ')\n'
                                'db.Query(string(destination)) // query',
                                [('query', 'sql', 'db.Query')], imports='import "io"')

    def test_readinto_rune_reslice_bounds_do_not_prove_zero_length(self):
        self.check_scan('buffer := make([]byte, 8)\n'
                        "alias := buffer[:'\\x01']\n"
                        'io.ReadFull(r.Body, alias)\ndb.Query(string(buffer)) // query',
                        [('query', 'sql', 'db.Query')], imports='import "io"')

    def test_copy_empty_sources_and_destinations_do_not_write(self):
        self.check_scan('buffer := make([]byte, 8)\nvar empty []byte\n'
                        'n1 := copy(buffer[:0], r.FormValue("q"))\n'
                        'n2 := copy(empty, r.FormValue("q"))\n'
                        'n3 := copy(buffer, empty)\nn4 := copy(buffer, "")\n'
                        'db.Query(string(buffer))\nfmt.Fprint(w, n1, n2, n3, n4)')

    def test_copy_weak_prefix_writes_and_sanitizer_domains(self):
        self.check_scan('buffer := make([]byte, 32)\ncopy(buffer, os.Getenv("UBS_COPY_INPUT"))\n'
                        'copy(buffer, "x")\ndb.Query(string(buffer)) // suffix\n'
                        'db.Query("SELECT $1", string(buffer))\n'
                        'escaped := make([]byte, 32)\n'
                        'copy(escaped, html.EscapeString(os.Getenv("UBS_COPY_INPUT")))\n'
                        'fmt.Fprint(w, string(escaped))\ndb.Query(string(escaped)) // domain',
                        [('suffix', 'sql', 'db.Query'), ('domain', 'sql', 'db.Query')],
                        imports='import ("os"; "html"; "fmt")')

    def test_copy_selected_helper_writes_and_return_count(self):
        self.check_scan('buffer := make([]byte, 8)\nsource := make([]byte, 8)\n'
                        'io.ReadFull(r.Body, source)\nn := relay(buffer, source)\n'
                        'db.Query(string(buffer)) // query\nfmt.Fprint(w, n)\n'
                        'empty := make([]byte, 0)\nrelay(empty, source)\n'
                        'db.Query(string(empty))', [('query', 'sql', 'db.Query')],
                        imports='import ("io"; "fmt")',
                        helpers='func move(destination []byte, value []byte) int {\n'
                                '    return copy(destination, value)\n}\n'
                                'func relay(destination []byte, value []byte) int {\n'
                                '    return move(destination, value)\n}\n')

    def test_copy_shadowed_builtin_keeps_selected_function_behavior(self):
        self.check_scan('buffer := make([]byte, 8)\ncopy(buffer, r.FormValue("q"))\n'
                        'db.Query(string(buffer))',
                        helpers='func copy(destination []byte, value string) int { return 0 }')

    def test_copy_captured_header_replacement_stays_explicitly_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', 'package app\nfunc h() {\n'
                    'db.Query(r.FormValue("before"))\n'
                    'original := make([]byte, 8)\nreplacement := make([]byte, 8)\n'
                    'destination := original\n'
                    'copy(destination, func() string {\n'
                    '    destination = replacement\n    return r.FormValue("q")\n}())\n'
                    'db.Query(string(original))\ndb.Query(string(replacement))\n}\n')
        findings = []
        with self.assertRaisesRegex(AnalysisLimit, 'captured buffer replacement'):
            for finding in packages.taint_go.run(packages.RunContext(lang='go', files=list(self.sources.values()))):
                findings.append(finding)
        self.assertEqual([(finding['line'], finding['rule']) for finding in findings],
                         [(3, 'go.taint.sql')], findings)

    def test_copy_unknown_ownership_and_deferred_writes_are_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit

        for body in (
            'buffer := external()\ncopy(buffer, r.FormValue("q"))',
            'buffer := make([]byte, 8)\n'
            "copy(buffer[:'\\x01'], os.Getenv(\"UBS_COPY_INPUT\"))",
            'buffer := make([]byte, 8)\ncopy(buffer, r.FormValue("q"))',
            'source, _ := io.ReadAll(strings.NewReader("fixed"))\nalias := source\n'
            'alias[0] = r.FormValue("q")[0]\nbuffer := make([]byte, 5)\n'
            'copy(buffer, source)\ndb.Query(string(buffer))',
            'source, _ := io.ReadAll(strings.NewReader("fixed"))\nalias := source\n'
            'alias[0] = r.FormValue("q")[0]\nbuffer := make([]byte, 5)\n'
            'copy(buffer, string(source))\ndb.Query(string(buffer))',
            'buffer := make([]byte, 8)\nsource := r.FormValue("q")\n'
            'copy(func() []byte { source = "fixed"; return buffer }(), source)',
            'buffer := make([]byte, 8)\nsource := r.FormValue("q")\n'
            'copy(buffer[index():], source)',
            'buffer := make([]byte, 8)\nexternal.Mutate(buffer)\ncopy(buffer, r.FormValue("q"))',
            'buffer := make([]byte, 8)\nreader := bytes.NewReader(buffer)\n'
            'copy(buffer, r.FormValue("q"))',
            'buffer := make([]byte, 8)\nsource := make([]byte, 8)\nexternal.Mutate(source)\n'
            'copy(buffer, source)',
            'buffer := make([]byte, 8)\ndefer copy(buffer, r.FormValue("q"))',
            'buffer := make([]byte, 8)\ngo copy(buffer, r.FormValue("q"))',
        ):
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'buffer'):
                self.check_scan(body, imports='import ("bytes"; "io"; "strings"; "os")')

    def test_copy_boundary_preserves_findings_reached_before_it(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', 'package app\nfunc h() {\n'
                    'db.Query(r.FormValue("before"))\n'
                    'buffer := external()\ncopy(buffer, r.FormValue("q"))\n}\n')
        findings = []
        with self.assertRaisesRegex(AnalysisLimit, 'buffer'):
            for finding in packages.taint_go.run(packages.RunContext(lang='go', files=list(self.sources.values()))):
                findings.append(finding)
        self.assertEqual([(finding['line'], finding['rule']) for finding in findings],
                         [(3, 'go.taint.sql')], findings)

    def test_copy_untracked_buffer_conversion_cannot_create_clean_content_proof(self):
        from ubs_core.taint_flow import AnalysisLimit

        for source in ('[]byte(string(raw))', 'snapshot'):
            with self.subTest(source=source), self.assertRaisesRegex(AnalysisLimit, 'buffer'):
                self.check_scan('raw, _ := io.ReadAll(strings.NewReader("fixed"))\n'
                                'alias := raw\nalias[0] = os.Getenv("QUERY")[0]\n'
                                'snapshot := []byte(string(raw))\nbuffer := make([]byte, 8)\n'
                                'copy(buffer, ' + source + ')\ndb.Query(string(buffer))',
                                imports='import ("io"; "strings"; "os")')

    @unittest.skipUnless(os.environ.get('UBS_GO_COPY_NATIVE') == '1',
                         'set UBS_GO_COPY_NATIVE=1 for real Go copy witnesses')
    def test_copy_native_witness_matches_alias_overlap_count_and_rune_slices(self):
        source = textwrap.dedent(r'''
            package main
            import ("encoding/json"; "io"; "os"; "fmt"; "strings")
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string) { db.Queries = append(db.Queries, query) }
            func move(destination []byte, source []byte) int { return copy(destination, source) }
            func relay(destination []byte, source []byte) int { return move(destination, source) }
            func main() {
                db := &Recorder{}
                buffer := []byte("12345678")
                snapshot := string(buffer)
                n := copy(buffer, os.Getenv("UBS_GO_BUFFERED_INPUT"))
                db.Query(string(buffer)) // payload
                db.Query(snapshot)
                db.Query(fmt.Sprint(n))
                alias := buffer[1:5]
                copy(alias, "x")
                db.Query(string(buffer)) // short-alias
                overlap := copy(buffer[1:], buffer)
                db.Query(string(buffer)) // overlapping
                db.Query(fmt.Sprint(overlap))
                copy(buffer, "z")
                db.Query(string(buffer)) // suffix
                runeBuffer := make([]byte, 2)
                runeAlias := runeBuffer[:'\x01']
                copy(runeAlias, os.Getenv("UBS_GO_BUFFERED_INPUT"))
                db.Query(string(runeBuffer)) // rune-copy
                input := make([]byte, 8)
                io.ReadFull(os.Stdin, input)
                destination := make([]byte, 8)
                count := relay(destination, input)
                db.Query(string(destination)) // helper
                db.Query(fmt.Sprint(count))
                readBuffer := make([]byte, 2)
                readAlias := readBuffer[:'\x01']
                io.ReadFull(strings.NewReader(os.Getenv("UBS_GO_BUFFERED_INPUT")), readAlias)
                db.Query(string(readBuffer)) // rune-read
                emptyCount := copy(buffer[:0], os.Getenv("UBS_GO_BUFFERED_INPUT"))
                noSource := copy(buffer, "")
                db.Query(fmt.Sprint(emptyCount, ":", noSource))
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        BufferedReaderFlowTests.run_native_reader(
            self, source, ['<supplie', '12345678', '8', '<xupplie', '<<xuppli', '7',
                           'z<xuppli', '<\0', '<stdin>\n', '8', '<\0', '0:0'])
        findings = self.scan()
        markers = ('payload', 'short-alias', 'overlapping', 'suffix', 'rune-copy', 'helper', 'rune-read')
        expected = sorted((number, line.index('db.Query') + 1, 'go.taint.sql')
                          for number, line in enumerate(source.splitlines(), 1)
                          if any('// ' + marker in line for marker in markers))
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings), expected, findings)

    def test_string_scan_family_uses_input_slot_and_keeps_metadata_clean(self):
        for operation, arguments in [('Sscan', 'input, &value'), ('Sscanln', 'input, &value'),
                                     ('Sscanf', 'input, "%s", &value')]:
            with self.subTest(operation=operation):
                self.check_scan('input := r.FormValue("query")\nvar value string\n'
                                'n, err := fmt.' + operation + '(' + arguments + ')\n'
                                'db.Query(value) // query\nfmt.Fprint(w, n, err)',
                                [('query', 'sql', 'db.Query')])

    def test_reader_scan_family_tracks_bodies_and_native_stdin(self):
        for operation, separator in [('Fscan', ''), ('Fscanln', ''), ('Fscanf', '"%s", ')]:
            for reader in ('r.Body', 'os.Stdin', 'strings.NewReader(r.FormValue("query"))'):
                with self.subTest(operation=operation, reader=reader):
                    self.check_scan('var value string\nn, err := fmt.' + operation + '(' + reader + ', '
                                    + separator + '&value)\ndb.Query(value) // query\nfmt.Fprint(w, n, err)',
                                    [('query', 'sql', 'db.Query')],
                                    imports='import ("fmt"; "os"; "strings")')

    def test_fixed_input_and_safe_bound_queries_stay_clean(self):
        self.check_scan('''
            var a, b, c string
            fmt.Sscan("fixed", &a)
            fmt.Sscanf("fixed", "%s", &b)
            fmt.Fscan(strings.NewReader("fixed"), &c)
            db.Query(a)
            db.Query(b)
            db.Query(c)
            fmt.Scan(&a)
            db.Query("SELECT $1", a)
            fmt.Fprint(w, html.EscapeString(a))
            exec.Command("printf", "%s", a)
        ''')

    def test_reader_body_aliases_preserve_contents(self):
        self.check_scan('''
            body := request.Body
            alias := body
            var value string
            fmt.Fscan(alias, &value)
            db.Query(value) // query
        ''', [('query', 'sql', 'db.Query')])

    def test_saved_callable_alias_parentheses_and_dot_imports(self):
        self.check_scan('''
            var value string
            read := input.Sscanf
            saved := read
            n, err := ((saved))(r.FormValue("q"), "%s", &value)
            db.Query(value) // query
            fmt.Fprint(w, n, err)
        ''', [('query', 'sql', 'db.Query')], imports='import input "fmt"')
        self.check_scan('var value string\nScanln(&value)\ndb.Query(value) // query',
                        [('query', 'sql', 'db.Query')], imports='import . "fmt"')

    def test_pointers_branches_literal_kills_and_value_copies(self):
        self.check_scan('''
            first, second := "first", "second"
            before := first
            out := &first
            if choice { out = &second }
            fmt.Scan(out)
            db.Query(first) // first
            db.Query(second) // second
            db.Query(before)
            first = "fixed"
            db.Query(first)
        ''', [('first', 'sql', 'db.Query'), ('second', 'sql', 'db.Query')])

    def test_byte_slice_and_new_string_destinations(self):
        self.check_scan('''
            var bytes []byte
            text := new(string)
            fmt.Scan(&bytes, text)
            db.Query(string(bytes)) // bytes
            db.Query(*text) // text
        ''', [('bytes', 'sql', 'db.Query'), ('text', 'sql', 'db.Query')])

    def test_selected_helper_pointer_effects_and_captured_calls(self):
        self.check_scan('''
            var value string
            parse(r.FormValue("q"), &value)
            db.Query(value) // helper
            value = "fixed"
            read := fmt.Scan
            func() { read(&value) }()
            db.Query(value) // captured
        ''', [('helper', 'sql', 'db.Query'), ('captured', 'sql', 'db.Query')], helpers='''
            func parse(input string, out *string) (int, error) {
                return fmt.Sscan(input, out)
            }
        ''')

    def test_failed_or_partial_clean_scan_does_not_erase_prior_value(self):
        self.check_scan('''
            var value string = r.FormValue("q")
            fmt.Sscan("", &value)
            db.Query(value) // preserved
        ''', [('preserved', 'sql', 'db.Query')])

    def test_text_token_scan_preserves_domain_specific_sanitization(self):
        self.check_scan('''
            var value string
            fmt.Sscan(html.EscapeString(r.FormValue("q")), &value)
            fmt.Fprint(w, value)
            db.Query(value) // sql
            exec.Command("sh", "-c", value) // command
        ''', [('sql', 'sql', 'db.Query'), ('command', 'command', 'exec.Command')])

    def test_import_lookalikes_and_shadowed_scanners_do_not_invent_stdin(self):
        self.check_scan('var value string\nfmt.Scan(&value)\ndb.Query(value)',
                        imports='import fmt "example.test/format"')
        self.check_scan('var value string\nfmt := formatter\nfmt.Scan(&value)\ndb.Query(value)')
        self.check_scan('''
            var value string
            Scan := func(out *string) (int, error) { return 0, nil }
            Scan(&value)
            db.Query(value)
        ''', imports='import . "fmt"')

    def test_unused_callable_and_no_destination_calls_are_not_sources(self):
        self.check_scan('''
            read := fmt.Scan
            fmt.Fprint(w, read)
            count, err := fmt.Scan()
            fmt.Fprint(w, count, err)
            count, err = fmt.Sscan(r.FormValue("q"))
            fmt.Fprint(w, count, err)
        ''')

    def test_unknown_scanner_reader_and_destination_lists_are_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit
        cases = (
            'var value CustomScanner\nfmt.Scan(&value)',
            'value := wrap(r.FormValue("q"))\nfmt.Scan(&value)',
            'value := r.FormValue("q")\nfmt.Scan(&value)',
            'var value int\nfmt.Scan(&value)\nfmt.Fprint(w, string(value))',
            'var value Payload\nfmt.Scan(&value.SQL)',
            'var value string\nfmt.Fscan(customReader, &value)',
            'var value string\nfmt.Fscan(customReader(r.Body), &value)',
            'var value string\nvalues := []any{&value}\nfmt.Scan(values...)',
            'var value string\nread := fmt.Scan\nif custom { read = callbacks.Scan }\nread(&value)',
            'var value string\ngo func() { fmt.Scan(&value) }()\ndb.Query(value)',
        )
        for body in cases:
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'formatted input'):
                self.check_scan(body)

    def test_encoded_and_dynamic_formats_do_not_grant_sanitizer_proof(self):
        from ubs_core.taint_flow import AnalysisLimit
        for format_expression in ('"%q"', '"%x"', 'r.FormValue("format")'):
            with self.subTest(format_expression=format_expression):
                with self.assertRaisesRegex(AnalysisLimit, 'formatted input'):
                    self.check_scan('var value string\nfmt.Sscanf(html.EscapeString(r.FormValue("q")), '
                                    + format_expression + ', &value)\nfmt.Fprint(w, value)')

    def test_source_capability_storage_and_argument_replacement_are_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit
        cases = (
            'scans := []func(...any) (int, error){fmt.Scan}\nvar value string\n'
            'scans[0](&value)\ndb.Query(value)',
            'var holder Holder\nholder.scan = fmt.Scan\nvar value string\n'
            'holder.scan(&value)\ndb.Query(value)',
            'var value string\nscan := fmt.Scan\nscan(func() *string { '
            'scan = callbacks.Scan; return &value }())\ndb.Query(value)',
        )
        for body in cases:
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'formatted input'):
                self.check_scan(body)
        with self.assertRaisesRegex(AnalysisLimit, 'formatted input'):
            self.check_scan('read()\ndb.Query(value)', helpers='''
                var value string
                func read() { fmt.Scan(&value) }
            ''')

    def test_shadowed_builtin_type_names_do_not_prove_plain_destinations(self):
        from ubs_core.taint_flow import AnalysisLimit
        for declaration, typename in [('type string Custom', 'string'),
                                      ('type string = Custom', 'string'),
                                      ('type byte Custom', '[]byte'),
                                      ('type uint8 Custom', '[]uint8')]:
            for local in (False, True):
                with self.subTest(declaration=declaration, local=local):
                    with self.assertRaisesRegex(AnalysisLimit, 'formatted input'):
                        self.check_scan((declaration + '\n' if local else '')
                                        + 'var value ' + typename + '\nfmt.Scan(&value)',
                                        helpers='' if local else declaration)

    @unittest.skipUnless(os.environ.get('UBS_GO_SCAN_NATIVE') == '1',
                         'set UBS_GO_SCAN_NATIVE=1 for the real Go compiler witness')
    def test_native_scan_writes_match_real_go_inputs_and_safe_controls(self):
        from test_keep_temp import prevent_child_deletion

        source = textwrap.dedent('''
            package main
            import ("fmt"; "strings"; "os"; "encoding/json")
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string, args ...any) { db.Queries = append(db.Queries, query) }
            func parse(input string, out *string) (int, error) { return fmt.Sscan(input, out) }
            func main() {
                db := &Recorder{}
                var direct, supplied, read, viaHelper string
                count, err := fmt.Scan(&direct)
                if err != nil || count != 1 { panic("stdin scan failed") }
                db.Query(direct) // direct
                saved := fmt.Sscanf
                count, err = saved(os.Getenv("UBS_GO_SCAN_INPUT"), "%s", &supplied)
                if err != nil || count != 1 { panic("string scan failed") }
                db.Query(supplied) // supplied
                fmt.Fscan(strings.NewReader(os.Getenv("UBS_GO_SCAN_INPUT")), &read)
                db.Query(read) // read
                parse(os.Getenv("UBS_GO_SCAN_INPUT"), &viaHelper)
                db.Query(viaHelper) // helper
                db.Query("SELECT $1", direct)
                direct = "fixed"
                fmt.Sscan("", &direct)
                db.Query(direct)
                var constant string
                fmt.Sscanf("constant", "%s", &constant)
                db.Query(constant)
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        path = self.source('main.go', source)
        executable = self.root / 'scan-witness'
        environment = dict(os.environ, GO111MODULE='off', GOWORK='off', GOTOOLCHAIN='local',
                           UBS_GO_SCAN_INPUT='<supplied>')
        compiler = os.environ.get('UBS_GO_COMPILER', 'go')
        build = subprocess.run([compiler, 'build', '-work', '-o', str(executable), str(path)],
                               cwd=self.root, env=environment, capture_output=True, text=True,
                               timeout=180, preexec_fn=prevent_child_deletion)
        (self.root / 'build.stdout.log').write_text(build.stdout)
        (self.root / 'build.stderr.log').write_text(build.stderr)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        result = subprocess.run([str(executable)], input='<stdin>\n', cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=30, preexec_fn=prevent_child_deletion)
        (self.root / 'native.stdout.log').write_text(result.stdout)
        (self.root / 'native.stderr.log').write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         ['<stdin>', '<supplied>', '<supplied>', '<supplied>', 'SELECT $1', 'fixed', 'constant'])
        findings = self.scan()
        expected = sorted((number, line.index('db.Query') + 1, 'go.taint.sql')
                          for number, line in enumerate(source.splitlines(), 1)
                          if any('// ' + marker in line for marker in ('direct', 'supplied', 'read', 'helper')))
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings), expected, findings)


class BufferedReaderFlowTests(packages.PackageTestCase):
    def check_readers(self, body, markers=(), helpers=''):
        source = ('package app\nimport ("bufio"; "bytes"; "strings"; "os"; "io"; "fmt"; '
                  '"encoding/json"; "encoding/xml"; "os/exec")\nfunc h() {\n'
                  + textwrap.dedent(body) + '\n}\n')
        self.source('handler.go', source)
        if helpers:
            self.source('helpers.go', 'package app\nimport ("bufio"; "strings"; "io")\n' + helpers)
        expected = []
        for marker, rule in markers:
            lines = [(number, line) for number, line in enumerate(source.splitlines(), 1)
                     if '// ' + marker in line]
            self.assertEqual(len(lines), 1, (marker, source))
            number, line = lines[0]
            sink = {'sql': 'db.Query', 'xss': 'fmt.Fprint', 'command': 'exec.Command'}[rule]
            expected.append((number, line.index(sink) + 1, 'go.taint.' + rule))
        findings = self.scan()
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings),
                         sorted(expected), findings)
        return findings

    def test_scanner_scan_changes_tokens_but_keeps_boolean_error_and_early_text_clean(self):
        self.check_readers('''
            scanner := bufio.NewScanner(os.Stdin)
            db.Query(scanner.Text())
            db.Query(string(scanner.Bytes()))
            alias := scanner
            ok := alias.Scan()
            db.Query(scanner.Text()) // text
            exec.Command("sh", "-c", string(alias.Bytes())) // command
            fmt.Fprint(w, ok, scanner.Err())
        ''', (('text', 'sql'), ('command', 'command')))

    def test_scanner_loop_and_saved_bound_methods_share_native_state(self):
        self.check_readers('''
            scanner := bufio.NewScanner(r.Body)
            text := scanner.Text
            read := scanner.Scan
            db.Query(text())
            for read() {
                db.Query(text()) // query
            }
        ''', (('query', 'sql'),))

    def test_fixed_scanner_and_buffer_capacity_do_not_introduce_token_provenance(self):
        self.check_readers('''
            scanner := bufio.NewScanner(strings.NewReader("fixed"))
            scanner.Buffer([]byte(r.FormValue("buffer")), len(r.FormValue("size")))
            scanner.Scan()
            db.Query(scanner.Text())
            fmt.Fprint(w, scanner.Bytes(), scanner.Err())
        ''')

    def test_textual_readers_preserve_payload_and_separate_metadata_results(self):
        cases = (('ReadString(10)', 'value, err', 'err'),
                 ('ReadBytes(10)', 'value, err', 'err'),
                 ('ReadSlice(10)', 'value, err', 'err'),
                 ('Peek(8)', 'value, err', 'err'),
                 ('ReadLine()', 'value, prefix, err', 'prefix, err'),
                 ('ReadByte()', 'value, err', 'err'),
                 ('ReadRune()', 'value, size, err', 'size, err'))
        for operation, targets, metadata in cases:
            with self.subTest(operation=operation):
                self.check_readers('reader := bufio.NewReader(os.Stdin)\n'
                                   + targets + ' := reader.' + operation + '\n'
                                   'db.Query(string(value)) // query\n'
                                   'fmt.Fprint(w, ' + metadata + ', reader.Size(), reader.Buffered())',
                                   (('query', 'sql'),))

    def test_native_import_aliases_and_saved_constructors_are_source_aware(self):
        source = '''package app
import (b "bufio"; o "os"; s "strings")
func h() {
    input := o.Stdin
    factory := b.NewReaderSize
    reader := factory(input, 4096)
    read := reader.ReadString
    text, err := read(10)
    db.Query(text)
    db.Query(err.Error())
    fixed := factory(s.NewReader("fixed"), len(o.Getenv("SIZE")))
    safe, _ := fixed.ReadString(10)
    db.Query(safe)
}
'''
        self.source('handler.go', source)
        findings = self.scan()
        self.assertEqual([(row['rule'], row['line'], row['col']) for row in findings],
                         [('go.taint.sql', 9, 5)], findings)

    def test_stdin_reader_capability_feeds_readall_decoders_and_formatted_input(self):
        self.check_readers('''
            input := os.Stdin
            raw, err := io.ReadAll(input)
            db.Query(string(raw)) // raw
            var decoded, scanned string
            json.NewDecoder(input).Decode(&decoded)
            db.Query(decoded) // decoded
            reader := bufio.NewReader(input)
            count, scanErr := fmt.Fscan(reader, &scanned)
            db.Query(scanned) // scanned
            fmt.Fprint(w, err, count, scanErr)
        ''', (('raw', 'sql'), ('decoded', 'sql'), ('scanned', 'sql')))

    def test_stdin_alias_keeps_its_source_after_the_original_reader_is_replaced(self):
        self.check_readers('''
            var input io.Reader = os.Stdin
            saved := input
            input = strings.NewReader("fixed")
            fixed, _ := io.ReadAll(input)
            original, _ := io.ReadAll(saved)
            db.Query(string(fixed))
            db.Query(string(original)) // query
        ''', (('query', 'sql'),))

    def test_saved_method_keeps_its_original_receiver_after_rebinding(self):
        self.check_readers('''
            reader := bufio.NewReader(os.Stdin)
            read := reader.ReadString
            reader = bufio.NewReader(strings.NewReader("fixed"))
            original, _ := read(10)
            fixed, _ := reader.ReadString(10)
            db.Query(original) // query
            db.Query(fixed)
        ''', (('query', 'sql'),))

    def test_json_buffered_reader_retains_its_input_and_clean_read_error(self):
        self.check_readers('''
            decoder := json.NewDecoder(os.Stdin)
            var value string
            decoder.Decode(&value)
            remaining := decoder.Buffered()
            raw, err := io.ReadAll(remaining)
            db.Query(string(raw)) // query
            fmt.Fprint(w, err)
        ''', (('query', 'sql'),))

    def test_reader_backed_unknown_readall_alternative_cannot_borrow_clean_error_contract(self):
        self.check_readers('''
            read := io.ReadAll
            if choice { read = customRead }
            data, err := read(strings.NewReader(os.Getenv("TEXT")))
            db.Query(string(data)) // data
            db.Query(err.Error()) // error
        ''', (('data', 'sql'), ('error', 'sql')))

    def test_native_readers_reach_all_existing_sinks(self):
        self.check_readers('''
            reader := bufio.NewReader(strings.NewReader(os.Getenv("TEXT")))
            value, err := reader.ReadString(10)
            db.Query(value) // query
            fmt.Fprint(w, value) // html
            exec.Command("sh", "-c", value) // command
            db.Query("SELECT $1", value)
            fmt.Fprint(w, err)
        ''', (('query', 'sql'), ('html', 'xss'), ('command', 'command')))

    def test_bytes_buffer_contents_and_counts_have_distinct_meaning(self):
        self.check_readers('''
            buffer := bytes.NewBufferString(r.FormValue("text"))
            db.Query(buffer.String()) // text
            db.Query(string(buffer.Bytes())) // bytes
            fmt.Fprint(w, buffer.Len(), buffer.Cap(), buffer.Available())
            fixed := bytes.NewBuffer([]byte("fixed"))
            db.Query(fixed.String())
        ''', (('text', 'sql'), ('bytes', 'sql')))

    def test_helper_factory_returns_input_capability_with_distinct_allocations(self):
        self.check_readers('''
            first := makeScanner("fixed")
            second := makeScanner(os.Getenv("TEXT"))
            first.Scan()
            db.Query(second.Text())
            second.Scan()
            db.Query(second.Text()) // query
            db.Query(first.Text())
        ''', (('query', 'sql'),), helpers='''
func makeScanner(value string) *bufio.Scanner {
    return bufio.NewScanner(strings.NewReader(value))
}
''')

    def test_helper_scan_effect_reaches_original_scanner_and_returned_alias(self):
        self.check_readers('''
            scanner := bufio.NewScanner(os.Stdin)
            alias := identity(scanner)
            advance(alias)
            db.Query(scanner.Text()) // query
        ''', (('query', 'sql'),), helpers='''
func identity(scanner *bufio.Scanner) *bufio.Scanner { return scanner }
func advance(scanner *bufio.Scanner) bool { return scanner.Scan() }
''')

    def test_helper_read_and_helper_wrapping_use_symbolic_reader_contents(self):
        self.check_readers('''
            reader := wrap(os.Stdin)
            value, err := read(reader)
            db.Query(value) // query
            fmt.Fprint(w, err)
            fixed, _ := read(wrap(strings.NewReader("fixed")))
            db.Query(fixed)
        ''', (('query', 'sql'),), helpers='''
func wrap(reader io.Reader) *bufio.Reader { return bufio.NewReader(reader) }
func read(reader *bufio.Reader) (string, error) { return reader.ReadString(10) }
''')

    def test_native_consumers_wait_for_selected_reader_factory_summaries(self):
        self.check_readers('''
            raw, err := io.ReadAll(open())
            db.Query(string(raw)) // readall
            reader := bufio.NewReader(open())
            value, _ := reader.ReadString(10)
            db.Query(value) // reader
            scanner := bufio.NewScanner(open())
            scanner.Scan()
            db.Query(scanner.Text()) // scanner
            var decoded string
            json.NewDecoder(open()).Decode(&decoded)
            db.Query(decoded) // decoder
            fmt.Fprint(w, err)
        ''', (('readall', 'sql'), ('reader', 'sql'), ('scanner', 'sql'), ('decoder', 'sql')),
                           helpers='func open() io.Reader { return strings.NewReader(r.FormValue("body")) }\n')

    def test_selected_factory_that_resolves_to_custom_reader_remains_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit
        with self.assertRaisesRegex(AnalysisLimit, 'custom reader'):
            self.check_readers('raw, _ := io.ReadAll(open())\ndb.Query(string(raw))',
                               helpers='func open() io.Reader { return external() }\n')

    def test_immediate_closure_scan_preserves_capture_and_argument_aliases(self):
        self.check_readers('''
            scanner := bufio.NewScanner(os.Stdin)
            func(other *bufio.Scanner) { other.Scan() }(scanner)
            db.Query(scanner.Text()) // query
        ''', (('query', 'sql'),))

    def test_immediate_closure_can_replace_a_reader_without_replacing_its_old_alias(self):
        self.check_readers('''
            scanner := bufio.NewScanner(strings.NewReader("fixed"))
            previous := scanner
            func() { scanner = bufio.NewScanner(os.Stdin) }()
            scanner.Scan()
            previous.Scan()
            db.Query(scanner.Text()) // query
            db.Query(previous.Text())
        ''', (('query', 'sql'),))

    def test_supported_native_split_choices_preserve_only_the_reader_input(self):
        for split in ('ScanLines', 'ScanWords', 'ScanBytes', 'ScanRunes'):
            with self.subTest(split=split):
                self.check_readers('scanner := bufio.NewScanner(os.Stdin)\n'
                                   'split := bufio.' + split + '\nscanner.Split(split)\n'
                                   'scanner.Scan()\ndb.Query(scanner.Text()) // query', (('query', 'sql'),))

    def test_unknown_reader_protocols_and_mutations_are_explicit(self):
        from ubs_core.taint_flow import AnalysisLimit
        bodies = (
            'scanner := bufio.NewScanner(customReader)\nscanner.Scan()',
            'data, _ := io.ReadAll(customReader)\ndb.Query(string(data))',
            'data, _ := io.ReadAll(external())\ndb.Query(string(data))',
            'var value string\njson.NewDecoder(customReader).Decode(&value)\ndb.Query(value)',
            'var value string\nxml.NewDecoder(external()).Decode(&value)\ndb.Query(value)',
            'scanner := bufio.NewScanner(os.Stdin)\nscanner.Split(customSplit)',
            'reader := bufio.NewReader(os.Stdin)\nreader.Reset(strings.NewReader("fixed"))',
            'reader := bufio.NewReader(os.Stdin)\nreader.Read(destination)',
            'os.Stdin.Read(destination)',
            'r.Body.Read(destination)',
            'scanner := bufio.NewScanner(os.Stdin)\nif choice { scanner = custom }\nscanner.Scan()',
            'factory := bufio.NewScanner\nif choice { factory = customFactory }\nfactory(os.Stdin)',
            'scanner := bufio.NewScanner(os.Stdin)\ndefer func() { scanner.Scan() }()',
            'reader := bufio.NewReader(os.Stdin)\nexternal(reader)',
            'reader := bufio.NewReader(os.Stdin)\nexternal(&reader)',
            'reader := bufio.NewReader(os.Stdin)\nvalues := []io.Reader{reader}',
            'values := []io.Reader{bufio.NewReader(os.Stdin)}',
            'scanner := bufio.NewScanner(os.Stdin)\ncallback := func() { db.Query(scanner.Text()) }',
        )
        for body in bodies:
            with self.subTest(body=body), self.assertRaisesRegex(AnalysisLimit, 'reader|scanner'):
                self.check_readers(body)

    def test_reader_output_parameter_replacement_remains_explicit(self):
        from ubs_core.taint_flow import AnalysisLimit
        self.source('helper.go', 'package app\nimport ("bufio"; "os")\n'
                    'func replace(out **bufio.Scanner) { *out = bufio.NewScanner(os.Stdin) }\n')
        with self.assertRaisesRegex(AnalysisLimit, 'reader output-parameter'):
            self.scan()

    def test_unimported_and_local_lookalike_reader_constructors_have_no_native_authority(self):
        from ubs_core.taint_flow import AnalysisLimit
        bodies = (
            '''package app
import codec "encoding/json"
func h() {
    var value string
    codec.NewDecoder(strings.NewReader(`"fixed"`)).Decode(&value)
    db.Query(value)
}
''',
            '''package app
import ("encoding/json"; "io"; "bytes"; "os")
type customFactory struct{}
func (customFactory) NewReader(_ string) io.Reader {
    return bytes.NewReader([]byte(os.Getenv("READER_CONTENTS")))
}
var strings = customFactory{}
func h() {
    var value string
    json.NewDecoder(strings.NewReader(`"fixed"`)).Decode(&value)
    db.Query(value)
}
''',
        )
        for source in bodies:
            with self.subTest(source=source), self.assertRaisesRegex(AnalysisLimit, 'custom reader'):
                self.source('handler.go', source)
                self.scan()

    def run_native_reader(self, source, expected):
        from test_keep_temp import prevent_child_deletion

        path = self.source('main.go', source)
        executable = self.root / 'reader-witness'
        environment = dict(os.environ, GO111MODULE='off', GOWORK='off', GOTOOLCHAIN='local',
                           UBS_GO_BUFFERED_INPUT='<supplied>')
        compiler = os.environ.get('UBS_GO_COMPILER', 'go')
        build = subprocess.run([compiler, 'build', '-work', '-o', str(executable), str(path)],
                               cwd=self.root, env=environment, capture_output=True, text=True,
                               timeout=180, preexec_fn=prevent_child_deletion)
        (self.root / 'build.stdout.log').write_text(build.stdout)
        (self.root / 'build.stderr.log').write_text(build.stderr)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        result = subprocess.run([str(executable)], input='<stdin>\n', cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=30, preexec_fn=prevent_child_deletion)
        (self.root / 'native.stdout.log').write_text(result.stdout)
        (self.root / 'native.stderr.log').write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), expected)
        return path

    @unittest.skipUnless(os.environ.get('UBS_GO_BUFFERED_NATIVE') == '1',
                         'set UBS_GO_BUFFERED_NATIVE=1 for real Go buffered-reader witnesses')
    def test_native_reader_tokens_bound_methods_and_helper_state_match_source_findings(self):
        source = textwrap.dedent('''
            package main
            import ("bufio"; "os"; "strings"; "encoding/json"; "io"; "strconv"; "fmt")
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string) { db.Queries = append(db.Queries, query) }
            func makeScanner(value string) *bufio.Scanner { return bufio.NewScanner(strings.NewReader(value)) }
            func advance(scanner *bufio.Scanner) bool { return scanner.Scan() }
            func main() {
                db := &Recorder{}
                scanner := bufio.NewScanner(os.Stdin)
                db.Query(scanner.Text())
                next, token := scanner.Scan, scanner.Text
                scanner = bufio.NewScanner(strings.NewReader("fixed"))
                next()
                db.Query(token()) // stdin
                scanner.Scan()
                db.Query(scanner.Text())
                first := makeScanner("fixed")
                second := makeScanner(os.Getenv("UBS_GO_BUFFERED_INPUT"))
                advance(first)
                db.Query(second.Text())
                advance(second)
                db.Query(second.Text()) // helper
                reader := bufio.NewReader(strings.NewReader(os.Getenv("UBS_GO_BUFFERED_INPUT") + "\\n"))
                read := reader.ReadString
                reader = bufio.NewReader(strings.NewReader("fixed\\n"))
                value, err := read(10)
                db.Query(value) // reader
                db.Query(fmt.Sprint(err))
                db.Query(strconv.Itoa(reader.Buffered()))
                raw, readErr := io.ReadAll(strings.NewReader(os.Getenv("UBS_GO_BUFFERED_INPUT")))
                if readErr != nil { panic(readErr) }
                db.Query(string(raw)) // readall
                var decoded string
                json.NewDecoder(strings.NewReader(strconv.Quote(os.Getenv("UBS_GO_BUFFERED_INPUT")))).Decode(&decoded)
                db.Query(decoded) // decoder
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        self.run_native_reader(source, ['', '<stdin>', 'fixed', '', '<supplied>', '<supplied>\n',
                                        '<nil>', '0', '<supplied>', '<supplied>'])
        expected = sorted((number, line.index('db.Query') + 1, 'go.taint.sql')
                          for number, line in enumerate(source.splitlines(), 1)
                          if any('// ' + marker in line for marker in ('stdin', 'helper', 'reader', 'readall', 'decoder')))
        findings = self.scan()
        self.assertEqual(sorted((row['line'], row['col'], row['rule']) for row in findings), expected, findings)

    @unittest.skipUnless(os.environ.get('UBS_GO_BUFFERED_NATIVE') == '1',
                         'set UBS_GO_BUFFERED_NATIVE=1 for real Go buffered-reader witnesses')
    def test_native_local_lookalike_reader_can_supply_external_data(self):
        from ubs_core.taint_flow import AnalysisLimit

        source = textwrap.dedent('''
            package main
            import ("encoding/json"; "io"; "os"; standard "strings")
            type customFactory struct{}
            func (customFactory) NewReader(_ string) io.Reader {
                return standard.NewReader(os.Getenv("UBS_GO_BUFFERED_INPUT"))
            }
            var strings = customFactory{}
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string) { db.Queries = append(db.Queries, query) }
            func main() {
                db := &Recorder{}
                raw, err := io.ReadAll(strings.NewReader("fixed"))
                if err != nil { panic(err) }
                db.Query(string(raw))
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        self.run_native_reader(source, ['<supplied>'])
        with self.assertRaisesRegex(AnalysisLimit, 'custom reader'):
            self.scan()


class BufferedReaderCacheTests(packages.PackageTestCase):
    scan_main = packages.PackageCacheTests.scan_main

    def test_copy_helper_edit_invalidates_warm_selected_package(self):
        helper = self.source('helper.go', 'package app\nimport "os"\n'
                             'func move(buffer []byte) { copy(buffer, "fixed") }\n')
        handler = self.source('handler.go', 'package app\nfunc h() {\n'
                              'buffer := make([]byte, 8)\nmove(buffer)\n'
                              'db.Query(string(buffer))\n}\n')
        (self.root / 'unselected.go').write_text('package app\nimport "os"\n'
                                              'func unselected() { db.Query(os.Getenv("SQL")) }\n')
        self.assertEqual(self.scan_main()[0], [])
        warm, stats = self.scan_main()
        self.assertEqual(warm, [])
        self.assertEqual(stats['hits'], 2, stats)
        self.source('helper.go', 'package app\nimport "os"\n'
                    'func move(buffer []byte) { copy(buffer, os.Getenv("SQL")) }\n')
        changed, stats = self.scan_main()
        self.assertEqual([(Path(row['path']).name, row['line'], row['col'], row['rule']) for row in changed],
                         [('handler.go', 5, 1, 'go.taint.sql')], changed)
        self.assertEqual(stats['misses'], 2, stats)
        self.assertEqual(self.scan_main([helper])[0], [])
        self.assertEqual(self.scan_main([helper, handler])[0], changed)

    def test_readinto_reader_factory_edit_invalidates_warm_selected_package(self):
        helper = self.source('helper.go', 'package app\nimport ("strings"; "io")\n'
                             'func open() io.Reader { return strings.NewReader("fixed") }\n')
        handler = self.source('handler.go', 'package app\nimport "io"\nfunc h() {\n'
                              'buffer := make([]byte, 8)\nio.ReadFull(open(), buffer)\n'
                              'db.Query(string(buffer))\n}\n')
        (self.root / 'unselected.go').write_text('package app\nimport "os"\n'
                                              'func unselected() { db.Query(os.Getenv("SQL")) }\n')
        self.assertEqual(self.scan_main()[0], [])
        warm, stats = self.scan_main()
        self.assertEqual(warm, [])
        self.assertEqual(stats['hits'], 2, stats)
        self.source('helper.go', 'package app\nimport ("os"; "io")\n'
                    'func open() io.Reader { return os.Stdin }\n')
        changed, stats = self.scan_main()
        self.assertEqual([(Path(row['path']).name, row['line'], row['col'], row['rule']) for row in changed],
                         [('handler.go', 6, 1, 'go.taint.sql')], changed)
        self.assertEqual(stats['misses'], 2, stats)
        self.assertEqual(self.scan_main([helper])[0], [])
        self.assertEqual(self.scan_main([helper, handler])[0], changed)

    def test_reader_factory_changes_invalidate_warm_package_findings(self):
        helper = self.source('helper.go', 'package app\nimport ("strings"; "io")\n'
                             'func open() io.Reader { return strings.NewReader("fixed") }\n')
        handler = self.source('handler.go', 'package app\nimport "io"\n'
                              'func h() { raw, _ := io.ReadAll(open()); db.Query(string(raw)) }\n')
        (self.root / 'unselected.go').write_text('package app\nimport "os"\n'
                                              'func unselected() { db.Query(os.Getenv("SQL")) }\n')
        self.assertEqual(self.scan_main()[0], [])
        warm, stats = self.scan_main()
        self.assertEqual(warm, [])
        self.assertEqual(stats['hits'], 2, stats)
        self.source('helper.go', 'package app\nimport ("os"; "io")\n'
                    'func open() io.Reader { return os.Stdin }\n')
        changed, stats = self.scan_main()
        self.assertEqual([(Path(row['path']).name, row['line'], row['col'], row['rule']) for row in changed],
                         [('handler.go', 3, 42, 'go.taint.sql')], changed)
        self.assertEqual(stats['misses'], 2, stats)
        self.assertEqual(self.scan_main([helper])[0], [])
        self.assertEqual(self.scan_main([helper, handler])[0], changed)


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1',
                     'set UBS_TAINT_E2E=1 for real Go buffered-reader reports')
class BufferedReaderModuleTests(unittest.TestCase):
    def test_public_unsafe_and_metadata_reports(self):
        self.check_public_cases(0, 4)

    def test_public_controls_and_protocol_boundaries(self):
        self.check_public_cases(4, 8)

    def test_public_readinto_unsafe_and_metadata_reports(self):
        self.check_public_cases(8, 12)

    def test_public_readinto_controls_suppression_and_partial_findings(self):
        self.check_public_cases(12, 16)

    def test_public_copy_unsafe_and_metadata_reports(self):
        self.check_public_cases(16, 20)

    def test_public_copy_controls_suppression_and_partial_findings(self):
        self.check_public_cases(20, 24)

    def check_public_cases(self, start, end):
        from test_keep_temp import prevent_child_deletion

        cases = (
            ('scanner', 'scanner := bufio.NewScanner(os.Stdin)\nscanner.Scan()\n'
             'db.Query(scanner.Text()) // query', True, False),
            ('reader', 'factory := bufio.NewReader\nreader := factory(os.Stdin)\n'
             'read := reader.ReadString\nvalue, err := read(10)\n'
             'db.Query(value) // query\nfmt.Fprint(w, err)', True, False),
            ('readall', 'input := os.Stdin\nvalue, err := io.ReadAll(input)\n'
             'db.Query(string(value)) // query\nfmt.Fprint(w, err)', True, False),
            ('metadata', 'scanner := bufio.NewScanner(os.Stdin)\ndb.Query(scanner.Text())\n'
             'ok := scanner.Scan()\nreader := bufio.NewReader(os.Stdin)\n'
             'fmt.Fprint(w, ok, scanner.Err(), reader.Buffered(), reader.Size())', False, False),
            ('fixed', 'scanner := bufio.NewScanner(strings.NewReader("fixed"))\n'
             'scanner.Scan()\ndb.Query(scanner.Text())', False, False),
            ('suppressed', 'scanner := bufio.NewScanner(os.Stdin)\nscanner.Scan()\n'
             'db.Query(scanner.Text()) // ubs:ignore[go.taint.sql]', False, False),
            ('custom', 'value, err := io.ReadAll(customReader)\ndb.Query(string(value))', False, True),
            ('mutation', 'reader := bufio.NewReader(os.Stdin)\nreader.Reset(strings.NewReader("fixed"))',
             False, True),
            ('readinto-full', 'buffer := make([]byte, 64)\nio.ReadFull(os.Stdin, buffer)\n'
             'db.Query(string(buffer)) // query', True, False),
            ('readinto-saved', 'buffer := make([]byte, 64)\nalias := buffer[:]\nread := io.ReadAtLeast\n'
             'read(r.Body, alias, 1)\ndb.Query(string(buffer)) // query', True, False),
            ('readinto-metadata', 'buffer := make([]byte, 64)\nn, err := io.ReadFull(r.Body, buffer)\n'
             'fmt.Fprint(w, n, err, len(buffer), cap(buffer))', False, False),
            ('readinto-bound', 'buffer := make([]byte, 64)\nio.ReadFull(r.Body, buffer)\n'
             'db.Query("SELECT $1", string(buffer))', False, False),
            ('readinto-fixed', 'buffer := []byte("fixed")\n'
             'io.ReadFull(strings.NewReader("constant"), buffer)\ndb.Query(string(buffer))', False, False),
            ('readinto-suppressed', 'buffer := make([]byte, 64)\nio.ReadFull(os.Stdin, buffer)\n'
             'db.Query(string(buffer)) // ubs:ignore[go.taint.sql]', False, False),
            ('readinto-no-read', 'empty := make([]byte, 0)\nio.ReadFull(customReader, empty)\n'
             'buffer := make([]byte, 2)\nio.ReadAtLeast(customReader, buffer, 3)\n'
             'io.ReadAtLeast(customReader, buffer, 0)\ndb.Query(string(empty))\n'
             'db.Query(string(buffer))', False, False),
            ('readinto-partial', 'db.Query(r.FormValue("prior")) // query\n'
             'buffer := make([]byte, 64)\nio.ReadFull(customReader, buffer)', True, True),
            ('copy-content', 'buffer := make([]byte, 64)\ncopy(buffer, os.Getenv("QUERY"))\n'
             'db.Query(string(buffer)) // query', True, False),
            ('copy-alias', 'buffer := make([]byte, 64)\nalias := buffer[1:]\n'
             'copy(alias, os.Getenv("QUERY"))\ndb.Query(string(buffer)) // query', True, False),
            ('copy-metadata', 'buffer := make([]byte, 64)\nn := copy(buffer, os.Getenv("QUERY"))\n'
             'fmt.Fprint(w, n, len(buffer), cap(buffer))', False, False),
            ('copy-bound', 'buffer := make([]byte, 64)\ncopy(buffer, os.Getenv("QUERY"))\n'
             'db.Query("SELECT $1", string(buffer))', False, False),
            ('copy-fixed', 'buffer := make([]byte, 8)\ncopy(buffer, "fixed")\n'
             'db.Query(string(buffer))', False, False),
            ('copy-suppressed', 'buffer := make([]byte, 64)\ncopy(buffer, os.Getenv("QUERY"))\n'
             'db.Query(string(buffer)) // ubs:ignore[go.taint.sql]', False, False),
            ('copy-empty', 'buffer := make([]byte, 8)\nvar empty []byte\n'
             'copy(buffer[:0], r.FormValue("q"))\ncopy(buffer, empty)\n'
             'db.Query(string(buffer))', False, False),
            ('copy-partial', 'db.Query(r.FormValue("prior")) // query\n'
             'buffer := external()\ncopy(buffer, r.FormValue("q"))', True, True),
        )
        artifacts = packages.ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='go-buffered-public-', dir=artifacts))
        skipped = ','.join(str(category) for category in range(1, 23) if category != 9)
        for name, body, unsafe, partial in cases[start:end]:
            folder = root / name
            folder.mkdir()
            source = ('package app\nimport ("bufio"; "os"; "io"; "strings"; "fmt")\n'
                      'func h() {\n' + body + '\n}\n')
            path = folder / 'handler.go'
            path.write_text(source)
            (folder / 'unselected.go').write_text('package app\nfunc other() { db.Query(r.FormValue("q")) }\n')
            expected = [(number, line.index('db.Query') + 1, 'go.taint.sql')
                        for number, line in enumerate(source.splitlines(), 1) if '// query' in line]
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, format=output):
                        command = [str(packages.ROOT / ('ubs' if meta else 'modules/ubs-golang.sh')),
                                   str(path), '--ci', '--no-color', '--format=' + output, '--skip=' + skipped]
                        if meta:
                            command.append('--only=golang')
                        result = subprocess.run(command, cwd=folder, capture_output=True, text=True,
                                                timeout=45, preexec_fn=prevent_child_deletion,
                                                env=dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1',
                                                         UBS_NO_CACHE='1', UBS_CACHE_DIR=str(folder / 'cache')))
                        prefix = folder / f'{meta}-{output}'
                        prefix.with_suffix('.stdout.log').write_text(result.stdout)
                        prefix.with_suffix('.stderr.log').write_text(result.stderr)
                        self.assertEqual(result.returncode, 2 if partial else 1 if unsafe else 0,
                                         (command, result.stdout, result.stderr))
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report['status'], 'partial' if partial else 'ok', report)
                            totals = report['totals'] if meta else report
                            self.assertEqual([totals[key] for key in ('files', 'critical', 'warning', 'info')],
                                             [1, len(expected), 0, 0], report)
                            actual = [(row['line'], row['col'], row['rule_id' if meta else 'rule'])
                                      for row in report['findings']]
                            for row in report['findings']:
                                self.assertEqual(Path(row['file' if meta else 'path']).name, path.name, row)
                                self.assertEqual(row['severity'], 'critical', row)
                        else:
                            self.assertEqual(report['version'], '2.1.0', report)
                            analyzer_runs = [run for run in report['runs']
                                             if run['tool']['driver']['name'] == 'ubs-golang-heuristics']
                            self.assertTrue(analyzer_runs, report)
                            if partial:
                                for run in analyzer_runs:
                                    failures = [invocation for invocation in run.get('invocations', [])
                                                if not invocation['executionSuccessful']
                                                and invocation.get('exitCode') == 2]
                                    self.assertTrue(failures, run)
                                    self.assertTrue(any(
                                        notice.get('level') == 'error'
                                        and notice.get('descriptor', {}).get('id') == 'ubs/module-partial'
                                        and 'reader' in notice.get('message', {}).get('text', '')
                                        for invocation in failures
                                        for notice in invocation.get('toolExecutionNotifications', [])), run)
                            actual = []
                            for run in report['runs']:
                                for invocation in run.get('invocations', []):
                                    if not partial:
                                        self.assertTrue(invocation['executionSuccessful'], invocation)
                                for row in run.get('results', []):
                                    location = row['locations'][0]['physicalLocation']
                                    region = location['region']
                                    self.assertEqual(Path(location['artifactLocation']['uri']).name, path.name, row)
                                    self.assertEqual(row['level'], 'error', row)
                                    actual.append((region['startLine'], region['startColumn'], row['ruleId']))
                        self.assertEqual(sorted(actual), sorted(expected), report)
                        if partial:
                            self.assertIn('reader', json.dumps(report), report)
                        print('GO_BUFFERED_PUBLIC_PASS', name, 'runner' if meta else 'module', output, flush=True)


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1',
                     'set UBS_TAINT_E2E=1 for real Go module and runner reports')
class NativeScanningModuleTests(unittest.TestCase):
    def test_public_unsafe_and_metadata_reports(self):
        self.check_public_cases(0, 4)

    def test_public_controls_and_boundaries(self):
        self.check_public_cases(4, 8)

    def check_public_cases(self, start, end):
        from test_keep_temp import prevent_child_deletion

        cases = (
            ('stdin', 'var value string\nfmt.Scan(&value)\ndb.Query(value) // query', True, False),
            ('saved', 'var value string\nread := fmt.Sscanf\n'
             'read(r.FormValue("q"), "%s", &value)\ndb.Query(value) // query', True, False),
            ('body', 'var value string\nfmt.Fscan(r.Body, &value)\ndb.Query(value) // query', True, False),
            ('metadata', 'var value string\nn, err := fmt.Scan(&value)\nfmt.Fprint(w, n, err)', False, False),
            ('bound', 'var value string\nfmt.Scan(&value)\ndb.Query("SELECT $1", value)', False, False),
            ('literal', 'var value string\nfmt.Sscan("fixed", &value)\ndb.Query(value)', False, False),
            ('custom', 'var value CustomScanner\nfmt.Scan(&value)', False, True),
            ('encoded', 'var value string\nfmt.Sscanf(r.FormValue("q"), "%q", &value)', False, True),
        )
        artifacts = packages.ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='go-scanning-public-', dir=artifacts))
        skipped = ','.join(str(category) for category in range(1, 23) if category != 9)
        for name, body, unsafe, partial in cases[start:end]:
            folder = root / name
            folder.mkdir()
            source = 'package app\nimport "fmt"\nfunc h() {\n' + body + '\n}\n'
            path = folder / 'handler.go'
            path.write_text(source)
            (folder / 'unselected.go').write_text('package app\nfunc other() { db.Query(r.FormValue("q")) }\n')
            expected = [(number, line.index('db.Query') + 1, 'go.taint.sql')
                        for number, line in enumerate(source.splitlines(), 1) if '// query' in line]
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, format=output):
                        command = [str(packages.ROOT / ('ubs' if meta else 'modules/ubs-golang.sh')),
                                   str(path), '--ci', '--no-color', '--format=' + output, '--skip=' + skipped]
                        if meta:
                            command.append('--only=golang')
                        result = subprocess.run(command, cwd=folder, capture_output=True, text=True,
                                                timeout=45, preexec_fn=prevent_child_deletion,
                                                env=dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1',
                                                         UBS_NO_CACHE='1', UBS_CACHE_DIR=str(folder / 'cache')))
                        prefix = folder / f'{meta}-{output}'
                        prefix.with_suffix('.stdout.log').write_text(result.stdout)
                        prefix.with_suffix('.stderr.log').write_text(result.stderr)
                        self.assertEqual(result.returncode, 2 if partial else 1 if unsafe else 0,
                                         (command, result.stdout, result.stderr))
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report['status'], 'partial' if partial else 'ok', report)
                            totals = report['totals'] if meta else report
                            self.assertEqual([totals[key] for key in ('files', 'critical', 'warning', 'info')],
                                             [1, len(expected), 0, 0], report)
                            records = report['findings']
                            actual = [(row['line'], row['col'], row['rule_id' if meta else 'rule'])
                                      for row in records]
                            for row in records:
                                self.assertEqual(Path(row['file' if meta else 'path']).name, path.name, row)
                                self.assertEqual(row['severity'], 'critical', row)
                        else:
                            self.assertEqual(report['version'], '2.1.0', report)
                            actual = []
                            for run in report['runs']:
                                for row in run.get('results', []):
                                    location = row['locations'][0]['physicalLocation']
                                    region = location['region']
                                    self.assertEqual(Path(location['artifactLocation']['uri']).name, path.name, row)
                                    self.assertEqual(row['level'], 'error', row)
                                    actual.append((region['startLine'], region['startColumn'], row['ruleId']))
                        self.assertEqual(sorted(actual), sorted(expected), report)
                        if partial:
                            self.assertIn('formatted input', json.dumps(report), report)


class OrdinaryDestinationWriteTests(packages.PackageTestCase):
    def check_writes(self, body, sites, helpers=''):
        self.source('handler.go', 'package app\nimport ("html"; "encoding/json"; "strings"; "os/exec")\n'
                    'func h() {\n' + textwrap.dedent(body) + '\n}\n')
        self.source('helpers.go', 'package app\ntype Payload struct { SQL string; HTML string }\n'
                    + textwrap.dedent(helpers))
        lines = self.sources['handler.go'].read_text().splitlines()
        expected = []
        for marker, rule in sites:
            matches = [number for number, line in enumerate(lines, 1) if '// ' + marker in line]
            self.assertEqual(len(matches), 1, (marker, lines))
            expected.append(('handler.go', matches[0], 'go.taint.' + rule))
        return self.assert_hits(expected)

    def test_pointer_assignment_reaches_scalar_sinks_and_keeps_value_copies(self):
        self.check_writes('''
            value := "fixed"
            saved := value
            out := &value
            *out = r.FormValue("q")
            db.Query(value) // written
            db.Query(saved)
        ''', [('written', 'sql')])

    def test_pointer_output_helpers_propagate_across_selected_files(self):
        self.check_writes('''
            value := "fixed"
            forward(&value, r.FormValue("q"))
            fmt.Fprint(w, value) // output
            exec.Command("sh", "-c", value) // command
        ''', [('output', 'xss'), ('command', 'command')], '''
            func assign(out *string, input string) { *out = input }
            func forward(out *string, input string) { assign(out, input) }
        ''')

    def test_selector_writes_reach_local_pointer_and_helper_destinations(self):
        self.check_writes('''
            var local, written, untouched Payload
            local.SQL = r.FormValue("q")
            db.Query(local.SQL) // local
            pointer := &Payload{}
            pointer.SQL = r.FormValue("q")
            db.Query(pointer.SQL) // pointer
            assign(&written, r.FormValue("q"))
            db.Query(written.SQL) // helper
            db.Query(untouched.SQL)
        ''', [('local', 'sql'), ('pointer', 'sql'), ('helper', 'sql')], '''
            func assign(out *Payload, input string) { out.SQL = input }
        ''')

    def test_field_pointer_writes_preserve_other_fields_and_parentheses(self):
        self.check_writes('''
            var value Payload
            out := &value.SQL
            (*out) = r.FormValue("q")
            pointer := &value
            (*pointer).HTML = "fixed"
            db.Query(value.SQL) // field
        ''', [('field', 'sql')])

    def test_pointer_rebinding_and_shadowing_keep_distinct_destinations(self):
        self.check_writes('''
            first, second := "fixed", "fixed"
            out := &first
            out = &second
            { shadow := "fixed"; out := &shadow; *out = r.FormValue("shadow") }
            *out = r.FormValue("q")
            db.Query(first)
            db.Query(second) // rebound
        ''', [('rebound', 'sql')])

    def test_branch_targets_keep_possible_writes_and_do_not_gain_clean_resets(self):
        self.check_writes('''
            first, second := "fixed", "fixed"
            out := &first
            if choice { out = &second }
            *out = r.FormValue("q")
            db.Query(first) // first
            db.Query(second) // second
            *out = "fixed"
            db.Query(first) // possible-old
        ''', [('first', 'sql'), ('second', 'sql'), ('possible-old', 'sql')])

    def test_exact_scalar_reset_does_not_erase_a_previously_saved_value(self):
        self.check_writes('''
            value := r.FormValue("q")
            saved := value
            out := &value
            alias := out
            *alias = "fixed"
            db.Query(value)
            db.Query(saved) // copy
        ''', [('copy', 'sql')])

    def test_returned_field_pointer_cannot_clear_a_tainted_sibling(self):
        self.check_writes('''
            value := Payload{HTML: r.FormValue("q")}
            out := field(&value)
            *out = "fixed"
            fmt.Fprint(w, value.HTML) // sibling
        ''', [('sibling', 'xss')], '''
            func field(value *Payload) *string { return &value.SQL }
        ''')

    def test_collapsed_pointer_to_pointer_does_not_clear_the_old_value(self):
        self.check_writes('''
            value := r.FormValue("q")
            fixed := "fixed"
            out := &value
            slot := &out
            *slot = &fixed
            db.Query(value) // original
        ''', [('original', 'sql')])

    def test_compound_writes_keep_the_old_value_and_new_input(self):
        self.check_writes('''
            var payload Payload
            payload.SQL += r.FormValue("q")
            db.Query(payload.SQL) // appended-field
            value := r.FormValue("q")
            out := &value
            *out += "suffix"
            db.Query(value) // appended-pointer
        ''', [('appended-field', 'sql'), ('appended-pointer', 'sql')])

    def test_writes_keep_html_sanitization_specific_to_its_output_domain(self):
        self.check_writes('''
            var payload Payload
            payload.HTML = html.EscapeString(r.FormValue("q"))
            fmt.Fprint(w, payload.HTML)
            db.Query(payload.HTML) // query
            db.Query("SELECT $1", payload.HTML)
            value := "fixed"
            out := &value
            *out = html.EscapeString(r.FormValue("q"))
            fmt.Fprint(w, value)
            exec.Command("sh", "-c", value) // command
        ''', [('query', 'sql'), ('command', 'command')])

    def test_value_parameter_copies_and_fixed_pointer_inputs_stay_clean(self):
        self.check_writes('''
            value := "fixed"
            var payload, fixed Payload
            scalar(value, r.FormValue("q"))
            copied(payload, r.FormValue("q"))
            assign(&fixed, "SELECT 1")
            db.Query(value)
            db.Query(payload.SQL)
            db.Query(fixed.SQL)
        ''', [], '''
            func scalar(out string, input string) { out = input }
            func copied(out Payload, input string) { out.SQL = input }
            func assign(out *Payload, input string) { out.SQL = input }
        ''')

    def test_pointer_decoder_replacement_carries_the_new_reader(self):
        self.check_writes('''
            decoder := json.NewDecoder(strings.NewReader("{}"))
            out := &decoder
            *out = json.NewDecoder(r.Body)
            var payload Payload
            err := decoder.Decode(&payload)
            db.Query(payload.SQL) // decoded
            db.Query(err.Error())
        ''', [('decoded', 'sql')])

    def test_unknown_pointer_decoder_replacement_cannot_keep_clean_authority(self):
        self.check_writes('''
            decoder := json.NewDecoder(strings.NewReader("{}"))
            out := &decoder
            *out = callbacks.Decoder(r.FormValue("q"))
            var payload Payload
            err := decoder.Decode(&payload)
            db.Query(payload.SQL) // possible-output
            db.Query(err.Error()) // possible-error
        ''', [('possible-output', 'sql'), ('possible-error', 'sql')])

    def test_unknown_pointer_join_never_proves_a_whole_cell_reset(self):
        for factory in ('fresh', 'globalPointer'):
            with self.subTest(factory=factory):
                self.check_writes('''
                    value := r.FormValue("q")
                    out := &value
                    if choice { out = ''' + factory + '''() }
                    *out = "fixed"
                    db.Query(value) // possible-old
                ''', [('possible-old', 'sql')], '''
                    var global = "fixed"
                    func fresh() *string { value := "fixed"; return &value }
                    func globalPointer() *string { return &global }
                ''')

    def test_mixed_local_and_parameter_pointer_return_does_not_erase_input(self):
        self.check_writes('''
            value := r.FormValue("q")
            out := choosePointer(&value, choice)
            *out = "fixed"
            db.Query(value) // possible-old
        ''', [('possible-old', 'sql')], '''
            func choosePointer(value *string, choice bool) *string {
                if choice { other := "fixed"; return &other }
                return value
            }
        ''')

    def test_pointer_cell_rebinding_and_double_indirection_write_the_actual_pointee(self):
        self.check_writes('''
            old, other := "fixed", "fixed"
            out := &old
            cell := &out
            *cell = &other
            *out = r.FormValue("q")
            db.Query(old)
            db.Query(other) // rebound
            third := "fixed"
            pointer := &third
            slot := &pointer
            **slot = r.FormValue("q")
            db.Query(third) // indirect
        ''', [('rebound', 'sql'), ('indirect', 'sql')])

    def test_field_writes_keep_clean_siblings_and_exact_field_resets(self):
        self.check_writes('''
            var payload Payload
            payload.SQL = r.FormValue("q")
            db.Query(payload.HTML)
            payload.SQL = "fixed"
            db.Query(payload.SQL)
            out := &payload.SQL
            *out = r.FormValue("q")
            db.Query(payload.HTML)
            db.Query(payload.SQL) // written-field
            var nested Nested
            nested.Payload.SQL = r.FormValue("q")
            db.Query(nested.Payload.HTML)
            db.Query(nested.Payload.SQL) // nested-field
        ''', [('written-field', 'sql'), ('nested-field', 'sql')], '''
            type Nested struct { Payload Payload }
        ''')

    def test_struct_value_copies_snapshot_the_field_facts_before_reset(self):
        self.check_writes('''
            var payload Payload
            before := payload
            payload.SQL = r.FormValue("q")
            saved := payload
            payload = Payload{}
            db.Query(before.SQL)
            db.Query(saved.HTML)
            db.Query(saved.SQL) // saved-field
            db.Query(payload.SQL)
        ''', [('saved-field', 'sql')])

    def test_captured_or_addressed_pointer_mutation_keeps_saved_copy_precision(self):
        for mutation in ('replace(&out)', 'func() { out = fresh() }()'):
            with self.subTest(mutation=mutation):
                self.check_writes('''
                    value := r.FormValue("q")
                    out := &value
                    saved := out
                    ''' + mutation + '''
                    *out = "fixed"
                    db.Query(value) // possible-old
                    *saved = "fixed"
                    db.Query(value)
                ''', [('possible-old', 'sql')], '''
                    func fresh() *string { value := "fixed"; return &value }
                    func replace(out **string) { *out = fresh() }
                ''')

    def test_clean_field_facets_cannot_mask_unresolved_aggregate_provenance(self):
        self.check_writes('''
            value := Embedded{Base: Base{SQL: r.FormValue("q")}}
            value.SQL = "fixed"
            value.Base.SQL = r.FormValue("again")
            db.Query(value.SQL) // promoted-alias
        ''', [('promoted-alias', 'sql')], '''
            type Base struct { SQL string }
            type Embedded struct { Base }
        ''')


class NativeFunctionValueTests(packages.PackageTestCase):
    def test_deferred_reader_capture_does_not_snapshot_a_clean_error_contract(self):
        self.source('handler.go', '''
            package app
            import "io"
            func custom(reader io.Reader) ([]byte, error) { return nil, fmt.Errorf("%v", reader) }
            func h() {
                read := io.ReadAll
                render := func() { _, err := read(r.Body); fmt.Fprint(w, err) }
                read = custom
                render()
            }
        ''')
        self.assert_hits([('handler.go', 6, 'go.taint.xss')])

    def test_saved_reader_and_unmarshal_keep_output_and_error_positions(self):
        for reader in ('io', 'io/ioutil'):
            for codec in ('encoding/json', 'encoding/xml'):
                with self.subTest(reader=reader, codec=codec):
                    self.source('handler.go', 'package app\nimport (\n'
                                'stream "' + reader + '"\ncodec "' + codec + '"\n)\n'
                                'func h() {\nread := stream.ReadAll\ndecode := codec.Unmarshal\n'
                                'raw, readErr := read(r.Body)\nvar p Payload\n'
                                'decodeErr := decode(raw, &p)\n'
                                'db.Query(string(raw))\ndb.Query(p.SQL)\n'
                                'db.Query(readErr.Error())\ndb.Query(decodeErr.Error())\n}\n')
                    self.assert_hits([('handler.go', 12, 'go.taint.sql'),
                                      ('handler.go', 13, 'go.taint.sql')])

    def test_saved_decoder_constructor_and_alias_keep_reader_capture(self):
        for codec in ('encoding/json', 'encoding/xml'):
            with self.subTest(codec=codec):
                self.source('handler.go', 'package app\nimport codec "' + codec + '"\n'
                            'func h() {\nfactory := (codec.NewDecoder)\nalias := factory\n'
                            'dec := alias(r.Body)\nvar p Payload\nerr := dec.Decode(&p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                self.assert_hits([('handler.go', 9, 'go.taint.sql')])

    def test_saved_constructor_immediate_decode_preserves_destination(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                factory := json.NewDecoder
                var p Payload
                factory(r.Body).Decode(&p)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_saved_dot_imports_and_parallel_aliases_keep_identity(self):
        self.source('handler.go', '''
            package app
            import (. "encoding/json"; . "io")
            func h() {
                read, decode := ReadAll, Unmarshal
                reader, decoder := read, decode
                raw, err := reader(r.Body)
                var p Payload
                decodeErr := decoder(raw, &p)
                db.Query(p.SQL)
                db.Query(err.Error())
                db.Query(decodeErr.Error())
            }
        ''')
        self.assert_hits([('handler.go', 9, 'go.taint.sql')])

    def test_native_unmarshal_choice_keeps_all_destination_writes(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "encoding/xml")
            func h() {
                decode := json.Unmarshal
                if xmlBody { decode = xml.Unmarshal }
                var p Payload
                err := decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 8, 'go.taint.sql')])

    def test_unknown_reader_choice_does_not_borrow_clean_error_contract(self):
        self.source('handler.go', '''
            package app
            import "io"
            func h() {
                read := io.ReadAll
                if choice { read = customRead }
                raw, err := read(r.Body)
                db.Query(string(raw))
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.sql'), ('handler.go', 8, 'go.taint.sql')])

    def test_unknown_reader_preserves_captured_source_with_clean_arguments(self):
        self.source('handler.go', '''
            package app
            import ("io"; "strings"; callbacks "example.test/callbacks")
            func h() {
                read := io.ReadAll
                saved := read
                if choice { read = callbacks.Reader(r.FormValue("q")) }
                raw, err := read(strings.NewReader("fixed"))
                fmt.Fprint(w, raw)
                fmt.Fprint(w, err)
                clean, cleanErr := saved(strings.NewReader("fixed"))
                fmt.Fprint(w, clean, cleanErr)
            }
        ''')
        self.assert_hits([('handler.go', 8, 'go.taint.xss'), ('handler.go', 9, 'go.taint.xss')])

    def test_unknown_unmarshal_preserves_captured_source_in_writes_and_error(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; callbacks "example.test/callbacks")
            func h() {
                decode := json.Unmarshal
                saved := decode
                if choice { decode = callbacks.Unmarshal(r.FormValue("q")) }
                var p Payload
                err := decode([]byte("{}"), &p)
                db.Query(p.SQL)
                db.Query(err.Error())
                var clean Payload
                cleanErr := saved([]byte("{}"), &clean)
                db.Query(clean.SQL)
                db.Query(cleanErr.Error())
            }
        ''')
        self.assert_hits([('handler.go', 9, 'go.taint.sql'), ('handler.go', 10, 'go.taint.sql')])

    def test_unknown_factory_preserves_captured_source_in_decoder_output(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings"; callbacks "example.test/callbacks")
            func h() {
                factory := json.NewDecoder
                saved := factory
                if choice { factory = callbacks.Factory(r.FormValue("body")) }
                decoder := factory(strings.NewReader("{}"))
                var p Payload
                decoder.Decode(&p)
                db.Query(p.SQL)
                known := saved(strings.NewReader("{}"))
                var clean Payload
                known.Decode(&clean)
                db.Query(clean.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 10, 'go.taint.sql')])

    def test_unknown_decoder_receiver_preserves_its_own_source_in_writes(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings"; callbacks "example.test/callbacks")
            func h() {
                decoder := json.NewDecoder(strings.NewReader("{}"))
                saved := decoder
                if choice { decoder = callbacks.Decoder(r.FormValue("body")) }
                var p Payload
                err := decoder.Decode(&p)
                db.Query(p.SQL)
                db.Query(err.Error())
                var clean Payload
                cleanErr := saved.Decode(&clean)
                db.Query(clean.SQL)
                db.Query(cleanErr.Error())
            }
        ''')
        self.assert_hits([('handler.go', 9, 'go.taint.sql'), ('handler.go', 10, 'go.taint.sql')])

    def test_unknown_escaper_preserves_captured_source_with_a_clean_argument(self):
        self.source('handler.go', '''
            package app
            import ("html"; callbacks "example.test/callbacks")
            func h() {
                escape := html.EscapeString
                saved := escape
                if choice { escape = callbacks.Escaper(r.FormValue("q")) }
                fmt.Fprint(w, escape("fixed"))
                fmt.Fprint(w, saved("fixed"))
            }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.xss')])

    def test_native_alias_retains_identity_after_original_binding_changes(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decode := json.Unmarshal
                saved := decode
                decode = customDecode
                var p Payload
                saved([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 9, 'go.taint.sql')])

    def test_overwritten_callable_does_not_keep_native_return_contract(self):
        self.source('handler.go', '''
            package app
            import "io"
            func h() {
                read := io.ReadAll
                read = customRead
                _, err := read(r.Body)
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_saved_lookalike_package_never_gets_native_result_contract(self):
        self.source('handler.go', '''
            package app
            import io "example.test/reader"
            func h() {
                read := io.ReadAll
                _, err := read(r.Body)
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 6, 'go.taint.sql')])

    def test_block_shadow_does_not_change_captured_native_value(self):
        self.source('handler.go', '''
            package app
            import "io"
            func h() {
                read := io.ReadAll
                { read := customRead; _, err := read(r.Body); db.Query(err.Error()) }
                _, err := read(r.Body)
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 5, 'go.taint.sql')])

    def test_helper_local_native_alias_retains_output_parameter_summary(self):
        self.source('helper.go', '''
            package app
            import codec "encoding/json"
            func decode(raw []byte, dst *Payload) {
                run := codec.Unmarshal
                run(raw, dst)
            }
        ''')
        self.source('handler.go', '''
            package app
            func h() {
                var p Payload
                decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
                db.Query("SELECT $1", p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 5, 'go.taint.sql')])

    def test_closure_can_use_a_lexically_captured_native_decoder(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decode := json.Unmarshal
                query := func() string {
                    var p Payload
                    decode([]byte(r.FormValue("body")), &p)
                    return p.SQL
                }()
                db.Query(query)
            }
        ''')
        self.assert_hits([('handler.go', 10, 'go.taint.sql')])

    def test_invoked_closure_native_reader_keeps_payload_and_error_slots(self):
        for package in ('io', 'io/ioutil'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport reader "' + package + '"\n'
                            'func h() {\n'
                            'func(read func(io.Reader) ([]byte, error)) {\n'
                            'payload, err := read(r.Body)\n'
                            'db.Query(string(payload))\n'
                            'db.Query(err.Error())\n'
                            '}(reader.ReadAll)\n}\n')
                self.assert_hits([('handler.go', 6, 'go.taint.sql')])

    def test_invoked_closure_decoder_factory_preserves_destination_writes(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport codec "' + package + '"\n'
                            'func h() {\n'
                            'func(factory func(io.Reader) *codec.Decoder) {\n'
                            'var p Payload\ndecoder := factory(r.Body)\n'
                            'err := decoder.Decode(&p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n'
                            'db.Query("SELECT $1", p.SQL)\n'
                            '}(codec.NewDecoder)\n}\n')
                self.assert_hits([('handler.go', 8, 'go.taint.sql')])

    def test_invoked_closure_unmarshal_callback_keeps_output_and_error_separate(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport codec "' + package + '"\n'
                            'func h() {\n'
                            'func(decode func([]byte, any) error) {\n'
                            'var p Payload\n'
                            'err := decode([]byte(r.FormValue("body")), &p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n'
                            '}(codec.Unmarshal)\n}\n')
                self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_invoked_closure_decoder_and_destination_arguments_keep_identity(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport codec "' + package + '"\n'
                            'func h() {\nvar p Payload\n'
                            'decoder := codec.NewDecoder(r.Body)\n'
                            'func(reader *codec.Decoder, out *Payload) {\n'
                            'err := reader.Decode(out)\n'
                            'db.Query(out.SQL)\ndb.Query(err.Error())\n'
                            '}(decoder, &p)\n}\n')
                self.assert_hits([('handler.go', 8, 'go.taint.sql')])

    def test_invoked_closure_fixed_decoder_and_reader_arguments_remain_clean(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "io"; "strings")
            func h() {
                func(read func(io.Reader) ([]byte, error), makeDecoder func(io.Reader) *json.Decoder) {
                    raw, err := read(strings.NewReader("SELECT 1"))
                    db.Query(string(raw))
                    db.Query(err.Error())
                    var p Payload
                    decoder := makeDecoder(strings.NewReader(`{"SQL":"SELECT 1"}`))
                    failure := decoder.Decode(&p)
                    db.Query(p.SQL)
                    db.Query(failure.Error())
                }(io.ReadAll, json.NewDecoder)
            }
        ''')
        self.assert_hits([])

    def test_immediate_closure_reader_results_keep_payload_and_error_slots(self):
        for package in ('io', 'io/ioutil'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport reader "' + package + '"\n'
                            'func h() {\n'
                            'payload, err := func() ([]byte, error) { return reader.ReadAll(r.Body) }()\n'
                            'db.Query(string(payload))\ndb.Query(err.Error())\n}\n')
                self.assert_hits([('handler.go', 5, 'go.taint.sql')])

    def test_immediate_closure_returns_decoder_and_clean_error_contracts(self):
        for package in ('encoding/json', 'encoding/xml'):
            with self.subTest(package=package):
                self.source('handler.go', 'package app\nimport codec "' + package + '"\n'
                            'func h() {\n'
                            'decoder := func() *codec.Decoder { return codec.NewDecoder(r.Body) }()\n'
                            'var p Payload\nerr := decoder.Decode(&p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n'
                            'db.Query("SELECT $1", p.SQL)\n}\n')
                self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_immediate_closure_result_preserves_outer_pointer_alias(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                var p Payload
                out := func() *Payload { return &p }()
                json.NewDecoder(r.Body).Decode(out)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_immediate_closure_local_pointer_result_is_explicitly_incomplete(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', '''
            package app
            func h() {
                out := func() *Payload { var p Payload; p.SQL = r.FormValue("q"); return &p }()
                db.Query(out.SQL)
            }
        ''')
        with self.assertRaisesRegex(AnalysisLimit, 'closure-local pointer result transport'):
            self.scan()

    def test_immediate_closure_pointer_result_retains_captured_destination_writes(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                var p Payload
                out := func() *Payload {
                    json.NewDecoder(r.Body).Decode(&p)
                    return &p
                }()
                db.Query(out.SQL)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 9, 'go.taint.sql'), ('handler.go', 10, 'go.taint.sql')])

    def test_immediate_closure_named_pointer_result_retains_captured_destination_writes(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                var p Payload
                out := func() (result *Payload) {
                    result = &p
                    json.NewDecoder(r.Body).Decode(result)
                    return
                }()
                db.Query(out.SQL)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 10, 'go.taint.sql'), ('handler.go', 11, 'go.taint.sql')])

    def test_saved_native_operations_with_fixed_data_stay_clean(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "io"; "strings")
            func h() {
                read := io.ReadAll
                decode := json.Unmarshal
                raw, err := read(strings.NewReader(`{"SQL":"SELECT 1"}`))
                var p Payload
                decodeErr := decode(raw, &p)
                db.Query(p.SQL)
                db.Query(err.Error())
                db.Query(decodeErr.Error())
            }
        ''')
        self.assert_hits([])


class HigherOrderNativeFlowTests(packages.PackageTestCase):
    """Native function values keep their semantics across selected Go helpers.

    Expected sites follow the values actually returned or written by each Go
    call. Error results, bound SQL arguments and escaped HTML are deliberate
    controls against replacing missing dataflow with blanket taint propagation.
    """

    def assert_sites(self, sites):
        expected = []
        for name, marker, callee, rule in sites:
            lines = self.sources[name].read_text(encoding='utf-8').splitlines()
            matches = [(number, line) for number, line in enumerate(lines, 1)
                       if '// ' + marker in line]
            self.assertEqual(len(matches), 1, (name, marker, lines))
            number, line = matches[0]
            expected.append((name, number, line.index(callee) + 1, 'go.taint.' + rule))
        findings = self.scan()
        actual = [(str(Path(row['path']).relative_to(self.root)), row['line'],
                   row['col'], row['rule']) for row in findings]
        self.assertEqual(sorted(actual), sorted(expected), findings)

    def test_unmarshal_parameter_forwarding_writes_only_the_destination(self):
        for codec in ('encoding/json', 'encoding/xml'):
            with self.subTest(codec=codec):
                self.source('handler.go', '''
                    package app
                    import codec "''' + codec + '''"
                    func invoke(decode func([]byte, any) error, data []byte, out *Payload) error {
                        return decode(data, out)
                    }
                    func forward(decode func([]byte, any) error, data []byte, out *Payload) error {
                        return invoke(decode, data, out)
                    }
                    func h() {
                        var p, unrelated, fixed Payload
                        err := forward(codec.Unmarshal, []byte(r.FormValue("body")), &p)
                        db.Query(p.SQL) // decoded-query
                        db.Query(unrelated.SQL)
                        db.Query(err.Error())
                        db.Query("SELECT $1", p.SQL)
                        fixedErr := forward(codec.Unmarshal, []byte("{}"), &fixed)
                        db.Query(fixed.SQL)
                        db.Query(fixedErr.Error())
                    }
                ''')
                self.assert_sites([('handler.go', 'decoded-query', 'db.Query', 'sql')])

    def test_reader_parameter_forwarding_preserves_payload_and_error_slots(self):
        self.source('handler.go', '''
            package app
            import ("io"; "strings")
            func invoke(read func(io.Reader) ([]byte, error), input io.Reader) ([]byte, error) {
                return read(input)
            }
            func forward(read func(io.Reader) ([]byte, error), input io.Reader) ([]byte, error) {
                return invoke(read, input)
            }
            func h() {
                data, err := forward(io.ReadAll, r.Body)
                db.Query(string(data)) // request-bytes
                db.Query(err.Error())
                fixed, fixedErr := forward(io.ReadAll, strings.NewReader("SELECT 1"))
                db.Query(string(fixed))
                db.Query(fixedErr.Error())
            }
        ''')
        self.assert_sites([('handler.go', 'request-bytes', 'db.Query', 'sql')])

    def test_returned_callable_and_value_keep_distinct_tuple_slots(self):
        self.source('handler.go', '''
            package app
            import ("io"; "strings")
            func pair(value string) (string, func(io.Reader) ([]byte, error)) {
                return value, io.ReadAll
            }
            func keep(read func(io.Reader) ([]byte, error)) func(io.Reader) ([]byte, error) {
                return read
            }
            func h() {
                value, reader := pair(r.FormValue("q"))
                read := keep(reader)
                db.Query(value) // separate-value
                fixed, fixedErr := read(strings.NewReader("SELECT 1"))
                db.Query(string(fixed))
                db.Query(fixedErr.Error())
                data, err := read(r.Body)
                db.Query(string(data)) // returned-reader
                db.Query(err.Error())
            }
        ''')
        self.assert_sites([('handler.go', 'separate-value', 'db.Query', 'sql'),
                           ('handler.go', 'returned-reader', 'db.Query', 'sql')])

    def test_factory_parameters_and_returned_decoders_retain_reader_identity(self):
        for codec in ('encoding/json', 'encoding/xml'):
            with self.subTest(codec=codec):
                self.source('handler.go', '''
                    package app
                    import (codec "''' + codec + '''"; "io"; "strings")
                    func makeDecoder(factory func(io.Reader) *codec.Decoder, input io.Reader) *codec.Decoder {
                        return factory(input)
                    }
                    func decode(dec *codec.Decoder, out *Payload) error {
                        return dec.Decode(out)
                    }
                    func h() {
                        var p, fixed Payload
                        decoder := makeDecoder(codec.NewDecoder, r.Body)
                        err := decode(decoder, &p)
                        db.Query(p.SQL) // returned-decoder
                        db.Query(err.Error())
                        known := makeDecoder(codec.NewDecoder, strings.NewReader("{}"))
                        fixedErr := decode(known, &fixed)
                        db.Query(fixed.SQL)
                        db.Query(fixedErr.Error())
                    }
                ''')
                self.assert_sites([('handler.go', 'returned-decoder', 'db.Query', 'sql')])

    def test_returned_functions_keep_the_defining_files_import_authority(self):
        self.source('factory.go', '''
            package app
            import (codec "encoding/json"; html "html")
            func decoder() func([]byte, any) error { return codec.Unmarshal }
            func escaper() func(string) string { return html.EscapeString }
        ''')
        self.source('handler.go', '''
            package app
            import (codec "example.test/codec"; html "example.test/html")
            func pretendEscape() func(string) string { return html.EscapeString }
            func h() {
                decode := decoder()
                var p Payload
                err := decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL) // native-returned-write
                db.Query(err.Error())
                escape := escaper()
                fmt.Fprint(w, escape(r.FormValue("q")))
                unknown := pretendEscape()
                fmt.Fprint(w, unknown(r.FormValue("q"))) // lookalike-return
                _ = codec.Unmarshal
            }
        ''')
        self.assert_sites([('handler.go', 'native-returned-write', 'db.Query', 'sql'),
                           ('handler.go', 'lookalike-return', 'fmt.Fprint', 'xss')])

    def test_native_and_unknown_callback_choices_survive_helper_transport(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "encoding/xml"; callbacks "example.test/callbacks")
            func invoke(decode func([]byte, any) error, data []byte, out *Payload) error {
                return decode(data, out)
            }
            func keep(decode func([]byte, any) error) func([]byte, any) error {
                return decode
            }
            func h() {
                decode := json.Unmarshal
                if xmlBody { decode = xml.Unmarshal }
                var native, uncertain Payload
                nativeErr := invoke(decode, []byte(r.FormValue("body")), &native)
                db.Query(native.SQL) // native-choice
                db.Query(nativeErr.Error())
                if custom { decode = callbacks.Unmarshal(r.FormValue("q")) }
                uncertainDecode := keep(decode)
                err := invoke(uncertainDecode, []byte("{}"), &uncertain)
                db.Query(uncertain.SQL) // callback-capture-write
                db.Query(err.Error()) // callback-capture-error
            }
        ''')
        self.assert_sites([('handler.go', 'native-choice', 'db.Query', 'sql'),
                           ('handler.go', 'callback-capture-write', 'db.Query', 'sql'),
                           ('handler.go', 'callback-capture-error', 'db.Query', 'sql')])

    def test_escaper_parameter_contexts_do_not_contaminate_each_other(self):
        for module, member in (('html', 'EscapeString'), ('html/template', 'HTMLEscapeString'),
                               ('text/template', 'HTMLEscapeString')):
            with self.subTest(module=module):
                self.source('handler.go', '''
                    package app
                    import (safe "''' + module + '''"; "os/exec")
                    func apply(escape func(string) string, value string) string { return escape(value) }
                    func raw(value string) string { return value }
                    func h() {
                        value := r.FormValue("q")
                        escaped := apply(safe.''' + member + ''', value)
                        fmt.Fprint(w, escaped)
                        db.Query(escaped) // escaped-sql
                        exec.Command("sh", "-c", escaped) // escaped-command
                        fmt.Fprint(w, apply(raw, value)) // raw-context
                        fmt.Fprint(w, apply(safe.''' + member + ''', value))
                        fmt.Fprint(w, apply(raw, "fixed"))
                    }
                ''')
                self.assert_sites([('handler.go', 'escaped-sql', 'db.Query', 'sql'),
                                   ('handler.go', 'escaped-command', 'exec.Command', 'command'),
                                   ('handler.go', 'raw-context', 'fmt.Fprint', 'xss')])

    def test_returned_escaper_choices_require_every_alternative_to_escape(self):
        self.source('handler.go', '''
            package app
            import ("html"; "text/template")
            func raw(value string) string { return value }
            func chooseNative(choice bool) func(string) string {
                if choice { return html.EscapeString }
                return template.HTMLEscapeString
            }
            func chooseUnknown(choice bool) func(string) string {
                if choice { return html.EscapeString }
                return raw
            }
            func keep(escape func(string) string) func(string) string { return escape }
            func h() {
                value := r.FormValue("q")
                native := keep(chooseNative(choice))
                fmt.Fprint(w, native(value))
                unknown := keep(chooseUnknown(choice))
                fmt.Fprint(w, unknown(value)) // possible-pass-through
            }
        ''')
        self.assert_sites([('handler.go', 'possible-pass-through', 'fmt.Fprint', 'xss')])

    def test_uncertain_escaper_keeps_its_own_source_across_helpers(self):
        self.source('handler.go', '''
            package app
            import ("html"; callbacks "example.test/callbacks")
            func keep(escape func(string) string) func(string) string { return escape }
            func apply(escape func(string) string, value string) string { return escape(value) }
            func h() {
                escape := html.EscapeString
                if choice { escape = callbacks.Escaper(r.FormValue("q")) }
                carried := keep(escape)
                fmt.Fprint(w, apply(carried, "fixed")) // callback-capture
                fmt.Fprint(w, apply(html.EscapeString, "fixed"))
            }
        ''')
        self.assert_sites([('handler.go', 'callback-capture', 'fmt.Fprint', 'xss')])

    def test_parameter_overwrite_preserves_only_an_earlier_value_copy(self):
        self.source('handler.go', '''
            package app
            import "html"
            func raw(value string) string { return value }
            func saved(escape func(string) string, value string) string {
                copy := escape
                escape = raw
                return copy(value)
            }
            func overwritten(escape func(string) string, value string) string {
                escape = raw
                return escape(value)
            }
            func shadowed(escape func(string) string, value string) string {
                { escape := raw; _ = escape }
                return escape(value)
            }
            func h() {
                value := r.FormValue("q")
                fmt.Fprint(w, saved(html.EscapeString, value))
                fmt.Fprint(w, overwritten(html.EscapeString, value)) // overwritten-value
                fmt.Fprint(w, shadowed(html.EscapeString, value))
            }
        ''')
        self.assert_sites([('handler.go', 'overwritten-value', 'fmt.Fprint', 'xss')])

    def test_specialized_escaper_retains_argument_sinks_and_raw_siblings(self):
        self.source('handler.go', '''
            package app
            import "html"
            func apply(escape func(string) string, value string) string { return escape(value) }
            func emit(value string) string { fmt.Fprint(w, value); return value }
            func h() {
                value := r.FormValue("q")
                escaped := apply(html.EscapeString, emit(value)) // argument-effect
                fmt.Fprint(w, escaped)
                fmt.Fprint(w, escaped + value) // raw-sibling
            }
        ''')
        self.assert_sites([('handler.go', 'argument-effect', 'emit(', 'xss'),
                           ('handler.go', 'raw-sibling', 'fmt.Fprint', 'xss')])

    def test_recursive_callable_forwarding_converges_without_losing_result_slots(self):
        self.source('handler.go', '''
            package app
            import "io"
            func keep(read func(io.Reader) ([]byte, error), stop bool) func(io.Reader) ([]byte, error) {
                if stop { return read }
                return keep(read, true)
            }
            func forward(read func(io.Reader) ([]byte, error), input io.Reader, stop bool) ([]byte, error) {
                if stop { return read(input) }
                return forward(read, input, true)
            }
            func h() {
                read := keep(io.ReadAll, false)
                value, err := forward(read, r.Body, false)
                db.Query(string(value)) // recursive-reader
                db.Query(err.Error())
            }
        ''')
        self.assert_sites([('handler.go', 'recursive-reader', 'db.Query', 'sql')])

    def test_returned_callable_observes_other_result_expression_effects(self):
        self.source('handler.go', '''
            package app
            import "html"
            func raw(value string) string { return value }
            func replace(pointer *func(string) string) string { *pointer = raw; return "" }
            func changed() (func(string) string, string) {
                escape := html.EscapeString
                return escape, replace(&escape)
            }
            func copied() (func(string) string, string) {
                escape := html.EscapeString
                saved := escape
                return saved, replace(&escape)
            }
            func h() {
                uncertain, _ := changed()
                saved, _ := copied()
                value := r.FormValue("q")
                fmt.Fprint(w, uncertain(value)) // result-expression-mutation
                fmt.Fprint(w, saved(value))
            }
        ''')
        self.assert_sites([('handler.go', 'result-expression-mutation', 'fmt.Fprint', 'xss')])

    def test_parenthesized_native_unmarshal_keeps_writes_and_error_results(self):
        for codec in ('encoding/json', 'encoding/xml'):
            with self.subTest(codec=codec):
                self.source('handler.go', '''
                    package app
                    import (codec "''' + codec + '''"; "os/exec")
                    func h() {
                        var p, fixed Payload
                        err := ((codec.Unmarshal))([]byte(r.FormValue("body")), &p)
                        db.Query(p.SQL) // decoded-query
                        fmt.Fprint(w, p.HTML) // decoded-html
                        exec.Command("sh", "-c", p.Command) // decoded-command
                        db.Query(err.Error())
                        db.Query("SELECT $1", p.SQL)
                        fixedErr := (codec.Unmarshal)([]byte("{}"), &fixed)
                        db.Query(fixed.SQL)
                        db.Query(fixedErr.Error())
                    }
                ''')
                self.assert_sites([('handler.go', 'decoded-query', 'db.Query', 'sql'),
                                   ('handler.go', 'decoded-html', 'fmt.Fprint', 'xss'),
                                   ('handler.go', 'decoded-command', 'exec.Command', 'command')])

    def test_parenthesized_saved_readers_keep_payload_and_error_slots(self):
        self.source('handler.go', '''
            package app
            import (stream "io"; "strings")
            func h() {
                read := stream.ReadAll
                saved := read
                read = customReader
                value, err := ((saved))(r.Body)
                db.Query(string(value)) // request-bytes
                db.Query(err.Error())
                fixed, fixedErr := (saved)(strings.NewReader("SELECT 1"))
                db.Query(string(fixed))
                db.Query(fixedErr.Error())
            }
        ''')
        self.assert_sites([('handler.go', 'request-bytes', 'db.Query', 'sql')])

    def test_parenthesized_decoder_factories_preserve_chained_and_saved_receivers(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                var a, b, fixed Payload
                err := (json.NewDecoder)(r.Body).Decode(&a)
                db.Query(a.SQL) // chained-decoder
                db.Query(err.Error())
                factory := json.NewDecoder
                decoder := ((factory))(r.Body)
                decoder.Decode(&b)
                db.Query(b.SQL) // saved-decoder
                known := (factory)(strings.NewReader("{}"))
                known.Decode(&fixed)
                db.Query(fixed.SQL)
            }
        ''')
        self.assert_sites([('handler.go', 'chained-decoder', 'db.Query', 'sql'),
                           ('handler.go', 'saved-decoder', 'db.Query', 'sql')])

    def test_parenthesized_helpers_keep_pointer_effects_and_native_contexts(self):
        self.source('helper.go', '''
            package app
            import codec "encoding/json"
            func decode(data []byte, out *Payload) error { return (codec.Unmarshal)(data, out) }
            func relay(data []byte, out *Payload) error { return ((decode))(data, out) }
            func apply(escape func(string) string, value string) string { return (escape)(value) }
        ''')
        self.source('handler.go', '''
            package app
            import "html"
            func h() {
                var p Payload
                err := ((relay))([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL) // helper-write
                db.Query(err.Error())
                escaped := (apply)(html.EscapeString, r.FormValue("q"))
                fmt.Fprint(w, escaped)
                db.Query(escaped) // sanitizer-domain
            }
        ''')
        self.assert_sites([('handler.go', 'helper-write', 'db.Query', 'sql'),
                           ('handler.go', 'sanitizer-domain', 'db.Query', 'sql')])

    def test_parenthesized_sanitizers_keep_identity_and_argument_effects(self):
        self.source('handler.go', '''
            package app
            import ("html"; "os/exec")
            func raw(value string) string { return value }
            func emit(value string) string { fmt.Fprint(w, value); return value }
            func h() {
                value := r.FormValue("q")
                escape := html.EscapeString
                saved := escape
                escape = raw
                fmt.Fprint(w, (saved)(value))
                fmt.Fprint(w, ((escape))(value)) // overwritten-callee
                fmt.Fprint(w, (html.EscapeString)((emit)(value))) // argument-sink
                db.Query((saved)(value)) // sql-domain
                exec.Command("sh", "-c", (saved)(value)) // command-domain
                html := custom
                fmt.Fprint(w, (html.EscapeString)(value)) // shadowed-package
            }
        ''')
        self.assert_sites([('handler.go', 'overwritten-callee', 'fmt.Fprint', 'xss'),
                           ('handler.go', 'argument-sink', 'emit)', 'xss'),
                           ('handler.go', 'sql-domain', 'db.Query', 'sql'),
                           ('handler.go', 'command-domain', 'exec.Command', 'command'),
                           ('handler.go', 'shadowed-package', 'fmt.Fprint', 'xss')])

    def test_parenthesized_sink_targets_and_source_getters_keep_locations(self):
        self.source('handler.go', '''
            package app
            func h() {
                value := (r.FormValue)("q")
                (db.Query)(value) // query-sink
                ((fmt.Fprint))(w, value) // html-sink
                (exec.Command)("sh", "-c", value) // command-sink
                _ = "(json.Unmarshal)(r.Body, &value)"
                // (db.Query)(r.FormValue("q"))
            }
        ''')
        self.assert_sites([('handler.go', 'query-sink', 'db.Query', 'sql'),
                           ('handler.go', 'html-sink', 'fmt.Fprint', 'xss'),
                           ('handler.go', 'command-sink', 'exec.Command', 'command')])

    def test_parenthesized_lookalike_imports_do_not_borrow_native_contracts(self):
        self.source('handler.go', '''
            package app
            import (codec "example.test/codec"; "example.test/html")
            func h() {
                var p Payload
                err := (codec.Unmarshal)([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
                db.Query(err.Error()) // unknown-result
                fmt.Fprint(w, (html.EscapeString)(r.FormValue("q"))) // false-escaper
            }
        ''')
        self.assert_sites([('handler.go', 'unknown-result', 'db.Query', 'sql'),
                           ('handler.go', 'false-escaper', 'fmt.Fprint', 'xss')])


class BoundDecoderMethodTests(packages.PackageTestCase):
    """A saved decoder method captures its receiver, not a clean free function."""

    def assert_sites(self, sites):
        lines = self.sources['handler.go'].read_text(encoding='utf-8').splitlines()
        expected = []
        for marker, callee, rule in sites:
            matches = [(number, line) for number, line in enumerate(lines, 1)
                       if '// ' + marker in line]
            self.assertEqual(len(matches), 1, (marker, lines))
            number, line = matches[0]
            expected.append(('handler.go', number, line.index(callee) + 1, 'go.taint.' + rule))
        findings = self.scan()
        actual = [(str(Path(row['path']).relative_to(self.root)), row['line'], row['col'], row['rule'])
                  for row in findings]
        self.assertEqual(sorted(actual), sorted(expected), findings)

    def test_bound_decode_writes_payload_in_each_domain_but_not_its_error(self):
        for codec in ('encoding/json', 'encoding/xml'):
            with self.subTest(codec=codec):
                self.source('handler.go', '''
                    package app
                    import (codec "''' + codec + '''"; "os/exec")
                    func h() {
                        decoder := codec.NewDecoder(r.Body)
                        decode := decoder.Decode
                        var p Payload
                        err := decode(&p)
                        db.Query(p.SQL) // sql
                        fmt.Fprint(w, p.HTML) // html
                        exec.Command("sh", "-c", p.Command) // command
                        db.Query(err.Error())
                        db.Query("SELECT $1", p.SQL)
                    }
                ''')
                self.assert_sites([('sql', 'db.Query', 'sql'), ('html', 'fmt.Fprint', 'xss'),
                                   ('command', 'exec.Command', 'command')])

    def test_bound_copy_keeps_original_receiver_after_decoder_and_method_rebinding(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                decoder := json.NewDecoder(r.Body)
                decode := (decoder.Decode)
                saved := decode
                decoder = json.NewDecoder(strings.NewReader(`"fixed"`))
                decode = decoder.Decode
                var original, fixed string
                ((saved))(&original)
                decode(&fixed)
                db.Query(original) // captured
                db.Query(fixed)
            }
        ''')
        self.assert_sites([('captured', 'db.Query', 'sql')])

    def test_bound_receiver_survives_pointer_cell_rebinding(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                decoder := json.NewDecoder(r.Body)
                decode := decoder.Decode
                cell := &decoder
                *cell = json.NewDecoder(strings.NewReader(`"fixed"`))
                var original, fixed string
                decode(&original)
                decoder.Decode(&fixed)
                db.Query(original) // captured
                db.Query(fixed)
            }
        ''')
        self.assert_sites([('captured', 'db.Query', 'sql')])

    def test_bound_method_weak_pointer_install_keeps_unknown_alternatives(self):
        from ubs_core.taint_flow import AnalysisLimit

        for target in ('first', 'second'):
            with self.subTest(target=target):
                self.source('handler.go', 'package app\nimport "encoding/json"\nfunc h() {\n'
                            'var first, second func(any) error\np := &first\n'
                            'if choose { p = &second }\n*p = json.NewDecoder(r.Body).Decode\n'
                            'var value Payload\n' + target + '(&value)\ndb.Query(value.SQL)\n}\n')
                with self.assertRaisesRegex(AnalysisLimit, 'decoder.*alternative'):
                    self.scan()

    def test_bound_method_on_constructor_and_selected_factory_results(self):
        self.source('factory.go', '''
            package app
            import ("encoding/json"; "io")
            func factory(input io.Reader) *json.Decoder { return json.NewDecoder(input) }
        ''')
        self.source('handler.go', '''
            package app
            import (codec "encoding/json"; "strings")
            func h() {
                first := codec.NewDecoder(r.Body).Decode
                second := factory(r.Body).Decode
                safe := factory(strings.NewReader(`"fixed"`)).Decode
                var a, b, c string
                first(&a)
                second(&b)
                safe(&c)
                db.Query(a) // constructed
                db.Query(b) // helper-result
                db.Query(c)
            }
        ''')
        self.assert_sites([('constructed', 'db.Query', 'sql'), ('helper-result', 'db.Query', 'sql')])

    def test_bound_method_arguments_and_returns_keep_destination_and_tuple_slots(self):
        self.source('helper.go', '''
            package app
            import ("encoding/json"; "io")
            func method(input io.Reader) (string, func(any) error) {
                decoder := json.NewDecoder(input)
                return "fixed", decoder.Decode
            }
            func invoke(decode func(any) error, out *Payload) error { return decode(out) }
            func relay(decode func(any) error, out *Payload) error { return invoke(decode, out) }
        ''')
        self.source('handler.go', '''
            package app
            import "strings"
            func h() {
                fixed, decode := method(r.Body)
                var p, clean Payload
                err := relay(decode, &p)
                db.Query(p.SQL) // transported
                db.Query(fixed)
                db.Query(err.Error())
                _, safe := method(strings.NewReader(`{}`))
                relay(safe, &clean)
                db.Query(clean.SQL)
            }
        ''')
        self.assert_sites([('transported', 'db.Query', 'sql')])

    def test_bound_tokens_keep_payload_and_error_result_positions(self):
        for codec, method in (('encoding/json', 'Token'), ('encoding/xml', 'Token'),
                              ('encoding/xml', 'RawToken')):
            with self.subTest(codec=codec, method=method):
                self.source('handler.go', '''
                    package app
                    import codec "''' + codec + '''"
                    func h() {
                        decoder := codec.NewDecoder(r.Body)
                        token := decoder.''' + method + '''
                        value, err := token()
                        fmt.Fprint(w, value) // payload
                        fmt.Fprint(w, err)
                    }
                ''')
                self.assert_sites([('payload', 'fmt.Fprint', 'xss')])

    def test_bound_metadata_results_stay_clean(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                more, offset := decoder.More, decoder.InputOffset
                fmt.Fprint(w, more())
                fmt.Fprint(w, offset())
            }
        ''')
        self.assert_sites([])

    def test_bound_buffered_result_remains_a_reader(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "io")
            func h() {
                decoder := json.NewDecoder(r.Body)
                var ignored any
                decoder.Decode(&ignored)
                buffered := decoder.Buffered
                value, err := io.ReadAll(buffered())
                db.Query(string(value)) // buffered
                db.Query(err.Error())
            }
        ''')
        self.assert_sites([('buffered', 'db.Query', 'sql')])

    def test_bound_safe_queries_and_html_sanitizers_remain_domain_specific(self):
        self.source('handler.go', '''
            package app
            import (. "encoding/json"; "html"; "strings"; "os/exec")
            func h() {
                decoder := NewDecoder(r.Body)
                decode := decoder.Decode
                var value string
                decode(&value)
                escaped := html.EscapeString(value)
                fmt.Fprint(w, escaped)
                db.Query("SELECT $1", value)
                db.Query(escaped) // query-domain
                exec.Command("sh", "-c", escaped) // command-domain
                fixed := NewDecoder(strings.NewReader(`"SELECT 1"`))
                decode = fixed.Decode
                var clean string
                decode(&clean)
                db.Query(clean)
            }
        ''')
        self.assert_sites([('query-domain', 'db.Query', 'sql'),
                           ('command-domain', 'exec.Command', 'command')])

    def test_bound_method_local_pointer_storage_preserves_the_receiver(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                var decode func(any) error
                pointer := &decode
                *pointer = decoder.Decode
                var value string
                decode(&value)
                db.Query(value) // indirect
            }
        ''')
        self.assert_sites([('indirect', 'db.Query', 'sql')])

    def test_bound_native_branch_keeps_possible_request_receiver(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                fixed := json.NewDecoder(strings.NewReader(`"fixed"`))
                incoming := json.NewDecoder(r.Body)
                decode := fixed.Decode
                if choose { decode = incoming.Decode }
                var value string
                decode(&value)
                db.Query(value) // branch
            }
        ''')
        self.assert_sites([('branch', 'db.Query', 'sql')])

    def test_bound_method_side_effects_run_before_destination_write(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                decode := decoder.Decode
                var value string
                decode(func() *string {
                    db.Query(r.FormValue("q")) // argument
                    return &value
                }())
                db.Query(value) // decoded
            }
        ''')
        self.assert_sites([('argument', 'db.Query', 'sql'), ('decoded', 'db.Query', 'sql')])

    def test_bound_method_unknown_alternative_cannot_certify_a_clean_scan(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                decode := decoder.Decode
                if choose { decode = foreign }
                var value string
                decode(&value)
                db.Query(value)
            }
        ''')
        with self.assertRaisesRegex(AnalysisLimit, 'decoder.*alternative'):
            self.scan()

    def test_bound_method_opaque_overwrite_is_refusal_only_and_keeps_saved_copy(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                decode := decoder.Decode
                saved := decode
                decode = foreign
                var value string
                saved(&value)
                db.Query(value) // saved-copy
            }
        ''')
        self.assert_sites([('saved-copy', 'db.Query', 'sql')])
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                decoder := json.NewDecoder(strings.NewReader(`"fixed"`))
                decode := decoder.Decode
                decode = foreign
                var value string
                decode(&value)
                db.Query(value)
            }
        ''')
        with self.assertRaisesRegex(AnalysisLimit, 'decoder.*alternative'):
            self.scan()

    def test_bound_decode_element_includes_supplied_start_attributes(self):
        self.source('handler.go', '''
            package app
            import ("encoding/xml"; "strings")
            func h() {
                decoder := xml.NewDecoder(strings.NewReader("<Value></Value>"))
                decoder.Token()
                decode := decoder.DecodeElement
                start := xml.StartElement{Name: xml.Name{Local: "Value"},
                    Attr: []xml.Attr{{Name: xml.Name{Local: "q"}, Value: r.FormValue("q")}}}
                var value Payload
                err := decode(&value, &start)
                db.Query(value.SQL) // attribute
                db.Query(err.Error())
            }
        ''')
        self.assert_sites([('attribute', 'db.Query', 'sql')])

    def test_bound_method_immediate_closure_replacement_uses_current_cell(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                unsafeDecoder := json.NewDecoder(r.Body)
                safeDecoder := json.NewDecoder(strings.NewReader(`"fixed"`))
                decode := safeDecoder.Decode
                func() { decode = unsafeDecoder.Decode }()
                var first, second string
                decode(&first)
                db.Query(first) // installed-source
                func() { decode = safeDecoder.Decode }()
                decode(&second)
                db.Query(second)
            }
        ''')
        self.assert_sites([('installed-source', 'db.Query', 'sql')])

    def test_bound_method_callee_survives_argument_replacement_only_for_that_call(self):
        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                decoder := json.NewDecoder(r.Body)
                fixed := json.NewDecoder(strings.NewReader(`"fixed"`))
                decode := decoder.Decode
                var value, clean string
                decode(func() *string { decode = fixed.Decode; return &value }())
                db.Query(value) // selected-callee
                decode(&clean)
                db.Query(clean)
            }
        ''')
        self.assert_sites([('selected-callee', 'db.Query', 'sql')])

    def test_bound_method_delayed_captured_cell_is_not_a_fixed_receiver(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                fixed := json.NewDecoder(strings.NewReader(`"fixed"`))
                decode := fixed.Decode
                later := func() {
                    var value string
                    decode(&value)
                    db.Query(value)
                }
                decoder := json.NewDecoder(r.Body)
                decode = decoder.Decode
                later()
            }
        ''')
        with self.assertRaisesRegex(AnalysisLimit, 'decoder.*alternative'):
            self.scan()

    def test_bound_method_receiver_object_mutation_is_an_explicit_boundary(self):
        from ubs_core.taint_flow import AnalysisLimit

        for mutation in ('*decoder = *incoming', 'decoder.Strict = flag',
                         'cell := &decoder; **cell = *incoming'):
            with self.subTest(mutation=mutation):
                self.source('handler.go', 'package app\nimport ("encoding/xml"; "strings")\n'
                            'func h() {\ndecoder := xml.NewDecoder(strings.NewReader("<Value/>"))\n'
                            'decode := decoder.Decode\nincoming := xml.NewDecoder(r.Body)\n'
                            + mutation + '\nvar value Payload\ndecode(&value)\ndb.Query(value.SQL)\n}\n')
                with self.assertRaisesRegex(AnalysisLimit, 'decoder receiver mutation'):
                    self.scan()

    def test_bound_method_selected_inside_stored_closure_is_not_a_fixed_handle(self):
        from ubs_core.taint_flow import AnalysisLimit

        self.source('handler.go', '''
            package app
            import ("encoding/json"; "strings")
            func h() {
                decoder := json.NewDecoder(strings.NewReader(`"fixed"`))
                later := func() {
                    decode := decoder.Decode
                    var value string
                    decode(&value)
                    db.Query(value)
                }
                decoder = json.NewDecoder(r.Body)
                later()
            }
        ''')
        with self.assertRaisesRegex(AnalysisLimit, 'decoder.*alternative'):
            self.scan()

    def test_bound_grouped_receiver_selection_preserves_input(self):
        self.source('handler.go', '''
            package app
            import "encoding/json"
            func h() {
                decoder := json.NewDecoder(r.Body)
                first := ((decoder)).Decode
                second := ((json.NewDecoder(r.Body))).Decode
                var a, b string
                first(&a)
                second(&b)
                db.Query(a) // grouped-handle
                db.Query(b) // grouped-constructor
            }
        ''')
        self.assert_sites([('grouped-handle', 'db.Query', 'sql'), ('grouped-constructor', 'db.Query', 'sql')])

    def test_bound_method_unmodeled_storage_cannot_drop_decoder_contents(self):
        from ubs_core.taint_flow import AnalysisLimit

        for assignment, invocation in (
                ('callbacks := []func(any) error{decoder.Decode}', 'callbacks[0](&value)'),
                ('holder := Holder{}; holder.decode = decoder.Decode', 'holder.decode(&value)'),
                ('decode := opaque(decoder.Decode)', 'decode(&value)')):
            with self.subTest(assignment=assignment):
                self.source('handler.go', 'package app\nimport "encoding/json"\nfunc h() {\n'
                            'decoder := json.NewDecoder(r.Body)\n' + assignment + '\n'
                            'var value string\n' + invocation + '\ndb.Query(value)\n}\n')
                with self.assertRaisesRegex(AnalysisLimit, 'decoder.*(?:storage|transport)'):
                    self.scan()

    @unittest.skipUnless(os.environ.get('UBS_GO_DECODER_NATIVE') == '1',
                         'set UBS_GO_DECODER_NATIVE=1 for the real Go decoder-method witness')
    def test_native_method_capture_tokens_buffer_and_xml_attributes_match_findings(self):
        from test_keep_temp import prevent_child_deletion

        source = textwrap.dedent('''
            package main
            import ("encoding/json"; "encoding/xml"; "strings"; "strconv"; "os"; "io"; "fmt")
            type Recorder struct { Queries []string }
            func (db *Recorder) Query(query string) { db.Queries = append(db.Queries, query) }
            func invoke(decode func(any) error, out *string) error { return decode(out) }
            func method(input io.Reader) func(any) error { return json.NewDecoder(input).Decode }
            type Value struct { SQL string `xml:"q,attr"` }
            func main() {
                db := &Recorder{}
                input := os.Getenv("UBS_GO_DECODER_INPUT")
                decoder := json.NewDecoder(strings.NewReader(strconv.Quote(input)))
                decode := decoder.Decode
                cell := &decoder
                *cell = json.NewDecoder(strings.NewReader(`"fixed"`))
                var captured, fixed, passed, returned string
                if err := decode(&captured); err != nil { panic(err) }
                decoder.Decode(&fixed)
                db.Query(captured) // captured-native
                db.Query(fixed)
                second := json.NewDecoder(strings.NewReader(strconv.Quote(input)))
                if err := invoke(second.Decode, &passed); err != nil { panic(err) }
                db.Query(passed) // passed-native
                clean := method(strings.NewReader(`"fixed"`))
                clean(&returned)
                db.Query(returned)
                tokens := json.NewDecoder(strings.NewReader(strconv.Quote(input)))
                token := tokens.Token
                value, tokenErr := token()
                db.Query(fmt.Sprint(value)) // token-native
                db.Query(fmt.Sprint(tokenErr))
                bufferedDecoder := json.NewDecoder(strings.NewReader("0 " + input))
                var ignored any
                bufferedDecoder.Decode(&ignored)
                buffered := bufferedDecoder.Buffered
                rest, readErr := io.ReadAll(buffered())
                if readErr != nil { panic(readErr) }
                db.Query(string(rest)) // buffered-native
                elementDecoder := xml.NewDecoder(strings.NewReader("<Value></Value>"))
                if _, err := elementDecoder.Token(); err != nil { panic(err) }
                decodeElement := elementDecoder.DecodeElement
                start := xml.StartElement{Name: xml.Name{Local: "Value"},
                    Attr: []xml.Attr{{Name: xml.Name{Local: "q"}, Value: input}}}
                var element Value
                if err := decodeElement(&element, &start); err != nil { panic(err) }
                db.Query(element.SQL) // attribute-native
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        ''').lstrip('\n')
        self.source('handler.go', source)
        artifacts = packages.ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        native = Path(tempfile.mkdtemp(prefix='go-bound-decoder-', dir=artifacts))
        program = native / 'main.go'
        program.write_text(source, encoding='utf-8')
        executable = native / 'decoder-witness'
        environment = dict(os.environ, GO111MODULE='off', GOWORK='off', GOTOOLCHAIN='local',
                           GOMAXPROCS='2', GOFLAGS='-p=2', UBS_GO_DECODER_INPUT='<supplied>')
        compiler = os.environ.get('UBS_GO_COMPILER', 'go')
        print(f'[{self.id()}] compiler={compiler} source={program}', flush=True)
        build = subprocess.run([compiler, 'build', '-work', '-o', str(executable), str(program)],
                               cwd=native, env=environment, capture_output=True, text=True,
                               timeout=180, preexec_fn=prevent_child_deletion)
        (native / 'build.stdout.log').write_text(build.stdout)
        (native / 'build.stderr.log').write_text(build.stderr)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        result = subprocess.run([str(executable)], cwd=native, env=environment, capture_output=True,
                                text=True, timeout=30, preexec_fn=prevent_child_deletion)
        (native / 'native.stdout.log').write_text(result.stdout)
        (native / 'native.stderr.log').write_text(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), ['<supplied>', 'fixed', '<supplied>', 'fixed',
                                                    '<supplied>', '<nil>', ' <supplied>', '<supplied>'])
        self.assert_sites([(marker, 'db.Query', 'sql') for marker in (
            'captured-native', 'passed-native', 'token-native', 'buffered-native', 'attribute-native')])


class HigherOrderContextLimitTests(packages.PackageTestCase):
    def test_exhausted_context_budget_is_partial_and_never_cached_as_complete(self):
        from ubs_core.findings_merge import to_sarif
        from ubs_core.taint_flow import AnalysisLimit

        self.source('first/main.go', '''
            package first
            func h() {
                db.Query(r.FormValue("q")) // retained finding
            }
        ''')
        limited = '''
            package limited
            import ("html"; "text/template")
            func apply(escape func(string) string, value string) string { return escape(value) }
            func h() {
                _ = apply(html.EscapeString, r.FormValue("q"))
                _ = apply(template.HTMLEscapeString, r.FormValue("q"))
            }
        '''
        self.source('limited/main.go', limited)
        listing = self.root / 'files.nul'
        listing.write_bytes(b'\0'.join(os.fsencode(path) for path in self.sources.values()) + b'\0')
        sink = self.root / 'findings.ndjson'
        report = self.root / 'summary.json'
        stats = self.root / 'cache-stats.json'

        def scan_main():
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                status = packages.go_scan.main([
                    '--files-from', str(listing), '--sink', str(sink),
                    '--project-dir', str(self.root), '--json-out', str(report),
                ])
            self.assertNotIn('Traceback', output.getvalue())
            return status, json.loads(report.read_text()), json.loads(stats.read_text())

        environment = dict(UBS_CACHE_DIR=str(self.root / 'cache'), UBS_NO_CACHE='0',
                           UBS_CACHE_FILE=str(stats), UBS_NO_AUTO_UPDATE='1')
        with patch.object(packages.taint_go, 'NATIVE_CONTEXT_LIMIT', 1), patch.dict(os.environ, environment):
            with self.assertRaisesRegex(AnalysisLimit, 'native callable context limit'):
                self.scan()
            for attempt in range(2):
                with self.subTest(attempt=attempt):
                    status, document, cache = scan_main()
                    self.assertEqual(status, 2, document)
                    self.assertEqual(document['status'], 'partial', document)
                    self.assertEqual(document['module_error'], 'ANALYZER_ERROR', document)
                    self.assertIn('native callable context limit', document['message'])
                    taint = [(Path(row['path']), row['line'], row['col'], row['rule'])
                             for row in document['findings'] if row['rule'].startswith('go.taint.')]
                    self.assertEqual(taint, [(self.sources['first/main.go'], 3, 5, 'go.taint.sql')])
                    self.assertEqual((cache['hits'], cache['misses']), (0, 2), cache)
                    sarif = to_sarif(document)
                    self.assertTrue(sarif['runs'], sarif)
                    for run in sarif['runs']:
                        invocation = run['invocations'][0]
                        self.assertFalse(invocation['executionSuccessful'])
                        self.assertEqual(invocation['exitCode'], 2)
                        self.assertTrue(any('native callable context limit' in item['message']['text']
                                            for item in invocation['toolExecutionNotifications']))

            # With only one native identity the same real helper can finish;
            # only that completed answer may become a subsequent cache hit.
            self.source('limited/main.go', '''
                package limited
                import "html"
                func apply(escape func(string) string, value string) string { return escape(value) }
                func h() { _ = apply(html.EscapeString, r.FormValue("q")) }
            ''')
            status, document, cache = scan_main()
            self.assertEqual((status, document['status']), (1, 'ok'), document)
            self.assertNotIn('module_error', document)
            self.assertEqual((cache['hits'], cache['misses']), (0, 2), cache)
            status, document, cache = scan_main()
            self.assertEqual((status, document['status']), (1, 'ok'), document)
            self.assertEqual((cache['hits'], cache['misses']), (2, 0), cache)


class NativeCallableMutationTests(packages.PackageTestCase):
    def check(self, body, *, globals='', helpers='', expected=()):
        path = self.source('handler.go', 'package app\nimport "html"\n' + globals + '\n'
                           'func h() {\n' + body + '\n}\n' + helpers + '\n')
        lines = path.read_text().splitlines()
        hits = []
        for marker in expected:
            matches = [index for index, line in enumerate(lines, 1) if '// ' + marker in line]
            self.assertEqual(len(matches), 1, (marker, lines))
            hits.append(('handler.go', matches[0], 'go.taint.xss'))
        self.assert_hits(hits)

    def test_unknown_pointer_escape_invalidates_only_the_addressed_binding(self):
        self.check('escape := html.EscapeString\nsaved := escape\n'
                   'pointer := &escape\nreplace(pointer)\nvalue := r.FormValue("q")\n'
                   'fmt.Fprint(w, saved(value))\nfmt.Fprint(w, escape(value)) // replaced',
                   expected=('replaced',))

    def test_helper_pointer_write_cannot_keep_old_sanitizer_proof(self):
        self.check('escape := html.EscapeString\nreplace(&escape)\n'
                   'fmt.Fprint(w, escape(r.FormValue("q"))) // replaced',
                   helpers='func replace(p *func(string) string) { *p = identity }\n'
                           'func identity(value string) string { return value }',
                   expected=('replaced',))

    def test_direct_pointer_write_cannot_keep_old_sanitizer_proof(self):
        self.check('escape := html.EscapeString\npointer := &escape\n'
                   '*pointer = identity\nfmt.Fprint(w, escape(r.FormValue("q"))) // replaced',
                   helpers='func identity(value string) string { return value }',
                   expected=('replaced',))

    def test_closure_write_invalidates_capture_but_not_an_earlier_value_copy(self):
        for invoke in ('func() { escape = identity }()',
                       'replace := func() { escape = identity }; replace()'):
            with self.subTest(invoke=invoke):
                self.check('escape := html.EscapeString\nsaved := escape\n' + invoke + '\n'
                           'value := r.FormValue("q")\nfmt.Fprint(w, saved(value))\n'
                           'fmt.Fprint(w, escape(value)) // replaced',
                           helpers='func identity(value string) string { return value }',
                           expected=('replaced',))

    def test_closure_local_shadow_does_not_invalidate_outer_callable(self):
        self.check('escape := html.EscapeString\n'
                   'func() { escape := identity; _ = escape }()\n'
                   'fmt.Fprint(w, escape(r.FormValue("q")))',
                   helpers='func identity(value string) string { return value }')

    def test_stable_forward_package_alias_keeps_native_authority(self):
        self.check('fmt.Fprint(w, escape(r.FormValue("q")))',
                   globals='var escape = original\nvar original = html.EscapeString')

    def test_package_write_in_another_function_invalidates_initializer_authority(self):
        self.check('replace()\nfmt.Fprint(w, escape(r.FormValue("q"))) // replaced',
                   globals='var escape = html.EscapeString',
                   helpers='func replace() { escape = identity }\n'
                           'func identity(value string) string { return value }',
                   expected=('replaced',))

    def test_global_alias_retains_its_defining_file_import_identity(self):
        self.source('factory.go', 'package app\nimport html "html"\nvar escaped = html.EscapeString\n')
        self.source('handler.go', 'package app\nimport html "example.test/html"\n'
                    'func h() { fmt.Fprint(w, escaped(r.FormValue("q"))) }\n')
        self.assert_hits([])

    def test_earlier_argument_pointer_effect_prevents_later_sanitizer_proof(self):
        self.check('escape := html.EscapeString\n'
                   'fmt.Fprint(w, replace(&escape), escape(r.FormValue("q"))) // replaced',
                   helpers='func replace(p *func(string) string) string { *p = identity; return "" }\n'
                           'func identity(value string) string { return value }',
                   expected=('replaced',))

    def test_saved_escape_covers_a_package_helpers_return_value(self):
        self.check('escape := html.EscapeString\n'
                   'fmt.Fprint(w, escape(identity(r.FormValue("q"))))',
                   helpers='func identity(value string) string { return value }')

    def test_saved_escape_retains_argument_sinks_without_tainting_escaped_return(self):
        self.check('escape := html.EscapeString\n'
                   'fmt.Fprint(w, escape(emit(r.FormValue("q")))) // argument-sink',
                   helpers='func emit(value string) string { fmt.Fprint(w, value); return value }',
                   expected=('argument-sink',))


class ImportIdentityTests(packages.PackageTestCase):
    def test_saved_unmarshal_functions_preserve_destination_and_error_positions(self):
        for package in ('encoding/json', 'encoding/xml'):
            for binding in ('codec.Unmarshal', '(codec.Unmarshal)'):
                with self.subTest(package=package, binding=binding):
                    self.source('handler.go', 'package app\nimport codec "' + package + '"\n'
                                'func h() {\nvar p Payload\n'
                                'decode := ' + binding + '\ncopy := decode\n'
                                'err := copy([]byte(r.FormValue("body")), &p)\n'
                                'db.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                    self.assert_hits([('handler.go', 8, 'go.taint.sql')])

    def test_saved_readers_and_factories_keep_native_return_shapes(self):
        self.source('handler.go', '''
            package app
            import (stream "io"; codec "encoding/json")
            func h() {
                read := stream.ReadAll
                newDecoder := codec.NewDecoder
                raw, err := read(r.Body)
                var first, second Payload
                newDecoder(r.Body).Decode(&first)
                dec := newDecoder(r.Body)
                dec.Decode(&second)
                db.Query(string(raw))
                db.Query(first.SQL)
                db.Query(second.SQL)
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', line, 'go.taint.sql') for line in (11, 12, 13)])

    def test_saved_dot_import_and_helper_pointer_write(self):
        self.source('helper.go', '''
            package app
            import . "encoding/xml"
            func decode(raw []byte, target *Payload) {
                saved := Unmarshal
                saved(raw, target)
            }
        ''')
        self.source('handler.go', '''
            package app
            func h() {
                var p Payload
                decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 5, 'go.taint.sql')])

    def test_saved_function_rebinding_does_not_change_existing_alias(self):
        self.source('handler.go', '''
            package app
            import codec "encoding/json"
            func h() {
                var first, second Payload
                decode := codec.Unmarshal
                saved := decode
                decode = unrelated
                decode([]byte(r.FormValue("body")), &first)
                saved([]byte(r.FormValue("body")), &second)
                db.Query(first.SQL)
                db.Query(second.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 11, 'go.taint.sql')])

    def test_saved_function_branch_keeps_possible_destination_writes(self):
        self.source('handler.go', '''
            package app
            import codec "encoding/json"
            func h() {
                var first, second Payload
                decode := codec.Unmarshal
                if choice { decode = unrelated }
                decode([]byte(r.FormValue("body")), &first)
                var other func([]byte, any) error
                if choice { other = codec.Unmarshal }
                other([]byte(r.FormValue("body")), &second)
                db.Query(first.SQL)
                db.Query(second.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 11, 'go.taint.sql'), ('handler.go', 12, 'go.taint.sql')])

    def test_saved_functions_respect_shadowing_and_file_import_identity(self):
        self.source('a.go', '''
            package app
            import codec "example.com/decoder"
            func a() {
                var p Payload
                decode := codec.Unmarshal
                decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
            }
        ''')
        self.source('b.go', '''
            package app
            import codec "encoding/json"
            func b() {
                var outer, inner Payload
                decode := codec.Unmarshal
                { decode := unrelated; decode([]byte(r.FormValue("body")), &inner) }
                decode([]byte(r.FormValue("body")), &outer)
                db.Query(inner.SQL)
                db.Query(outer.SQL)
            }
        ''')
        self.assert_hits([('b.go', 9, 'go.taint.sql')])

    def test_saved_native_functions_keep_clean_inputs_and_bound_queries_clean(self):
        self.source('handler.go', '''
            package app
            import codec "encoding/json"
            func h() {
                var clean, input Payload
                decode := codec.Unmarshal
                decode([]byte(`{"SQL":"SELECT 1"}`), &clean)
                decode([]byte(r.FormValue("body")), &input)
                db.Query(clean.SQL)
                db.Query("SELECT $1", input.SQL)
            }
        ''')
        self.assert_hits([])

    def test_aliased_json_and_xml_decode_destinations(self):
        for path, operation in (('encoding/json', 'Decode(&p)'),
                                ('encoding/xml', 'DecodeElement(&p, &start)')):
            for constructor in ('codec.NewDecoder(r.Body)', '(codec.NewDecoder(r.Body))'):
                with self.subTest(path=path, constructor=constructor):
                    self.source('handler.go', 'package app\nimport codec "' + path + '"\n'
                                'func h() {\nvar p Payload\n'
                                'dec := ' + constructor + '\nalias := dec\n'
                                'err := alias.' + operation + '\n'
                                'db.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                    self.assert_hits([('handler.go', 8, 'go.taint.sql')])

    def test_aliased_readall_and_unmarshal_keep_result_positions(self):
        for reader in ('io', 'io/ioutil'):
            for decoder in ('encoding/json', 'encoding/xml'):
                with self.subTest(reader=reader, decoder=decoder):
                    self.source('handler.go', 'package app\nimport (\n'
                                'stream "' + reader + '"\ncodec "' + decoder + '"\n)\n'
                                'func h() {\nraw, readErr := stream.ReadAll(r.Body)\nvar p Payload\n'
                                'decodeErr := codec.Unmarshal(raw, &p)\n'
                                'db.Query(string(raw))\ndb.Query(p.SQL)\n'
                                'db.Query(readErr.Error())\ndb.Query(decodeErr.Error())\n}\n')
                    self.assert_hits([('handler.go', 10, 'go.taint.sql'),
                                      ('handler.go', 11, 'go.taint.sql')])

    def test_dot_imports_resolve_constructor_unmarshal_and_readall(self):
        self.source('handler.go', '''
            package app
            import (
                . "encoding/json"
                . "io"
            )
            func h() {
                raw, readErr := ReadAll(r.Body)
                var first, second Payload
                decodeErr := NewDecoder(r.Body).Decode(&first)
                unmarshalErr := Unmarshal(raw, &second)
                db.Query(first.SQL)
                db.Query(second.SQL)
                db.Query(readErr.Error())
                db.Query(decodeErr.Error())
                db.Query(unmarshalErr.Error())
            }
        ''')
        self.assert_hits([('handler.go', 11, 'go.taint.sql'), ('handler.go', 12, 'go.taint.sql')])

    def test_grouped_comments_raw_and_escaped_import_paths(self):
        for literal in ('`encoding/json`', r'"\x65ncoding/json"', r'"encoding/\u006ason"'):
            with self.subTest(literal=literal):
                self.source('handler.go', 'package app\nimport (\n'
                            'codec /* alias comment */ ' + literal + '\n'
                            'stream `io` // import json "example.com/json"\n)\n'
                            'func h() {\nraw, err := stream.ReadAll(r.Body)\nvar p Payload\n'
                            'codec.Unmarshal(raw, &p)\ndb.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                self.assert_hits([('handler.go', 10, 'go.taint.sql')])

    def test_same_alias_has_separate_identity_in_each_file(self):
        for filename, path in (('a.go', 'encoding/json'), ('b.go', 'example.com/json')):
            self.source(filename, 'package app\nimport codec "' + path + '"\n'
                        'func ' + filename[0] + '() {\nvar p Payload\n'
                        'codec.NewDecoder(r.Body).Decode(&p)\ndb.Query(p.SQL)\n}\n')
        self.assert_hits([('a.go', 6, 'go.taint.sql')])
        self.assert_hits([('a.go', 6, 'go.taint.sql')], selected=list(reversed(list(self.sources.values()))))
        self.assert_hits([], selected=[self.sources['b.go']])

    def test_default_name_and_alias_do_not_cross_file_boundaries(self):
        self.source('a.go', '''
            package app
            import json "example.com/json"
            func a() {
                var p Payload
                err := json.Unmarshal([]byte(r.FormValue("body")), &p)
                db.Query(err.Error())
                db.Query(p.SQL)
            }
        ''')
        self.source('b.go', '''
            package app
            import "encoding/json"
            func b() {
                var p Payload
                err := json.Unmarshal([]byte(r.FormValue("body")), &p)
                db.Query(err.Error())
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('a.go', 6, 'go.taint.sql'), ('b.go', 7, 'go.taint.sql')])

    def test_unknown_reader_import_does_not_get_a_clean_error_contract(self):
        self.source('handler.go', '''
            package app
            import io "example.com/reader"
            func h() {
                raw, err := io.ReadAll(r.Body)
                db.Query(string(raw))
                db.Query(err.Error())
            }
        ''')
        self.assert_hits([('handler.go', 5, 'go.taint.sql'), ('handler.go', 6, 'go.taint.sql')])

    def test_blank_import_and_other_imports_do_not_bind_canonical_names(self):
        for declaration in ('import _ "encoding/json"', 'import codec "encoding/json"', 'import "fmt"'):
            with self.subTest(declaration=declaration):
                self.source('handler.go', 'package app\n' + declaration + '\nfunc h() {\n'
                            'var p Payload\nerr := json.Unmarshal([]byte(r.FormValue("body")), &p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_parameter_and_block_declarations_shadow_imports(self):
        self.source('handler.go', '''
            package app
            import codec "encoding/json"
            func shadowed(codec CustomDecoder) {
                var p Payload
                codec.NewDecoder(r.Body).Decode(&p)
                db.Query(p.SQL)
            }
            func h() {
                var inner, outer Payload
                { codec := custom; codec.NewDecoder(r.Body).Decode(&inner) }
                db.Query(inner.SQL)
                codec.NewDecoder(r.Body).Decode(&outer)
                db.Query(outer.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 13, 'go.taint.sql')])

    def test_local_type_names_shadow_imports(self):
        for declaration in ('type codec CustomDecoder', 'type (codec = CustomDecoder)'):
            with self.subTest(declaration=declaration):
                self.source('handler.go', 'package app\nimport codec "encoding/json"\n'
                            'func h() {\n' + declaration + '\nvar p Payload\n'
                            'codec.NewDecoder(r.Body).Decode(&p)\ndb.Query(p.SQL)\n}\n')
                self.assert_hits([])

    def test_dot_import_name_is_shadowed_by_parameters_and_local_helpers(self):
        self.source('handler.go', '''
            package app
            import . "encoding/json"
            func h(NewDecoder CustomFactory) {
                var p Payload
                NewDecoder(r.Body).Decode(&p)
                db.Query(p.SQL)
                db.Query(Unmarshal(r.FormValue("q")))
            }
            func Unmarshal(value string) string { return value }
        ''')
        self.assert_hits([('handler.go', 7, 'go.taint.sql')])

    def test_ambiguous_dot_imports_do_not_prove_native_behavior(self):
        for other in ('encoding/xml', 'example.com/decoder'):
            with self.subTest(other=other):
                self.source('handler.go', 'package app\nimport (\n. "encoding/json"\n. "' + other + '"\n)\n'
                            'func h() {\nvar p Payload\n'
                            'err := Unmarshal([]byte(r.FormValue("body")), &p)\n'
                            'db.Query(p.SQL)\ndb.Query(err.Error())\n}\n')
                self.assert_hits([('handler.go', 10, 'go.taint.sql')])

    def test_import_text_in_comments_and_literals_is_inert(self):
        self.source('handler.go', '''
            package app
            // import codec "encoding/json"
            /* import . "encoding/json" */
            const text = `import codec "encoding/json"`
            func h() {
                var first, second Payload
                codec.NewDecoder(r.Body).Decode(&first)
                NewDecoder(r.Body).Decode(&second)
                db.Query(first.SQL)
                db.Query(second.SQL)
            }
        ''')
        self.assert_hits([])

    def test_closure_keeps_its_file_import_context(self):
        self.source('a.go', 'package app\nimport codec "example.com/json"\nfunc a() {}\n')
        self.source('b.go', '''
            package app
            import codec "encoding/json"
            func h() {
                query := func() string {
                    var p Payload
                    codec.NewDecoder(r.Body).Decode(&p)
                    return p.SQL
                }()
                db.Query(query)
            }
        ''')
        self.assert_hits([('b.go', 9, 'go.taint.sql')])

    def test_helper_pointer_summary_uses_its_own_imports(self):
        self.source('helper.go', '''
            package app
            import codec "encoding/xml"
            func decode(raw []byte, dst *Payload) { codec.Unmarshal(raw, dst) }
        ''')
        self.source('handler.go', '''
            package app
            import codec "example.com/json"
            func h() {
                var p Payload
                decode([]byte(r.FormValue("body")), &p)
                db.Query(p.SQL)
            }
        ''')
        self.assert_hits([('handler.go', 6, 'go.taint.sql')])

    def test_global_initializers_use_each_files_imports(self):
        self.source('a.go', '''
            package app
            import codec "example.com/json"
            var query = read()
            var result = db.Query(query)
        ''')
        self.source('b.go', '''
            package app
            import codec "encoding/json"
            func read() string {
                var p Payload
                codec.NewDecoder(r.Body).Decode(&p)
                return p.SQL
            }
        ''')
        self.assert_hits([('a.go', 4, 'go.taint.sql')])

    def test_clean_input_and_bound_sql_stay_clean_with_import_aliases(self):
        self.source('handler.go', '''
            package app
            import (codec "encoding/json"; "strings")
            func h() {
                var clean, input Payload
                codec.NewDecoder(strings.NewReader(`{"SQL":"SELECT 1"}`)).Decode(&clean)
                db.Query(clean.SQL)
                codec.NewDecoder(r.Body).Decode(&input)
                db.Query("SELECT $1", input.SQL)
            }
        ''')
        self.assert_hits([])


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real scanner tests')
class DecodingRunnerTests(unittest.TestCase):
    def test_bound_decoder_methods_in_public_reports(self):
        from test_keep_temp import prevent_child_deletion

        cases = (
            ('captured', 'decoder := json.NewDecoder(r.Body)\ndecode := decoder.Decode\n'
             'decoder = json.NewDecoder(strings.NewReader(`"fixed"`))\n'
             'var value string\nerr := decode(&value)\ndb.Query(value) // expect-sql\n'
             'fmt.Fprint(w, err)\ndb.Query("SELECT $1", value)', False),
            ('token', 'decoder := json.NewDecoder(r.Body)\ntoken := decoder.Token\n'
             'value, err := token()\nfmt.Fprint(w, value) // expect-xss\nfmt.Fprint(w, err)', False),
            ('fixed', 'decoder := json.NewDecoder(strings.NewReader(`"fixed"`))\n'
             'decode := decoder.Decode\nvar value string\ndecode(&value)\ndb.Query(value)', False),
            ('suppressed', 'decoder := json.NewDecoder(r.Body)\ndecode := decoder.Decode\n'
             'var value string\ndecode(&value)\ndb.Query(value) // ubs:ignore[go.taint.sql]', False),
            ('xml-attribute', 'decoder := xml.NewDecoder(strings.NewReader("<Value></Value>"))\ndecoder.Token()\n'
             'decode := decoder.DecodeElement\nstart := xml.StartElement{Name: xml.Name{Local: "Value"},\n'
             'Attr: []xml.Attr{{Name: xml.Name{Local: "q"}, Value: r.FormValue("q")}}}\n'
             'var value Payload\nerr := decode(&value, &start)\n'
             'db.Query(value.SQL) // expect-sql\nfmt.Fprint(w, err)', False),
            ('partial', 'db.Query(r.FormValue("q")) // expect-sql\n'
             'decoder := json.NewDecoder(r.Body)\ndecode := decoder.Decode\n'
             'if choose { decode = foreign }\nvar value string\ndecode(&value)\ndb.Query(value)', True),
            ('weak-pointer', 'db.Query(r.FormValue("q")) // expect-sql\n'
             'var first, second func(any) error\np := &first\nif choose { p = &second }\n'
             '*p = json.NewDecoder(r.Body).Decode\nvar value string\nfirst(&value)\ndb.Query(value)', True),
        )
        artifacts = packages.ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix='go-bound-decoder-public-', dir=artifacts))
        skipped = ','.join(str(category) for category in range(1, 23) if category != 9)
        for name, body, partial in cases:
            folder = root / name
            folder.mkdir()
            source = ('package app\nimport ("encoding/json"; "encoding/xml"; "strings"; "fmt")\n'
                      'func h() {\n' + body + '\n}\n')
            path = folder / 'handler.go'
            path.write_text(source)
            (folder / 'unselected.go').write_text('package app\nfunc h() { db.Query(r.FormValue("q")) }\n')
            expected = [(number, line.index(callee) + 1, 'go.taint.' + rule)
                        for number, line in enumerate(source.splitlines(), 1)
                        for rule, callee in (('sql', 'db.Query'), ('xss', 'fmt.Fprint'))
                        if '// expect-' + rule in line]
            for meta in (False, True):
                for output in ('json', 'sarif'):
                    with self.subTest(case=name, meta=meta, format=output):
                        command = [str(packages.ROOT / ('ubs' if meta else 'modules/ubs-golang.sh')),
                                   str(path), '--ci', '--no-color', '--format=' + output, '--skip=' + skipped]
                        if meta:
                            command.append('--only=golang')
                        result = subprocess.run(command, cwd=folder, capture_output=True, text=True,
                                                timeout=45, preexec_fn=prevent_child_deletion,
                                                env=dict(os.environ, UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1',
                                                         UBS_NO_CACHE='1', UBS_CACHE_DIR=str(folder / 'cache')))
                        prefix = folder / f'{meta}-{output}'
                        prefix.with_suffix('.stdout.log').write_text(result.stdout)
                        prefix.with_suffix('.stderr.log').write_text(result.stderr)
                        self.assertEqual(result.returncode, 2 if partial else 1 if expected else 0,
                                         (command, result.stdout, result.stderr))
                        report = json.loads(result.stdout)
                        if output == 'json':
                            self.assertEqual(report['status'], 'partial' if partial else 'ok', report)
                            totals = report['totals'] if meta else report
                            self.assertEqual([totals[key] for key in ('files', 'critical', 'warning', 'info')],
                                             [1, len(expected), 0, 0], report)
                            actual = [(row['line'], row['col'], row['rule_id' if meta else 'rule'])
                                      for row in report['findings']]
                            for row in report['findings']:
                                self.assertEqual(Path(row['file' if meta else 'path']).name, path.name, row)
                                self.assertEqual(row['severity'], 'critical', row)
                        else:
                            self.assertEqual(report['version'], '2.1.0', report)
                            runs = [run for run in report['runs']
                                    if run['tool']['driver']['name'] == 'ubs-golang-heuristics']
                            self.assertTrue(runs, report)
                            if partial:
                                self.assertTrue(any(
                                    not invocation['executionSuccessful'] and invocation.get('exitCode') == 2
                                    and any('decoder' in notice.get('message', {}).get('text', '')
                                            for notice in invocation.get('toolExecutionNotifications', []))
                                    for run in runs for invocation in run.get('invocations', [])), report)
                            actual = []
                            for run in report['runs']:
                                for invocation in run.get('invocations', []):
                                    if not partial:
                                        self.assertTrue(invocation['executionSuccessful'], invocation)
                                for row in run.get('results', []):
                                    location = row['locations'][0]['physicalLocation']
                                    region = location['region']
                                    self.assertEqual(Path(location['artifactLocation']['uri']).name, path.name, row)
                                    self.assertEqual(row['level'], 'error', row)
                                    actual.append((region['startLine'], region['startColumn'], row['ruleId']))
                        self.assertEqual(sorted(actual), sorted(expected), report)
                        if partial:
                            self.assertIn('decoder', json.dumps(report), report)
                        print('GO_BOUND_DECODER_PUBLIC_PASS', name, 'runner' if meta else 'module', output, flush=True)

    def test_actual_json_and_sarif_include_decoded_request_flows(self):
        cases = [
            ('decode-sql', '', '', 'var p Payload; json.NewDecoder(r.Body).Decode(&p); db.Query(p.SQL)', {'sql'}),
            ('decode-command', '', '', 'dec := json.NewDecoder(r.Body); var p Payload; dec.Decode(&p); '
             'exec.Command("sh", "-c", p.Command)', {'command'}),
            ('unmarshal-xss', '', '', 'raw, _ := io.ReadAll(r.Body); var p Payload; '
             'json.Unmarshal(raw, &p); fmt.Fprint(w, p.HTML)', {'xss'}),
            ('error-not-input', '', '', 'var p Payload; err := json.NewDecoder(r.Body).Decode(&p); '
             'db.Query(err.Error())', set()),
            ('clean-document', '', '', 'var p Payload; json.Unmarshal([]byte(`{}`), &p); db.Query(p.SQL)', set()),
            ('helper-output', '', 'func decode(raw []byte, dst *Payload) { json.Unmarshal(raw, dst) }',
             'raw, _ := io.ReadAll(r.Body); var p Payload; decode(raw, &p); db.Query(p.SQL)', {'sql'}),
            ('import-alias', 'import codec "encoding/json"', '',
             'var p Payload; codec.NewDecoder(r.Body).Decode(&p); db.Query(p.SQL)', {'sql'}),
            ('dot-import', 'import . "encoding/xml"', '',
             'var p Payload; NewDecoder(r.Body).Decode(&p); fmt.Fprint(w, p.HTML)', {'xss'}),
            ('aliased-errors', 'import (stream "io"; codec "encoding/json")', '',
             'raw, err := stream.ReadAll(r.Body); var p Payload; decodeErr := codec.Unmarshal(raw, &p); '
             'db.Query(err.Error()); db.Query(decodeErr.Error())', set()),
            ('import-helper', 'import codec "example.com/decoder"',
             'import codec "encoding/json"\nfunc decode(raw []byte, dst *Payload) { codec.Unmarshal(raw, dst) }',
             'var p Payload; decode([]byte(r.FormValue("body")), &p); db.Query(p.SQL)', {'sql'}),
            ('saved-unmarshal', 'import ("encoding/json"; "io")', '',
             'read := io.ReadAll; decode := json.Unmarshal; raw, readErr := read(r.Body); '
             'var p Payload; decodeErr := decode(raw, &p); db.Query(p.SQL); '
             'db.Query(readErr.Error()); db.Query(decodeErr.Error())', {'sql'}),
            ('saved-factory', 'import "encoding/xml"', '',
             'factory := xml.NewDecoder; var p Payload; err := factory(r.Body).Decode(&p); '
             'fmt.Fprint(w, p.HTML); db.Query(err.Error())', {'xss'}),
            ('saved-native-choice', 'import ("encoding/json"; "encoding/xml")', '',
             'decode := json.Unmarshal; if choice { decode = xml.Unmarshal }; '
             'var p Payload; decode([]byte(r.FormValue("body")), &p); db.Query(p.SQL)', {'sql'}),
            ('saved-clean-input', 'import "encoding/json"', '',
             'decode := json.Unmarshal; var p Payload; decode([]byte(`{"SQL":"SELECT 1"}`), &p); '
             'db.Query(p.SQL)', set()),
            ('parenthesized-write', 'import "encoding/json"', '',
             'var p Payload; err := ((json.Unmarshal))([]byte(r.FormValue("body")), &p); '
             '(db.Query)(p.SQL); db.Query(err.Error()); db.Query("SELECT $1", p.SQL)', {'sql'}),
            ('parenthesized-reader', 'import "io"', '',
             'read := io.ReadAll; raw, err := (read)(r.Body); '
             'db.Query(string(raw)); db.Query(err.Error())', {'sql'}),
            ('parenthesized-helper', '',
             'import "encoding/json"\nfunc decode(raw []byte, dst *Payload) error { return (json.Unmarshal)(raw, dst) }',
             'var p Payload; err := (decode)([]byte(r.FormValue("body")), &p); '
             'db.Query(p.SQL); db.Query(err.Error())', {'sql'}),
            ('parenthesized-escape', 'import "html"', '',
             'escape := html.EscapeString; fmt.Fprint(w, ((escape))(r.FormValue("q")))', set()),
            ('parenthesized-bound-query', 'import "encoding/json"', '',
             'var p Payload; (json.Unmarshal)([]byte(r.FormValue("body")), &p); '
             '(db.Query)("SELECT $1", p.SQL)', set()),
        ]
        artifacts = packages.ROOT / 'test-suite/artifacts/go-decoding'
        for name, imports, helper, body, expected in cases:
            for format_name in ('json', 'sarif'):
                with self.subTest(case=name, format=format_name), temporary_directory(prefix='ubs-decode-e2e-') as tmp:
                    project = Path(tmp)
                    (project / 'handler.go').write_text('package app\n' + imports + '\nfunc h() { ' + body + ' }\n')
                    (project / 'helper.go').write_text('package app\n' + helper + '\n')
                    result = subprocess.run([str(packages.ROOT / 'ubs'), str(project), '--only=golang',
                                             '--ci', '--format=' + format_name], cwd=tmp, capture_output=True,
                                            text=True, timeout=180,
                                            env=dict(os.environ, UBS_NO_AUTO_UPDATE='1',
                                                     UBS_CACHE_DIR=str(project / 'cache')))
                    folder = artifacts / (name + '-' + format_name)
                    folder.mkdir(parents=True, exist_ok=True)
                    (folder / 'stdout.log').write_text(result.stdout)
                    (folder / 'stderr.log').write_text(result.stderr)
                    self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    if format_name == 'json':
                        self.assertEqual(report['status'], 'ok', report)
                    rules = set()
                    def visit(value):
                        if isinstance(value, dict):
                            for key in ('rule', 'rule_id', 'ruleId'):
                                rule = value.get(key)
                                if isinstance(rule, str) and rule.startswith(('go.taint.', 'golang.taint.')):
                                    rules.add(rule.rsplit('.', 1)[-1])
                            for child in value.values():
                                visit(child)
                        elif isinstance(value, list):
                            for child in value:
                                visit(child)
                    visit(report)
                    self.assertEqual(rules, expected, report)
                    print('GO_DECODE_E2E_PASS', name, format_name, sorted(rules), flush=True)

    def test_higher_order_function_flow_in_public_reports(self):
        cases = [
            ('callback-destination', '''
                package app
                import ("encoding/json"; "net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    read := reader()
                    raw, readErr := read(r.Body)
                    var p Payload
                    err := invoke(json.Unmarshal, raw, &p)
                    db.Query(p.SQL) // expect-sql
                    if readErr != nil { db.Query(readErr.Error()) }
                    if err != nil { db.Query(err.Error()) }
                    db.Query("SELECT $1", p.SQL)
                }
            ''', '''
                package app
                import "io"
                type Payload struct { SQL string }
                func reader() func(io.Reader) ([]byte, error) { return io.ReadAll }
                func invoke(call func([]byte, any) error, data []byte, dst *Payload) error {
                    return call(data, dst)
                }
            '''),
            ('decoder-handle', '''
                package app
                import ("net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    decoder := wrap(factory(), r.Body)
                    var p Payload
                    err := decodeHandle(decoder, &p)
                    db.Query(p.SQL) // expect-sql
                    if err != nil { db.Query(err.Error()) }
                }
            ''', '''
                package app
                import ("encoding/json"; "io")
                type Payload struct { SQL string }
                func factory() func(io.Reader) *json.Decoder { return json.NewDecoder }
                func wrap(makeDecoder func(io.Reader) *json.Decoder, input io.Reader) *json.Decoder {
                    return makeDecoder(input)
                }
                func decodeHandle(decoder *json.Decoder, dst *Payload) error {
                    return decoder.Decode(dst)
                }
            '''),
            ('sanitizer-domains', '''
                package app
                import ("html"; "fmt"; "os/exec"; "net/http"; "database/sql")
                func h(r *http.Request, w http.ResponseWriter, db *sql.DB) {
                    value := r.FormValue("q")
                    safe := apply(keep(html.EscapeString), value)
                    fmt.Fprint(w, safe)
                    db.Query(safe) // expect-sql
                    exec.Command("sh", "-c", safe) // expect-command
                    fmt.Fprint(w, apply(raw, value)) // expect-xss
                }
            ''', '''
                package app
                func raw(value string) string { return value }
                func keep(call func(string) string) func(string) string { return call }
                func apply(call func(string) string, value string) string { return call(value) }
            '''),
            ('fixed-and-bound-input', '''
                package app
                import ("encoding/json"; "net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    var fixed, input Payload
                    invoke(json.Unmarshal, []byte(`{"SQL":"SELECT 1"}`), &fixed)
                    db.Query(fixed.SQL)
                    invoke(json.Unmarshal, []byte(r.FormValue("body")), &input)
                    db.Query("SELECT $1", input.SQL)
                }
            ''', '''
                package app
                type Payload struct { SQL string }
                func invoke(call func([]byte, any) error, data []byte, dst *Payload) error {
                    return call(data, dst)
                }
            '''),
            ('ordinary-pointer-output', '''
                package app
                import ("net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    value := "fixed"
                    saved := value
                    forward(&value, r.FormValue("q"))
                    db.Query(value) // expect-sql
                    db.Query(saved)
                    db.Query("SELECT $1", value)
                }
            ''', '''
                package app
                func assign(out *string, input string) { *out = input }
                func forward(out *string, input string) { assign(out, input) }
            '''),
            ('ordinary-selector-output', '''
                package app
                import ("net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    var value, untouched Payload
                    assign(&value, r.FormValue("q"))
                    value.HTML = "fixed"
                    db.Query(value.SQL) // expect-sql
                    db.Query(untouched.SQL)
                }
            ''', '''
                package app
                type Payload struct { SQL string; HTML string }
                func assign(out *Payload, input string) { out.SQL = input }
            '''),
            ('ordinary-write-sanitizer-domains', '''
                package app
                import ("html"; "fmt"; "net/http"; "database/sql")
                func h(r *http.Request, w http.ResponseWriter, db *sql.DB) {
                    value := "fixed"
                    out := &value
                    *out = html.EscapeString(r.FormValue("q"))
                    fmt.Fprint(w, value)
                    db.Query(value) // expect-sql
                    db.Query("SELECT $1", value)
                }
            ''', 'package app\n'),
            ('ordinary-reset-and-copy-controls', '''
                package app
                import ("net/http"; "database/sql")
                func h(r *http.Request, db *sql.DB) {
                    value := r.FormValue("q")
                    out := &value
                    *out = "fixed"
                    var payload Payload
                    copied(payload, r.FormValue("q"))
                    db.Query(value)
                    db.Query(payload.SQL)
                }
            ''', '''
                package app
                type Payload struct { SQL string }
                func copied(out Payload, input string) { out.SQL = input }
            '''),
        ]
        artifacts = packages.ROOT / 'test-suite/artifacts/go-higher-order'
        for name, handler, helper in cases:
            handler = textwrap.dedent(handler).lstrip('\n')
            helper = textwrap.dedent(helper).lstrip('\n')
            expected = sorted(
                ('handler.go', number, len(line) - len(line.lstrip()) + 1,
                 'go.taint.' + line.split('// expect-', 1)[1].strip())
                for number, line in enumerate(handler.splitlines(), 1) if '// expect-' in line
            )
            for entrypoint in ('module', 'runner'):
                for format_name in ('json', 'sarif'):
                    with self.subTest(case=name, entrypoint=entrypoint, format=format_name), \
                            temporary_directory(prefix='ubs-higher-order-e2e-') as tmp:
                        project = Path(tmp)
                        (project / 'handler.go').write_text(handler)
                        (project / 'helper.go').write_text(helper)
                        executable = packages.ROOT / ('ubs' if entrypoint == 'runner' else 'modules/ubs-golang.sh')
                        command = [str(executable), str(project), '--ci', '--format=' + format_name]
                        if entrypoint == 'runner':
                            command.append('--only=golang')
                        result = subprocess.run(command, cwd=tmp, capture_output=True, text=True, timeout=180,
                                                env=dict(os.environ, UBS_NO_AUTO_UPDATE='1',
                                                         UBS_CACHE_DIR=str(project / 'cache')))
                        folder = artifacts / (name + '-' + entrypoint + '-' + format_name)
                        folder.mkdir(parents=True, exist_ok=True)
                        (folder / 'stdout.log').write_text(result.stdout)
                        (folder / 'stderr.log').write_text(result.stderr)
                        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        actual = []
                        if format_name == 'json':
                            self.assertEqual(report['status'], 'ok', report)
                            for finding in report['findings']:
                                rule = finding.get('rule_id', finding.get('rule', ''))
                                if rule.startswith(('go.taint.', 'golang.taint.')):
                                    actual.append((Path(finding.get('file', finding.get('path', ''))).name,
                                                   finding['line'], finding['col'],
                                                   rule.replace('golang.taint.', 'go.taint.', 1)))
                        else:
                            for run in report['runs']:
                                for invocation in run.get('invocations', []):
                                    self.assertTrue(invocation['executionSuccessful'], invocation)
                                for finding in run.get('results', []):
                                    rule = finding.get('ruleId', '')
                                    if rule.startswith(('go.taint.', 'golang.taint.')):
                                        location = finding['locations'][0]['physicalLocation']
                                        actual.append((Path(location['artifactLocation']['uri']).name,
                                                       location['region']['startLine'],
                                                       location['region']['startColumn'],
                                                       rule.replace('golang.taint.', 'go.taint.', 1)))
                        self.assertEqual(sorted(actual), expected, report)
                        print('GO_HIGHER_ORDER_E2E_PASS', name, entrypoint, format_name, actual, flush=True)

    def test_native_context_exhaustion_is_publicly_incomplete(self):
        # Exercise the real production ceiling, without changing analyzer limits
        # or substituting a failing process for the registered Go analyzer.
        parameters = ', '.join(name + ' func(string) string' for name in 'abcdefghi')
        calls = []
        for choice in range(257):
            callbacks = ', '.join('html.EscapeString' if choice & (1 << bit) else 'tmpl.HTMLEscapeString'
                                  for bit in range(9))
            calls.append('    fmt.Fprint(w, apply(' + callbacks + ', r.FormValue("q")))')
        source = ('package app\nimport ("html"; tmpl "html/template"; "fmt"; "net/http")\n'
                  'func apply(' + parameters + ', value string) string { return a(value) }\n'
                  'func h(r *http.Request, w http.ResponseWriter) {\n' + '\n'.join(calls) + '\n}\n')
        artifacts = packages.ROOT / 'test-suite/artifacts/go-higher-order-budget'
        for entrypoint in ('module', 'runner'):
            with temporary_directory(prefix='ubs-native-budget-e2e-') as tmp:
                project = Path(tmp)
                (project / 'handler.go').write_text(source)
                for attempt, format_name in enumerate(('json', 'json', 'sarif')):
                    with self.subTest(entrypoint=entrypoint, format=format_name, attempt=attempt):
                        executable = packages.ROOT / ('ubs' if entrypoint == 'runner' else 'modules/ubs-golang.sh')
                        command = [str(executable), str(project), '--ci', '--format=' + format_name]
                        if entrypoint == 'runner':
                            command.append('--only=golang')
                        result = subprocess.run(command, cwd=tmp, capture_output=True, text=True, timeout=180,
                                                env=dict(os.environ, UBS_NO_AUTO_UPDATE='1',
                                                         UBS_CACHE_DIR=str(project / 'cache')))
                        folder = artifacts / (entrypoint + '-' + str(attempt) + '-' + format_name)
                        folder.mkdir(parents=True, exist_ok=True)
                        (folder / 'stdout.log').write_text(result.stdout)
                        (folder / 'stderr.log').write_text(result.stderr)
                        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                        report = json.loads(result.stdout)
                        self.assertIn('native callable context limit exceeded', json.dumps(report), report)
                        if format_name == 'json':
                            self.assertEqual(report['status'], 'partial', report)
                        else:
                            self.assertTrue(any(not invocation['executionSuccessful']
                                                for run in report['runs']
                                                for invocation in run.get('invocations', [])), report)
                        print('GO_NATIVE_BUDGET_E2E_PASS', entrypoint, format_name, attempt, flush=True)




class ComputedFactoryChainTests(unittest.TestCase):
    def analyze(self, source: str):
        with temporary_directory(prefix='ubs-go-factory-chain-') as tmp:
            path = Path(tmp) / 'handler.go'
            path.write_text(textwrap.dedent(source), encoding='utf-8')
            return list(packages.taint_go.run(packages.taint_go.RunContext(lang='go', files=[path])))

    def test_factory_chained_decoder_and_reader_calls_preserve_provenance_and_error_separation(self):
        source = r"""
            package app
            import (
                "bufio"
                "database/sql"
                j "encoding/json"
                x "encoding/xml"
                "fmt"
                "io"
                "net/http"
                "strings"
            )
            func mkJSON(r io.Reader) *j.Decoder { return j.NewDecoder(r) }
            func mkXML(r io.Reader) *x.Decoder { return x.NewDecoder(r) }
            func mkCleanJSON(r io.Reader) *j.Decoder { return j.NewDecoder(strings.NewReader(`"safe"`)) }
            func mkBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
            func mkScanned(r io.Reader) *bufio.Scanner {
                sc := bufio.NewScanner(r)
                sc.Scan()
                return sc
            }
            func mkUnscanned(r io.Reader) *bufio.Scanner { return bufio.NewScanner(r) }
            func handler(db *sql.DB, req *http.Request) {
                var a, b, c, d, clean string
                if err := mkJSON(req.Body).Decode(&a); err != nil {
                    db.Query("SELECT * FROM logs WHERE err = " + err.Error())
                }
                db.Query("SELECT * FROM u WHERE a = " + a) // json-factory-sql

                _ = mkXML(req.Body).Decode(&b)
                db.Query("SELECT * FROM u WHERE b = " + b) // xml-factory-sql

                _ = (mkJSON(req.Body)).Decode(&c)
                db.Query("SELECT * FROM u WHERE c = " + c) // paren-factory-sql

                _ = (j.NewDecoder(req.Body)).Decode(&d)
                db.Query("SELECT * FROM u WHERE d = " + d) // paren-native-sql

                _ = mkCleanJSON(req.Body).Decode(&clean)
                db.Query("SELECT * FROM u WHERE clean = " + clean)
                db.Query("SELECT * FROM u WHERE bound = $1", a)

                tok, terr := mkJSON(req.Body).Token()
                if terr != nil {
                    db.Query("SELECT * FROM logs WHERE err = " + terr.Error())
                }
                db.Query("SELECT * FROM u WHERE tok = " + fmt.Sprint(tok)) // token-factory-sql

                bufBytes, berr := io.ReadAll(mkJSON(req.Body).Buffered())
                if berr != nil {
                    db.Query("SELECT * FROM logs WHERE err = " + berr.Error())
                }
                db.Query("SELECT * FROM u WHERE buf = " + string(bufBytes)) // buffered-factory-sql

                inlineBuf, _ := io.ReadAll(j.NewDecoder(req.Body).Buffered())
                db.Query("SELECT * FROM u WHERE ibuf = " + string(inlineBuf)) // buffered-native-sql

                line, rerr := mkBufReader(req.Body).ReadString('\n')
                if rerr != nil {
                    db.Query("SELECT * FROM logs WHERE err = " + rerr.Error())
                }
                db.Query("SELECT * FROM u WHERE line = " + line) // reader-factory-sql

                db.Query("SELECT * FROM u WHERE scanned = " + mkScanned(req.Body).Text()) // scanned-factory-sql
                db.Query("SELECT * FROM u WHERE unscanned = " + mkUnscanned(req.Body).Text())
            }
        """
        findings = self.analyze(source)
        expected = {
            (number, 'go.taint.sql')
            for number, line in enumerate(textwrap.dedent(source).splitlines(), 1)
            if any(tag in line for tag in (
                '// json-factory-sql', '// xml-factory-sql', '// paren-factory-sql',
                '// paren-native-sql', '// token-factory-sql', '// buffered-factory-sql',
                '// buffered-native-sql', '// reader-factory-sql', '// scanned-factory-sql',
            ))
        }
        actual = {(row['line'], row['rule']) for row in findings}
        self.assertEqual(actual, expected, findings)

    def test_factory_chained_unsupported_reader_method_remains_incomplete(self):
        source = r"""
            package app
            import ("bufio"; "io"; "net/http")
            func mkBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
            func handler(req *http.Request) {
                buf := make([]byte, 16)
                _, _ = mkBufReader(req.Body).Read(buf)
            }
        """
        with self.assertRaises(packages.taint_go.AnalysisLimit):
            self.analyze(source)

    def test_compiled_go_witness_for_factory_chained_decoding_and_reading(self):
        handler_source = textwrap.dedent(r"""
            package main
            import (
                "bufio"
                "encoding/json"
                "encoding/xml"
                "io"
                "net/http"
                "strings"
            )
            type database struct{ Queries []string }
            func (d *database) Query(q string, args ...any) { d.Queries = append(d.Queries, q) }
            func mkJSON(r io.Reader) *json.Decoder { return json.NewDecoder(r) }
            func mkXML(r io.Reader) *xml.Decoder { return xml.NewDecoder(r) }
            func mkCleanJSON(r io.Reader) *json.Decoder { return json.NewDecoder(strings.NewReader(`"fixed"`)) }
            func mkBuf(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
            func mkScanned(r io.Reader) *bufio.Scanner { sc := bufio.NewScanner(r); sc.Scan(); return sc }
            func mkUnscanned(r io.Reader) *bufio.Scanner { return bufio.NewScanner(r) }
            func runJSON(db *database, req *http.Request) {
                var s, clean string
                _ = (mkJSON(req.Body)).Decode(&s)
                db.Query("J:" + s) // json-sql
                _ = mkCleanJSON(req.Body).Decode(&clean)
                db.Query("C:" + clean)
            }
            func runXML(db *database, req *http.Request) {
                var s string
                _ = mkXML(req.Body).Decode(&s)
                db.Query("X:" + s) // xml-sql
            }
            func runReader(db *database, req *http.Request) {
                line, _ := mkBuf(req.Body).ReadString('\n')
                db.Query("R:" + line) // reader-sql
            }
            func runScanner(db *database, req *http.Request) {
                db.Query("S:" + mkScanned(req.Body).Text()) // scanned-sql
                db.Query("U:" + mkUnscanned(req.Body).Text())
            }
        """)
        driver_source = textwrap.dedent(r"""
            package main
            import (
                "encoding/json"
                "net/http/httptest"
                "os"
                "strings"
            )
            func main() {
                db := &database{}
                runJSON(db, httptest.NewRequest("POST", "/", strings.NewReader(`"atk-j"`)))
                runXML(db, httptest.NewRequest("POST", "/", strings.NewReader(`<v>atk-x</v>`)))
                runReader(db, httptest.NewRequest("POST", "/", strings.NewReader("atk-r\n")))
                runScanner(db, httptest.NewRequest("POST", "/", strings.NewReader("atk-s\n")))
                if err := json.NewEncoder(os.Stdout).Encode(db.Queries); err != nil { panic(err) }
            }
        """)
        with temporary_directory(prefix='ubs-go-factory-native-') as tmp:
            handler_path = Path(tmp) / 'handler.go'
            driver_path = Path(tmp) / 'main.go'
            handler_path.write_text(handler_source, encoding='utf-8')
            driver_path.write_text(driver_source, encoding='utf-8')
            go_bin = shutil.which('go')
            if go_bin is not None:
                native = subprocess.run(
                    [go_bin, 'run', str(handler_path), str(driver_path)],
                    cwd=tmp, text=True, capture_output=True, timeout=180,
                    env=dict(os.environ, GOWORK='off', GO111MODULE='off', GOTOOLCHAIN='local'),
                )
                self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
                self.assertEqual(
                    json.loads(native.stdout),
                    ['J:atk-j', 'C:fixed', 'X:atk-x', 'R:atk-r\n', 'S:atk-s', 'U:'],
                )
            findings = list(packages.taint_go.run(packages.taint_go.RunContext(lang='go', files=[handler_path])))
            expected = {
                (number, 'go.taint.sql')
                for number, line in enumerate(handler_source.splitlines(), 1)
                if any(tag in line for tag in ('// json-sql', '// xml-sql', '// reader-sql', '// scanned-sql'))
            }
            self.assertEqual({(row['line'], row['rule']) for row in findings}, expected, findings)

if __name__ == '__main__':
    unittest.main()
