"""Source-only regressions for Go decoding destinations and error results.

JSON/XML decoding writes through its destination; its error return is not the
request payload. Fixtures are parsed as source and never imported or executed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_taint_go_packages as packages


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
            import codec "encoding/json"
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
        ]
        artifacts = packages.ROOT / 'test-suite/artifacts/go-decoding'
        for name, imports, helper, body, expected in cases:
            for format_name in ('json', 'sarif'):
                with self.subTest(case=name, format=format_name), tempfile.TemporaryDirectory(prefix='ubs-decode-e2e-') as tmp:
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


if __name__ == '__main__':
    unittest.main()
