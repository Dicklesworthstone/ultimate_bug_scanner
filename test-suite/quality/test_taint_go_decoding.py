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


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real scanner tests')
class DecodingRunnerTests(unittest.TestCase):
    def test_actual_json_and_sarif_include_decoded_request_flows(self):
        cases = [
            ('decode-sql', '', 'var p Payload; json.NewDecoder(r.Body).Decode(&p); db.Query(p.SQL)', {'sql'}),
            ('decode-command', '', 'dec := json.NewDecoder(r.Body); var p Payload; dec.Decode(&p); '
             'exec.Command("sh", "-c", p.Command)', {'command'}),
            ('unmarshal-xss', '', 'raw, _ := io.ReadAll(r.Body); var p Payload; '
             'json.Unmarshal(raw, &p); fmt.Fprint(w, p.HTML)', {'xss'}),
            ('error-not-input', '', 'var p Payload; err := json.NewDecoder(r.Body).Decode(&p); '
             'db.Query(err.Error())', set()),
            ('clean-document', '', 'var p Payload; json.Unmarshal([]byte(`{}`), &p); db.Query(p.SQL)', set()),
            ('helper-output', 'func decode(raw []byte, dst *Payload) { json.Unmarshal(raw, dst) }',
             'raw, _ := io.ReadAll(r.Body); var p Payload; decode(raw, &p); db.Query(p.SQL)', {'sql'}),
        ]
        artifacts = packages.ROOT / 'test-suite/artifacts/go-decoding'
        for name, helper, body, expected in cases:
            for format_name in ('json', 'sarif'):
                with self.subTest(case=name, format=format_name), tempfile.TemporaryDirectory(prefix='ubs-decode-e2e-') as tmp:
                    project = Path(tmp)
                    (project / 'handler.go').write_text('package app\nfunc h() { ' + body + ' }\n')
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
