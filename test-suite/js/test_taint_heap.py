"""D6 heap identities: paired alias, field precision and snapshot regressions."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


class JavaScriptHeapTests(unittest.TestCase):
    def check(self, source, *expected):
        with tempfile.TemporaryDirectory(prefix='ubs-heap-') as tmp:
            path = Path(tmp) / 'handler.ts'
            path.write_text(source + '\n', encoding='utf-8')
            findings = list(taint_js.run(RunContext(lang='javascript', files=[path])))
        self.assertEqual(Counter(f['rule'].removeprefix('javascript.taint.') for f in findings),
                         Counter(expected), findings)
        for finding in findings:
            self.assertEqual(finding['severity'], 'critical')
            self.assertGreater(finding['line'], 0)
            self.assertGreater(finding['col'], 0)
            self.assertIn(' -> ', finding['message'])
        return findings

    def test_alias_write_reaches_original_object(self):
        result = self.check('const state = {}; const alias = state;\n'
                            'alias.html = req.query.html;\nres.send(state.html);', 'xss')
        self.assertEqual(result[0]['line'], 3)
        self.assertIn('alias.html', result[0]['message'])

    def test_original_write_reaches_alias(self):
        self.check('const state = {}; const alias = state;\n'
                   'state.code = req.query.code; eval(alias.code);', 'eval')

    def test_alias_chain_reaches_command_sink(self):
        self.check('const a = {}; const b = a; const c = b;\n'
                   'c.command = req.query.command; shell.exec(a.command);', 'command')

    def test_array_alias_and_constant_index(self):
        self.check('const a = []; const b = a;\n'
                   'b[0] = req.query.sql; db.query(a[0]);', 'sql')

    def test_unrelated_object_field_stays_clean(self):
        self.check('const o = {safe: "hello", raw: req.query.html}; res.send(o.safe);')

    def test_unrelated_array_element_stays_clean(self):
        self.check('const o = ["hello", req.query.html]; res.send(o[0]);')

    def test_nested_alias_reaches_root(self):
        self.check('const child = {}; const root = {nested: child};\n'
                   'child.html = req.query.html; res.send(root.nested.html);', 'xss')

    def test_nested_read_alias_can_be_mutated(self):
        self.check('const root = {nested: {}}; const alias = root.nested;\n'
                   'alias.html = req.query.html; res.send(root.nested.html);', 'xss')

    def test_nested_array_object(self):
        self.check('const a = [{payload: {}}]; const b = a[0].payload;\n'
                   'b.sql = req.query.sql; db.query(a[0].payload.sql);', 'sql')

    def test_strong_alias_overwrite_clears_one_field(self):
        self.check('const a = {html: req.query.html}; const b = a;\n'
                   'b.html = "hello"; res.send(a.html);')

    def test_overwrite_does_not_clear_other_fields(self):
        self.check('const a = {html: req.query.html, other: req.query.html};\n'
                   'a.html = "hello"; res.send(a.other);', 'xss')

    def test_rebinding_does_not_mutate_original(self):
        self.check('let a = {}; const b = a; a = {};\n'
                   'b.html = req.query.html; res.send(a.html);')
        self.check('let a = {}; const b = a; a = {};\n'
                   'b.html = req.query.html; res.send(b.html);', 'xss')

    def test_member_replacement_does_not_mutate_old_child(self):
        self.check('const root = {child: {}}; const old = root.child;\n'
                   'root.child = {}; old.html = req.query.html; res.send(root.child.html);')

    def test_conditional_write_preserves_unsafe_path(self):
        self.check('const a = {html: "hello"}; const b = a;\n'
                   'if (flag) { b.html = req.query.html; } res.send(a.html);', 'xss')

    def test_conditional_cleanup_preserves_unsafe_path(self):
        self.check('const a = {html: req.query.html}; const b = a;\n'
                   'if (flag) { b.html = "hello"; } res.send(a.html);', 'xss')

    def test_both_branches_cleanup(self):
        self.check('const a = {html: req.query.html};\n'
                   'if (flag) { a.html = "a"; } else { a.html = "b"; } res.send(a.html);')

    def test_ambiguous_alias_cleanup_is_not_a_strong_update(self):
        self.check('const a = {html: req.query.html}; const b = {html: "hello"};\n'
                   'const selected = flag ? a : b; selected.html = "clean"; res.send(a.html);', 'xss')

    def test_ambiguous_alias_write_reaches_each_possible_object(self):
        self.check('const a = {}; const b = {}; const selected = flag ? a : b;\n'
                   'selected.html = req.query.html; res.send(a.html); res.send(b.html);', 'xss', 'xss')

    def test_dynamic_index_read_cannot_ignore_other_fields(self):
        self.check('const o = ["hello", req.query.html]; res.send(o[index]);', 'xss')

    def test_dynamic_write_taints_possible_named_field(self):
        self.check('const o = {html: "hello"}; o[key] = req.query.html; res.send(o.html);', 'xss')

    def test_dynamic_cleanup_does_not_clear_every_field(self):
        self.check('const o = {html: req.query.html}; o[key] = "hello"; res.send(o.html);', 'xss')

    def test_literal_computed_key_matches_dot_access(self):
        self.check('const o = {["html"]: req.query.html}; res.send(o.html);', 'xss')
        self.check('const o = {}; o["html"] = req.query.html; res.send(o.html);', 'xss')

    def test_input_in_key_is_not_input_in_the_value(self):
        self.check('const o = {[req.query.key]: "hello"}; res.send(o.any);')

    def test_sink_materializes_the_current_object(self):
        self.check('const o = {}; const alias = o; alias.html = req.query.html; res.send(o);', 'xss')

    def test_nested_heap_cycle_terminates_with_other_taint(self):
        self.check('const o = {}; o.self = o; o.html = req.query.html; res.send(o);', 'xss')
        self.check('const o = {}; o.self = o; res.send(o);')

    def test_mutual_heap_cycle_terminates(self):
        self.check('const a = {}; const b = {}; a.other = b; b.other = a;\n'
                   'b.code = req.query.code; eval(a.other.code);', 'eval')

    def test_read_helper_selects_only_the_requested_field(self):
        self.check('function get(o) { return o.safe; }\n'
                   'const o = {safe: "hello", raw: req.query.html}; res.send(get(o));')
        self.check('function get(o) { return o.raw; }\n'
                   'const o = {safe: "hello", raw: req.query.html}; res.send(get(o));', 'xss')

    def test_nested_field_projection_through_helper(self):
        self.check('function get(o) { return o.nested.raw; }\n'
                   'const o = {nested: {raw: req.query.html}}; res.send(get(o));', 'xss')

    def test_identity_helper_preserves_alias(self):
        self.check('function id(o) { return o; } const o = {}; const alias = id(o);\n'
                   'alias.html = req.query.html; res.send(o.html);', 'xss')

    def test_immediate_member_of_returned_alias(self):
        self.check('function id(o) { return o; } const o = {safe: "hello", raw: req.query.html};\n'
                   'res.send(id(o).safe);')
        self.check('function id(o) { return o; } const o = {raw: req.query.html};\n'
                   'res.send(id(o)["raw"]);', 'xss')

    def test_factory_return_does_not_lose_reachable_taint(self):
        self.check('function make() { return {html: req.query.html}; } res.send(make());', 'xss')

    def test_helper_sink_uses_call_time_heap_snapshot(self):
        self.check('function output(o) { res.send(o); }\n'
                   'const o = {}; output(o); o.html = req.query.html;')
        self.check('function output(o) { res.send(o); }\n'
                   'const o = {html: req.query.html}; output(o); o.html = "hello";', 'xss')

    def test_heap_scope_isolation(self):
        self.check('function first(req) { const o = {}; o.html = req.query.html; }\n'
                   'function second() { const o = {}; res.send(o.html); }')

    def test_local_parameter_property_assignment_is_readable(self):
        self.check('function output(o) { o.html = req.query.html; res.send(o.html); }', 'xss')

    def test_source_objects_are_still_sources(self):
        self.check('const o = req.query; res.send(o.html);', 'xss')
        self.check('function output(req) { res.send(req.query.html); }', 'xss')

    def test_sanitizers_remain_domain_specific_through_heap(self):
        self.check('const o = {}; const a = o; a.html = DOMPurify.sanitize(req.query.html);\n'
                   'res.send(o.html); eval(o.html);', 'eval')

    def test_bound_values_do_not_taint_query_text(self):
        self.check('const o = {sql: "SELECT 1", raw: req.query.sql}; db.query(o.sql, [o.raw]);')
        self.check('const o = {}; const a = o; a.sql = req.query.sql; db.query(o.sql, [123]);', 'sql')

    def test_loop_writes_converge(self):
        self.check('const o = {}; while (flag) { const alias = o; alias.html = req.query.html; }\n'
                   'res.send(o.html);', 'xss')

    def test_repeated_allocation_site_does_not_clear_old_objects(self):
        self.check('let saved; while (flag) { const item = {};\n'
                   'if (first) { saved = item; item.html = req.query.html; }\n'
                   'else { item.html = "hello"; } } res.send(saved.html);', 'xss')

    def test_read_before_later_heap_mutation_is_preserved(self):
        self.check('const o = {html: req.query.html};\nres.send(o.html + (o.html = "hello"));', 'xss')
        self.check('const o = {html: "hello"};\nres.send(o.html); o.html = req.query.html;')

    def test_unchanged_legacy_selftests(self):
        for name, check in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                check()


@unittest.skipUnless(os.environ.get('UBS_HEAP_E2E') == '1', 'set UBS_HEAP_E2E=1 for the real scanner')
class JavaScriptHeapIntegrationTests(unittest.TestCase):
    def test_real_scanner_heap_flows(self):
        cases = [
            ('alias-xss', 'const o = {}; const a = o; a.html = req.query.html; res.send(o.html);', {'xss'}),
            ('array-eval', 'const o = []; const a = o; a[0] = req.query.code; eval(o[0]);', {'eval'}),
            ('alias-sql', 'const o = {}; const a = o; a.sql = req.query.sql; db.query(o.sql, []);', {'sql'}),
            ('clean-field', 'const o = {safe: "hello", raw: req.query.html}; res.send(o.safe);', set()),
            ('alias-cleanup', 'const o = {html: req.query.html}; const a = o; a.html = "hello"; res.send(o.html);', set()),
            ('read-helper', 'function get(o) { return o.safe; } const o = {safe: "hello", raw: req.query.html}; res.send(get(o));', set()),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='ubs-heap-e2e-') as tmp:
                path = Path(tmp) / 'app.ts'
                path.write_text(source + '\n', encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(path), '--only=js', '--ci', '--format=json'],
                                        cwd=tmp, text=True, capture_output=True, timeout=120)
                self.assertIn(result.returncode, (0, 1), (result.stdout, result.stderr))
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'ok', report)
                rules = set()
                def collect(value):
                    if isinstance(value, dict):
                        for key in ('rule', 'rule_id', 'ruleId'):
                            rule = value.get(key)
                            if isinstance(rule, str) and rule.startswith(('javascript.taint.', 'js.taint.')):
                                rules.add(rule.rsplit('.', 1)[-1])
                        for item in value.values():
                            collect(item)
                    elif isinstance(value, list):
                        for item in value:
                            collect(item)
                collect(report)
                self.assertEqual(rules, expected, report)
                print('JS_HEAP_E2E_PASS', name, sorted(rules), flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
