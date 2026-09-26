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

    def test_assign_mutates_target_and_returns_its_alias(self):
        self.check('const o = {}; const alias = o; Object.assign(alias, {html: req.query.html}); '
                   'res.send(o.html);', 'xss')
        self.check('const o = {}; const alias = Object.assign(o, {}); '
                   'alias.code = req.query.code; eval(o.code);', 'eval')

    def test_assign_source_order_and_unrelated_fields(self):
        self.check('const o = {html: req.query.html}; Object.assign(o, {html: "hello"}); res.send(o.html);')
        self.check('const o = {}; Object.assign(o, {html: req.query.html}, {html: "hello"}); res.send(o.html);')
        self.check('const o = {}; Object.assign(o, {html: "hello"}, {html: req.query.html}); res.send(o.html);', 'xss')
        self.check('const o = {}; Object.assign(o, {safe: "hello", raw: req.query.html}); res.send(o.safe);')

    def test_assign_optional_key_cannot_clear_existing_value(self):
        self.check('const o = {html: req.query.html}; const other = flag ? {html: "hello"} : {}; '
                   'Object.assign(o, other); res.send(o.html);', 'xss')

    def test_assign_unknown_source_and_explicit_later_override(self):
        self.check('const o = {html: "hello"}; Object.assign(o, req.query); res.send(o.html);', 'xss')
        self.check('const o = {}; Object.assign(o, req.query, {html: "hello"}); res.send(o.html);')

    def test_object_spread_is_shallow_not_an_alias_of_the_outer_object(self):
        self.check('const o = {html: "hello", child: {}}; const copy = {...o}; '
                   'copy.html = req.query.html; res.send(o.html);')
        self.check('const o = {child: {}}; const copy = {...o}; '
                   'copy.child.html = req.query.html; res.send(o.child.html);', 'xss')

    def test_object_spread_respects_order_and_optional_keys(self):
        self.check('const o = {html: "hello", ...req.query}; res.send(o.html);', 'xss')
        self.check('const o = {...req.query, html: "hello"}; res.send(o.html);')
        self.check('const other = flag ? {html: "hello"} : {}; '
                   'const o = {html: req.query.html, ...other}; res.send(o.html);', 'xss')

    def test_array_push_mutates_alias_but_returns_clean_length(self):
        self.check('const o = []; const alias = o; alias.push(req.query.code); eval(o[0]);', 'eval')
        self.check('const o = []; res.send(o.push(req.query.html));')
        self.check('const o = [req.query.html]; res.send(o.length);')

    def test_array_push_preserves_existing_safe_element(self):
        self.check('const o = ["hello"]; o.push(req.query.html); res.send(o[0]);')
        self.check('const o = []; o.push("hello", req.query.html); res.send(o[1]);', 'xss')

    def test_array_unshift_reindexes_existing_elements(self):
        self.check('const o = [req.query.html]; o.unshift("hello"); res.send(o[0]);')
        self.check('const o = [req.query.html]; o.unshift("hello"); res.send(o[1]);', 'xss')
        self.check('const o = []; res.send(o.unshift(req.query.html));')

    def test_pop_returns_removed_element_and_cleans_array(self):
        self.check('const o = [req.query.html]; res.send(o.pop());', 'xss')
        self.check('const o = [req.query.html]; const alias = o; alias.pop(); res.send(o[0]);')
        self.check('const o = [req.query.html, "hello"]; res.send(o.pop());')

    def test_shift_returns_removed_element_and_reindexes(self):
        self.check('const o = [req.query.html, "hello"]; res.send(o.shift());', 'xss')
        self.check('const o = [req.query.html, "hello"]; o.shift(); res.send(o[0]);')
        self.check('const o = ["hello", req.query.html]; o.shift(); res.send(o[0]);', 'xss')

    def test_empty_array_removals_are_clean(self):
        self.check('const o = []; res.send(o.pop()); res.send(o.shift());')

    def test_join_uses_elements_not_unrelated_properties(self):
        self.check('const o = ["hello"]; o.extra = req.query.html; res.send(o.join(""));')
        self.check('const o = ["hello", req.query.html]; res.send(o.join(""));', 'xss')

    def test_join_separator_only_used_for_multiple_elements(self):
        self.check('const empty = []; const one = ["hello"]; '
                   'res.send(empty.join(req.query.html)); res.send(one.join(req.query.html));')
        self.check('const o = ["a", "b"]; res.send(o.join(req.query.html));', 'xss')

    def test_known_array_spread_preserves_offsets_and_holes(self):
        self.check('const o = [...[req.query.html], "hello"]; res.send(o[0]);', 'xss')
        self.check('const o = [...[req.query.html], "hello"]; res.send(o[1]);')
        self.check('const o = [...[, req.query.html], "hello"]; res.send(o[1]);', 'xss')
        self.check('const o = [...[, req.query.html], "hello"]; res.send(o[0]);')

    def test_unknown_array_spread_does_not_assign_a_false_fixed_offset(self):
        self.check('const o = [...req.query.items, "hello"]; res.send(o[0]);', 'xss')
        self.check('const o = ["hello", ...req.query.items]; res.send(o[0]);')

    def test_array_spread_is_shallow(self):
        self.check('const original = [{}]; const copy = [...original]; '
                   'copy[0].html = req.query.html; res.send(original[0].html);', 'xss')
        self.check('const original = ["hello"]; const copy = [...original]; '
                   'copy[0] = req.query.html; res.send(original[0]);')

    def test_push_spread_and_nested_spread(self):
        self.check('const o = []; o.push(...["hello", req.query.html]); res.send(o[1]);', 'xss')
        self.check('const o = []; o.push(...["hello", ...[req.query.html]]); res.send(o[1]);', 'xss')
        self.check('const o = ["hello"]; o.push(...req.query.items); res.send(o[0]);')
        self.check('const o = []; o.push(...req.query.items); res.send(o[index]);', 'xss')

    def test_conditional_pop_does_not_remove_the_bypass_value(self):
        self.check('const o = [req.query.html]; if (flag) { o.pop(); } res.send(o[0]);', 'xss')

    def test_ambiguous_receiver_pop_does_not_clear_every_array(self):
        self.check('const a = [req.query.html]; const b = []; '
                   'const selected = flag ? a : b; selected.pop(); res.send(a[0]);', 'xss')

    def test_loop_pushes_converge_and_retain_added_values(self):
        self.check('const o = []; while (flag) { o.push(req.query.html); } res.send(o[index]);', 'xss')

    def test_array_method_override_cannot_earn_native_clean_return(self):
        self.check('const o = []; o.push = external; res.send(o.push(req.query.html));', 'xss')
        self.check('Array.prototype.push = external; const o = []; res.send(o.push(req.query.html));', 'xss')

    def test_computed_prototype_override_invalidates_native_identity(self):
        self.check('Array.prototype[key] = external; const o = []; res.send(o.push(req.query.html));', 'xss')

    def test_shadowed_assign_cannot_clear_target(self):
        self.check('const Object = service; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "hello"}); res.send(o.html);', 'xss')
        self.check('Object.assign = external; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "hello"}); res.send(o.html);', 'xss')

    def test_computed_assign_override_cannot_clear_target(self):
        self.check('Object[key] = external; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "hello"}); res.send(o.html);', 'xss')

    def test_logical_heap_assignment_preserves_rhs_bypass(self):
        self.check('let text = req.query.html; const o = {value: "hello"}; '
                   'o.value ||= (text = "clean"); res.send(text);', 'xss')

    def test_template_reads_selected_field_not_the_entire_heap(self):
        self.check('const o = {safe: "hello", raw: req.query.html}; res.send(`${o.safe}`);')
        self.check('const o = {safe: "hello", raw: req.query.html}; res.send(`${o.raw}`);', 'xss')

    def test_mutator_return_does_not_hide_its_argument_sink_effects(self):
        self.check('const o = []; o.push(eval(req.query.code));', 'eval')

    def test_branch_optional_source_field_cannot_clear_assign_target(self):
        self.check('const source = {}; if (flag) { source.html = "hello"; } '
                   'const target = {html: req.query.html}; Object.assign(target, source); res.send(target.html);', 'xss')

    def test_optional_property_presence_survives_multiple_copies(self):
        self.check('const source = {}; if (flag) { source.html = "hello"; } '
                   'const copied = {...source}; const target = {html: req.query.html}; '
                   'Object.assign(target, copied); res.send(target.html);', 'xss')
        self.check('const source = {}; if (flag) { source.html = "hello"; } '
                   'const copied = {}; Object.assign(copied, source); '
                   'const target = {html: req.query.html, ...copied}; res.send(target.html);', 'xss')

    def test_definite_write_after_branch_makes_copy_key_present(self):
        self.check('const source = {}; if (flag) { source.html = req.query.html; } '
                   'source.html = "hello"; const target = {html: req.query.html}; '
                   'Object.assign(target, source); res.send(target.html);')

    def test_shadowing_global_object_binding_disables_assign_assumptions(self):
        self.check('Object = external; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "hello"}); res.send(o.html);', 'xss')

    def test_length_truncation_changes_the_element_removed_by_pop(self):
        self.check('const o = [req.query.html, "hello"]; o.length = 1; res.send(o.pop());', 'xss')
        self.check('const o = [req.query.html]; const a = o; a.length = 0; res.send(o[0]);')
        self.check('const o = [req.query.html]; o.length = 4; res.send(o.pop());')

    def test_unknown_length_cannot_hide_a_possible_removed_value(self):
        self.check('const o = [req.query.html, "hello"]; o.length = size; res.send(o.pop());', 'xss')

    def test_length_truncation_does_not_clear_arbitrary_named_properties(self):
        self.check('const o = []; o[key] = req.query.html; o.length = 0; res.send(o.html);', 'xss')

    def test_prototype_alias_or_reflection_disables_native_clean_return(self):
        self.check('const prototype = Array.prototype; prototype.push = external; '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')
        self.check('Object.defineProperty(Array.prototype, "push", {value: external}); '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')

    def test_constructor_alias_does_not_preserve_an_obsolete_native(self):
        self.check('const alias = Object; alias.assign = external; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "hello"}); res.send(o.html);', 'xss')

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
            ('assign-alias', 'const o = {}; const a = o; Object.assign(a, {html: req.query.html}); res.send(o.html);', {'xss'}),
            ('push-alias', 'const o = []; const a = o; a.push(req.query.code); eval(o[0]);', {'eval'}),
            ('push-return-clean', 'const o = []; res.send(o.push(req.query.html));', set()),
            ('pop-cleanup', 'const o = [req.query.html]; o.pop(); res.send(o[0]);', set()),
            ('spread-index', 'const o = [...[req.query.html], "hello"]; res.send(o[0]);', {'xss'}),
            ('spread-clean-index', 'const o = [...[req.query.html], "hello"]; res.send(o[1]);', set()),
            ('truncate-pop', 'const o = [req.query.html, "hello"]; o.length = 1; res.send(o.pop());', {'xss'}),
            ('optional-copy', 'const source = {}; if (flag) { source.html = "hello"; } const o = {html: req.query.html}; Object.assign(o, source); res.send(o.html);', {'xss'}),
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
