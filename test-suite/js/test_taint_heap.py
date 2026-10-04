"""D6 heap identities: paired alias, field precision and snapshot regressions."""
from __future__ import annotations

from collections import Counter
import itertools
import json
import os
from pathlib import Path
import shutil
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

    def test_optional_shape_survives_helper_return_and_borrowed_copy(self):
        self.check('function make() { const o = {}; if (flag) o.html = "safe"; return o; } '
                   'function copy(dst, src) { Object.assign(dst, src); } '
                   'const target = {html: req.query.html}; copy(target, make()); res.send(target.html);', 'xss')

    def test_unknown_key_taint_survives_branch_then_explicit_overwrite(self):
        self.check('const o = {...req.query}; if (flag) o.html = "safe"; res.send(o.html);', 'xss')
        self.check('const o = {...req.query}; if (flag) o.extra = req.query.html; '
                   'o.html = "safe"; res.send(o.html);')

    def test_copy_of_wildcard_with_explicit_exception_is_precise(self):
        self.check('const source = {...req.query, html: "safe"}; '
                   'const target = {html: req.query.html}; Object.assign(target, source); res.send(target.html);')
        self.check('const source = {...req.query, html: "safe"}; '
                   'const copy = {...source}; res.send(copy.other);', 'xss')

    def test_missing_key_join_preserves_another_branch_wildcard(self):
        self.check('const source = flag ? {...req.query} : {html: "safe"}; '
                   'const target = {...source}; res.send(target.html);', 'xss')

    def test_sparse_unknown_range_moves_with_shift_and_reverse(self):
        self.check('const a = ["safe", ...req.query.items]; a.length = 2; '
                   'a.shift(); res.send(a[0]);', 'xss')
        self.check('const a = ["safe", ...req.query.items]; a.length = 2; '
                   'a.reverse(); res.send(a[0]); res.send(a[1]);', 'xss')

    def test_truncated_unknown_elements_do_not_reappear_when_length_grows(self):
        self.check('const a = [...req.query.items]; a.length = 0; a.length = 4; res.send(a.pop());')
        self.check('const a = ["safe", ...req.query.items]; a.length = 1; '
                   'a.length = 3; res.send(a[2]);')

    def test_huge_array_length_stays_sparse(self):
        self.check('const a = [req.query.html]; a.length = 4000000000; '
                   'const b = [...a]; res.send(b[0]); res.send(b[3999999999]);', 'xss')

    def test_copying_unknown_array_length_cannot_hide_pop_input(self):
        self.check('const a = [req.query.html, "safe"]; '
                   'Object.assign(a, {length: 1}); res.send(a.pop());', 'xss')

    def test_spread_and_join_ignore_non_element_properties(self):
        self.check('const a = ["safe"]; a.extra = req.query.html; '
                   'const b = [...a]; res.send(b.join(""));')
        self.check('const a = [...req.query.items]; res.send(a.named);')

    def test_logical_assignment_retains_normal_bypass_of_throwing_rhs(self):
        self.check('let html = req.query.html; const o = {value: "safe"}; '
                   'function clear() { html = "safe"; throw Error(); } '
                   'o.value ||= clear(); res.send(html);', 'xss')

    def test_logical_assignment_preserves_object_identity_on_bypass(self):
        self.check('const a = {}; let current = a; current ||= {}; '
                   'a.html = req.query.html; res.send(current.html);', 'xss')

    def test_saved_native_assign_survives_later_replacement(self):
        self.check('const copy = Object.assign; Object.assign = external; '
                   'const o = {html: req.query.html}; copy(o, {html: "safe"}); res.send(o.html);')
        self.check('const api = {copy: Object.assign}; Object.assign = external; '
                   'const o = {}; api.copy(o, {html: req.query.html}); res.send(o.html);', 'xss')

    def test_native_callee_is_captured_before_argument_replacement(self):
        self.check('function replace() { Object.assign = external; return {html: "safe"}; } '
                   'const o = {html: req.query.html}; Object.assign(o, replace()); res.send(o.html);')
        self.check('const o = []; function replace() { Array.prototype.push = external; return req.query.html; } '
                   'res.send(o.push(replace())); res.send(o.push(req.query.html));', 'xss')

    def test_native_array_receiver_is_captured_before_argument_rebinding(self):
        self.check('let selected = []; const original = selected; '
                   'function swap() { selected = []; return req.query.html; } '
                   'selected.push(swap()); res.send(original[0]); res.send(selected[0]);', 'xss')

    def test_native_replacement_does_not_change_an_earlier_call(self):
        self.check('const o = []; res.send(o.push(req.query.html)); '
                   'Array.prototype.push = external; res.send(o.push(req.query.html));', 'xss')

    def test_conditional_native_replacement_keeps_unknown_alternative(self):
        self.check('if (flag) Array.prototype.push = external; const o = []; '
                   'res.send(o.push(req.query.html));', 'xss')
        self.check('if (flag) Object.assign = external; const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "safe"}); res.send(o.html);', 'xss')

    def test_optional_copied_native_override_cannot_prove_cleanup(self):
        self.check('const replacement = {}; if (flag) replacement.assign = external; '
                   'Object.assign(Object, replacement); const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "safe"}); res.send(o.html);', 'xss')

    def test_native_identity_can_be_restored_from_a_saved_value(self):
        self.check('const push = Array.prototype.push; Array.prototype.push = external; '
                   'Array.prototype.push = push; const o = []; res.send(o.push(req.query.html));')
        self.check('const assign = Object.assign; Object[key] = external; Object.assign = assign; '
                   'const o = {html: req.query.html}; Object.assign(o, {html: "safe"}); res.send(o.html);')

    def test_native_override_through_local_or_borrowed_helper(self):
        self.check('function replace() { Array.prototype.push = external; } replace(); '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')
        self.check('function replace(target) { target.push = external; } replace(Array.prototype); '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')

    def test_native_override_through_captured_constructor_alias(self):
        self.check('const api = Object; function replace() { api.assign = external; } replace(); '
                   'const o = {html: req.query.html}; Object.assign(o, {html: "safe"}); res.send(o.html);', 'xss')

    def test_lexically_shadowed_constructor_stays_unknown_in_nested_helper(self):
        self.check('function outer(Object) { const o = {html: req.query.html}; '
                   'function copy() { Object.assign(o, {html: "safe"}); } copy(); res.send(o.html); } outer(external);', 'xss')

    def test_reflective_native_replacements_are_visible(self):
        self.check('Reflect.defineProperty(Array.prototype, "push", {value: external}); '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')
        self.check('Object.defineProperties(Array.prototype, {push: {value: external}}); '
                   'const o = []; res.send(o.push(req.query.html));', 'xss')

    def test_replaced_reflection_function_cannot_prove_cleanup(self):
        self.check('Object.defineProperty = external; const o = {html: req.query.html}; '
                   'Object.defineProperty(o, "html", {value: "safe"}); res.send(o.html);', 'xss')

    def test_unsupported_descriptor_does_not_prove_clean_value(self):
        self.check('const o = {html: req.query.html}; Object.defineProperty(o, "html", descriptor); '
                   'res.send(o.html);', 'xss')

    def test_replaced_receiver_prototype_cannot_earn_native_return(self):
        self.check('const o = []; Object.setPrototypeOf(o, external); res.send(o.push(req.query.html));', 'xss')
        self.check('const o = []; o.__proto__ = external; res.send(o.push(req.query.html));', 'xss')

    def test_escaped_realm_object_loses_native_proofs(self):
        self.check('external(Array.prototype); const o = []; res.send(o.push(req.query.html));', 'xss')
        self.check('external({api: Object}); const o = {html: req.query.html}; '
                   'Object.assign(o, {html: "safe"}); res.send(o.html);', 'xss')

    def test_unrelated_native_property_replacement_keeps_precision(self):
        self.check('Array.prototype.extra = external; Object.extra = external; '
                   'const o = []; res.send(o.push(req.query.html)); '
                   'const target = {html: req.query.html}; Object.assign(target, {html: "safe"}); res.send(target.html);')

    def test_native_override_across_selected_module_call(self):
        with tempfile.TemporaryDirectory(prefix='ubs-native-module-') as tmp:
            helper, caller = Path(tmp) / 'helper.js', Path(tmp) / 'caller.js'
            helper.write_text('export function replace() { Array.prototype.push = external; }\n', encoding='utf-8')
            caller.write_text('import {replace} from "./helper.js"; replace(); '
                              'const o = []; res.send(o.push(req.query.html));\n', encoding='utf-8')
            findings = list(taint_js.run(RunContext(lang='javascript', files=[helper, caller])))
            self.assertEqual([f['rule'] for f in findings], ['javascript.taint.xss'], findings)

    def test_spread_argument_call_is_not_evaluated_twice(self):
        self.check('let html = req.query.html; function take() { const old = html; html = "safe"; return old; } '
                   'function output(x) { res.send(x); } output(...[take()]);', 'xss')

    def test_spread_argument_pop_does_not_repeat_mutation(self):
        self.check('const a = [req.query.html, "safe"]; function ignore(x) {} '
                   'ignore(...[a.pop()]); res.send(a[0]);', 'xss')

    def test_nested_spread_argument_values_keep_their_original_snapshots(self):
        self.check('let html = req.query.html; function take() { const old = html; html = "safe"; return old; } '
                   'function output(x, y) { res.send(y); } output(...["safe", ...[take()]]);', 'xss')

    def test_fixed_spread_defaults_keep_undefined_and_trailing_comma_semantics(self):
        self.check('function get(x = req.query.html) { return x; } res.send(get(...[ , ]));', 'xss')
        self.check('function get(x = req.query.html) { return x; } res.send(get(...["safe", ] ));')
        self.check('function get(x = req.query.html) { return x; } res.send(get(...[...[undefined]]));', 'xss')

    def test_possible_spread_default_cannot_prove_cleanup(self):
        self.check('let html = req.query.html; function clear() { html = "safe"; } '
                   'function accept(x = clear()) {} const args = [external]; accept(...args); res.send(html);', 'xss')

    def test_large_spread_call_materializes_only_formal_positions(self):
        self.check('function first(a) { return a; } const args = [req.query.html]; '
                   'args.length = 4000000000; res.send(first(...args));', 'xss')

    def test_optional_array_presence_survives_shift_and_copy(self):
        self.check('const source = ["safe"]; source.length = 2; if (flag) source[1] = "safe"; source.shift(); '
                   'const target = {0: req.query.html}; Object.assign(target, source); res.send(target[0]);', 'xss')

    def test_imported_constructor_preserves_exporter_native_replacement(self):
        cases = [
            ('export const api=Object; api.assign=external;',
             'import {api} from "./helper.js";', 'api.assign', True),
            ('export const api=Object; api.assign=external;',
             'import * as helper from "./helper.js";', 'helper.api.assign', True),
            ('exports.api=Object; Object.assign=external;',
             'const {api}=require("./helper.js");', 'api.assign', True),
            ('export const copy=Object.assign; Object.assign=external;',
             'import {copy} from "./helper.js";', 'copy', False),
        ]
        for exporter, binding, call, unsafe in cases:
            with self.subTest(binding=binding), tempfile.TemporaryDirectory(prefix='ubs-native-export-') as tmp:
                helper, caller = Path(tmp)/'helper.js', Path(tmp)/'caller.js'
                helper.write_text(exporter+'\n', encoding='utf-8')
                caller.write_text(binding+f'const o={{html:req.query.html}};{call}(o,{{html:"safe"}});res.send(o.html);\n', encoding='utf-8')
                findings = list(taint_js.run(RunContext(lang='javascript', files=[helper, caller])))
                self.assertEqual([f['rule'] for f in findings], ['javascript.taint.xss'] if unsafe else [], findings)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for independent semantic controls')
    def test_imported_native_alias_cases_agree_with_node(self):
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory(prefix='ubs-native-node-') as tmp:
                root = Path(tmp)
                (root/'package.json').write_text('{"type":"module"}', encoding='utf-8')
                exporter = ('export const copy=Object.assign; Object.assign=external;' if snapshot
                            else 'export const api=Object; api.assign=external;')
                binding, call = ('copy', 'copy') if snapshot else ('api', 'api.assign')
                helper, caller = root/'helper.js', root/'caller.js'
                helper.write_text(exporter+'\n', encoding='utf-8')
                caller.write_text(f'import {{{binding}}} from "./helper.js"; '
                                  f'const o={{html:req.query.html}};{call}(o,{{html:"safe"}});res.send(o.html);\n', encoding='utf-8')
                findings = list(taint_js.run(RunContext(lang='javascript', files=[helper, caller])))
                program = ('globalThis.external=value=>value;globalThis.req={query:{html:"UNSAFE"}};'
                           'const results=[];globalThis.res={send(value){if(value==="UNSAFE")results.push(1)}};'
                           f'await import({json.dumps(caller.as_uri())});console.log(JSON.stringify(results));')
                result = subprocess.run(['node','--input-type=module','-e',program],
                                        text=True,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                expected = 0 if snapshot else 1
                self.assertEqual(len(json.loads(result.stdout)),expected)
                self.assertEqual(len(findings),expected,findings)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for independent semantic controls')
    def test_fixed_array_operation_matrix_agrees_with_node(self):
        initials = ['[]','[req.query.html]','["safe",req.query.html]',
                    '[req.query.html,"safe"]','[,req.query.html]']
        operations = ['a.push("safe");','a.unshift("safe");','a.pop();','a.shift();',
                      'a.reverse();','a.length=0;','a.length=3;','a.push(...["safe",req.query.html]);']
        cases = [f'const a={initial};{operation}{consume}'
                 for initial,operation,consume in itertools.product(initials,operations,
                     ['res.send(a[0]);res.send(a[1]);','res.send(a.pop());'])]
        cases += [f'const a=[req.query.html,"safe"];{first}{second}'
                  'const b=[...a];res.send(b[0]);res.send(b[1]);'
                  for first,second in itertools.product(['a.push("safe");','a.shift();','a.reverse();'],repeat=2)]
        # Only this fixed operation vocabulary reaches Node, never arbitrary
        # repository source. Scanner inputs use fresh names and scan roots.
        program = ('const req={query:{html:"UNSAFE"}};const sources='+json.dumps(cases)+';'
                   'const results=sources.map(source=>{const found=[];const res={send(v){'
                   'if(JSON.stringify(v)?.includes("UNSAFE"))found.push(1)}};'
                   'new Function("req","res",source)(req,res);return found.length});'
                   'console.log(JSON.stringify(results));')
        result = subprocess.run(['node','-e',program],text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        expected = json.loads(result.stdout)
        self.assertEqual(len(cases),89)
        for source,count in zip(cases,expected):
            with self.subTest(source=source):
                self.check(source,*(['xss']*count))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for independent semantic controls')
    def test_fixed_native_identity_cases_agree_with_node(self):
        # Mutations are isolated in one process per fixed test program.
        cases = [
            ('Array.prototype.push = external; const o = []; res.send(o.push(req.query.html));', ['xss']),
            ('const prototype = Array.prototype; prototype.push = external; const o = []; '
             'res.send(o.push(req.query.html));', ['xss']),
            ('const copy = Object.assign; Object.assign = external; const o = {html: req.query.html}; '
             'copy(o, {html: "safe"}); res.send(o.html);', []),
            ('function replace() { Object.assign = external; return {html: "safe"}; } '
             'const o = {html: req.query.html}; Object.assign(o, replace()); res.send(o.html);', []),
            ('const o = []; function replace() { Array.prototype.push = external; return req.query.html; } '
             'res.send(o.push(replace())); res.send(o.push(req.query.html));', ['xss']),
            ('let selected = []; const original = selected; function swap() { selected = []; return req.query.html; } '
             'selected.push(swap()); res.send(original[0]); res.send(selected[0]);', ['xss']),
            ('const replacement = {}; if (flag) replacement.assign = external; Object.assign(Object, replacement); '
             'const o = {html: req.query.html}; Object.assign(o, {html: "safe"}); res.send(o.html);', ['xss']),
            ('const push = Array.prototype.push; Array.prototype.push = external; Array.prototype.push = push; '
             'const o = []; res.send(o.push(req.query.html));', []),
            ('Reflect.defineProperty(Array.prototype, "push", {value: external}); const o = []; '
             'res.send(o.push(req.query.html));', ['xss']),
            ('Object.defineProperties(Array.prototype, {push: {value: external}}); const o = []; '
             'res.send(o.push(req.query.html));', ['xss']),
            ('const o = []; Object.setPrototypeOf(o, {push: external}); res.send(o.push(req.query.html));', ['xss']),
            ('Array.prototype.extra = external; const o = []; res.send(o.push(req.query.html));', []),
            ('let html = req.query.html; function take() { const old = html; html = "safe"; return old; } '
             'function output(x) { res.send(x); } output(...[take()]);', ['xss']),
            ('const a = [req.query.html, "safe"]; function ignore(x) {} ignore(...[a.pop()]); res.send(a[0]);', ['xss']),
            ('function get(x = req.query.html) { return x; } res.send(get(...[ , ]));', ['xss']),
            ('function get(x = req.query.html) { return x; } res.send(get(...["safe", ] ));', []),
        ]
        prefix = ('const req={query:{html:"UNSAFE"}}; const flag=true; const results=[]; '
                  'const append=Array.prototype.push; const external=(value)=>value; '
                  'const res={send(value){if(JSON.stringify(value)?.includes("UNSAFE"))append.call(results,"xss")}};')
        for source, expected in cases:
            with self.subTest(source=source):
                self.check(source, *expected)
                result = subprocess.run(['node', '-e', prefix + source + ';console.log(JSON.stringify(results));'],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertEqual(json.loads(result.stdout), expected)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for independent semantic controls')
    def test_fixed_copy_and_array_cases_agree_with_node(self):
        # These are fixed test programs, never repository files under analysis.
        cases = [
            ('const source = {}; if (false) source.html = "safe"; const o = {html: req.query.html}; '
             'Object.assign(o, source); res.send(o.html);', ['xss']),
            ('const source = {...req.query, html: "safe"}; const o = {}; '
             'Object.assign(o, source); res.send(o.html);', []),
            ('const a = [...[req.query.html], "safe"]; res.send(a[0]); res.send(a[1]);', ['xss']),
            ('const a = [...[,req.query.html], "safe"]; res.send(a[0]); res.send(a[1]);', ['xss']),
            ('const a = ["safe", ...req.query.items]; a.length = 2; a.shift(); res.send(a[0]);', ['xss']),
            ('const a = ["safe", ...req.query.items]; a.length = 2; a.reverse(); res.send(a[0]); res.send(a[1]);', ['xss']),
            ('const a = [...req.query.items]; a.length = 0; a.length = 4; res.send(a.pop());', []),
            ('const a = ["safe"]; a.push(...[req.query.html]); res.send(a[0]); res.send(a[1]);', ['xss']),
            ('const a = [{}]; const b = [...a]; b[0].html = req.query.html; res.send(a[0].html);', ['xss']),
            ('const a = ["safe"]; a.extra = req.query.html; res.send(a.join(req.query.html));', []),
            ('const a = ["a", "b"]; res.send(a.join(req.query.html));', ['xss']),
            ('let html = req.query.html; const o = {value: "safe"}; o.value ||= (html = "safe"); res.send(html);', ['xss']),
        ]
        prefix = ('const req = {query:{html:"UNSAFE",items:["UNSAFE"]}}; const results=[]; '
                  'const res={send(value){if(JSON.stringify(value)?.includes("UNSAFE"))results.push("xss")}};')
        for source, expected in cases:
            with self.subTest(source=source):
                self.check(source, *expected)
                result = subprocess.run(['node', '-e', prefix + source + ';console.log(JSON.stringify(results));'],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertEqual(json.loads(result.stdout), expected)

    def test_unchanged_legacy_selftests(self):
        for name, check in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                check()


@unittest.skipUnless(os.environ.get('UBS_HEAP_E2E') == '1', 'set UBS_HEAP_E2E=1 for the real scanner')
class JavaScriptHeapIntegrationTests(unittest.TestCase):
    def test_real_scanner_native_export_identity(self):
        for snapshot in (False, True):
            with self.subTest(snapshot=snapshot), tempfile.TemporaryDirectory(prefix='ubs-native-export-e2e-') as tmp:
                root = Path(tmp)
                exporter = ('export const copy=Object.assign; Object.assign=external;' if snapshot
                            else 'export const api=Object; api.assign=external;')
                binding, call = ('copy', 'copy') if snapshot else ('api', 'api.assign')
                (root/'helper.js').write_text(exporter+'\n',encoding='utf-8')
                (root/'caller.js').write_text(f'import {{{binding}}} from "./helper.js";'
                    f'const o={{html:req.query.html}};{call}(o,{{html:"safe"}});res.send(o.html);\n',encoding='utf-8')
                result = subprocess.run([str(ROOT/'ubs'),str(root),'--only=js','--ci','--format=json'],
                                        cwd=tmp,text=True,capture_output=True,timeout=120)
                self.assertIn(result.returncode,(0,1),(result.stdout,result.stderr))
                report = json.loads(result.stdout)
                self.assertEqual(report['status'],'ok',report)
                records = []
                def collect(value):
                    if isinstance(value,dict):
                        for key in ('rule','rule_id','ruleId'):
                            if value.get(key) in ('javascript.taint.xss','js.taint.xss'):
                                records.append(value)
                                break
                        for child in value.values():
                            collect(child)
                    elif isinstance(value,list):
                        for child in value:
                            collect(child)
                collect(report)
                self.assertEqual(bool(records),not snapshot,report)
                artifacts = ROOT/'test-suite'/'artifacts'/'javascript-heap-shapes'
                artifacts.mkdir(parents=True,exist_ok=True)
                name = 'native-export-snapshot' if snapshot else 'native-export-override'
                (artifacts/f'{name}.json').write_text(result.stdout,encoding='utf-8')
                (artifacts/f'{name}.stderr').write_text(result.stderr,encoding='utf-8')
                print('JS_HEAP_EXPORT_E2E_PASS',name,flush=True)

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
            ('native-alias-override', 'const alias = Object; alias.assign = external; const o = {html: req.query.html}; Object.assign(o, {html:"safe"}); res.send(o.html);', {'xss'}),
            ('native-prototype-override', 'Array.prototype.push = external; const o = []; res.send(o.push(req.query.html));', {'xss'}),
            ('native-computed-override', 'Object[key] = external; const o = {html:req.query.html}; Object.assign(o,{html:"safe"}); res.send(o.html);', {'xss'}),
            ('native-reflection', 'Reflect.defineProperty(Array.prototype,"push",{value:external}); const o=[]; res.send(o.push(req.query.html));', {'xss'}),
            ('native-snapshot-clean', 'const copy=Object.assign; Object.assign=external; const o={html:req.query.html}; copy(o,{html:"safe"}); res.send(o.html);', set()),
            ('native-receiver-snapshot', 'let selected=[]; const original=selected; function swap(){selected=[]; return req.query.html;} selected.push(swap()); res.send(original[0]);', {'xss'}),
            ('native-argument-snapshot', 'function replace(){Object.assign=external; return {html:"safe"};} const o={html:req.query.html}; Object.assign(o,replace()); res.send(o.html);', set()),
            ('optional-native-copy', 'const r={}; if(flag)r.assign=external; Object.assign(Object,r); const o={html:req.query.html}; Object.assign(o,{html:"safe"}); res.send(o.html);', {'xss'}),
            ('spread-once', 'let html=req.query.html; function take(){const old=html;html="safe";return old;} function output(x){res.send(x);} output(...[take()]);', {'xss'}),
            ('sparse-reverse', 'const o=["safe",...req.query.items];o.length=2;o.reverse();res.send(o[0]);', {'xss'}),
            ('sparse-truncate-clean', 'const o=[...req.query.items];o.length=0;o.length=4;res.send(o.pop());', set()),
            ('spread-named-clean', 'const o=["safe"];o.extra=req.query.html;const other=[...o];res.send(other.join(""));', set()),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='ubs-heap-e2e-') as tmp:
                path = Path(tmp) / 'app.ts'
                path.write_text(source + '\n', encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(path), '--only=js', '--ci', '--format=json'],
                                        cwd=tmp, text=True, capture_output=True, timeout=120)
                self.assertIn(result.returncode, (0, 1), (result.stdout, result.stderr))
                report = json.loads(result.stdout)
                artifacts = ROOT / 'test-suite' / 'artifacts' / 'javascript-heap-shapes'
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / f'{name}.json').write_text(result.stdout, encoding='utf-8')
                (artifacts / f'{name}.stderr').write_text(result.stderr, encoding='utf-8')
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
