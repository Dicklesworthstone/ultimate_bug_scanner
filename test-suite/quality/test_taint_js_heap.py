"""D6 regressions: allocation identity, property writes, aliases and joins."""
from __future__ import annotations

from collections import Counter
import itertools
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_js as taint
from ubs_core.registry import RunContext


class HeapTaintTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(case is self for case, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def scan(self, source, *rules):
        with tempfile.TemporaryDirectory(prefix='ubs-heap-') as scratch:
            path = Path(scratch) / 'handler.js'
            path.write_text(source + '\n', encoding='utf-8')
            findings = list(taint.run(RunContext(lang='javascript', files=[path])))
        self.assertEqual(Counter(f['rule'].removeprefix('javascript.taint.') for f in findings),
                         Counter(rules), (source, findings))
        for finding in findings:
            self.assertEqual(finding['severity'], 'critical')
            self.assertGreater(finding['line'], 0)
            self.assertGreater(finding['col'], 0)
            self.assertIn(' -> ', finding['message'])
        return findings

    def assert_runtime_sends(self, source, expected):
        """Use fixed harmless markers to check the independent JS behavior."""
        node = shutil.which('node')
        if node is None:
            return  # The scanner assertions still run without this optional oracle.
        fixture = ('const req = {query: {html: "review-input"}}; '
                   'const observed = []; const res = {send(value) { observed.push(value); }};\n')
        result = subprocess.run([node, '-e', fixture + source
                                 + '\nprocess.stdout.write(JSON.stringify(observed));'],
                                text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, (source, result.stdout, result.stderr))
        self.assertEqual(json.loads(result.stdout), expected, source)

    def test_write_through_alias_reaches_original(self):
        self.scan('const box = {}; const alias = box; alias.html = req.query.html; res.send(box.html);', 'xss')

    def test_nested_factory_captures_unassigned_parameter(self):
        factory = ('function simulate(label) { function get() { return { note: label }; } '
                   'return get(); }\n')
        self.scan(factory + 'res.send(simulate(req.query.label).note);', 'xss')
        for first, second, sink, rules in (
            ('req.query.label', '"safe"', 'a', ('xss',)),
            ('req.query.label', '"safe"', 'b', ()),
            ('"safe"', 'req.query.label', 'a', ()),
            ('"safe"', 'req.query.label', 'b', ('xss',)),
        ):
            with self.subTest(first=first, second=second, sink=sink):
                self.scan(factory + f'const a = simulate({first}); const b = simulate({second}); '
                          f'res.send({sink}.note);', *rules)

    def test_recursive_nested_factory_preserves_captured_parameter(self):
        self.scan('function simulate(label) { function get(n) { '
                  'if (n > 0) return get(n - 1); return { note: label, kind: "safe" }; } '
                  'return get(3); } const a = simulate(req.query.label); '
                  'const b = simulate("safe"); res.send(a.note); res.send(b.note); res.send(a.kind);', 'xss')

    def test_nested_setter_mutates_unassigned_object_parameter(self):
        factory = ('function outer(box, value) { '
                   'function set() { box.html = value; } set(); }\n')
        calls = ('outer(dirty, req.query.html);', 'outer(clean, "safe");')
        for order in (calls, calls[::-1]):
            with self.subTest(order=order):
                findings = self.scan(factory
                    + 'const dirty = {}; const alias = dirty; const clean = {};\n'
                    + '\n'.join(order) + '\n'
                    + 'res.send(alias.html);\nres.send(clean.html);', 'xss')
                self.assertEqual(findings[0]['line'], 5)
                self.assertIn('req.query.html', findings[0]['message'])

    def test_transitive_nested_setter_preserves_captured_heap(self):
        self.scan('function outer(box, value) { function middle() { '
                  'function set() { box.html = value; } set(); } middle(); } '
                  'const result = {}; outer(result, req.query.html); res.send(result.html);', 'xss')

    def test_nested_captured_property_read_keeps_field_precision(self):
        factory = ('function outer(box) { function get() { return box.html; } '
                   'return get(); } ')
        self.scan(factory + 'res.send(outer({html: req.query.html, kind: "safe"}));', 'xss')
        self.scan(factory + 'res.send(outer({html: "safe", kind: req.query.html}));')

    def test_nested_captured_heap_cleanup_requires_definite_write(self):
        for statement, rules in (('box.html = "safe";', ()),
                                 ('if (flag) box.html = "safe";', ('xss',)),
                                 ('return; box.html = "safe";', ('xss',))):
            with self.subTest(statement=statement):
                self.scan('function outer(box) { function clear() { ' + statement
                          + ' } clear(); } const result = {html: req.query.html}; '
                          'outer(result); res.send(result.html);', *rules)

    def test_nested_captured_heap_respects_shadowing_rebinding_and_execution(self):
        for helper, call in (
            ('function set(box) { box.html = req.query.html; }', 'set({})'),
            ('function set() { const box = {}; box.html = req.query.html; }', 'set()'),
            ('function set() { box = {}; box.html = req.query.html; }', 'set()'),
            ('function set() { box.html = req.query.html; }', ''),
        ):
            with self.subTest(helper=helper, call=call):
                self.scan('function outer(box) { ' + helper + ' ' + call + '; } '
                          'const result = {html: "safe"}; outer(result); res.send(result.html);')

    def test_nested_array_mutator_keeps_captured_identity_and_sanitizer_domains(self):
        findings = self.scan('function outer(items, value) { '
                  'function append() { items.push(value); } append(); }\n'
                  'const dirty = []; const clean = [];\n'
                  'outer(dirty, req.query.html); outer(clean, DOMPurify.sanitize(req.query.html));\n'
                  'res.send(dirty[0]);\nres.send(clean[0]);\neval(clean[0]);', 'xss', 'eval')
        self.assertEqual([(finding['rule'], finding['line']) for finding in findings],
                         [('javascript.taint.xss', 4), ('javascript.taint.eval', 6)])

    def test_nested_captured_heap_mutation_survives_exception(self):
        findings = self.scan('function outer(box, value) { function set() { '
                  'box.html = value; throw "stop"; } set(); }\n'
                  'const dirty = {}; const clean = {};\n'
                  'try { outer(dirty, req.query.html); } catch (error) { res.send(dirty.html); }\n'
                  'try { outer(clean, "safe"); } catch (error) { res.send(clean.html); }', 'xss')
        self.assertEqual(findings[0]['line'], 3)

    def test_destructured_declarations_preserve_nested_aliases(self):
        for declaration in (
            'const {child: alias} = {child: box};',
            'const [alias] = [box];',
            'const {nested: [alias]} = {nested: [box]};',
            'const {"child-key": alias} = {"child-key": box};',
            'const {child: alias}: {child: object} = {child: box};',
        ):
            with self.subTest(declaration=declaration):
                self.scan('const box = {html: "safe"}; ' + declaration
                          + ' alias.html = req.query.html; res.send(box.html);', 'xss')

    def test_destructured_bindings_keep_clean_fields_and_objects_separate(self):
        self.scan('const {safe, dirty} = {safe: "hello", dirty: req.query.html}; '
                  'res.send(safe); res.send(dirty);', 'xss')
        self.scan('const a = {}; const b = {}; '
                  'const {first, second} = {first: a, second: b}; '
                  'first.html = req.query.html; res.send(second.html);')
        self.scan('const [safe, dirty] = ["hello", req.query.html]; '
                  'res.send(safe); res.send(dirty);', 'xss')

    def test_destructured_scalars_are_snapshots_and_objects_are_aliases(self):
        self.scan('const box = {html: "safe"}; const {html: snapshot} = box; '
                  'box.html = req.query.html; res.send(snapshot);')
        self.scan('const box = {html: req.query.html}; const {html: snapshot} = box; '
                  'box.html = "safe"; res.send(snapshot);', 'xss')
        self.scan('const box = {child: {html: "safe"}}; const {child: alias} = box; '
                  'alias.html = req.query.html; res.send(box.child.html);', 'xss')

    def test_destructuring_assignment_updates_existing_lexical_binding(self):
        for assignment in ('({box: alias} = {box});', '[alias] = [box];'):
            with self.subTest(assignment=assignment):
                self.scan('const box = {}; let alias; ' + assignment
                          + ' alias.html = req.query.html; res.send(box.html);', 'xss')
        findings = self.scan('let result = {}; function assign() { '
                  '({box: result} = {box: {html: req.query.html}}); }\n'
                  '{ const result = {html: "safe"}; assign(); res.send(result.html); }\n'
                  'res.send(result.html);', 'xss')
        self.assertEqual(findings[0]['line'], 3)

    def test_destructuring_assignment_writes_through_member_targets(self):
        for assignment in ('({html: box.html} = {html: req.query.html});',
                           '[box.html] = [req.query.html];',
                           '({child: box["html"]} = {child: req.query.html});'):
            with self.subTest(assignment=assignment):
                self.scan('const box = {}; const alias = box; ' + assignment
                          + ' res.send(alias.html);', 'xss')
        self.scan('const box = {html: req.query.html}; '
                  '({html: box.html} = {html: "safe"}); res.send(box.html);')

    def test_destructuring_member_target_runs_before_source_read_and_default(self):
        for initial, changed, rules in (('"safe"', 'req.query.html', ('xss',)),
                                         ('req.query.html', '"safe"', ())):
            with self.subTest(initial=initial, changed=changed):
                self.scan('let value = ' + initial + '; const out = {}; '
                          'function key() { value = ' + changed + '; return "html"; } '
                          '({x: out[key()] = value} = {}); res.send(out.html);', *rules)
                self.scan('const src = {x: ' + initial + '}; const out = {}; '
                          'function key() { src.x = ' + changed + '; return "html"; } '
                          '({x: out[key()]} = src); res.send(out.html);', *rules)
                self.scan('const src = [' + initial + ']; const out = {}; '
                          'function key() { src[0] = ' + changed + '; return "html"; } '
                          '([out[key()]] = src); res.send(out.html);', *rules)

    def test_destructuring_member_target_is_evaluated_once_and_keeps_receiver(self):
        self.scan('let value = "safe"; let saved = req.query.html; const out = {}; '
                  'function key() { const old = value; value = saved; saved = old; return "html"; } '
                  '({x: out[key()] = value} = {}); res.send(out.html); res.send(value);', 'xss', 'xss')
        self.scan('const first = {}; let out = first; '
                  'function key() { out = {}; return "html"; } '
                  '({x: out[key()]} = {x: req.query.html}); '
                  'res.send(first.html); res.send(out.html);', 'xss')

    def test_destructuring_member_target_throw_skips_default_and_assignment(self):
        self.scan('const out = {}; const observed = {}; '
                  'function key() { throw "stop"; } '
                  'function fallback() { observed.html = req.query.html; return "safe"; } '
                  'try { ({x: out[key()] = fallback()} = {}); } catch (error) {} '
                  'res.send(observed.html); res.send(out.html);')

    def test_destructuring_rest_target_runs_before_shallow_copy(self):
        for initial, changed, rules in (('"safe"', 'req.query.html', ('xss',)),
                                         ('req.query.html', '"safe"', ())):
            with self.subTest(initial=initial, changed=changed):
                self.scan('const src = {html: ' + initial + '}; const out = {}; '
                          'function key() { src.html = ' + changed + '; return "copy"; } '
                          '({...out[key()]} = src); res.send(out.copy.html);', *rules)

    def test_destructuring_member_writes_reach_dom_sinks(self):
        for assignment in (
            '({html: element.innerHTML} = {html: req.query.html});',
            '([element.innerHTML] = [req.query.html]);',
            '({html: element["innerHTML"]} = {html: req.query.html});',
            '({html: element.outerHTML} = {html: req.query.html});',
            '({html: element.dangerouslySetInnerHTML} = {html: req.query.html});',
            '({html: element.innerHTML = req.query.html} = {});',
        ):
            with self.subTest(assignment=assignment):
                findings = self.scan(assignment, 'xss')
                marker = '[' if 'element[' in assignment else '.'
                self.assertEqual(findings[0]['col'], assignment.index(marker, assignment.index('element')) + 1)
        self.scan('function render(value) { ({html: element.innerHTML} = value); } '
                  'render({html: req.query.html});', 'xss')

    def test_destructuring_dom_sinks_respect_fields_sanitizers_and_execution(self):
        self.scan('({html: element.innerHTML} = {html: "safe", other: req.query.html});')
        self.scan('const value = {html: DOMPurify.sanitize(req.query.html)}; '
                  '({html: element.innerHTML} = value); eval(value.html);', 'eval')
        self.scan('if (false) { ({html: element.innerHTML} = {html: req.query.html}); }')
        self.scan('const text = "([element.innerHTML] = [req.query.html]);";')
        self.scan('const value = {html: req.query.html}; '
                  'const names = [element.innerHTML]; const {html} = value;')

    def test_destructured_parameters_preserve_borrowed_objects_and_callers(self):
        for pattern, dirty, clean in (
            ('{child: box}', '{child: a}', '{child: b}'),
            ('[box]', '[a]', '[b]'),
            ('{nested: [box]}', '{nested: [a]}', '{nested: [b]}'),
        ):
            with self.subTest(pattern=pattern):
                findings = self.scan('function put(' + pattern
                    + ', value) { box.html = value; }\n'
                    'const a = {}; const b = {};\n'
                    'put(' + dirty + ', req.query.html); put(' + clean + ', "safe");\n'
                    'res.send(a.html);\nres.send(b.html);', 'xss')
                self.assertEqual(findings[0]['line'], 4)

    def test_destructured_parameter_reads_keep_field_precision(self):
        for declaration in (
            'function read({html}) { return html; }',
            'function read({html}: {html: string, other: string}) { return html; }',
            'const read = ({html}) => html;',
        ):
            with self.subTest(declaration=declaration):
                self.scan(declaration + ' res.send(read({html: "safe", other: req.query.html}));')
                self.scan(declaration + ' res.send(read({html: req.query.html, other: "safe"}));', 'xss')

    def test_destructured_defaults_observe_earlier_bindings(self):
        self.scan('const {html, copy = html} = {html: req.query.html}; res.send(copy);', 'xss')
        self.scan('function read({html, copy = html}) { return copy; } '
                  'res.send(read({html: req.query.html}));', 'xss')
        self.scan('function read(box, {child = box}) { return child; } '
                  'const box = {}; const alias = read(box, {}); alias.html = req.query.html; '
                  'res.send(box.html);', 'xss')

    def test_ternary_destructured_defaults_do_not_become_property_aliases(self):
        for fallback in ('flag ? req.query.html : "safe"', 'flag ? "safe" : req.query.html'):
            with self.subTest(fallback=fallback):
                self.scan('const {value = ' + fallback + '} = {}; res.send(value);', 'xss')
                self.scan('function read({value = ' + fallback + '}) { return value; } '
                          'res.send(read({}));', 'xss')
                self.scan('try { throw {}; } catch ({value = ' + fallback
                          + '}) { res.send(value); }', 'xss')

    def test_destructured_defaults_use_captured_values_without_mixing_callers(self):
        findings = self.scan('function factory(label) { function read({html = label}) { '
                  'return {html}; } return read({}); }\n'
                  'const a = factory(req.query.first); const b = factory(req.query.second); '
                  'const clean = factory("safe");\n'
                  'res.send(a.html);\nres.send(b.html);\nres.send(clean.html);', 'xss', 'xss')
        self.assertEqual([finding['line'] for finding in findings], [3, 4])
        for finding, source, other in zip(findings, ('first', 'second'), ('second', 'first')):
            self.assertIn('req.query.' + source, finding['message'])
            self.assertNotIn('req.query.' + other, finding['message'])

    def test_missing_destructured_defaults_execute_and_known_objects_bypass(self):
        self.scan('const {value = req.query.html} = {}; res.send(value);', 'xss')
        self.scan('function read({value = req.query.html}) { return value; } res.send(read({}));', 'xss')
        self.scan('const {value = {html: req.query.html}} = {value: {html: "safe"}}; '
                  'res.send(value.html);')
        self.scan('function read({value = {html: req.query.html}}) { return value; } '
                  'res.send(read({value: {html: "safe"}}).html);')
        self.scan('function read({html} = {html: req.query.html}) { return html; } '
                  'res.send(read());', 'xss')

    def test_destructured_defaults_keep_bypass_paths_for_unknown_fields(self):
        prefix = ('const box = {html: req.query.html}; '
                  'function clear() { box.html = "safe"; } ')
        self.scan(prefix + 'const {unused = clear()} = unknown; res.send(box.html);', 'xss')
        self.scan(prefix + 'function read({unused = clear()}) {} read(unknown); res.send(box.html);', 'xss')
        self.scan('const {html = "safe"} = req.query; res.send(html);', 'xss')

    def test_destructured_computed_keys_run_before_later_property_reads(self):
        source = ('const box = {next: "safe"}; '
                  'function change() { box.next = req.query.html; return "first"; } ')
        self.scan(source + 'const {[change()]: first, next} = box; res.send(next);', 'xss')
        self.scan(source + 'function read({[change()]: first, next}) { return next; } '
                  'res.send(read(box));', 'xss')

    def test_destructured_default_throws_keep_prior_writes_and_skip_body(self):
        prefix = ('const box = {}; function reject() { '
                  'box.html = req.query.html; throw {html: req.query.code}; }\n')
        for declaration, invocation in (
            ('', 'const {value = reject()} = {};'),
            ('function read({value = reject()}) { box.html = "safe"; }\n', 'read({});'),
        ):
            with self.subTest(invocation=invocation):
                self.scan(prefix + declaration + 'try { ' + invocation
                          + ' } catch (error) { res.send(box.html); eval(error.html); }', 'xss', 'eval')

    def test_object_rest_is_a_shallow_copy_with_excluded_fields(self):
        self.scan('const box = {skip: req.query.html, child: {html: "safe"}}; '
                  'const {skip, ...rest} = box; res.send(rest.skip); '
                  'rest.child.html = req.query.code; eval(box.child.html);', 'eval')
        self.scan('const box = {html: "safe"}; const {...rest} = box; '
                  'rest.html = req.query.html; res.send(box.html);')
        self.scan('const {skip, ...rest} = {skip: "safe", html: req.query.html}; '
                  'res.send(rest.html);', 'xss')

    def test_array_rest_reindexes_elements_and_preserves_nested_aliases(self):
        self.scan('const box = {}; const [skip, ...tail] = [req.query.secret, box]; '
                  'tail[0].html = req.query.html; res.send(box.html); '
                  'res.send(tail.length); res.send(tail[1]);', 'xss')
        self.scan('const [skip, ...tail] = [req.query.secret, "safe"]; res.send(tail[0]);')

    def test_parameter_rest_copies_keep_separate_calls(self):
        for pattern, dirty, clean, field in (
            ('{skip, ...rest}', '{skip: "safe", html: req.query.html}',
             '{skip: req.query.secret, html: "safe"}', '.html'),
            ('[skip, ...rest]', '["safe", req.query.html]',
             '[req.query.secret, "safe"]', '[0]'),
        ):
            with self.subTest(pattern=pattern):
                findings = self.scan('function read(' + pattern + ') { return rest; }\n'
                    'const dirty = read(' + dirty + '); const clean = read(' + clean + ');\n'
                    'res.send(dirty' + field + ');\nres.send(clean' + field + ');', 'xss')
                self.assertEqual(findings[0]['line'], 3)
                self.assertNotIn('req.query.secret', findings[0]['message'])

    def test_destructured_rest_formals_keep_positions_and_borrowed_objects(self):
        for pattern in ('...[box, value]', '...{0: box, 1: value}',
                        '...[box, value]: [object, string]'):
            with self.subTest(pattern=pattern):
                findings = self.scan('function put(skip, ' + pattern + ') { box.html = value; }\n'
                    'const dirty = {}; const clean = {};\n'
                    'put(req.query.secret, dirty, req.query.html); put(req.query.secret, clean, "safe");\n'
                    'res.send(dirty.html);\nres.send(clean.html);', 'xss')
                self.assertEqual(findings[0]['line'], 4)
                self.assertNotIn('req.query.secret', findings[0]['message'])
        self.scan('function put(...[[box], , value]) { box.html = value; } '
                  'const box = {}; put([box], "skip", req.query.html); res.send(box.html);', 'xss')

    def test_destructured_rest_formals_keep_clean_fields_and_defaults(self):
        self.scan('function read(...[box]) { return box.html; } '
                  'res.send(read({html: req.query.html}));', 'xss')
        self.scan('function read(...[box]) { return box.html; } '
                  'res.send(read({html: "safe", other: req.query.html}));')
        self.scan('function read(...[box = {html: req.query.html}]) { return box; } '
                  'res.send(read().html);', 'xss')
        self.scan('function read(...[box = {html: req.query.html}]) { return box; } '
                  'res.send(read({html: "safe"}).html);')

    def test_rest_argument_arrays_are_fresh_shallow_copies(self):
        self.scan('function collect(...items) { return items; } '
                  'const first = collect("safe"); const second = collect("safe"); '
                  'first[0] = req.query.html; res.send(first[0]); res.send(second[0]); '
                  'res.send(first.length);', 'xss')
        self.scan('function collect(...items) { return items; } '
                  'const box = {}; const items = collect(box); '
                  'items[0].html = req.query.html; res.send(box.html);', 'xss')
        self.scan('function collect(...items) { items[0] = {html: req.query.html}; } '
                  'const box = {html: "safe"}; collect(box); res.send(box.html);')
        self.scan('function collect(...items) { return items; } '
                  'const value = collect(DOMPurify.sanitize(req.query.html)); '
                  'res.send(value[0]); eval(value[0]);', 'eval')

    def test_rest_formals_preserve_known_and_uncertain_spread_elements(self):
        prefix = 'function put(...[box, value]) { box.html = value; } const box = {}; '
        self.scan(prefix + 'const args = [box, req.query.html]; '
                  'put(...args); res.send(box.html);', 'xss')
        self.scan(prefix + 'const args = [box]; if (flag) args.push({}); '
                  'put(...args, req.query.html); res.send(box.html);', 'xss')
        self.scan('function read(...[skip, ...tail]) { return tail; } '
                  'const args = [req.query.secret, "safe"]; '
                  'res.send(read(...args)[0]);')
        self.scan('function put(...[box, value]) { box.html = value; } '
                  'const box = {html: req.query.html}; const args = [box, "safe"]; '
                  'put(...args); res.send(box.html);')

    def test_known_array_spreads_keep_default_and_bypass_paths(self):
        for literal in ('[undefined]', '[void 0]', '[,]'):
            with self.subTest(literal=literal):
                self.scan('function read(value = req.query.html) { return value; } '
                          'const args = ' + literal + '; res.send(read(...args));', 'xss')
        self.scan('const box = {html: req.query.html}; '
                  'function clear() { box.html = "safe"; } '
                  'function read(value = clear()) {} '
                  'const args = ["safe"]; read(...args); res.send(box.html);', 'xss')
        self.scan('function read(value = {html: req.query.html}) { return value; } '
                  'const args = [{html: "safe"}]; res.send(read(...args).html);')

    def test_spread_elements_are_snapshotted_before_later_arguments(self):
        for initial, replacement, expected, rules in (
            ('req.query.html', '"safe"', ['review-input'], ('xss',)),
            ('"safe"', 'req.query.html', ['safe'], ()),
        ):
            for formal in ('value', '...[value]'):
                with self.subTest(initial=initial, replacement=replacement, formal=formal):
                    source = ('function read(' + formal + ') { return value; } '
                              'const items = [' + initial + ']; '
                              'function replace() { items[0] = ' + replacement + '; return 0; } '
                              'res.send(read(...items, replace()));')
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)

    def test_spreads_preserve_yielded_object_identity_and_run_once(self):
        cases = (
            ('const box = {html: "safe"}; const items = [box]; '
             'function replace() { items[0] = {html: req.query.html}; } '
             'res.send(read(...items, replace()).html);', ['safe'], ()),
            ('const box = {html: "safe"}; const items = [box]; '
             'function change() { box.html = req.query.html; } '
             'res.send(read(...items, change()).html);', ['review-input'], ('xss',)),
            ('let first = req.query.html; let second = "safe"; '
             'function values() { const old = first; first = second; second = old; return []; } '
             'read(...values()); res.send(first);', ['safe'], ()),
            ('const values = ["safe", req.query.html]; '
             'res.send(read(...values.reverse()));', ['review-input'], ('xss',)),
        )
        for body, expected, rules in cases:
            with self.subTest(body=body):
                source = 'function read(...[value]) { return value; } ' + body
                self.assert_runtime_sends(source, expected)
                self.scan(source, *rules)

    def test_later_parameter_defaults_update_earlier_bindings(self):
        for initial, replacement, expected, rules in (
            ('"safe"', 'req.query.html', ['review-input'], ('xss',)),
            ('req.query.html', '"safe"', ['safe'], ()),
        ):
            for formal, arguments in (
                ('{value}, ignored = (value = ' + replacement + ')', '{value: ' + initial + '}'),
                ('value, {ignored = (value = ' + replacement + ')}', initial + ', {}'),
                ('value, ignored = (value = ' + replacement + '), ...rest', initial),
                ('{value}, ignored = (value = ' + replacement + '), copy = value', '{value: ' + initial + '}'),
            ):
                with self.subTest(formal=formal, arguments=arguments):
                    result = 'copy' if 'copy = value' in formal else 'value'
                    source = ('function read(' + formal + ') { return ' + result + '; } '
                              'res.send(read(' + arguments + '));')
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)
        source = ('function read({value}, ignored = (value = {html: req.query.html})) { return value; } '
                  'res.send(read({value: {html: "safe"}}).html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')

    def test_nullish_destructured_arguments_throw_before_cleanup(self):
        for pattern, clean in (('{value}', '{}'), ('[value]', '[]')):
            for argument in ('', 'null', 'undefined', 'void 1', 'void (1 + 2)', clean):
                with self.subTest(pattern=pattern, argument=argument):
                    source = ('const box = {html: req.query.html}; '
                              'function clear(' + pattern + ') { box.html = "safe"; } '
                              'try { clear(' + argument + '); } catch (error) {} res.send(box.html);')
                    unsafe = argument != clean
                    self.assert_runtime_sends(source, ['review-input' if unsafe else 'safe'])
                    self.scan(source, *('xss',) if unsafe else ())
        source = ('const box = {html: req.query.html}; function clear({value}) { box.html = "safe"; } '
                  'clear("safe"); res.send(box.html);')
        self.assert_runtime_sends(source, ['safe'])
        self.scan(source)

    def test_nested_missing_patterns_and_null_defaults_keep_exception_store(self):
        for declaration, unsafe in (
            ('const {child: {value}} = {};', True),
            ('const [[value]] = [];', True),
            ('const {value} = null;', True),
            ('let value; ({value} = undefined);', True),
            ('const {child: {value} = null} = {};', True),
            ('const {child: {value} = {}} = {child: null};', True),
            ('const [[value] = []] = [null];', True),
            ('const {child: {value} = {}} = {};', False),
            ('const [[value] = []] = [];', False),
        ):
            with self.subTest(declaration=declaration):
                source = ('const box = {html: req.query.html}; try { ' + declaration
                          + ' box.html = "safe"; } catch (error) {} res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input' if unsafe else 'safe'])
                self.scan(source, *('xss',) if unsafe else ())
        for initial, replacement, expected, rules in (
            ('req.query.html', '"safe"', ['review-input'], ('xss',)),
            ('"safe"', 'req.query.html', ['safe'], ()),
        ):
            with self.subTest(initial=initial, replacement=replacement):
                source = ('const box = {html: ' + initial + '}; '
                          'function fallback() { box.html = ' + replacement + '; return {}; } try { '
                          'const {child: {value} = fallback()} = {child: null}; '
                          'box.html = "safe"; } catch (error) {} res.send(box.html);')
                self.assert_runtime_sends(source, expected)
                self.scan(source, *rules)

    def test_array_patterns_preserve_noniterable_failure_path(self):
        for argument, unsafe in (('1', True), ('true', True), ('1n', True),
                                 ('0x10', True), ('{}', True), ('[]', False),
                                 ('"safe"', False), ('`safe`', False),
                                 ('`${req.query.html}`', False)):
            for pattern in ('[value]', '{value}'):
                with self.subTest(argument=argument, pattern=pattern):
                    source = ('const box = {html: req.query.html}; '
                              'function clear(' + pattern + ') { box.html = "safe"; } '
                              'try { clear(' + argument + '); } catch (error) {} res.send(box.html);')
                    throws = unsafe and pattern == '[value]'
                    self.assert_runtime_sends(source, ['review-input' if throws else 'safe'])
                    self.scan(source, *('xss',) if throws else ())
        source = ('const box = {html: req.query.html}; try { const [value] = 1; '
                  'box.html = "safe"; } catch (error) {} res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        source = ('function render([value], input) { res.send(input); } '
                  'try { render(1, req.query.html); } catch (error) {}')
        self.assert_runtime_sends(source, [])
        self.scan(source)

    def test_parenthesized_templates_keep_string_shape_and_interpolation_effects(self):
        for template, expected in (
            ('`safe`', 'safe'), ('`${null}`', 'null'), ('`${undefined}`', 'undefined'),
            ('`${void 0}`', 'undefined'), ('`${1}`', '1'), ('`${true}`', 'true'),
        ):
            for depth in (1, 2):
                argument = '(' * depth + template + ')' * depth
                for pattern in ('{value}', '[value]'):
                    with self.subTest(argument=argument, pattern=pattern):
                        source = ('function render(' + pattern + ', input) { res.send(input); } '
                                  'render(' + argument + ', req.query.html);')
                        self.assert_runtime_sends(source, ['review-input'])
                        self.scan(source, 'xss')
                        source = ('const box = {html: req.query.html}; '
                                  'function clear(' + pattern + ') { box.html = "safe"; } '
                                  'try { clear(' + argument + '); } catch (error) {} res.send(box.html);')
                        self.assert_runtime_sends(source, ['safe'])
                        self.scan(source)
                source = ('function read(value = req.query.html) { return value; } '
                          'res.send(read(' + argument + '));')
                self.assert_runtime_sends(source, [expected])
                self.scan(source)
        source = ('let first = req.query.html; let second = "safe"; '
                  'function change() { const old = first; first = second; second = old; return null; } '
                  'function render([value], input) { res.send(input); } '
                  'render((`${change()}`), first); res.send(second);')
        self.assert_runtime_sends(source, ['safe', 'review-input'])
        findings = self.scan(source, 'xss')
        self.assertEqual(findings[0]['col'], source.index('res.send(second)') + 1)

    def test_spread_parameter_defaults_keep_separate_entry_exception_stores(self):
        for pattern, fallback in (('{value}', '{}'), ('[value]', '[]')):
            for initial, replacement, argument, expected, rules in (
                ('req.query.html', '"safe"', 'null', ['review-input'], ('xss',)),
                ('"safe"', 'req.query.html', 'null', ['safe'], ()),
                ('"safe"', 'req.query.html', 'req.query.html', ['safe'], ()),
                ('req.query.html', '"safe"', ',', ['safe'], ()),
                ('req.query.html', 'req.query.html', fallback, ['safe'], ()),
            ):
                with self.subTest(pattern=pattern, argument=argument, replacement=replacement):
                    source = ('const box = {html: ' + initial + '}; '
                              'function fallback() { box.html = ' + replacement + '; return ' + fallback + '; } '
                              'function clear(' + pattern + ' = fallback()) { box.html = "safe"; } '
                              'const args = [' + argument + ']; '
                              'try { clear(...args); } catch (error) {} res.send(box.html);')
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)
            for result in ('null', 'undefined', 'void req.query.html'):
                with self.subTest(pattern=pattern, default_result=result):
                    source = ('const box = {html: "safe"}; '
                              'function fallback() { box.html = req.query.html; return ' + result + '; } '
                              'function clear(' + pattern + ' = fallback()) { box.html = "safe"; } '
                              'const args = [undefined]; '
                              'try { clear(...args); } catch (error) {} res.send(box.html);')
                    self.assert_runtime_sends(source, ['review-input'])
                    self.scan(source, 'xss')

    def test_nested_defaults_do_not_put_initializer_effects_on_null_bypass(self):
        for binding, argument in (
            ('{child: {value} = fallback()}', '{child: req.query.html}'),
            ('[[value] = fallback()]', '[req.query.html]'),
            ('...[{value} = fallback()]', 'req.query.html'),
        ):
            with self.subTest(binding=binding):
                fallback = '[]' if binding.startswith('[') else '{}'
                source = ('const box = {html: "safe"}; '
                          'function fallback() { box.html = req.query.html; return ' + fallback + '; } '
                          'function clear(' + binding + ') { box.html = "safe"; } '
                          'try { clear(' + argument + '); } catch (error) {} res.send(box.html);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan(source)

    def test_destructuring_exception_preserves_prior_default_effects(self):
        for initial, prior, later, expected, rules in (
            ('"safe"', 'req.query.html', '"safe"', ['review-input'], ('xss',)),
            ('req.query.html', '"safe"', 'req.query.html', ['safe'], ()),
        ):
            with self.subTest(prior=prior):
                source = ('const box = {html: ' + initial + '}; '
                          'function read(first = (box.html = ' + prior + '), {value}) { '
                          'box.html = ' + later + '; } '
                          'try { read(); } catch (error) {} res.send(box.html);')
                self.assert_runtime_sends(source, expected)
                self.scan(source, *rules)
        source = ('function render({value}, input) { res.send(input); } '
                  'try { render(null, req.query.html); } catch (error) {}')
        self.assert_runtime_sends(source, [])
        self.scan(source)
        source = ('function read({value} = {value: req.query.html}) { return value; } '
                  'try { res.send(read(null)); } catch (error) {}')
        self.assert_runtime_sends(source, [])
        self.scan(source)

    def test_uncertain_destructuring_cannot_prove_catch_path_cleanup(self):
        for actual, expected, rules in (('null', ['review-input'], ('xss',)),
                                         ('{}', ['safe'], ())):
            with self.subTest(actual=actual):
                source = ('const box = {html: req.query.html}; const input = ' + actual + '; '
                          'function clear({value}) { box.html = "safe"; } '
                          'try { clear(input); } catch (error) {} res.send(box.html);')
                self.assert_runtime_sends(source, expected)
                self.scan(source, *rules)

    def test_shadowed_undefined_does_not_activate_parameter_defaults(self):
        for value, formal, result in (
            ('"safe"', 'value = req.query.html', 'value'),
            ('{html: "safe"}', '{html} = {html: req.query.html}', 'html'),
        ):
            for declaration, call in (('const undefined = ' + value + ';', 'outer();'),
                                      ('', 'outer(' + value + ');')):
                with self.subTest(value=value, declaration=declaration):
                    parameters = '' if declaration else 'undefined'
                    source = ('function outer(' + parameters + ') { ' + declaration
                              + ' function read(' + formal + ') { return ' + result + '; } '
                              'res.send(read(undefined)); } ' + call)
                    self.assert_runtime_sends(source, ['safe'])
                    self.scan(source)

    def test_body_undefined_declarations_do_not_shadow_parameter_initializers(self):
        for declaration in ('var undefined = "body";', 'let undefined = "body";',
                            'const undefined = "body";', 'function undefined() { return "body"; }'):
            with self.subTest(declaration=declaration):
                source = ('function read(value = req.query.html) { return value; } '
                          'function outer(value = read(undefined)) { ' + declaration + ' return value; } '
                          'res.send(outer());')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')
                for actual, expected, rules in (('"safe"', ['safe'], ()),
                                                 ('req.query.html', ['review-input'], ('xss',))):
                    source = ('function read(value = "safe") { return value; } '
                              'function outer(undefined) { function inner(value = read(undefined)) { '
                              + declaration + ' return value; } return inner(); } '
                              'res.send(outer(' + actual + '));')
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)
        for actual, expected, rules in (('"safe"', ['safe'], ()),
                                         ('req.query.html', ['review-input'], ('xss',))):
            source = ('function read(value = "safe") { return value; } '
                      'function outer(undefined, value = read(undefined)) { return value; } '
                      'res.send(outer(' + actual + '));')
            self.assert_runtime_sends(source, expected)
            self.scan(source, *rules)

    def test_shadowed_undefined_values_still_activate_defaults(self):
        read = 'function read(value = req.query.html) { return value; } '
        for body in (
            'function outer(undefined) { return read(undefined); }',
            'function outer(undefined, value = read(undefined)) { return value; }',
            'function outer() { var undefined; return read(undefined); }',
            'function outer() { const undefined = void 0; return read(undefined); }',
            'function outer() { let undefined; return read(((undefined))); }',
            'function outer() { const missing = void 0; const undefined = missing; return read(undefined); }',
            'function outer() { const {undefined} = {}; return read(undefined); }',
        ):
            with self.subTest(body=body):
                source = read + body + ' res.send(outer());'
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')

    def test_shadowed_undefined_contexts_keep_clean_actuals_separate(self):
        read = 'function read(value = req.query.html) { return value; } '
        for body in (
            'function outer(undefined) { return read(undefined); }',
            'function outer(undefined) { var undefined; return read(undefined); }',
            'function outer(undefined, value = read(undefined)) { return value; }',
            'function outer(undefined) { function inner() { return read(undefined); } return inner(); }',
        ):
            for actual in ('"safe"', 'null', '0', 'false'):
                with self.subTest(body=body, actual=actual):
                    source = read + body + '\nres.send(outer());\nres.send(outer(' + actual + '));'
                    self.assert_runtime_sends(source, ['review-input', json.loads(actual)])
                    findings = self.scan(source, 'xss')
                    self.assertEqual(findings[0]['line'], 2)
        source = (read + 'function outer() { var undefined = "safe"; var undefined; '
                  'return read(undefined); } res.send(outer());')
        self.assert_runtime_sends(source, ['safe'])
        self.scan(source)

    def test_shadowed_undefined_tracks_capture_and_initializer_writes(self):
        read = 'function read(value = req.query.html) { return value; } '
        for value, expected, rules in (('void 0', ['review-input'], ('xss',)),
                                       ('"safe"', ['safe'], ())):
            for body in (
                'function outer(undefined) { function set() { undefined = ' + value + '; } '
                'set(); return read(undefined); }',
                'function outer(undefined, unused = (undefined = ' + value + ')) { return read(undefined); }',
                'function outer(undefined) { undefined = ' + value + '; return read(undefined); }',
                'function outer(undefined) { function set() { undefined = ' + value + '; throw "stop"; } '
                'try { set(); } catch (error) {} return read(undefined); }',
            ):
                with self.subTest(body=body):
                    source = read + body + ' res.send(outer("initial"));'
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)
        source = (read + 'function outer() { let undefined = "safe"; '
                  '{ let undefined; res.send(read(undefined)); }\nres.send(read(undefined)); } outer();')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        findings = self.scan(source, 'xss')
        self.assertEqual(findings[0]['line'], 1)

    def test_shadowed_undefined_default_effects_preserve_bypass_and_snapshot(self):
        setup = ('const box = {html: req.query.html}; '
                 'function clear() { box.html = "safe"; return "safe"; } '
                 'function read(value = clear(), unused) {} ')
        for argument, expected, rules in (('', ['safe'], ()), ('"safe"', ['review-input'], ('xss',))):
            source = ('function outer(undefined) { ' + setup
                      + 'read(undefined); res.send(box.html); } outer(' + argument + ');')
            self.assert_runtime_sends(source, expected)
            self.scan(source, *rules)
        source = ('function outer(undefined) { ' + setup
                  + 'if (req.query.flag) undefined = void 0; read(undefined); '
                  'res.send(box.html); } outer("safe");')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        for initial, replacement, expected, rules in (
            ('void 0', '"safe"', ['safe'], ()),
            ('"safe"', 'void 0', ['review-input'], ('xss',)),
        ):
            source = ('function outer() { let undefined = ' + initial + '; ' + setup
                      + 'read(undefined, (undefined = ' + replacement + ')); '
                      'res.send(box.html); } outer();')
            self.assert_runtime_sends(source, expected)
            self.scan(source, *rules)

    def test_shadowed_undefined_recursive_and_uncalled_sources_are_retained(self):
        source = ('function read(value = req.query.html) { return value; } '
                  'function outer(undefined, depth) { if (depth) return outer(undefined, depth - 1); '
                  'return read(undefined); }\nres.send(outer(void 0, 2));\nres.send(outer("safe", 2));')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        findings = self.scan(source, 'xss')
        self.assertEqual(findings[0]['line'], 2)
        # Uncalled bodies are still analyzed as possible external entries.
        # A self edge alone must not suppress their independent source sites.
        self.scan('function outer(undefined) { res.send(req.query.html); outer(undefined); }', 'xss')

    def test_shadowed_undefined_annotations_do_not_change_runtime_values(self):
        for body in (
            'function outer(undefined: string | undefined = void 0) { return read(undefined); }',
            'function outer(undefined: string | undefined = void 0, value = read(undefined)) { return value; }',
            'function outer() { const undefined: string | undefined = void 0; return read(undefined); }',
        ):
            source = ('function read(value = req.query.html) { return value; } ' + body
                      + ' res.send(outer());')
            self.assert_runtime_sends(source.replace(': string | undefined', ''), ['review-input'])
            self.scan(source, 'xss')

    def test_shadowed_undefined_namespace_wrappers_keep_actual_kinds(self):
        helper = ('export function outer(undefined) { '
                  'function read(value = req.query.html) { return value; } return read(undefined); }')
        caller = ('import * as lib from "./helper.mjs"; '
                  'function wrapper(value) { return lib.outer(value); }\n'
                  'res.send(wrapper(void 0));\nres.send(wrapper("safe"));')
        self.assert_runtime_sends(helper.removeprefix('export ') + caller.replace(
            'import * as lib from "./helper.mjs";', '').replace('lib.outer', 'outer'),
            ['review-input', 'safe'])
        with tempfile.TemporaryDirectory(prefix='ubs-undefined-modules-') as scratch:
            root = Path(scratch)
            paths = [root / 'helper.mjs', root / 'app.mjs']
            for path, source in zip(paths, (helper, caller)):
                path.write_text(source, encoding='utf-8')
            findings = list(taint.scan_project_findings(paths))
            self.assertEqual([(path.name, rule, line) for path, rule, line, _, _ in findings],
                             [('app.mjs', 'js.taint.xss', 2)], findings)

    def test_void_arguments_apply_defaults_after_operand_effects(self):
        for argument in ('void 1', 'void (1 + 2)', 'void +1', 'void 1e2', 'void 1n',
                         'void ({value: "safe"})', 'void Math.abs(-1)', 'void function() {}'):
            with self.subTest(argument=argument):
                source = ('function read(value = req.query.html) { return value; } '
                          'res.send(read(' + argument + '));')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')
        source = ('const box = {html: "safe"}; function change() { box.html = req.query.html; return "safe"; } '
                  'function read(value = "safe") { return value; } '
                  'res.send(read(void change())); res.send(box.html);')
        self.assert_runtime_sends(source, ['safe', 'review-input'])
        self.scan(source, 'xss')
        source = ('const box = {html: req.query.html}; function clear() { box.html = "safe"; return req.query.html; } '
                  'function read(value = "safe") { return value; } '
                  'res.send(read(void clear())); res.send(box.html);')
        self.assert_runtime_sends(source, ['safe', 'safe'])
        self.scan(source)
        for expression in ('void 1 + 2', '(void 1, 2)'):
            source = ('function read(value = req.query.html) { return value; } '
                      'res.send(String(read(' + expression + ')));')
            self.assert_runtime_sends(source, ['NaN' if '+' in expression else '2'])
            self.scan(source)
        source = ('function read(value = "safe") { return value; } '
                  'res.send(read(void function() {} + req.query.html));')
        self.assert_runtime_sends(source, ['undefinedreview-input'])
        self.scan(source, 'xss')

    def test_void_defaults_discard_values_but_preserve_operand_effects(self):
        for source in (
            'function read(value = void req.query.html) { return value; } res.send(read());',
            'function read({value = void req.query.html}) { return value; } res.send(read({}));',
            'const {value = void req.query.html} = {}; res.send(value);',
            'const {value = void req.query.html} = {value: "safe"}; res.send(value);',
        ):
            with self.subTest(source=source):
                self.assert_runtime_sends(source, ['safe'] if 'value: "safe"' in source else [None])
                self.scan(source)
        source = ('const box = {html: "safe"}; '
                  'function change() { box.html = req.query.html; return req.query.html; } '
                  'function read(value = void change()) { return value; } '
                  'res.send(read()); res.send(box.html);')
        self.assert_runtime_sends(source, [None, 'review-input'])
        findings = self.scan(source, 'xss')
        self.assertEqual(findings[0]['col'], source.index('res.send(box.html)') + 1)
        source = 'const {value = void res.send(req.query.html)} = {}; res.send(value);'
        self.assert_runtime_sends(source, ['review-input', None])
        findings = self.scan(source, 'xss')
        self.assertEqual(findings[0]['col'], source.index('res.send(req.query.html)') + 1)

    def test_destructuring_targets_keep_function_returned_receivers(self):
        for target in ('target().html', '(target()).html', 'target()["html"]'):
            for initial, expected, rules in (('req.query.html', ['review-input'], ('xss',)),
                                             ('"safe"', ['safe'], ())):
                with self.subTest(target=target, initial=initial):
                    source = ('const box = {}; function target() { return box; } '
                              '({value: ' + target + '} = {value: ' + initial + '}); res.send(box.html);')
                    self.assert_runtime_sends(source, expected)
                    self.scan(source, *rules)
        source = ('const first = {}; let box = first; function target() { return box; } '
                  'function key() { box = {}; return "html"; } '
                  '([target()[key()]] = [req.query.html]); res.send(first.html); res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input', None])
        self.scan(source, 'xss')
        source = ('const box = {html: req.query.html}; function target() { throw "stop"; } '
                  'try { ({value: target().html = (box.html = "safe")} = {}); } catch (error) {} '
                  'res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        self.scan('function target() { return element; } '
                  '({value: target().innerHTML} = {value: req.query.html});', 'xss')

    def test_qualified_type_annotations_do_not_execute_binding_defaults_twice(self):
        prefix = ('let first = req.query.html; let second = "safe"; '
                  'function change() { const old = first; first = second; second = old; return "safe"; } ')
        for body in (
            'const {value = change()}: Box.Shape = {}; res.send(first);',
            'function read({value = change()}: Box.Shape) { return value; } read({}); res.send(first);',
        ):
            with self.subTest(body=body):
                source = prefix + body
                self.assert_runtime_sends(source.replace(': Box.Shape', ''), ['safe'])
                self.scan(source)

    def test_default_parameter_allocations_keep_callsite_identity(self):
        for initializer in ('{html: "safe"}', 'make()'):
            with self.subTest(initializer=initializer):
                source = ('function make() { return {html: "safe"}; } '
                          'function read(value = ' + initializer + ') { return value; } '
                          'const first = read(); const second = read(); '
                          'first.html = req.query.html; ')
                self.scan(source + 'res.send(second.html);')
                self.scan(source + 'res.send(first.html);', 'xss')

    def test_destructured_bindings_keep_sanitizer_domains(self):
        self.scan('const {html} = {html: DOMPurify.sanitize(req.query.html)}; '
                  'res.send(html); eval(html);', 'eval')
        self.scan('function read({html}) { return html; } '
                  'const value = read({html: DOMPurify.sanitize(req.query.html)}); '
                  'res.send(value); eval(value);', 'eval')

    def test_destructured_parameters_keep_selected_module_offsets_and_heap(self):
        functions = ('function put({box}, value) { box.html = value; }\n'
                     'function read({skip, ...rest}) { return rest; }\n')
        for extension, exports, imports in (
            ('js', 'export {put, read};', 'import {put, read} from "./z-lib.js";'),
            ('cjs', 'module.exports = {put, read};', 'const {put, read} = require("./z-lib.cjs");'),
        ):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory(prefix='ubs-pattern-modules-') as scratch:
                library = Path(scratch) / ('z-lib.' + extension)
                library.write_text(functions + exports + '\n', encoding='utf-8')
                caller = Path(scratch) / ('app.' + extension)
                caller.write_text(imports + '\nconst box = {};\n'
                    'put({box}, req.query.html);\n'
                    'const clean = read({skip: req.query.secret, html: "safe"});\n'
                    'res.send(box.html);\nres.send(clean.html);\n', encoding='utf-8')
                findings = list(taint.scan_project_findings([library, caller]))
                self.assertEqual([(path.name, rule, line) for path, rule, line, _, _ in findings],
                                 [(caller.name, 'js.taint.xss', 5)], findings)

    def test_mutual_recursion_preserves_borrowed_heap_mutations(self):
        source = ('function first(box, n) { if (n > 0) second(box, n - 1); '
                  'else box.html = box.input; } '
                  'function second(box, n) { first(box, n); } '
                  'const a = { input: req.query.x }; const b = { input: "safe" }; '
                  'first(a, 3); first(b, 3); ')
        self.scan(source + 'res.send(a.html);', 'xss')
        self.scan(source + 'res.send(b.html);')

    def test_state_inequality_includes_heap_and_captured_cells(self):
        before = taint._State()
        after = before.copy()
        after.heap[('allocation', 1)] = {'html': frozenset()}
        self.assertNotEqual(before, after)
        self.assertFalse(before == after)
        after = before.copy()
        after.cells[('scope', 1, 'label')] = frozenset()
        self.assertNotEqual(before, after)

    def test_write_through_original_reaches_alias(self):
        self.scan('const box = {}; const alias = box; box.html = req.query.html; res.send(alias.html);', 'xss')

    def test_clean_alias_write_replaces_property(self):
        self.scan('const box = {html: req.query.html}; const alias = box; alias.html = "safe"; res.send(box.html);')

    def test_rebinding_alias_does_not_clean_original_object(self):
        self.scan('const box = {html: req.query.html}; let alias = box; alias = {}; res.send(box.html);', 'xss')

    def test_rebinding_alias_does_not_taint_original_object(self):
        self.scan('const box = {}; let alias = box; alias = {}; alias.html = req.query.html; res.send(box.html);')

    def test_scalar_read_is_snapshot_not_alias(self):
        self.scan('const box = {html: "safe"}; const snapshot = box.html; box.html = req.query.html; res.send(snapshot);')
        self.scan('const box = {html: req.query.html}; const snapshot = box.html; box.html = "safe"; res.send(snapshot);', 'xss')

    def test_static_bracket_and_dot_access_alias(self):
        self.scan('const box = {}; const alias = box; alias["html"] = req.query.html; res.send(box.html);', 'xss')
        self.scan("const box = {html: req.query.html}; box['html'] = 'safe'; res.send(box.html);")

    def test_array_element_alias(self):
        self.scan('const items = []; const alias = items; alias[0] = req.query.html; res.send(items[0]);', 'xss')

    def test_array_field_precision(self):
        self.scan('const items = [req.query.html, "safe"]; res.send(items[1]);')
        self.scan('const items = ["safe", req.query.html]; eval(items[1]);', 'eval')

    def test_array_element_clean_overwrite(self):
        self.scan('const items = [req.query.html]; const alias = items; alias[0] = "safe"; res.send(items[0]);')

    def test_dynamic_write_reaches_any_property(self):
        self.scan('const box = {html: "safe"}; box[key] = req.query.html; res.send(box.html);', 'xss')

    def test_dynamic_read_keeps_all_possibilities(self):
        self.scan('const box = {safe: "hello", bad: req.query.html}; res.send(box[key]);', 'xss')

    def test_unknown_map_retains_conservative_selector_flow(self):
        self.scan('const session = sessions[req.query.id]; db.query(session.userId);', 'sql')

    def test_known_clean_map_does_not_taint_from_selector_alone(self):
        self.scan('const values = {safe:"hello"}; res.send(values[req.query.key]);')

    def test_dynamic_clean_write_is_not_a_strong_update(self):
        self.scan('const box = {html: req.query.html}; box[key] = "safe"; res.send(box.html);', 'xss')

    def test_nested_objects_keep_identity(self):
        self.scan('const box = {nested: {html: "safe"}}; const alias = box.nested; alias.html = req.query.html; res.send(box.nested.html);', 'xss')

    def test_replacing_nested_object_keeps_old_alias(self):
        self.scan('const box = {nested: {html: "safe"}}; const alias = box.nested; box.nested = {}; alias.html = req.query.html; res.send(box.nested.html);')
        self.scan('const box = {nested: {html: req.query.html}}; const alias = box.nested; box.nested = {}; res.send(alias.html);', 'xss')

    def test_spread_is_shallow_copy_not_same_object(self):
        self.scan('const box = {html: "safe"}; const copy = {...box}; copy.html = req.query.html; res.send(box.html);')
        self.scan('const box = {html: req.query.html}; const copy = {...box}; copy.html = "safe"; res.send(box.html);', 'xss')

    def test_shallow_spread_keeps_nested_alias(self):
        self.scan('const box = {nested: {html: "safe"}}; const copy = {...box}; copy.nested.html = req.query.html; res.send(box.nested.html);', 'xss')

    def test_duplicate_literal_properties_use_last_value(self):
        self.scan('const box = {html: req.query.html, html: "safe"}; res.send(box.html);')
        self.scan('const box = {html: "safe", html: req.query.html}; res.send(box.html);', 'xss')

    def test_unrelated_fields_do_not_cross_contaminate(self):
        self.scan('const box = {unsafe: req.query.html, safe: "hello"}; res.send(box.safe);')

    def test_unrelated_allocations_do_not_cross_contaminate(self):
        self.scan('const a = {}; const b = {}; a.html = req.query.html; res.send(b.html);')

    def test_conditional_write_preserves_possible_taint(self):
        self.scan('const box = {}; if (flag) { box.html = req.query.html; } res.send(box.html);', 'xss')

    def test_conditional_cleanup_preserves_untouched_branch(self):
        self.scan('const box = {html: req.query.html}; if (flag) { box.html = "safe"; } res.send(box.html);', 'xss')

    def test_cleanup_on_both_branches_is_safe(self):
        self.scan('const box = {html: req.query.html}; if (flag) { box.html = "a"; } else { box.html = "b"; } res.send(box.html);')

    def test_conditional_alias_write_is_weak_update(self):
        self.scan('const a = {html: req.query.html}; const b = {}; const alias = flag ? a : b; alias.html = "safe"; res.send(a.html);', 'xss')

    def test_conditional_alias_write_taints_possible_receivers(self):
        self.scan('const a = {}; const b = {}; const alias = flag ? a : b; alias.html = req.query.html; res.send(a.html); res.send(b.html);', 'xss', 'xss')

    def test_short_circuit_write_keeps_bypass_path(self):
        self.scan('const box = {html: req.query.html}; flag && (box.html = "safe"); res.send(box.html);', 'xss')

    def test_compound_property_assignment(self):
        self.scan('const box = {html: "safe"}; const alias = box; alias.html += req.query.html; res.send(box.html);', 'xss')

    def test_loop_alias_write_reaches_sink(self):
        self.scan('const box = {}; const alias = box; while (flag) { alias.html = req.query.html; } res.send(box.html);', 'xss')

    def test_loop_cleanup_keeps_zero_iteration_path(self):
        self.scan('const box = {html: req.query.html}; while (flag) { box.html = "safe"; } res.send(box.html);', 'xss')

    def test_cyclic_object_graph_terminates(self):
        self.scan('const a = {}; const b = {back: a}; a.next = b; b.html = req.query.html; res.send(a);', 'xss')

    def test_clean_cyclic_object_graph_stays_clean(self):
        self.scan('const a = {}; a.self = a; res.send(a);')

    def test_deep_cyclic_heap_has_no_python_recursion_cutoff(self):
        heap = {index: {'next': taint._Fact(refs=[index + 1])} for index in range(3000)}
        source = taint._Trace(('source', 'input'), ('input',))
        heap[3000] = {'next': taint._Fact(refs=[0]), 'html': frozenset([source])}
        self.assertEqual(taint._materialize(taint._Fact(refs=[0]), heap), frozenset([source]))

    def test_whole_object_sink_sees_reachable_property(self):
        self.scan('const box = {}; const alias = box; alias.html = req.query.html; res.send(box);', 'xss')

    def test_sanitizer_effect_is_local_to_sink_domain(self):
        self.scan('const box = {}; const alias = box; alias.value = DOMPurify.sanitize(req.query.html); res.send(box.value); eval(box.value);', 'eval')

    def test_function_local_objects_are_isolated(self):
        self.scan('function a() { const box = {}; box.html = req.query.html; } function b() { const box = {}; res.send(box.html); }')

    def test_external_callback_reads_captured_object_taint(self):
        self.scan('const box = {html:req.query.html}; function callback() { res.send(box.html); }', 'xss')
        self.scan('function outer() { const box = {html:req.query.html}; function callback() { res.send(box.html); } }', 'xss')

    def test_captured_clean_object_does_not_become_a_source(self):
        self.scan('const box = {html:"safe"}; function callback() { res.send(box.html); }')

    def test_object_return_retains_source(self):
        self.scan('function make(x) { const box = {html: x}; return box; } res.send(make(req.query.html));', 'xss')

    def test_object_argument_passes_through_identity(self):
        self.scan('function id(x) { return x; } const box = {}; const alias = id(box); alias.html = req.query.html; res.send(box.html);', 'xss')

    def test_default_object_argument_retains_source(self):
        self.scan('function output(box = {html: req.query.html}) { res.send(box); } output();', 'xss')
        self.scan('function output(box = {html: req.query.html}) { res.send(box); } output({html:"safe"});')

    def test_later_cleanup_does_not_erase_earlier_operand(self):
        self.scan('const box = {html:req.query.html}; res.send(box.html + Object.assign(box, {html:"safe"}));', 'xss')

    def test_scalar_coercion_does_not_retain_object_identity(self):
        self.scan('const box = {}; const text = "prefix" + box; box.html = req.query.html; res.send(text);')

    def test_later_mutator_does_not_taint_earlier_scalar_argument(self):
        self.scan('const box = {html:"safe"}; function first(a,b) { return a; } res.send(first(box.html, Object.assign(box,{html:req.query.html})));')

    def test_reads_before_later_write_keep_coordinates(self):
        findings = self.scan('const box = {};\nres.send(box.html);\nbox.html = req.query.html;\n  res.send(box.html);', 'xss')
        self.assertEqual((findings[0]['line'], findings[0]['col']), (4, 3))

    def test_fact_lattice_laws_include_references(self):
        source = taint._Trace(('source', 'input'), ('input',))
        values = [frozenset(), taint._Fact([source]), taint._Fact(refs=[('a', 1)]),
                  taint._Fact([source], [('a', 1), ('b', 2)])]
        for a, b, c in itertools.product(values, repeat=3):
            self.assertEqual(taint._join(a, a), a)
            self.assertEqual(taint._join(a, b), taint._join(b, a))
            self.assertEqual(taint._join(taint._join(a, b), c), taint._join(a, taint._join(b, c)))
        self.assertEqual(hash(taint._Fact([source])), hash(frozenset([source])))
        self.assertNotEqual(taint._Fact(refs=[('a', 1)]), frozenset())

    def test_heap_copy_does_not_mutate_other_branch(self):
        left = taint._State()
        left.heap[('obj', 1)] = {'html': frozenset()}
        right = left.copy()
        right.heap[('obj', 1)]['html'] = frozenset([taint._Trace(('source', 'input'), ('input',))])
        self.assertFalse(left.heap[('obj', 1)]['html'])
        self.assertTrue(taint._join_states(left, right).heap[('obj', 1)]['html'])

    def test_object_assign_mutates_alias_and_returns_target(self):
        self.scan('const box = {}; const alias = box; Object.assign(alias, {html: req.query.html}); res.send(box.html);', 'xss')
        self.scan('const box = {}; const alias = Object.assign(box, {}); alias.html = req.query.html; res.send(box.html);', 'xss')

    def test_object_assign_preserves_unmentioned_properties(self):
        self.scan('const box = {html: req.query.html}; Object.assign(box, {other: "safe"}); res.send(box.html);', 'xss')

    def test_object_assign_source_order_is_left_to_right(self):
        self.scan('const box = {}; Object.assign(box, {html: req.query.html}, {html: "safe"}); res.send(box.html);')
        self.scan('const box = {}; Object.assign(box, {html: "safe"}, {html: req.query.html}); res.send(box.html);', 'xss')

    def test_object_assign_alternative_source_is_not_strong_cleanup(self):
        self.scan('const box = {html: req.query.html}; const source = flag ? {html: "safe"} : {}; Object.assign(box, source); res.send(box.html);', 'xss')

    def test_object_assign_unknown_source_keeps_taint(self):
        self.scan('const box = {}; Object.assign(box, req.query); res.send(box.html);', 'xss')

    def test_object_assign_shadowed_constructor_is_not_trusted(self):
        self.scan('const Object = external; const box = {html: req.query.html}; Object.assign(box, {html: "safe"}); res.send(box.html);', 'xss')

    def test_push_through_alias_updates_array(self):
        self.scan('const items = []; const alias = items; alias.push(req.query.html); res.send(items[0]);', 'xss')

    def test_push_does_not_taint_existing_clean_element(self):
        self.scan('const items = ["safe"]; items.push(req.query.html); res.send(items[0]);')

    def test_push_return_value_is_count_not_input(self):
        self.scan('const items = []; const length = items.push(req.query.html); res.send(length);')

    def test_pop_returns_removed_value(self):
        self.scan('const items = [req.query.html]; const value = items.pop(); res.send(value);', 'xss')

    def test_pop_removes_value_from_all_aliases(self):
        self.scan('const items = [req.query.html]; const alias = items; alias.pop(); res.send(items[0]);')

    def test_pop_on_empty_array_is_clean(self):
        self.scan('const items = []; res.send(items.pop());')

    def test_unshift_moves_existing_elements(self):
        self.scan('const items = [req.query.html]; items.unshift("safe"); res.send(items[0]);')
        self.scan('const items = [req.query.html]; items.unshift("safe"); res.send(items[1]);', 'xss')

    def test_shift_moves_remaining_elements(self):
        self.scan('const items = [req.query.html, "safe"]; items.shift(); res.send(items[0]);')
        self.scan('const items = ["safe", req.query.html]; items.shift(); res.send(items[0]);', 'xss')

    def test_reverse_preserves_array_identity(self):
        self.scan('const items = [req.query.html, "safe"]; const alias = items.reverse(); res.send(items[0]);')
        self.scan('const items = [req.query.html, "safe"]; const alias = items.reverse(); res.send(alias[1]);', 'xss')

    def test_nested_array_mutation(self):
        self.scan('const box = {items: []}; box.items.push(req.query.html); res.send(box.items[0]);', 'xss')

    def test_loop_length_widens_and_terminates(self):
        self.scan('const items = []; while (flag) { items.push(req.query.html); } res.send(items[0]);', 'xss')

    def test_conditional_pop_does_not_erase_untaken_path(self):
        self.scan('const items = [req.query.html]; if (flag) { items.pop(); } res.send(items[0]);', 'xss')

    def test_uncertain_alias_pop_is_not_strong_cleanup(self):
        self.scan('const a = [req.query.html]; const b = []; const alias = flag ? a : b; alias.pop(); res.send(a[0]);', 'xss')

    def test_overridden_pop_does_not_clean_array(self):
        self.scan('const items = [req.query.html]; items.pop = external; items.pop(); res.send(items[0]);', 'xss')

    def test_array_holes_preserve_push_index(self):
        self.scan('const items = [,,]; items.push(req.query.html); res.send(items[0]);')
        self.scan('const items = [,,]; items.push(req.query.html); res.send(items[2]);', 'xss')

    def test_numeric_looking_named_properties_are_not_array_indices(self):
        for key in ('00', '01', '-1', '4294967295'):
            with self.subTest(key=key):
                self.scan(f'const a=[]; a["{key}"]=req.query.html; a.reverse(); res.send(a["{key}"]);', 'xss')
                self.scan(f'const a=[]; a["{key}"]=req.query.html; res.send(a.pop());')

    def test_array_length_does_not_become_code(self):
        self.scan('const items = []; items[key] = req.query.html; eval(items.length);')

    def test_spread_unknown_length_does_not_invent_safe_index(self):
        self.scan('const items = [...source, req.query.html]; res.send(items[0]);', 'xss')

    def test_fact_references_are_immutable(self):
        fact = taint._Fact(refs=[('a', 1)])
        with self.assertRaises(AttributeError):
            fact.refs = frozenset()

    def test_helper_writes_to_argument_object(self):
        self.scan('function put(box, text) { box.html = text; } '
                  'const a = {}; const b = a; put(b, req.query.html); res.send(a.html);', 'xss')

    def test_helper_clean_overwrite_updates_all_aliases(self):
        self.scan('function clean(box) { box.html = "safe"; } '
                  'const a = {html: req.query.html}; const b = a; clean(b); res.send(a.html);')

    def test_helper_clean_overwrite_keeps_unrelated_taint(self):
        self.scan('function clean(box) { box.html = "safe"; } '
                  'const a = {html: req.query.html, code: req.query.code}; '
                  'clean(a); eval(a.code);', 'eval')

    def test_helper_parameter_rebinding_is_not_a_caller_write(self):
        self.scan('function clean(box) { box = {html: "safe"}; } '
                  'const a = {html: req.query.html}; clean(a); res.send(a.html);', 'xss')

    def test_helper_parameter_aliases_are_shared(self):
        self.scan('function put(a, b, text) { a.html = text; res.send(b.html); } '
                  'const box = {}; put(box, box, req.query.html);', 'xss')

    def test_helper_distinct_parameters_are_not_aliased(self):
        self.scan('function put(a, b, text) { a.html = text; res.send(b.html); } '
                  'put({}, {}, req.query.html);')

    def test_helper_property_read_uses_exact_field(self):
        self.scan('function read(box) { return box.safe; } '
                  'res.send(read({safe: "hello", other: req.query.html}));')

    def test_helper_identity_keeps_reference(self):
        self.scan('function identity(box) { return box; } '
                  'const a = {}; const b = identity(a); b.html = req.query.html; res.send(a.html);', 'xss')

    def test_helper_nested_identity_keeps_reference(self):
        self.scan('function read(box) { return box.child; } '
                  'const a = {child: {}}; const b = read(a); b.html = req.query.html; '
                  'res.send(a.child.html);', 'xss')

    def test_factory_returns_object_shape(self):
        self.scan('function make(text) { return {html: text, safe: "hello"}; } '
                  'const a = make(req.query.html); res.send(a.safe);')
        self.scan('function make(text) { return {html: text, safe: "hello"}; } '
                  'const a = make(req.query.html); res.send(a.html);', 'xss')

    def test_factory_calls_allocate_independent_objects(self):
        self.scan('function make() { return {}; } const a = make(); const b = make(); '
                  'a.html = req.query.html; res.send(b.html);')

    def test_nested_factory_calls_allocate_independent_objects(self):
        self.scan('function inner() { return {}; } function make() { return inner(); } '
                  'const a = make(); const b = make(); a.html = req.query.html; res.send(b.html);')

    def test_helper_nested_property_mutation(self):
        self.scan('function put(box, text) { box.child.html = text; } '
                  'const a = {child: {}}; put(a, req.query.html); res.send(a.child.html);', 'xss')

    def test_helper_array_push_mutates_callers_array(self):
        self.scan('function put(items, text) { items.push(text); } '
                  'const items = []; put(items, req.query.html); res.send(items[0]);', 'xss')

    def test_helper_array_pop_is_shared_cleanup(self):
        self.scan('function take(items) { return items.pop(); } '
                  'const items = [req.query.html]; take(items); res.send(items[0]);')

    def test_helper_array_pop_returns_removed_data(self):
        self.scan('function take(items) { return items.pop(); } '
                  'const items = [req.query.html]; res.send(take(items));', 'xss')

    def test_helper_heap_sink_before_cleanup_survives(self):
        self.scan('function output(box) { res.send(box.html); box.html = "safe"; } '
                  'const a = {html: req.query.html}; output(a);', 'xss')

    def test_helper_heap_sink_after_cleanup_is_clean(self):
        self.scan('function output(box) { box.html = "safe"; res.send(box.html); } '
                  'const a = {html: req.query.html}; output(a);')

    def test_transitive_helper_mutation(self):
        self.scan('function put(box, text) { box.html = text; } '
                  'function outer(box, text) { put(box, text); } '
                  'const a = {}; outer(a, req.query.html); res.send(a.html);', 'xss')

    def test_recursive_helper_mutation_converges(self):
        self.scan('function put(box, text) { if (flag) { put(box, text); } box.html = text; } '
                  'const a = {}; put(a, req.query.html); res.send(a.html);', 'xss')

    def test_conditional_helper_cleanup_keeps_untaken_path(self):
        self.scan('function clean(box) { if (flag) { box.html = "safe"; } } '
                  'const a = {html: req.query.html}; clean(a); res.send(a.html);', 'xss')

    def test_helper_mutation_keeps_sanitizer_domain(self):
        self.scan('function put(box, text) { box.html = DOMPurify.sanitize(text); } '
                  'const a = {}; put(a, req.query.html); res.send(a.html); eval(a.html);', 'eval')

    def test_helper_captured_heap_write(self):
        self.scan('const a = {}; function put(text) { a.html = text; } '
                  'put(req.query.html); res.send(a.html);', 'xss')

    def test_helper_local_shadow_does_not_write_captured_heap(self):
        self.scan('const a = {}; function put(text) { const a = {}; a.html = text; } '
                  'put(req.query.html); res.send(a.html);')

    def test_helper_installs_fresh_nested_object(self):
        self.scan('function put(box, text) { box.child = {html: text}; } '
                  'const a = {}; put(a, req.query.html); res.send(a.child.html);', 'xss')

    def test_helper_returned_reference_sees_later_mutation(self):
        self.scan('function read(box) { return box; } const a = {}; '
                  'const b = read(a); a.html = req.query.html; res.send(b.html);', 'xss')

    def test_repeated_arrow_factory_remains_callable(self):
        self.scan('const make = () => ({}); const a = make(); const b = make(); '
                  'b.html = req.query.html; res.send(b.html);', 'xss')

    def test_helper_does_not_invalidate_unmodified_callable(self):
        self.scan('const read = () => req.query.html; function noop(box) {} '
                  'noop({}); res.send(read());', 'xss')

    def test_helper_captured_callable_reassignment_invalidates_summary(self):
        self.scan('let clean = x => "safe"; function change(box) { clean = external; } '
                  'change({}); res.send(clean(req.query.html));', 'xss')

    def test_direct_factory_property_read_is_field_sensitive(self):
        self.scan('function make(x) { return {html: x, safe: "hello"}; } '
                  'res.send(make(req.query.html).safe);')
        self.scan('function make(x) { return {html: x, safe: "hello"}; } '
                  'res.send(make(req.query.html)["html"]);', 'xss')

    def test_helper_default_can_mutate_previous_object_argument(self):
        self.scan('function put(box, text) { box.html = text; } '
                  'function run(box, unused = put(box, req.query.html)) {} '
                  'const a = {}; run(a); res.send(a.html);', 'xss')

    def test_helper_explicit_argument_bypasses_heap_default(self):
        self.scan('function put(box, text) { box.html = text; } '
                  'function run(box, unused = put(box, req.query.html)) {} '
                  'const a = {}; run(a, "safe"); res.send(a.html);')

    def test_helper_default_object_remains_an_object(self):
        self.scan('function make(box = {safe: "hello", html: req.query.html}) { return box; } '
                  'const a = make(); res.send(a.safe);')

    def test_helper_sibling_calls_keep_exact_inputs(self):
        self.scan('function put(box, text) { box.html = text; } '
                  'const a = {}; const b = {}; put(a, req.query.html); put(b, "safe"); '
                  'res.send(b.html);')

    def test_loop_invocations_keep_prior_returned_objects(self):
        self.scan('function make(text) { return {html: text}; } '
                  'let a; let b; while (flag) { b = a; a = make(req.query.html); } '
                  'res.send(b);', 'xss')

    def test_earlier_object_argument_sees_later_argument_mutation(self):
        self.scan('function change(box) { box.html = req.query.html; } '
                  'function output(box, unused) { res.send(box.html); } '
                  'const a = {}; output(a, change(a));', 'xss')

    def test_earlier_scalar_argument_keeps_pre_mutation_value(self):
        self.scan('function clean(box) { box.html = "safe"; } '
                  'function output(text, unused) { res.send(text); } '
                  'const a = {html: req.query.html}; output(a.html, clean(a));', 'xss')

    def test_recursive_array_mutations_widen_and_terminate(self):
        self.scan('function put(a, x) { a.push(x); if (flag) { put(a, x); } } '
                  'const a = []; put(a, req.query.html); res.send(a[0]);', 'xss')

    def test_two_inner_allocations_remain_distinct_after_outer_return(self):
        self.scan('function make() { return {}; } '
                  'function pair() { return {a: make(), b: make()}; } '
                  'const p = pair(); p.a.html = req.query.html; res.send(p.b.html);')

    def test_actual_inner_alias_is_retained_after_outer_return(self):
        self.scan('function make() { return {}; } '
                  'function pair() { const a = make(); return {a: a, b: a}; } '
                  'const p = pair(); p.a.html = req.query.html; res.send(p.b.html);', 'xss')

    def test_uncertain_spread_does_not_make_default_cleanup_definite(self):
        self.scan('function clean(box) { box.html = "safe"; } '
                  'function run(box, unused = clean(box)) {} '
                  'const a = {html: req.query.html}; run(a, ...values); res.send(a.html);', 'xss')

    def test_definitely_missing_argument_applies_default_cleanup(self):
        self.scan('function clean(box) { box.html = "safe"; } '
                  'function run(box, unused = clean(box)) {} '
                  'const a = {html: req.query.html}; run(a); res.send(a.html);')

    def test_structured_taint_cli_reports_alias_write(self):
        with tempfile.TemporaryDirectory(prefix='ubs-heap-cli-') as tmp:
            target = Path(tmp) / 'app.js'
            target.write_text('const a = {}; const b = a; b.code = req.query.code; eval(a.code);\n')
            listing = Path(tmp) / 'files.txt'
            listing.write_bytes(str(target).encode() + b'\0')
            result = subprocess.run([sys.executable, '-m', 'ubs_core', 'taint', '--lang', 'javascript',
                                     '--files-from', str(listing)], cwd=tmp,
                                    env={**os.environ, 'PYTHONPATH': str(ROOT / 'modules/helpers'),
                                         'PYTHONDONTWRITEBYTECODE': '1'},
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
            records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            self.assertEqual([item['rule'] for item in records], ['javascript.taint.eval'], records)
            self.assertEqual(records[0]['path'], str(target.resolve()))

    def test_structured_cli_returns_canonical_path_for_a_symlink(self):
        # /var is itself symlinked on macOS; explicitly exercise that path
        # contract on every platform rather than assuming tempfile is canonical.
        with tempfile.TemporaryDirectory(prefix='ubs-heap-symlink-') as tmp:
            target = Path(tmp) / 'actual.js'
            target.write_text('const a = {}; const b = a; b.code = req.query.code; eval(a.code);\n')
            alias = Path(tmp) / 'alias.js'
            alias.symlink_to(target)
            listing = Path(tmp) / 'files.txt'
            listing.write_bytes(str(alias).encode() + b'\0')
            result = subprocess.run([sys.executable, '-m', 'ubs_core', 'taint', '--lang', 'javascript',
                                     '--files-from', str(listing)], cwd=tmp,
                                    env={**os.environ, 'PYTHONPATH': str(ROOT / 'modules/helpers'),
                                         'PYTHONDONTWRITEBYTECODE': '1'},
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
            records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            self.assertEqual([item['rule'] for item in records], ['javascript.taint.eval'], records)
            self.assertEqual(records[0]['path'], str(target.resolve()))

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner integration requires ast-grep')
    def test_meta_runner_heap_flows_and_clean_controls(self):
        cases = [
            ('alias-source', 'const a={}; const b=a; b.html=req.query.html; res.send(a.html);', {'xss'}),
            ('alias-clean', 'const a={html:req.query.html}; const b=a; b.html="safe"; res.send(a.html);', set()),
            ('push-source', 'const a=[]; const b=a; b.push(req.query.code); eval(a[0]);', {'eval'}),
            ('push-count', 'const a=[]; res.send(a.push(req.query.html));', set()),
            ('assign-source', 'const a={}; Object.assign(a,{html:req.query.html}); res.send(a.html);', {'xss'}),
            ('assign-clean', 'const a={html:req.query.html}; Object.assign(a,{html:"safe"}); res.send(a.html);', set()),
            ('cycle-source', 'const a={}; a.self=a; a.html=req.query.html; res.send(a);', {'xss'}),
            ('pop-clean', 'const a=[req.query.html]; const b=a; b.pop(); res.send(a[0]);', set()),
            ('helper-write', 'function put(o,x){o.html=x;} const a={}; put(a,req.query.html); res.send(a.html);', {'xss'}),
            ('helper-clean', 'function clear(o){o.html="safe";} const a={html:req.query.html}; const b=a; clear(b); res.send(a.html);', set()),
            ('factory-source', 'function make(x){return {html:x,safe:"hello"};} const a=make(req.query.html); res.send(a.html);', {'xss'}),
            ('factory-clean-field', 'function make(x){return {html:x,safe:"hello"};} const a=make(req.query.html); res.send(a.safe);', set()),
            ('factory-call-isolation', 'function make(x){return {html:x};} const a=make(req.query.html); const b=make("safe"); res.send(b.html);', set()),
            ('helper-array', 'function add(a,x){a.push(x);} const a=[]; add(a,req.query.code); eval(a[0]);', {'eval'}),
            ('wrapper-allocation-isolation', 'function make(){return {};} function pair(){return {a:make(),b:make()};} const p=pair(); p.a.html=req.query.html; res.send(p.b.html);', set()),
            ('helper-sanitizer-domain', 'function clear(o,x){o.html=DOMPurify.sanitize(x);} const a={}; clear(a,req.query.html); res.send(a.html); eval(a.html);', {'eval'}),
            ('destructured-alias', 'const box={}; const {box:alias}={box}; alias.html=req.query.html; res.send(box.html);', {'xss'}),
            ('destructured-parameter', 'function put({box},x){box.html=x;} const box={}; put({box},req.query.html); res.send(box.html);', {'xss'}),
            ('destructured-clean-field', 'function read({html}){return html;} res.send(read({html:"safe",other:req.query.html}));', set()),
            ('destructured-rest-parameter', 'function put(...[box,value]){box.html=value;} const box={}; put(box,req.query.html); res.send(box.html);', {'xss'}),
            ('destructured-target-order', 'const src={html:"safe"}; const out={}; function key(){src.html=req.query.html;return "html";} ({html:out[key()]}=src); res.send(out.html);', {'xss'}),
            ('destructured-dom-write', '({html:element.innerHTML}={html:req.query.html});', {'xss'}),
            ('destructured-dom-clean', '({html:element.innerHTML}={html:DOMPurify.sanitize(req.query.html)});', set()),
            ('spread-before-later-clear', 'function read(...[x]){return x;} const a=[req.query.html]; function clear(){a[0]="safe";} res.send(read(...a,clear()));', {'xss'}),
            ('spread-before-later-taint', 'function read(...[x]){return x;} const a=["safe"]; function change(){a[0]=req.query.html;} res.send(read(...a,change()));', set()),
            ('later-default-updates-earlier', 'function read({x},ignored=(x=req.query.html)){return x;} res.send(read({x:"safe"}));', {'xss'}),
            ('later-default-repairs-earlier', 'function read({x},ignored=(x="safe")){return x;} res.send(read({x:req.query.html}));', set()),
            ('call-returned-destructuring-target', 'const box={}; function get(){return box;} ({x:get().html}={x:req.query.html}); res.send(box.html);', {'xss'}),
            ('null-destructuring-skips-cleanup', 'const box={html:req.query.html}; function clear({x}){box.html="safe";} try{clear(null);}catch(error){} res.send(box.html);', {'xss'}),
            ('template-null-remains-a-string', 'function render({x},input){res.send(input);} render((`${null}`),req.query.html);', {'xss'}),
            ('template-string-allows-cleanup', 'const box={html:req.query.html}; function clear([x]){box.html="safe";} try{clear((`safe`));}catch(error){} res.send(box.html);', set()),
            ('spread-null-default-keeps-catch-store', 'const box={html:req.query.html}; function fallback(){box.html="safe";return {};} function clear({x}=fallback()){box.html="safe";} const args=[null]; try{clear(...args);}catch(error){} res.send(box.html);', {'xss'}),
            ('spread-default-effects-skip-null-bypass', 'const box={html:"safe"}; function fallback(){box.html=req.query.html;return {};} function clear({x}=fallback()){box.html="safe";} const args=[req.query.html]; try{clear(...args);}catch(error){} res.send(box.html);', set()),
            ('noniterable-destructuring-skips-cleanup', 'const box={html:req.query.html}; function clear([x]){box.html="safe";} try{clear(1);}catch(error){} res.send(box.html);', {'xss'}),
            ('shadowed-undefined-bypasses-default', 'function outer(){const undefined="safe"; function read(x=req.query.html){return x;} res.send(read(undefined));} outer();', set()),
            ('body-undefined-does-not-shadow-default', 'function read(value=req.query.html){return value;} function outer(value=read(undefined)){var undefined="body";return value;} res.send(outer());', {'xss'}),
            ('missing-undefined-formal-uses-default', 'function read(value=req.query.html){return value;} function outer(undefined){return read(undefined);} res.send(outer());', {'xss'}),
            ('missing-prior-undefined-formal-uses-default', 'function read(value=req.query.html){return value;} function outer(undefined,value=read(undefined)){return value;} res.send(outer());', {'xss'}),
            ('uninitialized-undefined-local-uses-default', 'function read(value=req.query.html){return value;} function outer(){var undefined;return read(undefined);} res.send(outer());', {'xss'}),
            ('void-undefined-local-uses-default', 'function read(value=req.query.html){return value;} function outer(){const undefined=void 0;return read(undefined);} res.send(outer());', {'xss'}),
            ('clean-undefined-formal-bypasses-default', 'function read(value=req.query.html){return value;} function outer(undefined){return read(undefined);} res.send(outer("safe"));', set()),
            ('void-expression-uses-default', 'function read(x=req.query.html){return x;} res.send(read(void (1+2)));', {'xss'}),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='ubs-heap-meta-') as tmp:
                target = Path(tmp) / 'app.js'
                target.write_text(source + '\n', encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(target), '--only=js', '--format=json', '--ci'],
                                        cwd=tmp, capture_output=True, text=True, timeout=120)
                artifacts = ROOT / 'test-suite/artifacts/javascript-heap' / name
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / 'stdout.log').write_text(result.stdout)
                (artifacts / 'stderr.log').write_text(result.stderr)
                self.assertIn(result.returncode, (0, 1), (result.stdout, result.stderr))
                report = json.loads(result.stdout)
                (artifacts / 'result.json').write_text(json.dumps(report, indent=2))
                self.assertEqual(report.get('status'), 'ok', report)
                rules = set()
                def visit(value):
                    if isinstance(value, dict):
                        for key in ('rule', 'rule_id', 'ruleId'):
                            rule = value.get(key)
                            if isinstance(rule, str) and rule.startswith(('js.taint.', 'javascript.taint.')):
                                rules.add(rule.rsplit('.', 1)[-1])
                        for child in value.values():
                            visit(child)
                    elif isinstance(value, list):
                        for child in value:
                            visit(child)
                visit(report)
                self.assertEqual(rules, expected, report)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for fixed-fixture semantic checks')
    def test_fixed_mutator_fixtures_agree_with_javascript_execution(self):
        # Execute only these authored benign fixtures, never user/scanned code.
        cases = [
            'const a = []; const b = a; b.push(req.query.html); res.send(a[0]);',
            'const a = ["safe"]; a.push(req.query.html); res.send(a[0]);',
            'const a = [req.query.html]; a.pop(); res.send(a[0]);',
            'const a = [req.query.html]; res.send(a.pop());',
            'const a = [req.query.html]; a.unshift("safe"); res.send(a[0]);',
            'const a = [req.query.html]; a.unshift("safe"); res.send(a[1]);',
            'const a = ["safe", req.query.html]; a.shift(); res.send(a[0]);',
            'const a = {}; Object.assign(a, {html:req.query.html}, {html:"safe"}); res.send(a.html);',
            'const a = [req.query.html, "safe"]; a.reverse(); res.send(a[1]);',
            'const a = []; res.send(a.push(req.query.html));',
            'function put(a,x){a.html=x;} const a={}; put(a,req.query.html); res.send(a.html);',
            'function clear(a){a.html="safe";} const a={html:req.query.html}; clear(a); res.send(a.html);',
            'function put(a,x){a.html=x;} const a={}; const b={}; put(a,req.query.html); put(b,"safe"); res.send(b.html);',
            'function make(x){return {html:x,safe:"hello"};} const a=make(req.query.html); res.send(a.safe);',
            'function make(x){return {html:x};} const a=make(req.query.html); const b=make("safe"); res.send(a.html);',
            'function make(){return {};} function pair(){return {a:make(),b:make()};} const p=pair(); p.a.html=req.query.html; res.send(p.b.html);',
            'function make(){return {};} function pair(){const a=make(); return {a:a,b:a};} const p=pair(); p.a.html=req.query.html; res.send(p.b.html);',
            'function pop(a){return a.pop();} const a=[req.query.html]; res.send(pop(a));',
            'function pop(a){return a.pop();} const a=[req.query.html]; pop(a); res.send(a[0]);',
            'function clear(o){o.html="safe";} function run(o,x=clear(o)){} const a={html:req.query.html}; run(a); res.send(a.html);',
            'function clear(o){o.html="safe";} function run(o,x=clear(o)){} const values=["supplied"]; const a={html:req.query.html}; run(a,...values); res.send(a.html);',
        ]
        prefix = ('const req = {query:{html:"<UNTRUSTED>"}}; const outputs = []; '
                  'const res = {send: value => outputs.push(value)}; ')
        for source in cases:
            with self.subTest(source=source):
                result = subprocess.run(['node', '-e', prefix + source + '; console.log(JSON.stringify(outputs));'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, (source, result.stdout, result.stderr))
                expected = ('xss',) if '<UNTRUSTED>' in result.stdout else ()
                self.scan(source, *expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
